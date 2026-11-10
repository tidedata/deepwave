//! Where trust comes from: the committee (and protocol version) of the epoch the node starts in.
//!
//! The root is the genesis committee (`checkpoint.genesisCommittee` over mainnet's
//! `genesis.blob`). From there the node walks the end-of-epoch checkpoints, as a light client
//! does: the certificate of epoch e's last checkpoint is verified with committee e, and its
//! `next_epoch_committee` becomes committee e + 1. Only certified summaries are trusted; the
//! epoch index (`epochs.jsonl`: which sequence number ends each epoch) is a hint, and a wrong
//! hint fails verification. Epochs the index does not cover are found by bisection over the
//! source (the last checkpoint whose summary has epoch e).
//!
//! A committee the node has verified is kept in `<dir>/node/epochs/<epoch>.json`
//! (`{"epoch","pv","keys":[hex],"stakes":[..]}`, the bls-cert line format plus `pv`), written to a
//! temporary file, synced and renamed, so restarts need no walk.
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const checkpoint = @import("checkpoint");
const sync = @import("sync");
const source_mod = @import("source.zig");
const Source = source_mod.Source;
const Atomic = std.atomic.Value;

pub const EpochInfo = struct {
    epoch: u64,
    /// Protocol version in force during the epoch.
    protocol_version: u64,
    /// Sorted by key (committee index order).
    keys: []const [96]u8,
    stakes: []const u64,
    /// Reference gas price of the epoch (SystemEpochInfoEvent of the change that started it), and
    /// the epoch's start timestamp (its ChangeEpoch `epoch_start_timestamp_ms`). Null when the node
    /// has not seen a verified end-of-epoch checkpoint that carries them.
    rgp: ?u64 = null,
    start_ms: ?u64 = null,

    pub fn syncCommittee(e: *const EpochInfo, arena: std.mem.Allocator) !sync.Committee {
        return sync.Committee.init(arena, e.epoch, e.keys, e.stakes);
    }

    pub fn fromCheckpoint(arena: std.mem.Allocator, c: *const checkpoint.Committee, pv: u64) !EpochInfo {
        const keys = try arena.alloc([96]u8, c.members.len);
        const stakes = try arena.alloc(u64, c.members.len);
        for (c.members, keys, stakes) |m, *k, *s| {
            k.* = m.name;
            s.* = m.stake;
        }
        return .{ .epoch = c.epoch, .protocol_version = pv, .keys = keys, .stakes = stakes };
    }
};

/// Splits a `CertifiedCheckpointSummary` (summary ++ AuthorityStrongQuorumSignInfo) into its two
/// values.
pub fn splitCert(cert: []const u8) !checkpoint.CertifiedSummaryView {
    var r = bcs.Reader.init(cert);
    try bcs.skip(types.CheckpointSummary, &r);
    const n = r.pos();
    return .{ .summary = cert[0..n], .sig = cert[n..] };
}

/// The certified summary of a checkpoint blob (`0x01 ++ BCS(CheckpointData)`).
pub fn blobCert(blob: []const u8) !checkpoint.CertifiedSummaryView {
    if (blob.len < 1 or blob[0] != 1) return error.BadBlob;
    var r = bcs.Reader.init(blob[1..]);
    try bcs.skip(types.CheckpointSummary, &r);
    const s_end = 1 + r.pos();
    try bcs.skip(types.AuthorityQuorumSignInfo, &r);
    return .{ .summary = blob[1..s_end], .sig = blob[s_end .. 1 + r.pos()] };
}

// ------------------------------------------------------------------ persistence

pub fn save(io: Io, dir: Io.Dir, e: *const EpochInfo) !void {
    var buf: std.ArrayList(u8) = .empty;
    const gpa = std.heap.page_allocator;
    defer buf.deinit(gpa);
    var aw: std.Io.Writer.Allocating = .fromArrayList(gpa, &buf);
    defer buf = aw.toArrayList();
    const w = &aw.writer;
    try w.print("{{\"epoch\":{d},\"pv\":{d},\"keys\":[", .{ e.epoch, e.protocol_version });
    for (e.keys, 0..) |k, i| try w.print("{s}\"{x}\"", .{ if (i > 0) "," else "", &k });
    try w.writeAll("],\"stakes\":[");
    for (e.stakes, 0..) |s, i| try w.print("{s}{d}", .{ if (i > 0) "," else "", s });
    try w.writeAll("]");
    if (e.rgp) |v| try w.print(",\"rgp\":{d}", .{v});
    if (e.start_ms) |v| try w.print(",\"start_ms\":{d}", .{v});
    try w.writeAll("}\n");
    var nb: [64]u8 = undefined;
    var tb: [64]u8 = undefined;
    const name = std.fmt.bufPrint(&nb, "{d}.json", .{e.epoch}) catch unreachable;
    const tmp = std.fmt.bufPrint(&tb, ".{d}.json.tmp", .{e.epoch}) catch unreachable;
    {
        const f = try dir.createFile(io, tmp, .{ .truncate = true });
        defer f.close(io);
        try f.writePositionalAll(io, aw.writer.buffered(), 0);
        try f.sync(io);
    }
    try dir.rename(tmp, dir, name, io);
    // Make the rename durable.
    try syncDir(io, dir);
}

/// fsync of a directory. The handle may be O_PATH on Linux (a Dir opened without `.iterate`,
/// as `std.testing.tmpDir` does), where fsync fails with EBADF (a panic in Debug builds), so the
/// directory is opened again as a real descriptor. A failure means the rename may not be durable
/// and is reported.
pub fn syncDir(io: Io, dir: Io.Dir) !void {
    const d = try dir.openDir(io, ".", .{ .iterate = true });
    defer d.close(io);
    const f: Io.File = .{ .handle = d.handle, .flags = .{ .nonblocking = false } };
    try f.sync(io);
}

pub fn load(arena: std.mem.Allocator, io: Io, dir: Io.Dir, epoch: u64) !?EpochInfo {
    var nb: [64]u8 = undefined;
    const name = std.fmt.bufPrint(&nb, "{d}.json", .{epoch}) catch unreachable;
    const text = dir.readFileAlloc(io, name, arena, .limited(1 << 20)) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    const V = struct { epoch: u64, pv: u64, keys: []const []const u8, stakes: []const u64, rgp: ?u64 = null, start_ms: ?u64 = null };
    const v = try std.json.parseFromSliceLeaky(V, arena, text, .{ .ignore_unknown_fields = true });
    if (v.epoch != epoch or v.keys.len != v.stakes.len) return error.BadEpochFile;
    const keys = try arena.alloc([96]u8, v.keys.len);
    for (v.keys, keys) |hex, *k| {
        if (hex.len != 192) return error.BadEpochFile;
        _ = try std.fmt.hexToBytes(k, hex);
    }
    return .{ .epoch = v.epoch, .protocol_version = v.pv, .keys = keys, .stakes = v.stakes, .rgp = v.rgp, .start_ms = v.start_ms };
}

// ------------------------------------------------------------------ epoch parameters

pub const EpochParams = struct { rgp: ?u64 = null, start_ms: ?u64 = null };

/// The `epoch_start_timestamp_ms` of a ChangeEpoch transaction (direct, or inside an
/// EndOfEpochTransaction), or null for any other transaction kind.
pub fn changeEpochStart(arena: std.mem.Allocator, data_bytes: []const u8) ?u64 {
    const td = bcs.decode(types.TransactionData, arena, data_bytes) catch return null;
    switch (td.V1.kind) {
        .ChangeEpoch => |ce| return ce.epoch_start_timestamp_ms,
        .EndOfEpochTransaction => |list| for (list) |k| switch (k) {
            .ChangeEpoch => |ce| return ce.epoch_start_timestamp_ms,
            else => {},
        },
        else => {},
    }
    return null;
}

/// `0x3::sui_system_state_inner::SystemEpochInfoEvent { epoch, protocol_version,
/// reference_gas_price, .. }` in a transaction's events (BCS `TransactionEvents`): the reference gas
/// price of the epoch advance_epoch started. Null when absent (safe mode emits none).
pub fn epochInfoRgp(arena: std.mem.Allocator, events_bytes: []const u8) ?u64 {
    const evs = bcs.decode(types.TransactionEvents, arena, events_bytes) catch return null;
    for (evs.data) |ev| {
        const t = ev.type_;
        if (!std.mem.eql(u8, &t.address.@"0", &sui_system_addr)) continue;
        if (!std.mem.eql(u8, t.module.@"0", "sui_system_state_inner") or !std.mem.eql(u8, t.name.@"0", "SystemEpochInfoEvent")) continue;
        if (ev.contents.len < 24) return null;
        return std.mem.readInt(u64, ev.contents[16..24], .little);
    }
    return null;
}

const sui_system_addr: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[31] = 3;
    break :blk a;
};

/// The parameters of the epoch that a verified end-of-epoch checkpoint blob starts.
pub fn epochParamsOfBlob(arena: std.mem.Allocator, blob: []const u8, idx: *types.CheckpointIndex) !EpochParams {
    try types.indexCheckpointData(blob, idx);
    var p: EpochParams = .{};
    var i = idx.tx_count;
    while (i > 0) {
        i -= 1;
        const t = idx.txAt(i);
        const start = changeEpochStart(arena, t.data.slice(blob)) orelse continue;
        p.start_ms = start;
        if (t.events) |ev| p.rgp = epochInfoRgp(arena, ev.slice(blob));
        break;
    }
    return p;
}

// ------------------------------------------------------------------ the walk

/// `epochs.jsonl` lines: `{"epoch","first","last","pv",...}`. Index = epoch.
pub const EpochIndex = struct {
    last: []?u64 = &.{},
    first: []?u64 = &.{},
    pv: []?u64 = &.{},

    pub fn load(arena: std.mem.Allocator, io: Io, path: []const u8) !EpochIndex {
        const text = try Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(64 << 20));
        const L = struct { epoch: u64, first: ?u64 = null, last: ?u64 = null, pv: ?u64 = null };
        var lines: std.ArrayList(L) = .empty;
        var max: u64 = 0;
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |line| {
            if (std.mem.trim(u8, line, " \r").len == 0) continue;
            const l = try std.json.parseFromSliceLeaky(L, arena, line, .{ .ignore_unknown_fields = true });
            max = @max(max, l.epoch);
            try lines.append(arena, l);
        }
        const n: usize = @intCast(max + 1);
        var x: EpochIndex = .{ .last = try arena.alloc(?u64, n), .first = try arena.alloc(?u64, n), .pv = try arena.alloc(?u64, n) };
        @memset(x.last, null);
        @memset(x.first, null);
        @memset(x.pv, null);
        for (lines.items) |l| {
            const e: usize = @intCast(l.epoch);
            x.last[e] = l.last;
            x.first[e] = l.first;
            x.pv[e] = l.pv;
        }
        return x;
    }

    fn get(x: *const EpochIndex, comptime f: []const u8, e: u64) ?u64 {
        const a = @field(x, f);
        return if (e < a.len) a[@intCast(e)] else null;
    }
};

pub const Walker = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// Sources to read end-of-epoch checkpoints from, in order (for example the local corpus, then S3).
    sources: []const *const Source,
    index: EpochIndex = .{},
    log: bool = true,
    save_dir: ?Io.Dir = null,
    save_every: u64 = 100,
    /// When set, receives the fully verified end-of-epoch checkpoint blob of `target - 1` (the
    /// snapshot restore anchors on it).
    keep_last_eoe: ?*std.ArrayList(u8) = null,
    /// Threads that fetch the indexed end-of-epoch checkpoints ahead of the walk. Only fetching is
    /// parallel (S3 latency made the serial walk about 146 s for 1,304 epochs on a bench machine);
    /// certificates are still verified in order, each with the committee its predecessor handed
    /// over, so prefetched bytes are trusted no more than serially fetched ones.
    parallel: u32 = 1,

    /// Prefetched certified summaries (summary ++ signature), index = epoch - base. Null where the
    /// index has no hint or the fetch failed; the walk then fetches serially (and reports errors).
    const Prefetch = struct {
        base: u64,
        certs: []?[]u8,
        seqs: []const ?u64,
        next: Atomic(usize) = .init(0),
        w: *Walker,

        fn run(p: *Prefetch) void {
            var sc = source_mod.Scratch.init(p.w.gpa);
            defer sc.deinit(p.w.gpa);
            var buf: std.ArrayList(u8) = .empty;
            defer buf.deinit(p.w.gpa);
            while (true) {
                const i = p.next.fetchAdd(1, .monotonic);
                if (i >= p.certs.len) return;
                const seq = p.seqs[i] orelse continue;
                const ok = p.w.fetch(&sc, seq, &buf) catch continue;
                if (!ok) continue;
                const cert = blobCert(buf.items) catch continue;
                const bytes = p.w.gpa.alloc(u8, cert.summary.len + cert.sig.len) catch continue;
                @memcpy(bytes[0..cert.summary.len], cert.summary);
                @memcpy(bytes[cert.summary.len..], cert.sig);
                p.certs[i] = bytes;
            }
        }

        fn get(p: *const Prefetch, e: u64) ?checkpoint.CertifiedSummaryView {
            if (e < p.base or e - p.base >= p.certs.len) return null;
            const b = p.certs[@intCast(e - p.base)] orelse return null;
            return splitCert(b) catch null;
        }

        fn deinit(p: *Prefetch) void {
            for (p.certs) |c| if (c) |b| p.w.gpa.free(b);
            p.w.gpa.free(p.certs);
        }
    };

    /// Fetches the certificates of epochs [e0, target - 1) (the last step needs the whole blob and
    /// is fetched by the walk) with `parallel` threads.
    fn prefetch(w: *Walker, e0: u64, target: u64) !?Prefetch {
        if (w.parallel <= 1 or target < e0 + 2) return null;
        const n: usize = @intCast(target - 1 - e0);
        const seqs = w.index.last[@min(w.index.last.len, @as(usize, @intCast(e0)))..@min(w.index.last.len, @as(usize, @intCast(e0)) + n)];
        if (seqs.len == 0) return null;
        const certs = try w.gpa.alloc(?[]u8, seqs.len);
        @memset(certs, null);
        var p: Prefetch = .{ .base = e0, .certs = certs, .seqs = seqs, .w = w };
        const k = @min(w.parallel, 64);
        var threads: [64]?std.Thread = @splat(null);
        for (threads[0..k]) |*t| t.* = std.Thread.spawn(.{}, Prefetch.run, .{&p}) catch null;
        Prefetch.run(&p); // this thread helps (and does all of it if no thread could start)
        for (threads[0..k]) |t| if (t) |th| th.join();
        return p;
    }

    fn fetch(w: *Walker, sc: *source_mod.Scratch, seq: u64, out: *std.ArrayList(u8)) !bool {
        for (w.sources) |s| {
            if (try s.fetch(sc, seq, out) == .ok) return true;
        }
        return false;
    }

    /// Epoch of checkpoint `seq` (unverified: used only to steer the bisection).
    fn epochOf(w: *Walker, sc: *source_mod.Scratch, seq: u64, buf: *std.ArrayList(u8)) !u64 {
        if (!try w.fetch(sc, seq, buf)) return error.SourceMissing;
        const cert = try blobCert(buf.items);
        return (try checkpoint.Summary.parse(cert.summary)).epoch;
    }

    /// The last checkpoint of epoch `e`, given `lo` in epoch e (or earlier) and `hi` in a later epoch.
    fn findEpochEnd(w: *Walker, sc: *source_mod.Scratch, e: u64, lo_in: u64, hi_in: u64, buf: *std.ArrayList(u8)) !u64 {
        var lo = lo_in;
        var hi = hi_in;
        while (hi - lo > 1) {
            const mid = lo + (hi - lo) / 2;
            if (try w.epochOf(sc, mid, buf) <= e) lo = mid else hi = mid;
        }
        return lo;
    }

    /// Committee and protocol version of `target`, walked from the genesis committee in
    /// `genesis_blob`. `tip` is a checkpoint at or past `target`'s start (bisection bound).
    /// Committee and protocol version of `target`, walked from `from` (a verified epoch, for
    /// example one saved earlier) or from the genesis committee in `genesis_blob`. `tip` is a
    /// checkpoint at or past `target`'s start (bisection bound). Every `save_every` epochs the
    /// committee reached is saved to `save_dir`, so an interrupted walk resumes from there.
    pub fn walk(w: *Walker, arena: std.mem.Allocator, genesis_blob: []const u8, from: ?EpochInfo, target: u64, tip: u64) !EpochInfo {
        var sc = source_mod.Scratch.init(w.gpa);
        defer sc.deinit(w.gpa);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(w.gpa);
        var probe: std.ArrayList(u8) = .empty;
        defer probe.deinit(w.gpa);

        var cur_arena: std.heap.ArenaAllocator = .init(w.gpa);
        defer cur_arena.deinit();
        var committee: checkpoint.Committee = undefined;
        var pv: u64 = undefined;
        var e: u64 = undefined;
        if (from) |f| {
            const rights = try cur_arena.allocator().alloc(checkpoint.Member, f.keys.len);
            for (rights, f.keys, f.stakes) |*m, k, st| m.* = .{ .name = k, .stake = st };
            committee = try checkpoint.Committee.init(cur_arena.allocator(), f.epoch, rights);
            pv = f.protocol_version;
            e = f.epoch;
        } else {
            committee = try checkpoint.genesisCommittee(cur_arena.allocator(), genesis_blob);
            pv = w.index.get("pv", 0) orelse 1;
            e = 0;
        }
        const e0 = e;
        // exec-history: epoch 0 has no end-of-epoch checkpoint before it; its reference gas
        // price and start come from the genesis system state (the trust root itself)
        var params: EpochParams = if (from) |f| .{ .rgp = f.rgp, .start_ms = f.start_ms } else if (checkpoint.genesis.genesisEpochParams(cur_arena.allocator(), genesis_blob)) |g| .{ .rgp = g.rgp, .start_ms = g.start_ms } else |_| .{};
        var prev_last: ?u64 = if (e > 0) w.index.get("last", e - 1) else null;
        const t0 = source_mod.nowNs();
        var pre = try w.prefetch(e, target);
        defer if (pre) |*p| p.deinit();
        if (w.log) if (pre) |p| {
            var got: usize = 0;
            for (p.certs) |c| got += @intFromBool(c != null);
            std.log.info("trust walk: prefetched {d} of {d} end-of-epoch certificates with {d} threads in {d} ms", .{ got, p.certs.len, w.parallel, (source_mod.nowNs() - t0) / std.time.ns_per_ms });
        };
        while (e < target) : (e += 1) {
            const last = w.index.get("last", e) orelse blk: {
                const lo = if (prev_last) |p| p + 1 else (w.index.get("first", e) orelse 0);
                break :blk try w.findEpochEnd(&sc, e, lo, tip, &probe);
            };
            const pre_cert: ?checkpoint.CertifiedSummaryView = if (e + 1 == target) null else if (pre) |*p| p.get(e) else null;
            if (pre_cert == null) {
                if (!try w.fetch(&sc, last, &buf)) return error.SourceMissing;
            }
            const cert = pre_cert orelse try blobCert(buf.items);
            const v = checkpoint.verifyCertifiedSummary(&committee, cert);
            if (v != .ok) {
                if (w.log) std.log.err("trust walk: end-of-epoch checkpoint {d} of epoch {d} does not verify: {s}", .{ last, e, @tagName(v) });
                return error.UntrustedCheckpoint;
            }
            const s = try checkpoint.Summary.parse(cert.summary);
            if (s.epoch != e) return error.UntrustedCheckpoint;
            if (e + 1 == target) {
                // The target epoch's reference gas price and start time come from this checkpoint's
                // ChangeEpoch transaction and its events: verify the whole checkpoint first.
                var tmp: std.heap.ArenaAllocator = .init(w.gpa);
                defer tmp.deinit();
                const ta = tmp.allocator();
                const info = try EpochInfo.fromCheckpoint(ta, &committee, pv);
                const sc_comm = try info.syncCommittee(ta);
                var idx = try types.CheckpointIndex.init(w.gpa);
                defer idx.deinit(w.gpa);
                const fv = try sync.verify.full(ta, buf.items, &idx, &sc_comm, null);
                if (!fv.isOk()) {
                    std.log.err("trust walk: end-of-epoch checkpoint {d} does not verify in full: {s}", .{ last, fv.name() });
                    return error.UntrustedCheckpoint;
                }
                params = try epochParamsOfBlob(ta, buf.items, &idx);
                if (w.keep_last_eoe) |k| {
                    k.clearRetainingCapacity();
                    try k.appendSlice(w.gpa, buf.items);
                }
            }
            var next_arena: std.heap.ArenaAllocator = .init(w.gpa);
            errdefer next_arena.deinit();
            const next = checkpoint.nextCommittee(next_arena.allocator(), s) catch return error.UntrustedCheckpoint;
            pv = s.next_protocol_version;
            cur_arena.deinit();
            cur_arena = next_arena;
            committee = next;
            prev_last = last;
            if (w.log and (e % 200 == 0 or e + 1 == target)) std.log.info("trust walk: epoch {d} -> {d} via checkpoint {d}", .{ e, e + 1, last });
            if (w.save_dir) |d| if ((e + 1) % w.save_every == 0) {
                var tmp: std.heap.ArenaAllocator = .init(w.gpa);
                defer tmp.deinit();
                const info = try EpochInfo.fromCheckpoint(tmp.allocator(), &committee, pv);
                try save(w.io, d, &info);
            };
        }
        if (w.log) std.log.info("trust walk: {d} epoch changes ({d} to {d}) verified in {d} ms", .{ target - e0, e0, target, (source_mod.nowNs() - t0) / std.time.ns_per_ms });
        var out = try EpochInfo.fromCheckpoint(arena, &committee, pv);
        out.rgp = params.rgp;
        out.start_ms = params.start_ms;
        return out;
    }
};

/// The highest saved epoch below `below`, if any.
pub fn highestSaved(arena: std.mem.Allocator, io: Io, dir: Io.Dir, below: u64) !?EpochInfo {
    var d = try dir.openDir(io, ".", .{ .iterate = true });
    defer d.close(io);
    var it = d.iterate();
    var best: ?u64 = null;
    while (try it.next(io)) |ent| {
        if (!std.mem.endsWith(u8, ent.name, ".json") or ent.name[0] == '.') continue;
        const e = std.fmt.parseInt(u64, ent.name[0 .. ent.name.len - 5], 10) catch continue;
        if (e < below and (best == null or e > best.?)) best = e;
    }
    return if (best) |e| try load(arena, io, dir, e) else null;
}
