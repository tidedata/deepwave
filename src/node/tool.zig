//! deepwave-tool: the operator subcommands of sui-tool / `sui-tool db-tool` (mainnet-v1.83.1,
//! crates/sui-tool/src/{commands.rs,db_tool/mod.rs}) for a deepwave node directory. Every command
//! works on a stopped node (it takes `node/LOCK`, as deepwave does), like db-tool on a closed
//! RocksDB.
//!
//!   sui-tool / db-tool                 deepwave-tool
//!   db-tool list-tables, table-summary info
//!   db-tool print-object               print-object
//!   db-tool print-checkpoint(-content) print-checkpoint
//!   db-tool print-transaction          print-transaction
//!   (none; sui-node checks at runtime) verify-store
//!   expensive state-root check         state-hash
//!   expensive SUI conservation check   sui-conservation
//!   db-tool prune-objects/-checkpoints prune
//!   db-tool compact                    prune (segment cleaning is deepwave's compaction)
//!   state-snapshot-write-config        snapshot-write
//!   db-checkpoint-config               db-checkpoint
//!   restore-db                         restore-db
//!   download-formal-snapshot           `deepwave run --snapshot E` (and `deepwave snapshot-check`)
//! Not ported: consensus and validator commands (scan-consensus-commits, locked-object,
//! dump-validators, anemo), fetch-* from validators (FULLNODE-PARITY section 10), db-shell.
const std = @import("std");
const Io = std.Io;
const node = @import("node");
const exec = @import("exec");
const bcs = @import("bcs");
const checkpoint = @import("checkpoint");
const serve = @import("serve");
const store = node.store;
const types = node.types;
const snapwrite = node.snapwrite;
const dbc = node.dbcheckpoint;
const Atomic = std.atomic.Value;

const usage =
    \\deepwave-tool <command> --dir DIR [options]      (the node must be stopped)
    \\  info                                      committed checkpoint, epochs, segments, live objects
    \\  print-object --id HEX [--version V] [--bcs]   an object (latest, or a retained version)
    \\  print-checkpoint --seq N [--bcs]          a checkpoint's summary and contents size
    \\  print-transaction --digest B58 [--bcs]    a transaction's checkpoint and record sizes
    \\  verify-store [--live]                     every retained checkpoint record (checksum, chain of
    \\                                            previous digests, contents digest); --live also every
    \\                                            live object's digest
    \\  state-hash [--epoch E | --checkpoint S] [--threads N]
    \\                                            ECMH live object set root at an end-of-epoch checkpoint
    \\                                            (default: the newest the store holds) vs the certified commitment
    \\  sui-conservation [--epoch E | --checkpoint S] [--threads N] [--save]
    \\                                            SUI conservation (sui-node expensive_check_sui_conservation) over the
    \\                                            live set at an end of epoch, against DIR/node/sui-conservation
    \\                                            (the node's first check); --save records this result there
    \\  snapshot-write --out DIR [--epoch E] [--threads N] [--compression zstd|none]
    \\                                            formal snapshot epoch_E/ (Mysten format) from the store
    \\  prune --retention-epochs N                move the history window and clean aged segments now
    \\  db-checkpoint --out DIR                   consistent copy of the node directory (hard links + clones)
    \\  restore-db --from DIR                     DIR (a db-checkpoint) becomes the node directory --dir
    \\
;

fn usageErr(msg: []const u8) u8 {
    std.debug.print("{s}\n{s}", .{ msg, usage });
    return 2;
}

const Args = struct {
    dir: ?[]const u8 = null,
    id: ?[]const u8 = null,
    version: ?u64 = null,
    seq: ?u64 = null,
    digest: ?[]const u8 = null,
    epoch: ?u64 = null,
    checkpoint: ?u64 = null,
    out: ?[]const u8 = null,
    from: ?[]const u8 = null,
    threads: u32 = 8,
    retention: ?u32 = null,
    compression: node.snapshot.Compression = .zstd,
    show_bcs: bool = false,
    live: bool = false,
    save: bool = false,
};

fn parseArgs(args: []const []const u8) !Args {
    var a: Args = .{};
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const k = args[i];
        const v = if (i + 1 < args.len) args[i + 1] else "";
        if (std.mem.eql(u8, k, "--bcs")) {
            a.show_bcs = true;
            continue;
        }
        if (std.mem.eql(u8, k, "--save")) {
            a.save = true;
            continue;
        }
        if (std.mem.eql(u8, k, "--live")) {
            a.live = true;
            continue;
        }
        i += 1;
        if (i >= args.len) return error.MissingValue;
        if (std.mem.eql(u8, k, "--dir")) {
            a.dir = v;
        } else if (std.mem.eql(u8, k, "--id")) {
            a.id = v;
        } else if (std.mem.eql(u8, k, "--version")) {
            a.version = try std.fmt.parseInt(u64, v, 10);
        } else if (std.mem.eql(u8, k, "--seq")) {
            a.seq = try std.fmt.parseInt(u64, v, 10);
        } else if (std.mem.eql(u8, k, "--digest")) {
            a.digest = v;
        } else if (std.mem.eql(u8, k, "--epoch")) {
            a.epoch = try std.fmt.parseInt(u64, v, 10);
        } else if (std.mem.eql(u8, k, "--checkpoint")) {
            a.checkpoint = try std.fmt.parseInt(u64, v, 10);
        } else if (std.mem.eql(u8, k, "--out")) {
            a.out = v;
        } else if (std.mem.eql(u8, k, "--from")) {
            a.from = v;
        } else if (std.mem.eql(u8, k, "--threads")) {
            a.threads = try std.fmt.parseInt(u32, v, 10);
        } else if (std.mem.eql(u8, k, "--retention-epochs")) {
            a.retention = try std.fmt.parseInt(u32, v, 10);
        } else if (std.mem.eql(u8, k, "--compression")) {
            a.compression = std.meta.stringToEnum(node.snapshot.Compression, v) orelse return error.BadCompression;
        } else return error.UnknownArgument;
    }
    return a;
}

const Opened = struct {
    st: *store.Store,
    rio: *store.RealIo,
    lock_fd: std.c.fd_t,
    restored_epoch: ?u64,

    fn close(o: *Opened) void {
        o.st.close() catch |e| std.log.err("store close: {s}", .{@errorName(e)});
        o.rio.deinit();
        dbc.unlock(o.lock_fd);
    }
};

fn openNode(gpa: std.mem.Allocator, io: Io, arena: std.mem.Allocator, dir: []const u8, retention: ?u32, verify_index: bool) !Opened {
    const fd = try dbc.lock(dir);
    errdefer dbc.unlock(fd);
    var restored: ?u64 = null;
    if (Io.Dir.cwd().openDir(io, dir, .{})) |root| {
        defer root.close(io);
        if (root.openDir(io, "node", .{})) |nd| {
            defer nd.close(io);
            const m = try node.snapshot.readMarker(io, nd);
            if (m.state == .loading) return error.SnapshotRestoreInterrupted;
            if (m.state == .done) restored = m.epoch;
        } else |_| {}
    } else |e| return e;
    var scfg: store.Config = .{ .dir = try std.fs.path.join(arena, &.{ dir, "store" }), .codec = exec.objects.store_codec };
    if (retention) |r| scfg.retention_epochs = r;
    // Checking every live-table page at open reads the whole table (35 GB on mainnet); readers
    // check record checksums anyway. verify-store asks for it.
    scfg.verify_index_on_open = verify_index;
    const cfg_ptr = try arena.create(store.Config);
    cfg_ptr.* = scfg;
    const o = try store.openDir(gpa, io, cfg_ptr, .{ .sync = .data });
    return .{ .st = o.store, .rio = o.io, .lock_fd = fd, .restored_epoch = restored };
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    const cmd = args[1];
    const a = parseArgs(args) catch |e| return usageErr(@errorName(e));
    var obuf: [64 << 10]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    const w = &ow.interface;
    defer w.flush() catch {};

    if (std.mem.eql(u8, cmd, "restore-db")) {
        const from = a.from orelse return usageErr("restore-db: --from is required");
        const dir = a.dir orelse return usageErr("restore-db: --dir is required");
        const rep = try dbc.copyTree(gpa, io, from, dir);
        try w.print("restored {s} -> {s}: {d} sealed segments linked ({d} MiB), {d} files cloned ({d} MiB), {d} copied ({d} MiB) in {d} ms\n", .{ from, dir, rep.linked, rep.linked_bytes >> 20, rep.cloned, rep.cloned_bytes >> 20, rep.copied, rep.copied_bytes >> 20, rep.ms });
        var o = try openNode(gpa, io, arena, dir, null, false);
        defer o.close();
        try w.print("store opens: committed checkpoint {?d}, epoch {?d}; start deepwave run --dir {s} to follow from there\n", .{ o.st.committed(), o.st.currentEpoch(), dir });
        return 0;
    }

    const dir = a.dir orelse return usageErr("--dir is required");
    if (std.mem.eql(u8, cmd, "db-checkpoint")) {
        const out = a.out orelse return usageErr("db-checkpoint: --out is required");
        // Open (recovery) and close cleanly so the copy needs no replay; keep the lock while copying.
        var o = try openNode(gpa, io, arena, dir, null, false);
        const c = o.st.committed();
        const e = o.st.currentEpoch();
        o.st.close() catch |err| {
            std.log.err("store close: {s}", .{@errorName(err)});
            return 1;
        };
        o.rio.deinit();
        defer dbc.unlock(o.lock_fd);
        const rep = try dbc.copyTree(gpa, io, dir, out);
        try w.print("db checkpoint of {s} at checkpoint {?d} (epoch {?d}) -> {s}: {d} sealed segments linked ({d} MiB), {d} files cloned ({d} MiB), {d} copied ({d} MiB) in {d} ms\n", .{ dir, c, e, out, rep.linked, rep.linked_bytes >> 20, rep.cloned, rep.cloned_bytes >> 20, rep.copied, rep.copied_bytes >> 20, rep.ms });
        return 0;
    }

    var o = openNode(gpa, io, arena, dir, a.retention, std.mem.eql(u8, cmd, "verify-store")) catch |e| {
        if (e == error.NodeRunning) std.log.err("{s} is in use (node/LOCK): stop deepwave first", .{dir});
        return e;
    };
    defer o.close();
    if (std.mem.eql(u8, cmd, "info")) return info(w, &o);
    if (std.mem.eql(u8, cmd, "print-object")) return printObject(w, &o, a);
    if (std.mem.eql(u8, cmd, "print-checkpoint")) return printCheckpoint(arena, w, &o, a);
    if (std.mem.eql(u8, cmd, "print-transaction")) return printTransaction(w, &o, a);
    if (std.mem.eql(u8, cmd, "verify-store")) return verifyStore(gpa, w, &o, a);
    if (std.mem.eql(u8, cmd, "state-hash")) return stateHash(gpa, arena, w, &o, a);
    if (std.mem.eql(u8, cmd, "snapshot-write")) return snapshotWrite(gpa, io, arena, w, &o, a);
    if (std.mem.eql(u8, cmd, "sui-conservation")) return suiConservation(gpa, io, arena, w, &o, a, dir);
    if (std.mem.eql(u8, cmd, "prune")) return prune(w, &o, a);
    return usageErr("unknown command");
}

fn hex32(buf: *[64]u8, b: *const [32]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{x}", .{b}) catch unreachable;
}

fn info(w: *Io.Writer, o: *Opened) !u8 {
    var snap = o.st.snapshot();
    defer snap.release();
    try w.print("committed checkpoint: {?d}\ncurrent epoch: {?d}\nlowest available checkpoint: {?d}\nhighest pruned checkpoint: {?d}\nrestored from formal snapshot of epoch: {?d}\nlive objects: {d}\n", .{
        o.st.committed(), o.st.currentEpoch(), node.snapshot.lowestAvailable(&snap, o.restored_epoch), snap.highestPruned(), o.restored_epoch, o.st.liveCount(),
    });
    const ls = o.st.liveSlots();
    try w.print("live table: {d} of {d} slots used, {d} pages\nretention epochs: {d}\n", .{ ls.used, ls.capacity, ls.pages, o.st.cfg.retention_epochs });
    const aged = o.st.agedSegments();
    try w.print("aged segments kept for their live objects: {d} ({d} MiB)\nindex runs: {d}\n", .{ aged.count, aged.bytes >> 20, o.st.totalRuns() });
    return 0;
}

fn parseId(text: []const u8) ![32]u8 {
    const t = if (std.mem.startsWith(u8, text, "0x")) text[2..] else text;
    if (t.len == 0 or t.len > 64) return error.BadObjectId;
    var padded: [64]u8 = @splat('0');
    @memcpy(padded[64 - t.len ..], t);
    var id: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&id, &padded);
    return id;
}

fn printObject(w: *Io.Writer, o: *Opened, a: Args) !u8 {
    const id = parseId(a.id orelse return usageErr("print-object: --id is required")) catch return usageErr("print-object: --id is 0x and up to 64 hex digits");
    var snap = o.st.snapshot();
    defer snap.release();
    var hb: [64]u8 = undefined;
    var db: [serve.b58.max_len_32]u8 = undefined;
    const ref: store.ObjectRef = if (a.version) |v| (try snap.objectAtChecked(&id, v)) orelse {
        try w.print("object 0x{s} version {d}: not in the store (retention, or never existed)\n", .{ hex32(&hb, &id), v });
        return 1;
    } else switch ((try snap.latest(&id)) orelse {
        try w.print("object 0x{s}: not in the store\n", .{hex32(&hb, &id)});
        return 1;
    }) {
        .live => |r| r,
        .removed => |r| {
            try w.print("object 0x{s}: {s} at version {d}\n", .{ hex32(&hb, &id), @tagName(r.kind), r.version });
            return 0;
        },
    };
    try w.print("object 0x{s}\nversion: {d}\ndigest: {s}\nbcs bytes: {d}\n", .{ hex32(&hb, &id), ref.version, serve.b58.encode32(&db, &ref.digest), ref.bytes.len });
    const k = exec.objects.keyOf(ref.bytes) catch null;
    if (k) |key| if (key.version != ref.version or !std.mem.eql(u8, &key.id, &id)) try w.print("WARNING: bytes carry 0x{s} version {d}\n", .{ hex32(&hb, &key.id), key.version });
    if (!std.mem.eql(u8, &store.objectDigest(ref.bytes), &ref.digest)) try w.print("WARNING: digest of the bytes differs from the stored digest\n", .{});
    if (a.show_bcs) try w.print("bcs: {x}\n", .{ref.bytes});
    return 0;
}

fn printCheckpoint(arena: std.mem.Allocator, w: *Io.Writer, o: *Opened, a: Args) !u8 {
    const seq = a.seq orelse o.st.committed() orelse return usageErr("print-checkpoint: --seq is required (empty store)");
    var snap = o.st.snapshot();
    defer snap.release();
    const rec = (try snap.checkpointChecked(seq)) orelse {
        try w.print("checkpoint {d}: not in the store (lowest available {?d})\n", .{ seq, snap.lowestAvailable() });
        return 1;
    };
    const cert = try node.trust.splitCert(rec.summary_cert);
    const s = try bcs.decode(types.CheckpointSummary, arena, cert.summary);
    var db: [serve.b58.max_len_32]u8 = undefined;
    var db2: [serve.b58.max_len_32]u8 = undefined;
    const digest = checkpoint.summaryDigest(cert.summary);
    try w.print("checkpoint {d}\ndigest: {s}\nepoch: {d}\ntimestamp_ms: {d}\nnetwork_total_transactions: {d}\ncontent_digest: {s}\n", .{ s.sequence_number, serve.b58.encode32(&db, &digest), s.epoch, s.timestamp_ms, s.network_total_transactions, serve.b58.encode32(&db2, &s.content_digest.@"0".@"0") });
    if (s.previous_digest) |p| try w.print("previous_digest: {s}\n", .{serve.b58.encode32(&db, &p.@"0".@"0")});
    try w.print("end_of_epoch: {s}\nsummary bytes: {d}, signature bytes: {d}, contents bytes: {d}\n", .{ if (s.end_of_epoch_data != null) "yes" else "no", cert.summary.len, cert.sig.len, rec.contents.len });
    if (s.end_of_epoch_data != null) if (node.snapshot.commitmentOf(arena, cert.summary)) |r| {
        var hb: [64]u8 = undefined;
        try w.print("ecmh live object set commitment: {s}\n", .{hex32(&hb, &r)});
    } else |_| {};
    if (a.show_bcs) try w.print("summary bcs: {x}\ncontents bcs: {x}\n", .{ cert.summary, rec.contents });
    return 0;
}

fn printTransaction(w: *Io.Writer, o: *Opened, a: Args) !u8 {
    const text = a.digest orelse return usageErr("print-transaction: --digest is required");
    const d = serve.b58.decode32(text) orelse return usageErr("print-transaction: --digest is base58 (32 bytes)");
    var snap = o.st.snapshot();
    defer snap.release();
    const t = (try snap.transactionChecked(&d)) orelse {
        try w.print("transaction {s}: not in the store\n", .{text});
        return 1;
    };
    var db: [serve.b58.max_len_32]u8 = undefined;
    try w.print("transaction {s}\ncheckpoint: {d}\neffects_digest: {s}\ntransaction bytes: {d}\neffects bytes: {d}\nevents bytes: {d}\n", .{ text, t.checkpoint, serve.b58.encode32(&db, t.effects_digest), t.tx.len, t.effects.len, if (t.events) |e| e.len else 0 });
    if (a.show_bcs) try w.print("transaction bcs: {x}\neffects bcs: {x}\n", .{ t.tx, t.effects });
    return 0;
}

/// Every retained checkpoint record (checksums through checked reads), the previous-digest
/// chain, and each contents digest against its summary; with --live, every live object's bytes
/// against its stored digest.
fn verifyStore(gpa: std.mem.Allocator, w: *Io.Writer, o: *Opened, a: Args) !u8 {
    const top = o.st.committed() orelse {
        try w.print("empty store\n", .{});
        return 0;
    };
    var snap = o.st.snapshot();
    defer snap.release();
    const low = snap.lowestCheckpoint() orelse top;
    var bad: u64 = 0;
    var prev: ?[32]u8 = null;
    var seq = low;
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    while (seq <= top) : (seq += 1) {
        _ = tmp.reset(.retain_capacity);
        const rec = (snap.checkpointChecked(seq) catch |e| {
            try w.print("checkpoint {d}: {s}\n", .{ seq, @errorName(e) });
            bad += 1;
            prev = null;
            continue;
        }) orelse {
            try w.print("checkpoint {d}: missing\n", .{seq});
            bad += 1;
            prev = null;
            continue;
        };
        const cert = node.trust.splitCert(rec.summary_cert) catch {
            try w.print("checkpoint {d}: summary does not decode\n", .{seq});
            bad += 1;
            continue;
        };
        const s = bcs.decode(types.CheckpointSummary, tmp.allocator(), cert.summary) catch {
            try w.print("checkpoint {d}: summary does not decode\n", .{seq});
            bad += 1;
            continue;
        };
        if (s.sequence_number != seq) {
            try w.print("checkpoint {d}: summary says {d}\n", .{ seq, s.sequence_number });
            bad += 1;
        }
        if (prev) |p| if (s.previous_digest == null or !std.mem.eql(u8, &s.previous_digest.?.@"0".@"0", &p)) {
            try w.print("checkpoint {d}: previous_digest does not name checkpoint {d}\n", .{ seq, seq - 1 });
            bad += 1;
        };
        var cd: [32]u8 = undefined;
        {
            var hs = std.crypto.hash.blake2.Blake2b256.init(.{});
            hs.update("CheckpointContents::");
            hs.update(rec.contents);
            hs.final(&cd);
        }
        if (!std.mem.eql(u8, &cd, &s.content_digest.@"0".@"0")) {
            try w.print("checkpoint {d}: contents digest differs from the summary\n", .{seq});
            bad += 1;
        }
        prev = checkpoint.summaryDigest(cert.summary);
    }
    try w.print("checkpoints {d}..{d}: {d} checked, {d} problems\n", .{ low, top, top - low + 1, bad });
    if (a.live) {
        var n: u64 = 0;
        var lbad: u64 = 0;
        const Ctx = struct {
            w: *Io.Writer,
            n: *u64,
            bad: *u64,
            fn check(c: @This(), obj: store.LiveIter.Item) anyerror!void {
                c.n.* += 1;
                if (obj.stored_digest) |sd| if (!std.mem.eql(u8, &sd, &store.objectDigest(obj.bytes))) {
                    c.bad.* += 1;
                    if (c.bad.* <= 20) {
                        var hb: [64]u8 = undefined;
                        try c.w.print("object 0x{s} version {d}: bytes do not match the stored digest\n", .{ hex32(&hb, &obj.id), obj.version });
                    }
                };
            }
        };
        var sc = try store.LiveScan.init(o.st.gpa, o.st, top + 1);
        defer sc.deinit();
        while (sc.next()) |g| try sc.group(g, Ctx{ .w = w, .n = &n, .bad = &lbad }, Ctx.check);
        try w.print("live objects: {d} checked, {d} problems\n", .{ n, lbad });
        bad += lbad;
    }
    return if (bad == 0) 0 else 1;
}

/// The end-of-epoch checkpoint of `epoch` in the store (binary search on epochs), or the newest
/// end-of-epoch checkpoint the store holds when `epoch` is null.
fn endOfEpoch(arena: std.mem.Allocator, o: *Opened, epoch: ?u64) !struct { seq: u64, epoch: u64, root: [32]u8 } {
    var snap = o.st.snapshot();
    defer snap.release();
    const top = o.st.committed() orelse return error.EmptyStore;
    const low = snap.lowestCheckpoint() orelse top;
    const target = epoch orelse blk: {
        const r = (try snap.checkpointChecked(top)) orelse return error.StoreMissingCommitted;
        const s = try bcs.decode(types.CheckpointSummary, arena, (try node.trust.splitCert(r.summary_cert)).summary);
        break :blk if (s.end_of_epoch_data != null) s.epoch else if (s.epoch == 0) return error.NoEpochEnded else s.epoch - 1;
    };
    // last checkpoint with epoch <= target
    var lo = low;
    var hi = top;
    if ((try epochAt(arena, &snap, lo)) > target) return error.EpochNotInStore;
    while (lo < hi) {
        const mid = lo + (hi - lo + 1) / 2;
        if ((try epochAt(arena, &snap, mid)) <= target) lo = mid else hi = mid - 1;
    }
    const rec = (try snap.checkpointChecked(lo)) orelse return error.StoreMissingCommitted;
    const summary = (try node.trust.splitCert(rec.summary_cert)).summary;
    const s = try bcs.decode(types.CheckpointSummary, arena, summary);
    if (s.epoch != target or s.end_of_epoch_data == null) return error.EpochEndNotInStore;
    return .{ .seq = lo, .epoch = target, .root = try node.snapshot.commitmentOf(arena, summary) };
}

fn epochAt(arena: std.mem.Allocator, snap: *const store.Snapshot, seq: u64) !u64 {
    const r = (try snap.checkpointChecked(seq)) orelse return error.StoreMissingCheckpoint;
    _ = arena;
    return r.epoch;
}

fn stateHash(gpa: std.mem.Allocator, arena: std.mem.Allocator, w: *Io.Writer, o: *Opened, a: Args) !u8 {
    const Eoe = struct { seq: u64, epoch: u64, root: [32]u8 };
    const eoe: Eoe = if (a.checkpoint) |c| blk: {
        var snap = o.st.snapshot();
        defer snap.release();
        const rec = (try snap.checkpointChecked(c)) orelse return usageErr("state-hash: checkpoint not in the store");
        const summary = (try node.trust.splitCert(rec.summary_cert)).summary;
        break :blk .{ .seq = c, .epoch = rec.epoch, .root = node.snapshot.commitmentOf(arena, summary) catch return usageErr("state-hash: not an end-of-epoch checkpoint") };
    } else blk: {
        const e = try endOfEpoch(arena, o, a.epoch);
        break :blk .{ .seq = e.seq, .epoch = e.epoch, .root = e.root };
    };
    var objects: Atomic(u64) = .init(0);
    const t0 = node.source.nowNs();
    const root = try snapwrite.liveRoot(gpa, o.st, eoe.seq, a.threads, &objects);
    const ms = (node.source.nowNs() - t0) / std.time.ns_per_ms;
    var h1: [64]u8 = undefined;
    var h2: [64]u8 = undefined;
    const ok = std.mem.eql(u8, &root, &eoe.root);
    try w.print("epoch {d} ends at checkpoint {d}\nlive objects: {d} ({d} ms)\nroot:      {s}\ncertified: {s}\n{s}\n", .{ eoe.epoch, eoe.seq, objects.load(.monotonic), ms, hex32(&h1, &root), hex32(&h2, &eoe.root), if (ok) "EQUAL" else "MISMATCH" });
    return if (ok) 0 else 3;
}

fn suiConservation(gpa: std.mem.Allocator, io: Io, arena: std.mem.Allocator, w: *Io.Writer, o: *Opened, a: Args, dir: []const u8) !u8 {
    const cons = node.conservation;
    const seq: u64 = if (a.checkpoint) |c| c else (try endOfEpoch(arena, o, a.epoch)).seq;
    var progress: Atomic(u64) = .init(0);
    var done: Atomic(bool) = .init(false);
    const Prog = struct {
        fn run(p: *Atomic(u64), d: *Atomic(bool), at: u64) void {
            const t0 = node.source.nowNs();
            var n: u64 = 0;
            while (!d.load(.acquire)) {
                const ts: std.posix.timespec = .{ .sec = 1, .nsec = 0 };
                _ = std.c.nanosleep(&ts, null);
                n += 1;
                if (n % 30 != 0) continue;
                const v = p.load(.monotonic);
                const s = (node.source.nowNs() - t0) / std.time.ns_per_s;
                std.debug.print("sui-conservation: checkpoint {d}: {d} objects in {d} s ({d}/s)\n", .{ at, v, s, v / @max(s, 1) });
            }
        }
    };
    const pt = std.Thread.spawn(.{}, Prog.run, .{ &progress, &done, seq }) catch null;
    defer if (pt) |t| {
        done.store(true, .release);
        t.join();
    };
    std.debug.print("sui-conservation: scanning the live set as of checkpoint {d} ({d} threads)\n", .{ seq, a.threads });
    const r = try cons.scan(gpa, o.st, seq, .{ .threads = a.threads, .progress = &progress });
    done.store(true, .release);
    const ndir_path = try std.fs.path.join(arena, &.{ dir, "node" });
    const ndir = try Io.Dir.cwd().openDir(io, ndir_path, .{});
    defer ndir.close(io);
    const want = cons.loadExpected(io, ndir);
    const v = cons.judge(&r, want);
    try w.print("end-of-epoch checkpoint {d} (system state epoch {d})\nlive objects: {d} ({d} ms)\ntotal SUI:            {d}\nsupply difference:    {d}\ntotal storage rebate: {d}\nstorage fund rebates: {d}\nstorage fund imbalance: {d}\nunresolved objects:   {d}\n", .{ seq, r.epoch, r.totals.objects, r.ms, r.totals.total_sui, r.supplyImbalance(), r.totals.storage_rebate, r.storage_fund, r.imbalance(), r.totals.unresolved });
    if (r.totals.first_unresolved) |u| {
        var hb: [64]u8 = undefined;
        try w.print("first unresolved: 0x{s}\n", .{hex32(&hb, &u)});
    }
    if (want) |e| try w.print("expected:   total SUI {d}, imbalance {d}\n", .{ e.total_sui, e.imbalance });
    try w.print("{s}\n", .{switch (v) {
        .first => "FIRST (no expected values recorded)",
        .ok => "OK",
        .mismatch => "MISMATCH",
        .unresolved => "UNRESOLVED",
    }});
    if (a.save and v != .unresolved) if (r.expected()) |e| {
        try cons.saveExpected(io, ndir, e, r.epoch);
        try w.print("saved as the expected values in {s}/{s}\n", .{ ndir_path, cons.expected_file });
    };
    return switch (v) {
        .first, .ok => 0,
        .mismatch, .unresolved => 3,
    };
}

fn snapshotWrite(gpa: std.mem.Allocator, io: Io, arena: std.mem.Allocator, w: *Io.Writer, o: *Opened, a: Args) !u8 {
    const out_path = a.out orelse return usageErr("snapshot-write: --out is required");
    const eoe = try endOfEpoch(arena, o, a.epoch);
    try Io.Dir.cwd().createDirPath(io, out_path);
    const out = try Io.Dir.cwd().openDir(io, out_path, .{});
    defer out.close(io);
    var stats: snapwrite.Stats = .{};
    const r = snapwrite.write(gpa, io, o.st, out, .{ .epoch = eoe.epoch, .checkpoint = eoe.seq, .expect_root = eoe.root, .threads = a.threads, .compression = a.compression }, &stats) catch |e| {
        try w.print("snapshot of epoch {d}: {s}; nothing published\n", .{ eoe.epoch, @errorName(e) });
        return 1;
    };
    var hb: [64]u8 = undefined;
    try w.print("snapshot of epoch {d} (checkpoint {d}) -> {s}/epoch_{d}\nobjects: {d}, object bytes: {d} MiB, stored: {d} MiB in {d} files, {d} s\nroot {s} equals the certified commitment\n", .{ eoe.epoch, eoe.seq, out_path, eoe.epoch, r.objects, r.bytes >> 20, r.stored >> 20, r.files, r.ms / 1000, hex32(&hb, &r.root) });
    return 0;
}

fn prune(w: *Io.Writer, o: *Opened, a: Args) !u8 {
    if (a.retention == null) return usageErr("prune: --retention-epochs is required");
    const rep = try o.st.ageRetained();
    var total: store.PruneReport = .{};
    var steps: u64 = 0;
    while (true) : (steps += 1) {
        const r = try o.st.cleanStep(64 << 20);
        if (r.idle) break;
        total.segments_dropped += r.segments_dropped;
        total.bytes_dropped += r.bytes_dropped;
        total.objects_carried += r.objects_carried;
        total.tombstones_dropped += r.tombstones_dropped;
    }
    var snap = o.st.snapshot();
    defer snap.release();
    try w.print("window: {d} epochs; {d} segments left it ({d} runs dropped); cleaning: {d} segments deleted ({d} MiB), {d} live objects carried, {d} tombstones dropped in {d} steps\nlowest available checkpoint: {?d}\n", .{ a.retention.?, rep.segments_aged, rep.runs_dropped, total.segments_dropped, total.bytes_dropped >> 20, total.objects_carried, total.tombstones_dropped, steps, node.snapshot.lowestAvailable(&snap, o.restored_epoch) });
    return 0;
}
