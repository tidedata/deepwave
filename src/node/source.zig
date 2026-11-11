//! Checkpoint sources and the fetch-ahead stage.
//!
//! A source turns a sequence number into a checkpoint blob (`0x01 ++ BCS(CheckpointData)`):
//!   dir   a local directory of `<seq>.chk` blobs or `<seq>.binpb.zst` archive protos;
//!   s3    Mysten's archive (`<seq>.binpb.zst`, requester pays), converted by `convert.zig`.
//! Sources are untrusted: the follower verifies every blob before the store sees it.
//!
//! `Fetcher` runs N threads that fetch ahead of the follower into the spool directory
//! (`<seq>.chk`, written to a temporary name and renamed, so a reader never sees half a file).
//! A claim is allowed only `window` checkpoints past the follower's applied position, so memory
//! and disk stay bounded. At the tip, only the thread holding the frontier (the lowest sequence
//! not known to exist) polls the source every `poll_ms`; the others wait for it, so a caught-up
//! node makes about one request per poll interval plus one per checkpoint. The spool is a cache for one process lifetime: it is emptied at
//! start, and files are deleted once their checkpoint is committed.
const std = @import("std");
const memstat = @import("memstat.zig");
const Io = std.Io;
const convert = @import("convert.zig");
const sigorder = @import("sigorder.zig");
const s3 = @import("s3.zig");
const http = @import("http.zig");
const edge = @import("edge");
const edgewire = @import("edgewire");
const types = @import("types");
const Atomic = std.atomic.Value;
const Metrics = struct {
    fn max(slot: *Atomic(u64), n: u64) void {
        var cur = slot.load(.monotonic);
        while (n > cur) cur = slot.cmpxchgWeak(cur, n, .monotonic, .monotonic) orelse return;
    }
};

pub const max_blob: usize = 1 << 30;

pub const Kind = union(enum) {
    dir: Io.Dir,
    s3: *s3.Bucket,
    /// Mysten's public bucket (checkpoints.mainnet.sui.io), with an optional S3 fallback.
    http: *http.Public,
    /// Core nodes over zui/1 (`--source zui1:ADDR/KEY,...`, src/edge, docs/EDGE.md): edge feeds
    /// rebuilt into blobs. Untrusted like every source: the follower verifies each blob.
    zui1: *edge.client.Pool,
    /// No source (`--p2p-only`): every checkpoint is missing.
    none,
};

pub const Result = enum { ok, missing };

/// What a fetcher's scratch keeps across checkpoints (arena, raw and aux bytes each).
pub const scratch_keep: usize = 4 << 20;

/// Per-thread buffers for `fetch`.
pub const Scratch = struct {
    raw: std.ArrayList(u8) = .empty,
    /// After a fetch: the checkpoint's aux record (convert.Aux), empty when the source has none
    /// (a `.chk` without a kept `.aux`).
    aux: std.ArrayList(u8) = .empty,
    arena: std.heap.ArenaAllocator,
    /// Bytes last added to memstat's `fetch_scratch` gauge.
    kept: u64 = 0,
    /// Edge fallback only (`feedForm`): the second blob buffer and the checkpoint index, made
    /// at the first checkpoint this thread takes from the fallback.
    tmp: std.ArrayList(u8) = .empty,
    idx: ?*types.CheckpointIndex = null,
    /// After a `fetchRaw` that returned a blob: a core's feed served it (a zui1 source). False
    /// for everything else, an edge's fallback included: such a checkpoint carries a quorum
    /// certificate that is not the core's (edge/certs.zig).
    from_core: bool = false,

    pub fn init(gpa: std.mem.Allocator) Scratch {
        return .{ .arena = .init(gpa) };
    }
    pub fn deinit(s: *Scratch, gpa: std.mem.Allocator) void {
        s.raw.deinit(gpa);
        s.aux.deinit(gpa);
        s.tmp.deinit(gpa);
        if (s.idx) |i| {
            i.deinit(gpa);
            gpa.destroy(i);
        }
        s.arena.deinit();
    }
};

/// Rewrites the full checkpoint blob in `out` to its feed form (edgewire `feed.feedForm`: no
/// input objects) and drops its aux record: exactly what a core's feed of the same checkpoint
/// rebuilds to. Every consumer of an edge's blobs (the store, the rpc and ledger-history indexes,
/// which read a blob's input objects when it has them) then sees the same bytes whichever source
/// served the checkpoint.
pub fn feedForm(gpa: std.mem.Allocator, sc: *Scratch, out: *std.ArrayList(u8)) !void {
    if (sc.idx == null) {
        const i = try gpa.create(types.CheckpointIndex);
        errdefer gpa.destroy(i);
        i.* = try types.CheckpointIndex.init(gpa);
        sc.idx = i;
    }
    const idx = sc.idx.?;
    types.indexCheckpointData(out.items, idx) catch return error.BadData;
    sc.tmp.clearRetainingCapacity();
    try edgewire.feed.feedForm(&sc.tmp, gpa, sc.arena.allocator(), out.items, idx);
    std.mem.swap(std.ArrayList(u8), out, &sc.tmp);
    sc.aux.clearRetainingCapacity();
}

/// The longest a sleeping fetch thread goes without looking at its stop flag.
pub const stop_slice_ms: u64 = 20;

/// Tells the whole fetch stage to stop, without waiting for it: the fetch threads and, for a
/// zui1 source, the core pool (a connect or a request in progress ends at its next turn), the
/// fallback's waits and the prober's probe in progress. The node calls this when it stops the
/// follower and again before it joins the fetch threads (`Fetcher.stop`). Every flag is set
/// before any join, and none of them waits on the network: a core that stopped answering, a
/// response half received or a switch to the fallback in progress end within a few milliseconds
/// of the call. Until then the fallback's flag was set alone: fetch threads saw the stop as a
/// source error (`SourceUnavailable`, a retry line and a backoff sleep), and one inside a core
/// call waited for the network, up to the grace with a fallback (3 s) and the pool's connect and
/// request timeouts without one (5 s and 20 s per core), with the node's stop deadline running.
pub fn requestStop(f: ?*Fetcher, src: *const Source, prober: ?*edge.fallback.Prober) void {
    if (f) |x| x.requestStop();
    if (src.edge_fb) |fb| fb.stopping.store(true, .release);
    switch (src.kind) {
        .zui1 => |p| p.stop(),
        .http => |h| {
            h.stopping.store(true, .release);
            if (h.fallback) |b| b.stopping.store(true, .release);
        },
        .s3 => |b| b.stopping.store(true, .release),
        .dir, .none => {},
    }
    if (src.edge_fb) |fb| if (fb.src.kind == .http) fb.src.kind.http.stopping.store(true, .release);
    if (prober) |p| p.stopping.store(true, .release);
}

/// The second way to the same checkpoints for a zui1 source (`--edge-fallback`, docs/EDGE.md
/// section 10): when no core can serve the next checkpoint, the edge takes it from `src` (the
/// public bucket, or a directory) and returns to the cores when they are healthy again. The
/// rules are edge/fallback.zig's `Switch`; this is the fetch path that follows them. Whatever
/// side a checkpoint comes from, the follower gets the feed-form blob (`feedForm`) and verifies it.
pub const EdgeFallback = struct {
    // (Explicit `anyerror` below: these call `Source`'s methods on `src`, and `Source`'s call
    // them back, so the error sets cannot be inferred.)
    /// Where checkpoints come from while the cores cannot serve them. Never a zui1 source.
    src: Source,
    sw: edge.fallback.Switch = .{},
    /// The follower's next checkpoint to apply: the lowest the edge still needs (what a core
    /// must still hold for the edge to return to it). Null until the follower exists.
    applied_next: ?*const Atomic(u64) = null,
    /// Set at shutdown: a call waiting out the grace returns `SourceUnavailable`.
    stopping: Atomic(bool) = .init(false),
    /// Returns to the cores (`sw.stats.to_core`) the pool's connections were retired for.
    retired: Atomic(u64) = .init(0),

    const Pool = edge.client.Pool;
    const now = edge.fallback.nowNs;

    /// The pause between two tries inside the grace; a stop ends it.
    fn pause(fb: *EdgeFallback, io: Io) void {
        var left: u64 = @max(1, fb.sw.t.retry_ms);
        while (left > 0 and !fb.stopping.load(.acquire)) {
            const step = @min(left, stop_slice_ms);
            io.sleep(.fromMilliseconds(@intCast(step)), .awake) catch return;
            left -= step;
        }
    }

    /// Before a core call: after a return to the cores, the connections opened before it are
    /// closed and opened again (client.zig `Pool.retire`). What they saw during the spell on the
    /// fallback (the shutdown notice of a core since restarted, a core that went silent) is not
    /// news about the cores now, and must not send the edge straight back to the fallback.
    fn freshPool(fb: *EdgeFallback, p: *Pool) void {
        const backs = fb.sw.stats.to_core.load(.acquire);
        const seen = fb.retired.load(.acquire);
        if (backs != seen and fb.retired.cmpxchgStrong(seen, backs, .acq_rel, .monotonic) == null) p.retire();
    }

    /// A core call failed with `e`; `since` is when this caller's run of unanswered tries began.
    /// True: the edge is on the fallback now. False: still inside the grace; the caller pauses
    /// and asks the cores again.
    fn failed(fb: *EdgeFallback, io: Io, p: *Pool, since: u64, e: anyerror, seq: u64) bool {
        const why: edge.fallback.Reason = switch (e) {
            error.NoEdgeFeed => .no_feed,
            error.WrongChain => .wrong_chain,
            // the core said it is going away and no other core answered in this call
            else => if (p.shutdown_ns.load(.monotonic) >= since) .shutdown else .silent,
        };
        return fb.sw.coreFailed(now(io), since, why, seq);
    }

    fn fetchRaw(fb: *EdgeFallback, s: *const Source, p: *Pool, sc: *Scratch, seq: u64, out: *std.ArrayList(u8)) anyerror!Source.Raw {
        if (fb.applied_next) |an| fb.sw.need.store(an.load(.acquire), .monotonic);
        // When this call's run of unanswered tries began (0: none yet). Its grace runs from
        // there even if the cores answer other threads meanwhile: a core that serves every
        // checkpoint but this one must not hold the edge on it.
        var first: u64 = 0;
        while (true) {
            if (fb.stopping.load(.acquire)) return error.SourceUnavailable;
            if (fb.sw.mode() == .fallback) return fb.fromFallback(s, sc, seq, out);
            fb.freshPool(p);
            const t0 = now(s.io);
            const since = if (first != 0) first else t0;
            var fail: edge.client.Fail = .{};
            const r = p.fetchBlobBy(sc.arena.allocator(), seq, out, fb.sw.deadline(since), &fail) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    // The node is stopping (the pool was stopped under the call): not a word
                    // about the cores, so no grace clock, no switch and no pause.
                    if (fb.stopping.load(.acquire)) return error.SourceUnavailable;
                    // A response that was under way when the link failed: the core answered
                    // until its last byte, so a long transfer that breaks is not 3 s of silence.
                    const transport = e == error.Closed or e == error.StreamGone or e == error.Timeout;
                    first = since;
                    if (transport and fail.progress_ns > since) {
                        fb.sw.coreAnswered();
                        first = fail.progress_ns;
                    }
                    if (!fb.failed(s.io, p, first, e, seq)) fb.pause(s.io);
                    continue;
                },
            };
            if (r == .ok) {
                fb.sw.fetched(.core, seq);
                sc.from_core = true;
                return .blob;
            }
            // Below every core's retention: no core will ever hold it.
            if (p.pruned_seq.load(.monotonic) == seq) {
                fb.sw.behind(now(s.io), seq, .pruned);
                continue;
            }
            // "Not held yet": the tip, unless the cores are behind. After `behind_after_ms` of it
            // for the lowest checkpoint wanted, the fallback is asked whether it has it.
            if (fb.sw.coreMissed(now(s.io), seq)) {
                const there = fb.src.exists(seq) catch false;
                fb.sw.behindChecked();
                if (there) {
                    fb.sw.behind(now(s.io), seq, .behind);
                    continue;
                }
            }
            return .missing;
        }
    }

    /// Checkpoint `seq` from the fallback side. A ready blob comes back in feed form; an archive
    /// proto is put in feed form by `Source.decode` (the fetcher claims between the two steps).
    fn fromFallback(fb: *EdgeFallback, s: *const Source, sc: *Scratch, seq: u64, out: *std.ArrayList(u8)) anyerror!Source.Raw {
        const r = try fb.src.fetchRaw(sc, seq, out);
        if (r == .blob) {
            try feedForm(s.gpa, sc, out);
            fb.sw.fetched(.fallback, seq);
        }
        return r;
    }

    /// Checkpoint `seq` from the fallback whatever the switch says, as a feed-form blob in `out`
    /// (the node's second try for a checkpoint whose core feed failed verification).
    pub fn fetchFromFallback(fb: *EdgeFallback, s: *const Source, sc: *Scratch, seq: u64, out: *std.ArrayList(u8)) anyerror!Result {
        switch (try fb.src.fetchRaw(sc, seq, out)) {
            .missing => return .missing,
            .blob => try feedForm(s.gpa, sc, out),
            .zst => {
                const proto = convert.unzstdArena(sc.arena.allocator(), sc.raw.items, max_blob) catch |e| switch (e) {
                    error.OutOfMemory => return e,
                    else => return error.BadData,
                };
                try decodeProto(s.gpa, sc, proto, seq, out);
                try feedForm(s.gpa, sc, out);
            },
        }
        fb.sw.fetched(.fallback, seq);
        return .ok;
    }

    fn exists(fb: *EdgeFallback, s: *const Source, p: *Pool, seq: u64) anyerror!bool {
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        var first: u64 = 0;
        while (true) {
            if (fb.stopping.load(.acquire)) return error.SourceUnavailable;
            if (fb.sw.mode() == .fallback) return fb.src.exists(seq);
            fb.freshPool(p);
            const t0 = now(s.io);
            const since = if (first != 0) first else t0;
            const there = p.existsBy(arena.allocator(), seq, fb.sw.deadline(since)) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    if (fb.stopping.load(.acquire)) return error.SourceUnavailable;
                    first = since;
                    if (!fb.failed(s.io, p, since, e, seq)) fb.pause(s.io);
                    continue;
                },
            };
            fb.sw.coreAnswered();
            return there;
        }
    }

    /// The floor of a tip search from `lo`: the lowest checkpoint the core in use holds, or `lo`
    /// itself when the edge is on the fallback.
    fn searchFloor(fb: *EdgeFallback, s: *const Source, p: *Pool, lo: u64) anyerror!u64 {
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        var first: u64 = 0;
        while (true) {
            if (fb.stopping.load(.acquire)) return error.SourceUnavailable;
            if (fb.sw.mode() == .fallback) return lo;
            fb.freshPool(p);
            const t0 = now(s.io);
            const since = if (first != 0) first else t0;
            const held = p.lowestHeldBy(arena.allocator(), fb.sw.deadline(since)) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    if (fb.stopping.load(.acquire)) return error.SourceUnavailable;
                    first = since;
                    if (!fb.failed(s.io, p, since, e, lo)) fb.pause(s.io);
                    continue;
                },
            };
            fb.sw.coreAnswered();
            return @max(lo, held);
        }
    }
};

pub const Source = struct {
    gpa: std.mem.Allocator,
    io: Io,
    kind: Kind,
    /// A zui1 source's fallback (`--edge-fallback`); null: the cores are the only source.
    edge_fb: ?*EdgeFallback = null,

    /// Fetches checkpoint `seq` as a blob into `out`.
    pub fn fetch(s: *const Source, sc: *Scratch, seq: u64, out: *std.ArrayList(u8)) !Result {
        switch (try s.fetchRaw(sc, seq, out)) {
            .missing => return .missing,
            .blob => return .ok,
            .zst => {
                try s.decode(sc, seq, out);
                return .ok;
            },
        }
    }

    pub const Raw = enum {
        /// An archive proto, zstd-compressed, in `sc.raw`: `decode` turns it into a blob.
        zst,
        /// A ready blob in `out` (a `.chk` file), its aux record in `sc.aux` (empty if none).
        blob,
        missing,
    };

    /// Step one of `fetch`: the source's bytes for `seq`, no decoding. The fetcher claims the
    /// checkpoint between the two steps, so a duplicate download (several tip requests in flight
    /// when the object appears) costs no decode.
    pub fn fetchRaw(s: *const Source, sc: *Scratch, seq: u64, out: *std.ArrayList(u8)) !Raw {
        // Keep a typical checkpoint's worth, not the largest one seen (one scratch per fetcher).
        _ = sc.arena.reset(.{ .retain_with_limit = scratch_keep });
        if (sc.raw.capacity > scratch_keep) sc.raw.clearAndFree(s.gpa);
        if (sc.aux.capacity > scratch_keep) sc.aux.clearAndFree(s.gpa);
        if (sc.tmp.capacity > scratch_keep) sc.tmp.clearAndFree(s.gpa);
        sc.aux.clearRetainingCapacity();
        sc.from_core = false;
        memstat.keep(.fetch_scratch, &sc.kept, sc.arena.queryCapacity() + sc.raw.capacity + sc.aux.capacity + sc.tmp.capacity);
        var nb: [48]u8 = undefined;
        switch (s.kind) {
            .dir => |d| {
                const chk = std.fmt.bufPrint(&nb, "{d}.chk", .{seq}) catch unreachable;
                if (try readInto(s.io, d, chk, s.gpa, out)) {
                    const ax = std.fmt.bufPrint(&nb, "{d}.aux", .{seq}) catch unreachable;
                    if (!try readInto(s.io, d, ax, s.gpa, &sc.aux)) sc.aux.clearRetainingCapacity();
                    return .blob;
                }
                const pb = std.fmt.bufPrint(&nb, "{d}.binpb.zst", .{seq}) catch unreachable;
                if (!try readInto(s.io, d, pb, s.gpa, &sc.raw)) return .missing;
            },
            .s3 => |b| {
                const key = std.fmt.bufPrint(&nb, "{d}.binpb.zst", .{seq}) catch unreachable;
                if (try b.get(key, &sc.raw) == .missing) return .missing;
                // The download cap (--net-max-mbps): s3.zig cannot pace inside a body, so the
                // object is booked once it is in and this thread waits until it is paid for.
                // (The public bucket books inside its own read loop, http.zig.)
                http.net_cap.charge(s.io, sc.raw.items.len);
            },
            .http => |h| if (try h.get(seq, &sc.raw) == .missing) return .missing,
            .zui1 => |p| {
                if (s.edge_fb) |fb| return fb.fetchRaw(s, p, sc, seq, out);
                const r = p.fetchBlob(sc.arena.allocator(), seq, out) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.BadData, error.TooLarge => return error.BadData,
                    else => return error.SourceUnavailable,
                };
                if (r == .missing) return .missing;
                sc.from_core = true;
                return .blob;
            },
            .none => return .missing,
        }
        return .zst;
    }

    /// Can this source take several checkpoints in one pipelined call now (`fetchRun`)? A core
    /// pool can; an edge on its fallback, or stopping, cannot.
    pub fn pipelines(s: *const Source) bool {
        if (s.kind != .zui1) return false;
        const fb = s.edge_fb orelse return true;
        return fb.sw.mode() == .core and !fb.stopping.load(.acquire);
    }

    /// The checkpoints `first .. first + results.len` from the core pool in one pipelined call
    /// (client.zig `Pool.fetchBlobs`): each blob that comes back goes to `sink`. With a
    /// fallback the call is bounded by the grace like a single one, but its failure is no
    /// verdict on the cores: the caller asks again through `fetchRaw`, whose rules decide.
    pub fn fetchRun(s: *const Source, sc: *Scratch, first: u64, results: []edge.client.Pool.BatchItem, out: *std.ArrayList(u8), sink: edge.client.Pool.Sink, times: *edge.client.Pool.CallTimes) !void {
        const p = s.kind.zui1;
        _ = sc.arena.reset(.{ .retain_with_limit = scratch_keep });
        sc.aux.clearRetainingCapacity();
        const by = if (s.edge_fb) |fb| fb.sw.deadline(EdgeFallback.now(s.io)) else edge.client.Pool.no_deadline;
        try p.fetchBlobs(sc.arena.allocator(), first, results, out, sink, by, times);
        if (s.edge_fb) |fb| for (results, 0..) |r, k| if (r == .ok) fb.sw.fetched(.core, first + k);
    }

    /// Step two of `fetch`: the zstd archive proto in `sc.raw` to a blob in `out` and its aux
    /// record in `sc.aux`.
    pub fn decode(s: *const Source, sc: *Scratch, seq: u64, out: *std.ArrayList(u8)) !void {
        const proto = convert.unzstdArena(sc.arena.allocator(), sc.raw.items, max_blob) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => return error.BadData,
        };
        try decodeProto(s.gpa, sc, proto, seq, out);
        return s.edgeForm(sc, seq, out);
    }

    /// After a conversion: a zui1 source only converts what its fallback served, and hands the
    /// follower the feed form of it (`feedForm`), as for a core's feed.
    fn edgeForm(s: *const Source, sc: *Scratch, seq: u64, out: *std.ArrayList(u8)) !void {
        if (s.kind != .zui1) return;
        try feedForm(s.gpa, sc, out);
        if (s.edge_fb) |fb| fb.sw.fetched(.fallback, seq);
    }

    /// `decode`, restoring the submitted signature order from `ov` (sigorder.zig) when the proto
    /// carries none and its contents certify a list of two or more signatures. Without `ov`, or
    /// when the overlay is unavailable, the same as `decode` (the contents order).
    pub fn decodeOrdered(s: *const Source, sc: *Scratch, seq: u64, out: *std.ArrayList(u8), ov: ?*sigorder.Overlay) !void {
        const o = ov orelse return s.decode(sc, seq, out);
        const a = sc.arena.allocator();
        const proto = convert.unzstdArena(a, sc.raw.items, max_blob) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => return error.BadData,
        };
        var opts: convert.Options = .{};
        const wants = convert.wantsSigOrder(a, proto) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => false, // the conversion reports the bad bytes
        };
        if (wants) opts.sig_overlay = o.get(a, seq);
        try decodeProtoOpts(s.gpa, sc, proto, seq, out, opts);
        return s.edgeForm(sc, seq, out);
    }
    /// Does checkpoint `seq` exist at the source (one cheap request)?
    pub fn exists(s: *const Source, seq: u64) !bool {
        var nb: [48]u8 = undefined;
        switch (s.kind) {
            .dir => |d| {
                inline for (.{ "{d}.chk", "{d}.binpb.zst" }) |f| {
                    const name = std.fmt.bufPrint(&nb, f, .{seq}) catch unreachable;
                    if (d.statFile(s.io, name, .{})) |_| return true else |_| {}
                }
                return false;
            },
            .s3 => |b| return b.exists(std.fmt.bufPrint(&nb, "{d}.binpb.zst", .{seq}) catch unreachable),
            .http => |h| return h.exists(seq),
            .zui1 => |p| {
                if (s.edge_fb) |fb| return fb.exists(s, p, seq);
                var arena = std.heap.ArenaAllocator.init(s.gpa);
                defer arena.deinit();
                return p.exists(arena.allocator(), seq) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => {
                        std.log.warn("source zui/1: checkpoint {d}: {s}", .{ seq, @errorName(e) });
                        return error.SourceUnavailable;
                    },
                };
            },
            .none => return false,
        }
    }

    /// The highest sequence number at the source, searching up from `lo` (which must exist):
    /// doubling steps, then bisection. About 2 log2(tip - lo) requests.
    pub fn latest(s: *const Source, lo_in: u64) !u64 {
        var lo = lo_in;
        if (s.kind == .zui1) if (s.edge_fb) |fb| {
            lo = try fb.searchFloor(s, s.kind.zui1, lo);
        } else {
            var arena = std.heap.ArenaAllocator.init(s.gpa);
            defer arena.deinit();
            const held = s.kind.zui1.lowestHeld(arena.allocator()) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    std.log.warn("source zui/1: no core answered hello ({s})", .{@errorName(e)});
                    return error.SourceUnavailable;
                },
            };
            lo = @max(lo, held);
        };
        if (!try s.exists(lo)) return error.SourceMissing;
        var step: u64 = 1;
        var hi: u64 = lo +| step;
        while (try s.exists(hi)) {
            // No real chain gets here; a source that says every number exists would spin forever.
            if (hi == std.math.maxInt(u64)) return error.SourceUnavailable;
            lo = hi;
            step *|= 2;
            hi = lo +| step;
        }
        // lo exists, hi does not
        while (hi - lo > 1) {
            const mid = lo + (hi - lo) / 2;
            if (try s.exists(mid)) lo = mid else hi = mid;
        }
        return lo;
    }
};

/// A `sui.rpc.v2.Checkpoint` proto (uncompressed) to a blob in `out` and its aux record in
/// `sc.aux`; `error.WrongCheckpoint` unless it is checkpoint `seq`.
pub fn decodeProto(gpa: std.mem.Allocator, sc: *Scratch, proto: []const u8, seq: u64, out: *std.ArrayList(u8)) !void {
    return decodeProtoOpts(gpa, sc, proto, seq, out, .{});
}

/// `decodeProto` with conversion `Options`.
pub fn decodeProtoOpts(gpa: std.mem.Allocator, sc: *Scratch, proto: []const u8, seq: u64, out: *std.ArrayList(u8), opts: convert.Options) !void {
    sc.aux.clearRetainingCapacity();
    const got = convert.protoToChkOpts(gpa, sc.arena.allocator(), proto, out, &sc.aux, opts) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => return error.BadData,
    };
    if (got != seq) return error.WrongCheckpoint;
}

fn readInto(io: Io, d: Io.Dir, name: []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) !bool {
    const f = d.openFile(io, name, .{}) catch |e| switch (e) {
        error.FileNotFound => return false,
        else => return e,
    };
    defer f.close(io);
    const size: usize = @intCast((try f.stat(io)).size);
    try out.ensureTotalCapacity(gpa, size);
    out.items.len = size;
    const n = try f.readPositionalAll(io, out.items, 0);
    if (n != size) return error.ShortRead;
    return true;
}

/// The fetch stage's in-flight control for a zui1 source (`--feed-max-inflight`): the rules are
/// edge/inflight.zig's `Controller`; this is what the fetch threads share to feed it and to
/// read its answer. Only catch-up uses it: at the tip a fetch thread asks one request at a
/// time, as without it.
pub const InFlight = struct {
    ctl: edge.inflight.Controller,
    mu: std.atomic.Mutex = .unlocked,
    /// Requests to keep in flight now (the controller's last answer).
    target: Atomic(u32),
    /// The follower's time spent waiting for its next checkpoint (sync metrics `stall_ns`).
    /// Null: unknown, and the count never grows.
    stall_ns: ?*const Atomic(u64) = null,
    /// Pipelined calls that failed or were refused.
    errors: Atomic(u64) = .init(0),
    /// Smoothed times of a pipelined call: to its first response byte, and to its last.
    first_byte_ns: Atomic(u64) = .init(0),
    call_ns: Atomic(u64) = .init(0),
    /// Requests in flight in pipelined calls now, and the most there ever were.
    now: Atomic(u32) = .init(0),
    peak: Atomic(u32) = .init(0),
    /// Pipelined calls and the checkpoints they brought.
    calls: Atomic(u64) = .init(0),
    fetched: Atomic(u64) = .init(0),

    /// The most requests one fetch thread sends in one call.
    pub const max_depth = 32;

    /// `floor`: the fetch threads (one request each, the profile's count); `cap`:
    /// `--feed-max-inflight`; `window`: the fetch window.
    pub fn init(floor: u32, cap: u32, window: u32) InFlight {
        const ctl = edge.inflight.Controller.init(.{ .floor = @max(1, floor), .cap = cap, .window = window });
        return .{ .ctl = ctl, .target = .init(ctl.target) };
    }

    /// One sample for the controller (by whichever fetch thread gets here first); the count
    /// to keep in flight.
    fn decide(fl: *InFlight, f: *const Fetcher, at_tip: bool) u32 {
        if (!fl.mu.tryLock()) return fl.target.load(.acquire);
        defer fl.mu.unlock();
        const t = fl.ctl.tick(.{
            .now_ns = nowNs(),
            .applied = f.applied_next.load(.acquire),
            .fetched = f.stats.fetched.load(.monotonic),
            .stall_ns = if (fl.stall_ns) |p| p.load(.monotonic) else 0,
            .errors = fl.errors.load(.monotonic),
            .first_byte_ns = fl.first_byte_ns.load(.monotonic),
            .call_ns = fl.call_ns.load(.monotonic),
            .at_tip = at_tip,
        });
        fl.target.store(t, .release);
        return t;
    }

    fn smooth(slot: *Atomic(u64), v: u64) void {
        const old = slot.load(.monotonic);
        slot.store(if (old == 0) v else (old * 7 + v) / 8, .monotonic);
    }

    fn noteCall(fl: *InFlight, times: edge.client.Pool.CallTimes, got: u32) void {
        _ = fl.calls.fetchAdd(1, .monotonic);
        _ = fl.fetched.fetchAdd(got, .monotonic);
        if (times.first_byte_ns != 0) smooth(&fl.first_byte_ns, times.first_byte_ns);
        if (times.total_ns != 0) smooth(&fl.call_ns, times.total_ns);
    }

    fn noteError(fl: *InFlight) void {
        _ = fl.errors.fetchAdd(1, .monotonic);
    }
};

pub const FetcherStats = struct {
    fetched: Atomic(u64) = .init(0),
    bytes: Atomic(u64) = .init(0),
    misses: Atomic(u64) = .init(0),
    errors: Atomic(u64) = .init(0),
    /// Errors from the network or the local disk (retried forever with backoff).
    transient_errors: Atomic(u64) = .init(0),
    /// Errors in the bytes the source served (zstd, protobuf, wrong checkpoint): retried
    /// `max_bad` times, then the node stops.
    bad_data: Atomic(u64) = .init(0),
    /// Highest sequence number fetched so far (the source's tip as far as we know).
    highest: Atomic(u64) = .init(0),
    /// Times the node found itself behind the tip and went back to parallel fetching.
    behind: Atomic(u64) = .init(0),
    /// Time in requests that returned bytes, and in zstd + proto conversion.
    fetch_ns: Atomic(u64) = .init(0),
    decode_ns: Atomic(u64) = .init(0),
    /// Tip requests by threads waiting on their own claim, on behalf of the frontier, and hits.
    helper_gets: Atomic(u64) = .init(0),
    helper_hits: Atomic(u64) = .init(0),
    /// Lookahead requests past the frontier (one per frontier move, see `Fetcher.lookahead`),
    /// hits and misses.
    lookahead_gets: Atomic(u64) = .init(0),
    lookahead_hits: Atomic(u64) = .init(0),
    lookahead_misses: Atomic(u64) = .init(0),
    /// One-byte tip probes made while the live stream carried the tip (gap filling only).
    probes: Atomic(u64) = .init(0),
    /// Hits on a checkpoint another thread had already written (helper and owner raced).
    dup_hits: Atomic(u64) = .init(0),
};

/// Where a checkpoint (or its certified summary) showed up. `push`/`poll`: the certified summary
/// over p2p (PushCheckpointSummary, GetCheckpointAvailability); `p2p_contents`: its contents over
/// p2p; `p2p_built`: built locally from p2p and in the spool; `stream`: the fullnode stream;
/// `bucket`: the public bucket (or S3).
pub const SeenSrc = enum(u8) { push, poll, p2p_contents, p2p_built, stream, bucket };
pub const n_seen_src = @typeInfo(SeenSrc).@"enum".field_names.len;

pub const Fetcher = struct {
    gpa: std.mem.Allocator,
    io: Io,
    source: *const Source,
    spool: Io.Dir,
    threads: []std.Thread = &.{},
    /// Next sequence number to claim.
    next: Atomic(u64),
    /// The follower's next sequence to apply (set by the node).
    applied_next: *const Atomic(u64),
    window: u64,
    poll_ms: u32,
    to: u64,
    /// Lowest sequence number not known to exist: set by the first miss (the tip), then moved one
    /// past each checkpoint that arrives. Threads above it wait, so a caught-up node polls with
    /// one request at a time. Max (no limit) until the first miss, so catch-up runs in parallel.
    frontier: Atomic(u64) = .init(std.math.maxInt(u64)),
    /// Frontier checkpoints in a row that were already there at their first request. At the tip
    /// the poller misses a few times before each one appears; a run of first-try hits means the
    /// node fell behind (a stall, a sleep, a network outage), so the frontier is lifted and
    /// catch-up runs in parallel again until the next miss.
    frontier_hits: Atomic(u32) = .init(0),
    /// Frontier first-try hits in a row that lift it.
    behind_hits: u32 = 4,
    stopping: Atomic(bool) = .init(false),
    stats: FetcherStats = .{},
    /// When (`nowNs`) the source last answered a request for a checkpoint at the tip: its bytes,
    /// or "not there yet" (0: never). An edge's freshness guard reads it (`tipKnown`,
    /// `silentNs`; src/edge/forward.zig): a source that answers nothing cannot say where the tip is.
    answered_ns: Atomic(u64) = .init(0),
    /// Keep committed blobs in the spool (`--keep-spool`), so `deepwave check` can compare the
    /// whole store with what the source served after a live run.
    keep: bool = false,
    /// A fetch that fails this many times in a row with a non-transient error (the source served
    /// bytes that do not convert, or the wrong checkpoint) stops the node instead of retrying.
    max_bad: u32 = 8,
    /// Set when a sequence number hit `max_bad`; the node stops on it.
    stuck: Atomic(u64) = .init(std.math.maxInt(u64)),
    /// The wait before a failed fetch is tried again: `retry_ms` after the first failure of a
    /// checkpoint, doubled each time up to `retry_max_ms`.
    retry_ms: u64 = 100,
    retry_max_ms: u64 = 10_000,
    /// In-flight control for a zui1 source in catch-up (`InFlight`); null: one request per
    /// fetch thread, always.
    inflight: ?*InFlight = null,
    /// The archive publishes checkpoints in bursts (several appear at once, then nothing for up
    /// to a second). Threads waiting on the next `lookahead` sequence numbers past the frontier
    /// each make one immediate request every time the frontier moves, so a burst lands in one
    /// round trip, not one round trip each; a miss sends them back to the shared tip schedule.
    /// 0 = one request at a time. Off while the live stream carries the tip. The node passes
    /// `--lookahead` (default 2); A/B numbers are in docs/NODE.md.
    lookahead: u64 = 0,
    /// Next free slot (monotonic ns) on the shared tip schedule (`paceWait`).
    pace_next: Atomic(u64) = .init(0),
    /// Highest sequence number that got a 404.
    last_miss: Atomic(u64) = .init(0),
    tmp_n: Atomic(u64) = .init(0),
    /// Sequence numbers written to the spool, by `seq % len` (claims never run more than `window`
    /// ahead of the follower, far less than len, so a slot is never reused while it matters).
    done: [1 << 14]Atomic(u64) = @splat(.init(std.math.maxInt(u64))),
    /// Arrival wall clock of recent checkpoints' bytes (`noteArrival`).
    /// Sequence numbers whose spooled blob a core's feed served, by `seq % len` (as `done`).
    /// Set by the writer before its file is renamed in, cleared by any other writer of the same
    /// checkpoint: what `fromCore` does not name came from somewhere else (the fallback, a
    /// stream, p2p, a kept spool), and an edge marks its certificate as foreign.
    core_origin: [1 << 14]Atomic(u64) = @splat(.init(std.math.maxInt(u64))),
    arrived_seq: [1 << 12]Atomic(u64) = @splat(.init(std.math.maxInt(u64))),
    arrived_ms: [1 << 12]Atomic(u64) = @splat(.init(0)),
    /// First sighting of recent checkpoints per source (wall clock ms, 0: not seen), by
    /// `seq % len`: the tip-latency race report (node.zig `noteSources`).
    seen_seq: [1 << 12]Atomic(u64) = @splat(.init(std.math.maxInt(u64))),
    seen_ms: [1 << 12][n_seen_src]Atomic(u64) = @splat(@splat(.init(0))),
    /// Wall clock ms of the live stream's last delivery (0: never).
    stream_ms: Atomic(u64) = .init(0),
    stream_live_ms: u64 = 2000,
    /// Tip request spacing while the live stream delivers (the bucket is then only a gap filler).
    backup_poll_ms: u32 = 100,
    /// The submitted signature order for bucket checkpoints with sponsored or multi-signer
    /// transactions, from the stream's full node (sigorder.zig; null: contents order).
    sig_order: ?*sigorder.Overlay = null,
    /// Called after a checkpoint's `.chk` is renamed into the spool. Every spool writer (the
    /// fetch threads, the live stream, p2p, an edge refetch) goes through `writeSpool`, so the
    /// node points this at the follower, whose workers then block on the wake instead of
    /// trying to open the file every 2 ms.
    on_spooled: ?Spooled = null,

    pub const Spooled = struct {
        ctx: *anyopaque,
        call: *const fn (ctx: *anyopaque, seq: u64) void,
    };

    pub fn start(f: *Fetcher, n: u32) !void {
        f.threads = try f.gpa.alloc(std.Thread, n);
        var made: usize = 0;
        errdefer {
            f.stopping.store(true, .release);
            for (f.threads[0..made]) |t| t.join();
            f.gpa.free(f.threads);
        }
        for (f.threads) |*t| {
            t.* = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, run, .{ f, @as(u32, @intCast(made)) });
            made += 1;
        }
    }

    /// Tells the fetch threads to stop, without waiting for them.
    pub fn requestStop(f: *Fetcher) void {
        f.stopping.store(true, .release);
    }

    pub fn stop(f: *Fetcher) void {
        f.requestStop();
        for (f.threads) |t| t.join();
        f.gpa.free(f.threads);
        f.threads = &.{};
    }

    /// Sleeps `ms`, or until the fetcher is told to stop (looked at every `stop_slice_ms`). The
    /// backoff after a source error grows to 10 s: slept in one piece, a stop waited that long
    /// for the thread, longer than the node's stop deadline.
    fn sleepMs(f: *Fetcher, ms: u64) void {
        var left = ms;
        while (left > 0 and !f.stopping.load(.acquire)) {
            const step = @min(left, stop_slice_ms);
            f.io.sleep(.fromMilliseconds(@intCast(step)), .awake) catch return;
            left -= step;
        }
    }

    fn claim(f: *Fetcher) ?u64 {
        while (!f.stopping.load(.acquire)) {
            const cur = f.next.load(.monotonic);
            if (cur > f.to) return null;
            if (cur >= f.applied_next.load(.acquire) + f.window) {
                f.sleepMs(5);
                continue;
            }
            if (f.next.cmpxchgWeak(cur, cur + 1, .monotonic, .monotonic) == null) return cur;
        }
        return null;
    }

    fn run(f: *Fetcher, idx: u32) void {
        var sc = Scratch.init(f.gpa);
        defer sc.deinit(f.gpa);
        var blob: std.ArrayList(u8) = .empty;
        defer blob.deinit(f.gpa);
        while (true) {
            const d = f.depth(idx);
            if (d <= 1) {
                const seq = f.claim() orelse break;
                f.fetchOne(&sc, &blob, seq);
                continue;
            }
            const r = f.claimRun(d) orelse break;
            if (r.n == 0) continue; // the tip came while it waited for room: the single path
            if (r.n == 1) f.fetchOne(&sc, &blob, r.first) else f.fetchRun(&sc, &blob, r.first, r.n);
        }
    }

    /// Requests fetch thread `idx` sends in its next call: 1 (the single path) without
    /// in-flight control, at the tip, and while the source cannot pipeline (not a core pool, or
    /// an edge on its fallback); else its share of the controller's count.
    fn depth(f: *Fetcher, idx: u32) u32 {
        const fl = f.inflight orelse return 1;
        const at_tip = f.frontier.load(.acquire) != std.math.maxInt(u64);
        const t = fl.decide(f, at_tip);
        if (at_tip or !f.source.pipelines()) return 1;
        return @min(InFlight.max_depth, edge.inflight.Controller.depth(t, idx, @intCast(@max(1, f.threads.len))));
    }

    /// Claims `d` consecutive checkpoints (fewer only at `to`), never past the window: what is
    /// in flight and what waits for the follower together never exceed it. A whole run or
    /// nothing: a thread that took the one free place of a full window would be gone for a
    /// round trip with it, and the window would carry a fraction of what it can.
    fn claimRun(f: *Fetcher, d_in: u32) ?struct { first: u64, n: u32 } {
        const d: u64 = @min(@as(u64, d_in), f.window);
        while (!f.stopping.load(.acquire)) {
            const cur = f.next.load(.monotonic);
            if (cur > f.to) return null;
            const lim = f.applied_next.load(.acquire) + f.window;
            const want = @min(d, (f.to - cur) +| 1);
            if (cur >= lim or lim - cur < want) {
                f.sleepMs(2);
                // the count may have changed, or the tip come, while this thread waited
                if (f.frontier.load(.acquire) != std.math.maxInt(u64)) return .{ .first = 0, .n = 0 };
                continue;
            }
            const n: u32 = @intCast(want);
            if (f.next.cmpxchgWeak(cur, cur + n, .monotonic, .monotonic) == null) return .{ .first = cur, .n = n };
        }
        return null;
    }

    const RunSink = struct {
        f: *Fetcher,
        first: u64,
        /// Checkpoints written to the spool, and those whose write failed (bit `seq - first`).
        wrote: u32 = 0,
        failed: u64 = 0,

        fn put(ctx: *anyopaque, seq: u64, bytes: []const u8) void {
            const s: *RunSink = @ptrCast(@alignCast(ctx));
            const f = s.f;
            f.noteSeen(seq, .bucket);
            // another writer holds it (or wrote it): nothing to do
            if (!f.markDone(seq)) {
                _ = f.stats.dup_hits.fetchAdd(1, .monotonic);
                return;
            }
            f.noteArrival(seq);
            // a pipelined call only ever asks the core pool
            f.writeSpoolFrom(seq, bytes, "", true) catch |e| {
                f.unmarkDone(seq);
                _ = f.stats.errors.fetchAdd(1, .monotonic);
                std.log.warn("spool {d}: {s}", .{ seq, @errorName(e) });
                s.failed |= @as(u64, 1) << @intCast(seq - s.first);
                return;
            };
            s.wrote += 1;
            _ = f.stats.fetched.fetchAdd(1, .monotonic);
            _ = f.stats.bytes.fetchAdd(bytes.len, .monotonic);
            Metrics.max(&f.stats.highest, seq);
        }
    };

    /// Catch-up only: the checkpoints `first .. first + n` in one pipelined call. Whatever
    /// does not come out of it (a checkpoint the core does not hold yet, a refused request, a
    /// failed call) goes to the single path, one by one: the retries, the fallback's rules and
    /// the tip are all there and only there.
    fn fetchRun(f: *Fetcher, sc: *Scratch, blob: *std.ArrayList(u8), first: u64, n: u32) void {
        const fl = f.inflight.?;
        var results: [InFlight.max_depth]edge.client.Pool.BatchItem = @splat(.failed);
        var sink: RunSink = .{ .f = f, .first = first };
        const in_flight = fl.now.fetchAdd(n, .acq_rel) + n;
        var peak = fl.peak.load(.monotonic);
        while (in_flight > peak) peak = fl.peak.cmpxchgWeak(peak, in_flight, .monotonic, .monotonic) orelse break;
        const t0 = nowNs();
        var times: edge.client.Pool.CallTimes = .{};
        const ok = if (f.source.fetchRun(sc, first, results[0..n], blob, .{ .ctx = &sink, .put = RunSink.put }, &times)) |_| true else |_| false;
        _ = fl.now.fetchSub(n, .acq_rel);
        // a call the stop ended: nothing to count, nothing to ask again
        if (f.stopping.load(.acquire)) return;
        if (ok) {
            _ = f.stats.fetch_ns.fetchAdd(nowNs() - t0, .monotonic);
            fl.noteCall(times, sink.wrote);
            if (times.limited) fl.noteError();
        } else fl.noteError();
        for (0..n) |k| {
            if (f.stopping.load(.acquire)) return;
            if (results[k] == .ok and sink.failed >> @intCast(k) & 1 == 0) continue;
            f.fetchOne(sc, blob, first + k);
        }
    }

    fn fetchOne(f: *Fetcher, sc: *Scratch, blob: *std.ArrayList(u8), seq: u64) void {
        var backoff: u64 = f.retry_ms;
        var bad: u32 = 0;
        // The frontier value at this thread's last immediate request: one immediate request per
        // frontier move, everything else at the tip goes through the shared pacer.
        var tried_at: u64 = std.math.maxInt(u64) - 1;
        // Already there: a kept spool from an earlier run (--keep-spool), or the live stream
        // (stream.zig) delivered it before this claim.
        if (f.fetched(seq)) {
            Metrics.max(&f.stats.highest, seq);
            return;
        }
        while (!f.stopping.load(.acquire)) {
            // Another thread (a helper, or the live stream) holds its bytes and is writing it:
            // wait for the file, or for the claim to be dropped (a failed decode or write).
            if (f.claimed(seq)) {
                if (f.fetched(seq)) return;
                f.sleepNs(500 * std.time.ns_per_us);
                continue;
            }
            const fr = f.frontier.load(.acquire);
            // Which checkpoint to request now, and in what role.
            var target = seq;
            var role: Role = .own;
            if (fr != std.math.maxInt(u64)) {
                if (fr < seq) {
                    // The frontier can name a checkpoint that is already fetched: in parallel mode a
                    // later request for fr can hit and return while an earlier request for fr - 1
                    // misses, lowers the frontier to fr - 1, then hits and moves it to fr, which no
                    // thread owns any more (a live run on 2026-11-07 stalled for good this way); a
                    // helper, speculative or stream fetch also leaves fetched checkpoints past it.
                    if (f.fetched(fr)) {
                        f.advance(fr);
                        continue;
                    }
                    // Its bytes are in hand and being written: the frontier moves in a moment. No
                    // request (each one here was a duplicate download: 967 of 1,305 in a 75 s run).
                    if (f.claimed(fr)) {
                        f.sleepNs(500 * std.time.ns_per_us);
                        continue;
                    }
                    if (seq - fr <= f.lookahead and tried_at != fr and !f.streamLive()) {
                        // Speculative: one request each time the frontier moves, so checkpoints
                        // uploaded together land in one round trip, not one round trip each.
                        tried_at = fr;
                        role = .spec;
                    } else {
                        // Help poll the frontier on the shared schedule.
                        if (!f.paceWait(fr)) continue;
                        if (f.claimed(fr)) continue;
                        target = fr;
                        role = .helper;
                    }
                } else if (seq < fr and f.fetched(seq)) {
                    return; // a helper fetched it
                } else if (fr == seq) {
                    if (tried_at != fr and !f.streamLive()) {
                        tried_at = fr; // the first request for a new frontier goes at once
                    } else {
                        tried_at = fr;
                        if (!f.paceWait(fr)) continue;
                        if (f.claimed(seq)) continue;
                    }
                }
            }
            const t0 = nowNs();
            switch (role) {
                .own => {},
                .spec => _ = f.stats.lookahead_gets.fetchAdd(1, .monotonic),
                .helper => _ = f.stats.helper_gets.fetchAdd(1, .monotonic),
            }
            // While the stream carries the tip, a tip poll only fills its gaps: a one-byte probe
            // first, and the full download only if the stream has not delivered it meanwhile (a
            // full GET per poll downloaded most checkpoints a second time, ~0.6 MB/s for nothing).
            const probe = fr != std.math.maxInt(u64) and f.streamLive();
            if (probe) {
                _ = f.stats.probes.fetchAdd(1, .monotonic);
                const there = if (f.source.exists(target)) |t| ok: {
                    f.answered_ns.store(nowNs(), .monotonic);
                    break :ok t;
                } else |_| false;
                if (there and (f.claimed(target) or f.fetched(target))) continue;
                if (!there) {
                    _ = f.stats.misses.fetchAdd(1, .monotonic);
                    Metrics.max(&f.last_miss, target);
                    var cur = f.frontier.load(.monotonic);
                    while (target < cur) cur = f.frontier.cmpxchgWeak(cur, target, .release, .monotonic) orelse break;
                    if (role == .own) tried_at = f.frontier.load(.acquire);
                    continue;
                }
            }
            const raw = f.source.fetchRaw(sc, target, blob) catch |e| {
                // A request the stop ended is not a source error: no count, no retry line.
                if (f.stopping.load(.acquire)) return;
                _ = f.stats.errors.fetchAdd(1, .monotonic);
                // A helper or speculative request leaves errors to the thread that owns the checkpoint.
                if (role != .own) continue;
                _ = f.stats.transient_errors.fetchAdd(1, .monotonic);
                std.log.warn("fetch {d}: {s}; retry in {d} ms", .{ seq, @errorName(e), backoff });
                f.sleepMs(backoff);
                backoff = @min(backoff * 2, f.retry_max_ms);
                continue;
            };
            f.answered_ns.store(nowNs(), .monotonic);
            if (raw == .missing) {
                _ = f.stats.misses.fetchAdd(1, .monotonic);
                if (role == .spec) _ = f.stats.lookahead_misses.fetchAdd(1, .monotonic);
                Metrics.max(&f.last_miss, target);
                // Become (or stay) the frontier poller.
                var cur = f.frontier.load(.monotonic);
                while (target < cur) cur = f.frontier.cmpxchgWeak(cur, target, .release, .monotonic) orelse break;
                // The next request for this frontier goes through the pacer.
                if (role == .own) tried_at = f.frontier.load(.acquire);
                continue;
            }
            const t1 = nowNs();
            _ = f.stats.fetch_ns.fetchAdd(t1 - t0, .monotonic);
            f.noteSeen(target, .bucket);
            // Claim before decoding: requests that were in flight when the object appeared all
            // come back with it; only the first one decodes and writes.
            if (!f.markDone(target)) {
                _ = f.stats.dup_hits.fetchAdd(1, .monotonic);
                continue; // the loop top waits for the claimant's file (or retries if it fails)
            }
            f.noteArrival(target);
            if (raw == .zst) {
                f.source.decodeOrdered(sc, target, blob, f.sig_order) catch |e| {
                    f.unmarkDone(target);
                    _ = f.stats.errors.fetchAdd(1, .monotonic);
                    if (role != .own) continue;
                    if (isTransient(e)) {
                        _ = f.stats.transient_errors.fetchAdd(1, .monotonic);
                    } else {
                        _ = f.stats.bad_data.fetchAdd(1, .monotonic);
                        bad += 1;
                        if (bad >= f.max_bad) {
                            std.log.err("fetch {d}: {s} {d} times in a row; the source serves bad data for it, stopping", .{ seq, @errorName(e), bad });
                            _ = f.stuck.cmpxchgStrong(std.math.maxInt(u64), seq, .release, .monotonic);
                            return;
                        }
                    }
                    std.log.warn("fetch {d}: {s}; retry in {d} ms", .{ seq, @errorName(e), backoff });
                    f.sleepMs(backoff);
                    backoff = @min(backoff * 2, f.retry_max_ms);
                    continue;
                };
                _ = f.stats.decode_ns.fetchAdd(nowNs() - t1, .monotonic);
            }
            f.writeSpoolFrom(target, blob.items, sc.aux.items, sc.from_core) catch |e| {
                f.unmarkDone(target);
                _ = f.stats.errors.fetchAdd(1, .monotonic);
                std.log.warn("spool {d}: {s}", .{ target, @errorName(e) });
                if (role != .own) continue;
                f.sleepMs(backoff);
                continue;
            };
            switch (role) {
                .own => {},
                .spec => _ = f.stats.lookahead_hits.fetchAdd(1, .monotonic),
                .helper => _ = f.stats.helper_hits.fetchAdd(1, .monotonic),
            }
            _ = f.stats.fetched.fetchAdd(1, .monotonic);
            _ = f.stats.bytes.fetchAdd(blob.items.len, .monotonic);
            Metrics.max(&f.stats.highest, target);
            // The next sequence is the new frontier (at the tip it is not there yet; in
            // catch-up the frontier only moved when a fetch missed, which is the tip).
            if (f.frontier.load(.acquire) == target) {
                // A first-try hit: nothing at or above it has missed since.
                const first_try = f.last_miss.load(.monotonic) < target;
                const hits = if (first_try) f.frontier_hits.load(.monotonic) + 1 else 0;
                if (hits >= f.behind_hits) {
                    f.frontier_hits.store(0, .monotonic);
                    _ = f.stats.behind.fetchAdd(1, .monotonic);
                    std.log.info("fetch: {d} was already there; behind the tip, fetching in parallel again", .{target});
                    _ = f.frontier.cmpxchgStrong(target, std.math.maxInt(u64), .release, .monotonic);
                } else {
                    f.frontier_hits.store(hits, .monotonic);
                    if (f.frontier.cmpxchgStrong(target, target + 1, .release, .monotonic) == null) f.advance(target + 1);
                }
            }
            if (role == .own) return;
        }
    }

    /// The newest checkpoint known to exist at the source, or null while the fetcher has not met
    /// the tip (catch-up: no request has come back "not there yet" since it last fell behind).
    pub fn tipKnown(f: *const Fetcher) ?u64 {
        const fr = f.frontier.load(.acquire);
        if (fr == std.math.maxInt(u64)) return null;
        return @max(f.stats.highest.load(.monotonic), fr -| 1);
    }

    /// Nanoseconds since the source last answered (`answered_ns`); the maximum when it never did.
    pub fn silentNs(f: *const Fetcher) u64 {
        const at = f.answered_ns.load(.monotonic);
        return if (at == 0) std.math.maxInt(u64) else nowNs() -| at;
    }

    /// Another thread holds the bytes of `seq` (claimed by `markDone`, file not yet written).
    fn claimed(f: *Fetcher, seq: u64) bool {
        return f.done[seq % f.done.len].load(.acquire) == seq;
    }

    /// Records when the bytes of `seq` arrived (wall clock ms), for the stage split of the tip
    /// latency (arrival vs decode, verify and commit).
    pub fn noteArrival(f: *Fetcher, seq: u64) void {
        const i = seq % f.arrived_seq.len;
        f.arrived_seq[i].store(std.math.maxInt(u64), .release);
        f.arrived_ms[i].store(wallMs(), .release);
        f.arrived_seq[i].store(seq, .release);
    }

    /// Records the first time `src` had `seq` (any source, winner or not).
    pub fn noteSeen(f: *Fetcher, seq: u64, src: SeenSrc) void {
        const i = seq % f.seen_seq.len;
        var cur = f.seen_seq[i].load(.acquire);
        if (cur != seq) {
            if (cur != std.math.maxInt(u64) and cur > seq) return; // the ring has moved past it
            if (f.seen_seq[i].cmpxchgStrong(cur, seq, .acq_rel, .acquire)) |now_there| {
                cur = now_there;
                if (cur != seq) return;
            } else for (&f.seen_ms[i]) |*m| m.store(0, .release);
        }
        _ = f.seen_ms[i][@intFromEnum(src)].cmpxchgStrong(0, wallMs(), .acq_rel, .monotonic);
    }

    pub fn seenMs(f: *Fetcher, seq: u64, src: SeenSrc) ?u64 {
        const i = seq % f.seen_seq.len;
        if (f.seen_seq[i].load(.acquire) != seq) return null;
        const ms = f.seen_ms[i][@intFromEnum(src)].load(.acquire);
        return if (ms == 0) null else ms;
    }

    /// Wall clock ms at which `seq`'s bytes arrived, if still recorded.
    pub fn arrivalMs(f: *Fetcher, seq: u64) ?u64 {
        const i = seq % f.arrived_seq.len;
        if (f.arrived_seq[i].load(.acquire) != seq) return null;
        const ms = f.arrived_ms[i].load(.acquire);
        return if (f.arrived_seq[i].load(.acquire) == seq) ms else null;
    }

    /// The live stream (stream.zig) delivered a checkpoint in the last `stream_live_ms`: tip
    /// polling of the bucket backs off to `backup_poll_ms` and stops speculating, since the
    /// bucket sees each checkpoint about 100 ms after the stream (measured on a production node).
    pub fn streamLive(f: *Fetcher) bool {
        const t = f.stream_ms.load(.monotonic);
        return t != 0 and wallMs() -| t < f.stream_live_ms;
    }

    /// Called by a writer outside the fetch threads (the live stream) after it wrote `seq` to
    /// the spool: moves the frontier past it.
    pub fn delivered(f: *Fetcher, seq: u64) void {
        f.stream_ms.store(wallMs(), .monotonic);
        Metrics.max(&f.stats.highest, seq);
        const fr = f.frontier.load(.acquire);
        if (fr != std.math.maxInt(u64) and fr <= seq) f.advance(fr);
    }

    /// Room for an outside writer: `seq` is inside the fetch window and not yet fetched.
    pub fn wants(f: *Fetcher, seq: u64) bool {
        const lo = f.applied_next.load(.acquire);
        return seq >= lo and seq < lo + f.window and !f.claimed(seq) and !f.fetched(seq);
    }

    const Role = enum { own, spec, helper };

    /// Claims the right to write `seq` to the spool: false if another thread already did.
    pub fn markDone(f: *Fetcher, seq: u64) bool {
        const slot = &f.done[seq % f.done.len];
        var cur = slot.load(.monotonic);
        while (cur != seq) cur = slot.cmpxchgWeak(cur, seq, .acq_rel, .monotonic) orelse return true;
        return false;
    }

    pub fn unmarkDone(f: *Fetcher, seq: u64) void {
        _ = f.done[seq % f.done.len].cmpxchgStrong(seq, std.math.maxInt(u64), .acq_rel, .monotonic);
    }

    /// Moves the frontier past checkpoints that are already fetched, starting at `from`.
    fn advance(f: *Fetcher, from: u64) void {
        var fr = from;
        while (fr != std.math.maxInt(u64) and f.fetched(fr)) {
            fr = if (f.frontier.cmpxchgStrong(fr, fr + 1, .release, .monotonic)) |actual| actual else fr + 1;
        }
    }

    /// Waits for this thread's slot on the shared tip schedule (one frontier request every
    /// `poll_ms` across all threads, so with a round trip longer than `poll_ms` several are in
    /// flight and a new checkpoint is seen within `poll_ms` of appearing). False if the frontier
    /// moved off `fr` meanwhile or the fetcher is stopping. Slots are taken at most one interval
    /// ahead, so a new frontier never waits behind a queue.
    fn paceWait(f: *Fetcher, fr: u64) bool {
        const ms = if (f.streamLive()) @max(f.poll_ms, f.backup_poll_ms) else f.poll_ms;
        const delta: u64 = @as(u64, @max(1, ms)) * std.time.ns_per_ms;
        while (!f.stopping.load(.acquire)) {
            if (f.frontier.load(.acquire) != fr) return false;
            const now = nowNs();
            const cur = f.pace_next.load(.monotonic);
            if (cur > now + delta) {
                f.sleepNs(@min(delta, cur - now - delta));
                continue;
            }
            const slot = @max(now, cur);
            if (f.pace_next.cmpxchgWeak(cur, slot + delta, .monotonic, .monotonic) != null) continue;
            if (slot > now) f.sleepNs(slot - now);
            return f.frontier.load(.acquire) == fr and !f.stopping.load(.acquire);
        }
        return false;
    }

    fn sleepNs(f: *Fetcher, ns: u64) void {
        f.io.sleep(.fromNanoseconds(@intCast(ns)), .awake) catch {};
    }

    /// Checkpoint `seq` is applied or waits in the spool (files are renamed in complete and
    /// removed only after the follower applied them).
    fn fetched(f: *Fetcher, seq: u64) bool {
        if (seq < f.applied_next.load(.acquire)) return true;
        var nb: [48]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, "{d}.chk", .{seq}) catch unreachable;
        _ = f.spool.statFile(f.io, name, .{}) catch return false;
        return true;
    }

    /// `writeSpool` for a checkpoint built here (p2p_exec.zig): `<seq>.p2p`, an empty file
    /// written before the blob, tells history.zig that the read sets are deepwave's own, so the
    /// checkpoint is marked for reconcile (reconcile.zig). A file of its own: the blob and aux
    /// formats stay what every reader (and an older binary on a kept spool) knows.
    pub fn writeSpoolBuilt(f: *Fetcher, seq: u64, bytes: []const u8, aux: []const u8) !void {
        var nb: [48]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, "{d}.p2p", .{seq}) catch unreachable;
        try f.spool.writeFile(f.io, .{ .sub_path = name, .data = "" });
        f.writeSpool(seq, bytes, aux) catch |e| {
            f.spool.deleteFile(f.io, name) catch {};
            return e;
        };
    }

    /// The spooled blob of `seq` came from a core's feed (`core_origin`). The follower's observer
    /// asks before it commits `seq`.
    pub fn fromCore(f: *const Fetcher, seq: u64) bool {
        return f.core_origin[seq % f.core_origin.len].load(.acquire) == seq;
    }

    /// `<seq>.aux` first, then `<seq>.chk` (each written to a temporary name and renamed), so a
    /// reader that sees the `.chk` also sees its `.aux`. For bytes that did not come from a
    /// core's feed (`writeSpoolFrom`).
    pub fn writeSpool(f: *Fetcher, seq: u64, bytes: []const u8, aux: []const u8) !void {
        return f.writeSpoolFrom(seq, bytes, aux, false);
    }

    /// `writeSpool`, saying whether a core's feed served the bytes.
    pub fn writeSpoolFrom(f: *Fetcher, seq: u64, bytes: []const u8, aux: []const u8, from_core: bool) !void {
        var tb: [48]u8 = undefined;
        var nb: [48]u8 = undefined;
        // Unique temporary names: a helper and the owning thread can write the same checkpoint.
        const u = f.tmp_n.fetchAdd(1, .monotonic);
        if (aux.len > 0) {
            const tmp = std.fmt.bufPrint(&tb, ".{d}.{d}.atmp", .{ seq, u }) catch unreachable;
            const name = std.fmt.bufPrint(&nb, "{d}.aux", .{seq}) catch unreachable;
            try f.spool.writeFile(f.io, .{ .sub_path = tmp, .data = aux });
            try f.spool.rename(tmp, f.spool, name, f.io);
        }
        const tmp = std.fmt.bufPrint(&tb, ".{d}.{d}.tmp", .{ seq, u }) catch unreachable;
        const name = std.fmt.bufPrint(&nb, "{d}.chk", .{seq}) catch unreachable;
        try f.spool.writeFile(f.io, .{ .sub_path = tmp, .data = bytes });
        // Before the rename: whoever reads the file knows where it came from.
        const origin = &f.core_origin[seq % f.core_origin.len];
        if (from_core) origin.store(seq, .release) else _ = origin.cmpxchgStrong(seq, std.math.maxInt(u64), .acq_rel, .monotonic);
        try f.spool.rename(tmp, f.spool, name, f.io);
        // After the rename: a reader woken here finds the file.
        if (f.on_spooled) |h| h.call(h.ctx, seq);
        // A duplicate that lands after the checkpoint was applied and cleaned would stay forever.
        if (!f.keep and seq < f.applied_next.load(.acquire)) {
            f.spool.deleteFile(f.io, name) catch {};
            const ax = std.fmt.bufPrint(&nb, "{d}.aux", .{seq}) catch unreachable;
            f.spool.deleteFile(f.io, ax) catch {};
            const pp = std.fmt.bufPrint(&nb, "{d}.p2p", .{seq}) catch unreachable;
            f.spool.deleteFile(f.io, pp) catch {};
        }
    }

    /// Deletes spooled blobs below `below` (committed checkpoints). Called by the node.
    pub fn clean(f: *Fetcher, from: u64, below: u64) void {
        if (f.keep) return;
        var s = from;
        var nb: [48]u8 = undefined;
        while (s < below) : (s += 1) {
            inline for (.{ "{d}.chk", "{d}.aux", "{d}.p2p" }) |fmt| {
                const name = std.fmt.bufPrint(&nb, fmt, .{s}) catch unreachable;
                f.spool.deleteFile(f.io, name) catch {};
            }
        }
    }
};

/// Network, disk and S3 server errors are retried forever; bad bytes (`BadData`: zstd, protobuf,
/// BCS) and a different checkpoint than asked for count toward `max_bad`.
pub fn isTransient(e: anyerror) bool {
    return switch (e) {
        error.WrongCheckpoint, error.BadData => false,
        else => true,
    };
}

pub fn wallMs() u64 {
    var ts: std.posix.timespec = undefined;
    if (@import("builtin").os.tag == .linux) {
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
    } else {
        _ = std.c.clock_gettime(.REALTIME, &ts);
    }
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

pub fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    if (@import("builtin").os.tag == .linux) {
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    } else {
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
    }
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

test "fetcher: the tip is known only once a request missed; silence counts from the last answer" {
    var f: Fetcher = undefined;
    f.frontier = .init(std.math.maxInt(u64));
    f.stats = .{};
    f.answered_ns = .init(0);
    // nothing fetched, nothing answered
    try std.testing.expectEqual(@as(?u64, null), f.tipKnown());
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), f.silentNs());
    // catch-up: checkpoints arrive, but no request has come back "not there yet"
    f.stats.highest.store(100, .monotonic);
    try std.testing.expectEqual(@as(?u64, null), f.tipKnown());
    // the first miss: 101 is not there, so 100 is the tip
    f.frontier.store(101, .release);
    try std.testing.expectEqual(@as(?u64, 100), f.tipKnown());
    // a frontier past the highest spooled (its checkpoints are being written): one under it
    f.frontier.store(105, .release);
    try std.testing.expectEqual(@as(?u64, 104), f.tipKnown());
    // fell behind again (`behind_hits`): unknown until the next miss
    f.frontier.store(std.math.maxInt(u64), .release);
    try std.testing.expectEqual(@as(?u64, null), f.tipKnown());
    f.answered_ns.store(nowNs(), .monotonic);
    try std.testing.expect(f.silentNs() < std.time.ns_per_s);
}
