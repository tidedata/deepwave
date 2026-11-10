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

    pub fn init(gpa: std.mem.Allocator) Scratch {
        return .{ .arena = .init(gpa) };
    }
    pub fn deinit(s: *Scratch, gpa: std.mem.Allocator) void {
        s.raw.deinit(gpa);
        s.aux.deinit(gpa);
        s.arena.deinit();
    }
};

pub const Source = struct {
    gpa: std.mem.Allocator,
    io: Io,
    kind: Kind,

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
        sc.aux.clearRetainingCapacity();
        memstat.keep(.fetch_scratch, &sc.kept, sc.arena.queryCapacity() + sc.raw.capacity + sc.aux.capacity);
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
                const r = p.fetchBlob(sc.arena.allocator(), seq, out) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.BadData, error.TooLarge => return error.BadData,
                    else => return error.SourceUnavailable,
                };
                if (r == .missing) return .missing;
                return .blob;
            },
            .none => return .missing,
        }
        return .zst;
    }

    /// Step two of `fetch`: the zstd archive proto in `sc.raw` to a blob in `out` and its aux
    /// record in `sc.aux`.
    pub fn decode(s: *const Source, sc: *Scratch, seq: u64, out: *std.ArrayList(u8)) !void {
        const proto = convert.unzstdArena(sc.arena.allocator(), sc.raw.items, max_blob) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => return error.BadData,
        };
        return decodeProto(s.gpa, sc, proto, seq, out);
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
        return decodeProtoOpts(s.gpa, sc, proto, seq, out, opts);
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
        if (s.kind == .zui1) {
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
        }
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
    /// Keep committed blobs in the spool (`--keep-spool`), so `deepwave check` can compare the
    /// whole store with what the source served after a live run.
    keep: bool = false,
    /// A fetch that fails this many times in a row with a non-transient error (the source served
    /// bytes that do not convert, or the wrong checkpoint) stops the node instead of retrying.
    max_bad: u32 = 8,
    /// Set when a sequence number hit `max_bad`; the node stops on it.
    stuck: Atomic(u64) = .init(std.math.maxInt(u64)),
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
            t.* = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, run, .{f});
            made += 1;
        }
    }

    pub fn stop(f: *Fetcher) void {
        f.stopping.store(true, .release);
        for (f.threads) |t| t.join();
        f.gpa.free(f.threads);
        f.threads = &.{};
    }

    fn sleepMs(f: *Fetcher, ms: u64) void {
        f.io.sleep(.fromMilliseconds(@intCast(ms)), .awake) catch {};
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

    fn run(f: *Fetcher) void {
        var sc = Scratch.init(f.gpa);
        defer sc.deinit(f.gpa);
        var blob: std.ArrayList(u8) = .empty;
        defer blob.deinit(f.gpa);
        while (f.claim()) |seq| f.fetchOne(&sc, &blob, seq);
    }

    fn fetchOne(f: *Fetcher, sc: *Scratch, blob: *std.ArrayList(u8), seq: u64) void {
        var backoff: u64 = 100;
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
                const there = f.source.exists(target) catch false;
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
                _ = f.stats.errors.fetchAdd(1, .monotonic);
                // A helper or speculative request leaves errors to the thread that owns the checkpoint.
                if (role != .own) continue;
                _ = f.stats.transient_errors.fetchAdd(1, .monotonic);
                std.log.warn("fetch {d}: {s}; retry in {d} ms", .{ seq, @errorName(e), backoff });
                f.sleepMs(backoff);
                backoff = @min(backoff * 2, 10_000);
                continue;
            };
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
                    backoff = @min(backoff * 2, 10_000);
                    continue;
                };
                _ = f.stats.decode_ns.fetchAdd(nowNs() - t1, .monotonic);
            }
            f.writeSpool(target, blob.items, sc.aux.items) catch |e| {
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

    /// `<seq>.aux` first, then `<seq>.chk` (each written to a temporary name and renamed), so a
    /// reader that sees the `.chk` also sees its `.aux`.
    pub fn writeSpool(f: *Fetcher, seq: u64, bytes: []const u8, aux: []const u8) !void {
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
        try f.spool.rename(tmp, f.spool, name, f.io);
        // After the rename: a reader woken here finds the file.
        if (f.on_spooled) |h| h.call(h.ctx, seq);
        // A duplicate that lands after the checkpoint was applied and cleaned would stay forever.
        if (!f.keep and seq < f.applied_next.load(.acquire)) {
            f.spool.deleteFile(f.io, name) catch {};
            const ax = std.fmt.bufPrint(&nb, "{d}.aux", .{seq}) catch unreachable;
            f.spool.deleteFile(f.io, ax) catch {};
        }
    }

    /// Deletes spooled blobs below `below` (committed checkpoints). Called by the node.
    pub fn clean(f: *Fetcher, from: u64, below: u64) void {
        if (f.keep) return;
        var s = from;
        var nb: [48]u8 = undefined;
        while (s < below) : (s += 1) {
            inline for (.{ "{d}.chk", "{d}.aux" }) |fmt| {
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
