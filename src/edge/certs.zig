//! Foreign certificates of an edge (docs/EDGE.md section 13): which checkpoints hold a quorum
//! certificate that did not come from a core, kept durably, and the rules of replacing them.
//!
//! A checkpoint an edge takes from its fallback (or from a stream, or from the bucket during a
//! start-up restore) carries that source's quorum certificate: valid for the committee, but other
//! bytes than the core's (another aggregate signature over another set of signers; measured on
//! mainnet, docs/EDGE.md 10.3). Everything else of the checkpoint is byte-equal. So:
//!
//!  1. Mark. Every such checkpoint is marked before its commit (`Certs.onApply`, on the
//!     follower's apply thread). The mark is in `node/edge-certs.log`, written and synced before
//!     the store commits the checkpoint, so no crash leaves a foreign certificate without its
//!     mark. One record covers a run ahead (`Log.ahead` checkpoints): a long spell on the
//!     fallback costs one sync per run, not one per checkpoint. The checkpoints of a run that
//!     then come from a core are marked in the log and not in memory: after a crash they are
//!     marked for real, checked against the core and found equal.
//!  2. Converge. Back on a core, the node fetches the certified summaries of marked checkpoints
//!     from it (the node's part: node/edge_certs.zig), verifies each, and hands them to
//!     `resolve`: one log record per checkpoint (the core's certificate, or "the stored one is
//!     the core's"), synced, then the store serves the core's bytes, then the mark is gone. A
//!     crash between any two of those steps leaves a state the next start reads as one of them.
//!  3. Until then, every read that would hand out the certificate goes to the core
//!     (`Certs.isMarked`; route.zig `foreign_cert`).
//!
//! A log that is missing while the store holds checkpoints (an edge from before this existed, a
//! deleted file), or that has a damaged record between intact ones, says nothing about which
//! certificates are foreign: every checkpoint the edge serves is then marked, and the core is
//! asked about each (`Open.all_from`). Nothing is assumed to be the core's without a record.
//!
//! This file is the state and its rules (the marked set, the log, the pacing, the gate); it
//! fetches nothing and trusts nothing. Thread safe where the node needs it: `onApply` on the
//! apply thread, `isMarked` on request threads, the rest on the converge thread.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

// ---------------------------------------------------------------- the marked set

/// Consecutive marked checkpoints and when the oldest of them was marked (wall clock ms).
pub const Run = struct { first: u64, last: u64, at_ms: u64 };

/// The marked checkpoints, as runs. A fallback period marks one run; reads ask `contains`.
pub const Marks = struct {
    gpa: Allocator,
    mu: std.atomic.Mutex = .unlocked,
    /// Sorted by `first`, disjoint, never adjacent.
    runs: std.ArrayList(Run) = .empty,
    n: Atomic(u64) = .init(0),

    pub fn deinit(m: *Marks) void {
        m.runs.deinit(m.gpa);
    }

    fn lock(m: *Marks) void {
        while (!m.mu.tryLock()) std.atomic.spinLoopHint();
    }

    pub fn count(m: *const Marks) u64 {
        return m.n.load(.acquire);
    }

    /// Index of the first run whose `last` is at or above `seq` (`runs.len`: none).
    fn lowerBound(m: *const Marks, seq: u64) usize {
        var lo: usize = 0;
        var hi: usize = m.runs.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (m.runs.items[mid].last < seq) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    /// One load while nothing is marked (every node, almost always).
    pub fn contains(m: *Marks, seq: u64) bool {
        if (m.n.load(.acquire) == 0) return false;
        m.lock();
        defer m.mu.unlock();
        const i = m.lowerBound(seq);
        return i < m.runs.items.len and m.runs.items[i].first <= seq;
    }

    /// Any marked checkpoint in `lo..=hi`.
    pub fn any(m: *Marks, lo: u64, hi: u64) bool {
        if (m.n.load(.acquire) == 0 or lo > hi) return false;
        m.lock();
        defer m.mu.unlock();
        const i = m.lowerBound(lo);
        return i < m.runs.items.len and m.runs.items[i].first <= hi;
    }

    /// Marks `first..=last`; returns how many were not marked before.
    pub fn addRange(m: *Marks, first: u64, last: u64, at_ms: u64) Allocator.Error!u64 {
        if (first > last) return 0;
        m.lock();
        defer m.mu.unlock();
        // runs overlapping or adjacent to the new one are merged into it
        var i = m.lowerBound(first -| 1);
        var nf = first;
        var nl = last;
        var at = at_ms;
        var had: u64 = 0;
        const from = i;
        while (i < m.runs.items.len and m.runs.items[i].first <= last +| 1) : (i += 1) {
            const r = m.runs.items[i];
            nf = @min(nf, r.first);
            nl = @max(nl, r.last);
            at = @min(at, r.at_ms);
            had += r.last - r.first + 1;
        }
        const merged: Run = .{ .first = nf, .last = nl, .at_ms = at };
        if (i == from) {
            try m.runs.insert(m.gpa, from, merged);
        } else {
            m.runs.items[from] = merged;
            m.runs.replaceRangeAssumeCapacity(from + 1, i - from - 1, &.{});
        }
        const added = (nl - nf + 1) - had;
        m.n.store(m.n.load(.monotonic) + added, .release);
        return added;
    }

    pub fn add(m: *Marks, seq: u64, at_ms: u64) Allocator.Error!bool {
        return try m.addRange(seq, seq, at_ms) == 1;
    }

    /// Unmarks `first..=last`; returns how many were marked.
    pub fn removeRange(m: *Marks, first: u64, last: u64) Allocator.Error!u64 {
        if (first > last or m.n.load(.acquire) == 0) return 0;
        m.lock();
        defer m.mu.unlock();
        var i = m.lowerBound(first);
        var gone: u64 = 0;
        while (i < m.runs.items.len and m.runs.items[i].first <= last) {
            const r = m.runs.items[i];
            const cut_lo = @max(r.first, first);
            const cut_hi = @min(r.last, last);
            gone += cut_hi - cut_lo + 1;
            const left = cut_lo > r.first;
            const right = cut_hi < r.last;
            if (left and right) {
                // split: room first, so nothing is lost if it cannot be had
                try m.runs.insert(m.gpa, i + 1, .{ .first = cut_hi + 1, .last = r.last, .at_ms = r.at_ms });
                m.runs.items[i].last = cut_lo - 1;
                i += 2;
            } else if (left) {
                m.runs.items[i].last = cut_lo - 1;
                i += 1;
            } else if (right) {
                m.runs.items[i].first = cut_hi + 1;
                i += 1;
            } else _ = m.runs.orderedRemove(i);
        }
        m.n.store(m.n.load(.monotonic) - gone, .release);
        return gone;
    }

    pub fn remove(m: *Marks, seq: u64) bool {
        // one checkpoint off a run: a split needs room for one run
        return (m.removeRange(seq, seq) catch return false) == 1;
    }

    /// Wall clock ms at which the oldest mark still here was made (null: none).
    pub fn oldestMs(m: *Marks) ?u64 {
        if (m.n.load(.acquire) == 0) return null;
        m.lock();
        defer m.mu.unlock();
        var at: ?u64 = null;
        for (m.runs.items) |r| at = if (at) |a| @min(a, r.at_ms) else r.at_ms;
        return at;
    }

    /// The highest marked checkpoint (null: none).
    pub fn highest(m: *Marks) ?u64 {
        if (m.n.load(.acquire) == 0) return null;
        m.lock();
        defer m.mu.unlock();
        return if (m.runs.items.len == 0) null else m.runs.items[m.runs.items.len - 1].last;
    }

    /// Marked checkpoints in `lo..=hi`, highest first, into `out`; `skip` (may be null) leaves
    /// some out. Returns how many.
    pub fn top(m: *Marks, out: []u64, lo: u64, hi: u64, skip: ?*const Deferred) usize {
        if (out.len == 0 or lo > hi or m.n.load(.acquire) == 0) return 0;
        m.lock();
        defer m.mu.unlock();
        var k: usize = 0;
        var i = m.runs.items.len;
        while (i > 0 and k < out.len) {
            i -= 1;
            const r = m.runs.items[i];
            if (r.first > hi) continue;
            if (r.last < lo) break;
            var s = @min(r.last, hi);
            const stop = @max(r.first, lo);
            while (k < out.len) {
                if (skip == null or !skip.?.has(s)) {
                    out[k] = s;
                    k += 1;
                }
                if (s == stop) break;
                s -= 1;
            }
        }
        return k;
    }

    /// A copy of the runs (the log's rewrite).
    pub fn snapshot(m: *Marks, gpa: Allocator) Allocator.Error![]Run {
        m.lock();
        defer m.mu.unlock();
        return gpa.dupe(Run, m.runs.items);
    }
};

/// Checkpoints the converge loop leaves alone for a while (a refetch that was refused, a
/// certificate that did not verify): each with the time it may be asked again. Converge
/// thread only. Bounded: when it is full, `put` says so and the loop backs off as a whole.
pub const Deferred = struct {
    gpa: Allocator,
    map: std.AutoHashMapUnmanaged(u64, Entry) = .empty,
    max: usize = 4096,

    const Entry = struct { until_ns: u64, tries: u32 };

    pub fn deinit(d: *Deferred) void {
        d.map.deinit(d.gpa);
    }

    pub fn has(d: *const Deferred, seq: u64) bool {
        return d.map.contains(seq);
    }

    /// Defers `seq`: `base_ms` after the first failure, doubled each time, at most `max_ms`.
    /// False when the table is full (nothing was recorded).
    pub fn put(d: *Deferred, seq: u64, now_ns: u64, base_ms: u64, max_ms: u64) bool {
        const gop = d.map.getOrPut(d.gpa, seq) catch return false;
        if (!gop.found_existing) {
            if (d.map.count() > d.max) {
                _ = d.map.remove(seq);
                return false;
            }
            gop.value_ptr.* = .{ .until_ns = 0, .tries = 0 };
        }
        const shift: u6 = @intCast(@min(gop.value_ptr.tries, 20));
        const wait_ms = @min(max_ms, base_ms *| (@as(u64, 1) << shift));
        gop.value_ptr.until_ns = now_ns +| wait_ms * std.time.ns_per_ms;
        gop.value_ptr.tries +|= 1;
        return true;
    }

    pub fn drop(d: *Deferred, seq: u64) void {
        _ = d.map.remove(seq);
    }

    /// Forgets the entries whose time has come (they are asked again), and those below `floor`.
    pub fn expire(d: *Deferred, now_ns: u64, floor: u64) void {
        if (d.map.count() == 0) return;
        var gone: [64]u64 = undefined;
        while (true) {
            var n: usize = 0;
            var it = d.map.iterator();
            while (it.next()) |kv| {
                if (kv.value_ptr.until_ns <= now_ns or kv.key_ptr.* < floor) {
                    gone[n] = kv.key_ptr.*;
                    n += 1;
                    if (n == gone.len) break;
                }
            }
            for (gone[0..n]) |s| {
                // the count of tries is kept by a put that follows; an expired entry starts again
                _ = d.map.remove(s);
            }
            if (n < gone.len) return;
        }
    }
};

// ---------------------------------------------------------------- the log

/// `node/edge-certs.log`: magic, then records `crc32 (of the rest) u32, kind u8, pad 3, len u32,
/// seq u64, len bytes`.
///   mark   `n u32, at_ms u64`: checkpoints `seq .. seq + n` hold (or may come to hold) a
///          certificate that is not a core's; `at_ms` is when (wall clock).
///   cert   the core's BCS CertifiedCheckpointSummary of checkpoint `seq`, verified: served in
///          place of the stored one from here on; the mark of `seq` is cleared.
///   clear  `n u32`: the certificates the edge serves for `seq .. seq + n` (the stored ones, or
///          ones logged before) are the core's, compared byte for byte after the same
///          verification; their marks are cleared.
/// Read in order: a later certificate of a checkpoint replaces an earlier one, a later mark
/// marks it again. A torn tail is cut.
pub const log_name = "edge-certs.log";
pub const log_tmp = "edge-certs.log.tmp";
pub const log_magic = "ZUIECRT1";
pub const rec_head = 20;

pub const Kind = enum(u8) { mark = 1, cert = 2, clear = 3 };

/// A certificate may not be larger than this in a record (a summary with an end-of-epoch
/// committee is a few tens of KiB).
pub const max_cert: usize = 1 << 20;

pub fn encodeRec(gpa: Allocator, out: *std.ArrayList(u8), kind: Kind, seq: u64, payload: []const u8) Allocator.Error!void {
    const at = out.items.len;
    try out.appendNTimes(gpa, 0, rec_head);
    try out.appendSlice(gpa, payload);
    const r = out.items[at..];
    r[4] = @intFromEnum(kind);
    std.mem.writeInt(u32, r[8..12], @intCast(payload.len), .little);
    std.mem.writeInt(u64, r[12..20], seq, .little);
    std.mem.writeInt(u32, r[0..4], std.hash.Crc32.hash(r[4..]), .little);
}

/// One mark record (no allocation: the apply thread writes it before a commit).
fn markBytes(seq: u64, n: u32, at_ms: u64) [rec_head + 12]u8 {
    var r: [rec_head + 12]u8 = @splat(0);
    r[4] = @intFromEnum(Kind.mark);
    std.mem.writeInt(u32, r[8..12], 12, .little);
    std.mem.writeInt(u64, r[12..20], seq, .little);
    std.mem.writeInt(u32, r[20..24], n, .little);
    std.mem.writeInt(u64, r[24..32], at_ms, .little);
    std.mem.writeInt(u32, r[0..4], std.hash.Crc32.hash(r[4..]), .little);
    return r;
}

fn encodeMark(gpa: Allocator, out: *std.ArrayList(u8), seq: u64, n: u32, at_ms: u64) Allocator.Error!void {
    try out.appendSlice(gpa, &markBytes(seq, n, at_ms));
}

fn encodeClear(gpa: Allocator, out: *std.ArrayList(u8), seq: u64, n: u32) Allocator.Error!void {
    var p: [4]u8 = undefined;
    std.mem.writeInt(u32, &p, n, .little);
    try encodeRec(gpa, out, .clear, seq, &p);
}

const Rec = struct { kind: Kind, seq: u64, payload: []const u8 };

const Parsed = union(enum) {
    ok: Rec,
    /// A whole frame (its length fits) that is not a record: a bad checksum, an unknown kind, a
    /// payload of the wrong size. The frame's size.
    bad: usize,
    /// Too short for the record its header names.
    none,
};

fn parseRec(r: []const u8) Parsed {
    if (r.len < rec_head) return .none;
    const len = std.mem.readInt(u32, r[8..12], .little);
    if (len > r.len - rec_head) return .none;
    const n = rec_head + len;
    if (std.hash.Crc32.hash(r[4..n]) != std.mem.readInt(u32, r[0..4], .little)) return .{ .bad = n };
    const kind: Kind = switch (r[4]) {
        1 => .mark,
        2 => .cert,
        3 => .clear,
        else => return .{ .bad = n },
    };
    const ok = switch (kind) {
        .mark => len == 12,
        .clear => len == 4,
        .cert => len > 0 and len <= max_cert,
    };
    if (!ok) return .{ .bad = n };
    return .{ .ok = .{ .kind = kind, .seq = std.mem.readInt(u64, r[12..20], .little), .payload = r[rec_head..n] } };
}

/// The core's certified summary of one checkpoint, as the log holds it.
pub const Fix = struct { seq: u64, cert: []const u8 };

/// What a start-up read of the log found.
pub const Open = struct {
    /// Certificates to serve in place of the stored ones (slices into `data`).
    fixes: []Fix = &.{},
    /// The log's bytes (owner of `fixes`); freed by `deinit`.
    data: []u8 = &.{},
    /// Set when the log could not say which certificates are foreign (missing over a store that
    /// holds checkpoints, or damaged): every checkpoint from here to the store's tip was marked.
    all_from: ?u64 = null,
    /// Why (`all_from`).
    all_why: []const u8 = "",
    bytes: u64 = 0,
    marks: u64 = 0,
    certs: u64 = 0,
    clears: u64 = 0,
    /// Bytes of torn tail cut.
    cut: u64 = 0,
    rewritten: bool = false,
    size: u64 = 0,

    pub fn deinit(o: *Open, gpa: Allocator) void {
        gpa.free(o.fixes);
        gpa.free(o.data);
        o.* = .{};
    }
};

/// `Certs.open`'s result: the state, and what the log held (the caller installs
/// `found.fixes` in its store, then frees `found`).
pub const Opened = struct { certs: *Certs, found: Open };

pub const Crash = enum {
    /// A replacement's records are written in part and not synced (a torn tail).
    cert_torn,
    /// The records are durable; the store does not serve the certificate yet.
    cert_logged,
    /// The store serves the certificate; the mark is still set.
    cert_installed,
    /// A rewrite of the log stopped before, or after, its rename.
    rewrite_before_rename,
    rewrite_after_rename,
};

pub const ErrKind = enum(u8) {
    /// The core's summary is not the one the edge holds: never overwritten.
    summary_mismatch,
    /// The core's certificate does not verify against the epoch's committee.
    bad_certificate,
    /// The answer does not decode, or names another checkpoint.
    decode,
    /// The core does not hold the checkpoint (below its retention, or not yet).
    not_held,
    /// The core refused the request (rate limited) or answered an error.
    refused,
    /// The way to the core failed.
    transport,
    /// The log could not be written.
    log_write,

    pub const count = @typeInfo(ErrKind).@"enum".field_names.len;
};

/// Where a read was answered with a certificate the edge holds that is not a core's, because
/// no core could be reached (docs/EDGE.md 13.2): a gRPC answer or stream frame, a zui/1
/// checkpoint, or a zui/1 proof (a verified read, the epoch proof).
pub const HeldPath = enum(u8) {
    grpc,
    zui1,
    proof,

    pub const count = @typeInfo(HeldPath).@"enum".field_names.len;
};

pub const Stats = struct {
    /// Checkpoints marked (since start; marks found in the log at start included).
    marked: Atomic(u64) = .init(0),
    /// Marks cleared: the core's certificate installed, the stored one found to be the core's,
    /// and the checkpoint pruned before either.
    replaced: Atomic(u64) = .init(0),
    equal: Atomic(u64) = .init(0),
    pruned: Atomic(u64) = .init(0),
    errors: [ErrKind.count]Atomic(u64) = @splat(.init(0)),
    /// Refetch calls and the summaries asked for in them.
    batches: Atomic(u64) = .init(0),
    requests: Atomic(u64) = .init(0),
    /// Log syncs (marks and replacements).
    syncs: Atomic(u64) = .init(0),
    /// Fallback periods whose marks were all cleared.
    periods: Atomic(u64) = .init(0),
    /// The wait before the next refetch call (ms): the pace, or the backoff.
    wait_ms: Atomic(u64) = .init(0),
    /// Reads answered with a held certificate that is not a core's while no core was reachable.
    held_served: [HeldPath.count]Atomic(u64) = @splat(.init(0)),
};

/// A verified answer of the core for one marked checkpoint (`Certs.resolve`).
pub const Resolved = struct {
    seq: u64,
    /// The core's certified summary; null: the stored bytes are the core's.
    cert: ?[]const u8,
};

pub const Options = struct {
    /// The store's lowest served checkpoint and its committed tip (null: an empty store).
    floor: u64 = 0,
    top: ?u64 = null,
    /// Checkpoints one mark record covers ahead.
    ahead: u32 = 32,
    /// Wall clock ms (marks made at open).
    now_ms: u64 = 0,
    /// The log is rewritten at open when at least this much of it is dead, and that is a
    /// quarter of it or `compact_bytes`.
    compact_min: u64 = 64 << 10,
    compact_bytes: u64 = 16 << 20,
    crash_at: ?Crash = null,
    /// Log lines (off in rule tests).
    log: bool = true,
};

pub const Certs = struct {
    gpa: Allocator,
    io: Io,
    dir: Io.Dir,
    file: Io.File,
    marks: Marks,
    deferred: Deferred,
    stats: Stats = .{},
    /// Guards the file and the coverage (the apply thread marks, the converge thread resolves).
    mu: Io.Mutex = .init,
    end: u64 = 0,
    /// Checkpoints `cover_first .. cover_end` are under a durable mark record of this process.
    cover_first: u64 = 0,
    cover_end: u64 = 0,
    ahead: u32 = 32,
    /// The current fallback period, for its closing line: when its first mark was made and how
    /// its marks ended. A period opens with the first mark on an empty set and closes when the
    /// set is empty again.
    period_ms: Atomic(u64) = .init(0),
    period_marked: Atomic(u64) = .init(0),
    period_replaced: Atomic(u64) = .init(0),
    period_equal: Atomic(u64) = .init(0),
    period_pruned: Atomic(u64) = .init(0),
    /// Reads answered with a held certificate during the period (no core was reachable).
    period_held: Atomic(u64) = .init(0),
    /// The core's lowest held checkpoint as a refetch last learned it (0: unknown): marks below
    /// it wait for the edge's own floor to pass them.
    core_floor: Atomic(u64) = .init(0),
    /// Tests: `error.CrashInjected` at this point, as a crash would stop there.
    crash_at: ?Crash = null,
    log: bool = true,

    pub const Error = error{ CrashInjected, LogWrite } || Allocator.Error;

    /// Opens (or creates) `dir/edge-certs.log` and rebuilds the marked set. The caller installs
    /// `result.fixes` in its store (`Store.cert_fix.load`) and then frees the result.
    pub fn open(gpa: Allocator, io: Io, dir: Io.Dir, o: Options) !Opened {
        // A rewrite that a crash stopped before its rename: the log is still the old one.
        dir.deleteFile(io, log_tmp) catch {};
        var missing = false;
        const data = dir.readFileAlloc(io, log_name, gpa, .unlimited) catch |e| switch (e) {
            error.FileNotFound => blk: {
                missing = true;
                break :blk try gpa.dupe(u8, "");
            },
            else => return e,
        };
        var found: Open = .{ .data = data, .bytes = data.len };
        errdefer found.deinit(gpa);
        const c = try gpa.create(Certs);
        errdefer gpa.destroy(c);
        c.* = .{ .gpa = gpa, .io = io, .dir = dir, .file = undefined, .marks = .{ .gpa = gpa }, .deferred = .{ .gpa = gpa }, .ahead = @max(1, o.ahead), .crash_at = o.crash_at, .log = o.log };
        errdefer c.marks.deinit();

        const has_magic = data.len >= log_magic.len and std.mem.eql(u8, data[0..log_magic.len], log_magic);
        var certs: std.AutoHashMapUnmanaged(u64, []const u8) = .empty;
        defer certs.deinit(gpa);
        var damaged = false;
        var at: usize = if (has_magic) log_magic.len else 0;
        var live: u64 = 0;
        if (has_magic) scan: while (true) {
            const rec = switch (parseRec(data[at..])) {
                .ok => |r| r,
                .none => break,
                .bad => |first| {
                    // intact records after it: a record in the middle is lost, and with it
                    // possibly a mark. Nothing after it can make up for that.
                    var to = at + first;
                    while (true) switch (parseRec(data[to..])) {
                        .ok => {
                            damaged = true;
                            break :scan;
                        },
                        .none => break :scan, // nothing intact after it: the torn tail
                        .bad => |k| to += k,
                    };
                },
            };
            at += rec_head + rec.payload.len;
            switch (rec.kind) {
                .mark => {
                    found.marks += 1;
                    const n = std.mem.readInt(u32, rec.payload[0..4], .little);
                    if (n == 0) continue;
                    const last = rec.seq +| (n - 1);
                    // A checkpoint marked again after its certificate was logged (a store that
                    // lost the commit and took it again) keeps both: the mark decides the reads
                    // until the core is asked again, and the logged certificate is still the
                    // core's for that checkpoint.
                    _ = try c.marks.addRange(rec.seq, last, std.mem.readInt(u64, rec.payload[4..12], .little));
                },
                .cert => {
                    found.certs += 1;
                    _ = c.marks.remove(rec.seq);
                    try certs.put(gpa, rec.seq, rec.payload);
                },
                .clear => {
                    found.clears += 1;
                    const n = std.mem.readInt(u32, rec.payload[0..4], .little);
                    if (n == 0) continue;
                    // what the edge serves for them (the stored certificate, or one logged
                    // before) is the core's: only the marks go
                    _ = try c.marks.removeRange(rec.seq, rec.seq +| (n - 1));
                },
            }
        };
        found.cut = data.len - at;

        // What is no longer served needs neither a mark nor a certificate; a mark above the
        // store's tip is of a commit the store does not hold (it is made again with the commit).
        if (o.floor > 0) _ = try c.marks.removeRange(0, o.floor - 1);
        if (o.top) |t| {
            if (t < std.math.maxInt(u64)) _ = try c.marks.removeRange(t + 1, std.math.maxInt(u64));
        } else _ = try c.marks.removeRange(0, std.math.maxInt(u64));

        // No word on the checkpoints the store holds: all of them are suspect.
        const unknown: ?[]const u8 = if (damaged)
            "a damaged record between intact ones"
        else if (o.top != null and (missing or !has_magic))
            (if (missing) "no log beside a store that holds checkpoints" else "the log's header is not this log's")
        else
            null;
        if (unknown) |why| if (o.top) |t| if (t >= o.floor) {
            _ = try c.marks.addRange(o.floor, t, o.now_ms);
            found.all_from = o.floor;
            found.all_why = why;
        };

        var fixes: std.ArrayList(Fix) = .empty;
        errdefer fixes.deinit(gpa);
        var it = certs.iterator();
        while (it.next()) |kv| {
            const seq = kv.key_ptr.*;
            if (seq < o.floor) continue;
            if (o.top) |t| {
                if (seq > t) continue;
            } else continue;
            // marked for a check of everything: the fix stays, the mark decides the reads
            try fixes.append(gpa, .{ .seq = seq, .cert = kv.value_ptr.* });
            live += rec_head + kv.value_ptr.len;
        }
        std.mem.sort(Fix, fixes.items, {}, struct {
            fn lt(_: void, a: Fix, b: Fix) bool {
                return a.seq < b.seq;
            }
        }.lt);
        found.fixes = try fixes.toOwnedSlice(gpa);

        // The file: as it is, cut at its torn tail, or written anew without its dead records.
        const runs = try c.marks.snapshot(gpa);
        defer gpa.free(runs);
        live += @as(u64, runs.len) * (rec_head + 12);
        const body: u64 = if (has_magic) at - log_magic.len else 0;
        const dead = body -| live;
        const want_rewrite = !has_magic or damaged or found.all_from != null or
            (dead >= o.compact_min and (dead * 4 > body or dead >= o.compact_bytes));
        if (want_rewrite) {
            if (rewrite(gpa, io, dir, runs, found.fixes, o.crash_at)) |n| {
                found.rewritten = true;
                found.size = n;
            } else |e| {
                if (e == error.CrashInjected) return e;
                // a new log is needed and cannot be written: nothing durable would say what is
                // marked. The caller decides (the node stops).
                if (!has_magic or damaged or found.all_from != null) return e;
                dir.deleteFile(io, log_tmp) catch {};
                found.size = at;
            }
        } else found.size = at;
        const f = try dir.createFile(io, log_name, .{ .read = true, .truncate = false });
        errdefer f.close(io);
        if (!found.rewritten and found.cut > 0) {
            try f.setLength(io, at);
            try f.sync(io);
        }
        c.file = f;
        c.end = found.size;
        const n = c.marks.count();
        _ = c.stats.marked.fetchAdd(n, .monotonic);
        if (n > 0) c.openPeriod(c.marks.oldestMs() orelse o.now_ms, n);
        return .{ .certs = c, .found = found };
    }

    pub fn deinit(c: *Certs) void {
        c.file.close(c.io);
        c.marks.deinit();
        c.deferred.deinit();
        c.gpa.destroy(c);
    }

    /// Writes the log anew: the certificates, then the marked runs. Beside the old one, synced,
    /// renamed over it, the directory synced: a crash leaves the old log or the new one, whole.
    fn rewrite(gpa: Allocator, io: Io, dir: Io.Dir, runs: []const Run, fixes: []const Fix, crash_at: ?Crash) !u64 {
        var end: u64 = 0;
        {
            const f = try dir.createFile(io, log_tmp, .{ .truncate = true });
            defer f.close(io);
            var buf: std.ArrayList(u8) = .empty;
            defer buf.deinit(gpa);
            try buf.appendSlice(gpa, log_magic);
            // Certificates first: a mark after a certificate stands (a checkpoint that is both
            // marked and served from a logged certificate stays both).
            for (fixes) |fx| {
                try encodeRec(gpa, &buf, .cert, fx.seq, fx.cert);
                if (buf.items.len < 1 << 20) continue;
                try f.writePositionalAll(io, buf.items, end);
                end += buf.items.len;
                buf.clearRetainingCapacity();
            }
            for (runs) |r| {
                // a run longer than a record's count is several records
                var s = r.first;
                while (true) {
                    const left = r.last - s + 1;
                    const n: u32 = @intCast(@min(left, std.math.maxInt(u32)));
                    try encodeMark(gpa, &buf, s, n, r.at_ms);
                    if (left == n) break;
                    s += n;
                }
            }
            try f.writePositionalAll(io, buf.items, end);
            end += buf.items.len;
            try f.sync(io);
        }
        if (crash_at) |x| if (x == .rewrite_before_rename) return error.CrashInjected;
        try dir.rename(log_tmp, dir, log_name, io);
        if (crash_at) |x| if (x == .rewrite_after_rename) return error.CrashInjected;
        syncDir(io, dir) catch |e| std.log.warn("edge certificates log: directory sync after the rewrite: {s}", .{@errorName(e)});
        return end;
    }

    fn syncDir(io: Io, dir: Io.Dir) !void {
        const d = try dir.openDir(io, ".", .{ .iterate = true });
        defer d.close(io);
        const f: Io.File = .{ .handle = d.handle, .flags = .{ .nonblocking = false } };
        try f.sync(io);
    }

    fn openPeriod(c: *Certs, at_ms: u64, n: u64) void {
        c.period_ms.store(at_ms, .monotonic);
        c.period_marked.store(n, .monotonic);
        c.period_replaced.store(0, .monotonic);
        c.period_equal.store(0, .monotonic);
        c.period_pruned.store(0, .monotonic);
        c.period_held.store(0, .monotonic);
    }

    /// A read went out with the certificate the edge holds for a marked checkpoint, because no
    /// core could be reached: valid, and not the core's bytes.
    pub fn noteHeld(c: *Certs, path: HeldPath) void {
        _ = c.stats.held_served[@intFromEnum(path)].fetchAdd(1, .monotonic);
        _ = c.period_held.fetchAdd(1, .monotonic);
    }

    /// Appends `bytes` and syncs. Under `mu`.
    fn appendSync(c: *Certs, bytes: []const u8) !void {
        try c.file.writePositionalAll(c.io, bytes, c.end);
        c.end += bytes.len;
        try c.file.sync(c.io);
        _ = c.stats.syncs.fetchAdd(1, .monotonic);
    }

    /// The follower is about to commit checkpoint `seq`; `from_core`: its bytes came from a
    /// core's feed. Anything else is marked, durably, before this returns: an error here must
    /// stop the commit (the certificate would be foreign with nothing saying so).
    pub fn onApply(c: *Certs, seq: u64, from_core: bool, now_ms: u64) Error!void {
        if (from_core) return;
        {
            c.mu.lockUncancelable(c.io);
            defer c.mu.unlock(c.io);
            if (seq < c.cover_first or seq >= c.cover_end) {
                const rec = markBytes(seq, c.ahead, now_ms);
                c.appendSync(&rec) catch |e| {
                    _ = c.stats.errors[@intFromEnum(ErrKind.log_write)].fetchAdd(1, .monotonic);
                    if (c.log) std.log.err("edge certificates log: marking checkpoint {d}: {s}", .{ seq, @errorName(e) });
                    return error.LogWrite;
                };
                c.cover_first = seq;
                c.cover_end = seq +| c.ahead;
            }
        }
        const was = c.marks.count();
        if (try c.marks.add(seq, now_ms)) {
            _ = c.stats.marked.fetchAdd(1, .monotonic);
            if (was == 0) c.openPeriod(now_ms, 1) else _ = c.period_marked.fetchAdd(1, .monotonic);
        }
    }

    /// Is the certificate the edge holds for `seq` one that did not come from a core (and has
    /// not been replaced)? One load while nothing is marked.
    pub fn isMarked(c: *Certs, seq: u64) bool {
        return c.marks.contains(seq);
    }

    pub fn pending(c: *const Certs) u64 {
        return c.marks.count();
    }

    /// The edge is in a foreign period at its tip: the highest marked checkpoint is within
    /// `hold` checkpoints of `tip`. A stream that renders certificates is not started locally
    /// then (its next checkpoints are likely marked too).
    pub fn recentAt(c: *Certs, tip: u64, hold: u64) bool {
        const h = c.marks.highest() orelse return false;
        return h +| hold >= tip;
    }

    /// The marked checkpoints to ask the core about next: within `floor..=tip` (what the edge
    /// serves) and at or above what the core holds, highest first (reads are at the tip, and old
    /// marks leave with retention). Marks below `floor` are dropped here: pruned, never served.
    pub fn next(c: *Certs, out: []u64, floor: u64, tip: u64, now_ns: u64) usize {
        if (floor > 0) {
            const gone = c.marks.removeRange(0, floor - 1) catch 0;
            if (gone > 0) {
                _ = c.stats.pruned.fetchAdd(gone, .monotonic);
                _ = c.period_pruned.fetchAdd(gone, .monotonic);
                c.maybeClosePeriod(now_ns);
            }
        }
        c.deferred.expire(now_ns, floor);
        return c.marks.top(out, @max(floor, c.core_floor.load(.monotonic)), tip, &c.deferred);
    }

    /// Step one of a replacement: the verified answers are logged and synced. After this the
    /// caller installs the certificates in its store, then calls `cleared`. `items` in any order.
    pub fn resolve(c: *Certs, items: []const Resolved) Error!void {
        if (items.len == 0) return;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(c.gpa);
        for (items) |it| {
            if (it.cert) |bytes| try encodeRec(c.gpa, &buf, .cert, it.seq, bytes) else try encodeClear(c.gpa, &buf, it.seq, 1);
        }
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        if (c.crash_at) |x| if (x == .cert_torn) {
            // half of the bytes, no sync: what a crash inside the write leaves at best
            c.file.writePositionalAll(c.io, buf.items[0 .. buf.items.len / 2], c.end) catch {};
            return error.CrashInjected;
        };
        c.appendSync(buf.items) catch |e| {
            _ = c.stats.errors[@intFromEnum(ErrKind.log_write)].fetchAdd(1, .monotonic);
            if (c.log) std.log.err("edge certificates log: {d} replacements: {s}", .{ items.len, @errorName(e) });
            return error.LogWrite;
        };
        if (c.crash_at) |x| if (x == .cert_logged) return error.CrashInjected;
    }

    /// Step three (after the store serves the certificates of `items`): the marks are cleared.
    pub fn cleared(c: *Certs, items: []const Resolved, now_ms: u64) Error!void {
        if (c.crash_at) |x| if (x == .cert_installed) return error.CrashInjected;
        for (items) |it| {
            if (!c.marks.remove(it.seq)) continue;
            c.deferred.drop(it.seq);
            if (it.cert != null) {
                _ = c.stats.replaced.fetchAdd(1, .monotonic);
                _ = c.period_replaced.fetchAdd(1, .monotonic);
            } else {
                _ = c.stats.equal.fetchAdd(1, .monotonic);
                _ = c.period_equal.fetchAdd(1, .monotonic);
            }
        }
        c.closePeriodAt(now_ms);
    }

    fn maybeClosePeriod(c: *Certs, _: u64) void {
        c.closePeriodAt(wallMs());
    }

    /// The one line when a period's marks are all gone.
    fn closePeriodAt(c: *Certs, now_ms: u64) void {
        if (c.marks.count() != 0) return;
        const at = c.period_ms.swap(0, .acq_rel);
        if (at == 0) return;
        _ = c.stats.periods.fetchAdd(1, .monotonic);
        if (c.log) std.log.info("edge certificates: all {d} checkpoints taken from another source than a core now hold the core's certificate ({d} replaced, {d} already equal, {d} pruned first), {d} s after the first was marked; {d} reads were answered with the held certificate while no core was reachable", .{
            c.period_marked.load(.monotonic),
            c.period_replaced.load(.monotonic),
            c.period_equal.load(.monotonic),
            c.period_pruned.load(.monotonic),
            (now_ms -| at) / 1000,
            c.period_held.load(.monotonic),
        });
    }

    pub fn countError(c: *Certs, k: ErrKind) void {
        _ = c.stats.errors[@intFromEnum(k)].fetchAdd(1, .monotonic);
    }

    /// Seconds since the oldest mark still pending was made (0: none).
    pub fn oldestSeconds(c: *Certs, now_ms: u64) u64 {
        const at = c.marks.oldestMs() orelse return 0;
        return (now_ms -| at) / 1000;
    }

    /// The `zui_edge_cert_*` lines (docs/EDGE.md 13.6).
    pub fn renderMetrics(c: *Certs, w: *Io.Writer, now_ms: u64) !void {
        const s = &c.stats;
        try w.print("# TYPE zui_edge_cert_pending gauge\nzui_edge_cert_pending {d}\n", .{c.pending()});
        try w.print("# TYPE zui_edge_cert_oldest_mark_seconds gauge\nzui_edge_cert_oldest_mark_seconds {d}\n", .{c.oldestSeconds(now_ms)});
        try w.print("# TYPE zui_edge_cert_marked counter\nzui_edge_cert_marked {d}\n", .{s.marked.load(.monotonic)});
        try w.print("# TYPE zui_edge_cert_replaced counter\nzui_edge_cert_replaced {d}\n", .{s.replaced.load(.monotonic)});
        try w.print("# TYPE zui_edge_cert_equal counter\nzui_edge_cert_equal {d}\n", .{s.equal.load(.monotonic)});
        try w.print("# TYPE zui_edge_cert_pruned counter\nzui_edge_cert_pruned {d}\n", .{s.pruned.load(.monotonic)});
        try w.writeAll("# TYPE zui_edge_cert_errors counter\n");
        inline for (comptime std.meta.fieldNames(ErrKind), 0..) |name, i| {
            try w.print("zui_edge_cert_errors{{kind=\"{s}\"}} {d}\n", .{ name, s.errors[i].load(.monotonic) });
        }
        try w.writeAll("# TYPE zui_edge_cert_held_served counter\n");
        inline for (comptime std.meta.fieldNames(HeldPath), 0..) |name, i| {
            try w.print("zui_edge_cert_held_served{{path=\"{s}\"}} {d}\n", .{ name, s.held_served[i].load(.monotonic) });
        }
        try w.print("# TYPE zui_edge_cert_refetch_calls counter\nzui_edge_cert_refetch_calls {d}\n", .{s.batches.load(.monotonic)});
        try w.print("# TYPE zui_edge_cert_refetch_requests counter\nzui_edge_cert_refetch_requests {d}\n", .{s.requests.load(.monotonic)});
        try w.print("# TYPE zui_edge_cert_periods_cleared counter\nzui_edge_cert_periods_cleared {d}\n", .{s.periods.load(.monotonic)});
        try w.print("# TYPE zui_edge_cert_wait_ms gauge\nzui_edge_cert_wait_ms {d}\n", .{s.wait_ms.load(.monotonic)});
        try w.print("# TYPE zui_edge_cert_log_bytes gauge\nzui_edge_cert_log_bytes {d}\n", .{c.end});
    }
};

pub fn wallMs() u64 {
    var ts: std.posix.timespec = undefined;
    if (@import("builtin").os.tag == .linux) {
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
    } else {
        _ = std.c.clock_gettime(.REALTIME, &ts);
    }
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

// ---------------------------------------------------------------- pacing and the gate

/// How fast the edge asks its core for certified summaries. The refetch is the lowest priority
/// thing an edge does: one call at a time, `batch` small requests in it (each is answered from
/// the core's store on its listener thread, a few hundred bytes), a pause between calls, and
/// after anything but a clean call (a refusal, an error, a failed link, a certificate that does
/// not verify) the pause doubles up to `backoff_max_ms`. A clean call brings it back.
pub const Pace = struct {
    /// Requests in one call: all that are ever in flight.
    batch: u32 = 16,
    interval_ms: u32 = 100,
    backoff_max_ms: u32 = 30_000,
    /// The wait when there is nothing to do, or the gate is shut.
    idle_ms: u32 = 250,
    cur_ms: u32 = 0,

    pub const Outcome = enum { clean, failed, idle };

    /// The wait (ms) before the next call, after a call that ended `o`.
    pub fn after(p: *Pace, o: Outcome) u32 {
        switch (o) {
            .clean => p.cur_ms = p.interval_ms,
            .failed => p.cur_ms = @min(@max(p.backoff_max_ms, p.interval_ms), @max(p.cur_ms, p.interval_ms) *| 2),
            // a backoff under way is not forgotten for a turn with nothing to ask
            .idle => return @max(p.idle_ms, p.cur_ms),
        }
        return p.cur_ms;
    }
};

/// What the converge loop looks at before a call.
pub const Obs = struct {
    /// Marks waiting.
    pending: u64,
    /// The edge takes its checkpoints from a core now (not from its fallback).
    on_core: bool,
    /// The newest checkpoint known to exist at the edge's sources (null: unknown, as in catch-up).
    known_tip: ?u64,
    /// The edge's committed tip (null: an empty store).
    committed: ?u64,
};

pub const Gate = enum {
    run,
    no_marks,
    /// The edge is on its fallback: no core to ask (or none that should be asked now).
    on_fallback,
    /// The edge does not know where the tip is (catch-up).
    tip_unknown,
    /// More than the lag limit behind the tip: the feed comes first.
    behind,
};

/// May the edge ask its core for certified summaries now? Never while it is on its fallback,
/// never while it is behind the tip by more than its lag guard (`max_lag`, `--edge-max-lag`) or
/// cannot tell: the core's time goes to the live feed first.
pub fn gate(max_lag: u64, o: Obs) Gate {
    if (o.pending == 0) return .no_marks;
    if (!o.on_core) return .on_fallback;
    const known = o.known_tip orelse return .tip_unknown;
    const have = o.committed orelse return .tip_unknown;
    if (known -| have > max_lag) return .behind;
    return .run;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn tmpCerts(tmp: *std.testing.TmpDir, o: Options) !Opened {
    var oo = o;
    oo.log = false;
    return Certs.open(testing.allocator, testing.io, tmp.dir, oo);
}

test "marks: runs merge, split and count; contains and top answer from them" {
    var m: Marks = .{ .gpa = testing.allocator };
    defer m.deinit();
    try testing.expect(!m.contains(5));
    try testing.expectEqual(@as(?u64, null), m.oldestMs());
    // a fallback period: 100..119, one by one, then 121 (120 came from a core)
    for (100..120) |s| try testing.expect(try m.add(s, 1000 + s));
    try testing.expect(!try m.add(105, 99_999));
    try testing.expect(try m.add(121, 2000));
    try testing.expectEqual(@as(u64, 21), m.count());
    try testing.expectEqual(@as(usize, 2), m.runs.items.len);
    try testing.expect(m.contains(100) and m.contains(119) and m.contains(121));
    try testing.expect(!m.contains(99) and !m.contains(120) and !m.contains(122));
    try testing.expect(m.any(90, 100) and m.any(120, 121) and !m.any(120, 120) and !m.any(122, 500) and !m.any(0, 99));
    try testing.expectEqual(@as(?u64, 1100), m.oldestMs());
    try testing.expectEqual(@as(?u64, 121), m.highest());
    // 120 joins the two runs
    try testing.expect(try m.add(120, 5000));
    try testing.expectEqual(@as(usize, 1), m.runs.items.len);
    try testing.expectEqual(@as(u64, 22), m.count());
    // highest first, inside a window, leaving the deferred ones out
    var d: Deferred = .{ .gpa = testing.allocator };
    defer d.deinit();
    try testing.expect(d.put(120, 0, 1000, 60_000));
    var out: [5]u64 = undefined;
    try testing.expectEqual(@as(usize, 5), m.top(&out, 0, 1000, &d));
    try testing.expectEqualSlices(u64, &.{ 121, 119, 118, 117, 116 }, &out);
    try testing.expectEqual(@as(usize, 3), m.top(&out, 100, 102, null));
    try testing.expectEqualSlices(u64, &.{ 102, 101, 100 }, out[0..3]);
    try testing.expectEqual(@as(usize, 0), m.top(&out, 200, 300, null));
    // one out of the middle splits the run; the ends shrink it
    try testing.expect(m.remove(110));
    try testing.expect(!m.remove(110));
    try testing.expectEqual(@as(usize, 2), m.runs.items.len);
    try testing.expect(m.remove(100) and m.remove(121));
    try testing.expectEqual(@as(u64, 19), m.count());
    try testing.expect(!m.contains(100) and m.contains(101) and !m.contains(110) and m.contains(120) and !m.contains(121));
    // ranges: over several runs, and everything
    try testing.expectEqual(@as(u64, 4), try m.removeRange(108, 112));
    try testing.expectEqual(@as(u64, 10), try m.addRange(95, 111, 7));
    try testing.expectEqual(@as(usize, 2), m.runs.items.len);
    try testing.expectEqual(@as(?u64, 7), m.oldestMs());
    try testing.expectEqual(m.count(), try m.removeRange(0, std.math.maxInt(u64)));
    try testing.expectEqual(@as(u64, 0), m.count());
    try testing.expectEqual(@as(usize, 0), m.runs.items.len);
}

test "marks: against a plain set, over random adds and removes" {
    var m: Marks = .{ .gpa = testing.allocator };
    defer m.deinit();
    var set: [512]bool = @splat(false);
    var prng = std.Random.DefaultPrng.init(0xce47);
    const rnd = prng.random();
    for (0..4000) |_| {
        const a = rnd.uintLessThan(u64, 512);
        const b: u64 = @min(511, a + rnd.uintLessThan(u64, 12));
        if (rnd.boolean()) {
            var want: u64 = 0;
            for (a..b + 1) |s| {
                if (!set[s]) want += 1;
                set[s] = true;
            }
            try testing.expectEqual(want, try m.addRange(a, b, 1));
        } else {
            var want: u64 = 0;
            for (a..b + 1) |s| {
                if (set[s]) want += 1;
                set[s] = false;
            }
            try testing.expectEqual(want, try m.removeRange(a, b));
        }
    }
    var n: u64 = 0;
    for (set, 0..) |on, s| {
        try testing.expectEqual(on, m.contains(s));
        if (on) n += 1;
    }
    try testing.expectEqual(n, m.count());
    for (m.runs.items, 0..) |r, i| {
        try testing.expect(r.first <= r.last);
        if (i > 0) try testing.expect(m.runs.items[i - 1].last + 1 < r.first);
    }
    var out: [512]u64 = undefined;
    const k = m.top(&out, 0, 511, null);
    try testing.expectEqual(n, @as(u64, k));
    for (out[0..k], 0..) |s, i| {
        try testing.expect(set[s]);
        if (i > 0) try testing.expect(out[i - 1] > s);
    }
}

test "deferred: a checkpoint waits longer each time, is asked again when its time comes, and the table is bounded" {
    var d: Deferred = .{ .gpa = testing.allocator, .max = 3 };
    defer d.deinit();
    const ms = std.time.ns_per_ms;
    try testing.expect(d.put(7, 1000 * ms, 100, 1000));
    try testing.expect(d.has(7));
    d.expire(1099 * ms, 0);
    try testing.expect(d.has(7));
    d.expire(1100 * ms, 0);
    try testing.expect(!d.has(7));
    // again and again without an expiry between: 100, 200, 400, 800, 1000, 1000
    for ([_]u64{ 100, 200, 400, 800, 1000, 1000 }) |want| {
        try testing.expect(d.put(7, 5000 * ms, 100, 1000));
        try testing.expectEqual(5000 * ms + want * ms, d.map.get(7).?.until_ns);
    }
    try testing.expect(d.put(8, 0, 100, 1000) and d.put(9, 0, 100, 1000));
    try testing.expect(!d.put(10, 0, 100, 1000));
    try testing.expect(!d.has(10));
    // below the floor: gone whatever its time
    d.expire(0, 9);
    try testing.expect(!d.has(7) and !d.has(8) and d.has(9));
}

test "edge certificates log: a mark is durable before onApply returns, one record covers a run ahead, and a restart finds every mark" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var o = try tmpCerts(&tmp, .{ .ahead = 8 });
        defer o.certs.deinit();
        defer o.found.deinit(testing.allocator);
        const c = o.certs;
        try testing.expectEqual(@as(?u64, null), o.found.all_from);
        try testing.expectEqual(@as(u64, log_magic.len), c.end);
        // from a core: nothing marked, nothing written
        try c.onApply(100, true, 50);
        try testing.expectEqual(@as(u64, 0), c.stats.syncs.load(.monotonic));
        // a spell on the fallback: 101..112, with 105 and 106 from the core in between
        for (101..113) |s| try c.onApply(s, s == 105 or s == 106, 1000 + s);
        try testing.expectEqual(@as(u64, 10), c.pending());
        try testing.expect(c.isMarked(101) and c.isMarked(104) and !c.isMarked(105) and !c.isMarked(106) and c.isMarked(107) and c.isMarked(112));
        // two records for twelve checkpoints: 101..108 and 109..116
        try testing.expectEqual(@as(u64, 2), c.stats.syncs.load(.monotonic));
        try testing.expectEqual(@as(u64, log_magic.len + 2 * (rec_head + 12)), c.end);
        try testing.expectEqual(@as(u64, 10), c.stats.marked.load(.monotonic));
    }
    // a restart (a crash: nothing was closed in order). The store's tip is 110: the marks of
    // 111 and 112 are of commits it does not hold. 105 and 106 are under the first record, so
    // they are marked now: the log cannot say they came from a core.
    {
        var o = try tmpCerts(&tmp, .{ .floor = 90, .top = 110 });
        defer o.certs.deinit();
        defer o.found.deinit(testing.allocator);
        const c = o.certs;
        try testing.expectEqual(@as(?u64, null), o.found.all_from);
        try testing.expectEqual(@as(u64, 10), c.pending());
        for (101..111) |s| try testing.expect(c.isMarked(s));
        try testing.expect(!c.isMarked(100) and !c.isMarked(111) and !c.isMarked(112));
        try testing.expectEqual(@as(u64, 1101), c.marks.oldestMs().?);
        // the first foreign checkpoint after the restart is logged again (no coverage is assumed)
        try c.onApply(111, false, 3000);
        try testing.expectEqual(@as(u64, 1), c.stats.syncs.load(.monotonic));
        try testing.expect(c.isMarked(111));
    }
    // a floor above some marks: they are not served, so they are gone
    {
        var o = try tmpCerts(&tmp, .{ .floor = 108, .top = 111 });
        defer o.certs.deinit();
        defer o.found.deinit(testing.allocator);
        try testing.expectEqual(@as(u64, 4), o.certs.pending());
        try testing.expect(!o.certs.isMarked(107) and o.certs.isMarked(108) and o.certs.isMarked(111));
    }
}

test "edge certificates log: a replacement is the record, then the store, then the mark; a crash at each step is read as one of them at the next start" {
    const gpa = testing.allocator;
    const core_cert = "summary-102|the core's certificate";
    // (crash point, marked after the restart, certificate to install after the restart)
    const Case = struct { at: ?Crash, marked: bool, fix: bool };
    const cases = [_]Case{
        // torn in the write: the record is cut, the mark stands, nothing to install
        .{ .at = .cert_torn, .marked = true, .fix = false },
        // logged, not yet in the store: the next start installs it, the mark is gone
        .{ .at = .cert_logged, .marked = false, .fix = true },
        // in the store, mark not yet cleared: the same
        .{ .at = .cert_installed, .marked = false, .fix = true },
        // no crash
        .{ .at = null, .marked = false, .fix = true },
    };
    for (cases) |case| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var o = try tmpCerts(&tmp, .{ .ahead = 4 });
            defer o.certs.deinit();
            defer o.found.deinit(gpa);
            const c = o.certs;
            for (100..104) |s| try c.onApply(s, false, 10);
            c.crash_at = case.at;
            const items = [_]Resolved{ .{ .seq = 102, .cert = core_cert }, .{ .seq = 103, .cert = null } };
            const r: Certs.Error!void = blk: {
                c.resolve(&items) catch |e| break :blk e;
                // (the store installs here)
                c.cleared(&items, 20) catch |e| break :blk e;
            };
            if (case.at != null) try testing.expectError(error.CrashInjected, r) else try r;
            // until the last step the marks stand: reads still go to the core
            try testing.expectEqual(case.at != null, c.isMarked(102));
            try testing.expectEqual(case.at != null, c.isMarked(103));
        }
        var o = try tmpCerts(&tmp, .{ .floor = 0, .top = 103 });
        defer o.certs.deinit();
        defer o.found.deinit(gpa);
        const c = o.certs;
        try testing.expectEqual(@as(?u64, null), o.found.all_from);
        try testing.expect(c.isMarked(100) and c.isMarked(101));
        try testing.expectEqual(case.marked, c.isMarked(102));
        try testing.expectEqual(case.marked, c.isMarked(103));
        if (case.fix) {
            try testing.expectEqual(@as(usize, 1), o.found.fixes.len);
            try testing.expectEqual(@as(u64, 102), o.found.fixes[0].seq);
            try testing.expectEqualStrings(core_cert, o.found.fixes[0].cert);
        } else {
            try testing.expectEqual(@as(usize, 0), o.found.fixes.len);
            try testing.expect(o.found.cut > 0);
        }
        // and convergence completes from there
        const rest = [_]Resolved{ .{ .seq = 100, .cert = "c100" }, .{ .seq = 101, .cert = null }, .{ .seq = 102, .cert = core_cert }, .{ .seq = 103, .cert = null } };
        try c.resolve(&rest);
        try c.cleared(&rest, 30);
        try testing.expectEqual(@as(u64, 0), c.pending());
        try testing.expectEqual(@as(u64, 1), c.stats.periods.load(.monotonic));
    }
}

test "edge certificates log: no log beside a store that holds checkpoints, or a damaged record between intact ones, marks everything served; an empty store marks nothing" {
    const gpa = testing.allocator;
    // a fresh edge
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var o = try tmpCerts(&tmp, .{});
        defer o.certs.deinit();
        defer o.found.deinit(gpa);
        try testing.expectEqual(@as(?u64, null), o.found.all_from);
        try testing.expectEqual(@as(u64, 0), o.certs.pending());
    }
    // an edge from before the log existed: its store serves 500..900
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var o = try tmpCerts(&tmp, .{ .floor = 500, .top = 900, .now_ms = 77 });
            defer o.certs.deinit();
            defer o.found.deinit(gpa);
            try testing.expectEqual(@as(?u64, 500), o.found.all_from);
            try testing.expectEqual(@as(u64, 401), o.certs.pending());
            try testing.expect(o.certs.isMarked(500) and o.certs.isMarked(900) and !o.certs.isMarked(499) and !o.certs.isMarked(901));
            try testing.expect(o.found.rewritten);
        }
        // that verdict is durable: the next start finds the same marks and does not start over
        var o = try tmpCerts(&tmp, .{ .floor = 500, .top = 905 });
        defer o.certs.deinit();
        defer o.found.deinit(gpa);
        try testing.expectEqual(@as(?u64, null), o.found.all_from);
        try testing.expectEqual(@as(u64, 401), o.certs.pending());
        try testing.expect(!o.certs.isMarked(901));
    }
    // a damaged record in the middle
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var o = try tmpCerts(&tmp, .{ .ahead = 1 });
            defer o.certs.deinit();
            defer o.found.deinit(gpa);
            for (10..14) |s| try o.certs.onApply(s, false, 5);
        }
        const data = try tmp.dir.readFileAlloc(testing.io, log_name, gpa, .unlimited);
        defer gpa.free(data);
        // the second record's sequence number
        data[log_magic.len + (rec_head + 12) + 12] ^= 0x40;
        try tmp.dir.writeFile(testing.io, .{ .sub_path = log_name, .data = data });
        {
            var o = try tmpCerts(&tmp, .{ .floor = 3, .top = 20 });
            defer o.certs.deinit();
            defer o.found.deinit(gpa);
            try testing.expectEqual(@as(?u64, 3), o.found.all_from);
            try testing.expectEqual(@as(u64, 18), o.certs.pending());
        }
        // the same damage at the tail is a torn write: cut, and the marks before it stand
        const good = try tmp.dir.readFileAlloc(testing.io, log_name, gpa, .unlimited);
        defer gpa.free(good);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = log_name, .data = good[0 .. good.len - 5] });
        var o = try tmpCerts(&tmp, .{ .floor = 3, .top = 20 });
        defer o.certs.deinit();
        defer o.found.deinit(gpa);
        try testing.expectEqual(@as(?u64, null), o.found.all_from);
        try testing.expect(o.found.cut > 0);
    }
}

test "edge certificates log: a start rewrites a log that is mostly dead, and a crash on either side of the rename leaves a whole log" {
    const gpa = testing.allocator;
    for ([_]?Crash{ null, .rewrite_before_rename, .rewrite_after_rename }) |crash| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var cert: [300]u8 = undefined;
        @memset(&cert, 0x5a);
        {
            var o = try tmpCerts(&tmp, .{ .ahead = 1 });
            defer o.certs.deinit();
            defer o.found.deinit(gpa);
            const c = o.certs;
            for (0..400) |s| try c.onApply(s, false, 1);
            for (0..300) |s| {
                const it = [_]Resolved{.{ .seq = s, .cert = if (s % 2 == 0) &cert else null }};
                try c.resolve(&it);
                try c.cleared(&it, 2);
            }
        }
        const before = (try tmp.dir.statFile(testing.io, log_name, .{})).size;
        // the store's floor is 250 now: most records are of checkpoints no longer served
        const r = tmpCerts(&tmp, .{ .floor = 250, .top = 399, .compact_min = 1024, .crash_at = crash });
        if (crash != null) {
            try testing.expectError(error.CrashInjected, r);
        } else {
            var o = try r;
            defer o.certs.deinit();
            defer o.found.deinit(gpa);
            try testing.expect(o.found.rewritten);
            try testing.expect(o.found.size < before / 4);
        }
        // whatever happened, the next start reads the same state
        var o = try tmpCerts(&tmp, .{ .floor = 250, .top = 399, .compact_min = 1 << 30 });
        defer o.certs.deinit();
        defer o.found.deinit(gpa);
        try testing.expectEqual(@as(?u64, null), o.found.all_from);
        try testing.expectEqual(@as(u64, 100), o.certs.pending());
        try testing.expect(!o.certs.isMarked(299) and o.certs.isMarked(300) and o.certs.isMarked(399));
        try testing.expectEqual(@as(usize, 25), o.found.fixes.len);
        for (o.found.fixes, 0..) |fx, i| {
            try testing.expectEqual(@as(u64, 250 + 2 * i), fx.seq);
            try testing.expectEqualSlices(u8, &cert, fx.cert);
        }
    }
}

test "edge certificates: next asks highest first inside what the edge serves and the core holds, and drops marks below the floor" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var o = try tmpCerts(&tmp, .{});
    defer o.certs.deinit();
    defer o.found.deinit(testing.allocator);
    const c = o.certs;
    for (100..140) |s| try c.onApply(s, false, 1);
    var out: [4]u64 = undefined;
    // the tip is 137: 138 and 139 are not committed yet
    try testing.expectEqual(@as(usize, 4), c.next(&out, 0, 137, 0));
    try testing.expectEqualSlices(u64, &.{ 137, 136, 135, 134 }, &out);
    // one of them failed: left alone until its time
    try testing.expect(c.deferred.put(136, 0, 1000, 60_000));
    try testing.expectEqual(@as(usize, 4), c.next(&out, 0, 137, 500 * std.time.ns_per_ms));
    try testing.expectEqualSlices(u64, &.{ 137, 135, 134, 133 }, &out);
    try testing.expectEqual(@as(usize, 4), c.next(&out, 0, 137, 1000 * std.time.ns_per_ms));
    try testing.expectEqualSlices(u64, &.{ 137, 136, 135, 134 }, &out);
    // the core holds nothing below 120; the edge's floor moved to 110
    c.core_floor.store(120, .monotonic);
    var all: [64]u64 = undefined;
    try testing.expectEqual(@as(usize, 18), c.next(&all, 110, 137, 0));
    try testing.expectEqual(@as(u64, 120), all[17]);
    try testing.expectEqual(@as(u64, 30), c.pending());
    try testing.expectEqual(@as(u64, 10), c.stats.pruned.load(.monotonic));
    // a period ends when its last marks are pruned, too
    try testing.expectEqual(@as(usize, 0), c.next(&all, 200, 300, 0));
    try testing.expectEqual(@as(u64, 0), c.pending());
    try testing.expectEqual(@as(u64, 1), c.stats.periods.load(.monotonic));
    // a foreign period at the tip: the newest mark within a few checkpoints of it
    try c.onApply(500, false, 1);
    try testing.expect(c.recentAt(500, 8) and c.recentAt(508, 8) and !c.recentAt(509, 8));
}

test "pace: one call at a time; anything but a clean call doubles the pause up to the cap, a clean one brings it back" {
    var p: Pace = .{};
    try testing.expectEqual(@as(u32, 100), p.after(.clean));
    var want: u32 = 200;
    for (0..12) |_| {
        try testing.expectEqual(want, p.after(.failed));
        want = @min(want * 2, 30_000);
    }
    try testing.expectEqual(@as(u32, 30_000), p.after(.failed));
    // nothing to ask does not shorten a backoff
    try testing.expectEqual(@as(u32, 30_000), p.after(.idle));
    try testing.expectEqual(@as(u32, 100), p.after(.clean));
    try testing.expectEqual(@as(u32, 250), p.after(.idle));
    // at the shipped numbers: 16 requests every 100 ms, 160 summaries a second at most
    try testing.expectEqual(@as(u32, 16), p.batch);
}

test "gate: only on a core, at the tip, inside the lag limit" {
    const Row = struct { o: Obs, want: Gate };
    const rows = [_]Row{
        .{ .o = .{ .pending = 0, .on_core = true, .known_tip = 100, .committed = 100 }, .want = .no_marks },
        .{ .o = .{ .pending = 3, .on_core = true, .known_tip = 100, .committed = 100 }, .want = .run },
        .{ .o = .{ .pending = 3, .on_core = true, .known_tip = 105, .committed = 100 }, .want = .run },
        .{ .o = .{ .pending = 3, .on_core = true, .known_tip = 106, .committed = 100 }, .want = .behind },
        .{ .o = .{ .pending = 3, .on_core = false, .known_tip = 100, .committed = 100 }, .want = .on_fallback },
        .{ .o = .{ .pending = 3, .on_core = true, .known_tip = null, .committed = 100 }, .want = .tip_unknown },
        .{ .o = .{ .pending = 3, .on_core = true, .known_tip = 100, .committed = null }, .want = .tip_unknown },
        // the store ahead of what the fetcher last saw is not behind
        .{ .o = .{ .pending = 3, .on_core = true, .known_tip = 100, .committed = 104 }, .want = .run },
    };
    for (rows) |r| try testing.expectEqual(r.want, gate(5, r.o));
}

test "edge certificates: metrics" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var o = try tmpCerts(&tmp, .{});
    defer o.certs.deinit();
    defer o.found.deinit(testing.allocator);
    const c = o.certs;
    for (10..15) |s| try c.onApply(s, false, 1000);
    c.countError(.bad_certificate);
    c.noteHeld(.zui1);
    c.noteHeld(.proof);
    c.noteHeld(.proof);
    try testing.expectEqual(@as(u64, 3), c.period_held.load(.monotonic));
    const it = [_]Resolved{.{ .seq = 12, .cert = "x" }};
    try c.resolve(&it);
    try c.cleared(&it, 2000);
    var aw: Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try c.renderMetrics(&aw.writer, 61_000);
    const text = aw.written();
    for ([_][]const u8{
        "zui_edge_cert_pending 4\n",
        "zui_edge_cert_oldest_mark_seconds 60\n",
        "zui_edge_cert_marked 5\n",
        "zui_edge_cert_replaced 1\n",
        "zui_edge_cert_errors{kind=\"bad_certificate\"} 1\n",
        "zui_edge_cert_errors{kind=\"summary_mismatch\"} 0\n",
        "zui_edge_cert_held_served{path=\"grpc\"} 0\n",
        "zui_edge_cert_held_served{path=\"zui1\"} 1\n",
        "zui_edge_cert_held_served{path=\"proof\"} 2\n",
    }) |line| try testing.expect(std.mem.indexOf(u8, text, line) != null);
}
