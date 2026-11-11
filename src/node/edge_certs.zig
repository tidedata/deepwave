//! The node's part of an edge's certificate convergence (docs/EDGE.md section 13). The marked
//! set, its log and the rules are edge/certs.zig; this is what touches the store, the fetch
//! stage and the cores:
//!
//!  - `onBatch` (the follower's apply thread, before each commit): a checkpoint whose spooled
//!    blob did not come from a core's feed is marked, durably, before its batch is committed.
//!  - The converge thread: while the edge is on a core, at the tip and inside its lag limit, it
//!    asks the core for the certified summaries of marked checkpoints (`Pool.fetchSummaries`:
//!    `get_checkpoint` with no parts, a few at a time, paced), verifies each as the follower
//!    verifies any (the certificate against the epoch's committee) and against what the edge
//!    holds (the same CheckpointSummary, byte for byte: a different summary is never taken),
//!    logs the answers, installs the core's certificates in the store (`Store.cert_fix`) and
//!    clears the marks. Every reader of a checkpoint (`Snapshot.checkpoint`) then gets the
//!    core's bytes, and the GetCheckpoint response cache drops what it rendered before
//!    (the fix table's generation).
//!  - `nativeHook`: what the zui/1 dispatcher asks, so it never hands a marked certificate on.
const std = @import("std");
const Io = std.Io;
const Atomic = std.atomic.Value;
const store = @import("store");
const sync = @import("sync");
const bcs = @import("bcs");
const types = @import("types");
const edge = @import("edge");
const native = @import("native");
const source_mod = @import("source.zig");
const certs_mod = edge.certs;
const Pool = edge.client.Pool;
const log = std.log.scoped(.edge_certs);

/// Where the committee of an epoch comes from (the node: the committees it persisted,
/// trust.zig; every committed checkpoint's epoch has one on disk).
pub const Committees = struct {
    ctx: *anyopaque,
    /// The committee of `epoch`, built in `arena`; null: not known.
    get: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, epoch: u64) ?sync.Committee,
};

/// How one answer of the core for a marked checkpoint was judged.
pub const Verdict = union(enum) {
    /// The core's certificate verifies and differs from the one the edge serves: take it.
    replace,
    /// It verifies and is the one the edge serves already.
    equal,
    bad: certs_mod.ErrKind,
    /// The edge no longer holds the checkpoint (pruned meanwhile): nothing to do.
    gone,
};

pub const Options = struct {
    /// `--edge-max-lag`: the converge loop waits while the edge is further behind the tip.
    max_lag: u64 = 5,
    pace: certs_mod.Pace = .{},
    /// Checkpoints one mark record covers ahead (edge/certs.zig).
    ahead: u32 = 32,
    /// A refetch call with no answer after this long is given up (and backed off).
    call_timeout_ms: u64 = 3_000,
    log: bool = true,
    crash_at: ?certs_mod.Crash = null,
};

pub const Converger = struct {
    gpa: std.mem.Allocator,
    io: Io,
    certs: *certs_mod.Certs,
    st: *store.Store,
    pool: *Pool,
    /// The fetch stage: where each spooled blob came from, and where the tip is.
    fetcher: ?*source_mod.Fetcher = null,
    /// The fallback switch; null: the cores are the only source.
    sw: ?*edge.fallback.Switch = null,
    committees: Committees,
    max_lag: u64,
    pace: certs_mod.Pace,
    call_timeout_ms: u64,
    stopping: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    /// The committee last used (one epoch at a time: marks are worked highest first).
    com_arena: std.heap.ArenaAllocator,
    com: ?sync.Committee = null,
    arena: std.heap.ArenaAllocator,
    /// Why the loop last did not ask (`certs_mod.Gate`), for the status line and the tests.
    last_gate: Atomic(u8) = .init(@intFromEnum(certs_mod.Gate.no_marks)),
    /// Hard errors are logged a few times, then only counted.
    shown: u32 = 0,
    quiet: bool = false,

    /// Opens the log beside the store (`dir`: the node's own directory), rebuilds the marked
    /// set and reinstalls the certificates the log holds. Before the follower starts.
    pub fn open(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, st: *store.Store, pool: *Pool, committees: Committees, o: Options) !*Converger {
        var floor: u64 = 0;
        var top: ?u64 = null;
        {
            var snap = st.snapshot();
            defer snap.release();
            top = snap.highestCommitted();
            floor = heldFloor(&snap);
        }
        var opened = try certs_mod.Certs.open(gpa, io, dir, .{ .floor = floor, .top = top, .ahead = o.ahead, .now_ms = certs_mod.wallMs(), .log = o.log, .crash_at = o.crash_at });
        defer opened.found.deinit(gpa);
        errdefer opened.certs.deinit();
        const found = &opened.found;
        if (found.fixes.len > 0) {
            const entries = try gpa.alloc(store.txfix.Entry, found.fixes.len);
            defer gpa.free(entries);
            for (entries, found.fixes) |*e, fx| e.* = .{ .seq = fx.seq, .digest = store.certFixKey(fx.seq), .tx = fx.cert };
            _ = try st.cert_fix.load(entries);
        }
        if (o.log) {
            if (found.all_from) |from| log.warn("edge certificates: {s}: every checkpoint this edge serves ({d}..{?d}) is marked and will be checked against the core", .{ found.all_why, from, top });
            if (opened.certs.pending() > 0 or found.fixes.len > 0) log.info("edge certificates: {d} checkpoints hold a certificate that is not a core's (to be replaced), {d} served with the core's certificate from the log ({d} bytes{s})", .{ opened.certs.pending(), found.fixes.len, found.size, if (found.rewritten) ", rewritten" else "" });
        }
        const cv = try gpa.create(Converger);
        cv.* = .{
            .gpa = gpa,
            .io = io,
            .certs = opened.certs,
            .st = st,
            .pool = pool,
            .committees = committees,
            .max_lag = o.max_lag,
            .pace = o.pace,
            .call_timeout_ms = o.call_timeout_ms,
            .com_arena = .init(gpa),
            .arena = .init(gpa),
            .quiet = !o.log,
        };
        return cv;
    }

    /// The lowest checkpoint whose certified summary the edge can hand out: the lowest it holds.
    /// (Not the lowest it serves over gRPC: a store restored from a snapshot holds the
    /// snapshot's end-of-epoch checkpoint below that, with the certificate the restore's source
    /// gave, and zui/1 proofs of objects it wrote and the epoch proof read it.)
    fn heldFloor(snap: *const store.Snapshot) u64 {
        return snap.lowestCheckpoint() orelse 0;
    }

    pub fn start(cv: *Converger) !void {
        cv.thread = try std.Thread.spawn(.{ .stack_size = 4 << 20 }, loop, .{cv});
    }

    /// Tells the thread to end, without waiting (a call to the core in progress ends when the
    /// pool is stopped, as every pool call does).
    pub fn requestStop(cv: *Converger) void {
        cv.stopping.store(true, .release);
    }

    pub fn stop(cv: *Converger) void {
        cv.requestStop();
        if (cv.thread) |t| t.join();
        cv.thread = null;
    }

    pub fn deinit(cv: *Converger) void {
        cv.stop();
        cv.certs.deinit();
        cv.com_arena.deinit();
        cv.arena.deinit();
        cv.gpa.destroy(cv);
    }

    /// Follower `on_batch`, before the commit of `seq`: an error stops the commit.
    pub fn onBatch(cv: *Converger, seq: u64) !void {
        const from_core = if (cv.fetcher) |f| f.fromCore(seq) else false;
        try cv.certs.onApply(seq, from_core, certs_mod.wallMs());
    }

    fn nowNs(cv: *const Converger) u64 {
        return edge.fallback.nowNs(cv.io);
    }

    fn loop(cv: *Converger) void {
        var wait_ms: u64 = cv.pace.idle_ms;
        var turns: u32 = 0;
        while (!cv.stopping.load(.acquire)) : (turns +%= 1) {
            // While the gate is shut (an edge on its fallback for days) nothing asks `next`,
            // which is what drops the marks retention has passed: done here now and then.
            if (turns % 256 == 255 and cv.certs.pending() != 0) cv.dropPruned();
            // sleeps in slices: a stop is seen within one
            var left = wait_ms;
            while (left > 0 and !cv.stopping.load(.acquire)) {
                const slice = @min(left, source_mod.stop_slice_ms);
                cv.io.sleep(.fromMilliseconds(@intCast(slice)), .awake) catch return;
                left -= slice;
            }
            if (cv.stopping.load(.acquire)) return;
            wait_ms = cv.pace.after(cv.step());
            cv.certs.stats.wait_ms.store(wait_ms, .monotonic);
        }
    }

    /// Drops the marks of checkpoints the edge no longer holds.
    pub fn dropPruned(cv: *Converger) void {
        const floor = blk: {
            var snap = cv.st.snapshot();
            defer snap.release();
            break :blk heldFloor(&snap);
        };
        var none: [0]u64 = .{};
        _ = cv.certs.next(&none, floor, cv.st.committed() orelse return, cv.nowNs());
    }

    pub fn gate(cv: *Converger) certs_mod.Gate {
        const g = certs_mod.gate(cv.max_lag, .{
            .pending = cv.certs.pending(),
            .on_core = if (cv.sw) |s| s.mode() == .core else true,
            .known_tip = if (cv.fetcher) |f| f.tipKnown() else null,
            .committed = cv.st.committed(),
        });
        cv.last_gate.store(@intFromEnum(g), .monotonic);
        return g;
    }

    /// One call to the core, if the gate lets it: up to `pace.batch` marked checkpoints asked,
    /// verified, logged, installed and cleared. The loop's body; tests call it directly.
    pub fn step(cv: *Converger) certs_mod.Pace.Outcome {
        return cv.stepInner() catch |e| {
            if (e == error.CrashInjected) return .failed;
            if (!cv.stopping.load(.acquire) and !cv.quiet) log.warn("edge certificates: {s}", .{@errorName(e)});
            return .failed;
        };
    }

    /// `step`, with a crash injected by the tests coming back as `error.CrashInjected`.
    pub fn stepInner(cv: *Converger) !certs_mod.Pace.Outcome {
        if (cv.gate() != .run) return .idle;
        const max_batch = 64;
        var seqs: [max_batch]u64 = undefined;
        var out: [max_batch]Pool.Summary = undefined;
        const tip = cv.st.committed() orelse return .idle;
        const floor = blk: {
            var snap = cv.st.snapshot();
            defer snap.release();
            break :blk heldFloor(&snap);
        };
        const now = cv.nowNs();
        const n = cv.certs.next(seqs[0..@min(max_batch, @max(1, cv.pace.batch))], floor, tip, now);
        if (n == 0) return .idle;
        _ = cv.arena.reset(.{ .retain_with_limit = 1 << 20 });
        const a = cv.arena.allocator();
        const asked = cv.pool.fetchSummaries(a, seqs[0..n], out[0..n], now + cv.call_timeout_ms * std.time.ns_per_ms) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                // the node is stopping (the pool was stopped under the call): not the core's failure
                if (cv.stopping.load(.acquire) or e == error.Closed and cv.pool.stopping.load(.acquire)) return .idle;
                cv.certs.countError(.transport);
                return .failed;
            },
        };
        // every connection is with the feed: it comes first, and nothing was asked
        if (!asked) return .idle;
        _ = cv.certs.stats.batches.fetchAdd(1, .monotonic);
        _ = cv.certs.stats.requests.fetchAdd(n, .monotonic);

        var failed = false;
        var resolved: std.ArrayList(certs_mod.Resolved) = .empty;
        var fixes: std.ArrayList(store.txfix.Entry) = .empty;
        {
            var snap = cv.st.snapshot();
            defer snap.release();
            for (seqs[0..n], out[0..n]) |seq, res| switch (res) {
                .cert => |bytes| switch (try cv.judge(a, &snap, seq, bytes)) {
                    .replace => {
                        try resolved.append(a, .{ .seq = seq, .cert = bytes });
                        try fixes.append(a, .{ .seq = seq, .digest = store.certFixKey(seq), .tx = bytes });
                    },
                    .equal => try resolved.append(a, .{ .seq = seq, .cert = null }),
                    .bad => |k| {
                        cv.refuse(seq, k, now);
                        failed = true;
                    },
                    .gone => {},
                },
                .missing => {
                    // not there yet (a core behind this edge's other source): asked again later
                    cv.certs.countError(.not_held);
                    _ = cv.certs.deferred.put(seq, now, 5_000, 300_000);
                },
                .pruned => |lo| {
                    // below the core's retention: it will never hold it. The mark stays (reads
                    // of that certificate go to the core, which answers for itself) until the
                    // edge's own floor passes it.
                    cv.certs.countError(.not_held);
                    if (lo > cv.certs.core_floor.load(.monotonic)) cv.certs.core_floor.store(lo, .monotonic);
                    if (lo <= seq) _ = cv.certs.deferred.put(seq, now, 5_000, 300_000);
                },
                .refused, .failed => {
                    cv.certs.countError(.refused);
                    failed = true;
                },
                .bad => {
                    cv.refuse(seq, .decode, now);
                    failed = true;
                },
            };
        }
        if (resolved.items.len > 0) {
            // the record, then the store, then the mark: each step leaves a state the next
            // start reads as one of them (edge/certs.zig)
            try cv.certs.resolve(resolved.items);
            if (fixes.items.len > 0) _ = try cv.st.cert_fix.putMany(fixes.items);
            try cv.certs.cleared(resolved.items, certs_mod.wallMs());
        }
        return if (failed) .failed else .clean;
    }

    /// A refetch the edge does not take: counted, said (a few times), and the checkpoint is
    /// left alone for a while. Its mark stays and so does the certificate the edge holds.
    fn refuse(cv: *Converger, seq: u64, kind: certs_mod.ErrKind, now: u64) void {
        cv.certs.countError(kind);
        _ = cv.certs.deferred.put(seq, now, 10_000, 600_000);
        if (cv.quiet or cv.shown >= 8) return;
        cv.shown += 1;
        switch (kind) {
            .summary_mismatch => log.err("edge certificates: the core's summary of checkpoint {d} is not the one this edge verified and holds: refused, nothing overwritten", .{seq}),
            .bad_certificate => log.err("edge certificates: the core's certificate of checkpoint {d} does not verify against the epoch's committee: refused", .{seq}),
            else => log.warn("edge certificates: the core's answer for checkpoint {d} does not decode: refused", .{seq}),
        }
    }

    /// Is `got` (the core's answer) the certified summary of the checkpoint the edge holds as
    /// `seq`, with a certificate that verifies? The same summary bytes (so the same digest: the
    /// edge verified its own when it applied the checkpoint), a well formed
    /// AuthorityQuorumSignInfo with nothing after it, and a quorum of the epoch's committee
    /// over it (`sync.verify.checkCert`, the follower's own check).
    pub fn judge(cv: *Converger, a: std.mem.Allocator, snap: *const store.Snapshot, seq: u64, got: []const u8) !Verdict {
        const rec = snap.checkpoint(seq) orelse return .gone;
        const have_n = summaryLen(rec.summary_cert) orelse return .{ .bad = .decode };
        const got_n = summaryLen(got) orelse return .{ .bad = .decode };
        var r = bcs.Reader.init(got[got_n..]);
        bcs.skip(types.AuthorityQuorumSignInfo, &r) catch return .{ .bad = .decode };
        if (r.remaining() != 0) return .{ .bad = .decode };
        if (!std.mem.eql(u8, got[0..got_n], rec.summary_cert[0..have_n])) return .{ .bad = .summary_mismatch };
        if (std.mem.eql(u8, got, rec.summary_cert)) return .equal;
        const com = cv.committee(rec.epoch) orelse return .{ .bad = .bad_certificate };
        return switch (try sync.verify.checkCert(a, com, rec.epoch, got[0..got_n], got[got_n..])) {
            .ok => .replace,
            else => .{ .bad = .bad_certificate },
        };
    }

    fn summaryLen(cert: []const u8) ?usize {
        var r = bcs.Reader.init(cert);
        bcs.skip(types.CheckpointSummary, &r) catch return null;
        return r.pos();
    }

    fn committee(cv: *Converger, epoch: u64) ?*const sync.Committee {
        if (cv.com) |*c| if (c.epoch == epoch) return c;
        cv.com = null;
        _ = cv.com_arena.reset(.retain_capacity);
        cv.com = cv.committees.get(cv.committees.ctx, cv.com_arena.allocator(), epoch) orelse return null;
        return &cv.com.?;
    }

    // ------------------------------------------------------------ zui/1 (the edge's own listener)

    /// What the zui/1 dispatcher asks about a checkpoint before it hands out its certified
    /// summary, and how it passes a request to a core instead.
    pub fn nativeHook(cv: *Converger) native.dispatch.Foreign {
        return .{ .ctx = cv, .pending = &cv.certs.marks.n, .marked = nativeMarked, .reachable = nativeReachable, .forward = nativeForward, .held = nativeHeld };
    }

    /// A core can be asked: the edge takes its checkpoints from one (the fallback's switch says;
    /// without a fallback the cores are all there is, and a forward that finds none says so).
    fn nativeReachable(ctx: *anyopaque) bool {
        const cv: *Converger = @ptrCast(@alignCast(ctx));
        return if (cv.sw) |sw| sw.mode() == .core else true;
    }

    fn nativeHeld(ctx: *anyopaque, proof: bool) void {
        const cv: *Converger = @ptrCast(@alignCast(ctx));
        cv.certs.noteHeld(if (proof) .proof else .zui1);
    }

    fn nativeMarked(ctx: *anyopaque, seq: u64) bool {
        const cv: *Converger = @ptrCast(@alignCast(ctx));
        return cv.certs.isMarked(seq);
    }

    /// The same request to a core, its whole response into `out`. False: no core answered.
    fn nativeForward(ctx: *anyopaque, a: std.mem.Allocator, req: native.proto.Request, out: *std.ArrayList(u8)) bool {
        const cv: *Converger = @ptrCast(@alignCast(ctx));
        // (On its fallback the edge has just learned that no core answers: the dispatcher asks
        // `reachable` first and does not come here.)
        if (!nativeReachable(ctx)) return false;
        // Without ZSTD: the core's dictionaries are not this node's; the dispatcher compresses
        // for its own client as that client asked.
        const flags = req.flags & ~native.proto.flag_zstd_ok;
        const resp = cv.pool.forward(a, req.method, flags, req.body, cv.nowNs() + cv.call_timeout_ms * std.time.ns_per_ms) catch return false;
        out.clearRetainingCapacity();
        out.appendSlice(a, resp) catch return false;
        return true;
    }

    /// The `zui_edge_cert_*` lines.
    pub fn renderMetrics(cv: *Converger, w: *Io.Writer) !void {
        try cv.certs.renderMetrics(w, certs_mod.wallMs());
        try w.print("# TYPE zui_edge_cert_gate gauge\nzui_edge_cert_gate {d}\n", .{cv.last_gate.load(.monotonic)});
        // The certificates served in place of stored ones: how many, and the memory they take
        // (the log holds the same certificates: `zui_edge_cert_log_bytes`).
        try w.print("# TYPE zui_edge_cert_fixes gauge\nzui_edge_cert_fixes {d}\n", .{cv.st.cert_fix.count()});
        try w.print("# TYPE zui_edge_cert_fix_bytes gauge\nzui_edge_cert_fix_bytes {d}\n", .{cv.st.cert_fix.heldBytes()});
    }
};
