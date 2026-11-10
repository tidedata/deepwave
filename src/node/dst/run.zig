//! Deterministic simulation of the whole follow pipeline of the node (VOPR style): one run is one
//! seed, on a virtual clock, against simulated sources and a simulated disk.
//!
//! What is simulated: time (an event queue; nothing sleeps), the network (N checkpoint sources
//! with latency spikes, drops, partitions, stale tips, corrupted and forged blobs, a source on a
//! fork), the disk (store/sim.zig: torn and lost writes, EIO/ENOSPC, failed fsync) and the
//! process (killed between events, killed at a random disk operation, exits on a store error),
//! plus a skewed node clock. What is real: the store engine (open, recovery, begin, commit), the
//! verification (sync.verify.check/checkCert, Committee, committee hand-over at epoch ends), the
//! follower's admission rules (sync.follower.Admission, the same code its ordered stage runs),
//! the peer choice and scoring (net.peer_score: PeerScore, order, Pinned), and the restart
//! anchor (walk of the stored end-of-epoch checkpoints, as node/trust.zig does).
//!
//! The node here is single threaded and event driven; the production follower is a thread
//! pipeline, so what is tested is the decision logic and the persistence, not the scheduling.
//!
//! Invariants, checked against the generated chain (the oracle, chain.zig):
//!   safety       every checkpoint the store holds has the truth's summary digest and contents and
//!                a certificate that verifies under the truth's committee (never accept a bad one);
//!   durability   after any crash and recovery the store holds every acknowledged commit, at most
//!                one more (the one in flight), as a prefix with no gaps;
//!   convergence  once faults stop (`heal_ms`), the node reaches the tip within a bounded time,
//!                whatever happened before, and a final crash and recovery loses nothing;
//!   determinism  `Result.trace` hashes every decision; two runs of a seed agree (tested).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const sync = @import("sync");
const net = @import("net");
const store_mod = @import("store");
const chain_mod = @import("chain.zig");
const trust = @import("../trust.zig");

const Chain = chain_mod.Chain;
const Store = store_mod.Store;
const SimIo = store_mod.sim.SimIo;
const follower = sync.follower;
const verify = sync.verify;
const Verdict = verify.Verdict;
const Committee = sync.Committee;
const peer_score = net.peer_score;

pub const Sabotage = enum {
    none,
    /// The node accepts any certificate (the harness must flag forged checkpoints).
    skip_cert,
    /// The node skips the epoch and chain-link rules.
    skip_chain,
    /// The node acknowledges a checkpoint before committing it and loses it in a crash.
    lose_ack,
};

/// One fault kind at full strength with the others off (`deepwave-dst --family <focus>`). `none`:
/// the mixed draw every family used before (seeds replay unchanged).
pub const Focus = enum {
    none,
    /// Every source but the first serves a fork certified by the real committee past `fork_at`.
    forks,
    /// Every source has a partition window; half the seeds black out all sources at once.
    partitions,
    /// Kills, crashes at disk ops, I/O-error exits and OOM exits, several per run; honest sources.
    crashes,
    /// The node's clock runs at 0.5x to 2x; sources drop and spike (timeouts and backoff matter).
    skew,
    /// Every source but the first answers each request with a forgery made with real keys.
    forged,
};

pub const Options = struct {
    seed: u64,
    focus: Focus = .none,
    /// Shared chain (not freed); null: generated from the seed.
    chain: ?*Chain = null,
    checkpoints: u32 = 36,
    sources: u8 = 4,
    window: u32 = 5,
    /// Sources lie, drop and delay (always at least one flaky but honest source).
    adversarial: bool = true,
    io_faults: bool = true,
    crashes: bool = true,
    /// The node's allocations (slot arenas, committees) fail at random: every such failure must
    /// end in a restart, never in a verdict against a source and never in a crash.
    oom: bool = true,
    /// Memoise certificate verdicts (the pairing dominates a run); off: every check is real.
    memo: bool = true,
    sabotage: Sabotage = .none,
    /// Virtual time when every fault stops.
    heal_ms: u64 = 12_000,
    /// Virtual time the run may take in all; passing it without reaching the tip is a failure.
    max_ms: u64 = 240_000,
    debug: bool = false,
};

pub const Result = struct {
    ok: bool = true,
    msg_buf: [320]u8 = @splat(0),
    msg_len: usize = 0,
    /// Checkpoints committed at the end (the chain length when the run converged).
    committed: u64 = 0,
    commits: u64 = 0,
    kills: u32 = 0,
    op_crashes: u32 = 0,
    io_exits: u32 = 0,
    oom_exits: u32 = 0,
    recoveries: u32 = 0,
    requests: u64 = 0,
    drops: u64 = 0,
    timeouts: u64 = 0,
    missing: u64 = 0,
    forged_served: u64 = 0,
    forged_accepted: u64 = 0,
    rejected: [16]u64 = @splat(0),
    off_chain_marked: u64 = 0,
    in_flight_kept: u32 = 0,
    in_flight_lost: u32 = 0,
    virtual_ms: u64 = 0,
    converged_ms: u64 = 0,
    trace: u64 = 0,
    sim_ops: u64 = 0,

    pub fn msg(r: *const Result) []const u8 {
        return r.msg_buf[0..r.msg_len];
    }

    fn failf(r: *Result, comptime fmt: []const u8, args: anytype) void {
        if (!r.ok) return;
        r.ok = false;
        const out: []const u8 = std.fmt.bufPrint(&r.msg_buf, fmt, args) catch r.msg_buf[0..];
        r.msg_len = if (out.ptr == &r.msg_buf and out.len == r.msg_buf.len) (std.mem.indexOfScalar(u8, out, 0) orelse out.len) else out.len;
    }
};

// ------------------------------------------------------------------ the world

const ms = std.time.ns_per_ms;
const cp_interval_ns = 250 * ms;
const request_timeout_ns = 2_000 * ms;
const poll_ns = 100 * ms;

/// Allocator whose allocations fail at random (deterministic from its PRNG) while armed.
const Flaky = struct {
    parent: std.mem.Allocator,
    prng: std.Random.DefaultPrng,
    ppm: u32 = 0,
    armed: bool = false,
    failures: u64 = 0,

    fn allocator(f: *Flaky) std.mem.Allocator {
        return .{ .ptr = f, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const f: *Flaky = @ptrCast(@alignCast(ctx));
        if (f.armed and f.ppm != 0 and f.prng.random().uintLessThan(u32, 1_000_000) < f.ppm) {
            f.failures += 1;
            return null;
        }
        return f.parent.rawAlloc(len, alignment, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, alignment: std.mem.Alignment, n: usize, ra: usize) bool {
        const f: *Flaky = @ptrCast(@alignCast(ctx));
        return f.parent.rawResize(m, alignment, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, alignment: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const f: *Flaky = @ptrCast(@alignCast(ctx));
        return f.parent.rawRemap(m, alignment, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const f: *Flaky = @ptrCast(@alignCast(ctx));
        f.parent.rawFree(m, alignment, ra);
    }
};

const Kind = enum { response, timeout, wake, kill, restart, heal };
const Ev = struct { at: u64, ord: u64, kind: Kind, a: u64 = 0 };

const Heap = struct {
    items: std.ArrayList(Ev) = .empty,

    fn less(a: Ev, b: Ev) bool {
        return a.at < b.at or (a.at == b.at and a.ord < b.ord);
    }
    fn push(h: *Heap, gpa: std.mem.Allocator, e: Ev) !void {
        try h.items.append(gpa, e);
        var i = h.items.items.len - 1;
        while (i > 0) {
            const p = (i - 1) / 2;
            if (!less(h.items.items[i], h.items.items[p])) break;
            std.mem.swap(Ev, &h.items.items[i], &h.items.items[p]);
            i = p;
        }
    }
    fn pop(h: *Heap) ?Ev {
        if (h.items.items.len == 0) return null;
        const top = h.items.items[0];
        const last = h.items.pop().?;
        if (h.items.items.len > 0) {
            h.items.items[0] = last;
            var i: usize = 0;
            while (true) {
                const l = 2 * i + 1;
                const r = l + 1;
                var m = i;
                if (l < h.items.items.len and less(h.items.items[l], h.items.items[m])) m = l;
                if (r < h.items.items.len and less(h.items.items[r], h.items.items[m])) m = r;
                if (m == i) break;
                std.mem.swap(Ev, &h.items.items[i], &h.items.items[m]);
                i = m;
            }
        }
        return top;
    }
};

const Peer = struct {
    /// Never lies (still drops and delays).
    core: bool,
    lag_ns: u64,
    base_ns: u64,
    jitter_ns: u64,
    spike_ppm: u32,
    spike_ns: u64,
    drop_ppm: u32,
    corrupt_ppm: u32,
    /// Serves the fork whenever it can (a peer on another chain).
    forky: bool,
    /// Partition window (no answers at all).
    part_from: u64 = 0,
    part_to: u64 = 0,
};

const Resp = struct {
    inc: u32,
    seq: u64,
    peer: u8,
    sent: u64,
    /// null: the source does not have the checkpoint yet.
    blob: ?[]const u8,
    forged: bool,
};

const SlotState = enum { want, inflight, ready };

const Slot = struct {
    state: SlotState = .want,
    seq: u64 = 0,
    req: u64 = 0,
    peer: u8 = 0,
    tries: u32 = 0,
    not_before: u64 = 0,
    blob: []const u8 = &.{},
    forged: bool = false,
    arena: std.heap.ArenaAllocator,
    checked: ?verify.Checked = null,
    cert: ?Verdict = null,
};

const Sim = struct {
    gpa: std.mem.Allocator,
    o: Options,
    res: *Result,
    chain: *Chain,
    prng: std.Random.DefaultPrng,
    /// Draws of the node itself (peer choice), apart from the world's.
    node_prng: std.Random.DefaultPrng,
    /// Owns the blobs the sources made up and the run's other long-lived memory.
    wa: std.mem.Allocator,
    now: u64 = 0,
    ord: u64 = 0,
    heap: Heap = .{},
    healed: bool = false,
    peers: []Peer,
    resps: std.ArrayList(Resp) = .empty,
    disk: *SimIo,
    cfg: store_mod.Config,
    // oracle
    acked: ?u64 = null,
    in_flight: ?u64 = null,
    oracle_committees: []?Committee,
    oracle_arena: std.heap.ArenaAllocator,
    // node
    inc: u32 = 0,
    alive: bool = false,
    store: ?*Store = null,
    narena: std.heap.ArenaAllocator,
    flaky: *Flaky,
    committees: std.AutoHashMapUnmanaged(u64, Committee) = .empty,
    adm: follower.Admission = .{},
    next_apply: u64 = 0,
    slots: []Slot,
    scores: [chain_mod.max_validators * 8]?peer_score.PeerScore = @splat(null),
    off_chain: [chain_mod.max_validators * 8]bool = @splat(false),
    pinned: peer_score.Pinned = .{},
    idx: types.CheckpointIndex,
    wake_at: u64 = std.math.maxInt(u64),
    clock_skew_ppm: i64,
    disk_ns_seen: u64 = 0,
    fork_pinned: bool = false,

    fn trace(s: *Sim, v: u64) void {
        s.res.trace = std.hash.Wyhash.hash(s.res.trace, std.mem.asBytes(&v));
    }

    fn rnd(s: *Sim) std.Random {
        return s.prng.random();
    }

    fn push(s: *Sim, at: u64, kind: Kind, a: u64) !void {
        s.ord += 1;
        try s.heap.push(s.gpa, .{ .at = at, .ord = s.ord, .kind = kind, .a = a });
    }

    /// The node's clock: monotonic, running a little fast or slow.
    fn nodeNow(s: *const Sim) u64 {
        const d: i128 = @as(i128, s.now) * s.clock_skew_ppm;
        return @intCast(@as(i128, s.now) + @divTrunc(d, 1_000_000));
    }

    fn advanceDisk(s: *Sim) void {
        const t = s.disk.stats.clock_ns;
        s.now += t - s.disk_ns_seen;
        s.disk_ns_seen = t;
    }

    // ------------------------------------------------------------ sources

    fn avail(s: *const Sim, p: *const Peer) u64 {
        const backlog = s.chain.len() / 3;
        const t = s.now -| p.lag_ns;
        return @min(s.chain.len(), backlog + t / cp_interval_ns + 1);
    }

    fn partitioned(s: *const Sim, p: *const Peer) bool {
        return !s.healed and s.now >= p.part_from and s.now < p.part_to;
    }

    fn ppm(s: *Sim, v: u32) bool {
        return v != 0 and s.rnd().uintLessThan(u32, 1_000_000) < v;
    }

    /// What peer `pi` answers for `seq` now: its blob (maybe corrupt or forged), or null when it
    /// does not have it. `dropped` set: no answer at all.
    fn serve(s: *Sim, pi: usize, seq: u64, dropped: *bool, forged: *bool) !?[]const u8 {
        const p = &s.peers[pi];
        dropped.* = false;
        forged.* = false;
        if (s.partitioned(p) or (!s.healed and s.ppm(p.drop_ppm))) {
            dropped.* = true;
            return null;
        }
        if (seq >= s.avail(p)) return null;
        const honest = s.chain.cps[seq].blob;
        if (s.healed and !p.forky) return honest;
        const a = s.wa;
        if (p.forky and seq > s.chain.fork_at and s.chain.fork.len > 0) {
            forged.* = true;
            return s.chain.fork[seq - s.chain.fork_at].blob;
        }
        if (p.core or s.healed or !s.ppm(p.corrupt_ppm)) return honest;
        const r = s.rnd();
        forged.* = true;
        switch (r.uintLessThan(u8, if (s.o.focus == .forged) 6 else 12)) {
            0...5 => {
                // Forgeries built with real keys and real blobs.
                const kinds = std.enums.values(Chain.Forgery);
                const kind = kinds[r.uintLessThan(usize, kinds.len)];
                if (try s.chain.forge(a, r, kind, seq)) |b| return b;
                forged.* = false;
                return honest;
            },
            6 => { // one flipped byte
                const b = try a.dupe(u8, honest);
                b[r.uintLessThan(usize, b.len)] ^= @as(u8, 1) << @intCast(r.uintLessThan(u8, 8));
                return b;
            },
            7 => return try a.dupe(u8, honest[0..r.uintLessThan(usize, honest.len)]), // truncated
            8 => return &.{}, // empty
            9 => { // zeroed region
                const b = try a.dupe(u8, honest);
                const at = r.uintLessThan(usize, b.len);
                @memset(b[at..@min(b.len, at + 1 + r.uintLessThan(usize, 24))], 0);
                return b;
            },
            10 => { // trailing garbage
                const b = try a.alloc(u8, honest.len + 1 + r.uintLessThan(usize, 8));
                @memcpy(b[0..honest.len], honest);
                r.bytes(b[honest.len..]);
                return b;
            },
            else => { // a different sequence number's genuine blob (never the same)
                const o = (seq + 1 + r.uintLessThan(u64, s.chain.len() - 1)) % s.chain.len();
                return s.chain.cps[o].blob;
            },
        }
    }

    fn latency(s: *Sim, p: *const Peer) u64 {
        var l = p.base_ns + s.rnd().uintAtMost(u64, p.jitter_ns);
        if (s.ppm(p.spike_ppm)) l += p.spike_ns;
        return l;
    }

    // ------------------------------------------------------------ node: boot and anchor

    fn openStore(s: *Sim) !void {
        var tries: u32 = 0;
        while (true) : (tries += 1) {
            if (s.o.crashes and !s.healed and tries > 0 and tries < 4 and s.rnd().uintLessThan(u8, 3) == 0) s.disk.scheduleCrash(s.rnd().uintLessThan(u64, 14));
            s.disk.io_armed = s.o.io_faults and !s.healed;
            const st = Store.open(s.gpa, .{ .sim = s.disk }, &s.cfg) catch |e| switch (e) {
                error.Crashed => {
                    s.disk.io_armed = false;
                    s.res.op_crashes += 1;
                    s.disk.crash();
                    continue;
                },
                error.Io, error.NoSpace, error.ShortRead => if (tries < 20 or (s.healed and tries < 400)) {
                    s.disk.io_armed = false;
                    s.res.io_exits += 1;
                    s.disk.crash();
                    continue;
                } else if (!s.healed) {
                    // The supervisor keeps restarting the node while the disk misbehaves; time
                    // passes until the faults stop.
                    s.disk.io_armed = false;
                    s.res.io_exits += 1;
                    s.disk.crash();
                    return error.OpenTransient;
                } else {
                    s.res.failf("store open kept failing with {t} (400 tries)", .{e});
                    return error.RecoveryFailed;
                },
                else => {
                    s.res.failf("recovery: store refused to open after crash and I/O errors: {t}", .{e});
                    return error.RecoveryFailed;
                },
            };
            s.disk.io_armed = false;
            s.disk.scheduleCrash(null);
            s.store = st;
            s.advanceDisk();
            return;
        }
    }

    fn digestOfSummary(summary: []const u8) [32]u8 {
        return hash.blake2b256(&.{ "CheckpointSummary::", summary });
    }

    /// Oracle: the store holds a prefix of the truth, exactly (see the header).
    fn checkStoreAgainstTruth(s: *Sim, what: []const u8) void {
        const st = s.store.?;
        const hi_opt = st.committed();
        if (s.acked) |a| {
            if (hi_opt == null or hi_opt.? < a) {
                s.res.failf("{s}: store committed {?d}, acknowledged {d} (lost a committed checkpoint)", .{ what, hi_opt, a });
                return;
            }
        }
        if (hi_opt) |hi| {
            const bound = if (s.acked) |a| a + 1 else 0;
            if (hi > bound) {
                s.res.failf("{s}: store committed {d}, at most {d} was ever started", .{ what, hi, bound });
                return;
            }
            if (s.acked == null or hi != s.acked.?) s.res.in_flight_kept += 1;
            if (hi >= s.chain.len()) {
                s.res.failf("{s}: committed {d} beyond the chain", .{ what, hi });
                return;
            }
            var snap = st.snapshot();
            defer snap.release();
            var q: u64 = 0;
            while (q <= hi) : (q += 1) {
                const rec = snap.checkpointChecked(q) catch |e| {
                    s.res.failf("{s}: checkpoint {d} unreadable: {t}", .{ what, q, e });
                    return;
                } orelse {
                    s.res.failf("{s}: checkpoint {d} missing below committed {d}", .{ what, q, hi });
                    return;
                };
                s.oracleRecord(what, q, rec.summary_cert, rec.contents, rec.epoch);
                if (!s.res.ok) return;
            }
            // The node moves on from what is durable: the in-flight one counts now.
            if (s.acked == null or hi > s.acked.?) s.acked = hi;
        } else if (s.acked != null) {
            s.res.failf("{s}: store empty after {d} acknowledged", .{ what, s.acked.? });
        }
    }

    /// One stored checkpoint against the truth: same summary, same contents, certificate valid
    /// under the truth's committee of that epoch.
    fn oracleRecord(s: *Sim, what: []const u8, seq: u64, summary_cert: []const u8, contents: []const u8, epoch: u64) void {
        const truth = s.chain.cps[seq];
        const cv = trust.splitCert(summary_cert) catch {
            s.res.failf("{s}: checkpoint {d} stored record does not parse", .{ what, seq });
            return;
        };
        if (!std.mem.eql(u8, &digestOfSummary(cv.summary), &truth.digest)) {
            s.res.failf("{s}: checkpoint {d} stored with a summary that is not the chain's (accepted a bad checkpoint)", .{ what, seq });
            return;
        }
        if (!std.mem.eql(u8, contents, truth.contents) or epoch != truth.epoch) {
            s.res.failf("{s}: checkpoint {d} stored with other contents or epoch", .{ what, seq });
            return;
        }
        const oc = &(s.oracle_committees[truth.epoch].?);
        var arena_s: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena_s.deinit();
        const v = s.chain.checkCert(s.o.memo, arena_s.allocator(), oc, truth.epoch, cv.summary, cv.sig) catch .decode;
        if (!v.isOk()) {
            s.res.forged_accepted += 1;
            s.res.failf("{s}: checkpoint {d} stored with a certificate that does not verify ({s}) (accepted a forged checkpoint)", .{ what, seq, v.name() });
        }
    }

    /// Builds the node's trust state from the store, like node/trust.zig: the genesis committee,
    /// then the end-of-epoch checkpoints in order (their certificates verified), so the committee
    /// of the next checkpoint's epoch and the chain link are known.
    fn anchorFromStore(s: *Sim) !void {
        const ca = s.narena.allocator();
        s.committees = .empty;
        var comm = try s.chain.genesisCommittee(ca);
        try s.committees.put(ca, 0, comm);
        const st = s.store.?;
        var anchor: follower.Anchor = .{ .committee = comm, .first_seq = 0 };
        if (st.committed()) |hi| {
            var snap = st.snapshot();
            defer snap.release();
            var prev: ?[32]u8 = null;
            var q: u64 = 0;
            var scratch: std.heap.ArenaAllocator = .init(s.gpa);
            defer scratch.deinit();
            var last_eoe = false;
            while (q <= hi) : (q += 1) {
                _ = scratch.reset(.retain_capacity);
                const sa = scratch.allocator();
                const rec = (snap.checkpointChecked(q) catch |e| {
                    s.res.failf("restart: checkpoint {d} unreadable: {t}", .{ q, e });
                    return error.RecoveryFailed;
                }) orelse {
                    s.res.failf("restart: checkpoint {d} missing below committed {d}", .{ q, hi });
                    return error.RecoveryFailed;
                };
                const cv = trust.splitCert(rec.summary_cert) catch {
                    s.res.failf("restart: stored checkpoint {d} has no splittable certificate", .{q});
                    return error.RecoveryFailed;
                };
                const sum = bcs.decode(types.CheckpointSummary, sa, cv.summary) catch {
                    s.res.failf("restart: stored summary {d} does not decode", .{q});
                    return error.RecoveryFailed;
                };
                const d = digestOfSummary(cv.summary);
                if (sum.sequence_number != q or (prev != null and (sum.previous_digest == null or !std.mem.eql(u8, &sum.previous_digest.?.@"0".@"0", &prev.?)))) {
                    s.res.failf("restart: stored chain broken at {d}", .{q});
                    return error.RecoveryFailed;
                }
                last_eoe = sum.end_of_epoch_data != null;
                if (sum.end_of_epoch_data) |eoe| {
                    const cvd = try s.chain.checkCert(s.o.memo, sa, &comm, comm.epoch, cv.summary, cv.sig);
                    if (!cvd.isOk()) {
                        s.res.failf("restart: stored end-of-epoch checkpoint {d} fails its certificate ({s})", .{ q, cvd.name() });
                        return error.RecoveryFailed;
                    }
                    comm = Committee.fromEndOfEpoch(ca, comm.epoch + 1, eoe) catch {
                        s.res.failf("restart: stored end-of-epoch checkpoint {d} has no usable next committee", .{q});
                        return error.RecoveryFailed;
                    };
                    try s.committees.put(ca, comm.epoch, comm);
                }
                prev = d;
            }
            anchor = .{ .committee = comm, .first_seq = hi + 1, .prev_digest = prev, .prev_was_eoe = last_eoe };
        }
        s.adm = follower.Admission.init(anchor);
        s.next_apply = anchor.first_seq;
    }

    fn resetSlots(s: *Sim) void {
        var q = s.next_apply;
        while (q < s.next_apply + s.slots.len) : (q += 1) {
            const sl = s.slotOf(q);
            _ = sl.arena.reset(.retain_capacity);
            sl.* = .{ .arena = sl.arena, .seq = q };
        }
    }

    fn boot(s: *Sim) !void {
        s.flaky.armed = false; // recovery runs with memory; the pipeline below is what is shaken
        _ = s.narena.reset(.retain_capacity);
        s.inc += 1;
        s.res.recoveries += 1;
        s.scores = @splat(null);
        s.openStore() catch |e| switch (e) {
            error.OpenTransient => {
                s.alive = false;
                try s.push(s.now + 500 * ms, .restart, 0);
                return;
            },
            else => return e,
        };
        s.checkStoreAgainstTruth("recovery");
        if (!s.res.ok) return;
        try s.anchorFromStore();
        s.resetSlots();
        s.alive = true;
        s.flaky.armed = s.o.oom and !s.healed;
        s.wake_at = std.math.maxInt(u64);
        if (s.o.crashes and !s.healed and s.rnd().boolean()) s.disk.scheduleCrash(1 + s.rnd().uintLessThan(u64, 500));
        try s.push(s.now, .wake, 0);
    }

    /// The process dies (killed, or exits on a store error): memory is lost, the disk keeps what
    /// it kept.
    fn die(s: *Sim, why: enum { kill, op_crash, io_exit, oom }) !void {
        switch (why) {
            .kill => s.res.kills += 1,
            .op_crash => s.res.op_crashes += 1,
            .io_exit => s.res.io_exits += 1,
            .oom => s.res.oom_exits += 1,
        }
        s.trace(@as(u64, @intFromEnum(why)) + 100);
        s.alive = false;
        s.flaky.armed = false;
        if (s.store) |st| st.deinit();
        s.store = null;
        s.disk.crash();
        s.disk.scheduleCrash(null);
        const delay = if (s.healed) 50 * ms else (20 + s.rnd().uintLessThan(u64, 2_000)) * ms;
        try s.push(s.now + delay, .restart, 0);
    }

    // ------------------------------------------------------------ node: pump

    fn slotOf(s: *Sim, seq: u64) *Slot {
        return &s.slots[seq % s.slots.len];
    }

    fn peerInfo(s: *Sim, out: []peer_score.PeerInfo) void {
        for (s.peers, 0..) |*p, i| out[i] = .{
            .connected = true,
            .on_same_chain = !s.off_chain[i],
            // The advertised tip is a little stale.
            .height = s.avail(p) -| 1 -| @as(u64, if (s.healed) 0 else 1),
            .rtt_ns = p.base_ns,
        };
    }

    fn blame(s: *Sim, peer: u8) void {
        if (s.scores[peer] == null) s.scores[peer] = .init(60_000 * ms, 0.3);
        s.scores[peer].?.recordFailure(s.nodeNow());
    }

    fn fail(s: *Sim, sl: *Slot, v: Verdict) void {
        s.res.rejected[@intFromEnum(std.meta.activeTag(v))] += 1;
        // A forged blob rejected is the node doing its job; an honest one rejected is a bug (for
        // instance an out of memory read as a verdict against the source).
        if (!sl.forged) s.res.failf("rejected an honest checkpoint {d}: {s}", .{ sl.seq, v.name() });
        s.blame(sl.peer);
        s.trace(@as(u64, @intFromEnum(std.meta.activeTag(v))) << 8 | sl.seq);
        sl.tries += 1;
        sl.state = .want;
        sl.blob = &.{};
        sl.checked = null;
        sl.cert = null;
        // Exponential backoff with a cap.
        sl.not_before = s.now + (@as(u64, 20) << @intCast(@min(sl.tries, 6))) * ms;
    }

    fn pump(s: *Sim) !void {
        while (s.alive) {
            var progress = false;
            while (s.alive and s.next_apply < s.chain.len() and s.slotOf(s.next_apply).state == .ready) {
                if (!s.res.ok) return;
                try s.applyReady(s.slotOf(s.next_apply));
                progress = true;
            }
            if (!s.alive) return;
            if (s.next_apply >= s.chain.len()) return;
            // Issue requests.
            var infos: [chain_mod.max_validators * 8]peer_score.PeerInfo = undefined;
            s.peerInfo(&infos);
            var earliest: u64 = std.math.maxInt(u64);
            var q = s.next_apply;
            const end = @min(s.next_apply + s.slots.len, s.chain.len());
            while (q < end) : (q += 1) {
                const sl = s.slotOf(q);
                if (sl.state != .want) continue;
                if (sl.not_before > s.now) {
                    earliest = @min(earliest, sl.not_before);
                    continue;
                }
                var scores: [chain_mod.max_validators * 8]?*const peer_score.PeerScore = undefined;
                for (s.peers, 0..) |_, i| scores[i] = if (s.scores[i]) |*x| x else null;
                var ord: [64]u8 = undefined;
                const n = peer_score.order(scores[0..s.peers.len], infos[0..s.peers.len], s.nodeNow(), .summary, q, 0.1, s.node_prng.random(), &ord);
                if (n == 0) {
                    sl.not_before = s.now + poll_ns;
                    earliest = @min(earliest, sl.not_before);
                    continue;
                }
                // The first choice; later ones when it was tried and failed (tries rotate).
                const pick = ord[sl.tries % n];
                try s.issue(sl, pick);
                progress = true;
            }
            if (earliest != std.math.maxInt(u64) and earliest < s.wake_at) {
                s.wake_at = earliest;
                try s.push(earliest, .wake, 1);
            }
            if (!progress) return;
        }
    }

    fn issue(s: *Sim, sl: *Slot, pi: u8) !void {
        s.res.requests += 1;
        var dropped = false;
        var forged = false;
        const blob = try s.serve(pi, sl.seq, &dropped, &forged);
        const id = s.resps.items.len;
        try s.resps.append(s.gpa, .{ .inc = s.inc, .seq = sl.seq, .peer = pi, .sent = s.now, .blob = blob, .forged = forged });
        sl.state = .inflight;
        sl.req = id;
        sl.peer = pi;
        s.trace(@as(u64, pi) << 56 | sl.seq << 8 | @intFromBool(dropped));
        if (dropped) {
            s.res.drops += 1;
        } else {
            try s.push(s.now + s.latency(&s.peers[pi]), .response, id);
        }
        try s.push(s.now + request_timeout_ns, .timeout, id);
    }

    fn onResponse(s: *Sim, id: u64) !void {
        s.onResponseInner(id) catch |e| switch (e) {
            error.OutOfMemory => return s.die(.oom),
        };
    }

    fn onResponseInner(s: *Sim, id: u64) !void {
        const r = s.resps.items[id];
        if (!s.alive or r.inc != s.inc) return;
        const sl = s.slotOf(r.seq);
        if (sl.seq != r.seq or sl.state != .inflight or sl.req != id) return; // late duplicate
        const blob = r.blob orelse {
            s.res.missing += 1;
            sl.state = .want;
            sl.not_before = s.now + poll_ns;
            return;
        };
        if (r.forged) s.res.forged_served += 1;
        sl.forged = r.forged;
        // The worker stage: index, check, certificate when the committee is known.
        _ = sl.arena.reset(.retain_capacity);
        sl.blob = blob;
        types.indexCheckpointData(blob, &s.idx) catch {
            return s.fail(sl, .decode);
        };
        const cr = try verify.check(sl.arena.allocator(), blob, &s.idx);
        const c = switch (cr) {
            .ok => |c| c,
            .bad => |v| return s.fail(sl, v),
        };
        sl.checked = c;
        sl.cert = null;
        if (s.committees.getPtr(c.epoch)) |comm| {
            sl.cert = try s.certOf(sl, comm, c.epoch);
            if (!sl.cert.?.isOk()) return s.fail(sl, sl.cert.?);
        }
        // Pinned checkpoints: a summary at a pinned seq with another digest means another chain.
        if (s.pinned.check(c.seq, &c.digest) == .mismatch) {
            if (!s.off_chain[r.peer]) s.res.off_chain_marked += 1;
            s.off_chain[r.peer] = true;
            return s.fail(sl, .chain_break);
        }
        if (s.scores[r.peer] == null) s.scores[r.peer] = .init(60_000 * ms, 0.3);
        s.scores[r.peer].?.recordSuccess(s.nodeNow(), blob.len, @max(1, s.now - r.sent));
        sl.state = .ready;
    }

    fn certOf(s: *Sim, sl: *Slot, comm: *const Committee, epoch: u64) !Verdict {
        if (s.o.sabotage == .skip_cert) return .ok;
        return s.chain.checkCert(s.o.memo, sl.arena.allocator(), comm, epoch, s.idx.summary.slice(sl.blob), s.idx.sig.slice(sl.blob));
    }

    fn onTimeout(s: *Sim, id: u64) !void {
        const r = s.resps.items[id];
        if (!s.alive or r.inc != s.inc) return;
        const sl = s.slotOf(r.seq);
        if (sl.seq != r.seq or sl.state != .inflight or sl.req != id) return;
        s.res.timeouts += 1;
        s.blame(r.peer);
        sl.tries += 1;
        sl.state = .want;
        sl.not_before = s.now;
    }

    /// The ordered stage for the slot of `next_apply`.
    fn applyReady(s: *Sim, sl: *Slot) !void {
        const seq = sl.seq;
        const c = sl.checked.?;
        const blob = sl.blob;
        if (s.o.sabotage != .skip_chain) {
            if (s.adm.check(seq, &c)) |v| return s.fail(sl, v);
        }
        const comm = s.committees.getPtr(c.epoch) orelse return s.fail(sl, .no_committee);
        var cv = sl.cert;
        if (cv == null) {
            types.indexCheckpointData(blob, &s.idx) catch return s.fail(sl, .decode);
            cv = s.certOf(sl, comm, c.epoch) catch |e| switch (e) {
                error.OutOfMemory => return s.die(.oom),
            };
        }
        if (!cv.?.isOk()) return s.fail(sl, cv.?);
        var next: ?Committee = null;
        if (c.end_of_epoch) |eoe| {
            next = Committee.fromEndOfEpoch(s.narena.allocator(), c.epoch + 1, eoe) catch |e| switch (e) {
                error.OutOfMemory => return s.die(.oom),
                else => return s.fail(sl, .no_committee),
            };
        }
        types.indexCheckpointData(blob, &s.idx) catch return s.fail(sl, .decode);
        const st = s.store.?;
        s.disk.io_armed = s.o.io_faults and !s.healed;
        defer s.disk.io_armed = false;
        if (s.o.sabotage == .lose_ack) {
            // Acknowledge before the commit, then lose the checkpoint in a crash.
            s.acked = seq;
            return s.die(.kill);
        }
        s.in_flight = seq;
        const b = st.begin(seq, c.epoch) catch |e| return s.storeFailed(e);
        const sum_cert = blob[s.idx.summary.o .. s.idx.sig.o + s.idx.sig.n];
        b.checkpoint(sum_cert, s.idx.contents.slice(blob)) catch |e| {
            st.abort(b);
            return s.storeFailed(e);
        };
        b.checkpointDigest(&c.digest) catch |e| {
            st.abort(b);
            return s.storeFailed(e);
        };
        st.commit(b) catch |e| return s.storeFailed(e);
        s.advanceDisk();
        // Acknowledged: durable from here on.
        s.in_flight = null;
        s.acked = seq;
        s.res.commits += 1;
        if (!std.mem.eql(u8, &c.digest, &s.chain.cps[seq].digest)) {
            s.res.forged_accepted += 1;
            s.res.failf("committed checkpoint {d} whose digest is not the chain's (accepted a bad checkpoint)", .{seq});
        }
        s.trace(0xc0ffee00 | seq);
        s.adm.advance(&c);
        if (next) |n| s.committees.put(s.narena.allocator(), n.epoch, n) catch {
            // The commit is durable; the committee is rebuilt from the store at restart.
            return s.die(.oom);
        };
        // Slide the window.
        _ = sl.arena.reset(.retain_capacity);
        sl.* = .{ .arena = sl.arena, .seq = seq + s.slots.len };
        s.next_apply = seq + 1;
        if (s.o.debug) std.debug.print("t={d}ms commit {d}\n", .{ s.now / ms, seq });
    }

    fn storeFailed(s: *Sim, e: anyerror) !void {
        s.advanceDisk();
        if (e == error.Crashed) return s.die(.op_crash);
        // Any other store error ends the node process (the follower returns it and the node
        // exits); the supervisor restarts it.
        return s.die(.io_exit);
    }

    // ------------------------------------------------------------ the loop

    fn loop(s: *Sim) !void {
        const max = s.o.max_ms * ms;
        while (s.res.ok) {
            const ev = s.heap.pop() orelse {
                s.res.failf("event queue ran dry at {d} ms with {d}/{d} committed (no wake scheduled: the node stalled)", .{ s.now / ms, s.next_apply, s.chain.len() });
                return;
            };
            if (ev.at > max) {
                s.res.failf("did not converge: {d}/{d} committed at the {d} ms limit (faults stopped at {d} ms)", .{ s.next_apply, s.chain.len(), s.o.max_ms, s.o.heal_ms });
                return;
            }
            s.now = @max(s.now, ev.at);
            switch (ev.kind) {
                .response => try s.onResponse(ev.a),
                .timeout => try s.onTimeout(ev.a),
                .wake => {
                    if (ev.a == 1) s.wake_at = std.math.maxInt(u64);
                },
                .kill => if (s.alive and !s.healed) try s.die(.kill),
                .restart => try s.boot(),
                .heal => s.heal(),
            }
            if (!s.res.ok) return;
            if (s.alive) try s.pump();
            if (s.alive and s.next_apply >= s.chain.len()) {
                s.res.converged_ms = s.now / ms;
                return;
            }
        }
    }

    fn heal(s: *Sim) void {
        s.healed = true;
        s.disk.faults.read_error_ppm = 0;
        s.disk.faults.write_error_ppm = 0;
        s.disk.faults.sync_error_ppm = 0;
        s.disk.io_armed = false;
        s.disk.scheduleCrash(null);
        s.flaky.armed = false;
        s.trace(0x4ea1);
    }
};

/// Runs one seed. Errors are harness failures (out of memory); invariant violations are in
/// `Result.ok`/`msg`.
pub fn run(gpa: std.mem.Allocator, o: Options) !Result {
    var res: Result = .{};
    var own_chain: ?*Chain = null;
    defer if (own_chain) |c| c.deinit();
    const chain: *Chain = o.chain orelse blk: {
        own_chain = try Chain.generate(gpa, .{ .seed = o.seed, .checkpoints = o.checkpoints });
        break :blk own_chain.?;
    };
    if (chain.len() > 4096) return error.ChainTooLong;

    var prng: std.Random.DefaultPrng = .init(o.seed ^ 0x51d0_a11c);
    const r = prng.random();
    const faults: store_mod.sim.Faults = .{
        .persist_256 = r.intRangeAtMost(u16, 0, 256),
        .torn_sectors = r.boolean(),
        .meta_persist_256 = r.intRangeAtMost(u16, 0, 256),
        .read_error_ppm = if (o.io_faults and r.boolean()) r.intRangeAtMost(u32, 500, 20_000) else 0,
        .write_error_ppm = if (o.io_faults and r.boolean()) r.intRangeAtMost(u32, 500, 10_000) else 0,
        .sync_error_ppm = if (o.io_faults and r.boolean()) r.intRangeAtMost(u32, 500, 20_000) else 0,
        .crash_garble_pending = r.boolean(),
    };
    const disk = try SimIo.init(gpa, o.seed ^ 0xd15c_0de, faults, 16 << 20);
    defer disk.deinit();

    const n_peers: usize = @min(o.sources, chain_mod.max_validators * 8);
    var world: std.heap.ArenaAllocator = .init(gpa);
    defer world.deinit();
    const peers = try world.allocator().alloc(Peer, n_peers);
    for (peers, 0..) |*p, i| {
        const core = i == 0 or !o.adversarial;
        p.* = .{
            .core = core,
            .lag_ns = r.uintAtMost(u64, 3_000 * ms),
            .base_ns = (2 + r.uintAtMost(u64, 60)) * ms,
            .jitter_ns = r.uintAtMost(u64, 40 * ms),
            .spike_ppm = if (o.adversarial) r.uintAtMost(u32, 100_000) else 0,
            .spike_ns = (100 + r.uintAtMost(u64, 3_000)) * ms,
            .drop_ppm = if (o.adversarial) r.uintAtMost(u32, if (core) 150_000 else 400_000) else 0,
            .corrupt_ppm = if (core or !o.adversarial) 0 else r.uintAtMost(u32, 700_000),
            .forky = !core and o.adversarial and r.uintLessThan(u8, 6) == 0,
        };
        if (o.adversarial and r.uintLessThan(u8, 3) == 0) {
            p.part_from = r.uintAtMost(u64, o.heal_ms * ms);
            p.part_to = p.part_from + r.uintAtMost(u64, 6_000 * ms);
        }
    }
    // Focused families: drawn after the mixed draw (from their own stream), so `.none` replays as before.
    var fprng: std.Random.DefaultPrng = .init(o.seed ^ 0xf0c5_0001);
    const fr = fprng.random();
    switch (o.focus) {
        .none, .crashes => {},
        .forks => for (peers) |*p| {
            p.part_from = 0;
            p.part_to = 0;
            p.corrupt_ppm = 0;
            p.forky = !p.core;
        },
        .partitions => {
            const blackout = fr.boolean();
            const b_from = fr.uintAtMost(u64, o.heal_ms * ms * 3 / 4);
            const b_to = b_from + (500 + fr.uintAtMost(u64, 8_000)) * ms;
            for (peers) |*p| {
                p.corrupt_ppm = 0;
                p.forky = false;
                if (blackout) {
                    p.part_from = b_from;
                    p.part_to = b_to;
                } else {
                    p.part_from = fr.uintAtMost(u64, o.heal_ms * ms * 3 / 4);
                    p.part_to = p.part_from + (500 + fr.uintAtMost(u64, 8_000)) * ms;
                }
            }
        },
        .skew => for (peers) |*p| {
            p.corrupt_ppm = 0;
            p.forky = false;
        },
        .forged => for (peers) |*p| {
            p.part_from = 0;
            p.part_to = 0;
            p.forky = false;
            p.corrupt_ppm = if (p.core) 0 else 1_000_000;
        },
    }
    const cfg: store_mod.Config = .{
        .max_live_objects = 4096,
        .max_object_versions = 1 << 12,
        .max_transactions = 1 << 12,
        .max_checkpoints = 1 << 12,
        .max_batch_bytes = 1 << 20,
        .max_batch_objects = 128,
        .max_segments = 64,
        .index_flush_interval = r.intRangeAtMost(u64, 2, 48),
        .segment_reserve = 16 << 20,
        .seed = o.seed | 1,
        .retention_epochs = 1 << 20,
        .object_retention_epochs = 1 << 20,
    };
    const window: u32 = @max(1, o.window);
    var flaky: Flaky = .{ .parent = gpa, .prng = .init(o.seed ^ 0xf1a4), .ppm = if (o.oom) r.uintAtMost(u32, 30_000) else 0 };
    const slots = try world.allocator().alloc(Slot, window);
    for (slots) |*sl| sl.* = .{ .arena = .init(flaky.allocator()) };
    defer for (slots) |*sl| sl.arena.deinit();
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);

    var s: Sim = .{
        .gpa = gpa,
        .o = o,
        .res = &res,
        .chain = chain,
        .prng = .init(o.seed ^ 0xa5a5_1234),
        .node_prng = .init(o.seed ^ 0x0de0_77),
        .wa = world.allocator(),
        .peers = peers,
        .disk = disk,
        .cfg = cfg,
        .oracle_committees = try world.allocator().alloc(?Committee, chain.epochs.len),
        .oracle_arena = .init(gpa),
        .narena = .init(flaky.allocator()),
        .flaky = &flaky,
        .slots = slots,
        .idx = idx,
        .clock_skew_ppm = r.intRangeAtMost(i64, -50_000, 50_000),
    };
    if (o.focus == .skew) s.clock_skew_ppm = if (fr.boolean()) fr.intRangeAtMost(i64, -500_000, -100_000) else fr.intRangeAtMost(i64, 100_000, 1_000_000);
    defer s.heap.items.deinit(gpa);
    defer s.resps.deinit(gpa);
    defer s.oracle_arena.deinit();
    defer s.narena.deinit();
    defer if (s.store) |st| st.deinit();
    @memset(s.oracle_committees, null);
    for (chain.epochs, 0..) |*e, i| {
        const keys = try e.keys(s.oracle_arena.allocator());
        const stakes = try e.stakes(s.oracle_arena.allocator());
        s.oracle_committees[i] = try Committee.init(s.oracle_arena.allocator(), i, keys, stakes);
    }
    // Pinned checkpoints: a few digests of the truth.
    var pins: [3]peer_score.Pinned.Entry = undefined;
    for (&pins) |*p| {
        const q = r.uintLessThan(u64, chain.len());
        p.* = .{ .seq = q, .digest = chain.cps[q].digest };
    }
    // Duplicate seqs are harmless (same digest).
    s.pinned = peer_score.Pinned.init(&pins);

    // Fault schedule.
    try s.push(o.heal_ms * ms, .heal, 0);
    if (o.crashes) {
        var k = r.uintLessThan(u8, 5);
        while (k > 0) : (k -= 1) try s.push(r.uintAtMost(u64, o.heal_ms * ms), .kill, 0);
    }
    if (o.focus == .crashes) {
        var k = 3 + fr.uintLessThan(u8, 6);
        while (k > 0) : (k -= 1) try s.push(fr.uintAtMost(u64, o.heal_ms * ms), .kill, 0);
    }
    s.disk_ns_seen = disk.stats.clock_ns;
    s.boot() catch |e| switch (e) {
        error.RecoveryFailed => if (res.ok) res.failf("recovery failed", .{}),
        else => return e,
    };
    if (res.ok) s.loop() catch |e| switch (e) {
        error.RecoveryFailed => if (res.ok) res.failf("recovery failed", .{}),
        else => return e,
    };
    res.virtual_ms = s.now / ms;
    res.committed = s.next_apply;
    res.sim_ops = disk.stats.ops;
    // Final: all faults off, a clean crash with nothing in flight, recovery must come back whole.
    if (res.ok) {
        s.heal();
        if (s.alive) {
            s.alive = false;
            if (s.store) |st| st.deinit();
            s.store = null;
            disk.crash();
            s.openStore() catch {};
            if (res.ok) {
                if (s.store) |st| {
                    if (st.committed() != chain.len() - 1) res.failf("final recovery: committed {?d}, expected {d}", .{ st.committed(), chain.len() - 1 });
                    s.acked = chain.len() - 1;
                    if (res.ok) s.checkStoreAgainstTruth("final recovery");
                }
            }
        }
    }
    res.trace ^= disk.trace;
    return res;
}

// ------------------------------------------------------------------ tests

test "a quiet network converges" {
    const gpa = std.testing.allocator;
    const r = try run(gpa, .{ .seed = 1, .checkpoints = 14, .adversarial = false, .io_faults = false, .crashes = false });
    if (!r.ok) std.debug.print("{s}\n", .{r.msg()});
    try std.testing.expect(r.ok);
    try std.testing.expectEqual(@as(u64, 14), r.committed);
}

test "seeds with every fault hold the invariants" {
    const gpa = std.testing.allocator;
    const c = try Chain.generate(gpa, .{ .seed = 99, .checkpoints = 20 });
    defer c.deinit();
    var seed: u64 = 1;
    while (seed <= 6) : (seed += 1) {
        const r = try run(gpa, .{ .seed = seed, .chain = c });
        if (!r.ok) std.debug.print("seed {d}: {s}\n", .{ seed, r.msg() });
        try std.testing.expect(r.ok);
    }
}

test "each focused fault family holds the invariants" {
    const gpa = std.testing.allocator;
    const c = try Chain.generate(gpa, .{ .seed = 98, .checkpoints = 20 });
    defer c.deinit();
    for ([_]Focus{ .forks, .partitions, .crashes, .skew, .forged }) |f| {
        var seed: u64 = 1;
        while (seed <= 4) : (seed += 1) {
            var o: Options = .{ .seed = seed, .chain = c, .focus = f };
            if (f != .crashes) {
                o.io_faults = false;
                o.crashes = false;
                o.oom = false;
            }
            if (f == .crashes) o.adversarial = false;
            const r = try run(gpa, o);
            if (!r.ok) std.debug.print("{t} seed {d}: {s}\n", .{ f, seed, r.msg() });
            try std.testing.expect(r.ok);
            if (f == .forged) try std.testing.expect(r.forged_served > 0);
        }
    }
}

test "a seed replays bit for bit" {
    const gpa = std.testing.allocator;
    const c = try Chain.generate(gpa, .{ .seed = 5, .checkpoints = 16 });
    defer c.deinit();
    const a = try run(gpa, .{ .seed = 42, .chain = c });
    const b = try run(gpa, .{ .seed = 42, .chain = c });
    try std.testing.expectEqual(a.trace, b.trace);
    try std.testing.expectEqual(a.virtual_ms, b.virtual_ms);
    try std.testing.expectEqual(a.commits, b.commits);
    const d = try run(gpa, .{ .seed = 43, .chain = c });
    try std.testing.expect(d.trace != a.trace);
}

test "the harness catches a node that skips the certificate" {
    const gpa = std.testing.allocator;
    const c = try Chain.generate(gpa, .{ .seed = 6, .checkpoints = 20 });
    defer c.deinit();
    var caught: u32 = 0;
    var seed: u64 = 1;
    while (seed <= 12) : (seed += 1) {
        const r = try run(gpa, .{ .seed = seed, .chain = c, .sabotage = .skip_cert, .crashes = false });
        if (!r.ok) caught += 1;
    }
    try std.testing.expect(caught > 0);
}

test "the harness catches a node that skips the chain rules" {
    const gpa = std.testing.allocator;
    const c = try Chain.generate(gpa, .{ .seed = 7, .checkpoints = 20 });
    defer c.deinit();
    var caught: u32 = 0;
    var seed: u64 = 1;
    while (seed <= 12) : (seed += 1) {
        const r = try run(gpa, .{ .seed = seed, .chain = c, .sabotage = .skip_chain, .crashes = false });
        if (!r.ok) caught += 1;
    }
    try std.testing.expect(caught > 0);
}

test "the harness catches an acknowledgement before the commit" {
    const gpa = std.testing.allocator;
    const r = try run(gpa, .{ .seed = 3, .checkpoints = 12, .sabotage = .lose_ack, .adversarial = false });
    try std.testing.expect(!r.ok);
}
