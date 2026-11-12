//! Deterministic simulation tester for the store (suite `store-dst`).
//!
//! One run = one seed. The driver feeds checkpoints (synthetic, or real corpus checkpoints from
//! the storage truth files) through the real engine on the simulated disk (sim.zig), and in
//! between it crashes the disk at random operation counts (including in the middle of recovery),
//! prunes, snapshots the index, closes and reopens. After every recovery it checks the whole
//! store against an in-memory reference model of the committed history:
//!
//!   - the recovered checkpoint is the last acknowledged commit, or the one in flight when the
//!     crash hit (then the model takes it too); nothing else is acceptable;
//!   - every live object reads back with its exact version, digest and bytes, every tombstone
//!     with its version and kind, every retained checkpoint, transaction and object version
//!     byte for byte, and nothing pruned is required (extra retention is allowed, wrong bytes
//!     never are);
//!   - an older MVCC snapshot keeps seeing its own versions after newer commits.
//!
//! Corruption seeds end with latent sector errors and misdirected writes on durable data, then
//! a crash. There the store must either refuse to open (error.Corrupt), report the damaged read
//! as an error, or return bytes that equal the model's for that exact key: never wrong data.
//!
//! With `lean` set, the run also emits the NDJSON trace of the Lean store model
//! (lean/Zui/Store/Trace.lean): a `commit` per checkpoint started (its object writes as
//! [key, version, value]), an `ack` per acknowledged commit, a `recover` with the recovered
//! checkpoint count and the store's whole live index after every crash, and a `read` after
//! every clean check. `zui-spec store-trace` then checks the recovery bounds and states
//! independently of the in-memory model. Keys are object ids numbered in first-write order,
//! values a hash of digest and bytes (even) or the tombstone kind (odd). The Lean model has no
//! pruning, so a tombstone the store dropped by pruning is reported with the value it had
//! (the in-memory model checks the pruning itself).
//!
//! The Lean checker recomputes each state from the whole history, so long runs are cut into
//! windows (`Options.lean_window` checkpoints): at a point where every commit is acknowledged
//! and checked against the in-memory model, the next window starts with one commit holding
//! that state (every non-pruned key), acknowledged, and continues from there. Each window is
//! its own trace; `Result.lean_cuts` holds where each one ends.
//!
//! `steady` seeds run long (>= 2000 checkpoints) with tiny index limits and a prune at every
//! epoch change, so memtables seal many runs, the live index grows and reclaims tombstone
//! slots, and runs are dropped with their segments: the steady state DST must cover.
//!
//! `io_faults` seeds add I/O errors (sim.zig: failed reads, failed or partial writes, failed
//! fdatasync that drops dirty pages) to commits and recoveries, each class switched on or off
//! per seed (swarm). A commit that fails is either retried at once (a node re-executes the
//! checkpoint) or ends the process (crash, reopen): either way the store must never lose an
//! acknowledged checkpoint, never acknowledge a checkpoint that is not durable, and must open
//! again after a transient error (an EIO is not corruption).
const std = @import("std");
const store_mod = @import("store.zig");
const cs = @import("checksum.zig");
const sim_mod = @import("sim.zig");
const ops = @import("ops.zig");
const io_mod = @import("io.zig");
const format_mod = @import("format.zig");
const chunk_mod = @import("chunk.zig");

const Store = store_mod.Store;
const SimIo = sim_mod.SimIo;
const RemoveKind = store_mod.RemoveKind;

pub const Options = struct {
    seed: u64,
    checkpoints: u32 = 120,
    /// Real checkpoints to replay instead of synthetic ones (taken in order).
    corpus: ?[]const ops.Checkpoint = null,
    corruption: bool = false,
    /// I/O error faults in commits and recoveries (see above).
    io_faults: bool = false,
    file_cap: u64 = 32 << 20,
    /// Trace every step to stderr (reproducing a failing seed).
    debug: bool = false,
    /// Emit the Lean store-model trace into `Result.lean_trace` (allocated with gpa).
    lean: bool = false,
    /// Long run with tiny index limits and a prune at every epoch change.
    steady: bool = false,
    /// Checkpoints per Lean trace window (0: one trace).
    lean_window: u32 = 0,
    /// Age-out seeds: sui-node's two floors move at random (`setFloors`), age-out steps run
    /// (with crashes inside them), some reopens write raw segments (a mixed store), and a reader
    /// snapshot taken before the steps must read every retained value after them. Retention is
    /// then checked against the floors: checkpoints and transactions from the checkpoint floor
    /// up, object versions in the object window unless the checkpoint that superseded them is
    /// below the object floor.
    age: bool = false,
    /// With `age`: deferred age-out and the read-ahead (lane ager-catchup). The node's catch-up
    /// signal flips at random and the ager follows the store's gate as the ager thread does:
    /// no step while it waits (cleaning goes on and floors move, so segments age out and are
    /// deleted under its cursors), steps while it runs, and a bulk catch-up without the segment
    /// pass once the backlog passes `age_defer_bytes`, with crashes inside the steps and the
    /// bulk runs. Every step is preceded by its read-ahead (`age` seeds without this keep the
    /// serial path, so their runs stay the same draw for draw).
    age_defer: bool = false,
    /// With `age`: the segment pass with a live set (lane ager-segment-pass), with the
    /// read-ahead it needs. The set's memory is 8 to 2048 bytes by seed, so one pass over the
    /// aged segments takes many table passes; steps of a few KiB cut each table pass into
    /// several, with commits, floor moves, cleaning (it deletes live-table entries, which moves
    /// slots) and crashes between them and between the table pass and the walk that uses it.
    age_set: bool = false,
    /// The forced option of store-dst (`ZUI_DST_LIVE_SET`, the runner's `--live-set`): every
    /// seed that runs the ager (`age`) runs it with the read-ahead and the live set, whatever
    /// its family: 64 KiB of bits, or the seed's own size for a live-set seed. The draws of
    /// `age` and deferral seeds are then not those of the default run. `set_verify`: with the
    /// cross-check as well (`Config.age_set_verify`), for every such seed.
    live_set: bool = false,
    set_verify: bool = false,
    /// `pending` seeds: every crash garbles the target of the pending write (sim.zig
    /// `crash_garble_pending`). Checked as strictly as plain crash seeds: the garbled write was
    /// never acknowledged.
    pending: bool = false,
    /// `misdir` seeds: after the strict run, whole writes land at wrong places (another offset
    /// of the same file or another file) over a few commits, index flushes and a close, then a
    /// crash. As corruption seeds: refuse (error.Corrupt), report damaged reads, or return the
    /// model's bytes.
    misdir: bool = false,
    /// `tail` seeds (torn versus rotted newest group): after the strict run the newest group is
    /// damaged. Rot followed by a durable group, or under dir entries that prove the group was
    /// written whole, must refuse with error.Corrupt or read as damaged: never truncate it.
    /// Damage with nothing durable after it and no dir proof must open (truncated as torn).
    tail: bool = false,
};

pub const Result = struct {
    ok: bool = true,
    commits: u64 = 0,
    crashes: u64 = 0,
    recoveries: u64 = 0,
    in_flight_kept: u64 = 0,
    in_flight_lost: u64 = 0,
    prunes: u64 = 0,
    reopens: u64 = 0,
    mvcc_checks: u64 = 0,
    reads_checked: u64 = 0,
    corrupt_detected: u64 = 0,
    /// I/O errors the store reported (io_faults), and how many failed commits a retry fixed.
    io_errors: u64 = 0,
    io_retried: u64 = 0,
    open_refused: bool = false,
    rolled_back: bool = false,
    /// Prunes over a rotted store: succeeded (with every intact live object kept) or refused.
    rot_prunes: u64 = 0,
    age_steps: u64 = 0,
    age_dropped: u64 = 0,
    age_rewrites: u64 = 0,
    /// Deferral seeds: checks that waited, bulk catch-ups run to the end, and those a crash cut.
    age_waits: u64 = 0,
    age_bulks: u64 = 0,
    age_bulk_crashes: u64 = 0,
    /// Live-set seeds: table passes finished, records kept without a lookup, lookups made,
    /// object versions judged dead by a clear bit alone, passes started over or finished
    /// inexact, and clear bits the table contradicted (a failure).
    set_builds: u64 = 0,
    set_kept: u64 = 0,
    age_lookups: u64 = 0,
    set_dead: u64 = 0,
    set_restarts: u64 = 0,
    set_inexact: u64 = 0,
    set_misses: u64 = 0,
    floor_moves: u64 = 0,
    rot_prunes_refused: u64 = 0,
    /// Tail seeds: the damage mode run (0 rot + later group, 1 lost sector, 2 rot under dir
    /// proof, 3 rot with nothing after), and whether the open truncated the damaged group.
    tail_mode: u8 = 0,
    tail_truncated: bool = false,
    trace: u64 = 0,
    sim: sim_mod.Stats = .{},
    msg_buf: [320]u8 = undefined,
    msg_len: usize = 0,
    /// Lean NDJSON trace (caller frees with the gpa given to `run`).
    lean_trace: ?[]u8 = null,
    /// End offsets of the trace windows in `lean_trace` (caller frees with the gpa).
    lean_cuts: ?[]usize = null,
    lean_events: u64 = 0,
    max_runs: u64 = 0,
    max_live_slots: u64 = 0,
    /// Distinct object ids written (with `lean`).
    distinct_ids: u64 = 0,

    pub fn msg(r: *const Result) []const u8 {
        return r.msg_buf[0..r.msg_len];
    }

    fn failf(r: *Result, comptime fmt: []const u8, args: anytype) void {
        if (!r.ok) return;
        r.ok = false;
        const m = std.fmt.bufPrint(&r.msg_buf, fmt, args) catch r.msg_buf[0..];
        r.msg_len = m.len;
    }
};

const VKey = struct { id: [32]u8, v: u64 };
const CpVal = struct { epoch: u64, summary: []const u8, contents: []const u8 };
const TxVal = struct { seq: u64, epoch: u64, tx: []const u8, effects: []const u8, events: ?[]const u8, effects_digest: [32]u8 };
const VerVal = struct { epoch: u64, digest: [32]u8, bytes: []const u8, sup: ?u64 = null };
const LiveVal = struct { version: u64, digest: [32]u8, bytes: []const u8, removed: ?RemoveKind, rec_epoch: u64 };

/// The committed history, as a node would see it.
const Model = struct {
    cps: std.AutoHashMapUnmanaged(u64, CpVal) = .empty,
    txs: std.AutoHashMapUnmanaged([32]u8, TxVal) = .empty,
    vers: std.AutoHashMapUnmanaged(VKey, VerVal) = .empty,
    live: std.AutoHashMapUnmanaged([32]u8, LiveVal) = .empty,
    /// Tombstones pruning dropped (for the Lean trace).
    pruned: std.AutoHashMapUnmanaged([32]u8, LiveVal) = .empty,
    committed: ?u64 = null,
    cur_epoch: ?u64 = null,
    oldest: u64 = 0,

    fn apply(m: *Model, a: std.mem.Allocator, cp: *const ops.Checkpoint) !void {
        try m.cps.put(a, cp.seq, .{ .epoch = cp.epoch, .summary = cp.summary_cert, .contents = cp.contents });
        for (cp.txs) |*t| {
            try m.txs.put(a, t.digest.*, .{ .seq = cp.seq, .epoch = cp.epoch, .tx = t.tx, .effects = t.effects, .events = t.events, .effects_digest = t.effects_digest.* });
            // The checkpoint that supersedes a version (sui-node prunes it with that checkpoint).
            for (t.puts) |*p| m.supersede(p.id, cp.seq);
            for (t.removes) |*r| m.supersede(r.id, cp.seq);
            for (t.puts) |*p| {
                try m.vers.put(a, .{ .id = p.id.*, .v = p.version }, .{ .epoch = cp.epoch, .digest = p.digest.*, .bytes = p.bytes });
                try m.live.put(a, p.id.*, .{ .version = p.version, .digest = p.digest.*, .bytes = p.bytes, .removed = null, .rec_epoch = cp.epoch });
                _ = m.pruned.remove(p.id.*);
            }
            for (t.removes) |*r| {
                try m.live.put(a, r.id.*, .{ .version = r.version, .digest = @splat(0), .bytes = &.{}, .removed = ops.removeKind(r.kind), .rec_epoch = cp.epoch });
                _ = m.pruned.remove(r.id.*);
            }
        }
        m.committed = cp.seq;
        m.cur_epoch = cp.epoch;
    }

    /// Retention after pruning: history written in epochs >= target stays; the live version of
    /// every object stays (carried forward); tombstones in dropped epochs go.
    fn prune(m: *Model, a: std.mem.Allocator, target: u64) void {
        var it = m.live.iterator();
        var drop: std.ArrayList([32]u8) = .empty;
        defer drop.deinit(std.heap.page_allocator);
        while (it.next()) |e| {
            if (e.value_ptr.removed != null and e.value_ptr.rec_epoch < target)
                drop.append(std.heap.page_allocator, e.key_ptr.*) catch @panic("oom");
        }
        for (drop.items) |id| {
            m.pruned.put(a, id, m.live.get(id).?) catch @panic("oom");
            _ = m.live.remove(id);
        }
        m.oldest = target;
    }

    fn supersede(m: *Model, id: *const [32]u8, seq: u64) void {
        const lv = m.live.get(id.*) orelse return;
        if (lv.removed != null) return;
        if (m.vers.getPtr(.{ .id = id.*, .v = lv.version })) |v| if (v.sup == null) {
            v.sup = seq;
        };
    }

    fn isLiveVersion(m: *const Model, id: *const [32]u8, v: u64) bool {
        const l = m.live.get(id.*) orelse return false;
        return l.removed == null and l.version == v;
    }
};

/// Synthetic Sui-shaped workload: an id pool (some ids with long zero prefixes, like system
/// objects), versions from a Lamport clock, creates, mutations, deletes, wraps, unwraps,
/// occasional large objects, epoch changes.
const Gen = struct {
    const pool = 160;
    rnd: std.Random,
    ids: [pool][32]u8 = undefined,
    state: [pool]enum { none, live, wrapped, deleted } = @splat(.none),
    lamport: u64 = 1,
    bigs: u32 = 0,
    seq: u64 = 0,
    epoch: u64 = 0,
    /// Steady churn: deleted ids are replaced by fresh ones, so unique ids keep coming.
    churn: bool = false,

    fn init(rnd: std.Random) Gen {
        var g: Gen = .{ .rnd = rnd };
        for (&g.ids, 0..) |*id, i| {
            if (i < 8) {
                id.* = @splat(0);
                id[31] = @intCast(i + 1);
            } else rnd.bytes(id);
        }
        g.seq = rnd.uintLessThan(u64, 1000);
        g.epoch = rnd.uintLessThan(u64, 50);
        return g;
    }

    fn idCopy(a: std.mem.Allocator, id: *const [32]u8) !*const [32]u8 {
        const c = try a.create([32]u8);
        c.* = id.*;
        return c;
    }

    fn bytes(g: *Gen, a: std.mem.Allocator, min: usize, max: usize) ![]const u8 {
        const n = g.rnd.intRangeAtMost(usize, min, max);
        const b = try a.alloc(u8, n);
        g.rnd.bytes(b);
        return b;
    }

    fn next(g: *Gen, a: std.mem.Allocator) !ops.Checkpoint {
        g.seq += 1 + (if (g.rnd.uintLessThan(u8, 4) == 0) g.rnd.uintLessThan(u64, 3) else 0);
        if (g.rnd.uintLessThan(u8, 12) == 0) g.epoch += 1 + (if (g.rnd.uintLessThan(u8, 8) == 0) @as(u64, 1) else 0);
        const ntx = g.rnd.uintLessThan(usize, 7);
        g.bigs = 0;
        if (g.churn) for (&g.ids, &g.state, 0..) |*id, *st, i| {
            if (i >= 8 and st.* == .deleted and g.rnd.uintLessThan(u8, 4) == 0) {
                g.rnd.bytes(id);
                st.* = .none;
            }
        };
        const txs = try a.alloc(ops.Tx, ntx);
        for (txs) |*t| {
            const d = try a.create([32]u8);
            g.rnd.bytes(d);
            const ed = try a.create([32]u8);
            g.rnd.bytes(ed);
            t.* = .{
                .digest = d,
                .effects_digest = ed,
                .tx = try g.bytes(a, 0, 600),
                .effects = try g.bytes(a, 1, 400),
                .events = if (g.rnd.boolean()) try g.bytes(a, 0, 300) else null,
                .puts = &.{},
                .removes = &.{},
            };
            g.lamport += 1;
            const version = g.lamport;
            var puts: std.ArrayList(ops.Put) = .empty;
            var rems: std.ArrayList(ops.Remove) = .empty;
            var used: [pool]bool = @splat(false);
            const nput = g.rnd.uintLessThan(usize, 6);
            for (0..nput) |_| {
                const i = g.rnd.uintLessThan(usize, pool);
                if (used[i] or g.state[i] == .deleted) continue;
                used[i] = true;
                const dg = try a.create([32]u8);
                g.rnd.bytes(dg);
                const big = g.bigs < 2 and g.rnd.uintLessThan(u16, 300) == 0;
                if (big) g.bigs += 1;
                try puts.append(a, .{ .id = try idCopy(a, &g.ids[i]), .version = version, .digest = dg, .bytes = if (big) try g.bytes(a, 60_000, 300_000) else try g.bytes(a, 0, 2_500) });
                g.state[i] = .live;
            }
            const nrem = g.rnd.uintLessThan(usize, 3);
            for (0..nrem) |_| {
                const i = g.rnd.uintLessThan(usize, pool);
                if (used[i]) continue;
                switch (g.state[i]) {
                    .live => {
                        const wrap = g.rnd.boolean();
                        try rems.append(a, .{ .id = try idCopy(a, &g.ids[i]), .version = version, .kind = if (wrap) 1 else 0 });
                        g.state[i] = if (wrap) .wrapped else .deleted;
                    },
                    .wrapped => {
                        try rems.append(a, .{ .id = try idCopy(a, &g.ids[i]), .version = version, .kind = 2 });
                        g.state[i] = .deleted;
                    },
                    else => continue,
                }
                used[i] = true;
            }
            t.puts = puts.items;
            t.removes = rems.items;
        }
        return .{ .seq = g.seq, .epoch = g.epoch, .summary_cert = try g.bytes(a, 100, 900), .contents = try g.bytes(a, 0, 3000), .txs = txs };
    }
};

/// Emits the Lean store-model trace (see the file comment).
const Lean = struct {
    gpa: std.mem.Allocator,
    out: std.ArrayList(u8) = .empty,
    ord: std.AutoHashMapUnmanaged([32]u8, u64) = .empty,
    ids: std.ArrayList([32]u8) = .empty,
    /// ordinal -> index of the first commit in `hist` that writes it (none: maxInt).
    first: std.ArrayList(u64) = .empty,
    /// commit index -> checkpoint seq.
    hist: std.ArrayList(u64) = .empty,
    events: u64 = 0,
    cuts: std.ArrayList(usize) = .empty,
    window: u64 = 0,
    /// Commits in the current window.
    in_window: u64 = 0,

    const none = std.math.maxInt(u64);

    fn deinit(l: *Lean) void {
        l.cuts.deinit(l.gpa);
        l.out.deinit(l.gpa);
        l.ord.deinit(l.gpa);
        l.ids.deinit(l.gpa);
        l.first.deinit(l.gpa);
        l.hist.deinit(l.gpa);
    }

    fn print(l: *Lean, comptime fmt: []const u8, args: anytype) !void {
        try l.out.print(l.gpa, fmt, args);
    }

    fn keyOf(l: *Lean, id: *const [32]u8) !u64 {
        const g = try l.ord.getOrPut(l.gpa, id.*);
        if (!g.found_existing) {
            g.value_ptr.* = l.ids.items.len;
            try l.ids.append(l.gpa, id.*);
            try l.first.append(l.gpa, none);
        }
        const k = g.value_ptr.*;
        // `commit` appended this checkpoint already: it is index len - 1.
        if (l.first.items[k] == none) l.first.items[k] = l.hist.items.len - 1;
        return k;
    }

    fn liveVal(digest: *const [32]u8, bytes: []const u8) u64 {
        return (cs.hash(cs.hash(0x6c65616e, digest), bytes) >> 2) << 1;
    }

    fn tombVal(kind: RemoveKind) u64 {
        return @as(u64, @intFromEnum(kind)) * 2 + 1;
    }

    /// Every commit so far is acknowledged and the model was checked: if the window is full,
    /// start a new trace from the model's state.
    fn maybeCut(l: *Lean, model: *const Model) !void {
        if (l.window == 0 or l.in_window < l.window or model.committed == null) return;
        try l.cuts.append(l.gpa, l.out.items.len);
        l.in_window = 0;
        l.hist.clearRetainingCapacity();
        for (l.first.items) |*f| f.* = none;
        try l.hist.append(l.gpa, model.committed.?);
        try l.print("{{\"op\":\"commit\",\"writes\":[", .{});
        // Sorted by key ordinal (any order is valid; sorted keeps traces stable).
        var keys: std.ArrayList(u64) = .empty;
        defer keys.deinit(l.gpa);
        var it = model.live.iterator();
        while (it.next()) |e| try keys.append(l.gpa, try l.keyOf(e.key_ptr));
        std.mem.sort(u64, keys.items, {}, std.sort.asc(u64));
        for (keys.items, 0..) |k, n| {
            const v = model.live.get(l.ids.items[k]).?;
            const val = if (v.removed) |kind| tombVal(kind) else liveVal(&v.digest, v.bytes);
            try l.print("{s}[{d},{d},{d}]", .{ if (n == 0) "" else ",", k, v.version, val });
        }
        try l.print("]}}\n{{\"op\":\"ack\"}}\n", .{});
        l.events += 2;
    }

    fn commit(l: *Lean, cp: *const ops.Checkpoint) !void {
        l.in_window += 1;
        try l.hist.append(l.gpa, cp.seq);
        try l.print("{{\"op\":\"commit\",\"writes\":[", .{});
        var n: usize = 0;
        for (cp.txs) |*t| {
            for (t.puts) |*p| {
                const k = try l.keyOf(p.id);
                try l.print("{s}[{d},{d},{d}]", .{ if (n == 0) "" else ",", k, p.version, liveVal(p.digest, p.bytes) });
                n += 1;
            }
            for (t.removes) |*r| {
                const k = try l.keyOf(r.id);
                try l.print("{s}[{d},{d},{d}]", .{ if (n == 0) "" else ",", k, r.version, tombVal(ops.removeKind(r.kind)) });
                n += 1;
            }
        }
        try l.print("]}}\n", .{});
        l.events += 1;
    }

    fn ack(l: *Lean) !void {
        try l.print("{{\"op\":\"ack\"}}\n", .{});
        l.events += 1;
    }

    /// The store's live index over every key the current history writes, sorted by key.
    fn state(l: *Lean, s: *Store, model: *const Model) !void {
        var snap = s.snapshot();
        defer snap.release();
        try l.print("[", .{});
        var n: usize = 0;
        for (l.ids.items, 0..) |*id, k| {
            if (l.first.items[k] >= l.hist.items.len) continue;
            const got = snap.latest(id) catch null;
            const vv: ?struct { u64, u64 } = if (got) |g| switch (g) {
                .live => |o| .{ o.version, liveVal(&o.digest, o.bytes) },
                .removed => |r| .{ r.version, tombVal(r.kind) },
            } else if (model.pruned.get(id.*)) |p|
                .{ p.version, tombVal(p.removed.?) }
            else
                null;
            if (vv) |x| {
                try l.print("{s}[{d},{d},{d}]", .{ if (n == 0) "" else ",", k, x[0], x[1] });
                n += 1;
            }
        }
        try l.print("]", .{});
    }

    fn read(l: *Lean, s: *Store, model: *const Model) !void {
        try l.print("{{\"op\":\"read\",\"state\":", .{});
        try l.state(s, model);
        try l.print("}}\n", .{});
        l.events += 1;
    }

    /// After a crash: the recovered count, the state, then the history continues from there.
    fn recover(l: *Lean, s: *Store, model: *const Model) !void {
        const c = s.committed();
        var k: usize = 0;
        if (c) |cseq| while (k < l.hist.items.len and l.hist.items[k] <= cseq) : (k += 1) {};
        l.hist.shrinkRetainingCapacity(k);
        for (l.first.items) |*f| if (f.* != none and f.* >= k) {
            f.* = none;
        };
        try l.print("{{\"op\":\"recover\",\"k\":{d},\"state\":", .{k});
        try l.state(s, model);
        try l.print("}}\n", .{});
        l.events += 1;
    }
};

const Driver = struct {
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    rnd: std.Random,
    sim: *SimIo,
    cfg: store_mod.Config,
    store: ?*Store = null,
    model: Model = .{},
    res: *Result,
    opts: *const Options,
    lean: ?*Lean = null,
    last_prune_epoch: ?u64 = null,
    /// Deferral seeds: the node's catch-up signal.
    behind: bool = true,
    /// The store whose age counters were last added to the result, and their values then.
    seen_store: ?*Store = null,
    seen: [7]u64 = @splat(0),

    fn reopen(d: *Driver) !void {
        // Age seeds: some incarnations write raw segments (a store mixing both formats).
        if (d.opts.age) d.cfg.compress = d.rnd.uintLessThan(u8, 4) != 0;
        // Recovery itself may crash; keep going until it completes.
        var tries: u32 = 0;
        while (true) : (tries += 1) {
            if (tries > 0 and tries < 4 and d.rnd.uintLessThan(u8, 3) == 0) d.sim.scheduleCrash(d.rnd.uintLessThan(u64, 12));
            d.sim.io_armed = d.opts.io_faults;
            const s = Store.open(d.gpa, .{ .sim = d.sim }, &d.cfg) catch |e| switch (e) {
                error.Crashed => {
                    d.sim.io_armed = false;
                    d.res.crashes += 1;
                    d.sim.crash();
                    continue;
                },
                // A transient error fails this open; the process restarts and opens again.
                error.Io, error.NoSpace, error.ShortRead => if (d.opts.io_faults and tries < 200) {
                    d.sim.io_armed = false;
                    if (d.opts.debug) std.debug.print("open: {t} (sim reads {d} writes {d} syncs {d} failed)\n", .{ e, d.sim.stats.read_errors, d.sim.stats.write_errors, d.sim.stats.sync_errors });
                    d.res.io_errors += 1;
                    d.sim.crash();
                    continue;
                } else return e,
                else => {
                    d.sim.io_armed = false;
                    if (d.opts.io_faults) d.res.failf("open after I/O errors: {t} (sim {d} read, {d} write, {d} sync errors)", .{ e, d.sim.stats.read_errors, d.sim.stats.write_errors, d.sim.stats.sync_errors });
                    return e;
                },
            };
            d.sim.io_armed = false;
            d.sim.scheduleCrash(null);
            d.store = s;
            d.res.recoveries += 1;
            return;
        }
    }

    fn leanRecover(d: *Driver) !void {
        if (d.lean) |l| try l.recover(d.store.?, &d.model);
    }

    fn leanRead(d: *Driver) !void {
        if (d.lean) |l| try l.read(d.store.?, &d.model);
    }

    fn crashed(d: *Driver) !void {
        if (d.opts.debug) std.debug.print("crash\n", .{});
        d.res.crashes += 1;
        d.store.?.deinit();
        d.store = null;
        d.sim.crash();
        try d.reopen();
    }

    /// Full comparison with the model. `lenient`: corruption mode (errors allowed; any bytes
    /// returned must equal the model's for that key).
    fn check(d: *Driver, lenient: bool) void {
        var snap = d.store.?.snapshot();
        defer snap.release();
        d.checkWith(lenient, &snap);
    }

    fn checkWith(d: *Driver, lenient: bool, snap: *store_mod.Snapshot) void {
        const s = d.store.?;
        const res = d.res;
        const oldest = s.oldest_epoch.load(.monotonic);
        const cp_floor = s.cp_floor.load(.monotonic);
        const obj_floor = s.obj_floor.load(.monotonic);
        const obj_epoch = s.obj_floor_epoch.load(.monotonic);
        if (!lenient) {
            if (!std.meta.eql(s.committed(), d.model.committed))
                return res.failf("committed {?d}, model {?d}", .{ s.committed(), d.model.committed });
            if (oldest != d.model.oldest and d.model.committed != null)
                return res.failf("oldest epoch {d}, model {d}", .{ oldest, d.model.oldest });
        }
        const visible_max: ?u64 = s.committed();
        var cit = d.model.cps.iterator();
        while (cit.next()) |e| {
            res.reads_checked += 1;
            const got = snap.checkpointChecked(e.key_ptr.*) catch |err| {
                if (lenient and err == error.Corrupt) {
                    res.corrupt_detected += 1;
                    continue;
                }
                return res.failf("checkpoint {d}: {s}", .{ e.key_ptr.*, @errorName(err) });
            };
            const must = !lenient and e.value_ptr.epoch >= oldest and e.key_ptr.* >= cp_floor;
            if (got) |c| {
                if (!std.mem.eql(u8, c.summary_cert, e.value_ptr.summary) or !std.mem.eql(u8, c.contents, e.value_ptr.contents) or c.epoch != e.value_ptr.epoch)
                    return res.failf("checkpoint {d}: wrong bytes", .{e.key_ptr.*});
                if (visible_max == null or e.key_ptr.* > visible_max.?) return res.failf("checkpoint {d} beyond committed", .{e.key_ptr.*});
            } else if (must) return res.failf("checkpoint {d} missing", .{e.key_ptr.*});
        }
        var tit = d.model.txs.iterator();
        while (tit.next()) |e| {
            res.reads_checked += 1;
            const got = snap.transactionChecked(e.key_ptr) catch |err| {
                if (lenient and err == error.Corrupt) {
                    res.corrupt_detected += 1;
                    continue;
                }
                return res.failf("tx: {s}", .{@errorName(err)});
            };
            const v = e.value_ptr;
            if (got) |t| {
                const ev_ok = if (v.events) |ev| (t.events != null and std.mem.eql(u8, t.events.?, ev)) else t.events == null;
                if (!std.mem.eql(u8, t.tx, v.tx) or !std.mem.eql(u8, t.effects, v.effects) or !ev_ok or t.checkpoint != v.seq or !std.mem.eql(u8, t.effects_digest, &v.effects_digest))
                    return res.failf("tx in checkpoint {d}: wrong bytes", .{v.seq});
            } else if (!lenient and v.epoch >= oldest and v.seq >= cp_floor) return res.failf("tx in checkpoint {d} missing", .{v.seq});
        }
        var vit = d.model.vers.iterator();
        while (vit.next()) |e| {
            res.reads_checked += 1;
            const got = snap.objectAtChecked(&e.key_ptr.id, e.key_ptr.v) catch |err| {
                if (lenient and err == error.Corrupt) {
                    res.corrupt_detected += 1;
                    continue;
                }
                return res.failf("objectAt v{d}: {s}", .{ e.key_ptr.v, @errorName(err) });
            };
            if (got) |o| {
                if (!std.mem.eql(u8, o.bytes, e.value_ptr.bytes) or !std.mem.eql(u8, &o.digest, &e.value_ptr.digest))
                    return res.failf("objectAt v{d}: wrong bytes", .{e.key_ptr.v});
            } else if (!lenient and ((e.value_ptr.epoch >= oldest and e.value_ptr.epoch >= obj_epoch and (e.value_ptr.sup == null or e.value_ptr.sup.? >= obj_floor)) or d.model.isLiveVersion(&e.key_ptr.id, e.key_ptr.v))) {
                if (d.opts.debug) {
                    std.debug.print("missing id {x} v{d}\n", .{ e.key_ptr.id[0..8], e.key_ptr.v });
                    if (d.model.live.get(e.key_ptr.id)) |lv| std.debug.print("  model live v{d} rec_epoch {d} removed {any}\n", .{ lv.version, lv.rec_epoch, lv.removed });
                }
                return res.failf("objectAt v{d} missing (epoch {d}, oldest {d})", .{ e.key_ptr.v, e.value_ptr.epoch, oldest });
            }
        }
        var lit = d.model.live.iterator();
        while (lit.next()) |e| {
            res.reads_checked += 1;
            const v = e.value_ptr;
            const got = snap.latest(e.key_ptr) catch |err| {
                if (lenient and err == error.Corrupt) {
                    res.corrupt_detected += 1;
                    continue;
                }
                return res.failf("latest: {s}", .{@errorName(err)});
            };
            if (lenient) {
                // Whatever comes back must be some committed version of this object.
                if (got) |g| switch (g) {
                    .live => |o| {
                        const h = d.model.vers.get(.{ .id = e.key_ptr.*, .v = o.version }) orelse return res.failf("latest: unknown version {d}", .{o.version});
                        if (!std.mem.eql(u8, o.bytes, h.bytes) or !std.mem.eql(u8, &o.digest, &h.digest)) return res.failf("latest: wrong bytes", .{});
                    },
                    .removed => {},
                };
                continue;
            }
            if (v.removed) |kind| {
                if (got) |g| switch (g) {
                    .removed => |r| if (r.version != v.version or r.kind != kind) return res.failf("tombstone v{d}: got v{d}", .{ v.version, r.version }),
                    .live => return res.failf("tombstone v{d}: object is live", .{v.version}),
                } else if (v.rec_epoch >= oldest) return res.failf("tombstone v{d} missing", .{v.version});
            } else {
                const g = got orelse return res.failf("live object v{d} missing", .{v.version});
                switch (g) {
                    .live => |o| if (o.version != v.version or !std.mem.eql(u8, o.bytes, v.bytes) or !std.mem.eql(u8, &o.digest, &v.digest))
                        return res.failf("live object: got v{d}, model v{d}", .{ o.version, v.version }),
                    .removed => return res.failf("live object v{d} reads as removed", .{v.version}),
                }
            }
        }
    }

    fn step(d: *Driver, cp: *const ops.Checkpoint) !void {
        const r = d.rnd;
        // Every earlier commit is acknowledged (or recovered) and checked here.
        if (d.lean) |l| try l.maybeCut(&d.model);
        if (r.uintLessThan(u8, 6) == 0) d.sim.scheduleCrash(r.uintLessThan(u64, 24));
        // MVCC probe: an id this checkpoint writes that already has a committed live value.
        var probe: ?struct { id: [32]u8, val: LiveVal, snap: store_mod.Snapshot } = null;
        if (r.uintLessThan(u8, 3) == 0) outer: for (cp.txs) |*t| for (t.puts) |*p| {
            if (d.model.live.get(p.id.*)) |v| if (v.removed == null) {
                probe = .{ .id = p.id.*, .val = v, .snap = d.store.?.snapshot() };
                break :outer;
            };
        };
        if (d.opts.debug) std.debug.print("cp seq {d} epoch {d}\n", .{ cp.seq, cp.epoch });
        if (d.lean) |l| try l.commit(cp);
        const outcome = d.commitOne(cp);
        if (outcome) |_| {
            try d.model.apply(d.arena, cp);
            if (d.lean) |l| try l.ack();
            d.res.commits += 1;
            if (probe) |*pr| {
                d.res.mvcc_checks += 1;
                const o = pr.snap.liveObject(&pr.id) orelse {
                    if (d.sim.crashed) {
                        // A crash after the acknowledgement (a deferred punch in the RCU poll
                        // swallows it): the commit stays, the probe is moot.
                        pr.snap.release();
                        try d.crashed();
                        if (!std.meta.eql(d.store.?.committed(), @as(?u64, cp.seq)))
                            return d.res.failf("after crash past ack: committed {?d}, expected {d}", .{ d.store.?.committed(), cp.seq });
                        try d.leanRecover();
                        return;
                    }
                    if (d.opts.debug) {
                        std.debug.print("probe v{d} seq {d}, committed {?d}\n", .{ pr.val.version, cp.seq, d.store.?.committed() });
                        pr.snap.debugChain(&pr.id);
                    }
                    pr.snap.release();
                    return d.res.failf("mvcc: old snapshot lost object", .{});
                };
                if (o.version != pr.val.version or !std.mem.eql(u8, o.bytes, pr.val.bytes)) d.res.failf("mvcc: old snapshot sees v{d}, expected v{d}", .{ o.version, pr.val.version });
                pr.snap.release();
            }
        } else |e| switch (e) {
            error.Crashed => {
                if (probe) |*pr| pr.snap.release();
                probe = null;
                try d.crashed();
                const got = d.store.?.committed();
                if (std.meta.eql(got, @as(?u64, cp.seq))) {
                    try d.model.apply(d.arena, cp);
                    d.res.in_flight_kept += 1;
                } else if (std.meta.eql(got, d.model.committed)) {
                    d.res.in_flight_lost += 1;
                } else return d.res.failf("after crash: committed {?d}, expected {?d} or {d}", .{ got, d.model.committed, cp.seq });
                try d.leanRecover();
                d.check(false);
            },
            else => {
                if (probe) |*pr| pr.snap.release();
                probe = null;
                if (!d.opts.io_faults or !ioFault(e)) return e;
                d.res.io_errors += 1;
                if (d.opts.debug) std.debug.print("io error {t} at seq {d}\n", .{ e, cp.seq });
                const retried = e != error.Poisoned and r.boolean() and blk: {
                    d.commitOne(cp) catch |e2| {
                        if (e2 != error.Crashed and !ioFault(e2)) return e2;
                        break :blk false;
                    };
                    break :blk true;
                };
                if (retried) {
                    try d.model.apply(d.arena, cp);
                    if (d.lean) |l| try l.ack();
                    d.res.commits += 1;
                    d.res.io_retried += 1;
                } else {
                    // The process dies on the error: the in-flight checkpoint may or may not
                    // have become durable, nothing before it may be lost.
                    try d.crashed();
                    const got = d.store.?.committed();
                    if (std.meta.eql(got, @as(?u64, cp.seq))) {
                        try d.model.apply(d.arena, cp);
                        d.res.in_flight_kept += 1;
                    } else if (std.meta.eql(got, d.model.committed)) {
                        d.res.in_flight_lost += 1;
                    } else return d.res.failf("after I/O error: committed {?d}, expected {?d} or {d}", .{ got, d.model.committed, cp.seq });
                    try d.leanRecover();
                    d.check(false);
                }
            },
        }
        if (!d.res.ok) return;

        // Steady mode: keep two epochs of history, pruned at every epoch change.
        if (d.opts.steady and d.model.cur_epoch != null) {
            const cur = d.model.cur_epoch.?;
            // A prune that crashed after moving the floor leaves aged segments behind; prune
            // again until they are gone, as the node's cleaning does between checkpoints
            // (several crashed prunes in a row would otherwise fill the 8 segment slots).
            const st = d.store.?;
            const leftover = st.aged.items.len > 0 and st.aged.items[0] < d.model.oldest;
            if ((d.last_prune_epoch != cur and cur >= 2 and cur - 2 > d.model.oldest) or leftover) {
                d.last_prune_epoch = cur;
                try d.prune(if (cur >= 2) @max(cur - 2, d.model.oldest) else d.model.oldest);
                if (!d.res.ok) return;
            }
        }
        if (d.opts.age) {
            if (r.uintLessThan(u8, 3) == 0) try d.moveFloors();
            if (!d.res.ok) return;
            // Live-set seeds: now and then the table's sequence counter moves as a deletion
            // moves it (cleaning deletes few entries in these runs), so table passes start
            // over and some finish inexact.
            if (d.opts.age_set and r.uintLessThan(u8, 6) == 0) if (d.store.?.live.raw) |h| {
                _ = h.t.seq.fetchAdd(2, .monotonic);
            };
            if (d.opts.age_defer) try d.ageGated() else if (r.uintLessThan(u8, 2) == 0) try d.ageSome(false);
            if (!d.res.ok) return;
        }
        // Occasional maintenance.
        const x = r.uintLessThan(u8, 40);
        if (x == 0 and d.model.cur_epoch != null) {
            const cur = d.model.cur_epoch.?;
            try d.prune(d.model.oldest + r.uintLessThan(u64, cur - d.model.oldest + 1));
        } else if (x == 1) {
            d.store.?.flushIndex() catch |e| switch (e) {
                error.Crashed => {
                    try d.crashed();
                    try d.leanRecover();
                },
                else => return e,
            };
        } else if (x == 2) {
            var crashed_close = false;
            d.store.?.close() catch |e| switch (e) {
                error.Crashed => {
                    d.res.crashes += 1;
                    d.sim.crash();
                    crashed_close = true;
                },
                else => return e,
            };
            d.store = null;
            d.res.reopens += 1;
            try d.reopen();
            if (crashed_close) try d.leanRecover() else try d.leanRead();
            d.check(false);
        }
    }

    /// The aged floor may move with the floors (ageOut): the model follows the store.
    fn followOldest(d: *Driver) void {
        const now = d.store.?.oldest_epoch.load(.monotonic);
        if (now > d.model.oldest) d.model.prune(d.arena, now);
    }

    /// The smallest committed checkpoint >= `seq`'s epoch (the current one past the tip).
    fn epochFrom(d: *Driver, seq: u64) u64 {
        var best: ?u64 = null;
        var ep: u64 = d.model.cur_epoch orelse 0;
        var it = d.model.cps.iterator();
        while (it.next()) |e| if (e.key_ptr.* >= seq and (best == null or e.key_ptr.* < best.?)) {
            best = e.key_ptr.*;
            ep = e.value_ptr.epoch;
        };
        return ep;
    }

    fn moveFloors(d: *Driver) !void {
        const r = d.rnd;
        const s = d.store.?;
        const c = d.model.committed orelse return;
        const cpb = s.cp_floor.load(.monotonic) -| 1;
        const obb = s.obj_floor.load(.monotonic) -| 1;
        const cp_p = @min(c, cpb + r.uintLessThan(u64, (c -| cpb) / 2 + 2));
        // sui-node keeps object versions no longer than checkpoints: mostly a higher floor.
        const ob_p = @min(c, @max(obb, cp_p) + r.uintLessThan(u64, (c -| @max(obb, cp_p)) / 2 + 2));
        const f: Store.Floors = .{ .cp_pruned = cp_p, .obj_pruned = ob_p, .cp_epoch = d.epochFrom(cp_p + 1), .obj_epoch = d.epochFrom(ob_p + 1) };
        if (d.opts.debug) std.debug.print("floors cp {d} obj {d} (epochs {d} {d})\n", .{ cp_p, ob_p, f.cp_epoch, f.obj_epoch });
        if (r.uintLessThan(u8, 5) == 0) d.sim.scheduleCrash(r.uintLessThan(u64, 8));
        if (s.setFloors(f)) |_| {
            d.sim.scheduleCrash(null);
            if (d.sim.crashed) {
                try d.crashed();
                d.followOldest();
                try d.leanRecover();
                d.check(false);
                return;
            }
            d.res.floor_moves += 1;
            d.followOldest();
            // Make them durable now and then (age-out frees only below durable floors).
            if (r.boolean()) s.flushIndex() catch |e| switch (e) {
                error.Crashed => {
                    try d.crashed();
                    d.followOldest();
                    try d.leanRecover();
                },
                else => return e,
            };
        } else |e| switch (e) {
            error.Crashed => {
                try d.crashed();
                d.followOldest();
                try d.leanRecover();
            },
            else => return e,
        }
        d.check(false);
    }

    /// Adds what the store's age counters gained since the last call (a reopened store starts
    /// at zero).
    fn noteAge(d: *Driver) void {
        const s = d.store orelse return;
        if (d.seen_store != s) {
            d.seen_store = s;
            d.seen = @splat(0);
        }
        const st = &s.age_stats;
        const now: [7]u64 = .{
            st.set_builds.load(.monotonic),   st.set_kept.load(.monotonic),    st.lookups.load(.monotonic), st.set_dead.load(.monotonic),
            st.set_restarts.load(.monotonic), st.set_inexact.load(.monotonic), st.set_misses.load(.monotonic),
        };
        // A reopened store can sit where the old one sat: counters that went down say so.
        for (now, d.seen) |x, y| if (x < y) {
            d.seen = @splat(0);
            break;
        };
        inline for (.{ "set_builds", "set_kept", "age_lookups", "set_dead", "set_restarts", "set_inexact", "set_misses" }, 0..) |name, i| {
            @field(d.res, name) += now[i] -| d.seen[i];
        }
        d.seen = now;
        if (d.res.set_misses != 0) d.res.failf("live set: {d} records with a clear bit in an exact set that the table still named", .{d.res.set_misses});
    }

    /// Live-set seeds, one in four: the table's sequence counter moves before every age step, so
    /// a table pass that takes several steps starts over three times and then finishes inexact
    /// (clear bits go back to lookups).
    fn moveSeq(d: *Driver) void {
        if (!d.opts.age_set or ((d.opts.seed *% 0x9e3779b97f4a7c15) >> 50) & 3 != 0) return;
        if (d.store.?.live.raw) |h| _ = h.t.seq.fetchAdd(2, .monotonic);
    }

    /// Deferral seeds: one visit of the ager thread's loop.
    fn ageGated(d: *Driver) !void {
        const r = d.rnd;
        if (r.uintLessThan(u8, 12) == 0) d.behind = !d.behind;
        const s = d.store.?;
        s.age_mode = .deferred;
        s.ageBehind(d.behind);
        switch (s.ageGate()) {
            .run => if (r.uintLessThan(u8, 2) == 0) try d.ageSome(false),
            .wait => {
                d.res.age_waits += 1;
                // The writer's cleaner does not wait for the ager.
                if (r.uintLessThan(u8, 6) == 0) try d.ageSome(true);
            },
            .bulk => try d.ageBulk(),
        }
    }

    /// A bulk catch-up: steps without the segment pass until one is idle, a crash scheduled
    /// inside half of them.
    fn ageBulk(d: *Driver) !void {
        const r = d.rnd;
        var held: ?store_mod.Snapshot = if (r.boolean()) d.store.?.snapshot() else null;
        if (r.boolean()) d.sim.scheduleCrash(r.uintLessThan(u64, 60));
        var steps: u32 = 0;
        while (true) : (steps += 1) {
            const s = d.store.?;
            d.moveSeq();
            if (steps > 1 << 14) {
                if (held) |*h| h.release();
                return d.res.failf("a bulk catch-up did not end in {d} steps", .{steps});
            }
            const rep = s.ageStepOpts(r.intRangeAtMost(u64, 4096, 1 << 20), .{ .skip_seg = true }) catch |e| switch (e) {
                error.Crashed => {
                    if (held) |*h| h.release();
                    d.res.age_bulk_crashes += 1;
                    try d.crashed();
                    d.followOldest();
                    try d.leanRecover();
                    d.check(false);
                    return;
                },
                else => {
                    if (held) |*h| h.release();
                    return e;
                },
            };
            d.res.age_steps += 1;
            d.res.age_dropped += rep.records_dropped;
            d.res.age_rewrites += rep.chunks_rewritten;
            d.noteAge();
            if (rep.idle) {
                s.ageBulkDone();
                break;
            }
        }
        d.sim.scheduleCrash(null);
        // A crash that landed in a deferred punch (reclaim cannot report it): recover now.
        if (d.sim.crashed) {
            if (held) |*h| h.release();
            held = null;
            d.res.age_bulk_crashes += 1;
            try d.crashed();
            d.followOldest();
            try d.leanRecover();
        } else d.res.age_bulks += 1;
        d.followOldest();
        if (held) |*h| {
            d.checkWith(false, h);
            h.release();
        }
        d.check(false);
    }

    /// `clean_only`: cleaning steps alone (the ager waits).
    fn ageSome(d: *Driver, clean_only: bool) !void {
        const r = d.rnd;
        var held: ?store_mod.Snapshot = if (r.boolean()) d.store.?.snapshot() else null;
        if (r.uintLessThan(u8, 3) == 0) d.sim.scheduleCrash(r.uintLessThan(u64, 40));
        const n = 1 + r.uintLessThan(u8, 4);
        for (0..n) |_| {
            const s = d.store.?;
            d.moveSeq();
            const res_step = if (clean_only or r.uintLessThan(u8, 6) == 0) s.cleanStep(r.intRangeAtMost(u64, 4096, 1 << 18)) else if (s.ageStep(r.intRangeAtMost(u64, 4096, 1 << 20))) |rep| blk: {
                d.res.age_steps += 1;
                d.res.age_dropped += rep.records_dropped;
                d.res.age_rewrites += rep.chunks_rewritten;
                d.noteAge();
                break :blk @as(store_mod.PruneReport, .{});
            } else |e| e;
            _ = res_step catch |e| switch (e) {
                error.Crashed => {
                    if (held) |*h| h.release();
                    held = null;
                    try d.crashed();
                    d.followOldest();
                    try d.leanRecover();
                    d.check(false);
                    return;
                },
                else => {
                    if (held) |*h| h.release();
                    return e;
                },
            };
        }
        d.sim.scheduleCrash(null);
        // A crash that landed in a deferred punch (reclaim cannot report it): recover now.
        if (d.sim.crashed) {
            if (held) |*h| h.release();
            held = null;
            try d.crashed();
            d.followOldest();
            try d.leanRecover();
        }
        d.followOldest();
        if (held) |*h| {
            // Taken before the steps: everything retained still reads through it.
            d.checkWith(false, h);
            h.release();
        }
        d.check(false);
    }

    fn prune(d: *Driver, target: u64) !void {
        const before = d.store.?.oldest_epoch.load(.monotonic);
        if (d.opts.debug) std.debug.print("prune {d} (cur {?d}, oldest {d})\n", .{ target, d.model.cur_epoch, d.model.oldest });
        // A crash the store could not report counts as a crash here too. `step` leaves its
        // crash scheduled after an acknowledged commit, and it can land in a deferred punch (the
        // RCU poll's reclaim swallows a punch's error), in the commit before this prune or in
        // the prune's own poll. The prune then returns success, and one with nothing to do
        // touches no file, so nothing noticed: the check below read a crashed disk and failed
        // the seed with "checkpoint N: Crashed" (store-dst agedefer/187 with the live set forced
        // on). The simulated process is dead either way: recover, then judge the floor.
        const crashed_now = if (d.store.?.pruneBefore(target)) |_| d.sim.crashed else |e| switch (e) {
            error.Crashed => true,
            else => return e,
        };
        if (!crashed_now) {
            if (target > d.model.oldest) d.model.prune(d.arena, target);
            d.res.prunes += 1;
            try d.leanRead();
        } else {
            try d.crashed();
            const now = d.store.?.oldest_epoch.load(.monotonic);
            if (now == target and target > before) d.model.prune(d.arena, target) else if (now != before) return d.res.failf("prune crash: oldest {d}, expected {d} or {d}", .{ now, before, target });
            try d.leanRecover();
        }
        d.check(false);
    }

    fn ioFault(e: anyerror) bool {
        return e == error.Io or e == error.NoSpace or e == error.ShortRead or e == error.Poisoned;
    }

    fn commitOne(d: *Driver, cp: *const ops.Checkpoint) !void {
        d.sim.io_armed = d.opts.io_faults;
        defer d.sim.io_armed = false;
        const s = d.store.?;
        const b = try s.begin(cp.seq, cp.epoch);
        ops.apply(b, cp) catch |e| {
            if (e != error.Crashed) s.abort(b);
            return e;
        };
        try s.commit(b);
    }
};

/// Heap bytes in use and their peak (memory diagnosis: ZUI_DST_MEM).
const Counting = struct {
    parent: std.mem.Allocator,
    cur: std.atomic.Value(usize) = .init(0),
    peak: std.atomic.Value(usize) = .init(0),
    largest: std.atomic.Value(usize) = .init(0),

    fn allocator(c: *Counting) std.mem.Allocator {
        return .{ .ptr = c, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn add(c: *Counting, n: usize) void {
        const now = c.cur.fetchAdd(n, .monotonic) + n;
        _ = c.peak.fetchMax(now, .monotonic);
        _ = c.largest.fetchMax(n, .monotonic);
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        const p = c.parent.rawAlloc(len, a, ra) orelse return null;
        c.add(len);
        return p;
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        if (!c.parent.rawResize(m, a, n, ra)) return false;
        _ = c.cur.fetchSub(m.len, .monotonic);
        c.add(n);
        return true;
    }
    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        const p = c.parent.rawRemap(m, a, n, ra) orelse return null;
        _ = c.cur.fetchSub(m.len, .monotonic);
        c.add(n);
        return p;
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.parent.rawFree(m, a, ra);
        _ = c.cur.fetchSub(m.len, .monotonic);
    }
};

/// Runs one seed. Errors are harness problems (out of memory); store misbehaviour is reported
/// in the result.
pub fn run(parent_gpa: std.mem.Allocator, opts: Options) !Result {
    var counting: Counting = .{ .parent = parent_gpa };
    const mem_diag = std.c.getenv("ZUI_DST_MEM") != null;
    const gpa = if (mem_diag) counting.allocator() else parent_gpa;
    var res: Result = .{};
    var prng: std.Random.DefaultPrng = .init(opts.seed);
    const rnd = prng.random();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const faults: sim_mod.Faults = .{
        .persist_256 = rnd.intRangeAtMost(u16, 0, 256),
        .torn_sectors = rnd.boolean(),
        .meta_persist_256 = rnd.intRangeAtMost(u16, 0, 256),
        // Swarm: each I/O error class on or off per seed, at a rate that hits a few per run.
        .read_error_ppm = if (opts.io_faults and rnd.boolean()) rnd.intRangeAtMost(u32, 500, 20_000) else 0,
        .write_error_ppm = if (opts.io_faults and rnd.boolean()) rnd.intRangeAtMost(u32, 500, 10_000) else 0,
        .sync_error_ppm = if (opts.io_faults and rnd.boolean()) rnd.intRangeAtMost(u32, 500, 20_000) else 0,
        .crash_garble_pending = opts.pending,
    };
    const sim = try SimIo.init(gpa, opts.seed ^ 0xd15c, faults, opts.file_cap);
    defer sim.deinit();
    const big = opts.corpus != null;
    const steady = opts.steady and !big;
    var cfg: store_mod.Config = if (steady) .{
        .max_live_objects = 64,
        .max_object_versions = 128,
        .max_transactions = 64,
        .max_checkpoints = 16,
        .max_batch_bytes = 3 << 20,
        .max_batch_objects = 512,
        .max_segments = 8,
        .index_flush_interval = rnd.intRangeAtMost(u64, 1, 16),
        .max_dirty_pages = rnd.intRangeAtMost(u64, 1, 8),
        .segment_reserve = 1 << 16,
        .seed = opts.seed | 1,
    } else .{
        .max_live_objects = if (big) 1 << 18 else 4096,
        .max_object_versions = if (big) 1 << 19 else 1 << 14,
        .max_transactions = if (big) 1 << 17 else 1 << 13,
        .max_checkpoints = 1 << 12,
        .max_batch_bytes = if (big) 32 << 20 else rnd.intRangeAtMost(usize, 1 << 20, 3 << 20),
        .max_batch_objects = if (big) 1 << 15 else 512,
        .max_segments = 256,
        .index_flush_interval = rnd.intRangeAtMost(u64, 2, 48),
        .segment_reserve = opts.file_cap,
        .seed = opts.seed | 1,
    };
    // Multi-chunk groups (several frames each), so a torn or garbled group can keep some.
    if (opts.tail or opts.pending or opts.misdir) cfg.chunk_bytes = rnd.intRangeAtMost(u32, 1 << 10, 16 << 10);
    if (opts.age and !steady) {
        cfg.chunk_bytes = rnd.intRangeAtMost(u32, 1 << 10, 32 << 10);
        cfg.age_lag_checkpoints = rnd.uintLessThan(u64, 6);
        cfg.age_pending_max = if (rnd.boolean()) 1 << 16 else rnd.intRangeAtMost(u64, 4, 64);
        cfg.age_whole_group_bytes = if (rnd.boolean()) 4 << 20 else rnd.intRangeAtMost(u64, 4096, 64 << 10);
        cfg.max_segments = 64;
        // A small decoded-chunk cache: the default 1 GiB filled up per seed (tiny chunks, every
        // group read by the age passes), 4 GiB resident each and the 16-job run past its 60 GiB
        // cap. Small also means evictions racing the rewrites' cache drops.
        // From the seed, not `rnd`: the seed's run stays the same draw for draw.
        cfg.cache_bytes = (1 + (opts.seed >> 3) % 16) << 20;
        if (std.c.getenv("ZUI_DST_CACHE_MB")) |v| cfg.cache_bytes = (std.fmt.parseInt(u64, std.mem.span(v), 10) catch 16) << 20;
        // The serial path unless the seed is a deferral seed: the read-ahead's reads would move
        // every `age` seed's draws. Deferral seeds hold back 16 KiB to 1 MiB (from the seed).
        cfg.age_serial = !(opts.age_defer or opts.age_set);
        if (opts.age_set) {
            cfg.age_live_set = true;
            cfg.age_set_bytes = @as(u64, 8) << @intCast(((opts.seed *% 0x9e3779b97f4a7c15) >> 44) % 9);
            // Half of them look every clear bit up as well: the cross-check of the set's proof.
            cfg.age_set_verify = ((opts.seed *% 0x9e3779b97f4a7c15) >> 54) & 1 == 1;
            // One in four (those whose sequence counter moves before every step, `moveSeq`):
            // two table pages a step, so every table pass is cut and ends inexact.
            if (((opts.seed *% 0x9e3779b97f4a7c15) >> 50) & 3 == 0) cfg.age_set_step_pages = 2;
        }
        if (opts.age_defer) cfg.age_defer_bytes = @as(u64, 16 << 10) << @intCast(((opts.seed *% 0x9e3779b97f4a7c15) >> 40) % 7);
        if (opts.live_set) {
            cfg.age_serial = false;
            if (!opts.age_set) {
                cfg.age_live_set = true;
                cfg.age_set_bytes = 1 << 16;
            }
            if (opts.set_verify) cfg.age_set_verify = true;
        }
    }
    // History dictionaries (chunk codec 3) small enough that every compressed seed cuts and
    // replaces several. From the seed, not `rnd`: every seed keeps its draws.
    cfg.dict_bytes = @intCast((8 + (opts.seed >> 4) % 33) << 10);
    cfg.dict_refresh_bytes = (16 + (opts.seed >> 7) % 113) << 10;
    // A/B for triage: ZUI_DST_DICTS=0 (codec 2 only), ZUI_DST_ELIDE=0 (codec 1 only).
    if (std.c.getenv("ZUI_DST_DICTS")) |v| if (v[0] == '0') {
        cfg.history_dicts = false;
    };
    if (std.c.getenv("ZUI_DST_ELIDE")) |v| if (v[0] == '0') {
        cfg.elide_sums = false;
    };
    var lean: Lean = .{ .gpa = gpa, .window = opts.lean_window };
    defer lean.deinit();
    var d: Driver = .{ .gpa = gpa, .arena = arena, .rnd = rnd, .sim = sim, .cfg = cfg, .res = &res, .opts = &opts, .lean = if (opts.lean) &lean else null };
    defer if (d.store) |s| s.deinit();
    try d.reopen();

    var gen = Gen.init(rnd);
    gen.churn = steady;
    var n: u32 = 0;
    while (n < opts.checkpoints and res.ok) : (n += 1) {
        const cp = if (opts.corpus) |c| (if (n < c.len) c[n] else break) else try gen.next(arena);
        try d.step(&cp);
        if (d.store) |s| {
            res.max_runs = @max(res.max_runs, s.totalRuns());
            res.max_live_slots = @max(res.max_live_slots, s.liveSlots().capacity);
        }
    }
    if (res.ok) {
        // Final crash with nothing in flight: must come back exactly.
        if (d.store) |s| s.deinit();
        d.store = null;
        sim.crash();
        try d.reopen();
        try d.leanRecover();
        d.check(false);
    }
    // Corruption is outside the Lean model (it assumes the hash chain holds).
    d.lean = null;
    if (opts.lean) {
        try lean.cuts.append(gpa, lean.out.items.len);
        res.lean_cuts = try lean.cuts.toOwnedSlice(gpa);
        res.lean_trace = try lean.out.toOwnedSlice(gpa);
        res.lean_events = lean.events;
        res.distinct_ids = lean.ids.items.len;
    }
    if (res.ok and opts.corruption) corrupt: {
        sim.faults.misdirect_ppm = 20_000;
        var k: u32 = 0;
        while (k < 6) : (k += 1) {
            const cp = if (opts.corpus != null) break else try gen.next(arena);
            d.commitOne(&cp) catch |e| switch (e) {
                error.Crashed => break,
                else => return e,
            };
            try d.model.apply(arena, &cp);
        }
        // Latent damage in segments a prune will drop: rot bytes of live records there (half
        // the time inside the object id, the field the carry-forward sweep matches on), then
        // prune. Pruning must never lose a live object silently: every live object that read
        // back intact before the prune reads back intact after it, or the prune fails.
        if (d.store) |s| if (res.ok) prune_rot: {
            const cur = s.currentEpoch() orelse break :prune_rot;
            const oldest = s.oldest_epoch.load(.monotonic);
            if (cur <= oldest) break :prune_rot;
            var lit = d.model.live.iterator();
            var rotted: u32 = 0;
            while (lit.next()) |e| {
                if (e.value_ptr.removed != null or rnd.uintLessThan(u8, 4) != 0) continue;
                const l = s.liveLocation(e.key_ptr) orelse continue;
                if (format_mod.epochOf(l) >= cur) continue;
                var nb: [64]u8 = undefined;
                const name = io_mod.segName(&nb, format_mod.epochOf(l));
                const rec_len = format_mod.header_len + @sizeOf(format_mod.ObjectFixed) + e.value_ptr.bytes.len;
                const at = if (rnd.boolean()) format_mod.header_len + rnd.uintLessThan(u64, 32) else rnd.uintLessThan(u64, rec_len);
                if (sim.rotAt(name, format_mod.offsetOf(l) + at)) rotted += 1;
                if (rotted >= 3) break;
            }
            if (rotted == 0) break :prune_rot;
            // Live objects that read back intact before the prune (the rest read as damaged).
            var intact: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
            defer intact.deinit(gpa);
            {
                var snap = s.snapshot();
                defer snap.release();
                var it = d.model.live.iterator();
                while (it.next()) |e| {
                    if (e.value_ptr.removed != null) continue;
                    const g = (snap.latest(e.key_ptr) catch continue) orelse continue;
                    switch (g) {
                        .live => |o| if (o.version == e.value_ptr.version and std.mem.eql(u8, o.bytes, e.value_ptr.bytes))
                            try intact.put(gpa, e.key_ptr.*, {}),
                        .removed => {},
                    }
                }
            }
            if (s.pruneBefore(cur)) |_| {
                res.rot_prunes += 1;
                var snap = s.snapshot();
                defer snap.release();
                var it = d.model.live.iterator();
                while (it.next()) |e| {
                    const v = e.value_ptr;
                    if (v.removed != null) continue;
                    const was_intact = intact.contains(e.key_ptr.*);
                    const g = snap.latest(e.key_ptr) catch |err| {
                        // Damage stays reported as damage; an intact object must stay intact.
                        if (was_intact or err != error.Corrupt) {
                            res.failf("prune over rot: live object v{d} now reads {s}", .{ v.version, @errorName(err) });
                            break;
                        }
                        continue;
                    };
                    const ok = if (g) |x| switch (x) {
                        .live => |o| o.version == v.version and std.mem.eql(u8, o.bytes, v.bytes),
                        .removed => false,
                    } else false;
                    if (!ok) {
                        res.failf("prune over rot: live object v{d} ({s}) lost silently", .{ v.version, if (was_intact) "intact" else "damaged" });
                        break;
                    }
                }
                d.model.prune(arena, cur);
            } else |e| switch (e) {
                error.Corrupt => res.rot_prunes_refused += 1,
                else => return e,
            }
        };
        if (!res.ok) break :corrupt;
        for (0..rnd.intRangeAtMost(usize, 1, 6)) |_| {
            const target = switch (rnd.uintLessThan(u8, 4)) {
                0 => "meta",
                1 => "index/",
                else => "seg/",
            };
            _ = sim.rot(target);
        }
        if (d.store) |s| s.deinit();
        d.store = null;
        sim.crash();
        sim.faults.misdirect_ppm = 0;
        const s = Store.open(gpa, .{ .sim = sim }, &cfg) catch |e| switch (e) {
            error.Corrupt => {
                res.open_refused = true;
                break :corrupt;
            },
            else => return e,
        };
        d.store = s;
        if (!std.meta.eql(s.committed(), d.model.committed)) res.rolled_back = true;
        d.check(true);
    }
    if (res.ok and opts.tail) try tailPhase(&d, &gen, &res);
    if (res.ok and opts.misdir) try misdirPhase(&d, &gen, &res);
    res.trace = sim.trace;
    res.sim = sim.stats;
    if (mem_diag) {
        const t = sim.touched();
        std.debug.print("dst mem seed {x}: sim files {d}, seg {d} MiB, side {d} MiB, age {d} MiB, other {d} MiB; arena {d} MiB; heap peak {d} MiB, largest {d} KiB\n", .{
            opts.seed,                      t.files,                                t.seg >> 20, t.side >> 20, t.age >> 20, t.other >> 20, arena_state.queryCapacity() >> 20,
            counting.peak.raw >> 20, counting.largest.raw >> 10,
        });
    }
    return res;
}

/// Tail seeds' end phase (see `Options.tail`).
fn tailPhase(d: *Driver, gen: *Gen, res: *Result) !void {
    const rnd = d.rnd;
    const sim = d.sim;
    var s = d.store.?;
    const before = d.model.committed;
    // Every index durable before the group: then only the dir file can prove it was written
    // whole (a live table or run past it also would, and recovery refuses on those too). The
    // group's own commit does not flush (index_flush_interval >= 2 here).
    try s.flushIndex();
    const cp_a = try gen.next(d.arena);
    try d.commitOne(&cp_a);
    try d.model.apply(d.arena, &cp_a);
    const tg = s.tailGroup() orelse return;
    var mode = rnd.uintLessThan(u8, 4);
    if (mode == 2 and !tg.compressed) mode = 3;
    res.tail_mode = mode;
    if (mode == 0) {
        const cp_b = try gen.next(d.arena);
        try d.commitOne(&cp_b);
        try d.model.apply(d.arena, &cp_b);
    }
    if (mode == 2) try s.syncDirs();
    var nb: [64]u8 = undefined;
    const name = io_mod.segName(&nb, tg.epoch);
    const span = tg.phys_end - tg.phys;
    if (span == 0) return;
    s.deinit();
    d.store = null;
    sim.crash();
    if (mode == 1) {
        // A lost sector of the group's write (what a torn write leaves), anywhere in it.
        const at = tg.phys + rnd.uintLessThan(u64, span);
        const len = @min(512 - at % 512, tg.phys_end - at);
        _ = sim.zeroAt(name, at, len);
    } else _ = sim.rotAt(name, tg.phys + rnd.uintLessThan(u64, span));
    // The oracle's own reading of the dir file: does its trusted prefix name the group?
    const proof = try dirProofEnd(d, tg.epoch);
    const proven = tg.compressed and proof > tg.ls;
    if (d.opts.debug) std.debug.print("tail mode {d}: dir proof {d}, group ls {d}\n", .{ mode, proof, tg.ls });
    if (d.opts.debug) std.debug.print("tail mode {d}: group e {d} phys {d}..{d} ({s})\n", .{ mode, tg.epoch, tg.phys, tg.phys_end, if (tg.compressed) "compressed" else "raw" });
    const st = Store.open(d.gpa, .{ .sim = sim }, &d.cfg) catch |e| switch (e) {
        error.Corrupt => {
            res.open_refused = true;
            if (mode != 0 and !proven) res.failf("tail mode {d}: damaged newest group with nothing durable after it refused with Corrupt (torn tail)", .{mode});
            return;
        },
        else => return e,
    };
    d.store = st;
    const got = st.committed();
    if (!std.meta.eql(got, d.model.committed)) {
        res.rolled_back = true;
        res.tail_truncated = true;
        if (mode == 0 or proven) return res.failf("tail mode {d}: acknowledged group truncated (committed {?d}, model {?d}, dir proof {d}, group at {d})", .{ mode, got, d.model.committed, proof, tg.ls });
        if (!std.meta.eql(got, before)) return res.failf("tail mode {d}: committed {?d}, expected {?d} or {?d}", .{ mode, got, before, d.model.committed });
    }
    d.check(true);
}

/// End of the trusted prefix of segment `e`'s dir file, read straight from the sim disk.
fn dirProofEnd(d: *Driver, e: u64) !u64 {
    var nb: [64]u8 = undefined;
    const name = std.fmt.bufPrint(&nb, "index/{d:0>8}.dir", .{e}) catch unreachable;
    var sb: [64]u8 = undefined;
    const seg = io_mod.segName(&sb, e);
    const sfd = d.sim.openFile(seg, false) catch return 0;
    defer d.sim.closeFile(sfd);
    const fd = d.sim.openFile(name, false) catch return 0;
    defer d.sim.closeFile(fd);
    const img = try d.gpa.alloc(u8, try d.sim.size(fd));
    defer d.gpa.free(img);
    try d.sim.read(fd, 0, img);
    var ents: std.ArrayList(chunk_mod.Entry) = .empty;
    defer ents.deinit(d.gpa);
    _ = try chunk_mod.trustedPrefix(img, e, try d.sim.size(sfd), &ents, d.gpa);
    return if (ents.items.len == 0) 0 else ents.items[ents.items.len - 1].end();
}

/// Misdirection seeds' end phase (see `Options.misdir`): up to three rounds, each a few
/// commits and index flushes with misdirection armed, a close or a crash, then an open (armed
/// too: recovery's own writes can land elsewhere) checked as corruption seeds are.
fn misdirPhase(d: *Driver, gen: *Gen, res: *Result) !void {
    const rnd = d.rnd;
    const sim = d.sim;
    var round: u32 = 0;
    while (round < 3 and res.ok) : (round += 1) {
        sim.faults.misdirect_write_ppm = rnd.intRangeAtMost(u32, 2_000, 60_000);
        const mis0 = sim.stats.misdirected_writes + sim.stats.misdirect_seg_blocks;
        var k: u32 = 0;
        var crashed = false;
        while (k < 6) : (k += 1) {
            const cp = try gen.next(d.arena);
            d.commitOne(&cp) catch |e| switch (e) {
                error.Crashed => {
                    crashed = true;
                    break;
                },
                else => return e,
            };
            try d.model.apply(d.arena, &cp);
            if (rnd.uintLessThan(u8, 3) == 0) d.store.?.flushIndex() catch |e| switch (e) {
                error.Crashed => {
                    crashed = true;
                    break;
                },
                else => return e,
            };
        }
        if (d.store) |s| {
            if (!crashed and rnd.boolean()) s.close() catch {} else s.deinit();
        }
        d.store = null;
        sim.crash();
        const st = Store.open(d.gpa, .{ .sim = sim }, &d.cfg) catch |e| switch (e) {
            error.Corrupt => {
                sim.faults.misdirect_write_ppm = 0;
                res.open_refused = true;
                return;
            },
            error.Crashed => {
                sim.faults.misdirect_write_ppm = 0;
                sim.crash();
                continue;
            },
            else => return e,
        };
        sim.faults.misdirect_write_ppm = 0;
        d.store = st;
        if (!std.meta.eql(st.committed(), d.model.committed)) {
            res.rolled_back = true;
            // A misdirected write loses the group it held and damages the groups it lands on
            // (one per block it covers, plus one): a deeper rollback dropped acknowledged groups
            // whose bytes are intact.
            var lost: u64 = 0;
            var it = d.model.cps.keyIterator();
            while (it.next()) |q| if (st.committed() == null or q.* > st.committed().?) {
                lost += 1;
            };
            const mis = sim.stats.misdirected_writes + sim.stats.misdirect_seg_blocks - mis0;
            if (lost > mis) return res.failf("misdir: {d} acknowledged checkpoints rolled back, at most {d} damaged by misdirected writes", .{ lost, mis });
        }
        d.check(true);
        // The model follows the store from here (what it lost is gone).
        if (res.rolled_back) return;
    }
}

test "dst: synthetic seeds, crash safety" {
    var seed: u64 = 1;
    while (seed <= 24) : (seed += 1) {
        const r = try run(std.testing.allocator, .{ .seed = seed, .checkpoints = 80 });
        if (!r.ok) {
            std.debug.print("seed {d}: {s}\n", .{ seed, r.msg() });
            return error.TestUnexpectedResult;
        }
    }
}

test "dst: corruption seeds never return wrong data" {
    var seed: u64 = 1000;
    while (seed < 1012) : (seed += 1) {
        const r = try run(std.testing.allocator, .{ .seed = seed, .checkpoints = 60, .corruption = true });
        if (!r.ok) {
            std.debug.print("seed {d}: {s}\n", .{ seed, r.msg() });
            return error.TestUnexpectedResult;
        }
    }
}

test "dst: age-out seeds (floors, holes, punches, crashes inside steps)" {
    var seed: u64 = 3000;
    var dropped: u64 = 0;
    var rewrites: u64 = 0;
    while (seed < 3024) : (seed += 1) {
        const r = run(std.testing.allocator, .{ .seed = seed, .checkpoints = 160, .age = true }) catch |e| {
            std.debug.print("age seed {d}: error {s}\n", .{ seed, @errorName(e) });
            return e;
        };
        if (!r.ok) {
            std.debug.print("seed {d}: {s}\n", .{ seed, r.msg() });
            return error.TestUnexpectedResult;
        }
        dropped += r.age_dropped;
        rewrites += r.age_rewrites;
    }
    std.debug.print("age dst: {d} records dropped, {d} chunks rewritten\n", .{ dropped, rewrites });
    try std.testing.expect(dropped > 0 and rewrites > 0);
}

test "dst: deferred age-out seeds (waits, bulk catch-ups, read-ahead before every step, crashes inside)" {
    var seed: u64 = 5000;
    var tot: Result = .{};
    while (seed < 5024) : (seed += 1) {
        const r = run(std.testing.allocator, .{ .seed = seed, .checkpoints = 160, .age = true, .age_defer = true }) catch |e| {
            std.debug.print("deferred age seed {d}: error {s}\n", .{ seed, @errorName(e) });
            return e;
        };
        if (!r.ok) {
            std.debug.print("seed {d}: {s}\n", .{ seed, r.msg() });
            return error.TestUnexpectedResult;
        }
        inline for (.{ "age_dropped", "age_rewrites", "age_waits", "age_bulks", "age_bulk_crashes", "age_steps", "crashes" }) |name| @field(tot, name) += @field(r, name);
    }
    std.debug.print("deferred age dst: {d} waits, {d} bulk catch-ups ({d} more cut by a crash), {d} steps, {d} records dropped, {d} chunks rewritten, {d} crashes\n", .{
        tot.age_waits, tot.age_bulks, tot.age_bulk_crashes, tot.age_steps, tot.age_dropped, tot.age_rewrites, tot.crashes,
    });
    try std.testing.expect(tot.age_dropped > 0 and tot.age_rewrites > 0);
    try std.testing.expect(tot.age_waits > 0 and tot.age_bulks > 0 and tot.age_bulk_crashes > 0);
}

test "dst: live-set segment pass seeds (table passes cut by commits, cleaning and crashes; with and without deferral)" {
    var seed: u64 = 7000;
    var tot: Result = .{};
    while (seed < 7024) : (seed += 1) {
        const r = run(std.testing.allocator, .{ .seed = seed, .checkpoints = 160, .age = true, .age_set = true, .age_defer = seed % 2 == 1 }) catch |e| {
            std.debug.print("live-set age seed {d}: error {s}\n", .{ seed, @errorName(e) });
            return e;
        };
        if (!r.ok) {
            std.debug.print("seed {d}: {s}\n", .{ seed, r.msg() });
            return error.TestUnexpectedResult;
        }
        inline for (.{ "age_dropped", "age_rewrites", "age_steps", "crashes", "set_builds", "set_kept", "age_lookups", "set_dead", "set_restarts", "set_inexact", "set_misses" }) |name| @field(tot, name) += @field(r, name);
    }
    std.debug.print("live-set age dst: {d} table passes ({d} started over, {d} inexact), {d} records kept without a lookup, {d} judged dead without one, {d} lookups, {d} misses, {d} steps, {d} records dropped, {d} chunks rewritten, {d} crashes\n", .{
        tot.set_builds, tot.set_restarts, tot.set_inexact, tot.set_kept, tot.set_dead, tot.age_lookups, tot.set_misses, tot.age_steps, tot.age_dropped, tot.age_rewrites, tot.crashes,
    });
    try std.testing.expect(tot.age_dropped > 0 and tot.age_rewrites > 0 and tot.crashes > 0);
    try std.testing.expect(tot.set_builds > 24 and tot.set_kept > 0 and tot.set_dead > 0);
    try std.testing.expect(tot.set_restarts > 0 and tot.set_inexact > 0);
    try std.testing.expectEqual(@as(u64, 0), tot.set_misses);
}

test "dst driver: a crash swallowed by a deferred punch is a crash for a prune that has nothing to do" {
    const gpa = std.testing.allocator;
    var res: Result = .{};
    var prng: std.Random.DefaultPrng = .init(11);
    const rnd = prng.random();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const opts: Options = .{ .seed = 11, .file_cap = 8 << 20 };
    const sim = try SimIo.init(gpa, 11, .{ .torn_sectors = false }, opts.file_cap);
    defer sim.deinit();
    const cfg: store_mod.Config = .{
        .max_live_objects = 4096,
        .max_object_versions = 1 << 14,
        .max_transactions = 1 << 13,
        .max_checkpoints = 1 << 12,
        .max_batch_bytes = 1 << 20,
        .max_batch_objects = 512,
        .max_segments = 256,
        .index_flush_interval = 8,
        .segment_reserve = opts.file_cap,
        .seed = 11,
    };
    var d: Driver = .{ .gpa = gpa, .arena = arena, .rnd = rnd, .sim = sim, .cfg = cfg, .res = &res, .opts = &opts };
    defer if (d.store) |s| s.deinit();
    try d.reopen();
    var gen = Gen.init(rnd);
    for (0..12) |_| {
        const cp = try gen.next(arena);
        try d.step(&cp);
        try std.testing.expect(res.ok);
    }
    // Whatever `step` left scheduled is dropped; then the disk crashes inside an operation
    // whose error is swallowed, as the reclaim swallows a punch's: nobody is told.
    d.sim.scheduleCrash(null);
    if (d.sim.crashed) try d.crashed();
    d.sim.scheduleCrash(0);
    d.sim.syncDir() catch {};
    try std.testing.expect(d.sim.crashed);
    const crashes = res.crashes;
    // Nothing to prune: the store touches no file and reports success.
    try d.prune(d.model.oldest);
    if (!res.ok) std.debug.print("prune after a swallowed crash: {s}\n", .{res.msg()});
    try std.testing.expect(res.ok);
    try std.testing.expectEqual(crashes + 1, res.crashes);
    try std.testing.expect(!d.sim.crashed);
}

test "dst: store-dst agedefer/187 with the live set forced on (a crash in a deferred punch, then a prune with nothing to do)" {
    // The seed as store-dst derives it (conformance.zig `runSeed`), with `--live-set`.
    const seed = (@as(u64, 187) *% 0x9e3779b97f4a7c15 ^ 0x5eed_0001) ^ 0xdefe;
    for ([_]bool{ false, true }) |verify| {
        const r = try run(std.testing.allocator, .{ .seed = seed, .checkpoints = 240, .age = true, .age_defer = true, .live_set = true, .set_verify = verify });
        if (!r.ok) std.debug.print("agedefer/187 (verify {}): {s}\n", .{ verify, r.msg() });
        try std.testing.expect(r.ok);
        try std.testing.expect(r.set_builds > 0 and r.crashes >= 3);
        try std.testing.expectEqual(@as(u64, 0), r.set_misses);
    }
}

test "dst: a seed replays bit for bit" {
    const a = try run(std.testing.allocator, .{ .seed = 77, .checkpoints = 60 });
    const b = try run(std.testing.allocator, .{ .seed = 77, .checkpoints = 60 });
    try std.testing.expect(a.ok and b.ok);
    try std.testing.expectEqual(a.trace, b.trace);
    try std.testing.expectEqual(a.crashes, b.crashes);
    try std.testing.expectEqual(a.reads_checked, b.reads_checked);
}

test "dst: steady state under tight limits, with a Lean trace" {
    var seed: u64 = 500;
    while (seed < 503) : (seed += 1) {
        // 4000 checkpoints: the smallest live table (16 pages) has 3,264 slots since slots are
        // 20 bytes (2,032 before), and about 1.3 distinct ids pass per checkpoint.
        const r = try run(std.testing.allocator, .{ .seed = seed, .checkpoints = 4000, .steady = true, .lean = true, .lean_window = 200 });
        defer if (r.lean_trace) |t| std.testing.allocator.free(t);
        defer if (r.lean_cuts) |t| std.testing.allocator.free(t);
        if (!r.ok) {
            std.debug.print("seed {d}: {s}\n", .{ seed, r.msg() });
            return error.TestUnexpectedResult;
        }
        try std.testing.expect(r.lean_cuts.?.len >= 9);
        try std.testing.expect(r.prunes > 50);
        // More distinct ids than the live table has slots: it must reclaim tombstone slots
        // (pruned) rather than grow with history.
        try std.testing.expect(r.distinct_ids > r.max_live_slots);
        try std.testing.expect(r.max_runs <= 3 * 8);
        try std.testing.expect(r.lean_events > 2000);
    }
}

test "dst: I/O error seeds lose nothing acknowledged" {
    var seed: u64 = 3000;
    var errors: u64 = 0;
    var failed: u32 = 0;
    while (seed < 3024) : (seed += 1) {
        const r = run(std.testing.allocator, .{ .seed = seed, .checkpoints = 60, .io_faults = true }) catch |e| {
            std.debug.print("io seed {d}: error {t}\n", .{ seed, e });
            failed += 1;
            continue;
        };
        if (!r.ok) {
            std.debug.print("io seed {d}: {s}\n", .{ seed, r.msg() });
            failed += 1;
        }
        errors += r.io_errors;
    }
    try std.testing.expectEqual(@as(u32, 0), failed);
    try std.testing.expect(errors > 0);
}

test "dst: io/196 (an EIO in an aged segment during a live-table rebuild) loses nothing" {
    const r = try run(std.testing.allocator, .{ .seed = @as(u64, 196) *% 0x9e3779b97f4a7c15 ^ 0x5eed_0001 ^ 0x10e, .io_faults = true, .lean = true });
    defer if (r.lean_trace) |t| std.testing.allocator.free(t);
    defer if (r.lean_cuts) |t| std.testing.allocator.free(t);
    if (!r.ok) std.debug.print("io/196: {s}\n", .{r.msg()});
    try std.testing.expect(r.ok);
}
