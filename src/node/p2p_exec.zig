//! Local execution of a certified checkpoint whose contents came over p2p state sync
//! (p2p.zig): every transaction runs on deepwave's executors against the node's store, and the
//! result is a checkpoint blob (`0x01 ++ BCS(CheckpointData)`) plus its aux record, the same
//! shape the bucket and the stream produce.
//!
//! Inputs. Peers send the certified summary and, per transaction, the signed transaction and its
//! certified effects (`ExecutionData`). Output objects and events are not sent: deepwave computes
//! them. Input objects come from the store (the checkpoint before this one is committed, so its
//! live set is the pre-state) overlaid with the writes of the checkpoint's earlier transactions.
//!
//! Trust. Nothing here is trusted by the store. A transaction is accepted only when deepwave's
//! effects bytes equal the certified effects bytes (whose digest the contents carry) and its
//! events hash to the effects' events digest; the follower then verifies the whole blob like any
//! other source (contents digest, transaction/effects/events digests, every output object's
//! digest against the effects, the BLS certificate, the chain link). A transaction deepwave cannot
//! execute or whose result differs makes the whole checkpoint fall back to the other sources.
const std = @import("std");
const bcs = @import("bcs");
const hash = @import("hash");
const types = @import("types");
const protocol = @import("protocol");
const store = @import("store");
const exec = @import("exec");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const ptb = exec.ptb;
const system = exec.system;

/// `chain`: the network followed (protocol table and `ProtocolConfig.chain`).
pub const Params = struct { pv: u64, rgp: u64, start_ms: u64, chain: protocol.Chain = .mainnet };

/// One transaction as a peer sends it.
pub const ExecData = struct {
    /// BCS `SenderSignedData` (the blob's transaction bytes).
    tx: []const u8,
    /// BCS `TransactionEffects` (certified through the contents).
    effects: []const u8,
};

pub const Result = union(enum) {
    /// The blob and aux record, in the arena, and the checkpoint's writes (for `parent`).
    ok: struct { blob: []const u8, aux: []const u8, layer: Layer },
    /// Why the checkpoint falls back (a static string or arena text).
    fallback: []const u8,
};

/// The writes of a whole built checkpoint (in its arena): the next checkpoint can run on top of
/// it before this one is committed (`run`'s `parent`). Only a checkpoint whose every effects
/// equal the certified effects becomes a layer, and the next one uses it only if its summary's
/// previous digest names this checkpoint's summary.
pub const Layer = struct {
    at: std.AutoHashMapUnmanaged(Key, []const u8) = .empty,
    live: std.AutoHashMapUnmanaged(Id, ?[]const u8) = .empty,
};

const Key = struct { id: Id, version: u64 };

/// Writes of the checkpoint's earlier transactions over the store snapshot.
const Overlay = struct {
    at: std.AutoHashMapUnmanaged(Key, []const u8) = .empty,
    /// id -> newest bytes, or null when an earlier transaction deleted or wrapped it.
    live: std.AutoHashMapUnmanaged(Id, ?[]const u8) = .empty,
    /// The previous checkpoint's writes while it is built but not yet committed.
    parent: ?*const Layer = null,
    snap: *const store.Snapshot,
    /// Objects read through `get` (the blob's input objects and aux extras come from here).
    reads: std.AutoArrayHashMapUnmanaged(Key, []const u8) = .empty,
    arena: Allocator,

    fn self(p: *const anyopaque) *Overlay {
        return @ptrCast(@alignCast(@constCast(p)));
    }

    fn getAt(o: *Overlay, id: *const Id, version: u64) ?[]const u8 {
        if (o.at.get(.{ .id = id.*, .version = version })) |b| return b;
        const raw = (if (o.parent) |l| l.at.get(.{ .id = id.*, .version = version }) else null) orelse
            o.snap.objectAt(id, version) orelse return null;
        o.reads.put(o.arena, .{ .id = id.*, .version = version }, raw) catch {};
        return raw;
    }

    fn latestOf(o: *Overlay, id: *const Id) ?[]const u8 {
        if (o.live.get(id.*)) |v| return v;
        if (o.parent) |l| if (l.live.get(id.*)) |v| return v;
        const r = o.snap.liveObject(id) orelse return null;
        return r.bytes;
    }

    fn get(p: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        return self(p).getAt(id, version);
    }

    fn latest(p: *const anyopaque, id: *const Id) ?[]const u8 {
        return self(p).latestOf(id);
    }

    fn childAtMost(p: *const anyopaque, id: *const Id, upper: u64) ?[]const u8 {
        const o = self(p);
        const raw = o.latestOf(id) orelse return null;
        const v = exec.objects.ObjectView.parse(raw) catch return null;
        if (v.version > upper) return null;
        return raw;
    }

    fn sharedLatest(p: *const anyopaque, id: *const Id) ?u64 {
        const raw = self(p).latestOf(id) orelse return null;
        const v = exec.objects.ObjectView.parse(raw) catch return null;
        return v.version;
    }

    fn noBalance(_: *const anyopaque, _: *const Id, _: *const types.TypeTag) ?u128 {
        return null;
    }

    fn sysChild(p: *const anyopaque, _: *const Id, id: *const Id, bound: u64) error{NotAvailable}!?[]const u8 {
        return childAtMost(p, id, bound);
    }

    fn sysPackage(p: *const anyopaque, id: *const Id) ?[]const u8 {
        return latest(p, id);
    }

    const pre_vtable: ptb.PreState.VTable = .{ .shared_latest = sharedLatest, .child_at_most = childAtMost, .address_balance = noBalance };

    /// `apply` with the bytes copied into the overlay's arena (they come from a worker's arena).
    fn applyCopy(o: *Overlay, written: []const exec.coin_ptb.Written, fx: *const types.TransactionEffectsV2, v1: ?*const types.TransactionEffectsV1) !void {
        const w = try o.arena.alloc(exec.coin_ptb.Written, written.len);
        for (written, w) |x, *y| y.* = .{ .id = x.id, .bytes = try o.arena.dupe(u8, x.bytes) };
        return o.apply(w, fx, v1);
    }

    fn apply(o: *Overlay, written: []const exec.coin_ptb.Written, fx: *const types.TransactionEffectsV2, v1: ?*const types.TransactionEffectsV1) !void {
        for (written) |w| {
            const v = try exec.objects.ObjectView.parse(w.bytes);
            try o.at.put(o.arena, .{ .id = w.id, .version = v.version }, w.bytes);
            try o.live.put(o.arena, w.id, w.bytes);
        }
        // V1 effects (the driver's V2 view has no output states): deleted, wrapped and
        // unwrapped-then-deleted leave the live set
        if (v1) |v| {
            inline for (.{ "deleted", "wrapped", "unwrapped_then_deleted" }) |list| {
                for (@field(v, list)) |r| try o.live.put(o.arena, r[0].@"0".@"0", null);
            }
            return;
        }
        for (fx.changed_objects) |c| switch (c[1].output_state) {
            .NotExist => try o.live.put(o.arena, c[0].@"0".@"0", null),
            else => {},
        };
    }
};

/// Package source over the store and the overlay (packages published earlier in the checkpoint).
/// The package bytes are copied into `keep`: exec's per-thread package caches hold them for the
/// whole epoch, past the checkpoint's arena and the store snapshot.
pub const PackageSource = struct {
    pkgs: exec.packages.Store = .{},
    overlay: ?*const Overlay = null,
    snap: ?*const store.Snapshot = null,
    keep: std.heap.ArenaAllocator,
    lock: std.atomic.Mutex = .unlocked,

    fn get(p: *const anyopaque, id: *const Id, epoch: u64) ?[]const u8 {
        _ = epoch;
        const s: *PackageSource = @ptrCast(@alignCast(@constCast(p)));
        const raw = (if (s.overlay) |o| Overlay.latest(o, id) else blk: {
            const snap = s.snap orelse return null;
            const r = snap.liveObject(id) orelse return null;
            break :blk @as(?[]const u8, r.bytes);
        }) orelse return null;
        while (!s.lock.tryLock()) std.atomic.spinLoopHint();
        defer s.lock.unlock();
        return s.keep.allocator().dupe(u8, raw) catch null;
    }

    pub fn bind(s: *PackageSource) void {
        s.pkgs.lookup = .{ .ctx = s, .get = get };
    }
};

/// The checkpoint's earlier transactions' object-balance withdrawals since the last accumulator
/// root settlement (replay.zig's `Unsettled`, over certified effects).
const Unsettled = struct {
    effects: []const *const types.TransactionEffectsV2,

    fn get(p: *const anyopaque, arena: Allocator, field: *const [32]u8) anyerror!u128 {
        _ = arena;
        const u: *const Unsettled = @ptrCast(@alignCast(p));
        var root: [32]u8 = @splat(0);
        root[30] = 0x0a;
        root[31] = 0xcc;
        var sum: u128 = 0;
        for (u.effects) |fx| for (fx.changed_objects) |*c| {
            if (std.mem.eql(u8, &c[0].@"0".@"0", &root) and c[1].output_state == .ObjectWrite) sum = 0;
            if (!std.mem.eql(u8, &c[0].@"0".@"0", field)) continue;
            switch (c[1].output_state) {
                .AccumulatorWriteV1 => |*w| if (w.operation == .Split) switch (w.value) {
                    .Integer => |v| sum += v,
                    else => return error.Unsupported,
                },
                else => {},
            }
        };
        return sum;
    }
};

pub const Stats = struct {
    txs: u64 = 0,
    ccp: u64 = 0,
    system: u64 = 0,
    coin: u64 = 0,
    move: u64 = 0,
};

fn putUleb(out: *std.ArrayList(u8), a: Allocator, v: u64) !void {
    var x = v;
    while (true) {
        const b: u8 = @intCast(x & 0x7f);
        x >>= 7;
        if (x == 0) {
            try out.append(a, b);
            return;
        }
        try out.append(a, b | 0x80);
    }
}

/// The `TransactionData` bytes inside a `SenderSignedData` (`[1] ++ intent(3) ++ data ++ sigs`).
pub fn txDataOf(tx: []const u8) ![]const u8 {
    if (tx.len < 4 or tx[0] != 1) return error.Malformed;
    var r = bcs.Reader.init(tx[4..]);
    try bcs.skip(types.TransactionData, &r);
    return tx[4..][0..r.pos()];
}

/// Workers for `run`: the transactions of one dependency level execute on several threads.
/// Levels come from the certified effects: a transaction runs after every earlier transaction
/// that wrote an object it reads or writes (read after write), and never before an earlier
/// reader of an object it writes (write after read: a level's writes are applied in transaction
/// order only once the whole level is done, so readers in the same level see the old version).
/// System and prologue transactions and package publishes are barriers. A read the effects do
/// not declare (an unchanged dynamic field, a package published earlier in the checkpoint) can
/// still see the wrong version; the effects then differ and the checkpoint is run again in order.
pub const Pool = struct {
    gpa: Allocator,
    io: std.Io,
    threads: []std.Thread = &.{},
    /// Per worker (0: the calling thread), reset at the start of each checkpoint.
    arenas: []std.heap.ArenaAllocator = &.{},
    gen: std.atomic.Value(u32) = .init(0),
    finished: std.atomic.Value(u32) = .init(0),
    next: std.atomic.Value(u32) = .init(0),
    stopping: std.atomic.Value(bool) = .init(false),
    level: []const u32 = &.{},
    job: ?*Run = null,
    /// Checkpoints run again in order after a parallel run differed.
    reruns: std.atomic.Value(u64) = .init(0),

    /// `n` threads in all (1: serial).
    pub fn start(p: *Pool, n: usize) !void {
        const w = @max(n, 1);
        p.arenas = try p.gpa.alloc(std.heap.ArenaAllocator, w);
        for (p.arenas) |*a| a.* = .init(p.gpa);
        p.threads = try p.gpa.alloc(std.Thread, w - 1);
        for (p.threads, 1..) |*t, i| t.* = try std.Thread.spawn(.{ .stack_size = 64 << 20 }, worker, .{ p, i });
    }

    pub fn stop(p: *Pool) void {
        p.stopping.store(true, .release);
        _ = p.gen.fetchAdd(1, .release);
        p.io.futexWake(u32, &p.gen.raw, std.math.maxInt(u32));
        for (p.threads) |t| t.join();
        for (p.arenas) |*a| a.deinit();
        p.gpa.free(p.threads);
        p.gpa.free(p.arenas);
    }

    fn worker(p: *Pool, w: usize) void {
        var seen: u32 = 0;
        while (true) {
            p.io.futexWait(u32, &p.gen.raw, seen) catch {};
            if (p.stopping.load(.acquire)) return;
            const g = p.gen.load(.acquire);
            if (g == seen) continue;
            seen = g;
            p.drain(w);
            _ = p.finished.fetchAdd(1, .acq_rel);
            p.io.futexWake(u32, &p.finished.raw, 1);
        }
    }

    fn drain(p: *Pool, w: usize) void {
        const r = p.job.?;
        while (true) {
            const k = p.next.fetchAdd(1, .monotonic);
            if (k >= p.level.len) return;
            const i = p.level[k];
            r.outs[i] = r.execTx(p.arenas[w].allocator(), i);
        }
    }

    fn runLevel(p: *Pool, r: *Run, level: []const u32, arena0: Allocator) void {
        if (level.len == 1 or p.threads.len == 0) {
            for (level) |i| r.outs[i] = r.execTx(arena0, i);
            return;
        }
        p.job = r;
        p.level = level;
        p.next.store(0, .monotonic);
        p.finished.store(0, .monotonic);
        _ = p.gen.fetchAdd(1, .release);
        p.io.futexWake(u32, &p.gen.raw, std.math.maxInt(u32));
        p.drain(0);
        while (true) {
            const f = p.finished.load(.acquire);
            if (f == p.threads.len) break;
            p.io.futexWait(u32, &p.finished.raw, f) catch {};
        }
    }
};

const TxKind = enum { ccp, system, coin, move };

/// One transaction's result (in the arena of the thread that ran it).
const TxOut = struct {
    fallback: ?[]const u8 = null,
    effects: []const u8 = &.{},
    events: ?[]const u8 = null,
    written: []const exec.coin_ptb.Written = &.{},
    loaded: []const ptb.Ref = &.{},
    /// Objects it read below the checkpoint (store or parent), in order (merged into the aux
    /// record in transaction order).
    reads: []const Key = &.{},
    read_bytes: []const []const u8 = &.{},
    kind: TxKind = .move,
};

/// One checkpoint's execution state shared by the workers (read-only during a level).
const Run = struct {
    gpa: Allocator,
    cfg: *const protocol.ProtocolConfig,
    params: Params,
    epoch: u64,
    pkg_src: *PackageSource,
    master: *Overlay,
    txs: []const ExecData,
    tx_raw: []const []const u8,
    data: []const *const types.TransactionDataV1,
    fx: []const *const types.TransactionEffectsV2,
    /// The certified V1 effects (protocols before 33), else null; `fx` is then the driver's view.
    v1: []const ?*const types.TransactionEffectsV1,
    outs: []TxOut,

    fn execTx(r: *Run, arena: Allocator, i: usize) TxOut {
        return r.execInner(arena, i) catch |e| .{ .fallback = @errorName(e) };
    }

    fn execInner(r: *Run, arena: Allocator, i: usize) !TxOut {
        var ov = r.master.*;
        ov.reads = .empty;
        ov.arena = arena;
        const t = r.txs[i];
        const tx_raw = r.tx_raw[i];
        const data = r.data[i];
        const fx = r.fx[i];
        const cfg = r.cfg;
        const params = r.params;
        const epoch = r.epoch;
        const tx_digest = hash.blake2b256(&.{ "TransactionData::", tx_raw });
        var out: TxOut = .{};

        var ins: std.ArrayList([]const u8) = .empty;
        const in_keys = try inputKeys(arena, fx, r.v1[i]);
        for (in_keys) |k| {
            const raw = ov.getAt(&k.id, k.version) orelse return .{ .fallback = "input object not in the store" };
            try ins.append(arena, raw);
        }
        const lookup: exec.coin_ptb.ObjectLookup = .{ .ctx = &ov, .get = Overlay.get, .latest = Overlay.latest };

        if (system.handles(&data.kind)) {
            out.kind = .system;
            var versions: std.ArrayList(system.InputVersion) = .empty;
            for (in_keys) |k| try versions.append(arena, .{ .id = k.id, .version = k.version });
            // V1: the blob's input objects only (as execute.zig's runSystem)
            if (r.v1[i] == null) for (fx.unchanged_consensus_objects) |u| switch (u[1]) {
                .ReadOnlyRoot => |ro| try versions.append(arena, .{ .id = u[0].@"0".@"0", .version = ro[0].@"0" }),
                else => {},
            };
            const env: system.Env = .{ .cfg = cfg, .epoch = epoch, .epoch_start_ms = params.start_ms, .rgp = params.rgp, .tx_digest = tx_digest };
            const src: system.Source = .{ .ctx = &ov, .input = Overlay.get, .child = Overlay.sysChild, .package = Overlay.sysPackage };
            const res = system.execute(arena, &env, tx_raw, data, versions.items, src) catch |e| return .{ .fallback = try std.fmt.allocPrint(arena, "system: {s}", .{@errorName(e)}) };
            switch (res) {
                .unsupported => |why| return .{ .fallback = why },
                .done => |o| {
                    out.effects = o.effects;
                    out.events = o.events;
                    const w = try arena.alloc(exec.coin_ptb.Written, o.written.len);
                    for (o.written, w) |x, *y| y.* = .{ .id = x.id, .bytes = x.bytes };
                    out.written = w;
                },
            }
        } else if (exec.ccp.timestampOf(&data.kind) != null) {
            out.kind = .ccp;
            const res = exec.ccp.execute(arena, cfg, epoch, tx_raw, data, ins.items) catch |e| return .{ .fallback = try std.fmt.allocPrint(arena, "ccp: {s}", .{@errorName(e)}) };
            switch (res) {
                .unsupported => |why| return .{ .fallback = why },
                .done => |o| {
                    out.effects = o.effects;
                    out.written = o.written;
                },
            }
        } else {
            const class = exec.classify.classify(&data.kind);
            var ran = false;
            if (class == .ptb_coin_transfer) {
                var objs = lookup;
                objs.assigned = exec.inputs.assignedFromEffects(arena, data, t.effects) catch return .{ .fallback = "effects do not decode" };
                const res = exec.coin_ptb.execute(arena, cfg, epoch, params.rgp, tx_raw, data, objs) catch |e| return .{ .fallback = try std.fmt.allocPrint(arena, "coin_ptb: {s}", .{@errorName(e)}) };
                switch (res) {
                    .unsupported => {},
                    .done => |o| {
                        out.effects = o.effects;
                        out.written = o.written;
                        out.kind = .coin;
                        ran = true;
                    },
                }
            }
            if (!ran) {
                if (data.kind != .ProgrammableTransaction) return .{ .fallback = @tagName(class) };
                if (!exec.versions.moveSupported(cfg)) return .{ .fallback = "execution version" };
                out.kind = .move;
                const unsettled: Unsettled = .{ .effects = r.fx[0..i] };
                const env: ptb.Env = .{ .gpa = r.gpa, .cfg = cfg, .pv = params.pv, .epoch = epoch, .epoch_start_ms = params.start_ms, .rgp = params.rgp, .pkgs = &r.pkg_src.pkgs };
                const res = ptb.execute(arena, env, tx_raw, data, .{
                    .objs = lookup,
                    .effects = fx,
                    .unchanged_loaded = null,
                    .unsettled = .{ .ctx = &unsettled, .get = Unsettled.get },
                    .insufficient_funds = fx.status == .Failure and fx.status.Failure.@"error" == .InsufficientFundsForWithdraw and fx.status.Failure.command == null,
                    .state = .{ .ctx = &ov, .vtable = &Overlay.pre_vtable },
                }) catch |e| return .{ .fallback = try std.fmt.allocPrint(arena, "ptb: {s}", .{@errorName(e)}) };
                switch (res) {
                    .unsupported => |why| return .{ .fallback = why },
                    .done => |o| {
                        out.effects = o.effects;
                        out.events = o.events;
                        out.written = o.written;
                        out.loaded = o.loaded;
                    },
                }
            }
        }

        // Accept only the certified result.
        if (!std.mem.eql(u8, out.effects, t.effects)) return .{ .fallback = try std.fmt.allocPrint(arena, "effects differ ({s})", .{@tagName(data.kind)}) };
        if (fx.events_digest) |d| {
            const ev = out.events orelse return .{ .fallback = "certified events, zui none" };
            if (!std.mem.eql(u8, &hash.blake2b256(&.{ "TransactionEvents::", ev }), &d.@"0".@"0")) return .{ .fallback = "events digest differs" };
        } else if (out.events != null) return .{ .fallback = "zui events, certified none" };
        out.reads = ov.reads.keys();
        out.read_bytes = ov.reads.values();
        return out;
    }
};

/// Dependency levels from the certified effects (see `Pool`); null: run in order.
fn levelsOf(arena: Allocator, data: []const *const types.TransactionDataV1, fx: []const *const types.TransactionEffectsV2) !?[]u32 {
    const n = fx.len;
    const lv = try arena.alloc(u32, n);
    var lw: std.AutoHashMapUnmanaged(Id, u32) = .empty; // last writer's level + 1
    var lr: std.AutoHashMapUnmanaged(Id, u32) = .empty; // highest reader level since
    var top: u32 = 0; // highest level so far + 1
    var floor: u32 = 0; // a barrier's level + 1: nothing later goes below it
    for (fx, data, 0..) |f, d, i| {
        const barrier = system.handles(&d.kind) or exec.ccp.timestampOf(&d.kind) != null or for (f.changed_objects) |c| {
            if (c[1].output_state == .PackageWrite) break true;
        } else false;
        var l: u32 = floor;
        if (barrier) l = @max(l, top) else {
            for (f.changed_objects) |c| {
                const id = c[0].@"0".@"0";
                if (lw.get(id)) |w| l = @max(l, w);
                if (lr.get(id)) |r| l = @max(l, r);
            }
            for (f.unchanged_consensus_objects) |u| if (lw.get(u[0].@"0".@"0")) |w| {
                l = @max(l, w);
            };
        }
        lv[i] = l;
        for (f.changed_objects) |c| try lw.put(arena, c[0].@"0".@"0", l + 1);
        for (f.unchanged_consensus_objects) |u| {
            const g = try lr.getOrPut(arena, u[0].@"0".@"0");
            g.value_ptr.* = if (g.found_existing) @max(g.value_ptr.*, l) else l;
        }
        top = @max(top, l + 1);
        if (barrier) floor = l + 1;
    }
    if (top == n) return null; // a chain: nothing to overlap
    return lv;
}

/// Executes the checkpoint and builds its blob. `cert` is the BCS `CertifiedCheckpointSummary`,
/// `contents` the BCS `CheckpointContents` (digest-checked by the caller against the summary).
/// With `pool`, independent transactions run on its threads (see `Pool`); the blob and aux are
/// the same bytes as an in-order run.
pub fn run(
    gpa: Allocator,
    arena: Allocator,
    snap: *const store.Snapshot,
    pkg_src: *PackageSource,
    params: Params,
    epoch: u64,
    cert: []const u8,
    contents: []const u8,
    txs: []const ExecData,
    stats: *Stats,
    parent: ?*const Layer,
    pool: ?*Pool,
) !Result {
    const cfg = protocol.get(params.pv, params.chain) catch return .{ .fallback = "protocol version" };
    var ov: Overlay = .{ .snap = snap, .arena = arena, .parent = parent };
    pkg_src.overlay = &ov;
    pkg_src.snap = snap;
    // `snap` is the caller's: never leave a pointer to it behind for a later `get`.
    defer {
        pkg_src.overlay = null;
        pkg_src.snap = null;
    }

    const n = txs.len;
    const tx_raw = try arena.alloc([]const u8, n);
    const data = try arena.alloc(*const types.TransactionDataV1, n);
    const fxs = try arena.alloc(*const types.TransactionEffectsV2, n);
    const v1s = try arena.alloc(?*const types.TransactionEffectsV1, n);
    var any_v1 = false;
    for (txs, 0..) |t, i| {
        tx_raw[i] = txDataOf(t.tx) catch return .{ .fallback = "transaction does not parse" };
        const td = try arena.create(types.TransactionData);
        td.* = bcs.decode(types.TransactionData, arena, tx_raw[i]) catch return .{ .fallback = "transaction does not decode" };
        data[i] = &td.V1;
        const fx_all = try arena.create(types.TransactionEffects);
        fx_all.* = bcs.decode(types.TransactionEffects, arena, t.effects) catch return .{ .fallback = "effects do not decode" };
        v1s[i] = null;
        fxs[i] = switch (fx_all.*) {
            .V2 => |*v| v,
            // exec-history: protocols before 33 certify V1 effects; the driver reads them through
            // a V2 view (as execute.zig and exec-replay do) and writes V1 itself
            .V1 => |*v| blk: {
                any_v1 = true;
                v1s[i] = v;
                break :blk exec.ptb.v2View(arena, v) catch return .{ .fallback = "effects v1 view" };
            },
        };
    }
    var r: Run = .{ .gpa = gpa, .cfg = cfg, .params = params, .epoch = epoch, .pkg_src = pkg_src, .master = &ov, .txs = txs, .tx_raw = tx_raw, .data = data, .fx = fxs, .v1 = v1s, .outs = try arena.alloc(TxOut, n) };

    // V1 checkpoints run in order (the levels read V2 output states)
    const par = if (any_v1) null else if (pool) |pl| (if (pl.threads.len > 0) try levelsOf(arena, data, fxs) else null) else null;
    if (pool) |pl| for (pl.arenas) |*x| {
        _ = x.reset(.retain_capacity);
    };
    var ok = try execAll(&r, arena, pool, par);
    if (!ok and par != null) {
        // Something the effects do not declare crossed a level: run in order.
        _ = pool.?.reruns.fetchAdd(1, .monotonic);
        ov = .{ .snap = snap, .arena = arena, .parent = parent };
        ok = try execAll(&r, arena, pool, null);
    }
    if (!ok) for (r.outs) |o| if (o.fallback) |why| return .{ .fallback = try arena.dupe(u8, why) };
    for (r.outs) |o| {
        stats.txs += 1;
        switch (o.kind) {
            .ccp => stats.ccp += 1,
            .system => stats.system += 1,
            .coin => stats.coin += 1,
            .move => stats.move += 1,
        }
    }

    // Blob and aux in transaction order (the same bytes as an in-order run).
    var blob: std.ArrayList(u8) = .empty;
    try blob.ensureTotalCapacity(arena, cert.len + contents.len + 64 * 1024);
    try blob.append(arena, 1);
    try blob.appendSlice(arena, cert);
    try blob.appendSlice(arena, contents);
    try putUleb(&blob, arena, n);
    var aux: std.ArrayList(u8) = .empty;
    try aux.appendSlice(arena, "ZUIAUX01");
    try putUleb(&aux, arena, n);
    var in_blob: std.AutoHashMapUnmanaged(Key, void) = .empty;
    ov.reads = .empty;
    for (txs, r.outs, fxs, v1s) |t, o, fx, v1| {
        // Input objects of the blob: the effects' modified-at versions, in effects order.
        var ins: std.ArrayList([]const u8) = .empty;
        for (try inputKeys(arena, fx, v1)) |k| try ins.append(arena, ov.getAt(&k.id, k.version) orelse return .{ .fallback = "input object not in the store" });
        for (o.reads, o.read_bytes) |k, raw| if (!ov.reads.contains(k)) try ov.reads.put(arena, k, raw);
        try blob.appendSlice(arena, t.tx);
        try blob.appendSlice(arena, t.effects);
        if (o.events) |ev| {
            try blob.append(arena, 1);
            try blob.appendSlice(arena, ev);
        } else try blob.append(arena, 0);
        try putUleb(&blob, arena, ins.items.len);
        for (ins.items) |raw| {
            try blob.appendSlice(arena, raw);
            const k = try exec.objects.keyOf(raw);
            try in_blob.put(arena, .{ .id = k.id, .version = k.version }, {});
        }
        var outs: std.ArrayList([]const u8) = .empty;
        // mutated (input exists), created, unwrapped: the order of `effectKeys`
        if (v1) |v| inline for (.{ "mutated", "created", "unwrapped" }) |list| {
            for (@field(v, list)) |e| {
                const raw = for (o.written) |w| {
                    if (std.mem.eql(u8, &w.id, &e[0][0].@"0".@"0")) break w.bytes;
                } else return .{ .fallback = "output object missing" };
                try outs.append(arena, raw);
            }
        } else inline for (.{ 0, 1, 2 }) |pass| {
            for (fx.changed_objects) |c| {
                const is_write = switch (c[1].output_state) {
                    .ObjectWrite, .PackageWrite => true,
                    else => false,
                };
                if (!is_write) continue;
                const sel = switch (pass) {
                    0 => c[1].input_state == .Exist,
                    1 => c[1].input_state == .NotExist and c[1].id_operation == .Created,
                    else => c[1].input_state == .NotExist and c[1].id_operation == .None and c[1].output_state == .ObjectWrite,
                };
                if (!sel) continue;
                const raw = for (o.written) |w| {
                    if (std.mem.eql(u8, &w.id, &c[0].@"0".@"0")) break w.bytes;
                } else return .{ .fallback = "output object missing" };
                try outs.append(arena, raw);
            }
        };
        if (outs.items.len != o.written.len) return .{ .fallback = "output object count differs" };
        try putUleb(&blob, arena, outs.items.len);
        for (outs.items) |raw| {
            try blob.appendSlice(arena, raw);
            const k = try exec.objects.keyOf(raw);
            try in_blob.put(arena, .{ .id = k.id, .version = k.version }, {});
        }

        // aux: the transaction's loaded runtime objects it did not change
        var kept: usize = 0;
        for (o.loaded) |l| kept += @intFromBool(!changed(fx, v1, &l.id));
        try putUleb(&aux, arena, kept);
        for (o.loaded) |l| if (!changed(fx, v1, &l.id)) {
            try aux.appendSlice(arena, &l.id);
            var vb: [8]u8 = undefined;
            std.mem.writeInt(u64, &vb, l.version, .little);
            try aux.appendSlice(arena, &vb);
            const raw = ov.getAt(&l.id, l.version);
            if (raw) |rw| {
                try aux.append(arena, 1);
                try aux.appendSlice(arena, &hash.blake2b256(&.{ "Object::", rw }));
            } else try aux.append(arena, 0);
        };
    }
    // aux extras: objects read from the store that the blob does not carry
    var extra: usize = 0;
    for (ov.reads.keys()) |k| extra += @intFromBool(!in_blob.contains(k));
    try putUleb(&aux, arena, extra);
    for (ov.reads.keys(), ov.reads.values()) |k, raw| if (!in_blob.contains(k)) {
        try putUleb(&aux, arena, raw.len);
        try aux.appendSlice(arena, raw);
    };
    return .{ .ok = .{ .blob = blob.items, .aux = aux.items, .layer = .{ .at = ov.at, .live = ov.live } } };
}

/// Runs every transaction, level by level (`lv`) or in order, applying each level's writes in
/// transaction order. False: a transaction fell back (its `outs` entry says why).
fn execAll(r: *Run, arena: Allocator, pool: ?*Pool, lv: ?[]const u32) !bool {
    const n = r.txs.len;
    var order: std.ArrayList(u32) = .empty;
    var bounds: std.ArrayList(u32) = .empty;
    if (lv) |levels| {
        var top: u32 = 0;
        for (levels) |l| top = @max(top, l + 1);
        for (0..top) |l| {
            try bounds.append(arena, @intCast(order.items.len));
            for (levels, 0..) |x, i| if (x == l) try order.append(arena, @intCast(i));
        }
    } else for (0..n) |i| {
        try bounds.append(arena, @intCast(i));
        try order.append(arena, @intCast(i));
    }
    try bounds.append(arena, @intCast(n));
    for (bounds.items[0 .. bounds.items.len - 1], bounds.items[1..]) |a, b| {
        const level = order.items[a..b];
        if (pool) |pl| pl.runLevel(r, level, arena) else for (level) |i| {
            r.outs[i] = r.execTx(arena, i);
        }
        for (level) |i| if (r.outs[i].fallback != null) return false;
        for (level) |i| try r.master.applyCopy(r.outs[i].written, r.fx[i], r.v1[i]);
    }
    return true;
}

fn changed(fx: *const types.TransactionEffectsV2, v1: ?*const types.TransactionEffectsV1, id: *const Id) bool {
    if (v1) |v| {
        for (v.modified_at_versions) |m| if (std.mem.eql(u8, &m[0].@"0".@"0", id)) return true;
        inline for (.{ "created", "unwrapped" }) |list| {
            for (@field(v, list)) |e| if (std.mem.eql(u8, &e[0][0].@"0".@"0", id)) return true;
        }
        return false;
    }
    for (fx.changed_objects) |c| if (std.mem.eql(u8, &c[0].@"0".@"0", id)) return true;
    return false;
}

/// The blob's input object keys of one transaction (convert.zig `effectKeys`): V2 the changed
/// objects whose input exists; V1 `modified_at_versions` minus `unwrapped_then_deleted`.
fn inputKeys(arena: Allocator, fx: *const types.TransactionEffectsV2, v1: ?*const types.TransactionEffectsV1) ![]const Key {
    var out: std.ArrayList(Key) = .empty;
    if (v1) |v| {
        for (v.modified_at_versions) |m| {
            const id = m[0].@"0".@"0";
            const dropped = for (v.unwrapped_then_deleted) |d| {
                if (std.mem.eql(u8, &d[0].@"0".@"0", &id)) break true;
            } else false;
            if (!dropped) try out.append(arena, .{ .id = id, .version = m[1].@"0" });
        }
        return out.items;
    }
    for (fx.changed_objects) |c| switch (c[1].input_state) {
        .Exist => |e| try out.append(arena, .{ .id = c[0].@"0".@"0", .version = e[0][0].@"0" }),
        .NotExist => {},
    };
    return out.items;
}

// ------------------------------------------------------------------ full contents (p2p wire)

/// The GenericSignature bodies of a BCS signature list: `Vec<GenericSignature>` (V1, and a
/// transaction's `tx_signatures`) or `Vec<(GenericSignature, Option<SequenceNumber>)>` (V2).
fn sigBodies(arena: Allocator, raw: []const u8, with_versions: bool) ![]const []const u8 {
    var r = bcs.Reader.init(raw);
    const k = try r.length();
    if (k > raw.len) return error.Malformed;
    const out = try arena.alloc([]const u8, k);
    for (out) |*b| {
        b.* = try r.bytes(try r.length());
        if (with_versions) switch (try r.int(u8)) {
            0 => {},
            1 => _ = try r.int(u64),
            else => return error.Malformed,
        };
    }
    if (r.remaining() != 0) return error.TrailingBytes;
    return out;
}

/// The `tx_signatures` of `SenderSignedData` bytes `tx` are a permutation of the certified list
/// `certified` (same count, each byte-equal to a distinct certified signature).
pub fn samePermutation(arena: Allocator, tx: []const u8, certified: []const u8, with_versions: bool) !bool {
    const td = try txDataOf(tx);
    const end = @intFromPtr(td.ptr) - @intFromPtr(tx.ptr) + td.len;
    const mine = try sigBodies(arena, tx[end..], false);
    const theirs = try sigBodies(arena, certified, with_versions);
    if (mine.len != theirs.len) return false;
    const used = try arena.alloc(bool, theirs.len);
    @memset(used, false);
    for (mine) |m| {
        for (theirs, used) |c, *u| {
            if (!u.* and std.mem.eql(u8, m, c)) {
                u.* = true;
                break;
            }
        } else return false;
    }
    return true;
}

pub const FullContents = struct {
    txs: []ExecData,
    /// BCS `CheckpointContents` rebuilt from the transactions and signatures.
    contents: []const u8,
};

/// Splits `VersionedFullCheckpointContents` (V1 or V2) into transactions and rebuilds the
/// `CheckpointContents` whose digest the summary certifies (the caller checks it).
pub fn splitFull(arena: Allocator, raw: []const u8) !FullContents {
    var r = bcs.Reader.init(raw);
    const tag = try r.uleb32();
    if (tag > 1) return error.Malformed;
    const n = try r.length();
    if (n > raw.len) return error.Malformed;
    const txs = try arena.alloc(ExecData, n);
    for (txs) |*t| {
        const a = r.pos();
        try bcs.skip(types.SenderSignedData, &r);
        const b = r.pos();
        try bcs.skip(types.TransactionEffects, &r);
        t.* = .{ .tx = raw[a..b], .effects = raw[b..r.pos()] };
    }
    const m = try r.length();
    if (m != n) return error.Malformed;
    var out: std.ArrayList(u8) = .empty;
    try out.append(arena, @intCast(tag));
    try putUleb(&out, arena, n);
    // V1: transactions (digests) then user_signatures; V2: per transaction digests ++ signatures.
    var sig_spans = try arena.alloc([]const u8, n);
    for (sig_spans) |*s| {
        const a = r.pos();
        const k = try r.length();
        for (0..k) |_| {
            _ = try r.bytes(try r.length());
            if (tag == 1) switch (try r.int(u8)) {
                0 => {},
                1 => _ = try r.int(u64),
                else => return error.Malformed,
            };
        }
        s.* = raw[a..r.pos()];
    }
    if (r.remaining() != 0) return error.TrailingBytes;
    for (txs, sig_spans) |t, s| {
        // The transaction's own signatures are not covered by any digest: accept the peer's copy
        // only when they are a permutation of the certified ones (the stored order is the
        // submitter's, the contents' is signer order; convert.zig "Signature order").
        if (!try samePermutation(arena, t.tx, s, tag == 1)) return error.SignatureMismatch;
    }
    for (txs, sig_spans) |t, s| {
        const td = try txDataOf(t.tx);
        try out.append(arena, 32);
        try out.appendSlice(arena, &hash.blake2b256(&.{ "TransactionData::", td }));
        try out.append(arena, 32);
        try out.appendSlice(arena, &hash.blake2b256(&.{ "TransactionEffects::", t.effects }));
        if (tag == 1) try out.appendSlice(arena, s);
    }
    if (tag == 0) {
        try putUleb(&out, arena, n);
        for (sig_spans) |s| try out.appendSlice(arena, s);
    }
    sig_spans = sig_spans;
    return .{ .txs = txs, .contents = out.items };
}
