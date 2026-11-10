//! SUI conservation check at every end of epoch (FULLNODE-PARITY 6 `expensive-safety-check-config`;
//! sui-node 1.83.1 `AuthorityStore::expensive_check_sui_conservation`, run from
//! `reconfigure_state` when `enable_epoch_sui_conservation_check` is on).
//!
//! Over the live object set as of the end-of-epoch checkpoint (wrapped tombstones excluded):
//! - `total_sui` = sum of `Object::get_total_sui - storage_rebate`, i.e. the SUI held in Move
//!   values: a gas coin's value; 0 for any other coin; the u128 of a SUI balance accumulator
//!   field (address balances); else every `0x2::balance::Balance<0x2::sui::SUI>` reached through
//!   the object's annotated layout (`BalanceTraversal`), packages 0. The storage fund, the stake
//!   pools and the address balances are all inside objects, so this is the whole supply.
//! - `total_storage_rebate` = sum of `storage_rebate`.
//! - `imbalance` = the system state's `storage_fund.total_object_storage_rebates` - the rebates.
//!
//! As sui-node: the first check a node makes records `total_sui` and `imbalance`
//! (`expected_network_sui_amount`, `expected_storage_fund_imbalance`); every later end of epoch
//! must reproduce both exactly. deepwave keeps them in `<dir>/node/sui-conservation` (a fresh
//! restore starts without, as sui-node's perpetual tables do). The supply difference against
//! 10B SUI is a gauge only (`sui_conservation_imbalance`), as in sui-node.
//!
//! sui-node panics on mainnet when an object's SUI cannot be computed (layout or BCS); deepwave counts
//! such objects (`unresolved`) and fails the check instead.
//!
//! The node runs it on the epoch-jobs thread after the end-of-epoch checkpoint commits (a pinned
//! past view of the live set, segment cleaning paused, like the snapshot writer); a failure is
//! ERROR lines, `zui_sui_conservation_*` metrics, execution off (verify-only) and, with
//! `--sui-conservation halt`, a stop. `deepwave-tool sui-conservation` runs it offline.
const std = @import("std");
const Io = std.Io;
const types = @import("types");
const store = @import("store");
const exec = @import("exec");
const serve = @import("serve");
const ml = serve.movelayout;
const RwLock = @import("index").RwLock;
const sysstate = serve.sysstate;
const Atomic = std.atomic.Value;

const zero_id: [32]u8 = @splat(0);

pub const total_supply_mist: u64 = 10_000_000_000 * 1_000_000_000;

pub const Policy = enum { verify_only, halt, off };

pub const Totals = struct {
    objects: u64 = 0,
    /// Sum of SUI in Move values (storage rebates excluded), u128 so an overflow shows.
    total_sui: u128 = 0,
    storage_rebate: u128 = 0,
    /// Objects whose SUI could not be computed (layout unresolved, contents unreadable).
    unresolved: u64 = 0,
    first_unresolved: ?[32]u8 = null,

    pub fn add(t: *Totals, o: *const Totals) void {
        t.objects += o.objects;
        t.total_sui += o.total_sui;
        t.storage_rebate += o.storage_rebate;
        t.unresolved += o.unresolved;
        if (t.first_unresolved == null) t.first_unresolved = o.first_unresolved;
    }
};

pub const Expected = struct { total_sui: u64, imbalance: i64 };

pub const Report = struct {
    checkpoint: u64,
    /// The system state's epoch at the end-of-epoch checkpoint (the new epoch, as sui-node logs).
    epoch: u64 = 0,
    totals: Totals = .{},
    storage_fund: u64 = 0,
    ms: u64 = 0,

    pub fn imbalance(r: *const Report) i64 {
        return @as(i64, @intCast(r.storage_fund)) - @as(i64, @intCast(@min(r.totals.storage_rebate, std.math.maxInt(i64))));
    }
    pub fn supplyImbalance(r: *const Report) i128 {
        return @as(i128, @intCast(r.totals.total_sui)) - total_supply_mist;
    }
    pub fn expected(r: *const Report) ?Expected {
        if (r.totals.total_sui > std.math.maxInt(u64)) return null;
        return .{ .total_sui = @intCast(r.totals.total_sui), .imbalance = r.imbalance() };
    }
};

pub const Verdict = enum { first, ok, mismatch, unresolved };

/// sui-node's two `fp_ensure!`s against the values its first check recorded.
pub fn judge(r: *const Report, want: ?Expected) Verdict {
    if (r.totals.unresolved != 0) return .unresolved;
    const got = r.expected() orelse return .mismatch;
    const w = want orelse return .first;
    if (got.imbalance != w.imbalance or got.total_sui != w.total_sui) return .mismatch;
    return .ok;
}

// ------------------------------------------------------------------ per object

const two: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[31] = 2;
    break :blk a;
};

fn isSui(t: *const types.TypeTag) bool {
    return switch (t.*) {
        .@"struct" => |s| std.mem.eql(u8, &s.address.@"0", &two) and std.mem.eql(u8, s.module.@"0", "sui") and std.mem.eql(u8, s.name.@"0", "SUI") and s.type_args.len == 0,
        else => false,
    };
}

/// `sui::balance::Balance<SUI>` (BalanceTraversal's `is_balance` with the GAS type).
pub fn isSuiBalance(s: *const types.StructTag) bool {
    return std.mem.eql(u8, &s.address.@"0", &two) and std.mem.eql(u8, s.module.@"0", "balance") and
        std.mem.eql(u8, s.name.@"0", "Balance") and s.type_args.len == 1 and isSui(&s.type_args[0]);
}

fn hasSui(l: ml.Layout) bool {
    return switch (l) {
        .vector => |c| hasSui(c.*),
        .@"struct" => |s| blk: {
            if (isSuiBalance(&s.type_)) break :blk true;
            for (s.fields) |f| if (hasSui(f.layout)) break :blk true;
            break :blk false;
        },
        .@"enum" => |e| blk: {
            for (e.variants) |v| for (v.fields) |f| if (hasSui(f.layout)) break :blk true;
            break :blk false;
        },
        else => false,
    };
}

const Walk = struct {
    b: []const u8,
    at: usize = 0,
    sui: u128 = 0,

    fn take(w: *Walk, n: usize) ![]const u8 {
        if (w.b.len - w.at < n) return error.EndOfStream;
        defer w.at += n;
        return w.b[w.at..][0..n];
    }
    fn uleb(w: *Walk) !u64 {
        var v: u64 = 0;
        var shift: u7 = 0;
        while (true) {
            const byte = (try w.take(1))[0];
            if (shift > 63) return error.InvalidValue;
            v |= @as(u64, byte & 0x7f) << @intCast(shift);
            if (byte & 0x80 == 0) return v;
            shift += 7;
        }
    }

    /// One value of layout `l`; u64s inside a `Balance<SUI>` count (BalanceTraversal's Accumulator).
    fn value(w: *Walk, l: ml.Layout, in_bal: bool) !void {
        switch (l) {
            .bool, .u8 => _ = try w.take(1),
            .u16 => _ = try w.take(2),
            .u32 => _ = try w.take(4),
            .u64 => {
                const v = std.mem.readInt(u64, (try w.take(8))[0..8], .little);
                if (in_bal) w.sui += v;
            },
            .u128 => _ = try w.take(16),
            .u256, .address, .signer => _ = try w.take(32),
            .vector => |c| {
                const n = try w.uleb();
                if (!in_bal and !hasSui(c.*)) {
                    if (fixedSize(c.*)) |sz| {
                        _ = try w.take(std.math.mul(usize, sz, n) catch return error.InvalidValue);
                        return;
                    }
                }
                for (0..n) |_| try w.value(c.*, in_bal);
            },
            .@"struct" => |s| {
                const inner = in_bal or isSuiBalance(&s.type_);
                for (s.fields) |f| try w.value(f.layout, inner);
            },
            .@"enum" => |e| {
                const tag = try w.uleb();
                if (tag >= e.variants.len) return error.InvalidValue;
                for (e.variants[@intCast(tag)].fields) |f| try w.value(f.layout, in_bal);
            },
        }
    }
};

fn fixedSize(l: ml.Layout) ?usize {
    return switch (l) {
        .bool, .u8 => 1,
        .u16 => 2,
        .u32 => 4,
        .u64 => 8,
        .u128 => 16,
        .u256, .address, .signer => 32,
        .vector, .@"enum" => null,
        .@"struct" => |s| blk: {
            var t: usize = 0;
            for (s.fields) |f| t += fixedSize(f.layout) orelse break :blk null;
            break :blk t;
        },
    };
}

/// The layout resolver (packages from `pkgs`) and a cache per object type, one for all workers.
/// Per-worker resolvers each decoded every package their objects used: at the end of epoch 1305
/// (rig rehearsal 2026-11-09, 8 workers) the check took `node gpa` from 4.8 to 14.7 GiB in two
/// minutes, past the 12G fence, and the node crawled at 0.1 cp/s under memory.high. Lookups take
/// the lock shared; a miss resolves under the exclusive lock. Layouts are never changed once in
/// the cache, so workers read them without the lock.
pub const Layouts = struct {
    lock: RwLock = .{},
    arena: std.heap.ArenaAllocator,
    resolver: ml.Resolver = undefined,
    cache: std.StringHashMapUnmanaged(Entry) = .empty,

    pub const Entry = struct { layout: ?ml.Layout, sui: bool };

    /// `l` must not move afterwards (the resolver keeps a pointer to its arena).
    pub fn init(l: *Layouts, gpa: std.mem.Allocator, pkgs: ml.PackageSource) void {
        l.* = .{ .arena = .init(gpa) };
        l.resolver = ml.Resolver.init(l.arena.allocator(), pkgs);
        // Values only: no VM limits apply to reading an existing object.
        l.resolver.limits = .{ .max_depth = 1 << 16, .max_nodes = 1 << 24 };
    }

    pub fn deinit(l: *Layouts) void {
        l.arena.deinit();
    }

    /// Single-threaded setup (tests): a known layout for `ty`.
    pub fn seed(l: *Layouts, ty: []const u8, layout: ml.Layout) !void {
        try l.cache.put(l.arena.allocator(), ty, .{ .layout = layout, .sui = hasSui(layout) });
    }

    fn entry(l: *Layouts, ty: []const u8) !Entry {
        {
            l.lock.lockShared();
            defer l.lock.unlockShared();
            if (l.cache.get(ty)) |e| return e;
        }
        l.lock.lock();
        defer l.lock.unlock();
        if (l.cache.get(ty)) |e| return e;
        const a = l.arena.allocator();
        const key = try a.dupe(u8, ty);
        const mot = @import("bcs").decode(types.MoveObjectType, a, key) catch null;
        const layout: ?ml.Layout = if (mot) |m| blk: {
            const tag = try ml.objectStructTag(a, m);
            break :blk try l.resolver.structLayout(&tag);
        } else null;
        // An unresolved layout must be walked (reported); a resolved one only if SUI can be inside.
        const e: Entry = .{ .layout = layout, .sui = if (layout) |x| hasSui(x) else true };
        try l.cache.put(a, key, e);
        return e;
    }
};

/// Per-thread state: the shared layouts, the sums, and an arena for this worker's copies.
pub const Counter = struct {
    arena: std.heap.ArenaAllocator,
    layouts: *Layouts,
    totals: Totals = .{},

    pub fn init(c: *Counter, gpa: std.mem.Allocator, layouts: *Layouts) void {
        c.* = .{ .arena = .init(gpa), .layouts = layouts };
    }

    pub fn deinit(c: *Counter) void {
        c.arena.deinit();
    }

    fn unresolved(c: *Counter, id: *const [32]u8) void {
        c.totals.unresolved += 1;
        if (c.totals.first_unresolved == null) c.totals.first_unresolved = id.*;
    }

    /// One live object (BCS `Object`).
    pub fn object(c: *Counter, raw: []const u8) !void {
        const v = exec.objects.ObjectView.parse(raw) catch {
            c.totals.objects += 1;
            return c.unresolved(&zero_id);
        };
        c.totals.objects += 1;
        c.totals.storage_rebate += std.mem.readInt(u64, raw[v.rebate_at..][0..8], .little);
        if (v.is_package) return;
        const contents = v.contents();
        // Data::Move tag (1 byte), MoveObjectType, has_public_transfer, version.
        const ty = raw[1 .. v.version_at - 1];
        switch (ty[0]) {
            1 => { // GasCoin: UID, then the balance's value
                if (contents.len < 40) return c.unresolved(&v.id);
                c.totals.total_sui += std.mem.readInt(u64, contents[32..40], .little);
            },
            3 => {}, // Coin<T>, T != SUI
            4 => { // Field<accumulator::Key<Balance<SUI>>, U128>: UID, key (address), u128
                if (contents.len != 80) return c.unresolved(&v.id);
                const x = std.mem.readInt(u128, contents[64..80], .little);
                if (x > std.math.maxInt(u64)) return c.unresolved(&v.id);
                c.totals.total_sui += x;
            },
            else => {
                const e = try c.layouts.entry(ty);
                if (!e.sui) return;
                const l = e.layout orelse return c.unresolved(&v.id);
                var w: Walk = .{ .b = contents };
                w.value(l, false) catch return c.unresolved(&v.id);
                if (w.at != contents.len) return c.unresolved(&v.id);
                c.totals.total_sui += w.sui;
            },
        }
    }
};

// ------------------------------------------------------------------ the scan

/// Packages for layouts: the newest stored version of each id (a package id's modules never
/// change, and a system package upgraded in place keeps every datatype's fields). Each read is
/// copied into the layouts' arena under a snapshot of its own, released at once: a snapshot held
/// for the whole scan pinned every chunk the packages came from (zui_store_chunk_kept_bytes
/// 2.6 GB at the end of epoch 1305 on a test machine). Called under the layouts' exclusive lock.
const Pkgs = struct {
    st: *store.Store,
    arena: std.mem.Allocator,
    fn get(ctx: *const anyopaque, id: *const [32]u8) ?[]const u8 {
        const p: *const Pkgs = @ptrCast(@alignCast(ctx));
        var snap = p.st.snapshot();
        defer snap.release();
        const l = (snap.latest(id) catch return null) orelse return null;
        return switch (l) {
            .live => |o| p.arena.dupe(u8, o.bytes) catch null,
            .removed => null,
        };
    }
};

const sys_field_v1 = blk: {
    @setEvalBranchQuota(1_000_000);
    break :blk sysstate.u64FieldId(&sysstate.system_state_id, 1);
};
const sys_field_v2 = blk: {
    @setEvalBranchQuota(1_000_000);
    break :blk sysstate.u64FieldId(&sysstate.system_state_id, 2);
};

const Worker = struct {
    scan: *store.LiveScan,
    counter: Counter = undefined,
    cancel: ?*const Atomic(bool),
    progress: *Atomic(u64),
    err: ?anyerror = null,
    /// System state objects seen (copies): the 0x5 wrapper and its `Field<u64, Inner>`.
    wrapper: ?[]u8 = null,
    fields: [2]?[]u8 = .{ null, null },

    fn run(w: *Worker) void {
        while (w.scan.next()) |g| {
            if (w.cancel) |c| if (c.load(.acquire)) {
                w.err = error.Cancelled;
                return;
            };
            w.scan.group(g, w, onItem) catch |e| {
                w.err = e;
                return;
            };
        }
    }

    fn onItem(w: *Worker, o: store.LiveIter.Item) anyerror!void {
        try w.counter.object(o.bytes);
        _ = w.progress.fetchAdd(1, .monotonic);
        const a = w.counter.arena.allocator();
        if (std.mem.eql(u8, &o.id, &sysstate.system_state_id)) w.wrapper = try a.dupe(u8, o.bytes) else if (std.mem.eql(u8, &o.id, &sys_field_v1)) w.fields[0] = try a.dupe(u8, o.bytes) else if (std.mem.eql(u8, &o.id, &sys_field_v2)) w.fields[1] = try a.dupe(u8, o.bytes);
    }
};

pub const Options = struct {
    /// Workers. Memory does not grow with them (one layout cache), only the scan's speed.
    threads: u32 = 8,
    cancel: ?*const Atomic(bool) = null,
    /// Objects visited so far (progress).
    progress: ?*Atomic(u64) = null,
    /// Layouts by object type (BCS `MoveObjectType`) used instead of the resolver (tests).
    layouts: []const Seed = &.{},
};

pub const Seed = struct { ty: []const u8, layout: ml.Layout };

/// The check's sums over the live object set as of checkpoint `seq` (an end of epoch the store
/// retains: the restore point or any followed one).
pub fn scan(gpa: std.mem.Allocator, st: *store.Store, seq: u64, opt: Options) !Report {
    var dummy: Atomic(u64) = .init(0);
    const t0 = monoNs();
    var ls = try store.LiveScan.init(gpa, st, seq + 1);
    defer ls.deinit();
    var pkgs: Pkgs = .{ .st = st, .arena = undefined };
    var layouts: Layouts = undefined;
    layouts.init(gpa, .{ .ctx = &pkgs, .get = Pkgs.get });
    defer layouts.deinit();
    pkgs.arena = layouts.arena.allocator();
    for (opt.layouts) |sd| try layouts.seed(sd.ty, sd.layout);
    const nt: u32 = @max(1, opt.threads);
    const ws = try gpa.alloc(Worker, nt);
    defer gpa.free(ws);
    for (ws) |*w| {
        w.* = .{ .scan = &ls, .cancel = opt.cancel, .progress = opt.progress orelse &dummy };
        w.counter.init(gpa, &layouts);
    }
    defer for (ws) |*w| w.counter.deinit();
    const ts = try gpa.alloc(?std.Thread, nt);
    defer gpa.free(ts);
    for (ws, ts) |*w, *t| t.* = std.Thread.spawn(.{ .stack_size = 8 << 20 }, Worker.run, .{w}) catch null;
    for (ws, ts) |*w, t| {
        if (t) |th| th.join() else w.run();
    }
    var r: Report = .{ .checkpoint = seq };
    var wrapper: ?[]const u8 = null;
    var fields: [2]?[]const u8 = .{ null, null };
    for (ws) |*w| {
        if (w.err) |e| return e;
        r.totals.add(&w.counter.totals);
        if (w.wrapper) |x| wrapper = x;
        for (w.fields, &fields) |f, *o| if (f) |x| {
            o.* = x;
        };
    }
    const wc = sysstate.moveContents(wrapper orelse return error.NoSystemState) orelse return error.NoSystemState;
    const ver = sysstate.wrapperVersion(wc) orelse return error.NoSystemState;
    if (ver != 1 and ver != 2) return error.UnsupportedSystemState;
    const fbytes = fields[@intCast(ver - 1)] orelse return error.NoSystemState;
    const fc = sysstate.moveContents(fbytes) orelse return error.NoSystemState;
    const sf = try sysstate.storageFund(.{ .version = ver, .inner = sysstate.innerOfField(fc) orelse return error.NoSystemState });
    r.epoch = sf.epoch;
    r.storage_fund = sf.total_object_storage_rebates;
    r.ms = (monoNs() - t0) / std.time.ns_per_ms;
    return r;
}

fn monoNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// ------------------------------------------------------------------ expected values

pub const expected_file = "sui-conservation";

/// `<node dir>/sui-conservation`: "total_sui imbalance epoch\n" from the node's first check.
pub fn loadExpected(io: Io, dir: Io.Dir) ?Expected {
    var buf: [128]u8 = undefined;
    const s = dir.readFile(io, expected_file, &buf) catch return null;
    var it = std.mem.tokenizeAny(u8, s, " \n");
    const a = std.fmt.parseInt(u64, it.next() orelse return null, 10) catch return null;
    const b = std.fmt.parseInt(i64, it.next() orelse return null, 10) catch return null;
    return .{ .total_sui = a, .imbalance = b };
}

pub fn saveExpected(io: Io, dir: Io.Dir, e: Expected, epoch: u64) !void {
    var buf: [128]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{d} {d} {d}\n", .{ e.total_sui, e.imbalance, epoch });
    const tmp = expected_file ++ ".tmp";
    {
        const f = try dir.createFile(io, tmp, .{ .truncate = true });
        defer f.close(io);
        try f.writePositionalAll(io, s, 0);
        try f.sync(io);
    }
    try dir.rename(tmp, dir, expected_file, io);
}

// ------------------------------------------------------------------ node side

pub const Stats = struct {
    checks_ok: Atomic(u64) = .init(0),
    mismatches: Atomic(u64) = .init(0),
    /// 1 once a check failed (gauge).
    failed: Atomic(u64) = .init(0),
    last_epoch: Atomic(u64) = .init(0),
    // sui-node's authority_store gauges.
    latency_s: Atomic(u64) = .init(0),
    live_objects: Atomic(u64) = .init(0),
    imbalance: Atomic(i64) = .init(0),
    storage_fund: Atomic(u64) = .init(0),
    storage_fund_imbalance: Atomic(i64) = .init(0),
    unresolved: Atomic(u64) = .init(0),

    pub fn note(s: *Stats, r: *const Report, v: Verdict) void {
        s.last_epoch.store(r.epoch, .release);
        s.latency_s.store(r.ms / 1000, .release);
        s.live_objects.store(r.totals.objects, .release);
        s.imbalance.store(@intCast(std.math.clamp(r.supplyImbalance(), std.math.minInt(i64), std.math.maxInt(i64))), .release);
        s.storage_fund.store(r.storage_fund, .release);
        s.storage_fund_imbalance.store(r.imbalance(), .release);
        s.unresolved.store(r.totals.unresolved, .release);
        switch (v) {
            .first, .ok => _ = s.checks_ok.fetchAdd(1, .monotonic),
            .mismatch, .unresolved => {
                _ = s.mismatches.fetchAdd(1, .monotonic);
                s.failed.store(1, .release);
            },
        }
    }

    pub fn render(s: *const Stats, w: *Io.Writer) !void {
        try w.print(
            \\# TYPE zui_sui_conservation_checks_ok counter
            \\zui_sui_conservation_checks_ok {d}
            \\# TYPE zui_sui_conservation_mismatches counter
            \\zui_sui_conservation_mismatches {d}
            \\# TYPE zui_sui_conservation_failed gauge
            \\zui_sui_conservation_failed {d}
            \\# TYPE zui_sui_conservation_last_epoch gauge
            \\zui_sui_conservation_last_epoch {d}
            \\# TYPE zui_sui_conservation_unresolved gauge
            \\zui_sui_conservation_unresolved {d}
            \\# TYPE sui_conservation_check_latency gauge
            \\sui_conservation_check_latency {d}
            \\# TYPE sui_conservation_live_object_count gauge
            \\sui_conservation_live_object_count {d}
            \\# TYPE sui_conservation_imbalance gauge
            \\sui_conservation_imbalance {d}
            \\# TYPE sui_conservation_storage_fund gauge
            \\sui_conservation_storage_fund {d}
            \\# TYPE sui_conservation_storage_fund_imbalance gauge
            \\sui_conservation_storage_fund_imbalance {d}
            \\
        , .{
            s.checks_ok.load(.monotonic),    s.mismatches.load(.monotonic), s.failed.load(.monotonic),     s.last_epoch.load(.monotonic),
            s.unresolved.load(.monotonic),   s.latency_s.load(.monotonic),  s.live_objects.load(.monotonic), s.imbalance.load(.monotonic),
            s.storage_fund.load(.monotonic), s.storage_fund_imbalance.load(.monotonic),
        });
    }
};

/// Logs a report the way sui-node does, plus the verdict.
pub fn logReport(r: *const Report, v: Verdict, want: ?Expected, quiet: bool) void {
    std.log.info("sui conservation: scanned {d} live objects at checkpoint {d} in {d} ms; total SUI amount in the network: {d}, storage fund balance: {d}, total storage rebate: {d} at beginning of epoch {d} (supply difference {d})", .{ r.totals.objects, r.checkpoint, r.ms, r.totals.total_sui, r.storage_fund, r.totals.storage_rebate, r.epoch, r.supplyImbalance() });
    switch (v) {
        .first => std.log.info("sui conservation: first check of this node: expecting total SUI {d} and storage fund imbalance {d} at every later end of epoch", .{ r.totals.total_sui, r.imbalance() }),
        .ok => std.log.info("sui conservation: epoch {d} ok (total SUI and storage fund imbalance {d} as expected)", .{ r.epoch, r.imbalance() }),
        .mismatch, .unresolved => {
            const w = want orelse Expected{ .total_sui = 0, .imbalance = 0 };
            if (quiet) {
                std.log.warn("SUI CONSERVATION FAILED at the beginning of epoch {d} (test)", .{r.epoch});
            } else if (v == .unresolved) {
                std.log.err("SUI CONSERVATION FAILED at the beginning of epoch {d}: the SUI of {d} live objects cannot be computed (first {x})", .{ r.epoch, r.totals.unresolved, r.totals.first_unresolved orelse zero_id });
            } else {
                std.log.err("SUI CONSERVATION FAILED: Inconsistent state detected at epoch {d}: total sui: {d}, expecting {d}; total storage rebate: {d}, storage fund balance: {d}, imbalance {d}, expected imbalance: {d}", .{ r.epoch, r.totals.total_sui, w.total_sui, r.totals.storage_rebate, r.storage_fund, r.imbalance(), w.imbalance });
            }
        },
    }
}

// ------------------------------------------------------------------ tests

test "conservation: Balance<SUI> inside structs, vectors, enums; other balances ignored" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const sui: types.TypeTag = .{ .@"struct" = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "sui" }, .name = .{ .@"0" = "SUI" }, .type_args = &.{} } };
    const usdc: types.TypeTag = .{ .@"struct" = .{ .address = .{ .@"0" = @splat(7) }, .module = .{ .@"0" = "usdc" }, .name = .{ .@"0" = "USDC" }, .type_args = &.{} } };
    const balOf = struct {
        fn f(al: std.mem.Allocator, t: types.TypeTag) !ml.Layout {
            const s = try al.create(ml.Struct);
            const fs = try al.alloc(ml.Field, 1);
            fs[0] = .{ .name = "value", .layout = .u64 };
            s.* = .{ .type_ = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "balance" }, .name = .{ .@"0" = "Balance" }, .type_args = try al.dupe(types.TypeTag, &.{t}) }, .fields = fs };
            return .{ .@"struct" = s };
        }
    }.f;
    const sb = try balOf(a, sui);
    const ub = try balOf(a, usdc);
    const vec = try a.create(ml.Layout);
    vec.* = sb;
    const en = try a.create(ml.Enum);
    const v0 = try a.alloc(ml.Field, 0);
    const v1 = try a.alloc(ml.Field, 1);
    v1[0] = .{ .name = "b", .layout = sb };
    const vars = try a.alloc(ml.Variant, 2);
    vars[0] = .{ .name = "None", .tag = 0, .fields = v0 };
    vars[1] = .{ .name = "Some", .tag = 1, .fields = v1 };
    en.* = .{ .type_ = .{ .address = .{ .@"0" = @splat(9) }, .module = .{ .@"0" = "m" }, .name = .{ .@"0" = "E" }, .type_args = &.{} }, .variants = vars };
    const top = try a.create(ml.Struct);
    const fs = try a.alloc(ml.Field, 6);
    fs[0] = .{ .name = "id", .layout = .address };
    fs[1] = .{ .name = "a", .layout = sb };
    fs[2] = .{ .name = "u", .layout = ub };
    fs[3] = .{ .name = "v", .layout = .{ .vector = vec } };
    fs[4] = .{ .name = "e", .layout = .{ .@"enum" = en } };
    fs[5] = .{ .name = "n", .layout = .u64 };
    top.* = .{ .type_ = .{ .address = .{ .@"0" = @splat(9) }, .module = .{ .@"0" = "m" }, .name = .{ .@"0" = "T" }, .type_args = &.{} }, .fields = fs };
    const l: ml.Layout = .{ .@"struct" = top };
    try std.testing.expect(hasSui(l));
    try std.testing.expect(!hasSui(ub));
    var b: std.ArrayList(u8) = .empty;
    try b.appendNTimes(a, 1, 32);
    for ([_]u64{ 100, 5000 }) |x| try b.appendSlice(a, &std.mem.toBytes(x)); // a, u
    try b.append(a, 2); // v: 2 balances
    for ([_]u64{ 7, 11 }) |x| try b.appendSlice(a, &std.mem.toBytes(x));
    try b.append(a, 1); // e: Some(b)
    try b.appendSlice(a, &std.mem.toBytes(@as(u64, 1000)));
    try b.appendSlice(a, &std.mem.toBytes(@as(u64, 99999))); // n: not a balance
    var w: Walk = .{ .b = b.items };
    try w.value(l, false);
    try std.testing.expectEqual(b.items.len, w.at);
    try std.testing.expectEqual(@as(u128, 100 + 7 + 11 + 1000), w.sui);
    // Mutation: one MIST more in a nested balance is seen.
    b.items[b.items.len - 16] +%= 1;
    var w2: Walk = .{ .b = b.items };
    try w2.value(l, false);
    try std.testing.expectEqual(@as(u128, 100 + 7 + 11 + 1001), w2.sui);
    // A truncated value is an error (unresolved), never a silent 0.
    var w3: Walk = .{ .b = b.items[0 .. b.items.len - 3] };
    try std.testing.expectError(error.EndOfStream, w3.value(l, false));
}

test "conservation: judge mirrors sui-node's expected values" {
    var r: Report = .{ .checkpoint = 10, .epoch = 5, .storage_fund = 1000 };
    r.totals = .{ .objects = 3, .total_sui = total_supply_mist, .storage_rebate = 990 };
    try std.testing.expectEqual(Verdict.first, judge(&r, null));
    const e = r.expected().?;
    try std.testing.expectEqual(@as(i64, 10), e.imbalance);
    try std.testing.expectEqual(Verdict.ok, judge(&r, e));
    var m = r;
    m.totals.total_sui += 1; // one MIST appears
    try std.testing.expectEqual(Verdict.mismatch, judge(&m, e));
    m = r;
    m.totals.storage_rebate += 1; // one rebate MIST without the fund
    try std.testing.expectEqual(Verdict.mismatch, judge(&m, e));
    m = r;
    m.totals.unresolved = 1;
    try std.testing.expectEqual(Verdict.unresolved, judge(&m, e));
}

// A store fixture: two gas coins, a SUI address balance, a USDC coin and the system state whose
// storage fund holds every rebate. Conserving changes pass; one MIST more in a coin, or one
// rebate MIST more without the fund, fail.
const Fx = struct {
    fn id(n: u8) [32]u8 {
        var a: [32]u8 = @splat(0);
        a[0] = 0xc0;
        a[31] = n;
        return a;
    }
    fn obj(a: std.mem.Allocator, ty: []const u8, version: u64, contents: []const u8, rebate: u64) ![]u8 {
        var b: std.ArrayList(u8) = .empty;
        try b.append(a, 0); // Data::Move
        try b.appendSlice(a, ty);
        try b.append(a, 1); // has_public_transfer
        try b.appendSlice(a, &std.mem.toBytes(version));
        var n = contents.len;
        while (n >= 0x80) : (n >>= 7) try b.append(a, @as(u8, @intCast(n & 0x7f)) | 0x80);
        try b.append(a, @intCast(n));
        try b.appendSlice(a, contents);
        try b.append(a, 0); // Owner::AddressOwner
        try b.appendNTimes(a, 0xaa, 32);
        try b.append(a, 32); // previous_transaction
        try b.appendNTimes(a, 0x11, 32);
        try b.appendSlice(a, &std.mem.toBytes(rebate));
        return b.items;
    }
    fn cat(a: std.mem.Allocator, parts: []const []const u8) ![]u8 {
        return std.mem.concat(a, u8, parts);
    }
    fn otherTy(a: std.mem.Allocator, name: []const u8) ![]u8 {
        var b: std.ArrayList(u8) = .empty;
        try b.append(a, 0); // MoveObjectType_::Other
        var three: [32]u8 = @splat(0);
        three[31] = 3;
        try b.appendSlice(a, &three);
        try b.append(a, 10);
        try b.appendSlice(a, "sui_system");
        try b.append(a, @intCast(name.len));
        try b.appendSlice(a, name);
        try b.append(a, 0);
        return b.items;
    }
    fn st(a: std.mem.Allocator, fields: []const ml.Field, t: types.StructTag) !ml.Layout {
        const s = try a.create(ml.Struct);
        s.* = .{ .type_ = t, .fields = try a.dupe(ml.Field, fields) };
        return .{ .@"struct" = s };
    }
    fn tag(m: []const u8, n: []const u8, args: []const types.TypeTag) types.StructTag {
        return .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = m }, .name = .{ .@"0" = n }, .type_args = args };
    }
};

fn fxPut(b: *store.Batch, id: [32]u8, version: u64, bytes: []const u8) !void {
    var d: [32]u8 = @splat(@intCast(version & 0xff));
    d[0] = id[31];
    try b.putObject(&id, version, &d, bytes);
}

test "conservation: store fixture passes; one MIST or one rebate MIST more fails" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const sim = try store.sim.SimIo.init(gpa, 31, .{}, 8 << 20);
    defer sim.deinit();
    const cfg: store.Config = .{ .max_live_objects = 1024, .max_object_versions = 4096, .max_transactions = 1024, .max_checkpoints = 1024, .max_batch_bytes = 1 << 20, .max_batch_objects = 256, .max_segments = 64, .index_flush_interval = 8, .segment_reserve = 8 << 20, .seed = 7 };
    var s = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();

    const sui_tt: types.TypeTag = .{ .@"struct" = Fx.tag("sui", "SUI", &.{}) };
    const bal = try Fx.st(a, &.{.{ .name = "value", .layout = .u64 }}, Fx.tag("balance", "Balance", try a.dupe(types.TypeTag, &.{sui_tt})));
    const tbl = try Fx.st(a, &.{ .{ .name = "id", .layout = .address }, .{ .name = "size", .layout = .u64 } }, Fx.tag("table", "Table", &.{}));
    const u8v = try a.create(ml.Layout);
    u8v.* = .u8;
    const u64v = try a.create(ml.Layout);
    u64v.* = .u64;
    const fund = try Fx.st(a, &.{ .{ .name = "total_object_storage_rebates", .layout = bal }, .{ .name = "non_refundable_balance", .layout = bal } }, Fx.tag("storage_fund", "StorageFund", &.{}));
    const inner = try Fx.st(a, &.{
        .{ .name = "epoch", .layout = .u64 },           .{ .name = "protocol_version", .layout = .u64 },
        .{ .name = "system_state_version", .layout = .u64 }, .{ .name = "total_stake", .layout = .u64 },
        .{ .name = "active_validators", .layout = .{ .vector = u8v } }, .{ .name = "pending_active_validators", .layout = tbl },
        .{ .name = "pending_removals", .layout = .{ .vector = u64v } }, .{ .name = "staking_pool_mappings", .layout = tbl },
        .{ .name = "inactive_validators", .layout = tbl }, .{ .name = "validator_candidates", .layout = tbl },
        .{ .name = "at_risk_validators", .layout = .{ .vector = u8v } }, .{ .name = "extra_fields", .layout = tbl },
        .{ .name = "storage_fund", .layout = fund },
    }, Fx.tag("sui_system_state_inner", "SuiSystemStateInnerV2", &.{}));
    const field_l = try Fx.st(a, &.{ .{ .name = "id", .layout = .address }, .{ .name = "name", .layout = .u64 }, .{ .name = "value", .layout = inner } }, Fx.tag("dynamic_field", "Field", &.{}));
    const wrap_l = try Fx.st(a, &.{ .{ .name = "id", .layout = .address }, .{ .name = "version", .layout = .u64 } }, Fx.tag("sui_system", "SuiSystemState", &.{}));
    const wrap_ty = try Fx.otherTy(a, "SuiSystemState");
    const field_ty = try Fx.otherTy(a, "Field");
    const seeds = [_]Seed{ .{ .ty = wrap_ty, .layout = wrap_l }, .{ .ty = field_ty, .layout = field_l } };

    const usdc_ty = try Fx.cat(a, &.{ &.{ 3, 7 }, &(@as([32]u8, @splat(7))), &.{4}, "usdc", &.{4}, "USDC", &.{0} });
    const gas = struct {
        fn f(al: std.mem.Allocator, i: [32]u8, v: u64, value: u64, rebate: u64) ![]u8 {
            return Fx.obj(al, &.{1}, v, try Fx.cat(al, &.{ &i, &std.mem.toBytes(value) }), rebate);
        }
    }.f;
    const sysField = struct {
        fn f(al: std.mem.Allocator, ty: []const u8, rebates: u64, nonref: u64, rebate: u64) ![]u8 {
            var c: std.ArrayList(u8) = .empty;
            try c.appendSlice(al, &sys_field_v2);
            try c.appendSlice(al, &std.mem.toBytes(@as(u64, 2)));
            for ([_]u64{ 7, 90, 2, 5_000 }) |x| try c.appendSlice(al, &std.mem.toBytes(x)); // epoch 7
            try c.append(al, 0);
            try c.appendNTimes(al, 0, 40);
            try c.append(al, 0);
            try c.appendNTimes(al, 0, 120);
            try c.append(al, 0);
            try c.appendNTimes(al, 0, 40);
            try c.appendSlice(al, &std.mem.toBytes(rebates));
            try c.appendSlice(al, &std.mem.toBytes(nonref));
            return Fx.obj(al, ty, 1, c.items, rebate);
        }
    }.f;
    // Rebates: 10 + 20 + 5 + 7 + 0 + 3 = 45, all in the fund; supply 1000 + 2000 + 500 + 45 + 100.
    var b = try s.begin(10, 7);
    try b.checkpoint("s10", "");
    try fxPut(b, Fx.id(1), 1, try gas(a, Fx.id(1), 1, 1000, 10));
    try fxPut(b, Fx.id(2), 1, try gas(a, Fx.id(2), 1, 2000, 20));
    try fxPut(b, Fx.id(3), 1, try Fx.obj(a, &.{4}, 1, try Fx.cat(a, &.{ &Fx.id(3), &(@as([32]u8, @splat(0xaa))), &std.mem.toBytes(@as(u128, 500)) }), 5));
    try fxPut(b, Fx.id(4), 1, try Fx.obj(a, usdc_ty, 1, try Fx.cat(a, &.{ &Fx.id(4), &std.mem.toBytes(@as(u64, 777)) }), 7));
    try fxPut(b, sysstate.system_state_id, 1, try Fx.obj(a, wrap_ty, 1, try Fx.cat(a, &.{ &sysstate.system_state_id, &std.mem.toBytes(@as(u64, 2)) }), 0));
    try fxPut(b, sys_field_v2, 1, try sysField(a, field_ty, 45, 100, 3));
    try s.commit(b);

    const opt: Options = .{ .threads = 2, .layouts = &seeds };
    const r0 = try scan(gpa, s, 10, opt);
    try std.testing.expectEqual(@as(u64, 6), r0.totals.objects);
    try std.testing.expectEqual(@as(u64, 0), r0.totals.unresolved);
    try std.testing.expectEqual(@as(u128, 3645), r0.totals.total_sui);
    try std.testing.expectEqual(@as(u128, 45), r0.totals.storage_rebate);
    try std.testing.expectEqual(@as(u64, 45), r0.storage_fund);
    try std.testing.expectEqual(@as(u64, 7), r0.epoch);
    try std.testing.expectEqual(Verdict.first, judge(&r0, null));
    const want = r0.expected().?;

    // A conserving checkpoint: 300 MIST moves from coin 1 to coin 2, coin 1's rebate grows by 4
    // and the fund by 4.
    b = try s.begin(11, 7);
    try b.checkpoint("s11", "");
    try fxPut(b, Fx.id(1), 2, try gas(a, Fx.id(1), 2, 700, 14));
    try fxPut(b, Fx.id(2), 2, try gas(a, Fx.id(2), 2, 2300, 20));
    try fxPut(b, sys_field_v2, 2, try sysField(a, field_ty, 49, 96, 3));
    try s.commit(b);
    const r1 = try scan(gpa, s, 11, opt);
    try std.testing.expectEqual(Verdict.ok, judge(&r1, want));
    // The past view still answers the first epoch end.
    const r0b = try scan(gpa, s, 10, opt);
    try std.testing.expectEqual(Verdict.ok, judge(&r0b, want));

    // Mutation 1: one MIST appears in coin 2.
    b = try s.begin(12, 7);
    try b.checkpoint("s12", "");
    try fxPut(b, Fx.id(2), 3, try gas(a, Fx.id(2), 3, 2301, 20));
    try s.commit(b);
    const r2 = try scan(gpa, s, 12, opt);
    try std.testing.expectEqual(@as(u128, 3646), r2.totals.total_sui);
    try std.testing.expectEqual(Verdict.mismatch, judge(&r2, want));

    // Mutation 2: back to conserving, then one storage-rebate MIST more on coin 2 (the fund unchanged).
    b = try s.begin(13, 7);
    try b.checkpoint("s13", "");
    try fxPut(b, Fx.id(2), 4, try gas(a, Fx.id(2), 4, 2300, 21));
    try s.commit(b);
    const r3 = try scan(gpa, s, 13, opt);
    try std.testing.expectEqual(@as(u128, 3645), r3.totals.total_sui);
    try std.testing.expectEqual(@as(i64, -1), r3.imbalance());
    try std.testing.expectEqual(Verdict.mismatch, judge(&r3, want));

    // Mutation 3: a nested Balance<SUI> (the storage fund's non-refundable balance) one MIST up.
    b = try s.begin(14, 7);
    try b.checkpoint("s14", "");
    try fxPut(b, Fx.id(2), 5, try gas(a, Fx.id(2), 5, 2300, 20));
    try fxPut(b, sys_field_v2, 3, try sysField(a, field_ty, 49, 97, 3));
    try s.commit(b);
    const r4 = try scan(gpa, s, 14, opt);
    try std.testing.expectEqual(Verdict.mismatch, judge(&r4, want));

    // Without a layout for the system state the check cannot pass.
    const r5 = try scan(gpa, s, 11, .{ .threads = 1 });
    try std.testing.expectEqual(@as(u64, 2), r5.totals.unresolved);
    try std.testing.expectEqual(Verdict.unresolved, judge(&r5, want));
}
