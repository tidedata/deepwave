//! Packages for the Move-call executor: package metadata (original id, linkage table with the
//! protocol's special amendments, gas size), a per-thread move_vm.Runtime per epoch (system
//! packages change at epoch boundaries), and the linkage resolution of
//! `static_programmable_transactions/linkage` (resolution.rs, analysis.rs, single_linkage.rs).
const std = @import("std");
const types = @import("types");
const bcs = @import("bcs");
const protocol = @import("protocol");
const move_format = @import("move_format");
const move_vm = @import("move_vm");
const natives = @import("natives");
const objects = @import("../objects.zig");
const packages = @import("../packages.zig");

const Allocator = std.mem.Allocator;
pub const Id = [32]u8;

pub const Fail = struct { kind: types.ExecutionErrorKind, command: ?u64 = null };
/// Loader errors (a package or type the corpus cannot provide) end as unsupported.
pub const Error = error{ Fail, Unsupported } || Allocator.Error || move_vm.loader.LoadError;

/// Where an executor step reports a failure (`error.Fail`) or why the transaction is outside
/// the modeled set (`error.Unsupported`).
pub const Diag = struct {
    fail: Fail = .{ .kind = .InvariantViolation },
    why: []const u8 = "",

    pub fn failWith(d: *Diag, kind: types.ExecutionErrorKind, command: ?u64) error{Fail} {
        d.fail = .{ .kind = kind, .command = command };
        return error.Fail;
    }
    pub fn unsupported(d: *Diag, why: []const u8) error{Unsupported} {
        d.why = why;
        return error.Unsupported;
    }
};

pub const Pkg = struct {
    raw: []const u8,
    view: objects.ObjectView,
    version_id: Id,
    original_id: Id,
    version: u64,
    /// `linkage_table` of the verified package: dependencies' upgraded ids plus the package
    /// itself (original -> version id), sorted by original id. Amendments apply in `linkageTable`.
    linkage: []const [2]Id,
    type_origins: []const move_vm.loader.TypeOrigin,
    modules: []const move_vm.loader.NamedModule,
    gas_size: u64,
    vm: ?*move_vm.Package = null,
    /// `linkageTable` result (amendments applied), memoized for the cache's protocol version.
    amended: ?[]const [2]Id = null,

    pub fn prevTx(p: *const Pkg) Id {
        return p.raw[p.view.prev_tx_at + 1 ..][0..32].*;
    }
};

fn idLess(_: void, a: [2]Id, b: [2]Id) bool {
    return std.mem.order(u8, &a[0], &b[0]) == .lt;
}

/// One thread's package cache and VM runtime for one epoch.
pub const Cache = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    epoch: u64,
    pv: u64,
    chain: protocol.Chain = .mainnet,
    rt: *move_vm.Runtime,
    map: std.AutoHashMapUnmanaged(Id, ?*Pkg) = .empty,
    store: *const packages.Store,
    /// Native type arguments by type for `rt`'s datatypes (move_vm.Host.ty_cache).
    ty_args: move_vm.TyArgCache,
    /// Package objects as transaction inputs (parsed view, owner, gas-metering size), by id.
    objs: std.AutoHashMapUnmanaged(Id, ?*const PackageObject) = .empty,
    /// Packages the running transaction published or upgraded (Rust's per-transaction package
    /// store: a later command of the same transaction calls into them). Their `raw`/`view` are
    /// empty (never an input object). `endTransaction` clears it.
    tx_pkgs: std.AutoHashMapUnmanaged(Id, *Pkg) = .empty,

    /// Bytes last added to `cache_bytes` for this cache.
    reported: u64 = 0,
    /// Linkage results by the linker operations that made them (typing.zig: a call's
    /// `compute_call_linkage`, a transaction's unified linkage), for this cache's packages.
    link_memo: std.StringHashMapUnmanaged(LinkMemo) = .empty,
    /// Link contexts by root linkage (the unified linkage of transactions without Publish or
    /// Upgrade): the VM's resolved external calls stay cached across transactions.
    link_ctxs: std.StringHashMapUnmanaged(*move_vm.LinkCtx) = .empty,

    /// The transaction ended: its published packages leave the runtime and the overlay.
    pub fn endTransaction(c: *Cache, published: []const Id) void {
        for (published) |*id| c.rt.removePackage(id);
        c.tx_pkgs.clearRetainingCapacity();
    }

    pub const PackageObject = struct { view: objects.ObjectView, owner: types.Owner, gas_size: u64 };

    pub const LinkMemo = struct { linkage: []const [2]Id, entries: usize };

    pub fn linkCtx(c: *Cache, linkage: []const [2]Id) Allocator.Error!*move_vm.LinkCtx {
        const key = std.mem.sliceAsBytes(linkage);
        if (c.link_ctxs.get(key)) |lc| return lc;
        const a = c.arena.allocator();
        const kept = try a.dupe([2]Id, linkage);
        const lc = try a.create(move_vm.LinkCtx);
        lc.* = move_vm.LinkCtx.init(c.rt, try rootPackage(a, c.rt, kept));
        try c.link_ctxs.put(c.gpa, std.mem.sliceAsBytes(kept), lc);
        return lc;
    }

    pub fn memoLink(c: *Cache, key: []const u8, linkage: []const [2]Id, entries: usize) Allocator.Error!void {
        const a = c.arena.allocator();
        try c.link_memo.put(c.gpa, try a.dupe(u8, key), .{ .linkage = try a.dupe([2]Id, linkage), .entries = entries });
    }

    /// The package object for `id` as a transaction input (null: the store does not hold it).
    /// Package bytes never change for an id in an epoch, so the parse is kept.
    pub fn packageObject(c: *Cache, id: *const Id) !?*const PackageObject {
        if (c.objs.get(id.*)) |p| return p;
        const a = c.arena.allocator();
        const po: ?*const PackageObject = if (c.store.get(id, c.epoch)) |raw| blk: {
            const view = try objects.ObjectView.parse(raw);
            const n = try a.create(PackageObject);
            n.* = .{
                .view = view,
                .owner = try bcs.decode(types.Owner, a, raw[view.owner_at..view.prev_tx_at]),
                .gas_size = try objects.sizeForGasMetering(a, &view),
            };
            break :blk n;
        } else null;
        try c.objs.put(c.gpa, id.*, po);
        return po;
    }

    pub fn init(gpa: Allocator, store: *const packages.Store, epoch: u64, pv: u64, chain: protocol.Chain) !*Cache {
        const c = try gpa.create(Cache);
        c.* = .{ .gpa = gpa, .arena = .init(gpa), .epoch = epoch, .pv = pv, .chain = chain, .rt = try gpa.create(move_vm.Runtime), .store = store, .ty_args = .init(gpa) };
        const cfg = try protocol.get(pv, chain);
        c.rt.* = move_vm.Runtime.init(gpa, try binaryConfig(cfg));
        c.rt.validation = try move_vm.conformance.validation(c.rt.arena_state.allocator(), pv);
        _ = cache_count.fetchAdd(1, .monotonic);
        return c;
    }

    /// The package object for `id` (null: the corpus does not hold it).
    pub fn get(c: *Cache, id: *const Id) Error!?*Pkg {
        if (c.tx_pkgs.count() > 0) if (c.tx_pkgs.get(id.*)) |p| return p;
        if (c.map.get(id.*)) |p| return p;
        const raw = c.store.get(id, c.epoch) orelse {
            // A miss is final only for a fixed corpus. With a live source (a node store, a remote
            // node) the package can appear later in the epoch (published elsewhere, the node
            // catching up), so the next request asks again.
            if (c.store.lookup == null) try c.map.put(c.gpa, id.*, null);
            return null;
        };
        const p = parse(c.arena.allocator(), raw) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
        if (p == null and c.store.lookup != null) return null;
        try c.map.put(c.gpa, id.*, p);
        return p;
    }

    /// The package loaded into the VM runtime (validated like Rust's package cache does).
    pub fn load(c: *Cache, p: *Pkg) !*move_vm.Package {
        if (p.vm) |v| return v;
        p.vm = try c.rt.addPackage(.{
            .version_id = p.version_id,
            .original_id = p.original_id,
            .version = p.version,
            .linkage = p.linkage,
            .type_origins = p.type_origins,
            .modules = p.modules,
        });
        return p.vm.?;
    }
};

fn binaryConfig(cfg: *const protocol.ProtocolConfig) !move_format.BinaryConfig {
    const b = try protocol.derived.binaryConfig(cfg, null);
    var out: move_format.BinaryConfig = .{
        .max_binary_format_version = b.max_binary_format_version,
        .min_binary_format_version = b.min_binary_format_version,
        .check_no_extraneous_bytes = b.check_no_extraneous_bytes,
        .deprecate_global_storage_ops = b.deprecate_global_storage_ops,
        .type_parameter_index_max = b.type_parameter_index_max,
        .table_config = undefined,
    };
    inline for (@typeInfo(@TypeOf(b.table_config)).@"struct".field_names) |f| {
        @field(out.table_config, f) = @field(b.table_config, f);
    }
    return out;
}

fn parse(arena: Allocator, raw: []const u8) !*Pkg {
    const view = try objects.ObjectView.parse(raw);
    if (!view.is_package) return error.NotAPackage;
    const obj = try bcs.decode(types.Object, arena, raw);
    const mp = switch (obj.data) {
        .Package => |m| m,
        else => return error.NotAPackage,
    };
    const info = try natives.objrt.packageInfo(arena, &mp);
    const id = mp.id.@"0".@"0";
    var link = try arena.alloc([2]Id, mp.linkage_table.entries.len + 1);
    for (mp.linkage_table.entries, 0..) |e, i| link[i] = .{ e.key.@"0".@"0", e.value.upgraded_id.@"0".@"0" };
    link[link.len - 1] = .{ info.original_id, id };
    std.mem.sort([2]Id, link, {}, idLess);
    const origins = try arena.alloc(move_vm.loader.TypeOrigin, mp.type_origin_table.len);
    for (mp.type_origin_table, origins) |t, *o| o.* = .{ .module = t.module_name.@"0", .name = t.datatype_name.@"0", .defining = t.package.@"0".@"0" };
    const mods = try arena.alloc(move_vm.loader.NamedModule, mp.module_map.entries.len);
    for (mp.module_map.entries, mods) |e, *m| m.* = .{ .name = e.key.@"0", .bytes = e.value };
    const p = try arena.create(Pkg);
    p.* = .{
        .raw = raw,
        .view = view,
        .version_id = id,
        .original_id = info.original_id,
        .version = mp.version.@"0",
        .linkage = link,
        .type_origins = origins,
        .modules = mods,
        .gas_size = try objects.sizeForGasMetering(arena, &view),
    };
    return p;
}

threadlocal var caches: [4]?*Cache = @splat(null);
/// Every thread's package caches: how many, and their arena and VM runtime bytes as last seen by
/// `cacheFor` (a gauge for the node's status line).
pub var cache_count: std.atomic.Value(u64) = .init(0);
pub var cache_bytes: std.atomic.Value(u64) = .init(0);
/// Caches dropped and rebuilt because they outgrew `max_cache_bytes`.
pub var cache_rebuilds: std.atomic.Value(u64) = .init(0);
threadlocal var next_slot: usize = 0;

/// Memory one thread's package cache may hold (its arena and its VM runtime's) before it is
/// dropped and rebuilt: a long-running node loads every package it ever touches, and published
/// packages' bytes go to the cache arena.
pub var max_cache_bytes: usize = 1536 << 20;

/// When set, `cacheFor` for epoch E drops the thread's caches of epochs below E - epoch_window
/// (null: keep the last `caches.len` epochs, for callers that jump between epochs).
pub var epoch_window: ?u64 = null;
/// Set by a caller that runs epochs in order once nothing below this epoch runs again:
/// `cacheFor` drops the thread's caches of older epochs.
pub var min_epoch: std.atomic.Value(u64) = .init(0);

fn destroy(gpa: Allocator, old: *Cache) void {
    _ = cache_count.fetchSub(1, .monotonic);
    _ = cache_bytes.fetchSub(old.reported, .monotonic);
    old.objs.deinit(gpa);
    old.tx_pkgs.deinit(gpa);
    old.link_memo.deinit(gpa);
    {
        var it = old.link_ctxs.valueIterator();
        while (it.next()) |lc| lc.*.deinit();
        old.link_ctxs.deinit(gpa);
    }
    old.ty_args.deinit();
    old.rt.deinit();
    gpa.destroy(old.rt);
    old.map.deinit(gpa);
    old.arena.deinit();
    gpa.destroy(old);
}

/// This thread's cache for `epoch` (a few epochs are kept; the oldest is dropped).
pub fn cacheFor(gpa: Allocator, store: *const packages.Store, epoch: u64, pv: u64, chain: protocol.Chain) !*Cache {
    // A caller that runs epochs in order (the node) never asks for an epoch far behind again:
    // drop those caches now instead of when the slot comes round.
    const floor = min_epoch.load(.monotonic);
    if (epoch_window) |w| for (&caches) |*c| if (c.*) |x| if (x.epoch + w < epoch or x.epoch < floor) {
        destroy(gpa, x);
        c.* = null;
    };
    for (&caches) |*c| if (c.*) |x| if (x.epoch == epoch and x.store == store and x.chain == chain) {
        const held = x.arena.queryCapacity() + x.rt.arena_state.queryCapacity() + x.ty_args.bytes();
        if (held != x.reported) {
            _ = cache_bytes.fetchAdd(held, .monotonic);
            _ = cache_bytes.fetchSub(x.reported, .monotonic);
            x.reported = held;
        }
        if (held <= max_cache_bytes) return x;
        _ = cache_rebuilds.fetchAdd(1, .monotonic);
        destroy(gpa, x);
        c.* = try Cache.init(gpa, store, epoch, pv, chain);
        return c.*.?;
    };
    const slot = for (caches, 0..) |c, i| {
        if (c == null) break i;
    } else blk: {
        next_slot += 1;
        break :blk (next_slot - 1) % caches.len;
    };
    if (caches[slot]) |old| destroy(gpa, old);
    const c = try Cache.init(gpa, store, epoch, pv, chain);
    caches[slot] = c;
    return c;
}

/// Frees this thread's package caches (`gpa` is the allocator `cacheFor` was given). For worker
/// threads that exit while the process lives on (the node's simulate pool).
pub fn releaseThreadCaches(gpa: Allocator) void {
    for (&caches) |*slot| if (slot.*) |c| {
        destroy(gpa, c);
        slot.* = null;
    };
    next_slot = 0;
}

test "a live package source is asked again after a miss" {
    const gpa = std.testing.allocator;
    const Src = struct {
        var raw: ?[]const u8 = null;
        var calls: usize = 0;
        fn get(_: *const anyopaque, _: *const [32]u8, _: u64) ?[]const u8 {
            calls += 1;
            return raw;
        }
    };
    var store: packages.Store = .{ .loaded = true, .lookup = .{ .ctx = undefined, .get = Src.get } };
    const c = try Cache.init(gpa, &store, 1, protocol.max_protocol_version, .mainnet);
    defer destroy(gpa, c);
    const id: Id = @splat(7);
    try std.testing.expect((try c.get(&id)) == null);
    try std.testing.expect((try c.get(&id)) == null);
    try std.testing.expectEqual(@as(usize, 2), Src.calls); // not cached as missing
    try std.testing.expect(!c.map.contains(id));
    // a fixed corpus caches the miss
    var fixed: packages.Store = .{ .loaded = true };
    const c2 = try Cache.init(gpa, &fixed, 1, protocol.max_protocol_version, .mainnet);
    defer destroy(gpa, c2);
    try std.testing.expect((try c2.get(&id)) == null);
    try std.testing.expect(c2.map.contains(id));
}

// ---------------------------------------------------------------------------------------------
// Linkage (resolution.rs)

pub const Constraint = struct { exact: bool, version: u64, id: Id };
pub const Resolution = struct { original: Id, version: u64 };

pub const Table = struct {
    /// original id -> constraint (BTreeMap order is applied by `linkage`).
    res: std.AutoArrayHashMapUnmanaged(Id, Constraint) = .empty,
    /// object id -> (original id, version), first insertion wins (`all_versions_resolution_table`).
    all: std.AutoArrayHashMapUnmanaged(Id, Resolution) = .empty,
    seen: std.AutoHashMapUnmanaged(Id, void) = .empty,
};

pub const Linker = struct {
    arena: Allocator,
    cache: *Cache,
    cfg: *const protocol.ProtocolConfig,
    diag: *Diag,
    /// `Env.authoritative_packages`: the store holds every package there is.
    authoritative: bool = false,

    /// `get_package` over `CachedPackageStore`: a missing package is not `Ok(None)` (the
    /// InvalidLinkage branch) but a store error, since the VM's `load_packages` answers
    /// LINKER_ERROR for it, so Rust fails with PublishUpgradeMissingDependency (no command: the
    /// first lookup of every command's packages is the input type resolution linkage, before
    /// loading). In corpus replay the store is not authoritative (a certified transaction's
    /// packages exist on chain), so a missing one is a corpus gap and the transaction is
    /// unsupported.
    pub fn pkg(l: *Linker, id: *const Id) Error!*Pkg {
        return (try l.cache.get(id)) orelse if (l.authoritative)
            l.diag.failWith(.PublishUpgradeMissingDependency, null)
        else
            l.diag.unsupported("package not in corpus");
    }

    /// `linkage_table(pkg)` with `include_special_package_amendments` applied.
    pub fn linkageTable(l: *Linker, p: *Pkg) Error![]const [2]Id {
        if (p.amended) |x| return x;
        p.amended = try l.amendedLinkage(p);
        return p.amended.?;
    }

    fn amendedLinkage(l: *Linker, p: *const Pkg) Error![]const [2]Id {
        const am = l.cfg.include_special_package_amendments orelse return p.linkage;
        // the cache outlives the transaction (and its cfg is the cache's protocol version)
        const keep = l.cache.arena.allocator();
        for (am) |e| if (std.mem.eql(u8, &e.k, &p.version_id)) {
            var out: std.ArrayList([2]Id) = .empty;
            try out.appendSlice(keep, p.linkage);
            for (e.v) |pair| {
                for (out.items) |*x| {
                    if (std.mem.eql(u8, &x[0], &pair.k)) {
                        x[1] = pair.v;
                        break;
                    }
                } else try out.append(keep, .{ pair.k, pair.v });
            }
            std.mem.sort([2]Id, out.items, {}, idLess);
            return out.items;
        };
        return p.linkage;
    }

    pub fn addAndUnify(l: *Linker, t: *Table, id: *const Id, exact: bool) Error!void {
        const p = try l.pkg(id);
        const c: Constraint = .{ .exact = exact, .version = p.version, .id = p.version_id };
        const gop = try t.res.getOrPut(l.arena, p.original_id);
        if (!gop.found_existing) {
            gop.value_ptr.* = c;
        } else gop.value_ptr.* = try l.unify(gop.value_ptr.*, c);
        if (!t.all.contains(id.*)) try t.all.put(l.arena, id.*, .{ .original = p.original_id, .version = p.version });
    }

    fn unify(l: *Linker, a: Constraint, b: Constraint) Error!Constraint {
        if (a.exact and b.exact) {
            if (!std.mem.eql(u8, &a.id, &b.id) or a.version != b.version) return l.diag.failWith(.InvalidLinkage, null);
            return a;
        }
        if (!a.exact and !b.exact) return if (a.version > b.version) a else .{ .exact = false, .version = @max(a.version, b.version), .id = b.id };
        const e = if (a.exact) a else b;
        const al = if (a.exact) b else a;
        if (e.version < al.version) return l.diag.failWith(.InvalidLinkage, null);
        return e;
    }

    /// `resolution_table_with_native_packages`: 0x2, 0x3, 0x1 exact.
    pub fn withNatives(l: *Linker) Error!Table {
        var t: Table = .{};
        for ([_]u8{ 2, 3, 1 }) |b| {
            var id: Id = @splat(0);
            id[31] = b;
            try l.addAndUnify(&t, &id, true);
        }
        return t;
    }

    pub fn addTypeLinkages(l: *Linker, t: *Table, ids: []const Id) Error!void {
        for (ids) |*id| {
            if ((try t.seen.getOrPut(l.arena, id.*)).found_existing) continue;
            const p = try l.pkg(id);
            const deps = try l.linkageTable(p);
            try l.addAndUnify(t, &p.version_id, false);
            for (deps) |*d| try l.addAndUnify(t, &d[1], false);
        }
    }

    /// single_linkage.rs `add_package` (self first, then dependencies).
    pub fn addPackageSelfFirst(l: *Linker, t: *Table, id: *const Id, self_exact: bool, dep_exact: bool) Error!void {
        const p = try l.pkg(id);
        const deps = try l.linkageTable(p);
        try l.addAndUnify(t, id, self_exact);
        for (deps) |*d| try l.addAndUnify(t, &d[1], dep_exact);
    }

    /// analysis.rs `add_package` (dependencies first, then self).
    pub fn addPackageDepsFirst(l: *Linker, t: *Table, id: *const Id, self_exact: bool, dep_exact: bool) Error!void {
        const p = try l.pkg(id);
        const deps = try l.linkageTable(p);
        for (deps) |*d| try l.addAndUnify(t, &d[1], dep_exact);
        try l.addAndUnify(t, id, self_exact);
    }
};

/// `ResolvedLinkage::linkage`: (original, version id) sorted by original id.
pub fn resolved(arena: Allocator, t: *const Table) Allocator.Error![]const [2]Id {
    const out = try arena.alloc([2]Id, t.res.count());
    for (t.res.keys(), t.res.values(), out) |k, v, *o| o.* = .{ k, v.id };
    std.mem.sort([2]Id, out, {}, idLess);
    return out;
}

/// A root package for a session: only its `linkage` is read (LinkCtx resolution).
pub fn rootPackage(arena: Allocator, rt: *move_vm.Runtime, linkage: []const [2]Id) Allocator.Error!*move_vm.Package {
    const p = try arena.create(move_vm.Package);
    p.* = .{
        .rt = rt,
        .version_id = @splat(0xff),
        .original_id = @splat(0xff),
        .version = 0,
        .linkage = linkage,
        .type_origins = &.{},
        .modules = &.{},
    };
    return p;
}
