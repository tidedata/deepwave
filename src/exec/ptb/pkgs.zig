//! Packages for the Move-call executor: package metadata (original id, linkage table with the
//! protocol's special amendments, gas size), a per-thread move_vm.Runtime per epoch (system
//! packages change at epoch boundaries), and the linkage resolution of
//! `static_programmable_transactions/linkage` (resolution.rs, analysis.rs, single_linkage.rs).
//!
//! With `shared_enabled` (off by default), what is a pure function of a package object's bytes
//! (the parsed metadata, the input-object view, the deserialized modules and the digest of
//! their bytes) is made once per process in the `Shared` table and handed to every thread's
//! cache. What points into a runtime (modules, functions, datatypes, link contexts) stays per
//! thread.
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
    /// The shared-table entry the metadata slices point into (pinned by the cache); null for a
    /// package the thread parsed itself and for one the running transaction published.
    shared: ?*Shared.Entry = null,
    /// The entry's deserialized modules are counted in the cache's `shared_bytes`.
    pre_counted: bool = false,

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
    /// The shared-table entries this cache's packages come from, each pinned once (so the
    /// table keeps it). Unpinned by `destroy`.
    pins: std.AutoHashMapUnmanaged(Shared.Key, *Shared.Entry) = .empty,
    /// Bytes of the shared table this cache keeps there by its pins: each pinned entry's
    /// parsed record and copy of the object, and the deserialized modules of each package it
    /// loaded. Part of `held`.
    shared_bytes: usize = 0,
    /// `keep_across_epochs`: the version of each system package in force when the cache was
    /// made (`systemVersions`); null: the switch was off then, and the cache stays with its epoch.
    sys: ?SysVersions = null,
    /// Linkage results by the linker operations that made them (typing.zig: a call's
    /// `compute_call_linkage`, a transaction's unified linkage), for this cache's packages.
    link_memo: std.StringHashMapUnmanaged(LinkMemo) = .empty,
    /// Link contexts by root linkage (the unified linkage of transactions without Publish or
    /// Upgrade): the VM's resolved external calls stay cached across transactions. Each one is
    /// the `ctx` of a `Link`.
    link_ctxs: std.StringHashMapUnmanaged(*move_vm.LinkCtx) = .empty,
    /// What the link contexts hold outside the arena (each one's resolved-call table and inline
    /// cache, which the VM allocates from the runtime's allocator as calls resolve), as of each
    /// context's last `linkUsed`.
    link_bytes: usize = 0,

    /// A link context of `link_ctxs` with the bytes `link_bytes` counts for it.
    const Link = struct { ctx: move_vm.LinkCtx, counted: usize = 0 };

    /// Everything the cache holds, for `max_cache_bytes`: its arena, the VM runtime's and the
    /// type cache's, the table of every map, and the link contexts' tables. A cache gains one
    /// link context per distinct unified linkage it runs, so those are bounded with the rest:
    /// past the limit `cacheFor` drops the cache whole. Not counted: the runtime's lists of a
    /// package's versions (one pointer per loaded package).
    ///
    /// The shared-table entries the cache pins count in full (`shared_bytes`), as if the cache
    /// had parsed and deserialized them itself: the table cannot evict a pinned entry, so the
    /// pins of the live caches are bounded by the caches' own limit and nothing else. An entry
    /// several caches pin is counted by each; the table's own budget (`Shared.max_bytes`) is
    /// only for what no cache pins.
    pub fn held(c: *const Cache) usize {
        return c.arena.queryCapacity() + c.rt.arena_state.queryCapacity() + c.ty_args.bytes() +
            mapBytes(c.map) + mapBytes(c.objs) + mapBytes(c.tx_pkgs) + mapBytes(c.link_memo) + mapBytes(c.link_ctxs) +
            mapBytes(c.rt.by_version) + mapBytes(c.rt.by_original) + c.link_bytes + mapBytes(c.pins) + c.shared_bytes;
    }

    /// The shared-table entry for the package object `raw` (pinned by this cache), or null
    /// when the package is the thread's own to parse: the switch is off, the bytes are no
    /// package object, or the table's entry for this (id, version) holds other bytes.
    ///
    /// Every answer compares `raw` with the entry's own copy, also for an entry this cache
    /// already pinned and for bytes at an address it was given before: an entry is served only
    /// for the bytes it was parsed from, whatever the store did with its memory in between.
    fn sharedEntry(c: *Cache, raw: []const u8) Allocator.Error!?*Shared.Entry {
        if (!shared_enabled) return null;
        const key = Shared.keyOf(raw) orelse return null;
        if (c.pins.get(key)) |e| return if (std.mem.eql(u8, e.raw, raw)) e else null;
        const e = (try shared.acquire(raw)) orelse return null;
        c.pins.put(c.gpa, key, e) catch |err| {
            shared.release(e);
            return err;
        };
        c.shared_bytes += e.base_bytes;
        return e;
    }

    /// A transaction that ran on `lc` (a context `linkCtx` returned) ended: counts what its
    /// calls added to the context.
    pub fn linkUsed(c: *Cache, lc: *move_vm.LinkCtx) void {
        const l: *Link = @fieldParentPtr("ctx", lc);
        const ic_bytes: usize = if (lc.ic) |t| @sizeOf(@TypeOf(t.*)) else 0;
        const now = mapBytes(lc.ext) + ic_bytes;
        c.link_bytes = c.link_bytes - l.counted + now;
        l.counted = now;
    }

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
        const l = try a.create(Link);
        l.* = .{ .ctx = move_vm.LinkCtx.init(c.rt, try rootPackage(a, c.rt, kept)) };
        try c.link_ctxs.put(c.gpa, std.mem.sliceAsBytes(kept), &l.ctx);
        return &l.ctx;
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
            if (try c.sharedEntry(raw)) |e| {
                // The entry was parsed from equal bytes: the same offsets, owner and size, over
                // the store's own bytes.
                const n = try a.create(PackageObject);
                n.* = .{ .view = e.pkg.view, .owner = e.owner, .gas_size = e.pkg.gas_size };
                n.view.raw = raw;
                break :blk n;
            }
            const view = try objects.ObjectView.parse(raw);
            const n = try a.create(PackageObject);
            n.* = .{
                .view = view,
                .owner = try bcs.decode(types.Owner, a, raw[view.owner_at..view.prev_tx_at]),
                .gas_size = try objects.sizeForGasMetering(a, &view),
            };
            break :blk n;
        } else null;
        // A cache that outlives its epoch does not keep a live source's miss (as `get` never
        // does): the package can appear later, and "later" is no longer bounded by the epoch.
        if (po == null and c.sys != null and c.store.lookup != null) return null;
        try c.objs.put(c.gpa, id.*, po);
        return po;
    }

    pub fn init(gpa: Allocator, store: *const packages.Store, epoch: u64, pv: u64, chain: protocol.Chain) !*Cache {
        const c = try gpa.create(Cache);
        c.* = .{ .gpa = gpa, .arena = .init(gpa), .epoch = epoch, .pv = pv, .chain = chain, .rt = try gpa.create(move_vm.Runtime), .store = store, .ty_args = .init(gpa) };
        const cfg = try protocol.get(pv, chain);
        c.rt.* = move_vm.Runtime.init(gpa, try binaryConfig(cfg));
        c.rt.validation = try move_vm.conformance.validation(c.rt.arena_state.allocator(), pv, chain);
        if (keep_across_epochs) c.sys = systemVersions(store, epoch);
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
        if (try c.sharedEntry(raw)) |e| {
            // The table parsed equal bytes once: this thread's copy of the record points into
            // the entry, and `raw`/`view` stay over the store's own bytes as before.
            const p = try c.arena.allocator().create(Pkg);
            p.* = e.pkg;
            p.raw = raw;
            p.view.raw = raw;
            p.shared = e;
            try c.map.put(c.gpa, id.*, p);
            return p;
        }
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
            // the modules deserialized once per process for this binary config (null when one
            // of them does not deserialize: the runtime then finds and reports that itself)
            .pre = if (p.shared) |e| try c.predecoded(p, e) else null,
        });
        return p.vm.?;
    }

    /// The modules of `p`'s entry deserialized under this cache's binary config, counted once
    /// in `shared_bytes` (the entry keeps them as long as this cache pins it).
    fn predecoded(c: *Cache, p: *Pkg, e: *Shared.Entry) Allocator.Error!?*const move_vm.loader.Predecoded {
        const d = try shared.decodedFor(e, &c.rt.binary);
        if (!p.pre_counted) {
            p.pre_counted = true;
            c.shared_bytes += d.bytes;
        }
        return d.pre;
    }
};

/// The heap bytes of a std hash map's table: its header and every slot's metadata byte, key
/// and value (alignment padding aside).
fn mapBytes(m: anytype) usize {
    const cap: usize = m.capacity();
    if (cap == 0) return 0;
    const KV = @TypeOf(m).KV;
    return 3 * @sizeOf(usize) + cap * (1 + @sizeOf(@FieldType(KV, "key")) + @sizeOf(@FieldType(KV, "value")));
}

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

/// Runtime switches of the package cache (set before execution starts, or by the environment:
/// `readEnv`). Both paths they choose between are kept, and pkgs_exact.zig runs the same
/// transactions through each.
///
/// `shared_enabled`: packages come from the process-wide parsed-package table (`Shared`)
/// instead of being parsed and deserialized by every thread's cache. Off by default (the old
/// path, unchanged) until the table has passed its gate on the full corpus;
/// `ZUI_PKG_SHARED=1` turns it on.
pub var shared_enabled: bool = false;
/// `keep_across_epochs`: a thread's cache is kept across an epoch change that changes neither
/// the protocol version nor a system package, instead of one cache per epoch. Off by default;
/// `ZUI_PKG_KEEP_EPOCHS=1` turns it on.
pub var keep_across_epochs: bool = false;

var env_state: std.atomic.Value(u8) = .init(0);

/// Applies `ZUI_PKG_SHARED`, `ZUI_PKG_KEEP_EPOCHS` and `ZUI_PKG_SHARED_MB` (the table's
/// budget) once per process; `cacheFor` calls it. A caller that sets the switches itself calls
/// it first so the environment does not override them later.
pub fn readEnv() void {
    if (env_state.load(.acquire) == 2) return;
    if (env_state.cmpxchgStrong(0, 1, .acquire, .acquire) != null) {
        while (env_state.load(.acquire) != 2) std.Thread.yield() catch {};
        return;
    }
    defer env_state.store(2, .release);
    if (@import("builtin").link_libc) {
        if (std.c.getenv("ZUI_PKG_SHARED")) |v| {
            const t = std.mem.span(v);
            if (std.mem.eql(u8, t, "0")) shared_enabled = false;
            if (std.mem.eql(u8, t, "1")) shared_enabled = true;
        }
        if (std.c.getenv("ZUI_PKG_KEEP_EPOCHS")) |v| {
            const t = std.mem.span(v);
            if (std.mem.eql(u8, t, "0")) keep_across_epochs = false;
            if (std.mem.eql(u8, t, "1")) keep_across_epochs = true;
        }
        if (std.c.getenv("ZUI_PKG_SHARED_MB")) |v| {
            if (std.fmt.parseInt(usize, std.mem.span(v), 10)) |mb| {
                shared_budget = mb << 20;
                shared.setMaxBytes(shared_budget);
            } else |_| {}
        }
    }
}

/// What the shared table may hold in entries no cache pins when nothing splits a budget
/// (`setBudget`): 512 MiB, or `ZUI_PKG_SHARED_MB`.
pub var shared_budget: usize = 512 << 20;

/// Splits one package-cache budget of `total` bytes over the process: `caches` thread caches
/// (two per caching thread: this epoch's and the previous one's) and the shared table, which is
/// one table however many threads there are, so its part comes out of `total` once and the
/// caches share the rest. The table's part is `shared_budget`, at most half of `total`; with
/// the table off it is nothing, and the split is the one it always was (`total / caches`, at
/// least 32 MiB).
///
/// A cache counts the entries it pins in its own share (`Cache.held`) and the table's part
/// covers only what no cache pins, so everything the package caches hold stays within `total`
/// (but for the 32 MiB floor).
pub fn setBudget(total: usize, n_caches: usize) void {
    readEnv();
    const table: usize = if (shared_enabled) @min(shared_budget, total / 2) else 0;
    if (shared_enabled) shared.setMaxBytes(table);
    max_cache_bytes = @max(32 << 20, (total - table) / @max(n_caches, 1));
}

// ---------------------------------------------------------------------------------------------
// The shared table

const Spin = struct {
    state: std.atomic.Value(u32) = .init(0),

    fn acquire(l: *Spin) void {
        var n: u32 = 0;
        while (l.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            n +%= 1;
            if (n < 64) std.atomic.spinLoopHint() else std.Thread.yield() catch {};
        }
    }
    fn release(l: *Spin) void {
        l.state.store(0, .release);
    }
};

/// Parsed packages, process-wide: one entry per package object, keyed by (id, version) and
/// used only for bytes equal to the entry's own copy, so everything in an entry is a pure
/// function of the bytes it is served for.
///
/// - An entry holds the `Pkg` record `parse` makes (over the entry's copy of the bytes), the
///   input-object fields (`Cache.PackageObject`), and per binary config the deserialized
///   modules with the digest of their bytes (`move_vm.loader.Predecoded`). BCS parsing happens
///   once per package, module deserialization once per package and binary config, and the
///   Blake2b over the module bytes once per package, for the whole process.
/// - A thread's cache pins the entries its packages point into and unpins them when it is
///   destroyed. Only unpinned entries are evicted, least recently released first, when the
///   table is over `max_bytes`; so the table holds at most `max_bytes` plus what live caches
///   pin (each cache is itself bounded by `max_cache_bytes`).
/// - Packages a transaction publishes or upgrades never come here: they are built by run.zig
///   into the thread's `tx_pkgs` and leave with the transaction.
/// - Memory comes from `std.heap.smp_allocator` and is counted in `bytes`.
pub const Shared = struct {
    lock: Spin = .{},
    map: std.AutoHashMapUnmanaged(Key, *Entry) = .empty,
    /// Unpinned entries, most recently released first.
    head: ?*Entry = null,
    tail: ?*Entry = null,
    /// Bytes of every entry in `map` (under `lock`; `bytes_held` mirrors it for readers).
    bytes: usize = 0,
    /// Budget for `bytes`. Entries pinned by a live cache stay whatever it says.
    max_bytes: usize = 512 << 20,

    /// Packages parsed into the table (one BCS parse of a package object).
    cold_loads: std.atomic.Value(u64) = .init(0),
    /// Lookups answered by an entry already there.
    hits: std.atomic.Value(u64) = .init(0),
    /// Packages whose modules were deserialized into the table (per binary config).
    module_loads: std.atomic.Value(u64) = .init(0),
    /// Loads into a runtime answered by modules already deserialized.
    module_hits: std.atomic.Value(u64) = .init(0),
    /// Lookups whose bytes differ from the entry's for the same (id, version): the thread
    /// parses for itself (two stores serving different objects under one key).
    mismatches: std.atomic.Value(u64) = .init(0),
    evictions: std.atomic.Value(u64) = .init(0),
    /// Gauges: bytes and entries the table holds now.
    bytes_held: std.atomic.Value(u64) = .init(0),
    entries: std.atomic.Value(u64) = .init(0),

    const gpa = std.heap.smp_allocator;

    /// (package id, version): what names a package object's bytes on a chain.
    pub const Key = struct { id: Id, version: u64 };

    const Decoded = struct {
        arena: std.heap.ArenaAllocator,
        binary: move_format.BinaryConfig,
        /// Null: a module does not deserialize under `binary`.
        pre: ?*const move_vm.loader.Predecoded,
        /// What this node adds to the entry's bytes (set before the node is linked, then fixed).
        bytes: usize = 0,
        next: ?*Decoded,
    };

    /// `decodedFor`'s answer: the modules (null: one does not deserialize) and their bytes in
    /// the table.
    pub const DecodedRef = struct { pre: ?*const move_vm.loader.Predecoded, bytes: usize };

    pub const Entry = struct {
        key: Key,
        /// The table's copy of the object bytes; the parsed slices point into it.
        raw: []u8,
        arena: std.heap.ArenaAllocator,
        /// `parse` of `raw` (`vm`, `amended` and `shared` unset).
        pkg: Pkg,
        owner: types.Owner,
        /// Caches holding the entry, and its bytes in `Shared.bytes` (both under the table lock).
        pins: u32 = 0,
        bytes: usize = 0,
        /// `bytes` without the deserialized modules: the record, the copy of the object and
        /// the parse. Fixed once the entry is made (read without the lock).
        base_bytes: usize = 0,
        prev: ?*Entry = null,
        next: ?*Entry = null,
        /// Guards `decoded` and `digest`.
        lock: Spin = .{},
        decoded: ?*Decoded = null,
        /// `VerifiedSet.modulesDigest` of the modules, once they deserialized under some config.
        digest: ?[32]u8 = null,

        /// A new entry for `raw` (null: the bytes do not parse as a package, which the caller's
        /// own parse then reports).
        fn create(key: Key, raw: []const u8) Allocator.Error!?*Entry {
            const e = try gpa.create(Entry);
            errdefer gpa.destroy(e);
            const copy = try gpa.dupe(u8, raw);
            errdefer gpa.free(copy);
            e.* = .{ .key = key, .raw = copy, .arena = .init(gpa), .pkg = undefined, .owner = undefined };
            errdefer e.arena.deinit();
            const a = e.arena.allocator();
            const made: ?*Pkg = parse(a, copy) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => null,
            };
            const owner: ?types.Owner = if (made) |p| bcs.decode(types.Owner, a, copy[p.view.owner_at..p.view.prev_tx_at]) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => null,
            } else null;
            if (made == null or owner == null or !std.mem.eql(u8, &made.?.version_id, &key.id) or made.?.version != key.version) {
                e.arena.deinit();
                gpa.free(copy);
                gpa.destroy(e);
                return null;
            }
            e.pkg = made.?.*;
            e.owner = owner.?;
            e.bytes = @sizeOf(Entry) + copy.len + e.arena.queryCapacity();
            e.base_bytes = e.bytes;
            return e;
        }

        fn destroy(e: *Entry) void {
            var d = e.decoded;
            while (d) |x| {
                d = x.next;
                x.arena.deinit();
                gpa.destroy(x);
            }
            e.arena.deinit();
            gpa.free(e.raw);
            gpa.destroy(e);
        }
    };

    /// (id, version) from the head of a package object's BCS (`Data::Package`, then
    /// `MovePackage { id, version, .. }`); null for anything else.
    pub fn keyOf(raw: []const u8) ?Key {
        if (raw.len < 41 or raw[0] != 1) return null;
        return .{ .id = raw[1..33].*, .version = std.mem.readInt(u64, raw[33..41], .little) };
    }

    fn unlink(t: *Shared, e: *Entry) void {
        if (e.prev) |p| p.next = e.next else t.head = e.next;
        if (e.next) |n| n.prev = e.prev else t.tail = e.prev;
        e.prev = null;
        e.next = null;
    }

    fn pushHead(t: *Shared, e: *Entry) void {
        e.prev = null;
        e.next = t.head;
        if (t.head) |h| h.prev = e else t.tail = e;
        t.head = e;
    }

    /// Under the lock: pins `e` (an entry of `map`).
    fn pin(t: *Shared, e: *Entry) void {
        if (e.pins == 0) t.unlink(e);
        e.pins += 1;
    }

    /// Under the lock: takes unpinned entries off the table, oldest first, until it is within
    /// `limit`; returns them chained through `next` for `destroyChain` (after the lock).
    fn evict(t: *Shared, limit: usize) ?*Entry {
        var chain: ?*Entry = null;
        while (t.bytes > limit) {
            const e = t.tail orelse break;
            t.unlink(e);
            _ = t.map.remove(e.key);
            t.bytes -= e.bytes;
            e.next = chain;
            chain = e;
            _ = t.evictions.fetchAdd(1, .monotonic);
        }
        t.bytes_held.store(t.bytes, .monotonic);
        t.entries.store(t.map.count(), .monotonic);
        return chain;
    }

    fn destroyChain(chain: ?*Entry) void {
        var c = chain;
        while (c) |e| {
            c = e.next;
            e.destroy();
        }
    }

    /// The entry whose bytes equal `raw`, pinned for the caller (`release` unpins); it is made
    /// on the first request. Null: `raw` is no package object, or the entry for its
    /// (id, version) holds different bytes.
    pub fn acquire(t: *Shared, raw: []const u8) Allocator.Error!?*Entry {
        const key = keyOf(raw) orelse return null;
        var fresh: ?*Entry = null;
        while (true) {
            t.lock.acquire();
            if (t.map.get(key)) |e| {
                t.pin(e);
                t.lock.release();
                if (fresh) |f| f.destroy(); // another thread made it first
                if (std.mem.eql(u8, e.raw, raw)) {
                    _ = t.hits.fetchAdd(1, .monotonic);
                    return e;
                }
                _ = t.mismatches.fetchAdd(1, .monotonic);
                t.release(e);
                return null;
            }
            if (fresh) |f| {
                t.map.put(gpa, key, f) catch {
                    t.lock.release();
                    f.destroy();
                    return error.OutOfMemory;
                };
                f.pins = 1;
                t.bytes += f.bytes;
                const chain = t.evict(t.max_bytes);
                t.lock.release();
                destroyChain(chain);
                _ = t.cold_loads.fetchAdd(1, .monotonic);
                return f;
            }
            t.lock.release();
            // Parse outside the lock; the loop then inserts it or finds another thread's.
            fresh = (try Entry.create(key, raw)) orelse return null;
        }
    }

    pub fn release(t: *Shared, e: *Entry) void {
        t.lock.acquire();
        e.pins -= 1;
        if (e.pins == 0) t.pushHead(e);
        const chain = t.evict(t.max_bytes);
        t.lock.release();
        destroyChain(chain);
    }

    /// The modules of `e` (pinned by the caller) deserialized under `binary`, made on the
    /// first request for that config; null when one of them does not deserialize under it.
    pub fn decodedFor(t: *Shared, e: *Entry, binary: *const move_format.BinaryConfig) Allocator.Error!DecodedRef {
        e.lock.acquire();
        defer e.lock.release();
        var d = e.decoded;
        while (d) |x| : (d = x.next) if (std.meta.eql(x.binary, binary.*)) {
            _ = t.module_hits.fetchAdd(1, .monotonic);
            return .{ .pre = x.pre, .bytes = x.bytes };
        };
        const node = try gpa.create(Decoded);
        node.* = .{ .arena = .init(gpa), .binary = binary.*, .pre = null, .next = e.decoded };
        node.pre = move_vm.loader.predecode(node.arena.allocator(), e.pkg.modules, binary, e.digest) catch |err| {
            node.arena.deinit();
            gpa.destroy(node);
            return err;
        };
        if (node.pre) |p| {
            e.digest = p.digest;
        } else {
            // keep the verdict, not the partial work
            node.arena.deinit();
            node.arena = .init(gpa);
        }
        const added = @sizeOf(Decoded) + node.arena.queryCapacity();
        node.bytes = added;
        e.decoded = node;
        _ = t.module_loads.fetchAdd(1, .monotonic);
        t.lock.acquire();
        e.bytes += added;
        t.bytes += added;
        const chain = t.evict(t.max_bytes);
        t.lock.release();
        destroyChain(chain);
        return .{ .pre = node.pre, .bytes = added };
    }

    /// Sets the budget and evicts down to it.
    pub fn setMaxBytes(t: *Shared, limit: usize) void {
        t.lock.acquire();
        t.max_bytes = limit;
        const chain = t.evict(limit);
        t.lock.release();
        destroyChain(chain);
    }

    /// Drops every unpinned entry (tests; a process that wants the memory back).
    pub fn clear(t: *Shared) void {
        t.lock.acquire();
        const chain = t.evict(0);
        if (t.map.count() == 0) t.map.clearAndFree(gpa);
        t.lock.release();
        destroyChain(chain);
    }
};

/// The process's parsed-package table.
pub var shared: Shared = .{};

// ---------------------------------------------------------------------------------------------
// Caches across epochs (`keep_across_epochs`)

/// sui-types `SYSTEM_PACKAGE_ADDRESSES` (`packages.isSystemPackage`): the packages that change
/// in place, at an epoch change.
pub const system_ids: [5]Id = blk: {
    var ids: [5]Id = undefined;
    for ([_]u16{ 0x1, 0x2, 0x3, 0xb, 0xdee9 }, &ids) |tail, *id| {
        id.* = @splat(0);
        std.mem.writeInt(u16, id[30..32], tail, .big);
    }
    break :blk ids;
};

/// The version of each system package the store serves at an epoch (null: it has none).
pub const SysVersions = [system_ids.len]?u64;

/// The system packages `store` serves at an epoch: each one's version and its object bytes.
const SysState = struct { versions: SysVersions, raws: [system_ids.len]?[]const u8 };

/// What `store` serves for the system packages at `epoch`, read from the store now. Null when
/// one of them is not a package object (no cache is then kept across an epoch change on its
/// account).
fn systemState(store: *const packages.Store, epoch: u64) ?SysState {
    var out: SysState = .{ .versions = @splat(null), .raws = @splat(null) };
    for (&system_ids, &out.versions, &out.raws) |*id, *v, *r| {
        const raw = store.get(id, epoch) orelse continue;
        const key = Shared.keyOf(raw) orelse return null;
        if (!std.mem.eql(u8, &key.id, id)) return null;
        v.* = key.version;
        r.* = raw;
    }
    return out;
}

/// The version of each system package `store` serves at `epoch` (`systemState`).
pub fn systemVersions(store: *const packages.Store, epoch: u64) ?SysVersions {
    return if (systemState(store, epoch)) |s| s.versions else null;
}

/// Caches moved to another epoch by `keep_across_epochs`, and moves refused because the cache
/// held a system package other than the one its key names.
pub var epoch_moves: std.atomic.Value(u64) = .init(0);
pub var epoch_moves_refused: std.atomic.Value(u64) = .init(0);

/// `keep_across_epochs`: when this thread has no cache for `epoch` but has one of another
/// epoch whose contents are exactly what `epoch` needs, that cache becomes the cache of
/// `epoch`. `cacheFor` then finds it by epoch as it always did.
///
/// Why the epoch was in the key, and what covers each reason now:
/// - System packages change in place at an epoch change (the store answers `get(id, epoch)`
///   by epoch). Covered: the cache's `sys` (the versions in force when it was made) must equal
///   the versions in force at `epoch` (read from the store on every move, never remembered),
///   and every system package the cache already holds (`map`, `objs`) must be that version
///   with the very bytes the store serves at `epoch`, or that same miss. A cache therefore
///   never holds two versions of a system package, and the link memo and link contexts (keyed
///   by ids, which system packages keep across versions) stay right.
/// - The protocol config: the runtime's binary config and verifier config, the linkage
///   amendments kept on each `Pkg`, the feature flags behind the memoized linkage. Covered:
///   the protocol version and the chain must be equal (the config is a function of the two).
/// - Type origin tables and module bytes belong to a package version: user packages are
///   immutable per id, system packages are covered by `sys`.
/// - A miss remembered for a fixed corpus stays a miss: the corpus serves a user package at
///   every epoch or at none, and a system package's absence is part of `sys`.
/// Nothing else in a cache depends on the epoch: datatypes resolve by runtime id from whichever
/// version loaded first, as they already did inside one epoch (upgrades keep layouts).
fn adopt(store: *const packages.Store, epoch: u64, pv: u64, chain: protocol.Chain) void {
    for (caches) |c| if (c) |x| if (x.epoch == epoch and x.store == store and x.chain == chain) return;
    var want: ?SysState = null;
    for (caches) |c| if (c) |x| {
        if (x.store != store or x.chain != chain or x.pv != pv) continue;
        const have = x.sys orelse continue;
        if (want == null) want = systemState(store, epoch) orelse return;
        if (!std.meta.eql(have, want.?.versions)) continue;
        if (!holdsOnly(x, &want.?)) {
            _ = epoch_moves_refused.fetchAdd(1, .monotonic);
            continue;
        }
        x.epoch = epoch;
        _ = epoch_moves.fetchAdd(1, .monotonic);
        return;
    };
}

/// The package cache's counters on one line (a status line, the end of a replay). The thread
/// caches' bytes include the table entries they pin (`Cache.held`), each cache counting its own.
pub fn statsLine(buf: []u8) []const u8 {
    const t = &shared;
    return std.fmt.bufPrint(buf, "package cache: shared table {s}, {d} packages, {d} KiB held (budget {d} MiB), {d} cold package loads, {d} hits, {d} module loads, {d} module hits, {d} mismatches, {d} evictions; thread caches: {d} holding {d} KiB, {d} rebuilds; kept across epochs {s}, {d} moves, {d} refused", .{
        if (shared_enabled) "on" else "off",
        t.entries.load(.monotonic),
        t.bytes_held.load(.monotonic) >> 10,
        t.max_bytes >> 20,
        t.cold_loads.load(.monotonic),
        t.hits.load(.monotonic),
        t.module_loads.load(.monotonic),
        t.module_hits.load(.monotonic),
        t.mismatches.load(.monotonic),
        t.evictions.load(.monotonic),
        cache_count.load(.monotonic),
        cache_bytes.load(.monotonic) >> 10,
        cache_rebuilds.load(.monotonic),
        if (keep_across_epochs) "on" else "off",
        epoch_moves.load(.monotonic),
        epoch_moves_refused.load(.monotonic),
    }) catch buf[0..0];
}

/// Every system package `c` has an answer for is the object `want` names, by version and by
/// bytes (a version number alone does not name the bytes: a store may serve other bytes under
/// it at another epoch), or the same miss.
fn holdsOnly(c: *const Cache, want: *const SysState) bool {
    for (&system_ids, want.versions, want.raws) |*id, v, raw| {
        if (c.map.get(id.*)) |entry| {
            if (entry) |p| {
                if (v == null or p.version != v.? or !std.mem.eql(u8, p.raw, raw.?)) return false;
            } else if (v != null) return false;
        }
        if (c.objs.get(id.*)) |entry| {
            if (entry) |po| {
                if (v == null or po.view.version != v.? or !std.mem.eql(u8, po.view.raw, raw.?)) return false;
            } else if (v != null) return false;
        }
    }
    return true;
}

threadlocal var caches: [4]?*Cache = @splat(null);
/// Every thread's package caches: how many, and the bytes they hold (`Cache.held`) as last seen
/// by `cacheFor` (a gauge for the node's status line).
pub var cache_count: std.atomic.Value(u64) = .init(0);
pub var cache_bytes: std.atomic.Value(u64) = .init(0);
/// Caches dropped and rebuilt because they outgrew `max_cache_bytes`.
pub var cache_rebuilds: std.atomic.Value(u64) = .init(0);
threadlocal var next_slot: usize = 0;

/// Memory one thread's package cache may hold (`Cache.held`) before it is dropped and rebuilt:
/// a long-running node loads every package it ever touches, published packages' bytes go to
/// the cache arena, and every distinct linkage it runs leaves a link context.
pub var max_cache_bytes: usize = 1536 << 20;

/// When set, `cacheFor` for epoch E drops the thread's caches of epochs below E - epoch_window
/// (null: keep the last `caches.len` epochs, for callers that jump between epochs).
pub var epoch_window: ?u64 = null;
/// Set by a caller that runs epochs in order once nothing below this epoch runs again:
/// `cacheFor` drops the thread's caches of older epochs.
pub var min_epoch: std.atomic.Value(u64) = .init(0);

/// Frees a cache with the allocator it was made with (`Cache.gpa`), whichever allocator the
/// caller at hand was given: a thread that calls `cacheFor` with two allocators (the node's
/// and a simulation engine's) must not free one's cache through the other.
fn destroy(old: *Cache) void {
    const gpa = old.gpa;
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
    // Last: the runtime and the records that pointed into the entries are gone.
    {
        var it = old.pins.valueIterator();
        while (it.next()) |e| shared.release(e.*);
        old.pins.deinit(gpa);
    }
    gpa.destroy(old);
}

/// This thread's cache for `epoch` (a few epochs are kept; the oldest is dropped). With
/// `keep_across_epochs`, a cache of another epoch that holds exactly what `epoch` needs is
/// first moved to `epoch` (`adopt`).
pub fn cacheFor(gpa: Allocator, store: *const packages.Store, epoch: u64, pv: u64, chain: protocol.Chain) !*Cache {
    if (env_state.load(.monotonic) != 2) readEnv();
    if (keep_across_epochs) adopt(store, epoch, pv, chain);
    // A caller that runs epochs in order (the node) never asks for an epoch far behind again:
    // drop those caches now instead of when the slot comes round.
    const floor = min_epoch.load(.monotonic);
    if (epoch_window) |w| for (&caches) |*c| if (c.*) |x| if (x.epoch + w < epoch or x.epoch < floor) {
        destroy(x);
        c.* = null;
    };
    for (&caches) |*c| if (c.*) |x| if (x.epoch == epoch and x.store == store and x.chain == chain) {
        const held = x.held();
        if (held != x.reported) {
            _ = cache_bytes.fetchAdd(held, .monotonic);
            _ = cache_bytes.fetchSub(x.reported, .monotonic);
            x.reported = held;
        }
        if (held <= max_cache_bytes) return x;
        _ = cache_rebuilds.fetchAdd(1, .monotonic);
        destroy(x);
        c.* = try Cache.init(gpa, store, epoch, pv, chain);
        return c.*.?;
    };
    const slot = for (caches, 0..) |c, i| {
        if (c == null) break i;
    } else blk: {
        next_slot += 1;
        break :blk (next_slot - 1) % caches.len;
    };
    if (caches[slot]) |old| destroy(old);
    const c = try Cache.init(gpa, store, epoch, pv, chain);
    caches[slot] = c;
    return c;
}

/// Frees this thread's package caches, each with the allocator it was made with (`destroy`).
/// For worker threads that exit while the process lives on (the node's simulate pool). The
/// caller names no allocator: the node's exit hooks passed `smp_allocator` for caches the
/// simulate engine had made with the node's allocator.
pub fn releaseThreadCaches() void {
    for (&caches) |*slot| if (slot.*) |c| {
        destroy(c);
        slot.* = null;
    };
    next_slot = 0;
}

test {
    _ = @import("pkgs_exact.zig");
}

test "releaseThreadCaches frees a cache with the allocator that made it" {
    // The testing allocator fails the test on a leak, and a free through any other allocator
    // (as the exit hooks did with smp_allocator) does not reach it.
    // One cache per epoch here, whatever the environment says (kept across epochs, the two
    // requests below would share one).
    readEnv();
    const keep = keep_across_epochs;
    defer keep_across_epochs = keep;
    keep_across_epochs = false;
    errdefer releaseThreadCaches();
    var store: packages.Store = .{ .loaded = true };
    const pv = protocol.max_protocol_version;
    const before = cache_count.load(.monotonic);
    const a = try cacheFor(std.testing.allocator, &store, 3, pv, .mainnet);
    const b = try cacheFor(std.testing.allocator, &store, 4, pv, .mainnet);
    try std.testing.expect(a != b);
    try std.testing.expectEqual(std.testing.allocator.ptr, a.gpa.ptr);
    // Something in every part of a cache: its arena, a map and a link context.
    const linkage: [1][2]Id = .{.{ @splat(1), @splat(2) }};
    _ = try a.linkCtx(&linkage);
    const id: Id = @splat(9);
    try std.testing.expect((try b.get(&id)) == null);
    try std.testing.expectEqual(before + 2, cache_count.load(.monotonic));
    releaseThreadCaches();
    try std.testing.expectEqual(before, cache_count.load(.monotonic));
    for (caches) |slot| try std.testing.expect(slot == null);
    // Nothing left to free: a second call is a no-op.
    releaseThreadCaches();
}

/// Test allocator that forwards to another and counts what is live through it.
const Counting = struct {
    child: Allocator,
    live: isize = 0,

    fn allocator(x: *Counting) Allocator {
        return .{ .ptr = x, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(p: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
        const x: *Counting = @ptrCast(@alignCast(p));
        const out = x.child.rawAlloc(len, al, ra) orelse return null;
        x.live += 1;
        return out;
    }
    fn resize(p: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) bool {
        const x: *Counting = @ptrCast(@alignCast(p));
        return x.child.rawResize(m, al, n, ra);
    }
    fn remap(p: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const x: *Counting = @ptrCast(@alignCast(p));
        return x.child.rawRemap(m, al, n, ra);
    }
    fn free(p: *anyopaque, m: []u8, al: std.mem.Alignment, ra: usize) void {
        const x: *Counting = @ptrCast(@alignCast(p));
        x.live -= 1;
        x.child.rawFree(m, al, ra);
    }
};

test "cacheFor frees a cache it replaces with the allocator that made it, not the caller's" {
    var one: Counting = .{ .child = std.testing.allocator };
    var two: Counting = .{ .child = std.testing.allocator };
    const saved = max_cache_bytes;
    defer max_cache_bytes = saved;
    // One cache per epoch here, whatever the environment says.
    readEnv();
    const keep = keep_across_epochs;
    defer keep_across_epochs = keep;
    keep_across_epochs = false;
    releaseThreadCaches();
    defer releaseThreadCaches();
    var store: packages.Store = .{ .loaded = true };
    const pv = protocol.max_protocol_version;
    // A cache made through `one`, with something in its arena and maps.
    const c = try cacheFor(one.allocator(), &store, 3, pv, .mainnet);
    const linkage: [1][2]Id = .{.{ @splat(1), @splat(2) }};
    _ = try c.linkCtx(&linkage);
    const id: Id = @splat(9);
    try std.testing.expect((try c.get(&id)) == null);
    try std.testing.expect(one.live > 0);
    try std.testing.expectEqual(@as(isize, 0), two.live);
    // The same thread asks through `two`, and the cache is over its limit: it is dropped and
    // rebuilt. Everything `one` gave out goes back through `one`, nothing of it through `two`.
    max_cache_bytes = 0;
    const fresh = try cacheFor(two.allocator(), &store, 3, pv, .mainnet);
    try std.testing.expect(fresh != c);
    try std.testing.expectEqual(@as(isize, 0), one.live);
    try std.testing.expect(two.live > 0);
    // The other ways a cache leaves: the slot coming round, and the epoch window.
    max_cache_bytes = saved;
    for (10..10 + caches.len) |e| _ = try cacheFor(one.allocator(), &store, e, pv, .mainnet);
    try std.testing.expectEqual(@as(isize, 0), two.live);
    const window = epoch_window;
    defer epoch_window = window;
    epoch_window = 1;
    _ = try cacheFor(two.allocator(), &store, 100, pv, .mainnet);
    try std.testing.expectEqual(@as(isize, 0), one.live);
    releaseThreadCaches();
    try std.testing.expectEqual(@as(isize, 0), two.live);
}

test "a live package source is asked again after a miss" {
    const gpa = std.testing.allocator;
    const Src = struct {
        var raw: ?[]const u8 = null;
        var calls: usize = 0;
        fn get(_: *const anyopaque, id: *const [32]u8, _: u64) ?[]const u8 {
            if (packages.isSystemPackage(id)) return null; // the cross-epoch key's reads, when on
            calls += 1;
            return raw;
        }
    };
    var store: packages.Store = .{ .loaded = true, .lookup = .{ .ctx = undefined, .get = Src.get } };
    const c = try Cache.init(gpa, &store, 1, protocol.max_protocol_version, .mainnet);
    defer destroy(c);
    const id: Id = @splat(7);
    try std.testing.expect((try c.get(&id)) == null);
    try std.testing.expect((try c.get(&id)) == null);
    try std.testing.expectEqual(@as(usize, 2), Src.calls); // not cached as missing
    try std.testing.expect(!c.map.contains(id));
    // a fixed corpus caches the miss
    var fixed: packages.Store = .{ .loaded = true };
    const c2 = try Cache.init(gpa, &fixed, 1, protocol.max_protocol_version, .mainnet);
    defer destroy(c2);
    try std.testing.expect((try c2.get(&id)) == null);
    try std.testing.expect(c2.map.contains(id));
}

test "a cache kept across epochs asks a live source again for a package object after a miss" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const Src = struct {
        var raw: ?[]const u8 = null;
        var calls: usize = 0;
        fn get(_: *const anyopaque, id: *const [32]u8, _: u64) ?[]const u8 {
            if (packages.isSystemPackage(id)) return null; // the key's reads
            calls += 1;
            return raw;
        }
    };
    readEnv();
    const saved = keep_across_epochs;
    defer keep_across_epochs = saved;
    const vers = try natives.framework.load(a);
    const p = &vers[vers.len - 1].packages[0];
    const id: Id = @splat(0x71);
    const prev: Id = @splat(1);
    const obj = try natives.framework.packageObjectBcs(a, p, 1, &prev);
    @memcpy(obj[1..33], &id);
    var store: packages.Store = .{ .loaded = true, .lookup = .{ .ctx = undefined, .get = Src.get } };
    shared.clear();
    defer shared.clear();
    for ([_]bool{ false, true }) |keep| {
        keep_across_epochs = keep;
        Src.raw = null;
        Src.calls = 0;
        const c = try Cache.init(gpa, &store, 1, protocol.max_protocol_version, .mainnet);
        defer destroy(c);
        try std.testing.expect((try c.packageObject(&id)) == null);
        try std.testing.expect((try c.packageObject(&id)) == null);
        Src.raw = obj;
        if (keep) {
            // asked each time, and the package is found once the source has it
            try std.testing.expectEqual(@as(usize, 2), Src.calls);
            try std.testing.expect(!c.objs.contains(id));
            try std.testing.expect((try c.packageObject(&id)) != null);
        } else {
            // the per-epoch cache keeps the miss until its epoch ends, as before
            try std.testing.expectEqual(@as(usize, 1), Src.calls);
            try std.testing.expect((try c.packageObject(&id)) == null);
        }
    }
}

test "a cache is not moved to an epoch where a system package has other bytes under the same version" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    readEnv();
    const saved = keep_across_epochs;
    defer keep_across_epochs = saved;
    keep_across_epochs = true;
    releaseThreadCaches();
    defer releaseThreadCaches();
    defer shared.clear(); // runs after the caches let go

    // Every system package at version 5 from epoch 0, and 0x2 again from epoch 3: the same
    // version over other bytes (another previous transaction).
    const vers = try natives.framework.load(a);
    const v = &vers[vers.len - 1];
    const two = system_ids[1];
    const prev_a: Id = @splat(0xaa);
    const prev_b: Id = @splat(0xbb);
    var store: packages.Store = .{ .loaded = true };
    var found_two = false;
    for (v.packages) |*p| {
        const gop = try store.system.getOrPut(a, p.id);
        gop.value_ptr.* = .empty;
        try gop.value_ptr.append(a, .{ .epoch = 0, .raw = try natives.framework.packageObjectBcs(a, p, 5, &prev_a) });
        if (!std.mem.eql(u8, &p.id, &two)) continue;
        try gop.value_ptr.append(a, .{ .epoch = 3, .raw = try natives.framework.packageObjectBcs(a, p, 5, &prev_b) });
        found_two = true;
    }
    try std.testing.expect(found_two);
    try std.testing.expectEqualDeep(systemVersions(&store, 1).?, systemVersions(&store, 3).?);
    try std.testing.expect(store.get(&two, 2).?.ptr != store.get(&two, 3).?.ptr);

    const pv = protocol.max_protocol_version;
    const c1 = try cacheFor(gpa, &store, 1, pv, .mainnet);
    try std.testing.expectEqualSlices(u8, &prev_a, &(try c1.get(&two)).?.prevTx());
    _ = (try c1.packageObject(&two)).?;
    // a plain epoch change: the cache moves
    try std.testing.expectEqual(c1, try cacheFor(gpa, &store, 2, pv, .mainnet));
    // epoch 3: the versions are equal, the bytes of 0x2 are not, and the cache holds 0x2
    const refused = epoch_moves_refused.load(.monotonic);
    const c3 = try cacheFor(gpa, &store, 3, pv, .mainnet);
    try std.testing.expect(c3 != c1);
    try std.testing.expectEqual(refused + 1, epoch_moves_refused.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2), c1.epoch);
    const now = (try c3.get(&two)).?;
    try std.testing.expectEqual(store.get(&two, 3).?.ptr, now.raw.ptr);
    try std.testing.expectEqualSlices(u8, &prev_b, &now.prevTx());
    const po = (try c3.packageObject(&two)).?;
    try std.testing.expectEqual(store.get(&two, 3).?.ptr, po.view.raw.ptr);
    // a cache of epoch 2 that holds no system package has nothing to compare and moves
    releaseThreadCaches();
    const empty = try cacheFor(gpa, &store, 2, pv, .mainnet);
    try std.testing.expectEqual(empty, try cacheFor(gpa, &store, 3, pv, .mainnet));
    try std.testing.expectEqualSlices(u8, &prev_b, &(try empty.get(&two)).?.prevTx());
}

test "both switches are off unless the environment turns them on" {
    // The old path is what runs until a switch has passed its gate and is turned on. (Tests
    // that flip a switch restore it, so this sees the process's own setting.)
    readEnv();
    const env = struct {
        fn get(name: [*:0]const u8) ?bool {
            if (!@import("builtin").link_libc) return null;
            const t = std.mem.span(std.c.getenv(name) orelse return null);
            if (std.mem.eql(u8, t, "1")) return true;
            if (std.mem.eql(u8, t, "0")) return false;
            return null;
        }
    }.get;
    try std.testing.expectEqual(env("ZUI_PKG_SHARED") orelse false, shared_enabled);
    try std.testing.expectEqual(env("ZUI_PKG_KEEP_EPOCHS") orelse false, keep_across_epochs);
}

test "statsLine names every counter" {
    var buf: [640]u8 = undefined;
    const line = statsLine(&buf);
    for ([_][]const u8{ "shared table", "cold package loads", "hits", "KiB held", "module loads", "evictions", "rebuilds", "kept across epochs", "moves" }) |word| {
        try std.testing.expect(std.mem.indexOf(u8, line, word) != null);
    }
}

test "system_ids are exactly the ids packages.isSystemPackage accepts" {
    var id: Id = @splat(0);
    var tail: u32 = 0;
    var n: usize = 0;
    while (tail <= 0xffff) : (tail += 1) {
        std.mem.writeInt(u16, id[30..32], @intCast(tail), .big);
        const listed = for (&system_ids) |*s| {
            if (std.mem.eql(u8, s, &id)) break true;
        } else false;
        try std.testing.expectEqual(packages.isSystemPackage(&id), listed);
        n += @intFromBool(listed);
    }
    try std.testing.expectEqual(system_ids.len, n);
    // anything above the last two bytes is no system package
    id = system_ids[1];
    id[0] = 1;
    try std.testing.expect(!packages.isSystemPackage(&id));
}

test "two stores serving different bytes for one (id, version): the second thread cache parses its own" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    readEnv();
    const saved = shared_enabled;
    defer shared_enabled = saved;
    shared_enabled = true;
    const vers = try natives.framework.load(a);
    const p = &vers[vers.len - 1].packages[0];
    // the same package object but for its previous transaction
    const prev_a: Id = @splat(0xaa);
    const prev_b: Id = @splat(0xbb);
    var stores: [2]packages.Store = .{ .{ .loaded = true }, .{ .loaded = true } };
    for (&stores, [_]*const Id{ &prev_a, &prev_b }) |*st, prev| {
        const gop = try st.system.getOrPut(a, p.id);
        gop.value_ptr.* = .empty;
        try gop.value_ptr.append(a, .{ .epoch = 0, .raw = try natives.framework.packageObjectBcs(a, p, 5, prev) });
    }
    const pv = protocol.max_protocol_version;
    shared.clear();
    defer shared.clear(); // after the caches below let go
    const ca = try Cache.init(gpa, &stores[0], 1, pv, .mainnet);
    defer destroy(ca);
    const cb = try Cache.init(gpa, &stores[1], 1, pv, .mainnet);
    defer destroy(cb);
    const mism = shared.mismatches.load(.monotonic);
    const pa = (try ca.get(&p.id)).?;
    const pb = (try cb.get(&p.id)).?;
    try std.testing.expect(pa.shared != null);
    try std.testing.expect(pb.shared == null);
    try std.testing.expectEqual(mism + 1, shared.mismatches.load(.monotonic));
    // each cache serves its own store's object
    try std.testing.expectEqualSlices(u8, &prev_a, &pa.prevTx());
    try std.testing.expectEqualSlices(u8, &prev_b, &pb.prevTx());
    try std.testing.expectEqual(stores[0].get(&p.id, 1).?.ptr, pa.raw.ptr);
    try std.testing.expectEqual(stores[1].get(&p.id, 1).?.ptr, pb.raw.ptr);
    const ob = (try cb.packageObject(&p.id)).?;
    try std.testing.expectEqualSlices(u8, &prev_b, ob.view.raw[ob.view.prev_tx_at + 1 ..][0..32]);
    const oa = (try ca.packageObject(&p.id)).?;
    try std.testing.expectEqualSlices(u8, &prev_a, oa.view.raw[oa.view.prev_tx_at + 1 ..][0..32]);
    // and both load the same package into their runtimes, one from the table, one from bytes
    const loads = move_vm.loader.predecoded_loads.load(.monotonic);
    const va = try ca.load(pa);
    const vb = try cb.load(pb);
    try std.testing.expectEqual(loads + 1, move_vm.loader.predecoded_loads.load(.monotonic));
    try move_vm.loader.expectSamePackage(va, vb);
}

fn ulebLen(n: usize) usize {
    var len: usize = 1;
    var x = n >> 7;
    while (x != 0) : (x >>= 7) len += 1;
    return len;
}

test "an entry a cache pinned is not served for other bytes at an address the cache saw before" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const Src = struct {
        var raw: []const u8 = &.{};
        fn get(_: *const anyopaque, id: *const [32]u8, _: u64) ?[]const u8 {
            if (packages.isSystemPackage(id)) return null;
            return raw;
        }
    };
    readEnv();
    const saved = shared_enabled;
    defer shared_enabled = saved;
    shared_enabled = true;
    const vers = try natives.framework.load(a);
    const p = &vers[vers.len - 1].packages[0];
    const id: Id = @splat(0x73);
    const prev: Id = @splat(1);
    const one = try natives.framework.packageObjectBcs(a, p, 1, &prev);
    @memcpy(one[1..33], &id);
    // A second object of the same (id, version) and the same length whose parts sit elsewhere:
    // one module 32 bytes shorter, and an address owner (33 bytes) for the immutable one (1).
    var obj = try bcs.decode(types.Object, a, one);
    const Entry = @typeInfo(@FieldType(@FieldType(types.MovePackage, "module_map"), "entries")).pointer.child;
    const entries = try a.dupe(Entry, obj.data.Package.module_map.entries);
    const cut = for (entries, 0..) |e, i| {
        if (e.value.len > 64 and ulebLen(e.value.len) == ulebLen(e.value.len - 32)) break i;
    } else return error.NoModuleToCut;
    entries[cut].value = entries[cut].value[0 .. entries[cut].value.len - 32];
    obj.data.Package.module_map.entries = entries;
    obj.owner = .{ .AddressOwner = .{ .@"0" = @splat(0x44) } };
    const two = try bcs.encodeAlloc(types.Object, a, &obj);
    try std.testing.expectEqual(one.len, two.len);
    try std.testing.expectEqualDeep(Shared.keyOf(one).?, Shared.keyOf(two).?);

    const buf = try a.dupe(u8, one);
    Src.raw = buf;
    var store: packages.Store = .{ .loaded = true, .lookup = .{ .ctx = undefined, .get = Src.get } };
    shared.clear();
    defer shared.clear(); // after the cache below lets go
    const c = try Cache.init(gpa, &store, 1, protocol.max_protocol_version, .mainnet);
    defer destroy(c);
    try std.testing.expect((try c.get(&id)).?.shared != null); // pins the entry made from `one`
    // The store rewrites its buffer in place (its contract says it does not): the entry was
    // parsed from other bytes, so the input object is the thread's own parse of what is there.
    @memcpy(buf, two);
    const po = (try c.packageObject(&id)).?;
    const view = try objects.ObjectView.parse(buf);
    try std.testing.expectEqualDeep(view, po.view);
    try std.testing.expect(po.owner == .AddressOwner);
    try std.testing.expectEqual(try objects.sizeForGasMetering(a, &view), po.gas_size);
    // and the same bytes again are served from the entry
    @memcpy(buf, one);
    const c2 = try Cache.init(gpa, &store, 1, protocol.max_protocol_version, .mainnet);
    defer destroy(c2);
    const hits = shared.hits.load(.monotonic);
    const po2 = (try c2.packageObject(&id)).?;
    try std.testing.expectEqual(hits + 1, shared.hits.load(.monotonic));
    try std.testing.expect(po2.owner == .Immutable);
    try std.testing.expectEqual(buf.ptr, po2.view.raw.ptr);
}

test "a package record from the shared table equals the thread's own parse, field for field" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    readEnv();
    const saved = shared_enabled;
    defer shared_enabled = saved;
    const vers = try natives.framework.load(a);
    const pv = protocol.max_protocol_version;
    defer shared.clear();
    var checked: usize = 0;
    // every package of the last eight snapshots, as version 1 and as a later version
    for (vers[vers.len - 8 ..]) |*v| for (v.packages) |*p| for ([_]u64{ 1, 7 }) |version| {
        // the snapshots reuse (id, version) for other bytes: start each from an empty table
        shared.clear();
        var store: packages.Store = .{ .loaded = true };
        const prev: Id = @splat(@truncate(v.version));
        const gop = try store.system.getOrPut(a, p.id);
        gop.value_ptr.* = .empty;
        try gop.value_ptr.append(a, .{ .epoch = 0, .raw = try natives.framework.packageObjectBcs(a, p, version, &prev) });
        shared_enabled = false;
        const cold = try Cache.init(gpa, &store, 1, pv, .mainnet);
        defer destroy(cold);
        shared_enabled = true;
        const warm = try Cache.init(gpa, &store, 1, pv, .mainnet);
        defer destroy(warm);
        shared_enabled = false;
        const x = (try cold.get(&p.id)).?;
        const xo = (try cold.packageObject(&p.id)).?;
        shared_enabled = true;
        const y = (try warm.get(&p.id)).?;
        const yo = (try warm.packageObject(&p.id)).?;
        try std.testing.expect(x.shared == null);
        try std.testing.expect(y.shared != null);
        try std.testing.expectEqual(x.raw.ptr, y.raw.ptr);
        try std.testing.expectEqual(x.raw.len, y.raw.len);
        try std.testing.expectEqualDeep(x.view, y.view);
        try std.testing.expectEqualSlices(u8, &x.version_id, &y.version_id);
        try std.testing.expectEqualSlices(u8, &x.original_id, &y.original_id);
        try std.testing.expectEqual(x.version, y.version);
        try std.testing.expectEqual(x.gas_size, y.gas_size);
        try std.testing.expectEqualDeep(x.linkage, y.linkage);
        try std.testing.expectEqualDeep(x.type_origins, y.type_origins);
        try std.testing.expectEqualDeep(x.modules, y.modules);
        try std.testing.expectEqualDeep(xo.view, yo.view);
        try std.testing.expectEqualDeep(xo.owner, yo.owner);
        try std.testing.expectEqual(xo.gas_size, yo.gas_size);
        checked += 1;
    };
    try std.testing.expect(checked >= 60);
}

test "the cache budget counts the maps and the link contexts, and they bring the rebuild" {
    const gpa = std.testing.allocator;
    const saved = max_cache_bytes;
    defer max_cache_bytes = saved;
    // This thread's caches go with the test (the testing allocator checks for leaks).
    defer for (&caches) |*slot| if (slot.*) |x| {
        destroy(x);
        slot.* = null;
    };
    var store: packages.Store = .{ .loaded = true };
    const pv = protocol.max_protocol_version;
    const c = try cacheFor(gpa, &store, 7, pv, .mainnet);
    try std.testing.expectEqual(@as(usize, 0), c.link_bytes);
    // 64 distinct linkages, each a link context whose transaction resolved 100 calls across
    // packages (what `LinkCtx.resolve` leaves in `ext`; the pointers are never followed).
    var linkage: [1][2]Id = .{.{ @splat(1), @splat(2) }};
    for (0..64) |i| {
        linkage[0][1][0] = @intCast(i);
        const lc = try c.linkCtx(&linkage);
        for (0..100) |h| try lc.ext.put(c.rt.gpa, .{ .m = @ptrFromInt(0x10000 * (i + 1)), .h = @intCast(h) }, @ptrFromInt(0x10000));
        const before = c.held();
        c.linkUsed(lc);
        // 100 entries: at least 100 slots of a metadata byte, a 16-byte key and a pointer.
        try std.testing.expect(c.held() - before >= 100 * 25);
        // The same context again adds nothing until it grows.
        c.linkUsed(lc);
        try std.testing.expectEqual(before + mapBytes(lc.ext), c.held());
    }
    try std.testing.expectEqual(@as(usize, 64), c.link_ctxs.count());
    try std.testing.expect(c.link_bytes >= 64 * 100 * 25);
    const maps = mapBytes(c.link_ctxs);
    try std.testing.expect(maps >= 64 * (1 + 16 + 8));
    // What the limit saw before: the arenas and the type cache. With the limit just there the
    // cache stays only if the maps and the link contexts go uncounted.
    const arenas = c.arena.queryCapacity() + c.rt.arena_state.queryCapacity() + c.ty_args.bytes();
    try std.testing.expect(c.held() >= arenas + maps + c.link_bytes);
    const rebuilds = cache_rebuilds.load(.monotonic);
    max_cache_bytes = c.held();
    try std.testing.expectEqual(c, try cacheFor(gpa, &store, 7, pv, .mainnet));
    try std.testing.expectEqual(rebuilds, cache_rebuilds.load(.monotonic));
    max_cache_bytes = arenas;
    const fresh = try cacheFor(gpa, &store, 7, pv, .mainnet);
    try std.testing.expectEqual(rebuilds + 1, cache_rebuilds.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), fresh.link_ctxs.count());
    try std.testing.expectEqual(@as(usize, 0), fresh.link_bytes);
}

test "the cache budget counts the shared table entries a cache pins, and they bring the rebuild" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    readEnv();
    const saved = .{ shared_enabled, max_cache_bytes };
    defer {
        shared_enabled = saved[0];
        max_cache_bytes = saved[1];
    }
    shared_enabled = true;
    releaseThreadCaches();
    shared.clear();
    try std.testing.expectEqual(@as(u64, 0), shared.entries.load(.monotonic));
    defer shared.clear(); // after the caches below let go
    defer releaseThreadCaches();

    const vers = try natives.framework.load(a);
    const v = &vers[vers.len - 1];
    var store: packages.Store = .{ .loaded = true };
    const prev: Id = @splat(3);
    for (v.packages) |*p| {
        const gop = try store.system.getOrPut(a, p.id);
        gop.value_ptr.* = .empty;
        try gop.value_ptr.append(a, .{ .epoch = 0, .raw = try natives.framework.packageObjectBcs(a, p, 3, &prev) });
    }
    const pv = protocol.max_protocol_version;
    const c = try cacheFor(gpa, &store, 7, pv, .mainnet);
    try std.testing.expectEqual(@as(usize, 0), c.shared_bytes);
    const before = c.held();
    // Every package pinned: the cache is charged each entry's record and copy of the object.
    var pinned: usize = 0;
    for (v.packages) |*p| {
        const pk = (try c.get(&p.id)).?;
        const e = pk.shared.?;
        try std.testing.expect(e.base_bytes >= @sizeOf(Shared.Entry) + pk.raw.len);
        pinned += e.base_bytes;
    }
    try std.testing.expectEqual(pinned, c.shared_bytes);
    try std.testing.expect(c.held() >= before + pinned);
    // The input-object view of an entry already pinned adds nothing.
    _ = (try c.packageObject(&v.packages[0].id)).?;
    try std.testing.expectEqual(pinned, c.shared_bytes);
    // Loading adds the deserialized modules, once.
    const p0 = (try c.get(&v.packages[0].id)).?;
    _ = try c.load(p0);
    const with_modules = c.shared_bytes;
    try std.testing.expect(with_modules > pinned + p0.raw.len / 2);
    _ = try c.load(p0);
    try std.testing.expectEqual(with_modules, c.shared_bytes);
    // One cache pins the whole table: what it is charged is what the table holds.
    try std.testing.expectEqual(@as(u64, c.shared_bytes), shared.bytes_held.load(.monotonic));

    // The limit sees the pins: at what the cache holds it stays, at what it holds without
    // them it is dropped and rebuilt, and the new cache starts with no pins.
    const rebuilds = cache_rebuilds.load(.monotonic);
    max_cache_bytes = c.held();
    try std.testing.expectEqual(c, try cacheFor(gpa, &store, 7, pv, .mainnet));
    try std.testing.expectEqual(rebuilds, cache_rebuilds.load(.monotonic));
    max_cache_bytes = c.held() - c.shared_bytes;
    const fresh = try cacheFor(gpa, &store, 7, pv, .mainnet);
    try std.testing.expectEqual(rebuilds + 1, cache_rebuilds.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), fresh.shared_bytes);
    try std.testing.expectEqual(@as(usize, 0), fresh.pins.count());
    // The entries stay in the table (unpinned, within its budget) for the next cache: a hit.
    try std.testing.expectEqual(@as(u64, v.packages.len), shared.entries.load(.monotonic));
    const cold = shared.cold_loads.load(.monotonic);
    try std.testing.expect((try fresh.get(&v.packages[0].id)).?.shared != null);
    try std.testing.expectEqual(cold, shared.cold_loads.load(.monotonic));
}

test "setBudget takes the shared table out of the budget once and splits the rest over the caches" {
    readEnv();
    const saved = .{ shared_enabled, max_cache_bytes, shared.max_bytes, shared_budget };
    defer {
        shared_enabled = saved[0];
        max_cache_bytes = saved[1];
        shared.max_bytes = saved[2];
        shared_budget = saved[3];
    }
    const mib: usize = 1 << 20;
    shared_budget = 512 * mib;
    // The table off: the split as it always was, and the table's budget is left alone.
    shared_enabled = false;
    shared.max_bytes = 7 * mib;
    setBudget(3072 * mib, 32);
    try std.testing.expectEqual(96 * mib, max_cache_bytes);
    try std.testing.expectEqual(7 * mib, shared.max_bytes);
    setBudget(3072 * mib, 24);
    try std.testing.expectEqual(128 * mib, max_cache_bytes);
    setBudget(64 * mib, 32);
    try std.testing.expectEqual(32 * mib, max_cache_bytes);
    // The table on: its part is counted once, whatever the number of caches, and the whole
    // adds up to the budget.
    shared_enabled = true;
    setBudget(3072 * mib, 32);
    try std.testing.expectEqual(512 * mib, shared.max_bytes);
    try std.testing.expectEqual(80 * mib, max_cache_bytes);
    try std.testing.expectEqual(3072 * mib, shared.max_bytes + 32 * max_cache_bytes);
    setBudget(3072 * mib, 8);
    try std.testing.expectEqual(512 * mib, shared.max_bytes);
    try std.testing.expectEqual(320 * mib, max_cache_bytes);
    // A second call (the node sets the budget for the executor, then again with the
    // simulation workers) starts from the configured part, not from the last result.
    setBudget(512 * mib, 4);
    try std.testing.expectEqual(256 * mib, shared.max_bytes); // at most half
    try std.testing.expectEqual(64 * mib, max_cache_bytes);
    setBudget(3072 * mib, 32);
    try std.testing.expectEqual(512 * mib, shared.max_bytes);
    // A larger table by configuration, still at most half.
    shared_budget = 2048 * mib;
    setBudget(3072 * mib, 32);
    try std.testing.expectEqual(1536 * mib, shared.max_bytes);
    try std.testing.expectEqual(48 * mib, max_cache_bytes);
    // No threads: one cache's worth.
    setBudget(1024 * mib, 0);
    try std.testing.expectEqual(512 * mib, max_cache_bytes);
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
