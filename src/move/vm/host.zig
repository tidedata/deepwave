//! The VM side of the native ABI (CONTRACTS.md 6.2 / 6.3): a `NativeTable` over the natives
//! lane's table. Arguments are converted from VM values to `types.layout.Value` by their
//! instantiated parameter types (references are read through), the native runs against the
//! host's transaction context and object runtime, `&mut` arguments are written back through
//! their references, and results are converted back to owned VM values by the return types.
//!
//! `Host` plays the part of the native extensions sui-adapter builds for a transaction
//! (`NativesCostTable` is the protocol config the natives read directly, `TransactionContext`,
//! `ObjectRuntime`).
const std = @import("std");
const natives = @import("natives");
const types_mod = @import("types");
const protocol = @import("protocol");
const loader = @import("loader.zig");
const value = @import("value.zig");
const vm_types = @import("types.zig");
const hash = @import("hash");
const interp = @import("interp.zig");

const Allocator = std.mem.Allocator;
const abi = natives.abi;
const LV = abi.Value;
const Layout = abi.Layout;
const TypeTag = abi.TypeTag;
const Type = loader.Type;
const Value = value.Value;

pub const Host = struct {
    cfg: *const protocol.ProtocolConfig,
    tx: abi.TxContext,
    rt: abi.ObjectRuntime = .{},
    /// Transaction-lifetime memory for everything the object runtime keeps: ids, transfers,
    /// events, child objects, received objects, accumulator events and the layout values and type
    /// tags they hold. null = the session arena. Natives that keep nothing run on the call-scoped
    /// LIFO instead.
    tx_arena: ?Allocator = null,
    /// VM copies of the child objects `borrow_child_object(_mut)` returned references to, by the
    /// object runtime's slot. The VM reads and writes the copy; `finish` (and a removal of that
    /// child) converts mutably borrowed copies back into fresh layout slices, so a shared slice
    /// (the child's fingerprint) is never written in place (CONTRACTS 6.3 aliasing rule).
    /// The copies' values live in the session heap: call `finish` before the session's memory goes.
    shadows: std.AutoArrayHashMapUnmanaged(*LV, Shadow) = .empty,
    /// exec-history-vm: address ranges of the VM copies of mutably borrowed children (every
    /// Value slot, container header and container array in the tree when it was borrowed), under
    /// the v0..v2 and pre-`minimize_child_object_mutations` rule: a write into one marks the
    /// child dirty (old `GlobalValue` status). A write that replaces or reallocates part of the
    /// tree marks it first, so stale ranges only ever point at already dirty children.
    watch: std.ArrayList(Watch) = .empty,
    /// Native type arguments (tags and layouts) by type, kept by the caller for the runtime's
    /// life; null computes them per call.
    ty_cache: ?*TyArgCache = null,

    pub fn table(h: *const Host) interp.NativeTable {
        // `lookup` reads only the execution version off the host: one memo key per version.
        return .{ .ctx = h, .lookupFn = lookup, .memo_key = 0x4f53_0000 + (h.cfg.execution_version orelse 0) };
    }

    /// `ObjectRuntime::finish`, after writing back every child object the VM borrowed mutably.
    /// `gpa` must outlive the results (and is used for the write-back slices).
    pub fn finish(h: *Host, gpa: Allocator) loader.LoadError!abi.ObjectRuntime.Finish {
        for (h.shadows.keys(), h.shadows.values()) |slot, sh| if (sh.mutable) {
            slot.* = if (sh.layout) |l| try toLayoutL(gpa, l, sh.val.*) else try toLayout(gpa, sh.ty, sh.val.*);
        };
        return h.rt.finishFor(gpa, h.cfg); // exec-history-vm: per-cut results shape
    }

    fn txArena(h: *const Host, ctx: *interp.NativeContext) Allocator {
        return h.tx_arena orelse ctx.arena();
    }

    /// Writes back the VM copy of the child `id` (before a native reads its slot).
    fn flushChild(h: *Host, a: Allocator, id: *const [32]u8) loader.LoadError!void {
        const co = h.rt.store.get(id.*) orelse return;
        const sh = h.shadows.get(&co.value) orelse return;
        if (sh.mutable) co.value = if (sh.layout) |l| try toLayoutL(a, l, sh.val.*) else try toLayout(a, sh.ty, sh.val.*);
    }
};

/// `layout`: the child's layout when known at borrow time (a type-parameter return, from the
/// call's type arguments); the write-back then walks it instead of instantiating field types.
const Shadow = struct { val: *Value, ty: *const Type, mutable: bool, layout: ?*const Layout = null };

/// The layout of signature token `tok` (a type parameter, or a reference to one, `inner`)
/// from the call's resolved type arguments; null for any other token.
fn tokLayout(tok: anytype, tys: []const abi.TyArg) ?*const Layout {
    const i: usize = if (tok.len == 1 and tok[0].tag == .TypeParameter)
        0
    else if (tok.len == 2 and (tok[0].tag == .Reference or tok[0].tag == .MutableReference) and tok[1].tag == .TypeParameter)
        1
    else
        return null;
    const idx = tok[i].idx;
    if (idx >= tys.len) return null;
    return tys[idx].traversal();
}
const Watch = struct { lo: usize, hi: usize, slot: *LV };

/// exec-history-vm: children are modified by the dirty flag, not by fingerprint.
pub fn legacyDirty(cfg: *const protocol.ProtocolConfig) bool {
    return (cfg.execution_version orelse 0) < 3 or !cfg.feature_flags.minimize_child_object_mutations;
}

fn watchTree(h: *Host, a: Allocator, slot: *LV, v: *const Value) Allocator.Error!void {
    try h.watch.append(a, .{ .lo = @intFromPtr(v), .hi = @intFromPtr(v) + @sizeOf(Value), .slot = slot });
    if (v.tag != .container) return;
    const c = v.cont();
    try h.watch.append(a, .{ .lo = @intFromPtr(c), .hi = @intFromPtr(c) + @sizeOf(value.Container), .slot = slot });
    if (c.kind.isPrimVec()) {
        const b = c.bytes();
        if (b.len > 0) try h.watch.append(a, .{ .lo = @intFromPtr(b.ptr), .hi = @intFromPtr(b.ptr) + b.len, .slot = slot });
        return;
    }
    for (c.values()) |*e| try watchTree(h, a, slot, e);
}

fn noteWrite(ext: ?*anyopaque, addr: usize) void {
    const h: *Host = @ptrCast(@alignCast(ext orelse return));
    for (h.watch.items) |w| if (addr >= w.lo and addr < w.hi) {
        for (h.rt.store.values()) |co| if (&co.value == w.slot) {
            co.dirty = true;
        };
    };
}

/// Natives that keep nothing past the call (their memory is the call-scoped LIFO): move-stdlib,
/// hashing and crypto, address, types, protocol_config, tx_context reads and
/// dynamic_field::hash_type_and_key. Everything else reaches the object runtime.
fn keepsNothing(short: u16, module: []const u8, func: []const u8) bool {
    if (short == 1) return true;
    if (short != 2) return false;
    const pure = [_][]const u8{ "address", "hash", "hmac", "types", "protocol_config", "ed25519", "ecdsa_k1", "ecdsa_r1", "bls12381", "ecvrf", "poseidon", "zklogin_verified_id", "zklogin_verified_issuer", "vdf", "rangeproofs", "groth16", "group_ops" };
    for (pure) |p| if (std.mem.eql(u8, module, p)) return true;
    if (std.mem.eql(u8, module, "tx_context")) return std.mem.startsWith(u8, func, "native_");
    if (std.mem.eql(u8, module, "dynamic_field")) return std.mem.eql(u8, func, "hash_type_and_key");
    return false;
}

fn shortAddr(addr: *const [32]u8) ?u16 {
    for (addr[0..30]) |b| if (b != 0) return null;
    return std.mem.readInt(u16, addr[30..32], .big);
}

fn lookup(hp: ?*const anyopaque, addr: *const [32]u8, module: []const u8, func_in: []const u8) ?interp.Native {
    for (addr[0..30]) |b| if (b != 0) return null;
    const short = std.mem.readInt(u16, addr[30..32], .big);
    var func = func_in;
    // exec-history-vm: frameworks before execution version 4 declare `type_name::get` and
    // `get_with_original_ids` native; the v0..v3 natives are the latest `with_defining_ids` and
    // `with_original_ids`.
    if (hp) |p| {
        const h: *const Host = @ptrCast(@alignCast(p));
        if ((h.cfg.execution_version orelse 0) < interp.LATEST_EXECUTION_VERSION and short == 1 and std.mem.eql(u8, module, "type_name")) {
            if (std.mem.eql(u8, func, "get")) func = "with_defining_ids";
            if (std.mem.eql(u8, func, "get_with_original_ids")) func = "with_original_ids";
        }
    }
    // Bulk vector natives work on the VM's vectors in place (the generic path would convert
    // the whole vector on every call).
    if (short == 1 and std.mem.eql(u8, module, "vector")) {
        const Vn = struct { name: []const u8, f: interp.NativeFn };
        const vns = [_]Vn{
            .{ .name = "reverse", .f = vecReverse },
            .{ .name = "keep_range", .f = vecKeepRange },
            .{ .name = "copy_range", .f = vecCopyRange },
            .{ .name = "replace_range", .f = vecReplaceRange },
            .{ .name = "borrow", .f = vecBorrow },
            .{ .name = "borrow_mut", .f = vecBorrow },
        };
        inline for (vns) |v| if (std.mem.eql(u8, func, v.name)) return .{ .call = v.f };
    }
    // Hot natives on the VM's own values (no layout-value conversion), gas as src/natives charges.
    if (fastNative(short, module, func)) |f| return .{ .call = f };
    // `object::borrow_uid` returns a reference into its argument: done on the VM's value.
    if (short == 2 and std.mem.eql(u8, module, "object") and std.mem.eql(u8, func, "borrow_uid")) return .{ .call = borrowUid };
    const f = natives.table.lookup(short, module, func) orelse return null;
    return .{ .call = call, .data = @ptrCast(f) };
}

fn call(ctx: *interp.NativeContext, data: ?*const anyopaque, ty_args: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!interp.NativeResult {
    const f: abi.NativeFn = @ptrCast(@alignCast(data.?));
    const host: *Host = @ptrCast(@alignCast(ctx.ext orelse return ctx.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null)));
    const func = ctx.func;
    const m = func.module;
    const short = shortAddr(&m.pkg.original_id) orelse return ctx.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null);
    // Native memory is call-scoped (the LIFO region, released when the native returns) unless
    // the native can keep what it is given (the object runtime): then it is the transaction's.
    const scratch = ctx.scratch();
    const keeps = !keepsNothing(short, m.name, func.name);
    const arena = if (keeps) host.txArena(ctx) else scratch;
    const heap = ctx.heap();
    const lim = Limits.of(ctx.session.cfg);

    const tys = try scratch.alloc(abi.TyArg, ty_args.len);
    for (ty_args, tys) |t, *o| {
        if (host.ty_cache) |tc| if (try tc.get(t, lim)) |hit| {
            o.* = hit;
            if (!keeps) o.annotated = null;
            continue;
        };
        const tag = try typeTag(arena, t, .defining);
        const rtag = try typeTag(arena, t, .original);
        const layout = try layoutLimited(arena, t, lim);
        o.* = .{
            .tag = tag,
            .runtime_tag = rtag,
            .layout = layout,
            .shape = if (layout == null) try layoutLimited(arena, t, Limits.none) else null,
            .annotated = if (keeps) try annotatedLimited(arena, t, lim) else null,
        };
    }
    const is_df = short == 2 and std.mem.eql(u8, m.name, "dynamic_field");
    // The removed child's slot is read by the native: write the VM's copy back first.
    if (is_df and std.mem.eql(u8, func.name, "remove_child_object") and args.len == 2 and args[1].tag == .address)
        try host.flushChild(arena, args[1].box());
    // borrow_child_object_mut reads its `&mut UID` and never writes it.
    const writes_back = !(is_df and std.mem.eql(u8, func.name, "borrow_child_object_mut"));
    const params = try scratch.alloc(*const Type, func.params.len);
    for (func.params, params) |tok, *p| p.* = try vm_types.instantiate(scratch, m, tok, ty_args);
    const largs = try arena.alloc(LV, args.len);
    for (args, params, largs, func.params) |a, p, *o, tok| {
        // A type-parameter argument walks its type argument's layout (no field instantiation).
        const pl = tokLayout(tok, tys);
        o.* = switch (p.*) {
            .ref, .mut_ref => |inner| if (pl) |l| try toLayoutL(arena, l, readThrough(a)) else try toLayout(arena, inner, readThrough(a)),
            else => blk: {
                const lv = if (pl) |l| try toLayoutL(arena, l, a) else try toLayout(arena, p, a);
                heap.drop(a);
                break :blk lv;
            },
        };
    }
    var nctx = abi.Ctx.init(arena, host.cfg, ctx.gas_budget, &host.tx, &host.rt);
    const out = try f(&nctx, tys, largs);
    switch (out) {
        .err => |e| return ctx.fail(e.status, e.sub),
        .ok, .abort => {},
    }
    // `&mut` arguments: the native updated `largs[i]` in place.
    if (writes_back) for (args, params, largs, func.params) |a, p, lv, tok| switch (p.*) {
        .mut_ref => |inner| writeThrough(heap, a, if (tokLayout(tok, tys)) |l| try fromLayoutL(heap, l, lv) else try fromLayout(heap, inner, lv)),
        else => {},
    };
    switch (out) {
        .ok => |o| {
            if (o.ref) |slot| {
                // One reference into the object runtime's stable slot: the VM gets a reference to
                // its own copy of the value (one copy per slot for the transaction).
                if (func.returns.len != 1 or o.rets.len != 0) return ctx.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null);
                const txa = host.txArena(ctx);
                const rty = try vm_types.instantiate(txa, m, func.returns[0], ty_args);
                const inner: *const Type, const mutable = switch (rty.*) {
                    .ref => |i| .{ i, false },
                    .mut_ref => |i| .{ i, true },
                    else => return ctx.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null),
                };
                const gop = try host.shadows.getOrPut(txa, slot);
                if (!gop.found_existing) {
                    const pv = try txa.create(Value);
                    // the layout lives in the runtime's type-argument cache or the transaction arena
                    const rl: ?*const Layout = if (keeps) tokLayout(func.returns[0], tys) else null;
                    pv.* = if (rl) |l| try fromLayoutL(heap, l, slot.*) else try fromLayout(heap, inner, slot.*);
                    // type arguments live in the caller's LIFO frame: keep a deep copy
                    gop.value_ptr.* = .{ .val = pv, .ty = try cloneType(txa, inner), .mutable = mutable, .layout = rl };
                } else if (mutable) gop.value_ptr.mutable = true;
                // exec-history-vm: watch writes into a mutable borrow under the old rule.
                if (mutable and legacyDirty(host.cfg)) {
                    try watchTree(host, txa, slot, gop.value_ptr.val);
                    ctx.session.write_hook = noteWrite;
                }
                const rets = try scratch.alloc(Value, 1);
                rets[0] = Value.refSlot(gop.value_ptr.val);
                return .{ .cost = o.cost, .outcome = .{ .ok = rets } };
            }
            if (o.rets.len != func.returns.len) return ctx.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null);
            const rets = try scratch.alloc(Value, o.rets.len);
            for (func.returns, o.rets, rets) |tok, lv, *r| {
                if (tokLayout(tok, tys)) |l| {
                    r.* = try fromLayoutL(heap, l, lv);
                    continue;
                }
                const rt = try vm_types.instantiate(scratch, m, tok, ty_args);
                r.* = try fromLayout(heap, rt, lv);
            }
            return .{ .cost = o.cost, .outcome = .{ .ok = rets } };
        },
        .abort => |a| return .{ .cost = a.cost, .outcome = .{ .abort = a.code } },
        .err => unreachable,
    }
}

// ---------------------------------------------------------------------------------------------
// References

/// The referent of a reference argument (not copied; primitive elements are read by value).
fn readThrough(r: Value) Value {
    return switch (r.tag) {
        .ref_slot => r.slot().*,
        .ref_elem => elemValue(r.cont(), r.b),
        else => r,
    };
}

/// A primitive vector element as a value whose 32-byte payload points into the vector.
fn elemValue(c: *const value.Container, i: u64) Value {
    const w = c.kind.width();
    const p = c.data + i * w;
    return switch (c.kind) {
        .vec_u8 => Value.u8_(p[0]),
        .vec_bool => Value.bool_(p[0] != 0),
        .vec_u16 => Value.u16_(std.mem.readInt(u16, p[0..2], .little)),
        .vec_u32 => Value.u32_(std.mem.readInt(u32, p[0..4], .little)),
        .vec_u64 => Value.u64_(std.mem.readInt(u64, p[0..8], .little)),
        .vec_u128 => Value.u128_(std.mem.readInt(u128, p[0..16], .little)),
        .vec_u256 => Value.boxed(.u256, p[0..32]),
        .vec_address => Value.boxed(.address, p[0..32]),
        else => unreachable,
    };
}

fn writeThrough(heap: value.Heap, r: Value, v: Value) void {
    switch (r.tag) {
        .ref_slot => {
            heap.drop(r.slot().*);
            r.slot().* = v;
        },
        .ref_elem => {
            value.writeElem(r.cont(), r.b, v);
            heap.drop(v);
        },
        else => unreachable,
    }
}

/// Native type arguments by type: the type tags (defining and original ids), the layout under
/// the call's limits (or its shape), and the annotated layout. A key is the type's structure
/// (datatypes by pointer, stable while the runtime that loaded them lives) and the limits; the
/// owner drops the cache with that runtime. Natives only read what a type argument points to.
pub const TyArgCache = struct {
    arena: std.heap.ArenaAllocator,
    map: std.StringHashMapUnmanaged(abi.TyArg) = .empty,

    pub fn init(gpa: Allocator) TyArgCache {
        return .{ .arena = .init(gpa) };
    }

    pub fn deinit(c: *TyArgCache) void {
        c.arena.deinit();
    }

    pub fn bytes(c: *const TyArgCache) usize {
        return c.arena.queryCapacity();
    }

    /// The cached type argument for `t` (computed on a miss); null for a type with no key
    /// (references, parameters, or a key over 512 bytes).
    pub fn get(c: *TyArgCache, t: *const Type, lim: Limits) Allocator.Error!?abi.TyArg {
        var buf: [512]u8 = undefined;
        var w: KeyWriter = .{ .buf = &buf };
        w.put(std.mem.asBytes(&lim.max_depth));
        w.put(std.mem.asBytes(&lim.max_nodes));
        w.put(&.{@intFromBool(lim.legacy)});
        if (!w.ty(t) or w.over) return null;
        const key = buf[0..w.len];
        if (c.map.get(key)) |hit| return hit;
        const a = c.arena.allocator();
        const layout = try layoutLimited(a, t, lim);
        const v: abi.TyArg = .{
            .tag = try typeTag(a, t, .defining),
            .runtime_tag = try typeTag(a, t, .original),
            .layout = layout,
            .shape = if (layout == null) try layoutLimited(a, t, Limits.none) else null,
            .annotated = try annotatedLimited(a, t, lim),
        };
        try c.map.put(a, try a.dupe(u8, key), v);
        return v;
    }

    const KeyWriter = struct {
        buf: []u8,
        len: usize = 0,
        over: bool = false,
        fn put(w: *KeyWriter, b: []const u8) void {
            if (w.len + b.len > w.buf.len) {
                w.over = true;
                return;
            }
            @memcpy(w.buf[w.len..][0..b.len], b);
            w.len += b.len;
        }
        fn ty(w: *KeyWriter, t: *const Type) bool {
            w.put(&.{@intFromEnum(std.meta.activeTag(t.*))});
            switch (t.*) {
                .vector => |e| return w.ty(e),
                .datatype => |d| {
                    w.put(std.mem.asBytes(&@intFromPtr(d.dt)));
                    w.put(&.{@truncate(d.args.len)});
                    if (d.args.len > 255) return false;
                    for (d.args) |x| if (!w.ty(x)) return false;
                    return true;
                },
                .ref, .mut_ref, .param => return false,
                else => return true,
            }
        }
    };
};

// ---------------------------------------------------------------------------------------------
// VM values <-> layout values

pub fn toLayout(arena: Allocator, t: *const Type, v: Value) loader.LoadError!LV {
    return switch (t.*) {
        .bool => .{ .bool = v.a != 0 },
        .u8 => .{ .u8 = @truncate(v.a) },
        .u16 => .{ .u16 = @truncate(v.a) },
        .u32 => .{ .u32 = @truncate(v.a) },
        .u64 => .{ .u64 = v.a },
        .u128 => .{ .u128 = v.asU128() },
        .u256 => .{ .u256 = v.asU256() },
        .address => .{ .address = v.box().* },
        .signer => .{ .signer = v.cont().values()[0].box().* },
        .vector => |e| blk: {
            const c = v.cont();
            if (c.kind == .vec_u8) break :blk .{ .bytes = try arena.dupe(u8, c.data[0..c.len]) };
            const items = try arena.alloc(LV, c.len);
            if (c.kind.isPrimVec()) {
                primToLayout(c, items);
            } else for (items, c.values()) |*it, x| {
                it.* = try toLayout(arena, e, x);
            }
            break :blk .{ .vector = items };
        },
        .datatype => |d| blk: {
            const c = v.cont();
            const fields = if (d.dt.is_enum) d.dt.variants[c.tag].fields else d.dt.fields;
            const items = try arena.alloc(LV, fields.len);
            for (fields, c.values(), items) |fd, x, *it| {
                it.* = try toLayout(arena, try vm_types.instantiate(arena, d.dt.module, fd.signature, d.args), x);
            }
            break :blk if (d.dt.is_enum) .{ .variant = .{ .tag = @intCast(c.tag), .fields = items } } else .{ .@"struct" = items };
        },
        .ref, .mut_ref, .param => unreachable,
    };
}

pub fn fromLayout(h: value.Heap, t: *const Type, v: LV) loader.LoadError!Value {
    return switch (t.*) {
        .bool => Value.bool_(v.bool),
        .u8 => Value.u8_(v.u8),
        .u16 => Value.u16_(v.u16),
        .u32 => Value.u32_(v.u32),
        .u64 => Value.u64_(v.u64),
        .u128 => Value.u128_(v.u128),
        .u256 => h.u256_(v.u256),
        .address => Value.boxed(.address, try h.box32(v.address)),
        .signer => blk: {
            const c = try h.newContainer(.struct_, 1);
            c.values()[0] = Value.boxed(.address, try h.box32(v.signer));
            break :blk Value.container(c);
        },
        .vector => |e| blk: {
            const k = e.vecKind();
            if (v == .bytes) break :blk try bytesFromLayout(h, v.bytes);
            const items = v.vector;
            const c = try h.newContainer(k, items.len);
            if (k.isPrimVec()) {
                primFromLayout(c, items);
            } else for (items, c.values()) |it, *x| {
                x.* = try fromLayout(h, e, it);
            }
            break :blk Value.container(c);
        },
        .datatype => |d| blk: {
            const tag: u16, const items = if (d.dt.is_enum) .{ v.variant.tag, v.variant.fields } else .{ 0, v.@"struct" };
            const fields = if (d.dt.is_enum) d.dt.variants[tag].fields else d.dt.fields;
            const c = try h.newContainer(if (d.dt.is_enum) .variant else .struct_, fields.len);
            c.tag = tag;
            for (fields, items, c.values()) |fd, it, *x| {
                x.* = try fromLayout(h, try vm_types.instantiate(h.arena, d.dt.module, fd.signature, d.args), it);
            }
            break :blk Value.container(c);
        },
        .ref, .mut_ref, .param => unreachable,
    };
}

/// A primitive vector's elements as layout values (`toLayout` of each element).
fn primToLayout(c: *const value.Container, items: []LV) void {
    const p = c.data;
    switch (c.kind) {
        .vec_u8 => for (items, 0..) |*it, i| {
            it.* = .{ .u8 = p[i] };
        },
        .vec_bool => for (items, 0..) |*it, i| {
            it.* = .{ .bool = p[i] != 0 };
        },
        .vec_u16 => for (items, 0..) |*it, i| {
            it.* = .{ .u16 = std.mem.readInt(u16, p[i * 2 ..][0..2], .little) };
        },
        .vec_u32 => for (items, 0..) |*it, i| {
            it.* = .{ .u32 = std.mem.readInt(u32, p[i * 4 ..][0..4], .little) };
        },
        .vec_u64 => for (items, 0..) |*it, i| {
            it.* = .{ .u64 = std.mem.readInt(u64, p[i * 8 ..][0..8], .little) };
        },
        .vec_u128 => for (items, 0..) |*it, i| {
            it.* = .{ .u128 = std.mem.readInt(u128, p[i * 16 ..][0..16], .little) };
        },
        .vec_u256 => for (items, 0..) |*it, i| {
            it.* = .{ .u256 = std.mem.readInt(u256, p[i * 32 ..][0..32], .little) };
        },
        .vec_address => for (items, 0..) |*it, i| {
            it.* = .{ .address = p[i * 32 ..][0..32].* };
        },
        else => unreachable,
    }
}

/// Layout values into a new primitive vector's elements (`fromLayout` + `writeElem` of each).
/// A packed `vector<u8>` layout value as a VM `vector<u8>`.
fn bytesFromLayout(h: value.Heap, b: []const u8) loader.LoadError!Value {
    const c = try h.newContainer(.vec_u8, b.len);
    @memcpy(c.data[0..b.len], b);
    return Value.container(c);
}

fn primFromLayout(c: *value.Container, items: []const LV) void {
    const p = c.data;
    switch (c.kind) {
        .vec_u8 => for (items, 0..) |it, i| {
            p[i] = it.u8;
        },
        .vec_bool => for (items, 0..) |it, i| {
            p[i] = @intFromBool(it.bool);
        },
        .vec_u16 => for (items, 0..) |it, i| std.mem.writeInt(u16, p[i * 2 ..][0..2], it.u16, .little),
        .vec_u32 => for (items, 0..) |it, i| std.mem.writeInt(u32, p[i * 4 ..][0..4], it.u32, .little),
        .vec_u64 => for (items, 0..) |it, i| std.mem.writeInt(u64, p[i * 8 ..][0..8], it.u64, .little),
        .vec_u128 => for (items, 0..) |it, i| std.mem.writeInt(u128, p[i * 16 ..][0..16], it.u128, .little),
        .vec_u256 => for (items, 0..) |it, i| std.mem.writeInt(u256, p[i * 32 ..][0..32], it.u256, .little),
        .vec_address => for (items, 0..) |it, i| {
            p[i * 32 ..][0..32].* = it.address;
        },
        else => unreachable,
    }
}

/// `Type.vecKind` of a vector whose element has layout `e`.
fn vecKindOf(e: *const Layout) value.Kind {
    return switch (e.*) {
        .u8 => .vec_u8,
        .u16 => .vec_u16,
        .u32 => .vec_u32,
        .u64 => .vec_u64,
        .u128 => .vec_u128,
        .u256 => .vec_u256,
        .bool => .vec_bool,
        .address => .vec_address,
        else => .vec,
    };
}

/// `toLayout` walking a layout instead of a type: the same layout value for a value of the
/// type the layout was made from (no field types instantiated).
pub fn toLayoutL(arena: Allocator, l: *const Layout, v: Value) loader.LoadError!LV {
    return switch (l.*) {
        .bool => .{ .bool = v.a != 0 },
        .u8 => .{ .u8 = @truncate(v.a) },
        .u16 => .{ .u16 = @truncate(v.a) },
        .u32 => .{ .u32 = @truncate(v.a) },
        .u64 => .{ .u64 = v.a },
        .u128 => .{ .u128 = v.asU128() },
        .u256 => .{ .u256 = v.asU256() },
        .address => .{ .address = v.box().* },
        .signer => .{ .signer = v.cont().values()[0].box().* },
        .vector => |e| blk: {
            const c = v.cont();
            if (c.kind == .vec_u8) break :blk .{ .bytes = try arena.dupe(u8, c.data[0..c.len]) };
            const items = try arena.alloc(LV, c.len);
            if (c.kind.isPrimVec()) {
                primToLayout(c, items);
            } else for (items, c.values()) |*it, x| {
                it.* = try toLayoutL(arena, e, x);
            }
            break :blk .{ .vector = items };
        },
        .@"struct" => |sl| blk: {
            const c = v.cont();
            const fields = sl.@"0";
            const items = try arena.alloc(LV, fields.len);
            for (fields, c.values(), items) |*fl, x, *it| it.* = try toLayoutL(arena, fl, x);
            break :blk .{ .@"struct" = items };
        },
        .@"enum" => |el| blk: {
            const c = v.cont();
            const fields = el.@"0"[c.tag];
            const items = try arena.alloc(LV, fields.len);
            for (fields, c.values(), items) |*fl, x, *it| it.* = try toLayoutL(arena, fl, x);
            break :blk .{ .variant = .{ .tag = @intCast(c.tag), .fields = items } };
        },
    };
}

/// `fromLayout` walking a layout instead of a type.
pub fn fromLayoutL(h: value.Heap, l: *const Layout, v: LV) loader.LoadError!Value {
    return switch (l.*) {
        .bool => Value.bool_(v.bool),
        .u8 => Value.u8_(v.u8),
        .u16 => Value.u16_(v.u16),
        .u32 => Value.u32_(v.u32),
        .u64 => Value.u64_(v.u64),
        .u128 => Value.u128_(v.u128),
        .u256 => h.u256_(v.u256),
        .address => Value.boxed(.address, try h.box32(v.address)),
        .signer => blk: {
            const c = try h.newContainer(.struct_, 1);
            c.values()[0] = Value.boxed(.address, try h.box32(v.signer));
            break :blk Value.container(c);
        },
        .vector => |e| blk: {
            const k = vecKindOf(e);
            if (v == .bytes) break :blk try bytesFromLayout(h, v.bytes);
            const items = v.vector;
            const c = try h.newContainer(k, items.len);
            if (k.isPrimVec()) {
                primFromLayout(c, items);
            } else for (items, c.values()) |it, *x| {
                x.* = try fromLayoutL(h, e, it);
            }
            break :blk Value.container(c);
        },
        .@"struct" => |sl| blk: {
            const fields = sl.@"0";
            const items = v.@"struct";
            const c = try h.newContainer(.struct_, fields.len);
            c.tag = 0;
            for (fields, items, c.values()) |*fl, it, *x| x.* = try fromLayoutL(h, fl, it);
            break :blk Value.container(c);
        },
        .@"enum" => |el| blk: {
            const tag: u16 = v.variant.tag;
            const fields = el.@"0"[tag];
            const c = try h.newContainer(.variant, fields.len);
            c.tag = tag;
            for (fields, v.variant.fields, c.values()) |*fl, it, *x| x.* = try fromLayoutL(h, fl, it);
            break :blk Value.container(c);
        },
    };
}

/// `types.deserialize` walking a layout: the same VM value from the same BCS bytes for a value
/// of the type the layout was made from (no field types instantiated).
pub fn deserializeL(h: value.Heap, l: *const Layout, r: *loader.Reader, depth: u32) loader.DecodeError!Value {
    if (depth > 1024) return error.TooDeep;
    switch (l.*) {
        .vector => |e| {
            const n = try r.uleb();
            const k = vecKindOf(e);
            if (n > r.bytes.len - r.pos) return error.EndOfInput;
            if (k != .vec) {
                const bytes = try r.take(n * k.width());
                const c = try h.newContainer(k, n);
                if (k == .vec_bool) for (bytes) |b| if (b > 1) return error.BadBool;
                @memcpy(c.bytes(), bytes);
                return Value.container(c);
            }
            const c = try h.newContainer(.vec, n);
            for (c.values()) |*v| v.* = try deserializeL(h, e, r, depth + 1);
            return Value.container(c);
        },
        .@"enum" => |el| {
            const tag = try r.uleb();
            if (tag >= el.@"0".len) return error.BadTag;
            const fields = el.@"0"[tag];
            const c = try h.newContainer(.variant, fields.len);
            c.tag = @intCast(tag);
            for (fields, c.values()) |*fl, *v| v.* = try deserializeL(h, fl, r, depth + 1);
            return Value.container(c);
        },
        .@"struct" => |sl| {
            const fields = sl.@"0";
            const c = try h.newContainer(.struct_, fields.len);
            for (fields, c.values()) |*fl, *v| v.* = try deserializeL(h, fl, r, depth + 1);
            return Value.container(c);
        },
        .bool => return loader.primValue(h, .bool, r),
        .u8 => return loader.primValue(h, .u8, r),
        .u16 => return loader.primValue(h, .u16, r),
        .u32 => return loader.primValue(h, .u32, r),
        .u64 => return loader.primValue(h, .u64, r),
        .u128 => return loader.primValue(h, .u128, r),
        .u256 => return loader.primValue(h, .u256, r),
        .address => return loader.primValue(h, .address, r),
        .signer => return loader.primValue(h, .signer, r),
    }
}

// ---------------------------------------------------------------------------------------------
// Type tags and layouts of type arguments

const IdKind = enum { defining, original };

pub fn typeTag(arena: Allocator, t: *const Type, ids: IdKind) Allocator.Error!*const TypeTag {
    const out = try arena.create(TypeTag);
    out.* = switch (t.*) {
        .bool => .bool,
        .u8 => .u8,
        .u16 => .u16,
        .u32 => .u32,
        .u64 => .u64,
        .u128 => .u128,
        .u256 => .u256,
        .address => .address,
        .signer => .signer,
        .vector => |e| .{ .vector = try typeTag(arena, e, ids) },
        .datatype => |d| blk: {
            const args = try arena.alloc(TypeTag, d.args.len);
            for (d.args, args) |a, *o| o.* = (try typeTag(arena, a, ids)).*;
            const addr = switch (ids) {
                .defining => d.dt.defining_id,
                .original => d.dt.module.pkg.original_id,
            };
            break :blk .{ .@"struct" = .{
                .address = .{ .@"0" = addr },
                .module = .{ .@"0" = d.dt.module.name },
                .name = .{ .@"0" = d.dt.name },
                .type_args = args,
            } };
        },
        .ref, .mut_ref, .param => unreachable,
    };
    return out;
}

/// `TypeSize::from_vm_config_for_value_depth`: the limits `type_to_type_layout` and
/// `type_to_fully_annotated_layout` run under (depth `max_move_value_depth`, nodes
/// `max_type_to_layout_nodes`). Past them Rust's native context gets `None`.
pub const Limits = struct {
    max_depth: u64,
    max_nodes: u64,
    /// exec-history-vm: v0..v2 and v3 before `variant_nodes` (72): the node count is checked
    /// before each node is counted (max + 1 nodes pass), variants do not count, and the depth
    /// limit is VALUE_DEPTH_MAX (128) checked before descending.
    legacy: bool = false,
    pub const none: Limits = .{ .max_depth = std.math.maxInt(u64), .max_nodes = std.math.maxInt(u64) };
    pub fn of(cfg: interp.ExecConfig) Limits {
        if (cfg.rules.legacy_layout_count) return .{ .max_depth = 128, .max_nodes = cfg.max_type_nodes, .legacy = true };
        return .{ .max_depth = cfg.max_value_depth orelse 128, .max_nodes = cfg.max_type_nodes };
    }
};

const TypeSize = struct {
    lim: Limits,
    depth: u64 = 0,
    nodes: u64 = 0,
    fn check(z: *const TypeSize) error{Limit}!void {
        if (z.lim.legacy) return; // no checks after a node in the legacy count
        if (z.depth > z.lim.max_depth or z.nodes > z.lim.max_nodes) return error.Limit;
    }
    fn enter(z: *TypeSize) error{Limit}!void {
        if (z.lim.legacy) {
            if (z.nodes > z.lim.max_nodes or z.depth > z.lim.max_depth) return error.Limit;
            z.depth += 1;
            z.nodes += 1;
            return;
        }
        z.depth += 1;
        z.nodes += 1;
        try z.check();
    }
    fn incrNodes(z: *TypeSize) error{Limit}!void {
        if (z.lim.legacy) return; // variants count from variant_nodes
        z.nodes += 1;
        if (z.nodes > z.lim.max_nodes) return error.Limit;
    }
};

const LayoutError = Allocator.Error || error{Limit};

/// `type_to_type_layout` under `lim`; null where Rust's native context gets `None`.
pub fn layoutLimited(arena: Allocator, t: *const Type, lim: Limits) Allocator.Error!?*const Layout {
    var z: TypeSize = .{ .lim = lim };
    return layoutImpl(arena, t, &z) catch |e| switch (e) {
        error.Limit => null,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn layoutImpl(arena: Allocator, t: *const Type, z: *TypeSize) LayoutError!*const Layout {
    try z.enter();
    const out = try arena.create(Layout);
    out.* = switch (t.*) {
        .bool => .bool,
        .u8 => .u8,
        .u16 => .u16,
        .u32 => .u32,
        .u64 => .u64,
        .u128 => .u128,
        .u256 => .u256,
        .address => .address,
        .signer => .signer,
        .vector => |e| .{ .vector = try layoutImpl(arena, e, z) },
        .datatype => |d| blk: {
            try z.check();
            if (d.dt.is_enum) {
                const vs = try arena.alloc([]const Layout, d.dt.variants.len);
                for (d.dt.variants, vs) |vd, *o| {
                    try z.incrNodes();
                    const fs = try arena.alloc(Layout, vd.fields.len);
                    for (vd.fields, fs) |fd, *fo| fo.* = (try layoutImpl(arena, try fieldType(arena, d, fd.signature), z)).*;
                    o.* = fs;
                }
                try z.check();
                const el = try arena.create(types_mod.layout.MoveEnumLayout);
                el.* = .{ .@"0" = vs };
                break :blk .{ .@"enum" = el };
            }
            const fs = try arena.alloc(Layout, d.dt.fields.len);
            for (d.dt.fields, fs) |fd, *fo| fo.* = (try layoutImpl(arena, try fieldType(arena, d, fd.signature), z)).*;
            try z.check();
            const sl = try arena.create(types_mod.layout.MoveStructLayout);
            sl.* = .{ .@"0" = fs };
            break :blk .{ .@"struct" = sl };
        },
        .ref, .mut_ref, .param => return error.Limit,
    };
    try z.check();
    z.depth -= 1;
    return out;
}

const ALayout = abi.objrt.ALayout;

/// `type_to_fully_annotated_layout` under `lim` (struct tags with defining ids); null where Rust
/// gets `None`.
pub fn annotatedLimited(arena: Allocator, t: *const Type, lim: Limits) Allocator.Error!?*const ALayout {
    var z: TypeSize = .{ .lim = lim };
    const l = annotatedImpl(arena, t, &z) catch |e| switch (e) {
        error.Limit => return null,
        error.OutOfMemory => return error.OutOfMemory,
    };
    const out = try arena.create(ALayout);
    out.* = l;
    return out;
}

fn annotatedImpl(arena: Allocator, t: *const Type, z: *TypeSize) LayoutError!ALayout {
    try z.enter();
    const out: ALayout = switch (t.*) {
        .bool => .bool,
        .u8 => .u8,
        .u16 => .u16,
        .u32 => .u32,
        .u64 => .u64,
        .u128 => .u128,
        .u256 => .u256,
        .address => .address,
        .signer => .signer,
        .vector => |e| blk: {
            const el = try arena.create(ALayout);
            el.* = try annotatedImpl(arena, e, z);
            break :blk .{ .vector = el };
        },
        .datatype => |d| blk: {
            try z.check();
            const tag = (try typeTag(arena, t, .defining)).@"struct";
            const cm = d.dt.module.cm;
            if (d.dt.is_enum) {
                const vs = try arena.alloc(abi.objrt.AVariant, d.dt.variants.len);
                for (d.dt.variants, vs, 0..) |vd, *o, vi| {
                    try z.incrNodes();
                    const fs = try arena.alloc(abi.objrt.AField, vd.fields.len);
                    for (vd.fields, fs) |fd, *fo| fo.* = .{ .name = .{ .@"0" = cm.identifiers[fd.name] }, .layout = try annotatedImpl(arena, try fieldType(arena, d, fd.signature), z) };
                    o.* = .{ .key = .{ .name = .{ .@"0" = cm.identifiers[vd.variant_name] }, .tag = @intCast(vi) }, .fields = fs };
                }
                // Rust keys variants by (name, tag) in a BTreeMap: name order.
                std.mem.sort(abi.objrt.AVariant, vs, {}, variantLess);
                try z.check();
                const e = try arena.create(abi.objrt.AEnum);
                e.* = .{ .type_ = tag, .variants = vs };
                break :blk .{ .@"enum" = e };
            }
            const fs = try arena.alloc(abi.objrt.AField, d.dt.fields.len);
            for (d.dt.fields, fs) |fd, *fo| fo.* = .{ .name = .{ .@"0" = cm.identifiers[fd.name] }, .layout = try annotatedImpl(arena, try fieldType(arena, d, fd.signature), z) };
            try z.check();
            const st = try arena.create(abi.objrt.AStruct);
            st.* = .{ .type_ = tag, .fields = fs };
            break :blk .{ .@"struct" = st };
        },
        .ref, .mut_ref, .param => return error.Limit,
    };
    try z.check();
    z.depth -= 1;
    return out;
}

fn variantLess(_: void, a: abi.objrt.AVariant, b: abi.objrt.AVariant) bool {
    return switch (std.mem.order(u8, a.key.name.@"0", b.key.name.@"0")) {
        .lt => true,
        .gt => false,
        .eq => a.key.tag < b.key.tag,
    };
}

fn fieldType(arena: Allocator, d: Type.Inst, tok: loader.Token) LayoutError!*const Type {
    return vm_types.instantiate(arena, d.dt.module, tok, d.args) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Limit,
    };
}


// ---------------------------------------------------------------------------------------------
// Vector natives on VM vectors (move-stdlib vector.rs costs, as src/natives/stdlib.zig charges)

const INDEX_OUT_OF_BOUNDS: u64 = 1;
const VEC_SIZE_LIMIT_REACHED: u64 = 4;

fn gasCtx(ctx: *interp.NativeContext) Allocator.Error!abi.Ctx {
    const host: *Host = @ptrCast(@alignCast(ctx.ext.?));
    return abi.Ctx.init(ctx.scratch(), host.cfg, ctx.gas_budget, &host.tx, &host.rt);
}

fn oog(c: *const abi.Ctx) interp.NativeResult {
    return .{ .cost = c.budget, .outcome = .{ .abort = abi.NFE_OUT_OF_GAS } };
}

fn done(c: *const abi.Ctx, rets: []const Value) interp.NativeResult {
    return .{ .cost = c.used(), .outcome = .{ .ok = rets } };
}

fn abortWith(c: *const abi.Ctx, code: u64) interp.NativeResult {
    return .{ .cost = c.used(), .outcome = .{ .abort = code } };
}

fn vecOf(r: Value) *value.Container {
    return readThrough(r).cont();
}

fn validRange(len: u64, i: u64, j: u64) bool {
    return i <= j and j <= len;
}

/// Moves elements `[from, from+n)` to `to` inside one vector (overlapping ranges).
fn moveElems(c: *value.Container, to: usize, from: usize, n: usize) void {
    const w = c.kind.width();
    const base = c.data;
    std.mem.copyForwards(u8, base[to * w .. (to + n) * w], base[from * w .. (from + n) * w]);
}

fn moveElemsBack(c: *value.Container, to: usize, from: usize, n: usize) void {
    const w = c.kind.width();
    const base = c.data;
    std.mem.copyBackwards(u8, base[to * w .. (to + n) * w], base[from * w .. (from + n) * w]);
}

fn vecReverse(ctx: *interp.NativeContext, _: ?*const anyopaque, _: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!interp.NativeResult {
    var c = try gasCtx(ctx);
    if (!c.charge(c.p("vector_reverse_base_cost"))) return oog(&c);
    const v = vecOf(args[0]);
    if (!c.charge(c.p("vector_reverse_per_elem_cost") *| v.len)) return oog(&c);
    const w = v.kind.width();
    var i: usize = 0;
    var j: usize = v.len;
    var tmp: [32]u8 = undefined;
    while (i + 1 < j) : (i += 1) {
        j -= 1;
        const a = v.data[i * w ..][0..w];
        const b = v.data[j * w ..][0..w];
        @memcpy(tmp[0..w], a);
        @memcpy(a, b);
        @memcpy(b, tmp[0..w]);
    }
    return done(&c, &.{});
}

/// `vector::borrow(_mut)` called as a function (`native_borrow`): a reference to the element,
/// out of bounds aborts with INDEX_OUT_OF_BOUNDS (`native_error_to_abort`) after the base charge.
fn vecBorrow(ctx: *interp.NativeContext, _: ?*const anyopaque, _: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!interp.NativeResult {
    var c = try gasCtx(ctx);
    if (!c.charge(c.p("vector_borrow_base_cost"))) return oog(&c);
    const idx = args[1].a;
    const v = vecOf(args[0]);
    if (idx >= v.len) return abortWith(&c, INDEX_OUT_OF_BOUNDS);
    const rets = try ctx.scratch().alloc(Value, 1);
    rets[0] = if (v.kind.isPrimVec()) Value.refElem(v, idx) else Value.refSlot(&v.values()[@intCast(idx)]);
    return done(&c, rets);
}

fn vecKeepRange(ctx: *interp.NativeContext, _: ?*const anyopaque, _: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!interp.NativeResult {
    var c = try gasCtx(ctx);
    if (!c.charge(c.p("vector_keep_range_base_cost"))) return oog(&c);
    const end = args[2].a;
    const start = args[1].a;
    const v = vecOf(args[0]);
    const len: u64 = v.len;
    var dropped: u64 = 0;
    var moved: u64 = 0;
    if (validRange(len, start, end)) {
        const retained = end - start;
        dropped = len - retained;
        moved = if (start == 0) 0 else retained;
    }
    if (!c.charge(c.p("vector_keep_range_per_dropped_elem_cost") *| dropped)) return oog(&c);
    if (!c.charge(c.p("vector_keep_range_per_moved_elem_cost") *| moved)) return oog(&c);
    if (!validRange(len, start, end)) return abortWith(&c, INDEX_OUT_OF_BOUNDS);
    const h = ctx.heap();
    const s: usize = @intCast(start);
    const e: usize = @intCast(end);
    if (!v.kind.isPrimVec()) {
        for (v.values()[0..s]) |x| h.drop(x);
        for (v.values()[e..]) |x| h.drop(x);
    }
    moveElems(v, 0, s, e - s);
    v.len = @intCast(e - s);
    return done(&c, &.{});
}

fn vecCopyRange(ctx: *interp.NativeContext, _: ?*const anyopaque, _: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!interp.NativeResult {
    var c = try gasCtx(ctx);
    if (!c.charge(c.p("vector_copy_range_base_cost"))) return oog(&c);
    const j = args[2].a;
    const i = args[1].a;
    const v = vecOf(args[0]);
    if (!validRange(v.len, i, j)) return abortWith(&c, INDEX_OUT_OF_BOUNDS);
    const h = ctx.heap();
    const n: usize = @intCast(j - i);
    const out = try h.newContainer(v.kind, n);
    if (v.kind.isPrimVec()) {
        const w = v.kind.width();
        @memcpy(out.data[0 .. n * w], v.data[@as(usize, @intCast(i)) * w ..][0 .. n * w]);
    } else for (out.values(), v.values()[@intCast(i)..@intCast(j)]) |*o, x| {
        o.* = try h.copy(x);
    }
    const rets = try ctx.scratch().alloc(Value, 1);
    rets[0] = Value.container(out);
    return done(&c, rets);
}

fn vecReplaceRange(ctx: *interp.NativeContext, _: ?*const anyopaque, _: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!interp.NativeResult {
    var c = try gasCtx(ctx);
    const h = ctx.heap();
    const other = args[3].cont();
    if (!c.charge(c.p("vector_replace_range_base_cost"))) {
        h.drop(args[3]);
        return oog(&c);
    }
    const j = args[2].a;
    const i = args[1].a;
    const v = vecOf(args[0]);
    const len: u64 = v.len;
    const n_in: u64 = other.len;
    var count: u64 = 0;
    if (validRange(len, i, j)) {
        const tail_moved: u64 = if (n_in == j - i) 0 else len - j;
        count = n_in +| tail_moved;
    }
    if (!c.charge(c.p("vector_replace_range_per_elem_cost") *| count)) {
        h.drop(args[3]);
        return oog(&c);
    }
    if (!validRange(len, i, j)) {
        h.drop(args[3]);
        return abortWith(&c, INDEX_OUT_OF_BOUNDS);
    }
    const new_len = len - (j - i) + n_in;
    if (new_len > c.vector_len_max) {
        h.drop(args[3]);
        return abortWith(&c, VEC_SIZE_LIMIT_REACHED);
    }
    const ii: usize = @intCast(i);
    const jj: usize = @intCast(j);
    const w = v.kind.width();
    // The removed elements move out into a new vector.
    const removed = try h.newContainer(v.kind, jj - ii);
    @memcpy(removed.data[0 .. (jj - ii) * w], v.data[ii * w .. jj * w]);
    try h.ensureCap(v, @intCast(new_len));
    const tail = v.len - jj;
    const at = ii + other.len;
    if (at > jj) moveElemsBack(v, at, jj, tail) else moveElems(v, at, jj, tail);
    @memcpy(v.data[ii * w .. at * w], other.data[0 .. @as(usize, other.len) * w]);
    v.len = @intCast(new_len);
    // `other`'s elements moved into `v`: free only its storage.
    h.freeShell(other);
    const rets = try ctx.scratch().alloc(Value, 1);
    rets[0] = Value.container(removed);
    return done(&c, rets);
}

/// `object::borrow_uid<T: key>(obj: &T): &UID` (`obj.borrow_field(0)`): a reference to the
/// object's first field, on the VM's own value.
fn borrowUid(ctx: *interp.NativeContext, _: ?*const anyopaque, _: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!interp.NativeResult {
    var c = try gasCtx(ctx);
    if (!c.charge(c.p("object_borrow_uid_cost_base"))) return oog(&c);
    const obj = readThrough(args[0]);
    if (obj.tag != .container or obj.cont().len == 0) return ctx.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null);
    const rets = try ctx.scratch().alloc(Value, 1);
    rets[0] = Value.refSlot(&obj.cont().values()[0]);
    return done(&c, rets);
}

/// A deep copy of `t` in `a` (instantiated types point at frame-scoped type arguments).
fn cloneType(a: Allocator, t: *const Type) Allocator.Error!*const Type {
    const out = try a.create(Type);
    out.* = switch (t.*) {
        .vector => |e| .{ .vector = try cloneType(a, e) },
        .ref => |e| .{ .ref = try cloneType(a, e) },
        .mut_ref => |e| .{ .mut_ref = try cloneType(a, e) },
        .datatype => |d| blk: {
            const args = try a.alloc(*const Type, d.args.len);
            for (d.args, args) |x, *o| o.* = try cloneType(a, x);
            break :blk .{ .datatype = .{ .dt = d.dt, .args = args } };
        },
        else => t.*,
    };
    return out;
}

// ---------------------------------------------------------------------------------------------
// Hot natives on VM values. Same charges, in the same order, as src/natives (stdlib.zig,
// sui.zig); proven by move-vm-gas/move-vm-trace like every other native path.

fn fastNative(short: u16, module: []const u8, func: []const u8) ?interp.NativeFn {
    const F = struct { s: u16, m: []const u8, f: []const u8, n: interp.NativeFn };
    const table = [_]F{
        .{ .s = 1, .m = "hash", .f = "sha2_256", .n = fastSha2 },
        .{ .s = 1, .m = "hash", .f = "sha3_256", .n = fastSha3 },
        .{ .s = 2, .m = "hash", .f = "blake2b256", .n = fastBlake2b },
        .{ .s = 2, .m = "hash", .f = "keccak256", .n = fastKeccak },
        .{ .s = 1, .m = "bcs", .f = "to_bytes", .n = fastToBytes },
    };
    inline for (table) |e| if (short == e.s and std.mem.eql(u8, module, e.m) and std.mem.eql(u8, func, e.f)) return e.n;
    return null;
}

/// The bytes of a `vector<u8>` or `&vector<u8>` argument.
fn byteArg(v: Value) []const u8 {
    const c = readThrough(v).cont();
    return c.data[0..c.len];
}

/// Drops a by-value argument (references own nothing).
fn dropArg(ctx: *interp.NativeContext, v: Value) void {
    if (!v.isRef()) ctx.heap().drop(v);
}

fn bytesResult(ctx: *interp.NativeContext, b: []const u8) Allocator.Error![]const Value {
    const c = try ctx.heap().newContainer(.vec_u8, b.len);
    @memcpy(c.data[0..b.len], b);
    const rets = try ctx.scratch().alloc(Value, 1);
    rets[0] = Value.container(c);
    return rets;
}

fn hashLegacy(ctx: *interp.NativeContext, args: []Value, comptime H: type, comptime base: []const u8, comptime per_byte: []const u8, comptime min_len: []const u8) (error{Vm} || loader.LoadError)!interp.NativeResult {
    var c = try gasCtx(ctx);
    const data = byteArg(args[0]);
    defer dropArg(ctx, args[0]);
    if (!c.charge(c.p(base) +| c.p(per_byte) *| @max(@as(u64, data.len), c.p(min_len)))) return oog(&c);
    var out: [32]u8 = undefined;
    H.hash(data, &out);
    return done(&c, try bytesResult(ctx, &out));
}

fn fastSha2(ctx: *interp.NativeContext, _: ?*const anyopaque, _: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!interp.NativeResult {
    return hashLegacy(ctx, args, hash.Sha256, "hash_sha2_256_base_cost", "hash_sha2_256_per_byte_cost", "hash_sha2_256_legacy_min_input_len_cost");
}

fn fastSha3(ctx: *interp.NativeContext, _: ?*const anyopaque, _: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!interp.NativeResult {
    return hashLegacy(ctx, args, hash.Sha3_256, "hash_sha3_256_base_cost", "hash_sha3_256_per_byte_cost", "hash_sha3_256_legacy_min_input_len_cost");
}

fn hashBlocks(ctx: *interp.NativeContext, args: []Value, comptime H: type, comptime base: []const u8, comptime per_byte: []const u8, comptime per_block: []const u8, comptime block: usize) (error{Vm} || loader.LoadError)!interp.NativeResult {
    var c = try gasCtx(ctx);
    defer dropArg(ctx, args[0]);
    if (!c.charge(c.p(base))) return oog(&c);
    const m = byteArg(args[0]);
    const nblocks: u64 = @intCast((m.len + block - 1) / block);
    if (!c.charge(c.p(per_byte) *| m.len +| c.p(per_block) *| nblocks)) return oog(&c);
    var out: [32]u8 = undefined;
    H.hash(m, &out);
    return done(&c, try bytesResult(ctx, &out));
}

fn fastBlake2b(ctx: *interp.NativeContext, _: ?*const anyopaque, _: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!interp.NativeResult {
    return hashBlocks(ctx, args, hash.Blake2b256, "hash_blake2b256_cost_base", "hash_blake2b256_data_cost_per_byte", "hash_blake2b256_data_cost_per_block", 128);
}

fn fastKeccak(ctx: *interp.NativeContext, _: ?*const anyopaque, _: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!interp.NativeResult {
    return hashBlocks(ctx, args, hash.Keccak256, "hash_keccak256_cost_base", "hash_keccak256_data_cost_per_byte", "hash_keccak256_data_cost_per_block", 136);
}

/// `bcs::to_bytes<T>(v: &T)`: serialized straight from the VM value. A type whose layout Rust
/// cannot build (past the layout limits) fails as the generic native does.
fn fastToBytes(ctx: *interp.NativeContext, _: ?*const anyopaque, ty_args: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!interp.NativeResult {
    var c = try gasCtx(ctx);
    const t = ty_args[0];
    var z: TypeSize = .{ .lim = Limits.of(ctx.session.cfg) };
    const scratch = ctx.scratch();
    layoutFits(scratch, t, &z) catch |e| switch (e) {
        error.Limit => {
            _ = c.charge(c.p("bcs_failure_cost"));
            return abortWith(&c, abi.NFE_BCS_SERIALIZATION_FAILURE);
        },
        error.OutOfMemory => return error.OutOfMemory,
    };
    var out: std.ArrayList(u8) = .empty;
    try vm_types.serialize(scratch, t, readThrough(args[0]), &out);
    if (!c.charge(c.p("bcs_per_byte_serialized_cost") *| @max(@as(u64, out.items.len), c.p("bcs_legacy_min_output_size_cost")))) return oog(&c);
    return done(&c, try bytesResult(ctx, out.items));
}

/// `layoutImpl`'s limit checks without building the layout (field types go to `a`).
fn layoutFits(a: Allocator, t: *const Type, z: *TypeSize) LayoutError!void {
    try z.enter();
    switch (t.*) {
        .vector => |e| try layoutFits(a, e, z),
        .datatype => |d| {
            try z.check();
            if (d.dt.is_enum) {
                for (d.dt.variants) |vd| {
                    try z.incrNodes();
                    for (vd.fields) |fd| try layoutFits(a, try fieldType(a, d, fd.signature), z);
                }
            } else for (d.dt.fields) |fd| try layoutFits(a, try fieldType(a, d, fd.signature), z);
            try z.check();
        },
        .ref, .mut_ref, .param => return error.Limit,
        else => {},
    }
    try z.check();
    z.depth -= 1;
}
