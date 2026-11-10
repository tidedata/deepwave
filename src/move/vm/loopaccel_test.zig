//! Exactness tests of the loop accelerators (loopaccel.zig): every target function runs through
//! the plain interpreter (switch off) and through the accelerated path (switch on) from the same
//! inputs and the same meter state, and everything observable must be equal: the status, the
//! error location, the whole meter (gas left, instruction count, stack height and size with
//! their high-water marks, tier state), the returned values and the arguments behind `&mut`.
//!
//! The target functions are the real ones: the Move stdlib `vector` module of every framework
//! snapshot in `natives/framework.bin` (one world per distinct bytecode and gas model version),
//! and the Wormhole `bytes` / `cursor` and Pyth `merkle_tree` modules as published on mainnet
//! (loopaccel_fixtures/, the module bytes of packages 0x5306..fb6a version 1 and 0x04e2..ad91),
//! also under the addresses of their second mainnet deployments (0x99de..25b4 and 0x5530..e2c0),
//! whose modules are the same bytes with other address identifiers.
//! Gas is swept in internal units (1/1000 of a gas unit), one unit at a time from 0 up to the
//! cost of the whole call, so out of gas lands on every instruction of every iteration. Every
//! world takes that sweep for empty, 1, 2, odd and even inputs; the newest gas model of each
//! bytecode also for inputs of 64 and of 100 or more iterations. Inputs that cross the tiers
//! inside the loop (thousands of iterations) are swept at sampled budgets.
//! On top of the mainnet pairs, every bytecode runs under every gas model version up to
//! `loopaccel.MAX_GM` (`crossWorlds`), at sampled budgets.
//! ZUI_LOOPACCEL_SWEEP=full (many minutes, for an optimized build) widens all of it: more sizes
//! and every element kind in every world, every length up to 64 on the newest gas model of each
//! bytecode, 400 sampled budgets, every offset around the tier starts.
const std = @import("std");
const protocol = @import("protocol");
const move_format = @import("move_format");
const ff = move_format.file_format;
const natives = @import("natives");
const loader = @import("loader.zig");
const interp = @import("interp.zig");
const value = @import("value.zig");
const gas = @import("gas.zig");
const host = @import("host.zig");
const conformance = @import("conformance.zig");
const loopaccel = @import("loopaccel.zig");

const Allocator = std.mem.Allocator;
const Value = value.Value;
const Type = loader.Type;

/// More than any test call costs, in internal gas units.
const BIG: u64 = 1 << 40;

/// The runtimes (and the link contexts made from them) allocate here: the testing allocator
/// records a stack trace per allocation, which a link context made for every run cannot afford.
const rt_gpa = std.heap.smp_allocator;

// ---------------------------------------------------------------------------------------------
// Worlds: one loaded stdlib per (vector bytecode, gas model version)

pub const World = struct {
    rt: *loader.Runtime,
    pkg: *loader.Package,
    module: *loader.Module,
    digest: [32]u8,
    /// The first protocol version with this bytecode and gas model, and its configs.
    pv: u64,
    gm: u64,
    ecfg: interp.ExecConfig,
    /// The last world (latest gas model) of its bytecode: the one the widest sweeps run on.
    primary: bool = false,
    /// The calls need the Sui natives (Pyth hashes with keccak256).
    natives: bool = false,
    /// `0x1::string::String` of this world's stdlib: the struct element type (`Elem.struct_`).
    struct_ty: ?*const Type = null,

    /// The registered functions of this world's module (none: no template for its bytecode).
    pub fn templates(w: *const World) []const loopaccel.FnT {
        for (&loopaccel.registry) |*e| {
            if (std.mem.eql(u8, &e.digest, &w.digest)) return e.fns;
        }
        return &.{};
    }
    pub fn templated(w: *const World, name: []const u8) bool {
        for (w.templates()) |ft| if (std.mem.eql(u8, ft.name, name)) return true;
        return false;
    }
};

pub const Worlds = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    list: std.ArrayList(World) = .empty,
    rts: std.ArrayList(*loader.Runtime) = .empty,

    pub fn deinit(ws: *Worlds) void {
        for (ws.rts.items) |rt| {
            rt.deinit();
            rt_gpa.destroy(rt);
        }
        ws.arena.deinit();
    }
};

/// `0x1::string::String { bytes: vector<u8> }` as loaded in `pkg` (every stdlib has it).
fn stringType(pkg: *loader.Package) !*const Type {
    const m = pkg.module("string") orelse return error.NoStringModule;
    for (m.structs) |*dt| if (std.mem.eql(u8, dt.name, "String")) return &dt.plain;
    return error.NoStringStruct;
}

fn isStd(id: *const [32]u8) bool {
    for (id[0..31]) |b| if (b != 0) return false;
    return id[31] == 1;
}

/// Loads Move stdlib (0x1) of every framework snapshot whose `vector` bytecode differs, with the
/// accelerators on while loading (so they attach), and lists a world per gas model version the
/// bytecode ran under on mainnet. Snapshots whose `vector::reverse` is native (protocol 140 and
/// later: the loops are gone, `append` and `remove` call the `replace_range` native) have no
/// world.
pub fn stdWorlds(gpa: Allocator) !Worlds {
    var ws: Worlds = .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa) };
    errdefer ws.deinit();
    const a = ws.arena.allocator();
    const vers = try natives.framework.load(a);
    const bcfg: move_format.BinaryConfig = .{};
    const Loaded = struct { snap: u64, rt: *loader.Runtime, pkg: *loader.Package, module: *loader.Module, digest: [32]u8 };
    var loaded: std.ArrayList(Loaded) = .empty;
    loopaccel.enable();
    defer loopaccel.disable();
    var pv: u64 = protocol.min_protocol_version;
    while (pv <= protocol.max_protocol_version) : (pv += 1) {
        const snap = natives.framework.snapshot(vers, pv) orelse continue;
        const cfg = try protocol.get(pv, .mainnet);
        const gm = cfg.get("gas_model_version") catch continue;
        const ecfg = interp.ExecConfig.fromProtocolAnyCut(cfg) catch continue;
        var l: ?Loaded = null;
        for (loaded.items) |x| if (x.snap == snap.version) {
            l = x;
        };
        if (l == null) {
            const sp = for (snap.packages) |*p| {
                if (isStd(&p.id)) break p;
            } else continue;
            // the digest of this snapshot's vector module; reuse the runtime of an equal one
            var digest: [32]u8 = undefined;
            var found = false;
            const mods = try a.alloc(loader.NamedModule, sp.modules.len);
            for (sp.modules, mods) |b, *m| {
                const cm = switch (try move_format.deserialize(a, b, &bcfg)) {
                    .ok => |cm| cm,
                    else => return error.BadModule,
                };
                m.* = .{ .name = cm.selfName(), .bytes = b };
                if (std.mem.eql(u8, cm.selfName(), "vector")) {
                    digest = loopaccel.codeDigest(&cm);
                    found = true;
                }
            }
            if (!found) return error.NoVectorModule;
            for (loaded.items) |x| if (std.mem.eql(u8, &x.digest, &digest)) {
                l = .{ .snap = snap.version, .rt = x.rt, .pkg = x.pkg, .module = x.module, .digest = digest };
            };
            if (l == null) {
                const rt = try rt_gpa.create(loader.Runtime);
                rt.* = loader.Runtime.init(rt_gpa, bcfg);
                try ws.rts.append(a, rt);
                const link = [_][2]loader.Address{.{ sp.id, sp.id }};
                const pkg = try rt.addPackage(.{ .version_id = sp.id, .original_id = sp.id, .version = 1, .linkage = &link, .type_origins = &.{}, .modules = mods });
                if (pkg.refused != null) return error.Refused;
                l = .{ .snap = snap.version, .rt = rt, .pkg = pkg, .module = pkg.module("vector").?, .digest = digest };
            }
            try loaded.append(a, l.?);
        }
        const x = l.?;
        const rev = x.module.functionByName("reverse") orelse continue;
        if (rev.is_native) continue;
        const seen = for (ws.list.items) |w| {
            if (w.gm == gm and std.mem.eql(u8, &w.digest, &x.digest)) break true;
        } else false;
        if (!seen) try ws.list.append(a, .{ .rt = x.rt, .pkg = x.pkg, .module = x.module, .digest = x.digest, .pv = pv, .gm = gm, .ecfg = ecfg, .struct_ty = try stringType(x.pkg) });
    }
    for (ws.list.items, 0..) |*w, i| {
        w.primary = for (ws.list.items[i + 1 ..]) |*o| {
            if (std.mem.eql(u8, &o.digest, &w.digest)) break false;
        } else true;
    }
    return ws;
}

/// `bytes` with every occurrence of each `from` address replaced by its `to`. The first pair is
/// the module's own address and must occur.
fn readdress(a: Allocator, bytes: []const u8, pairs: []const [2]loader.Address) ![]const u8 {
    const out = try a.dupe(u8, bytes);
    for (pairs, 0..) |p, pi| {
        var n: usize = 0;
        var i: usize = 0;
        while (i + 32 <= out.len) {
            if (std.mem.eql(u8, out[i..][0..32], &p[0])) {
                @memcpy(out[i..][0..32], &p[1]);
                n += 1;
                i += 32;
            } else i += 1;
        }
        if (pi == 0 and n == 0) return error.AddressNotInModule;
    }
    return out;
}

fn addrOf(comptime last: u8) loader.Address {
    var a: loader.Address = @splat(0);
    a[31] = last;
    return a;
}

/// The Wormhole and Pyth modules as published on mainnet, over the protocol 141 framework: one
/// world per gas model version for `bytes::take_bytes`, and for the Pyth hashes the gas models
/// since Pyth's version 2 package.
pub fn fixtureWorlds(gpa: Allocator) !Worlds {
    var ws: Worlds = .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa) };
    errdefer ws.deinit();
    const a = ws.arena.allocator();
    const bcfg: move_format.BinaryConfig = .{};
    const rt = try rt_gpa.create(loader.Runtime);
    rt.* = loader.Runtime.init(rt_gpa, bcfg);
    try ws.rts.append(a, rt);
    loopaccel.enable();
    defer loopaccel.disable();
    const one = addrOf(1);
    const two = addrOf(2);
    const wh = loopaccel.wormhole_addr;
    const pyth = loopaccel.pyth_addr;
    const vers = try natives.framework.load(a);
    const snap = natives.framework.snapshot(vers, 141) orelse return error.NoSnapshot;
    for (snap.packages) |*p| {
        if (!std.mem.eql(u8, &p.id, &one) and !std.mem.eql(u8, &p.id, &two)) continue;
        const mods = try a.alloc(loader.NamedModule, p.modules.len);
        for (p.modules, mods) |b, *m| {
            const cm = switch (try move_format.deserialize(a, b, &bcfg)) {
                .ok => |cm| cm,
                else => return error.BadModule,
            };
            m.* = .{ .name = cm.selfName(), .bytes = b };
        }
        const link = try a.alloc([2]loader.Address, p.deps.len + 1);
        link[0] = .{ p.id, p.id };
        for (p.deps, link[1..]) |d, *l| l.* = .{ d, d };
        const pkg = try rt.addPackage(.{ .version_id = p.id, .original_id = p.id, .version = 1, .linkage = link, .type_origins = &.{}, .modules = mods });
        if (pkg.refused != null) return error.Refused;
    }
    const wh_mods = [_]loader.NamedModule{
        .{ .name = "bytes", .bytes = @embedFile("loopaccel_fixtures/wormhole_bytes.mv") },
        .{ .name = "bytes20", .bytes = @embedFile("loopaccel_fixtures/wormhole_bytes20.mv") },
        .{ .name = "cursor", .bytes = @embedFile("loopaccel_fixtures/wormhole_cursor.mv") },
    };
    const wh_link = [_][2]loader.Address{ .{ wh, wh }, .{ one, one }, .{ two, two } };
    const wh_pkg = try rt.addPackage(.{ .version_id = wh, .original_id = wh, .version = 1, .linkage = &wh_link, .type_origins = &.{}, .modules = &wh_mods });
    if (wh_pkg.refused != null) return error.Refused;
    const py_mods = [_]loader.NamedModule{
        .{ .name = "deserialize", .bytes = @embedFile("loopaccel_fixtures/pyth_deserialize.mv") },
        .{ .name = "i64", .bytes = @embedFile("loopaccel_fixtures/pyth_i64.mv") },
        .{ .name = "merkle_tree", .bytes = @embedFile("loopaccel_fixtures/pyth_merkle_tree.mv") },
    };
    const py_link = [_][2]loader.Address{ .{ pyth, pyth }, .{ one, one }, .{ two, two }, .{ wh, wh } };
    const py_pkg = try rt.addPackage(.{ .version_id = pyth, .original_id = pyth, .version = 2, .linkage = &py_link, .type_origins = &.{}, .modules = &py_mods });
    if (py_pkg.refused != null) return error.Refused;
    // The second deployments: the same modules with the package addresses replaced (the only
    // bytes in which the published modules of 0x99de..25b4 and 0x5530..e2c0 differ).
    const wh2 = loopaccel.wormhole2_addr;
    const pyth2 = loopaccel.pyth2_addr;
    const wh_pairs = [_][2]loader.Address{.{ wh, wh2 }};
    const py_pairs = [_][2]loader.Address{ .{ pyth, pyth2 }, .{ wh, wh2 } };
    var wh2_mods: [wh_mods.len]loader.NamedModule = undefined;
    for (wh_mods, &wh2_mods) |m, *o| o.* = .{ .name = m.name, .bytes = try readdress(a, m.bytes, &wh_pairs) };
    const wh2_link = [_][2]loader.Address{ .{ wh2, wh2 }, .{ one, one }, .{ two, two } };
    const wh2_pkg = try rt.addPackage(.{ .version_id = wh2, .original_id = wh2, .version = 1, .linkage = &wh2_link, .type_origins = &.{}, .modules = &wh2_mods });
    if (wh2_pkg.refused != null) return error.Refused;
    var py2_mods: [py_mods.len]loader.NamedModule = undefined;
    for (py_mods, &py2_mods) |m, *o| o.* = .{ .name = m.name, .bytes = try readdress(a, m.bytes, &py_pairs) };
    const py2_link = [_][2]loader.Address{ .{ pyth2, pyth2 }, .{ one, one }, .{ two, two }, .{ wh2, wh2 } };
    const py2_pkg = try rt.addPackage(.{ .version_id = pyth2, .original_id = pyth2, .version = 1, .linkage = &py2_link, .type_origins = &.{}, .modules = &py2_mods });
    if (py2_pkg.refused != null) return error.Refused;
    {
        const cfg = try protocol.get(141, .mainnet);
        const gm = try cfg.get("gas_model_version");
        const ecfg = try interp.ExecConfig.fromProtocolAnyCut(cfg);
        const m1 = wh2_pkg.module("bytes").?;
        const m2 = py2_pkg.module("merkle_tree").?;
        try ws.list.append(a, .{ .rt = rt, .pkg = wh2_pkg, .module = m1, .digest = loopaccel.codeDigest(&m1.cm), .pv = 141, .gm = gm, .ecfg = ecfg });
        try ws.list.append(a, .{ .rt = rt, .pkg = py2_pkg, .module = m2, .digest = loopaccel.codeDigest(&m2.cm), .pv = 141, .gm = gm, .ecfg = ecfg, .natives = true });
    }
    const wh_m = wh_pkg.module("bytes").?;
    const py_m = py_pkg.module("merkle_tree").?;
    const wh_digest = loopaccel.codeDigest(&wh_m.cm);
    const py_digest = loopaccel.codeDigest(&py_m.cm);
    var last_gm: u64 = 0;
    var pv: u64 = protocol.min_protocol_version;
    while (pv <= 141) : (pv += 1) {
        const cfg = try protocol.get(pv, .mainnet);
        const gm = cfg.get("gas_model_version") catch continue;
        if (gm == last_gm) continue;
        const ecfg = interp.ExecConfig.fromProtocolAnyCut(cfg) catch continue;
        last_gm = gm;
        try ws.list.append(a, .{ .rt = rt, .pkg = wh_pkg, .module = wh_m, .digest = wh_digest, .pv = pv, .gm = gm, .ecfg = ecfg });
        if (gm >= 8) try ws.list.append(a, .{ .rt = rt, .pkg = py_pkg, .module = py_m, .digest = py_digest, .pv = pv, .gm = gm, .ecfg = ecfg, .natives = true });
    }
    for (ws.list.items, 0..) |*w, i| {
        w.primary = for (ws.list.items[i + 1 ..]) |*o| {
            if (std.mem.eql(u8, &o.digest, &w.digest)) break false;
        } else true;
    }
    return ws;
}

/// Replaces the worlds of `ws` with the full cross product: every distinct bytecode in it under
/// every gas model version from 1 to `loopaccel.MAX_GM`, where `stdWorlds` and `fixtureWorlds`
/// pair a bytecode only with the gas models it ran under on mainnet. A gas model comes with the
/// execution config of the first mainnet protocol version that has it (version 12, which no
/// protocol version has, with that of 13). No world of a cross product is primary.
pub fn crossWorlds(ws: *Worlds) !void {
    const a = ws.arena.allocator();
    const Cfg = struct { pv: u64, ecfg: interp.ExecConfig };
    var cfgs: [loopaccel.MAX_GM + 1]?Cfg = @splat(null);
    var pv: u64 = protocol.min_protocol_version;
    while (pv <= protocol.max_protocol_version) : (pv += 1) {
        const cfg = try protocol.get(pv, .mainnet);
        const gm = cfg.get("gas_model_version") catch continue;
        if (gm > loopaccel.MAX_GM or cfgs[@intCast(gm)] != null) continue;
        cfgs[@intCast(gm)] = .{ .pv = pv, .ecfg = interp.ExecConfig.fromProtocolAnyCut(cfg) catch continue };
    }
    var gm: usize = loopaccel.MAX_GM;
    if (cfgs[gm] == null) return error.NoConfigForMaxGasModel;
    while (gm > 1) : (gm -= 1) {
        if (cfgs[gm - 1] == null) cfgs[gm - 1] = cfgs[gm];
    }
    var out: std.ArrayList(World) = .empty;
    for (ws.list.items, 0..) |*w, i| {
        const first = for (ws.list.items[0..i]) |*o| {
            if (std.mem.eql(u8, &o.digest, &w.digest)) break false;
        } else true;
        if (!first) continue;
        for (1..loopaccel.MAX_GM + 1) |g| {
            var x = w.*;
            x.gm = g;
            x.pv = cfgs[g].?.pv;
            x.ecfg = cfgs[g].?.ecfg;
            x.primary = false;
            try out.append(a, x);
        }
    }
    ws.list = out;
}

// ---------------------------------------------------------------------------------------------
// Calls

/// Element types of the generic calls: the primitives (packed vectors), `vector<u8>` and a
/// struct, `0x1::string::String` (vectors of boxed values).
pub const Elem = enum { u8, u16, u32, u64, u128, u256, address, bool, vec_u8, struct_ };
pub const all_elems = [_]Elem{ .u8, .u16, .u32, .u64, .u128, .u256, .address, .bool, .vec_u8, .struct_ };

const t_vec_u8: Type = .{ .vector = &Type.t_u8 };

fn elemType(e: Elem) *const Type {
    return switch (e) {
        .u8 => &Type.t_u8,
        .u16 => &Type.t_u16,
        .u32 => &Type.t_u32,
        .u64 => &Type.t_u64,
        .u128 => &Type.t_u128,
        .u256 => &Type.t_u256,
        .address => &Type.t_address,
        .bool => &Type.t_bool,
        .vec_u8 => &t_vec_u8,
        // the struct type belongs to a world's runtime: `elemTypeIn`
        .struct_ => unreachable,
    };
}

fn elemTypeIn(w: *const World, e: Elem) *const Type {
    return if (e == .struct_) w.struct_ty.? else elemType(e);
}

/// A `vector<e>` of `n` elements, every element different from its neighbours.
fn mkVec(h: value.Heap, e: Elem, n: u32, salt: u8) !Value {
    const kind: value.Kind = if (e == .struct_) .vec else elemType(e).vecKind();
    const c = try h.newContainer(kind, n);
    if (kind.isPrimVec()) {
        const w = kind.width();
        for (c.bytes(), 0..) |*b, i| {
            const el = i / w;
            b.* = if (kind == .vec_bool) @intCast((el *% 5 +% el / 3 +% salt) % 2) else @truncate(el *% 37 +% (i % w) *% 11 +% salt +% (el >> 8));
        }
    } else {
        for (c.values(), 0..) |*v, i| {
            const inner = try h.newContainer(.vec_u8, (i + salt) % 4);
            for (inner.bytes(), 0..) |*b, j| b.* = @truncate(i *% 13 +% j +% salt);
            // String { bytes }
            v.* = if (e == .struct_) try h.pack(.struct_, 0, &.{Value.container(inner)}) else Value.container(inner);
        }
    }
    return Value.container(c);
}

pub const Call = union(enum) {
    /// `vector::reverse<e>(&mut v)`, v of n elements.
    reverse: struct { e: Elem, n: u32 },
    /// `vector::append<e>(&mut lhs, other)`, lhs of n and other of m elements.
    append: struct { e: Elem, n: u32, m: u32 },
    /// `vector::remove<e>(&mut v, i)`, v of n elements.
    remove: struct { e: Elem, n: u32, i: u64 },
    /// A function of the world's module with a type argument given directly (type limits).
    reverse_ty: struct { ty: *const Type, n: u32 },
    /// Wormhole `bytes::take_bytes(&mut Cursor<u8>, n)`, the cursor over `len` bytes.
    take_bytes: struct { len: u32, n: u64 },
    /// Wormhole `bytes::take_u16_be` / `take_u32_be` / `take_u64_be(&mut Cursor<u8>)`.
    take_be: struct { bits: u8, len: u32 },
    /// Pyth `merkle_tree::hash(&vector<u8>)` and `leaf_hash(&vector<u8>)` of `n` bytes.
    pyth_hash: struct { n: u32 },
    pyth_leaf: struct { n: u32 },
    /// Pyth `merkle_tree::node_hash(Bytes20, Bytes20)`, the two children filled from the salts.
    pyth_node: struct { a: u8, b: u8 },

    pub fn name(c: Call) []const u8 {
        return switch (c) {
            .reverse, .reverse_ty => "reverse",
            .append => "append",
            .remove => "remove",
            .take_bytes => "take_bytes",
            .take_be => |b| switch (b.bits) {
                16 => "take_u16_be",
                32 => "take_u32_be",
                else => "take_u64_be",
            },
            .pyth_hash => "hash",
            .pyth_leaf => "leaf_hash",
            .pyth_node => "node_hash",
        };
    }
};

const Built = struct { func: *const loader.Function, ty_args: []const *const Type, args: []const Value };

fn build(w: *const World, h: value.Heap, a: Allocator, call: Call, slots: *[2]?*Value) !Built {
    const func = w.module.functionByName(call.name()) orelse return error.NoSuchFunction;
    const tys = try a.alloc(*const Type, 1);
    switch (call) {
        .take_bytes => |c| {
            // Cursor<u8> { data: vector<u8> }
            const slot = try a.create(Value);
            slot.* = try h.pack(.struct_, 0, &.{try mkVec(h, .u8, c.len, 7)});
            slots[0] = slot;
            const args = try a.alloc(Value, 2);
            args[0] = Value.refSlot(slot);
            args[1] = Value.u64_(c.n);
            return .{ .func = func, .ty_args = &.{}, .args = args };
        },
        .take_be => |c| {
            const slot = try a.create(Value);
            slot.* = try h.pack(.struct_, 0, &.{try mkVec(h, .u8, c.len, 0xc3)});
            slots[0] = slot;
            const args = try a.alloc(Value, 1);
            args[0] = Value.refSlot(slot);
            return .{ .func = func, .ty_args = &.{}, .args = args };
        },
        .pyth_hash, .pyth_leaf => {
            const n = switch (call) {
                .pyth_hash => |c| c.n,
                .pyth_leaf => |c| c.n,
                else => unreachable,
            };
            const slot = try a.create(Value);
            slot.* = try mkVec(h, .u8, n, 3);
            slots[0] = slot;
            const args = try a.alloc(Value, 1);
            args[0] = Value.refSlot(slot);
            return .{ .func = func, .ty_args = &.{}, .args = args };
        },
        .pyth_node => |c| {
            // Bytes20 { data: vector<u8> }, twice
            const args = try a.alloc(Value, 2);
            args[0] = try h.pack(.struct_, 0, &.{try mkVec(h, .u8, 20, c.a)});
            args[1] = try h.pack(.struct_, 0, &.{try mkVec(h, .u8, 20, c.b)});
            return .{ .func = func, .ty_args = &.{}, .args = args };
        },
        .reverse => |c| {
            tys[0] = elemTypeIn(w, c.e);
            const slot = try a.create(Value);
            slot.* = try mkVec(h, c.e, c.n, 1);
            slots[0] = slot;
            const args = try a.alloc(Value, 1);
            args[0] = Value.refSlot(slot);
            return .{ .func = func, .ty_args = tys, .args = args };
        },
        .reverse_ty => |c| {
            tys[0] = c.ty;
            const slot = try a.create(Value);
            const v = try h.newContainer(.vec, c.n);
            for (v.values()) |*x| x.* = Value.container(try h.newContainer(.vec, 0));
            slot.* = Value.container(v);
            slots[0] = slot;
            const args = try a.alloc(Value, 1);
            args[0] = Value.refSlot(slot);
            return .{ .func = func, .ty_args = tys, .args = args };
        },
        .append => |c| {
            tys[0] = elemTypeIn(w, c.e);
            const slot = try a.create(Value);
            slot.* = try mkVec(h, c.e, c.n, 1);
            slots[0] = slot;
            const args = try a.alloc(Value, 2);
            args[0] = Value.refSlot(slot);
            args[1] = try mkVec(h, c.e, c.m, 101);
            return .{ .func = func, .ty_args = tys, .args = args };
        },
        .remove => |c| {
            tys[0] = elemTypeIn(w, c.e);
            const slot = try a.create(Value);
            slot.* = try mkVec(h, c.e, c.n, 1);
            slots[0] = slot;
            const args = try a.alloc(Value, 2);
            args[0] = Value.refSlot(slot);
            args[1] = Value.u64_(c.i);
            return .{ .func = func, .ty_args = tys, .args = args };
        },
    }
}

/// The meter a run starts with.
pub const MeterSetup = struct {
    /// Internal gas units left.
    gas: u64 = BIG,
    /// Counters to start from (null: zero), with the tier state the meter has there. `lazy`:
    /// the tier state of one unit earlier, which is what the meter holds when a counter reaches
    /// a tier start exactly.
    instr: ?u64 = null,
    size: ?u64 = null,
    height: ?u64 = null,
    lazy: bool = false,
    /// Overrides `max_move_vector_len`.
    vec_max: ?u64 = null,
    /// `GasStatus::new_unmetered()` (system transactions) instead of everything above.
    unmetered: bool = false,

    fn apply(ms: MeterSetup, m: *gas.Meter) void {
        m.gas_left = ms.gas;
        m.initial_budget = ms.gas;
        const back: u64 = @intFromBool(ms.lazy);
        if (ms.instr) |x| {
            m.instructions_executed = x;
            const t = m.table.instructionTier(x -| back);
            m.instructions_current_tier_mult = t[0];
            m.instructions_next_tier_start = t[1];
        }
        if (ms.size) |x| {
            m.stack_size_current = x;
            m.stack_size_high_water_mark = x;
            const t = m.table.stackSizeTier(x -| back);
            m.stack_size_current_tier_mult = t[0];
            m.stack_size_next_tier_start = t[1];
        }
        if (ms.height) |x| {
            m.stack_height_current = x;
            m.stack_height_high_water_mark = x;
            const t = m.table.stackHeightTier(x -| back);
            m.stack_height_current_tier_mult = t[0];
            m.stack_height_next_tier_start = t[1];
        }
    }
};

/// Everything observable after a run.
pub const Out = struct {
    ok: bool,
    err: interp.VmError = .{ .major = .EXECUTED },
    meter: gas.Meter,
    /// The returned values (ok) and the values behind the `&mut` arguments, serialized.
    bytes: []const u8,

    fn same(x: *const Out, y: *const Out) bool {
        if (x.ok != y.ok) return false;
        if (!std.meta.eql(x.err, y.err)) return false;
        if (!std.meta.eql(x.meter, y.meter)) return false;
        return std.mem.eql(u8, x.bytes, y.bytes);
    }
};

fn dumpValue(out: *std.ArrayList(u8), a: Allocator, v: Value) Allocator.Error!void {
    try out.append(a, @intFromEnum(v.tag));
    switch (v.tag) {
        .invalid => {},
        .u8, .u16, .u32, .u64, .bool, .u128 => {
            try out.appendSlice(a, std.mem.asBytes(&v.a));
            try out.appendSlice(a, std.mem.asBytes(&v.b));
        },
        .u256, .address => try out.appendSlice(a, v.box()),
        .container => try dumpContainer(out, a, v.cont()),
        .ref_slot => try dumpValue(out, a, v.slot().*),
        .ref_elem => {
            try dumpContainer(out, a, v.cont());
            try out.appendSlice(a, std.mem.asBytes(&v.b));
        },
    }
}

fn dumpContainer(out: *std.ArrayList(u8), a: Allocator, c: *const value.Container) Allocator.Error!void {
    try out.append(a, @intFromEnum(c.kind));
    try out.appendSlice(a, std.mem.asBytes(&c.tag));
    try out.appendSlice(a, std.mem.asBytes(&c.len));
    if (c.kind.isPrimVec()) {
        try out.appendSlice(a, c.bytes());
    } else for (c.values()) |f| try dumpValue(out, a, f);
}

/// One run of `call` in `w` from the meter state `ms`, with the accelerators on or off.
/// Everything is allocated in `a`.
pub fn runOnce(w: *const World, a: Allocator, call: Call, ms: MeterSetup, accel: bool) !Out {
    var slots: [2]?*Value = .{ null, null };
    const b = try build(w, .{ .arena = a }, a, call, &slots);
    var meter = if (ms.unmetered) gas.Meter.unmetered() else gas.Meter.init(w.gm, 0, 1);
    if (!ms.unmetered) ms.apply(&meter);
    var lc = interp.LinkCtx.init(w.rt, w.pkg);
    defer lc.deinit();
    var ecfg = w.ecfg;
    if (ms.vec_max) |m| ecfg.vector_len_max = m;
    var sess = try interp.Session.init(a, &lc, &meter, ecfg);
    if (w.natives) {
        const h = try a.create(host.Host);
        h.* = .{ .cfg = try protocol.get(w.pv, .mainnet), .tx = conformance.DEFAULT_TX };
        const table = try a.create(interp.NativeTable);
        table.* = h.table();
        sess.natives = table;
        sess.ext = h;
    }
    if (accel) loopaccel.enable() else loopaccel.disable();
    defer loopaccel.disable();
    const res = try sess.run(b.func, b.ty_args, b.args);
    var bytes: std.ArrayList(u8) = .empty;
    var out: Out = .{ .ok = res == .ok, .meter = meter, .bytes = &.{} };
    switch (res) {
        .ok => |vals| for (vals) |v| try dumpValue(&bytes, a, v),
        .err => |e| out.err = e,
    }
    for (slots) |s| if (s) |sl| try dumpValue(&bytes, a, sl.*);
    out.bytes = bytes.items;
    return out;
}

/// Runs both paths and fails on any difference. Returns the interpreter's result (valid until
/// the next `check`).
pub const Checker = struct {
    a: std.heap.ArenaAllocator,
    b: std.heap.ArenaAllocator,
    runs: u64 = 0,
    /// Instructions the last accelerated run did not interpret.
    last_skipped: u64 = 0,

    pub fn init(gpa: Allocator) Checker {
        return .{ .a = std.heap.ArenaAllocator.init(gpa), .b = std.heap.ArenaAllocator.init(gpa) };
    }
    pub fn deinit(c: *Checker) void {
        c.a.deinit();
        c.b.deinit();
    }

    pub fn check(c: *Checker, w: *const World, call: Call, ms: MeterSetup) !Out {
        _ = c.a.reset(.retain_capacity);
        _ = c.b.reset(.retain_capacity);
        const ref = try runOnce(w, c.a.allocator(), call, ms, false);
        const before = loopaccel.stats.instrs;
        const acc = try runOnce(w, c.b.allocator(), call, ms, true);
        c.last_skipped = loopaccel.stats.instrs - before;
        c.runs += 1;
        if (!ref.same(&acc)) {
            std.debug.print("\nloopaccel differs from the interpreter: pv {d} gm {d} digest {x}\n  call {any}\n  meter setup {any}\n  interpreter: ok={} err={any}\n    meter {any}\n  accelerated: ok={} err={any}\n    meter {any}\n  values equal: {}\n", .{
                w.pv,       w.gm,      w.digest[0..4].*, call,     ms,
                ref.ok,     ref.err,   ref.meter,        acc.ok,   acc.err,
                acc.meter,  std.mem.eql(u8, ref.bytes, acc.bytes),
            });
            return error.LoopAccelDiffers;
        }
        return ref;
    }

    /// Every gas budget from 0 up to one more than the whole call costs, `step` internal units
    /// apart (1: every unit), from the counters in `ms`.
    pub fn sweep(c: *Checker, w: *const World, call: Call, ms: MeterSetup, step: u64) !void {
        var full = ms;
        full.gas = BIG;
        const r = try c.check(w, call, full);
        if (r.err.major == .OUT_OF_GAS) return error.CallNeverFinishes;
        const total = BIG - r.meter.gas_left;
        var g: u64 = 0;
        while (g <= total + 1) : (g += step) {
            var m = ms;
            m.gas = g;
            _ = try c.check(w, call, m);
        }
    }

    /// `sweep` with about `samples` budgets spread over the whole call.
    pub fn sweepSampled(c: *Checker, w: *const World, call: Call, ms: MeterSetup, samples: u64) !void {
        var full = ms;
        full.gas = BIG;
        const r = try c.check(w, call, full);
        const total = BIG - r.meter.gas_left;
        // an odd step, so the budgets do not line up with the loop's period
        return c.sweep(w, call, ms, (total / samples) | 1);
    }
};

fn fullSweep() bool {
    const v = std.c.getenv("ZUI_LOOPACCEL_SWEEP") orelse return false;
    return std.mem.eql(u8, std.mem.span(v), "full");
}

/// The elements a world's widest sweeps use: every kind on the primary world of a bytecode,
/// a packed and a boxed one on the others.
fn elemsOf(w: *const World, full: bool) []const Elem {
    if (w.primary or full) return &all_elems;
    return &.{ .u8, .vec_u8 };
}

// ---------------------------------------------------------------------------------------------

/// The accelerators applied iterations since `before` if (and only if) the world's bytecode has
/// a template for `name`.
fn expectEngaged(w: *const World, name: []const u8, before: u64) !void {
    const engaged = loopaccel.stats.iters > before;
    if (engaged != w.templated(name)) {
        std.debug.print("\nloopaccel: pv {d} gm {d} digest {x} function {s}: engaged={} but templated={}\n", .{ w.pv, w.gm, w.digest[0..4].*, name, engaged, w.templated(name) });
        return error.LoopAccelNotEngaged;
    }
}

test "stdlib vector loops: accelerated equals interpreted at every gas budget" {
    const gpa = std.testing.allocator;
    var ws = try stdWorlds(gpa);
    defer ws.deinit();
    var c = Checker.init(gpa);
    defer c.deinit();
    try std.testing.expect(ws.list.items.len >= 8);
    const full = fullSweep();
    const sizes_other: []const u32 = if (full) &.{ 0, 1, 2, 3, 4, 5, 8, 9, 17 } else &.{ 0, 1, 2, 5 };
    for (ws.list.items) |*w| {
        // every world (every bytecode under every gas model it ran with): empty, 1, 2, odd and
        // even sizes; the newest gas model of each bytecode also 64 and 65
        const sizes_u8: []const u32 = if (full) &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 65 } else if (w.primary) &.{ 0, 1, 2, 3, 4, 5, 8, 9, 64, 65 } else &.{ 0, 1, 2, 3, 4, 5, 8, 9 };
        var it0 = loopaccel.stats.iters;
        for (elemsOf(w, full)) |e| {
            const sizes = if (e == .u8) sizes_u8 else sizes_other;
            for (sizes) |n| try c.sweep(w, .{ .reverse = .{ .e = e, .n = n } }, .{}, 1);
        }
        try expectEngaged(w, "reverse", it0);
        it0 = loopaccel.stats.iters;
        for (elemsOf(w, full)) |e| {
            const sizes = if (e == .u8) sizes_u8 else sizes_other;
            for (sizes) |n| {
                // every index for small vectors, the ends and the middle otherwise, and one
                // out of range (the abort path)
                var i: u64 = 0;
                while (i <= n) : (i += 1) {
                    if (n > 3 and !full and !(i == 0 or i == n / 2 or i + 1 >= n)) continue;
                    try c.sweep(w, .{ .remove = .{ .e = e, .n = n, .i = i } }, .{}, 1);
                }
            }
        }
        try expectEngaged(w, "remove", it0);
        it0 = loopaccel.stats.iters;
        for (elemsOf(w, full)) |e| {
            const pairs: []const [2]u32 = if (e == .u8) &.{ .{ 0, 0 }, .{ 0, 1 }, .{ 1, 0 }, .{ 0, 2 }, .{ 2, 3 }, .{ 5, 4 }, .{ 3, 9 } } else &.{ .{ 0, 0 }, .{ 1, 1 }, .{ 2, 5 } };
            for (pairs) |p| try c.sweep(w, .{ .append = .{ .e = e, .n = p[0], .m = p[1] } }, .{}, 1);
            if (e == .u8 and (w.primary or full)) try c.sweep(w, .{ .append = .{ .e = e, .n = 3, .m = 64 } }, .{}, 1);
        }
        try expectEngaged(w, "append", it0);
    }
    try std.testing.expect(c.runs > 10_000);
}

test "stdlib vector loops: large vectors across the instruction, stack size and stack height tiers" {
    const gpa = std.testing.allocator;
    var ws = try stdWorlds(gpa);
    defer ws.deinit();
    var c = Checker.init(gpa);
    defer c.deinit();
    const samples: u64 = if (fullSweep()) 400 else 16;
    for (ws.list.items) |*w| {
        const m = gas.Meter.init(w.gm, 0, 1);
        // big enough to cross the first instruction tier of the world's cost table inside the loop
        const first = m.instructions_next_tier_start orelse 20_000;
        const n: u32 = @intCast(@min(first / 8 + 64, 4000));
        try c.sweepSampled(w, .{ .reverse = .{ .e = .u8, .n = n } }, .{}, samples);
        try c.sweepSampled(w, .{ .reverse = .{ .e = .u64, .n = n / 2 + 1 } }, .{}, samples / 2);
        try c.sweepSampled(w, .{ .remove = .{ .e = .u8, .n = n / 2, .i = 1 } }, .{}, samples);
        try c.sweepSampled(w, .{ .append = .{ .e = .u8, .n = 3, .m = n / 2 } }, .{}, samples);
        try c.sweepSampled(w, .{ .append = .{ .e = .vec_u8, .n = 3, .m = n / 4 } }, .{}, samples / 2);
        // with gas for the whole call most instructions are skipped (every tier start passed inside
        // the loop costs one interpreted iteration)
        const calls = [_]Call{ .{ .reverse = .{ .e = .u8, .n = n } }, .{ .remove = .{ .e = .u8, .n = n / 2, .i = 1 } }, .{ .append = .{ .e = .u8, .n = 3, .m = n / 2 } } };
        for (calls) |call| {
            const r = try c.check(w, call, .{});
            if (w.templated(call.name())) try std.testing.expect(c.last_skipped * 10 >= r.meter.instructions_executed * 8);
        }
    }
}

/// Each call with a counter starting a little below, at and a little above every tier start of
/// the world's cost table (both tier states the meter can hold at a start), alone and with a
/// gas sweep.
fn tierChecks(c: *Checker, w: *const World, calls: []const Call, full: bool) !void {
    const m = gas.Meter.init(w.gm, 0, 1);
    for (calls) |call| {
        // the gas sweeps only where a run is cheap or the world is the bytecode's primary one
        const gas_step: u64 = if (full) 17 else if (w.natives and !w.primary) BIG else 221;
        for (m.table.instruction_tiers) |t| {
            if (t.start == 0) continue;
            var d: u64 = 0;
            while (d <= 60) : (d += if (full or d < 40) 1 else 5) {
                for ([_]bool{ false, true }) |lazy| {
                    _ = try c.check(w, call, .{ .instr = t.start + 2 - d, .lazy = lazy });
                    if (d % 7 == 0) try c.sweep(w, call, .{ .instr = t.start + 2 - d, .lazy = lazy }, gas_step);
                }
            }
        }
        for (m.table.stack_size_tiers) |t| {
            if (t.start == 0) continue;
            var d: u64 = 0;
            while (d <= 400) : (d += if (full or d < 130) 1 else 9) {
                for ([_]bool{ false, true }) |lazy| {
                    _ = try c.check(w, call, .{ .size = t.start + 2 - d, .lazy = lazy });
                    if (d % 31 == 0) try c.sweep(w, call, .{ .size = t.start + 2 - d, .lazy = lazy }, gas_step);
                }
            }
        }
        for (m.table.stack_height_tiers) |t| {
            if (t.start == 0) continue;
            var d: u64 = 0;
            while (d <= 12) : (d += 1) {
                for ([_]bool{ false, true }) |lazy| {
                    _ = try c.check(w, call, .{ .height = t.start + 2 - d, .lazy = lazy });
                    if (d % 3 == 0) try c.sweep(w, call, .{ .height = t.start + 2 - d, .lazy = lazy }, gas_step);
                }
            }
        }
        // all three at once
        _ = try c.check(w, call, .{ .instr = m.table.instruction_tiers[m.table.instruction_tiers.len - 1].start - 20, .size = m.table.stack_size_tiers[m.table.stack_size_tiers.len - 1].start - 30, .height = m.table.stack_height_tiers[m.table.stack_height_tiers.len - 1].start - 3 });
    }
}

test "stdlib vector loops: counters placed around every tier start" {
    const gpa = std.testing.allocator;
    var ws = try stdWorlds(gpa);
    defer ws.deinit();
    var c = Checker.init(gpa);
    defer c.deinit();
    for (ws.list.items) |*w| {
        try tierChecks(&c, w, &.{
            .{ .reverse = .{ .e = .u8, .n = 9 } },
            .{ .reverse = .{ .e = .vec_u8, .n = 6 } },
            .{ .remove = .{ .e = .u16, .n = 7, .i = 1 } },
            .{ .append = .{ .e = .u8, .n = 2, .m = 5 } },
            .{ .append = .{ .e = .u256, .n = 1, .m = 4 } },
        }, fullSweep());
    }
}

test "stdlib vector loops: large vectors at every gas budget" {
    // the newest gas model of each bytecode: 100 iterations of each loop, out of gas on every
    // instruction of every one of them
    const gpa = std.testing.allocator;
    var ws = try stdWorlds(gpa);
    defer ws.deinit();
    var c = Checker.init(gpa);
    defer c.deinit();
    var n_worlds: usize = 0;
    for (ws.list.items) |*w| {
        if (!w.primary) continue;
        n_worlds += 1;
        try c.sweep(w, .{ .reverse = .{ .e = .u8, .n = 201 } }, .{}, 1);
        try c.sweep(w, .{ .remove = .{ .e = .u8, .n = 101, .i = 0 } }, .{}, 1);
        try c.sweep(w, .{ .append = .{ .e = .u8, .n = 3, .m = 100 } }, .{}, 1);
    }
    try std.testing.expect(n_worlds >= 5);
    // the exhaustive sweep: every length up to 64, then 100, 150, 200 and 300, on the same worlds
    if (fullSweep()) for (ws.list.items) |*w| {
        if (!w.primary) continue;
        var n: u32 = 0;
        while (n <= 300) : (n += if (n < 64) 1 else if (n < 100) 36 else if (n < 200) 50 else 100) {
            try c.sweep(w, .{ .reverse = .{ .e = .u8, .n = n } }, .{}, 1);
            try c.sweep(w, .{ .remove = .{ .e = .u8, .n = n, .i = n / 3 } }, .{}, 1);
            try c.sweep(w, .{ .append = .{ .e = .u8, .n = 3, .m = n } }, .{}, 1);
        }
    };
}

test "stdlib vector loops: random calls from random meter states" {
    const gpa = std.testing.allocator;
    var ws = try stdWorlds(gpa);
    defer ws.deinit();
    var c = Checker.init(gpa);
    defer c.deinit();
    var prng = std.Random.DefaultPrng.init(0x100b_acce1);
    const rnd = prng.random();
    const rounds: usize = if (fullSweep()) 200_000 else 12_000;
    for (0..rounds) |_| {
        const w = &ws.list.items[rnd.uintLessThan(usize, ws.list.items.len)];
        const e = all_elems[rnd.uintLessThan(usize, all_elems.len)];
        const n = rnd.uintLessThan(u32, 40);
        const call: Call = switch (rnd.uintLessThan(u8, 3)) {
            0 => .{ .reverse = .{ .e = e, .n = n } },
            1 => .{ .append = .{ .e = e, .n = rnd.uintLessThan(u32, 12), .m = n } },
            else => .{ .remove = .{ .e = e, .n = n, .i = rnd.uintLessThan(u64, @as(u64, n) + 3) } },
        };
        const m = gas.Meter.init(w.gm, 0, 1);
        var ms: MeterSetup = .{ .lazy = rnd.boolean() };
        if (rnd.boolean()) ms.gas = rnd.uintLessThan(u64, 6000);
        if (rnd.uintLessThan(u8, 3) == 0) {
            const t = m.table.instruction_tiers[rnd.uintLessThan(usize, m.table.instruction_tiers.len)];
            ms.instr = (t.start + 5) -| rnd.uintLessThan(u64, 700);
        }
        if (rnd.uintLessThan(u8, 3) == 0) {
            const t = m.table.stack_size_tiers[rnd.uintLessThan(usize, m.table.stack_size_tiers.len)];
            ms.size = (t.start + 5) -| rnd.uintLessThan(u64, 3000);
        }
        if (rnd.uintLessThan(u8, 3) == 0) {
            const t = m.table.stack_height_tiers[rnd.uintLessThan(usize, m.table.stack_height_tiers.len)];
            ms.height = (t.start + 3) -| rnd.uintLessThan(u64, 12);
        }
        if (rnd.uintLessThan(u8, 6) == 0) ms.vec_max = rnd.uintLessThan(u64, 48);
        _ = try c.check(w, call, ms);
    }
}

test "stdlib vector loops: the vector length limit and oversized type arguments" {
    const gpa = std.testing.allocator;
    var ws = try stdWorlds(gpa);
    defer ws.deinit();
    var c = Checker.init(gpa);
    defer c.deinit();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // vector<vector<..<u8>..>> with 20, 70 and 130 type nodes as the element type
    var deep: [3]*const Type = undefined;
    for ([_]usize{ 20, 70, 130 }, &deep) |nodes, *d| {
        var t: *const Type = &Type.t_u8;
        for (1..nodes) |_| {
            const v = try a.create(Type);
            v.* = .{ .vector = t };
            t = v;
        }
        d.* = t;
    }
    for (ws.list.items) |*w| {
        // append stops at max_move_vector_len: the push that would pass it fails
        for ([_]u64{ 0, 1, 4, 5, 6, 7, 8, 9 }) |max| {
            try c.sweep(w, .{ .append = .{ .e = .u8, .n = 4, .m = 5 } }, .{ .vec_max = max }, 3);
            try c.sweep(w, .{ .append = .{ .e = .vec_u8, .n = 2, .m = 6 } }, .{ .vec_max = max }, 5);
        }
        for (deep) |t| for ([_]u32{ 0, 2, 5 }) |n| {
            try c.sweep(w, .{ .reverse_ty = .{ .ty = t, .n = n } }, .{}, 7);
        };
        // an unmetered session (system transactions) is left to the interpreter
        const it0 = loopaccel.stats.iters;
        _ = try c.check(w, .{ .reverse = .{ .e = .u8, .n = 40 } }, .{ .unmetered = true });
        _ = try c.check(w, .{ .append = .{ .e = .u64, .n = 3, .m = 20 } }, .{ .unmetered = true });
        _ = try c.check(w, .{ .remove = .{ .e = .vec_u8, .n = 9, .i = 2 } }, .{ .unmetered = true });
        try std.testing.expectEqual(it0, loopaccel.stats.iters);
    }
}

// ---------------------------------------------------------------------------------------------
// Wormhole and Pyth

test "wormhole take_bytes: accelerated equals interpreted at every gas budget, around the tiers, on long reads" {
    const gpa = std.testing.allocator;
    var ws = try fixtureWorlds(gpa);
    defer ws.deinit();
    var c = Checker.init(gpa);
    defer c.deinit();
    const full = fullSweep();
    var n_worlds: usize = 0;
    for (ws.list.items) |*w| {
        if (w.natives) continue;
        n_worlds += 1;
        const it0 = loopaccel.stats.iters;
        // every world takes the same reads; the newest gas model also longer ones (64 bytes, and
        // 150 iterations with one more that aborts; 300 in the exhaustive sweep)
        const long_len: u32 = if (full) 300 else 150;
        if (w.primary or full) for ([_]u64{ long_len, long_len + 1 }) |n| try c.sweep(w, .{ .take_bytes = .{ .len = long_len, .n = n } }, .{}, 1);
        const lens: []const u32 = if (w.primary or full) &.{ 0, 1, 2, 5, 9, 33, 64 } else &.{ 0, 1, 2, 5, 9, 33 };
        for (lens) |len| {
            // none, one, half, all of the bytes, and more than there are (the pop of an empty
            // vector aborts in cursor::poke)
            for ([_]u64{ 0, 1, len / 2, len, @as(u64, len) + 1, @as(u64, len) + 7 }) |n| {
                try c.sweep(w, .{ .take_bytes = .{ .len = len, .n = n } }, .{}, 1);
            }
        }
        // the output vector stops at max_move_vector_len
        for ([_]u64{ 0, 1, 3, 4 }) |max| try c.sweep(w, .{ .take_bytes = .{ .len = 9, .n = 6 } }, .{ .vec_max = max }, 1);
        try expectEngaged(w, "take_bytes", it0);
        // the big-endian readers: fewer bytes than the integer needs (the pop aborts), exactly
        // enough, more
        for ([_]u8{ 16, 32, 64 }) |bits| {
            const it1 = loopaccel.stats.iters;
            for ([_]u32{ 0, 1, 2, 3, 4, 5, 7, 8, 9, 13 }) |len| try c.sweep(w, .{ .take_be = .{ .bits = bits, .len = len } }, .{}, 1);
            try expectEngaged(w, (Call{ .take_be = .{ .bits = bits, .len = 0 } }).name(), it1);
        }
        try tierChecks(&c, w, &.{ .{ .take_bytes = .{ .len = 12, .n = 9 } }, .{ .take_be = .{ .bits = 64, .len = 11 } }, .{ .take_be = .{ .bits = 16, .len = 3 } } }, full);
        // a read long enough to cross the instruction tiers inside the loop
        const long: Call = .{ .take_bytes = .{ .len = 3000, .n = 2900 } };
        try c.sweepSampled(w, long, .{}, if (full) 400 else 16);
        const r = try c.check(w, long, .{});
        try std.testing.expect(c.last_skipped * 10 >= r.meter.instructions_executed * 8);
    }
    try std.testing.expect(n_worlds >= 8);
}

test "pyth merkle hashes: accelerated equals interpreted at every gas budget and around the tiers" {
    const gpa = std.testing.allocator;
    var ws = try fixtureWorlds(gpa);
    defer ws.deinit();
    var c = Checker.init(gpa);
    defer c.deinit();
    const full = fullSweep();
    var n_worlds: usize = 0;
    for (ws.list.items) |*w| {
        if (!w.natives) continue;
        n_worlds += 1;
        // every internal gas unit in every world; the copies of hash and node_hash always run 20
        // times, leaf_hash once per byte of the leaf (the newest gas model also takes longer ones)
        var it0 = loopaccel.stats.iters;
        for ([_]u32{ 0, 1, 2, 5, 64 }) |n| try c.sweep(w, .{ .pyth_hash = .{ .n = n } }, .{}, 1);
        try expectEngaged(w, "hash", it0);
        it0 = loopaccel.stats.iters;
        const lens: []const u32 = if (full) &.{ 0, 1, 2, 9, 33, 64, 300 } else if (w.primary) &.{ 0, 1, 2, 9, 33, 64, 150 } else &.{ 0, 1, 2, 9, 33 };
        for (lens) |n| try c.sweep(w, .{ .pyth_leaf = .{ .n = n } }, .{}, 1);
        try expectEngaged(w, "leaf_hash", it0);
        it0 = loopaccel.stats.iters;
        // the children in both orders (node_hash sorts them) and equal
        for ([_][2]u8{ .{ 1, 2 }, .{ 2, 1 }, .{ 5, 5 } }) |p| try c.sweep(w, .{ .pyth_node = .{ .a = p[0], .b = p[1] } }, .{}, 1);
        try expectEngaged(w, "node_hash", it0);
        try tierChecks(&c, w, &.{ .{ .pyth_leaf = .{ .n = 12 } }, .{ .pyth_node = .{ .a = 1, .b = 9 } } }, full);
        // a leaf long enough to cross the instruction tiers inside the copy loop
        const long: Call = .{ .pyth_leaf = .{ .n = 2600 } };
        try c.sweepSampled(w, long, .{}, if (full) 400 else 16);
        const r = try c.check(w, long, .{});
        try std.testing.expect(c.last_skipped * 10 >= r.meter.instructions_executed * 8);
    }
    try std.testing.expect(n_worlds >= 5);
}

test "wormhole and pyth loops: random calls from random meter states" {
    const gpa = std.testing.allocator;
    var ws = try fixtureWorlds(gpa);
    defer ws.deinit();
    var c = Checker.init(gpa);
    defer c.deinit();
    var prng = std.Random.DefaultPrng.init(0x7a4e_b17e5);
    const rnd = prng.random();
    const rounds: usize = if (fullSweep()) 100_000 else 6_000;
    for (0..rounds) |_| {
        const w = &ws.list.items[rnd.uintLessThan(usize, ws.list.items.len)];
        const call: Call = if (!w.natives) (if (rnd.boolean()) Call{ .take_bytes = .{ .len = rnd.uintLessThan(u32, 60), .n = rnd.uintLessThan(u64, 70) } } else Call{ .take_be = .{ .bits = ([_]u8{ 16, 32, 64 })[rnd.uintLessThan(usize, 3)], .len = rnd.uintLessThan(u32, 12) } }) else switch (rnd.uintLessThan(u8, 3)) {
            0 => .{ .pyth_hash = .{ .n = rnd.uintLessThan(u32, 80) } },
            1 => .{ .pyth_leaf = .{ .n = rnd.uintLessThan(u32, 80) } },
            else => .{ .pyth_node = .{ .a = rnd.int(u8), .b = rnd.int(u8) } },
        };
        const m = gas.Meter.init(w.gm, 0, 1);
        var ms: MeterSetup = .{ .lazy = rnd.boolean() };
        if (rnd.boolean()) ms.gas = rnd.uintLessThan(u64, 9000);
        if (rnd.uintLessThan(u8, 3) == 0) {
            const t = m.table.instruction_tiers[rnd.uintLessThan(usize, m.table.instruction_tiers.len)];
            ms.instr = (t.start + 5) -| rnd.uintLessThan(u64, 1500);
        }
        if (rnd.uintLessThan(u8, 3) == 0) {
            const t = m.table.stack_size_tiers[rnd.uintLessThan(usize, m.table.stack_size_tiers.len)];
            ms.size = (t.start + 5) -| rnd.uintLessThan(u64, 6000);
        }
        if (rnd.uintLessThan(u8, 3) == 0) {
            const t = m.table.stack_height_tiers[rnd.uintLessThan(usize, m.table.stack_height_tiers.len)];
            ms.height = (t.start + 3) -| rnd.uintLessThan(u64, 12);
        }
        if (rnd.uintLessThan(u8, 6) == 0) ms.vec_max = rnd.uintLessThan(u64, 48);
        _ = try c.check(w, call, ms);
    }
}

// ---------------------------------------------------------------------------------------------
// The cross product

test "cross product: every bytecode under every gas model up to the maximum, with struct elements" {
    const gpa = std.testing.allocator;
    var c = Checker.init(gpa);
    defer c.deinit();
    const full = fullSweep();
    const samples: u64 = if (full) 200 else 20;
    {
        var ws = try stdWorlds(gpa);
        defer ws.deinit();
        var bytecodes: usize = 0;
        for (ws.list.items) |*w| bytecodes += @intFromBool(w.primary);
        try std.testing.expect(bytecodes >= 5);
        try crossWorlds(&ws);
        try std.testing.expectEqual(bytecodes * loopaccel.MAX_GM, ws.list.items.len);
        for (ws.list.items) |*w| {
            // a packed element, a boxed one and a struct, through each of the three loops
            var it0 = loopaccel.stats.iters;
            for ([_]Call{
                .{ .reverse = .{ .e = .u8, .n = 9 } },
                .{ .reverse = .{ .e = .u64, .n = 4 } },
                .{ .reverse = .{ .e = .vec_u8, .n = 4 } },
                .{ .reverse = .{ .e = .struct_, .n = 5 } },
            }) |call| try c.sweepSampled(w, call, .{}, samples);
            try expectEngaged(w, "reverse", it0);
            it0 = loopaccel.stats.iters;
            for ([_]Call{
                .{ .remove = .{ .e = .u8, .n = 7, .i = 1 } },
                .{ .remove = .{ .e = .u256, .n = 4, .i = 0 } },
                .{ .remove = .{ .e = .struct_, .n = 5, .i = 0 } },
                .{ .remove = .{ .e = .struct_, .n = 3, .i = 3 } },
            }) |call| try c.sweepSampled(w, call, .{}, samples);
            try expectEngaged(w, "remove", it0);
            it0 = loopaccel.stats.iters;
            for ([_]Call{
                .{ .append = .{ .e = .u8, .n = 2, .m = 5 } },
                .{ .append = .{ .e = .address, .n = 1, .m = 4 } },
                .{ .append = .{ .e = .struct_, .n = 2, .m = 3 } },
            }) |call| try c.sweepSampled(w, call, .{}, samples);
            try expectEngaged(w, "append", it0);
            // the struct elements were moved natively too
            it0 = loopaccel.stats.iters;
            _ = try c.check(w, .{ .reverse = .{ .e = .struct_, .n = 8 } }, .{});
            try std.testing.expect(loopaccel.stats.iters > it0);
            // a vector big enough to cross the first instruction tier inside the loop
            const m = gas.Meter.init(w.gm, 0, 1);
            const n: u32 = @intCast(@min((m.instructions_next_tier_start orelse 20_000) / 8 + 64, 4000));
            try c.sweepSampled(w, .{ .reverse = .{ .e = .u8, .n = n } }, .{}, 3);
            try c.sweepSampled(w, .{ .append = .{ .e = .struct_, .n = 3, .m = n / 4 } }, .{}, 3);
        }
    }
    {
        var ws = try fixtureWorlds(gpa);
        defer ws.deinit();
        try crossWorlds(&ws);
        // Wormhole `bytes` and Pyth `merkle_tree`
        try std.testing.expectEqual(2 * loopaccel.MAX_GM, ws.list.items.len);
        for (ws.list.items) |*w| {
            if (w.natives) {
                var it0 = loopaccel.stats.iters;
                try c.sweepSampled(w, .{ .pyth_hash = .{ .n = 5 } }, .{}, samples);
                try expectEngaged(w, "hash", it0);
                it0 = loopaccel.stats.iters;
                for ([_]u32{ 1, 33 }) |n| try c.sweepSampled(w, .{ .pyth_leaf = .{ .n = n } }, .{}, samples);
                try expectEngaged(w, "leaf_hash", it0);
                it0 = loopaccel.stats.iters;
                try c.sweepSampled(w, .{ .pyth_node = .{ .a = 1, .b = 9 } }, .{}, samples);
                try expectEngaged(w, "node_hash", it0);
                try c.sweepSampled(w, .{ .pyth_leaf = .{ .n = 2600 } }, .{}, 3);
            } else {
                var it0 = loopaccel.stats.iters;
                // a read that ends, and one that runs past the bytes (the pop aborts)
                for ([_][2]u32{ .{ 12, 9 }, .{ 9, 12 } }) |x| try c.sweepSampled(w, .{ .take_bytes = .{ .len = x[0], .n = x[1] } }, .{}, samples);
                try expectEngaged(w, "take_bytes", it0);
                for ([_]u8{ 16, 32, 64 }) |bits| {
                    it0 = loopaccel.stats.iters;
                    for ([_]u32{ 1, 11 }) |len| try c.sweepSampled(w, .{ .take_be = .{ .bits = bits, .len = len } }, .{}, samples);
                    try expectEngaged(w, (Call{ .take_be = .{ .bits = bits, .len = 0 } }).name(), it0);
                }
                try c.sweepSampled(w, .{ .take_bytes = .{ .len = 3000, .n = 2900 } }, .{}, 3);
            }
        }
    }
    try std.testing.expect(c.runs > 20_000);
}

// ---------------------------------------------------------------------------------------------
// The registry

test "every registered template attaches to the published bytecode and has a summary for its gas models" {
    const gpa = std.testing.allocator;
    var std_ws = try stdWorlds(gpa);
    defer std_ws.deinit();
    var fx_ws = try fixtureWorlds(gpa);
    defer fx_ws.deinit();
    loopaccel.enable(); // the summaries are built on the first enable
    loopaccel.disable();
    var templates: usize = 0;
    for (&loopaccel.registry) |*e| {
        if (e.fns.len == 0) continue;
        // a registered bytecode with no world would be an accelerator no test holds to the interpreter
        var worlds: usize = 0;
        for ([_]*const Worlds{ &std_ws, &fx_ws }) |ws| for (ws.list.items) |*w| {
            if (!std.mem.eql(u8, &w.digest, &e.digest)) continue;
            worlds += 1;
            try std.testing.expectEqualStrings(e.name, w.module.name);
            for (e.fns) |ft| {
                const f = &w.module.functions[ft.def_idx];
                try std.testing.expectEqualStrings(ft.name, f.name);
                try std.testing.expect(f.accel != null);
                for (ft.loops) |lt| {
                    // every loop is accelerated for byte vectors under every gas model it ran with
                    const sum = loopaccel.summarize(lt.shape, w.gm, .vec_u8);
                    try std.testing.expect(sum.valid);
                    try std.testing.expect(sum.n >= lt.shape.body.len);
                }
            }
        };
        try std.testing.expect(worlds > 0);
        templates += e.fns.len;
    }
    try std.testing.expect(templates >= 20);
    // nothing else in those packages got an accelerator
    for ([_]*const Worlds{ &std_ws, &fx_ws }) |ws| for (ws.list.items) |*w| {
        for (w.module.functions) |*f| {
            if (f.accel != null) try std.testing.expect(w.templated(f.name));
        }
    };
}

test "a gas model above the maximum is left to the interpreter" {
    const gpa = std.testing.allocator;
    // the maximum is the highest gas model of the protocol tables, on every chain
    var highest: u64 = 0;
    for ([_]protocol.Chain{ .mainnet, .testnet, .unknown }) |chain| {
        var pv: u64 = protocol.min_protocol_version;
        while (pv <= protocol.max_protocol_version) : (pv += 1) {
            const cfg = try protocol.get(pv, chain);
            highest = @max(highest, cfg.get("gas_model_version") catch continue);
        }
    }
    try std.testing.expectEqual(highest, loopaccel.MAX_GM);
    var std_ws = try stdWorlds(gpa);
    defer std_ws.deinit();
    var fx_ws = try fixtureWorlds(gpa);
    defer fx_ws.deinit();
    var c = Checker.init(gpa);
    defer c.deinit();
    // no loop has a summary past the maximum; every loop has one at the maximum
    for (&loopaccel.shapes) |*shape| {
        try std.testing.expect(loopaccel.summarize(shape, loopaccel.MAX_GM, .vec_u8).valid);
        for ([_]u64{ loopaccel.MAX_GM + 1, loopaccel.MAX_GM + 2, 24, 1000, std.math.maxInt(u64) }) |gm| {
            for ([_]value.Kind{ .vec_u8, .vec_u64, .vec }) |ek| try std.testing.expect(!loopaccel.summarize(shape, gm, ek).valid);
        }
    }
    // The accelerators are attached per package, whatever gas model a session will run with:
    // the same loaded functions that are accelerated at the maximum reach their loop heads
    // under a later gas model and nothing is applied there.
    var n: usize = 0;
    for ([_]*const Worlds{ &std_ws, &fx_ws }, 0..) |ws, wi| for (ws.list.items) |*w| {
        if (!w.primary) continue;
        const calls: []const Call = if (wi == 0) &.{
            .{ .reverse = .{ .e = .u8, .n = 9 } },
            .{ .remove = .{ .e = .u64, .n = 7, .i = 1 } },
            .{ .append = .{ .e = .vec_u8, .n = 2, .m = 5 } },
        } else if (w.natives) &.{
            .{ .pyth_hash = .{ .n = 5 } },
            .{ .pyth_leaf = .{ .n = 12 } },
            .{ .pyth_node = .{ .a = 1, .b = 9 } },
        } else &.{
            .{ .take_bytes = .{ .len = 12, .n = 9 } },
            .{ .take_be = .{ .bits = 16, .len = 3 } },
            .{ .take_be = .{ .bits = 32, .len = 5 } },
            .{ .take_be = .{ .bits = 64, .len = 11 } },
        };
        for (calls) |call| {
            if (!w.templated(call.name())) continue;
            n += 1;
            var at_max = w.*;
            at_max.gm = loopaccel.MAX_GM;
            _ = try c.check(&at_max, call, .{});
            try std.testing.expect(c.last_skipped > 0);
            for ([_]u64{ loopaccel.MAX_GM + 1, loopaccel.MAX_GM + 2, 24, 1000 }) |gm| {
                var later = w.*;
                later.gm = gm;
                const s0 = loopaccel.stats;
                try c.sweepSampled(&later, call, .{}, 12);
                try std.testing.expect(loopaccel.stats.heads > s0.heads);
                try std.testing.expectEqual(s0.hits, loopaccel.stats.hits);
                try std.testing.expectEqual(s0.iters, loopaccel.stats.iters);
                try std.testing.expectEqual(s0.instrs, loopaccel.stats.instrs);
            }
        }
    };
    try std.testing.expect(n >= 20);
}

test "the switch: only the exact value 1 turns the accelerators or the totals on" {
    const parse = loopaccel.parseSwitch;
    const Switch = loopaccel.Switch;
    try std.testing.expectEqual(Switch.off, parse(null));
    try std.testing.expectEqual(Switch.off, parse(""));
    try std.testing.expectEqual(Switch.off, parse("0"));
    try std.testing.expectEqual(Switch.on, parse("1"));
    // everything else is unrecognised (warned about, off): the words for on as much as the
    // words for off, and anything that only looks like 0 or 1
    for ([_][]const u8{ "on", "true", "off", "false", "ON", "True", "OFF", "yes", "no", "y", "enable", "2", "01", "10", "11", "00", "-1", "+1", "1 ", " 1", "1\n", "0 ", " ", "1.0", "0x1" }) |v| {
        try std.testing.expectEqual(Switch.unrecognised, parse(v));
    }
    const D = loopaccel.Decision;
    const decide = loopaccel.decideFrom;
    const nothing: D = .{ .accel = false, .stats = false, .warn_accel = false, .warn_stats = false };
    try std.testing.expectEqual(nothing, decide(null, null));
    try std.testing.expectEqual(nothing, decide("", ""));
    try std.testing.expectEqual(nothing, decide("0", "0"));
    try std.testing.expectEqual(D{ .accel = true, .stats = false, .warn_accel = false, .warn_stats = false }, decide("1", null));
    try std.testing.expectEqual(D{ .accel = true, .stats = false, .warn_accel = false, .warn_stats = false }, decide("1", "0"));
    try std.testing.expectEqual(D{ .accel = true, .stats = true, .warn_accel = false, .warn_stats = false }, decide("1", "1"));
    // the totals need the accelerators
    try std.testing.expectEqual(nothing, decide(null, "1"));
    try std.testing.expectEqual(nothing, decide("0", "1"));
    // an unrecognised value never turns anything on, whichever variable it is in
    for ([_][]const u8{ "on", "true", "off", "false", "2" }) |v| {
        try std.testing.expectEqual(D{ .accel = false, .stats = false, .warn_accel = true, .warn_stats = false }, decide(v, null));
        try std.testing.expectEqual(D{ .accel = false, .stats = false, .warn_accel = true, .warn_stats = false }, decide(v, "1"));
        try std.testing.expectEqual(D{ .accel = true, .stats = false, .warn_accel = false, .warn_stats = true }, decide("1", v));
        try std.testing.expectEqual(D{ .accel = false, .stats = false, .warn_accel = false, .warn_stats = true }, decide(null, v));
        try std.testing.expectEqual(D{ .accel = false, .stats = false, .warn_accel = true, .warn_stats = true }, decide(v, v));
    }
}

test "off by default: nothing attaches and no frame enters the runner" {
    const gpa = std.testing.allocator;
    loopaccel.disable();
    const bcfg: move_format.BinaryConfig = .{};
    var rt = loader.Runtime.init(gpa, bcfg);
    defer rt.deinit();
    const wh = loopaccel.wormhole_addr;
    const mods = [_]loader.NamedModule{
        .{ .name = "bytes", .bytes = @embedFile("loopaccel_fixtures/wormhole_bytes.mv") },
        .{ .name = "bytes20", .bytes = @embedFile("loopaccel_fixtures/wormhole_bytes20.mv") },
        .{ .name = "cursor", .bytes = @embedFile("loopaccel_fixtures/wormhole_cursor.mv") },
    };
    const link = [_][2]loader.Address{.{ wh, wh }};
    const pkg = try rt.addPackage(.{ .version_id = wh, .original_id = wh, .version = 1, .linkage = &link, .type_origins = &.{}, .modules = &mods });
    try std.testing.expect(pkg.refused == null);
    for (pkg.modules) |*m| for (m.functions) |*f| try std.testing.expect(f.accel == null);
}

test "a module with a registered name and address but other bytecode gets no accelerator" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // Wormhole `bytes` with one immediate changed: the bound of take_u16_be, LdU64 2, is LdU64 3
    const published: []const u8 = @embedFile("loopaccel_fixtures/wormhole_bytes.mv");
    const ld2 = [_]u8{ 0x06, 2, 0, 0, 0, 0, 0, 0, 0 };
    const at = std.mem.indexOf(u8, published, &ld2) orelse return error.NoSuchInstruction;
    try std.testing.expect(std.mem.indexOfPos(u8, published, at + 1, &ld2) == null);
    const changed = try a.dupe(u8, published);
    changed[at + 1] = 3;
    const bcfg: move_format.BinaryConfig = .{};
    var rt = loader.Runtime.init(gpa, bcfg);
    defer rt.deinit();
    loopaccel.enable();
    defer loopaccel.disable();
    const wh = loopaccel.wormhole_addr;
    const wh2 = loopaccel.wormhole2_addr;
    const miss0 = loopaccel.attach_stats.modules_digest_miss.load(.monotonic);
    const mods = [_]loader.NamedModule{
        .{ .name = "bytes", .bytes = changed },
        .{ .name = "bytes20", .bytes = @embedFile("loopaccel_fixtures/wormhole_bytes20.mv") },
        .{ .name = "cursor", .bytes = @embedFile("loopaccel_fixtures/wormhole_cursor.mv") },
    };
    const link = [_][2]loader.Address{.{ wh, wh }};
    const pkg = try rt.addPackage(.{ .version_id = wh, .original_id = wh, .version = 1, .linkage = &link, .type_origins = &.{}, .modules = &mods });
    try std.testing.expect(pkg.refused == null);
    // the module is Wormhole's by name and address, and no function of it has an accelerator
    // (not take_bytes either, whose own code is unchanged): it counts as a digest miss
    try std.testing.expect(pkg.module("bytes").?.functionByName("take_bytes") != null);
    for (pkg.modules) |*m| for (m.functions) |*f| try std.testing.expect(f.accel == null);
    try std.testing.expectEqual(miss0 + 1, loopaccel.attach_stats.modules_digest_miss.load(.monotonic));
    // the published bytes in the same runtime, under the second deployment's address, do attach
    var mods2: [mods.len]loader.NamedModule = undefined;
    const pairs = [_][2]loader.Address{.{ wh, wh2 }};
    mods2[0] = .{ .name = "bytes", .bytes = try readdress(a, published, &pairs) };
    for (mods[1..], mods2[1..]) |m, *o| o.* = .{ .name = m.name, .bytes = try readdress(a, m.bytes, &pairs) };
    const link2 = [_][2]loader.Address{.{ wh2, wh2 }};
    const pkg2 = try rt.addPackage(.{ .version_id = wh2, .original_id = wh2, .version = 1, .linkage = &link2, .type_origins = &.{}, .modules = &mods2 });
    try std.testing.expect(pkg2.refused == null);
    for ([_][]const u8{ "take_bytes", "take_u16_be", "take_u32_be", "take_u64_be" }) |name| {
        try std.testing.expect(pkg2.module("bytes").?.functionByName(name).?.accel != null);
    }
    try std.testing.expectEqual(miss0 + 1, loopaccel.attach_stats.modules_digest_miss.load(.monotonic));
}

/// How `reserialize` changes a module.
const Patch = union(enum) {
    /// Nothing: the module goes through the serializer unchanged.
    none,
    /// Every signature that is the single token `from` becomes the single token `to`. Only
    /// the signature table changes; no instruction does.
    signature: struct { from: ff.Node, to: ff.Node },
    /// The last instruction of the first function that is not `keep` becomes a Nop: the code
    /// of the module changes and the function `keep` does not (an upgrade of the module).
    code_outside: []const u8,
};

/// The module `bytes` deserialized, changed by `patch` and serialized again.
fn reserialize(a: Allocator, bytes: []const u8, patch: Patch) ![]const u8 {
    const bcfg: move_format.BinaryConfig = .{};
    var cm = switch (try move_format.deserialize(a, bytes, &bcfg)) {
        .ok => |x| x,
        else => return error.BadModule,
    };
    switch (patch) {
        .none => {},
        .signature => |p| {
            const sigs = try a.dupe([]const ff.Token, cm.signatures);
            var n: usize = 0;
            for (sigs) |*sig| {
                if (sig.len != 1 or sig.*[0].len != 1 or !sig.*[0][0].eql(p.from)) continue;
                const tok = try a.alloc(ff.Node, 1);
                tok[0] = p.to;
                const one = try a.alloc(ff.Token, 1);
                one[0] = tok;
                sig.* = one;
                n += 1;
            }
            if (n == 0) return error.NoSuchSignature;
            cm.signatures = sigs;
        },
        .code_outside => |keep| {
            const defs = try a.dupe(ff.FunctionDefinition, cm.function_defs);
            const fd = for (defs) |*d| {
                if (d.code == null) continue;
                const name = cm.identifiers[cm.function_handles[d.function].name];
                if (!std.mem.eql(u8, name, keep)) break d;
            } else return error.NoOtherFunction;
            const code = try a.dupe(ff.Instr, fd.code.?.code);
            code[code.len - 1] = .{ .op = .Nop };
            fd.code.?.code = code;
            cm.function_defs = defs;
        },
    }
    return move_format.serializeAlloc(a, &cm, cm.version);
}

fn digestOf(a: Allocator, bytes: []const u8) ![32]u8 {
    const bcfg: move_format.BinaryConfig = .{};
    return switch (try move_format.deserialize(a, bytes, &bcfg)) {
        .ok => |cm| loopaccel.codeDigest(&cm),
        else => error.BadModule,
    };
}

test "registered code whose tables or callee module differ gets no accelerator: a template mismatch" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // the mismatch is reported with a warning: keep it out of the test output
    const log_level = std.testing.log_level;
    std.testing.log_level = .err;
    defer std.testing.log_level = log_level;
    const bytes_mv: []const u8 = @embedFile("loopaccel_fixtures/wormhole_bytes.mv");
    const cursor_mv: []const u8 = @embedFile("loopaccel_fixtures/wormhole_cursor.mv");
    const u8_tok: ff.Node = .{ .tag = .U8 };
    const u64_tok: ff.Node = .{ .tag = .U64 };
    const tp0_tok: ff.Node = .{ .tag = .TypeParameter, .idx = 0 };
    const cases = [_]struct { caller: Patch, callee: Patch, attaches: bool, same_callee_code: bool = true }{
        // the control: both modules through the serializer unchanged attach, so it is the
        // change in the cases below that stops them, not the serializer
        .{ .caller = .none, .callee = .none, .attaches = true },
        // the caller, `bytes`: its `vector<u8>` signature (the element of the pushes, the type
        // argument of the call of `cursor::poke`) names another type; its code is the same
        .{ .caller = .{ .signature = .{ .from = u8_tok, .to = u64_tok } }, .callee = .none, .attaches = false },
        // the callee, `cursor`: the signature of its vector instructions is `u8` instead of
        // the type parameter; its code is the same, and `bytes` is untouched
        .{ .caller = .none, .callee = .{ .signature = .{ .from = tp0_tok, .to = u8_tok } }, .attaches = false },
        // the callee upgraded: `cursor` has other code in a function the loops never call,
        // and `bytes` is untouched (what a package upgrade that changes `cursor` alone gives)
        .{ .caller = .none, .callee = .{ .code_outside = "poke" }, .attaches = false, .same_callee_code = false },
    };
    const bytes_digest = try digestOf(a, bytes_mv);
    const cursor_digest = try digestOf(a, cursor_mv);
    const names = [_][]const u8{ "take_bytes", "take_u16_be", "take_u32_be", "take_u64_be" };
    for (cases) |cs| {
        const caller = try reserialize(a, bytes_mv, cs.caller);
        const callee = try reserialize(a, cursor_mv, cs.callee);
        // a table-only change leaves the code digest what it was: `bytes` is still the
        // registered module, and `cursor` still the one its template names
        try std.testing.expectEqualSlices(u8, &bytes_digest, &(try digestOf(a, caller)));
        try std.testing.expectEqual(cs.same_callee_code, std.mem.eql(u8, &cursor_digest, &(try digestOf(a, callee))));
        if (cs.caller != .none) try std.testing.expect(!std.mem.eql(u8, bytes_mv, caller));
        if (cs.callee != .none) try std.testing.expect(!std.mem.eql(u8, cursor_mv, callee));
        const bcfg: move_format.BinaryConfig = .{};
        var rt = loader.Runtime.init(gpa, bcfg);
        defer rt.deinit();
        loopaccel.enable();
        defer loopaccel.disable();
        const st = &loopaccel.attach_stats;
        const before = .{ st.modules_matched.load(.monotonic), st.modules_digest_miss.load(.monotonic), st.functions_attached.load(.monotonic), st.template_mismatch.load(.monotonic) };
        const g0 = readGroups();
        const wh = loopaccel.wormhole_addr;
        const mods = [_]loader.NamedModule{
            .{ .name = "bytes", .bytes = caller },
            .{ .name = "bytes20", .bytes = @embedFile("loopaccel_fixtures/wormhole_bytes20.mv") },
            .{ .name = "cursor", .bytes = callee },
        };
        const link = [_][2]loader.Address{.{ wh, wh }};
        const pkg = try rt.addPackage(.{ .version_id = wh, .original_id = wh, .version = 1, .linkage = &link, .type_origins = &.{}, .modules = &mods });
        try std.testing.expect(pkg.refused == null);
        const g1 = readGroups();
        const take_bytes = @intFromEnum(loopaccel.Group.take_bytes);
        const take_be = @intFromEnum(loopaccel.Group.take_be);
        // `bytes` is recognised by its digest either way, and it is never a digest miss
        try std.testing.expectEqual(before[0] + 1, st.modules_matched.load(.monotonic));
        try std.testing.expectEqual(before[1], st.modules_digest_miss.load(.monotonic));
        if (cs.attaches) {
            for (names) |name| try std.testing.expect(pkg.module("bytes").?.functionByName(name).?.accel != null);
            try std.testing.expectEqual(before[2] + 4, st.functions_attached.load(.monotonic));
            try std.testing.expectEqual(before[3], st.template_mismatch.load(.monotonic));
            try std.testing.expectEqual(g0[take_bytes].attached + 1, g1[take_bytes].attached);
            try std.testing.expectEqual(g0[take_be].attached + 3, g1[take_be].attached);
            try std.testing.expectEqual(g0[take_bytes].mismatches, g1[take_bytes].mismatches);
            try std.testing.expectEqual(g0[take_be].mismatches, g1[take_be].mismatches);
        } else {
            // nothing in the package is accelerated, and each of the four registered
            // functions counts as a template mismatch, in its group
            for (pkg.modules) |*m| for (m.functions) |*f| try std.testing.expect(f.accel == null);
            try std.testing.expectEqual(before[2], st.functions_attached.load(.monotonic));
            try std.testing.expectEqual(before[3] + 4, st.template_mismatch.load(.monotonic));
            try std.testing.expectEqual(g0[take_bytes].attached, g1[take_bytes].attached);
            try std.testing.expectEqual(g0[take_be].attached, g1[take_be].attached);
            try std.testing.expectEqual(g0[take_bytes].mismatches + 1, g1[take_bytes].mismatches);
            try std.testing.expectEqual(g0[take_be].mismatches + 3, g1[take_be].mismatches);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The operand stack and call depth limits: a call that starts on a used operand stack, under
// other frames (where a real call of these functions sits: inside a transaction's own code)

pub const Seed = struct {
    /// Values on the operand stack when the call starts.
    sp: usize = 0,
    /// Frames on the call stack, the call's own included.
    depth: usize = 1,
};

/// `Session.typeNodes` for the type arguments the tests pass.
fn tyNodes(t: *const Type) u64 {
    return switch (t.*) {
        .vector, .ref, .mut_ref => |e| 1 + tyNodes(e),
        .datatype => |d| blk: {
            var n: u64 = 1;
            for (d.args) |x| n += tyNodes(x);
            break :blk n;
        },
        else => 1,
    };
}

/// `runOnce` from a seeded session: `seed.sp` values under the call's arguments and
/// `seed.depth - 1` frames under its own. `Session.run` always starts from an empty stack and
/// one frame, so this drives the session itself, one `Session.stepUntraced` (the interpreter's
/// `step`) at a time, and a frame with accelerators attached through `loopaccel.run` when the
/// switch is on, which is the choice `Session.stepRun` makes. The run ends when the call's
/// frame returns. With an empty seed and the switch off it is `Session.run` (the test checks).
/// The error is the session's pending one (`Session.run` finalizes it).
pub fn runSeeded(w: *const World, a: Allocator, call: Call, ms: MeterSetup, seed: Seed, accel: bool) !Out {
    var slots: [2]?*Value = .{ null, null };
    const b = try build(w, .{ .arena = a }, a, call, &slots);
    var meter = gas.Meter.init(w.gm, 0, 1);
    ms.apply(&meter);
    var lc = interp.LinkCtx.init(w.rt, w.pkg);
    defer lc.deinit();
    var ecfg = w.ecfg;
    if (ms.vec_max) |m| ecfg.vector_len_max = m;
    var sess = try interp.Session.init(a, &lc, &meter, ecfg);
    if (w.natives) {
        const h = try a.create(host.Host);
        h.* = .{ .cfg = try protocol.get(w.pv, .mainnet), .tx = conformance.DEFAULT_TX };
        const table = try a.create(interp.NativeTable);
        table.* = h.table();
        sess.natives = table;
        sess.ext = h;
    }
    std.debug.assert(seed.depth >= 1 and seed.sp <= sess.stack.len);
    for (sess.stack[0..seed.sp], 0..) |*v, i| v.* = Value.u64_(0x5eed_0000 + i);
    sess.sp = seed.sp;
    // the frames below are never resumed: the run stops when the call's frame is gone
    for (1..seed.depth) |_| try sess.frames.append(a, .{ .func = b.func, .pc = 0, .mark = sess.lifo.mark(), .locals = &.{}, .ty_args = &.{} });
    // the call's frame, as `Session.run` makes it
    const mk = sess.lifo.mark();
    const locals = try sess.lifo.alloc(Value, b.func.n_locals);
    @memcpy(locals[0..b.args.len], b.args);
    @memset(locals[b.args.len..], Value.invalid);
    var fr: interp.Frame = .{ .func = b.func, .pc = 0, .mark = mk, .locals = locals, .ty_args = b.ty_args };
    if (b.ty_args.len != 0) {
        const nodes = try sess.lifo.alloc(u64, b.ty_args.len);
        for (b.ty_args, nodes) |t, *n| {
            n.* = tyNodes(t);
            fr.ty_nodes_sum += n.*;
        }
        fr.ty_nodes = nodes;
    }
    try sess.frames.append(a, fr);
    if (accel) loopaccel.enable() else loopaccel.disable();
    defer loopaccel.disable();
    var ok = true;
    while (true) {
        const f = &sess.frames.items[sess.frames.items.len - 1];
        const returned = (if (f.func.accel != null and loopaccel.live()) loopaccel.run(&sess, f) else sess.stepUntraced()) catch |e| switch (e) {
            error.Vm => {
                ok = false;
                break;
            },
            else => |x| return x,
        };
        if (returned or sess.frames.items.len < seed.depth) break;
    }
    var bytes: std.ArrayList(u8) = .empty;
    var out: Out = .{ .ok = ok, .meter = meter, .bytes = &.{} };
    if (ok) {
        // the seeded values (untouched) and the returned ones above them
        for (sess.stack[0..sess.sp]) |v| try dumpValue(&bytes, a, v);
    } else {
        out.err = sess.pending;
        try bytes.append(a, @intFromBool(sess.raw_err));
    }
    for (slots) |s| if (s) |sl| try dumpValue(&bytes, a, sl.*);
    out.bytes = bytes.items;
    return out;
}

/// `Checker.check` from a seeded session.
fn checkSeeded(c: *Checker, w: *const World, call: Call, ms: MeterSetup, seed: Seed) !Out {
    _ = c.a.reset(.retain_capacity);
    _ = c.b.reset(.retain_capacity);
    const ref = try runSeeded(w, c.a.allocator(), call, ms, seed, false);
    const before = loopaccel.stats.instrs;
    const acc = try runSeeded(w, c.b.allocator(), call, ms, seed, true);
    c.last_skipped = loopaccel.stats.instrs - before;
    c.runs += 1;
    if (!ref.same(&acc)) {
        std.debug.print("\nloopaccel differs from the interpreter: pv {d} gm {d} digest {x}\n  call {any}\n  seed {any}\n  meter setup {any}\n  interpreter: ok={} err={any}\n    meter {any}\n  accelerated: ok={} err={any}\n    meter {any}\n  values equal: {}\n", .{
            w.pv,      w.gm,      w.digest[0..4].*, call,     seed,     ms,
            ref.ok,    ref.err,   ref.meter,        acc.ok,   acc.err,  acc.meter,
            std.mem.eql(u8, ref.bytes, acc.bytes),
        });
        return error.LoopAccelDiffers;
    }
    return ref;
}

/// `checkSeeded` with all the gas, then at about `samples` budgets up to what the run used.
fn sweepSeeded(c: *Checker, w: *const World, call: Call, seed: Seed, samples: u64) !Out {
    const r = try checkSeeded(c, w, call, .{}, seed);
    const skipped = c.last_skipped;
    const total = BIG - r.meter.gas_left;
    const step = (total / samples) | 1;
    var g: u64 = 0;
    while (g <= total + 1) : (g += step) _ = try checkSeeded(c, w, call, .{ .gas = g }, seed);
    // (the caller reads what the run with all the gas did)
    c.last_skipped = skipped;
    return checkSeeded(c, w, call, .{}, seed);
}

test "limits: calls that start near the operand stack limit and near the call depth limit" {
    const gpa = std.testing.allocator;
    var std_ws = try stdWorlds(gpa);
    defer std_ws.deinit();
    var fx_ws = try fixtureWorlds(gpa);
    defer fx_ws.deinit();
    var c = Checker.init(gpa);
    defer c.deinit();
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const stack_max = interp.OPERAND_STACK_SIZE_LIMIT;
    const depth_max = interp.CALL_STACK_SIZE_LIMIT;
    var n_calls: usize = 0;
    var n_call_loops: usize = 0;
    for ([_]*const Worlds{ &std_ws, &fx_ws }, 0..) |ws, wi| for (ws.list.items) |*w| {
        const calls: []const Call = if (wi == 0) &.{
            .{ .reverse = .{ .e = .u8, .n = 9 } },
            .{ .reverse = .{ .e = .vec_u8, .n = 4 } },
            .{ .remove = .{ .e = .u64, .n = 7, .i = 1 } },
            .{ .append = .{ .e = .u8, .n = 2, .m = 5 } },
        } else if (w.natives) &.{
            .{ .pyth_hash = .{ .n = 5 } },
            .{ .pyth_leaf = .{ .n = 12 } },
            .{ .pyth_node = .{ .a = 1, .b = 9 } },
        } else &.{
            .{ .take_bytes = .{ .len = 12, .n = 9 } },
            .{ .take_be = .{ .bits = 64, .len = 11 } },
            .{ .take_be = .{ .bits = 16, .len = 3 } },
        };
        for (calls) |call| {
            if (!w.templated(call.name())) continue;
            n_calls += 1;
            // the driver is the interpreter: with nothing seeded and the switch off it does
            // what `Session.run` does
            {
                _ = scratch.reset(.retain_capacity);
                const a = scratch.allocator();
                const real = try runOnce(w, a, call, .{}, false);
                const driven = try runSeeded(w, a, call, .{}, .{}, false);
                try std.testing.expect(real.ok and driven.ok);
                try std.testing.expect(std.meta.eql(real.meter, driven.meter));
                try std.testing.expectEqualSlices(u8, real.bytes, driven.bytes);
            }
            // the operand stack: every height from 28 below the limit up to the limit itself.
            // Low enough the loop is accelerated; near the limit a push inside the loop is the
            // one that overflows, and the interpreter must be the one that runs it.
            var engaged = false;
            var refused = false;
            var overflow = false;
            var sp: usize = stack_max - 28;
            while (sp <= stack_max) : (sp += 1) {
                const r = if (sp % 4 == 0) try sweepSeeded(&c, w, call, .{ .sp = sp }, 6) else try checkSeeded(&c, w, call, .{}, .{ .sp = sp });
                if (c.last_skipped > 0) engaged = true else refused = true;
                if (!r.ok and r.err.major == .EXECUTION_STACK_OVERFLOW) {
                    overflow = true;
                    try std.testing.expectEqual(@as(u64, 0), c.last_skipped);
                }
            }
            try std.testing.expect(engaged and refused and overflow);
            // the call depth: shallow, and every depth from 16 below the limit to past it (a
            // frame can sit at depth limit + 1; one more is seeded too). A loop that calls
            // overflows the call stack inside its first iteration.
            const calls_in_loop = for (w.templates()) |ft| {
                if (std.mem.eql(u8, ft.name, call.name()) and ft.loops[0].shape.callee != null) break true;
            } else false;
            var depth: usize = 1;
            while (depth <= depth_max + 2) : (depth += if (depth == 3) depth_max - 16 - 3 else 1) {
                const r = if (depth % 4 == 0) try sweepSeeded(&c, w, call, .{ .depth = depth }, 6) else try checkSeeded(&c, w, call, .{}, .{ .depth = depth });
                if (!calls_in_loop or wi == 0) continue;
                // (the Wormhole readers: nothing is called before the loop)
                if (depth <= 3) {
                    try std.testing.expect(r.ok and c.last_skipped > 0);
                } else if (depth > depth_max) {
                    try std.testing.expect(!r.ok and r.err.major == .CALL_STACK_OVERFLOW);
                    try std.testing.expectEqual(@as(u64, 0), c.last_skipped);
                }
            }
            if (calls_in_loop and wi != 0) n_call_loops += 1;
            // both near their limits at once
            for ([_]usize{ stack_max - 16, stack_max - 11, stack_max - 10, stack_max - 9, stack_max - 3, stack_max - 1, stack_max }) |sp2| {
                for ([_]usize{ depth_max - 9, depth_max - 8, depth_max - 7, depth_max, depth_max + 1 }) |d2| {
                    _ = try checkSeeded(&c, w, call, .{}, .{ .sp = sp2, .depth = d2 });
                }
            }
        }
    };
    try std.testing.expect(n_calls >= 60 and n_call_loops >= 20);
}

// ---------------------------------------------------------------------------------------------
// The totals (ZUI_VM_LOOPACCEL_STATS)

/// `key=<decimal>` at the front of `text`, which it advances past the value.
fn takeField(text: *[]const u8, key: []const u8) !u64 {
    if (!std.mem.startsWith(u8, text.*, key) or text.len <= key.len or text.*[key.len] != '=') return error.BadTotalsFormat;
    var end = key.len + 1;
    while (end < text.len and std.ascii.isDigit(text.*[end])) end += 1;
    const v = try std.fmt.parseInt(u64, text.*[key.len + 1 .. end], 10);
    text.* = text.*[end..];
    return v;
}

fn takeLit(text: *[]const u8, lit: []const u8) !void {
    if (!std.mem.startsWith(u8, text.*, lit)) return error.BadTotalsFormat;
    text.* = text.*[lit.len..];
}

const GroupRow = struct { attached: u64, mismatches: u64, heads: u64, iters: u64, instrs: u64 };
const Report = struct { modules_matched: u64, digest_misses: u64, all: GroupRow, groups: [loopaccel.N_GROUPS]GroupRow };

/// Parses the two lines of `loopaccel.formatTotals` the way a gate script would: by the
/// documented keys, in the documented order, with nothing else on either line.
fn parseReport(report: []const u8) !Report {
    var r: Report = undefined;
    var t = report;
    try takeLit(&t, "vm-loopaccel: ");
    r.modules_matched = try takeField(&t, "modules_matched");
    try takeLit(&t, " ");
    r.digest_misses = try takeField(&t, "digest_misses");
    try takeLit(&t, " ");
    r.all.attached = try takeField(&t, "functions_attached");
    try takeLit(&t, " ");
    r.all.mismatches = try takeField(&t, "template_mismatches");
    try takeLit(&t, " ");
    r.all.heads = try takeField(&t, "heads");
    try takeLit(&t, " ");
    r.all.iters = try takeField(&t, "iters");
    try takeLit(&t, " ");
    r.all.instrs = try takeField(&t, "instrs");
    try takeLit(&t, "\nvm-loopaccel-shapes:");
    for (&r.groups, 0..) |*g, i| {
        try takeLit(&t, " ");
        try takeLit(&t, @tagName(@as(loopaccel.Group, @enumFromInt(@as(u8, @intCast(i))))));
        try takeLit(&t, ":");
        g.attached = try takeField(&t, "attached");
        try takeLit(&t, ",");
        g.mismatches = try takeField(&t, "mismatches");
        try takeLit(&t, ",");
        g.heads = try takeField(&t, "heads");
        try takeLit(&t, ",");
        g.iters = try takeField(&t, "iters");
        try takeLit(&t, ",");
        g.instrs = try takeField(&t, "instrs");
    }
    if (!std.mem.eql(u8, t, "\n")) return error.BadTotalsFormat;
    return r;
}

fn readGroups() [loopaccel.N_GROUPS]GroupRow {
    var out: [loopaccel.N_GROUPS]GroupRow = undefined;
    for (&loopaccel.totals.groups, &out) |*g, *o| o.* = .{
        .attached = g.attached.load(.monotonic),
        .mismatches = g.mismatches.load(.monotonic),
        .heads = g.heads.load(.monotonic),
        .iters = g.iters.load(.monotonic),
        .instrs = g.instrs.load(.monotonic),
    };
    return out;
}

test "totals: every group counts its attached functions and its accelerated heads, and the exit report parses" {
    const gpa = std.testing.allocator;
    const before = readGroups();
    var std_ws = try stdWorlds(gpa);
    defer std_ws.deinit();
    var fx_ws = try fixtureWorlds(gpa);
    defer fx_ws.deinit();
    var c = Checker.init(gpa);
    defer c.deinit();
    // loading the worlds attached every registered function, each counted in its group
    var want_attached: [loopaccel.N_GROUPS]u64 = @splat(0);
    for ([_]*const Worlds{ &std_ws, &fx_ws }) |ws| for (ws.rts.items) |rt| {
        var it = rt.by_version.valueIterator();
        while (it.next()) |p| for (p.*.modules) |*m| for (m.functions) |*f| {
            const at: *const loopaccel.Attached = @ptrCast(@alignCast(f.accel orelse continue));
            want_attached[@intFromEnum(at.loops[0].shape.group)] += 1;
        };
    };
    const loaded = readGroups();
    for (before, loaded, want_attached) |b, l, want| {
        try std.testing.expect(want > 0);
        try std.testing.expectEqual(want, l.attached - b.attached);
        try std.testing.expectEqual(b.mismatches, l.mismatches);
    }
    // one call per group, on a world that has its template; the per-head counters run only
    // while counting is on, and count what the thread's own stats count
    const std_w = &std_ws.list.items[std_ws.list.items.len - 1];
    var wh_w: ?*const World = null;
    var py_w: ?*const World = null;
    for (fx_ws.list.items) |*w| {
        if (w.natives) py_w = w else wh_w = w;
    }
    const G = loopaccel.Group;
    // (`append` reverses its argument first, and the Pyth leaf and node hashes call `hash`)
    const cases = [_]struct { g: G, also: ?G = null, w: *const World, call: Call }{
        .{ .g = .reverse, .w = std_w, .call = .{ .reverse = .{ .e = .u8, .n = 9 } } },
        .{ .g = .remove, .w = std_w, .call = .{ .remove = .{ .e = .u64, .n = 7, .i = 1 } } },
        .{ .g = .append, .also = .reverse, .w = std_w, .call = .{ .append = .{ .e = .u8, .n = 2, .m = 5 } } },
        .{ .g = .take_bytes, .w = wh_w.?, .call = .{ .take_bytes = .{ .len = 12, .n = 9 } } },
        .{ .g = .take_be, .w = wh_w.?, .call = .{ .take_be = .{ .bits = 16, .len = 5 } } },
        .{ .g = .take_be, .w = wh_w.?, .call = .{ .take_be = .{ .bits = 32, .len = 5 } } },
        .{ .g = .take_be, .w = wh_w.?, .call = .{ .take_be = .{ .bits = 64, .len = 9 } } },
        .{ .g = .pyth_hash, .w = py_w.?, .call = .{ .pyth_hash = .{ .n = 5 } } },
        .{ .g = .pyth_leaf_hash, .also = .pyth_hash, .w = py_w.?, .call = .{ .pyth_leaf = .{ .n = 12 } } },
        .{ .g = .pyth_node_hash, .also = .pyth_hash, .w = py_w.?, .call = .{ .pyth_node = .{ .a = 1, .b = 9 } } },
    };
    for (cases) |cs| {
        // counting off: an accelerated head counts nothing
        const g0 = readGroups();
        _ = try c.check(cs.w, cs.call, .{});
        try std.testing.expect(c.last_skipped > 0);
        try std.testing.expectEqual(g0, readGroups());
        // counting on: the head counts in its own group, and all the groups together count
        // what the thread's own stats count
        loopaccel.countTotals(true);
        defer loopaccel.countTotals(false);
        const s0 = loopaccel.stats;
        _ = try c.check(cs.w, cs.call, .{});
        const g1 = readGroups();
        var d: GroupRow = .{ .attached = 0, .mismatches = 0, .heads = 0, .iters = 0, .instrs = 0 };
        for (g0, g1, 0..) |x, y, i| {
            const g: G = @enumFromInt(@as(u8, @intCast(i)));
            if (g == cs.g) {
                try std.testing.expect(y.heads > x.heads);
                try std.testing.expect(y.iters - x.iters >= y.heads - x.heads);
                try std.testing.expect(y.instrs - x.instrs >= 10 * (y.iters - x.iters));
            } else if (cs.also == null or g != cs.also.?) try std.testing.expectEqual(x, y);
            try std.testing.expectEqual(x.attached, y.attached);
            try std.testing.expectEqual(x.mismatches, y.mismatches);
            d.heads += y.heads - x.heads;
            d.iters += y.iters - x.iters;
            d.instrs += y.instrs - x.instrs;
        }
        try std.testing.expectEqual(loopaccel.stats.hits - s0.hits, d.heads);
        try std.testing.expectEqual(loopaccel.stats.iters - s0.iters, d.iters);
        try std.testing.expectEqual(loopaccel.stats.instrs - s0.instrs, d.instrs);
    }
    // the exit report: the documented two lines, carrying exactly the counters
    var buf: [4096]u8 = undefined;
    const report = loopaccel.formatTotals(&buf);
    const r = try parseReport(report);
    const now = readGroups();
    var sum: GroupRow = .{ .attached = 0, .mismatches = 0, .heads = 0, .iters = 0, .instrs = 0 };
    for (r.groups, now) |got, want| {
        try std.testing.expectEqual(want, got);
        // what a gate requires of every group: attached, and exercised
        try std.testing.expect(got.attached > 0 and got.heads > 0 and got.iters > 0 and got.instrs > 0);
        sum.attached += got.attached;
        sum.mismatches += got.mismatches;
        sum.heads += got.heads;
        sum.iters += got.iters;
        sum.instrs += got.instrs;
    }
    try std.testing.expectEqual(sum, r.all);
    try std.testing.expectEqual(loopaccel.attach_stats.functions_attached.load(.monotonic), r.all.attached);
    try std.testing.expectEqual(loopaccel.attach_stats.template_mismatch.load(.monotonic), r.all.mismatches);
    try std.testing.expectEqual(loopaccel.attach_stats.modules_matched.load(.monotonic), r.modules_matched);
    try std.testing.expectEqual(loopaccel.attach_stats.modules_digest_miss.load(.monotonic), r.digest_misses);
    // a buffer that is too small gives a prefix, never more than it holds
    var small: [40]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, report, loopaccel.formatTotals(&small)));
}

extern "c" fn mkstemp(template: [*:0]u8) c_int;
extern "c" fn unlink(path: [*:0]const u8) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn pipe(fds: *[2]c_int) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern "c" fn pread(fd: c_int, buf: [*]u8, n: usize, offset: i64) isize;
extern "c" fn pwrite(fd: c_int, buf: [*]const u8, n: usize, offset: i64) isize;

test "the exit report goes after what a redirected stderr file already holds" {
    // A log that stdout and stderr were both redirected to. Its other writers are positional
    // (each from its own offset 0), so the descriptor's own offset is still 0 when the
    // process exits: a plain write, or one more positional writer, would start on top of
    // the first line.
    var path = "/tmp/zui-loopaccel-XXXXXX".*;
    const fd = mkstemp(&path);
    try std.testing.expect(fd >= 0);
    defer _ = close(fd);
    _ = unlink(&path);
    const log = "{\"suite\":\"move-vm-gas\",\"status\":\"ok\"}\nmove-vm-gas: peak call memory\n";
    try std.testing.expectEqual(@as(isize, log.len), pwrite(fd, log.ptr, log.len, 0));
    var report_buf: [4096]u8 = undefined;
    const report = loopaccel.formatTotals(&report_buf);
    loopaccel.writeAtEnd(fd, report);
    // and again: a second writer of the same file goes after the first
    loopaccel.writeAtEnd(fd, "last\n");
    var got: [8192]u8 = undefined;
    const n = pread(fd, &got, got.len, 0);
    try std.testing.expectEqual(@as(isize, @intCast(log.len + report.len + 5)), n);
    try std.testing.expectEqualStrings(log, got[0..log.len]);
    try std.testing.expectEqualStrings(report, got[log.len..][0..report.len]);
    try std.testing.expectEqualStrings("last\n", got[log.len + report.len ..][0..5]);
    // the report is still the documented two lines
    _ = try parseReport(got[log.len..][0..report.len]);
    // a pipe cannot seek: the bytes go through as they are
    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), pipe(&fds));
    defer _ = close(fds[0]);
    loopaccel.writeAtEnd(fds[1], report);
    _ = close(fds[1]);
    var piped: [8192]u8 = undefined;
    var len: usize = 0;
    while (true) {
        const r = read(fds[0], piped[len..].ptr, piped.len - len);
        if (r <= 0) break;
        len += @intCast(r);
    }
    try std.testing.expectEqualStrings(report, piped[0..len]);
}

// ---------------------------------------------------------------------------------------------
// Microbench (ZUI_LOOPACCEL_BENCH=1, a ReleaseFast build): ns per original instruction of each
// accelerated function with the switch off and on. The time is `Session.run` alone.

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn benchRun(w: *const World, arena: *std.heap.ArenaAllocator, call: Call, accel: bool, instrs: *u64) !u64 {
    _ = arena.reset(.retain_capacity);
    const a = arena.allocator();
    var slots: [2]?*Value = .{ null, null };
    const b = try build(w, .{ .arena = a }, a, call, &slots);
    var meter = gas.Meter.init(w.gm, 0, 1);
    (MeterSetup{}).apply(&meter);
    var lc = interp.LinkCtx.init(w.rt, w.pkg);
    defer lc.deinit();
    var sess = try interp.Session.init(a, &lc, &meter, w.ecfg);
    if (w.natives) {
        const h = try a.create(host.Host);
        h.* = .{ .cfg = try protocol.get(w.pv, .mainnet), .tx = conformance.DEFAULT_TX };
        const table = try a.create(interp.NativeTable);
        table.* = h.table();
        sess.natives = table;
        sess.ext = h;
    }
    if (accel) loopaccel.enable() else loopaccel.disable();
    defer loopaccel.disable();
    const t0 = nowNs();
    const res = try sess.run(b.func, b.ty_args, b.args);
    const t1 = nowNs();
    if (res != .ok) return error.BenchCallFailed;
    instrs.* = meter.instructions_executed;
    return t1 - t0;
}

fn benchCall(w: *const World, arena: *std.heap.ArenaAllocator, label: []const u8, call: Call) !void {
    var instrs: u64 = 0;
    _ = try benchRun(w, arena, call, false, &instrs);
    const reps: usize = @intCast(@max(200, @min(200_000, 40_000_000 / @max(instrs, 1))));
    var best: [2]u64 = .{ std.math.maxInt(u64), std.math.maxInt(u64) };
    // five passes each, interleaved; the best pass of each mode
    for (0..5) |_| {
        for ([_]bool{ false, true }, 0..) |accel, mode| {
            var total: u64 = 0;
            for (0..reps) |_| total += try benchRun(w, arena, call, accel, &instrs);
            best[mode] = @min(best[mode], total);
        }
    }
    const per = @as(f64, @floatFromInt(reps)) * @as(f64, @floatFromInt(instrs));
    const off = @as(f64, @floatFromInt(best[0])) / per;
    const on = @as(f64, @floatFromInt(best[1])) / per;
    std.debug.print("{s:<34} pv {d:>3} gm {d:>2}  {d:>7} instr/call  off {d:>7.2} ns/instr  on {d:>7.2} ns/instr  {d:>6.1}x\n", .{ label, w.pv, w.gm, instrs, off, on, off / on });
}

test "microbench: ns per original instruction, switch off and on" {
    if (std.c.getenv("ZUI_LOOPACCEL_BENCH") == null) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var std_ws = try stdWorlds(gpa);
    defer std_ws.deinit();
    var fx_ws = try fixtureWorlds(gpa);
    defer fx_ws.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    std.debug.print("\nloopaccel microbench (Session.run only; sizes near the mainnet per-call averages, then large)\n", .{});
    for (std_ws.list.items) |*w| {
        if (!w.primary) continue;
        std.debug.print("-- 0x1::vector digest {x}\n", .{w.digest[0..4].*});
        try benchCall(w, &arena, "reverse<u8> n=52", .{ .reverse = .{ .e = .u8, .n = 52 } });
        try benchCall(w, &arena, "reverse<u8> n=2000", .{ .reverse = .{ .e = .u8, .n = 2000 } });
        try benchCall(w, &arena, "reverse<u64> n=52", .{ .reverse = .{ .e = .u64, .n = 52 } });
        try benchCall(w, &arena, "reverse<vector<u8>> n=52", .{ .reverse = .{ .e = .vec_u8, .n = 52 } });
        try benchCall(w, &arena, "remove<u8> n=56 i=0", .{ .remove = .{ .e = .u8, .n = 56, .i = 0 } });
        try benchCall(w, &arena, "remove<u64> n=2000 i=0", .{ .remove = .{ .e = .u64, .n = 2000, .i = 0 } });
        try benchCall(w, &arena, "append<u8> 8 += 6", .{ .append = .{ .e = .u8, .n = 8, .m = 6 } });
        try benchCall(w, &arena, "append<u8> 8 += 2000", .{ .append = .{ .e = .u8, .n = 8, .m = 2000 } });
    }
    for (fx_ws.list.items) |*w| {
        if (!w.primary) continue;
        if (!w.natives) {
            std.debug.print("-- Wormhole bytes digest {x}\n", .{w.digest[0..4].*});
            try benchCall(w, &arena, "take_bytes n=1", .{ .take_bytes = .{ .len = 200, .n = 1 } });
            try benchCall(w, &arena, "take_bytes n=4", .{ .take_bytes = .{ .len = 200, .n = 4 } });
            try benchCall(w, &arena, "take_bytes n=32", .{ .take_bytes = .{ .len = 200, .n = 32 } });
            try benchCall(w, &arena, "take_bytes n=2000", .{ .take_bytes = .{ .len = 2100, .n = 2000 } });
            try benchCall(w, &arena, "take_u64_be", .{ .take_be = .{ .bits = 64, .len = 200 } });
            try benchCall(w, &arena, "take_u32_be", .{ .take_be = .{ .bits = 32, .len = 200 } });
            try benchCall(w, &arena, "take_u16_be", .{ .take_be = .{ .bits = 16, .len = 200 } });
        } else {
            std.debug.print("-- Pyth merkle_tree digest {x}\n", .{w.digest[0..4].*});
            try benchCall(w, &arena, "hash (32 bytes)", .{ .pyth_hash = .{ .n = 32 } });
            try benchCall(w, &arena, "leaf_hash (85 bytes)", .{ .pyth_leaf = .{ .n = 85 } });
            try benchCall(w, &arena, "node_hash", .{ .pyth_node = .{ .a = 1, .b = 2 } });
        }
    }
}
