//! Fuzz harness for the natives as DevInspect<true> exposes them (`Inputs.skip_all_checks`):
//! with checks disabled a client calls any function of the system packages, the private and
//! friend natives included, with values built from arbitrary bytes and with arbitrary type
//! arguments. Every such call must end as an execution result (success, a Move abort, an
//! execution error) or as unsupported: never a panic, an out-of-bounds access, or an allocation
//! or a loop the gas budget does not bound.
//!
//! The harness enumerates the functions the system packages declare (0x1, 0x2, 0x3, 0xb, 0xdee9
//! of the fixture's epoch): every native, and in a second pass every function (the Move
//! functions through which bytecode reaches the natives). Each case is a PTB of one to three
//! calls. Arguments are pure inputs shaped after the parameter types (valid BCS with edge
//! values: empty and long vectors, zero and maximum integers, known and bogus object ids, curve
//! points, invalid UTF-8) and then, for some, mutated (truncated, extended, random, a ULEB128
//! prefix that is not minimal, a huge length prefix); some arguments are the gas coin, an
//! object input or an earlier result instead. Type arguments come from a pool of primitives,
//! framework types, nested types up to 40 levels and types that do not exist. One case in five
//! aims at the pre-state's dynamic field (its parent and child ids, its type), so the object
//! runtime's natives find a real child.
//!
//! Deterministic: case `(function, iteration)` of seed S is the same PTB on every run.
//!   ZUI_DEVINSPECT_FUZZ_ITERS=N       cases per native (default 6: the unit lane's fixed set)
//!   ZUI_DEVINSPECT_FUZZ_ALL_ITERS=N   cases per function in the every-function pass (default 1)
//!   ZUI_DEVINSPECT_FUZZ_SEED=S        base seed (default 1)
//!   ZUI_DEVINSPECT_FUZZ_ONLY=module::function   one function
//!   ZUI_DEVINSPECT_FUZZ_TRACE=1       print each case before it runs (the last line is the crash)
//!   ZUI_DEVINSPECT_FUZZ_REPORT=1      per-function counts, and the native table entries no
//!                                     package declares
//! A long run (zig caches test results, so run the built binary with the environment set):
//!   ./zig build test -Dlane=exec -Doptimize=ReleaseSafe
//!   ZUI_DEVINSPECT_FUZZ_ITERS=100000 ZUI_DEVINSPECT_FUZZ_ALL_ITERS=3000 \
//!     $ZIG_LOCAL_CACHE_DIR/o/<newest>/test-exec
//! Needs the corpus system packages (`devinspect_test.Fixture`): skipped without them.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const move_vm = @import("move_vm");
const natives = @import("natives");
const objects = @import("../objects.zig");
const ptb = @import("root.zig");
const pkgs = @import("pkgs.zig");
const typing = @import("typing.zig");
const dt = @import("devinspect_test.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const Ty = typing.Ty;
const Fixture = dt.Fixture;

pub const Native = struct { pkg: Id, module: []const u8, name: []const u8, n_type_params: u16 };

const system_ids = [_]u16{ 0x1, 0x2, 0x3, 0xb, 0xdee9 };

fn shortId(x: u16) Id {
    var id: Id = @splat(0);
    std.mem.writeInt(u16, id[30..32], x, .big);
    return id;
}

fn cacheOf(f: *const Fixture) !*pkgs.Cache {
    return pkgs.cacheFor(std.heap.page_allocator, &f.pkgs, f.epoch, f.pv, f.cfg.chain);
}

pub const Which = enum { natives, functions };

/// The functions the fixture's system packages declare, in package, module, definition order:
/// every native, or (`functions`) every function, the Move ones through which bytecode reaches
/// the natives included.
pub fn enumerate(arena: Allocator, f: *const Fixture) ![]const Native {
    return enumerateWhich(arena, f, .natives);
}

pub fn enumerateWhich(arena: Allocator, f: *const Fixture, which: Which) ![]const Native {
    const cache = try cacheOf(f);
    var out: std.ArrayList(Native) = .empty;
    for (system_ids) |sid| {
        const id = shortId(sid);
        const pkg = (cache.get(&id) catch null) orelse continue;
        const vp = cache.load(pkg) catch continue;
        for (vp.modules) |*m| for (m.functions) |*func| {
            if (which == .natives and !func.is_native) continue;
            try out.append(arena, .{ .pkg = id, .module = m.name, .name = func.name, .n_type_params = func.n_type_params });
        };
    }
    return out.items;
}

// ---- pre-state ---------------------------------------------------------------------------------

pub const owned_coin: Id = dt.idOf(0x51);
pub const shared_coin: Id = dt.idOf(0x41);
pub const parent: Id = dt.idOf(0xc0);
pub const child: Id = dt.idOf(0xc1);
/// A config setting under `parent`: `Field<u64, Setting<u64>>`.
pub const setting: Id = dt.idOf(0xc3);
const clock_id: Id = shortId(6);

fn struct2(module: []const u8, name: []const u8, args: []const types.TypeTag) types.StructTag {
    return .{ .address = .{ .@"0" = dt.framework(2) }, .module = .{ .@"0" = module }, .name = .{ .@"0" = name }, .type_args = args };
}

fn moveObject(arena: Allocator, st: types.StructTag, version: u64, contents: []const u8, owner: types.Owner) ![]const u8 {
    const obj: types.Object = .{
        .data = .{ .Move = .{ .type_ = .{ .@"0" = .{ .Other = st } }, .has_public_transfer = false, .version = .{ .@"0" = version }, .contents = contents } },
        .owner = owner,
        .previous_transaction = .{ .@"0" = .{ .@"0" = dt.idOf(0x5a) } },
        .storage_rebate = 0,
    };
    return bcs.encodeAlloc(types.Object, arena, &obj);
}

/// Objects the natives can find: coins (owned, shared), the Clock, and a dynamic field
/// `Field<u64, u64>` under `parent`.
pub fn populate(f: *Fixture) !void {
    const a = f.arena;
    try f.add(try dt.coinObject(a, owned_coin, 8, 5000, .{ .AddressOwner = .{ .@"0" = dt.sender } }));
    try f.add(try dt.coinObject(a, shared_coin, 6, 4242, .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 3 } } }));
    var clock: [40]u8 = undefined;
    @memcpy(clock[0..32], &clock_id);
    std.mem.writeInt(u64, clock[32..40], f.start_ms, .little);
    try f.add(try moveObject(a, struct2("clock", "Clock", &.{}), 9, try a.dupe(u8, &clock), .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 1 } } }));
    var field: [48]u8 = undefined;
    @memcpy(field[0..32], &child);
    std.mem.writeInt(u64, field[32..40], 5, .little);
    std.mem.writeInt(u64, field[40..48], 42, .little);
    try f.add(try moveObject(a, struct2("dynamic_field", "Field", &.{ .u64, .u64 }), 7, try a.dupe(u8, &field), .{ .ObjectOwner = .{ .@"0" = parent } }));
    // Field<u64, Setting<u64>> { id, name: 5, value: Setting { data: some(SettingData {
    //   newer_value_epoch: 3, newer_value: some(42), older_value_opt: none }) } }
    var st: std.ArrayList(u8) = .empty;
    try st.appendSlice(a, &setting);
    try st.appendSlice(a, try dt.u64Bytes(a, 5));
    try st.append(a, 1);
    try st.appendSlice(a, try dt.u64Bytes(a, 3));
    try st.append(a, 1);
    try st.appendSlice(a, try dt.u64Bytes(a, 42));
    try st.append(a, 0);
    const setting_tag: types.TypeTag = .{ .@"struct" = struct2("config", "Setting", &.{.u64}) };
    try f.add(try moveObject(a, struct2("dynamic_field", "Field", &.{ .u64, setting_tag }), 7, st.items, .{ .ObjectOwner = .{ .@"0" = parent } }));
}

// ---- generators --------------------------------------------------------------------------------

const Gen = struct {
    r: std.Random,
    a: Allocator,
    /// Bytes this case may still generate (keeps a case's input bounded).
    budget: usize = 96 * 1024,
    /// A case that aims at the pre-state's dynamic fields: ids alternate between `parent` and
    /// one of its children (`child`, `setting`) and type arguments are mostly their types and
    /// parts of them, so the object runtime's natives find a real child of the right (or a
    /// wrong) type.
    coherent: bool = false,
    ids: u32 = 0,

    fn below(g: *Gen, n: usize) usize {
        return g.r.uintLessThan(usize, n);
    }
    fn chance(g: *Gen, percent: u8) bool {
        return g.r.uintLessThan(u8, 100) < percent;
    }

    // ---- type inputs

    fn st(g: *Gen, addr: Id, module: []const u8, name: []const u8, args: []const types.TypeInput) !types.TypeInput {
        return .{ .@"struct" = .{ .address = .{ .@"0" = addr }, .module = .{ .@"0" = module }, .name = .{ .@"0" = name }, .type_args = try g.a.dupe(types.TypeInput, args) } };
    }

    fn vec(g: *Gen, e: types.TypeInput) !types.TypeInput {
        const p = try g.a.create(types.TypeInput);
        p.* = e;
        return .{ .vector = p };
    }

    fn typeInput(g: *Gen, depth: u32) Allocator.Error!types.TypeInput {
        const two = dt.framework(2);
        const one = dt.framework(1);
        if (g.coherent and depth == 0 and g.chance(70)) {
            const setting_u64 = try g.st(two, "config", "Setting", &.{.u64});
            return switch (g.below(6)) {
                0, 1 => g.st(two, "dynamic_field", "Field", &.{ .u64, .u64 }),
                2, 3 => g.st(two, "dynamic_field", "Field", &.{ .u64, setting_u64 }),
                4 => setting_u64,
                else => g.st(two, "config", "SettingData", &.{.u64}),
            };
        }
        const leaf = depth >= 4;
        return switch (g.below(if (leaf) 22 else 40)) {
            0 => .bool,
            1 => .u8,
            2 => .u16,
            3 => .u32,
            4 => .u64,
            5 => .u128,
            6 => .u256,
            7 => .address,
            8 => .signer,
            9 => try g.st(one, "string", "String", &.{}),
            10 => try g.st(one, "ascii", "String", &.{}),
            11 => try g.st(one, "type_name", "TypeName", &.{}),
            12 => try g.st(two, "object", "ID", &.{}),
            13 => try g.st(two, "object", "UID", &.{}),
            14 => try g.st(two, "sui", "SUI", &.{}),
            15 => try g.st(two, "tx_context", "TxContext", &.{}),
            16 => try g.st(two, "clock", "Clock", &.{}),
            17 => try g.st(two, "bag", "Bag", &.{}),
            18 => try g.st(two, "bls12381", "G1", &.{}),
            19 => try g.st(two, "bls12381", "Scalar", &.{}),
            // types that do not exist: a module the package lacks, a struct the module lacks,
            // a package no store holds
            20 => try g.st(two, "no_such_module", "T", &.{}),
            21 => switch (g.below(3)) {
                0 => try g.st(two, "coin", "NoSuchStruct", &.{}),
                1 => try g.st(dt.idOf(0xee), "m", "T", &.{}),
                // wrong arity
                else => try g.st(two, "coin", "Coin", &.{}),
            },
            22, 23, 24 => try g.vec(try g.typeInput(depth + 1)),
            25 => try g.vec(.u8),
            26 => try g.st(one, "option", "Option", &.{try g.typeInput(depth + 1)}),
            27 => try g.st(two, "coin", "Coin", &.{try g.st(two, "sui", "SUI", &.{})}),
            28 => try g.st(two, "coin", "Coin", &.{try g.typeInput(depth + 1)}),
            29 => try g.st(two, "balance", "Balance", &.{try g.typeInput(depth + 1)}),
            30 => try g.st(two, "dynamic_field", "Field", &.{ try g.typeInput(depth + 1), try g.typeInput(depth + 1) }),
            31 => try g.st(two, "dynamic_field", "Field", &.{ .u64, .u64 }),
            32 => try g.st(two, "dynamic_object_field", "Wrapper", &.{try g.typeInput(depth + 1)}),
            33 => try g.st(two, "config", "Setting", &.{try g.typeInput(depth + 1)}),
            34 => try g.st(two, "transfer", "Receiving", &.{try g.typeInput(depth + 1)}),
            35 => try g.st(two, "table", "Table", &.{ try g.typeInput(depth + 1), try g.typeInput(depth + 1) }),
            36 => try g.st(two, "vec_map", "VecMap", &.{ try g.typeInput(depth + 1), try g.typeInput(depth + 1) }),
            37 => try g.st(two, "group_ops", "Element", &.{try g.typeInput(depth + 1)}),
            38 => try g.st(two, "accumulator", "Key", &.{try g.typeInput(depth + 1)}),
            // a deep nest: vector<vector<..<u8>..>> up to 40 levels
            else => blk: {
                var t: types.TypeInput = .u8;
                for (0..1 + g.below(40)) |_| t = try g.vec(t);
                break :blk t;
            },
        };
    }

    // ---- values

    fn id(g: *Gen) Id {
        if (g.coherent and g.chance(85)) {
            g.ids += 1;
            return if (g.ids % 2 == 1) parent else if (g.chance(50)) child else setting;
        }
        return switch (g.below(14)) {
            0 => dt.gas_id,
            1 => owned_coin,
            2 => shared_coin,
            3 => parent,
            4 => child,
            5 => clock_id,
            6 => shortId(5),
            7 => shortId(0x403),
            8 => shortId(0xacc),
            9 => dt.sender,
            10 => @splat(0),
            11 => @splat(0xff),
            else => blk: {
                var x: Id = undefined;
                g.r.bytes(&x);
                break :blk x;
            },
        };
    }

    fn uleb(g: *Gen, out: *std.ArrayList(u8), x0: u64) !void {
        var x = x0;
        while (x >= 0x80) : (x >>= 7) try out.append(g.a, @as(u8, @truncate(x)) | 0x80);
        try out.append(g.a, @truncate(x));
    }

    fn int(g: *Gen, comptime n: usize, out: *std.ArrayList(u8)) !void {
        var b: [n]u8 = undefined;
        switch (g.below(8)) {
            0 => @memset(&b, 0),
            1 => @memset(&b, 0xff),
            2 => {
                @memset(&b, 0);
                b[0] = 1;
            },
            3 => {
                @memset(&b, 0xff);
                b[n - 1] = 0x7f;
            },
            4, 5 => {
                // a small value
                @memset(&b, 0);
                b[0] = g.r.int(u8);
            },
            else => g.r.bytes(&b),
        }
        try out.appendSlice(g.a, &b);
    }

    /// Lengths that matter to hashes, keys, signatures, points and limits.
    fn len(g: *Gen) usize {
        const edges = [_]usize{ 0, 0, 1, 1, 2, 3, 8, 31, 32, 33, 47, 48, 49, 64, 65, 66, 95, 96, 97, 127, 128, 129, 255, 256, 1024, 4096, 16 * 1024 };
        return edges[g.below(edges.len)];
    }

    const g1_generator = [48]u8{ 0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb };

    /// A `vector<u8>` body (length prefix included).
    fn byteVector(g: *Gen, out: *std.ArrayList(u8)) !void {
        switch (g.below(12)) {
            0 => {
                try g.uleb(out, 48);
                try out.appendSlice(g.a, &g1_generator);
            },
            1 => {
                // the point at infinity of a compressed BLS12-381 group, G1 or G2 size
                const n: usize = if (g.chance(50)) 48 else 96;
                try g.uleb(out, n);
                try out.append(g.a, 0xc0);
                try out.appendNTimes(g.a, 0, n - 1);
            },
            2 => {
                // a scalar: 1, big endian
                try g.uleb(out, 32);
                try out.appendNTimes(g.a, 0, 31);
                try out.append(g.a, 1);
            },
            3 => {
                const s = "hello, world";
                try g.uleb(out, s.len);
                try out.appendSlice(g.a, s);
            },
            4 => {
                // not UTF-8
                try out.appendSlice(g.a, &.{ 4, 0xff, 0xfe, 0xc0, 0x80 });
            },
            else => {
                const n = @min(g.len(), g.budget);
                g.budget -= n;
                try g.uleb(out, n);
                const at = out.items.len;
                try out.resize(g.a, at + n);
                switch (g.below(4)) {
                    0 => @memset(out.items[at..], 0),
                    1 => @memset(out.items[at..], 0xff),
                    else => g.r.bytes(out.items[at..]),
                }
            },
        }
    }

    /// BCS of a value of runtime type `t`, with edge values.
    fn value(g: *Gen, t: Ty, out: *std.ArrayList(u8), depth: u32) !void {
        if (depth > 64) return;
        switch (t.*) {
            .bool => try out.append(g.a, if (g.chance(3)) g.r.int(u8) else @intFromBool(g.r.boolean())),
            .u8 => try g.int(1, out),
            .u16 => try g.int(2, out),
            .u32 => try g.int(4, out),
            .u64 => try g.int(8, out),
            .u128 => try g.int(16, out),
            .u256 => try g.int(32, out),
            .address, .signer => try out.appendSlice(g.a, &g.id()),
            .vector => |e| {
                if (e.* == .u8) return g.byteVector(out);
                const n = @min(g.len(), 40);
                const at = out.items.len;
                try g.uleb(out, n);
                var made: usize = 0;
                for (0..n) |_| {
                    if (g.budget < 64) break;
                    g.budget -= 64;
                    try g.value(e, out, depth + 1);
                    made += 1;
                }
                if (made != n) {
                    // out of budget: rewrite the length (n <= 40, one ULEB byte)
                    out.items[at] = @intCast(made);
                }
            },
            .datatype => |d| {
                if (d.dt.is_enum) {
                    const nv = d.dt.variants.len;
                    if (nv == 0) return;
                    const tag = if (g.chance(3)) nv + g.below(3) else g.below(nv);
                    try g.uleb(out, tag);
                    if (tag >= nv) return;
                    for (d.dt.variants[tag].fields) |fd| try g.value(try move_vm.types.instantiate(g.a, d.dt.module, fd.signature, d.args), out, depth + 1);
                    return;
                }
                for (d.dt.fields) |fd| try g.value(try move_vm.types.instantiate(g.a, d.dt.module, fd.signature, d.args), out, depth + 1);
            },
            .ref, .mut_ref => |i| try g.value(i, out, depth),
            .param => {},
        }
    }

    /// Bytes that are not (or only by chance) a value of the type.
    fn mutate(g: *Gen, b: *std.ArrayList(u8)) !void {
        switch (g.below(7)) {
            0 => if (b.items.len > 0) b.shrinkRetainingCapacity(g.below(b.items.len)),
            1 => {
                const n = 1 + g.below(9);
                const at = b.items.len;
                try b.resize(g.a, at + n);
                g.r.bytes(b.items[at..]);
            },
            2 => {
                b.clearRetainingCapacity();
                const n = g.len() % 300;
                try b.resize(g.a, n);
                g.r.bytes(b.items);
            },
            // a length prefix that is not minimal
            3 => try b.insertSlice(g.a, 0, &.{ 0x80, 0x00 }),
            // a length prefix of 2^32 - 1 and of 2^63
            4 => try b.insertSlice(g.a, 0, &.{ 0xff, 0xff, 0xff, 0xff, 0x0f }),
            5 => try b.insertSlice(g.a, 0, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 }),
            else => if (b.items.len > 0) {
                b.items[g.below(b.items.len)] ^= @as(u8, 1) << g.r.int(u3);
            },
        }
    }
};

// ---- one case ----------------------------------------------------------------------------------

pub const Verdict = enum { success, failed_in_execution, failed_before, unsupported };

pub const Stats = struct {
    cases: u64 = 0,
    success: u64 = 0,
    failed_in_execution: u64 = 0,
    failed_before: u64 = 0,
    unsupported: u64 = 0,
    max_ns: u64 = 0,
    max_arena: usize = 0,
};

/// The object inputs a case may use, appended once per case when used.
const ObjInput = enum { owned, shared_as_owned, shared, clock };

const Case = struct {
    f: *const Fixture,
    g: *Gen,
    inputs: std.ArrayList(types.CallArg) = .empty,
    commands: std.ArrayList(types.Command) = .empty,
    obj_slot: [4]?u16 = @splat(null),

    fn objInput(c: *Case, which: ObjInput) !types.Argument {
        const k = @intFromEnum(which);
        if (c.obj_slot[k]) |i| return .{ .Input = i };
        // a shared object is one input: never both as shared and as owned
        if (which == .shared) if (c.obj_slot[@intFromEnum(ObjInput.shared_as_owned)]) |i| return .{ .Input = i };
        if (which == .shared_as_owned) if (c.obj_slot[@intFromEnum(ObjInput.shared)]) |i| return .{ .Input = i };
        const a = c.g.a;
        const arg: types.CallArg = switch (which) {
            .owned => .{ .Object = .{ .ImmOrOwnedObject = try dt.refOf(c.f.objs.get(owned_coin).?) } },
            .shared_as_owned => .{ .Object = .{ .ImmOrOwnedObject = try dt.refOf(c.f.objs.get(shared_coin).?) } },
            .shared => .{ .Object = .{ .SharedObject = .{ .id = .{ .@"0" = .{ .@"0" = shared_coin } }, .initial_shared_version = .{ .@"0" = 3 }, .mutability = if (c.g.chance(50)) .Mutable else .Immutable } } },
            .clock => .{ .Object = .{ .SharedObject = .{ .id = .{ .@"0" = .{ .@"0" = clock_id } }, .initial_shared_version = .{ .@"0" = 1 }, .mutability = if (c.g.chance(80)) .Immutable else .Mutable } } },
        };
        try c.inputs.append(a, arg);
        c.obj_slot[k] = @intCast(c.inputs.items.len - 1);
        return .{ .Input = c.obj_slot[k].? };
    }

    fn pure(c: *Case, bytes: []const u8) !types.Argument {
        try c.inputs.append(c.g.a, .{ .Pure = bytes });
        return .{ .Input = @intCast(c.inputs.items.len - 1) };
    }

    /// One call of `n`: type arguments, then arguments shaped after the instantiated parameters
    /// when the function loads with them.
    fn call(c: *Case, n: *const Native, cache: *pkgs.Cache) !void {
        const g = c.g;
        const a = g.a;
        var call_shape: ?*typing.Call = null;
        var ty_args: []types.TypeInput = &.{};
        // mostly type arguments the function accepts (a few tries), sometimes whatever comes,
        // sometimes the wrong number of them
        const tries: usize = if (g.chance(85)) 6 else 1;
        for (0..tries) |_| {
            const count: usize = if (g.chance(4)) g.below(4) else n.n_type_params;
            ty_args = try a.alloc(types.TypeInput, count);
            for (ty_args) |*t| t.* = try g.typeInput(0);
            var diag: pkgs.Diag = .{};
            var linker: pkgs.Linker = .{ .arena = a, .cache = cache, .cfg = c.f.cfg, .diag = &diag, .authoritative = true };
            var p: typing.Ptb = .{ .arena = a, .cfg = c.f.cfg, .linker = &linker, .diag = &diag, .meter = undefined, .pt = undefined, .skip_checks = true };
            const mc: types.ProgrammableMoveCall = .{ .package = .{ .@"0" = .{ .@"0" = n.pkg } }, .module = .{ .@"0" = n.module }, .function = .{ .@"0" = n.name }, .type_arguments = ty_args, .arguments = &.{} };
            call_shape = typing.loadFunction(&p, &mc) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => null,
            };
            if (call_shape != null) break;
        }
        var args: std.ArrayList(types.Argument) = .empty;
        if (call_shape) |shape| {
            for (shape.params) |t| {
                if (typing.txContextKind(t) != .none) continue;
                try args.append(a, try c.argument(t));
            }
            // sometimes one argument too few or too many
            if (g.chance(2) and args.items.len > 0) _ = args.pop();
            if (g.chance(2)) try args.append(a, try c.pure(&.{0}));
        } else {
            for (0..g.below(4)) |_| {
                var b: std.ArrayList(u8) = .empty;
                try g.byteVector(&b);
                try args.append(a, try c.pure(b.items));
            }
        }
        try c.commands.append(a, .{ .MoveCall = .{
            .package = .{ .@"0" = .{ .@"0" = n.pkg } },
            .module = .{ .@"0" = n.module },
            .function = .{ .@"0" = n.name },
            .type_arguments = ty_args,
            .arguments = args.items,
        } });
    }

    fn argument(c: *Case, t: Ty) !types.Argument {
        const g = c.g;
        switch (g.below(100)) {
            0, 1 => return .GasCoin,
            2, 3 => return c.objInput(.owned),
            4 => return c.objInput(.shared_as_owned),
            5 => return c.objInput(.shared),
            6, 7 => return c.objInput(.clock),
            8, 9 => if (c.commands.items.len > 0) return .{ .NestedResult = .{ @intCast(g.below(c.commands.items.len)), @intCast(g.below(2)) } },
            else => {},
        }
        // a Clock parameter mostly gets the Clock
        if (typing.isDt(typing.inner(t), 2, "clock", "Clock") and g.chance(70)) return c.objInput(.clock);
        if (typing.coinInner(typing.inner(t)) != null and g.chance(30)) return if (g.chance(50)) .GasCoin else c.objInput(.owned);
        var b: std.ArrayList(u8) = .empty;
        try g.value(t, &b, 0);
        if (g.chance(15)) try g.mutate(&b);
        return c.pure(b.items);
    }
};

fn caseSeed(seed: u64, n: *const Native, iter: u64) u64 {
    var h = std.hash.Wyhash.init(seed);
    h.update(n.module);
    h.update("::");
    h.update(n.name);
    h.update(std.mem.asBytes(&iter));
    return h.final();
}

/// Builds and runs case `iter` of `n` under `seed` in `arena`. Returns how it ended.
pub fn runCase(f: *const Fixture, all: []const Native, n: *const Native, seed: u64, iter: u64, arena: Allocator) !Verdict {
    var prng = std.Random.DefaultPrng.init(caseSeed(seed, n, iter));
    var g: Gen = .{ .r = prng.random(), .a = arena };
    g.coherent = g.chance(20);
    var c: Case = .{ .f = f, .g = &g };
    const cache = try cacheOf(f);
    // sometimes another native runs first (its results can be this one's arguments), and
    // sometimes one runs after
    if (g.chance(15)) try c.call(&all[g.below(all.len)], cache);
    try c.call(n, cache);
    if (g.chance(10)) try c.call(&all[g.below(all.len)], cache);
    const pt: types.ProgrammableTransaction = .{ .inputs = c.inputs.items, .commands = c.commands.items };
    // rpc_exec answers UNIMPLEMENTED both for `.unsupported` and for an error `execute` returns
    const out = switch (f.runIn(arena, pt, .{ .skip_all_checks = true, .track_results = g.chance(50) }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => |x| {
            try noteReason(@errorName(x));
            return .unsupported;
        },
    }) {
        .unsupported => |why| {
            try noteReason(why);
            // every native that can hand back a value of another layout says which
            // (`abi.Outcome.ok.actual`): the guard for the others must never fire
            if (std.mem.indexOf(u8, why, "a native returned a value that is not of its declared type") != null) return error.TestUnexpectedResult;
            return .unsupported;
        },
        .done => |o| o,
    };
    const fx = (try bcs.decode(types.TransactionEffects, arena, out.effects)).V2;
    return switch (fx.status) {
        .Success => .success,
        .Failure => |x| switch (x.@"error") {
            // typing and loading: the native was not entered
            .CommandArgumentError, .TypeArgumentError, .ArityMismatch, .NonEntryFunctionInvoked, .FunctionNotFound, .VMVerificationOrDeserializationError, .InvariantViolation, .UnusedValueWithoutDrop, .InvalidPublicFunctionReturnType, .PublishUpgradeMissingDependency => .failed_before,
            else => .failed_in_execution,
        },
    };
}

/// `ZUI_DEVINSPECT_FUZZ_REPORT`: how often each unsupported reason came up (the test thread only).
var reasons: ?std.StringArrayHashMapUnmanaged(u64) = null;

fn noteReason(why: []const u8) !void {
    const m = &(reasons orelse return);
    const gpa = std.heap.page_allocator;
    const gop = try m.getOrPut(gpa, why);
    if (!gop.found_existing) {
        gop.key_ptr.* = try gpa.dupe(u8, why);
        gop.value_ptr.* = 0;
    }
    gop.value_ptr.* += 1;
}

fn envInt(name: [*:0]const u8, default: u64) u64 {
    const v = std.c.getenv(name) orelse return default;
    return std.fmt.parseInt(u64, std.mem.span(v), 0) catch default;
}

/// Runs `iters` cases of every native (or of `ZUI_DEVINSPECT_FUZZ_ONLY`). Returns the natives
/// and their statistics, in `enumerate` order.
pub fn run(f: *const Fixture, arena: Allocator, io: std.Io, which: Which, seed: u64, iters: u64, stats_out: *[]Stats) ![]const Native {
    const all = try enumerateWhich(arena, f, which);
    const stats = try arena.alloc(Stats, all.len);
    @memset(stats, .{});
    stats_out.* = stats;
    const only: ?[]const u8 = if (std.c.getenv("ZUI_DEVINSPECT_FUZZ_ONLY")) |v| std.mem.span(v) else null;
    const trace = std.c.getenv("ZUI_DEVINSPECT_FUZZ_TRACE") != null;
    var case_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer case_arena.deinit();
    for (all, stats) |*n, *s| {
        if (only) |o| {
            const full = try std.fmt.allocPrint(arena, "{s}::{s}", .{ n.module, n.name });
            if (!std.mem.eql(u8, full, o)) continue;
        }
        for (0..iters) |iter| {
            if (trace) std.debug.print("devinspect fuzz: {x}::{s}::{s} seed {d} iter {d}\n", .{ std.mem.readInt(u16, n.pkg[30..32], .big), n.module, n.name, seed, iter });
            _ = case_arena.reset(.{ .retain_with_limit = 64 << 20 });
            const t0 = std.Io.Timestamp.now(io, .awake);
            const v = try runCase(f, all, n, seed, iter, case_arena.allocator());
            const ns: u64 = @intCast(t0.durationTo(std.Io.Timestamp.now(io, .awake)).nanoseconds);
            s.cases += 1;
            switch (v) {
                .success => s.success += 1,
                .failed_in_execution => s.failed_in_execution += 1,
                .failed_before => s.failed_before += 1,
                .unsupported => s.unsupported += 1,
            }
            s.max_ns = @max(s.max_ns, ns);
            s.max_arena = @max(s.max_arena, case_arena.queryCapacity());
        }
    }
    return all;
}

/// One case may take this long and allocate this much (a Debug build under load included):
/// far above what the gas budget lets a native do, far below a runaway.
const max_case_ns: u64 = 60 * std.time.ns_per_s;
const max_case_arena: usize = 2 << 30;

/// The fixtures a pass runs over: mainnet's system packages and, when the corpus has them, the
/// next protocol version's (the natives 141 does not declare: `object::is_shared_input_impl`,
/// `clock::native_borrow`).
const Packages = enum { current, next };

fn pass(which: Which, packages_of: Packages, default_iters: u64, env_iters: [*:0]const u8, min_functions: usize) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    switch (packages_of) {
        .current => try f.init(arena, std.testing.io),
        .next => try f.initNext(arena, std.testing.io),
    }
    defer f.deinit();
    try populate(&f);
    const seed = envInt("ZUI_DEVINSPECT_FUZZ_SEED", 1);
    const iters = envInt(env_iters, default_iters);
    var stats: []Stats = &.{};
    const report = std.c.getenv("ZUI_DEVINSPECT_FUZZ_REPORT") != null;
    if (report) reasons = .empty;
    const all = try run(&f, arena, std.testing.io, which, seed, iters, &stats);
    try std.testing.expect(all.len >= min_functions);
    try summarize(f.pv, @tagName(which), all, stats, seed, iters > default_iters);
    if (reasons) |*m| {
        for (m.keys(), m.values()) |why, n| std.debug.print("devinspect fuzz: unsupported {d} times: {s}\n", .{ n, why });
        for (m.keys()) |k| std.heap.page_allocator.free(k);
        m.deinit(std.heap.page_allocator);
        reasons = null;
    }
}

test "DevInspect<true> natives fuzz: every native of the system packages, adversarial arguments and type arguments" {
    try pass(.natives, .current, 6, "ZUI_DEVINSPECT_FUZZ_ITERS", 100);
}

test "DevInspect<true> natives fuzz: every native of the next protocol version's system packages" {
    try pass(.natives, .next, 6, "ZUI_DEVINSPECT_FUZZ_ITERS", 100);
}

// The same over every function of the system packages: the Move functions (private and friend
// ones included) that call the natives with values and type arguments of the caller's choice,
// and the interpreter on values no Move code could have built (an Option of two elements, a
// VecMap with a key twice, a UID nobody created).
test "DevInspect<true> fuzz: every function of the system packages, adversarial arguments and type arguments" {
    try pass(.functions, .current, 1, "ZUI_DEVINSPECT_FUZZ_ALL_ITERS", 1000);
}

test "DevInspect<true> fuzz: every function of the next protocol version's system packages" {
    try pass(.functions, .next, 1, "ZUI_DEVINSPECT_FUZZ_ALL_ITERS", 1000);
}

fn summarize(pv: u64, what: []const u8, all: []const Native, stats: []const Stats, seed: u64, print_total: bool) !void {
    var total: Stats = .{};
    var never_ran: usize = 0;
    const report = std.c.getenv("ZUI_DEVINSPECT_FUZZ_REPORT") != null;
    for (all, stats) |n, s| {
        if (s.cases == 0) continue;
        total.cases += s.cases;
        total.success += s.success;
        total.failed_in_execution += s.failed_in_execution;
        total.failed_before += s.failed_before;
        total.unsupported += s.unsupported;
        total.max_ns = @max(total.max_ns, s.max_ns);
        total.max_arena = @max(total.max_arena, s.max_arena);
        if (s.success + s.failed_in_execution == 0) never_ran += 1;
        if (report) std.debug.print("devinspect fuzz: {x}::{s}::{s}: {d} cases, {d} success, {d} failed in execution, {d} failed before, {d} unsupported, slowest {d} ms\n", .{ std.mem.readInt(u16, n.pkg[30..32], .big), n.module, n.name, s.cases, s.success, s.failed_in_execution, s.failed_before, s.unsupported, s.max_ns / std.time.ns_per_ms });
        try std.testing.expect(s.max_ns < max_case_ns);
        try std.testing.expect(s.max_arena < max_case_arena);
    }
    if (report or print_total) std.debug.print("devinspect fuzz: protocol {d}, seed {d}, {d} {s}, {d} cases: {d} success, {d} failed in execution, {d} failed before execution, {d} unsupported; {d} never executed; slowest case {d} ms, largest case arena {d} MiB\n", .{ pv, seed, all.len, what, total.cases, total.success, total.failed_in_execution, total.failed_before, total.unsupported, never_ran, total.max_ns / std.time.ns_per_ms, total.max_arena >> 20 });
}

// The executor's native table against what the fixture's packages declare: a table entry no
// package declares cannot be reached through a PTB at this protocol version.
test "DevInspect<true> natives fuzz: the native table entries the system packages do not declare" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    f.initNext(arena, std.testing.io) catch |e| switch (e) {
        error.SkipZigTest => try f.init(arena, std.testing.io),
        else => return e,
    };
    defer f.deinit();
    const all = try enumerate(arena, &f);
    var undeclared: usize = 0;
    for (natives.table.entries) |e| {
        const declared = for (all) |n| {
            if (std.mem.readInt(u16, n.pkg[30..32], .big) == e.addr and std.mem.eql(u8, n.module, e.module) and std.mem.eql(u8, n.name, e.func)) break true;
        } else false;
        if (declared) continue;
        undeclared += 1;
        if (std.c.getenv("ZUI_DEVINSPECT_FUZZ_REPORT") != null) std.debug.print("devinspect fuzz: table entry not declared at protocol {d}: {x}::{s}::{s} (since {d})\n", .{ f.pv, e.addr, e.module, e.func, e.since });
    }
    try std.testing.expect(undeclared < natives.table.entries.len);
}
