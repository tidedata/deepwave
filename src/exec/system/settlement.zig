//! Accumulator settlement: `ProgrammableSystemTransaction` (sui-adapter
//! `accumulator_settlement.rs`, execution version 4). Rust runs these calls natively, not in the
//! Move VM, so deepwave does too:
//!   settlement_prologue(root, epoch, height, offset, input_sui, output_sui)
//!   settle_u128<T>(root, owner, merge, split)          Field<Key<T>, U128> under 0xacc
//!   settle_events(root, stream, new_root, count, checkpoint)  Field<Key<EventStreamHead>, EventStreamHead>
//!   record_accumulator_object_changes(root, created, destroyed)  Field<AccumulatorObjectCountKey, u64>
//! The root (0xacc) is always written; a child is written when its data or owner changed,
//! created when it did not exist, deleted when a balance reaches zero. Every `assert_invariant`
//! and `invariant_violation` of the Rust module is reported unsupported (Rust would fail the
//! transaction with an invariant violation; no corpus settlement does).
const std = @import("std");
const types = @import("types");
const hash = @import("hash");
const store_mod = @import("store.zig");
const objects = @import("../objects.zig");
const sys = @import("root.zig");

const Allocator = std.mem.Allocator;
const ObjectView = objects.ObjectView;
const Store = store_mod.Store;

pub const root_id: [32]u8 = addr(0xacc);
const framework: [32]u8 = addr(2);

fn addr(comptime n: u16) [32]u8 {
    var a: [32]u8 = @splat(0);
    std.mem.writeInt(u16, a[30..32], n, .big);
    return a;
}

const Child = struct {
    id: [32]u8,
    original: ?ObjectView,
    /// Current state: null = absent; else (header, contents) of the Move object.
    current: ?struct { header: []const u8, contents: []const u8 },
};

const Fail = error{ Invariant, OutOfMemory, NotAvailable };

const Ctx = struct {
    a: Allocator,
    src: sys.Source,
    root: ObjectView,
    root_arg: u16,
    inputs: []const types.CallArg,
    children: std.AutoArrayHashMapUnmanaged([32]u8, Child) = .empty,
    input_sui: u64 = 0,
    output_sui: u64 = 0,
    why: []const u8 = "",

    fn invariant(c: *Ctx, why: []const u8) Fail {
        c.why = why;
        return error.Invariant;
    }

    fn pure(c: *Ctx, arg: types.Argument, comptime n: usize) Fail!*const [n]u8 {
        const i = switch (arg) {
            .Input => |i| i,
            else => return c.invariant("settlement argument is not an input"),
        };
        if (i >= c.inputs.len) return c.invariant("settlement input index out of bounds");
        const bytes = switch (c.inputs[i]) {
            .Pure => |b| b,
            else => return c.invariant("settlement expected a pure argument"),
        };
        if (bytes.len != n) return c.invariant("invalid settlement argument");
        return bytes[0..n];
    }

    fn u64Arg(c: *Ctx, arg: types.Argument) Fail!u64 {
        return std.mem.readInt(u64, try c.pure(arg, 8), .little);
    }

    fn checkRoot(c: *Ctx, arg: types.Argument) Fail!void {
        switch (arg) {
            .Input => |i| if (i == c.root_arg) return,
            else => {},
        }
        return c.invariant("settlement call has an incorrect root argument");
    }

    /// `read_dynamic_field`: the child for `key` (loaded once), checked to be a
    /// `Field<key_type, value_type>` owned by the root. Returns its id and value bytes.
    fn read(c: *Ctx, key: []const u8, key_type: []const u8, field_type: []const u8) Fail!struct { id: [32]u8, value: ?[]const u8 } {
        var len_le: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_le, key.len, .little);
        const id = hash.blake2b256(&.{ &[_]u8{0xf0}, &root_id, &len_le, key, key_type });
        const gop = try c.children.getOrPut(c.a, id);
        if (!gop.found_existing) {
            const raw = try c.src.child(c.src.ctx, &root_id, &id, c.root.version);
            const original: ?ObjectView = if (raw) |r| ObjectView.parse(r) catch return c.invariant("settlement field does not parse") else null;
            gop.value_ptr.* = .{
                .id = id,
                .original = original,
                .current = if (original) |o| .{ .header = o.raw[0..o.version_at], .contents = o.contents() } else null,
            };
        }
        const ch = gop.value_ptr;
        const cur = ch.current orelse return .{ .id = id, .value = null };
        if (ch.original) |o| {
            if (!std.mem.eql(u8, &o.id, &id)) return c.invariant("invalid settlement field id");
            const owner = o.ownerBytes();
            if (owner.len != 33 or owner[0] != 1 or !std.mem.eql(u8, owner[1..33], &root_id)) return c.invariant("invalid settlement field owner");
        }
        if (!std.mem.eql(u8, cur.header, field_type)) return c.invariant("settlement field has an unexpected type");
        const prefix = 32 + key.len;
        if (cur.contents.len < prefix or !std.mem.eql(u8, cur.contents[32..prefix], key)) return c.invariant("cannot deserialize settlement field");
        return .{ .id = id, .value = cur.contents[prefix..] };
    }

    /// `write_dynamic_field`: `Field { id, name: key, value }` as the child's new state.
    fn write(c: *Ctx, id: [32]u8, key: []const u8, field_type: []const u8, value: []const u8) Fail!void {
        const ch = c.children.getPtr(id) orelse return c.invariant("settlement field was not loaded");
        const contents = try c.a.alloc(u8, 32 + key.len + value.len);
        @memcpy(contents[0..32], &id);
        @memcpy(contents[32..][0..key.len], key);
        @memcpy(contents[32 + key.len ..], value);
        ch.current = .{ .header = field_type, .contents = contents };
    }

    fn remove(c: *Ctx, id: [32]u8) Fail!void {
        const ch = c.children.getPtr(id) orelse return c.invariant("settlement field was not loaded");
        ch.current = null;
    }
};

// ---------------------------------------------------------------------------------------------
// Type tags (BCS) and MoveObjectType headers

fn appendStr(a: Allocator, buf: *std.ArrayList(u8), s: []const u8) !void {
    try buf.append(a, @intCast(s.len)); // identifiers here are < 128 bytes
    try buf.appendSlice(a, s);
}

/// BCS `StructTag` body (address, module, name, type args already encoded).
fn structTag(a: Allocator, address: *const [32]u8, module: []const u8, name: []const u8, args: []const []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    try buf.appendSlice(a, address);
    try appendStr(a, &buf, module);
    try appendStr(a, &buf, name);
    try buf.append(a, @intCast(args.len));
    for (args) |t| try buf.appendSlice(a, t);
    return buf.items;
}

/// BCS `TypeTag::Struct`.
fn structType(a: Allocator, address: *const [32]u8, module: []const u8, name: []const u8, args: []const []const u8) ![]u8 {
    const body = try structTag(a, address, module, name, args);
    const out = try a.alloc(u8, body.len + 1);
    out[0] = 7;
    @memcpy(out[1..], body);
    return out;
}

/// `Data::Move` header of a `Field<key_type, value_type>` object (has_public_transfer false):
/// MoveObjectType from the StructTag (`From<StructTag> for MoveObjectType`): a
/// `Field<Key<Balance<T>>, U128>` is SuiBalanceAccumulatorField or BalanceAccumulatorField(T),
/// anything else Other(StructTag).
fn fieldHeader(a: Allocator, key_type: []const u8, value_type: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    try buf.append(a, 0); // Data::Move
    if (balanceParam(key_type, value_type)) |t| {
        if (std.mem.eql(u8, t, sui_type)) {
            try buf.append(a, 4);
        } else {
            try buf.append(a, 5);
            try buf.appendSlice(a, t);
        }
    } else {
        try buf.append(a, 0);
        try buf.appendSlice(a, try structTag(a, &framework, "dynamic_field", "Field", &.{ key_type, value_type }));
    }
    try buf.append(a, 0); // has_public_transfer
    return buf.items;
}

const sui_type: []const u8 = blk: {
    const head = [_]u8{7} ++ addr(2) ++ [_]u8{3} ++ "sui".* ++ [_]u8{3} ++ "SUI".* ++ [_]u8{0};
    break :blk &head;
};
const u128_type: []const u8 = blk: {
    const head = [_]u8{7} ++ addr(2) ++ [_]u8{11} ++ "accumulator".* ++ [_]u8{4} ++ "U128".* ++ [_]u8{0};
    break :blk &head;
};
const event_head_type: []const u8 = blk: {
    const head = [_]u8{7} ++ addr(2) ++ [_]u8{22} ++ "accumulator_settlement".* ++ [_]u8{15} ++ "EventStreamHead".* ++ [_]u8{0};
    break :blk &head;
};
const count_key_type: []const u8 = blk: {
    const head = [_]u8{7} ++ addr(2) ++ [_]u8{20} ++ "accumulator_metadata".* ++ [_]u8{25} ++ "AccumulatorObjectCountKey".* ++ [_]u8{0};
    break :blk &head;
};
const u64_type: []const u8 = &[_]u8{2};

/// `Key<T>` prefix: TypeTag::Struct(0x2::accumulator::Key<..1 arg..>).
const key_prefix: []const u8 = blk: {
    const head = [_]u8{7} ++ addr(2) ++ [_]u8{11} ++ "accumulator".* ++ [_]u8{3} ++ "Key".* ++ [_]u8{1};
    break :blk &head;
};
const balance_prefix: []const u8 = blk: {
    const head = [_]u8{7} ++ addr(2) ++ [_]u8{7} ++ "balance".* ++ [_]u8{7} ++ "Balance".* ++ [_]u8{1};
    break :blk &head;
};

/// T when key_type is Key<Balance<T>> and value_type is U128.
fn balanceParam(key_type: []const u8, value_type: []const u8) ?[]const u8 {
    if (!std.mem.eql(u8, value_type, u128_type)) return null;
    if (!std.mem.startsWith(u8, key_type, key_prefix)) return null;
    const inner = key_type[key_prefix.len..];
    if (!std.mem.startsWith(u8, inner, balance_prefix)) return null;
    return inner[balance_prefix.len..];
}

fn keyType(a: Allocator, inner: []const u8) ![]u8 {
    const out = try a.alloc(u8, key_prefix.len + inner.len);
    @memcpy(out[0..key_prefix.len], key_prefix);
    @memcpy(out[key_prefix.len..], inner);
    return out;
}

/// TypeInput BCS equals TypeTag BCS (same variant order; strings and identifiers share their
/// encoding). Rust's `to_type_tag` also checks identifiers; system transactions come from
/// validators, so an invalid one is reported unsupported rather than modeled.
fn typeInputBytes(a: Allocator, t: *const types.TypeInput) ![]u8 {
    if (!validTypeInput(t)) return error.InvalidTypeInput;
    return @import("bcs").encodeAlloc(types.TypeInput, a, t);
}

fn validTypeInput(t: *const types.TypeInput) bool {
    return switch (t.*) {
        .vector => |e| validTypeInput(e),
        .@"struct" => |*st| blk: {
            if (!types.hand.Identifier.isValid(st.module.@"0") or !types.hand.Identifier.isValid(st.name.@"0")) break :blk false;
            for (st.type_args) |*x| if (!validTypeInput(x)) break :blk false;
            break :blk true;
        },
        else => true,
    };
}

// ---------------------------------------------------------------------------------------------
// Commands

fn settleU128(c: *Ctx, ty: []const u8, owner: *const [32]u8, merge: u128, split: u128) Fail!void {
    const key_type = try keyType(c.a, ty);
    const header = try fieldHeader(c.a, key_type, u128_type);
    const f = try c.read(owner, key_type, header);
    if (f.value) |v| if (v.len != 16) return c.invariant("cannot deserialize settlement field");
    if (f.value == null and split != 0) return c.invariant("cannot withdraw from a missing accumulator");
    const previous: u128 = if (f.value) |v| std.mem.readInt(u128, v[0..16], .little) else 0;
    const value: u128 = if (merge == 0 and split == 0)
        return c.invariant("settlement must merge or split a nonzero amount")
    else if (split == 0)
        std.math.add(u128, previous, merge) catch return c.invariant("settlement balance overflow or underflow")
    else if (merge == 0)
        std.math.sub(u128, previous, split) catch return c.invariant("settlement balance overflow or underflow")
    else
        return c.invariant("settlement cannot both merge and split");
    if (value == 0) return c.remove(f.id);
    var vb: [16]u8 = undefined;
    std.mem.writeInt(u128, &vb, value, .little);
    try c.write(f.id, owner, header, &vb);
}

fn settleEvents(c: *Ctx, stream: *const [32]u8, new_root: *const [32]u8, count: u64, checkpoint: u64) Fail!void {
    const key_type = try keyType(c.a, event_head_type);
    const header = try fieldHeader(c.a, key_type, event_head_type);
    const f = try c.read(stream, key_type, header);
    // EventStreamHead { mmr: vector<u256>, checkpoint_seq: u64, num_events: u64 }
    var mmr: std.ArrayList([32]u8) = .empty;
    var num_events: u64 = 0;
    if (f.value) |v| {
        var r = @import("bcs").Reader.init(v);
        const n = r.length() catch return c.invariant("cannot deserialize settlement field");
        for (0..n) |_| try mmr.append(c.a, (r.bytes(32) catch return c.invariant("cannot deserialize settlement field"))[0..32].*);
        _ = r.int(u64) catch return c.invariant("cannot deserialize settlement field");
        num_events = r.int(u64) catch return c.invariant("cannot deserialize settlement field");
        r.finish() catch return c.invariant("cannot deserialize settlement field");
    }
    // add_to_mmr
    var current = new_root.*;
    const zero: [32]u8 = @splat(0);
    const pushed = for (mmr.items) |*peak| {
        if (std.mem.eql(u8, peak, &zero)) {
            peak.* = current;
            break false;
        }
        current = hash.blake2b256(&.{ peak, &current });
        peak.* = zero;
    } else true;
    if (pushed) try mmr.append(c.a, current);
    num_events = std.math.add(u64, num_events, count) catch return c.invariant("settlement event count overflow");
    var buf: std.ArrayList(u8) = .empty;
    var n = mmr.items.len;
    while (true) {
        const b: u8 = @intCast(n & 0x7f);
        n >>= 7;
        if (n == 0) {
            try buf.append(c.a, b);
            break;
        }
        try buf.append(c.a, b | 0x80);
    }
    for (mmr.items) |*p| try buf.appendSlice(c.a, p);
    var v8: [8]u8 = undefined;
    std.mem.writeInt(u64, &v8, checkpoint, .little);
    try buf.appendSlice(c.a, &v8);
    std.mem.writeInt(u64, &v8, num_events, .little);
    try buf.appendSlice(c.a, &v8);
    try c.write(f.id, stream, header, buf.items);
}

fn recordObjectChanges(c: *Ctx, created: u64, destroyed: u64) Fail!void {
    const header = try fieldHeader(c.a, count_key_type, u64_type);
    const key = [_]u8{0};
    const f = try c.read(&key, count_key_type, header);
    if (f.value) |v| if (v.len != 8) return c.invariant("cannot deserialize settlement field");
    const previous: u64 = if (f.value) |v| std.mem.readInt(u64, v[0..8], .little) else 0;
    const up = std.math.add(u64, previous, created) catch return c.invariant("settlement object count overflow or underflow");
    const count = std.math.sub(u64, up, destroyed) catch return c.invariant("settlement object count overflow or underflow");
    var vb: [8]u8 = undefined;
    std.mem.writeInt(u64, &vb, count, .little);
    try c.write(f.id, &key, header, &vb);
}

fn command(c: *Ctx, index: usize, last: usize, cmd: *const types.Command) Fail!void {
    const call = switch (cmd.*) {
        .MoveCall => |*m| m,
        else => return c.invariant("settlement commands must be Move calls"),
    };
    if (!std.mem.eql(u8, &call.package.@"0".@"0", &framework)) return c.invariant("unexpected settlement package");
    const module = call.module.@"0";
    const func = call.function.@"0";
    const args = call.arguments;
    const eq = std.mem.eql;
    if (eq(u8, module, "accumulator_settlement") and eq(u8, func, "settlement_prologue")) {
        if (index != 0) return c.invariant("settlement prologue must be the first command");
        if (call.type_arguments.len != 0) return c.invariant("settlement prologue expects no type arguments");
        if (args.len != 6) return c.invariant("settlement prologue expects six arguments");
        try c.checkRoot(args[0]);
        _ = try c.u64Arg(args[1]);
        _ = try c.u64Arg(args[2]);
        _ = try c.u64Arg(args[3]);
        c.input_sui = try c.u64Arg(args[4]);
        c.output_sui = try c.u64Arg(args[5]);
    } else if (eq(u8, module, "accumulator_settlement") and eq(u8, func, "settle_u128")) {
        if (index == 0) return c.invariant("balance settlement must follow the prologue");
        if (call.type_arguments.len != 1) return c.invariant("balance settlement expects one type argument");
        if (args.len != 4) return c.invariant("balance settlement expects four arguments");
        const ty = typeInputBytes(c.a, &call.type_arguments[0]) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return c.invariant("invalid settlement type"),
        };
        try c.checkRoot(args[0]);
        const owner = try c.pure(args[1], 32);
        const merge = std.mem.readInt(u128, try c.pure(args[2], 16), .little);
        const split = std.mem.readInt(u128, try c.pure(args[3], 16), .little);
        try settleU128(c, ty, owner, merge, split);
    } else if (eq(u8, module, "accumulator_settlement") and eq(u8, func, "settle_events")) {
        if (index == 0) return c.invariant("event settlement must follow the prologue");
        if (call.type_arguments.len != 0) return c.invariant("event settlement expects no type arguments");
        if (args.len != 5) return c.invariant("event settlement expects five arguments");
        try c.checkRoot(args[0]);
        const stream = try c.pure(args[1], 32);
        const new_root = try c.pure(args[2], 32);
        const count = try c.u64Arg(args[3]);
        const checkpoint = try c.u64Arg(args[4]);
        try settleEvents(c, stream, new_root, count, checkpoint);
    } else if (eq(u8, module, "accumulator_metadata") and eq(u8, func, "record_accumulator_object_changes")) {
        if (index == 0) return c.invariant("object-count update must follow the prologue");
        if (index != last) return c.invariant("object-count update must be the last command");
        if (call.type_arguments.len != 0) return c.invariant("object-count update expects no type arguments");
        if (args.len != 3) return c.invariant("object-count update expects three arguments");
        try c.checkRoot(args[0]);
        const created = try c.u64Arg(args[1]);
        const destroyed = try c.u64Arg(args[2]);
        try recordObjectChanges(c, created, destroyed);
    } else return c.invariant("unexpected settlement call");
}

pub fn execute(arena: Allocator, s: *Store, sender: *const [32]u8, pt: *const types.ProgrammableTransaction, src: sys.Source) !sys.Outcome {
    const a = arena;
    if (!std.mem.eql(u8, sender, &@as([32]u8, @splat(0)))) return .{ .unsupported = "settlement sender is not the system address" };
    // Context::new: Pure inputs and exactly one mutable shared 0xacc.
    var root_arg: ?u16 = null;
    for (pt.inputs, 0..) |*in, i| switch (in.*) {
        .Pure => {},
        .Object => |*oa| switch (oa.*) {
            .SharedObject => |sh| {
                if (sh.mutability == .Immutable) return .{ .unsupported = "unexpected settlement input" };
                if (!std.mem.eql(u8, &sh.id.@"0".@"0", &root_id)) return .{ .unsupported = "settlement shared input is not the accumulator root" };
                if (root_arg != null) return .{ .unsupported = "settlement with two accumulator root inputs" };
                root_arg = @intCast(i);
            },
            else => return .{ .unsupported = "unexpected settlement input" },
        },
        else => return .{ .unsupported = "unexpected settlement input" },
    };
    const ra = root_arg orelse return .{ .unsupported = "settlement without an accumulator root input" };
    const root = s.input(&root_id) orelse return .{ .unsupported = "accumulator root not among the inputs" };
    if (pt.commands.len == 0) return .{ .unsupported = "settlement must contain a prologue" };
    var c: Ctx = .{ .a = a, .src = src, .root = root.*, .root_arg = ra, .inputs = pt.inputs };
    for (pt.commands, 0..) |*cmd, i| command(&c, i, pt.commands.len - 1, cmd) catch |e| switch (e) {
        error.Invariant => return .{ .unsupported = try std.fmt.allocPrint(a, "settlement invariant violation: {s}", .{c.why}) },
        error.NotAvailable => return .{ .unsupported = "settlement child object not available" },
        error.OutOfMemory => return error.OutOfMemory,
    };
    // Context::finish and save_loaded_runtime_objects.
    try s.write(Store.inputAsWrite(root), .modified);
    const owner_bytes = blk: {
        var o: [33]u8 = undefined;
        o[0] = 1;
        @memcpy(o[1..], &root_id);
        break :blk try a.dupe(u8, &o);
    };
    for (c.children.values()) |*ch| {
        if (ch.original) |*o| try s.loadedChild(o.raw);
        if (ch.original) |*o| {
            if (ch.current) |cur| {
                // Unchanged values produce no write (data and owner equal; the owner never changes here).
                if (std.mem.eql(u8, cur.header, o.raw[0..o.version_at]) and std.mem.eql(u8, cur.contents, o.contents())) continue;
                try s.write(.{ .id = ch.id, .header = cur.header, .contents = cur.contents, .owner = owner_bytes }, .modified);
            } else try s.delete(ch.id);
        } else if (ch.current) |cur| {
            try s.write(.{ .id = ch.id, .header = cur.header, .contents = cur.contents, .owner = owner_bytes }, .created);
        }
    }
    return .{ .done = s.intoEffects(null) catch |e| switch (e) {
        error.Unsupported => return .{ .unsupported = s.why },
        error.InvariantViolation => return .{ .unsupported = "settlement effects invariant violation" },
        error.OutOfMemory => return error.OutOfMemory,
    } };
}

// ---------------------------------------------------------------------------------------------
// Edge cases the corpus lacks, each as `accumulator_settlement.rs` (mainnet-v1.83.1) decides it.

const testing = std.testing;
const bcs_mod = @import("bcs");
const protocol = @import("protocol");

const TestKid = struct { id: [32]u8, raw: []const u8 };

const TestSrc = struct {
    root: []const u8,
    kids: []const TestKid,

    fn input(p: *const anyopaque, id: *const [32]u8, _: u64) ?[]const u8 {
        const s: *const TestSrc = @ptrCast(@alignCast(p));
        return if (std.mem.eql(u8, id, &root_id)) s.root else null;
    }
    fn child(p: *const anyopaque, _: *const [32]u8, id: *const [32]u8, _: u64) error{NotAvailable}!?[]const u8 {
        const s: *const TestSrc = @ptrCast(@alignCast(p));
        for (s.kids) |k| if (std.mem.eql(u8, &k.id, id)) return k.raw;
        return null;
    }
    fn package(_: *const anyopaque, _: *const [32]u8) ?[]const u8 {
        return null;
    }
    fn source(s: *const TestSrc) sys.Source {
        return .{ .ctx = s, .input = input, .child = child, .package = package };
    }
};

const test_digest: [32]u8 = @splat(0xd1);
const test_root_version: u64 = 40;
const root_owner = [_]u8{2} ++ [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 }; // Shared { initial_shared_version: 1 }
const child_owner = [_]u8{1} ++ root_id; // ObjectOwner(0xacc)

fn testRoot(a: Allocator) ![]const u8 {
    var header: std.ArrayList(u8) = .empty;
    try header.appendSlice(a, &.{ 0, 0 }); // Data::Move, MoveObjectType::Other
    try header.appendSlice(a, try structTag(a, &framework, "accumulator", "AccumulatorRoot", &.{}));
    try header.append(a, 0);
    return store_mod.objectBytes(a, &.{ .id = root_id, .header = header.items, .contents = &root_id, .owner = &root_owner }, test_root_version, &@as([32]u8, @splat(0x77)));
}

/// `Balance<SUI>` as the settle_u128 type argument, and its key type `Key<Balance<SUI>>`.
fn balanceSui(a: Allocator) !struct { input: types.TypeInput, key_type: []const u8 } {
    const sui_in = try a.create(types.TypeInput);
    sui_in.* = .{ .@"struct" = .{ .address = .{ .@"0" = framework }, .module = .{ .@"0" = "sui" }, .name = .{ .@"0" = "SUI" }, .type_args = &.{} } };
    const args = try a.alloc(types.TypeInput, 1);
    args[0] = sui_in.*;
    const bal: types.TypeInput = .{ .@"struct" = .{ .address = .{ .@"0" = framework }, .module = .{ .@"0" = "balance" }, .name = .{ .@"0" = "Balance" }, .type_args = args } };
    return .{ .input = bal, .key_type = try keyType(a, try typeInputBytes(a, &bal)) };
}

/// `derive_dynamic_field_id(0xacc, key_type, key)`.
fn fieldId(key: []const u8, key_type: []const u8) [32]u8 {
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, key.len, .little);
    return hash.blake2b256(&.{ &[_]u8{0xf0}, &root_id, &len_le, key, key_type });
}

fn balanceField(a: Allocator, owner: [32]u8, key_type: []const u8, value: u128, rebate: u64) !TestKid {
    const id = fieldId(&owner, key_type);
    var contents: [80]u8 = undefined;
    @memcpy(contents[0..32], &id);
    @memcpy(contents[32..64], &owner);
    std.mem.writeInt(u128, contents[64..80], value, .little);
    const header = try fieldHeader(a, key_type, u128_type);
    const raw = try store_mod.objectBytes(a, &.{ .id = id, .header = header, .contents = try a.dupe(u8, &contents), .owner = &child_owner, .rebate = rebate }, 12, &@as([32]u8, @splat(0x55)));
    return .{ .id = id, .raw = raw };
}

const PtBuilder = struct {
    a: Allocator,
    inputs: std.ArrayList(types.CallArg) = .empty,
    commands: std.ArrayList(types.Command) = .empty,

    fn root(b: *PtBuilder, mutability: types.SharedObjectMutability) !types.Argument {
        try b.inputs.append(b.a, .{ .Object = .{ .SharedObject = .{ .id = .{ .@"0" = .{ .@"0" = root_id } }, .initial_shared_version = .{ .@"0" = 1 }, .mutability = mutability } } });
        return .{ .Input = @intCast(b.inputs.items.len - 1) };
    }
    fn pure(b: *PtBuilder, comptime T: type, v: T) !types.Argument {
        try b.inputs.append(b.a, .{ .Pure = try bcs_mod.encodeAlloc(T, b.a, &v) });
        return .{ .Input = @intCast(b.inputs.items.len - 1) };
    }
    fn call(b: *PtBuilder, module: []const u8, function: []const u8, ty: []const types.TypeInput, args: []const types.Argument) !void {
        const mc: types.ProgrammableMoveCall = .{ .package = .{ .@"0" = .{ .@"0" = framework } }, .module = .{ .@"0" = module }, .function = .{ .@"0" = function }, .type_arguments = try b.a.dupe(types.TypeInput, ty), .arguments = try b.a.dupe(types.Argument, args) };
        try b.commands.append(b.a, .{ .MoveCall = mc });
    }
    fn prologue(b: *PtBuilder, r: types.Argument) !void {
        try b.call("accumulator_settlement", "settlement_prologue", &.{}, &.{ r, try b.pure(u64, 5), try b.pure(u64, 9), try b.pure(u64, 0), try b.pure(u64, 0), try b.pure(u64, 0) });
    }
    fn settle(b: *PtBuilder, r: types.Argument, ty: types.TypeInput, owner: [32]u8, merge: u128, split: u128) !void {
        try b.call("accumulator_settlement", "settle_u128", &.{ty}, &.{ r, try b.pure([32]u8, owner), try b.pure(u128, merge), try b.pure(u128, split) });
    }
    fn events(b: *PtBuilder, r: types.Argument, stream: [32]u8, new_root: [32]u8, n: u64, checkpoint: u64) !void {
        try b.call("accumulator_settlement", "settle_events", &.{}, &.{ r, try b.pure([32]u8, stream), try b.pure([32]u8, new_root), try b.pure(u64, n), try b.pure(u64, checkpoint) });
    }
    fn count(b: *PtBuilder, r: types.Argument, created: u64, destroyed: u64) !void {
        try b.call("accumulator_metadata", "record_accumulator_object_changes", &.{}, &.{ r, try b.pure(u64, created), try b.pure(u64, destroyed) });
    }
    fn pt(b: *const PtBuilder) types.ProgrammableTransaction {
        return .{ .inputs = b.inputs.items, .commands = b.commands.items };
    }
};

fn runPt(a: Allocator, src: *const TestSrc, access: store_mod.Access, pt: *const types.ProgrammableTransaction) !sys.Outcome {
    var s = Store.init(a, try protocol.get(protocol.max_protocol_version, .mainnet), 5, test_digest);
    try s.addInput(src.root, access);
    return execute(a, &s, &@as([32]u8, @splat(0)), pt, src.source());
}

fn effectsOf(a: Allocator, out: *const store_mod.Output) !types.TransactionEffectsV2 {
    return (try bcs_mod.decode(types.TransactionEffects, a, out.effects)).V2;
}

fn changeOf(fx: *const types.TransactionEffectsV2, id: *const [32]u8) ?@typeInfo(@FieldType(types.TransactionEffectsV2, "changed_objects")).pointer.child {
    for (fx.changed_objects) |c| if (std.mem.eql(u8, &c[0].@"0".@"0", id)) return c;
    return null;
}

fn expectUnsupported(o: sys.Outcome, want: []const u8) !void {
    try testing.expect(o == .unsupported);
    try testing.expect(std.mem.indexOf(u8, o.unsupported, want) != null);
}

test "settlement: merge into a missing balance creates the field at the lamport version" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bal = try balanceSui(a);
    const src: TestSrc = .{ .root = try testRoot(a), .kids = &.{} };
    const owner: [32]u8 = @splat(0xab);
    var b: PtBuilder = .{ .a = a };
    const r = try b.root(.Mutable);
    try b.prologue(r);
    try b.settle(r, bal.input, owner, 1_000, 0);
    const out = (try runPt(a, &src, .mutable, &b.pt())).done;
    const want = try balanceField(a, owner, bal.key_type, 1_000, 0);
    const fx = try effectsOf(a, &out);
    try testing.expectEqual(test_root_version + 1, fx.lamport_version.@"0");
    const c = changeOf(&fx, &want.id).?;
    try testing.expect(c[1].id_operation == .Created and c[1].input_state == .NotExist);
    try testing.expect(changeOf(&fx, &root_id).?[1].id_operation == .None);
    // The new field: SuiBalanceAccumulatorField, version = lamport, prev tx = this tx, rebate 0.
    for (out.written) |w| if (std.mem.eql(u8, &w.id, &want.id)) {
        const v = try ObjectView.parse(w.bytes);
        try testing.expectEqual(test_root_version + 1, v.version);
        try testing.expectEqualSlices(u8, &.{ 0, 4, 0 }, w.bytes[0..v.version_at]);
        try testing.expectEqualSlices(u8, (try ObjectView.parse(want.raw)).contents(), v.contents());
        try testing.expectEqualSlices(u8, &child_owner, v.ownerBytes());
        try testing.expectEqualSlices(u8, &test_digest, w.bytes[v.prev_tx_at + 1 ..][0..32]);
        try testing.expectEqual(@as(u64, 0), v.storageRebate());
    };
    try testing.expectEqual(@as(usize, 2), out.written.len);
}

test "settlement: merge then split to zero in one transaction leaves no trace of the field" {
    // (None, None) in Context::finish: neither written, created, deleted nor loaded.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bal = try balanceSui(a);
    const src: TestSrc = .{ .root = try testRoot(a), .kids = &.{} };
    var b: PtBuilder = .{ .a = a };
    const r = try b.root(.Mutable);
    try b.prologue(r);
    try b.settle(r, bal.input, @splat(1), 7, 0);
    try b.settle(r, bal.input, @splat(1), 0, 7);
    const out = (try runPt(a, &src, .mutable, &b.pt())).done;
    const fx = try effectsOf(a, &out);
    try testing.expectEqual(@as(usize, 1), fx.changed_objects.len);
    try testing.expectEqual(@as(usize, 1), out.written.len);
}

test "settlement: a split that empties an existing balance deletes it" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bal = try balanceSui(a);
    const kid = try balanceField(a, @splat(3), bal.key_type, 500, 0);
    const src: TestSrc = .{ .root = try testRoot(a), .kids = &.{kid} };
    var b: PtBuilder = .{ .a = a };
    const r = try b.root(.Mutable);
    try b.prologue(r);
    try b.settle(r, bal.input, @splat(3), 0, 500);
    const out = (try runPt(a, &src, .mutable, &b.pt())).done;
    const fx = try effectsOf(a, &out);
    const c = changeOf(&fx, &kid.id).?;
    try testing.expect(c[1].id_operation == .Deleted and c[1].output_state == .NotExist);
    try testing.expectEqual(@as(u64, 12), c[1].input_state.Exist[0][0].@"0");
}

test "settlement: deleting a field that holds a storage rebate needs 0x5 (Rust panics)" {
    // conserve_unmetered_storage_rebate reads 0x5, which a settlement does not take as input.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bal = try balanceSui(a);
    const kid = try balanceField(a, @splat(3), bal.key_type, 500, 88);
    const src: TestSrc = .{ .root = try testRoot(a), .kids = &.{kid} };
    var b: PtBuilder = .{ .a = a };
    const r = try b.root(.Mutable);
    try b.prologue(r);
    try b.settle(r, bal.input, @splat(3), 0, 500);
    try expectUnsupported(try runPt(a, &src, .mutable, &b.pt()), "0x5");
}

test "settlement: Rust invariant violations are never executed" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bal = try balanceSui(a);
    const kid = try balanceField(a, @splat(3), bal.key_type, 500, 0);
    const src: TestSrc = .{ .root = try testRoot(a), .kids = &.{kid} };
    const Case = enum { both, missing_split, underflow, zero, prologue_late, count_not_last, count_underflow, wrong_root, immutable_root, no_commands };
    inline for (@typeInfo(Case).@"enum".field_values) |fv| {
        const case: Case = @enumFromInt(fv);
        var b: PtBuilder = .{ .a = a };
        const r = try b.root(if (case == .immutable_root) .Immutable else .Mutable);
        switch (case) {
            .no_commands => {},
            .prologue_late => {
                try b.prologue(r);
                try b.prologue(r);
            },
            else => try b.prologue(r),
        }
        switch (case) {
            .both => try b.settle(r, bal.input, @splat(3), 1, 1),
            .missing_split => try b.settle(r, bal.input, @splat(4), 0, 1),
            .underflow => try b.settle(r, bal.input, @splat(3), 0, 501),
            .zero => try b.settle(r, bal.input, @splat(3), 0, 0),
            .count_not_last => {
                try b.count(r, 1, 0);
                try b.settle(r, bal.input, @splat(3), 1, 0);
            },
            .count_underflow => try b.count(r, 0, 1),
            .wrong_root => try b.settle(r, bal.input, @splat(3), 1, 0),
            else => {},
        }
        if (case == .wrong_root) {
            // Point the root argument of the settle call at a pure input.
            const mc = &b.commands.items[1].MoveCall;
            const args = try a.dupe(types.Argument, mc.arguments);
            args[0] = .{ .Input = 1 };
            mc.arguments = args;
        }
        const o = try runPt(a, &src, .mutable, &b.pt());
        try testing.expect(o == .unsupported);
    }
}

test "settlement: event stream head MMR across two settles in one transaction and the next" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const stream: [32]u8 = @splat(0x5e);
    const r1: [32]u8 = @splat(1);
    const r2: [32]u8 = @splat(2);
    const r3: [32]u8 = @splat(3);
    const key_type = try keyType(a, event_head_type);
    const id = fieldId(&stream, key_type);
    const src: TestSrc = .{ .root = try testRoot(a), .kids = &.{} };
    var b: PtBuilder = .{ .a = a };
    const r = try b.root(.Mutable);
    try b.prologue(r);
    try b.events(r, stream, r1, 4, 100);
    try b.events(r, stream, r2, 6, 101);
    const out = (try runPt(a, &src, .mutable, &b.pt())).done;
    // add_to_mmr: [r1] then peak 0 taken: current = H(r1, r2), peak 0 zeroed, pushed:
    // mmr [0, H(r1, r2)], checkpoint_seq 101, num_events 10.
    const h12 = hash.blake2b256(&.{ &r1, &r2 });
    var want: std.ArrayList(u8) = .empty;
    try want.appendSlice(a, &id);
    try want.appendSlice(a, &stream);
    try want.append(a, 2);
    try want.appendSlice(a, &@as([32]u8, @splat(0)));
    try want.appendSlice(a, &h12);
    try want.appendSlice(a, &.{ 101, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0 });
    const got = for (out.written) |w| {
        if (std.mem.eql(u8, &w.id, &id)) break w.bytes;
    } else return error.TestExpectedEqual;
    const v = try ObjectView.parse(got);
    try testing.expectEqualSlices(u8, want.items, v.contents());
    // Not a balance field: MoveObjectType::Other(Field<Key<EventStreamHead>, EventStreamHead>).
    try testing.expectEqual(@as(u8, 0), got[1]);

    // Next transaction: the zero peak takes r3 (no hash): mmr [r3, H(r1, r2)].
    const prev: TestKid = .{ .id = id, .raw = got };
    const src2: TestSrc = .{ .root = try testRoot(a), .kids = &.{prev} };
    var b2: PtBuilder = .{ .a = a };
    const q = try b2.root(.Mutable);
    try b2.prologue(q);
    try b2.events(q, stream, r3, 1, 102);
    const out2 = (try runPt(a, &src2, .mutable, &b2.pt())).done;
    for (out2.written) |w| if (std.mem.eql(u8, &w.id, &id)) {
        const c = (try ObjectView.parse(w.bytes)).contents();
        try testing.expectEqualSlices(u8, &r3, c[65..97]);
        try testing.expectEqualSlices(u8, &h12, c[97..129]);
        try testing.expectEqual(@as(u64, 11), std.mem.readInt(u64, c[137..145], .little));
    };
}

test "settlement: a NonExclusiveWrite root is read only in the effects" {
    // record_execution_results drops the unchanged root; compute_unchanged_consensus_objects
    // then lists it as ReadOnlyRoot at the version read. The lamport version still counts it.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root_raw = try testRoot(a);
    const src: TestSrc = .{ .root = root_raw, .kids = &.{} };
    var b: PtBuilder = .{ .a = a };
    const r = try b.root(.NonExclusiveWrite);
    try b.prologue(r);
    try b.count(r, 2, 0);
    const out = (try runPt(a, &src, .non_exclusive, &b.pt())).done;
    const fx = try effectsOf(a, &out);
    try testing.expect(changeOf(&fx, &root_id) == null);
    try testing.expectEqual(@as(usize, 1), fx.changed_objects.len);
    try testing.expectEqual(@as(usize, 1), fx.unchanged_consensus_objects.len);
    const u = fx.unchanged_consensus_objects[0];
    try testing.expectEqualSlices(u8, &root_id, &u[0].@"0".@"0");
    try testing.expectEqual(test_root_version, u[1].ReadOnlyRoot[0].@"0");
    try testing.expectEqualSlices(u8, &types.digest.objectDigest(root_raw), &u[1].ReadOnlyRoot[1].@"0".@"0");
    try testing.expectEqual(test_root_version + 1, fx.lamport_version.@"0");
    // The count field: Field<AccumulatorObjectCountKey, u64> keyed by `false`, value 2.
    const id = fieldId(&.{0}, count_key_type);
    try testing.expect(changeOf(&fx, &id).?[1].id_operation == .Created);
}
