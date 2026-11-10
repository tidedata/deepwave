//! The native call ABI (CONTRACTS.md section 6.3).
//!
//! A native takes a `*Ctx` (gas, protocol config, transaction context and object runtime), its
//! instantiated type arguments and its arguments as runtime values, and returns an `Outcome`
//! that mirrors `PartialVMResult<NativeResult>` exactly:
//!
//!   ok    { cost, rets }   NativeResult::ok        -> charge `cost`, push `rets`
//!   abort { cost, code }   NativeResult::err       -> charge `cost`, ABORTED with sub status
//!   err   { status, sub }  Err(PartialVMError)     -> no native charge, VM error
//!
//! Arguments are `types.layout.Value`. A `&mut` argument is updated in place in `args[i]`; the
//! caller writes it back through the reference. Reference arguments are passed as the value they
//! point to (natives in this table never observe reference identity).
const std = @import("std");
const types = @import("types");
const bcs = @import("bcs");
const protocol = @import("protocol");
const move_format = @import("move_format");
pub const objrt = @import("objrt.zig");

pub const Allocator = std.mem.Allocator;
pub const Value = types.layout.Value;
pub const Layout = types.layout.MoveTypeLayout;
pub const TypeTag = types.TypeTag;
pub const StatusCode = move_format.StatusCode;
pub const ProtocolConfig = protocol.ProtocolConfig;

/// move-core-types `vm_status::sub_status`.
pub const NFE_OUT_OF_GAS: u64 = 1;
pub const NFE_BCS_SERIALIZATION_FAILURE: u64 = 0x1C5;

/// An instantiated type argument as the VM resolves it.
pub const TyArg = struct {
    /// `type_to_type_tag`: defining ids.
    tag: *const TypeTag,
    /// `type_to_runtime_type_tag`: original ids. Null when equal to `tag`.
    runtime_tag: ?*const TypeTag = null,
    /// `type_to_type_layout`: null where Rust gets `None` (the layout exceeds the VM's
    /// `max_type_to_layout_nodes` or value depth limits).
    layout: ?*const Layout,
    /// The shape of the type's values when `layout` is null: natives that walk a value (sizes,
    /// serialization) use it, natives that ask the VM for a layout see `layout == null`.
    shape: ?*const Layout = null,
    /// `type_to_fully_annotated_layout`; null where Rust gets `None` (or the native never asks).
    annotated: ?*const objrt.ALayout = null,

    pub fn runtimeTag(t: TyArg) *const TypeTag {
        return t.runtime_tag orelse t.tag;
    }

    /// The layout a value of this type is walked with.
    pub fn traversal(t: TyArg) ?*const Layout {
        return t.layout orelse t.shape;
    }
};

pub const VmError = objrt.VmError;

pub const Outcome = union(enum) {
    /// `ref` is set when the native returns one reference (`&T`/`&mut T`) instead of values:
    /// the caller reads and writes the value through it.
    ok: struct { cost: u64, rets: []const Value, ref: ?*Value = null },
    abort: struct { cost: u64, code: u64 },
    err: VmError,
};

pub const Error = Allocator.Error;

pub const NativeFn = *const fn (ctx: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome;

/// `TxContext` as the `TransactionContext` extension holds it.
pub const TxContext = struct {
    sender: [32]u8,
    digest: [32]u8,
    epoch: u64,
    epoch_timestamp_ms: u64,
    rgp: u64,
    gas_price: u64,
    gas_budget: u64,
    sponsor: ?[32]u8,
    ids_created: u64 = 0,

    /// `ObjectID::derive_id`: Blake2b256(0xf1 ++ digest ++ creation_num LE)[0..32].
    pub fn deriveId(digest: *const [32]u8, n: u64) [32]u8 {
        const hash = @import("hash");
        var le: [8]u8 = undefined;
        std.mem.writeInt(u64, &le, n, .little);
        return hash.blake2b256(&.{ &[_]u8{0xf1}, digest, &le });
    }

    pub fn freshId(t: *TxContext) [32]u8 {
        const id = deriveId(&t.digest, t.ids_created);
        t.ids_created += 1;
        return id;
    }
};

/// The object runtime (objrt.zig): ids, transfers, events, child objects, accumulators, scratch.
pub const ObjectRuntime = objrt.ObjectRuntime;

pub const Ctx = struct {
    /// Results and scratch, reset by the caller per transaction.
    arena: Allocator,
    cfg: *const ProtocolConfig,
    /// `NativeContext::gas_budget` (the meter's remaining gas when the native was entered).
    budget: u64,
    left: u64,
    tx: *TxContext,
    rt: *ObjectRuntime,
    /// `VMRuntimeLimitsConfig::vector_len_max`.
    vector_len_max: u64,
    /// `VMRuntimeLimitsConfig::hardened_otw_check`.
    hardened_otw_check: bool,

    pub fn init(arena: Allocator, cfg: *const ProtocolConfig, budget: u64, tx: *TxContext, rt: *ObjectRuntime) Ctx {
        return .{
            .arena = arena,
            .cfg = cfg,
            .budget = budget,
            .left = budget,
            .tx = tx,
            .rt = rt,
            .vector_len_max = cfg.getOpt("max_move_vector_len") orelse std.math.maxInt(u64),
            .hardened_otw_check = cfg.feature_flags.hardened_otw_check,
        };
    }

    /// Start a new native call with `budget` (the meter's remaining gas).
    pub fn enter(c: *Ctx, budget: u64) void {
        c.budget = budget;
        c.left = budget;
    }

    /// `NativeContext::charge_gas`: false (and nothing charged) when the budget is short.
    pub inline fn charge(c: *Ctx, amount: u64) bool {
        if (c.left < amount) return false;
        c.left -= amount;
        return true;
    }

    pub inline fn used(c: *const Ctx) u64 {
        return c.budget - c.left;
    }

    /// Protocol config value as `get_gas_cost_or_default`/`_as_option().unwrap_or(0)` reads it.
    pub inline fn p(c: *const Ctx, comptime name: []const u8) u64 {
        // exec-history-vm: v0..v2 build the move-stdlib natives with `GasParameters::zeros()`.
        if (comptime isStdlibParam(name)) {
            if ((c.cfg.execution_version orelse 0) < 3) return 0;
        }
        return c.popt(name) orelse 0;
    }

    /// The move-stdlib natives' gas parameters (v3 `sui-move-natives/src/lib.rs` stdlib table).
    fn isStdlibParam(comptime name: []const u8) bool {
        const prefixes = [_][]const u8{ "bcs_", "debug_", "hash_sha2_256_", "hash_sha3_256_", "string_", "type_name_", "vector_" };
        inline for (prefixes) |pre| if (std.mem.startsWith(u8, name, pre)) return true;
        return false;
    }

    pub inline fn popt(c: *const Ctx, comptime name: []const u8) ?u64 {
        const v = c.cfg.getOpt(name) orelse return null;
        return @intCast(v);
    }

    pub inline fn flag(c: *const Ctx, comptime name: []const u8) bool {
        return @field(c.cfg.feature_flags, name);
    }

    /// `native_charge_gas_early_exit!` failure: the whole budget, NFE_OUT_OF_GAS.
    pub fn oog(c: *const Ctx) Outcome {
        return .{ .abort = .{ .cost = c.budget, .code = NFE_OUT_OF_GAS } };
    }

    pub fn ok(c: *const Ctx, rets: []const Value) Outcome {
        return .{ .ok = .{ .cost = c.used(), .rets = rets } };
    }

    pub fn okWith(cost: u64, rets: []const Value) Outcome {
        return .{ .ok = .{ .cost = cost, .rets = rets } };
    }

    pub fn ok1(c: *const Ctx, v: Value) Error!Outcome {
        const r = try c.arena.alloc(Value, 1);
        r[0] = v;
        return c.ok(r);
    }

    pub fn ok0(c: *const Ctx) Outcome {
        return c.ok(&.{});
    }

    pub fn abort(c: *const Ctx, code: u64) Outcome {
        return .{ .abort = .{ .cost = c.used(), .code = code } };
    }

    pub fn err(status: StatusCode, sub: ?u64) Outcome {
        return .{ .err = .{ .status = status, .sub = sub } };
    }

    pub fn okRef(c: *const Ctx, r: *Value) Outcome {
        return .{ .ok = .{ .cost = c.used(), .rets = &.{}, .ref = r } };
    }

    pub fn vmErr(e: VmError) Outcome {
        return .{ .err = e };
    }

    pub fn invariant() Outcome {
        return err(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null);
    }

    // ---- value helpers -------------------------------------------------------------------

    /// A `vector<u8>` result, packed (`b` is copied into the call's arena).
    pub fn bytesValue(c: *const Ctx, b: []const u8) Error!Value {
        return .{ .bytes = try c.arena.dupe(u8, b) };
    }

    pub fn ok1Bytes(c: *const Ctx, b: []const u8) Error!Outcome {
        return c.ok1(try c.bytesValue(b));
    }
};

/// Reads a `vector<u8>` value into bytes (arena memory).
/// Either form; a packed value is returned as is (no copy), so callers must not write to it.
pub fn bytesOf(arena: Allocator, v: Value) Error![]const u8 {
    return types.layout.byteSlice(arena, v);
}

pub fn vecOfBytesOf(arena: Allocator, v: Value) Error![][]const u8 {
    const items = v.vector;
    const out = try arena.alloc([]const u8, items.len);
    for (out, items) |*o, it| o.* = try bytesOf(arena, it);
    return out;
}

// ---- sizes used by gas formulas ------------------------------------------------------------

/// move-vm-runtime `Type::size` (legacy): 1 per node, datatypes 1 plus their type arguments.
pub fn typeSize(t: *const TypeTag) u64 {
    return switch (t.*) {
        .vector => |e| 1 +| typeSize(e),
        .@"struct" => |s| blk: {
            var acc: u64 = 1;
            for (s.type_args) |*a| acc +|= typeSize(a);
            break :blk acc;
        },
        else => 1,
    };
}

/// move-core-types `TypeTag::abstract_size_for_gas_metering`.
pub fn tagAbstractSize(t: *const TypeTag) u64 {
    const enum_size: u64 = 8 + 16;
    return enum_size +| switch (t.*) {
        .vector => |e| tagAbstractSize(e),
        .@"struct" => |*s| structAbstractSize(s),
        else => 0,
    };
}

/// move-core-types `StructTag::abstract_size_for_gas_metering` (no enum wrapper: the natives that
/// charge for a struct tag size the unwrapped `StructTag`).
pub fn structAbstractSize(s: *const types.StructTag) u64 {
    var acc: u64 = 32 +| s.module.@"0".len +| s.name.@"0".len;
    for (s.type_args) |*a| acc +|= tagAbstractSize(a);
    return acc;
}

/// `fine_grained`: false is `fine_grained_value_size: false` of the historical cuts (exec-history,
/// CONTRACTS 6.6b): every scalar but an address counts LEGACY_CONST_SIZE (16).
pub const SizeConfig = struct { include_vector_size: bool, traverse_references: bool = false, fine_grained: bool = true };

/// `ValueView::abstract_memory_size` over a value of `layout`. The layout says whether a vector
/// is a primitive vector (u8..u256, bool, address: element bytes) or a vector of containers.
pub fn abstractSize(v: *const Value, layout: *const Layout, cfg: SizeConfig) u64 {
    return switch (layout.*) {
        .u8, .u16, .u32, .u64, .bool => if (cfg.fine_grained) 8 else 16,
        .u128 => 16,
        .u256 => if (cfg.fine_grained) 32 else 16,
        .address => 32,
        // the VM holds a signer as a struct of one address
        .signer => 2 + 32,
        .@"struct" => |sl| blk: {
            var acc: u64 = 2;
            for (v.@"struct", sl.@"0") |*f, *fl| acc +|= abstractSize(f, fl, cfg);
            break :blk acc;
        },
        .@"enum" => |el| blk: {
            var acc: u64 = 2;
            const va = v.variant;
            for (va.fields, el.@"0"[va.tag]) |*f, *fl| acc +|= abstractSize(f, fl, cfg);
            break :blk acc;
        },
        .vector => |el| blk: {
            const n: u64 = v.vecLen();
            const prim: ?u64 = switch (el.*) {
                .u8, .bool => 1,
                .u16 => 2,
                .u32 => 4,
                .u64 => 8,
                .u128 => 16,
                .u256, .address => 32,
                else => null,
            };
            if (prim) |w| break :blk (if (cfg.include_vector_size) @as(u64, 2) else 0) +| n *| w;
            var acc: u64 = 2;
            for (v.vector) |*e| acc +|= abstractSize(e, el, cfg);
            break :blk acc;
        },
    };
}

/// exec-history-vm: v0..v3 move-vm-types `Value::legacy_size`: scalars 16, address 32,
/// struct 2 + fields, variant 2 + 2 + fields, generic vector 2 + elements, primitive vector
/// elements * width with no header (references are 8; callers size a reference themselves).
pub fn legacySize(v: *const Value, layout: *const Layout) u64 {
    return switch (layout.*) {
        .u8, .u16, .u32, .u64, .u128, .u256, .bool => 16,
        .address => 32,
        .signer => 2 + 32,
        .@"struct" => |sl| blk: {
            var acc: u64 = 2;
            for (v.@"struct", sl.@"0") |*f, *fl| acc +|= legacySize(f, fl);
            break :blk acc;
        },
        .@"enum" => |el| blk: {
            var acc: u64 = 2 + 2;
            const va = v.variant;
            for (va.fields, el.@"0"[va.tag]) |*f, *fl| acc +|= legacySize(f, fl);
            break :blk acc;
        },
        .vector => |el| blk: {
            const n: u64 = v.vecLen();
            const w: ?u64 = switch (el.*) {
                .u8, .bool => 1,
                .u16 => 2,
                .u32 => 4,
                .u64 => 8,
                .u128 => 16,
                .u256, .address => 32,
                else => null,
            };
            if (w) |x| break :blk n *| x;
            var acc: u64 = 2;
            for (v.vector) |*e| acc +|= legacySize(e, el);
            break :blk acc;
        },
    };
}

/// exec-history-vm: `LEGACY_REFERENCE_SIZE`.
pub const LEGACY_REFERENCE_SIZE: u64 = 8;

/// exec-history-vm: the object-runtime natives (dynamic fields, events, config) size values with
/// `legacy_size` in v0..v2 and before `abstract_size_in_object_runtime` (protocol 104) in v3.
pub fn legacyObjectSizes(cfg: *const protocol.ProtocolConfig) bool {
    return (cfg.execution_version orelse 0) < 3 or !cfg.feature_flags.abstract_size_in_object_runtime;
}

/// v3 `abstract_size(protocol_config, v)` (latest: the abstract size with vector headers).
pub fn objectRuntimeSize(cfg: *const protocol.ProtocolConfig, v: *const Value, layout: *const Layout) u64 {
    if (legacyObjectSizes(cfg)) return legacySize(v, layout);
    return abstractSize(v, layout, .{ .include_vector_size = true });
}

// ---- type tag rendering --------------------------------------------------------------------

/// `TypeTag::to_canonical_string(with_prefix)`.
pub fn canonicalString(arena: Allocator, t: *const TypeTag, with_prefix: bool) Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    try writeCanonical(arena, &list, t, with_prefix);
    return list.items;
}

fn writeCanonical(arena: Allocator, out: *std.ArrayList(u8), t: *const TypeTag, with_prefix: bool) Error!void {
    switch (t.*) {
        .bool => try out.appendSlice(arena, "bool"),
        .u8 => try out.appendSlice(arena, "u8"),
        .u16 => try out.appendSlice(arena, "u16"),
        .u32 => try out.appendSlice(arena, "u32"),
        .u64 => try out.appendSlice(arena, "u64"),
        .u128 => try out.appendSlice(arena, "u128"),
        .u256 => try out.appendSlice(arena, "u256"),
        .address => try out.appendSlice(arena, "address"),
        .signer => try out.appendSlice(arena, "signer"),
        .vector => |e| {
            try out.appendSlice(arena, "vector<");
            try writeCanonical(arena, out, e, with_prefix);
            try out.append(arena, '>');
        },
        .@"struct" => |s| {
            if (with_prefix) try out.appendSlice(arena, "0x");
            const hexd = std.fmt.bytesToHex(s.address.@"0", .lower);
            try out.appendSlice(arena, &hexd);
            try out.appendSlice(arena, "::");
            try out.appendSlice(arena, s.module.@"0");
            try out.appendSlice(arena, "::");
            try out.appendSlice(arena, s.name.@"0");
            if (s.type_args.len > 0) {
                try out.append(arena, '<');
                for (s.type_args, 0..) |*a, i| {
                    if (i > 0) try out.append(arena, ',');
                    try writeCanonical(arena, out, a, with_prefix);
                }
                try out.append(arena, '>');
            }
        },
    }
}

/// BCS of a type tag (arena memory).
pub fn tagBcs(arena: Allocator, t: *const TypeTag) Error![]u8 {
    var cw: bcs.CountingWriter = .{};
    bcs.encode(TypeTag, t, &cw) catch unreachable;
    const buf = try arena.alloc(u8, cw.n);
    var w = bcs.Writer.init(buf);
    bcs.encode(TypeTag, t, &w) catch unreachable;
    return buf;
}

test "type sizes" {
    const u8t: TypeTag = .u8;
    const v: TypeTag = .{ .vector = &u8t };
    try std.testing.expectEqual(@as(u64, 2), typeSize(&v));
    try std.testing.expectEqual(@as(u64, 48), tagAbstractSize(&v));
}
