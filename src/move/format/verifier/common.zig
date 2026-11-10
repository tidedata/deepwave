//! Shared pieces of the bytecode verifier port: VerifierConfig, the meter, error plumbing and
//! the ability cache (move-bytecode-verifier 1.83.1 `ability_cache.rs`).
const std = @import("std");
const ff = @import("../file_format.zig");

pub const Allocator = std.mem.Allocator;
pub const StatusCode = ff.StatusCode;
pub const PartialVmError = ff.PartialVmError;
pub const Token = ff.Token;
pub const Node = ff.Node;
pub const AbilitySet = ff.AbilitySet;

/// `move_vm_config::verifier::VerifierConfig` (field names as in Rust).
pub const Config = struct {
    max_loop_depth: ?usize = null,
    max_function_parameters: ?usize = null,
    max_generic_instantiation_length: ?usize = null,
    max_basic_blocks: ?usize = null,
    max_value_stack_size: usize = 1024,
    max_type_nodes: ?usize = null,
    max_push_size: ?usize = null,
    max_dependency_depth: ?usize = null,
    max_data_definitions: ?usize = null,
    max_fields_in_struct: ?usize = null,
    max_function_definitions: ?usize = null,
    max_constant_vector_len: ?u64 = null,
    max_back_edges_per_function: ?usize = null,
    max_back_edges_per_module: ?usize = null,
    max_basic_blocks_in_script: ?usize = null,
    max_identifier_len: ?u64 = null,
    disallow_self_identifier: bool = false,
    allow_receiving_object_id: bool = false,
    reject_mutable_random_on_entry_functions: bool = false,
    bytecode_version: u32 = 6,
    max_variants_in_enum: ?u64 = null,
    additional_borrow_checks: bool = false,
    better_loader_errors: bool = false,
    private_generics_verifier_v2: bool = false,
    sanity_check_with_regex_reference_safety: ?u128 = null,
    deprecate_global_storage_ops: bool = false,
    disable_entry_point_signature_check: bool = false,
    switch_to_regex_reference_safety: bool = false,
    framework_tx_context_mut_restrictions: bool = false,
    disallow_jump_orphans: bool = false,
    max_generic_instantiation_type_nodes_per_function: ?usize = null,
    max_generic_instantiation_type_nodes_per_module: ?usize = null,
    include_function_signatures_in_instantiation_limits: bool = false,
    disable_id_leak_verifier: bool = false,

    /// Parses the Rust serde_json form (field names as keys, null for None).
    pub fn fromJson(v: std.json.Value) !Config {
        var c: Config = .{};
        const o = v.object;
        inline for (@typeInfo(Config).@"struct".field_names, @typeInfo(Config).@"struct".field_types) |name, T| {
            const x = o.get(name) orelse return error.MissingField;
            switch (@typeInfo(T)) {
                .optional => |opt| @field(c, name) = if (x == .null) null else try num(opt.child, x),
                .bool => @field(c, name) = x.bool,
                else => @field(c, name) = try num(T, x),
            }
        }
        return c;
    }
    fn num(comptime T: type, x: std.json.Value) !T {
        return switch (x) {
            .integer => |i| @intCast(i),
            .number_string => |s| try std.fmt.parseInt(T, s, 10),
            else => error.BadNumber,
        };
    }
};

pub const E = error{ Vm, OutOfMemory };

/// Holds the PartialVMError of a failed check (`error.Vm`).
pub const Ctx = struct {
    err: PartialVmError = .{ .major = .UNKNOWN_STATUS },

    pub fn fail(c: *Ctx, e: PartialVmError) error{Vm} {
        c.err = e;
        return error.Vm;
    }
    pub fn status(c: *Ctx, s: StatusCode) error{Vm} {
        return c.fail(.new(s));
    }
    /// `safe_assert!` / `safe_unwrap!` failures in a release build.
    pub fn invariant(c: *Ctx) error{Vm} {
        return c.fail(.new(.UNKNOWN_INVARIANT_VIOLATION_ERROR));
    }
    pub fn atIndex(c: *Ctx, kind: ff.IndexKind, idx: u16) void {
        c.err = c.err.atIndex(kind, idx);
    }
};

pub const Scope = enum { Transaction, Package, Module, Function };

/// The verifier meter. Always records units (like the truth tool's recording meter); limits
/// follow `BoundMeter` (`kind = .bound`, > max is CONSTRAINT_NOT_SATISFIED) or Sui's
/// `SuiVerifierMeter` (`kind = .sui`, >= max is PROGRAM_TOO_COMPLEX).
pub const Meter = struct {
    pkg: u128 = 0,
    module: u128 = 0,
    fun: u128 = 0,
    fun_total: u128 = 0,
    fun_max: u128 = 0,
    adds: u64 = 0,
    kind: enum { record, bound, sui } = .record,
    max_pkg: ?u128 = null,
    max_mod: ?u128 = null,
    max_fun: ?u128 = null,

    pub fn enterScope(m: *Meter, scope: Scope) void {
        switch (scope) {
            .Package => m.pkg = 0,
            .Module => m.module = 0,
            .Function => m.fun = 0,
            .Transaction => {},
        }
    }

    pub fn transfer(m: *Meter, ctx: *Ctx, from: Scope, to: Scope, factor: f32) error{Vm}!void {
        const units: u128 = switch (from) {
            .Package => m.pkg,
            .Module => m.module,
            .Function => m.fun,
            .Transaction => 0,
        };
        const f = @as(f32, @floatFromInt(units)) * factor;
        return m.add(ctx, to, f32ToU128(f));
    }

    pub fn add(m: *Meter, ctx: *Ctx, scope: Scope, units: u128) error{Vm}!void {
        m.adds += 1;
        const slot: *u128, const max: ?u128 = switch (scope) {
            .Package => .{ &m.pkg, m.max_pkg },
            .Module => .{ &m.module, m.max_mod },
            .Function => .{ &m.fun, m.max_fun },
            .Transaction => return,
        };
        const new = slot.* +| units;
        switch (m.kind) {
            .record => {},
            .bound => if (max) |mx| if (new > mx) return ctx.status(.CONSTRAINT_NOT_SATISFIED),
            .sui => if (new >= (max orelse std.math.maxInt(u128))) return ctx.status(.PROGRAM_TOO_COMPLEX),
        }
        slot.* = new;
        if (scope == .Function) {
            m.fun_total +|= units;
            if (m.fun > m.fun_max) m.fun_max = m.fun;
        }
    }

    pub fn addItems(m: *Meter, ctx: *Ctx, scope: Scope, per: u128, items: usize) error{Vm}!void {
        if (items == 0) return;
        return m.add(ctx, scope, per *| @as(u128, items));
    }
};

/// Rust `f as u128` for a non-negative finite f32 (saturating, truncating).
fn f32ToU128(f: f32) u128 {
    if (!(f > 0)) return 0;
    if (f >= 3.4028235e38) return std.math.maxInt(u128);
    return @intFromFloat(f);
}

// ---------------------------------------------------------------------------------------------
// Ability cache

const TYPE_ARG_COST: u128 = 1;

pub const AbilityCache = struct {
    m: *const ff.CompiledModule,
    arena: Allocator,
    /// vector_results: inner abilities -> vector abilities (16 possible keys).
    vec: [16]?AbilitySet = @splat(null),
    /// datatype_results: (handle, type arg abilities) -> abilities. Key bytes: handle LE ++ args.
    dt: std.StringHashMapUnmanaged(AbilitySet) = .empty,
    key_buf: std.ArrayList(u8) = .empty,

    pub fn init(arena: Allocator, m: *const ff.CompiledModule) AbilityCache {
        return .{ .m = m, .arena = arena };
    }

    /// `AbilityCache::abilities` of the subtree at `t[0]`.
    pub fn abilities(c: *AbilityCache, ctx: *Ctx, scope: Scope, meter: *Meter, tparams: []const AbilitySet, t: Token) E!AbilitySet {
        const n = t[0];
        switch (n.tag) {
            .Bool, .U8, .U16, .U32, .U64, .U128, .U256, .Address => return AbilitySet.PRIMITIVES,
            .Reference, .MutableReference => return AbilitySet.REFERENCES,
            .Signer => return AbilitySet.SIGNER,
            .TypeParameter => {
                if (n.idx >= tparams.len) return ctx.invariant();
                return tparams[n.idx];
            },
            .Datatype => return c.m.datatype_handles[n.idx].abilities,
            .Vector => {
                const inner_ab = try c.abilities(ctx, scope, meter, tparams, t[1..]);
                if (c.vec[inner_ab.bits]) |r| return r;
                try meter.add(ctx, scope, TYPE_ARG_COST);
                const r = AbilitySet.polymorphic(AbilitySet.VECTOR, &.{.{ .constraints = .EMPTY, .is_phantom = false }}, &.{inner_ab});
                c.vec[inner_ab.bits] = r;
                return r;
            },
            .DatatypeInstantiation => {
                var args: [256]AbilitySet = undefined;
                var it = ff.ArgIter.init(t);
                var k: usize = 0;
                while (it.next()) |a| : (k += 1) args[k] = try c.abilities(ctx, scope, meter, tparams, a);
                const key_len = 2 + k;
                var key: [258]u8 = undefined;
                std.mem.writeInt(u16, key[0..2], n.idx, .little);
                for (args[0..k], 0..) |a, i| key[2 + i] = a.bits;
                if (c.dt.get(key[0..key_len])) |r| return r;
                try meter.addItems(ctx, scope, TYPE_ARG_COST, @max(k, 1));
                const sh = &c.m.datatype_handles[n.idx];
                if (sh.type_parameters.len != k) return ctx.status(.VERIFIER_INVARIANT_VIOLATION);
                const r = AbilitySet.polymorphic(sh.abilities, sh.type_parameters, args[0..k]);
                try c.dt.put(c.arena, try c.arena.dupe(u8, key[0..key_len]), r);
                return r;
            },
        }
    }
};

/// `CompiledModule::abilities` (uncached, unmetered). Errors are VERIFIER_INVARIANT_VIOLATION.
pub fn moduleAbilities(m: *const ff.CompiledModule, t: Token, constraints: []const AbilitySet) ?AbilitySet {
    const n = t[0];
    return switch (n.tag) {
        .Bool, .U8, .U16, .U32, .U64, .U128, .U256, .Address => AbilitySet.PRIMITIVES,
        .Reference, .MutableReference => AbilitySet.REFERENCES,
        .Signer => AbilitySet.SIGNER,
        .TypeParameter => constraints[n.idx],
        .Datatype => m.datatype_handles[n.idx].abilities,
        .Vector => AbilitySet.polymorphic(AbilitySet.VECTOR, &.{.{ .constraints = .EMPTY, .is_phantom = false }}, &.{moduleAbilities(m, t[1..], constraints) orelse return null}),
        .DatatypeInstantiation => blk: {
            var args: [256]AbilitySet = undefined;
            var it = ff.ArgIter.init(t);
            var k: usize = 0;
            while (it.next()) |a| : (k += 1) args[k] = moduleAbilities(m, a, constraints) orelse return null;
            const sh = &m.datatype_handles[n.idx];
            if (sh.type_parameters.len != k) return null;
            break :blk AbilitySet.polymorphic(sh.abilities, sh.type_parameters, args[0..k]);
        },
    };
}

// ---------------------------------------------------------------------------------------------
// Token helpers

/// Builds tokens in an arena.
pub const TokBuf = struct {
    arena: Allocator,
    buf: std.ArrayList(Node) = .empty,

    pub fn wrap(b: *TokBuf, tag: ff.Tag, inner: Token) E!Token {
        const out = try b.arena.alloc(Node, inner.len + 1);
        out[0] = .{ .tag = tag };
        @memcpy(out[1..], inner);
        return out;
    }

    /// `ST::Datatype(h)` or `ST::DatatypeInstantiation(h, args)`.
    pub fn datatype(b: *TokBuf, handle: u16, args: []const Token) E!Token {
        if (args.len == 0) {
            const out = try b.arena.alloc(Node, 1);
            out[0] = .{ .tag = .Datatype, .idx = handle };
            return out;
        }
        var len: usize = 1;
        for (args) |a| len += a.len;
        const out = try b.arena.alloc(Node, len);
        out[0] = .{ .tag = .DatatypeInstantiation, .idx = handle, .arity = @intCast(args.len) };
        var i: usize = 1;
        for (args) |a| {
            @memcpy(out[i..][0..a.len], a);
            i += a.len;
        }
        return out;
    }

    /// Substitutes type parameters (`instantiate` / `rec` in type_safety.rs). With an empty
    /// substitution the token is returned as is.
    pub fn instantiate(b: *TokBuf, t: Token, subst: []const Token) E!Token {
        if (subst.len == 0) return t;
        var has_param = false;
        for (t) |n| if (n.tag == .TypeParameter) {
            has_param = true;
            break;
        };
        if (!has_param) return t;
        b.buf.clearRetainingCapacity();
        for (t) |n| {
            if (n.tag == .TypeParameter) {
                try b.buf.appendSlice(b.arena, subst[n.idx]);
            } else try b.buf.append(b.arena, n);
        }
        return b.arena.dupe(Node, b.buf.items);
    }
};

pub fn sigTokens(m: *const ff.CompiledModule, idx: u16) []const Token {
    return m.signatures[idx];
}

/// Rust `format_signature_token`.
pub fn formatToken(w: *std.Io.Writer, m: *const ff.CompiledModule, t: Token) std.Io.Writer.Error!void {
    const n = t[0];
    switch (n.tag) {
        .Bool => try w.writeAll("bool"),
        .U8 => try w.writeAll("u8"),
        .U16 => try w.writeAll("u16"),
        .U32 => try w.writeAll("u32"),
        .U64 => try w.writeAll("u64"),
        .U128 => try w.writeAll("u128"),
        .U256 => try w.writeAll("u256"),
        .Address => try w.writeAll("address"),
        .Signer => try w.writeAll("signer"),
        .Vector => {
            try w.writeAll("vector<");
            try formatToken(w, m, t[1..]);
            try w.writeAll(">");
        },
        .Reference => {
            try w.writeAll("&");
            try formatToken(w, m, t[1..]);
        },
        .MutableReference => {
            try w.writeAll("&mut ");
            try formatToken(w, m, t[1..]);
        },
        .TypeParameter => try w.print("T{d}", .{n.idx}),
        .Datatype, .DatatypeInstantiation => {
            const sh = &m.datatype_handles[n.idx];
            const mh = &m.module_handles[sh.module];
            try w.writeAll("0x");
            try writeShortAddr(w, &m.address_identifiers[mh.address]);
            try w.print("::{s}::{s}", .{ m.identifiers[mh.name], m.identifiers[sh.name] });
            if (n.tag == .DatatypeInstantiation) {
                try w.writeAll("<");
                var it = ff.ArgIter.init(t);
                var first = true;
                while (it.next()) |a| {
                    if (!first) try w.writeAll(", ");
                    first = false;
                    try formatToken(w, m, a);
                }
                try w.writeAll(">");
            }
        },
    }
}

/// `AccountAddress::short_str_lossless`.
pub fn writeShortAddr(w: *std.Io.Writer, a: *const [32]u8) std.Io.Writer.Error!void {
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{a}) catch unreachable;
    var i: usize = 0;
    while (i < 64 and hex[i] == '0') i += 1;
    if (i == 64) try w.writeAll("0") else try w.writeAll(hex[i..]);
}

/// `AccountAddress` Display: 64 lowercase hex digits.
pub fn writeAddr(w: *std.Io.Writer, a: *const [32]u8) std.Io.Writer.Error!void {
    try w.print("{x}", .{a});
}

pub fn addrFromU16(x: u16) [32]u8 {
    var a: [32]u8 = @splat(0);
    a[30] = @intCast(x >> 8);
    a[31] = @intCast(x & 0xff);
    return a;
}
