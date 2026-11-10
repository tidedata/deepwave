//! Transaction resolution for SimulateTransaction (sui-rpc-api
//! `transaction_execution_service/simulate/resolve`): a `Transaction` proto without `bcs`, as
//! @mysten/sui's `tx.build()` sends it, becomes a full `TransactionData`.
//!
//! - A fully formed proto (every field `sui_sdk_types::Transaction::try_from` needs) converts as is.
//! - Otherwise inputs resolve against the live object set: object refs take the live version and
//!   digest (a given version or digest must match), shared inputs get their initial shared version
//!   and a mutability derived from how the commands use them, address-owned inputs passed where a
//!   `0x2::transfer::Receiving<T>` parameter is expected become Receiving, coin reservation refs
//!   are re-encoded. Gas payment refs resolve the same way and bound the default budget.
//! - `literal` inputs (JSON values typed by the called function) answer UNIMPLEMENTED.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const exec = @import("exec");
const serve = @import("serve");
const mf = @import("move_format");

const state_mod = @import("state.zig");
const checks = @import("checks.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const proto = serve.proto;
const ObjectView = exec.objects.ObjectView;
const State = state_mod.State;
const ff = mf.file_format;

pub const Reason = serve.status.Reason;

/// A resolution failure: a BadRequest field violation (INVALID_ARGUMENT, message = description)
/// or a plain status.
pub const Error = union(enum) {
    bad: struct { field: []const u8, description: []const u8, reason: Reason },
    status: struct { code: u8, message: []const u8 },
};

pub const Result = union(enum) {
    ok: types.TransactionDataV1,
    err: Error,
    unimplemented: []const u8,
};

const code_invalid_argument = 3;
const code_not_found = 5;
const code_internal = 13;

// ---- the parsed request ------------------------------------------------------------------------

const PInput = struct {
    kind: ?u64 = null,
    pure: ?[]const u8 = null,
    object_id: ?[]const u8 = null,
    version: ?u64 = null,
    digest: ?[]const u8 = null,
    mutable: ?bool = null,
    mutability: ?u64 = null,
    funds: ?[]const u8 = null,
    literal: bool = false,
};

const PRef = struct { object_id: ?[]const u8 = null, version: ?u64 = null, digest: ?[]const u8 = null };

const PGas = struct {
    objects: []const PRef = &.{},
    owner: ?[]const u8 = null,
    price: ?u64 = null,
    budget: ?u64 = null,
};

/// What the request carries besides the transaction itself (for the gas selection flow).
pub const Request = struct {
    version: ?u64 = null,
    kind: ?[]const u8 = null,
    sender: ?[]const u8 = null,
    gas: ?PGas = null,
    expiration: ?[]const u8 = null,
    inputs: []const PInput = &.{},
    commands: []const []const u8 = &.{},
    /// The PTB message (`kind.programmable_transaction`) was present.
    has_ptb: bool = false,

    pub fn gasBudget(r: *const Request) ?u64 {
        return if (r.gas) |g| g.budget else null;
    }
    pub fn gasPrice(r: *const Request) ?u64 {
        return if (r.gas) |g| g.price else null;
    }
    pub fn gasObjects(r: *const Request) usize {
        return if (r.gas) |g| g.objects.len else 0;
    }
};

const DecodeError = proto.Reader.DecodeError || Allocator.Error;

/// Parses a `Transaction` proto (without `bcs`).
pub fn parse(arena: Allocator, msg: []const u8) DecodeError!Request {
    var q: Request = .{};
    var r = proto.Reader.init(msg);
    var kind_buf: std.ArrayList(u8) = .empty;
    var exp_buf: std.ArrayList(u8) = .empty;
    var gas_buf: std.ArrayList(u8) = .empty;
    var has_kind = false;
    var has_exp = false;
    var has_gas = false;
    while (try r.next()) |f| switch (f.number) {
        3 => q.version = try proto.Reader.varintOf(f),
        4 => {
            has_kind = true;
            try kind_buf.appendSlice(arena, try proto.Reader.bytesOf(f));
        },
        5 => q.sender = try proto.Reader.stringOf(f),
        6 => {
            has_gas = true;
            try gas_buf.appendSlice(arena, try proto.Reader.bytesOf(f));
        },
        7 => {
            has_exp = true;
            try exp_buf.appendSlice(arena, try proto.Reader.bytesOf(f));
        },
        else => {},
    };
    if (has_kind) q.kind = kind_buf.items;
    if (has_exp) q.expiration = exp_buf.items;
    if (has_gas) {
        var g: PGas = .{};
        var refs: std.ArrayList(PRef) = .empty;
        var gr = proto.Reader.init(gas_buf.items);
        while (try gr.next()) |f| switch (f.number) {
            1 => try refs.append(arena, try parseRef(try proto.Reader.bytesOf(f))),
            2 => g.owner = try proto.Reader.stringOf(f),
            3 => g.price = try proto.Reader.varintOf(f),
            4 => g.budget = try proto.Reader.varintOf(f),
            else => {},
        };
        g.objects = refs.items;
        q.gas = g;
    }
    // TransactionKind { kind = 1; programmable_transaction = 2 }
    if (q.kind) |k| {
        var ptb: std.ArrayList(u8) = .empty;
        var kr = proto.Reader.init(k);
        while (try kr.next()) |f| if (f.number == 2) {
            q.has_ptb = true;
            try ptb.appendSlice(arena, try proto.Reader.bytesOf(f));
        };
        var inputs: std.ArrayList(PInput) = .empty;
        var commands: std.ArrayList([]const u8) = .empty;
        var pr = proto.Reader.init(ptb.items);
        while (try pr.next()) |f| switch (f.number) {
            1 => try inputs.append(arena, try parseInput(try proto.Reader.bytesOf(f))),
            2 => try commands.append(arena, try proto.Reader.bytesOf(f)),
            else => {},
        };
        q.inputs = inputs.items;
        q.commands = commands.items;
    }
    return q;
}

fn parseRef(msg: []const u8) DecodeError!PRef {
    var p: PRef = .{};
    var r = proto.Reader.init(msg);
    while (try r.next()) |f| switch (f.number) {
        1 => p.object_id = try proto.Reader.stringOf(f),
        2 => p.version = try proto.Reader.varintOf(f),
        3 => p.digest = try proto.Reader.stringOf(f),
        else => {},
    };
    return p;
}

fn parseInput(msg: []const u8) DecodeError!PInput {
    var p: PInput = .{};
    var r = proto.Reader.init(msg);
    while (try r.next()) |f| switch (f.number) {
        1 => p.kind = try proto.Reader.varintOf(f),
        2 => p.pure = try proto.Reader.bytesOf(f),
        3 => p.object_id = try proto.Reader.stringOf(f),
        4 => p.version = try proto.Reader.varintOf(f),
        5 => p.digest = try proto.Reader.stringOf(f),
        6 => p.mutable = (try proto.Reader.varintOf(f)) != 0,
        7 => p.mutability = try proto.Reader.varintOf(f),
        8 => p.funds = try proto.Reader.bytesOf(f),
        1000 => p.literal = true,
        else => {},
    };
    return p;
}

// ---- string forms -------------------------------------------------------------------------------

/// `sui_sdk_types::Address::from_str` (`hex_address_bytes`): an optional lowercase `0x`
/// (`remove_0x_prefix`), then 1 to 64 hex digits of either case, left padded. An empty string and
/// a bare `0x` are rejected. Every failure renders as `address_parse_error`.
pub fn parseAddress(s: []const u8) ?Id {
    const h = if (s.len >= 2 and s[0] == '0' and s[1] == 'x') s[2..] else s;
    if (h.len == 0 or h.len > 64) return null;
    var buf: [64]u8 = @splat('0');
    @memcpy(buf[64 - h.len ..], h);
    var out: Id = undefined;
    _ = std.fmt.hexToBytes(&out, &buf) catch return null;
    return out;
}

/// sui-types `SuiAddress::from_str` (fastcrypto `decode_bytes_hex`): an optional `0x`, then
/// exactly 64 hex digits. GasPayment.owner and a funds withdrawal's funder parse this way.
pub fn parseSuiAddress(s: []const u8) ?Id {
    const h = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    if (h.len != 64) return null;
    var out: Id = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch return null;
    return out;
}
/// fastcrypto `InvalidInput`'s Display (a failed `SuiAddress::from_str`).
pub const sui_address_parse_error = "Invalid value was given to the function";

/// sui-types `ObjectID::from_str`: `decode_bytes_hex`, else `from_hex_literal` (`0x` and up to
/// 64 digits, left padded; a bare `0x` is ObjectID zero). Every failure is
/// `ObjectIDParseError::HexLiteralPrefixMissing` (the padded retry has no prefix).
pub fn parseObjectId(s: []const u8) ?Id {
    if (parseSuiAddress(s)) |a| return a;
    if (!std.mem.startsWith(u8, s, "0x") or s.len - 2 > 64) return null;
    var buf: [64]u8 = @splat('0');
    @memcpy(buf[64 - (s.len - 2) ..], s[2..]);
    var out: Id = undefined;
    _ = std.fmt.hexToBytes(&out, &buf) catch return null;
    return out;
}
pub const object_id_parse_error = "ObjectID hex literal must start with 0x";

/// `AddressParseError`'s Display (every variant).
pub const address_parse_error = "Unable to parse Address (must be hex string of length 32)";
/// `DigestParseError`'s Display.
pub const digest_parse_error = "Unable to parse Digest (must be Base58 string of length 32)";
/// `TryFromIntError`'s Display (u32 -> u16 argument indices).
const int_range_error = "out of range integral type conversion attempted";

fn parseDigest(s: []const u8) ?Id {
    return serve.b58.decode32(s);
}

/// sui-sdk-types `type_tag/parse.rs` limits: a `vector<..>` or generic argument is one level
/// deeper (depth >= 128 is rejected), and a type has at most 256 TypeTag nodes.
pub const max_type_depth = 128;
pub const max_type_nodes = 256;
const max_identifier_len = 128;

const TypeErr = error{ Backtrack, Depth, Nodes } || Allocator.Error;

/// The winnow grammar of sui-sdk-types `parse_type_tag`, step for step: primitives match as
/// literal prefixes, `vector<` has no inner spaces, struct addresses need a lowercase `0x` and 1
/// to 64 hex digits, identifiers are at most 128 characters, and only generic arguments may be
/// surrounded by spaces or tabs. Recursion is bounded by `max_type_depth`.
const TypeParser = struct {
    arena: Allocator,
    s: []const u8,
    i: usize = 0,
    nodes: u64 = 0,

    fn lit(p: *TypeParser, t: []const u8) bool {
        if (!std.mem.startsWith(u8, p.s[p.i..], t)) return false;
        p.i += t.len;
        return true;
    }
    fn space0(p: *TypeParser) void {
        while (p.i < p.s.len and (p.s[p.i] == ' ' or p.s[p.i] == '\t')) p.i += 1;
    }
    fn identChar(c: u8) bool {
        return std.ascii.isAlphanumeric(c) or c == '_';
    }
    /// `identifier`: an ASCII letter then 0 to 127 identifier characters, or `_` then 1 to 127.
    fn ident(p: *TypeParser) ?[]const u8 {
        const start = p.i;
        if (p.i >= p.s.len) return null;
        const c0 = p.s[p.i];
        const min: usize = if (std.ascii.isAlphabetic(c0)) 0 else if (c0 == '_') 1 else return null;
        p.i += 1;
        var n: usize = 0;
        while (n < max_identifier_len - 1 and p.i < p.s.len and identChar(p.s[p.i])) : (n += 1) p.i += 1;
        if (n < min) {
            p.i = start;
            return null;
        }
        return p.s[start..p.i];
    }

    fn tag(p: *TypeParser, depth: usize) TypeErr!types.TypeTag {
        p.nodes += 1;
        if (p.nodes > max_type_nodes) return error.Nodes;
        if (depth >= max_type_depth) return error.Depth;
        const prims = .{ .{ "u8", types.TypeTag.u8 }, .{ "u16", types.TypeTag.u16 }, .{ "u32", types.TypeTag.u32 }, .{ "u64", types.TypeTag.u64 }, .{ "u128", types.TypeTag.u128 }, .{ "u256", types.TypeTag.u256 }, .{ "bool", types.TypeTag.bool }, .{ "address", types.TypeTag.address }, .{ "signer", types.TypeTag.signer } };
        inline for (prims) |pr| if (p.lit(pr[0])) return pr[1];
        const start = p.i;
        if (p.lit("vector<")) {
            const inner = p.tag(depth + 1) catch |e| switch (e) {
                // the struct branch cannot match at `vector<` either
                error.Backtrack => {
                    p.i = start;
                    return error.Backtrack;
                },
                else => return e,
            };
            if (!p.lit(">")) {
                p.i = start;
                return error.Backtrack;
            }
            const x = try p.arena.create(types.TypeTag);
            x.* = inner;
            return .{ .vector = x };
        }
        return .{ .@"struct" = try p.structTag(depth) };
    }

    fn structTag(p: *TypeParser, depth: usize) TypeErr!@FieldType(types.TypeTag, "struct") {
        const start = p.i;
        errdefer p.i = start;
        if (!p.lit("0x")) return error.Backtrack;
        const hs = p.i;
        while (p.i < p.s.len and p.i - hs < 64 and std.ascii.isHex(p.s[p.i])) p.i += 1;
        if (p.i == hs) return error.Backtrack;
        var buf: [64]u8 = @splat('0');
        @memcpy(buf[64 - (p.i - hs) ..], p.s[hs..p.i]);
        var addr: Id = undefined;
        _ = std.fmt.hexToBytes(&addr, &buf) catch return error.Backtrack;
        if (!p.lit("::")) return error.Backtrack;
        const module = p.ident() orelse return error.Backtrack;
        if (!p.lit("::")) return error.Backtrack;
        const name = p.ident() orelse return error.Backtrack;
        // opt("<" separated(1.., delimited(space0, type_tag, space0), ",") ">")
        var args: []const types.TypeTag = &.{};
        const save = p.i;
        if (p.lit("<")) gen: {
            var list: std.ArrayList(types.TypeTag) = .empty;
            p.space0();
            const first = p.tag(depth + 1) catch |e| switch (e) {
                error.Backtrack => {
                    p.i = save;
                    break :gen;
                },
                else => return e,
            };
            p.space0();
            try list.append(p.arena, first);
            while (true) {
                const before = p.i;
                if (!p.lit(",")) break;
                p.space0();
                const t = p.tag(depth + 1) catch |e| switch (e) {
                    error.Backtrack => {
                        p.i = before;
                        break;
                    },
                    else => return e,
                };
                p.space0();
                try list.append(p.arena, t);
            }
            if (!p.lit(">")) {
                p.i = save;
                break :gen;
            }
            args = list.items;
        }
        return .{ .address = .{ .@"0" = addr }, .module = .{ .@"0" = module }, .name = .{ .@"0" = name }, .type_args = args };
    }
};

/// `TypeTag::from_str` (sui-sdk-types): ok, or the failure's label (`extract_message`: the depth
/// and node-count limits name themselves; any other failure has none).
pub const TypeParse = union(enum) { ok: types.TypeTag, err: ?[]const u8 };

pub fn parseType(arena: Allocator, s: []const u8) Allocator.Error!TypeParse {
    var p: TypeParser = .{ .arena = arena, .s = s };
    const t = p.tag(0) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Backtrack => return .{ .err = null },
        error.Depth => return .{ .err = "type exceeds the maximum nesting depth of 128" },
        error.Nodes => return .{ .err = "type exceeds the maximum node count of 256" },
    };
    return if (p.i == s.len) .{ .ok = t } else .{ .err = null };
}

/// `TypeTag::from_str`, null on any failure.
pub fn parseTypeTag(arena: Allocator, s: []const u8) Allocator.Error!?types.TypeTag {
    return switch (try parseType(arena, s)) {
        .ok => |t| t,
        .err => null,
    };
}

/// `TypeParseError`'s Display.
pub fn typeParseError(arena: Allocator, s: []const u8, label: ?[]const u8) Allocator.Error![]const u8 {
    if (label) |l| return std.fmt.allocPrint(arena, "unable to parse type \"{s}\": {s}", .{ s, l });
    return std.fmt.allocPrint(arena, "unable to parse type \"{s}\"", .{s});
}

/// `Identifier::from_str` (sui-sdk-types `parse_identifier`).
fn sdkIdentifier(s: []const u8) bool {
    var p: TypeParser = .{ .arena = undefined, .s = s };
    _ = p.ident() orelse return false;
    return p.i == s.len;
}

/// `TypeInput::from(TypeTag)` (recursion bounded by `max_type_depth`).
pub fn toInput(arena: Allocator, t: *const types.TypeTag) Allocator.Error!types.TypeInput {
    return switch (t.*) {
        .bool => .bool,
        .u8 => .u8,
        .u16 => .u16,
        .u32 => .u32,
        .u64 => .u64,
        .u128 => .u128,
        .u256 => .u256,
        .address => .address,
        .signer => .signer,
        .vector => |inner| blk: {
            const x = try arena.create(types.TypeInput);
            x.* = try toInput(arena, inner);
            break :blk .{ .vector = x };
        },
        .@"struct" => |s| blk: {
            const args = try arena.alloc(types.TypeInput, s.type_args.len);
            for (s.type_args, args) |*a, *o| o.* = try toInput(arena, a);
            break :blk .{ .@"struct" = .{ .address = s.address, .module = .{ .@"0" = s.module.@"0" }, .name = .{ .@"0" = s.name.@"0" }, .type_args = args } };
        },
    };
}

// ---- commands (sui_sdk_types::Command::try_from, then into sui_types) --------------------------

/// A conversion result: the value, or `TryFromProtoError`'s Display ("error converting from
/// protobuf: field: F reason: R[ description: D]").
fn Conv(comptime T: type) type {
    return union(enum) { ok: T, err: []const u8 };
}

fn protoMissing(arena: Allocator, field: []const u8) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(arena, "error converting from protobuf: field: {s} reason: FIELD_MISSING", .{field});
}
fn protoInvalid(arena: Allocator, field: []const u8, description: []const u8) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(arena, "error converting from protobuf: field: {s} reason: FIELD_INVALID description: {s}", .{ field, description });
}

/// `Argument::try_from` (kind: GAS 1, INPUT 2, RESULT 3; anything else is UNKNOWN).
fn parseArgument(arena: Allocator, msg: []const u8) (DecodeError)!Conv(types.Argument) {
    var kind: u64 = 0;
    var input: ?u32 = null;
    var result: ?u32 = null;
    var sub: ?u32 = null;
    var r = proto.Reader.init(msg);
    while (try r.next()) |f| switch (f.number) {
        1 => kind = try proto.Reader.varintOf(f),
        2 => input = @truncate(try proto.Reader.varintOf(f)),
        3 => result = @truncate(try proto.Reader.varintOf(f)),
        4 => sub = @truncate(try proto.Reader.varintOf(f)),
        else => {},
    };
    switch (kind) {
        1 => return .{ .ok = .GasCoin },
        2 => {
            const i = input orelse return .{ .err = try protoMissing(arena, "input") };
            const x = std.math.cast(u16, i) orelse return .{ .err = try protoInvalid(arena, "input", int_range_error) };
            return .{ .ok = .{ .Input = x } };
        },
        3 => {
            const res = result orelse return .{ .err = try protoMissing(arena, "result") };
            const x = std.math.cast(u16, res) orelse return .{ .err = try protoInvalid(arena, "result", int_range_error) };
            const s = sub orelse return .{ .ok = .{ .Result = x } };
            const y = std.math.cast(u16, s) orelse return .{ .err = try protoInvalid(arena, "subresult", int_range_error) };
            return .{ .ok = .{ .NestedResult = .{ x, y } } };
        },
        else => return .{ .err = try protoInvalid(arena, "kind", "unknown ArgumentKind") },
    }
}

fn parseArgs(arena: Allocator, raws: []const []const u8) DecodeError!Conv([]const types.Argument) {
    const out = try arena.alloc(types.Argument, raws.len);
    for (raws, out) |m, *o| switch (try parseArgument(arena, m)) {
        .ok => |a| o.* = a,
        .err => |e| return .{ .err = e },
    };
    return .{ .ok = out };
}

fn parseAddrField(arena: Allocator, field: []const u8, s: ?[]const u8) Allocator.Error!Conv(Id) {
    const v = s orelse return .{ .err = try protoMissing(arena, field) };
    return if (parseAddress(v)) |a| .{ .ok = a } else .{ .err = try protoInvalid(arena, field, address_parse_error) };
}

fn parseDeps(arena: Allocator, deps: []const []const u8) Allocator.Error!Conv([]const types.ObjectID) {
    const out = try arena.alloc(types.ObjectID, deps.len);
    for (deps, out) |d, *o| o.* = .{ .@"0" = .{ .@"0" = parseAddress(d) orelse return .{ .err = try protoInvalid(arena, "dependencies", address_parse_error) } } };
    return .{ .ok = out };
}

/// `sui_sdk_types::Command::try_from(&proto)`, field checks in the Rust order, then the
/// conversion into sui_types (type tags become TypeInputs).
fn parseCommand(arena: Allocator, msg: []const u8) DecodeError!Conv(types.Command) {
    // oneof command { move_call 1, transfer_objects 2, split_coins 3, merge_coins 4, publish 5,
    // make_move_vector 6, upgrade 7 }: the last variant wins; repeats of it merge
    var r = proto.Reader.init(msg);
    var which: u32 = 0;
    var body: std.ArrayList(u8) = .empty;
    while (try r.next()) |f| if (f.number >= 1 and f.number <= 7) {
        if (f.number != which) body.clearRetainingCapacity();
        which = f.number;
        try body.appendSlice(arena, try proto.Reader.bytesOf(f));
    };
    if (which == 0) return .{ .err = try protoMissing(arena, "command") };
    // the message's fields, prost style: strings keep the last occurrence, repeated fields append
    var s1: ?[]const u8 = null;
    var s2: ?[]const u8 = null;
    var s3: ?[]const u8 = null;
    var arg1: ?std.ArrayList(u8) = null;
    var arg2: ?std.ArrayList(u8) = null;
    var arg4: ?std.ArrayList(u8) = null;
    var rep1: std.ArrayList([]const u8) = .empty;
    var rep2: std.ArrayList([]const u8) = .empty;
    var rep4: std.ArrayList([]const u8) = .empty;
    var rep5: std.ArrayList([]const u8) = .empty;
    var br = proto.Reader.init(body.items);
    while (try br.next()) |f| {
        const b = try proto.Reader.bytesOf(f);
        switch (which) {
            1 => switch (f.number) { // MoveCall
                1 => s1 = b,
                2 => s2 = b,
                3 => s3 = b,
                4 => try rep4.append(arena, b),
                5 => try rep5.append(arena, b),
                else => {},
            },
            2 => switch (f.number) { // TransferObjects { objects 1, address 2 }
                1 => try rep1.append(arena, b),
                2 => {
                    if (arg2 == null) arg2 = .empty;
                    try arg2.?.appendSlice(arena, b);
                },
                else => {},
            },
            3, 4 => switch (f.number) { // SplitCoins { coin 1, amounts 2 } / MergeCoins { coin 1, coins_to_merge 2 }
                1 => {
                    if (arg1 == null) arg1 = .empty;
                    try arg1.?.appendSlice(arena, b);
                },
                2 => try rep2.append(arena, b),
                else => {},
            },
            5 => switch (f.number) { // Publish { modules 1, dependencies 2 }
                1 => try rep1.append(arena, b),
                2 => try rep2.append(arena, b),
                else => {},
            },
            6 => switch (f.number) { // MakeMoveVector { element_type 1, elements 2 }
                1 => s1 = b,
                2 => try rep2.append(arena, b),
                else => {},
            },
            7 => switch (f.number) { // Upgrade { modules 1, dependencies 2, package 3, ticket 4 }
                1 => try rep1.append(arena, b),
                2 => try rep2.append(arena, b),
                3 => s3 = b,
                4 => {
                    if (arg4 == null) arg4 = .empty;
                    try arg4.?.appendSlice(arena, b);
                },
                else => {},
            },
            else => {},
        }
    }
    switch (which) {
        1 => {
            const pkg = switch (try parseAddrField(arena, "package", s1)) {
                .ok => |a| a,
                .err => |e| return .{ .err = e },
            };
            const m = s2 orelse return .{ .err = try protoMissing(arena, "module") };
            if (!sdkIdentifier(m)) return .{ .err = try protoInvalid(arena, "module", try typeParseError(arena, m, null)) };
            const fun = s3 orelse return .{ .err = try protoMissing(arena, "function") };
            if (!sdkIdentifier(fun)) return .{ .err = try protoInvalid(arena, "function", try typeParseError(arena, fun, null)) };
            const targs = try arena.alloc(types.TypeInput, rep4.items.len);
            for (rep4.items, targs) |s, *o| switch (try parseType(arena, s)) {
                .ok => |t| o.* = try toInput(arena, &t),
                .err => |l| return .{ .err = try protoInvalid(arena, "type_arguments", try typeParseError(arena, s, l)) },
            };
            const args = switch (try parseArgs(arena, rep5.items)) {
                .ok => |a| a,
                .err => |e| return .{ .err = e },
            };
            return .{ .ok = .{ .MoveCall = .{ .package = .{ .@"0" = .{ .@"0" = pkg } }, .module = .{ .@"0" = m }, .function = .{ .@"0" = fun }, .type_arguments = targs, .arguments = @constCast(args) } } };
        },
        2 => {
            const objs = switch (try parseArgs(arena, rep1.items)) {
                .ok => |a| a,
                .err => |e| return .{ .err = e },
            };
            const am = arg2 orelse return .{ .err = try protoMissing(arena, "address") };
            const addr = switch (try parseArgument(arena, am.items)) {
                .ok => |a| a,
                .err => |e| return .{ .err = e },
            };
            return .{ .ok = .{ .TransferObjects = .{ @constCast(objs), addr } } };
        },
        3, 4 => {
            const cm = arg1 orelse return .{ .err = try protoMissing(arena, "coin") };
            const coin = switch (try parseArgument(arena, cm.items)) {
                .ok => |a| a,
                .err => |e| return .{ .err = e },
            };
            const list = switch (try parseArgs(arena, rep2.items)) {
                .ok => |a| a,
                .err => |e| return .{ .err = e },
            };
            return .{ .ok = if (which == 3) .{ .SplitCoins = .{ coin, @constCast(list) } } else .{ .MergeCoins = .{ coin, @constCast(list) } } };
        },
        5 => {
            const deps = switch (try parseDeps(arena, rep2.items)) {
                .ok => |d| d,
                .err => |e| return .{ .err = e },
            };
            return .{ .ok = .{ .Publish = .{ rep1.items, @constCast(deps) } } };
        },
        6 => {
            var ty: ?types.TypeInput = null;
            if (s1) |s| switch (try parseType(arena, s)) {
                .ok => |t| ty = try toInput(arena, &t),
                .err => |l| return .{ .err = try protoInvalid(arena, "element_type", try typeParseError(arena, s, l)) },
            };
            const elems = switch (try parseArgs(arena, rep2.items)) {
                .ok => |a| a,
                .err => |e| return .{ .err = e },
            };
            return .{ .ok = .{ .MakeMoveVec = .{ ty, @constCast(elems) } } };
        },
        7 => {
            const deps = switch (try parseDeps(arena, rep2.items)) {
                .ok => |d| d,
                .err => |e| return .{ .err = e },
            };
            const pkg = switch (try parseAddrField(arena, "package", s3)) {
                .ok => |a| a,
                .err => |e| return .{ .err = e },
            };
            const tm = arg4 orelse return .{ .err = try protoMissing(arena, "ticket") };
            const ticket = switch (try parseArgument(arena, tm.items)) {
                .ok => |a| a,
                .err => |e| return .{ .err = e },
            };
            return .{ .ok = .{ .Upgrade = .{ rep1.items, @constCast(deps), .{ .@"0" = .{ .@"0" = pkg } }, ticket } } };
        },
        else => unreachable,
    }
}
fn commandArgs(c: *const types.Command) usize {
    return switch (c.*) {
        .MoveCall => |m| m.arguments.len,
        .TransferObjects => |t| t[0].len,
        .SplitCoins => |s| s[1].len,
        .MergeCoins => |m| m[1].len,
        .MakeMoveVec => |v| v[1].len,
        .Publish, .Upgrade => 0,
    };
}

// ---- expiration ---------------------------------------------------------------------------------

/// The two conversions of a `TransactionExpiration` proto sui-node uses:
/// - `.sdk`: sui-rpc's `sui_sdk_types::TransactionExpiration::try_from` (the fully formed path):
///   timestamps keep the raw `seconds` (`timestamp.seconds as _`), allowed proposers may be empty;
/// - `.resolve`: sui-types `rpc_proto_conversions` `TransactionExpiration::try_from` (resolution):
///   `timestamp_to_ms` (negative or overflowing timestamps are errors), allowed proposers must
///   not be empty, and the errors carry sui-types' texts.
/// Both read a missing `epoch` of an Epoch expiration as 0.
pub const ExpMode = enum { sdk, resolve };

const Timestamp = struct { seconds: i64 = 0, nanos: i32 = 0 };

fn parseTimestamp(msg: []const u8) DecodeError!Timestamp {
    var t: Timestamp = .{};
    var r = proto.Reader.init(msg);
    while (try r.next()) |f| switch (f.number) {
        1 => t.seconds = @bitCast(try proto.Reader.varintOf(f)),
        2 => t.nanos = @bitCast(@as(u32, @truncate(try proto.Reader.varintOf(f)))),
        else => {},
    };
    return t;
}

/// sui-types `timestamp_to_ms`.
fn timestampToMs(t: Timestamp) Conv(u64) {
    const secs = std.math.cast(u64, t.seconds) orelse return .{ .err = "invalid timestamp: negative seconds" };
    const nanos = std.math.cast(u64, t.nanos) orelse return .{ .err = "invalid timestamp: negative nanos" };
    const ms = std.math.mul(u64, secs, 1000) catch return .{ .err = "invalid timestamp: out of range" };
    return .{ .ok = std.math.add(u64, ms, nanos / 1_000_000) catch return .{ .err = "invalid timestamp: out of range" } };
}

fn parseExpiration(arena: Allocator, msg: []const u8, mode: ExpMode) DecodeError!Conv(types.TransactionExpiration) {
    var kind: u64 = 0;
    var epoch: ?u64 = null;
    var min_epoch: ?u64 = null;
    var min_ts: ?std.ArrayList(u8) = null;
    var max_ts: ?std.ArrayList(u8) = null;
    var chain_s: ?[]const u8 = null;
    var nonce: ?u32 = null;
    var ap: ?std.ArrayList(u8) = null;
    var r = proto.Reader.init(msg);
    while (try r.next()) |f| switch (f.number) {
        1 => kind = try proto.Reader.varintOf(f),
        2 => epoch = try proto.Reader.varintOf(f),
        3 => min_epoch = try proto.Reader.varintOf(f),
        4 => {
            if (min_ts == null) min_ts = .empty;
            try min_ts.?.appendSlice(arena, try proto.Reader.bytesOf(f));
        },
        5 => {
            if (max_ts == null) max_ts = .empty;
            try max_ts.?.appendSlice(arena, try proto.Reader.bytesOf(f));
        },
        6 => chain_s = try proto.Reader.stringOf(f),
        7 => nonce = @truncate(try proto.Reader.varintOf(f)),
        8 => {
            if (ap == null) ap = .empty;
            try ap.?.appendSlice(arena, try proto.Reader.bytesOf(f));
        },
        else => {},
    };
    const unknown: []const u8 = "unknown TransactionExpirationKind";
    switch (kind) {
        1 => return .{ .ok = .None },
        2 => return .{ .ok = .{ .Epoch = epoch orelse 0 } },
        3, 4 => {},
        else => return .{ .err = unknown },
    }
    var allowed: ?types.AllowedProposers = null;
    if (ap) |list| {
        var e: u64 = 0;
        var props: std.ArrayList(u32) = .empty;
        var ar = proto.Reader.init(list.items);
        while (try ar.next()) |g| switch (g.number) {
            1 => e = try proto.Reader.varintOf(g),
            2 => if (g.wire == 2) {
                var pr = proto.Reader.init(try proto.Reader.bytesOf(g));
                while (pr.pos < pr.buf.len) try props.append(arena, @truncate(try pr.varint()));
            } else try props.append(arena, @truncate(try proto.Reader.varintOf(g))),
            else => {},
        };
        allowed = .{ .epoch = e, .proposers = props.items };
    }
    const sdk = mode == .sdk;
    const chain_str = chain_s orelse return .{ .err = if (sdk) "chain missing" else "ValidDuring expiration is missing chain" };
    const chain = parseDigest(chain_str) orelse return .{ .err = if (sdk) "chain invalid" else "ValidDuring expiration has invalid chain digest" };
    const n = nonce orelse return .{ .err = if (sdk) "nonce missing" else "ValidDuring expiration is missing nonce" };
    var mins: ?u64 = null;
    var maxs: ?u64 = null;
    inline for (.{ .{ &min_ts, &mins }, .{ &max_ts, &maxs } }) |pair| if (pair[0].*) |b| {
        const t = try parseTimestamp(b.items);
        pair[1].* = if (sdk) @bitCast(t.seconds) else switch (timestampToMs(t)) {
            .ok => |ms| ms,
            .err => |e| return .{ .err = e },
        };
    };
    const chain_id: types.ChainIdentifier = .{ .@"0" = .{ .@"0" = .{ .@"0" = chain } } };
    if (kind == 3) return .{ .ok = .{ .ValidDuring = .{ .min_epoch = min_epoch, .max_epoch = epoch, .min_timestamp = mins, .max_timestamp = maxs, .chain = chain_id, .nonce = n } } };
    if (!sdk) if (allowed) |a| if (a.proposers.len == 0) return .{ .err = "allowed_proposers must not be empty" };
    return .{ .ok = .{ .Validity = .{ .min_epoch = min_epoch, .max_epoch = epoch, .min_timestamp = mins, .max_timestamp = maxs, .chain = chain_id, .nonce = n, .allowed_proposers = allowed } } };
}

// ---- funds withdrawals --------------------------------------------------------------------------

/// `UnresolvedInput::from_proto`'s funds withdrawal: a FieldViolation per field, in field order.
fn parseFunds(arena: Allocator, msg: []const u8) DecodeError!union(enum) { ok: types.FundsWithdrawalArg, err: Error } {
    var amount: ?u64 = null;
    var coin: []const u8 = "";
    var source: u64 = 0;
    var funder: []const u8 = "";
    var allowance: []const u8 = "";
    var r = proto.Reader.init(msg);
    while (try r.next()) |f| switch (f.number) {
        1 => amount = try proto.Reader.varintOf(f),
        2 => coin = try proto.Reader.stringOf(f),
        3 => source = try proto.Reader.varintOf(f),
        4 => funder = try proto.Reader.stringOf(f),
        5 => allowance = try proto.Reader.stringOf(f),
        else => {},
    };
    const amt = amount orelse return .{ .err = .{ .bad = .{ .field = "amount", .description = "", .reason = .field_missing } } };
    // Rust parses coin_type with move-core-types' TypeTag::from_str; the grammar and limits used
    // here are sui-sdk-types' (the bounded parser), and the error text names the type the same way
    const t = switch (try parseType(arena, coin)) {
        .ok => |t| t,
        .err => |l| return .{ .err = .{ .bad = .{ .field = "coin_type", .description = try std.fmt.allocPrint(arena, "invalid coin_type: {s}", .{try typeParseError(arena, coin, l)}), .reason = .field_invalid } } },
    };
    const from: @FieldType(types.FundsWithdrawalArg, "withdraw_from") = switch (source) {
        2 => .Sponsor,
        3 => .{ .SenderAllowance = .{
            .funder = .{ .@"0" = parseSuiAddress(funder) orelse return .{ .err = .{ .bad = .{ .field = "funder", .description = "invalid funder: " ++ sui_address_parse_error, .reason = .field_invalid } } } },
            .allowance = .{ .@"0" = .{ .@"0" = parseObjectId(allowance) orelse return .{ .err = .{ .bad = .{ .field = "allowance", .description = "invalid allowance: " ++ object_id_parse_error, .reason = .field_invalid } } } } },
        } },
        else => .Sender,
    };
    return .{ .ok = .{ .reservation = .{ .MaxAmountU64 = amt }, .type_arg = .{ .Balance = t }, .withdraw_from = from } };
}
// ---- the fully formed path ----------------------------------------------------------------------

/// `sui_sdk_types::Transaction::try_from(&proto)` then `TransactionData::try_from`: null when a
/// field it needs is missing or malformed (the caller then resolves).
fn fullyFormed(arena: Allocator, q: *const Request) (DecodeError)!?types.TransactionDataV1 {
    if ((q.version orelse return null) != 1) return null;
    if (!q.has_ptb) return null;
    const sender = parseAddress(q.sender orelse return null) orelse return null;
    const g = q.gas orelse return null;
    const exp_msg = q.expiration orelse return null;
    const inputs = try arena.alloc(types.CallArg, q.inputs.len);
    for (q.inputs, inputs) |in, *o| {
        o.* = switch (in.kind orelse return null) {
            1 => .{ .Pure = in.pure orelse return null },
            2, 4 => blk: {
                const id = parseAddress(in.object_id orelse return null) orelse return null;
                const v = in.version orelse return null;
                const d = parseDigest(in.digest orelse return null) orelse return null;
                const ref = .{ types.ObjectID{ .@"0" = .{ .@"0" = id } }, types.SequenceNumber{ .@"0" = v }, types.ObjectDigest{ .@"0" = .{ .@"0" = d } } };
                break :blk .{ .Object = if (in.kind.? == 2) .{ .ImmOrOwnedObject = ref } else .{ .Receiving = ref } };
            },
            3 => blk: {
                const id = parseAddress(in.object_id orelse return null) orelse return null;
                const isv = in.version orelse return null;
                const m: types.SharedObjectMutability = switch (in.mutability orelse 0) {
                    0 => if (in.mutable orelse return null) .Mutable else .Immutable,
                    1 => .Immutable,
                    2 => .Mutable,
                    3 => .NonExclusiveWrite,
                    else => return null,
                };
                break :blk .{ .Object = .{ .SharedObject = .{ .id = .{ .@"0" = .{ .@"0" = id } }, .initial_shared_version = .{ .@"0" = isv }, .mutability = m } } };
            },
            5 => .{ .FundsWithdrawal = switch (try parseFunds(arena, in.funds orelse return null)) {
                .ok => |w| w,
                .err => return null,
            } },
            else => return null,
        };
    }
    const commands = try arena.alloc(types.Command, q.commands.len);
    for (q.commands, commands) |c, *o| o.* = switch (try parseCommand(arena, c)) {
        .ok => |x| x,
        .err => return null,
    };
    const pay = try arena.alloc(@typeInfo(@TypeOf(@as(types.GasData, undefined).payment)).pointer.child, g.objects.len);
    for (g.objects, pay) |ref, *o| {
        const id = parseAddress(ref.object_id orelse return null) orelse return null;
        const d = parseDigest(ref.digest orelse return null) orelse return null;
        o.* = .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = ref.version orelse return null }, .{ .@"0" = .{ .@"0" = d } } };
    }
    const owner = parseAddress(g.owner orelse return null) orelse return null;
    const exp = switch (try parseExpiration(arena, exp_msg, .sdk)) {
        .ok => |x| x,
        .err => return null,
    };
    return .{
        .kind = .{ .ProgrammableTransaction = .{ .inputs = inputs, .commands = commands } },
        .sender = .{ .@"0" = sender },
        .gas_data = .{ .payment = pay, .owner = .{ .@"0" = owner }, .price = g.price orelse return null, .budget = g.budget orelse return null },
        .expiration = exp,
    };
}

// ---- resolution -----------------------------------------------------------------------------------

pub const Env = struct {
    cfg: *const protocol.ProtocolConfig,
    rgp: u64,
    chain_id: Id,
    pkgs: *const exec.packages.Store,
    epoch: u64,
};

fn bad(field: []const u8, description: []const u8, reason: Reason) Result {
    return .{ .err = .{ .bad = .{ .field = field, .description = description, .reason = reason } } };
}
fn status(code: u8, message: []const u8) Result {
    return .{ .err = .{ .status = .{ .code = code, .message = message } } };
}
fn notFound(arena: Allocator, id: *const Id) Allocator.Error!Result {
    return status(code_not_found, try std.fmt.allocPrint(arena, "Object {s} not found", .{checks.hex(id).s()}));
}

/// Resolves the request's transaction. `q` comes from `parse`.
pub fn resolve(arena: Allocator, env: *const Env, state: State, q: *const Request) Allocator.Error!Result {
    if (fullyFormed(arena, q) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => null,
    }) |td| return .{ .ok = td };

    const sender = parseAddress(q.sender orelse "") orelse
        return bad("transaction.sender", "invalid sender: " ++ address_parse_error, .field_invalid);
    if (!q.has_ptb) return bad("transaction.kind.programmable_transaction", "", .field_missing);

    const commands = try arena.alloc(types.Command, q.commands.len);
    for (q.commands, commands) |c, *o| o.* = switch (parseCommand(arena, c) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        // prost failed to decode the request: not reached for a request `parse` accepted
        else => return bad("commands", "invalid command", .field_invalid),
    }) {
        .ok => |x| x,
        .err => |e| return bad("commands", try std.fmt.allocPrint(arena, "invalid command: {s}", .{e}), .field_invalid),
    };

    // enforce_ptb_structural_limits
    const cfg = env.cfg;
    if (cfg.max_programmable_tx_commands) |max| if (commands.len >= max)
        return status(code_invalid_argument, try std.fmt.allocPrint(arena, "programmable transaction has too many commands: {d} (limit {d})", .{ commands.len, max }));
    if (cfg.max_input_objects) |max| if (q.inputs.len > max)
        return status(code_invalid_argument, try std.fmt.allocPrint(arena, "programmable transaction has too many inputs: {d} (limit {d})", .{ q.inputs.len, max }));
    if (cfg.max_arguments) |max| for (commands) |*c| if (commandArgs(c) >= max)
        return status(code_invalid_argument, try std.fmt.allocPrint(arena, "programmable transaction command has too many arguments: {d} (limit {d})", .{ commandArgs(c), max }));

    // called_packages: every MoveCall package must be a live package
    var pkgs: Pkgs = .{ .arena = arena, .state = state, .env = env };
    for (commands) |*c| switch (c.*) {
        .MoveCall => |m| {
            const pid = m.package.@"0".@"0";
            if (pkgs.raw(&pid) == null) {
                const live = state.latest(&pid) orelse return notFound(arena, &pid);
                _ = live;
                return status(code_invalid_argument, try std.fmt.allocPrint(arena, "object {s} is not a package", .{checks.hex(&pid).s()}));
            }
        },
        else => {},
    };

    // gas data
    const max_budget = cfg.max_tx_gas orelse 0;
    var gas: types.GasData = undefined;
    if (q.gas) |g| {
        const pay = try arena.alloc(@typeInfo(@TypeOf(gas.payment)).pointer.child, g.objects.len);
        var total: u64 = 0;
        for (g.objects, pay) |ref, *o| {
            const id = parseAddress(ref.object_id orelse "") orelse return bad("object_id", "invalid object_id: " ++ address_parse_error, .field_invalid);
            var digest: ?Id = null;
            if (ref.digest) |ds| digest = parseDigest(ds) orelse return bad("digest", "invalid digest: " ++ digest_parse_error, .field_invalid);
            if (digest) |d| if (exec.inputs.isCoinReservation(&d)) {
                o.* = .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = ref.version orelse 0 }, .{ .@"0" = .{ .@"0" = d } } };
                total +|= std.mem.readInt(u64, d[0..8], .little);
                continue;
            };
            const raw = state.latest(&id) orelse return notFound(arena, &id);
            const v = ObjectView.parse(raw) catch return notFound(arena, &id);
            const value = gasCoinValue(raw, &v) orelse
                return bad("payment", try std.fmt.allocPrint(arena, "object {s} is not a valid gas coin", .{checks.hex(&id).s()}), .field_invalid);
            switch (try checkRef(arena, raw, &v, ref.version, digest)) {
                .ok => |r| o.* = r,
                .err => |e| return .{ .err = e },
            }
            total +|= value;
        }
        const budget_cap = if (pay.len == 0) max_budget else @min(total, max_budget);
        // GasData.owner is a sui-types SuiAddress
        const owner = parseSuiAddress(g.owner orelse "") orelse
            return bad("owner", "invalid owner: " ++ sui_address_parse_error, .field_invalid);
        gas = .{ .payment = pay, .owner = .{ .@"0" = owner }, .price = g.price orelse env.rgp, .budget = g.budget orelse budget_cap };
    } else gas = .{ .payment = &.{}, .owner = .{ .@"0" = sender }, .price = env.rgp, .budget = max_budget };

    const expiration: types.TransactionExpiration = if (q.expiration) |m| switch (parseExpiration(arena, m, .resolve) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return bad("expiration", "invalid expiration", .field_invalid),
    }) {
        .ok => |x| x,
        .err => |e| return bad("expiration", e, .field_invalid),
    } else .None;

    // resolve_ptb
    const uses = try ArgUses.build(arena, q.inputs.len, commands);
    const inputs = try arena.alloc(types.CallArg, q.inputs.len);
    for (q.inputs, inputs, 0..) |*in, *o, idx| {
        switch (try resolveArg(arena, state, &pkgs, &uses, commands, in, idx)) {
            .ok => |a| o.* = a,
            .err => |e| return .{ .err = e },
            .unimplemented => |why| return .{ .unimplemented = why },
        }
    }
    return .{ .ok = .{
        .kind = .{ .ProgrammableTransaction = .{ .inputs = inputs, .commands = commands } },
        .sender = .{ .@"0" = sender },
        .gas_data = gas,
        .expiration = expiration,
    } };
}

/// GasCoin::try_from: a `0x2::coin::Coin<0x2::sui::SUI>` Move object; its value.
pub fn gasCoinValue(raw: []const u8, v: *const ObjectView) ?u64 {
    if (v.is_package or raw.len < 2 or raw[0] != 0 or raw[1] != 1) return null; // MoveObjectType_::GasCoin
    const c = v.contents();
    if (c.len != 40) return null;
    return std.mem.readInt(u64, c[32..40], .little);
}

const Ref = struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest };
const RefResult = union(enum) { ok: Ref, err: Error };

/// `resolve_object_reference_with_object`.
fn checkRef(arena: Allocator, raw: []const u8, v: *const ObjectView, version: ?u64, digest: ?Id) Allocator.Error!RefResult {
    const owner_tag = raw[v.owner_at];
    if (owner_tag != 0 and owner_tag != 3) // AddressOwner, Immutable
        return .{ .err = .{ .status = .{ .code = code_invalid_argument, .message = try std.fmt.allocPrint(arena, "object {s} is not Immutable or AddressOwned", .{checks.hex(&v.id).s()}) } } };
    const d = v.digest();
    if (version) |ver| if (ver != v.version)
        return .{ .err = .{ .status = .{ .code = code_invalid_argument, .message = try std.fmt.allocPrint(arena, "provided version doesn't match for object {s}, provided: {d} actual: {d}", .{ checks.hex(&v.id).s(), ver, v.version }) } } };
    if (digest) |want| if (!std.mem.eql(u8, &want, &d))
        return .{ .err = .{ .status = .{ .code = code_invalid_argument, .message = try std.fmt.allocPrint(arena, "provided digest doesn't match for object {s}, provided: {s} actual: {s}", .{ checks.hex(&v.id).s(), try checks.b58(arena, &want), try checks.b58(arena, &d) }) } } };
    return .{ .ok = .{ .{ .@"0" = .{ .@"0" = v.id } }, .{ .@"0" = v.version }, .{ .@"0" = .{ .@"0" = d } } } };
}

const ArgResult = union(enum) { ok: types.CallArg, err: Error, unimplemented: []const u8 };

fn resolveArg(arena: Allocator, state: State, pkgs: *Pkgs, uses: *const ArgUses, commands: []const types.Command, in: *const PInput, idx: usize) Allocator.Error!ArgResult {
    // UnresolvedInput::from_proto: object_id, digest and funds_withdrawal parse first
    var parsed_id: ?Id = null;
    if (in.object_id) |s| parsed_id = parseAddress(s) orelse return .{ .err = .{ .bad = .{ .field = "object_id", .description = "invalid object_id: " ++ address_parse_error, .reason = .field_invalid } } };
    var digest: ?Id = null;
    if (in.digest) |ds| digest = parseDigest(ds) orelse return .{ .err = .{ .bad = .{ .field = "digest", .description = "invalid digest: " ++ digest_parse_error, .reason = .field_invalid } } };
    var funds: ?types.FundsWithdrawalArg = null;
    if (in.funds) |fm| funds = switch (parseFunds(arena, fm) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return invalidInput(),
    }) {
        .ok => |w| w,
        .err => |e| return .{ .err = e },
    };
    const no_obj = in.object_id == null and in.version == null and in.digest == null and in.mutable == null;
    if (in.literal) {
        if (in.kind == null and in.pure == null and no_obj and in.funds == null) return .{ .unimplemented = "transaction resolution of literal inputs is not supported" };
        return invalidInput();
    }
    // Pure
    if ((in.kind == null or in.kind.? == 1) and in.pure != null and no_obj and in.funds == null) return .{ .ok = .{ .Pure = in.pure.? } };
    // FundsWithdrawal
    if ((in.kind == null or in.kind.? == 5) and funds != null and in.pure == null and no_obj) return .{ .ok = .{ .FundsWithdrawal = funds.? } };
    if (in.pure != null or in.funds != null or in.object_id == null) return invalidInput();
    const id = parsed_id.?;
    const kind = in.kind orelse 0;
    switch (kind) {
        2, 4 => if (in.mutable != null) return invalidInput(),
        3 => if (in.digest != null) return invalidInput(),
        0 => {},
        else => return invalidInput(),
    }
    // coin reservations (ImmOrOwned, Receiving and unkinded refs)
    if (kind != 3) if (digest) |d| if (exec.inputs.isCoinReservation(&d)) {
        const ref: Ref = .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = in.version orelse 0 }, .{ .@"0" = .{ .@"0" = d } } };
        return .{ .ok = .{ .Object = if (kind == 4) .{ .Receiving = ref } else .{ .ImmOrOwnedObject = ref } } };
    };
    const raw = state.latest(&id) orelse return .{ .err = (try notFound(arena, &id)).err };
    const v = ObjectView.parse(raw) catch return .{ .err = (try notFound(arena, &id)).err };
    if (kind == 3) return shared(arena, pkgs, uses, commands, idx, raw, &v);
    if (kind == 2 or kind == 4) {
        return switch (try checkRef(arena, raw, &v, in.version, digest)) {
            .ok => |r| .{ .ok = .{ .Object = if (kind == 2) .{ .ImmOrOwnedObject = r } else .{ .Receiving = r } } },
            .err => |e| .{ .err = e },
        };
    }
    // resolve_object: by owner
    return switch (raw[v.owner_at]) {
        3 => switch (try checkRef(arena, raw, &v, in.version, digest)) {
            .ok => |r| .{ .ok = .{ .Object = .{ .ImmOrOwnedObject = r } } },
            .err => |e| .{ .err = e },
        },
        0 => switch (try checkRef(arena, raw, &v, in.version, digest)) {
            .ok => |r| blk: {
                const recv = switch (try isReceiving(arena, pkgs, uses, commands, idx)) {
                    .ok => |b| b,
                    .err => |e| break :blk .{ .err = e },
                };
                break :blk .{ .ok = .{ .Object = if (recv) .{ .Receiving = r } else .{ .ImmOrOwnedObject = r } } };
            },
            .err => |e| .{ .err = e },
        },
        1 => .{ .err = .{ .status = .{ .code = code_invalid_argument, .message = try std.fmt.allocPrint(arena, "object {s} is object owned and cannot be used as an input", .{checks.hex(&id).s()}) } } },
        else => shared(arena, pkgs, uses, commands, idx, raw, &v),
    };
}

fn invalidInput() ArgResult {
    return .{ .err = .{ .status = .{ .code = code_invalid_argument, .message = "invalid unresolved input argument" } } };
}

/// `resolve_shared_input_with_object`.
fn shared(arena: Allocator, pkgs: *Pkgs, uses: *const ArgUses, commands: []const types.Command, idx: usize, raw: []const u8, v: *const ObjectView) Allocator.Error!ArgResult {
    const owner = bcs.decode(types.Owner, arena, raw[v.owner_at..v.prev_tx_at]) catch return .{ .err = .{ .status = .{ .code = code_internal, .message = "invalid owner" } } };
    const isv: u64 = switch (owner) {
        .Shared => |s| s.initial_shared_version.@"0",
        .ConsensusAddressOwner => |c| c.start_version.@"0",
        else => return .{ .err = .{ .status = .{ .code = code_invalid_argument, .message = try std.fmt.allocPrint(arena, "object {s} is not a shared or consensus object", .{checks.hex(&v.id).s()}) } } },
    };
    var mutable = false;
    for (uses.of(idx)) |u| {
        const c = &commands[u.cmd];
        switch (c.*) {
            .MoveCall => |*m| if (u.pos) |pos| {
                const t = switch (try pkgs.param(m, pos)) {
                    .ok => |t| t,
                    .err => |e| return .{ .err = e },
                };
                const n = t.tok[0];
                if (n.tag == .MutableReference or n.tag == .Datatype or n.tag == .DatatypeInstantiation or n.tag == .TypeParameter) mutable = true;
            },
            .SplitCoins, .MergeCoins, .MakeMoveVec => mutable = true,
            else => {},
        }
        if (mutable) break;
    }
    return .{ .ok = .{ .Object = .{ .SharedObject = .{
        .id = .{ .@"0" = .{ .@"0" = v.id } },
        .initial_shared_version = .{ .@"0" = isv },
        .mutability = if (mutable) .Mutable else .Immutable,
    } } } };
}

const BoolResult = union(enum) { ok: bool, err: Error };

/// `is_input_argument_receiving`: a MoveCall parameter (through one reference) of type
/// `0x2::transfer::Receiving<_>`.
fn isReceiving(arena: Allocator, pkgs: *Pkgs, uses: *const ArgUses, commands: []const types.Command, idx: usize) Allocator.Error!BoolResult {
    _ = arena;
    for (uses.of(idx)) |u| {
        const c = &commands[u.cmd];
        switch (c.*) {
            .MoveCall => |*m| if (u.pos) |pos| {
                const t = switch (try pkgs.param(m, pos)) {
                    .ok => |t| t,
                    .err => |e| return .{ .err = e },
                };
                var tok = t.tok;
                if (tok[0].tag == .Reference or tok[0].tag == .MutableReference) tok = tok[1..];
                if (tok[0].tag == .Datatype or tok[0].tag == .DatatypeInstantiation) {
                    const dh = t.cm.datatypeHandleAt(tok[0].idx);
                    const mh = t.cm.moduleHandleAt(dh.module);
                    var two: Id = @splat(0);
                    two[31] = 2;
                    if (std.mem.eql(u8, &t.cm.address_identifiers[mh.address], &two) and
                        std.mem.eql(u8, t.cm.identifierAt(mh.name), "transfer") and
                        std.mem.eql(u8, t.cm.identifierAt(dh.name), "Receiving")) return .{ .ok = true };
                }
            },
            else => {},
        }
    }
    return .{ .ok = false };
}

/// `ArgUses`: per input, the commands that use it with the first argument position there
/// (`None` for a coin, address or ticket slot).
const ArgUses = struct {
    const Use = struct { cmd: usize, pos: ?usize };
    lists: []std.ArrayList(Use),

    fn build(arena: Allocator, n: usize, commands: []const types.Command) Allocator.Error!ArgUses {
        const lists = try arena.alloc(std.ArrayList(Use), n);
        for (lists) |*l| l.* = .empty;
        var first: std.AutoArrayHashMapUnmanaged(u16, ?usize) = .empty;
        for (commands, 0..) |*c, ci| {
            first.clearRetainingCapacity();
            const rec = struct {
                fn f(a: Allocator, m: *std.AutoArrayHashMapUnmanaged(u16, ?usize), arg: types.Argument, pos: ?usize) Allocator.Error!void {
                    switch (arg) {
                        .Input => |i| {
                            const g = try m.getOrPut(a, i);
                            if (!g.found_existing) g.value_ptr.* = pos;
                        },
                        else => {},
                    }
                }
            }.f;
            switch (c.*) {
                .MoveCall => |m| for (m.arguments, 0..) |a, i| try rec(arena, &first, a, i),
                .TransferObjects => |t| {
                    try rec(arena, &first, t[1], null);
                    for (t[0], 0..) |a, i| try rec(arena, &first, a, i);
                },
                .SplitCoins => |s| {
                    try rec(arena, &first, s[0], null);
                    for (s[1], 0..) |a, i| try rec(arena, &first, a, i);
                },
                .MergeCoins => |s| {
                    try rec(arena, &first, s[0], null);
                    for (s[1], 0..) |a, i| try rec(arena, &first, a, i);
                },
                .MakeMoveVec => |v| for (v[1], 0..) |a, i| try rec(arena, &first, a, i),
                .Upgrade => |u| try rec(arena, &first, u[3], null),
                .Publish => {},
            }
            // BTreeMap iteration: ascending input index (order within one command does not matter
            // for the per-input lists)
            var it = first.iterator();
            while (it.next()) |e| if (e.key_ptr.* < n) try lists[e.key_ptr.*].append(arena, .{ .cmd = ci, .pos = e.value_ptr.* });
        }
        return .{ .lists = lists };
    }

    fn of(u: *const ArgUses, idx: usize) []const Use {
        return if (idx < u.lists.len) u.lists[idx].items else &.{};
    }
};

/// Called packages: live package objects and their modules' function signatures.
const Pkgs = struct {
    arena: Allocator,
    state: State,
    env: *const Env,
    mods: std.StringHashMapUnmanaged(?*ff.CompiledModule) = .empty,

    const Param = struct { cm: *const ff.CompiledModule, tok: ff.Token };
    const ParamResult = union(enum) { ok: Param, err: Error };

    fn raw(p: *Pkgs, id: *const Id) ?[]const u8 {
        const r = p.env.pkgs.get(id, p.env.epoch) orelse p.state.latest(id) orelse return null;
        const v = ObjectView.parse(r) catch return null;
        return if (v.is_package) r else null;
    }

    fn module(p: *Pkgs, pkg: *const Id, name: []const u8) Allocator.Error!?*ff.CompiledModule {
        const key = try std.fmt.allocPrint(p.arena, "{s}\x00{s}", .{ pkg, name });
        if (p.mods.get(key)) |m| return m;
        const m: ?*ff.CompiledModule = blk: {
            const r = p.raw(pkg) orelse break :blk null;
            const obj = bcs.decode(types.Object, p.arena, r) catch break :blk null;
            const mp = switch (obj.data) {
                .Package => |x| x,
                .Move => break :blk null,
            };
            for (mp.module_map.entries) |e| if (std.mem.eql(u8, e.key.@"0", name)) {
                const cfg: mf.BinaryConfig = .{};
                const res = try mf.deserialize(p.arena, e.value, &cfg);
                switch (res) {
                    .ok => |cm| {
                        const x = try p.arena.create(ff.CompiledModule);
                        x.* = cm;
                        break :blk x;
                    },
                    .err => break :blk null,
                }
            };
            break :blk null;
        };
        try p.mods.put(p.arena, key, m);
        return m;
    }

    /// `arg_type_of_move_call_input`.
    fn param(p: *Pkgs, m: *const types.ProgrammableMoveCall, pos: usize) Allocator.Error!ParamResult {
        const pid = m.package.@"0".@"0";
        const not_found: ParamResult = .{ .err = .{ .status = .{ .code = code_invalid_argument, .message = try std.fmt.allocPrint(p.arena, "unable to find function {s}::{s}::{s}", .{ checks.hex(&pid).s(), m.module.@"0", m.function.@"0" }) } } };
        const cm = (try p.module(&pid, m.module.@"0")) orelse return not_found;
        var found: ?*const ff.FunctionHandle = null;
        for (cm.function_defs) |d| {
            const fh = cm.functionHandleAt(d.function);
            if (std.mem.eql(u8, cm.identifierAt(fh.name), m.function.@"0")) found = fh;
        }
        const fh = found orelse return not_found;
        const params = cm.signatureAt(fh.parameters);
        if (pos >= params.len) return .{ .err = .{ .status = .{ .code = code_invalid_argument, .message = "invalid input parameter" } } };
        return .{ .ok = .{ .cm = cm, .tok = params[pos] } };
    }
};

// ---- coin reservations ------------------------------------------------------------------------

/// `ParsedObjectRefWithdrawal::new(account, epoch, amount).encode(version, chain)`.
pub fn encodeReservation(account: *const Id, epoch: u64, amount: u64, version: u64, chain_id: *const Id) Ref {
    var d: Id = @splat(0xac);
    std.mem.writeInt(u64, d[0..8], amount, .little);
    std.mem.writeInt(u32, d[8..12], @truncate(epoch), .little);
    return .{ .{ .@"0" = .{ .@"0" = checks.unmask(account, chain_id) } }, .{ .@"0" = version }, .{ .@"0" = .{ .@"0" = d } } };
}

test "type tags parse like sui-sdk-types" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const t = (try parseTypeTag(a.allocator(), "0x2::coin::Coin<0x2::sui::SUI>")).?;
    try std.testing.expectEqualStrings("coin", t.@"struct".module.@"0");
    try std.testing.expectEqual(@as(u8, 2), t.@"struct".type_args[0].@"struct".address.@"0"[31]);
    try std.testing.expect((try parseTypeTag(a.allocator(), "vector<u8>")).? == .vector);
    try std.testing.expect((try parseTypeTag(a.allocator(), "0x2::coin::Coin<")) == null);
    const m = (try parseTypeTag(a.allocator(), "0xab::pool::Pool<0x2::sui::SUI, vector<u64>>")).?;
    try std.testing.expectEqual(@as(usize, 2), m.@"struct".type_args.len);
    try std.testing.expect(parseAddress("0x6").?[31] == 6);
}

test "type tags: sui-sdk-types depth and node limits, no recursion past them" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    // 200-deep vector<...>: rejected at depth 128 with the sdk's label
    var deep: std.ArrayList(u8) = .empty;
    for (0..200) |_| try deep.appendSlice(al, "vector<");
    try deep.appendSlice(al, "u8");
    for (0..200) |_| try deep.append(al, '>');
    try std.testing.expectEqualStrings("type exceeds the maximum nesting depth of 128", (try parseType(al, deep.items)).err.?);
    // a few MB of nesting (the reported stack overflow) ends the same way, without recursing deeper
    var huge: std.ArrayList(u8) = .empty;
    for (0..300_000) |_| try huge.appendSlice(al, "vector<");
    try std.testing.expectEqualStrings("type exceeds the maximum nesting depth of 128", (try parseType(al, huge.items)).err.?);
    // 127 levels of vector around u8 is depth 127: accepted
    var ok: std.ArrayList(u8) = .empty;
    for (0..127) |_| try ok.appendSlice(al, "vector<");
    try ok.appendSlice(al, "u8");
    for (0..127) |_| try ok.append(al, '>');
    try std.testing.expect((try parseType(al, ok.items)) == .ok);
    // wide: a struct with 256 generic arguments is 257 nodes
    var wide: std.ArrayList(u8) = .empty;
    try wide.appendSlice(al, "0x2::m::S<");
    for (0..256) |i| try wide.appendSlice(al, if (i == 0) "u8" else ",u8");
    try wide.append(al, '>');
    try std.testing.expectEqualStrings("type exceeds the maximum node count of 256", (try parseType(al, wide.items)).err.?);
    // grammar: spaces only around generic arguments, lowercase 0x, no space inside vector<
    try std.testing.expect((try parseType(al, "0x2::coin::Coin< 0x2::sui::SUI , u8 >")) == .ok);
    try std.testing.expect((try parseType(al, "vector< u8>")).err == null);
    try std.testing.expect((try parseTypeTag(al, "vector< u8>")) == null);
    try std.testing.expect((try parseTypeTag(al, "0X2::sui::SUI")) == null);
    try std.testing.expect((try parseTypeTag(al, "u8 ")) == null);
    try std.testing.expect((try parseTypeTag(al, "0x2::coin::Coin <u8>")) == null);
    try std.testing.expectEqualStrings("unable to parse type \"vector<\"", try typeParseError(al, "vector<", null));
}

test "sui-types SuiAddress and ObjectID parse like fastcrypto decode_bytes_hex" {
    try std.testing.expect(parseSuiAddress("0x2") == null); // exactly 64 digits
    const full: [66]u8 = .{ '0', 'x' } ++ @as([64]u8, @splat('a'));
    try std.testing.expect(parseSuiAddress(&full) != null);
    try std.testing.expect(parseSuiAddress(full[2..]) != null);
    try std.testing.expectEqual(@as(u8, 2), parseObjectId("0x2").?[31]); // from_hex_literal pads
    try std.testing.expect(parseObjectId("2") == null);
    try std.testing.expectEqual(@as(u8, 0), parseObjectId("0x").?[31]);
}

test "addresses parse like sui_sdk_types::Address::from_str" {
    try std.testing.expectEqual(@as(u8, 6), parseAddress("0x6").?[31]);
    try std.testing.expectEqual(@as(u8, 0xab), parseAddress("ab").?[31]); // no prefix
    try std.testing.expectEqual(@as(u8, 0xab), parseAddress("0xAB").?[31]); // upper-case digits
    try std.testing.expect(parseAddress("0Xab") == null); // only a lowercase prefix is stripped
    try std.testing.expect(parseAddress("") == null);
    try std.testing.expect(parseAddress("0x") == null);
    const long: [67]u8 = .{ '0', 'x' } ++ @as([65]u8, @splat('1'));
    try std.testing.expect(parseAddress(&long) == null);
    try std.testing.expect(parseAddress(long[3..]) != null);
}

fn testCmd(al: Allocator, comptime field: u32, body: []const u8) ![]const u8 {
    var buf: [256]u8 = undefined;
    var w = proto.Writer.init(&buf);
    try w.bytes(field, body);
    return al.dupe(u8, w.bytesWritten());
}

test "command errors render TryFromProtoError like sui-rpc" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    try std.testing.expectEqualStrings("error converting from protobuf: field: command reason: FIELD_MISSING", (try parseCommand(al, "")).err);
    // MoveCall { package: "zz" }
    var buf: [128]u8 = undefined;
    var w = proto.Writer.init(&buf);
    try w.bytes(1, "zz");
    try std.testing.expectEqualStrings("error converting from protobuf: field: package reason: FIELD_INVALID description: Unable to parse Address (must be hex string of length 32)", (try parseCommand(al, try testCmd(al, 1, w.bytesWritten()))).err);
    // MoveCall { package: "2" (no prefix), module: "coin", function: "value", type_arguments: ["vector< u8>"] }
    w = proto.Writer.init(&buf);
    try w.bytes(1, "2");
    try w.bytes(2, "coin");
    try w.bytes(3, "value");
    try w.bytes(4, "vector< u8>");
    try std.testing.expectEqualStrings("error converting from protobuf: field: type_arguments reason: FIELD_INVALID description: unable to parse type \"vector< u8>\"", (try parseCommand(al, try testCmd(al, 1, w.bytesWritten()))).err);
    // MoveCall with an argument of kind INPUT and input 70000
    w = proto.Writer.init(&buf);
    try w.bytes(1, "2");
    try w.bytes(2, "coin");
    try w.bytes(3, "value");
    var ab: [16]u8 = undefined;
    var aw = proto.Writer.init(&ab);
    try aw.uint(1, 2);
    try aw.uint(2, 70000);
    try w.bytes(5, aw.bytesWritten());
    try std.testing.expectEqualStrings("error converting from protobuf: field: input reason: FIELD_INVALID description: out of range integral type conversion attempted", (try parseCommand(al, try testCmd(al, 1, w.bytesWritten()))).err);
    // SplitCoins without a coin
    try std.testing.expectEqualStrings("error converting from protobuf: field: coin reason: FIELD_MISSING", (try parseCommand(al, try testCmd(al, 3, ""))).err);
    // the same MoveCall with input 1 converts; the package needed no 0x
    w = proto.Writer.init(&buf);
    try w.bytes(1, "2");
    try w.bytes(2, "coin");
    try w.bytes(3, "value");
    aw = proto.Writer.init(&ab);
    try aw.uint(1, 2);
    try aw.uint(2, 1);
    try w.bytes(5, aw.bytesWritten());
    const mc = (try parseCommand(al, try testCmd(al, 1, w.bytesWritten()))).ok.MoveCall;
    try std.testing.expectEqual(@as(u8, 2), mc.package.@"0".@"0"[31]);
    try std.testing.expectEqual(types.Argument{ .Input = 1 }, mc.arguments[0]);
}

test "expiration: raw seconds when fully formed, timestamp_to_ms when resolving" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    const chain = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S";
    var ts: [32]u8 = undefined;
    var tw = proto.Writer.init(&ts);
    try tw.uint(1, 1_700_000_000);
    try tw.uint(2, 500_000_000);
    var buf: [256]u8 = undefined;
    var w = proto.Writer.init(&buf);
    try w.uint(1, 3); // ValidDuring
    try w.bytes(4, tw.bytesWritten());
    try w.bytes(6, chain);
    try w.uint(7, 9);
    const msg = try al.dupe(u8, w.bytesWritten());
    try std.testing.expectEqual(@as(?u64, 1_700_000_000), (try parseExpiration(al, msg, .sdk)).ok.ValidDuring.min_timestamp);
    try std.testing.expectEqual(@as(?u64, 1_700_000_000_500), (try parseExpiration(al, msg, .resolve)).ok.ValidDuring.min_timestamp);
    // Epoch without an epoch value is Epoch(0) on both paths
    w = proto.Writer.init(&buf);
    try w.uint(1, 2);
    try std.testing.expectEqual(@as(u64, 0), (try parseExpiration(al, w.bytesWritten(), .sdk)).ok.Epoch);
    try std.testing.expectEqual(@as(u64, 0), (try parseExpiration(al, w.bytesWritten(), .resolve)).ok.Epoch);
    // Validity with an empty allowed_proposers: accepted fully formed, rejected when resolving
    w = proto.Writer.init(&buf);
    try w.uint(1, 4);
    try w.bytes(6, chain);
    try w.uint(7, 9);
    var apb: [32]u8 = undefined;
    var apw = proto.Writer.init(&apb);
    try apw.uint(1, 5);
    try w.bytes(8, apw.bytesWritten());
    const v = try al.dupe(u8, w.bytesWritten());
    try std.testing.expectEqual(@as(usize, 0), (try parseExpiration(al, v, .sdk)).ok.Validity.allowed_proposers.?.proposers.len);
    try std.testing.expectEqualStrings("allowed_proposers must not be empty", (try parseExpiration(al, v, .resolve)).err);
    // a negative timestamp is an error only when resolving
    tw = proto.Writer.init(&ts);
    try tw.uint(1, @bitCast(@as(i64, -5)));
    w = proto.Writer.init(&buf);
    try w.uint(1, 3);
    try w.bytes(5, tw.bytesWritten());
    try w.bytes(6, chain);
    try w.uint(7, 9);
    try std.testing.expectEqualStrings("invalid timestamp: negative seconds", (try parseExpiration(al, w.bytesWritten(), .resolve)).err);
    try std.testing.expectEqual(@as(?u64, @bitCast(@as(i64, -5))), (try parseExpiration(al, w.bytesWritten(), .sdk)).ok.ValidDuring.max_timestamp);
}
