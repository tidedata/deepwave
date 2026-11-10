//! Subscription and list filters of sui-node 1.83.1, ported:
//! - `transaction_filter_to_query` / `event_filter_to_query` (sui-rpc-api ledger_history/filter.rs):
//!   a proto DNF filter to terms of encoded dimension keys, with `affected_address` expanded to
//!   `sender OR affected_address`, the literal fan-out and expansion caps, and the synthetic
//!   universe include of exclude-only terms. Every validation error is the RpcError sui-rpc-api
//!   builds from a `FieldViolation` (INVALID_ARGUMENT, message = description, BadRequest details).
//! - `for_each_transaction_dimension` / `for_each_event_dimension` and the key encoders
//!   (sui-inverted-index dimensions.rs), plus the synthetic `TxUniverse` key that
//!   `extract_checkpoint_keys` (subscription/matcher.rs) adds to every transaction's key set.
//! - `term_matches`: every include present, every exclude absent; a query matches if any term does.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const proto = @import("proto.zig");
const status = @import("status.zig");
const h2 = @import("h2/root.zig");
const objset = @import("objset.zig");

/// `DEFAULT_MAX_BITMAP_FILTER_LITERALS` (sui-config rpc_config.rs): the default of
/// `ledger_history.max_bitmap_filter_literals`.
pub const default_max_literals: u32 = 10;

/// `MAX_EXPANDED_TRANSACTION_TERMS` (filter.rs).
pub const max_expanded_terms: usize = 64;

/// `IndexDimension` tag bytes.
pub const Dim = enum(u8) {
    sender = 0x01,
    affected_address = 0x02,
    affected_object = 0x03,
    move_call = 0x04,
    emit_module = 0x05,
    event_type = 0x06,
    event_stream_head = 0x07,
    event_extant = 0x08,
    tx_universe = 0x09,
    any_package_write = 0x0a,
};

/// `encode_dimension_key(TxUniverse, TX_UNIVERSE_VALUE)`.
pub const tx_universe_key = [_]u8{ 0x09, 0x00 };
/// `encode_dimension_key(EventExtant, EVENT_EXTANT_VALUE)`.
pub const event_extant_key = [_]u8{ 0x08, 0x00 };
/// `encode_dimension_key(AnyPackageWrite, ANY_PACKAGE_VALUE)`.
pub const any_package_write_key = [_]u8{ 0x0a, 0x00 };

/// One literal of a compiled term, in the order `BitmapTerm::literals` keeps.
pub const Literal = struct { include: bool, key: []const u8 };

/// One DNF term: encoded dimension keys (tag byte ++ value). `literals` keeps the Rust order of
/// includes and excludes together; `includes` / `excludes` split it (`compile_term`).
pub const Term = struct {
    includes: []const []const u8,
    excludes: []const []const u8,
    literals: []const Literal,
};

pub const Query = struct { terms: []const Term };

/// Encoded dimension keys of one transaction or one event.
pub const KeySet = std.StringHashMapUnmanaged(void);

// ---------------------------------------------------------------- compile

/// The `FieldViolation` of a rejected filter.
pub const Violation = struct {
    field: []const u8 = "",
    description: []const u8 = "",
    reason: status.Reason = .field_invalid,
};

/// `Invalid`: `v` holds the violation (INVALID_ARGUMENT). `Malformed`: prost would reject the
/// request bytes before the handler runs (tonic answers INTERNAL "failed to decode Protobuf
/// message"; service.zig's `fail` maps error.Malformed to exactly that).
pub const CompileError = error{ Invalid, Malformed, OutOfMemory };

/// Decodes a `TransactionFilter` (the bytes of the request's `filter` field; when the field
/// repeats, pass the concatenation of every occurrence: prost merges a repeated message field,
/// which for this message is the same as decoding the concatenated bytes) and compiles it like
/// `transaction_filter_to_query`. On a validation error the reply is set on `rs` like
/// service.zig's `badField` (message = the violation's description, `grpc-status-details-bin` =
/// Status { 3, description, [Any(BadRequest)] }) and error.Reported is returned: the caller maps
/// it to INVALID_ARGUMENT with `withDetails`/`fail`. error.Malformed: undecodable filter bytes.
pub fn compileTransactionFilter(arena: Allocator, bytes: []const u8, max_literals: u32, rs: *h2.ResponseStream) error{ Reported, Malformed, OutOfMemory }!Query {
    var v: Violation = .{};
    return compileTx(arena, bytes, max_literals, &v) catch |e| return report(arena, rs, e, v);
}

/// `event_filter_to_query` over an `EventFilter`'s bytes; same conventions.
pub fn compileEventFilter(arena: Allocator, bytes: []const u8, max_literals: u32, rs: *h2.ResponseStream) error{ Reported, Malformed, OutOfMemory }!Query {
    var v: Violation = .{};
    return compileEv(arena, bytes, max_literals, &v) catch |e| return report(arena, rs, e, v);
}

fn report(arena: Allocator, rs: *h2.ResponseStream, e: CompileError, v: Violation) error{ Reported, Malformed, OutOfMemory } {
    switch (e) {
        error.Invalid => {
            const bin = status.badRequest(arena, 3, v.field, v.description, v.reason) catch return error.OutOfMemory;
            rs.setMessage(v.description);
            rs.details(bin);
            return error.Reported;
        },
        error.Malformed => return error.Malformed,
        error.OutOfMemory => return error.OutOfMemory,
    }
}

const Kind = enum { sender, affected_address, affected_object, move_call, emit_module, event_type, event_stream_head, package_write };

/// `TransactionLiteral.predicate` oneof field numbers.
fn txKind(n: u32) ?Kind {
    return switch (n) {
        2 => .sender,
        3 => .affected_address,
        4 => .affected_object,
        5 => .move_call,
        6 => .emit_module,
        7 => .event_type,
        8 => .event_stream_head,
        9 => .package_write,
        else => null,
    };
}

/// `EventLiteral.predicate` oneof field numbers.
fn evKind(n: u32) ?Kind {
    return switch (n) {
        2 => .sender,
        3 => .emit_module,
        4 => .event_type,
        5 => .event_stream_head,
        else => null,
    };
}

/// A decoded literal: `negated`, the oneof variant (null: unset) and its one optional string.
const Lit = struct { negated: bool = false, kind: ?Kind = null, value: ?[]const u8 = null };

/// `Filter { repeated Term terms = 1 }`, `Term { repeated Literal literals = 1 }`, prost merge
/// rules: repeated fields append, the last scalar wins, a oneof field of the variant already set
/// merges into it, another variant replaces it; unknown fields are skipped.
fn decodeFilter(arena: Allocator, bytes: []const u8, comptime kindOf: fn (u32) ?Kind) CompileError![]const []const Lit {
    var terms: std.ArrayList([]const Lit) = .empty;
    var r = proto.Reader.init(bytes);
    while (try r.next()) |f| {
        if (f.number != 1) continue;
        var lits: std.ArrayList(Lit) = .empty;
        var tr = proto.Reader.init(try proto.Reader.bytesOf(f));
        while (try tr.next()) |tf| {
            if (tf.number != 1) continue;
            var lit: Lit = .{};
            var lr = proto.Reader.init(try proto.Reader.bytesOf(tf));
            while (try lr.next()) |lf| {
                if (lf.number == 1) {
                    lit.negated = (try proto.Reader.varintOf(lf)) != 0;
                    continue;
                }
                const k = kindOf(lf.number) orelse continue;
                const sub = try proto.Reader.bytesOf(lf);
                if (lit.kind != k) {
                    lit.kind = k;
                    lit.value = null;
                }
                var sr = proto.Reader.init(sub);
                while (try sr.next()) |sf| {
                    if (sf.number == 1 and k != .package_write) lit.value = try proto.Reader.stringOf(sf);
                }
            }
            try lits.append(arena, lit);
        }
        try terms.append(arena, lits.items);
    }
    return terms.items;
}

fn fail(v: *Violation, field: []const u8, description: []const u8, reason: status.Reason) CompileError {
    v.* = .{ .field = field, .description = description, .reason = reason };
    return error.Invalid;
}

fn compileTx(arena: Allocator, bytes: []const u8, max_literals: u32, v: *Violation) CompileError!Query {
    const terms = try decodeFilter(arena, bytes, txKind);
    if (terms.len == 0) return fail(v, "filter.terms", "at least one filter term is required", .field_missing);
    try validateFanout(arena, terms, max_literals, v);
    // validate_expanded_term_count
    var total: usize = 0;
    for (terms) |t| {
        var splits: usize = 0;
        for (t) |l| {
            if (!l.negated and l.kind == .affected_address) splits += 1;
        }
        if (splits == 0) continue;
        const expanded: usize = if (splits >= @bitSizeOf(usize)) std.math.maxInt(usize) else @as(usize, 1) << @intCast(splits);
        total +|= expanded;
        if (total > max_expanded_terms) return fail(v, "filter.terms", std.fmt.comptimePrint(
            "affected_address literals expand this filter to more than {d} terms (each non-negated affected_address literal doubles its term because it also matches the transaction sender)",
            .{max_expanded_terms},
        ), .field_invalid);
    }
    var out: std.ArrayList(Term) = .empty;
    for (terms) |t| try txTerm(arena, t, &out, v);
    return .{ .terms = out.items };
}

fn compileEv(arena: Allocator, bytes: []const u8, max_literals: u32, v: *Violation) CompileError!Query {
    const terms = try decodeFilter(arena, bytes, evKind);
    if (terms.len == 0) return fail(v, "filter.terms", "at least one filter term is required", .field_missing);
    try validateFanout(arena, terms, max_literals, v);
    var out: std.ArrayList(Term) = .empty;
    for (terms) |t| {
        var lits: std.ArrayList(Literal) = .empty;
        if (!hasInclude(t)) try lits.append(arena, .{ .include = true, .key = &event_extant_key });
        for (t) |l| try lits.append(arena, try convertLiteral(arena, l, v));
        try out.append(arena, try finishTerm(arena, lits.items));
    }
    return .{ .terms = out.items };
}

/// `validate_literal_fanout`: the running total is reported at the first term that crosses.
fn validateFanout(arena: Allocator, terms: []const []const Lit, max: u32, v: *Violation) CompileError!void {
    var total: usize = 0;
    for (terms) |t| {
        total += t.len;
        if (total > max) return fail(v, "filter.terms.literals", try std.fmt.allocPrint(arena, "filter contains {d} literals; at most {d} are allowed", .{ total, max }), .field_invalid);
    }
}

fn hasInclude(t: []const Lit) bool {
    for (t) |l| if (!l.negated) return true;
    return false;
}

const literal_field = "filter.terms.literals";

/// `transaction_term_to_query`: a positive `affected_address(X)` splits every term built so far
/// into one with `Sender(X)` and one with `AffectedAddress(X)`; a negated one adds both as
/// excludes in place. Exclude-only terms are anchored on the `TxUniverse` include.
fn txTerm(arena: Allocator, t: []const Lit, out: *std.ArrayList(Term), v: *Violation) CompileError!void {
    var expanded: std.ArrayList(std.ArrayList(Literal)) = .empty;
    var first: std.ArrayList(Literal) = .empty;
    if (!hasInclude(t)) try first.append(arena, .{ .include = true, .key = &tx_universe_key });
    try expanded.append(arena, first);
    for (t) |l| {
        const converted = try convertLiteral(arena, l, v);
        if (l.kind != .affected_address) {
            for (expanded.items) |*e| try e.append(arena, converted);
            continue;
        }
        const addr = try parseAddress(l.value.?, literal_field ++ ".affected_address.address", v);
        const sender: Literal = .{ .include = !l.negated, .key = try encodeKey(arena, .sender, &addr) };
        if (l.negated) {
            for (expanded.items) |*e| try e.appendSlice(arena, &.{ sender, converted });
            continue;
        }
        var next: std.ArrayList(std.ArrayList(Literal)) = .empty;
        try next.ensureTotalCapacity(arena, expanded.items.len * 2);
        for (expanded.items) |e| {
            var with_sender: std.ArrayList(Literal) = .empty;
            try with_sender.appendSlice(arena, e.items);
            try with_sender.append(arena, sender);
            var with_affected = e;
            try with_affected.append(arena, converted);
            next.appendAssumeCapacity(with_sender);
            next.appendAssumeCapacity(with_affected);
        }
        expanded = next;
    }
    for (expanded.items) |e| try out.append(arena, try finishTerm(arena, e.items));
}

/// `BitmapTerm::new` (never fails here: every term has an include) and `compile_term`.
fn finishTerm(arena: Allocator, lits: []const Literal) CompileError!Term {
    var inc: std.ArrayList([]const u8) = .empty;
    var exc: std.ArrayList([]const u8) = .empty;
    for (lits) |l| try (if (l.include) &inc else &exc).append(arena, l.key);
    return .{ .includes = inc.items, .excludes = exc.items, .literals = lits };
}

/// `convert_transaction_literal` / `convert_event_literal` with field prefix
/// "filter.terms.literals".
fn convertLiteral(arena: Allocator, l: Lit, v: *Violation) CompileError!Literal {
    const kind = l.kind orelse return fail(v, literal_field, "predicate variant is required", .field_missing);
    const key = try convertPredicate(arena, kind, l.value, v);
    return .{ .include = !l.negated, .key = key };
}

fn convertPredicate(arena: Allocator, kind: Kind, value: ?[]const u8, v: *Violation) CompileError![]const u8 {
    switch (kind) {
        .sender, .affected_address => {
            const field = if (kind == .sender) literal_field ++ ".sender.address" else literal_field ++ ".affected_address.address";
            const s = value orelse return fail(v, field, "address is required", .field_missing);
            const a = try parseAddress(s, field, v);
            return encodeKey(arena, if (kind == .sender) .sender else .affected_address, &a);
        },
        .affected_object => {
            const field = literal_field ++ ".affected_object.object_id";
            const s = value orelse return fail(v, field, "object_id is required", .field_missing);
            const id = parseObjectId(s) orelse return fail(v, field, "invalid object_id: ObjectID hex literal must start with 0x", .field_invalid);
            return encodeKey(arena, .affected_object, &id);
        },
        .move_call => {
            const field = literal_field ++ ".move_call.function";
            const s = value orelse return fail(v, field, "function is required", .field_missing);
            var parts: [3][]const u8 = undefined;
            const n = splitColons(s, &parts) orelse return fail(v, field, "expected `package[::module[::function]]`", .field_invalid);
            const pkg = try parseAddress(parts[0], field, v);
            return encodeKey(arena, .move_call, try moveCallValue(arena, &pkg, if (n > 1) parts[1] else null, if (n > 2) parts[2] else null));
        },
        .emit_module => {
            const field = literal_field ++ ".emit_module.module";
            const s = value orelse return fail(v, field, "module is required", .field_missing);
            var parts: [3][]const u8 = undefined;
            const n = splitColons(s, &parts) orelse 3;
            if (n > 2) return fail(v, field, "expected `package[::module]`", .field_invalid);
            const pkg = try parseAddress(parts[0], field, v);
            return encodeKey(arena, .emit_module, try concat(arena, &.{ &pkg, if (n > 1) parts[1] else "" }));
        },
        .event_type => {
            const field = literal_field ++ ".event_type.event_type";
            const s = value orelse return fail(v, field, "type is required", .field_missing);
            const lt = std.mem.indexOfScalar(u8, s, '<');
            const head = if (lt) |i| s[0..i] else s;
            var parts: [3][]const u8 = undefined;
            const n = splitColons(head, &parts) orelse return fail(v, field, "expected `address[::module[::Name[<type_params>]]]`", .field_invalid);
            const addr = try parseAddress(parts[0], field, v);
            if (lt != null and n < 3) return fail(v, field, "generic instantiation requires a type name", .field_invalid);
            var inst: ?[]const u8 = null;
            if (lt != null) {
                var p: TypeParser = .{ .arena = arena, .s = s };
                const tag = p.parseAll() catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.Syntax => return fail(v, field, try std.fmt.allocPrint(arena, "invalid type: {s}", .{p.err}), .field_invalid),
                };
                if (tag != .@"struct") return fail(v, field, "expected a struct type", .field_invalid);
                inst = try bcs.encodeAlloc([]const types.TypeTag, arena, &tag.@"struct".type_args);
            }
            return encodeKey(arena, .event_type, try eventTypeValue(arena, &addr, if (n > 1) parts[1] else null, if (n > 2) parts[2] else null, inst));
        },
        .event_stream_head => {
            const field = literal_field ++ ".event_stream_head.stream_id";
            const s = value orelse return fail(v, field, "stream_id is required", .field_missing);
            const a = try parseAddress(s, field, v);
            return encodeKey(arena, .event_stream_head, &a);
        },
        .package_write => return &any_package_write_key,
    }
}

/// `s.split("::")` into at most 3 parts; null when there are more.
fn splitColons(s: []const u8, parts: *[3][]const u8) ?usize {
    var it = std.mem.splitSequence(u8, s, "::");
    var n: usize = 0;
    while (it.next()) |p| {
        if (n == 3) return null;
        parts[n] = p;
        n += 1;
    }
    return n;
}

/// `decode_bytes_hex::<[u8; 32]>`: an optional "0x", then exactly 64 hex digits.
fn decodeHex32(s0: []const u8) ?[32]u8 {
    const s = if (std.mem.startsWith(u8, s0, "0x")) s0[2..] else s0;
    if (s.len != 64) return null;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch return null;
    return out;
}

/// `parse_address` (`SuiAddress::from_str`): only the full 32-byte form is accepted.
fn parseAddress(s: []const u8, field: []const u8, v: *Violation) CompileError![32]u8 {
    return decodeHex32(s) orelse fail(v, field, "invalid address: Invalid value was given to the function", .field_invalid);
}

/// `ObjectID::from_str`: `decode_bytes_hex(s).or_else(|_| from_hex_literal(s))`, recursion and
/// all (`from_hex_literal` zero-pads a short "0x" literal and parses the rest with `from_str`).
pub fn parseObjectId(s: []const u8) ?[32]u8 {
    if (decodeHex32(s)) |a| return a;
    if (!std.mem.startsWith(u8, s, "0x")) return null;
    const hex = s[2..];
    if (hex.len < 64) {
        var buf: [64]u8 = undefined;
        @memset(buf[0 .. 64 - hex.len], '0');
        @memcpy(buf[64 - hex.len ..], hex);
        return parseObjectId(&buf);
    }
    return parseObjectId(hex);
}

/// `encode_dimension_key`: tag byte ++ value.
pub fn encodeKey(arena: Allocator, dim: Dim, value: []const u8) Allocator.Error![]const u8 {
    const k = try arena.alloc(u8, 1 + value.len);
    k[0] = @intFromEnum(dim);
    @memcpy(k[1..], value);
    return k;
}

fn concat(arena: Allocator, parts: []const []const u8) Allocator.Error![]const u8 {
    return std.mem.concat(arena, u8, parts);
}

/// `move_call_value`: `pkg` | `pkg module` | `pkg module \0 function`.
pub fn moveCallValue(arena: Allocator, pkg: *const [32]u8, module: ?[]const u8, function: ?[]const u8) Allocator.Error![]const u8 {
    const m = module orelse return concat(arena, &.{pkg});
    const f = function orelse return concat(arena, &.{ pkg, m });
    return concat(arena, &.{ pkg, m, "\x00", f });
}

/// `emit_module_value`: `pkg` | `pkg module`.
pub fn emitModuleValue(arena: Allocator, pkg: *const [32]u8, module: ?[]const u8) Allocator.Error![]const u8 {
    return concat(arena, &.{ pkg, module orelse "" });
}

/// `event_type_value`: `addr` | `addr module` | `.. \0 name` | `.. \0 name \0 bcs(type_params)`.
pub fn eventTypeValue(arena: Allocator, addr: *const [32]u8, module: ?[]const u8, name: ?[]const u8, inst: ?[]const u8) Allocator.Error![]const u8 {
    const m = module orelse return concat(arena, &.{addr});
    const n = name orelse return concat(arena, &.{ addr, m });
    const i = inst orelse return concat(arena, &.{ addr, m, "\x00", n });
    return concat(arena, &.{ addr, m, "\x00", n, "\x00", i });
}

/// `parse_sui_type_tag`: move-core-types `ParsedType::parse` (TypeToken tokenizer, the
/// `Parser` grammar and its error texts, MAX_TYPE_DEPTH 128 / MAX_TYPE_NODE_COUNT 256), then
/// `into_type_tag` with sui's `resolve_address` (named addresses resolve after the whole string
/// parsed, so a syntax error wins over an unbound name).
const TypeParser = struct {
    arena: Allocator,
    s: []const u8,
    err: []const u8 = "",
    toks: std.ArrayList(Tok) = .empty,
    pos: usize = 0,
    count: u64 = 0,
    /// First unbound named address in parse order (reported after the parse succeeds).
    unbound: ?[]const u8 = null,

    const TokKind = enum { ident, addr, colon2, lt, gt, comma };
    const Tok = struct { kind: TokKind, text: []const u8 };
    const PErr = error{ Syntax, OutOfMemory };

    fn name(k: TokKind) []const u8 {
        return switch (k) {
            .ident => "[identifier]",
            .addr => "[address]",
            .colon2 => "::",
            .lt => "<",
            .gt => ">",
            .comma => ",",
        };
    }

    fn fail(p: *TypeParser, comptime fmt: []const u8, args: anytype) PErr {
        p.err = try std.fmt.allocPrint(p.arena, fmt, args);
        return error.Syntax;
    }

    fn identChar(c: u8) bool {
        return std.ascii.isAlphanumeric(c) or c == '_';
    }

    /// Rust `char::is_ascii_whitespace`: space, \t, \n, form feed, \r.
    fn space(c: u8) bool {
        return c == ' ' or c == '\t' or c == '\n' or c == 0x0c or c == '\r';
    }

    fn tokenize(p: *TypeParser) PErr!void {
        const s = p.s;
        var i: usize = 0;
        while (i < s.len) {
            const rest = s[i..];
            const c = s[i];
            var n: usize = 1;
            var kind: ?TokKind = null;
            switch (c) {
                '<' => kind = .lt,
                '>' => kind = .gt,
                ',' => kind = .comma,
                ':' => {
                    if (rest.len < 2 or rest[1] != ':') return p.fail("unrecognized token: {s}", .{rest});
                    kind = .colon2;
                    n = 2;
                },
                else => if (c == '0' and rest.len > 1 and rest[1] == 'x') {
                    if (rest.len < 3 or !std.ascii.isHex(rest[2])) return p.fail("unrecognized token: {s}", .{rest});
                    n = 3;
                    while (n < rest.len and (std.ascii.isHex(rest[n]) or rest[n] == '_')) n += 1;
                    kind = .addr;
                } else if (std.ascii.isDigit(c)) {
                    while (n < rest.len and (std.ascii.isDigit(rest[n]) or rest[n] == '_')) n += 1;
                    kind = .addr;
                } else if (space(c)) {
                    while (n < rest.len and space(rest[n])) n += 1;
                } else if (std.ascii.isAlphabetic(c) or (c == '_' and rest.len > 1 and identChar(rest[1]))) {
                    while (n < rest.len and identChar(rest[n])) n += 1;
                    kind = .ident;
                } else return p.fail("unrecognized token: {s}", .{rest}),
            }
            if (kind) |k| try p.toks.append(p.arena, .{ .kind = k, .text = rest[0..n] });
            i += n;
        }
    }

    fn peek(p: *TypeParser) ?TokKind {
        return if (p.pos < p.toks.items.len) p.toks.items[p.pos].kind else null;
    }

    fn advanceAny(p: *TypeParser) PErr!Tok {
        if (p.pos >= p.toks.items.len) return p.fail("unexpected end of tokens", .{});
        p.pos += 1;
        return p.toks.items[p.pos - 1];
    }

    fn advance(p: *TypeParser, k: TokKind) PErr![]const u8 {
        const t = try p.advanceAny();
        if (t.kind != k) return p.fail("expected token {s}, got {s}", .{ name(k), name(t.kind) });
        return t.text;
    }

    fn parseAll(p: *TypeParser) PErr!types.TypeTag {
        try p.tokenize();
        const t = try p.parseType(0);
        if (p.pos < p.toks.items.len) return p.fail("Expected end of token stream. Got: {s}", .{p.toks.items[p.pos].text});
        if (p.unbound) |n| return p.fail("Unbound named address: '{s}'", .{n});
        return t;
    }

    fn parseType(p: *TypeParser, depth: u64) PErr!types.TypeTag {
        p.count += 1;
        if (depth > 128 or p.count > 256) return p.fail("Type exceeds maximum nesting depth or node count", .{});
        const t = try p.advanceAny();
        if (t.kind == .ident) {
            const prims = .{ .{ "u8", .@"u8" }, .{ "u16", .@"u16" }, .{ "u32", .@"u32" }, .{ "u64", .@"u64" }, .{ "u128", .@"u128" }, .{ "u256", .@"u256" }, .{ "bool", .@"bool" }, .{ "address", .address }, .{ "signer", .signer } };
            inline for (prims) |pr| if (std.mem.eql(u8, t.text, pr[0])) return pr[1];
            if (std.mem.eql(u8, t.text, "vector")) {
                _ = try p.advance(.lt);
                const inner = try p.arena.create(types.TypeTag);
                inner.* = try p.parseType(depth + 1);
                _ = try p.advance(.gt);
                return .{ .vector = inner };
            }
        }
        if (t.kind != .ident and t.kind != .addr) return p.fail("unexpected token {s}, expected type", .{name(t.kind)});
        // parse_address_impl
        var addr: [32]u8 = @splat(0);
        if (t.kind == .addr) {
            addr = numericAddress(p.arena, t.text) orelse return p.fail(
                "Failed to parse numerical address '{s}'. Got error: Invalid address literal. The numeric value is too large. The maximum size is 32 bytes",
                .{t.text},
            );
        } else if (resolveAddress(t.text)) |a| {
            addr = a;
        } else if (p.unbound == null) p.unbound = t.text;
        _ = try p.advance(.colon2);
        const module = try p.advance(.ident);
        _ = try p.advance(.colon2);
        const nm = try p.advance(.ident);
        var args: std.ArrayList(types.TypeTag) = .empty;
        if (p.peek() == .lt) {
            // parse_type_args_impl(depth + 1)
            _ = try p.advance(.lt);
            while (p.peek() != .gt) {
                try args.append(p.arena, try p.parseType(depth + 1));
                if (p.peek() == .gt) break;
                _ = try p.advance(.comma);
            }
            _ = try p.advance(.gt);
            if (args.items.len == 0) return p.fail("expected at least one type argument", .{});
        }
        return .{ .@"struct" = .{
            .address = .{ .@"0" = addr },
            .module = .{ .@"0" = module },
            .name = .{ .@"0" = nm },
            .type_args = args.items,
        } };
    }
};

/// `parse_address_number`: `_` dropped, hex at most 64 digits, decimal at most 78 digits and
/// below 2^256.
fn numericAddress(arena: Allocator, tok: []const u8) ?[32]u8 {
    const hex = std.mem.startsWith(u8, tok, "0x");
    const body = if (hex) tok[2..] else tok;
    const txt = arena.alloc(u8, body.len) catch return null;
    var n: usize = 0;
    for (body) |c| if (c != '_') {
        txt[n] = c;
        n += 1;
    };
    if (n == 0 or n > @as(usize, if (hex) 64 else 78)) return null;
    const v = std.fmt.parseUnsigned(u256, txt[0..n], if (hex) 16 else 10) catch return null;
    var a: [32]u8 = undefined;
    std.mem.writeInt(u256, &a, v, .big);
    return a;
}

fn isIdent(s: []const u8) bool {
    if (s.len == 0) return false;
    if (!(std.ascii.isAlphabetic(s[0]) or (s[0] == '_' and s.len > 1))) return false;
    return true;
}

/// Numeric address (0x + up to 64 hex digits, or decimal) or a `resolve_address` name.
fn resolveAddress(w: []const u8) ?[32]u8 {
    var a: [32]u8 = @splat(0);
    if (std.mem.startsWith(u8, w, "0x")) {
        const h = w[2..];
        if (h.len == 0 or h.len > 64) return null;
        var buf: [64]u8 = undefined;
        @memset(buf[0 .. 64 - h.len], '0');
        @memcpy(buf[64 - h.len ..], h);
        _ = std.fmt.hexToBytes(&a, &buf) catch return null;
        return a;
    }
    if (std.ascii.isDigit(w[0])) {
        for (w) |c| {
            if (!std.ascii.isDigit(c)) return null;
            var carry: u16 = c - '0';
            var i: usize = 32;
            while (i > 0) {
                i -= 1;
                const x = @as(u16, a[i]) * 10 + carry;
                a[i] = @truncate(x);
                carry = x >> 8;
            }
            if (carry != 0) return null;
        }
        return a;
    }
    const named = .{ .{ "std", 0x1 }, .{ "sui", 0x2 }, .{ "sui_system", 0x3 }, .{ "bridge", 0xb } };
    inline for (named) |n| if (std.mem.eql(u8, w, n[0])) {
        a[31] = n[1];
        return a;
    };
    if (std.mem.eql(u8, w, "deepbook")) {
        a[30] = 0xde;
        a[31] = 0xe9;
        return a;
    }
    return null;
}

// ---------------------------------------------------------------- dimensions

fn put(arena: Allocator, ks: *KeySet, dim: Dim, value: []const u8) Allocator.Error!void {
    var stack: [256]u8 = undefined;
    if (value.len < stack.len) {
        stack[0] = @intFromEnum(dim);
        @memcpy(stack[1..][0..value.len], value);
        if (ks.contains(stack[0 .. 1 + value.len])) return;
    }
    const k = try encodeKey(arena, dim, value);
    try ks.put(arena, k, {});
}

fn isFramework(a: *const [32]u8) bool {
    for (a[0..31]) |b| if (b != 0) return false;
    return a[31] == 2;
}

fn structIs(t: types.TypeTag, module: []const u8, name: []const u8) bool {
    if (t != .@"struct") return false;
    const s = t.@"struct";
    return isFramework(&s.address.@"0") and std.mem.eql(u8, s.module.@"0", module) and std.mem.eql(u8, s.name.@"0", name);
}

fn str(s: anytype) []const u8 {
    if (@TypeOf(s) == []const u8) return s;
    return s.@"0";
}

/// The address an object's owner contributes (`owner_as_affected_address`), from raw
/// BCS(Object); null for packages and non-address owners.
fn ownerAddress(arena: Allocator, raw: []const u8) !?[32]u8 {
    if (raw.len == 0 or raw[0] != 0) return null; // packages are immutable
    var r = bcs.Reader.init(raw);
    try bcs.skip(types.Data, &r);
    const owner = try bcs.decodeFrom(types.Owner, arena, &r);
    return switch (owner) {
        .AddressOwner => |a| a.@"0",
        .ConsensusAddressOwner => |c| c.owner.@"0",
        else => null,
    };
}

const Change = struct { id: [32]u8, input: ?u64, output: ?u64 };

/// `TransactionEffectsAPI::object_changes` (V1: created, mutated, unwrapped, deleted,
/// unwrapped_then_deleted, wrapped, input versions from modified_at_versions; V2: every
/// changed object except accumulator writes).
fn objectChanges(arena: Allocator, eff: *const types.TransactionEffects) ![]const Change {
    var out: std.ArrayList(Change) = .empty;
    switch (eff.*) {
        .V2 => |v| for (v.changed_objects) |e| {
            const input: ?u64 = switch (e.@"1".input_state) {
                .NotExist => null,
                .Exist => |x| x.@"0".@"0".@"0",
            };
            const output: ?u64 = switch (e.@"1".output_state) {
                .NotExist => null,
                .ObjectWrite => v.lamport_version.@"0",
                .PackageWrite => |p| p.@"0".@"0",
                .AccumulatorWriteV1 => continue,
            };
            try out.append(arena, .{ .id = e.@"0".@"0".@"0", .input = input, .output = output });
        },
        .V1 => |v| {
            var at: std.AutoHashMapUnmanaged([32]u8, u64) = .empty;
            for (v.modified_at_versions) |e| try at.put(arena, e.@"0".@"0".@"0", e.@"1".@"0");
            for (v.created) |e| try out.append(arena, .{ .id = e.@"0".@"0".@"0".@"0", .input = null, .output = e.@"0".@"1".@"0" });
            for (v.mutated) |e| try out.append(arena, .{ .id = e.@"0".@"0".@"0".@"0", .input = at.get(e.@"0".@"0".@"0".@"0"), .output = e.@"0".@"1".@"0" });
            for (v.unwrapped) |e| try out.append(arena, .{ .id = e.@"0".@"0".@"0".@"0", .input = null, .output = e.@"0".@"1".@"0" });
            for (v.deleted) |e| try out.append(arena, .{ .id = e.@"0".@"0".@"0", .input = at.get(e.@"0".@"0".@"0"), .output = null });
            for (v.unwrapped_then_deleted) |e| try out.append(arena, .{ .id = e.@"0".@"0".@"0", .input = null, .output = null });
            for (v.wrapped) |e| try out.append(arena, .{ .id = e.@"0".@"0".@"0", .input = at.get(e.@"0".@"0".@"0"), .output = null });
        },
    }
    return out.items;
}

/// `for_each_transaction_dimension` plus the synthetic `TxUniverse` key, from raw BCS:
/// TransactionData, TransactionEffects, TransactionEvents (null: none), and the objects the
/// owners are read from (the checkpoint's object set, or the transaction's inputs + outputs).
pub fn transactionKeys(arena: Allocator, tx_data_bcs: []const u8, effects_bcs: []const u8, events_bcs: ?[]const u8, objects: *const objset.ObjSet) !KeySet {
    const tx = try bcs.decode(types.TransactionData, arena, tx_data_bcs);
    const eff = try bcs.decode(types.TransactionEffects, arena, effects_bcs);
    const evs: ?types.TransactionEvents = if (events_bcs) |b| try bcs.decode(types.TransactionEvents, arena, b) else null;
    return transactionKeysDecoded(arena, &tx, &eff, if (evs) |*e| e else null, objects);
}

pub fn transactionKeysDecoded(arena: Allocator, tx: *const types.TransactionData, eff: *const types.TransactionEffects, events: ?*const types.TransactionEvents, objects: *const objset.ObjSet) !KeySet {
    var ks: KeySet = .empty;
    try put(arena, &ks, .tx_universe, tx_universe_key[1..]);
    const data = tx.V1;
    const sender = data.sender.@"0";
    try put(arena, &ks, .sender, &sender);

    for (try objectChanges(arena, eff)) |c| {
        for ([_]?u64{ c.input, c.output }) |ver| {
            const vv = ver orelse continue;
            const raw = objects.get(&c.id, vv) orelse continue;
            if (try ownerAddress(arena, raw)) |a| try put(arena, &ks, .affected_address, &a);
        }
        try put(arena, &ks, .affected_object, &c.id);
        if (c.output) |ov| {
            if (objects.get(&c.id, ov)) |raw| {
                if (raw.len > 0 and raw[0] == 1) try put(arena, &ks, .any_package_write, any_package_write_key[1..]);
            }
        }
    }

    switch (data.kind) {
        .ProgrammableTransaction => |pt| for (pt.commands) |cmd| switch (cmd) {
            .MoveCall => |m| {
                const pkg = &m.package.@"0".@"0";
                try put(arena, &ks, .move_call, pkg);
                try put(arena, &ks, .move_call, try moveCallValue(arena, pkg, str(m.module), null));
                try put(arena, &ks, .move_call, try moveCallValue(arena, pkg, str(m.module), str(m.function)));
            },
            else => {},
        },
        else => {},
    }

    try eventDims(arena, sender, eff, events, &ks, null);

    switch (eff.*) {
        .V2 => |v| for (v.changed_objects) |e| switch (e.@"1".output_state) {
            .AccumulatorWriteV1 => |w| {
                // Balance::is_balance_type(ty) && AccumulatorValue::Integer
                if (structIs(w.address.ty, "balance", "Balance") and w.value == .Integer)
                    try put(arena, &ks, .affected_address, &w.address.address.@"0");
            },
            else => {},
        },
        .V1 => {},
    }
    return ks;
}

/// `for_each_event_dimension`: into `tx_keys` (tx space: no EventExtant) or into `per_event`.
fn eventDims(arena: Allocator, sender: [32]u8, eff: *const types.TransactionEffects, events: ?*const types.TransactionEvents, tx_keys: ?*KeySet, per_event: ?[]KeySet) !void {
    const evs: []const types.Event = if (events) |e| e.data else &.{};
    for (evs, 0..) |ev, i| {
        const ks = if (tx_keys) |k| k else &per_event.?[i];
        if (tx_keys == null) try put(arena, ks, .event_extant, event_extant_key[1..]);
        try put(arena, ks, .sender, &sender);
        const pkg = &ev.package_id.@"0".@"0";
        const emit_mod = ev.transaction_module.@"0";
        try put(arena, ks, .emit_module, pkg);
        try put(arena, ks, .emit_module, try emitModuleValue(arena, pkg, emit_mod));
        const t = ev.type_;
        const addr = &t.address.@"0";
        try put(arena, ks, .event_type, addr);
        try put(arena, ks, .event_type, try eventTypeValue(arena, addr, t.module.@"0", null, null));
        try put(arena, ks, .event_type, try eventTypeValue(arena, addr, t.module.@"0", t.name.@"0", null));
        if (t.type_args.len > 0) {
            const inst = try bcs.encodeAlloc([]const types.TypeTag, arena, &t.type_args);
            try put(arena, ks, .event_type, try eventTypeValue(arena, addr, t.module.@"0", t.name.@"0", inst));
        }
    }
    switch (eff.*) {
        .V2 => |v| for (v.changed_objects) |e| switch (e.@"1".output_state) {
            .AccumulatorWriteV1 => |w| {
                const digests = switch (w.value) {
                    .EventDigest => |d| d,
                    else => continue,
                };
                // stream_id_from_accumulator_event: 0x2::accumulator_settlement::EventStreamHead
                if (!structIs(w.address.ty, "accumulator_settlement", "EventStreamHead")) continue;
                for (digests) |d| {
                    const idx = d.@"0";
                    // Rust asserts idx < event count (a panic); an out-of-range index is skipped here
                    if (idx >= evs.len) continue;
                    const ks = if (tx_keys) |k| k else &per_event.?[@intCast(idx)];
                    try put(arena, ks, .event_stream_head, &w.address.address.@"0");
                }
            },
            else => {},
        },
        .V1 => {},
    }
}

/// Per-event key sets of one transaction (`extract_checkpoint_keys`, event space).
pub fn eventKeysDecoded(arena: Allocator, tx: *const types.TransactionData, eff: *const types.TransactionEffects, events: ?*const types.TransactionEvents) ![]KeySet {
    const n = if (events) |e| e.data.len else 0;
    const sets = try arena.alloc(KeySet, n);
    for (sets) |*s| s.* = .empty;
    if (n > 0) try eventDims(arena, tx.V1.sender.@"0", eff, events, null, sets);
    return sets;
}

// ---------------------------------------------------------------- matching

/// `term_matches`: every include present and every exclude absent.
pub fn termMatches(t: *const Term, keys: *const KeySet) bool {
    for (t.includes) |k| if (!keys.contains(k)) return false;
    for (t.excludes) |k| if (keys.contains(k)) return false;
    return true;
}

/// A DNF query matches when any of its terms does.
pub fn matches(q: *const Query, keys: *const KeySet) bool {
    for (q.terms) |*t| if (termMatches(t, keys)) return true;
    return false;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const T = struct {
    arena: Allocator,

    fn hexAddr(t: T, b: u8) []const u8 {
        const digits = "0123456789abcdef";
        const s = t.arena.alloc(u8, 66) catch unreachable;
        s[0] = '0';
        s[1] = 'x';
        for (0..32) |i| {
            s[2 + 2 * i] = digits[b >> 4];
            s[3 + 2 * i] = digits[b & 15];
        }
        return s;
    }

    /// A literal: `negated`, predicate oneof field `pred` holding the string `value`.
    fn lit(t: T, pred: u32, negated: bool, value: ?[]const u8) []const u8 {
        const buf = t.arena.alloc(u8, 32 + (if (value) |v| v.len else 0)) catch unreachable;
        var w = proto.Writer.init(buf);
        if (negated) w.uint(1, 1) catch unreachable;
        const m = w.begin(pred, 70) catch unreachable;
        if (value) |v| w.string(1, v) catch unreachable;
        w.end(m) catch unreachable;
        return w.bytesWritten();
    }

    /// `Message { repeated bytes field 1 }`: a term from literals, a filter from terms.
    fn list(t: T, items: []const []const u8) []const u8 {
        var n: usize = 0;
        for (items) |x| n += x.len + 12;
        const buf = t.arena.alloc(u8, n) catch unreachable;
        var w = proto.Writer.init(buf);
        for (items) |x| w.bytes(1, x) catch unreachable;
        return w.bytesWritten();
    }

    fn sender(t: T, b: u8, negated: bool) []const u8 {
        return t.lit(2, negated, t.hexAddr(b));
    }
    fn affected(t: T, b: u8, negated: bool) []const u8 {
        return t.lit(3, negated, t.hexAddr(b));
    }
    fn senderKey(t: T, b: u8) []const u8 {
        return encodeKey(t.arena, .sender, &@as([32]u8, @splat(b))) catch unreachable;
    }
    fn affectedKey(t: T, b: u8) []const u8 {
        return encodeKey(t.arena, .affected_address, &@as([32]u8, @splat(b))) catch unreachable;
    }
    fn filter(t: T, terms: []const []const []const u8) []const u8 {
        const tb = t.arena.alloc([]const u8, terms.len) catch unreachable;
        for (terms, tb) |lits, *d| d.* = t.list(lits);
        return t.list(tb);
    }
};

fn expectTerms(q: Query, want: []const []const Literal) !void {
    try testing.expectEqual(want.len, q.terms.len);
    for (q.terms, want) |got, w| {
        try testing.expectEqual(w.len, got.literals.len);
        for (got.literals, w) |g, x| {
            try testing.expectEqual(x.include, g.include);
            try testing.expectEqualSlices(u8, x.key, g.key);
        }
    }
}

fn compileOk(arena: Allocator, bytes: []const u8, max: u32) !Query {
    var v: Violation = .{};
    return compileTx(arena, bytes, max, &v) catch |e| {
        std.debug.print("unexpected violation {s}: {s}\n", .{ v.field, v.description });
        return e;
    };
}

fn compileErr(arena: Allocator, bytes: []const u8, max: u32) !Violation {
    var v: Violation = .{};
    if (compileTx(arena, bytes, max, &v)) |_| return error.TestUnexpectedResult else |e| try testing.expectEqual(error.Invalid, e);
    return v;
}

test "affected_address_matches_sender_or_affected_address" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const t: T = .{ .arena = ar.allocator() };
    const q = try compileOk(t.arena, t.filter(&.{&.{t.affected(1, false)}}), 10);
    try expectTerms(q, &.{ &.{.{ .include = true, .key = t.senderKey(1) }}, &.{.{ .include = true, .key = t.affectedKey(1) }} });
}

test "affected_address_expansion_keeps_other_literals_in_every_term" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const t: T = .{ .arena = ar.allocator() };
    const q = try compileOk(t.arena, t.filter(&.{&.{ t.sender(2, false), t.affected(1, false), t.sender(3, true) }}), 10);
    try expectTerms(q, &.{
        &.{ .{ .include = true, .key = t.senderKey(2) }, .{ .include = true, .key = t.senderKey(1) }, .{ .include = false, .key = t.senderKey(3) } },
        &.{ .{ .include = true, .key = t.senderKey(2) }, .{ .include = true, .key = t.affectedKey(1) }, .{ .include = false, .key = t.senderKey(3) } },
    });
}

test "negated_affected_address_excludes_sender_and_affected_address" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const t: T = .{ .arena = ar.allocator() };
    const q = try compileOk(t.arena, t.filter(&.{&.{t.affected(1, true)}}), 10);
    try expectTerms(q, &.{&.{ .{ .include = true, .key = &tx_universe_key }, .{ .include = false, .key = t.senderKey(1) }, .{ .include = false, .key = t.affectedKey(1) } }});
}

test "multiple_affected_addresses_in_one_term_expand_to_cross_product" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const t: T = .{ .arena = ar.allocator() };
    const q = try compileOk(t.arena, t.filter(&.{&.{ t.affected(1, false), t.affected(2, false) }}), 10);
    try expectTerms(q, &.{
        &.{ .{ .include = true, .key = t.senderKey(1) }, .{ .include = true, .key = t.senderKey(2) } },
        &.{ .{ .include = true, .key = t.senderKey(1) }, .{ .include = true, .key = t.affectedKey(2) } },
        &.{ .{ .include = true, .key = t.affectedKey(1) }, .{ .include = true, .key = t.senderKey(2) } },
        &.{ .{ .include = true, .key = t.affectedKey(1) }, .{ .include = true, .key = t.affectedKey(2) } },
    });
}

test "affected_address_expansion_is_capped" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const t: T = .{ .arena = ar.allocator() };
    const affectedTerm = struct {
        fn f(tt: T, n: usize) []const []const u8 {
            const lits = tt.arena.alloc([]const u8, n) catch unreachable;
            for (lits, 0..) |*l, i| l.* = tt.affected(@intCast(i), false);
            return lits;
        }
    }.f;
    const splits: usize = std.math.log2_int(usize, max_expanded_terms); // 6
    const max: u32 = @intCast(2 * splits + 2);
    const q = try compileOk(t.arena, t.filter(&.{affectedTerm(t, splits)}), max);
    try testing.expectEqual(@as(usize, 1) << @intCast(splits), q.terms.len);
    for ([_][]const u8{ t.filter(&.{affectedTerm(t, splits + 1)}), t.filter(&.{ affectedTerm(t, splits), affectedTerm(t, 1) }) }) |f| {
        const v = try compileErr(t.arena, f, max);
        try testing.expectEqualStrings("filter.terms", v.field);
        try testing.expectEqual(status.Reason.field_invalid, v.reason);
        try testing.expectEqualStrings("affected_address literals expand this filter to more than 64 terms (each non-negated affected_address literal doubles its term because it also matches the transaction sender)", v.description);
    }
    // terms without a positive affected_address literal do not count toward the cap
    const plain = max_expanded_terms + 1;
    const terms = try t.arena.alloc([]const []const u8, plain);
    for (terms, 0..) |*x, i| {
        const one = try t.arena.alloc([]const u8, 1);
        one[0] = t.sender(@intCast(i), false);
        x.* = one;
    }
    const q2 = try compileOk(t.arena, t.filter(terms), plain);
    try testing.expectEqual(plain, q2.terms.len);
}

test "transaction_filter literal fan-out" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const t: T = .{ .arena = ar.allocator() };
    var lits: [11][]const u8 = undefined;
    for (&lits, 0..) |*l, i| l.* = t.sender(@intCast(i), false);
    _ = try compileOk(t.arena, t.filter(&.{lits[0..10]}), default_max_literals);
    const v = try compileErr(t.arena, t.filter(&.{lits[0..11]}), default_max_literals);
    try testing.expectEqualStrings("filter.terms.literals", v.field);
    try testing.expectEqualStrings("filter contains 11 literals; at most 10 are allowed", v.description);
    // the running total is reported at the first term that crosses the cap
    const v2 = try compileErr(t.arena, t.filter(&.{ lits[0..2], lits[0..1], lits[0..5] }), 2);
    try testing.expectEqualStrings("filter contains 3 literals; at most 2 are allowed", v2.description);
}

test "transaction_filter exclude-only terms: TxUniverse anchor, not counted in fan-out" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const t: T = .{ .arena = ar.allocator() };
    const q = try compileOk(t.arena, t.filter(&.{&.{t.sender(1, true)}}), 10);
    try expectTerms(q, &.{&.{ .{ .include = true, .key = &tx_universe_key }, .{ .include = false, .key = t.senderKey(1) } }});
    _ = try compileOk(t.arena, t.filter(&.{ &.{t.sender(1, true)}, &.{t.sender(2, true)} }), 2);
    // an empty term is anchored on the universe alone: it matches every transaction
    const qe = try compileOk(t.arena, t.filter(&.{&.{}}), 10);
    try expectTerms(qe, &.{&.{.{ .include = true, .key = &tx_universe_key }}});
}

test "event_stream_head and package_write keys" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const t: T = .{ .arena = ar.allocator() };
    const q = try compileOk(t.arena, t.filter(&.{&.{ t.lit(8, false, t.hexAddr(7)), t.lit(9, false, null) }}), 10);
    try expectTerms(q, &.{&.{
        .{ .include = true, .key = try encodeKey(t.arena, .event_stream_head, &@as([32]u8, @splat(7))) },
        .{ .include = true, .key = &.{ 0x0a, 0x00 } },
    }});
}

test "filter validation errors" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const t: T = .{ .arena = ar.allocator() };
    const Case = struct { lit: []const u8, field: []const u8, desc: []const u8, reason: status.Reason };
    const no_pred = t.list(&.{}); // empty literal message: predicate unset
    const cases = [_]Case{
        .{ .lit = no_pred, .field = "filter.terms.literals", .desc = "predicate variant is required", .reason = .field_missing },
        .{ .lit = t.lit(2, false, null), .field = "filter.terms.literals.sender.address", .desc = "address is required", .reason = .field_missing },
        .{ .lit = t.lit(2, false, "0x2"), .field = "filter.terms.literals.sender.address", .desc = "invalid address: Invalid value was given to the function", .reason = .field_invalid },
        .{ .lit = t.lit(3, true, "zz"), .field = "filter.terms.literals.affected_address.address", .desc = "invalid address: Invalid value was given to the function", .reason = .field_invalid },
        .{ .lit = t.lit(4, false, null), .field = "filter.terms.literals.affected_object.object_id", .desc = "object_id is required", .reason = .field_missing },
        .{ .lit = t.lit(4, false, "5"), .field = "filter.terms.literals.affected_object.object_id", .desc = "invalid object_id: ObjectID hex literal must start with 0x", .reason = .field_invalid },
        .{ .lit = t.lit(5, false, null), .field = "filter.terms.literals.move_call.function", .desc = "function is required", .reason = .field_missing },
        .{ .lit = t.lit(5, false, "a::b::c::d"), .field = "filter.terms.literals.move_call.function", .desc = "expected `package[::module[::function]]`", .reason = .field_invalid },
        .{ .lit = t.lit(5, false, "0x2::coin::transfer"), .field = "filter.terms.literals.move_call.function", .desc = "invalid address: Invalid value was given to the function", .reason = .field_invalid },
        .{ .lit = t.lit(6, false, null), .field = "filter.terms.literals.emit_module.module", .desc = "module is required", .reason = .field_missing },
        .{ .lit = t.lit(6, false, "a::b::c"), .field = "filter.terms.literals.emit_module.module", .desc = "expected `package[::module]`", .reason = .field_invalid },
        .{ .lit = t.lit(7, false, null), .field = "filter.terms.literals.event_type.event_type", .desc = "type is required", .reason = .field_missing },
        .{ .lit = t.lit(7, false, "a::b::c::d"), .field = "filter.terms.literals.event_type.event_type", .desc = "expected `address[::module[::Name[<type_params>]]]`", .reason = .field_invalid },
        .{ .lit = t.lit(8, false, null), .field = "filter.terms.literals.event_stream_head.stream_id", .desc = "stream_id is required", .reason = .field_missing },
    };
    for (cases) |c| {
        const v = try compileErr(t.arena, t.filter(&.{&.{c.lit}}), 10);
        try testing.expectEqualStrings(c.field, v.field);
        try testing.expectEqualStrings(c.desc, v.description);
        try testing.expectEqual(c.reason, v.reason);
    }
    const generic_no_name = try std.fmt.allocPrint(t.arena, "{s}::m<u8>", .{t.hexAddr(2)});
    const v = try compileErr(t.arena, t.filter(&.{&.{t.lit(7, false, generic_no_name)}}), 10);
    try testing.expectEqualStrings("generic instantiation requires a type name", v.description);
    const ve = try compileErr(t.arena, t.filter(&.{}), 10);
    try testing.expectEqualStrings("filter.terms", ve.field);
    try testing.expectEqualStrings("at least one filter term is required", ve.description);
    try testing.expectEqual(status.Reason.field_missing, ve.reason);
    // invalid UTF-8 in a string field: prost rejects the request
    var ev: Violation = .{};
    try testing.expectError(error.Malformed, compileTx(t.arena, t.filter(&.{&.{t.lit(2, false, "\xff")}}), 10, &ev));
}

test "object ids, move call / emit module / event type values" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const t: T = .{ .arena = ar.allocator() };
    var two: [32]u8 = @splat(0);
    two[31] = 2;
    try testing.expectEqual(two, parseObjectId("0x2").?);
    const sui = "0x0000000000000000000000000000000000000000000000000000000000000002";
    try testing.expectEqual(two, parseObjectId(sui).?);
    try testing.expectEqual(@as(?[32]u8, null), parseObjectId("2"));
    const q = try compileOk(t.arena, t.filter(&.{&.{
        t.lit(5, false, sui ++ "::coin::transfer"),
        t.lit(6, false, sui ++ "::coin"),
        t.lit(7, false, sui ++ "::coin::Coin<0x2::sui::SUI>"),
        t.lit(4, false, "0x2"),
    }}), 10);
    const k = q.terms[0].includes;
    try testing.expectEqualSlices(u8, "\x04" ++ two ++ "coin\x00transfer", k[0]);
    try testing.expectEqualSlices(u8, "\x05" ++ two ++ "coin", k[1]);
    // BCS(vec![TypeTag::Struct(0x2::sui::SUI)]): len 1, variant 7, address, "sui", "SUI", no args
    try testing.expectEqualSlices(u8, "\x06" ++ two ++ "coin\x00Coin\x00" ++ "\x01\x07" ++ two ++ "\x03sui\x03SUI\x00", k[2]);
    try testing.expectEqualSlices(u8, "\x03" ++ two, k[3]);
}

test "matcher: sender, affected_address fallback, exclude-only via TxUniverse" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const t: T = .{ .arena = ar.allocator() };
    // one key set per transaction: the universe key and its sender, nothing else
    var sets: [2]KeySet = .{ .empty, .empty };
    for (&sets, 0..) |*s, i| {
        try s.put(t.arena, &tx_universe_key, {});
        try s.put(t.arena, t.senderKey(@intCast(i)), {});
    }
    const by_sender = try compileOk(t.arena, t.filter(&.{&.{t.sender(0, false)}}), 16);
    try testing.expect(matches(&by_sender, &sets[0]) and !matches(&by_sender, &sets[1]));
    // a sponsored tx touching only shared objects: no AffectedAddress key, the sender matches
    const by_affected = try compileOk(t.arena, t.filter(&.{&.{t.affected(0, false)}}), 16);
    try testing.expect(matches(&by_affected, &sets[0]) and !matches(&by_affected, &sets[1]));
    const not_sender = try compileOk(t.arena, t.filter(&.{&.{t.sender(0, true)}}), 16);
    try testing.expect(!matches(&not_sender, &sets[0]) and matches(&not_sender, &sets[1]));
}

test "event filter: EventExtant anchor only when a term has no include" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const t: T = .{ .arena = ar.allocator() };
    var v: Violation = .{};
    const q = try compileEv(t.arena, t.filter(&.{ &.{t.sender(1, false)}, &.{t.sender(2, true)} }), 2, &v);
    try testing.expectEqualSlices(u8, t.senderKey(1), q.terms[0].literals[0].key);
    try testing.expectEqualSlices(u8, &event_extant_key, q.terms[1].literals[0].key);
    try testing.expect(q.terms[1].literals[0].include and !q.terms[1].literals[1].include);
    // affected_address is not an EventLiteral variant (field 3 is emit_module there)
    const q2 = try compileEv(t.arena, t.filter(&.{&.{t.lit(3, false, t.hexAddr(2))}}), 2, &v);
    try testing.expectEqual(@as(u8, 0x05), q2.terms[0].includes[0][0]);
}

test "corpus checkpoint: transaction dimension keys" {
    const io = testing.io;
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const arena = ar.allocator();
    const root = testing.environ.getPosix("ZUI_CORPUS") orelse blk: {
        const home = testing.environ.getPosix("HOME") orelse return error.SkipZigTest;
        break :blk try std.fmt.allocPrint(arena, "{s}/zui-corpus", .{home});
    };
    var saw_call = false;
    var saw_event = false;
    for ([_]u64{ 279972122, 284679034, 290766114, 278618636 }) |seq| {
        const path = try std.fmt.allocPrint(arena, "{s}/chk/{d}.chk", .{ root, seq });
        const blob = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(64 << 20)) catch return error.SkipZigTest;
        try testing.expect(blob.len > 0 and blob[0] == 1);
        var idx = try types.index.CheckpointIndex.init(testing.allocator);
        defer idx.deinit(testing.allocator);
        try types.index.indexCheckpointData(blob, &idx);
        const raws = try arena.alloc([]const u8, idx.obj_total);
        for (idx.objs[0..idx.obj_total], raws) |o, *d| d.* = o.slice(blob);
        const os = try objset.ObjSet.build(arena, raws);
        for (idx.txs[0..idx.tx_count]) |tx| {
            const data = tx.data.slice(blob);
            const effects = tx.effects.slice(blob);
            const events = if (tx.events) |e| e.slice(blob) else null;
            const keys = try transactionKeys(arena, data, effects, events, &os);
            try testing.expect(keys.contains(&tx_universe_key));
            const td = try bcs.decode(types.TransactionData, arena, data);
            try testing.expect(keys.contains(try encodeKey(arena, .sender, &td.V1.sender.@"0")));
            const eff = try bcs.decode(types.TransactionEffects, arena, effects);
            for (try objectChanges(arena, &eff)) |c| try testing.expect(keys.contains(try encodeKey(arena, .affected_object, &c.id)));
            switch (td.V1.kind) {
                .ProgrammableTransaction => |pt| for (pt.commands) |cmd| if (cmd == .MoveCall) {
                    const m = cmd.MoveCall;
                    saw_call = true;
                    const pkg = &m.package.@"0".@"0";
                    try testing.expect(keys.contains(try encodeKey(arena, .move_call, pkg)));
                    try testing.expect(keys.contains(try encodeKey(arena, .move_call, try moveCallValue(arena, pkg, str(m.module), null))));
                    try testing.expect(keys.contains(try encodeKey(arena, .move_call, try moveCallValue(arena, pkg, str(m.module), str(m.function)))));
                },
                else => {},
            }
            if (events) |eb| {
                const evs = try bcs.decode(types.TransactionEvents, arena, eb);
                for (evs.data) |ev| {
                    saw_event = true;
                    const a = &ev.type_.address.@"0";
                    try testing.expect(keys.contains(try encodeKey(arena, .event_type, try eventTypeValue(arena, a, ev.type_.module.@"0", ev.type_.name.@"0", null))));
                    try testing.expect(keys.contains(try encodeKey(arena, .emit_module, try emitModuleValue(arena, &ev.package_id.@"0".@"0", ev.transaction_module.@"0"))));
                }
                // no EventExtant in tx space
                try testing.expect(!keys.contains(&event_extant_key));
            }
            // a user transaction pays gas from an address-owned coin: its owner is affected
            if (td.V1.kind == .ProgrammableTransaction) {
                var any_aa = false;
                var it = keys.keyIterator();
                while (it.next()) |k| any_aa = any_aa or k.*[0] == @intFromEnum(Dim.affected_address);
                try testing.expect(any_aa);
            }
        }
    }
    try testing.expect(saw_call and saw_event);
}

test "event_type generic parse errors are move-core-types' texts" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const z = "0x0000000000000000000000000000000000000000000000000000000000000002";
    const ones: [65]u8 = @splat('1');
    const Case = struct { s: []const u8, err: ?[]const u8 };
    const cases = [_]Case{
        // sui-node 1.83.1, live (tools/stream-compare --errors)
        .{ .s = z ++ "::coin::Coin<0x2::sui::>", .err = "expected token [identifier], got >" },
        .{ .s = z ++ "::coin::Coin<2::sui::SUI>", .err = null },
        .{ .s = z ++ "::coin::Coin<sui::sui::SUI>", .err = null },
        // grammar (parser.rs)
        .{ .s = z ++ "::coin::Coin<>", .err = "expected at least one type argument" },
        .{ .s = z ++ "::coin::Coin<u8", .err = "unexpected end of tokens" },
        .{ .s = z ++ "::coin::Coin<u8>>", .err = "Expected end of token stream. Got: >" },
        .{ .s = z ++ "::coin::Coin<,>", .err = "unexpected token ,, expected type" },
        .{ .s = z ++ "::coin::Coin<u8 u8>", .err = "expected token ,, got [identifier]" },
        .{ .s = z ++ "::coin::Coin<u8,>", .err = null },
        .{ .s = z ++ "::coin::Coin<0x::a::B>", .err = "unrecognized token: 0x::a::B>" },
        .{ .s = z ++ "::coin::Coin<a:b>", .err = "unrecognized token: :b>" },
        .{ .s = z ++ "::coin::Coin<$>", .err = "unrecognized token: $>" },
        .{ .s = z ++ "::coin::Coin<foo::a::B>", .err = "Unbound named address: 'foo'" },
        .{ .s = z ++ "::coin::Coin<foo::a::B, $>", .err = "unrecognized token: $>" },
        .{ .s = z ++ "::coin::Coin<0x1_0::a::B>", .err = null },
        .{ .s = z ++ "::coin::Coin<0x" ++ ones ++ "::a::B>", .err = "Failed to parse numerical address '0x" ++ ones ++ "'. Got error: Invalid address literal. The numeric value is too large. The maximum size is 32 bytes" },
        .{ .s = z ++ "::coin::Coin<vector<u8>>", .err = null },
        .{ .s = z ++ "::coin::Coin<vector u8>", .err = "expected token <, got [identifier]" },
    };
    for (cases) |c| {
        var p: TypeParser = .{ .arena = arena, .s = c.s };
        if (p.parseAll()) |_| {
            if (c.err) |e| {
                std.debug.print("{s}: parsed, want {s}\n", .{ c.s, e });
                return error.TestUnexpectedResult;
            }
        } else |e| {
            try t.expectEqual(error.Syntax, e);
            const want = c.err orelse {
                std.debug.print("{s}: {s}\n", .{ c.s, p.err });
                return error.TestUnexpectedResult;
            };
            try t.expectEqualStrings(want, p.err);
        }
    }
    // decimal 2 and `sui` name the same address as 0x2
    var p1: TypeParser = .{ .arena = arena, .s = z ++ "::coin::Coin<2::sui::SUI>" };
    var p2: TypeParser = .{ .arena = arena, .s = z ++ "::coin::Coin<sui::sui::SUI>" };
    const t1 = try p1.parseAll();
    const t2 = try p2.parseAll();
    try t.expectEqualSlices(u8, &t1.@"struct".type_args[0].@"struct".address.@"0", &t2.@"struct".type_args[0].@"struct".address.@"0");
}
