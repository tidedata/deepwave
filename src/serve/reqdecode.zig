//! prost's decode of the request messages, replayed to produce the exact `DecodeError` text.
//! tonic answers a request that prost rejects with INTERNAL and `error.to_string()`:
//! `failed to decode Protobuf message: <Msg>.<field>: ...: <description>` (innermost frame first).
//! `check` mirrors prost-0.14's `Message::decode` for the sui.rpc.v2 request messages the service
//! reads: wire type checks, varints, length delimiters, UTF-8, groups in unknown fields and the
//! recursion limit. It reads no values; the handlers do that once the request is known to decode.
const std = @import("std");

pub const Kind = enum { u64, string, bytes, msg };
pub const Field = struct { n: u32, name: []const u8, kind: Kind, sub: ?*const Msg = null, as: ?[]const u8 = null };
pub const Msg = struct { name: []const u8, fields: []const Field };

const field_mask: Msg = .{ .name = "FieldMask", .fields = &.{.{ .n = 1, .name = "paths", .kind = .string }} };
const get_object: Msg = .{ .name = "GetObjectRequest", .fields = &.{
    .{ .n = 1, .name = "object_id", .kind = .string },
    .{ .n = 2, .name = "version", .kind = .u64 },
    .{ .n = 3, .name = "read_mask", .kind = .msg, .sub = &field_mask },
} };
pub const get_object_request = get_object;
pub const batch_get_objects_request: Msg = .{ .name = "BatchGetObjectsRequest", .fields = &.{
    .{ .n = 1, .name = "requests", .kind = .msg, .sub = &get_object },
    .{ .n = 2, .name = "read_mask", .kind = .msg, .sub = &field_mask },
} };
pub const get_transaction_request: Msg = .{ .name = "GetTransactionRequest", .fields = &.{
    .{ .n = 1, .name = "digest", .kind = .string },
    .{ .n = 2, .name = "read_mask", .kind = .msg, .sub = &field_mask },
} };
pub const batch_get_transactions_request: Msg = .{ .name = "BatchGetTransactionsRequest", .fields = &.{
    .{ .n = 1, .name = "digests", .kind = .string },
    .{ .n = 2, .name = "read_mask", .kind = .msg, .sub = &field_mask },
} };
pub const get_checkpoint_request: Msg = .{ .name = "GetCheckpointRequest", .fields = &.{
    .{ .n = 1, .name = "sequence_number", .kind = .u64, .as = "checkpoint_id" },
    .{ .n = 2, .name = "digest", .kind = .string, .as = "checkpoint_id" },
    .{ .n = 3, .name = "read_mask", .kind = .msg, .sub = &field_mask },
} };
pub const get_package_request: Msg = .{ .name = "GetPackageRequest", .fields = &.{
    .{ .n = 1, .name = "package_id", .kind = .string },
    .{ .n = 2, .name = "version", .kind = .u64, .as = "selector" },
    .{ .n = 3, .name = "at_checkpoint", .kind = .u64, .as = "selector" },
} };
pub const get_datatype_request: Msg = .{ .name = "GetDatatypeRequest", .fields = &.{
    .{ .n = 1, .name = "package_id", .kind = .string },
    .{ .n = 2, .name = "module_name", .kind = .string },
    .{ .n = 3, .name = "name", .kind = .string },
} };
pub const get_function_request: Msg = .{ .name = "GetFunctionRequest", .fields = &.{
    .{ .n = 1, .name = "package_id", .kind = .string },
    .{ .n = 2, .name = "module_name", .kind = .string },
    .{ .n = 3, .name = "name", .kind = .string },
} };
const addr_filter = struct {
    fn msg(comptime name: []const u8, comptime field: []const u8) Msg {
        return .{ .name = name, .fields = &.{.{ .n = 1, .name = field, .kind = .string }} };
    }
};
const sender_filter = addr_filter.msg("SenderFilter", "address");
const affected_address_filter = addr_filter.msg("AffectedAddressFilter", "address");
const affected_object_filter = addr_filter.msg("AffectedObjectFilter", "object_id");
const move_call_filter = addr_filter.msg("MoveCallFilter", "function");
const emit_module_filter = addr_filter.msg("EmitModuleFilter", "module");
const event_type_filter = addr_filter.msg("EventTypeFilter", "event_type");
const event_stream_head_filter = addr_filter.msg("EventStreamHeadFilter", "stream_id");
const package_write_filter: Msg = .{ .name = "PackageWriteFilter", .fields = &.{} };
const transaction_literal: Msg = .{ .name = "TransactionLiteral", .fields = &.{
    .{ .n = 1, .name = "negated", .kind = .u64 },
    .{ .n = 2, .name = "sender", .kind = .msg, .sub = &sender_filter, .as = "predicate" },
    .{ .n = 3, .name = "affected_address", .kind = .msg, .sub = &affected_address_filter, .as = "predicate" },
    .{ .n = 4, .name = "affected_object", .kind = .msg, .sub = &affected_object_filter, .as = "predicate" },
    .{ .n = 5, .name = "move_call", .kind = .msg, .sub = &move_call_filter, .as = "predicate" },
    .{ .n = 6, .name = "emit_module", .kind = .msg, .sub = &emit_module_filter, .as = "predicate" },
    .{ .n = 7, .name = "event_type", .kind = .msg, .sub = &event_type_filter, .as = "predicate" },
    .{ .n = 8, .name = "event_stream_head", .kind = .msg, .sub = &event_stream_head_filter, .as = "predicate" },
    .{ .n = 9, .name = "package_write", .kind = .msg, .sub = &package_write_filter, .as = "predicate" },
} };
const transaction_term: Msg = .{ .name = "TransactionTerm", .fields = &.{.{ .n = 1, .name = "literals", .kind = .msg, .sub = &transaction_literal }} };
const transaction_filter: Msg = .{ .name = "TransactionFilter", .fields = &.{.{ .n = 1, .name = "terms", .kind = .msg, .sub = &transaction_term }} };
pub const subscribe_checkpoints_request: Msg = .{ .name = "SubscribeCheckpointsRequest", .fields = &.{
    .{ .n = 1, .name = "read_mask", .kind = .msg, .sub = &field_mask },
    .{ .n = 2, .name = "filter", .kind = .msg, .sub = &transaction_filter },
} };
pub const subscribe_transactions_request: Msg = .{ .name = "SubscribeTransactionsRequest", .fields = &.{
    .{ .n = 1, .name = "read_mask", .kind = .msg, .sub = &field_mask },
    .{ .n = 2, .name = "filter", .kind = .msg, .sub = &transaction_filter },
} };
const event_literal: Msg = .{ .name = "EventLiteral", .fields = &.{
    .{ .n = 1, .name = "negated", .kind = .u64 },
    .{ .n = 2, .name = "sender", .kind = .msg, .sub = &sender_filter, .as = "predicate" },
    .{ .n = 3, .name = "emit_module", .kind = .msg, .sub = &emit_module_filter, .as = "predicate" },
    .{ .n = 4, .name = "event_type", .kind = .msg, .sub = &event_type_filter, .as = "predicate" },
    .{ .n = 5, .name = "event_stream_head", .kind = .msg, .sub = &event_stream_head_filter, .as = "predicate" },
} };
const event_term: Msg = .{ .name = "EventTerm", .fields = &.{.{ .n = 1, .name = "literals", .kind = .msg, .sub = &event_literal }} };
const event_filter: Msg = .{ .name = "EventFilter", .fields = &.{.{ .n = 1, .name = "terms", .kind = .msg, .sub = &event_term }} };
pub const subscribe_events_request: Msg = .{ .name = "SubscribeEventsRequest", .fields = &.{
    .{ .n = 1, .name = "read_mask", .kind = .msg, .sub = &field_mask },
    .{ .n = 2, .name = "filter", .kind = .msg, .sub = &event_filter },
} };
// sui.rpc.v2alpha.ProofService (proof.zig)
pub const get_checkpoint_object_proof_request: Msg = .{ .name = "GetCheckpointObjectProofRequest", .fields = &.{
    .{ .n = 1, .name = "object_id", .kind = .string },
    .{ .n = 2, .name = "checkpoint", .kind = .u64 },
} };
pub const empty_request: Msg = .{ .name = "GetServiceInfoRequest", .fields = &.{} };
// epoch-pkg lane (DROP-IN G6, G8)
pub const get_epoch_request: Msg = .{ .name = "GetEpochRequest", .fields = &.{
    .{ .n = 1, .name = "epoch", .kind = .u64 },
    .{ .n = 2, .name = "read_mask", .kind = .msg, .sub = &field_mask },
} };
pub const list_package_versions_request: Msg = .{ .name = "ListPackageVersionsRequest", .fields = &.{
    .{ .n = 1, .name = "package_id", .kind = .string },
    .{ .n = 2, .name = "page_size", .kind = .u64 },
    .{ .n = 3, .name = "page_token", .kind = .bytes },
} };
pub const lookup_name_request: Msg = .{ .name = "LookupNameRequest", .fields = &.{.{ .n = 1, .name = "name", .kind = .string }} };
pub const reverse_lookup_name_request: Msg = .{ .name = "ReverseLookupNameRequest", .fields = &.{.{ .n = 1, .name = "address", .kind = .string }} };

// ---- SignatureVerificationService (sui-rpc 8c356d6 protos) ----
const bcs_msg: Msg = .{ .name = "Bcs", .fields = &.{
    .{ .n = 1, .name = "name", .kind = .string },
    .{ .n = 2, .name = "value", .kind = .bytes },
} };
const simple_signature: Msg = .{ .name = "SimpleSignature", .fields = &.{
    .{ .n = 1, .name = "scheme", .kind = .u64 },
    .{ .n = 2, .name = "signature", .kind = .bytes },
    .{ .n = 3, .name = "public_key", .kind = .bytes },
} };
const zk_identifier: Msg = .{ .name = "ZkLoginPublicIdentifier", .fields = &.{
    .{ .n = 1, .name = "iss", .kind = .string },
    .{ .n = 2, .name = "address_seed", .kind = .string },
} };
const circom_g1: Msg = .{ .name = "CircomG1", .fields = &.{
    .{ .n = 1, .name = "e0", .kind = .string },
    .{ .n = 2, .name = "e1", .kind = .string },
    .{ .n = 3, .name = "e2", .kind = .string },
} };
const circom_g2: Msg = .{ .name = "CircomG2", .fields = &.{
    .{ .n = 1, .name = "e00", .kind = .string },
    .{ .n = 2, .name = "e01", .kind = .string },
    .{ .n = 3, .name = "e10", .kind = .string },
    .{ .n = 4, .name = "e11", .kind = .string },
    .{ .n = 5, .name = "e20", .kind = .string },
    .{ .n = 6, .name = "e21", .kind = .string },
} };
const zk_proof: Msg = .{ .name = "ZkLoginProof", .fields = &.{
    .{ .n = 1, .name = "a", .kind = .msg, .sub = &circom_g1 },
    .{ .n = 2, .name = "b", .kind = .msg, .sub = &circom_g2 },
    .{ .n = 3, .name = "c", .kind = .msg, .sub = &circom_g1 },
} };
const zk_claim: Msg = .{ .name = "ZkLoginClaim", .fields = &.{
    .{ .n = 1, .name = "value", .kind = .string },
    .{ .n = 2, .name = "index_mod_4", .kind = .u64 },
} };
const zk_inputs: Msg = .{ .name = "ZkLoginInputs", .fields = &.{
    .{ .n = 1, .name = "proof_points", .kind = .msg, .sub = &zk_proof },
    .{ .n = 2, .name = "iss_base64_details", .kind = .msg, .sub = &zk_claim },
    .{ .n = 3, .name = "header_base64", .kind = .string },
    .{ .n = 4, .name = "address_seed", .kind = .string },
} };
const jwk_id: Msg = .{ .name = "JwkId", .fields = &.{
    .{ .n = 1, .name = "iss", .kind = .string },
    .{ .n = 2, .name = "kid", .kind = .string },
} };
const zk_authenticator: Msg = .{ .name = "ZkLoginAuthenticator", .fields = &.{
    .{ .n = 1, .name = "inputs", .kind = .msg, .sub = &zk_inputs },
    .{ .n = 2, .name = "max_epoch", .kind = .u64 },
    .{ .n = 3, .name = "signature", .kind = .msg, .sub = &simple_signature },
    .{ .n = 4, .name = "public_identifier", .kind = .msg, .sub = &zk_identifier },
    .{ .n = 5, .name = "jwk_id", .kind = .msg, .sub = &jwk_id },
} };
const passkey_authenticator: Msg = .{ .name = "PasskeyAuthenticator", .fields = &.{
    .{ .n = 1, .name = "authenticator_data", .kind = .bytes },
    .{ .n = 2, .name = "client_data_json", .kind = .string },
    .{ .n = 3, .name = "signature", .kind = .msg, .sub = &simple_signature },
} };
const multisig_member_pk: Msg = .{ .name = "MultisigMemberPublicKey", .fields = &.{
    .{ .n = 1, .name = "scheme", .kind = .u64 },
    .{ .n = 2, .name = "public_key", .kind = .bytes },
    .{ .n = 3, .name = "zklogin", .kind = .msg, .sub = &zk_identifier },
} };
const multisig_member: Msg = .{ .name = "MultisigMember", .fields = &.{
    .{ .n = 1, .name = "public_key", .kind = .msg, .sub = &multisig_member_pk },
    .{ .n = 2, .name = "weight", .kind = .u64 },
} };
const multisig_committee: Msg = .{ .name = "MultisigCommittee", .fields = &.{
    .{ .n = 1, .name = "members", .kind = .msg, .sub = &multisig_member },
    .{ .n = 2, .name = "threshold", .kind = .u64 },
} };
const multisig_member_sig: Msg = .{ .name = "MultisigMemberSignature", .fields = &.{
    .{ .n = 1, .name = "scheme", .kind = .u64 },
    .{ .n = 2, .name = "signature", .kind = .bytes },
    .{ .n = 3, .name = "zklogin", .kind = .msg, .sub = &zk_authenticator },
    .{ .n = 4, .name = "passkey", .kind = .msg, .sub = &passkey_authenticator },
} };
const multisig_aggregated: Msg = .{ .name = "MultisigAggregatedSignature", .fields = &.{
    .{ .n = 1, .name = "signatures", .kind = .msg, .sub = &multisig_member_sig },
    .{ .n = 2, .name = "bitmap", .kind = .u64 },
    .{ .n = 3, .name = "legacy_bitmap", .kind = .bytes },
    .{ .n = 4, .name = "committee", .kind = .msg, .sub = &multisig_committee },
} };
const user_signature: Msg = .{ .name = "UserSignature", .fields = &.{
    .{ .n = 1, .name = "bcs", .kind = .msg, .sub = &bcs_msg },
    .{ .n = 2, .name = "scheme", .kind = .u64 },
    .{ .n = 3, .name = "simple", .kind = .msg, .sub = &simple_signature, .as = "signature" },
    .{ .n = 4, .name = "multisig", .kind = .msg, .sub = &multisig_aggregated, .as = "signature" },
    .{ .n = 5, .name = "zklogin", .kind = .msg, .sub = &zk_authenticator, .as = "signature" },
    .{ .n = 6, .name = "passkey", .kind = .msg, .sub = &passkey_authenticator, .as = "signature" },
} };
const jwk: Msg = .{ .name = "Jwk", .fields = &.{
    .{ .n = 1, .name = "kty", .kind = .string },
    .{ .n = 2, .name = "e", .kind = .string },
    .{ .n = 3, .name = "n", .kind = .string },
    .{ .n = 4, .name = "alg", .kind = .string },
} };
const active_jwk: Msg = .{ .name = "ActiveJwk", .fields = &.{
    .{ .n = 1, .name = "id", .kind = .msg, .sub = &jwk_id },
    .{ .n = 2, .name = "jwk", .kind = .msg, .sub = &jwk },
    .{ .n = 3, .name = "epoch", .kind = .u64 },
} };
pub const verify_signature_request: Msg = .{ .name = "VerifySignatureRequest", .fields = &.{
    .{ .n = 1, .name = "message", .kind = .msg, .sub = &bcs_msg },
    .{ .n = 2, .name = "signature", .kind = .msg, .sub = &user_signature },
    .{ .n = 3, .name = "address", .kind = .string },
    .{ .n = 4, .name = "jwks", .kind = .msg, .sub = &active_jwk },
    .{ .n = 6, .name = "check_address_aliases", .kind = .u64 },
} };

const recursion_limit = 100;

const Frame = struct { msg: []const u8, field: []const u8 };

const D = struct {
    buf: []const u8,
    pos: usize = 0,
    desc: []const u8 = "",
    stack: [8]Frame = undefined,
    depth: usize = 0,

    fn fail(d: *D, comptime fmt: []const u8, args: anytype, scratch: *[96]u8) error{Decode} {
        d.desc = std.fmt.bufPrint(scratch, fmt, args) catch "decode error";
        return error.Decode;
    }
    fn remaining(d: *const D) usize {
        return d.buf.len - d.pos;
    }
};

const Err = error{Decode};

fn varint(d: *D, sc: *[96]u8) Err!u64 {
    var v: u64 = 0;
    var count: u6 = 0;
    while (count < 10 and d.pos < d.buf.len) : (count += 1) {
        const b = d.buf[d.pos];
        d.pos += 1;
        v |= @as(u64, b & 0x7f) << (count * 7);
        if (b < 0x80) {
            if (count == 9 and b >= 2) return d.fail("invalid varint", .{}, sc);
            return v;
        }
    }
    return d.fail("invalid varint", .{}, sc);
}

const wire_names = [_][]const u8{ "Varint", "SixtyFourBit", "LengthDelimited", "StartGroup", "EndGroup", "ThirtyTwoBit" };

fn key(d: *D, sc: *[96]u8) Err!struct { tag: u32, wire: u3 } {
    const k = try varint(d, sc);
    if (k > std.math.maxInt(u32)) return d.fail("invalid key value: {d}", .{k}, sc);
    const w: u64 = k & 7;
    if (w > 5) return d.fail("invalid wire type value: {d}", .{w}, sc);
    const tag: u32 = @intCast(k >> 3);
    if (tag < 1) return d.fail("invalid tag value: 0", .{}, sc);
    return .{ .tag = tag, .wire = @intCast(w) };
}

fn wireIs(d: *D, expected: u3, actual: u3, sc: *[96]u8) Err!void {
    if (expected != actual) return d.fail("invalid wire type: {s} (expected {s})", .{ wire_names[actual], wire_names[expected] }, sc);
}

fn skipField(d: *D, wire: u3, tag: u32, budget: u32, sc: *[96]u8) Err!void {
    if (budget == 0) return d.fail("recursion limit reached", .{}, sc);
    var len: u64 = 0;
    switch (wire) {
        0 => _ = try varint(d, sc),
        1 => len = 8,
        5 => len = 4,
        2 => len = try varint(d, sc),
        3 => while (true) {
            const k = try key(d, sc);
            if (k.wire == 4) {
                if (k.tag != tag) return d.fail("unexpected end group tag", .{}, sc);
                break;
            }
            try skipField(d, k.wire, k.tag, budget - 1, sc);
        },
        else => return d.fail("unexpected end group tag", .{}, sc),
    }
    if (len > d.remaining()) return d.fail("buffer underflow", .{}, sc);
    d.pos += @intCast(len);
}

fn push(d: *D, msg: []const u8, field: []const u8) void {
    if (d.depth < d.stack.len) d.stack[d.depth] = .{ .msg = msg, .field = field };
    d.depth += 1;
}

/// The body of `msg` up to the end of the buffer or `limit` bytes before the end.
fn mergeBody(d: *D, msg: *const Msg, limit: usize, budget: u32, sc: *[96]u8) Err!void {
    while (d.remaining() > limit) {
        const k = try key(d, sc);
        var known: ?*const Field = null;
        for (msg.fields) |*f| if (f.n == k.tag) {
            known = f;
            break;
        };
        const f = known orelse {
            try skipField(d, k.wire, k.tag, budget, sc);
            continue;
        };
        mergeField(d, f, k.wire, budget, sc) catch |e| {
            push(d, msg.name, f.as orelse f.name);
            return e;
        };
    }
}

fn mergeField(d: *D, f: *const Field, wire: u3, budget: u32, sc: *[96]u8) Err!void {
    switch (f.kind) {
        .u64 => {
            try wireIs(d, 0, wire, sc);
            _ = try varint(d, sc);
        },
        .string => {
            try wireIs(d, 2, wire, sc);
            const len = try varint(d, sc);
            if (len > d.remaining()) return d.fail("buffer underflow", .{}, sc);
            const s = d.buf[d.pos..][0..@intCast(len)];
            d.pos += s.len;
            if (!std.unicode.utf8ValidateSlice(s)) return d.fail("invalid string value: data is not UTF-8 encoded", .{}, sc);
        },
        .bytes => {
            try wireIs(d, 2, wire, sc);
            const len = try varint(d, sc);
            if (len > d.remaining()) return d.fail("buffer underflow", .{}, sc);
            d.pos += @intCast(len);
        },
        .msg => {
            try wireIs(d, 2, wire, sc);
            if (budget == 0) return d.fail("recursion limit reached", .{}, sc);
            const len = try varint(d, sc);
            const rem = d.remaining();
            if (len > rem) return d.fail("buffer underflow", .{}, sc);
            const limit = rem - @as(usize, @intCast(len));
            try mergeBody(d, f.sub.?, limit, budget - 1, sc);
            if (d.remaining() != limit) return d.fail("delimited length exceeded", .{}, sc);
        },
    }
}

/// Null when prost decodes `body` as `msg`; otherwise tonic's INTERNAL message.
pub fn check(arena: std.mem.Allocator, msg: *const Msg, body: []const u8) ?[]const u8 {
    var d: D = .{ .buf = body };
    var sc: [96]u8 = undefined;
    mergeBody(&d, msg, 0, recursion_limit, &sc) catch {
        var out: std.ArrayList(u8) = .empty;
        out.appendSlice(arena, "failed to decode Protobuf message: ") catch return "failed to decode Protobuf message";
        for (d.stack[0..@min(d.depth, d.stack.len)]) |fr| {
            out.print(arena, "{s}.{s}: ", .{ fr.msg, fr.field }) catch break;
        }
        out.appendSlice(arena, d.desc) catch {};
        return out.items;
    };
    return null;
}

test "decode errors" {
    var ar = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    try std.testing.expect(check(a, &get_transaction_request, &.{ 0x0a, 0x01, 'x' }) == null);
    try std.testing.expectEqualStrings(
        "failed to decode Protobuf message: GetTransactionRequest.digest: invalid wire type: Varint (expected LengthDelimited)",
        check(a, &get_transaction_request, &.{ 0x08, 0x01 }).?,
    );
    try std.testing.expectEqualStrings(
        "failed to decode Protobuf message: GetTransactionRequest.digest: invalid string value: data is not UTF-8 encoded",
        check(a, &get_transaction_request, &.{ 0x0a, 0x01, 0xff }).?,
    );
}
