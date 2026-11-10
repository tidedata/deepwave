//! google.rpc.Status detail payloads the way sui-rpc-api's `RpcError` builds them (error.rs):
//! `Status { code, message, details: [Any(ErrorInfo), Any(BadRequest), ...] }`, sent in the
//! `grpc-status-details-bin` trailer. Also read_mask validation (`FieldMaskUtil::validate`).
const std = @import("std");
const Allocator = std.mem.Allocator;
const proto = @import("proto.zig");
const schema = @import("schema.zig");

/// First path of `paths` that is not valid for `root` (a message name from schema.zig), or null.
/// `*` is always valid; the empty path is not.
pub fn invalidPath(root: i16, paths: []const []const u8) ?[]const u8 {
    for (paths) |path| {
        if (std.mem.eql(u8, path, "*")) continue;
        if (!validPath(root, path)) return path;
    }
    return null;
}

fn validPath(root: i16, path0: []const u8) bool {
    var fields = schema.messages[@intCast(root)].fields;
    var path = path0;
    while (true) {
        const dot = std.mem.indexOfScalar(u8, path, '.');
        const name = if (dot) |d| path[0..d] else path;
        const rem: ?[]const u8 = if (dot) |d| (if (d + 1 < path.len) path[d + 1 ..] else null) else null;
        var found: ?schema.Field = null;
        for (fields) |f| if (std.mem.eql(u8, f.name, name)) {
            found = f;
            break;
        };
        const f = found orelse return false;
        if (rem) |r| {
            if (f.sub < 0) return false;
            fields = schema.messages[@intCast(f.sub)].fields;
            path = r;
        } else return true;
    }
}

/// prost `Name::type_url` of the generated google.rpc types (no host part).
pub const type_url_bad_request = "/google.rpc.BadRequest";

/// `ErrorReason::as_str_name` (sui.rpc.v2), used as `FieldViolation.reason`.
pub const Reason = enum { field_invalid, field_missing };

fn reasonName(r: Reason) []const u8 {
    return switch (r) {
        .field_invalid => "FIELD_INVALID",
        .field_missing => "FIELD_MISSING",
    };
}

fn str(w: *proto.Writer, field: u32, s: []const u8) !void {
    if (s.len > 0) try w.string(field, s);
}

/// `Status { code, message, details = [Any(BadRequest { field_violations = [{field, description, reason}] })] }`.
pub fn badRequest(arena: Allocator, code: u32, field: []const u8, description: []const u8, reason: Reason) ![]const u8 {
    // BadRequest.FieldViolation: field = 1, description = 2, reason = 3
    const vbuf = try arena.alloc(u8, field.len + description.len + 64);
    var vw = proto.Writer.init(vbuf);
    try str(&vw, 1, field);
    try str(&vw, 2, description);
    try str(&vw, 3, reasonName(reason));
    // BadRequest: repeated field_violations = 1
    const bbuf = try arena.alloc(u8, vw.len + 16);
    var bw = proto.Writer.init(bbuf);
    try bw.bytes(1, vw.bytesWritten());
    // Any: type_url = 1, value = 2
    const abuf = try arena.alloc(u8, bw.len + type_url_bad_request.len + 16);
    var aw = proto.Writer.init(abuf);
    try str(&aw, 1, type_url_bad_request);
    try aw.bytes(2, bw.bytesWritten());
    // Status: code = 1, message = 2, details = 3
    const sbuf = try arena.alloc(u8, aw.len + description.len + 32);
    var sw = proto.Writer.init(sbuf);
    try sw.uint(1, code);
    try str(&sw, 2, description);
    try sw.bytes(3, aw.bytesWritten());
    return sbuf[0..sw.len];
}

/// `Status { code, message }` without details (an item error of a batch reply).
pub fn plain(arena: Allocator, code: u32, message: []const u8) ![]const u8 {
    const buf = try arena.alloc(u8, message.len + 16);
    var w = proto.Writer.init(buf);
    try w.uint(1, code);
    try str(&w, 2, message);
    return w.bytesWritten();
}

test "read_mask validation" {
    const cp = comptime schema.index("Checkpoint");
    try std.testing.expect(invalidPath(cp, &.{ "sequence_number", "transactions.effects.bcs", "*", "objects.objects.bcs" }) == null);
    try std.testing.expectEqualStrings("summary.nope", invalidPath(cp, &.{ "digest", "summary.nope" }).?);
    try std.testing.expectEqualStrings("digest.x", invalidPath(cp, &.{"digest.x"}).?);
    try std.testing.expectEqualStrings("", invalidPath(cp, &.{""}).?);
    try std.testing.expect(invalidPath(cp, &.{"summary."}) == null);
}
