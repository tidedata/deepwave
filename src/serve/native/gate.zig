//! The access-gate hook of the zui/1 serving paths (docs/GATE.md, docs/NATIVE-PROTOCOL.md 6.2).
//! Null (the default): nothing here runs and every answer is what it was. With a hook, a
//! connection's key is its hello token (or the WebTransport CONNECT token), and each request is
//! put to the hook before it is dispatched.
//!
//! The hook is a set of function pointers so this module does not depend on the gate itself
//! (the node wires them to `edge.gate`). None of them may block: the listener calls them on its
//! I/O thread. A key that is still being looked up answers `.wait`, and the listener asks again
//! on its next pass until the hook is told `may_wait = false`.
const std = @import("std");
const Io = std.Io;
const proto = @import("proto.zig");

/// What the hook hands back for an admitted request and gets again when it is settled. Opaque
/// here.
pub const Ticket = struct {
    bytes: [size]u8 align(16) = undefined,
    pub const size = 160;
};

pub const Refusal = struct {
    code: proto.Code,
    message: []const u8,
    /// RATE_LIMITED detail (0: none).
    retry_after_ms: u32 = 0,
};

pub const Verdict = union(enum) {
    allow: Ticket,
    wait,
    deny: Refusal,
};

pub const Hello = union(enum) {
    ok,
    wait,
    deny: Refusal,
};

/// How long a request may wait for its key's lookup before it is treated as keyless.
pub const wait_ms: u64 = 150;

pub const Hook = struct {
    ctx: *anyopaque,
    /// A hello that carries a token: is the key refused outright (invalid, suspended)?
    hello: *const fn (ctx: *anyopaque, key: []const u8, peer: Io.net.IpAddress, may_wait: bool) Hello,
    /// One request. `key` is the connection's key ("" for none), `body` the request body (the
    /// hook reads a batch's size from it), `stream` true for a subscription.
    admit: *const fn (ctx: *anyopaque, key: []const u8, peer: Io.net.IpAddress, method: proto.Method, body: []const u8, may_wait: bool) Verdict,
    /// The request was answered: `ok` false when the answer is an error (it then costs nothing).
    settle: *const fn (ctx: *anyopaque, t: *const Ticket, ok: bool) void,
    /// A subscription delivered `frames` more frames. A refusal ends it.
    stream_frames: *const fn (ctx: *anyopaque, t: *Ticket, key: []const u8, frames: u32) ?Refusal,
    stream_close: *const fn (ctx: *anyopaque, t: *Ticket) void,
};

/// A refusal as a whole zui/1 error response (RATE_LIMITED carries `retry_after_ms` as its
/// detail, u32 LE).
pub fn respond(out: *std.ArrayList(u8), a: std.mem.Allocator, r: Refusal) !void {
    var d: [4]u8 = undefined;
    std.mem.writeInt(u32, &d, r.retry_after_ms, .little);
    try proto.errorResponse(out, a, r.code, r.message, if (r.code == .rate_limited) &d else "");
}

test "a refusal is an ordinary zui/1 error response" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try respond(&out, gpa, .{ .code = .rate_limited, .message = "rate limit exceeded", .retry_after_ms = 250 });
    const resp = proto.parseResponse(out.items).?;
    try std.testing.expectEqual(@as(u8, 6), resp.status);
    var r: proto.R = .{ .b = resp.body };
    try std.testing.expectEqual(@as(u32, 6), try r.int(u32));
    try std.testing.expectEqualStrings("rate limit exceeded", try r.str());
    try std.testing.expectEqualSlices(u8, &.{ 250, 0, 0, 0 }, try r.bytes());
    try respond(&out, gpa, .{ .code = .permission_denied, .message = "key revoked" });
    const resp2 = proto.parseResponse(out.items).?;
    try std.testing.expectEqual(@as(u8, 8), resp2.status);
    var r2: proto.R = .{ .b = resp2.body };
    _ = try r2.int(u32);
    try std.testing.expectEqualStrings("key revoked", try r2.str());
    try std.testing.expectEqual(@as(usize, 0), (try r2.bytes()).len);
}
