//! anemo wire format (anemo@68adc31 network/wire.rs): an 8-byte version frame `anemo 0x0001 0x00`,
//! then 4-byte big-endian length-prefixed frames. A request stream is
//! `version, frame(bincode RawRequestHeader), frame(body)`; a response stream is
//! `version, frame(bincode RawResponseHeader), frame(body)`. Headers are bincode 1.x defaults
//! (fixed-width little endian integers, u64 lengths).
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const version_frame = [8]u8{ 'a', 'n', 'e', 'm', 'o', 0, 1, 0 };
pub const default_max_frame: usize = 8 * 1024 * 1024;
/// sui-node: request frames 1 MiB, response frames 128 MiB.
pub const sui_max_request_frame: usize = 1 << 20;
pub const sui_max_response_frame: usize = 128 << 20;
const max_headers = 256;

pub const Error = error{ BadVersion, FrameTooLarge, Malformed, InvalidStatus, TooManyHeaders, OutOfMemory };

pub const Header = struct { name: []const u8, value: []const u8 };

/// `anemo::types::response::StatusCode`.
pub const Status = enum(u16) {
    success = 200,
    bad_request = 400,
    not_found = 404,
    request_timeout = 408,
    too_many_requests = 429,
    internal_server_error = 500,
    version_not_supported = 505,
    unknown = 520,

    pub fn fromU16(code: u16) ?Status {
        return switch (code) {
            200, 400, 404, 408, 429, 500, 505, 520 => @enumFromInt(code),
            else => null,
        };
    }
};

pub const Request = struct { route: []const u8, headers: []const Header, body: []const u8 };
pub const Response = struct { status: Status, headers: []const Header, body: []const u8 };

pub fn checkVersionFrame(buf: *const [8]u8) Error!void {
    if (!std.mem.eql(u8, buf[0..5], "anemo") or buf[7] != 0) return error.BadVersion;
    if (std.mem.readInt(u16, buf[5..7], .big) != 1) return error.BadVersion;
}

/// Name of a header the timeout layer adds: nanoseconds as a decimal u64.
pub const timeout_header = "timeout";

// ------------------------------------------------------------------ encode

pub const Builder = struct {
    list: std.ArrayList(u8) = .empty,

    pub fn appendFrame(b: *Builder, gpa: Allocator, payload: []const u8) Allocator.Error!void {
        try b.list.ensureUnusedCapacity(gpa, 4 + payload.len);
        var len: [4]u8 = undefined;
        std.mem.writeInt(u32, &len, @intCast(payload.len), .big);
        b.list.appendSliceAssumeCapacity(&len);
        b.list.appendSliceAssumeCapacity(payload);
    }
};

fn bincodeString(list: *std.ArrayList(u8), gpa: Allocator, s: []const u8) Allocator.Error!void {
    var l: [8]u8 = undefined;
    std.mem.writeInt(u64, &l, s.len, .little);
    try list.appendSlice(gpa, &l);
    try list.appendSlice(gpa, s);
}

fn bincodeHeaders(list: *std.ArrayList(u8), gpa: Allocator, headers: []const Header) Allocator.Error!void {
    var l: [8]u8 = undefined;
    std.mem.writeInt(u64, &l, headers.len, .little);
    try list.appendSlice(gpa, &l);
    for (headers) |h| {
        try bincodeString(list, gpa, h.name);
        try bincodeString(list, gpa, h.value);
    }
}

/// bincode(RawRequestHeader { route, headers }).
pub fn encodeRequestHeader(gpa: Allocator, route: []const u8, headers: []const Header) Allocator.Error![]u8 {
    var l: std.ArrayList(u8) = .empty;
    errdefer l.deinit(gpa);
    try bincodeString(&l, gpa, route);
    try bincodeHeaders(&l, gpa, headers);
    return l.toOwnedSlice(gpa);
}

/// bincode(RawResponseHeader { status, headers }).
pub fn encodeResponseHeader(gpa: Allocator, status: Status, headers: []const Header) Allocator.Error![]u8 {
    var l: std.ArrayList(u8) = .empty;
    errdefer l.deinit(gpa);
    var s: [2]u8 = undefined;
    std.mem.writeInt(u16, &s, @intFromEnum(status), .little);
    try l.appendSlice(gpa, &s);
    try bincodeHeaders(&l, gpa, headers);
    return l.toOwnedSlice(gpa);
}

/// The bytes a client writes on a request stream.
pub fn encodeRequest(gpa: Allocator, route: []const u8, headers: []const Header, body: []const u8) Allocator.Error![]u8 {
    const hdr = try encodeRequestHeader(gpa, route, headers);
    defer gpa.free(hdr);
    var b: Builder = .{};
    errdefer b.list.deinit(gpa);
    try b.list.ensureTotalCapacityPrecise(gpa, version_frame.len + 8 + hdr.len + body.len);
    b.list.appendSliceAssumeCapacity(&version_frame);
    try b.appendFrame(gpa, hdr);
    try b.appendFrame(gpa, body);
    return b.list.toOwnedSlice(gpa);
}

pub fn encodeResponse(gpa: Allocator, status: Status, headers: []const Header, body: []const u8) Allocator.Error![]u8 {
    const hdr = try encodeResponseHeader(gpa, status, headers);
    defer gpa.free(hdr);
    var b: Builder = .{};
    errdefer b.list.deinit(gpa);
    try b.list.ensureTotalCapacityPrecise(gpa, version_frame.len + 8 + hdr.len + body.len);
    b.list.appendSliceAssumeCapacity(&version_frame);
    try b.appendFrame(gpa, hdr);
    try b.appendFrame(gpa, body);
    return b.list.toOwnedSlice(gpa);
}

// ------------------------------------------------------------------ decode

/// Incremental frame reader over a growing contiguous buffer. Returns null until the whole
/// frame is present; the payload borrows `buf`.
pub fn nextFrame(buf: []const u8, pos: *usize, max_frame: usize) Error!?[]const u8 {
    if (buf.len - pos.* < 4) return null;
    const len: usize = std.mem.readInt(u32, buf[pos.*..][0..4], .big);
    if (len > max_frame) return error.FrameTooLarge;
    if (buf.len - pos.* - 4 < len) return null;
    const payload = buf[pos.* + 4 ..][0..len];
    pos.* += 4 + len;
    return payload;
}

const Cursor = struct {
    b: []const u8,
    p: usize = 0,
    fn u64le(c: *Cursor) Error!u64 {
        if (c.b.len - c.p < 8) return error.Malformed;
        const v = std.mem.readInt(u64, c.b[c.p..][0..8], .little);
        c.p += 8;
        return v;
    }
    fn str(c: *Cursor) Error![]const u8 {
        const n = try c.u64le();
        if (n > c.b.len - c.p) return error.Malformed;
        const s = c.b[c.p..][0..@intCast(n)];
        c.p += @intCast(n);
        if (!std.unicode.utf8ValidateSlice(s)) return error.Malformed;
        return s;
    }
    fn headers(c: *Cursor, arena: Allocator) Error![]const Header {
        const n = try c.u64le();
        if (n > max_headers) return error.TooManyHeaders;
        if (n > (c.b.len - c.p) / 16) return error.Malformed;
        const out = try arena.alloc(Header, @intCast(n));
        for (out) |*h| {
            h.name = try c.str();
            h.value = try c.str();
        }
        return out;
    }
};

/// Parses a response stream from the front of `buf`. Null when more bytes are needed. Header
/// strings and body borrow `buf`; the header slice is allocated in `arena`.
pub fn parseResponse(arena: Allocator, buf: []const u8, max_frame: usize) Error!?Response {
    if (buf.len < 8) return null;
    try checkVersionFrame(buf[0..8]);
    var pos: usize = 8;
    const hdr = (try nextFrame(buf, &pos, max_frame)) orelse return null;
    const body = (try nextFrame(buf, &pos, max_frame)) orelse return null;
    var c: Cursor = .{ .b = hdr };
    if (hdr.len < 2) return error.Malformed;
    const code = std.mem.readInt(u16, hdr[0..2], .little);
    c.p = 2;
    const status = Status.fromU16(code) orelse return error.InvalidStatus;
    const headers = try c.headers(arena);
    // bincode::deserialize (the free function) allows trailing bytes, so the header may be longer.
    return .{ .status = status, .headers = headers, .body = body };
}

pub fn parseRequest(arena: Allocator, buf: []const u8, max_frame: usize) Error!?Request {
    if (buf.len < 8) return null;
    try checkVersionFrame(buf[0..8]);
    var pos: usize = 8;
    const hdr = (try nextFrame(buf, &pos, max_frame)) orelse return null;
    const body = (try nextFrame(buf, &pos, max_frame)) orelse return null;
    var c: Cursor = .{ .b = hdr };
    const route = try c.str();
    const headers = try c.headers(arena);
    // trailing bytes allowed, as above
    return .{ .route = route, .headers = headers, .body = body };
}

test "version frame" {
    try checkVersionFrame(&version_frame);
    var bad = version_frame;
    bad[7] = 1;
    try std.testing.expectError(error.BadVersion, checkVersionFrame(&bad));
}

test "encoders return exactly-sized allocations (gpa-safe)" {
    const gpa = std.testing.allocator;
    const hs = [_]Header{ .{ .name = "timeout", .value = "1" }, .{ .name = "x-a", .value = "b" } };
    const req = try encodeRequest(gpa, "/a/b", &hs, "body");
    defer gpa.free(req);
    const resp = try encodeResponse(gpa, .not_found, &hs, "");
    defer gpa.free(resp);
    const h = try encodeRequestHeader(gpa, "/r", &.{});
    defer gpa.free(h);
    const rh = try encodeResponseHeader(gpa, .success, &hs);
    defer gpa.free(rh);
}

test "request round trip" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const hs = [_]Header{.{ .name = "timeout", .value = "30000000000" }};
    const enc = try encodeRequest(a, "/sui.StateSync/GetCheckpointSummary", &hs, "body");
    const req = (try parseRequest(a, enc, default_max_frame)).?;
    try std.testing.expectEqualStrings("/sui.StateSync/GetCheckpointSummary", req.route);
    try std.testing.expectEqualStrings("body", req.body);
    try std.testing.expectEqual(@as(usize, 1), req.headers.len);
    // incremental: every strict prefix is "need more"
    for (0..enc.len) |n| try std.testing.expect((try parseRequest(a, enc[0..n], default_max_frame)) == null);
}
