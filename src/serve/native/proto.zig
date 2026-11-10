//! zui/1 wire layer (docs/NATIVE-PROTOCOL.md sections 2, 4, 5, 8): QUIC varints for stream
//! headers, a minimal BCS writer for response envelopes (stored chain bytes are appended as
//! `vector<u8>` without re-encoding), a BCS reader for requests, method ids and error codes.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const alpn = "zui/1";
pub const minor: u16 = 0;

pub const Method = enum(u64) {
    hello = 0x00,
    get_object = 0x01,
    batch_get_objects = 0x02,
    get_checkpoint = 0x03,
    get_transaction = 0x04,
    batch_get_transactions = 0x05,
    list_owned_objects = 0x06,
    get_balance = 0x07,
    list_balances = 0x08,
    dry_run = 0x09,
    submit_transaction = 0x0a,
    get_dictionary = 0x0b,
    get_epoch_proof = 0x0c,
    get_epoch_info = 0x0d,
    subscribe = 0x20,
    pair_relay = 0x30,
    _,
};

pub const flag_verify: u64 = 0x1;
pub const flag_zstd_ok: u64 = 0x2;
pub const resp_zstd: u64 = 0x1;
pub const resp_proof: u64 = 0x2;

pub const part_contents: u8 = 0x01;
pub const part_tx: u8 = 0x02;
pub const part_effects: u8 = 0x04;
pub const part_events: u8 = 0x08;

pub const Code = enum(u32) {
    ok = 0,
    bad_request = 1,
    unimplemented = 2,
    not_found = 3,
    pruned = 4,
    unavailable = 5,
    rate_limited = 6,
    unauthenticated = 7,
    permission_denied = 8,
    too_large = 9,
    internal = 10,
    lagged = 11,
    tx_rejected = 12,
    timeout = 13,
    shutdown = 14,
};

pub const Frame = enum(u64) {
    checkpoint = 0x01,
    tx_match = 0x02,
    object_change = 0x03,
    event_match = 0x04,
    checkpoint_end = 0x05,
    heartbeat = 0x06,
    end = 0x07,
    proof = 0x08,
};

pub const max_batch_objects = 1000;
pub const max_batch_txs = 100;
pub const max_request_bytes = 128 << 10;
pub const max_submit_bytes = 1 << 20;

// ---------------------------------------------------------------- QUIC varints

pub fn varintLen(v: u64) usize {
    return if (v < 64) 1 else if (v < 16384) 2 else if (v < (1 << 30)) 4 else 8;
}

pub fn putVarint(out: *std.ArrayList(u8), gpa: Allocator, v: u64) Allocator.Error!void {
    var b: [8]u8 = undefined;
    const n = varintLen(v);
    switch (n) {
        1 => b[0] = @intCast(v),
        2 => std.mem.writeInt(u16, b[0..2], @as(u16, @intCast(v)) | 0x4000, .big),
        4 => std.mem.writeInt(u32, b[0..4], @as(u32, @intCast(v)) | 0x8000_0000, .big),
        else => std.mem.writeInt(u64, b[0..8], v | 0xC000_0000_0000_0000, .big),
    }
    try out.appendSlice(gpa, b[0..n]);
}

pub fn getVarint(b: []const u8, p: *usize) ?u64 {
    if (p.* >= b.len) return null;
    const first = b[p.*];
    const n: usize = @as(usize, 1) << @intCast(first >> 6);
    if (b.len - p.* < n) return null;
    var v: u64 = first & 0x3f;
    for (b[p.* + 1 ..][0 .. n - 1]) |x| v = (v << 8) | x;
    p.* += n;
    return v;
}

// ---------------------------------------------------------------- BCS writer

pub const W = struct {
    gpa: Allocator,
    out: *std.ArrayList(u8),

    pub fn uleb(w: W, v: u64) !void {
        var x = v;
        while (x >= 0x80) {
            try w.out.append(w.gpa, @as(u8, @truncate(x)) | 0x80);
            x >>= 7;
        }
        try w.out.append(w.gpa, @intCast(x));
    }
    pub fn u8_(w: W, v: u8) !void {
        try w.out.append(w.gpa, v);
    }
    pub fn int(w: W, comptime T: type, v: T) !void {
        var b: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &b, v, .little);
        try w.out.appendSlice(w.gpa, &b);
    }
    pub fn fixed(w: W, b: []const u8) !void {
        try w.out.appendSlice(w.gpa, b);
    }
    /// `vector<u8>`: the stored bytes verbatim behind a ULEB128 length.
    pub fn bytes(w: W, b: []const u8) !void {
        try w.uleb(b.len);
        try w.out.appendSlice(w.gpa, b);
    }
    pub fn str(w: W, s: []const u8) !void {
        try w.bytes(s);
    }
    pub fn optBytes(w: W, b: ?[]const u8) !void {
        if (b) |x| {
            try w.u8_(1);
            try w.bytes(x);
        } else try w.u8_(0);
    }
};

// ---------------------------------------------------------------- BCS reader

pub const R = struct {
    b: []const u8,
    p: usize = 0,

    pub const Error = error{Malformed};

    pub fn uleb(r: *R) Error!u64 {
        var v: u64 = 0;
        var shift: u7 = 0;
        while (true) {
            if (r.p >= r.b.len or shift > 63) return error.Malformed;
            const x = r.b[r.p];
            r.p += 1;
            v |= @as(u64, x & 0x7f) << @intCast(shift);
            if (x & 0x80 == 0) return v;
            shift += 7;
        }
    }
    pub fn u8_(r: *R) Error!u8 {
        if (r.p >= r.b.len) return error.Malformed;
        r.p += 1;
        return r.b[r.p - 1];
    }
    pub fn int(r: *R, comptime T: type) Error!T {
        const n = @sizeOf(T);
        if (r.b.len - r.p < n) return error.Malformed;
        defer r.p += n;
        return std.mem.readInt(T, r.b[r.p..][0..n], .little);
    }
    pub fn fixed(r: *R, comptime n: usize) Error!*const [n]u8 {
        if (r.b.len - r.p < n) return error.Malformed;
        defer r.p += n;
        return r.b[r.p..][0..n];
    }
    pub fn bytes(r: *R) Error![]const u8 {
        const n = try r.uleb();
        if (n > r.b.len - r.p) return error.Malformed;
        defer r.p += @intCast(n);
        return r.b[r.p..][0..@intCast(n)];
    }
    pub fn str(r: *R) Error![]const u8 {
        return r.bytes();
    }
    pub fn option(r: *R) Error!bool {
        return switch (try r.u8_()) {
            0 => false,
            1 => true,
            else => error.Malformed,
        };
    }
    pub fn done(r: *const R) Error!void {
        if (r.p != r.b.len) return error.Malformed;
    }
};

// ---------------------------------------------------------------- request / response headers

pub const Request = struct { method: Method, flags: u64, body: []const u8 };

pub fn parseRequest(b: []const u8) ?Request {
    var p: usize = 0;
    const m = getVarint(b, &p) orelse return null;
    const f = getVarint(b, &p) orelse return null;
    return .{ .method = @enumFromInt(m), .flags = f, .body = b[p..] };
}

pub fn encodeRequest(out: *std.ArrayList(u8), gpa: Allocator, method: Method, flags: u64, body: []const u8) !void {
    try putVarint(out, gpa, @intFromEnum(method));
    try putVarint(out, gpa, flags);
    try out.appendSlice(gpa, body);
}

/// OK header (status 0, flags); the caller appends the body (and proof).
pub fn okHeader(out: *std.ArrayList(u8), gpa: Allocator, flags: u64) !void {
    try out.append(gpa, 0);
    try putVarint(out, gpa, flags);
}

/// Whole error response: status byte, flags 0, ErrorBody.
pub fn errorResponse(out: *std.ArrayList(u8), gpa: Allocator, code: Code, message: []const u8, detail: []const u8) !void {
    out.clearRetainingCapacity();
    const c: u32 = @intFromEnum(code);
    try out.append(gpa, if (c > 255) 255 else @intCast(c));
    try putVarint(out, gpa, 0);
    try errorBody(out, gpa, code, message, detail);
}

pub fn errorBody(out: *std.ArrayList(u8), gpa: Allocator, code: Code, message: []const u8, detail: []const u8) !void {
    const w: W = .{ .gpa = gpa, .out = out };
    try w.int(u32, @intFromEnum(code));
    try w.str(message);
    try w.bytes(detail);
}

pub const Response = struct { status: u8, flags: u64, body: []const u8 };

pub fn parseResponse(b: []const u8) ?Response {
    if (b.len < 2) return null;
    var p: usize = 1;
    const f = getVarint(b, &p) orelse return null;
    return .{ .status = b[0], .flags = f, .body = b[p..] };
}

/// Subscription data-stream frame: varint type, varint len, payload.
pub fn frame(out: *std.ArrayList(u8), gpa: Allocator, ty: Frame, payload: []const u8) !void {
    try putVarint(out, gpa, @intFromEnum(ty));
    try putVarint(out, gpa, payload.len);
    try out.appendSlice(gpa, payload);
}

// ---------------------------------------------------------------- sui object helpers

/// `Object.previous_transaction` from raw Object BCS without decoding the type: the object ends
/// with `previous_transaction: Digest` (ULEB 32 + 32 bytes) then `storage_rebate: u64`.
pub fn objectPrevTx(obj: []const u8) ?[32]u8 {
    if (obj.len < 41) return null;
    const at = obj.len - 8 - 32;
    if (obj[at - 1] != 32) return null;
    return obj[at..][0..32].*;
}

test "varint and bcs round trip" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    for ([_]u64{ 0, 63, 64, 16383, 16384, 1 << 30, (1 << 62) - 1 }) |v| {
        out.clearRetainingCapacity();
        try putVarint(&out, gpa, v);
        var p: usize = 0;
        try std.testing.expectEqual(v, getVarint(out.items, &p).?);
        try std.testing.expectEqual(out.items.len, p);
    }
    out.clearRetainingCapacity();
    const w: W = .{ .gpa = gpa, .out = &out };
    try w.uleb(300);
    try w.int(u64, 7);
    try w.bytes("abc");
    try w.optBytes(null);
    var r: R = .{ .b = out.items };
    try std.testing.expectEqual(@as(u64, 300), try r.uleb());
    try std.testing.expectEqual(@as(u64, 7), try r.int(u64));
    try std.testing.expectEqualStrings("abc", try r.bytes());
    try std.testing.expect(!try r.option());
    try r.done();
}
