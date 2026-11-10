//! In-process gRPC client over `h2.Conn`: frames a unary request, drives the connection, and
//! returns the response message and status. Used by the conformance suite and tests so the
//! whole path (HPACK, frames, flow control, gRPC framing, handler) runs without sockets.
const std = @import("std");
const Allocator = std.mem.Allocator;
const h2 = @import("h2/root.zig");
const hpack = @import("h2/hpack.zig");

/// `grpc_message` is percent-decoded; `details` is the base64-decoded `grpc-status-details-bin`.
pub const Reply = struct { status: u8, message: []const u8, grpc_message: []const u8, details: []const u8 = &.{} };

const Trailers = struct {
    arena: Allocator,
    status: u8 = 255,
    grpc_message: []const u8 = "",
    details: []const u8 = &.{},
    fn push(t: *Trailers, name: []const u8, value: []const u8) hpack.Error!void {
        if (std.mem.eql(u8, name, "grpc-status")) {
            t.status = std.fmt.parseInt(u8, value, 10) catch 255;
        } else if (std.mem.eql(u8, name, "grpc-message")) {
            var out: std.ArrayList(u8) = .empty;
            var i: usize = 0;
            while (i < value.len) : (i += 1) {
                if (value[i] == '%' and i + 2 < value.len) {
                    const b = std.fmt.parseInt(u8, value[i + 1 ..][0..2], 16) catch return error.Malformed;
                    try out.append(t.arena, b);
                    i += 2;
                } else try out.append(t.arena, value[i]);
            }
            t.grpc_message = out.items;
        } else if (std.mem.eql(u8, name, "grpc-status-details-bin")) {
            const d = std.base64.standard_no_pad.Decoder;
            const n = d.calcSizeForSlice(value) catch return error.Malformed;
            const buf = try t.arena.alloc(u8, n);
            d.decode(buf, value) catch return error.Malformed;
            t.details = buf;
        }
    }
};

fn frame(out: *std.ArrayList(u8), gpa: Allocator, t: u8, flags: u8, sid: u32, payload: []const u8) !void {
    try out.appendSlice(gpa, &.{ @intCast(payload.len >> 16), @intCast((payload.len >> 8) & 0xff), @intCast(payload.len & 0xff), t, flags });
    var s: [4]u8 = undefined;
    std.mem.writeInt(u32, &s, sid, .big);
    try out.appendSlice(gpa, &s);
    try out.appendSlice(gpa, payload);
}

/// One unary call on a fresh connection. Result slices live in `arena`.
pub fn unary(arena: Allocator, handler: h2.Handler, path: []const u8, body: []const u8) !Reply {
    return unaryTimeout(arena, handler, path, body, null);
}

/// `unary` with a `grpc-timeout` header (milliseconds) when `timeout_ms` is set.
pub fn unaryTimeout(arena: Allocator, handler: h2.Handler, path: []const u8, body: []const u8, timeout_ms: ?u64) !Reply {
    var c = try h2.Conn.init(arena, .{}, handler);
    defer c.deinit();
    var in: std.ArrayList(u8) = .empty;
    try in.appendSlice(arena, h2.conn.preface);
    try frame(&in, arena, 4, 0, 0, &.{});
    var hb: std.ArrayList(u8) = .empty;
    try hb.appendSlice(arena, &.{ 0x83, 0x86 });
    try hpack.encodeLiteral(&hb, arena, ":path", path);
    try hpack.encodeLiteral(&hb, arena, ":authority", "loopback");
    try hpack.encodeLiteral(&hb, arena, "content-type", "application/grpc");
    if (timeout_ms) |t| try hpack.encodeLiteral(&hb, arena, "grpc-timeout", try std.fmt.allocPrint(arena, "{d}m", .{t}));
    try frame(&in, arena, 1, 4, 1, hb.items);
    var msg: std.ArrayList(u8) = .empty;
    try msg.append(arena, 0);
    var len: [4]u8 = undefined;
    std.mem.writeInt(u32, &len, @intCast(body.len), .big);
    try msg.appendSlice(arena, &len);
    try msg.appendSlice(arena, body);
    var off: usize = 0;
    while (off < msg.items.len) {
        const n = @min(16384, msg.items.len - off);
        const last = off + n == msg.items.len;
        try frame(&in, arena, 0, if (last) 1 else 0, 1, msg.items[off..][0..n]);
        off += n;
    }
    try c.feed(in.items);

    var data: std.ArrayList(u8) = .empty;
    var dec = hpack.Decoder.init(arena);
    defer dec.deinit();
    var tr: Trailers = .{ .arena = arena };
    var rounds: usize = 0;
    while (rounds < 100000) : (rounds += 1) {
        const out = c.pending();
        if (out.len == 0) break;
        var pos: usize = 0;
        var credit: usize = 0;
        while (pos + 9 <= out.len) {
            const flen = (@as(usize, out[pos]) << 16) | (@as(usize, out[pos + 1]) << 8) | out[pos + 2];
            const t = out[pos + 3];
            const flags = out[pos + 4];
            const payload = out[pos + 9 ..][0..flen];
            if (t == 0) {
                try data.appendSlice(arena, payload);
                credit += flen;
            } else if (t == 1) {
                // response headers, then trailers (or trailers-only); END_HEADERS is always set
                var sink: Trailers = .{ .arena = arena };
                try dec.decode(arena, payload, &sink, Trailers.push);
                if (flags & 1 != 0) tr = sink;
            }
            pos += 9 + flen;
        }
        c.consumed(out.len);
        if (credit > 0) {
            var wu: std.ArrayList(u8) = .empty;
            var inc: [4]u8 = undefined;
            std.mem.writeInt(u32, &inc, @intCast(credit), .big);
            try frame(&wu, arena, 8, 0, 0, &inc);
            try frame(&wu, arena, 8, 0, 1, &inc);
            try c.feed(wu.items);
        }
    }
    if (data.items.len == 0) return .{ .status = tr.status, .message = &.{}, .grpc_message = tr.grpc_message, .details = tr.details };
    if (data.items.len < 5 or data.items[0] != 0) return error.BadReply;
    const n = std.mem.readInt(u32, data.items[1..5], .big);
    if (data.items.len != 5 + n) return error.BadReply;
    return .{ .status = tr.status, .message = data.items[5..], .grpc_message = tr.grpc_message, .details = tr.details };
}

// ---------------------------------------------------------------- socket client (streams)

/// One response message as sent: the compressed flag of its 5-byte prefix and its payload.
pub const Message = struct { compressed: bool, payload: []const u8 };

/// A gRPC call's reply as it came off the wire: `:status`, every header and trailer (names
/// lowercase, values raw: `grpc-message` still percent-encoded), and each message.
pub const StreamReply = struct {
    status: []const u8 = "",
    headers: std.ArrayList([2][]const u8) = .empty,
    trailers: std.ArrayList([2][]const u8) = .empty,
    /// The first HEADERS block ended the stream (a trailers-only response).
    trailers_only: bool = false,
    messages: std.ArrayList(Message) = .empty,
    /// END_STREAM arrived (false: the client stopped reading first).
    ended: bool = false,
    /// RST_STREAM error code, when the server reset the stream.
    reset: ?u32 = null,
    /// Every DATA payload as received (gRPC-web text replies are read from here).
    data: std.ArrayList(u8) = .empty,
};

pub const StreamOptions = struct {
    /// Stop reading (and close) once this many messages arrived.
    max_messages: ?usize = null,
    /// Give up after this long with nothing from the server and nothing left to drive.
    idle_ms: u32 = 3000,
    /// Called between reads (every 50 ms of quiet): the caller drives the server, e.g. publishes
    /// the next checkpoint. Returns false once it has nothing more to do.
    tick: ?Tick = null,
    /// Send the framed request messages base64 encoded (a gRPC-web text request).
    text_body: bool = false,
    pub const Tick = struct { ctx: *anyopaque, f: *const fn (*anyopaque) bool };
};

const HeaderSink = struct {
    a: Allocator,
    status: *[]const u8,
    list: *std.ArrayList([2][]const u8),
    fn push(s: *HeaderSink, name: []const u8, value: []const u8) hpack.Error!void {
        if (std.mem.eql(u8, name, ":status")) {
            s.status.* = s.a.dupe(u8, value) catch return error.OutOfMemory;
            return;
        }
        s.list.append(s.a, .{ s.a.dupe(u8, name) catch return error.OutOfMemory, s.a.dupe(u8, value) catch return error.OutOfMemory }) catch return error.OutOfMemory;
    }
};

/// One call on a fresh h2c connection to 127.0.0.1:`port` (the deepwave runtime, h2/server.zig):
/// `headers` after the pseudo-headers (a `:authority` among them replaces the default), then
/// each request message framed. The client opens a 2^31-1 window up front, so the server is
/// never held back by flow control.
pub fn call(arena: Allocator, io: std.Io, port: u16, path: []const u8, headers: []const [2][]const u8, messages: []const []const u8, opts: StreamOptions) !StreamReply {
    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const st = try addr.connect(io, .{ .mode = .stream });
    defer st.close(io);
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, h2.conn.preface);
    // SETTINGS_INITIAL_WINDOW_SIZE = 2^31-1, then the connection window to the same
    try frame(&out, arena, 4, 0, 0, &.{ 0, 4, 0x7f, 0xff, 0xff, 0xff });
    var inc: [4]u8 = undefined;
    std.mem.writeInt(u32, &inc, 0x7fffffff - 65535, .big);
    try frame(&out, arena, 8, 0, 0, &inc);
    var authority: []const u8 = "127.0.0.1";
    for (headers) |kv| if (std.mem.eql(u8, kv[0], ":authority")) {
        authority = kv[1];
    };
    var hb: std.ArrayList(u8) = .empty;
    try hpack.encodeLiteral(&hb, arena, ":method", "POST");
    try hpack.encodeLiteral(&hb, arena, ":scheme", "http");
    try hpack.encodeLiteral(&hb, arena, ":path", path);
    try hpack.encodeLiteral(&hb, arena, ":authority", authority);
    for (headers) |kv| if (kv[0].len == 0 or kv[0][0] != ':') try hpack.encodeLiteral(&hb, arena, kv[0], kv[1]);
    var body: std.ArrayList(u8) = .empty;
    for (messages) |m| {
        var len: [4]u8 = undefined;
        std.mem.writeInt(u32, &len, @intCast(m.len), .big);
        try body.append(arena, 0);
        try body.appendSlice(arena, &len);
        try body.appendSlice(arena, m);
    }
    if (opts.text_body and body.items.len > 0) {
        const e = std.base64.standard.Encoder;
        const t = try arena.alloc(u8, e.calcSize(body.items.len));
        _ = e.encode(t, body.items);
        body = .fromOwnedSlice(t);
    }
    try frame(&out, arena, 1, if (body.items.len == 0) 5 else 4, 1, hb.items);
    var off: usize = 0;
    while (off < body.items.len) {
        const n = @min(16384, body.items.len - off);
        try frame(&out, arena, 0, if (off + n == body.items.len) 1 else 0, 1, body.items[off..][0..n]);
        off += n;
    }
    try writeAllTo(io, st, out.items);

    var dec = hpack.Decoder.init(arena);
    defer dec.deinit();
    var rep: StreamReply = .{};
    var in: std.ArrayList(u8) = .empty;
    var pos: usize = 0;
    var data: std.ArrayList(u8) = .empty;
    var dpos: usize = 0;
    var blocks: u32 = 0;
    var idle: u32 = 0;
    var buf: [16384]u8 = undefined;
    loop: while (true) {
        // frames
        while (in.items.len - pos >= 9) {
            const h = in.items[pos..][0..9];
            const flen = (@as(usize, h[0]) << 16) | (@as(usize, h[1]) << 8) | h[2];
            if (in.items.len - pos < 9 + flen) break;
            const payload = in.items[pos + 9 ..][0..flen];
            const t = h[3];
            const flags = h[4];
            const sid = std.mem.readInt(u32, h[5..9], .big) & 0x7fffffff;
            pos += 9 + flen;
            switch (t) {
                4 => if (flags & 1 == 0) {
                    var ack: std.ArrayList(u8) = .empty;
                    try frame(&ack, arena, 4, 1, 0, &.{});
                    try writeAllTo(io, st, ack.items);
                },
                6 => if (flags & 1 == 0) {
                    var pong: std.ArrayList(u8) = .empty;
                    try frame(&pong, arena, 6, 1, 0, payload);
                    try writeAllTo(io, st, pong.items);
                },
                7 => break :loop,
                else => {},
            }
            if (sid != 1) continue;
            switch (t) {
                1 => {
                    var hs: HeaderSink = .{ .a = arena, .status = &rep.status, .list = if (blocks == 0) &rep.headers else &rep.trailers };
                    try dec.decode(arena, payload, &hs, HeaderSink.push);
                    if (blocks == 0 and flags & 1 != 0) rep.trailers_only = true;
                    blocks += 1;
                },
                0 => {
                    var p = payload;
                    if (flags & 8 != 0) { // PADDED
                        const pad = p[0];
                        p = p[1 .. p.len - pad];
                    }
                    try data.appendSlice(arena, p);
                    try rep.data.appendSlice(arena, p);
                    while (data.items.len - dpos >= 5) {
                        const n = std.mem.readInt(u32, data.items[dpos + 1 ..][0..4], .big);
                        if (data.items.len - dpos < 5 + n) break;
                        try rep.messages.append(arena, .{ .compressed = data.items[dpos] != 0, .payload = try arena.dupe(u8, data.items[dpos + 5 ..][0..n]) });
                        dpos += 5 + n;
                    }
                    if (opts.max_messages) |mx| if (rep.messages.items.len >= mx) break :loop;
                },
                3 => {
                    rep.reset = if (payload.len >= 4) std.mem.readInt(u32, payload[0..4], .big) else 0;
                    break :loop;
                },
                else => {},
            }
            if ((t == 0 or t == 1) and flags & 1 != 0) {
                rep.ended = true;
                break :loop;
            }
        }
        // more bytes, or a tick of the caller's driver
        var p = [_]std.c.pollfd{.{ .fd = st.socket.handle, .events = std.c.POLL.IN, .revents = 0 }};
        if (std.c.poll(&p, 1, 50) > 0) {
            var iov = [_][]u8{&buf};
            const n = st.read(io, &iov) catch 0;
            if (n == 0) break;
            try in.appendSlice(arena, buf[0..n]);
            idle = 0;
            continue;
        }
        const busy = if (opts.tick) |tk| tk.f(tk.ctx) else false;
        if (busy) {
            idle = 0;
        } else {
            idle += 50;
            if (idle >= opts.idle_ms) break;
        }
    }
    return rep;
}

fn writeAllTo(io: std.Io, st: std.Io.net.Stream, bytes: []const u8) !void {
    var wbuf: [4096]u8 = undefined;
    var w = st.writer(io, &wbuf);
    try w.interface.writeAll(bytes);
    try w.interface.flush();
}
