//! HTTP/3 (RFC 9114) server side, cut to what WebTransport needs (draft-ietf-webtrans-http3 as
//! Chrome ships it, docs/NATIVE-PROTOCOL.md 1.2): control and QPACK streams, SETTINGS, one
//! extended CONNECT (`:protocol webtransport`, RFC 9220) to `/zui/1`, the session's capsules
//! (RFC 9297), and the WT stream prefixes (bidi `0x41 session`, uni `0x54 session`). No request
//! bodies, no push, no QPACK dynamic table.
//!
//! Sans-I/O: the caller feeds each stream's newly received contiguous bytes to `onStream` and
//! passes an `io` with `openUni(self) !u64` and `write(self, stream, bytes, fin) !void` (the QUIC
//! connection). WT stream payload is handed back as `Delivery.wt_data` chunks.
const std = @import("std");
const Allocator = std.mem.Allocator;
const conn = @import("net").conn;
const qpack = @import("qpack.zig");

pub const varintLen = conn.varintLen;
pub const putVarint = conn.putVarint;
pub const getVarint = conn.getVarint;

// Frame types (RFC 9114 7.2, RFC 9297).
pub const frame_data: u64 = 0x00;
pub const frame_headers: u64 = 0x01;
pub const frame_cancel_push: u64 = 0x03;
pub const frame_settings: u64 = 0x04;
pub const frame_push_promise: u64 = 0x05;
pub const frame_goaway: u64 = 0x07;
pub const frame_max_push_id: u64 = 0x0d;
/// First varint of a WebTransport bidirectional stream (WEBTRANSPORT_STREAM signal).
pub const frame_wt_stream: u64 = 0x41;

// Unidirectional stream types.
pub const stream_control: u64 = 0x00;
pub const stream_push: u64 = 0x01;
pub const stream_qpack_encoder: u64 = 0x02;
pub const stream_qpack_decoder: u64 = 0x03;
pub const stream_wt_uni: u64 = 0x54;

// SETTINGS identifiers.
pub const setting_qpack_max_table_capacity: u64 = 0x01;
pub const setting_max_field_section_size: u64 = 0x06;
pub const setting_qpack_blocked_streams: u64 = 0x07;
pub const setting_enable_connect_protocol: u64 = 0x08;
pub const setting_h3_datagram: u64 = 0x33;
pub const setting_enable_webtransport: u64 = 0x2b603742;
pub const setting_webtransport_max_sessions: u64 = 0xc671706a;

// Capsules.
pub const capsule_close_session: u64 = 0x2843;
pub const capsule_drain_session: u64 = 0x78ae;

// HTTP/3 error codes (RFC 9114 8.1), for CONNECTION_CLOSE.
pub const err_no_error: u64 = 0x100;
pub const err_general_protocol: u64 = 0x101;
pub const err_internal: u64 = 0x102;
pub const err_stream_creation: u64 = 0x103;
pub const err_closed_critical_stream: u64 = 0x104;
pub const err_frame_unexpected: u64 = 0x105;
pub const err_frame: u64 = 0x106;
pub const err_id: u64 = 0x108;
pub const err_settings: u64 = 0x109;
pub const err_missing_settings: u64 = 0x10a;
pub const err_message: u64 = 0x10e;
pub const err_qpack_decompression: u64 = 0x200;

/// The WebTransport path this server answers (docs/NATIVE-PROTOCOL.md 1.2).
pub const wt_path = "/zui/1";
/// Largest HTTP frame we buffer on a request or control stream.
pub const max_frame = 64 << 10;

/// The server's SETTINGS, exactly as docs/NATIVE-PROTOCOL.md 1.2 lists them.
pub const server_settings = [_][2]u64{
    .{ setting_qpack_max_table_capacity, 0 },
    .{ setting_qpack_blocked_streams, 0 },
    .{ setting_enable_connect_protocol, 1 },
    .{ setting_h3_datagram, 1 },
    .{ setting_enable_webtransport, 1 },
    .{ setting_webtransport_max_sessions, 1 },
};

pub fn appendVarint(out: *std.ArrayList(u8), gpa: Allocator, v: u64) Allocator.Error!void {
    var tmp: [8]u8 = undefined;
    var p: usize = 0;
    putVarint(&tmp, &p, v);
    try out.appendSlice(gpa, tmp[0..p]);
}

pub fn appendFrame(out: *std.ArrayList(u8), gpa: Allocator, ty: u64, payload: []const u8) Allocator.Error!void {
    try appendVarint(out, gpa, ty);
    try appendVarint(out, gpa, payload.len);
    try out.appendSlice(gpa, payload);
}

/// A SETTINGS frame (type and length included) with `server_settings`.
pub fn encodeSettings(out: *std.ArrayList(u8), gpa: Allocator) Allocator.Error!void {
    var body: [64]u8 = undefined;
    var p: usize = 0;
    for (server_settings) |kv| {
        putVarint(&body, &p, kv[0]);
        putVarint(&body, &p, kv[1]);
    }
    try appendFrame(out, gpa, frame_settings, body[0..p]);
}

pub const Frame = struct { ty: u64, payload: []const u8 };

/// One whole frame from `b` at `pos.*`, or null when it is not all there yet.
pub fn readFrame(b: []const u8, pos: *usize) ?Frame {
    var p = pos.*;
    const ty = getVarint(b, &p) orelse return null;
    const len = getVarint(b, &p) orelse return null;
    if (len > b.len - p) return null;
    pos.* = p + @as(usize, @intCast(len));
    return .{ .ty = ty, .payload = b[p..][0..@intCast(len)] };
}

/// WebTransport application error code `e` as an HTTP/3 error code (draft-ietf-webtrans-http3:
/// 0x52e4a40fa8db + e + floor(e / 0x1e), skipping the reserved code points).
pub fn wtErrorCode(e: u64) u64 {
    return 0x52e4a40fa8db + e + e / 0x1e;
}

/// RFC 9114 reserved (grease) identifiers: 0x1f * N + 0x21.
pub fn isReserved(v: u64) bool {
    return v >= 0x21 and (v - 0x21) % 0x1f == 0;
}

pub const Delivery = union(enum) {
    /// The CONNECT was accepted (response HEADERS written). `token` is the `token=` query
    /// value or the `authorization: Bearer` value; valid until the next call.
    session_open: struct { stream: u64, token: ?[]const u8 },
    /// The session's CONNECT stream finished or carried CLOSE_WEBTRANSPORT_SESSION.
    session_closed: struct { stream: u64, code: u32 = 0 },
    /// Payload of a WT stream after its prefix (`bytes` valid until the next call; may be empty
    /// with `fin`).
    wt_data: struct { stream: u64, session: u64, bidi: bool, bytes: []const u8, fin: bool },
};

pub const Error = error{ OutOfMemory, H3 };

const Kind = enum { unknown, control, drain, ignore, wt, request, session };

const StreamState = struct {
    kind: Kind = .unknown,
    buf: std.ArrayList(u8) = .empty,
    session: u64 = 0,
    // session stream: DATA payload bytes (the capsule stream)
    caps: std.ArrayList(u8) = .empty,
};

pub const ServerSession = struct {
    gpa: Allocator,
    streams: std.AutoHashMapUnmanaged(u64, *StreamState) = .empty,
    /// The open WebTransport session's id (its CONNECT stream), if any.
    session: ?u64 = null,
    session_closed: bool = false,
    got_control: bool = false,
    got_settings: bool = false,
    /// Peer SETTINGS we care about.
    peer_h3_datagram: bool = false,
    peer_webtransport: bool = false,
    /// Set with `error.H3`: the HTTP/3 error code to close the connection with.
    err_code: u64 = 0,
    control_stream: ?u64 = null,
    /// Holds bytes handed out in a Delivery until the next call.
    scratch: std.ArrayList(u8) = .empty,
    token: std.ArrayList(u8) = .empty,

    pub fn init(gpa: Allocator) ServerSession {
        return .{ .gpa = gpa };
    }

    pub fn deinit(s: *ServerSession) void {
        var it = s.streams.valueIterator();
        while (it.next()) |st| s.freeState(st.*);
        s.streams.deinit(s.gpa);
        s.scratch.deinit(s.gpa);
        s.token.deinit(s.gpa);
    }

    fn freeState(s: *ServerSession, st: *StreamState) void {
        st.buf.deinit(s.gpa);
        st.caps.deinit(s.gpa);
        s.gpa.destroy(st);
    }

    fn drop(s: *ServerSession, id: u64) void {
        if (s.streams.fetchRemove(id)) |kv| s.freeState(kv.value);
    }

    fn fail(s: *ServerSession, code: u64) Error {
        s.err_code = code;
        return error.H3;
    }

    /// Opens the control stream (with SETTINGS) and the QPACK encoder and decoder streams.
    pub fn start(s: *ServerSession, io: anytype) !void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(s.gpa);
        try appendVarint(&out, s.gpa, stream_control);
        try encodeSettings(&out, s.gpa);
        const ctl = try io.openUni();
        try io.write(ctl, out.items, false);
        s.control_stream = ctl;
        const enc = try io.openUni();
        try io.write(enc, &.{@intCast(stream_qpack_encoder)}, false);
        const dec = try io.openUni();
        try io.write(dec, &.{@intCast(stream_qpack_decoder)}, false);
    }

    /// Opens a server WT unidirectional stream for `session` (prefix written).
    pub fn openWtUni(s: *ServerSession, io: anytype, session: u64) !u64 {
        _ = s;
        const id = try io.openUni();
        var tmp: [16]u8 = undefined;
        var p: usize = 0;
        putVarint(&tmp, &p, stream_wt_uni);
        putVarint(&tmp, &p, session);
        try io.write(id, tmp[0..p], false);
        return id;
    }

    /// The caller saw a stream reset by the peer (or gave up on it): forget its state.
    pub fn onReset(s: *ServerSession, io: anytype, id: u64) ?Delivery {
        _ = io;
        s.drop(id);
        if (s.session) |sid| if (sid == id and !s.session_closed) {
            s.session_closed = true;
            return .{ .session_closed = .{ .stream = id } };
        };
        return null;
    }

    /// Feeds the newly received contiguous bytes of client stream `id`.
    pub fn onStream(s: *ServerSession, io: anytype, id: u64, data: []const u8, fin: bool) !?Delivery {
        const bidi = id & 2 == 0;
        if (id & 1 == 1) return null; // server-initiated: nothing comes back on our uni streams
        const gop = try s.streams.getOrPut(s.gpa, id);
        if (!gop.found_existing) {
            const st = s.gpa.create(StreamState) catch |e| {
                _ = s.streams.remove(id);
                return e;
            };
            st.* = .{};
            gop.value_ptr.* = st;
        }
        const st = gop.value_ptr.*;
        switch (st.kind) {
            .wt => {
                const d: Delivery = .{ .wt_data = .{ .stream = id, .session = st.session, .bidi = bidi, .bytes = data, .fin = fin } };
                if (fin) s.drop(id);
                return d;
            },
            .drain, .ignore => {
                if (fin) s.drop(id);
                return null;
            },
            else => {},
        }
        if (st.buf.items.len + data.len > max_frame + 64) return s.fail(err_frame);
        try st.buf.appendSlice(s.gpa, data);
        if (st.kind == .unknown) {
            var p: usize = 0;
            const ty = getVarint(st.buf.items, &p) orelse {
                if (fin) s.drop(id);
                return null;
            };
            if (bidi and ty == frame_wt_stream or !bidi and ty == stream_wt_uni) {
                const sid = getVarint(st.buf.items, &p) orelse {
                    if (fin) s.drop(id);
                    return null;
                };
                if (s.session == null or s.session.? != sid or s.session_closed) {
                    st.kind = .ignore;
                    st.buf.clearAndFree(s.gpa);
                    if (fin) s.drop(id);
                    return null;
                }
                st.kind = .wt;
                st.session = sid;
                s.scratch.clearRetainingCapacity();
                try s.scratch.appendSlice(s.gpa, st.buf.items[p..]);
                st.buf.clearAndFree(s.gpa);
                const d: Delivery = .{ .wt_data = .{ .stream = id, .session = sid, .bidi = bidi, .bytes = s.scratch.items, .fin = fin } };
                if (fin) s.drop(id);
                return d;
            }
            if (bidi) {
                st.kind = .request; // HTTP frames from byte 0
            } else {
                switch (ty) {
                    stream_control => {
                        if (s.got_control) return s.fail(err_stream_creation);
                        s.got_control = true;
                        st.kind = .control;
                    },
                    stream_qpack_encoder, stream_qpack_decoder => st.kind = .drain,
                    else => st.kind = .ignore, // push (we never allow it) or unknown types
                }
                std.mem.copyForwards(u8, st.buf.items, st.buf.items[p..]);
                st.buf.shrinkRetainingCapacity(st.buf.items.len - p);
                if (st.kind != .control) {
                    st.buf.clearAndFree(s.gpa);
                    if (fin) s.drop(id);
                    return null;
                }
            }
        }
        return switch (st.kind) {
            .control => s.onControl(id, st, fin),
            .request => s.onRequest(io, id, st, fin),
            .session => s.onSession(id, st, fin),
            else => null,
        };
    }

    fn consume(st: *StreamState, n: usize) void {
        std.mem.copyForwards(u8, st.buf.items, st.buf.items[n..]);
        st.buf.shrinkRetainingCapacity(st.buf.items.len - n);
    }

    fn onControl(s: *ServerSession, id: u64, st: *StreamState, fin: bool) Error!?Delivery {
        if (fin) return s.fail(err_closed_critical_stream);
        _ = id;
        var pos: usize = 0;
        while (readFrame(st.buf.items, &pos)) |f| {
            if (!s.got_settings and f.ty != frame_settings) return s.fail(err_missing_settings);
            switch (f.ty) {
                frame_settings => {
                    if (s.got_settings) return s.fail(err_frame_unexpected);
                    s.got_settings = true;
                    var p: usize = 0;
                    while (p < f.payload.len) {
                        const k = getVarint(f.payload, &p) orelse return s.fail(err_settings);
                        const v = getVarint(f.payload, &p) orelse return s.fail(err_settings);
                        switch (k) {
                            setting_h3_datagram => s.peer_h3_datagram = v == 1,
                            setting_enable_webtransport => s.peer_webtransport = v == 1,
                            0x02, 0x03, 0x04, 0x05 => return s.fail(err_settings), // HTTP/2 settings
                            else => {},
                        }
                    }
                },
                frame_data, frame_headers, frame_push_promise => return s.fail(err_frame_unexpected),
                else => {}, // GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, reserved: nothing to do
            }
        }
        if (pos == 0 and st.buf.items.len > max_frame) return s.fail(err_frame);
        consume(st, pos);
        return null;
    }

    fn respond(s: *ServerSession, io: anytype, id: u64, status: []const u8, fin: bool) !void {
        var fs: std.ArrayList(u8) = .empty;
        defer fs.deinit(s.gpa);
        const ok = std.mem.eql(u8, status, "200");
        const fields_ok = [_]qpack.Field{
            .{ .name = ":status", .value = status },
            .{ .name = "sec-webtransport-http3-draft", .value = "draft02" },
        };
        const fields_err = [_]qpack.Field{.{ .name = ":status", .value = status }};
        try qpack.encodeFieldSection(&fs, s.gpa, if (ok) &fields_ok else &fields_err);
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(s.gpa);
        try appendFrame(&out, s.gpa, frame_headers, fs.items);
        try io.write(id, out.items, fin);
    }

    fn onRequest(s: *ServerSession, io: anytype, id: u64, st: *StreamState, fin: bool) !?Delivery {
        var pos: usize = 0;
        while (readFrame(st.buf.items, &pos)) |f| {
            switch (f.ty) {
                frame_headers => {
                    var arena_state = std.heap.ArenaAllocator.init(s.gpa);
                    defer arena_state.deinit();
                    // Copy first: field strings may point into the block, and `consume` moves the buffer.
                    const block = try arena_state.allocator().dupe(u8, f.payload);
                    const fields = qpack.decodeFieldSection(arena_state.allocator(), block) catch |e| switch (e) {
                        error.OutOfMemory => return e,
                        else => return s.fail(err_qpack_decompression),
                    };
                    consume(st, pos);
                    const method = qpack.get(fields, ":method") orelse "";
                    if (!std.mem.eql(u8, method, "CONNECT")) {
                        try s.respond(io, id, "405", true);
                        s.drop(id);
                        return null;
                    }
                    const proto = qpack.get(fields, ":protocol") orelse "";
                    const path = qpack.get(fields, ":path") orelse "";
                    if (!std.mem.eql(u8, proto, "webtransport") or qpack.get(fields, ":authority") == null) {
                        try s.respond(io, id, "400", true);
                        s.drop(id);
                        return null;
                    }
                    const path_ok = std.mem.startsWith(u8, path, wt_path) and
                        (path.len == wt_path.len or path[wt_path.len] == '?');
                    if (!path_ok) {
                        try s.respond(io, id, "404", true);
                        s.drop(id);
                        return null;
                    }
                    if (s.session != null) {
                        try s.respond(io, id, "429", true);
                        s.drop(id);
                        return null;
                    }
                    try s.respond(io, id, "200", false);
                    s.session = id;
                    s.session_closed = false;
                    st.kind = .session;
                    s.token.clearRetainingCapacity();
                    var has_token = false;
                    if (tokenFromPath(path)) |t| {
                        try s.token.appendSlice(s.gpa, t);
                        has_token = true;
                    } else if (qpack.get(fields, "authorization")) |a| {
                        if (std.ascii.startsWithIgnoreCase(a, "bearer ")) {
                            try s.token.appendSlice(s.gpa, std.mem.trim(u8, a["bearer ".len..], " "));
                            has_token = true;
                        }
                    }
                    if (fin) {
                        // CONNECT with FIN: the session ends at once; tell the caller next time.
                        s.session_closed = true;
                        s.drop(id);
                        return .{ .session_closed = .{ .stream = id } };
                    }
                    return .{ .session_open = .{ .stream = id, .token = if (has_token) s.token.items else null } };
                },
                frame_data => return s.fail(err_frame_unexpected), // body before HEADERS
                frame_settings, frame_goaway, frame_max_push_id, frame_cancel_push => return s.fail(err_frame_unexpected),
                else => {}, // reserved / unknown: skip
            }
        }
        if (pos == 0 and st.buf.items.len > max_frame) return s.fail(err_frame);
        consume(st, pos);
        if (fin) s.drop(id);
        return null;
    }

    fn onSession(s: *ServerSession, id: u64, st: *StreamState, fin: bool) Error!?Delivery {
        var pos: usize = 0;
        while (readFrame(st.buf.items, &pos)) |f| {
            switch (f.ty) {
                frame_data => try st.caps.appendSlice(s.gpa, f.payload),
                frame_headers => {}, // trailers: ignore
                else => {},
            }
        }
        consume(st, pos);
        var cp: usize = 0;
        var code: ?u32 = null;
        while (true) {
            var p = cp;
            const ty = getVarint(st.caps.items, &p) orelse break;
            const len = getVarint(st.caps.items, &p) orelse break;
            if (len > st.caps.items.len - p) break;
            const v = st.caps.items[p..][0..@intCast(len)];
            cp = p + @as(usize, @intCast(len));
            if (ty == capsule_close_session) {
                code = if (v.len >= 4) std.mem.readInt(u32, v[0..4], .big) else 0;
            }
        }
        std.mem.copyForwards(u8, st.caps.items, st.caps.items[cp..]);
        st.caps.shrinkRetainingCapacity(st.caps.items.len - cp);
        if (st.caps.items.len > max_frame) return s.fail(err_frame);
        if (code != null or fin) {
            s.session_closed = true;
            s.drop(id);
            return .{ .session_closed = .{ .stream = id, .code = code orelse 0 } };
        }
        return null;
    }
};

/// The raw value of `token=` in the query of `path`.
fn tokenFromPath(path: []const u8) ?[]const u8 {
    const q = std.mem.indexOfScalar(u8, path, '?') orelse return null;
    var it = std.mem.splitScalar(u8, path[q + 1 ..], '&');
    while (it.next()) |kv| {
        if (std.mem.startsWith(u8, kv, "token=")) return kv["token=".len..];
    }
    return null;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

const FakeIo = struct {
    gpa: Allocator,
    next_uni: u64 = 3,
    out: std.AutoArrayHashMapUnmanaged(u64, std.ArrayList(u8)) = .empty,
    fins: std.AutoHashMapUnmanaged(u64, void) = .empty,

    fn deinit(f: *FakeIo) void {
        for (f.out.values()) |*v| v.deinit(f.gpa);
        f.out.deinit(f.gpa);
        f.fins.deinit(f.gpa);
    }
    pub fn openUni(f: *FakeIo) !u64 {
        const id = f.next_uni;
        f.next_uni += 4;
        try f.out.put(f.gpa, id, .empty);
        return id;
    }
    pub fn write(f: *FakeIo, stream: u64, bytes: []const u8, fin: bool) !void {
        const gop = try f.out.getOrPut(f.gpa, stream);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.appendSlice(f.gpa, bytes);
        if (fin) try f.fins.put(f.gpa, stream, {});
    }
};

fn connectRequest(gpa: Allocator, path: []const u8) !std.ArrayList(u8) {
    const req = [_]qpack.Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost:9443" },
        .{ .name = ":path", .value = path },
        .{ .name = "sec-webtransport-http3-draft02", .value = "1" },
    };
    var fs: std.ArrayList(u8) = .empty;
    defer fs.deinit(gpa);
    try qpack.encodeFieldSection(&fs, gpa, &req);
    var out: std.ArrayList(u8) = .empty;
    try appendFrame(&out, gpa, frame_headers, fs.items);
    return out;
}

fn clientControl(gpa: Allocator) !std.ArrayList(u8) {
    var out: std.ArrayList(u8) = .empty;
    try appendVarint(&out, gpa, stream_control);
    var body: [32]u8 = undefined;
    var p: usize = 0;
    putVarint(&body, &p, setting_h3_datagram);
    putVarint(&body, &p, 1);
    putVarint(&body, &p, 0x21 + 0x1f * 3); // grease setting
    putVarint(&body, &p, 7);
    putVarint(&body, &p, setting_enable_webtransport);
    putVarint(&body, &p, 1);
    try appendFrame(&out, gpa, frame_settings, body[0..p]);
    return out;
}

test "start emits control SETTINGS and QPACK streams" {
    const gpa = testing.allocator;
    var io: FakeIo = .{ .gpa = gpa };
    defer io.deinit();
    var s = ServerSession.init(gpa);
    defer s.deinit();
    try s.start(&io);
    try testing.expectEqual(@as(usize, 3), io.out.count());
    const ctl = io.out.get(3).?.items;
    try testing.expectEqual(@as(u8, 0x00), ctl[0]);
    var pos: usize = 1;
    const f = readFrame(ctl, &pos).?;
    try testing.expectEqual(frame_settings, f.ty);
    var p: usize = 0;
    var n: usize = 0;
    while (p < f.payload.len) : (n += 1) {
        const k = getVarint(f.payload, &p).?;
        const v = getVarint(f.payload, &p).?;
        try testing.expectEqual(server_settings[n][0], k);
        try testing.expectEqual(server_settings[n][1], v);
    }
    try testing.expectEqual(server_settings.len, n);
    try testing.expectEqualSlices(u8, &.{0x02}, io.out.get(7).?.items);
    try testing.expectEqualSlices(u8, &.{0x03}, io.out.get(11).?.items);
}

test "CONNECT accepted, WT bidi and uni prefixes stripped across chunks, close capsule" {
    const gpa = testing.allocator;
    var io: FakeIo = .{ .gpa = gpa };
    defer io.deinit();
    var s = ServerSession.init(gpa);
    defer s.deinit();
    try s.start(&io);

    var ctl = try clientControl(gpa);
    defer ctl.deinit(gpa);
    // control stream in two chunks
    try testing.expect(try s.onStream(&io, 2, ctl.items[0..3], false) == null);
    try testing.expect(try s.onStream(&io, 2, ctl.items[3..], false) == null);
    try testing.expect(s.got_settings and s.peer_h3_datagram and s.peer_webtransport);
    // QPACK encoder stream: drained
    try testing.expect(try s.onStream(&io, 6, &.{ 0x02, 0x3f, 0x00 }, false) == null);

    var req = try connectRequest(gpa, "/zui/1?token=k123&x=1");
    defer req.deinit(gpa);
    try testing.expect(try s.onStream(&io, 0, req.items[0..5], false) == null);
    const d = (try s.onStream(&io, 0, req.items[5..], false)).?;
    try testing.expectEqual(@as(u64, 0), d.session_open.stream);
    try testing.expectEqualStrings("k123", d.session_open.token.?);
    // response HEADERS :status 200 without FIN
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var pos: usize = 0;
    const rf = readFrame(io.out.get(0).?.items, &pos).?;
    try testing.expectEqual(frame_headers, rf.ty);
    const rh = try qpack.decodeFieldSection(arena_state.allocator(), rf.payload);
    try testing.expectEqualStrings("200", qpack.get(rh, ":status").?);
    try testing.expectEqualStrings("draft02", qpack.get(rh, "sec-webtransport-http3-draft").?);
    try testing.expect(!io.fins.contains(0));

    // WT bidi stream 4: prefix 0x41 (2-byte varint 0x4041) + session 0, split mid-prefix.
    try testing.expect(try s.onStream(&io, 4, &.{0x40}, false) == null);
    const d1 = (try s.onStream(&io, 4, &.{ 0x41, 0x00, 'a', 'b' }, false)).?;
    try testing.expectEqualStrings("ab", d1.wt_data.bytes);
    try testing.expect(d1.wt_data.bidi and d1.wt_data.session == 0 and !d1.wt_data.fin);
    const d2 = (try s.onStream(&io, 4, "cd", true)).?;
    try testing.expectEqualStrings("cd", d2.wt_data.bytes);
    try testing.expect(d2.wt_data.fin);

    // WT uni stream 10: 0x40 0x54 (2-byte varint 0x54) + session 0
    try testing.expect(try s.onStream(&io, 10, &.{ 0x40, 0x54 }, false) == null);
    const d3 = (try s.onStream(&io, 10, &.{ 0x00, 'z' }, true)).?;
    try testing.expectEqualStrings("z", d3.wt_data.bytes);
    try testing.expect(!d3.wt_data.bidi and d3.wt_data.fin);

    // WT stream for another session id: ignored
    try testing.expect(try s.onStream(&io, 8, &.{ 0x40, 0x41, 0x04, 'q' }, false) == null);
    try testing.expect(try s.onStream(&io, 8, "more", false) == null);

    // server WT uni stream prefix
    const u = try s.openWtUni(&io, 0);
    try testing.expectEqualSlices(u8, &.{ 0x40, 0x54, 0x00 }, io.out.get(u).?.items);

    // CLOSE_WEBTRANSPORT_SESSION capsule inside a DATA frame (code 7, empty message)
    var cap: std.ArrayList(u8) = .empty;
    defer cap.deinit(gpa);
    try appendVarint(&cap, gpa, capsule_close_session);
    try appendVarint(&cap, gpa, 4);
    try cap.appendSlice(gpa, &.{ 0, 0, 0, 7 });
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(gpa);
    try appendFrame(&data, gpa, frame_data, cap.items);
    try testing.expect(try s.onStream(&io, 0, data.items[0..2], false) == null);
    const dc = (try s.onStream(&io, 0, data.items[2..], false)).?;
    try testing.expectEqual(@as(u32, 7), dc.session_closed.code);
    try testing.expect(s.session_closed);
}

test "wrong path is 404, non-CONNECT is 405, second control stream is an error" {
    const gpa = testing.allocator;
    var io: FakeIo = .{ .gpa = gpa };
    defer io.deinit();
    var s = ServerSession.init(gpa);
    defer s.deinit();
    var req = try connectRequest(gpa, "/other");
    defer req.deinit(gpa);
    try testing.expect(try s.onStream(&io, 0, req.items, false) == null);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var pos: usize = 0;
    const rf = readFrame(io.out.get(0).?.items, &pos).?;
    const rh = try qpack.decodeFieldSection(arena_state.allocator(), rf.payload);
    try testing.expectEqualStrings("404", qpack.get(rh, ":status").?);
    try testing.expect(io.fins.contains(0));
    try testing.expect(s.session == null);

    // /zui/10 is not /zui/1
    var req2 = try connectRequest(gpa, "/zui/10");
    defer req2.deinit(gpa);
    _ = try s.onStream(&io, 4, req2.items, false);
    pos = 0;
    const rh2 = try qpack.decodeFieldSection(arena_state.allocator(), readFrame(io.out.get(4).?.items, &pos).?.payload);
    try testing.expectEqualStrings("404", qpack.get(rh2, ":status").?);

    var fs: std.ArrayList(u8) = .empty;
    defer fs.deinit(gpa);
    try qpack.encodeFieldSection(&fs, gpa, &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":path", .value = "/zui/1" } });
    var get: std.ArrayList(u8) = .empty;
    defer get.deinit(gpa);
    try appendFrame(&get, gpa, frame_headers, fs.items);
    _ = try s.onStream(&io, 8, get.items, true);
    pos = 0;
    const rh3 = try qpack.decodeFieldSection(arena_state.allocator(), readFrame(io.out.get(8).?.items, &pos).?.payload);
    try testing.expectEqualStrings("405", qpack.get(rh3, ":status").?);

    var ctl = try clientControl(gpa);
    defer ctl.deinit(gpa);
    _ = try s.onStream(&io, 2, ctl.items, false);
    try testing.expectError(error.H3, s.onStream(&io, 6, &.{0x00}, false));
    try testing.expectEqual(err_stream_creation, s.err_code);
}

test "session stream FIN closes the session; authorization bearer token" {
    const gpa = testing.allocator;
    var io: FakeIo = .{ .gpa = gpa };
    defer io.deinit();
    var s = ServerSession.init(gpa);
    defer s.deinit();
    const req = [_]qpack.Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "h" },
        .{ .name = ":path", .value = "/zui/1" },
        .{ .name = "authorization", .value = "Bearer tok9" },
    };
    var fs: std.ArrayList(u8) = .empty;
    defer fs.deinit(gpa);
    try qpack.encodeFieldSection(&fs, gpa, &req);
    var hf: std.ArrayList(u8) = .empty;
    defer hf.deinit(gpa);
    try appendFrame(&hf, gpa, frame_headers, fs.items);
    const d = (try s.onStream(&io, 0, hf.items, false)).?;
    try testing.expectEqualStrings("tok9", d.session_open.token.?);
    const dc = (try s.onStream(&io, 0, "", true)).?;
    try testing.expectEqual(@as(u64, 0), dc.session_closed.stream);
}

test "wt error code mapping" {
    try testing.expectEqual(@as(u64, 0x52e4a40fa8db), wtErrorCode(0));
    try testing.expectEqual(@as(u64, 0x52e4a40fa8db + 0x1d), wtErrorCode(0x1d));
    try testing.expectEqual(@as(u64, 0x52e4a40fa8db + 0x1e + 1), wtErrorCode(0x1e));
    try testing.expect(isReserved(0x21) and isReserved(0x40) and !isReserved(0x41));
}
