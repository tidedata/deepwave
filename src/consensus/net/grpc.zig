//! gRPC for consensus: HTTP/2 client and server over `tls.Session`, unary, server-streaming and
//! bidi-streaming calls, zstd message compression both ways, message size limits and keepalive
//! PINGs from `Parameters.tonic` (tonic `http2_keep_alive_interval`). Owner lane: val-consensus-net.
//!
//! One blocking thread reads each connection (frames, HPACK, flow control); application threads
//! call `Stream.recv` / `send` (blocking with deadlines); a server runs one handler thread per
//! stream. All state sits behind one monitor per connection; writes are serialized by a write
//! lock and never happen under the state lock for longer than a flow-control update.
//!
//! Wire behaviour follows tonic 0.14 / hyper: request headers `:method POST`, `content-type:
//! application/grpc`, `te: trailers`, `grpc-timeout`, `grpc-encoding` / `grpc-accept-encoding:
//! zstd`; responses `:status 200`, trailers `grpc-status` / `grpc-message`; trailers-only errors;
//! the 5-byte message prefix with the compressed flag. Windows are credited as the application
//! consumes messages (complete but unread messages hold their credit back, as hyper does), the
//! bytes buffered per stream and per connection are capped, and a server stream accepts exactly
//! one request message, so a peer cannot grow memory.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const serve = @import("serve");
const hpack = serve.h2.hpack;
const codec = serve.h2.codec;
const proto = @import("proto.zig");
const tls = @import("tls.zig");
const mon = @import("mon.zig");
const Monitor = mon.Monitor;
const sock = serve.h2.sock;
const log = std.log.scoped(.consensus_grpc);

pub const Status = enum(u8) { ok = 0, cancelled = 1, unknown = 2, invalid_argument = 3, deadline_exceeded = 4, not_found = 5, resource_exhausted = 8, failed_precondition = 9, unimplemented = 12, internal = 13, unavailable = 14, unauthenticated = 16 };

pub const Error = error{ Unavailable, DeadlineExceeded, Cancelled, Malformed, ResourceExhausted, Status, OutOfMemory };

pub const Config = struct {
    /// Largest gRPC message either way (Parameters.tonic.message_size_limit).
    message_limit: usize = 64 << 20,
    /// tonic_network.rs HTTP2_INITIAL_STREAM_WINDOW_SIZE / HTTP2_INITIAL_CONNECTION_WINDOW_SIZE.
    stream_window: u32 = 32 << 20,
    conn_window: u32 = 64 << 20,
    /// PING interval and ACK timeout (Parameters.tonic.keepalive_interval).
    keepalive_ns: u64 = 10 * std.time.ns_per_s,
    max_concurrent_streams: u32 = 1024,
    /// Bytes of complete messages one stream may hold unread before it is reset.
    max_queued_bytes: usize = 64 << 20,
    /// Unread complete messages plus partial messages over all streams of one connection.
    max_conn_buffered: usize = 128 << 20,
    /// Live connections one authenticated peer may hold open on a server.
    max_conns_per_peer: u32 = 8,
    /// TCP connections a server accepts that have not finished their TLS handshake yet.
    max_pending_handshakes: u32 = 64,
    connect_timeout_ns: u64 = 5 * std.time.ns_per_s,
};

const frame_data = 0;
const frame_headers = 1;
const frame_rst = 3;
const frame_settings = 4;
const frame_ping = 6;
const frame_goaway = 7;
const frame_window = 8;
const frame_continuation = 9;
const flag_end_stream = 1;
const flag_ack = 1;
const flag_end_headers = 4;
const flag_padded = 8;
const flag_priority = 0x20;
const max_frame_in: u32 = 1 << 16;
const max_header_block: usize = 64 << 10;
const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const thread_stack: usize = 8 << 20;
const compress_min = 1024;

const Msg = struct { compressed: bool, data: []u8 };

pub const Role = enum { client, server };

/// One h2 stream: a gRPC call. Both roles use it; the server's handler receives one.
pub const Stream = struct {
    conn: *Conn,
    id: u32,
    refs: std.atomic.Value(u32) = .init(2), // the connection's map and the application
    // Guarded by conn.mon.
    rxbuf: std.ArrayList(u8) = .empty,
    queue: std.ArrayList(Msg) = .empty,
    q_head: usize = 0,
    queued_bytes: usize = 0,
    saw_headers: bool = false,
    rx_end: bool = false,
    reset_code: ?u32 = null,
    status: ?u8 = null,
    status_message: []u8 = &.{},
    peer_zstd: bool = false, // the peer's messages may use zstd / accepts zstd
    send_window: i64,
    tx_end: bool = false,
    tx_headers: bool = false,
    removed: bool = false,
    /// Flow control: wire bytes received, credited back, and held by complete unread messages.
    rx_total: u64 = 0,
    credited: u64 = 0,
    unread_wire: usize = 0,
    msgs_in: u32 = 0,
    path: []u8 = &.{},
    /// Monotonic ns deadline for this call (client: our timeout; server: grpc-timeout), 0 = none.
    deadline_ns: u64 = 0,

    pub fn peer(st: *const Stream) u32 {
        return st.conn.sess.peer_index;
    }

    pub fn method(st: *const Stream) ?proto.Method {
        return proto.methodFromPath(st.path);
    }

    /// The call's gRPC status once it ended (client side), `ok` otherwise.
    pub fn grpcStatus(st: *Stream) Status {
        st.conn.mon.lock();
        defer st.conn.mon.unlock();
        return statusOf(st.status orelse 0);
    }

    fn statusOf(code: u8) Status {
        return std.enums.fromInt(Status, code) orelse .unknown;
    }

    /// Next message, null after a clean end of the peer's stream. Blocks up to `timeout_ns`
    /// (0: until the call's own deadline, if any, else forever).
    pub fn recv(st: *Stream, arena: Allocator, timeout_ns: u64) Error!?[]u8 {
        const c = st.conn;
        const io = c.io;
        c.mon.lock();
        const until: u64 = blk: {
            var d: u64 = if (timeout_ns != 0) mon.monoNs(io) +| timeout_ns else 0;
            if (st.deadline_ns != 0 and (d == 0 or st.deadline_ns < d)) d = st.deadline_ns;
            break :blk d;
        };
        while (true) {
            if (st.q_head < st.queue.items.len) {
                const m = st.queue.items[st.q_head];
                st.q_head += 1;
                st.queued_bytes -= m.data.len;
                if (st.q_head == st.queue.items.len) {
                    st.queue.clearRetainingCapacity();
                    st.q_head = 0;
                }
                // Consumption returns flow-control credit to the peer.
                var sc: u32 = 0;
                if (!st.removed) {
                    const wire = 5 + m.data.len;
                    st.unread_wire -= wire;
                    c.conn_unread -= wire;
                    sc = c.streamCreditLocked(st);
                }
                const cc = c.connCreditLocked();
                const sid = st.id;
                const zstd_ok = true;
                c.mon.unlock();
                c.sendCredit(sid, sc, cc);
                defer c.gpa.free(m.data);
                if (!m.compressed) return arena.dupe(u8, m.data) catch error.OutOfMemory;
                if (!zstd_ok) return error.Malformed;
                const out = try decompress(arena, m.data, c.cfg.message_limit);
                return out;
            }
            if (st.reset_code) |code| {
                c.mon.unlock();
                return if (code == 8) error.Cancelled else error.Unavailable;
            }
            if (st.rx_end) {
                const code = st.status orelse 0;
                c.mon.unlock();
                if (code != 0) return error.Status;
                return null;
            }
            if (c.dead) {
                c.mon.unlock();
                return error.Unavailable;
            }
            if (until != 0) {
                const now = mon.monoNs(io);
                if (now >= until) {
                    c.mon.unlock();
                    return error.DeadlineExceeded;
                }
                c.mon.waitNs(until - now);
            } else c.mon.wait();
        }
    }

    /// Sends one message (client request or server response message).
    pub fn send(st: *Stream, msg: []const u8) Error!void {
        if (msg.len > st.conn.cfg.message_limit) return error.ResourceExhausted;
        try st.ensureHeaders();
        const c = st.conn;
        var framed: std.ArrayList(u8) = .empty;
        defer framed.deinit(c.gpa);
        var payload: []const u8 = msg;
        var z: ?[]u8 = null;
        defer if (z) |zz| c.gpa.free(zz);
        c.mon.lock();
        const may_compress = st.peer_zstd;
        c.mon.unlock();
        if (may_compress and msg.len >= compress_min) {
            if (codec.compress(c.gpa, .zstd, msg)) |zb| {
                if (zb.len < msg.len) {
                    z = zb;
                    payload = zb;
                } else c.gpa.free(zb);
            } else |_| {}
        }
        framed.ensureTotalCapacity(c.gpa, 5 + payload.len) catch return error.OutOfMemory;
        framed.appendAssumeCapacity(if (z != null) 1 else 0);
        var len4: [4]u8 = undefined;
        std.mem.writeInt(u32, &len4, @intCast(payload.len), .big);
        framed.appendSliceAssumeCapacity(&len4);
        framed.appendSliceAssumeCapacity(payload);
        try st.writeData(framed.items, false);
    }

    /// Client: no more request messages (END_STREAM).
    pub fn closeSend(st: *Stream) Error!void {
        try st.ensureHeaders();
        try st.writeData(&.{}, true);
    }

    /// Server: ends the call with `status` (trailers, or a trailers-only response when nothing
    /// was sent yet). A stream that already ended is left alone.
    pub fn finish(st: *Stream, status: Status, message: []const u8) void {
        const c = st.conn;
        c.mon.lock();
        const done = st.tx_end or st.reset_code != null or c.dead;
        const hdr_sent = st.tx_headers;
        if (!done) st.tx_end = true;
        st.tx_headers = true;
        c.mon.unlock();
        if (done) return;
        var hb: std.ArrayList(u8) = .empty;
        defer hb.deinit(c.gpa);
        const ok = blk: {
            if (!hdr_sent) {
                hpack.encodeLiteral(&hb, c.gpa, ":status", "200") catch break :blk false;
                hpack.encodeLiteral(&hb, c.gpa, "content-type", "application/grpc") catch break :blk false;
            }
            var num: [4]u8 = undefined;
            const code = std.fmt.bufPrint(&num, "{d}", .{@intFromEnum(status)}) catch unreachable;
            hpack.encodeLiteral(&hb, c.gpa, "grpc-status", code) catch break :blk false;
            if (message.len > 0) {
                var enc: std.ArrayList(u8) = .empty;
                defer enc.deinit(c.gpa);
                codec.percentEncode(&enc, c.gpa, message) catch break :blk false;
                hpack.encodeLiteral(&hb, c.gpa, "grpc-message", enc.items) catch break :blk false;
            }
            break :blk true;
        };
        if (ok) c.writeHeaders(st.id, hb.items, true) catch c.die("write failed");
        // The client may still be sending: tell it we are done with the stream.
        c.mon.lock();
        const rx_done = st.rx_end;
        c.mon.unlock();
        if (!rx_done) c.writeRst(st.id, 0) catch {};
        c.mon.lock();
        c.maybeRemoveLocked(st);
        c.mon.unlock();
        c.flushCredit();
    }

    /// Client: abandons the call (RST_STREAM CANCEL).
    pub fn cancel(st: *Stream) void {
        const c = st.conn;
        c.mon.lock();
        const was = st.reset_code != null or st.removed or c.dead;
        if (st.reset_code == null) st.reset_code = 8;
        c.mon.broadcast();
        c.maybeRemoveLocked(st);
        c.mon.unlock();
        if (!was) c.writeRst(st.id, 8) catch {};
        c.flushCredit();
    }

    /// True once the call can no longer carry messages (reset, connection lost, we finished it).
    pub fn closed(st: *Stream) bool {
        const c = st.conn;
        c.mon.lock();
        defer c.mon.unlock();
        return c.dead or st.reset_code != null or st.tx_end;
    }

    pub fn release(st: *Stream) void {
        if (st.refs.fetchSub(1, .acq_rel) == 1) st.destroy();
    }

    fn destroy(st: *Stream) void {
        const c = st.conn;
        for (st.queue.items[st.q_head..]) |m| c.gpa.free(m.data);
        st.queue.deinit(c.gpa);
        st.rxbuf.deinit(c.gpa);
        if (st.path.len > 0) c.gpa.free(st.path);
        if (st.status_message.len > 0) c.gpa.free(st.status_message);
        c.gpa.destroy(st);
        c.unref();
    }

    /// Server: response HEADERS before the first message.
    fn ensureHeaders(st: *Stream) Error!void {
        const c = st.conn;
        c.mon.lock();
        if (st.tx_headers or c.role == .client) {
            c.mon.unlock();
            return;
        }
        st.tx_headers = true;
        const zstd = st.peer_zstd;
        c.mon.unlock();
        var hb: std.ArrayList(u8) = .empty;
        defer hb.deinit(c.gpa);
        hpack.encodeLiteral(&hb, c.gpa, ":status", "200") catch return error.OutOfMemory;
        hpack.encodeLiteral(&hb, c.gpa, "content-type", "application/grpc") catch return error.OutOfMemory;
        if (zstd) hpack.encodeLiteral(&hb, c.gpa, "grpc-encoding", "zstd") catch return error.OutOfMemory;
        c.writeHeaders(st.id, hb.items, false) catch {
            c.die("write failed");
            return error.Unavailable;
        };
    }

    /// DATA frames honoring both flow-control windows.
    fn writeData(st: *Stream, bytes: []const u8, end: bool) Error!void {
        const c = st.conn;
        var off: usize = 0;
        while (true) {
            c.mon.lock();
            var n: usize = 0;
            while (true) {
                if (c.dead or st.reset_code != null or st.tx_end) {
                    const was_reset = st.reset_code != null;
                    c.mon.unlock();
                    return if (was_reset) error.Cancelled else error.Unavailable;
                }
                if (off == bytes.len) break; // only an empty END_STREAM frame left
                const win = @min(st.send_window, c.send_window);
                if (win > 0) {
                    n = @intCast(@min(@as(i64, @intCast(bytes.len - off)), @min(win, c.peer_max_frame)));
                    st.send_window -= @intCast(n);
                    c.send_window -= @intCast(n);
                    break;
                }
                if (st.deadline_ns != 0) {
                    const now = mon.monoNs(c.io);
                    if (now >= st.deadline_ns) {
                        c.mon.unlock();
                        return error.DeadlineExceeded;
                    }
                    c.mon.waitNs(@min(st.deadline_ns - now, 500 * std.time.ns_per_ms));
                } else c.mon.waitNs(500 * std.time.ns_per_ms);
            }
            const last = off + n == bytes.len;
            if (last and end) st.tx_end = true;
            c.mon.unlock();
            c.writeFrame(frame_data, if (last and end) flag_end_stream else 0, st.id, bytes[off..][0..n]) catch {
                c.die("write failed");
                return error.Unavailable;
            };
            off += n;
            if (last) {
                if (end) {
                    c.mon.lock();
                    c.maybeRemoveLocked(st);
                    c.mon.unlock();
                }
                return;
            }
        }
    }
};

fn decompress(arena: Allocator, z: []const u8, limit: usize) Error![]u8 {
    var in: Io.Reader = .fixed(z);
    const zstd = std.compress.zstd;
    const window = arena.alloc(u8, zstd.default_window_len + zstd.block_size_max) catch return error.OutOfMemory;
    defer arena.free(window);
    var d: zstd.Decompress = .init(&in, window, .{});
    return d.reader.allocRemaining(arena, .limited(limit)) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.ResourceExhausted,
        else => error.Malformed,
    };
}

pub const Handler = struct {
    ctx: *anyopaque,
    /// Runs on its own thread for each incoming call; must `finish` the stream (the connection
    /// finishes it with INTERNAL if the handler returns without doing so).
    serve: *const fn (ctx: *anyopaque, st: *Stream) void,
};

pub const Conn = struct {
    gpa: Allocator,
    io: Io,
    role: Role,
    cfg: Config,
    sess: *tls.Session,
    fd: std.c.fd_t,
    handler: ?Handler,
    mon: Monitor,
    wmu: Io.Mutex = .init,
    wbuf: std.ArrayList(u8) = .empty,
    refs: std.atomic.Value(u32) = .init(1), // the reader thread
    // Guarded by mon.
    streams: std.AutoHashMapUnmanaged(u32, *Stream) = .empty,
    send_window: i64 = 65_535,
    peer_initial_window: i64 = 65_535,
    peer_max_frame: u32 = 16_384,
    next_stream: u32 = 1,
    last_peer_stream: u32 = 0,
    dead: bool = false,
    dead_reason: []const u8 = "",
    handlers: u32 = 0,
    /// Flow control over the whole connection (see Stream.rx_total).
    conn_rx_total: u64 = 0,
    conn_credited: u64 = 0,
    conn_unread: usize = 0,
    /// Bytes of partial (incomplete) messages held in the streams' receive buffers.
    partial_total: usize = 0,
    ping_sent_ns: u64 = 0,
    last_rx_ns: u64 = 0,
    /// Owner of the fd's lifetime: closed when the last reference goes.
    owns_fd: bool = true,
    /// Live-connection counter of the owner (Channel or Server), decremented when this connection is freed.
    gate: ?*std.atomic.Value(u32) = null,
    /// Server registry hook: called when the connection is freed.
    on_free: ?*const fn (owner: *anyopaque, c: *Conn) void = null,
    on_free_ctx: ?*anyopaque = null,

    pub fn ref(c: *Conn) void {
        _ = c.refs.fetchAdd(1, .acq_rel);
    }

    /// Takes a reference unless the connection is already being freed.
    fn tryRef(c: *Conn) bool {
        var r = c.refs.load(.acquire);
        while (r != 0) {
            r = c.refs.cmpxchgWeak(r, r + 1, .acq_rel, .acquire) orelse return true;
        }
        return false;
    }

    pub fn unref(c: *Conn) void {
        if (c.refs.fetchSub(1, .acq_rel) != 1) return;
        // Leave the owner's registry first: nothing can take a new reference after this.
        if (c.on_free) |f| f(c.on_free_ctx.?, c);
        c.sess.deinit();
        if (c.owns_fd) _ = std.c.close(c.fd);
        c.wbuf.deinit(c.gpa);
        c.streams.deinit(c.gpa);
        const gate = c.gate;
        c.gpa.destroy(c);
        if (gate) |g| _ = g.fetchSub(1, .acq_rel);
    }

    pub fn isDead(c: *Conn) bool {
        c.mon.lock();
        defer c.mon.unlock();
        return c.dead;
    }

    /// Ends the connection: every stream fails with UNAVAILABLE, the socket is shut down so the
    /// reader thread exits.
    pub fn die(c: *Conn, reason: []const u8) void {
        c.mon.lock();
        if (c.dead) {
            c.mon.unlock();
            return;
        }
        c.dead = true;
        c.dead_reason = reason;
        var it = c.streams.iterator();
        while (it.next()) |kv| {
            const st = kv.value_ptr.*;
            if (st.reset_code == null) st.reset_code = 14;
            st.removed = true;
            if (st.status == null) st.status = 14;
        }
        // Drop the map's references after the walk.
        var ids: std.ArrayList(*Stream) = .empty;
        defer ids.deinit(c.gpa);
        var it2 = c.streams.valueIterator();
        while (it2.next()) |p| ids.append(c.gpa, p.*) catch {};
        c.streams.clearRetainingCapacity();
        c.mon.broadcast();
        c.mon.unlock();
        c.sess.shutdown();
        for (ids.items) |st| st.release();
    }

    // ---------------------------------------------------------------- flow-control credit

    /// Stream window credit owed to the peer once it reaches a quarter window (under `mon`).
    /// Everything received counts as consumed except complete messages the application has not
    /// read yet.
    fn streamCreditLocked(c: *Conn, st: *Stream) u32 {
        if (st.removed or st.rx_end) return 0;
        const owed = st.rx_total - st.credited - st.unread_wire;
        if (owed < c.cfg.stream_window / 4) return 0;
        const n: u32 = @intCast(@min(owed, 0x7fff_ffff));
        st.credited += n;
        return n;
    }

    fn connCreditLocked(c: *Conn) u32 {
        const owed = c.conn_rx_total - c.conn_credited - c.conn_unread;
        if (owed < c.cfg.conn_window / 4) return 0;
        const n: u32 = @intCast(@min(owed, 0x7fff_ffff));
        c.conn_credited += n;
        return n;
    }

    fn sendCredit(c: *Conn, id: u32, stream: u32, conn: u32) void {
        if (conn > 0) c.writeWindow(0, conn) catch c.die("write failed");
        if (stream > 0) c.writeWindow(id, stream) catch c.die("write failed");
    }

    /// Returns connection credit freed by streams that ended with unread messages.
    fn flushCredit(c: *Conn) void {
        c.mon.lock();
        const cc = c.connCreditLocked();
        c.mon.unlock();
        c.sendCredit(0, 0, cc);
    }

    // ---------------------------------------------------------------- writing

    fn writeFrame(c: *Conn, kind: u8, flags: u8, id: u32, payload: []const u8) !void {
        c.wmu.lockUncancelable(c.io);
        defer c.wmu.unlock(c.io);
        c.wbuf.clearRetainingCapacity();
        var h: [9]u8 = undefined;
        std.mem.writeInt(u24, h[0..3], @intCast(payload.len), .big);
        h[3] = kind;
        h[4] = flags;
        std.mem.writeInt(u32, h[5..9], id & 0x7fff_ffff, .big);
        try c.wbuf.ensureTotalCapacity(c.gpa, 9 + payload.len);
        c.wbuf.appendSliceAssumeCapacity(&h);
        c.wbuf.appendSliceAssumeCapacity(payload);
        try c.sess.writeAll(c.wbuf.items);
        if (c.wbuf.capacity > 1 << 20) c.wbuf.clearAndFree(c.gpa);
    }

    fn writeHeaders(c: *Conn, id: u32, block: []const u8, end_stream: bool) !void {
        // Header blocks here are small; one HEADERS frame (END_HEADERS) unless they exceed the
        // peer's frame size.
        var rest = block;
        var first = true;
        while (true) {
            const n = @min(rest.len, c.peer_max_frame);
            const last = n == rest.len;
            var flags: u8 = if (last) flag_end_headers else 0;
            if (first and end_stream) flags |= flag_end_stream;
            try c.writeFrame(if (first) frame_headers else frame_continuation, flags, id, rest[0..n]);
            rest = rest[n..];
            first = false;
            if (last) return;
        }
    }

    fn writeRst(c: *Conn, id: u32, code: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, code, .big);
        try c.writeFrame(frame_rst, 0, id, &b);
    }

    fn writeWindow(c: *Conn, id: u32, inc: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, inc, .big);
        try c.writeFrame(frame_window, 0, id, &b);
    }

    fn maybeRemoveLocked(c: *Conn, st: *Stream) void {
        if (st.removed) return;
        const done = st.reset_code != null or (st.rx_end and (st.tx_end or c.role == .client));
        if (!done) return;
        st.removed = true;
        _ = c.streams.remove(st.id);
        // Its unread messages and partial bytes no longer hold connection credit or budget.
        c.conn_unread -|= st.unread_wire;
        st.unread_wire = 0;
        c.partial_total -|= st.rxbuf.items.len;
        st.rxbuf.clearAndFree(c.gpa);
        c.mon.broadcast();
        // The map's reference. Safe under the lock: the application holds its own.
        if (st.refs.fetchSub(1, .acq_rel) == 1) st.destroy();
    }

    // ---------------------------------------------------------------- client calls

    pub fn start(c: *Conn, path: []const u8, authority: []const u8, timeout_ns: u64) Error!*Stream {
        var hb: std.ArrayList(u8) = .empty;
        defer hb.deinit(c.gpa);
        hpack.encodeLiteral(&hb, c.gpa, ":method", "POST") catch return error.OutOfMemory;
        hpack.encodeLiteral(&hb, c.gpa, ":scheme", "https") catch return error.OutOfMemory;
        hpack.encodeLiteral(&hb, c.gpa, ":path", path) catch return error.OutOfMemory;
        hpack.encodeLiteral(&hb, c.gpa, ":authority", authority) catch return error.OutOfMemory;
        hpack.encodeLiteral(&hb, c.gpa, "content-type", "application/grpc") catch return error.OutOfMemory;
        hpack.encodeLiteral(&hb, c.gpa, "user-agent", "mysticeti") catch return error.OutOfMemory;
        hpack.encodeLiteral(&hb, c.gpa, "te", "trailers") catch return error.OutOfMemory;
        hpack.encodeLiteral(&hb, c.gpa, "grpc-encoding", "zstd") catch return error.OutOfMemory;
        hpack.encodeLiteral(&hb, c.gpa, "grpc-accept-encoding", "zstd") catch return error.OutOfMemory;
        if (timeout_ns != 0) {
            var tb: [24]u8 = undefined;
            const ms = @max(1, timeout_ns / std.time.ns_per_ms);
            const v = std.fmt.bufPrint(&tb, "{d}m", .{ms}) catch unreachable;
            hpack.encodeLiteral(&hb, c.gpa, "grpc-timeout", v) catch return error.OutOfMemory;
        }
        const st = c.gpa.create(Stream) catch return error.OutOfMemory;
        c.mon.lock();
        if (c.dead) {
            c.mon.unlock();
            c.gpa.destroy(st);
            return error.Unavailable;
        }
        const id = c.next_stream;
        c.next_stream += 2;
        st.* = .{ .conn = c, .id = id, .send_window = c.peer_initial_window, .peer_zstd = true, .tx_headers = true };
        if (timeout_ns != 0) st.deadline_ns = mon.monoNs(c.io) +| timeout_ns;
        c.streams.put(c.gpa, id, st) catch {
            c.mon.unlock();
            c.gpa.destroy(st);
            return error.OutOfMemory;
        };
        c.ref();
        c.mon.unlock();
        // Stream ids must reach the wire in order: HEADERS under the write lock in id order is
        // guaranteed by the caller serializing `start` (Channel does).
        c.writeHeaders(id, hb.items, false) catch {
            c.die("write failed");
            st.release();
            return error.Unavailable;
        };
        return st;
    }

    // ---------------------------------------------------------------- reader

    const Hdrs = struct {
        path: []const u8 = "",
        http_status: u16 = 0,
        grpc_status: ?u8 = null,
        grpc_message: []const u8 = "",
        accept_zstd: bool = false,
        encoding_zstd: bool = false,
        timeout_ns: u64 = 0,
        arena: Allocator = undefined,
    };

    fn hdrSink(h: *Hdrs, name: []const u8, value: []const u8) hpack.Error!void {
        if (std.mem.eql(u8, name, ":path")) h.path = value;
        if (std.mem.eql(u8, name, ":status")) h.http_status = std.fmt.parseInt(u16, value, 10) catch 0;
        if (std.mem.eql(u8, name, "grpc-status")) h.grpc_status = std.fmt.parseInt(u8, value, 10) catch 2;
        if (std.mem.eql(u8, name, "grpc-message")) h.grpc_message = value;
        if (std.mem.eql(u8, name, "grpc-accept-encoding") and std.mem.indexOf(u8, value, "zstd") != null) h.accept_zstd = true;
        if (std.mem.eql(u8, name, "grpc-encoding") and std.mem.eql(u8, value, "zstd")) h.encoding_zstd = true;
        if (std.mem.eql(u8, name, "grpc-timeout")) {
            if (serve.h2.meta.parseTimeout(value)) |ms| h.timeout_ns = ms *| std.time.ns_per_ms;
        }
    }

    fn readFull(c: *Conn, buf: []u8) !void {
        var off: usize = 0;
        while (off < buf.len) {
            const n = try c.sess.read(buf[off..]);
            if (n == 0) return error.Closed;
            off += n;
        }
    }

    /// The reader loop of a connection (runs on its own thread, owns one reference).
    pub fn run(c: *Conn) void {
        defer c.unref();
        c.runInner() catch |e| c.die(switch (e) {
            error.Closed => "connection closed",
            error.Protocol => "h2 protocol error",
            error.KeepaliveTimeout => "keepalive timeout",
            else => "connection failed",
        });
        c.die("connection closed");
    }

    const RunError = tls.Error || error{ Protocol, KeepaliveTimeout };

    /// Connection preface (client), SETTINGS and the connection-level WINDOW_UPDATE. Runs before
    /// any other thread can write on the connection (clients: in `dial`, before the Conn is
    /// published; servers: first thing on the reader thread).
    fn writePreamble(c: *Conn) tls.Error!void {
        if (c.role == .client) {
            c.wmu.lockUncancelable(c.io);
            defer c.wmu.unlock(c.io);
            try c.sess.writeAll(preface);
        }
        var s: [24]u8 = undefined;
        var n: usize = 0;
        const put = struct {
            fn f(b: *[24]u8, at: *usize, id: u16, v: u32) void {
                std.mem.writeInt(u16, b[at.*..][0..2], id, .big);
                std.mem.writeInt(u32, b[at.* + 2 ..][0..4], v, .big);
                at.* += 6;
            }
        }.f;
        put(&s, &n, 2, 0); // ENABLE_PUSH
        put(&s, &n, 4, c.cfg.stream_window); // INITIAL_WINDOW_SIZE
        put(&s, &n, 5, max_frame_in); // MAX_FRAME_SIZE
        if (c.role == .server) put(&s, &n, 3, c.cfg.max_concurrent_streams);
        c.writeFrame(frame_settings, 0, 0, s[0..n]) catch return error.Io;
        c.writeWindow(0, c.cfg.conn_window - 65_535) catch return error.Io;
    }

    fn runInner(c: *Conn) RunError!void {
        const gpa = c.gpa;
        // A client wrote its preface and SETTINGS in `Channel.dial`, before any call could start.
        if (c.role == .server) try c.writePreamble();
        if (c.role == .server) {
            var pf: [preface.len]u8 = undefined;
            try c.readFull(&pf);
            if (!std.mem.eql(u8, &pf, preface)) return error.Protocol;
        }
        var dec = hpack.Decoder.init(gpa);
        defer dec.deinit();
        var hblock: std.ArrayList(u8) = .empty;
        defer hblock.deinit(gpa);
        var hstream: u32 = 0;
        var hend_stream = false;
        const payload = gpa.alloc(u8, max_frame_in) catch return error.OutOfMemory;
        defer gpa.free(payload);
        c.last_rx_ns = mon.monoNs(c.io);
        while (true) {
            // Wait for a frame; ping when the line is quiet, give up when a PING goes unanswered.
            while (true) {
                const now = mon.monoNs(c.io);
                if (c.sess.buffered()) break;
                var wait_ns: u64 = c.cfg.keepalive_ns;
                if (c.ping_sent_ns != 0) {
                    if (now -| c.ping_sent_ns >= c.cfg.keepalive_ns) return error.KeepaliveTimeout;
                    wait_ns = c.cfg.keepalive_ns - (now -| c.ping_sent_ns);
                } else if (now -| c.last_rx_ns >= c.cfg.keepalive_ns) {
                    c.ping_sent_ns = now;
                    c.writeFrame(frame_ping, 0, 0, &@as([8]u8, @splat(0x7a))) catch return error.Io;
                    wait_ns = c.cfg.keepalive_ns;
                } else wait_ns = c.cfg.keepalive_ns - (now -| c.last_rx_ns);
                const ms: i32 = @intCast(@min(@max(wait_ns / std.time.ns_per_ms, 1), 60_000));
                if (try c.sess.waitReadable(ms)) break;
            }
            var h: [9]u8 = undefined;
            try c.readFull(&h);
            const len = std.mem.readInt(u24, h[0..3], .big);
            const kind = h[3];
            const flags = h[4];
            const id = std.mem.readInt(u32, h[5..9], .big) & 0x7fff_ffff;
            if (len > max_frame_in) return error.Protocol;
            const p = payload[0..len];
            try c.readFull(p);
            c.last_rx_ns = mon.monoNs(c.io);
            c.ping_sent_ns = 0;
            if (hstream != 0 and kind != frame_continuation) return error.Protocol;
            switch (kind) {
                frame_settings => {
                    if (flags & flag_ack != 0) continue;
                    if (id != 0 or len % 6 != 0) return error.Protocol;
                    var i: usize = 0;
                    c.mon.lock();
                    while (i < len) : (i += 6) {
                        const sid = std.mem.readInt(u16, p[i..][0..2], .big);
                        const v = std.mem.readInt(u32, p[i + 2 ..][0..4], .big);
                        switch (sid) {
                            4 => {
                                if (v > 0x7fff_ffff) {
                                    c.mon.unlock();
                                    return error.Protocol;
                                }
                                const delta = @as(i64, v) - c.peer_initial_window;
                                c.peer_initial_window = v;
                                var it = c.streams.valueIterator();
                                while (it.next()) |st| st.*.send_window += delta;
                            },
                            5 => {
                                if (v < 16_384 or v > 16_777_215) {
                                    c.mon.unlock();
                                    return error.Protocol;
                                }
                                c.peer_max_frame = v;
                            },
                            else => {},
                        }
                    }
                    c.mon.broadcast();
                    c.mon.unlock();
                    c.writeFrame(frame_settings, flag_ack, 0, &.{}) catch return error.Io;
                },
                frame_ping => {
                    if (len != 8 or id != 0) return error.Protocol;
                    if (flags & flag_ack == 0) c.writeFrame(frame_ping, flag_ack, 0, p) catch return error.Io;
                },
                frame_goaway => return error.Closed,
                frame_window => {
                    if (len != 4) return error.Protocol;
                    const inc = std.mem.readInt(u32, p[0..4], .big) & 0x7fff_ffff;
                    if (inc == 0) {
                        if (id == 0) return error.Protocol;
                        continue;
                    }
                    c.mon.lock();
                    if (id == 0) {
                        c.send_window += inc;
                        if (c.send_window > 0x7fff_ffff) {
                            c.mon.unlock();
                            return error.Protocol;
                        }
                    } else if (c.streams.get(id)) |st| {
                        st.send_window += inc;
                    }
                    c.mon.broadcast();
                    c.mon.unlock();
                },
                frame_rst => {
                    if (len != 4 or id == 0) return error.Protocol;
                    const code = std.mem.readInt(u32, p[0..4], .big);
                    c.mon.lock();
                    if (c.streams.get(id)) |st| {
                        if (st.reset_code == null) st.reset_code = if (code == 8 or code == 0) code else 14;
                        // NO_ERROR after trailers is a clean end, not a failure.
                        if (code == 0 and (st.rx_end)) st.reset_code = null;
                        if (st.reset_code == null) {} else if (st.status == null) st.status = 14;
                        c.maybeRemoveLocked(st);
                        if (!st.removed and st.reset_code == null) {} // clean end, stays until the app finishes
                        c.mon.broadcast();
                    }
                    c.mon.unlock();
                    c.flushCredit();
                },
                frame_headers, frame_continuation => {
                    var body = p;
                    var end_stream = hend_stream;
                    if (kind == frame_headers) {
                        if (id == 0) return error.Protocol;
                        var pad: usize = 0;
                        if (flags & flag_padded != 0) {
                            if (body.len < 1) return error.Protocol;
                            pad = body[0];
                            body = body[1..];
                        }
                        if (flags & flag_priority != 0) {
                            if (body.len < 5) return error.Protocol;
                            body = body[5..];
                        }
                        if (pad > body.len) return error.Protocol;
                        body = body[0 .. body.len - pad];
                        hstream = id;
                        end_stream = flags & flag_end_stream != 0;
                        hend_stream = end_stream;
                        hblock.clearRetainingCapacity();
                    } else if (hstream == 0 or id != hstream) return error.Protocol;
                    if (hblock.items.len + body.len > max_header_block) return error.Protocol;
                    hblock.appendSlice(gpa, body) catch return error.OutOfMemory;
                    if (flags & flag_end_headers == 0) continue;
                    const sid = hstream;
                    hstream = 0;
                    var arena_state = std.heap.ArenaAllocator.init(gpa);
                    defer arena_state.deinit();
                    var hd: Hdrs = .{ .arena = arena_state.allocator() };
                    dec.decode(arena_state.allocator(), hblock.items, &hd, hdrSink) catch return error.Protocol;
                    try c.onHeaders(sid, &hd, hend_stream);
                },
                frame_data => {
                    if (id == 0) return error.Protocol;
                    var body = p;
                    if (flags & flag_padded != 0) {
                        if (body.len < 1) return error.Protocol;
                        const pad = body[0];
                        if (pad >= body.len) return error.Protocol;
                        body = body[1 .. body.len - pad];
                    }
                    try c.onData(id, body, len, flags & flag_end_stream != 0);
                },
                else => {}, // PRIORITY, PUSH_PROMISE (disabled), unknown frames: ignored
            }
        }
    }

    fn onHeaders(c: *Conn, id: u32, hd: *const Hdrs, end_stream: bool) RunError!void {
        c.mon.lock();
        if (c.streams.get(id)) |st| {
            // client: response headers, then trailers; server: request trailers (none expected).
            if (c.role == .client) {
                if (!st.saw_headers) {
                    st.saw_headers = true;
                    st.peer_zstd = hd.encoding_zstd or st.peer_zstd;
                }
                if (hd.grpc_status) |g| {
                    st.status = g;
                    if (hd.grpc_message.len > 0 and st.status_message.len == 0) {
                        var dec_msg: std.ArrayList(u8) = .empty;
                        defer dec_msg.deinit(c.gpa);
                        percentDecode(&dec_msg, c.gpa, hd.grpc_message) catch {};
                        st.status_message = dec_msg.toOwnedSlice(c.gpa) catch &.{};
                    }
                } else if (hd.http_status != 0 and hd.http_status != 200 and st.status == null) {
                    st.status = 14;
                }
            }
            if (end_stream) {
                st.rx_end = true;
                if (c.role == .client and st.status == null) st.status = 2; // ended without grpc-status
            }
            c.maybeRemoveLocked(st);
            c.mon.broadcast();
            c.mon.unlock();
            c.flushCredit();
            return;
        }
        if (c.role == .client or id % 2 == 0 or id <= c.last_peer_stream) {
            // Late headers for a stream we already dropped (decoded above to keep HPACK in sync).
            if (c.role == .server and id % 2 == 0) {
                c.mon.unlock();
                return error.Protocol;
            }
            c.mon.unlock();
            return;
        }
        c.last_peer_stream = id;
        if (c.handler == null or c.dead or c.handlers >= c.cfg.max_concurrent_streams) {
            c.mon.unlock();
            c.writeRst(id, 7) catch {};
            return;
        }
        const st = c.gpa.create(Stream) catch {
            c.mon.unlock();
            return error.OutOfMemory;
        };
        st.* = .{ .conn = c, .id = id, .send_window = c.peer_initial_window, .peer_zstd = hd.accept_zstd, .saw_headers = true };
        st.path = c.gpa.dupe(u8, hd.path) catch &.{};
        if (hd.timeout_ns != 0) st.deadline_ns = mon.monoNs(c.io) +| hd.timeout_ns;
        if (end_stream) st.rx_end = true;
        c.streams.put(c.gpa, id, st) catch {
            c.mon.unlock();
            c.gpa.destroy(st);
            return error.OutOfMemory;
        };
        c.ref();
        c.handlers += 1;
        c.mon.unlock();
        const t = std.Thread.spawn(.{ .stack_size = thread_stack }, handlerMain, .{st}) catch {
            c.mon.lock();
            c.handlers -= 1;
            st.reset_code = 7;
            c.maybeRemoveLocked(st);
            c.mon.unlock();
            c.writeRst(id, 7) catch {};
            st.release();
            return;
        };
        t.detach();
    }

    fn handlerMain(st: *Stream) void {
        const c = st.conn;
        const h = c.handler.?;
        h.serve(h.ctx, st);
        st.finish(.internal, "handler returned without a status");
        c.mon.lock();
        c.handlers -= 1;
        c.mon.broadcast();
        c.mon.unlock();
        st.release();
    }

    fn onData(c: *Conn, id: u32, body: []const u8, frame_len: usize, end_stream: bool) RunError!void {
        c.mon.lock();
        // The whole frame counts against the connection window, delivered or not.
        c.conn_rx_total +|= frame_len;
        const st = c.streams.get(id);
        var stream_credit: u32 = 0;
        var reset_with: ?u32 = null;
        if (st) |s| {
            s.rx_total += frame_len;
            if (s.reset_code == null) {
                const before = s.rxbuf.items.len;
                s.rxbuf.appendSlice(c.gpa, body) catch {
                    c.mon.unlock();
                    return error.OutOfMemory;
                };
                // Split complete gRPC messages off the buffer.
                var off: usize = 0;
                while (s.rxbuf.items.len - off >= 5) {
                    const flag = s.rxbuf.items[off];
                    const mlen = std.mem.readInt(u32, s.rxbuf.items[off + 1 ..][0..4], .big);
                    if (flag > 1 or mlen > c.cfg.message_limit) {
                        reset_with = 11;
                        break;
                    }
                    if (s.rxbuf.items.len - off - 5 < mlen) break;
                    // Every consensus method takes exactly one request message: a server stream
                    // refuses further data instead of buffering what the handler never reads.
                    if (c.role == .server and s.msgs_in >= 1) {
                        reset_with = 11;
                        break;
                    }
                    if (s.queued_bytes + mlen > c.cfg.max_queued_bytes) {
                        reset_with = 11;
                        break;
                    }
                    const data = c.gpa.dupe(u8, s.rxbuf.items[off + 5 ..][0..mlen]) catch {
                        c.mon.unlock();
                        return error.OutOfMemory;
                    };
                    s.queue.append(c.gpa, .{ .compressed = flag == 1, .data = data }) catch {
                        c.gpa.free(data);
                        c.mon.unlock();
                        return error.OutOfMemory;
                    };
                    s.queued_bytes += mlen;
                    s.unread_wire += 5 + mlen;
                    c.conn_unread += 5 + mlen;
                    s.msgs_in += 1;
                    off += 5 + mlen;
                }
                if (off > 0) {
                    const rest = s.rxbuf.items.len - off;
                    std.mem.copyForwards(u8, s.rxbuf.items[0..rest], s.rxbuf.items[off..]);
                    s.rxbuf.shrinkRetainingCapacity(rest);
                }
                if (s.rxbuf.items.len >= before) c.partial_total += s.rxbuf.items.len - before else c.partial_total -|= before - s.rxbuf.items.len;
                if (reset_with == null and s.rxbuf.items.len > 5 + c.cfg.message_limit) reset_with = 11;
                if (reset_with == null and c.role == .server and s.msgs_in >= 1 and s.rxbuf.items.len > 0) reset_with = 11;
                if (reset_with == null and c.conn_unread + c.partial_total > c.cfg.max_conn_buffered) reset_with = 11;
                if (end_stream and reset_with == null) {
                    if (s.rxbuf.items.len != 0) reset_with = 2 else s.rx_end = true;
                }
                if (reset_with != null) {
                    s.reset_code = 14;
                    s.status = 8; // RESOURCE_EXHAUSTED
                }
                if (reset_with == null) stream_credit = c.streamCreditLocked(s);
                c.maybeRemoveLocked(s);
            }
            c.mon.broadcast();
        }
        const conn_credit = c.connCreditLocked();
        c.mon.unlock();
        if (conn_credit > 0) c.writeWindow(0, conn_credit) catch return error.Io;
        if (stream_credit > 0) c.writeWindow(id, stream_credit) catch return error.Io;
        if (reset_with) |code| c.writeRst(id, code) catch return error.Io;
    }
};

fn percentDecode(out: *std.ArrayList(u8), gpa: Allocator, s: []const u8) !void {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 2 < s.len + 0 and i + 2 <= s.len - 1 + 0) {
            if (std.fmt.parseInt(u8, s[i + 1 ..][0..2], 16)) |b| {
                try out.append(gpa, b);
                i += 2;
                continue;
            } else |_| {}
        }
        try out.append(gpa, s[i]);
    }
}

// ---------------------------------------------------------------- client channel


/// Connects an IPv4 literal with a deadline on a non-blocking socket (poll for writability, then
/// SO_ERROR). std's `Io.net` connect has neither a timeout nor a safe EINTR retry on POSIX.
fn connectIp4(host: []const u8, port: u16, timeout_ns: u64) !std.c.fd_t {
    const ip = Io.net.Ip4Address.parse(host, port) catch return error.NotAnIpLiteral;
    const c = std.c;
    const fd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer _ = c.close(fd);
    const fl = c.fcntl(fd, c.F.GETFL);
    _ = c.fcntl(fd, c.F.SETFL, fl | @as(c_int, @bitCast(c.O{ .NONBLOCK = true })));
    var sa: c.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(ip.bytes) };
    const r = c.connect(fd, @ptrCast(&sa), @sizeOf(c.sockaddr.in));
    if (r != 0) {
        switch (c.errno(r)) {
            .INPROGRESS, .INTR => {},
            else => return error.ConnectionRefused,
        }
        var p = [_]c.pollfd{.{ .fd = fd, .events = c.POLL.OUT, .revents = 0 }};
        const ms: c_int = @intCast(@min(timeout_ns / std.time.ns_per_ms, 600_000));
        while (true) {
            const n = c.poll(&p, 1, ms);
            if (n < 0 and c.errno(n) == .INTR) continue;
            if (n <= 0) return error.ConnectionTimedOut;
            break;
        }
        var err: c_int = 0;
        var len: c.socklen_t = @sizeOf(c_int);
        if (c.getsockopt(fd, c.SOL.SOCKET, c.SO.ERROR, &err, &len) != 0 or err != 0) return error.ConnectionRefused;
    }
    _ = c.fcntl(fd, c.F.SETFL, fl);
    return fd;
}

/// TCP connect with a deadline. `Io.net` has no connect timeout on POSIX yet, so the blocking
/// connect runs on a helper thread that the caller abandons at the deadline (the helper closes
/// a late socket itself).
fn dialTcp(gpa: Allocator, io: Io, host: []const u8, port: u16, timeout_ns: u64) !std.c.fd_t {
    if (connectIp4(host, port, timeout_ns)) |fd| return fd else |e| if (e != error.NotAnIpLiteral) return e;
    const Ctx = struct {
        gpa: Allocator,
        io: Io,
        host: []u8,
        port: u16,
        state: std.atomic.Value(u8) = .init(0), // 0 pending, 1 done, 2 abandoned
        refs: std.atomic.Value(u8) = .init(2),
        stream: ?Io.net.Stream = null,

        fn unref(x: *@This()) void {
            if (x.refs.fetchSub(1, .acq_rel) == 1) {
                x.gpa.free(x.host);
                x.gpa.destroy(x);
            }
        }
        fn run(x: *@This()) void {
            defer x.unref();
            const hn = Io.net.HostName.init(x.host) catch {
                _ = x.state.cmpxchgStrong(0, 1, .acq_rel, .acquire);
                return;
            };
            const st = hn.connect(x.io, x.port, .{ .mode = .stream }) catch {
                _ = x.state.cmpxchgStrong(0, 1, .acq_rel, .acquire);
                return;
            };
            x.stream = st;
            if (x.state.cmpxchgStrong(0, 1, .acq_rel, .acquire) != null) _ = std.c.close(st.socket.handle);
        }
    };
    const x = try gpa.create(Ctx);
    x.* = .{ .gpa = gpa, .io = io, .host = try gpa.dupe(u8, host), .port = port };
    const t = std.Thread.spawn(.{ .stack_size = thread_stack }, Ctx.run, .{x}) catch |e| {
        gpa.free(x.host);
        gpa.destroy(x);
        return e;
    };
    t.detach();
    const deadline = mon.monoNs(io) +| timeout_ns;
    while (x.state.load(.acquire) == 0) {
        if (mon.monoNs(io) >= deadline) {
            if (x.state.cmpxchgStrong(0, 2, .acq_rel, .acquire) == null) {
                x.unref();
                return error.ConnectionTimedOut;
            }
            break;
        }
        sock.sleepMs(2);
    }
    defer x.unref();
    const st = x.stream orelse return error.ConnectionRefused;
    return st.socket.handle;
}

pub const Endpoint = struct {
    host: []const u8,
    port: u16,
};

/// A lazily connecting, reconnecting client channel to one peer: TLS pinned to the peer's
/// network key, our identity as client certificate.
pub const Channel = struct {
    gpa: Allocator,
    io: Io,
    cfg: Config,
    endpoint: Endpoint,
    server_name: []u8,
    identity: *const tls.Identity,
    peer_key: [32]u8,
    mu: Io.Mutex = .init,
    conn: ?*Conn = null,
    authority: []u8,
    /// Serializes `start` so stream ids reach the wire in order.
    start_mu: Io.Mutex = .init,
    /// Connections of this channel not yet freed (their reader threads may outlive `close`).
    gate: std.atomic.Value(u32) = .init(0),

    pub fn create(gpa: Allocator, io: Io, cfg: Config, endpoint: Endpoint, server_name: []const u8, identity: *const tls.Identity, peer_key: *const [32]u8) Allocator.Error!*Channel {
        const ch = try gpa.create(Channel);
        errdefer gpa.destroy(ch);
        const sn = try gpa.dupe(u8, server_name);
        errdefer gpa.free(sn);
        const host = try gpa.dupe(u8, endpoint.host);
        errdefer gpa.free(host);
        const auth = try std.fmt.allocPrint(gpa, "{s}:{d}", .{ endpoint.host, endpoint.port });
        ch.* = .{ .gpa = gpa, .io = io, .cfg = cfg, .endpoint = .{ .host = host, .port = endpoint.port }, .server_name = sn, .identity = identity, .peer_key = peer_key.*, .authority = auth };
        return ch;
    }

    pub fn destroy(ch: *Channel) void {
        ch.close();
        // Reader threads end once their socket is shut down. A connection frees itself and
        // decrements `gate` last, so wait for every one before the channel goes.
        var waited: u32 = 0;
        while (ch.gate.load(.acquire) != 0) : (waited += 2) {
            sock.sleepMs(2);
            if (waited % 10_000 == 0 and waited != 0) log.warn("channel {s}: still waiting for {d} connection(s) to finish", .{ ch.authority, ch.gate.load(.acquire) });
        }
        ch.gpa.free(ch.server_name);
        ch.gpa.free(@constCast(ch.endpoint.host));
        ch.gpa.free(ch.authority);
        ch.gpa.destroy(ch);
    }

    /// Drops the current connection (calls on it fail with UNAVAILABLE); the next call reconnects.
    pub fn close(ch: *Channel) void {
        ch.mu.lockUncancelable(ch.io);
        const c = ch.conn;
        ch.conn = null;
        ch.mu.unlock(ch.io);
        if (c) |cc| {
            cc.die("channel closed");
            cc.unref();
        }
    }

    /// The live connection, with a reference for the caller (`unref` it when done; a stream
    /// holds its own). The reference is taken under `mu`, so a concurrent reconnect or `close`
    /// cannot free the connection under the caller.
    fn connected(ch: *Channel) Error!*Conn {
        ch.mu.lockUncancelable(ch.io);
        defer ch.mu.unlock(ch.io);
        if (ch.conn) |c| {
            if (!c.isDead() and c.tryRef()) return c;
            c.unref();
            ch.conn = null;
        }
        const c = ch.dial() catch |e| {
            log.debug("dial {s}: {s}", .{ ch.authority, @errorName(e) });
            return error.Unavailable;
        };
        c.ref(); // the caller's; the channel keeps the dial reference
        ch.conn = c;
        return c;
    }

    fn dial(ch: *Channel) !*Conn {
        const fd = try dialTcp(ch.gpa, ch.io, ch.endpoint.host, ch.endpoint.port, ch.cfg.connect_timeout_ns);
        var owned = false; // once the Conn exists it frees the socket and session
        errdefer if (!owned) {
            _ = std.c.close(fd);
        };
        sock.tune(fd);
        const sess = try tls.Session.connect(ch.gpa, ch.io, fd, ch.server_name, ch.identity, &ch.peer_key);
        errdefer if (!owned) sess.deinit();
        const c = try ch.gpa.create(Conn);
        c.* = .{ .gpa = ch.gpa, .io = ch.io, .role = .client, .cfg = ch.cfg, .sess = sess, .fd = fd, .handler = null, .mon = Monitor.init(ch.io) };
        owned = true;
        c.gate = &ch.gate;
        _ = ch.gate.fetchAdd(1, .acq_rel);
        // Preface, SETTINGS and the window update go out before the Conn is published, so no
        // call's HEADERS can precede them and no two threads ever write the session at once.
        c.writePreamble() catch {
            c.die("preamble failed");
            c.unref();
            return error.Io;
        };
        c.refs.store(2, .release); // the channel's and the reader thread's
        const t = std.Thread.spawn(.{ .stack_size = thread_stack }, Conn.run, .{c}) catch {
            c.refs.store(1, .release);
            c.unref();
            return error.ThreadQuotaExceeded;
        };
        t.detach();
        return c;
    }

    /// Opens a call. The caller owns the returned stream (`release` it, `cancel` it to abandon).
    pub fn startCall(ch: *Channel, method: proto.Method, timeout_ns: u64) Error!*Stream {
        const c = try ch.connected();
        defer c.unref();
        ch.start_mu.lockUncancelable(ch.io);
        defer ch.start_mu.unlock(ch.io);
        return c.start(method.path(), ch.authority, timeout_ns);
    }

    /// One request, one response. The response is allocated in `arena`.
    pub fn unary(ch: *Channel, arena: Allocator, method: proto.Method, request: []const u8, timeout_ns: u64) Error![]u8 {
        const st = try ch.startCall(method, timeout_ns);
        defer st.release();
        st.send(request) catch |e| {
            st.cancel();
            return e;
        };
        st.closeSend() catch |e| {
            st.cancel();
            return e;
        };
        const resp = st.recv(arena, 0) catch |e| {
            st.cancel();
            return e;
        };
        // Drain to the trailers so the status is known.
        _ = st.recv(arena, 0) catch |e| switch (e) {
            error.Status => return error.Status,
            else => {},
        };
        return resp orelse error.Unavailable;
    }
};

// ---------------------------------------------------------------- server

pub const ServerOptions = struct {
    /// Dotted IPv4 or "localhost"; port 0 picks a free one (read it back from `port`).
    listen_host: []const u8 = "127.0.0.1",
    listen_port: u16 = 0,
    server_name: []const u8,
    identity: *const tls.Identity,
    check: tls.PeerKeyCheck,
    cfg: Config = .{},
    handler: Handler,
};

pub const Server = struct {
    gpa: Allocator,
    io: Io,
    opts: ServerOptions,
    listener: Io.net.Server,
    port: u16,
    stopping: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    /// Live connections (registered by their thread, removed when freed), for a clean `stop`.
    reg_mu: Monitor,
    registry: std.ArrayList(*Conn) = .empty,
    /// connMain threads from accept until they return (handshake included); guarded by `reg_mu`.
    inflight: u32 = 0,
    /// Of those, the ones still in the TLS handshake; guarded by `reg_mu`.
    handshaking: u32 = 0,

    pub fn start(gpa: Allocator, io: Io, opts: ServerOptions) !*Server {
        const s = try gpa.create(Server);
        errdefer gpa.destroy(s);
        var addr = try Io.net.IpAddress.parse(opts.listen_host, opts.listen_port);
        var l = try addr.listen(io, .{ .reuse_address = true });
        errdefer l.deinit(io);
        s.* = .{ .gpa = gpa, .io = io, .opts = opts, .listener = l, .port = l.socket.address.getPort(), .reg_mu = Monitor.init(io) };
        s.thread = try std.Thread.spawn(.{ .stack_size = thread_stack }, acceptLoop, .{s});
        return s;
    }

    pub fn stop(s: *Server) void {
        s.stopping.store(true, .release);
        // Wake `accept` with a throwaway connection.
        if (Io.net.IpAddress.parse("127.0.0.1", s.port)) |a| {
            var addr = a;
            if (addr.connect(s.io, .{ .mode = .stream })) |st| {
                _ = std.c.close(st.socket.handle);
            } else |_| {}
        } else |_| {}
        if (s.thread) |t| t.join();
        s.listener.deinit(s.io);
        // End every live connection, then wait for every connMain thread (a handshake in
        // progress ends within its deadline and then sees `stopping`) and for every connection
        // to be freed (their handler threads may still touch what the owner frees next).
        var waited: u64 = 0;
        while (true) {
            var live: std.ArrayList(*Conn) = .empty;
            s.reg_mu.lock();
            for (s.registry.items) |c| if (c.tryRef()) live.append(s.gpa, c) catch c.unref();
            s.reg_mu.unlock();
            for (live.items) |c| {
                c.die("server stopping");
                c.unref();
            }
            live.deinit(s.gpa);
            s.reg_mu.lock();
            if (s.inflight == 0 and s.registry.items.len == 0) {
                s.reg_mu.unlock();
                break;
            }
            s.reg_mu.waitNs(20 * std.time.ns_per_ms);
            s.reg_mu.unlock();
            waited += 20;
            if (waited % 10_000 == 0) log.warn("consensus server stop: waiting for {d} connection thread(s)", .{s.inflight});
        }
        // Serialize with the last connFreed / connMain exit still inside the monitor.
        s.reg_mu.lock();
        s.reg_mu.unlock();
        s.registry.deinit(s.gpa);
        s.gpa.destroy(s);
    }

    fn connFreed(owner: *anyopaque, c: *Conn) void {
        const s: *Server = @ptrCast(@alignCast(owner));
        s.reg_mu.lock();
        for (s.registry.items, 0..) |x, i| if (x == c) {
            _ = s.registry.swapRemove(i);
            break;
        };
        s.reg_mu.broadcast();
        s.reg_mu.unlock();
    }

    fn acceptLoop(s: *Server) void {
        while (!s.stopping.load(.acquire)) {
            const st = s.listener.accept(s.io) catch continue;
            if (s.stopping.load(.acquire)) {
                _ = std.c.close(st.socket.handle);
                return;
            }
            const fd = st.socket.handle;
            // Anyone who can reach the port gets here before authenticating: bound the threads.
            s.reg_mu.lock();
            const full = s.handshaking >= s.opts.cfg.max_pending_handshakes;
            if (!full) {
                s.inflight += 1;
                s.handshaking += 1;
            }
            s.reg_mu.unlock();
            if (full) {
                _ = std.c.close(fd);
                continue;
            }
            const t = std.Thread.spawn(.{ .stack_size = thread_stack }, connMain, .{ s, fd }) catch {
                s.reg_mu.lock();
                s.inflight -= 1;
                s.handshaking -= 1;
                s.reg_mu.broadcast();
                s.reg_mu.unlock();
                _ = std.c.close(fd);
                continue;
            };
            t.detach();
        }
    }

    /// Leaves the handshake phase (once) and, when `done`, the in-flight set.
    fn endPhase(s: *Server, handshake_over: bool, done: bool) void {
        s.reg_mu.lock();
        if (handshake_over) s.handshaking -= 1;
        if (done) s.inflight -= 1;
        s.reg_mu.broadcast();
        s.reg_mu.unlock();
    }

    fn connMain(s: *Server, fd: std.c.fd_t) void {
        sock.tune(fd);
        // The thread was counted at accept; it leaves `inflight` only as its very last access to `s`.
        const sess = tls.Session.accept(s.gpa, s.io, fd, s.opts.server_name, s.opts.identity, s.opts.check) catch |e| {
            log.debug("consensus tls accept refused: {s}", .{@errorName(e)});
            _ = std.c.close(fd);
            s.endPhase(true, true);
            return;
        };
        const c = s.gpa.create(Conn) catch {
            sess.deinit();
            _ = std.c.close(fd);
            s.endPhase(true, true);
            return;
        };
        c.* = .{ .gpa = s.gpa, .io = s.io, .role = .server, .cfg = s.opts.cfg, .sess = sess, .fd = fd, .handler = s.opts.handler, .mon = Monitor.init(s.io), .on_free = connFreed, .on_free_ctx = s };
        s.reg_mu.lock();
        s.handshaking -= 1;
        var same_peer: u32 = 0;
        for (s.registry.items) |x| {
            if (x.sess.peer_index == sess.peer_index) same_peer += 1;
        }
        var registered = false;
        if (!s.stopping.load(.acquire) and same_peer < s.opts.cfg.max_conns_per_peer) {
            if (s.registry.append(s.gpa, c)) |_| registered = true else |_| {}
        }
        if (!registered) {
            s.reg_mu.unlock();
            sess.deinit();
            s.gpa.destroy(c);
            _ = std.c.close(fd);
            s.endPhase(false, true);
            return;
        }
        s.reg_mu.unlock();
        if (s.stopping.load(.acquire)) c.die("server stopping");
        c.run(); // owns the initial reference; frees the connection when the last stream is done
        s.endPhase(false, true);
    }
};

// ---------------------------------------------------------------- tests

const TestEnv = struct {
    keys: [2][32]u8,
    fn lookup(ctx: *anyopaque, key: *const [32]u8) ?u32 {
        const self: *TestEnv = @ptrCast(@alignCast(ctx));
        for (self.keys, 0..) |k, i| if (std.mem.eql(u8, &k, key)) return @intCast(i);
        return null;
    }
};

const EchoHandler = struct {
    fn serveFn(_: *anyopaque, st: *Stream) void {
        var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const m = st.method() orelse return st.finish(.unimplemented, "no such method");
        switch (m) {
            .GetLatestRounds => {
                const req = st.recv(arena, 5 * std.time.ns_per_s) catch return st.finish(.invalid_argument, "bad request");
                _ = req;
                const resp = proto.encode(proto.GetLatestRoundsResponse, arena, &.{ .highest_received = &.{ 1, 2, 3 }, .highest_accepted = &.{ 4, 5, 6 } }) catch return st.finish(.internal, "oom");
                st.send(resp) catch return;
                st.finish(.ok, "");
            },
            .FetchBlocks => {
                // server streaming: three chunks, one of them large enough to be compressed
                const big = arena.alloc(u8, 300_000) catch return st.finish(.internal, "oom");
                @memset(big, 0x5a);
                for (0..3) |i| {
                    const resp = proto.encode(proto.FetchBlocksResponse, arena, &.{ .blocks = &.{if (i == 1) big else "blk"} }) catch return;
                    st.send(resp) catch return;
                }
                st.finish(.ok, "");
            },
            .SubscribeBlocks => {
                const first = (st.recv(arena, 5 * std.time.ns_per_s) catch return st.finish(.invalid_argument, "bad")) orelse return st.finish(.invalid_argument, "no first");
                const req = proto.decode(proto.SubscribeBlocksRequest, arena, first) catch return st.finish(.invalid_argument, "decode");
                var round = req.last_received_round;
                while (round < req.last_received_round + 5) {
                    round += 1;
                    const resp = proto.encode(proto.SubscribeBlocksResponse, arena, &.{ .block = "b", .excluded_ancestors = &.{} }) catch return;
                    st.send(resp) catch return;
                }
                // keep the stream open until the client cancels
                while (true) {
                    const more = st.recv(arena, 0) catch return;
                    if (more == null) return st.finish(.ok, "");
                }
            },
            else => st.finish(.unimplemented, "nope"),
        }
    }
};

test "grpc: unary, server streaming with compression, bidi subscribe, status errors" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var name_buf: [40]u8 = undefined;
    const name = try tls.serverName(&name_buf, 3);
    const seed_a: [32]u8 = @splat(11);
    const seed_b: [32]u8 = @splat(12);
    const id_a = try tls.Identity.init(&seed_a, name);
    const id_b = try tls.Identity.init(&seed_b, name);
    var env: TestEnv = .{ .keys = .{ id_a.publicKey(), id_b.publicKey() } };
    var dummy: u8 = 0;
    const srv = try Server.start(gpa, io, .{
        .server_name = name,
        .identity = &id_a,
        .check = .{ .ctx = &env, .lookup = TestEnv.lookup },
        .handler = .{ .ctx = &dummy, .serve = EchoHandler.serveFn },
    });
    defer srv.stop();

    const pub_a = id_a.publicKey();
    const ch = try Channel.create(gpa, io, .{ .keepalive_ns = 200 * std.time.ns_per_ms }, .{ .host = "127.0.0.1", .port = srv.port }, name, &id_b, &pub_a);
    defer ch.destroy();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // unary
    const resp = try ch.unary(arena, .GetLatestRounds, "", 5 * std.time.ns_per_s);
    const rr = try proto.decode(proto.GetLatestRoundsResponse, arena, resp);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 3 }, rr.highest_received);
    try std.testing.expectEqualSlices(u32, &.{ 4, 5, 6 }, rr.highest_accepted);

    // server streaming: three messages, the middle one 300 KB (compressed on the wire)
    {
        const st = try ch.startCall(.FetchBlocks, 5 * std.time.ns_per_s);
        defer st.release();
        try st.send("");
        try st.closeSend();
        var n: usize = 0;
        while (try st.recv(arena, 0)) |m| : (n += 1) {
            const fb = try proto.decode(proto.FetchBlocksResponse, arena, m);
            try std.testing.expectEqual(@as(usize, 1), fb.blocks.len);
            try std.testing.expectEqual(@as(usize, if (n == 1) 300_000 else 3), fb.blocks[0].len);
        }
        try std.testing.expectEqual(@as(usize, 3), n);
    }

    // bidi: one request message, then a stream of responses until we cancel
    {
        const st = try ch.startCall(.SubscribeBlocks, 0);
        defer st.release();
        const rq = try proto.encode(proto.SubscribeBlocksRequest, arena, &.{ .last_received_round = 40 });
        try st.send(rq);
        var n: usize = 0;
        while (n < 5) : (n += 1) {
            const m = (try st.recv(arena, 5 * std.time.ns_per_s)) orelse return error.TestUnexpectedResult;
            const sb = try proto.decode(proto.SubscribeBlocksResponse, arena, m);
            try std.testing.expectEqualStrings("b", sb.block);
        }
        // no more arrive: a timed recv times out while the stream is idle (keepalives flow)
        try std.testing.expectError(error.DeadlineExceeded, st.recv(arena, 600 * std.time.ns_per_ms));
        st.cancel();
    }

    // an unknown method returns its status
    {
        const st = try ch.startCall(.SendBlock, 5 * std.time.ns_per_s);
        defer st.release();
        try st.send("");
        try st.closeSend();
        try std.testing.expectError(error.Status, st.recv(arena, 0));
        try std.testing.expectEqual(Status.unimplemented, st.grpcStatus());
    }

    // the channel survives: a further unary works on the same connection
    _ = try ch.unary(arena, .GetLatestRounds, "", 5 * std.time.ns_per_s);
}

test "grpc: a client with a key outside the committee cannot call" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var name_buf: [40]u8 = undefined;
    const name = try tls.serverName(&name_buf, 3);
    const seed_a: [32]u8 = @splat(11);
    const seed_x: [32]u8 = @splat(99);
    const id_a = try tls.Identity.init(&seed_a, name);
    const id_x = try tls.Identity.init(&seed_x, name);
    var env: TestEnv = .{ .keys = .{ id_a.publicKey(), id_a.publicKey() } };
    var dummy: u8 = 0;
    const srv = try Server.start(gpa, io, .{
        .server_name = name,
        .identity = &id_a,
        .check = .{ .ctx = &env, .lookup = TestEnv.lookup },
        .handler = .{ .ctx = &dummy, .serve = EchoHandler.serveFn },
    });
    defer srv.stop();
    const pub_a = id_a.publicKey();
    const ch = try Channel.create(gpa, io, .{}, .{ .host = "127.0.0.1", .port = srv.port }, name, &id_x, &pub_a);
    defer ch.destroy();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    // The handshake may complete on the client side, but the server drops the connection before
    // any call is served.
    try std.testing.expectError(error.Unavailable, ch.unary(arena_state.allocator(), .GetLatestRounds, "", 2 * std.time.ns_per_s));
}
