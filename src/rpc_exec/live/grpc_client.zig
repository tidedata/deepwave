//! A small HTTP/2 gRPC client for unary calls: one TCP connection (TLS pinned to a validator's
//! network key, TLS against the system CA bundle, or cleartext h2c), many concurrent calls.
//!
//! Threads: `start` and `cancel` may be called from any thread; they take the connection lock and
//! write frames. One reader thread per connection connects, handshakes, then reads frames and
//! hands each finished call to its `Sink` (under the connection lock, so a cancelled call is never
//! delivered afterwards). A connection that fails ends every call on it with UNAVAILABLE and is
//! marked dead; the owner replaces it.
//!
//! References: the owner holds one (`release`), the reader thread one, the keepalive registry one,
//! and every caller that keeps the pointer across a call holds its own (`retain` / `unref`; the
//! validator pool hands out retained connections). The connection is freed at the last `unref`.
//!
//! Liveness (mysten-network's `connect_timeout`, `http2_keepalive_interval` and
//! `http2_keepalive_timeout`): one process-wide watchdog thread ends a connection that is not
//! ready `connect_timeout_ns` after `open` (TCP connect plus TLS handshake), PINGs every ready
//! connection (every `keepalive_busy_ns` while calls are open, `keepalive_idle_ns` otherwise) and
//! ends one whose PING is not acknowledged within `keepalive_timeout_ns`. A silently dead peer
//! therefore fails its calls with UNAVAILABLE instead of holding them until the caller's deadline.
//!
//! Limits against a misbehaving peer (sui-node tolerates f byzantine validators; so must this):
//! SETTINGS values are validated (RFC 9113 6.5.2), a response body is capped at
//! `max_response_bytes` (RESOURCE_EXHAUSTED and RST for that call) and a header block at
//! `max_header_block` (connection error).
//!
//! What tonic/hyper does that matters here and is mirrored: `te: trailers`, `content-type:
//! application/grpc`, `grpc-timeout` when the caller has one, trailers-only error replies,
//! percent-decoded `grpc-message`, base64 `grpc-status-details-bin`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const serve = @import("serve");
const hpack = serve.h2.hpack;
const tls_client = @import("tls_client.zig");
const log = std.log.scoped(.grpc_client);
pub var trace_frames = false;
/// Reader and watchdog thread stacks. glibc's pthread_create carves static TLS out of the stack
/// and answers EINVAL (std.Thread: unreachable) when the stack cannot hold it; the binaries that
/// link serve/exec carry hundreds of KiB of threadlocal caches, so 256 KiB failed on Linux.
/// Only touched pages are committed.
const thread_stack: usize = 8 << 20;

pub const Status = struct { code: u8, message: []const u8 = "", details: []const u8 = "" };
pub const Result = union(enum) { ok: []const u8, status: Status };

/// Receives a finished call. The result's bytes are valid only during the callback.
pub const Sink = struct {
    ctx: *anyopaque,
    done: *const fn (ctx: *anyopaque, tag: u64, result: Result) void,
};

pub const Security = union(enum) {
    /// h2c (loopback or WireGuard upstreams).
    plain,
    /// TLS, the leaf certificate must hold this Ed25519 key (validators, sui-tls).
    pinned: [32]u8,
    /// TLS against the system CA bundle, host name checked (public fullnodes).
    ca,
};

pub const Endpoint = struct {
    host: []const u8,
    port: u16,
    security: Security,
    /// SNI and certificate name for `pinned` (sui-tls `SUI_VALIDATOR_SERVER_NAME`).
    server_name: []const u8 = "sui",
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

/// Our receive windows: large, so validators never wait on us.
const recv_window: u32 = 16 << 20;
const max_frame_in: u32 = 1 << 20;
/// One unary response (gRPC prefix included); tonic's default `max_decoding_message_size` is
/// 4 MiB, sui-node raises it for its clients; validators' effects replies stay far below this.
pub var max_response_bytes: usize = 64 << 20;
/// One HEADERS + CONTINUATION block (hyper's default max header list is 16 KiB).
pub var max_header_block: usize = 64 << 10;
pub var connect_timeout_ns: u64 = 10 * std.time.ns_per_s;
pub var keepalive_busy_ns: u64 = 5 * std.time.ns_per_s;
pub var keepalive_idle_ns: u64 = 30 * std.time.ns_per_s;
pub var keepalive_timeout_ns: u64 = 20 * std.time.ns_per_s;

const Call = struct {
    sink: Sink,
    tag: u64,
    data: std.ArrayList(u8) = .empty,
    /// Request bytes not yet sent (flow control).
    out: []u8,
    out_pos: usize = 0,
    send_window: i64,
    grpc_status: ?u8 = null,
    grpc_message: []u8 = &.{},
    grpc_details: []u8 = &.{},
    http_status: ?u16 = null,
    end_sent: bool = false,
};

pub const Conn = struct {
    gpa: Allocator,
    io: Io,
    ep: Endpoint,
    authority: []u8,
    mu: Io.Mutex = .init,
    state: enum { connecting, ready, dead } = .connecting,
    dead_reason: []const u8 = "",
    calls: std.AutoHashMapUnmanaged(u32, *Call) = .empty,
    /// Calls started before the connection was ready, in order (stream ids not assigned yet).
    queued: std.ArrayList(Queued) = .empty,
    next_stream: u32 = 1,
    conn_send_window: i64 = 65_535,
    peer_initial_window: i64 = 65_535,
    peer_max_frame: u32 = 16_384,
    /// Set once the reader thread has the transport up.
    writer: ?*Io.Writer = null,
    /// The socket writer under TLS (the TLS writer's flush only encrypts into it).
    sock_writer: ?*Io.Writer = null,
    stream: ?Io.net.Stream = null,
    thread: ?std.Thread = null,
    /// Reference count: the owner's, the reader thread's and the keepalive registry's, plus one
    /// per `retain`.
    refs: std.atomic.Value(u32) = .init(3),
    /// Monotonic ns at `open` (the connect + handshake deadline).
    opened_at: u64 = 0,
    /// Keepalive: when the last PING went out, and whether its ACK is still due.
    ping_at: u64 = 0,
    ping_due: bool = false,
    /// Set (under `mu`) when the reader thread is gone; the registry then drops its reference.
    reader_done: bool = false,
    shutting_down: std.atomic.Value(bool) = .init(false),
    /// Monotonic ns when the connection died (the pool's reconnect cooldown).
    died_at: u64 = 0,
    /// Set once the connection reached `ready` (a pool backs off reconnects to peers that never do).
    was_ready: bool = false,

    const Queued = struct { id_slot: *u32, path: []u8, body: []u8, sink: Sink, tag: u64, timeout_ms: ?u64 };

    /// Starts connecting in the background.
    pub fn open(gpa: Allocator, io: Io, ep: Endpoint) !*Conn {
        const c = try gpa.create(Conn);
        errdefer gpa.destroy(c);
        const host = try gpa.dupe(u8, ep.host);
        errdefer gpa.free(host);
        var e = ep;
        e.host = host;
        const authority = try std.fmt.allocPrint(gpa, "{s}:{d}", .{ host, ep.port });
        const now = monotonic(io);
        c.* = .{ .gpa = gpa, .io = io, .ep = e, .authority = authority, .opened_at = now, .ping_at = now };
        c.thread = std.Thread.spawn(.{ .stack_size = thread_stack }, run, .{c}) catch |err| {
            gpa.free(authority);
            gpa.free(host);
            return err;
        };
        c.thread.?.detach();
        watchdog.register(c);
        return c;
    }

    /// Takes a reference for a caller that keeps the pointer (drop it with `unref`).
    pub fn retain(c: *Conn) void {
        _ = c.refs.fetchAdd(1, .acq_rel);
    }

    /// Drops the owner's reference: the connection closes and is freed once its reader exits.
    pub fn release(c: *Conn) void {
        c.shutting_down.store(true, .release);
        c.mu.lockUncancelable(c.io);
        if (c.stream) |s| s.shutdown(c.io, .both) catch {};
        c.mu.unlock(c.io);
        c.unref();
    }

    /// Drops a reference taken with `retain` (or the owner's after `release` set the shutdown).
    pub fn unref(c: *Conn) void {
        if (c.refs.fetchSub(1, .acq_rel) != 1) return;
        const gpa = c.gpa;
        var it = c.calls.valueIterator();
        while (it.next()) |call| freeCall(gpa, call.*);
        c.calls.deinit(gpa);
        for (c.queued.items) |q| {
            gpa.free(q.path);
            gpa.free(q.body);
        }
        c.queued.deinit(gpa);
        gpa.free(c.authority);
        gpa.free(c.ep.host);
        gpa.destroy(c);
    }

    pub fn isDead(c: *Conn) bool {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        return c.state == .dead;
    }

    /// Starts a unary call. `id_slot` receives the stream id (0 while queued), which `cancel`
    /// takes. Never blocks on the network beyond a socket write.
    pub fn start(c: *Conn, id_slot: *u32, path: []const u8, body: []const u8, sink: Sink, tag: u64, timeout_ms: ?u64) void {
        id_slot.* = 0;
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        switch (c.state) {
            .dead => {
                sink.done(sink.ctx, tag, .{ .status = .{ .code = 14, .message = c.dead_reason } });
            },
            .connecting => {
                const p = c.gpa.dupe(u8, path) catch return oom(sink, tag);
                const b = c.gpa.dupe(u8, body) catch {
                    c.gpa.free(p);
                    return oom(sink, tag);
                };
                c.queued.append(c.gpa, .{ .id_slot = id_slot, .path = p, .body = b, .sink = sink, .tag = tag, .timeout_ms = timeout_ms }) catch {
                    c.gpa.free(p);
                    c.gpa.free(b);
                    return oom(sink, tag);
                };
            },
            .ready => c.startLocked(id_slot, path, body, sink, tag, timeout_ms),
        }
    }

    /// Forgets a call: no delivery after this returns. Sends RST_STREAM(CANCEL) when it is open.
    pub fn cancel(c: *Conn, id_slot: *u32, tag: u64) void {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        if (id_slot.* == 0) {
            var i: usize = 0;
            while (i < c.queued.items.len) {
                const q = c.queued.items[i];
                if (q.id_slot == id_slot and q.tag == tag) {
                    c.gpa.free(q.path);
                    c.gpa.free(q.body);
                    _ = c.queued.orderedRemove(i);
                } else i += 1;
            }
            return;
        }
        if (c.calls.fetchRemove(id_slot.*)) |kv| {
            freeCall(c.gpa, kv.value);
            if (c.state == .ready) {
                var rst: [4]u8 = undefined;
                std.mem.writeInt(u32, &rst, 8, .big);
                c.writeFrame(frame_rst, 0, id_slot.*, &rst) catch {};
                c.flush();
            }
        }
    }

    fn oom(sink: Sink, tag: u64) void {
        sink.done(sink.ctx, tag, .{ .status = .{ .code = 8, .message = "out of memory" } });
    }

    fn startLocked(c: *Conn, id_slot: *u32, path: []const u8, body: []const u8, sink: Sink, tag: u64, timeout_ms: ?u64) void {
        const id = c.next_stream;
        c.next_stream += 2;
        const call = c.gpa.create(Call) catch return oom(sink, tag);
        const out = c.gpa.alloc(u8, body.len + 5) catch {
            c.gpa.destroy(call);
            return oom(sink, tag);
        };
        out[0] = 0;
        std.mem.writeInt(u32, out[1..5], @intCast(body.len), .big);
        @memcpy(out[5..], body);
        call.* = .{ .sink = sink, .tag = tag, .out = out, .send_window = c.peer_initial_window };
        c.calls.put(c.gpa, id, call) catch {
            freeCall(c.gpa, call);
            return oom(sink, tag);
        };
        id_slot.* = id;
        var hb: std.ArrayList(u8) = .empty;
        defer hb.deinit(c.gpa);
        const scheme = if (c.ep.security == .plain) "http" else "https";
        var tbuf: [32]u8 = undefined;
        const hdrs = [_][2][]const u8{
            .{ ":method", "POST" },
            .{ ":scheme", scheme },
            .{ ":path", path },
            .{ ":authority", c.authority },
            .{ "content-type", "application/grpc" },
            .{ "te", "trailers" },
            .{ "user-agent", "zui/execute" },
        };
        for (hdrs) |h| hpack.encodeLiteral(&hb, c.gpa, h[0], h[1]) catch return c.failCallLocked(id, "out of memory");
        if (timeout_ms) |t| {
            const v = std.fmt.bufPrint(&tbuf, "{d}m", .{t}) catch unreachable;
            hpack.encodeLiteral(&hb, c.gpa, "grpc-timeout", v) catch return c.failCallLocked(id, "out of memory");
        }
        c.writeHeaderBlock(id, hb.items) catch return c.dieLocked("write failed");
        c.pumpLocked(id, call) catch return c.dieLocked("write failed");
        c.flush();
    }

    fn writeHeaderBlock(c: *Conn, id: u32, block: []const u8) !void {
        var rest = block;
        var first = true;
        while (true) {
            const n = @min(rest.len, c.peer_max_frame);
            const last = n == rest.len;
            try c.writeFrame(if (first) frame_headers else frame_continuation, if (last) flag_end_headers else 0, id, rest[0..n]);
            rest = rest[n..];
            first = false;
            if (last) return;
        }
    }

    /// Sends as much of a call's request as the windows allow.
    fn pumpLocked(c: *Conn, id: u32, call: *Call) !void {
        while (!call.end_sent) {
            const left = call.out.len - call.out_pos;
            const win = @min(call.send_window, c.conn_send_window);
            if (left > 0 and win <= 0) return;
            const n: usize = @intCast(@min(@as(i64, @intCast(left)), @min(win, c.peer_max_frame)));
            const end = n == left;
            try c.writeFrame(frame_data, if (end) flag_end_stream else 0, id, call.out[call.out_pos..][0..n]);
            call.out_pos += n;
            call.send_window -= @intCast(n);
            c.conn_send_window -= @intCast(n);
            if (end) call.end_sent = true;
        }
    }

    fn writeFrame(c: *Conn, kind: u8, flags: u8, id: u32, payload: []const u8) !void {
        const w = c.writer orelse return error.WriteFailed;
        if (trace_frames) log.debug("{s} send kind {d} flags {x} stream {d} len {d}", .{ c.ep.host, kind, flags, id, payload.len });
        var h: [9]u8 = undefined;
        std.mem.writeInt(u24, h[0..3], @intCast(payload.len), .big);
        h[3] = kind;
        h[4] = flags;
        std.mem.writeInt(u32, h[5..9], id & 0x7fff_ffff, .big);
        try w.writeAll(&h);
        try w.writeAll(payload);
    }

    fn flush(c: *Conn) void {
        c.flushOut() catch c.dieLocked("write failed");
    }

    /// Flushes the h2 writer and, under TLS, the socket writer below it.
    fn flushOut(c: *Conn) !void {
        const w = c.writer orelse return error.WriteFailed;
        try w.flush();
        if (c.sock_writer) |sw| try sw.flush();
    }

    fn failCallLocked(c: *Conn, id: u32, msg: []const u8) void {
        if (c.calls.fetchRemove(id)) |kv| {
            kv.value.sink.done(kv.value.sink.ctx, kv.value.tag, .{ .status = .{ .code = 13, .message = msg } });
            freeCall(c.gpa, kv.value);
        }
    }

    /// Ends every call with UNAVAILABLE (tonic's transport error) and marks the connection dead.
    fn dieLocked(c: *Conn, reason: []const u8) void {
        if (c.state == .dead) return;
        c.state = .dead;
        c.dead_reason = reason;
        c.died_at = @intCast(Io.Clock.awake.now(c.io).nanoseconds);
        c.writer = null;
        c.sock_writer = null;
        var it = c.calls.iterator();
        while (it.next()) |kv| {
            kv.value_ptr.*.sink.done(kv.value_ptr.*.sink.ctx, kv.value_ptr.*.tag, .{ .status = .{ .code = 14, .message = reason } });
            freeCall(c.gpa, kv.value_ptr.*);
        }
        c.calls.clearRetainingCapacity();
        for (c.queued.items) |q| {
            q.sink.done(q.sink.ctx, q.tag, .{ .status = .{ .code = 14, .message = reason } });
            c.gpa.free(q.path);
            c.gpa.free(q.body);
        }
        c.queued.clearRetainingCapacity();
        if (c.stream) |s| s.shutdown(c.io, .both) catch {};
    }

    fn die(c: *Conn, reason: []const u8) void {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        c.dieLocked(reason);
    }

    // --------------------------------------------------------------------------------------
    // reader thread

    fn reasonOf(e: anyerror) []const u8 {
        return switch (e) {
            error.ConnectFailed => "transport error: connect failed",
            error.TlsFailed => "transport error: tls handshake failed",
            error.GoAway => "transport error: connection closed by peer (GOAWAY)",
            error.EndOfStream => "transport error: connection closed",
            error.Protocol => "transport error: h2 protocol error",
            error.HeaderBlockTooLarge => "transport error: header block too large",
            error.FrameTooLarge => "transport error: frame too large",
            else => "transport error: connection failed",
        };
    }

    /// The reader's transport is going away: no writer after this, and the connection is dead.
    fn detachTransport(c: *Conn, reason: []const u8) void {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        c.writer = null;
        c.sock_writer = null;
        c.dieLocked(reason);
    }

    /// The reader's transport state, on the heap so it outlives `runInner`'s frame until the
    /// connection no longer points at it.
    const Transport = struct {
        bufs: []u8 = &.{},
        sr: Io.net.Stream.Reader = undefined,
        sw: Io.net.Stream.Writer = undefined,
        tls: tls_client = undefined,
        bundle: std.crypto.Certificate.Bundle = .empty,
        bundle_lock: Io.RwLock = .init,
    };

    fn run(c: *Conn) void {
        defer c.unref();
        if (c.gpa.create(Transport)) |t| {
            t.* = .{};
            // the reader only ever leaves with an error; the writers are gone after this
            c.runInner(t) catch |e| c.detachTransport(reasonOf(e));
            t.bundle.deinit(c.gpa);
            c.gpa.free(t.bufs);
            c.gpa.destroy(t);
        } else |_| c.detachTransport("transport error: out of memory");
        c.mu.lockUncancelable(c.io);
        if (c.stream) |s| {
            s.close(c.io);
            c.stream = null;
        }
        c.reader_done = true;
        c.mu.unlock(c.io);
    }

    fn runInner(c: *Conn, t: *Transport) !void {
        const io = c.io;
        const gpa = c.gpa;
        const host = Io.net.HostName.init(c.ep.host) catch return error.ConnectFailed;
        const stream = host.connect(io, c.ep.port, .{ .mode = .stream }) catch return error.ConnectFailed;
        {
            c.mu.lockUncancelable(io);
            defer c.mu.unlock(io);
            c.stream = stream;
            // released, or ended by the watchdog's connect deadline while connect was blocked
            if (c.shutting_down.load(.acquire) or c.state == .dead) return error.EndOfStream;
        }

        // The transport (`bufs`, `sw`, `tls`) lives in `t`, owned by `run`, which detaches it from
        // the connection under the lock before freeing it: a thread in `start`/`cancel` never
        // writes through a dangling writer.
        t.bufs = try gpa.alloc(u8, 4 * tls_client.min_buffer_len + 64 * 1024);
        const bufs = t.bufs;
        const sock_r = bufs[0..tls_client.min_buffer_len];
        const sock_w = bufs[tls_client.min_buffer_len..][0..tls_client.min_buffer_len];
        const tls_r = bufs[2 * tls_client.min_buffer_len ..][0 .. tls_client.min_buffer_len + 32 * 1024];
        const tls_w = bufs[3 * tls_client.min_buffer_len + 32 * 1024 ..][0 .. tls_client.min_buffer_len];
        t.sr = stream.reader(io, sock_r);
        t.sw = stream.writer(io, sock_w);
        const sr = &t.sr;
        const sw = &t.sw;
        const tls = &t.tls;
        const bundle = &t.bundle;
        var reader: *Io.Reader = &sr.interface;
        var writer: *Io.Writer = &sw.interface;
        if (c.ep.security != .plain) {
            var entropy: [tls_client.Options.entropy_len]u8 = undefined;
            io.random(&entropy);
            const now = Io.Clock.real.now(io);
            if (c.ep.security == .ca) bundle.rescan(gpa, io, now) catch return error.TlsFailed;
            tls.* = tls_client.init(&sr.interface, &sw.interface, .{
                .host = .{ .explicit = if (c.ep.security == .ca) c.ep.host else c.ep.server_name },
                .ca = switch (c.ep.security) {
                    .ca => .{ .bundle = .{ .gpa = gpa, .io = io, .lock = &t.bundle_lock, .bundle = bundle } },
                    else => .no_verification,
                },
                .pin_ed25519 = switch (c.ep.security) {
                    .pinned => |k| k,
                    else => null,
                },
                .read_buffer = tls_r,
                .write_buffer = tls_w,
                .entropy = &entropy,
                .realtime_now = now,
                .allow_truncation_attacks = true,
            }) catch |e| {
                log.debug("tls {s}:{d}: {s}", .{ c.ep.host, c.ep.port, @errorName(e) });
                return error.TlsFailed;
            };
            reader = &tls.reader;
            writer = &tls.writer;
        }

        // preface, SETTINGS (no push, big windows), connection window
        {
            c.mu.lockUncancelable(io);
            defer c.mu.unlock(io);
            c.writer = writer;
            c.sock_writer = if (c.ep.security != .plain) &sw.interface else null;
            try writer.writeAll(serve.h2.conn.preface);
            var s: [18]u8 = undefined;
            std.mem.writeInt(u16, s[0..2], 2, .big); // ENABLE_PUSH
            std.mem.writeInt(u32, s[2..6], 0, .big);
            std.mem.writeInt(u16, s[6..8], 4, .big); // INITIAL_WINDOW_SIZE
            std.mem.writeInt(u32, s[8..12], recv_window, .big);
            std.mem.writeInt(u16, s[12..14], 5, .big); // MAX_FRAME_SIZE
            std.mem.writeInt(u32, s[14..18], max_frame_in, .big);
            try c.writeFrame(frame_settings, 0, 0, &s);
            var wu: [4]u8 = undefined;
            std.mem.writeInt(u32, &wu, recv_window - 65_535, .big);
            try c.writeFrame(frame_window, 0, 0, &wu);
            try c.flushOut();
            c.state = .ready;
            c.was_ready = true;
            for (c.queued.items) |q| {
                c.startLocked(q.id_slot, q.path, q.body, q.sink, q.tag, q.timeout_ms);
                gpa.free(q.path);
                gpa.free(q.body);
                if (c.state == .dead) break;
            }
            c.queued.clearRetainingCapacity();
        }

        var dec = hpack.Decoder.init(gpa);
        defer dec.deinit();
        var hblock: std.ArrayList(u8) = .empty;
        defer hblock.deinit(gpa);
        var hstream: u32 = 0;
        var hend_stream = false;
        var conn_recv_used: u64 = 0;
        const payload = try gpa.alloc(u8, max_frame_in);
        defer gpa.free(payload);
        while (true) {
            var h: [9]u8 = undefined;
            reader.readSliceAll(&h) catch return error.EndOfStream;
            const len = std.mem.readInt(u24, h[0..3], .big);
            const kind = h[3];
            const flags = h[4];
            const id = std.mem.readInt(u32, h[5..9], .big) & 0x7fff_ffff;
            if (len > max_frame_in) return error.FrameTooLarge;
            const p = payload[0..len];
            reader.readSliceAll(p) catch return error.EndOfStream;
            if (trace_frames) log.debug("{s} frame kind {d} flags {x} stream {d} len {d}", .{ c.ep.host, kind, flags, id, len });
            c.mu.lockUncancelable(io);
            defer c.mu.unlock(io);
            if (c.state == .dead) return error.EndOfStream;
            switch (kind) {
                frame_settings => {
                    if (id != 0) return error.Protocol;
                    if (flags & flag_ack != 0) continue;
                    if (p.len % 6 != 0) return error.Protocol;
                    var i: usize = 0;
                    while (i + 6 <= p.len) : (i += 6) {
                        const key = std.mem.readInt(u16, p[i..][0..2], .big);
                        const val = std.mem.readInt(u32, p[i + 2 ..][0..4], .big);
                        if (!settingValid(key, val)) return error.Protocol;
                        switch (key) {
                            4 => {
                                const delta = @as(i64, val) - c.peer_initial_window;
                                c.peer_initial_window = val;
                                var it = c.calls.valueIterator();
                                while (it.next()) |call| call.*.send_window += delta;
                            },
                            5 => c.peer_max_frame = val,
                            else => {},
                        }
                    }
                    try c.writeFrame(frame_settings, flag_ack, 0, &.{});
                    try c.pumpAllLocked();
                    try c.flushOut();
                },
                frame_ping => {
                    if (flags & flag_ack != 0) {
                        c.ping_due = false;
                    } else if (p.len == 8) {
                        try c.writeFrame(frame_ping, flag_ack, 0, p);
                        try c.flushOut();
                    }
                },
                frame_window => {
                    if (p.len != 4) return error.Protocol;
                    const inc = std.mem.readInt(u32, p[0..4], .big) & 0x7fff_ffff;
                    if (id == 0) c.conn_send_window += inc else if (c.calls.get(id)) |call| call.send_window += inc;
                    try c.pumpAllLocked();
                    try c.flushOut();
                },
                frame_goaway => return error.GoAway,
                frame_rst => {
                    if (c.calls.fetchRemove(id)) |kv| {
                        const code = if (p.len >= 4) std.mem.readInt(u32, p[0..4], .big) else 0;
                        const msg = if (code == 7) "h2 protocol error: stream refused" else "h2 protocol error: stream reset";
                        kv.value.sink.done(kv.value.sink.ctx, kv.value.tag, .{ .status = .{ .code = if (code == 7) 14 else 13, .message = msg } });
                        freeCall(gpa, kv.value);
                    }
                },
                frame_headers, frame_continuation => {
                    var body = p;
                    if (kind == frame_headers) {
                        hblock.clearRetainingCapacity();
                        hstream = id;
                        hend_stream = flags & flag_end_stream != 0;
                        if (flags & flag_padded != 0) {
                            if (body.len < 1) return error.Protocol;
                            const pad = body[0];
                            body = body[1..];
                            if (pad > body.len) return error.Protocol;
                            body = body[0 .. body.len - pad];
                        }
                        if (flags & flag_priority != 0) {
                            if (body.len < 5) return error.Protocol;
                            body = body[5..];
                        }
                    } else if (id != hstream) return error.Protocol;
                    if (hblock.items.len + body.len > max_header_block) return error.HeaderBlockTooLarge;
                    try hblock.appendSlice(gpa, body);
                    if (flags & flag_end_headers == 0) continue;
                    var arena_state = std.heap.ArenaAllocator.init(gpa);
                    defer arena_state.deinit();
                    const call = c.calls.get(hstream);
                    const Ctx = struct {
                        call: ?*Call,
                        gpa: Allocator,
                        fn sink(ctx: @This(), name: []const u8, value: []const u8) hpack.Error!void {
                            const cl = ctx.call orelse return;
                            if (std.mem.eql(u8, name, ":status")) {
                                cl.http_status = std.fmt.parseInt(u16, value, 10) catch 0;
                            } else if (std.mem.eql(u8, name, "grpc-status")) {
                                cl.grpc_status = std.fmt.parseInt(u8, value, 10) catch 2;
                            } else if (std.mem.eql(u8, name, "grpc-message")) {
                                ctx.gpa.free(cl.grpc_message);
                                cl.grpc_message = percentDecode(ctx.gpa, value) catch return error.OutOfMemory;
                            } else if (std.mem.eql(u8, name, "grpc-status-details-bin")) {
                                ctx.gpa.free(cl.grpc_details);
                                cl.grpc_details = base64Decode(ctx.gpa, value) catch return error.OutOfMemory;
                            }
                        }
                    };
                    dec.decode(arena_state.allocator(), hblock.items, Ctx{ .call = call, .gpa = gpa }, Ctx.sink) catch return error.Protocol;
                    if (hend_stream) c.finishLocked(hstream);
                },
                frame_data => {
                    var body = p;
                    if (flags & flag_padded != 0) {
                        if (body.len < 1) return error.Protocol;
                        const pad = body[0];
                        body = body[1..];
                        if (pad > body.len) return error.Protocol;
                        body = body[0 .. body.len - pad];
                    }
                    var overflow = false;
                    if (c.calls.get(id)) |call| {
                        if (call.data.items.len + body.len > max_response_bytes) {
                            overflow = true;
                        } else try call.data.appendSlice(gpa, body);
                    }
                    if (overflow) {
                        // the call fails alone (RESOURCE_EXHAUSTED, as tonic's decode limit) and its
                        // stream is reset; the connection keeps serving the others
                        if (c.calls.fetchRemove(id)) |kv| {
                            kv.value.sink.done(kv.value.sink.ctx, kv.value.tag, .{ .status = .{ .code = 8, .message = "response message too large" } });
                            freeCall(gpa, kv.value);
                        }
                        var rst: [4]u8 = undefined;
                        std.mem.writeInt(u32, &rst, 8, .big);
                        try c.writeFrame(frame_rst, 0, id, &rst);
                    }
                    // replenish windows (per stream and connection) once half is used
                    conn_recv_used += len;
                    if (len > 0) {
                        if (flags & flag_end_stream == 0 and c.calls.contains(id)) {
                            var wu: [4]u8 = undefined;
                            std.mem.writeInt(u32, &wu, len, .big);
                            try c.writeFrame(frame_window, 0, id, &wu);
                        }
                        if (conn_recv_used >= recv_window / 2) {
                            var wu: [4]u8 = undefined;
                            std.mem.writeInt(u32, &wu, @intCast(conn_recv_used), .big);
                            try c.writeFrame(frame_window, 0, 0, &wu);
                            conn_recv_used = 0;
                        }
                        try c.flushOut();
                    }
                    if (flags & flag_end_stream != 0) c.finishLocked(id);
                },
                else => {},
            }
        }
    }

    fn pumpAllLocked(c: *Conn) !void {
        var it = c.calls.iterator();
        while (it.next()) |kv| try c.pumpLocked(kv.key_ptr.*, kv.value_ptr.*);
    }

    /// The stream ended: deliver the message or the status.
    fn finishLocked(c: *Conn, id: u32) void {
        const kv = c.calls.fetchRemove(id) orelse return;
        const call = kv.value;
        defer freeCall(c.gpa, call);
        const sink = call.sink;
        const st: u8 = call.grpc_status orelse blk: {
            // tonic: no grpc-status -> from the HTTP status
            const hs = call.http_status orelse 0;
            break :blk switch (hs) {
                400 => 13,
                401 => 16,
                403 => 7,
                404 => 12,
                429, 502, 503, 504 => 14,
                else => 2,
            };
        };
        if (st != 0) return sink.done(sink.ctx, call.tag, .{ .status = .{ .code = st, .message = call.grpc_message, .details = call.grpc_details } });
        sink.done(sink.ctx, call.tag, decodeUnary(call.data.items));
    }

    /// One keepalive / deadline check (the watchdog, under no lock). True when the connection is
    /// finished (dead and its reader gone): the registry then drops it.
    fn tick(c: *Conn, now: u64) bool {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        switch (c.state) {
            .dead => return c.reader_done,
            .connecting => if (now -| c.opened_at >= connect_timeout_ns) c.dieLocked("transport error: connect timeout"),
            .ready => {
                if (c.ping_due) {
                    if (now -| c.ping_at >= keepalive_timeout_ns) c.dieLocked("transport error: keepalive timeout");
                    return false;
                }
                const every = if (c.calls.count() > 0) keepalive_busy_ns else keepalive_idle_ns;
                if (now -| c.ping_at < every) return false;
                var payload: [8]u8 = undefined;
                std.mem.writeInt(u64, &payload, now, .big);
                c.writeFrame(frame_ping, 0, 0, &payload) catch return c.dieAndFalse("write failed");
                c.flushOut() catch return c.dieAndFalse("write failed");
                c.ping_at = now;
                c.ping_due = true;
            },
        }
        return false;
    }

    fn dieAndFalse(c: *Conn, reason: []const u8) bool {
        c.dieLocked(reason);
        return false;
    }
};

/// RFC 9113 6.5.2: values a peer may not send (a PROTOCOL_ERROR / FLOW_CONTROL_ERROR that ends
/// the connection). A MAX_FRAME_SIZE of 0 used to make every write loop forever.
pub fn settingValid(key: u16, val: u32) bool {
    return switch (key) {
        2 => val <= 1, // ENABLE_PUSH
        4 => val <= 0x7fff_ffff, // INITIAL_WINDOW_SIZE
        5 => val >= 16_384 and val <= 16_777_215, // MAX_FRAME_SIZE
        else => true,
    };
}

/// A finished unary call's DATA: exactly one uncompressed gRPC message (tonic: a second message,
/// or bytes after the first, is a protocol error for a unary call).
pub fn decodeUnary(d: []const u8) Result {
    if (d.len < 5) return .{ .status = .{ .code = 13, .message = "protocol error: missing response message" } };
    if (d[0] != 0) return .{ .status = .{ .code = 13, .message = "protocol error: compressed response" } };
    const n = std.mem.readInt(u32, d[1..5], .big);
    // compared in usize: `5 + n` in u32 wraps for n > 0xFFFFFFFA
    if (d.len - 5 < n) return .{ .status = .{ .code = 13, .message = "protocol error: truncated response message" } };
    if (d.len - 5 > n) return .{ .status = .{ .code = 13, .message = "protocol error: trailing bytes after the response message" } };
    return .{ .ok = d[5..][0..n] };
}

fn monotonic(io: Io) u64 {
    return @intCast(Io.Clock.awake.now(io).nanoseconds);
}

/// The process-wide keepalive / connect-deadline thread and its registry (each registered
/// connection holds one reference for it).
pub const watchdog = struct {
    var mu: Io.Mutex = .init;
    var conns: std.ArrayListUnmanaged(*Conn) = .empty;
    var started = false;
    var io_: Io = undefined;
    pub var period_ns: u64 = std.time.ns_per_s;

    fn register(c: *Conn) void {
        mu.lockUncancelable(c.io);
        defer mu.unlock(c.io);
        if (!started) {
            io_ = c.io;
            if (std.Thread.spawn(.{ .stack_size = thread_stack }, loop, .{})) |t| {
                t.detach();
                started = true;
            } else |_| {}
        }
        conns.append(std.heap.page_allocator, c) catch {
            c.unref(); // no registry slot: drop its reference now (no keepalive for this one)
        };
    }

    fn loop() void {
        while (true) {
            Io.sleep(io_, .fromNanoseconds(@intCast(period_ns)), .awake) catch {};
            sweep(io_, monotonic(io_));
        }
    }

    /// One pass: tick every connection, drop the finished ones.
    pub fn sweep(io: Io, now: u64) void {
        var gone: std.ArrayListUnmanaged(*Conn) = .empty;
        defer gone.deinit(std.heap.page_allocator);
        {
            mu.lockUncancelable(io);
            defer mu.unlock(io);
            var i: usize = 0;
            while (i < conns.items.len) {
                const c = conns.items[i];
                if (c.tick(now)) {
                    _ = conns.swapRemove(i);
                    gone.append(std.heap.page_allocator, c) catch c.unref();
                } else i += 1;
            }
        }
        for (gone.items) |c| c.unref();
    }

    pub fn count(io: Io) usize {
        mu.lockUncancelable(io);
        defer mu.unlock(io);
        return conns.items.len;
    }
};

fn freeCall(gpa: Allocator, call: *Call) void {
    call.data.deinit(gpa);
    gpa.free(call.out);
    gpa.free(call.grpc_message);
    gpa.free(call.grpc_details);
    gpa.destroy(call);
}

fn percentDecode(gpa: Allocator, s: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 2 < s.len) {
            if (std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16)) |b| {
                try out.append(gpa, b);
                i += 2;
                continue;
            } else |_| {}
        }
        try out.append(gpa, s[i]);
    }
    return out.toOwnedSlice(gpa);
}

fn base64Decode(gpa: Allocator, s: []const u8) ![]u8 {
    const dec = std.base64.standard_no_pad.Decoder;
    const trimmed = std.mem.trimEnd(u8, s, "=");
    const n = dec.calcSizeForSlice(trimmed) catch return gpa.dupe(u8, "");
    const out = try gpa.alloc(u8, n);
    dec.decode(out, trimmed) catch {
        gpa.free(out);
        return gpa.dupe(u8, "");
    };
    return out;
}

// ------------------------------------------------------------------------------------------
// blocking unary helper (tools: upstream fullnode reads)

/// One call, waited for. The reply is allocated with `arena`.
pub fn callBlocking(arena: Allocator, c: *Conn, path: []const u8, body: []const u8, timeout_ms: u64) !Result {
    const W = struct {
        io: Io,
        mu: Io.Mutex = .init,
        cond: Io.Condition = .init,
        done_flag: bool = false,
        arena: Allocator,
        result: Result = .{ .status = .{ .code = 4 } },
        fn done(ctx: *anyopaque, _: u64, r: Result) void {
            const w: *@This() = @ptrCast(@alignCast(ctx));
            w.mu.lockUncancelable(w.io);
            defer w.mu.unlock(w.io);
            w.result = switch (r) {
                .ok => |b| .{ .ok = w.arena.dupe(u8, b) catch "" },
                .status => |s| .{ .status = .{
                    .code = s.code,
                    .message = w.arena.dupe(u8, s.message) catch "",
                    .details = w.arena.dupe(u8, s.details) catch "",
                } },
            };
            w.done_flag = true;
            w.cond.broadcast(w.io);
        }
    };
    var w: W = .{ .io = c.io, .arena = arena };
    var slot: u32 = 0;
    c.start(&slot, path, body, .{ .ctx = &w, .done = W.done }, 0, timeout_ms);
    const deadline = Io.Clock.Timestamp.fromNow(c.io, .{ .raw = .fromMilliseconds(@intCast(timeout_ms)), .clock = .awake });
    w.mu.lockUncancelable(c.io);
    while (!w.done_flag) {
        w.cond.waitTimeout(c.io, &w.mu, .{ .deadline = deadline }) catch {
            if (w.done_flag) break;
            w.mu.unlock(c.io);
            c.cancel(&slot, 0);
            w.mu.lockUncancelable(c.io);
            if (!w.done_flag) {
                w.done_flag = true;
                w.result = .{ .status = .{ .code = 4, .message = "deadline exceeded" } };
            }
        };
    }
    w.mu.unlock(c.io);
    return w.result;
}
