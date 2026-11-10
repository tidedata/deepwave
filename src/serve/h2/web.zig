//! HTTP/1.1 server connection with gRPC-web (binary and text), `GET /health` and CORS, shaped
//! like sui-node 1.83.1 on :9000 (hyper 1 + tonic-web 0.14 + tower-http CORS; captures in
//! `vectors/h1-*`):
//! - keep-alive; an idle connection closes 30 s after its last response (hyper header_read_timeout);
//! - grpc-web responses are chunked, one chunk per frame, chunk sizes in upper-case hex; the
//!   trailers frame is `0x80 len "grpc-status:0\r\n"`; a reply with no message is trailers-only
//!   (status in the HTTP headers, `content-length: 0`);
//! - gRPC-web is the four tonic-web content types, matched exactly; text output is chosen by
//!   `accept` equal to a text type (not by the request type): each frame is base64 (padded) in
//!   its own chunk, type `application/grpc-web-text+proto`;
//! - a gRPC-web type with another method than POST answers 405; `application/grpc` over
//!   HTTP/1.1, or GET on a gRPC path, 400; a path outside every service 404; any OPTIONS the
//!   permissive CORS preflight; `/health` GET and HEAD (405 with `allow` otherwise);
//! - hyper's connection framing (`Framing`): `connection: close` / `keep-alive`, HTTP/1.0
//!   status lines and close-delimited bodies;
//! - chunked request bodies are bounded (size line, trailers, total).
//! Server streams (`pump.attach` + `Status.deferred`) run their pump on this connection's thread:
//! headers go out at once, then every message as its own chunk, then the trailers frame.
const std = @import("std");
const Allocator = std.mem.Allocator;
const conn = @import("conn.zig");
const codec = @import("codec.zig");
const meta = @import("meta.zig");
const sock = @import("sock.zig");
const pump = @import("pump.zig");
const obs = @import("obs.zig");
const Status = conn.Status;
const Handler = conn.Handler;

pub const Options = struct {
    max_request_bytes: usize = 4 << 20,
    /// hyper http1 header_read_timeout (sui-http default 30 s).
    idle_ns: u64 = 30 * std.time.ns_per_s,
    default_timeout_ns: ?u64 = 60 * std.time.ns_per_s,
    max_head: usize = 64 << 10,
    max_body: usize = 24 << 20,
};

pub const Control = struct {
    stop: *const std.atomic.Value(bool),
    /// Monotonic time after which the connection closes after its current response (max age).
    close_after_ns: ?u64 = null,
};

const Req = struct {
    method: []const u8,
    path: []const u8,
    /// The request line says HTTP/1.0 (the reply's status line follows it, as hyper's does).
    http10: bool,
    close: bool = false,
    keepalive: bool = false,
    content_type: []const u8 = "",
    accept: []const u8 = "",
    content_length: ?usize = null,
    chunked: bool = false,
    expect_continue: bool = false,
    grpc_accept: codec.Encoding = .identity,
    grpc_encoding: []const u8 = "",
    timeout_ns: ?u64 = null,
    client_protocol_version: ?u64 = null,
};

/// How one response is framed on the connection, hyper 1.11 style (proto/h1/role.rs
/// `encode`, conn.rs `enforce_version`; vectors h1-health-close, h1-health-10,
/// h1-health-10-ka, h1-svcinfo-close, h1-svcinfo-10, h1-10-ka-svcinfo):
/// - the status line repeats the request's version;
/// - HTTP/1.1 without keep-alive: `connection: close` after the service headers, before
///   content-length / transfer-encoding and date;
/// - HTTP/1.0 with `connection: keep-alive` and a known length: `connection: keep-alive` there;
///   with a streamed body (gRPC-web) no header, and the connection closes;
/// - HTTP/1.0 bodies of unknown length are written raw and delimited by the close.
const Framing = struct {
    http10: bool,
    keep: bool,

    fn statusLine(f: Framing, out: *std.ArrayList(u8), a: Allocator, code: []const u8) !void {
        // Request metrics: a reply that is not gRPC is labelled with its HTTP status (a gRPC
        // reply set its label before writing the status line).
        if (obs.current) |t| t.status(obs.httpLabel(std.fmt.parseInt(u16, code[0..3], 10) catch 0), meta.monoNs());
        try out.appendSlice(a, if (f.http10) "HTTP/1.0 " else "HTTP/1.1 ");
        try out.appendSlice(a, code);
        try out.appendSlice(a, "\r\n");
    }
    /// For a reply with a known length.
    fn connHdr(f: Framing, out: *std.ArrayList(u8), a: Allocator) !void {
        if (!f.http10 and !f.keep) try hdr(out, a, "connection", "close");
        if (f.http10 and f.keep) try hdr(out, a, "connection", "keep-alive");
    }
    /// For a streamed (chunked or close-delimited) reply.
    fn streamed(f: Framing) Framing {
        return .{ .http10 = f.http10, .keep = f.keep and !f.http10 };
    }
};

pub fn serve(gpa: Allocator, fd: std.c.fd_t, first: []const u8, opts: Options, handler: Handler, ctl: Control) void {
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(gpa);
    in.appendSlice(gpa, first) catch return;
    while (true) {
        const keep = serveOne(gpa, fd, &in, opts, handler, ctl) catch return;
        if (!keep) return;
    }
}

fn fill(gpa: Allocator, fd: std.c.fd_t, in: *std.ArrayList(u8), deadline: u64, ctl: Control) !void {
    while (true) {
        if (ctl.stop.load(.acquire)) return error.Closed;
        const now = meta.monoNs();
        if (now >= deadline) return error.Timeout;
        const wait_ms: i32 = @intCast(@min(1000, (deadline - now) / std.time.ns_per_ms + 1));
        if (!try sock.waitReadable(fd, wait_ms)) continue;
        var buf: [16384]u8 = undefined;
        const n = try sock.read(fd, &buf);
        if (n == 0) return error.Closed;
        try in.appendSlice(gpa, buf[0..n]);
        return;
    }
}

/// Longest chunk-size line accepted, extensions included (hyper bounds it as well).
pub const max_chunk_line = 4096;

const BodyError = error{ BadChunk, TooLarge };

/// Reads a chunked request body into `out` (arena). Every framing byte sits in `in` only until
/// its chunk is consumed (`in` is compacted as it goes); a chunk-size line over
/// `max_chunk_line`, trailers over `opts.max_head` or a body over `opts.max_body` fail.
/// Returns the end of the body in `in` (the trailers' final CRLF consumed).
fn readChunked(gpa: Allocator, arena: Allocator, fd: std.c.fd_t, in: *std.ArrayList(u8), head_end: usize, opts: Options, ctl: Control, out: *std.ArrayList(u8)) !usize {
    var p = head_end; // start of the next chunk-size line
    var scan = head_end; // CRLF search resumes here
    while (true) {
        // drop consumed framing once it adds up (keeps `in` near one chunk plus one read)
        if (p - head_end >= 64 << 10) {
            const rest = in.items.len - p;
            std.mem.copyForwards(u8, in.items[head_end..][0..rest], in.items[p..]);
            in.shrinkRetainingCapacity(head_end + rest);
            scan -= p - head_end;
            p = head_end;
        }
        const line_end = while (true) {
            if (std.mem.indexOfPos(u8, in.items, scan, "\r\n")) |e| break e;
            if (in.items.len - p > max_chunk_line) return error.BadChunk;
            scan = @max(p, in.items.len -| 1);
            try fill(gpa, fd, in, meta.monoNs() + opts.idle_ns, ctl);
        };
        if (line_end - p > max_chunk_line) return error.BadChunk;
        const raw = in.items[p..line_end];
        const semi = std.mem.indexOfScalar(u8, raw, ';') orelse raw.len;
        const size_text = std.mem.trim(u8, raw[0..semi], " \t");
        if (size_text.len == 0 or size_text.len > 16) return error.BadChunk;
        const size = std.fmt.parseInt(u64, size_text, 16) catch return error.BadChunk;
        if (size > opts.max_body - out.items.len) return error.TooLarge;
        const data_start = line_end + 2;
        if (size == 0) {
            // trailers (ignored) up to the empty line, at most `max_head` bytes
            var q = data_start;
            scan = q;
            while (true) {
                if (in.items.len >= q + 2 and std.mem.eql(u8, in.items[q..][0..2], "\r\n")) return q + 2;
                if (std.mem.indexOfPos(u8, in.items, scan, "\r\n")) |e| {
                    q = e + 2;
                    scan = q;
                    continue;
                }
                if (in.items.len - data_start > opts.max_head) return error.BadChunk;
                scan = @max(q, in.items.len -| 1);
                try fill(gpa, fd, in, meta.monoNs() + opts.idle_ns, ctl);
            }
        }
        const n: usize = @intCast(size);
        while (in.items.len < data_start + n + 2) try fill(gpa, fd, in, meta.monoNs() + opts.idle_ns, ctl);
        if (!std.mem.eql(u8, in.items[data_start + n ..][0..2], "\r\n")) return error.BadChunk;
        try out.appendSlice(arena, in.items[data_start..][0..n]);
        p = data_start + n + 2;
        scan = p;
    }
}

/// One request/response. Returns whether the connection stays open.
fn serveOne(gpa: Allocator, fd: std.c.fd_t, in: *std.ArrayList(u8), opts: Options, handler: Handler, ctl: Control) !bool {
    const idle_deadline = meta.monoNs() + opts.idle_ns;
    var head_end: usize = 0;
    var scan: usize = 0;
    while (true) {
        if (std.mem.indexOfPos(u8, in.items, scan, "\r\n\r\n")) |i| {
            head_end = i + 4;
            break;
        }
        if (in.items.len > opts.max_head) {
            sock.writeAll(fd, "HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
            return false;
        }
        scan = in.items.len -| 3;
        try fill(gpa, fd, in, idle_deadline, ctl);
    }
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const t0 = meta.monoNs();
    const head = try arena.dupe(u8, in.items[0..head_end]);
    var req = parseHead(head) catch {
        sock.writeAll(fd, "HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
        return false;
    };
    // body
    var body: []const u8 = &.{};
    var consumed: usize = head_end;
    if (req.expect_continue and (req.content_length orelse 1) > 0) try sock.writeAll(fd, "HTTP/1.1 100 Continue\r\n\r\n");
    if (req.chunked) {
        var out: std.ArrayList(u8) = .empty;
        consumed = readChunked(gpa, arena, fd, in, head_end, opts, ctl, &out) catch |e| switch (e) {
            error.BadChunk => {
                sock.writeAll(fd, "HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
                return false;
            },
            error.TooLarge => {
                sock.writeAll(fd, "HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
                return false;
            },
            else => |x| return x,
        };
        body = out.items;
    } else if (req.content_length) |n| {
        if (n > opts.max_body) {
            sock.writeAll(fd, "HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
            return false;
        }
        while (in.items.len < head_end + n) try fill(gpa, fd, in, meta.monoNs() + opts.idle_ns, ctl);
        body = try arena.dupe(u8, in.items[head_end..][0..n]);
        consumed = head_end + n;
    }
    // drop the request bytes, keep anything pipelined
    const rest = in.items.len - consumed;
    std.mem.copyForwards(u8, in.items[0..rest], in.items[consumed..]);
    in.shrinkRetainingCapacity(rest);

    var keep = !req.close and (!req.http10 or req.keepalive);
    if (ctl.close_after_ns) |d| if (meta.monoNs() >= d) {
        keep = false;
    };
    if (ctl.stop.load(.acquire)) keep = false;
    const fr: Framing = .{ .http10 = req.http10, .keep = keep };
    var out: std.ArrayList(u8) = .empty;
    const eql = std.mem.eql;
    const path_only = meta.pathOnly(req.path);
    const health_route = eql(u8, path_only, "/health");
    const web_kind = codec.grpcWebKind(req.content_type);
    const known = path_only.len > 1 and handler.isKnown(path_only) and std.mem.indexOfScalarPos(u8, path_only, 1, '/') != null;
    // Request metrics (obs.zig); CORS preflights sit outside sui-node's metrics layer.
    var track: obs.Track = .{};
    if (!eql(u8, req.method, "OPTIONS")) track.begin(path_only, obs.isGrpcContentType(req.content_type), t0);
    obs.current = &track;
    defer {
        obs.current = null;
        track.end(meta.monoNs());
    }

    if (eql(u8, req.method, "OPTIONS")) {
        // tower-http CORS: any OPTIONS request is a preflight (h1-options-bare, -health, -unknown)
        var list: std.ArrayList(meta.Header) = .empty;
        try meta.preflight(&list, arena, (meta.monoNs() - t0) / std.time.ns_per_ms, health_route);
        try fr.statusLine(&out, arena, "200 OK");
        try hdrs(&out, arena, list.items);
        // axum's /health route sets content-length itself (before hyper's connection header);
        // elsewhere hyper adds it after
        if (health_route) try hdr(&out, arena, "content-length", "0");
        try fr.connHdr(&out, arena);
        if (!health_route) try hdr(&out, arena, "content-length", "0");
        try dateHdr(&out, arena);
        try out.appendSlice(arena, "\r\n");
    } else if (health_route) {
        const get = eql(u8, req.method, "GET");
        if (get or eql(u8, req.method, "HEAD")) {
            const up = if (handler.health) |f| f(handler.ctx, meta.healthThreshold(req.path)) else true;
            try fr.statusLine(&out, arena, if (up) "200 OK" else "503 Service Unavailable");
            try hdr(&out, arena, "content-type", "text/plain; charset=utf-8");
            try commonHdrs(&out, arena, arena, handler, t0);
            // axum sets content-length on its routes, ahead of hyper's connection header
            // (h1-health-close, h1-health-10-ka)
            try hdr(&out, arena, "content-length", if (up) "2" else "4");
            try fr.connHdr(&out, arena);
            try dateHdr(&out, arena);
            try out.appendSlice(arena, "\r\n");
            if (get) try out.appendSlice(arena, if (up) "up" else "down");
        } else {
            // axum's method router (h1-post-health)
            try fr.statusLine(&out, arena, "405 Method Not Allowed");
            try commonHdrs(&out, arena, arena, handler, t0);
            try hdr(&out, arena, "allow", "GET,HEAD");
            try hdr(&out, arena, "content-length", "0");
            try fr.connHdr(&out, arena);
            try dateHdr(&out, arena);
            try out.appendSlice(arena, "\r\n");
        }
    } else if (web_kind != .none and handler.isKnown(path_only)) {
        if (eql(u8, req.method, "POST")) return grpcWeb(gpa, arena, fd, &req, web_kind, path_only, body, opts, handler, t0, fr, ctl);
        // tonic-web: a gRPC-web type with another method (h1-get-grpcweb-ct, h1-put-grpcweb-ct)
        try fr.statusLine(&out, arena, "405 Method Not Allowed");
        try commonHdrs(&out, arena, arena, handler, t0);
        try fr.connHdr(&out, arena);
        try hdr(&out, arena, "content-length", "0");
        try dateHdr(&out, arena);
        try out.appendSlice(arena, "\r\n");
    } else {
        try fr.statusLine(&out, arena, if (known) "400 Bad Request" else "404 Not Found");
        try commonHdrs(&out, arena, arena, handler, t0);
        try fr.connHdr(&out, arena);
        try hdr(&out, arena, "content-length", "0");
        try dateHdr(&out, arena);
        try out.appendSlice(arena, "\r\n");
    }
    try sock.writeAll(fd, out.items);
    return keep;
}

fn hdr(out: *std.ArrayList(u8), arena: Allocator, name: []const u8, value: []const u8) !void {
    try out.appendSlice(arena, name);
    try out.appendSlice(arena, ": ");
    try out.appendSlice(arena, value);
    try out.appendSlice(arena, "\r\n");
}

fn hdrs(out: *std.ArrayList(u8), arena: Allocator, list: []const meta.Header) !void {
    for (list) |h| try hdr(out, arena, h.name, h.value);
}

fn dateHdr(out: *std.ArrayList(u8), arena: Allocator) !void {
    var d: [29]u8 = undefined;
    try hdr(out, arena, "date", meta.httpDate(&d, meta.unixS()));
}

/// Header values are built in `arena`; `out` grows with `oa`.
fn commonHdrs(out: *std.ArrayList(u8), oa: Allocator, arena: Allocator, handler: Handler, t0: u64) !void {
    var list: std.ArrayList(meta.Header) = .empty;
    var info: meta.Info = .{};
    const have = handler.getInfo(&info);
    try meta.common(&list, arena, if (have) &info else null, (meta.monoNs() - t0) / std.time.ns_per_ms);
    try hdrs(out, oa, list.items);
}

fn parseHead(head: []const u8) !Req {
    var lines = std.mem.splitSequence(u8, head[0 .. head.len - 4], "\r\n");
    const first = lines.next() orelse return error.Bad;
    var parts = std.mem.splitScalar(u8, first, ' ');
    const method = parts.next() orelse return error.Bad;
    const path = parts.next() orelse return error.Bad;
    const version = parts.next() orelse return error.Bad;
    if (!std.mem.startsWith(u8, version, "HTTP/1.")) return error.Bad;
    var r: Req = .{ .method = method, .path = path, .http10 = std.mem.eql(u8, version, "HTTP/1.0") };
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.Bad;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        const ieql = std.ascii.eqlIgnoreCase;
        if (ieql(name, "content-type")) {
            r.content_type = value;
        } else if (ieql(name, "accept")) {
            r.accept = value;
        } else if (ieql(name, "content-length")) {
            r.content_length = std.fmt.parseInt(usize, value, 10) catch return error.Bad;
        } else if (ieql(name, "transfer-encoding")) {
            r.chunked = std.ascii.findIgnoreCase(value, "chunked") != null;
        } else if (ieql(name, "connection")) {
            if (std.ascii.findIgnoreCase(value, "close") != null) r.close = true;
            if (std.ascii.findIgnoreCase(value, "keep-alive") != null) r.keepalive = true;
        } else if (ieql(name, "expect")) {
            r.expect_continue = std.ascii.eqlIgnoreCase(value, "100-continue");
        } else if (ieql(name, "grpc-accept-encoding")) {
            r.grpc_accept = codec.pickAccept(value);
        } else if (ieql(name, "grpc-encoding")) {
            r.grpc_encoding = value;
        } else if (ieql(name, "grpc-timeout")) {
            r.timeout_ns = meta.parseTimeout(value);
        } else if (ieql(name, "x-sui-client-protocol-version")) {
            r.client_protocol_version = meta.parseClientProtocolVersion(value);
        }
    }
    return r;
}

const Sink = struct {
    gpa: Allocator,
    arena: Allocator,
    fd: std.c.fd_t,
    handler: Handler,
    t0: u64,
    text: bool,
    content_type: []const u8,
    encoding: codec.Encoding,
    /// Framing of a streamed body (`Framing.streamed`): chunked on HTTP/1.1, raw and
    /// close-delimited on HTTP/1.0.
    fr: Framing,
    /// Write each message at once (server streaming); unary replies go out in one write.
    stream: bool = false,
    out: std.ArrayList(u8) = .empty,
    headers_sent: bool = false,
    closed: bool = false,
    /// The request's metrics track (pump threads write through the sink too).
    track: ?*obs.Track = null,

    fn startHeaders(s: *Sink) !void {
        if (s.track) |t| t.status(obs.grpcLabel(.ok), meta.monoNs());
        try s.fr.statusLine(&s.out, s.gpa, "200 OK");
        try hdr(&s.out, s.gpa, "content-type", s.content_type);
        if (s.encoding != .identity) try hdr(&s.out, s.gpa, "grpc-encoding", s.encoding.name());
        try commonHdrs(&s.out, s.gpa, s.arena, s.handler, s.t0);
        if (!s.fr.http10) {
            if (!s.fr.keep) try hdr(&s.out, s.gpa, "connection", "close");
            try hdr(&s.out, s.gpa, "transfer-encoding", "chunked");
        }
        try dateHdr(&s.out, s.gpa);
        try s.out.appendSlice(s.gpa, "\r\n");
        s.headers_sent = true;
    }

    /// The trailers frame (`0x80`, length, `name:value\r\n` lines) and the last chunk.
    fn trailers(s: *Sink, status: Status, text: []const u8, details: []const u8) !void {
        if (!s.headers_sent) try s.startHeaders();
        var scratch = std.heap.ArenaAllocator.init(s.gpa);
        defer scratch.deinit();
        var list: std.ArrayList(meta.Header) = .empty; // in `scratch`
        try conn.statusHeaders(&list, scratch.allocator(), status, text, details);
        var tr: std.ArrayList(u8) = .empty;
        defer tr.deinit(s.gpa);
        for (list.items) |h| {
            try tr.appendSlice(s.gpa, h.name);
            try tr.append(s.gpa, ':');
            try tr.appendSlice(s.gpa, h.value);
            try tr.appendSlice(s.gpa, "\r\n");
        }
        var th: [5]u8 = undefined;
        th[0] = 0x80;
        std.mem.writeInt(u32, th[1..5], @intCast(tr.items.len), .big);
        try s.chunk(&.{ &th, tr.items });
        if (!s.fr.http10) try s.out.appendSlice(s.gpa, "0\r\n\r\n");
    }

    fn chunk(s: *Sink, parts: []const []const u8) !void {
        if (s.track) |t| t.firstChunk(meta.monoNs());
        var n: usize = 0;
        for (parts) |p| n += p.len;
        const chunked = !s.fr.http10;
        var szb: [20]u8 = undefined;
        if (s.text) {
            const e = std.base64.standard.Encoder;
            const raw = try s.gpa.alloc(u8, n);
            defer s.gpa.free(raw);
            var o: usize = 0;
            for (parts) |p| {
                @memcpy(raw[o..][0..p.len], p);
                o += p.len;
            }
            const len = e.calcSize(n);
            if (chunked) try s.out.appendSlice(s.gpa, std.fmt.bufPrint(&szb, "{X}\r\n", .{len}) catch unreachable);
            const at = s.out.items.len;
            try s.out.resize(s.gpa, at + len);
            _ = e.encode(s.out.items[at..][0..len], raw);
        } else {
            if (chunked) try s.out.appendSlice(s.gpa, std.fmt.bufPrint(&szb, "{X}\r\n", .{n}) catch unreachable);
            for (parts) |p| try s.out.appendSlice(s.gpa, p);
        }
        if (chunked) try s.out.appendSlice(s.gpa, "\r\n");
    }

    fn flushOut(s: *Sink) !void {
        if (s.out.items.len == 0) return;
        sock.writeAll(s.fd, s.out.items) catch {
            s.closed = true;
            return error.Cancelled;
        };
        s.out.clearRetainingCapacity();
    }

    fn write(impl: *anyopaque, h: *const [5]u8, payload: []const u8) anyerror!void {
        const s: *Sink = @ptrCast(@alignCast(impl));
        if (s.closed) return error.Cancelled;
        if (!s.headers_sent) try s.startHeaders();
        try s.chunk(&.{ h, payload });
        if (s.stream) try s.flushOut();
    }
    fn cancelled(impl: *anyopaque) bool {
        const s: *Sink = @ptrCast(@alignCast(impl));
        if (s.closed) return true;
        if (s.stream and sock.peerClosed(s.fd)) s.closed = true;
        return s.closed;
    }
    const vt: conn.ResponseStream.VTable = .{ .write = write, .cancelled = cancelled };
};

/// The deferred stream of one gRPC-web response: `pump.attach` stores the pump, the runtime
/// runs it on this thread with a Link over the chunked body.
const WebStream = struct {
    sink: *Sink,
    rs: *conn.ResponseStream,
    stop: *const std.atomic.Value(bool),
    pump: ?pump.Pump = null,
    finished: bool = false,

    fn attachFn(ctx: *anyopaque, _: u32, p: pump.Pump) bool {
        const w: *WebStream = @ptrCast(@alignCast(ctx));
        if (w.pump != null) return false;
        w.pump = p;
        return true;
    }
    fn send(impl: *anyopaque, _: u32, payload: []const u8) error{Closed}!void {
        const w: *WebStream = @ptrCast(@alignCast(impl));
        if (w.finished or w.sink.closed or w.stop.load(.acquire)) return error.Closed;
        w.rs.message(payload) catch {
            w.sink.closed = true;
            return error.Closed;
        };
    }
    fn finish(impl: *anyopaque, _: u32, status: Status, text: []const u8, details: []const u8) void {
        const w: *WebStream = @ptrCast(@alignCast(impl));
        if (w.finished or w.sink.closed) return;
        w.finished = true;
        w.sink.trailers(status, text, details) catch {
            w.sink.closed = true;
            return;
        };
        w.sink.flushOut() catch {};
    }
    fn blocked(impl: *anyopaque, _: u32) ?bool {
        const w: *WebStream = @ptrCast(@alignCast(impl));
        if (w.finished or w.sink.closed or w.stop.load(.acquire)) return null;
        if (sock.peerClosed(w.sink.fd)) {
            w.sink.closed = true;
            return null;
        }
        return false;
    }
    const vt: pump.Link.VTable = .{ .send = send, .finish = finish, .blocked = blocked };
};

fn grpcWeb(gpa: Allocator, arena: Allocator, fd: std.c.fd_t, req: *const Req, kind: codec.WebKind, path: []const u8, raw_body: []const u8, opts: Options, handler: Handler, t0: u64, fr: Framing, ctl: Control) !bool {
    const text_resp = codec.textAccept(req.accept);
    const ct = if (text_resp) "application/grpc-web-text+proto" else "application/grpc-web+proto";
    const encoding: codec.Encoding = if (handler.compresses(path)) req.grpc_accept else .identity;
    var sink: Sink = .{ .gpa = gpa, .arena = arena, .fd = fd, .handler = handler, .t0 = t0, .text = text_resp, .content_type = ct, .encoding = encoding, .fr = fr.streamed(), .track = obs.current };
    defer sink.out.deinit(gpa);
    var body = raw_body;
    var decode_failed = false;
    if (kind == .text) {
        if (codec.base64DecodeChunks(arena, raw_body)) |b| body = b else |_| decode_failed = true;
    }
    if (!decode_failed and handler.isBidi(path)) return bidiWeb(&sink, arena, ct, path, body, opts, handler, req.grpc_encoding, fr);
    var status: Status = .ok;
    var text: []const u8 = "";
    var details: []const u8 = "";
    var reject = false;
    var rs: conn.ResponseStream = .{ .gpa = gpa, .impl = &sink, .vt = &Sink.vt, .encoding = encoding };
    defer rs.release();
    var ws: WebStream = .{ .sink = &sink, .rs = &rs, .stop = ctl.stop };
    if (decode_failed) {
        status = .internal;
        text = "invalid base64";
    } else {
        var scratch: [256]u8 = undefined;
        switch (conn.checkBody(body, opts.max_request_bytes, req.grpc_encoding, &scratch, handler.methodExists(path))) {
            .err => |e| {
                status = e.status;
                text = try arena.dupe(u8, e.text);
                reject = e.reject_encoding;
            },
            .ok => |payload| {
                const tmo = if (req.timeout_ns) |a| (if (opts.default_timeout_ns) |b| @min(a, b) else a) else opts.default_timeout_ns;
                const deadline: ?u64 = if (tmo) |t| t0 +| t else null;
                rs.deadline_ns = deadline;
                const r: conn.Request = .{ .path = path, .authority = "", .body = payload, .stream_id = 1, .accept = encoding, .deadline_ns = deadline, .web = true, .client_protocol_version = req.client_protocol_version };
                const prev = pump.current;
                pump.current = .{ .ctx = &ws, .attach = WebStream.attachFn };
                status = handler.call(handler.ctx, &r, &rs);
                pump.current = prev;
                text = rs.msg;
                details = rs.details_bin;
            },
        }
    }
    if (ws.pump) |p| {
        // The pump's `done` runs once: after `run`, or in its place when the stream never
        // starts (the handler failed after attaching, or the client is gone before the headers).
        defer if (p.done) |d| d(p.ctx);
        if (status == .deferred) {
            // Server stream: headers now, then each message as the pump sends it.
            sink.stream = true;
            if (!sink.headers_sent) try sink.startHeaders();
            sink.flushOut() catch return false;
            var link: pump.Link = .{ .impl = &ws, .vt = &WebStream.vt, .stream_id = 1 };
            p.run(p.ctx, &link);
            if (!ws.finished or sink.closed) return false;
            return sink.fr.keep;
        }
    } else if (status == .deferred) {
        status = .unimplemented;
        return finishUnary(&sink, arena, ct, status, "", "", false, fr);
    }
    if (status == .held) {
        // grpc.health Watch: the messages are out; the response stays open until the client
        // leaves or the server stops.
        sink.stream = true;
        if (!sink.headers_sent) try sink.startHeaders();
        sink.flushOut() catch return false;
        while (!ctl.stop.load(.acquire) and !sock.peerClosed(fd)) sock.sleepMs(250);
        return false;
    }
    return finishUnary(&sink, arena, ct, status, text, details, reject, fr);
}

/// A bidi call over gRPC-web (reflection): the whole request is here, so each message is
/// dispatched in turn after the headers. As tonic-reflection: a call that fails ends the
/// response with its status; a request message that does not decode (bad flag, over the size
/// limit, a partial frame) ends it with OK and no reply (h1-refl-bad, h1-refl-short); an
/// unsupported `grpc-encoding` is refused before the service runs (trailers-only).
fn bidiWeb(sink: *Sink, arena: Allocator, ct: []const u8, path: []const u8, body: []const u8, opts: Options, handler: Handler, grpc_encoding: []const u8, fr: Framing) !bool {
    var scratch: [256]u8 = undefined;
    if (grpc_encoding.len > 0 and !std.mem.eql(u8, grpc_encoding, "identity")) {
        const e = conn.checkBody("", opts.max_request_bytes, grpc_encoding, &scratch, false).err;
        return finishUnary(sink, arena, ct, e.status, e.text, "", e.reject_encoding, fr);
    }
    try sink.startHeaders();
    var rs: conn.ResponseStream = .{ .gpa = sink.gpa, .impl = sink, .vt = &Sink.vt, .encoding = sink.encoding };
    defer rs.release();
    var off: usize = 0;
    var status: Status = .ok;
    var text: []const u8 = "";
    var details: []const u8 = "";
    while (off < body.len) {
        const rest = body[off..];
        if (rest.len < 5) break;
        const n = std.mem.readInt(u32, rest[1..5], .big);
        if (n > opts.max_request_bytes or rest.len - 5 < n) break;
        const frame = rest[0 .. 5 + n];
        const payload = switch (conn.checkBody(frame, opts.max_request_bytes, grpc_encoding, &scratch, false)) {
            .err => break,
            .ok => |p| p,
        };
        const r: conn.Request = .{ .path = path, .authority = "", .body = payload, .stream_id = 1, .web = true };
        const st = handler.call(handler.ctx, &r, &rs);
        if (st != .ok or rs.end_stream) {
            status = if (st == .deferred or st == .held) .unimplemented else st;
            text = rs.msg;
            details = rs.details_bin;
            break;
        }
        off += frame.len;
    }
    if (sink.closed) return false;
    try sink.trailers(status, text, details);
    sink.flushOut() catch return false;
    return sink.fr.keep;
}

fn finishUnary(sink: *Sink, arena: Allocator, ct: []const u8, status: Status, text: []const u8, details: []const u8, reject: bool, fr: Framing) !bool {
    const gpa = sink.gpa;
    if (sink.closed) return false;
    if (!sink.headers_sent and status != .ok) {
        // trailers-only: the status goes in the HTTP headers, before sui-node's common headers;
        // the length is known, so the connection framing is `fr` (not the streamed one)
        var list: std.ArrayList(meta.Header) = .empty;
        try conn.trailersOnlyHeaders(&list, arena, ct, status, text, details, reject);
        if (sink.track) |t| t.status(obs.grpcLabel(status), meta.monoNs());
        try fr.statusLine(&sink.out, gpa, "200 OK");
        try hdrs(&sink.out, gpa, list.items);
        try commonHdrs(&sink.out, gpa, arena, sink.handler, sink.t0);
        try fr.connHdr(&sink.out, gpa);
        try hdr(&sink.out, gpa, "content-length", "0");
        try dateHdr(&sink.out, gpa);
        try sink.out.appendSlice(gpa, "\r\n");
        sink.flushOut() catch return false;
        return fr.keep;
    }
    try sink.trailers(status, text, details);
    sink.flushOut() catch return false;
    return sink.fr.keep;
}
