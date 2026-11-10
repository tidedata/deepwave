//! Sans-IO HTTP/2 server connection (RFC 7540, h2c prior knowledge) with gRPC framing.
//!
//! Feed received bytes with `feed`, send `pending()` and report `consumed(n)`. A request is
//! dispatched when its END_STREAM arrives, the handler writes response messages through a
//! `ResponseStream`, and the connection frames them as HEADERS, DATA (respecting both flow
//! control windows; blocked bytes wait in the stream until WINDOW_UPDATE) and trailers.
//! Server streams that outlive the handler return `Status.deferred` and are fed later with
//! `push` / `finish` (the owner calls them from its own loop, then drains `pending()`).
//! The handler runs synchronously inside `feed`; a poll-driven runtime keeps the same API.
//!
//! Response metadata follows sui-node 1.83.1 byte for byte where a client could see it (header
//! order, trailers-only shapes, tonic's request framing errors, `grpc-encoding`), see `vectors/`.
//! Server-streaming handlers return `Status.deferred` after `pump.attach` (pump.zig); the runner
//! (`server.zig`) feeds them with `push` / `finish` under the connection lock. Bidi paths
//! (`Handler.bidi`, reflection) are dispatched per request message as DATA arrives.
const std = @import("std");
const Allocator = std.mem.Allocator;
const hpack = @import("hpack.zig");
const codec = @import("codec.zig");
const meta = @import("meta.zig");
const obs = @import("obs.zig");
pub const Encoding = codec.Encoding;

pub const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const Status = enum(u8) {
    ok = 0,
    cancelled = 1,
    unknown = 2,
    invalid_argument = 3,
    deadline_exceeded = 4,
    not_found = 5,
    already_exists = 6,
    permission_denied = 7,
    resource_exhausted = 8,
    failed_precondition = 9,
    aborted = 10,
    out_of_range = 11,
    unimplemented = 12,
    internal = 13,
    unavailable = 14,
    data_loss = 15,
    unauthenticated = 16,
    /// The handler keeps the stream open; the owner feeds it with `Conn.push` and `Conn.finish`.
    deferred = 255,
    /// The handler wrote its messages and the stream stays open with nothing more to send
    /// (grpc.health Watch: the status never changes) until the client or the connection ends
    /// it. No pump and no thread hold it.
    held = 254,
};

pub const Request = struct {
    path: []const u8,
    authority: []const u8,
    /// One gRPC message payload (de-framed).
    body: []const u8,
    stream_id: u32,
    /// Response compression the transport chose from `grpc-accept-encoding` (handlers ignore it).
    accept: Encoding = .identity,
    /// Monotonic deadline (ns) for a stream's first message: `grpc-timeout` bounded by the server
    /// default. Unary handlers run to completion (sui-node's timeout only fires while a handler waits).
    deadline_ns: ?u64 = null,
    /// grpc-web over HTTP/1.1.
    web: bool = false,
    /// `x-sui-client-protocol-version` (sui-rpc-api `client_protocol_version`): SimulateTransaction
    /// offers `Validity` with allowed proposers only to clients that can decode it.
    client_protocol_version: ?u64 = null,
};

pub const ResponseStream = struct {
    gpa: Allocator,
    impl: *anyopaque,
    vt: *const VTable,
    /// Compression applied to each message (flag 1 in the frame header).
    encoding: Encoding = .identity,
    messages: u32 = 0,
    deadline_ns: ?u64 = null,
    msg: []const u8 = "",
    details_bin: []const u8 = "",
    /// Copies of `msg` / `details_bin` owned by the connection: the handler's own memory (a
    /// per-request arena) is gone by the time the trailers are written.
    msg_owned: ?[]u8 = null,
    details_owned: ?[]u8 = null,
    /// Bidi calls: end the stream after this call with the returned status (tonic-reflection
    /// ends its response stream with OK when a request message fails to decode).
    end_stream: bool = false,

    pub const VTable = struct {
        /// One framed message: the 5-byte prefix and the (possibly compressed) payload.
        write: *const fn (impl: *anyopaque, hdr: *const [5]u8, payload: []const u8) anyerror!void,
        cancelled: *const fn (impl: *anyopaque) bool,
    };

    pub fn message(rs: *ResponseStream, payload: []const u8) !void {
        var hdr: [5]u8 = undefined;
        if (rs.encoding != .identity) {
            const z = try codec.compress(rs.gpa, rs.encoding, payload);
            defer rs.gpa.free(z);
            hdr[0] = 1;
            std.mem.writeInt(u32, hdr[1..5], @intCast(z.len), .big);
            try rs.vt.write(rs.impl, &hdr, z);
        } else {
            hdr[0] = 0;
            std.mem.writeInt(u32, hdr[1..5], @intCast(payload.len), .big);
            try rs.vt.write(rs.impl, &hdr, payload);
        }
        rs.messages += 1;
    }
    /// One message already compressed with `rs.encoding` (flag 1 in the frame header; a cached
    /// response's frame, so the call does not compress again).
    pub fn messageCompressed(rs: *ResponseStream, z: []const u8) !void {
        std.debug.assert(rs.encoding != .identity);
        var hdr: [5]u8 = undefined;
        hdr[0] = 1;
        std.mem.writeInt(u32, hdr[1..5], @intCast(z.len), .big);
        try rs.vt.write(rs.impl, &hdr, z);
        rs.messages += 1;
    }
    pub fn setMessage(rs: *ResponseStream, text: []const u8) void {
        if (rs.msg_owned) |o| rs.gpa.free(o);
        rs.msg_owned = rs.gpa.dupe(u8, text) catch null;
        rs.msg = rs.msg_owned orelse "";
    }
    pub fn details(rs: *ResponseStream, bin: []const u8) void {
        if (rs.details_owned) |o| rs.gpa.free(o);
        rs.details_owned = rs.gpa.dupe(u8, bin) catch null;
        rs.details_bin = rs.details_owned orelse "";
    }
    pub fn release(rs: *ResponseStream) void {
        if (rs.msg_owned) |o| rs.gpa.free(o);
        if (rs.details_owned) |o| rs.gpa.free(o);
        rs.msg_owned = null;
        rs.details_owned = null;
    }
    pub fn cancelled(rs: *const ResponseStream) bool {
        return rs.vt.cancelled(rs.impl);
    }
    /// True once a stream's first-message deadline passed with nothing sent (the handler then
    /// returns `deadlineExceeded`).
    pub fn timedOut(rs: *const ResponseStream) bool {
        const d = rs.deadline_ns orelse return false;
        return rs.messages == 0 and meta.monoNs() >= d;
    }
    /// sui-http GrpcTimeout's reply.
    pub fn deadlineExceeded(rs: *ResponseStream) Status {
        rs.setMessage("Timeout expired");
        return .deadline_exceeded;
    }
};

pub const Handler = struct {
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque, req: *const Request, rs: *ResponseStream) Status,
    /// Bidi-streaming paths: `call` runs once per request message as it arrives, writes its
    /// replies, and returns `.ok` to keep the stream open (null: none).
    bidi: ?*const fn (ctx: *anyopaque, path: []const u8) bool = null,
    /// False answers HTTP 404, like sui-node's router for a path outside every service (null: all known).
    known: ?*const fn (ctx: *anyopaque, path: []const u8) bool = null,
    /// The method exists (tonic's generated router routes it; null: every method). An unknown
    /// method answers UNIMPLEMENTED before its body is read, so the missing-message check
    /// applies only to methods that exist.
    method: ?*const fn (ctx: *anyopaque, path: []const u8) bool = null,
    /// tonic `send_compressed` per path (null: never compress).
    compress: ?*const fn (ctx: *anyopaque, path: []const u8) bool = null,
    /// x-sui-* response metadata (null: none). Strings must outlive the response (cached by the source).
    info: ?*const fn (ctx: *anyopaque, out: *meta.Info) void = null,
    /// `GET /health[?threshold_seconds=N]`: true answers 200 "up", false 503 "down" (null: always up).
    health: ?*const fn (ctx: *anyopaque, threshold_s: ?u32) bool = null,

    pub fn isBidi(h: *const Handler, path: []const u8) bool {
        return if (h.bidi) |f| f(h.ctx, path) else false;
    }
    pub fn isKnown(h: *const Handler, path: []const u8) bool {
        return if (h.known) |f| f(h.ctx, path) else true;
    }
    pub fn methodExists(h: *const Handler, path: []const u8) bool {
        return if (h.method) |f| f(h.ctx, path) else true;
    }
    pub fn compresses(h: *const Handler, path: []const u8) bool {
        return if (h.compress) |f| f(h.ctx, path) else false;
    }
    pub fn getInfo(h: *const Handler, out: *meta.Info) bool {
        const f = h.info orelse return false;
        f(h.ctx, out);
        return true;
    }
};

/// Result of tonic's request framing checks (shared with grpc-web).
pub const BodyCheck = union(enum) {
    ok: []const u8,
    err: struct { status: Status, text: []const u8, reject_encoding: bool = false },
};

/// tonic's unary request decoding: `grpc-encoding` (no compressed requests accepted), the frame
/// prefix, the 4 MiB decode limit; the first message wins. `scratch` holds error texts.
/// `need_message`: unary and server-streaming calls (tonic `map_request_unary`) answer a body
/// with no message at all `INTERNAL: Missing request message.` (vectors h1-empty-body,
/// h2-empty-body); bidi calls take zero messages as an empty request stream.
pub fn checkBody(b: []const u8, max: usize, grpc_encoding: []const u8, scratch: []u8, need_message: bool) BodyCheck {
    if (grpc_encoding.len > 0 and !std.mem.eql(u8, grpc_encoding, "identity")) {
        const t = std.fmt.bufPrint(scratch, "Content is compressed with `{s}` which isn't supported", .{grpc_encoding}) catch "Content is compressed";
        return .{ .err = .{ .status = .unimplemented, .text = t, .reject_encoding = true } };
    }
    if (b.len == 0) {
        if (need_message) return .{ .err = .{ .status = .internal, .text = "Missing request message." } };
        return .{ .ok = b };
    }
    if (b.len < 5) return .{ .err = .{ .status = .internal, .text = "Unexpected EOF decoding stream." } };
    const n = std.mem.readInt(u32, b[1..5], .big);
    switch (b[0]) {
        0 => {},
        1 => return .{ .err = .{ .status = .internal, .text = "protocol error: received message with compressed-flag but no grpc-encoding was specified" } },
        else => {
            const t = std.fmt.bufPrint(scratch, "protocol error: received message with invalid compression flag: {d} (valid flags are 0 and 1) while receiving request", .{b[0]}) catch "protocol error";
            return .{ .err = .{ .status = .internal, .text = t } };
        },
    }
    if (n > max) {
        const t = std.fmt.bufPrint(scratch, "Error, decoded message length too large: found {d} bytes, the limit is: {d} bytes", .{ n, max }) catch "message too large";
        // tonic 0.14.6 (sui-node 1.83.1) `Status::out_of_range` in decode.rs.
        return .{ .err = .{ .status = .out_of_range, .text = t } };
    }
    if (b.len - 5 < n) return .{ .err = .{ .status = .internal, .text = "Unexpected EOF decoding stream." } };
    return .{ .ok = b[5..][0..n] };
}

/// `grpc-status`, `grpc-message` (tonic's percent encoding), `grpc-status-details-bin`.
pub fn statusHeaders(list: *std.ArrayList(meta.Header), arena: Allocator, status: Status, text: []const u8, details_bin: []const u8) !void {
    try list.append(arena, .{ .name = "grpc-status", .value = try std.fmt.allocPrint(arena, "{d}", .{@intFromEnum(status)}) });
    if (text.len > 0) {
        var enc: std.ArrayList(u8) = .empty;
        try codec.percentEncode(&enc, arena, text);
        try list.append(arena, .{ .name = "grpc-message", .value = enc.items });
    }
    if (details_bin.len > 0) {
        const e = std.base64.standard_no_pad.Encoder;
        const buf = try arena.alloc(u8, e.calcSize(details_bin.len));
        try list.append(arena, .{ .name = "grpc-status-details-bin", .value = e.encode(buf, details_bin) });
    }
}

/// Headers of a trailers-only reply, in tonic's order: its generated router answers an unknown
/// method with `grpc-status` before `content-type`; a Status reply puts `content-type` first and
/// a rejected `grpc-encoding` adds `grpc-accept-encoding: identity`.
pub fn trailersOnlyHeaders(list: *std.ArrayList(meta.Header), arena: Allocator, content_type: []const u8, status: Status, text: []const u8, details_bin: []const u8, reject_encoding: bool) !void {
    if (status == .unimplemented and text.len == 0 and details_bin.len == 0 and !reject_encoding) {
        try list.append(arena, .{ .name = "grpc-status", .value = "12" });
        try list.append(arena, .{ .name = "content-type", .value = content_type });
        return;
    }
    try list.append(arena, .{ .name = "content-type", .value = content_type });
    if (reject_encoding) try list.append(arena, .{ .name = "grpc-accept-encoding", .value = "identity" });
    try statusHeaders(list, arena, status, text, details_bin);
}



pub const Options = struct {
    /// SETTINGS_MAX_CONCURRENT_STREAMS (sui-http default 200); streams beyond it are refused.
    max_streams: u32 = 200,
    /// tonic's default max decoding message size.
    max_request_bytes: usize = 4 << 20,
    /// Receive window we advertise per stream and for the connection (hyper: 1 MiB).
    window: u32 = 1 << 20,
    max_header_list: usize = 16 << 10,
    /// Server default for `grpc-timeout` (sui-node `grpc-timeout-ms` 60 s).
    default_timeout_ns: ?u64 = 60 * std.time.ns_per_s,
    /// A plain tonic `Routes` stack (sui-node's validator port, sui-network
    /// `validator/server.rs`): no axum `/health` route, no CORS preflight, no gRPC-web layer, and
    /// a path outside every service answers tonic's fallback (UNIMPLEMENTED, empty message)
    /// instead of 404. Off: the full node's stack.
    grpc_only: bool = false,
    /// Send bound: bytes framed and waiting for the socket (`pending()`). At the bound `flush`
    /// leaves response DATA in its stream, which stays open and counted against `max_streams`,
    /// and the runtime reads no more requests until the socket takes some (`outFull`). Without
    /// it a peer with a huge h2 window that reads slowly had every response copied whole into
    /// `out`, with no limit. The h2 crate bounds the same thing per stream
    /// (`max_send_buffer_size`); DATA frame sizes are unchanged for a peer with the default
    /// SETTINGS_MAX_FRAME_SIZE. HEADERS, trailers and control frames are small and not held back.
    max_out_bytes: usize = 1 << 20,
    /// Rapid reset (CVE-2023-44487). The h2 crate's default, which sui-node runs with
    /// (`max_pending_accept_reset_streams`, 20): streams the peer opens and resets before the
    /// server has taken them up. Here that is within one `feed` pass; one more answers
    /// GOAWAY(ENHANCE_YOUR_CALM) with h2's debug data `too_many_resets`.
    max_pending_resets: u32 = 20,
    /// deepwave's own bound, for what tonic gets for free: there a reset drops the call's future,
    /// here the handler keeps its worker until it returns. Calls still on a worker whose stream
    /// is gone (reset by the peer, or by this side for a stream error the peer caused) are
    /// counted, and one more than this many closes the connection the same way, so a peer
    /// never has more than `max_streams` + this many calls on the workers (`--h2-max-cancelled`).
    /// A client that cancels calls, at any rate, stays below it unless that many cancelled calls
    /// are still running at once. The default leaves room for that case too: a node that stalls
    /// while its clients time out and retry several times over (sui-node never closes such a
    /// client; a cancelled call costs it nothing).
    max_reset_running: u32 = 4096,
};

const FrameType = enum(u8) { data = 0, headers = 1, priority = 2, rst_stream = 3, settings = 4, push_promise = 5, ping = 6, goaway = 7, window_update = 8, continuation = 9, _ };
const flag_end_stream: u8 = 1;
const flag_ack: u8 = 1;
const flag_end_headers: u8 = 4;
const flag_padded: u8 = 8;
const flag_priority: u8 = 0x20;

pub const ErrCode = enum(u32) { no_error = 0, protocol = 1, internal = 2, flow_control = 3, settings_timeout = 4, stream_closed = 5, frame_size = 6, refused_stream = 7, cancel = 8, compression = 9, connect = 10, enhance_your_calm = 11 };

pub const ConnError = error{ ConnectionError, OutOfMemory };

pub const Method = enum { post, get, head, options, other };

/// A unary request handed to a worker (`Conn.offload`): copies of what the handler needs, owned
/// by the worker, freed with `destroy`. The worker answers with `Conn.complete` under the
/// connection lock.
pub const Job = struct {
    stream_id: u32,
    path: []u8,
    authority: []u8,
    body: []u8,
    encoding: Encoding,
    deadline_ns: ?u64,
    client_protocol_version: ?u64 = null,
    /// Set by the connection (under its lock) when nobody waits for the answer any more: the
    /// stream was reset or dropped, or `expireJobs` answered it at its deadline.
    cancelled: std.atomic.Value(bool) = .init(false),

    /// Why a worker taking the job at `now_ns` must not run its handler, or null to run it.
    /// `.cancelled`: the stream is gone, any answer would be dropped. `.deadline_exceeded`: the
    /// deadline passed while the job waited for a worker; the worker answers what `expireJobs`
    /// answers ("Timeout expired", trailers-only), whichever of the two gets there first.
    /// sui-http's GrpcTimeout drops the call's future at the deadline, so sui-node does not run
    /// it either.
    pub fn dropped(j: *const Job, now_ns: u64) ?Status {
        if (j.cancelled.load(.acquire)) return .cancelled;
        if (j.deadline_ns) |d| if (now_ns >= d) return .deadline_exceeded;
        return null;
    }

    pub fn request(j: *const Job) Request {
        return .{ .path = j.path, .authority = j.authority, .body = j.body, .stream_id = j.stream_id, .accept = j.encoding, .deadline_ns = j.deadline_ns, .client_protocol_version = j.client_protocol_version };
    }
    pub fn destroy(j: *Job, gpa: Allocator) void {
        gpa.free(j.path);
        gpa.free(j.authority);
        gpa.free(j.body);
        gpa.destroy(j);
    }
};

/// Runs unary handlers off the connection (server.zig: the worker pool). `submit` takes the job
/// (true) or declines it (false: the handler runs inline, as without an offload). The stream
/// keeps a pointer to a job it handed out until `complete` or `jobEnded` is called for it, so the
/// worker calls one of them (under the connection lock) before it frees the job.
pub const Offload = struct {
    ctx: *anyopaque,
    submit: *const fn (ctx: *anyopaque, job: *Job) bool,
};

pub const Stream = struct {
    id: u32,
    path: []u8 = &.{},
    authority: []u8 = &.{},
    grpc_encoding: []u8 = &.{},
    accept: Encoding = .identity,
    timeout_ns: ?u64 = null,
    client_protocol_version: ?u64 = null,
    body: std.ArrayList(u8) = .empty,
    send_window: i64,
    /// Framed gRPC bytes not yet sent as DATA.
    out: std.ArrayList(u8) = .empty,
    out_off: usize = 0,
    headers_sent: bool = false,
    messages: u32 = 0,
    request_done: bool = false,
    /// Encoding of the response messages (announced in `grpc-encoding`).
    encoding: Encoding = .identity,
    /// Trailers block (encoded) once the handler finished; null while the stream is open.
    trailers: ?[]u8 = null,
    reset: bool = false,
    trailers_only: bool = false,
    t0: u64 = 0,
    /// Bidi stream: request messages are dispatched as they complete; `body_off` is the first
    /// byte not yet dispatched.
    bidi: bool = false,
    body_off: usize = 0,
    method: Method = .post,
    /// tonic-web content-type (exact match); only its method rule applies on h2.
    web: codec.WebKind = .none,
    /// The handler runs on a worker; `complete` answers the stream.
    running: bool = false,
    /// Deadline of the call running on a worker (`expireJobs`).
    job_deadline: ?u64 = null,
    /// The job of that call, to tell its worker when the stream goes (`Job.cancelled`).
    job: ?*Job = null,
    /// A plain HTTP reply (GET /health, gRPC-web): the stream ends after `out` with an empty
    /// DATA frame instead of trailers.
    plain_end: bool = false,
    /// `accept` equals a gRPC-web text type.
    accept_text: bool = false,
    /// gRPC-web over h2 (tonic-web serves it whatever the HTTP version: h2-post-grpcweb):
    /// messages and a `0x80` trailers frame in DATA, base64 per frame for text.
    web_out: codec.WebKind = .none,
    /// Request content-type is gRPC (`application/grpc*`): the metrics path label rule.
    grpc_ct: bool = false,
    /// Request metrics (obs.zig): begun at the request head, ended when the stream goes.
    obs: obs.Track = .{},

    fn ended(s: *const Stream) bool {
        return s.trailers != null or s.plain_end;
    }

    fn deinit(s: *Stream, gpa: Allocator) void {
        s.obs.end(meta.monoNs());
        gpa.free(s.path);
        gpa.free(s.authority);
        gpa.free(s.grpc_encoding);
        s.body.deinit(gpa);
        s.out.deinit(gpa);
        if (s.trailers) |t| gpa.free(t);
    }
};

pub const Conn = struct {
    gpa: Allocator,
    opts: Options,
    handler: Handler,
    in: std.ArrayList(u8) = .empty,
    out: std.ArrayList(u8) = .empty,
    out_off: usize = 0,
    got_preface: bool = false,
    sent_settings: bool = false,
    dec: hpack.Decoder,
    streams: std.AutoHashMapUnmanaged(u32, *Stream) = .empty,
    last_stream: u32 = 0,
    conn_send_window: i64 = 65535,
    peer_initial_window: i64 = 65535,
    peer_max_frame: u32 = 16384,
    closing: bool = false,
    /// GOAWAY(NO_ERROR) sent: no new streams; close once the open ones finish.
    draining: bool = false,
    /// A PING we sent and its ack (keepalive).
    ping_out: ?u64 = null,
    ping_acked: bool = false,
    // header block assembly
    hb_stream: u32 = 0,
    hb: std.ArrayList(u8) = .empty,
    hb_end_stream: bool = false,
    scratch: std.ArrayList(u8) = .empty,
    /// Unary handlers run here when set (null: inline, inside `feed`).
    offload: ?Offload = null,
    /// Earliest deadline of a call running on a worker (connection thread only): the server
    /// loop waits no longer than this, so `expireJobs` answers at the deadline.
    next_job_deadline: ?u64 = null,
    /// A `flush` stopped at the send bound (`Options.max_out_bytes`): `consumed` moves more
    /// stream bytes into `out` once there is room.
    out_blocked: bool = false,
    /// `consumed` moved held-back stream bytes into `out` (the runtime wakes its pumps: their
    /// `unsent` may have reached zero) and clears it.
    out_refilled: bool = false,
    /// RST_STREAM frames received on this connection.
    rst_frames: u64 = 0,
    /// `last_stream` when the current `feed` pass began: streams above it were opened in this
    /// pass (`Options.max_pending_resets`), and how many of those the peer reset in it.
    pass_base: u32 = 0,
    pass_resets: u32 = 0,
    /// Streams dropped while their call was still on a worker (`Options.max_reset_running`);
    /// the worker's `complete` takes its stream out.
    reset_running: std.AutoHashMapUnmanaged(u32, void) = .empty,
    /// The connection was closed for resets (GOAWAY ENHANCE_YOUR_CALM).
    calmed: bool = false,

    pub fn init(gpa: Allocator, opts: Options, handler: Handler) !Conn {
        var c: Conn = .{ .gpa = gpa, .opts = opts, .handler = handler, .dec = hpack.Decoder.init(gpa) };
        try c.queueSettings();
        return c;
    }

    pub fn deinit(c: *Conn) void {
        var it = c.streams.valueIterator();
        while (it.next()) |s| {
            s.*.deinit(c.gpa);
            c.gpa.destroy(s.*);
        }
        c.streams.deinit(c.gpa);
        c.reset_running.deinit(c.gpa);
        c.in.deinit(c.gpa);
        c.out.deinit(c.gpa);
        c.hb.deinit(c.gpa);
        c.scratch.deinit(c.gpa);
        c.dec.deinit();
    }

    pub fn pending(c: *const Conn) []const u8 {
        return c.out.items[c.out_off..];
    }

    pub fn consumed(c: *Conn, n: usize) void {
        c.out_off += n;
        if (c.out_off == c.out.items.len) {
            // Control frames are not held back, so `out` can pass the bound: do not keep that.
            if (c.out.capacity > 2 *| c.opts.max_out_bytes) c.out.clearAndFree(c.gpa) else c.out.clearRetainingCapacity();
            c.out_off = 0;
        } else if (c.out_off >= out_compact_min and c.out_off >= c.out.items.len / 2) {
            // A backlog that is refilled as it drains never empties: drop the sent prefix here,
            // or `out` would grow by everything ever sent.
            const rest = c.out.items.len - c.out_off;
            std.mem.copyForwards(u8, c.out.items[0..rest], c.out.items[c.out_off..]);
            c.out.shrinkRetainingCapacity(rest);
            c.out_off = 0;
        }
        if (c.out_blocked and !c.outFull()) {
            c.out_blocked = false;
            c.out_refilled = true;
            // Out of memory here leaves streams that nothing would flush again: close.
            c.flushAll() catch {
                c.closing = true;
            };
        }
    }

    const out_compact_min = 64 << 10;

    /// The queued output is at the send bound (`Options.max_out_bytes`): the runtime writes
    /// `pending()` and reads nothing more from the peer until this is false again.
    pub fn outFull(c: *const Conn) bool {
        return c.pending().len >= c.opts.max_out_bytes;
    }

    /// Does nothing (lets a runtime drain `pending()` through its usual control path).
    pub fn noop(_: *Conn) !void {}

    pub fn wantsClose(c: *const Conn) bool {
        if (c.draining and c.streams.count() == 0 and c.pending().len == 0) return true;
        return c.closing and c.pending().len == 0;
    }

    pub fn openStreams(c: *const Conn) usize {
        return c.streams.count();
    }

    // ---- output helpers ----

    fn frameHeader(c: *Conn, len: usize, t: FrameType, flags: u8, stream: u32) !void {
        var h: [9]u8 = undefined;
        h[0] = @intCast(len >> 16);
        h[1] = @intCast((len >> 8) & 0xff);
        h[2] = @intCast(len & 0xff);
        h[3] = @intFromEnum(t);
        h[4] = flags;
        std.mem.writeInt(u32, h[5..9], stream, .big);
        try c.out.appendSlice(c.gpa, &h);
    }

    fn queueSettings(c: *Conn) !void {
        // hyper/sui-http order: MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE,
        // MAX_HEADER_LIST_SIZE, ENABLE_CONNECT_PROTOCOL (captured: vectors/h2-settings.resp)
        const ids = [_]u16{ 3, 4, 5, 6, 8 };
        const vals = [_]u32{ c.opts.max_streams, c.opts.window, 16384, @intCast(c.opts.max_header_list), 1 };
        try c.frameHeader(ids.len * 6, .settings, 0, 0);
        for (ids, vals) |id, v| {
            var b: [6]u8 = undefined;
            std.mem.writeInt(u16, b[0..2], id, .big);
            std.mem.writeInt(u32, b[2..6], v, .big);
            try c.out.appendSlice(c.gpa, &b);
        }
        // grow the connection receive window from the 65535 default
        if (c.opts.window > 65535) try c.windowUpdate(0, c.opts.window - 65535);
        c.sent_settings = true;
    }

    fn windowUpdate(c: *Conn, stream: u32, inc: u32) !void {
        try c.frameHeader(4, .window_update, 0, stream);
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, inc, .big);
        try c.out.appendSlice(c.gpa, &b);
    }

    fn rst(c: *Conn, stream: u32, code: ErrCode) !void {
        try c.frameHeader(4, .rst_stream, 0, stream);
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, @intFromEnum(code), .big);
        try c.out.appendSlice(c.gpa, &b);
    }

    fn goaway(c: *Conn, code: ErrCode) ConnError {
        c.closing = true;
        c.frameHeader(8, .goaway, 0, 0) catch return error.OutOfMemory;
        var b: [8]u8 = undefined;
        std.mem.writeInt(u32, b[0..4], c.last_stream, .big);
        std.mem.writeInt(u32, b[4..8], @intFromEnum(code), .big);
        c.out.appendSlice(c.gpa, &b) catch return error.OutOfMemory;
        return error.ConnectionError;
    }

    /// GOAWAY(ENHANCE_YOUR_CALM) with the h2 crate's debug data, for a peer that resets streams
    /// faster than the limits allow.
    fn tooManyResets(c: *Conn) ConnError {
        const debug = "too_many_resets";
        c.closing = true;
        c.calmed = true;
        c.frameHeader(8 + debug.len, .goaway, 0, 0) catch return error.OutOfMemory;
        var b: [8]u8 = undefined;
        std.mem.writeInt(u32, b[0..4], c.last_stream, .big);
        std.mem.writeInt(u32, b[4..8], @intFromEnum(ErrCode.enhance_your_calm), .big);
        c.out.appendSlice(c.gpa, &b) catch return error.OutOfMemory;
        c.out.appendSlice(c.gpa, debug) catch return error.OutOfMemory;
        return error.ConnectionError;
    }

    /// Calls still on a worker whose stream is gone.
    pub fn resetRunning(c: *const Conn) usize {
        return c.reset_running.count();
    }

    fn maxResetRunning(c: *const Conn) usize {
        return c.opts.max_reset_running;
    }

    /// Graceful shutdown (max connection age, server stop): GOAWAY(NO_ERROR) with the last
    /// stream id; open streams finish, new ones are refused.
    pub fn drain(c: *Conn) !void {
        if (c.draining or c.closing) return;
        c.draining = true;
        try c.frameHeader(8, .goaway, 0, 0);
        var b: [8]u8 = undefined;
        std.mem.writeInt(u32, b[0..4], c.last_stream, .big);
        std.mem.writeInt(u32, b[4..8], 0, .big);
        try c.out.appendSlice(c.gpa, &b);
    }

    /// Keepalive: queue a PING with `opaque_data`; `ping_acked` turns true when it comes back.
    pub fn ping(c: *Conn, opaque_data: u64) !void {
        try c.frameHeader(8, .ping, 0, 0);
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, opaque_data, .big);
        try c.out.appendSlice(c.gpa, &b);
        c.ping_out = opaque_data;
        c.ping_acked = false;
    }

    // ---- input ----

    pub fn feed(c: *Conn, bytes: []const u8) ConnError!void {
        if (c.closing) return;
        try c.in.appendSlice(c.gpa, bytes);
        c.pass_base = c.last_stream;
        c.pass_resets = 0;
        var pos: usize = 0;
        defer {
            if (pos > 0) {
                const rest = c.in.items.len - pos;
                std.mem.copyForwards(u8, c.in.items[0..rest], c.in.items[pos..]);
                c.in.shrinkRetainingCapacity(rest);
            }
        }
        if (!c.got_preface) {
            if (c.in.items.len < preface.len) {
                if (!std.mem.startsWith(u8, preface, c.in.items)) return c.goaway(.protocol);
                return;
            }
            if (!std.mem.eql(u8, c.in.items[0..preface.len], preface)) return c.goaway(.protocol);
            pos = preface.len;
            c.got_preface = true;
        }
        while (c.in.items.len - pos >= 9) {
            const h = c.in.items[pos..][0..9];
            const len = (@as(usize, h[0]) << 16) | (@as(usize, h[1]) << 8) | h[2];
            if (len > 16384) return c.goaway(.frame_size);
            if (c.in.items.len - pos < 9 + len) break;
            const t: FrameType = @enumFromInt(h[3]);
            const flags = h[4];
            const sid = std.mem.readInt(u32, h[5..9], .big) & 0x7fffffff;
            const payload = c.in.items[pos + 9 ..][0..len];
            // a header block must be continued by CONTINUATION frames only
            if (c.hb_stream != 0 and t != .continuation) return c.goaway(.protocol);
            try c.frame(t, flags, sid, payload);
            pos += 9 + len;
            if (c.closing) return;
        }
        try c.flushAll();
    }

    fn frame(c: *Conn, t: FrameType, flags: u8, sid: u32, payload: []const u8) ConnError!void {
        switch (t) {
            .settings => {
                if (sid != 0) return c.goaway(.protocol);
                if (flags & flag_ack != 0) return;
                if (payload.len % 6 != 0) return c.goaway(.frame_size);
                var i: usize = 0;
                while (i < payload.len) : (i += 6) {
                    const id = std.mem.readInt(u16, payload[i..][0..2], .big);
                    const v = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
                    switch (id) {
                        4 => {
                            if (v > 0x7fffffff) return c.goaway(.flow_control);
                            const delta = @as(i64, v) - c.peer_initial_window;
                            c.peer_initial_window = v;
                            var it = c.streams.valueIterator();
                            while (it.next()) |s| s.*.send_window += delta;
                        },
                        5 => {
                            if (v < 16384 or v > 16777215) return c.goaway(.protocol);
                            c.peer_max_frame = v;
                        },
                        // 1 (HEADER_TABLE_SIZE) bounds the peer's decoder, i.e. our encoder,
                        // which never indexes. Our decoder's limit is the 4096 default we keep
                        // advertising; letting the peer raise it would let it grow our table.
                        else => {},
                    }
                }
                c.frameHeader(0, .settings, flag_ack, 0) catch return error.OutOfMemory;
            },
            .ping => {
                if (sid != 0 or payload.len != 8) return c.goaway(.protocol);
                if (flags & flag_ack != 0) {
                    if (c.ping_out) |p| if (std.mem.readInt(u64, payload[0..8], .big) == p) {
                        c.ping_acked = true;
                    };
                    return;
                }
                c.frameHeader(8, .ping, flag_ack, 0) catch return error.OutOfMemory;
                c.out.appendSlice(c.gpa, payload) catch return error.OutOfMemory;
            },
            .window_update => {
                if (payload.len != 4) return c.goaway(.frame_size);
                const inc = std.mem.readInt(u32, payload[0..4], .big) & 0x7fffffff;
                if (inc == 0) {
                    if (sid == 0) return c.goaway(.protocol);
                    c.rst(sid, .protocol) catch return error.OutOfMemory;
                    return;
                }
                if (sid == 0) {
                    c.conn_send_window += inc;
                    if (c.conn_send_window > 0x7fffffff) return c.goaway(.flow_control);
                } else if (c.streams.get(sid)) |s| {
                    s.send_window += inc;
                    if (s.send_window > 0x7fffffff) {
                        c.rst(sid, .flow_control) catch return error.OutOfMemory;
                        c.dropStream(sid);
                        // a reset the peer provoked frees the stream like its own would
                        if (c.reset_running.count() > c.maxResetRunning()) return c.tooManyResets();
                    }
                }
            },
            .priority => {},
            .rst_stream => {
                if (sid == 0 or payload.len != 4) return c.goaway(.protocol);
                c.rst_frames += 1;
                if (c.streams.get(sid)) |s| {
                    s.reset = true;
                    if (sid > c.pass_base) {
                        c.pass_resets += 1;
                        if (c.pass_resets > c.opts.max_pending_resets) return c.tooManyResets();
                    }
                }
                c.dropStream(sid);
                if (c.reset_running.count() > c.maxResetRunning()) return c.tooManyResets();
            },
            .goaway => {
                c.closing = true;
            },
            .push_promise => return c.goaway(.protocol),
            .headers => {
                if (sid == 0 or sid & 1 == 0) return c.goaway(.protocol);
                var p = payload;
                var pad: usize = 0;
                if (flags & flag_padded != 0) {
                    if (p.len < 1) return c.goaway(.protocol);
                    pad = p[0];
                    p = p[1..];
                }
                if (flags & flag_priority != 0) {
                    if (p.len < 5) return c.goaway(.protocol);
                    p = p[5..];
                }
                if (pad > p.len) return c.goaway(.protocol);
                p = p[0 .. p.len - pad];
                if (sid <= c.last_stream and c.streams.get(sid) == null) return c.goaway(.stream_closed);
                if (sid > c.last_stream) {
                    if (c.streams.count() >= c.opts.max_streams or c.draining) {
                        // The header block must still be decoded (RFC 7540 4.3): it may change
                        // the HPACK dynamic table the next requests index into.
                        c.rst(sid, .refused_stream) catch return error.OutOfMemory;
                        c.last_stream = sid;
                        c.hb.clearRetainingCapacity();
                        c.hb.appendSlice(c.gpa, p) catch return error.OutOfMemory;
                        c.hb_stream = sid;
                        c.hb_end_stream = false;
                        if (flags & flag_end_headers != 0) try c.finishHeaders();
                        return;
                    }
                    const s = c.gpa.create(Stream) catch return error.OutOfMemory;
                    s.* = .{ .id = sid, .send_window = c.peer_initial_window, .t0 = meta.monoNs() };
                    c.streams.put(c.gpa, sid, s) catch return error.OutOfMemory;
                    c.last_stream = sid;
                }
                c.hb.clearRetainingCapacity();
                c.hb.appendSlice(c.gpa, p) catch return error.OutOfMemory;
                c.hb_stream = sid;
                c.hb_end_stream = flags & flag_end_stream != 0;
                if (flags & flag_end_headers != 0) try c.finishHeaders();
            },
            .continuation => {
                if (sid == 0 or sid != c.hb_stream) return c.goaway(.protocol);
                if (c.hb.items.len + payload.len > c.opts.max_header_list) return c.goaway(.enhance_your_calm);
                c.hb.appendSlice(c.gpa, payload) catch return error.OutOfMemory;
                if (flags & flag_end_headers != 0) try c.finishHeaders();
            },
            .data => {
                if (sid == 0) return c.goaway(.protocol);
                var p = payload;
                if (flags & flag_padded != 0) {
                    if (p.len < 1) return c.goaway(.protocol);
                    const pad = p[0];
                    if (pad >= p.len) return c.goaway(.protocol);
                    p = p[1 .. p.len - pad];
                }
                // connection window credit for everything received, padding included
                if (payload.len > 0) c.windowUpdate(0, @intCast(payload.len)) catch return error.OutOfMemory;
                const s = c.streams.get(sid) orelse {
                    if (sid > c.last_stream) return c.goaway(.protocol);
                    c.rst(sid, .stream_closed) catch return error.OutOfMemory;
                    return;
                };
                if (s.request_done) {
                    c.rst(sid, .stream_closed) catch return error.OutOfMemory;
                    return;
                }
                if (!s.bidi and s.body.items.len - s.body_off + p.len > c.opts.max_request_bytes + 5) {
                    // tonic reads the message header as it arrives and answers OUT_OF_RANGE
                    // "decoded message length too large" without waiting for the body.
                    s.body.appendSlice(c.gpa, p[0..@min(p.len, 5)]) catch return error.OutOfMemory;
                    var scratch: [256]u8 = undefined;
                    s.request_done = true;
                    switch (checkBody(s.body.items, c.opts.max_request_bytes, s.grpc_encoding, &scratch, c.handler.methodExists(s.path))) {
                        .err => |e| return c.setTrailersEx(s, e.status, e.text, "", e.reject_encoding),
                        .ok => {
                            c.rst(sid, .cancel) catch return error.OutOfMemory;
                            c.dropStream(sid);
                            return;
                        },
                    }
                }
                if (s.bidi and s.body.items.len - s.body_off + p.len > c.opts.max_request_bytes + 5) {
                    c.rst(sid, .cancel) catch return error.OutOfMemory;
                    c.dropStream(sid);
                    return;
                }
                s.body.appendSlice(c.gpa, p) catch return error.OutOfMemory;
                if (payload.len > 0 and flags & flag_end_stream == 0) c.windowUpdate(sid, @intCast(payload.len)) catch return error.OutOfMemory;
                if (s.bidi) {
                    try c.bidiFeed(s, flags & flag_end_stream != 0);
                } else if (flags & flag_end_stream != 0) try c.dispatch(s);
            },
            _ => {}, // unknown frame types are ignored
        }
    }

    const HeaderSink = struct {
        c: *Conn,
        s: *Stream,
        fn push(self: *HeaderSink, name: []const u8, value: []const u8) hpack.Error!void {
            const eql = std.mem.eql;
            const gpa = self.c.gpa;
            if (eql(u8, name, ":path")) {
                gpa.free(self.s.path);
                self.s.path = try gpa.dupe(u8, value);
            } else if (eql(u8, name, ":method")) {
                self.s.method = if (eql(u8, value, "POST")) .post else if (eql(u8, value, "GET")) .get else if (eql(u8, value, "HEAD")) .head else if (eql(u8, value, "OPTIONS")) .options else .other;
            } else if (eql(u8, name, "content-type")) {
                self.s.web = codec.grpcWebKind(value);
                self.s.grpc_ct = obs.isGrpcContentType(value);
            } else if (eql(u8, name, "accept")) {
                self.s.accept_text = codec.textAccept(value);
            } else if (eql(u8, name, ":authority") or eql(u8, name, "host")) {
                gpa.free(self.s.authority);
                self.s.authority = try gpa.dupe(u8, value);
            } else if (eql(u8, name, "grpc-accept-encoding")) {
                self.s.accept = codec.pickAccept(value);
            } else if (eql(u8, name, "grpc-encoding")) {
                gpa.free(self.s.grpc_encoding);
                self.s.grpc_encoding = try gpa.dupe(u8, value);
            } else if (eql(u8, name, "grpc-timeout")) {
                self.s.timeout_ns = meta.parseTimeout(value);
            } else if (eql(u8, name, "x-sui-client-protocol-version")) {
                self.s.client_protocol_version = meta.parseClientProtocolVersion(value);
            }
        }
    };

    const DiscardSink = struct {
        fn push(_: *DiscardSink, _: []const u8, _: []const u8) hpack.Error!void {}
    };

    fn finishHeaders(c: *Conn) ConnError!void {
        const sid = c.hb_stream;
        c.hb_stream = 0;
        var arena_state = std.heap.ArenaAllocator.init(c.gpa);
        defer arena_state.deinit();
        // Every header block goes through the decoder, also for refused, closed or finished
        // streams, so the HPACK dynamic table stays in step with the peer's encoder.
        const s = c.streams.get(sid) orelse {
            var none: DiscardSink = .{};
            c.dec.decode(arena_state.allocator(), c.hb.items, &none, DiscardSink.push) catch return c.goaway(.compression);
            return;
        };
        if (s.request_done) {
            // client trailers after the request ended
            var none: DiscardSink = .{};
            c.dec.decode(arena_state.allocator(), c.hb.items, &none, DiscardSink.push) catch return c.goaway(.compression);
            return;
        }
        var sink: HeaderSink = .{ .c = c, .s = s };
        c.dec.decode(arena_state.allocator(), c.hb.items, &sink, HeaderSink.push) catch return c.goaway(.compression);
        // CORS sits outside sui-node's metrics layer: preflights are not counted.
        if (s.method != .options) s.obs.begin(meta.pathOnly(s.path), s.grpc_ct, meta.monoNs());
        // tonic serves the bidi path whatever the method; OPTIONS (CORS) and a gRPC-web type
        // with another method than POST (tonic-web 405) are answered by `dispatch`.
        if (c.handler.isBidi(s.path) and c.handler.isKnown(s.path) and s.method != .options and s.web == .none) {
            s.bidi = true;
            if (c.handler.compresses(s.path)) s.encoding = s.accept;
            if (c.hb_end_stream) try c.bidiFeed(s, true);
            return;
        }
        if (c.hb_end_stream) try c.dispatch(s);
    }

    fn dropStream(c: *Conn, sid: u32) void {
        if (c.streams.fetchRemove(sid)) |kv| {
            // Its call is still on a worker: the stream no longer counts against
            // `max_streams`, the call does against `max_reset_running`.
            if (kv.value.running) c.reset_running.put(c.gpa, sid, {}) catch {};
            // a worker that has not started the call yet drops it
            if (kv.value.job) |j| j.cancelled.store(true, .release);
            kv.value.deinit(c.gpa);
            c.gpa.destroy(kv.value);
        }
    }

    const ConnSink = struct {
        c: *Conn,
        s: *Stream,
        fn write(impl: *anyopaque, hdr: *const [5]u8, payload: []const u8) anyerror!void {
            const self: *ConnSink = @ptrCast(@alignCast(impl));
            try self.c.appendOut(self.s, &.{ hdr, payload });
            self.s.messages += 1;
        }
        fn cancelled(impl: *anyopaque) bool {
            const self: *ConnSink = @ptrCast(@alignCast(impl));
            return self.s.reset;
        }
        const vt: ResponseStream.VTable = .{ .write = write, .cancelled = cancelled };
    };

    fn deadlineOf(c: *const Conn, s: *const Stream) ?u64 {
        const t = if (s.timeout_ns) |a| (if (c.opts.default_timeout_ns) |b| @min(a, b) else a) else c.opts.default_timeout_ns orelse return null;
        return s.t0 +| t;
    }

    /// Routes a complete request the way sui-node's stack does (vectors h2-*): tower-http CORS
    /// answers any OPTIONS as a preflight; axum's `/health` route serves GET and HEAD (405 with
    /// `allow` otherwise); tonic-web answers a gRPC-web content type with a method other than
    /// POST 405; a path outside every service is 404; the rest goes to tonic, which ignores the
    /// method (a GET on a gRPC path is a call with no message: h2-get-grpc-path).
    fn dispatch(c: *Conn, s: *Stream) ConnError!void {
        s.request_done = true;
        const path = meta.pathOnly(s.path);
        if (c.opts.grpc_only) {
            // tonic Routes: every request is a gRPC call; unknown paths hit the fallback
            s.web = .none;
            if (!c.handler.isKnown(s.path)) return c.setTrailersEx(s, .unimplemented, "", "", false);
        }
        const health_route = !c.opts.grpc_only and std.mem.eql(u8, path, "/health");
        if (s.method == .options and !c.opts.grpc_only) return c.plainReply(s, if (health_route) .preflight_health else .preflight);
        if (health_route) return switch (s.method) {
            .get => c.healthReply(s, true),
            .head => c.healthReply(s, false),
            else => c.plainReply(s, .health_method),
        };
        if (!c.handler.isKnown(s.path)) return c.plainReply(s, .not_found);
        if (s.web != .none and s.method != .post) return c.plainReply(s, .web_method);
        if (s.web != .none) {
            s.web_out = if (s.accept_text) .text else .binary;
            if (s.web == .text) {
                // grpc-web-text request: base64 (in one or more padded chunks)
                const raw = codec.base64DecodeChunks(c.gpa, s.body.items) catch return c.setTrailersEx(s, .internal, "invalid base64", "", false);
                defer c.gpa.free(raw);
                s.body.clearRetainingCapacity();
                s.body.appendSlice(c.gpa, raw) catch return error.OutOfMemory;
            }
        }
        var scratch: [256]u8 = undefined;
        const payload = switch (checkBody(s.body.items, c.opts.max_request_bytes, s.grpc_encoding, &scratch, c.handler.methodExists(s.path))) {
            .ok => |p| p,
            .err => |e| return c.setTrailersEx(s, e.status, e.text, "", e.reject_encoding),
        };
        if (c.handler.compresses(s.path)) s.encoding = s.accept;
        if (c.offload) |o| {
            if (c.makeJob(s, payload)) |job| {
                const dl = job.deadline_ns;
                s.job = job; // before `submit`: the worker may have the job at once
                if (o.submit(o.ctx, job)) {
                    s.running = true;
                    s.job_deadline = dl;
                    if (dl) |d| c.next_job_deadline = if (c.next_job_deadline) |x| @min(x, d) else d;
                    return;
                }
                s.job = null;
                job.destroy(c.gpa);
            } else |_| {}
        }
        var sink: ConnSink = .{ .c = c, .s = s };
        var rs: ResponseStream = .{ .gpa = c.gpa, .impl = &sink, .vt = &ConnSink.vt, .encoding = s.encoding };
        defer rs.release();
        const req: Request = .{ .path = s.path, .authority = s.authority, .body = payload, .stream_id = s.id, .accept = s.encoding, .deadline_ns = c.deadlineOf(s), .client_protocol_version = s.client_protocol_version };
        const status = c.handler.call(c.handler.ctx, &req, &rs);
        switch (status) {
            .deferred => return,
            .held => return c.flush(s),
            else => try c.setTrailersEx(s, status, rs.msg, rs.details_bin, false),
        }
    }

    fn makeJob(c: *Conn, s: *const Stream, payload: []const u8) !*Job {
        const j = try c.gpa.create(Job);
        errdefer c.gpa.destroy(j);
        const path = try c.gpa.dupe(u8, s.path);
        errdefer c.gpa.free(path);
        const authority = try c.gpa.dupe(u8, s.authority);
        errdefer c.gpa.free(authority);
        const body = try c.gpa.dupe(u8, payload);
        j.* = .{ .stream_id = s.id, .path = path, .authority = authority, .body = body, .encoding = s.encoding, .deadline_ns = c.deadlineOf(s), .client_protocol_version = s.client_protocol_version };
        return j;
    }

    /// The answer of a worker for a stream handed out through `offload`: the framed messages
    /// (prefix and payload, compressed with the stream's encoding) and the status. False when
    /// the stream is gone (reset by the peer, or the connection failed).
    pub fn complete(c: *Conn, stream_id: u32, framed: []const u8, messages: u32, status: Status, text: []const u8, details_bin: []const u8) ConnError!bool {
        _ = c.reset_running.remove(stream_id);
        const s = c.streams.get(stream_id) orelse return false;
        s.running = false;
        s.job = null;
        if (s.reset or s.ended() or c.closing) return false;
        var off: usize = 0;
        while (off + 5 <= framed.len) {
            const n = std.mem.readInt(u32, framed[off + 1 ..][0..4], .big);
            c.appendOut(s, &.{framed[off..][0..5], framed[off + 5 ..][0..n]}) catch return error.OutOfMemory;
            off += 5 + n;
        }
        s.messages += messages;
        switch (status) {
            .deferred, .held => try c.flush(s),
            else => try c.setTrailersEx(s, status, text, details_bin, false),
        }
        return true;
    }

    /// The worker of `stream_id`'s job is done with it and has no answer to give (the connection
    /// failed): what `complete` does for the bookkeeping, nothing queued.
    pub fn jobEnded(c: *Conn, stream_id: u32) void {
        _ = c.reset_running.remove(stream_id);
        const s = c.streams.get(stream_id) orelse return;
        s.running = false;
        s.job = null;
    }

    /// sui-http's `GrpcTimeout` (the 60 s server default, or a shorter `grpc-timeout`): a unary
    /// call still running on a worker at its deadline is answered now with trailers-only
    /// DEADLINE_EXCEEDED "Timeout expired"; the worker's late `complete` finds the stream gone.
    pub fn expireJobs(c: *Conn, now_ns: u64) ConnError!void {
        var ids: [64]u32 = undefined;
        var n: usize = 0;
        var next: ?u64 = null;
        var it = c.streams.valueIterator();
        while (it.next()) |sp| {
            const s = sp.*;
            if (!s.running or s.reset or s.ended()) continue;
            const d = s.job_deadline orelse continue;
            if (now_ns < d or n == ids.len) {
                next = if (next) |x| @min(x, d) else d;
                continue;
            }
            ids[n] = s.id;
            n += 1;
        }
        c.next_job_deadline = next;
        for (ids[0..n]) |id| if (c.streams.get(id)) |s| {
            s.running = false;
            s.job_deadline = null;
            // answered here: a worker that has not started the call drops it
            if (s.job) |j| j.cancelled.store(true, .release);
            s.job = null;
            try c.setTrailersEx(s, .deadline_exceeded, "Timeout expired", "", false);
        };
    }

    /// Bidi streams (tonic-reflection): dispatch every complete request message. A request
    /// message that fails to decode (bad flag, over the size limit, a partial message at the
    /// end) ends tonic-reflection's task, so the response ends with OK and no reply
    /// (vectors h1-refl-bad, h1-refl-short, h2-refl-bad). An unsupported `grpc-encoding` is
    /// refused before the service runs (trailers-only UNIMPLEMENTED).
    fn bidiFeed(c: *Conn, s: *Stream, end: bool) ConnError!void {
        var scratch: [256]u8 = undefined;
        if (s.grpc_encoding.len > 0 and !std.mem.eql(u8, s.grpc_encoding, "identity")) {
            const e = checkBody("", c.opts.max_request_bytes, s.grpc_encoding, &scratch, false).err;
            s.request_done = true;
            return c.setTrailersEx(s, e.status, e.text, "", e.reject_encoding);
        }
        // tonic answers a streaming call with its HEADERS at once; statuses go in trailers
        // (h2-refl-ext: HEADERS, then grpc-status 5 in the trailers)
        if (!s.headers_sent) try c.flush(s);
        while (true) {
            const b = s.body.items[s.body_off..];
            if (b.len < 5) break;
            const n = std.mem.readInt(u32, b[1..5], .big);
            if (n > c.opts.max_request_bytes) return c.setTrailersEx(s, .ok, "", "", false);
            if (b.len - 5 < n) break;
            const payload = switch (checkBody(b[0 .. 5 + n], c.opts.max_request_bytes, s.grpc_encoding, &scratch, false)) {
                .ok => |p| p,
                .err => return c.setTrailersEx(s, .ok, "", "", false),
            };
            s.body_off += 5 + n;
            var sink: ConnSink = .{ .c = c, .s = s };
            var rs: ResponseStream = .{ .gpa = c.gpa, .impl = &sink, .vt = &ConnSink.vt, .encoding = s.encoding };
            defer rs.release();
            const req: Request = .{ .path = s.path, .authority = s.authority, .body = payload, .stream_id = s.id, .accept = s.encoding, .client_protocol_version = s.client_protocol_version };
            const status = c.handler.call(c.handler.ctx, &req, &rs);
            if (status != .ok or rs.end_stream) return c.setTrailersEx(s, if (status == .deferred or status == .held) .unimplemented else status, rs.msg, rs.details_bin, false);
            try c.flush(s);
        }
        const rest = s.body.items.len - s.body_off;
        if (s.body_off > 0) {
            std.mem.copyForwards(u8, s.body.items[0..rest], s.body.items[s.body_off..]);
            s.body.shrinkRetainingCapacity(rest);
            s.body_off = 0;
        }
        if (end) {
            s.request_done = true;
            return c.setTrailersEx(s, .ok, "", "", false);
        }
    }

    const PlainKind = enum { not_found, web_method, health_method, preflight, preflight_health };

    /// A bodiless HTTP reply in sui-node's header order (vectors h2-post-unknown, h2-get-grpcweb-ct,
    /// h2-post-health, h2-options-*). hyper sends no content-length on h2 for the 404 and 405
    /// replies, `content-length: 0` on axum's `/health` route.
    fn plainReply(c: *Conn, s: *Stream, kind: PlainKind) ConnError!void {
        c.plainReplyInner(s, kind) catch return error.OutOfMemory;
        c.dropStream(s.id);
    }

    fn plainReplyInner(c: *Conn, s: *Stream, kind: PlainKind) !void {
        var arena_state = std.heap.ArenaAllocator.init(c.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var list: std.ArrayList(meta.Header) = .empty;
        var blk: std.ArrayList(u8) = .empty;
        const dur = (meta.monoNs() -| s.t0) / std.time.ns_per_ms;
        s.obs.status(obs.httpLabel(switch (kind) {
            .not_found => 404,
            .web_method, .health_method => 405,
            .preflight, .preflight_health => 200,
        }), meta.monoNs());
        switch (kind) {
            .not_found => {
                try blk.append(arena, 0x8d); // :status 404
                try c.commonHeaders(&list, arena, s);
            },
            .web_method, .health_method => {
                try hpack.encodeLiteral(&blk, arena, ":status", "405");
                var info: meta.Info = .{};
                const have = c.handler.getInfo(&info);
                try meta.common(&list, arena, if (have) &info else null, dur);
                if (kind == .health_method) {
                    try list.append(arena, .{ .name = "allow", .value = "GET,HEAD" });
                    try list.append(arena, .{ .name = "content-length", .value = "0" });
                }
                try c.dateHeader(&list, arena);
            },
            .preflight, .preflight_health => {
                try blk.append(arena, 0x88); // :status 200
                try meta.preflight(&list, arena, dur, kind == .preflight_health);
                if (kind == .preflight_health) try list.append(arena, .{ .name = "content-length", .value = "0" });
                try c.dateHeader(&list, arena);
            },
        }
        try c.encodeHeaders(&blk, arena, list.items);
        try c.frameHeader(blk.items.len, .headers, flag_end_headers | flag_end_stream, s.id);
        try c.out.appendSlice(c.gpa, blk.items);
    }

    /// `GET /health[?threshold_seconds=N]` (and HEAD, no body) on h2 (vectors h2-get-health,
    /// h2-head-health): 200 `up` or 503 `down`, text/plain, the common headers, content-length.
    fn healthReply(c: *Conn, s: *Stream, with_body: bool) ConnError!void {
        const up = if (c.handler.health) |f| f(c.handler.ctx, meta.healthThreshold(s.path)) else true;
        const body: []const u8 = if (up) "up" else "down";
        s.obs.status(obs.httpLabel(if (up) 200 else 503), meta.monoNs());
        {
            var arena_state = std.heap.ArenaAllocator.init(c.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            var list: std.ArrayList(meta.Header) = .empty;
            var blk: std.ArrayList(u8) = .empty;
            if (up) {
                blk.append(arena, 0x88) catch return error.OutOfMemory;
            } else hpack.encodeLiteral(&blk, arena, ":status", "503") catch return error.OutOfMemory;
            list.append(arena, .{ .name = "content-type", .value = "text/plain; charset=utf-8" }) catch return error.OutOfMemory;
            var info: meta.Info = .{};
            const have = c.handler.getInfo(&info);
            meta.common(&list, arena, if (have) &info else null, (meta.monoNs() -| s.t0) / std.time.ns_per_ms) catch return error.OutOfMemory;
            list.append(arena, .{ .name = "content-length", .value = if (up) "2" else "4" }) catch return error.OutOfMemory;
            c.dateHeader(&list, arena) catch return error.OutOfMemory;
            c.encodeHeaders(&blk, arena, list.items) catch return error.OutOfMemory;
            const flags: u8 = if (with_body) flag_end_headers else flag_end_headers | flag_end_stream;
            c.frameHeader(blk.items.len, .headers, flags, s.id) catch return error.OutOfMemory;
            c.out.appendSlice(c.gpa, blk.items) catch return error.OutOfMemory;
        }
        if (!with_body) return c.dropStream(s.id);
        s.headers_sent = true;
        s.plain_end = true;
        s.out.appendSlice(c.gpa, body) catch return error.OutOfMemory;
        try c.flush(s);
    }

    fn dateHeader(_: *Conn, list: *std.ArrayList(meta.Header), arena: Allocator) !void {
        const d = try arena.create([29]u8);
        try list.append(arena, .{ .name = "date", .value = meta.httpDate(d, meta.unixS()) });
    }

    fn commonHeaders(c: *Conn, list: *std.ArrayList(meta.Header), arena: Allocator, s: *const Stream) !void {
        var info: meta.Info = .{};
        const have = c.handler.getInfo(&info);
        const dur = (meta.monoNs() -| s.t0) / std.time.ns_per_ms;
        try meta.common(list, arena, if (have) &info else null, dur);
        const d = try arena.create([29]u8);
        try list.append(arena, .{ .name = "date", .value = meta.httpDate(d, meta.unixS()) });
    }

    fn encodeHeaders(c: *Conn, blk: *std.ArrayList(u8), arena: Allocator, list: []const meta.Header) !void {
        _ = c;
        for (list) |h| try hpack.encodeLiteral(blk, arena, h.name, h.value);
    }

    /// Queues one frame (prefix and payload) on the stream: as is, or base64 for gRPC-web text.
    fn appendOut(c: *Conn, s: *Stream, parts: []const []const u8) !void {
        if (s.web_out != .text) {
            for (parts) |p| try s.out.appendSlice(c.gpa, p);
            return;
        }
        var n: usize = 0;
        for (parts) |p| n += p.len;
        const raw = try c.gpa.alloc(u8, n);
        defer c.gpa.free(raw);
        var o: usize = 0;
        for (parts) |p| {
            @memcpy(raw[o..][0..p.len], p);
            o += p.len;
        }
        const e = std.base64.standard.Encoder;
        const at = s.out.items.len;
        try s.out.resize(c.gpa, at + e.calcSize(n));
        _ = e.encode(s.out.items[at..], raw);
    }

    fn webContentType(s: *const Stream) []const u8 {
        return if (s.web_out == .text) "application/grpc-web-text+proto" else "application/grpc-web+proto";
    }

    fn setTrailersEx(c: *Conn, s: *Stream, status: Status, text: []const u8, details_bin: []const u8, reject_encoding: bool) ConnError!void {
        var arena_state = std.heap.ArenaAllocator.init(c.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var list: std.ArrayList(meta.Header) = .empty;
        var blk: std.ArrayList(u8) = .empty;
        // trailers-only: the response HEADERS carry :status and content-type too
        const trailers_only = !s.headers_sent and s.messages == 0 and status != .ok;
        if (trailers_only) s.obs.status(obs.grpcLabel(status), meta.monoNs());
        if (trailers_only) {
            blk.append(arena, 0x88) catch return error.OutOfMemory; // :status 200
            const ct = if (s.web_out != .none) webContentType(s) else "application/grpc";
            trailersOnlyHeaders(&list, arena, ct, status, text, details_bin, reject_encoding) catch return error.OutOfMemory;
            c.commonHeaders(&list, arena, s) catch return error.OutOfMemory;
        } else if (s.web_out != .none) {
            // gRPC-web: the trailers travel as a 0x80 frame at the end of the body
            statusHeaders(&list, arena, status, text, details_bin) catch return error.OutOfMemory;
            var tr: std.ArrayList(u8) = .empty;
            for (list.items) |h| {
                tr.appendSlice(arena, h.name) catch return error.OutOfMemory;
                tr.append(arena, ':') catch return error.OutOfMemory;
                tr.appendSlice(arena, h.value) catch return error.OutOfMemory;
                tr.appendSlice(arena, "\r\n") catch return error.OutOfMemory;
            }
            var th: [5]u8 = undefined;
            th[0] = 0x80;
            std.mem.writeInt(u32, th[1..5], @intCast(tr.items.len), .big);
            c.appendOut(s, &.{ &th, tr.items }) catch return error.OutOfMemory;
            s.plain_end = true;
            return c.flush(s);
        } else {
            statusHeaders(&list, arena, status, text, details_bin) catch return error.OutOfMemory;
        }
        c.encodeHeaders(&blk, arena, list.items) catch return error.OutOfMemory;
        if (s.trailers) |t| c.gpa.free(t);
        s.trailers = c.gpa.dupe(u8, blk.items) catch return error.OutOfMemory;
        if (trailers_only) s.headers_sent = true; // the trailers block already is the HEADERS
        s.trailers_only = trailers_only;
        try c.flush(s);
    }

    // ---- responses ----

    /// For deferred streams: queue one message (compressed with the stream's encoding) and send
    /// what the windows allow.
    pub fn push(c: *Conn, stream_id: u32, payload: []const u8) !void {
        const s = c.streams.get(stream_id) orelse return error.StreamClosed;
        if (s.reset or s.ended()) return error.StreamClosed;
        var hdr: [5]u8 = undefined;
        if (s.encoding != .identity) {
            const z = try codec.compress(c.gpa, s.encoding, payload);
            defer c.gpa.free(z);
            hdr[0] = 1;
            std.mem.writeInt(u32, hdr[1..5], @intCast(z.len), .big);
            try c.appendOut(s, &.{ &hdr, z });
        } else {
            hdr[0] = 0;
            std.mem.writeInt(u32, hdr[1..5], @intCast(payload.len), .big);
            try c.appendOut(s, &.{ &hdr, payload });
        }
        s.messages += 1;
        try c.flush(s);
    }

    /// For deferred streams: end the stream with a status.
    pub fn finish(c: *Conn, stream_id: u32, status: Status, text: []const u8) !void {
        return c.finishDetails(stream_id, status, text, "");
    }

    pub fn finishDetails(c: *Conn, stream_id: u32, status: Status, text: []const u8, details_bin: []const u8) !void {
        const s = c.streams.get(stream_id) orelse return;
        if (s.ended()) return;
        c.setTrailersEx(s, status, text, details_bin, false) catch return error.OutOfMemory;
    }

    /// For deferred streams: send the response HEADERS now (a server stream's headers go out
    /// when it is established, before its first message).
    pub fn open(c: *Conn, stream_id: u32) !void {
        const s = c.streams.get(stream_id) orelse return error.StreamClosed;
        try c.flush(s);
    }

    /// For deferred streams: framed response bytes still waiting for flow-control window
    /// (null once the stream is gone, e.g. reset by the peer).
    pub fn unsent(c: *const Conn, stream_id: u32) ?usize {
        const s = c.streams.get(stream_id) orelse return null;
        if (s.reset) return null;
        return s.out.items.len - s.out_off;
    }

    pub fn streamOpen(c: *const Conn, stream_id: u32) bool {
        return c.streams.get(stream_id) != null;
    }

    fn flushAll(c: *Conn) ConnError!void {
        var ids: std.ArrayList(u32) = .empty;
        defer ids.deinit(c.gpa);
        var it = c.streams.valueIterator();
        while (it.next()) |s| {
            if (s.*.out.items.len > s.*.out_off or s.*.trailers != null or s.*.plain_end) ids.append(c.gpa, s.*.id) catch return error.OutOfMemory;
        }
        for (ids.items) |id| if (c.streams.get(id)) |s| try c.flush(s);
    }

    fn responseHeaders(c: *Conn, s: *Stream) ConnError!void {
        var arena_state = std.heap.ArenaAllocator.init(c.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var list: std.ArrayList(meta.Header) = .empty;
        list.append(arena, .{ .name = "content-type", .value = if (s.web_out != .none) webContentType(s) else "application/grpc" }) catch return error.OutOfMemory;
        if (s.encoding != .identity) list.append(arena, .{ .name = "grpc-encoding", .value = s.encoding.name() }) catch return error.OutOfMemory;
        c.commonHeaders(&list, arena, s) catch return error.OutOfMemory;
        var blk: std.ArrayList(u8) = .empty;
        blk.append(arena, 0x88) catch return error.OutOfMemory;
        c.encodeHeaders(&blk, arena, list.items) catch return error.OutOfMemory;
        c.frameHeader(blk.items.len, .headers, flag_end_headers, s.id) catch return error.OutOfMemory;
        c.out.appendSlice(c.gpa, blk.items) catch return error.OutOfMemory;
        s.headers_sent = true;
        s.obs.status(obs.grpcLabel(.ok), meta.monoNs());
    }

    fn flush(c: *Conn, s: *Stream) ConnError!void {
        if (!s.headers_sent) try c.responseHeaders(s);
        while (s.out.items.len > s.out_off) {
            const avail = s.out.items.len - s.out_off;
            const win = @min(c.conn_send_window, s.send_window);
            if (win <= 0) break;
            // The send bound: the rest stays in the stream until the socket takes some
            // (`consumed`). A frame is cut to the room left only above the 16,384 bytes every
            // peer accepts, so default-sized frames keep their size.
            const room = c.opts.max_out_bytes -| c.pending().len;
            if (room == 0) {
                c.out_blocked = true;
                break;
            }
            const cap: i64 = @intCast(@min(@max(room, 16384), @as(usize, c.peer_max_frame)));
            const n: usize = @intCast(@min(@min(@as(i64, @intCast(avail)), win), cap));
            s.obs.firstChunk(meta.monoNs());
            c.frameHeader(n, .data, 0, s.id) catch return error.OutOfMemory;
            c.out.appendSlice(c.gpa, s.out.items[s.out_off..][0..n]) catch return error.OutOfMemory;
            s.out_off += n;
            c.conn_send_window -= @intCast(n);
            s.send_window -= @intCast(n);
        }
        if (s.out_off == s.out.items.len) {
            s.out.clearRetainingCapacity();
            s.out_off = 0;
            if (s.trailers) |t| {
                // trailers-only: the stream's only HEADERS (:status, content-type and the status)
                c.frameHeader(t.len, .headers, flag_end_headers | flag_end_stream, s.id) catch return error.OutOfMemory;
                c.out.appendSlice(c.gpa, t) catch return error.OutOfMemory;
                c.dropStream(s.id);
            } else if (s.plain_end) {
                c.frameHeader(0, .data, flag_end_stream, s.id) catch return error.OutOfMemory;
                c.dropStream(s.id);
            }
        }
    }
};
