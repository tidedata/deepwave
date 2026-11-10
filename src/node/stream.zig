//! Live checkpoint stream: `sui.rpc.v2.SubscriptionService/SubscribeCheckpoints` from a public
//! full node (default `https://fullnode.mainnet.sui.io`), over gRPC-web on HTTP/1.1 (std.http; the
//! endpoint answers `application/grpc-web+proto` with a chunked body, one frame per checkpoint).
//!
//! Why: Mysten's checkpoint bucket sees a checkpoint about 100 ms after Mysten's full node
//! streams it (measured on a production node 2026-11-08: stream arrival p50 594 ms after the
//! checkpoint timestamp, bucket 758 ms; our sui-node's sampled tip age p50 605 ms). Apply mode
//! needs the output objects, which p2p state sync does not carry (sync/peers.zig), so the
//! earliest full checkpoint we can get without executing is this stream.
//!
//! Untrusted like every source: each message is converted to a blob exactly as the bucket's
//! files are (`convert.protoToChkAux`) and the follower verifies it (digests, certificate,
//! effects against output objects) before the store sees it. `deepwave stream-check` compares
//! the stream's blobs with the bucket's byte for byte.
//!
//! Every connect and read is bounded (netguard.timed: `open_timeout_ms`, `stall_ms`) and every
//! failed or empty connection backs off (`Pacer`, shared by both workers), so a silent peer, a
//! refusing server or a shutdown never hangs or spins a worker.
//!
//! The stream starts at the newest checkpoint (no resume cursor) and Google's front end ends
//! HTTP/1.1 responses after about 30 s, so it reconnects at once and the bucket poller
//! (source.zig) fills whatever a reconnect skipped. While the stream delivers, the poller backs
//! off (`Fetcher.streamLive`).
const std = @import("std");
const Io = std.Io;
const source = @import("source.zig");
const netguard = @import("netguard.zig");
const reconcile = @import("reconcile.zig");
const Atomic = std.atomic.Value;

pub const default_url = "https://fullnode.mainnet.sui.io";

/// The fields `convert.protoToChkAux` reads: the `bcs` of summary, contents, transactions,
/// effects, events and objects, the certificate, and the loaded runtime objects (aux).
pub const read_mask = [_][]const u8{
    "sequence_number",
    "summary.bcs",
    "signature",
    "contents.bcs",
    "transactions.transaction.bcs",
    // the serving node's stored signature order (convert.txSignatures)
    "transactions.signatures.bcs",
    "transactions.effects.bcs",
    "transactions.effects.unchanged_loaded_runtime_objects",
    "transactions.events.bcs",
    "objects.objects.bcs",
};

pub const Stats = struct {
    connects: Atomic(u64) = .init(0),
    /// Connection attempts that failed (network, timeout, HTTP status, gRPC status in the head).
    connect_errors: Atomic(u64) = .init(0),
    /// Connections that ended without delivering a message (a refusal in the trailers, an empty
    /// body, a transport error before the first message). Paced like connect errors.
    empty_ends: Atomic(u64) = .init(0),
    /// Connections cut after `stall_ms` without a message (a peer that went silent).
    stalls: Atomic(u64) = .init(0),
    /// Malformed, oversized or compressed frames, non-zero grpc-status trailers.
    protocol_errors: Atomic(u64) = .init(0),
    /// Streams that ended (the front end's ~30 s cut, or an error mid-stream).
    ends: Atomic(u64) = .init(0),
    messages: Atomic(u64) = .init(0),
    bytes: Atomic(u64) = .init(0),
    /// Checkpoints the stream wrote to the spool first.
    delivered: Atomic(u64) = .init(0),
    /// Already fetched or claimed by the bucket poller.
    dups: Atomic(u64) = .init(0),
    /// Outside the fetch window (the node is catching up; the bucket serves those).
    skipped: Atomic(u64) = .init(0),
    /// Messages that did not convert (the follower would have rejected them anyway).
    bad: Atomic(u64) = .init(0),
    decode_ns: Atomic(u64) = .init(0),
};

pub const Msg = struct {
    /// `SubscribeCheckpointsResponse.cursor` (the checkpoint's sequence number).
    cursor: ?u64,
    /// `SubscribeCheckpointsResponse.checkpoint`: a `sui.rpc.v2.Checkpoint` proto.
    checkpoint: []const u8,
};

/// The grpc-web request body: one uncompressed frame of `SubscribeCheckpointsRequest { read_mask }`.
pub fn requestBody(gpa: std.mem.Allocator) ![]u8 {
    var mask: std.ArrayList(u8) = .empty;
    defer mask.deinit(gpa);
    for (read_mask) |p| try putLen(gpa, &mask, 1, p); // FieldMask.paths = 1
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try putLen(gpa, &msg, 1, mask.items); // SubscribeCheckpointsRequest.read_mask = 1
    const out = try gpa.alloc(u8, 5 + msg.items.len);
    out[0] = 0;
    std.mem.writeInt(u32, out[1..5], @intCast(msg.items.len), .big);
    @memcpy(out[5..], msg.items);
    return out;
}

fn putLen(gpa: std.mem.Allocator, out: *std.ArrayList(u8), field: u32, bytes: []const u8) !void {
    try putVarint(gpa, out, (field << 3) | 2);
    try putVarint(gpa, out, bytes.len);
    try out.appendSlice(gpa, bytes);
}

fn putVarint(gpa: std.mem.Allocator, out: *std.ArrayList(u8), v_in: u64) !void {
    var v = v_in;
    while (v >= 0x80) : (v >>= 7) try out.append(gpa, @as(u8, @truncate(v)) | 0x80);
    try out.append(gpa, @truncate(v));
}

fn varint(b: []const u8, i: *usize) !u64 {
    var r: u64 = 0;
    var shift: u6 = 0;
    while (i.* < b.len) {
        const x = b[i.*];
        i.* += 1;
        r |= @as(u64, x & 0x7f) << shift;
        if (x < 0x80) return r;
        if (shift >= 63) return error.Malformed;
        shift += 7;
    }
    return error.Malformed;
}

/// Splits a `SubscribeCheckpointsResponse` into its cursor and checkpoint.
pub fn parseResponse(b: []const u8) !Msg {
    var m: Msg = .{ .cursor = null, .checkpoint = &.{} };
    var i: usize = 0;
    while (i < b.len) {
        const key = try varint(b, &i);
        switch (key & 7) {
            0 => {
                const v = try varint(b, &i);
                if (key >> 3 == 1) m.cursor = v;
            },
            1 => i += 8,
            5 => i += 4,
            2 => {
                const n = try varint(b, &i);
                if (n > b.len - i) return error.Malformed;
                if (key >> 3 == 2) m.checkpoint = b[i..][0..n];
                i += n;
            },
            else => return error.Malformed,
        }
        if (i > b.len) return error.Malformed;
    }
    return m;
}

/// `dst` with every top-level occurrence of `field` replaced by those of `src` (both protos).
/// stream-check uses it to tell "differs only in the certificate" (field 4, `signature`: two
/// nodes can hold different, equally valid aggregate signatures for one checkpoint) from a real
/// difference.
pub fn replaceField(a: std.mem.Allocator, dst: []const u8, src: []const u8, field: u64) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ dst, src }, [_]bool{ false, true }) |b, want| {
        var i: usize = 0;
        while (i < b.len) {
            const start = i;
            const key = try varint(b, &i);
            switch (key & 7) {
                0 => _ = try varint(b, &i),
                1 => i += 8,
                5 => i += 4,
                2 => {
                    const n = try varint(b, &i);
                    if (n > b.len - i) return error.Malformed;
                    i += n;
                },
                else => return error.Malformed,
            }
            if (i > b.len) return error.Malformed;
            if ((key >> 3 == field) == want) try out.appendSlice(a, b[start..i]);
        }
    }
    return out.items;
}

/// A gRPC status the server sent in the response head (a trailers-only response: HTTP 200,
/// `grpc-status` among the headers, no body). sui-rpc-api answers that way when it refuses a
/// subscription: UNAVAILABLE "subscription service is unavailable" at `max_subscribers`,
/// UNIMPLEMENTED on a node without the subscription service, a front end's RESOURCE_EXHAUSTED.
pub const HeadStatus = struct {
    code: u32,
    message: []const u8,
};

/// The non-zero `grpc-status` in a response head, if any (null: none, or 0).
pub fn headStatus(head: std.http.Client.Response.Head) ?HeadStatus {
    var code: ?u32 = null;
    var message: []const u8 = "";
    var it = head.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "grpc-status")) {
            code = std.fmt.parseInt(u32, std.mem.trim(u8, h.value, " "), 10) catch 2; // UNKNOWN
        } else if (std.ascii.eqlIgnoreCase(h.name, "grpc-message")) message = h.value;
    }
    const c = code orelse return null;
    if (c == 0) return null;
    return .{ .code = c, .message = message };
}

/// One open stream. Pinned in memory while open (the response reader points into `req`).
pub const Conn = struct {
    req: std.http.Client.Request,
    reader: *std.Io.Reader,
    transfer: [64 * 1024]u8,
    buf: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,
    /// Why the server refused or ended the stream with an error (a non-zero grpc-status in the
    /// head or the trailers, or an HTTP status), for the caller's log.
    why: [160]u8 = undefined,
    why_len: usize = 0,
    /// The stream ended with a non-zero grpc-status trailer.
    failed_status: bool = false,

    pub fn reason(c: *const Conn) []const u8 {
        return c.why[0..c.why_len];
    }

    fn setWhy(c: *Conn, comptime fmt: []const u8, args: anytype) void {
        c.why_len = if (std.fmt.bufPrint(&c.why, fmt, args)) |t| t.len else |_| c.why.len;
    }

    /// `abort`, when given, gets the connection's socket for as long as it is open (the caller
    /// disarms it before `close`), so a timed wait can wake a blocked read (netguard.Abort).
    pub fn open(c: *Conn, gpa: std.mem.Allocator, client: *std.http.Client, base: []const u8, body: []u8, abort: ?*netguard.Abort) !void {
        var ub: [256]u8 = undefined;
        const url = try std.fmt.bufPrint(&ub, "{s}/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", .{base});
        const uri = try std.Uri.parse(url);
        c.* = .{ .req = undefined, .reader = undefined, .transfer = undefined, .gpa = gpa };
        c.req = try client.request(.POST, uri, .{
            .keep_alive = false,
            .redirect_behavior = .unhandled,
            .headers = .{ .content_type = .{ .override = "application/grpc-web+proto" }, .accept_encoding = .omit, .user_agent = .{ .override = "deepwave" } },
            .extra_headers = &.{
                .{ .name = "x-grpc-web", .value = "1" },
                .{ .name = "accept", .value = "application/grpc-web+proto" },
            },
        });
        errdefer c.req.deinit();
        if (abort) |a| try a.arm(netguard.socketOf(c.req.connection.?));
        errdefer if (abort) |a| a.disarm();
        try c.req.sendBodyComplete(body);
        var res = try c.req.receiveHead(&.{});
        if (res.head.status != .ok) {
            c.setWhy("HTTP {d}", .{@intFromEnum(res.head.status)});
            return error.HttpStatus;
        }
        if (headStatus(res.head)) |st| {
            c.setWhy("grpc-status {d}: {s}", .{ st.code, st.message[0..@min(st.message.len, 120)] });
            return error.GrpcStatus;
        }
        c.reader = res.reader(&c.transfer);
    }

    /// The next message, or null when the server ended the stream (trailers or end of body). A
    /// non-zero grpc-status trailer sets `failed_status` and `reason()`.
    pub fn next(c: *Conn) !?Msg {
        var hdr: [5]u8 = undefined;
        c.reader.readSliceAll(&hdr) catch |e| switch (e) {
            error.EndOfStream => return null,
            else => return e,
        };
        const n = std.mem.readInt(u32, hdr[1..5], .big);
        if (n > source.max_blob) return error.FrameTooLarge;
        try c.buf.resize(c.gpa, n);
        try c.reader.readSliceAll(c.buf.items);
        if (hdr[0] & 0x80 != 0) {
            // Trailers: `grpc-status:0` is a clean end.
            const t = c.buf.items;
            if (std.mem.indexOf(u8, t, "grpc-status:0") == null and std.mem.indexOf(u8, t, "grpc-status: 0") == null) {
                c.failed_status = true;
                var flat: [120]u8 = undefined;
                const shown = t[0..@min(t.len, flat.len)];
                for (shown, 0..) |b, i| flat[i] = if (b == '\r' or b == '\n') ' ' else b;
                c.setWhy("trailers: {s}", .{std.mem.trim(u8, flat[0..shown.len], " ")});
            }
            return null;
        }
        if (hdr[0] & 1 != 0) return error.CompressedFrame; // never asked for
        return try parseResponse(c.buf.items);
    }

    pub fn close(c: *Conn) void {
        c.req.deinit();
        c.buf.deinit(c.gpa);
    }
};

/// Retry pacing shared by a stream's workers: a failed connection (refused, no checkpoints, cut
/// for silence, a protocol error) moves `retry_at` out by the current backoff and doubles it; a
/// connection that delivers a checkpoint resets it. Both workers wait for `retry_at` before they
/// open, so a server that keeps refusing gets one attempt per backoff, not a reconnect loop.
pub const Pacer = struct {
    backoff_ms: Atomic(u64) = .init(min_backoff_ms),
    retry_at_ms: Atomic(u64) = .init(0),

    pub const min_backoff_ms: u64 = 250;
    pub const max_backoff_ms: u64 = 30_000;

    /// Records a failure at `now_ms`; returns the wait it set.
    pub fn failed(p: *Pacer, now_ms: u64) u64 {
        const b = p.backoff_ms.load(.acquire);
        p.retry_at_ms.store(now_ms + b, .release);
        p.backoff_ms.store(@min(b * 2, max_backoff_ms), .release);
        return b;
    }

    pub fn delivered(p: *Pacer) void {
        p.backoff_ms.store(min_backoff_ms, .release);
    }

    /// Ms to wait at `now_ms` before the next open (0: go).
    pub fn waitMs(p: *const Pacer, now_ms: u64) u64 {
        return p.retry_at_ms.load(.acquire) -| now_ms;
    }
};

/// How a connection ended, for pacing.
pub const End = enum {
    /// Normal: the server's cut or our handoff, after it delivered checkpoints.
    ok,
    /// Delivered nothing (refused in the head or the trailers, or empty).
    empty,
    /// Nothing for `stall_ms`: the peer went silent (lost FIN/RST, stalled front end).
    stall,
    /// A malformed, oversized or compressed frame, or a non-zero grpc-status trailer.
    protocol,
    stopped,
};

pub fn classify(msgs: u64, err: ?anyerror, failed_status: bool) End {
    if (err) |e| return switch (e) {
        error.Stopped => .stopped,
        error.Timeout => .stall,
        error.FrameTooLarge, error.CompressedFrame, error.Malformed => .protocol,
        // Transport errors after checkpoints flowed are how a front end's cut can look.
        else => if (msgs == 0) .empty else .ok,
    };
    if (failed_status) return .protocol;
    return if (msgs == 0) .empty else .ok;
}

/// Feeds the fetcher's spool from the stream on its own threads.
pub const Stream = struct {
    gpa: std.mem.Allocator,
    io: Io,
    base: []const u8 = default_url,
    fetcher: *source.Fetcher,
    /// Takes the duplicates of checkpoints p2p delivered first (reconcile.zig); null: dropped.
    reconcile: ?*reconcile.Reconciler = null,
    stats: Stats = .{},
    stopping: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    /// The second worker (make-before-break, see `run`).
    thread2: ?std.Thread = null,
    /// Which worker opens the next connection (0 or 1).
    turn: Atomic(u8) = .init(0),
    /// Two workers run (false if the second could not be spawned: worker 0 reconnects alone).
    pair: Atomic(bool) = .init(true),
    /// A connection hands over to the other worker after this long, and closes itself
    /// `overlap_ms` later once the successor delivers (or when the server ends it, whichever is
    /// first). Google's front end ends HTTP/1.1 responses at ~30 s; a plain reconnect then loses
    /// the checkpoints of one round trip plus the stream's startup (measured: 80 reconnects and
    /// ~2.6% of checkpoints left to the bucket in 40 min), which shows in the p90/p99 tip age.
    handoff_ms: u64 = 24_000,
    overlap_ms: u64 = 8_000,
    /// Connect, TLS handshake, request and response head must finish within this.
    open_timeout_ms: u64 = 10_000,
    /// A connection that delivers nothing for this long is cut and counted as a stall
    /// (checkpoints come about 4 a second; epoch changes pause the chain ~1-2 s).
    stall_ms: u64 = 5_000,
    pacer: Pacer = .{},
    /// Per worker: its current connection has delivered a message.
    flowing: [2]Atomic(bool) = .{ .init(false), .init(false) },
    /// Per worker: wall ms when its current open started (0: not opening). A worker whose open
    /// outlives twice `open_timeout_ms` (the residual case netguard.Abort cannot reach: a cancel
    /// lost in the connect and a peer gone mid-handshake) loses the turn to the other.
    opening_ms: [2]Atomic(u64) = .{ .init(0), .init(0) },
    warned_ms: Atomic(u64) = .init(0),

    pub fn start(s: *Stream) !void {
        s.pair.store(true, .release);
        s.thread = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, run, .{ s, @as(u8, 0) });
        s.thread2 = std.Thread.spawn(.{ .stack_size = 8 << 20 }, run, .{ s, @as(u8, 1) }) catch blk: {
            s.pair.store(false, .release);
            break :blk null;
        };
    }

    /// Joins the workers. Every wait they make is bounded (`netguard.timed` checks the flag every
    /// 100 ms and cancels a blocked connect or read), so this returns in about 100 ms.
    pub fn stop(s: *Stream) void {
        s.stopping.store(true, .release);
        if (s.thread) |t| t.join();
        if (s.thread2) |t| t.join();
        s.thread = null;
        s.thread2 = null;
    }

    fn sleepMs(s: *Stream, ms: u64) void {
        var left = ms;
        while (left > 0 and !s.stopping.load(.acquire)) {
            const d = @min(left, 100);
            s.io.sleep(.fromMilliseconds(@intCast(d)), .awake) catch {};
            left -= d;
        }
    }

    /// A failed connection: pace the next attempt (both workers) and log, at most once a minute.
    fn failed(s: *Stream, what: []const u8, why: []const u8) void {
        const now = source.wallMs();
        const wait = s.pacer.failed(now);
        const last = s.warned_ms.load(.monotonic);
        if (now -| last > 60_000 and s.warned_ms.cmpxchgStrong(last, now, .monotonic, .monotonic) == null)
            std.log.warn("stream {s}: {s}{s}{s}; retrying in {d} ms, the bucket carries the tip meanwhile", .{ s.base, what, if (why.len > 0) ": " else "", why, wait });
    }

    /// Worker `slot` of two. Make-before-break: a worker connects when it is its turn, passes the
    /// turn to the other after `handoff_ms`, and keeps reading until the server ends the stream
    /// or, once the successor delivers, `overlap_ms` more have passed, so a new stream is already
    /// flowing when the old one is cut. Both feed the same claims, so the overlap costs
    /// bandwidth, not decodes. With one worker (the second failed to spawn) it reconnects in a
    /// loop. Every connect and read is bounded (`open_timeout_ms`, `stall_ms`), and failures
    /// back off through `pacer`.
    fn run(s: *Stream, slot: u8) void {
        const body = requestBody(s.gpa) catch return;
        defer s.gpa.free(body);
        var sc = source.Scratch.init(s.gpa);
        defer sc.deinit(s.gpa);
        var blob: std.ArrayList(u8) = .empty;
        defer blob.deinit(s.gpa);
        const c = s.gpa.create(Conn) catch return;
        defer s.gpa.destroy(c);
        // One client per worker: its TLS clock can be refreshed without racing another thread.
        var client = netguard.Client.init(s.gpa, s.io);
        defer client.deinit();
        var ab: netguard.Abort = .{};
        while (!s.stopping.load(.acquire)) {
            const solo = !s.pair.load(.acquire);
            if (!solo and s.turn.load(.acquire) != slot) {
                const since = s.opening_ms[slot ^ 1].load(.acquire);
                if (since != 0 and source.wallMs() -| since > 2 * s.open_timeout_ms) {
                    s.turn.store(slot, .release); // the other worker is stuck in its open
                } else {
                    s.sleepMs(20);
                    continue;
                }
            }
            const wait = s.pacer.waitMs(source.wallMs());
            if (wait > 0) {
                s.sleepMs(@min(wait, 100));
                continue;
            }
            client.prepare(source.wallMs());
            c.why_len = 0;
            ab.reset();
            s.opening_ms[slot].store(source.wallMs(), .release);
            const opened_ok = netguard.timed(s.io, s.open_timeout_ms, &s.stopping, &ab, Conn.open, .{ c, s.gpa, &client.http, s.base, body, &ab });
            s.opening_ms[slot].store(0, .release);
            opened_ok catch |e| {
                if (e == error.Stopped) break;
                client.noteError(e, source.wallMs());
                _ = s.stats.connect_errors.fetchAdd(1, .monotonic);
                s.failed(@errorName(e), c.reason());
                continue;
            };
            _ = s.stats.connects.fetchAdd(1, .monotonic);
            const opened = source.wallMs();
            var handed = false;
            var msgs: u64 = 0;
            var end_err: ?anyerror = null;
            while (!s.stopping.load(.acquire)) {
                const got = netguard.timed(s.io, s.stall_ms, &s.stopping, &ab, Conn.next, .{c}) catch |e| {
                    end_err = e;
                    break;
                };
                const m = got orelse break;
                if (msgs == 0) {
                    s.pacer.delivered();
                    s.flowing[slot].store(true, .release);
                }
                msgs += 1;
                s.handle(m, &sc, &blob);
                const age = source.wallMs() -| opened;
                if (!solo and !handed and age >= s.handoff_ms) {
                    handed = true;
                    s.turn.store(slot ^ 1, .release);
                }
                if (handed and age >= s.handoff_ms + s.overlap_ms and s.flowing[slot ^ 1].load(.acquire)) break;
            }
            s.flowing[slot].store(false, .release);
            const failed_status = c.failed_status;
            var why_buf: [160]u8 = undefined;
            const why = why_buf[0..c.why_len];
            @memcpy(why, c.reason());
            ab.disarm();
            c.close();
            _ = s.stats.ends.fetchAdd(1, .monotonic);
            switch (classify(msgs, end_err, failed_status)) {
                .ok, .stopped => {},
                .empty => {
                    _ = s.stats.empty_ends.fetchAdd(1, .monotonic);
                    s.failed(if (end_err) |e| @errorName(e) else "ended with no checkpoints", why);
                },
                .stall => {
                    _ = s.stats.stalls.fetchAdd(1, .monotonic);
                    s.failed("no message", "stalled, connection cut");
                },
                .protocol => {
                    _ = s.stats.protocol_errors.fetchAdd(1, .monotonic);
                    s.failed(if (end_err) |e| @errorName(e) else "stream ended", why);
                },
            }
            // Ended before the handoff (server cut, error, stall): the other worker connects now.
            if (!solo and !handed) s.turn.store(slot ^ 1, .release);
        }
    }

    /// A checkpoint another source delivered first. When that source was p2p the read sets in
    /// the store are deepwave's own: this copy carries sui-node's, which reconcile.zig compares.
    fn duplicate(s: *Stream, seq: u64, m: Msg, sc: *source.Scratch, blob: *std.ArrayList(u8)) void {
        const r = s.reconcile orelse return;
        if (!r.wantsCopy(seq)) return;
        _ = sc.arena.reset(.retain_capacity);
        source.decodeProto(s.gpa, sc, m.checkpoint, seq, blob) catch {
            _ = s.stats.bad.fetchAdd(1, .monotonic);
            return;
        };
        r.offer(seq, sc.aux.items, .stream);
    }

    /// One stream message: spooled when the stream has it first, else a duplicate.
    pub fn handle(s: *Stream, m: Msg, sc: *source.Scratch, blob: *std.ArrayList(u8)) void {
        const f = s.fetcher;
        _ = s.stats.messages.fetchAdd(1, .monotonic);
        _ = s.stats.bytes.fetchAdd(m.checkpoint.len, .monotonic);
        const seq = m.cursor orelse {
            _ = s.stats.bad.fetchAdd(1, .monotonic);
            return;
        };
        f.noteSeen(seq, .stream);
        if (!f.wants(seq)) {
            const lo = f.applied_next.load(.acquire);
            if (seq >= lo + f.window) {
                _ = s.stats.skipped.fetchAdd(1, .monotonic);
            } else {
                _ = s.stats.dups.fetchAdd(1, .monotonic);
                s.duplicate(seq, m, sc, blob);
            }
            return;
        }
        if (!f.markDone(seq)) {
            _ = s.stats.dups.fetchAdd(1, .monotonic);
            s.duplicate(seq, m, sc, blob);
            return;
        }
        f.noteArrival(seq);
        const t0 = source.nowNs();
        _ = sc.arena.reset(.retain_capacity);
        source.decodeProto(s.gpa, sc, m.checkpoint, seq, blob) catch |e| {
            f.unmarkDone(seq);
            _ = s.stats.bad.fetchAdd(1, .monotonic);
            std.log.warn("stream checkpoint {d}: {s}; left to the bucket", .{ seq, @errorName(e) });
            return;
        };
        _ = s.stats.decode_ns.fetchAdd(source.nowNs() - t0, .monotonic);
        f.writeSpool(seq, blob.items, sc.aux.items) catch |e| {
            f.unmarkDone(seq);
            std.log.warn("stream spool {d}: {s}", .{ seq, @errorName(e) });
            return;
        };
        _ = s.stats.delivered.fetchAdd(1, .monotonic);
        f.delivered(seq);
    }
};

test "stream: request body and response parsing" {
    const gpa = std.testing.allocator;
    const body = try requestBody(gpa);
    defer gpa.free(body);
    try std.testing.expectEqual(@as(u8, 0), body[0]);
    try std.testing.expectEqual(@as(usize, body.len - 5), std.mem.readInt(u32, body[1..5], .big));
    // read_mask (field 1, len) wrapping paths (field 1, len) "sequence_number" first.
    try std.testing.expectEqual(@as(u8, 0x0a), body[5]);
    try std.testing.expect(std.mem.indexOf(u8, body, "objects.objects.bcs") != null);
    // cursor = 342937851 (varint), checkpoint = { 08 01 }.
    var r: std.ArrayList(u8) = .empty;
    defer r.deinit(gpa);
    try putVarint(gpa, &r, 1 << 3);
    try putVarint(gpa, &r, 342937851);
    try putLen(gpa, &r, 2, &.{ 0x08, 0x01 });
    const m = try parseResponse(r.items);
    try std.testing.expectEqual(@as(?u64, 342937851), m.cursor);
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0x01 }, m.checkpoint);
    try std.testing.expectError(error.Malformed, parseResponse(&.{ 0x12, 0x05, 0x00 }));
}

test "stream: a trailers-only refusal in the head is an error, with its status" {
    const head = try std.http.Client.Response.Head.parse("HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ngrpc-status: 14\r\ngrpc-message: subscription service is unavailable\r\ncontent-length: 0\r\n\r\n");
    const st = headStatus(head).?;
    try std.testing.expectEqual(@as(u32, 14), st.code);
    try std.testing.expectEqualStrings("subscription service is unavailable", st.message);
    const ok = try std.http.Client.Response.Head.parse("HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ntransfer-encoding: chunked\r\n\r\n");
    try std.testing.expect(headStatus(ok) == null);
    const zero = try std.http.Client.Response.Head.parse("HTTP/1.1 200 OK\r\ngrpc-status: 0\r\n\r\n");
    try std.testing.expect(headStatus(zero) == null);
}

test "stream: pacing doubles to 30 s on failures and resets on delivery; classify" {
    var p: Pacer = .{};
    try std.testing.expectEqual(@as(u64, 0), p.waitMs(1000));
    try std.testing.expectEqual(@as(u64, 250), p.failed(1000));
    try std.testing.expectEqual(@as(u64, 250), p.waitMs(1000));
    try std.testing.expectEqual(@as(u64, 500), p.failed(1000));
    var last: u64 = 0;
    for (0..20) |_| last = p.failed(1000);
    try std.testing.expectEqual(Pacer.max_backoff_ms, last);
    p.delivered();
    try std.testing.expectEqual(@as(u64, 250), p.failed(5000));
    try std.testing.expectEqual(End.empty, classify(0, null, false));
    try std.testing.expectEqual(End.empty, classify(0, error.EndOfStream, false));
    try std.testing.expectEqual(End.ok, classify(40, null, false));
    try std.testing.expectEqual(End.ok, classify(40, error.ReadFailed, false));
    try std.testing.expectEqual(End.stall, classify(40, error.Timeout, false));
    try std.testing.expectEqual(End.protocol, classify(40, error.FrameTooLarge, false));
    try std.testing.expectEqual(End.protocol, classify(40, null, true));
    try std.testing.expectEqual(End.stopped, classify(0, error.Stopped, false));
}

fn runAgainst(srv: *netguard.TestServer, ms: u64, open_timeout_ms: u64, stall_ms: u64) !*Stream {
    const gpa = std.testing.allocator;
    const st = try gpa.create(Stream);
    var ub: [64]u8 = undefined;
    // `fetcher` is never touched: no message reaches `handle` in these tests.
    st.* = .{ .gpa = gpa, .io = std.testing.io, .base = try gpa.dupe(u8, srv.url(&ub)), .fetcher = undefined, .open_timeout_ms = open_timeout_ms, .stall_ms = stall_ms };
    try st.start();
    std.testing.io.sleep(.fromMilliseconds(@intCast(ms)), .awake) catch {};
    const t0 = netguard.wallMs();
    st.stop();
    // Shutdown never waits on a socket.
    try std.testing.expect(netguard.wallMs() - t0 < 1500);
    return st;
}

fn freeStream(st: *Stream) void {
    std.testing.allocator.free(st.base);
    std.testing.allocator.destroy(st);
}

test "stream: a server that refuses in the head gets paced attempts, not a reconnect loop" {
    var srv: netguard.TestServer = undefined;
    try srv.start(std.testing.io, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ngrpc-status: 14\r\ngrpc-message: subscription service is unavailable\r\ncontent-length: 0\r\n\r\n");
    defer srv.stop();
    const st = try runAgainst(&srv, 1600, 2000, 2000);
    defer freeStream(st);
    // 250 + 500 + 1000 ms of backoff fit about 4 attempts in 1.6 s (unpaced: thousands).
    const n = st.stats.connect_errors.load(.monotonic);
    try std.testing.expect(n >= 2 and n <= 5);
    try std.testing.expectEqual(@as(u64, 0), st.stats.connects.load(.monotonic));
    try std.testing.expect(srv.accepts.load(.monotonic) <= 5);
}

test "stream: an empty stream (trailers-only, no status) is paced too" {
    var srv: netguard.TestServer = undefined;
    try srv.start(std.testing.io, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: 0\r\n\r\n");
    defer srv.stop();
    const st = try runAgainst(&srv, 1600, 2000, 2000);
    defer freeStream(st);
    const n = st.stats.empty_ends.load(.monotonic);
    try std.testing.expect(n >= 2 and n <= 5);
    try std.testing.expectEqual(n, st.stats.connects.load(.monotonic));
}

test "stream: a silent peer is cut at the open timeout and after the head at stall_ms" {
    {
        // Accepts, never answers: the open (request + head) times out.
        var srv: netguard.TestServer = undefined;
        try srv.start(std.testing.io, null);
        defer srv.stop();
        const st = try runAgainst(&srv, 1200, 300, 300);
        defer freeStream(st);
        try std.testing.expect(st.stats.connect_errors.load(.monotonic) >= 1);
        try std.testing.expectEqual(@as(u64, 0), st.stats.connects.load(.monotonic));
    }
    {
        // Answers the head, then goes silent mid-stream: the read is cut at stall_ms.
        var srv: netguard.TestServer = undefined;
        try srv.startOpts(std.testing.io, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ntransfer-encoding: chunked\r\n\r\n", true);
        defer srv.stop();
        const st = try runAgainst(&srv, 1200, 2000, 300);
        defer freeStream(st);
        try std.testing.expect(st.stats.stalls.load(.monotonic) >= 1);
        try std.testing.expect(st.stats.connects.load(.monotonic) >= 1);
    }
}
