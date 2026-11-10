//! Sponsored and multi-signer transactions: the submitted signature order for checkpoints the
//! bucket fills.
//!
//! sui-node 1.83.1 answers a transaction's `signatures` (GetTransaction, BatchGetTransactions,
//! GetCheckpoint transactions, subscriptions) from its stored transaction, in the order the
//! submitter sent. Checkpoint contents certify the same signatures in signer order (sender, then
//! sponsor), and Mysten's bucket protos carry only the contents, so a checkpoint converted from
//! the bucket stores e.g. [sender, sponsor] where sui-node has [sponsor, sender]. No digest covers
//! the order: it has to come from a node that has it.
//!
//! The live stream and p2p already carry it (convert.txSignatures, p2p_exec.samePermutation). For
//! a checkpoint the bucket wins (a stream reconnect gap, catch-up) whose contents hold a list of
//! two or more signatures, the fetcher asks the stream's full node for
//! `GetCheckpoint { sequence_number, read_mask: transactions.signatures.bcs }` over gRPC-web and
//! converts with that overlay (convert.Options.sig_overlay). The overlay is untrusted like every
//! source: a list is taken only when it is exactly the certified signatures as a multiset, else
//! the contents order stays.
//!
//! Bounded so a catch-up never floods the public node: a request budget (`rps`, default 20 a
//! second, a burst of the same size); over budget, or when the node does not answer within
//! `timeout_ms` or does not hold the checkpoint (NOT_FOUND), the checkpoint keeps the contents
//! order and the miss is counted (`zui_sig_order_*`).
//!
//! The sweep (`Sweep`) makes those misses temporary. One per-checkpoint request per bucket
//! checkpoint is far more than the budget during a catch-up (2026-11-09 shadow: 2,391 of 3,146
//! skipped, 2 transactions then served in the contents order). The sweep walks every committed
//! checkpoint in order behind the tip, collects the transactions whose contents certify two or
//! more signatures, and asks the same node `BatchGetTransactions` for their `signatures`, 200
//! transactions a request (sui-rpc-api's MAX_BATCH_REQUESTS), waiting for the budget instead of
//! skipping (and ahead of the per-checkpoint requests). A transaction whose stored order differs
//! from the node's, with the very same signatures, gets the reordered envelope installed in the
//! store (store txfix.zig: every transaction read then returns it) and appended to
//! `node/sig-order.log`; the log also records how far the sweep got, so a restart reinstalls the
//! fixes before serving and resumes where it stopped. A store without the log (older builds, a
//! restore) is swept from its lowest available checkpoint. Why the order cannot be rebuilt
//! without asking: contents V2 put the signatures in `required_signers` order (sui-core
//! authority_per_epoch_store.rs `process_user_signatures`, messages_checkpoint.rs
//! `CheckpointTransactionContents`), the submitted order is the client's choice, and no digest
//! covers it (the transaction digest hashes TransactionData only).
const std = @import("std");
const Io = std.Io;
const Atomic = std.atomic.Value;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const netguard = @import("netguard.zig");
const stream = @import("stream.zig");
const b58 = @import("serve").b58;

/// The fields asked of the full node: enough to align and to take each transaction's list.
pub const read_mask = [_][]const u8{ "sequence_number", "transactions.signatures.bcs" };

pub const path = "/sui.rpc.v2.LedgerService/GetCheckpoint";

pub const Stats = struct {
    /// Bucket checkpoints whose contents certify a 2+ signature list (an overlay was wanted).
    wanted: Atomic(u64) = .init(0),
    requests: Atomic(u64) = .init(0),
    /// Overlays received and handed to the conversion.
    served: Atomic(u64) = .init(0),
    /// The full node does not hold the checkpoint (pruned, or ahead of it).
    not_found: Atomic(u64) = .init(0),
    /// Over the request budget: contents order kept.
    throttled: Atomic(u64) = .init(0),
    timeouts: Atomic(u64) = .init(0),
    errors: Atomic(u64) = .init(0),
    bytes: Atomic(u64) = .init(0),
};

/// A request budget: `burst` requests at once, then one per `interval_ns` (GCRA). Lock-free.
pub const Pace = struct {
    /// 0: no limit.
    interval_ns: u64,
    burst: u64,
    /// Theoretical arrival time of the next request (monotonic ns).
    tat: Atomic(u64) = .init(0),

    pub fn perSecond(rps: u32) Pace {
        if (rps == 0) return .{ .interval_ns = 0, .burst = 1 };
        return .{ .interval_ns = std.time.ns_per_s / rps, .burst = rps };
    }

    /// Nanoseconds until `take` can succeed at `now_ns` (0: now).
    pub fn waitNs(p: *const Pace, now_ns: u64) u64 {
        if (p.interval_ns == 0) return 0;
        const slack = (p.burst -| 1) * p.interval_ns;
        const t = @max(p.tat.load(.monotonic), now_ns);
        return (t - now_ns) -| slack;
    }

    /// Takes one request at `now_ns`; false when the budget is spent.
    pub fn take(p: *Pace, now_ns: u64) bool {
        if (p.interval_ns == 0) return true;
        const slack = (p.burst -| 1) * p.interval_ns;
        var cur = p.tat.load(.monotonic);
        while (true) {
            const t = @max(cur, now_ns);
            if (t - now_ns > slack) return false;
            cur = p.tat.cmpxchgWeak(cur, t + p.interval_ns, .monotonic, .monotonic) orelse return true;
        }
    }
};

/// The grpc-web request body: one uncompressed frame of
/// `GetCheckpointRequest { sequence_number = 1: seq, read_mask = 3: { paths = 1 } }`.
pub fn requestBody(a: std.mem.Allocator, seq: u64) ![]u8 {
    var mask: std.ArrayList(u8) = .empty;
    for (read_mask) |p| try putLen(a, &mask, 1, p);
    var msg: std.ArrayList(u8) = .empty;
    try putVarint(a, &msg, 1 << 3);
    try putVarint(a, &msg, seq);
    try putLen(a, &msg, 3, mask.items);
    const out = try a.alloc(u8, 5 + msg.items.len);
    out[0] = 0;
    std.mem.writeInt(u32, out[1..5], @intCast(msg.items.len), .big);
    @memcpy(out[5..], msg.items);
    return out;
}

fn putLen(a: std.mem.Allocator, out: *std.ArrayList(u8), field: u32, bytes: []const u8) !void {
    try putVarint(a, out, (field << 3) | 2);
    try putVarint(a, out, bytes.len);
    try out.appendSlice(a, bytes);
}

fn putVarint(a: std.mem.Allocator, out: *std.ArrayList(u8), v_in: u64) !void {
    var v = v_in;
    while (v >= 0x80) : (v >>= 7) try out.append(a, @as(u8, @truncate(v)) | 0x80);
    try out.append(a, @truncate(v));
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

pub const Unary = union(enum) {
    /// `GetCheckpointResponse.checkpoint` (a `Checkpoint` proto; empty if absent).
    checkpoint: []const u8,
    not_found,
};

/// A grpc-web unary response body (data frames, then a trailers frame) to the checkpoint it
/// carries. grpc-status 5 is `not_found`; any other non-zero status is `error.GrpcStatus`.
pub fn parseUnary(body: []const u8) !Unary {
    const m = switch (try unaryMessage(body)) {
        .message => |x| x,
        .not_found => return .not_found,
    };
    // GetCheckpointResponse { checkpoint = 1 }
    var cp: []const u8 = &.{};
    var it: Pb = .{ .b = m };
    while (try it.next()) |f| if (f.n == 1 and f.wire == 2) {
        cp = f.bytes;
    };
    return .{ .checkpoint = cp };
}

/// A grpc-web unary response body to its one message (or NOT_FOUND).
pub fn unaryMessage(body: []const u8) !union(enum) { message: []const u8, not_found } {
    var msg: ?[]const u8 = null;
    var i: usize = 0;
    while (i < body.len) {
        if (body.len - i < 5) return error.Malformed;
        const flags = body[i];
        const n = std.mem.readInt(u32, body[i + 1 ..][0..4], .big);
        i += 5;
        if (n > body.len - i) return error.Malformed;
        const payload = body[i..][0..n];
        i += n;
        if (flags & 0x80 != 0) {
            const code = trailerStatus(payload) orelse return error.Malformed;
            if (code == 5) return .not_found;
            if (code != 0) return error.GrpcStatus;
            break;
        }
        if (flags & 1 != 0) return error.CompressedFrame; // never asked for
        msg = payload;
    }
    return .{ .message = msg orelse return error.Malformed };
}

/// A protobuf field iterator: varint, fixed and length-delimited fields.
const Pb = struct {
    b: []const u8,
    i: usize = 0,

    const Field = struct { n: u64, wire: u3, v: u64 = 0, bytes: []const u8 = &.{} };

    fn next(p: *Pb) !?Field {
        if (p.i >= p.b.len) return null;
        const key = try varint(p.b, &p.i);
        var f: Field = .{ .n = key >> 3, .wire = @intCast(key & 7) };
        switch (f.wire) {
            0 => f.v = try varint(p.b, &p.i),
            1, 5 => {
                const w: usize = if (f.wire == 1) 8 else 4;
                if (w > p.b.len - p.i) return error.Malformed;
                p.i += w;
            },
            2 => {
                const n = try varint(p.b, &p.i);
                if (n > p.b.len - p.i) return error.Malformed;
                f.bytes = p.b[p.i..][0..@intCast(n)];
                p.i += @intCast(n);
            },
            else => return error.Malformed,
        }
        return f;
    }
};

/// `grpc-status` in a grpc-web trailers block (`name:value` lines).
fn trailerStatus(t: []const u8) ?u32 {
    var it = std.mem.tokenizeAny(u8, t, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), "grpc-status")) continue;
        return std.fmt.parseInt(u32, std.mem.trim(u8, line[colon + 1 ..], " "), 10) catch null;
    }
    return null;
}

/// What one call came back with: a body to parse, or a trailers-only NOT_FOUND.
const Answer = enum { body, not_found };

/// One POST into `w`, with the connection's socket registered in `abort` while it exists.
fn callOnce(c: *std.http.Client, url: []const u8, body: []u8, w: *std.Io.Writer, abort: *netguard.Abort) !Answer {
    const uri = try std.Uri.parse(url);
    var req = try c.request(.POST, uri, .{
        .redirect_behavior = .unhandled,
        .headers = .{ .content_type = .{ .override = "application/grpc-web+proto" }, .accept_encoding = .omit, .user_agent = .{ .override = "deepwave" } },
        .extra_headers = &.{
            .{ .name = "x-grpc-web", .value = "1" },
            .{ .name = "accept", .value = "application/grpc-web+proto" },
        },
    });
    defer req.deinit();
    // Any failure: the connection is not reused (see http.zig fetchOnce).
    errdefer if (req.connection) |conn| {
        conn.closing = true;
    };
    try abort.arm(netguard.socketOf(req.connection.?));
    defer abort.disarm();
    try req.sendBodyComplete(body);
    var res = try req.receiveHead(&.{});
    if (res.head.status != .ok) return error.HttpStatus;
    if (stream.headStatus(res.head)) |st| {
        // Trailers-only: no body to drain; do not reuse the connection anyway.
        if (req.connection) |conn| conn.closing = true;
        if (st.code == 5) return .not_found;
        return error.GrpcStatus;
    }
    if (res.head.content_encoding != .identity) return error.UnsupportedCompressionMethod;
    const reader = res.reader(&.{});
    // Bounded while reading, not checked after: a node streaming without end would otherwise
    // grow the arena for the whole timeout. A failed socket read leaves `bodyErr` null (std sets
    // it only for chunk framing errors), so it is not unwrapped.
    var left: usize = Overlay.max_answer + 1;
    while (left > 0) {
        left -= reader.stream(w, .limited(left)) catch |err| switch (err) {
            error.EndOfStream => return .body,
            error.ReadFailed => return res.bodyErr() orelse error.ReadFailed,
            error.WriteFailed => return error.WriteFailed,
        };
    }
    return error.AnswerTooLarge;
}

/// A stale keep-alive connection's failure (worth one retry on a fresh connection).
fn retryable(e: anyerror) bool {
    return switch (e) {
        error.HttpConnectionClosing, error.ConnectionResetByPeer, error.BrokenPipe, error.HttpRequestTruncated, error.ReadFailed, error.WriteFailed, error.EndOfStream => true,
        else => false,
    };
}

/// Request budget for a remote node (a public full node).
pub const default_rps: u32 = 20;
/// For a node on this host (the local sui-node in the shadow phase): enough for a catch-up.
pub const loopback_rps: u32 = 200;

/// Whether `url` names a node on this host.
pub fn isLoopback(url: []const u8) bool {
    const rest = if (std.mem.indexOf(u8, url, "://")) |k| url[k + 3 ..] else url;
    const host_end = std.mem.indexOfAny(u8, rest, ":/") orelse rest.len;
    const host = if (rest.len > 0 and rest[0] == '[') blk: {
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse break :blk rest;
        break :blk rest[1..close];
    } else rest[0..host_end];
    return std.mem.eql(u8, host, "localhost") or std.mem.eql(u8, host, "::1") or std.mem.startsWith(u8, host, "127.");
}

/// The overlay node from the `--stream` list (`A,B,...`): the first loopback URL (the local
/// sui-node standby: the very order the drop-in is compared with, and no public limits), else the
/// first URL. Trimmed of spaces and a trailing slash; null for an empty list.
pub fn pickBase(urls: []const u8) ?[]const u8 {
    var first: ?[]const u8 = null;
    var it = std.mem.tokenizeScalar(u8, urls, ',');
    while (it.next()) |raw| {
        const u = std.mem.trimEnd(u8, std.mem.trim(u8, raw, " "), "/");
        if (u.len == 0) continue;
        if (isLoopback(u)) return u;
        if (first == null) first = u;
    }
    return first;
}

/// The overlay client: one per node, shared by the fetch threads.
pub const Overlay = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// The full node's base URL (the first `--stream` URL), no trailing slash.
    base: []const u8,
    pace: Pace,
    /// Requests a second (`pace`), for the logs and the config echo.
    rps: u32,
    /// One attempt (connect, TLS, request, whole answer) must finish within this; past it the
    /// checkpoint keeps the contents order. A stale keep-alive failure gets one more attempt, so
    /// a fetch thread is held at most twice this (plus a wait for a free client).
    timeout_ms: u64 = 3_000,
    /// Set at shutdown: calls in flight end within ~100 ms.
    stopping: Atomic(bool) = .init(false),
    slots: [max_clients]Slot,
    stats: Stats = .{},
    warned_ms: Atomic(u64) = .init(0),
    /// The sweep waits for a request (`waitTurn`): `get` yields to it.
    sweep_waiting: Atomic(bool) = .init(false),

    pub const max_clients = 4;
    /// Largest answer read (signatures only: a few hundred KB at most).
    pub const max_answer: usize = 64 << 20;

    const Slot = struct {
        busy: Atomic(bool) = .init(false),
        client: netguard.Client,
    };

    pub fn init(gpa: std.mem.Allocator, io: Io, base: []const u8, rps: u32) Overlay {
        var o: Overlay = .{ .gpa = gpa, .io = io, .base = std.mem.trimEnd(u8, base, "/"), .pace = .perSecond(rps), .rps = rps, .slots = undefined };
        for (&o.slots) |*sl| {
            sl.* = .{ .client = netguard.Client.init(gpa, io) };
            sl.client.http.connection_pool.free_size = 2;
        }
        return o;
    }

    pub fn deinit(o: *Overlay) void {
        for (&o.slots) |*sl| sl.client.deinit();
    }

    fn acquire(o: *Overlay) *Slot {
        while (true) {
            for (&o.slots) |*sl| {
                if (sl.busy.cmpxchgStrong(false, true, .acquire, .monotonic) == null) return sl;
            }
            o.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
    }

    fn warn(o: *Overlay, seq: u64, why: []const u8) void {
        const now = netguard.wallMs();
        const last = o.warned_ms.load(.monotonic);
        if (now -| last > 60_000 and o.warned_ms.cmpxchgStrong(last, now, .monotonic, .monotonic) == null)
            std.log.warn("signature order {d} from {s}: {s}; the contents order is kept (logged once a minute)", .{ seq, o.base, why });
    }

    /// The overlay `Checkpoint` proto for `seq`, allocated in `arena`, or null (over budget, not
    /// held by the node, or failed: the caller converts with the contents order). Thread-safe.
    pub fn get(o: *Overlay, arena: std.mem.Allocator, seq: u64) ?[]const u8 {
        _ = o.stats.wanted.fetchAdd(1, .monotonic);
        if (o.stopping.load(.acquire)) return null;
        // A waiting sweep request covers up to 200 transactions: it goes first.
        if (o.sweep_waiting.load(.acquire) or !o.pace.take(@import("source.zig").nowNs())) {
            _ = o.stats.throttled.fetchAdd(1, .monotonic);
            return null;
        }
        _ = o.stats.requests.fetchAdd(1, .monotonic);
        const body = requestBody(arena, seq) catch return null;
        const got = switch (o.post(arena, path, body, seq)) {
            .body => |b| b,
            .not_found => {
                _ = o.stats.not_found.fetchAdd(1, .monotonic);
                return null;
            },
            .failed => return null,
        };
        const u = parseUnary(got) catch |e| {
            _ = o.stats.errors.fetchAdd(1, .monotonic);
            o.warn(seq, @errorName(e));
            return null;
        };
        switch (u) {
            .not_found => {
                _ = o.stats.not_found.fetchAdd(1, .monotonic);
                return null;
            },
            .checkpoint => |cp| {
                _ = o.stats.served.fetchAdd(1, .monotonic);
                return cp;
            },
        }
    }

    pub const Post = union(enum) { body: []const u8, not_found, failed };

    /// One grpc-web unary call of `rpc` (a `/package.Service/Method` path) with the framed
    /// `body`; the answer body in `arena`. Counts timeouts, errors and bytes in `stats`. No budget
    /// check: the caller took one.
    pub fn post(o: *Overlay, arena: std.mem.Allocator, rpc: []const u8, body: []u8, seq: u64) Post {
        var ub: [256]u8 = undefined;
        const url = std.fmt.bufPrint(&ub, "{s}{s}", .{ o.base, rpc }) catch {
            _ = o.stats.errors.fetchAdd(1, .monotonic);
            return .failed;
        };
        var out: std.ArrayList(u8) = .empty;
        var aw: std.Io.Writer.Allocating = .fromArrayList(arena, &out);
        const sl = o.acquire();
        defer sl.busy.store(false, .release);
        sl.client.prepare(netguard.wallMs());
        defer sl.client.done(netguard.wallMs());
        var ab: netguard.Abort = .{};
        // A pooled keep-alive connection the server closed fails on first use: one retry on a
        // fresh connection (the call only reads). Each attempt is bounded by `timeout_ms`.
        var attempt: u32 = 0;
        const ans = while (true) : (attempt += 1) {
            aw.writer.end = 0;
            ab.reset();
            break netguard.timed(o.io, o.timeout_ms, &o.stopping, &ab, callOnce, .{ &sl.client.http, url, body, &aw.writer, &ab }) catch |e| {
                sl.client.noteError(e, netguard.wallMs());
                sl.client.dropPool();
                if (e == error.Stopped) return .failed;
                if (attempt == 0 and retryable(e)) continue;
                _ = (if (e == error.Timeout) &o.stats.timeouts else &o.stats.errors).fetchAdd(1, .monotonic);
                o.warn(seq, @errorName(e));
                return .failed;
            };
        };
        if (ans == .not_found) return .not_found;
        const got = aw.writer.buffered();
        _ = o.stats.bytes.fetchAdd(got.len, .monotonic);
        if (got.len > max_answer) {
            _ = o.stats.errors.fetchAdd(1, .monotonic);
            return .failed;
        }
        return .{ .body = got };
    }

    /// Waits for one request of the budget (ahead of `get`). False at shutdown.
    pub fn waitTurn(o: *Overlay) bool {
        o.sweep_waiting.store(true, .release);
        defer o.sweep_waiting.store(false, .release);
        while (!o.stopping.load(.acquire)) {
            const now = @import("source.zig").nowNs();
            if (o.pace.take(now)) return true;
            const ns = @min(@max(o.pace.waitNs(now), std.time.ns_per_ms), 50 * std.time.ns_per_ms);
            o.io.sleep(.fromNanoseconds(@intCast(ns)), .awake) catch {};
        }
        return false;
    }
};

// ------------------------------------------------------------------------------------- sweep

pub const batch_path = "/sui.rpc.v2.LedgerService/BatchGetTransactions";
/// sui-rpc-api get_transaction.rs MAX_BATCH_REQUESTS.
pub const max_batch: usize = 200;

/// `BatchGetTransactionsRequest { digests = 1 (base58), read_mask = 2: { paths = 1 } }` with the
/// mask `digest,signatures.bcs`, framed.
pub fn batchBody(a: std.mem.Allocator, digests: []const [32]u8) ![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    for (digests) |*d| {
        var tb: [b58.max_len_32]u8 = undefined;
        try putLen(a, &msg, 1, b58.encode32(&tb, d));
    }
    var mask: std.ArrayList(u8) = .empty;
    try putLen(a, &mask, 1, "digest");
    try putLen(a, &mask, 1, "signatures.bcs");
    try putLen(a, &msg, 2, mask.items);
    const out = try a.alloc(u8, 5 + msg.items.len);
    out[0] = 0;
    std.mem.writeInt(u32, out[1..5], @intCast(msg.items.len), .big);
    @memcpy(out[5..], msg.items);
    return out;
}

/// One `GetTransactionResult` of a batch answer.
pub const TxAnswer = union(enum) {
    /// `ExecutedTransaction { digest = 1, signatures = 3: { bcs = 1: { value = 2 } } }`.
    tx: struct { digest: ?[32]u8, sigs: []const []const u8 },
    /// `error = 2: google.rpc.Status { code = 1 }`.
    err: u64,
};

/// `BatchGetTransactionsResponse { transactions = 1: GetTransactionResult }` to its results.
pub fn parseBatch(a: std.mem.Allocator, msg: []const u8) ![]TxAnswer {
    var out: std.ArrayList(TxAnswer) = .empty;
    var it: Pb = .{ .b = msg };
    while (try it.next()) |f| {
        if (f.n != 1) continue;
        if (f.wire != 2) return error.Malformed;
        var r: Pb = .{ .b = f.bytes };
        var ans: ?TxAnswer = null;
        while (try r.next()) |g| switch (g.n) {
            1 => {
                if (g.wire != 2) return error.Malformed;
                var digest: ?[32]u8 = null;
                var sigs: std.ArrayList([]const u8) = .empty;
                var t: Pb = .{ .b = g.bytes };
                while (try t.next()) |h| switch (h.n) {
                    1 => digest = b58.decode32(h.bytes) orelse return error.Malformed,
                    3 => {
                        if (h.wire != 2) return error.Malformed;
                        var value: ?[]const u8 = null;
                        var u: Pb = .{ .b = h.bytes };
                        while (try u.next()) |k| if (k.n == 1 and k.wire == 2) {
                            var bb: Pb = .{ .b = k.bytes };
                            while (try bb.next()) |q| if (q.n == 2 and q.wire == 2) {
                                value = q.bytes;
                            };
                        };
                        try sigs.append(a, value orelse return error.Malformed);
                    },
                    else => {},
                };
                ans = .{ .tx = .{ .digest = digest, .sigs = sigs.items } };
            },
            2 => {
                if (g.wire != 2) return error.Malformed;
                var code: u64 = 2; // UNKNOWN unless stated
                var st: Pb = .{ .b = g.bytes };
                while (try st.next()) |h| if (h.n == 1 and h.wire == 0) {
                    code = h.v;
                };
                ans = .{ .err = code };
            },
            else => {},
        };
        try out.append(a, ans orelse return error.Malformed);
    }
    return out.items;
}

/// The signatures of a stored transaction envelope (`SenderSignedData` bytes) and where their
/// vector starts.
pub fn envelopeSigs(a: std.mem.Allocator, tx: []const u8) !struct { head: usize, sigs: []const []const u8 } {
    var r = bcs.Reader.init(tx);
    if (try r.length() != 1) return error.Malformed;
    _ = try r.bytes(3); // intent
    try bcs.skip(types.TransactionData, &r);
    const head = r.pos();
    const n = try r.length();
    if (n > 64) return error.Malformed;
    const sigs = try a.alloc([]const u8, n);
    for (sigs) |*g| g.* = try r.bytes(try r.length());
    if (r.remaining() != 0) return error.Malformed;
    return .{ .head = head, .sigs = sigs };
}

/// The stored envelope `tx` with its signatures in `order`, when `order` holds exactly the
/// stored signatures (as a multiset, which the certified contents digest covers) in another
/// order. Null when the order is already the same or `order` is not such a permutation.
pub fn reorder(a: std.mem.Allocator, tx: []const u8, order: []const []const u8) !?[]u8 {
    const e = try envelopeSigs(a, tx);
    if (e.sigs.len != order.len or order.len < 2) return null;
    const same = for (e.sigs, order) |x, y| {
        if (!std.mem.eql(u8, x, y)) break false;
    } else true;
    if (same) return null;
    var used: u64 = 0;
    outer: for (order) |g| {
        for (e.sigs, 0..) |c, i| {
            const bit = @as(u64, 1) << @intCast(i);
            if (used & bit == 0 and std.mem.eql(u8, c, g)) {
                used |= bit;
                continue :outer;
            }
        }
        return null;
    }
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(a, tx.len);
    try out.appendSlice(a, tx[0..e.head]);
    try putVarint(a, &out, order.len);
    for (order) |g| {
        try putVarint(a, &out, g.len);
        try out.appendSlice(a, g);
    }
    if (out.items.len != tx.len) return null;
    return out.items;
}

/// Digest and certified signature count of each transaction of V2 checkpoint contents (V1
/// contents keep each transaction's own order: `new_with_causally_ordered_execution_data`, and
/// before `fix_checkpoint_signature_mapping` a plain zip; returns none).
fn multiSigner(a: std.mem.Allocator, contents: []const u8, out: *std.ArrayList([32]u8)) !void {
    var r = bcs.Reader.init(contents);
    if (try r.uleb32() != 1) return;
    const n = try r.length();
    for (0..n) |_| {
        const d = try r.bytes(66);
        if (d[0] != 32 or d[33] != 32) return error.Malformed;
        const k = try r.length();
        for (0..k) |_| {
            _ = try r.bytes(try r.length());
            switch (try r.int(u8)) {
                0 => {},
                1 => _ = try r.int(u64),
                else => return error.Malformed,
            }
        }
        if (k >= 2) try out.append(a, d[1..33].*);
    }
}

pub const SweepStats = struct {
    /// Checkpoints swept (the sweep's position is `zui_sig_order_sweep_next`).
    checkpoints: Atomic(u64) = .init(0),
    /// Transactions whose contents certify two or more signatures, asked for.
    candidates: Atomic(u64) = .init(0),
    requests: Atomic(u64) = .init(0),
    /// Served in the node's order from now on (stored in the contents order).
    fixed: Atomic(u64) = .init(0),
    /// Already stored in the node's order.
    same: Atomic(u64) = .init(0),
    /// The node does not hold it (pruned): the contents order stays.
    unavailable: Atomic(u64) = .init(0),
    /// The node's list is not the certified signatures: ignored.
    rejected: Atomic(u64) = .init(0),
    /// Failed batches, retried.
    retries: Atomic(u64) = .init(0),
    /// Fixes reinstalled from the log at start.
    loaded: Atomic(u64) = .init(0),
};

/// `node/sig-order.log`: magic, then records `crc32 (of the rest) u32, kind u8, pad 3, len u32,
/// seq u64, digest [32], len bytes`. Kind 1: a fix (the envelope to serve for `digest` in
/// checkpoint `seq`). Kind 2: every checkpoint up to `seq` is swept. A torn tail is cut.
pub const log_name = "sig-order.log";
const log_magic = "ZUISIGO1";
const rec_head = 52;
const kind_fix: u8 = 1;
const kind_mark: u8 = 2;

fn encodeRec(a: std.mem.Allocator, out: *std.ArrayList(u8), kind: u8, seq: u64, digest: *const [32]u8, payload: []const u8) !void {
    const at = out.items.len;
    try out.appendNTimes(a, 0, rec_head);
    try out.appendSlice(a, payload);
    const r = out.items[at..];
    r[4] = kind;
    std.mem.writeInt(u32, r[8..12], @intCast(payload.len), .little);
    std.mem.writeInt(u64, r[12..20], seq, .little);
    r[20..52].* = digest.*;
    std.mem.writeInt(u32, r[0..4], std.hash.Crc32.hash(r[4..]), .little);
}

pub const Sweep = struct {
    gpa: std.mem.Allocator,
    io: Io,
    st: *store.Store,
    ov: *Overlay,
    file: Io.File,
    end: u64,
    /// Next checkpoint to sweep; null: from the store's lowest available.
    next: ?u64 = null,
    /// Stay this many checkpoints behind the committed tip.
    behind: u64 = 2,
    /// Checkpoints read per pass at most (the snapshot is held that long).
    max_scan: u64 = 2_000,
    /// A transaction the node says it does not hold, within this many checkpoints of the tip,
    /// may only be lagging there: the batch is asked again (up to `nf_tries`) before giving up.
    recent: u64 = 2_000,
    nf_tries: u32 = 30,
    nf_seen: u32 = 0,
    /// A mark is written at least this often (and after every fix).
    mark_every: u64 = 10_000,
    last_mark: u64 = 0,
    idle_ms: u64 = 500,
    stats: SweepStats = .{},
    /// For the metrics: `next` (0 before the first pass).
    pos: Atomic(u64) = .init(0),
    thread: ?std.Thread = null,
    /// NOT_FOUND answers of the current pass for recent transactions (counted as unavailable
    /// when the retries run out).
    pending_nf: u64 = 0,

    /// Opens (or creates) `dir/sig-order.log`, reinstalls its fixes into the store (each checked
    /// against the stored envelope: a permutation of the same signatures) and resumes after its
    /// last mark. A mark above the store's committed tip (another store under the same dir) is
    /// ignored: the sweep then starts from the store's lowest checkpoint.
    pub fn open(gpa: std.mem.Allocator, io: Io, st: *store.Store, ov: *Overlay, dir: Io.Dir) !*Sweep {
        const data = dir.readFileAlloc(io, log_name, gpa, .unlimited) catch |e| switch (e) {
            error.FileNotFound => try gpa.dupe(u8, ""),
            else => return e,
        };
        defer gpa.free(data);
        const f = try dir.createFile(io, log_name, .{ .read = true, .truncate = false });
        errdefer f.close(io);
        const sw = try gpa.create(Sweep);
        errdefer gpa.destroy(sw);
        sw.* = .{ .gpa = gpa, .io = io, .st = st, .ov = ov, .file = f, .end = 0 };
        if (data.len < log_magic.len or !std.mem.eql(u8, data[0..log_magic.len], log_magic)) {
            try f.setLength(io, 0);
            try f.writePositionalAll(io, log_magic, 0);
            try f.sync(io);
            sw.end = log_magic.len;
            return sw;
        }
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        var snap = st.snapshot();
        defer snap.release();
        const top = snap.highestCommitted();
        var mark: ?u64 = null;
        var at: usize = log_magic.len;
        // Collected, then installed in one bulk build (one sort, one published set).
        var loaded: std.ArrayList(store.txfix.Entry) = .empty;
        defer loaded.deinit(gpa);
        // A snapshot keeps every chunk it decoded alive until it is released, so one snapshot
        // held across tens of thousands of fixes (each in another checkpoint) pinned over 12 GB
        // on a production node at 65k fixes. Take a fresh one every `snap_every` lookups.
        const snap_every = 1024;
        var lookups: usize = 0;
        while (data.len - at >= rec_head) {
            const r = data[at..];
            const len = std.mem.readInt(u32, r[8..12], .little);
            if (len > r.len - rec_head) break;
            const rec = r[0 .. rec_head + len];
            if (std.hash.Crc32.hash(rec[4..]) != std.mem.readInt(u32, rec[0..4], .little)) break;
            const seq = std.mem.readInt(u64, rec[12..20], .little);
            const digest: *const [32]u8 = rec[20..52];
            switch (rec[4]) {
                kind_fix => if (blk: {
                    lookups += 1;
                    if (lookups % snap_every == 0) {
                        snap.release();
                        snap = st.snapshot();
                    }
                    break :blk snap.transaction(digest);
                }) |t| {
                    _ = arena.reset(.retain_capacity);
                    if (t.checkpoint == seq and validFix(arena.allocator(), t.tx, rec[rec_head..]))
                        try loaded.append(gpa, .{ .seq = seq, .digest = digest.*, .tx = rec[rec_head..] });
                },
                kind_mark => mark = seq,
                else => break,
            }
            at += rec.len;
        }
        _ = sw.stats.loaded.fetchAdd(try st.tx_fix.load(loaded.items), .monotonic);
        if (at != data.len) {
            std.log.warn("signature order log: torn or corrupt tail at byte {d} of {d}; cut", .{ at, data.len });
            try f.setLength(io, at);
            try f.sync(io);
        }
        sw.end = at;
        if (mark) |m| if (top != null and m <= top.?) {
            sw.next = m + 1;
            sw.last_mark = m;
        };
        return sw;
    }

    /// `fix` is the stored envelope `stored` with the same signatures in some order.
    fn validFix(a: std.mem.Allocator, stored: []const u8, fix: []const u8) bool {
        if (std.mem.eql(u8, stored, fix)) return true;
        const e = envelopeSigs(a, fix) catch return false;
        const r = reorder(a, stored, e.sigs) catch return false;
        return if (r) |x| std.mem.eql(u8, x, fix) else false;
    }

    pub fn deinit(sw: *Sweep) void {
        sw.file.close(sw.io);
        sw.gpa.destroy(sw);
    }

    pub fn start(sw: *Sweep) !void {
        sw.thread = try std.Thread.spawn(.{}, loop, .{sw});
    }

    /// Joins the thread; the overlay's `stopping` must be set first.
    pub fn join(sw: *Sweep) void {
        if (sw.thread) |t| t.join();
        sw.thread = null;
    }

    fn loop(sw: *Sweep) void {
        var backoff_ms: u64 = 500;
        while (!sw.ov.stopping.load(.acquire)) {
            const r = sw.step() catch |e| blk: {
                std.log.warn("signature order sweep at {d}: {s}", .{ sw.next orelse 0, @errorName(e) });
                break :blk Step.retry;
            };
            switch (r) {
                .progress => backoff_ms = 500,
                .idle => sw.sleep(sw.idle_ms),
                .retry => {
                    _ = sw.stats.retries.fetchAdd(1, .monotonic);
                    sw.sleep(backoff_ms);
                    backoff_ms = @min(backoff_ms * 2, 30_000);
                },
            }
        }
    }

    fn sleep(sw: *Sweep, ms: u64) void {
        var left = ms;
        while (left > 0 and !sw.ov.stopping.load(.acquire)) {
            const d = @min(left, 100);
            sw.io.sleep(.fromMilliseconds(@intCast(d)), .awake) catch {};
            left -= d;
        }
    }

    pub const Step = enum { progress, idle, retry };

    const Item = store.txfix.Entry;

    /// One pass: the checkpoints from `next` (at most `max_scan`, at least one whole checkpoint)
    /// up to `behind` below the tip, their multi-signer transactions asked for in batches.
    /// `progress` when `next` moved.
    pub fn step(sw: *Sweep) !Step {
        var arena_state: std.heap.ArenaAllocator = .init(sw.gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        var items: std.ArrayList(Item) = .empty;
        var last: u64 = undefined;
        var committed: u64 = undefined;
        var lo: u64 = undefined;
        sw.pending_nf = 0;
        {
            var snap = sw.st.snapshot();
            defer snap.release();
            committed = snap.highestCommitted() orelse return .idle;
            const low = snap.lowestAvailable() orelse return .idle;
            lo = @max(sw.next orelse low, low);
            if (committed < sw.behind or lo > committed - sw.behind) return .idle;
            const hi = @min(committed - sw.behind, lo + sw.max_scan - 1);
            var ds: std.ArrayList([32]u8) = .empty;
            last = lo;
            var seq = lo;
            while (seq <= hi) : (seq += 1) {
                last = seq;
                const rec = snap.checkpoint(seq) orelse continue;
                ds.clearRetainingCapacity();
                try multiSigner(a, rec.contents, &ds);
                for (ds.items) |d| {
                    const t = snap.transactionNear(&d, seq) orelse continue;
                    try items.append(a, .{ .seq = seq, .digest = d, .tx = try a.dupe(u8, t.tx) });
                }
                if (items.items.len >= max_batch) break;
            }
        }
        var fixes: std.ArrayList(Item) = .empty;
        var i: usize = 0;
        var nf_recent = false;
        while (i < items.items.len) {
            const chunk = items.items[i..@min(i + max_batch, items.items.len)];
            switch (try sw.ask(a, chunk, committed, &fixes)) {
                .done => {},
                .not_found_recent => nf_recent = true,
                .failed => {
                    try sw.flush(a, &fixes, null);
                    return .retry;
                },
            }
            i += chunk.len;
        }
        if (nf_recent and sw.nf_seen < sw.nf_tries) {
            sw.nf_seen += 1;
            try sw.flush(a, &fixes, null);
            return .retry;
        }
        // Final: count what the node still does not hold.
        _ = sw.stats.unavailable.fetchAdd(sw.pending_nf, .monotonic);
        sw.nf_seen = 0;
        const mark: ?u64 = if (fixes.items.len > 0 or last >= sw.last_mark + sw.mark_every) last else null;
        try sw.flush(a, &fixes, mark);
        _ = sw.stats.checkpoints.fetchAdd(last + 1 - lo, .monotonic);
        sw.next = last + 1;
        sw.pos.store(last + 1, .monotonic);
        return .progress;
    }

    const Asked = enum { done, not_found_recent, failed };

    fn ask(sw: *Sweep, a: std.mem.Allocator, chunk: []const Item, committed: u64, fixes: *std.ArrayList(Item)) !Asked {
        const ds = try a.alloc([32]u8, chunk.len);
        for (ds, chunk) |*d, it| d.* = it.digest;
        const body = try batchBody(a, ds);
        if (!sw.ov.waitTurn()) return .failed;
        _ = sw.stats.requests.fetchAdd(1, .monotonic);
        const got = switch (sw.ov.post(a, batch_path, body, chunk[0].seq)) {
            .body => |b| b,
            .not_found, .failed => return .failed,
        };
        const msg = switch (unaryMessage(got) catch return .failed) {
            .message => |m| m,
            .not_found => return .failed,
        };
        const answers = parseBatch(a, msg) catch return .failed;
        if (answers.len != chunk.len) return .failed;
        var out: Asked = .done;
        var nf: u64 = 0;
        for (chunk, answers) |it, ans| switch (ans) {
            .err => |code| {
                if (code != 5) return .failed;
                if (committed -| it.seq < sw.recent) {
                    out = .not_found_recent;
                    nf += 1;
                } else _ = sw.stats.unavailable.fetchAdd(1, .monotonic);
            },
            .tx => |t| {
                if (t.digest) |d| if (!std.mem.eql(u8, &d, &it.digest)) return .failed;
                _ = sw.stats.candidates.fetchAdd(1, .monotonic);
                const fixed = (reorder(a, it.tx, t.sigs) catch null) orelse {
                    const e = envelopeSigs(a, it.tx) catch {
                        _ = sw.stats.rejected.fetchAdd(1, .monotonic);
                        continue;
                    };
                    const same = e.sigs.len == t.sigs.len and for (e.sigs, t.sigs) |x, y| {
                        if (!std.mem.eql(u8, x, y)) break false;
                    } else true;
                    _ = (if (same) &sw.stats.same else &sw.stats.rejected).fetchAdd(1, .monotonic);
                    continue;
                };
                if (sw.st.tx_fix.installed(&it.digest, fixed)) {
                    _ = sw.stats.same.fetchAdd(1, .monotonic);
                    continue;
                }
                try fixes.append(a, .{ .seq = it.seq, .digest = it.digest, .tx = fixed });
            },
        };
        sw.pending_nf += nf;
        return out;
    }

    /// Logs the pass's fixes, then the mark (one write, fsync'd when it holds a fix), then
    /// installs the fixes: a served order is always durable first. A lost mark only repeats
    /// work; a mark is never durable without the fixes before it (the log is read in order and
    /// cut at the first bad record).
    fn flush(sw: *Sweep, a: std.mem.Allocator, fixes: *std.ArrayList(Item), mark: ?u64) !void {
        var buf: std.ArrayList(u8) = .empty;
        for (fixes.items) |f| try encodeRec(a, &buf, kind_fix, f.seq, &f.digest, f.tx);
        if (mark) |m| try encodeRec(a, &buf, kind_mark, m, &@as([32]u8, @splat(0)), "");
        if (buf.items.len > 0) {
            try sw.file.writePositionalAll(sw.io, buf.items, sw.end);
            sw.end += buf.items.len;
            if (fixes.items.len > 0) try sw.file.sync(sw.io);
        }
        if (mark) |m| sw.last_mark = m;
        _ = sw.stats.fixed.fetchAdd(try sw.st.tx_fix.putMany(fixes.items), .monotonic);
        fixes.clearRetainingCapacity();
    }
};

test "sigorder: request body is a framed GetCheckpointRequest with the signatures mask" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const b = try requestBody(a, 343111673);
    try std.testing.expectEqual(@as(u8, 0), b[0]);
    try std.testing.expectEqual(@as(usize, b.len - 5), std.mem.readInt(u32, b[1..5], .big));
    // sequence_number = 1 (varint) first.
    try std.testing.expectEqual(@as(u8, 0x08), b[5]);
    var i: usize = 6;
    try std.testing.expectEqual(@as(u64, 343111673), try varint(b, &i));
    // read_mask = 3 (len).
    try std.testing.expectEqual(@as(u8, 0x1a), b[i]);
    try std.testing.expect(std.mem.indexOf(u8, b, "transactions.signatures.bcs") != null);
    try std.testing.expect(std.mem.indexOf(u8, b, "sequence_number") != null);
}

fn frame(a: std.mem.Allocator, out: *std.ArrayList(u8), flags: u8, payload: []const u8) !void {
    var h: [5]u8 = undefined;
    h[0] = flags;
    std.mem.writeInt(u32, h[1..5], @intCast(payload.len), .big);
    try out.appendSlice(a, &h);
    try out.appendSlice(a, payload);
}

test "sigorder: unary grpc-web answers (checkpoint, NOT_FOUND trailer, error, malformed)" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // GetCheckpointResponse { checkpoint = 1: { sequence_number = 1: 7 } }
    const cp = [_]u8{ 0x08, 0x07 };
    var msg: std.ArrayList(u8) = .empty;
    try putLen(a, &msg, 1, &cp);
    var ok: std.ArrayList(u8) = .empty;
    try frame(a, &ok, 0, msg.items);
    try frame(a, &ok, 0x80, "grpc-status:0\r\ngrpc-message:\r\n");
    const u = try parseUnary(ok.items);
    try std.testing.expectEqualSlices(u8, &cp, u.checkpoint);

    var nf: std.ArrayList(u8) = .empty;
    try frame(a, &nf, 0x80, "grpc-status: 5\r\ngrpc-message: checkpoint 9 not found\r\n");
    try std.testing.expect((try parseUnary(nf.items)) == .not_found);

    var bad: std.ArrayList(u8) = .empty;
    try frame(a, &bad, 0x80, "grpc-status:14\r\n");
    try std.testing.expectError(error.GrpcStatus, parseUnary(bad.items));

    try std.testing.expectError(error.Malformed, parseUnary(&.{ 0, 0, 0, 0, 9, 1 }));
    try std.testing.expectError(error.Malformed, parseUnary(&.{}));
    var comp: std.ArrayList(u8) = .empty;
    try frame(a, &comp, 1, msg.items);
    try std.testing.expectError(error.CompressedFrame, parseUnary(comp.items));
}

test "sigorder: the request budget allows a burst, then one per interval" {
    var p: Pace = .perSecond(20); // 50 ms, burst 20
    var n: u32 = 0;
    for (0..100) |_| n += @intFromBool(p.take(1_000_000_000));
    try std.testing.expectEqual(@as(u32, 20), n);
    // 50 ms later: one more.
    try std.testing.expect(p.take(1_050_000_000));
    try std.testing.expect(!p.take(1_050_000_000));
    // A second idle: a full burst again.
    n = 0;
    for (0..100) |_| n += @intFromBool(p.take(3_000_000_000));
    try std.testing.expectEqual(@as(u32, 20), n);
    var off: Pace = .perSecond(0);
    for (0..1000) |_| try std.testing.expect(off.take(5));
}

test "sigorder: a NOT_FOUND head and a silent node both leave the contents order, bounded" {
    {
        var srv: netguard.TestServer = undefined;
        try srv.start(std.testing.io, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ngrpc-status: 5\r\ngrpc-message: not found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        defer srv.stop();
        var ub: [64]u8 = undefined;
        var o = Overlay.init(std.testing.allocator, std.testing.io, srv.url(&ub), 20);
        defer o.deinit();
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        try std.testing.expect(o.get(arena.allocator(), 9) == null);
        try std.testing.expectEqual(@as(u64, 1), o.stats.not_found.load(.monotonic));
    }
    {
        var srv: netguard.TestServer = undefined;
        try srv.start(std.testing.io, null);
        defer srv.stop();
        var ub: [64]u8 = undefined;
        var o = Overlay.init(std.testing.allocator, std.testing.io, srv.url(&ub), 20);
        defer o.deinit();
        o.timeout_ms = 300;
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        const t0 = netguard.wallMs();
        try std.testing.expect(o.get(arena.allocator(), 9) == null);
        try std.testing.expect(netguard.wallMs() - t0 < 3000);
        try std.testing.expectEqual(@as(u64, 1), o.stats.timeouts.load(.monotonic));
    }
}

test "sigorder: a served answer comes back as the checkpoint proto" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cp = [_]u8{ 0x08, 0x09 };
    var msg: std.ArrayList(u8) = .empty;
    try putLen(a, &msg, 1, &cp);
    var body: std.ArrayList(u8) = .empty;
    try frame(a, &body, 0, msg.items);
    try frame(a, &body, 0x80, "grpc-status:0\r\n");
    const reply = try std.fmt.allocPrint(a, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n{s}", .{ body.items.len, body.items });
    var srv: netguard.TestServer = undefined;
    try srv.start(std.testing.io, reply);
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var o = Overlay.init(std.testing.allocator, std.testing.io, srv.url(&ub), 20);
    defer o.deinit();
    const got = o.get(a, 9) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &cp, got);
    try std.testing.expectEqual(@as(u64, 1), o.stats.served.load(.monotonic));
}

test "sigorder: the overlay node prefers a loopback stream URL" {
    try std.testing.expect(isLoopback("http://127.0.0.1:9000"));
    try std.testing.expect(isLoopback("http://localhost:9000/"));
    try std.testing.expect(isLoopback("http://[::1]:9000"));
    try std.testing.expect(!isLoopback("https://fullnode.mainnet.sui.io"));
    try std.testing.expect(!isLoopback("https://127example.com"));
    try std.testing.expectEqualStrings("http://127.0.0.1:9000", pickBase("https://fullnode.mainnet.sui.io,http://127.0.0.1:9000/").?);
    try std.testing.expectEqualStrings("https://fullnode.mainnet.sui.io", pickBase(" https://fullnode.mainnet.sui.io/ ,https://other.example").?);
    try std.testing.expect(pickBase(" , ") == null);
}
