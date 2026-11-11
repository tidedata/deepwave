//! Tests of forward.zig against a scripted core on loopback: the relay (bytes, status, message
//! and details verbatim; streams; flow control), read-after-write, the lag guard, and the ways
//! the way to the core can fail. The edge's local side is a scripted handler over a real (small,
//! synthetic) store, so tip, floor and "is this transaction applied" are the store's own.
//!
//! Allocators: everything forward.zig owns comes from `testing.allocator` (a leak fails the
//! test). The h2 servers and the reused h2 client take `smp_allocator`, as in their own tests:
//! their connection threads may outlive a test by a moment.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const Atomic = std.atomic.Value;
const serve = @import("serve");
const store = @import("store");
const native = @import("native");
const rpc_exec = @import("rpc_exec");
const bcs = @import("bcs");
const types = @import("types");
const forward = @import("forward.zig");
const route = @import("route.zig");
const h2 = serve.h2;
const loopback = serve.loopback;
const grpc = rpc_exec.live.grpc_client;

const io = testing.io;
const sys = std.heap.smp_allocator;
const ms = std.time.ns_per_ms;

const p_lookup = "/sui.rpc.v2.NameService/LookupName";
const p_reverse = "/sui.rpc.v2.NameService/ReverseLookupName";
const p_info = "/sui.rpc.v2.LedgerService/GetServiceInfo";
const p_object = "/sui.rpc.v2.LedgerService/GetObject";
const p_tx = "/sui.rpc.v2.LedgerService/GetTransaction";
const p_checkpoint = "/sui.rpc.v2.LedgerService/GetCheckpoint";
const p_execute = "/sui.rpc.v2.TransactionExecutionService/ExecuteTransaction";
const p_simulate = "/sui.rpc.v2.TransactionExecutionService/SimulateTransaction";
const p_list = "/sui.rpc.v2.LedgerService/ListCheckpoints";
const p_events = "/sui.rpc.v2.LedgerService/ListEvents";
const p_subscribe = "/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints";

fn nowNs() u64 {
    return h2.meta.monoNs();
}
fn sleepMs(n: u64) void {
    Io.sleep(io, .fromMilliseconds(@intCast(n)), .awake) catch {};
}

// ---------------------------------------------------------------- the scripted core

/// What the core answers, by path. Process-wide (the stream answers get no context).
const core = struct {
    var calls: Atomic(u32) = .init(0);
    var info_calls: Atomic(u32) = .init(0);
    var exec_fail: Atomic(bool) = .init(false);
    var slow_ms: Atomic(u32) = .init(0);
    /// The `grpc-timeout` budget the last slow call arrived with (ms; 0: none).
    var seen_budget_ms: Atomic(u64) = .init(0);
    var seen_protocol: Atomic(u64) = .init(0);
    /// Set when a stream answer saw its client gone.
    var stream_cancelled: Atomic(bool) = .init(false);
    var forever_sent: Atomic(u32) = .init(0);
    /// ExecuteTransaction answers a real ExecuteTransactionResponse rendered by the request's
    /// read mask, with these BCS effects (empty: the fixed text answer).
    var effects_bcs: []const u8 = "";
    /// The read mask paths the last execute arrived with, joined by commas.
    var seen_mask_buf: [256]u8 = undefined;
    var seen_mask_len: Atomic(usize) = .init(0);

    const details = [_]u8{ 0x08, 0x05, 0x12, 0x03, 'a', 0xff, 0x00 };
    const not_found_text = "name 100% not found: \xc3\xa9 \"quoted\"";
    const stream_messages = 40;
    const stream_end_text = "page past the end";

    fn reset() void {
        calls.store(0, .release);
        info_calls.store(0, .release);
        exec_fail.store(false, .release);
        slow_ms.store(0, .release);
        seen_budget_ms.store(0, .release);
        seen_protocol.store(0, .release);
        stream_cancelled.store(false, .release);
        forever_sent.store(0, .release);
        effects_bcs = "";
        seen_mask_len.store(0, .release);
    }

    fn seenMask() []const u8 {
        return seen_mask_buf[0..seen_mask_len.load(.acquire)];
    }

    fn varint(out: *std.ArrayList(u8), a: std.mem.Allocator, value: u64) !void {
        var v = value;
        while (v >= 0x80) : (v >>= 7) try out.append(a, @as(u8, @truncate(v)) | 0x80);
        try out.append(a, @truncate(v));
    }
    fn lenField(out: *std.ArrayList(u8), a: std.mem.Allocator, tag: u8, bytes: []const u8) !void {
        try out.append(a, tag);
        try varint(out, a, bytes.len);
        try out.appendSlice(a, bytes);
    }

    /// ExecuteTransactionResponse { transaction = 1 { digest = 1, effects = 4 { bcs = 1 { name,
    /// value }, status = 4 }, events = 5 } } for the request's mask (absent: `effects`), the
    /// way a node renders: only what the mask selects, fields in tag order.
    fn executeAnswer(a: std.mem.Allocator, request: []const u8) ![]u8 {
        var has_mask = false;
        var want_digest = false;
        var want_bcs = false;
        var want_status = false;
        var want_events = false;
        var seen: std.ArrayList(u8) = .empty;
        var r = serve.proto.Reader.init(request);
        while (try r.next()) |fld| if (fld.number == 3) {
            has_mask = true;
            var pr = serve.proto.Reader.init(try serve.proto.Reader.bytesOf(fld));
            while (try pr.next()) |pf| if (pf.number == 1) {
                const path = try serve.proto.Reader.stringOf(pf);
                if (seen.items.len > 0) try seen.append(a, ',');
                try seen.appendSlice(a, path);
                const eq = std.mem.eql;
                if (eq(u8, path, "digest")) want_digest = true;
                if (eq(u8, path, "events")) want_events = true;
                if (eq(u8, path, "effects") or eq(u8, path, "effects.bcs")) want_bcs = true;
                if (eq(u8, path, "effects") or eq(u8, path, "effects.status")) want_status = true;
            };
        };
        if (!has_mask) {
            want_bcs = true;
            want_status = true;
        }
        const n = @min(seen.items.len, seen_mask_buf.len);
        @memcpy(seen_mask_buf[0..n], seen.items[0..n]);
        seen_mask_len.store(n, .release);
        var eff: std.ArrayList(u8) = .empty;
        if (want_bcs) {
            var b: std.ArrayList(u8) = .empty;
            try lenField(&b, a, 0x0a, "TransactionEffects");
            try lenField(&b, a, 0x12, effects_bcs);
            try lenField(&eff, a, 0x0a, b.items);
        }
        if (want_status) try lenField(&eff, a, 0x22, "\x08\x01");
        var tx: std.ArrayList(u8) = .empty;
        if (want_digest) try lenField(&tx, a, 0x0a, "DigestOfTheTransaction");
        if (want_bcs or want_status) try lenField(&tx, a, 0x22, eff.items);
        if (want_events) try lenField(&tx, a, 0x2a, "\x12\x03evs");
        var out: std.ArrayList(u8) = .empty;
        try lenField(&out, a, 0x0a, tx.items);
        return out.items;
    }

    fn streamMessage(a: std.mem.Allocator, i: usize) ![]u8 {
        // sizes from a few bytes to 300 KiB: several h2 frames and more than one window
        const n: usize = if (i % 7 == 3) 300 * 1024 else 5 + i * 37;
        const b = try a.alloc(u8, n);
        for (b, 0..) |*x, k| x.* = @truncate(i *% 131 +% k);
        return b;
    }

    fn call(_: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const eq = std.mem.eql;
        if (eq(u8, req.path, p_info)) {
            _ = info_calls.fetchAdd(1, .monotonic);
            // GetServiceInfoResponse { lowest_available_checkpoint = 6: 77 }
            rs.message(&.{ 0x30, 77 }) catch return .internal;
            return .ok;
        }
        _ = calls.fetchAdd(1, .monotonic);
        if (req.client_protocol_version) |v| seen_protocol.store(v, .release);
        if (eq(u8, req.path, p_lookup)) {
            rs.message("hello from the core") catch return .internal;
            return .ok;
        }
        if (eq(u8, req.path, p_reverse)) {
            rs.setMessage(not_found_text);
            rs.details(&details);
            return .not_found;
        }
        if (eq(u8, req.path, p_object) or eq(u8, req.path, p_tx) or eq(u8, req.path, p_checkpoint)) {
            // echoes the request so a test sees the same bytes went through
            var buf: [512]u8 = undefined;
            const text = std.fmt.bufPrint(&buf, "core:{s}:{x}", .{ req.path, req.body[0..@min(req.body.len, 64)] }) catch "core";
            rs.message(text) catch return .internal;
            return .ok;
        }
        if (eq(u8, req.path, p_execute)) {
            if (exec_fail.load(.acquire)) {
                rs.setMessage("transaction rejected by the committee");
                rs.details(&details);
                return .invalid_argument;
            }
            if (effects_bcs.len > 0) {
                var arena = std.heap.ArenaAllocator.init(sys);
                defer arena.deinit();
                const answer = executeAnswer(arena.allocator(), req.body) catch return .internal;
                rs.message(answer) catch return .internal;
                return .ok;
            }
            rs.message("executed: effects and all") catch return .internal;
            return .ok;
        }
        if (eq(u8, req.path, p_simulate)) {
            if (req.deadline_ns) |d| seen_budget_ms.store((d -| nowNs()) / ms, .release);
            var left = slow_ms.load(.acquire);
            while (left > 0 and !rs.cancelled()) : (left -|= 5) sleepMs(5);
            rs.message("simulated") catch return .internal;
            return .ok;
        }
        if (eq(u8, req.path, p_list)) {
            if (serve.lh_service.ListPump.attachTest(req.stream_id, req.body, answerList)) return .deferred;
            return .unavailable;
        }
        if (eq(u8, req.path, p_events) or eq(u8, req.path, p_subscribe)) {
            if (serve.lh_service.ListPump.attachTest(req.stream_id, req.body, answerForever)) return .deferred;
            return .unavailable;
        }
        return .unimplemented;
    }

    fn answerList(_: *serve.lh_service.ListPump, arena: std.mem.Allocator, rs: *h2.ResponseStream) h2.Status {
        for (0..stream_messages) |i| {
            const m = streamMessage(arena, i) catch return .internal;
            rs.message(m) catch return .cancelled;
        }
        rs.setMessage(stream_end_text);
        rs.details(&details);
        return .out_of_range;
    }

    fn answerForever(_: *serve.lh_service.ListPump, _: std.mem.Allocator, rs: *h2.ResponseStream) h2.Status {
        var i: u32 = 0;
        while (i < 100_000) : (i += 1) {
            if (rs.cancelled()) break;
            rs.message("tick") catch break;
            _ = forever_sent.fetchAdd(1, .monotonic);
            sleepMs(5);
        }
        stream_cancelled.store(true, .release);
        return .cancelled;
    }

    const handler: h2.Handler = .{ .ctx = @constCast(&unit), .call = call };
    const unit: u8 = 0;
};

/// An h2 server on loopback (h2c, or TLS with `tls`), stopped and joined by `stop`.
const Server = struct {
    listener: Io.net.Server,
    port: u16,
    stop_flag: Atomic(bool) = .init(false),
    thread: std.Thread,
    handler: h2.Handler,
    opts: h2.ServerOptions,

    fn start(handler: h2.Handler, tls: ?h2.sock.Acceptor) !*Server {
        const s = try sys.create(Server);
        var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        s.* = .{ .listener = try addr.listen(io, .{ .reuse_address = true }), .port = 0, .thread = undefined, .handler = handler, .opts = .{ .poll_accept = true, .stop_grace_ns = 50 * ms, .tls = tls } };
        s.port = s.listener.socket.address.getPort();
        s.thread = try std.Thread.spawn(.{}, run, .{s});
        return s;
    }
    /// `start` with the grace a stopped server gives its open streams (the node: `--drain-ms`).
    fn startGrace(handler: h2.Handler, grace_ms: u64) !*Server {
        const s = try sys.create(Server);
        var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        s.* = .{ .listener = try addr.listen(io, .{ .reuse_address = true }), .port = 0, .thread = undefined, .handler = handler, .opts = .{ .poll_accept = true, .stop_grace_ns = grace_ms * ms } };
        s.port = s.listener.socket.address.getPort();
        s.thread = try std.Thread.spawn(.{}, run, .{s});
        return s;
    }
    fn run(s: *Server) void {
        h2.serveBlocking(sys, io, &s.listener, s.opts, s.handler, &s.stop_flag) catch {};
    }
    fn stop(s: *Server) void {
        s.stop_flag.store(true, .release);
        s.thread.join();
        _ = h2.server.waitDrained(3 * std.time.ns_per_s);
        s.listener.deinit(io);
        sys.destroy(s);
    }
};

// ---------------------------------------------------------------- the edge under test

/// The edge's local side: answers by script, counts what it was asked.
const Local = struct {
    calls: Atomic(u32) = .init(0),
    /// GetObject / GetTransaction / GetCheckpoint: the status to answer with (0: a message).
    code: Atomic(u8) = .init(0),
    with_details: Atomic(bool) = .init(true),
    /// Set `serve.service.gap` as a batch with a missing item would, then fail.
    gap: Atomic(u8) = .init(0),
    /// Answers end with `@<the store's tip>`: which state a local answer was given from.
    st: ?*store.Store = null,
    /// GetCheckpoint by number does what the service's does when the mask renders the
    /// certificate (service.zig `certState`): a marked checkpoint ends as the `foreign_cert` gap
    /// while the core can be asked, and is answered `held:...` when none can be reached.
    svc: ?*const serve.service.Service = null,

    fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const l: *Local = @ptrCast(@alignCast(ctx));
        _ = l.calls.fetchAdd(1, .monotonic);
        if (l.svc) |svc| if (serve.service.gap_watch and serve.service.gap_cert and std.mem.eql(u8, req.path, p_checkpoint)) {
            var r = serve.proto.Reader.init(req.body);
            var seq: ?u64 = null;
            while (r.next() catch null) |fld| if (fld.number == 1) {
                seq = serve.proto.Reader.varintOf(fld) catch null;
            };
            if (seq) |n| switch (serve.service.certState(svc, n)) {
                .core => {},
                .withhold => {
                    serve.service.gap = .foreign_cert;
                    rs.setMessage("internal error");
                    return .internal;
                },
                .held => {
                    if (svc.foreign_cert) |fc| fc.served_held(fc.ctx);
                    var hb: [300]u8 = undefined;
                    rs.message(std.fmt.bufPrint(&hb, "held:{s}@{d}", .{ req.path, if (l.st) |st| st.committed() orelse 0 else 0 }) catch "held") catch return .internal;
                    return .ok;
                },
            };
        };
        const g = l.gap.load(.acquire);
        if (g != 0 and serve.service.gap_watch) {
            serve.service.gap = @enumFromInt(g);
            rs.setMessage("internal error");
            return .internal;
        }
        const code = l.code.load(.acquire);
        if (code != 0) {
            rs.setMessage("local says no");
            if (l.with_details.load(.acquire)) rs.details(&.{ 0x08, code });
            return @enumFromInt(code);
        }
        var buf: [300]u8 = undefined;
        const text = if (l.st) |st|
            std.fmt.bufPrint(&buf, "local:{s}@{d}", .{ req.path, st.committed() orelse 0 }) catch "local"
        else
            std.fmt.bufPrint(&buf, "local:{s}", .{req.path}) catch "local";
        rs.message(text) catch return .internal;
        return .ok;
    }
};

const store_cfg: store.Config = .{ .retention_epochs = 2, .max_live_objects = 1 << 10, .max_object_versions = 1 << 12, .max_transactions = 1 << 10, .max_checkpoints = 1 << 8, .max_batch_bytes = 4 << 20, .max_batch_objects = 1 << 10, .max_segments = 64, .segment_reserve = 1 << 20, .seed = 7 };

const Edge = struct {
    tmp: testing.TmpDir,
    st: *store.Store,
    sio: *store.RealIo,
    svc: serve.service.Service,
    local: Local = .{},
    gt: forward.GrpcTransport,
    f: *forward.Forwarder,
    next_seq: u64 = 0,
    // the guard's view of the sources
    known_tip: Atomic(u64) = .init(std.math.maxInt(u64)),
    silent_ns: Atomic(u64) = .init(0),

    fn create(ep: grpc.Endpoint, cfg: forward.Config) !*Edge {
        const e = try testing.allocator.create(Edge);
        errdefer testing.allocator.destroy(e);
        e.tmp = testing.tmpDir(.{});
        errdefer e.tmp.cleanup();
        var pb: [512]u8 = undefined;
        const n = try e.tmp.dir.realPath(io, &pb);
        var cb: [600]u8 = undefined;
        var c = store_cfg;
        c.dir = try std.fmt.bufPrint(&cb, "{s}/store", .{pb[0..n]});
        const h = try store.openDir(testing.allocator, io, &c, .{ .sync = .none });
        e.st = h.store;
        e.sio = h.io;
        e.svc = .{ .gpa = testing.allocator, .store = h.store, .chain_id = @splat(0) };
        e.local = .{};
        e.next_seq = 0;
        e.known_tip = .init(std.math.maxInt(u64));
        e.silent_ns = .init(0);
        e.gt = try forward.GrpcTransport.init(sys, io, ep);
        e.gt.up.cooldown_ns = 50 * ms;
        e.f = try forward.Forwarder.create(testing.allocator, io, &e.svc, e.gt.transport(), cfg);
        e.f.inner = .{ .ctx = &e.local, .call = Local.call };
        e.f.source = .{ .ctx = e, .known_tip = knownTip, .silent_ns = silentNs };
        return e;
    }

    fn destroy(e: *Edge) void {
        e.f.destroy();
        // the transport's connection: closed, and its reader thread gone before the test ends
        const conn = e.gt.up.conn;
        if (conn) |c| c.retain();
        e.gt.deinit();
        if (conn) |c| {
            var i: u32 = 0;
            while (i < 5000) : (i += 1) {
                c.mu.lockUncancelable(io);
                const gone = c.reader_done;
                c.mu.unlock(io);
                if (gone) break;
                sleepMs(1);
            }
            c.unref();
        }
        e.svc.deinit();
        e.st.deinit();
        e.sio.deinit();
        e.tmp.cleanup();
        testing.allocator.destroy(e);
    }

    fn knownTip(ctx: *anyopaque) ?u64 {
        const e: *Edge = @ptrCast(@alignCast(ctx));
        const v = e.known_tip.load(.acquire);
        return if (v == std.math.maxInt(u64)) null else v;
    }
    fn silentNs(ctx: *anyopaque) u64 {
        const e: *Edge = @ptrCast(@alignCast(ctx));
        return e.silent_ns.load(.acquire);
    }

    /// Commits the next (synthetic) checkpoint, with `digest` as its one transaction when
    /// given, and tells the forwarder as the node's commit observer does.
    fn commit(e: *Edge, digest: ?*const [32]u8) !void {
        const b = try e.st.begin(e.next_seq, 0);
        errdefer e.st.abort(b);
        try b.checkpoint("summary", "contents");
        if (digest) |d| try b.transaction(d, &@as([32]u8, @splat(3)), "tx", "effects", null);
        try e.st.commit(b);
        e.next_seq += 1;
        e.f.noteApplied();
    }

    /// The guard as a healthy edge has it.
    fn healthy(e: *Edge) void {
        e.f.guard.state = .ok;
        e.f.guard_state.store(@intFromEnum(route.GuardState.ok), .release);
    }

    fn unary(e: *Edge, a: std.mem.Allocator, path: []const u8, body: []const u8) !loopback.Reply {
        return loopback.unary(a, e.f.handler(), path, body);
    }

    fn forwarded(e: *Edge, m: route.Method, why: route.Reason) u64 {
        return e.f.metrics.methods[@intFromEnum(m)].forwarded[@intFromEnum(why)].load(.monotonic);
    }
    fn servedLocal(e: *Edge, m: route.Method) u64 {
        return e.f.metrics.methods[@intFromEnum(m)].served_local.load(.monotonic);
    }
};

fn plain(port: u16) grpc.Endpoint {
    return .{ .host = "127.0.0.1", .port = port, .security = .plain };
}

fn expectSameReply(want: loopback.Reply, got: loopback.Reply) !void {
    try testing.expectEqual(want.status, got.status);
    try testing.expectEqualSlices(u8, want.message, got.message);
    try testing.expectEqualStrings(want.grpc_message, got.grpc_message);
    try testing.expectEqualSlices(u8, want.details, got.details);
}

// ---------------------------------------------------------------- tests

test "parseUpstream: TLS unless loopback or said out loud" {
    const P = forward.parseUpstream;
    const pin: []const u8 = &@as([64]u8, @splat('a'));
    const not_hex: []const u8 = &@as([64]u8, @splat('z'));
    // loopback without a suffix: h2c
    try testing.expectEqual(grpc.Security.plain, (try P("127.0.0.1:9000", null)).security);
    try testing.expectEqual(grpc.Security.plain, (try P("localhost:9000", null)).security);
    // anything else: WebPKI
    const ca = try P("core.example.org:443", null);
    try testing.expectEqual(grpc.Security.ca, ca.security);
    try testing.expectEqualStrings("core.example.org", ca.host);
    try testing.expectEqual(@as(u16, 443), ca.port);
    try testing.expectEqual(grpc.Security.ca, (try P("10.0.0.5:9000", null)).security);
    try testing.expectEqual(grpc.Security.ca, (try P("https://10.0.0.5:9000", null)).security);
    try testing.expectEqual(grpc.Security.ca, (try P("https://127.0.0.1:9000", null)).security);
    // cleartext to another host only when spelled
    try testing.expectEqual(grpc.Security.plain, (try P("10.0.0.5:9000/plain", null)).security);
    try testing.expectEqual(grpc.Security.plain, (try P("http://10.0.0.5:9000", null)).security);
    // a pin, in the address or from the flag
    var with_pin: [128]u8 = undefined;
    const p1 = try P(try std.fmt.bufPrint(&with_pin, "10.0.0.5:9443/pin={s}", .{pin}), null);
    try testing.expectEqual(@as([32]u8, @splat(0xaa)), p1.security.pinned_cert);
    var pin_b: [128]u8 = undefined;
    const p2 = try P("10.0.0.5:9443", try std.fmt.bufPrint(&pin_b, "sha256:{s}", .{pin}));
    try testing.expectEqual(@as([32]u8, @splat(0xaa)), p2.security.pinned_cert);
    const p3 = try P("127.0.0.1:9443", pin);
    try testing.expectEqual(@as([32]u8, @splat(0xaa)), p3.security.pinned_cert);
    // mistakes
    try testing.expectError(error.BadPin, P("10.0.0.5:9443/plain", pin));
    try testing.expectError(error.BadPin, P("10.0.0.5:9443/pin=abcd", null));
    try testing.expectError(error.BadPin, P("10.0.0.5:9443", not_hex));
    try testing.expectError(error.BadUpstream, P("10.0.0.5", null));
    try testing.expectError(error.BadUpstream, P(":9000", null));
    try testing.expectError(error.BadUpstream, P("10.0.0.5:port", null));
    try testing.expectError(error.BadUpstream, P("10.0.0.5:9000/tls", null));
    try testing.expectError(error.BadUpstream, P("https://10.0.0.5:9000/plain", null));
}

test "a forwarded unary call returns the core's bytes, status, message and details; a local one never reaches the core" {
    core.reset();
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{});
    defer e.destroy();
    e.healthy();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // policy: NameService goes to the core, success and error alike
    try expectSameReply(try loopback.unary(a, core.handler, p_lookup, "name"), try e.unary(a, p_lookup, "name"));
    const nf = try e.unary(a, p_reverse, "addr");
    try expectSameReply(try loopback.unary(a, core.handler, p_reverse, "addr"), nf);
    try testing.expectEqual(@as(u8, 5), nf.status);
    try testing.expectEqualStrings(core.not_found_text, nf.grpc_message);
    try testing.expectEqualSlices(u8, &core.details, nf.details);
    try testing.expectEqual(@as(u64, 2), e.forwarded(.lookup_name, .policy) + e.forwarded(.reverse_lookup_name, .policy));
    try testing.expectEqual(@as(u32, 0), e.local.calls.load(.acquire));

    // local: the edge's own answer, the core is not asked
    const before = core.calls.load(.acquire);
    const obj = try e.unary(a, p_object, "\x0a\x030x5");
    try testing.expectEqualStrings("local:" ++ p_object, obj.message);
    try testing.expectEqual(before, core.calls.load(.acquire));
    try testing.expectEqual(@as(u64, 1), e.servedLocal(.get_object));

    // a local miss is not the edge's to give: the core's answer goes out
    e.local.code.store(5, .release);
    const miss = try e.unary(a, p_object, "\x0a\x030x5");
    try expectSameReply(try loopback.unary(a, core.handler, p_object, "\x0a\x030x5"), miss);
    try testing.expectEqual(@as(u64, 1), e.forwarded(.get_object, .negative));
    // ... and so is OUT_OF_RANGE, an index that is not ready, an RpcError internal
    e.local.code.store(11, .release);
    _ = try e.unary(a, p_tx, "\x0a\x01x");
    try testing.expectEqual(@as(u64, 1), e.forwarded(.get_transaction, .negative));
    e.local.code.store(14, .release);
    _ = try e.unary(a, p_tx, "\x0a\x01x");
    try testing.expectEqual(@as(u64, 1), e.forwarded(.get_transaction, .other));
    // INVALID_ARGUMENT is the request's own fault: it stands, with the edge's details
    e.local.code.store(3, .release);
    const bad = try e.unary(a, p_tx, "\x0a\x01x");
    try testing.expectEqual(@as(u8, 3), bad.status);
    try testing.expectEqualStrings("local says no", bad.grpc_message);
    try testing.expectEqualSlices(u8, &.{ 0x08, 3 }, bad.details);
    // a gap met by the local handler (a batch item it does not hold) forwards the whole call
    e.local.code.store(0, .release);
    e.local.gap.store(@intFromEnum(route.Gap.item_missing), .release);
    const gap = try e.unary(a, p_tx, "\x0a\x01x");
    try testing.expect(std.mem.startsWith(u8, gap.message, "core:"));
    try testing.expectEqual(@as(u64, 2), e.forwarded(.get_transaction, .negative));
    e.local.gap.store(@intFromEnum(route.Gap.sig_order), .release);
    _ = try e.unary(a, p_tx, "\x0a\x01x");
    try testing.expectEqual(@as(u64, 1), e.forwarded(.get_transaction, .needs_read_sets));
    e.local.gap.store(0, .release);

    // a mask that needs the object set never touches the local handler
    const local_before = e.local.calls.load(.acquire);
    // GetTransactionRequest { digest = 1: "x", read_mask = 2 { paths: "effects" } }
    const eff = try e.unary(a, p_tx, "\x0a\x01x\x12\x09\x0a\x07effects");
    try testing.expect(std.mem.startsWith(u8, eff.message, "core:"));
    try testing.expectEqual(local_before, e.local.calls.load(.acquire));
    try testing.expectEqual(@as(u64, 2), e.forwarded(.get_transaction, .needs_read_sets));

    // the edge's own paths are the edge's
    const health = try e.unary(a, "/grpc.health.v1.Health/Check", "");
    try testing.expectEqualStrings("local:/grpc.health.v1.Health/Check", health.message);

    // the metrics text names all of it
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try forward.renderMetrics(e.f, &out.writer);
    const text = out.written();
    try testing.expect(std.mem.indexOf(u8, text, "zui_edge_route_served_local{method=\"/sui.rpc.v2.LedgerService/GetObject\"} 1\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "zui_edge_route_forward_reason{method=\"/sui.rpc.v2.LedgerService/GetTransaction\",reason=\"needs_read_sets\"} 2\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "zui_edge_route_forward_reason{method=\"/sui.rpc.v2.NameService/LookupName\",reason=\"policy\"} 1\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "zui_edge_route_guard 0\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "zui_edge_route_forward_latency_seconds_count{method=\"/sui.rpc.v2.NameService/LookupName\"} 1\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "zui_edge_route_execute_hold_seconds_count 0\n") != null);
}

test "requests ahead of the edge wait for the follower, then go to the core" {
    core.reset();
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{ .ahead_wait_ms = 300 });
    defer e.destroy();
    e.healthy();
    for (0..5) |_| try e.commit(null); // tip 4
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // GetCheckpointRequest { sequence_number = 1 }
    const at4 = try e.unary(a, p_checkpoint, "\x08\x04");
    try testing.expectEqualStrings("local:" ++ p_checkpoint, at4.message);

    // checkpoint 5 arrives 80 ms into the wait: answered locally, well inside the bound
    const T = struct {
        fn later(edge: *Edge, after_ms: u64) void {
            sleepMs(after_ms);
            edge.commit(null) catch {};
        }
    };
    var t0 = nowNs();
    var th = try std.Thread.spawn(.{}, T.later, .{ e, 80 });
    const at5 = try e.unary(a, p_checkpoint, "\x08\x05");
    th.join();
    var took = (nowNs() - t0) / ms;
    try testing.expectEqualStrings("local:" ++ p_checkpoint, at5.message);
    try testing.expect(took >= 70 and took < 280);
    try testing.expectEqual(@as(u64, 0), e.forwarded(.get_checkpoint, .ahead));

    // checkpoint 9 never arrives: the whole wait, then the core's answer
    t0 = nowNs();
    const at9 = try e.unary(a, p_checkpoint, "\x08\x09");
    took = (nowNs() - t0) / ms;
    try testing.expect(std.mem.startsWith(u8, at9.message, "core:"));
    try testing.expect(took >= 290 and took < 1500);
    try testing.expectEqual(@as(u64, 1), e.forwarded(.get_checkpoint, .ahead));

    // by digest: no wait at all; a local miss goes straight to the core
    e.local.code.store(5, .release);
    t0 = nowNs();
    // GetCheckpointRequest { digest = 2: "d" }
    const byd = try e.unary(a, p_checkpoint, "\x12\x01d");
    try testing.expect(std.mem.startsWith(u8, byd.message, "core:"));
    try testing.expect((nowNs() - t0) / ms < 250);
    try testing.expectEqual(@as(u64, 1), e.forwarded(.get_checkpoint, .negative));
}

test "a forwarded server stream: every message in order, then the core's status and details" {
    core.reset();
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{});
    defer e.destroy();
    e.healthy();
    const front = try Server.start(e.f.handler(), null);
    defer front.stop();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const direct = try loopback.call(a, io, up.port, p_list, &.{}, &.{"req"}, .{});
    const via = try loopback.call(a, io, front.port, p_list, &.{}, &.{"req"}, .{});
    try testing.expect(direct.ended and via.ended);
    try testing.expectEqual(@as(usize, core.stream_messages), direct.messages.items.len);
    try testing.expectEqual(direct.messages.items.len, via.messages.items.len);
    for (direct.messages.items, via.messages.items) |d, v| try testing.expectEqualSlices(u8, d.payload, v.payload);
    // the trailers: grpc-status, grpc-message, grpc-status-details-bin, byte for byte
    inline for (.{ "grpc-status", "grpc-message", "grpc-status-details-bin" }) |name| {
        const dv = header(direct.trailers.items, name) orelse return error.MissingTrailer;
        const vv = header(via.trailers.items, name) orelse return error.MissingTrailer;
        try testing.expectEqualStrings(dv, vv);
    }
    try testing.expectEqualStrings("11", header(via.trailers.items, "grpc-status").?);
    try testing.expectEqual(@as(u64, 1), e.forwarded(.list_checkpoints, .list_paging));
}

fn header(list: []const [2][]const u8, name: []const u8) ?[]const u8 {
    for (list) |kv| if (std.mem.eql(u8, kv[0], name)) return kv[1];
    return null;
}

test "a client that leaves cancels the upstream call" {
    core.reset();
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{});
    defer e.destroy();
    e.healthy();
    const front = try Server.start(e.f.handler(), null);
    defer front.stop();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // the client reads three messages of an endless stream and closes its connection
    const rep = try loopback.call(arena.allocator(), io, front.port, p_events, &.{}, &.{"req"}, .{ .max_messages = 3 });
    try testing.expect(rep.messages.items.len >= 3);
    try testing.expect(!rep.ended);
    // the core's handler sees its stream reset, promptly
    var waited: u32 = 0;
    while (!core.stream_cancelled.load(.acquire) and waited < 3000) : (waited += 5) sleepMs(5);
    try testing.expect(core.stream_cancelled.load(.acquire));
    try testing.expect(waited < 2000);
    // and it stopped being fed: a handful of messages, not thousands
    try testing.expect(core.forever_sent.load(.acquire) < 400);
}

test "deadlines: the core gets the time left, and a slow core is DEADLINE_EXCEEDED on time" {
    core.reset();
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{});
    defer e.destroy();
    e.healthy();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // in time: the budget the core saw is the client's, less what the edge used
    const ok = try loopback.unaryTimeout(a, e.f.handler(), p_simulate, "tx", 5000);
    try testing.expectEqualStrings("simulated", ok.message);
    const budget = core.seen_budget_ms.load(.acquire);
    try testing.expect(budget > 4000 and budget <= 5000);
    // too slow: answered at the deadline, as a node answers a call that ran out of time
    core.slow_ms.store(1500, .release);
    const t0 = nowNs();
    const late = try loopback.unaryTimeout(a, e.f.handler(), p_simulate, "tx", 200);
    const took = (nowNs() - t0) / ms;
    try testing.expectEqual(@as(u8, 4), late.status);
    try testing.expectEqualStrings("Timeout expired", late.grpc_message);
    try testing.expect(took >= 190 and took < 900);
    try testing.expectEqual(@as(u64, 2), e.forwarded(.simulate_transaction, .policy));
}

test "a core that refuses connections: UNAVAILABLE at once, naming the upstream; local reads go on" {
    core.reset();
    // a port nobody listens on
    var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var l = try addr.listen(io, .{ .reuse_address = true });
    const dead_port = l.socket.address.getPort();
    l.deinit(io);
    const e = try Edge.create(plain(dead_port), .{});
    defer e.destroy();
    e.healthy();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (0..3) |_| {
        const t0 = nowNs();
        const r = try e.unary(a, p_lookup, "name");
        try testing.expectEqual(@as(u8, 14), r.status);
        try testing.expect(std.mem.startsWith(u8, r.grpc_message, "edge: core upstream unavailable (transport error"));
        try testing.expect((nowNs() - t0) / ms < 2500);
        sleepMs(60); // past the reconnect cooldown: the next call dials again
    }
    try testing.expectEqual(@as(u64, 3), e.f.metrics.methods[@intFromEnum(route.Method.lookup_name)].upstream_errors.load(.monotonic));
    // what the edge holds it still serves
    const obj = try e.unary(a, p_object, "\x0a\x030x5");
    try testing.expectEqualStrings("local:" ++ p_object, obj.message);
    // with the guard tripped too (feed and fallback both lost), everything is the core's to
    // answer, and the client is told it is unavailable rather than given stale data
    e.silent_ns.store(10 * std.time.ns_per_s, .release);
    e.known_tip.store(0, .release);
    e.f.tick();
    try testing.expectEqual(route.GuardState.tripped, e.f.guardState());
    const stale = try e.unary(a, p_object, "\x0a\x030x5");
    try testing.expectEqual(@as(u8, 14), stale.status);
    try testing.expectEqual(@as(u64, 1), e.forwarded(.get_object, .lag_guard));
}

/// A raw h2c peer: answers the first request with response headers, one whole gRPC message and
/// the first half of a second one, then drops the connection (`rst`: resets the stream first).
const BrokenCore = struct {
    listener: Io.net.Server,
    port: u16,
    thread: std.Thread,
    rst: bool,

    fn start(rst: bool) !*BrokenCore {
        const b = try sys.create(BrokenCore);
        var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        b.* = .{ .listener = try addr.listen(io, .{ .reuse_address = true }), .port = 0, .thread = undefined, .rst = rst };
        b.port = b.listener.socket.address.getPort();
        b.thread = try std.Thread.spawn(.{}, run, .{b});
        return b;
    }
    fn frame(out: *std.ArrayList(u8), kind: u8, flags: u8, id: u32, payload: []const u8) !void {
        var h: [9]u8 = undefined;
        std.mem.writeInt(u24, h[0..3], @intCast(payload.len), .big);
        h[3] = kind;
        h[4] = flags;
        std.mem.writeInt(u32, h[5..9], id, .big);
        try out.appendSlice(sys, &h);
        try out.appendSlice(sys, payload);
    }
    fn run(b: *BrokenCore) void {
        const st = b.listener.accept(io) catch return;
        defer st.close(io);
        // read until the request is in: its path (a literal in the header block), then a
        // moment for its DATA
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(sys);
        var buf: [4096]u8 = undefined;
        while (std.mem.indexOf(u8, got.items, "ListCheckpoints") == null) {
            var iov = [_][]u8{&buf};
            const n = st.read(io, &iov) catch return;
            if (n == 0) return;
            got.appendSlice(sys, buf[0..n]) catch return;
        }
        sleepMs(20);
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(sys);
        frame(&out, 4, 0, 0, &.{}) catch return; // SETTINGS
        var hb: std.ArrayList(u8) = .empty;
        defer hb.deinit(sys);
        h2.hpack.encodeLiteral(&hb, sys, ":status", "200") catch return;
        h2.hpack.encodeLiteral(&hb, sys, "content-type", "application/grpc") catch return;
        frame(&out, 1, 4, 1, hb.items) catch return;
        // message "whole", then 5 of the 9 bytes of a second frame
        frame(&out, 0, 0, 1, &[_]u8{ 0, 0, 0, 0, 5, 'w', 'h', 'o', 'l', 'e', 0, 0, 0, 0, 4 }) catch return;
        if (b.rst) frame(&out, 3, 0, 1, &.{ 0, 0, 0, 2 }) catch return;
        var wbuf: [256]u8 = undefined;
        var w = st.writer(io, &wbuf);
        w.interface.writeAll(out.items) catch return;
        w.interface.flush() catch return;
        sleepMs(if (b.rst) 300 else 30);
    }
    fn stop(b: *BrokenCore) void {
        // wake an accept nobody reached
        var addr = Io.net.IpAddress.parseIp4("127.0.0.1", b.port) catch unreachable;
        if (addr.connect(io, .{ .mode = .stream })) |c| c.close(io) else |_| {}
        b.thread.join();
        b.listener.deinit(io);
        sys.destroy(b);
    }
};

test "a core that drops mid-answer: what arrived is relayed, then UNAVAILABLE; no hang" {
    inline for (.{ false, true }) |rst| {
        const b = try BrokenCore.start(rst);
        defer b.stop();
        const e = try Edge.create(plain(b.port), .{});
        defer e.destroy();
        e.healthy();
        const front = try Server.start(e.f.handler(), null);
        defer front.stop();
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const t0 = nowNs();
        const rep = try loopback.call(arena.allocator(), io, front.port, p_list, &.{}, &.{"req"}, .{});
        try testing.expect((nowNs() - t0) / ms < 3000);
        try testing.expect(rep.ended);
        try testing.expectEqual(@as(usize, 1), rep.messages.items.len);
        try testing.expectEqualStrings("whole", rep.messages.items[0].payload);
        try testing.expectEqualStrings("14", header(rep.trailers.items, "grpc-status").?);
        // (as sent: percent-encoded)
        const text = header(rep.trailers.items, "grpc-message").?;
        try testing.expect(std.mem.startsWith(u8, text, "edge:") and std.mem.indexOf(u8, text, "unavailable") != null);
    }
}

test "TLS upstream: the pinned certificate is the only one accepted" {
    core.reset();
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var tls = native.tcptls.Server.init(sys, io, native.cert.generate(try P256.KeyPair.generateDeterministic(@splat(6)), @splat(1), 1_800_000_000, 14, "localhost"));
    defer tls.deinit();
    const up = try Server.start(core.handler, tls.acceptor());
    defer up.stop();
    const good = tls.cert.sha256();
    var bad = good;
    bad[0] ^= 1;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    {
        // the right pin: the core's answer, verbatim, over TLS
        const e = try Edge.create(.{ .host = "127.0.0.1", .port = up.port, .security = .{ .pinned_cert = good } }, .{});
        defer e.destroy();
        e.healthy();
        const r = try e.unary(a, p_reverse, "addr");
        try testing.expectEqual(@as(u8, 5), r.status);
        try testing.expectEqualStrings(core.not_found_text, r.grpc_message);
        try testing.expectEqualSlices(u8, &core.details, r.details);
    }
    const calls_before = core.calls.load(.acquire);
    {
        // another certificate's hash: no call ever reaches that server
        const e = try Edge.create(.{ .host = "127.0.0.1", .port = up.port, .security = .{ .pinned_cert = bad } }, .{});
        defer e.destroy();
        e.healthy();
        const t0 = nowNs();
        const r = try e.unary(a, p_lookup, "name");
        try testing.expectEqual(@as(u8, 14), r.status);
        try testing.expect(std.mem.indexOf(u8, r.grpc_message, "tls handshake failed") != null);
        try testing.expect((nowNs() - t0) / ms < 3000);
    }
    {
        // and WebPKI does not take a self-signed certificate
        const e = try Edge.create(.{ .host = "127.0.0.1", .port = up.port, .security = .ca }, .{});
        defer e.destroy();
        e.healthy();
        const r = try e.unary(a, p_lookup, "name");
        try testing.expectEqual(@as(u8, 14), r.status);
    }
    try testing.expectEqual(calls_before, core.calls.load(.acquire));
}

/// ExecuteTransactionRequest { transaction = 1 { bcs = 1 { value = 2: `data` } } }.
fn executeRequest(a: std.mem.Allocator, data: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, &.{ 0x0a, @intCast(data.len + 4), 0x0a, @intCast(data.len + 2), 0x12, @intCast(data.len) });
    try out.appendSlice(a, data);
    return out.items;
}

fn txDigest(data: []const u8) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2b256.init(.{});
    h.update("TransactionData::");
    h.update(data);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

test "read-after-write: a successful execute is held until the edge applied it, at most the bound; a failed one never" {
    core.reset();
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{ .raw = .hold });
    defer e.destroy();
    e.healthy();
    try e.f.start();
    for (0..3) |_| try e.commit(null);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try loopback.unary(a, core.handler, p_execute, "x");
    const hold = &e.f.metrics.execute_hold;

    // early: the edge applied the checkpoint before the core's answer came back
    {
        const req = try executeRequest(a, "early transaction");
        const d = txDigest("early transaction");
        try e.commit(&d);
        const t0 = nowNs();
        const r = try e.unary(a, p_execute, req);
        try expectSameReply(want, r);
        try testing.expect((nowNs() - t0) / ms < 400);
        try testing.expectEqual(@as(u64, 1), hold.n.load(.monotonic));
        try testing.expectEqual(@as(usize, 0), e.f.pending.n.load(.acquire));
    }
    // late: the checkpoint lands 300 ms after the execute; the answer follows it at once
    {
        const req = try executeRequest(a, "late transaction");
        const T = struct {
            fn later(edge: *Edge) void {
                sleepMs(300);
                const d = txDigest("late transaction");
                edge.commit(&d) catch {};
            }
        };
        const t0 = nowNs();
        var th = try std.Thread.spawn(.{}, T.later, .{e});
        const r = try e.unary(a, p_execute, req);
        const took = (nowNs() - t0) / ms;
        th.join();
        try expectSameReply(want, r);
        try testing.expect(took >= 290 and took < 1200);
        try testing.expectEqual(@as(u64, 2), hold.n.load(.monotonic));
        try testing.expectEqual(@as(u64, 0), e.f.metrics.execute_hold_timeouts.load(.monotonic));
    }
    // never: answered anyway at the 2 s bound, and the digest stays pending for the read side
    {
        const req = try executeRequest(a, "lost transaction");
        const t0 = nowNs();
        const r = try e.unary(a, p_execute, req);
        const took = (nowNs() - t0) / ms;
        try expectSameReply(want, r);
        try testing.expect(took >= 1990 and took < 2900);
        try testing.expectEqual(@as(u64, 1), e.f.metrics.execute_hold_timeouts.load(.monotonic));
        const d = txDigest("lost transaction");
        try testing.expect(e.f.pending.contains(&d));
        // ... until its checkpoint is applied after all
        try e.commit(&d);
        var waited: u32 = 0;
        while (e.f.pending.contains(&d) and waited < 2000) : (waited += 5) sleepMs(5);
        try testing.expect(!e.f.pending.contains(&d));
    }
    // a failed execute is the core's error, at once, and nothing is pending
    {
        core.exec_fail.store(true, .release);
        defer core.exec_fail.store(false, .release);
        const req = try executeRequest(a, "rejected transaction");
        const t0 = nowNs();
        const r = try e.unary(a, p_execute, req);
        try testing.expectEqual(@as(u8, 3), r.status);
        try testing.expectEqualStrings("transaction rejected by the committee", r.grpc_message);
        try testing.expectEqualSlices(u8, &core.details, r.details);
        try testing.expect((nowNs() - t0) / ms < 400);
        try testing.expectEqual(@as(usize, 0), e.f.pending.n.load(.acquire));
        try testing.expectEqual(@as(u64, 3), hold.n.load(.monotonic));
    }
    // the histogram is exported
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try forward.renderMetrics(e.f, &out.writer);
    try testing.expect(std.mem.indexOf(u8, out.written(), "zui_edge_route_execute_hold_seconds_count 3\n") != null);
    try testing.expect(std.mem.indexOf(u8, out.written(), "zui_edge_route_execute_hold_timeouts 1\n") != null);
    // the floor thread read the core's lowest checkpoint
    try testing.expect(std.mem.indexOf(u8, out.written(), "zui_edge_route_core_lowest_checkpoint 77\n") != null);
}

test "read-after-write off: the execute answer is not held" {
    core.reset();
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{ .execute_wait_ms = 0 });
    defer e.destroy();
    e.healthy();
    try testing.expectEqual(forward.ExecMode.off, e.f.cfg.execMode());
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t0 = nowNs();
    const r = try e.unary(a, p_execute, try executeRequest(a, "any transaction"));
    try testing.expectEqualStrings("executed: effects and all", r.message);
    try testing.expect((nowNs() - t0) / ms < 400);
    try testing.expectEqual(@as(u64, 0), e.f.metrics.execute_hold.n.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), e.f.pending.n.load(.acquire));
}

test "lag guard: trips past the limit, forwards everything, closes local streams, recovers under half the limit after the hold" {
    core.reset();
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{ .max_lag = 5, .hold_ms = 60 });
    defer e.destroy();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // two local subscriptions (slots without a client behind them)
    var hub = serve.subscribe.Hub.init(testing.allocator, io, &e.svc);
    defer hub.deinit();
    e.svc.hub = &hub;
    defer e.svc.hub = null;
    const s1 = (try hub.holdSlot(.checkpoints)).?;
    const s2 = (try hub.holdSlot(.checkpoints)).?;

    for (0..11) |_| try e.commit(null); // tip 10
    // a new edge is tripped until it has shown it is fresh for the hold
    try testing.expectEqual(route.GuardState.tripped, e.f.guardState());
    const first = try e.unary(a, p_object, "\x0a\x030x5");
    try testing.expect(std.mem.startsWith(u8, first.message, "core:"));
    try testing.expectEqual(@as(u64, 1), e.forwarded(.get_object, .lag_guard));
    e.known_tip.store(10, .release);
    e.f.tick();
    try testing.expectEqual(route.GuardState.tripped, e.f.guardState());
    sleepMs(70);
    e.f.tick();
    try testing.expectEqual(route.GuardState.ok, e.f.guardState());
    try testing.expectEqual(@as(u64, 0), e.f.metrics.lag.load(.monotonic));
    try testing.expectEqualStrings("local:" ++ p_object, (try e.unary(a, p_object, "\x0a\x030x5")).message);

    // 5 behind: still serving; 6 behind: tripped
    e.known_tip.store(15, .release);
    e.f.tick();
    try testing.expectEqual(route.GuardState.ok, e.f.guardState());
    try testing.expect(s1.end == null and s2.end == null);
    e.known_tip.store(16, .release);
    e.f.tick();
    try testing.expectEqual(route.GuardState.tripped, e.f.guardState());
    try testing.expectEqual(@as(u64, 6), e.f.metrics.lag.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), e.f.metrics.guard_trips.load(.monotonic));
    // the local streams were ended UNAVAILABLE, so their clients reconnect (and are forwarded)
    try testing.expectEqual(serve.subscribe.Reason.source_lag, s1.end.?);
    try testing.expectEqualStrings(forward.Forwarder.guard_stream_text, s1.end_unavailable.?);
    try testing.expectEqualStrings(forward.Forwarder.guard_stream_text, s2.end_unavailable.?);
    try testing.expectEqual(@as(u64, 2), e.f.metrics.streams_closed.load(.monotonic));
    hub.releaseHeld(s1);
    hub.releaseHeld(s2);
    // everything forwards, the locally answerable too
    const before = e.local.calls.load(.acquire);
    const fwd = try e.unary(a, p_object, "\x0a\x030x5");
    try testing.expect(std.mem.startsWith(u8, fwd.message, "core:"));
    try testing.expectEqual(before, e.local.calls.load(.acquire));
    try testing.expectEqual(@as(u64, 2), e.forwarded(.get_object, .lag_guard));

    // catching up to the limit, or to just over half of it, does not recover it, however long
    for ([_]u64{ 15, 13 }) |known| {
        e.known_tip.store(known, .release);
        e.f.tick();
        sleepMs(70);
        e.f.tick();
        try testing.expectEqual(route.GuardState.tripped, e.f.guardState());
    }
    // within half the limit: only after the hold
    e.known_tip.store(12, .release);
    e.f.tick();
    try testing.expectEqual(route.GuardState.tripped, e.f.guardState());
    sleepMs(70);
    e.f.tick();
    try testing.expectEqual(route.GuardState.ok, e.f.guardState());
    try testing.expectEqual(@as(u64, 1), e.f.metrics.guard_recoveries.load(.monotonic) - 1);
    // hovering at the boundary does not flap it
    for (0..20) |i| {
        e.known_tip.store(if (i % 2 == 0) 15 else 14, .release);
        e.f.tick();
    }
    try testing.expectEqual(route.GuardState.ok, e.f.guardState());
    try testing.expectEqual(@as(u64, 1), e.f.metrics.guard_trips.load(.monotonic));

    // sources silent (feed and fallback both lost), or the tip unknown (catch-up): tripped
    e.silent_ns.store(4 * std.time.ns_per_s, .release);
    e.f.tick();
    try testing.expectEqual(route.GuardState.tripped, e.f.guardState());
    e.silent_ns.store(0, .release);
    e.known_tip.store(10, .release);
    e.f.tick();
    sleepMs(70);
    e.f.tick();
    try testing.expectEqual(route.GuardState.ok, e.f.guardState());
    e.known_tip.store(std.math.maxInt(u64), .release);
    e.f.tick();
    try testing.expectEqual(route.GuardState.tripped, e.f.guardState());
    try testing.expectEqual(@as(u64, 3), e.f.metrics.guard_trips.load(.monotonic));
}

test "the protocol version header goes along; the edge reports the core's lowest checkpoint once it knows it" {
    core.reset();
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{});
    defer e.destroy();
    e.healthy();
    const front = try Server.start(e.f.handler(), null);
    defer front.stop();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rep = try loopback.call(a, io, front.port, p_simulate, &.{.{ "x-sui-client-protocol-version", "141" }}, &.{"tx"}, .{});
    try testing.expect(rep.ended);
    try testing.expectEqual(@as(u64, 141), core.seen_protocol.load(.acquire));

    // GetServiceInfo: the core's until the edge has read the core's floor, then its own
    const info1 = try e.unary(a, p_info, "");
    try testing.expectEqualSlices(u8, &.{ 0x30, 77 }, info1.message);
    try testing.expectEqual(@as(u64, 1), e.forwarded(.get_service_info, .other));
    e.f.refreshFloor(nowNs());
    try testing.expectEqual(@as(u64, 77), serve.service.reportedLowest(&e.svc));
    const info2 = try e.unary(a, p_info, "");
    try testing.expectEqualStrings("local:" ++ p_info, info2.message);
    try testing.expectEqual(@as(u64, 1), e.servedLocal(.get_service_info));
}

test "routing overhead on a locally served call" {
    core.reset();
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{});
    defer e.destroy();
    e.healthy();
    for (0..3) |_| try e.commit(null);
    // a response stream that drops what it is given: only the handlers are timed
    const Null = struct {
        fn write(_: *anyopaque, _: *const [5]u8, _: []const u8) anyerror!void {}
        fn cancelled(_: *anyopaque) bool {
            return false;
        }
        const vt: h2.ResponseStream.VTable = .{ .write = write, .cancelled = cancelled };
    };
    var unit: u8 = 0;
    const n: u64 = if (@import("builtin").mode == .debug) 20_000 else 2_000_000;
    const cases = [_]struct { path: []const u8, body: []const u8 }{
        .{ .path = p_object, .body = "\x0a\x030x5" },
        // GetCheckpointRequest { sequence_number = 2, read_mask { "sequence_number", "digest", "summary" } }
        .{ .path = p_checkpoint, .body = "\x08\x02\x1a\x22\x0a\x0fsequence_number\x0a\x06digest\x0a\x07summary" },
        // GetTransactionRequest { digest, read_mask { "digest", "transaction", "events" } }
        .{ .path = p_tx, .body = "\x0a\x01x\x12\x1d\x0a\x06digest\x0a\x0btransaction\x0a\x06events" },
    };
    const outer = e.f.handler();
    const inner = e.f.inner;
    for (cases) |c| {
        const req: h2.Request = .{ .path = c.path, .authority = "", .body = c.body, .stream_id = 1 };
        var best_inner: u64 = std.math.maxInt(u64);
        var best_outer: u64 = std.math.maxInt(u64);
        for (0..5) |_| {
            var t0 = nowNs();
            for (0..n) |_| {
                var rs: h2.ResponseStream = .{ .gpa = testing.allocator, .impl = &unit, .vt = &Null.vt };
                _ = inner.call(inner.ctx, &req, &rs);
                rs.release();
            }
            best_inner = @min(best_inner, nowNs() - t0);
            t0 = nowNs();
            for (0..n) |_| {
                var rs: h2.ResponseStream = .{ .gpa = testing.allocator, .impl = &unit, .vt = &Null.vt };
                _ = outer.call(outer.ctx, &req, &rs);
                rs.release();
            }
            best_outer = @min(best_outer, nowNs() - t0);
        }
        std.debug.print("edge routing overhead, {s} ({s}): scripted handler alone {d} ns/call, through the forwarder {d} ns/call, routing {d} ns/call\n", .{ c.path, @tagName(@import("builtin").mode), best_inner / n, best_outer / n, (best_outer -| best_inner) / n });
    }
    try testing.expectEqual(@as(u64, 0), core.calls.load(.acquire));
    // read-after-write: the same GetObject while transactions are pending that did not write it
    // (the table is looked up: the id is parsed and hashed under the table's lock)
    const req: h2.Request = .{ .path = p_object, .authority = "", .body = "\x0a\x030x5", .stream_id = 1 };
    const far = nowNs() + 3600 * std.time.ns_per_s;
    var pending_n: usize = 0;
    for ([_]usize{ 1, 1000 }) |target| {
        while (pending_n < target) : (pending_n += 1) {
            var d: [32]u8 = @splat(0xee);
            std.mem.writeInt(u64, d[0..8], pending_n, .little);
            var o: [32]u8 = @splat(0xcc);
            std.mem.writeInt(u64, o[0..8], pending_n, .little);
            try testing.expect(e.f.pending.addWrites(&d, nowNs(), far, .{ .objects = &.{o}, .addresses = &.{o} }));
        }
        var best: u64 = std.math.maxInt(u64);
        for (0..5) |_| {
            const t0 = nowNs();
            for (0..n) |_| {
                var rs: h2.ResponseStream = .{ .gpa = testing.allocator, .impl = &unit, .vt = &Null.vt };
                _ = outer.call(outer.ctx, &req, &rs);
                rs.release();
            }
            best = @min(best, nowNs() - t0);
        }
        std.debug.print("edge routing overhead, GetObject with {d} pending transactions that did not write it ({s}): {d} ns/call through the forwarder\n", .{ target, @tagName(@import("builtin").mode), best / n });
    }
    try testing.expectEqual(@as(u64, 0), core.calls.load(.acquire));
}

// ---------------------------------------------------------------- read-after-write, mode `reads`

const raw = forward.raw;

fn rid(b: u8) [32]u8 {
    return @splat(b);
}
const o_gas = rid(0x11); // mutated, owned by `a_owner` before and after
const o_field = rid(0x12); // a dynamic field created under `o_parent`
const o_parent = rid(0x13);
const o_other = rid(0x77); // written by nobody
const a_owner = rid(0xa1);
const a_other = rid(0xa9);

/// BCS effects: the gas object mutated (owned by `a_owner`), a dynamic field created under
/// `o_parent`.
fn someEffects(a: std.mem.Allocator) ![]u8 {
    const dg: types.ObjectDigest = .{ .@"0" = .{ .@"0" = rid(3) } };
    const eff: types.TransactionEffects = .{ .V2 = .{
        .status = .Success,
        .executed_epoch = 7,
        .gas_used = .{ .computationCost = 1, .storageCost = 2, .storageRebate = 3, .nonRefundableStorageFee = 0 },
        .transaction_digest = .{ .@"0" = .{ .@"0" = rid(0xdd) } },
        .gas_object_index = 0,
        .events_digest = null,
        .dependencies = &.{},
        .lamport_version = .{ .@"0" = 12 },
        .changed_objects = &.{
            .{ .{ .@"0" = .{ .@"0" = o_gas } }, .{ .input_state = .{ .Exist = .{ .{ .{ .@"0" = 5 }, dg }, .{ .AddressOwner = .{ .@"0" = a_owner } } } }, .output_state = .{ .ObjectWrite = .{ dg, .{ .AddressOwner = .{ .@"0" = a_owner } } } }, .id_operation = .None } },
            .{ .{ .@"0" = .{ .@"0" = o_field } }, .{ .input_state = .NotExist, .output_state = .{ .ObjectWrite = .{ dg, .{ .ObjectOwner = .{ .@"0" = o_parent } } } }, .id_operation = .Created } },
        },
        .unchanged_consensus_objects = &.{},
        .aux_data_digest = null,
    } };
    return bcs.encodeAlloc(types.TransactionEffects, a, &eff);
}

/// A request whose field 1 is an id or address as text (GetObject, ListDynamicFields,
/// ListOwnedObjects, GetBalance, ListBalances).
fn idReq(a: std.mem.Allocator, id: *const [32]u8) ![]u8 {
    return std.fmt.allocPrint(a, "\x0a\x420x{x}", .{id});
}
fn batchReq(a: std.mem.Allocator, ids: []const [32]u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    for (ids) |*id| {
        try out.appendSlice(a, "\x0a\x44");
        try out.appendSlice(a, try idReq(a, id));
    }
    return out.items;
}
fn txReq(a: std.mem.Allocator, digest: *const [32]u8) ![]u8 {
    var db: [serve.b58.max_len_32]u8 = undefined;
    const text = serve.b58.encode32(&db, digest);
    return std.fmt.allocPrint(a, "\x0a{c}{s}", .{ @as(u8, @intCast(text.len)), text });
}
/// `executeRequest` with a read mask.
fn executeMasked(a: std.mem.Allocator, data: []const u8, paths: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, try executeRequest(a, data));
    var m: std.ArrayList(u8) = .empty;
    for (paths) |p| {
        try m.append(a, 0x0a);
        try m.append(a, @intCast(p.len));
        try m.appendSlice(a, p);
    }
    try out.append(a, 0x1a);
    try out.append(a, @intCast(m.items.len));
    try out.appendSlice(a, m.items);
    return out.items;
}

const p_fields = "/sui.rpc.v2.StateService/ListDynamicFields";
const p_owned = "/sui.rpc.v2.StateService/ListOwnedObjects";
const p_balance = "/sui.rpc.v2.StateService/GetBalance";
const p_balances = "/sui.rpc.v2.StateService/ListBalances";
const p_batch = "/sui.rpc.v2.LedgerService/BatchGetObjects";

fn commitLater(edge: *Edge, after_ms: u64, digest: [32]u8) void {
    sleepMs(after_ms);
    edge.commit(&digest) catch {};
}

const Timed = struct { ms: u64, reply: loopback.Reply };
fn timed(e: *Edge, a: std.mem.Allocator, path: []const u8, body: []const u8) !Timed {
    const t0 = nowNs();
    const r = try e.unary(a, path, body);
    return .{ .ms = (nowNs() - t0) / ms, .reply = r };
}

test "read-after-write reads: the execute answers at once; a read of what it wrote waits and then sees it; an unrelated read does not wait (hold beside it)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    inline for (.{ forward.ExecMode.hold, forward.ExecMode.reads }) |mode| {
        core.reset();
        core.effects_bcs = try someEffects(a);
        const up = try Server.start(core.handler, null);
        defer up.stop();
        const e = try Edge.create(plain(up.port), .{ .raw = mode });
        defer e.destroy();
        e.local.st = e.st;
        e.f.source = null; // the guard is not this test's subject: it stays as `healthy` leaves it
        e.healthy();
        try e.f.start();
        for (0..3) |_| try e.commit(null); // tip 2
        const data = "transaction of the " ++ @tagName(mode) ++ " run";
        const req = try executeMasked(a, data, &.{"digest"});
        const want = try loopback.unary(a, core.handler, p_execute, req);
        // the edge applies the transaction's checkpoint (3) 300 ms after the execute starts
        var th = try std.Thread.spawn(.{}, commitLater, .{ e, 300, txDigest(data) });
        const exec = try timed(e, a, p_execute, req);
        const unrelated = try timed(e, a, p_object, try idReq(a, &o_other));
        const read = try timed(e, a, p_object, try idReq(a, &o_gas));
        th.join();
        std.debug.print("read-after-write {s}: execute {d} ms, unrelated read {d} ms, read of a written object {d} ms ({s})\n", .{ @tagName(mode), exec.ms, unrelated.ms, read.ms, read.reply.message });
        // the execute answer is the core's for the client's own mask, byte for byte
        try expectSameReply(want, exec.reply);
        // whichever waited, the read of the written object is answered from the state with it
        try testing.expectEqualStrings("local:" ++ p_object ++ "@3", read.reply.message);
        try testing.expect(unrelated.ms < 150);
        if (mode == .hold) {
            try testing.expect(exec.ms >= 290 and exec.ms < 1500);
            try testing.expect(read.ms < 150);
            try testing.expectEqualStrings("digest", core.seenMask()); // nothing added in hold
        } else {
            try testing.expect(exec.ms < 150);
            try testing.expectEqualStrings("local:" ++ p_object ++ "@2", unrelated.reply.message);
            try testing.expect(read.ms >= 200 and read.ms < 1500);
            // the edge asked the core for effects.bcs on its own account and took it out again
            try testing.expectEqualStrings("digest,effects.bcs", core.seenMask());
            try testing.expectEqual(@as(u64, 1), e.f.metrics.raw_recorded.load(.monotonic));
            try testing.expectEqual(@as(u64, 0), e.f.metrics.execute_hold.n.load(.monotonic));
            try testing.expectEqual(@as(u64, 1), e.f.metrics.raw_read_wait.n.load(.monotonic));
            try testing.expect(e.f.pending.idle());
        }
    }
}

test "read-after-write reads: the execute answer is the core's for every client mask" {
    core.reset();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    core.effects_bcs = try someEffects(a);
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{ .raw = .reads });
    defer e.destroy();
    e.healthy();
    const Case = struct { paths: ?[]const []const u8, sent: []const u8 };
    const cases = [_]Case{
        .{ .paths = null, .sent = "" }, // the default mask has the effects: nothing added
        .{ .paths = &.{"effects"}, .sent = "effects" },
        .{ .paths = &.{ "digest", "effects.bcs" }, .sent = "digest,effects.bcs" },
        .{ .paths = &.{"digest"}, .sent = "digest,effects.bcs" },
        .{ .paths = &.{ "digest", "events" }, .sent = "digest,events,effects.bcs" },
        .{ .paths = &.{ "digest", "effects.status" }, .sent = "digest,effects.status,effects.bcs" },
        .{ .paths = &.{"effects.status"}, .sent = "effects.status,effects.bcs" },
        .{ .paths = &.{}, .sent = "effects.bcs" },
    };
    for (cases, 0..) |c, i| {
        const data = try std.fmt.allocPrint(a, "masked transaction {d}", .{i});
        const req = if (c.paths) |ps| try executeMasked(a, data, ps) else try executeRequest(a, data);
        const want = try loopback.unary(a, core.handler, p_execute, req);
        const got = try e.unary(a, p_execute, req);
        try testing.expectEqualStrings(c.sent, core.seenMask());
        try expectSameReply(want, got);
        // every one of them was recorded with its write set, none held
        try testing.expectEqual(@as(u64, i + 1), e.f.metrics.raw_recorded.load(.monotonic));
        try testing.expect(e.f.pending.contains(&txDigest(data)));
    }
    try testing.expectEqual(@as(u64, 0), e.f.metrics.raw_held_instead.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), e.f.metrics.raw_strip_failures.load(.monotonic));
    // an answer the edge cannot read a write set from (here: not a response message) is held
    core.effects_bcs = "";
    const t0 = nowNs();
    const held = try e.unary(a, p_execute, try executeMasked(a, "unreadable answer", &.{"digest"}));
    try testing.expectEqualStrings("executed: effects and all", held.message);
    try testing.expectEqual(@as(u64, 1), e.f.metrics.raw_held_instead.load(.monotonic));
    try testing.expect((nowNs() - t0) / ms >= 1990);
    // a failed execute is neither held nor recorded
    core.exec_fail.store(true, .release);
    const n_before = e.f.pending.n.load(.acquire);
    const failed = try timed(e, a, p_execute, try executeMasked(a, "rejected", &.{"digest"}));
    try testing.expectEqual(@as(u8, 3), failed.reply.status);
    try testing.expect(failed.ms < 300);
    try testing.expectEqual(n_before, e.f.pending.n.load(.acquire));
}

const Reader = struct {
    e: *Edge,
    path: []const u8,
    body: []const u8,
    ms: u64 = 0,
    text: [200]u8 = undefined,
    len: usize = 0,
    status: u8 = 255,
    thread: std.Thread = undefined,

    fn run(r: *Reader) void {
        var arena = std.heap.ArenaAllocator.init(sys);
        defer arena.deinit();
        const t0 = nowNs();
        const rep = r.e.unary(arena.allocator(), r.path, r.body) catch return;
        r.ms = (nowNs() - t0) / ms;
        r.status = rep.status;
        r.len = @min(rep.message.len, r.text.len);
        @memcpy(r.text[0..r.len], rep.message[0..r.len]);
    }
    fn message(r: *const Reader) []const u8 {
        return r.text[0..r.len];
    }
};

test "read-after-write reads: by-address reads, dynamic fields, a batch with one pending item, the transaction itself and a second client all wait; reads that touch nothing pending do not" {
    core.reset();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    core.effects_bcs = try someEffects(a);
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{ .raw = .reads, .raw_max_waiters = 32 });
    defer e.destroy();
    e.local.st = e.st;
    e.f.source = null; // the guard is not this test's subject: it stays as `healthy` leaves it
    e.healthy();
    try e.f.start();
    for (0..3) |_| try e.commit(null); // tip 2

    // nothing pending: nothing waits, the core is not asked
    for ([_][]const u8{ p_object, p_owned, p_balance, p_balances, p_fields }) |path| {
        const r = try timed(e, a, path, try idReq(a, &o_gas));
        try testing.expect(r.ms < 100 and std.mem.endsWith(u8, r.reply.message, "@2"));
    }
    try testing.expectEqual(@as(u64, 0), e.f.metrics.raw_read_wait.n.load(.monotonic));

    const data = "the transaction everybody reads after";
    const digest = txDigest(data);
    const exec = try timed(e, a, p_execute, try executeMasked(a, data, &.{"digest"}));
    try testing.expect(exec.ms < 150);
    // reads of what it did not write: at once, from the state the edge has
    const unrelated = [_]struct { path: []const u8, body: []const u8 }{
        .{ .path = p_object, .body = try idReq(a, &o_other) },
        .{ .path = p_batch, .body = try batchReq(a, &.{ o_other, a_other }) },
        .{ .path = p_owned, .body = try idReq(a, &a_other) },
        .{ .path = p_balance, .body = try idReq(a, &a_other) },
        .{ .path = p_balances, .body = try idReq(a, &a_other) },
        .{ .path = p_fields, .body = try idReq(a, &o_other) },
        // the object id of the owner address is not the address: an object read, another key
        .{ .path = p_object, .body = try idReq(a, &a_owner) },
        .{ .path = p_tx, .body = try txReq(a, &rid(0x44)) },
    };
    for (unrelated) |u| {
        const r = try timed(e, a, u.path, u.body);
        try testing.expect(r.ms < 100);
        try testing.expect(std.mem.endsWith(u8, r.reply.message, "@2"));
    }
    try testing.expectEqual(@as(u64, 0), e.f.metrics.raw_read_wait.n.load(.monotonic));
    // reads of what it wrote, from two clients at once: all wait for checkpoint 3
    var readers = [_]Reader{
        .{ .e = e, .path = p_object, .body = try idReq(a, &o_gas) },
        .{ .e = e, .path = p_object, .body = try idReq(a, &o_gas) }, // a second client, the same object
        .{ .e = e, .path = p_object, .body = try idReq(a, &o_field) }, // the created field object
        .{ .e = e, .path = p_fields, .body = try idReq(a, &o_parent) }, // its parent's field list
        .{ .e = e, .path = p_owned, .body = try idReq(a, &a_owner) },
        .{ .e = e, .path = p_balance, .body = try idReq(a, &a_owner) },
        .{ .e = e, .path = p_balances, .body = try idReq(a, &a_owner) },
        .{ .e = e, .path = p_batch, .body = try batchReq(a, &.{ o_other, o_gas, a_other }) }, // one pending item
        .{ .e = e, .path = p_tx, .body = try txReq(a, &digest) },
    };
    for (&readers) |*r| r.thread = try std.Thread.spawn(.{}, Reader.run, .{r});
    sleepMs(250);
    try testing.expectEqual(@as(u32, readers.len), e.f.raw_waiters.load(.acquire));
    try e.commit(&digest);
    for (&readers) |*r| r.thread.join();
    for (&readers) |*r| {
        std.debug.print("read-after-write reads: {s} waited {d} ms -> {s}\n", .{ r.path, r.ms, r.message() });
        try testing.expect(r.ms >= 200 and r.ms < 1500);
        try testing.expectEqual(@as(u8, 0), r.status);
        try testing.expect(std.mem.startsWith(u8, r.message(), "local:") and std.mem.endsWith(u8, r.message(), "@3"));
    }
    try testing.expectEqual(@as(u64, readers.len), e.f.metrics.raw_read_wait.n.load(.monotonic));
    try testing.expectEqual(@as(u32, 0), e.f.raw_waiters.load(.acquire));
    try testing.expect(e.f.pending.idle());
    // applied: the same reads are immediate again
    const again = try timed(e, a, p_object, try idReq(a, &o_gas));
    try testing.expect(again.ms < 100);
}

test "read-after-write reads: applied early nothing waits; never applied the read is passed to the core at the bound, later reads at once, and the entry expires" {
    core.reset();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    core.effects_bcs = try someEffects(a);
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{ .raw = .reads, .execute_wait_ms = 300, .raw_expiry_ms = 900 });
    defer e.destroy();
    e.local.st = e.st;
    e.f.source = null; // the guard is not this test's subject: it stays as `healthy` leaves it
    e.healthy();
    try e.f.start();
    for (0..3) |_| try e.commit(null);
    // early: the edge applied the checkpoint before the core's answer came back
    {
        const data = "applied before the answer";
        try e.commit(&txDigest(data));
        _ = try e.unary(a, p_execute, try executeMasked(a, data, &.{"digest"}));
        try testing.expect(e.f.pending.idle());
        const r = try timed(e, a, p_object, try idReq(a, &o_gas));
        try testing.expect(r.ms < 100 and std.mem.endsWith(u8, r.reply.message, "@3"));
    }
    // never: the transaction reaches no checkpoint the edge sees
    const data = "never in a checkpoint";
    const t0 = nowNs();
    _ = try e.unary(a, p_execute, try executeMasked(a, data, &.{"digest"}));
    const first = try timed(e, a, p_object, try idReq(a, &o_gas));
    // the wait ends 300 ms after the execute; then the core answers, not the edge's old state
    try testing.expect(first.ms >= 200 and first.ms < 1000);
    try testing.expect(std.mem.startsWith(u8, first.reply.message, "core:"));
    // from then on reads of it go to the core at once: nobody waits twice for one transaction
    const second = try timed(e, a, p_object, try idReq(a, &o_gas));
    const owned = try timed(e, a, p_owned, try idReq(a, &a_owner));
    try testing.expect(second.ms < 100 and std.mem.startsWith(u8, second.reply.message, "core:"));
    try testing.expect(owned.ms < 100 and owned.reply.status == 12); // the scripted core has no StateService
    try testing.expectEqual(@as(u64, 3), e.f.metrics.raw_reads_late.load(.monotonic));
    try testing.expectEqual(@as(u64, 3), e.forwarded(.get_object, .ahead) + e.forwarded(.list_owned_objects, .ahead));
    // an unrelated read never noticed
    const other = try timed(e, a, p_object, try idReq(a, &o_other));
    try testing.expect(other.ms < 100 and std.mem.startsWith(u8, other.reply.message, "local:"));
    // the hard expiry: the entry leaves 900 ms after the execute, and reads are the edge's again
    var waited: u32 = 0;
    while (!e.f.pending.idle() and waited < 3000) : (waited += 10) sleepMs(10);
    const gone_after = (nowNs() - t0) / ms;
    try testing.expect(e.f.pending.idle());
    try testing.expect(gone_after >= 890 and gone_after < 2500);
    const after = try timed(e, a, p_object, try idReq(a, &o_gas));
    try testing.expect(after.ms < 100 and std.mem.startsWith(u8, after.reply.message, "local:"));
    std.debug.print("read-after-write reads, never applied: first read {d} ms (core), second {d} ms (core), entry gone after {d} ms, then {d} ms (local)\n", .{ first.ms, second.ms, gone_after, after.ms });
}

test "read-after-write reads: a full table holds the next execute instead of dropping an entry; too many waiting reads are passed to the core" {
    core.reset();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    core.effects_bcs = try someEffects(a);
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{ .raw = .reads, .execute_wait_ms = 400, .raw_max_entries = 1, .raw_max_waiters = 2 });
    defer e.destroy();
    e.local.st = e.st;
    e.f.source = null; // the guard is not this test's subject: it stays as `healthy` leaves it
    e.healthy();
    try e.f.start();
    for (0..3) |_| try e.commit(null);
    const one = try timed(e, a, p_execute, try executeMasked(a, "first, recorded", &.{"digest"}));
    try testing.expect(one.ms < 150);
    // the table is full: the second execute is held as in `hold` (it never lands: the bound)
    const want = try loopback.unary(a, core.handler, p_execute, try executeMasked(a, "second, held", &.{"digest"}));
    const two = try timed(e, a, p_execute, try executeMasked(a, "second, held", &.{"digest"}));
    try expectSameReply(want, two.reply);
    try testing.expect(two.ms >= 390 and two.ms < 1500);
    try testing.expectEqual(@as(u64, 1), e.f.metrics.raw_recorded.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), e.f.metrics.raw_held_instead.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), e.f.metrics.execute_hold_timeouts.load(.monotonic));
    // the first entry is still there
    try testing.expect(e.f.pending.contains(&txDigest("first, recorded")));
    try testing.expectEqual(@as(usize, 1), e.f.pending.n.load(.acquire));

    // five reads of a written object at once, two may wait: three go to the core at once
    const data = "third, read by five";
    e.f.pending.remove(&txDigest("first, recorded"));
    _ = try e.unary(a, p_execute, try executeMasked(a, data, &.{"digest"}));
    var readers: [5]Reader = undefined;
    for (&readers) |*r| r.* = .{ .e = e, .path = p_object, .body = try idReq(a, &o_gas) };
    for (&readers) |*r| r.thread = try std.Thread.spawn(.{}, Reader.run, .{r});
    for (&readers) |*r| r.thread.join();
    var waited: u32 = 0;
    var at_once: u32 = 0;
    for (&readers) |*r| {
        try testing.expect(std.mem.startsWith(u8, r.message(), "core:")); // nobody got the old state
        if (r.ms >= 200) waited += 1 else at_once += 1;
    }
    try testing.expectEqual(@as(u32, 2), waited);
    try testing.expectEqual(@as(u32, 3), at_once);
    try testing.expectEqual(@as(u64, 3), e.f.metrics.raw_reads_over_limit.load(.monotonic));
}

test "read-after-write reads: waiting reads keep serve workers; the bound keeps the pool free" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // the fast pool's size in this process (GetObject runs on it)
    const workers = h2.pool.workersFor(h2.pool.usableCpus());
    const Client = struct {
        port: u16,
        body: []const u8,
        ms: u64 = 0,
        thread: std.Thread = undefined,
        fn run(c: *@This()) void {
            var ar = std.heap.ArenaAllocator.init(sys);
            defer ar.deinit();
            const t0 = nowNs();
            _ = loopback.call(ar.allocator(), io, c.port, p_object, &.{}, &.{c.body}, .{}) catch {};
            c.ms = (nowNs() - t0) / ms;
        }
    };
    var probe_ms: [2]u64 = .{ 0, 0 };
    for ([_]u32{ 1_000_000, @max(1, workers / 4) }, 0..) |max_waiters, round| {
        core.reset();
        core.effects_bcs = try someEffects(a);
        const up = try Server.start(core.handler, null);
        defer up.stop();
        const e = try Edge.create(plain(up.port), .{ .raw = .reads, .execute_wait_ms = 600, .raw_max_waiters = max_waiters });
        defer e.destroy();
        e.f.source = null; // the guard is not this test's subject: it stays as `healthy` leaves it
        e.healthy();
        try e.f.start();
        for (0..3) |_| try e.commit(null);
        const front = try Server.start(e.f.handler(), null);
        defer front.stop();
        _ = try e.unary(a, p_execute, try executeMasked(a, try std.fmt.allocPrint(a, "pool round {d}", .{round}), &.{"digest"}));
        // as many clients as the pool has workers read the written object
        const clients = try a.alloc(Client, workers);
        for (clients) |*c| c.* = .{ .port = front.port, .body = try idReq(a, &o_gas) };
        for (clients) |*c| c.thread = try std.Thread.spawn(.{}, Client.run, .{c});
        sleepMs(150);
        // ... and one more client reads something else
        const t0 = nowNs();
        _ = try loopback.call(a, io, front.port, p_object, &.{}, &.{try idReq(a, &o_other)}, .{});
        probe_ms[round] = (nowNs() - t0) / ms;
        for (clients) |*c| c.thread.join();
        var waited: u32 = 0;
        for (clients) |*c| if (c.ms >= 300) {
            waited += 1;
        };
        std.debug.print("read-after-write reads, {d} serve workers, {d} clients reading a pending object, at most {d} may wait: {d} waited; an unrelated read meanwhile took {d} ms\n", .{ workers, workers, max_waiters, waited, probe_ms[round] });
        if (round == 1) try testing.expect(waited <= max_waiters);
    }
    // with the bound the unrelated read is not behind the waiters
    try testing.expect(probe_ms[1] < 200);
}

// ---------------------------------------------------------------- the node's stop

/// A client that stays on its stream when the server says GOAWAY, as gRPC clients do
/// (`loopback.call` leaves at a GOAWAY): the node's own h2 client with a raw call.
const StreamClient = struct {
    conn: *grpc.Conn,
    slot: u32 = 0,
    bytes: Atomic(u64) = .init(0),
    done: Atomic(bool) = .init(false),
    code: Atomic(u8) = .init(255),

    fn open(port: u16, path: []const u8) !*StreamClient {
        const c = try sys.create(StreamClient);
        c.* = .{ .conn = try grpc.Conn.open(sys, io, plain(port)) };
        c.conn.startOpts(&c.slot, path, "req", .{ .ctx = c, .done = onDone }, 0, .{ .raw = .{ .on_data = onData } });
        return c;
    }
    fn onData(ctx: *anyopaque, _: u64, bytes: []const u8) void {
        const c: *StreamClient = @ptrCast(@alignCast(ctx));
        _ = c.bytes.fetchAdd(bytes.len, .monotonic);
    }
    fn onDone(ctx: *anyopaque, _: u64, r: grpc.Result) void {
        const c: *StreamClient = @ptrCast(@alignCast(ctx));
        switch (r) {
            .ok => {},
            .status => |st| c.code.store(st.code, .release),
        }
        c.done.store(true, .release);
    }
    fn waitDone(c: *StreamClient, limit_ms: u64) bool {
        const t0 = nowNs();
        while (!c.done.load(.acquire)) {
            if (nowNs() - t0 > limit_ms * ms) return false;
            sleepMs(1);
        }
        return true;
    }
    /// Closed, and its reader thread gone before the test ends.
    fn close(c: *StreamClient) void {
        const conn = c.conn;
        conn.retain();
        conn.release();
        var i: u32 = 0;
        while (i < 5000) : (i += 1) {
            conn.mu.lockUncancelable(io);
            const gone = conn.reader_done;
            conn.mu.unlock(io);
            if (gone) break;
            sleepMs(1);
        }
        conn.unref();
        sys.destroy(c);
    }
};

test "a stopped server's forwarded streams end at once (endStreams): none holds the drain for --drain-ms, the core's stream is cancelled, and unary calls are still routed" {
    core.reset();
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{});
    defer e.destroy();
    e.healthy();
    // the grace a stopped server gives its open streams, as the node's --drain-ms
    const grace_ms: u64 = 4000;
    const front = try Server.startGrace(e.f.handler(), grace_ms);
    defer front.stop();
    const c = try StreamClient.open(front.port, p_events);
    defer c.close();
    var waited: u32 = 0;
    while (c.bytes.load(.acquire) == 0 and waited < 3000) : (waited += 5) sleepMs(5);
    try testing.expect(c.bytes.load(.acquire) > 0);

    // the server stops taking calls (GOAWAY) and drains: the open stream is served on
    front.stop_flag.store(true, .release);
    sleepMs(150);
    try testing.expect(!c.done.load(.acquire));
    const at_stop = c.bytes.load(.acquire);
    sleepMs(50);
    try testing.expect(c.bytes.load(.acquire) > at_stop);

    // the node ends its streams (gracefulStop): the forwarded one ends too, well inside the grace
    const t0 = nowNs();
    e.f.endStreams();
    try testing.expect(c.waitDone(grace_ms / 2));
    try testing.expect((nowNs() - t0) / ms < 500);
    // with a status, not a dropped connection (CANCELLED, as at the forwarder's own stop)
    try testing.expectEqual(@as(u8, 1), c.code.load(.acquire));
    // and the core's stream was cancelled, not left running
    waited = 0;
    while (!core.stream_cancelled.load(.acquire) and waited < 3000) : (waited += 5) sleepMs(5);
    try testing.expect(core.stream_cancelled.load(.acquire));
    try testing.expect(waited < 1000);

    // the rest goes on while the server drains: a unary call is still passed to the core
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const rep = try e.unary(arena.allocator(), p_lookup, "x");
    try testing.expectEqual(@as(u8, 0), rep.status);
    try testing.expectEqualStrings("hello from the core", rep.message);
}

var stop_ticks: Atomic(u32) = .init(0);
fn countTick(_: *forward.Forwarder) void {
    _ = stop_ticks.fetchAdd(1, .monotonic);
}

test "requestStop ends the tick and the floor thread without a join (the node asks before the first join of its shutdown, so the join finds them gone)" {
    core.reset();
    const up = try Server.start(core.handler, null);
    defer up.stop();
    const e = try Edge.create(plain(up.port), .{ .tick_ms = 5, .floor_refresh_ms = 10 });
    defer e.destroy();
    stop_ticks.store(0, .release);
    e.f.on_tick = countTick;
    try e.f.start();
    var waited: u32 = 0;
    while ((stop_ticks.load(.acquire) < 5 or core.info_calls.load(.acquire) < 3) and waited < 5000) : (waited += 5) sleepMs(5);
    try testing.expect(stop_ticks.load(.acquire) >= 5);
    try testing.expect(core.info_calls.load(.acquire) >= 3);

    e.f.requestStop();
    // what was under way ends; nothing starts after it
    sleepMs(150);
    const ticks = stop_ticks.load(.acquire);
    const reads = core.info_calls.load(.acquire);
    sleepMs(200);
    try testing.expectEqual(ticks, stop_ticks.load(.acquire));
    try testing.expectEqual(reads, core.info_calls.load(.acquire));
    const t0 = nowNs();
    e.f.stop();
    try testing.expect((nowNs() - t0) / ms < 50);
}

fn stopLater(e: *Edge, after_ms: u64) void {
    sleepMs(after_ms);
    e.f.requestStop();
}

test "requestStop releases the reads waiting for an apply: each is passed to the core at once, none waits out its bound and none is answered from the edge's store; a read that comes later does not wait" {
    core.reset();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    core.effects_bcs = try someEffects(a);
    const up = try Server.start(core.handler, null);
    defer up.stop();
    // the bound is far off: a reader that waits it out is seen in the times below
    const e = try Edge.create(plain(up.port), .{ .raw = .reads, .execute_wait_ms = 5000, .raw_max_waiters = 32 });
    defer e.destroy();
    e.local.st = e.st;
    e.f.source = null; // the guard is not this test's subject: it stays as `healthy` leaves it
    e.healthy();
    try e.f.start();
    for (0..3) |_| try e.commit(null);
    const data = "a transaction the stop finds unapplied";
    const digest = txDigest(data);
    const exec = try timed(e, a, p_execute, try executeMasked(a, data, &.{"digest"}));
    try testing.expect(exec.ms < 150);
    var readers = [_]Reader{
        .{ .e = e, .path = p_object, .body = try idReq(a, &o_gas) },
        .{ .e = e, .path = p_object, .body = try idReq(a, &o_gas) },
        .{ .e = e, .path = p_object, .body = try idReq(a, &o_field) },
        .{ .e = e, .path = p_owned, .body = try idReq(a, &a_owner) },
        .{ .e = e, .path = p_batch, .body = try batchReq(a, &.{ o_other, o_gas, a_other }) },
        .{ .e = e, .path = p_tx, .body = try txReq(a, &digest) },
    };
    for (&readers) |*r| r.thread = try std.Thread.spawn(.{}, Reader.run, .{r});
    sleepMs(250);
    try testing.expectEqual(@as(u32, readers.len), e.f.raw_waiters.load(.acquire));
    const local_before = e.local.calls.load(.acquire);

    const t0 = nowNs();
    e.f.requestStop();
    for (&readers) |*r| r.thread.join();
    const released_ms = (nowNs() - t0) / ms;
    std.debug.print("read-after-write reads, stop with {d} readers waiting (bound 5000 ms): all answered {d} ms after requestStop\n", .{ readers.len, released_ms });
    // within a slice of the stop (20 ms) and the core's answer, not 4.7 s later at the bound
    try testing.expect(released_ms < 1000);
    try testing.expectEqual(@as(u32, 0), e.f.raw_waiters.load(.acquire));
    // none was answered from the edge's own state: the local side was not asked again
    try testing.expectEqual(local_before, e.local.calls.load(.acquire));
    for (&readers) |*r| {
        try testing.expect(r.ms >= 200 and r.ms < 2000);
        try testing.expect(!std.mem.startsWith(u8, r.message(), "local:"));
        // the scripted core answers GetObject and GetTransaction; it has no StateService or batch
        const from_core = std.mem.eql(u8, r.path, p_object) or std.mem.eql(u8, r.path, p_tx);
        if (from_core) {
            try testing.expectEqual(@as(u8, 0), r.status);
            try testing.expect(std.mem.startsWith(u8, r.message(), "core:"));
        } else try testing.expectEqual(@as(u8, 12), r.status);
    }
    try testing.expectEqual(@as(u64, readers.len), e.f.metrics.raw_reads_late.load(.monotonic));
    // the stop dropped nothing from the table (it goes with the forwarder), and a read of a
    // written object that comes after the stop is passed on without waiting
    try testing.expect(e.f.pending.contains(&digest));
    const later = try timed(e, a, p_object, try idReq(a, &o_gas));
    try testing.expect(later.ms < 300);
    try testing.expect(std.mem.startsWith(u8, later.reply.message, "core:"));
    try testing.expectEqual(local_before, e.local.calls.load(.acquire));
    // a read of something no pending transaction wrote is the edge's own, as before the stop
    const other = try timed(e, a, p_object, try idReq(a, &o_other));
    try testing.expect(other.ms < 300 and std.mem.startsWith(u8, other.reply.message, "local:"));
}

test "requestStop releases a held execute (hold, and a full table's wait on the store): the core's answer goes out at once" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 0 entries: the digest has no place in the table and the hold looks at the store instead
    for ([_]u32{ 4096, 0 }) |max_entries| {
        core.reset();
        const up = try Server.start(core.handler, null);
        defer up.stop();
        const e = try Edge.create(plain(up.port), .{ .raw = .hold, .execute_wait_ms = 5000, .raw_max_entries = max_entries });
        defer e.destroy();
        e.f.source = null; // the guard is not this test's subject: it stays as `healthy` leaves it
        e.healthy();
        try e.f.start();
        for (0..3) |_| try e.commit(null);
        const req = try executeRequest(a, try std.fmt.allocPrint(a, "held at the stop, table of {d}", .{max_entries}));
        const want = try loopback.unary(a, core.handler, p_execute, req);
        var th = try std.Thread.spawn(.{}, stopLater, .{ e, 250 });
        const exec = try timed(e, a, p_execute, req);
        th.join();
        std.debug.print("read-after-write hold, stop 250 ms into a held execute (bound 5000 ms, table of {d}): answered after {d} ms\n", .{ max_entries, exec.ms });
        try testing.expect(exec.ms >= 200 and exec.ms < 1500);
        try expectSameReply(want, exec.reply);
        try testing.expectEqual(@as(u64, 1), e.f.metrics.execute_hold_timeouts.load(.monotonic));
    }
}

// ---------------------------------------------------------------- read-after-write beside the marked certificates

const certs_mod = @import("certs.zig");

/// GetCheckpointRequest { sequence_number = 1, read_mask = 3 }.
fn checkpointReq(a: std.mem.Allocator, seq: u64, paths: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, 0x08);
    try core.varint(&out, a, seq);
    var m: std.ArrayList(u8) = .empty;
    for (paths) |p| try core.lenField(&m, a, 0x0a, p);
    try core.lenField(&out, a, 0x1a, m.items);
    return out.items;
}

/// The edge applies its next checkpoint from its fallback: marked before the commit, as the
/// follower's `on_batch` does (certs.zig `onApply`), with `digest` as its transaction.
fn commitForeignLater(edge: *Edge, certs: *certs_mod.Certs, after_ms: u64, digest: [32]u8) void {
    sleepMs(after_ms);
    certs.onApply(edge.next_seq, false, 1) catch {};
    edge.commit(&digest) catch {};
}

test "read-after-write reads beside marked certificates: a read that waited for an apply is answered once, a certificate read of that checkpoint goes to the core after one wait, and a stop releases the waiters" {
    core.reset();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    core.effects_bcs = try someEffects(a);
    const up = try Server.start(core.handler, null);
    defer up.stop();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var opened = try certs_mod.Certs.open(testing.allocator, io, tmp.dir, .{ .log = false });
    opened.found.deinit(testing.allocator);
    const certs = opened.certs;
    defer certs.deinit(); // after the forwarder, which reads it
    // both bounds far off: a second wait on top of the first is seen in the times below
    const e = try Edge.create(plain(up.port), .{ .raw = .reads, .execute_wait_ms = 4000, .ahead_wait_ms = 4000, .raw_max_waiters = 32 });
    defer e.destroy();
    e.local.st = e.st;
    e.local.svc = &e.svc;
    e.f.source = null; // the guard is not this test's subject: it stays as `healthy` leaves it
    e.healthy();
    e.f.setCerts(certs);
    try e.f.start();
    for (0..3) |_| try e.commit(null); // tip 2, nothing marked

    // A transaction executed through the edge; its checkpoint (3) reaches the edge 300 ms later
    // from the fallback, so with a certificate that is not the core's.
    const data = "applied from the fallback";
    const digest = txDigest(data);
    const exec = try timed(e, a, p_execute, try executeMasked(a, data, &.{"digest"}));
    try testing.expect(exec.ms < 150);
    var th = try std.Thread.spawn(.{}, commitForeignLater, .{ e, certs, 300, digest });
    var readers = [_]Reader{
        .{ .e = e, .path = p_tx, .body = try txReq(a, &digest) }, // waits in the pending table
        .{ .e = e, .path = p_object, .body = try idReq(a, &o_gas) }, // waits in the pending table
        .{ .e = e, .path = p_checkpoint, .body = try checkpointReq(a, 3, &.{ "sequence_number", "signature" }) }, // ahead of the tip, renders the certificate
        .{ .e = e, .path = p_checkpoint, .body = try checkpointReq(a, 3, &.{ "sequence_number", "digest" }) }, // ahead of the tip, no certificate
    };
    for (&readers) |*r| r.thread = try std.Thread.spawn(.{}, Reader.run, .{r});
    for (&readers) |*r| r.thread.join();
    th.join();
    for (&readers) |*r| {
        std.debug.print("read-after-write reads, checkpoint 3 applied marked: {s} waited {d} ms -> {s}\n", .{ r.path, r.ms, r.message() });
        // one wait each, for the apply at 300 ms: none waits again behind another bound
        try testing.expect(r.ms >= 200 and r.ms < 1500);
        try testing.expectEqual(@as(u8, 0), r.status);
    }
    try testing.expect(certs.isMarked(3));
    // a transaction and an object carry no certificate: the edge's own answer, from the state with it
    try testing.expectEqualStrings("local:" ++ p_tx ++ "@3", readers[0].message());
    try testing.expectEqualStrings("local:" ++ p_object ++ "@3", readers[1].message());
    // the certificate of the marked checkpoint is the core's to answer, never the edge's
    try testing.expect(std.mem.startsWith(u8, readers[2].message(), "core:" ++ p_checkpoint));
    try testing.expectEqual(@as(u64, 1), e.forwarded(.get_checkpoint, .foreign_cert));
    try testing.expectEqual(@as(u64, 0), e.forwarded(.get_checkpoint, .ahead));
    // the same checkpoint without its certificate is the edge's
    try testing.expectEqualStrings("local:" ++ p_checkpoint ++ "@3", readers[3].message());
    // only the two reads of what the transaction wrote waited in the table
    try testing.expectEqual(@as(u64, 2), e.f.metrics.raw_read_wait.n.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), e.f.metrics.raw_reads_late.load(.monotonic));
    try testing.expect(e.f.pending.idle());

    // A second transaction stays pending (the table is not idle): the certificate read of the
    // marked checkpoint is passed on at once, and the pending table makes no checkpoint read wait.
    const data2 = "pending at the stop";
    const digest2 = txDigest(data2);
    _ = try e.unary(a, p_execute, try executeMasked(a, data2, &.{"digest"}));
    try testing.expect(!e.f.pending.idle());
    const cert_now = try timed(e, a, p_checkpoint, try checkpointReq(a, 3, &.{"signature"}));
    try testing.expect(cert_now.ms < 150 and std.mem.startsWith(u8, cert_now.reply.message, "core:"));
    try testing.expectEqual(@as(u64, 2), e.forwarded(.get_checkpoint, .foreign_cert));
    const plain_now = try timed(e, a, p_checkpoint, try checkpointReq(a, 3, &.{"digest"}));
    try testing.expect(plain_now.ms < 150 and std.mem.startsWith(u8, plain_now.reply.message, "local:"));
    try testing.expectEqual(@as(u64, 2), e.f.metrics.raw_read_wait.n.load(.monotonic));

    // The stop: the reads waiting for the second transaction are released as without marks.
    var waiting = [_]Reader{
        .{ .e = e, .path = p_tx, .body = try txReq(a, &digest2) },
        .{ .e = e, .path = p_object, .body = try idReq(a, &o_gas) },
    };
    for (&waiting) |*r| r.thread = try std.Thread.spawn(.{}, Reader.run, .{r});
    sleepMs(250);
    try testing.expectEqual(@as(u32, waiting.len), e.f.raw_waiters.load(.acquire));
    const local_before = e.local.calls.load(.acquire);
    const t0 = nowNs();
    e.f.requestStop();
    for (&waiting) |*r| r.thread.join();
    const released_ms = (nowNs() - t0) / ms;
    std.debug.print("read-after-write reads beside marked certificates: stop with {d} readers waiting (bound 4000 ms): all answered {d} ms after requestStop\n", .{ waiting.len, released_ms });
    try testing.expect(released_ms < 1000);
    for (&waiting) |*r| {
        try testing.expectEqual(@as(u8, 0), r.status);
        try testing.expect(std.mem.startsWith(u8, r.message(), "core:"));
    }
    try testing.expectEqual(local_before, e.local.calls.load(.acquire));
    // and the certificate read still goes to the core after the stop, without a local attempt
    const cert_after = try timed(e, a, p_checkpoint, try checkpointReq(a, 3, &.{"signature"}));
    try testing.expect(cert_after.ms < 300 and std.mem.startsWith(u8, cert_after.reply.message, "core:"));
    try testing.expectEqual(local_before, e.local.calls.load(.acquire));
    try testing.expectEqual(@as(u64, 3), e.forwarded(.get_checkpoint, .foreign_cert));
}

test "read-after-write reads beside marked certificates, no core reachable: a read that waited is answered once, and the certificate read of the marked checkpoint gets the held certificate after one wait" {
    core.reset();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    core.effects_bcs = try someEffects(a);
    const up = try Server.start(core.handler, null);
    var up_live = true;
    defer if (up_live) up.stop();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var opened = try certs_mod.Certs.open(testing.allocator, io, tmp.dir, .{ .log = false });
    opened.found.deinit(testing.allocator);
    const certs = opened.certs;
    defer certs.deinit(); // after the forwarder, which reads it
    const e = try Edge.create(plain(up.port), .{ .raw = .reads, .execute_wait_ms = 4000, .ahead_wait_ms = 4000, .raw_max_waiters = 32 });
    defer e.destroy();
    e.local.st = e.st;
    e.local.svc = &e.svc;
    e.f.source = null; // the guard is not this test's subject: it stays as `healthy` leaves it
    e.healthy();
    e.f.setCerts(certs);
    try e.f.start();
    for (0..3) |_| try e.commit(null); // tip 2, nothing marked

    // executed through the edge while the core answers; then the core is gone, and the
    // transaction's checkpoint (3) reaches the edge from the fallback: marked
    const data = "applied from the fallback with the core gone";
    const digest = txDigest(data);
    _ = try e.unary(a, p_execute, try executeMasked(a, data, &.{"digest"}));
    try testing.expect(!e.f.pending.idle());
    up.stop();
    up_live = false;
    var th = try std.Thread.spawn(.{}, commitForeignLater, .{ e, certs, 300, digest });
    var readers = [_]Reader{
        .{ .e = e, .path = p_tx, .body = try txReq(a, &digest) }, // waits in the pending table
        .{ .e = e, .path = p_checkpoint, .body = try checkpointReq(a, 3, &.{ "sequence_number", "signature" }) }, // ahead of the tip, renders the certificate
    };
    for (&readers) |*r| r.thread = try std.Thread.spawn(.{}, Reader.run, .{r});
    for (&readers) |*r| r.thread.join();
    th.join();
    for (&readers) |*r| {
        std.debug.print("read-after-write reads, checkpoint 3 applied marked, no core: {s} waited {d} ms -> {s}\n", .{ r.path, r.ms, r.message() });
        try testing.expectEqual(@as(u8, 0), r.status);
        // one wait for the apply at 300 ms (and at most one refused dial), never a second bound
        try testing.expect(r.ms >= 200 and r.ms < 3000);
    }
    // the read that waited in the table needs no core: the edge's own answer, from the state with it
    try testing.expectEqualStrings("local:" ++ p_tx ++ "@3", readers[0].message());
    try testing.expectEqual(@as(u64, 1), e.f.metrics.raw_read_wait.n.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), e.f.metrics.raw_reads_late.load(.monotonic));
    try testing.expect(e.f.pending.idle());
    // the certificate read: no core to ask, so the certificate the edge holds, counted
    try testing.expectEqualStrings("held:" ++ p_checkpoint ++ "@3", readers[1].message());
    try testing.expect(e.f.upstreamDown());
    const held = &certs.stats.held_served[@intFromEnum(certs_mod.HeldPath.grpc)];
    try testing.expectEqual(@as(u64, 1), held.load(.monotonic));
    try testing.expect(e.forwarded(.get_checkpoint, .foreign_cert) <= 1); // tried the core at most once
    try testing.expectEqual(@as(u64, 0), e.forwarded(.get_checkpoint, .ahead));
    // the next one is answered at once, without a try at the core
    const again = try timed(e, a, p_checkpoint, try checkpointReq(a, 3, &.{"signature"}));
    try testing.expect(again.ms < 150);
    try testing.expectEqualStrings("held:" ++ p_checkpoint ++ "@3", again.reply.message);
    try testing.expectEqual(@as(u64, 2), held.load(.monotonic));
}

/// ExecuteTransactionRequest { transaction { bcs { value } }, signatures [{ bcs { value } }], read_mask? }.
fn signedRequest(a: std.mem.Allocator, data: []const u8, sig: []const u8, paths: ?[]const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var inner: std.ArrayList(u8) = .empty;
    inline for (.{ .{ @as(u8, 0x0a), data }, .{ @as(u8, 0x12), sig } }) |part| {
        inner.clearRetainingCapacity();
        var b: std.ArrayList(u8) = .empty;
        try core.lenField(&b, a, 0x12, part[1]);
        try core.lenField(&inner, a, 0x0a, b.items);
        try core.lenField(&out, a, part[0], inner.items);
    }
    if (paths) |ps| {
        var m: std.ArrayList(u8) = .empty;
        for (ps) |p| try core.lenField(&m, a, 0x0a, p);
        try core.lenField(&out, a, 0x1a, m.items);
    }
    return out.items;
}

test "read-after-write reads: with the node's own ExecuteTransaction renderer, the answer after adding effects.bcs and taking it out is the answer for the client's mask" {
    // The renderer a deepwave core answers ExecuteTransaction with (rpc_exec driver handler), over
    // its in-process fake validators: each client mask is rendered as the client sent it, and
    // as the edge sends it (one more path), and the second, stripped, must be the first.
    const drv = rpc_exec.driver;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const td: types.TransactionData = .{ .V1 = .{
        .kind = .{ .ProgrammableTransaction = .{ .inputs = &.{}, .commands = &.{} } },
        .sender = .{ .@"0" = @splat(1) },
        .gas_data = .{ .payment = &.{}, .owner = .{ .@"0" = @splat(1) }, .price = 1000, .budget = 5_000_000 },
        .expiration = .None,
    } };
    const data = try bcs.encodeAlloc(types.TransactionData, a, &td);
    const sig: [97]u8 = [_]u8{0} ++ @as([96]u8, @splat(0));
    const committee = try drv.fake.committee(a, &.{ 2500, 2500, 2500, 2500 });
    const Run = struct {
        fn answer(al: std.mem.Allocator, cm: anytype, request: []const u8, effects_out: ?*[]const u8) !drv.handler.Reply {
            var net = try drv.fake.Net.init(al, 4, @splat(9));
            var exec: drv.handler.DriverExecutor = .{ .committee = cm, .transport = net.transport(), .clock = net.clock(), .waiter = net.waiter(), .options = .{ .reference_gas_price = 750, .seed = 1 } };
            if (effects_out) |o| o.* = net.honest_effects;
            return drv.handler.executeTransaction(al, exec.executor(), request);
        }
    };
    const masks = [_][]const []const u8{
        &.{"digest"},
        &.{ "digest", "transaction" },
        &.{ "digest", "signatures" },
        &.{"transaction.bcs"},
        &.{ "digest", "events" },
        &.{"effects.status"},
        &.{ "digest", "effects.status", "effects.gas_used" },
        &.{"effects.digest"},
        &.{ "effects.epoch", "effects.dependencies", "checkpoint", "timestamp" },
        &.{"effects.changed_objects"},
        &.{"balance_changes"},
        &.{"objects"},
        &.{},
    };
    var compared: u32 = 0;
    var with_data: u32 = 0;
    for (masks) |paths| {
        const req = try signedRequest(a, data, &sig, paths);
        const use = raw.maskUse(req);
        try testing.expect(!use.has_bcs);
        const own = try Run.answer(a, &committee, req, null);
        var effects: []const u8 = "";
        const more = try Run.answer(a, &committee, (try raw.withEffectsBcs(a, req)).?, &effects);
        compared += 1;
        switch (own) {
            .err => |e| {
                // a mask this renderer refuses is refused the same with the path added
                try testing.expectEqual(e.code, more.err.code);
                try testing.expectEqualStrings(e.message, more.err.message);
            },
            .ok => |want| {
                with_data += 1;
                const got = try raw.stripEffectsBcs(a, more.ok, use.any_effects);
                testing.expectEqualSlices(u8, want, got) catch |err| {
                    std.debug.print("mask {any}: stripped answer differs from the answer for the client's mask\n", .{paths});
                    return err;
                };
                // and the edge reads the transaction's real effects out of what the core sent it
                const eff = raw.nested(more.ok, &.{ 1, 4, 1, 2 }) orelse return error.NoEffectsInTheAnswer;
                try testing.expectEqualSlices(u8, effects, eff);
                const w = try raw.writesOf(a, eff, data);
                try testing.expect(w.addresses.len >= 1); // the sender at least
            },
        }
    }
    // the default mask and masks that select effects.bcs are sent as they are
    for ([_]?[]const []const u8{ null, &.{"effects"}, &.{ "digest", "effects.bcs" } }) |paths| {
        const req = try signedRequest(a, data, &sig, paths);
        try testing.expect(raw.maskUse(req).has_bcs);
        const own = try Run.answer(a, &committee, req, null);
        try testing.expect(raw.nested(own.ok, &.{ 1, 4, 1, 2 }) != null);
    }
    std.debug.print("read-after-write reads: the node's ExecuteTransaction renderer under {d} client masks without effects.bcs: {d} answered with data, stripped answer equal to the client's own in all\n", .{ compared, with_data });
    try testing.expect(with_data >= 8);
}
