//! The `sui.validator.Validator` gRPC server (TLS 1.3 + h2 over `network-address` as sui-node binds it,
//! plain h2c only when `Options.tls_seed` is null: tests and tools) at
//! mainnet-v1.83.1: SubmitTransaction, WaitForEffects, ObjectInfo, TransactionInfo, Checkpoint,
//! CheckpointV2, GetSystemStateObject, ValidatorHealth. Transport is the full node's h2 server
//! (src/serve/h2): thread per connection, a worker pool for unary calls, 4 MiB request limit (tonic's
//! default decode limit), max 200 concurrent streams, 60 s default call timeout.
//!
//! Message codecs follow `sui-network/build.rs`: prost for the three `Raw*` methods, BCS
//! (`BcsCodec`) for the rest, both without compression. A failed call answers with
//! `Status::with_details(Internal, error.to_string(), bcs(error))`, so every error is a
//! `SuiErrorKind` value (rpc_exec.driver.sui_error has its Display texts and BCS).
//!
//! Behaviour copied from `authority_server.rs`:
//!   - SubmitTransaction retries once when the backend answers ValidatorHaltedAtEpochEnd: it waits up
//!     to 15 s for the next epoch and submits again;
//!   - the request methods count into `validator_service_*` metrics.
//! Per-transaction overload checks, traffic control tallies and consensus position handling are the
//! backend's (val-authority), which shares the metrics registry and `overload.Info`.
const std = @import("std");
const Io = std.Io;
const serve = @import("serve");
const bcs = @import("bcs");
const native = @import("native");
const h2 = serve.h2;
const backend_mod = @import("backend.zig");
const wire = @import("wire.zig");
const metrics = @import("metrics.zig");
const Backend = backend_mod.Backend;
const SuiErrorKind = backend_mod.SuiErrorKind;
const Atomic = std.atomic.Value;

pub const service_path = "/sui.validator.Validator/";
pub const Method = enum { SubmitTransaction, WaitForEffects, ObjectInfo, TransactionInfo, Checkpoint, CheckpointV2, GetSystemStateObject, ValidatorHealth };

pub const Error = error{ BadAddress, Io, OutOfMemory };

pub fn methodOf(path: []const u8) ?Method {
    if (!std.mem.startsWith(u8, path, service_path)) return null;
    return std.meta.stringToEnum(Method, path[service_path.len..]);
}

/// tonic-health on the same port (sui-network `ServerBuilder::from_config` adds it; sui-node
/// registers no per-service status, so only "" answers SERVING).
pub const health_path = "/grpc.health.v1.Health/";

/// The transport settings of sui-node's validator server (lib.rs `start_grpc_validator_service`
/// with mysten-network `Config`, sui-network `validator/server.rs`): a plain tonic Routes stack,
/// HTTP/2 keepalive every 60 s with a 60 s timeout, 300 s default request timeout.
pub fn validatorH2Options() h2.ServerOptions {
    var o: h2.ServerOptions = .{};
    o.h2.grpc_only = true;
    o.h2.default_timeout_ns = 300 * std.time.ns_per_s;
    o.keepalive_ns = 60 * std.time.ns_per_s;
    o.keepalive_timeout_ns = 60 * std.time.ns_per_s;
    return o;
}

pub const Options = struct {
    h2: h2.ServerOptions = validatorH2Options(),
    /// ValidatorHaltedAtEpochEnd retry: wait this long for the next epoch (authority_server.rs: 15 s).
    halted_retry_wait_ms: u64 = 15_000,
    /// Seed of the validator's Ed25519 network key: the server speaks TLS 1.3 with a self-signed
    /// certificate of that key, server name "sui" (sui-node `sui_tls::create_rustls_server_config`,
    /// no client authentication; callers pin the key). Null: plaintext h2c.
    tls_seed: ?[32]u8 = null,
    /// How long `stop` waits for in-flight calls (WaitForEffects may run 20 s) before it gives up.
    stop_wait_ns: u64 = 45 * std.time.ns_per_s,
};

/// The socket address a multiaddr binds to, as mysten-network's `ToSocketAddrs for Multiaddr`
/// (what sui-http's `serve` binds `network-address` with): `/ip4/<a>` or `/ip6/<a>`, then
/// `/tcp/<port>` or `/udp/<port>`; later components (`/http`, `/https`) are ignored. Also
/// `host:port` (SocketAddr fields such as metrics-address). `/dns/...` is not resolved here.
pub fn parseListen(text: []const u8) Error!Io.net.IpAddress {
    if (text.len > 0 and text[0] == '/') {
        var it = std.mem.splitScalar(u8, text[1..], '/');
        const proto = it.next() orelse return error.BadAddress;
        const host = it.next() orelse return error.BadAddress;
        const transport = it.next() orelse return error.BadAddress;
        const port_text = it.next() orelse return error.BadAddress;
        if (!std.mem.eql(u8, transport, "tcp") and !std.mem.eql(u8, transport, "udp")) return error.BadAddress;
        if (!std.mem.eql(u8, proto, "ip4") and !std.mem.eql(u8, proto, "ip6")) return error.BadAddress;
        const port = std.fmt.parseInt(u16, port_text, 10) catch return error.BadAddress;
        return Io.net.IpAddress.parse(host, port) catch error.BadAddress;
    }
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.BadAddress;
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return error.BadAddress;
    const host = if (colon >= 2 and text[0] == '[' and text[colon - 1] == ']') text[1 .. colon - 1] else text[0..colon];
    return Io.net.IpAddress.parse(host, port) catch error.BadAddress;
}

pub const Server = struct {
    gpa: std.mem.Allocator,
    io: Io,
    be: Backend,
    reg: *metrics.Registry,
    /// Current epoch, kept by the epoch manager (for the halted-at-epoch-end retry).
    epoch: *const Atomic(u64),
    opts: Options,
    listener: Io.net.Server,
    tls: ?native.tcptls.Server = null,
    stop_flag: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,

    /// Binds `listen` and serves in a background thread. The caller has run the safety gate.
    pub fn start(gpa: std.mem.Allocator, io: Io, listen: []const u8, be: Backend, reg: *metrics.Registry, epoch: *const Atomic(u64), opts: Options) Error!*Server {
        const addr = try parseListen(listen);
        const s = gpa.create(Server) catch return error.OutOfMemory;
        errdefer gpa.destroy(s);
        s.* = .{ .gpa = gpa, .io = io, .be = be, .reg = reg, .epoch = epoch, .opts = opts, .listener = addr.listen(io, .{ .reuse_address = true }) catch return error.Io };
        errdefer s.listener.deinit(io);
        if (opts.tls_seed) |seed| {
            s.tls = native.tcptls.Server.initEd25519(gpa, io, seed, "sui") catch return error.Io;
            if (s.tls) |*t| s.opts.h2.tls = t.acceptor();
        }
        s.thread = std.Thread.spawn(.{}, run, .{s}) catch return error.Io;
        return s;
    }

    /// The bound port (useful when started on port 0).
    pub fn port(s: *const Server) u16 {
        return s.listener.socket.address.getPort();
    }

    /// Stops accepting and waits for the calls in flight (each is bounded by its own deadline, and
    /// `waitForEpoch` polls the stop flag). True when everything drained and the server was freed.
    /// False: a call outlived `stop_wait_ns`; the server and everything its backend points at are
    /// still referenced by connection threads, so nothing is freed and the caller must keep the
    /// backend (store, signer, registry) alive too.
    pub fn stop(s: *Server) bool {
        s.stop_flag.store(true, .release);
        const st: Io.net.Stream = .{ .socket = s.listener.socket };
        st.shutdown(s.io, .both) catch {};
        var a = s.listener.socket.address;
        if (a.connect(s.io, .{ .mode = .stream })) |c| c.close(s.io) else |_| {}
        if (s.thread) |t| t.join();
        if (!h2.server.waitDrained(s.opts.stop_wait_ns)) return false;
        s.listener.deinit(s.io);
        s.gpa.destroy(s);
        return true;
    }

    fn run(s: *Server) void {
        h2.server.serveBlocking(s.gpa, s.io, &s.listener, s.opts.h2, s.handler(), &s.stop_flag) catch {};
    }

    pub fn handler(s: *Server) h2.Handler {
        return .{ .ctx = s, .call = call, .known = known, .method = methodExists };
    }

    fn known(_: *anyopaque, path: []const u8) bool {
        return std.mem.startsWith(u8, path, service_path) or std.mem.startsWith(u8, path, health_path);
    }
    fn methodExists(_: *anyopaque, path: []const u8) bool {
        if (std.mem.startsWith(u8, path, health_path)) {
            const m = path[health_path.len..];
            return std.mem.eql(u8, m, "Check") or std.mem.eql(u8, m, "Watch");
        }
        return methodOf(path) != null;
    }

    fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const s: *Server = @ptrCast(@alignCast(ctx));
        if (std.mem.startsWith(u8, req.path, health_path)) return healthCall(req, rs);
        const m = methodOf(req.path) orelse return .unimplemented;
        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        s.reg.counter("zui_validator_grpc_requests").incLabel(@tagName(m));
        return switch (m) {
            .SubmitTransaction => s.submitTransaction(arena, req, rs),
            .WaitForEffects => s.waitForEffects(arena, req, rs),
            .ObjectInfo => s.objectInfo(arena, req, rs),
            .TransactionInfo => s.transactionInfo(arena, req, rs),
            .Checkpoint => s.checkpoint(arena, req, rs, false),
            .CheckpointV2 => s.checkpoint(arena, req, rs, true),
            .GetSystemStateObject => s.systemState(arena, req, rs),
            .ValidatorHealth => s.validatorHealth(arena, rs),
        };
    }

    // ------------------------------------------------------------------ replies

    /// `Status::from(SuiError)`: INTERNAL, Display text, BCS of the error as details.
    pub fn fail(rs: *h2.ResponseStream, arena: std.mem.Allocator, kind: SuiErrorKind) h2.Status {
        const text = kind.text(arena) catch "error";
        rs.setMessage(text);
        if (bcs.encodeAlloc(SuiErrorKind, arena, &kind)) |b| rs.details(b) else |_| {}
        return .internal;
    }

    /// `GrpcMessageDeserializeError` with prost's `UnknownEnumValue` text.
    fn unknownEnum(type_info: []const u8, arena: std.mem.Allocator, v: i32) SuiErrorKind {
        const text = std.fmt.allocPrint(arena, "unknown enumeration value {d}", .{v}) catch "unknown enumeration value";
        return .{ .GrpcMessageDeserializeError = .{ .type_info = .{ .@"0" = type_info }, .@"error" = .{ .@"0" = text } } };
    }

    fn decodeFailure(rs: *h2.ResponseStream, arena: std.mem.Allocator, type_info: []const u8) h2.Status {
        _ = arena;
        // tonic's codecs fail with Status::internal; the text is the codec's own error.
        var buf: [96]u8 = undefined;
        rs.setMessage(std.fmt.bufPrint(&buf, "failed to decode {s}", .{type_info}) catch "failed to decode request");
        return .internal;
    }

    fn send(rs: *h2.ResponseStream, body: []const u8) h2.Status {
        rs.message(body) catch return .internal;
        return .ok;
    }

    fn nowSecs(s: *Server) f64 {
        _ = s;
        return @as(f64, @floatFromInt(h2.meta.monoNs())) / 1e9;
    }

    // ------------------------------------------------------------------ methods

    fn submitTransaction(s: *Server, arena: std.mem.Allocator, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const t0 = s.nowSecs();
        const raw = wire.decodeSubmitTxRequest(arena, req.body) catch return decodeFailure(rs, arena, "Protobuf message");
        // An unknown submit_type is the backend's to report: Rust checks it after the
        // is_validator / ValidatorHaltedAtEpochEnd test, which only the backend knows.
        var bad_submit_type: ?i32 = null;
        const submit_type: enum { default, ping, soft_bundle } = switch (raw.submit_type) {
            wire.submit_type_default => .default,
            wire.submit_type_ping => .ping,
            wire.submit_type_soft_bundle => .soft_bundle,
            else => blk: {
                bad_submit_type = raw.submit_type;
                break :blk .default;
            },
        };
        const label: []const u8 = switch (submit_type) {
            .default => "default",
            .ping => "ping",
            .soft_bundle => "soft_bundle",
        };
        var total_bytes: u64 = 0;
        for (raw.transactions) |t| total_bytes += t.len;
        s.reg.histogram("validator_service_submit_transaction_bytes").observe(label, @floatFromInt(total_bytes));
        s.reg.histogram("validator_service_submit_transaction_batch_size").observe(label, @floatFromInt(raw.transactions.len));
        const bq: backend_mod.SubmitRequest = .{ .transactions = raw.transactions, .ping = submit_type == .ping, .soft_bundle = submit_type == .soft_bundle, .client = null, .invalid_submit_type = bad_submit_type };
        const start_epoch = s.epoch.load(.acquire);
        var res = s.be.submit(arena, bq);
        if (res == .err and res.err == .ValidatorHaltedAtEpochEnd) {
            if (s.waitForEpoch(start_epoch + 1)) res = s.be.submit(arena, bq);
        }
        s.reg.histogram("validator_service_submit_transaction_latency").observe(label, s.nowSecs() - t0);
        if (bad_submit_type) |v| {
            // a backend that did not reject it (halted, or one that ignores the field) still must
            if (res == .ok or res.err != .ValidatorHaltedAtEpochEnd) return fail(rs, arena, unknownEnum("RawSubmitTxRequest.submit_type", arena, v));
        }
        switch (res) {
            .err => |e| {
                s.reg.counter("validator_service_submission_rejected_transactions").incLabel(@tagName(std.meta.activeTag(e)));
                return fail(rs, arena, e);
            },
            .ok => |results| {
                const body = wire.driver_wire.submitTxResponse(arena, results) catch return .internal;
                return send(rs, body);
            },
        }
    }

    /// `state.wait_for_epoch(next)` with a 15 s timeout: true once the epoch reached `target`.
    fn waitForEpoch(s: *Server, target: u64) bool {
        const deadline = h2.meta.monoNs() + s.opts.halted_retry_wait_ms * std.time.ns_per_ms;
        while (h2.meta.monoNs() < deadline) {
            if (s.epoch.load(.acquire) >= target) return true;
            if (s.stop_flag.load(.acquire)) return false;
            h2.sock.sleepMs(20);
        }
        return s.epoch.load(.acquire) >= target;
    }

    fn waitForEffects(s: *Server, arena: std.mem.Allocator, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const raw = wire.decodeWaitForEffectsRequest(req.body) catch return decodeFailure(rs, arena, "Protobuf message");
        var digest: ?[32]u8 = null;
        if (raw.transaction_digest) |d| {
            const dd = bcs.decode(@import("types").Digest, arena, d) catch |e| return fail(rs, arena, .{ .GrpcMessageDeserializeError = .{
                .type_info = .{ .@"0" = "RawWaitForEffectsRequest.transaction_digest" },
                .@"error" = .{ .@"0" = backend_mod.sui_error.bcsErrorText(e) },
            } });
            digest = dd.@"0";
        }
        if (raw.consensus_position) |cp| {
            _ = bcs.decode(wire.driver_wire.ConsensusPosition, arena, cp) catch |e| return fail(rs, arena, .{ .GrpcMessageDeserializeError = .{
                .type_info = .{ .@"0" = "ConsensusPosition" },
                .@"error" = .{ .@"0" = backend_mod.sui_error.bcsErrorText(e) },
            } });
        }
        if (raw.ping_type) |p| {
            if (p != 0) return fail(rs, arena, unknownEnum("RawWaitForEffectsRequest.ping_type", arena, p));
        }
        const q: backend_mod.WaitRequest = .{
            .transaction_digest = digest,
            .consensus_position = raw.consensus_position,
            .include_details = raw.include_details,
            .ping = raw.ping_type != null,
            .deadline_ms = if (raw.ping_type != null) 10_000 else 20_000,
        };
        const t0 = s.nowSecs();
        const res = s.be.waitForEffects(arena, q);
        if (q.ping) s.reg.histogram("validator_service_handle_wait_for_effects_ping_latency").observe("consensus", s.nowSecs() - t0);
        switch (res) {
            .err => |e| return fail(rs, arena, e),
            .ok => |r| {
                const body = wire.driver_wire.waitForEffectsResponse(arena, r) catch return .internal;
                return send(rs, body);
            },
        }
    }

    fn objectInfo(s: *Server, arena: std.mem.Allocator, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const q = wire.decodeObjectInfoRequest(req.body) catch return decodeFailure(rs, arena, "ObjectInfoRequest");
        return switch (s.be.objectInfo(arena, q)) {
            .ok => |b| send(rs, b),
            .err => |e| fail(rs, arena, e),
        };
    }

    fn transactionInfo(s: *Server, arena: std.mem.Allocator, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const d = wire.decodeTransactionInfoRequest(req.body) catch return decodeFailure(rs, arena, "TransactionInfoRequest");
        return switch (s.be.transactionInfo(arena, &d)) {
            .ok => |b| send(rs, b),
            .err => |e| fail(rs, arena, e),
        };
    }

    fn checkpoint(s: *Server, arena: std.mem.Allocator, req: *const h2.Request, rs: *h2.ResponseStream, v2: bool) h2.Status {
        const q = wire.decodeCheckpointRequest(req.body, v2) catch return decodeFailure(rs, arena, if (v2) "CheckpointRequestV2" else "CheckpointRequest");
        return switch (s.be.checkpoint(arena, .{ .sequence_number = q.sequence_number, .request_content = q.request_content, .certified = q.certified }, v2)) {
            .ok => |b| send(rs, b),
            .err => |e| fail(rs, arena, e),
        };
    }

    fn systemState(s: *Server, arena: std.mem.Allocator, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        wire.decodeSystemStateRequest(req.body) catch return decodeFailure(rs, arena, "SystemStateRequest");
        return switch (s.be.systemState(arena)) {
            .ok => |b| send(rs, b),
            .err => |e| fail(rs, arena, e),
        };
    }

    fn validatorHealth(s: *Server, arena: std.mem.Allocator, rs: *h2.ResponseStream) h2.Status {
        const body = wire.healthResponse(arena, s.be.health()) catch return .internal;
        return send(rs, body);
    }
};

/// grpc.health.v1.Health/Check and Watch as tonic-health 0.14.6 answers them with only the
/// overall status ("") registered: SERVING, else NOT_FOUND "service not registered" (Watch fails
/// before any message). Watch sends the status once and holds the stream: it never changes.
pub fn healthCall(req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    const method = req.path[health_path.len..];
    var r = serve.proto.Reader.init(req.body);
    var name: []const u8 = "";
    while (r.next() catch {
        rs.setMessage("failed to decode Protobuf message: invalid wire type value");
        return .internal;
    }) |f| {
        if (f.number == 1) name = serve.proto.Reader.stringOf(f) catch {
            rs.setMessage("failed to decode Protobuf message: invalid wire type value");
            return .internal;
        };
    }
    const serving = [_]u8{ 0x08, 0x01 };
    const watch = std.mem.eql(u8, method, "Watch");
    if (!watch and !std.mem.eql(u8, method, "Check")) return .unimplemented;
    if (name.len != 0) {
        rs.setMessage("service not registered");
        return .not_found;
    }
    rs.message(&serving) catch return .internal;
    return if (watch) .held else .ok;
}

// ------------------------------------------------------------------ metrics endpoint

/// `GET /metrics` on `metrics-address` (Prometheus text). One connection at a time with a short
/// read deadline: scrapes are tiny and rare.
pub const MetricsServer = struct {
    gpa: std.mem.Allocator,
    io: Io,
    reg: *metrics.Registry,
    listener: Io.net.Server,
    stop_flag: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,

    pub fn start(gpa: std.mem.Allocator, io: Io, listen: []const u8, reg: *metrics.Registry) Error!*MetricsServer {
        const addr = try parseListen(listen);
        const s = gpa.create(MetricsServer) catch return error.OutOfMemory;
        errdefer gpa.destroy(s);
        s.* = .{ .gpa = gpa, .io = io, .reg = reg, .listener = addr.listen(io, .{ .reuse_address = true }) catch return error.Io };
        s.thread = std.Thread.spawn(.{}, run, .{s}) catch return error.Io;
        return s;
    }

    pub fn port(s: *const MetricsServer) u16 {
        return s.listener.socket.address.getPort();
    }

    pub fn stop(s: *MetricsServer) void {
        s.stop_flag.store(true, .release);
        const st: Io.net.Stream = .{ .socket = s.listener.socket };
        st.shutdown(s.io, .both) catch {};
        var a = s.listener.socket.address;
        if (a.connect(s.io, .{ .mode = .stream })) |c| c.close(s.io) else |_| {}
        if (s.thread) |t| t.join();
        s.listener.deinit(s.io);
        s.gpa.destroy(s);
    }

    fn run(s: *MetricsServer) void {
        while (!s.stop_flag.load(.acquire)) {
            const stream = s.listener.accept(s.io) catch |e| switch (e) {
                error.SocketNotListening, error.Canceled => return,
                else => {
                    h2.sock.sleepMs(10);
                    continue;
                },
            };
            if (s.stop_flag.load(.acquire)) {
                stream.close(s.io);
                return;
            }
            s.serveOne(stream.socket.handle);
            stream.close(s.io);
        }
    }

    fn serveOne(s: *MetricsServer, fd: std.c.fd_t) void {
        var buf: [4096]u8 = undefined;
        var n: usize = 0;
        while (n < buf.len) {
            const ready = h2.sock.waitReadable(fd, 2000) catch return;
            if (!ready) return;
            const k = h2.sock.read(fd, buf[n..]) catch return;
            if (k == 0) return;
            n += k;
            if (std.mem.indexOf(u8, buf[0..n], "\r\n\r\n") != null) break;
        }
        const line_end = std.mem.indexOf(u8, buf[0..n], "\r\n") orelse return;
        var parts = std.mem.tokenizeScalar(u8, buf[0..line_end], ' ');
        const method = parts.next() orelse return;
        const target = parts.next() orelse return;
        var out: std.Io.Writer.Allocating = .init(s.gpa);
        defer out.deinit();
        var code: u16 = 200;
        if (!std.mem.eql(u8, method, "GET")) {
            code = 405;
        } else if (!std.mem.eql(u8, target, "/metrics")) {
            code = 404;
        } else {
            s.reg.render(&out.writer) catch {
                code = 500;
            };
        }
        var hb: [160]u8 = undefined;
        const reason: []const u8 = switch (code) {
            200 => "OK",
            404 => "Not Found",
            405 => "Method Not Allowed",
            else => "Internal Server Error",
        };
        const head = std.fmt.bufPrint(&hb, "HTTP/1.1 {d} {s}\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n", .{ code, reason, out.written().len }) catch return;
        h2.sock.writeAll(fd, head) catch return;
        h2.sock.writeAll(fd, out.written()) catch return;
    }
};

test "listen addresses parse from multiaddrs and host:port" {
    const a = try parseListen("/ip4/127.0.0.1/tcp/8080");
    try std.testing.expectEqual(@as(u16, 8080), a.getPort());
    const b = try parseListen("127.0.0.1:9184");
    try std.testing.expectEqual(@as(u16, 9184), b.getPort());
    // Mysten's validator.yaml form (sui-swarm-config, docs): trailing /http is ignored
    const c = try parseListen("/ip4/0.0.0.0/tcp/8080/http");
    try std.testing.expectEqual(@as(u16, 8080), c.getPort());
    try std.testing.expectEqual(@as(u16, 8081), (try parseListen("/ip4/127.0.0.1/udp/8081")).getPort());
    try std.testing.expectEqual(@as(u16, 9), (try parseListen("/ip6/::1/tcp/9/https")).getPort());
    try std.testing.expectEqual(@as(u16, 9184), (try parseListen("[::1]:9184")).getPort());
    try std.testing.expectError(error.BadAddress, parseListen("/ip4/127.0.0.1/quic/8080"));
    try std.testing.expectError(error.BadAddress, parseListen("/dns/localhost/tcp/1"));
    try std.testing.expectError(error.BadAddress, parseListen("nonsense"));
}

test "method paths" {
    try std.testing.expectEqual(Method.WaitForEffects, methodOf("/sui.validator.Validator/WaitForEffects").?);
    try std.testing.expect(methodOf("/sui.validator.Validator/Nope") == null);
    try std.testing.expect(methodOf("/other/WaitForEffects") == null);
}
