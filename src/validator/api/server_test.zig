//! End to end: the Validator server on a loopback port, called through the h2c gRPC client the
//! execution lane already uses against real validators.
const std = @import("std");
const rpc_exec = @import("rpc_exec");
const bcs = @import("bcs");
const server = @import("server.zig");
const backend = @import("backend.zig");
const wire = @import("wire.zig");
const metrics = @import("metrics.zig");
const grpc = rpc_exec.live.grpc_client;
const dw = wire.driver_wire;

const Fake = struct {
    submits: u32 = 0,
    halted_first: bool = false,
    epoch: std.atomic.Value(u64) = .init(5),

    fn me(ctx: *anyopaque) *Fake {
        return @ptrCast(@alignCast(ctx));
    }
    fn submit(ctx: *anyopaque, arena: std.mem.Allocator, req: backend.SubmitRequest) backend.Result([]const dw.RawSubmitResult) {
        const f = me(ctx);
        f.submits += 1;
        if (f.halted_first and f.submits == 1) {
            // the epoch changes while the validator is halted
            f.epoch.store(6, .release);
            return .{ .err = .{ .ValidatorHaltedAtEpochEnd = {} } };
        }
        const res = arena.alloc(dw.RawSubmitResult, req.transactions.len) catch return .{ .err = backend.storageError("oom") };
        for (res) |*r| r.* = .{ .Submitted = "position" };
        return .{ .ok = res };
    }
    fn wait(_: *anyopaque, _: std.mem.Allocator, _: backend.WaitRequest) backend.Result(dw.RawWaitResponse) {
        return .{ .ok = .{ .Expired = .{ .epoch = 5, .round = null } } };
    }
    fn objectInfo(_: *anyopaque, arena: std.mem.Allocator, req: wire.ObjectInfoRequest) backend.Result([]const u8) {
        if (req.object_id[0] == 1) return .{ .ok = wire.objectInfoResponse(arena, "object-bytes") catch unreachable };
        return .{ .err = backend.objectNotFound(&req.object_id, req.version) };
    }
    fn txInfo(_: *anyopaque, _: std.mem.Allocator, d: *const [32]u8) backend.Result([]const u8) {
        return .{ .err = .{ .TransactionNotFound = .{ .digest = .{ .@"0" = .{ .@"0" = d.* } } } } };
    }
    fn checkpoint(_: *anyopaque, arena: std.mem.Allocator, q: backend.CheckpointQuery, v2: bool) backend.Result([]const u8) {
        _ = q;
        return .{ .ok = (if (v2) wire.checkpointResponseV2(arena, null, null) else wire.checkpointResponse(arena, null, null)) catch unreachable };
    }
    fn state(_: *anyopaque, arena: std.mem.Allocator) backend.Result([]const u8) {
        return .{ .ok = wire.systemStateResponse(arena, 2, "inner") catch unreachable };
    }
    fn health(_: *anyopaque) wire.Health {
        return .{ .pending_certificates = 1, .inflight_consensus_messages = 2, .consensus_round = 3, .checkpoint_sequence = 4 };
    }
    const vt: backend.Backend.VTable = .{
        .submit = submit,
        .wait_for_effects = wait,
        .object_info = objectInfo,
        .transaction_info = txInfo,
        .checkpoint = checkpoint,
        .system_state = state,
        .health = health,
    };
};

fn connect(port: u16) !*grpc.Conn {
    return grpc.Conn.open(std.heap.page_allocator, std.testing.io, .{ .host = "127.0.0.1", .port = port, .security = .plain });
}

test "validator service answers every method through a real h2c client" {
    var fake: Fake = .{};
    var reg = metrics.Registry.init(std.testing.io);
    const s = try server.Server.start(std.testing.allocator, std.testing.io, "127.0.0.1:0", .{ .ctx = &fake, .vt = &Fake.vt }, &reg, &fake.epoch, .{});
    defer _ = s.stop();
    const c = try connect(s.port());
    defer c.release();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // SubmitTransaction (prost both ways)
    const req = try dw.submitTxRequest(arena, "tx-bytes");
    const r1 = try grpc.callBlocking(arena, c, server.service_path ++ "SubmitTransaction", req, 5000);
    try std.testing.expectEqualSlices(u8, try dw.submitTxResponse(arena, &.{.{ .Submitted = "position" }}), r1.ok);

    // WaitForEffects
    const wreq = try dw.waitForEffectsRequest(arena, .{ .transaction_digest = @splat(3) });
    const r2 = try grpc.callBlocking(arena, c, server.service_path ++ "WaitForEffects", wreq, 5000);
    try std.testing.expectEqualSlices(u8, try dw.waitForEffectsResponse(arena, .{ .Expired = .{ .epoch = 5, .round = null } }), r2.ok);

    // ObjectInfo: found, and not found as a SuiError in the status details
    var oi: [34]u8 = @splat(0);
    oi[0] = 1;
    oi[32] = 1; // layout None
    const r3 = try grpc.callBlocking(arena, c, server.service_path ++ "ObjectInfo", &oi, 5000);
    try std.testing.expectEqualSlices(u8, "object-bytes\x00\x00", r3.ok);
    oi[0] = 2;
    const r4 = try grpc.callBlocking(arena, c, server.service_path ++ "ObjectInfo", &oi, 5000);
    try std.testing.expectEqual(@as(u8, 13), r4.status.code);
    const kind = try bcs.decode(backend.SuiErrorKind, arena, r4.status.details);
    try std.testing.expect(kind == .UserInputError);
    try std.testing.expect(std.mem.indexOf(u8, r4.status.message, "Could not find the referenced object") != null);

    // TransactionInfo not found, Checkpoint, CheckpointV2, system state, health
    var ti: [33]u8 = @splat(7);
    ti[0] = 32;
    const r5 = try grpc.callBlocking(arena, c, server.service_path ++ "TransactionInfo", &ti, 5000);
    try std.testing.expectEqual(@as(u8, 13), r5.status.code);
    const r6 = try grpc.callBlocking(arena, c, server.service_path ++ "Checkpoint", &.{ 0, 1 }, 5000);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0 }, r6.ok);
    const r7 = try grpc.callBlocking(arena, c, server.service_path ++ "CheckpointV2", &.{ 0, 1, 1 }, 5000);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0 }, r7.ok);
    const r8 = try grpc.callBlocking(arena, c, server.service_path ++ "GetSystemStateObject", &.{0}, 5000);
    try std.testing.expectEqualSlices(u8, "\x01inner", r8.ok);
    const r9 = try grpc.callBlocking(arena, c, server.service_path ++ "ValidatorHealth", "", 5000);
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 1, 0x10, 2, 0x18, 3, 0x20, 4 }, r9.ok);

    // a malformed BCS request is INTERNAL, an unknown method UNIMPLEMENTED
    const r10 = try grpc.callBlocking(arena, c, server.service_path ++ "ObjectInfo", "short", 5000);
    try std.testing.expectEqual(@as(u8, 13), r10.status.code);
    const r11 = try grpc.callBlocking(arena, c, server.service_path ++ "Nope", "", 5000);
    try std.testing.expectEqual(@as(u8, 12), r11.status.code);

    // the rest of sui-node's validator port (tonic Routes): grpc.health.v1 with only "" serving,
    // and tonic's UNIMPLEMENTED fallback (not 404) for any other path, /health included
    const h1 = try grpc.callBlocking(arena, c, server.health_path ++ "Check", "", 5000);
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0x01 }, h1.ok);
    const h2 = try grpc.callBlocking(arena, c, server.health_path ++ "Check", "\x0a\x17sui.validator.Validator", 5000);
    try std.testing.expectEqual(@as(u8, 5), h2.status.code);
    try std.testing.expectEqualStrings("service not registered", h2.status.message);
    const un1 = try grpc.callBlocking(arena, c, "/sui.rpc.v2.LedgerService/GetServiceInfo", "", 5000);
    try std.testing.expectEqual(@as(u8, 12), un1.status.code);
    const un2 = try grpc.callBlocking(arena, c, "/health", "", 5000);
    try std.testing.expectEqual(@as(u8, 12), un2.status.code);
    try std.testing.expect(reg.counter("zui_validator_grpc_requests").f.series[0].used.load(.acquire));
}

test "submit retries once after the validator halted at epoch end" {
    var fake: Fake = .{ .halted_first = true };
    var reg = metrics.Registry.init(std.testing.io);
    const s = try server.Server.start(std.testing.allocator, std.testing.io, "127.0.0.1:0", .{ .ctx = &fake, .vt = &Fake.vt }, &reg, &fake.epoch, .{ .halted_retry_wait_ms = 2000 });
    defer _ = s.stop();
    const c = try connect(s.port());
    defer c.release();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const req = try dw.submitTxRequest(arena, "tx");
    const r = try grpc.callBlocking(arena, c, server.service_path ++ "SubmitTransaction", req, 8000);
    try std.testing.expectEqualSlices(u8, try dw.submitTxResponse(arena, &.{.{ .Submitted = "position" }}), r.ok);
    try std.testing.expectEqual(@as(u32, 2), fake.submits);
}

test "metrics endpoint serves the registry" {
    var reg = metrics.Registry.init(std.testing.io);
    reg.counter("total_signature_errors").inc();
    const m = try server.MetricsServer.start(std.testing.allocator, std.testing.io, "127.0.0.1:0", &reg);
    defer m.stop();
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", m.port());
    var st = try addr.connect(std.testing.io, .{ .mode = .stream });
    defer st.close(std.testing.io);
    const fd = st.socket.handle;
    try @import("serve").h2.sock.writeAll(fd, "GET /metrics HTTP/1.1\r\nhost: x\r\n\r\n");
    var buf: [65536]u8 = undefined;
    var n: usize = 0;
    while (n < buf.len) {
        const k = @import("serve").h2.sock.read(fd, buf[n..]) catch break;
        if (k == 0) break;
        n += k;
    }
    try std.testing.expect(std.mem.startsWith(u8, buf[0..n], "HTTP/1.1 200 OK"));
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "total_signature_errors 1\n") != null);
}

fn isOk(r: anyerror!grpc.Result) bool {
    const v = r catch return false;
    return v == .ok;
}

test "with a network key the service speaks TLS 1.3 pinned to that key, like sui-node" {
    var fake: Fake = .{};
    var reg = metrics.Registry.init(std.testing.io);
    const seed: [32]u8 = @splat(9);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const s = try server.Server.start(std.testing.allocator, std.testing.io, "127.0.0.1:0", .{ .ctx = &fake, .vt = &Fake.vt }, &reg, &fake.epoch, .{ .tls_seed = seed });
    defer _ = s.stop();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // pinned to the validator's network key: the call goes through
    const c = try grpc.Conn.open(std.heap.page_allocator, std.testing.io, .{ .host = "127.0.0.1", .port = s.port(), .security = .{ .pinned = kp.public_key.toBytes() } });
    defer c.release();
    const r = try grpc.callBlocking(arena, c, server.service_path ++ "ValidatorHealth", "", 5000);
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 1, 0x10, 2, 0x18, 3, 0x20, 4 }, r.ok);

    // pinned to another key: the handshake is refused
    const other = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(10));
    const bad = grpc.Conn.open(std.heap.page_allocator, std.testing.io, .{ .host = "127.0.0.1", .port = s.port(), .security = .{ .pinned = other.public_key.toBytes() } });
    if (bad) |bc| {
        defer bc.release();
        try std.testing.expect(!isOk(grpc.callBlocking(arena, bc, server.service_path ++ "ValidatorHealth", "", 3000)));
    } else |_| {}

    // plaintext h2c to a TLS port is not served
    const plain = try connect(s.port());
    defer plain.release();
    try std.testing.expect(!isOk(grpc.callBlocking(arena, plain, server.service_path ++ "ValidatorHealth", "", 2000)));
}
