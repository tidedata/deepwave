//! The listener's I/O thread never waits on the store (listener.zig module comment). A store read
//! that takes seconds (a cold page on a busy core) holds the worker that does it and nothing
//! else: the connection's ACKs, its other requests and every other connection go on. And a
//! checkpoint's pre-state, which every Address or Package subscription needs, is read once
//! however many subscriptions ask for it.
//!
//! The slow read is a test hook that blocks until the test lets it go (`Dispatcher.test_stall`
//! on the answer path, `sub.KeyCache.test_stall` on the pre-state path); the bounds are wall
//! clock, far apart: what must go on is asserted within 2 s while the read is held for up to 10.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const proto = @import("proto.zig");
const listener = @import("listener.zig");
const cert_mod = @import("cert.zig");
const certs_test = @import("certs_test.zig");
const Rig = certs_test.Rig;
const Client = certs_test.Client;

const id_seed: [32]u8 = @splat(9);

var hold: std.atomic.Value(bool) = .init(false);
var stalled: std.atomic.Value(u32) = .init(0);

/// Blocks while `hold`, at most 10 s.
fn waitRelease() void {
    const ts: std.c.timespec = .{ .sec = 0, .nsec = std.time.ns_per_ms };
    var k: usize = 0;
    while (hold.load(.acquire) and k < 10_000) : (k += 1) _ = std.c.nanosleep(&ts, null);
}

fn stallCheckpoint(req: proto.Request) void {
    if (req.method != .get_checkpoint) return;
    _ = stalled.fetchAdd(1, .monotonic);
    waitRelease();
}

fn stallPreState(_: u64) void {
    _ = stalled.fetchAdd(1, .monotonic);
    waitRelease();
}

fn nowMs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ms_per_s + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

fn connect(gpa: std.mem.Allocator, io: Io, l: *listener.Listener, salt: u8) !Client {
    var seed: [64]u8 = @splat(salt);
    seed[1] = 0x29;
    var cl = try Client.open(gpa, io, l.address(), .{
        .server_name = "zui",
        .identity_seed = @splat(4),
        .expected_peer = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(id_seed)).public_key.toBytes(),
        .seed = seed,
        .now_unix = 1_800_000_000,
        .alpn = &.{proto.alpn},
        .max_streams_uni = 16,
        .max_streams_bidi = 64,
        .keep_alive_ms = 0,
    });
    errdefer cl.close(gpa);
    if (!try cl.handshake()) return error.TestUnexpectedResult;
    return cl;
}

fn helloBody(gpa: std.mem.Allocator) !std.ArrayList(u8) {
    var b: std.ArrayList(u8) = .empty;
    const w: proto.W = .{ .gpa = gpa, .out = &b };
    try w.str("offthread-test");
    try w.int(u16, 0);
    try w.u8_(0);
    return b;
}

/// Sends a request on a new stream without waiting for the answer; returns the stream.
fn send(gpa: std.mem.Allocator, cl: *Client, method: proto.Method, body: []const u8, fin: bool) !u64 {
    var rounds: usize = 0;
    const id = while (true) : (rounds += 1) {
        if (cl.c.openBidi()) |id| break id else |_| {}
        if (rounds > 2000) return error.TestUnexpectedResult;
        cl.pump();
    };
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(gpa);
    try proto.encodeRequest(&req, gpa, method, 0, body);
    try cl.c.streamWrite(id, req.items, fin);
    return id;
}

fn answered(cl: *Client, id: u64) bool {
    const st = cl.c.stream(id) orelse return false;
    return st.recv.complete();
}

/// A hello on `cl`, timed (ms).
fn timedHello(gpa: std.mem.Allocator, cl: *Client) !u64 {
    var b = try helloBody(gpa);
    defer b.deinit(gpa);
    const t0 = nowMs();
    const resp = try cl.request(gpa, .hello, b.items);
    defer gpa.free(resp);
    try testing.expect(resp.len > 0 and resp[0] == 0);
    return nowMs() - t0;
}

fn startListener(gpa: std.mem.Allocator, rig: *Rig, cert: *const cert_mod.Cert) !*listener.Listener {
    return listener.Listener.start(gpa, rig.io(), .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = id_seed, .cert = cert, .sub_workers = 2 }, &rig.disp);
}

fn testCert() !cert_mod.Cert {
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    return cert_mod.generate(try P256.KeyPair.generateDeterministic(@splat(6)), @splat(1), 1_800_000_000, 14, "zui");
}

/// Checkpoint 1, with no transactions (CheckpointContents V1, both vectors empty).
fn commitCheckpoint(rig: *Rig) !void {
    const b = try rig.st.begin(1, 1);
    try b.checkpoint("summary-1", &.{ 0, 0, 0 });
    try rig.st.commit(b);
}

/// SubscribeReq: Address `addr` (sender), From 1, effects, default lag.
fn addressSub(addr: u8) [48]u8 {
    var b: [48]u8 = undefined;
    b[0] = 1;
    @memset(b[1..33], addr);
    b[33] = 0x01;
    b[34] = 1;
    std.mem.writeInt(u64, b[35..43], 1, .little);
    b[43] = proto.part_effects;
    std.mem.writeInt(u32, b[44..48], 0, .little);
    return b;
}

/// Bytes the server sent on `cl`'s subscription data streams (uni streams it opened), summed.
fn subBytes(cl: *Client, uni: *std.ArrayList(u64), gpa: std.mem.Allocator) !usize {
    while (cl.c.acceptUni()) |id| try uni.append(gpa, id);
    var n: usize = 0;
    for (uni.items) |id| if (cl.c.stream(id)) |st| {
        n += st.recv.contiguous().len;
    };
    return n;
}

test "zui/1 listener: a store read held for seconds holds only its worker; ACKs, the connection's other requests and other connections go on" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    const io = rig.io();
    try commitCheckpoint(&rig);
    rig.disp.test_stall = stallCheckpoint;
    hold.store(true, .release);
    stalled.store(0, .monotonic);
    defer hold.store(false, .release);
    const cert = try testCert();
    const l = try startListener(gpa, &rig, &cert);
    defer l.stop();
    var a = try connect(gpa, io, l, 1);
    defer a.close(gpa);
    var b = try connect(gpa, io, l, 2);
    defer b.close(gpa);

    // get_checkpoint (latest, no parts): its store read is held
    const slow = try send(gpa, &a, .get_checkpoint, &.{ 0, 0 }, true);
    const t0 = nowMs();
    while (stalled.load(.monotonic) == 0) {
        if (nowMs() - t0 > 2000) return error.TestUnexpectedResult;
        a.pump();
    }
    var rtt_max: u64 = 0;
    // the same connection's next request, and another connection's, while the read is held
    for (0..5) |_| {
        try testing.expect(try timedHello(gpa, &a) < 2000);
        rtt_max = @max(rtt_max, a.c.latest_rtt);
        try testing.expect(try timedHello(gpa, &b) < 2000);
    }
    try testing.expect(!answered(&a, slow));
    try testing.expect(nowMs() - t0 < 5000); // all of it well inside the hold
    // the I/O thread acknowledged a's packets as they came: round trips of loopback, not of the
    // held read
    try testing.expect(rtt_max < 250 * std.time.ns_per_ms);

    hold.store(false, .release);
    const t1 = nowMs();
    while (!answered(&a, slow)) {
        if (nowMs() - t1 > 5000) return error.TestUnexpectedResult;
        a.pump();
    }
    const st = a.c.stream(slow).?;
    try testing.expectEqual(@as(u8, 0), proto.parseResponse(st.recv.contiguous()).?.status);
}

test "zui/1 subscriptions: a checkpoint's pre-state read held for seconds stalls no connection, and N subscriptions cost one read" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    const io = rig.io();
    try commitCheckpoint(&rig);
    hold.store(true, .release);
    stalled.store(0, .monotonic);
    defer hold.store(false, .release);
    const cert = try testCert();
    const l = try startListener(gpa, &rig, &cert);
    defer l.stop();
    l.keys.test_stall = stallPreState;

    var cls: [3]Client = undefined;
    var n_open: usize = 0;
    defer for (cls[0..n_open]) |*c| c.close(gpa);
    for (&cls, 0..) |*c, i| {
        c.* = try connect(gpa, io, l, @intCast(10 + i));
        n_open += 1;
    }
    var unis: [3]std.ArrayList(u64) = @splat(.empty);
    defer for (&unis) |*u| u.deinit(gpa);
    // four subscriptions to checkpoint 1: one on each connection, a second on the first
    for (&cls, 0..) |*c, i| _ = try send(gpa, c, .subscribe, &addressSub(@intCast(0xa0 + i)), false);
    _ = try send(gpa, &cls[0], .subscribe, &addressSub(0xaf), false);
    const subs = 4;

    const t0 = nowMs();
    while (stalled.load(.monotonic) == 0) {
        if (nowMs() - t0 > 2000) return error.TestUnexpectedResult;
        for (&cls) |*c| c.pump();
    }
    // the first one's read is held: every connection still answers at once, and nothing of
    // checkpoint 1 has gone out (each data stream carries only its subscription id)
    var rtt_max: u64 = 0;
    for (0..3) |_| {
        for (&cls) |*c| {
            try testing.expect(try timedHello(gpa, c) < 2000);
            rtt_max = @max(rtt_max, c.c.latest_rtt);
        }
    }
    try testing.expect(rtt_max < 250 * std.time.ns_per_ms);
    for (&cls, &unis) |*c, *u| {
        const n = try subBytes(c, u, gpa);
        try testing.expect(n <= u.items.len); // one varint byte per subscription id
    }
    // no worker waits for the held computation with a snapshot: the other subscriptions' batches
    // keep finishing (asked again on later passes) while it is held
    const t2 = nowMs();
    while (l.sub_stats.works.load(.monotonic) < 3) {
        if (nowMs() - t2 > 2000) return error.TestUnexpectedResult;
        for (&cls) |*c| c.pump();
    }
    try testing.expect(nowMs() - t0 < 5000);
    try testing.expectEqual(@as(u32, 1), stalled.load(.monotonic));

    hold.store(false, .release);
    // every subscription gets checkpoint 1 (its CheckpointEnd), from the one read
    const t1 = nowMs();
    while (true) {
        var have: usize = 0;
        for (&cls, &unis) |*c, *u| {
            _ = try subBytes(c, u, gpa);
            for (u.items) |id| if (c.c.stream(id)) |st| {
                if (st.recv.contiguous().len > 1) have += 1;
            };
        }
        if (have == subs) break;
        if (nowMs() - t1 > 5000) return error.TestUnexpectedResult;
        for (&cls) |*c| c.pump();
    }
    const ks = &l.keys.stats;
    try testing.expectEqual(@as(u32, 1), stalled.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), ks.misses.load(.monotonic));
    // the others found it being computed, did not wait for it (a worker holds a snapshot), and
    // were served the kept result once it was there
    try testing.expect(ks.coalesced.load(.monotonic) >= 1);
    try testing.expectEqual(@as(u64, subs - 1), ks.hits.load(.monotonic));
}

/// Checkpoint `seq`, with no transactions.
fn commitSeq(rig: *Rig, seq: u64) !void {
    const b = try rig.st.begin(seq, 1);
    try b.checkpoint("summary", &.{ 0, 0, 0 });
    try rig.st.commit(b);
}

/// `n` get_checkpoint requests over `cls`, at most 32 in flight per connection, all answered.
fn readLoad(gpa: std.mem.Allocator, cls: []Client, n: usize, threads_max: *usize) !void {
    var left = n;
    while (left > 0) {
        var ids: [2][32]u64 = undefined;
        var sent: [2]usize = @splat(0);
        for (cls, 0..) |*c, ci| {
            while (sent[ci] < 32 and left > 0) : (left -= 1) {
                ids[ci][sent[ci]] = try send(gpa, c, .get_checkpoint, &.{ 0, 0 }, true);
                sent[ci] += 1;
            }
        }
        const t0 = nowMs();
        while (true) {
            var all = true;
            for (cls, 0..) |*c, ci| for (ids[ci][0..sent[ci]]) |id| {
                if (!answered(c, id)) all = false;
            };
            if (all) break;
            if (nowMs() - t0 > 10_000) return error.TestUnexpectedResult;
            for (cls) |*c| c.pump();
        }
        if (tcache.processThreads()) |t| threads_max.* = @max(threads_max.*, t);
    }
}

const tcache = @import("core").threads;

test "zui/1 listener: no thread is started per request or per subscription batch; the thread count stays flat" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    const io = rig.io();
    try commitCheckpoint(&rig);
    const cert = try testCert();
    const l = try startListener(gpa, &rig, &cert);
    defer l.stop();
    var cls: [2]Client = undefined;
    cls[0] = try connect(gpa, io, l, 21);
    defer cls[0].close(gpa);
    cls[1] = try connect(gpa, io, l, 22);
    defer cls[1].close(gpa);
    // Address subscriptions: every checkpoint is a subscription batch and a pre-state read
    for (&cls, 0..) |*c, i| _ = try send(gpa, c, .subscribe, &addressSub(@intCast(0xc0 + i)), false);

    // warm: every pool worker started (the read pool's 4 run at once under 64 in flight)
    var threads_max: usize = 0;
    var seq: u64 = 2;
    for (0..4) |_| {
        try readLoad(gpa, &cls, 256, &threads_max);
        try commitSeq(&rig, seq);
        seq += 1;
    }
    const works0 = l.sub_stats.works.load(.monotonic);
    const finished0 = l.read_jobs.?.finished.load(.monotonic);
    const started0 = tcache.threadsStarted();
    const kept0 = tcache.stats.started.load(.monotonic);
    const threads0 = tcache.processThreads();
    threads_max = threads0 orelse 0;

    // 1,000 requests, with a checkpoint every 125 of them
    for (0..8) |_| {
        try readLoad(gpa, &cls, 125, &threads_max);
        try commitSeq(&rig, seq);
        seq += 1;
    }
    // the subscriptions took the new checkpoints
    const t0 = nowMs();
    while (l.sub_stats.checkpoints.load(.monotonic) < 2 * (seq - 1)) {
        if (nowMs() - t0 > 10_000) return error.TestUnexpectedResult;
        for (&cls) |*c| c.pump();
    }
    try testing.expect(l.sub_stats.works.load(.monotonic) > works0);
    try testing.expect(l.read_jobs.?.finished.load(.monotonic) - finished0 >= 1000);

    // threads started for the 1,000 requests and 8 checkpoints: none
    if (started0) |s0| {
        const spawned = tcache.threadsStarted().? - s0;
        std.debug.print("native: threads started per 1,000 requests and 8 checkpoints after warm-up: {d} (kept-thread cache: {d})\n", .{ spawned, tcache.stats.started.load(.monotonic) - kept0 });
        try testing.expectEqual(@as(u64, 0), spawned);
    }
    if (threads0) |n0| {
        try testing.expectEqual(n0, threads_max);
        try testing.expectEqual(n0, tcache.processThreads().?);
    }
}
