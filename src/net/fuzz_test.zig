//! Deterministic mutation fuzzing of every parser that sees network bytes: no panic, no
//! out-of-bounds, no unbounded allocation (Debug mode safety checks are on in `zig build test`).
const std = @import("std");
const snappy = @import("snappy.zig");
const wire = @import("wire.zig");
const x509 = @import("x509.zig");
const tls13 = @import("tls13.zig");
const Ed25519 = std.crypto.sign.Ed25519;

fn mutate(r: std.Random, buf: []u8) void {
    if (buf.len == 0) return;
    for (0..1 + r.uintLessThan(usize, 4)) |_| {
        switch (r.uintLessThan(u8, 3)) {
            0 => buf[r.uintLessThan(usize, buf.len)] ^= @as(u8, 1) << r.int(u3),
            1 => buf[r.uintLessThan(usize, buf.len)] = r.int(u8),
            else => buf[r.uintLessThan(usize, buf.len)] = 0xff,
        }
    }
}

test "snappy decoders reject garbage without crashing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(1);
    const r = prng.random();
    const gpa = std.testing.allocator;
    var keep = std.heap.ArenaAllocator.init(gpa);
    defer keep.deinit();
    const good = try snappy.compressFrame(keep.allocator(), "the quick brown fox jumps over the lazy dog, the quick brown fox jumps over the lazy dog");
    var out: [64]u8 = undefined;
    for (0..20000) |i| {
        _ = arena_state.reset(.retain_capacity);
        var b = try a.dupe(u8, good);
        mutate(r, b);
        if (i % 7 == 0) b = b[0..r.uintLessThan(usize, b.len + 1)];
        _ = snappy.decompressFrame(a, b, 1 << 20) catch {};
        if (b.len > 6) {
            _ = snappy.blockLen(b[6..]) catch {};
            _ = snappy.decompressBlock(b[6..], &out) catch {};
        }
    }
}

test "anemo wire parsers reject garbage without crashing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(2);
    const r = prng.random();
    const hs = [_]wire.Header{ .{ .name = "timeout", .value = "5" }, .{ .name = "x", .value = "yy" } };
    var keep = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer keep.deinit();
    const req = try wire.encodeRequest(keep.allocator(), "/r", &hs, "body");
    const resp = try wire.encodeResponse(keep.allocator(), .success, &hs, "body");
    for (0..20000) |i| {
        _ = arena_state.reset(.retain_capacity);
        var b = try a.dupe(u8, if (i % 2 == 0) req else resp);
        mutate(r, b);
        if (i % 5 == 0) b = b[0..r.uintLessThan(usize, b.len + 1)];
        _ = wire.parseRequest(a, b, 1 << 20) catch {};
        _ = wire.parseResponse(a, b, 1 << 20) catch {};
    }
}

test "certificate verifier rejects mutated certificates" {
    var prng = std.Random.DefaultPrng.init(3);
    const r = prng.random();
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(9));
    var buf: [x509.max_cert_len]u8 = undefined;
    const n = x509.generateSelfSigned(&buf, kp, @splat(1), "sui-35834a8a");
    _ = try x509.verifyPeerCert(buf[0..n], "sui-35834a8a", .server, 1_800_000_000);
    var m: [x509.max_cert_len]u8 = undefined;
    var accepted: usize = 0;
    for (0..30000) |_| {
        @memcpy(m[0..n], buf[0..n]);
        mutate(r, m[0..n]);
        if (x509.verifyPeerCert(m[0..n], "sui-35834a8a", .server, 1_800_000_000)) |_| {
            accepted += 1;
        } else |_| {}
    }
    // a mutation may land in an ignored byte (e.g. the serial number is covered by the signature, so
    // practically nothing verifies); it must never crash and almost never verify
    try std.testing.expect(accepted < 30);
}

test "tls client survives random server messages" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(4);
    const r = prng.random();
    var msg: [200]u8 = undefined;
    for (0..3000) |i| {
        var c = tls13.Client.init(.{
            .server_name = "sui-test",
            .local_tp = "",
            .identity = try Ed25519.KeyPair.generateDeterministic(@splat(1)),
            .cert_der = "",
            .now_unix = 0,
            .random = @splat(0),
            .x25519_secret = @splat(5),
        });
        defer c.deinit(gpa);
        try c.start(gpa);
        const n = r.uintLessThan(usize, msg.len);
        r.bytes(msg[0..n]);
        if (n >= 4 and i % 2 == 0) {
            msg[0] = 2; // ServerHello
            msg[1] = 0;
            msg[2] = 0;
            msg[3] = @intCast(n - 4);
        }
        c.feed(gpa, .initial, msg[0..n]) catch {};
        c.feed(gpa, .handshake, msg[0..n]) catch {};
    }
}
