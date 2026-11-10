//! Deterministic mutation fuzzing of every parser that sees network bytes: no panic, no
//! out-of-bounds, no unbounded allocation (Debug mode safety checks are on in `zig build test`).
const std = @import("std");
const snappy = @import("snappy.zig");
const wire = @import("wire.zig");
const x509 = @import("x509.zig");
const tls13 = @import("tls13.zig");
const tls13_server = @import("tls13_server.zig");
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

test "tls server survives mutated ClientHellos, every length field forced to its extremes" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5);
    const r = prng.random();
    const ckp = try Ed25519.KeyPair.generateDeterministic(@splat(1));
    const skp = try Ed25519.KeyPair.generateDeterministic(@splat(2));
    var scert: [x509.max_cert_len]u8 = undefined;
    const sl = x509.generateSelfSigned(&scert, skp, @splat(6), "zui");
    var hellos: [2][]u8 = undefined;
    for (&hellos, [_][]const u8{ "zui/1", "" }) |*h, alpn| {
        var c = tls13.Client.init(.{ .server_name = "zui", .local_tp = "ctp", .identity = ckp, .cert_der = "", .now_unix = 0, .random = @splat(7), .x25519_secret = @splat(8), .alpn = alpn });
        defer c.deinit(gpa);
        try c.start(gpa);
        h.* = try gpa.dupe(u8, c.takeOutput(.initial));
    }
    defer for (hellos) |h| gpa.free(h);
    const extremes = [_]u16{ 0, 1, 2, 0x7f, 0x80, 0xfe, 0xff, 0x100, 0x7fff, 0xfffd, 0xfffe, 0xffff };
    const exts = [_]u16{ 0x0000, 0x000a, 0x000d, 0x0033, 0x002b, 0x0010, 0x0039 };
    const no_alpn: []const []const u8 = &.{};
    const zui_alpn: []const []const u8 = &.{"zui/1"};
    var m: [512]u8 = undefined;
    var accepted: usize = 0;
    for (0..20000) |i| {
        const h = hellos[i % 2];
        @memcpy(m[0..h.len], h);
        var n = h.len;
        const v = if (r.boolean()) extremes[r.uintLessThan(usize, extremes.len)] else r.int(u16);
        switch (r.uintLessThan(u8, 4)) {
            // a length inside one extension's data (u8 or u16)
            0 => if (tls13_server.helloExtOffset(m[0..n], exts[r.uintLessThan(usize, exts.len)])) |at| {
                const w: u8 = if (r.boolean()) 1 else 2;
                if (at + w <= n) tls13_server.pokeLength(m[0..n], at, v, w);
            },
            // any 16-bit position (extension type/length, cipher suite and extension list lengths)
            1 => tls13_server.pokeLength(m[0..n], 4 + r.uintLessThan(usize, n - 5), v, 2),
            // any byte (session id and compression method lengths)
            2 => m[4 + r.uintLessThan(usize, n - 4)] = @truncate(v),
            else => mutate(r, m[4..n]),
        }
        if (i % 9 == 0) n = 4 + r.uintLessThan(usize, n - 3);
        // keep the handshake header consistent so the body reaches the parser
        const bl = n - 4;
        m[1] = @intCast(bl >> 16);
        m[2] = @intCast((bl >> 8) & 0xff);
        m[3] = @intCast(bl & 0xff);
        var s = tls13_server.Server.init(.{ .server_name = "zui", .local_tp = "stp", .identity = skp, .cert_der = scert[0..sl], .now_unix = 1_800_000_000, .random = @splat(9), .x25519_secret = @splat(10), .alpn = if (i % 3 == 0) no_alpn else zui_alpn, .client_auth = i % 2 == 0, .tcp = i % 5 == 0 });
        defer s.deinit(gpa);
        if (s.feed(gpa, .initial, m[0..n])) |_| accepted += 1 else |_| {}
    }
    try std.testing.expect(accepted > 0); // some mutations land in ignored bytes
}
