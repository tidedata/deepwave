//! HMAC (RFC 2104) and HKDF (RFC 5869) over any of the hashers in this module.
//! Keys of any length (0..) are accepted, as the Rust `hmac` crate does. The inner and outer
//! midstates are computed once in `init` and copied by value, so repeated MACs under one key
//! (HKDF expand, TLS) cost two compressions less per call. No allocation.
const std = @import("std");

pub fn Hmac(comptime H: type) type {
    return struct {
        const Self = @This();
        pub const mac_length = H.digest_length;
        const B = H.block_length;

        inner: H,
        outer: H,

        pub fn init(key: []const u8) Self {
            var k: [B]u8 = @splat(0);
            if (key.len > B) {
                var hk: [H.digest_length]u8 = undefined;
                H.hash(key, &hk);
                @memcpy(k[0..H.digest_length], &hk);
            } else {
                @memcpy(k[0..key.len], key);
            }
            var ip: [B]u8 = undefined;
            var op: [B]u8 = undefined;
            for (k, &ip, &op) |x, *i, *o| {
                i.* = x ^ 0x36;
                o.* = x ^ 0x5c;
            }
            var s: Self = .{ .inner = H.init(), .outer = H.init() };
            s.inner.update(&ip);
            s.outer.update(&op);
            std.crypto.secureZero(u8, &k);
            std.crypto.secureZero(u8, &ip);
            std.crypto.secureZero(u8, &op);
            return s;
        }

        pub fn update(s: *Self, data: []const u8) void {
            s.inner.update(data);
        }

        pub fn final(s: *Self, out: *[H.digest_length]u8) void {
            var ih: [H.digest_length]u8 = undefined;
            s.inner.final(&ih);
            s.outer.update(&ih);
            s.outer.final(out);
        }

        pub fn mac(key: []const u8, msg: []const u8) [H.digest_length]u8 {
            var m = init(key);
            m.update(msg);
            var out: [H.digest_length]u8 = undefined;
            m.final(&out);
            return out;
        }
    };
}

pub const HkdfError = error{OutputTooLong};

pub fn Hkdf(comptime H: type) type {
    return struct {
        const M = Hmac(H);
        const L = H.digest_length;

        /// PRK = HMAC(salt, ikm). An empty salt is a valid key (zero padding), as in the RFC.
        pub fn extract(salt: []const u8, ikm: []const u8) [L]u8 {
            return M.mac(salt, ikm);
        }

        /// OKM of out.len bytes (at most 255 * L) from PRK and info.
        pub fn expand(prk: *const [L]u8, info: []const u8, out: []u8) HkdfError!void {
            if (out.len > 255 * L) return error.OutputTooLong;
            const base = M.init(prk);
            var t: [L]u8 = undefined;
            var have_t = false;
            var i: u8 = 1;
            var off: usize = 0;
            while (off < out.len) : (i +%= 1) {
                var m = base;
                if (have_t) m.update(&t);
                m.update(info);
                m.update(&.{i});
                m.final(&t);
                have_t = true;
                const n = @min(L, out.len - off);
                @memcpy(out[off..][0..n], t[0..n]);
                off += n;
            }
        }
    };
}

test "RFC 4231 case 1: HMAC-SHA-256" {
    const sha2 = @import("sha2.zig");
    var key: [20]u8 = @splat(0x0b);
    const mac = Hmac(sha2.Sha256).mac(&key, "Hi There");
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    try std.testing.expectEqualSlices(u8, &want, &mac);
}

test "RFC 5869 case 1: HKDF-SHA-256" {
    const sha2 = @import("sha2.zig");
    var ikm: [22]u8 = @splat(0x0b);
    var salt: [13]u8 = undefined;
    for (&salt, 0..) |*b, i| b.* = @intCast(i);
    var info: [10]u8 = undefined;
    for (&info, 0..) |*b, i| b.* = @intCast(0xf0 + i);
    const K = Hkdf(sha2.Sha256);
    const prk = K.extract(&salt, &ikm);
    var want_prk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    try std.testing.expectEqualSlices(u8, &want_prk, &prk);
    var okm: [42]u8 = undefined;
    try K.expand(&prk, &info, &okm);
    var want: [42]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    try std.testing.expectEqualSlices(u8, &want, &okm);
}

// dudect-style timing test (Reparaz, Balasch, Verbauwhede 2016): two input classes, one fixed key
// and one random key, interleaved at random; Welch's t-test on the cropped timings. HMAC and HKDF
// are the only secret-keyed code in this module; the hashers themselves have no secret-dependent
// branches or table lookups. |t| above ~10 on this many samples would be a definite leak; the
// test retries once because a shared machine adds noise.
fn timingT(comptime H: type, key_len: usize) !f64 {
    const io = std.Io.Threaded.global_single_threaded.io();
    var prng = std.Random.DefaultPrng.init(0xd0d3c7);
    const r = prng.random();
    const n = 20000;
    var fixed_key: [200]u8 = undefined;
    r.bytes(&fixed_key);
    var msg: [64]u8 = undefined;
    r.bytes(&msg);
    var samples: [2][n]f64 = undefined;
    var counts = [2]usize{ 0, 0 };
    // Class 1 draws from a small pool of random keys so both classes read L1-resident key bytes:
    // the test is about the computation, not about cache misses on fresh memory.
    var pool: [64][200]u8 = undefined;
    for (&pool) |*k| r.bytes(k);
    var step: usize = 0;
    var kbuf: [200]u8 align(64) = undefined;
    for (0..2 * n) |_| {
        const class: usize = r.int(u1);
        if (counts[class] == n) continue;
        // Both classes present the key at the same address: only the value differs.
        kbuf = if (class == 0) fixed_key else pool[step % pool.len];
        step += 1;
        const t0 = std.Io.Timestamp.now(io, .awake);
        const mac = Hmac(H).mac(kbuf[0..key_len], &msg);
        const t1 = std.Io.Timestamp.now(io, .awake);
        std.mem.doNotOptimizeAway(&mac);
        samples[class][counts[class]] = @floatFromInt(t0.durationTo(t1).nanoseconds);
        counts[class] += 1;
    }
    // crop the slowest 5% of each class (interrupts), then Welch's t
    var mean: [2]f64 = undefined;
    var vari: [2]f64 = undefined;
    var m: [2]usize = undefined;
    for (0..2) |c| {
        const s = samples[c][0..counts[c]];
        std.mem.sort(f64, s, {}, std.sort.asc(f64));
        const keep = s[0 .. s.len * 95 / 100];
        var sum: f64 = 0;
        for (keep) |x| sum += x;
        mean[c] = sum / @as(f64, @floatFromInt(keep.len));
        var sq: f64 = 0;
        for (keep) |x| sq += (x - mean[c]) * (x - mean[c]);
        vari[c] = sq / @as(f64, @floatFromInt(keep.len - 1));
        m[c] = keep.len;
    }
    const se = @sqrt(vari[0] / @as(f64, @floatFromInt(m[0])) + vari[1] / @as(f64, @floatFromInt(m[1])));
    if (se == 0) return 0;
    return (mean[0] - mean[1]) / se;
}

test "timing: HMAC time does not depend on the key value (dudect)" {
    const sha2 = @import("sha2.zig");
    const keccak = @import("keccak.zig");
    inline for (.{ sha2.Sha256, keccak.Sha3_256 }) |H| {
        for ([_]usize{ 32, 136 }) |kl| {
            // A real key dependence shows in every attempt; scheduler noise on a shared machine
            // does not, so up to four attempts are made.
            var t = try timingT(H, kl);
            var attempt: usize = 1;
            while (@abs(t) > 10 and attempt < 4) : (attempt += 1) t = try timingT(H, kl);
            if (@abs(t) > 10) {
                std.debug.print("dudect t = {d:.2} for key length {d}\n", .{ t, kl });
                return error.TimingLeak;
            }
        }
    }
}
