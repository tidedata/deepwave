//! The slice of rand 0.8.5 that consensus's leader election uses, bit for bit: `StdRng` =
//! ChaCha12 (rand_chacha 0.3.1, 64-bit block counter, zero stream), `gen::<u32|u64|f64>`,
//! `gen_range(0..n)` for u32 (sample_single_inclusive with the conservative zone), `shuffle`
//! (Fisher-Yates from the back) and `choose_multiple_weighted` (Efraimidis-Spirakis with
//! `key = u^(1/w)`, f64, taken from a max-heap). Truth: `leader_schedule.rs`. Owner: val-consensus-core.
const std = @import("std");

pub const ChaCha12 = struct {
    key: [8]u32,
    counter: u64 = 0,
    buf: [16]u32 = undefined,
    /// Next unread word in `buf`; 16 means empty.
    idx: usize = 16,

    pub fn fromSeed(seed: [32]u8) ChaCha12 {
        var k: [8]u32 = undefined;
        for (&k, 0..) |*w, i| w.* = std.mem.readInt(u32, seed[i * 4 ..][0..4], .little);
        return .{ .key = k };
    }

    fn qr(x: *[16]u32, a: usize, b: usize, c: usize, d: usize) void {
        x[a] +%= x[b];
        x[d] = std.math.rotl(u32, x[d] ^ x[a], 16);
        x[c] +%= x[d];
        x[b] = std.math.rotl(u32, x[b] ^ x[c], 12);
        x[a] +%= x[b];
        x[d] = std.math.rotl(u32, x[d] ^ x[a], 8);
        x[c] +%= x[d];
        x[b] = std.math.rotl(u32, x[b] ^ x[c], 7);
    }

    fn refill(self: *ChaCha12) void {
        var s: [16]u32 = undefined;
        s[0] = 0x61707865;
        s[1] = 0x3320646e;
        s[2] = 0x79622d32;
        s[3] = 0x6b206574;
        @memcpy(s[4..12], &self.key);
        s[12] = @truncate(self.counter);
        s[13] = @truncate(self.counter >> 32);
        s[14] = 0;
        s[15] = 0;
        var x = s;
        var r: usize = 0;
        while (r < 6) : (r += 1) {
            qr(&x, 0, 4, 8, 12);
            qr(&x, 1, 5, 9, 13);
            qr(&x, 2, 6, 10, 14);
            qr(&x, 3, 7, 11, 15);
            qr(&x, 0, 5, 10, 15);
            qr(&x, 1, 6, 11, 12);
            qr(&x, 2, 7, 8, 13);
            qr(&x, 3, 4, 9, 14);
        }
        for (&self.buf, x, s) |*o, a, b| o.* = a +% b;
        self.counter +%= 1;
        self.idx = 0;
    }

    pub fn nextU32(self: *ChaCha12) u32 {
        if (self.idx >= 16) self.refill();
        const v = self.buf[self.idx];
        self.idx += 1;
        return v;
    }

    pub fn nextU64(self: *ChaCha12) u64 {
        const lo = self.nextU32();
        const hi = self.nextU32();
        return (@as(u64, hi) << 32) | lo;
    }

    /// `rng.gen::<f64>()`: top 53 bits of a u64 times 2^-53.
    pub fn nextF64(self: *ChaCha12) f64 {
        const v = self.nextU64() >> 11;
        return @as(f64, @floatFromInt(v)) * (1.0 / 9007199254740992.0);
    }

    /// `rng.gen_range(0..ubound)` for u32 (ubound > 0).
    pub fn genRangeU32(self: *ChaCha12, ubound: u32) u32 {
        std.debug.assert(ubound > 0);
        const range = ubound;
        const zone = (range << @as(u5, @intCast(@clz(range)))) -% 1;
        while (true) {
            const v = self.nextU32();
            const m = @as(u64, v) * @as(u64, range);
            const hi: u32 = @intCast(m >> 32);
            const lo: u32 = @truncate(m);
            if (lo <= zone) return hi;
        }
    }

    /// `slice.shuffle(rng)`.
    pub fn shuffle(self: *ChaCha12, comptime T: type, items: []T) void {
        var i: usize = items.len;
        while (i > 1) {
            i -= 1;
            const j = self.genRangeU32(@intCast(i + 1));
            std.mem.swap(T, &items[i], &items[j]);
        }
    }
};

/// Index of the first element `choose_multiple_weighted(rng, len, weight).skip(offset).next()`
/// yields. `weights` are f64 (Rust converts f32 stakes with `Into<f64>`). Keys are drawn in index
/// order, then taken largest first. Fixed capacity 1024 keys (committee size bound is 512).
pub const max_weighted = 1024;

pub fn chooseWeighted(rng: *ChaCha12, weights: []const f64, offset: usize) ?usize {
    if (weights.len > max_weighted or offset >= weights.len) return null;
    var keys: [max_weighted]f64 = undefined;
    var order: [max_weighted]u32 = undefined;
    for (weights, 0..) |w, i| {
        if (!(w >= 0.0)) return null;
        keys[i] = std.math.pow(f64, rng.nextF64(), 1.0 / w);
        order[i] = @intCast(i);
    }
    // Descending by key; the heap pop order for distinct keys equals a descending sort.
    const Ctx = struct {
        k: []const f64,
        fn lt(c: @This(), a: u32, b: u32) bool {
            return c.k[a] > c.k[b];
        }
    };
    std.mem.sort(u32, order[0..weights.len], Ctx{ .k = keys[0..weights.len] }, Ctx.lt);
    return order[offset];
}

test "StdRng value stability (rand 0.8.5 test_stdrng_construction)" {
    const seed = [32]u8{ 1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var rng = ChaCha12.fromSeed(seed);
    try std.testing.expectEqual(@as(u64, 10719222850664546238), rng.nextU64());
}

test "genRangeU32 stays in range and shuffle permutes" {
    var rng = ChaCha12.fromSeed(@splat(7));
    for (0..200) |_| try std.testing.expect(rng.genRangeU32(13) < 13);
    var a = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    rng.shuffle(u8, &a);
    var seen: u8 = 0;
    for (a) |v| seen |= @as(u8, 1) << @intCast(v);
    try std.testing.expectEqual(@as(u8, 0xff), seen);
}
