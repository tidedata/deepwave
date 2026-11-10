//! Exactness harness for the Ed25519 verifier paths (tests only).
//!
//! One set of inputs, one reference verdict per item, and every path of the verifier checked
//! against it item by item, single and batch. A path is a setting of the runtime switches (the
//! default scalar chain first, then the four-way point kernel, the batch key cache, the batch key
//! merge and their combinations), so a path that accepts or rejects anything differently, or
//! reports another error kind, fails here before it can be switched on.
//!
//! The reference is the ed25519-consensus rule written the long way, with none of the fast
//! machinery: decode A and R with the plain `decompress`, k = SHA-512(R, A, msg) mod l with
//! std's SHA-512, [k]A - [s]B by the 253-step double scalar multiplication, add R, multiply by
//! the cofactor, compare with the identity. No half-size scalars, no interleaved decoding, no
//! shared chain, no vector code, no cache.
//!
//! Inputs (generated, fixed seed):
//!   - the ZIP-215 set: all 14 encodings of the eight small-order points (canonical, non-canonical
//!     y, negative zero) as A and as R with s = 0 (196 signatures, all valid under ZIP-215);
//!   - Wycheproof-style edges: s = 0, s + l, s with high bits, R and A that do not decode, R
//!     negated, all-zero and all-ones inputs, wrong message, wrong key;
//!   - mixed-order keys and nonces: A = [a]B + T and R = [r]B + T' for every pair of torsion points
//!     (valid only under the cofactored equation), and their off-by-one neighbours;
//!   - small-order keys in every encoding with a full-size chain (R = [s]B + T');
//!   - random honest signatures and their single-bit corruptions.
const std = @import("std");
const ed = @import("ed25519.zig");
const verdict = @import("verdict.zig");
const Verdict = verdict.Verdict;
const Point = ed.Point;
const scalar = std.crypto.ecc.Edwards25519.scalar;
const cpu = @import("core").cpu;
const fast = @import("fast.zig");

pub const Item = struct {
    pk: [32]u8,
    sig: [64]u8,
    msg_buf: [40]u8 = @splat(0),
    msg_len: u8 = 0,
    tag: []const u8,

    pub fn msg(it: *const Item) []const u8 {
        return it.msg_buf[0..it.msg_len];
    }

    /// `d32`: store SHA-256(m) instead, so every message is 32 bytes (user signatures sign a
    /// 32-byte digest).
    fn setMsg(it: *Item, m: []const u8, d32: bool) void {
        if (d32) {
            std.crypto.hash.sha2.Sha256.hash(m, it.msg_buf[0..32], .{});
            it.msg_len = 32;
            return;
        }
        @memcpy(it.msg_buf[0..m.len], m);
        it.msg_len = @intCast(m.len);
    }
};

/// A setting of the verifier's runtime switches.
pub const Path = struct {
    name: []const u8,
    /// The four-way point kernel (core/cpu.zig `edVec4`); `force` runs it on every target.
    vec4: cpu.EdVec4 = .off,
    /// The batch reads and fills the decoded-key cache (needs `pk_cache`).
    batch_cache: bool = false,
    /// The batch merges the items that share a key.
    batch_merge: bool = false,
    /// sig/fast.zig's decoded-key cache.
    pk_cache: bool = false,

    /// The switches as they were before `enter`.
    pub const Saved = struct {
        vec4: cpu.EdVec4,
        batch_keys: ed.BatchKeys,
        fast_cfg: fast.Config,

        pub fn now() Saved {
            return .{ .vec4 = cpu.edVec4(), .batch_keys = ed.batchKeys(), .fast_cfg = fast.config() };
        }

        /// Puts the saved switches back and clears the caches.
        pub fn restore(s: Saved) void {
            cpu.setEdVec4(s.vec4);
            ed.setBatchKeys(s.batch_keys);
            fast.configure(s.fast_cfg);
            fast.clearCaches();
        }
    };

    /// Sets this path's switches and clears the caches. Returns what was set before, for
    /// `Saved.restore`: a path run with switches already set (from the environment, or inside
    /// another path) ends with those switches again, not with everything off.
    pub fn enter(p: Path) Saved {
        const was = Saved.now();
        cpu.setEdVec4(p.vec4);
        ed.setBatchKeys(.{ .cache = p.batch_cache, .merge = p.batch_merge });
        fast.configure(.{ .pk_cache = p.pk_cache });
        fast.clearCaches();
        return was;
    }
};

/// Every path the verifier can run. The first one is the reference configuration (all switches
/// off: what runs by default).
pub const paths = [_]Path{
    .{ .name = "default" },
    .{ .name = "vec4", .vec4 = .force },
    .{ .name = "batch merge", .batch_merge = true },
    .{ .name = "batch cache", .batch_cache = true, .pk_cache = true },
    .{ .name = "batch cache + merge", .batch_cache = true, .batch_merge = true, .pk_cache = true },
    .{ .name = "vec4 + batch merge", .vec4 = .force, .batch_merge = true },
    .{ .name = "vec4 + batch cache + merge", .vec4 = .force, .batch_cache = true, .batch_merge = true, .pk_cache = true },
};

const bad_sig: Verdict = .{ .invalid = .verify_invalid_signature };
const bad_pk: Verdict = .{ .invalid = .pk_invalid_input };

fn hashK(r: *const [32]u8, a: *const [32]u8, m: []const u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha512.init(.{});
    h.update(r);
    h.update(a);
    h.update(m);
    var d: [64]u8 = undefined;
    h.final(&d);
    return scalar.reduce64(d);
}

/// fastcrypto Ed25519PublicKey::from_bytes + verify on ed25519-consensus 2.1, the long way.
pub fn refVerdict(it: *const Item) Verdict {
    const a = ed.decompress(&it.pk) orelse return bad_pk;
    const s = it.sig[32..64];
    if (std.mem.readInt(u256, s, .little) >= ed.l_int) return bad_sig;
    const r = ed.decompress(it.sig[0..32]) orelse return bad_sig;
    const k = hashK(it.sig[0..32], &it.pk, it.msg());
    const neg_s = scalar.neg(s.*);
    // [k]A - [s]B + R
    const q = ed.doubleScalarMulBase(&k, a, &neg_s).add(r);
    return if (q.mulByCofactor().isIdentity()) .valid else bad_sig;
}

fn eqlPoint(p: Point, q: Point) bool {
    return std.mem.eql(u8, &p.toBytes(), &q.toBytes());
}

/// The eight points of small order: multiples of one point of order 8.
fn torsionPoints() [8]Point {
    const zero: [32]u8 = @splat(0);
    var y: [32]u8 = @splat(0);
    var c: u8 = 2;
    while (true) : (c += 1) {
        y[0] = c;
        const p = ed.decompress(&y) orelse continue;
        // [l]P has small order; keep it when the order is exactly 8
        const q = ed.doubleScalarMulBase(&ed.l_bytes, p, &zero);
        if (q.dbl().dbl().isIdentity()) continue;
        var out: [8]Point = undefined;
        out[0] = Point.identity;
        for (1..8) |i| out[i] = out[i - 1].add(q);
        return out;
    }
}

/// All 14 encodings that decode to a small-order point: the eight canonical ones, the sign bit
/// set on the two points with x = 0 (negative zero), and y = p and y = p + 1 with either sign.
pub fn torsionEncodings() [14][32]u8 {
    const t = torsionPoints();
    var out: [14][32]u8 = undefined;
    var n: usize = 0;
    for (t) |p| {
        out[n] = p.toBytes();
        n += 1;
    }
    for (t) |p| {
        if (!p.x.isZero()) continue;
        out[n] = p.toBytes();
        out[n][31] |= 0x80;
        n += 1;
    }
    const p_int: u256 = (1 << 255) - 19;
    for ([_]u256{ p_int, p_int + 1 }) |yv| {
        for ([_]u8{ 0, 0x80 }) |sign| {
            std.mem.writeInt(u256, &out[n], yv, .little);
            out[n][31] |= sign;
            n += 1;
        }
    }
    std.debug.assert(n == 14);
    return out;
}

pub const Set = struct {
    gpa: std.mem.Allocator,
    items: []Item,
    /// The reference verdict of each item.
    want: []Verdict,
    /// Three honest signatures used to pad a batch around one item.
    fill: [3]Item,

    pub fn deinit(s: *const Set) void {
        s.gpa.free(s.items);
        s.gpa.free(s.want);
    }

    pub fn init(gpa: std.mem.Allocator) !Set {
        return initOpts(gpa, false);
    }

    /// `d32`: every message is a 32-byte digest (the intake tests of user.zig).
    pub fn initOpts(gpa: std.mem.Allocator, d32: bool) !Set {
        var list: std.ArrayList(Item) = .empty;
        errdefer list.deinit(gpa);
        var prng: std.Random.DefaultPrng = .init(0x6578_6163_7431);
        const rnd = prng.random();
        const tors = torsionPoints();
        const tenc = torsionEncodings();

        // ZIP-215: small-order A and R in every encoding, s = 0.
        for (tenc) |a| for (tenc) |r| {
            var it: Item = .{ .pk = a, .sig = @splat(0), .tag = "zip215" };
            it.sig[0..32].* = r;
            it.setMsg("Zcash", d32);
            try list.append(gpa, it);
        };

        // Honest signatures and their corruptions.
        var honest: [48]Item = undefined;
        for (&honest, 0..) |*h, i| {
            var seed: [32]u8 = undefined;
            rnd.bytes(&seed);
            const kp = ed.KeyPair.fromSeed(&seed);
            h.* = .{ .pk = kp.pk, .sig = undefined, .tag = "honest" };
            var m: [40]u8 = undefined;
            rnd.bytes(&m);
            h.setMsg(m[0 .. i % 41], d32);
            h.sig = kp.sign(h.msg());
            try list.append(gpa, h.*);
        }
        // Repeated keys: a few senders with many signatures each (the batch may merge them).
        for (0..8) |ki| {
            var seed: [32]u8 = undefined;
            rnd.bytes(&seed);
            const kp = ed.KeyPair.fromSeed(&seed);
            for (0..24) |mi| {
                var it: Item = .{ .pk = kp.pk, .sig = undefined, .tag = "honest" };
                var m: [40]u8 = undefined;
                rnd.bytes(&m);
                it.setMsg(m[0 .. (ki + mi) % 41], d32);
                it.sig = kp.sign(it.msg());
                try list.append(gpa, it);
                if (mi % 8 == 3) {
                    it.tag = "flip s";
                    it.sig[40] ^= 4;
                    try list.append(gpa, it);
                }
            }
        }
        for (honest[0..32], 0..) |h, i| {
            var it = h;
            it.tag = "flip R";
            it.sig[i % 32] ^= @as(u8, 1) << @intCast(i % 8);
            try list.append(gpa, it);
            it = h;
            it.tag = "flip s";
            it.sig[32 + i % 32] ^= @as(u8, 1) << @intCast(i % 8);
            try list.append(gpa, it);
            it = h;
            it.tag = "flip pk";
            it.pk[i % 32] ^= @as(u8, 1) << @intCast(i % 8);
            try list.append(gpa, it);
            it = h;
            it.tag = "other msg";
            it.msg_buf[0] ^= 1;
            if (it.msg_len == 0) it.msg_len = 1;
            try list.append(gpa, it);
            it = h;
            it.tag = "other key";
            it.pk = honest[(i + 1) % honest.len].pk;
            try list.append(gpa, it);
            // s + l: the same residue, not canonical
            it = h;
            it.tag = "s + l";
            const s_int = std.mem.readInt(u256, it.sig[32..64], .little);
            std.mem.writeInt(u256, it.sig[32..64], s_int + ed.l_int, .little);
            try list.append(gpa, it);
            it = h;
            it.tag = "s high bits";
            it.sig[63] |= 0xe0;
            try list.append(gpa, it);
            it = h;
            it.tag = "s = 0";
            it.sig[32..64].* = @splat(0);
            try list.append(gpa, it);
            it = h;
            it.tag = "s = l";
            it.sig[32..64].* = ed.l_bytes;
            try list.append(gpa, it);
            it = h;
            it.tag = "s = l - 1";
            std.mem.writeInt(u256, it.sig[32..64], ed.l_int - 1, .little);
            try list.append(gpa, it);
            it = h;
            it.tag = "R negated";
            it.sig[31] ^= 0x80;
            try list.append(gpa, it);
            it = h;
            it.tag = "R = identity";
            it.sig[0..32].* = tenc[0];
            try list.append(gpa, it);
            it = h;
            it.tag = "pk small order";
            it.pk = tenc[i % tenc.len];
            try list.append(gpa, it);
        }

        // Encodings that do not decode, as key and as R.
        {
            var n_bad: usize = 0;
            var y: [32]u8 = undefined;
            while (n_bad < 12) {
                rnd.bytes(&y);
                if (ed.decompress(&y) != null) continue;
                const h = honest[n_bad % honest.len];
                var it = h;
                it.tag = "pk not on curve";
                it.pk = y;
                try list.append(gpa, it);
                // the key error comes first, whatever else is wrong
                it.tag = "pk not on curve, s not canonical";
                it.sig[32..64].* = @splat(0xff);
                try list.append(gpa, it);
                it = h;
                it.tag = "R not on curve";
                it.sig[0..32].* = y;
                try list.append(gpa, it);
                it.tag = "R not on curve, pk not on curve";
                it.pk = y;
                try list.append(gpa, it);
                n_bad += 1;
            }
        }
        for ([_]u8{ 0x00, 0xff }) |fillb| {
            var it: Item = .{ .pk = @splat(fillb), .sig = @splat(fillb), .tag = "constant bytes" };
            it.setMsg("", d32);
            try list.append(gpa, it);
            it.pk = honest[0].pk;
            try list.append(gpa, it);
            it = honest[0];
            it.tag = "constant pk";
            it.pk = @splat(fillb);
            try list.append(gpa, it);
        }

        // Mixed-order keys and nonces: A = [a]B + T, R = [r]B + T'. Valid under the cofactored
        // equation only. Several signatures share each key (the batch may merge them).
        for (0..2) |ki| {
            var ab: [64]u8 = undefined;
            rnd.bytes(&ab);
            const a = scalar.reduce64(ab);
            for (tors, 0..) |ta, ti| {
                const pk = ed.mulBaseCT(&a).add(ta).toBytes();
                for (tors, 0..) |tr, tj| {
                    if (ki == 1 and (ti + tj) % 3 != 0) continue;
                    var rb: [64]u8 = undefined;
                    rnd.bytes(&rb);
                    const r = scalar.reduce64(rb);
                    var it: Item = .{ .pk = pk, .sig = undefined, .tag = "mixed order" };
                    var m: [16]u8 = undefined;
                    rnd.bytes(&m);
                    it.setMsg(&m, d32);
                    it.sig[0..32].* = ed.mulBaseCT(&r).add(tr).toBytes();
                    const k = hashK(it.sig[0..32], &pk, it.msg());
                    it.sig[32..64].* = scalar.mulAdd(k, a, r);
                    try list.append(gpa, it);
                    if (tj % 4 == 1) {
                        // s + 1: off by B, not a torsion point
                        it.tag = "mixed order, s + 1";
                        const one: [32]u8 = .{1} ++ @as([31]u8, @splat(0));
                        it.sig[32..64].* = scalar.add(it.sig[32..64].*, one);
                        try list.append(gpa, it);
                    }
                }
            }
        }

        // Small-order keys in every encoding with a full-size chain: R = [s]B + T'.
        for (tenc, 0..) |a, i| {
            for (0..3) |j| {
                var sb: [64]u8 = undefined;
                rnd.bytes(&sb);
                const s = scalar.reduce64(sb);
                var it: Item = .{ .pk = a, .sig = undefined, .tag = "small-order key" };
                it.setMsg("small order", d32);
                it.sig[0..32].* = ed.mulBaseCT(&s).add(tors[(i + 3 * j) % 8]).toBytes();
                it.sig[32..64].* = s;
                try list.append(gpa, it);
                if (j == 2) {
                    it.tag = "small-order key, R off by B";
                    it.sig[0..32].* = ed.mulBaseCT(&s).add(ed.basepoint).toBytes();
                    try list.append(gpa, it);
                }
            }
        }

        const items = try list.toOwnedSlice(gpa);
        errdefer gpa.free(items);
        const want = try gpa.alloc(Verdict, items.len);
        for (items, want) |*it, *w| w.* = refVerdict(it);
        return .{ .gpa = gpa, .items = items, .want = want, .fill = honest[45..48].* };
    }
};

fn fail(path: Path, what: []const u8, i: usize, it: *const Item, want: Verdict, got: Verdict) error{VerdictMismatch} {
    std.debug.print("path {s}: {s} item {d} ({s}): want {s}, got {s}\n  pk  {x}\n  sig {x}\n  msg {x}\n", .{ path.name, what, i, it.tag, want.truthName(), got.truthName(), &it.pk, &it.sig, it.msg() });
    return error.VerdictMismatch;
}

fn batchItem(it: *const Item) ed.BatchItem {
    return .{ .pk = &it.pk, .msg = it.msg(), .sig = &it.sig };
}

fn asVerdict(ok: bool) Verdict {
    return if (ok) .valid else bad_sig;
}

/// Every single-signature entry point, item by item.
pub fn checkSingles(path: Path, set: *const Set) !void {
    for (set.items, set.want, 0..) |*it, w, i| {
        const got = ed.verify(&it.pk, it.msg(), &it.sig);
        if (!std.meta.eql(got, w)) return fail(path, "verify", i, it, w, got);
        const got_sl = ed.verifySlices(&it.pk, it.msg(), &it.sig);
        if (!std.meta.eql(got_sl, w)) return fail(path, "verifySlices", i, it, w, got_sl);
        // the entry points that take a decoded key: only the signature verdict is theirs
        const a = ed.decompress(&it.pk) orelse continue;
        const got_dec = asVerdict(ed.verifyDecoded(a, ed.decompress(it.sig[0..32]), &it.pk, it.msg(), &it.sig));
        if (!std.meta.eql(got_dec, w)) return fail(path, "verifyDecoded", i, it, w, got_dec);
        const pk = ed.PublicKey.fromBytes(&it.pk).?;
        const got_pk = asVerdict(pk.verify(it.msg(), &it.sig));
        if (!std.meta.eql(got_pk, w)) return fail(path, "PublicKey.verify", i, it, w, got_pk);
    }
}

/// The batch verdict per item: each item inside a batch of honest signatures, first and last
/// (four items, so the shared chain runs and not the tiny-batch single checks).
pub fn checkBatchPerItem(path: Path, set: *const Set, scratch: []u8) !void {
    const f = &set.fill;
    for (set.items, set.want, 0..) |*it, w, i| {
        const want_b = asVerdict(w == .valid);
        const first = [_]ed.BatchItem{ batchItem(it), batchItem(&f[0]), batchItem(&f[1]), batchItem(&f[2]) };
        const last = [_]ed.BatchItem{ batchItem(&f[0]), batchItem(&f[1]), batchItem(&f[2]), batchItem(it) };
        const g0 = ed.verifyBatch(&first, scratch);
        if (!std.meta.eql(g0, want_b)) return fail(path, "batch (item first)", i, it, want_b, g0);
        const g1 = ed.verifyBatch(&last, scratch);
        if (!std.meta.eql(g1, want_b)) return fail(path, "batch (item last)", i, it, want_b, g1);
    }
}

/// Whole batches: every valid item of the set in one batch (repeated keys, small-order and
/// mixed-order points, several chunks), prefixes of every decode-group shape, and each of those
/// with one invalid item put in.
pub fn checkBatchSets(path: Path, set: *const Set, gpa: std.mem.Allocator, scratch: []u8) !void {
    var good: std.ArrayList(ed.BatchItem) = .empty;
    defer good.deinit(gpa);
    var bad: std.ArrayList(usize) = .empty;
    defer bad.deinit(gpa);
    for (set.items, set.want, 0..) |*it, w, i| {
        if (w == .valid) try good.append(gpa, batchItem(it)) else try bad.append(gpa, i);
    }
    // more than two full chunks: the valid items again from the start (a repeated signature is
    // one more valid item, and one more repeat of its key)
    const n_distinct = good.items.len;
    try std.testing.expect(n_distinct > ed.batch_chunk_best);
    var rep: usize = 0;
    while (good.items.len < 2 * ed.batch_chunk_best + 61) : (rep += 1) try good.append(gpa, good.items[(rep * 7) % n_distinct]);
    const all = good.items;
    const tmp = try gpa.alloc(ed.BatchItem, all.len + 1);
    defer gpa.free(tmp);
    const sizes = [_]usize{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 31, 64, 65, 200, ed.batch_chunk_best - 1, ed.batch_chunk_best, ed.batch_chunk_best + 1, ed.batch_chunk_best + 2, ed.batch_chunk_best + 3, all.len };
    var which: usize = 0;
    for (sizes) |n| {
        // a window that moves through the set, so every kind of item meets every group shape
        const off = if (n == all.len) 0 else (which * 37) % (all.len - n);
        const win = all[off .. off + n];
        const g = ed.verifyBatch(win, scratch);
        if (g != .valid) {
            std.debug.print("path {s}: batch of {d} valid items at {d} rejected\n", .{ path.name, n, off });
            return error.VerdictMismatch;
        }
        // one invalid item at three positions
        for ([_]usize{ 0, n / 2, n }) |pos| {
            const bi = bad.items[which % bad.items.len];
            which += 1;
            @memcpy(tmp[0..pos], win[0..pos]);
            tmp[pos] = batchItem(&set.items[bi]);
            @memcpy(tmp[pos + 1 .. n + 1], win[pos..]);
            const gb = ed.verifyBatch(tmp[0 .. n + 1], scratch);
            if (!std.meta.eql(gb, bad_sig)) return fail(path, "batch with one invalid item", bi, &set.items[bi], bad_sig, gb);
        }
    }
    // a small scratch (three items per chunk) and no scratch at all give the same verdicts
    for ([_]usize{ 3 * ed.batch_scratch_per_item + 16, 0 }) |len| {
        const n = 41;
        if (ed.verifyBatch(all[0..n], scratch[0..len]) != .valid) return error.VerdictMismatch;
        @memcpy(tmp[0..n], all[0..n]);
        tmp[n] = batchItem(&set.items[bad.items[0]]);
        if (ed.verifyBatch(tmp[0 .. n + 1], scratch[0..len]) == .valid) return error.VerdictMismatch;
    }
}

test "exactness: the generated set covers every verdict and every edge class" {
    const set = try Set.init(std.testing.allocator);
    defer set.deinit();
    var n_valid: usize = 0;
    var n_bad_sig: usize = 0;
    var n_bad_pk: usize = 0;
    for (set.items, set.want) |*it, w| {
        switch (w) {
            .valid => n_valid += 1,
            .invalid => |r| switch (r) {
                .verify_invalid_signature => n_bad_sig += 1,
                .pk_invalid_input => n_bad_pk += 1,
                else => return error.UnexpectedVerdict,
            },
        }
        // what each class must be, independent of the reference code
        const must_be_valid = std.mem.eql(u8, it.tag, "zip215") or std.mem.eql(u8, it.tag, "honest") or
            std.mem.eql(u8, it.tag, "mixed order") or std.mem.eql(u8, it.tag, "small-order key");
        if (must_be_valid) try std.testing.expect(w == .valid);
        const must_be_bad_pk = std.mem.startsWith(u8, it.tag, "pk not on curve") or std.mem.eql(u8, it.tag, "R not on curve, pk not on curve");
        if (must_be_bad_pk) try std.testing.expect(std.meta.eql(w, bad_pk));
        for ([_][]const u8{ "flip s", "other msg", "other key", "s + l", "s high bits", "s = 0", "s = l", "s = l - 1", "R negated", "R = identity", "R not on curve", "mixed order, s + 1", "small-order key, R off by B", "pk small order" }) |t| {
            if (std.mem.eql(u8, it.tag, t)) try std.testing.expect(std.meta.eql(w, bad_sig));
        }
    }
    try std.testing.expect(n_valid >= 196 + 48 + 192 + 64 + 42);
    try std.testing.expect(n_bad_sig > 300);
    try std.testing.expect(n_bad_pk >= 24);
    // the 14 small-order encodings are distinct and all decode
    const tenc = torsionEncodings();
    for (tenc, 0..) |a, i| {
        try std.testing.expect(ed.decompress(&a) != null);
        try std.testing.expect(ed.decompress(&a).?.mulByCofactor().isIdentity());
        for (tenc[0..i]) |b| try std.testing.expect(!std.mem.eql(u8, &a, &b));
    }
}

test "exactness: every verifier path gives the reference verdict, item by item, single and batch" {
    const gpa = std.testing.allocator;
    const set = try Set.init(gpa);
    defer set.deinit();
    const scratch = try gpa.alloc(u8, (2 * ed.batch_chunk_best + 64) * ed.batch_scratch_per_item + 64);
    defer gpa.free(scratch);
    const x4 = @import("ed25519_avx2.zig");
    const ifma_single = @import("ed25519_ifma.zig").enabled;
    // Every kernel tier this binary carries and this CPU runs: the build's own code, then on
    // x86-64 the avx2 and avx512 kernel objects (src/cpu_kernels.zig), each forced in turn.
    defer cpu.restoreTier();
    var tiers_run: usize = 0;
    for (std.enums.values(cpu.Tier)) |tier| {
        if (!cpu.forceTier(tier)) continue;
        tiers_run += 1;
        // the counters below live in this compilation: they see the code only when it runs
        // here and not in a kernel object
        const local = tier == cpu.native_tier;
        for (paths) |p| {
            const was = p.enter();
            defer was.restore();
            const chains0 = x4.test_chains.load(.monotonic);
            const keyed0 = ed.test_keyed.chunks.load(.monotonic);
            const merged0 = ed.test_keyed.merged.load(.monotonic);
            const cached0 = ed.test_keyed.cached.load(.monotonic);
            const pk0 = fast.pkCacheStats().ed25519;
            try checkSingles(p, &set);
            try checkBatchPerItem(p, &set, scratch);
            try checkBatchSets(p, &set, gpa, scratch);
            // each switch reached the code it selects, and only that code
            const chains = x4.test_chains.load(.monotonic) - chains0;
            const keyed = ed.test_keyed.chunks.load(.monotonic) - keyed0;
            const merged = ed.test_keyed.merged.load(.monotonic) - merged0;
            const cached = ed.test_keyed.cached.load(.monotonic) - cached0;
            const pk = fast.pkCacheStats().ed25519;
            if (local) {
                try std.testing.expectEqual(p.vec4 != .off, chains > 0);
                // the AVX-512 IFMA kernel keeps the single chain; everywhere else vec4 moves it
                if (p.vec4 != .off and !ifma_single) try std.testing.expect(chains > set.items.len);
                try std.testing.expectEqual(p.vec4 != .off or p.batch_merge or p.batch_cache, keyed > 0);
                try std.testing.expectEqual(p.batch_merge, merged > 0);
                try std.testing.expectEqual(p.batch_cache, cached > 0);
            }
            // the cache is in this compilation whatever tier runs the batch
            try std.testing.expectEqual(p.batch_cache, pk.hits > pk0.hits);
            try std.testing.expectEqual(p.batch_cache, pk.inserts > pk0.inserts);
        }
    }
    try std.testing.expect(tiers_run >= 1);
}

test "exactness: a path leaves the switches as it found them" {
    const before = Path.Saved.now();
    defer before.restore();
    // switches set by something else: the environment, an outer path
    const outer = [_]Path.Saved{
        .{ .vec4 = .force, .batch_keys = .{ .merge = true }, .fast_cfg = .{ .pk_cache = true, .zk_cache = true, .multisig_batch_min = 4 } },
        .{ .vec4 = .on, .batch_keys = .{ .cache = true, .merge = true }, .fast_cfg = .{ .ed_verified_cache = true } },
        .{ .vec4 = .off, .batch_keys = .{ .cache = true }, .fast_cfg = fast.all_on },
        .{ .vec4 = .off, .batch_keys = .{}, .fast_cfg = .{} },
    };
    for (outer) |o| {
        o.restore();
        try std.testing.expect(std.meta.eql(o, Path.Saved.now()));
        for (paths) |p| {
            const was = p.enter();
            try std.testing.expect(std.meta.eql(o, was));
            // inside: the path's own switches and nothing else
            try std.testing.expectEqual(p.vec4, cpu.edVec4());
            try std.testing.expect(std.meta.eql(ed.batchKeys(), ed.BatchKeys{ .cache = p.batch_cache, .merge = p.batch_merge }));
            try std.testing.expect(std.meta.eql(fast.config(), fast.Config{ .pk_cache = p.pk_cache }));
            was.restore();
            try std.testing.expect(std.meta.eql(o, Path.Saved.now()));
        }
    }
}

test "exactness: vec4 'on' covers the avx2 tier only, 'force' every tier" {
    const before = cpu.edVec4();
    defer cpu.setEdVec4(before);
    cpu.setEdVec4(.on);
    const is_x86 = @import("builtin").cpu.arch == .x86_64;
    try std.testing.expectEqual(is_x86 and cpu.tier() == .avx2, cpu.edVec4Live());
    cpu.setEdVec4(.force);
    try std.testing.expect(cpu.edVec4Live());
    cpu.setEdVec4(.off);
    try std.testing.expect(!cpu.edVec4Live());
}

test "exactness: the batch key cache serves hits, remembers keys that do not decode, and is unused while sig.fast's cache is off" {
    const gpa = std.testing.allocator;
    const set = try Set.init(gpa);
    defer set.deinit();
    const scratch = try gpa.alloc(u8, 64 * ed.batch_scratch_per_item + 64);
    defer gpa.free(scratch);
    const on: Path = .{ .name = "batch cache", .batch_cache = true, .pk_cache = true };
    const was = on.enter();
    defer was.restore();
    var good: [40]ed.BatchItem = undefined;
    var ng: usize = 0;
    var bad_key: ?ed.BatchItem = null;
    for (set.items, set.want) |*it, w| {
        if (w == .valid and ng < good.len and std.mem.eql(u8, it.tag, "honest")) {
            good[ng] = batchItem(it);
            ng += 1;
        }
        if (bad_key == null and std.meta.eql(w, bad_pk)) bad_key = batchItem(it);
    }
    try std.testing.expectEqual(good.len, ng);
    // first pass: every distinct key is a miss and is stored; second pass: every one is a hit
    const s0 = fast.pkCacheStats().ed25519;
    try std.testing.expectEqual(Verdict.valid, ed.verifyBatch(&good, scratch));
    const s1 = fast.pkCacheStats().ed25519;
    try std.testing.expect(s1.misses > s0.misses and s1.inserts > s0.inserts);
    try std.testing.expectEqual(s0.hits, s1.hits);
    try std.testing.expectEqual(Verdict.valid, ed.verifyBatch(&good, scratch));
    const s2 = fast.pkCacheStats().ed25519;
    try std.testing.expectEqual(s1.misses, s2.misses);
    try std.testing.expectEqual(s1.inserts, s2.inserts);
    try std.testing.expectEqual(s1.inserts - s0.inserts, s2.hits - s1.hits);
    // every cached point is the decoder's point for those bytes
    for (good) |g| {
        const c = fast.edGetKey(g.pk).?.?;
        try std.testing.expect(eqlPoint(c, ed.decompress(g.pk).?));
    }
    // a key that does not decode: rejected cold, stored as such, rejected again from the cache
    var mixed = good[0..5].*;
    mixed[3] = bad_key.?;
    try std.testing.expect(std.meta.eql(ed.verifyBatch(&mixed, scratch), bad_sig));
    try std.testing.expect(fast.edGetKey(bad_key.?.pk).? == null);
    const s3 = fast.pkCacheStats().ed25519;
    try std.testing.expect(std.meta.eql(ed.verifyBatch(&mixed, scratch), bad_sig));
    try std.testing.expect(fast.pkCacheStats().ed25519.hits > s3.hits);
    // sig.fast's cache off: the batch switch alone reads nothing
    fast.configure(.{});
    const s4 = fast.pkCacheStats().ed25519;
    try std.testing.expectEqual(Verdict.valid, ed.verifyBatch(&good, scratch));
    const s5 = fast.pkCacheStats().ed25519;
    try std.testing.expectEqual(s4.hits + s4.misses + s4.inserts, s5.hits + s5.misses + s5.inserts);
}

// ---------------------------------------------------------------------------------------------
// Repeated keys. With the batch key merge on, the items of a chunk that share a key share one
// table and one summed scalar, so the things to rule out are a bad item hidden by its key's other
// items, and errors of two items that cancel in a sum.

const rep_per = 12;
const rep_n = 2 * rep_per;

/// A batch that must be rejected: the items in order, and the positions of the altered ones.
const BadBatch = struct {
    what: []const u8,
    items: [rep_n]Item,
    len: u8 = rep_n,
    bad: [3]u8 = undefined,
    n_bad: u8 = 0,

    fn mark(b: *BadBatch, pos: usize) *Item {
        b.bad[b.n_bad] = @intCast(pos);
        b.n_bad += 1;
        return &b.items[pos];
    }
};

/// s + delta or s - delta mod l: still canonical, and off by a multiple of B.
fn shiftS(it: *Item, delta: [32]u8, minus: bool) void {
    const s: [32]u8 = it.sig[32..64].*;
    it.sig[32..64].* = if (minus) scalar.sub(s, delta) else scalar.add(s, delta);
}

fn arranged(base: *const [rep_n]Item, ord: *const [rep_n]u8) [rep_n]Item {
    var o: [rep_n]Item = undefined;
    for (ord, &o) |b, *x| x.* = base[b];
    return o;
}

fn posOf(ord: *const [rep_n]u8, b: usize) usize {
    return std.mem.indexOfScalar(u8, ord, @intCast(b)).?;
}

test "exactness: repeated keys: a bad signature at every position, and same-key errors that cancel under equal coefficients, are rejected on every path, cold and warm" {
    const gpa = std.testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x7265_7065_6174);
    const rnd = prng.random();
    // two senders, twelve signatures each: base[0..12] sender 0, base[12..24] sender 1
    var base: [rep_n]Item = undefined;
    for (0..2) |ki| {
        var seed: [32]u8 = undefined;
        rnd.bytes(&seed);
        const kp = ed.KeyPair.fromSeed(&seed);
        for (0..rep_per) |mi| {
            const it = &base[ki * rep_per + mi];
            it.* = .{ .pk = kp.pk, .sig = undefined, .tag = "honest" };
            var m: [40]u8 = undefined;
            rnd.bytes(&m);
            it.setMsg(m[0 .. 8 + ki * rep_per + mi], false);
            it.sig = kp.sign(it.msg());
            try std.testing.expect(refVerdict(it) == .valid);
        }
    }
    // Three orders: each sender's items together, the senders alternating, and shuffled. A key's
    // first occurrence (the item whose table the merge keeps) lands on different positions.
    var orders: [3][rep_n]u8 = undefined;
    for (0..rep_n) |i| {
        orders[0][i] = @intCast(i);
        orders[1][i] = @intCast((i % 2) * rep_per + i / 2);
        orders[2][i] = @intCast(i);
    }
    rnd.shuffle(u8, &orders[2]);
    try std.testing.expect(orders[2][0] != 0 or orders[2][1] != 1);
    const one: [32]u8 = .{1} ++ @as([31]u8, @splat(0));
    const two: [32]u8 = .{2} ++ @as([31]u8, @splat(0));

    var cases: std.ArrayList(BadBatch) = .empty;
    defer cases.deinit(gpa);
    for (&orders, 0..) |*ord, oi| {
        const good = arranged(&base, ord);
        // One bad signature at every position: as the first occurrence of its key and as a
        // later one. Its s off by a bit (the equation fails), then its message changed (the
        // key's scalar is wrong).
        for (0..rep_n) |pos| {
            var c: BadBatch = .{ .what = "one s changed", .items = good };
            c.mark(pos).sig[40] ^= 4;
            try cases.append(gpa, c);
            c = .{ .what = "one message changed", .items = good };
            c.mark(pos).msg_buf[0] ^= 1;
            try cases.append(gpa, c);
        }
        // Two signatures of ONE key, s - a on one and s + a on the other. Each is invalid alone;
        // with equal coefficients the two errors would cancel in the sum of z_i s_i, and with the
        // key's terms merged carelessly they would cancel there. Every pair of sender 0 in the
        // alternating order with a = 1; a third of the pairs in the other orders.
        var pair_no: usize = 0;
        for (0..rep_per) |i| for (i + 1..rep_per) |j| {
            pair_no += 1;
            const pi = posOf(ord, i);
            const pj = posOf(ord, j);
            if (oi == 1 or pair_no % 3 == oi) {
                var c: BadBatch = .{ .what = "same key: s - 1 and s + 1", .items = good };
                shiftS(c.mark(pi), one, oi != 2);
                shiftS(c.mark(pj), one, oi == 2);
                try cases.append(gpa, c);
            }
            if (pair_no % 3 == oi) {
                // s - a and s + a for a random a
                var ab: [64]u8 = undefined;
                rnd.bytes(&ab);
                const a = scalar.reduce64(ab);
                var c: BadBatch = .{ .what = "same key: s - a and s + a", .items = good };
                shiftS(c.mark(pi), a, true);
                shiftS(c.mark(pj), a, false);
                try cases.append(gpa, c);
                // the two s values exchanged: the sum of s over the key is unchanged
                c = .{ .what = "same key: s exchanged", .items = good };
                const si: [32]u8 = good[pi].sig[32..64].*;
                c.mark(pi).sig[32..64].* = good[pj].sig[32..64].*;
                c.mark(pj).sig[32..64].* = si;
                try cases.append(gpa, c);
            }
        };
        // Three of one key: +1, +1, -2.
        for ([_][3]usize{ .{ 0, 1, 2 }, .{ 0, 5, 11 }, .{ 3, 4, 10 }, .{ 9, 10, 11 } }) |t| {
            var c: BadBatch = .{ .what = "same key: s + 1, s + 1, s - 2", .items = good };
            shiftS(c.mark(posOf(ord, t[0])), one, false);
            shiftS(c.mark(posOf(ord, t[1])), one, false);
            shiftS(c.mark(posOf(ord, t[2])), two, true);
            try cases.append(gpa, c);
        }
        // Two keys, s - 1 on one sender's item and s + 1 on the other's: the base point term
        // is shared by the whole chunk.
        for (0..4) |k| {
            var c: BadBatch = .{ .what = "two keys: s - 1 and s + 1", .items = good };
            shiftS(c.mark(posOf(ord, 3 * k)), one, true);
            shiftS(c.mark(posOf(ord, rep_per + (5 * k + oi) % rep_per)), one, false);
            try cases.append(gpa, c);
        }
    }
    // One sender alone (the whole chunk merges into one table): every pair, and the smallest
    // batch that runs the chain (three items).
    {
        var solo: [rep_n]Item = undefined;
        solo[0..rep_per].* = base[0..rep_per].*;
        for (0..rep_per) |i| for (i + 1..rep_per) |j| {
            var c: BadBatch = .{ .what = "one sender: s - 1 and s + 1", .items = solo, .len = rep_per };
            shiftS(c.mark(i), one, (i + j) % 2 == 0);
            shiftS(c.mark(j), one, (i + j) % 2 != 0);
            try cases.append(gpa, c);
        };
        for ([_][2]usize{ .{ 0, 1 }, .{ 0, 2 }, .{ 1, 2 } }) |pr| {
            var c: BadBatch = .{ .what = "three of one sender: s - 1 and s + 1", .items = solo, .len = 3 };
            shiftS(c.mark(pr[0]), one, true);
            shiftS(c.mark(pr[1]), one, false);
            try cases.append(gpa, c);
        }
        for (0..3) |pos| {
            var c: BadBatch = .{ .what = "three of one sender: one s changed", .items = solo, .len = 3 };
            c.mark(pos).sig[40] ^= 4;
            try cases.append(gpa, c);
        }
    }
    // What the reference says: every altered item is invalid on its own, with a canonical s and
    // an R that decodes (so it is the equation that fails, in the single check and in the batch),
    // and every other item is valid.
    for (cases.items) |*c| {
        try std.testing.expect(c.n_bad >= 1);
        for (c.items[0..c.len], 0..) |*it, pos| {
            const altered = std.mem.indexOfScalar(u8, c.bad[0..c.n_bad], @intCast(pos)) != null;
            try std.testing.expect(std.meta.eql(refVerdict(it), if (altered) bad_sig else Verdict.valid));
            try std.testing.expect(std.mem.readInt(u256, it.sig[32..64], .little) < ed.l_int);
            try std.testing.expect(ed.decompress(it.sig[0..32]) != null);
        }
    }
    try std.testing.expect(cases.items.len > 300);

    const scratch = try gpa.alloc(u8, (rep_n + 1) * ed.batch_scratch_per_item + 64);
    defer gpa.free(scratch);
    var bi: [rep_n]ed.BatchItem = undefined;
    defer cpu.restoreTier();
    var tiers_run: usize = 0;
    for (std.enums.values(cpu.Tier)) |tier| {
        if (!cpu.forceTier(tier)) continue;
        tiers_run += 1;
        const local = tier == cpu.native_tier;
        for (paths) |p| {
            const was = p.enter();
            defer was.restore();
            const merged0 = ed.test_keyed.merged.load(.monotonic);
            const cached0 = ed.test_keyed.cached.load(.monotonic);
            // cold (the caches cleared just before), then warm where the path has a cache
            const passes: usize = if (p.batch_cache) 2 else 1;
            // the unaltered batches are accepted
            for (&orders) |*ord| {
                const good = arranged(&base, ord);
                for (&good, &bi) |*it, *b| b.* = batchItem(it);
                for ([_]usize{ rep_n, rep_n - 1, rep_per, 3 }) |len| {
                    fast.clearCaches();
                    for (0..passes) |pass| {
                        if (ed.verifyBatch(bi[0..len], scratch) != .valid) {
                            std.debug.print("path {s}: {d} valid repeated-key items rejected (pass {d})\n", .{ p.name, len, pass });
                            return error.VerdictMismatch;
                        }
                    }
                }
            }
            for (cases.items, 0..) |*c, ci| {
                for (c.items[0..c.len], bi[0..c.len]) |*it, *b| b.* = batchItem(it);
                fast.clearCaches();
                for (0..passes) |pass| {
                    const got = ed.verifyBatch(bi[0..c.len], scratch);
                    if (!std.meta.eql(got, bad_sig)) {
                        std.debug.print("path {s}: repeated-key case {d} ({s}, {s} cache): want {s}, got {s}\n", .{ p.name, ci, c.what, if (pass == 0) "cold" else "warm", bad_sig.truthName(), got.truthName() });
                        return error.VerdictMismatch;
                    }
                }
                // and each altered item alone
                for (c.bad[0..c.n_bad]) |pos| {
                    const it = &c.items[pos];
                    const got = ed.verify(&it.pk, it.msg(), &it.sig);
                    if (!std.meta.eql(got, bad_sig)) return fail(p, "verify (repeated key)", ci, it, bad_sig, got);
                }
            }
            // the switches reached these batches
            if (local) {
                try std.testing.expectEqual(p.batch_merge, ed.test_keyed.merged.load(.monotonic) - merged0 > cases.items.len);
                try std.testing.expectEqual(p.batch_cache, ed.test_keyed.cached.load(.monotonic) - cached0 > cases.items.len);
            }
        }
    }
    try std.testing.expect(tiers_run >= 1);
}
