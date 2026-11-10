//! Ed25519 point arithmetic four field elements at a time on 32-bit vector lanes: the AVX2 twin
//! of ed25519_ifma.zig, on `fe25519x4.Fe4` (radix 2^25.5, ten limbs, one `@Vector(4, u32)` per
//! limb, products through `vpmuludq`).
//!
//! Design:
//!
//!   - A point (X, Y, Z, T) is one `Fe4`: lane 0 is X, lane 1 Y, lane 2 Z, lane 3 T. One `Fe4.mul`
//!     is four field multiplications. Doubling is one squaring pass and one multiplication pass,
//!     an addition with a cached point two multiplication passes; the lane shuffles, blends and
//!     32-bit additions between them are cheap next to the passes.
//!   - Formulas: the extended twisted Edwards (a = -1) ones of Hisil, Wong, Carter and Dawson in
//!     the parallel arrangement curve25519-dalek's AVX2 backend uses. They compute the same
//!     group element as the scalar formulas of ed25519.zig (a doubling gives all four
//!     coordinates negated, which is the same projective point), so verdicts are identical.
//!   - A cached point is c * (Y - X, Y + X, 2Z, 2dT) for any nonzero c: a common factor scales
//!     all four coordinates of the sum, which is the same point. Table entries use c = 121666
//!     (then c * 2d = -243330 and the whole conversion is four multiplications by small
//!     constants); the comptime base tables use c = 1.
//!   - Limbs are unsigned. A subtraction adds 2p first (`neg2p`). Between passes limbs are not
//!     carried; the bounds below show no 32-bit limb and no 64-bit column can overflow. In Debug
//!     builds every vector add, subtract and multiply is overflow-checked, so the unit tests
//!     (which include every limb at the top of its bound) would trap on a wrong bound.
//!
//! Bounds, in multiples of a carried limb (2^26 for even limbs, 2^25 for odd ones). A carried
//! element (what `Fe4.mul`, `Fe4.sqNeg`, `Fe4.mulSmall` return and what `fromPoint` builds) is at
//! most 1.01. 2p has limbs 2 - epsilon, so `neg2p` needs its input at most 1.99 and returns at
//! most 2. `Fe4.mul(a, b)` needs b at most 3.36 and a * b at most 32; `Fe4.sqNeg` needs its
//! input at most 3.36.
//!   dbl:        squares (X, Y, Z, X + Y), at most 2.02. From the carried squares S1..S4:
//!               S5 = S1 + S2 <= 2.02, S6 = S1 + 2p - S2 <= 3.01, S8 = S6 + 2 S3 <= 5.03,
//!               S9 = S1 + S2 + S4 <= 3.03. The product is (S8, S5, S8, S5) * (S9, S6, S6, S9):
//!               a <= 5.03, b <= 3.03.
//!   addCached:  (Y - X + 2p, Y + X, Z, T) <= 3.01 times a carried cached point; then
//!               E, F <= 3.01 and G, H <= 2.02, and the product is (E, H, G, E) * (F, G, F, H).
//!   toCached:   (Y - X + 2p, Y + X, Z, 2p - T) <= 3.01 times constants below 2^18.
//!
//! Where it runs: `ed25519.checkHalf` (the single-verify chain) and the batch chain use this
//! kernel when the caller passes the vec4 switch (core/cpu.zig `edVec4`, off by default; the
//! AVX-512 IFMA kernel keeps the single chain where it is compiled in). The source is plain
//! `@Vector` code: the AVX2 kernel object lowers it to 256-bit `vpmuludq`, aarch64 to NEON
//! `umull`/`umlal`, baseline x86-64 to SSE2. It is only expected to pay on AVX2 (on an Apple M5
//! one `Fe4.mul` costs 8.7 scalar multiplies; see the microbench in fe25519x4.zig), so "on"
//! means the avx2 tier and "force" means every build and tier (equality runs).
//! Verification is variable time (public inputs), like the scalar verifier.
const std = @import("std");
const ed = @import("ed25519.zig");
const Fe = @import("fe25519.zig").Fe;
const Fe4 = @import("fe25519x4.zig").Fe4;
const cpu = @import("core").cpu;

const V = @Vector(4, u32);

/// Test builds count the chains that ran here, so a test can tell the switch reached the kernel.
pub var test_chains: std.atomic.Value(usize) = .init(0);

pub inline fn countChain() void {
    if (@import("builtin").is_test) _ = test_chains.fetchAdd(1, .monotonic);
}

// ---------------------------------------------------------------------------------------------
// Lane plumbing.

/// (f[p0], f[p1], f[p2], f[p3]) with 0..3 = X, Y, Z, T.
inline fn shuf(f: Fe4, comptime p: [4]i32) Fe4 {
    var o: Fe4 = undefined;
    inline for (0..10) |i| o.l[i] = @shuffle(u32, f.l[i], undefined, p);
    return o;
}

inline fn add(a: Fe4, b: Fe4) Fe4 {
    var o: Fe4 = undefined;
    inline for (0..10) |i| o.l[i] = a.l[i] + b.l[i];
    return o;
}

/// Lanes in m from a, the others from b.
inline fn pick(comptime m: [4]bool, a: Fe4, b: Fe4) Fe4 {
    const k: @Vector(4, bool) = m;
    var o: Fe4 = undefined;
    inline for (0..10) |i| o.l[i] = @select(u32, k, a.l[i], b.l[i]);
    return o;
}

/// The limbs of 2p.
const p2: [10]u32 = blk: {
    var l: [10]u32 = undefined;
    for (&l, 0..) |*x, i| x.* = if (i == 0) (1 << 27) - 38 else if (i % 2 == 0) (1 << 27) - 2 else (1 << 26) - 2;
    break :blk l;
};

/// 2p - a: the negative of a. Needs every limb of a at most the limb of 2p.
inline fn neg2p(a: Fe4) Fe4 {
    var o: Fe4 = undefined;
    inline for (0..10) |i| o.l[i] = @as(V, @splat(p2[i])) - a.l[i];
    return o;
}

const zero4: Fe4 = .{ .l = @splat(@as(V, @splat(0))) };

// ---------------------------------------------------------------------------------------------
// Conversions with deepwave's radix-2^51 `Fe`.

/// The same value with limbs below 2^51 + 2^18 (any input limbs).
fn weak(x: Fe) Fe {
    const m51 = Fe.mask51;
    return .{ .l = .{
        (x.l[0] & m51) + (x.l[4] >> 51) * 19,
        (x.l[1] & m51) + (x.l[0] >> 51),
        (x.l[2] & m51) + (x.l[1] >> 51),
        (x.l[3] & m51) + (x.l[2] >> 51),
        (x.l[4] & m51) + (x.l[3] >> 51),
    } };
}

pub fn fromPoint(p: ed.Point) Fe4 {
    return Fe4.fromFe(.{ weak(p.x), weak(p.y), weak(p.z), weak(p.t) });
}

pub fn toPoint(q: Fe4) ed.Point {
    const f = q.toFe();
    return .{ .x = f[0], .y = f[1], .z = f[2], .t = f[3] };
}

pub fn toProjective(q: Fe4) ed.Projective {
    const f = q.toFe();
    return .{ .x = f[0], .y = f[1], .z = f[2] };
}

/// A cached point as it sits in a table: ten limbs of four u32 lanes (no vector alignment, so
/// tables can live in the batch scratch next to the scalar ones).
pub const Cached = struct {
    l: [10][4]u32,

    pub inline fn load(c: *const Cached) Fe4 {
        var o: Fe4 = undefined;
        inline for (0..10) |i| o.l[i] = c.l[i];
        return o;
    }

    pub inline fn store(f: Fe4) Cached {
        var c: Cached = undefined;
        inline for (0..10) |i| c.l[i] = f.l[i];
        return c;
    }
};

// ---------------------------------------------------------------------------------------------
// Points.

pub const identity: Fe4 = blk: {
    var f: Fe4 = zero4;
    f.l[0] = .{ 0, 1, 1, 0 };
    break :blk f;
};

/// 2P (T of the input unused). Input carried.
pub fn dbl(p: Fe4) Fe4 {
    // (X, Y, Z, X + Y)
    const ta = pick(.{ true, true, true, false }, p, add(shuf(p, .{ 0, 0, 0, 0 }), shuf(p, .{ 1, 1, 1, 1 })));
    // (S1, S2, S3, S4) = (X^2, Y^2, Z^2, -(X + Y)^2)
    const s = ta.sqNeg(.{ false, false, false, true });
    const s1 = shuf(s, .{ 0, 0, 0, 0 });
    const s2 = shuf(s, .{ 1, 1, 1, 1 });
    // (S2, -S2, -S2, S2) + (0, 0, 2 S3, S4) + S1 = (S5, S6, S8, S9)
    const u = pick(.{ true, false, false, true }, s2, neg2p(s2));
    const w = pick(.{ false, false, true, false }, add(s, s), pick(.{ false, false, false, true }, s, zero4));
    const t = add(add(s1, u), w);
    // (S8 S9, S5 S6, S8 S6, S5 S9)
    return shuf(t, .{ 2, 0, 2, 0 }).mul(shuf(t, .{ 3, 1, 1, 3 }));
}

/// P + Q (`sub` false) or P - Q (`sub` true) for Q cached. P carried, Q carried.
inline fn addSub(p: Fe4, q: Fe4, comptime sub: bool) Fe4 {
    // add: (Y - X, Y + X, Z, T); sub: (Y + X, Y - X, Z, T)
    const yy = shuf(p, .{ 1, 1, 2, 3 });
    const xx = shuf(p, .{ 0, 0, 0, 0 });
    const xs = pick(.{ false, false, true, true }, zero4, pick(.{ !sub, sub, false, false }, neg2p(xx), xx));
    const m = add(yy, xs).mul(q);
    // add: m = (mm, pp, zz2, tt2d): E = pp - mm, H = pp + mm, G = zz2 + tt2d, F = zz2 - tt2d
    // sub: m = (pm, mp, zz2, tt2d): E = pm - mp, H = pm + mp, G = zz2 - tt2d, F = zz2 + tt2d
    const a = if (sub) shuf(m, .{ 0, 0, 2, 2 }) else shuf(m, .{ 1, 1, 2, 2 });
    const b = if (sub) shuf(m, .{ 1, 1, 3, 3 }) else shuf(m, .{ 0, 0, 3, 3 });
    // v = (E, H, G, F)
    const v = add(a, pick(if (sub) .{ true, false, true, false } else .{ true, false, false, true }, neg2p(b), b));
    // (E F, H G, G F, E H)
    return shuf(v, .{ 0, 1, 2, 0 }).mul(shuf(v, .{ 3, 2, 3, 1 }));
}

pub fn addCached(p: Fe4, q: Fe4) Fe4 {
    return addSub(p, q, false);
}

pub fn subCached(p: Fe4, q: Fe4) Fe4 {
    return addSub(p, q, true);
}

/// 121666 * (Y - X, Y + X, 2Z, 2dT), carried. 121666 * 2d = -243330. P carried.
pub fn toCached(p: Fe4) Fe4 {
    const yy = shuf(p, .{ 1, 1, 2, 3 });
    const xx = shuf(p, .{ 0, 0, 0, 0 });
    // (Y, Y, Z, -T) + (-X, X, 0, 0)
    const t = add(pick(.{ false, false, false, true }, neg2p(yy), yy), pick(.{ false, false, true, true }, zero4, pick(.{ true, false, false, false }, neg2p(xx), xx)));
    return t.mulSmall(.{ 121666, 121666, 243332, 243330 });
}

/// Odd multiples P, 3P, ..., 15P (width-5 NAF), cached. The same size as the scalar
/// `ed.Naf5Table`, so either kind fits a batch entry.
pub const Table = struct {
    t: [8]Cached,

    pub fn init(tbl: *Table, p: ed.Point) void {
        const q = fromPoint(p);
        const c2 = toCached(dbl(q));
        var cur = q;
        tbl.t[0] = Cached.store(toCached(cur));
        for (1..8) |i| {
            cur = addCached(cur, c2);
            tbl.t[i] = Cached.store(toCached(cur));
        }
    }
};

fn canon(comptime x: Fe) Fe {
    const b = x.toBytes();
    return Fe.fromBytes(&b);
}

fn baseTable(comptime src: [64]ed.AffineNiels) [64]Cached {
    @setEvalBranchQuota(100_000_000);
    var t: [64]Cached = undefined;
    const two: Fe = .{ .l = .{ 2, 0, 0, 0, 0 } };
    for (0..64) |i| {
        const n = src[i];
        // (y - x, y + x, 2, 2dxy): fully reduced, so the limbs are carried
        const f = Fe4.fromFe(.{ canon(n.ymx), canon(n.ypx), two, canon(n.xy2d) });
        for (0..10) |k| t[i].l[k] = f.l[k];
    }
    return t;
}

/// B, 3B, ..., 127B and 2^128 B times the same, cached (affine: Z = 1, c = 1).
pub const base_c: [64]Cached = baseTable(ed.base_table);
pub const base128_c: [64]Cached = baseTable(ed.base128_table);

inline fn half(d: i8) usize {
    return @as(usize, @abs(d)) >> 1;
}

/// acc + [d]P for a NAF digit d over the odd multiples in `tbl`.
pub inline fn step(acc: Fe4, d: i8, tbl: []const Cached) Fe4 {
    if (d > 0) return addCached(acc, tbl[half(d)].load());
    if (d < 0) return subCached(acc, tbl[half(d)].load());
    return acc;
}

/// [a]A + [r]R + [b0]B + [b1](2^128 B) for the half-size NAFs of `ed.checkHalf`: the same chain as
/// `ed.quadMul`, with the point arithmetic on the four-way kernel.
pub fn quadMul(a: ed.Point, na: *const [ed.qn]i8, r: ed.Point, nr: *const [ed.qn]i8, nb0: *const [ed.qn]i8, nb1: *const [ed.qn]i8) ed.Projective {
    var i: usize = ed.qn - 1;
    while (i > 0 and na[i] == 0 and nr[i] == 0 and nb0[i] == 0 and nb1[i] == 0) i -= 1;
    countChain();
    var ta: Table = undefined;
    var tr: Table = undefined;
    ta.init(a);
    tr.init(r);
    var acc = identity;
    while (true) {
        acc = dbl(acc);
        acc = step(acc, na[i], &ta.t);
        acc = step(acc, nr[i], &tr.t);
        acc = step(acc, nb0[i], &base_c);
        acc = step(acc, nb1[i], &base128_c);
        if (i == 0) break;
        i -= 1;
    }
    return toProjective(acc);
}

// ---------------------------------------------------------------------------------------------
// Self-test: the kernel's formulas as field identities at the top of the limb bounds, as code
// that runs in every compilation of this file.
//
// The unit tests below run in the test binary's own compilation. On x86-64 the code that
// verifies signatures is a second and a third compilation of this file, inside the kernel
// objects (src/cpu_kernels.zig: the AVX2 and the AVX-512 lowering), and no test of this file
// reaches those. `selfTest` dispatches like the verifier does, so a unit test forces each tier
// and runs the identities inside that tier's object.
//
// A Debug build traps on a limb or column that overflows. A ReleaseFast build does not: there a
// wrong bound shows as a value that differs from the scalar field's (`SelfTest.failed`) and as
// limbs that differ from a Debug build's (`SelfTest.digest`).

/// `failed`: 0, or the number of the first check that failed (the hundreds name the operation:
/// 1 dbl, 2 addCached, 3 subCached, 4 toCached, 5 Fe4.mul, 6 Fe4.sqNeg, 7 Fe4.mulSmall; a
/// number ending in 0 is the limb bound of the result, 1 to 4 the value of lanes 0 to 3).
/// `digest`: FNV-1a over every limb the kernel returned, in order.
pub const SelfTest = struct { failed: u32, digest: u64 };

/// `selfTestImpl` in the kernel object of the live tier (or in this compilation).
pub fn selfTest(rounds: u32, fault: u32) SelfTest {
    return cpu.call("ed25519_x4_selftest", selfTestImpl, .{ rounds, fault });
}

const SelfRun = struct {
    st: u64,
    digest: u64 = 0xcbf29ce484222325,
    failed: u32 = 0,

    /// splitmix64: the same inputs in every compilation, on every target.
    fn next(s: *SelfRun) u64 {
        s.st +%= 0x9e3779b97f4a7c15;
        var z = s.st;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

    /// Four elements with every limb below `pct` percent of a carried limb (2^26 even, 2^25
    /// odd); with `raise`, limbs 1 and 5 may be 2^18 higher (above what `Fe4.carry` leaves).
    /// kind 0: every limb at the top of that range (minus a few units). kind 1: anywhere in it.
    /// kind 2: per limb and lane zero, the top, one, or anywhere.
    fn gen(s: *SelfRun, kind: u32, comptime pct: u64, comptime raise: bool) Fe4 {
        var f: Fe4 = undefined;
        inline for (0..10) |i| {
            const unit: u64 = if (i % 2 == 0) 1 << 26 else 1 << 25;
            const top: u64 = unit * pct / 100 + (if (raise and (i == 1 or i == 5)) @as(u64, 1 << 18) else 0);
            var l: [4]u32 = undefined;
            for (&l) |*x| {
                const r = s.next();
                const v: u64 = switch (kind) {
                    0 => top - 1 - r % 64,
                    1 => r % top,
                    else => switch ((r >> 60) & 3) {
                        0 => 0,
                        1 => top - 1,
                        2 => 1,
                        else => r % top,
                    },
                };
                x.* = @intCast(v);
            }
            f.l[i] = l;
        }
        return f;
    }

    /// Takes the result into the digest and checks its limbs are carried: even limbs below
    /// 2^26, odd limbs below 2^25, limbs 1 and 5 above that by less than 2^18 and 2^14.
    fn result(s: *SelfRun, id: u32, f: Fe4) void {
        var ok = true;
        inline for (0..10) |i| {
            const l: [4]u32 = f.l[i];
            const lim: u32 = switch (i) {
                1 => (1 << 25) + (1 << 18),
                5 => (1 << 25) + (1 << 14),
                else => if (i % 2 == 0) 1 << 26 else 1 << 25,
            };
            for (l) |x| {
                ok = ok and x < lim;
                var v = x;
                for (0..4) |_| {
                    s.digest = (s.digest ^ (v & 0xff)) *% 0x100000001b3;
                    v >>= 8;
                }
            }
        }
        s.check(id, ok);
    }

    fn check(s: *SelfRun, id: u32, ok: bool) void {
        if (!ok and s.failed == 0) s.failed = id;
    }

    /// The four lanes of `got` against the scalar field's values.
    fn lanes(s: *SelfRun, id: u32, got: Fe4, want: [4]Fe) void {
        s.result(id, got);
        const g = got.toFe();
        for (g, want, 1..) |a, b, j| s.check(id + @as(u32, @intCast(j)), a.eql(b));
    }
};

/// Runs `rounds` rounds of: dbl, addCached, subCached and toCached on carried inputs (a third of
/// the rounds with every limb at the top of the carried bound, limbs 1 and 5 raised), and
/// `Fe4.mul`, `Fe4.sqNeg` and `Fe4.mulSmall` at the widest operands the kernel hands them (5.03
/// by 3.03, 3.36, 3.01 times a carried limb). Each result is compared, lane by lane, with the
/// same polynomial evaluated in the scalar field (fe25519.zig) on the same inputs.
/// `fault` (tests): nonzero flips one bit of the doubling's result in round `fault - 1` before
/// it is compared, to show a wrong limb is reported.
pub fn selfTestImpl(rounds: u32, fault: u32) SelfTest {
    var s: SelfRun = .{ .st = 0x7a75_6920_7834_2073 };
    const c121666 = feOf(121666);
    var round: u32 = 0;
    while (round < rounds) : (round += 1) {
        const kind = round % 3;
        const p = s.gen(kind, 100, true);
        const q = s.gen((round / 3) % 3, 100, true);
        const pf = p.toFe();
        const qf = q.toFe();
        const x = pf[0];
        const y = pf[1];
        const z = pf[2];
        const t = pf[3];
        // dbl: (S8 S9, S5 S6, S8 S6, S5 S9)
        {
            const s1 = x.sq();
            const s2 = y.sq();
            const s3 = z.sq();
            const s4 = x.add(y).sq().neg();
            const s5 = s1.add(s2);
            const s6 = s1.sub(s2);
            const s8 = s6.add(s3).add(s3);
            const s9 = s5.add(s4);
            var got = dbl(p);
            if (fault != 0 and round == fault - 1) got.l[4] ^= @as(V, @splat(1));
            s.lanes(100, got, .{ s8.mul(s9), s5.mul(s6), s8.mul(s6), s5.mul(s9) });
        }
        // addCached, subCached: q = (ymx, ypx, 2z, t2d) of the other point
        inline for (.{ false, true }) |sub| {
            const ypx = y.add(x);
            const ymx = y.sub(x);
            const zz2 = z.mul(qf[2]);
            const tt = t.mul(qf[3]);
            const pp = if (sub) ypx.mul(qf[0]) else ypx.mul(qf[1]);
            const mm = if (sub) ymx.mul(qf[1]) else ymx.mul(qf[0]);
            const e = pp.sub(mm);
            const h = pp.add(mm);
            const gg = if (sub) zz2.sub(tt) else zz2.add(tt);
            const f = if (sub) zz2.add(tt) else zz2.sub(tt);
            s.lanes(if (sub) 300 else 200, if (sub) subCached(p, q) else addCached(p, q), .{ e.mul(f), h.mul(gg), gg.mul(f), e.mul(h) });
        }
        // toCached: 121666 * (y - x, y + x, 2z, 2dt)
        s.lanes(400, toCached(p), .{ y.sub(x).mul(c121666), y.add(x).mul(c121666), z.add(z).mul(c121666), t.mul(Fe.d2).mul(c121666) });
        // Fe4.mul at the widest pair the kernel forms: 5.03 times 3.03
        {
            const a = s.gen(kind, 503, false);
            const b = s.gen(kind, 303, false);
            const af = a.toFe();
            const bf = b.toFe();
            s.lanes(500, a.mul(b), .{ af[0].mul(bf[0]), af[1].mul(bf[1]), af[2].mul(bf[2]), af[3].mul(bf[3]) });
        }
        // Fe4.sqNeg at its limit (3.36), with the kernel's negation pattern and two others
        {
            const f = s.gen(kind, 336, false);
            const ff = f.toFe();
            inline for ([_][4]bool{ .{ false, false, false, true }, .{ true, false, true, false }, .{ false, false, false, false } }, 0..) |neg, k| {
                var want: [4]Fe = undefined;
                inline for (0..4) |j| want[j] = if (neg[j]) ff[j].sq().neg() else ff[j].sq();
                s.lanes(600 + 10 * @as(u32, k), f.sqNeg(neg), want);
            }
        }
        // Fe4.mulSmall with toCached's constants on its widest input (3.01)
        {
            const f = s.gen(kind, 301, false);
            const ff = f.toFe();
            const ks = [4]u32{ 121666, 121666, 243332, 243330 };
            s.lanes(700, f.mulSmall(ks), .{ ff[0].mul(c121666), ff[1].mul(c121666), ff[2].mul(feOf(ks[2])), ff[3].mul(feOf(ks[3])) });
        }
    }
    return .{ .failed = s.failed, .digest = s.digest };
}

fn feOf(k: u64) Fe {
    return .{ .l = .{ k, 0, 0, 0, 0 } };
}

// ---------------------------------------------------------------------------------------------
// Tests (the same source on every target: NEON on aarch64, AVX2 with -Dcpu=x86_64_v3).

fn projEql(p: ed.Projective, q: ed.Projective) bool {
    return p.x.mul(q.z).eql(q.x.mul(p.z)) and p.y.mul(q.z).eql(q.y.mul(p.z));
}

/// Extended points equal as group elements, T included (T/Z must be the same too).
fn pointEql(p: ed.Point, q: ed.Point) bool {
    return projEql(p.toProjective(), q.toProjective()) and p.t.mul(q.z).eql(q.t.mul(p.z)) and
        p.x.mul(p.y).eql(p.z.mul(p.t));
}

fn randPoint(rng: std.Random) ed.Point {
    var s: [32]u8 = undefined;
    rng.bytes(&s);
    s[31] &= 0x0f;
    return ed.mulBaseCT(&s);
}

/// Every limb within `pct` percent of a carried limb.
fn within(f: Fe4, comptime pct: u64) bool {
    inline for (0..10) |i| {
        const unit: u64 = if (i % 2 == 0) 1 << 26 else 1 << 25;
        const l: [4]u32 = f.l[i];
        for (l) |x| if (@as(u64, x) * 100 > unit * pct) return false;
    }
    return true;
}

/// Four field elements with every limb at the top of the carried bound (minus a few units),
/// limbs 1 and 5 included.
fn topLimbs(rng: std.Random) Fe4 {
    var f: Fe4 = undefined;
    inline for (0..10) |i| {
        const unit: u32 = if (i % 2 == 0) 1 << 26 else 1 << 25;
        var l: [4]u32 = undefined;
        // limbs 1 and 5 can sit above 2^25: each takes a carry after it was masked
        // (`Fe4.carry`: limb 1 by less than 2^18, limb 5 by less than 2^14). Both are raised by
        // 2^18 here, above anything a carry leaves.
        for (&l) |*x| x.* = unit - 1 - rng.uintLessThan(u32, 64) + (if (i == 1 or i == 5) @as(u32, 1 << 18) else 0);
        f.l[i] = l;
    }
    return f;
}

test "x4: formulas as field identities on arbitrary and top-of-bound limbs" {
    var prng = std.Random.DefaultPrng.init(0xa2c4);
    const rng = prng.random();
    // the top-of-bound inputs have limbs 1 and 5 above 2^25
    {
        const f = topLimbs(rng);
        const l1: [4]u32 = f.l[1];
        const l5: [4]u32 = f.l[5];
        const l3: [4]u32 = f.l[3];
        for (l1, l5, l3) |a, b, c| try std.testing.expect(a > (1 << 25) + (1 << 17) and b > (1 << 25) + (1 << 17) and c < (1 << 25));
    }
    for (0..600) |round| {
        // not curve points: the formulas are polynomial identities, checked coordinate by
        // coordinate against the same polynomials in the scalar field
        const p = if (round % 3 == 0) topLimbs(rng) else fromPoint(.{ .x = randPoint(rng).x, .y = randPoint(rng).y, .z = randPoint(rng).t, .t = randPoint(rng).x });
        const q = if (round % 2 == 0) topLimbs(rng) else fromPoint(.{ .x = randPoint(rng).y, .y = randPoint(rng).t, .z = randPoint(rng).x, .t = randPoint(rng).y });
        const pf = p.toFe();
        const qf = q.toFe();
        const x = pf[0];
        const y = pf[1];
        const z = pf[2];
        const t = pf[3];
        // dbl: (S8 S9, S5 S6, S8 S6, S5 S9)
        {
            const s1 = x.sq();
            const s2 = y.sq();
            const s3 = z.sq();
            const s4 = x.add(y).sq().neg();
            const s5 = s1.add(s2);
            const s6 = s1.sub(s2);
            const s8 = s6.add(s3).add(s3);
            const s9 = s5.add(s4);
            const got = dbl(p);
            try std.testing.expect(within(got, 101));
            const g = got.toFe();
            try std.testing.expect(g[0].eql(s8.mul(s9)));
            try std.testing.expect(g[1].eql(s5.mul(s6)));
            try std.testing.expect(g[2].eql(s8.mul(s6)));
            try std.testing.expect(g[3].eql(s5.mul(s9)));
            // and against the scalar doubling: every coordinate negated
            const sc = (ed.Projective{ .x = x, .y = y, .z = z }).dbl().toExtended();
            try std.testing.expect(g[0].eql(sc.x.neg()) and g[1].eql(sc.y.neg()) and g[2].eql(sc.z.neg()) and g[3].eql(sc.t.neg()));
        }
        // addCached / subCached against the scalar Niels formulas: q = (ymx, ypx, 2z, t2d)
        {
            const two_z = qf[2];
            const sp: ed.Point = .{ .x = x, .y = y, .z = z, .t = t };
            // the scalar formulas double z * q.z themselves; here q's third lane is already 2z,
            // so compare with the completed point written out
            inline for (.{ false, true }) |sub| {
                const got = if (sub) subCached(p, q) else addCached(p, q);
                try std.testing.expect(within(got, 101));
                const g = got.toFe();
                const ypx = sp.y.add(sp.x);
                const ymx = sp.y.sub(sp.x);
                const zz2 = sp.z.mul(two_z);
                const tt = sp.t.mul(qf[3]);
                const pp = if (sub) ypx.mul(qf[0]) else ypx.mul(qf[1]);
                const mm = if (sub) ymx.mul(qf[1]) else ymx.mul(qf[0]);
                const e = pp.sub(mm);
                const h = pp.add(mm);
                const gg = if (sub) zz2.sub(tt) else zz2.add(tt);
                const f = if (sub) zz2.add(tt) else zz2.sub(tt);
                try std.testing.expect(g[0].eql(e.mul(f)));
                try std.testing.expect(g[1].eql(h.mul(gg)));
                try std.testing.expect(g[2].eql(gg.mul(f)));
                try std.testing.expect(g[3].eql(e.mul(h)));
            }
        }
        // toCached: 121666 * (y - x, y + x, 2z, 2dt)
        {
            const got = toCached(p);
            try std.testing.expect(within(got, 101));
            const g = got.toFe();
            const c = feOf(121666);
            try std.testing.expect(g[0].eql(y.sub(x).mul(c)));
            try std.testing.expect(g[1].eql(y.add(x).mul(c)));
            try std.testing.expect(g[2].eql(z.add(z).mul(c)));
            try std.testing.expect(g[3].eql(t.mul(Fe.d2).mul(c)));
        }
    }
}

test "x4 self-test: the field identities at the top of the limb bounds hold inside every kernel object, limb for limb" {
    const rounds = 96;
    // this compilation (the only one off x86-64)
    const own = selfTestImpl(rounds, 0);
    try std.testing.expectEqual(@as(u32, 0), own.failed);
    // The limbs are pinned. The digest was taken from a Debug build, where every vector add,
    // subtract and multiply is overflow-checked, so no limb or column wrapped on the way to it.
    // A ReleaseFast build has no such checks: equal limbs there (and in every kernel object
    // below) is the value comparison at the bounds.
    try std.testing.expectEqual(@as(u64, 0x4aa7f43ad82870e3), own.digest);
    // the digest covers every round, and a wrong limb is reported
    try std.testing.expect(selfTestImpl(rounds - 1, 0).digest != own.digest);
    for ([_]u32{ 1, 2, 3, rounds }) |fault| {
        const bad = selfTestImpl(rounds, fault);
        try std.testing.expect(bad.failed > 100 and bad.failed < 105);
        try std.testing.expect(bad.digest != own.digest);
    }
    // every kernel tier this binary carries and this CPU runs: on x86-64 the avx2 and avx512
    // objects, each a compilation of this file of its own
    defer cpu.restoreTier();
    var tiers_run: usize = 0;
    for (std.enums.values(cpu.Tier)) |tier| {
        if (!cpu.forceTier(tier)) continue;
        tiers_run += 1;
        const got = selfTest(rounds, 0);
        try std.testing.expectEqual(@as(u32, 0), got.failed);
        try std.testing.expectEqual(own.digest, got.digest);
        const bad = selfTest(rounds, 7);
        try std.testing.expect(bad.failed > 100 and bad.failed < 105);
        try std.testing.expect(bad.digest != own.digest);
    }
    try std.testing.expect(tiers_run >= 1);
}

test "x4: dbl, addCached, subCached and tables match the scalar formulas on points" {
    var prng = std.Random.DefaultPrng.init(0x77);
    const rng = prng.random();
    const exact = @import("ed25519_exact.zig");
    // random points, the eight small-order points and the identity, in every pairing
    var pts: [40]ed.Point = undefined;
    for (pts[0..24]) |*p| p.* = randPoint(rng);
    const tenc = exact.torsionEncodings();
    for (pts[24..38], tenc) |*p, e| p.* = ed.decompress(&e).?;
    pts[38] = ed.Point.identity;
    pts[39] = ed.basepoint;
    for (pts, 0..) |p, i| {
        try std.testing.expect(pointEql(toPoint(dbl(fromPoint(p))), p.dbl()));
        // P + (-P) and P + P through the addition
        const self_c = toCached(fromPoint(p));
        try std.testing.expect(pointEql(toPoint(subCached(fromPoint(p), self_c)), ed.Point.identity));
        try std.testing.expect(pointEql(toPoint(addCached(fromPoint(p), self_c)), p.dbl()));
        for (pts[0..i]) |q| {
            const qc = toCached(fromPoint(q));
            try std.testing.expect(pointEql(toPoint(addCached(fromPoint(p), qc)), p.add(q)));
            try std.testing.expect(pointEql(toPoint(subCached(fromPoint(p), qc)), p.sub(q)));
        }
        // odd multiples
        var tbl: Table = undefined;
        tbl.init(p);
        var acc = p;
        const p2x = p.dbl();
        for (0..8) |k| {
            try std.testing.expect(pointEql(toPoint(addCached(identity, tbl.t[k].load())), acc));
            try std.testing.expect(pointEql(toPoint(subCached(identity, tbl.t[k].load())), acc.neg()));
            acc = acc.add(p2x);
        }
    }
    // affine base entries: entry i is (2i+1)B and (2i+1) 2^128 B
    var acc = ed.basepoint;
    const b2 = ed.basepoint.dbl();
    var b128 = ed.basepoint;
    for (0..128) |_| b128 = b128.dbl();
    var acc128 = b128;
    const b128_2 = b128.dbl();
    for (0..64) |i| {
        try std.testing.expect(pointEql(toPoint(addCached(identity, base_c[i].load())), acc));
        try std.testing.expect(pointEql(toPoint(subCached(identity, base128_c[i].load())), acc128.neg()));
        acc = acc.add(b2);
        acc128 = acc128.add(b128_2);
    }
}

test "x4: a long mixed chain stays in bounds and ends on the scalar result" {
    var prng = std.Random.DefaultPrng.init(0xc4a1);
    const rng = prng.random();
    for (0..4) |_| {
        const p = randPoint(rng);
        var tbl: Table = undefined;
        tbl.init(p);
        const st = ed.Naf5Table.init(p);
        var v = identity;
        var s = ed.Point.identity;
        for (0..1500) |k| {
            const op = rng.uintLessThan(u8, 4);
            const e = rng.uintLessThan(usize, 8);
            switch (op) {
                0, 1 => {
                    v = dbl(v);
                    s = s.dbl();
                },
                2 => {
                    v = addCached(v, tbl.t[e].load());
                    s = s.addNiels(st.t[e]).toExtended();
                },
                else => {
                    v = subCached(v, tbl.t[e].load());
                    s = s.subNiels(st.t[e]).toExtended();
                },
            }
            try std.testing.expect(within(v, 101));
            if (k % 97 == 0) try std.testing.expect(pointEql(toPoint(v), s));
        }
        try std.testing.expect(pointEql(toPoint(v), s));
    }
}

test "x4: quadMul equals the scalar quadMul on random and edge digits and points" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rng = prng.random();
    const exact = @import("ed25519_exact.zig");
    const tenc = exact.torsionEncodings();
    for (0..96) |round| {
        const a = if (round % 8 == 7) ed.decompress(&tenc[round / 8 % 14]).? else randPoint(rng);
        const r = if (round % 8 == 6) ed.decompress(&tenc[(round / 8 + 5) % 14]).? else randPoint(rng);
        var k: [4]u128 = undefined;
        for (&k) |*x| x.* = rng.int(u128);
        // edge scalars: zero, one, all ones, a single top bit, in every slot
        const edges = [_]u128{ 0, 1, std.math.maxInt(u128) >> 1, 1 << 126, 31, 255 };
        if (round % 4 == 1) k[round / 4 % 4] = edges[round / 16 % edges.len];
        if (round == 2) k = @splat(0);
        const na = ed.wnaf(ed.qn, k[0] >> 2, 5, rng.boolean());
        const nr = ed.wnaf(ed.qn, k[1] >> 1, 5, false);
        const nb0 = ed.wnaf(ed.qn, k[2], 8, true);
        const nb1 = ed.wnaf(ed.qn, k[3], 8, true);
        const tabs = ed.naf5Tables2(a, r);
        const want = ed.quadMul(&tabs[0], &na, &tabs[1], &nr, &nb0, &nb1);
        const got = quadMul(a, &na, r, &nr, &nb0, &nb1);
        try std.testing.expect(projEql(got, want));
    }
}

fn benchOn() bool {
    return std.testing.environ.containsUnempty(std.testing.allocator, "ZUI_ED25519_MICROBENCH") catch false;
}

fn nowNs() u64 {
    return @intCast(std.Io.Timestamp.now(std.testing.io, .awake).nanoseconds);
}

fn perOp(t: u64, k: usize) f64 {
    return @as(f64, @floatFromInt(t)) / @as(f64, @floatFromInt(k));
}

// Point operations, scalar against four-way. Run with
//   ZUI_ED25519_MICROBENCH=1 ./zig build test -Dlane=sig -Doptimize=ReleaseFast [-Dcpu=x86_64_v3]
// These rows time this test binary's own code, so on x86 they are AVX2 numbers only with
// -Dcpu=x86_64_v3 (a plain x86-64 build compiles this file for baseline: SSE2).
test "microbench: four-way point operations against the scalar ones" {
    if (!benchOn()) return;
    var prng = std.Random.DefaultPrng.init(0x6265_6e34);
    const rng = prng.random();
    const p = randPoint(rng);
    const q = randPoint(rng);
    const runs = 5;
    var sink: u64 = 0;
    std.debug.print("ed25519 point microbench ({s}, {s}), ns per operation, best of {d}:\n", .{ @tagName(@import("builtin").cpu.arch), @tagName(@import("builtin").mode), runs });
    {
        const n: usize = 400_000;
        var best: [4]u64 = @splat(std.math.maxInt(u64));
        const qn = q.toProjNiels();
        const qc = toCached(fromPoint(q));
        for (0..runs) |_| {
            var s = p;
            var t0 = nowNs();
            for (0..n) |_| s = s.dbl();
            best[0] = @min(best[0], nowNs() - t0);
            sink +%= s.x.l[0];
            t0 = nowNs();
            for (0..n) |_| s = s.addNiels(qn).toExtended();
            best[1] = @min(best[1], nowNs() - t0);
            sink +%= s.x.l[0];
            var v = fromPoint(p);
            t0 = nowNs();
            for (0..n) |_| v = dbl(v);
            best[2] = @min(best[2], nowNs() - t0);
            sink +%= @as([4]u32, v.l[0])[0];
            t0 = nowNs();
            for (0..n) |_| v = addCached(v, qc);
            best[3] = @min(best[3], nowNs() - t0);
            sink +%= @as([4]u32, v.l[0])[0];
        }
        std.debug.print("  doubling          scalar {d:>8.1}   four-way {d:>8.1}   ({d:.2}x)\n", .{ perOp(best[0], n), perOp(best[2], n), perOp(best[0], n) / perOp(best[2], n) });
        std.debug.print("  addition          scalar {d:>8.1}   four-way {d:>8.1}   ({d:.2}x)\n", .{ perOp(best[1], n), perOp(best[3], n), perOp(best[1], n) / perOp(best[3], n) });
    }
    {
        const n: usize = 20_000;
        var best: [2]u64 = @splat(std.math.maxInt(u64));
        for (0..runs) |_| {
            var t0 = nowNs();
            for (0..n) |_| {
                const t = ed.Naf5Table.init(p);
                sink +%= t.t[7].z.l[0];
            }
            best[0] = @min(best[0], nowNs() - t0);
            t0 = nowNs();
            for (0..n) |_| {
                var t: Table = undefined;
                t.init(p);
                sink +%= t.t[7].l[0][0];
            }
            best[1] = @min(best[1], nowNs() - t0);
        }
        std.debug.print("  width-5 table     scalar {d:>8.1}   four-way {d:>8.1}   ({d:.2}x)\n", .{ perOp(best[0], n), perOp(best[1], n), perOp(best[0], n) / perOp(best[1], n) });
    }
    {
        const n: usize = 2_000;
        var best: [2]u64 = @splat(std.math.maxInt(u64));
        const na = ed.wnaf(ed.qn, rng.int(u128) >> 2, 5, true);
        const nr = ed.wnaf(ed.qn, rng.int(u128) >> 1, 5, false);
        const nb0 = ed.wnaf(ed.qn, rng.int(u128), 8, true);
        const nb1 = ed.wnaf(ed.qn, rng.int(u128) >> 3, 8, true);
        for (0..runs) |_| {
            var t0 = nowNs();
            for (0..n) |_| {
                const tabs = ed.naf5Tables2(p, q);
                sink +%= ed.quadMul(&tabs[0], &na, &tabs[1], &nr, &nb0, &nb1).x.l[0];
            }
            best[0] = @min(best[0], nowNs() - t0);
            t0 = nowNs();
            for (0..n) |_| sink +%= quadMul(p, &na, q, &nr, &nb0, &nb1).x.l[0];
            best[1] = @min(best[1], nowNs() - t0);
        }
        std.debug.print("  128-step chain    scalar {d:>8.1}   four-way {d:>8.1}   ({d:.2}x)   (tables included)\n", .{ perOp(best[0], n), perOp(best[1], n), perOp(best[0], n) / perOp(best[1], n) });
    }
    std.mem.doNotOptimizeAway(&sink);
}

// Whole verifications through the public entry points, with each kernel tier this binary
// carries forced in turn and the four-way switch off and on: these rows time the kernel objects,
// whatever the build's own CPU (same command as above; -Dcpu not needed).
test "microbench: verify and batch, scalar against four-way, on every kernel tier" {
    if (!benchOn()) return;
    const fast = @import("fast.zig");
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6265_6e35);
    const rng = prng.random();
    const runs = 5;
    var sink: u64 = 0;
    // Whole verifications through the public entry points, per tier.
    const n_sig = 256;
    const kps = try gpa.alloc(ed.KeyPair, n_sig);
    defer gpa.free(kps);
    const msgs = try gpa.alloc([32]u8, n_sig);
    defer gpa.free(msgs);
    const sigs = try gpa.alloc([64]u8, 2 * n_sig);
    defer gpa.free(sigs);
    const items = try gpa.alloc(ed.BatchItem, n_sig);
    defer gpa.free(items);
    // the same messages signed by eight senders only (repeated keys)
    const few = try gpa.alloc(ed.BatchItem, n_sig);
    defer gpa.free(few);
    for (0..n_sig) |i| {
        var sd: [32]u8 = undefined;
        rng.bytes(&sd);
        kps[i] = ed.KeyPair.fromSeed(&sd);
        rng.bytes(&msgs[i]);
        sigs[i] = kps[i].sign(&msgs[i]);
        items[i] = .{ .pk = &kps[i].pk, .msg = &msgs[i], .sig = &sigs[i] };
        sigs[n_sig + i] = kps[i % 8].sign(&msgs[i]);
        few[i] = .{ .pk = &kps[i % 8].pk, .msg = &msgs[i], .sig = &sigs[n_sig + i] };
    }
    const scratch = try gpa.alloc(u8, (n_sig + 1) * ed.batch_scratch_per_item + 64);
    defer gpa.free(scratch);
    // the switches go back to what they were, not to off
    const vec4_before = cpu.edVec4();
    const keys_before = ed.batchKeys();
    const fast_before = fast.config();
    defer cpu.restoreTier();
    defer cpu.setEdVec4(vec4_before);
    defer ed.setBatchKeys(keys_before);
    defer fast.configure(fast_before);
    defer fast.clearCaches();
    for (std.enums.values(cpu.Tier)) |tier| {
        if (!cpu.forceTier(tier)) continue;
        var row: [2][5]f64 = undefined;
        for ([_]cpu.EdVec4{ .off, .force }, 0..) |mode, mi| {
            cpu.setEdVec4(mode);
            var best: [5]u64 = @splat(std.math.maxInt(u64));
            for (0..runs) |_| {
                ed.setBatchKeys(.{});
                fast.configure(.{});
                var t0 = nowNs();
                for (0..4) |_| for (items) |it| {
                    sink +%= @intFromBool(ed.verify(it.pk, it.msg, it.sig) == .valid);
                };
                best[0] = @min(best[0], (nowNs() - t0) / 4);
                t0 = nowNs();
                for (0..4) |_| sink +%= @intFromBool(ed.verifyBatch(items, scratch) == .valid);
                best[1] = @min(best[1], (nowNs() - t0) / 4);
                t0 = nowNs();
                for (0..4) |_| sink +%= @intFromBool(ed.verifyBatch(few, scratch) == .valid);
                best[2] = @min(best[2], (nowNs() - t0) / 4);
                ed.setBatchKeys(.{ .merge = true });
                t0 = nowNs();
                for (0..4) |_| sink +%= @intFromBool(ed.verifyBatch(few, scratch) == .valid);
                best[3] = @min(best[3], (nowNs() - t0) / 4);
                // warm key cache, distinct keys (no merge): the saved key decodes alone
                ed.setBatchKeys(.{ .cache = true });
                fast.configure(.{ .pk_cache = true });
                sink +%= @intFromBool(ed.verifyBatch(items, scratch) == .valid);
                t0 = nowNs();
                for (0..4) |_| sink +%= @intFromBool(ed.verifyBatch(items, scratch) == .valid);
                best[4] = @min(best[4], (nowNs() - t0) / 4);
            }
            for (&row[mi], best) |*r, b| r.* = perOp(b, n_sig) / 1000.0;
        }
        std.debug.print("ed25519 verify microbench, tier {s} ({s} / {s}), us per signature, scalar then four-way, best of 5:\n", .{ @tagName(tier), cpu.kernelNameFor(.ed25519, tier, .{ .sha_ni = false }), cpu.kernelNameFor(.ed25519, tier, .{ .sha_ni = false, .ed_vec4 = .force }) });
        const names = [_][]const u8{ "single verify", "batch of 256, 256 keys", "batch of 256, 8 keys", "batch of 256, 8 keys, merge", "batch of 256, 256 keys, warm cache" };
        for (names, 0..) |nm, k| std.debug.print("    {s:<36} {d:>7.2}   {d:>7.2}   ({d:.2}x)\n", .{ nm, row[0][k], row[1][k], row[0][k] / row[1][k] });
    }
    std.mem.doNotOptimizeAway(&sink);
}
