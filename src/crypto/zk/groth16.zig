//! Groth16 verification over BN254 with fastcrypto-zkp's byte API (the `sui::groth16` Move
//! natives and zkLogin). Results, including which error a malformed input produces, follow
//! `fastcrypto_zkp::bn254::api` at fastcrypto da61cd46 (arkworks 0.4 underneath):
//!
//!   prepare_pvk_bytes(vk)            -> [vk_gamma_abc_g1, alpha_g1_beta_g2, -gamma, -delta]
//!   verify_groth16_in_bytes(4 parts, public inputs, proof points) -> Ok(bool) or an error
//!
//! No allocation on the verify path: the prepared input point is accumulated while the
//! gamma_abc points are decoded, in the same order arkworks reads them.
const std = @import("std");
const bn = @import("bn254.zig");
const errors = @import("errors.zig");
const Fail = errors.Fail;
const core = @import("core");
const Fq = bn.Fq;
const Fq12 = bn.Fq12;
const Fr = bn.Fr;
const G1 = bn.G1;
const G2 = bn.G2;

pub const Curve = enum(u8) { bls12381 = 0, bn254 = 1 };

pub const scalar_size = 32;
pub const g1_size = 32;
pub const g2_size = 64;
pub const gt_size = 384;
/// Move native limit (`groth16::MAX_PUBLIC_INPUTS`).
pub const max_public_inputs = 8;

/// The ark error string for `SynthesisError::MalformedVerifyingKey`.
pub const malformed_vk = "malformed verifying key";

/// `fastcrypto_zkp::groth16::api::get_public_inputs_num` for BN254 sizes.
pub fn publicInputsNum(vk_len: usize) ?usize {
    const prefix = 2 * g1_size + 3 * g2_size + 8;
    if (vk_len < prefix) return null;
    const rest = vk_len - prefix;
    if (rest % g1_size != 0) return null;
    return rest / g1_size;
}

/// A prepared verifying key ready for repeated verification (zkLogin keeps two of these).
pub const PreparedVk = struct {
    gamma_abc: []const G1,
    alpha_beta: Fq12,
    gamma_neg: bn.G2Prepared,
    delta_neg: bn.G2Prepared,

    /// arkworks `prepare_inputs` + `verify_proof_with_prepared_inputs`. Returns null for
    /// `MalformedVerifyingKey` (wrong input count).
    pub fn verify(pvk: *const PreparedVk, inputs: []const Fr, a: G1, b: G2, c: G1) ?bool {
        if (inputs.len + 1 != pvk.gamma_abc.len) return null;
        var acc = pvk.gamma_abc[0].toJacobian();
        for (inputs, pvk.gamma_abc[1..]) |x, p| {
            const k = x.toLimbs();
            acc = acc.add(bn.G1J.mulLimbs(p, &k));
        }
        return pairingEquation(acc.toAffine(), pvk.alpha_beta, &pvk.gamma_neg, &pvk.delta_neg, a, b, c);
    }
};

/// One proof of a `PreparedVk.verifyBatch` call: decoded (and subgroup-checked) as the single
/// path decodes it.
pub const BatchItem = struct { inputs: []const Fr, a: G1, b: G2, c: G1 };

/// `PreparedVk.verify` on every item, as one randomized batch (see `batchVerify`): `out[i]` is
/// null (MalformedVerifyingKey: wrong input count) or the verdict `verify` returns. `rng` must be
/// a CSPRNG (`osRng`) outside tests.
pub fn verifyBatch(pvk: *const PreparedVk, gpa: std.mem.Allocator, items: []const BatchItem, rng: std.Random, opts: BatchOpts, out: []?bool) void {
    std.debug.assert(out.len >= items.len);
    var n_ok: usize = 0;
    for (items, 0..) |it, i| {
        if (it.inputs.len + 1 != pvk.gamma_abc.len) {
            out[i] = null;
        } else {
            out[i] = false;
            n_ok += 1;
        }
    }
    if (n_ok == 0) return;
    // A key whose alpha_beta is outside the target group fails every proof (a final
    // exponentiation always lands in it); the batch equation needs it inside.
    if (n_ok > @max(1, opts.leaf) and !bn.inTargetGroup(pvk.alpha_beta)) return;
    const pos = gpa.alloc(u32, n_ok) catch {
        for (items, 0..) |it, i| if (out[i] != null) {
            out[i] = pvk.verify(it.inputs, it.a, it.b, it.c).?;
        };
        return;
    };
    defer gpa.free(pos);
    const ok = gpa.alloc(bool, n_ok) catch {
        for (items, 0..) |it, i| if (out[i] != null) {
            out[i] = pvk.verify(it.inputs, it.a, it.b, it.c).?;
        };
        return;
    };
    defer gpa.free(ok);
    var k: usize = 0;
    for (0..items.len) |i| if (out[i] != null) {
        pos[k] = @intCast(i);
        k += 1;
    };
    const Ctx = struct {
        pvk: *const PreparedVk,
        items: []const BatchItem,
        pos: []const u32,
        pub fn proof(c: @This(), i: usize) BatchProof {
            const it = c.items[c.pos[i]];
            return .{ .a = it.a, .b = it.b, .c = it.c };
        }
        pub fn inputs(c: @This(), i: usize) []const Fr {
            return c.items[c.pos[i]].inputs;
        }
        pub fn single(c: @This(), i: usize) bool {
            const it = c.items[c.pos[i]];
            return c.pvk.verify(it.inputs, it.a, it.b, it.c).?;
        }
    };
    const key: BatchKey = .{ .abc = pvk.gamma_abc, .alpha_beta = pvk.alpha_beta, .gamma_neg = &pvk.gamma_neg, .delta_neg = &pvk.delta_neg };
    batchVerify(Ctx, gpa, key, .{ .pvk = pvk, .items = items, .pos = pos }, n_ok, rng, opts, ok);
    for (pos, ok) |i, v| out[i] = v;
}

/// A ChaCha CSPRNG seeded from OS entropy (`io.randomSecure`, else `io.random`), for the batch
/// scalars: `var g = osRng(io); verifyBatch(.., g.random(), ..)`.
pub fn osRng(io: std.Io) std.Random.ChaCha {
    var seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
    io.randomSecure(&seed) catch io.random(&seed);
    return .init(seed);
}

/// e(A, B) * e(L, -gamma) * e(C, -delta) == alpha_beta (after final exponentiation).
pub fn pairingEquation(l: G1, alpha_beta: Fq12, gamma_neg: *const bn.G2Prepared, delta_neg: *const bn.G2Prepared, a: G1, b: G2, c: G1) bool {
    return @import("core").cpu.call("bn254_pairing_equation", pairingEquationImpl, .{ l, alpha_beta, gamma_neg, delta_neg, a, b, c });
}

pub fn pairingEquationImpl(l: G1, alpha_beta: Fq12, gamma_neg: *const bn.G2Prepared, delta_neg: *const bn.G2Prepared, a: G1, b: G2, c: G1) bool {
    const bp = bn.G2Prepared.init(b);
    // finalExponentiation null (UnexpectedIdentity) never happens for valid points: false
    return pairingEquationPrepared(l, alpha_beta, gamma_neg, delta_neg, a, &bp, c);
}

/// `pairingEquationImpl` with B already prepared (the batch verifier keeps the prepared B of a
/// proof for its per-proof fallback).
pub fn pairingEquationPrepared(l: G1, alpha_beta: Fq12, gamma_neg: *const bn.G2Prepared, delta_neg: *const bn.G2Prepared, a: G1, bp: *const bn.G2Prepared, c: G1) bool {
    const f = bn.multiMillerLoop(&.{
        .{ .p = a, .q = bp },
        .{ .p = l, .q = gamma_neg },
        .{ .p = c, .q = delta_neg },
    });
    const e = bn.finalExponentiation(f) orelse return false;
    return e.eql(alpha_beta);
}

/// Output of `prepare_pvk_bytes`: part 0 lives in the caller's arena.
pub const PvkBytes = struct {
    vk_gamma_abc_g1: []u8,
    alpha_g1_beta_g2: [gt_size]u8,
    gamma_g2_neg_pc: [g2_size]u8,
    delta_g2_neg_pc: [g2_size]u8,
};

/// `fastcrypto_zkp::bn254::api::prepare_pvk_bytes`. Every decode failure is InvalidInput.
/// Trailing bytes after the last gamma_abc point are ignored, as arkworks does.
pub fn preparePvkBytes(arena: std.mem.Allocator, vk: []const u8) (error{InvalidInput} || std.mem.Allocator.Error)!PvkBytes {
    var pos: usize = 0;
    const take = struct {
        fn f(b: []const u8, p: *usize, comptime n: usize) ?*const [n]u8 {
            if (b.len - p.* < n) return null;
            defer p.* += n;
            return b[p.*..][0..n];
        }
    }.f;
    const alpha = bn.curve.g1FromCompressed(take(vk, &pos, 32) orelse return error.InvalidInput) catch return error.InvalidInput;
    const beta = bn.curve.g2FromCompressed(take(vk, &pos, 64) orelse return error.InvalidInput) catch return error.InvalidInput;
    const gamma = bn.curve.g2FromCompressed(take(vk, &pos, 64) orelse return error.InvalidInput) catch return error.InvalidInput;
    const delta = bn.curve.g2FromCompressed(take(vk, &pos, 64) orelse return error.InvalidInput) catch return error.InvalidInput;
    const n = std.mem.readInt(u64, take(vk, &pos, 8) orelse return error.InvalidInput, .little);
    // Each point needs 32 bytes: a count beyond the input cannot succeed (arkworks hits EOF).
    if (n > (vk.len - pos) / 32) return error.InvalidInput;
    const part0 = try arena.alloc(u8, @intCast(n * 32));
    for (0..@intCast(n)) |i| {
        const p = bn.curve.g1FromCompressed(take(vk, &pos, 32).?) catch return error.InvalidInput;
        part0[i * 32 ..][0..32].* = bn.curve.g1ToCompressed(p);
    }
    return .{
        .vk_gamma_abc_g1 = part0,
        .alpha_g1_beta_g2 = bn.pairing(alpha, beta).toBytes(),
        .gamma_g2_neg_pc = bn.curve.g2ToCompressed(gamma.neg()),
        .delta_g2_neg_pc = bn.curve.g2ToCompressed(delta.neg()),
    };
}

/// Result of `verify_groth16_in_bytes`: Ok(bool) or the FastCryptoError.
pub const Verdict = union(enum) {
    ok: bool,
    err: Fail,
};

/// `fastcrypto_zkp::bn254::api::verify_groth16_in_bytes`, same error precedence:
/// input length, prepared key parts, proof points, input scalars, input count, pairing.
/// Allocation-free; variable time (all data is public).
pub fn verifyInBytes(
    vk_gamma_abc_g1: []const u8,
    alpha_g1_beta_g2: []const u8,
    gamma_g2_neg_pc: []const u8,
    delta_g2_neg_pc: []const u8,
    public_inputs: []const u8,
    proof_points: []const u8,
) Verdict {
    if (public_inputs.len % scalar_size != 0) return .{ .err = .{ .input_length_wrong = scalar_size } };
    const n_inputs = public_inputs.len / scalar_size;

    // Part 0: decode every point (any failure is InvalidInput) while accumulating
    // L = gamma_abc[0] + sum x_i * gamma_abc[i + 1] with the inputs read lazily.
    if (vk_gamma_abc_g1.len % scalar_size != 0) return .{ .err = .invalid_input };
    const n_points = vk_gamma_abc_g1.len / g1_size;
    var acc = bn.G1J.identity;
    var inputs_ok = true;
    for (0..n_points) |j| {
        const p = bn.curve.g1FromCompressed(vk_gamma_abc_g1[j * 32 ..][0..32]) catch return .{ .err = .invalid_input };
        if (j == 0) {
            acc = p.toJacobian();
        } else if (j - 1 < n_inputs and n_points == n_inputs + 1) {
            const xb = public_inputs[(j - 1) * 32 ..][0..32];
            const k = bn.Fr.limbsLe(xb);
            if (!bn.Fr.ltModulus(k)) {
                inputs_ok = false;
            } else if (inputs_ok) {
                acc = acc.add(bn.G1J.mulLimbs(p, &k));
            }
        }
    }
    if (alpha_g1_beta_g2.len < gt_size) return .{ .err = .invalid_input };
    const alpha_beta = Fq12.fromBytes(alpha_g1_beta_g2[0..gt_size]) orelse return .{ .err = .invalid_input };
    if (gamma_g2_neg_pc.len < g2_size) return .{ .err = .invalid_input };
    const gamma_neg = bn.curve.g2FromCompressed(gamma_g2_neg_pc[0..g2_size]) catch return .{ .err = .invalid_input };
    if (delta_g2_neg_pc.len < g2_size) return .{ .err = .invalid_input };
    const delta_neg = bn.curve.g2FromCompressed(delta_g2_neg_pc[0..g2_size]) catch return .{ .err = .invalid_input };

    if (proof_points.len < 128) return .{ .err = .invalid_input };
    const a = bn.curve.g1FromCompressed(proof_points[0..32]) catch return .{ .err = .invalid_input };
    const b = bn.curve.g2FromCompressed(proof_points[32..96]) catch return .{ .err = .invalid_input };
    const c = bn.curve.g1FromCompressed(proof_points[96..128]) catch return .{ .err = .invalid_input };

    for (0..n_inputs) |i| {
        if (!bn.Fr.ltModulus(bn.Fr.limbsLe(public_inputs[i * 32 ..][0..32]))) return .{ .err = .invalid_input };
    }
    if (n_points != n_inputs + 1) return .{ .err = .{ .general = malformed_vk } };
    std.debug.assert(inputs_ok);

    const gp = bn.G2Prepared.init(gamma_neg);
    const dp = bn.G2Prepared.init(delta_neg);
    return .{ .ok = pairingEquation(acc.toAffine(), alpha_beta, &gp, &dp, a, b, c) };
}

// ------------------------------------------------------------------------------------------------
// Randomized batch verification
//
// k proofs against one key: with independent random 128-bit r_i,
//
//   prod_i e(r_i A_i, B_i) * e(sum r_i L_i, -gamma) * e(sum r_i C_i, -delta) == e(alpha, beta)^(sum r_i)
//
// as one multi-Miller loop (split over the pool's lanes; the partial products multiply, since
// the Miller loop of a product of pairs is the product of their Miller loops) and one final
// exponentiation. sum r_i L_i = (sum r_i) IC0 + sum_j (sum_i r_i x_ij) IC_j+1, so the input side
// costs one scalar multiplication per IC point per batch, not per proof.
//
// Verdicts equal the single verifier's: a passing batch marks its proofs valid (a false pass
// needs the random r_i to cancel a nonzero error, probability about 2^-128); a failing batch is
// bisected (if one half passes the other must fail, so it is split without checking it) down to
// `leaf` proofs, which run the single verifier. A work budget switches to the single verifier
// when many proofs are bad, so a batch full of invalid proofs costs little more than checking
// them one by one. Callers decide decode, subgroup and input-count errors per proof before the
// batch, exactly as the single path does.

const Pool = core.pool.Pool;

pub const BatchProof = struct { a: G1, b: G2, c: G1 };

pub const BatchOpts = struct {
    /// Lanes to split over; null: `core.pool.shared()` (inline when none is installed).
    pool: ?*Pool = null,
    /// At most this many lanes (0: all of the pool).
    max_lanes: usize = 0,
    /// Failing sub-batches of at most this many proofs are decided proof by proof.
    leaf: usize = 2,
    /// Proofs per batch equation; longer lists run in chunks (bounds the prepared-B memory,
    /// about 17 KiB a proof).
    max_batch: usize = 512,
};

/// The key side shared by every proof of a batch. `alpha_beta` must be in the target group
/// (callers check untrusted keys with `bn.inTargetGroup`).
pub const BatchKey = struct {
    /// gamma_abc / IC points: L = abc[0] + sum_j x_j abc[j + 1].
    abc: []const G1,
    alpha_beta: Fq12,
    gamma_neg: *const bn.G2Prepared,
    delta_neg: *const bn.G2Prepared,
};

/// A random nonzero 128-bit scalar.
fn randScalar(rng: std.Random) u128 {
    while (true) {
        const r = rng.int(u128);
        if (r != 0) return r;
    }
}

fn limbs128(r: u128) [2]u64 {
    return .{ @truncate(r), @truncate(r >> 64) };
}

/// Jacobian to affine for a run of points with one inversion (Montgomery's trick).
fn normalizeG1(jac: []const bn.G1J, out: []G1, prefix: []Fq) void {
    var acc = Fq.one;
    for (jac, 0..) |p, i| {
        prefix[i] = acc;
        if (!p.isIdentity()) acc = acc.mul(p.z);
    }
    var inv = acc.inverse();
    var i: usize = jac.len;
    while (i > 0) {
        i -= 1;
        const p = jac[i];
        if (p.isIdentity()) {
            out[i] = G1.identity;
            continue;
        }
        const zi = inv.mul(prefix[i]);
        inv = inv.mul(p.z);
        const zi2 = zi.sq();
        out[i] = .{ .x = p.x.mul(zi2), .y = p.y.mul(zi2.mul(zi)), .infinity = false };
    }
}

/// Pairs per Miller loop inside one lane's share (a stack buffer; each loop shares its
/// squarings across these pairs).
const ml_chunk = 32;

/// The batch engine over `n` proofs that a context `C` describes:
///   ctx.proof(i) BatchProof, ctx.inputs(i) []const Fr (length abc.len - 1),
///   ctx.single(i) bool  (the single verifier on proof i).
/// `out[i]` gets the verdict of proof i. Never fails: without memory it runs the single path.
pub fn batchVerify(comptime C: type, gpa: std.mem.Allocator, key: BatchKey, ctx: C, n: usize, rng: std.Random, opts: BatchOpts, out: []bool) void {
    std.debug.assert(out.len >= n);
    const step = @max(1, opts.max_batch);
    var lo: usize = 0;
    while (lo < n) : (lo += step) {
        const hi = @min(n, lo + step);
        const Shift = struct {
            c: C,
            base: usize,
            pub fn proof(s: @This(), i: usize) BatchProof {
                return s.c.proof(s.base + i);
            }
            pub fn inputs(s: @This(), i: usize) []const Fr {
                return s.c.inputs(s.base + i);
            }
            pub fn single(s: @This(), i: usize) bool {
                return s.c.single(s.base + i);
            }
        };
        Engine(Shift).run(gpa, key, .{ .c = ctx, .base = lo }, hi - lo, rng, opts, out[lo..hi]);
    }
}

fn Engine(comptime C: type) type {
    return struct {
        const Self = @This();
        key: BatchKey,
        ctx: C,
        pool: ?*Pool,
        lanes: usize,
        leaf: usize,
        r: []u128,
        prep: []bn.G2Prepared,
        ra: []G1,
        rc: []bn.G1J,
        prefix: []Fq,
        part_f: []Fq12,
        part_c: []bn.G1J,
        idx: []u32,
        /// Scratch index list for the parallel failure path's single checks.
        sx: []u32,
        out: []bool,
        /// Proofs' worth of bisection checks left before falling back to the single path.
        budget: usize,

        fn run(gpa: std.mem.Allocator, key: BatchKey, ctx: C, n: usize, rng: std.Random, opts: BatchOpts, out: []bool) void {
            const pool = opts.pool orelse core.pool.shared();
            const pool_lanes: usize = if (pool) |p| p.lanes() else 1;
            const lanes = if (opts.max_lanes == 0) pool_lanes else @min(opts.max_lanes, pool_lanes);
            var e: Self = .{
                .key = key,
                .ctx = ctx,
                .pool = pool,
                .lanes = @max(1, lanes),
                .leaf = @max(1, opts.leaf),
                .r = &.{},
                .prep = &.{},
                .ra = &.{},
                .rc = &.{},
                .prefix = &.{},
                .part_f = &.{},
                .part_c = &.{},
                .idx = &.{},
                .sx = &.{},
                .out = out,
                .budget = 2 * n,
            };
            if (n == 0) return;
            if (n <= e.leaf or key.abc.len == 0 or key.abc.len - 1 > max_public_inputs) return e.singles(null, allIdx(n));
            e.alloc(gpa, n) catch {
                e.freeAll(gpa);
                return e.singles(null, allIdx(n));
            };
            defer e.freeAll(gpa);
            for (e.r) |*r| r.* = randScalar(rng);
            for (e.idx, 0..) |*x, i| x.* = @intCast(i);
            if (e.check(e.idx, true)) {
                @memset(out[0..n], true);
                return;
            }
            e.resolveFailed(e.idx);
        }

        /// Index lists for the single path without the engine's buffers.
        fn allIdx(n: usize) IdxRange {
            return .{ .n = n };
        }

        const IdxRange = struct { n: usize };

        fn alloc(e: *Self, gpa: std.mem.Allocator, n: usize) !void {
            e.r = try gpa.alloc(u128, n);
            e.prep = try gpa.alloc(bn.G2Prepared, n);
            e.ra = try gpa.alloc(G1, n);
            e.rc = try gpa.alloc(bn.G1J, n);
            e.prefix = try gpa.alloc(Fq, n);
            e.part_f = try gpa.alloc(Fq12, n);
            e.part_c = try gpa.alloc(bn.G1J, n);
            e.idx = try gpa.alloc(u32, n);
            e.sx = try gpa.alloc(u32, n);
        }

        fn freeAll(e: *Self, gpa: std.mem.Allocator) void {
            gpa.free(e.r);
            gpa.free(e.prep);
            gpa.free(e.ra);
            gpa.free(e.rc);
            gpa.free(e.prefix);
            gpa.free(e.part_f);
            gpa.free(e.part_c);
            gpa.free(e.idx);
            gpa.free(e.sx);
            e.sx = &.{};
            e.r = &.{};
            e.prep = &.{};
            e.ra = &.{};
            e.rc = &.{};
            e.prefix = &.{};
            e.part_f = &.{};
            e.part_c = &.{};
            e.idx = &.{};
        }

        const Job = struct { e: *Self, set: []const u32, grain: usize, first: bool };

        /// One lane's share: [lo, hi) of `set`, in sub-ranges of `grain` (an inline call covers
        /// the whole set), each leaving a Miller product and a sum of r_i C_i in its part slot.
        fn share(j: Job, lo: usize, hi: usize) void {
            const e = j.e;
            var s = lo;
            while (s < hi) : (s += j.grain) {
                const t = @min(hi, s + j.grain);
                const sub = j.set[s..t];
                if (j.first) {
                    for (sub) |i| {
                        const p = e.ctx.proof(i);
                        const rl = limbs128(e.r[i]);
                        e.prep[i] = bn.G2Prepared.init(p.b);
                        e.rc[i] = bn.G1J.mulLimbs(p.a, &rl); // r_i A_i, normalized below
                    }
                    // contiguous on the first pass (set is 0..n): normalize the run in place
                    normalizeG1(e.rc[sub[0] .. sub[sub.len - 1] + 1], e.ra[sub[0] .. sub[sub.len - 1] + 1], e.prefix[sub[0] .. sub[sub.len - 1] + 1]);
                    for (sub) |i| {
                        const p = e.ctx.proof(i);
                        const rl = limbs128(e.r[i]);
                        e.rc[i] = bn.G1J.mulLimbs(p.c, &rl);
                    }
                }
                const m = e.millerSerial(sub);
                e.part_f[s / j.grain] = m.f;
                e.part_c[s / j.grain] = m.cs;
            }
        }

        const Partial = struct { f: Fq12, cs: bn.G1J };

        /// Miller product of (r_i A_i, B_i) and the sum of r_i C_i over `sub`, on this thread.
        fn millerSerial(e: *const Self, sub: []const u32) Partial {
            var f = Fq12.one;
            var cs = bn.G1J.identity;
            var k: usize = 0;
            var buf: [ml_chunk]bn.pairing_.Pair = undefined;
            while (k < sub.len) {
                const m = @min(ml_chunk, sub.len - k);
                for (0..m) |q| {
                    const i = sub[k + q];
                    buf[q] = .{ .p = e.ra[i], .q = &e.prep[i] };
                }
                const g = bn.multiMillerLoopAny(buf[0..m]);
                f = if (k == 0) g else f.mul(g);
                k += m;
            }
            for (sub) |i| cs = cs.add(e.rc[i]);
            return .{ .f = f, .cs = cs };
        }

        /// The batch equation over `set` (with fresh prepared points when `first`).
        fn check(e: *Self, set: []const u32, first: bool) bool {
            const lanes = @min(e.lanes, set.len);
            const grain = (set.len + lanes - 1) / lanes;
            const job: Job = .{ .e = e, .set = set, .grain = grain, .first = first };
            core.pool.forRange(e.pool, set.len, grain, lanes, job, share);
            const parts = (set.len + grain - 1) / grain;
            var f = e.part_f[0];
            var cs = e.part_c[0];
            for (1..parts) |g| {
                f = f.mul(e.part_f[g]);
                cs = cs.add(e.part_c[g]);
            }
            return e.equation(set, f, cs);
        }

        /// The rest of the batch equation over `set` given its Miller product and sum r_i C_i.
        fn equation(e: *const Self, set: []const u32, f: Fq12, cs: bn.G1J) bool {
            // sum r_i L_i from the scalar sums
            const n_in = e.key.abc.len - 1;
            var s = Fr.zero;
            var t: [max_public_inputs]Fr = @splat(Fr.zero);
            for (set) |i| {
                const rl = limbs128(e.r[i]);
                const rf = Fr.fromCanonicalLimbs(.{ rl[0], rl[1], 0, 0 });
                s = s.add(rf);
                const xs = e.ctx.inputs(i);
                for (0..n_in) |jj| t[jj] = t[jj].add(rf.mul(xs[jj]));
            }
            var l = bn.G1J.mulLimbs(e.key.abc[0], &s.toLimbs());
            for (0..n_in) |jj| l = l.add(bn.G1J.mulLimbs(e.key.abc[jj + 1], &t[jj].toLimbs()));
            const tail = bn.multiMillerLoop(&.{
                .{ .p = l.toAffine(), .q = e.key.gamma_neg },
                .{ .p = cs.toAffine(), .q = e.key.delta_neg },
            });
            const fe = bn.finalExponentiation(f.mul(tail)) orelse return false;
            return fe.eql(bn.cyclotomicPow(e.key.alpha_beta, &s.toLimbs()));
        }

        fn checkBudget(e: *Self, set: []const u32) ?bool {
            if (e.budget < set.len) return null;
            e.budget -= set.len;
            return e.check(set, false);
        }

        fn mark(e: *Self, set: []const u32) void {
            for (set) |i| e.out[i] = true;
        }

        /// `set` is known to fail as one batch.
        fn resolveFailed(e: *Self, set: []const u32) void {
            if (set.len <= e.leaf) return e.singles(set, null);
            if (e.lanes > 1) return e.resolveFailedParallel(set);
            const h = set.len / 2;
            const left = set[0..h];
            const right = set[h..];
            const lv = e.checkBudget(left) orelse return e.singles(set, null);
            if (lv) {
                e.mark(left);
                e.resolveFailed(right);
            } else {
                e.resolveFailed(left);
                e.resolveUnknown(right);
            }
        }

        fn resolveUnknown(e: *Self, set: []const u32) void {
            if (set.len <= e.leaf) return e.singles(set, null);
            const v = e.checkBudget(set) orelse return e.singles(set, null);
            if (v) e.mark(set) else e.resolveFailed(set);
        }

        const GroupJob = struct { e: *const Self, set: []const u32, bounds: []const usize, res: []bool };

        fn groupShare(j: GroupJob, lo: usize, hi: usize) void {
            for (lo..hi) |g| {
                const sub = j.set[j.bounds[g]..j.bounds[g + 1]];
                const m = j.e.millerSerial(sub);
                j.res[g] = j.e.equation(sub, m.f, m.cs);
            }
        }

        /// Many lanes: split a failing set into one group per lane, check every group as its own
        /// batch on its own lane, then decide the small failing groups with the single verifier
        /// (all of them in one parallel pass) and split the large ones again. Bisection would
        /// leave most lanes idle while its serial checks run.
        fn resolveFailedParallel(e: *Self, set: []const u32) void {
            const small = @max(e.leaf, 4);
            if (set.len <= small or e.budget < set.len) return e.singles(set, null);
            e.budget -= set.len;
            const g: usize = @max(2, @min(e.lanes, (set.len + small - 1) / small));
            var bounds: [core.pool.max_lanes + 1]usize = undefined;
            var res: [core.pool.max_lanes]bool = undefined;
            for (0..g + 1) |k| bounds[k] = k * set.len / g;
            core.pool.forRange(e.pool, g, 1, e.lanes, GroupJob{ .e = e, .set = set, .bounds = bounds[0 .. g + 1], .res = res[0..g] }, groupShare);
            var m: usize = 0;
            for (0..g) |k| {
                const sub = set[bounds[k]..bounds[k + 1]];
                if (res[k]) {
                    e.mark(sub);
                } else if (sub.len <= small) {
                    @memcpy(e.sx[m..][0..sub.len], sub);
                    m += sub.len;
                }
            }
            if (m != 0) e.singles(e.sx[0..m], null);
            for (0..g) |k| {
                const sub = set[bounds[k]..bounds[k + 1]];
                if (!res[k] and sub.len > small) e.resolveFailedParallel(sub);
            }
        }

        const SingleJob = struct { e: *Self, set: ?[]const u32 };

        fn singleShare(j: SingleJob, lo: usize, hi: usize) void {
            const e = j.e;
            for (lo..hi) |k| {
                const i: usize = if (j.set) |s| s[k] else k;
                e.out[i] = e.ctx.single(i);
            }
        }

        /// The single verifier on `set` (engine buffers ready) or on every proof (`all`).
        fn singles(e: *Self, set: ?[]const u32, all: ?IdxRange) void {
            const n = if (set) |s| s.len else all.?.n;
            core.pool.forRange(e.pool, n, 1, e.lanes, SingleJob{ .e = e, .set = set }, singleShare);
        }
    };
}

/// The `sui::groth16` Move natives (sui-move-natives crypto/groth16.rs) without gas: gas is the
/// natives lane's (`numPublicInputsForGas` gives the count it charges per input). BLS12-381
/// (curve 0) returns `.unsupported` until the crypto-bls lane lands its pairing.
pub const native = struct {
    pub const invalid_verifying_key: u64 = 0;
    pub const invalid_curve: u64 = 1;
    pub const too_many_public_inputs: u64 = 2;
    pub const bls12381: u8 = 0;
    pub const bn254: u8 = 1;

    pub const PrepareResult = union(enum) { ok: PvkBytes, abort: u64, unsupported };
    pub const VerifyResult = union(enum) { ok: bool, abort: u64, unsupported };

    /// `prepare_verifying_key_internal(curve, vk)`; `limit_inputs` is the protocol flag
    /// `limit_groth16_pvk_inputs`.
    pub fn prepareVerifyingKey(arena: std.mem.Allocator, curve: u8, vk: []const u8, limit_inputs: bool) std.mem.Allocator.Error!PrepareResult {
        if (curve != bls12381 and curve != bn254) return .{ .abort = invalid_curve };
        if (curve == bls12381) return .unsupported;
        if (limit_inputs) {
            const n = publicInputsNum(vk.len) orelse return .{ .abort = invalid_verifying_key };
            if (n > max_public_inputs) return .{ .abort = too_many_public_inputs };
        }
        const p = preparePvkBytes(arena, vk) catch |e| switch (e) {
            error.InvalidInput => return .{ .abort = invalid_verifying_key },
            error.OutOfMemory => return error.OutOfMemory,
        };
        return .{ .ok = p };
    }

    /// `verify_groth16_proof_internal(curve, 4 key parts, inputs, proof)` after gas: any
    /// fastcrypto error is `false`.
    pub fn verifyProof(curve: u8, parts: [4][]const u8, public_inputs: []const u8, proof_points: []const u8) VerifyResult {
        if (curve != bls12381 and curve != bn254) return .{ .abort = invalid_curve };
        if (curve == bls12381) return .unsupported;
        if (public_inputs.len > scalar_size * max_public_inputs) return .{ .abort = too_many_public_inputs };
        return switch (verifyInBytes(parts[0], parts[1], parts[2], parts[3], public_inputs, proof_points)) {
            .ok => |b| .{ .ok = b },
            .err => .{ .ok = false },
        };
    }

    /// The input count the verify native charges for (both curves use 32-byte scalars).
    pub fn numPublicInputsForGas(public_inputs_len: usize) usize {
        return (public_inputs_len + scalar_size - 1) / scalar_size;
    }
};

test "groth16 roundtrip on a tiny key" {
    // A key whose gamma_abc has one point and no inputs: verify with a forged "proof" fails.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const g1 = bn.curve.g1ToCompressed(bn.curve.g1_generator);
    const g2 = bn.curve.g2ToCompressed(bn.curve.g2_generator);
    var vk: [32 + 64 * 3 + 8 + 32]u8 = undefined;
    @memcpy(vk[0..32], &g1);
    @memcpy(vk[32..96], &g2);
    @memcpy(vk[96..160], &g2);
    @memcpy(vk[160..224], &g2);
    std.mem.writeInt(u64, vk[224..232], 1, .little);
    @memcpy(vk[232..264], &g1);
    try std.testing.expectEqual(@as(?usize, 0), publicInputsNum(vk.len));
    const pvk = try preparePvkBytes(arena_state.allocator(), &vk);
    // e(g1, g2) * e(g1, -g2) * e(C, -g2) == e(g1, g2) holds for A = g1, B = g2, C = -g1.
    var proof: [128]u8 = undefined;
    @memcpy(proof[0..32], &g1);
    @memcpy(proof[32..96], &g2);
    proof[96..128].* = bn.curve.g1ToCompressed(bn.curve.g1_generator.neg());
    const v = verifyInBytes(pvk.vk_gamma_abc_g1, &pvk.alpha_g1_beta_g2, &pvk.gamma_g2_neg_pc, &pvk.delta_g2_neg_pc, &.{}, &proof);
    try std.testing.expect(v == .ok and v.ok);
    proof[96..128].* = g1;
    const v2 = verifyInBytes(pvk.vk_gamma_abc_g1, &pvk.alpha_g1_beta_g2, &pvk.gamma_g2_neg_pc, &pvk.delta_g2_neg_pc, &.{}, &proof);
    try std.testing.expect(v2 == .ok and !v2.ok);
}

// ------------------------------------------------------------------------------------------------
// Batch tests

/// A Groth16 key with known trapdoor scalars, so tests can make valid proofs for any input.
pub const TestKey = struct {
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    delta: Fr,
    abc_s: [3]Fr,
    abc: [3]G1,
    pvk: PreparedVk,

    pub fn g1(s: Fr) G1 {
        return bn.G1J.mulLimbs(bn.curve.g1_generator, &s.toLimbs()).toAffine();
    }
    pub fn g2(s: Fr) G2 {
        return bn.G2J.mulLimbs(bn.curve.g2_generator, &s.toLimbs()).toAffine();
    }
    pub fn randFr(rng: std.Random) Fr {
        var b: [32]u8 = undefined;
        rng.bytes(&b);
        b[31] &= 0x1f;
        return Fr.fromBytesLeModOrder(&b);
    }

    /// `n_inputs` public inputs (at most 2).
    pub fn init(k: *TestKey, rng: std.Random, n_inputs: usize) void {
        k.alpha = randFr(rng);
        k.beta = randFr(rng);
        k.gamma = randFr(rng);
        k.delta = randFr(rng);
        for (&k.abc_s, &k.abc) |*s, *p| {
            s.* = randFr(rng);
            p.* = g1(s.*);
        }
        k.pvk = .{
            .gamma_abc = k.abc[0 .. n_inputs + 1],
            .alpha_beta = bn.pairing(g1(k.alpha), g2(k.beta)),
            .gamma_neg = bn.G2Prepared.init(g2(k.gamma).neg()),
            .delta_neg = bn.G2Prepared.init(g2(k.delta).neg()),
        };
    }

    /// A valid proof for `inputs`: A = a G1, B = b G2, C = (ab - alpha beta - l gamma) / delta G1.
    pub fn prove(k: *const TestKey, inputs: []const Fr, rng: std.Random) BatchProof {
        const a = randFr(rng);
        const b = randFr(rng);
        var l = k.abc_s[0];
        for (inputs, 0..) |x, j| l = l.add(x.mul(k.abc_s[j + 1]));
        const c = a.mul(b).sub(k.alpha.mul(k.beta)).sub(l.mul(k.gamma)).mul(k.delta.inverse());
        return .{ .a = g1(a), .b = g2(b), .c = g1(c) };
    }
};

test "groth16 batch: verdicts equal the single verifier on valid and tampered proofs" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6b61);
    const rng = prng.random();
    var key: TestKey = undefined;
    key.init(rng, 2);
    const pool = try Pool.init(std.testing.io, gpa, 4);
    defer pool.deinit();
    const max = 64;
    var inputs: [max][2]Fr = undefined;
    var items: [max]BatchItem = undefined;
    var out: [max]?bool = undefined;
    var valid: [max]BatchProof = undefined;
    for (0..max) |i| {
        inputs[i] = .{ TestKey.randFr(rng), TestKey.randFr(rng) };
        valid[i] = key.prove(&inputs[i], rng);
    }
    for (valid[0..2]) |p| try std.testing.expect(key.pvk.verify(&inputs[0], p.a, p.b, p.c) != null);
    var bad_seen: usize = 0;
    for ([_]usize{ 1, 2, 3, 5, 8, 13, 16, 33, 64 }, 0..) |n, round| {
        for (0..n) |i| {
            const p = valid[i];
            items[i] = .{ .inputs = &inputs[i], .a = p.a, .b = p.b, .c = p.c };
            // tamper about a quarter of them (none in the first round's single proof)
            if (round != 0 and rng.uintLessThan(u8, 4) == 0) {
                switch (rng.uintLessThan(u8, 7)) {
                    0 => items[i].a = bn.curve.g1_generator,
                    1 => items[i].b = bn.curve.g2_generator,
                    2 => items[i].c = p.a,
                    3 => items[i].inputs = &inputs[(i + 1) % max], // input flipped to another valid one
                    4 => items[i].a = G1.identity,
                    5 => items[i].inputs = inputs[i][0..1], // wrong count: null
                    else => {
                        items[i].a = p.a.neg();
                        items[i].c = p.c.neg(); // e(-A,B) e(-C,-delta): fails unless lucky
                    },
                }
            }
        }
        const opts_list = [_]BatchOpts{ .{ .pool = pool }, .{ .pool = pool, .max_lanes = 1 }, .{ .pool = pool, .leaf = 1, .max_batch = 7 } };
        for (opts_list) |o| {
            verifyBatch(&key.pvk, gpa, items[0..n], rng, o, out[0..n]);
            for (items[0..n], out[0..n]) |it, got| {
                const want = key.pvk.verify(it.inputs, it.a, it.b, it.c);
                try std.testing.expectEqual(want, got);
                if (want == null or !want.?) bad_seen += 1;
            }
        }
    }
    try std.testing.expect(bad_seen > 10);
    // a batch where every proof is valid passes as one equation
    for (0..max) |i| items[i] = .{ .inputs = &inputs[i], .a = valid[i].a, .b = valid[i].b, .c = valid[i].c };
    verifyBatch(&key.pvk, gpa, &items, rng, .{ .pool = pool }, &out);
    for (out) |v| try std.testing.expectEqual(@as(?bool, true), v);
    // alpha_beta outside the target group: every proof fails, as the single verifier says
    var off = key.pvk;
    off.alpha_beta = Fq12.one.mul(.{ .c0 = .{ .c0 = bn.Fq2.one.dbl(), .c1 = bn.Fq2.zero, .c2 = bn.Fq2.zero }, .c1 = Fq12.one.c1 });
    try std.testing.expect(!bn.inTargetGroup(off.alpha_beta));
    verifyBatch(&off, gpa, items[0..8], rng, .{ .pool = pool }, out[0..8]);
    for (items[0..8], out[0..8]) |it, got| try std.testing.expectEqual(off.verify(it.inputs, it.a, it.b, it.c), got);
}
