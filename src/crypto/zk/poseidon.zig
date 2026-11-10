//! Poseidon over the BN254 scalar field exactly as fastcrypto-zkp computes it (neptune 13 in
//! `OptimizedStatic` mode with circomlib's constants): width t = n + 1, state[0] = 0 (sponge
//! domain tag), x^5 S-box, 8 full rounds, partial rounds per width from circomlib, output
//! state[0]. `hashBytes` mirrors `poseidon_bytes` (the Move native), `merkle` mirrors
//! `poseidon_merkle_tree` and `zkLogin` mirrors `poseidon_zk_login`.
const std = @import("std");
const fp = @import("bn254/fp.zig");
const consts = @import("poseidon_constants.zig");
/// The raw circomlib tables (round constants `c<t>`, MDS matrices `m<t>`), for the GPU path.
pub const constants = consts;
const errors = @import("errors.zig");
const Fr = fp.Fr;

pub const max_inputs = 16;
pub const merkle_degree = 16;
pub const zklogin_max_inputs = 64;

const full_rounds = 8;

fn Tables(comptime t: usize) type {
    return struct {
        const rp: usize = consts.partial_rounds[t - 2];
        const m: [t][t]Fr = matrix(@field(consts, std.fmt.comptimePrint("m{d}", .{t})));
        const p: [t][t]Fr = matrix(@field(consts, std.fmt.comptimePrint("p{d}", .{t})));
        const cf: [full_rounds][t]Fr = blk: {
            @setEvalBranchQuota(100000);
            const raw = @field(consts, std.fmt.comptimePrint("cf{d}", .{t}));
            var out: [full_rounds][t]Fr = undefined;
            for (0..full_rounds) |r| for (0..t) |i| {
                out[r][i] = .{ .l = raw[r * t + i] };
            };
            break :blk out;
        };
        const cp: [rp]Fr = blk: {
            @setEvalBranchQuota(100000);
            const raw = @field(consts, std.fmt.comptimePrint("cp{d}", .{t}));
            var out: [rp]Fr = undefined;
            for (0..rp) |i| out[i] = .{ .l = raw[i] };
            break :blk out;
        };
        /// Per partial round: m00, w[t-1] (first row), v[t-1] (first column).
        const sp: [rp][2 * t - 1]Fr = blk: {
            @setEvalBranchQuota(1000000);
            const raw = @field(consts, std.fmt.comptimePrint("sp{d}", .{t}));
            var out: [rp][2 * t - 1]Fr = undefined;
            for (0..rp) |r| for (0..2 * t - 1) |i| {
                out[r][i] = .{ .l = raw[r * (2 * t - 1) + i] };
            };
            break :blk out;
        };

        fn matrix(comptime raw: anytype) [t][t]Fr {
            @setEvalBranchQuota(100000);
            var out: [t][t]Fr = undefined;
            for (0..t) |i| for (0..t) |j| {
                out[i][j] = .{ .l = raw[i * t + j] };
            };
            return out;
        }
    };
}

fn pow5(x: Fr) Fr {
    const x2 = x.sq();
    return x2.sq().mul(x);
}

fn mulMatrix(comptime t: usize, mat: *const [t][t]Fr, s: *[t]Fr) void {
    var ns: [t]Fr = undefined;
    inline for (0..t) |i| ns[i] = Fr.sumOfProducts(t, &mat[i], s);
    s.* = ns;
}

fn fullRound(comptime t: usize, comptime T: type, r: usize, mat: *const [t][t]Fr, s: *[t]Fr) void {
    inline for (0..t) |i| s[i] = pow5(s[i].add(T.cf[r][i]));
    mulMatrix(t, mat, s);
}

/// Poseidon permutation output state[0] for `n` = 1..16 inputs (already reduced field elements),
/// in the optimized form: folded constants and sparse partial-round matrices (tables generated
/// by `zui-zk-truth gen-poseidon`; the plain form is kept in `permutePlain` for the tests).
fn permute(comptime t: usize, inputs: []const Fr) Fr {
    const T = Tables(t);
    var s: [t]Fr = undefined;
    s[0] = Fr.zero;
    for (1..t) |i| s[i] = inputs[i - 1];
    for (0..full_rounds / 2 - 1) |r| fullRound(t, T, r, &T.m, &s);
    fullRound(t, T, full_rounds / 2 - 1, &T.p, &s);
    for (0..T.rp) |k| {
        s[0] = pow5(s[0].add(T.cp[k]));
        const row = &T.sp[k];
        const s0 = s[0];
        const acc = Fr.sumOfProducts(t, row[0..t], &s);
        inline for (1..t) |i| s[i] = s[i].add(row[t - 1 + i].mul(s0));
        s[0] = acc;
    }
    for (full_rounds / 2..full_rounds) |r| fullRound(t, T, r, &T.m, &s);
    return s[0];
}

/// The textbook permutation from the raw circomlib constants (reference for the tests).
fn permutePlain(comptime t: usize, inputs: []const Fr) Fr {
    const T = Tables(t);
    const raw_c = @field(consts, std.fmt.comptimePrint("c{d}", .{t}));
    var s: [t]Fr = undefined;
    s[0] = Fr.zero;
    for (1..t) |i| s[i] = inputs[i - 1];
    const total = full_rounds + T.rp;
    for (0..total) |r| {
        for (0..t) |i| s[i] = s[i].add(.{ .l = raw_c[r * t + i] });
        if (r < full_rounds / 2 or r >= full_rounds / 2 + T.rp) {
            for (0..t) |i| s[i] = pow5(s[i]);
        } else {
            s[0] = pow5(s[0]);
        }
        mulMatrix(t, &T.m, &s);
    }
    return s[0];
}

/// fastcrypto `poseidon`: 1..=16 field elements.
pub fn hash(inputs: []const Fr) ?Fr {
    return switch (inputs.len) {
        inline 1...16 => |n| permute(n + 1, inputs),
        else => null,
    };
}

/// Error detail for `hash`/`merkle`/`zkLogin` failures (the length fastcrypto reports).
pub const Fail = errors.Fail;

pub fn hashOr(inputs: []const Fr, fail: *Fail) ?Fr {
    return hash(inputs) orelse {
        fail.* = .{ .input_length_wrong = inputs.len };
        return null;
    };
}

/// fastcrypto `poseidon_merkle_tree`: hash chunks of 16 until one hash remains.
pub fn merkle(inputs: []const Fr, fail: *Fail) ?Fr {
    if (inputs.len <= merkle_degree) return hashOr(inputs, fail);
    var level: [zklogin_max_inputs_cap]Fr = undefined;
    std.debug.assert(inputs.len <= zklogin_max_inputs_cap * merkle_degree);
    var n: usize = 0;
    var i: usize = 0;
    while (i < inputs.len) : (i += merkle_degree) {
        const end = @min(i + merkle_degree, inputs.len);
        level[n] = hashOr(inputs[i..end], fail) orelse return null;
        n += 1;
    }
    return merkle(level[0..n], fail);
}

const zklogin_max_inputs_cap = 256;

/// fastcrypto `poseidon_zk_login`: 1..=64 inputs through the merkle tree.
pub fn zkLogin(inputs: []const Fr, fail: *Fail) ?Fr {
    if (inputs.len == 0 or inputs.len > zklogin_max_inputs) {
        fail.* = .{ .input_length_wrong = inputs.len };
        return null;
    }
    return merkle(inputs, fail);
}

/// fastcrypto `poseidon_bytes` (Move `poseidon::poseidon_bn254`): each input is 32 canonical
/// little-endian bytes; errors are InvalidInput (bad element) before InputLengthWrong (count).
pub fn hashBytes(inputs: []const []const u8, out: *[32]u8, fail: *Fail) bool {
    var buf: [max_inputs]Fr = undefined;
    for (inputs, 0..) |b, i| {
        if (b.len != 32) {
            fail.* = .invalid_input;
            return false;
        }
        const x = Fr.fromBytesLeCanonical(b[0..32]) orelse {
            fail.* = .invalid_input;
            return false;
        };
        if (i < max_inputs) buf[i] = x;
    }
    if (inputs.len == 0 or inputs.len > max_inputs) {
        fail.* = .{ .input_length_wrong = inputs.len };
        return false;
    }
    const h = hash(buf[0..inputs.len]).?;
    out.* = h.toBytesLe();
    return true;
}

/// Move native `poseidon::poseidon_bn254_internal` after the feature check and gas.
pub const native = struct {
    pub const non_canonical_input: u64 = 0;
    pub const not_supported: u64 = 1;
    pub const too_many_inputs: u64 = 2;

    pub fn poseidonBn254(inputs: []const []const u8, out: *[32]u8) ?u64 {
        if (inputs.len > max_inputs) return too_many_inputs;
        var fail: Fail = .none;
        if (!hashBytes(inputs, out, &fail)) return non_canonical_input;
        return null;
    }
};

test "fastcrypto poseidon vectors" {
    const one = Fr.fromInt(1);
    const two = Fr.fromInt(2);
    var fail: Fail = .none;
    // test_hash_to_bytes
    var out: [32]u8 = undefined;
    var b1: [32]u8 = @splat(0);
    b1[0] = 1;
    var b2: [32]u8 = @splat(0);
    b2[0] = 2;
    try std.testing.expect(hashBytes(&.{&b1}, &out, &fail));
    var exp: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&exp, "33018202c57d898b84338b16d1a4960e133c6a4d656cfec1bd62a9ea00611729");
    try std.testing.expectEqualSlices(u8, &exp, &out);
    try std.testing.expect(hashBytes(&.{ &b1, &b2 }, &out, &fail));
    _ = try std.fmt.hexToBytes(&exp, "9a1817447a60199e51453274f217362acfe962966b4cf63d4190d6e7f5c05c11");
    try std.testing.expectEqualSlices(u8, &exp, &out);
    const ff: [32]u8 = @splat(0xff);
    try std.testing.expect(!hashBytes(&.{&ff}, &out, &fail));
    // poseidon_test
    const h = hash(&.{
        Fr.fromDecimal("134696963602902907403122104327765350261").?,
        Fr.fromDecimal("17932473587154777519561053972421347139").?,
        Fr.fromDecimal("10000").?,
        Fr.fromDecimal("50683480294434968413708503290439057629605340925620961559740848568164438166").?,
    }).?;
    try std.testing.expect(h.eql(Fr.fromDecimal("2272550810841985018139126931041192927190568084082399473943239080305281957330").?));
    _ = one;
    _ = two;
    // optimized == plain for every width
    var rnd: [16]Fr = undefined;
    for (0..16) |i| rnd[i] = Fr.fromU64(0x9e3779b97f4a7c15 *% (i + 1)).sq();
    inline for (2..18) |t| try std.testing.expect(permute(t, rnd[0 .. t - 1]).eql(permutePlain(t, rnd[0 .. t - 1])));
    // test_to_poseidon_hash: merkle over 1..=k
    var xs: [33]Fr = undefined;
    for (0..33) |i| xs[i] = Fr.fromU64(i);
    try std.testing.expect(merkle(xs[1..2], &fail).?.eql(Fr.fromDecimal("18586133768512220936620570745912940619677854269274689475585506675881198879027").?));
    try std.testing.expect(merkle(xs[1..16], &fail).?.eql(Fr.fromDecimal("4203130618016961831408770638653325366880478848856764494148034853759773445968").?));
    try std.testing.expect(merkle(xs[0..30], &fail).?.eql(Fr.fromDecimal("4123755143677678663754455867798672266093104048057302051129414708339780424023").?));
    try std.testing.expect(merkle(xs[0..33], &fail).?.eql(Fr.fromDecimal("15368023340287843142129781602124963668572853984788169144128906033251913623349").?));
}
