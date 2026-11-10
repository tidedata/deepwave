//! zkLogin as Sui mainnet-v1.83.1 runs it (fastcrypto-zkp da61cd46 + sui-types):
//!
//! - `Authenticator.parse`: `ZkLoginAuthenticator::from_bytes` (BCS + `ZkLoginInputs::init`),
//!   zero-copy over the signature bytes; decoded strings (kid, iss) live in caller scratch.
//! - `verify`: `verify_zk_login(inputs, max_epoch, eph_pk, jwks, env, mode)`; every error is the
//!   same `FastCryptoError` value Rust returns (compared via its Debug text).
//! - `address`: padded (`get_zk_login_address`) and unpadded (`SuiAddress::try_from_unpadded`).
//! - `checkEpoch`: `verify_user_authenticator_epoch`.
//! - `genAddressSeed`, `nonce`, `checkId`, `checkIss`: the utils and the Move natives' helpers.
//!
//! Nothing on the verify path allocates. All inputs are public; nothing here is secret, so the
//! code is variable time.
const std = @import("std");
const bn = @import("bn254.zig");
const fp = @import("bn254/fp.zig");
const poseidon = @import("poseidon.zig");
const groth16 = @import("groth16.zig");
const b64 = @import("b64.zig");
const json = @import("json.zig");
const errors = @import("errors.zig");
const Fail = errors.Fail;
const Fr = bn.Fr;
const Fq = bn.Fq;
const Fq2 = bn.Fq2;
const G1 = bn.G1;
const G2 = bn.G2;
const Blake2b256 = @import("hash").Blake2b256;

pub const flag: u8 = 0x05;
const pack_bytes = 31; // PACK_WIDTH 248 bits

pub const Version = enum { v1, v2 };
pub const Mode = enum { v1_only, both, v2_only };
pub const Usage = enum { prod, test_ };

pub const Config = struct { max_header_len_b64: u16, max_iss_len: u16, max_rsa_bits: u16 };

pub fn config(v: Version) Config {
    return switch (v) {
        .v1 => .{ .max_header_len_b64 = 248, .max_iss_len = 4 * (1 + 165 / 3), .max_rsa_bits = 2048 },
        .v2 => .{ .max_header_len_b64 = 279, .max_iss_len = 186, .max_rsa_bits = 8192 },
    };
}

// ------------------------------------------------------------------------------------------------
// Field packing (`hash_to_field`, `hash_ascii_str_to_field`)

/// Packs a big-endian byte string (the bit string of `convert_base`, always whole bytes here)
/// into 248-bit chunks taken from the right and hashes them with `poseidon_zk_login`.
fn packAndHash(bytes: []const u8, fail: *Fail) ?Fr {
    const n = (bytes.len + pack_bytes - 1) / pack_bytes;
    if (n == 0 or n > poseidon.zklogin_max_inputs) {
        fail.* = .{ .input_length_wrong = n };
        return null;
    }
    var buf: [poseidon.zklogin_max_inputs]Fr = undefined;
    var end = bytes.len;
    var i = n;
    while (i > 0) {
        i -= 1;
        const start = end -| pack_bytes;
        buf[i] = Fr.fromBytesBeModOrder(bytes[start..end]);
        end = start;
    }
    return poseidon.zkLogin(buf[0..n], fail);
}

/// `hash_ascii_str_to_field(s, max_size)`. `s` must be valid UTF-8 (a Rust &str).
pub fn hashAsciiStrToField(s: []const u8, max_size: u16, fail: *Fail) ?Fr {
    const count = std.unicode.utf8CountCodepoints(s) catch unreachable;
    if (count > max_size) {
        fail.* = .{ .general = "in_arr too long" };
        return null;
    }
    var codes: [std.math.maxInt(u16)]u8 = undefined;
    var it = std.unicode.Utf8View.initUnchecked(s).iterator();
    var k: usize = 0;
    while (it.nextCodepoint()) |cp| : (k += 1) {
        if (cp > 0xff) {
            fail.* = .invalid_input;
            return null;
        }
        codes[k] = @intCast(cp);
    }
    @memset(codes[k..max_size], 0);
    return packAndHash(codes[0..max_size], fail);
}

/// `hash_to_field(&[BigUint::from_bytes_be(modulus)], max_rsa_bits, 248)`; `modulus` has no
/// leading zero bytes.
fn hashModulus(modulus: []const u8, max_rsa_bits: u16, fail: *Fail) ?Fr {
    if (bitLen(modulus) > max_rsa_bits) {
        fail.* = .invalid_input;
        return null;
    }
    var buf: [8192 / 8]u8 = undefined;
    const nb = max_rsa_bits / 8;
    @memset(buf[0 .. nb - modulus.len], 0);
    @memcpy(buf[nb - modulus.len .. nb], modulus);
    return packAndHash(buf[0..nb], fail);
}

fn bitLen(be: []const u8) usize {
    if (be.len == 0) return 0;
    return (be.len - 1) * 8 + (8 - @as(usize, @clz(be[0])));
}

/// `split_to_two_frs(flag || pk)`.
pub fn splitToTwoFrs(eph: Eph, fail: *Fail) ?[2]Fr {
    const len = 1 + eph.pk.len;
    if (len < 33) {
        fail.* = .{ .input_too_short = 33 };
        return null;
    }
    if (len > 47) {
        fail.* = .{ .input_too_long = 47 };
        return null;
    }
    var buf: [47]u8 = undefined;
    buf[0] = eph.flag;
    @memcpy(buf[1..len], eph.pk);
    return .{ Fr.fromBytesBeModOrder(buf[0 .. len - 16]), Fr.fromBytesBeModOrder(buf[len - 16 .. len]) };
}

/// The ephemeral public key as `flag || pk` (two slices, no copy).
pub const Eph = struct { flag: u8, pk: []const u8 };

// ------------------------------------------------------------------------------------------------
// Authenticator parsing

const Reader = struct {
    b: []const u8,
    i: usize = 0,

    fn byte(r: *Reader) ?u8 {
        if (r.i >= r.b.len) return null;
        defer r.i += 1;
        return r.b[r.i];
    }

    /// bcs `parse_length`: canonical ULEB128 u32, at most 2^31 - 1.
    fn len(r: *Reader) ?usize {
        var v: u64 = 0;
        var shift: u6 = 0;
        while (shift < 32) : (shift += 7) {
            const b = r.byte() orelse return null;
            const d = b & 0x7f;
            v |= @as(u64, d) << shift;
            if (d == b) {
                if (shift > 0 and d == 0) return null;
                if (v > std.math.maxInt(u32)) return null;
                if (v > std.math.maxInt(i32)) return null;
                return @intCast(v);
            }
        }
        return null;
    }

    fn bytes(r: *Reader) ?[]const u8 {
        const n = r.len() orelse return null;
        if (r.b.len - r.i < n) return null;
        defer r.i += n;
        return r.b[r.i..][0..n];
    }

    fn str(r: *Reader) ?[]const u8 {
        const s = r.bytes() orelse return null;
        if (!std.unicode.utf8ValidateSlice(s)) return null;
        return s;
    }

    fn fq(r: *Reader) ?Fq {
        return Fq.fromDecimal(r.str() orelse return null);
    }

    fn u64le(r: *Reader) ?u64 {
        if (r.b.len - r.i < 8) return null;
        defer r.i += 8;
        return std.mem.readInt(u64, r.b[r.i..][0..8], .little);
    }
};

/// Signature flag and total length of each `Signature` variant (`flag || sig || pk`).
fn sigLayout(f: u8) ?struct { total: usize, pk: usize } {
    return switch (f) {
        0 => .{ .total = 1 + 64 + 32, .pk = 32 },
        1, 2 => .{ .total = 1 + 64 + 33, .pk = 33 },
        7 => .{ .total = 1 + 3309 + 1952, .pk = 1952 },
        else => null,
    };
}

/// Scratch bytes `Authenticator.parse` needs for an authenticator of `bcs_len` bytes. With
/// H and I the header and iss_base64 lengths (H + I <= bcs_len), init uses at most
/// 3 * (3H/4) while parsing the header (decoded JSON, its strings, the skip stack), then keeps
/// 2 * (3H/4) and adds 3I/4 for the decoded claim, 3I/4 + 1 for the braced claim text and 3I/4
/// for the claim's decoded strings: max(2.25H, 1.5H + 2.25I + 1) <= 3 * bcs_len.
pub fn scratchLen(bcs_len: usize) usize {
    return 3 * bcs_len + 16;
}

pub const Authenticator = struct {
    /// Proof points as parsed field elements; `*_n` are the vector lengths (shape is checked by
    /// `proofPoints`, as `as_arkworks` does).
    a: [3]Fq,
    a_n: usize,
    b: [3][2]Fq,
    b_shape_ok: bool,
    c: [3]Fq,
    c_n: usize,
    iss_value: []const u8,
    index_mod_4: u8,
    header_base64: []const u8,
    /// Address seed, 32 bytes big-endian (canonical, reduced as `Fr::from_str` does).
    seed: [32]u8,
    max_epoch: u64,
    /// The user signature `flag || sig || pk`.
    user_signature: []const u8,
    // Filled by init (JWTDetails), slices into caller scratch.
    kid: []const u8,
    iss: []const u8,

    pub fn eph(a: *const Authenticator) Eph {
        const l = sigLayout(a.user_signature[0]).?;
        return .{ .flag = a.user_signature[0], .pk = a.user_signature[l.total - l.pk ..] };
    }

    /// `ZkLoginAuthenticator::from_bytes(0x05 || bcs)` given the BCS bytes after the flag.
    /// `scratch` must hold at least `scratchLen(bcs.len)` bytes and outlive the result.
    pub fn parse(bcs: []const u8, scratch: []u8, out: *Authenticator, fail: *Fail) bool {
        if (scratch.len < scratchLen(bcs.len)) @panic("zklogin.Authenticator.parse: scratch too small");
        if (!out.parseBcs(bcs)) {
            fail.* = .invalid_signature;
            return false;
        }
        return out.init(scratch, fail);
    }

    fn parseBcs(a: *Authenticator, bcs: []const u8) bool {
        var r: Reader = .{ .b = bcs };
        // proof_points.a: Vec<String>
        a.a_n = r.len() orelse return false;
        for (0..a.a_n) |i| {
            const x = r.fq() orelse return false;
            if (i < 3) a.a[i] = x;
        }
        const bn_ = r.len() orelse return false;
        a.b_shape_ok = bn_ == 3;
        for (0..bn_) |i| {
            const m = r.len() orelse return false;
            if (m != 2) a.b_shape_ok = false;
            for (0..m) |j| {
                const x = r.fq() orelse return false;
                if (i < 3 and j < 2) a.b[i][j] = x;
            }
        }
        a.c_n = r.len() orelse return false;
        for (0..a.c_n) |i| {
            const x = r.fq() orelse return false;
            if (i < 3) a.c[i] = x;
        }
        a.iss_value = r.str() orelse return false;
        a.index_mod_4 = r.byte() orelse return false;
        a.header_base64 = r.str() orelse return false;
        const seed = Fr.fromDecimal(r.str() orelse return false) orelse return false;
        a.seed = seed.toBytesBe();
        a.max_epoch = r.u64le() orelse return false;
        const sig = r.bytes() orelse return false;
        if (sig.len == 0) return false;
        const l = sigLayout(sig[0]) orelse return false;
        if (sig.len != l.total) return false;
        a.user_signature = sig;
        return r.i == bcs.len;
    }

    /// `ZkLoginInputs::init` = `JWTDetails::new(header_base64, iss_base64_details)`.
    fn init(a: *Authenticator, scratch: []u8, fail: *Fail) bool {
        var rest = scratch;
        // JWTHeader::new
        const hdr_json = b64.decodeUrlUnpadded(a.header_base64, rest) orelse {
            fail.* = .invalid_input;
            return false;
        };
        rest = rest[hdr_json.len..];
        // decoded header strings fit in hdr_json.len bytes; the next hdr_json.len bytes are
        // the parser's skip stack, free again once the header is parsed
        const h = json.jwtHeader(hdr_json, rest[0 .. 2 * hdr_json.len]) catch {
            fail.* = .invalid_input;
            return false;
        };
        if (!std.mem.eql(u8, h.alg, "RS256")) {
            fail.* = .{ .general = "Invalid header" };
            return false;
        }
        a.kid = h.kid;
        rest = rest[hdr_json.len..];
        // decode_base64_url + verify_extended_claim
        const ext = b64.decodeBase64UrlBits(a.iss_value, a.index_mod_4, rest, fail) orelse return false;
        rest = rest[ext.len..];
        a.iss = verifyExtendedClaim(ext, "iss", rest, fail) orelse return false;
        return true;
    }
};

/// `verify_extended_claim(claim, key)`; `buf` needs 2 * claim.len + 2 bytes.
fn verifyExtendedClaim(claim: []const u8, key: []const u8, buf: []u8, fail: *Fail) ?[]const u8 {
    if (claim.len == 0 or (claim[claim.len - 1] != '}' and claim[claim.len - 1] != ',')) {
        fail.* = .{ .general = "Invalid extended claim" };
        return null;
    }
    const text = buf[0 .. claim.len + 1];
    text[0] = '{';
    @memcpy(text[1..claim.len], claim[0 .. claim.len - 1]);
    text[claim.len] = '}';
    const v = json.claimValue(text, key, buf[claim.len + 1 ..]) catch {
        fail.* = .invalid_input;
        return null;
    };
    return v orelse {
        fail.* = .invalid_input;
        return null;
    };
}

// ------------------------------------------------------------------------------------------------
// Verifying keys

/// A Groth16 key with one public input, prepared once. `ic1_table` holds d * 16^w * IC1 for
/// every 4-bit window w and digit d, so the input point costs at most 64 mixed additions.
pub const FixedVk = struct {
    ic: [2]G1,
    ic1_table: [64][16]G1,
    alpha_beta: bn.Fq12,
    gamma_neg: bn.G2Prepared,
    delta_neg: bn.G2Prepared,

    fn init(vk: *FixedVk, comptime d: VkDec) void {
        const alpha = g1Dec(d.alpha);
        const beta = g2Dec(d.beta);
        vk.ic = .{ g1Dec(d.ic0), g1Dec(d.ic1) };
        vk.alpha_beta = bn.pairing(alpha, beta);
        vk.gamma_neg = bn.G2Prepared.init(g2Dec(d.gamma).neg());
        vk.delta_neg = bn.G2Prepared.init(g2Dec(d.delta).neg());
        var base = vk.ic[1].toJacobian();
        for (&vk.ic1_table) |*row| {
            var jac: [16]bn.G1J = undefined;
            jac[0] = bn.G1J.identity;
            for (1..16) |i| jac[i] = jac[i - 1].add(base);
            normalize(&jac, row);
            base = jac[15].add(base); // 16 * base
        }
    }

    /// Batch affine conversion (one inversion for the row).
    fn normalize(jac: *const [16]bn.G1J, out: *[16]G1) void {
        var prefix: [16]Fq = undefined;
        var acc = Fq.one;
        for (jac, 0..) |p, i| {
            prefix[i] = acc;
            if (!p.isIdentity()) acc = acc.mul(p.z);
        }
        var inv = acc.inverse();
        var i: usize = 16;
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

    /// IC0 + x * IC1.
    fn inputPoint(vk: *const FixedVk, x: Fr) G1 {
        const k = x.toLimbs();
        var acc = vk.ic[0].toJacobian();
        for (0..64) |w| {
            const digit: usize = @intCast((k[w / 16] >> @intCast((w % 16) * 4)) & 15);
            if (digit != 0) acc = acc.addAffine(vk.ic1_table[w][digit]);
        }
        return acc.toAffine();
    }

    /// `Groth16::verify_with_processed_vk(vk, &[x], proof)`.
    pub fn verify(vk: *const FixedVk, x: Fr, p: Proof) bool {
        return groth16.pairingEquation(vk.inputPoint(x), vk.alpha_beta, &vk.gamma_neg, &vk.delta_neg, p.a, p.b, p.c);
    }
};

const VkDec = struct {
    alpha: [2][]const u8,
    beta: [4][]const u8,
    gamma: [4][]const u8,
    delta: [4][]const u8,
    ic0: [2][]const u8,
    ic1: [2][]const u8,
};

fn g1Dec(comptime d: [2][]const u8) G1 {
    return .{ .x = Fq.fromDecimal(d[0]).?, .y = Fq.fromDecimal(d[1]).?, .infinity = false };
}

fn g2Dec(comptime d: [4][]const u8) G2 {
    return .{
        .x = .{ .c0 = Fq.fromDecimal(d[0]).?, .c1 = Fq.fromDecimal(d[1]).? },
        .y = .{ .c0 = Fq.fromDecimal(d[2]).?, .c1 = Fq.fromDecimal(d[3]).? },
        .infinity = false,
    };
}

const g2_gen_dec: [4][]const u8 = .{
    "10857046999023057135944570762232829481370756359578518086990519993285655852781",
    "11559732032986387107991004021392285783925812861821192530917403151452391805634",
    "8495653923123431417604973247489272438418190587263600148770280649306958101930",
    "4082367875863433681332203403145435568316851327593401208105741076214120093531",
};

/// `global_pvk` (prod; `global_pvk_v2` returns the same key).
const prod_vk: VkDec = .{
    .alpha = .{ "21529901943976716921335152104180790524318946701278905588288070441048877064089", "7775817982019986089115946956794180159548389285968353014325286374017358010641" },
    .beta = .{
        "6600437987682835329040464538375790690815756241121776438004683031791078085074",
        "16207344858883952201936462217289725998755030546200154201671892670464461194903",
        "17943105074568074607580970189766801116106680981075272363121544016828311544390",
        "18339640667362802607939727433487930605412455701857832124655129852540230493587",
    },
    .gamma = g2_gen_dec,
    .delta = .{
        "19260309516619721648285279557078789954438346514188902804737557357941293711874",
        "2480422554560175324649200374556411861037961022026590718777465211464278308900",
        "14489104692423540990601374549557603533921811847080812036788172274404299703364",
        "12564378633583954025611992187142343628816140907276948128970903673042690269191",
    },
    .ic0 = .{ "1607694606386445293170795095076356565829000940041894770459712091642365695804", "18066827569413962196795937356879694709963206118612267170825707780758040578649" },
    .ic1 = .{ "20653794344898475822834426774542692225449366952113790098812854265588083247207", "3296759704176575765409730962060698204792513807296274014163938591826372646699" },
};

const insecure_alpha: [2][]const u8 = .{ "20491192805390485299153009773594534940189261866228447918068658471970481763042", "9383485363053290200918347156157836566562967994039712273449902621266178545958" };
const insecure_beta: [4][]const u8 = .{
    "6375614351688725206403948262868962793625744043794305715222011528459656738731",
    "4252822878758300859123897981450591353533073413197771768651442665752259397132",
    "10505242626370262277552901082094356697409835680220590971873171140371331206856",
    "21847035105528745403288232691147584728191162732299865338377159692350059136679",
};

/// `insecure_pvk` (test, v1).
const test_vk_v1: VkDec = .{
    .alpha = insecure_alpha,
    .beta = insecure_beta,
    .gamma = g2_gen_dec,
    .delta = g2_gen_dec,
    .ic0 = .{ "20701306374481714853949730154526815782802808896228594855451770849676897643964", "2766989084754673216772682210231588284954002353414778477810174100808747060165" },
    .ic1 = .{ "501195541410525737371980194958674422793469475773065719916327137354779402600", "13527631693157515024233848630878973193664410306029731429350155106228769355415" },
};

/// `insecure_pvk_v2` (test, v2).
const test_vk_v2: VkDec = .{
    .alpha = insecure_alpha,
    .beta = insecure_beta,
    .gamma = g2_gen_dec,
    .delta = g2_gen_dec,
    .ic0 = .{ "7494019946711010262111829149650251402606293243816947408234427261113297488209", "15277037309547978131462479061393755632702482465205499508808087107719455935457" },
    .ic1 = .{ "11337299590256247592846534480065240790944417381563410255189124427241414159992", "10513214342948426742825684049934611922239382370302051503558098869981509341761" },
};

/// The three distinct zkLogin verifying keys, prepared once per process (about 100 KiB).
pub const Keys = struct {
    prod: FixedVk,
    test_v1: FixedVk,
    test_v2: FixedVk,

    pub fn init(k: *Keys) void {
        k.prod.init(prod_vk);
        k.test_v1.init(test_vk_v1);
        k.test_v2.init(test_vk_v2);
    }

    pub fn get(k: *const Keys, usage: Usage, v: Version) *const FixedVk {
        return switch (usage) {
            .prod => &k.prod,
            .test_ => if (v == .v1) &k.test_v1 else &k.test_v2,
        };
    }
};

// ------------------------------------------------------------------------------------------------
// Verification

/// JWK lookup by (iss, kid) after `JwkId::new` normalisation; returns the base64url modulus `n`.
pub const Jwks = struct {
    ctx: *const anyopaque,
    lookupFn: *const fn (ctx: *const anyopaque, iss: []const u8, kid: []const u8) ?[]const u8,

    pub fn lookup(j: Jwks, iss: []const u8, kid: []const u8) ?[]const u8 {
        return j.lookupFn(j.ctx, iss, kid);
    }

    pub const empty: Jwks = .{ .ctx = undefined, .lookupFn = struct {
        fn f(_: *const anyopaque, _: []const u8, _: []const u8) ?[]const u8 {
            return null;
        }
    }.f };
};

pub const Env = struct {
    keys: *const Keys,
    jwks: Jwks,
    usage: Usage = .prod,
    mode: Mode = .v1_only,
};

/// `JwkId::new`: a Microsoft tenant iss maps to the common one.
pub fn normalizeIss(iss: []const u8) []const u8 {
    if (std.mem.startsWith(u8, iss, "https://login.microsoftonline.com/") and std.mem.endsWith(u8, iss, "/v2.0"))
        return "https://login.microsoftonline.com/v2.0";
    return iss;
}

pub const Proof = struct { a: G1, b: G2, c: G1 };

fn jacobianToAffineG1(x: Fq, y: Fq, z: Fq) G1 {
    if (z.isZero()) return G1.identity;
    const zi = z.inverse();
    const zi2 = zi.sq();
    return .{ .x = x.mul(zi2), .y = y.mul(zi2.mul(zi)), .infinity = false };
}

fn jacobianToAffineG2(x: Fq2, y: Fq2, z: Fq2) G2 {
    if (z.isZero()) return G2.identity;
    const zi = z.inverse();
    const zi2 = zi.sq();
    return .{ .x = x.mul(zi2), .y = y.mul(zi2.mul(zi)), .infinity = false };
}

/// `ZkLoginProof::as_arkworks`: Jacobian coordinates, on-curve and subgroup checks.
pub fn proofPoints(a: *const Authenticator) ?Proof {
    if (a.a_n != 3 or !a.b_shape_ok or a.c_n != 3) return null;
    const pa = jacobianToAffineG1(a.a[0], a.a[1], a.a[2]);
    const pb = jacobianToAffineG2(
        .{ .c0 = a.b[0][0], .c1 = a.b[0][1] },
        .{ .c0 = a.b[1][0], .c1 = a.b[1][1] },
        .{ .c0 = a.b[2][0], .c1 = a.b[2][1] },
    );
    const pc = jacobianToAffineG1(a.c[0], a.c[1], a.c[2]);
    if (!pa.isOnCurve() or !pc.isOnCurve() or !pb.isOnCurve()) return null;
    if (!bn.curve.g2InSubgroup(pb)) return null;
    return .{ .a = pa, .b = pb, .c = pc };
}

/// Modulus decoded from the JWK `n` with leading zero bytes dropped (as `BigUint` holds it).
const Modulus = struct {
    buf: [8192 / 8 + 1]u8 = undefined,
    len: usize = 0,
    /// More significant bytes than `buf` holds: larger than any circuit accepts.
    too_big: bool = false,

    fn bytes(m: *const Modulus) []const u8 {
        return m.buf[0..m.len];
    }

    fn push(m: *Modulus, b: u8) void {
        if (m.len == 0 and b == 0) return;
        if (m.len == m.buf.len) {
            m.too_big = true;
            return;
        }
        m.buf[m.len] = b;
        m.len += 1;
    }

    /// Strict base64ct URL-unpadded decode, streamed. False on any decode error.
    fn decode(m: *Modulus, n: []const u8) bool {
        var i: usize = 0;
        var out: [3]u8 = undefined;
        while (i + 4 <= n.len) : (i += 4) {
            const got = b64.decodeUrlUnpadded(n[i..][0..4], &out) orelse return false;
            for (got) |b| m.push(b);
        }
        if (i < n.len) {
            const got = b64.decodeUrlUnpadded(n[i..], &out) orelse return false;
            for (got) |b| m.push(b);
        }
        return true;
    }
};

/// `ZkLoginInputs::calculate_all_inputs_hash`.
pub fn allInputsHash(a: *const Authenticator, eph: Eph, modulus: *const Modulus, v: Version, fail: *Fail) ?Fr {
    const cfg = config(v);
    if (a.header_base64.len > cfg.max_header_len_b64) {
        fail.* = .{ .general = "Header too long" };
        return null;
    }
    const seed = Fr.fromBytesBeModOrder(&a.seed);
    const two = splitToTwoFrs(eph, fail) orelse return null;
    const max_epoch_f = Fr.fromU64(a.max_epoch);
    const header_f = hashAsciiStrToField(a.header_base64, cfg.max_header_len_b64, fail) orelse return null;
    if (modulus.too_big) {
        fail.* = .invalid_input;
        return null;
    }
    const modulus_f = hashModulus(modulus.bytes(), cfg.max_rsa_bits, fail) orelse return null;
    switch (v) {
        .v1 => {
            const iss_f = hashAsciiStrToField(a.iss_value, cfg.max_iss_len, fail) orelse return null;
            return poseidon.zkLogin(&.{ two[0], two[1], seed, max_epoch_f, iss_f, Fr.fromU64(a.index_mod_4), header_f, modulus_f }, fail);
        },
        .v2 => {
            var buf: [4096]u8 = undefined;
            // decode again, as hash_iss_decoded does (cannot fail: init succeeded)
            const ext = b64.decodeBase64UrlBits(a.iss_value, a.index_mod_4, if (a.iss_value.len <= buf.len) &buf else return longIss(a, cfg, fail), fail) orelse return null;
            const iss_f = hashAsciiStrToField(ext, cfg.max_iss_len, fail) orelse return null;
            const bits = Fr.fromU64(bitLen(modulus.bytes()));
            return poseidon.zkLogin(&.{ two[0], two[1], seed, max_epoch_f, iss_f, header_f, modulus_f, bits }, fail);
        },
    }
}

/// An iss claim longer than the stack buffer decodes to more than max_iss_len characters.
fn longIss(a: *const Authenticator, cfg: Config, fail: *Fail) ?Fr {
    _ = a;
    _ = cfg;
    fail.* = .{ .general = "in_arr too long" };
    return null;
}

/// `verify_zk_login(inputs, max_epoch, eph, jwks, env, mode)`. Returns `.none` on success.
pub fn verify(env: *const Env, a: *const Authenticator) Fail {
    const eph = a.eph();
    const n = env.jwks.lookup(normalizeIss(a.iss), a.kid) orelse
        return .{ .jwk_not_found = .{ .iss = a.iss, .kid = a.kid } };
    var modulus: Modulus = .{};
    if (!modulus.decode(n)) return .{ .general = "Invalid Base64 encoded jwk modulus" };
    const proof = proofPoints(a) orelse return .invalid_input;
    return switch (env.mode) {
        .v1_only => verifyVersion(env, a, eph, &modulus, proof, .v1),
        .v2_only => verifyVersion(env, a, eph, &modulus, proof, .v2),
        .both => switch (verifyVersion(env, a, eph, &modulus, proof, .v2)) {
            .none => .none,
            else => verifyVersion(env, a, eph, &modulus, proof, .v1),
        },
    };
}

fn verifyVersion(env: *const Env, a: *const Authenticator, eph: Eph, modulus: *const Modulus, proof: Proof, v: Version) Fail {
    var fail: Fail = .none;
    const h = allInputsHash(a, eph, modulus, v, &fail) orelse return fail;
    if (!env.keys.get(env.usage, v).verify(h, proof)) return .{ .general = "Groth16 proof verify failed" };
    return .none;
}

/// `verify_user_authenticator_epoch`.
pub fn checkEpoch(max_epoch: u64, epoch: u64, delta: ?u64) bool {
    if (delta) |d| if (max_epoch > epoch +% d) return false;
    return epoch <= max_epoch;
}

// ------------------------------------------------------------------------------------------------
// Addresses and helpers

/// Address of (iss, seed): `padded` = `get_zk_login_address` / `try_from_padded`, otherwise
/// `try_from_unpadded` (seed with leading zero bytes dropped, one zero byte for seed 0).
pub fn address(iss: []const u8, seed: *const [32]u8, padded: bool) [32]u8 {
    var h = Blake2b256.init();
    h.update(&.{ flag, @truncate(iss.len) });
    h.update(iss);
    if (padded) {
        h.update(seed);
    } else {
        var i: usize = 0;
        while (i < 31 and seed[i] == 0) i += 1;
        h.update(seed[i..]);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

const max_key_claim_name_length = 32;
const max_key_claim_value_length = 115;
const max_aud_value_length = 145;

/// `gen_address_seed_with_salt_hash` with the salt hash already a field element.
pub fn addressSeedWithSaltHash(salt_hash: Fr, name: []const u8, value: []const u8, aud: []const u8, fail: *Fail) ?Fr {
    const a = hashAsciiStrToField(name, max_key_claim_name_length, fail) orelse return null;
    const b = hashAsciiStrToField(value, max_key_claim_value_length, fail) orelse return null;
    const c = hashAsciiStrToField(aud, max_aud_value_length, fail) orelse return null;
    return poseidon.zkLogin(&.{ a, b, c, salt_hash }, fail);
}

/// `gen_address_seed(salt, name, value, aud)`.
pub fn genAddressSeed(salt: []const u8, name: []const u8, value: []const u8, aud: []const u8, fail: *Fail) ?Fr {
    const s = Fr.fromDecimal(salt) orelse {
        fail.* = .invalid_input;
        return null;
    };
    const salt_hash = poseidon.zkLogin(&.{s}, fail) orelse return null;
    return addressSeedWithSaltHash(salt_hash, name, value, aud, fail);
}

/// `get_nonce(eph_pk_bytes, max_epoch, jwt_randomness)`: 27 base64url characters.
pub fn nonce(eph_pk_bytes: []const u8, max_epoch: u64, randomness: []const u8, out: *[27]u8, fail: *Fail) bool {
    if (eph_pk_bytes.len == 0) {
        fail.* = .{ .input_too_short = 33 };
        return false;
    }
    const two = splitToTwoFrs(.{ .flag = eph_pk_bytes[0], .pk = eph_pk_bytes[1..] }, fail) orelse return false;
    const rnd = Fr.fromDecimal(randomness) orelse {
        fail.* = .invalid_input;
        return false;
    };
    const h = poseidon.zkLogin(&.{ two[0], two[1], Fr.fromU64(max_epoch), rnd }, fail).?;
    const be = h.toBytesBe();
    _ = b64.encodeUrlUnpadded(be[12..32], out);
    return true;
}

/// `verify_zk_login_iss(address, address_seed, iss)`: `.none` when equal, InvalidProof when not.
pub fn checkIss(addr: *const [32]u8, address_seed: []const u8, iss: []const u8) Fail {
    const seed = Fr.fromDecimal(address_seed) orelse return .invalid_input;
    const bytes = seed.toBytesBe();
    const got = address(iss, &bytes, true);
    return if (std.mem.eql(u8, &got, addr)) .none else .invalid_proof;
}

/// `verify_zk_login_id(address, name, value, aud, iss, salt_hash)`.
pub fn checkId(addr: *const [32]u8, name: []const u8, value: []const u8, aud: []const u8, iss: []const u8, salt_hash: []const u8) Fail {
    var fail: Fail = .none;
    // gen_address_seed_with_salt_hash hashes the strings before parsing the salt hash
    const a = hashAsciiStrToField(name, max_key_claim_name_length, &fail) orelse return fail;
    const b = hashAsciiStrToField(value, max_key_claim_value_length, &fail) orelse return fail;
    const c = hashAsciiStrToField(aud, max_aud_value_length, &fail) orelse return fail;
    const sh = Fr.fromDecimal(salt_hash) orelse return .invalid_input;
    const seed = poseidon.zkLogin(&.{ a, b, c, sh }, &fail) orelse return fail;
    const bytes = seed.toBytesBe();
    const got = address(iss, &bytes, true);
    return if (std.mem.eql(u8, &got, addr)) .none else .invalid_proof;
}

/// Move natives `zklogin_verified_id::check_zklogin_id_internal` and
/// `zklogin_verified_issuer::check_zklogin_issuer_internal` (after gas): true, false, or abort
/// with `invalid_input`.
pub const native = struct {
    pub const invalid_input: u64 = 0;
    pub const Result = union(enum) { ok: bool, abort: u64 };

    fn verdict(f: Fail) Result {
        return switch (f) {
            .none => .{ .ok = true },
            .invalid_proof => .{ .ok = false },
            else => .{ .abort = invalid_input },
        };
    }

    pub fn checkZkloginId(addr: *const [32]u8, name: []const u8, value: []const u8, aud: []const u8, iss: []const u8, pin_hash: u256) Result {
        for ([_][]const u8{ name, value, aud, iss }) |x| if (!std.unicode.utf8ValidateSlice(x)) return .{ .abort = invalid_input };
        var buf: [80]u8 = undefined;
        const pin = std.fmt.bufPrint(&buf, "{d}", .{pin_hash}) catch unreachable;
        return verdict(checkId(addr, name, value, aud, iss, pin));
    }

    pub fn checkZkloginIssuer(addr: *const [32]u8, address_seed: u256, iss: []const u8) Result {
        var buf: [80]u8 = undefined;
        const seed = std.fmt.bufPrint(&buf, "{d}", .{address_seed}) catch unreachable;
        if (!std.unicode.utf8ValidateSlice(iss)) return .{ .abort = invalid_input };
        return verdict(checkIss(addr, seed, iss));
    }
};

test "zklogin helpers" {
    const keys = try std.testing.allocator.create(Keys);
    defer std.testing.allocator.destroy(keys);
    keys.init();
    for ([_]u64{ 0, 1, 15, 16, 0xdeadbeefcafebabe }) |v| {
        const x = Fr.fromU64(v).mul(Fr.fromU64(v +% 0x1234567));
        const slow = keys.prod.ic[0].toJacobian().add(bn.G1J.mulLimbs(keys.prod.ic[1], &x.toLimbs())).toAffine();
        try std.testing.expect(slow.eql(keys.prod.inputPoint(x)));
    }
    try std.testing.expect(checkEpoch(10, 10, null));
    try std.testing.expect(!checkEpoch(9, 10, null));
    try std.testing.expect(!checkEpoch(41, 10, 30));
}

/// BCS of a ZkLoginAuthenticator for tests (user signature: Ed25519 layout, zero bytes).
fn testAuthBcs(buf: []u8, a: [3][]const u8, b: [3][2][]const u8, c: [3][]const u8, iss: []const u8, idx: u8, hdr: []const u8, seed: []const u8, max_epoch: u64) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    const S = struct {
        fn uleb(wr: *std.Io.Writer, v: usize) void {
            var x = v;
            while (x >= 0x80) : (x >>= 7) wr.writeByte(@as(u8, @truncate(x)) | 0x80) catch unreachable;
            wr.writeByte(@intCast(x)) catch unreachable;
        }
        fn str(wr: *std.Io.Writer, s: []const u8) void {
            uleb(wr, s.len);
            wr.writeAll(s) catch unreachable;
        }
    };
    S.uleb(&w, 3);
    for (a) |x| S.str(&w, x);
    S.uleb(&w, 3);
    for (b) |row| {
        S.uleb(&w, 2);
        for (row) |x| S.str(&w, x);
    }
    S.uleb(&w, 3);
    for (c) |x| S.str(&w, x);
    S.str(&w, iss);
    w.writeByte(idx) catch unreachable;
    S.str(&w, hdr);
    S.str(&w, seed);
    w.writeInt(u64, max_epoch, .little) catch unreachable;
    S.uleb(&w, 97);
    w.splatByteAll(0, 97) catch unreachable;
    return w.buffered();
}

test "fastcrypto test_verify_zk_login: v1 proof under the insecure (Test) key" {
    // fastcrypto-zkp da61cd46 src/bn254/unit_tests/zk_login_tests.rs `test_verify_zk_login`
    // (the offline first half): verifies with ZkLoginEnv::Test in V1Only and Both, fails in
    // V2Only, and a proof with a[0] = 1 is rejected.
    const pa = [3][]const u8{ "7566241567720780416751598994698310678767195459947224622023785587667176814058", "18104499930818305143361187733659014043953751050617136254447624192327280445771", "1" };
    const pb = [3][2][]const u8{
        .{ "11369230593957954942221175389182778816136534144714579815927653075736806430994", "11928003240637992017698644299021052465098754853899210401706726930513411198353" },
        .{ "2597127058046351054449743605218058440565462021354202666955356076272028963802", "3385145993275542896693643488618289924488296318344621918448585222369718288892" },
        .{ "1", "0" },
    };
    const pc = [3][]const u8{ "395141536511114303768253959602639884294254888080713473665269769443249414257", "21430657725804540809568084344756144327539843580919730138594118365564728808275", "1" };
    const iss = "yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC";
    const hdr = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ";
    const seed = "4959624758616676340947699768172740454110375485415332267384397278368360470616";
    const n = "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw";
    // [0] ++ BigUint("3598866369818193253063936208363210863933653800990958031560302098730308306242903464").to_bytes_be()
    var pk: [34]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pk, "79686aa4ca7d8b8730615205effecb4023183f2434b00ff4f439bdf1c0b37f281da8");
    const eph: Eph = .{ .flag = 0, .pk = &pk };

    const keys = try std.testing.allocator.create(Keys);
    defer std.testing.allocator.destroy(keys);
    keys.init();
    var bcs_buf: [2048]u8 = undefined;
    var scratch: [8192]u8 = undefined;
    const bcs = testAuthBcs(&bcs_buf, pa, pb, pc, iss, 1, hdr, seed, 10000);
    var auth: Authenticator = undefined;
    var fail: Fail = .none;
    try std.testing.expect(Authenticator.parse(bcs, &scratch, &auth, &fail));
    try std.testing.expectEqualStrings("https://accounts.google.com", auth.iss);
    try std.testing.expectEqualStrings("c9afda3682ebf09eb3055c1c4bd39b751fbf8195", auth.kid);
    var modulus: Modulus = .{};
    try std.testing.expect(modulus.decode(n));
    const proof = proofPoints(&auth).?;
    const h1 = allInputsHash(&auth, eph, &modulus, .v1, &fail).?;
    try std.testing.expect(keys.get(.test_, .v1).verify(h1, proof));
    try std.testing.expect(!keys.get(.prod, .v1).verify(h1, proof));
    const h2 = allInputsHash(&auth, eph, &modulus, .v2, &fail).?;
    try std.testing.expect(!keys.get(.test_, .v2).verify(h2, proof));

    const bad_a = [3][]const u8{ "1", pa[1], pa[2] };
    const bad_b = [3][2][]const u8{ .{ "1", pb[0][1] }, pb[1], pb[2] };
    const bcs2 = testAuthBcs(&bcs_buf, bad_a, bad_b, pc, iss, 1, hdr, seed, 10000);
    var auth2: Authenticator = undefined;
    try std.testing.expect(Authenticator.parse(bcs2, &scratch, &auth2, &fail));
    try std.testing.expect(proofPoints(&auth2) == null);
}
