//! Conformance suites of the crypto-bls lane (CONTRACTS.md section 3.3).
//!
//!   bls12381   vectors/bls12381/fastcrypto.jsonl (written by tools/truth/crypto-bls with
//!              fastcrypto + blst: hash_to_g1, keygen, sign, verify verdicts, decode rules,
//!              aggregation) and vectors/bls12381/upstream/*.json (RFC 9380 hash-to-curve and
//!              expand_message_xmd vectors).
//!   bls-cert   vectors/bls-cert/<epoch>.jsonl: every corpus checkpoint certificate plus seven
//!              mutated negatives each, with the verdict Mysten's own verification path returns;
//!              vectors/bls-cert/synthetic.jsonl: the same path over a synthetic committee for
//!              what mainnet never shows (few signers, indices outside the committee, no signers).
//!   bls-group-ops  vectors/bls-group-ops/fastcrypto.jsonl: the BLS12-381 arms of the
//!              sui::group_ops natives, computed with the natives' own fastcrypto calls.
const std = @import("std");
const harness = @import("harness");
const core = @import("core");
const bls = @import("root.zig");
const sig = bls.sig;
const curve = bls.curve;
const encoding = bls.encoding;
const h2c = bls.hash_to_curve;

pub const suites = [_]harness.Suite{
    .{ .name = "bls12381", .lane = "crypto-bls", .doc = "sign/verify/aggregate/decode/hash-to-curve vs fastcrypto+blst, RFC 9380 hash-to-curve and expand_message_xmd", .run = runVectors },
    .{
        .name = "bls-cert",
        .lane = "crypto-bls",
        .doc = "every corpus checkpoint certificate and 7 mutated negatives, plus synthetic-committee cases (few signers, unknown signers, none): verdict vs Mysten's AuthorityQuorumSignInfo BLS check",
        .run = runCerts,
        .bench = benchCerts,
        .baselines = &.{
            .{ .name = "cert-verify", .argv = &.{ "{release}/zui-truth-bls", "bench", "cert-verify" } },
            .{ .name = "committee-prepare", .argv = &.{ "{release}/zui-truth-bls", "bench", "committee-prepare" } },
        },
        .inputs = .{ .dir = "vectors/bls-cert", .suffix = ".jsonl" },
    },
    .{ .name = "bls-group-ops", .lane = "crypto-bls", .doc = "sui::group_ops BLS12-381 natives (validate, add/sub/mul/div, hash_to, msm, pairing, convert, sum) vs the natives' fastcrypto calls", .run = runGroupOps },
};

fn hexAlloc(a: std.mem.Allocator, s: []const u8) ![]u8 {
    return core.hex.decodeAlloc(a, s);
}

fn hexFixed(comptime n: usize, s: []const u8) ![n]u8 {
    if (s.len != 2 * n) return error.BadHex;
    var out: [n]u8 = undefined;
    try core.hex.decode(&out, s);
    return out;
}

// ---------------------------------------------------------------------------------------------
// bls12381

const VecLine = struct {
    op: []const u8,
    id: []const u8,
    msg: ?[]const u8 = null,
    dst: ?[]const u8 = null,
    out: ?[]const u8 = null,
    sk: ?[]const u8 = null,
    pk: ?[]const u8 = null,
    sig: ?[]const u8 = null,
    verdict: ?[]const u8 = null,
    decode: ?bool = null,
    valid: ?bool = null,
    g1: ?bool = null,
    bytes: ?[]const u8 = null,
    in: ?[]const u8 = null,
    ok: ?bool = null,
    sigs: ?[]const []const u8 = null,
    pks: ?[]const []const u8 = null,
    msgs: ?[]const []const u8 = null,
};

fn need(v: anytype) !@TypeOf(v.?) {
    return v orelse error.MissingField;
}

fn runVectors(ctx: *harness.Ctx) !void {
    const names = [_][]const u8{
        "fastcrypto.jsonl",
        "upstream/expand_message_xmd_SHA256_38.json",
        "upstream/expand_message_xmd_SHA256_256.json",
        "upstream/BLS12381G1_XMD_SHA-256_SSWU_RO_.json",
        "upstream/BLS12381G1_XMD_SHA-256_SSWU_NU_.json",
        "upstream/BLS12381G2_XMD_SHA-256_SSWU_RO_.json",
        "upstream/BLS12381G2_XMD_SHA-256_SSWU_NU_.json",
    };
    try ctx.forEachName(&names, {}, vectorFile);
}

fn vectorFile(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const path = try std.fmt.allocPrint(ctx.scratch(), "vectors/bls12381/{s}", .{name});
    const text = try ctx.readFile(path, 64 << 20);
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    if (std.mem.endsWith(u8, name, ".jsonl")) {
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            if (ctx.done()) return;
            _ = arena.reset(.retain_capacity);
            const a = arena.allocator();
            const v = try std.json.parseFromSliceLeaky(VecLine, a, line, .{ .ignore_unknown_fields = true });
            if (!ctx.selected(v.id)) continue;
            vectorLine(ctx, a, &v) catch |e| ctx.fail(v.id, "error {s}", .{@errorName(e)});
        }
    } else if (std.mem.indexOf(u8, name, "expand_message") != null) {
        try expandFile(ctx, arena.allocator(), name, text);
    } else {
        try h2cFile(ctx, arena.allocator(), name, text);
    }
}

fn verifyVerdict(pk_b: []const u8, msg: []const u8, sig_b: []const u8) []const u8 {
    const pk = sig.PublicKey.decode(pk_b) orelse return "pk-decode";
    const s = sig.Signature.decode(sig_b) orelse return "sig-decode";
    return if (sig.verify(&pk, msg, &s)) "ok" else "invalid";
}

fn decodePks(a: std.mem.Allocator, hexes: []const []const u8) ![]sig.PublicKey {
    const out = try a.alloc(sig.PublicKey, hexes.len);
    for (hexes, out) |h, *o| o.* = sig.PublicKey.decode(try hexAlloc(a, h)) orelse return error.TruthKeyDecode;
    return out;
}

fn vectorLine(ctx: *harness.Ctx, a: std.mem.Allocator, v: *const VecLine) !void {
    var c = ctx.check(v.id);
    const op = v.op;
    if (std.mem.eql(u8, op, "hash_to_g1")) {
        const msg = try hexAlloc(a, try need(v.msg));
        const dst = try hexAlloc(a, try need(v.dst));
        const got = encoding.g1Compress(h2c.hashToG1(msg, dst).toAffine());
        c.bytes("hash_to_g1", try hexAlloc(a, try need(v.out)), &got);
    } else if (std.mem.eql(u8, op, "sk_to_pk")) {
        const skb = try hexFixed(32, try need(v.sk));
        const sk = sig.SecretKey.fromBytes(&skb) orelse return error.SecretKeyRejected;
        c.bytes("pk", try hexAlloc(a, try need(v.pk)), &sk.publicKey().toBytes());
    } else if (std.mem.eql(u8, op, "sk_decode")) {
        const skb = try hexAlloc(a, try need(v.sk));
        const got = skb.len == 32 and sig.SecretKey.fromBytes(skb[0..32]) != null;
        c.eql("decode", try need(v.decode), got);
    } else if (std.mem.eql(u8, op, "sign")) {
        const skb = try hexFixed(32, try need(v.sk));
        const sk = sig.SecretKey.fromBytes(&skb) orelse return error.SecretKeyRejected;
        const msg = try hexAlloc(a, try need(v.msg));
        c.bytes("sig", try hexAlloc(a, try need(v.sig)), &sk.sign(msg).toBytes());
    } else if (std.mem.eql(u8, op, "verify")) {
        const got = verifyVerdict(try hexAlloc(a, try need(v.pk)), try hexAlloc(a, try need(v.msg)), try hexAlloc(a, try need(v.sig)));
        c.text("verdict", try need(v.verdict), got);
    } else if (std.mem.eql(u8, op, "sig_decode")) {
        const in = try hexAlloc(a, try need(v.in));
        const s = sig.Signature.decode(in);
        c.eql("decode", try need(v.decode), s != null);
        if (s) |x| c.bytes("bytes", try hexAlloc(a, try need(v.bytes)), &x.toBytes());
        if (v.g1) |want| {
            if (in.len != 48) return error.G1CheckNeeds48Bytes;
            const got = switch (encoding.g1Uncompress(in[0..48])) {
                .ok => |p| p.isInfinity() or curve.g1AffineInGroup(p),
                .err => false,
            };
            c.eql("g1", want, got);
        }
    } else if (std.mem.eql(u8, op, "pk_decode")) {
        const in = try hexAlloc(a, try need(v.in));
        const pk = sig.PublicKey.decode(in);
        c.eql("decode", try need(v.decode), pk != null);
        if (pk) |x| {
            c.eql("valid", try need(v.valid), x.validate());
            c.bytes("bytes", try hexAlloc(a, try need(v.bytes)), &x.toBytes());
        }
    } else if (std.mem.eql(u8, op, "aggregate")) {
        const hs = try need(v.sigs);
        const sigs = try a.alloc(sig.Signature, hs.len);
        for (hs, sigs) |h, *o| o.* = sig.Signature.decode(try hexAlloc(a, h)) orelse return error.TruthSigDecode;
        const agg = sig.aggregate(sigs) orelse return error.EmptyAggregate;
        c.bytes("out", try hexAlloc(a, try need(v.out)), &agg.toBytes());
    } else if (std.mem.eql(u8, op, "fast_aggregate_verify")) {
        const pks = try decodePks(a, try need(v.pks));
        const s = sig.Signature.decode(try hexAlloc(a, try need(v.sig))) orelse return error.TruthSigDecode;
        c.eql("ok", try need(v.ok), sig.fastAggregateVerify(pks, try hexAlloc(a, try need(v.msg)), &s));
    } else if (std.mem.eql(u8, op, "aggregate_verify")) {
        const pks = try decodePks(a, try need(v.pks));
        const mh = try need(v.msgs);
        const msgs = try a.alloc([]const u8, mh.len);
        for (mh, msgs) |h, *o| o.* = try hexAlloc(a, h);
        const s = sig.Signature.decode(try hexAlloc(a, try need(v.sig))) orelse return error.TruthSigDecode;
        c.eql("ok", try need(v.ok), sig.aggregateVerify(pks, msgs, &s));
    } else {
        c.failf("unknown op {s}", .{op});
    }
    _ = c.finish();
}

const ExpandFile = struct {
    DST: []const u8,
    tests: []const struct { len_in_bytes: []const u8, msg: []const u8, uniform_bytes: []const u8 },
};

fn expandFile(ctx: *harness.Ctx, a: std.mem.Allocator, name: []const u8, text: []const u8) !void {
    const f = try std.json.parseFromSliceLeaky(ExpandFile, a, text, .{ .ignore_unknown_fields = true });
    for (f.tests, 0..) |t, i| {
        const id = try std.fmt.allocPrint(a, "rfc9380/{s}/{d}", .{ name, i });
        if (!ctx.selected(id)) continue;
        const len = try std.fmt.parseInt(usize, t.len_in_bytes, 0);
        const want = try hexAlloc(a, t.uniform_bytes);
        const got = try a.alloc(u8, len);
        h2c.expandMessageXmd(got, t.msg, f.DST);
        _ = ctx.expectBytes(id, "uniform_bytes", want, got);
    }
}

const H2cPoint = struct { x: []const u8, y: []const u8 };
const H2cFile = struct {
    dst: []const u8,
    vectors: []const struct { msg: []const u8, P: H2cPoint, Q0: ?H2cPoint = null, Q1: ?H2cPoint = null, Q: ?H2cPoint = null, u: []const []const u8 },
};

/// "0x<hex>" (Fp) or "0x<c0>,0x<c1>" (Fp2) as the big-endian bytes deepwave serializes: c1 || c0.
fn rfcCoord(a: std.mem.Allocator, s: []const u8) ![]u8 {
    var parts: [2][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |p| : (n += 1) {
        if (n == 2) return error.BadCoord;
        parts[n] = if (std.mem.startsWith(u8, p, "0x")) p[2..] else p;
    }
    const out = try a.alloc(u8, 48 * n);
    for (0..n) |i| {
        const v = try std.fmt.parseInt(u384, parts[i], 16);
        // written c1 then c0
        std.mem.writeInt(u384, out[48 * (n - 1 - i) ..][0..48], v, .big);
    }
    return out;
}

fn h2cFile(ctx: *harness.Ctx, a: std.mem.Allocator, name: []const u8, text: []const u8) !void {
    const f = try std.json.parseFromSliceLeaky(H2cFile, a, text, .{ .ignore_unknown_fields = true });
    const g2 = std.mem.indexOf(u8, name, "G2") != null;
    const ro = std.mem.indexOf(u8, name, "_RO_") != null;
    for (f.vectors, 0..) |t, i| {
        const id = try std.fmt.allocPrint(a, "rfc9380/{s}/{d}", .{ name, i });
        if (!ctx.selected(id)) continue;
        var c = ctx.check(id);
        const want_p = try std.mem.concat(a, u8, &.{ try rfcCoord(a, t.P.x), try rfcCoord(a, t.P.y) });
        const q0 = t.Q0 orelse t.Q;
        if (g2) {
            // hash_to_curve hashes two field elements, encode_to_curve one (different expand lengths)
            var u: [2]bls.Fp2 = undefined;
            if (ro) u = h2c.hashToFieldFp2(2, t.msg, f.dst) else u[0] = h2c.hashToFieldFp2(1, t.msg, f.dst)[0];
            const p = if (ro) h2c.hashToG2(t.msg, f.dst) else h2c.encodeToG2(t.msg, f.dst);
            c.bytes("P", want_p, &encoding.g2Serialize(p.toAffine()));
            for (0..if (ro) 2 else 1) |k| {
                const got_u = try std.mem.concat(a, u8, &.{ &u[k].c1.toBytesBE(), &u[k].c0.toBytesBE() });
                c.bytes("u", try rfcCoord(a, t.u[k]), got_u);
            }
            if (q0) |q| {
                const want = try std.mem.concat(a, u8, &.{ try rfcCoord(a, q.x), try rfcCoord(a, q.y) });
                c.bytes("Q0", want, &encoding.g2Serialize(h2c.isoMapG2(h2c.sswuG2(u[0]))));
            }
            if (t.Q1) |q| {
                const want = try std.mem.concat(a, u8, &.{ try rfcCoord(a, q.x), try rfcCoord(a, q.y) });
                c.bytes("Q1", want, &encoding.g2Serialize(h2c.isoMapG2(h2c.sswuG2(u[1]))));
            }
        } else {
            var u: [2]bls.Fp = undefined;
            if (ro) u = h2c.hashToFieldFp(2, t.msg, f.dst) else u[0] = h2c.hashToFieldFp(1, t.msg, f.dst)[0];
            const p = if (ro) h2c.hashToG1(t.msg, f.dst) else h2c.encodeToG1(t.msg, f.dst);
            c.bytes("P", want_p, &encoding.g1Serialize(p.toAffine()));
            for (0..if (ro) 2 else 1) |k| c.bytes("u", try rfcCoord(a, t.u[k]), &u[k].toBytesBE());
            if (q0) |q| {
                const want = try std.mem.concat(a, u8, &.{ try rfcCoord(a, q.x), try rfcCoord(a, q.y) });
                c.bytes("Q0", want, &encoding.g1Serialize(h2c.isoMapG1(h2c.sswuG1(u[0])).toAffine()));
            }
            if (t.Q1) |q| {
                const want = try std.mem.concat(a, u8, &.{ try rfcCoord(a, q.x), try rfcCoord(a, q.y) });
                c.bytes("Q1", want, &encoding.g1Serialize(h2c.isoMapG1(h2c.sswuG1(u[1])).toAffine()));
            }
        }
        _ = c.finish();
    }
}

// ---------------------------------------------------------------------------------------------
// bls-cert

const CommitteeLine = struct { epoch: u64, keys: []const []const u8 };
const CertLine = struct { seq: u64, case: []const u8, signers: []const u32, msg: []const u8, sig: []const u8, verdict: []const u8 };

fn verdictText(v: sig.CertVerdict) []const u8 {
    return switch (v) {
        .ok => "ok",
        .invalid => "invalid",
        .sig_decode => "decode",
        .unknown_signer => "unknown-signer",
    };
}

fn prepare(arena: std.mem.Allocator, line: []const u8) !sig.PreparedCommittee {
    const cl = try std.json.parseFromSliceLeaky(CommitteeLine, arena, line, .{ .ignore_unknown_fields = true });
    const keys = try arena.alloc([96]u8, cl.keys.len);
    for (cl.keys, keys) |h, *k| k.* = try hexFixed(96, h);
    return sig.PreparedCommittee.init(arena, keys);
}

fn runCerts(ctx: *harness.Ctx) !void {
    try ctx.forEachFile("vectors/bls-cert", ".jsonl", {}, certFile);
    const n = certBatchSize();
    if (n > 1) {
        const t = &cert_batch_totals;
        std.debug.print("bls-cert through verifyCertBatch, lists of {d}: early={d} off_g2={d} equations={d} failed={d} batch_ok={d} singles={d} no_memory={d}\n", .{
            n,                         t[0].load(.monotonic), t[1].load(.monotonic), t[2].load(.monotonic),
            t[3].load(.monotonic), t[4].load(.monotonic), t[5].load(.monotonic), t[6].load(.monotonic),
        });
    }
}

/// ZUI_BLS_CERT_BATCH=N (N > 1) sends the suite's certificates through `sig.verifyCertBatch`
/// in lists of N per epoch file: the real certificates in lists of their own (the catch-up
/// shape: every batch equation must hold) and the mutated ones in lists of their own (decided
/// before the equation, or by the single check after it fails). Every verdict must still be
/// the one Mysten's path gave. Unset: one `verifyAggregateVerdict` per certificate.
fn certBatchSize() usize {
    const v = std.c.getenv("ZUI_BLS_CERT_BATCH") orelse return 0;
    return std.fmt.parseInt(usize, std.mem.span(v), 10) catch 0;
}

/// CertBatchStats summed over the suite's workers: early, off_g2, equations, failed, batch_ok,
/// singles, no_memory.
var cert_batch_totals: [7]std.atomic.Value(usize) = @splat(.init(0));

const CertList = struct {
    certs: std.ArrayList(sig.CertItem) = .empty,
    ids: std.ArrayList([]const u8) = .empty,
    want: std.ArrayList([]const u8) = .empty,

    fn flush(l: *CertList, ctx: *harness.Ctx, a: std.mem.Allocator, rng: std.Random, st: *sig.CertBatchStats) !void {
        const n = l.certs.items.len;
        if (n == 0) return;
        const out = try a.alloc(sig.CertVerdict, n);
        sig.verifyCertBatch(ctx.gpa, l.certs.items, rng, .{ .max_batch = n, .stats = st }, out);
        for (l.ids.items, l.want.items, out) |id, want, got| _ = ctx.expectText(id, "verdict", want, verdictText(got));
        l.certs.clearRetainingCapacity();
        l.ids.clearRetainingCapacity();
        l.want.clearRetainingCapacity();
    }
};

/// One epoch file through `verifyCertBatch` in lists of `n`. The file's lines stay in one arena
/// until its last list is checked.
fn certFileBatched(ctx: *harness.Ctx, committee: *const sig.PreparedCommittee, it: *std.mem.SplitIterator(u8, .scalar), n: usize) !void {
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var seed: [32]u8 = undefined;
    ctx.io.random(&seed);
    var chacha = std.Random.ChaCha.init(seed);
    const rng = chacha.random();
    var st: sig.CertBatchStats = .{};
    var real: CertList = .{};
    var mutated: CertList = .{};
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (ctx.done()) break;
        const cl = try std.json.parseFromSliceLeaky(CertLine, a, line, .{ .ignore_unknown_fields = true });
        const id = try std.fmt.allocPrint(a, "{d}/{s}", .{ cl.seq, cl.case });
        if (!ctx.selected(id)) continue;
        const msg = try hexAlloc(a, cl.msg);
        const sigb = try hexAlloc(a, cl.sig);
        if (sigb.len != 48) {
            // the certificate field is a fixed 48-byte BCS array
            _ = ctx.expectText(id, "verdict", cl.verdict, verdictText(.sig_decode));
            continue;
        }
        const l = if (std.mem.eql(u8, cl.case, "real")) &real else &mutated;
        try l.certs.append(a, .{ .committee = committee, .signers = cl.signers, .msg = msg, .agg_sig = sigb[0..48] });
        try l.ids.append(a, id);
        try l.want.append(a, cl.verdict);
        if (l.certs.items.len >= n) try l.flush(ctx, a, rng, &st);
    }
    try real.flush(ctx, a, rng, &st);
    try mutated.flush(ctx, a, rng, &st);
    const t = &cert_batch_totals;
    for ([_]usize{ st.early, st.off_g2, st.batch.equations, st.batch.failed, st.batch.batch_ok, st.batch.singles, st.no_memory }, 0..) |v, i| {
        _ = t[i].fetchAdd(v, .monotonic);
    }
}

fn certFile(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const path = try std.fmt.allocPrint(ctx.scratch(), "vectors/bls-cert/{s}", .{name});
    const text = try ctx.readFile(path, 256 << 20);
    var it = std.mem.splitScalar(u8, text, '\n');
    const first = it.next() orelse return error.EmptyCertFile;
    const committee = try prepare(ctx.scratch(), first);
    const batch = certBatchSize();
    if (batch > 1) return certFileBatched(ctx, &committee, &it, batch);
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (ctx.done()) return;
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        const cl = try std.json.parseFromSliceLeaky(CertLine, a, line, .{ .ignore_unknown_fields = true });
        const id = try std.fmt.allocPrint(a, "{d}/{s}", .{ cl.seq, cl.case });
        if (!ctx.selected(id)) continue;
        const msg = try hexAlloc(a, cl.msg);
        const sigb = try hexAlloc(a, cl.sig);
        // the certificate field is a fixed 48-byte BCS array
        const got: sig.CertVerdict = if (sigb.len != 48) .sig_decode else committee.verifyAggregateVerdict(cl.signers, msg, sigb[0..48]);
        _ = ctx.expectText(id, "verdict", cl.verdict, verdictText(got));
    }
}

const BenchCert = struct { signers: []const u32, msg: []const u8, sig: *const [48]u8 };
const BenchEpoch = struct { keys: []const [96]u8, committee: sig.PreparedCommittee, certs: []const BenchCert };
const BenchState = struct { epochs: []const BenchEpoch, arena: *std.heap.ArenaAllocator };

const BatchBench = struct {
    epochs: []const BenchEpoch,
    items: []sig.BatchItem,
    out: []bool,
    pool: *core.pool.Pool,
    rng: std.Random,
    gpa: std.mem.Allocator,
    /// Certificates per batch (0: the whole epoch's set at once).
    k: usize = 0,
    /// Lanes (0: the whole pool).
    lanes: usize = 0,

    fn with(b: BatchBench, k: usize, lanes: usize) BatchBench {
        var c = b;
        c.k = k;
        c.lanes = lanes;
        return c;
    }

    const Single = struct {
        e: *const BenchEpoch,
        fn f(j: Single, lo: usize, hi: usize) void {
            for (j.e.certs[lo..hi]) |*c| {
                if (!j.e.committee.verifyAggregate(c.signers, c.msg, c.sig)) @panic("bench certificate rejected");
            }
        }
    };

    /// Single checks spread over the pool's lanes (today's follower: one worker per certificate).
    fn singles(b: BatchBench) !void {
        for (b.epochs) |*e| b.pool.forRange(e.certs.len, 1, b.lanes, Single{ .e = e }, Single.f);
    }

    fn batches(b: BatchBench) !void {
        for (b.epochs) |*e| {
            const n = e.certs.len;
            for (e.certs, b.items[0..n]) |*c, *it| {
                const s = sig.Signature.decode(c.sig) orelse return error.BenchCertRejected;
                const pk = switch (e.committee.aggregateKey(c.signers)) {
                    .ok => |x| x,
                    else => return error.BenchCertRejected,
                };
                it.* = .{ .pk = pk, .msg = c.msg, .sig = s.point };
            }
            const step = if (b.k == 0) n else b.k;
            var lo: usize = 0;
            while (lo < n) : (lo += step) {
                const hi = @min(n, lo + step);
                sig.verifyBatchValidated(b.gpa, b.items[lo..hi], e.committee.g2_lines, b.rng, .{ .pool = b.pool, .max_lanes = if (b.lanes == 0) 0 else b.lanes, .keys_in_group = true, .max_batch = @max(1024, step) }, b.out[lo..hi]);
            }
            for (b.out[0..n]) |ok| if (!ok) return error.BenchCertRejected;
        }
    }
};

fn benchCerts(ctx: *harness.Ctx) !void {
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const inputs = ctx.benchInputs();
    const epochs = try a.alloc(BenchEpoch, inputs.len);
    var units: u64 = 0;
    var n_keys: u64 = 0;
    for (inputs, epochs) |p, *e| {
        const text = try ctx.corpus.readFileAlloc(ctx.io, p, a, .limited(256 << 20));
        var it = std.mem.splitScalar(u8, text, '\n');
        const first = it.next() orelse return error.EmptyCertFile;
        const cl = try std.json.parseFromSliceLeaky(CommitteeLine, a, first, .{ .ignore_unknown_fields = true });
        const keys = try a.alloc([96]u8, cl.keys.len);
        for (cl.keys, keys) |h, *k| k.* = try hexFixed(96, h);
        var certs: std.ArrayList(BenchCert) = .empty;
        while (it.next()) |line| {
            if (line.len == 0) continue;
            const c = try std.json.parseFromSliceLeaky(CertLine, a, line, .{ .ignore_unknown_fields = true });
            if (!std.mem.eql(u8, c.case, "real")) continue;
            const s = try a.create([48]u8);
            s.* = try hexFixed(48, c.sig);
            try certs.append(a, .{ .signers = c.signers, .msg = try hexAlloc(a, c.msg), .sig = s });
        }
        e.* = .{ .keys = keys, .committee = try sig.PreparedCommittee.init(a, keys), .certs = certs.items };
        units += certs.items.len;
        n_keys += keys.len;
    }
    var prep_arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer prep_arena.deinit();
    const st: BenchState = .{ .epochs = epochs, .arena = &prep_arena };
    try ctx.benchPasses("cert-verify", "cert", units, st, struct {
        fn f(s: BenchState) !void {
            for (s.epochs) |*e| for (e.certs) |*c| {
                if (!e.committee.verifyAggregate(c.signers, c.msg, c.sig)) return error.BenchCertRejected;
            };
        }
    }.f);
    // The follower's certificate batching (sync.follower Config.cert_batch, sync.verify
    // prepCert + pairingVerdicts): per certificate the signature decode and aggregate key, then
    // randomized batches with keys_in_group. Same certificates; lanes 1 and the pool (at most 6).
    const lanes = @min(6, std.Thread.getCpuCount() catch 1);
    const pool = try core.pool.Pool.init(ctx.io, ctx.gpa, lanes);
    defer pool.deinit();
    var seed: [32]u8 = undefined;
    ctx.io.random(&seed);
    var chacha = std.Random.ChaCha.init(seed);
    var max_certs: usize = 0;
    for (epochs) |e| max_certs = @max(max_certs, e.certs.len);
    const bst: BatchBench = .{
        .epochs = epochs,
        .items = try a.alloc(sig.BatchItem, max_certs),
        .out = try a.alloc(bool, max_certs),
        .pool = pool,
        .rng = chacha.random(),
        .gpa = ctx.gpa,
    };
    try ctx.benchPasses("cert-verify-pool", "cert", units, BatchBench.with(bst, 0, 0), BatchBench.singles);
    inline for (.{ .{ "cert-verify-batch32", 32, 1 }, .{ "cert-verify-batch32-pool", 32, 0 }, .{ "cert-verify-batchall", 0, 1 }, .{ "cert-verify-batchall-pool", 0, 0 } }) |row| {
        try ctx.benchPasses(row[0], "cert", units, BatchBench.with(bst, row[1], row[2]), BatchBench.batches);
    }
    try ctx.benchPasses("committee-g2-check", "key", n_keys, st, struct {
        fn f(s: BenchState) !void {
            for (s.epochs) |*e| for (e.committee.keys) |k| {
                if (!k.isInfinity() and !curve.g2AffineInGroup(k)) return error.BenchKeyNotInG2;
            };
        }
    }.f);
    try ctx.benchPasses("committee-prepare", "key", n_keys, st, struct {
        fn f(s: BenchState) !void {
            for (s.epochs) |*e| {
                _ = s.arena.reset(.retain_capacity);
                const c = try sig.PreparedCommittee.init(s.arena.allocator(), e.keys);
                std.mem.doNotOptimizeAway(&c);
            }
        }
    }.f);
}

// ---------------------------------------------------------------------------------------------
// bls-group-ops

const GroupLine = struct {
    id: []const u8,
    op: []const u8,
    g: u8,
    to: ?u8 = null,
    a: ?[]const u8 = null,
    b: ?[]const u8 = null,
    terms: ?[]const []const u8 = null,
    ok: ?bool = null,
    out: ?[]const u8 = null,
};

fn runGroupOps(ctx: *harness.Ctx) !void {
    const names = [_][]const u8{"fastcrypto.jsonl"};
    try ctx.forEachName(&names, {}, groupOpsFile);
}

fn groupOpsFile(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const path = try std.fmt.allocPrint(ctx.scratch(), "vectors/bls-group-ops/{s}", .{name});
    const text = try ctx.readFile(path, 64 << 20);
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (ctx.done()) return;
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        const v = try std.json.parseFromSliceLeaky(GroupLine, a, line, .{ .ignore_unknown_fields = true });
        if (!ctx.selected(v.id)) continue;
        groupOpsLine(ctx, a, &v) catch |e| ctx.fail(v.id, "error {s}", .{@errorName(e)});
    }
}

fn groupOpsLine(ctx: *harness.Ctx, a: std.mem.Allocator, v: *const GroupLine) !void {
    const go = bls.group_ops;
    const g: go.Group = @enumFromInt(v.g);
    const x = if (v.a) |h| try hexAlloc(a, h) else &[_]u8{};
    const y = if (v.b) |h| try hexAlloc(a, h) else &[_]u8{};
    var buf: [go.max_out]u8 = undefined;
    var c = ctx.check(v.id);
    if (std.mem.eql(u8, v.op, "validate")) {
        c.eql("ok", try need(v.ok), go.validate(g, x));
        _ = c.finish();
        return;
    }
    const got: go.Error![]const u8 = if (std.mem.eql(u8, v.op, "add"))
        go.add(g, x, y, &buf)
    else if (std.mem.eql(u8, v.op, "sub"))
        go.sub(g, x, y, &buf)
    else if (std.mem.eql(u8, v.op, "mul"))
        go.mul(g, x, y, &buf)
    else if (std.mem.eql(u8, v.op, "div"))
        go.div(g, x, y, &buf)
    else if (std.mem.eql(u8, v.op, "hash_to"))
        go.hashTo(g, x, &buf)
    else if (std.mem.eql(u8, v.op, "msm"))
        go.multiScalarMul(g, x, y, &buf)
    else if (std.mem.eql(u8, v.op, "pairing"))
        go.pairing(g, x, y, &buf)
    else if (std.mem.eql(u8, v.op, "convert"))
        go.convert(g, @enumFromInt(try need(v.to)), x, &buf)
    else if (std.mem.eql(u8, v.op, "sum")) blk: {
        const th = try need(v.terms);
        const terms = try a.alloc([]const u8, th.len);
        for (th, terms) |h, *t| t.* = try hexAlloc(a, h);
        break :blk go.sum(g, terms, &buf);
    } else {
        c.failf("unknown op {s}", .{v.op});
        _ = c.finish();
        return;
    };
    if (v.out) |want_hex| {
        if (got) |bytes| c.bytes("out", try hexAlloc(a, want_hex), bytes) else |_| c.failf("expected a value, got InvalidInput", .{});
    } else {
        if (got) |bytes| c.failf("expected InvalidInput, got {d} bytes", .{bytes.len}) else |_| {}
    }
    _ = c.finish();
}
