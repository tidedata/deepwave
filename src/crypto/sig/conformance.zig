//! Conformance suites of the crypto-sig lane (CONTRACTS.md section 3.3). Truth comes from
//! `tools/truth/crypto-sig` (zui-truth-sig, linking fastcrypto and sui-types at mainnet-v1.83.1);
//! formats are in tools/truth/crypto-sig/README.md.
//!
//! sig-vectors: one item per line of vectors/sig-vectors/vectors.jsonl (Wycheproof, ZIP-215,
//!   generated sign/verify/recover/batch vectors). Compares the verdict string, the signature
//!   bytes for sign, and the recovered key for recover.
//! sig-corpus: one item per line of vectors/sig-corpus/<seq>.jsonl.zst after the header: every
//!   user signature in the corpus checkpoint (bytes taken from chk/<seq>.chk at the offsets in
//!   the dumper truth), plus seeded mutations of it, through GenericSignature parsing, address
//!   derivation and verify_authenticator; and every transaction through
//!   verify_sender_signed_data_message_signatures with the address aliases the checkpoint pins
//!   and the JWKs the validators held (verdict and signature indices).
const std = @import("std");
const harness = @import("harness");
const ed25519 = @import("ed25519.zig");
const ecdsa = @import("ecdsa.zig");
const user = @import("user.zig");
const rst = @import("ristretto255.zig");
const ecvrf = @import("ecvrf.zig");
const verdict_mod = @import("verdict.zig");
const zkl = @import("zk").zklogin;
const sig_fast = @import("fast.zig");
const batch = @import("batch.zig");
const core = @import("core");
const Verdict = verdict_mod.Verdict;

pub const suites = [_]harness.Suite{
    .{
        .name = "sig-vectors",
        .lane = "crypto-sig",
        .doc = "ed25519/secp256k1/secp256r1 sign+verify+recover+batch vs fastcrypto, Wycheproof, ZIP-215 vectors; synthesized user signatures and alias tx sets; mainnet zkLogin signatures as MultiSig members and under flag/epoch/JWK variants",
        .run = runVectors,
        .bench = benchVectors,
        .baselines = &.{
            .{ .name = "ed25519-verify", .argv = &.{ "{release}/zui-truth-sig", "bench", "ed25519-verify" } },
            .{ .name = "ed25519-verify-bytes", .argv = &.{ "{release}/zui-truth-sig", "bench", "ed25519-verify-bytes" } },
            .{ .name = "ed25519-batch", .argv = &.{ "{release}/zui-truth-sig", "bench", "ed25519-batch" } },
            .{ .name = "ed25519-sign", .argv = &.{ "{release}/zui-truth-sig", "bench", "ed25519-sign" } },
            .{ .name = "secp256k1-verify", .argv = &.{ "{release}/zui-truth-sig", "bench", "secp256k1-verify" } },
            .{ .name = "secp256r1-verify", .argv = &.{ "{release}/zui-truth-sig", "bench", "secp256r1-verify" } },
            .{ .name = "secp256k1-recover", .argv = &.{ "{release}/zui-truth-sig", "bench", "secp256k1-recover" } },
            .{ .name = "secp256r1-recover", .argv = &.{ "{release}/zui-truth-sig", "bench", "secp256r1-recover" } },
        },
        .inputs = .{ .dir = "vectors/sig-vectors", .suffix = "vectors.jsonl" },
    },
    .{
        .name = "sig-corpus",
        .lane = "crypto-sig",
        .doc = "every user signature in corpus checkpoints, zkLogin included (+ seeded mutations), and every tx signature set with its pinned address aliases: verdict, address and indices equal Rust",
        .run = runCorpus,
        .bench = benchCorpus,
        .baselines = &.{.{ .name = "user-sig", .argv = &.{ "{release}/zui-truth-sig", "bench", "user-sig" } }},
    },
    .{
        .name = "ecmh",
        .lane = "crypto-sig",
        .doc = "Ristretto EllipticCurveMultisetHash (state accumulator): insert/remove/union digests and bytes, from_bytes verdicts vs fastcrypto",
        .run = runEcmh,
        .bench = benchEcmh,
        .baselines = &.{.{ .name = "ecmh-insert", .argv = &.{ "{release}/zui-truth-sig", "bench", "ecmh-insert" } }},
        .inputs = .{ .dir = "vectors/ecmh", .suffix = "vectors.jsonl" },
    },
    .{
        .name = "ecvrf",
        .lane = "crypto-sig",
        .doc = "ECVRF (ristretto255, sui_vrf) prove bytes and output, and the sui::ecvrf native verify verdicts vs fastcrypto",
        .run = runEcvrf,
        .bench = benchEcvrf,
        .baselines = &.{
            .{ .name = "ecvrf-prove", .argv = &.{ "{release}/zui-truth-sig", "bench", "ecvrf-prove" } },
            .{ .name = "ecvrf-verify", .argv = &.{ "{release}/zui-truth-sig", "bench", "ecvrf-verify" } },
        },
        .inputs = .{ .dir = "vectors/ecvrf", .suffix = "vectors.jsonl" },
    },
    .{
        .name = "sig-fast",
        .lane = "crypto-sig",
        .doc = "sig.fast layer (off by default): parallel Ed25519 batches (spawned and pooled) give the verdict of ed25519.verifyBatch and of single checks on every corpus Ed25519 user signature, honest and with one corrupted; bench: key-decode caches, zkLogin cache and parallel batch, on vs off",
        .run = runFast,
        .bench = benchFast,
    },
};

// ---------------------------------------------------------------------------------------------
// ecmh

const ecmh_path = "vectors/ecmh/vectors.jsonl";
const ecvrf_path = "vectors/ecvrf/vectors.jsonl";

fn ecmhRun(a: std.mem.Allocator, ops: []const std.json.Value) !rst.Ecmh {
    var acc: rst.Ecmh = .{};
    for (ops) |o| {
        const arr = o.array.items;
        const k = arr[0].string;
        if (std.mem.eql(u8, k, "i")) {
            acc.insert(try unhex(a, arr[1].string));
        } else if (std.mem.eql(u8, k, "r")) {
            acc.remove(try unhex(a, arr[1].string));
        } else if (std.mem.eql(u8, k, "u")) {
            const other = try ecmhRun(a, arr[1].array.items);
            acc.add(&other);
        } else return error.BadVector;
    }
    return acc;
}

fn runEcmh(ctx: *harness.Ctx) !void {
    const text = try ctx.corpus.readFileAlloc(ctx.io, ecmh_path, ctx.gpa, .limited(1 << 30));
    defer ctx.gpa.free(text);
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) break;
        _ = arena_state.reset(.retain_capacity);
        const a = arena_state.allocator();
        const v = (try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{})).object;
        const id = v.get("id").?.string;
        if (!ctx.selected(id)) continue;
        var c = ctx.check(id);
        const op = v.get("op").?.string;
        if (std.mem.eql(u8, op, "ecmh")) {
            const acc = try ecmhRun(a, v.get("ops").?.array.items);
            c.bytes("accumulator bytes", try unhex(a, v.get("acc").?.string), &acc.toBytes());
            c.bytes("digest", try unhex(a, v.get("digest").?.string), &acc.digest());
        } else if (std.mem.eql(u8, op, "ecmh_from_bytes")) {
            const b = try unhex(a, v.get("bytes").?.string);
            const want = v.get("v").?.string;
            if (rst.Ecmh.fromBytes(b)) |acc| {
                c.text("verdict", want, "ok");
                if (v.get("digest").? == .string) {
                    c.bytes("digest", try unhex(a, v.get("digest").?.string), &acc.digest());
                    c.bytes("accumulator bytes", try unhex(a, v.get("acc").?.string), &acc.toBytes());
                }
            } else c.text("verdict", want, "err");
        } else return error.UnknownOp;
        _ = c.finish();
    }
}

fn benchEcmh(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var items: std.ArrayList([]const u8) = .empty;
    for (ctx.benchInputs()) |path| {
        const text = try ctx.corpus.readFileAlloc(ctx.io, path, a, .limited(1 << 30));
        var it = harness.lines(text);
        while (it.next()) |line| {
            const v = (try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{})).object;
            if (!std.mem.eql(u8, v.get("op").?.string, "ecmh")) continue;
            for (v.get("ops").?.array.items) |o| {
                const arr = o.array.items;
                if (std.mem.eql(u8, arr[0].string, "i")) try items.append(a, try unhex(a, arr[1].string));
            }
        }
    }
    const B = struct {
        fn run(xs: []const []const u8) !void {
            var acc: rst.Ecmh = .{};
            acc.insertAll(xs);
            std.mem.doNotOptimizeAway(acc.digest());
        }
    };
    try ctx.benchPasses("ecmh-insert", "item", items.items.len, @as([]const []const u8, items.items), B.run);
}

// ---------------------------------------------------------------------------------------------
// ecvrf

const VrfVec = struct {
    id: []const u8,
    op: []const u8,
    sk: ?[]const u8 = null,
    alpha: []const u8,
    pk: []const u8,
    proof: []const u8,
    output: ?[]const u8 = null,
    hash: ?[]const u8 = null,
    v: ?[]const u8 = null,
};

fn runEcvrf(ctx: *harness.Ctx) !void {
    const text = try ctx.corpus.readFileAlloc(ctx.io, ecvrf_path, ctx.gpa, .limited(1 << 30));
    defer ctx.gpa.free(text);
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) break;
        _ = arena_state.reset(.retain_capacity);
        const a = arena_state.allocator();
        const v = try std.json.parseFromSliceLeaky(VrfVec, a, line, .{ .ignore_unknown_fields = true });
        if (!ctx.selected(v.id)) continue;
        var c = ctx.check(v.id);
        const alpha = try unhex(a, v.alpha);
        if (std.mem.eql(u8, v.op, "ecvrf_prove")) {
            const sk = try unhex(a, v.sk.?);
            if (sk.len != 32) return error.BadVector;
            if (ecvrf.KeyPair.fromSecret(sk[0..32])) |kp| {
                const o = kp.output(alpha);
                c.bytes("public key", try unhex(a, v.pk), &kp.pk);
                c.bytes("proof", try unhex(a, v.proof), &o[1]);
                c.bytes("output", try unhex(a, v.output.?), &o[0]);
            } else c.failf("secret key rejected", .{});
        } else if (std.mem.eql(u8, v.op, "ecvrf_verify")) {
            const got = ecvrf.verifyNative(try unhex(a, v.hash.?), alpha, try unhex(a, v.pk), try unhex(a, v.proof));
            c.text("verdict", v.v.?, got.truthName());
        } else return error.UnknownOp;
        _ = c.finish();
    }
}

const VrfBench = struct {
    proves: std.ArrayList(struct { kp: ecvrf.KeyPair, alpha: []const u8 }) = .empty,
    verifies: std.ArrayList(struct { hash: []const u8, alpha: []const u8, pk: []const u8, proof: []const u8 }) = .empty,
};

fn benchEcvrf(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var st: VrfBench = .{};
    for (ctx.benchInputs()) |path| {
        const text = try ctx.corpus.readFileAlloc(ctx.io, path, a, .limited(1 << 30));
        var it = harness.lines(text);
        while (it.next()) |line| {
            const v = try std.json.parseFromSliceLeaky(VrfVec, a, line, .{ .ignore_unknown_fields = true });
            if (std.mem.eql(u8, v.op, "ecvrf_prove")) {
                const sk = try unhex(a, v.sk.?);
                try st.proves.append(a, .{ .kp = ecvrf.KeyPair.fromSecret(sk[0..32]).?, .alpha = try unhex(a, v.alpha) });
            } else if (v.v != null and std.mem.eql(u8, v.v.?, "true")) {
                try st.verifies.append(a, .{ .hash = try unhex(a, v.hash.?), .alpha = try unhex(a, v.alpha), .pk = try unhex(a, v.pk), .proof = try unhex(a, v.proof) });
            }
        }
    }
    const B = struct {
        fn prove(s: *const VrfBench) !void {
            for (s.proves.items) |*x| std.mem.doNotOptimizeAway(x.kp.output(x.alpha));
        }
        fn verify(s: *const VrfBench) !void {
            for (s.verifies.items) |x| std.mem.doNotOptimizeAway(ecvrf.verifyNative(x.hash, x.alpha, x.pk, x.proof));
        }
    };
    const s: *const VrfBench = &st;
    try ctx.benchPasses("ecvrf-prove", "proof", st.proves.items.len, s, B.prove);
    try ctx.benchPasses("ecvrf-verify", "proof", st.verifies.items.len, s, B.verify);
}

const vectors_path = "vectors/sig-vectors/vectors.jsonl";
/// Synthesized user signatures (MultiSig, MultiSigLegacy, Passkey, single-key encodings).
const user_vectors_path = "vectors/sig-vectors/user.jsonl";
const zk_vectors_dir = "vectors/sig-vectors/zk";
const corpus_dir = "vectors/sig-corpus";

// ---------------------------------------------------------------------------------------------
// helpers

fn unhex(a: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len % 2 != 0) return error.BadHex;
    const out = try a.alloc(u8, s.len / 2);
    _ = std.fmt.hexToBytes(out, s) catch return error.BadHex;
    return out;
}

fn hexLower(a: std.mem.Allocator, b: []const u8) ![]u8 {
    const out = try a.alloc(u8, b.len * 2);
    const digits = "0123456789abcdef";
    for (b, 0..) |x, i| {
        out[2 * i] = digits[x >> 4];
        out[2 * i + 1] = digits[x & 15];
    }
    return out;
}

fn hashKind(h: ?[]const u8) !ecdsa.HashKind {
    const s = h orelse return error.MissingHash;
    if (std.mem.eql(u8, s, "sha256")) return .sha256;
    if (std.mem.eql(u8, s, "keccak256")) return .keccak256;
    return error.UnknownHash;
}

// ---------------------------------------------------------------------------------------------
// sig-vectors

const Vec = struct {
    id: []const u8,
    op: []const u8,
    pk: ?[]const u8 = null,
    sk: ?[]const u8 = null,
    msg: ?[]const u8 = null,
    sig: ?[]const u8 = null,
    h: ?[]const u8 = null,
    out: ?[]const u8 = null,
    v: ?[]const u8 = null,
    items: ?[]const []const []const u8 = null,
    // user_sig
    author: ?[]const u8 = null,
    addr: ?[]const u8 = null,
    flags: ?Flags = null,
    // user_sig with a zkLogin environment (zk/ shards): the epoch and the JWK map the verdict used
    epoch: ?u64 = null,
    jwks: ?[]const Jwk = null,
    // user_tx
    sigs: ?[]const []const u8 = null,
    aliases: ?[]const std.json.Value = null,
    idx: ?[]const u64 = null,
};

/// ZUI_SIG_FAST=1 turns the whole signature speed layer on for the suite (default off), so the
/// same corpus can be checked with and without it; the verdicts must not differ.
fn sigFastFromEnv() void {
    const v = std.c.getenv("ZUI_SIG_FAST") orelse return;
    if (std.mem.eql(u8, std.mem.span(v), "1")) sig_fast.configure(sig_fast.all_on);
}

pub fn runVectors(ctx: *harness.Ctx) !void {
    sigFastFromEnv();
    try batchSetup(ctx);
    defer batchTeardown(ctx);
    try runVectorFile(ctx, vectors_path);
    try runVectorFile(ctx, user_vectors_path);
    try ctx.forEachFile(zk_vectors_dir, ".jsonl.zst", {}, zkVectorFile);
}

/// One `zk/NNN.jsonl.zst` shard (`zui-truth-sig zkvec`): mainnet zkLogin signatures as MultiSig
/// members and at top level under flag, epoch, provider and JWK variants. Shards run in parallel.
fn zkVectorFile(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    var pbuf: [96]u8 = undefined;
    const text = try ctx.readZstd(try std.fmt.bufPrint(&pbuf, zk_vectors_dir ++ "/{s}", .{name}), 1 << 31);
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();
    var dq: ?Deferred = if (batch_active) .{ .gpa = ctx.gpa } else null;
    defer if (dq) |*d| d.deinit();
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) break;
        if (dq) |*d| {
            if (d.list.items.len >= flush_every) {
                try d.flush(ctx);
                _ = arena_state.reset(.retain_capacity);
            }
        } else _ = arena_state.reset(.retain_capacity);
        const a = arena_state.allocator();
        const v = try a.create(Vec);
        v.* = try std.json.parseFromSliceLeaky(Vec, a, line, .{ .ignore_unknown_fields = true });
        if (!ctx.selected(v.id)) continue;
        if (!std.mem.eql(u8, v.op, "user_sig") or v.jwks == null) return error.BadVector;
        var no_scratch: [0]u8 = .{};
        try runVector(ctx, a, v, &no_scratch, if (dq) |*d| d else null);
    }
    if (dq) |*d| try d.flush(ctx);
}

fn runVectorFile(ctx: *harness.Ctx, path: []const u8) !void {
    const text = try ctx.corpus.readFileAlloc(ctx.io, path, ctx.gpa, .limited(1 << 30));
    defer ctx.gpa.free(text);
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const scratch = try ctx.gpa.alloc(u8, 1 << 20);
    defer ctx.gpa.free(scratch);
    var dq: ?Deferred = if (batch_active) .{ .gpa = ctx.gpa } else null;
    defer if (dq) |*d| d.deinit();
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) break;
        if (dq) |*d| {
            if (d.list.items.len >= flush_every) {
                try d.flush(ctx);
                _ = arena_state.reset(.retain_capacity);
            }
        } else _ = arena_state.reset(.retain_capacity);
        const a = arena_state.allocator();
        const v = try a.create(Vec);
        v.* = try std.json.parseFromSliceLeaky(Vec, a, line, .{ .ignore_unknown_fields = true });
        if (!ctx.selected(v.id)) continue;
        try runVector(ctx, a, v, scratch, if (dq) |*d| d else null);
    }
    if (dq) |*d| try d.flush(ctx);
}

/// `dq` non-null (batch mode): Ed25519 verify, user_sig and user_tx items are queued (their
/// memory is `a`'s, kept until the flush) and checked as one batch by `Deferred.flush`.
fn runVector(ctx: *harness.Ctx, a: std.mem.Allocator, v: *const Vec, scratch: []u8, dq: ?*Deferred) !void {
    var c = ctx.check(v.id);
    const op = v.op;
    if (std.mem.eql(u8, op, "ed25519_sign")) {
        const sk = try unhex(a, v.sk.?);
        const msg = try unhex(a, v.msg.?);
        const want = try unhex(a, v.out.?);
        if (sk.len != 32) return error.BadVector;
        const got = ed25519.sign(sk[0..32], msg);
        c.bytes("signature", want, &got);
    } else if (std.mem.eql(u8, op, "ed25519_verify")) {
        if (dq) |d| return d.push(.{ .c = c, .want_v = v.v.?, .work = .{ .ed = .{ .pk = try unhex(a, v.pk.?), .msg = try unhex(a, v.msg.?), .sig = try unhex(a, v.sig.?) } } });
        const got = ed25519.verifySlices(try unhex(a, v.pk.?), try unhex(a, v.msg.?), try unhex(a, v.sig.?));
        c.text("verdict", v.v.?, got.truthName());
    } else if (std.mem.eql(u8, op, "ed25519_batch")) {
        const items = v.items.?;
        const bi = try a.alloc(ed25519.BatchItem, items.len);
        var malformed = false;
        for (items, bi) |t, *b| {
            const pk = try unhex(a, t[0]);
            const sig = try unhex(a, t[2]);
            if (pk.len != 32 or sig.len != 64) malformed = true;
            b.* = .{ .pk = if (pk.len == 32) pk[0..32] else undefined, .msg = try unhex(a, t[1]), .sig = if (sig.len == 64) sig[0..64] else undefined };
        }
        if (malformed) return error.BadVector;
        c.text("verdict", v.v.?, ed25519.verifyBatch(bi, scratch).truthName());
    } else if (std.mem.eql(u8, op, "secp256k1_verify") or std.mem.eql(u8, op, "secp256r1_verify")) {
        const pk = try unhex(a, v.pk.?);
        const msg = try unhex(a, v.msg.?);
        const sig = try unhex(a, v.sig.?);
        const h = try hashKind(v.h);
        const got = if (op[7] == 'k') ecdsa.secp256k1.verifySlices(pk, msg, sig, h) else ecdsa.secp256r1.verifySlices(pk, msg, sig, h);
        c.text("verdict", v.v.?, got.truthName());
    } else if (std.mem.eql(u8, op, "secp256k1_recover") or std.mem.eql(u8, op, "secp256r1_recover")) {
        const msg = try unhex(a, v.msg.?);
        const sig = try unhex(a, v.sig.?);
        const h = try hashKind(v.h);
        const got = if (op[7] == 'k') ecdsa.secp256k1.recoverSlices(msg, sig, h) else ecdsa.secp256r1.recoverSlices(msg, sig, h);
        switch (got) {
            .ok => |k| {
                c.text("verdict", v.v.?, "ok");
                if (v.out) |o| c.bytes("recovered key", try unhex(a, o), &k) else c.failf("recovered a key, truth has none", .{});
            },
            .invalid => |r| {
                c.text("verdict", v.v.?, r.truthName());
                if (v.out != null) c.failf("no key recovered, truth has one", .{});
            },
        }
    } else if (std.mem.eql(u8, op, "user_sig")) {
        const f = v.flags orelse return error.BadVector;
        const jl = try a.create(JwkList);
        jl.* = .{ .items = v.jwks orelse &.{} };
        const env = try a.create(user.UserSigEnv);
        env.* = if (v.jwks != null) envWithJwks(v.epoch orelse 0, &f, jl) else envOfFlags(v.epoch orelse 0, &f);
        var author: user.Address = undefined;
        _ = try std.fmt.hexToBytes(&author, v.author.?);
        if (dq) |d| {
            const item = try prepUserSig(&c, a, env, try unhex(a, v.sig.?), try unhex(a, v.msg.?), &author, v.v.?, v.addr) orelse {
                _ = c.finish();
                return;
            };
            return d.push(.{ .c = c, .want_v = v.v.?, .work = .{ .sig = item } });
        }
        try checkUserSig(&c, a, env, try unhex(a, v.sig.?), try unhex(a, v.msg.?), &author, v.v.?, v.addr);
    } else if (std.mem.eql(u8, op, "user_tx")) {
        const f = v.flags orelse return error.BadVector;
        const env = try a.create(user.UserSigEnv);
        env.* = envOfFlags(0, &f);
        const hs = v.sigs orelse return error.BadVector;
        const sigs = try a.alloc([]const u8, hs.len);
        for (hs, sigs) |h, *o| o.* = try unhex(a, h);
        const aliases = try parseAliases(a, v.aliases orelse &.{});
        const sc = try a.alloc(u8, user.txScratchLen(sigs));
        if (dq) |d| return d.push(.{ .c = c, .want_v = v.v.?, .want_idx = v.idx, .work = .{ .tx = .{ .env = env, .intent = try unhex(a, v.msg.?), .sigs = sigs, .aliases = aliases, .scratch = sc } } });
        const r = user.verifyTransaction(env, try unhex(a, v.msg.?), sigs, aliases, sc) catch |e| {
            c.failf("{s}", .{@errorName(e)});
            _ = c.finish();
            return;
        };
        checkTxResult(&c, v.v.?, v.idx, &r);
    } else return error.UnknownOp;
    _ = c.finish();
}

const EcVerify = struct { pk: []const u8, msg: []const u8, sig: []const u8, h: ecdsa.HashKind };
const EcRecover = struct { msg: []const u8, sig: []const u8, h: ecdsa.HashKind };

const VecBench = struct {
    a: std.mem.Allocator,
    ed: std.ArrayList(struct { pk: ed25519.PublicKey, msg: []const u8, sig: *const [64]u8 }) = .empty,
    ed_bytes: std.ArrayList(struct { pk: []const u8, msg: []const u8, sig: []const u8 }) = .empty,
    batches: std.ArrayList([]const ed25519.BatchItem) = .empty,
    batch_items: u64 = 0,
    signs: std.ArrayList(struct { kp: ed25519.KeyPair, msg: []const u8 }) = .empty,
    k1v: std.ArrayList(EcVerify) = .empty,
    r1v: std.ArrayList(EcVerify) = .empty,
    k1r: std.ArrayList(EcRecover) = .empty,
    r1r: std.ArrayList(EcRecover) = .empty,
    scratch: []u8 = &.{},
};

fn benchVectors(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var st: VecBench = .{ .a = a };
    st.scratch = try a.alloc(u8, 1 << 20);
    for (ctx.benchInputs()) |path| {
        const text = try ctx.corpus.readFileAlloc(ctx.io, path, a, .limited(1 << 30));
        var it = harness.lines(text);
        while (it.next()) |line| {
            const v = try std.json.parseFromSliceLeaky(Vec, a, line, .{ .ignore_unknown_fields = true });
            const op = v.op;
            if (std.mem.eql(u8, op, "ed25519_sign")) {
                try st.signs.append(a, .{ .kp = ed25519.KeyPair.fromSeed((try unhex(a, v.sk.?))[0..32]), .msg = try unhex(a, v.msg.?) });
                continue;
            }
            if (v.v == null or !std.mem.eql(u8, v.v.?, "ok")) continue;
            if (std.mem.eql(u8, op, "ed25519_verify")) {
                const pk = try unhex(a, v.pk.?);
                const msg = try unhex(a, v.msg.?);
                const sig = try unhex(a, v.sig.?);
                try st.ed.append(a, .{ .pk = ed25519.PublicKey.fromBytes(pk[0..32]).?, .msg = msg, .sig = sig[0..64] });
                try st.ed_bytes.append(a, .{ .pk = pk, .msg = msg, .sig = sig });
            } else if (std.mem.eql(u8, op, "ed25519_batch")) {
                const bi = try a.alloc(ed25519.BatchItem, v.items.?.len);
                for (v.items.?, bi) |t, *b| b.* = .{ .pk = (try unhex(a, t[0]))[0..32], .msg = try unhex(a, t[1]), .sig = (try unhex(a, t[2]))[0..64] };
                try st.batches.append(a, bi);
                st.batch_items += bi.len;
            } else if (std.mem.eql(u8, op, "secp256k1_verify") or std.mem.eql(u8, op, "secp256r1_verify")) {
                const e: EcVerify = .{ .pk = try unhex(a, v.pk.?), .msg = try unhex(a, v.msg.?), .sig = try unhex(a, v.sig.?), .h = try hashKind(v.h) };
                if (op[7] == 'k') try st.k1v.append(a, e) else try st.r1v.append(a, e);
            } else if (std.mem.eql(u8, op, "secp256k1_recover") or std.mem.eql(u8, op, "secp256r1_recover")) {
                const e: EcRecover = .{ .msg = try unhex(a, v.msg.?), .sig = try unhex(a, v.sig.?), .h = try hashKind(v.h) };
                if (op[7] == 'k') try st.k1r.append(a, e) else try st.r1r.append(a, e);
            }
        }
    }
    const B = struct {
        fn edVerify(s: *const VecBench) !void {
            for (s.ed.items) |*x| std.mem.doNotOptimizeAway(x.pk.verify(x.msg, x.sig));
        }
        fn edBytes(s: *const VecBench) !void {
            for (s.ed_bytes.items) |x| std.mem.doNotOptimizeAway(ed25519.verifySlices(x.pk, x.msg, x.sig));
        }
        fn edBatch(s: *const VecBench) !void {
            for (s.batches.items) |b| std.mem.doNotOptimizeAway(ed25519.verifyBatch(b, s.scratch));
        }
        fn edSign(s: *const VecBench) !void {
            for (s.signs.items) |*x| std.mem.doNotOptimizeAway(x.kp.sign(x.msg));
        }
        fn k1Verify(s: *const VecBench) !void {
            for (s.k1v.items) |x| std.mem.doNotOptimizeAway(ecdsa.secp256k1.verifySlices(x.pk, x.msg, x.sig, x.h));
        }
        fn r1Verify(s: *const VecBench) !void {
            for (s.r1v.items) |x| std.mem.doNotOptimizeAway(ecdsa.secp256r1.verifySlices(x.pk, x.msg, x.sig, x.h));
        }
        fn k1Recover(s: *const VecBench) !void {
            for (s.k1r.items) |x| std.mem.doNotOptimizeAway(ecdsa.secp256k1.recoverSlices(x.msg, x.sig, x.h));
        }
        fn r1Recover(s: *const VecBench) !void {
            for (s.r1r.items) |x| std.mem.doNotOptimizeAway(ecdsa.secp256r1.recoverSlices(x.msg, x.sig, x.h));
        }
    };
    const s: *const VecBench = &st;
    try ctx.benchPasses("ed25519-verify", "sig", st.ed.items.len, s, B.edVerify);
    try ctx.benchPasses("ed25519-verify-bytes", "sig", st.ed_bytes.items.len, s, B.edBytes);
    try ctx.benchPasses("ed25519-batch", "sig", st.batch_items, s, B.edBatch);
    try ctx.benchPasses("ed25519-sign", "sig", st.signs.items.len, s, B.edSign);
    try ctx.benchPasses("secp256k1-verify", "sig", st.k1v.items.len, s, B.k1Verify);
    try ctx.benchPasses("secp256r1-verify", "sig", st.r1v.items.len, s, B.r1Verify);
    try ctx.benchPasses("secp256k1-recover", "sig", st.k1r.items.len, s, B.k1Recover);
    try ctx.benchPasses("secp256r1-recover", "sig", st.r1r.items.len, s, B.r1Recover);
}

// ---------------------------------------------------------------------------------------------
// sig-corpus

pub const Flags = struct {
    accept_zklogin_in_multisig: bool,
    accept_passkey_in_multisig: bool,
    accept_mldsa65_in_multisig: bool,
    additional_multisig_checks: bool,
    validate_zklogin_public_identifier: bool,
    verify_legacy_zklogin_address: bool,
    zklogin_max_epoch_upper_bound_delta: ?u64 = null,
    zklogin_circuit_mode: u64 = 0,
    zklogin_supported_providers: []const []const u8 = &.{},
};

pub const Jwk = struct { iss: []const u8, kid: []const u8, n: []const u8 };

pub const Header = struct {
    k: []const u8,
    seq: u64,
    epoch: u64,
    pv: u64,
    flags: Flags,
    sigs: u64,
    mutations: u64,
    /// The validators' JWK map at this checkpoint (only in checkpoints with zkLogin signatures).
    jwks: []const Jwk = &.{},
};

pub const Line = struct {
    k: []const u8,
    tx: u32,
    // sig lines
    sig: ?u32 = null,
    m: ?[]const u8 = null,
    author: ?[]const u8 = null,
    addr: ?[]const u8 = null,
    // tx lines
    system: ?bool = null,
    signers: ?[]const []const u8 = null,
    idx: ?[]const u64 = null,
    aliases: ?[]const std.json.Value = null,
    v: []const u8,
};

/// The zkLogin verifying keys, prepared once per process.
var zk_keys: zkl.Keys = undefined;
/// 0 uninitialised, 1 being initialised, 2 ready (suite files run on several threads).
var zk_keys_state: std.atomic.Value(u8) = .init(0);

fn zkKeys() *const zkl.Keys {
    if (zk_keys_state.load(.acquire) != 2) {
        if (zk_keys_state.cmpxchgStrong(0, 1, .acq_rel, .acquire) == null) {
            zk_keys.init();
            zk_keys_state.store(2, .release);
        } else while (zk_keys_state.load(.acquire) != 2) std.atomic.spinLoopHint();
    }
    return &zk_keys;
}

/// JWK map lookup over a header's list (iss as stored: already `JwkId::new`-normalised).
pub const JwkList = struct {
    items: []const Jwk,

    pub fn lookup(ctx: *const anyopaque, iss: []const u8, kid: []const u8) ?[]const u8 {
        const l: *const JwkList = @ptrCast(@alignCast(ctx));
        for (l.items) |j| if (std.mem.eql(u8, j.iss, iss) and std.mem.eql(u8, j.kid, kid)) return j.n;
        return null;
    }
};

fn envOf(h: *const Header, jwks: *const JwkList) user.UserSigEnv {
    return envWithJwks(h.epoch, &h.flags, jwks);
}

pub fn envWithJwks(epoch: u64, f: *const Flags, jwks: *const JwkList) user.UserSigEnv {
    var env = envOfFlags(epoch, f);
    env.zklogin = .{
        .keys = zkKeys(),
        .jwks = .{ .ctx = jwks, .lookupFn = JwkList.lookup },
        .usage = .prod,
        .mode = switch (f.zklogin_circuit_mode) {
            0 => .v1_only,
            1 => .both,
            else => .v2_only,
        },
    };
    return env;
}

/// `[[signer, [alias, ...]], ...]`
pub fn parseAliases(a: std.mem.Allocator, vals: []const std.json.Value) ![]const user.AliasSet {
    const out = try a.alloc(user.AliasSet, vals.len);
    for (vals, out) |v, *o| {
        const pair = v.array.items;
        if (pair.len != 2) return error.MalformedTruth;
        _ = try std.fmt.hexToBytes(&o.signer, pair[0].string);
        const list = pair[1].array.items;
        const al = try a.alloc(user.Address, list.len);
        for (list, al) |x, *y| _ = try std.fmt.hexToBytes(y, x.string);
        o.aliases = al;
    }
    return out;
}

fn checkTxResult(c: *harness.Check, want_v: []const u8, want_idx: ?[]const u64, r: *const user.TxResult) void {
    c.text("verdict", want_v, r.verdict.truthName());
    if (want_idx) |want| {
        if (r.verdict == .valid) {
            c.eql("indices count", want.len, r.n);
            if (want.len == r.n) for (want, r.indices[0..r.n]) |w, g| c.eql("index", w, @as(u64, g));
        }
    }
}

fn envOfFlags(epoch: u64, f: *const Flags) user.UserSigEnv {
    var providers: user.ProviderSet = .empty;
    for (f.zklogin_supported_providers) |name| providers.insert(user.OidcProvider.fromName(name) orelse @panic("unknown provider in truth"));
    return .{ .epoch = epoch, .flags = .{
        .zklogin_supported_providers = providers,
        .accept_zklogin_in_multisig = f.accept_zklogin_in_multisig,
        .accept_passkey_in_multisig = f.accept_passkey_in_multisig,
        .accept_mldsa65_in_multisig = f.accept_mldsa65_in_multisig,
        .additional_multisig_checks = f.additional_multisig_checks,
        .validate_zklogin_public_identifier = f.validate_zklogin_public_identifier,
        .verify_legacy_zklogin_address = f.verify_legacy_zklogin_address,
        .zklogin_max_epoch_upper_bound_delta = f.zklogin_max_epoch_upper_bound_delta,
    } };
}

/// Byte ranges of one checkpoint's transactions in its blob, from the dumper truth.
const TxBytes = struct {
    /// intent message bytes: Intent (3 bytes) ++ BCS(TransactionData)
    intent: []const u8 = &.{},
    sigs: std.ArrayList([]const u8) = .empty,
};

fn parseIndex(s: []const u8, i: *usize) !u32 {
    const start = i.*;
    while (i.* < s.len and std.ascii.isDigit(s[i.*])) i.* += 1;
    return std.fmt.parseInt(u32, s[start..i.*], 10) catch error.MalformedTruthPath;
}

/// Reads tx[i].data and tx[i].sig[j] ranges out of truth/checkpoint/<seq>.jsonl.zst.
fn loadTxBytes(ctx: *harness.Ctx, a: std.mem.Allocator, seq: u64, blob: []const u8) ![]TxBytes {
    var pbuf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&pbuf, "truth/checkpoint/{d}.jsonl.zst", .{seq});
    const text = try ctx.readZstd(path, 1 << 32);
    var it = harness.lines(text);
    const first = it.next() orelse return error.EmptyTruth;
    const hdr = try harness.truth.parseHeader(a, first);
    const txs = try a.alloc(TxBytes, hdr.txs);
    for (txs) |*t| t.* = .{};
    while (it.next()) |line| {
        const l = try harness.truth.parseLine(line);
        const p = l.p;
        if (!std.mem.startsWith(u8, p, "tx[")) continue;
        var i: usize = 3;
        const ti = try parseIndex(p, &i);
        if (ti >= txs.len) return error.MalformedTruthPath;
        const rest = p[i..];
        if (std.mem.eql(u8, rest, "].data")) {
            if (l.o < 3) return error.MalformedTruthPath;
            const raw = try l.raw(blob);
            txs[ti].intent = blob[@intCast(l.o - 3)..][0 .. raw.len + 3];
        } else if (std.mem.startsWith(u8, rest, "].sig[")) {
            i += 6;
            const j = try parseIndex(p, &i);
            if (!std.mem.eql(u8, p[i..], "]")) continue;
            if (j != txs[ti].sigs.items.len) return error.MalformedTruthPath;
            const raw = try l.raw(blob);
            // strip the ULEB128 length prefix of the BCS byte vector
            var k: usize = 0;
            var n: u64 = 0;
            var shift: u6 = 0;
            while (true) : (k += 1) {
                if (k >= raw.len or shift > 28) return error.MalformedTruthPath;
                n |= @as(u64, raw[k] & 0x7f) << shift;
                if (raw[k] & 0x80 == 0) break;
                shift += 7;
            }
            k += 1;
            if (raw.len - k != n) return error.MalformedTruthPath;
            try txs[ti].sigs.append(a, raw[k..]);
        }
    }
    return txs;
}

fn seqOfName(name: []const u8) !u64 {
    const dot = std.mem.indexOfScalar(u8, name, '.') orelse return error.BadName;
    return std.fmt.parseInt(u64, name[0..dot], 10) catch error.BadName;
}

pub fn runCorpus(ctx: *harness.Ctx) !void {
    sigFastFromEnv();
    try batchSetup(ctx);
    defer batchTeardown(ctx);
    try ctx.forEachFile(corpus_dir, ".jsonl.zst", {}, corpusFile);
}

fn corpusFile(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const a = ctx.scratch();
    const seq = try seqOfName(name);
    var pbuf: [96]u8 = undefined;
    const truth_text = try ctx.readZstd(try std.fmt.bufPrint(&pbuf, corpus_dir ++ "/{s}", .{name}), 1 << 32);
    const blob = try ctx.readFile(try std.fmt.bufPrint(&pbuf, "chk/{d}.chk", .{seq}), 1 << 31);
    const txs = try loadTxBytes(ctx, a, seq, blob);
    var it = harness.lines(truth_text);
    const hdr = try std.json.parseFromSliceLeaky(Header, a, it.next() orelse return error.EmptyTruth, .{ .ignore_unknown_fields = true });
    if (!std.mem.eql(u8, hdr.k, "Header") or hdr.seq != seq) return error.MalformedTruth;
    const jwks: JwkList = .{ .items = hdr.jwks };
    const env = envOf(&hdr, &jwks);
    var mbuf: [1 << 16]u8 = undefined;
    var dq: ?Deferred = if (batch_active) .{ .gpa = ctx.gpa } else null;
    defer if (dq) |*d| d.deinit();
    while (it.next()) |text| {
        const l = try std.json.parseFromSliceLeaky(Line, a, text, .{ .ignore_unknown_fields = true });
        if (l.tx >= txs.len) return error.MalformedTruth;
        const tb = &txs[l.tx];
        var ibuf: [128]u8 = undefined;
        if (std.mem.eql(u8, l.k, "tx")) {
            const item = try std.fmt.bufPrint(&ibuf, "{d}/tx{d}", .{ seq, l.tx });
            var c = ctx.check(item);
            const signers_hex = l.signers orelse return error.MalformedTruth;
            if (signers_hex.len > 8) return error.MalformedTruth;
            var signers: [8]user.Address = undefined;
            for (signers_hex, 0..) |sh, i| _ = try std.fmt.hexToBytes(&signers[i], sh);
            // signers and the system flag come from the transaction bytes (types), checked
            // against what Rust's required_signers / is_system_tx said
            const derived = user.txSigners(tb.intent[3..]) catch {
                c.failf("txSigners: TransactionData did not decode", .{});
                _ = c.finish();
                continue;
            };
            c.eql("system", l.system orelse false, derived.is_system);
            c.eql("signer count", signers_hex.len, derived.n);
            if (signers_hex.len == derived.n) for (signers[0..derived.n], derived.slice()) |w, g| c.eql("signer", w, g);
            const aliases = try parseAliases(a, l.aliases orelse &.{});
            const sc = try a.alloc(u8, user.txScratchLen(tb.sigs.items));
            if (dq) |*d| {
                c.item = try a.dupe(u8, item);
                try d.push(.{ .c = c, .want_v = l.v, .want_idx = l.idx, .work = .{ .tx = .{ .env = &env, .intent = tb.intent, .sigs = tb.sigs.items, .aliases = aliases, .scratch = sc } } });
                continue;
            }
            const r = user.verifyTransaction(&env, tb.intent, tb.sigs.items, aliases, sc) catch |e| {
                c.failf("{s}", .{@errorName(e)});
                _ = c.finish();
                continue;
            };
            checkTxResult(&c, l.v, l.idx, &r);
            _ = c.finish();
            continue;
        }
        const j = l.sig orelse return error.MalformedTruth;
        if (j >= tb.sigs.items.len) return error.MalformedTruth;
        const item = try std.fmt.bufPrint(&ibuf, "{d}/tx{d}/sig{d}/{s}", .{ seq, l.tx, j, l.m orelse "orig" });
        if (!ctx.selected(item)) continue;
        var c = ctx.check(item);
        var sig_bytes = tb.sigs.items[j];
        var intent = tb.intent;
        var author: user.Address = undefined;
        _ = try std.fmt.hexToBytes(&author, l.author orelse return error.MalformedTruth);
        if (l.m) |m| {
            // "<target>:<offset>:<xor hex>"; author mutations are already in "author"
            var parts = std.mem.splitScalar(u8, m, ':');
            const target = parts.next().?;
            const off = try std.fmt.parseInt(usize, parts.next() orelse return error.MalformedTruth, 10);
            const xor = try std.fmt.parseInt(u8, parts.next() orelse return error.MalformedTruth, 16);
            if (std.mem.eql(u8, target, "sig")) {
                if (off >= sig_bytes.len or sig_bytes.len > mbuf.len) return error.MalformedTruth;
                @memcpy(mbuf[0..sig_bytes.len], sig_bytes);
                mbuf[off] ^= xor;
                sig_bytes = mbuf[0..sig_bytes.len];
            } else if (std.mem.eql(u8, target, "msg")) {
                const copy = try a.dupe(u8, intent);
                if (off >= copy.len) return error.MalformedTruth;
                copy[off] ^= xor;
                intent = copy;
            } else if (!std.mem.eql(u8, target, "author")) return error.MalformedTruth;
        }
        if (dq) |*d| {
            c.item = try a.dupe(u8, item);
            const sb = try a.dupe(u8, sig_bytes);
            const ws = try prepUserSig(&c, a, &env, sb, intent, &author, l.v, l.addr) orelse {
                _ = c.finish();
                continue;
            };
            try d.push(.{ .c = c, .want_v = l.v, .work = .{ .sig = ws } });
            continue;
        }
        try checkUserSig(&c, a, &env, sig_bytes, intent, &author, l.v, l.addr);
        _ = c.finish();
    }
    if (dq) |*d| try d.flush(ctx);
}

/// One user signature as the truth tool's `check_sig` sees it: GenericSignature::from_bytes,
/// SuiAddress::try_from (truth "addr": hex, "err:<kind>", or null when parsing failed), then
/// verify_authenticator over the intent message (truth "v").
fn checkUserSig(c: *harness.Check, a: std.mem.Allocator, env: *const user.UserSigEnv, sig_bytes: []const u8, intent: []const u8, author: *const user.Address, want_v: []const u8, want_addr: ?[]const u8) !void {
    const it = try prepUserSig(c, a, env, sig_bytes, intent, author, want_v, want_addr) orelse return;
    const v = user.verifyParsed(it.env, it.parsed, it.digest, it.author, it.scratch) catch |e| {
        c.failf("verify: {s}", .{@errorName(e)});
        return;
    };
    c.text("verdict", want_v, v.truthName());
}

/// The parse and address half of `checkUserSig`: checks those, and returns what is left to
/// verify (memory from `a`), or null when the item is decided already.
fn prepUserSig(c: *harness.Check, a: std.mem.Allocator, env: *const user.UserSigEnv, sig_bytes: []const u8, intent: []const u8, author: *const user.Address, want_v: []const u8, want_addr: ?[]const u8) !?batch.SigItem {
    const digest = try a.create([32]u8);
    digest.* = user.intentDigest(intent);
    const p = try a.create(user.Parsed);
    const sc = try a.alloc(u8, user.scratchLen(sig_bytes.len));
    if (user.parse(sig_bytes, p, sc)) |reason| {
        c.text("verdict", want_v, reason.truthName());
        if (want_addr != null) c.failf("address: truth {s}, zui: parse failed", .{want_addr.?});
        return null;
    }
    const addr = user.address(p) catch |e| {
        c.failf("address: {s}", .{@errorName(e)});
        return null;
    };
    var abuf: [80]u8 = undefined;
    const addr_text = switch (addr) {
        .ok => |x| try hexLower(a, &x),
        .err => |r| try std.fmt.bufPrint(&abuf, "err:{s}", .{r.truthName()}),
    };
    c.text("address", want_addr orelse "null", addr_text);
    const au = try a.create(user.Address);
    au.* = author.*;
    return .{ .env = env, .parsed = p, .digest = digest, .author = au, .scratch = sc };
}

// ---------------------------------------------------------------------------------------------
// Batch mode (ZUI_SIG_PATH=cpu1|pool|gpu): the same items and truth, checked through sig.batch

/// Set by a suite that installs the accelerator first (gpu.conformance sig-corpus-gpu and
/// sig-vectors-gpu); else ZUI_SIG_PATH decides. Null and no env: the plain per-item path.
pub var forced_path: ?batch.Path = null;

var batch_active = false;
var batch_path: batch.Path = .cpu1;
var batch_own_pool: ?*core.pool.Pool = null;
var batch_saved_fast: sig_fast.Config = .{};
var bst_mu: std.atomic.Value(bool) = .init(false);
var bst: batch.Stats = .{};
var bst_ed: [2]u64 = .{ 0, 0 };

const flush_every = 4096;

fn batchSetup(ctx: *harness.Ctx) !void {
    const path: batch.Path = forced_path orelse blk: {
        const v = std.mem.span(std.c.getenv("ZUI_SIG_PATH") orelse return);
        if (v.len == 0 or std.mem.eql(u8, v, "off")) return;
        break :blk batch.Path.parse(v) orelse return error.BadSigPath;
    };
    if (path == .accel and batch.backend() == null) {
        ctx.stderr.print("ZUI_SIG_PATH=gpu needs an installed accelerator: run the sig-corpus-gpu / sig-vectors-gpu suites\n", .{}) catch {};
        return error.NoSigBackend;
    }
    if (path != .cpu1 and core.pool.shared() == null) {
        // lanes as the node's engine picks them: the hw plan (cgroup quota and affinity counted)
        var spec: core.hw.Spec = .{};
        core.hw.parseEnv(&spec, null) catch {};
        const m = core.hw.detect(null);
        const plan_lanes: usize = @max(1, core.hw.plan(&m, &spec).pool_threads);
        const lanes: usize = if (std.c.getenv("ZUI_SIG_LANES")) |l| std.fmt.parseInt(usize, std.mem.span(l), 10) catch plan_lanes else plan_lanes;
        batch_own_pool = try core.pool.Pool.init(ctx.io, std.heap.page_allocator, lanes);
        _ = core.pool.setShared(batch_own_pool);
    }
    batch_saved_fast = sig_fast.config();
    if (path != .cpu1) {
        // the zkLogin batch fills the proof cache (successes only) that the per-item pass reads
        var c = batch_saved_fast;
        c.zk_cache = true;
        sig_fast.configure(c);
    }
    batch_path = path;
    bst = .{ .path = path };
    bst_ed = .{ 0, 0 };
    batch_active = true;
    const lanes: usize = if (core.pool.shared()) |p| p.lanes() else 1;
    ctx.stderr.print("{s}: batch mode, path {s}, pool {d} lanes, backend {s}\n", .{ ctx.suite.name, @tagName(path), lanes, if (batch.backend()) |b| b.name else "none" }) catch {};
}

fn batchTeardown(ctx: *harness.Ctx) void {
    if (!batch_active) return;
    batch_active = false;
    ctx.stderr.print("{s}: batch {s}: {d} signature/transaction items, {d} Ed25519 leaves, {d} accepted in the batch pass, {d} zkLogin proofs batched ({d} filled), {d} raw Ed25519 vectors ({d} accepted); pass 1 {d} ms, pass 2 {d} ms\n", .{
        ctx.suite.name,  @tagName(batch_path), bst.items, bst.leaves, bst.accepted, bst.zk_items, bst.zk_filled, bst_ed[0], bst_ed[1],
        bst.leaf_ns / std.time.ns_per_ms, bst.item_ns / std.time.ns_per_ms,
    }) catch {};
    sig_fast.configure(batch_saved_fast);
    if (batch_own_pool) |p| {
        _ = core.pool.setShared(null);
        p.deinit();
        batch_own_pool = null;
    }
}

const EdWork = struct { pk: []const u8, msg: []const u8, sig: []const u8 };

const Pend = struct {
    c: harness.Check,
    want_v: []const u8,
    want_idx: ?[]const u64 = null,
    work: union(enum) { sig: batch.SigItem, tx: batch.TxItem, ed: EdWork },
};

/// Queued items of one file (or one window of it); their memory belongs to the caller's arena.
const Deferred = struct {
    gpa: std.mem.Allocator,
    list: std.ArrayList(Pend) = .empty,

    fn deinit(d: *Deferred) void {
        d.list.deinit(d.gpa);
    }

    fn push(d: *Deferred, p: Pend) !void {
        try d.list.append(d.gpa, p);
    }

    fn flush(d: *Deferred, ctx: *harness.Ctx) !void {
        defer d.list.clearRetainingCapacity();
        const gpa = d.gpa;
        var ns: usize = 0;
        var nt: usize = 0;
        var ne: usize = 0;
        for (d.list.items) |*p| switch (p.work) {
            .sig => ns += 1,
            .tx => nt += 1,
            .ed => |e| ne += @intFromBool(e.pk.len == 32 and e.sig.len == 64),
        };
        const sitems = try gpa.alloc(batch.SigItem, ns);
        defer gpa.free(sitems);
        const sres = try gpa.alloc(batch.SigResult, ns);
        defer gpa.free(sres);
        const titems = try gpa.alloc(batch.TxItem, nt);
        defer gpa.free(titems);
        const tres = try gpa.alloc(batch.TxOutcome, nt);
        defer gpa.free(tres);
        const eitems = try gpa.alloc(ed25519.BatchItem, ne);
        defer gpa.free(eitems);
        const eout = try gpa.alloc(Verdict, ne);
        defer gpa.free(eout);
        var i: usize = 0;
        var j: usize = 0;
        var k: usize = 0;
        for (d.list.items) |*p| switch (p.work) {
            .sig => |w| {
                sitems[i] = w;
                i += 1;
            },
            .tx => |w| {
                titems[j] = w;
                j += 1;
            },
            .ed => |e| if (e.pk.len == 32 and e.sig.len == 64) {
                eitems[k] = .{ .pk = e.pk[0..32], .msg = e.msg, .sig = e.sig[0..64] };
                k += 1;
            },
        };
        const o: batch.Options = .{ .path = batch_path, .io = ctx.io };
        var st = batch.verifySigs(gpa, sitems, sres, o);
        st.add(batch.verifyTxs(gpa, titems, tres, o));
        batch.verifyLeaves(batch_path, null, eitems, eout);
        var ed_ok: u64 = 0;
        for (eout) |v| ed_ok += @intFromBool(v == .valid);
        {
            while (bst_mu.swap(true, .acquire)) std.atomic.spinLoopHint();
            defer bst_mu.store(false, .release);
            bst.add(st);
            bst_ed[0] += ne;
            bst_ed[1] += ed_ok;
        }
        i = 0;
        j = 0;
        k = 0;
        for (d.list.items) |*p| {
            var c = p.c;
            switch (p.work) {
                .sig => {
                    const r = sres[i];
                    i += 1;
                    if (r) |v| c.text("verdict", p.want_v, v.truthName()) else |e| c.failf("verify: {s}", .{@errorName(e)});
                },
                .tx => {
                    const r = tres[j];
                    j += 1;
                    if (r) |res| checkTxResult(&c, p.want_v, p.want_idx, &res) else |e| c.failf("{s}", .{@errorName(e)});
                },
                .ed => |e| {
                    // only an acceptance comes from the batch pass; anything else is the single check
                    var got: ?Verdict = null;
                    if (e.pk.len == 32 and e.sig.len == 64) {
                        if (eout[k] == .valid) got = .valid;
                        k += 1;
                    }
                    c.text("verdict", p.want_v, (got orelse ed25519.verifySlices(e.pk, e.msg, e.sig)).truthName());
                },
            }
            _ = c.finish();
        }
    }
};

const UserWork = struct {
    env: user.UserSigEnv,
    intent: []const u8,
    author: user.Address,
    sig: []const u8,
};

fn benchCorpus(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var work: std.ArrayList(UserWork) = .empty;
    for (ctx.benchInputs()) |path| {
        const base = std.fs.path.basename(path);
        const seq = try seqOfName(base);
        const blob = try ctx.corpus.readFileAlloc(ctx.io, path, a, .limited(1 << 31));
        const txs = try loadTxBytes(ctx, a, seq, blob);
        // epoch flags and system-tx marks come from this checkpoint's sig-corpus header and tx lines
        var pbuf: [96]u8 = undefined;
        const zt = try ctx.corpus.readFileAlloc(ctx.io, try std.fmt.bufPrint(&pbuf, corpus_dir ++ "/{d}.jsonl.zst", .{seq}), a, .limited(1 << 32));
        const tt = try harness.decompressZstd(a, zt, 1 << 32);
        var it = harness.lines(tt);
        const hdr = try std.json.parseFromSliceLeaky(Header, a, it.next() orelse return error.EmptyTruth, .{ .ignore_unknown_fields = true });
        const jl = try a.create(JwkList);
        jl.* = .{ .items = hdr.jwks };
        const env = envOf(&hdr, jl);
        const system = try a.alloc(bool, txs.len);
        @memset(system, false);
        while (it.next()) |text| {
            if (!std.mem.startsWith(u8, text, "{\"k\":\"tx\"")) continue;
            const l = try std.json.parseFromSliceLeaky(Line, a, text, .{ .ignore_unknown_fields = true });
            system[l.tx] = l.system orelse false;
        }
        for (txs, system) |t, sys| {
            if (sys) continue;
            for (t.sigs.items) |s| {
                var p: user.Parsed = undefined;
                if (s.len > 0 and s[0] == 5) continue; // zkLogin: not in the Rust user-sig baseline
                if (user.parse(s, &p, &.{}) != null) continue;
                switch (p) {
                    .zklogin => continue,
                    .multisig => |*m| {
                        var zk = false;
                        for (m.sigs[0..m.n_sigs]) |cs| zk = zk or cs.kind == .zklogin;
                        if (zk) continue;
                    },
                    else => {},
                }
                const addr = switch (try user.address(&p)) {
                    .ok => |x| x,
                    .err => continue,
                };
                try work.append(a, .{ .env = env, .intent = t.intent, .author = addr, .sig = s });
            }
        }
    }
    const B = struct {
        fn run(w: []const UserWork) !void {
            for (w) |*x| std.mem.doNotOptimizeAway(try user.verifyUserSignature(&x.env, x.intent, x.author, x.sig, &.{}));
        }
    };
    try ctx.benchPasses("user-sig", "sig", work.items.len, @as([]const UserWork, work.items), B.run);
}

// ---------------------------------------------------------------------------------------------
// sig-fast: the speed layer against the plain paths on corpus signatures

/// Every Ed25519 single user signature of the checkpoint, as batch items over its intent digest.
fn edItems(a: std.mem.Allocator, txs: []const TxBytes) ![]ed25519.BatchItem {
    var items: std.ArrayList(ed25519.BatchItem) = .empty;
    for (txs) |t| {
        if (t.intent.len == 0) continue;
        var dg: ?*[32]u8 = null;
        for (t.sigs.items) |s| {
            if (s.len != 1 + 64 + 32 or s[0] != 0) continue;
            if (dg == null) {
                dg = try a.create([32]u8);
                dg.?.* = user.intentDigest(t.intent);
            }
            try items.append(a, .{ .pk = s[65..97], .msg = dg.?, .sig = s[1..65] });
        }
    }
    return items.items;
}

fn edVerdicts(gpa: std.mem.Allocator, items: []const ed25519.BatchItem, scratch: []u8) [4]Verdict {
    var singles: Verdict = .valid;
    for (items) |it| if (ed25519.verify(it.pk, it.msg, it.sig) != .valid) {
        singles = .{ .invalid = .verify_invalid_signature };
    };
    if (items.len == 0) singles = .{ .invalid = .verify_invalid_input };
    return .{
        singles,
        ed25519.verifyBatch(items, scratch),
        sig_fast.verifyBatchParallel(gpa, items, .{ .threads = 3, .min_per_thread = 1 }),
        sig_fast.verifyBatchParallel(gpa, items, .{ .threads = 2, .min_per_thread = 1, .chunk = 7 }),
    };
}

fn runFast(ctx: *harness.Ctx) !void {
    try ctx.forEachFile(corpus_dir, ".jsonl.zst", {}, fastFile);
}

fn fastFile(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const a = ctx.scratch();
    const seq = try seqOfName(name);
    var pbuf: [96]u8 = undefined;
    const blob = try ctx.readFile(try std.fmt.bufPrint(&pbuf, "chk/{d}.chk", .{seq}), 1 << 31);
    const txs = try loadTxBytes(ctx, a, seq, blob);
    const items = try edItems(a, txs);
    if (items.len == 0) return;
    const scratch = try a.alloc(u8, (items.len + 1) * ed25519.batch_scratch_per_item + 64);
    var ib: [64]u8 = undefined;
    {
        var c = ctx.check(try std.fmt.bufPrint(&ib, "{d}/ed-batch", .{seq}));
        const v = edVerdicts(ctx.gpa, items, scratch);
        for (v[1..], [_][]const u8{ "verifyBatch", "verifyBatchParallel/3", "verifyBatchParallel/2 chunk 7" }) |g, what|
            c.text(what, v[0].truthName(), g.truthName());
        _ = c.finish();
    }
    {
        // one signature corrupted (its S, so the key and R still decode): every path rejects
        const bad = try a.dupe(ed25519.BatchItem, items);
        const k = items.len / 2;
        const sig = try a.dupe(u8, items[k].sig);
        sig[40] ^= 0x01;
        bad[k].sig = sig[0..64];
        var c = ctx.check(try std.fmt.bufPrint(&ib, "{d}/ed-batch-bad", .{seq}));
        const v = edVerdicts(ctx.gpa, bad, scratch);
        c.text("single checks", "verify:InvalidSignature", v[0].truthName());
        for (v[1..], [_][]const u8{ "verifyBatch", "verifyBatchParallel/3", "verifyBatchParallel/2 chunk 7" }) |g, what|
            c.text(what, v[0].truthName(), g.truthName());
        _ = c.finish();
    }
}

const FastWork = struct {
    env: user.UserSigEnv,
    digest: [32]u8,
    author: user.Address,
    sig: []const u8,
};

const FastSet = struct {
    w: []const FastWork,
    scratch: []u8,
    fn run(s: *const FastSet) !void {
        for (s.w) |*x| std.mem.doNotOptimizeAway(try user.verifyUserSignatureDigest(&x.env, &x.digest, &x.author, x.sig, s.scratch));
    }
};

fn nowNs(io: std.Io) u64 {
    return @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds);
}

/// off, on with caches cleared before every pass (cold: only repeats inside one pass hit), on warm.
fn benchFastSet(ctx: *harness.Ctx, label: []const u8, set: *const FastSet) !void {
    if (set.w.len == 0) return;
    var nb: [64]u8 = undefined;
    sig_fast.configure(.{});
    try ctx.benchPasses(try std.fmt.bufPrint(&nb, "{s}-off", .{label}), "sig", set.w.len, set, FastSet.run);
    sig_fast.configure(sig_fast.all_on);
    defer sig_fast.configure(.{});
    const iters = @max(1, ctx.opts.iters);
    const times = try ctx.gpa.alloc(u64, iters);
    defer ctx.gpa.free(times);
    const pk0 = sig_fast.pkCacheStats();
    const zs0 = sig_fast.zkCacheStats();
    for (times) |*t| {
        sig_fast.clearCaches();
        const t0 = nowNs(ctx.io);
        try set.run();
        t.* = nowNs(ctx.io) - t0;
    }
    const pk = sig_fast.pkCacheStats();
    const zs = sig_fast.zkCacheStats();
    ctx.stderr.print("sig-fast {s}: {d} sigs; cold passes (cache cleared before each) ed25519 hits {d} misses {d}, secp256k1 {d}/{d}, secp256r1 {d}/{d}, zk {d}/{d} (hits/misses summed over {d} passes)\n", .{ label, set.w.len, pk.ed25519.hits - pk0.ed25519.hits, pk.ed25519.misses - pk0.ed25519.misses, pk.secp256k1.hits - pk0.secp256k1.hits, pk.secp256k1.misses - pk0.secp256k1.misses, pk.secp256r1.hits - pk0.secp256r1.hits, pk.secp256r1.misses - pk0.secp256r1.misses, zs.hits - zs0.hits, zs.misses - zs0.misses, iters }) catch {};
    sig_fast.clearCaches();
    ctx.benchRecordTimes(try std.fmt.bufPrint(&nb, "{s}-on-cold", .{label}), "sig", set.w.len, times);
    try ctx.benchPasses(try std.fmt.bufPrint(&nb, "{s}-on-warm", .{label}), "sig", set.w.len, set, FastSet.run);
    sig_fast.clearCaches();
}

const BatchBench = struct {
    gpa: std.mem.Allocator,
    items: []const ed25519.BatchItem,
    scratch: []u8,
    threads: u32,
    fn single(b: *const BatchBench) !void {
        for (b.items) |it| std.mem.doNotOptimizeAway(ed25519.verify(it.pk, it.msg, it.sig));
    }
    fn batch(b: *const BatchBench) !void {
        if (ed25519.verifyBatch(b.items, b.scratch) != .valid) return error.BatchRejected;
    }
    fn par(b: *const BatchBench) !void {
        if (sig_fast.verifyBatchParallel(b.gpa, b.items, .{ .threads = b.threads }) != .valid) return error.BatchRejected;
    }
};

fn benchFast(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    sig_fast.configure(.{});
    sig_fast.clearCaches();
    // ---- corpus user signatures, by kind, in corpus order (zkLogin and multisig included)
    var all: std.ArrayList(FastWork) = .empty;
    var ed: std.ArrayList(FastWork) = .empty;
    var k1: std.ArrayList(FastWork) = .empty;
    var r1: std.ArrayList(FastWork) = .empty;
    var zkw: std.ArrayList(FastWork) = .empty;
    var msw: std.ArrayList(FastWork) = .empty;
    var max_scratch: usize = 0;
    var batch_items: std.ArrayList(ed25519.BatchItem) = .empty;
    for (ctx.benchInputs()) |path| {
        const base = std.fs.path.basename(path);
        const seq = try seqOfName(base);
        const blob = try ctx.corpus.readFileAlloc(ctx.io, path, a, .limited(1 << 31));
        var pbuf: [96]u8 = undefined;
        const zt = ctx.corpus.readFileAlloc(ctx.io, try std.fmt.bufPrint(&pbuf, corpus_dir ++ "/{d}.jsonl.zst", .{seq}), a, .limited(1 << 32)) catch continue;
        const txs = loadTxBytes(ctx, a, seq, blob) catch continue;
        try batch_items.appendSlice(a, try edItems(a, txs));
        const tt = try harness.decompressZstd(a, zt, 1 << 32);
        var it = harness.lines(tt);
        const hdr = try std.json.parseFromSliceLeaky(Header, a, it.next() orelse return error.EmptyTruth, .{ .ignore_unknown_fields = true });
        const jl = try a.create(JwkList);
        jl.* = .{ .items = hdr.jwks };
        const env = envOf(&hdr, jl);
        const system = try a.alloc(bool, txs.len);
        @memset(system, false);
        while (it.next()) |text| {
            if (!std.mem.startsWith(u8, text, "{\"k\":\"tx\"")) continue;
            const l = try std.json.parseFromSliceLeaky(Line, a, text, .{ .ignore_unknown_fields = true });
            if (l.tx < system.len) system[l.tx] = l.system orelse false;
        }
        for (txs, system) |t, sys| {
            if (sys or t.intent.len == 0) continue;
            const dg = user.intentDigest(t.intent);
            for (t.sigs.items) |s| {
                const sc = try a.alloc(u8, user.scratchLen(s.len));
                var p: user.Parsed = undefined;
                if (user.parse(s, &p, sc) != null) continue;
                const addr = switch (try user.address(&p)) {
                    .ok => |x| x,
                    .err => continue,
                };
                max_scratch = @max(max_scratch, user.scratchLen(s.len));
                const w: FastWork = .{ .env = env, .digest = dg, .author = addr, .sig = s };
                try all.append(a, w);
                switch (p) {
                    .single => |x| switch (x.scheme) {
                        .ed25519 => try ed.append(a, w),
                        .secp256k1 => try k1.append(a, w),
                        .secp256r1 => try r1.append(a, w),
                        else => {},
                    },
                    .zklogin => try zkw.append(a, w),
                    .multisig => try msw.append(a, w),
                    else => {},
                }
            }
        }
    }
    const scratch = try a.alloc(u8, @max(max_scratch, 1 << 16));
    ctx.stderr.print("sig-fast bench: {d} corpus user signatures (ed25519 {d}, secp256k1 {d}, secp256r1 {d}, zklogin {d}, multisig {d}) from {d} checkpoints\n", .{ all.items.len, ed.items.len, k1.items.len, r1.items.len, zkw.items.len, msw.items.len, ctx.benchInputs().len }) catch {};
    inline for (.{ "corpus-all", "corpus-ed25519", "corpus-secp256k1", "corpus-secp256r1", "corpus-zklogin", "corpus-multisig" }, .{ &all, &ed, &k1, &r1, &zkw, &msw }) |label, list| {
        const set: FastSet = .{ .w = list.items, .scratch = scratch };
        try benchFastSet(ctx, label, &set);
    }

    // ---- repeat keys (an agent or a market maker signing many transactions): 64 keys x 64 msgs
    if (ed.items.len > 0) {
        var rk: std.ArrayList(FastWork) = .empty;
        var prng = std.Random.DefaultPrng.init(0x7a7569);
        const env0 = ed.items[0].env;
        for (0..64) |_| {
            var seed: [32]u8 = undefined;
            prng.random().bytes(&seed);
            const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
            const pkb = kp.public_key.toBytes();
            var addr_in: [33]u8 = undefined;
            addr_in[0] = 0;
            @memcpy(addr_in[1..], &pkb);
            var addr: user.Address = undefined;
            std.crypto.hash.blake2.Blake2b256.hash(&addr_in, &addr, .{});
            for (0..64) |_| {
                var dg: [32]u8 = undefined;
                prng.random().bytes(&dg);
                const sg = (try kp.sign(&dg, null)).toBytes();
                const sb = try a.alloc(u8, 97);
                sb[0] = 0;
                @memcpy(sb[1..65], &sg);
                @memcpy(sb[65..97], &pkb);
                try rk.append(a, .{ .env = env0, .digest = dg, .author = addr, .sig = sb });
            }
        }
        // interleave keys (k0 m0, k1 m0, ...) so a hit is never the previous call's key
        const inter = try a.alloc(FastWork, rk.items.len);
        for (0..64) |ki| for (0..64) |mi| {
            inter[mi * 64 + ki] = rk.items[ki * 64 + mi];
        };
        sig_fast.configure(.{});
        var nvalid: usize = 0;
        for (inter) |*x| if ((try user.verifyUserSignatureDigest(&x.env, &x.digest, &x.author, x.sig, scratch)) == .valid) {
            nvalid += 1;
        };
        ctx.stderr.print("sig-fast repeat-key ed25519: {d}/{d} valid\n", .{ nvalid, inter.len }) catch {};
        const set: FastSet = .{ .w = inter, .scratch = scratch };
        try benchFastSet(ctx, "repeat-key-ed25519", &set);
    }

    // ---- parallel Ed25519 batch: 4096 distinct keys, and the corpus's own Ed25519 signatures
    var syn: std.ArrayList(ed25519.BatchItem) = .empty;
    {
        var prng = std.Random.DefaultPrng.init(0x62617463);
        for (0..4096) |_| {
            var seed: [32]u8 = undefined;
            prng.random().bytes(&seed);
            const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
            const pk = try a.create([32]u8);
            pk.* = kp.public_key.toBytes();
            const msg = try a.alloc(u8, 32);
            prng.random().bytes(msg);
            const sg = try a.create([64]u8);
            sg.* = (try kp.sign(msg, null)).toBytes();
            try syn.append(a, .{ .pk = pk, .msg = msg, .sig = sg });
        }
    }
    inline for (.{ "synthetic-4096", "synthetic-256", "corpus" }) |label| {
        const items: []const ed25519.BatchItem = if (comptime std.mem.eql(u8, label, "synthetic-4096")) syn.items else if (comptime std.mem.eql(u8, label, "synthetic-256")) syn.items[0..256] else batch_items.items;
        if (items.len >= 3) {
            const bscratch = try a.alloc(u8, (items.len + 1) * ed25519.batch_scratch_per_item + 64);
            var bb: BatchBench = .{ .gpa = ctx.gpa, .items = items, .scratch = bscratch, .threads = 1 };
            const bp: *const BatchBench = &bb;
            if (ed25519.verifyBatch(items, bscratch) != .valid) {
                ctx.stderr.print("sig-fast batch {s}: verifyBatch rejected the set, skipped\n", .{label}) catch {};
            } else {
                try ctx.benchPasses("ed25519-" ++ label ++ "-single", "sig", items.len, bp, BatchBench.single);
                try ctx.benchPasses("ed25519-" ++ label ++ "-batch", "sig", items.len, bp, BatchBench.batch);
                inline for (.{ 2, 4 }) |nt| {
                    bb.threads = nt;
                    try ctx.benchPasses(std.fmt.comptimePrint("ed25519-{s}-par{d}-spawn", .{ label, nt }), "sig", items.len, bp, BatchBench.par);
                }
                // one thread, scratch for `c` items per chunk: how the chunk size alone moves the cost
                inline for (.{ 64, 128, 256, 512, 1024, 4096 }) |cs| if (cs < items.len) {
                    var bc: BatchBench = bb;
                    bc.scratch = bscratch[0 .. (cs + 1) * ed25519.batch_scratch_per_item + 64];
                    const bcp: *const BatchBench = &bc;
                    try ctx.benchPasses(std.fmt.comptimePrint("ed25519-{s}-batch-chunk{d}", .{ label, cs }), "sig", items.len, bcp, BatchBench.batch);
                };
                if (sig_fast.startPool(ctx.io, std.heap.page_allocator, 4)) {
                    defer sig_fast.stopPool();
                    bb.threads = 4;
                    try ctx.benchPasses("ed25519-" ++ label ++ "-par4-pool", "sig", items.len, bp, BatchBench.par);
                }
            }
        }
    }
    ctx.stderr.flush() catch {};
}
