//! Signature pre-verification gives the serial results exactly: blocks and SubmitTransaction
//! requests with valid, invalid-signature, wrong-signer, malformed, multisig, secp256k1/r1,
//! duplicate and state-failing transactions produce the same accept/reject indices, reason
//! strings, counters and hook calls with the stage off, on (inline, on a pool, with pre-steps)
//! and auto, and with the real zkLogin and Ed25519 pre-steps (presteps.zig) filling the sig.fast
//! caches (Accel off and Accel forced to the pool path; zkLogin signatures from $ZUI_CORPUS when
//! it is there).
const std = @import("std");
const core = @import("core");
const consensus = @import("consensus");
const messages = @import("../messages.zig");
const env_mod = @import("env.zig");
const tx_validator = @import("tx_validator.zig");
const submit_mod = @import("submit.zig");
const state_mod = @import("state.zig");
const adapter_mod = @import("adapter.zig");
const preverify = @import("preverify.zig");
const fixture = @import("preverify_fixture.zig");
const sig = @import("sig");
const zk = @import("zk");
const gpu = @import("gpu");
const presteps = @import("presteps.zig");
const zkl = zk.zklogin;

const Allocator = std.mem.Allocator;
const Fixture = fixture.Fixture;
const Signer = fixture.Signer;
const Pool = core.pool.Pool;

const Run = struct {
    mode: preverify.Mode,
    pool: ?*Pool = null,
    pre_steps: []const preverify.PreStep = &.{},
    /// zk and Ed25519 verified caches on for this run (cleared first unless `warm`).
    caches: bool = false,
    warm: bool = false,
};

fn setCaches(r: Run) void {
    if (r.caches) {
        presteps.Set.enableCaches();
        if (!r.warm) sig.fast.clearCaches();
    } else {
        sig.fast.configure(.{});
        sig.fast.clearCaches();
    }
}

/// zkLogin GenericSignatures (flag 5) from $ZUI_CORPUS/vectors/zklogin with their senders, and
/// one JWK map to check all of them under (the corpus union, then each item's extra JWK where
/// the map has none yet). Null without the corpus.
const ZkCorpus = struct {
    gpa: Allocator,
    set: *zk.corpus_vectors.Set,
    arena: std.heap.ArenaAllocator,
    map: std.StringHashMapUnmanaged([]const u8) = .empty,
    sigs: std.ArrayList([]const u8) = .empty,
    addrs: std.ArrayList(fixture.Id) = .empty,

    fn create(gpa: Allocator, io: std.Io, max: usize) !?*ZkCorpus {
        const set = (try zk.corpus_vectors.load(gpa, io, &.{"edge.items.jsonl"}, 1)) orelse return null;
        const z = try gpa.create(ZkCorpus);
        z.* = .{ .gpa = gpa, .set = set, .arena = .init(gpa) };
        errdefer z.destroy();
        const a = z.arena.allocator();
        var mi = set.map.iterator();
        while (mi.next()) |e| try z.map.put(a, e.key_ptr.*, e.value_ptr.*);
        const corpus = std.mem.span(std.c.getenv("ZUI_CORPUS").?);
        var dir = try std.Io.Dir.cwd().openDir(io, corpus, .{});
        defer dir.close(io);
        outer: for ([_][]const u8{ "edge.items.jsonl", "corpus001.items.jsonl" }) |name| {
            const path = try std.fmt.allocPrint(a, "vectors/zklogin/{s}", .{name});
            const text = dir.readFileAlloc(io, path, a, .limited(256 << 20)) catch continue;
            var it = std.mem.splitScalar(u8, text, '\n');
            while (it.next()) |line| {
                if (line.len == 0) continue;
                if (z.sigs.items.len >= max) break :outer;
                const o = (try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{})).object;
                const h = (o.get("auth") orelse continue).string;
                const bytes = try a.alloc(u8, 1 + h.len / 2);
                bytes[0] = zkl.flag;
                _ = std.fmt.hexToBytes(bytes[1..], h) catch continue;
                const scratch = try a.alloc(u8, sig.user.scratchLen(bytes.len));
                var p: sig.user.Parsed = undefined;
                if (sig.user.parse(bytes, &p, scratch) != null) continue;
                if (o.get("xjwk")) |x| if (x == .object) {
                    const iss = x.object.get("iss").?.string;
                    const kid = x.object.get("kid").?.string;
                    const key = try std.fmt.allocPrint(a, "{s}\x00{s}", .{ iss, kid });
                    const gop = try z.map.getOrPut(a, key);
                    if (!gop.found_existing) gop.value_ptr.* = x.object.get("n").?.string;
                };
                try z.sigs.append(a, bytes);
                try z.addrs.append(a, p.zklogin.address(false));
            }
        }
        return z;
    }

    fn destroy(z: *ZkCorpus) void {
        z.set.deinit();
        z.arena.deinit();
        z.gpa.destroy(z);
    }

    fn lookup(ctx: *const anyopaque, iss: []const u8, kid: []const u8) ?[]const u8 {
        const z: *const ZkCorpus = @ptrCast(@alignCast(ctx));
        var buf: [1024]u8 = undefined;
        if (iss.len + kid.len + 1 > buf.len) return null;
        @memcpy(buf[0..iss.len], iss);
        buf[iss.len] = 0;
        @memcpy(buf[iss.len + 1 ..][0..kid.len], kid);
        return z.map.get(buf[0 .. iss.len + 1 + kid.len]);
    }

    fn env(z: *const ZkCorpus, mode: zkl.Mode) zkl.Env {
        return .{ .keys = &z.set.keys, .jwks = .{ .ctx = z, .lookupFn = lookup }, .usage = .prod, .mode = mode };
    }

    /// How many of `sigs[0..n]` have a proof that verifies under `e` (plain zkl.verify).
    fn proofsOk(z: *const ZkCorpus, e: *const zkl.Env, n: usize) !usize {
        var ok: usize = 0;
        for (z.sigs.items[0..n]) |raw| {
            const scratch = try z.gpa.alloc(u8, sig.user.scratchLen(raw.len));
            defer z.gpa.free(scratch);
            var p: sig.user.Parsed = undefined;
            _ = sig.user.parse(raw, &p, scratch);
            ok += @intFromBool(zkl.verify(e, &p.zklogin.auth) == .none);
        }
        return ok;
    }
};

/// Overload hooks that fire on a fixed pattern of calls: only the serial loop calls them, so the
/// call sequence (and the transcript) must not depend on the stage.
const Counter = struct {
    calls: u32 = 0,
    fn overloaded(ctx: *anyopaque) bool {
        const c: *Counter = @ptrCast(@alignCast(ctx));
        c.calls += 1;
        return c.calls % 7 == 3;
    }
    fn systemOverload(ctx: *anyopaque) ?[]const u8 {
        const c: *Counter = @ptrCast(@alignCast(ctx));
        c.calls += 1;
        return if (c.calls % 9 == 4) "Validator is overloaded (test)" else null;
    }
};

/// A pre-step that checks what it is given and counts it.
const Probe = struct {
    calls: std.atomic.Value(u32) = .init(0),
    items: std.atomic.Value(u32) = .init(0),
    bad: std.atomic.Value(u32) = .init(0),
    fn run(ctx: ?*anyopaque, pool: ?*Pool, env: *const sig.user.UserSigEnv, items: []const preverify.Item) void {
        _ = pool;
        _ = env;
        const p: *Probe = @ptrCast(@alignCast(ctx.?));
        _ = p.calls.fetchAdd(1, .monotonic);
        _ = p.items.fetchAdd(@intCast(items.len), .monotonic);
        for (items) |it| {
            if (!std.mem.eql(u8, &sig.user.intentDigest(it.intent), &it.digest) or it.sigs.len == 0 or it.intent[0] != 0) _ = p.bad.fetchAdd(1, .monotonic);
        }
    }
};

fn voteTranscript(gpa: Allocator, f: *Fixture, run: Run, blocks: []const []const consensus.types.Transaction, w: *std.Io.Writer) !void {
    var ctl = try env_mod.LocalEpochControl.init(gpa, &f.stakes);
    defer ctl.deinit();
    var reasons: tx_validator.ReasonCache = .{ .gpa = gpa };
    defer reasons.deinit();
    var v = tx_validator.TxValidator.init(gpa, f.params, f.cfg, &f.env, ctl.control(), &reasons);
    defer v.deinit();
    v.preverify = .{ .mode = run.mode, .pool = run.pool, .pre_steps = run.pre_steps };
    var counter: Counter = .{};
    v.hooks = .{ .ctx = &counter, .overloaded = Counter.overloaded };
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    for (blocks, 0..) |b, bi| {
        var out: [1024]consensus.types.TransactionIndex = undefined;
        const ref: consensus.types.BlockRef = .{ .round = @intCast(bi + 1), .author = 1, .digest = @splat(@intCast(bi)) };
        if (v.verifyAndVote(ref, b, &out)) |n| {
            try w.print("block {d}: {d} rejects [", .{ bi, n });
            for (out[0..n]) |x| try w.print("{d},", .{x});
            try w.writeAll("]\n");
            for (0..b.len) |i| {
                const r = reasons.get(ar.allocator(), .{ .round = ref.round, .author = ref.author, .digest = ref.digest, .index = @intCast(i) }) orelse "-";
                try w.print("  {d}: {s}\n", .{ i, r });
            }
        } else |e| try w.print("block {d}: error {s}\n", .{ bi, @errorName(e) });
    }
    try w.print("accept {d} reject {d} overload-calls {d}\n", .{ v.votes_accept, v.votes_reject, counter.calls });
}

fn zeroNow() u64 {
    return 1_000_000;
}

fn submitTranscript(gpa: Allocator, f: *Fixture, run: Run, reqs: []const submit_mod.Request, w: *std.Io.Writer) !void {
    var ctl = try env_mod.LocalEpochControl.init(gpa, &f.stakes);
    defer ctl.deinit();
    var state = state_mod.EpochState.init(gpa);
    defer state.deinit();
    var adapter = adapter_mod.Adapter.init(gpa, .{});
    defer adapter.deinit();
    var counter: Counter = .{};
    var s: submit_mod.Submit = .{
        .gpa = gpa,
        .params = f.params,
        .cfg = f.cfg,
        .check_env = &f.env,
        .state = &state,
        .epoch_ctl = ctl.control(),
        .adapter = &adapter,
        .own_index = 0,
        .own_name = .{ .@"0" = @splat(0) },
        .now_ms = zeroNow,
        .hooks = .{ .ctx = &counter, .system_overload = Counter.systemOverload },
        .preverify = .{ .mode = run.mode, .pool = run.pool, .pre_steps = run.pre_steps },
    };
    defer s.deinit();
    for (reqs, 0..) |req, ri| {
        var ar: std.heap.ArenaAllocator = .init(gpa);
        defer ar.deinit();
        var failure: submit_mod.Failure = undefined;
        if (s.handle(ar.allocator(), req, &failure)) |resp| {
            try w.print("request {d}:\n", .{ri});
            for (resp.results, 0..) |r, i| switch (r) {
                .submitted => |t| try w.print("  {d}: submitted {d}\n", .{ i, t }),
                .executed => |e| try w.print("  {d}: executed {x}\n", .{ i, e.effects_digest }),
                .rejected => |m| try w.print("  {d}: rejected {s}\n", .{ i, m }),
            };
        } else |e| switch (e) {
            error.Failed => try w.print("request {d}: failed {s}: {s}\n", .{ ri, @errorName(failure.kind), failure.message }),
            else => try w.print("request {d}: error {s}\n", .{ ri, @errorName(e) }),
        }
    }
    try w.print("submitted {d} rejected {d} executed {d} suppressed {d} overload-calls {d} pending {d}\n", .{ s.stats.submitted, s.stats.rejected, s.stats.executed, s.stats.suppressed, counter.calls, adapter.pendingUser() });
}

const Cases = struct {
    blocks: []const []const consensus.types.Transaction,
    reqs: []const submit_mod.Request,
    /// User transactions whose validity passes, over all blocks (what a vote pre-step sees).
    vote_items: u32,
};

fn buildCases(f: *Fixture, zk_signers: []const Signer) !Cases {
    const a = f.arena();
    var coin: u32 = 0;
    const T = struct {
        fn mk(fx: *Fixture, c: *u32, o: fixture.TxOpts) !fixture.Made {
            var oo = o;
            oo.coin = c.*;
            c.* += 1;
            return fx.makeTx(oo);
        }
    };
    var ms_keys: [3]sig.ed25519.KeyPair = undefined;
    for (&ms_keys, 0..) |*k, i| k.* = Signer.edSeed(@intCast(500 + i)).ed;
    const ms_owned = try a.dupe(sig.ed25519.KeyPair, &ms_keys);
    const multi: Signer = .{ .multi = ms_owned };

    var valid: [8]fixture.Made = undefined;
    for (&valid, 0..) |*m, i| m.* = try T.mk(f, &coin, .{ .signer = Signer.edSeed(@intCast(i)), .coin = 0 });
    const bad_sig = try T.mk(f, &coin, .{ .signer = Signer.edSeed(20), .coin = 0, .corrupt_sig = true });
    const wrong = try T.mk(f, &coin, .{ .signer = Signer.edSeed(21), .coin = 0, .sign_with = Signer.edSeed(22) });
    const malformed = try T.mk(f, &coin, .{ .signer = Signer.edSeed(23), .coin = 0, .raw_sig = "\x09not a signature" });
    const short_ed = try T.mk(f, &coin, .{ .signer = Signer.edSeed(24), .coin = 0, .raw_sig = "\x00short" });
    const ms_ok = try T.mk(f, &coin, .{ .signer = multi, .coin = 0 });
    const ms_bad = try T.mk(f, &coin, .{ .signer = multi, .coin = 0, .corrupt_sig = true });
    const k1 = try T.mk(f, &coin, .{ .signer = Signer.k1Seed(1), .coin = 0 });
    const r1 = try T.mk(f, &coin, .{ .signer = Signer.r1Seed(1), .coin = 0 });
    const k1_bad = try T.mk(f, &coin, .{ .signer = Signer.k1Seed(2), .coin = 0, .corrupt_sig = true });
    const low_price = try T.mk(f, &coin, .{ .signer = Signer.edSeed(30), .coin = 0, .price = 1 });
    const expired = try T.mk(f, &coin, .{ .signer = Signer.edSeed(35), .coin = 0, .expire_epoch = 0 });
    const poor = try T.mk(f, &coin, .{ .signer = Signer.edSeed(31), .coin = 0, .balance = 10 });
    const no_coin = try T.mk(f, &coin, .{ .signer = Signer.edSeed(32), .coin = 0, .put_coin = false });
    const bad_alias = try T.mk(f, &coin, .{ .signer = Signer.edSeed(33), .coin = 0, .alias_version = 3 });
    const extra = try T.mk(f, &coin, .{ .signer = Signer.edSeed(34), .coin = 0, .extra_sig = true });
    const eop = blk: {
        const ct: messages.ConsensusTransaction = .{ .tracking_id = @splat(0), .kind = .{ .EndOfPublish = .{ .@"0" = @splat(1) } } };
        break :blk try @import("bcs").encodeAlloc(messages.ConsensusTransaction, a, &ct);
    };
    const rsu = blk: {
        const ct: messages.ConsensusTransaction = .{ .tracking_id = @splat(0), .kind = .{ .RandomnessStateUpdate = .{ 1, "x" } } };
        break :blk try @import("bcs").encodeAlloc(messages.ConsensusTransaction, a, &ct);
    };

    // blocks
    const b0 = try f.block(&.{
        valid[0].block_tx, bad_sig.block_tx, valid[1].block_tx, wrong.block_tx, eop,
        ms_ok.block_tx,    ms_bad.block_tx,  k1.block_tx,       r1.block_tx,      k1_bad.block_tx,    valid[0].block_tx,
        low_price.block_tx, poor.block_tx,   no_coin.block_tx,  bad_alias.block_tx, extra.block_tx,
        valid[2].block_tx, valid[3].block_tx, valid[4].block_tx, valid[5].block_tx, valid[6].block_tx, valid[7].block_tx,
        expired.block_tx,
    });
    const b1 = try f.block(&.{valid[0].block_tx});
    const b2 = try f.block(&.{ valid[1].block_tx, bad_sig.block_tx, rsu });
    const b3 = try f.block(&.{});
    const b4 = try f.block(&.{ eop, eop });
    const b5 = try f.block(&.{ wrong.block_tx, bad_sig.block_tx });
    // a signature that does not decode makes the block undecodable (GenericSignature checks)
    const b6 = try f.block(&.{ valid[2].block_tx, malformed.block_tx });
    const b7 = try f.block(&.{ short_ed.block_tx, valid[3].block_tx });
    // zkLogin senders (corpus signatures: they parse, their proofs may verify, but their
    // ephemeral signatures are over another message, so every one is rejected)
    var zk_blk: std.ArrayList([]const u8) = .empty;
    var zk_raw: std.ArrayList([]const u8) = .empty;
    try zk_blk.append(a, valid[4].block_tx);
    for (zk_signers) |zs| {
        const m = try T.mk(f, &coin, .{ .signer = zs, .coin = 0 });
        try zk_blk.append(a, m.block_tx);
        try zk_raw.append(a, m.raw);
    }
    try zk_raw.append(a, valid[4].raw);
    const b8 = try f.block(zk_blk.items);
    const blocks = try a.dupe([]const consensus.types.Transaction, &.{ b0, b1, b2, b3, b4, b5, b6, b7, b8 });

    // requests
    const R = submit_mod.Request;
    const reqs = try a.dupe(R, &.{
        // per-transaction outcomes only
        .{ .transactions = try a.dupe([]const u8, &.{ valid[0].raw, valid[1].raw, valid[0].raw, poor.raw, no_coin.raw, ms_ok.raw, k1.raw, r1.raw, valid[2].raw, valid[3].raw, bad_alias.raw, valid[4].raw }) },
        // invalid signature at 2 fails the request (validity failure after it is not reached)
        .{ .transactions = try a.dupe([]const u8, &.{ valid[5].raw, valid[6].raw, bad_sig.raw, valid[7].raw, low_price.raw }) },
        // validity failure before an invalid signature
        .{ .transactions = try a.dupe([]const u8, &.{ valid[5].raw, expired.raw, bad_sig.raw }) },
        .{ .transactions = try a.dupe([]const u8, &.{ valid[5].raw, low_price.raw, valid[6].raw }) },
        // wrong signer, malformed, multisig with a bad member, k1 with a bad signature, extra signature
        .{ .transactions = try a.dupe([]const u8, &.{ valid[6].raw, wrong.raw }) },
        .{ .transactions = try a.dupe([]const u8, &.{ malformed.raw, valid[6].raw }) },
        .{ .transactions = try a.dupe([]const u8, &.{ valid[7].raw, ms_bad.raw }) },
        .{ .transactions = try a.dupe([]const u8, &.{ k1_bad.raw, valid[7].raw }) },
        .{ .transactions = try a.dupe([]const u8, &.{ extra.raw, valid[7].raw }) },
        .{ .transactions = try a.dupe([]const u8, &.{ short_ed.raw, valid[7].raw }) },
        // undecodable transaction before an invalid signature
        .{ .transactions = try a.dupe([]const u8, &.{ valid[5].raw, "xx", bad_sig.raw }) },
        // soft bundles: fine, duplicate, single
        .{ .submit_type = .soft_bundle, .transactions = try a.dupe([]const u8, &.{ valid[5].raw, valid[6].raw }) },
        .{ .submit_type = .soft_bundle, .transactions = try a.dupe([]const u8, &.{ valid[7].raw, valid[7].raw, bad_sig.raw }) },
        .{ .transactions = try a.dupe([]const u8, &.{valid[2].raw}) },
        // the first request again: in-flight suppression
        .{ .transactions = try a.dupe([]const u8, &.{ valid[0].raw, valid[1].raw, valid[0].raw, poor.raw, no_coin.raw, ms_ok.raw, k1.raw, r1.raw }) },
        // zkLogin senders (empty without the corpus: then just valid[4])
        .{ .transactions = zk_raw.items },
        .{ .transactions = zk_raw.items[zk_raw.items.len - 1 ..] },
    });
    // b0: every user transaction but low_price and the undecodable signatures passes validity
    // (counted from the transcript of the probe run below, not assumed)
    return .{ .blocks = blocks, .reqs = reqs, .vote_items = 0 };
}

fn transcripts(gpa: Allocator, f: *Fixture, cases: Cases, run: Run) !struct { vote: []u8, submit: []u8 } {
    setCaches(run);
    var vw: std.Io.Writer.Allocating = .init(gpa);
    errdefer vw.deinit();
    try voteTranscript(gpa, f, run, cases.blocks, &vw.writer);
    var sw: std.Io.Writer.Allocating = .init(gpa);
    errdefer sw.deinit();
    try submitTranscript(gpa, f, run, cases.reqs, &sw.writer);
    return .{ .vote = try vw.toOwnedSlice(), .submit = try sw.toOwnedSlice() };
}

test "pre-verification gives the serial votes and submit results exactly" {
    const gpa = std.testing.allocator;
    const f = try Fixture.create(gpa);
    defer f.destroy();
    defer sig.fast.configure(.{});
    defer sig.fast.clearCaches();
    // zkLogin: corpus signatures, checked under one environment (epoch 1 is below every max_epoch)
    const zc = try ZkCorpus.create(gpa, std.testing.io, 8);
    defer if (zc) |z| z.destroy();
    var zk_signers: [8]Signer = undefined;
    var n_zk: usize = 0;
    var zk_ok: usize = 0;
    if (zc) |z| {
        f.sig_env.zklogin = z.env(.v1_only);
        for (z.sigs.items, z.addrs.items) |s, ad| {
            zk_signers[n_zk] = .{ .fixed = .{ .addr = ad, .sig = s } };
            n_zk += 1;
        }
        zk_ok = try z.proofsOk(&f.sig_env.zklogin.?, n_zk);
    } else std.debug.print("preverify test: no $ZUI_CORPUS, zkLogin transactions left out\n", .{});
    const cases = try buildCases(f, zk_signers[0..n_zk]);

    const base = try transcripts(gpa, f, cases, .{ .mode = .off });
    defer gpa.free(base.vote);
    defer gpa.free(base.submit);

    // the cases must exercise both accept and reject, and real reasons
    try std.testing.expect(std.mem.indexOf(u8, base.vote, "Signature is not valid") != null);
    try std.testing.expect(std.mem.indexOf(u8, base.vote, "  0: -\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, base.submit, "submitted") != null);
    try std.testing.expect(std.mem.indexOf(u8, base.submit, "failed InvalidRequest: Signature is not valid") != null);
    try std.testing.expect(std.mem.indexOf(u8, base.submit, "Repeated transaction") != null);

    const pool = try Pool.init(std.testing.io, gpa, 4);
    defer pool.deinit();
    var probe: Probe = .{};
    const steps = [_]preverify.PreStep{.{ .name = "probe", .ctx = &probe, .run = Probe.run }};
    // the real pre-steps: Accel off (its dispatch table: one item inline, more on the pool) and
    // Accel forced to the pool path
    var accel_off = gpu.Accel.initOpts(gpa, .{ .mode = .off });
    defer accel_off.deinit();
    accel_off.pool = pool;
    var accel_pool = gpu.Accel.initOpts(gpa, .{ .mode = .off });
    defer accel_pool.deinit();
    accel_pool.pool = pool;
    accel_pool.forced = .pool;
    var set_off: presteps.Set = undefined;
    set_off.init(std.testing.io, gpa, &accel_off);
    var set_pool: presteps.Set = undefined;
    set_pool.init(std.testing.io, gpa, &accel_pool);
    // no GPU here: make the Ed25519 step run on the CPU paths (by default it leaves them to the
    // per-transaction pass)
    set_off.ed.cpu = true;
    set_pool.ed.cpu = true;

    const runs = [_]Run{
        .{ .mode = .on },
        .{ .mode = .on, .pool = pool },
        .{ .mode = .auto, .pool = pool },
        .{ .mode = .on, .pool = pool, .pre_steps = &steps },
        .{ .mode = .on, .pre_steps = &steps },
        .{ .mode = .on, .pool = pool, .pre_steps = set_off.slice(), .caches = true },
        .{ .mode = .on, .pool = pool, .pre_steps = set_pool.slice(), .caches = true },
        .{ .mode = .on, .pre_steps = set_pool.slice(), .caches = true },
        .{ .mode = .auto, .pool = pool, .pre_steps = set_pool.slice(), .caches = true },
        // warm: every accepted signature is already cached from the run before
        .{ .mode = .on, .pool = pool, .pre_steps = set_off.slice(), .caches = true, .warm = true },
        // caches on with the stage off: the per-transaction path alone fills and reads them
        .{ .mode = .off, .caches = true },
        .{ .mode = .off, .caches = true, .warm = true },
    };
    for (runs) |r| {
        const got = try transcripts(gpa, f, cases, r);
        defer gpa.free(got.vote);
        defer gpa.free(got.submit);
        std.testing.expectEqualStrings(base.vote, got.vote) catch |e| {
            std.debug.print("vote transcript differs for mode {s} pool {} steps {d}\n", .{ @tagName(r.mode), r.pool != null, r.pre_steps.len });
            return e;
        };
        std.testing.expectEqualStrings(base.submit, got.submit) catch |e| {
            std.debug.print("submit transcript differs for mode {s} pool {} steps {d}\n", .{ @tagName(r.mode), r.pool != null, r.pre_steps.len });
            return e;
        };
    }
    // the real pre-steps did their work: Ed25519 signatures checked and cached, cache hits in the
    // per-transaction pass, and (with the corpus) zkLogin proofs batch-checked
    for ([_]*presteps.Set{ &set_off, &set_pool }) |st| {
        try std.testing.expect(st.ed.calls.load(.monotonic) > 0);
        try std.testing.expect(st.ed.filled.load(.monotonic) > 0);
        try std.testing.expect(st.ed.checked.load(.monotonic) > st.ed.filled.load(.monotonic)); // some invalid ones too
    }
    try std.testing.expect(set_off.ed.cached.load(.monotonic) > 0); // the warm run
    try std.testing.expect(sig.fast.edVerifiedStats().hits > 0);
    if (n_zk != 0) {
        const zs = set_off.zk.sigs.load(.monotonic) + set_pool.zk.sigs.load(.monotonic);
        const zf = set_off.zk.filled.load(.monotonic) + set_pool.zk.filled.load(.monotonic);
        try std.testing.expect(zs > 0);
        if (zk_ok != 0) try std.testing.expect(zf > 0);
        std.debug.print("preverify test: {d} zkLogin senders ({d} with a valid proof), zk pre-step saw {d}, filled {d}\n", .{ n_zk, zk_ok, zs, zf });
    }
    try std.testing.expect(probe.calls.load(.monotonic) > 0);
    try std.testing.expect(probe.items.load(.monotonic) > 0);
    try std.testing.expectEqual(@as(u32, 0), probe.bad.load(.monotonic));
}

test "stage counters: one batch per block or request, verdicts only where reachable" {
    const gpa = std.testing.allocator;
    const f = try Fixture.create(gpa);
    defer f.destroy();
    var ms: [2]fixture.Made = undefined;
    for (&ms, 0..) |*m, i| m.* = try f.makeTx(.{ .signer = Signer.edSeed(@intCast(i)), .coin = @intCast(i) });
    const low = try f.makeTx(.{ .signer = Signer.edSeed(7), .coin = 7, .expire_epoch = 0 });
    var ctl = try env_mod.LocalEpochControl.init(gpa, &f.stakes);
    defer ctl.deinit();
    var reasons: tx_validator.ReasonCache = .{ .gpa = gpa };
    defer reasons.deinit();
    var v = tx_validator.TxValidator.init(gpa, f.params, f.cfg, &f.env, ctl.control(), &reasons);
    v.preverify = .{ .mode = .on };
    var out: [8]consensus.types.TransactionIndex = undefined;
    const n = try v.verifyAndVote(.{ .round = 1, .author = 0, .digest = @splat(0) }, try f.block(&.{ ms[0].block_tx, low.block_tx, ms[1].block_tx }), &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u16, 1), out[0]);
    try std.testing.expectEqual(@as(u64, 1), v.preverify_stats.batches.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 3), v.preverify_stats.txs.load(.monotonic));
    // the expired transaction fails validity: its signatures are never needed
    try std.testing.expectEqual(@as(u64, 2), v.preverify_stats.verified.load(.monotonic));
    // auto without a pool: off
    v.preverify = .{ .mode = .auto };
    _ = try v.verifyAndVote(.{ .round = 2, .author = 0, .digest = @splat(0) }, try f.block(&.{ ms[0].block_tx, ms[1].block_tx }), &out);
    if (core.pool.shared() == null) try std.testing.expectEqual(@as(u64, 1), v.preverify_stats.batches.load(.monotonic));
}

test "zkLogin pre-step on corpus signatures: zkVerify verdicts equal zkl.verify, every success a cache hit" {
    const gpa = std.testing.allocator;
    const zc = (try ZkCorpus.create(gpa, std.testing.io, 160)) orelse return error.SkipZigTest;
    defer zc.destroy();
    defer sig.fast.configure(.{});
    defer sig.fast.clearCaches();
    const pool = try Pool.init(std.testing.io, gpa, 4);
    defer pool.deinit();
    var accel = gpu.Accel.initOpts(gpa, .{ .mode = .off });
    defer accel.deinit();
    var set: presteps.Set = undefined;
    set.init(std.testing.io, gpa, &accel);
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    // one item per signature (the zk step reads only the signatures), plus one item holding
    // several of them, as a transaction with a sponsor would
    const n = zc.sigs.items.len;
    const items = try a.alloc(preverify.Item, n + 1);
    for (0..n) |i| items[i] = .{ .index = i, .intent = "\x00\x00\x00", .digest = @splat(0), .sigs = zc.sigs.items[i .. i + 1] };
    items[n] = .{ .index = n, .intent = "\x00\x00\x00", .digest = @splat(0), .sigs = zc.sigs.items[0..@min(3, n)] };
    var b1: [512]u8 = undefined;
    var b2: [512]u8 = undefined;
    var total_ok: usize = 0;
    for ([_]zkl.Mode{ .v1_only, .both, .v2_only }) |mode| {
        const uenv: sig.user.UserSigEnv = .{ .epoch = 0, .zklogin = zc.env(mode) };
        const zenv = &uenv.zklogin.?;
        // cache off: the step does nothing
        sig.fast.configure(.{});
        sig.fast.clearCaches();
        const filled0 = set.zk.filled.load(.monotonic);
        set.steps[0].run(set.steps[0].ctx, pool, &uenv, items);
        try std.testing.expectEqual(filled0, set.zk.filled.load(.monotonic));
        // cache on
        presteps.Set.enableCaches();
        set.steps[0].run(set.steps[0].ctx, pool, &uenv, items);
        const filled = set.zk.filled.load(.monotonic) - filled0;
        const before = sig.fast.zkCacheStats();
        var ok: usize = 0;
        var ok_first3: usize = 0;
        for (zc.sigs.items, 0..) |raw, i| {
            const scratch = try gpa.alloc(u8, sig.user.scratchLen(raw.len));
            defer gpa.free(scratch);
            var p: sig.user.Parsed = undefined;
            try std.testing.expect(sig.user.parse(raw, &p, scratch) == null);
            const want = zkl.verify(zenv, &p.zklogin.auth);
            const got = sig.fast.zkVerify(zenv, &p.zklogin.auth);
            try std.testing.expectEqualStrings(want.debugAlloc(&b1), got.debugAlloc(&b2));
            ok += @intFromBool(want == .none);
            if (i < 3) ok_first3 += @intFromBool(want == .none);
        }
        const after = sig.fast.zkCacheStats();
        // every success was put by the step (the first three twice: they are in the same batch
        // twice), so every successful zkVerify was a hit and nothing new was inserted
        try std.testing.expectEqual(ok + ok_first3, filled);
        try std.testing.expectEqual(@as(u64, ok), after.hits - before.hits);
        try std.testing.expectEqual(before.inserts, after.inserts);
        total_ok += ok;
        std.debug.print("zk pre-step, mode {s}: {d} signatures, {d} proofs verify, {d} cached by the step\n", .{ @tagName(mode), n, ok, filled });
    }
    try std.testing.expect(total_ok > 0);
}

test "Ed25519 pre-step: only accepted signatures enter the verified cache (Accel off and forced pool)" {
    const gpa = std.testing.allocator;
    defer sig.fast.configure(.{});
    defer sig.fast.clearCaches();
    const pool = try Pool.init(std.testing.io, gpa, 4);
    defer pool.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    // 200 transactions: Ed25519 (every 5th corrupted), a k1 one and a malformed one mixed in
    const n = 200;
    const items = try a.alloc(preverify.Item, n);
    var n_valid: usize = 0;
    for (items, 0..) |*it, i| {
        var d: [32]u8 = @splat(0);
        std.mem.writeInt(u32, d[0..4], @intCast(i), .little);
        const signer = if (i % 50 == 7) Signer.k1Seed(@intCast(i)) else Signer.edSeed(@intCast(i));
        var s = try signer.sign(a, &d);
        if (i % 50 == 9) s = s[0..40]; // wrong length: not a plain Ed25519 signature
        if (i % 5 == 0) {
            const c = try a.dupe(u8, s);
            c[10] ^= 1;
            s = c;
        }
        const sigs = try a.alloc([]const u8, 1);
        sigs[0] = s;
        it.* = .{ .index = i, .intent = "\x00\x00\x00", .digest = d, .sigs = sigs };
        n_valid += @intFromBool(signer == .ed and i % 5 != 0 and i % 50 != 9);
    }
    const env: sig.user.UserSigEnv = .{ .epoch = 0 };
    for (0..2) |which| {
        var accel = gpu.Accel.initOpts(gpa, .{ .mode = .off });
        defer accel.deinit();
        accel.pool = pool;
        if (which == 1) accel.forced = .pool;
        var set: presteps.Set = undefined;
        set.init(std.testing.io, gpa, &accel);
        sig.fast.configure(.{});
        sig.fast.clearCaches();
        // default: a CPU path is left to the per-transaction pass
        presteps.Set.enableCaches();
        const ins0 = sig.fast.edVerifiedStats().inserts;
        set.steps[1].run(set.steps[1].ctx, pool, &env, items);
        try std.testing.expectEqual(@as(u64, 1), set.ed.skipped.load(.monotonic));
        try std.testing.expectEqual(@as(u64, 0), set.ed.checked.load(.monotonic));
        try std.testing.expectEqual(ins0, sig.fast.edVerifiedStats().inserts);
        set.ed.cpu = true;
        set.ed.calls.store(0, .monotonic);
        sig.fast.configure(.{});
        set.steps[1].run(set.steps[1].ctx, pool, &env, items);
        try std.testing.expectEqual(@as(u64, 0), set.ed.calls.load(.monotonic)); // cache off: nothing
        presteps.Set.enableCaches();
        set.steps[1].run(set.steps[1].ctx, pool, &env, items);
        try std.testing.expectEqual(@as(u64, n_valid), set.ed.filled.load(.monotonic));
        for (items) |it| {
            const s = it.sigs[0];
            if (s.len != 97 or s[0] != 0) continue;
            const want = sig.ed25519.verify(s[65..97], &it.digest, s[1..65]) == .valid;
            try std.testing.expectEqual(want, sig.fast.edVerifiedContains(&sig.fast.edVerifiedKey(s[65..97], &it.digest, s[1..65])));
            // another digest never hits
            var d2 = it.digest;
            d2[31] ^= 1;
            try std.testing.expect(!sig.fast.edVerifiedContains(&sig.fast.edVerifiedKey(s[65..97], &d2, s[1..65])));
        }
        // a second pass finds every plain Ed25519 signature it accepted cached and checks the rest again
        const checked = set.ed.checked.load(.monotonic);
        set.steps[1].run(set.steps[1].ctx, pool, &env, items);
        try std.testing.expectEqual(@as(u64, n_valid), set.ed.cached.load(.monotonic));
        try std.testing.expectEqual(checked * 2 - n_valid, set.ed.checked.load(.monotonic));
    }
}
