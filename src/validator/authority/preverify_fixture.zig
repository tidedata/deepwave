//! Synthetic signed user transactions for the signature pre-verification tests and benchmark
//! (`deepwave-validator preverify-bench`). Local test material only: every key is derived from a
//! small public seed, nothing here touches a validator key or a network.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const sig = @import("sig");
const rpc_exec = @import("rpc_exec");
const consensus = @import("consensus");
const messages = @import("../messages.zig");
const env_mod = @import("env.zig");
const checker = @import("checker.zig");

const Allocator = std.mem.Allocator;
const Blake2b256 = std.crypto.hash.blake2.Blake2b256;
const K1 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const R1 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
pub const Id = [32]u8;

pub const Signer = union(enum) {
    ed: sig.ed25519.KeyPair,
    k1: K1.KeyPair,
    r1: R1.KeyPair,
    /// MultiSig of Ed25519 members, weight 1 each, threshold = member count.
    multi: []const sig.ed25519.KeyPair,
    /// A ready GenericSignature for a given sender, whatever the digest (zkLogin corpus
    /// signatures: their ephemeral key is not ours, so they never verify over a new digest).
    fixed: struct { addr: Id, sig: []const u8 },

    pub fn edSeed(i: u32) Signer {
        return .{ .ed = sig.ed25519.KeyPair.fromSeed(&seedOf(0xed, i)) };
    }
    pub fn k1Seed(i: u32) Signer {
        return .{ .k1 = K1.KeyPair.generateDeterministic(seedOf(0x41, i)) catch unreachable };
    }
    pub fn r1Seed(i: u32) Signer {
        return .{ .r1 = R1.KeyPair.generateDeterministic(seedOf(0x42, i)) catch unreachable };
    }

    pub fn address(s: Signer) Id {
        if (s == .fixed) return s.fixed.addr;
        var h = Blake2b256.init(.{});
        switch (s) {
            .fixed => unreachable,
            .ed => |kp| {
                h.update(&.{0});
                h.update(&kp.pk);
            },
            .k1 => |kp| {
                h.update(&.{1});
                h.update(&kp.public_key.toCompressedSec1());
            },
            .r1 => |kp| {
                h.update(&.{2});
                h.update(&kp.public_key.toCompressedSec1());
            },
            .multi => |ms| {
                h.update(&.{3});
                var t: [2]u8 = undefined;
                std.mem.writeInt(u16, &t, @intCast(ms.len), .little);
                h.update(&t);
                for (ms) |kp| {
                    h.update(&.{0});
                    h.update(&kp.pk);
                    h.update(&.{1});
                }
            },
        }
        var out: Id = undefined;
        h.final(&out);
        return out;
    }

    /// GenericSignature bytes over the intent digest.
    pub fn sign(s: Signer, arena: Allocator, digest: *const [32]u8) ![]const u8 {
        switch (s) {
            .fixed => |f| return arena.dupe(u8, f.sig),
            .ed => |kp| {
                const out = try arena.alloc(u8, 1 + 64 + 32);
                out[0] = 0;
                out[1..65].* = kp.sign(digest);
                out[65..97].* = kp.pk;
                return out;
            },
            .k1 => |kp| return ecdsaSig(K1, arena, 1, kp, digest),
            .r1 => |kp| return ecdsaSig(R1, arena, 2, kp, digest),
            .multi => |ms| {
                var w: std.Io.Writer.Allocating = .init(arena);
                const wr = &w.writer;
                try wr.writeByte(3);
                try wr.writeByte(@intCast(ms.len)); // uleb, < 128
                for (ms) |kp| {
                    try wr.writeByte(0); // CompressedSignature::Ed25519
                    try wr.writeAll(&kp.sign(digest));
                }
                try wr.writeInt(u16, @intCast((@as(u32, 1) << @intCast(ms.len)) - 1), .little);
                try wr.writeByte(@intCast(ms.len));
                for (ms) |kp| {
                    try wr.writeByte(0); // PublicKey::Ed25519
                    try wr.writeAll(&kp.pk);
                    try wr.writeByte(1);
                }
                try wr.writeInt(u16, @intCast(ms.len), .little);
                return w.written();
            },
        }
    }
};

fn seedOf(tag: u8, i: u32) [32]u8 {
    var s: [32]u8 = @splat(tag);
    std.mem.writeInt(u32, s[0..4], i +% 1, .little);
    return s;
}

/// Sui ECDSA user signature: flag, (r, s) with s normalized low, compressed key; ECDSA over
/// SHA-256 of the 32-byte intent digest.
fn ecdsaSig(comptime S: type, arena: Allocator, flag: u8, kp: S.KeyPair, digest: *const [32]u8) ![]const u8 {
    const sg = try kp.sign(digest, null);
    var b = sg.toBytes();
    const order = S.Curve.scalar.field_order;
    const sv = std.mem.readInt(u256, b[32..64], .big);
    if (sv > order / 2) std.mem.writeInt(u256, b[32..64], order - sv, .big);
    const out = try arena.alloc(u8, 1 + 64 + 33);
    out[0] = flag;
    out[1..65].* = b;
    out[65..98].* = kp.public_key.toCompressedSec1();
    return out;
}

pub fn gasCoin(arena: Allocator, id: Id, version: u64, owner: Id, balance: u64) ![]const u8 {
    const buf = try arena.alloc(u8, 3 + 8 + 1 + 40 + 1 + 32 + 33 + 8);
    @memset(buf, 0);
    buf[1] = 1; // MoveObjectType::GasCoin
    buf[2] = 1; // has_public_transfer
    std.mem.writeInt(u64, buf[3..11], version, .little);
    buf[11] = 40;
    @memcpy(buf[12..44], &id);
    std.mem.writeInt(u64, buf[44..52], balance, .little);
    @memcpy(buf[53..85], &owner);
    buf[85] = 32;
    return buf;
}

pub const TxOpts = struct {
    signer: Signer,
    /// Gas coin number (its id); each transaction should use its own.
    coin: u32,
    balance: u64 = 1_000_000_000_000,
    price: u64 = 1000,
    budget: u64 = 5_000_000,
    /// Flip a bit of the signature (invalid signature).
    corrupt_sig: bool = false,
    /// Sign with this key instead of `signer` (wrong signer).
    sign_with: ?Signer = null,
    /// Replace the signature bytes (malformed signature).
    raw_sig: ?[]const u8 = null,
    /// Store the gas coin in the state.
    put_coin: bool = true,
    /// AddressAliasesV2 claim version (a wrong claim: "Address aliases have changed").
    alias_version: ?u64 = null,
    /// A second, unneeded signature (signature count mismatch).
    extra_sig: bool = false,
    /// `TransactionExpiration::Epoch(e)` (0: expired at epoch 1, a validity failure).
    expire_epoch: ?u64 = null,
};

pub const Made = struct {
    /// BCS `Transaction` (a SubmitTransaction entry).
    raw: []const u8,
    /// BCS `ConsensusTransaction` UserTransactionV2 (a block entry).
    block_tx: []const u8,
};

pub const Fixture = struct {
    gpa: Allocator,
    arena_state: std.heap.ArenaAllocator,
    cfg: *const protocol.ProtocolConfig,
    params: env_mod.Params,
    sig_env: sig.user.UserSigEnv,
    map: rpc_exec.state.MapState = .{},
    env: checker.Env,
    stakes: [4]u64 = .{ 2500, 2500, 2500, 2500 },
    recipient: Id = @splat(0x77),

    pub const rgp: u64 = 1000;

    /// Heap-allocated (the env points into it).
    pub fn create(gpa: Allocator) !*Fixture {
        const f = try gpa.create(Fixture);
        errdefer gpa.destroy(f);
        const cfg = try protocol.get(141, .mainnet);
        f.* = .{
            .gpa = gpa,
            .arena_state = .init(gpa),
            .cfg = cfg,
            .params = env_mod.Params.fromProtocol(cfg, 1, 0, rgp),
            .sig_env = .{ .epoch = 1 },
            .env = undefined,
        };
        f.env = .{ .cfg = cfg, .epoch = 1, .chain_id = @splat(0), .rgp = rgp, .committee_size = 4, .state = f.map.state(), .sig_env = &f.sig_env };
        return f;
    }

    pub fn destroy(f: *Fixture) void {
        f.map.map.deinit(f.gpa);
        f.arena_state.deinit();
        f.gpa.destroy(f);
    }

    pub fn arena(f: *Fixture) Allocator {
        return f.arena_state.allocator();
    }

    pub fn coinId(i: u32) Id {
        var id: Id = @splat(0);
        id[0] = 0xc0;
        std.mem.writeInt(u32, id[28..32], i, .big);
        return id;
    }

    pub fn makeTx(f: *Fixture, o: TxOpts) !Made {
        const a = f.arena();
        const sender = o.signer.address();
        const id = coinId(o.coin);
        const version: u64 = 5;
        const coin = try gasCoin(a, id, version, sender, o.balance);
        if (o.put_coin) try f.map.put(f.gpa, id, version, coin);
        const inputs = try a.alloc(types.CallArg, 1);
        inputs[0] = .{ .Pure = try a.dupe(u8, &f.recipient) };
        const objs = try a.alloc(types.Argument, 1);
        objs[0] = .GasCoin;
        const cmds = try a.alloc(types.Command, 1);
        cmds[0] = .{ .TransferObjects = .{ objs, .{ .Input = 0 } } };
        const Pay = @typeInfo(@TypeOf(@as(types.GasData, undefined).payment)).pointer.child;
        const pay = try a.alloc(Pay, 1);
        pay[0] = .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = version }, .{ .@"0" = .{ .@"0" = types.digest.objectDigest(coin) } } };
        const td: types.TransactionData = .{ .V1 = .{
            .kind = .{ .ProgrammableTransaction = .{ .inputs = inputs, .commands = cmds } },
            .sender = .{ .@"0" = sender },
            .gas_data = .{ .payment = pay, .owner = .{ .@"0" = sender }, .price = o.price, .budget = o.budget },
            .expiration = if (o.expire_epoch) |e| .{ .Epoch = e } else .None,
        } };
        const td_bcs = try bcs.encodeAlloc(types.TransactionData, a, &td);
        const intent = try a.alloc(u8, 3 + td_bcs.len);
        @memset(intent[0..3], 0);
        @memcpy(intent[3..], td_bcs);
        var digest: [32]u8 = undefined;
        Blake2b256.hash(intent, &digest, .{});

        var s = if (o.raw_sig) |r| r else try (o.sign_with orelse o.signer).sign(a, &digest);
        if (o.corrupt_sig) {
            const c = try a.dupe(u8, s);
            c[5] ^= 0x01;
            s = c;
        }
        const nsigs: usize = if (o.extra_sig) 2 else 1;
        const sigs = try a.alloc(types.GenericSignature, nsigs);
        sigs[0] = .{ .@"0" = s };
        if (o.extra_sig) sigs[1] = .{ .@"0" = try Signer.edSeed(9999).sign(a, &digest) };
        const sst = try a.alloc(types.SenderSignedTransaction, 1);
        sst[0] = .{ .intent_message = .{ .intent = types.Intent.sui(.transaction_data), .value = td }, .tx_signatures = sigs };
        const tx: messages.Transaction = .{ .data = .{ .@"0" = .{ .items = sst } }, .auth_signature = .{} };
        const raw = try bcs.encodeAlloc(messages.Transaction, a, &tx);

        var claims: []const messages.TransactionClaim = &.{};
        if (f.cfg.feature_flags.address_aliases) {
            const Al = @typeInfo(@FieldType(messages.TransactionClaim, "AddressAliasesV2")).pointer.child;
            const al = try a.alloc(Al, 1);
            al[0] = .{ 0, if (o.alias_version) |v| types.SequenceNumber{ .@"0" = v } else null };
            const c = try a.alloc(messages.TransactionClaim, 1);
            c[0] = .{ .AddressAliasesV2 = al };
            claims = c;
        }
        const ct: messages.ConsensusTransaction = .{ .tracking_id = @splat(0), .kind = .{ .UserTransactionV2 = .{ .tx = tx, .claims = claims } } };
        return .{ .raw = raw, .block_tx = try bcs.encodeAlloc(messages.ConsensusTransaction, a, &ct) };
    }

    pub fn block(f: *Fixture, items: []const []const u8) ![]consensus.types.Transaction {
        const out = try f.arena().alloc(consensus.types.Transaction, items.len);
        for (items, out) |i, *o| o.* = .{ .data = i };
        return out;
    }
};

// ---------------------------------------------------------------------------------------------
// `deepwave-validator preverify-bench`: the stage off vs on for blocks and submit requests of N signed
// transactions (no keys, no network, no gate).

const tx_validator = @import("tx_validator.zig");
const submit_mod = @import("submit.zig");
const state_mod = @import("state.zig");
const adapter_mod = @import("adapter.zig");
const preverify = @import("preverify.zig");
const presteps = @import("presteps.zig");
const core = @import("core");
const gpu = @import("gpu");

pub const bench_usage =
    \\deepwave-validator preverify-bench [--lanes N] [--sizes 1,8,64,256,1024] [--reps R] [--mixed]
    \\                              [--pre-steps] [--pre-cpu] [--gpu off|auto|metal|cuda]
    \\    block votes (verifyAndVote) and SubmitTransaction (n <= 128) with --sig-preverify off vs on;
    \\    synthetic local transactions only. --mixed: Ed25519, secp256k1 and secp256r1 senders.
    \\    --pre-steps: a third column, on with the zkLogin and Ed25519 pre-steps and their caches
    \\    (Accel per --gpu, default ZUI_GPU, unset = off). Caches are cleared before every rep.
    \\    --pre-cpu: the Ed25519 step also runs when the Accel picks a CPU path (default: skipped).
    \\
;

fn nowNs(io: std.Io) i128 {
    return std.Io.Clock.awake.now(io).toNanoseconds();
}

fn median(xs: []u64) u64 {
    std.mem.sort(u64, xs, {}, std.sort.asc(u64));
    return xs[xs.len / 2];
}

fn noNow() u64 {
    return 1;
}

pub fn benchMain(gpa: Allocator, io: std.Io, args: []const []const u8) u8 {
    return benchRun(gpa, io, args) catch |e| {
        std.debug.print("preverify-bench: {s}\n", .{@errorName(e)});
        return 1;
    };
}

fn benchRun(gpa: Allocator, io: std.Io, args: []const []const u8) !u8 {
    var lanes: usize = 0;
    var reps: usize = 0;
    var mixed = false;
    var with_pre = false;
    var pre_cpu = false;
    var gpu_mode: gpu.Mode = gpu.modeFromEnv();
    var sizes_buf: [16]usize = undefined;
    var sizes: []const usize = &.{ 1, 8, 64, 256, 1024 };
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const has = i + 1 < args.len;
        if (std.mem.eql(u8, a, "--lanes") and has) {
            i += 1;
            lanes = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, a, "--reps") and has) {
            i += 1;
            reps = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, a, "--sizes") and has) {
            i += 1;
            var n: usize = 0;
            var it = std.mem.splitScalar(u8, args[i], ',');
            while (it.next()) |x| : (n += 1) {
                if (n == sizes_buf.len) return error.TooManySizes;
                sizes_buf[n] = try std.fmt.parseInt(usize, x, 10);
            }
            sizes = sizes_buf[0..n];
        } else if (std.mem.eql(u8, a, "--mixed")) {
            mixed = true;
        } else if (std.mem.eql(u8, a, "--pre-steps")) {
            with_pre = true;
        } else if (std.mem.eql(u8, a, "--pre-cpu")) {
            pre_cpu = true;
        } else if (std.mem.eql(u8, a, "--gpu") and has) {
            i += 1;
            gpu_mode = gpu.Mode.parse(args[i]) orelse return error.BadGpuMode;
        } else {
            std.debug.print("{s}", .{bench_usage});
            return 2;
        }
    }
    const pool = try core.pool.Pool.init(io, gpa, lanes);
    defer pool.deinit();
    defer sig.fast.configure(.{});
    defer sig.fast.clearCaches();
    var accel = gpu.Accel.initOpts(gpa, .{ .mode = if (with_pre) gpu_mode else .off });
    defer accel.deinit();
    accel.pool = pool;
    // the machine's dispatch table (cached calibration, or a new one), as deepwave-validator does
    if (accel.deviceCount() > 0) _ = gpu.calibrate.autoTable(io, gpa, &accel, null, false, .{});
    var steps: presteps.Set = undefined;
    steps.init(io, gpa, &accel);
    steps.ed.cpu = pre_cpu;
    std.debug.print("preverify-bench: pool lanes {d}, senders {s}", .{ pool.lanes(), if (mixed) "ed25519/secp256k1/secp256r1 (1:1:1)" else "ed25519" });
    if (with_pre) std.debug.print(", pre-steps on, gpu {s} ({d} devices){s}", .{ accel.name(), accel.deviceCount(), if (pre_cpu) ", ed25519 step on CPU paths too" else "" });
    std.debug.print("\n{s:>6} {s:>8} {s:>12} {s:>12} {s:>8} {s:>12} {s:>12} {s:>8}", .{ "n", "path", "off us/tx", "on us/tx", "speedup", "off ms", "on ms", "rejects" });
    if (with_pre) std.debug.print(" {s:>12} {s:>8} {s:>12} {s:>8}", .{ "pre us/tx", "speedup", "pre ms", "rejects" });
    std.debug.print("\n", .{});
    const n_modes: usize = if (with_pre) 3 else 2;
    const modes = [3]BenchMode{ .{ .mode = .off }, .{ .mode = .on }, .{ .mode = .on, .pre = true } };

    for (sizes) |n| {
        const f = try Fixture.create(gpa);
        defer f.destroy();
        const blk = try f.arena().alloc([]const u8, n);
        const raws = try f.arena().alloc([]const u8, n);
        for (0..n) |k| {
            const s: Signer = if (!mixed) Signer.edSeed(@intCast(k)) else switch (k % 3) {
                0 => Signer.edSeed(@intCast(k)),
                1 => Signer.k1Seed(@intCast(k)),
                else => Signer.r1Seed(@intCast(k)),
            };
            const m = try f.makeTx(.{ .signer = s, .coin = @intCast(k) });
            blk[k] = m.block_tx;
            raws[k] = m.raw;
        }
        const block = try f.block(blk);
        const r = if (reps != 0) reps else @max(5, @min(200, 4096 / n));

        // block votes
        var res: [3]BenchRes = undefined;
        for (modes[0..n_modes], 0..) |bm, mi| {
            var reasons: tx_validator.ReasonCache = .{ .gpa = gpa };
            defer reasons.deinit();
            var ctl = try env_mod.LocalEpochControl.init(gpa, &f.stakes);
            defer ctl.deinit();
            var v = tx_validator.TxValidator.init(gpa, f.params, f.cfg, &f.env, ctl.control(), &reasons);
            v.preverify = .{ .mode = bm.mode, .pool = pool, .pre_steps = if (bm.pre) steps.slice() else &.{} };
            bm.caches(&steps);
            const out = try gpa.alloc(consensus.types.TransactionIndex, n);
            defer gpa.free(out);
            const times = try gpa.alloc(u64, r);
            defer gpa.free(times);
            var rej: usize = 0;
            for (times, 0..) |*t, k| {
                sig.fast.clearCaches();
                const t0 = nowNs(io);
                rej = try v.verifyAndVote(.{ .round = @intCast(k + 1), .author = 0, .digest = @splat(0) }, block, out);
                t.* = @intCast(nowNs(io) - t0);
            }
            res[mi] = .{ .med = median(times), .rejects = rej };
        }
        printRow(n, "block", res[0..n_modes]);

        // submit requests (at most 128 transactions each); fresh state per run (in-flight marks)
        if (n <= 128) {
            for (modes[0..n_modes], 0..) |bm, mi| {
                bm.caches(&steps);
                const times = try gpa.alloc(u64, r);
                defer gpa.free(times);
                var rej: usize = 0;
                for (times) |*t| {
                    var ctl = try env_mod.LocalEpochControl.init(gpa, &f.stakes);
                    defer ctl.deinit();
                    var state = state_mod.EpochState.init(gpa);
                    defer state.deinit();
                    var adapter = adapter_mod.Adapter.init(gpa, .{});
                    defer adapter.deinit();
                    var s: submit_mod.Submit = .{ .gpa = gpa, .params = f.params, .cfg = f.cfg, .check_env = &f.env, .state = &state, .epoch_ctl = ctl.control(), .adapter = &adapter, .own_index = 0, .own_name = .{ .@"0" = @splat(0) }, .now_ms = noNow, .preverify = .{ .mode = bm.mode, .pool = pool, .pre_steps = if (bm.pre) steps.slice() else &.{} } };
                    defer s.deinit();
                    var ar: std.heap.ArenaAllocator = .init(gpa);
                    defer ar.deinit();
                    var failure: submit_mod.Failure = undefined;
                    sig.fast.clearCaches();
                    const t0 = nowNs(io);
                    const resp = s.handle(ar.allocator(), .{ .transactions = raws }, &failure) catch |e| {
                        std.debug.print("submit failed: {s} {s}\n", .{ @errorName(e), failure.message });
                        return error.SubmitFailed;
                    };
                    t.* = @intCast(nowNs(io) - t0);
                    rej = 0;
                    for (resp.results) |x| rej += @intFromBool(x != .submitted);
                }
                res[mi] = .{ .med = median(times), .rejects = rej };
            }
            printRow(n, "submit", res[0..n_modes]);
        }
    }
    return 0;
}

const BenchMode = struct {
    mode: preverify.Mode,
    /// The real pre-steps with the zk and Ed25519 verified caches on.
    pre: bool = false,

    fn caches(bm: BenchMode, steps: *const presteps.Set) void {
        if (bm.pre) steps.enableUsed() else sig.fast.configure(.{});
    }
};

const BenchRes = struct { med: u64, rejects: usize };

fn printRow(n: usize, path: []const u8, res: []const BenchRes) void {
    const nf: f64 = @floatFromInt(n);
    const offf: f64 = @floatFromInt(res[0].med);
    const onf: f64 = @floatFromInt(res[1].med);
    std.debug.print("{d:>6} {s:>8} {d:>12.2} {d:>12.2} {d:>7.2}x {d:>12.3} {d:>12.3} {d:>4}/{d}", .{ n, path, offf / 1000.0 / nf, onf / 1000.0 / nf, offf / @max(onf, 1), offf / 1e6, onf / 1e6, res[0].rejects, res[1].rejects });
    if (res.len > 2) {
        const pf: f64 = @floatFromInt(res[2].med);
        std.debug.print(" {d:>12.2} {d:>7.2}x {d:>12.3} {d:>8}", .{ pf / 1000.0 / nf, offf / @max(pf, 1), pf / 1e6, res[2].rejects });
    }
    std.debug.print("\n", .{});
}
