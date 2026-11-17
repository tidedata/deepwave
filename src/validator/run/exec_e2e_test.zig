//! End to end over a real Mysten `sui genesis` (1.83.1) blob: load genesis, seed the exec and
//! checkpoint stores, execute a consensus commit prologue and a signed transfer of a genesis gas
//! coin (a sui.keystore key) through the exec bridge, build checkpoint 1 with the checkpoint
//! builder over this Env and Store (settlement and barrier included when accumulators are on),
//! then reopen both stores and check what survived.
//!
//! Needs `$ZUI_VALIDATOR_GENESIS` = path of genesis.blob, with sui.keystore beside it (skipped
//! otherwise). Generate on a test machine:
//!   /opt/sui-1.83.1/sui genesis --working-dir DIR --force
//! `$ZUI_VALIDATOR_E2E_VERBOSE` prints the transfer (base64 data and signature) and its effects
//! digest, to execute the same transaction on a Mysten localnet from that genesis and compare.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const protocol = @import("protocol");
const exec = @import("exec");
const checkpoint = @import("checkpoint");
const exec_bridge = @import("../authority/exec_bridge.zig");
const state_mod = @import("../authority/state.zig");
const builder = @import("../checkpoints/builder.zig");
const iface = @import("../iface.zig");
const state_update = @import("../randomness/state_update.zig");
const genesis_mod = @import("genesis.zig");
const store_mod = @import("exec_store.zig");
const ckpt_store = @import("ckpt_store.zig");
const runner_mod = @import("runner.zig");
const ckpt_env = @import("ckpt_env.zig");
const objects = @import("objects.zig");

const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;
const ObjectView = exec.objects.ObjectView;
const Id = [32]u8;
const testing = std.testing;

const Key = struct { kp: Ed25519.KeyPair, address: Id };

fn keystore(a: Allocator, io: std.Io, dir: []const u8) ![]Key {
    const path = try std.fs.path.join(a, &.{ dir, "sui.keystore" });
    const text = try std.Io.Dir.cwd().readFileAlloc(io, path, a, .unlimited);
    const parsed = try std.json.parseFromSliceLeaky([]const []const u8, a, text, .{});
    var out: std.ArrayList(Key) = .empty;
    for (parsed) |b64| {
        var raw: [64]u8 = undefined;
        const n = try std.base64.standard.Decoder.calcSizeForSlice(b64);
        if (n != 33) continue;
        try std.base64.standard.Decoder.decode(raw[0..n], b64);
        if (raw[0] != 0) continue; // Ed25519 only
        const kp = try Ed25519.KeyPair.generateDeterministic(raw[1..33].*);
        const pk = kp.public_key.toBytes();
        try out.append(a, .{ .kp = kp, .address = hash.blake2b256(&.{ &[_]u8{0}, &pk }) });
    }
    return out.items;
}

/// A genesis GasCoin owned by one of `keys`.
fn findGas(g: *const genesis_mod.Genesis, keys: []const Key) ?struct { raw: []const u8, key: Key } {
    for (g.objects) |raw| {
        if (raw.len < 2 or raw[0] != 0 or raw[1] != 1) continue; // Data::Move, MoveObjectType::GasCoin
        const v = ObjectView.parse(raw) catch continue;
        const o = v.ownerBytes();
        if (o.len != 33 or o[0] != 0) continue;
        for (keys) |k| if (std.mem.eql(u8, o[1..33], &k.address)) return .{ .raw = raw, .key = k };
    }
    return null;
}

const Sigs = struct {
    digest: Id,
    sig: []const u8,
    fn get(ctx: *anyopaque, arena: Allocator, d: *const Id) ?state_mod.UserSigs {
        _ = arena;
        const s: *Sigs = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, d, &s.digest)) return null;
        return .{ .digest = s.digest, .sigs = @as([*]const []const u8, @ptrCast(&s.sig))[0..1], .alias_versions = &.{null} };
    }
};

test "e2e: genesis, prologue, signed transfer, checkpoint 1, reopen (skipped without $ZUI_VALIDATOR_GENESIS)" {
    const gpa = testing.allocator;
    const io = testing.io;
    const blob = genesis_mod.testBlob(gpa, io) orelse return error.SkipZigTest;
    defer gpa.free(blob);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const g = try genesis_mod.load(a, blob);
    const gdir = std.fs.path.dirname(std.mem.span(std.c.getenv("ZUI_VALIDATOR_GENESIS").?)) orelse ".";
    const keys = try keystore(a, io, gdir);
    const gas = findGas(&g, keys) orelse return error.NoGasCoin;
    const gv = try ObjectView.parse(gas.raw);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const db = pb[0..try tmp.dir.realPath(io, &pb)];

    const cfg = try protocol.get(g.protocol_version, .unknown);
    const ctx: runner_mod.EpochCtx = .{ .cfg = cfg, .epoch = 0, .epoch_start_ms = g.epoch_start_timestamp_ms, .rgp = g.reference_gas_price, .chain_id = g.chain_id, .committee_size = @intCast(g.validators.len) };

    var transfer_digest: Id = undefined;
    var ccp_digest: Id = undefined;
    var built_digest: Id = undefined;
    var n_settle: usize = 0;
    const recipient: Id = @splat(0x42);
    {
        var es = try store_mod.ExecStore.open(gpa, io, db);
        defer es.close();
        try es.seedGenesis(&g);
        try es.seedGenesis(&g); // idempotent
        try testing.expectEqual(@as(usize, 1), es.txCount());
        var cs = try ckpt_store.CkptStore.open(gpa, io, db);
        defer cs.close();
        try cs.seedGenesis(&g);

        var r: runner_mod.Runner = undefined;
        r.init(gpa, &es, ctx);
        defer r.deinit();

        // the consensus commit prologue (V4) of round 1
        const clock_raw = es.latest(&runner_mod.clock_id) orelse return error.NoClock;
        const clock_v = (try ObjectView.parse(clock_raw)).version;
        const ccp_td = state_update.systemTransactionData(.{ .ConsensusCommitPrologueV4 = .{
            .epoch = 0,
            .round = 1,
            .sub_dag_index = null,
            .commit_timestamp_ms = g.epoch_start_timestamp_ms + 1000,
            .consensus_commit_digest = std.mem.zeroes(types.ConsensusCommitDigest),
            .consensus_determined_version_assignments = .{ .CancelledTransactionsV2 = &.{} },
            .additional_state_digest = std.mem.zeroes(types.AdditionalConsensusStateDigest),
        } });
        const ccp_bcs = try bcs.encodeAlloc(types.TransactionData, a, &ccp_td);
        ccp_digest = types.digest.transactionDataDigest(ccp_bcs);

        // TransferObjects([GasCoin], recipient), paid by the coin itself
        const inputs = try a.alloc(types.CallArg, 1);
        inputs[0] = .{ .Pure = try a.dupe(u8, &recipient) };
        const cmds = try a.alloc(types.Command, 1);
        cmds[0] = .{ .TransferObjects = .{ &.{.GasCoin}, .{ .Input = 0 } } };
        const pay = try a.alloc(struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest }, 1);
        pay[0] = .{ .{ .@"0" = .{ .@"0" = gv.id } }, .{ .@"0" = gv.version }, .{ .@"0" = .{ .@"0" = gv.digest() } } };
        const sender: types.SuiAddress = .{ .@"0" = gas.key.address };
        const td: types.TransactionData = .{ .V1 = .{
            .kind = .{ .ProgrammableTransaction = .{ .inputs = inputs, .commands = cmds } },
            .sender = sender,
            .gas_data = .{ .payment = pay, .owner = sender, .price = g.reference_gas_price, .budget = 50_000_000 },
            .expiration = .None,
        } };
        const td_bcs = try bcs.encodeAlloc(types.TransactionData, a, &td);
        transfer_digest = types.digest.transactionDataDigest(td_bcs);
        // the user signature: Ed25519 over Blake2b256(intent ++ data)
        const intent_digest = hash.blake2b256(&.{ &[_]u8{ 0, 0, 0 }, td_bcs });
        const sg = try gas.key.kp.sign(&intent_digest, null);
        const sig_bytes = try a.alloc(u8, 97);
        sig_bytes[0] = 0;
        sig_bytes[1..65].* = sg.toBytes();
        sig_bytes[65..97].* = gas.key.kp.public_key.toBytes();
        var sigs: Sigs = .{ .digest = transfer_digest, .sig = sig_bytes };

        // through the bridge: the transfer is queued first and still runs (owned input ready)
        var bridge = exec_bridge.Bridge.init(gpa, r.runner());
        defer bridge.deinit();
        try bridge.enqueue(.{ .key = .{ .digest = transfer_digest }, .kind = .user, .td_bcs = td_bcs, .digest = transfer_digest, .shared = &.{}, .system = &.{}, .owned = &.{.{ .id = gv.id, .version = gv.version, .digest = gv.digest() }} });
        try bridge.enqueue(.{ .key = .{ .digest = ccp_digest }, .kind = .consensus_commit_prologue, .td_bcs = ccp_bcs, .digest = ccp_digest, .shared = &.{.{ .id = runner_mod.clock_id, .isv = 1, .version = clock_v }}, .system = &.{} });
        const acc = es.latest(&runner_mod.acc_root_id) != null and cfg.feature_flags.enable_accumulators;
        const skey: store_mod.Key = .{ .accumulator_settlement = .{ .epoch = 0, .height = 1 } };
        if (acc) try bridge.enqueue(.{ .key = skey, .kind = .accumulator_settlement, .td_bcs = null, .digest = null, .shared = &.{}, .system = &.{} });
        try testing.expectEqual(@as(usize, 2), try bridge.pump(a));
        if (r.lastError().len != 0) std.debug.print("runner: {s}\n", .{r.lastError()});
        try testing.expectEqual(@as(u64, 0), bridge.unsupported);
        try testing.expect(bridge.effectsDigest(&transfer_digest) != null);

        const fx = (try bcs.decode(types.TransactionEffects, a, es.effects(&transfer_digest).?)).V2;
        if (std.c.getenv("ZUI_VALIDATOR_E2E_VERBOSE") != null) {
            // for a cross-check against a Mysten node from the same genesis
            // (`sui client execute-signed-tx --tx-bytes TX --signatures SIG`)
            const enc = std.base64.standard.Encoder;
            const tb = try a.alloc(u8, enc.calcSize(td_bcs.len));
            const sb = try a.alloc(u8, enc.calcSize(sig_bytes.len));
            std.debug.print("e2e transfer: TX={s} SIG={s} effects_digest={x}\n", .{ enc.encode(tb, td_bcs), enc.encode(sb, sig_bytes), &es.executed(&transfer_digest).?.effects_digest });
        }
        try testing.expect(fx.status == .Success);
        const moved = es.latest(&gv.id).?;
        try testing.expectEqualSlices(u8, &recipient, (try ObjectView.parse(moved)).ownerBytes()[1..33]);
        const cfx = (try bcs.decode(types.TransactionEffects, a, es.effects(&ccp_digest).?)).V2;
        try testing.expect(cfx.status == .Success);

        // checkpoint 1: the prologue and the transfer (+ settlement and barrier)
        var env: ckpt_env.CkptEnv = .{ .runner = &r, .sigs = .{ .ctx = &sigs, .get = Sigs.get } };
        var b = builder.Builder.init(gpa, cfg, 0, env.env(), cs.store(), null);
        defer b.deinit();
        const roots = try a.alloc(iface.CheckpointRoots, 1);
        roots[0] = .{
            .tx_roots = &.{ .{ .digest = .{ .@"0" = .{ .@"0" = ccp_digest } } }, .{ .digest = .{ .@"0" = .{ .@"0" = transfer_digest } } } },
            .settlement_root = if (acc) .{ .accumulator_settlement = .{ .epoch = 0, .height = 1 } } else null,
            .height = 1,
        };
        try b.push(&.{ .roots = roots, .details = .{
            .timestamp_ms = g.epoch_start_timestamp_ms + 1000,
            .last_of_epoch = false,
            .checkpoint_height = 1,
            .consensus_commit_ref = std.mem.zeroes(@FieldType(iface.PendingCheckpointInfo, "consensus_commit_ref")),
            .rejected_transactions_digest = .{ .@"0" = @splat(0) },
            .checkpoint_seq = 1,
        } });
        const n = b.runQueued() catch |e| {
            std.debug.print("builder: {s} runner: {s}\n", .{ @errorName(e), r.lastError() });
            return e;
        };
        try testing.expectEqual(@as(u32, 1), n);
        const last = cs.store().lastBuilt().?;
        try testing.expectEqual(@as(u64, 1), last.seq);
        built_digest = last.digest;
        n_settle = if (acc) 1 else 0; // no accumulator events: no settlement transaction, one barrier
        try testing.expectEqual(@as(u64, 1 + 2 + n_settle), last.network_total_transactions);
        const contents = (try cs.store().builtContents(a, 1)).?;
        const cc = try bcs.decode(types.CheckpointContents, a, contents);
        const txs = cc.V2.transactions;
        try testing.expectEqual(@as(usize, 2 + n_settle), txs.len);
        try testing.expectEqualSlices(u8, &ccp_digest, &txs[0].digest.transaction.@"0".@"0");
        // the transfer carries the user signature, the system transactions the zero signature
        try testing.expectEqualSlices(u8, sig_bytes, txs[1].user_signatures[0][0].@"0");
        try testing.expect(txs[0].user_signatures[0][0].@"0"[1] == 0);
        // the settlement item is now ready and answers the barrier
        if (acc) {
            try testing.expectEqual(@as(usize, 1), try bridge.pump(a));
            try testing.expect(es.keyDigest(skey) != null);
        }
        if (std.c.getenv("ZUI_VALIDATOR_E2E_VERBOSE") != null) std.debug.print("e2e: chain {s}, protocol {d}, checkpoint 1 {x} ({d} txs, accumulators {})\n", .{ &g.chain_id8, g.protocol_version, built_digest[0..8], txs.len, acc });
    }

    // reopen: everything survived
    var es = try store_mod.ExecStore.open(gpa, io, db);
    defer es.close();
    try testing.expectEqual(@as(u64, 0), es.cut_at_open);
    try testing.expect(es.effects(&transfer_digest) != null);
    try testing.expect(es.effects(&ccp_digest) != null);
    try testing.expectEqualSlices(u8, &recipient, (try ObjectView.parse(es.latest(&gv.id).?)).ownerBytes()[1..33]);
    try testing.expect(es.objectAt(&gv.id, gv.version) != null);
    var cs = try ckpt_store.CkptStore.open(gpa, io, db);
    defer cs.close();
    try testing.expectEqualSlices(u8, &built_digest, &cs.store().lastBuilt().?.digest);
    try testing.expectEqual(@as(u64, 1), cs.store().runningRoot().?.seq);
    try testing.expectEqual(@as(u64, 0), cs.store().highestCertified().?);
    // the builder resumes on top of the stored checkpoint: a rebuild of seq 1 is skipped
    var r: runner_mod.Runner = undefined;
    r.init(gpa, &es, ctx);
    defer r.deinit();
    var env: ckpt_env.CkptEnv = .{ .runner = &r };
    var b = builder.Builder.init(gpa, cfg, 0, env.env(), cs.store(), null);
    defer b.deinit();
    try testing.expectEqual(@as(?u64, 1), b.running.last_seq);
}
