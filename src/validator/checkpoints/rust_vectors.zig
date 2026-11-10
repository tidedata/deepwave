//! Checkpoint wire vectors generated from Mysten's Rust at mainnet-v1.83.1 (sui-types, by
//! tools/truth/checkpoints/vectors/run.sh; the `v_*` constants at the bottom are its output,
//! pasted verbatim). Every vector is rebuilt here by deepwave's code from the same fixed inputs:
//!
//!   contents V1/V2     CheckpointContents BCS and digest (system signature, an alias version)
//!   summaries          a protocol 141 summary (artifacts commitment, version-specific data V1
//!                      with two randomness rounds) and an end-of-epoch summary (next committee,
//!                      protocol version, ECMH root), BCS and digest
//!   signing            four generated BLS keys sign the summary (Intent(2,0,0) ++ BCS ++ epoch):
//!                      signature bytes and the CheckpointSignatureV2 ConsensusTransaction each
//!                      validator submits, tracking id included
//!   certificate        AuthorityStrongQuorumSignInfo of 3 of 4 signers and of all 4, and the
//!                      CertifiedCheckpointSummary, built by deepwave's SignatureAggregator
//!   bitmaps            roaring-rs 0.11.4 `serialize_into` for four signer sets
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const bls = @import("bls");
const checkpoint = @import("checkpoint");
const messages = @import("../messages.zig");
const iface = @import("../iface.zig");
const create = @import("create.zig");
const output = @import("output.zig");
const aggregator = @import("aggregator.zig");
const store_mod = @import("store.zig");

const testing = std.testing;

fn hx(comptime s: []const u8) *const [s.len / 2]u8 {
    return comptime blk: {
        @setEvalBranchQuota(1_000_000);
        var out: [s.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, s) catch unreachable;
        const o = out;
        break :blk &o;
    };
}

fn d32(b: u8) [32]u8 {
    return @splat(b);
}

fn sigA() [97]u8 {
    var b: [97]u8 = undefined;
    b[0] = 0;
    for (0..64) |i| b[1 + i] = @as(u8, @intCast(i)) ^ 0x5a;
    for (0..32) |i| b[65 + i] = @as(u8, @intCast(i)) *% 3;
    return b;
}

const sig_sys: [97]u8 = @splat(0);

fn ed(t: u8, e: u8) types.ExecutionDigests {
    return .{ .transaction = .{ .@"0" = .{ .@"0" = d32(t) } }, .effects = .{ .@"0" = .{ .@"0" = d32(e) } } };
}

fn gsig(b: []const u8) types.hand.GenericSignature {
    return .{ .@"0" = b };
}

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    sks: [4]bls.SecretKey,
    committee: checkpoint.Committee,
    contents_v1: []u8,
    contents_v2: []u8,
    summary: types.CheckpointSummary,
    summary_bcs: []u8,

    fn init(gpa: std.mem.Allocator) !*Fixture {
        const f = try gpa.create(Fixture);
        f.arena = std.heap.ArenaAllocator.init(gpa);
        const a = f.arena.allocator();
        const sa = sigA();
        const sa_s = try a.dupe(u8, &sa);
        const sys_s = try a.dupe(u8, &sig_sys);

        const c1: types.CheckpointContents = .{ .V1 = .{
            .transactions = &.{ ed(1, 2), ed(3, 4) },
            .user_signatures = &.{ &.{gsig(sys_s)}, &.{ gsig(sa_s), gsig(sys_s) } },
        } };
        f.contents_v1 = try bcs.encodeAlloc(types.CheckpointContents, a, &c1);
        const t1 = try a.alloc(create.SigEntry, 1);
        t1[0] = .{ gsig(sys_s), null };
        const t2 = try a.alloc(create.SigEntry, 2);
        t2[0] = .{ gsig(sa_s), .{ .@"0" = 42 } };
        t2[1] = .{ gsig(sys_s), null };
        const txs = try a.alloc(types.CheckpointTransactionContents, 2);
        txs[0] = .{ .digest = ed(1, 2), .user_signatures = t1 };
        txs[1] = .{ .digest = ed(3, 4), .user_signatures = t2 };
        const c2: types.CheckpointContents = .{ .V2 = .{ .transactions = txs } };
        f.contents_v2 = try bcs.encodeAlloc(types.CheckpointContents, a, &c2);

        const cfg = try protocol.get(141, .mainnet);
        const commitments = try a.alloc(types.CheckpointCommitment, 1);
        commitments[0] = .{ .CheckpointArtifactsDigest = .{ .@"0" = .{ .@"0" = d32(9) } } };
        f.summary = .{
            .epoch = 5,
            .sequence_number = 12,
            .network_total_transactions = 1000,
            .content_digest = .{ .@"0" = .{ .@"0" = types.digest.checkpointContentsDigest(f.contents_v2) } },
            .previous_digest = .{ .@"0" = .{ .@"0" = d32(7) } },
            .epoch_rolling_gas_cost_summary = .{ .computationCost = 1, .storageCost = 2, .storageRebate = 3, .nonRefundableStorageFee = 4 },
            .timestamp_ms = 1_700_000_000_123,
            .checkpoint_commitments = commitments,
            .end_of_epoch_data = null,
            .version_specific_data = try create.versionSpecificData(a, cfg, &.{ 77, 78 }),
        };
        f.summary_bcs = try bcs.encodeAlloc(types.CheckpointSummary, a, &f.summary);

        var members: [4]checkpoint.Member = undefined;
        for (&f.sks, &members, 0..) |*sk, *m, i| {
            var seed: [32]u8 = @splat(0);
            seed[0] = 0x21;
            seed[31] = @intCast(i + 1);
            sk.* = bls.SecretKey.fromBytes(&seed).?;
            m.* = .{ .name = sk.publicKey().toBytes(), .stake = 2500 };
        }
        f.committee = try checkpoint.Committee.init(a, 5, &members);
        return f;
    }

    fn deinit(f: *Fixture, gpa: std.mem.Allocator) void {
        f.arena.deinit();
        gpa.destroy(f);
    }

    fn vote(f: *const Fixture, i: usize) !aggregator.Vote {
        const msg = try create.signingMessage(testing.allocator, f.summary_bcs, 5);
        defer testing.allocator.free(msg);
        return .{
            .seq = 12,
            .digest = types.digest.checkpointSummaryDigest(f.summary_bcs),
            .epoch = 5,
            .authority = f.sks[i].publicKey().toBytes(),
            .sig = f.sks[i].sign(msg).toBytes(),
        };
    }
};

test "rust vectors: protocol 141 checkpoint parameters" {
    const cfg = try protocol.get(141, .mainnet);
    try testing.expectEqual(@as(?u64, 20000), cfg.max_transactions_per_checkpoint);
    try testing.expectEqual(@as(?u64, 31457280), cfg.max_checkpoint_size_bytes);
    try testing.expectEqual(@as(?u64, 200), cfg.min_checkpoint_interval_ms);
    try testing.expectEqual(@as(?u64, 1), cfg.checkpoint_summary_version_specific_data);
    const ff = &cfg.feature_flags;
    try testing.expect(ff.split_checkpoints_in_consensus_handler);
    try testing.expect(ff.merge_randomness_into_checkpoint);
    try testing.expect(ff.consensus_checkpoint_signature_key_includes_digest);
    try testing.expect(ff.include_checkpoint_artifacts_digest_in_summary);
    try testing.expect(ff.commit_root_state_digest);
    try testing.expect(ff.address_aliases);
    try testing.expect(ff.disable_effects_tx_dependencies);
    try testing.expect(ff.prepend_prologue_tx_in_consensus_commit_in_checkpoints);
}

test "rust vectors: contents V1 and V2" {
    const f = try Fixture.init(testing.allocator);
    defer f.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, hx(v_contents_v1), f.contents_v1);
    try testing.expectEqualSlices(u8, hx(v_contents_v1_digest), &types.digest.checkpointContentsDigest(f.contents_v1));
    try testing.expectEqualSlices(u8, hx(v_contents_v2), f.contents_v2);
    try testing.expectEqualSlices(u8, hx(v_contents_v2_digest), &types.digest.checkpointContentsDigest(f.contents_v2));
}

test "rust vectors: summaries and version-specific data" {
    const f = try Fixture.init(testing.allocator);
    defer f.deinit(testing.allocator);
    const a = f.arena.allocator();
    const cfg = try protocol.get(141, .mainnet);
    try testing.expectEqualSlices(u8, hx(v_version_specific_data), try create.versionSpecificData(a, cfg, &.{ 77, 78 }));
    try testing.expectEqualSlices(u8, hx(v_summary), f.summary_bcs);
    try testing.expectEqualSlices(u8, hx(v_summary_digest), &types.digest.checkpointSummaryDigest(f.summary_bcs));

    // committee order (Committee::new sorts by name) and the end-of-epoch summary
    inline for (0..4) |i| try testing.expectEqualSlices(u8, hx(v_committee_names[i]), &f.committee.members[i].name);
    const next = try a.alloc(create.CommitteeEntry, 4);
    for (f.committee.members, next) |m, *o| o.* = .{ .name = m.name, .stake = m.stake };
    // built by create.create's end-of-epoch encoding: rebuild its pieces as create does
    const committee = try a.alloc(@typeInfo(@FieldType(types.EndOfEpochData, "nextEpochCommittee")).pointer.child, 4);
    for (next, committee) |m, *o| o.* = .{ .{ .@"0" = m.name }, m.stake };
    const ec = try a.alloc(types.CheckpointCommitment, 1);
    ec[0] = .{ .ECMHLiveObjectSetDigest = .{ .digest = .{ .@"0" = d32(5) } } };
    const cc = try a.alloc(types.CheckpointCommitment, 1);
    cc[0] = .{ .CheckpointArtifactsDigest = .{ .@"0" = .{ .@"0" = d32(8) } } };
    const s2: types.CheckpointSummary = .{
        .epoch = 5,
        .sequence_number = 13,
        .network_total_transactions = 1002,
        .content_digest = .{ .@"0" = .{ .@"0" = types.digest.checkpointContentsDigest(f.contents_v1) } },
        .previous_digest = .{ .@"0" = .{ .@"0" = types.digest.checkpointSummaryDigest(f.summary_bcs) } },
        .epoch_rolling_gas_cost_summary = .{ .computationCost = 10, .storageCost = 20, .storageRebate = 30, .nonRefundableStorageFee = 40 },
        .timestamp_ms = 1_700_000_000_456,
        .checkpoint_commitments = cc,
        .end_of_epoch_data = .{ .nextEpochCommittee = committee, .nextEpochProtocolVersion = .{ .@"0" = 141 }, .epochCommitments = ec },
        .version_specific_data = try create.versionSpecificData(a, cfg, &.{}),
    };
    const s2b = try bcs.encodeAlloc(types.CheckpointSummary, a, &s2);
    try testing.expectEqualSlices(u8, hx(v_summary_eoe), s2b);
    try testing.expectEqualSlices(u8, hx(v_summary_eoe_digest), &types.digest.checkpointSummaryDigest(s2b));
}

const Capture = struct {
    gpa: std.mem.Allocator,
    sent: std.ArrayList([]u8) = .empty,
    fn submit(ctx: *anyopaque, txs: []const []const u8, priority: iface.ConsensusSubmit.Priority) iface.ConsensusSubmit.Error!void {
        _ = priority;
        const c: *Capture = @ptrCast(@alignCast(ctx));
        for (txs) |t| c.sent.append(c.gpa, c.gpa.dupe(u8, t) catch return error.Overloaded) catch return error.Overloaded;
    }
    const vtable: iface.ConsensusSubmit.VTable = .{ .submit = submit };
    fn deinit(c: *Capture) void {
        for (c.sent.items) |s| c.gpa.free(s);
        c.sent.deinit(c.gpa);
    }
};

test "rust vectors: signatures and the CheckpointSignatureV2 consensus transaction" {
    const f = try Fixture.init(testing.allocator);
    defer f.deinit(testing.allocator);
    const digest = types.digest.checkpointSummaryDigest(f.summary_bcs);
    inline for (0..4) |i| {
        try testing.expectEqualSlices(u8, hx(v_keys[i]), &f.sks[i].publicKey().toBytes());
        const v = try f.vote(i);
        try testing.expectEqualSlices(u8, hx(v_sigs[i]), &v.sig);
        // what Output submits, byte for byte (tracking id included)
        var ms = store_mod.MemStore.init(testing.allocator);
        defer ms.deinit();
        var cap: Capture = .{ .gpa = testing.allocator };
        defer cap.deinit();
        var ts = output.TestSigner.init(@intCast(i + 1));
        var out: output.Output = .{ .gpa = testing.allocator, .signer = ts.checkpointSigner(), .submit = .{ .ctx = &cap, .vtable = &Capture.vtable }, .store = ms.store() };
        try testing.expectEqual(output.Submitted.sent, try out.checkpointCreated(&f.summary, f.summary_bcs, &digest));
        try testing.expectEqualSlices(u8, hx(v_consensus_txs[i]), cap.sent.items[0]);
        // the tracking id alone
        try testing.expectEqualSlices(u8, hx(v_consensus_txs[i])[0..8], &output.trackingId(&v.sig));
        // the signed envelope (summary ++ AuthoritySignInfo)
        const signed: messages.SignedCheckpointSummary = .{ .data = f.summary, .auth_signature = .{ .epoch = 5, .authority = .{ .@"0" = v.authority }, .signature = v.sig } };
        const sb = try bcs.encodeAlloc(messages.SignedCheckpointSummary, testing.allocator, &signed);
        defer testing.allocator.free(sb);
        try testing.expectEqualSlices(u8, hx(v_signed_summaries[i]), sb);
    }
}

test "rust vectors: block verification of CheckpointSignatureV2 messages" {
    const f = try Fixture.init(testing.allocator);
    defer f.deinit(testing.allocator);
    const a = f.arena.allocator();
    var msgs: [4]*const messages.CheckpointSignatureMessage = undefined;
    inline for (0..4) |i| {
        const tx = try bcs.decode(messages.ConsensusTransaction, a, hx(v_consensus_txs[i]));
        const m = try a.create(messages.CheckpointSignatureMessage);
        m.* = tx.kind.CheckpointSignatureV2;
        msgs[i] = m;
    }
    try testing.expect(try aggregator.verifySignatureMessages(testing.allocator, &f.committee, &msgs));
    // a signature moved to another signer's name, a wrong epoch, a changed summary: rejected
    var bad = msgs[0].*;
    bad.summary.auth_signature.authority = msgs[1].summary.auth_signature.authority;
    try testing.expect(!try aggregator.verifySignatureMessages(testing.allocator, &f.committee, &.{ msgs[2], &bad }));
    bad = msgs[0].*;
    bad.summary.auth_signature.epoch = 6;
    try testing.expect(!try aggregator.verifySignatureMessages(testing.allocator, &f.committee, &.{&bad}));
    bad = msgs[0].*;
    bad.summary.data.timestamp_ms += 1;
    try testing.expect(!try aggregator.verifySignatureMessages(testing.allocator, &f.committee, &.{&bad}));
    bad = msgs[0].*;
    bad.summary.data.epoch = 6;
    try testing.expect(!try aggregator.verifySignatureMessages(testing.allocator, &f.committee, &.{&bad}));
}

test "rust vectors: strong quorum certificate and certified summary" {
    const f = try Fixture.init(testing.allocator);
    defer f.deinit(testing.allocator);
    var agg = try aggregator.SignatureAggregator.init(testing.allocator, &f.committee, 12, 5, f.summary_bcs);
    defer agg.deinit();
    try testing.expect((try agg.tryAggregate(try f.vote(0))).cert == null);
    try testing.expect((try agg.tryAggregate(try f.vote(1))).cert == null);
    const out = try agg.tryAggregate(try f.vote(3));
    const cert = out.cert.?;
    defer testing.allocator.free(cert.bitmap);
    const cb = try aggregator.certifiedBcs(testing.allocator, f.summary_bcs, cert);
    defer testing.allocator.free(cb);
    try testing.expectEqualSlices(u8, hx(v_certified_summary), cb);
    try testing.expectEqualSlices(u8, hx(v_quorum_sign_info), cb[f.summary_bcs.len..]);

    // all four signers: aggregate + bitmap as new_from_auth_sign_infos makes them
    var sigs: [4]bls.Signature = undefined;
    for (&sigs, 0..) |*s, i| s.* = bls.Signature.fromBytes(&(try f.vote(i)).sig).?;
    const all = bls.aggregate(&sigs).?;
    const bm = try aggregator.serializeBitmap(testing.allocator, &.{ 0, 1, 2, 3 });
    defer testing.allocator.free(bm);
    const qb = try aggregator.certifiedBcs(testing.allocator, &.{}, .{ .epoch = 5, .signature = all.toBytes(), .bitmap = bm });
    defer testing.allocator.free(qb);
    try testing.expectEqualSlices(u8, hx(v_quorum_sign_info_all), qb);
}

test "rust vectors: roaring bitmaps" {
    const sets = [_][]const u32{ &.{0}, &.{ 1, 5, 9 }, &range100, &.{ 3, 65536, 70000 } };
    const want = [_][]const u8{ v_bitmap_one, v_bitmap_159, v_bitmap_range100, v_bitmap_two_containers };
    inline for (sets, want) |s, w| {
        const b = try aggregator.serializeBitmap(testing.allocator, s);
        defer testing.allocator.free(b);
        try testing.expectEqualSlices(u8, hx(w), b);
    }
}

const range100 = blk: {
    var r: [100]u32 = undefined;
    for (&r, 0..) |*x, i| x.* = i;
    break :blk r;
};

// ---------------------------------------------------------------- generated (run.sh output)
const v_contents_v1 = "0002200101010101010101010101010101010101010101010101010101010101010101200202020202020202020202020202020202020202020202020202020202020202200303030303030303030303030303030303030303030303030303030303030303200404040404040404040404040404040404040404040404040404040404040404020161000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000261005a5b58595e5f5c5d52535051565754554a4b48494e4f4c4d42434041464744457a7b78797e7f7c7d72737071767774756a6b68696e6f6c6d6263606166676465000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d6100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const v_contents_v1_digest = "0281a88b402fb6f3504d77ff7bf98fea08cc9d085eac0027a03e9ef2b61d182a";
const v_contents_v2 = "0102200101010101010101010101010101010101010101010101010101010101010101200202020202020202020202020202020202020202020202020202020202020202016100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002003030303030303030303030303030303030303030303030303030303030303032004040404040404040404040404040404040404040404040404040404040404040261005a5b58595e5f5c5d52535051565754554a4b48494e4f4c4d42434041464744457a7b78797e7f7c7d72737071767774756a6b68696e6f6c6d6263606166676465000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d012a00000000000000610000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const v_contents_v2_digest = "bc32d1a84e6b93befcb0f7daa4081aed7ab51472db853b33ddd9774d928cb639";
const v_summary = "05000000000000000c00000000000000e80300000000000020bc32d1a84e6b93befcb0f7daa4081aed7ab51472db853b33ddd9774d928cb6390120070707070707070707070707070707070707070707070707070707070707070701000000000000000200000000000000030000000000000004000000000000007b68e5cf8b0100000101200909090909090909090909090909090909090909090909090909090909090909001200024d000000000000004e00000000000000";
const v_summary_digest = "1cb5aeb866c50f864c2544f79a4009fb7e0ec21dee4fee16f28508083a6b2e68";
const v_keys = [_][]const u8{
    "9680e0ba137a7604a0ebdbeb4dc296d72c64ab9fa701a91a1fa8044de2a986f75c5b76e9b5c28bad280cade9c7d93e1a07be7f399a7f185b042759444f97b16e960bd647e8ce6d88d337308b1c1f95064f44cc202f94c5d51ab72eb9c03ebad6",
    "ad4dc162e04573c015f47018765e6c4267b19473a28169316caa3ad7c422dc4db9adb3d29cf38bf3839ada00bc4ef7e4164d903ebb5c23600757d2077051604b632beb31b91fbed366b6095856df6eb8c9232e92be41ec48094ddb600fb7d640",
    "accd1b6de353f0d141edb7f2329e2c50332f1272cca7b2648ab4eab180056e9392de8deb40cf96767780cbf4be0a0b4a0d9a052c3460cbb1e4533e042645e7681ba0fd572ed8745f212169aea41f566b6a1e6a71919ae8e285de8d7883fff898",
    "99e733b2da1927ae0ec07b0502ea15815523233336906960a751cd64be567710469d2263197763d4626232a91267e76f04379bb9d994be83540459308eb51d52adb078244cc9d9074e6d5e02532e08c1db95b4c0fd00e9284a0472349455cb25",
};
const v_committee_names = [_][]const u8{
    "9680e0ba137a7604a0ebdbeb4dc296d72c64ab9fa701a91a1fa8044de2a986f75c5b76e9b5c28bad280cade9c7d93e1a07be7f399a7f185b042759444f97b16e960bd647e8ce6d88d337308b1c1f95064f44cc202f94c5d51ab72eb9c03ebad6",
    "99e733b2da1927ae0ec07b0502ea15815523233336906960a751cd64be567710469d2263197763d4626232a91267e76f04379bb9d994be83540459308eb51d52adb078244cc9d9074e6d5e02532e08c1db95b4c0fd00e9284a0472349455cb25",
    "accd1b6de353f0d141edb7f2329e2c50332f1272cca7b2648ab4eab180056e9392de8deb40cf96767780cbf4be0a0b4a0d9a052c3460cbb1e4533e042645e7681ba0fd572ed8745f212169aea41f566b6a1e6a71919ae8e285de8d7883fff898",
    "ad4dc162e04573c015f47018765e6c4267b19473a28169316caa3ad7c422dc4db9adb3d29cf38bf3839ada00bc4ef7e4164d903ebb5c23600757d2077051604b632beb31b91fbed366b6095856df6eb8c9232e92be41ec48094ddb600fb7d640",
};
const v_summary_eoe = "05000000000000000d00000000000000ea03000000000000200281a88b402fb6f3504d77ff7bf98fea08cc9d085eac0027a03e9ef2b61d182a01201cb5aeb866c50f864c2544f79a4009fb7e0ec21dee4fee16f28508083a6b2e680a0000000000000014000000000000001e000000000000002800000000000000c869e5cf8b01000001012008080808080808080808080808080808080808080808080808080808080808080104609680e0ba137a7604a0ebdbeb4dc296d72c64ab9fa701a91a1fa8044de2a986f75c5b76e9b5c28bad280cade9c7d93e1a07be7f399a7f185b042759444f97b16e960bd647e8ce6d88d337308b1c1f95064f44cc202f94c5d51ab72eb9c03ebad6c4090000000000006099e733b2da1927ae0ec07b0502ea15815523233336906960a751cd64be567710469d2263197763d4626232a91267e76f04379bb9d994be83540459308eb51d52adb078244cc9d9074e6d5e02532e08c1db95b4c0fd00e9284a0472349455cb25c40900000000000060accd1b6de353f0d141edb7f2329e2c50332f1272cca7b2648ab4eab180056e9392de8deb40cf96767780cbf4be0a0b4a0d9a052c3460cbb1e4533e042645e7681ba0fd572ed8745f212169aea41f566b6a1e6a71919ae8e285de8d7883fff898c40900000000000060ad4dc162e04573c015f47018765e6c4267b19473a28169316caa3ad7c422dc4db9adb3d29cf38bf3839ada00bc4ef7e4164d903ebb5c23600757d2077051604b632beb31b91fbed366b6095856df6eb8c9232e92be41ec48094ddb600fb7d640c4090000000000008d000000000000000100200505050505050505050505050505050505050505050505050505050505050505020000";
const v_summary_eoe_digest = "f1ca938fe1bdba5a051738814736848ea15ae058ec54a4f8e2e6f98854c53e20";
const v_sigs = [_][]const u8{
    "9742bd66cc60911e780a655550d43adc768f9b6bb818c22b6ed2c018c3b2a2dbb3c455591d037413babd0d7f3d484603",
    "b4f07d9f02f5504ec4f5f4c9216ff9dcca56bf2597103591339cc7d20426f6dd16ead1c2c7a7ddda535faf8fdbce1eb0",
    "90b02a2685ce9816ff936d9af3806dc91fe5bbd610b79e5a76da11135f298a5735334fefad8bd07949433f81e13996b6",
    "ab21630351aabfa6707155a5f35edc7dfc05bcfdc2a9ac4ea7f5d7379e121cb2dec711d61da5af431d77c6ef4254bf31",
};
const v_signed_summaries = [_][]const u8{
    "05000000000000000c00000000000000e80300000000000020bc32d1a84e6b93befcb0f7daa4081aed7ab51472db853b33ddd9774d928cb6390120070707070707070707070707070707070707070707070707070707070707070701000000000000000200000000000000030000000000000004000000000000007b68e5cf8b0100000101200909090909090909090909090909090909090909090909090909090909090909001200024d000000000000004e000000000000000500000000000000609680e0ba137a7604a0ebdbeb4dc296d72c64ab9fa701a91a1fa8044de2a986f75c5b76e9b5c28bad280cade9c7d93e1a07be7f399a7f185b042759444f97b16e960bd647e8ce6d88d337308b1c1f95064f44cc202f94c5d51ab72eb9c03ebad69742bd66cc60911e780a655550d43adc768f9b6bb818c22b6ed2c018c3b2a2dbb3c455591d037413babd0d7f3d484603",
    "05000000000000000c00000000000000e80300000000000020bc32d1a84e6b93befcb0f7daa4081aed7ab51472db853b33ddd9774d928cb6390120070707070707070707070707070707070707070707070707070707070707070701000000000000000200000000000000030000000000000004000000000000007b68e5cf8b0100000101200909090909090909090909090909090909090909090909090909090909090909001200024d000000000000004e00000000000000050000000000000060ad4dc162e04573c015f47018765e6c4267b19473a28169316caa3ad7c422dc4db9adb3d29cf38bf3839ada00bc4ef7e4164d903ebb5c23600757d2077051604b632beb31b91fbed366b6095856df6eb8c9232e92be41ec48094ddb600fb7d640b4f07d9f02f5504ec4f5f4c9216ff9dcca56bf2597103591339cc7d20426f6dd16ead1c2c7a7ddda535faf8fdbce1eb0",
    "05000000000000000c00000000000000e80300000000000020bc32d1a84e6b93befcb0f7daa4081aed7ab51472db853b33ddd9774d928cb6390120070707070707070707070707070707070707070707070707070707070707070701000000000000000200000000000000030000000000000004000000000000007b68e5cf8b0100000101200909090909090909090909090909090909090909090909090909090909090909001200024d000000000000004e00000000000000050000000000000060accd1b6de353f0d141edb7f2329e2c50332f1272cca7b2648ab4eab180056e9392de8deb40cf96767780cbf4be0a0b4a0d9a052c3460cbb1e4533e042645e7681ba0fd572ed8745f212169aea41f566b6a1e6a71919ae8e285de8d7883fff89890b02a2685ce9816ff936d9af3806dc91fe5bbd610b79e5a76da11135f298a5735334fefad8bd07949433f81e13996b6",
    "05000000000000000c00000000000000e80300000000000020bc32d1a84e6b93befcb0f7daa4081aed7ab51472db853b33ddd9774d928cb6390120070707070707070707070707070707070707070707070707070707070707070701000000000000000200000000000000030000000000000004000000000000007b68e5cf8b0100000101200909090909090909090909090909090909090909090909090909090909090909001200024d000000000000004e0000000000000005000000000000006099e733b2da1927ae0ec07b0502ea15815523233336906960a751cd64be567710469d2263197763d4626232a91267e76f04379bb9d994be83540459308eb51d52adb078244cc9d9074e6d5e02532e08c1db95b4c0fd00e9284a0472349455cb25ab21630351aabfa6707155a5f35edc7dfc05bcfdc2a9ac4ea7f5d7379e121cb2dec711d61da5af431d77c6ef4254bf31",
};
const v_consensus_txs = [_][]const u8{
    "0652140be49eaf3e0b05000000000000000c00000000000000e80300000000000020bc32d1a84e6b93befcb0f7daa4081aed7ab51472db853b33ddd9774d928cb6390120070707070707070707070707070707070707070707070707070707070707070701000000000000000200000000000000030000000000000004000000000000007b68e5cf8b0100000101200909090909090909090909090909090909090909090909090909090909090909001200024d000000000000004e000000000000000500000000000000609680e0ba137a7604a0ebdbeb4dc296d72c64ab9fa701a91a1fa8044de2a986f75c5b76e9b5c28bad280cade9c7d93e1a07be7f399a7f185b042759444f97b16e960bd647e8ce6d88d337308b1c1f95064f44cc202f94c5d51ab72eb9c03ebad69742bd66cc60911e780a655550d43adc768f9b6bb818c22b6ed2c018c3b2a2dbb3c455591d037413babd0d7f3d484603",
    "fc9e85ae3f9773c60b05000000000000000c00000000000000e80300000000000020bc32d1a84e6b93befcb0f7daa4081aed7ab51472db853b33ddd9774d928cb6390120070707070707070707070707070707070707070707070707070707070707070701000000000000000200000000000000030000000000000004000000000000007b68e5cf8b0100000101200909090909090909090909090909090909090909090909090909090909090909001200024d000000000000004e00000000000000050000000000000060ad4dc162e04573c015f47018765e6c4267b19473a28169316caa3ad7c422dc4db9adb3d29cf38bf3839ada00bc4ef7e4164d903ebb5c23600757d2077051604b632beb31b91fbed366b6095856df6eb8c9232e92be41ec48094ddb600fb7d640b4f07d9f02f5504ec4f5f4c9216ff9dcca56bf2597103591339cc7d20426f6dd16ead1c2c7a7ddda535faf8fdbce1eb0",
    "8ef75c6aca3938410b05000000000000000c00000000000000e80300000000000020bc32d1a84e6b93befcb0f7daa4081aed7ab51472db853b33ddd9774d928cb6390120070707070707070707070707070707070707070707070707070707070707070701000000000000000200000000000000030000000000000004000000000000007b68e5cf8b0100000101200909090909090909090909090909090909090909090909090909090909090909001200024d000000000000004e00000000000000050000000000000060accd1b6de353f0d141edb7f2329e2c50332f1272cca7b2648ab4eab180056e9392de8deb40cf96767780cbf4be0a0b4a0d9a052c3460cbb1e4533e042645e7681ba0fd572ed8745f212169aea41f566b6a1e6a71919ae8e285de8d7883fff89890b02a2685ce9816ff936d9af3806dc91fe5bbd610b79e5a76da11135f298a5735334fefad8bd07949433f81e13996b6",
    "6246ba49ed9fc7380b05000000000000000c00000000000000e80300000000000020bc32d1a84e6b93befcb0f7daa4081aed7ab51472db853b33ddd9774d928cb6390120070707070707070707070707070707070707070707070707070707070707070701000000000000000200000000000000030000000000000004000000000000007b68e5cf8b0100000101200909090909090909090909090909090909090909090909090909090909090909001200024d000000000000004e0000000000000005000000000000006099e733b2da1927ae0ec07b0502ea15815523233336906960a751cd64be567710469d2263197763d4626232a91267e76f04379bb9d994be83540459308eb51d52adb078244cc9d9074e6d5e02532e08c1db95b4c0fd00e9284a0472349455cb25ab21630351aabfa6707155a5f35edc7dfc05bcfdc2a9ac4ea7f5d7379e121cb2dec711d61da5af431d77c6ef4254bf31",
};
const v_quorum_sign_info = "050000000000000095ef5bd5a868113b78e8d5ba551e8198dd2f93aa79d6f7ff80fa8a8a057db86206ad6143e7266b6a705147bfb4280d04163a300000010000000000020010000000000001000300";
const v_certified_summary = "05000000000000000c00000000000000e80300000000000020bc32d1a84e6b93befcb0f7daa4081aed7ab51472db853b33ddd9774d928cb6390120070707070707070707070707070707070707070707070707070707070707070701000000000000000200000000000000030000000000000004000000000000007b68e5cf8b0100000101200909090909090909090909090909090909090909090909090909090909090909001200024d000000000000004e00000000000000050000000000000095ef5bd5a868113b78e8d5ba551e8198dd2f93aa79d6f7ff80fa8a8a057db86206ad6143e7266b6a705147bfb4280d04163a300000010000000000020010000000000001000300";
const v_quorum_sign_info_all = "05000000000000008845b6c6f47ccf58f2a0a28714188bdb94712de2cadcfede1132a7f8097e1fd499215db6f0a01d2f2c0da2983b51bd7c183a3000000100000000000300100000000000010002000300";
const v_bitmap_one = "3a3000000100000000000000100000000000";
const v_bitmap_159 = "3a300000010000000000020010000000010005000900";
const v_bitmap_range100 = "3a30000001000000000063001000000000000100020003000400050006000700080009000a000b000c000d000e000f0010001100120013001400150016001700180019001a001b001c001d001e001f0020002100220023002400250026002700280029002a002b002c002d002e002f0030003100320033003400350036003700380039003a003b003c003d003e003f0040004100420043004400450046004700480049004a004b004c004d004e004f0050005100520053005400550056005700580059005a005b005c005d005e005f006000610062006300";
const v_bitmap_two_containers = "3a300000020000000000000001000100180000001a000000030000007011";
const v_version_specific_data = "00024d000000000000004e00000000000000";
