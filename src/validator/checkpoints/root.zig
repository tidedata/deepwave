//! val-checkpoints: checkpoint production as a validator at mainnet-v1.83.1
//! (docs/VALIDATOR-DESIGN.md 5.4). Sources: sui-core
//! `checkpoints/mod.rs` (CheckpointBuilder, CheckpointAggregator, CheckpointSignatureAggregator),
//! `causal_order.rs`, `checkpoint_output.rs`, `stake_aggregator.rs`, the checkpoint queue of
//! `consensus_handler.rs`, `global_state_hasher.rs` and the CheckpointSummary/Contents/Artifacts
//! of sui-types `messages_checkpoint.rs`.
//!
//! Flow: the consensus handler pushes each commit's chunks into `queue.Queue`, which emits
//! `iface.PendingCheckpoint`s into `Builder` (`iface.PendingCheckpointSink`). The builder waits
//! for the executed effects (`builder.Env`), builds contents and summary (`create`), stores them
//! (`store`), signs and submits `CheckpointSignatureV2` (`output`). Sequenced signatures arrive
//! at `Aggregator` (`iface.CheckpointSignatureSink`), which certifies on a strong quorum and
//! emits through `iface.CertifiedSink`.
const std = @import("std");
const iface = @import("../iface.zig");

pub const effects_view = @import("effects_view.zig");
pub const causal_order = @import("causal_order.zig");
pub const artifacts = @import("artifacts.zig");
pub const state_acc = @import("state_acc.zig");
pub const create = @import("create.zig");
pub const store = @import("store.zig");
pub const output = @import("output.zig");
pub const aggregator = @import("aggregator.zig");
pub const builder = @import("builder.zig");
pub const queue = @import("queue.zig");

pub const Builder = builder.Builder;
pub const Aggregator = aggregator.Aggregator;
pub const Queue = queue.Queue;
pub const Store = store.Store;
pub const MemStore = store.MemStore;
pub const Env = builder.Env;
pub const Output = output.Output;
pub const Error = builder.Error;

/// One thread's worth of work: build what is queued, then certify what the votes allow. Rust
/// runs the two as separate tasks that wake each other; a single driver thread (or two, one
/// calling each half) is the same.
pub const Service = struct {
    builder: *Builder,
    aggregator: *Aggregator,

    pub const Tick = struct { built: u32, certified: u32 };

    pub fn tick(s: *Service, gpa: std.mem.Allocator) Error!Tick {
        const built = try s.builder.runQueued();
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const certified = try s.aggregator.poll(arena.allocator());
        return .{ .built = built, .certified = certified };
    }
};

test {
    std.testing.refAllDecls(@This());
    _ = effects_view;
    _ = causal_order;
    _ = artifacts;
    _ = state_acc;
    _ = create;
    _ = store;
    _ = output;
    _ = aggregator;
    _ = builder;
    _ = queue;
    _ = @import("rust_vectors.zig");
    _ = @import("replay.zig");
}

// ---------------------------------------------------------------- end to end (local test committee)

const bls = @import("bls");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const checkpoint = @import("checkpoint");
const messages = @import("../messages.zig");
const testing = std.testing;

const Cert = struct {
    gpa: std.mem.Allocator,
    got: std.ArrayList([]u8) = .empty,
    seqs: std.ArrayList(u64) = .empty,
    fn certified(ctx: *anyopaque, seq: u64, summary_bcs: []const u8, contents_bcs: []const u8) error{ Io, Unimplemented }!void {
        _ = contents_bcs;
        const c: *Cert = @ptrCast(@alignCast(ctx));
        c.got.append(c.gpa, c.gpa.dupe(u8, summary_bcs) catch return error.Io) catch return error.Io;
        c.seqs.append(c.gpa, seq) catch return error.Io;
    }
    const vtable: iface.CertifiedSink.VTable = .{ .certified = certified };
    fn sink(c: *Cert) iface.CertifiedSink {
        return .{ .ctx = c, .vtable = &vtable };
    }
    fn deinit(c: *Cert) void {
        for (c.got.items) |g| c.gpa.free(g);
        c.got.deinit(c.gpa);
        c.seqs.deinit(c.gpa);
    }
};

const Sent = struct {
    gpa: std.mem.Allocator,
    sent: std.ArrayList([]u8) = .empty,
    fn submit(ctx: *anyopaque, txs: []const []const u8, p: iface.ConsensusSubmit.Priority) iface.ConsensusSubmit.Error!void {
        _ = p;
        const c: *Sent = @ptrCast(@alignCast(ctx));
        for (txs) |t| c.sent.append(c.gpa, c.gpa.dupe(u8, t) catch return error.Overloaded) catch return error.Overloaded;
    }
    const vtable: iface.ConsensusSubmit.VTable = .{ .submit = submit };
    fn handle(c: *Sent) iface.ConsensusSubmit {
        return .{ .ctx = c, .vtable = &vtable };
    }
    fn deinit(c: *Sent) void {
        for (c.sent.items) |s| c.gpa.free(s);
        c.sent.deinit(c.gpa);
    }
};

test "end to end: four validators build, sign, aggregate and certify a checkpoint" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try protocol.get(100, .mainnet);

    // generated test committee (never a real key)
    var signers: [4]output.TestSigner = undefined;
    var members: [4]checkpoint.Member = undefined;
    for (&signers, &members, 0..) |*s, *m, i| {
        s.* = output.TestSigner.init(@intCast(i + 1));
        m.* = .{ .name = s.sk.publicKey().toBytes(), .stake = 2500 };
    }
    const committee = try checkpoint.Committee.init(a, 1, &members);

    var ms = store.MemStore.init(testing.allocator);
    defer ms.deinit();
    ms.seedCertified(.{ .seq = 0, .epoch = 1, .timestamp_ms = 900, .network_total_transactions = 1, .rolling_gas = .{}, .digest = @splat(3) });
    ms.seedRoot((@import("sig").Ecmh{}).toBytes(), 0);
    var te: builder.TestEnv = .{};
    te.raws[1] = try builder.fx(a, 1);
    te.raws[2] = try builder.fx(a, 2);
    var sent: Sent = .{ .gpa = testing.allocator };
    defer sent.deinit();
    var out: Output = .{ .gpa = testing.allocator, .signer = signers[0].checkpointSigner(), .submit = sent.handle(), .store = ms.store() };
    var b = Builder.init(testing.allocator, cfg, 1, te.env(), ms.store(), &out);
    defer b.deinit();
    var certs: Cert = .{ .gpa = testing.allocator };
    defer certs.deinit();
    var agg = Aggregator.init(testing.allocator, &committee, ms.store(), certs.sink());
    defer agg.deinit();
    var svc: Service = .{ .builder = &b, .aggregator = &agg };

    // the consensus handler pushes the pending checkpoint
    const pending = try builder.pend(a, &.{ 1, 2 }, 1, 1, false);
    try b.pendingSink().push(&pending);
    var t = try svc.tick(testing.allocator);
    try testing.expectEqual(@as(u32, 1), t.built);
    try testing.expectEqual(@as(u32, 0), t.certified);
    try testing.expectEqual(@as(usize, 1), sent.sent.items.len);

    // our own signature comes back sequenced; two peers sign the same summary
    const own = try bcs.decode(messages.ConsensusTransaction, a, sent.sent.items[0]);
    const own_msg = own.kind.CheckpointSignatureV2;
    const from = own_msg.summary.auth_signature.authority;
    agg.signatureSink().add(&from, &own_msg);
    t = try svc.tick(testing.allocator);
    try testing.expectEqual(@as(u32, 0), t.certified);

    const sbytes = (try ms.store().builtSummary(a, 1)).?;
    const summary = try bcs.decode(types.CheckpointSummary, a, sbytes);
    const sign_msg = try create.signingMessage(a, sbytes, 1);
    for (1..3) |i| {
        const m: messages.CheckpointSignatureMessage = .{ .summary = .{
            .data = summary,
            .auth_signature = .{ .epoch = 1, .authority = .{ .@"0" = signers[i].sk.publicKey().toBytes() }, .signature = signers[i].sk.sign(sign_msg).toBytes() },
        } };
        try agg.addSignature(&m.summary.auth_signature.authority, &m);
    }
    t = try svc.tick(testing.allocator);
    try testing.expectEqual(@as(u32, 1), t.certified);
    try testing.expectEqual(@as(u64, 1), certs.seqs.items[0]);
    // the certified checkpoint is what the store now holds, and it verifies under the committee
    try testing.expectEqual(@as(u64, 2), ms.store().nextToCertify());
    const cb = certs.got.items[0];
    // summary bytes ++ epoch(8) ++ sig(48) ++ uleb(len) ++ bitmap
    const bm_len = cb[cb.len - 1 - 5] ; // not used: split below from the known summary length
    _ = bm_len;
    const split = sbytes.len;
    try testing.expect(checkpoint.verifyCertifiedSummary(&committee, .{ .summary = cb[0..split], .sig = cb[split..] }).isOk());
}
