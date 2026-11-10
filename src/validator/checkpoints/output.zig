//! `SubmitCheckpointToConsensus` (sui-core `checkpoints/checkpoint_output.rs`, 1.83.1): sign a
//! built summary with the authority BLS key and submit it to consensus as
//! `ConsensusTransactionKind::CheckpointSignatureV2` (protocol flag
//! `consensus_checkpoint_signature_key_includes_digest`). A checkpoint that is already certified
//! is not signed again.
//!
//! SAFETY: signing goes through `CheckpointSigner`; the production implementation wraps
//! `validator.signer.Signer`, which refuses without a gate license and keeps the (epoch, seq,
//! digest) watermark on disk. Nothing in this file holds a key.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const iface = @import("../iface.zig");
const messages = @import("../messages.zig");
const signer_mod = @import("../signer.zig");
const create = @import("create.zig");
const store_mod = @import("store.zig");

pub const Error = error{ SignRefused, Submit, OutOfMemory };

pub const CheckpointSigner = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Signs `msg` (Intent ++ BCS(summary) ++ epoch). The watermark rule: for one (epoch, seq)
        /// only one digest is ever signed.
        sign: *const fn (ctx: *anyopaque, epoch: u64, seq: u64, digest: *const [32]u8, msg: []const u8) error{Refused}![48]u8,
        authority: *const fn (ctx: *anyopaque) [96]u8,
    };

    pub fn sign(s: CheckpointSigner, epoch: u64, seq: u64, digest: *const [32]u8, msg: []const u8) error{Refused}![48]u8 {
        return s.vtable.sign(s.ctx, epoch, seq, digest, msg);
    }
    pub fn authority(s: CheckpointSigner) [96]u8 {
        return s.vtable.authority(s.ctx);
    }
};

/// Adapter over the validator's `Signer`.
pub const ValidatorSigner = struct {
    signer: *signer_mod.Signer,
    name: [96]u8,

    pub fn init(s: *signer_mod.Signer) signer_mod.Error!ValidatorSigner {
        const keys = try s.publicKeys();
        return .{ .signer = s, .name = keys.authority };
    }

    fn doSign(ctx: *anyopaque, epoch: u64, seq: u64, digest: *const [32]u8, msg: []const u8) error{Refused}![48]u8 {
        const v: *ValidatorSigner = @ptrCast(@alignCast(ctx));
        return v.signer.signCheckpoint(epoch, seq, digest, msg) catch error.Refused;
    }
    fn doAuthority(ctx: *anyopaque) [96]u8 {
        const v: *ValidatorSigner = @ptrCast(@alignCast(ctx));
        return v.name;
    }
    const vtable: CheckpointSigner.VTable = .{ .sign = doSign, .authority = doAuthority };

    pub fn checkpointSigner(v: *ValidatorSigner) CheckpointSigner {
        return .{ .ctx = v, .vtable = &vtable };
    }
};

pub const Submitted = enum { sent, already_certified, epoch_ending };

/// The tracking id `ConsensusTransaction::new_checkpoint_signature_message_v2` puts on the wire:
/// Rust's `DefaultHasher` (SipHash-1-3, zero key) fed `signature.hash()` (a `[u8]` slice hashes
/// its length as a usize, then its 48 bytes), `finish().to_le_bytes()`.
pub fn trackingId(sig: *const [48]u8) [8]u8 {
    const zero_key: [16]u8 = @splat(0);
    var h = std.crypto.auth.siphash.SipHash64(1, 3).init(&zero_key);
    var len: [8]u8 = undefined;
    std.mem.writeInt(u64, &len, sig.len, .little);
    h.update(&len);
    h.update(sig);
    var out: [8]u8 = undefined;
    std.mem.writeInt(u64, &out, h.finalInt(), .little);
    return out;
}

pub const Output = struct {
    gpa: std.mem.Allocator,
    signer: CheckpointSigner,
    submit: iface.ConsensusSubmit,
    store: store_mod.Store,
    tracer: iface.Tracer = .{},
    last_sent_seq: ?u64 = null,

    /// `checkpoint_created`: sign and send our signature of the checkpoint just built.
    pub fn checkpointCreated(o: *Output, summary: *const types.CheckpointSummary, summary_bcs: []const u8, digest: *const [32]u8) Error!Submitted {
        const seq = summary.sequence_number;
        if (o.store.highestCertified()) |h| if (seq <= h) return .already_certified;

        const msg = try create.signingMessage(o.gpa, summary_bcs, summary.epoch);
        defer o.gpa.free(msg);
        const sig = o.signer.sign(summary.epoch, seq, digest, msg) catch return error.SignRefused;

        const tx: messages.ConsensusTransaction = .{
            .tracking_id = trackingId(&sig),
            .kind = .{ .CheckpointSignatureV2 = .{ .summary = .{
                .data = summary.*,
                .auth_signature = .{ .epoch = summary.epoch, .authority = .{ .@"0" = o.signer.authority() }, .signature = sig },
            } } },
        };
        const bytes = bcs.encodeAlloc(messages.ConsensusTransaction, o.gpa, &tx) catch return error.OutOfMemory;
        defer o.gpa.free(bytes);
        o.submit.submit(&.{bytes}, .system) catch |e| switch (e) {
            error.EpochEnding => return .epoch_ending,
            else => return error.Submit,
        };
        o.last_sent_seq = seq;
        return .sent;
    }
};

// ---------------------------------------------------------------- tests

const bls = @import("bls");
const testing = std.testing;

/// A signer for tests only: a generated BLS key and the real watermark rule.
pub const TestSigner = struct {
    sk: bls.SecretKey,
    marks: signer_mod.Watermarks = .{},

    pub fn init(seed_byte: u8) TestSigner {
        var seed: [32]u8 = @splat(0);
        seed[31] = seed_byte;
        seed[0] = 0x21;
        return .{ .sk = bls.SecretKey.fromBytes(&seed).? };
    }
    fn doSign(ctx: *anyopaque, epoch: u64, seq: u64, digest: *const [32]u8, msg: []const u8) error{Refused}![48]u8 {
        const t: *TestSigner = @ptrCast(@alignCast(ctx));
        if (!t.marks.allowCheckpoint(epoch, seq, digest)) return error.Refused;
        t.marks.recordCheckpoint(epoch, seq, digest);
        return t.sk.sign(msg).toBytes();
    }
    fn doAuthority(ctx: *anyopaque) [96]u8 {
        const t: *TestSigner = @ptrCast(@alignCast(ctx));
        return t.sk.publicKey().toBytes();
    }
    const vtable: CheckpointSigner.VTable = .{ .sign = doSign, .authority = doAuthority };
    pub fn checkpointSigner(t: *TestSigner) CheckpointSigner {
        return .{ .ctx = t, .vtable = &vtable };
    }
};

const Capture = struct {
    gpa: std.mem.Allocator,
    sent: std.ArrayList([]u8) = .empty,
    fn submit(ctx: *anyopaque, txs: []const []const u8, priority: iface.ConsensusSubmit.Priority) iface.ConsensusSubmit.Error!void {
        _ = priority;
        const c: *Capture = @ptrCast(@alignCast(ctx));
        for (txs) |t| c.sent.append(c.gpa, c.gpa.dupe(u8, t) catch return error.Overloaded) catch return error.Overloaded;
    }
    const vtable: iface.ConsensusSubmit.VTable = .{ .submit = submit };
    fn handle(c: *Capture) iface.ConsensusSubmit {
        return .{ .ctx = c, .vtable = &vtable };
    }
    fn deinit(c: *Capture) void {
        for (c.sent.items) |s| c.gpa.free(s);
        c.sent.deinit(c.gpa);
    }
};

test "a built checkpoint is signed once and submitted as CheckpointSignatureV2" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = store_mod.MemStore.init(testing.allocator);
    defer ms.deinit();
    var cap: Capture = .{ .gpa = testing.allocator };
    defer cap.deinit();
    var ts = TestSigner.init(1);
    var out: Output = .{ .gpa = testing.allocator, .signer = ts.checkpointSigner(), .submit = cap.handle(), .store = ms.store() };

    const summary: types.CheckpointSummary = .{
        .epoch = 5,
        .sequence_number = 12,
        .network_total_transactions = 1,
        .content_digest = .{ .@"0" = .{ .@"0" = @splat(1) } },
        .previous_digest = null,
        .epoch_rolling_gas_cost_summary = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .timestamp_ms = 3,
        .checkpoint_commitments = &.{},
        .end_of_epoch_data = null,
        .version_specific_data = &.{},
    };
    const sb = try bcs.encodeAlloc(types.CheckpointSummary, a, &summary);
    const d = types.digest.checkpointSummaryDigest(sb);
    try testing.expectEqual(Submitted.sent, try out.checkpointCreated(&summary, sb, &d));
    try testing.expectEqual(@as(usize, 1), cap.sent.items.len);
    // the wire bytes decode back to a CheckpointSignatureV2 whose signature verifies
    const tx = try bcs.decode(messages.ConsensusTransaction, a, cap.sent.items[0]);
    const m = tx.kind.CheckpointSignatureV2;
    try testing.expectEqual(@as(u64, 12), m.summary.data.sequence_number);
    const msg = try create.signingMessage(a, sb, 5);
    const pk = bls.PublicKey.fromBytes(&m.summary.auth_signature.authority.@"0").?;
    const sg = bls.Signature.fromBytes(&m.summary.auth_signature.signature).?;
    try testing.expect(bls.verify(&pk, msg, &sg));
    // a different digest for the same sequence number is refused by the watermark
    const other: [32]u8 = @splat(9);
    try testing.expectError(error.SignRefused, out.checkpointCreated(&summary, sb, &other));
    // an already certified checkpoint is not signed
    try ms.store().putCertified(12, d, "x");
    try testing.expectEqual(Submitted.already_certified, try out.checkpointCreated(&summary, sb, &d));
}
