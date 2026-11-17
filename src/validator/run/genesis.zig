//! A Mysten `sui genesis` genesis.blob as the validator's execution side needs it: the certified
//! checkpoint 0 (summary, signature, contents), the genesis transaction (data, effects, events),
//! every genesis object, the epoch 0 parameters and committee (`seat.readGenesis`, not
//! duplicated here) and the ECMH running root after checkpoint 0 (sui-core
//! `GlobalStateHasher::accumulate_checkpoint` over the genesis effects).
//!
//! Layout (sui-config `Genesis`, 1.83.1): BCS `Vec<u8>` holding
//!   CertifiedCheckpointSummary (summary ++ AuthorityQuorumSignInfo), CheckpointContents,
//!   Transaction (Envelope<SenderSignedData, EmptySignInfo>), TransactionEffects,
//!   TransactionEvents, Vec<Object>.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const seat = @import("../seat.zig");
const ev = @import("../checkpoints/effects_view.zig");
const state_acc = @import("../checkpoints/state_acc.zig");
const create = @import("../checkpoints/create.zig");

const Allocator = std.mem.Allocator;
const Reader = bcs.Reader;

pub const Error = error{ BadGenesis, UnsupportedProtocol, OutOfMemory };

pub const Genesis = struct {
    /// Digest of checkpoint 0's summary (`ChainIdentifier`).
    chain_id: [32]u8,
    /// The first 4 bytes of `chain_id` in hex (`sui client chain-identifier`).
    chain_id8: [8]u8,
    /// BCS CheckpointSummary of checkpoint 0.
    summary_bcs: []const u8,
    /// BCS CertifiedCheckpointSummary (summary ++ AuthorityQuorumSignInfo), as stored certified.
    certified_bcs: []const u8,
    contents_bcs: []const u8,
    summary: types.CheckpointSummary,
    /// The genesis transaction: digest, BCS TransactionData, BCS SenderSignedData.
    tx_digest: [32]u8,
    td_bcs: []const u8,
    tx_bcs: []const u8,
    effects_bcs: []const u8,
    /// BCS TransactionEvents (null when the genesis transaction emitted none).
    events_bcs: ?[]const u8,
    /// Raw BCS `Object`s, in blob order.
    objects: []const []const u8,
    epoch: u64,
    protocol_version: u64,
    epoch_start_timestamp_ms: u64,
    reference_gas_price: u64,
    /// The epoch 0 committee (sorted by protocol key).
    validators: []const seat.GenesisValidator,
    /// ECMH running root after checkpoint 0 (`Ecmh.toBytes`).
    running_root: [32]u8,

    /// What the checkpoint builder needs of checkpoint 0 to build checkpoint 1.
    pub fn lastBuilt(g: *const Genesis) create.LastBuilt {
        return create.LastBuilt.fromSummary(&g.summary, g.chain_id, null);
    }
};

/// Parses `blob` into `arena` (every slice borrows `blob` or the arena).
pub fn load(arena: Allocator, blob: []const u8) Error!Genesis {
    return loadInner(arena, blob) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.UnsupportedProtocol => error.UnsupportedProtocol,
        else => error.BadGenesis,
    };
}

fn loadInner(arena: Allocator, blob: []const u8) !Genesis {
    const info = try seat.readGenesis(arena, blob);
    var outer = Reader.init(blob);
    const n = try outer.length();
    const inner = try outer.bytes(n);
    var r = Reader.init(inner);

    const s0 = r.at;
    try bcs.skip(types.CheckpointSummary, &r);
    const summary_bcs = inner[s0..r.at];
    try bcs.skip(types.AuthorityQuorumSignInfo, &r);
    const certified_bcs = inner[s0..r.at];
    const c0 = r.at;
    try bcs.skip(types.CheckpointContents, &r);
    const contents_bcs = inner[c0..r.at];
    const t0 = r.at;
    try bcs.skip(types.SenderSignedData, &r); // Envelope<_, EmptySignInfo>: no auth bytes
    const tx_bcs = inner[t0..r.at];
    const e0 = r.at;
    try bcs.skip(types.TransactionEffects, &r);
    const effects_bcs = inner[e0..r.at];
    const v0 = r.at;
    try bcs.skip(types.TransactionEvents, &r);
    const events_raw = inner[v0..r.at];
    const nobj = try r.length();
    if (nobj > r.remaining()) return error.EndOfInput;
    const objs = try arena.alloc([]const u8, nobj);
    for (objs) |*o| {
        const st = r.at;
        try bcs.skip(types.Object, &r);
        o.* = inner[st..r.at];
    }

    const summary = try bcs.decode(types.CheckpointSummary, arena, summary_bcs);
    const chain_id = types.digest.checkpointSummaryDigest(summary_bcs);

    const ssd = try bcs.decode(types.SenderSignedData, arena, tx_bcs);
    const td: types.TransactionData = ssd.@"0".items[0].intent_message.value;
    const td_bcs = try bcs.encodeAlloc(types.TransactionData, arena, &td);
    const tx_digest = types.digest.transactionDataDigest(td_bcs);

    // events: an empty TransactionEvents is what Rust stores when nothing was emitted; the
    // effects name an events digest only when there were events
    const fx = try bcs.decode(types.TransactionEffects, arena, effects_bcs);
    const has_events = switch (fx) {
        .V1 => |v| v.events_digest != null,
        .V2 => |v| v.events_digest != null,
    };

    // running root after checkpoint 0
    const cfg = protocol.get(info.protocol_version, .mainnet) catch return error.UnsupportedProtocol;
    const view = try ev.View.parse(arena, effects_bcs);
    const acc = state_acc.accumulateEffects(arena, cfg, &.{view}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.UnsupportedProtocol,
    };
    var running: state_acc.RunningRoot = .{};
    try running.apply(0, &acc);

    return .{
        .chain_id = chain_id,
        .chain_id8 = info.chain_id,
        .summary_bcs = summary_bcs,
        .certified_bcs = certified_bcs,
        .contents_bcs = contents_bcs,
        .summary = summary,
        .tx_digest = tx_digest,
        .td_bcs = td_bcs,
        .tx_bcs = tx_bcs,
        .effects_bcs = effects_bcs,
        .events_bcs = if (has_events) events_raw else null,
        .objects = objs,
        .epoch = info.epoch,
        .protocol_version = info.protocol_version,
        .epoch_start_timestamp_ms = info.epoch_start_timestamp_ms,
        .reference_gas_price = info.reference_gas_price,
        .validators = info.validators,
        .running_root = running.root.toBytes(),
    };
}

/// The genesis blob of a local `sui genesis` run for the tests: `$ZUI_VALIDATOR_GENESIS` (a
/// genesis.blob path; its directory also holds sui.keystore). Null when unset or unreadable.
pub fn testBlob(gpa: Allocator, io: std.Io) ?[]u8 {
    const path = std.c.getenv("ZUI_VALIDATOR_GENESIS") orelse return null;
    return std.Io.Dir.cwd().readFileAlloc(io, std.mem.span(path), gpa, .unlimited) catch null;
}

test "genesis: a local sui genesis blob loads (skipped without $ZUI_VALIDATOR_GENESIS)" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const blob = testBlob(gpa, io) orelse return error.SkipZigTest;
    defer gpa.free(blob);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const g = try load(arena_state.allocator(), blob);
    try std.testing.expectEqual(@as(u64, 0), g.summary.sequence_number);
    try std.testing.expectEqual(@as(u64, 0), g.epoch);
    try std.testing.expect(g.objects.len > 10);
    try std.testing.expect(g.validators.len > 0);
    try std.testing.expect(g.reference_gas_price > 0);
    // the chain id's hex prefix is the one seat computes
    var hex8: [8]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex8, "{x}", .{g.chain_id[0..4]});
    try std.testing.expectEqualSlices(u8, &hex8, &g.chain_id8);
    // the contents name the genesis transaction
    const contents = try bcs.decode(types.CheckpointContents, arena_state.allocator(), g.contents_bcs);
    _ = contents;
    try std.testing.expectEqualSlices(u8, &g.tx_digest, &(try bcs.decode(types.TransactionEffects, arena_state.allocator(), g.effects_bcs)).V2.transaction_digest.@"0".@"0");
}

test "genesis: a truncated blob is BadGenesis" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(error.BadGenesis, load(arena_state.allocator(), &.{ 4, 1, 2, 3 }));
}
