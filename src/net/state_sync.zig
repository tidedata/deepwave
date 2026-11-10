//! sui-network state-sync / discovery message codecs: BCS + snappy framing (mysten-network
//! `BcsSnappyCodec`, anemo variant). Only the request side is encoded here (a read-only peer
//! sends small requests); responses are decoded to their raw BCS and handed to the bcs and
//! checkpoint modules, which own the typed decode.
const std = @import("std");
const Allocator = std.mem.Allocator;
const snappy = @import("snappy.zig");
const anemo = @import("anemo.zig");
const wire = @import("wire.zig");

pub const mainnet_server_name = "sui-35834a8a";
/// mysten-network codec: MAX_DECOMPRESSED_SIZE.
pub const max_decompressed: usize = 128 << 20;

pub const Route = struct {
    pub const push_checkpoint_summary = "/sui.StateSync/PushCheckpointSummary";
    pub const get_checkpoint_summary = "/sui.StateSync/GetCheckpointSummary";
    pub const get_checkpoint_contents = "/sui.StateSync/GetCheckpointContents";
    pub const get_checkpoint_contents_v2 = "/sui.StateSync/GetCheckpointContentsV2";
    pub const get_checkpoint_contents_digests = "/sui.StateSync/GetCheckpointContentsDigests";
    pub const get_checkpoint_transactions = "/sui.StateSync/GetCheckpointTransactions";
    pub const get_checkpoint_availability = "/sui.StateSync/GetCheckpointAvailability";
    pub const get_known_peers_v2 = "/sui.Discovery/GetKnownPeersV2";
    pub const get_known_peers_v3 = "/sui.Discovery/GetKnownPeersV3";
    pub const send_signatures = "/sui.Randomness/SendSignatures";
};

pub const CheckpointId = union(enum) {
    latest,
    digest: [32]u8,
    seq: u64,
};

/// BCS of `GetCheckpointSummaryRequest` (enum Latest | ByDigest(Digest) | BySequenceNumber(u64)).
/// A `Digest` is BCS bytes with a ULEB128 length prefix of 32. Returns the length written.
pub fn bcsSummaryRequest(id: CheckpointId, out: *[34]u8) usize {
    switch (id) {
        .latest => {
            out[0] = 0;
            return 1;
        },
        .digest => |d| {
            out[0] = 1;
            out[1] = 32;
            @memcpy(out[2..34], &d);
            return 34;
        },
        .seq => |n| {
            out[0] = 2;
            std.mem.writeInt(u64, out[1..9], n, .little);
            return 9;
        },
    }
}

/// Snappy-framed BCS of a `GetCheckpointSummaryRequest`.
pub fn encodeSummaryRequest(arena: Allocator, id: CheckpointId) Allocator.Error![]u8 {
    var b: [34]u8 = undefined;
    const n = bcsSummaryRequest(id, &b);
    return snappy.compressFrame(arena, b[0..n]);
}

/// Snappy-framed BCS of a `CheckpointContentsDigest` request (ULEB 32 ++ digest).
pub fn encodeDigestRequest(arena: Allocator, digest: [32]u8) Allocator.Error![]u8 {
    var b: [33]u8 = undefined;
    b[0] = 32;
    @memcpy(b[1..], &digest);
    return snappy.compressFrame(arena, &b);
}

/// Snappy-framed BCS of a bare `u64` request (`GetCheckpointContentsDigests`).
pub fn encodeSeqRequest(arena: Allocator, seq: u64) Allocator.Error![]u8 {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, seq, .little);
    return snappy.compressFrame(arena, &b);
}

pub const TransactionsRequest = struct { sequence_number: u64, start: u64, end: u64 };

pub fn encodeTransactionsRequest(arena: Allocator, r: TransactionsRequest) Allocator.Error![]u8 {
    var b: [24]u8 = undefined;
    std.mem.writeInt(u64, b[0..8], r.sequence_number, .little);
    std.mem.writeInt(u64, b[8..16], r.start, .little);
    std.mem.writeInt(u64, b[16..24], r.end, .little);
    return snappy.compressFrame(arena, &b);
}

/// Request body of the `()` requests (`GetCheckpointAvailability`, `GetKnownPeersV2`): the Rust
/// codec writes nothing, so the snappy stream is empty.
pub fn encodeUnitRequest() []const u8 {
    return &.{};
}

pub const DecodeError = error{ Malformed, TrailingBytes } || snappy.Error;

/// Decompresses a response body to its raw BCS.
pub fn decodeBody(arena: Allocator, body: []const u8) DecodeError![]u8 {
    return snappy.decompressFrame(arena, body, max_decompressed);
}

/// `Option<T>` response: null for None, else the raw BCS of T (a slice of `bcs`).
pub fn optionPayload(bcs: []const u8) DecodeError!?[]const u8 {
    if (bcs.len == 0) return error.Malformed;
    return switch (bcs[0]) {
        0 => if (bcs.len == 1) null else error.TrailingBytes,
        1 => bcs[1..],
        else => error.Malformed,
    };
}

pub const Availability = struct {
    /// Raw BCS of the `CertifiedCheckpointSummary` (the highest synced checkpoint).
    highest_synced_summary: []const u8,
    lowest_available_checkpoint: u64,
};

/// `GetCheckpointAvailabilityResponse { highest_synced_checkpoint, lowest_available_checkpoint }`:
/// the summary is variable length, the trailing u64 is the lowest available sequence number.
pub fn splitAvailability(bcs: []const u8) DecodeError!Availability {
    if (bcs.len < 8) return error.Malformed;
    return .{
        .highest_synced_summary = bcs[0 .. bcs.len - 8],
        .lowest_available_checkpoint = std.mem.readInt(u64, bcs[bcs.len - 8 ..][0..8], .little),
    };
}

test "summary request encodings" {
    var b: [34]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), bcsSummaryRequest(.latest, &b));
    try std.testing.expectEqual(@as(usize, 9), bcsSummaryRequest(.{ .seq = 256 }, &b));
    try std.testing.expectEqualSlices(u8, &.{ 2, 0, 1, 0, 0, 0, 0, 0, 0 }, b[0..9]);
}

// ------------------------------------------------------------------ typed calls over a Peer

pub const CallError = anemo.Error || DecodeError || error{ UnexpectedStatus, NotFound };

const default_timeout_ms: u64 = 10_000;
/// sui-node sends its own timeout as a header; the server drops work that outlives it.
const timeout_header = [_]wire.Header{.{ .name = wire.timeout_header, .value = "10000000000" }};

fn call(p: *anemo.Peer, arena: Allocator, route: []const u8, body: []const u8) CallError![]u8 {
    const r = try p.request(arena, route, &timeout_header, body, default_timeout_ms);
    if (r.status != .success) return error.UnexpectedStatus;
    return decodeBody(arena, r.body);
}

/// `GetCheckpointSummary`: the raw BCS of the `CertifiedCheckpointSummary`, null if the peer does
/// not have it. The checkpoint module verifies and decodes it.
pub fn getCheckpointSummary(p: *anemo.Peer, arena: Allocator, id: CheckpointId) CallError!?[]const u8 {
    const body = try encodeSummaryRequest(arena, id);
    return optionPayload(try call(p, arena, Route.get_checkpoint_summary, body));
}

/// `GetCheckpointContentsV2`: raw BCS of `VersionedFullCheckpointContents`, null if unknown.
pub fn getCheckpointContentsV2(p: *anemo.Peer, arena: Allocator, digest: [32]u8) CallError!?[]const u8 {
    const body = try encodeDigestRequest(arena, digest);
    return optionPayload(try call(p, arena, Route.get_checkpoint_contents_v2, body));
}

/// `GetCheckpointContents` (the V1 route, `use-get-checkpoint-contents-v2: false`): raw BCS of
/// `FullCheckpointContents`, null if unknown.
pub fn getCheckpointContentsV1(p: *anemo.Peer, arena: Allocator, digest: [32]u8) CallError!?[]const u8 {
    const body = try encodeDigestRequest(arena, digest);
    return optionPayload(try call(p, arena, Route.get_checkpoint_contents, body));
}

/// Page requests of the paged contents download wait this long (sui-node:
/// `checkpoint_content_timeout_max`, 30 s; pages are bounded in bytes, not transactions).
pub const page_timeout_ms: u64 = 30_000;
const page_timeout_header = [_]wire.Header{.{ .name = wire.timeout_header, .value = "30000000000" }};

fn callPage(p: *anemo.Peer, arena: Allocator, route: []const u8, body: []const u8) CallError![]u8 {
    const r = try p.request(arena, route, &page_timeout_header, body, page_timeout_ms);
    if (r.status != .success) return error.UnexpectedStatus;
    return decodeBody(arena, r.body);
}

/// `GetCheckpointContentsDigests`: raw BCS of `CheckpointContents` for a sequence number.
pub fn getCheckpointContentsDigests(p: *anemo.Peer, arena: Allocator, seq: u64) CallError!?[]const u8 {
    const body = try encodeSeqRequest(arena, seq);
    return optionPayload(try callPage(p, arena, Route.get_checkpoint_contents_digests, body));
}

/// `GetCheckpointTransactions`: raw BCS of `Vec<ExecutionData>` for `[start, end)` of a checkpoint.
pub fn getCheckpointTransactions(p: *anemo.Peer, arena: Allocator, r: TransactionsRequest) CallError!?[]const u8 {
    const body = try encodeTransactionsRequest(arena, r);
    return optionPayload(try callPage(p, arena, Route.get_checkpoint_transactions, body));
}

/// `PushCheckpointSummary` of a certified summary we synced to a peer whose reported height is
/// below it (sui-node's `notify_peers_of_checkpoint`). The answer is `()`.
pub fn pushCheckpointSummary(p: *anemo.Peer, arena: Allocator, cert: []const u8) CallError!void {
    const body = try snappy.compressFrame(arena, cert);
    _ = try call(p, arena, Route.push_checkpoint_summary, body);
}

/// `GetCheckpointAvailability`: the peer's highest synced checkpoint and lowest available number.
pub fn getCheckpointAvailability(p: *anemo.Peer, arena: Allocator) CallError!Availability {
    return splitAvailability(try call(p, arena, Route.get_checkpoint_availability, encodeUnitRequest()));
}
