//! sui.rpc.v2 `Checkpoint` rendering (summary, signature, contents) from the BCS bytes the store
//! holds, byte-equal to sui-types `rpc_proto_conversions.rs` lines 41-560 through prost.
//! Every renderer takes the request `Mask` position for its message and writes only the
//! selected fields, in field-number order, into a `proto.Writer`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const proto = @import("proto.zig");
const mask = @import("mask.zig");
const b58 = @import("b58.zig");
const sig_render = @import("render_sig.zig");

const Mask = mask.Mask;
pub const Error = proto.Error || bcs.DecodeError || Allocator.Error || error{ InvalidValue, Unsupported };

pub const CertifiedSummary = types.hand.Envelope(types.CheckpointSummary, types.AuthorityQuorumSignInfo);

/// A certified checkpoint summary parsed once: raw summary BCS plus decoded views.
pub const Cert = struct {
    summary_bcs: []const u8,
    summary: types.CheckpointSummary,
    sig: types.AuthorityQuorumSignInfo,

    /// `bytes` = BCS(CertifiedCheckpointSummary); trailing bytes are an error.
    pub fn parse(arena: Allocator, bytes: []const u8) Error!Cert {
        var r = bcs.Reader.init(bytes);
        const start = r.pos();
        const summary = try bcs.decodeFrom(types.CheckpointSummary, arena, &r);
        const end = r.pos();
        const sig = try bcs.decodeFrom(types.AuthorityQuorumSignInfo, arena, &r);
        try r.finish();
        return .{ .summary_bcs = bytes[start..end], .summary = summary, .sig = sig };
    }

    pub fn digest(c: *const Cert) [32]u8 {
        return types.digest.checkpointSummaryDigest(c.summary_bcs);
    }
};

fn str32(w: *proto.Writer, field: u32, d: *const [32]u8) proto.Error!void {
    var buf: [b58.max_len_32]u8 = undefined;
    try w.string(field, b58.encode32Cached(&buf, d));
}

/// `Bcs { name = 1, value = 2 }` with both fields present.
fn bcsMsg(w: *proto.Writer, field: u32, name: []const u8, value: []const u8) proto.Error!void {
    const m = try w.begin(field, name.len + value.len + 8);
    try w.string(1, name);
    try w.bytes(2, value);
    try w.end(m);
}

/// google.protobuf.Timestamp from milliseconds: plain proto3 scalars (zero omitted).
fn timestampMsg(w: *proto.Writer, field: u32, ms: u64) proto.Error!void {
    const secs: u64 = ms / 1000;
    const nanos: u64 = (ms % 1000) * 1_000_000;
    const m = try w.begin(field, 12);
    if (secs != 0) try w.uint(1, secs);
    if (nanos != 0) try w.uint(2, nanos);
    try w.end(m);
}

pub fn writeGasCostSummary(w: *proto.Writer, field: u32, g: types.GasCostSummary) proto.Error!void {
    const m = try w.begin(field, 24);
    try w.uint(1, g.computationCost);
    try w.uint(2, g.storageCost);
    try w.uint(3, g.storageRebate);
    try w.uint(4, g.nonRefundableStorageFee);
    try w.end(m);
}

fn writeCommitment(w: *proto.Writer, field: u32, c: types.CheckpointCommitment) proto.Error!void {
    const m = try w.begin(field, 40);
    switch (c) {
        .ECMHLiveObjectSetDigest => |d| {
            try w.uint(1, 1);
            try str32(w, 2, &d.digest.@"0");
        },
        .CheckpointArtifactsDigest => |d| {
            try w.uint(1, 2);
            try str32(w, 2, &d.@"0".@"0");
        },
    }
    try w.end(m);
}

fn writeEndOfEpoch(w: *proto.Writer, field: u32, e: types.EndOfEpochData) proto.Error!void {
    const m = try w.begin(field, e.nextEpochCommittee.len * 108 + 64);
    for (e.nextEpochCommittee) |member| {
        const mm = try w.begin(1, 108);
        try w.bytes(1, &member.@"0".@"0");
        try w.uint(2, member.@"1");
        try w.end(mm);
    }
    try w.uint(2, e.nextEpochProtocolVersion.@"0");
    for (e.epochCommitments) |c| try writeCommitment(w, 3, c);
    try w.end(m);
}

/// CheckpointSummary message body fields for `m` (the message `Checkpoint.summary`).
pub fn writeSummary(w: *proto.Writer, m: Mask, c: *const Cert) proto.Error!void {
    const s = &c.summary;
    if (m.contains("bcs")) try bcsMsg(w, 1, "CheckpointSummary", c.summary_bcs);
    if (m.contains("digest")) try str32(w, 2, &c.digest());
    if (m.contains("epoch")) try w.uint(3, s.epoch);
    if (m.contains("sequence_number")) try w.uint(4, s.sequence_number);
    if (m.contains("total_network_transactions")) try w.uint(5, s.network_total_transactions);
    if (m.contains("content_digest")) try str32(w, 6, &s.content_digest.@"0".@"0");
    if (m.contains("previous_digest")) if (s.previous_digest) |d| try str32(w, 7, &d.@"0".@"0");
    if (m.contains("epoch_rolling_gas_cost_summary")) try writeGasCostSummary(w, 8, s.epoch_rolling_gas_cost_summary);
    if (m.contains("timestamp")) try timestampMsg(w, 9, s.timestamp_ms);
    if (m.contains("commitments")) for (s.checkpoint_commitments) |cm| try writeCommitment(w, 10, cm);
    if (m.contains("end_of_epoch_data")) if (s.end_of_epoch_data) |e| try writeEndOfEpoch(w, 11, e);
    if (m.contains("version_specific_data")) try w.bytes(12, s.version_specific_data);
}

/// ValidatorAggregatedSignature (the whole message: `Checkpoint.signature` is all-or-nothing).
pub fn writeSignature(w: *proto.Writer, field: u32, sig: types.AuthorityQuorumSignInfo) proto.Error!void {
    const m = try w.begin(field, 48 + 2 + sig.signers_map.@"0".len + 10);
    try w.uint(1, sig.epoch);
    try w.bytes(2, &sig.signature);
    try w.bytes(3, sig.signers_map.@"0");
    try w.end(m);
}

/// A decoded CheckpointContents plus its raw BCS.
pub const Contents = struct {
    bcs_bytes: []const u8,
    value: types.CheckpointContents,

    pub fn parse(arena: Allocator, bytes: []const u8) Error!Contents {
        return .{ .bcs_bytes = bytes, .value = try bcs.decode(types.CheckpointContents, arena, bytes) };
    }

    pub fn digest(c: *const Contents) [32]u8 {
        return types.digest.checkpointContentsDigest(c.bcs_bytes);
    }
};

/// CheckpointContents message body for mask `m`.
pub fn writeContents(w: *proto.Writer, arena: Allocator, m: Mask, c: *const Contents) Error!void {
    if (m.contains("bcs")) try bcsMsg(w, 1, "CheckpointContents", c.bcs_bytes);
    if (m.contains("digest")) try str32(w, 2, &c.digest());
    if (m.contains("version")) try w.uint(3, switch (c.value) {
        .V1 => 1,
        .V2 => 2,
    });
    if (m.contains("transactions")) {
        switch (c.value) {
            .V1 => |v| for (v.transactions, 0..) |d, i| {
                try writeInfo(w, arena, &d, v.user_signatures[i], null);
            },
            .V2 => |v| for (v.transactions) |t| {
                try writeInfo(w, arena, &t.digest, null, t.user_signatures);
            },
        }
    }
}

const SigVersion = struct { types.hand.GenericSignature, ?types.SequenceNumber };

fn writeInfo(
    w: *proto.Writer,
    arena: Allocator,
    d: *const types.ExecutionDigests,
    v1_sigs: ?[]const types.hand.GenericSignature,
    v2_sigs: ?[]const SigVersion,
) Error!void {
    const mm = try w.begin(4, 200);
    try str32(w, 1, &d.transaction.@"0".@"0");
    try str32(w, 2, &d.effects.@"0".@"0");
    if (v1_sigs) |sigs| {
        for (sigs) |s| try sig_render.writeUserSignature(w, 3, arena, mask_all(), s.@"0");
        for (sigs) |_| {
            const a = try w.begin(4, 0);
            try w.end(a);
        }
    }
    if (v2_sigs) |sigs| {
        for (sigs) |s| try sig_render.writeUserSignature(w, 3, arena, mask_all(), s.@"0".@"0");
        for (sigs) |s| {
            const a = try w.begin(4, 10);
            if (s.@"1") |ver| try w.uint(1, ver.@"0");
            try w.end(a);
        }
    }
    try w.end(mm);
}

var wild_tree: mask.Tree = .{ .wildcard = true };
fn mask_all() Mask {
    return wild_tree.mask();
}

/// `Checkpoint` message body fields 1-5 (sequence_number, digest, summary, signature, contents)
/// for the top-level `Checkpoint` mask `m`. Fields 6 and 7 are the caller's.
pub fn writeCheckpointHead(
    w: *proto.Writer,
    m: Mask,
    cert: *const Cert,
    contents: ?*const Contents,
    arena: Allocator,
) Error!void {
    if (m.contains("sequence_number")) try w.uint(1, cert.summary.sequence_number);
    if (m.contains("digest")) try str32(w, 2, &cert.digest());
    if (m.subtree("summary")) |sm| {
        const mm = try w.begin(3, 256);
        try writeSummary(w, sm, cert);
        try w.end(mm);
    }
    if (m.contains("signature")) try writeSignature(w, 4, cert.sig);
    if (m.subtree("contents")) |cm| if (contents) |c| {
        const mm = try w.begin(5, 256);
        try writeContents(w, arena, cm, c);
        try w.end(mm);
    };
}
