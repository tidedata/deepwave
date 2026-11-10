//! Verification of one checkpoint blob (`0x01 ++ BCS(CheckpointData)`), in two parts that
//! the follower runs on different threads:
//!
//!  * `check`: everything that needs no committee. Contents digest against the summary,
//!    transaction/effects/events digests against the contents, and every output object's
//!    digest against the (certified) effects. The result is an `Applied` plan: the object
//!    writes and removals the store must record, derived from the effects the way
//!    sui-types does (`deleted`, `wrapped`, `unwrapped_then_deleted`).
//!  * `checkCert`: the BLS quorum certificate over the summary against a `Committee`.
//!
//! A checkpoint is only applied when both pass and the chain links (follower.zig).
const std = @import("std");
const bcs = @import("bcs");
const hash = @import("hash");
const types = @import("types");
const bls = @import("bls");
const Committee = @import("committee.zig").Committee;
const wire = @import("wire.zig");
const Reader = bcs.Reader;

pub const What = enum { contents, tx, effects, events, object, object_set, effects_shape, tx_count, sequence };

pub const Verdict = union(enum) {
    ok,
    decode,
    epoch_mismatch,
    bad_bitmap,
    insufficient_stake,
    bad_signature,
    digest_mismatch: What,
    chain_break,
    no_committee,

    pub fn isOk(v: Verdict) bool {
        return v == .ok;
    }
    pub fn name(v: Verdict) []const u8 {
        return switch (v) {
            .digest_mismatch => |w| @tagName(w),
            else => @tagName(v),
        };
    }
};

pub const Put = struct { index: u32, id: *const [32]u8, version: u64, digest: [32]u8 };
pub const Remove = struct { id: [32]u8, version: u64, kind: u8 };
pub const TxPlan = struct {
    tx_digest: *const [32]u8,
    effects_digest: [32]u8,
    puts: []const Put,
    removes: []const Remove,
};

/// What `check` learns about a checkpoint. Everything lives in the arena given to `check`.
pub const Checked = struct {
    seq: u64,
    epoch: u64,
    timestamp_ms: u64,
    network_total_transactions: u64,
    digest: [32]u8,
    previous: ?[32]u8,
    content_digest: [32]u8,
    end_of_epoch: ?types.EndOfEpochData,
    txs: []const TxPlan,
    puts: u32,
    removes: u32,
};

pub const CheckResult = union(enum) { ok: Checked, bad: Verdict };


inline fn bad(v: Verdict) CheckResult {
    return .{ .bad = v };
}

pub fn objectDigest(bytes: []const u8) [32]u8 {
    return hash.blake2b256(&.{ "Object::", bytes });
}

/// Everything except the certificate. `idx` must be the index of `blob`.
pub fn check(arena: std.mem.Allocator, blob: []const u8, idx: *const types.CheckpointIndex) std.mem.Allocator.Error!CheckResult {
    const summary_bytes = idx.summary.slice(blob);
    const summary = bcs.decode(types.CheckpointSummary, arena, summary_bytes) catch return bad(.decode);
    // Mysten deserialises the aggregate signature (blst `Signature::from_bytes`) with the blob, so
    // an undecodable point is `decode` before any digest, epoch or signer check (sync-follow
    // edge/sig-not-a-point-and-epoch). AuthorityQuorumSignInfo = epoch u64 ++ 48 bytes ++ bitmap.
    const sig_bytes = idx.sig.slice(blob);
    if (sig_bytes.len < 56 or bls.Signature.decode(sig_bytes[8..56]) == null) return bad(.decode);
    const contents_bytes = idx.contents.slice(blob);
    const content_digest = hash.blake2b256(&.{ "CheckpointContents::", contents_bytes });
    if (!std.mem.eql(u8, &content_digest, &summary.content_digest.@"0".@"0")) return bad(.{ .digest_mismatch = .contents });
    const pairs = wire.contentsDigests(arena, contents_bytes) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return bad(.decode),
    };
    if (pairs.len != idx.tx_count) return bad(.{ .digest_mismatch = .tx_count });

    const txs = try arena.alloc(TxPlan, pairs.len);
    var n_put: u32 = 0;
    var n_rm: u32 = 0;
    for (pairs, txs, 0..) |pair, *plan, i| {
        const t = idx.txAt(i);
        const tx_digest = hash.blake2b256(&.{ "TransactionData::", t.data.slice(blob) });
        if (!std.mem.eql(u8, &tx_digest, pair.tx)) return bad(.{ .digest_mismatch = .tx });
        const eff_bytes = t.effects.slice(blob);
        const eff_digest = hash.blake2b256(&.{ "TransactionEffects::", eff_bytes });
        if (!std.mem.eql(u8, &eff_digest, pair.effects)) return bad(.{ .digest_mismatch = .effects });
        const eff = bcs.decode(types.TransactionEffects, arena, eff_bytes) catch return bad(.decode);

        const events_digest: ?*const [32]u8 = switch (eff) {
            .V1 => |v| if (v.events_digest) |*d| &d.@"0".@"0" else null,
            .V2 => |v| if (v.events_digest) |*d| &d.@"0".@"0" else null,
        };
        if (t.events) |ev| {
            const d = hash.blake2b256(&.{ "TransactionEvents::", ev.slice(blob) });
            if (events_digest == null or !std.mem.eql(u8, &d, events_digest.?)) return bad(.{ .digest_mismatch = .events });
        } else if (events_digest != null) return bad(.{ .digest_mismatch = .events });

        // Output objects against the effects.
        const outs = idx.objs[t.out_first..][0..t.out_count];
        const puts = try arena.alloc(Put, outs.len);
        for (outs, puts, 0..) |r, *p, k| {
            const ob = r.slice(blob);
            const head = wire.objectHead(ob) catch return bad(.decode);
            p.* = .{ .index = @intCast(t.out_first + k), .id = head.id, .version = head.version, .digest = objectDigest(ob) };
        }
        var removes: std.ArrayList(Remove) = .empty;
        if (!try matchEffects(arena, &eff, puts, &removes)) return bad(.{ .digest_mismatch = .object });
        plan.* = .{ .tx_digest = pair.tx, .effects_digest = eff_digest, .puts = puts, .removes = removes.items };
        n_put += @intCast(puts.len);
        n_rm += @intCast(removes.items.len);
    }
    return .{ .ok = .{
        .seq = summary.sequence_number,
        .epoch = summary.epoch,
        .timestamp_ms = summary.timestamp_ms,
        .network_total_transactions = summary.network_total_transactions,
        .digest = hash.blake2b256(&.{ "CheckpointSummary::", summary_bytes }),
        .previous = if (summary.previous_digest) |p| p.@"0".@"0" else null,
        .content_digest = content_digest,
        .end_of_epoch = summary.end_of_epoch_data,
        .txs = txs,
        .puts = n_put,
        .removes = n_rm,
    } };
}

const Ref = struct { id: *const [32]u8, version: u64, digest: *const [32]u8 };

fn same(a: *const [32]u8, b: *const [32]u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Every object write the effects promise must be present among the output objects with the
/// promised digest, and every output object must be promised. Fills `removes` in sui-types
/// order: deleted, wrapped, unwrapped_then_deleted.
fn matchEffects(arena: std.mem.Allocator, eff: *const types.TransactionEffects, puts: []const Put, removes: *std.ArrayList(Remove)) std.mem.Allocator.Error!bool {
    var expected: usize = 0;
    switch (eff.*) {
        .V1 => |*v| {
            for (v.created) |*e| {
                if (!findPut(puts, &e.@"0"[0].@"0".@"0", e.@"0"[1].@"0", &e.@"0"[2].@"0".@"0")) return false;
                expected += 1;
            }
            for (v.mutated) |*e| {
                if (!findPut(puts, &e.@"0"[0].@"0".@"0", e.@"0"[1].@"0", &e.@"0"[2].@"0".@"0")) return false;
                expected += 1;
            }
            for (v.unwrapped) |*e| {
                if (!findPut(puts, &e.@"0"[0].@"0".@"0", e.@"0"[1].@"0", &e.@"0"[2].@"0".@"0")) return false;
                expected += 1;
            }
            for (v.deleted) |*e| try removes.append(arena, .{ .id = e.@"0".@"0".@"0", .version = e.@"1".@"0", .kind = 0 });
            for (v.wrapped) |*e| try removes.append(arena, .{ .id = e.@"0".@"0".@"0", .version = e.@"1".@"0", .kind = 1 });
            for (v.unwrapped_then_deleted) |*e| try removes.append(arena, .{ .id = e.@"0".@"0".@"0", .version = e.@"1".@"0", .kind = 2 });
        },
        .V2 => |*v| {
            const lamport = v.lamport_version.@"0";
            for (v.changed_objects) |*c| {
                const id = &c.@"0".@"0".@"0";
                switch (c.@"1".output_state) {
                    .ObjectWrite => |w| {
                        if (!findPutAtLamport(puts, id, lamport, &w[0].@"0".@"0")) return false;
                        expected += 1;
                    },
                    .PackageWrite => |w| {
                        if (!findPut(puts, id, w[0].@"0", &w[1].@"0".@"0")) return false;
                        expected += 1;
                    },
                    .AccumulatorWriteV1 => {},
                    .NotExist => {},
                }
            }
            for ([3]u8{ 0, 1, 2 }) |kind| {
                for (v.changed_objects) |*c| {
                    const in_exist = c.@"1".input_state == .Exist;
                    if (c.@"1".output_state != .NotExist) continue;
                    const op = c.@"1".id_operation;
                    const hit = switch (kind) {
                        0 => in_exist and op == .Deleted,
                        1 => in_exist and op == .None,
                        else => !in_exist and op == .Deleted,
                    };
                    if (hit) try removes.append(arena, .{ .id = c.@"0".@"0".@"0", .version = lamport, .kind = kind });
                }
            }
        },
    }
    return expected == puts.len;
}

fn findPut(puts: []const Put, id: *const [32]u8, version: u64, digest: *const [32]u8) bool {
    for (puts) |*p| {
        if (same(p.id, id)) return p.version == version and same(&p.digest, digest);
    }
    return false;
}

fn findPutAtLamport(puts: []const Put, id: *const [32]u8, lamport: u64, digest: *const [32]u8) bool {
    return findPut(puts, id, lamport, digest);
}

/// The BLS certificate of a summary against `committee`. `sig_bytes` is the BCS of the
/// AuthorityQuorumSignInfo, `summary_bytes` the BCS of the summary.
pub fn checkCert(arena: std.mem.Allocator, committee: *const Committee, summary_epoch: u64, summary_bytes: []const u8, sig_bytes: []const u8) Verdict {
    var r = Reader.init(sig_bytes);
    const epoch = r.int(u64) catch return .decode;
    const sig = (r.bytes(48) catch return .decode)[0..48];
    const blen = r.length() catch return .decode;
    const bitmap = r.bytes(blen) catch return .decode;
    if (epoch != committee.epoch or summary_epoch != committee.epoch) return .epoch_mismatch;
    var signers_buf: [160]u32 = undefined;
    const signers = wire.roaringMembers(bitmap, &signers_buf) catch return .bad_bitmap;
    const w = committee.weight(signers) orelse return .bad_bitmap;
    if (w < committee.quorum()) return .insufficient_stake;
    const msg = arena.alloc(u8, 3 + summary_bytes.len + 8) catch return .decode;
    msg[0..3].* = .{ 2, 0, 0 }; // Intent { scope: CheckpointSummary, version: V0, app_id: Sui }
    @memcpy(msg[3..][0..summary_bytes.len], summary_bytes);
    std.mem.writeInt(u64, msg[3 + summary_bytes.len ..][0..8], epoch, .little);
    return switch (committee.prepared.verifyAggregateVerdict(signers, msg, sig)) {
        .ok => .ok,
        // Mysten deserialises (and validates) the aggregate signature with the blob.
        .sig_decode => .decode,
        .unknown_signer => .bad_bitmap,
        .invalid => .bad_signature,
    };
}


/// The truth tool's vocabulary for a verdict (tools/truth/state-sync): decode, contents, tx_count,
/// tx, effects, events, objects, epoch, bitmap, stake, signature, chain, ok.
pub fn class(v: Verdict) []const u8 {
    return switch (v) {
        .ok => "ok",
        .decode => "decode",
        .epoch_mismatch => "epoch",
        .bad_bitmap => "bitmap",
        .insufficient_stake => "stake",
        .bad_signature => "signature",
        .chain_break => "chain",
        .no_committee => "no_committee",
        .digest_mismatch => |w| switch (w) {
            .contents => "contents",
            .tx_count => "tx_count",
            .tx => "tx",
            .effects => "effects",
            .events => "events",
            .object, .object_set, .effects_shape => "objects",
            .sequence => "sequence",
        },
    };
}

/// Index, check, certificate and chain link of one blob, in the order the truth tool uses.
/// `idx` is scratch. No store is touched.
pub fn full(arena: std.mem.Allocator, blob: []const u8, idx: *types.CheckpointIndex, committee: *const Committee, prev_digest: ?[32]u8) std.mem.Allocator.Error!Verdict {
    types.indexCheckpointData(blob, idx) catch return .decode;
    const r = try check(arena, blob, idx);
    const c = switch (r) {
        .ok => |c| c,
        .bad => |v| return v,
    };
    const cv = checkCert(arena, committee, c.epoch, idx.summary.slice(blob), idx.sig.slice(blob));
    if (!cv.isOk()) return cv;
    if (prev_digest) |p| {
        if (c.previous == null or !std.mem.eql(u8, &c.previous.?, &p)) return .chain_break;
    }
    return .ok;
}
