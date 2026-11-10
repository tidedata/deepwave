//! Zero-copy readers for the three wire values certificate verification needs: the
//! CheckpointSummary fields (including the end-of-epoch committee), the
//! AuthorityStrongQuorumSignInfo and its roaring signer bitmap. Nothing allocates and nothing is
//! copied: every slice and pointer borrows the input bytes.
//!
//! The readers are bounds-checked but they are not full validators: the checkpoint blob is
//! validated once by `types.indexCheckpointData` (every byte, Rust's decode rules), and these
//! readers take the ranges that index produced. A caller with bytes of unknown origin must
//! validate them first (`bcs.View(types.CheckpointSummary).init`).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");

pub const Error = bcs.Error;
const Reader = bcs.Reader;

/// Wire size of one `(AuthorityPublicKeyBytes, u64)` committee entry: a 96-byte string with its
/// length prefix, then the stake.
pub const entry_len = 1 + 96 + 8;

/// The next-epoch committee as it sits in an end-of-epoch summary.
pub const EoeCommittee = struct {
    count: u32,
    /// `count * entry_len` bytes.
    bytes: []const u8,

    pub fn key(e: EoeCommittee, i: usize) *const [96]u8 {
        return e.bytes[i * entry_len + 1 ..][0..96];
    }
    pub fn stake(e: EoeCommittee, i: usize) u64 {
        return std.mem.readInt(u64, e.bytes[i * entry_len + 97 ..][0..8], .little);
    }
};

pub const Summary = struct {
    bytes: []const u8,
    epoch: u64,
    sequence_number: u64,
    network_total_transactions: u64,
    content_digest: *const [32]u8,
    previous_digest: ?*const [32]u8,
    timestamp_ms: u64,
    /// Present exactly in end-of-epoch checkpoints.
    next_committee: ?EoeCommittee,
    next_protocol_version: u64,

    /// Reads the fields of a BCS `CheckpointSummary` (exactly the bytes of one value).
    pub fn parse(bytes: []const u8) Error!Summary {
        var r = Reader.init(bytes);
        var s: Summary = undefined;
        s.bytes = bytes;
        s.epoch = try r.int(u64);
        s.sequence_number = try r.int(u64);
        s.network_total_transactions = try r.int(u64);
        s.content_digest = try digest(&r);
        s.previous_digest = switch (try r.int(u8)) {
            0 => null,
            1 => try digest(&r),
            else => return error.InvalidEnumTag,
        };
        _ = try r.bytes(32); // epoch_rolling_gas_cost_summary: 4 x u64
        s.timestamp_ms = try r.int(u64);
        const ncommit = try r.length();
        var i: usize = 0;
        while (i < ncommit) : (i += 1) {
            try bcs.skip(types.CheckpointCommitment, &r);
        }
        s.next_committee = null;
        s.next_protocol_version = 0;
        switch (try r.int(u8)) {
            0 => {},
            1 => {
                const n = try r.length();
                // entry_len bytes per member: bound the count by the input before multiplying
                if (n > r.remaining() / entry_len) return error.EndOfInput;
                const raw = try r.bytes(n * entry_len);
                var k: usize = 0;
                while (k < n) : (k += 1) if (raw[k * entry_len] != 96) return error.InvalidValue;
                s.next_committee = .{ .count = @intCast(n), .bytes = raw };
                s.next_protocol_version = try r.int(u64);
            },
            else => return error.InvalidEnumTag,
        }
        return s;
    }

    fn digest(r: *Reader) Error!*const [32]u8 {
        if ((try r.int(u8)) != 32) return error.InvalidValue;
        return (try r.bytes(32))[0..32];
    }
};

/// AuthorityStrongQuorumSignInfo: epoch, the 48-byte aggregate signature (a fixed array on the
/// wire) and the signer bitmap bytes.
pub const SigInfo = struct {
    epoch: u64,
    signature: *const [48]u8,
    /// The serialized RoaringBitmap, without its length prefix.
    bitmap: []const u8,

    pub fn parse(bytes: []const u8) Error!SigInfo {
        var r = Reader.init(bytes);
        const epoch = try r.int(u64);
        const sig = (try r.bytes(48))[0..48];
        const n = try r.length();
        const bm = try r.bytes(n);
        try r.finish();
        return .{ .epoch = epoch, .signature = sig, .bitmap = bm };
    }
};

/// Members of a serialized roaring bitmap in ascending order. `bytes` must have passed
/// `types.roaring.validate` (the blob index does that): that bounds the cardinality to
/// `max_signers` and rules out bitmap containers.
pub const max_signers = 150;
pub const Signers = struct {
    n: usize,
    ids: [max_signers]u32,

    pub fn slice(s: *const Signers) []const u32 {
        return s.ids[0..s.n];
    }
};

pub fn signers(bytes: []const u8, out: *Signers) error{InvalidValue}!void {
    const roaring = types.roaring;
    const info = try roaring.validateInfo(bytes);
    _ = info;
    var at: usize = 0;
    const u16at = struct {
        fn f(b: []const u8, o: usize) u32 {
            return std.mem.readInt(u16, b[o..][0..2], .little);
        }
    }.f;
    const cookie = std.mem.readInt(u32, bytes[0..4], .little);
    var size: usize = undefined;
    var has_offsets = true;
    var has_run = false;
    at = 4;
    if (cookie == 12346) {
        size = std.mem.readInt(u32, bytes[4..8], .little);
        at = 8;
    } else {
        size = (cookie >> 16) + 1;
        has_offsets = size >= 4;
        has_run = true;
    }
    const run_bitmap: []const u8 = if (has_run) bytes[at..][0 .. (size + 7) / 8] else &.{};
    at += run_bitmap.len;
    const desc = bytes[at..][0 .. size * 4];
    at += size * 4;
    if (has_offsets) at += size * 4;
    var n: usize = 0;
    for (0..size) |i| {
        const key: u32 = u16at(desc, i * 4);
        const card: u32 = u16at(desc, i * 4 + 2) + 1;
        const is_run = has_run and (run_bitmap[i / 8] & (@as(u8, 1) << @intCast(i % 8))) != 0;
        if (is_run) {
            const runs = u16at(bytes, at);
            at += 2;
            for (0..runs) |_| {
                const s = u16at(bytes, at);
                const len = u16at(bytes, at + 2);
                at += 4;
                var v: u32 = s;
                while (v <= s + len) : (v += 1) {
                    out.ids[n] = (key << 16) | v;
                    n += 1;
                }
            }
        } else {
            // array container (a bitmap container needs more than 4096 members, over the cap)
            for (0..card) |k| {
                out.ids[n] = (key << 16) | u16at(bytes, at + k * 2);
                n += 1;
            }
            at += card * 2;
        }
    }
    out.n = n;
}

test "signers of a small array bitmap" {
    // cookie 12346, one container (key 0, 3 values: 1, 5, 9), offset 16
    const b = [_]u8{ 0x3a, 0x30, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 16, 0, 0, 0, 1, 0, 5, 0, 9, 0 };
    var s: Signers = undefined;
    try signers(&b, &s);
    try std.testing.expectEqualSlices(u32, &.{ 1, 5, 9 }, s.slice());
}
