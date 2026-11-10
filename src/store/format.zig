//! On-disk format of the deepwave store: segment logs, record headers, locations, checksums.
//!
//! A segment is one append-only file per epoch, `seg/<epoch>.log`. It is a sequence of commit
//! groups. Every group starts at a 4096-byte boundary, holds whole records and ends with one
//! commit record; the bytes after the commit record up to the next boundary are zero padding.
//! A group is durable when its commit record and every record before it in the group carry
//! valid checksums. Records are never rewritten; the log is the write-ahead log and the source
//! of truth, every index is derived from it.
//!
//! Record = 40-byte header ++ payload, padded to 8 bytes:
//!
//!   checksum u64   checksum.hash (pinned Wyhash, checksum.zig) seeded with location ^ salt,
//!                  over header[8..] ++ payload; the location
//!                  seed catches misdirected writes, the hash catches torn and rotten bytes
//!   size     u32   payload bytes
//!   kind     u8    Kind
//!   flags    u8    object: 1 = carried forward by pruning, 2 = historical (version index only:
//!                  never enters the live table, so it is never carried by pruning)
//!   _        u16
//!   seq      u64   checkpoint that wrote the value (commit: the group's checkpoint)
//!   a        u64   object/remove: location of the previous version record (0 = none)
//!   b        u64   reserved (0)
//!
//! Compact object record (kind `object_c`, CONTRACTS 6.8): a 16-byte short header (checksum,
//! size, kind, flags, _) ++ the BCS `Object` bytes, padded to 8. No seq (reads as 0: visible to
//! every snapshot), no previous-version link, no id/version/digest copies: the store's codec
//! parses (id, version) out of the BCS and the digest is blake2b("Object::" ++ bytes). Written
//! for the restored live set and for objects carried by segment cleaning, where it saves 96 of
//! the 112 bytes a full object record spends besides the object.
//!
//! Locations are `epoch << 44 | offset`: 20 bits of epoch, 44 bits (16 TiB) of offset. They grow
//! monotonically with log order, which makes every index update idempotent (`max`).
const std = @import("std");
const cs = @import("checksum.zig");

pub const block = 4096;
pub const header_len = 40;
pub const short_len = 16;
pub const offset_bits = 44;
pub const offset_mask: u64 = (1 << offset_bits) - 1;
pub const max_epoch: u64 = (1 << (64 - offset_bits)) - 1;
const salt: u64 = 0x7a75_692d_7374_6f72; // "zui-stor"

pub const Kind = enum(u8) {
    segment = 1,
    checkpoint = 2,
    tx = 3,
    object = 4,
    remove = 5,
    commit = 6,
    /// Compact object record: short header ++ BCS `Object` (see above).
    object_c = 7,
    /// Version-index link: payload `LinkFixed` (id, version), header `a` = location of the
    /// compact record holding that version. Written when a compact record is first superseded,
    /// so its version stays findable by (id, version) for the history window.
    link = 8,
    /// Version-index cross-reference (short header): payload `XrefFixed` (id, version, target).
    /// Written by the checkpoint that reads or supersedes a version whose record lies in an older
    /// segment, instead of a copy of its bytes. The version index points at the xref itself, so
    /// the version stays readable for the xref's (the consuming checkpoint's) retention; readers
    /// follow `target` to the record holding the bytes. Cleaning carries a target that an
    /// in-window xref still names before it deletes the target's segment.
    xref = 9,
    /// A record age-out dropped (store.zig age-out): the short header keeps the dead record's
    /// checksum (so the group's checksum chain still walks), `size` covers its padded length,
    /// `flags` holds its old kind, and the payload is zeros. Reads there are NotFound. Only
    /// written into rewritten chunks of compressed segments (their frames carry the checksums).
    hole = 10,
    _,
};

pub const flag_carried: u8 = 1;
/// An older object version stored for reads by (id, version) only (`Batch.putHistorical`).
pub const flag_historical: u8 = 2;

pub const Header = extern struct {
    checksum: u64,
    size: u32,
    kind: Kind,
    flags: u8,
    _r: u16 = 0,
    seq: u64,
    a: u64 = 0,
    b: u64 = 0,
};

/// The first 16 bytes of every record (all a compact record has).
pub const Short = extern struct {
    checksum: u64,
    size: u32,
    kind: Kind,
    flags: u8,
    _r: u16 = 0,
};

comptime {
    std.debug.assert(@sizeOf(Header) == header_len);
    std.debug.assert(@sizeOf(Short) == short_len);
}

/// Header bytes of a record of this kind.
pub inline fn hdrLen(kind: Kind) usize {
    return if (kind == .object_c or kind == .xref or kind == .hole) short_len else header_len;
}

/// Turns the whole padded record `rec` (`lenAt(rec)` bytes) into a hole of the same length.
pub fn makeHole(rec: []u8) void {
    const h: *align(1) Short = @ptrCast(rec[0..short_len]);
    const old = h.kind;
    const sum = h.checksum;
    const nh: Short = .{ .checksum = sum, .size = @intCast(rec.len - short_len), .kind = .hole, .flags = @intFromEnum(old) };
    h.* = nh;
    @memset(rec[short_len..], 0);
}

/// Padded length of a record of this kind and payload size.
pub inline fn lenOf(kind: Kind, size: usize) usize {
    return std.mem.alignForward(usize, hdrLen(kind) + size, 8);
}

pub fn short(rec: []const u8) *align(1) const Short {
    return @ptrCast(rec[0..short_len]);
}

/// Padded length of the record starting at `rec` (its short header must be in bounds).
pub inline fn lenAt(rec: []const u8) usize {
    const h = short(rec);
    return lenOf(h.kind, h.size);
}

/// Payload of a whole record (header ++ payload).
pub inline fn payload(rec: []const u8) []const u8 {
    return rec[hdrLen(short(rec).kind)..];
}

pub const ObjectFixed = extern struct {
    id: [32]u8,
    version: u64,
    digest: [32]u8,
};

pub const LinkFixed = extern struct {
    id: [32]u8,
    version: u64,
};

pub const XrefFixed = extern struct {
    id: [32]u8,
    version: u64,
    /// Location of the record holding the version's bytes (full or compact object record).
    target: u64,
};

pub const RemoveFixed = extern struct {
    id: [32]u8,
    version: u64,
    kind: u8,
    _r: [7]u8 = @splat(0),
};

pub const TxFixed = extern struct {
    digest: [32]u8,
    effects_digest: [32]u8,
    tx_len: u32,
    effects_len: u32,
    events_len: u32,
    has_events: u32,
};

pub const CheckpointFixed = extern struct {
    epoch: u64,
    summary_len: u32,
    contents_len: u32,
};

pub const CommitFixed = extern struct {
    epoch: u64,
    /// Location of the group's first record.
    group_start: u64,
    records: u32,
    _r: u32 = 0,
    /// Chain over the checksums of the group's records, in order.
    group_hash: u64,
    /// Checksum of the previous commit record (a hash chain across groups and segments).
    prev_commit: u64,
};

pub const SegmentFixed = extern struct {
    magic: [8]u8 = "ZUISEG02".*,
    epoch: u64,
    format: u32 = 2,
    /// Checksum algorithm of every record in the segment (checksum.zig ids).
    algo: u32 = cs.current_algo,
};

pub fn loc(epoch: u64, offset: u64) u64 {
    std.debug.assert(epoch <= max_epoch and offset <= offset_mask);
    return (epoch << offset_bits) | offset;
}

pub fn epochOf(l: u64) u64 {
    return l >> offset_bits;
}

pub fn offsetOf(l: u64) u64 {
    return l & offset_mask;
}

pub fn recordLen(size: usize) usize {
    return std.mem.alignForward(usize, header_len + size, 8);
}

/// Checksum of a record whose header and payload are contiguous in `rec`.
pub fn checksum(l: u64, rec: []const u8) u64 {
    return cs.hash(l ^ salt, rec[8..]);
}

pub fn chain(acc: u64, rec_checksum: u64) u64 {
    return cs.hash64(acc, rec_checksum);
}

pub fn header(rec: []const u8) *align(1) const Header {
    return @ptrCast(rec[0..header_len]);
}

pub fn fixed(comptime T: type, rec: []const u8) *align(1) const T {
    return @ptrCast(rec[header_len..][0..@sizeOf(T)]);
}

/// The fixed part of a short-header record (compact object, xref).
pub fn fixedShort(comptime T: type, rec: []const u8) *align(1) const T {
    return @ptrCast(rec[short_len..][0..@sizeOf(T)]);
}

pub const Error = error{Corrupt};

/// Validates the record at `off` of `data` (a segment view) whose location is `l`. Returns the
/// whole record (header ++ payload, unpadded). `data` is the segment's bytes up to its end.
pub fn validate(data: []const u8, off: usize, l: u64) Error![]const u8 {
    if (off + short_len > data.len) return error.Corrupt;
    const h = short(data[off..]);
    const hl = hdrLen(h.kind);
    if (off + hl > data.len) return error.Corrupt;
    const end = off + hl + @as(usize, h.size);
    if (end > data.len or end < off) return error.Corrupt;
    const rec = data[off..end];
    if (checksum(l, rec) != h.checksum) return error.Corrupt;
    return rec;
}

/// Writes a record at `buf[0..]` (which must have room for recordLen(payload)) and returns its
/// padded length. `parts` are concatenated into the payload.
pub fn write(buf: []u8, l: u64, kind: Kind, flags: u8, seq: u64, a: u64, parts: []const []const u8) usize {
    return writeB(buf, l, kind, flags, seq, a, 0, parts);
}

/// `write` with the header's `b` field set (full headers only). A carried historical object
/// record uses it for the location of the xref whose retention it keeps (store.zig cleaning).
pub fn writeB(buf: []u8, l: u64, kind: Kind, flags: u8, seq: u64, a: u64, b: u64, parts: []const []const u8) usize {
    var size: usize = 0;
    for (parts) |p| size += p.len;
    const hl = hdrLen(kind);
    const total = lenOf(kind, size);
    var pos: usize = hl;
    for (parts) |p| {
        @memcpy(buf[pos..][0..p.len], p);
        pos += p.len;
    }
    @memset(buf[pos..total], 0);
    if (hl == short_len) {
        const hs: *align(1) Short = @ptrCast(buf[0..short_len]);
        hs.* = .{ .checksum = 0, .size = @intCast(size), .kind = kind, .flags = flags };
        hs.checksum = checksum(l, buf[0 .. hl + size]);
        return total;
    }
    const h: *align(1) Header = @ptrCast(buf[0..header_len]);
    h.* = .{ .checksum = 0, .size = @intCast(size), .kind = kind, .flags = flags, .seq = seq, .a = a, .b = b };
    h.checksum = checksum(l, buf[0 .. header_len + size]);
    return total;
}

test "record round trip and misdirection" {
    var buf: [256]u8 align(8) = undefined;
    const l = loc(7, 4096);
    const n = write(&buf, l, .object, 0, 42, 0, &.{ "abc", "defgh" });
    try std.testing.expectEqual(@as(usize, 48), n);
    const rec = try validate(buf[0..n], 0, l);
    try std.testing.expectEqualStrings("abcdefgh", rec[header_len..]);
    try std.testing.expectError(error.Corrupt, validate(buf[0..n], 0, loc(7, 8192)));
    buf[header_len + 1] ^= 1;
    try std.testing.expectError(error.Corrupt, validate(buf[0..n], 0, l));
}

test "compact record round trip" {
    var buf: [256]u8 align(8) = undefined;
    const l = loc(3, 8192);
    const n = write(&buf, l, .object_c, 1, 99, 5, &.{"0123456789"});
    try std.testing.expectEqual(@as(usize, 32), n);
    try std.testing.expectEqual(n, lenAt(&buf));
    const rec = try validate(buf[0..n], 0, l);
    try std.testing.expectEqualStrings("0123456789", payload(rec));
    try std.testing.expectEqual(@as(u8, 1), short(rec).flags);
    buf[short_len] ^= 1;
    try std.testing.expectError(error.Corrupt, validate(buf[0..n], 0, l));
}

test "locations order like the log" {
    try std.testing.expect(loc(1, offset_mask) < loc(2, 0));
    try std.testing.expectEqual(@as(u64, 9), epochOf(loc(9, 123)));
    try std.testing.expectEqual(@as(u64, 123), offsetOf(loc(9, 123)));
}
