//! Small zero-allocation readers for the few byte shapes the follower needs without a full
//! decode: signer sets of a certificate, the id and version of an object, the digest pairs of
//! checkpoint contents.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const Reader = bcs.Reader;

pub const Error = bcs.Error;

/// Members of a serialized RoaringBitmap that `types.roaring.validate` accepted, ascending, into
/// `out`. Returns the count. Same container rules as the roaring crate (array, bitmap, run).
pub fn roaringMembers(bytes: []const u8, out: []u32) error{ InvalidValue, TooMany }![]u32 {
    _ = types.roaring.validate(bytes) catch return error.InvalidValue;
    const rd = std.mem.readInt;
    const cookie = rd(u32, bytes[0..4], .little);
    var at: usize = 4;
    var size: usize = undefined;
    var has_run = false;
    var has_offsets = true;
    if (cookie == 12346) {
        size = rd(u32, bytes[4..8], .little);
        at = 8;
    } else {
        size = (cookie >> 16) + 1;
        has_run = true;
        has_offsets = size >= 4;
    }
    const run_bits = if (has_run) bytes[at..][0 .. (size + 7) / 8] else bytes[0..0];
    at += run_bits.len;
    const desc = bytes[at..][0 .. size * 4];
    at += size * 4;
    if (has_offsets) at += size * 4;
    var n: usize = 0;
    for (0..size) |i| {
        const key: u32 = rd(u16, desc[i * 4 ..][0..2], .little);
        const card: u32 = @as(u32, rd(u16, desc[i * 4 + 2 ..][0..2], .little)) + 1;
        const is_run = has_run and (run_bits[i / 8] & (@as(u8, 1) << @intCast(i % 8))) != 0;
        if (is_run) {
            const runs = rd(u16, bytes[at..][0..2], .little);
            at += 2;
            for (0..runs) |_| {
                const s: u32 = rd(u16, bytes[at..][0..2], .little);
                const len: u32 = rd(u16, bytes[at + 2 ..][0..2], .little);
                at += 4;
                var v = s;
                while (v <= s + len) : (v += 1) {
                    if (n == out.len) return error.TooMany;
                    out[n] = (key << 16) | v;
                    n += 1;
                }
            }
        } else if (card <= 4096) {
            for (0..card) |_| {
                if (n == out.len) return error.TooMany;
                out[n] = (key << 16) | rd(u16, bytes[at..][0..2], .little);
                at += 2;
                n += 1;
            }
        } else {
            const words = bytes[at..][0..8192];
            at += 8192;
            for (0..1024) |w| {
                var bits = rd(u64, words[w * 8 ..][0..8], .little);
                while (bits != 0) {
                    const b = @ctz(bits);
                    bits &= bits - 1;
                    if (n == out.len) return error.TooMany;
                    out[n] = (key << 16) | @as(u32, @intCast(w * 64 + b));
                    n += 1;
                }
            }
        }
    }
    return out[0..n];
}

/// Identity of an object blob (BCS of `Object`): the object id, its version and whether it is a package.
pub const ObjectHead = struct { id: *const [32]u8, version: u64, is_package: bool };

pub fn objectHead(bytes: []const u8) Error!ObjectHead {
    var r = Reader.init(bytes);
    const tag = try r.uleb32();
    switch (tag) {
        0 => {
            try bcs.skip(types.gen.MoveObjectType, &r);
            _ = try r.boolean();
            const version = try r.int(u64);
            const clen = try r.length();
            if (clen < 32) return error.InvalidValue;
            const c = try r.bytes(clen);
            return .{ .id = c[0..32], .version = version, .is_package = false };
        },
        1 => {
            const id = try r.bytes(32);
            const version = try r.int(u64);
            return .{ .id = id[0..32], .version = version, .is_package = true };
        },
        else => return error.InvalidEnumTag,
    }
}

/// The (transaction digest, effects digest) pairs of a CheckpointContents blob, without the
/// user signatures. `out` receives views into `contents`.
pub const DigestPair = struct { tx: *const [32]u8, effects: *const [32]u8 };

pub fn contentsDigests(arena: std.mem.Allocator, contents: []const u8) (Error || std.mem.Allocator.Error)![]DigestPair {
    var r = Reader.init(contents);
    const tag = try r.uleb32();
    if (tag > 1) return error.InvalidEnumTag;
    const n = try r.length();
    const out = try arena.alloc(DigestPair, n);
    for (out) |*p| {
        // ExecutionDigests = two Digests: ULEB length 32 then 32 bytes each.
        if (try r.uleb32() != 32) return error.InvalidValue;
        p.tx = (try r.bytes(32))[0..32];
        if (try r.uleb32() != 32) return error.InvalidValue;
        p.effects = (try r.bytes(32))[0..32];
        if (tag == 1) try bcs.skip(@FieldType(types.gen.CheckpointTransactionContents, "user_signatures"), &r);
    }
    return out;
}
