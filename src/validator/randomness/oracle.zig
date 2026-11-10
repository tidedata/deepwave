//! fastcrypto-tbls `random_oracle::RandomOracle`: SHA3-512 over
//! `u32 BE(len(prefix)) || prefix || BCS(object)`, with `extend` adding "-<name>" to the prefix.
//! Prefixes here are short ("dkg <chain id hex> <epoch>-encs <id>-zk"), so a fixed buffer holds
//! them and nothing allocates.
const std = @import("std");
const group = @import("group.zig");

pub const max_prefix = 256;

pub const RandomOracle = struct {
    buf: [max_prefix]u8 = undefined,
    len: u16 = 0,

    pub const Error = error{PrefixTooLong};

    pub fn init(p: []const u8) Error!RandomOracle {
        if (p.len > max_prefix) return error.PrefixTooLong;
        var ro: RandomOracle = .{};
        @memcpy(ro.buf[0..p.len], p);
        ro.len = @intCast(p.len);
        return ro;
    }

    pub fn prefix(ro: *const RandomOracle) []const u8 {
        return ro.buf[0..ro.len];
    }

    pub fn extend(ro: *const RandomOracle, ext: []const u8) Error!RandomOracle {
        if (@as(usize, ro.len) + 1 + ext.len > max_prefix) return error.PrefixTooLong;
        var out = ro.*;
        out.buf[out.len] = '-';
        @memcpy(out.buf[out.len + 1 ..][0..ext.len], ext);
        out.len += @intCast(1 + ext.len);
        return out;
    }

    /// `extend(format!(...))` helpers for the DKG sub-oracles.
    pub fn extendFmt(ro: *const RandomOracle, comptime fmt: []const u8, args: anytype) Error!RandomOracle {
        var tmp: [max_prefix]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, fmt, args) catch return error.PrefixTooLong;
        return ro.extend(s);
    }

    /// `evaluate(&obj)` where `obj_bcs` is the already serialized BCS of the object.
    pub fn evaluate(ro: *const RandomOracle, obj_bcs: []const u8) [64]u8 {
        var h = std.crypto.hash.sha3.Sha3_512.init(.{});
        var l: [4]u8 = undefined;
        std.mem.writeInt(u32, &l, ro.len, .big);
        h.update(&l);
        h.update(ro.prefix());
        h.update(obj_bcs);
        var out: [64]u8 = undefined;
        h.final(&out);
        return out;
    }

    /// `evaluate_to_group_element::<Scalar>`: the digest reduced mod r.
    pub fn evaluateToScalar(ro: *const RandomOracle, obj_bcs: []const u8) group.Scalar {
        const d = ro.evaluate(obj_bcs);
        return group.scalarReduceWide(&d);
    }
};

test "extend and evaluate are deterministic" {
    const a = try RandomOracle.init("dkg 0102 5");
    const b = try a.extend("encs");
    try std.testing.expectEqualStrings("dkg 0102 5-encs", b.prefix());
    const c = try a.extendFmt("encs {}", .{7});
    try std.testing.expectEqualStrings("dkg 0102 5-encs 7", c.prefix());
    try std.testing.expectEqualSlices(u8, &b.evaluate("x"), &b.evaluate("x"));
    try std.testing.expect(!std.mem.eql(u8, &b.evaluate("x"), &b.evaluate("y")));
}
