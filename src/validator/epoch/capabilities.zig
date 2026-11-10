//! This validator's CapabilityNotificationV2 (protocol-upgrade vote) at mainnet-v1.83.1:
//! `AuthorityCapabilitiesV2::new` (messages_consensus.rs) with `SupportedProtocolVersionsWithHashes`
//! (supported_protocol_versions.rs): for every version in the supported range the Blake2b256 digest
//! of BCS(ProtocolConfig::get_for_version(v, chain)), plus the available system packages.
//!
//! The digest of the Rust struct's serde layout is not reproduced by deepwave's config types, so Rust's
//! values for versions 1..=141 on the unknown, mainnet and testnet chains are compiled in
//! (`protocol-digests.txt`, written by tools/truth/validator-keys from sui-types 1.83.1): every
//! notification carries Mysten's digests unless a `DigestTable` (`--protocol-digests`) overrides
//! them. Only a version outside that table falls back to a digest of the insta snapshot text,
//! which no Mysten validator would match.
const std = @import("std");
const hash = @import("hash");
const protocol = @import("protocol");
const types = @import("types");
const messages = @import("../messages.zig");

pub const Error = error{ OutOfMemory, BadTable, UnsupportedVersion };

/// `ProtocolVersion::MIN` / `MAX` of sui-protocol-config at mainnet-v1.83.1.
pub const supported_min: u64 = 1;
pub const supported_max: u64 = 141;

pub const Flavour = enum { snapshot_text, rust_truth };

pub const DigestTable = struct {
    arena: std.heap.ArenaAllocator,
    /// index (chain, version) -> digest
    map: std.AutoHashMapUnmanaged(u64, [32]u8) = .empty,

    pub fn deinit(t: *DigestTable) void {
        t.arena.deinit();
    }

    fn key(chain: protocol.Chain, version: u64) u64 {
        return (@as(u64, @intFromEnum(chain)) << 32) | version;
    }

    /// `protocol-digests.txt`: one `<unknown|mainnet|testnet> <version> <64 hex>` per line, `#` comments.
    pub fn parse(gpa: std.mem.Allocator, text: []const u8) Error!DigestTable {
        var t: DigestTable = .{ .arena = std.heap.ArenaAllocator.init(gpa) };
        errdefer t.deinit();
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            var it = std.mem.tokenizeAny(u8, line, " \t");
            const c = it.next() orelse return error.BadTable;
            const v = it.next() orelse return error.BadTable;
            const h = it.next() orelse return error.BadTable;
            const chain = std.meta.stringToEnum(protocol.Chain, c) orelse return error.BadTable;
            const version = std.fmt.parseInt(u64, v, 10) catch return error.BadTable;
            if (h.len != 64) return error.BadTable;
            var d: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&d, h) catch return error.BadTable;
            try t.map.put(t.arena.allocator(), key(chain, version), d);
        }
        return t;
    }

    pub fn get(t: *const DigestTable, chain: protocol.Chain, version: u64) ?[32]u8 {
        return t.map.get(key(chain, version));
    }
};

/// Rust's digests, `<chain> <version> <hex>` per line.
pub const rust_digests = @embedFile("protocol-digests.txt");

/// The compiled-in Rust digest of `version` on `chain`.
pub fn rustDigest(chain: protocol.Chain, version: u64) ?[32]u8 {
    var lines = std.mem.splitScalar(u8, rust_digests, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const c = std.meta.stringToEnum(protocol.Chain, it.next() orelse continue) orelse continue;
        if (c != chain) continue;
        const v = std.fmt.parseInt(u64, it.next() orelse continue, 10) catch continue;
        if (v != version) continue;
        const h = it.next() orelse return null;
        var d: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&d, h) catch return null;
        return d;
    }
    return null;
}

/// Digest of the config of `version` on `chain`: the table's entry, else Rust's compiled-in
/// value, else (a version Rust's table does not have) the snapshot text digest.
pub fn protocolConfigDigest(gpa: std.mem.Allocator, table: ?*const DigestTable, chain: protocol.Chain, version: u64) Error![32]u8 {
    if (table) |t| if (t.get(chain, version)) |d| return d;
    if (rustDigest(chain, version)) |d| return d;
    const cfg = protocol.get(version, chain) catch return error.UnsupportedVersion;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    protocol.renderSnapshot(cfg, &out.writer) catch return error.OutOfMemory;
    var d: [32]u8 = undefined;
    hash.Blake2b256.hash(out.written(), &d);
    return d;
}

pub fn supportedVersionsWithHashes(arena: std.mem.Allocator, table: ?*const DigestTable, chain: protocol.Chain, min: u64, max: u64) Error!messages.SupportedProtocolVersionsWithHashes {
    if (max < min) return error.UnsupportedVersion;
    const n: usize = @intCast(max - min + 1);
    const list = try arena.alloc(struct { types.ProtocolVersion, types.Digest }, n);
    var i: usize = 0;
    var v = min;
    while (v <= max) : ({
        v += 1;
        i += 1;
    }) {
        const d = try protocolConfigDigest(arena, table, chain, v);
        list[i] = .{ .{ .@"0" = v }, .{ .@"0" = d } };
    }
    return .{ .versions = list };
}

/// The consensus transaction body this validator submits at epoch start (and when its supported
/// versions or packages change). `generation` must grow with every new notification
/// (sui-node uses the wall clock in ms).
pub fn buildCapabilities(
    arena: std.mem.Allocator,
    table: ?*const DigestTable,
    chain: protocol.Chain,
    authority: [96]u8,
    generation: u64,
    min: u64,
    max: u64,
    available_system_packages: []const messages.ObjectRef,
) Error!messages.AuthorityCapabilitiesV2 {
    return .{
        .authority = .{ .@"0" = authority },
        .generation = generation,
        .supported_protocol_versions = try supportedVersionsWithHashes(arena, table, chain, min, max),
        .available_system_packages = available_system_packages,
    };
}

test "compiled-in digests are Rust's (sui-types SupportedProtocolVersionsWithHashes, 1.83.1)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const want = struct {
        fn h(comptime x: []const u8) [32]u8 {
            var d: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&d, x) catch unreachable;
            return d;
        }
    }.h;
    try std.testing.expectEqualSlices(u8, &want("049f4a9344fc103e12a9771d65846814563649361e17d0a08dd98e7cfffc9876"), &try protocolConfigDigest(arena.allocator(), null, .mainnet, 141));
    try std.testing.expectEqualSlices(u8, &want("84c3c8a4216d07905fd44397f156cd7066ad2d1e4a88d4e0f6bbc7ac557483b4"), &try protocolConfigDigest(arena.allocator(), null, .unknown, 141));
    try std.testing.expectEqualSlices(u8, &want("ab890993ac6a6059efc5a7adb14645cd323e154e36dfa38bee7a803d1434b737"), &try protocolConfigDigest(arena.allocator(), null, .testnet, 141));
    // every supported version on every chain has its Rust digest
    for ([_]protocol.Chain{ .unknown, .mainnet, .testnet }) |c| {
        var v: u64 = supported_min;
        while (v <= supported_max) : (v += 1) try std.testing.expect(rustDigest(c, v) != null);
    }
}

test "digests are stable and differ across versions" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = try protocolConfigDigest(arena.allocator(), null, .mainnet, 140);
    const b = try protocolConfigDigest(arena.allocator(), null, .mainnet, 140);
    const c = try protocolConfigDigest(arena.allocator(), null, .mainnet, 141);
    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
}

test "a truth table entry wins over the snapshot digest" {
    const line = "mainnet 141 abababababababababababababababababababababababababababababababab\n# comment\n";
    var t = try DigestTable.parse(std.testing.allocator, line);
    defer t.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const d = try protocolConfigDigest(arena.allocator(), &t, .mainnet, 141);
    try std.testing.expectEqual(@as(u8, 0xab), d[0]);
    try std.testing.expectError(error.BadTable, DigestTable.parse(std.testing.allocator, "mainnet x y\n"));
}

test "capabilities cover the whole supported range" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const caps = try buildCapabilities(arena.allocator(), null, .unknown, @splat(1), 7, 139, 141, &.{});
    try std.testing.expectEqual(@as(usize, 3), caps.supported_protocol_versions.versions.len);
    try std.testing.expectEqual(@as(u64, 141), caps.supported_protocol_versions.versions[2][0].@"0");
}
