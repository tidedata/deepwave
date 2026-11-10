//! The local test committee generator (docs/VALIDATOR-DESIGN.md 5.6, 8): N validators on loopback
//! ports whose keys all derive from one seed. Nothing here writes a key file: a localnet validator
//! asks for `KeySpec.generated` (seed and index), which is the only key source the safety gate
//! allows for a local committee.
//!
//! Layout written to `dir`:
//!   localnet.json          chain id, seed, committee (public keys, stake, addresses), epoch settings
//!   validator-<i>.yaml     a validator.yaml per member (db paths under dir/db-<i>, loopback addresses)
//! Ports of member i: base + 10*i: +0 validator gRPC, +1 consensus, +2 p2p, +3 metrics.
//! Genesis objects (the system state and framework packages) come from the existing genesis tooling
//! and are not produced here; the committee file carries what every lane needs from it.
const std = @import("std");
const hash = @import("hash");
const material = @import("material.zig");
const fsutil = @import("fsutil.zig");

pub const Error = error{ Io, BadConfig, OutOfMemory };

pub const Options = struct {
    base_port: u16 = 18000,
    /// Equal stake per validator; total voting power is 10000 as on Sui (`TOTAL_VOTING_POWER`).
    epoch_duration_ms: u64 = 600_000,
    protocol_version: u64 = 141,
};

pub const total_voting_power: u64 = 10_000;

pub const Member = struct {
    index: u32,
    stake: u64,
    authority_pk: [96]u8,
    worker_pk: [32]u8,
    network_pk: [32]u8,
    account_pk: [32]u8,
    network_address: []const u8,
    consensus_address: []const u8,
    p2p_address: []const u8,
    metrics_address: []const u8,
};

pub const Description = struct {
    chain_id: [8]u8,
    seed: [32]u8,
    epoch_duration_ms: u64,
    protocol_version: u64,
    members: []const Member,
};

pub const Loaded = struct {
    arena: std.heap.ArenaAllocator,
    desc: Description,
    pub fn deinit(l: *Loaded) void {
        l.arena.deinit();
    }
};

/// Stake split as `Committee` voting power: `total / n` each, the remainder going to the first
/// validators one point at a time (so the sum is exactly 10000).
pub fn stakeOf(n: u32, index: u32) u64 {
    const base = total_voting_power / n;
    const rem = total_voting_power % n;
    return base + @intFromBool(index < rem);
}

pub fn chainIdOf(seed: *const [32]u8, n: u32) [8]u8 {
    var h = hash.Blake2b256.init();
    h.update("zui-localnet-genesis-v1");
    h.update(seed);
    h.update(std.mem.asBytes(&n));
    var d: [32]u8 = undefined;
    h.final(&d);
    return std.fmt.bytesToHex(d[0..4].*, .lower);
}

/// Builds the description for `n` members (strings allocated from `arena`).
pub fn describe(arena: std.mem.Allocator, n: u32, seed: [32]u8, opts: Options) Error!Description {
    if (n == 0 or n > 1000) return error.BadConfig;
    const members = try arena.alloc(Member, n);
    for (members, 0..) |*m, i| {
        const idx: u32 = @intCast(i);
        const ks = material.generate(&seed, idx);
        const port: u32 = @as(u32, opts.base_port) + 10 * idx;
        if (port + 3 > 65535) return error.BadConfig;
        m.* = .{
            .index = idx,
            .stake = stakeOf(n, idx),
            .authority_pk = ks.authority_pk,
            .worker_pk = ks.worker.public_key.toBytes(),
            .network_pk = ks.network.public_key.toBytes(),
            .account_pk = ks.account.?.public_key.toBytes(),
            .network_address = try std.fmt.allocPrint(arena, "/ip4/127.0.0.1/tcp/{d}", .{port}),
            .consensus_address = try std.fmt.allocPrint(arena, "/ip4/127.0.0.1/udp/{d}", .{port + 1}),
            .p2p_address = try std.fmt.allocPrint(arena, "127.0.0.1:{d}", .{port + 2}),
            .metrics_address = try std.fmt.allocPrint(arena, "127.0.0.1:{d}", .{port + 3}),
        };
    }
    return .{ .chain_id = chainIdOf(&seed, n), .seed = seed, .epoch_duration_ms = opts.epoch_duration_ms, .protocol_version = opts.protocol_version, .members = members };
}

fn hex(comptime N: usize, b: *const [N]u8) [2 * N]u8 {
    return std.fmt.bytesToHex(b.*, .lower);
}

pub fn renderJson(gpa: std.mem.Allocator, d: *const Description) Error![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    const seed_hex = hex(32, &d.seed);
    w.print("{{\n  \"chain_id\": \"{s}\",\n  \"seed\": \"{s}\",\n  \"epoch_duration_ms\": {d},\n  \"protocol_version\": {d},\n  \"members\": [\n", .{ &d.chain_id, &seed_hex, d.epoch_duration_ms, d.protocol_version }) catch return error.OutOfMemory;
    for (d.members, 0..) |m, i| {
        const a = hex(96, &m.authority_pk);
        const wk = hex(32, &m.worker_pk);
        const nk = hex(32, &m.network_pk);
        const ak = hex(32, &m.account_pk);
        w.print("    {{\"index\": {d}, \"stake\": {d}, \"authority_pk\": \"{s}\", \"worker_pk\": \"{s}\", \"network_pk\": \"{s}\", \"account_pk\": \"{s}\", \"network_address\": \"{s}\", \"consensus_address\": \"{s}\", \"p2p_address\": \"{s}\", \"metrics_address\": \"{s}\"}}{s}\n", .{ m.index, m.stake, &a, &wk, &nk, &ak, m.network_address, m.consensus_address, m.p2p_address, m.metrics_address, if (i + 1 < d.members.len) "," else "" }) catch return error.OutOfMemory;
    }
    w.writeAll("  ]\n}\n") catch return error.OutOfMemory;
    return out.toOwnedSlice() catch error.OutOfMemory;
}

/// `host:port` of a p2p socket address as the udp multiaddr anemo dials (`SeedPeer.address` is a
/// Multiaddr; `to_anemo_address` takes `/ip4/<a>/udp/<port>`).
fn p2pMultiaddr(buf: []u8, sock: []const u8) Error![]const u8 {
    const colon = std.mem.lastIndexOfScalar(u8, sock, ':') orelse return error.BadConfig;
    return std.fmt.bufPrint(buf, "/ip4/{s}/udp/{s}", .{ sock[0..colon], sock[colon + 1 ..] }) catch error.BadConfig;
}

/// A validator.yaml that sui-config's NodeConfig deserializes (checked by
/// tools/truth/validator-keys): `genesis` is a required NodeConfig field, so it names
/// `<dir>/genesis.blob` (read lazily by sui-node; the localnet genesis comes from the genesis
/// tooling), and seed peers are udp multiaddrs.
pub fn renderYaml(gpa: std.mem.Allocator, dir: []const u8, d: *const Description, i: u32) Error![]u8 {
    const m = d.members[i];
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    w.print(
        \\# zui local test committee, validator {d} of {d}. No key paths: keys derive from the
        \\# committee seed in localnet.json (gate: generated keys only).
        \\db-path: {s}/db-{d}/authorities_db
        \\network-address: {s}
        \\metrics-address: {s}
        \\admin-interface-port: {d}
        \\consensus-config:
        \\  db-path: {s}/db-{d}/consensus_db
        \\  db-retention-epochs: 1
        \\  listen-address: {s}
        \\  external-address: {s}
        \\genesis:
        \\  genesis-file-location: {s}/genesis.blob
        \\p2p-config:
        \\  listen-address: {s}
        \\
    , .{ i, d.members.len, dir, i, m.network_address, m.metrics_address, 11337 + i, dir, i, m.consensus_address, m.consensus_address, dir, m.p2p_address }) catch return error.OutOfMemory;
    if (d.members.len > 1) {
        w.writeAll("  seed-peers:\n") catch return error.OutOfMemory;
        for (d.members) |o| {
            if (o.index == i) continue;
            var mb: [96]u8 = undefined;
            w.print("  - address: {s}\n", .{try p2pMultiaddr(&mb, o.p2p_address)}) catch return error.OutOfMemory;
        }
    }
    return out.toOwnedSlice() catch error.OutOfMemory;
}

pub const Localnet = struct {
    /// Writes `localnet.json` and one validator yaml per member into `dir`.
    pub fn generate(gpa: std.mem.Allocator, io: std.Io, dir: []const u8, n: u32, seed: [32]u8, opts: Options) Error!void {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const d = try describe(arena.allocator(), n, seed, opts);
        try fsutil.makePath(io, dir);
        const json = try renderJson(gpa, &d);
        defer gpa.free(json);
        var pb: [std.fs.max_path_bytes]u8 = undefined;
        try fsutil.writeAtomic(io, std.fmt.bufPrint(&pb, "{s}/localnet.json", .{dir}) catch return error.Io, json);
        for (0..n) |i| {
            const y = try renderYaml(gpa, dir, &d, @intCast(i));
            defer gpa.free(y);
            try fsutil.writeAtomic(io, std.fmt.bufPrint(&pb, "{s}/validator-{d}.yaml", .{ dir, i }) catch return error.Io, y);
        }
    }

    pub fn load(gpa: std.mem.Allocator, io: std.Io, dir: []const u8) Error!Loaded {
        var pb: [std.fs.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrint(&pb, "{s}/localnet.json", .{dir}) catch return error.Io;
        const data = (try fsutil.readAll(gpa, io, path, 1 << 24)) orelse return error.Io;
        defer gpa.free(data);
        return parseJson(gpa, data);
    }
};

const JsonMember = struct {
    index: u32,
    stake: u64,
    authority_pk: []const u8,
    worker_pk: []const u8,
    network_pk: []const u8,
    account_pk: []const u8,
    network_address: []const u8,
    consensus_address: []const u8,
    p2p_address: []const u8,
    metrics_address: []const u8,
};
const JsonDesc = struct {
    chain_id: []const u8,
    seed: []const u8,
    epoch_duration_ms: u64,
    protocol_version: u64,
    members: []const JsonMember,
};

fn unhex(comptime N: usize, s: []const u8) Error![N]u8 {
    if (s.len != 2 * N) return error.BadConfig;
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch return error.BadConfig;
    return out;
}

pub fn parseJson(gpa: std.mem.Allocator, data: []const u8) Error!Loaded {
    var l: Loaded = .{ .arena = std.heap.ArenaAllocator.init(gpa), .desc = undefined };
    errdefer l.arena.deinit();
    const a = l.arena.allocator();
    const j = std.json.parseFromSliceLeaky(JsonDesc, a, data, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return error.BadConfig;
    if (j.chain_id.len != 8) return error.BadConfig;
    const members = try a.alloc(Member, j.members.len);
    for (j.members, members) |jm, *m| {
        m.* = .{
            .index = jm.index,
            .stake = jm.stake,
            .authority_pk = try unhex(96, jm.authority_pk),
            .worker_pk = try unhex(32, jm.worker_pk),
            .network_pk = try unhex(32, jm.network_pk),
            .account_pk = try unhex(32, jm.account_pk),
            .network_address = jm.network_address,
            .consensus_address = jm.consensus_address,
            .p2p_address = jm.p2p_address,
            .metrics_address = jm.metrics_address,
        };
    }
    l.desc = .{ .chain_id = j.chain_id[0..8].*, .seed = try unhex(32, j.seed), .epoch_duration_ms = j.epoch_duration_ms, .protocol_version = j.protocol_version, .members = members };
    return l;
}

test "committee stake sums to total voting power" {
    for ([_]u32{ 1, 3, 4, 7, 10, 13 }) |n| {
        var sum: u64 = 0;
        for (0..n) |i| sum += stakeOf(n, @intCast(i));
        try std.testing.expectEqual(total_voting_power, sum);
    }
}

test "describe, render and parse round trip; every address is local" {
    const gate = @import("../gate.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const seed: [32]u8 = @splat(1);
    const d = try describe(arena.allocator(), 4, seed, .{});
    const json = try renderJson(std.testing.allocator, &d);
    defer std.testing.allocator.free(json);
    var l = try parseJson(std.testing.allocator, json);
    defer l.deinit();
    try std.testing.expectEqual(@as(usize, 4), l.desc.members.len);
    try std.testing.expectEqualSlices(u8, &d.members[2].authority_pk, &l.desc.members[2].authority_pk);
    try std.testing.expectEqualStrings(&d.chain_id, &l.desc.chain_id);
    var addrs: std.ArrayList([]const u8) = .empty;
    defer addrs.deinit(std.testing.allocator);
    for (l.desc.members) |m| {
        try addrs.append(std.testing.allocator, m.network_address);
        try addrs.append(std.testing.allocator, m.consensus_address);
        try addrs.append(std.testing.allocator, m.p2p_address);
    }
    const dec = gate.decide(.{ .chain_id = &l.desc.chain_id, .addresses = addrs.items, .key_source = .generated });
    try std.testing.expect(dec == .allowed);
    // the yaml of member 1 loads with the validator.yaml loader
    const y = try renderYaml(std.testing.allocator, "/tmp/ln", &d, 1);
    defer std.testing.allocator.free(y);
    const config = @import("config.zig");
    var cfg = try config.parse(std.testing.allocator, y);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(usize, 3), cfg.cfg.seed_peers.len);
    try std.testing.expect(cfg.cfg.protocol_key == null);
    // what sui-config's NodeConfig needs (tools/truth/validator-keys parses these files): the
    // required `genesis` field and seed peers as udp multiaddrs
    try std.testing.expectEqualStrings("/tmp/ln/genesis.blob", cfg.cfg.genesis_path.?);
    try std.testing.expectEqualStrings("/ip4/127.0.0.1/udp/18002", cfg.cfg.seed_peers[0]);
}
