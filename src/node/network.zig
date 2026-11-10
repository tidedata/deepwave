//! The network deepwave follows (`--network mainnet|testnet`): everything that differs between
//! Sui mainnet and testnet in one table. Mysten ships each release to testnet about a week before
//! mainnet, so the release pipeline (tools/release/) gates a new protocol version on testnet first.
//!
//! Per network: the chain identifier (digest of checkpoint 0, reported by GetServiceInfo and in
//! `x-sui-chain-id`), the protocol table chain (`protocol.get(v, chain)`: the chain's amendments
//! and `ProtocolConfig.chain`, which execution reads), the public checkpoint bucket, the S3
//! archive, the formal snapshot origin, the live stream full node, the anemo TLS server name
//! (`sui-<first 4 bytes of the chain id>`) and Mysten's state-sync seed peers.
//! The genesis blob (trust root) is a file: `--genesis`, from
//! https://github.com/MystenLabs/sui-genesis/raw/main/<network>/genesis.blob.
const std = @import("std");
const protocol = @import("protocol");

pub const Network = enum {
    mainnet,
    testnet,

    pub fn params(n: Network) *const Params {
        return switch (n) {
            .mainnet => &mainnet,
            .testnet => &testnet,
        };
    }

    pub fn parse(s: []const u8) ?Network {
        return std.meta.stringToEnum(Network, s);
    }
};

pub const Params = struct {
    name: []const u8,
    chain: protocol.Chain,
    /// Genesis checkpoint digest, base58 (sui `ChainIdentifier`) and raw.
    chain_id_b58: []const u8,
    chain_id: [32]u8,
    /// Mysten's public checkpoint bucket (30-day window), no credentials.
    bucket_url: []const u8,
    /// Mysten's full archive on S3 (us-west-2, requester pays).
    s3_bucket: []const u8,
    formal_snapshot_url: []const u8,
    /// A full node serving gRPC-web SubscribeCheckpoints (the live stream).
    fullnode_url: []const u8,
    /// anemo TLS server name: `sui-` ++ hex of the chain id's first 4 bytes.
    p2p_server_name: []const u8,
    /// Mysten's state-sync seed peers (`host@peerid`, port 8084/udp), from sui's
    /// fullnode-template / scripts/compatibility/fullnode-sync.sh.
    seed_peers: []const []const u8,
};

fn hex32(comptime h: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

pub const mainnet: Params = .{
    .name = "mainnet",
    .chain = .mainnet,
    .chain_id_b58 = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S",
    .chain_id = hex32("35834a8ac17ca48fb14ac8f99c17c98747e95dd07294ae41a46b382246a4499b"),
    .bucket_url = "https://checkpoints.mainnet.sui.io",
    .s3_bucket = "mysten-mainnet-checkpoints",
    .formal_snapshot_url = "https://formal-snapshot.mainnet.sui.io",
    .fullnode_url = "https://fullnode.mainnet.sui.io",
    .p2p_server_name = "sui-35834a8a",
    .seed_peers = &.{
        "mel-00.mainnet.sui.io@d32b55bdf1737ec415df8c88b3bf91e194b59ee3127e3f38ea46fd88ba2e7849",
        "ewr-00.mainnet.sui.io@c7bf6cb93ca8fdda655c47ebb85ace28e6931464564332bf63e27e90199c50ee",
        "ewr-01.mainnet.sui.io@3227f8a05f0faa1a197c075d31135a366a1c6f3d4872cb8af66c14dea3e0eb66",
        "lhr-00.mainnet.sui.io@c619a5e0f8f36eac45118c1f8bda28f0f508e2839042781f1d4a9818043f732c",
    },
};

pub const testnet: Params = .{
    .name = "testnet",
    .chain = .testnet,
    .chain_id_b58 = "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD",
    .chain_id = hex32("4c78adacf2a2f5ad80f27ed7d54aa69d3a78f1ca67fdef9ecf5754f5b8bb77b0"),
    .bucket_url = "https://checkpoints.testnet.sui.io",
    .s3_bucket = "mysten-testnet-checkpoints",
    .formal_snapshot_url = "https://formal-snapshot.testnet.sui.io",
    .fullnode_url = "https://fullnode.testnet.sui.io",
    .p2p_server_name = "sui-4c78adac",
    .seed_peers = &.{
        "ewr-tnt-ssfn-00.testnet.sui.io@df8a8d128051c249e224f95fcc463f518a0ebed8986bbdcc11ed751181fecd38",
        "lax-tnt-ssfn-00.testnet.sui.io@f9a72a0a6c17eed09c27898eab389add704777c03e135846da2428f516a0c11d",
        "lhr-tnt-ssfn-00.testnet.sui.io@9393d6056bb9c9d8475a3cf3525c747257f17c6a698a7062cbbd1875bc6ef71e",
        "mel-tnt-ssfn-00.testnet.sui.io@c88742f46e66a11cb8c84aca488065661401ef66f726cb9afeb8a5786d83456e",
    },
};

test "network: chain id, base58 and server name agree" {
    const b58 = @import("serve").b58;
    for ([_]Network{ .mainnet, .testnet }) |n| {
        const p = n.params();
        try std.testing.expectEqualSlices(u8, &p.chain_id, &b58.decode32(p.chain_id_b58).?);
        var nb: [16]u8 = undefined;
        try std.testing.expectEqualStrings(p.p2p_server_name, try std.fmt.bufPrint(&nb, "sui-{x}", .{p.chain_id[0..4]}));
        try std.testing.expectEqual(p.chain, (try protocol.get(140, p.chain)).chain);
    }
}
