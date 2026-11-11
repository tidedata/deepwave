//! Node profiles (docs/EDGE.md section 6): the flag defaults of a core, an edge and a Mac mini.
//! A profile only sets defaults; any flag after `--profile` still wins. Pure data, so the numbers
//! are testable and the node's argument parser stays one `apply`.
const std = @import("std");

pub const Kind = enum {
    /// A full-history node (the existing defaults; serves the edge feed to edges).
    core,
    /// A small edge box (4 to 8 cores, 16 to 32 GB, 500 GB to 1 TB NVMe).
    edge,
    /// Mac mini (M-series, 32 to 64 GB unified memory, 1 to 2 TB SSD): an edge with more cache
    /// and headroom to run a pruned executing node.
    macmini,

    pub fn parse(name: []const u8) ?Kind {
        return std.meta.stringToEnum(Kind, name);
    }
};

pub const Settings = struct {
    /// Checkpoints, transactions, effects and events kept: whole epochs.
    retention_epochs: u32,
    /// Superseded object versions kept: whole epochs.
    object_retention_epochs: u32,
    age_out: bool,
    chunk_cache_mb: u32,
    cp_cache_mb: u32,
    fetchers: u32,
    window: u32,
    /// Store input versions and loaded runtime object lists (needs input objects: edge feeds have none).
    read_sets: bool,
    /// zui/1 connections to the cores.
    max_conns: u32,
    /// Tip poll spacing against a zui/1 source (milliseconds).
    poll_ms: u32,
    /// Serve the edge feed and dictionaries to other edges (edge-to-edge fan-out).
    edge_feed: bool,
    /// StateService indexes on disk (owned objects, balances).
    indexes: bool,
    /// `POST /zui1/rpc` for Workers and browsers (behind a TLS terminator).
    http_rpc: bool,
    /// With `--source zui1:`: take checkpoints from the public bucket while no core can serve
    /// them (`--edge-fallback http`; fallback.zig). Off for a core, which follows no core.
    edge_fallback: bool,
};

pub fn settings(k: Kind) Settings {
    return switch (k) {
        // what deepwave does without a profile
        .core => .{ .retention_epochs = 2, .object_retention_epochs = 1, .age_out = false, .chunk_cache_mb = 1024, .cp_cache_mb = 256, .fetchers = 8, .window = 64, .read_sets = true, .max_conns = 4, .poll_ms = 25, .edge_feed = true, .indexes = false, .http_rpc = false, .edge_fallback = false },
        // recent history of one epoch, the live set, little memory
        .edge => .{ .retention_epochs = 1, .object_retention_epochs = 1, .age_out = true, .chunk_cache_mb = 1024, .cp_cache_mb = 128, .fetchers = 4, .window = 32, .read_sets = false, .max_conns = 4, .poll_ms = 50, .edge_feed = true, .indexes = true, .http_rpc = true, .edge_fallback = true },
        .macmini => .{ .retention_epochs = 2, .object_retention_epochs = 1, .age_out = true, .chunk_cache_mb = 8192, .cp_cache_mb = 1024, .fetchers = 8, .window = 128, .read_sets = false, .max_conns = 8, .poll_ms = 25, .edge_feed = true, .indexes = true, .http_rpc = true, .edge_fallback = true },
    };
}

/// Rough resident-memory budget in MiB the profile's caches ask for (caches plus the follower's
/// window of in-flight checkpoints at about 8 MiB each), for the startup log and docs.
pub fn cacheBudgetMb(s: Settings) u64 {
    return @as(u64, s.chunk_cache_mb) + s.cp_cache_mb + @as(u64, s.window) * 8;
}

test "profiles" {
    try std.testing.expectEqual(Kind.edge, Kind.parse("edge").?);
    try std.testing.expect(Kind.parse("nope") == null);
    const e = settings(.edge);
    const m = settings(.macmini);
    try std.testing.expect(e.retention_epochs <= settings(.core).retention_epochs);
    try std.testing.expect(!e.read_sets and !m.read_sets);
    // an edge keeps following through a core restart; a core has no core to fall back from
    try std.testing.expect(e.edge_fallback and m.edge_fallback and !settings(.core).edge_fallback);
    // the Mac mini profile fits a 32 GB machine with room for the live-set index and the OS
    try std.testing.expect(cacheBudgetMb(m) < 16 * 1024);
    try std.testing.expect(cacheBudgetMb(e) < 3 * 1024);
}
