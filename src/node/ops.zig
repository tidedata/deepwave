//! Ops parity with sui-node (docs/DROP-IN.md 2.4, 2.5, G11): what a production node's scripts read
//! from a node, in sui-node's exact shapes, so health.sh and protocol-watch.sh work against
//! deepwave with only the unit name changed.
//!
//!   metrics   `last_executed_checkpoint`, `highest_synced_checkpoint`,
//!             `last_executed_checkpoint_timestamp_ms` (bare names, no labels; health.sh does
//!             `awk '$1==name'`), plus `current_epoch` and `current_protocol_version`.
//!   version   `deepwave <x.y.z>-<sha>` (`awk '{print $2}' | cut -d- -f1` gives x.y.z).
//!   startup   `Supported protocol versions: Some(SupportedProtocolVersions { min: ProtocolVersion(1),
//!             max: ProtocolVersion(N) })`, sui-node's `{:?}` of its config field; protocol-watch
//!             reads N with `sed -nE 's/.*max: ProtocolVersion\(([0-9]+)\).*/\1/p'`.
//!
//! The version is deepwave's own, never a Sui release number, so protocol-watch's GitHub lookup of
//! `mainnet-v<x.y.z>` misses and it takes the max from the startup line, which is the protocol
//! range deepwave actually executes (src/protocol).
const std = @import("std");
const protocol = @import("protocol");

/// deepwave release number. Bump on every release installed on a box.
pub const version = "0.1.0";

/// Prints `deepwave <version>-<sha>`, sui-node's `sui-node 1.83.1-6a567faf6de1` shape. The sha
/// comes from the executable's build options (build.zig), so only main.zig depends on it.
pub fn printVersion(w: *std.Io.Writer, sha: []const u8) !void {
    try w.print("deepwave {s}-{s}\n", .{ version, sha });
}

/// `deepwave --protocol-range`: the startup line's protocol range on stdout, so deploy scripts
/// (deploy/zui-update.sh) can check a binary against the network before installing it.
pub fn printProtocolRange(w: *std.Io.Writer) !void {
    try w.print("Supported protocol versions: Some(SupportedProtocolVersions {{ min: ProtocolVersion({d}), max: ProtocolVersion({d}) }})\n", .{ protocol.min_protocol_version, protocol.max_protocol_version });
}

/// The two startup lines sui-node logs first (`Sui Node version`, `Supported protocol versions`).
pub fn logStartup(sha: []const u8) void {
    std.log.info("zui Node version: {s}-{s}", .{ version, sha });
    std.log.info("Supported protocol versions: Some(SupportedProtocolVersions {{ min: ProtocolVersion({d}), max: ProtocolVersion({d}) }})", .{ protocol.min_protocol_version, protocol.max_protocol_version });
}

/// The level word of a log line, as sui-node's tracing prints it: `ERROR`, `WARN`, `INFO`,
/// `DEBUG`, with a space on each side in the line. protocol-watch.sh's restart-loop alert quotes
/// the last line matching `grep ' ERROR '` (std's `asText` gives lowercase `error`, which never
/// matches).
pub fn levelName(level: std.log.Level) []const u8 {
    return switch (level) {
        .err => "ERROR",
        .warn => "WARN",
        .info => "INFO",
        .debug => "DEBUG",
    };
}

pub const Compat = struct {
    /// Highest checkpoint committed to the store (servable); null before the first.
    executed: ?u64,
    /// Its summary timestamp (ms since the Unix epoch).
    executed_ts_ms: u64,
    /// Highest checkpoint the node has fetched (verified or waiting to be).
    synced: u64,
    epoch: u64,
    protocol_version: u64,
};

/// sui-node's metric names, values as sui-node reports them. Nothing is written for a node that
/// has not committed a checkpoint yet (health.sh then reports age -1, as for a starting sui-node).
pub fn renderCompat(c: Compat, w: *std.Io.Writer) !void {
    const e = c.executed orelse return;
    try w.print(
        \\# HELP last_executed_checkpoint Last executed checkpoint
        \\# TYPE last_executed_checkpoint gauge
        \\last_executed_checkpoint {d}
        \\# HELP last_executed_checkpoint_timestamp_ms Last executed checkpoint timestamp ms
        \\# TYPE last_executed_checkpoint_timestamp_ms gauge
        \\last_executed_checkpoint_timestamp_ms {d}
        \\# HELP highest_synced_checkpoint Highest synced checkpoint
        \\# TYPE highest_synced_checkpoint gauge
        \\highest_synced_checkpoint {d}
        \\# HELP current_epoch Current epoch ID
        \\# TYPE current_epoch gauge
        \\current_epoch {d}
        \\# HELP current_protocol_version Current protocol version
        \\# TYPE current_protocol_version gauge
        \\current_protocol_version {d}
        \\
    , .{ e, c.executed_ts_ms, @max(c.synced, e), c.epoch, c.protocol_version });
}

/// The rest of what sui-node's operators and dashboards read (docs/FULLNODE-PARITY.md section 4),
/// same names, labels and help texts as sui-node 1.83.1's registry.
pub const NodeMetrics = struct {
    /// `uptime` labels: first 4 bytes of the chain identifier in hex, and the version string
    /// (sui-node: `1.83.1-6a567faf6de1`; deepwave: `<version>-<sha>`).
    chain_short: [8]u8,
    version: []const u8,
    uptime_s: u64,
    /// Highest checkpoint whose summary is certified and chained (deepwave verifies and commits in the
    /// same ordered stage, so this is the committed tip).
    verified: u64,
    /// Highest checkpoint the source has shown (fetcher frontier or stream).
    known: u64,
    /// Highest checkpoint removed by retention (0 when nothing was pruned).
    last_pruned: u64,
    protocol_version: u64,
    max_protocol_version: u64,
    safe_mode: bool = false,
    /// Transactions committed by this process (sui-node counts certificates executed).
    transactions: u64,
    /// Duration of the last finished epoch (ms), null before the first epoch change seen.
    epoch_duration_ms: ?u64 = null,
};

pub fn renderNode(m: NodeMetrics, w: *std.Io.Writer) !void {
    try w.print(
        \\# HELP uptime uptime of the node service in seconds
        \\# TYPE uptime counter
        \\uptime{{chain_identifier="{s}",process="fullnode",version="{s}"}} {d}
        \\# HELP highest_verified_checkpoint Highest verified checkpoint
        \\# TYPE highest_verified_checkpoint gauge
        \\highest_verified_checkpoint {d}
        \\# HELP highest_known_checkpoint Highest known checkpoint
        \\# TYPE highest_known_checkpoint gauge
        \\highest_known_checkpoint {d}
        \\# HELP last_pruned_checkpoint Last pruned checkpoint
        \\# TYPE last_pruned_checkpoint gauge
        \\last_pruned_checkpoint {d}
        \\# HELP sui_current_protocol_version Current protocol version in this epoch
        \\# TYPE sui_current_protocol_version gauge
        \\sui_current_protocol_version {d}
        \\# HELP sui_binary_max_protocol_version Max protocol version supported by this binary
        \\# TYPE sui_binary_max_protocol_version gauge
        \\sui_binary_max_protocol_version {d}
        \\# HELP sui_configured_max_protocol_version Max protocol version configured in the node config
        \\# TYPE sui_configured_max_protocol_version gauge
        \\sui_configured_max_protocol_version {d}
        \\# HELP is_safe_mode Whether we are running in safe mode
        \\# TYPE is_safe_mode gauge
        \\is_safe_mode {d}
        \\# HELP total_transaction_certificates Total number of transaction certificates handled
        \\# TYPE total_transaction_certificates counter
        \\total_transaction_certificates {d}
        \\# HELP total_transaction_effects Total number of transaction effects produced
        \\# TYPE total_transaction_effects counter
        \\total_transaction_effects {d}
        \\# HELP execution_driver_executed_transactions Cumulative number of transaction executed by execution driver
        \\# TYPE execution_driver_executed_transactions counter
        \\execution_driver_executed_transactions {d}
        \\
    , .{ &m.chain_short, m.version, m.uptime_s, m.verified, @max(m.known, m.verified), m.last_pruned, m.protocol_version, m.max_protocol_version, m.max_protocol_version, @intFromBool(m.safe_mode), m.transactions, m.transactions, m.transactions });
    if (m.epoch_duration_ms) |d| try w.print("# HELP epoch_total_duration Total duration of the epoch\n# TYPE epoch_total_duration gauge\nepoch_total_duration {d}\n", .{d});
    // last_executed_checkpoint_age(_ms) and the other executor families: opsmetrics.zig
}

/// `uptime`'s chain_identifier label: the chain identifier's first 4 bytes in hex (sui-node's
/// `ChainIdentifier` Display), `35834a8a` on mainnet.
pub fn chainShort(chain_id: [32]u8) [8]u8 {
    return std.fmt.bytesToHex(chain_id[0..4], .lower);
}

test "node metrics: names and labels as sui-node 1.83.1" {
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try renderNode(.{ .chain_short = "35834a8a".*, .version = "0.1.0-abc", .uptime_s = 5, .verified = 10, .known = 12, .last_pruned = 3, .protocol_version = 141, .max_protocol_version = 141, .transactions = 7 }, &w);
    const t = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, t, "uptime{chain_identifier=\"35834a8a\",process=\"fullnode\",version=\"0.1.0-abc\"} 5\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "\nhighest_verified_checkpoint 10\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "\nlast_pruned_checkpoint 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "\nsui_current_protocol_version 141\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "epoch_total_duration") == null);
}

test "compat metrics parse the way health.sh reads them" {
    var buf: [2048]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try renderCompat(.{ .executed = 342933373, .executed_ts_ms = 1794125265123, .synced = 342933375, .epoch = 1305, .protocol_version = 141 }, &w);
    // awk '$1==m {print int($2)}'
    var found: u32 = 0;
    var it = std.mem.splitScalar(u8, w.buffered(), '\n');
    while (it.next()) |line| {
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const name = f.next() orelse continue;
        const val = f.next() orelse continue;
        if (std.mem.eql(u8, name, "last_executed_checkpoint")) {
            try std.testing.expectEqualStrings("342933373", val);
            found += 1;
        } else if (std.mem.eql(u8, name, "highest_synced_checkpoint")) {
            try std.testing.expectEqualStrings("342933375", val);
            found += 1;
        } else if (std.mem.eql(u8, name, "last_executed_checkpoint_timestamp_ms")) {
            try std.testing.expectEqualStrings("1794125265123", val);
            found += 1;
        }
    }
    try std.testing.expectEqual(@as(u32, 3), found);
    // Nothing before the first commit.
    var w2 = std.Io.Writer.fixed(&buf);
    try renderCompat(.{ .executed = null, .executed_ts_ms = 0, .synced = 0, .epoch = 0, .protocol_version = 0 }, &w2);
    try std.testing.expectEqual(@as(usize, 0), w2.end);
}

test "version shape: field 2, cut -d- -f1" {
    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try printVersion(&w, "6a567faf6de1");
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, w.buffered(), "\n"), ' ');
    try std.testing.expectEqualStrings("deepwave", f.next().?);
    const field2 = f.next().?;
    try std.testing.expectEqualStrings(version, field2[0..std.mem.indexOfScalar(u8, field2, '-').?]);
}

test "ops: log levels are tracing's words, so protocol-watch's grep ' ERROR ' finds zui's errors" {
    // main.zig's logFn line shape: "<date> <time> PST <LEVEL> <message>".
    var buf: [128]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, "2026-11-08 03:00:00 PST {s} follower stopped: NodeFailed", .{levelName(.err)});
    try std.testing.expect(std.mem.indexOf(u8, line, " ERROR ") != null);
    try std.testing.expectEqualStrings("WARN", levelName(.warn));
    try std.testing.expectEqualStrings("INFO", levelName(.info));
    try std.testing.expectEqualStrings("DEBUG", levelName(.debug));
}
