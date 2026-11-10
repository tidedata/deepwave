//! Verify-only fallback on a protocol version this binary cannot execute.
//!
//! sui-node stops when the network moves to a protocol version newer than its binary
//! (the 2026-11-05 outage). deepwave keeps following: the follower still checks every checkpoint
//! (BLS certificate, contents and effects digests, output objects against effects), the store
//! still commits certified data, serving goes on. Only deepwave's own execution pauses:
//!   * the executor is not fed (its decode would only mark every transaction verify-only),
//!   * the end-of-epoch state-hash check cannot trust an accumulator path chosen for a protocol
//!     it has no table for: it keeps accumulating with the newest path, and a mismatch at the end
//!     of an unsupported epoch is a warning (the root is dropped), never an execution stop or a halt.
//! The alert is loud and machine-readable: ERROR lines starting `PROTOCOL UNSUPPORTED` (the lines
//! protocol-watch quotes) and `zui_protocol_*` metrics. The way out is a binary whose protocol
//! range covers the network: start it (zero downtime with handoff.zig) and execution resumes from
//! the store at the next checkpoint, because verify-only mode committed every output object.
//!
//! The flag (`--verify-fallback`, off by default) controls the behaviour change; the alert lines
//! and metrics are always on.
const std = @import("std");
const protocol = @import("protocol");
const Atomic = std.atomic.Value;

/// Test builds only (`-Dnode-test-flags`, `deepwave run --test-protocol-max N`): the newest protocol
/// this binary claims to support, to drive the fallback against a real chain. null: the real range.
/// Execution tables and the state-hash path are untouched; only the supported/unsupported verdict moves.
pub var test_protocol_max: ?u64 = null;

fn maxPv() u64 {
    return test_protocol_max orelse protocol.max_protocol_version;
}

pub const Guard = struct {
    /// `--verify-fallback`: skip execution on an unsupported protocol and keep the state-hash
    /// check from halting the node there.
    enabled: bool = false,
    /// Tests: log warnings instead of errors (the test runner fails on error lines).
    quiet: bool = false,
    /// Protocol version of the epoch being followed (0 until known).
    cur_pv: Atomic(u64) = .init(0),
    /// 1 while the current epoch's protocol is outside [min, max] (gauge).
    unsupported_now: Atomic(u32) = .init(0),
    /// The announced next epoch's protocol, when unsupported (0: none).
    next_unsupported_pv: Atomic(u64) = .init(0),
    /// Epochs followed in verify-only mode because of an unsupported protocol (counter) and the
    /// checkpoints in them.
    epochs: Atomic(u64) = .init(0),
    checkpoints: Atomic(u64) = .init(0),
    /// The first checkpoint of the current unsupported run (0: none) and the highest unsupported
    /// protocol seen.
    first_seq: Atomic(u64) = .init(0),
    highest_pv: Atomic(u64) = .init(0),
    alerts: Atomic(u64) = .init(0),

    pub fn supported(pv: u64) bool {
        return pv >= protocol.min_protocol_version and pv <= maxPv();
    }

    /// The protocol a verify-only epoch hashes with: the newest this binary knows.
    pub fn newestSupported() u64 {
        return protocol.max_protocol_version;
    }

    /// True when execution should not be fed checkpoints of protocol `pv`.
    pub fn skipExec(g: *const Guard, pv: u64) bool {
        return g.enabled and !supported(pv);
    }

    /// The protocol version the state-hash accumulator should be chosen with for `pv`.
    pub fn hashPv(pv: u64) u64 {
        return if (supported(pv)) pv else newestSupported();
    }

    fn alert(g: *Guard, comptime fmt: []const u8, args: anytype) void {
        _ = g.alerts.fetchAdd(1, .monotonic);
        if (g.quiet) std.log.warn("PROTOCOL UNSUPPORTED (test): " ++ fmt, args) else std.log.err("PROTOCOL UNSUPPORTED: " ++ fmt, args);
    }

    /// The node starts in (or switches to) epoch `epoch` running protocol `pv`, at checkpoint `seq`.
    pub fn noteEpoch(g: *Guard, pv: u64, epoch: u64, seq: u64) void {
        const was = g.unsupported_now.load(.acquire) == 1;
        g.cur_pv.store(pv, .release);
        g.next_unsupported_pv.store(0, .release);
        if (supported(pv)) {
            if (was) {
                g.unsupported_now.store(0, .release);
                g.first_seq.store(0, .release);
                std.log.info("protocol: epoch {d} runs protocol {d}, within this binary's range {d}..{d}; execution resumes", .{ epoch, pv, protocol.min_protocol_version, maxPv() });
            }
            return;
        }
        g.unsupported_now.store(1, .release);
        if (!was) {
            _ = g.epochs.fetchAdd(1, .monotonic);
            g.first_seq.store(seq, .release);
        } else _ = g.epochs.fetchAdd(1, .monotonic);
        if (pv > g.highest_pv.load(.monotonic)) g.highest_pv.store(pv, .monotonic);
        g.alert("epoch {d} runs protocol {d}; this binary supports {d}..{d}. Following and serving in verify-only mode{s}; install a deepwave that supports protocol {d}", .{ epoch, pv, protocol.min_protocol_version, maxPv(), if (g.enabled) "" else " (--verify-fallback is off: execution still reports each transaction verify-only)", pv });
    }

    /// An end-of-epoch checkpoint announced the next epoch's protocol: raise the alert one epoch early.
    pub fn noteEpochEnd(g: *Guard, next_pv: u64, epoch: u64, seq: u64) void {
        if (supported(next_pv)) return;
        g.next_unsupported_pv.store(next_pv, .release);
        if (next_pv > g.highest_pv.load(.monotonic)) g.highest_pv.store(next_pv, .monotonic);
        g.alert("epoch {d} ended at checkpoint {d} and epoch {d} will run protocol {d}, above this binary's maximum {d}: verify-only from the next epoch until a newer deepwave is running", .{ epoch, seq, epoch + 1, next_pv, maxPv() });
    }

    /// One checkpoint followed while the protocol is unsupported (call per checkpoint; cheap).
    pub fn noteCheckpoint(g: *Guard) void {
        if (g.unsupported_now.load(.acquire) == 1) _ = g.checkpoints.fetchAdd(1, .monotonic);
    }

    pub fn render(g: *const Guard, w: *std.Io.Writer) !void {
        try w.print(
            \\# TYPE zui_protocol_unsupported gauge
            \\zui_protocol_unsupported {d}
            \\# TYPE zui_protocol_next_unsupported gauge
            \\zui_protocol_next_unsupported {d}
            \\# TYPE zui_protocol_supported_min gauge
            \\zui_protocol_supported_min {d}
            \\# TYPE zui_protocol_supported_max gauge
            \\zui_protocol_supported_max {d}
            \\# TYPE zui_protocol_network_version gauge
            \\zui_protocol_network_version {d}
            \\# TYPE zui_protocol_highest_unsupported gauge
            \\zui_protocol_highest_unsupported {d}
            \\# TYPE zui_protocol_verify_only_epochs counter
            \\zui_protocol_verify_only_epochs {d}
            \\# TYPE zui_protocol_verify_only_checkpoints counter
            \\zui_protocol_verify_only_checkpoints {d}
            \\# TYPE zui_protocol_verify_only_since gauge
            \\zui_protocol_verify_only_since {d}
            \\# TYPE zui_protocol_alerts counter
            \\zui_protocol_alerts {d}
            \\# TYPE zui_protocol_fallback_enabled gauge
            \\zui_protocol_fallback_enabled {d}
            \\
        , .{
            g.unsupported_now.load(.monotonic),     @as(u32, if (g.next_unsupported_pv.load(.monotonic) != 0) 1 else 0),
            protocol.min_protocol_version,          maxPv(),
            g.cur_pv.load(.monotonic),              g.highest_pv.load(.monotonic),
            g.epochs.load(.monotonic),              g.checkpoints.load(.monotonic),
            g.first_seq.load(.monotonic),           g.alerts.load(.monotonic),
            @as(u32, if (g.enabled) 1 else 0),
        });
    }
};

test "guard: supported range, alerts, resume" {
    var g: Guard = .{ .enabled = true, .quiet = true };
    try std.testing.expect(Guard.supported(protocol.max_protocol_version));
    try std.testing.expect(!Guard.supported(protocol.max_protocol_version + 1));
    try std.testing.expect(!Guard.supported(0));
    try std.testing.expect(!g.skipExec(protocol.max_protocol_version));
    try std.testing.expect(g.skipExec(protocol.max_protocol_version + 1));
    try std.testing.expectEqual(protocol.max_protocol_version, Guard.hashPv(protocol.max_protocol_version + 5));
    g.noteEpoch(protocol.max_protocol_version, 10, 100);
    try std.testing.expectEqual(@as(u32, 0), g.unsupported_now.load(.monotonic));
    g.noteEpochEnd(protocol.max_protocol_version + 1, 10, 200);
    try std.testing.expectEqual(@as(u64, 1), g.alerts.load(.monotonic));
    g.noteEpoch(protocol.max_protocol_version + 1, 11, 201);
    g.noteCheckpoint();
    g.noteCheckpoint();
    try std.testing.expectEqual(@as(u64, 2), g.checkpoints.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 201), g.first_seq.load(.monotonic));
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try g.render(&w);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "zui_protocol_unsupported 1") != null);
    // a newer binary at the next epoch: back to supported
    g.noteEpoch(protocol.max_protocol_version, 12, 300);
    try std.testing.expectEqual(@as(u32, 0), g.unsupported_now.load(.monotonic));
    g.noteCheckpoint();
    try std.testing.expectEqual(@as(u64, 2), g.checkpoints.load(.monotonic));
}
