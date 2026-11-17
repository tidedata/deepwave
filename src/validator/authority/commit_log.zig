//! The consensus commit log line sui-core 1.83.1 writes for every commit its consensus handler
//! processes (`consensus_handler.rs` `handle_consensus_commit`, at info):
//!
//!   <RFC 3339 UTC, microseconds>Z  INFO sui_core::consensus_handler: Received consensus output
//!   C<index>(<digest>). Rejected transactions (<rejected digest>): [<block>: [<i>,..], ..]
//!   consensus_commit=C<index>(<digest>)@B<round>([<author>],<digest>) [<block>, ..])
//!
//! (one line). Displays as consensus-core and sui-types write them: CommitDigest and BlockDigest
//! show the first 4 base64 characters, BlockRef is `B<round>([<author>],<digest>)`, the rejected
//! digest is the full base58 Blake2b-256 of BCS `BTreeMap<BlockRef, Vec<TransactionIndex>>`
//! (`rejected_transactions_digest`). deepwave writes the same text with its own target
//! (`zui_validator::consensus_handler`), so the mixed localnet pairs deepwave and sui-node commits
//! line for line (tools/localnet-mixed/compare.py).
const std = @import("std");
const consensus = @import("consensus");
const serve = @import("serve");

const Allocator = std.mem.Allocator;
const ctypes = consensus.types;

pub const target = "zui_validator::consensus_handler";

fn b64Prefix(out: *[44]u8, d: *const [32]u8) []const u8 {
    return std.base64.standard.Encoder.encode(out, d)[0..4];
}

fn blockRef(w: *std.Io.Writer, r: ctypes.BlockRef) !void {
    var e: [44]u8 = undefined;
    try w.print("B{d}([{d}],{s})", .{ r.round, r.author, b64Prefix(&e, &r.digest) });
}

/// The text after the level and target (`Received consensus output ...`), no newline.
pub fn message(w: *std.Io.Writer, sub: *const ctypes.CommittedSubDag, rejected_digest: *const [32]u8) !void {
    var e1: [44]u8 = undefined;
    var b58: [serve.b58.max_len_32]u8 = undefined;
    const cd = b64Prefix(&e1, &sub.commit_ref.digest);
    try w.print("Received consensus output C{d}({s}). Rejected transactions ({s}): [", .{ sub.commit_ref.index, cd, serve.b58.encode32(&b58, rejected_digest) });
    for (sub.rejected_transactions_by_block, 0..) |r, i| {
        if (i != 0) try w.writeAll(", ");
        try blockRef(w, r.block);
        try w.writeAll(": [");
        for (r.indices, 0..) |x, j| {
            if (j != 0) try w.writeAll(",");
            try w.print("{d}", .{x});
        }
        try w.writeAll("]");
    }
    try w.print("] consensus_commit=C{d}({s})@", .{ sub.commit_ref.index, cd });
    try blockRef(w, sub.leader);
    try w.writeAll(" [");
    for (sub.blocks, 0..) |b, i| {
        if (i != 0) try w.writeAll(", ");
        try blockRef(w, b.reference());
    }
    try w.writeAll("])");
}

/// `2026-11-17T01:01:13.563553Z` (tracing-subscriber's default UTC time).
pub fn timestamp(w: *std.Io.Writer, unix_us: u64) !void {
    const secs = unix_us / std.time.us_per_s;
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    try w.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}Z", .{
        yd.year,                    md.month.numeric(),        @as(u32, md.day_index) + 1,
        ds.getHoursIntoDay(),       ds.getMinutesIntoHour(),   ds.getSecondsIntoMinute(),
        unix_us % std.time.us_per_s,
    });
}

/// The whole line, newline included.
pub fn line(w: *std.Io.Writer, unix_us: u64, sub: *const ctypes.CommittedSubDag, rejected_digest: *const [32]u8) !void {
    try timestamp(w, unix_us);
    try w.print("  INFO {s}: ", .{target});
    try message(w, sub, rejected_digest);
    try w.writeAll("\n");
}

/// Writes the line to stderr (the process log), from a 64 KiB stack buffer (a longer line is
/// cut, never dropped: the commit's ref and leader come first).
pub fn emit(unix_us: u64, sub: *const ctypes.CommittedSubDag, rejected_digest: *const [32]u8) void {
    var buf: [64 << 10]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    line(&w, unix_us, sub, rejected_digest) catch {
        // cut: end the line where the buffer filled
        if (w.end == buf.len) buf[buf.len - 1] = '\n';
    };
    std.debug.print("{s}", .{w.buffered()});
}

test "commit log: sui-core's text, empty and non-empty rejections" {
    const hash = @import("hash");
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const leader: ctypes.BlockRef = .{ .round = 3, .author = 3, .digest = @splat(0xe5) };
    const sub: ctypes.CommittedSubDag = .{
        .leader = leader,
        .blocks = &.{},
        .timestamp_ms = 0,
        .commit_ref = .{ .index = 3, .digest = @splat(0x10) },
        .decided_with_local_blocks = true,
        .recovered_rejected_transactions = false,
        .rejected_transactions_by_block = &.{},
    };
    // BCS of an empty map is [0]: the digest sui-node prints on every commit without rejections
    const empty = hash.blake2b256(&.{&[_]u8{0}});
    try line(&w, 1_794_877_273_563_553, &sub, &empty);
    try std.testing.expectEqualStrings(
        "2026-11-17T01:01:13.563553Z  INFO zui_validator::consensus_handler: Received consensus output C3(EBAQ). Rejected transactions (D4bn122GiEqs99z526GdhYETJqctLHGSmWokypEo9qu): [] consensus_commit=C3(EBAQ)@B3([3],5eXl) [])\n",
        w.buffered(),
    );
    w = std.Io.Writer.fixed(&buf);
    const rej = [_]ctypes.RejectedInBlock{.{ .block = leader, .indices = &.{ 0, 2 } }};
    var sub2 = sub;
    sub2.rejected_transactions_by_block = &rej;
    try message(&w, &sub2, &empty);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "): [B3([3],5eXl): [0,2]] consensus_commit=") != null);
}
