//! Read-only live probe of a sui-node anemo endpoint (our own node only; CONTRACTS.md 1.4 allows
//! "P2P connections to its public anemo port as an ordinary peer would make"). Connects as a
//! throwaway peer, asks `GetCheckpointAvailability` and two `GetCheckpointSummary` requests, checks
//! the answers decode, and records the exchange for replay tests.
//!
//!   ZUI_NET_LIVE=203.0.113.8:8084 ./zig build test -Dlane=net
const std = @import("std");
const Io = std.Io;
const anemo = @import("anemo.zig");
const wire = @import("wire.zig");
const ss = @import("state_sync.zig");

pub const Report = struct {
    peer_id: [32]u8,
    handshake_ms: f64,
    highest_epoch: u64,
    highest_seq: u64,
    lowest_available: u64,
    genesis_summary_bytes: usize,
    latest_seq: u64,
    rtt_ms: f64,
    known_peers: usize,
    known_peers_verified: usize,
    known_peers_dialable: usize,
};

fn hexLine(w: *std.ArrayList(u8), a: std.mem.Allocator, label: []const u8, bytes: []const u8) !void {
    try w.print(a, ",\"{s}\":\"", .{label});
    for (bytes) |b| try w.print(a, "{x:0>2}", .{b});
    try w.append(a, '"');
}

/// Runs the probe. If `record` is non-null the exchange is appended there as JSON lines.
pub fn probe(gpa: std.mem.Allocator, io: Io, addr: Io.net.IpAddress, record: ?*std.ArrayList(u8)) !Report {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const t0 = Io.Clock.awake.now(io);
    const p = try anemo.Peer.connect(gpa, io, addr, .{ .server_name = ss.mainnet_server_name, .handshake_timeout_ms = 10_000 });
    defer p.deinit();
    const t1 = Io.Clock.awake.now(io);
    var rep: Report = undefined;
    rep.peer_id = p.peer_id;
    rep.handshake_ms = @as(f64, @floatFromInt(t0.durationTo(t1).nanoseconds)) / 1e6;
    const timeout_hdr = [_]wire.Header{.{ .name = "timeout", .value = "10000000000" }};

    // 1. availability
    const ta = Io.Clock.awake.now(io);
    const av = try p.request(a, ss.Route.get_checkpoint_availability, &timeout_hdr, ss.encodeUnitRequest(), 10_000);
    const tb = Io.Clock.awake.now(io);
    rep.rtt_ms = @as(f64, @floatFromInt(ta.durationTo(tb).nanoseconds)) / 1e6;
    if (av.status != .success) return error.UnexpectedStatus;
    const avail_bcs = try ss.decodeBody(a, av.body);
    const avail = try ss.splitAvailability(avail_bcs);
    // CertifiedCheckpointSummary starts with CheckpointSummary { epoch: u64, sequence_number: u64, ... }
    if (avail.highest_synced_summary.len < 16) return error.Malformed;
    rep.highest_epoch = std.mem.readInt(u64, avail.highest_synced_summary[0..8], .little);
    rep.highest_seq = std.mem.readInt(u64, avail.highest_synced_summary[8..16], .little);
    rep.lowest_available = avail.lowest_available_checkpoint;
    if (record) |r| {
        try r.print(gpa, "{{\"route\":\"{s}\"", .{ss.Route.get_checkpoint_availability});
        try hexLine(r, gpa, "request", "");
        try hexLine(r, gpa, "response", av.body);
        try r.appendSlice(gpa, "}\n");
    }

    // 2. genesis summary by sequence number
    const req0 = try ss.encodeSummaryRequest(a, .{ .seq = 0 });
    const g = try p.request(a, ss.Route.get_checkpoint_summary, &timeout_hdr, req0, 10_000);
    if (g.status != .success) return error.UnexpectedStatus;
    const g_bcs = try ss.decodeBody(a, g.body);
    const g_payload = (try ss.optionPayload(g_bcs)) orelse return error.GenesisMissing;
    if (std.mem.readInt(u64, g_payload[8..16], .little) != 0) return error.WrongCheckpoint;
    rep.genesis_summary_bytes = g_payload.len;
    if (record) |r| {
        try r.print(gpa, "{{\"route\":\"{s}\"", .{ss.Route.get_checkpoint_summary});
        try hexLine(r, gpa, "request", req0);
        try hexLine(r, gpa, "response", g.body);
        try r.appendSlice(gpa, "}\n");
    }

    // 3. latest
    const reql = try ss.encodeSummaryRequest(a, .latest);
    const l = try p.request(a, ss.Route.get_checkpoint_summary, &timeout_hdr, reql, 10_000);
    if (l.status != .success) return error.UnexpectedStatus;
    const l_bcs = try ss.decodeBody(a, l.body);
    const l_payload = (try ss.optionPayload(l_bcs)) orelse return error.LatestMissing;
    rep.latest_seq = std.mem.readInt(u64, l_payload[8..16], .little);
    if (record) |r| {
        try r.print(gpa, "{{\"route\":\"{s}\"", .{ss.Route.get_checkpoint_summary});
        try hexLine(r, gpa, "request", reql);
        try hexLine(r, gpa, "response", l.body);
        try r.appendSlice(gpa, "}\n");
    }

    // 4. discovery: GetKnownPeersV2 with the unit request
    const kp_resp = try p.request(a, ss.Route.get_known_peers_v2, &timeout_hdr, ss.encodeUnitRequest(), 10_000);
    if (kp_resp.status != .success) return error.UnexpectedStatus;
    const kp_bcs = try ss.decodeBody(a, kp_resp.body);
    const kp = try @import("discovery.zig").decodeKnownPeers(a, kp_bcs, false);
    rep.known_peers = kp.peers.len;
    rep.known_peers_verified = 0;
    rep.known_peers_dialable = 0;
    for (kp.peers) |peer| {
        if (peer.verify()) rep.known_peers_verified += 1;
        for (peer.addresses) |text| if (@import("discovery.zig").parseAddress(text) != null) {
            rep.known_peers_dialable += 1;
            break;
        };
    }
    if (record) |r| {
        try r.print(gpa, "{{\"route\":\"{s}\"", .{ss.Route.get_known_peers_v2});
        try hexLine(r, gpa, "request", "");
        try hexLine(r, gpa, "response", kp_resp.body);
        try r.appendSlice(gpa, "}\n");
    }
    return rep;
}

test "live handshake and state-sync reads against our own node (ZUI_NET_LIVE=host:port)" {
    const text = @import("envutil.zig").get("ZUI_NET_LIVE") orelse return error.SkipZigTest;
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.SkipZigTest;
    const port = try std.fmt.parseInt(u16, text[colon + 1 ..], 10);
    const addr = try Io.net.IpAddress.parse(text[0..colon], port);
    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var rec: std.ArrayList(u8) = .empty;
    defer rec.deinit(std.testing.allocator);
    const r = try probe(std.testing.allocator, io, addr, &rec);
    std.debug.print(
        "\nlive: peer_id={x} handshake={d:.1}ms availability_rtt={d:.1}ms highest=epoch {d} seq {d} lowest_available={d} genesis_summary={d}B latest_seq={d} known_peers={d} verified={d} dialable={d}\n",
        .{ r.peer_id, r.handshake_ms, r.rtt_ms, r.highest_epoch, r.highest_seq, r.lowest_available, r.genesis_summary_bytes, r.latest_seq, r.known_peers, r.known_peers_verified, r.known_peers_dialable },
    );
    if (@import("envutil.zig").get("ZUI_NET_LIVE_RECORD")) |path| {
        const f = try Io.Dir.createFileAbsolute(io, path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, rec.items);
    }
}
