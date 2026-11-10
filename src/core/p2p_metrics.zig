//! sui-node's p2p (anemo) metric families, as hooks any lane's transport calls (lane
//! ops-metrics). The p2p code owns the connections; it only reports here:
//!
//!   inbound.begin/end/fail, outbound.begin/end/fail   mysten-network `NetworkMetrics`
//!       sui_{inbound,outbound}_requests{route}                   counter
//!       sui_{inbound,outbound}_inflight_requests{route}          gauge
//!       sui_{inbound,outbound}_request_latency{route}            histogram, LATENCY_SEC_BUCKETS
//!       sui_{inbound,outbound}_request_size{route}               histogram, BYTES_BUCKETS
//!       sui_{inbound,outbound}_response_size{route}              histogram, BYTES_BUCKETS
//!       sui_{inbound,outbound}_excessive_size_{requests,responses}{route}  counter (> 32 MiB)
//!       sui_{inbound,outbound}_request_errors{route,status}      counter: non-200 status
//!                                                                or `unknown` (no response)
//!   quinn.*                                              mysten-network `QuinnConnectionMetrics`
//!       sui_quinn_network_peers                                  gauge, connected peers
//!       sui_quinn_network_peer_connected{peer_id,peer_label}     gauge, known peers only
//!       sui_quinn_network_peer_disconnects{peer_id,peer_label,reason}  counter
//!       sui_quinn_network_peer_rtt{peer_id,peer_label}           gauge, ms
//!       sui_quinn_network_peer_{lost_packets,sent_packets,congestion_window}{peer_id,peer_label}
//!       sui_quinn_socket_{receive,send}_buffer_size              gauge
//!
//! "Known peers" are sui-node's: seed peers given with a peer id (`seed_peer`) and allowlisted
//! peers (`allowlisted_peer`); others count only in `sui_quinn_network_peers`.
//!
//! Cost per request: one label lookup (a short compare loop over the interned routes), a clock
//! read at each end, and relaxed atomic adds. No allocation after a route's first request.
const std = @import("std");
const prom = @import("prom.zig");
const Atomic = std.atomic.Value;
const Writer = std.Io.Writer;

/// `P2pConfig::excessive_message_size` (default 32 MiB; `p2p-config.excessive-message-size` sets it
/// at node start, before any request).
pub var excessive_message_size: usize = 32 << 20;

/// anemo statuses the error counter keeps apart; anything else is `other`.
const statuses = [_]u16{ 400, 404, 408, 429, 500, 505, 520 };
const status_names = [_][]const u8{ "400", "404", "408", "429", "500", "505", "520", "other", "unknown" };
const s_other = statuses.len;
const s_unknown = statuses.len + 1;

const Route = struct {
    requests: Atomic(u64) = .init(0),
    inflight: Atomic(i64) = .init(0),
    latency: prom.Histogram(&prom.buckets.latency_sec, prom.ns) = .{},
    request_size: prom.Histogram(&prom.buckets.bytes, prom.one) = .{},
    response_size: prom.Histogram(&prom.buckets.bytes, prom.one) = .{},
    excessive_requests: Atomic(u64) = .init(0),
    excessive_responses: Atomic(u64) = .init(0),
    errors: [status_names.len]Atomic(u64) = @splat(.init(0)),
};

pub const Network = struct {
    direction: []const u8,
    routes: prom.Labeled(Route, 64) = .{},

    pub const Call = struct { route: ?*Route, t0: u64 };

    /// A request on `route` with a body of `body_len` bytes (MetricsMakeCallbackHandler::make_handler).
    pub fn begin(n: *Network, route: []const u8, body_len: usize) Call {
        const r = n.routes.get(route) orelse return .{ .route = null, .t0 = 0 };
        _ = r.requests.fetchAdd(1, .monotonic);
        _ = r.inflight.fetchAdd(1, .monotonic);
        r.request_size.observe(body_len);
        if (body_len > excessive_message_size) _ = r.excessive_requests.fetchAdd(1, .monotonic);
        return .{ .route = r, .t0 = prom.monoNs() };
    }

    /// The response came (or was sent): its status and body size.
    pub fn end(n: *Network, c: Call, status: u16, body_len: usize) void {
        _ = n;
        const r = c.route orelse return;
        r.response_size.observe(body_len);
        if (body_len > excessive_message_size) _ = r.excessive_responses.fetchAdd(1, .monotonic);
        if (status != 200) {
            var i: usize = s_other;
            for (statuses, 0..) |s, k| if (s == status) {
                i = k;
                break;
            };
            _ = r.errors[i].fetchAdd(1, .monotonic);
        }
        done(r, c.t0);
    }

    /// No response (timeout, reset, closed connection): `on_error`, status `unknown`.
    pub fn fail(n: *Network, c: Call) void {
        _ = n;
        const r = c.route orelse return;
        _ = r.errors[s_unknown].fetchAdd(1, .monotonic);
        done(r, c.t0);
    }

    fn done(r: *Route, t0: u64) void {
        r.latency.observe(prom.monoNs() -| t0);
        _ = r.inflight.fetchSub(1, .monotonic);
    }

    pub fn render(n: *Network, w: *Writer) Writer.Error!void {
        var buf: [64]*prom.Labeled(Route, 64).Slot = undefined;
        const rs = n.routes.sorted(&buf);
        if (rs.len == 0) return;
        var nb: [96]u8 = undefined;
        var lb: [320]u8 = undefined;
        const d = n.direction;
        // families in name order, as the registry gathers them
        {
            const name = std.fmt.bufPrint(&nb, "sui_{s}_excessive_size_requests", .{d}) catch unreachable;
            try prom.head(w, name, "The number of excessively large request messages sent", "counter");
            for (rs) |s| try w.print("{s}{{route=\"{s}\"}} {d}\n", .{ name, s.name, s.v.excessive_requests.load(.monotonic) });
        }
        {
            const name = std.fmt.bufPrint(&nb, "sui_{s}_excessive_size_responses", .{d}) catch unreachable;
            try prom.head(w, name, "The number of excessively large response messages seen", "counter");
            for (rs) |s| try w.print("{s}{{route=\"{s}\"}} {d}\n", .{ name, s.name, s.v.excessive_responses.load(.monotonic) });
        }
        {
            const name = std.fmt.bufPrint(&nb, "sui_{s}_inflight_requests", .{d}) catch unreachable;
            try prom.head(w, name, "The number of inflight network requests", "gauge");
            for (rs) |s| try w.print("{s}{{route=\"{s}\"}} {d}\n", .{ name, s.name, s.v.inflight.load(.monotonic) });
        }
        {
            const name = std.fmt.bufPrint(&nb, "sui_{s}_request_errors", .{d}) catch unreachable;
            var any = false;
            for (rs) |s| for (&s.v.errors) |*e| {
                if (e.load(.monotonic) > 0) any = true;
            };
            if (any) {
                try prom.head(w, name, "Number of errors by route", "counter");
                for (rs) |s| for (&s.v.errors, 0..) |*e, i| {
                    const v = e.load(.monotonic);
                    if (v > 0) try w.print("{s}{{route=\"{s}\",status=\"{s}\"}} {d}\n", .{ name, s.name, status_names[i], v });
                };
            }
        }
        {
            const name = std.fmt.bufPrint(&nb, "sui_{s}_request_latency", .{d}) catch unreachable;
            try prom.head(w, name, "Latency of a request by route", "histogram");
            for (rs) |s| try s.v.latency.renderSeries(w, name, std.fmt.bufPrint(&lb, "route=\"{s}\"", .{s.name}) catch continue);
        }
        {
            const name = std.fmt.bufPrint(&nb, "sui_{s}_request_size", .{d}) catch unreachable;
            try prom.head(w, name, "Size of a request by route", "histogram");
            for (rs) |s| try s.v.request_size.renderSeries(w, name, std.fmt.bufPrint(&lb, "route=\"{s}\"", .{s.name}) catch continue);
        }
        {
            const name = std.fmt.bufPrint(&nb, "sui_{s}_requests", .{d}) catch unreachable;
            try prom.head(w, name, "The number of requests made on the network", "counter");
            for (rs) |s| try w.print("{s}{{route=\"{s}\"}} {d}\n", .{ name, s.name, s.v.requests.load(.monotonic) });
        }
        {
            const name = std.fmt.bufPrint(&nb, "sui_{s}_response_size", .{d}) catch unreachable;
            try prom.head(w, name, "Size of a response by route", "histogram");
            for (rs) |s| try s.v.response_size.renderSeries(w, name, std.fmt.bufPrint(&lb, "route=\"{s}\"", .{s.name}) catch continue);
        }
    }
};

pub var inbound: Network = .{ .direction = "inbound" };
pub var outbound: Network = .{ .direction = "outbound" };

/// anemo `DisconnectReason` Debug names.
pub const DisconnectReason = enum { Requested, VersionMismatch, TransportError, ConnectionClosed, ApplicationClosed, Reset, TimedOut, LocallyClosed };

const PeerStats = struct {
    id: [32]u8 = undefined,
    label: []const u8 = "",
    known: Atomic(bool) = .init(false),
    connected: Atomic(i64) = .init(0),
    disconnects: [@typeInfo(DisconnectReason).@"enum".field_names.len]Atomic(u64) = @splat(.init(0)),
    rtt_ms: Atomic(i64) = .init(0),
    lost_packets: Atomic(i64) = .init(0),
    sent_packets: Atomic(i64) = .init(0),
    cwnd: Atomic(i64) = .init(0),
    has_stats: Atomic(bool) = .init(false),
};

pub const Quinn = struct {
    /// Connected peers (`network.peers().len()`): the p2p code keeps this current.
    peers: Atomic(i64) = .init(0),
    socket_receive_buffer_size: Atomic(i64) = .init(0),
    socket_send_buffer_size: Atomic(i64) = .init(0),
    known: [max_known]PeerStats = @splat(.{}),
    n_known: Atomic(u32) = .init(0),
    lock: Atomic(u32) = .init(0),

    pub const max_known = 64;

    /// A peer sui-node would label (`seed_peer`, `allowlisted_peer`); at most 64.
    pub fn addKnown(q: *Quinn, id: *const [32]u8, label: []const u8) void {
        while (q.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
        defer q.lock.store(0, .release);
        const n = q.n_known.load(.acquire);
        for (q.known[0..n]) |*p| if (std.mem.eql(u8, &p.id, id)) return;
        if (n == max_known) return;
        q.known[n].id = id.*;
        q.known[n].label = label;
        q.known[n].known.store(true, .release);
        q.n_known.store(n + 1, .release);
    }

    fn find(q: *Quinn, id: *const [32]u8) ?*PeerStats {
        const n = q.n_known.load(.acquire);
        for (q.known[0..n]) |*p| if (std.mem.eql(u8, &p.id, id)) return p;
        return null;
    }

    pub fn connected(q: *Quinn, id: *const [32]u8) void {
        if (q.find(id)) |p| p.connected.store(1, .monotonic);
    }

    pub fn disconnected(q: *Quinn, id: *const [32]u8, reason: DisconnectReason) void {
        if (q.find(id)) |p| {
            p.connected.store(0, .monotonic);
            _ = p.disconnects[@intFromEnum(reason)].fetchAdd(1, .monotonic);
        }
    }

    /// A known peer's connection stats (`update_quinn_metrics_for_peer`, every few seconds).
    pub fn peerStats(q: *Quinn, id: *const [32]u8, rtt_ms: u64, lost_packets: u64, sent_packets: u64, cwnd: u64) void {
        const p = q.find(id) orelse return;
        p.rtt_ms.store(@intCast(@min(rtt_ms, std.math.maxInt(i64))), .monotonic);
        p.lost_packets.store(@intCast(@min(lost_packets, std.math.maxInt(i64))), .monotonic);
        p.sent_packets.store(@intCast(@min(sent_packets, std.math.maxInt(i64))), .monotonic);
        p.cwnd.store(@intCast(@min(cwnd, std.math.maxInt(i64))), .monotonic);
        p.has_stats.store(true, .monotonic);
    }

    pub fn render(q: *Quinn, w: *Writer) Writer.Error!void {
        const n = q.n_known.load(.acquire);
        const ks = q.known[0..n];
        var hex: [64]u8 = undefined;
        var any_conn = false;
        for (ks) |*p| any_conn = any_conn or p.known.load(.acquire);
        if (any_conn) {
            try prom.head(w, "sui_quinn_network_peer_connected", "The connection status of a peer. 0 if not connected, 1 if connected", "gauge");
            for (ks) |*p| try w.print("sui_quinn_network_peer_connected{{peer_id=\"{s}\",peer_label=\"{s}\"}} {d}\n", .{ hexOf(&hex, &p.id), p.label, p.connected.load(.monotonic) });
        }
        var any_disc = false;
        for (ks) |*p| for (&p.disconnects) |*d| {
            if (d.load(.monotonic) > 0) any_disc = true;
        };
        if (any_disc) {
            try prom.head(w, "sui_quinn_network_peer_disconnects", "Number of disconnect events per peer.", "counter");
            for (ks) |*p| for (&p.disconnects, 0..) |*d, i| {
                const v = d.load(.monotonic);
                if (v > 0) try w.print("sui_quinn_network_peer_disconnects{{peer_id=\"{s}\",peer_label=\"{s}\",reason=\"{s}\"}} {d}\n", .{ hexOf(&hex, &p.id), p.label, @tagName(@as(DisconnectReason, @enumFromInt(i))), v });
            };
        }
        const per = [_]struct { name: []const u8, help: []const u8, f: []const u8 }{
            .{ .name = "sui_quinn_network_peer_congestion_window", .help = "The congestion window for a peer connection.", .f = "cwnd" },
            .{ .name = "sui_quinn_network_peer_lost_packets", .help = "The total number of lost packets for a peer connection.", .f = "lost_packets" },
            .{ .name = "sui_quinn_network_peer_rtt", .help = "The rtt for a peer connection in ms.", .f = "rtt_ms" },
            .{ .name = "sui_quinn_network_peer_sent_packets", .help = "The total number of sent packets for a peer connection.", .f = "sent_packets" },
        };
        var any_stats = false;
        for (ks) |*p| any_stats = any_stats or p.has_stats.load(.monotonic);
        inline for (per) |m| if (any_stats) {
            try prom.head(w, m.name, m.help, "gauge");
            for (ks) |*p| if (p.has_stats.load(.monotonic)) try w.print("{s}{{peer_id=\"{s}\",peer_label=\"{s}\"}} {d}\n", .{ m.name, hexOf(&hex, &p.id), p.label, @field(p, m.f).load(.monotonic) });
        };
        try prom.scalar(w, "sui_quinn_network_peers", "The number of connected peers.", "gauge", q.peers.load(.monotonic));
        try prom.scalar(w, "sui_quinn_socket_receive_buffer_size", "Receive buffer size of Anemo socket.", "gauge", q.socket_receive_buffer_size.load(.monotonic));
        try prom.scalar(w, "sui_quinn_socket_send_buffer_size", "Send buffer size of Anemo socket.", "gauge", q.socket_send_buffer_size.load(.monotonic));
    }
};

fn hexOf(buf: *[64]u8, id: *const [32]u8) []const u8 {
    buf.* = std.fmt.bytesToHex(id, .lower);
    return buf;
}

pub var quinn: Quinn = .{};

/// Every p2p family (call from the node's /metrics).
pub fn render(w: *Writer) Writer.Error!void {
    try inbound.render(w);
    try outbound.render(w);
    try quinn.render(w);
}

test "network metrics: requests, errors, latency by route" {
    var n: Network = .{ .direction = "outbound" };
    const c1 = n.begin("/sui.StateSync/GetCheckpointSummary", 40);
    n.end(c1, 200, 1000);
    const c2 = n.begin("/sui.StateSync/GetCheckpointSummary", 40);
    n.end(c2, 404, 0);
    const c3 = n.begin("/sui.Discovery/GetKnownPeersV2", 0);
    n.fail(c3);
    const c4 = n.begin("/sui.Discovery/GetKnownPeersV2", 0);
    _ = c4; // in flight
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try n.render(&out.writer);
    const t = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, t, "sui_outbound_requests{route=\"/sui.StateSync/GetCheckpointSummary\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "sui_outbound_request_errors{route=\"/sui.StateSync/GetCheckpointSummary\",status=\"404\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "sui_outbound_request_errors{route=\"/sui.Discovery/GetKnownPeersV2\",status=\"unknown\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "sui_outbound_inflight_requests{route=\"/sui.Discovery/GetKnownPeersV2\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "sui_outbound_request_latency_count{route=\"/sui.StateSync/GetCheckpointSummary\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "sui_outbound_response_size_bucket{route=\"/sui.StateSync/GetCheckpointSummary\",le=\"1024\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "# TYPE sui_outbound_request_latency histogram\n") != null);
}

test "quinn metrics: peers and known peer labels" {
    var q: Quinn = .{};
    const id: [32]u8 = @splat(0xab);
    q.addKnown(&id, "seed_peer");
    q.connected(&id);
    q.peerStats(&id, 42, 1, 100, 12000);
    q.peers.store(3, .monotonic);
    q.disconnected(&id, .TimedOut);
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try q.render(&out.writer);
    const t = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, t, "\nsui_quinn_network_peers 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "sui_quinn_network_peer_rtt{peer_id=\"abababababababababababababababababababababababababababababababab\",peer_label=\"seed_peer\"} 42\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "reason=\"TimedOut\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "peer_label=\"seed_peer\"} 0\n") != null);
}
