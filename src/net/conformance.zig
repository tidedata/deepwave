//! Conformance suites of the net lane (CONTRACTS.md section 3.3). Truth comes from
//! `tools/truth/net` (Rust, anemo@68adc31 + mysten-network + snap), vectors under
//! `$ZUI_CORPUS/vectors/<suite>/`; the format is in `tools/truth/net/README.md`.
const std = @import("std");
const harness = @import("harness");
const core = @import("core");
const wire = @import("wire.zig");
const snappy = @import("snappy.zig");
const ss = @import("state_sync.zig");
const discovery = @import("discovery.zig");

pub const suites = [_]harness.Suite{
    .{ .name = "anemo-wire", .lane = "net", .doc = "anemo version/length frames and bincode request/response headers vs Rust anemo", .run = runWire },
    .{ .name = "anemo-interop", .lane = "net", .doc = "handshake + RPC round trips against a Rust anemo peer on loopback", .run = @import("interop.zig").run, .bench = @import("interop.zig").bench, .baselines = &.{
        .{ .name = "rpc-handshake", .argv = &.{ "{release}/zui-net-truth", "bench", "rpc-handshake" } },
        .{ .name = "rpc-small", .argv = &.{ "{release}/zui-net-truth", "bench", "rpc-small" } },
        .{ .name = "rpc-big", .argv = &.{ "{release}/zui-net-truth", "bench", "rpc-big" } },
    } },
    .{ .name = "sync-rpc-codec", .lane = "net", .doc = "snappy framing and state-sync BCS+snappy messages vs Rust snap/mysten-network", .run = runSync, .bench = benchSync, .baselines = &.{
        .{ .name = "snappy-compress", .argv = &.{ "{release}/zui-net-truth", "bench", "snappy-compress" } },
        .{ .name = "snappy-decompress", .argv = &.{ "{release}/zui-net-truth", "bench", "snappy-decompress" } },
    } },
};

fn readVectors(ctx: *harness.Ctx, sub: []const u8) ![]u8 {
    return ctx.corpus.readFileAlloc(ctx.io, sub, ctx.gpa, .limited(1 << 30));
}

fn hexBytes(a: std.mem.Allocator, text: []const u8) ![]u8 {
    return core.hex.decodeAlloc(a, text);
}

// ---------------------------------------------------------------- anemo-wire

const Pair = [2][]const u8;
const WireVec = struct {
    id: []const u8,
    kind: []const u8,
    hex: []const u8 = "",
    payload_hex: []const u8 = "",
    header_hex: []const u8 = "",
    body_hex: []const u8 = "",
    route: []const u8 = "",
    status: u16 = 0,
    headers: []const Pair = &.{},
    ordered: bool = true,
};

fn sortedHeaders(a: std.mem.Allocator, hs: []const wire.Header) ![]wire.Header {
    const out = try a.dupe(wire.Header, hs);
    std.mem.sort(wire.Header, out, {}, struct {
        fn lt(_: void, x: wire.Header, y: wire.Header) bool {
            return std.mem.lessThan(u8, x.name, y.name);
        }
    }.lt);
    return out;
}

fn headersEqual(c: *harness.Check, a: std.mem.Allocator, expect: []const Pair, got: []const wire.Header) void {
    const sorted = sortedHeaders(a, got) catch {
        c.failf("oom", .{});
        return;
    };
    if (sorted.len != expect.len) {
        c.failf("header count: expected {d} got {d}", .{ expect.len, sorted.len });
        return;
    }
    for (expect, sorted) |e, g| {
        c.text("header name", e[0], g.name);
        c.text("header value", e[1], g.value);
    }
}

fn runWire(ctx: *harness.Ctx) !void {
    const text = try readVectors(ctx, "vectors/anemo-wire/vectors.jsonl");
    defer ctx.gpa.free(text);
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) break;
        ctx.nextItem();
        const a = ctx.scratch();
        const v = std.json.parseFromSliceLeaky(WireVec, a, line, .{ .ignore_unknown_fields = true }) catch |e| {
            ctx.fail("?", "vector parse: {s}", .{@errorName(e)});
            continue;
        };
        if (!ctx.selected(v.id)) continue;
        var c = ctx.check(v.id);
        const expect = try hexBytes(a, v.hex);
        if (std.mem.eql(u8, v.kind, "version")) {
            c.bytes("version frame", expect, &wire.version_frame);
            wire.checkVersionFrame(expect[0..8]) catch c.failf("version frame rejected", .{});
        } else if (std.mem.eql(u8, v.kind, "frame")) {
            const payload = try hexBytes(a, v.payload_hex);
            var b: wire.Builder = .{};
            try b.appendFrame(a, payload);
            c.bytes("frame bytes", expect, b.list.items);
            var pos: usize = 0;
            const got = wire.nextFrame(expect, &pos, wire.default_max_frame + (1 << 20)) catch null;
            if (got) |g| c.bytes("frame payload", payload, g) else c.failf("frame decode failed", .{});
            c.eql("consumed", expect.len, pos);
            // every strict prefix is incomplete
            if (expect.len <= 70000) for (0..expect.len) |n| {
                var p2: usize = 0;
                const r = wire.nextFrame(expect[0..n], &p2, 1 << 30) catch {
                    c.failf("prefix {d} errored", .{n});
                    break;
                };
                if (r != null) {
                    c.failf("prefix {d} produced a frame", .{n});
                    break;
                }
            };
        } else if (std.mem.eql(u8, v.kind, "request")) {
            const body = try hexBytes(a, v.body_hex);
            if (v.ordered) {
                const hs = try a.alloc(wire.Header, v.headers.len);
                for (v.headers, hs) |p, *h| h.* = .{ .name = p[0], .value = p[1] };
                const enc = try wire.encodeRequest(a, v.route, hs, body);
                c.bytes("request stream", expect, enc);
            }
            if (wire.parseRequest(a, expect, wire.default_max_frame + (1 << 20))) |pr| {
                if (pr) |r| {
                    c.text("route", v.route, r.route);
                    c.bytes("body", body, r.body);
                    headersEqual(&c, a, v.headers, r.headers);
                } else c.failf("parseRequest: incomplete", .{});
            } else |e| c.failf("parseRequest: {s}", .{@errorName(e)});
        } else if (std.mem.eql(u8, v.kind, "response")) {
            const body = try hexBytes(a, v.body_hex);
            const status = wire.Status.fromU16(v.status).?;
            if (v.ordered) {
                const hs = try a.alloc(wire.Header, v.headers.len);
                for (v.headers, hs) |p, *h| h.* = .{ .name = p[0], .value = p[1] };
                const enc = try wire.encodeResponse(a, status, hs, body);
                c.bytes("response stream", expect, enc);
            }
            if (wire.parseResponse(a, expect, wire.default_max_frame + (1 << 20))) |pr| {
                if (pr) |r| {
                    c.eql("status", status, r.status);
                    c.bytes("body", body, r.body);
                    headersEqual(&c, a, v.headers, r.headers);
                } else c.failf("parseResponse: incomplete", .{});
            } else |e| c.failf("parseResponse: {s}", .{@errorName(e)});
        } else c.failf("unknown kind {s}", .{v.kind});
        _ = c.finish();
    }
}

// ---------------------------------------------------------------- sync-rpc-codec

const SnapVec = struct { id: []const u8, raw_len: usize, raw_hex: []const u8, framed_hex: []const u8, block_hex: []const u8 };

fn runSnappy(ctx: *harness.Ctx) !void {
    const text = try readVectors(ctx, "vectors/sync-rpc-codec/snappy.jsonl");
    defer ctx.gpa.free(text);
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) break;
        ctx.nextItem();
        const a = ctx.scratch();
        const v = try std.json.parseFromSliceLeaky(SnapVec, a, line, .{ .ignore_unknown_fields = true });
        var id_buf: [96]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "snappy/{s}", .{v.id}) catch v.id;
        if (!ctx.selected(id)) continue;
        var c = ctx.check(id);
        const raw = try hexBytes(a, v.raw_hex);
        const framed = try hexBytes(a, v.framed_hex);
        const block = try hexBytes(a, v.block_hex);
        c.bytes("compressFrame", framed, try snappy.compressFrame(a, raw));
        if (snappy.decompressFrame(a, framed, 1 << 30)) |d| c.bytes("decompressFrame", raw, d) else |e| c.failf("decompressFrame: {s}", .{@errorName(e)});
        const out = try a.alloc(u8, snappy.maxCompressedLen(raw.len));
        const n = snappy.compressBlock(raw, out);
        c.bytes("compressBlock", block, out[0..n]);
        const back = try a.alloc(u8, raw.len);
        if (snappy.blockLen(block)) |bl| {
            c.eql("blockLen", raw.len, bl);
            if (snappy.decompressBlock(block, back)) c.bytes("decompressBlock", raw, back) else |e| c.failf("decompressBlock: {s}", .{@errorName(e)});
        } else |e| c.failf("blockLen: {s}", .{@errorName(e)});
        _ = c.finish();
    }
}

const SyncVec = struct { id: []const u8, kind: []const u8, route: []const u8, bcs_hex: []const u8, snappy_hex: []const u8 };

fn encodeRequestFor(a: std.mem.Allocator, v: SyncVec, bcs: []const u8) !?[]u8 {
    if (std.mem.eql(u8, v.kind, "GetCheckpointSummaryRequest")) {
        const id: ss.CheckpointId = switch (bcs[0]) {
            0 => .latest,
            1 => .{ .digest = bcs[2..34].* },
            2 => .{ .seq = std.mem.readInt(u64, bcs[1..9], .little) },
            else => return null,
        };
        return try ss.encodeSummaryRequest(a, id);
    } else if (std.mem.eql(u8, v.kind, "CheckpointContentsDigest")) {
        return try ss.encodeDigestRequest(a, bcs[1..33].*);
    } else if (std.mem.eql(u8, v.kind, "u64")) {
        return try ss.encodeSeqRequest(a, std.mem.readInt(u64, bcs[0..8], .little));
    } else if (std.mem.eql(u8, v.kind, "GetCheckpointTransactionsRequest")) {
        return try ss.encodeTransactionsRequest(a, .{
            .sequence_number = std.mem.readInt(u64, bcs[0..8], .little),
            .start = std.mem.readInt(u64, bcs[8..16], .little),
            .end = std.mem.readInt(u64, bcs[16..24], .little),
        });
    } else if (std.mem.eql(u8, v.kind, "unit")) {
        return try a.dupe(u8, ss.encodeUnitRequest());
    }
    return null;
}

fn runSyncVectors(ctx: *harness.Ctx) !void {
    const text = try readVectors(ctx, "vectors/sync-rpc-codec/sync.jsonl");
    defer ctx.gpa.free(text);
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) break;
        ctx.nextItem();
        const a = ctx.scratch();
        const v = try std.json.parseFromSliceLeaky(SyncVec, a, line, .{ .ignore_unknown_fields = true });
        if (!ctx.selected(v.id)) continue;
        var c = ctx.check(v.id);
        const bcs = try hexBytes(a, v.bcs_hex);
        const snap = try hexBytes(a, v.snappy_hex);
        // decode direction: snappy -> BCS
        if (ss.decodeBody(a, snap)) |d| c.bytes("decodeBody", bcs, d) else |e| c.failf("decodeBody: {s}", .{@errorName(e)});
        // encode direction: structured request -> snappy bytes; responses re-compressed as one write
        if (std.mem.startsWith(u8, v.id, "req/")) {
            if (try encodeRequestFor(a, v, bcs)) |enc| c.bytes("request encode", snap, enc) else c.failf("unhandled request kind {s}", .{v.kind});
        } else {
            c.bytes("compressFrame", snap, try snappy.compressFrame(a, bcs));
            if (std.mem.eql(u8, v.kind, "Option<CertifiedCheckpointSummary>")) {
                const o = ss.optionPayload(bcs) catch null;
                if (std.mem.endsWith(u8, v.id, "/none")) {
                    c.eql("none", true, o == null);
                } else if (o) |p| c.eql("some payload", bcs.len - 1, p.len) else c.failf("expected Some", .{});
            } else if (std.mem.eql(u8, v.kind, "GetCheckpointAvailabilityResponse")) {
                const av = ss.splitAvailability(bcs) catch {
                    c.failf("splitAvailability", .{});
                    _ = c.finish();
                    continue;
                };
                c.eql("lowest", (std.fmt.parseInt(u64, v.id[std.mem.lastIndexOfScalar(u8, v.id, '/').? + 1 ..], 10) catch 0) / 2, av.lowest_available_checkpoint);
                c.eql("summary len", bcs.len - 8, av.highest_synced_summary.len);
            }
        }
        _ = c.finish();
    }
}

const LiveVec = struct { route: []const u8, request: []const u8, response: []const u8 };

/// Exchanges recorded from our own sui-node (`src/net/live.zig`): `vectors/sync-rpc-codec/live-*.jsonl`.
/// The responses are Rust snap/BCS output of the production node, so re-compressing the decoded
/// BCS must reproduce them byte for byte, and our requests must equal the ones the probe sent.
fn runLive(ctx: *harness.Ctx) !void {
    var dir = ctx.corpus.openDir(ctx.io, "vectors/sync-rpc-codec", .{ .iterate = true }) catch return;
    defer dir.close(ctx.io);
    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |n| ctx.gpa.free(n);
        names.deinit(ctx.gpa);
    }
    var it = dir.iterate();
    while (try it.next(ctx.io)) |e| {
        if (std.mem.startsWith(u8, e.name, "live-") and std.mem.endsWith(u8, e.name, ".jsonl")) try names.append(ctx.gpa, try ctx.gpa.dupe(u8, e.name));
    }
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    for (names.items) |name| {
        const path = try std.fmt.allocPrint(ctx.gpa, "vectors/sync-rpc-codec/{s}", .{name});
        defer ctx.gpa.free(path);
        const text = try ctx.corpus.readFileAlloc(ctx.io, path, ctx.gpa, .limited(1 << 28));
        defer ctx.gpa.free(text);
        var lines_it = harness.lines(text);
        var n: usize = 0;
        while (lines_it.next()) |line| : (n += 1) {
            ctx.nextItem();
            const a = ctx.scratch();
            const v = try std.json.parseFromSliceLeaky(LiveVec, a, line, .{ .ignore_unknown_fields = true });
            var id_buf: [160]u8 = undefined;
            const id = std.fmt.bufPrint(&id_buf, "live/{s}/{d}", .{ name, n }) catch name;
            if (!ctx.selected(id)) continue;
            var c = ctx.check(id);
            const resp = try hexBytes(a, v.response);
            const req = try hexBytes(a, v.request);
            if (ss.decodeBody(a, resp)) |bcs| {
                c.bytes("recompress(decompress(response))", resp, try snappy.compressFrame(a, bcs));
                if (std.mem.eql(u8, v.route, ss.Route.get_known_peers_v2)) {
                    if (discovery.decodeKnownPeers(a, bcs, false)) |kp| {
                        c.eql("own_info signature", true, kp.own.verify());
                        var bad: usize = 0;
                        for (kp.peers) |peer| {
                            if (!peer.verify()) bad += 1;
                        }
                        c.eql("known peers with bad signature", @as(usize, 0), bad);
                    } else |e| c.failf("decodeKnownPeers: {s}", .{@errorName(e)});
                } else if (std.mem.eql(u8, v.route, ss.Route.get_checkpoint_availability)) {
                    if (ss.splitAvailability(bcs)) |av| {
                        c.eql("availability: epoch 1304 summary", true, av.highest_synced_summary.len > 16);
                        c.eql("availability: lowest <= highest", true, av.lowest_available_checkpoint <= std.mem.readInt(u64, av.highest_synced_summary[8..16], .little));
                    } else |e| c.failf("splitAvailability: {s}", .{@errorName(e)});
                } else if (ss.optionPayload(bcs)) |o| {
                    if (o) |payload| c.eql("summary has epoch+seq", true, payload.len > 16) else c.failf("summary None", .{});
                } else |e| c.failf("optionPayload: {s}", .{@errorName(e)});
            } else |e| c.failf("decodeBody: {s}", .{@errorName(e)});
            // requests must be what deepwave encodes for the same question
            if (req.len == 0) {
                c.bytes("unit request", ss.encodeUnitRequest(), req);
            } else if (ss.decodeBody(a, req)) |rb| {
                if (rb.len == 9 and rb[0] == 2) c.bytes("seq request", req, try ss.encodeSummaryRequest(a, .{ .seq = std.mem.readInt(u64, rb[1..9], .little) })) else if (rb.len == 1 and rb[0] == 0) c.bytes("latest request", req, try ss.encodeSummaryRequest(a, .latest)) else c.failf("unexpected request", .{});
            } else |e| c.failf("request decode: {s}", .{@errorName(e)});
            _ = c.finish();
        }
    }
}

const DiscPeer = struct {
    peer_id: []const u8,
    addresses: []const []const u8 = &.{},
    p2p_addresses: []const []const u8 = &.{},
    timestamp_ms: u64,
    access: []const u8 = "",
    version: u8 = 1,
    signature_valid: bool,
    sig: []const u8,
};
const DiscVec = struct { id: []const u8, kind: []const u8, bcs_hex: []const u8, snappy_hex: []const u8, peers: []const DiscPeer = &.{} };

fn runDiscovery(ctx: *harness.Ctx) !void {
    const text = try readVectors(ctx, "vectors/sync-rpc-codec/discovery.jsonl");
    defer ctx.gpa.free(text);
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) break;
        ctx.nextItem();
        const a = ctx.scratch();
        const v = try std.json.parseFromSliceLeaky(DiscVec, a, line, .{ .ignore_unknown_fields = true });
        var id_buf: [96]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "discovery/{s}", .{v.id}) catch v.id;
        if (!ctx.selected(id)) continue;
        var c = ctx.check(id);
        const bcs = try hexBytes(a, v.bcs_hex);
        const snap = try hexBytes(a, v.snappy_hex);
        if (ss.decodeBody(a, snap)) |d| c.bytes("decodeBody", bcs, d) else |e| c.failf("decodeBody: {s}", .{@errorName(e)});
        c.bytes("compressFrame", snap, try snappy.compressFrame(a, bcs));
        if (std.mem.eql(u8, v.kind, "GetKnownPeersRequestV3")) {
            // the request holds one signed versioned info: decode it as a response with no peers
            var framed: std.ArrayList(u8) = .empty;
            try framed.appendSlice(a, bcs);
            try framed.append(a, 0);
            if (discovery.decodeKnownPeers(a, framed.items, true)) |kp| {
                c.eql("own signature", true, kp.own.verify());
            } else |e| c.failf("decode request: {s}", .{@errorName(e)});
            _ = c.finish();
            continue;
        }
        const versioned = std.mem.eql(u8, v.kind, "GetKnownPeersResponseV3");
        if (discovery.decodeKnownPeers(a, bcs, versioned)) |kp| {
            // expected order in `peers`: known peers first, then own_info last
            c.eql("peer count", v.peers.len, kp.peers.len + 1);
            if (v.peers.len == kp.peers.len + 1) {
                for (v.peers, 0..) |ep, i| {
                    const got = if (i < kp.peers.len) kp.peers[i] else kp.own;
                    c.text("peer_id", ep.peer_id, &std.fmt.bytesToHex(got.peer_id, .lower));
                    c.eql("timestamp_ms", ep.timestamp_ms, got.timestamp_ms);
                    c.eql("signature valid", ep.signature_valid, got.verify());
                    c.eql("version", ep.version, got.version);
                    const want_addrs = if (versioned) ep.p2p_addresses else ep.addresses;
                    c.eql("address count", want_addrs.len, got.addresses.len);
                    if (want_addrs.len == got.addresses.len) for (want_addrs, got.addresses) |w, g| {
                        c.text("address", w, g);
                        c.eql("address dialable", true, discovery.parseAddress(g) != null);
                    };
                    c.text("signature", ep.sig, &std.fmt.bytesToHex(got.signature, .lower));
                }
            }
        } else |e| c.failf("decodeKnownPeers: {s}", .{@errorName(e)});
        _ = c.finish();
    }
}

fn runSync(ctx: *harness.Ctx) !void {
    try runSnappy(ctx);
    try runSyncVectors(ctx);
    try runDiscovery(ctx);
    try runLive(ctx);
}

const SnapBench = struct {
    blobs: []const []const u8,
    comp: []const []const u8,
    arena: *std.heap.ArenaAllocator,
    sink: *usize,
};

fn benchCompress(st: *const SnapBench) anyerror!void {
    for (st.blobs) |b| {
        _ = st.arena.reset(.retain_capacity);
        const out = try snappy.compressFrame(st.arena.allocator(), b);
        st.sink.* +%= out.len;
    }
}

fn benchDecompress(st: *const SnapBench) anyerror!void {
    for (st.comp) |c| {
        _ = st.arena.reset(.retain_capacity);
        const out = try snappy.decompressFrame(st.arena.allocator(), c, 1 << 30);
        st.sink.* +%= out.len;
    }
}

fn benchSync(ctx: *harness.Ctx) !void {
    var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const names = ctx.benchInputs();
    const blobs = try a.alloc([]const u8, names.len);
    const comp = try a.alloc([]const u8, names.len);
    var total: u64 = 0;
    for (names, blobs) |n, *b| {
        b.* = try ctx.corpus.readFileAlloc(ctx.io, n, a, .limited(1 << 30));
        total += b.len;
    }
    for (blobs, comp) |b, *c| c.* = try snappy.compressFrame(a, b);
    var work = std.heap.ArenaAllocator.init(ctx.gpa);
    defer work.deinit();
    var sink: usize = 0;
    const st: SnapBench = .{ .blobs = blobs, .comp = comp, .arena = &work, .sink = &sink };
    try ctx.benchPasses("snappy-compress", "byte", total, &st, benchCompress);
    try ctx.benchPasses("snappy-decompress", "byte", total, &st, benchDecompress);
    std.mem.doNotOptimizeAway(sink);
}
