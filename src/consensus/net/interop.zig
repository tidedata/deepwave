//! Interop with Mysten's own consensus network stack at mainnet-v1.83.1 (val-audit net): a deepwave
//! ConsensusService server (authority 0) and deepwave client against consensus-core's TonicManager,
//! TonicValidatorClient and sui-tls (authority 1), over loopback TLS 1.3 + HTTP/2 + gRPC + zstd.
//!
//! The Rust side is the test `network::zui_interop::zui_interop` that
//! tools/truth/consensus-net/interop/run.sh drops into a scratch worktree of the sui checkout and
//! builds; the test below runs it as a child process when ZUI_CONSENSUS_INTEROP_BIN names that
//! test binary and ZUI_CONSENSUS_INTEROP_DIR an empty exchange directory (otherwise it skips).
//! Exchange: deepwave writes `zui.txt` (port, epoch, network key seeds, our certificate, block refs),
//! Rust writes `rust_ready` (its port and rcgen certificate) once its server listens, deepwave writes
//! `zig_done` after its client calls; Rust checks the requests it decoded and exits 0 on success.
//! Generated keys only.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const types = consensus.types;
const bcs = @import("bcs");
const net = @import("net");
const grpc = @import("grpc.zig");
const proto = @import("proto.zig");
const tls = @import("tls.zig");
const bc = @import("broadcast.zig");
const testkit = @import("testkit.zig");
const service = @import("service.zig");
const rounds_mod = @import("rounds.zig");

fn hex(a: Allocator, b: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{x}", .{b});
}

fn unhex(a: Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    return std.fmt.hexToBytes(out, s);
}

const Sink = struct {
    fn submit(ctx: *anyopaque, peer: types.AuthorityIndex, serialized: []const u8, excluded: []const types.BlockRef) bool {
        _ = .{ ctx, peer, serialized, excluded };
        return true;
    }
};

fn writeFile(io: Io, dir: Io.Dir, name: []const u8, text: []const u8) !void {
    var tmp_buf: [64]u8 = undefined;
    const tmp = try std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{name});
    try dir.writeFile(io, .{ .sub_path = tmp, .data = text });
    try dir.rename(tmp, dir, name, io);
}

test "tonic interop: Mysten consensus-core client and server against zui" {
    const env = net.envutil;
    const bin = env.get("ZUI_CONSENSUS_INTEROP_BIN") orelse return;
    const dir_path = env.get("ZUI_CONSENSUS_INTEROP_DIR") orelse return;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var dir = try Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);

    // The deepwave side: authority 0 of a 4-authority committee, epoch 5, with the fixture of the
    // service test (3 rounds of 4 authorities, commit 1 certified, commit 2 not).
    const epoch: types.Epoch = 5;
    const tc = try testkit.TestCommittee.init(gpa, io, 4, 7, 0, epoch);
    defer tc.deinit();
    var rc: testkit.RealClock = .{ .io = io };
    var ctx = testkit.makeContext(tc, 0, rc.clock());
    ctx.parameters.min_round_delay_ns = 2 * std.time.ns_per_ms;
    var fs = testkit.FakeStore.init(gpa, io);
    defer fs.deinit();
    var refs: [4][4]types.BlockRef = undefined;
    for (0..4) |a| refs[0][a] = .{ .round = 0, .author = @intCast(a), .digest = @splat(0) };
    var keep: std.ArrayList([]u8) = .empty;
    defer {
        for (keep.items) |k| gpa.free(k);
        keep.deinit(gpa);
    }
    for (1..4) |r| for (0..4) |a| {
        const b = try testkit.buildBlock(gpa, .{ .epoch = epoch, .round = @intCast(r), .author = @intCast(a), .timestamp_ms = 1000 + r, .ancestors = &refs[r - 1], .sign_seed = tc.protocol_seeds[a] });
        try keep.append(gpa, b.bytes);
        try fs.addBlock(b.bytes, b.ref);
        refs[r][a] = b.ref;
    };
    const c1 = try testkit.buildCommit(gpa, 1, @splat(0), refs[1][0], &.{refs[1][0]});
    const c2 = try testkit.buildCommit(gpa, 2, c1.digest, refs[2][0], &.{refs[2][0]});
    defer gpa.free(c1.bytes);
    defer gpa.free(c2.bytes);
    try fs.addCommit(1, c1.digest, c1.bytes, &.{ refs[3][0], refs[3][1], refs[3][2] });
    try fs.addCommit(2, c2.digest, c2.bytes, &.{ refs[3][0], refs[3][1] });

    var bcast = try bc.Broadcaster.init(gpa, io, 16);
    defer bcast.deinit();
    var rt = try rounds_mod.RoundTracker.init(gpa, io, &ctx.committee, 0);
    defer rt.deinit();
    var published = try service.Published.init(gpa, 4);
    defer published.deinit();
    published.publish(&.{ 3, 3, 3, 3 }, 3, 2);
    var stats: service.Stats = .{};
    var stopping: std.atomic.Value(bool) = .init(false);
    var sink: u8 = 0;
    var h = service.Handlers.init(gpa, io, &ctx, fs.store(), &bcast, &rt, &published, .{ .ctx = &sink, .submit = Sink.submit }, &stats, &stopping);

    var name_buf: [40]u8 = undefined;
    const name = try tls.serverName(&name_buf, epoch);
    const id0 = try tls.Identity.init(&tc.network_seeds[0], name);
    const Peers = struct {
        keys: [4][32]u8,
        fn lookup(c: *anyopaque, key: *const [32]u8) ?u32 {
            const self: *@This() = @ptrCast(@alignCast(c));
            for (self.keys, 0..) |k, i| if (std.mem.eql(u8, &k, key)) return @intCast(i);
            return null;
        }
    };
    var peers: Peers = .{ .keys = undefined };
    for (0..4) |i| peers.keys[i] = tc.authorities[i].network_key;
    const srv = try grpc.Server.start(gpa, io, .{ .server_name = name, .identity = &id0, .check = .{ .ctx = &peers, .lookup = Peers.lookup }, .handler = h.grpcHandler() });
    defer {
        stopping.store(true, .release);
        srv.stop();
    }

    // zui.txt
    {
        var t: std.ArrayList(u8) = .empty;
        const w = struct {
            fn line(a: Allocator, l: *std.ArrayList(u8), comptime f: []const u8, args: anytype) !void {
                const s = try std.fmt.allocPrint(a, f, args);
                try l.appendSlice(a, s);
            }
        }.line;
        try w(arena, &t, "port {d}\nepoch {d}\nseeds", .{ srv.port, epoch });
        for (0..4) |i| try w(arena, &t, " {s}", .{try hex(arena, &tc.network_seeds[i])});
        try w(arena, &t, "\nzui_cert {s}\nrefs", .{try hex(arena, id0.certDer())});
        for (0..3) |a| try w(arena, &t, " {s}", .{try hex(arena, &bc.encodeRef(refs[2][a]))});
        try w(arena, &t, "\nlive_ref {s}\n", .{try hex(arena, &bc.encodeRef(refs[3][0]))});
        dir.deleteFile(io, "rust_ready") catch {};
        dir.deleteFile(io, "zig_done") catch {};
        try writeFile(io, dir, "zui.txt", t.items);
    }

    const log_file = try dir.createFile(io, "rust.log", .{});
    defer log_file.close(io);
    var child = try std.process.spawn(io, .{
        .argv = &.{ bin, "network::zui_interop::zui_interop", "--exact", "--nocapture", "--test-threads=1" },
        .cwd = .{ .path = dir_path },
        .stdin = .ignore,
        .stdout = .{ .file = log_file },
        .stderr = .{ .file = log_file },
    });
    var waited = false;
    defer if (!waited) {
        child.kill(io);
    };

    // Wait for the Rust server.
    var ready: []u8 = &.{};
    var tries: usize = 0;
    while (tries < 1200) : (tries += 1) {
        if (dir.readFileAlloc(io, "rust_ready", arena, .limited(1 << 16))) |r| {
            ready = r;
            break;
        } else |_| {}
        try Io.sleep(io, .fromMilliseconds(50), .awake);
    }
    if (ready.len == 0) return error.RustPeerDidNotStart;
    var rust_port: u16 = 0;
    var rust_cert: []u8 = &.{};
    var lines = std.mem.tokenizeScalar(u8, ready, '\n');
    while (lines.next()) |l| {
        var it = std.mem.tokenizeScalar(u8, l, ' ');
        const k = it.next() orelse continue;
        const v = it.next() orelse continue;
        if (std.mem.eql(u8, k, "port")) rust_port = try std.fmt.parseInt(u16, v, 10);
        if (std.mem.eql(u8, k, "rust_cert")) rust_cert = try unhex(arena, v);
    }

    const ok = clientSide(arena, io, tc, name, &id0, rust_port, rust_cert);
    try writeFile(io, dir, "zig_done", if (ok) |_| "ok\n" else |e| try std.fmt.allocPrint(arena, "fail {s}\n", .{@errorName(e)}));
    const term = try child.wait(io);
    waited = true;
    if (!term.success()) {
        const log = dir.readFileAlloc(io, "rust.log", arena, .limited(1 << 20)) catch "";
        const tail = log[log.len -| 6000..];
        std.debug.print("Rust side failed ({any}):\n{s}\n", .{ term, tail });
    }
    try ok;
    try std.testing.expect(term.success());
}

/// deepwave's client (authority 0) against Mysten's TonicManager server (authority 1) and its
/// recording mock service; the Rust side checks what it decoded.
fn clientSide(arena: Allocator, io: Io, tc: *const testkit.TestCommittee, name: []const u8, id0: *const tls.Identity, port: u16, rust_cert: []const u8) !void {
    const gpa = std.testing.allocator;
    const pub1 = tc.authorities[1].network_key;
    // rcgen's certificate for authority 1's key passes deepwave's verifier in both roles.
    const now: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).toNanoseconds(), std.time.ns_per_s));
    const as_server = try net.x509.verifyPeerCert(rust_cert, name, .server, now);
    const as_client = try net.x509.verifyPeerCert(rust_cert, name, .client, now);
    try std.testing.expectEqualSlices(u8, &pub1, &as_server.public_key);
    try std.testing.expectEqualSlices(u8, &pub1, &as_client.public_key);
    try std.testing.expectError(error.NameMismatch, net.x509.verifyPeerCert(rust_cert, "consensus_epoch_999", .server, now));

    const ch = try grpc.Channel.create(gpa, io, .{}, .{ .host = "127.0.0.1", .port = port }, name, id0, &pub1);
    defer ch.destroy();
    const T = 10 * std.time.ns_per_s;

    // GetLatestRounds
    {
        const r = try proto.decode(proto.GetLatestRoundsResponse, arena, try ch.unary(arena, .GetLatestRounds, "", T));
        try std.testing.expectEqualSlices(u32, &.{ 1, 2, 3, 4 }, r.highest_received);
        try std.testing.expectEqualSlices(u32, &.{ 5, 6, 7, 8 }, r.highest_accepted);
    }
    // FetchBlocks (live-sync shape): the mock returns a Mysten TestBlock per requested ref.
    {
        const ref: types.BlockRef = .{ .round = 5, .author = 2, .digest = @splat(7) };
        const rb = bc.encodeRef(ref);
        const req = try proto.encode(proto.FetchBlocksRequest, arena, &.{ .block_refs = &.{&rb}, .fetch_after_rounds = &.{ 1, 2, 3, 4 }, .fetch_missing_ancestors = true });
        const st = try ch.startCall(.FetchBlocks, T);
        defer st.release();
        try st.send(req);
        try st.closeSend();
        var got: usize = 0;
        while (try st.recv(arena, 0)) |m| {
            for ((try proto.decode(proto.FetchBlocksResponse, arena, m)).blocks) |b| {
                const vb = try testkit.decodeBlock(arena, b);
                try std.testing.expectEqual(@as(types.Round, 5), vb.block.inner.round());
                try std.testing.expectEqual(@as(types.AuthorityIndex, 2), vb.block.inner.author());
                got += 1;
            }
        }
        try std.testing.expectEqual(@as(usize, 1), got);
    }
    // FetchCommits 3..=7: the mock answers commits 3 and 4 and three certifier blocks.
    {
        const req = try proto.encode(proto.FetchCommitsRequest, arena, &.{ .start = 3, .end = 7 });
        const r = try proto.decode(proto.FetchCommitsResponse, arena, try ch.unary(arena, .FetchCommits, req, T));
        try std.testing.expectEqual(@as(usize, 2), r.commits.len);
        try std.testing.expectEqual(@as(usize, 3), r.certifier_blocks.len);
        const c = try bcs.decode(types.Commit, arena, r.commits[0]);
        try std.testing.expectEqual(@as(types.CommitIndex, 3), c.index());
        for (r.certifier_blocks) |b| _ = try testkit.decodeBlock(arena, b);
    }
    // FetchLatestBlocks [0, 2]
    {
        const req = try proto.encode(proto.FetchLatestBlocksRequest, arena, &.{ .authorities = &.{ 0, 2 } });
        const st = try ch.startCall(.FetchLatestBlocks, T);
        defer st.release();
        try st.send(req);
        try st.closeSend();
        var authors: std.ArrayList(u32) = .empty;
        while (try st.recv(arena, 0)) |m| {
            for ((try proto.decode(proto.FetchLatestBlocksResponse, arena, m)).blocks) |b| try authors.append(arena, (try testkit.decodeBlock(arena, b)).block.inner.author());
        }
        try std.testing.expectEqualSlices(u32, &.{ 0, 2 }, authors.items);
    }
    // FetchLatestBlocks with an invalid authority: tonic answers INTERNAL (trailers-only).
    {
        const req = try proto.encode(proto.FetchLatestBlocksRequest, arena, &.{ .authorities = &.{99} });
        const st = try ch.startCall(.FetchLatestBlocks, T);
        defer st.release();
        try st.send(req);
        try st.closeSend();
        try std.testing.expectError(error.Status, st.recv(arena, 0));
        try std.testing.expectEqual(grpc.Status.internal, st.grpcStatus());
    }
    // SubscribeBlocks after round 9: rounds 10, 11, 12 of authority 1, each excluding (r-1, 3).
    {
        const st = try ch.startCall(.SubscribeBlocks, 0);
        defer st.release();
        try st.send(try proto.encode(proto.SubscribeBlocksRequest, arena, &.{ .last_received_round = 9 }));
        for ([_]types.Round{ 10, 11, 12 }) |round| {
            const m = (try st.recv(arena, T)) orelse return error.SubscriptionEnded;
            const sb = try proto.decode(proto.SubscribeBlocksResponse, arena, m);
            const vb = try testkit.decodeBlock(arena, sb.block);
            try std.testing.expectEqual(round, vb.block.inner.round());
            try std.testing.expectEqual(@as(types.AuthorityIndex, 1), vb.block.inner.author());
            try std.testing.expectEqual(@as(usize, 1), sb.excluded_ancestors.len);
            const ex = bc.decodeRef(sb.excluded_ancestors[0]) orelse return error.BadExcludedRef;
            try std.testing.expect(ex.eql(.{ .round = round - 1, .author = 3, .digest = @splat(0) }));
        }
        st.cancel();
    }
    // SendBlock
    {
        const req = try proto.encode(proto.SendBlockRequest, arena, &.{ .block = "hello zui" });
        _ = try ch.unary(arena, .SendBlock, req, T);
    }
}
