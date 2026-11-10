//! Suite `anemo-interop`: deepwave's anemo client against a Rust anemo peer (tools/truth/net `peer`,
//! the very anemo and rustls/quinn that sui-node runs) on loopback. Every item is a real QUIC +
//! TLS 1.3 mutual-auth handshake and RPC exchange; responses are compared byte for byte and the
//! requests are compared with what the Rust side logged after decoding them.
const std = @import("std");
const harness = @import("harness");
const core = @import("core");
const Io = std.Io;
const anemo = @import("anemo.zig");
const wire = @import("wire.zig");
const ss = @import("state_sync.zig");
const snappy = @import("snappy.zig");


const Rust = struct {
    child: std.process.Child,
    port: u16,
    peer_id: [32]u8,
    log_path: []const u8,

    fn stop(r: *Rust, io: Io) void {
        r.child.kill(io);
    }
};

const envutil = @import("envutil.zig");

/// The shared cargo target dir (tools/env.sh): $ZUI_CARGO_TARGET, else ~/.cache/zui/target-swarm.
/// Without libc there is no environment handle; the default corpus location gives $HOME.
fn truthBinary(a: std.mem.Allocator, corpus_path: []const u8) ![]const u8 {
    if (envutil.get("ZUI_CARGO_TARGET")) |t| return std.fmt.allocPrint(a, "{s}/release/zui-net-truth", .{t});
    const suffix = "/zui-corpus";
    const home: []const u8 = envutil.get("HOME") orelse blk: {
        if (std.mem.endsWith(u8, corpus_path, suffix)) break :blk corpus_path[0 .. corpus_path.len - suffix.len];
        return error.NoHome;
    };
    return std.fmt.allocPrint(a, "{s}/.cache/zui/target-swarm/release/zui-net-truth", .{home});
}

var run_dir_buf: [96]u8 = undefined;
var run_dir_len: usize = 0;

/// `sessions/net/run-<pid>-<ns>`, fixed on the first call: one directory for this process.
fn runDir(ctx: *harness.Ctx) ![]const u8 {
    if (run_dir_len == 0) {
        const ns: u64 = @intCast(Io.Clock.real.now(ctx.io).toNanoseconds());
        const s = try std.fmt.bufPrint(&run_dir_buf, "sessions/net/run-{d}-{x}", .{ std.c.getpid(), ns });
        run_dir_len = s.len;
    }
    return run_dir_buf[0..run_dir_len];
}

fn startRust(ctx: *harness.Ctx, a: std.mem.Allocator, tag: []const u8, fixtures: ?[]const u8, extra: []const []const u8) !Rust {
    const bin = try truthBinary(a, ctx.corpus_path);
    // One directory per run (pid and wall-clock nanoseconds): two runs on one corpus (the runner
    // boxes' slots, the gate's shards) must not share the Rust peer's ready file or request log
    // (File::create truncates, and a shared log doubled the counts and failed the run).
    const rel = try runDir(ctx);
    try ctx.corpus.createDirPath(ctx.io, rel);
    const dir = try std.fmt.allocPrint(a, "{s}/{s}", .{ ctx.corpus_path, rel });
    const ready = try std.fmt.allocPrint(a, "{s}/ready-{s}", .{ dir, tag });
    // The bench peer logs to /dev/null, like the peer `zui-net-truth bench` starts for the Rust
    // client: a request log in a real file costs the server a write(2) per request (about 10 us
    // on macOS), which was charged to deepwave's rpc-small round trip and not to Rust's.
    const log = if (std.mem.eql(u8, tag, "bench")) "/dev/null" else try std.fmt.allocPrint(a, "{s}/requests-{s}.jsonl", .{ dir, tag });
    const ready_rel = try std.fmt.allocPrint(a, "{s}/ready-{s}", .{ rel, tag });
    ctx.corpus.deleteFile(ctx.io, ready_rel) catch {};
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, &.{ bin, "peer", "--key", "0707070707070707070707070707070707070707070707070707070707070707", "--ready", ready, "--log", log });
    if (fixtures) |f| try argv.appendSlice(a, &.{ "--fixtures", f });
    try argv.appendSlice(a, extra);
    var child = try std.process.spawn(ctx.io, .{ .argv = argv.items, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore });
    errdefer child.kill(ctx.io);
    // wait for the ready file
    var tries: usize = 0;
    while (tries < 400) : (tries += 1) {
        if (ctx.corpus.readFileAlloc(ctx.io, ready_rel, a, .limited(4096))) |line| {
            var it = std.mem.tokenizeAny(u8, line, " \n");
            _ = it.next();
            const port = try std.fmt.parseInt(u16, it.next().?, 10);
            var id: [32]u8 = undefined;
            try core.hex.decode(&id, it.next().?);
            return .{ .child = child, .port = port, .peer_id = id, .log_path = log };
        } else |_| {}
        try Io.sleep(ctx.io, .fromMilliseconds(25), .awake);
    }
    return error.RustPeerDidNotStart;
}

const SyncVec = struct { id: []const u8, kind: []const u8, route: []const u8, bcs_hex: []const u8, snappy_hex: []const u8 };

const LogLine = struct {
    route: []const u8,
    headers: []const [2][]const u8,
    body_hex: []const u8,
    peer: ?[]const u8 = null,
};

pub fn run(ctx: *harness.Ctx) anyerror!void {
    ctx.nextItem();
    const a = ctx.scratch();
    // fixtures: real state-sync responses (from the sync-rpc-codec vectors) served by the Rust peer
    const sync_text = try ctx.corpus.readFileAlloc(ctx.io, "vectors/sync-rpc-codec/sync.jsonl", ctx.gpa, .limited(1 << 30));
    defer ctx.gpa.free(sync_text);
    const run_rel = try runDir(ctx);
    const fixtures_rel = try std.fmt.allocPrint(a, "{s}/fixtures", .{run_rel});
    try ctx.corpus.createDirPath(ctx.io, fixtures_rel);
    defer ctx.corpus.deleteTree(ctx.io, run_rel) catch {};
    var summary_fix: ?[]u8 = null;
    var avail_fix: ?[]u8 = null;
    defer if (summary_fix) |f| ctx.gpa.free(f);
    defer if (avail_fix) |f| ctx.gpa.free(f);
    {
        var it = harness.lines(sync_text);
        while (it.next()) |line| {
            const v = try std.json.parseFromSliceLeaky(SyncVec, a, line, .{ .ignore_unknown_fields = true });
            if (summary_fix == null and std.mem.startsWith(u8, v.id, "resp/summary/") and !std.mem.endsWith(u8, v.id, "none")) summary_fix = try core.hex.decodeAlloc(ctx.gpa, v.snappy_hex);
            if (avail_fix == null and std.mem.startsWith(u8, v.id, "resp/availability/")) avail_fix = try core.hex.decodeAlloc(ctx.gpa, v.snappy_hex);
        }
    }
    const fdir = try std.fmt.allocPrint(a, "{s}/{s}", .{ ctx.corpus_path, fixtures_rel });
    inline for (.{ .{ "_sui.StateSync_GetCheckpointSummary.bin", summary_fix.? }, .{ "_sui.StateSync_GetCheckpointAvailability.bin", avail_fix.? } }) |f| {
        const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ fixtures_rel, f[0] });
        try ctx.corpus.writeFile(ctx.io, .{ .sub_path = path, .data = f[1] });
    }

    var rust = startRust(ctx, a, "main", fdir, &.{}) catch |e| {
        ctx.fail("start-rust-peer", "{s}", .{@errorName(e)});
        return;
    };
    defer rust.stop(ctx.io);
    const addr: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(rust.port) };

    // ---- handshake + identity
    {
        const item = "handshake/peer-id";
        if (ctx.selected(item)) {
            ctx.nextItem();
            if (anemo.Peer.connect(ctx.gpa, ctx.io, addr, .{ .server_name = ss.mainnet_server_name, .expected = rust.peer_id })) |p| {
                defer p.deinit();
                _ = ctx.expectBytes(item, "peer id", &rust.peer_id, &p.peer_id);
            } else |e| ctx.fail(item, "connect: {s}", .{@errorName(e)});
        }
    }
    negative(ctx, addr, "handshake/wrong-peer-id", .{ .server_name = ss.mainnet_server_name, .expected = @as([32]u8, @splat(9)), .handshake_timeout_ms = 3000 });
    negative(ctx, addr, "handshake/wrong-server-name", .{ .server_name = "sui-00000000", .handshake_timeout_ms = 3000 });

    // ---- RPCs on one connection
    ctx.nextItem();
    const p = anemo.Peer.connect(ctx.gpa, ctx.io, addr, .{ .server_name = ss.mainnet_server_name, .expected = rust.peer_id }) catch |e| {
        ctx.fail("rpc/connect", "{s}", .{@errorName(e)});
        return;
    };
    defer p.deinit();
    rpcItems(ctx, p, &rust, summary_fix.?, avail_fix.?);

    // ---- loss recovery against quinn: 5% and 15% loss each way
    for ([_]u8{ 5, 15 }) |pct| {
        var name_buf: [64]u8 = undefined;
        const item = std.fmt.bufPrint(&name_buf, "loss/{d}pct", .{pct}) catch "loss";
        if (!ctx.selected(item)) continue;
        ctx.nextItem();
        const lp = anemo.Peer.connect(ctx.gpa, ctx.io, addr, .{ .server_name = ss.mainnet_server_name, .expected = rust.peer_id, .sim_drop_pct = pct, .sim_seed = 42 + pct, .handshake_timeout_ms = 20_000 }) catch |e| {
            ctx.fail(item, "connect: {s}", .{@errorName(e)});
            continue;
        };
        defer lp.deinit();
        var c = ctx.check(item);
        var size_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &size_buf, 3 << 20, .little);
        if (lp.request(ctx.scratch(), "/zui.Test/Big", &.{}, &size_buf, 60_000)) |r| {
            c.eql("status", wire.Status.success, r.status);
            c.eql("len", @as(usize, 3 << 20), r.body.len);
            c.eql("body", true, bigOk(r.body));
        } else |e| c.failf("request: {s}", .{@errorName(e)});
        _ = c.finish();
    }
    // the Rust log must show every request it decoded
    checkLog(ctx, a, try std.fmt.allocPrint(a, "{s}/requests-main.jsonl", .{run_rel}));
}

fn negative(ctx: *harness.Ctx, addr: Io.net.IpAddress, item: []const u8, opts: anemo.Options) void {
    if (!ctx.selected(item)) return;
    ctx.nextItem();
    if (anemo.Peer.connect(ctx.gpa, ctx.io, addr, opts)) |p| {
        p.deinit();
        ctx.fail(item, "connect succeeded but must be rejected", .{});
    } else |_| ctx.pass(item);
}

fn bigOk(body: []const u8) bool {
    for (body, 0..) |b, i| {
        const want: u8 = @truncate((i *% 2654435761) >> 7);
        if (b != want) return false;
    }
    return true;
}

fn rpcItems(ctx: *harness.Ctx, p: *anemo.Peer, rust: *Rust, summary_fix: []const u8, avail_fix: []const u8) void {
    _ = rust;
    // echo with headers, sizes around packet and stream boundaries
    const sizes = [_]usize{ 0, 1, 7, 1100, 1180, 1181, 2400, 65535, 65536, 300_000, 900_000 };
    for (sizes) |n| {
        var name_buf: [64]u8 = undefined;
        const item = std.fmt.bufPrint(&name_buf, "echo/{d}", .{n}) catch "echo";
        if (!ctx.selected(item)) continue;
        ctx.nextItem();
        const a = ctx.scratch();
        const body = a.alloc(u8, n) catch return;
        for (body, 0..) |*b, i| b.* = @truncate(i *% 31 +% n);
        const hs = [_]wire.Header{ .{ .name = "x-zui", .value = "value" }, .{ .name = "timeout", .value = "30000000000" } };
        var c = ctx.check(item);
        if (p.request(a, "/zui.Test/Echo", &hs, body, 20_000)) |r| {
            c.eql("status", wire.Status.success, r.status);
            c.bytes("body", body, r.body);
            var seen = false;
            for (r.headers) |h| if (std.mem.eql(u8, h.name, "x-zui")) {
                seen = true;
                c.text("x-zui", "value", h.value);
            };
            if (!seen) c.failf("echoed header missing", .{});
        } else |e| c.failf("request: {s}", .{@errorName(e)});
        _ = c.finish();
    }
    // large responses (flow control, window updates, ack handling)
    for ([_]usize{ 1, 1200, 100_000, 1 << 20, 16 << 20 }) |n| {
        var name_buf: [64]u8 = undefined;
        const item = std.fmt.bufPrint(&name_buf, "big/{d}", .{n}) catch "big";
        if (!ctx.selected(item)) continue;
        ctx.nextItem();
        const a = ctx.scratch();
        var size_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &size_buf, n, .little);
        var c = ctx.check(item);
        if (p.request(a, "/zui.Test/Big", &.{}, &size_buf, 60_000)) |r| {
            c.eql("status", wire.Status.success, r.status);
            c.eql("len", n, r.body.len);
            c.eql("body", true, bigOk(r.body));
        } else |e| c.failf("request: {s}", .{@errorName(e)});
        _ = c.finish();
    }
    // status codes and status-message header
    for ([_]u16{ 200, 400, 404, 408, 429, 500, 505, 520 }) |code| {
        var name_buf: [64]u8 = undefined;
        const item = std.fmt.bufPrint(&name_buf, "status/{d}", .{code}) catch "status";
        if (!ctx.selected(item)) continue;
        ctx.nextItem();
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, code, .little);
        var c = ctx.check(item);
        if (p.request(ctx.scratch(), "/zui.Test/Status", &.{}, &b, 10_000)) |r| {
            c.eql("status", code, @intFromEnum(r.status));
            var msg: []const u8 = "";
            for (r.headers) |h| if (std.mem.eql(u8, h.name, "status-message")) {
                msg = h.value;
            };
            c.text("status-message", "from the Rust peer", msg);
        } else |e| c.failf("request: {s}", .{@errorName(e)});
        _ = c.finish();
    }
    // unknown route: the Rust router answers 404
    if (ctx.selected("route/unknown")) {
        ctx.nextItem();
        var c = ctx.check("route/unknown");
        if (p.request(ctx.scratch(), "/zui.Nope/Nothing", &.{}, "", 10_000)) |r| c.eql("status", wire.Status.not_found, r.status) else |e| c.failf("request: {s}", .{@errorName(e)});
        _ = c.finish();
    }
    // server-initiated requests: the Rust peer calls us back; a read-only client answers 200 to a
    // checkpoint push and 404 to everything else
    if (ctx.selected("inbound/callback")) {
        ctx.nextItem();
        const a = ctx.scratch();
        var c = ctx.check("inbound/callback");
        if (p.request(a, "/zui.Test/Callback", &.{}, "", 10_000)) |_| {
            p.pump(400) catch |e| c.failf("pump: {s}", .{@errorName(e)});
            if (p.request(a, "/zui.Test/CallbackResult", &.{}, "", 10_000)) |r| {
                const want = [_]u8{ 200 & 0xff, 200 >> 8, 404 & 0xff, 404 >> 8, 404 & 0xff, 404 >> 8 };
                c.bytes("statuses the Rust peer saw from zui", &want, r.body);
            } else |e| c.failf("result request: {s}", .{@errorName(e)});
        } else |e| c.failf("callback request: {s}", .{@errorName(e)});
        _ = c.finish();
    }
    // state-sync: the requests deepwave sends are decoded by the Rust side (log check), responses are
    // real BCS+snappy bytes and round trip through deepwave's decoder
    stateSyncItems(ctx, p, summary_fix, avail_fix);
}

fn stateSyncItems(ctx: *harness.Ctx, p: *anemo.Peer, summary_fix: []const u8, avail_fix: []const u8) void {
    if (ctx.selected("statesync/summary")) {
        ctx.nextItem();
        const a = ctx.scratch();
        var c = ctx.check("statesync/summary");
        const body = ss.encodeSummaryRequest(a, .{ .seq = 1234567 }) catch return;
        const hs = [_]wire.Header{.{ .name = "timeout", .value = "10000000000" }};
        if (p.request(a, ss.Route.get_checkpoint_summary, &hs, body, 10_000)) |r| {
            c.eql("status", wire.Status.success, r.status);
            c.bytes("response bytes", summary_fix, r.body);
            if (ss.decodeBody(a, r.body)) |bcs| {
                if (ss.optionPayload(bcs)) |o| c.eql("some", true, o != null) else |e| c.failf("option: {s}", .{@errorName(e)});
            } else |e| c.failf("decode: {s}", .{@errorName(e)});
        } else |e| c.failf("request: {s}", .{@errorName(e)});
        _ = c.finish();
    }
    // typed helpers: same fixtures through getCheckpointSummary / getCheckpointAvailability
    if (ctx.selected("statesync/typed")) {
        ctx.nextItem();
        const a = ctx.scratch();
        var c = ctx.check("statesync/typed");
        if (ss.getCheckpointSummary(p, a, .latest)) |o| {
            c.eql("summary some", true, o != null);
            if (o) |payload| c.eql("summary epoch+seq present", true, payload.len > 16);
        } else |e| c.failf("getCheckpointSummary: {s}", .{@errorName(e)});
        if (ss.getCheckpointAvailability(p, a)) |av| {
            c.eql("availability summary", true, av.highest_synced_summary.len > 16);
        } else |e| c.failf("getCheckpointAvailability: {s}", .{@errorName(e)});
        _ = c.finish();
    }
    if (ctx.selected("statesync/availability")) {
        ctx.nextItem();
        const a = ctx.scratch();
        var c = ctx.check("statesync/availability");
        if (p.request(a, ss.Route.get_checkpoint_availability, &.{}, ss.encodeUnitRequest(), 10_000)) |r| {
            c.eql("status", wire.Status.success, r.status);
            c.bytes("response bytes", avail_fix, r.body);
            if (ss.decodeBody(a, r.body)) |bcs| {
                if (ss.splitAvailability(bcs)) |_| {} else |e| c.failf("split: {s}", .{@errorName(e)});
            } else |e| c.failf("decode: {s}", .{@errorName(e)});
        } else |e| c.failf("request: {s}", .{@errorName(e)});
        _ = c.finish();
    }
}

fn checkLog(ctx: *harness.Ctx, a: std.mem.Allocator, path: []const u8) void {
    if (!ctx.selected("rustlog/decoded")) return;
    ctx.nextItem();
    var c = ctx.check("rustlog/decoded");
    const text = ctx.corpus.readFileAlloc(ctx.io, path, a, .limited(1 << 30)) catch |e| {
        c.failf("read log: {s}", .{@errorName(e)});
        _ = c.finish();
        return;
    };
    var n_echo: usize = 0;
    var n_sync: usize = 0;
    var it = harness.lines(text);
    while (it.next()) |line| {
        const l = std.json.parseFromSliceLeaky(LogLine, a, line, .{ .ignore_unknown_fields = true }) catch {
            c.failf("log line parse", .{});
            continue;
        };
        if (std.mem.eql(u8, l.route, "/zui.Test/Echo")) n_echo += 1;
        if (std.mem.eql(u8, l.route, ss.Route.get_checkpoint_summary)) {
            n_sync += 1;
            // BySequenceNumber(1234567) snappy-framed, as the Rust codec would have decoded it
            const got = core.hex.decodeAlloc(a, l.body_hex) catch return;
            const want_seq = ss.encodeSummaryRequest(a, .{ .seq = 1234567 }) catch return;
            const want_latest = ss.encodeSummaryRequest(a, .latest) catch return;
            if (!std.mem.eql(u8, got, want_seq)) c.bytes("summary request as seen by Rust (latest)", want_latest, got);
            var has_timeout = false;
            for (l.headers) |h| if (std.mem.eql(u8, h[0], "timeout")) {
                has_timeout = true;
                c.text("timeout header", "10000000000", h[1]);
            };
            if (!has_timeout) c.failf("timeout header not seen by Rust", .{});
        }
    }
    c.eql("echo requests seen", @as(usize, 11), n_echo);
    c.eql("summary requests seen", @as(usize, 2), n_sync);
    _ = c.finish();
}

// ---------------------------------------------------------------- bench

const BenchState = struct {
    ctx: *harness.Ctx,
    addr: Io.net.IpAddress,
    id: [32]u8,
    peer: ?*anemo.Peer = null,
    arena: std.mem.Allocator,
    sink: usize = 0,
};

fn benchHandshake(st: *BenchState) anyerror!void {
    const p = try anemo.Peer.connect(st.ctx.gpa, st.ctx.io, st.addr, .{ .server_name = ss.mainnet_server_name, .expected = st.id });
    st.sink +%= p.peer_id[0];
    p.deinit();
}

const small_n = 2000;

fn benchSmall(st: *BenchState) anyerror!void {
    var arena_state = std.heap.ArenaAllocator.init(st.ctx.gpa);
    defer arena_state.deinit();
    const body: [64]u8 = @splat(1);
    for (0..small_n) |_| {
        _ = arena_state.reset(.retain_capacity);
        const r = try st.peer.?.request(arena_state.allocator(), "/zui.Test/Echo", &.{}, &body, 10_000);
        st.sink +%= r.body.len;
    }
}

fn benchBig(st: *BenchState) anyerror!void {
    var arena_state = std.heap.ArenaAllocator.init(st.ctx.gpa);
    defer arena_state.deinit();
    var sz: [8]u8 = undefined;
    std.mem.writeInt(u64, &sz, 64 << 20, .little);
    const r = try st.peer.?.request(arena_state.allocator(), "/zui.Test/Big", &.{}, &sz, 60_000);
    st.sink +%= r.body.len;
}

pub fn bench(ctx: *harness.Ctx) anyerror!void {
    var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var rust = try startRust(ctx, a, "bench", null, &.{});
    defer ctx.corpus.deleteTree(ctx.io, runDir(ctx) catch "sessions/net/none") catch {};
    defer rust.stop(ctx.io);
    const addr: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(rust.port) };
    var st: BenchState = .{ .ctx = ctx, .addr = addr, .id = rust.peer_id, .arena = a };
    try ctx.benchPasses("rpc-handshake", "handshake", 1, &st, benchHandshake);
    const spin: u32 = if (envutil.get("ZUI_NET_SPIN")) |v| std.fmt.parseInt(u32, v, 10) catch 0 else 0;
    const p = try anemo.Peer.connect(ctx.gpa, ctx.io, addr, .{ .server_name = ss.mainnet_server_name, .expected = rust.peer_id, .busy_poll_us = spin });
    defer p.deinit();
    st.peer = p;
    try ctx.benchPasses("rpc-small", "request", small_n, &st, benchSmall);
    try ctx.benchPasses("rpc-big", "byte", 64 << 20, &st, benchBig);
    std.mem.doNotOptimizeAway(st.sink);
}
