//! `deepwave p2p-probe SEEDS [--timeout-ms N] [--threads N] [--key FILE]`: why outbound p2p
//! connects fail. Connects to every seed, asks each for its known peers (GetKnownPeersV2), then
//! dials every distinct discovered peer at every address it advertises (IP and /dns, as sui-node's
//! `try_to_connect_to_peer` does) and classifies each attempt (anemo.ConnectDiag): silent (no
//! datagram came back), stalled, peer_closed / local_closed (code and reason), anemo, socket.
//! One line per peer, then one JSON summary line.
const std = @import("std");
const Io = std.Io;
const net = @import("net");
const p2p = @import("p2p.zig");
const anemo = net.anemo;
const discovery = net.discovery;
const Atomic = std.atomic.Value;
const class_names = @typeInfo(anemo.ConnectDiag.Class).@"enum".field_names;

const Target = struct {
    id: [32]u8,
    addrs: []const []const u8,
    access: discovery.AccessType,
    ts_ms: u64,
    from_seed: bool,
    // result
    ok: bool = false,
    ms: u64 = 0,
    class: ?anemo.ConnectDiag.Class = null,
    detail: [96]u8 = undefined,
    detail_len: usize = 0,
    kind: []const u8 = "",
};

const Ctx = struct {
    io: Io,
    gpa: std.mem.Allocator,
    seed: [32]u8,
    timeout_ms: u64,
    targets: []Target,
    next: Atomic(usize) = .init(0),
};

fn addrKind(text: []const u8) []const u8 {
    const d = discovery.parseAddress(text) orelse return "unparsed";
    return switch (d) {
        .dns => "dns",
        .ip4_or_6 => |ip| switch (ip) {
            .ip6 => "ip6",
            .ip4 => |a| blk: {
                const b = a.bytes;
                if (b[0] == 10 or (b[0] == 172 and b[1] & 0xf0 == 16) or (b[0] == 192 and b[1] == 168) or b[0] == 127 or (b[0] == 100 and b[1] & 0xc0 == 64) or b[0] == 0)
                    break :blk "ip4-private";
                break :blk "ip4";
            },
        },
    };
}

fn dialOne(c: *Ctx, t: *Target) void {
    var last: anemo.ConnectDiag = .{};
    for (t.addrs) |text| {
        const d = discovery.parseAddress(text) orelse continue;
        t.kind = addrKind(text);
        const ip: Io.net.IpAddress = switch (d) {
            .ip4_or_6 => |ip| ip,
            .dns => |h| net.peer_addr.resolve(c.io, .{ .dns = .{ .name = h.host, .port = h.port } }) catch {
                last = .{ .class = .socket };
                const r = "dns resolve failed";
                @memcpy(last.reason_buf[0..r.len], r);
                last.reason_len = r.len;
                continue;
            },
        };
        const t0 = std.Io.Clock.awake.now(c.io).toNanoseconds();
        var diag: anemo.ConnectDiag = .{};
        const peer = anemo.Peer.connect(c.gpa, c.io, ip, .{
            .server_name = net.state_sync.mainnet_server_name,
            .expected = t.id,
            .identity_seed = c.seed,
            .handshake_timeout_ms = c.timeout_ms,
            .diag = &diag,
        }) catch {
            last = diag;
            continue;
        };
        t.ms = @intCast(@divTrunc(std.Io.Clock.awake.now(c.io).toNanoseconds() - t0, std.time.ns_per_ms));
        t.ok = true;
        peer.deinit();
        return;
    }
    t.class = last.class;
    const s = std.fmt.bufPrint(&t.detail, "code=0x{x} app={} rx={d} {d}ms {s}", .{ last.code, last.app, last.received, last.elapsed_ms, last.reason() }) catch "";
    t.detail_len = s.len;
}

fn worker(c: *Ctx) void {
    while (true) {
        const i = c.next.fetchAdd(1, .monotonic);
        if (i >= c.targets.len) return;
        dialOne(c, &c.targets[i]);
    }
}

pub fn run(gpa: std.mem.Allocator, io: Io, args: []const []const u8) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    if (args.len < 3) {
        std.debug.print("usage: deepwave p2p-probe SEEDS [--timeout-ms N] [--threads N] [--key FILE]\n", .{});
        return 2;
    }
    var timeout_ms: u64 = 10_000;
    var threads: usize = 32;
    var seed: [32]u8 = undefined;
    io.random(&seed);
    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--timeout-ms") and i + 1 < args.len) {
            i += 1;
            timeout_ms = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--threads") and i + 1 < args.len) {
            i += 1;
            threads = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--key") and i + 1 < args.len) {
            i += 1;
            seed = (try p2p.loadKey(io, args[i])).secret_key.seed();
        }
    }
    const seeds = try p2p.parsePeers(a, args[2]);
    var targets: std.ArrayList(Target) = .empty;
    var seed_ok: usize = 0;
    var seed_fail: usize = 0;
    var total_known: usize = 0;
    var unverified: usize = 0;
    for (seeds) |sp| {
        var addr = sp.addr;
        if (sp.dns) |d| addr = net.peer_addr.resolve(io, .{ .dns = d }) catch {
            seed_fail += 1;
            continue;
        };
        var diag: anemo.ConnectDiag = .{};
        const peer = anemo.Peer.connect(gpa, io, addr, .{
            .server_name = net.state_sync.mainnet_server_name,
            .expected = sp.id,
            .identity_seed = seed,
            .handshake_timeout_ms = timeout_ms,
            .diag = &diag,
        }) catch {
            seed_fail += 1;
            std.debug.print("seed {f}: FAIL {s} code=0x{x} rx={d} {s}\n", .{ addr, @tagName(diag.class), diag.code, diag.received, diag.reason() });
            continue;
        };
        defer peer.deinit();
        seed_ok += 1;
        const kp = discovery.getKnownPeersV2(peer, a) catch |e| {
            std.debug.print("seed {f}: GetKnownPeersV2 {s}\n", .{ addr, @errorName(e) });
            continue;
        };
        total_known += kp.peers.len;
        std.debug.print("seed {f}: ok, {d} known peers\n", .{ addr, kp.peers.len });
        const all = [_][]const discovery.SignedInfo{ (&kp.own)[0..1], kp.peers };
        for (all, 0..) |list, li| for (list) |*info| {
            if (!info.verify()) {
                unverified += 1;
                continue;
            }
            const have = for (targets.items) |*t| {
                if (std.mem.eql(u8, &t.id, &info.peer_id)) break t;
            } else null;
            if (have) |t| {
                if (info.timestamp_ms > t.ts_ms) {
                    t.addrs = info.addresses;
                    t.ts_ms = info.timestamp_ms;
                }
                if (li == 0) t.from_seed = true;
                continue;
            }
            try targets.append(a, .{ .id = info.peer_id, .addrs = info.addresses, .access = info.access_type, .ts_ms = info.timestamp_ms, .from_seed = li == 0 });
        };
    }
    std.debug.print("dialing {d} distinct peers ({d} threads, {d} ms timeout)\n", .{ targets.items.len, threads, timeout_ms });
    var ctx: Ctx = .{ .io = io, .gpa = gpa, .seed = seed, .timeout_ms = timeout_ms, .targets = targets.items };
    const ts = try a.alloc(std.Thread, @min(threads, @max(targets.items.len, 1)));
    for (ts) |*t| t.* = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, worker, .{&ctx});
    for (ts) |t| t.join();
    var n_ok: usize = 0;
    var by_class: [class_names.len]usize = @splat(0);
    var no_addr: usize = 0;
    const kinds = [_][]const u8{ "ip4", "ip4-private", "ip6", "dns", "unparsed", "none" };
    var by_kind_all: [kinds.len]usize = @splat(0);
    var by_kind_fail: [kinds.len]usize = @splat(0);
    var ok_ms: std.ArrayList(u64) = .empty;
    const now_ms: u64 = @intCast(@divTrunc(Io.Clock.real.now(io).toNanoseconds(), std.time.ns_per_ms));
    for (targets.items) |*t| {
        const age_h = (now_ms -| t.ts_ms) / 3_600_000;
        if (t.addrs.len == 0) no_addr += 1;
        const k = if (t.kind.len == 0) "none" else t.kind;
        const ki = for (kinds, 0..) |kn, j| {
            if (std.mem.eql(u8, kn, k)) break j;
        } else kinds.len - 1;
        by_kind_all[ki] += 1;
        if (t.ok) {
            n_ok += 1;
            try ok_ms.append(a, t.ms);
            std.debug.print("peer {x}... {s} {s} age {d}h OK {d} ms\n", .{ t.id[0..4], k, @tagName(t.access), age_h, t.ms });
        } else {
            by_kind_fail[ki] += 1;
            if (t.class) |c| by_class[@intFromEnum(c)] += 1;
            const first: []const u8 = if (t.addrs.len > 0) t.addrs[0] else "-";
            std.debug.print("peer {x}... {s} {s} age {d}h FAIL {s} {s} [{s}]\n", .{ t.id[0..4], k, @tagName(t.access), age_h, if (t.class) |c| @tagName(c) else "no-address", t.detail[0..t.detail_len], first });
        }
    }
    std.mem.sort(u64, ok_ms.items, {}, std.sort.asc(u64));
    var out: std.Io.Writer.Allocating = .init(a);
    const w = &out.writer;
    try w.print("{{\"probe\":\"p2p\",\"seeds\":{d},\"seeds_ok\":{d},\"seeds_failed\":{d},\"known_peers_total\":{d},\"unverified\":{d},\"distinct\":{d},\"ok\":{d},\"no_address\":{d}", .{ seeds.len, seed_ok, seed_fail, total_known, unverified, targets.items.len, n_ok, no_addr });
    for (class_names, 0..) |name, fi| try w.print(",\"{s}\":{d}", .{ name, by_class[fi] });
    try w.writeAll(",\"by_kind\":{");
    for (kinds, by_kind_all, by_kind_fail, 0..) |k, v, f, ki| try w.print("{s}\"{s}\":[{d},{d}]", .{ if (ki == 0) "" else ",", k, v, f });
    try w.writeAll("}");
    if (ok_ms.items.len > 0) try w.print(",\"handshake_ms_p50\":{d},\"handshake_ms_p90\":{d}", .{ ok_ms.items[ok_ms.items.len / 2], ok_ms.items[ok_ms.items.len * 9 / 10] });
    try w.writeAll("}\n");
    std.debug.print("{s}", .{out.written()});
    return 0;
}
