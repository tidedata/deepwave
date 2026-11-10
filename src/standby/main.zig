//! deepwave-standby: hot-standby lease daemons and the watchdog (docs/STANDBY.md).
//!
//!   deepwave-standby keygen --out FILE                    shared secret for the lease messages (0600)
//!   deepwave-standby acceptor --listen ADDR --key FILE --state FILE --id NAME [--max-lease-ms N]
//!   deepwave-standby agent --name NAME --acceptors A,B,C --key FILE [options]    lease holder / candidate
//!   deepwave-standby status --acceptors A,B,C --key FILE                         what each acceptor says
//!   deepwave-standby watch --target NAME=ADDR ... [options]                      watchdog and alerts
//! Off unless started: nothing here runs inside deepwave.
const std = @import("std");
const Io = std.Io;
const lease = @import("lease.zig");
const watch = @import("watch.zig");
const net = @import("net.zig");
const Atomic = std.atomic.Value;

const usage =
    \\deepwave-standby keygen --out FILE
    \\deepwave-standby acceptor --listen ADDR:PORT --key FILE --state FILE [--id NAME] [--max-lease-ms N]
    \\deepwave-standby agent --name NAME --acceptors A:P,B:P,C:P --key FILE
    \\    [--lease-ms 6000] [--renew-ms 1500] [--margin-ms 1500] [--priority-delay-ms 0]
    \\    [--on-acquire CMD] [--on-lose CMD] [--hook-timeout-ms 2000] [--fence-file FILE] [--status-file FILE]
    \\    [--health-metrics ADDR --max-lag-s 60] [--health-cmd CMD] [--health-every-s 2] [--hook-fail-cooldown-s 30]
    \\    (hooks run as `sh -c 'CMD "$@"' sh TERM`; --on-lose must be quick and idempotent)
    \\deepwave-standby status --acceptors A:P,B:P,C:P --key FILE [--holders NAME,NAME]
    \\deepwave-standby watch --target NAME=ADDR[,NAME=ADDR] [--pair PRIMARY,STANDBY] [--interval-s 10]
    \\    [--alert-cmd CMD] [--label TEXT] [--heartbeat-s N] [--lease-acceptors A,B,C --key FILE --holders N1,N2]
    \\    [--lag-warn-s 30] [--lag-crit-s 120] [--stall-s 90] [--behind 200] [--min-peers 2]
    \\    [--serve-err-pct 5] [--standby-gap 50] [--rule name:metric[{k=v}]:op:thr[:for_s[:sev]]]...
    \\    [--stake-file FILE --stake-rule name:metric:label:op:thr:max_bad_pct[:for_s[:sev]]]...
    \\    [--once]   (one pass, exit 1 if anything is firing; for scripts and acceptance runs)
    \\
;

var g_stop: Atomic(bool) = .init(false);

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    g_stop.store(true, .release);
}

fn installSignals() void {
    const act: std.posix.Sigaction = .{ .handler = .{ .handler = onSignal }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);
    const ign: std.posix.Sigaction = .{ .handler = .{ .handler = std.posix.SIG.IGN }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.PIPE, &ign, null);
}

const Opts = struct {
    map: std.StringHashMapUnmanaged(std.ArrayList([]const u8)) = .empty,

    fn parse(gpa: std.mem.Allocator, args: []const [:0]const u8) !Opts {
        var o: Opts = .{};
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            const a = args[i];
            if (!std.mem.startsWith(u8, a, "--")) return error.BadArgument;
            const key = a[2..];
            var val: []const u8 = "";
            if (std.mem.eql(u8, key, "once")) {} else {
                i += 1;
                if (i >= args.len) return error.MissingValue;
                val = args[i];
            }
            const gop = try o.map.getOrPut(gpa, key);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(gpa, val);
        }
        return o;
    }
    fn one(o: *const Opts, k: []const u8) ?[]const u8 {
        const l = o.map.get(k) orelse return null;
        return l.items[l.items.len - 1];
    }
    fn all(o: *const Opts, k: []const u8) []const []const u8 {
        const l = o.map.get(k) orelse return &.{};
        return l.items;
    }
    fn num(o: *const Opts, comptime T: type, k: []const u8, default: T) !T {
        const v = o.one(k) orelse return default;
        return switch (@typeInfo(T)) {
            .float => std.fmt.parseFloat(T, v) catch error.BadNumber,
            else => std.fmt.parseInt(T, v, 10) catch error.BadNumber,
        };
    }
};

fn fail(comptime fmt: []const u8, args: anytype) u8 {
    std.debug.print(fmt ++ "\n", args);
    return 2;
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    const cmd = args[1];
    var o = Opts.parse(init.arena.allocator(), args[2..]) catch |e| return fail("bad arguments: {s}\n{s}", .{ @errorName(e), usage });
    _ = &o;
    installSignals();
    if (std.mem.eql(u8, cmd, "keygen")) return keygen(io, &o);
    if (std.mem.eql(u8, cmd, "acceptor")) return runAcceptor(gpa, io, &o);
    if (std.mem.eql(u8, cmd, "agent")) return runAgent(gpa, io, &o);
    if (std.mem.eql(u8, cmd, "status")) return runStatus(gpa, io, &o);
    if (std.mem.eql(u8, cmd, "watch")) return runWatch(gpa, io, &o);
    std.debug.print("{s}", .{usage});
    return 2;
}

fn keygen(io: Io, o: *const Opts) u8 {
    const out = o.one("out") orelse return fail("keygen: --out is required", .{});
    net.writeKeyFile(io, out) catch |e| return fail("keygen: {s}", .{@errorName(e)});
    std.debug.print("wrote {s} (mode 0600); copy it to every acceptor, agent and watcher box\n", .{out});
    return 0;
}

fn parsePeers(gpa: std.mem.Allocator, text: []const u8) ![]Io.net.IpAddress {
    var list: std.ArrayList(Io.net.IpAddress) = .empty;
    errdefer list.deinit(gpa);
    var it = std.mem.tokenizeScalar(u8, text, ',');
    while (it.next()) |p| try list.append(gpa, try net.parseAddr(std.mem.trim(u8, p, " ")));
    if (list.items.len == 0 or list.items.len > lease.max_acceptors) return error.BadAcceptorCount;
    return list.toOwnedSlice(gpa);
}

fn runAcceptor(gpa: std.mem.Allocator, io: Io, o: *const Opts) u8 {
    _ = gpa;
    const listen = net.parseAddr(o.one("listen") orelse return fail("acceptor: --listen is required", .{})) catch return fail("acceptor: bad --listen", .{});
    const key = net.loadKey(io, o.one("key") orelse return fail("acceptor: --key is required", .{})) catch |e| return fail("acceptor: key: {s}", .{@errorName(e)});
    const state_path = o.one("state") orelse return fail("acceptor: --state is required", .{});
    const max_lease = o.num(u32, "max-lease-ms", 60_000) catch return fail("acceptor: bad --max-lease-ms", .{});
    const id = lease.holderId(o.one("id") orelse "acceptor");
    var a = net.Acceptor.open(io, listen, key, .{ .id = id, .max_lease_ms = max_lease }, state_path, &g_stop) catch |e| return fail("acceptor: {s}", .{@errorName(e)});
    defer a.close();
    std.log.info("acceptor {x} on {s}: term {d} holder {x}", .{ id, o.one("listen").?, a.core.st.term, a.core.st.holder });
    a.run();
    std.log.info("acceptor stopped after {d} requests ({d} refused)", .{ a.served, a.refused });
    return 0;
}

// ---------------------------------------------------------------------------------- the agent

const Health = struct {
    gpa: std.mem.Allocator,
    io: Io,
    metrics: ?[]const u8,
    max_lag_s: u64,
    cmd: ?[]const u8,
    every_s: u64,
    ok: Atomic(bool) = .init(false),
    checked_ns: Atomic(u64) = .init(0),

    fn run(h: *Health) void {
        while (!g_stop.load(.acquire)) {
            const good = h.once();
            h.ok.store(good, .release);
            h.checked_ns.store(net.monoNs(), .release);
            var waited: u64 = 0;
            while (waited < h.every_s * 1000 and !g_stop.load(.acquire)) : (waited += 100) net.sleepMs(100);
        }
    }

    fn once(h: *Health) bool {
        if (h.metrics) |addr| {
            const body = net.httpGet(h.gpa, h.io, addr, "/metrics", 1500, 64 << 20) catch return false;
            defer h.gpa.free(body);
            var sc = watch.Scrape.parse(h.gpa, body) catch return false;
            defer sc.deinit(h.gpa);
            const ts = sc.get("last_executed_checkpoint_timestamp_ms") orelse return false;
            const now = net.wallMs();
            const t: u64 = watch.toU64(ts);
            if (now > t and (now - t) / 1000 > h.max_lag_s) return false;
        }
        if (h.cmd) |c| if (net.runHook(h.gpa, h.io, c, &.{}, 5000) != .ok) return false;
        return true;
    }
};

fn writeSmall(io: Io, path: []const u8, text: []const u8) void {
    var tmp_buf: [512]u8 = undefined;
    const tmp = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path}) catch return;
    const cwd = Io.Dir.cwd();
    {
        const f = cwd.createFile(io, tmp, .{ .truncate = true }) catch return;
        defer f.close(io);
        f.writePositionalAll(io, text, 0) catch return;
        f.sync(io) catch {};
    }
    cwd.rename(tmp, cwd, path, io) catch {};
}

fn runAgent(gpa: std.mem.Allocator, io: Io, o: *const Opts) u8 {
    const name = o.one("name") orelse return fail("agent: --name is required", .{});
    const peers = parsePeers(gpa, o.one("acceptors") orelse return fail("agent: --acceptors is required", .{})) catch |e| return fail("agent: --acceptors: {s}", .{@errorName(e)});
    defer gpa.free(peers);
    const key = net.loadKey(io, o.one("key") orelse return fail("agent: --key is required", .{})) catch |e| return fail("agent: key: {s}", .{@errorName(e)});
    const p: lease.Params = .{
        .lease_ms = o.num(u32, "lease-ms", 6000) catch return fail("bad --lease-ms", .{}),
        .renew_ms = o.num(u32, "renew-ms", 1500) catch return fail("bad --renew-ms", .{}),
        .margin_ms = o.num(u32, "margin-ms", 1500) catch return fail("bad --margin-ms", .{}),
        .priority_delay_ms = o.num(u32, "priority-delay-ms", 0) catch return fail("bad --priority-delay-ms", .{}),
        .round_timeout_ms = o.num(u32, "round-timeout-ms", 700) catch return fail("bad --round-timeout-ms", .{}),
    };
    var seed: u64 = undefined;
    io.random(std.mem.asBytes(&seed));
    var agent = lease.Agent.init(p, lease.holderId(name), @intCast(peers.len), seed) catch return fail("agent: parameters rejected (need round-timeout < renew, margin + 2*renew < lease)", .{});
    var client = net.Client.open(io, key, peers) catch |e| return fail("agent: socket: {s}", .{@errorName(e)});
    defer client.close();
    const on_acquire = o.one("on-acquire");
    const on_lose = o.one("on-lose");
    const hook_ms = o.num(u32, "hook-timeout-ms", 2000) catch return fail("bad --hook-timeout-ms", .{});
    const cooldown_s = o.num(u64, "hook-fail-cooldown-s", 30) catch return fail("bad --hook-fail-cooldown-s", .{});
    const fence_file = o.one("fence-file");
    const status_file = o.one("status-file");

    var health: Health = .{ .gpa = gpa, .io = io, .metrics = o.one("health-metrics"), .max_lag_s = o.num(u64, "max-lag-s", 60) catch 60, .cmd = o.one("health-cmd"), .every_s = o.num(u64, "health-every-s", 2) catch 2 };
    const have_health = health.metrics != null or health.cmd != null;
    var health_thread: ?std.Thread = null;
    if (have_health) health_thread = std.Thread.spawn(.{}, Health.run, .{&health}) catch return fail("agent: cannot start the health thread", .{});
    defer if (health_thread) |t| {
        g_stop.store(true, .release);
        t.join();
    };

    // A hook that outlasts the leader's own window would start serving after the lease is gone.
    if (@as(u64, hook_ms) + p.renew_ms >= @as(u64, p.lease_ms) - p.margin_ms) return fail("agent: --hook-timeout-ms + --renew-ms must stay below --lease-ms - --margin-ms", .{});

    std.log.info("agent {s} (id {x}): {d} acceptors, lease {d} ms, renew {d} ms, margin {d} ms", .{ name, agent.id, peers.len, p.lease_ms, p.renew_ms, p.margin_ms });
    var ho: Handover = .{ .io = io, .client = &client, .has_hook = on_lose != null, .fence_file = fence_file };
    // Always start in the not-serving state: a crashed or killed predecessor may have left serving on.
    ho.begin(0, null);
    var block_until_ns: u64 = 0;
    var next_status_ns: u64 = 0;
    while (!g_stop.load(.acquire)) {
        const now = net.monoNs();
        const wall = net.wallMs();
        // health, hook failures and an unfinished on-lose all keep us out of the race
        var ok = true;
        if (have_health) {
            const c = health.checked_ns.load(.acquire);
            const age = if (now > c) now - c else 0;
            ok = health.ok.load(.acquire) and age < (health.every_s * 3 + 3) * std.time.ns_per_s;
        }
        if (ho.lose_pending or now < block_until_ns) ok = false;
        if (agent.healthy and !ok) {
            if (agent.stepDown(now, wall)) |m| {
                std.log.warn("unhealthy: stepping down from term {d}", .{agent.term});
                ho.begin(agent.term, m);
            }
            agent.healthy = false;
        } else if (!agent.healthy and ok) agent.healthy = true;

        const st = agent.poll(now, wall);
        var out: ?lease.Msg = st.send;
        if (st.send) |m| if (m.kind == .release) {
            // unhealthy leader released inside poll: the release waits for on-lose
            ho.begin(agent.term, m);
            out = null;
        };
        if (st.event == .lost) {
            std.log.warn("lease lost (term {d})", .{agent.term});
            ho.begin(agent.term, null);
        }
        if (agent.takeRelease(now, wall)) |m| client.broadcast(m); // partial grants of a lost round: nothing served

        ho.tryLose(gpa, on_lose, hook_ms, now);
        // never open a new round while still serving by hand
        if (out) |m| if (!ho.lose_pending) client.broadcast(m);

        // replies: wait briefly, then drain
        var wait: i32 = 5;
        while (client.recv(wait)) |rep| {
            wait = 0;
            const ev = agent.onReply(net.monoNs(), rep.idx, rep.msg);
            if (ev == .acquired) {
                ho.last_term = agent.term;
                std.log.info("lease acquired: term {d}", .{agent.term});
                ho.fenceOn(agent.term, agent.valid_until_ns);
                if (on_acquire) |c| {
                    var tb: [24]u8 = undefined;
                    const ts = std.fmt.bufPrint(&tb, "{d}", .{agent.term}) catch "0";
                    const r = net.runHook(gpa, io, c, &.{ts}, hook_ms);
                    if (r != .ok) {
                        std.log.err("on-acquire hook {s}: giving the lease back, out for {d} s", .{ @tagName(r), cooldown_s });
                        block_until_ns = net.monoNs() + cooldown_s * std.time.ns_per_s;
                        const m = agent.stepDown(net.monoNs(), net.wallMs());
                        ho.begin(agent.term, m);
                    } else if (!agent.isLeader(net.monoNs())) {
                        // the hook took so long that the lease is already over: do not keep serving
                        std.log.err("on-acquire hook finished after the lease ended: switching serving off", .{});
                        ho.begin(agent.term, null);
                    }
                }
            } else if (ev == .renewed) {
                ho.fenceOn(agent.term, agent.valid_until_ns);
            } else if (ev == .lost) {
                ho.begin(agent.term, null);
            }
        }
        if (status_file) |f| if (now >= next_status_ns) {
            next_status_ns = now + std.time.ns_per_s;
            var sb: [256]u8 = undefined;
            const left: i64 = if (agent.isLeader(now)) @intCast((agent.valid_until_ns - now) / std.time.ns_per_ms) else 0;
            writeSmall(io, f, std.fmt.bufPrint(&sb, "state={s} term={d} max_term={d} valid_ms={d} healthy={any} wall_ms={d}\n", .{ if (agent.isLeader(now)) "leader" else "follower", agent.fence(now), agent.max_term, left, agent.healthy, wall }) catch "");
        };
    }
    // orderly stop: switch serving off first, and only then give the lease back so the other box takes over
    if (agent.stepDown(net.monoNs(), net.wallMs())) |m| ho.begin(agent.term, m) else if (ho.rel == null and !ho.lose_pending) ho.fenceOff();
    var tries: u8 = 0;
    while (ho.lose_pending and tries < 3) : (tries += 1) ho.tryLose(gpa, on_lose, hook_ms, std.math.maxInt(u64));
    if (ho.lose_pending) std.log.err("stopped with on-lose failing: lease NOT released, it runs out on its own", .{}) else std.log.info("stopped: lease of term {d} released", .{agent.term});
    if (status_file) |f| writeSmall(io, f, "state=stopped\n");
    return 0;
}

/// What happens when this box stops serving. The release is held back until the on-lose hook has
/// succeeded: the acceptors free the lease at once on a release, so releasing first would let the
/// other box serve while this one still does. If on-lose keeps failing, no release is ever sent and
/// the lease simply runs out (and the hook is retried every second).
const Handover = struct {
    io: Io,
    client: *net.Client,
    has_hook: bool,
    fence_file: ?[]const u8,
    lose_pending: bool = false,
    last_term: u64 = 0,
    last_try_ns: u64 = 0,
    rel: ?lease.Msg = null,

    fn begin(h: *Handover, term: u64, release: ?lease.Msg) void {
        h.last_term = term;
        h.last_try_ns = 0;
        h.fenceOff();
        if (release) |m| {
            if (h.has_hook) h.rel = m else h.client.broadcast(m);
        }
        h.lose_pending = h.has_hook;
    }

    fn tryLose(h: *Handover, gpa: std.mem.Allocator, cmd: ?[]const u8, hook_ms: u32, now: u64) void {
        if (!h.lose_pending) return;
        if (now != std.math.maxInt(u64) and now - h.last_try_ns < std.time.ns_per_s) return;
        h.last_try_ns = now;
        var tb: [24]u8 = undefined;
        const ts = std.fmt.bufPrint(&tb, "{d}", .{h.last_term}) catch "0";
        const r = net.runHook(gpa, h.io, cmd.?, &.{ts}, hook_ms);
        if (r != .ok) {
            std.log.err("on-lose hook {s}: retrying", .{@tagName(r)});
            return;
        }
        h.lose_pending = false;
        if (h.rel) |*m| {
            m.wall_ms = net.wallMs(); // fresh for the acceptors' replay window; the nonce is still above the last
            h.client.broadcast(m.*);
            h.rel = null;
        }
    }

    /// Fence file: `term valid_until_wall_ms`, rewritten on every renewal; `0 0` whenever not leading.
    fn fenceOn(h: *Handover, term: u64, valid_until_ns: u64) void {
        const f = h.fence_file orelse return;
        const now = net.monoNs();
        const left_ms = if (valid_until_ns > now) (valid_until_ns - now) / std.time.ns_per_ms else 0;
        var fb: [64]u8 = undefined;
        writeSmall(h.io, f, std.fmt.bufPrint(&fb, "{d} {d}\n", .{ term, net.wallMs() + left_ms }) catch return);
    }

    fn fenceOff(h: *Handover) void {
        if (h.fence_file) |f| writeSmall(h.io, f, "0 0\n");
    }
};

// --------------------------------------------------------------------------------- status

fn holderName(holders: []const []const u8, id: u64) []const u8 {
    for (holders) |h| if (lease.holderId(h) == id) return h;
    return "?";
}

fn runStatus(gpa: std.mem.Allocator, io: Io, o: *const Opts) u8 {
    const peers = parsePeers(gpa, o.one("acceptors") orelse return fail("status: --acceptors is required", .{})) catch |e| return fail("status: {s}", .{@errorName(e)});
    defer gpa.free(peers);
    const key = net.loadKey(io, o.one("key") orelse return fail("status: --key is required", .{})) catch |e| return fail("status: key: {s}", .{@errorName(e)});
    var holders: std.ArrayList([]const u8) = .empty;
    defer holders.deinit(gpa);
    if (o.one("holders")) |h| {
        var it = std.mem.tokenizeScalar(u8, h, ',');
        while (it.next()) |x| holders.append(gpa, x) catch {};
    }
    var c = net.Client.open(io, key, peers) catch |e| return fail("status: socket: {s}", .{@errorName(e)});
    defer c.close();
    const res = queryAll(&c, peers.len);
    var up: usize = 0;
    for (res[0..peers.len], 0..) |r, i| {
        if (r) |m| {
            up += 1;
            std.debug.print("acceptor {d}: term {d} holder {x} ({s}) lease left {d} ms\n", .{ i, m.term, m.holder, if (m.holder == 0) "free" else holderName(holders.items, m.holder), m.remaining_ms });
        } else std.debug.print("acceptor {d}: no answer\n", .{i});
    }
    return if (up * 2 > peers.len) 0 else 1;
}

/// A query round: replies per acceptor within 700 ms.
fn queryAll(c: *net.Client, n: usize) [lease.max_acceptors]?lease.Msg {
    var out: [lease.max_acceptors]?lease.Msg = @splat(null);
    const seq = (net.wallMs() << 20) + 1;
    c.broadcast(.{ .kind = .query, .seq = seq, .wall_ms = net.wallMs(), .term = 0, .holder = 1 });
    const deadline = net.monoNs() + 700 * std.time.ns_per_ms;
    var got: usize = 0;
    while (got < n and net.monoNs() < deadline) {
        if (c.recv(50)) |r| {
            if (r.msg.seq == seq and out[r.idx] == null) {
                out[r.idx] = r.msg;
                got += 1;
            }
        }
    }
    return out;
}

// ---------------------------------------------------------------------------------- watchdog

const Target = struct { name: []const u8, addr: []const u8, st: watch.NodeState = .{} };

const Dog = struct {
    gpa: std.mem.Allocator,
    io: Io,
    alert_cmd: ?[]const u8,
    label: []const u8,
    book: watch.Book,
    firing_now: usize = 0,
    /// One-shot mode: no debounce, a bad reading fires at once.
    immediate: bool = false,

    fn forOf(key: []const u8) u64 {
        const table = [_]struct { []const u8, u64 }{ .{ "/scrape", 20 }, .{ "/lag", 20 }, .{ "/stall", 0 }, .{ "/peers", 30 }, .{ "/behind", 60 }, .{ "/serve", 60 }, .{ "/store", 0 }, .{ "/state", 0 }, .{ "standby-gap", 60 }, .{ "lease/", 30 } };
        for (table) |e| if (std.mem.indexOf(u8, key, e[0]) != null) return e[1];
        return 30;
    }

    fn send(d: *Dog, sev: []const u8, text: []const u8) void {
        var line_buf: [1024]u8 = undefined;
        const line = std.fmt.bufPrint(&line_buf, "{s}{s}{s}", .{ d.label, if (d.label.len > 0) " " else "", text }) catch text;
        std.log.warn("{s} {s}", .{ sev, line });
        if (d.alert_cmd) |c| {
            const r = net.runHook(d.gpa, d.io, c, &.{ sev, line }, 30_000);
            if (r != .ok) std.log.err("alert command {s}", .{@tagName(r)});
        }
    }

    fn observe(d: *Dog, key: []const u8, bad: bool, sev: watch.Severity, detail: []const u8, now_s: u64, for_override: ?u64) void {
        const opts: watch.Book.Opts = .{ .for_s = if (d.immediate) 0 else for_override orelse forOf(key) };
        const n = d.book.observe(key, bad, sev, now_s, opts) catch return;
        if (d.book.isFiring(key)) d.firing_now += 1;
        const note = n orelse return;
        var b: [900]u8 = undefined;
        const text = switch (note.kind) {
            .fire => std.fmt.bufPrint(&b, "{s}: {s}", .{ key, detail }),
            .repeat => std.fmt.bufPrint(&b, "{s} still: {s} (for {d} s)", .{ key, detail, note.held_s }),
            .resolve => std.fmt.bufPrint(&b, "{s} recovered (was bad for {d} s)", .{ key, note.held_s }),
        } catch return;
        d.send(if (note.kind == .resolve) "OK" else sev.name(), text);
    }
};

fn runWatch(gpa: std.mem.Allocator, io: Io, o: *const Opts) u8 {
    var targets: std.ArrayList(Target) = .empty;
    defer targets.deinit(gpa);
    for (o.all("target")) |spec| {
        var it = std.mem.tokenizeScalar(u8, spec, ',');
        while (it.next()) |t| {
            const eq = std.mem.indexOfScalar(u8, t, '=') orelse return fail("watch: --target wants NAME=ADDR:PORT", .{});
            targets.append(gpa, .{ .name = t[0..eq], .addr = t[eq + 1 ..] }) catch return 1;
        }
    }
    const lease_acc = o.one("lease-acceptors");
    if (targets.items.len == 0 and lease_acc == null) return fail("watch: nothing to watch (--target or --lease-acceptors)", .{});
    const lim: watch.Limits = .{
        .lag_warn_s = o.num(u64, "lag-warn-s", 30) catch return fail("bad --lag-warn-s", .{}),
        .lag_crit_s = o.num(u64, "lag-crit-s", 120) catch return fail("bad --lag-crit-s", .{}),
        .stall_s = o.num(u64, "stall-s", 90) catch return fail("bad --stall-s", .{}),
        .behind = o.num(u64, "behind", 200) catch return fail("bad --behind", .{}),
        .min_peers = o.num(u64, "min-peers", 2) catch return fail("bad --min-peers", .{}),
        .serve_err_pct = o.num(f64, "serve-err-pct", 5.0) catch return fail("bad --serve-err-pct", .{}),
        .standby_gap = o.num(u64, "standby-gap", 50) catch return fail("bad --standby-gap", .{}),
    };
    const interval_s = o.num(u64, "interval-s", 10) catch return fail("bad --interval-s", .{});
    const heartbeat_s = o.num(u64, "heartbeat-s", 0) catch return fail("bad --heartbeat-s", .{});
    var gauge_rules: std.ArrayList(watch.GaugeRule) = .empty;
    defer gauge_rules.deinit(gpa);
    for (o.all("rule")) |s| gauge_rules.append(gpa, watch.GaugeRule.parse(s) orelse return fail("watch: bad --rule '{s}'", .{s})) catch return 1;
    var stake_rules: std.ArrayList(watch.StakeRule) = .empty;
    defer stake_rules.deinit(gpa);
    for (o.all("stake-rule")) |s| stake_rules.append(gpa, watch.StakeRule.parse(s) orelse return fail("watch: bad --stake-rule '{s}'", .{s})) catch return 1;
    var stake_text: []u8 = &.{};
    defer if (stake_text.len > 0) gpa.free(stake_text);
    var stake_tbl: std.ArrayList(watch.StakeEntry) = .empty;
    defer stake_tbl.deinit(gpa);
    if (o.one("stake-file")) |f| {
        stake_text = Io.Dir.cwd().readFileAlloc(io, f, gpa, .limited(4 << 20)) catch |e| return fail("watch: stake file: {s}", .{@errorName(e)});
        stake_tbl = watch.parseStake(gpa, stake_text) catch return 1;
    }
    if (stake_rules.items.len > 0 and stake_tbl.items.len == 0) return fail("watch: --stake-rule needs --stake-file with at least one validator", .{});
    var pair: ?[2][]const u8 = null;
    if (o.one("pair")) |p| {
        const c = std.mem.indexOfScalar(u8, p, ',') orelse return fail("watch: --pair wants PRIMARY,STANDBY", .{});
        pair = .{ p[0..c], p[c + 1 ..] };
    }
    var holders: std.ArrayList([]const u8) = .empty;
    defer holders.deinit(gpa);
    if (o.one("holders")) |h| {
        var it = std.mem.tokenizeScalar(u8, h, ',');
        while (it.next()) |x| holders.append(gpa, x) catch {};
    }
    var lease_peers: ?[]Io.net.IpAddress = null;
    defer if (lease_peers) |lp| gpa.free(lp);
    var client: ?net.Client = null;
    defer if (client) |*c| c.close();
    if (lease_acc) |la| {
        lease_peers = parsePeers(gpa, la) catch |e| return fail("watch: --lease-acceptors: {s}", .{@errorName(e)});
        const key = net.loadKey(io, o.one("key") orelse return fail("watch: --lease-acceptors needs --key", .{})) catch |e| return fail("watch: key: {s}", .{@errorName(e)});
        client = net.Client.open(io, key, lease_peers.?) catch |e| return fail("watch: socket: {s}", .{@errorName(e)});
    }
    var dog: Dog = .{ .gpa = gpa, .io = io, .alert_cmd = o.one("alert-cmd"), .label = o.one("label") orelse "", .book = watch.Book.init(gpa) };
    defer dog.book.deinit();
    const once = o.map.contains("once");
    dog.immediate = once;
    std.log.info("watching {d} target(s){s}, every {d} s", .{ targets.items.len, if (lease_acc != null) " and the lease" else "", interval_s });

    var last_lease: struct { term: u64 = 0, holder: u64 = 0 } = .{};
    var seen_max_term: u64 = 0;
    var next_hb: u64 = if (heartbeat_s > 0) heartbeat_s else std.math.maxInt(u64);
    const started = net.monoNs();
    while (true) {
        const now_s = (net.monoNs() - started) / std.time.ns_per_s;
        const now_ms = net.wallMs();
        var arena_i = std.heap.ArenaAllocator.init(gpa);
        defer arena_i.deinit();
        const arena = arena_i.allocator();
        dog.firing_now = 0;
        var findings: std.ArrayList(watch.Finding) = .empty;
        var bodies: std.ArrayList([]u8) = .empty;
        var scrapes = arena.alloc(?watch.Scrape, targets.items.len) catch return 1;
        for (targets.items, 0..) |*t, i| {
            scrapes[i] = null;
            if (net.httpGet(gpa, io, t.addr, "/metrics", 3000, 64 << 20)) |body| {
                bodies.append(arena, body) catch {};
                scrapes[i] = watch.Scrape.parse(arena, body) catch null;
            } else |_| {}
            watch.nodeFindings(arena, t.name, &t.st, if (scrapes[i]) |*s| s else null, now_s, now_ms, lim, &findings) catch {};
        }
        defer for (bodies.items) |b| gpa.free(b);
        if (pair) |p| {
            var a: ?*const watch.Scrape = null;
            var b: ?*const watch.Scrape = null;
            for (targets.items, 0..) |t, i| {
                if (std.mem.eql(u8, t.name, p[0])) a = if (scrapes[i]) |*s| s else null;
                if (std.mem.eql(u8, t.name, p[1])) b = if (scrapes[i]) |*s| s else null;
            }
            watch.standbyFinding(arena, a, b, lim, &findings) catch {};
        }
        for (findings.items) |f| dog.observe(f.key, f.bad, f.sev, f.detail, now_s, null);
        // generic gauge rules on every reachable target
        for (gauge_rules.items) |r| for (targets.items, 0..) |t, i| {
            const sc = if (scrapes[i]) |*s| s else continue;
            const key = std.fmt.allocPrint(arena, "{s}/{s}", .{ t.name, r.name }) catch continue;
            const v = r.value(sc);
            const bad = v == null or r.op.holds(v.?, r.threshold);
            const detail = if (v) |x| std.fmt.allocPrint(arena, "{s} = {d} ({s} {d})", .{ r.metric, x, r.op.text(), r.threshold }) catch "" else std.fmt.allocPrint(arena, "{s} is not reported", .{r.metric}) catch "";
            dog.observe(key, bad, r.sev, detail, now_s, r.for_s);
        };
        for (stake_rules.items) |r| for (targets.items, 0..) |t, i| {
            const sc = if (scrapes[i]) |*s| s else continue;
            const res = r.evaluate(sc, stake_tbl.items);
            const key = std.fmt.allocPrint(arena, "{s}/{s}", .{ t.name, r.name }) catch continue;
            const detail = std.fmt.allocPrint(arena, "{d:.1}% of stake is bad on {s} (limit {d:.1}%)", .{ res.bad_pct, r.metric, r.max_bad_pct }) catch "";
            dog.observe(key, res.bad, r.sev, detail, now_s, r.for_s);
        };
        // lease health
        if (client) |*c| {
            const rep = queryAll(c, lease_peers.?.len);
            var up: usize = 0;
            var live_holder: u64 = 0;
            var live_term: u64 = 0;
            var live_votes: usize = 0;
            var max_term: u64 = 0;
            for (rep[0..lease_peers.?.len]) |m| {
                const r = m orelse continue;
                up += 1;
                max_term = @max(max_term, r.term);
                if (r.holder != 0 and r.remaining_ms > 0) {
                    if (r.holder == live_holder and r.term == live_term) live_votes += 1 else if (live_votes == 0 or r.term > live_term) {
                        live_holder = r.holder;
                        live_term = r.term;
                        live_votes = 1;
                    }
                }
            }
            const n = lease_peers.?.len;
            dog.observe("lease/acceptors", up * 2 <= n, .crit, std.fmt.allocPrint(arena, "{d} of {d} lease acceptors answer (a majority is needed)", .{ up, n }) catch "", now_s, null);
            const has_leader = live_votes * 2 > n;
            dog.observe("lease/holder", up * 2 > n and !has_leader, .warn, "no node holds the lease: nothing is cleared to serve or sign", now_s, null);
            dog.observe("lease/term-regress", max_term < seen_max_term, .crit, std.fmt.allocPrint(arena, "highest lease term went from {d} to {d}: an acceptor lost its state", .{ seen_max_term, max_term }) catch "", now_s, 0);
            seen_max_term = @max(seen_max_term, max_term);
            if (has_leader and (live_term != last_lease.term or live_holder != last_lease.holder)) {
                if (last_lease.term != 0) {
                    var b: [200]u8 = undefined;
                    const t = std.fmt.bufPrint(&b, "lease moved to {s} (term {d})", .{ holderName(holders.items, live_holder), live_term }) catch "lease moved";
                    dog.send("INFO", t);
                }
                last_lease = .{ .term = live_term, .holder = live_holder };
            }
        }
        if (heartbeat_s > 0 and now_s >= next_hb) {
            next_hb = now_s + heartbeat_s;
            var b: [120]u8 = undefined;
            dog.send("INFO", std.fmt.bufPrint(&b, "watchdog alive, {d} alert(s) firing", .{dog.firing_now}) catch "watchdog alive");
        }
        if (once) return if (dog.firing_now == 0) 0 else 1;
        var waited: u64 = 0;
        while (waited < interval_s * 1000 and !g_stop.load(.acquire)) : (waited += 100) net.sleepMs(100);
        if (g_stop.load(.acquire)) return 0;
    }
}
