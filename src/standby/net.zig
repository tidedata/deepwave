//! Sockets, files, processes and clocks for the standby daemons. Everything blocking, one
//! thread per daemon, bounded waits. The protocol logic lives in lease.zig and watch.zig.
const std = @import("std");
const Io = std.Io;
const lease = @import("lease.zig");

const ms_ns = std.time.ns_per_ms;

pub fn monoNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn wallMs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / ms_ns;
}

pub fn sleepMs(n: u64) void {
    var ts: std.c.timespec = .{ .sec = @intCast(n / 1000), .nsec = @intCast((n % 1000) * ms_ns) };
    _ = std.c.nanosleep(&ts, &ts);
}

/// `host:port` or `[v6]:port` (an IP, not a name).
pub fn parseAddr(text: []const u8) !Io.net.IpAddress {
    const c = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.BadAddress;
    var host = text[0..c];
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
    const port = std.fmt.parseInt(u16, text[c + 1 ..], 10) catch return error.BadAddress;
    return Io.net.IpAddress.parse(host, port) catch error.BadAddress;
}

pub fn sameAddr(a: Io.net.IpAddress, b: Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => |x| switch (b) {
            .ip4 => |y| x.port == y.port and std.mem.eql(u8, &x.bytes, &y.bytes),
            else => false,
        },
        .ip6 => |x| switch (b) {
            .ip6 => |y| x.port == y.port and std.mem.eql(u8, &x.bytes, &y.bytes),
            else => false,
        },
    };
}

fn pollIn(fd: std.c.fd_t, timeout_ms: i32) bool {
    var fds = [1]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = std.posix.poll(&fds, timeout_ms) catch return false;
    return n > 0 and fds[0].revents & (std.posix.POLL.IN | std.posix.POLL.HUP) != 0;
}

/// TCP connect with a deadline (std's connect has no timeout on POSIX): non-blocking connect,
/// poll for writability, check SO_ERROR, back to blocking mode.
pub fn connectTimeout(addr: Io.net.IpAddress, timeout_ms: u32) !std.c.fd_t {
    const posix = std.posix;
    const c = std.c;
    var sa: extern union { any: posix.sockaddr, in: posix.sockaddr.in, in6: posix.sockaddr.in6 } = undefined;
    var len: c.socklen_t = undefined;
    var family: c_int = undefined;
    switch (addr) {
        .ip4 => |v| {
            sa.in = .{ .port = std.mem.nativeToBig(u16, v.port), .addr = @bitCast(v.bytes) };
            len = @sizeOf(posix.sockaddr.in);
            family = posix.AF.INET;
        },
        .ip6 => |v| {
            sa.in6 = .{ .port = std.mem.nativeToBig(u16, v.port), .flowinfo = v.flow, .addr = v.bytes, .scope_id = 0 };
            len = @sizeOf(posix.sockaddr.in6);
            family = posix.AF.INET6;
        },
    }
    const fd = c.socket(@intCast(family), posix.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer _ = c.close(fd);
    const fl = c.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    if (fl < 0) return error.SocketFailed;
    const nb: c_int = @bitCast(std.c.O{ .NONBLOCK = true });
    _ = c.fcntl(fd, posix.F.SETFL, fl | nb);
    const rc = c.connect(fd, &sa.any, len);
    if (rc != 0) {
        if (std.posix.errno(rc) != .INPROGRESS) return error.ConnectFailed;
        var fds = [1]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
        const n = posix.poll(&fds, @intCast(@min(timeout_ms, 60_000))) catch return error.ConnectFailed;
        if (n == 0) return error.Timeout;
        var soerr: c_int = 0;
        var sl: c.socklen_t = @sizeOf(c_int);
        _ = c.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, std.mem.asBytes(&soerr), &sl);
        if (soerr != 0) return error.ConnectFailed;
    }
    _ = c.fcntl(fd, posix.F.SETFL, fl);
    return fd;
}

// ---------------------------------------------------------------------------------- HTTP GET

/// GET http://addr/path (plain HTTP/1.1, `connection: close`), body only, 2xx or an error. Caps
/// the body at `max_body`. Used for the node's metrics and health endpoints.
pub fn httpGet(gpa: std.mem.Allocator, io: Io, addr_text: []const u8, path: []const u8, timeout_ms: u32, max_body: usize) ![]u8 {
    _ = io;
    const addr = try parseAddr(addr_text);
    const fd = connectTimeout(addr, timeout_ms) catch return error.ConnectFailed;
    defer _ = std.c.close(fd);
    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\nhost: {s}\r\nconnection: close\r\naccept: */*\r\n\r\n", .{ path, addr_text });
    var off: usize = 0;
    while (off < req.len) {
        const n = std.c.write(fd, req[off..].ptr, req.len - off);
        if (n <= 0) return error.WriteFailed;
        off += @intCast(n);
    }
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    const deadline = monoNs() + @as(u64, timeout_ms) * ms_ns;
    var chunk: [16384]u8 = undefined;
    while (true) {
        const now = monoNs();
        if (now >= deadline) return error.Timeout;
        if (!pollIn(fd, @intCast(@min((deadline - now) / ms_ns + 1, 60_000)))) continue;
        const n = std.c.read(fd, &chunk, chunk.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        try buf.appendSlice(gpa, chunk[0..@intCast(n)]);
        if (buf.items.len > max_body + 4096) return error.TooLarge;
    }
    const he = std.mem.indexOf(u8, buf.items, "\r\n\r\n") orelse return error.BadResponse;
    const status_line_end = std.mem.indexOfScalar(u8, buf.items, '\r').?;
    var parts = std.mem.tokenizeScalar(u8, buf.items[0..status_line_end], ' ');
    _ = parts.next();
    const code = std.fmt.parseInt(u16, parts.next() orelse return error.BadResponse, 10) catch return error.BadResponse;
    if (code < 200 or code > 299) return error.HttpStatus;
    const body = buf.items[he + 4 ..];
    if (body.len > max_body) return error.TooLarge;
    // chunked bodies are not produced by the endpoints we scrape; refuse rather than misparse
    if (std.mem.indexOf(u8, buf.items[0..he], "ransfer-") != null and std.mem.indexOf(u8, buf.items[0..he], "hunked") != null) return error.BadResponse;
    std.mem.copyForwards(u8, buf.items[0..body.len], body);
    buf.shrinkRetainingCapacity(body.len);
    return buf.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------------- key, state

pub fn loadKey(io: Io, path: []const u8) ![32]u8 {
    var buf: [256]u8 = undefined;
    const s = Io.Dir.cwd().readFile(io, path, &buf) catch return error.KeyUnreadable;
    const t = std.mem.trim(u8, s, " \t\r\n");
    var key: [32]u8 = undefined;
    if (t.len == 64) {
        _ = std.fmt.hexToBytes(&key, t) catch return error.BadKey;
        return key;
    }
    if (t.len >= 32) { // raw secret of any length: stretch to a key
        std.crypto.hash.sha2.Sha256.hash(t, &key, .{});
        return key;
    }
    return error.BadKey;
}

pub fn writeKeyFile(io: Io, path: []const u8) !void {
    var key: [32]u8 = undefined;
    io.random(&key);
    var hex: [65]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}\n", .{&key}) catch unreachable;
    const f = try Io.Dir.cwd().createFile(io, path, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer f.close(io);
    try f.writePositionalAll(io, &hex, 0);
}

pub fn loadState(io: Io, path: []const u8) !lease.State {
    var buf: [lease.State.file_len + 8]u8 = undefined;
    const s = Io.Dir.cwd().readFile(io, path, &buf) catch |e| switch (e) {
        error.FileNotFound => return .{},
        else => return e,
    };
    // A corrupt state file must not become "no lease": refuse to start, the operator decides.
    return lease.State.decode(s) orelse error.CorruptState;
}

/// Write-rename-fsync: the new state is on disk (file and directory entry) when this returns.
pub fn saveState(io: Io, path: []const u8, st: lease.State) !void {
    var b: [lease.State.file_len]u8 = undefined;
    st.encode(&b);
    var tmp_buf: [512]u8 = undefined;
    const tmp = try std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path});
    const cwd = Io.Dir.cwd();
    {
        const f = try cwd.createFile(io, tmp, .{ .truncate = true });
        defer f.close(io);
        try f.writePositionalAll(io, &b, 0);
        try f.sync(io);
    }
    try cwd.rename(tmp, cwd, path, io);
    const parent = std.fs.path.dirname(path) orelse ".";
    var d = try cwd.openDir(io, parent, .{ .iterate = true });
    defer d.close(io);
    _ = std.c.fsync(d.handle);
}

// ------------------------------------------------------------------------------- acceptor loop

pub const Acceptor = struct {
    io: Io,
    sock: Io.net.Socket,
    key: [32]u8,
    core: lease.Acceptor,
    state_path: []const u8,
    stop: *const std.atomic.Value(bool),
    served: u64 = 0,
    refused: u64 = 0,

    pub fn open(io: Io, listen: Io.net.IpAddress, key: [32]u8, cfg: lease.AcceptorConfig, state_path: []const u8, stop: *const std.atomic.Value(bool)) !Acceptor {
        const st = try loadState(io, state_path);
        const sock = try Io.net.IpAddress.bind(&listen, io, .{ .mode = .dgram });
        return .{ .io = io, .sock = sock, .key = key, .core = lease.Acceptor.init(cfg, st, monoNs()), .state_path = state_path, .stop = stop };
    }

    pub fn close(a: *Acceptor) void {
        a.sock.close(a.io);
    }

    /// Runs until `stop`.
    pub fn run(a: *Acceptor) void {
        var rx: [256]u8 = undefined;
        var tx: [lease.Msg.wire_len]u8 = undefined;
        while (!a.stop.load(.acquire)) {
            if (!pollIn(a.sock.handle, 200)) continue;
            const m = a.sock.receive(a.io, &rx) catch continue;
            const req = lease.Msg.decode(m.data, &a.key) catch {
                a.refused += 1;
                continue;
            };
            if (!lease.Acceptor.answers(req)) continue;
            const out = a.core.handle(monoNs(), wallMs(), req);
            if (out.persist) |st| {
                saveState(a.io, a.state_path, st) catch |e| {
                    // Not durable: do not announce the grant. The in-memory lease still blocks
                    // others, and the next request for it tries the write again.
                    std.log.err("acceptor: state write failed ({s}); grant not sent", .{@errorName(e)});
                    continue;
                };
                a.core.markPersisted(st);
            }
            out.reply.encode(&a.key, &tx);
            a.sock.send(a.io, &m.from, &tx) catch {};
            a.served += 1;
        }
    }
};

// ------------------------------------------------------------------------------------ client

/// What the agent and `status` use to talk to the acceptors: one UDP socket, broadcast a message,
/// feed replies to a callback until the deadline.
pub const Client = struct {
    io: Io,
    sock: Io.net.Socket,
    key: [32]u8,
    peers: []const Io.net.IpAddress,

    pub fn open(io: Io, key: [32]u8, peers: []const Io.net.IpAddress) !Client {
        // Same address family as the peers (the first one decides; mixing is not supported).
        const any: Io.net.IpAddress = if (peers.len > 0 and peers[0] == .ip6) .{ .ip6 = Io.net.Ip6Address.unspecified(0) } else .{ .ip4 = Io.net.Ip4Address.unspecified(0) };
        const sock = try Io.net.IpAddress.bind(&any, io, .{ .mode = .dgram });
        return .{ .io = io, .sock = sock, .key = key, .peers = peers };
    }

    pub fn close(c: *Client) void {
        c.sock.close(c.io);
    }

    pub fn broadcast(c: *Client, m: lease.Msg) void {
        var tx: [lease.Msg.wire_len]u8 = undefined;
        m.encode(&c.key, &tx);
        for (c.peers) |*p| c.sock.send(c.io, p, &tx) catch {};
    }

    pub const Reply = struct { idx: u8, msg: lease.Msg };

    /// One reply if one arrives within `wait_ms`; replies from unknown addresses and messages that
    /// do not authenticate are dropped.
    pub fn recv(c: *Client, wait_ms: i32) ?Reply {
        var rx: [256]u8 = undefined;
        if (!pollIn(c.sock.handle, wait_ms)) return null;
        const m = c.sock.receive(c.io, &rx) catch return null;
        const msg = lease.Msg.decode(m.data, &c.key) catch return null;
        for (c.peers, 0..) |p, i| if (sameAddr(p, m.from)) return .{ .idx = @intCast(i), .msg = msg };
        return null;
    }
};

// ------------------------------------------------------------------------------------- hooks

pub const HookResult = enum { ok, failed, timeout, spawn_failed };

/// Runs `sh -c cmd deepwave-standby-hook ARGS...` ($1.. are the args; for lease hooks $1 is the
/// fencing term) with a time limit. Output goes to the log.
pub fn runHook(gpa: std.mem.Allocator, io: Io, cmd: []const u8, args: []const []const u8, timeout_ms: u32) HookResult {
    const to: Io.Timeout = .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(timeout_ms), .clock = .awake } };
    var argv: [12][]const u8 = undefined;
    argv[0] = "/bin/sh";
    argv[1] = "-c";
    // A command with no `$` of its own gets the arguments appended ("tools/standby/alert.sh" works as is).
    var cmd_buf: [1024]u8 = undefined;
    argv[2] = if (std.mem.indexOfScalar(u8, cmd, '$') == null) (std.fmt.bufPrint(&cmd_buf, "{s} \"$@\"", .{cmd}) catch cmd) else cmd;
    argv[3] = "deepwave-standby-hook";
    const n = @min(args.len, argv.len - 4);
    for (args[0..n], 0..) |a, i| argv[4 + i] = a;
    const res = std.process.run(gpa, io, .{ .argv = argv[0 .. 4 + n], .timeout = to }) catch |e| return if (e == error.Timeout) .timeout else .spawn_failed;
    defer gpa.free(res.stdout);
    defer gpa.free(res.stderr);
    const out = std.mem.trim(u8, if (res.stderr.len > 0) res.stderr else res.stdout, " \r\n");
    if (out.len > 0) std.log.info("hook: {s}", .{out[0..@min(out.len, 400)]});
    return switch (res.term) {
        .exited => |c| if (c == 0) .ok else .failed,
        else => .failed,
    };
}

// ------------------------------------------------------------------------------------- tests

test "state file: save, load, corrupt is refused, missing is empty" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPathFile(io, ".", &pbuf);
    var path_buf: [std.fs.max_path_bytes + 16]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/acceptor.state", .{pbuf[0..dir]});
    try std.testing.expectEqual(lease.State{}, try loadState(io, path));
    try saveState(io, path, .{ .term = 9, .holder = 5, .lease_ms = 6000 });
    try std.testing.expectEqual(lease.State{ .term = 9, .holder = 5, .lease_ms = 6000 }, try loadState(io, path));
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "garbage-garbage-garbage!" });
    try std.testing.expectError(error.CorruptState, loadState(io, path));
}

test "acceptor and client over loopback UDP, wrong key ignored" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = pbuf[0..try tmp.dir.realPathFile(io, ".", &pbuf)];
    var path_buf: [std.fs.max_path_bytes + 16]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/a.state", .{dir});
    const key: [32]u8 = @splat(3);
    var stop: std.atomic.Value(bool) = .init(false);
    var acc = try Acceptor.open(io, try parseAddr("127.0.0.1:0"), key, .{ .id = 42 }, path, &stop);
    defer acc.close();
    const target = acc.sock.address;
    const th = try std.Thread.spawn(.{}, Acceptor.run, .{&acc});
    const peers = [_]Io.net.IpAddress{target};
    var c = try Client.open(io, key, &peers);
    defer c.close();
    const req: lease.Msg = .{ .kind = .acquire, .seq = (wallMs() << 20) + 1, .wall_ms = wallMs(), .term = 1, .holder = 77, .lease_ms = 5000 };
    c.broadcast(req);
    const got = c.recv(2000) orelse return error.NoReply;
    try std.testing.expect(got.msg.ok and got.msg.term == 1 and got.msg.holder == 77);
    // the grant is durable before the reply: the state file already holds it
    try std.testing.expectEqual(@as(u64, 1), (try loadState(io, path)).term);
    // another holder is refused while the lease is live
    var other = req;
    other.holder = 78;
    other.term = 2;
    other.seq += 1;
    c.broadcast(other);
    const r2 = c.recv(2000) orelse return error.NoReply;
    try std.testing.expect(!r2.msg.ok and r2.msg.holder == 77);
    // a client with another key gets no answer
    var bad = try Client.open(io, @splat(9), &peers);
    defer bad.close();
    bad.broadcast(req);
    try std.testing.expect(bad.recv(300) == null);
    stop.store(true, .release);
    th.join();
}

test "hook: runs with arguments, reports a failing exit" {
    const gpa = std.testing.allocator;
    try std.testing.expectEqual(HookResult.ok, runHook(gpa, std.testing.io, "test \"$1\" = 7", &.{"7"}, 5000));
    try std.testing.expectEqual(HookResult.failed, runHook(gpa, std.testing.io, "exit 3", &.{}, 5000));
    try std.testing.expectEqual(HookResult.ok, runHook(gpa, std.testing.io, "true", &.{ "a", "b" }, 5000));
}
