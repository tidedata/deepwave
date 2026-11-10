//! The admin port (sui-node `admin.rs`, 1.83.1): plain HTTP/1.1 on 127.0.0.1 (default port
//! 1337, `admin-interface-port`), no authentication, on its own thread so it answers while the
//! node is stuck. Routes, sui-node compatible where a full node has them:
//!
//!   GET  /logging        the log filter text (200)
//!   POST /logging        body = new filter; 200 "" and an INFO line, or 400 with the parse error
//!   GET  /capabilities   authority capabilities seen this epoch: always empty on a full node (200 "")
//!   GET  /node-config    the run configuration, one `key = value` per line (no secrets held)
//!   GET  /version        `deepwave <version>-<sha>` and the protocol range (deepwave only)
//!   GET  /get-tx-cost?tx_digest=D   400 for a digest that is not base58 of 32 bytes (sui-node
//!                        panics and aborts the node there), else 404: deepwave has no consensus cost
//!                        estimates on a full node
//!   GET  /transaction-deny-config   the deny config dump (sui-node `transaction_deny_config_dump`:
//!                        local, peers, effective, voting as pretty JSON; a full node has no peer votes)
//!   POST /traffic-control?error_threshold=N&spam_threshold=N&dry_run=B   retune the traffic
//!                        controller (sui-node's texts; see serve/traffic.zig `admin`)
//!   POST /enable-tracing?filter=F&duration=D[&trace_file=P][&sample_rate=R]   the trace filter
//!                        (logfilter.zig `setTrace`: lines it enables are logged) for D, then
//!                        reset; sui-node's texts and order (sample rate, trace file, filter)
//!   POST /reset-tracing  the trace filter back to TRACE_FILTER (or off) now
//!   POST /update-endpoint?endpoint_type=p2p|consensus&id=HEX&addresses=A,B   an admin address
//!                        override for a p2p peer (net/peer_pool.zig `admin_overrides`); consensus
//!                        updates are accepted and dropped, as a full node buffers them for a
//!                        consensus updater it never gets
//!   GET  /db-shell/ls, GET /db-shell/read, DELETE /db-shell/delete   the store as sui-node's
//!                        db-shell file system (admin_dbshell.zig)
//!   GET  /address-prober-report   503: a full node runs no address prober (sui-node's text)
//!
//! Anything else is 404, a known route with another method 405 (axum). Every request is read
//! with a 5 s deadline and a 64 KiB cap, one connection at a time.
const std = @import("std");
const Io = std.Io;
const serve = @import("serve");
const sock = serve.h2.sock;
const logfilter = @import("logfilter.zig");
const rpc_exec = @import("rpc_exec");
const net = @import("net");
const util = @import("admin_util.zig");
pub const dbshell = @import("admin_dbshell.zig");

/// The node's traffic controller (`policy-config`; null: `policy-config: null`, the kill switch).
/// Set once before the admin server starts.
pub var traffic_ctl: ?*serve.traffic.Controller = null;
const Atomic = std.atomic.Value;

pub const default_port: u16 = 1337;
const max_request = 64 << 10;
const read_timeout_ms = 5000;

pub const Source = struct {
    ctx: *anyopaque,
    /// `/node-config` body.
    config: *const fn (ctx: *anyopaque, w: *std.Io.Writer) anyerror!void,
    /// `/version` body.
    version: *const fn (ctx: *anyopaque, w: *std.Io.Writer) anyerror!void,
    /// The db-shell routes' data (null: they answer 503).
    db: ?dbshell.Source = null,
};

pub const Response = struct { code: u16, body: []const u8 };

fn reason(code: u16) []const u8 {
    return switch (code) {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        422 => "Unprocessable Entity",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        413 => "Payload Too Large",
        else => "Internal Server Error",
    };
}

/// Answers one parsed request into `out` (route logic, no IO; unit-tested).
pub fn route(gpa: std.mem.Allocator, src: Source, method: []const u8, target: []const u8, body: []const u8, out: *std.Io.Writer.Allocating) !u16 {
    var ct: []const u8 = dbshell.text_plain;
    return routeCt(gpa, src, method, target, body, out, &ct);
}

/// `route`, and the response's content type into `ct` (text/plain unless a route says else).
pub fn routeCt(gpa: std.mem.Allocator, src: Source, method: []const u8, target: []const u8, body: []const u8, out: *std.Io.Writer.Allocating, ct: *[]const u8) !u16 {
    const eql = std.mem.eql;
    const q = std.mem.indexOfScalar(u8, target, '?');
    const path = if (q) |i| target[0..i] else target;
    const query = if (q) |i| target[i + 1 ..] else "";
    const get = eql(u8, method, "GET");
    const post = eql(u8, method, "POST");
    if (eql(u8, path, "/logging")) {
        if (get) {
            var buf: [512]u8 = undefined;
            try out.writer.writeAll(logfilter.get(&buf));
            return 200;
        }
        if (post) {
            logfilter.set(body) catch |e| {
                try out.writer.print("invalid filter: {s}", .{@errorName(e)});
                return 400;
            };
            std.log.info("Log filter updated: {s}", .{std.mem.trim(u8, body, " \t\r\n")});
            return 200;
        }
        return 405;
    }
    if (eql(u8, path, "/capabilities")) return if (get) 200 else 405;
    if (eql(u8, path, "/node-config")) {
        if (!get) return 405;
        try src.config(src.ctx, &out.writer);
        return 200;
    }
    if (eql(u8, path, "/version")) {
        if (!get) return 405;
        try src.version(src.ctx, &out.writer);
        return 200;
    }
    if (eql(u8, path, "/transaction-deny-config")) {
        if (!get) return 405;
        try rpc_exec.txdeny.writeDump(&out.writer, rpc_exec.txdeny.current());
        return 200;
    }
    if (eql(u8, path, "/broadcast-transaction-deny-config") or eql(u8, path, "/withdraw-transaction-deny-config")) {
        if (!post) return 405;
        // sui-node on a full node: no consensus adapter
        try out.writer.writeAll("validator components not running; consensus adapter unavailable\n");
        return 503;
    }
    if (eql(u8, path, "/traffic-control")) {
        if (!post) return 405;
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const ans = try serve.traffic.admin(arena.allocator(), traffic_ctl, query);
        try out.writer.writeAll(ans.body);
        // 0: sui-node's handler panics (allowlist mode); the connection closes without a reply
        return ans.code;
    }
    if (eql(u8, path, "/get-tx-cost")) {
        if (!get) return 405;
        const d = queryParam(query, "tx_digest") orelse {
            try out.writer.writeAll("missing tx_digest");
            return 400;
        };
        if (d.len < 32 or d.len > serve.b58.max_len_32 or serve.b58.decode32(d) == null) {
            try out.writer.writeAll("invalid tx_digest");
            return 400;
        }
        try out.writer.writeAll("no cost estimate for this transaction (zui keeps no consensus cost estimates)");
        return 404;
    }
    if (eql(u8, path, "/enable-tracing")) {
        if (!post) return 405;
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        return enableTracing(arena.allocator(), query, &out.writer);
    }
    if (eql(u8, path, "/reset-tracing")) {
        if (!post) return 405;
        logfilter.resetTrace();
        std.log.info("admin: trace filter reset to TRACE_FILTER ({s})", .{logfilter.traceEnv() orelse "unset: off"});
        try out.writer.writeAll("tracing filter reset to TRACE_FILTER env var");
        return 200;
    }
    if (eql(u8, path, "/update-endpoint")) {
        if (!post) return 405;
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        return updateEndpoint(arena.allocator(), query, &out.writer, &net.peer_pool.admin_overrides);
    }
    if (eql(u8, path, "/address-prober-report")) {
        if (!get) return 405;
        try out.writer.writeAll("address prober is not running (node is not a validator, or the prober is disabled)\n");
        return 503;
    }
    const db_ls = eql(u8, path, "/db-shell/ls");
    const db_read = eql(u8, path, "/db-shell/read");
    const db_delete = eql(u8, path, "/db-shell/delete");
    if (db_ls or db_read or db_delete) {
        if (db_delete and !eql(u8, method, "DELETE")) return 405;
        if (!db_delete and !get) return 405;
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const ans = if (db_delete) try dbshell.delete(a, query) else if (src.db) |db|
            (if (db_ls) try dbshell.ls(a, db, query) else try dbshell.read(a, db, query))
        else
            dbshell.Answer{ .code = 503, .body = "db-shell: no store attached to the admin port" };
        try out.writer.writeAll(ans.body);
        ct.* = ans.content_type;
        return ans.code;
    }
    return 404;
}

// ---- /enable-tracing, /reset-tracing ------------------------------------------------------------

/// The sample rate sui-node's sampler would use (clamped to 0.0001..1; deepwave exports no spans).
pub var trace_sample_rate: f64 = 1.0;
/// The trace file `update_trace_file` opened last (deepwave writes nothing to it).
var trace_file_buf: [4096]u8 = undefined;
var trace_file_len: ?usize = null;

/// `enable_tracing`: query, then sample rate, trace file and filter in that order, each adding a
/// line; the first failure ends it with 400 and the lines so far.
fn enableTracing(arena: std.mem.Allocator, query: []const u8, w: *std.Io.Writer) !u16 {
    var filter: ?[]const u8 = null;
    var duration: ?[]const u8 = null;
    var trace_file: ?[]const u8 = null;
    var sample_rate: ?f64 = null;
    var seen: [4]bool = @splat(false);
    const names = [_][]const u8{ "filter", "duration", "trace_file", "sample_rate" };
    for (try util.pairs(arena, query)) |kv| {
        const i = for (names, 0..) |n, k| {
            if (std.mem.eql(u8, kv.key, n)) break k;
        } else continue;
        if (seen[i]) {
            try w.print(util.query_reject ++ "duplicate field `{s}`", .{names[i]});
            return 400;
        }
        seen[i] = true;
        switch (i) {
            0 => filter = kv.value,
            1 => duration = kv.value,
            2 => trace_file = kv.value,
            else => sample_rate = util.parseF64(kv.value) catch |e| {
                try w.print(util.query_reject ++ "sample_rate: {s}", .{util.floatErrorText(e)});
                return 400;
            },
        }
    }
    var lines: std.Io.Writer.Allocating = .init(arena);
    const l = &lines.writer;
    var first = true;
    const Line = struct {
        fn sep(lw: *std.Io.Writer, f: *bool) !void {
            if (!f.*) try lw.writeByte('\n');
            f.* = false;
        }
    };
    if (sample_rate) |r| {
        trace_sample_rate = if (std.math.isNan(r)) r else std.math.clamp(r, 0.0001, 1.0);
        try Line.sep(l, &first);
        try l.writeAll("sample rate set to ");
        try util.writeF64Debug(l, r);
    }
    if (trace_file) |path| {
        try Line.sep(l, &first);
        if (openTraceFile(path, l)) {
            try l.writeAll("trace file set to ");
            try util.writeStrDebug(l, path);
        } else |_| {
            try w.writeAll(lines.written());
            return 400;
        }
    }
    const f = filter orelse {
        try w.writeAll(lines.written());
        return 200;
    };
    try Line.sep(l, &first);
    const dtext = duration orelse {
        try l.writeAll("can't update filter: missing duration");
        try w.writeAll(lines.written());
        return 400;
    };
    const d = util.parseDuration(dtext) catch {
        try l.writeAll("can't update filter: invalid duration");
        try w.writeAll(lines.written());
        return 400;
    };
    logfilter.setTrace(f) catch |e| {
        // sui-node checks the filter only with tracing on (TRACE_FILTER set at start); without
        // it the update is ignored and answered OK
        if (logfilter.traceEnv() != null) {
            try l.print("can't update filter: ParseError {{ kind: {s} }}", .{if (e == error.BadLevel) "Level(ParseLevelFilterError(()))" else "Other(None)"});
            try w.writeAll(lines.written());
            return 400;
        }
        std.log.warn("admin: trace filter {s} not understood by zui ({s}); ignored", .{ f, @errorName(e) });
        return tracingOk(l, w, &lines, f, d);
    };
    startTraceReset(d);
    std.log.info("admin: trace filter set to {s} for {d} s", .{ f, d.secs });
    return tracingOk(l, w, &lines, f, d);
}

fn tracingOk(l: *std.Io.Writer, w: *std.Io.Writer, lines: *std.Io.Writer.Allocating, f: []const u8, d: util.Duration) !u16 {
    try l.writeAll("filter set to ");
    try util.writeStrDebug(l, f);
    try l.writeAll("\nfilter will be reset after ");
    try util.writeDurationDebug(l, d);
    try w.writeAll(lines.written());
    return 200;
}

/// `CachedOpenFile::update_path`: the same path again is a no-op, else the file is opened for
/// append (created if missing). On failure the line `can't update trace file: <io::Error>`.
fn openTraceFile(path: []const u8, l: *std.Io.Writer) !void {
    if (trace_file_len) |n| if (std.mem.eql(u8, trace_file_buf[0..n], path)) return;
    var z: [4097]u8 = undefined;
    if (std.mem.indexOfScalar(u8, path, 0) != null) {
        try l.writeAll("can't update trace file: " ++ util.nul_path_debug);
        return error.TraceFile;
    }
    if (path.len >= z.len) {
        try l.writeAll("can't update trace file: ");
        try util.writeIoErrorDebug(l, @intFromEnum(std.c.E.NAMETOOLONG), "NAMETOOLONG");
        return error.TraceFile;
    }
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    const rc = std.c.open(@ptrCast(&z), .{ .ACCMODE = .WRONLY, .APPEND = true, .CREAT = true, .CLOEXEC = true }, @as(c_uint, 0o666));
    if (rc < 0) {
        const e = std.c.errno(rc);
        try l.writeAll("can't update trace file: ");
        try util.writeIoErrorDebug(l, @intCast(@intFromEnum(e)), @tagName(e));
        return error.TraceFile;
    }
    _ = std.c.close(rc);
    @memcpy(trace_file_buf[0..path.len], path);
    trace_file_len = path.len;
}

/// sui-node spawns one task per update that resets the trace filter once its duration is over
/// (whatever was set since): one detached thread here.
fn startTraceReset(d: util.Duration) void {
    const ns = util.durationNs(d);
    const now = serve.h2.meta.monoNs();
    const deadline: u64 = if (ns >= std.math.maxInt(u64) - now) std.math.maxInt(u64) else now + @as(u64, @intCast(ns));
    // 1 MiB, not 64 KiB: glibc refuses (EINVAL, which std.Thread treats as unreachable) a stack
    // smaller than the binary's static TLS plus its minimum; the merged node's TLS outgrew 64 KiB.
    const t = std.Thread.spawn(.{ .stack_size = 1 << 20 }, traceResetMain, .{deadline}) catch |e| {
        std.log.warn("admin: trace filter reset timer not started: {s}", .{@errorName(e)});
        return;
    };
    t.detach();
}

fn traceResetMain(deadline: u64) void {
    while (true) {
        const now = serve.h2.meta.monoNs();
        if (now >= deadline) break;
        sock.sleepMs(@min((deadline - now) / std.time.ns_per_ms + 1, 1000));
    }
    logfilter.resetTrace();
    std.log.info("admin: trace filter reset after its duration", .{});
}

// ---- /update-endpoint ---------------------------------------------------------------------------

/// `update_endpoint`: `endpoint_type`, `id` and `addresses` are required (axum `Query`), then the
/// id, then every address as a multiaddr.
fn updateEndpoint(arena: std.mem.Allocator, query: []const u8, w: *std.Io.Writer, overrides: *net.peer_pool.Overrides) !u16 {
    const names = [_][]const u8{ "endpoint_type", "id", "addresses" };
    var vals: [3]?[]const u8 = @splat(null);
    for (try util.pairs(arena, query)) |kv| {
        const i = for (names, 0..) |n, k| {
            if (std.mem.eql(u8, kv.key, n)) break k;
        } else continue;
        if (vals[i] != null) {
            try w.print(util.query_reject ++ "duplicate field `{s}`", .{names[i]});
            return 400;
        }
        vals[i] = kv.value;
    }
    for (vals, names) |v, n| if (v == null) {
        try w.print(util.query_reject ++ "missing field `{s}`", .{n});
        return 400;
    };
    const kind = vals[0].?;
    const id = vals[1].?;
    const p2p = std.mem.eql(u8, kind, "p2p");
    if (!p2p and !std.mem.eql(u8, kind, "consensus")) {
        try w.print("Unknown endpoint_type: {s}", .{kind});
        return 400;
    }
    const bytes = (try util.hexDecode(arena, id)) orelse {
        try w.writeAll("Invalid id hex encoding: " ++ util.fastcrypto_invalid_input);
        return 400;
    };
    if (p2p and bytes.len != 32) {
        try w.writeAll("p2p id must be 32 bytes");
        return 400;
    }
    if (!p2p) {
        // NetworkPublicKey::from_bytes (ed25519-consensus VerificationKey): 32 bytes, a point
        const ok = bytes.len == 32 and if (std.crypto.ecc.Edwards25519.fromBytes(bytes[0..32].*)) |_| true else |_| false;
        if (!ok) {
            try w.writeAll("Invalid network public key: InvalidInput");
            return 400;
        }
    }
    var anemo: std.ArrayList([]const u8) = .empty;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, vals[2].?, ',');
    while (it.next()) |raw| {
        const a = std.mem.trim(u8, raw, " \t\r\n\x0b\x0c");
        if (a.len == 0) continue;
        var err: []const u8 = "";
        const m = (try util.parseMultiaddr(arena, a, &err)) orelse {
            try w.print("Invalid address '{s}': {s}", .{ a, err });
            return 400;
        };
        n += 1;
        if (m.isAnemo()) try anemo.append(arena, a) else if (p2p) std.log.warn("admin: skipping peer address {s}: can't convert to anemo address", .{a});
    }
    if (p2p) {
        try overrides.set(bytes[0..32], anemo.items);
        std.log.info("admin: p2p peer {s}: {d} admin address(es) ({d} dialable){s}", .{ id, n, anemo.items.len, if (anemo.items.len == 0) ", override cleared" else "" });
    } else {
        std.log.info("admin: consensus address update for {s} buffered (a full node runs no consensus)", .{id});
    }
    try w.print("Endpoint updated for {s} endpoint {s} with {d} address(es)\n", .{ kind, id, n });
    return 200;
}

fn queryParam(query: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        if (std.mem.eql(u8, kv[0..eq], name)) return kv[eq + 1 ..];
    }
    return null;
}

pub const Server = struct {
    gpa: std.mem.Allocator,
    io: Io,
    src: Source,
    listener: Io.net.Server,
    stop: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    served: Atomic(u64) = .init(0),

    /// Binds `127.0.0.1:port` (0 picks a free port; `port()` tells which).
    pub fn start(gpa: std.mem.Allocator, io: Io, port_num: u16, src: Source) !*Server {
        const s = try gpa.create(Server);
        errdefer gpa.destroy(s);
        const addr = try Io.net.IpAddress.parse("127.0.0.1", port_num);
        s.* = .{ .gpa = gpa, .io = io, .src = src, .listener = try addr.listen(io, .{ .reuse_address = true }) };
        s.thread = try std.Thread.spawn(.{}, run, .{s});
        return s;
    }

    pub fn port(s: *const Server) u16 {
        return s.listener.socket.address.getPort();
    }

    /// Stops the accept loop (a connection to itself wakes a blocked accept) and frees the server.
    pub fn deinit(s: *Server) void {
        s.stop.store(true, .release);
        const st: Io.net.Stream = .{ .socket = s.listener.socket };
        st.shutdown(s.io, .both) catch {};
        var a = s.listener.socket.address;
        if (a.connect(s.io, .{ .mode = .stream })) |c| c.close(s.io) else |_| {}
        if (s.thread) |t| t.join();
        s.listener.deinit(s.io);
        s.gpa.destroy(s);
    }

    fn run(s: *Server) void {
        while (!s.stop.load(.acquire)) {
            const stream = s.listener.accept(s.io) catch |e| switch (e) {
                error.SocketNotListening, error.Canceled => return,
                else => {
                    sock.sleepMs(10);
                    continue;
                },
            };
            if (s.stop.load(.acquire)) {
                stream.close(s.io);
                return;
            }
            s.serveOne(stream.socket.handle);
            stream.close(s.io);
            _ = s.served.fetchAdd(1, .monotonic);
        }
    }

    fn serveOne(s: *Server, fd: std.c.fd_t) void {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(s.gpa);
        var rb: [4096]u8 = undefined;
        var head_end: ?usize = null;
        var need: usize = 0;
        while (true) {
            if (head_end == null) if (std.mem.indexOf(u8, buf.items, "\r\n\r\n")) |i| {
                head_end = i + 4;
                need = i + 4 + contentLength(buf.items[0..i]);
            };
            if (head_end != null and buf.items.len >= need) break;
            if (buf.items.len > max_request or need > max_request) return reply(fd, 413, "");
            const ready = sock.waitReadable(fd, read_timeout_ms) catch return;
            if (!ready) return;
            const n = sock.read(fd, &rb) catch return;
            if (n == 0) return;
            buf.appendSlice(s.gpa, rb[0..n]) catch return;
        }
        const he = head_end.?;
        const line_end = std.mem.indexOf(u8, buf.items, "\r\n") orelse return reply(fd, 400, "");
        var parts = std.mem.tokenizeScalar(u8, buf.items[0..line_end], ' ');
        const method = parts.next() orelse return reply(fd, 400, "");
        const target = parts.next() orelse return reply(fd, 400, "");
        var out: std.Io.Writer.Allocating = .init(s.gpa);
        defer out.deinit();
        var ct: []const u8 = dbshell.text_plain;
        const code = routeCt(s.gpa, s.src, method, target, buf.items[he..need], &out, &ct) catch 500;
        if (code == 0) return;
        replyCt(fd, code, out.writer.buffered(), ct);
    }

    fn contentLength(head: []const u8) usize {
        var it = std.mem.splitSequence(u8, head, "\r\n");
        while (it.next()) |l| {
            const c = std.mem.indexOfScalar(u8, l, ':') orelse continue;
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, l[0..c], " "), "content-length"))
                return std.fmt.parseInt(usize, std.mem.trim(u8, l[c + 1 ..], " "), 10) catch max_request + 1;
        }
        return 0;
    }

    fn reply(fd: std.c.fd_t, code: u16, body: []const u8) void {
        replyCt(fd, code, body, dbshell.text_plain);
    }

    fn replyCt(fd: std.c.fd_t, code: u16, body: []const u8, ct: []const u8) void {
        var hb: [256]u8 = undefined;
        const head = std.fmt.bufPrint(&hb, "HTTP/1.1 {d} {s}\r\ncontent-type: {s}\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n", .{ code, reason(code), ct, body.len }) catch return;
        sock.writeAll(fd, head) catch return;
        sock.writeAll(fd, body) catch return;
    }
};

test "admin: logging read and reload, capabilities, bad digests never crash" {
    const gpa = std.testing.allocator;
    defer logfilter.set(logfilter.default_text) catch unreachable;
    const Src = struct {
        fn config(_: *anyopaque, w: *std.Io.Writer) anyerror!void {
            try w.writeAll("dir = /data/zui\n");
        }
        fn version(_: *anyopaque, w: *std.Io.Writer) anyerror!void {
            try w.writeAll("deepwave 0.1.0-test\n");
        }
    };
    var dummy: u8 = 0;
    const src: Source = .{ .ctx = &dummy, .config = Src.config, .version = Src.version };
    const R = struct {
        fn call(s: Source, m: []const u8, t: []const u8, b: []const u8, want: u16, body: ?[]const u8) !void {
            var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
            defer out.deinit();
            try std.testing.expectEqual(want, try route(std.testing.allocator, s, m, t, b, &out));
            if (body) |x| try std.testing.expectEqualStrings(x, out.writer.buffered());
        }
    };
    try R.call(src, "GET", "/logging", "", 200, "info");
    try R.call(src, "POST", "/logging", "debug\n", 200, "");
    try std.testing.expect(logfilter.enabled(.debug, "default"));
    try R.call(src, "GET", "/logging", "", 200, "debug");
    try R.call(src, "POST", "/logging", "chatty", 400, null);
    try R.call(src, "GET", "/logging", "", 200, "debug");
    try R.call(src, "PUT", "/logging", "", 405, null);
    try R.call(src, "GET", "/capabilities", "", 200, "");
    // transaction-deny-config (the empty config) and traffic-control
    {
        var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer out.deinit();
        try std.testing.expectEqual(@as(u16, 200), try route(std.testing.allocator, src, "GET", "/transaction-deny-config", "", &out));
        try std.testing.expect(std.mem.startsWith(u8, out.writer.buffered(), "{\n  \"local\": {\n    \"rules\": {\n      \"object-deny-list\": [],\n"));
    }
    try R.call(src, "POST", "/transaction-deny-config", "", 405, null);
    try R.call(src, "GET", "/traffic-control", "", 405, null);
    traffic_ctl = null;
    try R.call(src, "POST", "/traffic-control?dry_run=false", "", 500, "Invalid admin request: Traffic controller is not configured on this node");
    var ctl = try serve.traffic.Controller.init(std.testing.allocator, serve.traffic.PolicyConfig.dosDefault(), serve.h2.meta.monoNs);
    defer ctl.deinit();
    traffic_ctl = &ctl;
    defer traffic_ctl = null;
    try R.call(src, "POST", "/traffic-control?error_threshold=100&spam_threshold=100&dry_run=true", "", 200, "Traffic control configured with:\nError threshold: Some(100)\nSpam threshold: Some(100)\nDry run: Some(true)\n");
    try R.call(src, "POST", "/traffic-control?error_threshold=x", "", 400, "Failed to deserialize query string: error_threshold: invalid digit found in string");
    try R.call(src, "GET", "/node-config", "", 200, "dir = /data/zui\n");
    try R.call(src, "GET", "/version", "", 200, "deepwave 0.1.0-test\n");
    try R.call(src, "GET", "/get-tx-cost?tx_digest=not-a-digest", "", 400, "invalid tx_digest");
    try R.call(src, "GET", "/get-tx-cost?tx_digest=", "", 400, "invalid tx_digest");
    try R.call(src, "GET", "/get-tx-cost", "", 400, "missing tx_digest");
    try R.call(src, "GET", "/get-tx-cost?tx_digest=4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S", "", 404, null);
    try R.call(src, "GET", "/force-close-epoch", "", 404, null);

    // Over a socket: curl-shaped requests, the level changes without a restart.
    const s = try Server.start(gpa, std.testing.io, 0, src);
    defer s.deinit();
    const addr = try Io.net.IpAddress.parse("127.0.0.1", s.port());
    const Http = struct {
        fn req(a: Io.net.IpAddress, raw: []const u8, buf: []u8) ![]const u8 {
            const c = try a.connect(std.testing.io, .{ .mode = .stream });
            defer c.close(std.testing.io);
            try sock.writeAll(c.socket.handle, raw);
            var n: usize = 0;
            while (n < buf.len) {
                if (!(try sock.waitReadable(c.socket.handle, 5000))) break;
                const k = try sock.read(c.socket.handle, buf[n..]);
                if (k == 0) break;
                n += k;
            }
            return buf[0..n];
        }
    };
    var rb: [1024]u8 = undefined;
    var r = try Http.req(addr, "POST /logging HTTP/1.1\r\nhost: localhost:1337\r\ncontent-length: 4\r\n\r\nwarn", &rb);
    try std.testing.expect(std.mem.startsWith(u8, r, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(!logfilter.enabled(.info, "default"));
    r = try Http.req(addr, "GET /logging HTTP/1.1\r\nhost: localhost:1337\r\n\r\n", &rb);
    try std.testing.expect(std.mem.endsWith(u8, r, "\r\n\r\nwarn"));
    r = try Http.req(addr, "GET /get-tx-cost?tx_digest=zzz HTTP/1.1\r\n\r\n", &rb);
    try std.testing.expect(std.mem.startsWith(u8, r, "HTTP/1.1 400 Bad Request\r\n"));
    // the server is still up after the bad digest
    r = try Http.req(addr, "GET /capabilities HTTP/1.1\r\n\r\n", &rb);
    try std.testing.expect(std.mem.startsWith(u8, r, "HTTP/1.1 200 OK\r\n"));
}

// ---- tests: tracing, update-endpoint, db-shell ---------------------------------------------------

const Call = struct {
    code: u16,
    body: []u8,
    ct: []const u8,
    fn deinit(c: Call) void {
        std.testing.allocator.free(c.body);
    }
};

fn call(src: Source, method: []const u8, target: []const u8) !Call {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var ct: []const u8 = dbshell.text_plain;
    const code = try routeCt(std.testing.allocator, src, method, target, "", &out, &ct);
    return .{ .code = code, .body = try std.testing.allocator.dupe(u8, out.writer.buffered()), .ct = ct };
}

fn expectCall(src: Source, method: []const u8, target: []const u8, code: u16, body: ?[]const u8) !void {
    const c = try call(src, method, target);
    defer c.deinit();
    if (body) |b| std.testing.expectEqualStrings(b, c.body) catch |e| {
        std.debug.print("{s} {s}\n", .{ method, target });
        return e;
    };
    try std.testing.expectEqual(code, c.code);
}

fn noSrc() Source {
    const S = struct {
        var dummy: u8 = 0;
        fn config(_: *anyopaque, _: *std.Io.Writer) anyerror!void {}
    };
    return .{ .ctx = &S.dummy, .config = S.config, .version = S.config };
}

test "admin: enable-tracing and reset-tracing (sui-node texts, the filter resets itself)" {
    if (logfilter.traceEnv() != null) return error.SkipZigTest;
    const src = noSrc();
    defer logfilter.setTrace("off") catch unreachable;
    defer logfilter.set(logfilter.default_text) catch unreachable;
    try logfilter.set("info");
    try expectCall(src, "POST", "/enable-tracing", 200, "");
    try expectCall(src, "GET", "/enable-tracing", 405, null);
    try expectCall(src, "POST", "/enable-tracing?filter=serve%3Ddebug&duration=50ms", 200, "filter set to \"serve=debug\"\nfilter will be reset after 50ms");
    try std.testing.expect(logfilter.enabled(.debug, "serve"));
    var waited: u32 = 0;
    while (logfilter.enabled(.debug, "serve") and waited < 5000) : (waited += 10) sock.sleepMs(10);
    try std.testing.expect(!logfilter.enabled(.debug, "serve"));
    try expectCall(src, "POST", "/enable-tracing?filter=info", 400, "can't update filter: missing duration");
    try expectCall(src, "POST", "/enable-tracing?filter=info&duration=1.5s", 400, "can't update filter: invalid duration");
    try expectCall(src, "POST", "/enable-tracing?sample_rate=0.5", 200, "sample rate set to 0.5");
    try expectCall(src, "POST", "/enable-tracing?sample_rate=2&filter=info", 400, "sample rate set to 2.0\ncan't update filter: missing duration");
    try expectCall(src, "POST", "/enable-tracing?sample_rate=x", 400, "Failed to deserialize query string: sample_rate: invalid float literal");
    try expectCall(src, "POST", "/enable-tracing?filter=a&filter=b", 400, "Failed to deserialize query string: duplicate field `filter`");
    try expectCall(src, "POST", "/enable-tracing?trace_file=/nonexistent-zui-dir/trace.json", 400, "can't update trace file: Os { code: 2, kind: NotFound, message: \"No such file or directory\" }");
    try expectCall(src, "POST", "/enable-tracing?filter=debug&duration=1h+30m", 200, "filter set to \"debug\"\nfilter will be reset after 5400s");
    try std.testing.expect(logfilter.enabled(.debug, "anything"));
    try expectCall(src, "POST", "/reset-tracing", 200, "tracing filter reset to TRACE_FILTER env var");
    try std.testing.expect(!logfilter.enabled(.debug, "anything"));
    try expectCall(src, "GET", "/reset-tracing", 405, null);
    // a filter deepwave cannot read: sui-node without TRACE_FILTER answers OK and changes nothing
    try expectCall(src, "POST", "/enable-tracing?filter=a%3Dloud&duration=10s", 200, "filter set to \"a=loud\"\nfilter will be reset after 10s");
    try expectCall(src, "GET", "/address-prober-report", 503, "address prober is not running (node is not a validator, or the prober is disabled)\n");
}

test "admin: update-endpoint (sui-node texts; p2p overrides, consensus accepted)" {
    const src = noSrc();
    const ov = &net.peer_pool.admin_overrides;
    defer ov.clear();
    const id = "0x" ++ "abababababababababababababababababababababababababababababababab";
    try expectCall(src, "GET", "/update-endpoint", 405, null);
    try expectCall(src, "POST", "/update-endpoint", 400, "Failed to deserialize query string: missing field `endpoint_type`");
    try expectCall(src, "POST", "/update-endpoint?endpoint_type=p2p&addresses=", 400, "Failed to deserialize query string: missing field `id`");
    try expectCall(src, "POST", "/update-endpoint?endpoint_type=x&id=00&addresses=", 400, "Unknown endpoint_type: x");
    try expectCall(src, "POST", "/update-endpoint?endpoint_type=p2p&id=zz&addresses=", 400, "Invalid id hex encoding: Invalid value was given to the function");
    try expectCall(src, "POST", "/update-endpoint?endpoint_type=p2p&id=abc&addresses=", 400, "Invalid id hex encoding: Invalid value was given to the function");
    try expectCall(src, "POST", "/update-endpoint?endpoint_type=p2p&id=00&addresses=", 400, "p2p id must be 32 bytes");
    try expectCall(src, "POST", "/update-endpoint?endpoint_type=p2p&id=" ++ id ++ "&addresses=1.2.3.4:80", 400, "Invalid address '1.2.3.4:80': invalid multiaddr");
    try expectCall(src, "POST", "/update-endpoint?endpoint_type=p2p&id=" ++ id ++ "&addresses=/ip4/1.2.3.4/udp/x", 400, "Invalid address '/ip4/1.2.3.4/udp/x': failed to parse: invalid digit found in string");
    try expectCall(src, "POST", "/update-endpoint?endpoint_type=p2p&id=" ++ id ++ "&addresses=/ip4/1.2.3.4/udp/8084,%20/dns/a.example/udp/1,/ip4/1.2.3.4/tcp/80,", 200, "Endpoint updated for p2p endpoint " ++ id ++ " with 3 address(es)\n");
    var e: net.peer_pool.Overrides.Entry = undefined;
    try std.testing.expect(ov.get(&@as([32]u8, @splat(0xab)), &e));
    try std.testing.expectEqual(@as(u8, 2), e.n_addrs);
    try std.testing.expectEqualStrings("/dns/a.example/udp/1", e.addr(1));
    try expectCall(src, "POST", "/update-endpoint?endpoint_type=p2p&id=" ++ id ++ "&addresses=", 200, "Endpoint updated for p2p endpoint " ++ id ++ " with 0 address(es)\n");
    try std.testing.expectEqual(@as(usize, 0), ov.count());
    try expectCall(src, "POST", "/update-endpoint?endpoint_type=consensus&id=00&addresses=", 400, "Invalid network public key: InvalidInput");
    const base = "5866666666666666666666666666666666666666666666666666666666666666";
    try expectCall(src, "POST", "/update-endpoint?endpoint_type=consensus&id=" ++ base ++ "&addresses=/ip4/1.2.3.4/udp/1", 200, "Endpoint updated for consensus endpoint " ++ base ++ " with 1 address(es)\n");
}

/// Three checkpoints 10..12: 10 and 11 in epoch 1 (11 ends it), 12 in epoch 2; one transaction.
const FakeDb = struct {
    arena: std.heap.ArenaAllocator,
    certs: [3][]const u8 = undefined,
    sums: [3][]const u8 = undefined,
    contents: [3][]const u8 = undefined,
    digests: [3][32]u8 = undefined,
    content_digests: [3][32]u8 = undefined,
    epochs_of: [3]u64 = .{ 1, 1, 2 },
    tx: [32]u8 = @splat(0x11),
    fx: [32]u8 = @splat(0x22),
    key: [96]u8 = @splat(7),

    const types = @import("types");
    const bcs = @import("bcs");
    const hash = @import("hash");

    fn init(f: *FakeDb) !void {
        f.* = .{ .arena = .init(std.testing.allocator) };
        const a = f.arena.allocator();
        for (0..3) |i| {
            const sig_bytes = [_]u8{0} ++ @as([96]u8, @splat(5));
            const sig: types.GenericSignature = .{ .@"0" = &sig_bytes };
            const sigs = try a.dupe(types.GenericSignature, &.{sig});
            const eds = try a.dupe(types.ExecutionDigests, &.{.{ .transaction = .{ .@"0" = .{ .@"0" = if (i == 0) f.tx else @splat(@intCast(0x30 + i)) } }, .effects = .{ .@"0" = .{ .@"0" = if (i == 0) f.fx else @splat(@intCast(0x40 + i)) } } }});
            const c: types.CheckpointContents = .{ .V1 = .{ .transactions = eds, .user_signatures = try a.dupe([]const types.GenericSignature, &.{sigs}) } };
            f.contents[i] = try bcs.encodeAlloc(types.CheckpointContents, a, &c);
            f.content_digests[i] = hash.blake2b256(&.{ "CheckpointContents::", f.contents[i] });
            const next_committee = try a.dupe(@typeInfo(@FieldType(types.EndOfEpochData, "nextEpochCommittee")).pointer.child, &.{.{ .{ .@"0" = f.key }, 10_000 }});
            const s: types.CheckpointSummary = .{
                .epoch = f.epochs_of[i],
                .sequence_number = 10 + i,
                .network_total_transactions = 100 + i,
                .content_digest = .{ .@"0" = .{ .@"0" = f.content_digests[i] } },
                .previous_digest = if (i == 0) null else .{ .@"0" = .{ .@"0" = f.digests[i - 1] } },
                .epoch_rolling_gas_cost_summary = .{ .computationCost = 1, .storageCost = 2, .storageRebate = 3, .nonRefundableStorageFee = 4 },
                .timestamp_ms = 1_700_000_000_000 + i,
                .checkpoint_commitments = &.{},
                .end_of_epoch_data = if (i == 1) .{ .nextEpochCommittee = next_committee, .nextEpochProtocolVersion = .{ .@"0" = 99 }, .epochCommitments = &.{} } else null,
                .version_specific_data = &.{ 0, 1 },
            };
            f.sums[i] = try bcs.encodeAlloc(types.CheckpointSummary, a, &s);
            f.digests[i] = hash.blake2b256(&.{ "CheckpointSummary::", f.sums[i] });
            f.certs[i] = try std.mem.concat(a, u8, &.{ f.sums[i], "sig-info" });
        }
    }

    fn self(ctx: *anyopaque) *FakeDb {
        return @ptrCast(@alignCast(ctx));
    }
    fn range(_: *anyopaque) ?dbshell.Range {
        return .{ .lo = 10, .hi = 12 };
    }
    fn epochOf(ctx: *anyopaque, seq: u64) ?u64 {
        if (seq < 10 or seq > 12) return null;
        return self(ctx).epochs_of[seq - 10];
    }
    fn checkpoint(ctx: *anyopaque, arena: std.mem.Allocator, seq: u64) anyerror!?dbshell.Checkpoint {
        if (seq < 10 or seq > 12) return null;
        const f = self(ctx);
        const i = seq - 10;
        return .{ .epoch = f.epochs_of[i], .summary_cert = try arena.dupe(u8, f.certs[i]), .contents = try arena.dupe(u8, f.contents[i]) };
    }
    fn byDigest(ctx: *anyopaque, d: *const [32]u8) ?u64 {
        for (self(ctx).digests, 0..) |x, i| if (std.mem.eql(u8, &x, d)) return 10 + i;
        return null;
    }
    fn scan(ctx: *anyopaque, lo: u64, hi: u64, down: bool, v: dbshell.Visitor) anyerror!void {
        const f = self(ctx);
        var k: u64 = 0;
        while (k <= hi - lo) : (k += 1) {
            const seq = if (down) hi - k else lo + k;
            if (!try v.f(v.ctx, seq, f.certs[seq - 10], f.contents[seq - 10])) return;
        }
    }
    fn transaction(ctx: *anyopaque, _: std.mem.Allocator, d: *const [32]u8) anyerror!?dbshell.Tx {
        const f = self(ctx);
        if (!std.mem.eql(u8, d, &f.tx)) return null;
        return .{ .tx = "txbytes", .effects = "fxbytes", .effects_digest = f.fx };
    }
    fn epochs(_: *anyopaque, _: std.mem.Allocator) anyerror![]const u64 {
        return &.{ 1, 2 };
    }
    fn committee(ctx: *anyopaque, arena: std.mem.Allocator, e: u64) anyerror!?dbshell.Committee {
        if (e != 2) return null;
        return .{ .keys = try arena.dupe([96]u8, &.{self(ctx).key}), .stakes = try arena.dupe(u64, &.{10_000}) };
    }
    fn none(_: *anyopaque, _: u64) ?u64 {
        return null;
    }
    fn source(f: *FakeDb) dbshell.Source {
        return .{ .ctx = f, .range = range, .epochOf = epochOf, .checkpoint = checkpoint, .byDigest = byDigest, .scan = scan, .transaction = transaction, .epochs = epochs, .committee = committee, .epochEnd = none, .epochStart = none };
    }
};

fn b58s(buf: *[64]u8, d: *const [32]u8) []const u8 {
    return util.b58Encode(buf, d);
}

test "admin: db-shell ls, read and delete over a fake store (sui-node paths, texts, formats)" {
    const gpa = std.testing.allocator;
    var f: FakeDb = undefined;
    try f.init();
    defer f.arena.deinit();
    var src = noSrc();
    src.db = f.source();
    try expectCall(src, "GET", "/db-shell/ls?path=/", 200, "[{\"name\":\"epochs\",\"is_dir\":true},{\"name\":\"checkpoints\",\"is_dir\":true},{\"name\":\"checkpoint-contents\",\"is_dir\":true},{\"name\":\"transactions\",\"is_dir\":true},{\"name\":\"consensus\",\"is_dir\":true}]");
    try expectCall(src, "POST", "/db-shell/ls?path=/", 405, null);
    try expectCall(src, "GET", "/db-shell/ls", 400, "Failed to deserialize query string: missing field `path`");
    try expectCall(src, "GET", "/db-shell/ls?path=/&limit=x", 400, "Failed to deserialize query string: limit: invalid digit found in string");
    try expectCall(src, "GET", "/db-shell/ls?path=/&cursor=yes", 400, "Failed to deserialize query string: cursor: provided string was not `true` or `false`");
    try expectCall(src, "GET", "/db-shell/read?path=/&format=xml", 400, "Failed to deserialize query string: format: unknown variant `xml`, expected one of `json`, `debug`, `bcs`, `raw-bcs`");
    try expectCall(src, "GET", "/db-shell/ls?path=/checkpoints/seq&limit=2", 200, "[{\"name\":\"10\",\"is_dir\":true},{\"name\":\"11\",\"is_dir\":true}]");
    try expectCall(src, "GET", "/db-shell/ls?path=/checkpoints/seq/11&cursor=true", 200, "[{\"name\":\"11\",\"is_dir\":true},{\"name\":\"12\",\"is_dir\":true}]");
    try expectCall(src, "GET", "/db-shell/ls?path=/checkpoints/seq/11", 200, "[{\"name\":\"summary\",\"is_dir\":false},{\"name\":\"contents\",\"is_dir\":false},{\"name\":\"contents-short\",\"is_dir\":false}]");
    try expectCall(src, "GET", "/db-shell/ls?path=//epochs//", 200, "[{\"name\":\"1\",\"is_dir\":true},{\"name\":\"2\",\"is_dir\":true}]");
    try expectCall(src, "GET", "/db-shell/ls?path=/epochs/1/checkpoints", 200, "[{\"name\":\"10\",\"is_dir\":false},{\"name\":\"11\",\"is_dir\":false}]");
    try expectCall(src, "GET", "/db-shell/ls?path=/epochs/1/checkpoints/11&cursor=true", 200, "[{\"name\":\"11\",\"is_dir\":false}]");
    try expectCall(src, "GET", "/db-shell/ls?path=/epochs/2/checkpoints", 200, "[]");
    try expectCall(src, "GET", "/db-shell/ls?path=/consensus", 200, "[{\"name\":\"latest\",\"is_dir\":false},{\"name\":\"commits\",\"is_dir\":true}]");
    try expectCall(src, "GET", "/db-shell/ls?path=/consensus/commits", 501, "consensus store not available (node is not a validator)");
    try expectCall(src, "GET", "/db-shell/ls?path=/nope", 400, "unknown path: /nope");
    try expectCall(src, "GET", "/db-shell/ls?path=/epochs/x", 400, "invalid epoch: x");
    try expectCall(src, "GET", "/db-shell/ls?path=/epochs/1/foo", 400, "unknown path: /epochs/1/foo");
    try expectCall(src, "GET", "/db-shell/ls?path=/checkpoints/digest/xyz", 400, "invalid digest: xyz");
    try expectCall(src, "GET", "/db-shell/ls?path=/checkpoints/seq/10/summary", 400, "path is not a directory");
    try expectCall(src, "GET", "/db-shell/ls?path=/transactions/11111111111111111111111111111111", 400, "path is not a directory");
    // digest-ordered listings: byte order, limit, cursor
    var sorted = f.digests;
    std.mem.sort([32]u8, &sorted, {}, struct {
        fn lt(_: void, x: [32]u8, y: [32]u8) bool {
            return std.mem.order(u8, &x, &y) == .lt;
        }
    }.lt);
    var b1: [64]u8 = undefined;
    var b2: [64]u8 = undefined;
    {
        const want = try std.fmt.allocPrint(gpa, "[{{\"name\":\"{s}\",\"is_dir\":true}},{{\"name\":\"{s}\",\"is_dir\":true}}]", .{ b58s(&b1, &sorted[1]), b58s(&b2, &sorted[2]) });
        defer gpa.free(want);
        const t = try std.fmt.allocPrint(gpa, "/db-shell/ls?path=/checkpoints/digest/{s}&cursor=true&limit=5", .{b58s(&b1, &sorted[1])});
        defer gpa.free(t);
        try expectCall(src, "GET", t, 200, want);
    }
    {
        const want = try std.fmt.allocPrint(gpa, "[{{\"name\":\"{s}\",\"is_dir\":false}},{{\"name\":\"{s}.fx-{s}\",\"is_dir\":false}}]", .{ b58s(&b1, &f.tx), b58s(&b1, &f.tx), b58s(&b2, &f.fx) });
        defer gpa.free(want);
        try expectCall(src, "GET", "/db-shell/ls?path=/transactions&limit=1", 200, want);
    }
    // reads
    {
        const c = try call(src, "GET", "/db-shell/read?path=/epochs/1/last-checkpoint&format=raw-bcs");
        defer c.deinit();
        try std.testing.expectEqual(@as(u16, 200), c.code);
        try std.testing.expectEqualStrings(dbshell.octet, c.ct);
        try std.testing.expectEqualSlices(u8, f.sums[1], c.body);
    }
    {
        const c = try call(src, "GET", "/db-shell/read?path=/epochs/2/first-checkpoint&format=bcs");
        defer c.deinit();
        var enc: [512]u8 = undefined;
        try std.testing.expectEqualStrings(std.base64.standard.Encoder.encode(&enc, f.sums[2]), c.body);
    }
    {
        const c = try call(src, "GET", "/db-shell/read?path=/checkpoints/seq/10/summary");
        defer c.deinit();
        try std.testing.expectEqualStrings(dbshell.app_json, c.ct);
        try std.testing.expect(std.mem.startsWith(u8, c.body, "{\"epoch\":1,\"sequence_number\":10,\"network_total_transactions\":100,\"content_digest\":\""));
        try std.testing.expect(std.mem.endsWith(u8, c.body, "\"previous_digest\":null,\"epoch_rolling_gas_cost_summary\":{\"computationCost\":\"1\",\"storageCost\":\"2\",\"storageRebate\":\"3\",\"nonRefundableStorageFee\":\"4\"},\"timestamp_ms\":1700000000000,\"checkpoint_commitments\":[],\"end_of_epoch_data\":null,\"version_specific_data\":[0,1]}"));
    }
    {
        const c = try call(src, "GET", "/db-shell/read?path=/checkpoints/seq/11/summary&format=debug");
        defer c.deinit();
        try std.testing.expect(std.mem.startsWith(u8, c.body, "CheckpointSummary {\n    epoch: 1,\n    sequence_number: 11,\n"));
        try std.testing.expect(std.mem.indexOf(u8, c.body, "            next_epoch_protocol_version: ProtocolVersion(\n                99,\n            ),\n") != null);
        try std.testing.expect(std.mem.endsWith(u8, c.body, "    version_specific_data: [\n        0,\n        1,\n    ],\n}"));
    }
    try expectCall(src, "GET", "/db-shell/read?path=/checkpoints/seq/99/summary", 404, "checkpoint 99 not found");
    try expectCall(src, "GET", "/db-shell/read?path=/checkpoints/seq/x/summary", 400, "invalid sequence: x");
    try expectCall(src, "GET", "/db-shell/read?path=/epochs/1", 400, "epoch 1 is a directory");
    try expectCall(src, "GET", "/db-shell/read?path=/checkpoints", 400, "path is not a readable file");
    try expectCall(src, "GET", "/db-shell/read?path=/consensus/latest", 501, "consensus store not available (node is not a validator)");
    try expectCall(src, "GET", "/db-shell/read?path=/epochs/2/last-checkpoint", 404, "no last checkpoint for epoch 2");
    try expectCall(src, "GET", "/db-shell/read?path=/epochs/5/first-checkpoint", 404, "no data for epoch 5");
    try expectCall(src, "GET", "/db-shell/read?path=/epochs/1/committee", 404, "no committee for epoch 1");
    {
        const c = try call(src, "GET", "/db-shell/read?path=/epochs/2/committee&format=raw-bcs");
        defer c.deinit();
        try std.testing.expectEqual(@as(usize, 8 + 1 + 105 + 1 + 193 + 1 + 105), c.body.len);
        try std.testing.expectEqual(@as(u8, 2), c.body[0]);
    }
    try expectCall(src, "GET", "/db-shell/read?path=/checkpoints/seq/10/contents-short&format=bcs", 400, "bcs not supported for contents-short; use 'contents' instead");
    {
        const want = try std.fmt.allocPrint(gpa, "[{{\"transaction\":\"{s}\",\"effects\":\"{s}\"}}]", .{ b58s(&b1, &f.tx), b58s(&b2, &f.fx) });
        defer gpa.free(want);
        try expectCall(src, "GET", "/db-shell/read?path=/checkpoints/seq/10/contents-short", 200, want);
    }
    {
        const t = try std.fmt.allocPrint(gpa, "/db-shell/read?path=/checkpoint-contents/{s}&format=raw-bcs", .{b58s(&b1, &f.content_digests[2])});
        defer gpa.free(t);
        const c = try call(src, "GET", t);
        defer c.deinit();
        try std.testing.expectEqualSlices(u8, f.contents[2], c.body);
        const d = try call(src, "GET", "/db-shell/read?path=/checkpoints/seq/12/contents&format=debug");
        defer d.deinit();
        try std.testing.expect(std.mem.startsWith(u8, d.body, "V1(\n    CheckpointContentsV1 {\n        digest: OnceCell(Uninit),\n        transactions: [\n            ExecutionDigests {\n"));
        try std.testing.expect(std.mem.indexOf(u8, d.body, "                Signature(\n                    Ed25519SuiSignature(\n                        [\n                            0,\n") != null);
    }
    {
        const t = try std.fmt.allocPrint(gpa, "/db-shell/read?path=/transactions/{s}&format=raw-bcs", .{b58s(&b1, &f.tx)});
        defer gpa.free(t);
        try expectCall(src, "GET", t, 200, "txbytes");
        const t2 = try std.fmt.allocPrint(gpa, "/db-shell/read?path=/transactions/{s}.fx-{s}&format=raw-bcs", .{ b58s(&b1, &f.tx), b58s(&b2, &f.fx) });
        defer gpa.free(t2);
        try expectCall(src, "GET", t2, 200, "fxbytes");
        const t3 = try std.fmt.allocPrint(gpa, "/db-shell/read?path=/transactions/{s}", .{b58s(&b1, &f.tx)});
        defer gpa.free(t3);
        try expectCall(src, "GET", t3, 501, null);
    }
    try expectCall(src, "DELETE", "/db-shell/delete?path=/checkpoints/seq/1/summary", 501, "delete not yet implemented for path: /checkpoints/seq/1/summary");
    try expectCall(src, "GET", "/db-shell/delete?path=/x", 405, null);
    try expectCall(src, "DELETE", "/db-shell/delete", 400, "Failed to deserialize query string: missing field `path`");
}
