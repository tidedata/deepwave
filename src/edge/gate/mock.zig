//! A gate service for tests, in the process: it answers resolve, free and usage as the contract
//! says (docs/GATE.md), checks the bearer token and the edge id, treats a repeated batch id as a
//! no-op and records what it was sent. Reached two ways: `transport()` hands requests straight
//! to it (unit tests with a test clock), `Server` serves it over HTTP on a loopback port (tests
//! of the node's real HTTP client). Never used outside tests; nothing here calls out.
const std = @import("std");
const Io = std.Io;
const Atomic = std.atomic.Value;
const Allocator = std.mem.Allocator;
const contract = @import("contract.zig");
const state = @import("state.zig");
const gate_mod = @import("gate.zig");
const Counters = contract.Counters;

pub const MockGate = struct {
    gpa: Allocator,
    lock: state.SpinLock = .{},
    token: []const u8 = "test-token-0123456789abcdef-xyz",
    edge: []const u8 = "e1",
    /// Raw key -> the resolve answer's JSON. A key not listed answers `invalid`.
    keys: std.StringHashMapUnmanaged([]const u8) = .empty,
    free_json: []const u8 = contract.fixtures.free,
    usage_answer: []const u8 = "{\"ok\":true,\"duplicate\":false}",
    /// The gate is gone: every request fails at the transport.
    down: bool = false,
    /// Answer every request with this status instead.
    status: ?u16 = null,
    /// Fail this many usage posts (HTTP 500) before accepting again. With `usage_applied`, the
    /// failed posts are processed anyway: the answer was lost on the way back.
    fail_usage: u32 = 0,
    usage_applied: bool = false,
    /// Answer the next `usage_status_n` usage posts with this status and nothing else.
    usage_status: u16 = 0,
    usage_status_n: u32 = 0,
    /// A `Retry-After` header (seconds) on every answer that is not 2xx.
    retry_after_s: ?u32 = null,
    /// What a key not in `keys` is answered with.
    invalid_json: []const u8 = contract.fixtures.resolve_invalid_plain,
    /// Real-time delay of every answer (threaded tests).
    delay_ms: u32 = 0,
    io: ?Io = null,

    resolves: u32 = 0,
    frees: u32 = 0,
    usage_posts: u32 = 0,
    unauthorized: u32 = 0,
    /// Batch id -> the body first accepted under it.
    batches: std.StringArrayHashMapUnmanaged([]const u8) = .empty,
    duplicates_same: u32 = 0,
    duplicates_differ: u32 = 0,
    /// Every accepted row, summed by `subject \x00 method`.
    rows: std.StringArrayHashMapUnmanaged(Counters) = .empty,
    total: Counters = .{},
    max_rows_in_batch: usize = 0,
    /// Resolve request bodies' keys, in order.
    asked: std.ArrayList([]const u8) = .empty,

    pub fn deinit(m: *MockGate) void {
        var it = m.keys.iterator();
        while (it.next()) |kv| {
            m.gpa.free(kv.key_ptr.*);
            m.gpa.free(kv.value_ptr.*);
        }
        m.keys.deinit(m.gpa);
        for (m.batches.keys(), m.batches.values()) |k, v| {
            m.gpa.free(k);
            m.gpa.free(v);
        }
        m.batches.deinit(m.gpa);
        for (m.rows.keys()) |k| m.gpa.free(k);
        m.rows.deinit(m.gpa);
        for (m.asked.items) |k| m.gpa.free(k);
        m.asked.deinit(m.gpa);
    }

    pub fn setKey(m: *MockGate, key: []const u8, answer_json: []const u8) !void {
        m.lock.lock();
        defer m.lock.unlock();
        const gop = try m.keys.getOrPut(m.gpa, key);
        if (gop.found_existing) m.gpa.free(gop.value_ptr.*) else gop.key_ptr.* = try m.gpa.dupe(u8, key);
        gop.value_ptr.* = try m.gpa.dupe(u8, answer_json);
    }

    pub fn row(m: *MockGate, subject: []const u8, method: []const u8) Counters {
        var kb: [512]u8 = undefined;
        const k = std.fmt.bufPrint(&kb, "{s}\x00{s}", .{ subject, method }) catch return .{};
        m.lock.lock();
        defer m.lock.unlock();
        return m.rows.get(k) orelse .{};
    }

    pub fn transport(m: *MockGate) gate_mod.Transport {
        return .{ .ctx = m, .call = call };
    }

    fn call(ctx: *anyopaque, req: *const gate_mod.HttpRequest, out: *std.ArrayList(u8), gpa: Allocator) anyerror!gate_mod.Reply {
        const m: *MockGate = @ptrCast(@alignCast(ctx));
        if (m.delay_ms != 0) if (m.io) |io| io.sleep(.fromMilliseconds(m.delay_ms), .awake) catch {};
        if (m.down) return error.ConnectionRefused;
        const path = if (std.mem.indexOf(u8, req.url, "://")) |i| blk: {
            const rest = req.url[i + 3 ..];
            break :blk rest[std.mem.indexOfScalar(u8, rest, '/') orelse rest.len ..];
        } else req.url;
        const status = try m.handle(req.post, path, req.token, req.body, out, gpa);
        return .{ .status = status, .retry_after_ms = if (status / 100 != 2) (if (m.retry_after_s) |sec| sec * 1000 else null) else null };
    }

    fn fail(out: *std.ArrayList(u8), gpa: Allocator, status: u16, code: []const u8) !u16 {
        try out.print(gpa, "{{\"error\":{{\"code\":\"{s}\",\"message\":\"mock\"}}}}", .{code});
        return status;
    }

    /// One request: `path` is the URL's path and query, `token` the bearer token it carried.
    pub fn handle(m: *MockGate, post: bool, path: []const u8, token: []const u8, body: []const u8, out: *std.ArrayList(u8), gpa: Allocator) !u16 {
        m.lock.lock();
        defer m.lock.unlock();
        if (m.status) |s| return fail(out, gpa, s, "forced");
        if (!std.mem.eql(u8, token, m.token)) {
            m.unauthorized += 1;
            return fail(out, gpa, 401, "unauthorized");
        }
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const q = std.mem.indexOfScalar(u8, path, '?');
        const bare = path[0 .. q orelse path.len];
        if (!post and std.mem.endsWith(u8, bare, "/free")) {
            m.frees += 1;
            const query = if (q) |i| path[i + 1 ..] else "";
            if (!std.mem.startsWith(u8, query, "edge=") or !std.mem.eql(u8, query[5..], m.edge)) return fail(out, gpa, 403, "wrong_edge");
            try out.appendSlice(gpa, m.free_json);
            return 200;
        }
        if (!post) return fail(out, gpa, 404, "not_found");
        const v = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch return fail(out, gpa, 400, "invalid_params");
        if (v != .object) return fail(out, gpa, 400, "invalid_params");
        const edge = v.object.get("edge") orelse return fail(out, gpa, 400, "invalid_params");
        if (edge != .string or !std.mem.eql(u8, edge.string, m.edge)) return fail(out, gpa, 403, "wrong_edge");
        if (std.mem.endsWith(u8, bare, "/resolve")) {
            m.resolves += 1;
            const key = v.object.get("key") orelse return fail(out, gpa, 400, "invalid_params");
            if (key != .string) return fail(out, gpa, 400, "invalid_params");
            try m.asked.append(m.gpa, try m.gpa.dupe(u8, key.string));
            try out.appendSlice(gpa, m.keys.get(key.string) orelse m.invalid_json);
            return 200;
        }
        if (std.mem.endsWith(u8, bare, "/usage")) {
            m.usage_posts += 1;
            if (m.usage_status_n > 0) {
                m.usage_status_n -= 1;
                return fail(out, gpa, m.usage_status, "scripted");
            }
            const lost = m.fail_usage > 0;
            if (lost) {
                m.fail_usage -= 1;
                if (!m.usage_applied) return fail(out, gpa, 500, "internal");
            }
            const id = v.object.get("batch_id") orelse return fail(out, gpa, 400, "invalid_params");
            const rows = v.object.get("rows") orelse return fail(out, gpa, 400, "invalid_params");
            if (id != .string or rows != .array) return fail(out, gpa, 400, "invalid_params");
            if (rows.array.items.len > contract.max_batch_rows) return fail(out, gpa, 413, "too_many_rows");
            if (m.batches.get(id.string)) |first| {
                if (std.mem.eql(u8, first, body)) m.duplicates_same += 1 else m.duplicates_differ += 1;
            } else {
                try m.batches.put(m.gpa, try m.gpa.dupe(u8, id.string), try m.gpa.dupe(u8, body));
                m.max_rows_in_batch = @max(m.max_rows_in_batch, rows.array.items.len);
                for (rows.array.items) |r| {
                    if (r != .object) continue;
                    var c: Counters = .{};
                    inline for (.{ "local", "forwarded", "units", "limited", "stream_msgs" }) |f| {
                        if (r.object.get(f)) |x| if (x == .integer) {
                            @field(c, f) = @intCast(x.integer);
                        };
                    }
                    const kid = r.object.get("key_id");
                    const method = if (r.object.get("method")) |x| (if (x == .string) x.string else "") else "";
                    var kb: std.ArrayList(u8) = .empty;
                    defer kb.deinit(m.gpa);
                    if (kid != null and kid.? == .string) {
                        try kb.print(m.gpa, "k{s}", .{kid.?.string});
                    } else {
                        const pfx = r.object.get("ip_prefix");
                        try kb.print(m.gpa, "i{s}", .{if (pfx != null and pfx.? == .string) pfx.?.string else "?"});
                    }
                    try kb.append(m.gpa, 0);
                    try kb.appendSlice(m.gpa, method);
                    const gop = try m.rows.getOrPut(m.gpa, kb.items);
                    if (gop.found_existing) gop.value_ptr.add(c) else {
                        gop.key_ptr.* = try m.gpa.dupe(u8, kb.items);
                        gop.value_ptr.* = c;
                    }
                    m.total.add(c);
                }
            }
            if (lost) return fail(out, gpa, 500, "internal");
            try out.appendSlice(gpa, m.usage_answer);
            return 200;
        }
        return fail(out, gpa, 404, "not_found");
    }
};

/// `MockGate` over HTTP/1.1 on 127.0.0.1 (one request per connection).
pub const Server = struct {
    io: Io,
    gate: *MockGate,
    server: Io.net.Server,
    port: u16,
    stopping: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    requests: Atomic(u32) = .init(0),

    pub fn start(s: *Server, io: Io, gate: *MockGate) !void {
        const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
        s.* = .{ .io = io, .gate = gate, .server = try addr.listen(io, .{ .reuse_address = true }), .port = 0 };
        s.port = s.server.socket.address.getPort();
        s.thread = try std.Thread.spawn(.{}, loop, .{s});
    }

    pub fn url(s: *const Server, buf: []u8, base_path: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}{s}", .{ s.port, base_path }) catch unreachable;
    }

    pub fn stop(s: *Server) void {
        s.stopping.store(true, .release);
        const addr = Io.net.IpAddress.parse("127.0.0.1", s.port) catch unreachable;
        if (addr.connect(s.io, .{ .mode = .stream })) |c| c.close(s.io) else |_| {}
        if (s.thread) |t| t.join();
        s.server.deinit(s.io);
    }

    fn loop(s: *Server) void {
        while (true) {
            const c = s.server.accept(s.io) catch return;
            if (s.stopping.load(.acquire)) {
                c.close(s.io);
                return;
            }
            s.serve(c) catch {};
            c.close(s.io);
        }
    }

    fn serve(s: *Server, c: Io.net.Stream) !void {
        const gpa = s.gate.gpa;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        var head_end: ?usize = null;
        var want: usize = 0;
        while (true) {
            var chunk: [4096]u8 = undefined;
            var iov = [_][]u8{&chunk};
            const k = try c.read(s.io, &iov);
            if (k == 0) return;
            try buf.appendSlice(gpa, chunk[0..k]);
            if (buf.items.len > 8 << 20) return;
            if (head_end == null) if (std.mem.indexOf(u8, buf.items, "\r\n\r\n")) |e| {
                head_end = e + 4;
                var it = std.mem.splitSequence(u8, buf.items[0..e], "\r\n");
                while (it.next()) |line| {
                    const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
                    if (std.ascii.eqlIgnoreCase(line[0..colon], "content-length"))
                        want = std.fmt.parseInt(usize, std.mem.trim(u8, line[colon + 1 ..], " "), 10) catch 0;
                }
            };
            if (head_end) |e| if (buf.items.len >= e + want) break;
        }
        _ = s.requests.fetchAdd(1, .monotonic);
        const head = buf.items[0 .. head_end.? - 4];
        const body = buf.items[head_end.?..][0..want];
        var lines = std.mem.splitSequence(u8, head, "\r\n");
        const first = lines.next() orelse return;
        var parts = std.mem.splitScalar(u8, first, ' ');
        const method = parts.next() orelse return;
        const path = parts.next() orelse return;
        var token: []const u8 = "";
        while (lines.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            if (!std.ascii.eqlIgnoreCase(line[0..colon], "authorization")) continue;
            const v = std.mem.trim(u8, line[colon + 1 ..], " ");
            if (std.mem.startsWith(u8, v, "Bearer ")) token = v[7..];
        }
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        if (s.gate.delay_ms != 0) s.io.sleep(.fromMilliseconds(s.gate.delay_ms), .awake) catch {};
        if (s.gate.down) return; // closes without an answer
        const status = s.gate.handle(std.mem.eql(u8, method, "POST"), path, token, body, &out, gpa) catch 500;
        var resp: std.ArrayList(u8) = .empty;
        defer resp.deinit(gpa);
        try resp.print(gpa, "HTTP/1.1 {d} X\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {d}\r\n", .{ status, out.items.len });
        if (status / 100 != 2) if (s.gate.retry_after_s) |sec| try resp.print(gpa, "retry-after: {d}\r\n", .{sec});
        try resp.appendSlice(gpa, "connection: close\r\n\r\n");
        try resp.appendSlice(gpa, out.items);
        var wbuf: [1024]u8 = undefined;
        var w = c.writer(s.io, &wbuf);
        try w.interface.writeAll(resp.items);
        try w.interface.flush();
    }
};
