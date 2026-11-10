//! A reconnecting upstream gRPC endpoint: the epoch source of deepwave (`--execute-epoch-from`)
//! and the fullnode `deepwave-execute` reads from. A `grpc.Conn` never reconnects by itself; this
//! replaces a dead one (after `cooldown_ns`) before the next call, so a restarted sui-node, a
//! GOAWAY or a dropped TCP connection costs one failed call, not every call until a restart.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const grpc = @import("grpc_client.zig");

pub const Upstream = struct {
    gpa: Allocator,
    io: Io,
    ep: grpc.Endpoint,
    mu: Io.Mutex = .init,
    conn: ?*grpc.Conn = null,
    /// Minimum time between a connection's death and the next open.
    cooldown_ns: u64 = std.time.ns_per_s,
    reconnects: std.atomic.Value(u64) = .init(0),
    /// Test hook: opens a connection (null: `grpc.Conn.open`).
    open_fn: ?*const fn (gpa: Allocator, io: Io, ep: grpc.Endpoint) anyerror!*grpc.Conn = null,

    /// Copies `ep` and opens the first connection in the background.
    pub fn init(gpa: Allocator, io: Io, ep: grpc.Endpoint) !*Upstream {
        const u = try gpa.create(Upstream);
        errdefer gpa.destroy(u);
        var e = ep;
        e.host = try gpa.dupe(u8, ep.host);
        u.* = .{ .gpa = gpa, .io = io, .ep = e };
        if (u.acquire()) |c| c.unref();
        return u;
    }

    pub fn deinit(u: *Upstream) void {
        if (u.conn) |c| c.release();
        u.gpa.free(u.ep.host);
        u.gpa.destroy(u);
    }

    /// True for h2c or a loopback host (no public rate limit in front of it).
    pub fn isLocal(u: *const Upstream) bool {
        if (u.ep.security == .plain) return true;
        return std.mem.eql(u8, u.ep.host, "localhost") or std.mem.startsWith(u8, u.ep.host, "127.") or std.mem.eql(u8, u.ep.host, "::1");
    }

    fn open(u: *Upstream) ?*grpc.Conn {
        const f = u.open_fn orelse grpc.Conn.open;
        return f(u.gpa, u.io, u.ep) catch null;
    }

    /// A connection retained for the caller (`unref` it), reopened when the current one is dead
    /// and its cooldown has passed (until then the dead one is returned and fails at once).
    pub fn acquire(u: *Upstream) ?*grpc.Conn {
        u.mu.lockUncancelable(u.io);
        defer u.mu.unlock(u.io);
        if (u.conn) |c| {
            if (!c.isDead() or @as(u64, @intCast(Io.Clock.awake.now(u.io).nanoseconds)) -| c.died_at < u.cooldown_ns) {
                c.retain();
                return c;
            }
            c.release();
            u.conn = null;
            _ = u.reconnects.fetchAdd(1, .monotonic);
        }
        const c = u.open() orelse return null;
        u.conn = c;
        c.retain();
        return c;
    }

    /// One unary call (the reply is allocated in `arena`). UNAVAILABLE when no connection opens.
    pub fn call(u: *Upstream, arena: Allocator, path: []const u8, body: []const u8, timeout_ms: u64) !grpc.Result {
        const c = u.acquire() orelse return .{ .status = .{ .code = 14, .message = "transport error: upstream connect failed" } };
        defer c.unref();
        return grpc.callBlocking(arena, c, path, body, timeout_ms);
    }
};
