//! The real JWK `Transport`: an HTTPS GET with std.http through the node's netguard client (TLS
//! clock refresh, bounded by a hard timeout so a silent server never holds the updater). Cold
//! path (one request per provider per hour); never used by local test committees. Up to 10 redirects are followed
//! (a redirect to plain http is refused), any status is accepted like Rust, and the body is capped at `max_body` bytes.
const std = @import("std");
const node = @import("node");
const updater = @import("updater.zig");
const netguard = node.netguard;

pub const Https = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    client: netguard.Client,
    timeout_ms: u64 = 15_000,
    max_body: usize = 1 << 20,

    pub fn init(gpa: std.mem.Allocator, io: std.Io) Https {
        return .{ .gpa = gpa, .io = io, .client = netguard.Client.init(gpa, io) };
    }

    pub fn deinit(h: *Https) void {
        h.client.deinit();
    }

    pub fn transport(h: *Https) updater.Transport {
        return .{ .ctx = h, .get = get };
    }

    fn get(ctx: *anyopaque, arena: std.mem.Allocator, url: []const u8) anyerror![]const u8 {
        const h: *Https = @ptrCast(@alignCast(ctx));
        const buf = try h.gpa.alloc(u8, h.max_body);
        defer h.gpa.free(buf);
        var w: std.Io.Writer = .fixed(buf);
        h.client.prepare(netguard.wallMs());
        defer h.client.done(netguard.wallMs());
        var abort: netguard.Abort = .{};
        const status = netguard.timed(h.io, h.timeout_ms, null, &abort, fetchOnce, .{ &h.client.http, url, &w, &abort }) catch |e| {
            h.client.noteError(e, netguard.wallMs());
            return e;
        };
        _ = status; // Rust's fetch_jwks does not check the status; parse_jwks rejects non-JWKS bodies
        return arena.dupe(u8, w.buffered());
    }
};

fn fetchOnce(c: *std.http.Client, url: []const u8, w: *std.Io.Writer, abort: *netguard.Abort) !std.http.Status {
    const uri = try std.Uri.parse(url);
    var req = try c.request(.GET, uri, .{
        .redirect_behavior = .init(10), // reqwest default: up to 10 redirects
        .headers = .{ .accept_encoding = .omit },
    });
    defer req.deinit();
    errdefer if (req.connection) |conn| {
        conn.closing = true;
    };
    try abort.arm(netguard.socketOf(req.connection.?));
    defer abort.disarm();
    try req.sendBodiless();
    var redirect_buf: [8192]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (!std.ascii.eqlIgnoreCase(req.uri.scheme, "https")) return error.InsecureRedirect;
    if (response.head.content_encoding != .identity) return error.UnsupportedCompressionMethod;
    const reader = response.reader(&.{});
    _ = reader.streamRemaining(w) catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr() orelse error.ReadFailed,
        error.WriteFailed => return error.BodyTooLarge,
        else => |e| return e,
    };
    return response.head.status;
}
