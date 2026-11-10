//! deepwave-simproxy: SimulateTransaction served by deepwave's engine over h2c, with every object,
//! package, owned gas coin and the epoch read from an upstream sui-node (gRPC-web). The parity
//! tool for G9 (docs/DROP-IN.md): build the same transaction with @mysten/sui against sui-node and
//! against this proxy and compare. Simulate only: it never executes or submits anything.
//!
//!   deepwave-simproxy --upstream http://127.0.0.1:19007 --listen 127.0.0.1:9107
const std = @import("std");
const rpc_exec = @import("rpc_exec");
const exec = @import("exec");
const serve = @import("serve");

const Io = std.Io;
const h2 = serve.h2;

const Proxy = struct {
    gpa: std.mem.Allocator,
    up: *rpc_exec.remote.Upstream,
    engine: rpc_exec.simulate.Engine,
    env_mu: Io.Mutex = .init,
    env: ?rpc_exec.EpochEnv = null,
    env_at_ms: i64 = 0,
    served: std.atomic.Value(u64) = .init(0),
    retries: std.atomic.Value(u64) = .init(0),

    fn epoch(p: *Proxy, arena: std.mem.Allocator) !rpc_exec.EpochEnv {
        p.env_mu.lockUncancelable(p.up.io);
        defer p.env_mu.unlock(p.up.io);
        const now = Io.Clock.real.now(p.up.io).toMilliseconds();
        if (p.env) |e| if (now - p.env_at_ms < 30_000) return e;
        _ = arena;
        var a: std.heap.ArenaAllocator = .init(p.gpa);
        defer a.deinit();
        p.env = try p.up.epochEnv(a.allocator());
        p.env_at_ms = now;
        return p.env.?;
    }

    fn handler(p: *Proxy) h2.Handler {
        return .{ .ctx = p, .call = call };
    }

    fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const p: *Proxy = @ptrCast(@alignCast(ctx));
        var arena_state = std.heap.ArenaAllocator.init(p.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        // Parity runs pin the versions sui-node read (raw n x (id, version le)); empty clears.
        if (std.mem.eql(u8, req.path, "/zui.simproxy.Pins/Set")) {
            const n = p.up.setPins(arena, req.body) catch |e| {
                rs.setMessage(@errorName(e));
                return .invalid_argument;
            };
            _ = n;
            rs.message("") catch return .internal;
            return .ok;
        }
        if (!std.mem.eql(u8, req.path, "/sui.rpc.v2.TransactionExecutionService/SimulateTransaction")) return .unimplemented;
        const env = p.epoch(arena) catch {
            rs.setMessage("upstream epoch unavailable");
            return .unavailable;
        };
        // A view read object by object can catch a child newer than its root: run again on a
        // fresh view (sui-node reads one consistent store), up to 4 times.
        var attempt: u32 = 0;
        const r = while (true) : (attempt += 1) {
            var remote: rpc_exec.remote.Remote = .{ .up = p.up, .arena = arena };
            const got = p.engine.simulate(arena, &env, remote.state(), req.body) catch {
                rs.setMessage("out of memory");
                return .resource_exhausted;
            };
            if (!remote.stale or attempt == 3) break got;
            _ = p.retries.fetchAdd(1, .monotonic);
        };
        const n = p.served.fetchAdd(1, .monotonic) + 1;
        if (n % 100 == 0) std.log.info("served {d} simulate calls, {d} upstream calls, {d} stale-view retries", .{ n, p.up.calls.load(.monotonic), p.retries.load(.monotonic) });
        switch (r) {
            .ok => |bytes| {
                rs.message(bytes) catch return .internal;
                return .ok;
            },
            .err => |e| {
                rs.setMessage(e.message);
                if (e.details.len > 0) rs.details(e.details);
                return if (e.code == 0 or e.code > 16) .internal else @enumFromInt(e.code);
            },
        }
    }
};

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var upstream: []const u8 = "http://127.0.0.1:19007";
    var listen: []const u8 = "127.0.0.1:9107";
    var rate: u64 = 0;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--upstream") and i + 1 < args.len) {
            i += 1;
            upstream = args[i];
        } else if (std.mem.eql(u8, args[i], "--listen") and i + 1 < args.len) {
            i += 1;
            listen = args[i];
        } else if (std.mem.eql(u8, args[i], "--rate") and i + 1 < args.len) {
            i += 1;
            rate = try std.fmt.parseInt(u64, args[i], 10);
        } else {
            std.debug.print("usage: deepwave-simproxy [--upstream http://127.0.0.1:19007] [--listen 127.0.0.1:9107] [--rate <upstream req/s>]\n", .{});
            return 2;
        }
    }
    var up = rpc_exec.remote.Upstream.init(gpa, io, upstream);
    if (rate > 0) up.min_gap_ns = std.time.ns_per_s / rate;
    var pkgs: exec.packages.Store = .{ .lookup = up.packageLookup(), .loaded = true };
    var proxy: Proxy = .{ .gpa = gpa, .up = &up, .engine = .{ .gpa = gpa, .pkgs = &pkgs, .io = io } };
    const colon = std.mem.lastIndexOfScalar(u8, listen, ':') orelse return 2;
    const addr = try Io.net.IpAddress.parse(listen[0..colon], try std.fmt.parseInt(u16, listen[colon + 1 ..], 10));
    var server = try addr.listen(io, .{ .reuse_address = true });
    var stop: std.atomic.Value(bool) = .init(false);
    std.log.info("deepwave-simproxy: SimulateTransaction on {s} (h2c), state from {s}", .{ listen, upstream });
    try h2.serveBlocking(gpa, io, &server, .{}, proxy.handler(), &stop);
    return 0;
}
