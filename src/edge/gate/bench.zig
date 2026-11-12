//! What the gate adds to one call that passes (a resolved key under its limits, or a keyless
//! caller): `admitWait` before the handler and `settle` after it, against calling the handler
//! alone. A short smoke run in the unit tests; the measurement:
//!
//!   ZUI_GATE_BENCH=1 ./zig test src/edge/gate/root.zig -OReleaseFast --test-filter "gate bench"
const std = @import("std");
const testing = std.testing;
const ident = @import("ident.zig");
const methods_mod = @import("methods.zig");
const gate_mod = @import("gate.zig");
const mock_mod = @import("mock.zig");
const Gate = gate_mod.Gate;

const defs = [_]methods_mod.Def{ .{ .name = "/a.A/Get" }, .{ .name = "/a.A/Put" } };

var sink: std.atomic.Value(u64) = .init(0);

/// The stand-in for a handler: opaque to the optimizer, a few ns.
noinline fn handler(x: u64) u64 {
    var v = x *% 0x9e3779b97f4a7c15;
    v ^= v >> 29;
    std.mem.doNotOptimizeAway(&v);
    return v;
}

const Mode = enum { off, key, keyless };

const Job = struct {
    g: *Gate,
    mode: Mode,
    key: []const u8,
    peer: ident.Ip,
    method: u8,
    n: u64,
    ns: u64 = 0,
    refused: u64 = 0,

    fn run(j: *Job) void {
        const clock: gate_mod.Clock = .{};
        var acc: u64 = 0;
        const t0 = clock.mono(null);
        var i: u64 = 0;
        switch (j.mode) {
            .off => while (i < j.n) : (i += 1) {
                acc +%= handler(i);
            },
            .key, .keyless => {
                const c: gate_mod.Call = .{ .key = if (j.mode == .key) j.key else "", .peer = j.peer, .method = j.method };
                while (i < j.n) : (i += 1) {
                    switch (j.g.admitWait(&c)) {
                        .allow => |t| {
                            acc +%= handler(i);
                            j.g.settle(&t, .local, true, t.opened_ns);
                        },
                        else => j.refused += 1,
                    }
                }
            },
        }
        j.ns = clock.mono(null) - t0;
        _ = sink.fetchAdd(acc, .monotonic);
    }
};

fn measure(g: *Gate, mode: Mode, threads: usize, same_key: bool, n: u64, method: u8) !struct { ns_per_call: f64, refused: u64 } {
    var jobs: [16]Job = undefined;
    var ts: [16]std.Thread = undefined;
    var keys: [16][24]u8 = undefined;
    for (jobs[0..threads], 0..) |*j, i| {
        const key = std.fmt.bufPrint(&keys[i], "bench-key-{d:0>4}", .{if (same_key) 0 else i}) catch unreachable;
        j.* = .{ .g = g, .mode = mode, .key = key, .peer = .{ .v4 = .{ 198, 51, 100, @intCast(i + 1) } }, .method = method, .n = n };
    }
    for (ts[0..threads], jobs[0..threads]) |*t, *j| t.* = try std.Thread.spawn(.{}, Job.run, .{j});
    for (ts[0..threads]) |t| t.join();
    var total_ns: u64 = 0;
    var refused: u64 = 0;
    for (jobs[0..threads]) |j| {
        total_ns += j.ns;
        refused += j.refused;
    }
    return .{ .ns_per_call = @as(f64, @floatFromInt(total_ns)) / @as(f64, @floatFromInt(n * threads)), .refused = refused };
}

test "gate bench: the cost of the gate on a call that passes" {
    const gpa = testing.allocator;
    const full = std.c.getenv("ZUI_GATE_BENCH") != null;
    // (one key sees 5 million calls over the cases: inside its burst of 10 million units)
    const n: u64 = if (full) 500_000 else 5_000;
    var mock: mock_mod.MockGate = .{ .gpa = gpa };
    defer mock.deinit();
    // limits far above what the loop can reach: every call passes
    mock.free_json = "{\"rps_per_ip\":1000000,\"burst\":10000000}";
    var kb: [24]u8 = undefined;
    var jb: [256]u8 = undefined;
    for (0..16) |i| {
        const key = std.fmt.bufPrint(&kb, "bench-key-{d:0>4}", .{i}) catch unreachable;
        try mock.setKey(key, std.fmt.bufPrint(&jb, "{{\"key_id\":\"kid_bench_{d}\",\"status\":\"ok\",\"plan\":\"bench\",\"rps\":1000000,\"burst\":10000000,\"ttl_s\":3600,\"lease_units\":null,\"weights\":{{\"default\":1}}}}", .{i}) catch unreachable);
    }
    var m = methods_mod.Methods.init(&defs);
    const g = try Gate.init(gpa, testing.io, .{ .base_url = "https://gate.example", .token = mock.token, .edge_id = "e1", .methods = &m, .transport = mock.transport() });
    defer g.deinit();
    _ = g.refreshFree();
    const get = m.id("/a.A/Get");
    // resolve the keys first: the measurement is the cached path
    const peer: ident.Ip = .{ .v4 = .{ 198, 51, 100, 1 } };
    for (0..16) |i| {
        const key = std.fmt.bufPrint(&kb, "bench-key-{d:0>4}", .{i}) catch unreachable;
        _ = g.admit(&.{ .key = key, .peer = peer, .method = get }, 1_000_000_000);
    }
    while (g.resolveStep()) {}

    const cases = [_]struct { name: []const u8, mode: Mode, threads: usize, same: bool }{
        .{ .name = "1 thread, one key", .mode = .key, .threads = 1, .same = true },
        .{ .name = "1 thread, keyless", .mode = .keyless, .threads = 1, .same = true },
        .{ .name = "8 threads, 8 keys", .mode = .key, .threads = 8, .same = false },
        .{ .name = "8 threads, one key", .mode = .key, .threads = 8, .same = true },
        .{ .name = "8 threads, keyless, 8 addresses", .mode = .keyless, .threads = 8, .same = false },
    };
    for (cases) |c| {
        const off = try measure(g, .off, c.threads, c.same, n, get);
        const on = try measure(g, c.mode, c.threads, c.same, n, get);
        // every call passed: this is the cost of the path that admits
        try testing.expectEqual(@as(u64, 0), on.refused);
        if (full) std.debug.print("gate bench: {s}: off {d:.1} ns/call, on {d:.1} ns/call, added {d:.1} ns\n", .{ c.name, off.ns_per_call, on.ns_per_call, on.ns_per_call - off.ns_per_call });
        // the counters must not pile up between cases
        g.tick(g.cfg.clock.mono(null), g.cfg.clock.wall(null));
    }
    // nothing was allocated per call: the meter never spilled out of its stripes
    try testing.expectEqual(@as(u64, 0), g.meter.spilled.load(.monotonic));
}
