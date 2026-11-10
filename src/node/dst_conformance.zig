//! `node-dst` conformance suite: seeds of the node simulation tester (dst/run.zig). One item per
//! seed; no corpus needed. Chains are generated once (real BLS signing) and shared by the seeds.
//!
//!   -Dfilter=seed/17        one seed (ZUI_DST_DEBUG=1 prints its steps)
//!   ZUI_NODE_DST_SEEDS=N    seeds per family (default 256)
//! A failure line names the seed; `-Dsuite=node-dst -Dfilter=<item>` replays it bit for bit.
const std = @import("std");
const harness = @import("harness");
const dst = @import("dst/root.zig");

const chains_n = 12;

const Families = struct {
    const names = [_][]const u8{ "full", "quiet", "nocrash", "noio", "longrun", "replay" };
};

const State = struct {
    chains: []*dst.Chain,
    totals: *Totals,
};

const A = std.atomic.Value(u64);
const Totals = struct {
    runs: A = .init(0),
    commits: A = .init(0),
    kills: A = .init(0),
    op_crashes: A = .init(0),
    io_exits: A = .init(0),
    oom_exits: A = .init(0),
    recoveries: A = .init(0),
    requests: A = .init(0),
    drops: A = .init(0),
    timeouts: A = .init(0),
    forged_served: A = .init(0),
    off_chain: A = .init(0),
    rejected: [16]A = @splat(.init(0)),
    kept: A = .init(0),
    virtual_ms: A = .init(0),
};

pub fn run(ctx: *harness.Ctx) !void {
    const gpa = ctx.gpa;
    var per: usize = 256;
    if (std.c.getenv("ZUI_NODE_DST_SEEDS")) |v| per = std.fmt.parseInt(usize, std.mem.span(v), 10) catch per;
    var chains: [chains_n]*dst.Chain = undefined;
    var made: usize = 0;
    defer for (chains[0..made]) |c| c.deinit();
    for (&chains, 0..) |*c, i| {
        c.* = try dst.Chain.generate(gpa, .{ .seed = 0x6e6f6465 + i, .checkpoints = 24 + @as(u32, @intCast(i)) * 4 });
        made += 1;
    }
    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    for (Families.names) |fam| for (1..per + 1) |k| try names.append(gpa, try std.fmt.allocPrint(gpa, "{s}/{d}", .{ fam, k }));
    var totals: Totals = .{};
    const st: State = .{ .chains = &chains, .totals = &totals };
    try ctx.forEachName(names.items, &st, runSeed);
    const t = &totals;
    try ctx.stderr.print("node-dst: {d} runs, {d} commits, {d} kills, {d} crashes at a disk op, {d} exits on I/O errors, {d} on out of memory, {d} recoveries, in-flight commit kept {d}; {d} requests ({d} dropped, {d} timed out), {d} forged blobs served, {d} peers marked off-chain, {d} virtual seconds\n", .{
        t.runs.load(.monotonic),    t.commits.load(.monotonic),    t.kills.load(.monotonic),
        t.op_crashes.load(.monotonic), t.io_exits.load(.monotonic), t.oom_exits.load(.monotonic), t.recoveries.load(.monotonic),
        t.kept.load(.monotonic),    t.requests.load(.monotonic),   t.drops.load(.monotonic),
        t.timeouts.load(.monotonic), t.forged_served.load(.monotonic), t.off_chain.load(.monotonic),
        t.virtual_ms.load(.monotonic) / 1000,
    });
    try ctx.stderr.print("node-dst: rejections", .{});
    const names_v = [_][]const u8{ "ok", "decode", "epoch", "bitmap", "stake", "signature", "digest", "chain", "no_committee" };
    for (names_v, 0..) |n, i| try ctx.stderr.print(" {s} {d}", .{ n, t.rejected[i].load(.monotonic) });
    try ctx.stderr.print("\n", .{});
}

fn runSeed(st: *const State, ctx: *harness.Ctx, name: []const u8) !void {
    const slash = std.mem.indexOfScalar(u8, name, '/').?;
    const fam = name[0..slash];
    const k = try std.fmt.parseInt(u64, name[slash + 1 ..], 10);
    var o: dst.Options = .{
        .seed = k *% 0x9e3779b97f4a7c15 ^ 0x70de_d570,
        .chain = st.chains[k % st.chains.len],
        .debug = std.c.getenv("ZUI_DST_DEBUG") != null,
    };
    o.checkpoints = @intCast(o.chain.?.len());
    if (std.mem.eql(u8, fam, "quiet")) {
        o.adversarial = false;
        o.io_faults = false;
        o.crashes = false;
        o.oom = false;
    } else if (std.mem.eql(u8, fam, "nocrash")) {
        o.crashes = false;
    } else if (std.mem.eql(u8, fam, "noio")) {
        o.io_faults = false;
    } else if (std.mem.eql(u8, fam, "longrun")) {
        o.heal_ms = 60_000;
        o.max_ms = 600_000;
        o.window = 3;
    } else if (std.mem.eql(u8, fam, "replay")) {
        // Determinism: the same seed twice agrees on every decision.
        const a = dst.run.run(ctx.gpa, o) catch |e| return ctx.fail(name, "error {s}", .{@errorName(e)});
        const b = dst.run.run(ctx.gpa, o) catch |e| return ctx.fail(name, "error {s}", .{@errorName(e)});
        if (a.trace != b.trace or a.commits != b.commits or a.virtual_ms != b.virtual_ms) {
            ctx.fail(name, "replay differs: trace {x} vs {x}, commits {d} vs {d}", .{ a.trace, b.trace, a.commits, b.commits });
            return;
        }
    }
    const r = dst.run.run(ctx.gpa, o) catch |e| {
        ctx.fail(name, "error {s}", .{@errorName(e)});
        return;
    };
    const t = st.totals;
    _ = t.runs.fetchAdd(1, .monotonic);
    _ = t.commits.fetchAdd(r.commits, .monotonic);
    _ = t.kills.fetchAdd(r.kills, .monotonic);
    _ = t.op_crashes.fetchAdd(r.op_crashes, .monotonic);
    _ = t.io_exits.fetchAdd(r.io_exits, .monotonic);
    _ = t.oom_exits.fetchAdd(r.oom_exits, .monotonic);
    _ = t.recoveries.fetchAdd(r.recoveries, .monotonic);
    _ = t.requests.fetchAdd(r.requests, .monotonic);
    _ = t.drops.fetchAdd(r.drops, .monotonic);
    _ = t.timeouts.fetchAdd(r.timeouts, .monotonic);
    _ = t.forged_served.fetchAdd(r.forged_served, .monotonic);
    _ = t.off_chain.fetchAdd(r.off_chain_marked, .monotonic);
    _ = t.kept.fetchAdd(r.in_flight_kept, .monotonic);
    _ = t.virtual_ms.fetchAdd(r.virtual_ms, .monotonic);
    for (r.rejected, 0..) |n, i| _ = t.rejected[i].fetchAdd(n, .monotonic);
    if (!r.ok) {
        ctx.fail(name, "{s} (replay: -Dsuite=node-dst -Dfilter={s})", .{ r.msg(), name });
        return;
    }
    ctx.pass(name);
}
