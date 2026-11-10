//! deepwave-dst: runs the node simulation tester (src/node/dst) over many seeds on all cores.
//!
//!   deepwave-dst [--from N] [--count M] [--threads T] [--family F] [--chains K] [--checkpoints C]
//!                [--sabotage skip_cert|skip_chain|lose_ack] [--replay SEED] [--debug] [--forever]
//!
//! Families: full (default: every fault), quiet, nocrash, noio, longrun, and one fault kind at full
//! strength with the others off: forks, partitions, crashes, skew, forged. A failing seed is printed
//! with the command that replays it (`--replay SEED --family F`), and the exit status is 1.
//! `--forever` keeps drawing seeds (from `--from`, upward) until a failure or a signal: the soak
//! mode (millions of runs a day on a test machine). Build with -Doptimize=ReleaseFast.
const std = @import("std");
const node = @import("node");
const dst = node.dst;

const A = std.atomic.Value(u64);

const Shared = struct {
    next: A,
    end: u64,
    forever: bool,
    failed: A = .init(0),
    runs: A = .init(0),
    commits: A = .init(0),
    kills: A = .init(0),
    op_crashes: A = .init(0),
    io_exits: A = .init(0),
    oom_exits: A = .init(0),
    forged: A = .init(0),
    gpa: std.mem.Allocator,
    chains: []*dst.Chain,
    family: Family,
    checkpoints: u32,
    sabotage: dst.run.Sabotage,
    debug: bool,
    out_lock: std.atomic.Value(bool) = .init(false),
};

const Family = enum { full, quiet, nocrash, noio, longrun, forks, partitions, crashes, skew, forged };

fn seedOf(k: u64) u64 {
    return k *% 0x9e3779b97f4a7c15 ^ 0x70de_d570;
}

fn options(sh: *const Shared, k: u64) dst.Options {
    var o: dst.Options = .{ .seed = seedOf(k), .chain = sh.chains[k % sh.chains.len], .sabotage = sh.sabotage, .debug = sh.debug };
    o.checkpoints = @intCast(o.chain.?.len());
    switch (sh.family) {
        .full => {},
        .quiet => {
            o.adversarial = false;
            o.io_faults = false;
            o.crashes = false;
            o.oom = false;
        },
        .nocrash => o.crashes = false,
        .noio => o.io_faults = false,
        .longrun => {
            o.heal_ms = 60_000;
            o.max_ms = 600_000;
            o.window = 3;
        },
        // One fault kind at full strength, the others off (run.Focus).
        .forks, .partitions, .skew, .forged => {
            o.focus = std.meta.stringToEnum(dst.run.Focus, @tagName(sh.family)).?;
            o.io_faults = false;
            o.crashes = false;
            o.oom = false;
        },
        .crashes => {
            o.focus = .crashes;
            o.adversarial = false;
        },
    }
    return o;
}

fn worker(sh: *Shared) void {
    while (true) {
        const k = sh.next.fetchAdd(1, .monotonic);
        if (!sh.forever and k >= sh.end) return;
        if (sh.failed.load(.monotonic) != 0 and sh.forever) return;
        const r = dst.run.run(sh.gpa, options(sh, k)) catch |e| {
            std.debug.print("seed {d}: harness error {s}\n", .{ k, @errorName(e) });
            _ = sh.failed.fetchAdd(1, .monotonic);
            continue;
        };
        _ = sh.runs.fetchAdd(1, .monotonic);
        _ = sh.commits.fetchAdd(r.commits, .monotonic);
        _ = sh.kills.fetchAdd(r.kills, .monotonic);
        _ = sh.op_crashes.fetchAdd(r.op_crashes, .monotonic);
        _ = sh.io_exits.fetchAdd(r.io_exits, .monotonic);
        _ = sh.oom_exits.fetchAdd(r.oom_exits, .monotonic);
        _ = sh.forged.fetchAdd(r.forged_served, .monotonic);
        if (!r.ok) {
            _ = sh.failed.fetchAdd(1, .monotonic);
            std.debug.print("FAIL seed {d} ({s}): {s}\n  replay: deepwave-dst --family {t} --chains {d} --checkpoints {d} --replay {d} --debug\n", .{ k, @tagName(sh.family), r.msg(), sh.family, sh.chains.len, sh.checkpoints, k });
        }
    }
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var from: u64 = 1;
    var count: u64 = 1000;
    var threads: usize = @max(1, (std.Thread.getCpuCount() catch 2) -| 1);
    var family: Family = .full;
    var n_chains: usize = 12;
    var checkpoints: u32 = 32;
    var sabotage: dst.run.Sabotage = .none;
    var replay: ?u64 = null;
    var debug = false;
    var forever = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const val = if (i + 1 < args.len) args[i + 1] else "";
        if (std.mem.eql(u8, a, "--from")) {
            from = try std.fmt.parseInt(u64, val, 10);
            i += 1;
        } else if (std.mem.eql(u8, a, "--count")) {
            count = try std.fmt.parseInt(u64, val, 10);
            i += 1;
        } else if (std.mem.eql(u8, a, "--threads")) {
            threads = @max(1, try std.fmt.parseInt(usize, val, 10));
            i += 1;
        } else if (std.mem.eql(u8, a, "--family")) {
            family = std.meta.stringToEnum(Family, val) orelse return usage();
            i += 1;
        } else if (std.mem.eql(u8, a, "--chains")) {
            n_chains = @max(1, try std.fmt.parseInt(usize, val, 10));
            i += 1;
        } else if (std.mem.eql(u8, a, "--checkpoints")) {
            checkpoints = try std.fmt.parseInt(u32, val, 10);
            i += 1;
        } else if (std.mem.eql(u8, a, "--sabotage")) {
            sabotage = std.meta.stringToEnum(dst.run.Sabotage, val) orelse return usage();
            i += 1;
        } else if (std.mem.eql(u8, a, "--replay")) {
            replay = try std.fmt.parseInt(u64, val, 10);
            i += 1;
        } else if (std.mem.eql(u8, a, "--debug")) {
            debug = true;
        } else if (std.mem.eql(u8, a, "--forever")) {
            forever = true;
        } else return usage();
    }
    const chains = try gpa.alloc(*dst.Chain, n_chains);
    defer gpa.free(chains);
    var made: usize = 0;
    defer for (chains[0..made]) |c| c.deinit();
    for (chains, 0..) |*c, k| {
        c.* = try dst.Chain.generate(gpa, .{ .seed = 0x6e6f6465 + k, .checkpoints = checkpoints + @as(u32, @intCast(k)) * 4 });
        made += 1;
    }
    var sh: Shared = .{ .next = .init(from), .end = from + count, .forever = forever, .gpa = gpa, .chains = chains, .family = family, .checkpoints = checkpoints, .sabotage = sabotage, .debug = debug };
    if (replay) |k| {
        sh.next = .init(k);
        sh.end = k + 1;
        threads = 1;
    }
    const t0 = nowNs();
    const ts = try gpa.alloc(std.Thread, threads);
    defer gpa.free(ts);
    var spawned: usize = 0;
    for (ts) |*t| {
        t.* = try std.Thread.spawn(.{ .stack_size = 16 << 20 }, worker, .{&sh});
        spawned += 1;
    }
    for (ts[0..spawned]) |t| t.join();
    const ns: u64 = nowNs() - t0;
    const runs = sh.runs.load(.monotonic);
    std.debug.print("{d} runs in {d} ms ({d} per second), {d} failed; {d} commits, {d} kills, {d} crashes at a disk op, {d} exits on I/O errors, {d} on out of memory, {d} forged blobs served\n", .{
        runs,                          ns / 1_000_000,                  if (ns == 0) 0 else runs * 1_000_000_000 / ns, sh.failed.load(.monotonic),
        sh.commits.load(.monotonic),   sh.kills.load(.monotonic),       sh.op_crashes.load(.monotonic),                sh.io_exits.load(.monotonic),
        sh.oom_exits.load(.monotonic), sh.forged.load(.monotonic),
    });
    // With --sabotage the harness must notice: a clean sweep means the invariants are blind.
    if (sabotage != .none) return if (sh.failed.load(.monotonic) == 0) 1 else 0;
    return if (sh.failed.load(.monotonic) == 0) 0 else 1;
}

fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn usage() u8 {
    std.debug.print("usage: deepwave-dst [--from N] [--count M] [--threads T] [--family full|quiet|nocrash|noio|longrun|forks|partitions|crashes|skew|forged] [--chains K] [--checkpoints C] [--sabotage skip_cert|skip_chain|lose_ack] [--replay SEED] [--debug] [--forever]\n", .{});
    return 2;
}
