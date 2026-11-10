//! Shared pieces of the validator speed bench (docs/VALIDATOR-SPEED.md): the timing record both
//! sides print, nearest-rank percentiles, a wall-clock helper for N threads, and the comparison of
//! deepwave's canonical output lines with the Rust ones (tools/truth/val-bench writes
//! `bench/val-bench/rust-<stage>.out` under the bench corpus view).
const std = @import("std");
const harness = @import("harness");
const hash = @import("hash");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const dir = "bench/val-bench";

pub fn now(io: Io) Io.Timestamp {
    return Io.Timestamp.now(io, .awake);
}

pub fn since(io: Io, t0: Io.Timestamp) u64 {
    return @intCast(t0.durationTo(now(io)).nanoseconds);
}

/// Nearest-rank percentile of sorted nanoseconds (the Rust side uses the same rule).
pub fn pct(sorted: []const u64, p: f64) u64 {
    if (sorted.len == 0) return 0;
    const k: usize = @intFromFloat(@ceil(p / 100.0 * @as(f64, @floatFromInt(sorted.len))));
    return sorted[std.math.clamp(k, 1, sorted.len) - 1];
}

pub fn hexOf(a: Allocator, b: []const u8) Allocator.Error![]u8 {
    const out = try a.alloc(u8, b.len * 2);
    const digits = "0123456789abcdef";
    for (b, 0..) |x, i| {
        out[2 * i] = digits[x >> 4];
        out[2 * i + 1] = digits[x & 15];
    }
    return out;
}

pub fn digestHex(text: []const u8) [64]u8 {
    const d = hash.blake2b256(&.{text});
    var out: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{&d}) catch unreachable;
    return out;
}

pub const Rec = struct {
    stage: []const u8,
    case: []const u8,
    mode: []const u8,
    threads: usize,
    unit: []const u8,
    /// Per-item ns (sorted in place by `emit`); empty for wall-only runs.
    items: []u64 = &.{},
    count: u64,
    wall_ns: u64,
    out: []const u8 = "",
    /// Extra JSON members, starting with a comma.
    extra: []const u8 = "",
};

/// Prints one `{"impl":"deepwave",...}` timing line to stdout (the merge script reads both sides').
pub fn emit(ctx: *harness.Ctx, r: Rec) void {
    std.mem.sort(u64, r.items, {}, std.sort.asc(u64));
    var sum: u64 = 0;
    for (r.items) |t| sum += t;
    const mean: f64 = if (r.items.len == 0)
        @as(f64, @floatFromInt(r.wall_ns)) / @as(f64, @floatFromInt(@max(r.count, 1)))
    else
        @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(r.items.len));
    const per_s: f64 = if (r.wall_ns > 0) @as(f64, @floatFromInt(r.count)) * 1e9 / @as(f64, @floatFromInt(r.wall_ns)) else 0;
    ctx.shared.out_lock.lockUncancelable(ctx.io);
    defer ctx.shared.out_lock.unlock(ctx.io);
    ctx.stdout.print(
        "{{\"impl\":\"zui\",\"stage\":\"{s}\",\"case\":\"{s}\",\"mode\":\"{s}\",\"threads\":{d},\"unit\":\"{s}\",\"items\":{d},\"p50_ns\":{d},\"p99_ns\":{d},\"mean_ns\":{d:.1},\"per_s\":{d:.1},\"out\":\"{s}\"{s}}}\n",
        .{ r.stage, r.case, r.mode, r.threads, r.unit, r.count, pct(r.items, 50), pct(r.items, 99), mean, per_s, r.out, r.extra },
    ) catch {};
    ctx.stdout.flush() catch {};
}

/// Runs `f(state, i)` for i in 0..n split in `threads` contiguous parts on fresh threads; best
/// wall time (ns) of `reps`.
pub fn parWall(io: Io, n: usize, threads: usize, reps: usize, state: anytype, comptime f: fn (@TypeOf(state), usize) void) u64 {
    const S = @TypeOf(state);
    const W = struct {
        fn run(s: S, lo: usize, hi: usize) void {
            var i = lo;
            while (i < hi) : (i += 1) f(s, i);
        }
    };
    var best: u64 = std.math.maxInt(u64);
    var rep: usize = 0;
    while (rep < @max(reps, 1)) : (rep += 1) {
        const chunk = @max(1, (n + threads - 1) / threads);
        var ts: [64]?std.Thread = @splat(null);
        const t0 = now(io);
        var lo: usize = 0;
        var k: usize = 0;
        while (lo < n and k < ts.len) : (k += 1) {
            const hi = @min(n, lo + chunk);
            ts[k] = std.Thread.spawn(.{ .stack_size = 16 << 20 }, W.run, .{ state, lo, hi }) catch blk: {
                W.run(state, lo, hi);
                break :blk null;
            };
            lo = hi;
        }
        for (ts[0..k]) |t| if (t) |th| th.join();
        best = @min(best, since(io, t0));
    }
    return best;
}

/// Reads the list of corpus .chk paths the Rust side was given (`bench/val-bench/<stage>.list`,
/// absolute paths into this corpus view) and returns them relative to the corpus.
pub fn readList(ctx: *harness.Ctx, a: Allocator, stage: []const u8) ![]const []const u8 {
    const p = try std.fmt.allocPrint(a, dir ++ "/{s}.list", .{stage});
    const text = try ctx.corpus.readFileAlloc(ctx.io, p, a, .limited(64 << 20));
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |l| {
        const at = std.mem.indexOf(u8, l, "/chk/") orelse return error.BadListLine;
        try out.append(a, l[at + 1 ..]);
    }
    return out.items;
}

pub fn seqOf(path: []const u8) !u64 {
    const base = std.fs.path.basename(path);
    const dot = std.mem.indexOfScalar(u8, base, '.') orelse base.len;
    return std.fmt.parseInt(u64, base[0..dot], 10);
}

/// Compares deepwave's canonical lines with the Rust file line by line: one harness item per stage
/// (pass when identical), the first few differing lines printed.
pub fn compareOut(ctx: *harness.Ctx, a: Allocator, stage: []const u8, mine: []const u8) !bool {
    const p = try std.fmt.allocPrint(a, dir ++ "/rust-{s}.out", .{stage});
    const want = ctx.corpus.readFileAlloc(ctx.io, p, a, .limited(4 << 30)) catch |e| {
        ctx.fail(stage, "no Rust output {s}: {s}", .{ p, @errorName(e) });
        return false;
    };
    var wi = std.mem.splitScalar(u8, want, '\n');
    var mi = std.mem.splitScalar(u8, mine, '\n');
    var line: usize = 0;
    var diffs: usize = 0;
    var first: ?usize = null;
    while (true) {
        const w = wi.next();
        const m = mi.next();
        if (w == null and m == null) break;
        line += 1;
        const ws = w orelse "<end>";
        const ms = m orelse "<end>";
        if (!std.mem.eql(u8, ws, ms)) {
            diffs += 1;
            if (first == null) first = line;
            if (diffs <= 8) ctx.detail("DIFF {s} line {d}\n  rust: {s}\n  zui:  {s}\n", .{ stage, line, ws[0..@min(ws.len, 400)], ms[0..@min(ms.len, 400)] });
        }
    }
    if (diffs == 0) {
        ctx.pass(stage);
        return true;
    }
    ctx.fail(stage, "{d} of {d} output lines differ from Rust (first at line {d})", .{ diffs, line, first.? });
    return false;
}
