//! deepwave conformance harness (CONTRACTS.md section 3, docs/CONFORMANCE.md).
//!
//! Each lane registers suites in its own `src/<lane>/conformance.zig`:
//!
//!     pub const suites = [_]harness.Suite{
//!         .{ .name = "bcs", .lane = "bcs-types", .doc = "...", .run = run, .bench = bench,
//!            .baselines = &.{.{ .name = "decode", .argv = &.{ "{dumper}", "bench", "decode" } }} },
//!     };
//!
//! and `zig build test-conformance -Dsuite=bcs` runs it against $ZUI_CORPUS. A suite walks its
//! corpus items, compares deepwave's output to Mysten's ground truth byte for byte, and records one
//! pass, fail or skip per item. The run succeeds only when at least one item ran and every item
//! passed. Never weaken a comparison and never special-case items.
//!
//! Item work that is per file should go through `ctx.forEachFile`, which spreads files over
//! `-Djobs` worker threads (each with its own scratch arena and stats) and stays deterministic:
//! the summary does not depend on the job count or on scheduling.
const std = @import("std");
const core = @import("core");
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// Reviewer-owned suites that check the corpus itself.
pub const corpus_suite = @import("corpus_suite.zig");
/// Reviewer suites that run the lean lane's oracles (lean-bcs, lean-gas, lean-store).
pub const lean_suite = @import("lean_suite.zig");
/// Parser for the checkpoint truth files written by `zui-dumper truth` (docs/CONFORMANCE.md).
pub const truth = @import("truth.zig");

pub const Suite = struct {
    /// Suite name used with -Dsuite=. Unique across the repo (CONTRACTS.md section 3.3).
    name: []const u8,
    /// Owning lane, e.g. "bcs-types".
    lane: []const u8,
    /// One line: what is compared against what.
    doc: []const u8,
    run: *const fn (*Ctx) anyerror!void,
    /// Optional speed run over `ctx.benchInputs()`; records through `ctx.benchPasses`.
    bench: ?*const fn (*Ctx) anyerror!void = null,
    /// Rust baselines run by `zig build bench` on exactly the same inputs (CONTRACTS.md section 7).
    baselines: []const Baseline = &.{},
    /// Corpus files the bench runs over, on both sides.
    inputs: Inputs = .{},
};

/// The corpus files a bench reads: `<dir>/*<suffix>`, relative to $ZUI_CORPUS.
pub const Inputs = struct {
    dir: []const u8 = "chk",
    suffix: []const u8 = ".chk",
};

/// A Rust command timed on the same inputs as the Zig bench record of the same `name`.
/// `argv[i]` may start with "{dumper}" ($ZUI_DUMPER) or "{release}" ($CARGO_TARGET_DIR/release).
/// The harness appends `--iters N --list <file>` (one absolute input path per line). The command
/// prints JSON lines `{"impl":"rust","bench":<name>,"unit":..,"units":..,"ns_per_unit":..}`
/// with the median pass, as `zui-dumper bench` does.
pub const Baseline = struct {
    name: []const u8,
    argv: []const []const u8,
};

pub const Stats = struct {
    items: u64 = 0,
    passed: u64 = 0,
    failed: u64 = 0,
    skipped: u64 = 0,

    pub fn add(a: *Stats, b: Stats) void {
        a.items += b.items;
        a.passed += b.passed;
        a.failed += b.failed;
        a.skipped += b.skipped;
    }
};

pub const Options = struct {
    /// Stop after this many items (smoke runs). A limited run never counts as "done".
    limit: ?u64 = null,
    /// Only items whose id contains this substring.
    filter: ?[]const u8 = null,
    /// Max failure and skip details printed per suite.
    max_fail_details: u32 = 20,
    /// Bench passes (median reported).
    iters: u32 = 5,
    /// Worker threads for `forEachFile` (1 = run inline).
    jobs: u32 = 1,
    /// Bench input cap in bytes: an evenly spaced, deterministic subset of the input files.
    bench_bytes: u64 = 256 << 20,
};

/// State shared by every worker of one suite run.
pub const Shared = struct {
    items: std.atomic.Value(u64) = .init(0),
    details: std.atomic.Value(u32) = .init(0),
    out_lock: Io.Mutex = .init,
};

pub const BenchRecord = struct {
    name: []const u8,
    unit: []const u8,
    units: u64,
    ns_per_unit: f64,
};

pub const Ctx = struct {
    gpa: Allocator,
    /// Per-item scratch, reset by `nextItem` (and by `forEachFile` before each file).
    arena: *std.heap.ArenaAllocator,
    io: Io,
    corpus: Io.Dir,
    corpus_path: []const u8,
    suite: *const Suite,
    opts: Options,
    stats: Stats = .{},
    stderr: *Io.Writer,
    stdout: *Io.Writer,
    shared: *Shared,
    /// Bench mode: the input files (relative to the corpus), identical for Zig and Rust.
    bench_inputs: []const []const u8 = &.{},
    /// Bench mode: records made by `benchPasses` / `benchRecord`, compared with the baselines.
    bench_records: ?*std.ArrayList(BenchRecord) = null,

    /// True when the suite should stop iterating (limit reached).
    pub fn done(ctx: *const Ctx) bool {
        if (ctx.opts.limit) |l| return ctx.shared.items.load(.monotonic) >= l;
        return false;
    }

    /// True when `item` is selected by -Dfilter. Suites skip unselected items silently.
    pub fn selected(ctx: *const Ctx, item: []const u8) bool {
        const f = ctx.opts.filter orelse return true;
        return std.mem.indexOf(u8, item, f) != null;
    }

    /// Frees per-item scratch memory. Call at the start of each item.
    pub fn nextItem(ctx: *Ctx) void {
        _ = ctx.arena.reset(.retain_capacity);
    }

    pub fn scratch(ctx: *Ctx) Allocator {
        return ctx.arena.allocator();
    }

    fn count(ctx: *Ctx) void {
        ctx.stats.items += 1;
        _ = ctx.shared.items.fetchAdd(1, .monotonic);
    }

    pub fn pass(ctx: *Ctx, item: []const u8) void {
        _ = item;
        ctx.count();
        ctx.stats.passed += 1;
    }

    pub fn fail(ctx: *Ctx, item: []const u8, comptime fmt: []const u8, args: anytype) void {
        ctx.count();
        ctx.stats.failed += 1;
        ctx.detail("FAIL {s} {s}: " ++ fmt ++ "\n", .{ ctx.suite.name, item } ++ args);
    }

    /// Items the suite could not evaluate for a reason outside deepwave (e.g. a corpus file the
    /// suite does not cover yet). Skips make a run not-done, exactly like failures.
    pub fn skip(ctx: *Ctx, item: []const u8, reason: []const u8) void {
        ctx.count();
        ctx.stats.skipped += 1;
        ctx.detail("SKIP {s} {s}: {s}\n", .{ ctx.suite.name, item, reason });
    }

    /// Prints one failure detail (bounded by max_fail_details per suite, serialized across workers).
    pub fn detail(ctx: *Ctx, comptime fmt: []const u8, args: anytype) void {
        if (ctx.shared.details.fetchAdd(1, .monotonic) >= ctx.opts.max_fail_details) return;
        ctx.shared.out_lock.lockUncancelable(ctx.io);
        defer ctx.shared.out_lock.unlock(ctx.io);
        ctx.stderr.print(fmt, args) catch {};
        ctx.stderr.flush() catch {};
    }

    /// Starts a multi-comparison item: every check prints its own minimal diff, and `finish`
    /// records exactly one pass (all equal) or one fail for the item.
    pub fn check(ctx: *Ctx, item: []const u8) Check {
        return .{ .ctx = ctx, .item = item };
    }

    /// One-comparison item: pass when equal, else fail with a hex window around the first
    /// differing byte. Returns true when equal.
    pub fn expectBytes(ctx: *Ctx, item: []const u8, what: []const u8, expected: []const u8, actual: []const u8) bool {
        var c = ctx.check(item);
        c.bytes(what, expected, actual);
        return c.finish();
    }

    /// One-comparison item for text (tree text, rendered YAML): fail shows both sides around
    /// the first differing character.
    pub fn expectText(ctx: *Ctx, item: []const u8, what: []const u8, expected: []const u8, actual: []const u8) bool {
        var c = ctx.check(item);
        c.text(what, expected, actual);
        return c.finish();
    }

    /// Reads `sub_path` (relative to $ZUI_CORPUS) into per-item scratch memory.
    pub fn readFile(ctx: *Ctx, sub_path: []const u8, max_bytes: usize) ![]u8 {
        return ctx.corpus.readFileAlloc(ctx.io, sub_path, ctx.scratch(), .limited(max_bytes));
    }

    /// Reads and zstd-decompresses `sub_path` into per-item scratch memory.
    pub fn readZstd(ctx: *Ctx, sub_path: []const u8, max_bytes: usize) ![]u8 {
        const z = try ctx.readFile(sub_path, max_bytes);
        return decompressZstd(ctx.scratch(), z, max_bytes);
    }

    /// Sorted names of regular files in `sub_dir` ending in `suffix`, allocated with gpa
    /// (free with `freeNames`). Corpus order is numeric when names are numbers.
    pub fn listFiles(ctx: *Ctx, sub_dir: []const u8, suffix: []const u8) ![][]const u8 {
        return listFilesIn(ctx.gpa, ctx.io, ctx.corpus, sub_dir, suffix);
    }

    pub fn freeNames(ctx: *Ctx, names: [][]const u8) void {
        for (names) |n| ctx.gpa.free(n);
        ctx.gpa.free(names);
    }

    /// Calls `f(state, worker_ctx, name)` for every file `<sub_dir>/*<suffix>` that -Dfilter
    /// selects (the filter matches the file name), until -Dlimit is reached. Runs on `-Djobs`
    /// threads; each worker has its own arena (reset before each file) and stats, merged into
    /// `ctx` at the end. `state` is shared by all workers and must only be read. Returns the
    /// first error any call returned (the remaining files still run).
    pub fn forEachFile(
        ctx: *Ctx,
        sub_dir: []const u8,
        suffix: []const u8,
        state: anytype,
        comptime f: fn (@TypeOf(state), *Ctx, []const u8) anyerror!void,
    ) !void {
        const names = try ctx.listFiles(sub_dir, suffix);
        defer ctx.freeNames(names);
        return ctx.forEachName(names, state, f);
    }

    /// `forEachFile` over a caller-made name list.
    pub fn forEachName(
        ctx: *Ctx,
        names: []const []const u8,
        state: anytype,
        comptime f: fn (@TypeOf(state), *Ctx, []const u8) anyerror!void,
    ) !void {
        const S = @TypeOf(state);
        const Pool = struct {
            next: std.atomic.Value(usize) = .init(0),
            first_err: std.atomic.Value(u16) = .init(0),
            names: []const []const u8,
            state: S,

            fn work(pool: *@This(), w: *Ctx) void {
                while (!w.done()) {
                    const i = pool.next.fetchAdd(1, .monotonic);
                    if (i >= pool.names.len) break;
                    const name = pool.names[i];
                    if (!w.selected(name)) continue;
                    w.nextItem();
                    f(pool.state, w, name) catch |e| {
                        _ = pool.first_err.cmpxchgStrong(0, @intFromError(e), .monotonic, .monotonic);
                    };
                }
            }
        };
        var pool: Pool = .{ .names = names, .state = state };
        const jobs: usize = @max(1, @min(ctx.opts.jobs, names.len));
        if (jobs == 1) {
            pool.work(ctx);
        } else {
            const workers = try ctx.gpa.alloc(Ctx, jobs);
            defer ctx.gpa.free(workers);
            const arenas = try ctx.gpa.alloc(std.heap.ArenaAllocator, jobs);
            defer ctx.gpa.free(arenas);
            const threads = try ctx.gpa.alloc(std.Thread, jobs);
            defer ctx.gpa.free(threads);
            for (workers, arenas) |*w, *a| {
                a.* = .init(std.heap.page_allocator);
                w.* = ctx.*;
                w.arena = a;
                w.stats = .{};
            }
            defer for (arenas) |*a| a.deinit();
            var spawned: usize = 0;
            defer for (threads[0..spawned]) |t| t.join();
            for (threads, workers) |*t, *w| {
                t.* = std.Thread.spawn(.{ .stack_size = 64 << 20 }, Pool.work, .{ &pool, w }) catch |e| {
                    if (spawned == 0) return e;
                    break;
                };
                spawned += 1;
            }
            for (threads[0..spawned]) |t| t.join();
            const joined = spawned;
            spawned = 0;
            for (workers[0..joined]) |w| ctx.stats.add(w.stats);
        }
        const code = pool.first_err.load(.monotonic);
        if (code != 0) return @errorFromInt(code);
    }

    /// Bench inputs: paths relative to the corpus (`<inputs.dir>/<name>`), the same list the
    /// Rust baselines get.
    pub fn benchInputs(ctx: *const Ctx) []const []const u8 {
        return ctx.bench_inputs;
    }

    /// Times `iters` passes of `f(state)` after one untimed warm-up pass and records the median
    /// pass as `ns_per_unit = median_ns / units`. One pass must process every bench input once.
    pub fn benchPasses(
        ctx: *Ctx,
        name: []const u8,
        unit: []const u8,
        units: u64,
        state: anytype,
        comptime f: fn (@TypeOf(state)) anyerror!void,
    ) !void {
        try f(state);
        const iters = @max(1, ctx.opts.iters);
        const times = try ctx.gpa.alloc(u64, iters);
        defer ctx.gpa.free(times);
        for (times) |*t| {
            const t0 = Io.Timestamp.now(ctx.io, .awake);
            try f(state);
            const t1 = Io.Timestamp.now(ctx.io, .awake);
            t.* = @intCast(t0.durationTo(t1).nanoseconds);
        }
        std.mem.sort(u64, times, {}, std.sort.asc(u64));
        const med = times[times.len / 2];
        ctx.record(name, unit, units, med, times[0], iters);
    }

    /// Records the passes a suite timed itself (`times`: one total per pass over `units`
    /// units): median and min over every pass, `iters` = the number of passes. Sorts `times`.
    pub fn benchRecordTimes(ctx: *Ctx, name: []const u8, unit: []const u8, units: u64, times: []u64) void {
        if (times.len == 0) return;
        std.mem.sort(u64, times, {}, std.sort.asc(u64));
        ctx.record(name, unit, units, times[times.len / 2], times[0], @intCast(times.len));
    }

    /// Records one bench result measured by the suite itself: `total_ns` over `units` units.
    pub fn benchRecord(ctx: *Ctx, name: []const u8, unit: []const u8, units: u64, total_ns: u64) void {
        ctx.record(name, unit, units, total_ns, total_ns, 1);
    }

    fn record(ctx: *Ctx, name: []const u8, unit: []const u8, units: u64, med_ns: u64, min_ns: u64, iters: u32) void {
        const per = if (units == 0) 0 else @as(f64, @floatFromInt(med_ns)) / @as(f64, @floatFromInt(units));
        ctx.stdout.print(
            "{{\"impl\":\"zui\",\"suite\":\"{s}\",\"bench\":\"{s}\",\"mode\":\"{s}\",\"unit\":\"{s}\",\"units\":{d},\"iters\":{d},\"median_ns\":{d},\"min_ns\":{d},\"ns_per_unit\":{d:.2}}}\n",
            .{ ctx.suite.name, name, core.build_mode, unit, units, iters, med_ns, min_ns, per },
        ) catch {};
        // The record outlives the suite's bench function, so it owns copies of `name` and `unit`
        // (a suite may build names at run time in memory it frees). The runner frees them.
        if (ctx.bench_records) |list| {
            const n = ctx.gpa.dupe(u8, name) catch return;
            const u = ctx.gpa.dupe(u8, unit) catch {
                ctx.gpa.free(n);
                return;
            };
            list.append(ctx.gpa, .{ .name = n, .unit = u, .units = units, .ns_per_unit = per }) catch {
                ctx.gpa.free(n);
                ctx.gpa.free(u);
            };
        }
    }
};

/// Collects the comparisons of one item and records it once (see `Ctx.check`).
pub const Check = struct {
    ctx: *Ctx,
    item: []const u8,
    failures: u32 = 0,

    /// Bytes must be equal. On a difference prints lengths, the first differing offset and a
    /// 16-byte hex window of each side around it.
    pub fn bytes(c: *Check, what: []const u8, expected: []const u8, actual: []const u8) void {
        if (std.mem.eql(u8, expected, actual)) return;
        c.failures += 1;
        const at = firstDiff(expected, actual);
        const lo = at -| 8;
        c.ctx.detail("FAIL {s} {s}: {s} differs at byte {d} (expected {d} bytes, got {d})\n" ++
            "     expected[{d}..]: {x}\n     actual  [{d}..]: {x}\n", .{
            c.ctx.suite.name,          c.item,                        what, at, expected.len, actual.len,
            lo,                        window(expected, lo, 16), lo,   window(actual, lo, 16),
        });
    }

    /// Text must be equal. On a difference prints the first differing character's offset and up
    /// to 60 characters of each side around it.
    pub fn text(c: *Check, what: []const u8, expected: []const u8, actual: []const u8) void {
        if (std.mem.eql(u8, expected, actual)) return;
        c.failures += 1;
        const at = firstDiff(expected, actual);
        const lo = at -| 30;
        c.ctx.detail("FAIL {s} {s}: {s} differs at char {d} (expected {d} chars, got {d})\n" ++
            "     expected[{d}..]: {s}\n     actual  [{d}..]: {s}\n", .{
            c.ctx.suite.name, c.item,                    what, at, expected.len, actual.len,
            lo,               window(expected, lo, 60), lo,   window(actual, lo, 60),
        });
    }

    /// Scalars, enums, bools and optionals must be equal.
    pub fn eql(c: *Check, what: []const u8, expected: anytype, actual: @TypeOf(expected)) void {
        if (std.meta.eql(expected, actual)) return;
        c.failures += 1;
        c.ctx.detail("FAIL {s} {s}: {s}: expected {any}, got {any}\n", .{ c.ctx.suite.name, c.item, what, expected, actual });
    }

    /// A digest (or any output) given as lowercase hex in the truth must equal `actual`. Any
    /// length; compared 64 bytes at a time, a difference reports its byte offset.
    pub fn digestHex(c: *Check, what: []const u8, expected_hex: []const u8, actual: []const u8) void {
        if (expected_hex.len != actual.len * 2) {
            c.failures += 1;
            c.ctx.detail("FAIL {s} {s}: {s}: truth has {d} hex chars, got {d} bytes\n", .{ c.ctx.suite.name, c.item, what, expected_hex.len, actual.len });
            return;
        }
        var off: usize = 0;
        while (off < actual.len) : (off += 64) {
            const n: usize = @min(64, actual.len - off);
            var buf: [128]u8 = undefined;
            const got = std.fmt.bufPrint(&buf, "{x}", .{actual[off..][0..n]}) catch unreachable;
            const want = expected_hex[2 * off ..][0 .. 2 * n];
            if (std.mem.eql(u8, want, got)) continue;
            c.failures += 1;
            c.ctx.detail("FAIL {s} {s}: {s} differs in bytes {d}..{d} of {d}\n     expected: {s}\n     actual  : {s}\n", .{ c.ctx.suite.name, c.item, what, off, off + n, actual.len, want, got });
            return;
        }
    }

    /// A failure that is not a comparison (decode error, missing value).
    pub fn failf(c: *Check, comptime fmt: []const u8, args: anytype) void {
        c.failures += 1;
        c.ctx.detail("FAIL {s} {s}: " ++ fmt ++ "\n", .{ c.ctx.suite.name, c.item } ++ args);
    }

    pub fn ok(c: *const Check) bool {
        return c.failures == 0;
    }

    /// Records the item: one pass when every check was equal, else one fail. Returns ok().
    pub fn finish(c: *Check) bool {
        c.ctx.count();
        if (c.failures == 0) c.ctx.stats.passed += 1 else c.ctx.stats.failed += 1;
        return c.failures == 0;
    }
};

fn firstDiff(a: []const u8, b: []const u8) usize {
    const n = @min(a.len, b.len);
    for (0..n) |i| if (a[i] != b[i]) return i;
    return n;
}

fn window(s: []const u8, lo: usize, len: usize) []const u8 {
    if (lo >= s.len) return s[s.len..];
    return s[lo..@min(s.len, lo + len)];
}

/// zstd-decompresses a whole frame sequence into memory owned by `gpa`.
pub fn decompressZstd(gpa: Allocator, compressed: []const u8, max_bytes: usize) ![]u8 {
    var in: Io.Reader = .fixed(compressed);
    const zstd = std.compress.zstd;
    const window_buf = try gpa.alloc(u8, zstd.default_window_len + zstd.block_size_max);
    defer gpa.free(window_buf);
    var d: zstd.Decompress = .init(&in, window_buf, .{});
    return d.reader.allocRemaining(gpa, .limited(max_bytes));
}

/// Numeric-aware ordering: "9.chk" < "10.chk".
fn lessName(_: void, a: []const u8, b: []const u8) bool {
    const na = leadingNumber(a);
    const nb = leadingNumber(b);
    if (na != null and nb != null and na.? != nb.?) return na.? < nb.?;
    return std.mem.lessThan(u8, a, b);
}

pub fn leadingNumber(s: []const u8) ?u64 {
    var i: usize = 0;
    while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
    if (i == 0) return null;
    return std.fmt.parseInt(u64, s[0..i], 10) catch null;
}

pub fn listFilesIn(gpa: Allocator, io: Io, root: Io.Dir, sub_dir: []const u8, suffix: []const u8) ![][]const u8 {
    var dir = try root.openDir(io, sub_dir, .{ .iterate = true });
    defer dir.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .file and e.kind != .sym_link) continue;
        if (!std.mem.endsWith(u8, e.name, suffix)) continue;
        if (e.name.len > 0 and e.name[0] == '.') continue; // in-flight .part files
        try names.append(gpa, try gpa.dupe(u8, e.name));
    }
    const out = try names.toOwnedSlice(gpa);
    std.mem.sort([]const u8, out, {}, lessName);
    return out;
}

/// Splits newline-delimited text (truth .jsonl files). Empty trailing line is skipped.
pub const LineIterator = struct {
    rest: []const u8,
    pub fn next(it: *LineIterator) ?[]const u8 {
        while (it.rest.len > 0) {
            const nl = std.mem.indexOfScalar(u8, it.rest, '\n') orelse it.rest.len;
            const line = it.rest[0..nl];
            it.rest = if (nl < it.rest.len) it.rest[nl + 1 ..] else it.rest[it.rest.len..];
            if (line.len > 0) return line;
        }
        return null;
    }
};

pub fn lines(text_: []const u8) LineIterator {
    return .{ .rest = text_ };
}

test "line iterator" {
    var it = lines("a\n\nb\n");
    try std.testing.expectEqualStrings("a", it.next().?);
    try std.testing.expectEqualStrings("b", it.next().?);
    try std.testing.expect(it.next() == null);
}

test "numeric name order" {
    var names = [_][]const u8{ "10.chk", "9.chk", "100.chk" };
    std.mem.sort([]const u8, &names, {}, lessName);
    try std.testing.expectEqualStrings("9.chk", names[0]);
    try std.testing.expectEqualStrings("100.chk", names[2]);
}

test "diff helpers" {
    try std.testing.expectEqual(@as(usize, 2), firstDiff("abc", "abd"));
    try std.testing.expectEqual(@as(usize, 3), firstDiff("abc", "abcd"));
    try std.testing.expectEqualStrings("cd", window("abcd", 2, 16));
    try std.testing.expectEqualStrings("", window("ab", 5, 16));
}

test "check records one result per item, forEachName is job-count independent" {
    const io = std.testing.io;
    var discard_buf: [256]u8 = undefined;
    var discard: Io.Writer.Discarding = .init(&discard_buf);
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const suite: Suite = .{ .name = "t", .lane = "t", .doc = "", .run = undefined };
    var results: [2]Stats = undefined;
    for ([_]u32{ 1, 4 }, 0..) |jobs, r| {
        var shared: Shared = .{};
        var ctx: Ctx = .{
            .gpa = std.testing.allocator,
            .arena = &arena,
            .io = io,
            .corpus = undefined,
            .corpus_path = "",
            .suite = &suite,
            .opts = .{ .jobs = jobs },
            .stderr = &discard.writer,
            .stdout = &discard.writer,
            .shared = &shared,
        };
        var names: [100][]const u8 = undefined;
        var bufs: [100][8]u8 = undefined;
        for (&names, &bufs, 0..) |*n, *b, i| n.* = std.fmt.bufPrint(b, "{d}", .{i}) catch unreachable;
        const T = struct {
            fn each(_: void, w: *Ctx, name: []const u8) !void {
                const v = try std.fmt.parseInt(u32, name, 10);
                var c = w.check(name);
                c.eql("even", true, true);
                if (v % 10 == 3) c.bytes("b", "abc", "abd");
                if (v % 10 == 3) c.text("t", "x", "y");
                _ = try w.scratch().alloc(u8, 100);
                _ = c.finish();
            }
        };
        try ctx.forEachName(&names, {}, T.each);
        results[r] = ctx.stats;
    }
    try std.testing.expectEqual(results[0], results[1]);
    try std.testing.expectEqual(@as(u64, 100), results[0].items);
    try std.testing.expectEqual(@as(u64, 10), results[0].failed);
}

test "digestHex compares outputs of any length; bench records own their names" {
    const io = std.testing.io;
    var discard_buf: [256]u8 = undefined;
    var discard: Io.Writer.Discarding = .init(&discard_buf);
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const suite: Suite = .{ .name = "t", .lane = "t", .doc = "", .run = undefined };
    var shared: Shared = .{};
    var records: std.ArrayList(BenchRecord) = .empty;
    var ctx: Ctx = .{
        .gpa = std.testing.allocator,
        .arena = &arena,
        .io = io,
        .corpus = undefined,
        .corpus_path = "",
        .suite = &suite,
        .opts = .{ .jobs = 1 },
        .stderr = &discard.writer,
        .stdout = &discard.writer,
        .shared = &shared,
        .bench_records = &records,
    };
    var long: [200]u8 = undefined;
    for (&long, 0..) |*b, i| b.* = @truncate(i * 7);
    var hex_buf: [400]u8 = undefined;
    const hex = std.fmt.bufPrint(&hex_buf, "{x}", .{&long}) catch unreachable;
    var c = ctx.check("ok");
    c.digestHex("200 bytes", hex, &long);
    c.digestHex("empty", "", "");
    try std.testing.expect(c.ok());
    long[150] ^= 1;
    var c2 = ctx.check("bad");
    c2.digestHex("200 bytes", hex, &long);
    try std.testing.expect(!c2.ok());
    var c3 = ctx.check("len");
    c3.digestHex("short", hex[0..10], &long);
    try std.testing.expect(!c3.ok());
    // a run-time name freed right after recording
    const name = try std.testing.allocator.dupe(u8, "built-at-run-time");
    ctx.benchRecord(name, "msg", 10, 100);
    @memset(name, 'x');
    std.testing.allocator.free(name);
    try std.testing.expectEqualStrings("built-at-run-time", records.items[0].name);
    for (records.items) |rec| {
        std.testing.allocator.free(rec.name);
        std.testing.allocator.free(rec.unit);
    }
    records.deinit(std.testing.allocator);
}

test {
    _ = truth;
    _ = lean_suite;
}
