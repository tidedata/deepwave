//! deepwave-conformance: runs registered suites against $ZUI_CORPUS.
//!
//!   zig build test-conformance -Dsuite=bcs [-Dlimit=N] [-Dfilter=SUBSTR] [-Djobs=N]
//!   zig build test-conformance -Dsuite=corpus,corpus-chain      (comma list; lane names work too)
//!   zig build test-conformance -Dsuite=list                     (every suite and its lane)
//!   zig build bench -Dsuite=bcs -Doptimize=fast [-Diters=N] [-Dbench-bytes=N]
//!
//! Exit 0 only when every selected suite ran at least one item and all items passed with no
//! skips, no -Dlimit and no -Dfilter. Output ends with one JSON summary line per suite.
//!
//! Bench mode picks one deterministic input set per suite (Suite.inputs, evenly spaced over the
//! sorted corpus files, at most -Dbench-bytes), runs the Zig bench on it, then runs each
//! Suite.baselines Rust command on the very same files and prints one comparison line per
//! record name: {"compare":..., "zui_ns_per_unit":..., "rust_ns_per_unit":..., "speedup":...}.
const std = @import("std");
const harness = @import("harness");
const Io = std.Io;
const Allocator = std.mem.Allocator;

/// The lane modules this runner links, in dependency order: every module for deepwave-conformance,
/// one for deepwave-conformance-<module>, none for deepwave-conformance-harness. `zui_lanes` is generated
/// by build.zig from its module table. Reviewer-owned: lanes never edit this file; they add a
/// module row in build.zig and suites to the `suites` array in their own conformance.zig.
const linked = @import("zui_lanes");
const lanes = linked.lanes;

const all_suites: []const harness.Suite = blk: {
    @setEvalBranchQuota(1_000_000);
    var list: []const harness.Suite = &.{};
    if (linked.harness_suites) list = list ++ &harness.corpus_suite.suites ++ &harness.lean_suite.suites;
    for (lanes) |m| list = list ++ &m.conformance.suites;
    // Suite names must be unique.
    for (list, 0..) |a, i| for (list[i + 1 ..]) |b| {
        if (std.mem.eql(u8, a.name, b.name)) @compileError("duplicate suite name " ++ a.name);
    };
    break :blk list;
};

fn wanted(selection: []const u8, s: *const harness.Suite) bool {
    var it = std.mem.splitScalar(u8, selection, ',');
    while (it.next()) |raw| {
        const w = std.mem.trim(u8, raw, " ");
        if (std.mem.eql(u8, w, "all") or std.mem.eql(u8, w, s.name) or std.mem.eql(u8, w, s.lane)) return true;
    }
    return false;
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var out_buf: [8192]u8 = undefined;
    var err_buf: [8192]u8 = undefined;
    var out_w: Io.File.Writer = .init(.stdout(), io, &out_buf);
    var err_w: Io.File.Writer = .init(.stderr(), io, &err_buf);
    const stdout = &out_w.interface;
    const stderr = &err_w.interface;
    defer stdout.flush() catch {};
    defer stderr.flush() catch {};

    var suite_name: []const u8 = "all";
    var bench = false;
    var opts: harness.Options = .{};
    opts.jobs = @intCast(@min(16, std.Thread.getCpuCount() catch 1));
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const has_val = i + 1 < args.len;
        if (std.mem.eql(u8, a, "--bench")) {
            bench = true;
        } else if (has_val and std.mem.eql(u8, a, "--suite")) {
            i += 1;
            suite_name = args[i];
        } else if (has_val and std.mem.eql(u8, a, "--limit")) {
            i += 1;
            const n = try std.fmt.parseInt(u64, args[i], 10);
            if (n > 0) opts.limit = n;
        } else if (has_val and std.mem.eql(u8, a, "--filter")) {
            i += 1;
            if (args[i].len > 0) opts.filter = args[i];
        } else if (has_val and std.mem.eql(u8, a, "--details")) {
            // max failure/skip details printed per suite (default 20)
            i += 1;
            opts.max_fail_details = try std.fmt.parseInt(u32, args[i], 10);
        } else if (has_val and std.mem.eql(u8, a, "--iters")) {
            i += 1;
            opts.iters = try std.fmt.parseInt(u32, args[i], 10);
        } else if (has_val and std.mem.eql(u8, a, "--jobs")) {
            i += 1;
            const n = try std.fmt.parseInt(u32, args[i], 10);
            if (n > 0) opts.jobs = n;
        } else if (has_val and std.mem.eql(u8, a, "--bench-bytes")) {
            i += 1;
            const n = try std.fmt.parseInt(u64, args[i], 10);
            if (n > 0) opts.bench_bytes = n;
        } else {
            try stderr.print("unknown argument {s}\n", .{a});
            return 2;
        }
    }

    if (std.mem.eql(u8, suite_name, "list")) {
        for (all_suites) |s| try stdout.print("{s:<24} {s:<18} {s}\n", .{ s.name, s.lane, s.doc });
        return 0;
    }

    const env = init.environ_map;
    const corpus_path = env.get("ZUI_CORPUS") orelse {
        try stderr.print("ZUI_CORPUS is not set; source tools/env.sh or use ./zig\n", .{});
        return 2;
    };
    var corpus = Io.Dir.openDirAbsolute(io, corpus_path, .{}) catch |e| {
        try stderr.print("cannot open corpus {s}: {s}\n", .{ corpus_path, @errorName(e) });
        return 2;
    };
    defer corpus.close(io);

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();

    var ran: usize = 0;
    var all_ok = true;
    for (all_suites) |*s| {
        if (!wanted(suite_name, s)) continue;
        ran += 1;
        var shared: harness.Shared = .{};
        var ctx: harness.Ctx = .{
            .gpa = gpa,
            .arena = &arena,
            .io = io,
            .corpus = corpus,
            .corpus_path = corpus_path,
            .suite = s,
            .opts = opts,
            .stderr = stderr,
            .stdout = stdout,
            .shared = &shared,
        };
        if (bench) {
            const ok = runBench(&ctx, env) catch |e| blk: {
                try stdout.print("{{\"suite\":\"{s}\",\"bench_status\":\"{s}\"}}\n", .{ s.name, @errorName(e) });
                break :blk false;
            };
            if (!ok) all_ok = false;
            try stdout.flush();
            continue;
        }
        const t0 = Io.Timestamp.now(io, .awake);
        var status: []const u8 = "ok";
        s.run(&ctx) catch |e| {
            status = @errorName(e);
        };
        const ms = @divTrunc(t0.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds, std.time.ns_per_ms);
        const st = ctx.stats;
        const limited = opts.limit != null or opts.filter != null;
        const ok = std.mem.eql(u8, status, "ok") and st.items > 0 and st.failed == 0 and st.skipped == 0 and !limited;
        if (!ok) all_ok = false;
        const pct: f64 = if (st.items == 0) 0 else 100.0 * @as(f64, @floatFromInt(st.passed)) / @as(f64, @floatFromInt(st.items));
        try stdout.print(
            "{{\"suite\":\"{s}\",\"lane\":\"{s}\",\"status\":\"{s}\",\"items\":{d},\"passed\":{d},\"failed\":{d},\"skipped\":{d},\"pct\":{d:.4},\"limited\":{},\"jobs\":{d},\"ms\":{d},\"done\":{}}}\n",
            .{ s.name, s.lane, status, st.items, st.passed, st.failed, st.skipped, pct, limited, opts.jobs, ms, ok },
        );
        try stdout.flush();
    }
    if (ran == 0) {
        try stderr.print("no suite named {s}; try -Dsuite=list\n", .{suite_name});
        return 2;
    }
    return if (all_ok) 0 else 1;
}

/// Evenly spaced, deterministic subset of `<inputs.dir>/*<suffix>` within the byte cap (all of
/// them when they fit), after -Dfilter and -Dlimit (a file count). Paths relative to the corpus.
fn pickInputs(ctx: *harness.Ctx, arena: Allocator) ![]const []const u8 {
    const in = ctx.suite.inputs;
    const names = try ctx.listFiles(in.dir, in.suffix);
    defer ctx.freeNames(names);
    var sel: std.ArrayList([]const u8) = .empty;
    var sizes: std.ArrayList(u64) = .empty;
    var total: u64 = 0;
    for (names) |n| {
        if (!ctx.selected(n)) continue;
        const rel = try std.fmt.allocPrint(arena, "{s}/{s}", .{ in.dir, n });
        const st = try ctx.corpus.statFile(ctx.io, rel, .{});
        try sel.append(arena, rel);
        try sizes.append(arena, st.size);
        total += st.size;
    }
    var out: std.ArrayList([]const u8) = .empty;
    const max_files = ctx.opts.limit orelse std.math.maxInt(u64);
    if (total <= ctx.opts.bench_bytes and sel.items.len <= max_files) return sel.items;
    // Stride over the sorted list so the subset spans the whole corpus (every era, every size).
    const by_bytes = (total + ctx.opts.bench_bytes - 1) / ctx.opts.bench_bytes;
    const by_count = (sel.items.len +| (max_files - 1)) / max_files; // saturates: no --limit means maxInt
    const stride: usize = @intCast(@max(1, @max(by_bytes, by_count)));
    var used: u64 = 0;
    var k: usize = 0;
    while (k < sel.items.len and out.items.len < max_files) : (k += stride) {
        if (used + sizes.items[k] > ctx.opts.bench_bytes and out.items.len > 0) continue;
        used += sizes.items[k];
        try out.append(arena, sel.items[k]);
    }
    return out.items;
}

fn expandArg(arena: Allocator, env: *const std.process.Environ.Map, a: []const u8) ![]const u8 {
    const subs = [_]struct { key: []const u8, value: ?[]const u8 }{
        .{ .key = "{dumper}", .value = env.get("ZUI_DUMPER") },
        .{ .key = "{release}", .value = if (env.get("CARGO_TARGET_DIR")) |t| try std.fmt.allocPrint(arena, "{s}/release", .{t}) else null },
    };
    for (subs) |sub| if (std.mem.startsWith(u8, a, sub.key)) {
        const v = sub.value orelse return error.BaselineEnvMissing; // source tools/env.sh
        return std.fmt.allocPrint(arena, "{s}{s}", .{ v, a[sub.key.len..] });
    };
    return a;
}

fn jsonNumber(line: []const u8, key: []const u8) ?f64 {
    var buf: [64]u8 = undefined;
    const k = std.fmt.bufPrint(&buf, "\"{s}\":", .{key}) catch return null;
    const at = std.mem.indexOf(u8, line, k) orelse return null;
    var end = at + k.len;
    while (end < line.len and (std.ascii.isDigit(line[end]) or line[end] == '.' or line[end] == '-' or line[end] == 'e')) end += 1;
    return std.fmt.parseFloat(f64, line[at + k.len .. end]) catch null;
}

fn jsonString(line: []const u8, key: []const u8) ?[]const u8 {
    var buf: [64]u8 = undefined;
    const k = std.fmt.bufPrint(&buf, "\"{s}\":\"", .{key}) catch return null;
    const at = std.mem.indexOf(u8, line, k) orelse return null;
    const rest = line[at + k.len ..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    return rest[0..end];
}

fn runBench(ctx: *harness.Ctx, env: *const std.process.Environ.Map) !bool {
    const s = ctx.suite;
    if (s.bench == null and s.baselines.len == 0) {
        try ctx.stdout.print("{{\"suite\":\"{s}\",\"bench_status\":\"no-bench\"}}\n", .{s.name});
        return true;
    }
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const inputs = try pickInputs(ctx, arena);
    if (inputs.len == 0) return error.NoBenchInputs;
    var records: std.ArrayList(harness.BenchRecord) = .empty;
    defer {
        for (records.items) |rec| {
            ctx.gpa.free(rec.name);
            ctx.gpa.free(rec.unit);
        }
        records.deinit(ctx.gpa);
    }
    ctx.bench_inputs = inputs;
    ctx.bench_records = &records;
    ctx.opts.jobs = 1;

    var input_bytes: u64 = 0;
    for (inputs) |p| input_bytes += (try ctx.corpus.statFile(ctx.io, p, .{})).size;
    try ctx.stdout.print("{{\"suite\":\"{s}\",\"bench_inputs\":{d},\"bench_bytes\":{d},\"first\":\"{s}\",\"last\":\"{s}\"}}\n", .{ s.name, inputs.len, input_bytes, inputs[0], inputs[inputs.len - 1] });
    try ctx.stdout.flush();

    var ok = true;
    if (s.bench) |b| b(ctx) catch |e| {
        try ctx.stdout.print("{{\"suite\":\"{s}\",\"bench_status\":\"{s}\"}}\n", .{ s.name, @errorName(e) });
        ok = false;
    };
    if (s.baselines.len == 0) return ok;

    // The same inputs for Rust, as absolute paths.
    var list_text: std.Io.Writer.Allocating = .init(arena);
    for (inputs) |p| try list_text.writer.print("{s}/{s}\n", .{ ctx.corpus_path, p });
    // Kept at $ZUI_CORPUS/bench/<suite>.list so a Rust run can be repeated by hand on the same set.
    try ctx.corpus.createDirPath(ctx.io, "bench");
    const list_rel = try std.fmt.allocPrint(arena, "bench/{s}.list", .{s.name});
    try ctx.corpus.writeFile(ctx.io, .{ .sub_path = list_rel, .data = list_text.written() });
    const list_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ ctx.corpus_path, list_rel });

    const iters_text = try std.fmt.allocPrint(arena, "{d}", .{ctx.opts.iters});
    for (s.baselines) |bl| {
        var argv: std.ArrayList([]const u8) = .empty;
        for (bl.argv) |a| try argv.append(arena, try expandArg(arena, env, a));
        try argv.appendSlice(arena, &.{ "--iters", iters_text, "--list", list_path });
        const r = std.process.run(ctx.gpa, ctx.io, .{ .argv = argv.items }) catch |e| {
            try ctx.stdout.print("{{\"suite\":\"{s}\",\"baseline\":\"{s}\",\"status\":\"{s}\"}}\n", .{ s.name, bl.name, @errorName(e) });
            ok = false;
            continue;
        };
        defer ctx.gpa.free(r.stdout);
        defer ctx.gpa.free(r.stderr);
        if (!r.term.success()) {
            try ctx.stdout.print("{{\"suite\":\"{s}\",\"baseline\":\"{s}\",\"status\":\"exit\"}}\n", .{ s.name, bl.name });
            try ctx.stderr.print("{s}", .{r.stderr});
            ok = false;
            continue;
        }
        var it = harness.lines(r.stdout);
        var matched = false;
        while (it.next()) |line| {
            try ctx.stdout.print("{s}\n", .{line});
            const name = jsonString(line, "bench") orelse continue;
            if (!std.mem.eql(u8, name, bl.name)) continue;
            const rust = jsonNumber(line, "ns_per_unit") orelse continue;
            const unit = jsonString(line, "unit") orelse "";
            matched = true;
            for (records.items) |rec| {
                if (!std.mem.eql(u8, rec.name, bl.name)) continue;
                if (!std.mem.eql(u8, rec.unit, unit)) {
                    try ctx.stdout.print("{{\"compare\":\"{s}\",\"suite\":\"{s}\",\"status\":\"unit-mismatch\",\"zui_unit\":\"{s}\",\"rust_unit\":\"{s}\"}}\n", .{ bl.name, s.name, rec.unit, unit });
                    ok = false;
                    continue;
                }
                const speedup = if (rec.ns_per_unit > 0) rust / rec.ns_per_unit else 0;
                try ctx.stdout.print(
                    "{{\"compare\":\"{s}\",\"suite\":\"{s}\",\"unit\":\"{s}\",\"inputs\":{d},\"zui_ns_per_unit\":{d:.3},\"rust_ns_per_unit\":{d:.3},\"speedup\":{d:.3}}}\n",
                    .{ bl.name, s.name, unit, inputs.len, rec.ns_per_unit, rust, speedup },
                );
                try ctx.stderr.print("bench {s}/{s}: zui {d:.2} ns/{s}, rust {d:.2} ns/{s}, {d:.2}x\n", .{ s.name, bl.name, rec.ns_per_unit, unit, rust, unit, speedup });
            }
        }
        if (!matched) {
            try ctx.stdout.print("{{\"suite\":\"{s}\",\"baseline\":\"{s}\",\"status\":\"no-record\"}}\n", .{ s.name, bl.name });
            ok = false;
        }
    }
    return ok;
}

test "suite selection" {
    const s: harness.Suite = .{ .name = "bcs", .lane = "bcs-types", .doc = "", .run = undefined };
    try std.testing.expect(wanted("bcs", &s));
    try std.testing.expect(wanted("digests, bcs", &s));
    try std.testing.expect(wanted("bcs-types", &s));
    try std.testing.expect(wanted("all", &s));
    try std.testing.expect(!wanted("bcs-codec", &s));
}

test "json scraping" {
    const l = "{\"impl\":\"rust\",\"bench\":\"decode\",\"unit\":\"tx\",\"ns_per_unit\":1234.50}";
    try std.testing.expectEqualStrings("decode", jsonString(l, "bench").?);
    try std.testing.expectEqual(@as(f64, 1234.5), jsonNumber(l, "ns_per_unit").?);
}
