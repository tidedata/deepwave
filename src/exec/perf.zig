//! exec-replay measurement hooks (test/vm). Everything is off unless one of these environment
//! variables is set when the suite starts; nothing here changes what a transaction computes.
//!
//!   ZUI_REPLAY_TIMES=<file>  one line per Move transaction, written at the end of the run:
//!                            `<checkpoint>/tx[i] <execute ns> <done|unsupported|error> [<pkg>:<instrs>:<gas>,...]`
//!                            (the time of `ptb.execute` only: no effects comparison, no input decoding)
//!   ZUI_REPLAY_PROF=1        with TIMES: the gas profiler on every worker thread (the traced loop:
//!                            slower, times are not comparable). Each line gets the exclusive
//!                            instructions and gas per package (original id) the transaction ran, and
//!                            `<file>.fns` gets every function's totals:
//!                            `<pkg>::<module>::<fn> <calls> <instructions> <exclusive gas>`
//!   ZUI_REPLAY_AOT=1         the AOT tier on (`move_vm.aot.enable(null)`: whatever the registry holds)
//!   ZUI_REPLAY_DUMP=<file>   every package of the corpus (non-system objects and every system package
//!                            write) as a ZUIMVPK1 packages.bin, the input of `deepwave-aot gen --packages`
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const move_vm = @import("move_vm");
const natives = @import("natives");
const packages = @import("packages.zig");

const has_prof = @hasDecl(move_vm, "profile");
const has_aot = @hasDecl(move_vm, "aot");
const gpa = std.heap.smp_allocator;

pub const Perf = struct {
    lock: std.Io.Mutex = .init,
    out: std.ArrayList(u8) = .empty,
    path: []const u8,
    prof: bool = false,
    threads: std.ArrayList(*ThreadProf) = .empty,
};

/// Set by `setup` when ZUI_REPLAY_TIMES is given.
pub var perf: ?*Perf = null;

const ThreadProf = if (has_prof) struct {
    p: move_vm.profile.Profiler,
    last_gas: std.ArrayList(u64) = .empty,
    last_ins: std.ArrayList(u64) = .empty,
    ids: std.ArrayList(u32) = .empty,
} else struct {};

threadlocal var tprof: ?*ThreadProf = null;

fn env(name: [*:0]const u8) ?[]const u8 {
    const v = std.c.getenv(name) orelse return null;
    const s = std.mem.span(v);
    return if (s.len == 0) null else s;
}

/// Reads the environment once at suite start. Returns a message for the log (null: all off).
pub fn setup(io: std.Io, store: *const packages.Store) !?[]const u8 {
    var msg: std.ArrayList(u8) = .empty;
    if (env("ZUI_REPLAY_DUMP")) |path| {
        const n = try dump(io, store, path);
        try msg.print(gpa, "dump: {d} package objects to {s}; ", .{ n, path });
    }
    if (env("ZUI_REPLAY_AOT") != null) {
        if (comptime !has_aot) return error.AotNotInThisTree;
        const n = try move_vm.aot.enable(null);
        try msg.print(gpa, "aot: on, {d} compiled modules; ", .{n});
    }
    if (env("ZUI_REPLAY_TIMES")) |path| {
        const p = try gpa.create(Perf);
        p.* = .{ .path = path, .prof = env("ZUI_REPLAY_PROF") != null };
        if (p.prof and comptime !has_prof) return error.ProfilerNotInThisTree;
        perf = p;
        try msg.print(gpa, "times: {s}{s}; ", .{ path, if (p.prof) " (gas profiler on)" else "" });
    }
    return if (msg.items.len == 0) null else msg.items;
}

/// Before `ptb.execute` on this thread.
pub fn begin(p: *Perf, io: std.Io) void {
    if (comptime !has_prof) return;
    if (!p.prof) return;
    if (tprof == null) {
        const t = gpa.create(ThreadProf) catch return;
        t.* = .{ .p = move_vm.profile.Profiler.init(gpa) };
        p.lock.lockUncancelable(io);
        defer p.lock.unlock(io);
        p.threads.append(gpa, t) catch {};
        tprof = t;
    }
    move_vm.profile.activate(&tprof.?.p);
}

/// After `ptb.execute`: one line for the transaction.
pub fn end(p: *Perf, io: std.Io, id: []const u8, t0: std.Io.Timestamp, status: []const u8) void {
    const ns: u64 = @intCast(t0.durationTo(std.Io.Timestamp.now(io, .awake)).nanoseconds);
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(gpa);
    line.print(gpa, "{s} {d} {s}", .{ id, ns, status }) catch return;
    if (comptime has_prof) {
        if (p.prof) if (tprof) |t| {
            move_vm.profile.activate(null);
            perTx(t, &line) catch {};
            t.p.endTransaction();
        };
    }
    line.append(gpa, '\n') catch return;
    p.lock.lockUncancelable(io);
    defer p.lock.unlock(io);
    p.out.appendSlice(gpa, line.items) catch {};
}

fn perTx(t: *ThreadProf, line: *std.ArrayList(u8)) !void {
    const fns = t.p.fns.items;
    while (t.last_gas.items.len < fns.len) {
        try t.last_gas.append(gpa, 0);
        try t.last_ins.append(gpa, 0);
    }
    t.ids.clearRetainingCapacity();
    var it = t.p.by_ptr.valueIterator();
    while (it.next()) |v| try t.ids.append(gpa, v.*);
    std.mem.sort(u32, t.ids.items, {}, std.sort.asc(u32));
    const Agg = struct { addr: [32]u8, ins: u64 = 0, gas: u64 = 0 };
    var aggs: [64]Agg = undefined;
    var na: usize = 0;
    var prev: ?u32 = null;
    for (t.ids.items) |id| {
        if (prev == id) continue;
        prev = id;
        const c = fns[id].cell;
        const dg = c.exclusive -| t.last_gas.items[id];
        const di = c.instructions -| t.last_ins.items[id];
        t.last_gas.items[id] = c.exclusive;
        t.last_ins.items[id] = c.instructions;
        var k: usize = 0;
        while (k < na and !std.mem.eql(u8, &aggs[k].addr, &fns[id].addr)) k += 1;
        if (k == na) {
            if (na == aggs.len) continue;
            aggs[na] = .{ .addr = fns[id].addr };
            na += 1;
        }
        aggs[k].ins += di;
        aggs[k].gas += dg;
    }
    for (aggs[0..na], 0..) |a, i| try line.print(gpa, "{s}{x}:{d}:{d}", .{ if (i == 0) " " else ",", &a.addr, a.ins, a.gas });
}

/// At the end of the run: the lines (and with the profiler, `<path>.fns`).
pub fn finish(io: std.Io) !void {
    if (comptime has_aot) if (move_vm.aot.enabled()) {
        const st = &move_vm.aot.stats;
        std.debug.print("exec-replay perf: aot modules matched {d}, digest misses {d}, functions attached {d}, not hot {d}\n", .{
            st.modules_matched.load(.monotonic), st.modules_digest_miss.load(.monotonic), st.functions_attached.load(.monotonic), st.functions_not_hot.load(.monotonic),
        });
    };
    const p = perf orelse return;
    const cwd = std.Io.Dir.cwd();
    try cwd.writeFile(io, .{ .sub_path = p.path, .data = p.out.items });
    if (comptime !has_prof) return;
    if (!p.prof) return;
    // every thread's functions, merged by name
    const Tot = struct { calls: u64 = 0, ins: u64 = 0, gas: u64 = 0 };
    var tot: std.StringArrayHashMapUnmanaged(Tot) = .empty;
    for (p.threads.items) |t| for (t.p.fns.items) |f| {
        const key = try std.fmt.allocPrint(gpa, "{x}::{s}::{s}", .{ &f.addr, f.module, f.name });
        const e = try tot.getOrPut(gpa, key);
        if (!e.found_existing) e.value_ptr.* = .{};
        e.value_ptr.calls += f.cell.calls;
        e.value_ptr.ins += f.cell.instructions;
        e.value_ptr.gas += f.cell.exclusive;
    };
    var out: std.ArrayList(u8) = .empty;
    for (tot.keys(), tot.values()) |k, v| try out.print(gpa, "{s} {d} {d} {d}\n", .{ k, v.calls, v.ins, v.gas });
    const fpath = try std.fmt.allocPrint(gpa, "{s}.fns", .{p.path});
    try cwd.writeFile(io, .{ .sub_path = fpath, .data = out.items });
}

/// ZUIMVPK1 (tools/aot readPackages): per package version id, original id, version, no linkage,
/// no type origins, then the modules.
fn dump(io: std.Io, store: *const packages.Store, path: []const u8) !usize {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "ZUIMVPK1");
    try out.appendNTimes(arena, 0, 4);
    var n: u32 = 0;
    var uit = store.user.valueIterator();
    while (uit.next()) |raw| {
        if (try dumpOne(arena, &out, raw.*)) n += 1;
    }
    var sit = store.system.valueIterator();
    while (sit.next()) |list| for (list.items) |w| {
        if (try dumpOne(arena, &out, w.raw)) n += 1;
    };
    std.mem.writeInt(u32, out.items[8..12], n, .little);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = out.items });
    return n;
}

fn put32(a: std.mem.Allocator, out: *std.ArrayList(u8), v: usize) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, @intCast(v), .little);
    try out.appendSlice(a, &b);
}

fn dumpOne(a: std.mem.Allocator, out: *std.ArrayList(u8), raw: []const u8) !bool {
    const obj = bcs.decode(types.Object, a, raw) catch return false;
    const mp = switch (obj.data) {
        .Package => |m| m,
        else => return false,
    };
    if (mp.module_map.entries.len == 0) return false;
    const info = natives.objrt.packageInfo(a, &mp) catch return false;
    try out.appendSlice(a, &mp.id.@"0".@"0");
    try out.appendSlice(a, &info.original_id);
    var vb: [8]u8 = undefined;
    std.mem.writeInt(u64, &vb, mp.version.@"0", .little);
    try out.appendSlice(a, &vb);
    try put32(a, out, 0);
    try put32(a, out, 0);
    try put32(a, out, mp.module_map.entries.len);
    for (mp.module_map.entries) |e| {
        try put32(a, out, e.key.@"0".len);
        try out.appendSlice(a, e.key.@"0");
        try put32(a, out, e.value.len);
        try out.appendSlice(a, e.value);
    }
    return true;
}
