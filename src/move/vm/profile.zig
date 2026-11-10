//! Per-instruction gas attribution (gas profiler). Off unless a `Profiler` is
//! installed with `activate` on the running thread: then every `Session.init` on that thread
//! runs the traced interpreter loop with a gas-only `Tracer` (no JSON rendering), which calls
//! the hooks below. Nothing here changes what a transaction computes or charges: the hooks only
//! read the meter. Units are the meter's internal units (1000 per gas unit).
//!
//! Attribution: the gas used between the start of instruction i and the start of instruction i+1
//! (the instruction's own charge, and for a Call the call and native charges that follow it) is
//! attributed to instruction i. `exclusive` of a function is the sum over its instructions;
//! `inclusive` is the gas used between its frame's entry and exit.
const std = @import("std");
const loader = @import("loader.zig");
const gas = @import("gas.zig");
const move_format = @import("move_format");

const Allocator = std.mem.Allocator;
const Function = loader.Function;

pub const Cell = struct { gas: u64 = 0, count: u64 = 0, op: u8 = 0 };
pub const FnCell = struct { exclusive: u64 = 0, inclusive: u64 = 0, calls: u64 = 0, native: bool = false, instructions: u64 = 0 };

pub const FnInfo = struct {
    addr: [32]u8,
    module: []const u8,
    name: []const u8,
    cell: FnCell = .{},
};

pub const InstrKey = struct { fn_id: u32, pc: u16 };

const Frame = struct { fn_id: u32, entry_gas: u64 };

pub const Profiler = struct {
    gpa: Allocator,
    fns: std.ArrayList(FnInfo) = .empty,
    by_name: std.StringHashMapUnmanaged(u32) = .empty,
    cells: std.AutoHashMapUnmanaged(InstrKey, Cell) = .empty,
    by_op: [256]Cell = @splat(.{}),
    /// Function pointer -> id, valid within one transaction (the runtime may move or reuse them after).
    by_ptr: std.AutoHashMapUnmanaged(*const Function, u32) = .empty,
    stack: std.ArrayList(Frame) = .empty,
    // current instruction
    cur: ?InstrKey = null,
    cur_op: u8 = 0,
    gap: ?struct { key: InstrKey, op: u8, gas: u64 } = null,
    /// Totals
    total_gas: u64 = 0,
    instructions: u64 = 0,
    transactions: u64 = 0,
    failed: bool = false,
    cur_gas: u64 = 0,

    pub fn init(gpa: Allocator) Profiler {
        return .{ .gpa = gpa };
    }

    pub fn deinit(p: *Profiler) void {
        for (p.fns.items) |f| {
            p.gpa.free(f.module);
            p.gpa.free(f.name);
        }
        p.fns.deinit(p.gpa);
        var it = p.by_name.keyIterator();
        while (it.next()) |k| p.gpa.free(k.*);
        p.by_name.deinit(p.gpa);
        p.cells.deinit(p.gpa);
        p.by_ptr.deinit(p.gpa);
        p.stack.deinit(p.gpa);
    }

    /// Call between transactions: function pointers are only stable within one run.
    pub fn endTransaction(p: *Profiler) void {
        p.by_ptr.clearRetainingCapacity();
        p.stack.clearRetainingCapacity();
        p.cur = null;
        p.gap = null;
        p.transactions += 1;
    }

    fn fnId(p: *Profiler, f: *const Function) Allocator.Error!u32 {
        if (p.by_ptr.get(f)) |id| return id;
        const addr = f.module.pkg.original_id;
        var kb: [512]u8 = undefined;
        const key = std.fmt.bufPrint(&kb, "{x}::{s}::{s}#{d}", .{ &addr, f.module.name, f.name, f.def_idx }) catch f.name;
        const id: u32 = if (p.by_name.get(key)) |x| x else blk: {
            const nid: u32 = @intCast(p.fns.items.len);
            const kdup = try p.gpa.dupe(u8, key);
            errdefer p.gpa.free(kdup);
            try p.by_name.put(p.gpa, kdup, nid);
            try p.fns.append(p.gpa, .{ .addr = addr, .module = try p.gpa.dupe(u8, f.module.name), .name = try p.gpa.dupe(u8, f.name), .cell = .{ .native = f.is_native } });
            break :blk nid;
        };
        try p.by_ptr.put(p.gpa, f, id);
        return id;
    }

    fn charge(p: *Profiler, key: InstrKey, op: u8, g: u64, count: u64) Allocator.Error!void {
        const e = try p.cells.getOrPut(p.gpa, key);
        if (!e.found_existing) e.value_ptr.* = .{ .op = op };
        e.value_ptr.gas += g;
        e.value_ptr.count += count;
        p.by_op[op].gas += g;
        p.by_op[op].count += count;
        p.fns.items[key.fn_id].cell.exclusive += g;
        p.fns.items[key.fn_id].cell.instructions += count;
        p.total_gas += g;
    }

    fn flushGap(p: *Profiler, now: u64) Allocator.Error!void {
        if (p.gap) |g| {
            try p.charge(g.key, g.op, g.gas -| now, 0);
            p.gap = null;
        }
    }

    pub fn start(p: *Profiler, m: *const gas.Meter, f: *const Function, op: u8, pc: u16) Allocator.Error!void {
        const now = m.remainingGas();
        try p.flushGap(now);
        const key: InstrKey = .{ .fn_id = try p.fnId(f), .pc = pc };
        p.cur = key;
        p.cur_op = op;
        p.instructions += 1;
        p.cur_gas = now;
    }

    pub fn end(p: *Profiler, m: *const gas.Meter) Allocator.Error!void {
        const key = p.cur orelse return;
        const now = m.remainingGas();
        try p.charge(key, p.cur_op, p.cur_gas -| now, 1);
        p.gap = .{ .key = key, .op = p.cur_op, .gas = now };
        p.cur = null;
    }

    pub fn enter(p: *Profiler, m: *const gas.Meter, f: *const Function) Allocator.Error!void {
        const id = try p.fnId(f);
        p.fns.items[id].cell.calls += 1;
        try p.stack.append(p.gpa, .{ .fn_id = id, .entry_gas = m.remainingGas() });
    }

    pub fn exit(p: *Profiler, m: *const gas.Meter) Allocator.Error!void {
        // A native's call charge lands in the gap after the Call instruction: flush first.
        try p.flushGap(m.remainingGas());
        const fr = p.stack.pop() orelse return;
        const used = fr.entry_gas -| m.remainingGas();
        // recursion: only the outermost activation of a function counts its inclusive gas
        for (p.stack.items) |o| if (o.fn_id == fr.fn_id) return;
        p.fns.items[fr.fn_id].cell.inclusive += used;
    }
};

/// The profiler new sessions on this thread report to (null: none).
pub threadlocal var active: ?*Profiler = null;

pub fn activate(p: ?*Profiler) void {
    active = p;
}
