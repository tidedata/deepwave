//! aot: the ahead-of-time tier of the Move VM. Hot packages are compiled from
//! verified bytecode to Zig by `deepwave-aot` (aot_emit.zig), built into the binary (aot_gen.zig is the
//! registry of what was compiled), and attached to a loaded module's functions here when the
//! module's bytecode digest equals the compiled one. Anything else, including every upgrade of a
//! compiled package until it is compiled again, runs in the interpreter, which is also what a
//! compiled function falls back to at every call and return. OFF by default: `enable` turns it on
//! (deepwave `--vm-aot`, optionally with a hot list file `--vm-aot-hot <file>`).
//!
//! Gas and abort behaviour are the interpreter's own (aot_rt.zig): the compiled code calls the
//! interpreter's instruction implementation per instruction, so charges, order, errors and error
//! locations cannot differ. Charging whole basic blocks in one step is the next
//! optimization on top of this; it needs the meter's tier boundaries known per block.
const std = @import("std");
const loader = @import("loader.zig");
const rt = @import("aot_rt.zig");
const gen = @import("aot_gen.zig");

pub const digestModule = rt.digestModule;
pub const Entry = rt.Entry;

/// Counters of what the tier did since `enable` (relaxed atomics; for the node's metrics/log).
pub const Stats = struct {
    modules_matched: std.atomic.Value(u64) = .init(0),
    /// A compiled module of the same address and name whose bytecode differs (an upgrade not
    /// compiled yet): everything in it runs in the interpreter.
    modules_digest_miss: std.atomic.Value(u64) = .init(0),
    functions_attached: std.atomic.Value(u64) = .init(0),
    /// Compiled, but not attached because the hot list does not name it.
    functions_not_hot: std.atomic.Value(u64) = .init(0),
};
pub var stats: Stats = .{};

/// One line of a hot list.
pub const HotItem = struct {
    /// Module self address, which is the ORIGINAL package id (not the version id of an upgrade,
    /// which per-call data from tide is keyed by: map it back first); null matches any address.
    addr: ?[32]u8,
    module: []const u8,
    /// A function name, or "*" for every function of the module.
    func: []const u8,
    calls: u64 = 0,
    instrs: u64 = 0,
};

/// The hot-package list: a text file, one function per line, produced from tide's per-function
/// call and instruction counts (or by hand):
///
///   <package address hex, with or without 0x, or *>::<module>::<function or *> [calls [instructions]]
///
/// `#` starts a comment. Blank lines are ignored. The two counters only rank lines (`top`).
pub const HotList = struct {
    items: []HotItem,
    /// What `items` was cut from (`top` shortens `items`); freed by `deinit`.
    all: []HotItem,

    pub const ParseError = error{ BadLine, BadAddress, OutOfMemory };

    /// Parses `text`. Strings in the items point into `text`, which must outlive the list.
    pub fn parse(gpa: std.mem.Allocator, text: []const u8) ParseError!HotList {
        var items: std.ArrayList(HotItem) = .empty;
        errdefer items.deinit(gpa);
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            var line = raw;
            if (std.mem.indexOfScalar(u8, line, '#')) |i| line = line[0..i];
            line = std.mem.trim(u8, line, " \t\r");
            if (line.len == 0) continue;
            var fields = std.mem.tokenizeAny(u8, line, " \t");
            const key = fields.next() orelse continue;
            var parts = std.mem.splitSequence(u8, key, "::");
            const a = parts.next() orelse return error.BadLine;
            const m = parts.next() orelse return error.BadLine;
            const f = parts.next() orelse return error.BadLine;
            if (parts.next() != null or m.len == 0 or f.len == 0) return error.BadLine;
            var item: HotItem = .{ .addr = if (std.mem.eql(u8, a, "*")) null else try parseAddr(a), .module = m, .func = f };
            if (fields.next()) |c| item.calls = std.fmt.parseInt(u64, c, 10) catch return error.BadLine;
            if (fields.next()) |c| item.instrs = std.fmt.parseInt(u64, c, 10) catch return error.BadLine;
            if (fields.next() != null) return error.BadLine;
            try items.append(gpa, item);
        }
        const all = try items.toOwnedSlice(gpa);
        return .{ .items = all, .all = all };
    }

    pub fn deinit(h: *HotList, gpa: std.mem.Allocator) void {
        gpa.free(h.all);
    }

    pub fn contains(h: *const HotList, addr: *const [32]u8, module: []const u8, func: []const u8) bool {
        for (h.items) |it| {
            if (it.addr) |a| if (!std.mem.eql(u8, &a, addr)) continue;
            if (!std.mem.eql(u8, it.module, module)) continue;
            if (std.mem.eql(u8, it.func, "*") or std.mem.eql(u8, it.func, func)) return true;
        }
        return false;
    }

    /// Keeps the `n` lines with the most instructions executed (ties: most calls), in that order.
    pub fn top(h: *HotList, n: usize) void {
        std.mem.sort(HotItem, h.items, {}, struct {
            fn gt(_: void, a: HotItem, b: HotItem) bool {
                if (a.instrs != b.instrs) return a.instrs > b.instrs;
                return a.calls > b.calls;
            }
        }.gt);
        if (h.items.len > n) h.items = h.items[0..n];
    }
};

/// A package address as `0x1`, `0x000..01` or bare hex: at most 64 digits, left padded with zeros.
pub fn parseAddr(s: []const u8) error{BadAddress}![32]u8 {
    var t = s;
    if (std.mem.startsWith(u8, t, "0x") or std.mem.startsWith(u8, t, "0X")) t = t[2..];
    if (t.len == 0 or t.len > 64) return error.BadAddress;
    var out: [32]u8 = @splat(0);
    var i: usize = 0;
    // fill from the right, one nibble at a time
    var k: usize = t.len;
    while (k > 0) : (k -= 1) {
        const d = std.fmt.charToDigit(t[k - 1], 16) catch return error.BadAddress;
        const byte = 31 - i / 2;
        out[byte] |= if (i % 2 == 0) d else d << 4;
        i += 1;
    }
    return out;
}

// ---------------------------------------------------------------------------------------------
// The tier

var on: bool = false;
var hot: ?HotList = null;
var table: std.AutoHashMapUnmanaged([32]u8, *const Entry) = .empty;
/// (address, name) of every compiled module, to tell an upgrade (same module, other bytecode)
/// from a module that was never compiled.
var by_name: std.AutoHashMapUnmanaged([32]u8, void) = .empty;

pub fn enabled() bool {
    return on;
}

fn nameKey(addr: *const [32]u8, name: []const u8) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2b256.init(.{});
    h.update(addr);
    h.update(name);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Turns the tier on for packages loaded from now on: `hot_list` (borrowed, must outlive the
/// tier) limits which compiled functions are used, null uses every compiled function. Call once,
/// before the runtime loads packages (packages loaded earlier stay interpreted). Returns the
/// number of compiled modules in the registry.
pub fn enable(hot_list: ?HotList) std.mem.Allocator.Error!usize {
    disable();
    const gpa = std.heap.smp_allocator;
    for (&gen.entries) |*e| {
        try table.put(gpa, e.digest, e);
        try by_name.put(gpa, nameKey(&e.address, e.name), {});
    }
    if (gen.entries.len == 0) std.log.warn("vm-aot: the registry (src/move/vm/aot_gen.zig) is empty in this binary: nothing is compiled, everything runs in the interpreter; run deepwave-aot gen and rebuild", .{});
    hot = hot_list;
    stats = .{};
    loader.aot_hook = attach;
    on = true;
    return gen.entries.len;
}

/// Turns the tier off. Functions of packages loaded while it was on keep their compiled code.
pub fn disable() void {
    on = false;
    loader.aot_hook = null;
    const gpa = std.heap.smp_allocator;
    table.clearAndFree(gpa);
    by_name.clearAndFree(gpa);
    hot = null;
}

/// Sets `Function.aot` for every compiled function of every module of `p` whose bytecode digest
/// matches a compiled module. Runs once per package at load.
pub fn attach(p: *loader.Package) void {
    if (table.count() == 0) return;
    for (p.modules) |*m| {
        // Hash the module's bytecode only when a module of this address and name was compiled.
        if (!by_name.contains(nameKey(m.cm.selfAddress(), m.name))) continue;
        const digest = digestModule(&m.cm);
        const e = table.get(digest) orelse {
            _ = stats.modules_digest_miss.fetchAdd(1, .monotonic);
            continue;
        };
        _ = stats.modules_matched.fetchAdd(1, .monotonic);
        for (e.fns) |fe| {
            if (fe.def_idx >= m.functions.len) continue;
            const f = &m.functions[fe.def_idx];
            if (f.is_native or !std.mem.eql(u8, f.name, fe.name)) continue;
            if (hot) |*h| if (!h.contains(m.cm.selfAddress(), m.name, f.name)) {
                _ = stats.functions_not_hot.fetchAdd(1, .monotonic);
                continue;
            };
            f.aot = @ptrCast(fe.run);
            _ = stats.functions_attached.fetchAdd(1, .monotonic);
        }
    }
}

test "hot list parse, match, rank" {
    const text =
        \\# comment
        \\0x2::coin::*   100 5000
        \\*::pool::swap  7 90000  # trailing
        \\00000000000000000000000000000000000000000000000000000000000000ab::m::f
        \\
    ;
    var h = try HotList.parse(std.testing.allocator, text);
    defer h.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), h.items.len);
    const two = try parseAddr("0x2");
    try std.testing.expect(h.contains(&two, "coin", "mint"));
    try std.testing.expect(!h.contains(&two, "coin2", "mint"));
    try std.testing.expect(h.contains(&two, "pool", "swap"));
    try std.testing.expect(!h.contains(&two, "pool", "other"));
    const ab = try parseAddr("ab");
    try std.testing.expect(h.contains(&ab, "m", "f"));
    h.top(1);
    try std.testing.expectEqualStrings("swap", h.items[0].func);
    try std.testing.expectError(error.BadLine, HotList.parse(std.testing.allocator, "onlyone\n"));
    try std.testing.expectError(error.BadAddress, HotList.parse(std.testing.allocator, "zz::m::f\n"));
}
