//! Batch dispatch table: for each batch operation, which path runs a batch of n items (one CPU
//! thread, the shared CPU pool, or the GPU on k devices). The GPU module fills it from a short
//! calibration at first start and caches it here, keyed by a hardware fingerprint, so later
//! starts load it; `--hw dispatch=...` / ZUI_HW force a path (core/hw.zig).
//!
//! Cache file: one line per op, `op min_n path min_n path ...`, after a `fp <fingerprint>` line.
const std = @import("std");

pub const Op = enum(u8) {
    ed25519,
    poseidon,
    msm,
    mul_each,
};
pub const op_count = @typeInfo(Op).@"enum".field_names.len;

/// cpu1, pool, the GPU on `n` devices (`gpu(n)`), or the GPU on `n` devices and the CPU pool on
/// the same batch at once (`mix(n)`: the pool takes items from the front, the GPUs from the back).
pub const Path = enum(u8) {
    cpu1 = 0,
    pool = 1,
    _,

    const mix_base = 66;

    pub fn gpu(devices: usize) Path {
        return @enumFromInt(1 + @as(u8, @intCast(@max(1, @min(devices, 64)))));
    }
    pub fn mix(devices: usize) Path {
        return @enumFromInt(mix_base - 1 + @as(u8, @intCast(@max(1, @min(devices, 64)))));
    }
    /// Devices the path uses (0 for the CPU paths).
    pub fn gpuDevices(p: Path) usize {
        const v = @intFromEnum(p);
        return if (v >= mix_base) v - mix_base + 1 else if (v >= 2) v - 1 else 0;
    }
    /// Uses a GPU (gpu or mix).
    pub fn isGpu(p: Path) bool {
        return @intFromEnum(p) >= 2;
    }
    pub fn isMix(p: Path) bool {
        return @intFromEnum(p) >= mix_base;
    }
    /// The same path on `n` devices.
    pub fn withDevices(p: Path, n: usize) Path {
        return if (p.isMix()) mix(n) else if (p.isGpu()) gpu(n) else p;
    }
    pub fn format(p: Path, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (p) {
            .cpu1 => try w.writeAll("cpu1"),
            .pool => try w.writeAll("pool"),
            _ => if (p.isMix()) try w.print("mix{d}", .{p.gpuDevices()}) else try w.print("gpu{d}", .{p.gpuDevices()}),
        }
    }
    pub fn parse(s: []const u8) ?Path {
        if (std.mem.eql(u8, s, "cpu1")) return .cpu1;
        if (std.mem.eql(u8, s, "pool")) return .pool;
        inline for (.{ .{ "gpu", gpu }, .{ "mix", mix } }) |e| {
            if (std.mem.startsWith(u8, s, e[0])) {
                const n = std.fmt.parseInt(u8, s[3..], 10) catch return null;
                if (n == 0 or n > 64) return null;
                return e[1](n);
            }
        }
        return null;
    }
};

pub const Step = struct { min_n: u32, path: Path };

/// Ascending `min_n`; the first step has min_n 0.
pub const OpTable = struct {
    steps: [16]Step = undefined,
    len: u8 = 0,

    pub fn of(steps: []const Step) OpTable {
        var t: OpTable = .{};
        for (steps) |s| t.push(s.min_n, s.path);
        return t;
    }

    /// Appends a step (merged into the previous one when the path is the same).
    pub fn push(t: *OpTable, min_n: u32, path: Path) void {
        if (t.len > 0 and t.steps[t.len - 1].path == path) return;
        if (t.len == t.steps.len) return;
        t.steps[t.len] = .{ .min_n = if (t.len == 0) 0 else min_n, .path = path };
        t.len += 1;
    }

    pub fn pick(t: *const OpTable, n: usize) Path {
        var p: Path = .cpu1;
        for (t.steps[0..t.len]) |s| {
            if (n >= s.min_n) p = s.path else break;
        }
        return p;
    }
};

pub const Table = struct {
    ops: [op_count]OpTable,
    /// True when it came from calibration (or the cache), false for the static default.
    calibrated: bool = false,

    /// Without calibration (calibrate=off): the pool from 16 items, the GPU only where it won on
    /// both measured machines (an RTX A5000 machine and an M5 Pro): poseidon and msm/mul_each from 4096. Ed25519
    /// stays on the pool (on Apple GPUs it only pays mixed with the pool, which calibration finds).
    pub fn static(gpu_devices: usize) Table {
        const g: Path = if (gpu_devices > 0) Path.gpu(gpu_devices) else .pool;
        return .{ .ops = .{
            OpTable.of(&.{ .{ .min_n = 0, .path = .cpu1 }, .{ .min_n = 16, .path = .pool } }),
            OpTable.of(&.{ .{ .min_n = 0, .path = .cpu1 }, .{ .min_n = 16, .path = .pool }, .{ .min_n = 4096, .path = g } }),
            OpTable.of(&.{ .{ .min_n = 0, .path = .cpu1 }, .{ .min_n = 16, .path = .pool }, .{ .min_n = 4096, .path = g } }),
            OpTable.of(&.{ .{ .min_n = 0, .path = .cpu1 }, .{ .min_n = 16, .path = .pool }, .{ .min_n = 4096, .path = g } }),
        } };
    }

    /// Every op on one path.
    pub fn all(p: Path) Table {
        var t: Table = .{ .ops = undefined };
        for (&t.ops) |*o| o.* = OpTable.of(&.{.{ .min_n = 0, .path = p }});
        return t;
    }

    pub fn pick(t: *const Table, op: Op, n: usize) Path {
        return t.ops[@intFromEnum(op)].pick(n);
    }

    pub fn write(t: *const Table, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (t.ops, 0..) |o, i| {
            try w.print("{s}", .{@tagName(@as(Op, @enumFromInt(i)))});
            for (o.steps[0..o.len]) |s| try w.print(" {d} {f}", .{ s.min_n, s.path });
            try w.writeByte('\n');
        }
    }

    /// Parses what `write` wrote; null on any malformed line or a missing op.
    pub fn parse(text: []const u8) ?Table {
        var t: Table = .{ .ops = @splat(.{}), .calibrated = true };
        var seen: [op_count]bool = @splat(false);
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |line| {
            var it = std.mem.tokenizeScalar(u8, line, ' ');
            const name = it.next() orelse continue;
            const op = std.meta.stringToEnum(Op, name) orelse continue;
            var o: OpTable = .{};
            while (it.next()) |ns| {
                const ps = it.next() orelse return null;
                const n = std.fmt.parseInt(u32, ns, 10) catch return null;
                const p = Path.parse(ps) orelse return null;
                o.push(n, p);
            }
            if (o.len == 0) return null;
            t.ops[@intFromEnum(op)] = o;
            seen[@intFromEnum(op)] = true;
        }
        for (seen) |s| if (!s) return null;
        return t;
    }
};

/// Cache file name under the data dir or the hw cache dir.
pub const cache_name = "gpu-dispatch-v1.txt";

/// `<dir>/gpu-dispatch-v1.txt` holds `fp <fingerprint>\n` then the table. Returns the table when
/// the fingerprint matches.
pub fn loadCache(io: std.Io, gpa: std.mem.Allocator, dir: []const u8, fingerprint: []const u8) ?Table {
    const path = std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, cache_name }) catch return null;
    defer gpa.free(path);
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 16)) catch return null;
    defer gpa.free(text);
    const nl = std.mem.indexOfScalar(u8, text, '\n') orelse return null;
    const first = text[0..nl];
    if (!std.mem.startsWith(u8, first, "fp ")) return null;
    if (!std.mem.eql(u8, first[3..], fingerprint)) return null;
    return Table.parse(text[nl + 1 ..]);
}

pub fn saveCache(io: std.Io, gpa: std.mem.Allocator, dir: []const u8, fingerprint: []const u8, t: *const Table) !void {
    std.Io.Dir.cwd().createDirPath(io, dir) catch {};
    var buf: std.Io.Writer.Allocating = .init(gpa);
    defer buf.deinit();
    try buf.writer.print("fp {s}\n", .{fingerprint});
    try t.write(&buf.writer);
    const path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, cache_name });
    defer gpa.free(path);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = buf.written() });
}

/// The default cache directory: $ZUI_HW_CACHE, else $XDG_CACHE_HOME/zui/hw, else $HOME/.cache/zui/hw.
pub fn defaultCacheDir(buf: []u8) ?[]const u8 {
    if (std.c.getenv("ZUI_HW_CACHE")) |v| return std.fmt.bufPrint(buf, "{s}", .{std.mem.span(v)}) catch null;
    if (std.c.getenv("XDG_CACHE_HOME")) |v| return std.fmt.bufPrint(buf, "{s}/zui/hw", .{std.mem.span(v)}) catch null;
    const home = std.c.getenv("HOME") orelse return null;
    return std.fmt.bufPrint(buf, "{s}/.cache/zui/hw", .{std.mem.span(home)}) catch null;
}

test "table pick, write and parse round trip" {
    var t = Table.static(2);
    try std.testing.expectEqual(Path.cpu1, t.pick(.ed25519, 1));
    try std.testing.expectEqual(Path.pool, t.pick(.ed25519, 100));
    try std.testing.expectEqual(Path.pool, t.pick(.ed25519, 100_000));
    try std.testing.expectEqual(Path.gpu(2), t.pick(.poseidon, 100_000));
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try t.write(&w);
    const back = Table.parse(w.buffered()).?;
    for (t.ops, back.ops) |a, b| {
        try std.testing.expectEqual(a.len, b.len);
        for (a.steps[0..a.len], b.steps[0..b.len]) |x, y| try std.testing.expectEqual(x, y);
    }
    try std.testing.expect(Table.parse("ed25519 0 cpu1\n") == null); // missing ops
    try std.testing.expect(Path.parse("gpu0") == null);
    try std.testing.expectEqual(@as(usize, 3), Path.parse("gpu3").?.gpuDevices());
    try std.testing.expectEqual(@as(usize, 2), Path.parse("mix2").?.gpuDevices());
    try std.testing.expect(Path.parse("mix2").?.isMix() and !Path.parse("gpu2").?.isMix());
}
