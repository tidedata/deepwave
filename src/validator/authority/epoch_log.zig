//! The authority's durable group log (`<db>/validator/epoch-<n>/authority.log`), one record per
//! consensus commit, the same discipline as src/store: a record is checksummed with its file
//! offset mixed in, one write group is one record (so a commit is all or nothing), a torn or
//! corrupt tail is cut on open, and `appendGroup` is durable (fdatasync) before it returns. The
//! owned-object locks, next shared versions, processed keys, deferred transactions and congestion
//! debts of a commit live in one group, so a crash never splits them (docs/VALIDATOR-DESIGN 6.2).
//!
//! Two backends: `FileLog` (production) and `MemLog` (tests, the deterministic simulator).
const std = @import("std");
const Io = std.Io;

pub const Error = error{ Io, OutOfMemory, BadMagic, TooLarge };

pub const magic = "ZUIAUTH1";
/// Largest group accepted on read and write (a commit's records are bounded by block limits).
pub const max_group: usize = 256 << 20;
const header_len = 8;

fn checksum(offset: u64, len: u32, payload: []const u8) u32 {
    var c = std.hash.Crc32.init();
    var b: [12]u8 = undefined;
    std.mem.writeInt(u64, b[0..8], offset, .little);
    std.mem.writeInt(u32, b[8..12], len, .little);
    c.update(&b);
    c.update(payload);
    return c.final();
}

/// Frames `payload` as the record that goes at file offset `offset`.
pub fn frame(gpa: std.mem.Allocator, offset: u64, payload: []const u8) Error![]u8 {
    if (payload.len > max_group) return error.TooLarge;
    const buf = try gpa.alloc(u8, 8 + payload.len);
    const len: u32 = @intCast(payload.len);
    std.mem.writeInt(u32, buf[0..4], len, .little);
    std.mem.writeInt(u32, buf[4..8], checksum(offset, len, payload), .little);
    @memcpy(buf[8..], payload);
    return buf;
}

/// Walks the records of `data` (a whole log file including the magic). Calls `visit` with each
/// payload; returns the offset of the first byte that is not a whole valid record.
pub fn scan(data: []const u8, ctx: anytype, comptime visit: fn (@TypeOf(ctx), []const u8) anyerror!void) !u64 {
    if (data.len < header_len or !std.mem.eql(u8, data[0..header_len], magic)) return error.BadMagic;
    var at: usize = header_len;
    while (at + 8 <= data.len) {
        const len = std.mem.readInt(u32, data[at..][0..4], .little);
        if (len > max_group or at + 8 + len > data.len) break;
        const want = std.mem.readInt(u32, data[at + 4 ..][0..4], .little);
        const payload = data[at + 8 ..][0..len];
        if (checksum(at, len, payload) != want) break;
        try visit(ctx, payload);
        at += 8 + len;
    }
    return at;
}

pub const MemLog = struct {
    gpa: std.mem.Allocator,
    data: std.ArrayList(u8) = .empty,
    /// Test hook: fail the next append.
    fail_next: bool = false,

    pub fn init(gpa: std.mem.Allocator) MemLog {
        return .{ .gpa = gpa };
    }
    pub fn deinit(l: *MemLog) void {
        l.data.deinit(l.gpa);
    }
    pub fn appendGroup(l: *MemLog, payload: []const u8) Error!void {
        if (l.fail_next) {
            l.fail_next = false;
            return error.Io;
        }
        if (l.data.items.len == 0) try l.data.appendSlice(l.gpa, magic);
        const rec = try frame(l.gpa, l.data.items.len, payload);
        defer l.gpa.free(rec);
        try l.data.appendSlice(l.gpa, rec);
    }
    /// Replays every group; cuts a torn tail.
    pub fn replay(l: *MemLog, ctx: anytype, comptime visit: fn (@TypeOf(ctx), []const u8) anyerror!void) !void {
        if (l.data.items.len == 0) return;
        const end = try scan(l.data.items, ctx, visit);
        l.data.shrinkRetainingCapacity(end);
    }
};

pub const FileLog = struct {
    io: Io,
    file: Io.File,
    end: u64,
    gpa: std.mem.Allocator,

    /// Opens (or creates) `path`, replays every group through `visit`, cuts a torn tail.
    pub fn open(gpa: std.mem.Allocator, io: Io, path: []const u8, ctx: anytype, comptime visit: fn (@TypeOf(ctx), []const u8) anyerror!void) !FileLog {
        const cwd = Io.Dir.cwd();
        if (std.fs.path.dirname(path)) |d| try cwd.createDirPath(io, d);
        const data = cwd.readFileAlloc(io, path, gpa, .unlimited) catch |e| switch (e) {
            error.FileNotFound => try gpa.dupe(u8, ""),
            else => return e,
        };
        defer gpa.free(data);
        const f = try cwd.createFile(io, path, .{ .read = true, .truncate = false });
        errdefer f.close(io);
        var l: FileLog = .{ .io = io, .file = f, .end = 0, .gpa = gpa };
        if (data.len == 0) {
            try f.writePositionalAll(io, magic, 0);
            try f.sync(io);
            l.end = magic.len;
            return l;
        }
        const end = try scan(data, ctx, visit);
        if (end != data.len) {
            std.log.warn("authority log: {s}: torn or corrupt tail at byte {d} of {d}; cut", .{ path, end, data.len });
            try f.setLength(io, end);
            try f.sync(io);
        }
        l.end = end;
        return l;
    }

    pub fn close(l: *FileLog) void {
        l.file.close(l.io);
    }

    pub fn appendGroup(l: *FileLog, payload: []const u8) Error!void {
        const rec = try frame(l.gpa, l.end, payload);
        defer l.gpa.free(rec);
        l.file.writePositionalAll(l.io, rec, l.end) catch return error.Io;
        l.file.sync(l.io) catch return error.Io;
        l.end += rec.len;
    }
};

const Collect = struct {
    list: *std.ArrayList([]u8),
    gpa: std.mem.Allocator,
    fn visit(c: Collect, p: []const u8) anyerror!void {
        try c.list.append(c.gpa, try c.gpa.dupe(u8, p));
    }
};

test "mem log round trip and torn tail" {
    const gpa = std.testing.allocator;
    var l = MemLog.init(gpa);
    defer l.deinit();
    try l.appendGroup("one");
    try l.appendGroup("two two");
    try l.appendGroup("three");
    // tear the last record
    l.data.shrinkRetainingCapacity(l.data.items.len - 2);
    var got: std.ArrayList([]u8) = .empty;
    defer {
        for (got.items) |g| gpa.free(g);
        got.deinit(gpa);
    }
    try l.replay(Collect{ .list = &got, .gpa = gpa }, Collect.visit);
    try std.testing.expectEqual(@as(usize, 2), got.items.len);
    try std.testing.expectEqualStrings("two two", got.items[1]);
    // appending after the cut continues cleanly
    try l.appendGroup("four");
    var got2: std.ArrayList([]u8) = .empty;
    defer {
        for (got2.items) |g| gpa.free(g);
        got2.deinit(gpa);
    }
    try l.replay(Collect{ .list = &got2, .gpa = gpa }, Collect.visit);
    try std.testing.expectEqual(@as(usize, 3), got2.items.len);
}

test "checksum binds the offset" {
    const gpa = std.testing.allocator;
    const a = try frame(gpa, 8, "x");
    defer gpa.free(a);
    const b = try frame(gpa, 16, "x");
    defer gpa.free(b);
    try std.testing.expect(!std.mem.eql(u8, a, b));
}
