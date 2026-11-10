//! Durable removal-prior index (NODE.md "System child reads above the bound"): for every child
//! object (owner `ObjectOwner`) a transaction deleted or wrapped, (id, the version its removal
//! record carries) -> the version the removal consumed. `Executor.removed_prior` keeps it in
//! memory; this file makes it survive a restart, so a system child read whose store record is a
//! removal above the settlement's bound still walks back after a kill -9 or an upgrade.
//!
//! File `<node dir>/removed-prior.log`: an 8-byte magic, then fixed 72-byte records, each with a
//! CRC32 of its last 68 bytes:
//! - removal (cp, id, version, prior): written by the executor's ordered step for checkpoint cp;
//! - mark (cp): the removals of every checkpoint up to cp are in the file (written with the
//!   checkpoint's removals, or alone every `mark_every` checkpoints without any);
//! - scanned (cp = lo): the store's checkpoints from lo up to the file's first checkpoint were
//!   scanned (a file started on a store that already held history).
//! A torn or corrupt tail is cut at open. Records are written before the store commits their
//! checkpoint (the ordered step runs ahead of the commit), so after a crash the file may hold a
//! checkpoint the store does not; that is harmless (keys are certified removals, and the store
//! commits the same checkpoint again). Records the file lacks for committed checkpoints (a
//! stop between the commit and the next mark) are derived again from the store at open
//! (`fromStore`): the same entries from the stored effects.
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");

pub const Key = struct { id: [32]u8, version: u64 };
pub const Map = std.AutoHashMapUnmanaged(Key, u64);
pub const Entry = struct { id: [32]u8, version: u64, prior: u64 };

const magic = "ZUIRMP01";
pub const rec_len = 72;
const Kind = enum(u8) { removal = 0, mark = 1, scanned = 2 };
/// A mark at least this often (checkpoints), so the gap scanned again at open stays short.
pub const mark_every: u64 = 256;

pub const Log = struct {
    io: Io,
    file: Io.File,
    end: u64,
    /// Every checkpoint up to here has its removals in the file.
    wm: ?u64 = null,
    /// Lowest checkpoint the file covers (its first record's, or a finished scan's low end).
    lo: ?u64 = null,
    /// The scan below the file's first checkpoint finished (or was not needed).
    scanned: bool = false,
    last_mark: ?u64 = null,
    records: u64 = 0,
    lock: Io.Mutex = .init,

    /// Opens (or creates) `path` and loads its removals into `map`.
    pub fn open(gpa: std.mem.Allocator, io: Io, path: []const u8, map: *Map) !Log {
        const cwd = Io.Dir.cwd();
        if (std.fs.path.dirname(path)) |d| try cwd.createDirPath(io, d);
        const data = cwd.readFileAlloc(io, path, gpa, .unlimited) catch |e| switch (e) {
            error.FileNotFound => try gpa.dupe(u8, ""),
            else => return e,
        };
        defer gpa.free(data);
        const f = try cwd.createFile(io, path, .{ .read = true, .truncate = false });
        errdefer f.close(io);
        var l: Log = .{ .io = io, .file = f, .end = 0 };
        if (data.len < magic.len or !std.mem.eql(u8, data[0..magic.len], magic)) {
            try f.setLength(io, 0);
            try f.writePositionalAll(io, magic, 0);
            try f.sync(io);
            l.end = magic.len;
            return l;
        }
        var at: usize = magic.len;
        while (at + rec_len <= data.len) : (at += rec_len) {
            const r = data[at..][0..rec_len];
            if (std.hash.Crc32.hash(r[4..]) != std.mem.readInt(u32, r[0..4], .little)) break;
            if (r[4] > @intFromEnum(Kind.scanned)) break;
            const kind: Kind = @enumFromInt(r[4]);
            const cp = std.mem.readInt(u64, r[8..16], .little);
            switch (kind) {
                .removal => {
                    try map.put(gpa, .{ .id = r[16..48].*, .version = std.mem.readInt(u64, r[48..56], .little) }, std.mem.readInt(u64, r[56..64], .little));
                    if (l.lo == null) l.lo = cp;
                },
                .mark => {
                    if (l.lo == null) l.lo = cp;
                    l.wm = if (l.wm) |w| @max(w, cp) else cp;
                    l.last_mark = l.wm;
                },
                .scanned => {
                    l.scanned = true;
                    l.lo = if (l.lo) |x| @min(x, cp) else cp;
                },
            }
            l.records += 1;
        }
        if (at != data.len) {
            std.log.warn("removal log: {s}: torn or corrupt tail at byte {d} of {d}; cut", .{ path, at, data.len });
            try f.setLength(io, at);
            try f.sync(io);
        }
        l.end = at;
        return l;
    }

    pub fn close(l: *Log) void {
        l.file.close(l.io);
    }

    fn encode(buf: *[rec_len]u8, kind: Kind, cp: u64, e: Entry) void {
        @memset(buf, 0);
        buf[4] = @intFromEnum(kind);
        std.mem.writeInt(u64, buf[8..16], cp, .little);
        buf[16..48].* = e.id;
        std.mem.writeInt(u64, buf[48..56], e.version, .little);
        std.mem.writeInt(u64, buf[56..64], e.prior, .little);
        std.mem.writeInt(u32, buf[0..4], std.hash.Crc32.hash(buf[4..]), .little);
    }

    fn write(l: *Log, bytes: []const u8) !void {
        try l.file.writePositionalAll(l.io, bytes, l.end);
        l.end += bytes.len;
    }

    /// The removals of checkpoint `cp` (in sequence order), then a mark when there were any or
    /// `mark_every` checkpoints passed since the last one. One write; not fsync'd (a kill -9
    /// keeps it in the page cache; after a power loss `open` plus the store rescan recovers).
    pub fn appendCheckpoint(l: *Log, gpa: std.mem.Allocator, cp: u64, entries: []const Entry) !void {
        const need_mark = entries.len > 0 or l.last_mark == null or cp >= l.last_mark.? + mark_every;
        if (!need_mark) {
            l.wm = cp;
            return;
        }
        const buf = try gpa.alloc(u8, (entries.len + 1) * rec_len);
        defer gpa.free(buf);
        for (entries, 0..) |e, i| encode(buf[i * rec_len ..][0..rec_len], .removal, cp, e);
        encode(buf[entries.len * rec_len ..][0..rec_len], .mark, cp, .{ .id = @splat(0), .version = 0, .prior = 0 });
        l.lock.lockUncancelable(l.io);
        defer l.lock.unlock(l.io);
        try l.write(buf);
        if (l.lo == null) l.lo = cp;
        l.wm = cp;
        l.last_mark = cp;
        l.records += entries.len + 1;
    }

    /// Removals found by the scan below the file's start (any order), and its end record.
    pub fn appendScanned(l: *Log, gpa: std.mem.Allocator, cp: u64, entries: []const Entry) !void {
        if (entries.len == 0) return;
        const buf = try gpa.alloc(u8, entries.len * rec_len);
        defer gpa.free(buf);
        for (entries, 0..) |e, i| encode(buf[i * rec_len ..][0..rec_len], .removal, cp, e);
        l.lock.lockUncancelable(l.io);
        defer l.lock.unlock(l.io);
        try l.write(buf);
        l.records += entries.len;
    }

    pub fn finishScan(l: *Log, lo: u64) !void {
        var buf: [rec_len]u8 = undefined;
        encode(&buf, .scanned, lo, .{ .id = @splat(0), .version = 0, .prior = 0 });
        l.lock.lockUncancelable(l.io);
        defer l.lock.unlock(l.io);
        try l.write(&buf);
        try l.file.sync(l.io);
        l.scanned = true;
        l.lo = if (l.lo) |x| @min(x, lo) else lo;
        l.records += 1;
    }
};

/// The child removals of stored checkpoint `seq` from its effects: an input that existed with
/// an `ObjectOwner` and has no output (V2: input `Exist(.., ObjectOwner)`, output `NotExist`),
/// keyed by the transaction's lamport version, exactly what `Executor.noteRemovals` takes from
/// the checkpoint's objects. V1 effects carry no input owners and are skipped (pre-2024 history,
/// which no retained window holds). False: the store does not hold the checkpoint.
pub fn fromStore(gpa: std.mem.Allocator, arena: std.mem.Allocator, snap: *const store.Snapshot, seq: u64, out: *std.ArrayList(Entry)) !bool {
    const rec = (try snap.checkpointChecked(seq)) orelse return false;
    const contents = try bcs.decode(types.CheckpointContents, arena, try arena.dupe(u8, rec.contents));
    const n = switch (contents) {
        .V1 => |v| v.transactions.len,
        .V2 => |v| v.transactions.len,
    };
    for (0..n) |i| {
        const dg: *const [32]u8 = switch (contents) {
            .V1 => |v| &v.transactions[i].transaction.@"0".@"0",
            .V2 => |v| &v.transactions[i].digest.transaction.@"0".@"0",
        };
        const tr = (try snap.transactionChecked(dg)) orelse return error.TransactionNotStored;
        const eff = try bcs.decode(types.TransactionEffects, arena, try arena.dupe(u8, tr.effects));
        switch (eff) {
            .V1 => {},
            .V2 => |*v| for (v.changed_objects) |*c| {
                if (c.@"1".output_state != .NotExist) continue;
                switch (c.@"1".input_state) {
                    .NotExist => {},
                    .Exist => |x| if (x.@"1" == .ObjectOwner) try out.append(gpa, .{ .id = c.@"0".@"0".@"0", .version = v.lamport_version.@"0", .prior = x.@"0".@"0".@"0" }),
                }
            },
        }
    }
    return true;
}

test "removal log: append, reopen, torn tail, marks" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &pb);
    const path = try std.fmt.allocPrint(gpa, "{s}/node/removed-prior.log", .{pb[0..n]});
    defer gpa.free(path);
    var map: Map = .empty;
    defer map.deinit(gpa);
    {
        var l = try Log.open(gpa, io, path, &map);
        defer l.close();
        try std.testing.expectEqual(@as(?u64, null), l.wm);
        try l.appendCheckpoint(gpa, 100, &.{ .{ .id = @splat(1), .version = 50, .prior = 40 }, .{ .id = @splat(2), .version = 50, .prior = 7 } });
        try l.appendCheckpoint(gpa, 101, &.{}); // no mark: within mark_every
        try l.appendCheckpoint(gpa, 100 + mark_every, &.{}); // a mark alone
        try l.appendCheckpoint(gpa, 400, &.{.{ .id = @splat(3), .version = 90, .prior = 89 }});
        try std.testing.expectEqual(@as(?u64, 400), l.wm);
    }
    {
        var l = try Log.open(gpa, io, path, &map);
        defer l.close();
        try std.testing.expectEqual(@as(?u64, 400), l.wm);
        try std.testing.expectEqual(@as(?u64, 100), l.lo);
        try std.testing.expect(!l.scanned);
        try std.testing.expectEqual(@as(u32, 3), map.count());
        try std.testing.expectEqual(@as(?u64, 40), map.get(.{ .id = @splat(1), .version = 50 }));
        try std.testing.expectEqual(@as(?u64, 89), map.get(.{ .id = @splat(3), .version = 90 }));
        try l.finishScan(10);
        // A torn record (a kill -9 mid-write): half a record at the end.
        var junk: [rec_len / 2]u8 = @splat(0xab);
        try l.write(&junk);
    }
    map.clearRetainingCapacity();
    {
        var l = try Log.open(gpa, io, path, &map);
        defer l.close();
        try std.testing.expect(l.scanned);
        try std.testing.expectEqual(@as(?u64, 10), l.lo);
        try std.testing.expectEqual(@as(u32, 3), map.count());
        try std.testing.expectEqual(magic.len + 7 * rec_len, l.end);
        // Appends go after the cut.
        try l.appendCheckpoint(gpa, 401, &.{.{ .id = @splat(4), .version = 91, .prior = 3 }});
    }
    // A flipped byte in a record: the file is cut there.
    {
        const data = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .unlimited);
        defer gpa.free(data);
        data[magic.len + 3 * rec_len + 20] ^= 1;
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
    }
    map.clearRetainingCapacity();
    var l = try Log.open(gpa, io, path, &map);
    defer l.close();
    try std.testing.expectEqual(@as(u32, 2), map.count());
    try std.testing.expectEqual(@as(?u64, 100), l.wm);
}
