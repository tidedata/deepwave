//! The pending-transaction log of ExecuteTransaction (sui-node 1.83.1
//! `WritePathPendingTransactionLog`, the `fullnode_pending_transactions` table that
//! `TransactionOrchestrator` keeps beside its db): a transaction is written before the node
//! submits it and removed once the submission is over, so a node killed mid-submission submits it
//! again on the next start (`start_task_to_recover_txes_in_log`).
//!
//! - Keyed by transaction digest; the value is what a resubmission needs (the BCS `Transaction`
//!   envelope, the BCS `TransactionData` and the raw user signatures). `writeMaybe` answers
//!   whether the digest is new (`write_pending_transaction_maybe`); `finish` removes it and is a
//!   no-op for an unknown digest (`finish_transaction`).
//! - On disk: `<dir>/pending.log`, a magic header and then one record per add or finish
//!   (`len u32 | crc32 u32 | body`). Records are written with `pwrite` and not fsync'd (sui-node's
//!   rocksdb writes without `sync` either): they survive a process crash (kill -9), not a power
//!   cut; `sync = true` fsyncs each one. A torn or corrupt tail ends the replay and is cut off.
//! - `open` replays the log (adds minus finishes) and rewrites it compacted (tmp, fsync, rename,
//!   fsync of the directory), so the file holds only what is pending. While running it is
//!   compacted again once it is over `compact_min` bytes and four times the live records.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const file_name = "pending.log";
const tmp_name = "pending.log.tmp";
const magic = "ZUIPTX01";
const kind_add: u8 = 1;
const kind_finish: u8 = 2;

/// A pending transaction and its digest (`snapshot`).
pub const Pending = struct { digest: [32]u8, entry: Entry };

/// One pending transaction (bytes owned by the log).
pub const Entry = struct {
    envelope: []const u8,
    data_bcs: []const u8,
    signatures: []const []const u8,
};

pub const PendingLog = struct {
    gpa: Allocator,
    io: Io,
    dir: Io.Dir,
    file: Io.File,
    end: u64,
    /// Bytes of the add records of the pending entries (what a compaction keeps).
    live_bytes: u64 = 0,
    mu: Io.Mutex = .init,
    map: std.AutoArrayHashMapUnmanaged([32]u8, Stored) = .empty,
    sync: bool = false,
    compact_min: u64 = 8 << 20,
    /// Records the replay dropped (a torn or corrupt tail) at `open`.
    torn_bytes: u64 = 0,
    write_errors: std.atomic.Value(u64) = .init(0),

    /// The add record's body (owned) and the entry slicing into it.
    const Stored = struct { body: []u8, entry: Entry, sigs: [][]const u8 };

    pub fn open(gpa: Allocator, io: Io, path: []const u8) !*PendingLog {
        try Io.Dir.cwd().createDirPath(io, path);
        const dir = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
        errdefer dir.close(io);
        const self = try gpa.create(PendingLog);
        errdefer gpa.destroy(self);
        self.* = .{ .gpa = gpa, .io = io, .dir = dir, .file = undefined, .end = 0 };
        errdefer self.freeMap();
        if (dir.readFileAlloc(io, file_name, gpa, .unlimited)) |data| {
            defer gpa.free(data);
            try self.replay(data);
        } else |e| if (e != error.FileNotFound) return e;
        try self.rewrite();
        return self;
    }

    pub fn close(self: *PendingLog) void {
        self.file.close(self.io);
        self.dir.close(self.io);
        self.freeMap();
        self.gpa.destroy(self);
    }

    fn freeMap(self: *PendingLog) void {
        for (self.map.values()) |s| self.freeStored(s);
        self.map.deinit(self.gpa);
    }

    fn freeStored(self: *PendingLog, s: Stored) void {
        self.gpa.free(s.sigs);
        self.gpa.free(s.body);
    }

    pub fn count(self: *PendingLog) usize {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return self.map.count();
    }

    pub fn contains(self: *PendingLog, digest: *const [32]u8) bool {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return self.map.contains(digest.*);
    }

    /// Writes the transaction unless its digest is pending; true when it was new. An I/O error
    /// keeps it pending in memory (dedup still holds) and is counted.
    pub fn writeMaybe(self: *PendingLog, digest: *const [32]u8, e: Entry) bool {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        if (self.map.contains(digest.*)) return false;
        const body = encodeAdd(self.gpa, digest, e) catch {
            _ = self.write_errors.fetchAdd(1, .monotonic);
            return true;
        };
        const s = decodeStored(self.gpa, body) catch {
            self.gpa.free(body);
            _ = self.write_errors.fetchAdd(1, .monotonic);
            return true;
        };
        self.map.put(self.gpa, digest.*, s) catch {
            self.freeStored(s);
            _ = self.write_errors.fetchAdd(1, .monotonic);
            return true;
        };
        self.live_bytes += 8 + body.len;
        self.append(body);
        return true;
    }

    /// Removes the digest (a no-op when it is not pending).
    pub fn finish(self: *PendingLog, digest: *const [32]u8) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        const kv = self.map.fetchSwapRemove(digest.*) orelse return;
        self.live_bytes -= 8 + kv.value.body.len;
        self.freeStored(kv.value);
        var body: [33]u8 = undefined;
        body[0] = kind_finish;
        @memcpy(body[1..], digest);
        self.append(&body);
        if (self.end > self.compact_min and self.end > 4 * (self.live_bytes + magic.len)) self.rewrite() catch {
            _ = self.write_errors.fetchAdd(1, .monotonic);
        };
    }

    /// The pending entries (`load_all_pending_transactions`), copied into `arena`.
    pub fn snapshot(self: *PendingLog, arena: Allocator) ![]Pending {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        const out = try arena.alloc(Pending, self.map.count());
        for (self.map.keys(), self.map.values(), out) |k, v, *o| {
            const sigs = try arena.alloc([]const u8, v.entry.signatures.len);
            for (v.entry.signatures, sigs) |s, *d| d.* = try arena.dupe(u8, s);
            o.* = .{ .digest = k, .entry = .{
                .envelope = try arena.dupe(u8, v.entry.envelope),
                .data_bcs = try arena.dupe(u8, v.entry.data_bcs),
                .signatures = sigs,
            } };
        }
        return out;
    }

    fn append(self: *PendingLog, body: []const u8) void {
        var hdr: [8]u8 = undefined;
        std.mem.writeInt(u32, hdr[0..4], @intCast(body.len), .little);
        std.mem.writeInt(u32, hdr[4..8], std.hash.Crc32.hash(body), .little);
        self.file.writePositionalAll(self.io, &hdr, self.end) catch return self.ioError();
        self.file.writePositionalAll(self.io, body, self.end + 8) catch return self.ioError();
        self.end += 8 + body.len;
        if (self.sync) self.file.sync(self.io) catch return self.ioError();
    }

    fn ioError(self: *PendingLog) void {
        _ = self.write_errors.fetchAdd(1, .monotonic);
    }

    /// Applies the valid prefix of a log file; the rest is counted in `torn_bytes`.
    fn replay(self: *PendingLog, data: []const u8) !void {
        if (data.len < magic.len or !std.mem.eql(u8, data[0..magic.len], magic)) {
            self.torn_bytes = data.len;
            return;
        }
        var at: usize = magic.len;
        while (at + 8 <= data.len) {
            const len = std.mem.readInt(u32, data[at..][0..4], .little);
            const crc = std.mem.readInt(u32, data[at + 4 ..][0..4], .little);
            if (len < 33 or at + 8 + len > data.len) break;
            const body = data[at + 8 ..][0..len];
            if (std.hash.Crc32.hash(body) != crc) break;
            const digest = body[1..33];
            switch (body[0]) {
                kind_add => {
                    const own = try self.gpa.dupe(u8, body);
                    const s = decodeStored(self.gpa, own) catch {
                        self.gpa.free(own);
                        break;
                    };
                    const g = self.map.getOrPut(self.gpa, digest[0..32].*) catch |e| {
                        self.freeStored(s);
                        return e;
                    };
                    if (g.found_existing) {
                        self.live_bytes -= 8 + g.value_ptr.body.len;
                        self.freeStored(g.value_ptr.*);
                    }
                    g.value_ptr.* = s;
                    self.live_bytes += 8 + own.len;
                },
                kind_finish => if (self.map.fetchSwapRemove(digest[0..32].*)) |kv| {
                    self.live_bytes -= 8 + kv.value.body.len;
                    self.freeStored(kv.value);
                },
                else => break,
            }
            at += 8 + len;
        }
        self.torn_bytes = data.len - at;
    }

    /// Writes a log holding only the pending entries and makes it the live file.
    fn rewrite(self: *PendingLog) !void {
        const io = self.io;
        const f = try self.dir.createFile(io, tmp_name, .{ .read = true, .truncate = true });
        var ok = false;
        defer if (!ok) f.close(io);
        try f.writePositionalAll(io, magic, 0);
        var end: u64 = magic.len;
        for (self.map.values()) |s| {
            var hdr: [8]u8 = undefined;
            std.mem.writeInt(u32, hdr[0..4], @intCast(s.body.len), .little);
            std.mem.writeInt(u32, hdr[4..8], std.hash.Crc32.hash(s.body), .little);
            try f.writePositionalAll(io, &hdr, end);
            try f.writePositionalAll(io, s.body, end + 8);
            end += 8 + s.body.len;
        }
        try f.sync(io);
        try self.dir.rename(tmp_name, self.dir, file_name, io);
        syncDir(io, self.dir);
        ok = true;
        if (self.end != 0) self.file.close(io);
        self.file = f;
        self.end = end;
    }
};

fn putBytes(w: *std.ArrayList(u8), gpa: Allocator, b: []const u8) !void {
    var l: [4]u8 = undefined;
    std.mem.writeInt(u32, &l, @intCast(b.len), .little);
    try w.appendSlice(gpa, &l);
    try w.appendSlice(gpa, b);
}

/// kind | digest | envelope | data_bcs | nsig u32 | sigs (each `len u32 | bytes`).
fn encodeAdd(gpa: Allocator, digest: *const [32]u8, e: Entry) ![]u8 {
    var w: std.ArrayList(u8) = .empty;
    errdefer w.deinit(gpa);
    try w.append(gpa, kind_add);
    try w.appendSlice(gpa, digest);
    try putBytes(&w, gpa, e.envelope);
    try putBytes(&w, gpa, e.data_bcs);
    var n: [4]u8 = undefined;
    std.mem.writeInt(u32, &n, @intCast(e.signatures.len), .little);
    try w.appendSlice(gpa, &n);
    for (e.signatures) |s| try putBytes(&w, gpa, s);
    return w.toOwnedSlice(gpa);
}

/// Slices an add body (owned by the result).
fn decodeStored(gpa: Allocator, body: []u8) !PendingLog.Stored {
    var at: usize = 33;
    const take = struct {
        fn f(b: []const u8, p: *usize) ![]const u8 {
            if (p.* + 4 > b.len) return error.Malformed;
            const l = std.mem.readInt(u32, b[p.*..][0..4], .little);
            p.* += 4;
            if (p.* + l > b.len) return error.Malformed;
            defer p.* += l;
            return b[p.*..][0..l];
        }
    }.f;
    const env = try take(body, &at);
    const data = try take(body, &at);
    if (at + 4 > body.len) return error.Malformed;
    const n = std.mem.readInt(u32, body[at..][0..4], .little);
    at += 4;
    if (n > 1024) return error.Malformed;
    const sigs = try gpa.alloc([]const u8, n);
    errdefer gpa.free(sigs);
    for (sigs) |*s| s.* = try take(body, &at);
    if (at != body.len) return error.Malformed;
    return .{ .body = body, .entry = .{ .envelope = env, .data_bcs = data, .signatures = sigs }, .sigs = sigs };
}

fn syncDir(io: Io, dir: Io.Dir) void {
    const f: Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    f.sync(io) catch {};
}

/// sui-node's retry delay (mysten-common `ExponentialBackoff::new(1 s, 300 s)`): the next delay
/// is the current one times 1.2, capped at `max_ms`, plus a jitter below `jitter_ms` (the
/// initial delay). `r` is a uniform random u64.
pub fn nextDelayMs(cur_ms: u64, max_ms: u64, jitter_ms: u64, r: u64) u64 {
    const grown = @min(cur_ms + cur_ms / 5, max_ms);
    return grown + if (jitter_ms == 0) 0 else r % jitter_ms;
}

// ------------------------------------------------------------------------------------------ tests

const testing = std.testing;

fn tmpPath(buf: []u8, tmp: *testing.TmpDir, sub: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, sub });
}

fn entryOf(env: []const u8, sigs: []const []const u8) Entry {
    return .{ .envelope = env, .data_bcs = env[1..], .signatures = sigs };
}

test "pending log: write once per digest, finish, replay after reopen" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [256]u8 = undefined;
    const path = try tmpPath(&pb, &tmp, "p");
    const sigs = [_][]const u8{ "sig-a", "sig-bb" };
    var d: [3][32]u8 = undefined;
    for (&d, 0..) |*x, i| x.* = @splat(@intCast(i + 1));
    {
        const l = try PendingLog.open(testing.allocator, testing.io, path);
        defer l.close();
        try testing.expect(l.writeMaybe(&d[0], entryOf("envelope-0", &sigs)));
        try testing.expect(!l.writeMaybe(&d[0], entryOf("envelope-0", &sigs))); // in flight
        try testing.expect(l.writeMaybe(&d[1], entryOf("envelope-1", &sigs)));
        try testing.expect(l.writeMaybe(&d[2], entryOf("envelope-2", &.{})));
        l.finish(&d[1]);
        l.finish(&d[1]); // finishing twice is fine
        try testing.expectEqual(@as(usize, 2), l.count());
    }
    // reopen (the close above is a clean shutdown; the crash case is the next tests)
    const l = try PendingLog.open(testing.allocator, testing.io, path);
    defer l.close();
    try testing.expectEqual(@as(usize, 2), l.count());
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const got = try l.snapshot(a.allocator());
    var seen: u32 = 0;
    for (got) |g| {
        if (std.mem.eql(u8, &g.digest, &d[0])) {
            try testing.expectEqualStrings("envelope-0", g.entry.envelope);
            try testing.expectEqualStrings("nvelope-0", g.entry.data_bcs);
            try testing.expectEqual(@as(usize, 2), g.entry.signatures.len);
            try testing.expectEqualStrings("sig-bb", g.entry.signatures[1]);
            seen |= 1;
        }
        if (std.mem.eql(u8, &g.digest, &d[2])) {
            try testing.expectEqual(@as(usize, 0), g.entry.signatures.len);
            seen |= 2;
        }
    }
    try testing.expectEqual(@as(u32, 3), seen);
    // the reopen compacted the file: header + two add records
    try testing.expectEqual(l.live_bytes + magic.len, l.end);
}

test "pending log: a torn or corrupt tail is cut off, the prefix is kept" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [256]u8 = undefined;
    const path = try tmpPath(&pb, &tmp, "p");
    const d0: [32]u8 = @splat(7);
    const d1: [32]u8 = @splat(8);
    var full_len: u64 = 0;
    {
        const l = try PendingLog.open(testing.allocator, testing.io, path);
        // no close: a crash leaves the file as written
        try testing.expect(l.writeMaybe(&d0, entryOf("first", &.{"s"})));
        try testing.expect(l.writeMaybe(&d1, entryOf("second", &.{"s"})));
        full_len = l.end;
        l.file.close(testing.io);
        l.dir.close(testing.io);
        l.freeMap();
        testing.allocator.destroy(l);
    }
    var fb: [256]u8 = undefined;
    const fpath = try std.fmt.bufPrint(&fb, "{s}/{s}", .{ path, file_name });
    // torn: the second record lost its last 3 bytes
    {
        const f = try Io.Dir.cwd().openFile(testing.io, fpath, .{ .mode = .read_write });
        defer f.close(testing.io);
        try f.setLength(testing.io, full_len - 3);
    }
    {
        const l = try PendingLog.open(testing.allocator, testing.io, path);
        defer l.close();
        try testing.expectEqual(@as(usize, 1), l.count());
        try testing.expect(l.contains(&d0));
        try testing.expect(l.torn_bytes > 0);
        // the cut file takes new records again
        try testing.expect(l.writeMaybe(&d1, entryOf("second", &.{"s"})));
    }
    // corrupt: flip a byte inside the last record's body
    {
        const f = try Io.Dir.cwd().openFile(testing.io, fpath, .{ .mode = .read_write });
        defer f.close(testing.io);
        const st = try f.stat(testing.io);
        try f.writePositionalAll(testing.io, "X", st.size - 2);
    }
    const l = try PendingLog.open(testing.allocator, testing.io, path);
    defer l.close();
    try testing.expectEqual(@as(usize, 1), l.count());
    try testing.expect(l.contains(&d0));
    try testing.expect(!l.contains(&d1));
}

test "pending log: compaction while running keeps exactly the pending entries" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [256]u8 = undefined;
    const path = try tmpPath(&pb, &tmp, "p");
    const l = try PendingLog.open(testing.allocator, testing.io, path);
    l.compact_min = 4096;
    var big: [600]u8 = @splat('e');
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        var d: [32]u8 = @splat(0);
        std.mem.writeInt(u32, d[0..4], i, .little);
        try testing.expect(l.writeMaybe(&d, entryOf(&big, &.{})));
        if (i % 10 != 0) l.finish(&d);
    }
    try testing.expectEqual(@as(usize, 20), l.count());
    try testing.expect(l.end < 200 * 600); // compacted at least once
    l.close();
    const r = try PendingLog.open(testing.allocator, testing.io, path);
    defer r.close();
    try testing.expectEqual(@as(usize, 20), r.count());
    var d: [32]u8 = @splat(0);
    std.mem.writeInt(u32, d[0..4], 190, .little);
    try testing.expect(r.contains(&d));
}

test "retry delays: sui-node's ExponentialBackoff(1 s, 300 s), factor 1.2, jitter below 1 s" {
    // no jitter: 1000, 1200, 1440, ... capped at 300 s
    var cur: u64 = 1000;
    const want = [_]u64{ 1200, 1440, 1728, 2073, 2487 };
    for (want) |w| {
        cur = nextDelayMs(cur, 300_000, 0, 0);
        try testing.expectEqual(w, cur);
    }
    try testing.expectEqual(@as(u64, 300_000), nextDelayMs(290_000, 300_000, 0, 0));
    // jitter in [0, 1000)
    try testing.expectEqual(@as(u64, 1200 + 999), nextDelayMs(1000, 300_000, 1000, 1999));
    try testing.expectEqual(@as(u64, 300_000 + 5), nextDelayMs(300_000, 300_000, 1000, 5));
}
