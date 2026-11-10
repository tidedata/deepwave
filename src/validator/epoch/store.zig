//! The per-epoch store `<db>/validator/epoch-<n>/epoch.log` (docs/VALIDATOR-DESIGN.md 6.2): the
//! `AuthorityEpochTables` subset a validator needs, as named tables of byte keys and values held in
//! memory and persisted as one atomic, checksummed record per consensus commit (Rust's consensus
//! quarantine: `ConsensusCommitOutput` written in one batch). A batch is durable after one fdatasync;
//! recovery replays intact records and cuts a torn tail, so a commit is either fully there or not
//! at all, and the handler's `processed_through` (the table `exec_indices`) always matches the other
//! tables.
//!
//! Every validator lane keeps its epoch state here through its own tables (`Table`); the typed
//! helpers for this lane's tables (end of publish, capabilities, deny config, reconfig state) are
//! in reconfig.zig.
const std = @import("std");
const Io = std.Io;
const fsutil = @import("../keys/fsutil.zig");

pub const Error = error{ Io, OutOfMemory, BatchTooLarge };

/// Table ids are part of the file format; append only.
pub const Table = enum(u8) {
    /// Singleton values by name: `reconfig_state`, `epoch_info`.
    meta = 0,
    /// `last_consensus_stats`: key "last" = ExecutionIndices (commit index, sub-dag index, tx index).
    exec_indices = 1,
    /// Processed ConsensusTransactionKeys (BCS) -> empty.
    processed_keys = 2,
    owned_locks = 3,
    next_shared_versions = 4,
    deferred = 5,
    congestion = 6,
    pending_checkpoints = 7,
    builder_summaries = 8,
    own_checkpoint_sigs = 9,
    peer_checkpoint_sigs = 10,
    dkg_messages = 11,
    dkg_confirmations = 12,
    dkg_output = 13,
    randomness = 14,
    jwk_votes = 15,
    jwk_active = 16,
    /// Authority index (u32 LE) -> empty: validators whose EndOfPublish was sequenced.
    end_of_publish = 17,
    /// Authority index (u32 LE) -> BCS(AuthorityCapabilitiesV2) of the highest generation.
    capabilities_v2 = 18,
    deny_config = 19,
    /// Free for lanes that need one more table without a format change.
    scratch0 = 20,
    scratch1 = 21,
    scratch2 = 22,
    scratch3 = 23,
};

pub const table_count = std.enums.values(Table).len;

const Map = std.StringArrayHashMapUnmanaged([]u8);

const op_put: u8 = 1;
const op_del: u8 = 2;

/// Writes staged for one commit. Created by `EpochStore.batch`, applied by `commit`.
pub const Batch = struct {
    gpa: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,
    ops: u32 = 0,

    pub fn deinit(b: *Batch) void {
        b.buf.deinit(b.gpa);
    }

    pub fn put(b: *Batch, t: Table, key: []const u8, value: []const u8) Error!void {
        try b.op(op_put, t, key, value);
    }

    pub fn del(b: *Batch, t: Table, key: []const u8) Error!void {
        try b.op(op_del, t, key, "");
    }

    fn op(b: *Batch, kind: u8, t: Table, key: []const u8, value: []const u8) Error!void {
        if (key.len > std.math.maxInt(u16)) return error.BatchTooLarge;
        if (b.buf.items.len + key.len + value.len + 8 > fsutil.RecordLog.max_record - 16) return error.BatchTooLarge;
        var h: [8]u8 = undefined;
        h[0] = @intFromEnum(t);
        h[1] = kind;
        std.mem.writeInt(u16, h[2..4], @intCast(key.len), .little);
        std.mem.writeInt(u32, h[4..8], @intCast(value.len), .little);
        try b.buf.appendSlice(b.gpa, &h);
        try b.buf.appendSlice(b.gpa, key);
        try b.buf.appendSlice(b.gpa, value);
        b.ops += 1;
    }
};

/// Compaction policy: the log is rewritten as a snapshot of the live tables once it is at least
/// `compact_floor` bytes and `compact_ratio` times the live data (so a large, mostly live state
/// is not rewritten over and over).
pub const default_compact_floor: u64 = 32 << 20;
pub const compact_ratio: u64 = 3;
/// One snapshot record holds about this much.
const snapshot_chunk: usize = 1 << 20;

pub const Store = struct {
    gpa: std.mem.Allocator,
    path: []u8,
    log: fsutil.RecordLog,
    /// Bytes of keys, values and per-entry framing in the tables (what a snapshot would write).
    live_bytes: u64 = 0,
    compact_floor: u64 = default_compact_floor,
    compactions: u64 = 0,
    tables: [table_count]Map = @splat(.empty),
    mutex: Io.Mutex = .init,
    io: Io,
    /// Records replayed at open (for tests and logs).
    recovered_batches: u64 = 0,

    pub fn open(gpa: std.mem.Allocator, io: Io, path: []const u8) Error!*Store {
        if (std.fs.path.dirname(path)) |d| try fsutil.makePath(io, d);
        const self = gpa.create(Store) catch return error.OutOfMemory;
        errdefer gpa.destroy(self);
        self.* = .{ .gpa = gpa, .path = try gpa.dupe(u8, path), .log = undefined, .io = io };
        errdefer gpa.free(self.path);
        // a compaction that died before its rename left a partial snapshot: it is not the log
        {
            var tb: [std.fs.max_path_bytes]u8 = undefined;
            if (compactPath(&tb, path)) |t| Io.Dir.cwd().deleteFile(io, t) catch {};
        }
        const Visit = struct {
            fn go(s: *Store, payload: []const u8) void {
                s.apply(payload) catch {};
                s.recovered_batches += 1;
            }
        };
        self.log = try fsutil.RecordLog.open(gpa, io, path, self, Visit.go);
        return self;
    }

    pub fn close(s: *Store) void {
        s.log.close();
        s.gpa.free(s.path);
        for (&s.tables) |*m| {
            var it = m.iterator();
            while (it.next()) |e| {
                s.gpa.free(e.key_ptr.*);
                s.gpa.free(e.value_ptr.*);
            }
            m.deinit(s.gpa);
        }
        s.gpa.destroy(s);
    }

    pub fn batch(s: *Store) Batch {
        return .{ .gpa = s.gpa };
    }

    /// Makes `b` durable (one record, one fdatasync) and then visible to readers. An empty batch is
    /// a no-op.
    pub fn commit(s: *Store, b: *Batch) Error!void {
        if (b.ops == 0) return;
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        try s.log.append(b.buf.items);
        try s.log.sync();
        try s.apply(b.buf.items);
        b.buf.clearRetainingCapacity();
        b.ops = 0;
        if (s.log.end >= s.compact_floor and s.log.end >= compact_ratio * (s.live_bytes + 4096)) {
            // the commit is durable already: a failed compaction only leaves the log long
            s.compactLocked() catch {};
        }
    }

    fn compactPath(buf: []u8, path: []const u8) ?[]const u8 {
        return std.fmt.bufPrint(buf, "{s}.compact", .{path}) catch null;
    }

    /// Rewrites the log as a snapshot of the live tables (temp file, fsync, rename), dropping
    /// every superseded write.
    pub fn compact(s: *Store) Error!void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        try s.compactLocked();
    }

    fn compactLocked(s: *Store) Error!void {
        var tb: [std.fs.max_path_bytes]u8 = undefined;
        const tmp = compactPath(&tb, s.path) orelse return error.Io;
        var next = try s.log.beginReplace(tmp);
        var ok = false;
        defer if (!ok) {
            next.file.close(s.io);
            Io.Dir.cwd().deleteFile(s.io, tmp) catch {};
        };
        var b = s.batch();
        defer b.deinit();
        for (&s.tables, 0..) |*m, ti| {
            var it = m.iterator();
            while (it.next()) |e| {
                try b.put(@enumFromInt(ti), e.key_ptr.*, e.value_ptr.*);
                if (b.buf.items.len >= snapshot_chunk) {
                    try next.append(b.buf.items);
                    b.buf.clearRetainingCapacity();
                    b.ops = 0;
                }
            }
        }
        if (b.ops > 0) try next.append(b.buf.items);
        // finishReplace closes `next` itself on failure, and `l` stays as it was
        ok = true;
        s.log.finishReplace(&next, tmp, s.path) catch |e| return e;
        s.compactions += 1;
    }

    fn apply(s: *Store, payload: []const u8) Error!void {
        var at: usize = 0;
        while (at + 8 <= payload.len) {
            const t = payload[at];
            const kind = payload[at + 1];
            const kl = std.mem.readInt(u16, payload[at + 2 ..][0..2], .little);
            const vl = std.mem.readInt(u32, payload[at + 4 ..][0..4], .little);
            at += 8;
            if (at + kl + vl > payload.len or t >= table_count) return;
            const key = payload[at..][0..kl];
            const val = payload[at + kl ..][0..vl];
            at += kl + vl;
            const m = &s.tables[t];
            switch (kind) {
                op_put => {
                    if (m.getEntry(key)) |e| {
                        const nv = try s.gpa.dupe(u8, val);
                        s.live_bytes = s.live_bytes - e.value_ptr.*.len + val.len;
                        s.gpa.free(e.value_ptr.*);
                        e.value_ptr.* = nv;
                    } else {
                        const nk = try s.gpa.dupe(u8, key);
                        errdefer s.gpa.free(nk);
                        const nv = try s.gpa.dupe(u8, val);
                        errdefer s.gpa.free(nv);
                        try m.put(s.gpa, nk, nv);
                        s.live_bytes += 8 + key.len + val.len;
                    }
                },
                op_del => {
                    if (m.fetchSwapRemove(key)) |kv| {
                        s.live_bytes -= 8 + kv.key.len + kv.value.len;
                        s.gpa.free(kv.key);
                        s.gpa.free(kv.value);
                    }
                },
                else => return,
            }
        }
    }

    /// The value for `key`, valid until the next commit that touches it. Callers on other threads
    /// than the committer must copy under `lock`.
    pub fn get(s: *const Store, t: Table, key: []const u8) ?[]const u8 {
        return s.tables[@intFromEnum(t)].get(key);
    }

    pub fn count(s: *const Store, t: Table) usize {
        return s.tables[@intFromEnum(t)].count();
    }

    /// Entries of a table in insertion order.
    pub fn iterator(s: *const Store, t: Table) Map.Iterator {
        return s.tables[@intFromEnum(t)].iterator();
    }
};

fn tmpPath(tmp: *std.testing.TmpDir, buf: []u8, name: []const u8) ![]const u8 {
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(std.testing.io, &pbuf);
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ pbuf[0..n], name });
}

test "a commit is atomic and survives reopen; a torn tail drops the whole commit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(&tmp, &pb, "epoch.log");
    const io = std.testing.io;
    var s = try Store.open(std.testing.allocator, io, path);
    var b = s.batch();
    defer b.deinit();
    try b.put(.end_of_publish, "\x01\x00\x00\x00", "");
    try b.put(.exec_indices, "last", "\x05\x00\x00\x00");
    try s.commit(&b);
    try b.put(.end_of_publish, "\x02\x00\x00\x00", "");
    try b.del(.end_of_publish, "\x01\x00\x00\x00");
    try s.commit(&b);
    try std.testing.expectEqual(@as(usize, 1), s.count(.end_of_publish));
    // a torn third record: header claims more than is there
    try s.log.file.writePositionalAll(io, &[_]u8{ 0xff, 0, 0, 0, 1, 2, 3 }, s.log.end);
    s.close();
    var s2 = try Store.open(std.testing.allocator, io, path);
    defer s2.close();
    try std.testing.expectEqual(@as(u64, 2), s2.recovered_batches);
    try std.testing.expect(s2.get(.end_of_publish, "\x02\x00\x00\x00") != null);
    try std.testing.expect(s2.get(.end_of_publish, "\x01\x00\x00\x00") == null);
    try std.testing.expectEqualStrings("\x05\x00\x00\x00", s2.get(.exec_indices, "last").?);
}

test "compaction rewrites the log as a snapshot and survives reopen; a stale partial snapshot is ignored" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(&tmp, &pb, "epoch.log");
    const io = std.testing.io;
    var s = try Store.open(std.testing.allocator, io, path);
    s.compact_floor = 4096;
    var b = s.batch();
    defer b.deinit();
    var i: u32 = 0;
    while (i < 400) : (i += 1) {
        try b.put(.exec_indices, "last", std.mem.asBytes(&i));
        try b.put(.processed_keys, "key-a", "x");
        try s.commit(&b);
    }
    try b.del(.processed_keys, "key-a");
    try b.put(.end_of_publish, "\x01\x00\x00\x00", "");
    try s.commit(&b);
    // the exec_indices record was rewritten 400 times: the policy compacted at least once
    try std.testing.expect(s.compactions >= 1);
    try s.compact();
    try std.testing.expect(s.log.end < 200);
    // appends after a compaction land in the new file
    var v: u32 = 7777;
    try b.put(.exec_indices, "last", std.mem.asBytes(&v));
    try s.commit(&b);
    s.close();
    // a leftover partial snapshot from a crashed compaction is deleted at open
    var cb: [std.fs.max_path_bytes + 16]u8 = undefined;
    const cp = try std.fmt.bufPrint(&cb, "{s}.compact", .{path});
    try fsutil.writeAtomic(io, cp, "garbage");
    var s2 = try Store.open(std.testing.allocator, io, path);
    defer s2.close();
    try std.testing.expectEqual(@as(u32, 7777), std.mem.bytesToValue(u32, s2.get(.exec_indices, "last").?));
    try std.testing.expect(s2.get(.processed_keys, "key-a") == null);
    try std.testing.expect(s2.get(.end_of_publish, "\x01\x00\x00\x00") != null);
}
