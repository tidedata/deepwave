//! The durable checkpoints.store.Store (`<db>/validator/checkpoints/checkpoints.log`): built
//! summaries and contents, `last_built`, certified checkpoints, the running state root and
//! recorded forks, the rules of checkpoints/store.zig kept (put_built does not move last_built,
//! highest certified only grows). One checksummed record per write, offset-seeded checksum,
//! fsync before the write returns, torn tail cut at open, state rebuilt at open. Seeded with the
//! genesis checkpoint (certified seq 0, last built, running root after checkpoint 0).
const std = @import("std");
const Io = std.Io;
const store_mod = @import("../checkpoints/store.zig");
const create = @import("../checkpoints/create.zig");
const genesis_mod = @import("genesis.zig");
const Spin = @import("../authority/sync.zig").Spin;
const tdigest = @import("types").digest;

const Allocator = std.mem.Allocator;
const Id = [32]u8;

pub const magic = "ZUICKPT1";
const max_record: usize = 1 << 30;

pub const CkptStore = struct {
    gpa: Allocator,
    io: Io,
    file: ?Io.File = null,
    end: u64 = 0,
    wmu: Io.Mutex = .init,
    lock: Spin = .{},
    built: std.AutoArrayHashMapUnmanaged(u64, Built) = .empty,
    certified: std.AutoArrayHashMapUnmanaged(u64, Certified) = .empty,
    /// State sync lookups (run/state_sync.zig): certified summary digest and built contents
    /// digest to sequence number.
    by_digest: std.AutoHashMapUnmanaged(Id, u64) = .empty,
    by_contents: std.AutoHashMapUnmanaged(Id, u64) = .empty,
    last: ?create.LastBuilt = null,
    highest: ?u64 = null,
    root: ?store_mod.RunningRootRecord = null,
    forks: u32 = 0,
    /// The last write that failed (record_fork cannot return an error).
    write_errors: u32 = 0,

    const Built = struct { digest: Id, height: u64, summary: []u8, contents: []u8 };
    const Certified = struct { digest: Id, bytes: []u8 };

    pub fn open(gpa: Allocator, io: Io, db: []const u8) !CkptStore {
        var s: CkptStore = .{ .gpa = gpa, .io = io };
        errdefer s.freeAll();
        const dir = try std.fs.path.join(gpa, &.{ db, "validator", "checkpoints" });
        defer gpa.free(dir);
        const path = try std.fs.path.join(gpa, &.{ dir, "checkpoints.log" });
        defer gpa.free(path);
        const cwd = Io.Dir.cwd();
        try cwd.createDirPath(io, dir);
        const data = cwd.readFileAlloc(io, path, gpa, .unlimited) catch |e| switch (e) {
            error.FileNotFound => try gpa.dupe(u8, ""),
            else => return e,
        };
        defer gpa.free(data);
        const f = try cwd.createFile(io, path, .{ .read = true, .truncate = false });
        errdefer f.close(io);
        s.file = f;
        if (data.len < magic.len or !std.mem.eql(u8, data[0..magic.len], magic)) {
            if (data.len != 0) return error.Corrupt;
            try f.writePositionalAll(io, magic, 0);
            try f.sync(io);
            s.end = magic.len;
            return s;
        }
        var at: usize = magic.len;
        while (at + 8 <= data.len) {
            const len = std.mem.readInt(u32, data[at..][0..4], .little);
            if (len > max_record or at + 8 + len > data.len) break;
            const want = std.mem.readInt(u32, data[at + 4 ..][0..4], .little);
            const payload = data[at + 8 ..][0..len];
            if (checksum(at, len, payload) != want) break;
            s.apply(payload) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => break,
            };
            at += 8 + len;
        }
        if (at != data.len) {
            std.log.warn("checkpoint store: {s}: torn or corrupt tail at byte {d} of {d}; cut", .{ path, at, data.len });
            try f.setLength(io, at);
            try f.sync(io);
        }
        s.end = at;
        return s;
    }

    pub fn openMem(gpa: Allocator, io: Io) CkptStore {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn close(s: *CkptStore) void {
        if (s.file) |f| f.close(s.io);
        s.file = null;
        s.freeAll();
    }

    fn freeAll(s: *CkptStore) void {
        for (s.built.values()) |b| {
            s.gpa.free(b.summary);
            s.gpa.free(b.contents);
        }
        s.built.deinit(s.gpa);
        for (s.certified.values()) |c| s.gpa.free(c.bytes);
        s.certified.deinit(s.gpa);
        s.by_digest.deinit(s.gpa);
        s.by_contents.deinit(s.gpa);
    }

    /// Certified checkpoint 0, last built = genesis, running root after checkpoint 0
    /// (idempotent: a store with any certified checkpoint is left as it is).
    pub fn seedGenesis(s: *CkptStore, g: *const genesis_mod.Genesis) store_mod.Error!void {
        if (highestCertified(s) != null) return;
        try putCertified(s, 0, g.chain_id, g.certified_bcs);
        try setLastBuilt(s, g.lastBuilt());
        try putRunningRoot(s, .{ .root = g.running_root, .seq = 0 });
    }

    pub fn store(s: *CkptStore) store_mod.Store {
        return .{ .ctx = s, .vtable = &vtable };
    }

    const vtable: store_mod.Store.VTable = .{
        .last_built = lastBuiltFn,
        .locally_computed_digest = locallyComputed,
        .put_built = putBuiltFn,
        .set_last_built = setLastBuiltFn,
        .built_summary = builtSummary,
        .built_contents = builtContents,
        .highest_certified = highestCertifiedFn,
        .certified_digest = certifiedDigest,
        .put_certified = putCertifiedFn,
        .running_root = runningRoot,
        .put_running_root = putRunningRootFn,
        .record_fork = recordFork,
    };

    fn self(ctx: *anyopaque) *CkptStore {
        return @ptrCast(@alignCast(ctx));
    }

    // ---- writes: a record, then the state (both under the write mutex)

    fn write(s: *CkptStore, payload: []const u8) store_mod.Error!void {
        s.wmu.lockUncancelable(s.io);
        defer s.wmu.unlock(s.io);
        if (s.file) |f| {
            const rec = try s.gpa.alloc(u8, 8 + payload.len);
            defer s.gpa.free(rec);
            const len: u32 = @intCast(payload.len);
            std.mem.writeInt(u32, rec[0..4], len, .little);
            std.mem.writeInt(u32, rec[4..8], checksum(s.end, len, payload), .little);
            @memcpy(rec[8..], payload);
            f.writePositionalAll(s.io, rec, s.end) catch return error.Io;
            f.sync(s.io) catch return error.Io;
            s.end += rec.len;
        }
        s.apply(payload) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Io,
        };
    }

    const tag_built: u8 = 1;
    const tag_last: u8 = 2;
    const tag_cert: u8 = 3;
    const tag_root: u8 = 4;
    const tag_fork: u8 = 5;

    fn apply(s: *CkptStore, payload: []const u8) (Allocator.Error || error{Corrupt})!void {
        var r: Rd = .{ .b = payload };
        const tag = try r.byte();
        switch (tag) {
            tag_built => {
                const seq = try r.int(u64);
                const height = try r.int(u64);
                const last = try readLast(&r);
                const summary = try s.gpa.dupe(u8, try r.slice());
                errdefer s.gpa.free(summary);
                const contents = try s.gpa.dupe(u8, try r.slice());
                errdefer s.gpa.free(contents);
                const cd = tdigest.checkpointContentsDigest(contents);
                s.lock.lock();
                defer s.lock.unlock();
                try s.by_contents.ensureUnusedCapacity(s.gpa, 1);
                try s.built.ensureUnusedCapacity(s.gpa, 1);
                s.by_contents.putAssumeCapacity(cd, seq);
                const gop = try s.built.getOrPut(s.gpa, seq);
                if (gop.found_existing) {
                    s.gpa.free(gop.value_ptr.summary);
                    s.gpa.free(gop.value_ptr.contents);
                }
                gop.value_ptr.* = .{ .digest = last.digest, .height = height, .summary = summary, .contents = contents };
            },
            tag_last => {
                const last = try readLast(&r);
                s.lock.lock();
                defer s.lock.unlock();
                s.last = last;
            },
            tag_cert => {
                const seq = try r.int(u64);
                const digest = (try r.take(32))[0..32].*;
                const bytes = try s.gpa.dupe(u8, try r.slice());
                errdefer s.gpa.free(bytes);
                s.lock.lock();
                defer s.lock.unlock();
                try s.by_digest.put(s.gpa, digest, seq);
                const gop = try s.certified.getOrPut(s.gpa, seq);
                if (gop.found_existing) s.gpa.free(gop.value_ptr.bytes);
                gop.value_ptr.* = .{ .digest = digest, .bytes = bytes };
                if (s.highest == null or seq > s.highest.?) s.highest = seq;
            },
            tag_root => {
                const root = (try r.take(32))[0..32].*;
                const seq = try r.int(u64);
                s.lock.lock();
                defer s.lock.unlock();
                s.root = .{ .root = root, .seq = seq };
            },
            tag_fork => {
                s.lock.lock();
                defer s.lock.unlock();
                s.forks += 1;
            },
            else => return error.Corrupt,
        }
    }

    // ---- the Store vtable

    fn lastBuiltFn(ctx: *anyopaque) ?create.LastBuilt {
        const s = self(ctx);
        s.lock.lock();
        defer s.lock.unlock();
        return s.last;
    }
    fn locallyComputed(ctx: *anyopaque, seq: u64) ?[32]u8 {
        const s = self(ctx);
        s.lock.lock();
        defer s.lock.unlock();
        return if (s.built.get(seq)) |b| b.digest else null;
    }
    fn putBuiltFn(ctx: *anyopaque, seq: u64, height: u64, last: create.LastBuilt, summary_bcs: []const u8, contents_bcs: []const u8) store_mod.Error!void {
        const s = self(ctx);
        var w: std.ArrayList(u8) = .empty;
        defer w.deinit(s.gpa);
        try w.append(s.gpa, tag_built);
        try putInt(s.gpa, &w, seq);
        try putInt(s.gpa, &w, height);
        try putLast(s.gpa, &w, &last);
        try putSlice(s.gpa, &w, summary_bcs);
        try putSlice(s.gpa, &w, contents_bcs);
        return s.write(w.items);
    }
    pub fn setLastBuilt(s: *CkptStore, last: create.LastBuilt) store_mod.Error!void {
        var w: std.ArrayList(u8) = .empty;
        defer w.deinit(s.gpa);
        try w.append(s.gpa, tag_last);
        try putLast(s.gpa, &w, &last);
        return s.write(w.items);
    }
    fn setLastBuiltFn(ctx: *anyopaque, last: create.LastBuilt) store_mod.Error!void {
        return self(ctx).setLastBuilt(last);
    }
    fn builtSummary(ctx: *anyopaque, arena: Allocator, seq: u64) store_mod.Error!?[]const u8 {
        const s = self(ctx);
        s.lock.lock();
        defer s.lock.unlock();
        const b = s.built.get(seq) orelse return null;
        return try arena.dupe(u8, b.summary);
    }
    fn builtContents(ctx: *anyopaque, arena: Allocator, seq: u64) store_mod.Error!?[]const u8 {
        const s = self(ctx);
        s.lock.lock();
        defer s.lock.unlock();
        const b = s.built.get(seq) orelse return null;
        return try arena.dupe(u8, b.contents);
    }
    pub fn highestCertified(s: *CkptStore) ?u64 {
        s.lock.lock();
        defer s.lock.unlock();
        return s.highest;
    }
    fn highestCertifiedFn(ctx: *anyopaque) ?u64 {
        return self(ctx).highestCertified();
    }
    fn certifiedDigest(ctx: *anyopaque, seq: u64) ?[32]u8 {
        const s = self(ctx);
        s.lock.lock();
        defer s.lock.unlock();
        return if (s.certified.get(seq)) |c| c.digest else null;
    }
    pub fn putCertified(s: *CkptStore, seq: u64, digest: [32]u8, bytes: []const u8) store_mod.Error!void {
        var w: std.ArrayList(u8) = .empty;
        defer w.deinit(s.gpa);
        try w.append(s.gpa, tag_cert);
        try putInt(s.gpa, &w, seq);
        try w.appendSlice(s.gpa, &digest);
        try putSlice(s.gpa, &w, bytes);
        return s.write(w.items);
    }
    fn putCertifiedFn(ctx: *anyopaque, seq: u64, digest: [32]u8, bytes: []const u8) store_mod.Error!void {
        return self(ctx).putCertified(seq, digest, bytes);
    }
    /// The certified summary bytes stored for `seq` (borrowed until close).
    pub fn certifiedBytes(s: *CkptStore, seq: u64) ?[]const u8 {
        s.lock.lock();
        defer s.lock.unlock();
        return if (s.certified.get(seq)) |c| c.bytes else null;
    }
    /// The certified checkpoint with this summary digest.
    pub fn seqByDigest(s: *CkptStore, digest: *const Id) ?u64 {
        s.lock.lock();
        defer s.lock.unlock();
        return s.by_digest.get(digest.*);
    }
    /// The built checkpoint whose contents have this digest.
    pub fn seqByContents(s: *CkptStore, digest: *const Id) ?u64 {
        s.lock.lock();
        defer s.lock.unlock();
        return s.by_contents.get(digest.*);
    }
    /// A copy of the certified summary bytes of `seq`.
    pub fn certifiedCopy(s: *CkptStore, arena: Allocator, seq: u64) Allocator.Error!?[]u8 {
        s.lock.lock();
        defer s.lock.unlock();
        const c = s.certified.get(seq) orelse return null;
        return try arena.dupe(u8, c.bytes);
    }
    fn runningRoot(ctx: *anyopaque) ?store_mod.RunningRootRecord {
        const s = self(ctx);
        s.lock.lock();
        defer s.lock.unlock();
        return s.root;
    }
    pub fn putRunningRoot(s: *CkptStore, rec: store_mod.RunningRootRecord) store_mod.Error!void {
        var w: [1 + 32 + 8]u8 = undefined;
        w[0] = tag_root;
        w[1..33].* = rec.root;
        std.mem.writeInt(u64, w[33..41], rec.seq, .little);
        return s.write(&w);
    }
    fn putRunningRootFn(ctx: *anyopaque, rec: store_mod.RunningRootRecord) store_mod.Error!void {
        return self(ctx).putRunningRoot(rec);
    }
    fn recordFork(ctx: *anyopaque, seq: u64, local: [32]u8, cert: ?[32]u8) void {
        const s = self(ctx);
        var w: [1 + 8 + 32 + 33]u8 = @splat(0);
        w[0] = tag_fork;
        std.mem.writeInt(u64, w[1..9], seq, .little);
        w[9..41].* = local;
        if (cert) |c| {
            w[41] = 1;
            w[42..74].* = c;
        }
        std.log.warn("checkpoint fork at {d} recorded", .{seq});
        s.write(&w) catch {
            s.write_errors += 1;
        };
    }
};

fn checksum(offset: u64, len: u32, payload: []const u8) u32 {
    var c = std.hash.Crc32.init();
    var b: [12]u8 = undefined;
    std.mem.writeInt(u64, b[0..8], offset, .little);
    std.mem.writeInt(u32, b[8..12], len, .little);
    c.update(&b);
    c.update(payload);
    return c.final();
}

fn putInt(gpa: Allocator, w: *std.ArrayList(u8), v: u64) Allocator.Error!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    try w.appendSlice(gpa, &b);
}
fn putSlice(gpa: Allocator, w: *std.ArrayList(u8), s: []const u8) Allocator.Error!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, @intCast(s.len), .little);
    try w.appendSlice(gpa, &b);
    try w.appendSlice(gpa, s);
}
fn putLast(gpa: Allocator, w: *std.ArrayList(u8), l: *const create.LastBuilt) Allocator.Error!void {
    for ([_]u64{ l.seq, l.epoch, l.timestamp_ms, l.network_total_transactions, l.rolling_gas.computation_cost, l.rolling_gas.storage_cost, l.rolling_gas.storage_rebate, l.rolling_gas.non_refundable_storage_fee }) |v| try putInt(gpa, w, v);
    try w.appendSlice(gpa, &l.digest);
    if (l.height) |h| {
        try w.append(gpa, 1);
        try putInt(gpa, w, h);
    } else try w.append(gpa, 0);
}
fn readLast(r: *Rd) error{Corrupt}!create.LastBuilt {
    var l: create.LastBuilt = undefined;
    l.seq = try r.int(u64);
    l.epoch = try r.int(u64);
    l.timestamp_ms = try r.int(u64);
    l.network_total_transactions = try r.int(u64);
    l.rolling_gas = .{
        .computation_cost = try r.int(u64),
        .storage_cost = try r.int(u64),
        .storage_rebate = try r.int(u64),
        .non_refundable_storage_fee = try r.int(u64),
    };
    l.digest = (try r.take(32))[0..32].*;
    l.height = switch (try r.byte()) {
        0 => null,
        1 => try r.int(u64),
        else => return error.Corrupt,
    };
    return l;
}

const Rd = struct {
    b: []const u8,
    at: usize = 0,
    fn take(r: *Rd, n: usize) error{Corrupt}![]const u8 {
        if (r.at + n > r.b.len) return error.Corrupt;
        defer r.at += n;
        return r.b[r.at..][0..n];
    }
    fn byte(r: *Rd) error{Corrupt}!u8 {
        return (try r.take(1))[0];
    }
    fn int(r: *Rd, comptime T: type) error{Corrupt}!T {
        return std.mem.readInt(T, (try r.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }
    fn slice(r: *Rd) error{Corrupt}![]const u8 {
        const n = try r.int(u32);
        return r.take(n);
    }
};

test "ckpt store: durable across reopen, last built moves only on set" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const db = pb[0..try tmp.dir.realPath(io, &pb)];
    const last: create.LastBuilt = .{ .seq = 3, .epoch = 1, .timestamp_ms = 5, .network_total_transactions = 9, .rolling_gas = .{ .computation_cost = 7 }, .digest = @splat(4), .height = 11 };
    {
        var s = try CkptStore.open(gpa, io, db);
        defer s.close();
        const st = s.store();
        try st.putBuilt(3, 11, last, "abc", "def");
        try std.testing.expectEqual(@as(?create.LastBuilt, null), st.lastBuilt());
        try st.setLastBuilt(last);
        try st.putCertified(2, @splat(8), "cert2");
        try st.putRunningRoot(.{ .root = @splat(6), .seq = 3 });
        st.recordFork(4, @splat(1), null);
    }
    var s = try CkptStore.open(gpa, io, db);
    defer s.close();
    const st = s.store();
    try std.testing.expectEqual(last, st.lastBuilt().?);
    try std.testing.expectEqual(@as(u8, 4), st.locallyComputedDigest(3).?[0]);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    try std.testing.expectEqualStrings("def", (try st.builtContents(arena.allocator(), 3)).?);
    try std.testing.expectEqual(@as(u64, 3), st.nextToCertify());
    try std.testing.expectEqual(@as(u8, 8), st.certifiedDigest(2).?[0]);
    try std.testing.expectEqual(@as(u64, 3), st.runningRoot().?.seq);
    try std.testing.expectEqual(@as(u32, 1), s.forks);
}
