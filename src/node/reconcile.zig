//! Read-set reconcile of checkpoints the node built itself (p2p_exec.zig).
//!
//! A p2p-built checkpoint's loaded runtime object lists and read-only objects come from deepwave's
//! own execution; nothing certified covers them (`unchanged_loaded_runtime_objects` is not in
//! the effects). sui-node's copy of the same checkpoint still arrives a moment later, on the
//! live stream (a duplicate there) and in the bucket. This compares that copy with what the
//! store holds and, where they differ, makes the store serve sui-node's version.
//!
//! Which checkpoints. history.zig writes a marker record into a p2p-built checkpoint's own
//! commit group (`history.p2pBuilt`), so the store itself says which checkpoints were built
//! here, across restarts, and a checkpoint from the stream or the bucket is never looked at.
//! The log below holds a watermark: every checkpoint up to it is settled. After a restart the
//! markers above the watermark are the checkpoints still to reconcile.
//!
//! The authority's copy. The stream hands over its duplicate of a checkpoint that is waiting
//! here or not applied yet (`wantsCopy`, `offer`); a copy for a checkpoint that then arrives
//! from another source than p2p is dropped at apply. A waiting checkpoint with no copy after
//! `wait_ms` is fetched from the bucket once it is published there.
//!
//! The compare (`compare`, on this module's thread, off the commit path): each transaction's
//! stored list against the copy's, entry by entry in order, and every object of the copy's
//! object set against the store by (id, version).
//!
//! The repair. A list that differs is replaced in the store's loaded-list table
//! (`Store.list_fix`, the read every reader shares: GetCheckpoint, GetTransaction,
//! BatchGetTransactions, the List methods; the GetCheckpoint response cache drops its entry
//! through the table's generation). One log record holds all of a checkpoint's lists: it is
//! written and synced before the lists are installed, and reinstalled from the log at start, so
//! after a crash a checkpoint is either unrepaired and still waiting, or repaired and settled. An
//! object the store lacks goes into the next checkpoint's commit group (`applied`) as a
//! historical record, like the bucket path's read-only objects, and the lists are only replaced
//! once that group is committed.
//!
//! `node/p2p-reconcile.log`: magic, then records `crc32 (of the rest) u32, kind u8, pad 3,
//! len u32, seq u64, len bytes`. Kind 1, a repair of checkpoint `seq`: `count u32`, then per
//! transaction `digest [32], entries u32, entries * (version u64 le, id [32])`. Kind 2: every
//! p2p-built checkpoint up to `seq` is settled. A torn tail is cut.
const std = @import("std");
const Io = std.Io;
const store = @import("store");
const sync = @import("sync");
const exec = @import("exec");
const serve = @import("serve");
const convert = @import("convert.zig");
const history = @import("history.zig");
const source = @import("source.zig");
const Atomic = std.atomic.Value;

pub const log_name = "p2p-reconcile.log";
const log_magic = "ZUIP2PR1";
const rec_head = 20;
const kind_repair: u8 = 1;
const kind_mark: u8 = 2;

pub const Stats = struct {
    /// Transactions whose stored list was replaced with sui-node's (`zui_p2p_readset_repairs`).
    repairs: Atomic(u64) = .init(0),
    /// Checkpoints compared, and those that differed.
    reconciled: Atomic(u64) = .init(0),
    repaired_checkpoints: Atomic(u64) = .init(0),
    /// Objects of sui-node's object set the store lacked, written as historical records.
    objects_added: Atomic(u64) = .init(0),
    /// Copies taken from the stream's duplicates, and fetched from the bucket.
    from_stream: Atomic(u64) = .init(0),
    from_bucket: Atomic(u64) = .init(0),
    /// Bucket fetches that found nothing yet or failed (retried).
    bucket_waits: Atomic(u64) = .init(0),
    /// Copies that did not parse or did not fit the stored checkpoint (dropped; the bucket's is
    /// fetched instead).
    bad_copies: Atomic(u64) = .init(0),
    /// Lists reinstalled from the log at start.
    loaded: Atomic(u64) = .init(0),
    /// Checkpoints waiting (a gauge).
    pending: Atomic(u64) = .init(0),
};

pub const Config = struct {
    /// How long a p2p-built checkpoint waits for the stream's duplicate before the bucket is asked.
    wait_ms: u64 = 10_000,
    /// Copies held for checkpoints not compared yet, in bytes (a copy beyond it is not taken;
    /// the bucket serves that checkpoint later).
    max_held_bytes: usize = 256 << 20,
    /// A watermark record at least this often (settled checkpoints).
    mark_every: u64 = 256,
    /// First wait after a bucket fetch that found nothing (doubled up to 30 s).
    retry_ms: u64 = 500,
    tick_ms: u64 = 100,
};

pub const From = enum { stream, bucket };

/// One transaction's list to install: `list` in the stored layout (`history.entry_len` a entry).
pub const Fix = struct { digest: [32]u8, list: []const u8 };

/// What `compare` found for one checkpoint (in its arena).
pub const Plan = struct {
    seq: u64,
    from: From,
    fixes: []const Fix = &.{},
    /// Objects of the copy's object set the store does not hold (raw BCS `Object`).
    objects: []const []const u8 = &.{},
    /// The checkpoint is no longer in the store (pruned): nothing to do.
    gone: bool = false,
};

const Waiting = struct {
    since_ms: u64,
    /// The authority's aux record, once one arrived.
    copy: ?[]u8 = null,
    from: From = .stream,
    /// Next bucket fetch (after a miss).
    retry_ms: u64 = 0,
    backoff_ms: u64 = 0,
    /// A repair whose objects wait for (`batch` 0) or sit in the commit group of checkpoint `batch`.
    staged: ?*Staged = null,
};

const Staged = struct {
    arena: std.heap.ArenaAllocator,
    plan: Plan,
    batch: u64 = 0,
};

pub const Reconciler = struct {
    gpa: std.mem.Allocator,
    io: Io,
    st: *store.Store,
    file: Io.File,
    end: u64,
    /// The bucket (or directory) source for checkpoints the stream never duplicated; null: none.
    bucket: ?*const source.Source = null,
    cfg: Config = .{},
    stats: Stats = .{},
    lock: Io.Mutex = .init,
    /// p2p-built checkpoints not settled yet, by sequence number.
    waiting: std.AutoArrayHashMapUnmanaged(u64, Waiting) = .empty,
    /// Copies for checkpoints not applied yet (their source is not known before that).
    early: std.AutoArrayHashMapUnmanaged(u64, []u8) = .empty,
    held_bytes: usize = 0,
    /// The next checkpoint the follower applies (everything below was seen by `applied`).
    applied_next: Atomic(u64) = .init(0),
    /// Every p2p-built checkpoint below is settled; the last value written to the log.
    settled_below: u64 = 0,
    marked_below: u64 = 0,
    stopping: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    scratch: source.Scratch,
    last_floor_ms: u64 = 0,

    /// Opens (or creates) `dir/p2p-reconcile.log`, reinstalls its repairs into the store's
    /// loaded-list table and collects the p2p-built checkpoints above its watermark that have no
    /// repair record: those are compared again.
    pub fn open(gpa: std.mem.Allocator, io: Io, st: *store.Store, dir: Io.Dir, bucket: ?*const source.Source, cfg: Config) !*Reconciler {
        const data = dir.readFileAlloc(io, log_name, gpa, .unlimited) catch |e| switch (e) {
            error.FileNotFound => try gpa.dupe(u8, ""),
            else => return e,
        };
        defer gpa.free(data);
        const f = try dir.createFile(io, log_name, .{ .read = true, .truncate = false });
        errdefer f.close(io);
        const r = try gpa.create(Reconciler);
        errdefer gpa.destroy(r);
        r.* = .{ .gpa = gpa, .io = io, .st = st, .file = f, .end = 0, .bucket = bucket, .cfg = cfg, .scratch = .init(gpa) };
        errdefer r.freeState();
        var snap = st.snapshot();
        defer snap.release();
        const top = snap.highestCommitted();
        r.applied_next.store(if (top) |t| t + 1 else 0, .release);
        // Without a watermark (a new log, or a lost one) every marked checkpoint the store still
        // holds waits.
        var mark: u64 = 0;
        const fresh = data.len < log_magic.len or !std.mem.eql(u8, data[0..log_magic.len], log_magic);
        if (fresh) {
            try f.setLength(io, 0);
            try f.writePositionalAll(io, log_magic, 0);
            try f.sync(io);
        }
        var repaired: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer repaired.deinit(gpa);
        var entries: std.ArrayList(store.txfix.Entry) = .empty;
        defer entries.deinit(gpa);
        var at: usize = log_magic.len;
        while (!fresh and data.len - at >= rec_head) {
            const rec_all = data[at..];
            const len = std.mem.readInt(u32, rec_all[8..12], .little);
            if (len > rec_all.len - rec_head) break;
            const rec = rec_all[0 .. rec_head + len];
            if (std.hash.Crc32.hash(rec[4..]) != std.mem.readInt(u32, rec[0..4], .little)) break;
            const seq = std.mem.readInt(u64, rec[12..20], .little);
            switch (rec[4]) {
                kind_repair => {
                    const before = entries.items.len;
                    if (!try decodeRepair(gpa, &entries, seq, rec[rec_head..])) {
                        entries.shrinkRetainingCapacity(before);
                        break;
                    }
                    try repaired.put(gpa, seq, {});
                },
                kind_mark => mark = seq,
                else => break,
            }
            at += rec.len;
        }
        if (!fresh and at != data.len) {
            std.log.warn("p2p reconcile log: torn or corrupt tail at byte {d} of {d}; cut", .{ at, data.len });
            try f.setLength(io, at);
            try f.sync(io);
        }
        r.end = at;
        // Only lists of transactions the store still holds in that checkpoint are installed.
        var n: usize = 0;
        for (entries.items) |e| {
            const t = snap.transaction(&e.digest) orelse continue;
            if (t.checkpoint != e.seq) continue;
            entries.items[n] = e;
            n += 1;
        }
        _ = r.stats.loaded.fetchAdd(try st.list_fix.load(entries.items[0..n]), .monotonic);
        // A watermark above the store's tip is another store's (the same dir, a new store).
        const next = r.applied_next.load(.acquire);
        r.settled_below = @min(mark, next);
        r.marked_below = r.settled_below;
        const now = source.wallMs();
        var seq = @max(r.settled_below, snap.lowestCheckpoint() orelse next);
        while (seq < next) : (seq += 1) {
            if (repaired.contains(seq) or !history.p2pBuilt(&snap, seq)) continue;
            try r.waiting.put(gpa, seq, .{ .since_ms = now });
        }
        r.stats.pending.store(r.waiting.count(), .monotonic);
        return r;
    }

    fn decodeRepair(gpa: std.mem.Allocator, out: *std.ArrayList(store.txfix.Entry), seq: u64, payload: []const u8) !bool {
        if (payload.len < 4) return false;
        const count = std.mem.readInt(u32, payload[0..4], .little);
        var at: usize = 4;
        for (0..count) |_| {
            if (payload.len - at < 36) return false;
            const n = std.mem.readInt(u32, payload[at + 32 ..][0..4], .little);
            const bytes = @as(usize, n) * history.entry_len;
            if (payload.len - at - 36 < bytes) return false;
            try out.append(gpa, .{ .seq = seq, .digest = payload[at..][0..32].*, .tx = payload[at + 36 ..][0..bytes] });
            at += 36 + bytes;
        }
        return at == payload.len;
    }

    fn appendRec(r: *Reconciler, kind: u8, seq: u64, payload: []const u8, flush: bool) !void {
        var head: [rec_head]u8 = @splat(0);
        head[4] = kind;
        std.mem.writeInt(u32, head[8..12], @intCast(payload.len), .little);
        std.mem.writeInt(u64, head[12..20], seq, .little);
        var crc = std.hash.Crc32.init();
        crc.update(head[4..]);
        crc.update(payload);
        std.mem.writeInt(u32, head[0..4], crc.final(), .little);
        // One write: a record is whole or its checksum fails (cut at open).
        const buf = try r.gpa.alloc(u8, rec_head + payload.len);
        defer r.gpa.free(buf);
        @memcpy(buf[0..rec_head], &head);
        @memcpy(buf[rec_head..], payload);
        try r.file.writePositionalAll(r.io, buf, r.end);
        r.end += buf.len;
        if (flush) try r.file.sync(r.io);
    }

    fn writeMark(r: *Reconciler) !void {
        try r.appendRec(kind_mark, r.settled_below, &.{}, false);
        r.marked_below = r.settled_below;
    }

    fn freeState(r: *Reconciler) void {
        for (r.waiting.values()) |*w| {
            if (w.copy) |c| r.gpa.free(c);
            if (w.staged) |s| {
                s.arena.deinit();
                r.gpa.destroy(s);
            }
        }
        r.waiting.deinit(r.gpa);
        for (r.early.values()) |c| r.gpa.free(c);
        r.early.deinit(r.gpa);
        r.scratch.deinit(r.gpa);
    }

    /// Stops the thread (if started), writes the watermark and closes the log.
    pub fn deinit(r: *Reconciler) void {
        r.stop();
        if (r.settled_below != r.marked_below) r.writeMark() catch {};
        r.file.sync(r.io) catch {};
        r.file.close(r.io);
        r.freeState();
        r.gpa.destroy(r);
    }

    pub fn start(r: *Reconciler) !void {
        r.thread = try std.Thread.spawn(.{}, loop, .{r});
    }

    /// No new work (a fetch in flight ends with the source's own stop).
    pub fn quit(r: *Reconciler) void {
        r.stopping.store(true, .release);
    }

    pub fn stop(r: *Reconciler) void {
        r.stopping.store(true, .release);
        if (r.thread) |t| {
            t.join();
            r.thread = null;
        }
    }

    fn loop(r: *Reconciler) void {
        while (!r.stopping.load(.acquire)) {
            const progress = r.step() catch |e| blk: {
                std.log.warn("p2p reconcile: {s}; retrying", .{@errorName(e)});
                break :blk false;
            };
            if (!progress) r.io.sleep(.fromMilliseconds(@intCast(r.cfg.tick_ms)), .awake) catch {};
        }
    }

    // ------------------------------------------------------------------ the stream's side

    /// Whether the stream's duplicate of `seq` is of use: `seq` waits here without a copy, or is
    /// not applied yet (p2p may be building it) and none is held.
    pub fn wantsCopy(r: *Reconciler, seq: u64) bool {
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        if (r.held_bytes >= r.cfg.max_held_bytes) return false;
        if (r.waiting.getPtr(seq)) |w| return w.copy == null and w.staged == null;
        return seq >= r.applied_next.load(.acquire) and !r.early.contains(seq);
    }

    /// The authority's aux record of `seq` (`convert.Aux` bytes; copied).
    pub fn offer(r: *Reconciler, seq: u64, aux: []const u8, from: From) void {
        const copy = r.gpa.dupe(u8, aux) catch return;
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        if (r.waiting.getPtr(seq)) |w| {
            if (w.copy != null or w.staged != null) return r.gpa.free(copy);
            w.copy = copy;
            w.from = from;
        } else {
            if (seq < r.applied_next.load(.acquire) or r.early.contains(seq)) return r.gpa.free(copy);
            r.early.put(r.gpa, seq, copy) catch return r.gpa.free(copy);
        }
        r.held_bytes += copy.len;
        _ = (if (from == .stream) &r.stats.from_stream else &r.stats.from_bucket).fetchAdd(1, .monotonic);
    }

    // ------------------------------------------------------------------ the follower's side

    /// The follower's batch hook, after history.zig's: checkpoint `seq` is about to commit;
    /// `built`: it was built here (history wrote its marker into `b`). Objects a repair waits
    /// for join this commit group.
    pub fn applied(r: *Reconciler, seq: u64, built: bool, b: *store.Batch) !void {
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        r.applied_next.store(seq + 1, .release);
        // Copies taken before the checkpoint's source was known.
        var i: usize = 0;
        while (i < r.early.count()) {
            const s = r.early.keys()[i];
            if (s > seq) {
                i += 1;
                continue;
            }
            const copy = r.early.values()[i];
            r.early.swapRemoveAt(i);
            if (s == seq and built) {
                try r.waiting.put(r.gpa, seq, .{ .since_ms = source.wallMs(), .copy = copy });
            } else {
                r.held_bytes -= copy.len;
                r.gpa.free(copy);
            }
        }
        if (built and !r.waiting.contains(seq)) try r.waiting.put(r.gpa, seq, .{ .since_ms = source.wallMs() });
        r.stats.pending.store(r.waiting.count(), .monotonic);
        for (r.waiting.values()) |*w| {
            const s = w.staged orelse continue;
            if (s.batch != 0) continue;
            for (s.plan.objects) |raw| {
                const k = exec.objects.keyOf(raw) catch continue;
                try b.putHistorical(&k.id, k.version, &sync.verify.objectDigest(raw), raw);
            }
            s.batch = seq;
        }
    }

    // ------------------------------------------------------------------ compare and repair

    /// The stored lists and objects of checkpoint `seq` against the authority's aux record.
    /// Everything in `arena`. `error.BadCopy`: the record does not parse or fit the checkpoint.
    pub fn compare(r: *Reconciler, arena: std.mem.Allocator, seq: u64, aux_bytes: []const u8, from: From) !Plan {
        var snap = r.st.snapshot();
        defer snap.release();
        const cp = snap.checkpoint(seq) orelse return .{ .seq = seq, .from = from, .gone = true };
        const aux = convert.Aux.parse(arena, aux_bytes) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.BadCopy;
        const pairs = sync.wire.contentsDigests(arena, cp.contents) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.BadCopy;
        if (pairs.len != aux.loaded.len) return error.BadCopy;
        var fixes: std.ArrayList(Fix) = .empty;
        for (pairs, aux.loaded) |pair, want| {
            const have = history.loadedList(history.LoadedEntry, &snap, pair.tx);
            var same = have.len == want.len;
            if (same) for (have, want) |h, w| {
                if (h.version != w.version or !std.mem.eql(u8, &h.id, &w.id)) {
                    same = false;
                    break;
                }
            };
            if (same) continue;
            const list = try arena.alloc(u8, want.len * history.entry_len);
            for (want, 0..) |w, j| {
                std.mem.writeInt(u64, list[j * history.entry_len ..][0..8], w.version, .little);
                list[j * history.entry_len + 8 ..][0..32].* = w.id;
            }
            try fixes.append(arena, .{ .digest = pair.tx.*, .list = list });
        }
        var objects: std.ArrayList([]const u8) = .empty;
        for (aux.objects) |raw| {
            const k = exec.objects.keyOf(raw) catch return error.BadCopy;
            if (k.version > std.math.maxInt(i64)) return error.BadCopy;
            if (snap.objectAt(&k.id, k.version) == null) try objects.append(arena, raw);
        }
        return .{ .seq = seq, .from = from, .fixes = fixes.items, .objects = objects.items };
    }

    /// Makes the store serve the plan's lists: the log record first (synced), then the table.
    /// The plan's objects must be committed already (`applied`). One log line per transaction.
    pub fn commit(r: *Reconciler, plan: *const Plan) !void {
        if (plan.fixes.len == 0) return;
        var arena_state: std.heap.ArenaAllocator = .init(r.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        // What the lists replace, for the log line (read before they are installed).
        const lines = try arena.alloc([]const u8, plan.fixes.len);
        {
            var snap = r.st.snapshot();
            defer snap.release();
            for (plan.fixes, lines) |*f, *line| line.* = try describe(arena, plan, f, history.loadedList(history.LoadedEntry, &snap, &f.digest));
        }
        var payload: std.ArrayList(u8) = .empty;
        var n4: [4]u8 = undefined;
        std.mem.writeInt(u32, &n4, @intCast(plan.fixes.len), .little);
        try payload.appendSlice(arena, &n4);
        const entries = try arena.alloc(store.txfix.Entry, plan.fixes.len);
        for (plan.fixes, entries) |*f, *e| {
            try payload.appendSlice(arena, &f.digest);
            std.mem.writeInt(u32, &n4, @intCast(f.list.len / history.entry_len), .little);
            try payload.appendSlice(arena, &n4);
            try payload.appendSlice(arena, f.list);
            e.* = .{ .seq = plan.seq, .digest = f.digest, .tx = f.list };
        }
        try r.appendRec(kind_repair, plan.seq, payload.items, true);
        _ = try r.st.list_fix.putMany(entries);
        _ = r.stats.repairs.fetchAdd(plan.fixes.len, .monotonic);
        _ = r.stats.repaired_checkpoints.fetchAdd(1, .monotonic);
        for (lines) |line| std.log.warn("{s}", .{line});
    }

    /// "p2p reconcile: checkpoint N transaction D: ...": how the stored list differs.
    fn describe(arena: std.mem.Allocator, plan: *const Plan, f: *const Fix, have: []const history.LoadedEntry) ![]const u8 {
        var w: std.Io.Writer.Allocating = .init(arena);
        var tb: [44]u8 = undefined;
        const out = &w.writer;
        out.print("p2p reconcile: checkpoint {d} transaction {s}: stored loaded runtime objects differ from sui-node's ({s} copy), replaced:", .{ plan.seq, serve.b58.encode32(&tb, &f.digest), @tagName(plan.from) }) catch return error.OutOfMemory;
        const n = f.list.len / history.entry_len;
        var any = false;
        // In sui-node's list, not stored.
        for (0..n) |j| {
            const id = f.list[j * history.entry_len + 8 ..][0..32];
            const version = std.mem.readInt(u64, f.list[j * history.entry_len ..][0..8], .little);
            const found = for (have) |h| {
                if (h.version == version and std.mem.eql(u8, &h.id, id)) break true;
            } else false;
            if (found) continue;
            out.print(" missing 0x{x} v{d}", .{ id, version }) catch return error.OutOfMemory;
            any = true;
        }
        // Stored, not in sui-node's list.
        for (have) |h| {
            const found = for (0..n) |j| {
                const id = f.list[j * history.entry_len + 8 ..][0..32];
                const version = std.mem.readInt(u64, f.list[j * history.entry_len ..][0..8], .little);
                if (h.version == version and std.mem.eql(u8, &h.id, id)) break true;
            } else false;
            if (found) continue;
            out.print(" extra 0x{x} v{d}", .{ &h.id, h.version }) catch return error.OutOfMemory;
            any = true;
        }
        if (!any) {
            // The same entries in another order: the first one out of place.
            for (have, 0..) |h, j| {
                const id = f.list[j * history.entry_len + 8 ..][0..32];
                if (std.mem.eql(u8, &h.id, id)) continue;
                out.print(" order (entry {d}: stored 0x{x}, sui-node 0x{x})", .{ j, &h.id, id }) catch return error.OutOfMemory;
                break;
            }
        }
        return w.written();
    }

    const Job = struct { seq: u64, copy: ?[]u8, from: From, staged: ?*Staged };

    /// One pass: compares the waiting checkpoints that have a copy, finishes repairs whose
    /// objects are committed, and asks the bucket for those that waited `wait_ms` without one.
    /// True: something was done.
    pub fn step(r: *Reconciler) !bool {
        const committed = r.st.committed() orelse return false;
        const now = source.wallMs();
        var jobs: std.ArrayList(Job) = .empty;
        defer jobs.deinit(r.gpa);
        {
            r.lock.lockUncancelable(r.io);
            defer r.lock.unlock(r.io);
            for (r.waiting.keys(), r.waiting.values()) |seq, *w| {
                if (seq > committed) continue;
                if (w.staged) |s| {
                    if (s.batch != 0 and s.batch <= committed) try jobs.append(r.gpa, .{ .seq = seq, .copy = null, .from = w.from, .staged = s });
                    continue;
                }
                if (w.copy) |c| {
                    try jobs.append(r.gpa, .{ .seq = seq, .copy = c, .from = w.from, .staged = null });
                } else if (r.bucket != null and now -| w.since_ms >= r.cfg.wait_ms and now >= w.retry_ms) {
                    try jobs.append(r.gpa, .{ .seq = seq, .copy = null, .from = .bucket, .staged = null });
                }
            }
            r.advanceLocked();
        }
        var progress = false;
        // A checkpoint that left the history window while it waited (no copy ever came).
        if (now -| r.last_floor_ms >= 5_000) {
            r.last_floor_ms = now;
            var snap = r.st.snapshot();
            const low = snap.lowestCheckpoint();
            snap.release();
            if (low) |l| {
                var gone: std.ArrayList(u64) = .empty;
                defer gone.deinit(r.gpa);
                {
                    r.lock.lockUncancelable(r.io);
                    defer r.lock.unlock(r.io);
                    for (r.waiting.keys(), r.waiting.values()) |seq, *w| {
                        if (seq < l and w.staged == null) try gone.append(r.gpa, seq);
                    }
                }
                for (gone.items) |seq| r.settle(seq);
            }
        }
        for (jobs.items) |job| {
            if (!r.isWaiting(job.seq)) continue;
            if (r.stopping.load(.acquire)) break;
            if (job.staged) |s| {
                // Its objects are durable: the lists may be served now.
                try r.commit(&s.plan);
                _ = r.stats.objects_added.fetchAdd(s.plan.objects.len, .monotonic);
                r.settle(job.seq);
                progress = true;
                continue;
            }
            var arena_state: std.heap.ArenaAllocator = .init(r.gpa);
            var keep = false;
            defer if (!keep) arena_state.deinit();
            const arena = arena_state.allocator();
            var from = job.from;
            const aux_bytes: []const u8 = job.copy orelse blk: {
                from = .bucket;
                const got = r.fetchBucket(job.seq) catch null;
                break :blk got orelse {
                    _ = r.stats.bucket_waits.fetchAdd(1, .monotonic);
                    r.lock.lockUncancelable(r.io);
                    defer r.lock.unlock(r.io);
                    if (r.waiting.getPtr(job.seq)) |w| {
                        w.backoff_ms = @min(@max(w.backoff_ms * 2, r.cfg.retry_ms), 30_000);
                        w.retry_ms = source.wallMs() + w.backoff_ms;
                    }
                    continue;
                };
            };
            if (job.copy == null) _ = r.stats.from_bucket.fetchAdd(1, .monotonic);
            const plan = r.compare(arena, job.seq, aux_bytes, from) catch |e| switch (e) {
                error.BadCopy => {
                    _ = r.stats.bad_copies.fetchAdd(1, .monotonic);
                    std.log.warn("p2p reconcile: checkpoint {d}: the {s} copy does not fit the stored checkpoint; dropped", .{ job.seq, @tagName(from) });
                    r.dropCopy(job.seq);
                    progress = true;
                    continue;
                },
                else => return e,
            };
            _ = r.stats.reconciled.fetchAdd(1, .monotonic);
            progress = true;
            if (plan.gone or (plan.fixes.len == 0 and plan.objects.len == 0)) {
                r.settle(job.seq);
                continue;
            }
            if (plan.objects.len == 0) {
                try r.commit(&plan);
                r.settle(job.seq);
                continue;
            }
            // Objects first, in the next checkpoint's commit group; the plan outlives this pass
            // (and the copy it was read from: a bucket copy sits in the fetch scratch).
            const objs = try arena.alloc([]const u8, plan.objects.len);
            for (plan.objects, objs) |raw, *o| o.* = try arena.dupe(u8, raw);
            var staged_plan = plan;
            staged_plan.objects = objs;
            const s = try r.gpa.create(Staged);
            s.* = .{ .arena = arena_state, .plan = staged_plan };
            keep = true;
            r.lock.lockUncancelable(r.io);
            defer r.lock.unlock(r.io);
            if (r.waiting.getPtr(job.seq)) |w| {
                w.staged = s;
            } else {
                s.arena.deinit();
                r.gpa.destroy(s);
            }
        }
        return progress;
    }

    /// The bucket's aux record of `seq` (in `r.scratch`), null while it is not published.
    fn fetchBucket(r: *Reconciler, seq: u64) !?[]const u8 {
        const b = r.bucket orelse return null;
        var blob: std.ArrayList(u8) = .empty;
        defer blob.deinit(r.gpa);
        if (try b.fetch(&r.scratch, seq, &blob) != .ok) return null;
        if (r.scratch.aux.items.len == 0) return null;
        return r.scratch.aux.items;
    }

    /// A copy that could not be used: forgotten, so the bucket is asked after `wait_ms`.
    fn dropCopy(r: *Reconciler, seq: u64) void {
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        const w = r.waiting.getPtr(seq) orelse return;
        if (w.copy) |c| {
            r.held_bytes -= c.len;
            r.gpa.free(c);
            w.copy = null;
        }
        w.backoff_ms = @min(@max(w.backoff_ms * 2, r.cfg.retry_ms), 30_000);
        w.retry_ms = source.wallMs() + w.backoff_ms;
    }

    /// `seq` is done: forgotten, and the watermark moves up to the lowest checkpoint waiting.
    fn settle(r: *Reconciler, seq: u64) void {
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        if (r.waiting.fetchSwapRemove(seq)) |kv| {
            if (kv.value.copy) |c| {
                r.held_bytes -= c.len;
                r.gpa.free(c);
            }
            if (kv.value.staged) |s| {
                s.arena.deinit();
                r.gpa.destroy(s);
            }
        }
        r.stats.pending.store(r.waiting.count(), .monotonic);
        r.advanceLocked();
    }

    /// Moves the watermark up to the lowest checkpoint waiting, or past the store's committed
    /// tip when none waits (a built checkpoint is in `waiting` before it commits), and logs it
    /// every `mark_every`. Without this a node whose p2p rarely wins would look at its whole
    /// history window for markers at every start.
    fn advanceLocked(r: *Reconciler) void {
        var low = (r.st.committed() orelse return) + 1;
        for (r.waiting.keys()) |s| low = @min(low, s);
        r.settled_below = @max(r.settled_below, low);
        if (r.settled_below >= r.marked_below + r.cfg.mark_every) r.writeMark() catch {};
    }

    /// Whether `seq` still waits (tests, status).
    pub fn isWaiting(r: *Reconciler, seq: u64) bool {
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        return r.waiting.contains(seq);
    }
};
