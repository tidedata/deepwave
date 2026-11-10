//! The node's RPC side tables for the epoch-pkg lane (DROP-IN G6, G8), the deepwave counterparts of the
//! sui-rpc-store `epochs` and `package_versions` column families:
//!
//! - **Epoch records** (`<dir>/epochs/<epoch>.rec`, one file per epoch, rewritten atomically):
//!   the start record of epoch E+1 comes from the end-of-epoch checkpoint of E (the system state the
//!   change-epoch transaction wrote: protocol version, reference gas price, start time, start
//!   checkpoint = eoe + 1, and the whole state), the end record of E from the same checkpoint
//!   (its timestamp and sequence number); `sui_types::CheckpointData::epoch_info` and
//!   `sui-rpc-store/src/indexer/epochs.rs`.
//! - **Package versions** (`<dir>/pkgver.log`, append-only 80-byte rows: original id, version,
//!   storage id, checkpoint or u64::MAX for a restored row): every package object a checkpoint
//!   outputs, keyed by `original_package_id()`; `sui-rpc-store/src/indexer/package_versions.rs`.
//! - **Watermark** (`<dir>/watermark`, two checksummed slots written alternately): the last
//!   checkpoint whose rows are durable. It is the "highest indexed checkpoint" GetPackage
//!   `at_checkpoint` checks against; until it exists the index answers `rpc index is empty`.
//!
//! Feeds (CONTRACTS 6.8: a derived index with its own durable watermark):
//! - the commit stream: `onCheckpoint(seq, blob)` for every checkpoint the follower applies, before
//!   its batch commits, then `commit(seq)` (rows durable, then the watermark);
//! - a snapshot restore: `onRestoredObject` for every live object (packages become floor rows, as
//!   sui-node's `Restore for PackageVersions`), `seedEpochStart`, then `restoreDone(last)`;
//! - node start (`seed`): an index with no watermark on a store that has a live set walks the live
//!   set once (floor rows for every package: user packages are immutable, so the live set holds
//!   every version) and replays the stored checkpoints through the same row logic (sui-node's
//!   restore plus its `(L, T]` backfill, which overwrites floors with real publish checkpoints); an
//!   index whose watermark is below the store tip replays the stored checkpoints in between.
//! - system packages (0x1, 0x2, 0x3, 0xb, 0xdee9) are upgraded in place at epoch changes: the live
//!   set holds only their newest version. Every checkpoint the row logic sees that writes one in
//!   place (effects input state `Exist(prior)`, or the prior version among the checkpoint's input
//!   objects) also gives the prior version a floor row: a sui-node whose index saw that checkpoint
//!   holds the prior version (it was live at its restore, or indexed). So a live-set walk taken
//!   after the upgrade, or a restore that lands after it, keeps the version before. The epoch
//!   records fill (`onEpochCheckpoint`) does the same for the end-of-epoch checkpoints it fetches
//!   (each once: `eoe-pkgs` lists the epochs whose end-of-epoch package rows are in).
//!
//! Readers (request threads) bracket their reads with `enter`/`exit`: records and lineages are
//! never modified in place; an update builds a new one, swaps the pointer and retires the old one,
//! which is freed after a grace period (`store.rcu`) once no reader that could hold it remains.
//! One writer at a time (the follower's observer thread, or node start before it runs).
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const sysstate = @import("sysstate.zig");

pub const Start = struct {
    protocol_version: u64,
    reference_gas_price: u64,
    start_timestamp_ms: u64,
    start_checkpoint: ?u64,
    /// The system state at the start of the epoch (null when only the checkpoint is known).
    state: ?sysstate.State,
};

pub const End = struct {
    end_timestamp_ms: u64,
    end_checkpoint: u64,
};

pub const Record = struct {
    epoch: u64,
    start: ?Start = null,
    end: ?End = null,
};

pub const PkgVersion = struct {
    version: u64,
    storage_id: [32]u8,
    /// Checkpoint that published it; null for a restored row (matches any `at_checkpoint`).
    checkpoint: ?u64,
};

pub const Lineage = struct {
    /// Sorted by version, unique.
    versions: []const PkgVersion,
};

/// The committee of an epoch from another store than the epoch record (the node's per-epoch
/// committee files): sui-node's `get_committee(epoch)` reads its committee store, not epoch_info.
pub const CommitteeSource = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, arena: Allocator, epoch: u64) ?[]const sysstate.Member,
};

const SpinLock = struct {
    v: std.atomic.Value(u32) = .init(0),
    fn lock(l: *SpinLock) void {
        while (l.v.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn unlock(l: *SpinLock) void {
        l.v.store(0, .release);
    }
};

const Retired = union(enum) { record: *Record, lineage: *Lineage, bytes: []const u8 };

pub const SeedReport = struct {
    live_objects: u64 = 0,
    floor_rows: u64 = 0,
    replayed: u64 = 0,
    replay_from: ?u64 = null,
    watermark: ?u64 = null,
};

pub const Index = struct {
    gpa: Allocator,
    io: ?Io,
    dir: ?Io.Dir,
    epochs_dir: ?Io.Dir = null,
    lock: SpinLock = .{},
    epochs: std.AutoHashMapUnmanaged(u64, *Record) = .empty,
    lineages: std.AutoHashMapUnmanaged([32]u8, *Lineage) = .empty,
    /// Superseded records, lineages and bytes: freed once no reader can hold them.
    rcu: store.rcu.Rcu(Retired) = .{},
    pkg_log: ?Io.File = null,
    pkg_log_end: u64 = 0,
    pkg_dirty: bool = false,
    wm_file: ?Io.File = null,
    wm_gen: u64 = 0,
    /// Durable watermark (writer side): the last checkpoint every row of which is on disk.
    watermark: ?u64 = null,
    /// Highest checkpoint served as indexed (GetPackage `at_checkpoint`), published to readers.
    indexed_hi: std.atomic.Value(u64) = .init(std.math.maxInt(u64)),
    /// False while a fast-start background job (lane fast-start) fills package floors from the
    /// restore image and replays the stored checkpoints: package version selectors and
    /// ListPackageVersions answer UNAVAILABLE, and only that job writes.
    ready: std.atomic.Value(bool) = .init(true),
    /// Committees for epochs whose record has no state (GetEpoch `committee`).
    committees: ?CommitteeSource = null,
    /// Epochs whose end-of-epoch checkpoint gave its in-place system package rows (`eoe-pkgs`,
    /// append-only u64 rows; writer side, under `lock`).
    eoe_pkgs: std.AutoHashMapUnmanaged(u64, void) = .empty,
    eoe_file: ?Io.File = null,
    eoe_end: u64 = 0,
    /// Scratch for indexing blobs (one feeder thread).
    cidx: ?types.index.CheckpointIndex = null,

    /// In-memory only (tests, conformance).
    pub fn initMemory(gpa: Allocator) Index {
        return .{ .gpa = gpa, .io = null, .dir = null };
    }

    /// Opens (or creates) `path` and loads every record, package row and the watermark. Nothing is
    /// published to readers until `seed`, `restoreDone` or the first `commit`.
    pub fn open(gpa: Allocator, io: Io, path: []const u8) !*Index {
        const cwd = Io.Dir.cwd();
        try cwd.createDirPath(io, path);
        const dir = try cwd.openDir(io, path, .{ .iterate = true });
        try dir.createDirPath(io, "epochs");
        const x = try gpa.create(Index);
        x.* = .{ .gpa = gpa, .io = io, .dir = dir };
        errdefer x.deinit();
        x.epochs_dir = try dir.openDir(io, "epochs", .{ .iterate = true });
        try x.loadEpochs();
        try x.loadPackages();
        try x.loadEoePackages();
        try x.loadWatermark();
        try syncDir(io, dir);
        return x;
    }

    pub fn deinit(x: *Index) void {
        const gpa = x.gpa;
        var it = x.epochs.valueIterator();
        while (it.next()) |r| freeRecord(gpa, r.*);
        x.epochs.deinit(gpa);
        var lt = x.lineages.valueIterator();
        while (lt.next()) |l| {
            gpa.free(l.*.versions);
            gpa.destroy(l.*);
        }
        x.lineages.deinit(gpa);
        x.eoe_pkgs.deinit(gpa);
        x.rcu.drainAll(gpa, reclaim);
        x.rcu.deinit(gpa);
        if (x.cidx) |*c| c.deinit(gpa);
        if (x.io) |io| {
            if (x.pkg_log) |f| f.close(io);
            if (x.eoe_file) |f| f.close(io);
            if (x.wm_file) |f| f.close(io);
            if (x.epochs_dir) |d| d.close(io);
            if (x.dir) |d| d.close(io);
            gpa.destroy(x);
        }
    }

    fn freeRecord(gpa: Allocator, r: *Record) void {
        if (r.start) |s| if (s.state) |st| gpa.free(st.inner);
        gpa.destroy(r);
    }

    fn reclaim(gpa: Allocator, r: Retired) void {
        switch (r) {
            .record => |p| gpa.destroy(p),
            .lineage => |p| {
                gpa.free(p.versions);
                gpa.destroy(p);
            },
            .bytes => |b| gpa.free(b),
        }
    }

    /// Frees what no reader can still hold (the writer calls it once per checkpoint).
    pub fn reclaimRetired(x: *Index) void {
        x.rcu.poll(x.gpa, reclaim);
    }

    // ------------------------------------------------------------------ reads

    /// Readers: call before `epoch`/`lineage` and pass the token to `exit` once done with what
    /// they returned.
    pub fn enter(x: *Index) u1 {
        return x.rcu.enter();
    }

    pub fn exit(x: *Index, token: u1) void {
        x.rcu.exit(token);
    }

    /// The record of `epoch` (immutable; valid until `exit`).
    pub fn epoch(x: *Index, e: u64) ?*const Record {
        x.lock.lock();
        defer x.lock.unlock();
        return x.epochs.get(e);
    }

    /// The versions of the lineage whose original id is `original` (immutable; valid until `exit`).
    pub fn lineage(x: *Index, original: *const [32]u8) []const PkgVersion {
        x.lock.lock();
        defer x.lock.unlock();
        const l = x.lineages.get(original.*) orelse return &.{};
        return l.versions;
    }

    /// The committee of epoch `e` from the committee source (null without one, or unknown).
    pub fn committeeOf(x: *Index, arena: Allocator, e: u64) ?[]const sysstate.Member {
        const c = x.committees orelse return null;
        return c.get(c.ctx, arena, e);
    }

    pub fn highestIndexed(x: *const Index) ?u64 {
        const v = x.indexed_hi.load(.acquire);
        return if (v == std.math.maxInt(u64)) null else v;
    }

    /// Tells readers every row up to `seq` is in (in-memory indexes; `commit` does it with the
    /// durable watermark).
    pub fn publish(x: *Index, seq: u64) void {
        const cur = x.indexed_hi.load(.acquire);
        if (cur == std.math.maxInt(u64) or seq > cur) x.indexed_hi.store(seq, .release);
    }

    // ------------------------------------------------------------------ writes

    /// Merges `start` and/or `end` into the record of `e` and persists it. `state.inner` is copied.
    pub fn putEpoch(x: *Index, e: u64, start: ?Start, end: ?End) !void {
        const gpa = x.gpa;
        const rec = try gpa.create(Record);
        var rec_owned = true;
        defer if (rec_owned) gpa.destroy(rec);
        rec.* = .{ .epoch = e };
        x.lock.lock();
        const old = x.epochs.get(e);
        x.lock.unlock();
        if (old) |o| rec.* = o.*;
        var new_bytes: ?[]const u8 = null;
        errdefer if (new_bytes) |b| gpa.free(b);
        if (start) |s| {
            var s2 = s;
            if (s.state) |st| {
                const b = try gpa.dupe(u8, st.inner);
                new_bytes = b;
                s2.state = .{ .version = st.version, .inner = b };
            } else if (rec.start) |os| s2.state = os.state; // keep a known state
            rec.start = s2;
        }
        if (end) |en| rec.end = en;
        try x.persistEpoch(rec);
        try x.rcu.pending.ensureUnusedCapacity(gpa, 2);
        {
            x.lock.lock();
            defer x.lock.unlock();
            try x.epochs.put(gpa, e, rec);
        }
        rec_owned = false;
        new_bytes = null;
        if (old) |o| {
            x.rcu.pending.appendAssumeCapacity(.{ .record = o });
            // the old state bytes stay alive if the new record still points at them
            if (o.start) |os| if (os.state) |ost| {
                const kept = if (rec.start) |ns| if (ns.state) |nst| nst.inner.ptr == ost.inner.ptr else false else false;
                if (!kept) x.rcu.pending.appendAssumeCapacity(.{ .bytes = ost.inner });
            };
        }
    }

    /// Forgets the record of `e` (retention, or an index that must start where a restore did).
    pub fn dropEpoch(x: *Index, e: u64) !void {
        try x.rcu.pending.ensureUnusedCapacity(x.gpa, 2);
        x.lock.lock();
        const old = x.epochs.fetchRemove(e);
        x.lock.unlock();
        const kv = old orelse return;
        x.rcu.pending.appendAssumeCapacity(.{ .record = kv.value });
        if (kv.value.start) |st| if (st.state) |ss| x.rcu.pending.appendAssumeCapacity(.{ .bytes = ss.inner });
        if (x.io) |io| {
            var nb: [48]u8 = undefined;
            x.epochs_dir.?.deleteFile(io, std.fmt.bufPrint(&nb, "{d}.rec", .{e}) catch unreachable) catch {};
        }
    }

    /// Adds one package version. An indexed row (with a checkpoint) replaces anything; a restored
    /// row (checkpoint null, a restore floor) only fills a version that has no row yet.
    pub fn putPackage(x: *Index, original: *const [32]u8, version: u64, storage: *const [32]u8, checkpoint: ?u64) !void {
        const gpa = x.gpa;
        x.lock.lock();
        const old = x.lineages.get(original.*);
        x.lock.unlock();
        const cur: []const PkgVersion = if (old) |o| o.versions else &.{};
        var pos: usize = 0;
        while (pos < cur.len and cur[pos].version < version) pos += 1;
        const replace = pos < cur.len and cur[pos].version == version;
        if (replace) {
            const c = cur[pos];
            if (checkpoint == null and c.checkpoint != null) return; // keep the indexed row
            if (std.mem.eql(u8, &c.storage_id, storage) and std.meta.eql(c.checkpoint, checkpoint)) return;
        }
        const nv = try gpa.alloc(PkgVersion, cur.len + @intFromBool(!replace));
        errdefer gpa.free(nv);
        @memcpy(nv[0..pos], cur[0..pos]);
        nv[pos] = .{ .version = version, .storage_id = storage.*, .checkpoint = checkpoint };
        const rest = if (replace) pos + 1 else pos;
        @memcpy(nv[pos + 1 ..], cur[rest..]);
        const l = try gpa.create(Lineage);
        errdefer gpa.destroy(l);
        l.* = .{ .versions = nv };
        try x.appendPackageRow(original, version, storage, checkpoint);
        try x.rcu.pending.ensureUnusedCapacity(gpa, 1);
        {
            x.lock.lock();
            defer x.lock.unlock();
            try x.lineages.put(gpa, original.*, l);
        }
        if (old) |o| x.rcu.pending.appendAssumeCapacity(.{ .lineage = o });
    }

    // ------------------------------------------------------------------ feeds

    /// A live object restored from a snapshot: a package becomes a restored row (checkpoint None).
    pub fn onRestoredObject(x: *Index, id: *const [32]u8, version: u64, bytes: []const u8) !void {
        _ = version;
        if (bytes.len == 0 or bytes[0] != 1) return; // Data::Package is variant 1
        try x.addPackageObject(id, bytes, null);
    }

    /// The restore's live set is in and its last checkpoint is `last`: rows are durable up to it.
    pub fn restoreDone(x: *Index, last: u64) !void {
        try x.commit(last);
    }

    /// Fast start: the stored checkpoints from `from` to `to` through the row logic (no commit;
    /// the caller commits once the index is level). The number replayed.
    pub fn replayStored(x: *Index, snap: *const store.Snapshot, from: u64, to: u64) !u64 {
        var n: u64 = 0;
        var seq = from;
        while (seq <= to) : (seq += 1) {
            try x.onStoredCheckpoint(snap, seq);
            n += 1;
            if (n % 4096 == 0) x.reclaimRetired();
        }
        return n;
    }

    /// Fast start: the stored-checkpoint replay starts here (null: nothing to replay).
    pub fn replayFrom(x: *Index, snap: *const store.Snapshot) ?u64 {
        const tip = snap.highestCommitted() orelse return null;
        const lo = lowestStored(snap, tip);
        if (x.watermark) |wm| return if (wm >= tip) null else @max(wm + 1, lo);
        return lo;
    }

    /// Fast start, last step (the follower's thread, before checkpoint `tip + 1` is fed): durable
    /// rows and watermark at `tip`, published to readers.
    pub fn finishSeed(x: *Index, snap: *const store.Snapshot, tip: u64) !void {
        try x.syncRows();
        try x.seedFromStore(snap);
        try x.commit(@max(tip, x.watermark orelse tip));
        x.indexed_hi.store(@min(x.watermark.?, tip), .release);
        x.ready.store(true, .release);
    }

    /// After a restore at epoch E's last checkpoint `last`: the live system state is the state
    /// epoch E+1 starts with, so its start record is known (start checkpoint `last + 1`).
    pub fn seedEpochStart(x: *Index, snap: *const store.Snapshot, start_checkpoint: ?u64) !void {
        const st = liveState(snap) orelse return;
        const s = try sysstate.summary(st);
        if (x.epoch(s.epoch)) |r| if (r.start != null and r.start.?.state != null) return;
        try x.putEpoch(s.epoch, .{
            .protocol_version = s.protocol_version,
            .reference_gas_price = s.reference_gas_price,
            .start_timestamp_ms = s.epoch_start_timestamp_ms,
            .start_checkpoint = start_checkpoint,
            .state = st,
        }, null);
    }

    /// Node start, before the follower runs (no batch may commit while it walks the live table).
    /// Brings the index level with the store tip (see the file comment) and publishes it. The
    /// snapshot quiesces after each replayed checkpoint (nothing of it is kept across them), so
    /// a replay of the whole stored window does not pin every chunk it decodes.
    pub fn seed(x: *Index, snap: *store.Snapshot) !SeedReport {
        var rep: SeedReport = .{};
        const tip = snap.highestCommitted() orelse {
            // empty store: the follower's first checkpoint starts the index
            rep.watermark = x.watermark;
            return rep;
        };
        const lo = lowestStored(snap, tip);
        const from: ?u64 = if (x.watermark) |wm| (if (wm >= tip) null else wm + 1) else lo;
        if (from) |f| {
            if (x.watermark == null or f < lo) {
                // no rows for what predates the stored window: floors from the live set
                if (x.watermark != null) std.log.warn("rpc index: watermark {d} is below the lowest stored checkpoint {d}; package floors from the live set, epoch records in between are lost", .{ f - 1, lo });
                const Walk = struct {
                    x: *Index,
                    rep: *SeedReport,
                    fn each(w: @This(), id: *const [32]u8, version: u64, bytes: []const u8) anyerror!void {
                        w.rep.live_objects += 1;
                        if (bytes.len == 0 or bytes[0] != 1) return;
                        try w.x.onRestoredObject(id, version, bytes);
                        w.rep.floor_rows += 1;
                    }
                };
                try snap.forEachLive(Walk{ .x = x, .rep = &rep }, Walk.each);
                try x.syncRows();
            }
            const start = @max(f, lo);
            rep.replay_from = start;
            var seq = start;
            while (seq <= tip) : (seq += 1) {
                try x.onStoredCheckpoint(snap, seq);
                snap.quiesce();
                rep.replayed += 1;
                if (rep.replayed % 100_000 == 0) std.log.info("rpc index: replayed {d} stored checkpoints ({d}..{d})", .{ rep.replayed, start, tip });
                if (rep.replayed % 4096 == 0) x.reclaimRetired();
            }
        }
        try x.seedFromStore(snap);
        try x.commit(@max(tip, x.watermark orelse tip));
        rep.watermark = x.watermark;
        // a watermark above the tip (crash between this index and the store commit): those
        // checkpoints are fed again; serve only what the store has
        x.indexed_hi.store(@min(x.watermark.?, tip), .release);
        return rep;
    }

    /// The current epoch's start record when no end-of-epoch checkpoint gave it (a node started
    /// mid-epoch): the live state (sui-node `seed_current_epoch_start` stores its BCS too) and the
    /// epoch's first checkpoint if the previous epoch's last checkpoint is stored.
    pub fn seedFromStore(x: *Index, snap: *const store.Snapshot) !void {
        const st = liveState(snap) orelse return;
        const s = try sysstate.summary(st);
        if (x.epoch(s.epoch)) |r| if (r.start) |rs| if (rs.state != null) return;
        var first: ?u64 = null;
        if (snap.highestCommitted()) |hi| {
            const lo = lowestStored(snap, hi);
            if (snap.checkpoint(lo)) |lr| if (lr.epoch < s.epoch) {
                // the last stored checkpoint of an earlier epoch: binary search in [lo, hi]
                var a: u64 = lo;
                var b: u64 = hi;
                while (a + 1 < b) {
                    const mid = a + (b - a) / 2;
                    const r = snap.checkpoint(mid) orelse return error.StoreGap;
                    if (r.epoch < s.epoch) a = mid else b = mid;
                }
                if (snap.checkpoint(b)) |br| {
                    if (br.epoch == s.epoch) first = b;
                }
            };
        }
        if (first == null) if (x.epoch(s.epoch)) |r| if (r.start) |rs| {
            first = rs.start_checkpoint;
        };
        try x.putEpoch(s.epoch, .{
            .protocol_version = s.protocol_version,
            .reference_gas_price = s.reference_gas_price,
            .start_timestamp_ms = s.epoch_start_timestamp_ms,
            .start_checkpoint = first,
            .state = st,
        }, null);
    }

    /// One checkpoint blob (0x01 ++ BCS CheckpointData) the follower applies: package outputs and,
    /// at an end-of-epoch checkpoint, the epoch records. Then `commit(seq)`.
    pub fn onCheckpoint(x: *Index, seq: u64, blob: []const u8) !void {
        if (x.cidx == null) x.cidx = try types.index.CheckpointIndex.init(x.gpa);
        const idx = &x.cidx.?;
        try types.indexCheckpointData(blob, idx);
        const hdr = try parseSummary(idx.summary.slice(blob));
        // packages in the transactions' outputs; a package among the inputs is a system package
        // written in place: its prior version gets a floor row
        for (idx.txs[0..idx.tx_count]) |*t| {
            for (idx.objs[t.in_first..][0..t.in_count]) |rg| {
                const ob = rg.slice(blob);
                if (ob.len < 33 or ob[0] != 1) continue;
                try x.addPackageObject(ob[1..33], ob, null);
            }
            for (idx.objs[t.out_first..][0..t.out_count]) |rg| {
                const ob = rg.slice(blob);
                if (ob.len < 33 or ob[0] != 1) continue;
                try x.addPackageObject(ob[1..33], ob, seq);
            }
        }
        if (!hdr.end_of_epoch) return;
        try x.epochRecordsOf(seq, blob, hdr, true);
        try x.markEoePackages(hdr.epoch);
    }

    /// The epoch records of a verified end-of-epoch checkpoint blob (0x01 ++ BCS CheckpointData)
    /// of an epoch the node did not follow: the start record of the next epoch and, with
    /// `want_end`, the end record of the checkpoint's own epoch. Node start fills the records of
    /// past epochs with it (GetEpoch on epochs before the store's start, as sui-node answers them
    /// from its rpc-store `epochs` table, which is never pruned).
    /// Package rows: only the system packages the change-epoch transaction upgrades in place (a
    /// package among a transaction's inputs): the prior version as a floor row, the new version
    /// with this checkpoint. Packages published by user transactions are left to the live set's
    /// floors. The checkpoint's epoch is then marked in `eoe-pkgs`.
    pub fn onEpochCheckpoint(x: *Index, seq: u64, blob: []const u8, want_end: bool) !void {
        if (x.cidx == null) x.cidx = try types.index.CheckpointIndex.init(x.gpa);
        const idx = &x.cidx.?;
        try types.indexCheckpointData(blob, idx);
        const hdr = try parseSummary(idx.summary.slice(blob));
        if (!hdr.end_of_epoch) return error.NotEndOfEpoch;
        for (idx.txs[0..idx.tx_count]) |*t| {
            const ins = idx.objs[t.in_first..][0..t.in_count];
            for (ins) |rg| {
                const ob = rg.slice(blob);
                if (ob.len < 33 or ob[0] != 1) continue;
                try x.addPackageObject(ob[1..33], ob, null);
            }
            for (idx.objs[t.out_first..][0..t.out_count]) |rg| {
                const ob = rg.slice(blob);
                if (ob.len < 33 or ob[0] != 1) continue;
                const in_place = for (ins) |ir| {
                    const ib = ir.slice(blob);
                    if (ib.len >= 33 and ib[0] == 1 and std.mem.eql(u8, ib[1..33], ob[1..33])) break true;
                } else false;
                if (in_place) try x.addPackageObject(ob[1..33], ob, seq);
            }
        }
        try x.epochRecordsOf(seq, blob, hdr, want_end);
        try x.markEoePackages(hdr.epoch);
    }

    /// Records that the end-of-epoch checkpoint of `e` gave its package rows (made durable first).
    fn markEoePackages(x: *Index, e: u64) !void {
        x.lock.lock();
        const have = x.eoe_pkgs.contains(e);
        x.lock.unlock();
        if (have) return;
        if (x.io) |io| if (x.eoe_file) |f| {
            try x.syncRows();
            var le: [8]u8 = undefined;
            std.mem.writeInt(u64, &le, e, .little);
            try f.writePositionalAll(io, &le, x.eoe_end);
            try f.sync(io);
            x.eoe_end += 8;
        };
        x.lock.lock();
        defer x.lock.unlock();
        try x.eoe_pkgs.put(x.gpa, e, {});
    }

    /// Whether the end-of-epoch checkpoint of `e` still has records to give: the end of `e`
    /// (when `want_end`) or a complete start of `e + 1` (state and first checkpoint).
    /// Also true while the checkpoint's in-place system package rows are not in (`eoe-pkgs`): an
    /// index from before those rows fetches each end-of-epoch checkpoint once more.
    pub fn epochNeeds(x: *Index, e: u64, want_end: bool) bool {
        {
            x.lock.lock();
            defer x.lock.unlock();
            if (!x.eoe_pkgs.contains(e)) return true;
        }
        const tok = x.enter();
        defer x.exit(tok);
        if (want_end) {
            const r = x.epoch(e) orelse return true;
            if (r.end == null) return true;
        }
        const n = x.epoch(e + 1) orelse return true;
        const st = n.start orelse return true;
        return st.state == null or st.start_checkpoint == null;
    }

    /// The epoch records of end-of-epoch checkpoint `seq` (indexed in `x.cidx`).
    fn epochRecordsOf(x: *Index, seq: u64, blob: []const u8, hdr: Header, want_end: bool) !void {
        const idx = &x.cidx.?;
        // the system state the change-epoch transaction wrote: the last output of 0x5 and its field
        var wrapper: ?[]const u8 = null;
        var fields: std.ArrayList([]const u8) = .empty;
        defer fields.deinit(x.gpa);
        for (idx.txs[0..idx.tx_count]) |*t| {
            for (idx.objs[t.out_first..][0..t.out_count]) |rg| {
                const c = sysstate.moveContents(rg.slice(blob)) orelse continue;
                if (c.len < 32) continue;
                if (std.mem.eql(u8, c[0..32], &sysstate.system_state_id)) wrapper = c else try fields.append(x.gpa, c);
            }
        }
        var state: ?sysstate.State = null;
        if (wrapper) |w| {
            const ver = sysstate.wrapperVersion(w) orelse return error.Malformed;
            const want = sysstate.u64FieldId(&sysstate.system_state_id, ver);
            for (fields.items) |c| if (std.mem.eql(u8, c[0..32], &want)) {
                if (sysstate.innerOfField(c)) |in| state = .{ .version = ver, .inner = in };
            };
        }
        try x.onEndOfEpoch(seq, hdr, state, want_end);
    }

    /// The same rows from a checkpoint the store holds (node start: the stored window or the
    /// span since the watermark): outputs from the stored effects, objects from the store.
    pub fn onStoredCheckpoint(x: *Index, snap: *const store.Snapshot, seq: u64) !void {
        var ar = std.heap.ArenaAllocator.init(x.gpa);
        defer ar.deinit();
        const a = ar.allocator();
        const rec = (try snap.checkpointChecked(seq)) orelse return error.CheckpointNotStored;
        const hdr = try parseSummary(rec.summary_cert);
        const contents = try bcs.decode(types.CheckpointContents, a, rec.contents);
        const n = switch (contents) {
            .V1 => |v| v.transactions.len,
            .V2 => |v| v.transactions.len,
        };
        // object writes of an end-of-epoch checkpoint (to find the system state)
        var writes: std.ArrayList(struct { id: [32]u8, version: u64 }) = .empty;
        for (0..n) |i| {
            const dg: *const [32]u8 = switch (contents) {
                .V1 => |v| &v.transactions[i].transaction.@"0".@"0",
                .V2 => |v| &v.transactions[i].digest.transaction.@"0".@"0",
            };
            const t = (try snap.transactionChecked(dg)) orelse return error.TransactionNotStored;
            const eff = try bcs.decode(types.TransactionEffects, a, t.effects);
            switch (eff) {
                .V2 => |v| for (v.changed_objects) |co| {
                    const id: *const [32]u8 = &co[0].@"0".@"0";
                    switch (co[1].output_state) {
                        .PackageWrite => |pw| {
                            const ob = (try snap.objectAtChecked(id, pw[0].@"0")) orelse return error.ObjectNotStored;
                            try x.addPackageObject(id, ob.bytes, seq);
                            // a system package upgraded in place: the prior version (same id, which
                            // is its original id) keeps a floor row
                            switch (co[1].input_state) {
                                .Exist => |ex| try x.putPackage(id, ex[0][0].@"0", id, null),
                                .NotExist => {},
                            }
                        },
                        .ObjectWrite => if (hdr.end_of_epoch) try writes.append(a, .{ .id = id.*, .version = v.lamport_version.@"0" }),
                        else => {},
                    }
                },
                .V1 => |v| for ([_][]const struct { struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest }, types.Owner }{ v.created, v.mutated, v.unwrapped }) |list| for (list) |o| {
                    const id: *const [32]u8 = &o[0][0].@"0".@"0";
                    const ver = o[0][1].@"0";
                    const ob = (try snap.objectAtChecked(id, ver)) orelse continue;
                    if (ob.bytes.len > 0 and ob.bytes[0] == 1) try x.addPackageObject(id, ob.bytes, seq) else if (hdr.end_of_epoch) try writes.append(a, .{ .id = id.*, .version = ver });
                },
            }
        }
        if (!hdr.end_of_epoch) return;
        var state: ?sysstate.State = null;
        var wver: ?u64 = null;
        for (writes.items) |w| if (std.mem.eql(u8, &w.id, &sysstate.system_state_id)) {
            wver = w.version;
        };
        if (wver) |v| {
            const wo = (try snap.objectAtChecked(&sysstate.system_state_id, v)) orelse return error.ObjectNotStored;
            const wc = sysstate.moveContents(wo.bytes) orelse return error.Malformed;
            const ver = sysstate.wrapperVersion(wc) orelse return error.Malformed;
            const fid = sysstate.u64FieldId(&sysstate.system_state_id, ver);
            for (writes.items) |w| if (std.mem.eql(u8, &w.id, &fid)) {
                const fo = (try snap.objectAtChecked(&fid, w.version)) orelse return error.ObjectNotStored;
                const fc = sysstate.moveContents(fo.bytes) orelse return error.Malformed;
                if (sysstate.innerOfField(fc)) |in| state = .{ .version = ver, .inner = in };
            };
        }
        try x.onEndOfEpoch(seq, hdr, state, true);
        try x.markEoePackages(hdr.epoch);
    }

    const Header = struct { epoch: u64, timestamp_ms: u64, end_of_epoch: bool };

    /// CheckpointSummary prefix: epoch, sequence_number, network_total_transactions,
    /// content_digest, previous_digest, epoch_rolling_gas_cost_summary, timestamp_ms,
    /// checkpoint_commitments, end_of_epoch_data (the store's summary_cert starts with it too).
    fn parseSummary(sb: []const u8) !Header {
        var sr = bcs.Reader.init(sb);
        const ending = try sr.int(u64);
        _ = try sr.bytes(16);
        try bcs.skip(types.CheckpointContentsDigest, &sr);
        try bcs.skip(?types.CheckpointDigest, &sr);
        try bcs.skip(types.GasCostSummary, &sr);
        const ts = try sr.int(u64);
        try bcs.skip([]const types.CheckpointCommitment, &sr);
        return .{ .epoch = ending, .timestamp_ms = ts, .end_of_epoch = (try sr.int(u8)) == 1 };
    }

    fn onEndOfEpoch(x: *Index, seq: u64, hdr: Header, state: ?sysstate.State, want_end: bool) !void {
        if (state) |st| {
            const s = try sysstate.summary(st);
            try x.putEpoch(s.epoch, .{
                .protocol_version = s.protocol_version,
                .reference_gas_price = s.reference_gas_price,
                .start_timestamp_ms = s.epoch_start_timestamp_ms,
                .start_checkpoint = seq + 1,
                .state = st,
            }, null);
        } else std.log.warn("rpcindex: end-of-epoch checkpoint {d} does not write the system state", .{seq});
        if (want_end) try x.putEpoch(hdr.epoch, null, .{ .end_timestamp_ms = hdr.timestamp_ms, .end_checkpoint = seq });
    }

    fn addPackageObject(x: *Index, id: *const [32]u8, bytes: []const u8, checkpoint: ?u64) !void {
        if (bytes.len < 41) return error.Malformed;
        const original = originalId(bytes) orelse return error.Malformed;
        const version = std.mem.readInt(u64, bytes[33..41], .little); // Data::Package { id, version, .. }
        try x.putPackage(&original, version, id, checkpoint);
    }

    /// Every row of checkpoints up to `seq` is fed: makes them durable, then the watermark, then
    /// publishes `seq` to readers and frees what readers no longer hold. An error leaves the
    /// watermark where it was (the node stops; a restart replays from it).
    pub fn commit(x: *Index, seq: u64) !void {
        try x.syncRows();
        try x.persistWatermark(seq);
        x.publish(seq);
        x.reclaimRetired();
    }

    // ------------------------------------------------------------------ persistence

    const magic = "ZEPR";

    fn persistEpoch(x: *Index, r: *const Record) !void {
        const io = x.io orelse return;
        const dir = x.epochs_dir.?;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(x.gpa);
        const g = x.gpa;
        try buf.appendSlice(g, magic);
        var flags: u8 = 0;
        if (r.start != null) flags |= 1;
        if (r.end != null) flags |= 2;
        if (r.start) |s| if (s.state != null) {
            flags |= 4;
        };
        try buf.append(g, flags);
        const s = r.start orelse Start{ .protocol_version = 0, .reference_gas_price = 0, .start_timestamp_ms = 0, .start_checkpoint = null, .state = null };
        const en = r.end orelse End{ .end_timestamp_ms = 0, .end_checkpoint = 0 };
        const st = s.state orelse sysstate.State{ .version = 0, .inner = &.{} };
        for ([_]u64{ r.epoch, s.protocol_version, s.reference_gas_price, s.start_timestamp_ms, s.start_checkpoint orelse std.math.maxInt(u64), en.end_timestamp_ms, en.end_checkpoint, st.version, st.inner.len }) |v| {
            var le: [8]u8 = undefined;
            std.mem.writeInt(u64, &le, v, .little);
            try buf.appendSlice(g, &le);
        }
        try buf.appendSlice(g, st.inner);
        var nb: [48]u8 = undefined;
        var tb: [48]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, "{d}.rec", .{r.epoch}) catch unreachable;
        const tmp = std.fmt.bufPrint(&tb, ".{d}.rec.tmp", .{r.epoch}) catch unreachable;
        {
            const f = try dir.createFile(io, tmp, .{ .truncate = true });
            defer f.close(io);
            try f.writePositionalAll(io, buf.items, 0);
            try f.sync(io);
        }
        try dir.rename(tmp, dir, name, io);
        try syncDir(io, dir); // the rename is durable before the store commits
    }

    fn loadEpochs(x: *Index) !void {
        const io = x.io.?;
        const d = x.epochs_dir.?;
        var it = d.iterate();
        while (try it.next(io)) |ent| {
            if (ent.name[0] == '.' or !std.mem.endsWith(u8, ent.name, ".rec")) continue;
            const data = d.readFileAlloc(io, ent.name, x.gpa, .limited(64 << 20)) catch continue;
            defer x.gpa.free(data);
            if (data.len < 5 + 72 or !std.mem.eql(u8, data[0..4], magic)) continue;
            const flags = data[4];
            var v: [9]u64 = undefined;
            for (&v, 0..) |*o, i| o.* = std.mem.readInt(u64, data[5 + 8 * i ..][0..8], .little);
            if (data.len != 5 + 72 + v[8]) continue;
            const rec = try x.gpa.create(Record);
            rec.* = .{ .epoch = v[0] };
            if (flags & 1 != 0) {
                rec.start = .{
                    .protocol_version = v[1],
                    .reference_gas_price = v[2],
                    .start_timestamp_ms = v[3],
                    .start_checkpoint = if (v[4] == std.math.maxInt(u64)) null else v[4],
                    .state = if (flags & 4 != 0) .{ .version = v[7], .inner = try x.gpa.dupe(u8, data[77..]) } else null,
                };
            }
            if (flags & 2 != 0) rec.end = .{ .end_timestamp_ms = v[5], .end_checkpoint = v[6] };
            if (try x.epochs.fetchPut(x.gpa, rec.epoch, rec)) |kv| freeRecord(x.gpa, kv.value);
        }
    }

    const row_len = 80;

    fn appendPackageRow(x: *Index, original: *const [32]u8, version: u64, storage: *const [32]u8, checkpoint: ?u64) !void {
        const io = x.io orelse return;
        const f = x.pkg_log orelse return;
        var row: [row_len]u8 = undefined;
        encodeRow(&row, original, version, storage, checkpoint);
        try f.writePositionalAll(io, &row, x.pkg_log_end);
        x.pkg_log_end += row_len;
        x.pkg_dirty = true;
    }

    fn encodeRow(row: *[row_len]u8, original: *const [32]u8, version: u64, storage: *const [32]u8, checkpoint: ?u64) void {
        @memcpy(row[0..32], original);
        std.mem.writeInt(u64, row[32..40], version, .little);
        @memcpy(row[40..72], storage);
        std.mem.writeInt(u64, row[72..80], checkpoint orelse std.math.maxInt(u64), .little);
    }

    /// Makes the package rows appended so far durable; the dirty flag clears only once they are.
    fn syncRows(x: *Index) !void {
        const io = x.io orelse return;
        if (!x.pkg_dirty) return;
        if (x.pkg_log) |f| try f.sync(io);
        x.pkg_dirty = false;
    }

    /// Rebuilds every lineage from the log in one pass: rows sorted by (original, version, log
    /// order), each (original, version) folded with `putPackage`'s rule, one allocation per lineage.
    fn loadPackages(x: *Index) !void {
        const io = x.io.?;
        const dir = x.dir.?;
        const gpa = x.gpa;
        const data = dir.readFileAlloc(io, "pkgver.log", gpa, .limited(1 << 36)) catch |e| switch (e) {
            error.FileNotFound => &[_]u8{},
            else => return e,
        };
        defer if (data.len > 0) gpa.free(data);
        const whole = data.len - data.len % row_len;
        try x.buildLineages(data[0..whole]);
        const f = try dir.createFile(io, "pkgver.log", .{ .truncate = false, .read = true });
        x.pkg_log = f;
        x.pkg_log_end = whole; // a torn tail row is overwritten
    }

    fn buildLineages(x: *Index, rows: []const u8) !void {
        const gpa = x.gpa;
        const n = rows.len / row_len;
        const order = try gpa.alloc(u32, n);
        defer gpa.free(order);
        for (order, 0..) |*o, i| o.* = @intCast(i);
        const Ctx = struct {
            rows: []const u8,
            fn lt(c: @This(), a: u32, b: u32) bool {
                const ra = c.rows[@as(usize, a) * row_len ..][0..row_len];
                const rb = c.rows[@as(usize, b) * row_len ..][0..row_len];
                switch (std.mem.order(u8, ra[0..32], rb[0..32])) {
                    .lt => return true,
                    .gt => return false,
                    .eq => {},
                }
                const va = std.mem.readInt(u64, ra[32..40], .little);
                const vb = std.mem.readInt(u64, rb[32..40], .little);
                if (va != vb) return va < vb;
                return a < b;
            }
        };
        std.sort.pdq(u32, order, Ctx{ .rows = rows }, Ctx.lt);
        var i: usize = 0;
        var scratch: std.ArrayList(PkgVersion) = .empty;
        defer scratch.deinit(gpa);
        try x.lineages.ensureTotalCapacity(gpa, @intCast(@min(n, std.math.maxInt(u32))));
        while (i < n) {
            const first = rows[@as(usize, order[i]) * row_len ..][0..row_len];
            const original = first[0..32].*;
            scratch.clearRetainingCapacity();
            while (i < n) : (i += 1) {
                const row = rows[@as(usize, order[i]) * row_len ..][0..row_len];
                if (!std.mem.eql(u8, row[0..32], &original)) break;
                const cp_raw = std.mem.readInt(u64, row[72..80], .little);
                const e: PkgVersion = .{ .version = std.mem.readInt(u64, row[32..40], .little), .storage_id = row[40..72].*, .checkpoint = if (cp_raw == std.math.maxInt(u64)) null else cp_raw };
                if (scratch.items.len > 0 and scratch.items[scratch.items.len - 1].version == e.version) {
                    const last = &scratch.items[scratch.items.len - 1];
                    if (!(e.checkpoint == null and last.checkpoint != null)) last.* = e;
                } else try scratch.append(gpa, e);
            }
            const l = try gpa.create(Lineage);
            errdefer gpa.destroy(l);
            l.* = .{ .versions = try gpa.dupe(PkgVersion, scratch.items) };
            if (x.lineages.fetchPutAssumeCapacity(original, l)) |kv| reclaim(gpa, .{ .lineage = kv.value });
        }
    }

    // Watermark: two 32-byte slots (magic, seq, generation, checksum), written alternately and
    // fsynced; the valid slot with the higher generation wins, so a torn write loses at most the
    // newest value (the replay then covers one checkpoint more).
    const wm_magic: u64 = 0x314d575250455a; // "ZEPRWM1"

    fn wmChecksum(b: *const [24]u8) u64 {
        return std.hash.Wyhash.hash(0x6570776d, b);
    }

    /// `eoe-pkgs`: the epochs whose end-of-epoch package rows are in (u64 rows; a torn tail row
    /// is overwritten).
    fn loadEoePackages(x: *Index) !void {
        const io = x.io.?;
        const dir = x.dir.?;
        const data = dir.readFileAlloc(io, "eoe-pkgs", x.gpa, .limited(1 << 30)) catch |e| switch (e) {
            error.FileNotFound => &[_]u8{},
            else => return e,
        };
        defer if (data.len > 0) x.gpa.free(data);
        const whole = data.len - data.len % 8;
        var i: usize = 0;
        while (i < whole) : (i += 8) try x.eoe_pkgs.put(x.gpa, std.mem.readInt(u64, data[i..][0..8], .little), {});
        x.eoe_file = try dir.createFile(io, "eoe-pkgs", .{ .truncate = false, .read = true });
        x.eoe_end = whole;
    }

    fn loadWatermark(x: *Index) !void {
        const io = x.io.?;
        const f = try x.dir.?.createFile(io, "watermark", .{ .truncate = false, .read = true });
        x.wm_file = f;
        var buf: [64]u8 = @splat(0);
        const got = f.readPositionalAll(io, &buf, 0) catch 0;
        var best: ?struct { seq: u64, gen: u64 } = null;
        for (0..2) |slot| {
            if (got < (slot + 1) * 32) break;
            const b = buf[slot * 32 ..][0..32];
            if (std.mem.readInt(u64, b[0..8], .little) != wm_magic) continue;
            if (std.mem.readInt(u64, b[24..32], .little) != wmChecksum(b[0..24])) continue;
            const seq = std.mem.readInt(u64, b[8..16], .little);
            const gen = std.mem.readInt(u64, b[16..24], .little);
            if (best == null or gen > best.?.gen) best = .{ .seq = seq, .gen = gen };
        }
        if (best) |b| {
            x.watermark = b.seq;
            x.wm_gen = b.gen;
        }
    }

    fn persistWatermark(x: *Index, seq: u64) !void {
        if (x.io) |io| {
            const f = x.wm_file.?;
            const gen = x.wm_gen + 1;
            var b: [32]u8 = undefined;
            std.mem.writeInt(u64, b[0..8], wm_magic, .little);
            std.mem.writeInt(u64, b[8..16], seq, .little);
            std.mem.writeInt(u64, b[16..24], gen, .little);
            std.mem.writeInt(u64, b[24..32], wmChecksum(b[0..24]), .little);
            try f.writePositionalAll(io, &b, (gen % 2) * 32);
            try f.sync(io);
            x.wm_gen = gen;
        }
        x.watermark = seq;
    }
};

fn syncDir(io: Io, dir: Io.Dir) !void {
    const f: Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    try f.sync(io);
}

/// The lowest checkpoint the store holds at or below `hi` (the store keeps a contiguous window).
pub fn lowestStored(snap: *const store.Snapshot, hi: u64) u64 {
    var lo = hi;
    var step: u64 = 1;
    while (lo > 0) {
        const probe = lo -| step;
        if (snap.checkpoint(probe) == null) break;
        lo = probe;
        step *|= 2;
    }
    if (lo == 0) return 0;
    // the boundary is in (lo - step, lo]
    var a: u64 = lo -| step;
    var b: u64 = lo;
    while (a + 1 < b) {
        const mid = a + (b - a) / 2;
        if (snap.checkpoint(mid) != null) b = mid else a = mid;
    }
    return if (snap.checkpoint(a) != null) a else b;
}

/// `MovePackage::original_package_id()`: the package id at version 1, else the self address of
/// its first module (module_map is a BTreeMap, so the first in key order).
pub fn originalId(object_bytes: []const u8) ?[32]u8 {
    if (object_bytes.len < 41 or object_bytes[0] != 1) return null;
    var r = bcs.Reader.init(object_bytes[1..]);
    const id = (r.bytes(32) catch return null)[0..32].*;
    const version = r.int(u64) catch return null;
    if (version == 1) return id;
    const n = r.length() catch return null;
    if (n == 0) return null;
    // the module with the smallest name (BTreeMap order; BCS writes it sorted already)
    var best_name: ?[]const u8 = null;
    var best: []const u8 = &.{};
    for (0..n) |_| {
        const klen = r.length() catch return null;
        const key = r.bytes(klen) catch return null;
        const mlen = r.length() catch return null;
        const module = r.bytes(mlen) catch return null;
        if (best_name == null or std.mem.lessThan(u8, key, best_name.?)) {
            best_name = key;
            best = module;
        }
    }
    return selfAddress(best);
}

fn selfAddress(module: []const u8) ?[32]u8 {
    const mf = @import("move_format");
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const cfg: mf.BinaryConfig = .{};
    const res = mf.deserialize(arena.allocator(), module, &cfg) catch return null;
    return switch (res) {
        .ok => |cm| cm.selfAddress().*,
        .err => null,
    };
}

/// The live system state (wrapper 0x5 and its field) of a store snapshot.
pub fn liveState(snap: *const store.Snapshot) ?sysstate.State {
    const w = snap.liveObject(&sysstate.system_state_id) orelse return null;
    const wc = sysstate.moveContents(w.bytes) orelse return null;
    const ver = sysstate.wrapperVersion(wc) orelse return null;
    const fid = sysstate.u64FieldId(&sysstate.system_state_id, ver);
    const f = snap.liveObject(&fid) orelse return null;
    const fc = sysstate.moveContents(f.bytes) orelse return null;
    const inner = sysstate.innerOfField(fc) orelse return null;
    return .{ .version = ver, .inner = inner };
}

/// GetPackage `at_checkpoint`: the newest version whose row was published at or before `at`
/// (a floor row, checkpoint null, has always existed); sui-rpc-store `get_package_at_checkpoint`.
pub fn atCheckpoint(versions: []const PkgVersion, at: u64) ?PkgVersion {
    var i = versions.len;
    while (i > 0) {
        i -= 1;
        const v = versions[i];
        if (v.checkpoint == null or v.checkpoint.? <= at) return v;
    }
    return null;
}

// ---------------------------------------------------------------------- tests

const testing = std.testing;

/// A BCS value of `T` with every field zero/empty/first variant (synthetic blobs in tests).
fn zeroOf(comptime T: type) T {
    @setEvalBranchQuota(1_000_000);
    switch (@typeInfo(T)) {
        .int, .float => return 0,
        .bool => return false,
        .void => return {},
        .optional => return null,
        .array => |a| return @splat(zeroOf(a.child)),
        .@"enum" => |e| return @enumFromInt(e.field_values[0]),
        .pointer => |p| switch (p.size) {
            .slice => return &.{},
            else => return &comptime zeroOf(p.child),
        },
        .@"union" => |u| return @unionInit(T, u.field_names[0], zeroOf(u.field_types[0])),
        .@"struct" => |st| {
            var v: T = undefined;
            inline for (st.field_names, st.field_types) |name, FT| @field(v, name) = zeroOf(FT);
            if (@hasDecl(T, "bcs_min_wire") and @hasField(T, "items")) {
                const C = @typeInfo(@FieldType(T, "items")).pointer.child;
                v.items = &comptime [1]C{zeroOf(C)};
            }
            return v;
        },
        else => @compileError("zeroOf " ++ @typeName(T)),
    }
}

/// BCS Object bytes of a package `id` at `version` whose one module is `m` at address `self`.
fn testPackage(gpa: Allocator, id: [32]u8, version: u64, self: [32]u8) ![]u8 {
    const mf = @import("move_format");
    const module: mf.CompiledModule = .{
        .version = 6,
        .module_handles = &.{.{ .address = 0, .name = 0 }},
        .identifiers = &.{"m"},
        .address_identifiers = &.{self},
    };
    const code = try mf.serializeAlloc(gpa, &module, 6);
    defer gpa.free(code);
    var obj = zeroOf(types.Object);
    var pkg = zeroOf(types.gen.MovePackage);
    pkg.id = .{ .@"0" = .{ .@"0" = id } };
    pkg.version = .{ .@"0" = version };
    const entries = [_]@TypeOf(pkg.module_map).Entry{.{ .key = .{ .@"0" = "m" }, .value = code }};
    pkg.module_map = .{ .entries = &entries };
    obj.data = .{ .Package = pkg };
    obj.owner = .Immutable;
    return bcs.encodeAlloc(types.Object, gpa, &obj);
}

/// A CheckpointData blob (0x01 ++ BCS) at `seq` with one transaction that outputs `outputs`.
fn testBlob(gpa: Allocator, seq: u64, outputs: []const []const u8) ![]u8 {
    var ar = std.heap.ArenaAllocator.init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    var cd = zeroOf(types.CheckpointData);
    cd.checkpoint_summary.data.sequence_number = seq;
    cd.checkpoint_summary.data.timestamp_ms = 1000 * seq;
    cd.checkpoint_summary.auth_signature.signers_map = .{ .@"0" = &.{ 0x3a, 0x30, 0, 0, 0, 0, 0, 0 } }; // empty roaring bitmap
    var tx = zeroOf(types.gen.CheckpointTransaction);
    const objs = try a.alloc(types.Object, outputs.len);
    for (outputs, objs) |o, *d| d.* = try bcs.decode(types.Object, a, o);
    tx.output_objects = objs;
    cd.transactions = &.{tx};
    const body = try bcs.encodeAlloc(types.CheckpointData, a, &cd);
    const out = try gpa.alloc(u8, body.len + 1);
    out[0] = 1;
    @memcpy(out[1..], body);
    return out;
}

test "package lineage ordering and replacement" {
    var x = Index.initMemory(testing.allocator);
    defer x.deinit();
    const o: [32]u8 = @splat(1);
    const a: [32]u8 = @splat(2);
    const b: [32]u8 = @splat(3);
    try x.putPackage(&o, 3, &b, 10);
    try x.putPackage(&o, 1, &o, null);
    try x.putPackage(&o, 2, &a, 5);
    try x.putPackage(&o, 2, &a, null); // restored row does not replace the indexed one
    try x.putPackage(&o, 1, &o, 3); // an indexed row replaces the floor
    const l = x.lineage(&o);
    try testing.expectEqual(@as(usize, 3), l.len);
    try testing.expectEqual(@as(u64, 1), l[0].version);
    try testing.expectEqual(@as(?u64, 3), l[0].checkpoint);
    try testing.expectEqual(@as(?u64, 5), l[1].checkpoint);
    try testing.expectEqual(@as(u64, 3), l[2].version);
}

test "onCheckpoint: publish at 10, upgrade at 20; at_checkpoint and the lineage" {
    const gpa = testing.allocator;
    var x = Index.initMemory(gpa);
    defer x.deinit();
    const orig: [32]u8 = @splat(0xa1);
    const up: [32]u8 = @splat(0xb2);
    const p1 = try testPackage(gpa, orig, 1, orig);
    defer gpa.free(p1);
    const p2 = try testPackage(gpa, up, 2, orig); // upgrade: new id, modules keep the original address
    defer gpa.free(p2);
    try testing.expectEqualSlices(u8, &orig, &originalId(p2).?);
    const b10 = try testBlob(gpa, 10, &.{p1});
    defer gpa.free(b10);
    const b20 = try testBlob(gpa, 20, &.{p2});
    defer gpa.free(b20);
    try testing.expectEqual(@as(?u64, null), x.highestIndexed());
    try x.onCheckpoint(10, b10);
    try x.commit(10);
    try x.onCheckpoint(20, b20);
    try x.commit(20);
    try testing.expectEqual(@as(?u64, 20), x.highestIndexed());
    const l = x.lineage(&orig);
    try testing.expectEqual(@as(usize, 2), l.len);
    try testing.expectEqual(PkgVersion{ .version = 1, .storage_id = orig, .checkpoint = 10 }, l[0]);
    try testing.expectEqual(PkgVersion{ .version = 2, .storage_id = up, .checkpoint = 20 }, l[1]);
    try testing.expectEqual(@as(?PkgVersion, null), atCheckpoint(l, 9));
    try testing.expectEqual(@as(u64, 1), atCheckpoint(l, 15).?.version);
    try testing.expectEqual(@as(u64, 2), atCheckpoint(l, 20).?.version);
    // a replay of the same checkpoint changes nothing; a later floor does not override
    try x.onCheckpoint(20, b20);
    try x.onRestoredObject(&up, 2, p2);
    try testing.expectEqual(@as(?u64, 20), x.lineage(&orig)[1].checkpoint);
    // superseded lineages are freed once no reader holds them
    const tok = x.enter();
    const held = x.lineage(&orig);
    try x.onRestoredObject(&@as([32]u8, @splat(0xc3)), 1, p1); // another lineage (orig of p1 is orig: no-op)
    try x.putPackage(&orig, 3, &@as([32]u8, @splat(0xd4)), 21);
    x.reclaimRetired();
    try testing.expect(!x.rcu.idle()); // the reader still holds the old lineage
    try testing.expectEqual(@as(u64, 2), held[1].version);
    x.exit(tok);
    x.reclaimRetired();
    x.reclaimRetired();
    try testing.expect(x.rcu.idle());
}

test "persisted rows, watermark and epoch records survive a reopen; lineages rebuilt in one pass" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const base = pb[0..try tmp.dir.realPath(io, &pb)];
    const path = try std.fs.path.join(gpa, &.{ base, "rpc" });
    defer gpa.free(path);
    const o: [32]u8 = @splat(7);
    {
        const x = try Index.open(gpa, io, path);
        defer x.deinit();
        try testing.expectEqual(@as(?u64, null), x.watermark);
        var v: u64 = 1;
        while (v <= 300) : (v += 1) {
            var sid: [32]u8 = @splat(0);
            std.mem.writeInt(u64, sid[0..8], v, .little);
            try x.putPackage(&o, v, &sid, if (v % 2 == 0) v else null);
            if (v % 50 == 0) try x.commit(v);
        }
        try x.putPackage(&o, 4, &@as([32]u8, @splat(0)), null); // floor after an indexed row: ignored
        try x.putEpoch(9, .{ .protocol_version = 1, .reference_gas_price = 2, .start_timestamp_ms = 3, .start_checkpoint = 4, .state = .{ .version = 2, .inner = "state" } }, null);
        try x.putEpoch(9, null, .{ .end_timestamp_ms = 5, .end_checkpoint = 6 });
        try x.commit(301);
        try testing.expect(x.rcu.idle());
    }
    const x = try Index.open(gpa, io, path);
    defer x.deinit();
    try testing.expectEqual(@as(?u64, 301), x.watermark);
    try testing.expectEqual(@as(?u64, null), x.highestIndexed()); // nothing served before seed
    const l = x.lineage(&o);
    try testing.expectEqual(@as(usize, 300), l.len);
    for (l, 1..) |e, v| {
        try testing.expectEqual(@as(u64, v), e.version);
        try testing.expectEqual(@as(u64, v), std.mem.readInt(u64, e.storage_id[0..8], .little));
        try testing.expectEqual(if (v % 2 == 0) @as(?u64, v) else null, e.checkpoint);
    }
    try testing.expect(x.rcu.idle());
    const r = x.epoch(9).?;
    try testing.expectEqualStrings("state", r.start.?.state.?.inner);
    try testing.expectEqual(@as(u64, 6), r.end.?.end_checkpoint);
}

test "seed: live-set floors and stored-checkpoint replay on a store the index never saw" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const base = pb[0..try tmp.dir.realPath(io, &pb)];
    const sdir = try std.fs.path.join(gpa, &.{ base, "store" });
    defer gpa.free(sdir);
    var cfg: store.Config = .{ .dir = sdir, .max_live_objects = 1 << 10, .max_object_versions = 1 << 10, .max_transactions = 1 << 8, .max_checkpoints = 1 << 6, .max_batch_bytes = 1 << 24, .max_batch_objects = 1 << 10, .max_segments = 4, .segment_reserve = 1 << 22, .seed = 7 };
    var h = try store.openDir(gpa, io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    const orig: [32]u8 = @splat(0x11);
    const up: [32]u8 = @splat(0x22);
    const p1 = try testPackage(gpa, orig, 1, orig);
    defer gpa.free(p1);
    const p2 = try testPackage(gpa, up, 2, orig);
    defer gpa.free(p2);
    var ar = std.heap.ArenaAllocator.init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    // checkpoint 5: the package is live (a restore or an earlier node run put it there)
    {
        var sum = zeroOf(types.gen.CheckpointSummary);
        sum.sequence_number = 5;
        const sb = try bcs.encodeAlloc(types.gen.CheckpointSummary, a, &sum);
        const cb = try bcs.encodeAlloc(types.CheckpointContents, a, &zeroOf(types.CheckpointContents));
        const b = try h.store.begin(5, 0);
        try b.putObject(&orig, 1, &types.digest.objectDigest(p1), p1);
        try b.checkpoint(sb, cb);
        try h.store.commit(b);
    }
    // checkpoint 6: one transaction upgrades it (effects V2 PackageWrite)
    {
        var sum = zeroOf(types.gen.CheckpointSummary);
        sum.sequence_number = 6;
        const sb = try bcs.encodeAlloc(types.gen.CheckpointSummary, a, &sum);
        const tx_digest: [32]u8 = @splat(0x66);
        var contents = zeroOf(types.gen.CheckpointContentsV1);
        var ed = zeroOf(types.ExecutionDigests);
        ed.transaction.@"0".@"0" = tx_digest;
        contents.transactions = &.{ed};
        const cb = try bcs.encodeAlloc(types.CheckpointContents, a, &types.CheckpointContents{ .V1 = contents });
        var eff = zeroOf(types.gen.TransactionEffectsV2);
        var ch = zeroOf(types.gen.EffectsObjectChange);
        ch.output_state = .{ .PackageWrite = .{ .{ .@"0" = 2 }, zeroOf(types.ObjectDigest) } };
        eff.changed_objects = &.{.{ .{ .@"0" = .{ .@"0" = up } }, ch }};
        const eb = try bcs.encodeAlloc(types.TransactionEffects, a, &types.TransactionEffects{ .V2 = eff });
        const b = try h.store.begin(6, 0);
        try b.putObject(&up, 2, &types.digest.objectDigest(p2), p2);
        try b.transaction(&tx_digest, &@as([32]u8, @splat(0)), "tx", eb, null);
        try b.checkpoint(sb, cb);
        try h.store.commit(b);
    }
    const rpath = try std.fs.path.join(gpa, &.{ base, "rpc" });
    defer gpa.free(rpath);
    {
        const x = try Index.open(gpa, io, rpath);
        defer x.deinit();
        var snap = h.store.snapshot();
        defer snap.release();
        const rep = try x.seed(&snap);
        try testing.expectEqual(@as(u64, 2), rep.floor_rows);
        try testing.expectEqual(@as(?u64, 5), rep.replay_from);
        try testing.expectEqual(@as(u64, 2), rep.replayed);
        try testing.expectEqual(@as(?u64, 6), x.highestIndexed());
        const l = x.lineage(&orig);
        try testing.expectEqual(@as(usize, 2), l.len);
        try testing.expectEqual(@as(?u64, null), l[0].checkpoint); // floor: published before the window
        try testing.expectEqual(@as(?u64, 6), l[1].checkpoint); // the replay overwrote the floor
        try testing.expectEqual(@as(u64, 2), atCheckpoint(l, 6).?.version);
        try testing.expectEqual(@as(u64, 1), atCheckpoint(l, 5).?.version);
    }
    // a reopen at the store tip replays nothing
    const x = try Index.open(gpa, io, rpath);
    defer x.deinit();
    var snap = h.store.snapshot();
    defer snap.release();
    const rep = try x.seed(&snap);
    try testing.expectEqual(@as(u64, 0), rep.replayed);
    try testing.expectEqual(@as(u64, 0), rep.live_objects);
    try testing.expectEqual(@as(?u64, 6), x.highestIndexed());
    try testing.expectEqual(@as(usize, 2), x.lineage(&orig).len);
}

test "seed after an in-place system package upgrade keeps the prior version (ListPackageVersions 0x1)" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const base = pb[0..try tmp.dir.realPath(io, &pb)];
    const sdir = try std.fs.path.join(gpa, &.{ base, "store" });
    defer gpa.free(sdir);
    var cfg: store.Config = .{ .dir = sdir, .max_live_objects = 1 << 10, .max_object_versions = 1 << 10, .max_transactions = 1 << 8, .max_checkpoints = 1 << 6, .max_batch_bytes = 1 << 24, .max_batch_objects = 1 << 10, .max_segments = 4, .segment_reserve = 1 << 22, .seed = 7 };
    var h = try store.openDir(gpa, io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    var sys: [32]u8 = @splat(0);
    sys[31] = 1;
    const p25 = try testPackage(gpa, sys, 25, sys);
    defer gpa.free(p25);
    const p26 = try testPackage(gpa, sys, 26, sys);
    defer gpa.free(p26);
    var ar = std.heap.ArenaAllocator.init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    // checkpoint 5: 0x1 at version 25 is live
    {
        var sum = zeroOf(types.gen.CheckpointSummary);
        sum.sequence_number = 5;
        const sb = try bcs.encodeAlloc(types.gen.CheckpointSummary, a, &sum);
        const cb = try bcs.encodeAlloc(types.CheckpointContents, a, &zeroOf(types.CheckpointContents));
        const b = try h.store.begin(5, 0);
        try b.putObject(&sys, 25, &types.digest.objectDigest(p25), p25);
        try b.checkpoint(sb, cb);
        try h.store.commit(b);
    }
    // checkpoint 6: the change-epoch transaction upgrades 0x1 in place to 26 (input Exist(25))
    {
        var sum = zeroOf(types.gen.CheckpointSummary);
        sum.sequence_number = 6;
        const sb = try bcs.encodeAlloc(types.gen.CheckpointSummary, a, &sum);
        const tx_digest: [32]u8 = @splat(0x67);
        var contents = zeroOf(types.gen.CheckpointContentsV1);
        var ed = zeroOf(types.ExecutionDigests);
        ed.transaction.@"0".@"0" = tx_digest;
        contents.transactions = &.{ed};
        const cb = try bcs.encodeAlloc(types.CheckpointContents, a, &types.CheckpointContents{ .V1 = contents });
        var eff = zeroOf(types.gen.TransactionEffectsV2);
        var ch = zeroOf(types.gen.EffectsObjectChange);
        ch.input_state = .{ .Exist = .{ .{ .{ .@"0" = 25 }, zeroOf(types.ObjectDigest) }, .Immutable } };
        ch.output_state = .{ .PackageWrite = .{ .{ .@"0" = 26 }, zeroOf(types.ObjectDigest) } };
        eff.changed_objects = &.{.{ .{ .@"0" = .{ .@"0" = sys } }, ch }};
        const eb = try bcs.encodeAlloc(types.TransactionEffects, a, &types.TransactionEffects{ .V2 = eff });
        const b = try h.store.begin(6, 0);
        try b.putObject(&sys, 26, &types.digest.objectDigest(p26), p26);
        try b.transaction(&tx_digest, &@as([32]u8, @splat(0)), "tx", eb, null);
        try b.checkpoint(sb, cb);
        try h.store.commit(b);
    }
    const rpath = try std.fs.path.join(gpa, &.{ base, "rpc" });
    defer gpa.free(rpath);
    {
        // a fresh index: the live set holds only 0x1 v26; the replay of checkpoint 6 restores 25
        const x = try Index.open(gpa, io, rpath);
        defer x.deinit();
        var snap = h.store.snapshot();
        defer snap.release();
        _ = try x.seed(&snap);
        const l = x.lineage(&sys);
        try testing.expectEqual(@as(usize, 2), l.len);
        try testing.expectEqual(@as(u64, 25), l[0].version);
        try testing.expectEqual(@as(?u64, null), l[0].checkpoint); // floor: live before the window
        try testing.expectEqualSlices(u8, &sys, &l[0].storage_id);
        try testing.expectEqual(@as(u64, 26), l[1].version);
        try testing.expectEqual(@as(?u64, 6), l[1].checkpoint);
        try testing.expectEqual(@as(u64, 25), atCheckpoint(l, 5).?.version);
        try testing.expectEqual(@as(u64, 26), atCheckpoint(l, 6).?.version);
    }
    // the floor row persisted: a reopen lists both versions without replaying
    const x = try Index.open(gpa, io, rpath);
    defer x.deinit();
    var snap = h.store.snapshot();
    defer snap.release();
    const rep = try x.seed(&snap);
    try testing.expectEqual(@as(u64, 0), rep.replayed);
    try testing.expectEqual(@as(usize, 2), x.lineage(&sys).len);
}

test "eoe-pkgs: an epoch needs its end-of-epoch checkpoint until its package rows are in, and the mark persists" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const base = pb[0..try tmp.dir.realPath(io, &pb)];
    const rpath = try std.fs.path.join(gpa, &.{ base, "rpc" });
    defer gpa.free(rpath);
    const st: sysstate.State = .{ .version = 2, .inner = "state" };
    {
        const x = try Index.open(gpa, io, rpath);
        defer x.deinit();
        // complete records: end of 7 and a full start of 8
        try x.putEpoch(7, null, .{ .end_timestamp_ms = 70, .end_checkpoint = 700 });
        try x.putEpoch(8, .{ .protocol_version = 1, .reference_gas_price = 1, .start_timestamp_ms = 71, .start_checkpoint = 701, .state = st }, null);
        // an index from before the package rows still needs the checkpoint once
        try testing.expect(x.epochNeeds(7, true));
        try x.markEoePackages(7);
        try testing.expect(!x.epochNeeds(7, true));
        try x.markEoePackages(7); // idempotent: one row
        try testing.expect(x.epochNeeds(9, false));
    }
    const x = try Index.open(gpa, io, rpath);
    defer x.deinit();
    try testing.expect(!x.epochNeeds(7, true));
    try testing.expectEqual(@as(u64, 8), x.eoe_end);
}
