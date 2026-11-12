//! Read sets: what serve needs beyond the certified outputs to answer a transaction's `effects`,
//! `objects` and `balance_changes` masks (sui.rpc.v2), stored in the same durable group as the
//! checkpoint (follower `Observer.on_batch`).
//!
//!   * Input object versions. The blob carries each transaction's modified inputs; the archive
//!     proto's object set (`convert.Aux`) adds read-only consensus objects, immutable inputs,
//!     packages and loaded runtime objects. Each version the store does not hold yet is written with
//!     `Batch.putHistorical`: readable by (id, version), never part of the live set, so nothing
//!     here can change live state, `latest`, execution inputs or a later check of outputs. A
//!     version the store holds only in an older segment gets an xref record (`Batch.putXref`,
//!     ~64 bytes) naming those bytes instead of a copy (`inputAction`).
//!   * Each transaction's `unchanged_loaded_runtime_objects` list, under the key
//!     (transaction digest, version `loaded_version`). Object versions are at most i64::MAX
//!     (Rust `SequenceNumber::MAX`), so that key never names an object version, and a transaction
//!     digest is not an object id.
//!
//! Trust. The certified checkpoint names a digest for most inputs: effects input states
//! (`changed_objects` Exist, V1 `shared_objects`), read-only consensus roots
//! (`unchanged_consensus_objects` ReadOnlyRoot) and the transaction's own object and gas
//! references. Those are checked and a mismatch is never stored. Packages and loaded runtime
//! objects are the archive's word (counted as `unverified`): `unchanged_loaded_runtime_objects`
//! is not part of the certified effects, so the archive's own reference digest for one is only
//! checked for consistency (an object that disagrees is not stored). A node started from a formal
//! snapshot already holds most of them, verified by the snapshot's state commitment.
//!
//! An edge that keeps read sets (`History.edge`, docs/EDGE.md section 12) builds the same rows
//! from less: its blobs carry no input objects and its aux records hold loaded lists only (from
//! its core's feed, or cut from the archive's record by the fallback). The keys of every
//! transaction's object set are derived from the certified transaction and effects plus the
//! list, and every one of them must be an object version the edge's own store already holds: an
//! xref keeps it readable, nothing is ever copied in. See `onBatchEdge`.
//!
//! The read-set mark (`read_set_version`): one record per checkpoint whose read set this store
//! holds whole, written with the checkpoint (`History.mark_read_sets`). It is what lets a node
//! say, per checkpoint, "my answers under effects, balance_changes and objects are complete":
//! an edge answers those masks itself only where the mark is, and a node sends read sets in
//! its edge feed only for marked checkpoints.
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const sync = @import("sync");
const exec = @import("exec");
const serve = @import("serve");
const convert = @import("convert.zig");
const Atomic = std.atomic.Value(u64);

/// Version under which a transaction's loaded runtime object list is stored.
pub const loaded_version: u64 = std.math.maxInt(u64);

/// Version under which a checkpoint the node built itself (p2p_exec.zig) is marked: an aux
/// record `(p2pMarkId(seq), p2p_built_version)` in the checkpoint's own commit group, so the
/// store says which checkpoints' read sets are deepwave's own word and still to be compared with
/// sui-node's (reconcile.zig). Like `loaded_version` it is above every object version; the
/// store's own aux keys are u64::MAX - 1 to - 3.
pub const p2p_built_version: u64 = std.math.maxInt(u64) - 8;

/// The marker's id: a fixed tag and the sequence number (never an object id: those are hashes).
pub fn p2pMarkId(seq: u64) [32]u8 {
    var id: [32]u8 = @splat(0);
    const tag = "zui p2p-built checkpoint";
    @memcpy(id[0..tag.len], tag);
    std.mem.writeInt(u64, id[24..32], seq, .little);
    return id;
}

/// Whether checkpoint `seq` was stored from a p2p build (and is still in the history window).
pub fn p2pBuilt(snap: *const store.Snapshot, seq: u64) bool {
    return snap.objectAt(&p2pMarkId(seq), p2p_built_version) != null;
}

/// Version under which a checkpoint whose whole read set the store holds is marked: an aux
/// record `(readSetMarkId(seq), read_set_version)` in the checkpoint's own commit group, kept
/// exactly as long as the checkpoint. Above every object version, like the other aux keys.
pub const read_set_version: u64 = std.math.maxInt(u64) - 9;

/// The mark's id: a fixed tag and the sequence number (never an object id: those are hashes).
pub fn readSetMarkId(seq: u64) [32]u8 {
    var id: [32]u8 = @splat(0);
    const tag = "zui read set, checkpoint";
    @memcpy(id[0..tag.len], tag);
    std.mem.writeInt(u64, id[24..32], seq, .little);
    return id;
}

/// Whether the store holds the whole read set of checkpoint `seq` (and the checkpoint is still
/// in the history window): every transaction's loaded runtime object list as the node's source
/// gave it, and every object version of every transaction's object set readable for as long as
/// the checkpoint is. A checkpoint stored before marks were written, or without `mark_read_sets`,
/// has none.
pub fn readSetHeld(snap: *const store.Snapshot, seq: u64) bool {
    const v = snap.objectAt(&readSetMarkId(seq), read_set_version) orelse return false;
    return v.len == 8 and std.mem.readInt(u64, v[0..8], .little) == seq;
}

/// One loaded runtime object in the stored list: `version` u64 le, then the 32-byte id. This is
/// the in-memory layout of `serve.objset.Ref` (checked at compile time), so the provider hands
/// serve the stored bytes without copying.
pub const entry_len = 40;

/// The same layout as `serve.objset.Ref`, for readers outside serve.
pub const LoadedEntry = struct { id: [32]u8, version: u64 };

pub const Stats = struct {
    /// Object versions written as historical records.
    put: Atomic = .init(0),
    /// ... of which the certified checkpoint named the digest.
    verified: Atomic = .init(0),
    /// ... of which nothing certified names a digest (packages, loaded runtime objects, even when
    /// the archive's own loaded-object reference names one).
    unverified: Atomic = .init(0),
    /// Archive objects whose digest differs from the certified one, or from the archive's own
    /// loaded-object reference (never stored).
    rejected: Atomic = .init(0),
    /// Versions skipped because the store already holds them.
    present: Atomic = .init(0),
    /// Versions held only in an older segment, referenced with an xref record instead of a copy.
    xref: Atomic = .init(0),
    /// Transactions with a stored loaded runtime object list.
    loaded_lists: Atomic = .init(0),
    /// Checkpoints whose aux record was missing (a `.chk` source without `.aux`).
    no_aux: Atomic = .init(0),
    /// Checkpoints marked as holding their whole read set (`read_set_version`).
    marked: Atomic = .init(0),
    /// Edge only. Checkpoints whose lists failed a check (not stored, not marked): a list out of
    /// sui-node's form, one naming an object its transaction changed, or a package.
    edge_rejected: Atomic = .init(0),
    /// Edge only. Checkpoints with lists that named, or whose transactions read, an object
    /// version this store does not hold (not marked: their reads are the core's to answer).
    edge_incomplete: Atomic = .init(0),
    /// Edge only. Object versions of those checkpoints that were not held.
    edge_missing_objects: Atomic = .init(0),
    /// Edge only. Checkpoints marked by lists that came after them (the re-ask, `planLate`).
    late_marked: Atomic = .init(0),
    /// Edge only. Late lists that passed their checks but were not written (an epoch changed
    /// before the next commit group, or that group had no room): the checkpoint stays unmarked.
    late_dropped: Atomic = .init(0),
};

const Key = exec.objects.Key;

pub const History = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// Where `<seq>.aux` files are (the spool, or a directory source).
    aux_dir: ?Io.Dir,
    stats: Stats = .{},
    idx: types.CheckpointIndex,
    arena: std.heap.ArenaAllocator,
    buf: std.ArrayList(u8) = .empty,
    /// Mark the checkpoints built here (`p2p_built_version`); set by the node when it
    /// reconciles them (reconcile.zig).
    mark_built: bool = false,
    /// The last `onBatch`'s checkpoint was built here (and marked).
    last_built: bool = false,
    /// Write the read-set mark (`read_set_version`) for every checkpoint whose read set was
    /// stored whole. Set by the node for `--edge-read-sets on`; off, no store gains a record.
    mark_read_sets: bool = false,
    /// An edge that keeps read sets: `onBatchEdge` instead of the full path.
    edge: bool = false,
    /// Late lists checked and planned, waiting for the next commit group (`stageLate`).
    late_mu: std.atomic.Mutex = .unlocked,
    late: ?*LatePlan = null,
    /// Told of every staged plan when a commit group takes it (`writeLate`, follower thread):
    /// written with its mark, or dropped unmarked. The re-ask counts its outcomes by it.
    late_hook: ?LateHook = null,

    pub fn init(gpa: std.mem.Allocator, io: Io, aux_dir: ?Io.Dir) !History {
        return .{ .gpa = gpa, .io = io, .aux_dir = aux_dir, .idx = try types.CheckpointIndex.init(gpa), .arena = .init(gpa) };
    }

    pub fn deinit(h: *History) void {
        while (h.late) |p| {
            h.late = p.next;
            p.destroy();
        }
        h.idx.deinit(h.gpa);
        h.arena.deinit();
        h.buf.deinit(h.gpa);
    }

    /// Reads `<seq>.aux` (empty when absent).
    fn readAux(h: *History, seq: u64) ![]const u8 {
        h.buf.clearRetainingCapacity();
        const d = h.aux_dir orelse return &.{};
        var nb: [48]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, "{d}.aux", .{seq}) catch unreachable;
        const f = d.openFile(h.io, name, .{}) catch |e| switch (e) {
            error.FileNotFound => return &.{},
            else => return e,
        };
        defer f.close(h.io);
        const size: usize = @intCast((try f.stat(h.io)).size);
        try h.buf.resize(h.gpa, size);
        if (try f.readPositionalAll(h.io, h.buf.items, 0) != size) return error.ShortRead;
        return h.buf.items;
    }

    /// Whether the spool says checkpoint `seq` was built here: `<seq>.p2p` beside its blob
    /// (source.zig `writeSpoolBuilt`).
    fn builtHere(h: *History, seq: u64) bool {
        const d = h.aux_dir orelse return false;
        var nb: [48]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, "{d}.p2p", .{seq}) catch unreachable;
        _ = d.statFile(h.io, name, .{}) catch return false;
        return true;
    }

    /// The follower's batch hook: adds the checkpoint's read set to its open batch.
    pub fn onBatch(h: *History, st: *store.Store, seq: u64, c: *const sync.verify.Checked, blob: []const u8, b: *store.Batch) !void {
        if (h.edge) {
            try h.onBatchEdge(st, seq, c, blob, b);
            return h.writeLate(b);
        }
        _ = h.arena.reset(.retain_capacity);
        const a = h.arena.allocator();
        const rejected_before = h.stats.rejected.load(.monotonic);
        h.last_built = h.mark_built and h.builtHere(seq);
        if (h.last_built) {
            var le: [8]u8 = undefined;
            std.mem.writeInt(u64, &le, seq, .little);
            try b.putHistorical(&p2pMarkId(seq), p2p_built_version, &@as([32]u8, @splat(0)), &le);
        }
        const aux_bytes = try h.readAux(seq);
        const aux: ?convert.Aux = if (aux_bytes.len == 0) null else try convert.Aux.parse(a, aux_bytes);
        if (aux == null) _ = h.stats.no_aux.fetchAdd(1, .monotonic);
        try types.indexCheckpointData(blob, &h.idx);
        const n_tx = c.txs.len;
        if (aux) |x| if (x.loaded.len != n_tx) return error.AuxTransactionCount;

        // Versions this checkpoint writes (the follower puts them) and the digests it certifies.
        var outputs: std.AutoHashMapUnmanaged(Key, void) = .empty;
        var claims: std.AutoHashMapUnmanaged(Key, [32]u8) = .empty;
        // Input versions this checkpoint supersedes (mutated, deleted or wrapped inputs).
        var consumed: std.AutoHashMapUnmanaged(Key, void) = .empty;
        // The archive's own loaded runtime object references (not part of the certified effects):
        // an object that disagrees with one is not stored, but agreeing with it proves nothing.
        var aux_refs: std.AutoHashMapUnmanaged(Key, [32]u8) = .empty;
        for (c.txs, 0..) |plan, i| {
            for (plan.puts) |p| try outputs.put(a, .{ .id = p.id.*, .version = p.version }, {});
            const t = h.idx.txAt(i);
            try claimsOf(a, &claims, &consumed, t.data.slice(blob), t.effects.slice(blob));
            if (aux) |x| for (x.loaded[i]) |r| if (r.digest) |d| try aux_refs.put(a, .{ .id = r.id, .version = r.version }, d);
        }

        var snap = st.snapshot();
        defer snap.release();
        var done: std.AutoHashMapUnmanaged(Key, void) = .empty;
        // Modified inputs carried by the blob, then the archive's other objects.
        for (0..n_tx) |i| {
            const t = h.idx.txAt(i);
            for (h.idx.objs[t.in_first..][0..t.in_count]) |r| try h.putOne(a, &snap, b, &outputs, &claims, &consumed, &aux_refs, &done, r.slice(blob));
        }
        if (aux) |x| for (x.objects) |raw| try h.putOne(a, &snap, b, &outputs, &claims, &consumed, &aux_refs, &done, raw);

        // Loaded runtime object lists.
        if (aux) |x| for (x.loaded, c.txs) |list, plan| {
            if (list.len == 0) continue;
            const bytes = try a.alloc(u8, list.len * entry_len);
            for (list, 0..) |r, j| {
                std.mem.writeInt(u64, bytes[j * entry_len ..][0..8], r.version, .little);
                bytes[j * entry_len + 8 ..][0..32].* = r.id;
            }
            try b.putHistorical(plan.tx_digest, loaded_version, &@as([32]u8, @splat(0)), bytes);
            _ = h.stats.loaded_lists.fetchAdd(1, .monotonic);
        };
        // The read set as the source gave it is in this batch: every list, every object of the
        // record that passed its digest check. One that did not leaves the checkpoint unmarked.
        if (h.mark_read_sets and aux != null and h.stats.rejected.load(.monotonic) == rejected_before) try h.mark(b, seq);
    }

    fn mark(h: *History, b: *store.Batch, seq: u64) !void {
        var le: [8]u8 = undefined;
        std.mem.writeInt(u64, &le, seq, .little);
        try b.putHistorical(&readSetMarkId(seq), read_set_version, &@as([32]u8, @splat(0)), &le);
        _ = h.stats.marked.fetchAdd(1, .monotonic);
    }

    /// `onBatch` on an edge that keeps read sets (docs/EDGE.md section 12).
    ///
    /// What it has: the feed-form blob (no input objects) and, when the checkpoint came with
    /// read sets, an aux record of loaded lists only. What it writes:
    ///
    /// 1. Always: an xref for every input version this checkpoint's effects supersede, when the
    ///    store holds that version only in an older segment. These keys are certified (the
    ///    effects name them), so this needs nothing from the core, and it is what keeps the
    ///    read sets of earlier checkpoints readable for as long as sui-node keeps them.
    /// 2. With lists that pass every check, and every key of every transaction's object set
    ///    (`serve.txobjects.keys`: the certified keys plus the list) held by this store: the
    ///    xrefs of the remaining keys, the lists, and the read-set mark.
    ///
    /// Checks on a list (the core's word; nothing certified names it): sui-node's form (ids
    /// strictly ascending, real versions); no id its transaction's effects change (sui-node
    /// removes those); every entry the object as it was when the transaction ran, that is the
    /// version an earlier transaction of this checkpoint left, else the version live in this
    /// store before the checkpoint; and no entry a package (sui-node filters packages out). A
    /// held version whose digest is certified (inputs, read-only consensus roots) must carry
    /// that digest. What no edge can check is whether the VM loaded exactly these objects:
    /// an entry left out, or one added for another live object the transaction did not change.
    ///
    /// Nothing is ever copied in: object bytes come from this store only. A list that fails a
    /// check, or any key this store does not hold, leaves the checkpoint without its mark and
    /// without lists, and its reads under effects, balance_changes and objects go to the core.
    fn onBatchEdge(h: *History, st: *store.Store, seq: u64, c: *const sync.verify.Checked, blob: []const u8, b: *store.Batch) !void {
        _ = h.arena.reset(.retain_capacity);
        const a = h.arena.allocator();
        h.last_built = false;
        const aux_bytes = try h.readAux(seq);
        try types.indexCheckpointData(blob, &h.idx);
        const n_tx = c.txs.len;
        // A record that does not parse or does not fit the checkpoint is a missing one here: the
        // checkpoint itself is certified and applies either way.
        var rejected = false;
        const lists: ?[]const []const convert.LoadedRef = blk: {
            if (aux_bytes.len == 0) {
                _ = h.stats.no_aux.fetchAdd(1, .monotonic);
                break :blk null;
            }
            const x = convert.Aux.parse(a, aux_bytes) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    rejected = true;
                    break :blk null;
                },
            };
            if (x.loaded.len != n_tx) {
                rejected = true;
                break :blk null;
            }
            break :blk x.loaded;
        };

        // Versions this checkpoint writes, with the object's kind byte (0 Move, 1 package).
        var outputs: std.AutoHashMapUnmanaged(Key, u8) = .empty;
        var claims: std.AutoHashMapUnmanaged(Key, [32]u8) = .empty;
        var consumed: std.AutoHashMapUnmanaged(Key, void) = .empty;
        const decoded = try a.alloc(Decoded, n_tx);
        for (decoded, 0..) |*d, i| {
            const t = h.idx.txAt(i);
            for (h.idx.objs[t.out_first..][0..t.out_count]) |r| {
                const raw = r.slice(blob);
                const k = exec.objects.keyOf(raw) catch return error.BadAuxObject;
                try outputs.put(a, k, raw[0]);
            }
            d.td = try bcs.decode(types.TransactionData, a, t.data.slice(blob));
            d.fx = try bcs.decode(types.TransactionEffects, a, t.effects.slice(blob));
            try claimsOfDecoded(a, &claims, &consumed, &d.td, &d.fx);
        }

        var snap = st.snapshot();
        defer snap.release();
        // Keys looked at, and whether this store holds them (with the certified digest, where
        // one is named).
        var done: std.AutoHashMapUnmanaged(Key, Held) = .empty;
        // The batch has no room left for a read-set record: the certified records came first
        // and stay; the checkpoint goes without its mark.
        var no_room = false;

        // 1. The input versions this checkpoint supersedes. One the store does not hold is
        // counted in step 2, if a transaction's object set has it.
        var it = consumed.keyIterator();
        while (it.next()) |k| {
            if (outputs.contains(k.*)) continue;
            const f = try snap.objectFind(&k.id, k.version);
            const ok = if (f) |x| (if (claims.get(k.*)) |want| std.mem.eql(u8, &want, &x.ref.digest) else true) else false;
            try done.put(a, k.*, if (ok) .yes else .no);
            if (!ok) continue;
            switch (actionOf(f, b.epoch, true)) {
                .present => _ = h.stats.present.fetchAdd(1, .monotonic),
                .xref => |target| {
                    b.putXref(&k.id, k.version, target) catch |e| {
                        if (!noRoom(e)) return e;
                        no_room = true;
                        break;
                    };
                    _ = h.stats.xref.fetchAdd(1, .monotonic);
                },
                .copy => unreachable, // `ok`: found
            }
        }

        // 2. With lists: check them, then the rest of every transaction's object set.
        var chk: Checked = .{};
        if (lists) |ls| chk = try checkLists(a, &snap, b.epoch, ls, decoded, &outputs, &claims, &done, .{});
        if (chk.rejected) rejected = true;
        const missing = chk.missing;
        const xrefs = chk.xrefs;
        const present = chk.present;

        if (rejected) {
            _ = h.stats.edge_rejected.fetchAdd(1, .monotonic);
            std.log.warn("history: checkpoint {d}: the read sets its source sent fail the edge's checks; not stored, its reads go to the core", .{seq});
            return;
        }
        const ls = lists orelse return;
        if (missing != 0 or no_room) {
            _ = h.stats.edge_incomplete.fetchAdd(1, .monotonic);
            _ = h.stats.edge_missing_objects.fetchAdd(missing, .monotonic);
            return;
        }
        h.writeEdge(a, b, seq, xrefs, ls, c.txs) catch |e| {
            if (!noRoom(e)) return e;
            // what was written stays (harmless without the mark); the checkpoint is not marked
            _ = h.stats.edge_incomplete.fetchAdd(1, .monotonic);
            return;
        };
        _ = h.stats.present.fetchAdd(present, .monotonic);
    }

    /// Lists that arrived after their checkpoint was applied (the re-ask, reask.zig), checked
    /// and planned by `planLate` on the re-ask thread: written by the follower into the next
    /// commit group it opens (`writeLate`). The store has one writer and a commit group per new
    /// checkpoint, so a late write cannot be a group of its own: it joins the next one, which is
    /// atomic like any other, and its mark is its last record.
    pub fn stageLate(h: *History, plan: *LatePlan) void {
        while (!h.late_mu.tryLock()) std.atomic.spinLoopHint();
        defer h.late_mu.unlock();
        plan.next = h.late;
        h.late = plan;
    }

    /// The follower's side of `stageLate`: every staged plan into batch `b` (the xrefs, the
    /// lists, then the checkpoint's mark). A plan made in another epoch than the batch's is
    /// dropped (its xref decisions were for that epoch); one the batch has no room for is
    /// dropped too, unmarked. Either way the checkpoint stays forwarded, as it was.
    fn writeLate(h: *History, b: *store.Batch) !void {
        if (@atomicLoad(?*LatePlan, &h.late, .monotonic) == null) return;
        var list: ?*LatePlan = blk: {
            while (!h.late_mu.tryLock()) std.atomic.spinLoopHint();
            defer h.late_mu.unlock();
            const l = h.late;
            h.late = null;
            break :blk l;
        };
        while (list) |p| {
            list = p.next;
            defer p.destroy();
            if (p.epoch != b.epoch or p.seq >= b.seq) {
                _ = h.stats.late_dropped.fetchAdd(1, .monotonic);
                if (h.late_hook) |hk| hk.done(hk.ctx, p.seq, false);
                continue;
            }
            h.writeLatePlan(b, p) catch |e| {
                if (!noRoom(e)) return e;
                _ = h.stats.late_dropped.fetchAdd(1, .monotonic);
                if (h.late_hook) |hk| hk.done(hk.ctx, p.seq, false);
                continue;
            };
            _ = h.stats.late_marked.fetchAdd(1, .monotonic);
            if (h.late_hook) |hk| hk.done(hk.ctx, p.seq, true);
        }
    }

    fn writeLatePlan(h: *History, b: *store.Batch, p: *const LatePlan) !void {
        for (p.xrefs) |x| {
            try b.putXref(&x.k.id, x.k.version, x.target);
            _ = h.stats.xref.fetchAdd(1, .monotonic);
        }
        for (p.lists) |l| {
            try b.putHistorical(&l.digest, loaded_version, &@as([32]u8, @splat(0)), l.bytes);
            _ = h.stats.loaded_lists.fetchAdd(1, .monotonic);
        }
        if (h.mark_read_sets) try h.mark(b, p.seq);
    }

    /// Checks lists that came for checkpoint `seq` after it was applied, exactly as `onBatchEdge`
    /// checks lists that come with their checkpoint, and plans their records (`LatePlan`, for
    /// `stageLate`). `contents` is the checkpoint's CheckpointContents as the late answer carried
    /// it: it must be the stored one, byte for byte, so the lists are taken for the transactions
    /// they were sent for. Reads only the store: the checkpoint's transactions and effects as
    /// stored (certified), and its object versions. Thread safe (its own arena; `stats` atomics).
    ///
    /// "As it was when its transaction ran": at apply a loaded entry is checked against the
    /// store's live version before the checkpoint. Later checkpoints may have changed that
    /// object since, so here the version before checkpoint `seq` is the input version of the
    /// object's first change in checkpoints `seq ..= committed` (the snapshot's tip), taken from
    /// their certified effects (`noteFirst`); an object none of them changed has it as its
    /// newest version as of the snapshot (`Before.holds`).
    pub fn planLate(h: *History, gpa: std.mem.Allocator, st: *store.Store, seq: u64, contents: []const u8, lists_aux: []const u8) !LateOutcome {
        var snap = st.snapshot();
        defer snap.release();
        var plan: ?*LatePlan = null;
        const out = try h.planLateIn(gpa, &snap, seq, contents, lists_aux, &plan);
        if (plan) |p| h.stageLate(p);
        return out;
    }

    /// `planLate` on snapshot `snap`, without staging: on `.staged` the plan is in `plan_out`,
    /// the caller's to stage or destroy.
    pub fn planLateIn(h: *History, gpa: std.mem.Allocator, snap: *const store.Snapshot, seq: u64, contents: []const u8, lists_aux: []const u8, plan_out: *?*LatePlan) !LateOutcome {
        const committed = snap.highestCommitted() orelse return .not_yet;
        if (seq > committed) return .not_yet;
        if (readSetHeld(snap, seq)) return .already;
        // far behind (the re-ask runs seconds after the build, not checkpoints)
        if (committed - seq > late_max_span) return .gone;
        const cp = snap.checkpoint(seq) orelse return .gone;
        if (!std.mem.eql(u8, cp.contents, contents)) return .mismatch;

        const plan = try gpa.create(LatePlan);
        plan.* = .{ .arena = .init(gpa), .seq = seq, .epoch = cp.epoch };
        var keep = false;
        defer if (!keep) plan.destroy();
        const a = plan.arena.allocator();

        const digests = try contentDigests(a, cp.contents);
        const aux = convert.Aux.parse(a, lists_aux) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .mismatch,
        };
        if (aux.loaded.len != digests.len) return .mismatch;

        var outputs: std.AutoHashMapUnmanaged(Key, u8) = .empty;
        var claims: std.AutoHashMapUnmanaged(Key, [32]u8) = .empty;
        var consumed: std.AutoHashMapUnmanaged(Key, void) = .empty;
        const decoded = try a.alloc(Decoded, digests.len);
        for (decoded, digests) |*d, *dg| {
            const rec = snap.transaction(dg) orelse return .gone;
            const sp = serve.service.splitEnvelope(a, rec.tx) catch return .gone;
            d.td = try bcs.decode(types.TransactionData, a, sp.data);
            d.fx = try bcs.decode(types.TransactionEffects, a, rec.effects);
            try claimsOfDecoded(a, &claims, &consumed, &d.td, &d.fx);
            switch (d.fx) {
                .V2 => |*v| for (v.changed_objects) |ch| switch (ch[1].output_state) {
                    .ObjectWrite => try outputs.put(a, .{ .id = ch[0].@"0".@"0", .version = v.lamport_version.@"0" }, 0),
                    .PackageWrite => |x| try outputs.put(a, .{ .id = ch[0].@"0".@"0", .version = x[0].@"0" }, 1),
                    .NotExist, .AccumulatorWriteV1 => {},
                },
                // effects V1 predate the loaded lists: no list for one is sui-node's
                .V1 => return .rejected,
            }
        }

        // Each object's version before checkpoint `seq`, for the objects checkpoints
        // `seq ..= committed` changed: the input version of its first change (null: created).
        var first: std.AutoHashMapUnmanaged([32]u8, ?u64) = .empty;
        var s = seq;
        while (s <= committed) : (s += 1) {
            const c = if (s == seq) cp else (snap.checkpoint(s) orelse return .gone);
            if (c.epoch != cp.epoch) return .gone; // an epoch boundary since: not planned
            const ds = if (s == seq) digests else try contentDigests(a, c.contents);
            for (ds, 0..) |*dg, i| {
                const fx = if (s == seq) decoded[i].fx else blk: {
                    const rec = snap.transaction(dg) orelse return .gone;
                    break :blk try bcs.decode(types.TransactionEffects, a, rec.effects);
                };
                switch (fx) {
                    .V2 => |*v| try noteFirst(a, &first, v),
                    .V1 => return .gone,
                }
            }
        }

        var done: std.AutoHashMapUnmanaged(Key, Held) = .empty;
        const chk = try checkLists(a, snap, cp.epoch, aux.loaded, decoded, &outputs, &claims, &done, .{ .first = &first });
        if (chk.rejected) {
            _ = h.stats.edge_rejected.fetchAdd(1, .monotonic);
            std.log.warn("history: checkpoint {d}: the read sets its source sent late fail the edge's checks; not stored, its reads go to the core", .{seq});
            return .rejected;
        }
        if (chk.missing != 0) {
            _ = h.stats.edge_incomplete.fetchAdd(1, .monotonic);
            _ = h.stats.edge_missing_objects.fetchAdd(chk.missing, .monotonic);
            return .incomplete;
        }
        var ls: std.ArrayList(LateList) = .empty;
        for (aux.loaded, digests) |list, dg| {
            if (list.len == 0) continue;
            const bytes = try a.alloc(u8, list.len * entry_len);
            for (list, 0..) |r, j| {
                std.mem.writeInt(u64, bytes[j * entry_len ..][0..8], r.version, .little);
                bytes[j * entry_len + 8 ..][0..32].* = r.id;
            }
            try ls.append(a, .{ .digest = dg, .bytes = bytes });
        }
        plan.xrefs = chk.xrefs;
        plan.lists = ls.items;
        _ = h.stats.present.fetchAdd(chk.present, .monotonic);
        keep = true;
        plan_out.* = plan;
        return .staged;
    }

    /// The read-set records of a checkpoint whose lists passed: the remaining xrefs, the lists,
    /// then the mark, last, so it is only ever there with everything before it.
    fn writeEdge(h: *History, a: std.mem.Allocator, b: *store.Batch, seq: u64, xrefs: []const EdgeXref, lists: []const []const convert.LoadedRef, txs: []const sync.verify.TxPlan) !void {
        for (xrefs) |x| {
            try b.putXref(&x.k.id, x.k.version, x.target);
            _ = h.stats.xref.fetchAdd(1, .monotonic);
        }
        for (lists, txs) |list, plan| {
            if (list.len == 0) continue;
            const bytes = try a.alloc(u8, list.len * entry_len);
            for (list, 0..) |r, j| {
                std.mem.writeInt(u64, bytes[j * entry_len ..][0..8], r.version, .little);
                bytes[j * entry_len + 8 ..][0..32].* = r.id;
            }
            try b.putHistorical(plan.tx_digest, loaded_version, &@as([32]u8, @splat(0)), bytes);
            _ = h.stats.loaded_lists.fetchAdd(1, .monotonic);
        }
        if (h.mark_read_sets) try h.mark(b, seq);
    }

    fn putOne(h: *History, a: std.mem.Allocator, snap: *const store.Snapshot, b: *store.Batch, outputs: *const std.AutoHashMapUnmanaged(Key, void), claims: *const std.AutoHashMapUnmanaged(Key, [32]u8), consumed: *const std.AutoHashMapUnmanaged(Key, void), aux_refs: *const std.AutoHashMapUnmanaged(Key, [32]u8), done: *std.AutoHashMapUnmanaged(Key, void), raw: []const u8) !void {
        const k = exec.objects.keyOf(raw) catch return error.BadAuxObject;
        if (k.version == loaded_version) return error.BadAuxObject;
        if (outputs.contains(k)) return;
        const gop = try done.getOrPut(a, k);
        if (gop.found_existing) return;
        const d = sync.verify.objectDigest(raw);
        if (claims.get(k) orelse aux_refs.get(k)) |want| {
            if (!std.mem.eql(u8, &want, &d)) {
                _ = h.stats.rejected.fetchAdd(1, .monotonic);
                std.log.warn("history: archive object {x} version {d} does not match the certified digest; not stored", .{ &k.id, k.version });
                return;
            }
        }
        switch (try inputAction(snap, b.epoch, &k.id, k.version, consumed.contains(k))) {
            .present => {
                _ = h.stats.present.fetchAdd(1, .monotonic);
                return;
            },
            .xref => |target| {
                // The store holds these bytes already (checked against the certified digest
                // above, when one is named): reference them instead of copying.
                try b.putXref(&k.id, k.version, target);
                _ = h.stats.xref.fetchAdd(1, .monotonic);
                return;
            },
            .copy => {},
        }
        try b.putHistorical(&k.id, k.version, &d, raw);
        _ = h.stats.put.fetchAdd(1, .monotonic);
        _ = (if (claims.contains(k)) &h.stats.verified else &h.stats.unverified).fetchAdd(1, .monotonic);
    }
};

const EdgeXref = struct { k: Key, target: u64 };

/// The checkpoints `planLate` looks across at most (its checkpoint to the store's tip): the
/// re-ask runs within seconds of a build, a few checkpoints.
pub const late_max_span: u64 = 256;

/// What `History.planLate` made of late lists.
pub const LateOutcome = enum {
    /// Checked; their records wait for the next commit group (`History.stageLate`).
    staged,
    /// The checkpoint is marked already.
    already,
    /// Not committed here yet: ask again in a moment.
    not_yet,
    /// The answer is not for the stored checkpoint (other contents, or one list per transaction
    /// it does not have).
    mismatch,
    /// The lists fail a check (`edge_rejected`).
    rejected,
    /// A key of an object set is not held here (`edge_incomplete`).
    incomplete,
    /// The checkpoint or one after it is out of reach (pruned, an epoch boundary since, too far).
    gone,
};

/// `History.late_hook`.
pub const LateHook = struct {
    ctx: *anyopaque,
    done: *const fn (ctx: *anyopaque, seq: u64, marked: bool) void,
};

pub const LateList = struct { digest: [32]u8, bytes: []const u8 };

/// The records of one late checkpoint (`History.planLate`), owned by its arena.
pub const LatePlan = struct {
    arena: std.heap.ArenaAllocator,
    seq: u64,
    epoch: u64,
    xrefs: []const EdgeXref = &.{},
    lists: []const LateList = &.{},
    next: ?*LatePlan = null,

    pub fn destroy(p: *LatePlan) void {
        const gpa = p.arena.child_allocator;
        p.arena.deinit();
        gpa.destroy(p);
    }
};

/// The transaction digests of a BCS CheckpointContents, in order.
pub fn contentDigests(a: std.mem.Allocator, contents: []const u8) ![]const [32]u8 {
    const c = try bcs.decode(types.CheckpointContents, a, contents);
    switch (c) {
        .V1 => |v| {
            const out = try a.alloc([32]u8, v.transactions.len);
            for (v.transactions, out) |t, *o| o.* = t.transaction.@"0".@"0";
            return out;
        },
        .V2 => |v| {
            const out = try a.alloc([32]u8, v.transactions.len);
            for (v.transactions, out) |t, *o| o.* = t.digest.transaction.@"0".@"0";
            return out;
        },
    }
}

const Held = enum { yes, no, no_counted };
const Decoded = struct { td: types.TransactionData, fx: types.TransactionEffects };

/// What `checkLists` found.
const Checked = struct {
    rejected: bool = false,
    /// Keys of object sets this store does not hold (with the certified digest).
    missing: u64 = 0,
    /// Keys held only in an older segment: an xref each, with the read set.
    xrefs: []const EdgeXref = &.{},
    /// Keys held where they live as long as the checkpoint: nothing to write.
    present: u64 = 0,
};

/// How a loaded entry's "as it was before the checkpoint" is told. At apply (`first` null) the
/// snapshot is the one before the checkpoint, taken by the store's one writer: the live version.
/// Late (`first` set): the snapshot is later, and `first` has the version before the checkpoint
/// of every object the checkpoint or a later one up to the snapshot's tip changed (null: it did
/// not exist); any other object is unchanged since, so its newest version as of the snapshot is
/// still the one.
///
/// "As of the snapshot", not "live": the late path runs on the re-ask thread while the follower
/// commits, and a commit updates the live table before it publishes its checkpoint
/// (`Store.commit`: `applyGroup`, then `committed1`). In that gap the live table holds the next
/// checkpoint's version of every object it changed while the snapshot's tip, and so `first`,
/// stops before that checkpoint: the version a list names is found, not live, and in no entry
/// of `first`. `Snapshot.latest` walks back to the version the snapshot sees.
const Before = struct {
    first: ?*const std.AutoHashMapUnmanaged([32]u8, ?u64) = null,

    fn holds(b: Before, snap: *const store.Snapshot, f: store.Snapshot.Found, k: *const Key) !bool {
        const m = b.first orelse return f.live;
        if (m.get(k.id)) |v| return v != null and v.? == k.version;
        if (f.live) return true;
        return switch ((try snap.latest(&k.id)) orelse return false) {
            .live => |o| o.version == k.version,
            .removed => false,
        };
    }
};

/// Adds to `first` the input version of every object `fx` changes that it has no entry for yet
/// (null: created or unwrapped). An accumulator write (`AccumulatorWriteV1`, input always
/// `NotExist`) is not a change of the object: the settlement transaction changes it later, with
/// its real input version. Taking the write's `NotExist` would say the object did not exist
/// before the checkpoint, and reject every list that names its field object.
fn noteFirst(a: std.mem.Allocator, first: *std.AutoHashMapUnmanaged([32]u8, ?u64), fx: *const types.TransactionEffectsV2) !void {
    for (fx.changed_objects) |ch| {
        if (ch[1].output_state == .AccumulatorWriteV1) continue;
        const gop = try first.getOrPut(a, ch[0].@"0".@"0");
        if (gop.found_existing) continue;
        gop.value_ptr.* = switch (ch[1].input_state) {
            .Exist => |e| e[0][0].@"0",
            .NotExist => null,
        };
    }
}

/// Step 2 of `onBatchEdge`, and the whole check of `planLate`: each list against sui-node's
/// form and its transaction, then every key of every transaction's object set against the
/// store (`done`: keys looked at already, from step 1).
fn checkLists(a: std.mem.Allocator, snap: *const store.Snapshot, epoch: u64, ls: []const []const convert.LoadedRef, decoded: []const Decoded, outputs: *const std.AutoHashMapUnmanaged(Key, u8), claims: *const std.AutoHashMapUnmanaged(Key, [32]u8), done: *std.AutoHashMapUnmanaged(Key, Held), before: Before) !Checked {
    var out: Checked = .{};
    var xrefs: std.ArrayList(EdgeXref) = .empty;
    // Each object's newest write by the transactions before the one looked at (null: removed).
    var written: std.AutoHashMapUnmanaged([32]u8, ?u64) = .empty;
    check: for (ls, decoded) |list, *d| {
        const refs = try a.alloc(serve.objset.Ref, list.len);
        for (list, refs, 0..) |r, *o, j| {
            o.* = .{ .id = r.id, .version = r.version };
            if (r.version > std.math.maxInt(i64) or (j > 0 and std.mem.order(u8, &list[j - 1].id, &r.id) != .lt) or changes(&d.fx, &r.id)) {
                out.rejected = true;
                break :check;
            }
        }
        for (try serve.txobjects.keys(a, d.td, d.fx, refs)) |r| {
            const k: Key = .{ .id = r.id, .version = r.version };
            const loaded = inList(refs, &k);
            if (loaded) {
                // A loaded object is read as it was when its transaction ran: the version an
                // earlier transaction of this checkpoint left (a checkpoint's transactions
                // are in causal order), else the one live before the checkpoint (below).
                if (written.get(k.id)) |w| {
                    if (w == null or w.? != k.version or (outputs.get(k) orelse 0) == 1) {
                        out.rejected = true;
                        break :check;
                    }
                    continue;
                }
            } else if (outputs.contains(k)) continue;
            if (done.getPtr(k)) |held| {
                // looked at before (step 1, or another transaction of this checkpoint)
                if (held.* == .no) {
                    held.* = .no_counted;
                    out.missing += 1;
                }
                if (!loaded) continue;
            }
            const f = try snap.objectFind(&k.id, k.version);
            if (loaded) if (f) |x| if (!try before.holds(snap, x, &k) or (x.ref.bytes.len > 0 and x.ref.bytes[0] == 1)) {
                out.rejected = true;
                break :check;
            };
            if (done.contains(k)) continue;
            const ok = if (f) |x| (if (claims.get(k)) |want| std.mem.eql(u8, &want, &x.ref.digest) else true) else false;
            try done.put(a, k, if (ok) .yes else .no_counted);
            if (!ok) {
                out.missing += 1;
                continue;
            }
            switch (actionOf(f, epoch, false)) {
                .present => out.present += 1,
                .xref => |target| try xrefs.append(a, .{ .k = k, .target = target }),
                .copy => unreachable, // `ok`: found
            }
        }
        switch (d.fx) {
            .V2 => |*v| for (v.changed_objects) |ch| switch (ch[1].output_state) {
                .ObjectWrite => try written.put(a, ch[0].@"0".@"0", v.lamport_version.@"0"),
                .PackageWrite => |x| try written.put(a, ch[0].@"0".@"0", x[0].@"0"),
                .NotExist => try written.put(a, ch[0].@"0".@"0", null),
                .AccumulatorWriteV1 => {},
            },
            .V1 => {},
        }
    }
    out.xrefs = xrefs.items;
    return out;
}

/// Whether a transaction input version must be written as a historical record by the batch of
/// epoch `epoch` for the transaction to stay answerable (GetTransaction/GetCheckpoint with
/// effects, objects or balance_changes need every input version) for as long as it is retained.
/// No copy is needed when the store already holds the version
///  * in a segment of epoch `epoch` or newer: it leaves the history window no earlier than the
///    transaction does; or
///  * as the live record, when this checkpoint does not supersede it (`consumed` false): while
///    it is live the live table finds it wherever it sits (cleaning carries it), and the
///    checkpoint that later supersedes it copies it into its own epoch.
/// Otherwise (missing, or found only in an older segment), the version is copied: the record
/// there stops being readable when that epoch ages out (index reads check the window) and its
/// segment may be cleaned away, while sui-node prunes a version with the checkpoint that
/// superseded it, not the one that wrote it.
pub fn needsCopy(snap: *const store.Snapshot, epoch: u64, id: *const [32]u8, version: u64, consumed: bool) !bool {
    return try inputAction(snap, epoch, id, version, consumed) != .present;
}

pub const InputAction = union(enum) {
    /// Nothing to write (see needsCopy).
    present,
    /// Write the version's bytes (`Batch.putHistorical`): the store does not hold them.
    copy,
    /// The store holds the bytes at this location, in an older segment (or reachable only
    /// through an older xref): write `Batch.putXref` so the version lives as long as this
    /// checkpoint. Cleaning carries the bytes if their segment is deleted first.
    xref: u64,
};

/// needsCopy's decision, saying how: an xref when the bytes are already in the store (about 64
/// bytes instead of the object, measured ~400 bytes on mainnet at ~400 inputs per checkpoint).
pub fn inputAction(snap: *const store.Snapshot, epoch: u64, id: *const [32]u8, version: u64, consumed: bool) !InputAction {
    return actionOf(try snap.objectFind(id, version), epoch, consumed);
}

/// `inputAction` for a version already looked up (`found`: `Snapshot.objectFind`'s answer).
pub fn actionOf(found: ?store.Snapshot.Found, epoch: u64, consumed: bool) InputAction {
    const f = found orelse return .copy;
    // A compact live record this checkpoint supersedes is in no version index: the xref makes it
    // findable (and spares the store's link record, written only when no xref names it).
    if (f.live and consumed and f.compact) return .{ .xref = f.data_loc };
    if (store.format.epochOf(f.loc) >= epoch) return .present;
    if (f.live and !consumed) return .present;
    return .{ .xref = f.data_loc };
}

/// Digests the certified transaction and effects name for object versions the transaction read,
/// and the input versions its effects supersede (`consumed`).
pub fn claimsOf(a: std.mem.Allocator, claims: *std.AutoHashMapUnmanaged(Key, [32]u8), consumed: *std.AutoHashMapUnmanaged(Key, void), data_bytes: []const u8, effects_bytes: []const u8) !void {
    const td = try bcs.decode(types.TransactionData, a, data_bytes);
    const fx = try bcs.decode(types.TransactionEffects, a, effects_bytes);
    return claimsOfDecoded(a, claims, consumed, &td, &fx);
}

/// `claimsOf` for a transaction and effects already decoded.
pub fn claimsOfDecoded(a: std.mem.Allocator, claims: *std.AutoHashMapUnmanaged(Key, [32]u8), consumed: *std.AutoHashMapUnmanaged(Key, void), td: *const types.TransactionData, fx_in: *const types.TransactionEffects) !void {
    const v1 = &td.V1;
    for (v1.gas_data.payment) |r| try claims.put(a, .{ .id = r[0].@"0".@"0", .version = r[1].@"0" }, r[2].@"0".@"0");
    switch (v1.kind) {
        .ProgrammableTransaction => |pt| for (pt.inputs) |in| switch (in) {
            .Object => |o| switch (o) {
                .ImmOrOwnedObject, .Receiving => |r| try claims.put(a, .{ .id = r[0].@"0".@"0", .version = r[1].@"0" }, r[2].@"0".@"0"),
                .SharedObject => {},
            },
            else => {},
        },
        else => {},
    }
    switch (fx_in.*) {
        .V1 => |*v| {
            for (v.shared_objects) |r| try claims.put(a, .{ .id = r[0].@"0".@"0", .version = r[1].@"0" }, r[2].@"0".@"0");
            for (v.modified_at_versions) |m| try consumed.put(a, .{ .id = m[0].@"0".@"0", .version = m[1].@"0" }, {});
        },
        .V2 => |*v| {
            for (v.changed_objects) |ch| switch (ch[1].input_state) {
                .Exist => |e| {
                    const k: Key = .{ .id = ch[0].@"0".@"0", .version = e[0][0].@"0" };
                    try claims.put(a, k, e[0][1].@"0".@"0");
                    try consumed.put(a, k, {});
                },
                .NotExist => {},
            };
            for (v.unchanged_consensus_objects) |u| switch (u[1]) {
                .ReadOnlyRoot => |r| try claims.put(a, .{ .id = u[0].@"0".@"0", .version = r[0].@"0" }, r[1].@"0".@"0"),
                else => {},
            };
        },
    }
}

/// A read-set record that the checkpoint's batch has no room for.
fn noRoom(e: anyerror) bool {
    return e == error.BatchFull or e == error.SegmentFull;
}

/// Whether `effects` list `id` among the objects the transaction changed
/// (`TransactionEffects::object_changes`): sui-node leaves those out of the loaded list.
/// `object_changes` skips accumulator writes (effects_v2.rs), so an object the transaction
/// only wrote to as an accumulator stays in its list.
fn changes(fx: *const types.TransactionEffects, id: *const [32]u8) bool {
    switch (fx.*) {
        .V2 => |*v| for (v.changed_objects) |ch| {
            if (ch[1].output_state == .AccumulatorWriteV1) continue;
            if (std.mem.eql(u8, &ch[0].@"0".@"0", id)) return true;
        },
        // Effects V1 predate the loaded list: a list for one is not sui-node's.
        .V1 => return true,
    }
    return false;
}

fn inList(refs: []const serve.objset.Ref, k: *const Key) bool {
    // ascending by id (checked before this is asked)
    var lo: usize = 0;
    var hi: usize = refs.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, &refs[mid].id, &k.id)) {
            .lt => lo = mid + 1,
            .gt => hi = mid,
            .eq => return refs[mid].version == k.version,
        }
    }
    return false;
}

/// The stored loaded runtime object list of a transaction, as `[]const T` where T is
/// `serve.objset.Ref` (layout: version u64 then id, checked here). Empty when none is stored.
pub fn loadedList(comptime T: type, snap: *const store.Snapshot, tx_digest: *const [32]u8) []const T {
    return loadedListNear(T, snap, tx_digest, 0);
}

/// `loadedList` with the transaction record's location as a lookup hint (0 = none): the list
/// sits in the transaction's own batch (Snapshot.objectNear).
pub fn loadedListNear(comptime T: type, snap: *const store.Snapshot, tx_digest: *const [32]u8, at: u64) []const T {
    comptime {
        std.debug.assert(@sizeOf(T) == entry_len and @offsetOf(T, "version") == 0 and @offsetOf(T, "id") == 8);
        std.debug.assert(@import("builtin").cpu.arch.endian() == .little);
    }
    // A list installed in place of the stored record (store `list_fix`, reconcile.zig): the one
    // read every reader shares, so a repaired list is served by all of them. One atomic load
    // when the table is empty.
    const bytes: []const u8 = if (snap.store.list_fix.find(tx_digest)) |fx| fx.tx else snap.objectNear(tx_digest, loaded_version, at) orelse return &.{};
    if (bytes.len % entry_len != 0 or @intFromPtr(bytes.ptr) % @alignOf(T) != 0) return &.{};
    const p: [*]const T = @ptrCast(@alignCast(bytes.ptr));
    return p[0 .. bytes.len / entry_len];
}

test "loaded list entry layout matches serve's Ref" {
    const Ref = @import("serve").objset.Ref;
    try std.testing.expectEqual(@as(usize, entry_len), @sizeOf(Ref));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(Ref, "version"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(Ref, "id"));
}

test "edge read sets: records that do not fit the checkpoint's batch fail as no-room before the mark, and the batch still commits" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &pb);
    // a batch holds at most 8 object-class records (lists and the mark are such records)
    var cfg: store.Config = .{ .dir = pb[0..n], .max_live_objects = 1 << 10, .max_object_versions = 8, .segment_reserve = 1 << 20 };
    const opened = try store.openDir(gpa, io, &cfg, .{ .sync = .none });
    defer opened.io.deinit();
    defer opened.store.deinit();
    const st = opened.store;
    var h = try History.init(gpa, io, null);
    defer h.deinit();
    h.mark_read_sets = true;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var digests: [12][32]u8 = undefined;
    var plans: [12]sync.verify.TxPlan = undefined;
    var lists: [12][]const convert.LoadedRef = undefined;
    for (&digests, &plans, &lists, 0..) |*d, *p, *l, i| {
        d.* = @splat(@intCast(0x40 + i));
        p.* = .{ .tx_digest = d, .effects_digest = @splat(0), .puts = &.{}, .removes = &.{} };
        const one = try a.alloc(convert.LoadedRef, 1);
        one[0] = .{ .id = @splat(@intCast(0x80 + i)), .version = 5 + i, .digest = null };
        l.* = one;
    }

    // Checkpoint 1: nine lists and a mark do not fit eight records. The ninth list is refused,
    // the error is a no-room one (what `onBatchEdge` turns into "not marked"), nothing after it
    // was written, and the batch commits with the certified record it already had.
    {
        const b = try st.begin(1, 0);
        try b.checkpoint("s1", "c");
        const got = h.writeEdge(a, b, 1, &.{}, lists[0..9], plans[0..9]);
        try std.testing.expectError(error.BatchFull, got);
        try std.testing.expect(noRoom(error.BatchFull) and noRoom(error.SegmentFull) and !noRoom(error.OutOfMemory) and !noRoom(error.BadAuxObject));
        try st.commit(b);
    }
    // Checkpoint 2: seven lists and the mark fit.
    {
        const b = try st.begin(2, 0);
        try b.checkpoint("s2", "c");
        try h.writeEdge(a, b, 2, &.{}, lists[0..7], plans[0..7]);
        try st.commit(b);
    }
    var snap = st.snapshot();
    defer snap.release();
    try std.testing.expect(snap.checkpoint(1) != null and snap.checkpoint(2) != null);
    // the mark is the last record: without everything before it, it is not there
    try std.testing.expect(!readSetHeld(&snap, 1));
    try std.testing.expect(readSetHeld(&snap, 2));
    try std.testing.expect(!readSetHeld(&snap, 3));
    try std.testing.expectEqual(@as(u64, 1), h.stats.marked.load(.monotonic));
    const got = loadedList(serve.objset.Ref, &snap, &digests[6]);
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try std.testing.expectEqual(@as(u64, 11), got[0].version);
    try std.testing.expectEqual(@as([32]u8, @splat(0x86)), got[0].id);
}

test "late check: an accumulator write is not a change of its object (noteFirst, changes)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const T = struct {
        fn id(b: u8) types.ObjectID {
            return .{ .@"0" = .{ .@"0" = @splat(b) } };
        }
    };
    const dz: types.ObjectDigest = .{ .@"0" = .{ .@"0" = @splat(0) } };
    const owner: types.Owner = .{ .AddressOwner = .{ .@"0" = @splat(7) } };
    const gas: types.GasCostSummary = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 };
    const acc: types.EffectsObjectChange = .{ .input_state = .NotExist, .output_state = .{ .AccumulatorWriteV1 = .{ .address = .{ .address = .{ .@"0" = @splat(7) }, .ty = .u64 }, .operation = .Merge, .value = .{ .Integer = 1 } } }, .id_operation = .None };
    // A user transaction: writes 0x30, and an accumulator write to the field object 0x20.
    const user: types.TransactionEffectsV2 = .{
        .status = .Success,
        .executed_epoch = 1,
        .gas_used = gas,
        .transaction_digest = .{ .@"0" = .{ .@"0" = @splat(1) } },
        .gas_object_index = null,
        .events_digest = null,
        .dependencies = &.{},
        .lamport_version = .{ .@"0" = 10 },
        .changed_objects = &.{
            .{ T.id(0x30), .{ .input_state = .{ .Exist = .{ .{ .{ .@"0" = 5 }, dz }, owner } }, .output_state = .{ .ObjectWrite = .{ dz, owner } }, .id_operation = .None } },
            .{ T.id(0x20), acc },
        },
        .unchanged_consensus_objects = &.{},
        .aux_data_digest = null,
    };
    // The settlement after it: changes 0x20 from version 6.
    var settle = user;
    settle.lamport_version = .{ .@"0" = 11 };
    settle.changed_objects = &.{
        .{ T.id(0x20), .{ .input_state = .{ .Exist = .{ .{ .{ .@"0" = 6 }, dz }, owner } }, .output_state = .{ .ObjectWrite = .{ dz, owner } }, .id_operation = .None } },
    };

    var first: std.AutoHashMapUnmanaged([32]u8, ?u64) = .empty;
    try noteFirst(a, &first, &user);
    try noteFirst(a, &first, &settle);
    // 0x20 existed at 6 before the checkpoint: the settlement says so, the write does not count
    try std.testing.expectEqual(@as(?u64, 6), first.get(T.id(0x20).@"0".@"0").?);
    try std.testing.expectEqual(@as(?u64, 5), first.get(T.id(0x30).@"0".@"0").?);
    // only accumulator writes: no entry, so the object's version as of the snapshot decides
    first = .empty;
    try noteFirst(a, &first, &user);
    try std.testing.expect(first.get(T.id(0x20).@"0".@"0") == null);

    // sui-node's `object_changes` skips accumulator writes: 0x20 may stay in the loaded list
    const ufx: types.TransactionEffects = .{ .V2 = user };
    try std.testing.expect(!changes(&ufx, &T.id(0x20).@"0".@"0"));
    try std.testing.expect(changes(&ufx, &T.id(0x30).@"0".@"0"));
}
