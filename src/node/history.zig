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
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const sync = @import("sync");
const exec = @import("exec");
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

    pub fn init(gpa: std.mem.Allocator, io: Io, aux_dir: ?Io.Dir) !History {
        return .{ .gpa = gpa, .io = io, .aux_dir = aux_dir, .idx = try types.CheckpointIndex.init(gpa), .arena = .init(gpa) };
    }

    pub fn deinit(h: *History) void {
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
        _ = h.arena.reset(.retain_capacity);
        const a = h.arena.allocator();
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
    const f = (try snap.objectFind(id, version)) orelse return .copy;
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
    const fx = try bcs.decode(types.TransactionEffects, a, effects_bytes);
    switch (fx) {
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
