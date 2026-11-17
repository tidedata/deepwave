//! The validator's execution store (`<db>/validator/exec/exec.log`): every object version, the
//! effects, events and data of every executed transaction, and the TransactionKey -> digest map
//! (sui-core: the object tables, `executed_effects`/`effects`/`events`/`transactions` and
//! `tx_key_to_digest` of the epoch store).
//!
//! Durability (the discipline of src/consensus/store.zig and authority/epoch_log.zig): one
//! append-only log, one checksummed record per executed transaction (its objects, removals,
//! effects, events, data and keys together, so a crash never splits them), the checksum seeded
//! with the record's file offset, fdatasync before `commitTx` returns and before anything of the
//! transaction becomes visible to readers, a torn or corrupt tail cut at open. The in-memory
//! indexes are rebuilt from the log at open.
//!
//! Every slice a read returns stays valid until `close` (bytes are never freed while open), so
//! readers on other threads (API, checkpoint builder) need no copy. Reads take a short spin
//! lock; writers are serialized by a mutex held across the fsync.
//!
//! Localnet scale: the whole object history lives in memory. A long-running validator needs
//! pruning and an on-disk index (the node store), which this file does not do.
const std = @import("std");
const Io = std.Io;
const types = @import("types");
const hash = @import("hash");
const exec = @import("exec");
const versions = @import("../authority/versions.zig");
const Spin = @import("../authority/sync.zig").Spin;
const genesis_mod = @import("genesis.zig");

const Allocator = std.mem.Allocator;
const ObjectView = exec.objects.ObjectView;
pub const Id = [32]u8;
pub const Key = versions.Assignable.Key;

pub const Error = error{ Io, Corrupt, OutOfMemory };

pub const magic = "ZUIEXEC1";
const max_record: usize = 1 << 30;

/// What happened to an object at a version: written (live), or removed by the transaction that
/// ran at that lamport version.
pub const VersionKind = enum(u8) { live = 0, deleted = 1, wrapped = 2 };
pub const Version = struct { version: u64, kind: VersionKind };
pub const Removed = struct { id: Id, version: u64, kind: VersionKind };

/// One executed transaction as `commitTx` takes it.
pub const TxRecord = struct {
    digest: Id,
    /// TransactionKeys that resolve to this digest (randomness round, settlement barrier,
    /// prologue key); the digest itself always resolves.
    keys: []const Key = &.{},
    td_bcs: []const u8,
    effects_bcs: []const u8,
    events_bcs: ?[]const u8 = null,
    /// Raw BCS Objects at their new versions.
    written: []const []const u8,
    /// Deleted and wrapped objects (`changed_objects` with no output object).
    removed: []const Removed = &.{},
};

pub const Executed = struct {
    td_bcs: []const u8,
    effects_bcs: []const u8,
    events_bcs: ?[]const u8,
    effects_digest: Id,
    /// `executed_epoch` of the effects (V2; 0 when they do not decode): sui-core's
    /// `executed_transaction_digests` key and `executed_transactions_to_checkpoint` epoch.
    epoch: u64 = 0,
};

pub const ExecStore = struct {
    gpa: Allocator,
    io: Io,
    file: ?Io.File = null,
    end: u64 = 0,
    /// Serializes writers (held across the fsync).
    wmu: Io.Mutex = .init,
    /// Guards the indexes and `arena` (short sections, never across I/O).
    lock: Spin = .{},
    arena: std.heap.ArenaAllocator,
    objects: std.AutoHashMapUnmanaged([40]u8, []const u8) = .empty,
    history: std.AutoHashMapUnmanaged(Id, std.ArrayList(Version)) = .empty,
    txs: std.AutoHashMapUnmanaged(Id, Executed) = .empty,
    keys: std.AutoHashMapUnmanaged([33]u8, Id) = .empty,
    /// The per-epoch object markers signing reads (sui-core `TransactionOutputs` markers, keyed
    /// `(epoch, FullObjectKey)`), derived from each record's effects and transaction data:
    /// `received`: (epoch, id, version) of a receiving input the transaction consumed
    /// (`MarkerValue::Received`); `stream_ended`: (epoch, id, start version) of a consensus object
    /// whose stream a transaction ended (`MarkerValue::ConsensusStreamEnded`).
    received: std.AutoHashMapUnmanaged([48]u8, void) = .empty,
    stream_ended: std.AutoHashMapUnmanaged([48]u8, void) = .empty,
    /// The same markers at their full key: (epoch, id, start version, output version) ->
    /// `MarkerValue::ConsensusStreamEnded(tx_digest)`, the output version being the ending
    /// (or smearing) transaction's lamport version (`get_consensus_stream_end_tx_digest`).
    stream_end_at: std.AutoHashMapUnmanaged([56]u8, Id) = .empty,
    genesis_seeded: bool = false,
    /// Torn tail bytes cut at open (diagnostics).
    cut_at_open: u64 = 0,

    /// Opens (creating) `<db>/validator/exec/exec.log` and rebuilds the indexes from it.
    pub fn open(gpa: Allocator, io: Io, db: []const u8) !ExecStore {
        var s: ExecStore = .{ .gpa = gpa, .io = io, .arena = .init(gpa) };
        errdefer s.freeIndexes();
        const dir = try std.fs.path.join(gpa, &.{ db, "validator", "exec" });
        defer gpa.free(dir);
        const path = try std.fs.path.join(gpa, &.{ dir, "exec.log" });
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
            s.applyRecord(payload) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => break, // a record that checksums but does not decode: treat as the tail
            };
            at += 8 + len;
        }
        if (at != data.len) {
            std.log.warn("exec store: {s}: torn or corrupt tail at byte {d} of {d}; cut", .{ path, at, data.len });
            s.cut_at_open = data.len - at;
            try f.setLength(io, at);
            try f.sync(io);
        }
        s.end = at;
        return s;
    }

    /// An in-memory store (tests, the simulator): same API, no file.
    pub fn openMem(gpa: Allocator, io: Io) ExecStore {
        return .{ .gpa = gpa, .io = io, .arena = .init(gpa) };
    }

    pub fn close(s: *ExecStore) void {
        if (s.file) |f| f.close(s.io);
        s.file = null;
        s.freeIndexes();
    }

    fn freeIndexes(s: *ExecStore) void {
        s.objects.deinit(s.gpa);
        var it = s.history.valueIterator();
        while (it.next()) |l| l.deinit(s.gpa);
        s.history.deinit(s.gpa);
        s.txs.deinit(s.gpa);
        s.keys.deinit(s.gpa);
        s.received.deinit(s.gpa);
        s.stream_ended.deinit(s.gpa);
        s.stream_end_at.deinit(s.gpa);
        s.arena.deinit();
    }

    // ------------------------------------------------------------------ writes

    /// Seeds the genesis objects and transaction (idempotent: a store that has the genesis
    /// transaction is left as it is).
    pub fn seedGenesis(s: *ExecStore, g: *const genesis_mod.Genesis) Error!void {
        if (s.executed(&g.tx_digest) != null) return;
        try s.commitTx(&.{
            .digest = g.tx_digest,
            .td_bcs = g.td_bcs,
            .effects_bcs = g.effects_bcs,
            .events_bcs = g.events_bcs,
            .written = g.objects,
        });
    }

    /// Makes one executed transaction durable, then visible. A digest already stored is a no-op
    /// (its first record wins).
    pub fn commitTx(s: *ExecStore, rec: *const TxRecord) Error!void {
        s.wmu.lockUncancelable(s.io);
        defer s.wmu.unlock(s.io);
        if (s.executed(&rec.digest) != null) return;
        const payload = try encodeTx(s.gpa, rec);
        defer s.gpa.free(payload);
        try s.append(payload);
        try s.applyRecord(payload);
    }

    /// Records `key -> digest` alone (durable), for a key learned after its transaction ran.
    pub fn putKey(s: *ExecStore, key: Key, digest: Id) Error!void {
        s.wmu.lockUncancelable(s.io);
        defer s.wmu.unlock(s.io);
        if (s.keyDigest(key)) |d| if (std.mem.eql(u8, &d, &digest)) return;
        var buf: [1 + 33 + 32]u8 = undefined;
        buf[0] = tag_key;
        buf[1..34].* = keyBytes(key);
        buf[34..66].* = digest;
        try s.append(&buf);
        try s.applyRecord(&buf);
    }

    fn append(s: *ExecStore, payload: []const u8) Error!void {
        const f = s.file orelse return;
        if (payload.len > max_record) return error.Corrupt;
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

    // ------------------------------------------------------------------ reads

    /// `id` at exactly `version` (null for a removed version or one never written).
    pub fn objectAt(s: *ExecStore, id: *const Id, version: u64) ?[]const u8 {
        s.lock.lock();
        defer s.lock.unlock();
        return s.objects.get(objKey(id, version));
    }

    /// The live version of `id`; null when it never existed or its newest version is a removal.
    pub fn latest(s: *ExecStore, id: *const Id) ?[]const u8 {
        s.lock.lock();
        defer s.lock.unlock();
        const l = s.history.getPtr(id.*) orelse return null;
        const last = l.items[l.items.len - 1];
        if (last.kind != .live) return null;
        return s.objects.get(objKey(id, last.version));
    }

    /// The newest version of `id` including removals (`get_latest_object_ref_or_tombstone`).
    pub fn latestVersion(s: *ExecStore, id: *const Id) ?Version {
        s.lock.lock();
        defer s.lock.unlock();
        const l = s.history.getPtr(id.*) orelse return null;
        return l.items[l.items.len - 1];
    }

    /// `read_child_object`: the newest version of `id` at or below `upper`, when that version is live.
    pub fn atMost(s: *ExecStore, id: *const Id, upper: u64) ?[]const u8 {
        s.lock.lock();
        defer s.lock.unlock();
        const l = s.history.getPtr(id.*) orelse return null;
        var i = l.items.len;
        while (i > 0) {
            i -= 1;
            const v = l.items[i];
            if (v.version > upper) continue;
            if (v.kind != .live) return null;
            return s.objects.get(objKey(id, v.version));
        }
        return null;
    }

    pub fn executed(s: *ExecStore, digest: *const Id) ?Executed {
        s.lock.lock();
        defer s.lock.unlock();
        return s.txs.get(digest.*);
    }
    pub fn effects(s: *ExecStore, digest: *const Id) ?[]const u8 {
        return if (s.executed(digest)) |e| e.effects_bcs else null;
    }
    pub fn events(s: *ExecStore, digest: *const Id) ?[]const u8 {
        return if (s.executed(digest)) |e| e.events_bcs else null;
    }
    pub fn txData(s: *ExecStore, digest: *const Id) ?[]const u8 {
        return if (s.executed(digest)) |e| e.td_bcs else null;
    }

    /// `tx_key_to_digest`: a digest key resolves to itself once executed.
    pub fn keyDigest(s: *ExecStore, key: Key) ?Id {
        s.lock.lock();
        defer s.lock.unlock();
        if (s.keys.get(keyBytes(key))) |d| return d;
        return switch (key) {
            .digest => |d| if (s.txs.contains(d)) d else null,
            else => null,
        };
    }

    /// `have_received_object_at_version(FullObjectKey(id, None, version), epoch)`.
    pub fn receivedAt(s: *ExecStore, epoch: u64, id: *const Id, version: u64) bool {
        s.lock.lock();
        defer s.lock.unlock();
        return s.received.contains(markerKey(epoch, id, version));
    }

    /// `get_last_consensus_stream_end_info(FullObjectID(id, Some(start_version)), epoch)` is
    /// Some: a transaction executed in `epoch` ended this consensus stream. (Every marker of a
    /// consensus full id is ConsensusStreamEnded, so the latest one is too.)
    pub fn streamEnded(s: *ExecStore, epoch: u64, id: *const Id, start_version: u64) bool {
        s.lock.lock();
        defer s.lock.unlock();
        return s.stream_ended.contains(markerKey(epoch, id, start_version));
    }

    /// `get_consensus_stream_end_tx_digest(FullObjectKey(FullObjectID(id, Some(start_version)),
    /// version), epoch)`: the transaction that ended (or smeared) the stream at `version`.
    pub fn streamEndDigest(s: *ExecStore, epoch: u64, id: *const Id, start_version: u64, version: u64) ?Id {
        s.lock.lock();
        defer s.lock.unlock();
        return s.stream_end_at.get(fullMarkerKey(epoch, id, start_version, version));
    }

    pub fn txCount(s: *ExecStore) usize {
        s.lock.lock();
        defer s.lock.unlock();
        return s.txs.count();
    }

    /// `exec.packages.Store.Lookup`: the live package object of `id` (system packages change in
    /// place at epoch changes; the newest written one is the one this epoch loads).
    pub fn packageLookup(s: *ExecStore) exec.packages.Store.Lookup {
        return .{ .ctx = s, .get = pkgGet };
    }
    fn pkgGet(ctx: *const anyopaque, id: *const [32]u8, epoch: u64) ?[]const u8 {
        _ = epoch;
        const s: *ExecStore = @ptrCast(@alignCast(@constCast(ctx)));
        const raw = s.latest(id) orelse return null;
        const v = ObjectView.parse(raw) catch return null;
        return if (v.is_package) raw else null;
    }

    // ------------------------------------------------------------------ records

    const tag_tx: u8 = 1;
    const tag_key: u8 = 2;

    fn applyRecord(s: *ExecStore, payload: []const u8) Error!void {
        var r: Rd = .{ .b = payload };
        const tag = try r.byte();
        s.lock.lock();
        defer s.lock.unlock();
        const a = s.arena.allocator();
        switch (tag) {
            tag_key => {
                const k = (try r.take(33))[0..33].*;
                const d = (try r.take(32))[0..32].*;
                try s.keys.put(s.gpa, k, d);
            },
            tag_tx => {
                const digest = (try r.take(32))[0..32].*;
                const nk = try r.int(u32);
                for (0..nk) |_| {
                    const k = (try r.take(33))[0..33].*;
                    try s.keys.put(s.gpa, k, digest);
                }
                const td = try a.dupe(u8, try r.slice());
                const fx = try a.dupe(u8, try r.slice());
                const evs: ?[]const u8 = if (try r.byte() == 1) try a.dupe(u8, try r.slice()) else null;
                const nw = try r.int(u32);
                for (0..nw) |_| {
                    const raw = try a.dupe(u8, try r.slice());
                    const v = ObjectView.parse(raw) catch return error.Corrupt;
                    try s.objects.put(s.gpa, objKey(&v.id, v.version), raw);
                    try s.addVersion(v.id, .{ .version = v.version, .kind = .live });
                }
                const nr = try r.int(u32);
                for (0..nr) |_| {
                    const id = (try r.take(32))[0..32].*;
                    const ver = try r.int(u64);
                    const kind: VersionKind = switch (try r.byte()) {
                        0 => .live,
                        1 => .deleted,
                        2 => .wrapped,
                        else => return error.Corrupt,
                    };
                    try s.addVersion(id, .{ .version = ver, .kind = kind });
                }
                if (r.at != payload.len) return error.Corrupt;
                const epoch = try s.indexMarkers(&digest, td, fx);
                try s.txs.put(s.gpa, digest, .{ .td_bcs = td, .effects_bcs = fx, .events_bcs = evs, .effects_digest = types.digest.effectsDigest(fx), .epoch = epoch });
            },
            else => return error.Corrupt,
        }
    }

    /// The markers of one executed transaction (sui-core `TransactionOutputs::build_transaction_outputs`,
    /// mainnet-v1.83.1), the ones signing reads: Received for each receiving input in the effects'
    /// `modified_at_versions`; ConsensusStreamEnded for a tombstone whose input was a consensus
    /// object, `transferred_from_consensus`, `consensus_owner_changed`, and the smear of every
    /// `MutateConsensusStreamEnded` input (start version from the transaction's shared input).
    /// Returns the effects' executed epoch; effects or data that do not decode (V1, test
    /// records) give epoch 0 and no markers. Caller holds `lock`.
    fn indexMarkers(s: *ExecStore, digest: *const Id, td_bcs: []const u8, fx_bcs: []const u8) Allocator.Error!u64 {
        const bcs = @import("bcs");
        var scratch = std.heap.ArenaAllocator.init(s.gpa);
        defer scratch.deinit();
        const a = scratch.allocator();
        const fx = bcs.decode(types.TransactionEffects, a, fx_bcs) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return 0,
        };
        const v2 = switch (fx) {
            .V2 => |v| v,
            .V1 => |v| return v.executed_epoch,
        };
        const epoch = v2.executed_epoch;
        const lamport = v2.lamport_version.@"0";
        const td: ?types.TransactionData = bcs.decode(types.TransactionData, a, td_bcs) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
        const inputs: []const types.CallArg = if (td) |t| switch (t.V1.kind) {
            .ProgrammableTransaction => |p| p.inputs,
            else => &.{},
        } else &.{};
        // received: receiving inputs that appear in modified_at_versions
        for (inputs) |in| switch (in) {
            .Object => |o| switch (o) {
                .Receiving => |r| for (v2.changed_objects) |c| switch (c[1].input_state) {
                    .Exist => |e| if (std.mem.eql(u8, &c[0].@"0".@"0", &r[0].@"0".@"0") and e[0][0].@"0" == r[1].@"0") {
                        try s.received.put(s.gpa, markerKey(epoch, &r[0].@"0".@"0", r[1].@"0"), {});
                    },
                    .NotExist => {},
                },
                else => {},
            },
            else => {},
        };
        for (v2.changed_objects) |c| {
            const id = &c[0].@"0".@"0";
            const in_owner = switch (c[1].input_state) {
                .Exist => |e| e[1],
                .NotExist => continue,
            };
            const start = consensusStart(in_owner) orelse continue;
            const ended = switch (c[1].output_state) {
                // deleted or wrapped (tombstone) of a consensus input
                .NotExist => true,
                .ObjectWrite => |w| c[1].id_operation == .None and switch (in_owner) {
                    // transferred_from_consensus / consensus_owner_changed
                    .ConsensusAddressOwner => |old| switch (w[1]) {
                        .AddressOwner, .ObjectOwner, .Immutable => true,
                        .ConsensusAddressOwner => |new| !std.mem.eql(u8, &old.owner.@"0", &new.owner.@"0"),
                        else => false,
                    },
                    else => false,
                },
                else => false,
            };
            if (ended) {
                try s.stream_ended.put(s.gpa, markerKey(epoch, id, start), {});
                try s.stream_end_at.put(s.gpa, fullMarkerKey(epoch, id, start, lamport), digest.*);
            }
        }
        // smears: MutateConsensusStreamEnded inputs, keyed by the transaction's start version
        for (v2.unchanged_consensus_objects) |u| switch (u[1]) {
            .MutateConsensusStreamEnded => for (inputs) |in| switch (in) {
                .Object => |o| switch (o) {
                    .SharedObject => |sh| if (std.mem.eql(u8, &sh.id.@"0".@"0", &u[0].@"0".@"0")) {
                        try s.stream_ended.put(s.gpa, markerKey(epoch, &u[0].@"0".@"0", sh.initial_shared_version.@"0"), {});
                        try s.stream_end_at.put(s.gpa, fullMarkerKey(epoch, &u[0].@"0".@"0", sh.initial_shared_version.@"0", lamport), digest.*);
                    },
                    else => {},
                },
                else => {},
            },
            else => {},
        };
        return epoch;
    }

    fn addVersion(s: *ExecStore, id: Id, v: Version) Allocator.Error!void {
        const gop = try s.history.getOrPut(s.gpa, id);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        const l = gop.value_ptr;
        // usually ascending: insert from the end, replacing an equal version
        var i = l.items.len;
        while (i > 0 and l.items[i - 1].version > v.version) i -= 1;
        if (i > 0 and l.items[i - 1].version == v.version) {
            l.items[i - 1] = v;
            return;
        }
        try l.insert(s.gpa, i, v);
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

/// (epoch, object id, version) of a marker.
fn markerKey(epoch: u64, id: *const Id, version: u64) [48]u8 {
    var k: [48]u8 = undefined;
    std.mem.writeInt(u64, k[0..8], epoch, .little);
    k[8..40].* = id.*;
    std.mem.writeInt(u64, k[40..48], version, .little);
    return k;
}

fn fullMarkerKey(epoch: u64, id: *const Id, start_version: u64, version: u64) [56]u8 {
    var k: [56]u8 = undefined;
    k[0..48].* = markerKey(epoch, id, start_version);
    std.mem.writeInt(u64, k[48..56], version, .little);
    return k;
}

/// `Owner::start_version` of a consensus owner (`Owner::is_consensus`).
pub fn consensusStart(o: types.Owner) ?u64 {
    return switch (o) {
        .Shared => |x| x.initial_shared_version.@"0",
        .ConsensusAddressOwner => |x| x.start_version.@"0",
        .Party => |x| x.start_version.@"0",
        else => null,
    };
}

pub fn objKey(id: *const Id, version: u64) [40]u8 {
    var k: [40]u8 = undefined;
    k[0..32].* = id.*;
    std.mem.writeInt(u64, k[32..40], version, .little);
    return k;
}

/// A TransactionKey as 33 bytes (tag, then its fields little-endian, zero padded).
pub fn keyBytes(key: Key) [33]u8 {
    var b: [33]u8 = @splat(0);
    switch (key) {
        .digest => |d| {
            b[0] = 0;
            b[1..33].* = d;
        },
        .randomness_round => |x| {
            b[0] = 1;
            std.mem.writeInt(u64, b[1..9], x.epoch, .little);
            std.mem.writeInt(u64, b[9..17], x.round, .little);
        },
        .accumulator_settlement => |x| {
            b[0] = 2;
            std.mem.writeInt(u64, b[1..9], x.epoch, .little);
            std.mem.writeInt(u64, b[9..17], x.height, .little);
        },
        .consensus_commit_prologue => |x| {
            b[0] = 3;
            std.mem.writeInt(u64, b[1..9], x.epoch, .little);
            std.mem.writeInt(u64, b[9..17], x.round, .little);
            std.mem.writeInt(u32, b[17..21], x.sub_dag_index, .little);
        },
    }
    return b;
}

fn encodeTx(gpa: Allocator, rec: *const TxRecord) Allocator.Error![]u8 {
    var w: std.ArrayList(u8) = .empty;
    errdefer w.deinit(gpa);
    try w.append(gpa, ExecStore.tag_tx);
    try w.appendSlice(gpa, &rec.digest);
    try putInt(gpa, &w, u32, @intCast(rec.keys.len));
    for (rec.keys) |k| try w.appendSlice(gpa, &keyBytes(k));
    try putSlice(gpa, &w, rec.td_bcs);
    try putSlice(gpa, &w, rec.effects_bcs);
    if (rec.events_bcs) |e| {
        try w.append(gpa, 1);
        try putSlice(gpa, &w, e);
    } else try w.append(gpa, 0);
    try putInt(gpa, &w, u32, @intCast(rec.written.len));
    for (rec.written) |o| try putSlice(gpa, &w, o);
    try putInt(gpa, &w, u32, @intCast(rec.removed.len));
    for (rec.removed) |x| {
        try w.appendSlice(gpa, &x.id);
        try putInt(gpa, &w, u64, x.version);
        try w.append(gpa, @intFromEnum(x.kind));
    }
    return w.toOwnedSlice(gpa);
}

fn putInt(gpa: Allocator, w: *std.ArrayList(u8), comptime T: type, v: T) Allocator.Error!void {
    var b: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &b, v, .little);
    try w.appendSlice(gpa, &b);
}
fn putSlice(gpa: Allocator, w: *std.ArrayList(u8), s: []const u8) Allocator.Error!void {
    try putInt(gpa, w, u32, @intCast(s.len));
    try w.appendSlice(gpa, s);
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

/// The removals of an effects (`changed_objects` whose output is no object): deleted when the
/// id operation is Deleted, wrapped otherwise. Allocated in `arena`.
pub fn removalsOf(arena: Allocator, effects_bcs: []const u8) ![]const Removed {
    const bcs = @import("bcs");
    const fx = try bcs.decode(types.TransactionEffects, arena, effects_bcs);
    const v2 = switch (fx) {
        .V2 => |v| v,
        .V1 => return error.Unsupported,
    };
    var out: std.ArrayList(Removed) = .empty;
    for (v2.changed_objects) |c| switch (c[1].output_state) {
        .NotExist => {
            // an object created and removed in the same transaction never existed
            if (c[1].input_state == .NotExist and c[1].id_operation == .Created) continue;
            try out.append(arena, .{ .id = c[0].@"0".@"0", .version = v2.lamport_version.@"0", .kind = if (c[1].id_operation == .Deleted) .deleted else .wrapped });
        },
        else => {},
    };
    return out.items;
}

// ---------------------------------------------------------------------- tests

const testing = std.testing;

/// A raw Move object (GasCoin-like layout: Data::Move, MoveObjectType::GasCoin, public transfer,
/// version, contents = id ++ balance, AddressOwner, previous tx, rebate).
pub fn testObject(a: Allocator, id: Id, version: u64, owner: Id) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    try b.appendSlice(a, &.{ 0, 1, 1 });
    var v8: [8]u8 = undefined;
    std.mem.writeInt(u64, &v8, version, .little);
    try b.appendSlice(a, &v8);
    try b.append(a, 40);
    try b.appendSlice(a, &id);
    try b.appendSlice(a, &.{ 1, 0, 0, 0, 0, 0, 0, 0 });
    try b.append(a, 0);
    try b.appendSlice(a, &owner);
    try b.append(a, 32);
    try b.appendSlice(a, &@as([32]u8, @splat(0)));
    try b.appendSlice(a, &.{ 0, 0, 0, 0, 0, 0, 0, 0 });
    return b.items;
}

test "exec store: commit, reads, tombstones, keys, reopen, torn tail" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const db = pb[0..try tmp.dir.realPath(io, &pb)];

    const id1: Id = @splat(1);
    const id2: Id = @splat(2);
    const owner: Id = @splat(9);
    const d1: Id = @splat(0xd1);
    const d2: Id = @splat(0xd2);
    {
        var s = try ExecStore.open(gpa, io, db);
        defer s.close();
        try s.commitTx(&.{ .digest = d1, .td_bcs = "td1", .effects_bcs = "fx1", .written = &.{ try testObject(a, id1, 1, owner), try testObject(a, id2, 1, owner) } });
        try s.commitTx(&.{
            .digest = d2,
            .keys = &.{.{ .randomness_round = .{ .epoch = 0, .round = 7 } }},
            .td_bcs = "td2",
            .effects_bcs = "fx2",
            .events_bcs = "ev2",
            .written = &.{try testObject(a, id1, 5, owner)},
            .removed = &.{.{ .id = id2, .version = 5, .kind = .deleted }},
        });
        // idempotent
        try s.commitTx(&.{ .digest = d2, .td_bcs = "other", .effects_bcs = "other", .written = &.{} });
        try testing.expectEqualStrings("fx2", s.effects(&d2).?);
    }
    // reopen rebuilds everything
    var s = try ExecStore.open(gpa, io, db);
    try testing.expectEqual(@as(usize, 2), s.txCount());
    try testing.expectEqual(@as(u64, 5), (try ObjectView.parse(s.latest(&id1).?)).version);
    try testing.expect(s.objectAt(&id1, 1) != null);
    try testing.expect(s.latest(&id2) == null);
    try testing.expectEqual(VersionKind.deleted, s.latestVersion(&id2).?.kind);
    try testing.expect(s.atMost(&id2, 4) != null);
    try testing.expect(s.atMost(&id2, 9) == null);
    try testing.expectEqual(@as(u64, 1), (try ObjectView.parse(s.atMost(&id1, 4).?)).version);
    try testing.expectEqualSlices(u8, &d2, &s.keyDigest(.{ .randomness_round = .{ .epoch = 0, .round = 7 } }).?);
    try testing.expectEqualSlices(u8, &d1, &s.keyDigest(.{ .digest = d1 }).?);
    try testing.expect(s.keyDigest(.{ .digest = @splat(3) }) == null);
    try testing.expectEqualStrings("ev2", s.events(&d2).?);
    try testing.expectEqualStrings("td1", s.txData(&d1).?);
    try s.putKey(.{ .accumulator_settlement = .{ .epoch = 0, .height = 3 } }, d1);
    const end = s.end;
    s.close();

    // a torn tail (half a record) is cut at open, the rest survives
    {
        const path = try std.fs.path.join(gpa, &.{ db, "validator", "exec", "exec.log" });
        defer gpa.free(path);
        const f = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
        defer f.close(io);
        try f.writePositionalAll(io, &.{ 200, 0, 0, 0, 1, 2, 3 }, end);
    }
    var s2 = try ExecStore.open(gpa, io, db);
    defer s2.close();
    try testing.expectEqual(@as(u64, 7), s2.cut_at_open);
    try testing.expectEqual(end, s2.end);
    try testing.expectEqualSlices(u8, &d1, &s2.keyDigest(.{ .accumulator_settlement = .{ .epoch = 0, .height = 3 } }).?);
}

test "exec store: key encoding distinguishes kinds" {
    const a = keyBytes(.{ .randomness_round = .{ .epoch = 1, .round = 2 } });
    const b = keyBytes(.{ .accumulator_settlement = .{ .epoch = 1, .height = 2 } });
    try testing.expect(!std.mem.eql(u8, &a, &b));
}

test "exec store: consensus stream end markers at the ending transaction's lamport version" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const bcs = @import("bcs");
    var s = ExecStore.openMem(gpa, testing.io);
    defer s.close();
    const party: Id = @splat(0x57);
    const holder: Id = @splat(9);
    const d: Id = @splat(0xd7);
    const z: types.ObjectDigest = .{ .@"0" = .{ .@"0" = @splat(0) } };
    // a party object (start 5) transferred to an address: transferred_from_consensus at lamport 12
    const fx: types.TransactionEffects = .{ .V2 = .{
        .status = .Success,
        .executed_epoch = 3,
        .gas_used = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .transaction_digest = .{ .@"0" = .{ .@"0" = d } },
        .gas_object_index = null,
        .events_digest = null,
        .dependencies = &.{},
        .lamport_version = .{ .@"0" = 12 },
        .changed_objects = &.{.{ .{ .@"0" = .{ .@"0" = party } }, .{
            .input_state = .{ .Exist = .{ .{ .{ .@"0" = 7 }, z }, .{ .ConsensusAddressOwner = .{ .start_version = .{ .@"0" = 5 }, .owner = .{ .@"0" = holder } } } } },
            .output_state = .{ .ObjectWrite = .{ z, .{ .AddressOwner = .{ .@"0" = holder } } } },
            .id_operation = .None,
        } }},
        .unchanged_consensus_objects = &.{},
        .aux_data_digest = null,
    } };
    const fx_bcs = try bcs.encodeAlloc(types.TransactionEffects, a, &fx);
    try s.commitTx(&.{ .digest = d, .td_bcs = "td", .effects_bcs = fx_bcs, .written = &.{try testObject(a, party, 12, holder)} });
    try testing.expect(s.streamEnded(3, &party, 5));
    try testing.expectEqual(d, s.streamEndDigest(3, &party, 5, 12).?);
    try testing.expect(s.streamEndDigest(3, &party, 5, 7) == null);
    try testing.expect(s.streamEndDigest(4, &party, 5, 12) == null);
}
