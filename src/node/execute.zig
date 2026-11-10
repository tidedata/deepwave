//! Execute mode: re-execute what exec supports and compare with the certified checkpoint.
//!
//! The follower has already verified the checkpoint (certificate, digests, output objects
//! against effects) when it calls the observer, and stores the certified bytes either way. This
//! stage runs every transaction exec can execute and checks that deepwave produces the same effects
//! bytes and the same bytes for every output object. A transaction exec reports unsupported is
//! counted and left verified-only, so execute mode never stops on a protocol version or a
//! transaction kind exec does not cover yet.
//!
//! Dispatch. When exec exports `executeTransaction` (CONTRACTS 6.7 request), it is used for every
//! transaction and picked up at compile time with no change here. Until then the node routes each
//! transaction to exec's executors the way exec-replay does (src/exec/conformance.zig):
//!   - consensus commit prologues: `exec.ccp`;
//!   - system transactions (settlement, randomness, authenticator state, end of epoch):
//!     `exec.system.execute`;
//!   - coin-only PTBs: `exec.coin_ptb`, then the Move-call executor for what it does not model;
//!   - Move-call, MakeMoveVec and publish/upgrade PTBs: `exec.ptb.execute` (every cut `exec.versions.moveSupported` names).
//! Anything else, and anything an executor reports unsupported, is verified only.
//!
//! Inputs. Objects come from the checkpoint (its input and output objects), then the archive's
//! object set (`<seq>.aux`: read-only and immutable inputs, packages, runtime loads), then the
//! store. Packages are exec's `packages.Store`, grown as the node follows: every package the
//! checkpoints carry (inputs, outputs, the archive's object set). System packages follow the
//! store's rule: a system package read in epoch E is E's; one written by E's end-of-epoch
//! transaction is E+1's. A package the node has not seen is unsupported, never guessed.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const store = @import("store");
const exec = @import("exec");
const sync = @import("sync");
const trust = @import("trust.zig");
const convert = @import("convert.zig");
const Bump = @import("bump.zig").Bump;
const memstat = @import("memstat.zig");
const removal_log = @import("removal_log.zig");
const Io = std.Io;
const Atomic = std.atomic.Value(u64);

/// What reused per-checkpoint and per-transaction buffers keep across resets. Every owner keeps
/// its high-water mark otherwise, and there are many owners (`exec_window` jobs, one transaction
/// arena per thread), so the private memory of a sync grew with the largest checkpoint and
/// transaction seen (3.4 GiB by checkpoint 1.69M). A larger checkpoint or transaction allocates
/// past these and gives the rest back at its reset.
pub const keep = struct {
    /// A thread's transaction arena (and a job's ordered-rerun arena).
    pub const tx: usize = 8 << 20;
    /// A job's decode and prepare arena (Bump chunks double from 256 KiB: 2 MiB keeps the
    /// first three; `exec_window` jobs keep it each).
    pub const job: usize = 2 << 20;
    /// A job's checkpoint and archive-record bytes.
    pub const buf: usize = 8 << 20;
};

pub const Stats = struct {
    checkpoints: Atomic = .init(0),
    transactions: Atomic = .init(0),
    executed: Atomic = .init(0),
    matched: Atomic = .init(0),
    mismatched: Atomic = .init(0),
    unsupported: Atomic = .init(0),
    errors: Atomic = .init(0),
    exec_ns: Atomic = .init(0),
    /// Executed transactions by executor.
    ran_ccp: Atomic = .init(0),
    ran_coin: Atomic = .init(0),
    ran_move: Atomic = .init(0),
    ran_system: Atomic = .init(0),
    /// Checkpoints without an archive record (`.chk` source): runtime loads are unknown.
    no_aux: Atomic = .init(0),
    /// Transactions whose parallel result differed and that ran again in order afterwards
    /// (`rerun_matched` of them then matched).
    reruns: Atomic = .init(0),
    rerun_matched: Atomic = .init(0),
    /// The newest checkpoint whose every transaction is done (all earlier ones are done too).
    done_seq: Atomic = .init(0),
};

/// Why the last transaction this thread ran stayed verify-only (`Executor.skip`).
threadlocal var last_why: []const u8 = "";

pub const Mismatch = struct { seq: u64, tx: u32, why: []const u8 };

pub const Verdict = enum { match, mismatch, verify_only };

/// Called once per transaction (`tx` = maxInt(u32) for a checkpoint that could not be read).
pub const Report = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, seq: u64, tx: u32, v: Verdict, why: []const u8) void,
};

pub const Executor = struct {
    gpa: std.mem.Allocator,
    io: Io,
    st: *store.Store,
    stats: Stats = .{},
    /// Seeding only (`seedSystemPackages`, before any checkpoint).
    idx: types.CheckpointIndex,
    /// Where `<seq>.aux` records are (the spool, or a directory source); null: none.
    aux_dir: ?Io.Dir = null,
    /// Every package seen so far (see the file comment). Bytes live in `pkg_arena`. Written only
    /// by the ordered prepare step, under `pkg_lock`; transactions read it through `pkgs_view`.
    pkgs: exec.packages.Store = .{},
    /// What exec's executors get: empty maps and a fallback that reads `pkgs` under a shared
    /// `pkg_lock`, so transactions of earlier checkpoints run while a later one adds packages.
    pkgs_view: exec.packages.Store = .{},
    pkg_lock: Io.RwLock = .init,
    pkg_arena: std.heap.ArenaAllocator,
    /// Memory all threads' Move package caches may hold together (`--exec-cache-mb`).
    cache_budget: usize = 3 << 30,
    /// Checkpoint bytes in flight between submit and done (with the job count, `start`'s window).
    window_bytes: u64 = 128 << 20,
    /// Packages in `pkgs` and their bytes (status line `mem`).
    pkg_count: Atomic = .init(0),
    pkg_bytes: Atomic = .init(0),
    /// Package bytes (by address) -> the ids its linkage table names (prepare step only).
    linkage: std.AutoHashMapUnmanaged(usize, []const [32]u8) = .empty,
    /// `--packages DIR`: `<id hex>.obj` raw package objects (exec's corpus format), tried before
    /// the store for packages the node has not seen in a followed checkpoint.
    pkg_dir: ?Io.Dir = null,
    /// `--packages-from URL`: a full node asked (GetObject bcs, 20 req/s) for packages found
    /// nowhere else; fetched packages are saved to `pkg_dir` when it is writable.
    pkg_fetch: ?*@import("pkgfetch.zig").Fetcher = null,
    /// Holds `pkg_fetch` off while its full node does not answer (ordered step only).
    fetch_gate: FetchGate = .{},
    /// The network followed: selects the protocol table (`--network`).
    chain: protocol.Chain = .mainnet,
    /// Mismatches logged with both effects in hex (the first 3).
    hex_logged: Atomic = .init(0),
    /// Package ids found in neither the dir nor the store (not retried in this epoch).
    pkg_absent: std.AutoHashMapUnmanaged([32]u8, u64) = .empty,
    /// Why transactions stayed verify-only: reason -> count (reasons are static strings or
    /// copied into `pkg_arena`). Read by the status line under `why_lock`.
    whys: std.StringArrayHashMapUnmanaged(u64) = .empty,
    why_arena: std.heap.ArenaAllocator,
    why_lock: std.Io.Mutex = .init,
    /// First disagreement (the node halts on it when configured to), under `why_lock`.
    first_mismatch: ?Mismatch = null,
    mismatch_seen: std.atomic.Value(bool) = .init(false),
    report_lock: std.Io.Mutex = .init,
    why_buf: [256]u8 = undefined,
    /// The first epoch whose start the store's live object set fully covers: a formal snapshot of
    /// epoch E-1 restored (E), or a store that holds checkpoint 0 (0). null: the store holds only
    /// what the node followed, so an object it lacks may still exist (see `Lookup.latest`).
    complete_from: ?u64 = null,
    /// `--deny-state FILE`: exec's deny-list state file (`deny/objects.bin.zst`, every version of
    /// the 0x403 per-type configs and their settings with the epoch that wrote each), for stores
    /// that do not hold the full live set. Untrusted like `--packages`: a wrong file can only make
    /// a result differ from the certified one (a mismatch), never make the node accept anything.
    deny: ?exec.ptb.deny.Snapshot = null,
    /// Per-transaction verdicts for a caller that tallies them (the `node-execute` suite).
    report: ?Report = null,
    /// (id, the version its removal record carries) -> the version that removal (delete or wrap)
    /// consumed, from the checkpoints this process followed: a system child read whose store
    /// record is a removal above the bound starts its walk back there. Keyed by the removal, so a
    /// checkpoint's entries never answer an earlier checkpoint's reads (the pipeline notes them
    /// before earlier checkpoints finish). Durable with `openPriorLog` (removal_log.zig: the
    /// node's `<dir>/node/removed-prior.log`, reloaded and caught up from the store at start);
    /// without it in memory only. Cleared at `removed_cap` entries.
    removed_prior: std.AutoHashMapUnmanaged(RemovalKey, u64) = .empty,
    removed_lock: std.Io.Mutex = .init,
    prior_log: ?removal_log.Log = null,
    prior_scan: ?std.Thread = null,
    prior_scan_stop: std.atomic.Value(bool) = .init(false),
    /// The pipeline (`start`); without it `submit` runs each checkpoint on the caller's thread.
    pool: Pool = .{},
    /// The caller-thread job when there is no pool.
    inline_job: ?*Job = null,

    pub const RemovalKey = removal_log.Key;

    pub fn init(gpa: std.mem.Allocator, io: Io, st: *store.Store, aux_dir: ?Io.Dir) !Executor {
        return .{ .gpa = gpa, .io = io, .st = st, .aux_dir = aux_dir, .idx = try types.CheckpointIndex.init(gpa), .pkg_arena = .init(gpa), .why_arena = .init(gpa) };
    }

    const removed_cap = 8 << 20;

    pub fn deinit(x: *Executor) void {
        x.stop();
        if (x.pkg_fetch) |f| {
            f.deinit();
            x.gpa.destroy(f);
        }
        if (x.inline_job) |j| {
            j.deinit(x.gpa);
            x.gpa.destroy(j);
        }
        x.prior_scan_stop.store(true, .release);
        if (x.prior_scan) |t| t.join();
        if (x.prior_log) |*l| l.close();
        x.removed_prior.deinit(x.gpa);
        x.idx.deinit(x.gpa);
        x.linkage.deinit(x.gpa);
        x.pkg_arena.deinit();
        x.why_arena.deinit();
    }

    /// The default number of executor threads: half the CPUs (the follower's workers, fetchers
    /// and, on a shared box, other processes use the rest), at least 1, at most 16.
    pub fn defaultThreads() u32 {
        const n = std.Thread.getCpuCount() catch 2;
        return @intCast(std.math.clamp(n / 2, 1, 16));
    }

    /// Loads `--deny-state FILE` (zstd of exec's deny-list records).
    pub fn loadDenyState(x: *Executor, path: []const u8) !usize {
        const a = x.pkg_arena.allocator();
        const z = try Io.Dir.cwd().readFileAlloc(x.io, path, a, .limited(1 << 30));
        const raw = try convert.unzstd(a, z, 1 << 32);
        x.deny = try exec.ptb.deny.Snapshot.parse(a, raw);
        return x.deny.?.map.count();
    }

    /// The store's live set holds every object that exists at the start of `epoch`, plus every
    /// change the node followed since.
    fn stateComplete(x: *const Executor, epoch: u64) bool {
        const from = x.complete_from orelse return false;
        return epoch >= from;
    }

    fn verdict(x: *Executor, seq: u64, tx: usize, v: Verdict, why: []const u8) void {
        const r = x.report orelse return;
        x.report_lock.lockUncancelable(x.io);
        defer x.report_lock.unlock(x.io);
        r.f(r.ctx, seq, @intCast(@min(tx, std.math.maxInt(u32))), v, why);
    }

    /// Object reads of one checkpoint's transactions. `get` serves exact versions; `latest` and
    /// `latest_unstable` serve the reads exec makes outside a transaction's inputs (the coin deny
    /// list v2 state and per-epoch config settings, `ObjectStore::get_object`), CONTRACTS 6.4.3.
    const Lookup = struct {
        table: *const exec.objects.ObjectTable,
        /// The archive's object set beyond the checkpoint's own objects.
        extra: *const exec.objects.ObjectTable,
        snap: *const store.Snapshot,
        x: *Executor,
        epoch: u64,
        blob: []const u8,
        /// The checkpoint's transactions before the executing one (set per transaction).
        earlier: []const types.index.Tx = &.{},
        /// What the checkpoint's transactions left of each object (the job's, built in `decode`).
        changes: *const Changes,
        /// Set when `latest` could not answer exactly: the transaction's result is discarded and
        /// it stays verify-only with this reason.
        gap: ?[]const u8 = null,
        /// Every transaction of the checkpoint (the executing one is `earlier.len`) and the
        /// transaction's arena, for `received`.
        txs: []const types.index.Tx = &.{},
        arena: ?std.mem.Allocator = null,

        fn get(p: *const anyopaque, id: *const [32]u8, version: u64) ?[]const u8 {
            const l: *const Lookup = @ptrCast(@alignCast(p));
            const k: exec.objects.Key = .{ .id = id.*, .version = version };
            return l.table.get(k) orelse l.extra.get(k) orelse l.snap.objectAt(id, version);
        }

        /// The object as the validator's store holds it when the transaction runs: the newest
        /// write or removal by the checkpoint's earlier transactions, else the store's live
        /// record (the store has committed every earlier checkpoint). An id the store has never
        /// seen does not exist when the store holds the full live set; otherwise the deny-list
        /// state file answers, or the read is a gap.
        fn latest(p: *const anyopaque, id: *const [32]u8) ?[]const u8 {
            const l: *Lookup = @ptrCast(@alignCast(@constCast(p)));
            switch (l.changes.last(l.blob, l.earlier.len, id)) {
                .found => |b| return b,
                .removed => return null,
                .none => {},
            }
            const st = l.snap.latest(id) catch {
                l.gap = "store read error";
                return null;
            };
            if (st) |o| return switch (o) {
                .live => |v| v.bytes,
                .removed => null,
            };
            if (l.x.stateComplete(l.epoch)) return null;
            if (l.x.deny) |*d| return d.get(id, l.epoch);
            l.gap = "deny list state not available (store without the full live set, no --deny-state)";
            return null;
        }

        /// True when `id` may have been written during the executing epoch (exec then leaves a
        /// per-epoch config read unsupported): an earlier transaction of this checkpoint changed
        /// it, or the store's live version was written by a transaction of this epoch, or it was
        /// removed (the removing transaction is not indexed), or the node cannot tell (an id it
        /// has never seen without the full live set, unless the deny-list state file covers it).
        fn unstable(p: *const anyopaque, id: *const [32]u8) bool {
            const l: *const Lookup = @ptrCast(@alignCast(p));
            switch (l.changes.last(l.blob, l.earlier.len, id)) {
                .found, .removed => return true,
                .none => {},
            }
            const st = l.snap.latest(id) catch return true;
            if (st) |o| switch (o) {
                .live => |v| {
                    const view = exec.objects.ObjectView.parse(v.bytes) catch return true;
                    const writer = v.bytes[view.prev_tx_at + 1 ..][0..32];
                    if (l.snap.transaction(writer)) |rec| {
                        const cp = l.snap.checkpoint(rec.checkpoint) orelse return true;
                        return cp.epoch >= l.epoch;
                    }
                    // Not a followed transaction: the version came with a formal snapshot (written
                    // before the epoch the store is complete from).
                    return !l.x.stateComplete(l.epoch);
                },
                .removed => return true,
            };
            if (l.x.stateComplete(l.epoch)) return false;
            if (l.x.deny) |*d| return d.writtenIn(id, l.epoch);
            return true;
        }

        /// Sui's Received marker: an earlier transaction changed `id` from `version` (only a
        /// receive changes an object an object owns). The checkpoint's own transactions decide
        /// first (one before this one received it; this one or a later one changes it from
        /// there, so it was still unreceived); otherwise the store's live version, above
        /// `version`, says an earlier checkpoint did.
        fn received(p: *const anyopaque, id: *const [32]u8, version: u64) bool {
            const l: *const Lookup = @ptrCast(@alignCast(p));
            const arena = l.arena orelse return false;
            const fxs = arena.alloc([]const u8, l.txs.len) catch return false;
            for (l.txs, fxs) |*t, *f| f.* = t.effects.slice(l.blob);
            if (receivedInCheckpoint(arena, fxs, l.earlier.len, id, version)) |r| return r;
            const latest_rec = (l.snap.latest(id) catch return false) orelse return false;
            return receivedBefore(latest_rec, version);
        }

        fn objectLookup(l: *const Lookup) exec.coin_ptb.ObjectLookup {
            return .{ .ctx = l, .get = get, .latest = latest, .latest_unstable = unstable, .received = received };
        }
    };

    fn skip(x: *Executor, why: []const u8) ?Out {
        _ = x;
        last_why = why;
        return null;
    }

    fn tallyWhy(x: *Executor, why: []const u8, seq: u64, tx: usize) void {
        x.why_lock.lockUncancelable(x.io);
        defer x.why_lock.unlock(x.io);
        const gop = x.whys.getOrPut(x.why_arena.allocator(), why) catch return;
        if (!gop.found_existing) {
            if (x.whys.count() > 256) {
                // Bounded: dynamic reasons beyond 256 distinct ones fold into one bucket.
                _ = x.whys.swapRemove(why);
                const other = x.whys.getOrPut(x.why_arena.allocator(), "other") catch return;
                if (!other.found_existing) other.value_ptr.* = 0;
                other.value_ptr.* += 1;
                return;
            }
            gop.key_ptr.* = x.why_arena.allocator().dupe(u8, why) catch "other";
            gop.value_ptr.* = 0;
            // The first example of each reason, so a new gap can be looked at.
            std.log.info("execute: verify-only, first of its kind: checkpoint {d} tx {d}: {s}", .{ seq, tx, why });
        }
        gop.value_ptr.* += 1;
    }

    /// The `n` most common verify-only reasons, as "reason count; ...".
    pub fn topWhys(x: *Executor, w: *std.Io.Writer, n: usize) void {
        x.why_lock.lockUncancelable(x.io);
        defer x.why_lock.unlock(x.io);
        var shown: [16]usize = undefined;
        const k = @min(n, shown.len, x.whys.count());
        for (0..k) |j| {
            var best: ?usize = null;
            for (x.whys.values(), 0..) |v, i| {
                if (std.mem.indexOfScalar(usize, shown[0..j], i) != null) continue;
                if (best == null or v > x.whys.values()[best.?]) best = i;
            }
            shown[j] = best.?;
            w.print("{s}{s} {d}", .{ if (j > 0) "; " else "", x.whys.keys()[best.?], x.whys.values()[best.?] }) catch {};
        }
    }

    /// Reads `<seq>.aux` into `out` (false when absent or unreadable: runtime loads are then
    /// unknown). Called before the checkpoint commits: the spool drops it after the commit.
    fn readAux(x: *Executor, seq: u64, out: *std.ArrayList(u8)) bool {
        const d = x.aux_dir orelse return false;
        var nb: [48]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, "{d}.aux", .{seq}) catch unreachable;
        const f = d.openFile(x.io, name, .{}) catch return false;
        defer f.close(x.io);
        const size: usize = @intCast((f.stat(x.io) catch return false).size);
        out.resize(x.gpa, size) catch return false;
        return (f.readPositionalAll(x.io, out.items, 0) catch return false) == size;
    }

    /// Seeds the system packages in force up to `upto_epoch` from a directory of checkpoint blobs
    /// (`--trust-dir`): checkpoint 0 (genesis writes the first ones) and each epoch's last
    /// checkpoint (its end-of-epoch transaction writes upgrades, visible from the next epoch),
    /// found with the epoch index. Same rule as exec-replay's corpus loader. These blobs are the
    /// operator's local files: a wrong one can only make execution disagree with the certified
    /// effects (a mismatch), never make the node accept anything.
    pub fn seedSystemPackages(x: *Executor, dir: Io.Dir, last_of_epoch: []const ?u64, upto_epoch: u64) usize {
        var n: usize = 0;
        n += x.seedFrom(dir, 0, 0);
        for (last_of_epoch, 0..) |last, e| {
            if (e >= upto_epoch) break;
            if (last) |seq| n += x.seedFrom(dir, seq, e + 1);
        }
        return n;
    }

    fn seedFrom(x: *Executor, dir: Io.Dir, seq: u64, from: u64) usize {
        var nb: [48]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, "{d}.chk", .{seq}) catch unreachable;
        const blob = dir.readFileAlloc(x.io, name, x.gpa, .limited(1 << 30)) catch return 0;
        defer x.gpa.free(blob);
        types.indexCheckpointData(blob, &x.idx) catch return 0;
        var n: usize = 0;
        for (0..x.idx.tx_count) |i| {
            const t = x.idx.txAt(i);
            for (x.idx.objs[t.out_first..][0..t.out_count]) |r| {
                const raw = r.slice(blob);
                const v = exec.objects.ObjectView.parse(raw) catch continue;
                if (!v.is_package or !exec.packages.isSystemPackage(&v.id)) continue;
                x.addPackage(raw, from);
                n += 1;
            }
        }
        return n;
    }

    /// The package ids a checkpoint's transactions name directly: the framework, the packages and
    /// type arguments of their commands, and the types of every object they read or write (its
    /// own and the archive's object set). Pure: runs on any thread before the ordered step.
    fn packageIds(arena: std.mem.Allocator, blob: []const u8, idx: *const types.CheckpointIndex, txs: []const types.CheckpointTransaction, extra: *const exec.objects.ObjectTable) std.mem.Allocator.Error![]const [32]u8 {
        var work: std.ArrayList([32]u8) = .empty;
        for ([_]u8{ 1, 2, 3 }) |b| {
            var id: [32]u8 = @splat(0);
            id[31] = b;
            try work.append(arena, id);
        }
        for (txs) |*t| switch (t.transaction.data.@"0".element().intent_message.value.V1.kind) {
            .ProgrammableTransaction => |*pt| for (pt.commands) |*cmd| switch (cmd.*) {
                .MoveCall => |*mc| {
                    try work.append(arena, mc.package.@"0".@"0");
                    for (mc.type_arguments) |*ty| try typeInputIds(arena, &work, ty);
                },
                .MakeMoveVec => |*mv| if (mv[0]) |*ty| try typeInputIds(arena, &work, ty),
                else => {},
            },
            else => {},
        };
        for (idx.objs[0..idx.obj_total]) |r| try objectTypeIds(arena, &work, r.slice(blob));
        var it = extra.map.valueIterator();
        while (it.next()) |raw| try objectTypeIds(arena, &work, raw.*);
        // Distinct ids only (most objects of a checkpoint share a handful of types).
        var seen: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
        var out: std.ArrayList([32]u8) = .empty;
        for (work.items) |id| {
            if ((try seen.getOrPut(arena, id)).found_existing) continue;
            try out.append(arena, id);
        }
        return out.items;
    }

    /// Makes every package the checkpoint's transactions can load available in `pkgs` before
    /// they run: the ids `packageIds` found, then each package's linkage table (which lists all
    /// of its transitive dependencies). A package the node has not seen in a followed checkpoint
    /// comes from `--packages DIR`, then from the store's live version (a snapshot-started store
    /// holds every package). Only ids not yet known are looked up. Ordered step only.
    fn resolvePackages(x: *Executor, arena: std.mem.Allocator, snap: *const store.Snapshot, epoch: u64, ids: []const [32]u8) void {
        var work: std.ArrayList([32]u8) = .empty;
        work.appendSlice(arena, ids) catch return;
        var seen: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
        while (work.pop()) |id| {
            if ((seen.getOrPut(arena, id) catch return).found_existing) continue;
            const raw = x.pkgs.get(&id, epoch) orelse x.findPackage(snap, &id, epoch) orelse continue;
            const gop = x.linkage.getOrPut(x.gpa, @intFromPtr(raw.ptr)) catch return;
            if (!gop.found_existing) {
                gop.value_ptr.* = &.{};
                const pkg = bcs.decode(types.Object, arena, raw) catch continue;
                switch (pkg.data) {
                    .Package => |*mp| {
                        const deps = x.pkg_arena.allocator().alloc([32]u8, mp.linkage_table.entries.len) catch return;
                        for (mp.linkage_table.entries, deps) |e, *d| d.* = e.value.upgraded_id.@"0".@"0";
                        gop.value_ptr.* = deps;
                    },
                    .Move => {},
                }
            }
            work.appendSlice(arena, gop.value_ptr.*) catch return;
        }
    }

    /// A package from `--packages DIR` or the store (added to `pkgs`), or null.
    fn findPackage(x: *Executor, snap: *const store.Snapshot, id: *const [32]u8, epoch: u64) ?[]const u8 {
        if (x.pkg_absent.get(id.*)) |e| if (e == epoch) return null;
        if (x.pkg_dir) |d| {
            var nb: [80]u8 = undefined;
            const name = std.fmt.bufPrint(&nb, "{x}.obj", .{id}) catch unreachable;
            if (d.readFileAlloc(x.io, name, x.gpa, .limited(1 << 28))) |raw| {
                defer x.gpa.free(raw);
                x.addPackage(raw, epoch);
                if (x.pkgs.get(id, epoch)) |got| return got;
            } else |_| {}
        }
        if (snap.latest(id) catch null) |l| switch (l) {
            .live => |o| {
                x.addPackage(o.bytes, epoch);
                if (x.pkgs.get(id, epoch)) |got| return got;
            },
            .removed => {},
        };
        if (x.pkg_fetch) |f| {
            // This is the ordered step: every later checkpoint waits on it. One request is cut
            // at the fetcher's timeout, and a full node that does not answer is left alone for
            // a while, so a dead or slow one costs one timeout per pause, not one per package.
            // Not asked is not absent: the id is asked for again once the pause is over.
            if (!x.fetch_gate.open(nowMs())) return null;
            var fa: std.heap.ArenaAllocator = .init(x.gpa);
            defer fa.deinit();
            const errors = f.errors;
            const fetched = f.get(fa.allocator(), id);
            if (f.errors != errors) {
                const pause = x.fetch_gate.failed(nowMs());
                std.log.warn("execute: --packages-from did not answer for package {x} (within {d} ms); not asked again for {d} s, transactions that need a package it holds stay verify-only meanwhile", .{ id, f.timeout_ms, pause / 1000 });
                return null;
            }
            x.fetch_gate.answered();
            if (fetched) |raw| {
                const ok = if (exec.objects.ObjectView.parse(raw)) |v| v.is_package and std.mem.eql(u8, &v.id, id) else |_| false;
                if (ok) {
                    x.addPackage(raw, epoch);
                    if (x.pkg_dir) |d| {
                        var nb: [80]u8 = undefined;
                        const name = std.fmt.bufPrint(&nb, "{x}.obj", .{id}) catch unreachable;
                        d.writeFile(x.io, .{ .sub_path = name, .data = raw }) catch {};
                    }
                    if (x.pkgs.get(id, epoch)) |got| return got;
                }
            }
        }
        x.pkg_absent.put(x.pkg_arena.allocator(), id.*, epoch) catch {};
        return null;
    }

    /// Adds a package object to `pkgs`: a non-system package once per id (immutable), a system
    /// package as the version in force from epoch `from`.
    fn addPackage(x: *Executor, raw: []const u8, from: u64) void {
        const v = exec.objects.ObjectView.parse(raw) catch return;
        if (!v.is_package) return;
        const pa = x.pkg_arena.allocator();
        if (!exec.packages.isSystemPackage(&v.id)) {
            if (x.pkgs.user.contains(v.id)) return;
            const copy = pa.dupe(u8, raw) catch return;
            x.pkg_lock.lockUncancelable(x.io);
            defer x.pkg_lock.unlock(x.io);
            x.pkgs.user.put(pa, v.id, copy) catch return;
            x.notePkg(raw.len);
            return;
        }
        if (x.pkgs.system.get(v.id)) |list| if (list.items.len > 0 and list.items[list.items.len - 1].epoch >= from) return;
        const copy = pa.dupe(u8, raw) catch return;
        x.pkg_lock.lockUncancelable(x.io);
        defer x.pkg_lock.unlock(x.io);
        const gop = x.pkgs.system.getOrPut(pa, v.id) catch return;
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        gop.value_ptr.append(pa, .{ .epoch = from, .raw = copy }) catch return;
        x.notePkg(raw.len);
    }

    fn notePkg(x: *Executor, len: usize) void {
        _ = x.pkg_count.fetchAdd(1, .monotonic);
        _ = x.pkg_bytes.fetchAdd(len, .monotonic);
    }

    /// The status line's executor memory gauges (sizes read without locks: approximate).
    pub fn memLine(x: *Executor, w: *std.Io.Writer) void {
        w.print(" inflight {d} MiB", .{@atomicLoad(u64, &x.pool.inflight_bytes, .monotonic) >> 20}) catch {};
        w.print(" pkgs {d} ({d} MiB) linkage {d} absent {d} removed {d} | ptb caches {d} ({d} MiB, {d} rebuilds, cap {d} MiB) exec gpa {d} MiB", .{
            x.pkg_count.load(.monotonic),           x.pkg_bytes.load(.monotonic) >> 20,
            x.linkage.count(),                      x.pkg_absent.count(),
            x.removed_prior.count(),                exec.ptb.pkgs.cache_count.load(.monotonic),
            exec.ptb.pkgs.cache_bytes.load(.monotonic) >> 20, exec.ptb.pkgs.cache_rebuilds.load(.monotonic),
            exec.ptb.pkgs.max_cache_bytes >> 20,    memstat.exec_gpa.bytes() >> 20,
        }) catch {};
        // The process-wide parsed-package table (bytes counted once; a cache's MiB above
        // includes the entries it pins there).
        if (exec.ptb.pkgs.shared_enabled) w.print(" pkg table {d} ({d} MiB, cap {d} MiB, {d} evictions)", .{
            exec.ptb.pkgs.shared.entries.load(.monotonic), exec.ptb.pkgs.shared.bytes_held.load(.monotonic) >> 20,
            exec.ptb.pkgs.shared.max_bytes >> 20,          exec.ptb.pkgs.shared.evictions.load(.monotonic),
        }) catch {};
    }

    /// `pkgs_view`'s fallback: `pkgs` under a shared lock (the bytes are never freed or moved).
    fn viewGet(p: *const anyopaque, id: *const [32]u8, epoch: u64) ?[]const u8 {
        const x: *Executor = @ptrCast(@alignCast(@constCast(p)));
        x.pkg_lock.lockSharedUncancelable(x.io);
        defer x.pkg_lock.unlockShared(x.io);
        return x.pkgs.get(id, epoch);
    }

    /// The packages a checkpoint of `epoch` carries: inputs and the archive's object set are in
    /// force in `epoch`; outputs are new packages (user) or the next epoch's (system: only an
    /// end-of-epoch transaction writes them).
    /// `genesis`: checkpoint 0, whose outputs (the framework included) are in force in epoch 0
    /// (other outputs of system packages come from end-of-epoch transactions: the next epoch's).
    fn addPackages(x: *Executor, epoch: u64, found: []const FoundPkg, genesis: bool) void {
        for (found) |f| x.addPackage(f.raw, epoch + @intFromBool(f.output and !genesis));
    }

    const FoundPkg = struct { raw: []const u8, output: bool };

    /// The package objects among a checkpoint's objects and its archive set (any thread).
    fn findPackages(arena: std.mem.Allocator, blob: []const u8, idx: *const types.CheckpointIndex, aux: ?convert.Aux) std.mem.Allocator.Error![]const FoundPkg {
        var out: std.ArrayList(FoundPkg) = .empty;
        const S = struct {
            fn isPkg(raw: []const u8) bool {
                const v = exec.objects.ObjectView.parse(raw) catch return false;
                return v.is_package;
            }
        };
        if (aux) |a| for (a.objects) |raw| if (S.isPkg(raw)) try out.append(arena, .{ .raw = raw, .output = false });
        for (0..idx.tx_count) |i| {
            const t = idx.txAt(i);
            for (idx.objs[t.in_first..][0..t.in_count]) |r| if (S.isPkg(r.slice(blob))) try out.append(arena, .{ .raw = r.slice(blob), .output = false });
            for (idx.objs[t.out_first..][0..t.out_count]) |r| if (S.isPkg(r.slice(blob))) try out.append(arena, .{ .raw = r.slice(blob), .output = true });
        }
        return out.items;
    }

    // ------------------------------------------------------------------ pipeline
    //
    // Every transaction runs against the certified pre-state: its input objects are the
    // checkpoint's own (verified against the effects by the follower), the archive's object set,
    // or the store as of the previous checkpoint (each job holds a snapshot taken before its own
    // checkpoint commits). No transaction reads another's computed output, so the transactions of
    // one checkpoint, and of the checkpoints after it, run in any order on any thread; the
    // dependency graph of a checkpoint is empty here (p2p, which has no certified outputs, needs
    // its levels: p2p_exec.zig). Checkpoint N+1 starts while N still runs and after N committed.
    //
    // A job goes: submitted (caller thread: blob copy, archive record, snapshot) -> decoded (any
    // worker: index, decode, object tables, package ids) -> prepared (one worker at a time, in
    // sequence order: packages, removals) -> its transactions on any worker -> finished (the
    // worker of its last transaction: ordered rerun of what differed, verdicts, snapshot release).
    // At most `window` jobs are in flight; `submit` waits for room, so the commit stage runs at
    // most `window` checkpoints ahead of execution.

    /// Starts `threads` executor threads with `window` checkpoints in flight (0 threads: every
    /// checkpoint runs on the caller's thread inside `submit`).
    pub fn start(x: *Executor, threads: u32, window: u32) !void {
        // Checkpoints run in order: a thread's package caches of epochs before the previous one
        // are dead (each holds a VM runtime with every package the thread loaded that epoch).
        exec.ptb.pkgs.epoch_window = 1;
        // Each thread keeps up to two epochs' package caches (VM runtimes holding every package
        // the thread loaded that epoch); the epoch's working set grows with the chain's package
        // count, so the caches share one budget instead of 1.5 GiB each. The process-wide
        // parsed-package table, when on, is counted in that budget once (`pkgs.setBudget`).
        exec.ptb.pkgs.setBudget(x.cache_budget, @as(usize, @max(threads, 1)) * 2);
        x.bindView();
        if (threads == 0) return;
        const p = &x.pool;
        p.jobs = try x.gpa.alloc(Job, @max(window, 2));
        for (p.jobs) |*j| j.* = try Job.init(x.gpa);
        p.threads = try x.gpa.alloc(std.Thread, threads);
        p.nthreads = threads;
        var spawned: usize = 0;
        errdefer {
            x.stopThreads(spawned);
            for (p.jobs) |*j| j.deinit(x.gpa);
            x.gpa.free(p.jobs);
            p.jobs = &.{};
        }
        for (p.threads) |*t| {
            t.* = try std.Thread.spawn(.{ .stack_size = 64 << 20 }, worker, .{x});
            spawned += 1;
        }
    }

    fn bindView(x: *Executor) void {
        if (x.pkgs_view.lookup == null) x.pkgs_view.lookup = .{ .ctx = x, .get = viewGet };
    }

    /// Waits for every submitted checkpoint, then ends the threads.
    pub fn stop(x: *Executor) void {
        const p = &x.pool;
        if (p.jobs.len == 0) return;
        x.drain();
        x.stopThreads(p.threads.len);
        for (p.jobs) |*j| j.deinit(x.gpa);
        x.gpa.free(p.jobs);
        p.jobs = &.{};
    }

    fn stopThreads(x: *Executor, n: usize) void {
        const p = &x.pool;
        p.mu.lockUncancelable(x.io);
        p.stopping = true;
        p.work.broadcast(x.io);
        p.mu.unlock(x.io);
        for (p.threads[0..n]) |t| t.join();
        x.gpa.free(p.threads);
        p.threads = &.{};
    }

    /// Waits until every submitted checkpoint is done.
    pub fn drain(x: *Executor) void {
        const p = &x.pool;
        if (p.jobs.len == 0) return;
        p.mu.lockUncancelable(x.io);
        defer p.mu.unlock(x.io);
        while (p.head != p.tail) p.room.waitUncancelable(x.io, &p.mu);
    }

    /// True once any transaction's result differed from the certified one (after its rerun).
    pub fn mismatchSeen(x: *const Executor) bool {
        return x.mismatch_seen.load(.acquire);
    }

    /// Runs one verified checkpoint and waits for it. `pv` is the protocol version of its epoch
    /// and `params` its reference gas price and start timestamp (trust.zig).
    pub fn checkpoint(x: *Executor, seq: u64, epoch: u64, pv: u64, params: trust.EpochParams, blob: []const u8) void {
        x.submit(seq, epoch, pv, params, blob);
        x.drain();
    }

    /// Hands one verified checkpoint to the executor; call in sequence order, before the
    /// checkpoint commits (the job's store snapshot is the state after the previous one).
    pub fn submit(x: *Executor, seq: u64, epoch: u64, pv: u64, params: trust.EpochParams, blob: []const u8) void {
        x.bindView();
        const p = &x.pool;
        if (p.jobs.len == 0) {
            const j = x.inline_job orelse blk: {
                const nj = x.gpa.create(Job) catch return x.lost(seq);
                nj.* = Job.init(x.gpa) catch {
                    x.gpa.destroy(nj);
                    return x.lost(seq);
                };
                x.inline_job = nj;
                break :blk nj;
            };
            if (!x.fill(j, seq, epoch, pv, params, blob)) return x.lost(seq);
            x.decode(j);
            x.prepare(j);
            const arena = &j.tx_arena;
            for (0..j.txs.len) |i| {
                arena.reset(keep.tx);
                j.results[i] = x.runOne(j, i, arena.allocator());
                x.settle(j, i, arena.allocator());
            }
            x.finish(j);
            j.reset(x.gpa);
            return;
        }
        p.mu.lockUncancelable(x.io);
        // In flight: at most `jobs.len` checkpoints and `window_bytes` of their bytes (one job
        // always fits), so a run of large checkpoints does not hold `jobs.len` of them at once.
        while (p.tail - p.head >= p.jobs.len or (p.tail > p.head and p.inflight_bytes >= x.window_bytes)) p.room.waitUncancelable(x.io, &p.mu);
        const j = &p.jobs[p.tail % p.jobs.len];
        p.mu.unlock(x.io);
        // The slot is free: nothing else touches it until it is published below.
        const ok = x.fill(j, seq, epoch, pv, params, blob);
        j.lost = !ok;
        j.charged = j.blob.items.len + j.aux_raw.items.len;
        p.mu.lockUncancelable(x.io);
        p.inflight_bytes += j.charged;
        j.state = .submitted;
        p.tail += 1;
        p.work.signal(x.io);
        p.mu.unlock(x.io);
    }

    fn lost(x: *Executor, seq: u64) void {
        _ = x.stats.checkpoints.fetchAdd(1, .monotonic);
        _ = x.stats.errors.fetchAdd(1, .monotonic);
        x.verdict(seq, std.math.maxInt(u32), .mismatch, "OutOfMemory");
    }

    fn fill(x: *Executor, j: *Job, seq: u64, epoch: u64, pv: u64, params: trust.EpochParams, blob: []const u8) bool {
        j.seq = seq;
        j.epoch = epoch;
        j.pv = pv;
        j.params = params;
        j.blob.clearRetainingCapacity();
        j.blob.appendSlice(x.gpa, blob) catch return false;
        j.has_aux = x.readAux(seq, &j.aux_raw);
        j.snap = x.st.snapshot();
        j.has_snap = true;
        return true;
    }

    fn worker(x: *Executor) void {
        const p = &x.pool;
        var arena: Bump = .init(x.gpa);
        var kept: u64 = 0;
        defer {
            memstat.keep(.exec_threads, &kept, 0);
            arena.deinit();
        }
        p.mu.lockUncancelable(x.io);
        defer p.mu.unlock(x.io);
        while (true) {
            // 1. The ordered step of the next checkpoint (short; everything after it waits on it).
            if (p.prep_next < p.dec_next) {
                const j = &p.jobs[p.prep_next % p.jobs.len];
                if (j.state == .decoded) {
                    j.state = .preparing;
                    p.mu.unlock(x.io);
                    x.prepare(j);
                    p.mu.lockUncancelable(x.io);
                    p.prep_next += 1;
                    if (j.txs.len == 0) {
                        x.finishLocked(j);
                    } else {
                        j.state = .running;
                        p.unclaimed += j.txs.len;
                        p.work.broadcast(x.io);
                    }
                    continue;
                }
            }
            // 2. Decode ahead while the runnable transactions would not keep every thread busy.
            const decode_first = p.unclaimed < 2 * p.nthreads;
            if (decode_first and x.decodeNext()) continue;
            // 3. A transaction of the oldest running checkpoint.
            if (p.unclaimed > 0) {
                while (p.claim_pos < p.prep_next) : (p.claim_pos += 1) {
                    const j = &p.jobs[p.claim_pos % p.jobs.len];
                    if (j.state == .running and j.next_tx < j.txs.len) break;
                }
                if (p.claim_pos < p.prep_next) {
                    const j = &p.jobs[p.claim_pos % p.jobs.len];
                    const i = j.next_tx;
                    j.next_tx += 1;
                    p.unclaimed -= 1;
                    p.mu.unlock(x.io);
                    arena.reset(keep.tx);
                    memstat.keep(.exec_threads, &kept, arena.held());
                    j.results[i] = x.runOne(j, i, arena.allocator());
                    x.settle(j, i, arena.allocator());
                    p.mu.lockUncancelable(x.io);
                    j.done_tx += 1;
                    if (j.done_tx == j.txs.len) x.finishLocked(j);
                    continue;
                }
            }
            if (!decode_first and x.decodeNext()) continue;
            if (p.stopping and p.head == p.tail) return;
            p.work.waitUncancelable(x.io, &p.mu);
        }
    }

    /// Decodes the next submitted job (pool lock held; released while decoding).
    fn decodeNext(x: *Executor) bool {
        const p = &x.pool;
        if (p.dec_next >= p.tail) return false;
        const j = &p.jobs[p.dec_next % p.jobs.len];
        if (j.state != .submitted) return false;
        j.state = .decoding;
        p.dec_next += 1;
        p.mu.unlock(x.io);
        x.decode(j);
        p.mu.lockUncancelable(x.io);
        j.state = .decoded;
        p.work.broadcast(x.io);
        return true;
    }

    /// Finishes a job whose transactions are all done (pool lock held; released meanwhile).
    fn finishLocked(x: *Executor, j: *Job) void {
        const p = &x.pool;
        j.state = .finishing;
        p.mu.unlock(x.io);
        x.finish(j);
        p.mu.lockUncancelable(x.io);
        j.state = .done;
        x.retire();
    }

    /// Frees done jobs from the oldest on (pool lock held).
    fn retire(x: *Executor) void {
        const p = &x.pool;
        var freed = false;
        while (p.head < p.tail) {
            const j = &p.jobs[p.head % p.jobs.len];
            if (j.state != .done) break;
            x.stats.done_seq.store(j.seq, .monotonic);
            // Every later checkpoint is of this epoch or a later one: older package caches are dead.
            if (j.epoch > exec.ptb.pkgs.min_epoch.load(.monotonic)) exec.ptb.pkgs.min_epoch.store(j.epoch, .monotonic);
            p.inflight_bytes -= j.charged;
            j.reset(x.gpa);
            p.head += 1;
            freed = true;
        }
        if (p.claim_pos < p.head) p.claim_pos = p.head;
        if (freed) {
            p.room.broadcast(x.io);
            p.work.broadcast(x.io);
        }
    }

    /// Index, decode, object tables, package objects and ids (any thread).
    fn decode(x: *Executor, j: *Job) void {
        const arena = j.arena.allocator();
        const blob = j.blob.items;
        const seq = j.seq;
        const no_tx = std.math.maxInt(u32);
        if (j.lost) return x.lost(seq);
        _ = x.stats.checkpoints.fetchAdd(1, .monotonic);
        types.indexCheckpointData(blob, &j.idx) catch |e| {
            _ = x.stats.errors.fetchAdd(1, .monotonic);
            return x.verdict(seq, no_tx, .mismatch, @errorName(e));
        };
        j.indexed = true;
        const cp = bcs.decode(types.CheckpointData, arena, blob[1..]) catch |e| {
            _ = x.stats.errors.fetchAdd(1, .monotonic);
            // Out of memory says nothing about the checkpoint: not a divergence.
            return x.verdict(seq, no_tx, if (e == error.OutOfMemory) .verify_only else .mismatch, @errorName(e));
        };
        _ = x.stats.transactions.fetchAdd(cp.transactions.len, .monotonic);
        const cfg = protocol.get(j.pv, x.chain) catch {
            _ = x.stats.unsupported.fetchAdd(cp.transactions.len, .monotonic);
            for (0..cp.transactions.len) |i| x.verdict(seq, i, .verify_only, "no protocol config");
            return;
        };
        j.table.addCheckpoint(arena, blob, &j.idx) catch |e| {
            _ = x.stats.errors.fetchAdd(1, .monotonic);
            // Out of memory says nothing about the checkpoint: not a divergence.
            return x.verdict(seq, no_tx, if (e == error.OutOfMemory) .verify_only else .mismatch, @errorName(e));
        };
        // An allocation failure is not a divergence: without the index a `latest` read would
        // miss an earlier transaction's write, so the checkpoint is not executed.
        j.changes = Changes.build(arena, blob, j.idx.objs, j.idx.txs[0..j.idx.tx_count]) catch {
            _ = x.stats.errors.fetchAdd(1, .monotonic);
            for (0..cp.transactions.len) |i| x.verdict(seq, i, .verify_only, "out of memory");
            return;
        };
        const aux: ?convert.Aux = if (j.has_aux) convert.Aux.parse(arena, j.aux_raw.items) catch null else null;
        if (aux == null) _ = x.stats.no_aux.fetchAdd(1, .monotonic);
        if (aux) |a| if (a.loaded.len != cp.transactions.len) {
            _ = x.stats.errors.fetchAdd(1, .monotonic);
            return x.verdict(seq, no_tx, .mismatch, "archive record has another transaction count");
        };
        if (aux) |a| for (a.objects) |raw| {
            const k = exec.objects.keyOf(raw) catch continue;
            // `extra` is an input-object source: a dropped entry is a missing input.
            j.extra.map.put(arena, k, raw) catch {
                _ = x.stats.errors.fetchAdd(1, .monotonic);
                for (0..cp.transactions.len) |i| x.verdict(seq, i, .verify_only, "out of memory");
                return;
            };
        };
        // An allocation failure is not a divergence: the checkpoint is not executed (a missing
        // package or marker would otherwise read as wrong effects).
        j.found = findPackages(arena, blob, &j.idx, aux) catch {
            _ = x.stats.errors.fetchAdd(1, .monotonic);
            for (0..cp.transactions.len) |i| x.verdict(seq, i, .verify_only, "out of memory");
            return;
        };
        j.pkg_ids = packageIds(arena, blob, &j.idx, cp.transactions, &j.extra) catch {
            _ = x.stats.errors.fetchAdd(1, .monotonic);
            for (0..cp.transactions.len) |i| x.verdict(seq, i, .verify_only, "out of memory");
            return;
        };
        j.results = arena.alloc(TxResult, cp.transactions.len) catch {
            _ = x.stats.errors.fetchAdd(1, .monotonic);
            return x.verdict(seq, no_tx, .verify_only, "OutOfMemory");
        };
        @memset(j.results, .{});
        j.aux = aux;
        j.cfg = cfg;
        j.txs = cp.transactions;
    }

    /// The ordered step (one job at a time, in sequence order): packages and removals.
    fn prepare(x: *Executor, j: *Job) void {
        if (!j.indexed) return;
        const arena = j.arena.allocator();
        if (j.cfg != null) {
            x.addPackages(j.epoch, j.found, j.seq == 0);
            x.resolvePackages(arena, &j.snap, j.epoch, j.pkg_ids);
        }
        // Every indexed checkpoint's removals are noted, also when its transactions are not run
        // (a skipped checkpoint must not leave an older removal's version behind).
        x.noteRemovals(arena, j.seq, j.blob.items, &j.idx);
    }

    /// Makes `removed_prior` durable (removal_log.zig): loads `path`, derives the removals of
    /// committed checkpoints the file lacks from the store, and scans the store's older history
    /// on a thread when the file is new (or that scan never finished). Before `start`.
    pub fn openPriorLog(x: *Executor, path: []const u8) !void {
        const t0 = @import("source.zig").nowNs();
        x.prior_log = try removal_log.Log.open(x.gpa, x.io, path, &x.removed_prior);
        const l = &x.prior_log.?;
        const loaded = x.removed_prior.count();
        var snap = x.st.snapshot();
        defer snap.release();
        const tip = snap.highestCommitted();
        var arena = std.heap.ArenaAllocator.init(x.gpa);
        defer arena.deinit();
        var list: std.ArrayList(removal_log.Entry) = .empty;
        defer list.deinit(x.gpa);
        var rescanned: u64 = 0;
        if (l.wm) |wm| if (tip) |t| {
            var s = wm + 1;
            while (s <= t) : (s += 1) {
                _ = arena.reset(.retain_capacity);
                list.clearRetainingCapacity();
                if (!try removal_log.fromStore(x.gpa, arena.allocator(), &snap, s, &list)) continue;
                for (list.items) |e| try x.removed_prior.put(x.gpa, .{ .id = e.id, .version = e.version }, e.prior);
                try l.appendCheckpoint(x.gpa, s, list.items);
                rescanned += 1;
            }
        };
        const lowest = snap.lowestCheckpoint();
        // History below the file's start: none needed when the file starts at the store's low end.
        const scan_hi: ?u64 = if (l.scanned) null else if (l.lo) |lo| (if (lo > 0) lo - 1 else null) else tip;
        if (scan_hi != null and lowest != null and scan_hi.? >= lowest.?) {
            x.prior_scan = try std.Thread.spawn(.{}, priorScan, .{ x, lowest.?, scan_hi.? });
        } else if (!l.scanned) {
            if (lowest orelse l.lo) |lo| try l.finishScan(lo);
        }
        const ms = (@import("source.zig").nowNs() - t0) / std.time.ns_per_ms;
        std.log.info("execute: removal-prior index {s}: {d} entries loaded, {d} committed checkpoints derived from the store (watermark {?d}), older history {s}, {d} ms", .{ path, loaded, rescanned, l.wm, if (x.prior_scan != null) "scanning on a thread" else "covered", ms });
    }

    /// Thread: the removals of stored checkpoints `lo..=hi` (below the log's start) into the map
    /// and the log, then the log's `scanned` record.
    fn priorScan(x: *Executor, lo: u64, hi: u64) void {
        var arena = std.heap.ArenaAllocator.init(x.gpa);
        defer arena.deinit();
        var list: std.ArrayList(removal_log.Entry) = .empty;
        defer list.deinit(x.gpa);
        var found: u64 = 0;
        var s = hi + 1;
        var done_lo = hi + 1;
        while (s > lo) {
            s -= 1;
            if (x.prior_scan_stop.load(.acquire)) return;
            _ = arena.reset(.retain_capacity);
            list.clearRetainingCapacity();
            var snap = x.st.snapshot();
            defer snap.release();
            const ok = removal_log.fromStore(x.gpa, arena.allocator(), &snap, s, &list) catch |e| {
                std.log.warn("execute: removal-prior scan at {d}: {s}; stopped (rescanned at the next start)", .{ s, @errorName(e) });
                return;
            };
            if (!ok) break; // pruned meanwhile: nothing older is held
            done_lo = s;
            if (list.items.len == 0) continue;
            {
                x.removed_lock.lockUncancelable(x.io);
                defer x.removed_lock.unlock(x.io);
                // A newer entry for the same key (from the live path) is never older history.
                for (list.items) |e| _ = x.removed_prior.getOrPutValue(x.gpa, .{ .id = e.id, .version = e.version }, e.prior) catch return;
            }
            x.prior_log.?.appendScanned(x.gpa, s, list.items) catch |e| {
                std.log.warn("execute: removal-prior log: {s}", .{@errorName(e)});
                return;
            };
            found += list.items.len;
        }
        x.prior_log.?.finishScan(done_lo) catch |e| return std.log.warn("execute: removal-prior log: {s}", .{@errorName(e)});
        std.log.info("execute: removal-prior scan of stored checkpoints {d}..{d} done: {d} child removals", .{ done_lo, hi, found });
    }

    /// Runs transaction `i` of `j` (any thread; `arena` is the thread's, reset per transaction).
    fn runOne(x: *Executor, j: *Job, i: usize, arena: std.mem.Allocator) TxResult {
        const t0 = sync.follower.now();
        defer _ = x.stats.exec_ns.fetchAdd(sync.follower.now() - t0, .monotonic);
        const blob = j.blob.items;
        const tx = j.idx.txAt(i);
        const data = &j.txs[i].transaction.data.@"0".element().intent_message.value.V1;
        var lookup: Lookup = .{ .table = &j.table, .extra = &j.extra, .snap = &j.snap, .x = x, .epoch = j.epoch, .blob = blob, .changes = &j.changes, .earlier = j.idx.txs[0..i], .txs = j.idx.txs[0..j.txs.len], .arena = arena };
        const ctx: Ctx = .{ .cfg = j.cfg.?, .epoch = j.epoch, .pv = j.pv, .params = j.params, .blob = blob, .idx = &j.idx, .lookup = &lookup, .aux = j.aux, .extra = &j.extra };
        last_why = "";
        const res = x.run(arena, &ctx, i, tx, data) catch |e| return .{ .v = .mismatch, .why = @errorName(e), .err = true };
        // A `latest` read the node could not answer exactly voids the result.
        const out = (if (lookup.gap) |g| x.skip(g) else res) orelse return .{ .v = .verify_only, .why = last_why };
        if (compare(arena, blob, &j.idx, tx, out)) |why| {
            // The first few mismatches carry both effects in hex (decode offline with exec-replay's types).
            if (x.hex_logged.fetchAdd(1, .monotonic) < 3) {
                std.log.err("execute: checkpoint {d} tx {d} zui effects {x}", .{ j.seq, i, out.effects });
                std.log.err("execute: checkpoint {d} tx {d} certified effects {x}", .{ j.seq, i, tx.effects.slice(blob) });
            }
            return .{ .v = .mismatch, .why = why, .by = out.by };
        }
        return .{ .v = .match, .why = @tagName(out.by), .by = out.by };
    }

    /// Accounts for a transaction's first result (the thread that ran it; `arena` still holds
    /// its reason). A mismatch waits for the ordered rerun in `finish`.
    fn settle(x: *Executor, j: *Job, i: usize, arena: std.mem.Allocator) void {
        _ = arena;
        const r = j.results[i];
        switch (r.v) {
            .mismatch => {},
            .verify_only => {
                _ = x.stats.unsupported.fetchAdd(1, .monotonic);
                x.tallyWhy(r.why, j.seq, i);
                x.verdict(j.seq, i, .verify_only, r.why);
            },
            .match => x.count(j.seq, i, r),
        }
    }

    fn count(x: *Executor, seq: u64, i: usize, r: TxResult) void {
        _ = x.stats.executed.fetchAdd(1, .monotonic);
        if (r.by) |by| _ = switch (by) {
            inline else => |b| @field(x.stats, @tagName(b)).fetchAdd(1, .monotonic),
        };
        switch (r.v) {
            .match => {
                _ = x.stats.matched.fetchAdd(1, .monotonic);
                x.verdict(seq, i, .match, r.why);
            },
            else => {
                _ = x.stats.mismatched.fetchAdd(1, .monotonic);
                x.why_lock.lockUncancelable(x.io);
                if (x.first_mismatch == null or x.first_mismatch.?.seq > seq) {
                    const w = std.fmt.bufPrint(&x.why_buf, "{s}", .{r.why}) catch r.why;
                    x.first_mismatch = .{ .seq = seq, .tx = @intCast(i), .why = w };
                }
                x.why_lock.unlock(x.io);
                x.mismatch_seen.store(true, .release);
                std.log.err("execute: checkpoint {d} tx {d} ({s}): {s}", .{ seq, i, if (r.by) |b| @tagName(b) else "exec error", r.why });
                x.verdict(seq, i, .mismatch, r.why);
            },
        }
    }

    /// The ordered rerun: every transaction whose result differed (or whose executor failed) runs
    /// again, one at a time in transaction order with nothing else of the checkpoint running; that
    /// result is the verdict. Then the snapshot is released.
    fn finish(x: *Executor, j: *Job) void {
        for (j.results, 0..) |*r, i| {
            if (r.v != .mismatch) continue;
            _ = x.stats.reruns.fetchAdd(1, .monotonic);
            j.tx_arena.reset(keep.tx);
            const again = x.runOne(j, i, j.tx_arena.allocator());
            switch (again.v) {
                .match => {
                    _ = x.stats.rerun_matched.fetchAdd(1, .monotonic);
                    std.log.warn("execute: checkpoint {d} tx {d}: parallel result differed ({s}), the ordered rerun matched", .{ j.seq, i, r.why });
                    x.count(j.seq, i, again);
                },
                .verify_only => {
                    r.* = again;
                    x.settle(j, i, j.tx_arena.allocator());
                },
                .mismatch => {
                    if (again.err) _ = x.stats.errors.fetchAdd(1, .monotonic);
                    if (again.err) {
                        // An executor error is not a result: counted as an error, reported as a
                        // failure (as before), never as executed.
                        std.log.err("execute: checkpoint {d} tx {d}: exec error {s}", .{ j.seq, i, again.why });
                        x.verdict(j.seq, i, .mismatch, again.why);
                    } else x.count(j.seq, i, again);
                },
            }
        }
        if (j.has_snap) {
            j.snap.release();
            j.has_snap = false;
        }
    }

    /// Records the version each removal of this checkpoint consumed (a modified input without an
    /// output object), keyed by the removal's version (its transaction's lamport version, V2;
    /// the version the effects list, V1), for `SysSrc.child`. Only child objects (owner
    /// `ObjectOwner`, BCS tag 1) are kept: `SysSrc.child` reads nothing else, and the
    /// address-owned removals (coin merges, the bulk of mainnet's) would otherwise fill the map
    /// to `removed_cap` (hundreds of MiB) within hours and clear it, dropping the child entries
    /// with them.
    fn noteRemovals(x: *Executor, arena: std.mem.Allocator, seq: u64, blob: []const u8, idx: *const types.CheckpointIndex) void {
        var noted: std.ArrayList(removal_log.Entry) = .empty;
        defer if (x.prior_log) |*l| {
            l.appendCheckpoint(x.gpa, seq, noted.items) catch |e| std.log.warn("execute: removal-prior log at {d}: {s}", .{ seq, @errorName(e) });
        };
        x.removed_lock.lockUncancelable(x.io);
        defer x.removed_lock.unlock(x.io);
        if (x.removed_prior.count() >= removed_cap) x.removed_prior.clearRetainingCapacity();
        for (0..idx.tx_count) |i| {
            const t = idx.txAt(i);
            var fx: ?types.TransactionEffects = null;
            ins: for (idx.objs[t.in_first..][0..t.in_count]) |r| {
                const raw = r.slice(blob);
                const v = exec.objects.ObjectView.parse(raw) catch continue;
                if (v.is_package or raw[v.owner_at] != 1) continue;
                const k = v.key();
                for (idx.objs[t.out_first..][0..t.out_count]) |o| {
                    const ko = exec.objects.keyOf(o.slice(blob)) catch continue;
                    if (std.mem.eql(u8, &ko.id, &k.id)) continue :ins;
                }
                if (fx == null) fx = bcs.decode(types.TransactionEffects, arena, t.effects.slice(blob)) catch continue;
                const rv = removalVersion(&fx.?, &k.id) orelse continue;
                x.removed_prior.put(x.gpa, .{ .id = k.id, .version = rv }, k.version) catch return;
                if (x.prior_log != null) noted.append(arena, .{ .id = k.id, .version = rv, .prior = k.version }) catch {};
            }
        }
    }

    /// The version a removal of `id` carries in the store (sync/verify.zig `matchEffects`).
    fn removalVersion(fx: *const types.TransactionEffects, id: *const [32]u8) ?u64 {
        switch (fx.*) {
            .V2 => |*v| return v.lamport_version.@"0",
            .V1 => |*v| {
                for ([_][]const @TypeOf(v.deleted[0]){ v.deleted, v.wrapped, v.unwrapped_then_deleted }) |list| {
                    for (list) |*e| if (std.mem.eql(u8, &e.@"0".@"0".@"0", id)) return e.@"1".@"0";
                }
                return null;
            },
        }
    }

    /// The prior version a removal consumed (see `removed_prior`).
    fn removedPrior(x: *Executor, id: *const [32]u8, version: u64) ?u64 {
        x.removed_lock.lockUncancelable(x.io);
        defer x.removed_lock.unlock(x.io);
        return x.removed_prior.get(.{ .id = id.*, .version = version });
    }

    const By = enum { ran_ccp, ran_coin, ran_move, ran_system };
    const Written = exec.coin_ptb.Written;
    const Out = struct { effects: []const u8, events: ?[]const u8, written: []const Written, by: By };

    /// What every transaction of one checkpoint shares.
    const Ctx = struct {
        cfg: *const protocol.ProtocolConfig,
        epoch: u64,
        pv: u64,
        params: trust.EpochParams,
        blob: []const u8,
        idx: *const types.CheckpointIndex,
        lookup: *Lookup,
        aux: ?convert.Aux,
        extra: *const exec.objects.ObjectTable,
    };

    fn run(x: *Executor, arena: std.mem.Allocator, c: *const Ctx, i: usize, tx: *const types.index.Tx, data: *const types.TransactionDataV1) !?Out {
        const blob = c.blob;
        if (comptime @hasDecl(exec, "executeTransaction")) {
            // CONTRACTS 6.7: env carries the epoch's reference gas price and start timestamp.
            const rgp = c.params.rgp orelse return x.skip("reference gas price of the epoch unknown");
            const start_ms = c.params.start_ms orelse return x.skip("epoch start timestamp unknown");
            const r = try exec.executeTransaction(arena, .{ .cfg = c.cfg, .epoch = c.epoch, .reference_gas_price = rgp, .epoch_start_timestamp_ms = start_ms, .blob = blob, .idx = c.idx, .tx = tx, .data = data, .objects = c.lookup.objectLookup() });
            return switch (r) {
                .unsupported => |why| x.skip(why),
                .done => |o| .{ .effects = o.effects, .events = o.events, .written = o.written, .by = .ran_move },
            };
        }
        if (exec.ccp.timestampOf(&data.kind) != null) {
            const ins = try arena.alloc([]const u8, tx.in_count);
            for (c.idx.objs[tx.in_first..][0..tx.in_count], ins) |r, *o| o.* = r.slice(blob);
            const res = try exec.ccp.execute(arena, c.cfg, c.epoch, tx.data.slice(blob), data, ins);
            return switch (res) {
                .unsupported => |why| x.skip(why),
                .done => |o| .{ .effects = o.effects, .events = null, .written = o.written, .by = .ran_ccp },
            };
        }
        if (exec.system.handles(&data.kind)) return x.runSystem(arena, c, i, tx, data);
        const class = exec.classify.classify(&data.kind);
        // exec-history: every cut exec.versions runs (v0 to v4), not only execution version 4
        const move_ok = exec.versions.moveSupported(c.cfg);
        switch (class) {
            .ptb_coin_transfer => {
                // The reference gas price matters from the protocol that caps an aborted
                // transaction's gas price at a multiple of it (protocol 90+). Without a verified
                // one the transaction is left verify-only rather than guessed.
                const rgp = c.params.rgp orelse if (c.cfg.getOpt("max_gas_price_rgp_factor_for_aborted_transactions") == null) 0 else return x.skip("reference gas price of the epoch unknown");
                var objs = c.lookup.objectLookup();
                // Shared inputs at the versions consensus assigned (the certified effects name them).
                objs.assigned = try exec.inputs.assignedFromEffects(arena, data, tx.effects.slice(blob));
                const res = try exec.coin_ptb.execute(arena, c.cfg, c.epoch, rgp, tx.data.slice(blob), data, objs);
                switch (res) {
                    .done => |o| return .{ .effects = o.effects, .events = null, .written = o.written, .by = .ran_coin },
                    .unsupported => |why| {
                        if (!move_ok) return x.skip(why);
                        // What the coin executor read does not bear on the Move-call executor's run.
                        c.lookup.gap = null;
                        return x.runMove(arena, c, i, tx, data);
                    },
                }
            },
            // Publish/upgrade go to the same executor (every cut, the dynamic ones included).
            .ptb_move_call, .ptb_make_vec, .ptb_publish => return if (move_ok) x.runMove(arena, c, i, tx, data) else x.skip("Move call on an execution version zui does not run"),
            else => return x.skip(@tagName(class)),
        }
    }

    /// The Move-call executor (`exec.ptb`, every cut `exec.versions.moveSupported` names), as exec-replay runs it.
    fn runMove(x: *Executor, arena: std.mem.Allocator, c: *const Ctx, i: usize, tx: *const types.index.Tx, data: *const types.TransactionDataV1) !?Out {
        const rgp = c.params.rgp orelse return x.skip("reference gas price of the epoch unknown");
        const start_ms = c.params.start_ms orelse return x.skip("epoch start timestamp unknown");
        const blob = c.blob;
        const fx_all = try arena.create(types.TransactionEffects);
        fx_all.* = try bcs.decode(types.TransactionEffects, arena, tx.effects.slice(blob));
        const fx = switch (fx_all.*) {
            .V2 => |*v| v,
            // exec-history: protocols before 33 certify V1 effects; the driver reads them
            // through a V2 view (as exec-replay does) and writes V1 itself
            .V1 => |*v| exec.ptb.v2View(arena, v) catch return x.skip("effects v1 view"),
        };
        const loaded: ?[]const exec.ptb.Ref = if (c.aux) |a| blk: {
            const refs = try arena.alloc(exec.ptb.Ref, a.loaded[i].len);
            for (a.loaded[i], refs) |l, *r| r.* = .{ .id = l.id, .version = l.version };
            break :blk refs;
        } else null;
        const unsettled: Unsettled = .{ .blob = blob, .txs = c.idx.txs[0..i] };
        const res = try exec.ptb.execute(arena, .{
            .gpa = memstat.exec_gpa.allocator(),
            .cfg = c.cfg,
            .pv = c.pv,
            .epoch = c.epoch,
            .epoch_start_ms = start_ms,
            .rgp = rgp,
            .pkgs = &x.pkgs_view,
            // Not authoritative: a certified transaction passed input loading, so every package
            // it names exists on chain and one the node lacks is a store gap (skip), never a
            // failed execution (a false mismatch).
        }, tx.data.slice(blob), data, .{
            .objs = c.lookup.objectLookup(),
            .effects = fx,
            .unchanged_loaded = loaded,
            .unsettled = .{ .ctx = &unsettled, .get = Unsettled.get },
            .insufficient_funds = fx.status == .Failure and fx.status.Failure.@"error" == .InsufficientFundsForWithdraw and fx.status.Failure.command == null,
        });
        return switch (res) {
            .unsupported => |why| x.skip(why),
            .done => |o| .{ .effects = o.effects, .events = o.events, .written = o.written, .by = .ran_move },
        };
    }

    /// System transactions (`exec.system.execute`): inputs from the checkpoint, shared versions
    /// read without a change from the certified effects (as consensus assigned them), children
    /// read without a change from the archive's object set.
    fn runSystem(x: *Executor, arena: std.mem.Allocator, c: *const Ctx, i: usize, tx: *const types.index.Tx, data: *const types.TransactionDataV1) !?Out {
        const rgp = c.params.rgp orelse return x.skip("reference gas price of the epoch unknown");
        const start_ms = c.params.start_ms orelse return x.skip("epoch start timestamp unknown");
        const blob = c.blob;
        const views = try arena.alloc(exec.objects.ObjectView, tx.in_count);
        var versions: std.ArrayList(exec.system.InputVersion) = .empty;
        for (c.idx.objs[tx.in_first..][0..tx.in_count], views) |r, *v| {
            v.* = try exec.objects.ObjectView.parse(r.slice(blob));
            try versions.append(arena, .{ .id = v.id, .version = v.version });
        }
        const fx = try bcs.decode(types.TransactionEffects, arena, tx.effects.slice(blob));
        if (fx == .V2) for (fx.V2.unchanged_consensus_objects) |u| switch (u[1]) {
            .ReadOnlyRoot => |r| try versions.append(arena, .{ .id = u[0].@"0".@"0", .version = r[0].@"0" }),
            else => {},
        };
        var child_why: ?[]const u8 = null;
        const src: SysSrc = .{ .views = views, .lookup = c.lookup, .extra = c.extra, .pkgs = &x.pkgs_view, .epoch = c.epoch, .blob = blob, .earlier = c.idx.txs[0..i], .objs = c.idx.objs, .arena = arena, .why = &child_why };
        const env: exec.system.Env = .{ .cfg = c.cfg, .epoch = c.epoch, .epoch_start_ms = start_ms, .rgp = rgp };
        const res = try exec.system.execute(arena, &env, tx.data.slice(blob), data, versions.items, .{ .ctx = &src, .input = SysSrc.input, .child = SysSrc.child, .package = SysSrc.package });
        return switch (res) {
            // The node's reason for an unavailable child is the more precise one.
            .unsupported => |why| x.skip(child_why orelse why),
            .done => |o| .{ .effects = o.effects, .events = o.events, .written = @ptrCast(o.written), .by = .ran_system },
        };
    }
};

/// One transaction's first result. `why` is static or in the arena of the thread that ran it.
const TxResult = struct {
    v: Verdict = .verify_only,
    why: []const u8 = "",
    by: ?Executor.By = null,
    /// The executor returned an error (not a result).
    err: bool = false,
};

/// One checkpoint in the pipeline (`Executor.start`). Buffers keep their capacity across reuse.
const Job = struct {
    state: State = .free,
    seq: u64 = 0,
    epoch: u64 = 0,
    pv: u64 = 0,
    params: trust.EpochParams = .{},
    blob: std.ArrayList(u8) = .empty,
    aux_raw: std.ArrayList(u8) = .empty,
    has_aux: bool = false,
    snap: store.Snapshot = undefined,
    has_snap: bool = false,
    /// Out of memory copying it at submit: reported as an error, nothing runs.
    lost: bool = false,
    idx: types.CheckpointIndex,
    /// Decode and prepare allocations (one thread at a time); read-only while the transactions run.
    arena: Bump,
    /// The ordered rerun and the caller-thread path.
    tx_arena: Bump,
    /// Bytes this job's buffers keep between checkpoints, as last added to memstat's gauge.
    kept: u64 = 0,
    /// Bytes counted in `Pool.inflight_bytes` for it.
    charged: u64 = 0,
    indexed: bool = false,
    cfg: ?*const protocol.ProtocolConfig = null,
    txs: []const types.CheckpointTransaction = &.{},
    table: exec.objects.ObjectTable = .{},
    extra: exec.objects.ObjectTable = .{},
    /// What the checkpoint's transactions left of each object (`Lookup.latest`), in `arena`.
    changes: Changes = .{},
    aux: ?convert.Aux = null,
    found: []const Executor.FoundPkg = &.{},
    pkg_ids: []const [32]u8 = &.{},
    results: []TxResult = &.{},
    next_tx: usize = 0,
    done_tx: usize = 0,

    const State = enum { free, submitted, decoding, decoded, preparing, running, finishing, done };

    fn init(gpa: std.mem.Allocator) !Job {
        return .{ .idx = try types.CheckpointIndex.init(gpa), .arena = .init(gpa), .tx_arena = .init(gpa) };
    }

    fn deinit(j: *Job, gpa: std.mem.Allocator) void {
        if (j.has_snap) j.snap.release();
        j.blob.deinit(gpa);
        j.aux_raw.deinit(gpa);
        j.idx.deinit(gpa);
        j.arena.deinit();
        j.tx_arena.deinit();
    }

    fn reset(j: *Job, gpa: std.mem.Allocator) void {
        j.arena.reset(keep.job);
        j.tx_arena.reset(keep.tx);
        if (j.blob.capacity > keep.buf) j.blob.clearAndFree(gpa);
        if (j.aux_raw.capacity > keep.buf) j.aux_raw.clearAndFree(gpa);
        memstat.keep(.exec_jobs, &j.kept, j.arena.held() + j.tx_arena.held() + j.blob.capacity + j.aux_raw.capacity);
        j.state = .free;
        j.lost = false;
        j.indexed = false;
        j.cfg = null;
        j.txs = &.{};
        j.table = .{};
        j.extra = .{};
        j.changes = .{};
        j.aux = null;
        j.found = &.{};
        j.pkg_ids = &.{};
        j.results = &.{};
        j.next_tx = 0;
        j.done_tx = 0;
    }
};

/// The executor threads and the ring of jobs (sequence counters index `jobs` modulo its length).
/// Jobs in [head, tail) are in flight; [claim_pos, prep_next) are prepared (running or done);
/// [prep_next, dec_next) are decoding or decoded; [dec_next, tail) are submitted.
const Pool = struct {
    threads: []std.Thread = &.{},
    nthreads: usize = 0,
    jobs: []Job = &.{},
    head: u64 = 0,
    claim_pos: u64 = 0,
    prep_next: u64 = 0,
    dec_next: u64 = 0,
    tail: u64 = 0,
    /// Transactions of prepared jobs no thread has claimed yet.
    unclaimed: usize = 0,
    /// Checkpoint and archive-record bytes of the jobs between `head` and `tail`.
    inflight_bytes: u64 = 0,
    stopping: bool = false,
    mu: Io.Mutex = .init,
    /// Workers wait here for work; `submit` and `drain` wait on `room`.
    work: Io.Condition = .init,
    room: Io.Condition = .init,
};

/// When the package fetcher's full node may be asked. A request it did not answer (not
/// reachable, an HTTP error, cut at the timeout) closes the gate for a pause that doubles with
/// every failure in a row, from `min_ms` to `max_ms`; any answer, a package or none, resets it.
/// While it is closed nothing is fetched, so the ordered step that asks spends at most one
/// request timeout per pause on a full node that is down.
const FetchGate = struct {
    /// No request before this time (ms, monotonic).
    closed_until_ms: u64 = 0,
    /// The current pause (0: the last request was answered).
    pause_ms: u64 = 0,

    const min_ms: u64 = 5_000;
    const max_ms: u64 = 5 * 60_000;

    fn open(g: *const FetchGate, now_ms: u64) bool {
        return now_ms >= g.closed_until_ms;
    }

    /// A request went unanswered: closes the gate; returns the pause.
    fn failed(g: *FetchGate, now_ms: u64) u64 {
        g.pause_ms = std.math.clamp(g.pause_ms * 2, min_ms, max_ms);
        g.closed_until_ms = now_ms + g.pause_ms;
        return g.pause_ms;
    }

    fn answered(g: *FetchGate) void {
        g.pause_ms = 0;
    }
};

fn nowMs() u64 {
    return @import("source.zig").nowNs() / std.time.ns_per_ms;
}

const Last = union(enum) { none, found: []const u8, removed };

/// What a checkpoint's transactions left of each object, for `Lookup.latest` and `unstable`:
/// id -> the transactions that changed it, in checkpoint order, each with what it left of the
/// object: the output object it wrote, or a removal (a modified input without an output: deleted
/// or wrapped). Checkpoint order is causal, so the newest change by a transaction before the
/// executing one decides. Built once per checkpoint from its certified objects (`decode`) and
/// read-only while its transactions run: a read is one hash lookup and a binary search, where a
/// scan parsed every object of every earlier transaction (quadratic over a checkpoint, on every
/// coin deny list read).
const Changes = struct {
    spans: std.AutoHashMapUnmanaged([32]u8, Span) = .empty,
    /// Each id's changes side by side (`Span`), by transaction index ascending.
    list: []const Change = &.{},

    const Span = struct { first: u32, len: u32, last_tx: u32 };
    const Change = struct {
        tx: u32,
        /// The object the transaction wrote; null: it removed the object.
        raw: ?types.index.Range,
    };

    /// Per transaction and id, as the scan decides (`lastInCheckpointScan`): the first output
    /// object of that id, else a removal when an input has it. Objects that do not parse are
    /// passed over.
    fn build(arena: std.mem.Allocator, blob: []const u8, objs: []const types.index.Range, txs: []const types.index.Tx) std.mem.Allocator.Error!Changes {
        var total: u32 = 0;
        for (txs) |*t| total += t.in_count + t.out_count;
        var c: Changes = .{};
        // Reserved up front: a span's address is kept in `picks` while later ids are added.
        try c.spans.ensureTotalCapacity(arena, total);
        const Pick = struct { span: *Span, change: Change };
        var picks: std.ArrayList(Pick) = try .initCapacity(arena, total);
        for (txs, 0..) |*t, i| {
            const tx: u32 = @intCast(i);
            const sides = [2][]const types.index.Range{ objs[t.out_first..][0..t.out_count], objs[t.in_first..][0..t.in_count] };
            for (sides, 0..) |side, input| for (side) |r| {
                const k = exec.objects.keyOf(r.slice(blob)) catch continue;
                const gop = c.spans.getOrPutAssumeCapacity(k.id);
                if (!gop.found_existing) {
                    gop.value_ptr.* = .{ .first = 0, .len = 0, .last_tx = tx };
                } else if (gop.value_ptr.last_tx == tx) continue; // this transaction's answer is set
                gop.value_ptr.last_tx = tx;
                gop.value_ptr.len += 1;
                picks.appendAssumeCapacity(.{ .span = gop.value_ptr, .change = .{ .tx = tx, .raw = if (input == 0) r else null } });
            };
        }
        const list = try arena.alloc(Change, picks.items.len);
        var at: u32 = 0;
        var it = c.spans.valueIterator();
        while (it.next()) |s| {
            s.first = at;
            at += s.len;
            s.len = 0;
        }
        // `picks` is in transaction order, so each span fills in transaction order.
        for (picks.items) |p| {
            list[p.span.first + p.span.len] = p.change;
            p.span.len += 1;
        }
        c.list = list;
        return c;
    }

    /// What the first `earlier` transactions of the checkpoint left of `id`.
    fn last(c: *const Changes, blob: []const u8, earlier: usize, id: *const [32]u8) Last {
        const s = c.spans.get(id.*) orelse return .none;
        const l = c.list[s.first..][0..s.len];
        // The number of changes by transactions before `earlier`; the newest of them decides.
        var lo: usize = 0;
        var hi: usize = l.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (l[mid].tx < earlier) lo = mid + 1 else hi = mid;
        }
        if (lo == 0) return .none;
        return if (l[lo - 1].raw) |r| .{ .found = r.slice(blob) } else .removed;
    }
};

/// The scan `Changes` replaced, kept as its reference (tests only). What the checkpoint's
/// `earlier` transactions left of `id`: the newest one that changed it wrote it (an output
/// object) or removed it (a modified input without an output: deleted or wrapped). Checkpoint
/// order is causal, so the last such transaction decides.
fn lastInCheckpointScan(blob: []const u8, objs: []const types.index.Range, earlier: []const types.index.Tx, id: *const [32]u8) Last {
    var j = earlier.len;
    while (j > 0) {
        j -= 1;
        const t = &earlier[j];
        for (objs[t.out_first..][0..t.out_count]) |r| {
            const raw = r.slice(blob);
            const k = exec.objects.keyOf(raw) catch continue;
            if (std.mem.eql(u8, &k.id, id)) return .{ .found = raw };
        }
        for (objs[t.in_first..][0..t.in_count]) |r| {
            const k = exec.objects.keyOf(r.slice(blob)) catch continue;
            if (std.mem.eql(u8, &k.id, id)) return .removed;
        }
    }
    return .none;
}

fn typeInputIds(a: std.mem.Allocator, out: *std.ArrayList([32]u8), t: *const types.TypeInput) std.mem.Allocator.Error!void {
    switch (t.*) {
        .vector => |e| try typeInputIds(a, out, e),
        .@"struct" => |*st| {
            try out.append(a, st.address.@"0");
            for (st.type_args) |*x| try typeInputIds(a, out, x);
        },
        else => {},
    }
}

fn typeTagIds(a: std.mem.Allocator, out: *std.ArrayList([32]u8), t: *const types.TypeTag) std.mem.Allocator.Error!void {
    switch (t.*) {
        .vector => |e| try typeTagIds(a, out, e),
        .@"struct" => |*st| try structTagIds(a, out, st),
        else => {},
    }
}

fn structTagIds(a: std.mem.Allocator, out: *std.ArrayList([32]u8), st: *const types.StructTag) std.mem.Allocator.Error!void {
    try out.append(a, st.address.@"0");
    for (st.type_args) |*x| try typeTagIds(a, out, x);
}

/// The packages named by a Move object's type (its struct and its type arguments).
fn objectTypeIds(a: std.mem.Allocator, out: *std.ArrayList([32]u8), raw: []const u8) std.mem.Allocator.Error!void {
    const o = bcs.decode(types.Object, a, raw) catch |e| {
        return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => {},
        };
    };
    switch (o.data) {
        .Move => |*m| switch (m.type_.@"0") {
            .Other => |*st| try structTagIds(a, out, st),
            .Coin, .BalanceAccumulatorField => |*t| try typeTagIds(a, out, t),
            else => {},
        },
        .Package => {},
    }
}

comptime {
    // `runSystem` hands exec.system's written objects over as coin_ptb's: same fields, same layout.
    const A = exec.system.Written;
    const B = exec.coin_ptb.Written;
    std.debug.assert(@sizeOf(A) == @sizeOf(B) and @offsetOf(A, "id") == @offsetOf(B, "id") and @offsetOf(A, "bytes") == @offsetOf(B, "bytes"));
}

/// exec.system's object source in a node: the transaction's input objects, then the checkpoint,
/// the archive's object set and the store for exact versions. A child read without a change is
/// the newest version at or below the bound: the checkpoint's earlier transactions decide first
/// (their writes and removals are newer than anything the store or the archive set hold), then
/// the archive's object set, then the store's newest version when that is at or below the bound;
/// otherwise not available.
const SysSrc = struct {
    views: []const exec.objects.ObjectView,
    lookup: *const Executor.Lookup,
    extra: *const exec.objects.ObjectTable,
    pkgs: *const exec.packages.Store,
    epoch: u64,
    blob: []const u8,
    /// The checkpoint's transactions before this one, and the index's object ranges.
    earlier: []const types.index.Tx,
    objs: []const types.index.Range,
    arena: std.mem.Allocator,
    /// Why the last unavailable child read was unavailable.
    why: *?[]const u8,

    const Earlier = union(enum) { none, found: []const u8, removed, unknown };

    fn na(s: *const SysSrc, why: []const u8) error{NotAvailable} {
        s.why.* = why;
        return error.NotAvailable;
    }

    /// The child's state at `bound` as the checkpoint's earlier transactions left it. Checkpoint
    /// order is causal, so the newest change at or below the bound is in the latest earlier
    /// transaction that touched the id with its lamport version at or below the bound; a
    /// transaction that touched it later (above the bound) still shows the version it read.
    /// Example (checkpoint 342452223): a settlement created an accumulator field, an earlier
    /// transaction of a later checkpoint deleted it, and the next settlement must read none;
    /// the store (as of the previous checkpoint) still held the created version.
    fn fromEarlier(s: *const SysSrc, id: *const [32]u8, bound: u64) Earlier {
        var j = s.earlier.len;
        while (j > 0) {
            j -= 1;
            const t = &s.earlier[j];
            var in_raw: ?[]const u8 = null;
            var in_v: u64 = 0;
            for (s.objs[t.in_first..][0..t.in_count]) |r| {
                const raw = r.slice(s.blob);
                const k = exec.objects.keyOf(raw) catch return .unknown;
                if (std.mem.eql(u8, &k.id, id)) {
                    in_raw = raw;
                    in_v = k.version;
                }
            }
            var out_raw: ?[]const u8 = null;
            for (s.objs[t.out_first..][0..t.out_count]) |r| {
                const raw = r.slice(s.blob);
                const k = exec.objects.keyOf(raw) catch return .unknown;
                if (std.mem.eql(u8, &k.id, id)) out_raw = raw;
            }
            if (in_raw == null and out_raw == null) continue;
            const fx = bcs.decode(types.TransactionEffects, s.arena, t.effects.slice(s.blob)) catch return .unknown;
            const lamport = switch (fx) {
                .V2 => |v| v.lamport_version.@"0",
                // exec-history: V1 has no lamport field; every written, deleted or wrapped
                // entry carries the lamport version
                .V1 => |v| v1Lamport(&v),
            };
            if (lamport <= bound) return if (out_raw) |o| .{ .found = o } else .removed;
            // Changed above the bound: what it read is the state at the bound, if at or below.
            if (in_raw) |ir| if (in_v <= bound) return .{ .found = ir };
            // Created above the bound, or read above it: an even earlier change decides.
        }
        return .none;
    }

    fn input(p: *const anyopaque, id: *const [32]u8, version: u64) ?[]const u8 {
        const s: *const SysSrc = @ptrCast(@alignCast(p));
        for (s.views) |*v| if (std.mem.eql(u8, &v.id, id) and v.version == version) return v.raw;
        return Executor.Lookup.get(s.lookup, id, version);
    }

    fn child(p: *const anyopaque, parent: *const [32]u8, id: *const [32]u8, bound: u64) error{NotAvailable}!?[]const u8 {
        _ = parent;
        const s: *const SysSrc = @ptrCast(@alignCast(p));
        for (s.views) |*v| if (std.mem.eql(u8, &v.id, id) and v.version <= bound) return v.raw;
        switch (s.fromEarlier(id, bound)) {
            .found => |b| return b,
            .removed => return null,
            .unknown => return s.na("child: an earlier transaction of the checkpoint has V1 effects"),
            .none => {},
        }
        var best: ?[]const u8 = null;
        var best_v: u64 = 0;
        var it = s.extra.map.iterator();
        while (it.next()) |e| if (std.mem.eql(u8, &e.key_ptr.id, id) and e.key_ptr.version <= bound and (best == null or e.key_ptr.version > best_v)) {
            best = e.value_ptr.*;
            best_v = e.key_ptr.version;
        };
        if (best) |b| return b;
        // The store: its live version is the newest there is (the store applied every certified
        // output since it started, and a snapshot start holds the rest), so one at or below the
        // bound is the answer; a removal at or below the bound means no child at the bound.
        const st = s.lookup.snap.latest(id) catch return s.na("child: store read error");
        if (st) |l| switch (l) {
            .live => |o| return if (o.version <= bound) o.bytes else s.walkBack(id, o.bytes, bound),
            .removed => |r| {
                if (r.version <= bound) return null;
                // Removed above the bound: the version the removal consumed, then walk back.
                const prior = s.lookup.x.removedPrior(id, r.version) orelse return s.na("child: removed above the bound before this process followed it");
                if (prior >= r.version) return s.na("child: removal record out of order");
                const raw = s.lookup.snap.objectAt(id, prior) orelse return s.na("child: version before the removal not stored");
                return s.walkBack(id, raw, bound);
            },
        };
        // Never in the store. With the full live set this is none: sui-node restored from the
        // same formal snapshot holds exactly that live set and no older history, and its
        // `find_object_lt_or_eq_version(child, bound)` finds no entry for the id, so it reads
        // None (sui-core execution_cache.rs read_child_object). Snapshot-restored nodes execute
        // in consensus with every validator, so this is the network's answer. Without the full
        // live set the child may predate the store.
        if (s.lookup.x.stateComplete(s.epoch)) return null;
        return s.na("child: predates a store without the full live set");
    }

    /// The newest version of `id` at or below `bound`, from a newer stored version: each version's
    /// writer (its previous transaction) is in the store with certified effects that name the
    /// version it replaced, which the store also holds. Versions are not ordered across objects
    /// by checkpoint, so a child written in an earlier checkpoint can be above a later
    /// settlement's bound. A step the store cannot answer (a writer from before the store's
    /// history, V1 effects, or a writer that created the object, which says nothing about an
    /// earlier incarnation) is not available.
    fn walkBack(s: *const SysSrc, id: *const [32]u8, newest: []const u8, bound: u64) error{NotAvailable}!?[]const u8 {
        var cur = newest;
        for (0..1024) |_| {
            const v = exec.objects.ObjectView.parse(cur) catch return s.na("child: stored version does not parse");
            if (v.version <= bound) return cur;
            const rec = s.lookup.snap.transaction(cur[v.prev_tx_at + 1 ..][0..32]) orelse return s.na("child: walk back reached a writer the store does not hold");
            const fx = bcs.decode(types.TransactionEffects, s.arena, rec.effects) catch return s.na("child: writer effects do not decode");
            const v2 = switch (fx) {
                .V2 => |e| e,
                .V1 => return s.na("child: writer has V1 effects"),
            };
            const prior: u64 = for (v2.changed_objects) |ch| {
                if (!std.mem.eql(u8, &ch[0].@"0".@"0", id)) continue;
                switch (ch[1].input_state) {
                    .Exist => |e| break e[0][0].@"0",
                    .NotExist => return s.na("child: created above the bound (an earlier incarnation is not indexed)"),
                }
            } else return s.na("child: writer effects do not name it");
            if (prior >= v.version) return s.na("child: walk back out of order");
            cur = s.lookup.snap.objectAt(id, prior) orelse return s.na("child: walk back version not stored");
        }
        return s.na("child: walk back too long");
    }

    fn package(p: *const anyopaque, id: *const [32]u8) ?[]const u8 {
        const s: *const SysSrc = @ptrCast(@alignCast(p));
        return s.pkgs.get(id, s.epoch);
    }
};

/// The scheduler's unsettled object-balance withdrawals before a transaction: the Split writes of
/// the checkpoint's earlier transactions to the same balance field since the last accumulator
/// root write (mirror of exec-replay's `Unsettled` in src/exec/replay.zig, which is private).
const Unsettled = struct {
    blob: []const u8,
    txs: []const types.index.Tx,

    fn get(p: *const anyopaque, arena: std.mem.Allocator, field: *const [32]u8) anyerror!u128 {
        const u: *const Unsettled = @ptrCast(@alignCast(p));
        var root: [32]u8 = @splat(0);
        root[30] = 0x0a;
        root[31] = 0xcc;
        var sum: u128 = 0;
        for (u.txs) |*t| {
            const fx = switch (try bcs.decode(types.TransactionEffects, arena, t.effects.slice(u.blob))) {
                .V2 => |v| v,
                .V1 => continue,
            };
            for (fx.changed_objects) |*ch| {
                if (std.mem.eql(u8, &ch[0].@"0".@"0", &root) and ch[1].output_state == .ObjectWrite) sum = 0;
                if (!std.mem.eql(u8, &ch[0].@"0".@"0", field)) continue;
                switch (ch[1].output_state) {
                    .AccumulatorWriteV1 => |*w| if (w.operation == .Split) switch (w.value) {
                        .Integer => |v| sum += v,
                        else => return error.Unsupported,
                    },
                    else => {},
                }
            }
        }
        return sum;
    }
};

/// Null when deepwave's result equals the certified transaction: effects bytes, events bytes, and
/// the bytes of every certified output object (and no other object written).
fn compare(arena: std.mem.Allocator, blob: []const u8, idx: *const types.CheckpointIndex, tx: *const types.index.Tx, out: Executor.Out) ?[]const u8 {
    if (!std.mem.eql(u8, tx.effects.slice(blob), out.effects))
        return std.fmt.allocPrint(arena, "effects bytes differ: {s}", .{exec.replay.effectsDiff(arena, out.effects, tx.effects.slice(blob))}) catch "effects bytes differ";
    if (tx.events) |ev| {
        const got = out.events orelse return "certified events, zui none";
        // The blob holds `Option<TransactionEvents>` payload bytes.
        if (!std.mem.eql(u8, ev.slice(blob), got)) return "events bytes differ";
    } else if (out.events != null) return "zui events, certified none";
    if (out.written.len != tx.out_count) return "output object count differs";
    for (idx.objs[tx.out_first..][0..tx.out_count]) |r| {
        const want = r.slice(blob);
        const k = exec.objects.keyOf(want) catch return "certified output object does not parse";
        const got = for (out.written) |w| {
            if (std.mem.eql(u8, &w.id, &k.id)) break w.bytes;
        } else return "output object missing";
        if (!std.mem.eql(u8, got, want)) return "output object bytes differ";
    }
    return null;
}

/// exec-history: the lamport version of V1 effects (the version every changed entry carries).
fn v1Lamport(v: *const types.TransactionEffectsV1) u64 {
    var m: u64 = v.gas_object[0][1].@"0";
    inline for (.{ "created", "mutated", "unwrapped" }) |f| for (@field(v, f)) |r| {
        m = @max(m, r[0][1].@"0");
    };
    inline for (.{ "deleted", "unwrapped_then_deleted", "wrapped" }) |f| for (@field(v, f)) |r| {
        m = @max(m, r[1].@"0");
    };
    return m;
}

/// True when the effects change `id` from `version` (V2 effects: an entry whose input state is
/// that version). V1 effects (protocols before receiving) never do.
fn changedFrom(arena: std.mem.Allocator, raw: []const u8, id: *const [32]u8, version: u64) bool {
    const fx = switch (bcs.decode(types.TransactionEffects, arena, raw) catch return false) {
        .V2 => |v| v,
        .V1 => return false,
    };
    for (fx.changed_objects) |*ch| if (std.mem.eql(u8, &ch[0].@"0".@"0", id)) switch (ch[1].input_state) {
        .Exist => |e| return e[0][0].@"0" == version,
        .NotExist => return false,
    };
    return false;
}

/// The checkpoint's verdict on a receive at `version` by transaction `at`: true when an earlier
/// transaction changed the object from that version, false when this one or a later one does
/// (it was still there), null when none does.
fn receivedInCheckpoint(arena: std.mem.Allocator, effects: []const []const u8, at: usize, id: *const [32]u8, version: u64) ?bool {
    for (effects, 0..) |raw, j| if (changedFrom(arena, raw, id, version)) return j < at;
    return null;
}

/// The store's latest state of an object says a receive at `version` already happened: a live
/// version or a removal above it.
fn receivedBefore(latest: store.LatestObject, version: u64) bool {
    return switch (latest) {
        .live => |o| o.version > version,
        .removed => |r| r.version > version,
    };
}

// Regression (lane testnet): testnet checkpoint 404267715 tx 10 (FUdFA7Kx...) receives OwnerCap
// 0x83035b57... at 1082722667, which checkpoint 404267714's FV1vUVdf... had already received (to
// 1083805275). Sui hides a received version (`EUnableToReceiveObject`, transfer::receive_impl abort
// 3 in command 0); deepwave found it in the store and ran on into fuel::start_burning.
const fv1_effects_hex =
    "0100fd0400000000000040420f000000000020bc7300000000002ab9730000000000f60200000000000020d730ec0e4e" ++
    "e7b5278d7ea887be948879cbd36643a93d88988564894f3f83249a000120601c9c4d87bad9ad7926793842328d8d1e1a" ++
    "76f53b4a4835ec765de6384c6df4005b8e994000000000041369645322cd32a7fb0b04f255769d4e72fb3534f83d8ecd" ++
    "7ac8b47a0d8ae56c0169209940000000002059d08496ceba76b35a70525e888a85a35a5ca80dccd7a97cd818448a8a88" ++
    "386502aa0b6b3f0000000001209d5fdd7376fc22229d1ea57c053b6da9ab8ca769ddf4179492319c2c3245555802aa0b" ++
    "6b3f000000000083035b57ae9a73390ee98e862c4580933651eb248690b1f39a9b94b36489a5c1016b09894000000000" ++
    "20aa92e45d08c2b647df110ef401ce01057510316ae2053ea1ee683cb46562bb6f001369645322cd32a7fb0b04f25576" ++
    "9d4e72fb3534f83d8ecd7ac8b47a0d8ae56c01206933cdc2c82a29966d7ed7ecb90213cc6c85972d88a6d96ea2690ae6" ++
    "c21a3656001369645322cd32a7fb0b04f255769d4e72fb3534f83d8ecd7ac8b47a0d8ae56c009ea3352ace3620592582" ++
    "a26728bac4277397ef83c768ff6fcf389c8d1946fd60016b098940000000002080940d3643a8cf9ed97a69e1b7e46074" ++
    "b28a8c75c0d0d7dfacf3dc5d32b7ffb702b53888400000000001200080e7364d0f243d95ca1ecac2b18a78991ebdd418" ++
    "a878f25d345d500f3cb2da02b53888400000000000e9ca04d48e7d1fccd3aaaf7fa6e4886cbc9912b7d4a9ae76bb38cd" ++
    "459f44aab40003f60a44ce65b325ab3e4d76b09a86acba380bbd3cf1dbedbbff5d812acdc72e4f070000000000000000" ++
    "0000000000000000000000000000000000000000000000020762616c616e63650742616c616e63650107000000000000" ++
    "0000000000000000000000000000000000000000000000000002037375690353554900010036450f0000000000000100" ++
    "00000000000000000000000000000000000000000000000000000000000006005a8e994000000000206d317f4a835ef6" ++
    "07d801037cbbb99566f8da8011dd53ecb69670552a3b4f882b00";
const tx10_effects_hex =
    "01010c0000000000000000000000000000000000000000000000000000000000000002087472616e736665720f000000" ++
    "010c726563656976655f696d706c0300000000000000010000000000000000fd0400000000000040420f000000000000" ++
    "5a550000000000d1575500000000002f0200000000000020d71747b6db4def02b39f9bcf67075199f6615167e2fef836" ++
    "2aa8a0ac6dd42190000000618e994000000000031369645322cd32a7fb0b04f255769d4e72fb3534f83d8ecd7ac8b47a" ++
    "0d8ae56c015b8e994000000000209d5fdd7376fc22229d1ea57c053b6da9ab8ca769ddf4179492319c2c3245555802aa" ++
    "0b6b3f000000000120e5e3bfc83e52741844ac1217cf6851a054a93850dc42631a8a630f1fcbea09ed02aa0b6b3f0000" ++
    "0000009ea3352ace3620592582a26728bac4277397ef83c768ff6fcf389c8d1946fd60015b8e994000000000200080e7" ++
    "364d0f243d95ca1ecac2b18a78991ebdd418a878f25d345d500f3cb2da02b5388840000000000120c92c98a0a75443f4" ++
    "38aad054e20f948ca2c206519e6ae051694ded9754ea674e02b53888400000000000e9ca04d48e7d1fccd3aaaf7fa6e4" ++
    "886cbc9912b7d4a9ae76bb38cd459f44aab40003f60a44ce65b325ab3e4d76b09a86acba380bbd3cf1dbedbbff5d812a" ++
    "cdc72e4f0700000000000000000000000000000000000000000000000000000000000000020762616c616e6365074261" ++
    "6c616e636501070000000000000000000000000000000000000000000000000000000000000002037375690353554900" ++
    "01006f440f00000000000001000000000000000000000000000000000000000000000000000000000000000600608e99" ++
    "400000000020edbe6a8bb1c88d6dd0bddb76091be107fe155868c33a57cfcd709b565ae5674300";

fn testHex(comptime h: []const u8) [h.len / 2]u8 {
    var out: [h.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

test "receive of an already received version (testnet 404267715 tx 10)" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    @setEvalBranchQuota(100_000);
    const fv1 = testHex(fv1_effects_hex);
    const tx10 = testHex(tx10_effects_hex);
    const cap = testHex("83035b57ae9a73390ee98e862c4580933651eb248690b1f39a9b94b36489a5c1");
    const character = testHex("1369645322cd32a7fb0b04f255769d4e72fb3534f83d8ecd7ac8b47a0d8ae56c");
    try std.testing.expect(changedFrom(arena, &fv1, &cap, 1082722667));
    try std.testing.expect(!changedFrom(arena, &fv1, &cap, 1083805275));
    try std.testing.expect(!changedFrom(arena, &tx10, &cap, 1082722667));
    try std.testing.expect(changedFrom(arena, &tx10, &character, 1083805275));
    // The receiving transaction earlier in the same checkpoint: received; itself or later: not yet.
    const both = [_][]const u8{ &fv1, &tx10 };
    try std.testing.expectEqual(@as(?bool, true), receivedInCheckpoint(arena, &both, 1, &cap, 1082722667));
    try std.testing.expectEqual(@as(?bool, false), receivedInCheckpoint(arena, &both, 0, &cap, 1082722667));
    try std.testing.expectEqual(@as(?bool, null), receivedInCheckpoint(arena, both[1..], 0, &cap, 1082722667));
    // An earlier checkpoint received it: the store's live version is above the ref.
    const digest: [32]u8 = @splat(0);
    try std.testing.expect(receivedBefore(.{ .live = .{ .version = 1083805275, .digest = digest, .bytes = &.{} } }, 1082722667));
    try std.testing.expect(!receivedBefore(.{ .live = .{ .version = 1082722667, .digest = digest, .bytes = &.{} } }, 1082722667));
}

/// Test object bytes: a GasCoin Move object or an empty package of `id` at `version`.
fn testObject(out: *std.ArrayList(u8), a: std.mem.Allocator, id: [32]u8, version: u64, package: bool) !void {
    var v: [8]u8 = undefined;
    std.mem.writeInt(u64, &v, version, .little);
    if (package) {
        try out.append(a, 1); // Data::Package
        try out.appendSlice(a, &id);
        try out.appendSlice(a, &v);
        try out.appendSlice(a, &.{ 0, 0, 0 }); // no modules, type origins or linkage
    } else {
        try out.appendSlice(a, &.{ 0, 1, 1 }); // Data::Move, MoveObjectType::GasCoin, has_public_transfer
        try out.appendSlice(a, &v);
        try out.append(a, 40); // contents: id, balance
        try out.appendSlice(a, &id);
        try out.appendSlice(a, &v);
    }
    try out.append(a, 3); // Owner::Immutable
    try out.append(a, 32); // previous_transaction
    try out.appendNTimes(a, 0, 32);
    try out.appendNTimes(a, 0, 8); // storage_rebate
}

test "Changes answers as the scan of earlier transactions does (repeated writes, removals, rewrites after a removal)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(0x1a57);
    const rnd = prng.random();
    var found: usize = 0;
    var removed: usize = 0;
    var none: usize = 0;
    {
        // Both test object forms parse (so the vectors below are not all passed over).
        const id: [32]u8 = @splat(7);
        inline for (.{ false, true }) |package| {
            var one: std.ArrayList(u8) = .empty;
            try testObject(&one, a, id, 5, package);
            const k = try exec.objects.keyOf(one.items);
            try std.testing.expectEqual(@as(u64, 5), k.version);
            try std.testing.expectEqualSlices(u8, &id, &k.id);
        }
    }
    for (0..40) |round| {
        // A small id pool, so most ids are written, removed and written again many times.
        var ids: [12][32]u8 = undefined;
        for (&ids) |*id| rnd.bytes(id);
        var blob: std.ArrayList(u8) = .empty;
        var objs: std.ArrayList(types.index.Range) = .empty;
        var txs: std.ArrayList(types.index.Tx) = .empty;
        const ntx = rnd.uintLessThan(usize, 60);
        var version: u64 = 1;
        for (0..ntx) |_| {
            var t: types.index.Tx = .{ .transaction = .{ .o = 0, .n = 0 }, .data = .{ .o = 0, .n = 0 }, .sig_first = 0, .sig_count = 0, .effects = .{ .o = 0, .n = 0 }, .events = null, .in_first = 0, .in_count = 0, .out_first = 0, .out_count = 0 };
            inline for (.{ "in", "out" }) |side| {
                @field(t, side ++ "_first") = @intCast(objs.items.len);
                // Inputs only: a removal; both: a mutation; outputs only: a creation. The same id
                // twice on one side also happens (the first one decides).
                for (0..rnd.uintLessThan(usize, 5)) |_| {
                    const o: u32 = @intCast(blob.items.len);
                    if (rnd.uintLessThan(u8, 16) == 0) {
                        // Bytes that do not parse: passed over by both.
                        try blob.appendSlice(a, &.{ 0, 1, 1, 9 });
                    } else {
                        try testObject(&blob, a, ids[rnd.uintLessThan(usize, ids.len - 1)], version, round % 4 == 3 and rnd.boolean());
                        version += 1;
                    }
                    try objs.append(a, .{ .o = o, .n = @intCast(blob.items.len - o) });
                }
                @field(t, side ++ "_count") = @intCast(objs.items.len - @field(t, side ++ "_first"));
            }
            try txs.append(a, t);
        }
        const c = try Changes.build(a, blob.items, objs.items, txs.items);
        // Every id (the last of the pool is in no object) as every transaction sees it, and
        // as one after the last would.
        for (0..ntx + 1) |earlier| for (&ids) |*id| {
            const want = lastInCheckpointScan(blob.items, objs.items, txs.items[0..earlier], id);
            const got = c.last(blob.items, earlier, id);
            try std.testing.expectEqual(std.meta.activeTag(want), std.meta.activeTag(got));
            switch (want) {
                .found => |w| {
                    // The same object of the blob, not only equal bytes.
                    try std.testing.expectEqual(w.ptr, got.found.ptr);
                    try std.testing.expectEqual(w.len, got.found.len);
                    found += 1;
                },
                .removed => removed += 1,
                .none => none += 1,
            }
        };
    }
    // The vectors reach every answer.
    try std.testing.expect(found > 1000 and removed > 1000 and none > 1000);
}

test "FetchGate: an unanswered request pauses the fetcher, longer each time in a row, and an answer resets it" {
    var g: FetchGate = .{};
    try std.testing.expect(g.open(0));
    // The first failure: closed for the minimum, then one more request is let through.
    try std.testing.expectEqual(FetchGate.min_ms, g.failed(1_000));
    try std.testing.expect(!g.open(1_000));
    try std.testing.expect(!g.open(1_000 + FetchGate.min_ms - 1));
    try std.testing.expect(g.open(1_000 + FetchGate.min_ms));
    // Failures in a row double the pause up to the maximum.
    var now: u64 = 1_000 + FetchGate.min_ms;
    var want = FetchGate.min_ms * 2;
    const start = now;
    for (0..12) |_| {
        const pause = g.failed(now);
        try std.testing.expectEqual(@min(want, FetchGate.max_ms), pause);
        try std.testing.expect(!g.open(now + pause - 1));
        now += pause;
        try std.testing.expect(g.open(now));
        want *= 2;
    }
    try std.testing.expectEqual(FetchGate.max_ms, g.pause_ms);
    // A full node down for that long (over half an hour) cost the ordered step 12 requests,
    // however many packages were asked for meanwhile.
    try std.testing.expect(now - start > 30 * 60_000);
    // Any answer starts over.
    g.answered();
    try std.testing.expectEqual(FetchGate.min_ms, g.failed(now));
}
