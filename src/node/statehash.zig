//! State-hash check at every end of epoch (docs/FULLNODE-PARITY.md task 12; sui-node's
//! `GlobalStateHasher` root against `EndOfEpochData.epoch_commitments`).
//!
//! The running root is the ECMH of the live object set: the formal snapshot restore verifies it
//! against the certified commitment and stores it with the end-of-epoch checkpoint; from there
//! every checkpoint adds its accumulator (exec/state_hash.zig, `accumulate_effects` exactly as
//! sui-core chooses its path by protocol) and the new root is stored in the same commit group,
//! under version `seq` of a reserved id. A restart reads it back at the last committed checkpoint,
//! so the root is crash-consistent with the store. At each end-of-epoch checkpoint the root's
//! digest must equal its `ECMHLiveObjectSetDigest`.
//!
//! On a mismatch the node alerts (ERROR lines that protocol-watch quotes, `zui_state_hash_*`
//! metrics), stops executing (verify-only: the store keeps only certified data, never results
//! of its own execution) and, with `--state-hash halt`, stops following. The root is then
//! re-seeded from nothing it can trust, so checking stops until the next restore.
const std = @import("std");
const types = @import("types");
const sig = @import("sig");
const protocol = @import("protocol");
const store = @import("store");
const exec = @import("exec");
const sync = @import("sync");
const Atomic = std.atomic.Value;

/// Reserved object id of the running-root records (version = checkpoint sequence number). Never
/// a real object id (no Move address hashes to this ASCII text).
pub const root_id: [32]u8 = "zui:state-hash:running-root:v1\x00\x00".*;
const zero_digest: [32]u8 = @splat(0);

fn monoNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub const Policy = enum { verify_only, halt, off };

pub const Verdict = enum { none, ok, mismatch };

pub const Stats = struct {
    /// End-of-epoch checks that passed / failed.
    checks_ok: Atomic(u64) = .init(0),
    mismatches: Atomic(u64) = .init(0),
    /// Epoch of the last check, and 1 once a mismatch was seen (gauge).
    last_epoch: Atomic(u64) = .init(0),
    failed: Atomic(u64) = .init(0),
    /// 1 while the node holds a trusted running root.
    anchored: Atomic(u64) = .init(0),
    /// Checkpoints accumulated and the time spent (ns).
    checkpoints: Atomic(u64) = .init(0),
    ns: Atomic(u64) = .init(0),
};

pub const Checker = struct {
    gpa: std.mem.Allocator,
    idx: types.CheckpointIndex,
    arena: std.heap.ArenaAllocator,
    running: ?sig.Ecmh = null,
    policy: Policy = .verify_only,
    stats: Stats = .{},
    /// Tests: accept this digest instead of the summary's commitment at the next end of epoch.
    expect_root: ?[32]u8 = null,
    /// Tests: report a mismatch as a warning (the test runner fails on any error line).
    quiet: bool = false,
    /// `--verify-fallback` (upgrade.zig): during an epoch whose protocol this binary has no table
    /// for, hash with the newest path and treat a mismatch at the end of epoch as a warning (the
    /// root is dropped; no execution stop, no halt): the accumulator rules of that protocol are unknown.
    lenient: bool = false,

    pub fn init(gpa: std.mem.Allocator, policy: Policy) !Checker {
        return .{ .gpa = gpa, .idx = try types.CheckpointIndex.init(gpa), .arena = .init(gpa), .policy = policy };
    }

    pub fn deinit(k: *Checker) void {
        k.idx.deinit(k.gpa);
        k.arena.deinit();
    }

    /// The running root stored with checkpoint `seq` (null: none, e.g. a store restored before
    /// this check existed, or started from genesis without a restore).
    pub fn load(k: *Checker, snap: *const store.Snapshot, seq: u64) void {
        const bytes = snap.objectAt(&root_id, seq) orelse return;
        k.running = sig.Ecmh.fromBytes(bytes) orelse return;
        k.stats.anchored.store(1, .release);
    }

    /// Writes the root into the restore's closing batch (snapshot.zig).
    pub fn storeRoot(b: *store.Batch, seq: u64, root: *const sig.Ecmh) !void {
        const bytes = root.toBytes();
        try b.putHistorical(&root_id, seq, &zero_digest, &bytes);
    }

    /// One checkpoint, before its batch commits: add its accumulator, store the new root, and at
    /// an end of epoch compare with the certified commitment.
    pub fn onBatch(k: *Checker, seq: u64, c: *const sync.verify.Checked, blob: []const u8, b: *store.Batch, pv: u64) !Verdict {
        if (k.policy == .off) return .none;
        var run = k.running orelse return .none;
        const t0 = monoNs();
        defer {
            _ = k.stats.checkpoints.fetchAdd(1, .monotonic);
            _ = k.stats.ns.fetchAdd(monoNs() -| t0, .monotonic);
        }
        _ = k.arena.reset(.retain_capacity);
        try types.indexCheckpointData(blob, &k.idx);
        const unknown_pv = k.lenient and (pv < protocol.min_protocol_version or pv > protocol.max_protocol_version);
        const path: exec.state_hash.Path = if (protocol.get(if (unknown_pv) protocol.max_protocol_version else pv, .mainnet)) |cfg| exec.state_hash.pathFor(cfg) else |_| .v3;
        var out: exec.state_hash.CheckpointHash = .{};
        try exec.state_hash.accumulateCheckpoint(k.arena.allocator(), path, blob, &k.idx, &out);
        if (out.lookups.items.len != 0 or out.missing.items.len != 0) {
            // v1/v2 history lookups cannot be answered from one checkpoint (pre-effects-v2 chain):
            // no root to trust from here on.
            std.log.warn("state hash: checkpoint {d} needs history lookups ({s} path); per-epoch check off until the next restore", .{ seq, @tagName(path) });
            k.drop();
            return .none;
        }
        run.add(&out.acc);
        k.running = run;
        try storeRoot(b, seq, &run);
        const eoe = c.end_of_epoch orelse return .none;
        var want: ?[32]u8 = k.expect_root;
        k.expect_root = null;
        if (want == null) for (eoe.epochCommitments) |cm| switch (cm) {
            .ECMHLiveObjectSetDigest => |d| want = d.digest.@"0",
            else => {},
        };
        const w = want orelse {
            std.log.warn("state hash: end of epoch {d} (checkpoint {d}) carries no state commitment", .{ c.epoch, seq });
            return .none;
        };
        const got = run.digest();
        k.stats.last_epoch.store(c.epoch, .release);
        if (std.mem.eql(u8, &got, &w)) {
            _ = k.stats.checks_ok.fetchAdd(1, .monotonic);
            std.log.info("state hash: epoch {d} root {x} equals the certified commitment (checkpoint {d})", .{ c.epoch, &got, seq });
            return .ok;
        }
        if (unknown_pv) {
            std.log.warn("state hash: end of epoch {d} (checkpoint {d}) runs protocol {d}, unsupported by this binary: root {x} differs from the commitment {x}; check dropped until the next restore (verify-fallback)", .{ c.epoch, seq, pv, &got, &w });
            k.drop();
            return .none;
        }
        _ = k.stats.mismatches.fetchAdd(1, .monotonic);
        k.stats.failed.store(1, .release);
        if (k.quiet) {
            std.log.warn("STATE HASH MISMATCH at the end of epoch {d} (checkpoint {d}) (test)", .{ c.epoch, seq });
        } else {
            std.log.err("STATE HASH MISMATCH at the end of epoch {d} (checkpoint {d}): live object set root {x}, certified commitment {x}", .{ c.epoch, seq, &got, &w });
            std.log.err("STATE HASH MISMATCH: the store's object set no longer matches the network; execution stops (verify-only){s}", .{if (k.policy == .halt) " and the node halts" else ""});
        }
        k.drop();
        return .mismatch;
    }

    fn drop(k: *Checker) void {
        k.running = null;
        k.stats.anchored.store(0, .release);
    }

    pub fn render(k: *const Checker, w: *std.Io.Writer) !void {
        const s = &k.stats;
        try w.print(
            \\# TYPE zui_state_hash_checks_ok counter
            \\zui_state_hash_checks_ok {d}
            \\# TYPE zui_state_hash_mismatches counter
            \\zui_state_hash_mismatches {d}
            \\# TYPE zui_state_hash_failed gauge
            \\zui_state_hash_failed {d}
            \\# TYPE zui_state_hash_anchored gauge
            \\zui_state_hash_anchored {d}
            \\# TYPE zui_state_hash_last_epoch gauge
            \\zui_state_hash_last_epoch {d}
            \\# TYPE zui_state_hash_ns counter
            \\zui_state_hash_ns {d}
            \\
        , .{ s.checks_ok.load(.monotonic), s.mismatches.load(.monotonic), s.failed.load(.monotonic), s.anchored.load(.monotonic), s.last_epoch.load(.monotonic), s.ns.load(.monotonic) });
    }
};
