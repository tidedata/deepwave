//! store: the deepwave storage engine. Append-only history logs (one segment per epoch), a compact
//! live-object index (file-backed, incremental flushes), per-epoch sealed indexes for history,
//! epoch pruning with carry-forward instead of compaction, lock-free MVCC snapshots with
//! zero-copy reads, one durable write per checkpoint (io_uring on Linux), and a deterministic
//! simulation tester checked against an in-memory model and the Lean store model.
//! Owner lane: storage. Interface: CONTRACTS.md section 5.9. Design: store.zig, format.zig.
const std = @import("std");

pub const conformance = @import("conformance.zig");
pub const format = @import("format.zig");
pub const table = @import("table.zig");
pub const io = @import("io.zig");
pub const ops = @import("ops.zig");
pub const checksum = @import("checksum.zig");
pub const rcu = @import("rcu.zig");
pub const chunk = @import("chunk.zig");
pub const cache = @import("cache.zig");
pub const guard = @import("guard.zig");
pub const zstd = @import("zstd.zig");
pub const zstd_c = @import("zstd_c.zig");
pub const convert = @import("convert.zig");
pub const prefetch = @import("prefetch.zig");
pub const psort = @import("psort.zig");
/// Envelopes served in place of stored ones (submitted signature order).
pub const txfix = @import("txfix.zig");
/// Sampled read latency per table (`rocksdb_get_latency_seconds{cf_name}`).
pub const readstats = @import("readstats.zig");
const store_impl = @import("store.zig");

pub const Config = store_impl.Config;
pub const Store = store_impl.Store;
pub const Batch = store_impl.Batch;
pub const Snapshot = store_impl.Snapshot;
pub const ObjectRef = store_impl.ObjectRef;
pub const CheckpointRecord = store_impl.CheckpointRecord;
pub const TransactionRecord = store_impl.TransactionRecord;
pub const ProbeStats = store_impl.ProbeStats;
pub const probeStats = probeStatsFn;
fn probeStatsFn() *store_impl.ProbeStats {
    return &store_impl.probe_stats;
}
pub const LatestObject = store_impl.LatestObject;
pub const RemoveKind = store_impl.RemoveKind;
pub const PruneReport = store_impl.PruneReport;
pub const Stats = store_impl.Stats;
pub const Error = store_impl.Error;
pub const Codec = store_impl.Codec;
pub const ObjKey = store_impl.ObjKey;
pub const ObjRec = store_impl.ObjRec;
pub const LiveIter = store_impl.LiveIter;
pub const HistIter = store_impl.HistIter;
pub const SegScan = store_impl.SegScan;
pub const LiveScan = store_impl.LiveScan;
pub const objectDigest = store_impl.objectDigest;
pub const aux_loaded = store_impl.aux_loaded;
pub const aux_checkpoint_digest = store_impl.aux_checkpoint_digest;
pub const aux_superseded = store_impl.aux_superseded;
pub const aux_highest_pruned = store_impl.aux_highest_pruned;
pub const certFixKey = store_impl.certFixKey;

pub const Backend = io.Backend;
pub const RealIo = io.RealIo;
pub const SyncMode = io.SyncMode;
pub const SimIo = sim.SimIo;

/// Seeded disk, clock and fault simulator plus the DST driver (dst.zig).
pub const sim = struct {
    pub const SimIo = @import("sim.zig").SimIo;
    pub const Faults = @import("sim.zig").Faults;
    pub const dst = @import("dst.zig");
};

/// Opens (or creates) a store on real files at `cfg.dir`. Close with `closeDir`.
pub fn openDir(gpa: std.mem.Allocator, sys_io: std.Io, cfg: *const Config, opts: RealIo.Options) !struct { store: *Store, io: *RealIo } {
    const r = try RealIo.init(gpa, sys_io, cfg.dir, opts);
    errdefer r.deinit();
    const s = try Store.open(gpa, .{ .real = r }, cfg);
    return .{ .store = s, .io = r };
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("sim.zig");
    _ = @import("tests.zig");
    _ = @import("dst.zig");
    _ = @import("clock.zig");
    _ = @import("layout.zig");
}
