//! The deepwave storage engine (ARCHITECTURE.md section 8).
//!
//! Source of truth: one append-only segment log per epoch (format.zig). Each checkpoint is one
//! commit group: its summary and contents, every transaction with effects and events, every
//! object version and every removal, then a commit record, all appended in one write and made
//! durable with one fdatasync (io_uring: one submission). Nothing else is written per
//! checkpoint. The mapping of the segment being appended to grows (doubling) as it fills.
//!
//! Derived indexes, all rebuilt from the logs when missing or damaged (table.zig):
//!   live      ObjectID -> newest version or tombstone record. A file-backed table
//!             (`index/live-<tg>.tbl`, 4 KiB pages with checksums) in a private mapping. Only
//!             pages changed since the last flush are written, through a page journal
//!             (`index/live.jnl`), every `index_flush_interval` checkpoints; `meta` then names
//!             the log position the file covers. Pruned tombstones give their slots back, and
//!             the table grows (1.25x) when it fills, so it never runs out.
//!   runs      object versions (historical reads), transactions, checkpoints. New entries go to
//!             an in-memory memtable; when it fills (or at close) it is sealed once into an
//!             immutable run file in the slot of the epoch its range ends in
//!             (`index/<epoch>-<run>.run`), and runs are dropped with that segment. A memtable
//!             spans epoch changes, so short epochs do not make tiny runs; entries of pruned
//!             epochs left in a newer run point at dropped segments and read as absent.
//!             Index memory is bounded by the memtable, disk by retention plus one run.
//! Recovery loads the live table (journal applied), checks the run chains, and replays the log
//! from the earliest position an index does not cover. Index updates are monotone (locations
//! only grow), so replaying over any older index state converges.
//!
//! Readers never lock: a `Snapshot` is a committed checkpoint number plus a grace-period ticket
//! (rcu.zig) that keeps every mapping, run and memtable it can reach alive until release.
//! Index entries publish record locations with release stores; every record carries the
//! checkpoint that wrote it and a link to the previous version, so a reader of an older
//! snapshot walks back to the version it may see. Reads return views into the mmap'd segments
//! (zero copy) after checking the record's checksum and identity: a damaged byte is reported,
//! never returned.
//!
//! Pruning drops whole segments with their runs. Live objects whose newest record sits in a
//! dropped segment are first copied forward into the current segment (QMDB-style
//! carry-forward, one sequential sweep, measured in the report); nothing is ever compacted or
//! merged.
const std = @import("std");
const uaf_guard = @import("guard.zig");
const builtin = @import("builtin");
const format = @import("format.zig");
const table = @import("table.zig");
const io_mod = @import("io.zig");
const clock = @import("clock.zig");
const cs = @import("checksum.zig");
const rcu_mod = @import("rcu.zig");
const chunk = @import("chunk.zig");
const zstd_c = @import("zstd_c.zig");
const cache_mod = @import("cache.zig");
const readstats = @import("readstats.zig");
const txfix = @import("txfix.zig");
const prefetch = @import("prefetch.zig");
const hash = @import("hash");

const Backend = io_mod.Backend;
const Fd = io_mod.Fd;
const Kind = format.Kind;
const block = format.block;
const page_size = table.page_size;

/// Fills `buf` from the OS's secure random source (getrandom on Linux, arc4random elsewhere).
fn osRandom(buf: []u8) void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var got: usize = 0;
        while (got < buf.len) {
            const rc = linux.getrandom(buf[got..].ptr, buf.len - got, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => got += rc,
                .INTR => {},
                else => @panic("getrandom failed"),
            }
        }
    } else std.c.arc4random_buf(buf.ptr, buf.len);
}

pub const Config = struct {
    /// Store directory (used by `openDir`; `open` takes an already-built backend).
    dir: []const u8 = "",
    /// Epochs of history `pruneRetained` keeps besides the current one; for the node, sui-node's
    /// `num-epochs-to-retain-for-checkpoints` (checkpoints, transactions, effects, events).
    retention_epochs: u32 = 2,
    /// sui-node's `num-epochs-to-retain` (object versions); used by the node's retention.
    object_retention_epochs: u32 = 1,
    /// sui-node's `authority-store-pruning-config.smooth` (default true): the pruning watermarks
    /// approach their targets over an epoch instead of jumping (node retention.zig).
    smooth: bool = true,
    /// Initial capacity of the live index (object ids: live objects plus tombstones still in
    /// retained epochs). It doubles when it fills.
    max_live_objects: u64 = 1 << 20,
    /// Memtable capacity (entries per sealed run): object versions, transactions, checkpoints.
    max_object_versions: u64 = 1 << 22,
    max_transactions: u64 = 1 << 21,
    max_checkpoints: u64 = 1 << 20,
    /// Largest commit group (one checkpoint, or one chunk of carried objects).
    max_batch_bytes: usize = 64 << 20,
    /// Distinct objects one checkpoint may touch.
    max_batch_objects: u32 = 1 << 16,
    /// Segments that can be open at once (power of two; must exceed the retained epoch span).
    max_segments: u32 = 4096,
    /// Live-index flush every this many checkpoints (bounds recovery replay).
    index_flush_interval: u64 = 4096,
    /// Live-index pages changed since the last flush that force a flush (bounds the private
    /// memory of the live table and the journal size). While a background flush runs the
    /// writer goes on; it waits only when 4x this many pages are dirty again.
    max_dirty_pages: u64 = 1 << 17,
    /// Live-index flushes run on a background thread (real files only; the simulator flushes
    /// inline at the trigger, through the same steps). The commit that triggers one only
    /// freezes the dirty page set.
    background_flush: bool = true,
    /// Gaps of clean pages up to this many pages are written along with the dirty pages around
    /// them (identical bytes), so the in-place writes go out as runs of up to 64 pages: an
    /// IOPS-bound volume (EBS gp3) counts one operation per run, not per page. A bridged gap
    /// costs bandwidth: 7 stays under the break-even of gp3 at 16k IOPS and ~600 MB/s (~9
    /// pages per operation saved); 31 wrote 6.4x the dirty bytes in catch-up (14.2M pages for
    /// 2.2M dirty) and made each flush bandwidth-bound.
    flush_gap_pages: u64 = 7,
    /// 0 (default): one buffered writer, its pages synced at the next flush. N > 0 (real files,
    /// at most 64): N parallel writers, each on its own slice, then one fdatasync, so the pages
    /// are durable when the flush ends. Buffered by default: each writer writes back what it
    /// wrote every few MiB (sync_file_range on Linux) and the pages stay cached.
    flush_writers: u64 = 0,
    /// With `flush_writers` > 0 on Linux: the writers write unbuffered (O_DIRECT). Direct
    /// writes invalidate the written pages in the page cache, so every flushed (hot) page
    /// faults back from disk on its next use: on a read-saturated volume (box 1, 2026-11-08)
    /// catch-up had 16.5 commits over 100 ms per 1k against 4.3 serial buffered, p99 164
    /// against 70 ms.
    flush_direct: bool = false,
    /// Initial mapping of the segment being appended to; it doubles as the segment grows.
    segment_reserve: u64 = 1 << 30,
    /// Check every record's checksum on read.
    verify_reads: bool = true,
    /// Check every index page checksum at open (else rely on the record checks of readers).
    verify_index_on_open: bool = true,
    /// Copy each run's key filters (table.Bloom, ~1.3 bytes per index entry) into memory, so a
    /// cold page cache does not turn the filter checks into reads. Off: they are read through
    /// the run's mapping.
    run_filters_resident: bool = true,
    /// Hash seed for a new store (0: derived from the clock). Kept in `meta`.
    seed: u64 = 0,
    /// Parses (id, version) out of BCS `Object` bytes. Required to write or read compact object
    /// records (`Batch.putBase`, segment cleaning); without it they are written in full and a
    /// compact record reads as damage.
    codec: ?Codec = null,
    /// Segment cleaning (`cleanStep`): an aged segment is copied out and deleted when its live
    /// objects, at `clean_record_bytes` each, fill less than `clean_live_pct` percent of it.
    /// Denser segments (the restored live set) stay where they are.
    clean_record_bytes: u64 = 384,
    clean_live_pct: u64 = 25,
    /// The cleaner's live-table count pass reads ahead in large requests and marks what it
    /// walked cold (real files only). Off: page by page, as before lane catchup-io (A/B).
    clean_readahead: bool = true,
    /// New segments are written compressed (chunk.zig, segment format 3): records are packed into
    /// zstd chunks of about `chunk_bytes` logical bytes. Locations, indexes and checksums are those
    /// of the uncompressed layout, so uncompressed segments (format 2) stay readable beside them.
    compress: bool = true,
    chunk_bytes: u32 = 256 << 10,
    /// Threads that compress one commit group's chunks (the committing thread included; 0:
    /// min(4, cores)). The bytes written are the same for any value (chunk.Encoder).
    compress_threads: u32 = 0,
    /// Compressed chunks drop their record checksums (chunk codec 2; decoding recomputes them):
    /// about 7% less disk on a restored live set. False writes codec 1 (both always read).
    elide_sums: bool = true,
    /// History dictionaries (chunk codec 3, chunk.zig): outside a bulk restore, commit groups are
    /// compressed with a raw-content dictionary of the most recent `dict_bytes` committed bytes,
    /// persisted per segment in `index/<epoch>.zd` before first use and replaced every
    /// `dict_refresh_bytes` of committed history (1 GiB: the dictionary costs about 0.5% of
    /// the compressed bytes it serves). About 24% less disk for history on the fixture (3.79x to
    /// 4.97x with a 1 MiB dictionary cut 10 minutes before the chunks it compressed).
    history_dicts: bool = true,
    dict_bytes: u32 = 1 << 20,
    dict_refresh_bytes: u64 = 1 << 30,
    /// Byte budget of the decoded-chunk cache shared by all readers.
    cache_bytes: u64 = 1 << 30,
    /// Age-out (holes in sealed compressed segments, `ageStep` / `startAger`): the object pass
    /// trails the object floor by this many checkpoints, so versions superseded soon after they
    /// were written go in the first rewrite (later ones wait for the checkpoint pass).
    age_lag_checkpoints: u64 = 4096,
    /// Use-after-release guard (guard.zig): released segment views and decoded chunks become
    /// inaccessible reservations, so a slice read through a released snapshot faults at its first
    /// use. null: on in safety test builds or with ZUI_UAF_GUARD=1.
    uaf_guard: ?bool = null,
    /// Superseded locations remembered between the object floor scan and the passes (at most:
    /// `age_mem_bytes` holds the set to a quarter of the ager's memory, `agePendingMax`).
    age_pending_max: u64 = 1 << 23,
    /// What the ager may hold in memory, in bytes (`ageMem` measures it, `AgeStats.mem`):
    ///   - the pending set: a quarter. Its entries are capped so that the hash map, which grows
    ///     by doubling (old and new table side by side while it does), stays inside that;
    ///   - the live set's bits: half (and `age_set_bytes`);
    ///   - the group buffers of the step and of its read-ahead, and the batch buffer: a buffer
    ///     that had to grow past an eighth for one large group is given back after the step;
    ///   - finished rewrites waiting for the writer: each holds the old directory of its
    ///     segment (32 bytes a chunk: 23 MiB for a mainnet restore image) until the writer has
    ///     taken it, so the ager thread starts no step while more than an eighth waits.
    /// 256 MiB leaves the pending set 3,355,442 entries (36 MiB, 54 MiB while it grows).
    age_mem_bytes: u64 = 256 << 20,
    /// Logical bytes one background step reads, and the background pace (MiB/s read).
    age_budget: u64 = 8 << 20,
    age_mbps: u64 = 96,
    /// Groups up to this size are rewritten whole (one block-aligned punch); larger ones (the
    /// restored live set) chunk by chunk, only where a chunk lost an eighth of what it held.
    age_whole_group_bytes: u64 = 4 << 20,
    /// Deferred age-out (`AgeMode.deferred`): logical bytes of history below the checkpoint
    /// floor the ager may leave unprocessed while the node is behind the tip (`ageBacklog`);
    /// past it the ager stops waiting and catches up in one run (the scan, the object pass and
    /// the checkpoint pass, to their floors). Age-out only frees disk space, so this is what
    /// the deferral can cost: about this much history still allocated that a running ager
    /// would have punched.
    age_defer_bytes: u64 = 16 << 30,
    /// Age-out read-ahead (`ageWarm`): live-table page reads in flight, and the share of the
    /// ager thread's time those reads may take (percent; the thread sleeps the rest between
    /// slices of `16 * age_qd` pages, so a disk with an IOPS limit is not held at its limit;
    /// 100: no sleep).
    age_qd: u32 = 32,
    age_share_pct: u64 = 50,
    /// Segment pass with a live set (lane ager-segment-pass; needs the read-ahead, so not with
    /// `age_serial`). Before the pass walks aged segments, one sequential pass over the live
    /// table marks every location the table names in them, one bit per `AgeSet.cell` bytes, in
    /// at most `age_set_bytes` of memory (a larger stretch is done in several rounds, each with
    /// its own table pass). A record whose bit is set is kept without a lookup. An object
    /// version whose bit is clear is not the table's record of its object (`AgeSet` says why
    /// that is certain) and goes by the rest of the rule without a lookup; a tombstone whose
    /// bit is clear is still looked up. Off: one live-table lookup per object record of every
    /// aged segment (about 730M random reads for a mainnet restore image).
    age_live_set: bool = false,
    age_set_bytes: u64 = 512 << 20,
    /// Live-table pages one step of the table pass reads at most (0: what the step's budget
    /// allows). For tests: a pass cut into many steps meets commits and moved slots.
    age_set_step_pages: u64 = 0,
    /// With `age_live_set`: look every object version with a clear bit up as well (the rule as
    /// it was, one read per dead record, made only where a chunk could be rewritten) and count
    /// in `AgeStats.set_misses` any that the table still names. It must stay 0.
    age_set_verify: bool = false,
    /// Age-out as before lane ager-catchup (the old path, kept for comparison and as a switch):
    /// no read-ahead before a step, and one live-table lookup per object record under `age_mu`.
    /// Either way the same records become holes and the same bytes are written.
    age_serial: bool = false,
};

pub const ObjKey = struct { id: [32]u8, version: u64 };

pub const Codec = struct {
    key: *const fn (bytes: []const u8) ?ObjKey,
};

/// Sui object digest: blake2b256("Object::" ++ BCS Object).
pub fn objectDigest(bytes: []const u8) [32]u8 {
    return hash.blake2b256(&.{ "Object::", bytes });
}

pub const RemoveKind = enum(u8) { deleted = 0, wrapped = 1 };

pub const ObjectRef = struct {
    version: u64,
    digest: [32]u8,
    bytes: []const u8,
};

/// One object record, full or compact, decoded.
pub const ObjRec = struct {
    id: [32]u8,
    version: u64,
    /// Checkpoint that wrote it (0 for compact records: visible to every snapshot).
    seq: u64,
    /// Previous-version location (0: none).
    a: u64,
    flags: u8,
    bytes: []const u8,
    /// Stored digest (full records); compact records compute it.
    stored_digest: ?*align(1) const [32]u8,

    pub fn digest(o: *const ObjRec) [32]u8 {
        return if (o.stored_digest) |d| d.* else objectDigest(o.bytes);
    }

    pub fn ref(o: *const ObjRec) ObjectRef {
        return .{ .version = o.version, .digest = o.digest(), .bytes = o.bytes };
    }
};

/// A live object as the live-object iterator yields it.
pub const LiveItem = struct {
    id: [32]u8,
    version: u64,
    digest: [32]u8,
    bytes: []const u8,
};

pub const CheckpointRecord = struct {
    seq: u64,
    epoch: u64,
    summary_cert: []const u8,
    contents: []const u8,
};

pub const TransactionRecord = struct {
    /// Checkpoint that holds the transaction.
    checkpoint: u64,
    digest: *const [32]u8,
    effects_digest: *const [32]u8,
    tx: []const u8,
    effects: []const u8,
    events: ?[]const u8,
    /// Location of the transaction's record (0: unknown). `objectNear` and the loaded-list
    /// lookup take it as the hint for the transaction's object versions.
    loc: u64 = 0,
};

pub const LatestObject = union(enum) {
    live: ObjectRef,
    removed: struct { version: u64, kind: RemoveKind },
};

pub const PruneReport = struct {
    /// Segments whose epoch left the history window (kept in place while they hold live
    /// objects; their runs are dropped).
    segments_aged: u64 = 0,
    segments_dropped: u64 = 0,
    bytes_dropped: u64 = 0,
    runs_dropped: u64 = 0,
    objects_carried: u64 = 0,
    bytes_carried: u64 = 0,
    tombstones_dropped: u64 = 0,
    /// Live tombstones copied out of a cleaned segment because an older aged segment remains.
    tombstones_carried: u64 = 0,
    /// Superseded object versions copied out of a cleaned segment because an xref in the
    /// history window still names them (their bytes are counted in `bytes_carried`).
    versions_carried: u64 = 0,
    ns: u64 = 0,
    /// cleanStep: nothing to do.
    idle: bool = false,
};

const Clean = struct {
    phase: enum { idle, count, sweep } = .idle,
    /// A recount is due (an epoch aged out, or a segment was deleted).
    due: bool = false,
    live: ?*LiveHandle = null,
    page: u64 = 0,
    /// Pages of the count pass already asked for (MADV_WILLNEED) up to here.
    ahead: u64 = 0,
    /// Live objects per aged segment (index of `Store.aged`).
    counts: []u64 = &.{},
    target: u64 = 0,
    off: u64 = 0,
    /// Distinct live-table pages the sweep asked for ahead of its lookups (MADV_WILLNEED), and
    /// steps cut short by their deadline (`cleanStepUntil`). Totals since open.
    table_ahead: u64 = 0,
    cut: u64 = 0,
};

pub const Stats = struct {
    commits: u64 = 0,
    /// Open: the newest meta copy was found in the other slot (a misdirected write), or the
    /// other slot holds an older copy than the newest one's parent (a lost or stale write).
    meta_misdirected: u64 = 0,
    meta_stale: u64 = 0,
    bytes_appended: u64 = 0,
    /// Bytes written to compressed segments (frames and padding) for `bytes_appended` logical.
    bytes_written_phys: u64 = 0,
    /// Live-index flushes and the bytes they wrote (journal plus in-place pages).
    index_flushes: u64 = 0,
    index_bytes_written: u64 = 0,
    runs_sealed: u64 = 0,
    run_bytes_written: u64 = 0,
    live_grows: u64 = 0,
    segment_remaps: u64 = 0,
    replayed_groups: u64 = 0,
    /// The open found the live table closed cleanly (`meta_clean`: the page check is skipped).
    /// False after any other end of the last process: every page of the table was checked.
    open_clean: bool = false,
    truncated_bytes: u64 = 0,
    corrupt_reads: std.atomic.Value(u64) = .init(0),
    /// Background flushes and the pages the writer saved for them (copy on write), and the
    /// time commits waited on a running flush (backpressure, growth, epoch changes).
    flush_bg: u64 = 0,
    flush_cow_pages: u64 = 0,
    flush_wait_ns: u64 = 0,
    /// Duration of the last background flush (journal, meta, in-place writes, drops).
    flush_last_ns: u64 = 0,
    /// In-place write operations (runs of pages) of background flushes, and the pages in them.
    flush_runs: u64 = 0,
    flush_run_pages: u64 = 0,
    /// Pages of the last background flush, and its drain rate (pages per second, journal to
    /// drops): the pacing below slows the writer to it.
    flush_last_pages: u64 = 0,
    /// Background flushes whose in-place pages went out through the parallel writers (each
    /// ending in its own fdatasync).
    flush_parallel: u64 = 0,
    /// Of those, the ones written unbuffered (`flush_direct` on Linux).
    flush_direct: u64 = 0,
    flush_drain_pps: u64 = 0,
    /// Pacing: time commits slept so the dirty set grows no faster than a running flush drains
    /// it (instead of a hard block at the cap), and the longest single delay.
    flush_pace_ns: u64 = 0,
    flush_pace_max_ns: u64 = 0,
    /// The live table was rebuilt from the logs at open.
    rebuilt_index: bool = false,
    /// Runs rebuilt from the logs at open.
    rebuilt_runs: u64 = 0,
};

pub const Error = io_mod.Error || table.Error || format.Error || error{
    BatchFull,
    BatchActive,
    NoBatch,
    SeqRegression,
    EpochRegression,
    TooManySegments,
    TooManyRuns,
    PruneCurrent,
    NotFound,
    Poisoned,
    /// The segment's 44-bit offset space has no room for this group.
    SegmentFull,
};

const max_runs = 128;
const no_epoch = std.math.maxInt(u64);

const SegSlot = struct {
    epoch: std.atomic.Value(u64) = .init(no_epoch),
    base: std.atomic.Value(usize) = .init(0),
    /// Durable end of the segment (readers see records below it).
    end: std.atomic.Value(u64) = .init(0),
    /// Writer only: length of the current mapping.
    view_len: u64 = 0,
    fd: Fd = 0,
    runs: [max_runs]std.atomic.Value(?*table.Run) = @splat(.init(null)),
    nruns: std.atomic.Value(u32) = .init(0),
    /// Compressed segment (format 3): its chunk directory; null for an mmap'd raw segment.
    comp: std.atomic.Value(?*CSeg) = .init(null),
};

/// A compressed segment's state (chunk.zig). Readers use `fd`, `id` and `dir`; the rest is the
/// writer's.
const CSeg = struct {
    fd: Fd,
    /// Unique per opened segment: the cache key's high bits.
    id: u64,
    /// The segment's epoch (record locations, for codec-2 frames: chunk.zig).
    epoch: u64,
    dir: std.atomic.Value(*chunk.Dir),
    /// Physical append offset (4096-aligned).
    phys_tail: u64 = 0,
    /// `index/<epoch>.dir`: entries appended after each commit (unsynced; a trusted prefix is
    /// checked at open), or null when it could not be written.
    dir_fd: ?Fd = null,
    dir_written: u64 = 0,
    dir_seed: u64 = 0,
    /// The dir file may hold entries past `dir_written` (cut at the next write).
    dir_cut: bool = true,
    /// Logical end of the dir file's trusted prefix at open. An entry is appended only after
    /// its group's `writeSync` returned, so every group below this offset was durable on disk:
    /// recovery never truncates one of them as torn (a damaged one is rot, error.Corrupt).
    dir_proof: u64 = 0,
    /// Age-out (ager under `Store.age_mu`): the sidecar holding rewritten chunks
    /// (`index/<epoch>.side`, set before any `side_bit` entry is published) and its append
    /// offset; the age log (`index/<epoch>.age`), its trusted records and seed; the checkpoint
    /// pass's progress (logical offset) and the object floor epoch the last segment pass ran for.
    side_fd: ?Fd = null,
    side_tail: u64 = 0,
    age_fd: ?Fd = null,
    age_n: u64 = 0,
    age_seed: u64 = 0,
    age_cut: bool = false,
    cp_done: u64 = 0,
    seg_done: u64 = 0,
    /// The dir file was synced complete once the segment was sealed (before any rewrite).
    dir_sealed: bool = false,
    /// History dictionaries (codec 3) and their file `index/<epoch>.zd` (writer: append offset
    /// past the trusted prefix, and the record seed).
    dicts: *chunk.Dicts,
    zd_fd: ?Fd = null,
    zd_tail: u64 = 0,
    /// The dictionary file's directory entry is durable (synced after it was created, or found
    /// at open).
    zd_named: bool = false,
    zd_seed: u64 = 0,
};

/// A digested history dictionary held by the writer or the ager: dictionary `id` of the
/// segment `epoch` open as CSeg `cid`.
const HeldDict = struct {
    cid: u64,
    epoch: u64,
    id: u32,
    cdict: *zstd_c.CDict,

    fn matches(h: ?HeldDict, c: *const CSeg, id: ?u32) ?chunk.DictRef {
        const x = h orelse return null;
        if (x.cid != c.id or x.epoch != c.epoch) return null;
        if (id) |i| if (i != x.id) return null;
        return .{ .id = x.id, .cdict = x.cdict };
    }
};

const Meta = extern struct {
    /// "ZUIMETA3"; "ZUIMETA2" (written before lane disk-fit): the first 128 bytes only, no
    /// `live_key`, and the live table it names has 32-byte slots (`table.LegacyPage`), which the
    /// next open migrates (`migrateLive`).
    magic: [8]u8 = "ZUIMETA3".*,
    checksum: u64 = 0,
    generation: u64 = 0,
    algo: u32 = cs.current_algo,
    /// `meta_clean`: written by a clean close after the live table was synced and the journal
    /// emptied; the next open maps the table without checking every page. Every other meta
    /// write clears it (an in-place table write always follows a newer meta).
    flags: u32 = 0,
    seed: u64 = 0,
    has_committed: u64 = 0,
    committed: u64 = 0,
    oldest_epoch: u64 = 0,
    live_tg: u64 = 0,
    live_pages: u64 = 0,
    /// Generation of the live-table flush this meta completes (the journal of that flush).
    live_gen: u64 = 0,
    /// First log location the live table file does not cover.
    live_applied: u64 = 0,
    live_has_anchor: u64 = 0,
    /// Checksum of the commit record just before `live_applied`.
    live_anchor: u64 = 0,
    live_count: u64 = 0,
    live_live: u64 = 0,
    /// Secret of the live table's slot keys (table.zig; drawn from the OS at creation).
    live_key: table.Secret = @splat(0),

    const v2_len = 128;

    fn sum(m: *const Meta) u64 {
        var c = m.*;
        c.checksum = 0;
        const b = std.mem.asBytes(&c);
        return cs.hash(0x6d657461, if (m.legacy()) b[0..v2_len] else b);
    }

    /// Written before lane disk-fit: names a table of 32-byte slots.
    fn legacy(m: *const Meta) bool {
        return std.mem.eql(u8, &m.magic, "ZUIMETA2");
    }

    fn valid(m: *const Meta) bool {
        return (m.legacy() or std.mem.eql(u8, &m.magic, "ZUIMETA3")) and m.sum() == m.checksum;
    }
};

comptime {
    std.debug.assert(@offsetOf(Meta, "live_key") == Meta.v2_len);
    std.debug.assert(@sizeOf(Meta) <= MetaChain.offset);
}

/// Retention floors, in the meta page after `Meta` (its own magic and checksum, so a meta page
/// written before floors existed still reads: no floors).
const MetaFloors = extern struct {
    magic: [8]u8 = "ZUIFLOR1".*,
    checksum: u64 = 0,
    generation: u64 = 0,
    cp_floor: u64 = 0,
    obj_floor: u64 = 0,
    obj_floor_epoch: u64 = 0,

    const offset = 2048;

    fn sum(m: *const MetaFloors) u64 {
        var c = m.*;
        c.checksum = 0;
        return cs.hash(0x666c6f72, std.mem.asBytes(&c));
    }
};

/// Each meta slot's link in the chain of meta writes, in the meta page after `Meta` (its own
/// magic, so a page written before it existed reads as unchained). `slot` is the slot the copy
/// was written to (a copy found in the other slot was misdirected); `parent` the checksum and
/// generation of the newest copy it replaced, so the two slots are checked to be one history.
const MetaChain = extern struct {
    magic: [8]u8 = "ZUICHAN1".*,
    checksum: u64 = 0,
    generation: u64 = 0,
    meta_sum: u64 = 0,
    slot: u64 = 0,
    parent: u64 = 0,
    parent_gen: u64 = 0,

    const offset = 1024;

    fn sum(c: *const MetaChain) u64 {
        var x = c.*;
        x.checksum = 0;
        return cs.hash(0x6368616e, std.mem.asBytes(&x));
    }
};

/// `Meta.flags`: the live table was synced and its journal emptied by a clean close; the next
/// open skips the page check (lane fast-start). Every other meta write clears it.
const meta_clean: u32 = 1;
/// `Meta.flags`: every page of the live table was written sealed (a whole-table write: rebuild,
/// growth, bulk load), so an all-zero page in it is damage. Without it (a fresh sparse table,
/// or one from before empty pages were sealed) zero pages pass.
const meta_sealed: u32 = 2;

const JournalHeader = extern struct {
    magic: [8]u8 = "ZUIJRNL1".*,
    algo: u32 = cs.current_algo,
    /// `jnl_sealed`: its pages are sealed even when empty (zero in older journals).
    flags: u32 = jnl_sealed,
    checksum: u64 = 0,
    tg: u64,
    gen: u64,
    npages: u64,
    list_hash: u64,

    fn sum(h: *const JournalHeader) u64 {
        var c = h.*;
        c.checksum = 0;
        return cs.hash(0x6a726e6c, std.mem.asBytes(&c));
    }
};

const jnl_sealed: u32 = 1;

const LiveHandle = struct {
    t: table.LiveTable,
    view: []align(page_size) u8,
    fd: Fd,
    tg: u64,
    /// Every page of the file was written sealed (`meta_sealed`).
    sealed: bool = false,
};

const PendLink = struct { id: [32]u8, loc: u64 };

/// A finished age-out rewrite waiting for its grace period (`Retired.aged`).
const AgeDone = struct {
    c: *CSeg,
    old: *chunk.Dir,
    punch: std.ArrayList(PunchRange) = .empty,
    keys: std.ArrayList(u64) = .empty,
};
const PunchRange = struct { side: bool, off: u64, len: u64 };
const AgeChange = struct { idx: usize, ls: u64, ll: u32, phys: u64, bl: u32, codec: u32, old_phys: u64, old_bl: u32 };
const Lag = struct { end: u64, seq: u64 };

/// The locations the live table names inside a stretch of aged segments (`Store.ageSetScan`),
/// for the segment pass: one bit per `cell` bytes of each range. Under `Store.age_run`.
///
/// A set bit means: at some moment of the table pass a slot named a location in that cell.
/// A set bit keeps the record, without a lookup. It can be stale (the record died after the
/// pass read its slot): then the record is kept until the next pass.
///
/// A clear bit in an `exact` set means the record there is not live, now or later. Proof. Let
/// the record at `l`, in a sealed aged segment, be live when the ager judges it: the table
/// holds `l` for its object then. (1) The record was committed, and the table set to `l`, before
/// the segment was sealed, so before the pass began; a table entry only moves to later
/// locations (`LiveTable.upsertKey`), so the table held exactly `l` for that object from
/// before the pass until the judgement. (2) In an exact pass no slot moved: only
/// `LiveTable.remove` moves slots, under the table's sequence counter, and the pass read that
/// counter before its first slot and found it unchanged after its last, on one table (a
/// replaced table restarts the pass); inserts fill empty slots and updates store in place. So
/// the object's entry sat in one slot for the whole pass and the pass read that slot once, with
/// an atomic load, and saw `l`. (3) So the pass set the bit of `l`'s cell. Contrapositive: bit
/// clear, record not live. Two table-named records sharing a cell (they would have to start
/// within 64 bytes; full object records are at least 112 bytes, tombstones 88, a compact record
/// 16 plus a BCS object) only makes a dead one look named, which keeps it.
///
/// A pass that saw the counter move starts over, three times at most; after that it finishes
/// inexact, and a clear bit then sends the record to the lookup, as does a location outside
/// the ranges. A store in a bulk load (its table is not filled yet) builds no set.
///
/// Links. A record the table no longer names can still be one a read finds: a restored
/// (compact) version that a later commit superseded is read by (id, version) through its link
/// record for as long as the link's index run is inside the object window
/// (`Snapshot.objectFind`). So after the table pass the set also takes every location inside
/// its ranges that the version index of the in-window runs and of the memtable names
/// (`Store.ageSetLinks`); only then is it ready. Such an entry is a link's (an aged segment's
/// own version entries are in its own runs, which are gone with its window; a
/// cross-reference's entry names the cross-reference). Completeness: a link is committed
/// with the record that supersedes its target. If that commit came after the table pass read
/// the object's slot, the pass saw the target as the table's record and set its bit. If it
/// came before, the link was in the memtable or in a run when the link phase began: the
/// memtable is read whole at the phase's first step (its entries never move), and a run is
/// never replaced or removed while its epoch is in the window, only added.
///
/// What a set bit then says. For a compact record: the table or a link names it; it stays.
/// For a full record or a tombstone a bit from the index can also be the record's own version
/// entry, where the memtable or run that holds that entry is still in the window although the
/// record's segment has left it (the run a restore ends in, the run that straddles an epoch
/// boundary). Such entries name locations at or after the start of the oldest index source the
/// phase read (`amb_lo`); an entry that names an earlier location is a link, and links name
/// compact records only. So a set bit keeps a full record or a tombstone only before `amb_lo`
/// (`keeps`); at or after it the record is looked up, as without a set. A clear bit means the
/// same for every kind: neither the table nor an index entry names the location.
const AgeSet = struct {
    const cell: u64 = 64;
    const Range = struct { e: u64, lo: u64, hi: u64, base: u64 };

    ranges: std.ArrayList(Range) = .empty,
    bits: []u64 = &.{},
    /// The segment pass target the ranges were planned for.
    target: u64 = 0,
    state: enum { none, building, links, ready } = .none,
    /// No memory for the bits: the pass goes on with lookups.
    failed: bool = false,
    /// Table pass: next page, the table's generation, pages asked for ahead; the table's
    /// sequence counter before the first slot was read, whether it has stayed there, and how
    /// often the pass started over because it had not.
    page: u64 = 0,
    tg: u64 = 0,
    ahead: u64 = 0,
    seq0: u64 = 0,
    exact: bool = false,
    restarts: u32 = 0,
    /// Table bytes read since the last step (the step counts them as read: pace, not idle).
    credit: u64 = 0,
    last: usize = 0,
    /// Link phase: the memtable is done; the next run to read (its epoch, its number in the
    /// epoch's slot) and the next entry of it.
    lk_mem: bool = false,
    lk_epoch: u64 = 0,
    lk_run: u32 = 0,
    lk_entry: u64 = 0,
    /// Where the oldest index source the link phase read starts (see above).
    amb_lo: u64 = 0,

    fn find(st: *AgeSet, e: u64, off: u64) ?*const Range {
        const rs = st.ranges.items;
        if (rs.len == 0) return null;
        if (st.last < rs.len) {
            const r = &rs[st.last];
            if (r.e == e and off >= r.lo and off < r.hi) return r;
        }
        if (e < rs[0].e or e > rs[rs.len - 1].e) return null;
        for (rs, 0..) |*r, i| if (r.e == e and off >= r.lo and off < r.hi) {
            st.last = i;
            return r;
        };
        return null;
    }

    /// The ranges were planned for `target` and hold `off` of segment `e`.
    fn covers(st: *AgeSet, target: u64, e: u64, off: u64) bool {
        return st.state != .none and st.target == target and st.find(e, off) != null;
    }

    fn usable(st: *AgeSet, e: u64, off: u64) bool {
        return st.state == .ready and st.find(e, off) != null;
    }

    /// An exact, ready set holds `l`'s cell and its bit is clear: proof that the record there
    /// is not live and that no link in the window names it (see above).
    fn proves(st: *AgeSet, l: u64) bool {
        return st.state == .ready and st.exact and st.find(format.epochOf(l), format.offsetOf(l)) != null and !st.live(l);
    }

    /// The set says the record at `l` stays (`compact`: a compact record), without a lookup.
    fn keeps(st: *AgeSet, l: u64, compact: bool) bool {
        return (compact or l < st.amb_lo) and st.live(l);
    }

    /// The bit of `l`'s cell: the table named the location when it was read, or an index entry
    /// in the window does (`keeps` says what that is worth).
    fn live(st: *AgeSet, l: u64) bool {
        if (st.state != .ready) return false;
        const off = format.offsetOf(l);
        const r = st.find(format.epochOf(l), off) orelse return false;
        const bit = r.base + (off - r.lo) / cell;
        return st.bits[bit / 64] & (@as(u64, 1) << @intCast(bit % 64)) != 0;
    }

    fn mark(st: *AgeSet, l: u64) bool {
        const off = format.offsetOf(l);
        const r = st.find(format.epochOf(l), off) orelse return false;
        const bit = r.base + (off - r.lo) / cell;
        st.bits[bit / 64] |= @as(u64, 1) << @intCast(bit % 64);
        return true;
    }

    fn release(st: *AgeSet, gpa: std.mem.Allocator) void {
        gpa.free(st.bits);
        st.bits = &.{};
        st.ranges.clearRetainingCapacity();
        st.state = .none;
    }

    fn deinit(st: *AgeSet, gpa: std.mem.Allocator) void {
        gpa.free(st.bits);
        st.ranges.deinit(gpa);
    }
};

/// Read-ahead of an age-out step (`Store.ageWarm`), under `Store.age_run`.
const AgeWarm = struct {
    /// The last read-ahead ran: the step counts the lookups whose page it did not ask for.
    on: bool = false,
    /// A decoded group (the dry run's own buffer: the step's is `Ager.g`).
    g: std.ArrayList(u8) = .empty,
    /// Live-table pages the step's lookups will touch (sorted, distinct), and of those the
    /// ones to read (inside the table, not held dirty by the writer).
    pages: std.ArrayList(u64) = .empty,
    io: std.ArrayList(u64) = .empty,
    /// io_uring reader (Linux, real files; set up at the first read-ahead that has pages to
    /// read); null: MADV_WILLNEED, then a touch per page.
    pf: ?*prefetch.Prefetcher = null,
    pf_tried: bool = false,
    /// Per chunk of the group in `g`: bytes that could become holes, bytes that count
    /// (`Store.ageSetChunks`).
    maybe: std.ArrayList(u64) = .empty,
    total: std.ArrayList(u64) = .empty,

    fn deinit(w: *AgeWarm, gpa: std.mem.Allocator) void {
        if (w.pf) |p| p.deinit();
        w.g.deinit(gpa);
        w.pages.deinit(gpa);
        w.io.deinit(gpa);
        w.maybe.deinit(gpa);
        w.total.deinit(gpa);
    }
};

/// Age-out state, under `Store.age_mu` (the ager thread, or `ageStep`'s caller).
const Ager = struct {
    init: bool = false,
    /// The digested dictionary age-out rewrites chunks with (a segment's newest).
    dict: ?HeldDict = null,
    /// Object floor scan: next group (location); groups scanned and not yet passed by the object
    /// pass (end location, checkpoint) from `lag_head` on; how far the object pass may go.
    scan: u64 = std.math.maxInt(u64),
    scan_wait: u64 = std.math.maxInt(u64),
    scan_wait_seq: u64 = 0,
    lagq: std.ArrayList(Lag) = .empty,
    lag_head: usize = 0,
    objc: u64 = std.math.maxInt(u64),
    obj_frontier: u64 = 0,
    cpc: u64 = std.math.maxInt(u64),
    cp_wait: u64 = std.math.maxInt(u64),
    cp_wait_seq: u64 = 0,
    segc: u64 = std.math.maxInt(u64),
    seg_target: u64 = 0,
    /// Locations of records whose successor is below the object floor, and how far both
    /// passes had come when the full set was last pruned (`agePrunePending`).
    pending: std.AutoHashMapUnmanaged(u64, void) = .empty,
    pruned_at: u64 = 0,
    /// Finished rewrites for the writer's grace period (`ageHandoff`), and the bytes of the old
    /// directories they hold.
    handoff: std.ArrayList(*AgeDone) = .empty,
    handoff_n: std.atomic.Value(usize) = .init(0),
    handoff_bytes: std.atomic.Value(u64) = .init(0),
    g: std.ArrayList(u8) = .empty,
    out: std.ArrayList(u8) = .empty,
    ents: std.ArrayList(chunk.Entry) = .empty,
    recs: std.ArrayList(chunk.AgeRec) = .empty,
    changes: std.ArrayList(AgeChange) = .empty,
    punch: std.ArrayList(PunchRange) = .empty,
    drop_new: std.ArrayList(u64) = .empty,
    keep_live: std.ArrayList(u64) = .empty,
    batch_c: ?*CSeg = null,
    batch_e: u64 = 0,
    side_new: bool = false,
    mark_cp: ?u64 = null,
    mark_seg: ?u64 = null,
    /// The step's durable checkpoint floor.
    cp_floor: u64 = 0,
    /// The step's live-table lookups, and those whose page the read-ahead had not asked for.
    lookups: u64 = 0,
    lookups_cold: u64 = 0,
    warm: AgeWarm = .{},
    /// The live set of the segment pass, the records it kept without a lookup this step, and
    /// the step's per-chunk byte counts (`Store.ageSetChunks`).
    set: AgeSet = .{},
    set_kept: u64 = 0,
    maybe: std.ArrayList(u64) = .empty,
    total: std.ArrayList(u64) = .empty,

    fn deinit(a: *Ager, gpa: std.mem.Allocator) void {
        a.warm.deinit(gpa);
        a.set.deinit(gpa);
        a.maybe.deinit(gpa);
        a.total.deinit(gpa);
        if (a.dict) |d| zstd_c.freeCDict(d.cdict);
        a.lagq.deinit(gpa);
        a.pending.deinit(gpa);
        a.handoff.deinit(gpa);
        a.g.deinit(gpa);
        a.out.deinit(gpa);
        a.ents.deinit(gpa);
        a.recs.deinit(gpa);
        a.changes.deinit(gpa);
        a.punch.deinit(gpa);
        a.drop_new.deinit(gpa);
        a.keep_live.deinit(gpa);
    }
};

const Retired = union(enum) {
    view: struct { fd: Fd, view: []const u8, close: bool },
    run: *table.Run,
    mem: *table.Mem,
    live: *LiveHandle,
    chunk: *cache_mod.Item,
    dir: *chunk.Dir,
    cseg: *CSeg,
    /// An age-out rewrite's old directory, the frames it replaced (punched here, after the grace
    /// period, so no reader that saw the old directory reads a hole) and the cache keys of the
    /// rewritten chunks (dropped here: no reader can insert the old bytes again).
    aged: *AgeDone,
};

/// Per-batch id -> newest location in the batch (previous-version links inside one group).
const BatchMap = struct {
    const E = struct { id: [32]u8, loc: u64 };
    entries: []E,
    mask: u64,
    touched: []u64,
    n: usize = 0,

    fn init(gpa: std.mem.Allocator, max: u32) !BatchMap {
        const cap = std.math.ceilPowerOfTwo(u64, @max(16, @as(u64, max) * 2)) catch unreachable;
        const entries = try gpa.alloc(E, cap);
        @memset(std.mem.sliceAsBytes(entries), 0);
        errdefer gpa.free(entries);
        return .{ .entries = entries, .mask = cap - 1, .touched = try gpa.alloc(u64, max) };
    }

    fn deinit(m: *BatchMap, gpa: std.mem.Allocator) void {
        gpa.free(m.entries);
        gpa.free(m.touched);
    }

    fn home(m: *const BatchMap, id: *const [32]u8) u64 {
        return cs.hash(0x626d6170, id) & m.mask;
    }

    fn get(m: *const BatchMap, id: *const [32]u8) ?u64 {
        var i = m.home(id);
        while (m.entries[i].loc != 0) : (i = (i + 1) & m.mask) {
            if (std.mem.eql(u8, &m.entries[i].id, id)) return m.entries[i].loc;
        }
        return null;
    }

    /// Room for `id` (it is in the map, or the map is not full): checked before a record is
    /// appended, so a BatchFull never leaves the record in the batch (a caller that commits and
    /// retries would write it twice: one duplicate compact record per restore batch otherwise,
    /// which the restore-image walk counted twice).
    fn fits(m: *const BatchMap, id: *const [32]u8) bool {
        return m.n < m.touched.len or m.get(id) != null;
    }

    fn put(m: *BatchMap, id: *const [32]u8, l: u64) error{BatchFull}!void {
        var i = m.home(id);
        while (m.entries[i].loc != 0) : (i = (i + 1) & m.mask) {
            if (std.mem.eql(u8, &m.entries[i].id, id)) {
                m.entries[i].loc = l;
                return;
            }
        }
        if (m.n >= m.touched.len) return error.BatchFull;
        m.entries[i] = .{ .id = id.*, .loc = l };
        m.touched[m.n] = i;
        m.n += 1;
    }

    fn reset(m: *BatchMap) void {
        for (m.touched[0..m.n]) |i| m.entries[i].loc = 0;
        m.n = 0;
    }
};

/// Commits whose latency `Store.commitLatency` keeps (about 4.5 hours at the mainnet tip).
const commit_lat_len = 1 << 16;
/// Pages a flush job stages at once (its own buffer: 4 MiB), and the longest in-place run.
const flush_buf_pages = 1024;
const flush_run_max = 64;
/// Most parallel in-place writers of one flush.
const max_flush_writers = 64;
/// Parallel buffered flush writers write back (and wait) after about this many bytes each.
const writeback_bytes = 8 << 20;
/// Dirty pages at which a commit waits for the running flush (a multiple of max_dirty_pages);
/// pacing starts at half of it.
const pace_cap_x = 4;
/// Longest pacing delay of one commit.
const pace_max_ns = 1000 * std.time.ns_per_ms;
/// Journal pages read per batch when an open applies the journal (4 MiB).
const jnl_apply_pages = 1024;

/// One live-index flush of a frozen dirty page set (see "background flush" in Store).
const FlushJob = struct {
    s: *Store,
    h: *LiveHandle,
    /// Frozen pages, ascending.
    list: []u64,
    /// The log end at the freeze and the commit checksum before it: what meta will name.
    applied: u64,
    anchor: ?u64,
    /// Occupied and live slots at the freeze (meta's check of the table file).
    count: u64,
    live: u64,
    gen: u64,
    cow: table.Cow,
    buf: []align(page_size) u8,
    /// The previous flush's in-place writes are not synced yet.
    unsynced: bool,
    done: std.atomic.Value(bool) = .init(false),
    err: ?Error = null,
    ns: u64 = 0,
    bytes: u64 = 0,
    runs: u64 = 0,
    run_pages: u64 = 0,
    /// When the writer froze the set (pacing: pages over elapsed bounds this flush's drain).
    t_start: u64 = 0,
    /// The in-place pages were written unbuffered and synced by the flush itself.
    synced: bool = false,
    /// The parallel writers wrote unbuffered (O_DIRECT).
    direct: bool = false,

    fn main(job: *FlushJob) void {
        const t0 = clock.now();
        job.run() catch |e| {
            job.err = e;
        };
        job.ns = clock.now() -| t0;
        job.done.store(true, .release);
    }

    fn run(job: *FlushJob) Error!void {
        const s = job.s;
        const h = job.h;
        const t = &h.t;
        const c = &job.cow;
        const be = s.backend;
        // The previous flush's in-place pages must be durable before its journal is reused.
        if (job.unsynced) try be.sync(h.fd);
        const jfd = s.jnl_fd.?;
        const n: u64 = job.list.len;
        const list_bytes = std.mem.alignForward(u64, n * 8, page_size);
        const pages_off = page_size + list_bytes;
        {
            const need = pages_off + n * page_size;
            const have = try be.size(jfd);
            if (have > need and have - need > 64 << 20) try be.truncate(jfd, need);
        }
        const buf = job.buf;
        var jh: JournalHeader = .{ .tg = h.tg, .gen = job.gen, .npages = n, .list_hash = cs.hash(0x6a6c7374, std.mem.sliceAsBytes(job.list)) };
        jh.checksum = jh.sum();
        @memset(buf[0..page_size], 0);
        @memcpy(buf[0..@sizeOf(JournalHeader)], std.mem.asBytes(&jh));
        try be.write(jfd, 0, buf[0..page_size]);
        {
            const lb = std.mem.sliceAsBytes(job.list);
            var i: usize = 0;
            while (i < list_bytes) {
                const part = @min(list_bytes - i, buf.len);
                @memset(buf[0..part], 0);
                if (i < lb.len) {
                    const m = @min(part, lb.len - i);
                    @memcpy(buf[0..m], lb[i..][0..m]);
                }
                try be.write(jfd, page_size + i, buf[0..part]);
                i += part;
            }
        }
        // Frozen pages, copied under the copy-on-write lock (from the writer's saved copy if it
        // changed the page since the freeze).
        var k: usize = 0;
        while (k < n) {
            const take: u64 = @min(n - k, flush_buf_pages);
            c.lock();
            for (0..take) |j| {
                const p = job.list[k + j];
                const dst: *[page_size]u8 = buf[j * page_size ..][0..page_size];
                if (c.saved.get(p)) |cp| {
                    dst.* = cp.*;
                    t.sealCopy(p, dst);
                } else {
                    // Unchanged since the freeze: seal the table's page too (only flushes write
                    // the checksum word), so a page this flush cannot drop still equals the file.
                    dst.* = @as(*const [page_size]u8, @ptrCast(&t.pages[p])).*;
                    t.sealCopy(p, dst);
                    @atomicStore(u64, &t.pages[p].sum, std.mem.readInt(u64, dst[page_size - 8 ..], .little), .monotonic);
                }
                _ = @atomicRmw(u64, &c.captured[p / 64], .Or, @as(u64, 1) << @intCast(p % 64), .monotonic);
            }
            c.unlock();
            try be.write(jfd, pages_off + k * page_size, buf[0 .. take * page_size]);
            k += take;
        }
        try be.sync(jfd);
        job.bytes = pages_off + n * page_size;
        {
            s.lockMeta();
            defer s.unlockMeta();
            var m = s.metaAt(h, job.applied, job.anchor);
            m.live_gen = job.gen;
            m.live_count = job.count;
            m.live_live = job.live;
            try s.writeMetaLocked(&m, true);
        }
        // In place: runs of up to `flush_run_max` pages from the journal's copies, with gaps of
        // clean pages filled from the table (identical bytes) so runs go out as one write.
        // Default: one buffered writer; the pages are synced at the next flush. Opt-in
        // (`flush_writers` > 0, real files): that many threads, each on its own contiguous
        // slice of the sorted list, so the volume sees that many writes in flight, then one
        // fdatasync: the pages are durable when the flush ends. Buffered writers write back
        // as they go and the pages stay cached; direct ones (`flush_direct`, Linux) leave them
        // cold (see `Config.flush_direct`).
        var nb: [64]u8 = undefined;
        const name = io_mod.liveName(&nb, h.tg);
        const parallel = s.cfg.flush_writers > 0 and n >= 2 * flush_run_max;
        const direct: ?std.posix.fd_t = if (parallel and s.cfg.flush_direct) be.openDirect(name) else null;
        const wfd: ?std.posix.fd_t = if (!parallel) null else direct orelse be.rawHandle(h.fd);
        if (wfd) |dfd| {
            defer if (direct != null) be.closeDirect(dfd);
            const workers: usize = @intCast(@max(1, @min(s.cfg.flush_writers, n / flush_run_max)));
            var parts: [max_flush_writers]Part = undefined;
            var threads: [max_flush_writers]?std.Thread = @splat(null);
            const per = (n + workers - 1) / workers;
            for (0..workers) |w| {
                const lo = @min(n, w * per);
                const hi = @min(n, lo + per);
                parts[w] = .{ .job = job, .lo = lo, .hi = hi, .dfd = dfd, .buffered = direct == null, .jfd = jfd, .pages_off = pages_off };
            }
            for (0..workers) |w| threads[w] = std.Thread.spawn(.{}, Part.main, .{&parts[w]}) catch null;
            for (0..workers) |w| {
                if (threads[w]) |th| th.join() else parts[w].main();
            }
            defer for (parts[0..workers]) |*pt| pt.written.deinit(s.gpa);
            for (parts[0..workers]) |*pt| {
                if (pt.err) |e| return e;
                job.runs += pt.runs;
                job.run_pages += pt.run_pages;
                job.bytes += pt.bytes;
            }
            // A direct write whose page-cache invalidation failed leaves a stale cached page and
            // marks the file's write-back error, which this fdatasync returns: the flush fails
            // before any private copy is dropped, so no read ever faults the stale page in.
            // (Buffered writers dropped as they went: the cache holds what they wrote.)
            try be.fdatasync(dfd);
            job.synced = true;
            job.direct = direct != null;
            for (parts[0..workers]) |*pt| for (pt.written.items) |r| try job.dropClean(r[0], r[1]);
        } else {
            var pt: Part = .{ .job = job, .lo = 0, .hi = n, .dfd = null, .jfd = jfd, .pages_off = pages_off, .buf = buf[0 .. 2 * flush_run_max * page_size] };
            pt.main();
            if (pt.err) |e| return e;
            job.runs += pt.runs;
            job.run_pages += pt.run_pages;
            job.bytes += pt.bytes;
        }
    }

    /// One writer's slice [lo, hi) of the frozen list, written in place as runs.
    const Part = struct {
        job: *FlushJob,
        lo: u64,
        hi: u64,
        /// Parallel writers' handle (O_DIRECT, or the file's own when `buffered`), or null
        /// (the backend's `write`).
        dfd: ?std.posix.fd_t,
        /// Parallel buffered: write back every `writeback_bytes` and drop as it goes.
        buffered: bool = false,
        jfd: io_mod.Fd,
        pages_off: u64,
        /// Run assembly and staging (2 x flush_run_max pages); allocated by `main` when null.
        buf: ?[]align(page_size) u8 = null,
        err: ?Error = null,
        runs: u64 = 0,
        run_pages: u64 = 0,
        bytes: u64 = 0,
        /// `bytes` at the last write-back.
        wb_bytes: u64 = 0,
        /// Direct writes: the page ranges written, dropped only after the flush's fdatasync.
        written: std.ArrayListUnmanaged([2]u64) = .empty,

        fn main(pt: *Part) void {
            pt.run() catch |e| {
                pt.err = e;
            };
        }

        fn run(pt: *Part) Error!void {
            const job = pt.job;
            const s = job.s;
            const be = s.backend;
            const h = job.h;
            const t = &h.t;
            const c = &job.cow;
            const own = pt.buf == null;
            const buf = pt.buf orelse (s.gpa.alignedAlloc(u8, .fromByteUnits(page_size), 2 * flush_run_max * page_size) catch return error.OutOfMemory);
            defer if (own) s.gpa.free(buf);
            const gap = s.cfg.flush_gap_pages;
            const n = pt.hi;
            // Parallel buffered: the byte range written since the last write-back.
            var wb_lo: u64 = 0;
            var wb_hi: u64 = 0;
            var i: usize = @intCast(pt.lo);
            while (i < n) {
                const p0 = job.list[i];
                var j = i + 1;
                while (j < n and job.list[j] - job.list[j - 1] - 1 <= gap and job.list[j] - p0 < flush_run_max) j += 1;
                const span = job.list[j - 1] - p0 + 1;
                // Frozen pages i..j are adjacent in the journal: one read, then spread out.
                const stage = buf[flush_run_max * page_size ..];
                try be.read(pt.jfd, pt.pages_off + i * page_size, stage[0 .. (j - i) * page_size]);
                var ok: [flush_run_max]bool = @splat(false);
                for (i..j) |x| {
                    const off = job.list[x] - p0;
                    @memcpy(buf[off * page_size ..][0..page_size], stage[(x - i) * page_size ..][0..page_size]);
                    ok[off] = true;
                }
                if (span > j - i) {
                    // Gaps are filled only with pages already in memory (lane fast-start 52f64c9):
                    // inside a memory cap clean pages are cold, and reading them back just to
                    // write the same bytes was a QD1 fault per page (under the lock it stalled
                    // the writer in `touchSlow`: 7 cp/s, commit p99 689 ms; outside it, the next
                    // commit's waitFlush). A cold gap page splits the run instead. Off Linux
                    // every page counts as resident.
                    var resident: [flush_run_max]u8 = @splat(1);
                    if (builtin.os.tag == .linux) {
                        const rc = std.os.linux.syscall3(.mincore, @intFromPtr(&t.pages[p0]), span * page_size, @intFromPtr(&resident));
                        if (std.os.linux.errno(rc) != .SUCCESS) @memset(&resident, 0);
                    }
                    c.lock();
                    var q: u64 = 0;
                    var x = i;
                    while (q < span) : (q += 1) {
                        if (x < j and job.list[x] == p0 + q) {
                            x += 1;
                            continue;
                        }
                        const p = p0 + q;
                        if (resident[q] & 1 == 0) continue; // cold: not read back, the run splits here
                        if (table.Cow.bit(t.dirty, p)) continue; // changed since the freeze: not written
                        const dst: *[page_size]u8 = buf[q * page_size ..][0..page_size];
                        dst.* = @as(*const [page_size]u8, @ptrCast(&t.pages[p])).*;
                        t.sealCopy(p, dst);
                        // An empty page is sealed too now: the table's page must equal the file.
                        @atomicStore(u64, &t.pages[p].sum, std.mem.readInt(u64, dst[page_size - 8 ..], .little), .monotonic);
                        ok[q] = true;
                    }
                    c.unlock();
                }
                var q: u64 = 0;
                while (q < span) {
                    if (!ok[q]) {
                        q += 1;
                        continue;
                    }
                    var e = q + 1;
                    while (e < span and ok[e]) e += 1;
                    const data = buf[q * page_size .. e * page_size];
                    if (pt.dfd) |dfd| try be.pwriteAll(dfd, (p0 + q) * page_size, data) else try be.write(h.fd, (p0 + q) * page_size, data);
                    pt.runs += 1;
                    pt.run_pages += e - q;
                    pt.bytes += (e - q) * page_size;
                    if (pt.dfd != null and !pt.buffered)
                        pt.written.append(s.gpa, .{ p0 + q, p0 + e }) catch return error.OutOfMemory
                    else
                        try job.dropClean(p0 + q, p0 + e);
                    if (pt.buffered) {
                        if (wb_hi == wb_lo) wb_lo = (p0 + q) * page_size;
                        wb_hi = (p0 + e) * page_size;
                    }
                    q = e;
                }
                if (pt.buffered and pt.bytes - pt.wb_bytes >= writeback_bytes) {
                    try be.writeBack(pt.dfd.?, wb_lo, wb_hi - wb_lo);
                    pt.wb_bytes = pt.bytes;
                    wb_lo = wb_hi;
                }
                i = j;
            }
            if (pt.buffered and wb_hi > wb_lo) try be.writeBack(pt.dfd.?, wb_lo, wb_hi - wb_lo);
        }
    };

    /// Drops the private copies of table pages [a, b), just written in place, that the writer
    /// has not touched since the freeze; whole OS pages only (16 KiB on macOS).
    fn dropClean(job: *FlushJob, a: u64, b: u64) Error!void {
        const h = job.h;
        const t = &h.t;
        const c = &job.cow;
        const os_page = std.heap.pageSize();
        const per: u64 = @max(1, os_page / page_size);
        var p = std.mem.alignForward(u64, a, per);
        c.lock();
        defer c.unlock();
        while (p + per <= b) {
            var e = p;
            while (e + per <= b) : (e += per) {
                var clean = true;
                for (e..e + per) |x| {
                    if (table.Cow.bit(t.dirty, x)) clean = false;
                }
                if (!clean) break;
            }
            if (e > p) try job.s.backend.dropRange(h.fd, h.view, p * page_size, (e - p) * page_size);
            p = e + per;
        }
    }
};

pub const Store = struct {
    gpa: std.mem.Allocator,
    backend: Backend,
    cfg: Config,
    seed: u64,
    /// Secret of the live table's slot keys (meta `live_key`; table.zig): from the OS for a new
    /// store or a migrated legacy table, derived from `cfg.seed` when one is set (tests and
    /// simulation stay deterministic).
    live_key: table.Secret = @splat(0),

    /// Reader-visible live table (swapped when it grows). Set by recovery.
    live: std.atomic.Value(?*LiveHandle) = .init(null),
    /// Reader-visible memtable of the current epoch (swapped when sealed). Set by recovery.
    mem: std.atomic.Value(?*table.Mem) = .init(null),
    mem_pool: std.ArrayList(*table.Mem) = .empty,
    live_gen: u64 = 0,
    /// In-place live-table page writes not yet synced (the journal must not be reused first).
    live_unsynced: bool = false,
    jnl_fd: ?Fd = null,
    /// Bulk load of the live table (a formal snapshot restore; `bulkLiveBegin`).
    bulk: ?*BulkLive = null,

    segs: []SegSlot,
    seg_mask: u64,
    /// Retained epochs in order, for readers: ring[head..tail).
    ep_ring: []std.atomic.Value(u64),
    /// Runs published across all slots (readers skip the epoch walk when there are none).
    runs_total: std.atomic.Value(u64) = .init(0),
    ep_head: std.atomic.Value(u64) = .init(0),
    ep_tail: std.atomic.Value(u64) = .init(0),
    /// Aged floor: segments below it left the history window (runs dropped, kept only for their
    /// live objects). Moves only when both floors below have passed a segment (`setFloors`).
    oldest_epoch: std.atomic.Value(u64) = .init(0),
    /// Checkpoint floor (sui-node's checkpoint pruner): highest pruned checkpoint + 1, 0 = none.
    /// Checkpoints, transactions and checkpoint-class aux records written by a lower checkpoint
    /// read as absent; `Snapshot.lowestAvailable` reports it.
    cp_floor: std.atomic.Value(u64) = .init(0),
    /// Object floor (sui-node's objects pruner): highest pruned checkpoint + 1, 0 = none, and the
    /// first epoch whose segment's object versions stay readable (whole segments: deepwave keeps a
    /// superset of sui-node inside the partially pruned epoch).
    obj_floor: std.atomic.Value(u64) = .init(0),
    obj_floor_epoch: std.atomic.Value(u64) = .init(0),
    /// Segments below the history window that still hold live objects, ascending (writer
    /// only). Their slots stay published for live-table reads; they have no runs.
    aged: std.ArrayList(u64) = .empty,
    clean: Clean = .{},
    has_segment: bool = false,
    cur_epoch: u64 = 0,
    /// Append offset in the current segment (block aligned).
    tail: u64 = 0,
    /// Logical start of the newest group committed by this process (tailGroup).
    last_group_base: ?u64 = null,

    /// committed checkpoint + 1 (0: nothing committed yet).
    committed1: std.atomic.Value(u64) = .init(0),
    /// Envelopes served in place of stored ones (submitted signature order, txfix.zig).
    tx_fix: txfix.Table = .{},
    /// Loaded runtime object lists served in place of stored aux records (txfix.zig, second use;
    /// node/history.zig reads it, node/reconcile.zig installs). Memory only, like `tx_fix`: the
    /// node's own log reinstalls it at start. Empty unless a repair happened.
    list_fix: txfix.Table = .{},
    /// Certified summaries served in place of stored ones (txfix.zig, third use): a checkpoint
    /// an edge took from another source than its core holds that source's quorum certificate,
    /// valid but other bytes than the core's (docs/EDGE.md 10.3), and the edge installs the
    /// core's here once it has fetched and verified it (node/edge_certs.zig). Keyed by
    /// `certFixKey(seq)`; the caller has checked that the bytes are the stored CheckpointSummary
    /// with another certificate. Memory only, like `tx_fix`: the node's own log reinstalls it at
    /// start. Empty on every node that is not such an edge.
    cert_fix: txfix.Table = .{},
    /// Checksum of the newest commit record (the chain anchor for the next group).
    last_commit: ?u64 = null,
    /// Highest committed checkpoint some meta ever recorded (never written lower).
    meta_committed: ?u64 = null,
    since_flush: u64 = 0,
    meta_gen: u64 = 0,
    /// Files the newest meta no longer names but the other slot may (an old live table, runs
    /// of segments that aged): removed once a meta of a later generation is durable, so a
    /// fallback to the older slot never finds them gone and rebuilds (the usual rule: free
    /// blocks only after the next checkpoint). Under the meta lock.
    pending_frees: std.ArrayList(PendingFree) = .empty,
    /// Slot holding the newest meta copy (the next write goes to the other one), and that
    /// copy's checksum (the next write's parent).
    meta_slot: u64 = 0,
    meta_sum: u64 = 0,
    meta_fd: Fd = 0,
    meta_open: bool = false,
    /// Set after a failed write: the in-memory state may be ahead of the disk; reopen.
    poisoned: bool = false,
    /// A read that failed with an I/O error (not a bad checksum) while recovery was judging
    /// what is durable. Recovery then fails with it instead of taking the unreadable bytes for
    /// a torn tail (truncating acknowledged groups), a damaged log (error.Corrupt) or an older
    /// meta slot.
    scan_err: ?Error = null,

    batch: Batch = undefined,
    batch_active: bool = false,
    buf: []align(block) u8,
    bmap: BatchMap,
    /// Compact live records superseded in the open batch (id, location): their link records are
    /// written at commit unless an xref of the batch already names the record (`xref_targets`),
    /// so a node writing xrefs for its inputs pays for one cross-reference, not two.
    pend_links: std.ArrayList(PendLink) = .empty,
    xref_targets: std.AutoHashMapUnmanaged(u64, void) = .empty,

    rcu: rcu_mod.Rcu(Retired) = .{},
    /// Decoded chunks evicted from the cache are freed once no snapshot that got them is live
    /// (cache.zig: per-item reader epochs, not a grace period over all readers, so one
    /// long-lived snapshot pins only what it read). Snapshots register in `creaders`; any thread
    /// reclaims, under `chunk_lock`: `chunk_view`, `chunk_take` and `chunk_kept` are its state.
    creaders: cache_mod.Readers = .{},
    chunk_lock: cache_mod.Spin = .{},
    chunk_view: cache_mod.Readers.View = .{},
    chunk_take: std.ArrayList(*cache_mod.Item) = .empty,
    /// Evicted chunks a live snapshot may still hold, each with the oldest such reader epoch.
    chunk_kept: std.ArrayList(Kept) = .empty,
    chunk_kept_n: std.atomic.Value(u64) = .init(0),
    chunk_kept_bytes: std.atomic.Value(u64) = .init(0),
    stats: Stats = .{},
    /// Decoded chunks of compressed segments.
    cache: cache_mod.Cache,
    cseg_ids: u64 = 0,
    /// ZUI_DST_DEBUG: age-out prints its batches and punches (reproducing a store-dst seed).
    age_debug: bool = false,
    /// Writer scratch: the physical image of a compressed group, its directory entries, and
    /// logical group bytes read back from compressed segments (recovery, cleaning).
    pbuf: std.ArrayList(u8) = .empty,
    pents: std.ArrayList(chunk.Entry) = .empty,
    enc: chunk.Encoder = .{ .threads = 0 },
    /// History dictionaries (writer): the most recent committed bytes (at most 2 x
    /// `dict_bytes`), bytes committed since the current dictionary, and that dictionary.
    hist: std.ArrayList(u8) = .empty,
    hist_since: u64 = 0,
    wdict: ?HeldDict = null,
    gbuf: std.ArrayList(u8) = .empty,
    /// Commit durations (ns), newest at `commit_lat_n - 1` (ring): `commitLatency`.
    commit_lat: [commit_lat_len]std.atomic.Value(u32) = @splat(.init(0)),
    commit_lat_n: std.atomic.Value(u64) = .init(0),
    commit_lat_max: std.atomic.Value(u64) = .init(0),
    /// Commits that took longer than 100 ms since open.
    commit_slow: std.atomic.Value(u64) = .init(0),

    /// The running live-index flush (writer-owned pointer), its thread, and the lock every meta
    /// write takes (the writer's and the flusher's).
    flush: ?*FlushJob = null,
    /// Dirty pages after the previous commit (pacing: pages a commit added).
    pace_prev_dirty: u64 = 0,
    flush_thread: ?std.Thread = null,
    meta_lock: std.atomic.Value(u32) = .init(0),

    /// Age-out: its state and lock (the ager thread or `ageStep`; the writer takes it to delete
    /// a segment, after raising `age_yield` so a running step ends at the next group).
    ager: Ager = .{},
    age_mu: cache_mod.Spin = .{},
    /// Held by whoever runs steps (the ager thread, or `ageStep`'s caller) around each step and
    /// around what it reads of the ager's cursors outside `age_mu` (`ageGate`). The writer
    /// never takes it.
    age_run: cache_mod.Spin = .{},
    age_thread: ?std.Thread = null,
    age_stop: std.atomic.Value(bool) = .init(false),
    /// Tests: the ager counts its stop checks down from here and stops at zero, so a stop can
    /// be put at every point where one can take effect (`ageStopping`).
    age_stop_at: ?u64 = null,
    /// Readers that need old versions kept (agePause): age-out runs while it is 0.
    age_pause: std.atomic.Value(u32) = .init(0),
    age_yield: std.atomic.Value(bool) = .init(false),
    age_stats: AgeStats = .{},
    /// Deferral (`AgeMode`): the mode, whether the node is far behind the tip (`ageBehind`), and
    /// whether a bulk catch-up is running (ager only).
    age_mode: AgeMode = .on,
    age_behind: std.atomic.Value(bool) = .init(false),
    age_bulk: bool = false,
    /// Floors and the aged floor as of the newest durable meta (`noteDurableFloors`).
    dfloors: struct {
        cp: std.atomic.Value(u64) = .init(0),
        obj: std.atomic.Value(u64) = .init(0),
        obj_epoch: std.atomic.Value(u64) = .init(0),
        oldest: std.atomic.Value(u64) = .init(0),
    } = .{},

    // ------------------------------------------------------------------ open / close

    pub fn open(gpa: std.mem.Allocator, backend: Backend, cfg: *const Config) Error!*Store {
        const s = try create(gpa, backend, cfg);
        s.recover() catch |e| {
            s.releaseAll();
            return e;
        };
        return s;
    }

    fn create(gpa: std.mem.Allocator, backend: Backend, cfg: *const Config) Error!*Store {
        std.debug.assert(std.math.isPowerOfTwo(cfg.max_segments));
        const s = try gpa.create(Store);
        errdefer gpa.destroy(s);
        const buf = try gpa.alignedAlloc(u8, .fromByteUnits(block), std.mem.alignForward(usize, cfg.max_batch_bytes, block));
        errdefer gpa.free(buf);
        const segs = try gpa.alloc(SegSlot, cfg.max_segments);
        errdefer gpa.free(segs);
        @memset(segs, .{});
        const ring = try gpa.alloc(std.atomic.Value(u64), cfg.max_segments);
        errdefer gpa.free(ring);
        @memset(ring, .init(no_epoch));
        var bmap = try BatchMap.init(gpa, cfg.max_batch_objects);
        errdefer bmap.deinit(gpa);
        s.* = .{
            .gpa = gpa,
            .backend = backend,
            .cfg = cfg.*,
            .seed = 0,
            .segs = segs,
            .seg_mask = cfg.max_segments - 1,
            .ep_ring = ring,
            .buf = buf,
            .bmap = bmap,
            .cache = .init(gpa, cfg.cache_bytes),
            .age_debug = backend == .sim and std.c.getenv("ZUI_DST_DEBUG") != null,
        };
        s.cfg.dir = "";
        s.tx_fix = .{ .gpa = gpa, .readers = &s.creaders };
        s.list_fix = .{ .gpa = gpa, .readers = &s.creaders };
        s.cert_fix = .{ .gpa = gpa, .readers = &s.creaders };
        if (cfg.uaf_guard orelse (uaf_guard.default_on or uaf_guard.fromEnv())) {
            s.cache.mem = uaf_guard.allocator;
            switch (backend) {
                .real => |r| r.guard = true,
                else => {},
            }
        }
        return s;
    }

    /// The use-after-release guard is on (guard.zig).
    pub fn uafGuard(s: *const Store) bool {
        return s.cache.mem.vtable == uaf_guard.allocator.vtable;
    }

    fn reclaim(s: *Store, it: Retired) void {
        switch (it) {
            .view => |v| {
                s.backend.unmap(v.fd, v.view);
                if (v.close) s.backend.closeFile(v.fd);
            },
            .run => |r| {
                if (r.filter_mem) |fm| s.gpa.free(fm);
                s.backend.unmap(r.fd, r.view);
                s.backend.closeFile(r.fd);
                s.gpa.destroy(r);
            },
            .mem => |m| {
                m.reset();
                s.mem_pool.append(s.gpa, m) catch m.deinit(s.gpa);
            },
            .live => |h| {
                s.backend.unmapRw(h.fd, h.view);
                s.backend.closeFile(h.fd);
                h.t.deinit(s.gpa);
                s.gpa.destroy(h);
            },
            .chunk => |ci| s.cache.free(ci),
            .dir => |d| d.destroy(s.gpa),
            .aged => |a| s.ageReclaim(a),
            .cseg => |c| {
                s.backend.closeFile(c.fd);
                if (c.dir_fd) |f| s.backend.closeFile(f);
                if (c.side_fd) |f| s.backend.closeFile(f);
                if (c.age_fd) |f| s.backend.closeFile(f);
                if (c.zd_fd) |f| s.backend.closeFile(f);
                c.dicts.destroy(s.gpa);
                c.dir.raw.destroy(s.gpa);
                s.gpa.destroy(c);
            },
        }
    }

    fn rcuPoll(s: *Store) void {
        s.ageHandoff();
        s.chunkReclaim();
        s.rcu.poll(s, reclaim);
        s.tx_fix.collect();
        s.list_fix.collect();
        s.cert_fix.collect();
    }

    /// Drops the transaction fixes (txfix.zig) of checkpoints below `floor`, no longer served.
    fn dropFixesBelow(s: *Store, floor: u64) void {
        if (s.cert_fix.count() > 0) {
            if (s.cert_fix.dropBelow(floor)) |n| {
                if (n > 0) std.log.info("certificate fixes: dropped {d} below checkpoint {d}", .{ n, floor });
            } else |_| {} // memory only: retried at the next prune
        }
        if (s.list_fix.count() > 0) {
            if (s.list_fix.dropBelow(floor)) |n| {
                if (n > 0) std.log.info("loaded list fixes: dropped {d} below checkpoint {d}", .{ n, floor });
            } else |_| {} // memory only: retried at the next prune
        }
        if (s.tx_fix.count() == 0) return;
        const n = s.tx_fix.dropBelow(floor) catch return; // memory only: retried at the next prune
        if (n > 0) std.log.info("transaction fixes: dropped {d} below checkpoint {d}", .{ n, floor });
    }

    const Kept = struct { it: *cache_mod.Item, holder: u64 };

    /// Any thread: frees the cache's evicted chunks that no live snapshot got, and keeps the
    /// others until their readers are gone. Never blocks (skips when another thread is at it).
    /// Safe inside a snapshot too: chunks the caller got carry its epoch, so they are kept.
    fn chunkReclaim(s: *Store) void {
        if (!s.chunk_lock.tryLock()) return;
        defer s.chunk_lock.unlock();
        // Take, then view: a reader missing from the view registered after the items left
        // the cache, so it cannot have them.
        s.cache.takeEvicted(&s.chunk_take);
        if (s.chunk_take.items.len == 0 and s.chunk_kept.items.len == 0) return;
        const v = &s.chunk_view;
        s.creaders.view(v);
        const st = &s.cache.stats;
        var kept_bytes = s.chunk_kept_bytes.load(.monotonic);
        if (v.gone_n > 0 or v.gone_over) {
            // Only items whose oldest reader left can have become free.
            var w: usize = 0;
            for (s.chunk_kept.items) |k| {
                if (!v.isGone(k.holder)) {
                    s.chunk_kept.items[w] = k;
                    w += 1;
                } else if (v.holder(k.it.lo, k.it.hi)) |h| {
                    s.chunk_kept.items[w] = .{ .it = k.it, .holder = h };
                    w += 1;
                } else {
                    kept_bytes -= k.it.data.len;
                    s.cache.free(k.it);
                    _ = st.freed.fetchAdd(1, .monotonic);
                }
            }
            s.chunk_kept.shrinkRetainingCapacity(w);
        }
        for (s.chunk_take.items) |it| {
            if (v.holder(it.lo, it.hi)) |h| {
                s.chunk_kept.append(s.gpa, .{ .it = it, .holder = h }) catch continue; // leak rather than free under a reader
                kept_bytes += it.data.len;
                _ = st.pinned.fetchAdd(1, .monotonic);
            } else {
                s.cache.free(it);
                _ = st.freed.fetchAdd(1, .monotonic);
            }
        }
        s.chunk_take.clearRetainingCapacity();
        s.chunk_kept_n.store(s.chunk_kept.items.len, .monotonic);
        s.chunk_kept_bytes.store(kept_bytes, .monotonic);
    }

    /// Decoded-chunk memory (metrics): the cache, chunks evicted but not taken yet, chunks a
    /// live snapshot may hold, and live snapshots.
    pub fn chunkMemory(s: *Store) struct { cached_bytes: u64, evicted_bytes: u64, kept: u64, kept_bytes: u64, readers: u64 } {
        return .{
            .cached_bytes = s.cache.bytes(),
            .evicted_bytes = s.cache.evicted_bytes.load(.monotonic),
            .kept = s.chunk_kept_n.load(.monotonic),
            .kept_bytes = s.chunk_kept_bytes.load(.monotonic),
            .readers = s.creaders.live(),
        };
    }

    fn retire(s: *Store, it: Retired) void {
        s.rcu.retire(s.gpa, it) catch {
            // Out of memory for the list: leak the object rather than free it under a reader.
        };
    }

    /// Releases every file, mapping and buffer (no I/O beyond unmap/close; no readers allowed).
    fn releaseAll(s: *Store) void {
        const gpa = s.gpa;
        s.pending_frees.deinit(gpa);
        s.tx_fix.deinit();
        s.list_fix.deinit();
        s.cert_fix.deinit();
        s.stopAger();
        s.ager.batch_c = null;
        s.ageHandoffLocked();
        // A running flush is abandoned (its writes are covered by the journal protocol).
        if (s.flush) |job| {
            if (s.flush_thread) |th| th.join();
            s.flush_thread = null;
            s.freeFlush(job);
        }
        s.rcu.drainAll(s, reclaim);
        for (s.segs) |*slot| {
            if (slot.epoch.load(.monotonic) == no_epoch) continue;
            s.unpublishSlot(slot, false);
        }
        s.rcu.drainAll(s, reclaim);
        if (s.liveOrNull()) |h| s.reclaim(.{ .live = h });
        if (s.memOrNull()) |m| m.deinit(gpa);
        for (s.mem_pool.items) |m| m.deinit(gpa);
        s.mem_pool.deinit(gpa);
        if (s.jnl_fd) |f| s.backend.closeFile(f);
        if (s.meta_open) s.backend.closeFile(s.meta_fd);
        s.rcu.deinit(gpa);
        for (s.chunk_kept.items) |k| s.cache.free(k.it);
        s.chunk_kept.deinit(gpa);
        s.chunk_take.deinit(gpa);
        s.cache.deinit();
        s.pbuf.deinit(gpa);
        s.pents.deinit(gpa);
        s.enc.deinit(gpa);
        if (s.wdict) |d| zstd_c.freeCDict(d.cdict);
        s.hist.deinit(gpa);
        s.gbuf.deinit(gpa);
        s.bmap.deinit(gpa);
        s.pend_links.deinit(gpa);
        s.xref_targets.deinit(gpa);
        s.aged.deinit(gpa);
        s.ager.deinit(gpa);
        gpa.free(s.clean.counts);
        gpa.free(s.buf);
        gpa.free(s.segs);
        gpa.free(s.ep_ring);
        gpa.destroy(s);
    }

    fn liveOrNull(s: *Store) ?*LiveHandle {
        return s.live.raw;
    }

    fn memOrNull(s: *Store) ?*table.Mem {
        return s.mem.raw;
    }

    fn curMem(s: *Store) *table.Mem {
        return s.mem.raw.?;
    }

    /// Frees memory and descriptors without writing anything (also what a crashed simulation
    /// does). Use `close` for a clean shutdown.
    pub fn deinit(s: *Store) void {
        s.bulkLiveAbort();
        s.releaseAll();
    }

    /// Clean shutdown: seal the memtable and flush the live index, so the next open replays
    /// nothing.
    pub fn close(s: *Store) Error!void {
        s.stopAger();
        if (!s.poisoned) s.closeFlush() catch |e| {
            s.deinit();
            return e;
        };
        s.deinit();
    }

    fn closeFlush(s: *Store) Error!void {
        for (s.segs) |*slot| if (slot.epoch.load(.monotonic) != no_epoch) if (slot.comp.raw) |c| try s.dirPersist(slot.epoch.raw, c, true);
        if (s.has_segment) {

            const slot = s.slotOf(s.cur_epoch).?;
            if (slot.nruns.load(.monotonic) + 1 < max_runs) {
                const end = format.loc(s.cur_epoch, s.tail);
                if (try s.sealMem(end, s.last_commit)) try s.swapMem(no_epoch, end, s.last_commit);
            }
        }
        try s.flushLive();
        // The in-place pages synced; the journal is kept (an open re-applies the same pages).
        // Truncating it here (fast-start) broke store-dst seed 550 on main's flush: recovery
        // then found a durable group after a damaged one (Corrupt). persistLive still retires it.
        if (s.live.raw) |h| if (s.live_unsynced) {
            try s.backend.sync(h.fd);
            s.live_unsynced = false;
        };
        // The table file now equals the table: say so, so the next open skips the page check
        // (51.6 s cold on a 34 GB table under MADV_RANDOM).
        if (s.live.raw) |h| {
            var m = s.metaAt(h, s.tailLoc(), s.last_commit);
            m.flags |= meta_clean;
            try s.writeMeta(&m);
        }
    }

    /// Makes the live table durable in its file and empties the journal (the end of a restore:
    /// a later start, clean or not, maps the table without replaying anything).
    pub fn persistLive(s: *Store) Error!void {
        try s.flushLive();
        try s.retireJournal();
    }

    /// After a flush: syncs the in-place pages and empties the journal, so the next open applies
    /// nothing (a clean close; the end of a restore). A crash between the two re-applies the same
    /// pages, which is harmless.
    fn retireJournal(s: *Store) Error!void {
        const h = s.live.raw orelse return;
        if (s.live_unsynced) {
            try s.backend.sync(h.fd);
            s.live_unsynced = false;
        }
        if (s.jnl_fd) |jfd| {
            if ((try s.backend.size(jfd)) > 0) {
                try s.backend.truncate(jfd, 0);
                try s.backend.sync(jfd);
            }
        }
    }

    fn lt(s: *Store) *table.LiveTable {
        return &s.live.raw.?.t;
    }

    fn viewOf(slot: *const SegSlot) []const u8 {
        const p: [*]const u8 = @ptrFromInt(slot.base.load(.acquire));
        return p[0..slot.view_len];
    }

    fn readMeta(s: *Store) ?Meta {
        var best: ?Meta = null;
        var best_i: u64 = 0;
        var metas: [2]?Meta = .{ null, null };
        var chains: [2]?MetaChain = .{ null, null };
        for (0..2) |i| {
            var m: Meta = undefined;
            s.backend.read(s.meta_fd, i * block, std.mem.asBytes(&m)) catch |err| {
                // A slot never written reads short; any other failure leaves the slot unknown.
                if (err != error.ShortRead) s.scan_err = err;
                continue;
            };
            if (!m.valid()) continue;
            // A legacy meta has no key: whatever followed its 128 bytes in the page is not one.
            if (m.legacy()) m.live_key = @splat(0);
            var c: MetaChain = undefined;
            s.backend.read(s.meta_fd, i * block + MetaChain.offset, std.mem.asBytes(&c)) catch |err| {
                if (err != error.ShortRead) s.scan_err = err;
                continue;
            };
            if (std.mem.allEqual(u8, std.mem.asBytes(&c), 0)) {
                // Written before chains existed.
            } else if (!std.mem.eql(u8, &c.magic, "ZUICHAN1") or c.sum() != c.checksum or
                c.generation != m.generation or c.meta_sum != m.checksum)
            {
                // The meta sector of a write whose chain sector did not land: torn, never
                // acknowledged.
                continue;
            } else chains[i] = c;
            metas[i] = m;
            if (best == null or m.generation > best.?.generation) {
                best = m;
                best_i = i;
            }
        }
        if (best) |m| {
            s.meta_slot = best_i;
            s.meta_sum = m.checksum;
            if (chains[best_i]) |c| {
                if (c.slot != best_i) s.stats.meta_misdirected += 1;
                if (metas[1 - best_i]) |o| if (o.generation < m.generation) {
                    // The other slot must be the parent or older (a lost or misdirected write
                    // left it stale); a copy between the parent and the newest, or the parent's
                    // generation with other contents, is another history: refuse.
                    if (o.generation > c.parent_gen or (o.generation == c.parent_gen and o.checksum != c.parent)) {
                        s.scan_err = s.scan_err orelse error.Corrupt;
                        return null;
                    }
                    if (o.generation < c.parent_gen) s.stats.meta_stale += 1;
                };
            }
        }
        if (best) |m| {
            // The newest meta's floors block is another sector of its page and may be torn
            // when the meta sector is not. The floors only rise, so the other slot's (older)
            // block is then the right floor; with none the store claimed checkpoints and
            // versions age-out had freed under the previous floors (store-dst age/291
            // "checkpoint missing", age/55 "objectAt missing").
            const f = s.readFloors(best_i, m.generation, true) orelse s.readFloors(1 - best_i, m.generation, false);
            if (f) |x| {
                s.cp_floor.store(x.cp_floor, .release);
                s.obj_floor.store(x.obj_floor, .release);
                s.obj_floor_epoch.store(x.obj_floor_epoch, .release);
                s.noteDurableFloors(x.cp_floor, x.obj_floor, x.obj_floor_epoch, m.oldest_epoch);
            }
        }
        return best;
    }

    /// Slot `i`'s floors block when intact: of generation `gen` (`exact`) or older.
    fn readFloors(s: *Store, i: u64, gen: u64, exact: bool) ?MetaFloors {
        var f: MetaFloors = undefined;
        s.backend.read(s.meta_fd, i * block + MetaFloors.offset, std.mem.asBytes(&f)) catch return null;
        if (!std.mem.eql(u8, &f.magic, "ZUIFLOR1") or f.sum() != f.checksum) return null;
        if (if (exact) f.generation != gen else f.generation >= gen) return null;
        return f;
    }

    /// The floors some meta on disk holds: age-out frees only below them, so a crash that brings
    /// back an older meta never finds a hole above its floors.
    fn noteDurableFloors(s: *Store, cp: u64, obj: u64, obj_epoch: u64, oldest: u64) void {
        const d = &s.dfloors;
        if (cp > d.cp.load(.monotonic)) d.cp.store(cp, .release);
        if (obj > d.obj.load(.monotonic)) d.obj.store(obj, .release);
        if (obj_epoch > d.obj_epoch.load(.monotonic)) d.obj_epoch.store(obj_epoch, .release);
        if (oldest > d.oldest.load(.monotonic)) d.oldest.store(oldest, .release);
    }

    const PendingFree = struct { name: [64]u8, len: u8, gen: u64 };

    /// Removes `name` after the next durable meta (see `pending_frees`).
    fn deferFree(s: *Store, name: []const u8) Error!void {
        s.lockMeta();
        defer s.unlockMeta();
        var p: PendingFree = .{ .name = undefined, .len = @intCast(name.len), .gen = s.meta_gen };
        @memcpy(p.name[0..name.len], name);
        s.pending_frees.append(s.gpa, p) catch return error.OutOfMemory;
    }

    fn lockMeta(s: *Store) void {
        while (s.meta_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }

    fn unlockMeta(s: *Store) void {
        s.meta_lock.store(0, .release);
    }

    fn writeMeta(s: *Store, m: *Meta) Error!void {
        s.lockMeta();
        defer s.unlockMeta();
        return s.writeMetaLocked(m, false);
    }

    /// `plain`: write then sync (the flusher thread must not use the writer's io_uring).
    fn writeMetaLocked(s: *Store, m: *Meta, plain: bool) Error!void {
        s.meta_gen += 1;
        m.generation = s.meta_gen;
        m.checksum = m.sum();
        var page: [block]u8 align(8) = @splat(0);
        @memcpy(page[0..@sizeOf(Meta)], std.mem.asBytes(m));
        var f: MetaFloors = .{
            .generation = m.generation,
            .cp_floor = s.cp_floor.load(.monotonic),
            .obj_floor = s.obj_floor.load(.monotonic),
            .obj_floor_epoch = s.obj_floor_epoch.load(.monotonic),
        };
        f.checksum = f.sum();
        @memcpy(page[MetaFloors.offset..][0..@sizeOf(MetaFloors)], std.mem.asBytes(&f));
        // Never over the newest copy: a torn write then leaves it to fall back to.
        const slot = 1 - s.meta_slot;
        var c: MetaChain = .{ .generation = m.generation, .meta_sum = m.checksum, .slot = slot, .parent = s.meta_sum, .parent_gen = m.generation - 1 };
        c.checksum = c.sum();
        @memcpy(page[MetaChain.offset..][0..@sizeOf(MetaChain)], std.mem.asBytes(&c));
        if (plain) {
            try s.backend.write(s.meta_fd, slot * block, &page);
            try s.backend.sync(s.meta_fd);
        } else try s.backend.writeSync(s.meta_fd, slot * block, &page);
        s.meta_slot = slot;
        s.meta_sum = m.checksum;
        if (m.has_committed != 0) s.meta_committed = m.committed;
        s.noteDurableFloors(f.cp_floor, f.obj_floor, f.obj_floor_epoch, m.oldest_epoch);
        // This write replaced the other slot: neither slot names files freed before it now.
        var i: usize = 0;
        while (i < s.pending_frees.items.len) {
            const pf = s.pending_frees.items[i];
            if (pf.gen >= m.generation) {
                i += 1;
                continue;
            }
            s.backend.remove(pf.name[0..pf.len]) catch |err| if (err == error.Crashed) return err;
            _ = s.pending_frees.swapRemove(i);
        }
    }

    /// Meta naming the live table as covering the log up to `applied` (anchor: the commit
    /// checksum just before it).
    fn metaAt(s: *Store, h: *const LiveHandle, applied: u64, anchor: ?u64) Meta {
        const c1 = s.committed1.load(.monotonic);
        var has = c1 != 0;
        var cseq: u64 = if (c1 == 0) 0 else c1 - 1;
        if (s.meta_committed) |mc| if (!has or mc > cseq) {
            has = true;
            cseq = mc;
        };
        return .{
            .seed = s.seed,
            .has_committed = @intFromBool(has),
            .committed = cseq,
            .oldest_epoch = s.oldest_epoch.load(.monotonic),
            .live_tg = h.tg,
            .live_pages = h.t.pages.len,
            .live_gen = s.live_gen,
            .live_applied = applied,
            .live_has_anchor = @intFromBool(anchor != null),
            .live_anchor = anchor orelse 0,
            .live_count = h.t.count,
            .live_live = h.t.live,
            .live_key = h.t.secret,
            .flags = if (h.sealed) meta_sealed else 0,
        };
    }

    fn tailLoc(s: *const Store) u64 {
        return if (s.has_segment) format.loc(s.cur_epoch, s.tail) else 0;
    }

    /// Random-access advice for a mapping of a real file (io.adviseRandom); none in simulation.
    fn adviseRandom(s: *const Store, view: []const u8) void {
        if (s.backend == .real) io_mod.adviseRandom(view);
    }

    /// Copies a run's key filters out of its mapping (Config.run_filters_resident). Out of
    /// memory leaves them in the mapping. Before the run is published. `ZUI_STORE_FILTERS=0`
    /// (read once) drops them instead, for A/B timing: every lookup then probes every run.
    fn pinFilters(s: *Store, run: *table.Run) void {
        if (!filtersOn()) {
            run.ver_filter = null;
            run.tx_filter = null;
            return;
        }
        if (!s.cfg.run_filters_resident) return;
        const src = run.filterBytes();
        if (src.len == 0) return;
        const mem = s.gpa.alignedAlloc(u8, .fromByteUnits(64), src.len) catch return;
        @memcpy(mem, src);
        run.useFilterMem(mem);
    }

    /// Asynchronous read-ahead of a range about to be scanned sequentially.
    fn willNeed(s: *const Store, range: []const u8) void {
        if (s.backend == .real) io_mod.willNeed(range);
    }

    /// After recovery: every mapping the store reads at random gets random-access advice.
    fn adviseAll(s: *Store) void {
        if (s.backend != .real) return;
        for (s.segs) |*slot| {
            if (slot.epoch.load(.monotonic) == no_epoch) continue;
            if (slot.comp.load(.monotonic) == null and slot.base.load(.monotonic) != 0) io_mod.adviseRandom(viewOf(slot));
            const n = slot.nruns.load(.monotonic);
            for (slot.runs[0..n]) |*rp| if (rp.load(.monotonic)) |r| io_mod.adviseRandom(r.view);
        }
        if (s.liveOrNull()) |h| io_mod.adviseRandom(h.view);
    }

    fn slotOf(s: *const Store, e: u64) ?*SegSlot {
        const slot = &s.segs[e & s.seg_mask];
        if (slot.epoch.load(.seq_cst) != e) return null;
        return slot;
    }

    fn mapSegment(s: *Store, e: u64, new: bool) Error!void {
        const slot = &s.segs[e & s.seg_mask];
        if (slot.epoch.load(.monotonic) != no_epoch) return error.TooManySegments;
        var nb: [64]u8 = undefined;
        const fd = try s.backend.openFile(io_mod.segName(&nb, e), new);
        errdefer s.backend.closeFile(fd);
        if ((new and s.cfg.compress) or (!new and try s.isCompressedFile(fd))) {
            const c = if (new) try s.newCSeg(fd, e, 64) else try s.loadCSeg(e, fd);
            errdefer s.dropCSeg(c);
            if (new) {
                try s.backend.truncate(fd, 0);
                var nb2: [64]u8 = undefined;
                if (s.backend.exists(zdName(&nb2, e))) try s.backend.remove(zdName(&nb2, e));
                if (s.backend.exists(dirName(&nb2, e))) try s.backend.remove(dirName(&nb2, e));
                if (s.backend.exists(sideName(&nb2, e))) try s.backend.remove(sideName(&nb2, e));
                if (s.backend.exists(ageName(&nb2, e))) try s.backend.remove(ageName(&nb2, e));
            }
            slot.fd = fd;
            slot.view_len = 0;
            slot.nruns.store(0, .monotonic);
            slot.comp.store(c, .release);
            slot.base.store(0, .release);
            slot.end.store(0, .release);
            slot.epoch.store(e, .release);
            return;
        }

        const size = try s.backend.size(fd);
        const reserve = if (new) @max(s.cfg.segment_reserve, s.buf.len) else @max(size, 1);
        const v = try s.backend.map(fd, reserve);
        if (new) s.adviseRandom(v);
        slot.fd = fd;
        slot.view_len = v.len;
        slot.nruns.store(0, .monotonic);
        slot.base.store(@intFromPtr(v.ptr), .release);
        slot.end.store(0, .release);
        slot.epoch.store(e, .release);
    }

    /// Unpublishes a segment slot and its runs; `defer_free`: through the grace period.
    fn unpublishSlot(s: *Store, slot: *SegSlot, defer_free: bool) void {
        slot.epoch.store(no_epoch, .seq_cst);
        const n = slot.nruns.load(.monotonic);
        for (slot.runs[0..n]) |*rp| {
            if (rp.swap(null, .acq_rel)) |r| {
                if (defer_free) s.retire(.{ .run = r }) else s.reclaim(.{ .run = r });
            }
        }
        _ = s.runs_total.fetchSub(n, .acq_rel);
        slot.nruns.store(0, .release);
        const v: Retired = if (slot.comp.swap(null, .acq_rel)) |c| .{ .cseg = c } else .{ .view = .{ .fd = slot.fd, .view = viewOf(slot), .close = true } };
        if (defer_free) s.retire(v) else s.reclaim(v);
    }

    /// The segment file goes first, durably: a crash must never bring a segment back without
    /// the age log and sidecar its punched frames moved to (the leftovers are removed at open).
    fn removeEpochFiles(s: *Store, e: u64, nruns: u64) Error!void {
        var nb: [64]u8 = undefined;
        try s.backend.remove(io_mod.segName(&nb, e));
        try s.backend.syncDir();
        for (0..nruns) |r| try s.backend.remove(io_mod.runName(&nb, e, r));
        if (s.backend.exists(dirName(&nb, e))) try s.backend.remove(dirName(&nb, e));
        if (s.backend.exists(sideName(&nb, e))) try s.backend.remove(sideName(&nb, e));
        if (s.backend.exists(ageName(&nb, e))) try s.backend.remove(ageName(&nb, e));
        if (s.backend.exists(zdName(&nb, e))) try s.backend.remove(zdName(&nb, e));
    }

    // ------------------------------------------------------------------ compressed segments

    fn dirName(buf: []u8, e: u64) []const u8 {
        return std.fmt.bufPrint(buf, "index/{d:0>8}.dir", .{e}) catch unreachable;
    }

    fn sideName(buf: []u8, e: u64) []const u8 {
        return std.fmt.bufPrint(buf, "index/{d:0>8}.side", .{e}) catch unreachable;
    }

    /// Writer: the history dictionary to compress the next group of segment `e` with (codec 3),
    /// or null (dictionaries off, a bulk restore, too little history yet, or the dictionary file
    /// would not write). A new dictionary (the most recent `dict_bytes` of committed history) is
    /// appended to `index/<e>.zd` and synced before it is returned, so every frame naming it is
    /// written after its dictionary is durable. A new one is made for each segment and every
    /// `dict_refresh_bytes`; after a restart, until enough history is seen again, the segment's
    /// newest dictionary is reused.
    fn dictFor(s: *Store, c: *CSeg, e: u64) Error!?chunk.DictRef {
        if (!s.cfg.history_dicts or !s.cfg.elide_sums or s.bulk != null or !zstd_c.use()) return null;
        const cur = HeldDict.matches(s.wdict, c, null);
        if (cur != null and s.hist_since < s.cfg.dict_refresh_bytes) return cur;
        const min = @max(s.cfg.dict_bytes / 4, 4 << 10);
        if (s.hist.items.len < min or c.dicts.len() >= chunk.max_dicts) {
            if (cur != null) return cur;
            const n = c.dicts.len();
            if (n == 0) return null;
            return try s.holdWriterDict(c, @intCast(n));
        }
        const bytes = chunk.dictFrom(s.gpa, s.hist.items, s.cfg.dict_bytes) catch return error.OutOfMemory;
        var owned = true;
        defer if (owned) s.gpa.free(bytes);
        var rec: std.ArrayList(u8) = .empty;
        defer rec.deinit(s.gpa);
        const id: u32 = @intCast(c.dicts.len() + 1);
        if (c.zd_tail < chunk.dict_header_len) {
            rec.appendSlice(s.gpa, &chunk.dictFileHeader(e, c.zd_seed)) catch return error.OutOfMemory;
            c.zd_tail = 0;
        }
        chunk.dictRecord(s.gpa, &rec, c.zd_seed, id, bytes) catch return error.OutOfMemory;
        // A failed write keeps the old dictionary (or none); a later group tries again at the
        // same place. Only a simulated crash stops the commit.
        write: {
            var nb: [64]u8 = undefined;
            if (c.zd_fd == null) {
                c.zd_named = c.zd_named and s.backend.exists(zdName(&nb, e));
                c.zd_fd = s.backend.openFile(zdName(&nb, e), true) catch |err| {
                    if (err == error.Crashed) return err;
                    break :write;
                };
            }
            const f = c.zd_fd.?;
            if (c.zd_tail == 0) s.backend.truncate(f, 0) catch |err| {
                if (err == error.Crashed) return err;
                break :write;
            };
            s.backend.writeSync(f, c.zd_tail, rec.items) catch |err| {
                if (err == error.Crashed) return err;
                break :write;
            };
            // Until a directory sync succeeds after the file was created (a failed one is retried
            // by the next dictionary), the file may vanish in a crash with frames naming it.
            if (!c.zd_named) {
                s.backend.syncDir() catch |err| {
                    if (err == error.Crashed) return err;
                    break :write;
                };
                c.zd_named = true;
            }
            c.zd_tail += rec.items.len;
            owned = false;
            _ = c.dicts.push(s.gpa, bytes) catch unreachable; // id < max_dicts (checked above)
            s.hist_since = 0;
            return try s.holdWriterDict(c, id);
        }
        s.hist_since = 0; // retry after another refresh interval
        return cur;
    }

    fn holdWriterDict(s: *Store, c: *CSeg, id: u32) Error!chunk.DictRef {
        const cd = zstd_c.createCDict(c.dicts.get(id).?, zstd_c.level) catch return error.OutOfMemory;
        if (s.wdict) |old| zstd_c.freeCDict(old.cdict);
        s.wdict = .{ .cid = c.id, .epoch = c.epoch, .id = id, .cdict = cd };
        return .{ .id = id, .cdict = cd };
    }

    /// Writer, after a group of a compressed segment is durable: its records join the history
    /// the next dictionary is cut from.
    fn histFeed(s: *Store, g: []const u8) void {
        if (!s.cfg.history_dicts or s.bulk != null) return;
        const cap: usize = s.cfg.dict_bytes;
        const recs = std.mem.trimEnd(u8, g, &.{0});
        const take = recs[recs.len - @min(recs.len, cap) ..];
        if (s.hist.items.len + take.len > 2 * cap) {
            const keep = cap - take.len;
            const h = s.hist.items;
            std.mem.copyForwards(u8, h[0..keep], h[h.len - keep ..]);
            s.hist.shrinkRetainingCapacity(keep);
        }
        s.hist.appendSlice(s.gpa, take) catch {
            s.hist.clearRetainingCapacity();
            return;
        };
        s.hist_since += recs.len;
    }

    /// Ager: the dictionary to rewrite chunks of `c` with (its newest; null without one).
    fn ageDict(s: *Store, c: *CSeg) Error!?chunk.DictRef {
        if (!s.cfg.history_dicts or !s.cfg.elide_sums or !zstd_c.use()) return null;
        const n = c.dicts.len();
        if (n == 0) return null;
        const a = &s.ager;
        if (HeldDict.matches(a.dict, c, @intCast(n))) |d| return d;
        const cd = zstd_c.createCDict(c.dicts.get(@intCast(n)).?, zstd_c.level) catch return error.OutOfMemory;
        if (a.dict) |old| zstd_c.freeCDict(old.cdict);
        a.dict = .{ .cid = c.id, .epoch = c.epoch, .id = @intCast(n), .cdict = cd };
        return .{ .id = @intCast(n), .cdict = cd };
    }

    fn zdName(buf: []u8, e: u64) []const u8 {
        return std.fmt.bufPrint(buf, "index/{d:0>8}.zd", .{e}) catch unreachable;
    }

    fn ageName(buf: []u8, e: u64) []const u8 {
        return std.fmt.bufPrint(buf, "index/{d:0>8}.age", .{e}) catch unreachable;
    }

    fn newCSeg(s: *Store, fd: Fd, e: u64, cap: usize) Error!*CSeg {
        const d = chunk.Dir.create(s.gpa, cap) catch return error.OutOfMemory;
        errdefer d.destroy(s.gpa);
        const zd = chunk.Dicts.create(s.gpa) catch return error.OutOfMemory;
        errdefer zd.destroy(s.gpa);
        const c = s.gpa.create(CSeg) catch return error.OutOfMemory;
        s.cseg_ids += 1;
        c.* = .{ .fd = fd, .id = s.cseg_ids & ((1 << 20) - 1), .epoch = e, .dir = .init(d), .dir_seed = s.seed ^ 0x636469, .dicts = zd, .zd_seed = s.seed ^ 0x7a6473 ^ (e *% 0x9e3779b97f4a7c15) };
        return c;
    }

    /// Frees a CSeg that was never published (an open that failed after `newCSeg`).
    fn dropCSeg(s: *Store, c: *CSeg) void {
        if (c.zd_fd) |f| s.backend.closeFile(f);
        c.dicts.destroy(s.gpa);
        c.dir.raw.destroy(s.gpa);
        s.gpa.destroy(c);
    }

    fn isCompressedFile(s: *Store, fd: Fd) Error!bool {
        if ((try s.backend.size(fd)) < 8) return false;
        var m: [8]u8 = undefined;
        try s.backend.read(fd, 0, &m);
        return std.mem.eql(u8, &m, chunk.file_magic);
    }

    /// Opens a compressed segment: the trusted prefix of its dir file, then a walk over the
    /// frames after it (every frame checked) up to the first one that does not check.
    fn loadCSeg(s: *Store, e: u64, fd: Fd) Error!*CSeg {
        const size = try s.backend.size(fd);
        var ents: std.ArrayList(chunk.Entry) = .empty;
        defer ents.deinit(s.gpa);
        var hdr: chunk.FileHeader = undefined;
        try s.backend.read(fd, 0, std.mem.asBytes(&hdr));
        const header_ok = hdr.sum() == hdr.checksum and hdr.epoch == e and hdr.algo == cs.current_algo;
        var nb: [64]u8 = undefined;
        const dname = dirName(&nb, e);
        var trusted: usize = 0;
        var dir_fd: ?Fd = null;
        var dir_seed: u64 = 0;
        errdefer if (dir_fd) |f| s.backend.closeFile(f);
        if (header_ok and s.backend.exists(dname)) {
            const dfd = try s.backend.openFile(dname, false);
            var keep = false;
            defer if (!keep) s.backend.closeFile(dfd);
            const dsize = try s.backend.size(dfd);
            const img = s.gpa.alloc(u8, dsize) catch return error.OutOfMemory;
            defer s.gpa.free(img);
            try s.backend.read(dfd, 0, img);
            if (chunk.trustedPrefix(img, e, size, &ents, s.gpa) catch return error.OutOfMemory) |seed| {
                // Keep appending to it (cut after the trusted prefix at the next write).
                keep = true;
                dir_fd = dfd;
                dir_seed = seed;
            }
            trusted = ents.items.len;
        }
        // A damaged file header hides the dir file from the index, not from the proof.
        const dir_proof: u64 = if (trusted > 0) ents.items[trusted - 1].end() else if (!header_ok) try s.dirProof(e, size) else 0;
        // Age-out's log: chunks rewritten into the sidecar, and pass marks.
        var arecs: std.ArrayList(chunk.AgeRec) = .empty;
        defer arecs.deinit(s.gpa);
        var age_fd: ?Fd = null;
        var age_seed: u64 = 0;
        errdefer if (age_fd) |f| s.backend.closeFile(f);
        var side_fd: ?Fd = null;
        var side_size: u64 = 0;
        errdefer if (side_fd) |f| s.backend.closeFile(f);
        var old_at: std.AutoHashMapUnmanaged(u64, usize) = .empty;
        defer old_at.deinit(s.gpa);
        if (header_ok and s.backend.exists(ageName(&nb, e))) {
            const afd = try s.backend.openFile(ageName(&nb, e), false);
            var keep = false;
            defer if (!keep) s.backend.closeFile(afd);
            const asize = try s.backend.size(afd);
            const img = s.gpa.alloc(u8, asize) catch return error.OutOfMemory;
            defer s.gpa.free(img);
            try s.backend.read(afd, 0, img);
            if (chunk.ageTrusted(img, e, &arecs, s.gpa) catch return error.OutOfMemory) |seed| {
                keep = true;
                age_fd = afd;
                age_seed = seed;
            }
            var any_side = false;
            for (arecs.items, 0..) |r, i| if (r.kind == 0) {
                any_side = true;
                if (!chunk.isSide(r.old_phys)) {
                    const g = old_at.getOrPut(s.gpa, r.old_phys) catch return error.OutOfMemory;
                    if (!g.found_existing) g.value_ptr.* = i;
                }
            };
            if (any_side) {
                // Every rewritten frame was synced before its record: a missing sidecar means
                // lost data (the frames it replaced may be punched).
                if (!s.backend.exists(sideName(&nb, e))) return error.Corrupt;
                side_fd = try s.backend.openFile(sideName(&nb, e), false);
                side_size = try s.backend.size(side_fd.?);
                for (arecs.items) |r| if (r.kind == 0 and (r.phys & ~chunk.side_bit) + chunk.frameSpan(r.bl) > side_size) return error.Corrupt;
            } else if (s.backend.exists(sideName(&nb, e))) {
                side_fd = try s.backend.openFile(sideName(&nb, e), false);
                side_size = try s.backend.size(side_fd.?);
            }
        }
        if (header_ok) {
            var p: u64 = if (ents.items.len == 0) chunk.file_header_len else ents.items[ents.items.len - 1].phys + ents.items[ents.items.len - 1].span();
            var want: u64 = if (ents.items.len == 0) 0 else ents.items[ents.items.len - 1].end();
            var fbuf: std.ArrayList(u8) = .empty;
            defer fbuf.deinit(s.gpa);
            outer: while (true) {
                // The next frame follows at once, or after a group's padding.
                const cands = [2]u64{ p, std.mem.alignForward(u64, p, block) };
                for (cands, 0..) |at, ci| {
                    if (ci == 1 and cands[1] == cands[0]) break;
                    if (at + chunk.frame_len > size) break;
                    var f: chunk.Frame = undefined;
                    try s.backend.read(fd, at, std.mem.asBytes(&f));
                    if (f.logical_start != want or f.logical_len == 0 or at + chunk.frameSpan(f.body_len) > size or f.body_len > s.cfg.max_batch_bytes * 2) continue;
                    fbuf.resize(s.gpa, chunk.frame_len + f.body_len) catch return error.OutOfMemory;
                    try s.backend.read(fd, at, fbuf.items);
                    const en = chunk.checkFrame(at, fbuf.items) catch continue;
                    ents.append(s.gpa, en) catch return error.OutOfMemory;
                    p = at + en.span();
                    want = en.end();
                    continue :outer;
                }
                // A frame age-out moved to the sidecar and punched: its age record says what
                // it held (the dir file lost those entries).
                for (cands) |at| if (old_at.get(at)) |i| {
                    const r = arecs.items[i];
                    if (r.ls != want) continue;
                    ents.append(s.gpa, .{ .ls = r.ls, .phys = at, .ll = r.ll, .bl = r.old_bl, .codec = 0 }) catch return error.OutOfMemory;
                    p = at + chunk.frameSpan(r.old_bl);
                    want = r.ls + r.ll;
                    continue :outer;
                };
                break;
            }
        }
        const c = try s.newCSeg(fd, e, ents.items.len * 2);
        errdefer s.dropCSeg(c);
        // History dictionaries: the dictionary file's trusted prefix (a frame naming any other
        // id is Corrupt; one is synced before the first frame that names it).
        if (header_ok and s.backend.exists(zdName(&nb, e))) {
            // Closed again: the writer reopens it (`dictFor`) only to append.
            const zfd = try s.backend.openFile(zdName(&nb, e), false);
            defer s.backend.closeFile(zfd);
            const zsize = try s.backend.size(zfd);
            const img = s.gpa.alloc(u8, zsize) catch return error.OutOfMemory;
            defer s.gpa.free(img);
            try s.backend.read(zfd, 0, img);
            c.zd_named = true;
            if (chunk.dictsTrusted(img, e, c.dicts, s.gpa) catch return error.OutOfMemory) |t| {
                c.zd_seed = t.seed;
                c.zd_tail = t.end;
            }
        }
        const d = c.dir.raw;
        @memcpy(d.entries[0..ents.items.len], ents.items);
        d.n.store(ents.items.len, .release);
        c.phys_tail = std.mem.alignForward(u64, d.physEnd(), block);
        c.dir_written = trusted;
        c.dir_proof = dir_proof;
        if (dir_fd) |f| {
            c.dir_fd = f;
            c.dir_seed = dir_seed;
        }
        if (age_fd) |f| {
            c.age_fd = f;
            c.age_seed = age_seed;
            c.age_n = arecs.items.len;
            c.age_cut = true;
            age_fd = null;
        }
        if (side_fd) |f| {
            c.side_fd = f;
            c.side_tail = std.mem.alignForward(u64, side_size, block);
            side_fd = null;
        }
        var overrides = false;
        for (arecs.items) |r| switch (r.kind) {
            0 => overrides = true,
            1 => c.cp_done = @max(c.cp_done, r.ls),
            else => c.seg_done = @max(c.seg_done, r.phys),
        };
        if (overrides) {
            // The dir file names the frames in the segment file: complete it before any entry
            // points into the sidecar.
            if (c.dir_written < ents.items.len) try s.dirPersist(e, c, true);
            d.main_end = d.physEnd();
            for (arecs.items) |r| if (r.kind == 0) {
                const i = d.indexAt(r.ls) orelse return error.Corrupt;
                if (d.entries[i].ll != r.ll) return error.Corrupt;
                d.entries[i].phys = r.phys;
                d.entries[i].bl = r.bl;
                d.entries[i].codec = chunk.codecWord(r.codec, r.dict);
            };
        }
        // A chunk naming a history dictionary the dictionary file does not hold: the dictionary
        // was synced before any frame naming it was written, so only a fault (a misdirected or
        // lost write of the dictionary file) gets here. Its chunks cannot be decoded, and the
        // groups after them may be acknowledged: refuse rather than truncate.
        for (d.entries[0..d.n.raw]) |en| if (chunk.codecOf(en.codec) == 3 and c.dicts.get(chunk.dictOf(en.codec)) == null) {
            if (!builtin.is_test) std.log.err("store: segment {d}: chunk at {d} names history dictionary {d}, the dictionary file holds {d}", .{ e, en.ls, chunk.dictOf(en.codec), c.dicts.len() });
            return error.Corrupt;
        };
        return c;
    }

    /// Appends `ents` to a compressed segment's directory (readers see them once `n` is stored).
    fn dirAppend(s: *Store, c: *CSeg, ents: []const chunk.Entry) Error!void {
        var d = c.dir.raw;
        const n = d.n.raw;
        if (n + ents.len > d.entries.len) {
            const nd = chunk.Dir.create(s.gpa, (n + ents.len) * 2) catch return error.OutOfMemory;
            @memcpy(nd.entries[0..n], d.entries[0..n]);
            nd.main_end = d.main_end;
            nd.n.store(n, .release);
            c.dir.store(nd, .release);
            s.retire(.{ .dir = d });
            d = nd;
        }
        @memcpy(d.entries[n..][0..ents.len], ents);
        d.n.store(n + ents.len, .release);
    }

    /// Drops directory entries from logical offset `from` on (recovery truncation).
    fn dirTruncate(c: *CSeg, from: u64) void {
        const d = c.dir.raw;
        var n = d.n.raw;
        while (n > 0 and d.entries[n - 1].ls >= from) n -= 1;
        d.n.store(n, .release);
        if (c.dir_written > n) c.dir_written = n;
        c.dir_cut = true;
        c.phys_tail = std.mem.alignForward(u64, d.physEnd(), block);
    }

    const dir_batch = 256;

    /// Writes the directory entries not yet in `index/<epoch>.dir` (no sync: the file is a hint
    /// whose trusted prefix is checked at open). A failure only stops the appends.
    fn dirPersist(s: *Store, e: u64, c: *CSeg, sync: bool) Error!void {
        const d = c.dir.raw;
        const n = d.n.raw;
        if (c.dir_fd == null) {
            var nb: [64]u8 = undefined;
            const f = s.backend.openFile(dirName(&nb, e), true) catch |err| return keepCrash(err);
            var h: chunk.DirHeader = .{ .epoch = e, .seed = c.dir_seed };
            h.checksum = h.sum();
            var page: [chunk.dir_header_len]u8 = @splat(0);
            @memcpy(page[0..@sizeOf(chunk.DirHeader)], std.mem.asBytes(&h));
            s.backend.truncate(f, 0) catch |err| {
                s.backend.closeFile(f);
                return keepCrash(err);
            };
            s.backend.write(f, 0, &page) catch |err| {
                s.backend.closeFile(f);
                return keepCrash(err);
            };
            c.dir_fd = f;
            c.dir_written = 0;
        }
        const f = c.dir_fd.?;
        // Batched: the frames after the persisted prefix are walked at open (a few chunks).
        if (!sync and n - c.dir_written < dir_batch) return;
        if (c.dir_written < n) {
            const k = n - c.dir_written;
            const img = s.gpa.alloc(chunk.Entry, k) catch return;
            defer s.gpa.free(img);
            @memcpy(img, d.entries[c.dir_written..n]);
            for (img) |*x| chunk.sealEntry(x, c.dir_seed);
            if (c.dir_cut) {
                s.backend.truncate(f, chunk.dir_header_len + c.dir_written * 32) catch |err| return keepCrash(err);
                c.dir_cut = false;
            }
            s.backend.write(f, chunk.dir_header_len + c.dir_written * 32, std.mem.sliceAsBytes(img)) catch |err| {
                s.backend.closeFile(f);
                c.dir_fd = null;
                return keepCrash(err);
            };
            c.dir_written = n;
        }
        if (sync) s.backend.sync(f) catch |err| return keepCrash(err);
    }

    /// The dir file is a hint: its write errors are ignored, except a simulated crash.
    fn keepCrash(err: Error) Error!void {
        if (err == error.Crashed) return err;
    }

    /// The decoded bytes of a chunk (cached; valid until the snapshot of reader epoch `ep` is
    /// released or quiesces).
    fn chunkData(s: *Store, c: *CSeg, en: chunk.Entry, ep: u64) Error![]const u8 {
        const key = (c.id << format.offset_bits) | en.ls;
        if (s.cache.get(key, ep)) |d| return d;
        const t0 = clock.now();
        defer {
            const ns = clock.now() -| t0;
            const st = &s.cache.stats;
            _ = st.miss_ns.fetchAdd(ns, .monotonic);
            _ = st.miss_bytes.fetchAdd(chunk.frame_len + en.bl, .monotonic);
            var cur = st.miss_max_ns.load(.monotonic);
            while (ns > cur) cur = st.miss_max_ns.cmpxchgWeak(cur, ns, .monotonic, .monotonic) orelse break;
        }
        const raw = s.gpa.alloc(u8, chunk.frame_len + en.bl) catch return error.OutOfMemory;
        defer s.gpa.free(raw);
        try s.readFrame(c, en, raw);
        const ce = chunk.checkFrame(en.phys, raw) catch return error.Corrupt;
        if (ce.ls != en.ls or ce.ll != en.ll) return error.Corrupt;
        // The cache owns `out` from `put` on and frees it with its own allocator (guard.zig).
        const out = s.cache.mem.alloc(u8, en.ll) catch return error.OutOfMemory;
        chunk.decode(ce, c.epoch, c.dicts, raw[chunk.frame_len..][0..en.bl], out) catch |err| {
            s.cache.mem.free(out);
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.Corrupt,
            };
        };
        const d = s.cache.put(key, out, ep) catch return error.OutOfMemory;
        // A lone reader (no commits, no other releases) still frees what nobody holds.
        if (s.cache.evicted_bytes.load(.monotonic) >= s.cache.shard_budget) s.chunkReclaim();
        return d;
    }

    /// Reads a chunk's frame (header ++ body) from the segment file or, for a chunk age-out
    /// rewrote, from the segment's sidecar.
    fn readFrame(s: *Store, c: *CSeg, en: chunk.Entry, raw: []u8) Error!void {
        if (chunk.isSide(en.phys)) {
            const f = c.side_fd orelse return error.Corrupt;
            return s.backend.read(f, en.phys & ~chunk.side_bit, raw);
        }
        return s.backend.read(c.fd, en.phys, raw);
    }

    /// Writer only: decodes the chunk into `out` (no cache), for scans that touch a chunk once.
    fn chunkInto(s: *Store, c: *CSeg, en: chunk.Entry, out: *std.ArrayList(u8)) Error!void {
        const at = out.items.len;
        out.resize(s.gpa, at + en.ll) catch return error.OutOfMemory;
        const raw = s.gpa.alloc(u8, chunk.frame_len + en.bl) catch return error.OutOfMemory;
        defer s.gpa.free(raw);
        try s.readFrame(c, en, raw);
        const ce = chunk.checkFrame(en.phys, raw) catch return error.Corrupt;
        if (ce.ls != en.ls or ce.ll != en.ll) return error.Corrupt;
        chunk.decode(ce, c.epoch, c.dicts, raw[chunk.frame_len..][0..en.bl], out.items[at..][0..en.ll]) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Corrupt,
        };
    }

    /// The commit group starting at logical `off` of a segment, as logical bytes (`g[0]` is at
    /// `off`): a view of a raw segment, or chunks decoded into `s.gbuf` (valid until the next
    /// call). `full`: every record's checksum checked (scanGroup), else the structure (walkGroup).
    /// Null when no complete, valid group starts there.
    const GroupAt = struct { g: []const u8, len: u64, seq: u64, commit_checksum: u64, commit_off: u64 };

    fn groupAt(s: *Store, slot: *SegSlot, e: u64, off: u64, end: u64, expect_prev: ?u64, full: bool) ?GroupAt {
        // Recovery returns the error kept in `scan_err` in place of judging a tail torn.
        return s.groupAtE(slot, e, off, end, expect_prev, full) catch |err| {
            if (s.scan_err == null) s.scan_err = err;
            return null;
        };
    }

    /// `groupAt` that returns the I/O errors (a crash, out of memory) instead of null: only
    /// damage reads as "no group here". The cleaner reported a simulated crash inside its
    /// sweep as error.Corrupt (store-dst age/127, 167, 169, 281, 409) and a real EIO the same.
    fn groupAtE(s: *Store, slot: *SegSlot, e: u64, off: u64, end: u64, expect_prev: ?u64, full: bool) Error!?GroupAt {
        if (slot.comp.raw) |c| {
            const d = c.dir.load(.acquire);
            var i = d.indexAt(off) orelse return null;
            s.gbuf.clearRetainingCapacity();
            const es = d.slice();
            // Decode chunks until the commit record and the group's padding are in.
            var p: usize = 0;
            while (true) {
                if (i >= es.len or es[i].ls >= end) return null;
                if (s.gbuf.items.len > s.cfg.max_batch_bytes + block) return null;
                s.chunkInto(c, es[i], &s.gbuf) catch |err| switch (err) {
                    error.Corrupt, error.ShortRead => return null,
                    else => return err,
                };
                i += 1;
                const g = s.gbuf.items;
                var have_commit = false;
                while (p + format.short_len <= g.len) {
                    const h = format.short(g[p..]);
                    const n = format.lenOf(h.kind, h.size);
                    if (p + n > g.len) break;
                    if (h.kind == .commit) {
                        have_commit = true;
                        break;
                    }
                    p += n;
                }
                if (have_commit) {
                    const want = std.mem.alignForward(u64, p + format.recordLen(@sizeOf(format.CommitFixed)), block);
                    if (g.len < want) continue;
                    break;
                }
            }
            return groupIn(s.gbuf.items, off, e, expect_prev, full);
        }
        const data = viewOf(slot)[0..@min(end, slot.view_len)];
        if (off >= data.len) return null;
        return groupIn(data[off..], off, e, expect_prev, full);
    }

    /// Debug print for a group that does not read (ZUI_DST_DEBUG): its chunks and frames.
    fn debugGroup(s: *Store, slot: *SegSlot, e: u64, off: u64, end: u64) void {
        const c = slot.comp.raw orelse {
            std.debug.print("group e {d} off {d} end {d}: raw segment\n", .{ e, off, end });
            return;
        };
        const d = c.dir.load(.acquire);
        const es = d.slice();
        const first = d.indexAt(off);
        std.debug.print("group e {d} cseg {d} off {d} end {d}: {d} chunks, first {?d}, main_end {d}, side_tail {d}, age_n {d}\n", .{ e, c.id, off, end, es.len, first, d.main_end, c.side_tail, c.age_n });
        const lo = (first orelse return) -| 2;
        for (es[lo..@min(es.len, lo + 12)], lo..) |en, i| {
            var buf: std.ArrayList(u8) = .empty;
            defer buf.deinit(s.gpa);
            const ok = if (s.chunkInto(c, en, &buf)) |_| "ok" else |err| @errorName(err);
            std.debug.print("  [{d}] ls {d} ll {d} {s} {d} bl {d}: {s}\n", .{ i, en.ls, en.ll, if (chunk.isSide(en.phys)) "side" else "main", en.phys & ~chunk.side_bit, en.bl, ok });
        }
    }

    fn groupIn(g: []const u8, base: u64, e: u64, expect_prev: ?u64, full: bool) ?GroupAt {
        if (full) {
            const info = scanGroupRel(g, base, e, expect_prev) orelse return null;
            return .{ .g = g[0..info.len], .len = info.len, .seq = info.seq, .commit_checksum = info.commit_checksum, .commit_off = info.commit_off };
        }
        const w = walkGroupRel(g, base, e) orelse return null;
        return .{ .g = g[0..w.end], .len = w.end, .seq = 0, .commit_checksum = 0, .commit_off = w.commit_off };
    }

    /// Recovery: is there a durable group past a broken one (`break_loc`, the start of the
    /// group that does not read; null: anywhere in the segment)? Durable means proof that a
    /// group starting strictly after the break was written whole: a complete, valid group
    /// (its commit record names its start), or, compressed, dir entries past the break (the
    /// group's chunks were synced before their entries were written). A frame of the broken
    /// group itself is no proof: a torn multi-chunk group can lose its first frame and keep
    /// later ones (store-dst seed/550 under a shifted PRNG read that as durable data follows).
    fn laterDurable(s: *Store, slot: *SegSlot, e: u64, from: u64, break_loc: ?u64) bool {
        if (slot.comp.raw) |c| {
            const d = c.dir.raw;
            const brk: u64 = if (break_loc) |b| format.offsetOf(b) else 0;
            // The dir file names a chunk at or past the break: that group's write completed,
            // so it was acknowledged or about to be. Damage there is rot, not a torn tail.
            if (c.dir_proof > brk) return true;
            if (break_loc == null) {
                if (s.groupAt(slot, e, 0, d.logicalEnd(), null, true) != null) return true;
            }
            for (d.slice()) |en| if ((break_loc == null or en.ls > brk) and en.ls % block == 0) {
                if (s.groupAt(slot, e, en.ls, d.logicalEnd(), null, true) != null) return true;
            };
            const size = s.backend.size(slot.fd) catch |err| return s.scanFailed(err);
            var p = std.mem.alignForward(u64, d.physEnd(), block);
            while (p + chunk.frame_len <= size) : (p += block) {
                var f: chunk.Frame = undefined;
                s.backend.read(slot.fd, p, std.mem.asBytes(&f)) catch |err| return s.scanFailed(err);
                if ((break_loc != null and f.logical_start <= brk) or f.logical_len == 0 or p + chunk.frameSpan(f.body_len) > size) continue;
                if (s.commitInFrames(slot.fd, c.dicts, size, p, e, break_loc) catch |err| return s.scanFailed(err)) return true;
            }
            return false;
        }
        const size = s.backend.size(slot.fd) catch |err| return s.scanFailed(err);
        const data = viewOf(slot)[0..@min(size, slot.view_len)];
        if (findLaterCommit(data, e, from, break_loc)) return true;
        // A compressed segment whose file header did not survive (a lost or misdirected first
        // write) opens as raw: its frames and its dir file still prove durable groups
        // (store-dst misdir/4065 dropped three acknowledged groups after a lost first group).
        const brk: u64 = if (break_loc) |b| format.offsetOf(b) else 0;
        if ((s.dirProof(e, size) catch |err| return s.scanFailed(err)) > brk) return true;
        // Its history dictionaries (codec 3 frames), from the dictionary file.
        const zd = s.loadDicts(e) catch |err| return s.scanFailed(err);
        defer if (zd) |d| d.destroy(s.gpa);
        var p = std.mem.alignForward(u64, brk, block);
        while (p + chunk.frame_len <= size) : (p += block) {
            var f: chunk.Frame = undefined;
            s.backend.read(slot.fd, p, std.mem.asBytes(&f)) catch |err| return s.scanFailed(err);
            if (f.logical_len == 0 or f.codec > chunk.max_codec or p + chunk.frameSpan(f.body_len) > size) continue;
            if (s.commitInFrames(slot.fd, zd, size, p, e, break_loc) catch |err| return s.scanFailed(err)) return true;
        }
        return false;
    }

    /// The trusted prefix of segment `e`'s dictionary file (null: no file or no valid header).
    fn loadDicts(s: *Store, e: u64) Error!?*chunk.Dicts {
        var nb: [64]u8 = undefined;
        if (!s.backend.exists(zdName(&nb, e))) return null;
        const fd = try s.backend.openFile(zdName(&nb, e), false);
        defer s.backend.closeFile(fd);
        const img = s.gpa.alloc(u8, try s.backend.size(fd)) catch return error.OutOfMemory;
        defer s.gpa.free(img);
        try s.backend.read(fd, 0, img);
        const d = chunk.Dicts.create(s.gpa) catch return error.OutOfMemory;
        errdefer d.destroy(s.gpa);
        _ = (chunk.dictsTrusted(img, e, d, s.gpa) catch return error.OutOfMemory) orelse {
            d.destroy(s.gpa);
            return null;
        };
        return d;
    }

    /// Logical end of the trusted prefix of segment `e`'s dir file (0: none), for a segment of
    /// `phys_size` bytes: every group below it was written whole.
    fn dirProof(s: *Store, e: u64, phys_size: u64) Error!u64 {
        var nb: [64]u8 = undefined;
        const dname = dirName(&nb, e);
        if (!s.backend.exists(dname)) return 0;
        const dfd = try s.backend.openFile(dname, false);
        defer s.backend.closeFile(dfd);
        const img = s.gpa.alloc(u8, try s.backend.size(dfd)) catch return error.OutOfMemory;
        defer s.gpa.free(img);
        try s.backend.read(dfd, 0, img);
        var ents: std.ArrayList(chunk.Entry) = .empty;
        defer ents.deinit(s.gpa);
        _ = chunk.trustedPrefix(img, e, phys_size, &ents, s.gpa) catch return error.OutOfMemory;
        return if (ents.items.len == 0) 0 else ents.items[ents.items.len - 1].end();
    }

    /// Decodes the run of adjacent valid frames starting at physical `p` (one group's chunks
    /// are adjacent) and looks in it for a valid commit record of a group that starts after
    /// `break_loc` (any group when null), as `findLaterCommit` does for raw bytes.
    fn commitInFrames(s: *Store, fd: Fd, dicts: ?*const chunk.Dicts, size: u64, p0: u64, e: u64, break_loc: ?u64) Error!bool {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(s.gpa);
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(s.gpa);
        var p = p0;
        var base: u64 = 0;
        var want: ?u64 = null;
        while (p + chunk.frame_len <= size and out.items.len <= s.cfg.max_batch_bytes + block) {
            var f: chunk.Frame = undefined;
            try s.backend.read(fd, p, std.mem.asBytes(&f));
            if (f.logical_len == 0 or f.body_len > s.cfg.max_batch_bytes * 2 or p + chunk.frameSpan(f.body_len) > size) break;
            if (want) |w| if (f.logical_start != w) break;
            raw.resize(s.gpa, chunk.frame_len + f.body_len) catch return error.OutOfMemory;
            try s.backend.read(fd, p, raw.items);
            const en = chunk.checkFrame(p, raw.items) catch break;
            // A whole frame naming a dictionary that is not there: written after its dictionary
            // was synced, so the dictionary was lost to a fault; the frame is proof of a write
            // that completed (refuse rather than truncate).
            if (chunk.codecOf(en.codec) == 3 and (dicts == null or dicts.?.get(chunk.dictOf(en.codec)) == null)) return true;
            if (want == null) base = en.ls;
            const at = out.items.len;
            out.resize(s.gpa, at + en.ll) catch return error.OutOfMemory;
            chunk.decode(en, e, dicts, raw.items[chunk.frame_len..][0..en.bl], out.items[at..][0..en.ll]) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    out.shrinkRetainingCapacity(at);
                    break;
                },
            };
            want = en.end();
            p += en.span();
        }
        if (want == null) return false;
        const data = out.items;
        var q: usize = @intCast(std.mem.alignForward(u64, base, 8) - base);
        while (q + format.header_len <= data.len) : (q += 8) {
            const h = format.header(data[q..]);
            if (h.kind != .commit or h.size != @sizeOf(format.CommitFixed)) continue;
            const rec = format.validate(data, q, format.loc(e, base + q)) catch continue;
            const cf = format.fixed(format.CommitFixed, rec);
            if (cf.epoch != e) continue;
            if (break_loc == null or cf.group_start > break_loc.?) return true;
        }
        return false;
    }

    /// A read `laterDurable` needed failed: assume a durable group follows (never truncate
    /// over it) and keep the error, which recovery returns in place of error.Corrupt.
    fn scanFailed(s: *Store, err: Error) bool {
        if (err != error.ShortRead) s.scan_err = err;
        return true;
    }

    /// Logical end of a segment's stored bytes: the file size (raw) or the chunks' end.
    fn logicalSize(s: *Store, slot: *SegSlot) Error!u64 {

        if (slot.comp.raw) |c| return c.dir.raw.logicalEnd();
        return s.backend.size(slot.fd);
    }

    fn ringAppend(s: *Store, e: u64) void {
        const t = s.ep_tail.load(.monotonic);
        s.ep_ring[t & s.seg_mask].store(e, .monotonic);
        s.ep_tail.store(t + 1, .release);
    }

    // ------------------------------------------------------------------ memtables and runs

    fn takeMem(s: *Store) Error!*table.Mem {
        if (s.mem_pool.pop()) |m| return m;
        return table.Mem.init(s.gpa, s.cfg.max_object_versions, s.cfg.max_transactions, s.cfg.max_checkpoints, s.seed ^ 0x6d656d) catch return error.OutOfMemory;
    }

    /// Publishes a fresh memtable covering the log from `start` (`epoch` is informational).
    fn swapMem(s: *Store, epoch: u64, start: u64, anchor: ?u64) Error!void {
        const fresh = try s.takeMem();
        fresh.epoch = epoch;
        fresh.start_loc = start;
        fresh.start_anchor = anchor;
        const old = s.memOrNull();
        s.mem.store(fresh, .release);
        if (old) |o| s.retire(.{ .mem = o });
    }

    /// Seals the memtable as the next run of the epoch `end` falls in, covering the log from
    /// its start up to `end` (exclusive). Returns false when there was nothing to seal (the
    /// caller then keeps the memtable), else the caller swaps in a fresh one starting at `end`.
    fn sealMem(s: *Store, end: u64, anchor: ?u64) Error!bool {
        const m = s.curMem();
        if (end <= m.start_loc or m.empty()) return false;
        const e = format.epochOf(end);
        const slot = s.slotOf(e) orelse return false;
        const r = slot.nruns.load(.monotonic);
        if (r >= max_runs) return error.TooManyRuns;
        m.epoch = e;
        const img = table.buildRun(s.gpa, m, r, end, anchor) catch return error.OutOfMemory;
        defer s.gpa.free(img);
        var nb: [64]u8 = undefined;
        const name = io_mod.runName(&nb, e, r);
        const fd = try s.backend.openFile(name, true);
        errdefer s.backend.closeFile(fd);
        try s.backend.truncate(fd, 0);
        try s.backend.write(fd, 0, img);
        try s.backend.sync(fd);
        try s.backend.syncDir();
        const view = try s.backend.map(fd, img.len);
        s.adviseRandom(view);
        const run = s.gpa.create(table.Run) catch {
            s.backend.unmap(fd, view);
            return error.OutOfMemory;
        };
        run.* = table.Run.open(view, fd, false) catch {
            s.gpa.destroy(run);
            s.backend.unmap(fd, view);
            return error.Corrupt;
        };
        s.pinFilters(run);
        slot.runs[r].store(run, .release);
        slot.nruns.store(r + 1, .release);
        // Before the caller publishes the fresh memtable (readers load the memtable first).
        _ = s.runs_total.fetchAdd(1, .acq_rel);
        s.stats.runs_sealed += 1;
        s.stats.run_bytes_written += img.len;
        return true;
    }

    // ------------------------------------------------------------------ live table files

    /// A new live-table key secret (table.zig): 16 bytes from the OS, or derived from
    /// `cfg.seed` when one is set (tests and simulation replay byte for byte).
    fn newSecret(s: *const Store) table.Secret {
        var k: table.Secret = undefined;
        if (s.cfg.seed != 0) {
            std.mem.writeInt(u64, k[0..8], cs.hash(s.cfg.seed, "zui-live-key-0"), .little);
            std.mem.writeInt(u64, k[8..16], cs.hash(s.cfg.seed, "zui-live-key-1"), .little);
            return k;
        }
        osRandom(&k);
        return k;
    }

    fn liveSeed(s: *const Store, tg: u64) u64 {
        return s.seed ^ (tg *% 0x9e3779b97f4a7c15) ^ 0x6c697665;
    }

    fn livePages(capacity: u64) u64 {
        return std.mem.alignForward(u64, table.livePagesFor(capacity), 16);
    }

    /// Creates an empty live table file of generation `tg` and maps it.
    fn createLive(s: *Store, tg: u64, npages: u64) Error!*LiveHandle {
        var nb: [64]u8 = undefined;
        const fd = try s.backend.openFile(io_mod.liveName(&nb, tg), true);
        errdefer s.backend.closeFile(fd);
        try s.backend.truncate(fd, 0);
        try s.backend.truncate(fd, npages * page_size);
        return s.mapLive(fd, tg, npages);
    }

    fn mapLive(s: *Store, fd: Fd, tg: u64, npages: u64) Error!*LiveHandle {
        const view = try s.backend.mapRw(fd, npages * page_size);
        errdefer s.backend.unmapRw(fd, view);
        const h = try s.gpa.create(LiveHandle);
        errdefer s.gpa.destroy(h);
        const pages: []align(page_size) table.Page = @ptrCast(view);
        h.* = .{ .t = try table.LiveTable.init(s.gpa, pages, s.liveSeed(tg), s.live_key), .view = view, .fd = fd, .tg = tg };
        return h;
    }

    /// Opens the live table named by `m`, applying its journal. Null when it cannot be trusted
    /// (missing, wrong size, a bad page, counts off): the caller rebuilds it from the logs.
    fn monoMs() u64 {
        var ts: std.posix.timespec = undefined;
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
    }

    /// Applies the journal of the flush `m` completes to the live table file `fd` (its pages may
    /// be missing or torn in the file: the in-place writes are synced only at the next flush).
    /// False when the journal cannot be trusted (the table is then rebuilt).
    fn applyJournal(s: *Store, fd: Fd, m: *const Meta, seed: u64) Error!bool {
        // The journal of the flush `meta` completes: its pages may be missing or torn in the
        // table file (the in-place writes are synced only at the next flush).
        if (s.backend.exists(io_mod.journal_name)) {
            const jfd = try s.backend.openFile(io_mod.journal_name, false);
            defer s.backend.closeFile(jfd);
            var h: JournalHeader = undefined;
            const ok_header = blk: {
                // A missing or short journal is no journal; a failed read is not evidence.
                s.backend.read(jfd, 0, std.mem.asBytes(&h)) catch |err| if (err == error.ShortRead) break :blk false else return err;
                break :blk std.mem.eql(u8, &h.magic, "ZUIJRNL1") and h.sum() == h.checksum and h.algo == cs.current_algo;
            };
            if (ok_header and h.tg == m.live_tg and h.gen == m.live_gen) {
                const list_bytes = std.mem.alignForward(u64, h.npages * 8, page_size);
                const list = s.gpa.alignedAlloc(u8, .fromByteUnits(8), @max(list_bytes, 8)) catch return error.OutOfMemory;
                defer s.gpa.free(list);
                s.backend.read(jfd, page_size, list[0..list_bytes]) catch |err| if (err == error.ShortRead) return false else return err;
                if (cs.hash(0x6a6c7374, list[0 .. h.npages * 8]) != h.list_hash) return false;
                // Batched: one sequential journal read per chunk, and pages adjacent in the
                // table (the list is in page order) written together. The table is synced every
                // 64 MiB written (lane fast-start), so a large journal does not pile up dirty page
                // cache: a memory-capped cgroup throttles its writer hard once dirty pages reach
                // its limit (a 19 GB journal took 25 min page by page). The tail is left to the
                // first flush (main 23430af).
                var unsynced: u64 = 0;
                const jbuf = s.gpa.alignedAlloc(u8, .fromByteUnits(page_size), jnl_apply_pages * page_size) catch return error.OutOfMemory;
                defer s.gpa.free(jbuf);
                var i: u64 = 0;
                while (i < h.npages) {
                    const n: u64 = @min(jnl_apply_pages, h.npages - i);
                    s.backend.read(jfd, page_size + list_bytes + i * page_size, jbuf[0 .. n * page_size]) catch |err| if (err == error.ShortRead) return false else return err;
                    var a: u64 = 0;
                    while (a < n) {
                        const pa = std.mem.readInt(u64, list[(i + a) * 8 ..][0..8], .little);
                        var b = a;
                        while (true) {
                            const p = std.mem.readInt(u64, list[(i + b) * 8 ..][0..8], .little);
                            if (p >= m.live_pages) return false;
                            if (!table.pageValid(seed, p, jbuf[b * page_size ..][0..page_size], h.flags & jnl_sealed == 0)) return false;
                            b += 1;
                            if (b == n or std.mem.readInt(u64, list[(i + b) * 8 ..][0..8], .little) != p + 1) break;
                        }
                        try s.backend.write(fd, pa * page_size, jbuf[a * page_size .. b * page_size]);
                        a = b;
                    }
                    i += n;
                    unsynced += n;
                    if (unsynced >= 16384) {
                        try s.backend.sync(fd);
                        unsynced = 0;
                    }
                }
                // Not synced here: the first flush syncs the table before it reuses the journal,
                // on the flusher thread, so the open does not wait on the write-back.
                s.live_unsynced = h.npages > 0;
            }
        }
        return true;
    }

    fn loadLive(s: *Store, m: *const Meta) Error!?*LiveHandle {
        const t_open = monoMs();
        defer if (!builtin.is_test) std.log.info("store: live table load {d} ms", .{monoMs() - t_open});
        var nb: [64]u8 = undefined;
        const name = io_mod.liveName(&nb, m.live_tg);
        if (!s.backend.exists(name)) return null;
        const fd = try s.backend.openFile(name, false);
        var keep = false;
        defer if (!keep) s.backend.closeFile(fd);
        if ((try s.backend.size(fd)) < m.live_pages * page_size or m.live_pages == 0) return null;
        const seed = s.liveSeed(m.live_tg);
        if (!try s.applyJournal(fd, m, seed)) return null;
        const t_j = monoMs();
        const lh = try s.mapLive(fd, m.live_tg, m.live_pages);
        lh.sealed = m.flags & meta_sealed != 0;
        keep = true;
        var ok = true;
        defer if (!ok) {
            keep = false;
            s.backend.unmapRw(fd, lh.view);
            lh.t.deinit(s.gpa);
            s.gpa.destroy(lh);
        };
        const clean = m.flags & meta_clean != 0;
        s.stats.open_clean = clean;
        if (clean and !builtin.is_test) std.log.info("store: live table closed cleanly; page check skipped", .{});
        if (s.cfg.verify_index_on_open and !clean) {
            // Every page checked, in parallel slices read ahead (lane fast-start: a 35 GB table
            // read one fault at a time took minutes of the start; this runs at disk bandwidth).
            const V = struct {
                pages: []const table.Page,
                seed: u64,
                sealed: bool,
                count: std.atomic.Value(u64) = .init(0),
                live: std.atomic.Value(u64) = .init(0),
                bad: std.atomic.Value(bool) = .init(false),
                fn slice(v: *@This(), i: usize, n: usize) void {
                    const lo = v.pages.len * i / n;
                    const hi = v.pages.len * (i + 1) / n;
                    var count: u64 = 0;
                    var live: u64 = 0;
                    const step: usize = 4096; // pages per read-ahead window (16 MiB)
                    var p = lo;
                    while (p < hi) : (p += 1) {
                        if ((p - lo) % step == 0) {
                            const end = @min(hi, p + 2 * step);
                            const a = std.mem.alignBackward(usize, @intFromPtr(&v.pages[p]), std.heap.pageSize());
                            std.posix.madvise(@ptrFromInt(a), @intFromPtr(&v.pages[end - 1]) + page_size - a, std.posix.MADV.WILLNEED) catch {};
                            if (v.bad.load(.monotonic)) return;
                        }
                        const pg = &v.pages[p];
                        const bytes: *const [page_size]u8 = @ptrCast(pg);
                        if (!table.pageValid(v.seed, p, bytes, !v.sealed)) {
                            v.bad.store(true, .monotonic);
                            return;
                        }
                        for (pg.locs) |l| if (l != 0) {
                            count += 1;
                            if (l & table.tomb == 0) live += 1;
                        };
                    }
                    _ = v.count.fetchAdd(count, .monotonic);
                    _ = v.live.fetchAdd(live, .monotonic);
                }
            };
            var v: V = .{ .pages = lh.t.pages, .seed = seed, .sealed = lh.sealed };
            const nt: usize = if (builtin.is_test or lh.t.pages.len < 1 << 16) 1 else @min(std.Thread.getCpuCount() catch 4, 16);
            var ts: [16]?std.Thread = @splat(null);
            for (1..nt) |i| ts[i] = std.Thread.spawn(.{}, V.slice, .{ &v, i, nt }) catch null;
            V.slice(&v, 0, nt);
            for (1..nt) |i| if (ts[i]) |t| t.join() else V.slice(&v, i, nt);
            if (v.bad.load(.monotonic)) {
                ok = false;
                return null;
            }
            const count = v.count.load(.monotonic);
            const live = v.live.load(.monotonic);
            if (count != m.live_count or live != m.live_live) {
                ok = false;
                return null;
            }
        }
        lh.t.count = m.live_count;
        lh.t.live = m.live_live;
        if (!builtin.is_test) std.log.info("store: live table {d} MiB opened (journal replayed before; checked in {d} ms)", .{ (m.live_pages * page_size) >> 20, monoMs() - t_j });
        return lh;
    }

    fn journalFd(s: *Store) Error!Fd {
        if (s.jnl_fd) |f| return f;
        const f = try s.backend.openFile(io_mod.journal_name, true);
        s.jnl_fd = f;
        try s.backend.syncDir();
        return f;
    }

    /// Writes the live-table pages changed since the last flush: journal (synced), then `meta`
    /// naming the flush, then the pages in place (synced at the next flush, before the journal
    /// is reused). Afterwards the live table covers the log up to the current tail.
    pub fn flushIndex(s: *Store) Error!void {
        return s.flushLive();
    }

    /// A synchronous flush (epoch changes, cleaning, close): waits for a running background
    /// flush, then flushes what is dirty now, on this thread.
    fn flushLive(s: *Store) Error!void {
        try s.waitFlush();
        return s.flushLiveSync();
    }

    fn flushLiveSync(s: *Store) Error!void {
        const h = s.live.raw.?;
        const t = &h.t;
        if (s.live_unsynced) {
            try s.backend.sync(h.fd);
            s.live_unsynced = false;
        }
        const jfd = try s.journalFd();
        const n = t.ndirty;
        const list_bytes = std.mem.alignForward(u64, n * 8, page_size);
        // The previous flush's in-place pages are synced, so its journal is dead: give back the
        // space of an oversized one (a restore's last flush leaves ~12 GB) before reusing it.
        {
            const need = page_size + list_bytes + n * page_size;
            const have = try s.backend.size(jfd);
            if (have > need and have - need > 64 << 20) try s.backend.truncate(jfd, need);
        }
        // Stage header, page list and pages through the batch buffer (its group, if any, is
        // already durable and applied).
        const cap_pages = s.buf.len / page_size;
        std.debug.assert(cap_pages >= 2);
        var list = std.ArrayList(u64).initCapacity(s.gpa, n) catch return error.OutOfMemory;
        defer list.deinit(s.gpa);
        for (t.dirty, 0..) |w, wi| {
            var x = w;
            while (x != 0) : (x &= x - 1) list.appendAssumeCapacity(wi * 64 + @ctz(x));
        }
        std.debug.assert(list.items.len == n);
        for (list.items) |p| t.sealPage(p);
        var jh: JournalHeader = .{
            .tg = h.tg,
            .gen = s.live_gen + 1,
            .npages = n,
            .list_hash = cs.hash(0x6a6c7374, std.mem.sliceAsBytes(list.items)),
        };
        jh.checksum = jh.sum();
        var off: u64 = 0;
        {
            @memset(s.buf[0..page_size], 0);
            @memcpy(s.buf[0..@sizeOf(JournalHeader)], std.mem.asBytes(&jh));
            try s.backend.write(jfd, 0, s.buf[0..page_size]);
            off = page_size;
            var i: usize = 0;
            while (i < list_bytes) {
                const take_b = @min(list_bytes - i, s.buf.len);
                @memset(s.buf[0..take_b], 0);
                const from = i / 8;
                const upto = @min(n, (i + take_b) / 8);
                if (upto > from) @memcpy(s.buf[0 .. (upto - from) * 8], std.mem.sliceAsBytes(list.items[from..upto]));
                try s.backend.write(jfd, off, s.buf[0..take_b]);
                off += take_b;
                i += take_b;
            }
            var k: usize = 0;
            while (k < n) {
                const take = @min(n - k, cap_pages);
                for (0..take) |j| {
                    const p = list.items[k + j];
                    @memcpy(s.buf[j * page_size ..][0..page_size], std.mem.asBytes(&t.pages[p]));
                }
                try s.backend.write(jfd, off, s.buf[0 .. take * page_size]);
                off += take * page_size;
                k += take;
            }
        }
        try s.backend.sync(jfd);
        s.live_gen += 1;
        var m = s.metaAt(h, s.tailLoc(), s.last_commit);
        try s.writeMeta(&m);
        // In place, coalescing runs of adjacent pages.
        var i: usize = 0;
        while (i < n) {
            var j = i + 1;
            while (j < n and list.items[j] == list.items[j - 1] + 1) j += 1;
            const p0 = list.items[i];
            try s.backend.write(h.fd, p0 * page_size, h.view[p0 * page_size .. list.items[j - 1] * page_size + page_size]);
            i = j;
        }
        if (n > 0) {
            s.live_unsynced = true;
            try s.backend.dropPrivate(h.fd, h.view);
        }
        t.clearDirty();
        s.since_flush = 0;
        s.stats.index_flushes += 1;
        s.stats.index_bytes_written += off + n * page_size;
    }

    // ------------------------------------------------------------------ background flush
    //
    // The commit that triggers a flush only freezes the dirty page set (the bitmap moves to the
    // job, the table gets a fresh one) and remembers where the log ends; a flusher thread then
    // does what `flushLiveSync` does, from copies: the journal of the frozen pages (synced),
    // meta naming it, the pages in place, and finally drops the private copies of pages the
    // writer has not touched again. Pages the writer changes meanwhile are saved first
    // (table.Cow), so the flushed table is exactly the table at the freeze, which is what meta
    // says it covers (`live_applied` = the log end at the freeze). Crash safety is that of the
    // synchronous flush: same files, same order, same recovery.

    fn maybeFlush(s: *Store) Error!void {
        const grown = s.lt().ndirty -| s.pace_prev_dirty;
        defer s.pace_prev_dirty = s.lt().ndirty;
        if (s.flush) |job| {
            if (job.done.load(.acquire)) {
                try s.reapFlush();
            } else if (s.lt().ndirty >= pace_cap_x * s.cfg.max_dirty_pages) {
                // Last resort: pacing did not hold the dirty set under the cap.
                try s.waitFlush();
            } else {
                s.pace(grown);
                return;
            }
        }
        if (s.since_flush >= s.cfg.index_flush_interval or s.lt().ndirty >= s.cfg.max_dirty_pages) {
            try s.flushBegin();
            if (s.flush_thread == null) {
                // Inline (simulator, or background flushes off): the same steps, now.
                s.flushRun();
                try s.reapFlush();
            }
        }
    }

    /// While a flush runs and the dirty set is past half the cap, sleeps so the writer dirties
    /// pages no faster than the last flush drained them, ramping from 0 at half the cap to the
    /// full drain-rate match at the cap (`pace_max_ns`, 1 s, per commit at most). The commit
    /// slows smoothly instead of blocking for a whole flush when the flusher falls behind
    /// (catch-up on a busy volume); at the tip the dirty set never gets there.
    fn pace(s: *Store, grown: u64) void {
        const cap = pace_cap_x * s.cfg.max_dirty_pages;
        const half = cap / 2;
        const nd = s.lt().ndirty;
        if (nd <= half or grown == 0) return;
        const ramp = @as(f64, @floatFromInt(nd - half)) / @as(f64, @floatFromInt(cap - half));
        // Drain rate: the last flush's, but no more than the running flush's pages over its time
        // so far (an upper bound that falls the longer it takes; the first flush after an open
        // has only this one).
        const job = s.flush.?;
        const elapsed = @max(1, clock.now() -| job.t_start);
        var pps: u64 = @max(1, job.list.len * std.time.ns_per_s / elapsed);
        if (s.stats.flush_drain_pps > 0) pps = @min(pps, s.stats.flush_drain_pps);
        const want: f64 = ramp * @as(f64, @floatFromInt(grown)) / @as(f64, @floatFromInt(pps)) * std.time.ns_per_s;
        const ns: u64 = @intFromFloat(@min(want, @as(f64, @floatFromInt(pace_max_ns))));
        if (ns < 100 * std.time.ns_per_us) return;
        clock.sleep(ns);
        s.stats.flush_pace_ns += ns;
        s.stats.flush_pace_max_ns = @max(s.stats.flush_pace_max_ns, ns);
    }

    /// Freezes the dirty page set into a flush job (writer). With background flushes on real
    /// files the job starts on its own thread; otherwise `flushRun` runs it (tests interleave
    /// commits between the two to exercise copy on write).
    pub fn flushBegin(s: *Store) Error!void {
        std.debug.assert(s.flush == null);
        const h = s.live.raw.?;
        const t = &h.t;
        _ = try s.journalFd();
        const gpa = s.gpa;
        const fresh = gpa.alloc(u64, t.dirty.len) catch return error.OutOfMemory;
        errdefer gpa.free(fresh);
        @memset(fresh, 0);
        const captured = gpa.alloc(u64, t.dirty.len) catch return error.OutOfMemory;
        errdefer gpa.free(captured);
        @memset(captured, 0);
        const list = gpa.alloc(u64, t.ndirty) catch return error.OutOfMemory;
        errdefer gpa.free(list);
        var k: usize = 0;
        for (t.dirty, 0..) |w, wi| {
            var x = w;
            while (x != 0) : (x &= x - 1) {
                list[k] = wi * 64 + @ctz(x);
                k += 1;
            }
        }
        std.debug.assert(k == list.len);
        const buf = gpa.alignedAlloc(u8, .fromByteUnits(page_size), flush_buf_pages * page_size) catch return error.OutOfMemory;
        errdefer gpa.free(buf);
        const job = gpa.create(FlushJob) catch return error.OutOfMemory;
        job.* = .{
            .s = s,
            .h = h,
            .list = list,
            .applied = s.tailLoc(),
            .anchor = s.last_commit,
            .count = t.count,
            .live = t.live,
            .gen = s.live_gen + 1,
            .cow = .{ .frozen = t.dirty, .captured = captured, .gpa = gpa },
            .buf = buf,
            .unsynced = s.live_unsynced,
            .t_start = clock.now(),
        };
        t.dirty = fresh;
        t.ndirty = 0;
        t.cow = &job.cow;
        s.flush = job;
        s.since_flush = 0;
        if (s.cfg.background_flush and s.backend == .real) {
            s.flush_thread = std.Thread.spawn(.{}, FlushJob.main, .{job}) catch null;
        }
    }

    /// Runs the frozen flush job on this thread (inline mode and tests).
    pub fn flushRun(s: *Store) void {
        const job = s.flush.?;
        std.debug.assert(s.flush_thread == null and !job.done.load(.monotonic));
        FlushJob.main(job);
    }

    /// Waits for the running flush (if any) and takes its result.
    pub fn waitFlush(s: *Store) Error!void {
        if (s.flush == null) return;
        const t0 = clock.now();
        defer s.stats.flush_wait_ns += clock.now() -| t0;
        if (s.flush_thread == null and !s.flush.?.done.load(.acquire)) s.flushRun();
        try s.reapFlush();
    }

    fn reapFlush(s: *Store) Error!void {
        const job = s.flush.?;
        if (s.flush_thread) |th| th.join();
        s.flush_thread = null;
        std.debug.assert(job.done.load(.acquire));
        defer s.freeFlush(job);
        s.stats.flush_cow_pages += job.cow.saves;
        if (job.err) |e| {
            s.poisoned = true;
            return e;
        }
        s.live_gen = job.gen;
        if (job.list.len > 0 and !job.synced) s.live_unsynced = true else if (job.unsynced or job.synced) s.live_unsynced = false;
        s.stats.index_flushes += 1;
        s.stats.index_bytes_written += job.bytes;
        s.stats.flush_bg += @intFromBool(job.s.cfg.background_flush and s.backend == .real);
        s.stats.flush_last_ns = job.ns;
        s.stats.flush_runs += job.runs;
        s.stats.flush_run_pages += job.run_pages;
        s.stats.flush_last_pages = job.list.len;
        s.stats.flush_parallel += @intFromBool(job.synced);
        s.stats.flush_direct += @intFromBool(job.direct);
        if (job.ns > 0 and job.list.len >= 1024) s.stats.flush_drain_pps = job.list.len * std.time.ns_per_s / job.ns;
    }

    fn freeFlush(s: *Store, job: *FlushJob) void {
        const gpa = s.gpa;
        if (s.live.raw) |h| if (h.t.cow == &job.cow) {
            h.t.cow = null;
        };
        job.cow.deinit();
        gpa.free(job.cow.frozen);
        gpa.free(job.cow.captured);
        gpa.free(job.list);
        gpa.free(job.buf);
        gpa.destroy(job);
        s.flush = null;
    }

    /// Commit latency over the last `commit_lat_len` commits (ns): p50, p99, max, plus the
    /// slowest commit and the commits over 100 ms since open.
    /// Commit latency quantiles over the last `last` commits (at most the ring's 65,536).
    pub fn commitLatency(s: *Store, gpa: std.mem.Allocator, last: u64) CommitLatency {
        const total = s.commit_lat_n.load(.acquire);
        const n: usize = @intCast(@min(total, commit_lat_len, last));
        var out: CommitLatency = .{ .n = total, .p50 = 0, .p99 = 0, .p999 = 0, .max_window = 0, .max_ever = s.commit_lat_max.load(.monotonic), .slow = s.commit_slow.load(.monotonic) };
        if (n == 0) return out;
        const v = gpa.alloc(u32, n) catch return out;
        defer gpa.free(v);
        for (v, 0..) |*x, i| x.* = s.commit_lat[(total - n + i) % commit_lat_len].load(.monotonic);
        std.mem.sort(u32, v, {}, std.sort.asc(u32));
        const us: u64 = 1000;
        out.p50 = v[n / 2] * us;
        out.p99 = v[@min(n - 1, n * 99 / 100)] * us;
        out.p999 = v[@min(n - 1, n * 999 / 1000)] * us;
        out.max_window = v[n - 1] * us;
        return out;
    }

    pub const CommitLatency = struct { n: u64, p50: u64, p99: u64, p999: u64, max_window: u64, max_ever: u64, slow: u64 };

    fn noteCommit(s: *Store, ns: u64) void {
        const i = s.commit_lat_n.load(.monotonic);
        s.commit_lat[i % commit_lat_len].store(@intCast(@min(ns / 1000, std.math.maxInt(u32))), .monotonic);
        s.commit_lat_n.store(i + 1, .release);
        if (ns > s.commit_lat_max.load(.monotonic)) s.commit_lat_max.store(ns, .monotonic);
        if (ns > 100 * std.time.ns_per_ms) _ = s.commit_slow.fetchAdd(1, .monotonic);
    }

    /// Writes the whole live table to its (new) file, synced, then points `meta` at it with
    /// `applied`/`anchor`. Used after growth and after a rebuild.
    fn persistWholeLive(s: *Store, h: *LiveHandle, applied: u64, anchor: ?u64) Error!void {
        for (0..h.t.pages.len) |p| h.t.sealPage(p);
        h.sealed = true;
        try s.backend.write(h.fd, 0, h.view);
        try s.backend.sync(h.fd);
        try s.backend.syncDir();
        s.live_unsynced = false;
        s.live_gen += 1;
        var m = s.metaAt(h, applied, anchor);
        try s.writeMeta(&m);
        try s.backend.dropPrivate(h.fd, h.view);
        h.t.clearDirty();
        s.stats.index_bytes_written += h.view.len;
    }

    /// Grows the live table so that `need` occupied slots fit with room to spare. The new
    /// table is complete and durable before readers see it.
    fn growLive(s: *Store, need: u64, applied: u64, anchor: ?u64) Error!void {
        try s.waitFlush();
        const old = s.live.raw.?;
        // 1.25x the need, not doubling: a mainnet-sized table (hundreds of millions of slots)
        // stays within 1.43x of its fill limit, and growth rewrites amortize to about 5 writes
        // per slot over the table's life (growth is rare: the live set grows slowly).
        const npages = @max(old.t.pages.len + 16, livePages(need + need / 4));
        const nh = try s.createLive(old.tg + 1, npages);
        errdefer s.reclaim(.{ .live = nh });
        const Ctx = struct {
            t: *table.LiveTable,
            fn put(c: @This(), id: *const table.Key, l: u64) anyerror!void {
                _ = try c.t.upsertKey(id, l);
            }
        };
        old.t.forEach(Ctx{ .t = &nh.t }, Ctx.put) catch return error.IndexFull;
        try s.persistWholeLive(nh, applied, anchor);
        s.adviseRandom(nh.view);
        s.live.store(nh, .release);
        var nb: [64]u8 = undefined;
        try s.deferFree(io_mod.liveName(&nb, old.tg));
        s.retire(.{ .live = old });
        s.stats.live_grows += 1;
    }

    fn liveSet(s: *Store, t: *table.LiveTable, id: *const [32]u8, l: u64) Error!void {
        if (s.bulk) |bk| {
            const key = table.keyOf(&s.live_key, id);
            return bk.add(s, &key, l);
        }
        _ = try t.upsert(id, l);
    }

    // ------------------------------------------------------------------ bulk live-table load
    //
    // A formal snapshot restore inserts ~773M ids at random pages of a ~35 GB table: done in
    // place, the whole table is private dirty memory until the end (37.5 GB peak, more than a
    // production box has beside sui-node). In bulk mode the commits do not touch the table: each
    // (key, location) goes to one of `bulk_buckets` spill files by the top bits of its hash
    // under the next table's seed, which is the order of its home slot in any table size. At
    // the end the table is sized for the count and written front to back: per bucket, the
    // entries sorted by home slot are placed at max(home, cursor) (linear probing in sorted
    // order), and pages behind the cursor are final, so a small window of pages is written out
    // sequentially. Entries that run past the last slot wrap to the front (rare). Memory: the
    // spill buffers, one bucket's entries and the window (~0.5 GB at mainnet scale); temp disk:
    // 20 bytes per object (~15.5 GB). The table file, synced, is then named by `meta`, so the
    // next open maps it directly.

    pub const bulk_buckets = 128;
    const bulk_shift: u6 = 57; // 64 - log2(bulk_buckets)
    comptime {
        std.debug.assert(@as(u64, 1) << (64 - @as(u7, bulk_shift)) == bulk_buckets);
    }
    const bulk_buf = 256 << 10;
    const bulk_window_pages = 8192;

    /// A spilled (key, location): 20 bytes, 4-byte aligned (no padding in the spill files).
    const BulkEnt = extern struct {
        key: table.Key,
        lo: u32,
        hi: u32,

        fn of(key: *const table.Key, l: u64) BulkEnt {
            return .{ .key = key.*, .lo = @truncate(l), .hi = @intCast(l >> 32) };
        }
        fn loc(e: *const BulkEnt) u64 {
            return @as(u64, e.hi) << 32 | e.lo;
        }
    };
    comptime {
        std.debug.assert(@sizeOf(BulkEnt) == 20);
    }

    pub const BulkLive = struct {
        tg: u64,
        seed: u64,
        fds: [bulk_buckets]Fd = undefined,
        lens: [bulk_buckets]u64 = @splat(0),
        fill: [bulk_buckets]usize = @splat(0),
        bufs: []align(8) u8,
        unsynced: u64 = 0,
        n: u64 = 0,

        fn add(bk: *BulkLive, s: *Store, key: *const table.Key, l: u64) Error!void {
            const h = cs.hash(bk.seed, key);
            const b: usize = @intCast(h >> bulk_shift);
            const buf = bk.bufs[b * bulk_buf ..][0..bulk_buf];
            const e: BulkEnt = .of(key, l);
            @memcpy(buf[bk.fill[b]..][0..@sizeOf(BulkEnt)], std.mem.asBytes(&e));
            bk.fill[b] += @sizeOf(BulkEnt);
            bk.n += 1;
            if (bk.fill[b] + @sizeOf(BulkEnt) > bulk_buf) try bk.flushBucket(s, b);
        }

        fn flushBucket(bk: *BulkLive, s: *Store, b: usize) Error!void {
            const n = bk.fill[b];
            if (n == 0) return;
            try s.backend.write(bk.fds[b], bk.lens[b], bk.bufs[b * bulk_buf ..][0..n]);
            bk.lens[b] += n;
            bk.fill[b] = 0;
            bk.unsynced += n;
            if (bk.unsynced >= 256 << 20) {
                // written back and out of the page cache: no dirty pile-up in a capped cgroup
                for (0..bulk_buckets) |i| s.backend.dropCache(bk.fds[i], 0, bk.lens[i], true);
                bk.unsynced = 0;
            }
        }
    };

    /// `bulkLiveFinish`'s read-and-sort pipeline (lane index-fast): `threads` workers prepare
    /// buckets in order into a ring of `threads + 1` slots (bucket b waits until bucket
    /// b - ring.len is placed), the finishing thread takes them in bucket order. Memory: one
    /// bucket's entries and order per slot (~290 MB per slot at mainnet scale).
    const BulkPipe = struct {
        s: *Store,
        bk: *BulkLive,
        nslots: u64,
        stop: ?*const std.atomic.Value(bool),
        ring: []Prep = &.{},
        next: std.atomic.Value(usize) = .init(0),
        placed: std.atomic.Value(usize) = .init(0),
        quit: std.atomic.Value(bool) = .init(false),
        failed: std.atomic.Value(bool) = .init(false),
        err: ?Error = null,

        const Ord = struct { home: u64, i: u32 };

        const Prep = struct {
            /// The bucket held + 1 once it is ready (0: free).
            ready: std.atomic.Value(usize) = .init(0),
            ents: []align(8) u8 = &.{},
            len: usize = 0,
            ord: []Ord = &.{},
            n: usize = 0,

            fn free(p: *Prep, gpa: std.mem.Allocator) void {
                if (p.ents.len > 0) gpa.free(p.ents);
                if (p.ord.len > 0) gpa.free(p.ord);
                p.* = .{};
            }
        };

        /// Worker threads (0: prepare inline; the simulator's backend is single-threaded).
        /// ZUI_BULK_THREADS, default min(cores, 6).
        fn threads(s: *Store) usize {
            if (s.backend != .real or builtin.is_test) return 0;
            if (std.c.getenv("ZUI_BULK_THREADS")) |v| return std.math.clamp(std.fmt.parseInt(usize, std.mem.span(v), 10) catch 6, 0, 32);
            return @min(std.Thread.getCpuCount() catch 4, 6);
        }

        /// Reads bucket `b`, computes each entry's home slot and sorts by (home, key, newest
        /// location first).
        fn prepare(pp: *BulkPipe, b: usize, p: *Prep) Error!void {
            const s = pp.s;
            const bk = pp.bk;
            const len: usize = @intCast(bk.lens[b]);
            p.len = len;
            p.n = 0;
            if (len == 0) return;
            if (len % @sizeOf(BulkEnt) != 0) return error.Corrupt;
            if (p.ents.len < len) {
                if (p.ents.len > 0) s.gpa.free(p.ents);
                p.ents = &.{};
                p.ents = s.gpa.alignedAlloc(u8, .fromByteUnits(8), len + len / 8) catch return error.OutOfMemory;
            }
            try s.backend.read(bk.fds[b], 0, p.ents[0..len]);
            s.backend.dropCache(bk.fds[b], 0, len, false);
            const es: []const BulkEnt = @ptrCast(p.ents[0..len]);
            if (p.ord.len < es.len) {
                if (p.ord.len > 0) s.gpa.free(p.ord);
                p.ord = &.{};
                p.ord = s.gpa.alloc(Ord, es.len + es.len / 8) catch return error.OutOfMemory;
            }
            for (es, 0..) |*e, i| p.ord[i] = .{ .home = table.homeOf(bk.seed, pp.nslots, &e.key), .i = @intCast(i) };
            p.n = es.len;
            const Ctx = struct {
                es: []const BulkEnt,
                fn lt(c: @This(), x: Ord, y: Ord) bool {
                    if (x.home != y.home) return x.home < y.home;
                    return switch (std.mem.order(u8, &c.es[x.i].key, &c.es[y.i].key)) {
                        .lt => true,
                        .gt => false,
                        // the newest location first: it is the one kept
                        .eq => table.locOf(c.es[x.i].loc()) > table.locOf(c.es[y.i].loc()),
                    };
                }
            };
            std.sort.pdq(Ord, p.ord[0..p.n], Ctx{ .es = es }, Ctx.lt);
        }

        fn work(pp: *BulkPipe) void {
            while (!pp.quit.load(.acquire) and !pp.failed.load(.acquire)) {
                const b = pp.next.fetchAdd(1, .monotonic);
                if (b >= bulk_buckets) return;
                while (b >= pp.placed.load(.acquire) + pp.ring.len) {
                    if (pp.quit.load(.acquire) or pp.failed.load(.acquire)) return;
                    clock.sleep(std.time.ns_per_ms);
                }
                const p = &pp.ring[b % pp.ring.len];
                pp.prepare(b, p) catch |e| {
                    pp.err = e;
                    pp.failed.store(true, .release);
                    return;
                };
                p.ready.store(b + 1, .release);
            }
        }

        fn take(pp: *BulkPipe, b: usize) (Error || error{Stopped})!*Prep {
            const p = &pp.ring[b % pp.ring.len];
            while (p.ready.load(.acquire) != b + 1) {
                if (pp.failed.load(.acquire)) return pp.err.?;
                if (pp.stop) |x| if (x.load(.acquire)) return error.Stopped;
                clock.sleep(std.time.ns_per_ms / 4);
            }
            return p;
        }

        fn release(pp: *BulkPipe, b: usize) void {
            pp.ring[b % pp.ring.len].ready.store(0, .release);
            pp.placed.store(b + 1, .release);
        }
    };

    fn sealAt(pg: *table.Page, seed: u64, p: u64) void {
        const bytes: *const [page_size]u8 = @ptrCast(pg);
        pg.sum = table.pageChecksum(seed, p, bytes);
    }

    fn bulkName(buf: []u8, b: usize) []const u8 {
        return std.fmt.bufPrint(buf, "bulk-{d}.spl", .{b}) catch unreachable;
    }

    /// Empty spill files for a bulk build of live table generation `tg`.
    fn bulkOpen(s: *Store, tg: u64) Error!*BulkLive {
        const bk = s.gpa.create(BulkLive) catch return error.OutOfMemory;
        errdefer s.gpa.destroy(bk);
        const bufs = s.gpa.alignedAlloc(u8, .fromByteUnits(8), bulk_buckets * bulk_buf) catch return error.OutOfMemory;
        errdefer s.gpa.free(bufs);
        bk.* = .{ .tg = tg, .seed = s.liveSeed(tg), .bufs = bufs };
        var opened: usize = 0;
        errdefer for (bk.fds[0..opened]) |fd| s.backend.closeFile(fd);
        for (0..bulk_buckets) |b| {
            var nb: [32]u8 = undefined;
            const fd = try s.backend.openFile(bulkName(&nb, b), true);
            bk.fds[b] = fd;
            opened += 1;
            try s.backend.truncate(fd, 0);
        }
        return bk;
    }

    /// Starts a bulk load into an empty live table: from now on commits spill live-table
    /// changes instead of applying them, until `bulkLiveFinish`. No reader may look up objects
    /// meanwhile (a restore serves nothing until it is done).
    pub fn bulkLiveBegin(s: *Store) Error!void {
        std.debug.assert(s.bulk == null and !s.batch_active);
        try s.waitFlush();
        if (s.lt().count != 0) return error.Corrupt;
        s.bulk = try s.bulkOpen(s.live.raw.?.tg + 1);
    }

    fn bulkClose(s: *Store, bk: *BulkLive) void {
        for (0..bulk_buckets) |b| {
            s.backend.closeFile(bk.fds[b]);
            var nb: [32]u8 = undefined;
            s.backend.remove(bulkName(&nb, b)) catch {};
        }
        s.gpa.free(bk.bufs);
        s.gpa.destroy(bk);
        if (s.bulk == bk) s.bulk = null;
    }

    /// Drops a bulk load (its spill files too).
    pub fn bulkLiveAbort(s: *Store) void {
        if (s.bulk) |bk| s.bulkClose(bk);
    }

    pub const BulkReport = struct { objects: u64, live: u64, pages: u64, wrapped: u64, ms: u64 };

    /// Ends a bulk load: builds the live table from the spill files, writes and syncs it, names
    /// it in `meta`, and deletes the spill files. `stop` (optional) aborts with error.Stopped.
    pub fn bulkLiveFinish(s: *Store, stop: ?*const std.atomic.Value(bool)) (Error || error{Stopped})!BulkReport {
        const bk = s.bulk.?;
        defer s.bulkClose(bk);
        const t0 = clock.now();
        for (0..bulk_buckets) |b| try bk.flushBucket(s, b);
        const old = s.live.raw.?;
        const npages = @max(livePages(bk.n + bk.n / 4), 16);
        const built = try s.bulkBuild(bk, npages, stop);
        var keep = false;
        defer if (!keep) s.backend.closeFile(built.fd);
        const nh = try s.mapLive(built.fd, bk.tg, npages);
        keep = true;
        nh.t.count = built.count;
        nh.t.live = built.live;
        s.live.store(nh, .release);
        s.live_unsynced = false;
        s.live_gen += 1;
        var m = s.metaAt(nh, s.tailLoc(), s.last_commit);
        try s.writeMeta(&m);
        var ob: [64]u8 = undefined;
        try s.deferFree(io_mod.liveName(&ob, old.tg));
        s.retire(.{ .live = old });
        return .{ .objects = built.count, .live = built.live, .pages = npages, .wrapped = built.wrapped, .ms = (clock.now() -| t0) / std.time.ns_per_ms };
    }

    const Built = struct { fd: Fd, count: u64, live: u64, wrapped: u64 };

    /// Writes live table generation `bk.tg` of `npages` pages from the flushed spill files of
    /// `bk` (front to back, see above), synced with its directory entry. Equal keys keep the
    /// newest location. The caller maps the open file and names it in `meta`.
    fn bulkBuild(s: *Store, bk: *BulkLive, npages: u64, stop: ?*const std.atomic.Value(bool)) (Error || error{Stopped})!Built {
        const nslots = npages * table.per_page;
        var nb: [64]u8 = undefined;
        const fd = try s.backend.openFile(io_mod.liveName(&nb, bk.tg), true);
        var keep = false;
        defer if (!keep) s.backend.closeFile(fd);
        try s.backend.truncate(fd, 0);
        try s.backend.truncate(fd, npages * page_size);
        const win_bytes = bulk_window_pages * page_size;
        const win = s.gpa.alignedAlloc(u8, .fromByteUnits(page_size), win_bytes) catch return error.OutOfMemory;
        defer s.gpa.free(win);
        @memset(win, 0);
        const wpages: []table.Page = @ptrCast(win);
        var wlo: u64 = 0;
        var wrapped: std.ArrayList(BulkEnt) = .empty;
        defer wrapped.deinit(s.gpa);
        var cursor: u64 = 0;
        var count: u64 = 0;
        var live: u64 = 0;
        const W = struct {
            fn out(st: *Store, f: Fd, w: []u8, wp: []table.Page, lo: u64, np: u64, seed: u64) Error!void {
                if (lo >= np) return;
                const n: u64 = @min(bulk_window_pages, np - lo);
                for (0..n) |k| sealAt(&wp[k], seed, lo + k);
                try st.backend.write(f, lo * page_size, w[0 .. n * page_size]);
                st.backend.dropCache(f, lo * page_size, n * page_size, true);
                @memset(w, 0);
            }
        };
        // Buckets are read, hashed and sorted ahead on `nt` threads (lane index-fast: one thread
        // spent ~1.3 s per bucket, 174 s for mainnet); placement stays in bucket order on this
        // thread (it is linear, and the cursor carries across buckets).
        var pipe: BulkPipe = .{ .s = s, .bk = bk, .nslots = nslots, .stop = stop };
        const nt = BulkPipe.threads(s);
        pipe.ring = s.gpa.alloc(BulkPipe.Prep, nt + 1) catch return error.OutOfMemory;
        defer s.gpa.free(pipe.ring);
        for (pipe.ring) |*r| r.* = .{};
        defer for (pipe.ring) |*r| r.free(s.gpa);
        var workers: [32]?std.Thread = @splat(null);
        for (workers[0..@min(nt, workers.len)]) |*t| {
            t.* = std.Thread.spawn(.{ .stack_size = 1 << 20 }, BulkPipe.work, .{&pipe}) catch null;
        }
        defer {
            pipe.quit.store(true, .release);
            for (workers) |t| if (t) |x| x.join();
        }
        const threaded = for (workers) |t| {
            if (t != null) break true;
        } else false;
        var local: BulkPipe.Prep = .{};
        defer local.free(s.gpa);
        for (0..bulk_buckets) |b| {
            if (stop) |x| if (x.load(.acquire)) return error.Stopped;
            const prep: *BulkPipe.Prep = if (threaded) try pipe.take(b) else blk: {
                try pipe.prepare(b, &local);
                break :blk &local;
            };
            const es: []const BulkEnt = @ptrCast(prep.ents[0..prep.len]);
            var prev: ?*const table.Key = null;
            for (prep.ord[0..prep.n]) |o| {
                const e = &es[o.i];
                if (prev) |pk| if (std.mem.eql(u8, pk, &e.key)) continue;
                prev = &e.key;
                count += 1;
                const l = e.loc();
                if (l & table.tomb == 0) live += 1;
                const pos = @max(o.home, cursor);
                if (pos >= nslots) {
                    wrapped.append(s.gpa, e.*) catch return error.OutOfMemory;
                    continue;
                }
                cursor = pos + 1;
                const pg = pos / table.per_page;
                while (pg >= wlo + bulk_window_pages) {
                    try W.out(s, fd, win, wpages, wlo, npages, bk.seed);
                    wlo += bulk_window_pages;
                }
                table.setSlot(&wpages[pg - wlo], pos % table.per_page, &e.key, l);
            }
            if (threaded) pipe.release(b);
        }
        try W.out(s, fd, win, wpages, wlo, npages, bk.seed);
        if (count > table.liveLimit(nslots)) return error.IndexFull;
        // wrapped entries: the first free slots from the front, page by page
        if (wrapped.items.len > 0) {
            var page: table.Page align(page_size) = undefined;
            var p: u64 = 0;
            var k: usize = 0;
            while (k < wrapped.items.len) : (p += 1) {
                if (p >= npages) return error.IndexFull;
                try s.backend.read(fd, p * page_size, std.mem.asBytes(&page));
                var changed = false;
                for (0..table.per_page) |j| {
                    if (k == wrapped.items.len) break;
                    if (page.locs[j] != 0) continue;
                    table.setSlot(&page, j, &wrapped.items[k].key, wrapped.items[k].loc());
                    k += 1;
                    changed = true;
                }
                if (changed) {
                    sealAt(&page, bk.seed, p);
                    try s.backend.write(fd, p * page_size, std.mem.asBytes(&page));
                }
            }
        }
        try s.backend.sync(fd);
        try s.backend.syncDir();
        keep = true;
        return .{ .fd = fd, .count = count, .live = live, .wrapped = wrapped.items.len };
    }

    /// Opens a live table of 32-byte slots (named by a "ZUIMETA2" meta, written before lane
    /// disk-fit) by converting it: the journal of the flush `m` completes is applied to it as
    /// `loadLive` would, every page is read in order and checked, each slot's id tail is keyed
    /// under the new secret (`live_key`) into the bulk spill files, and generation
    /// `live_tg + 1` is built from them (`bulkBuild`), synced, and named by a new meta covering
    /// the same log position. Only that meta write switches formats: a crash before it leaves
    /// the legacy meta and table as they were (the next open converts again, under a fresh
    /// secret; the unnamed new file and the spill files are dropped or reused), a crash after it
    /// opens the new table. The legacy file is freed after the next meta write. Null when the
    /// legacy table cannot be trusted (missing, short, a bad page, counts off): the caller
    /// rebuilds from the logs, as for a damaged table. Temp disk: 20 bytes per slot of spill
    /// plus the new table, beside the legacy file.
    fn migrateLive(s: *Store, m: *const Meta) Error!?*LiveHandle {
        const t_open = monoMs();
        var nb: [64]u8 = undefined;
        const name = io_mod.liveName(&nb, m.live_tg);
        if (!s.backend.exists(name)) return null;
        const fd = try s.backend.openFile(name, false);
        defer s.backend.closeFile(fd);
        if (m.live_pages == 0 or (try s.backend.size(fd)) < m.live_pages * page_size) return null;
        const old_seed = s.liveSeed(m.live_tg);
        if (!try s.applyJournal(fd, m, old_seed)) return null;
        s.live_unsynced = false;
        const bk = try s.bulkOpen(m.live_tg + 1);
        defer s.bulkClose(bk);
        const allow_zero = m.flags & meta_sealed == 0;
        const win_pages: u64 = 2048; // 8 MiB per read
        const buf = s.gpa.alignedAlloc(u8, .fromByteUnits(page_size), win_pages * page_size) catch return error.OutOfMemory;
        defer s.gpa.free(buf);
        var count: u64 = 0;
        var live: u64 = 0;
        var p: u64 = 0;
        while (p < m.live_pages) {
            const n: u64 = @min(win_pages, m.live_pages - p);
            s.backend.read(fd, p * page_size, buf[0 .. n * page_size]) catch |err| if (err == error.ShortRead) return null else return err;
            s.backend.dropCache(fd, p * page_size, n * page_size, false);
            const pages: []const table.LegacyPage = @ptrCast(buf[0 .. n * page_size]);
            for (pages, 0..) |*pg, k| {
                if (!table.pageValid(old_seed, p + k, @ptrCast(pg), allow_zero)) return null;
                for (&pg.slots) |*sl| if (sl.loc != 0) {
                    count += 1;
                    if (sl.loc & table.tomb == 0) live += 1;
                    const key = table.keyOfTail(&s.live_key, &sl.id);
                    try bk.add(s, &key, sl.loc);
                };
            }
            p += n;
        }
        if (count != m.live_count or live != m.live_live) return null;
        for (0..bulk_buckets) |b| try bk.flushBucket(s, b);
        // The legacy table's fill limit carries over (its headroom for growth), at least the
        // restore's 1.25x.
        const npages = @max(livePages(table.liveLimit(m.live_pages * table.legacy_per_page)), livePages(count + count / 4), 16);
        const built = s.bulkBuild(bk, npages, null) catch |err| return switch (err) {
            error.Stopped => unreachable,
            else => |e| e,
        };
        var keep = false;
        defer if (!keep) s.backend.closeFile(built.fd);
        const nh = try s.mapLive(built.fd, bk.tg, npages);
        keep = true;
        errdefer s.reclaim(.{ .live = nh });
        nh.t.count = built.count;
        nh.t.live = built.live;
        // Two tails under one key would have merged (odds ~n^2/2^97, table.zig).
        if (built.count != count) std.log.warn("store: live table migration: {d} slots became {d}", .{ count, built.count });
        s.live_gen += 1;
        var nm = s.metaAt(nh, m.live_applied, if (m.live_has_anchor != 0) m.live_anchor else null);
        try s.writeMeta(&nm);
        try s.deferFree(name);
        s.stats.index_bytes_written += npages * page_size;
        if (!builtin.is_test) std.log.info("store: live table migrated to 20-byte slots: {d} slots, {d} MiB -> {d} MiB, {d} ms", .{ count, (m.live_pages * page_size) >> 20, (npages * page_size) >> 20, monoMs() - t_open });
        return nh;
    }

    // ------------------------------------------------------------------ recovery

    fn recover(s: *Store) Error!void {
        const fresh = !s.backend.exists("meta");
        s.meta_fd = try s.backend.openFile("meta", true);
        s.meta_open = true;
        s.scan_err = null;
        const meta: ?Meta = if (fresh) null else s.readMeta();
        if (s.scan_err) |err| return err;
        const segs = try s.backend.listSegments(s.gpa);
        defer s.gpa.free(segs);
        for (0..2) |_| s.mem_pool.append(s.gpa, try s.takeMem()) catch return error.OutOfMemory;
        if (meta == null) {
            // A store without a valid meta slot has no acknowledged commit only if it has no
            // segments: the first meta write is synced (file and directory) before open returns,
            // and segments are created only after that. Segments without meta mean meta was lost
            // or both slots were damaged: refuse rather than delete acknowledged history.
            if (segs.len > 0) return error.Corrupt;
            const seed = if (s.cfg.seed != 0) s.cfg.seed else (clock.now() *% 0x9e3779b97f4a7c15) | 1;
            s.seed = seed;
            s.live_key = s.newSecret();
            const h = try s.createLive(1, livePages(s.cfg.max_live_objects));
            s.live.store(h, .release);
            try s.backend.sync(h.fd);
            try s.swapMem(no_epoch, 0, null);
            var m = s.metaAt(h, 0, null);
            try s.writeMeta(&m);
            try s.backend.syncDir();
            return;
        }
        const m = meta.?;
        if (m.algo != cs.current_algo) return error.Corrupt;
        s.meta_gen = m.generation;
        s.seed = m.seed;
        // A legacy meta's table is converted below under a fresh secret.
        s.live_key = if (m.legacy()) s.newSecret() else m.live_key;
        s.live_gen = m.live_gen;
        s.oldest_epoch.store(m.oldest_epoch, .monotonic);
        if (m.has_committed != 0) {
            s.committed1.store(m.committed + 1, .monotonic);
            s.meta_committed = m.committed;
        }
        try s.swapMem(no_epoch, 0, null);

        // Segments: below the history window they are aged (kept for their live objects, no
        // runs, never replayed unless the live table is rebuilt); the rest are retained.
        var kept: std.ArrayList(u64) = .empty;
        defer kept.deinit(s.gpa);
        for (segs) |e| {
            try s.mapSegment(e, false);
            if (e < m.oldest_epoch) {
                const slot = s.slotOf(e).?;
                slot.end.store(try s.logicalSize(slot), .release);
                s.aged.append(s.gpa, e) catch return error.OutOfMemory;
                continue;
            }
            try kept.append(s.gpa, e);
        }
        std.mem.sort(u64, s.aged.items, {}, std.sort.asc(u64));
        s.clean.due = s.aged.items.len > 0;

        // Index files: runs of retained epochs (checked below), the live table named by meta.
        const RunFile = struct { epoch: u64, run: u64 };
        var runs: std.ArrayList(RunFile) = .empty;
        defer runs.deinit(s.gpa);
        {
            const names = try s.backend.listDir(s.gpa, "index");
            defer {
                for (names) |n| s.gpa.free(n);
                s.gpa.free(names);
            }
            for (names) |n| {
                var nb: [96]u8 = undefined;
                const full = std.fmt.bufPrint(&nb, "index/{s}", .{n}) catch continue;
                switch (io_mod.parseIndexName(n)) {
                    .run => |r| {
                        if (std.mem.indexOfScalar(u64, kept.items, r.epoch) != null) {
                            try runs.append(s.gpa, .{ .epoch = r.epoch, .run = r.run });
                        } else if (r.epoch < m.oldest_epoch) {
                            // Aged or pruned (never recreated): the older slot may still name it.
                            try s.deferFree(full);
                        } else try s.backend.remove(full);
                    },
                    // An older table may be the other slot's; a newer one no durable meta names
                    // (and its name is reused by the next table created).
                    .live => |tg| if (tg < m.live_tg) try s.deferFree(full) else if (tg > m.live_tg) try s.backend.remove(full),
                    .other => {
                        // A dir file, sidecar or age log whose segment is gone (deleted first).
                        for ([_][]const u8{ ".dir", ".side", ".age", ".zd" }) |ext| if (std.mem.endsWith(u8, n, ext)) {
                            const e = std.fmt.parseInt(u64, n[0 .. n.len - ext.len], 10) catch break;
                            if (std.mem.indexOfScalar(u64, segs, e) == null) try s.backend.remove(full);
                        };
                    },
                }
            }
        }

        // Live table, or a rebuild from the logs.
        var live_from: u64 = m.live_applied;
        var live_anchor: ?u64 = if (m.live_has_anchor != 0) m.live_anchor else null;
        var rebuild = false;
        if (try (if (m.legacy()) s.migrateLive(&m) else s.loadLive(&m))) |h| {
            s.live.store(h, .release);
        } else {
            rebuild = true;
            const pages = @max(m.live_pages, livePages(s.cfg.max_live_objects));
            s.live.store(try s.createLive(m.live_tg + 1, pages), .release);
            live_from = 0;
            live_anchor = null;
        }

        // Runs: one chain over the retained epochs in (epoch, run) order, each run starting where
        // the previous one ends and the first at or before the oldest retained segment (its
        // older part indexes pruned epochs). Runs past a gap or a bad run are rebuilt.
        const file_end = try s.gpa.alloc(u64, kept.items.len);
        defer s.gpa.free(file_end);
        var cover: u64 = if (kept.items.len > 0) format.loc(kept.items[0], 0) else 0;
        var cover_anchor: ?u64 = null;
        var have_run = false;
        var broken = false;
        // With `verify_index_on_open` every page of every run file is read and checked here,
        // one file after the other through its mapping: as long as the run files are large,
        // at the disk's speed, on every open (a clean close skips the live table's page check
        // only). On a mainnet store that is tens of seconds in which the start said nothing
        // (lane history-stop: 37 to 43 s between "live table load" and the log replay). It
        // now says what it reads and how far it is.
        const t_runs = monoMs();
        var t_said = t_runs;
        var runs_bytes: u64 = 0;
        var runs_done: usize = 0;
        if (!builtin.is_test and runs.items.len > 0 and s.cfg.verify_index_on_open) std.log.info("store: checking {d} run files of {d} retained segments (every index page, read through; no progress line means under 5 s a file)", .{ runs.items.len, kept.items.len });
        for (kept.items, 0..) |e, k| {
            const slot = s.slotOf(e).?;
            file_end[k] = try s.logicalSize(slot);
            var r: u64 = 0;
            while (!broken) : (r += 1) {
                const present = for (runs.items) |x| {
                    if (x.epoch == e and x.run == r) break true;
                } else false;
                if (!present) break;
                var nb: [64]u8 = undefined;
                const fd = try s.backend.openFile(io_mod.runName(&nb, e, r), false);
                const size = try s.backend.size(fd);
                const view = s.backend.map(fd, @max(size, 1)) catch {
                    s.backend.closeFile(fd);
                    broken = true;
                    break;
                };
                const run = table.Run.open(view[0..@min(size, view.len)], fd, s.cfg.verify_index_on_open) catch {
                    s.backend.unmap(fd, view);
                    s.backend.closeFile(fd);
                    broken = true;
                    break;
                };
                const h = run.header;
                const start_ok = if (have_run) h.start_loc == cover else h.start_loc <= cover;
                if (h.epoch != e or h.run != r or !start_ok or h.end_loc < h.start_loc or
                    format.epochOf(h.end_loc) != e or format.offsetOf(h.end_loc) > file_end[k])
                {
                    s.backend.unmap(fd, view);
                    s.backend.closeFile(fd);
                    broken = true;
                    break;
                }
                runs_done += 1;
                runs_bytes += size;
                if (!builtin.is_test and monoMs() - t_said >= 5000) {
                    t_said = monoMs();
                    std.log.info("store: run files: {d} of {d} checked, {d} MiB in {d} s (segment {d})", .{ runs_done, runs.items.len, runs_bytes >> 20, (t_said - t_runs) / 1000, e });
                }
                const rp = try s.gpa.create(table.Run);
                rp.* = run;
                rp.view = view;
                s.pinFilters(rp);
                slot.runs[r].store(rp, .release);
                slot.nruns.store(@intCast(r + 1), .release);
                _ = s.runs_total.fetchAdd(1, .acq_rel);
                cover = h.end_loc;
                cover_anchor = if (h.has_anchor != 0) h.end_anchor else null;
                have_run = true;
            }
            for (runs.items) |x| if (x.epoch == e and x.run >= r) {
                var nb: [64]u8 = undefined;
                try s.backend.remove(io_mod.runName(&nb, e, x.run));
            };
        }
        if (!builtin.is_test and runs_done > 0) std.log.info("store: {d} run files, {d} MiB, {s} in {d} ms", .{ runs_done, runs_bytes >> 20, if (s.cfg.verify_index_on_open) "checked page by page" else "opened (headers only)", monoMs() - t_runs });
        if (kept.items.len > 0) try s.backend.syncDir();
        // The memtable takes everything after the runs.
        try s.swapMem(no_epoch, cover, cover_anchor);
        s.rcu.drainAll(s, reclaim);

        // Replay from the earliest position an index does not cover.
        var start: u64 = if (rebuild or kept.items.len == 0) (if (kept.items.len > 0) format.loc(kept.items[0], 0) else 0) else live_from;
        var anchor: ?u64 = if (rebuild) null else live_anchor;
        if (cover < start) {
            start = cover;
            anchor = cover_anchor;
        }
        if (rebuild) s.stats.rebuilt_index = true;
        // Lane fast-start: this is the slow path (every record of every segment read again); say so.
        if (!builtin.is_test) {
            if (rebuild) {
                std.log.warn("store: no usable live table; rebuilding it from the segment logs (reads every segment from location {x}: tens of minutes on a restored mainnet store)", .{start});
            } else if (format.epochOf(start) != format.epochOf(s.tailLoc()) or format.offsetOf(s.tailLoc()) -| format.offsetOf(start) > 1 << 30) {
                std.log.info("store: replaying the log from location {x} (tail {x})", .{ start, s.tailLoc() });
            }
        }
        // A rebuilt live table starts from the aged segments (their live objects only; nothing
        // in them is history any more). An aged segment holds only acknowledged groups (it was
        // scanned and its tail cut when it was last retained, and only the current segment is
        // appended to), so it must replay to its end: stopping early at a failed read or a
        // damaged group would drop every live object after it from the new table, and the
        // table is then persisted (store-dst io/196: one EIO in an aged segment lost v297).
        if (rebuild) for (s.aged.items) |e| {
            const slot = s.slotOf(e).?;
            const aend = slot.end.load(.monotonic);
            var off: u64 = 0;
            while (try s.groupAtE(slot, e, off, aend, null, true)) |g| {
                const group = g.g;
                const cnt = countGroup(group);
                // Sized from meta's last table, which held all of this: no growth expected.
                if (s.lt().count + cnt.obj + cnt.rm > table.liveLimit(s.lt().nslots)) return error.IndexFull;
                try s.applyGroup(e, off, group, 0, std.math.maxInt(u64));
                off += g.len;
                s.stats.replayed_groups += 1;
            }
            if (s.scan_err) |err| return err;
            if (off < aend) return error.Corrupt;
        };

        var chain: ?u64 = anchor;
        var stop = false;
        for (kept.items, 0..) |e, k| {
            const slot = s.slotOf(e).?;
            const fe = file_end[k];
            if (e < format.epochOf(start)) {
                slot.end.store(fe, .release);
                s.noteSegment(e, fe);
                s.ringAppend(e);
                continue;
            }
            if (stop) {
                // A later segment after a broken tail: only legal if it holds nothing durable.
                if (s.laterDurable(slot, e, 0, null)) return s.scan_err orelse error.Corrupt;
                try s.dropSegment(e);
                continue;
            }
            var off: u64 = if (e == format.epochOf(start)) format.offsetOf(start) else 0;
            if (slot.comp.load(.acquire) == null) {
                const v = viewOf(slot)[0..@min(fe, slot.view_len)];
                if (off < v.len) s.willNeed(v[off..]);
            }
            while (true) {
                const g = s.groupAt(slot, e, off, fe, chain, true) orelse break;
                const group = g.g;
                const l0 = format.loc(e, off);
                const cnt = countGroup(group);
                if (l0 >= cover and !s.curMem().fits(cnt.obj, cnt.tx, cnt.cp)) {
                    if (try s.sealMem(l0, chain)) {
                        s.stats.rebuilt_runs += 1;
                        try s.swapMem(no_epoch, l0, chain);
                        s.rcu.drainAll(s, reclaim);
                    }
                }
                if (l0 >= live_from and s.lt().count + cnt.obj + cnt.rm > table.liveLimit(s.lt().nslots)) {
                    try s.growLive(s.lt().count + cnt.obj + cnt.rm, l0, chain);
                    s.rcu.drainAll(s, reclaim);
                    live_from = l0;
                }
                try s.applyGroup(e, off, group, live_from, cover);
                chain = g.commit_checksum;
                s.last_commit = g.commit_checksum;
                s.committed1.store(g.seq + 1, .monotonic);
                off += g.len;
                s.stats.replayed_groups += 1;
            }
            const ctail = if (slot.comp.raw) |c| (try s.backend.size(slot.fd)) > std.mem.alignForward(u64, c.dir.raw.physEnd(), block) else false;
            if (off < fe or ctail) {
                // Torn or never-acknowledged tail. A valid commit beyond it whose group starts
                // after `off` means a durable group follows a damaged one: refuse. Commits of
                // groups starting at or before `off` are the torn in-flight group or stale bytes
                // of an earlier incarnation's in-flight group (written past a file size that was
                // not persisted, then exposed by a later extension); neither was acknowledged.
                // An unreadable chunk is not a torn one: fail the open, the bytes may be fine.
                if (s.scan_err) |err| return err;
                if (s.laterDurable(slot, e, off + block, format.loc(e, off))) return s.scan_err orelse error.Corrupt;
                s.stats.truncated_bytes += fe - off;
                if (slot.comp.raw) |c| {
                    // Back to the frame that starts the broken group (or the end of the good ones).
                    const d = c.dir.raw;
                    const cut = if (d.indexAt(off)) |i| d.entries[i].phys else std.mem.alignForward(u64, d.physEnd(), block);
                    dirTruncate(c, off);
                    try s.backend.truncate(slot.fd, @max(cut, if (off == 0) 0 else chunk.file_header_len));
                    if (off == 0) c.phys_tail = 0;
                } else try s.backend.truncate(slot.fd, off);
                try s.backend.sync(slot.fd);
                stop = true;
            }
            if (slot.comp.raw) |c| try s.dirPersist(e, c, true);
            // A run covering more than the durable log: acknowledged history is gone.
            {
                const n = slot.nruns.load(.monotonic);
                if (n > 0 and slot.runs[n - 1].load(.monotonic).?.header.end_loc > format.loc(e, off)) return error.Corrupt;
            }
            if (off == 0) {
                try s.dropSegment(e);
                stop = true;
                continue;
            }
            slot.end.store(off, .release);
            s.noteSegment(e, off);
            s.ringAppend(e);
        }
        // The chain anchor for the next group: the last commit scanned, or the anchor at the
        // replay start when nothing was left to scan.
        if (chain == null and s.has_segment) chain = s.lastCommitOf(s.slotOf(s.cur_epoch).?);
        s.last_commit = chain;
        // The live table may not cover log that no longer exists.
        if (!rebuild and live_from > s.tailLoc()) return error.Corrupt;
        // No acknowledged checkpoint may be missing.
        if (s.meta_committed) |mc| {
            const c1 = s.committed1.load(.monotonic);
            if (c1 == 0 or c1 - 1 < mc) return error.Corrupt;
        }
        s.rcu.drainAll(s, reclaim);
        s.since_flush = s.stats.replayed_groups;
        // Remap the newest segment with the full reservation for appends.
        if (s.has_segment and s.slotOf(s.cur_epoch).?.comp.raw == null) {
            const slot = s.slotOf(s.cur_epoch).?;
            s.backend.unmap(slot.fd, viewOf(slot));
            // Never smaller than what is already durable (readers index up to `end`).
            const v = try s.backend.map(slot.fd, @max(@max(s.cfg.segment_reserve, s.buf.len), s.tail + s.buf.len));
            slot.base.store(@intFromPtr(v.ptr), .release);
            slot.view_len = v.len;
        }
        if (rebuild) try s.persistWholeLive(s.live.raw.?, s.tailLoc(), s.last_commit);
        s.adviseAll();
    }

    /// Checksum of the newest commit record of a segment (a full scan; recovery's rare path).
    fn lastCommitOf(s: *Store, slot: *SegSlot) ?u64 {
        const e = slot.epoch.load(.monotonic);
        if (slot.comp.raw) |c| {
            // The last chunk ends a group: its last commit record is the segment's last.
            const d = c.dir.raw;
            const es = d.slice();
            if (es.len == 0) return null;
            s.gbuf.clearRetainingCapacity();
            s.chunkInto(c, es[es.len - 1], &s.gbuf) catch return null;
            const g = s.gbuf.items;
            var p: usize = 0;
            var last: ?u64 = null;
            while (p + format.short_len <= g.len) {
                const h = format.short(g[p..]);
                if (h.size == 0 and @intFromEnum(h.kind) == 0) break;
                if (h.kind == .commit) last = h.checksum;
                p += format.lenOf(h.kind, h.size);
            }
            return last;
        }
        const data = viewOf(slot)[0..slot.end.load(.monotonic)];
        var off: u64 = 0;

        var last: ?u64 = null;
        while (scanGroup(data, e, off, null)) |g| {
            last = g.commit_checksum;
            off += g.len;
        }
        return last;
    }

    fn noteSegment(s: *Store, e: u64, end: u64) void {
        if (!s.has_segment or e >= s.cur_epoch) {
            s.has_segment = true;
            s.cur_epoch = e;
            s.tail = end;
        }
    }

    fn dropSegment(s: *Store, e: u64) Error!void {
        const slot = s.slotOf(e).?;
        const n = slot.nruns.load(.monotonic);
        s.unpublishSlot(slot, false);
        try s.removeEpochFiles(e, n);
        try s.backend.syncDir();
    }

    // ------------------------------------------------------------------ writing

    /// Starts the commit group of checkpoint `seq` in `epoch`. Single writer.
    pub fn begin(s: *Store, seq: u64, epoch: u64) Error!*Batch {
        if (s.batch_active) return error.BatchActive;
        if (s.poisoned) return error.Poisoned;
        const c1 = s.committed1.load(.monotonic);
        if (c1 != 0 and seq < c1) return error.SeqRegression;
        if (s.has_segment and epoch < s.cur_epoch) return error.EpochRegression;
        if (epoch > format.max_epoch) return error.EpochRegression;
        try s.startBatch(seq, epoch);
        return &s.batch;
    }

    fn startBatch(s: *Store, seq: u64, epoch: u64) Error!void {
        const new_segment = !s.has_segment or epoch != s.cur_epoch;
        if (new_segment) {
            try s.mapSegment(epoch, true);
            try s.backend.syncDir();
        }
        const base = if (new_segment) 0 else s.tail;
        const slot = s.slotOf(epoch).?;
        const comp = slot.comp.raw != null;
        // Room for a full group in the mapping: grow it (doubling) if needed.
        if (!comp and base + s.buf.len > slot.view_len) try s.growMapping(slot, base + s.buf.len);
        const seg_room: u64 = (format.offset_mask + 1) -| base;
        s.batch = .{
            .store = s,
            .seq = seq,
            .epoch = epoch,
            .base = base,
            .limit = @intCast(if (comp) @min(@as(u64, s.buf.len), seg_room) else @min(@as(u64, s.buf.len), seg_room, slot.view_len - base)),
            .new_segment = new_segment,
        };
        s.batch_active = true;
        s.bmap.reset();
        s.pend_links.clearRetainingCapacity();
        s.xref_targets.clearRetainingCapacity();
        if (new_segment) {
            const sf: format.SegmentFixed = .{ .epoch = epoch };
            _ = try s.batch.append(.segment, 0, seq, 0, &.{std.mem.asBytes(&sf)});
        }
    }

    /// Replaces the segment's mapping with a larger one; the old one is unmapped after the
    /// grace period (readers may hold views into it).
    fn growMapping(s: *Store, slot: *SegSlot, need: u64) Error!void {
        var n = @max(slot.view_len, block);
        while (n < need) n *= 2;
        n = @min(n, format.offset_mask + 1);
        const v = try s.backend.map(slot.fd, n);
        if (v.len <= slot.view_len) {
            // The backend cannot map more (simulated file capacity): keep the old view.
            s.backend.unmap(slot.fd, v);
            return;
        }
        const old = viewOf(slot);
        s.adviseRandom(v);
        slot.base.store(@intFromPtr(v.ptr), .release);
        slot.view_len = v.len;
        s.retire(.{ .view = .{ .fd = slot.fd, .view = old, .close = false } });
        s.stats.segment_remaps += 1;
    }

    /// Abandons the batch (nothing was written).
    pub fn abort(s: *Store, b: *Batch) void {
        std.debug.assert(b == &s.batch);
        if (b.new_segment) {
            const slot = s.slotOf(b.epoch).?;
            s.unpublishSlot(slot, true);
            var nb: [64]u8 = undefined;
            s.backend.remove(io_mod.segName(&nb, b.epoch)) catch {};
        }
        s.bmap.reset();
        s.batch_active = false;
    }

    /// Appends the commit record and makes the group durable (one write + one sync). On return
    /// the checkpoint is durable and visible to new snapshots.
    pub fn commit(s: *Store, b: *Batch) Error!void {
        std.debug.assert(b == &s.batch and s.batch_active);
        const t_commit = clock.now();
        defer {
            s.bmap.reset();
            s.batch_active = false;
        }
        for (s.pend_links.items) |pl| {
            if (s.xref_targets.contains(pl.loc)) continue;
            const f: format.LinkFixed = .{ .id = pl.id, .version = aux_superseded };
            _ = try b.append(.link, 0, b.seq, pl.loc, &.{std.mem.asBytes(&f)});
            b.n_obj += 1;
        }
        s.pend_links.clearRetainingCapacity();
        const start = format.loc(b.epoch, b.base);
        const cf: format.CommitFixed = .{
            .epoch = b.epoch,
            .group_start = start,
            .records = b.records + 1,
            .group_hash = b.group_hash,
            .prev_commit = s.last_commit orelse 0,
        };
        const commit_off = b.len;
        _ = try b.append(.commit, 0, b.seq, 0, &.{std.mem.asBytes(&cf)});
        const padded = std.mem.alignForward(usize, b.len, block);
        std.debug.assert(padded <= b.limit);
        @memset(s.buf[b.len..padded], 0);
        const slot = s.slotOf(b.epoch).?;
        // Index room before anything is written (a failure here leaves the disk unchanged).
        if (!s.curMem().fits(b.n_obj, b.n_tx, b.n_cp)) {
            // Nothing of the group is written yet and the memtable is untouched on failure.
            // The run ends where the log ends now: in the current segment, never at the start
            // of one this group creates (which recovery drops if the group is lost).
            const end = if (s.has_segment) format.loc(s.cur_epoch, s.tail) else start;
            if (try s.sealMem(end, s.last_commit)) try s.swapMem(no_epoch, end, s.last_commit);
        }
        const need = s.lt().count + b.n_obj + b.n_rm;
        if (s.bulk == null and need > table.liveLimit(s.lt().nslots)) s.growLive(need, s.tailLoc(), s.last_commit) catch |e| {
            s.poisoned = true;
            return e;
        };
        const cseg = slot.comp.raw;
        if (cseg) |c| {
            // Compressed: the group's chunks, after the file header for a segment's first group.
            s.pbuf.clearRetainingCapacity();
            s.pents.clearRetainingCapacity();
            const p0 = c.phys_tail;
            if (p0 == 0) {
                var fh: chunk.FileHeader = .{ .epoch = b.epoch };
                fh.checksum = fh.sum();
                s.pbuf.appendNTimes(s.gpa, 0, chunk.file_header_len) catch return error.OutOfMemory;
                @memcpy(s.pbuf.items[0..@sizeOf(chunk.FileHeader)], std.mem.asBytes(&fh));
            }
            if (s.enc.threads == 0) s.enc.threads = if (s.cfg.compress_threads == 0) chunk.defaultThreads() else @min(s.cfg.compress_threads, chunk.Encoder.max_threads);
            const zd = s.dictFor(c, b.epoch) catch |e| {
                s.poisoned = true;
                return e;
            };
            s.enc.encodeGroup(s.gpa, s.cfg.chunk_bytes, s.buf[0..padded], b.base, &s.pbuf, p0, &s.pents, if (s.cfg.elide_sums) b.epoch else null, zd) catch return error.OutOfMemory;
            s.backend.writeSync(slot.fd, p0, s.pbuf.items) catch |e| {
                s.poisoned = true;
                return e;
            };
            s.dirAppend(c, s.pents.items) catch |e| {
                s.poisoned = true;
                return e;
            };
            c.phys_tail = p0 + s.pbuf.items.len;
            // Recent records are the hot ones: seed the cache with this group's chunks.
            if (padded <= 4 << 20) for (s.pents.items) |en| {
                const d = s.cache.mem.dupe(u8, s.buf[en.ls - b.base ..][0..en.ll]) catch break;
                _ = s.cache.put((c.id << format.offset_bits) | en.ls, d, null) catch break;
            };
            s.stats.bytes_written_phys += s.pbuf.items.len;
        } else s.backend.writeSync(slot.fd, b.base, s.buf[0..padded]) catch |e| {
            s.poisoned = true;
            return e;
        };
        const commit_sum = format.header(s.buf[commit_off..]).checksum;

        // Durable: publish.
        if (b.new_segment) {
            s.has_segment = true;
            s.cur_epoch = b.epoch;
            s.ringAppend(b.epoch);
        }
        s.tail = b.base + padded;
        s.last_group_base = b.base;
        slot.end.store(s.tail, .release);
        // The group is durable: an index failure here leaves memory behind the disk.
        s.applyGroup(b.epoch, b.base, s.buf[0..padded], 0, 0) catch |e| {
            s.poisoned = true;
            return e;
        };
        if (cseg != null) s.histFeed(s.buf[0..padded]);
        s.last_commit = commit_sum;
        if (cseg) |c| s.dirPersist(b.epoch, c, false) catch |e| {
            s.poisoned = true;
            return e;
        };
        if (!b.carry) s.committed1.store(b.seq + 1, .release);
        s.stats.commits += 1;
        s.stats.bytes_appended += padded;
        s.since_flush += 1;
        s.maybeFlush() catch |e| {
            s.poisoned = true;
            return e;
        };
        s.rcuPoll();
        s.noteCommit(clock.now() -| t_commit);
    }

    const GroupCount = struct { obj: u64 = 0, rm: u64 = 0, tx: u64 = 0, cp: u64 = 0 };

    fn countGroup(group: []const u8) GroupCount {
        var c: GroupCount = .{};
        var off: usize = 0;
        while (off + format.short_len <= group.len) {
            const h = format.short(group[off..]);
            switch (h.kind) {
                .object, .object_c, .link, .xref => c.obj += 1,
                .remove => c.rm += 1,
                .tx => c.tx += 1,
                .checkpoint => c.cp += 1,
                .commit => break,
                else => {},
            }
            off += format.lenOf(h.kind, h.size);
        }
        return c;
    }

    /// Applies one durable group's records to the indexes (shared by commit and recovery):
    /// the live table for locations >= live_min, the memtable for locations >= mem_min.
    fn applyGroup(s: *Store, epoch: u64, base: u64, group: []const u8, live_min: u64, mem_min: u64) Error!void {
        const m = s.curMem();
        const t = s.lt();
        var off: usize = 0;
        while (off + format.short_len <= group.len) {
            const h = format.short(group[off..]);
            const l = format.loc(epoch, base + off);
            switch (h.kind) {
                .object => {
                    const f = format.fixed(format.ObjectFixed, group[off..]);
                    if (l >= live_min and h.flags & format.flag_historical == 0) try s.liveSet(t, &f.id, l);
                    if (l >= mem_min) try m.ver.put(s.verKey(&f.id, f.version), l);
                },
                .object_c => {
                    const c = s.cfg.codec orelse return error.Corrupt;
                    if (off + format.short_len + h.size > group.len) return error.Corrupt;
                    const k = c.key(group[off + format.short_len ..][0..h.size]) orelse return error.Corrupt;
                    // Not in the version index: while live the live table finds it, and once
                    // superseded the newer records' previous-version links do (objectAtChecked).
                    // The restored live set would otherwise cost ~30 GB of runs.
                    if (l >= live_min and h.flags & format.flag_historical == 0) try s.liveSet(t, &k.id, l | table.compact);
                },
                .remove => {
                    const f = format.fixed(format.RemoveFixed, group[off..]);
                    if (l >= live_min) try s.liveSet(t, &f.id, l | table.tomb);
                },
                .link => if (l >= mem_min) {
                    const f = format.fixed(format.LinkFixed, group[off..]);
                    try m.ver.put(s.verKey(&f.id, f.version), format.header(group[off..]).a);
                },
                // The version index names the xref itself: its retention is the xref's segment.
                .xref => if (l >= mem_min) {
                    if (h.size != @sizeOf(format.XrefFixed) or off + format.short_len + h.size > group.len) return error.Corrupt;
                    const f = format.fixedShort(format.XrefFixed, group[off..]);
                    try m.ver.put(s.verKey(&f.id, f.version), l);
                },
                .tx => if (l >= mem_min) {
                    const f = format.fixed(format.TxFixed, group[off..]);
                    try m.tx.put(txKey(&f.digest), l);
                },
                .checkpoint => if (l >= mem_min) try m.cps.append(format.header(group[off..]).seq, l),
                .segment => {
                    if (h.size != @sizeOf(format.SegmentFixed)) return error.Corrupt;
                    const f = format.fixed(format.SegmentFixed, group[off..]);
                    if (!std.mem.eql(u8, &f.magic, "ZUISEG02") or f.algo != cs.current_algo or f.epoch != epoch) return error.Corrupt;
                },
                .commit => return,
                else => {},
            }
            off += format.lenOf(h.kind, h.size);
        }
    }

    /// Decodes an object record (full or compact) returned by `record`.
    pub fn objRec(s: *const Store, rec: []const u8) Error!ObjRec {
        const k = format.short(rec).kind;
        switch (k) {
            .object => {
                if (rec.len < format.header_len + @sizeOf(format.ObjectFixed)) return error.Corrupt;
                const h = format.header(rec);
                const f = format.fixed(format.ObjectFixed, rec);
                return .{ .id = f.id, .version = f.version, .seq = h.seq, .a = h.a, .flags = h.flags, .bytes = rec[format.header_len + @sizeOf(format.ObjectFixed) ..], .stored_digest = &f.digest };
            },
            .object_c => {
                const c = s.cfg.codec orelse return error.Corrupt;
                const bytes = rec[format.short_len..];
                const key = c.key(bytes) orelse return error.Corrupt;
                return .{ .id = key.id, .version = key.version, .seq = 0, .a = 0, .flags = format.short(rec).flags, .bytes = bytes, .stored_digest = null };
            },
            else => return error.Corrupt,
        }
    }

    /// Whether index entries (memtable and runs) may point at `l`: locations in segments that
    /// left the history window are no longer history (only the live table reaches them).
    fn inWindow(s: *const Store, l: u64) bool {
        return format.epochOf(l) >= s.oldest_epoch.load(.acquire);
    }

    /// `objInWindow` as of the durable floors (age-out).
    fn objInWindowDurable(s: *const Store, l: u64) bool {
        return s.epochInObjWindowDurable(format.epochOf(l));
    }

    fn epochInObjWindowDurable(s: *const Store, e: u64) bool {
        return e >= @min(s.oldest_epoch.load(.acquire), s.dfloors.oldest.load(.acquire)) and e >= @min(s.obj_floor_epoch.load(.acquire), s.dfloors.obj_epoch.load(.acquire));
    }

    /// Object versions: the aged floor, and the object floor's epoch (whole segments).
    fn objInWindow(s: *const Store, l: u64) bool {
        return s.epochInObjWindow(format.epochOf(l));
    }

    fn epochInObjWindow(s: *const Store, e: u64) bool {
        return e >= s.oldest_epoch.load(.acquire) and e >= s.obj_floor_epoch.load(.acquire);
    }

    /// Checkpoint-class records (checkpoints, transactions, aux records) written by checkpoint
    /// `seq`: the checkpoint floor.
    fn cpInWindow(s: *const Store, seq: u64) bool {
        return seq >= s.cp_floor.load(.acquire);
    }

    pub fn verKey(s: *const Store, id: *const [32]u8, version: u64) u64 {
        var buf: [40]u8 = undefined;
        buf[0..32].* = id.*;
        std.mem.writeInt(u64, buf[32..40], version, .little);
        return cs.hash(s.seed ^ 0x76657273, &buf);
    }

    pub fn txKey(digest: *const [32]u8) u64 {
        return std.mem.readInt(u64, digest[0..8], .little);
    }

    // ------------------------------------------------------------------ retention

    /// Moves the history window's floor to `epoch` (CONTRACTS 6.8, liveness retention).
    /// Checkpoints, transactions, aux records and object versions in older segments stop being
    /// readable and those segments' runs are deleted, but the segments stay where they are for
    /// as long as they hold live objects: nothing is copied here, so following never pauses on
    /// it. Old live objects (the restored live set above all) are never rewritten; `cleanStep`
    /// later copies the few live records out of segments that are mostly dead and deletes them.
    pub fn ageOut(s: *Store, epoch: u64) Error!PruneReport {
        if (s.batch_active) return error.BatchActive;
        if (s.poisoned) return error.Poisoned;
        var rep: PruneReport = .{};
        const t0 = clock.now();
        if (!s.has_segment) return rep;
        if (epoch > s.cur_epoch) return error.PruneCurrent;
        const old = s.oldest_epoch.load(.monotonic);
        if (epoch <= old) return rep;
        errdefer s.poisoned = true;
        // Durable first: meta names the new floor, so recovery treats older segments as aged
        // and deletes their runs if this step stops halfway.
        s.oldest_epoch.store(epoch, .release);
        try s.flushLive();
        var e = old;
        while (e < epoch) : (e += 1) {
            const slot = s.slotOf(e) orelse continue;
            const n = slot.nruns.load(.monotonic);
            for (slot.runs[0..n]) |*rp| if (rp.swap(null, .acq_rel)) |r| s.retire(.{ .run = r });
            _ = s.runs_total.fetchSub(n, .acq_rel);
            slot.nruns.store(0, .release);
            var nb: [64]u8 = undefined;
            for (0..n) |r| try s.deferFree(io_mod.runName(&nb, e, r));
            rep.runs_dropped += n;
            s.aged.append(s.gpa, e) catch return error.OutOfMemory;
            rep.segments_aged += 1;
        }
        var head = s.ep_head.load(.monotonic);
        const tail = s.ep_tail.load(.monotonic);
        while (head < tail and s.ep_ring[head & s.seg_mask].load(.monotonic) < epoch) head += 1;
        s.ep_head.store(head, .release);
        try s.backend.syncDir();
        s.clean.due = true;
        // Checkpoints in the aged segments are gone: so are their transaction fixes.
        if (s.tx_fix.count() > 0 or s.list_fix.count() > 0 or s.cert_fix.count() > 0) {
            var snap = s.snapshot();
            const low = snap.lowestCheckpoint();
            snap.release();
            if (low) |l| s.dropFixesBelow(l);
        }
        s.rcuPoll();
        rep.ns = clock.now() - t0;
        return rep;
    }

    /// `ageOut` to `retention_epochs` before the current epoch.
    pub fn ageRetained(s: *Store) Error!PruneReport {
        if (!s.has_segment or s.cur_epoch < s.cfg.retention_epochs) return .{};
        return s.ageOut(s.cur_epoch - s.cfg.retention_epochs);
    }

    /// sui-node's two pruning watermarks (node retention.zig computes them with sui-node's
    /// formula). Readers see the new floors at once: checkpoints, transactions and
    /// checkpoint-class aux records at or below `cp_pruned`, and object versions in segments
    /// below `obj_epoch`, read as absent. Segments below both `cp_epoch` (the epoch of the first
    /// unpruned checkpoint) and `obj_epoch` age out (`ageOut`: runs dropped, kept for their live
    /// objects, cleaned by `cleanStep`). Floors only rise. They are made durable with the next
    /// meta write (a live-table flush or an age-out); a crash before that brings back a lower
    /// floor over data that is still on disk (nothing below a durable floor is ever removed).
    pub const Floors = struct {
        cp_pruned: ?u64 = null,
        obj_pruned: ?u64 = null,
        cp_epoch: u64 = 0,
        obj_epoch: u64 = 0,
    };

    pub fn setFloors(s: *Store, f: Floors) Error!PruneReport {
        if (s.batch_active) return error.BatchActive;
        if (s.poisoned) return error.Poisoned;
        if (f.cp_pruned) |hp| if (hp + 1 > s.cp_floor.load(.monotonic)) s.cp_floor.store(hp + 1, .release);
        s.dropFixesBelow(s.cp_floor.load(.monotonic));
        if (f.obj_pruned) |hp| if (hp + 1 > s.obj_floor.load(.monotonic)) s.obj_floor.store(hp + 1, .release);
        if (!s.has_segment) return .{};
        const oe = @min(f.obj_epoch, s.cur_epoch);
        if (oe > s.obj_floor_epoch.load(.monotonic)) s.obj_floor_epoch.store(oe, .release);
        const age = @min(@min(f.cp_epoch, oe), s.cur_epoch);
        if (age > s.oldest_epoch.load(.monotonic)) return s.ageOut(age);
        return .{};
    }

    /// One bounded step of segment cleaning, for the writer between checkpoints. A step reads
    /// at most about `budget` bytes: first a pass over the live table counting the live
    /// objects of each aged segment, then, for the sparsest aged segment whose live objects
    /// fill less than `clean_live_pct` of it, a sweep that copies its live records into the
    /// current segment (compact records when the store has a codec) and drops its tombstones;
    /// at the end of the sweep the segment is deleted. `rep.idle` when there is nothing to do.
    /// Each object is copied at most once per segment it lands in, and only out of a segment
    /// that is at least three quarters dead, so the copy cost stays a fraction of the space
    /// reclaimed; dense segments are never touched.
    pub fn cleanStep(s: *Store, budget: u64) Error!PruneReport {
        return s.cleanStepUntil(budget, 0);
    }

    /// `cleanStep` that also stops at `deadline` (`clock.now()` nanoseconds; 0: none). A step
    /// still does at least one unit of work (one 1 MiB window of the count pass, one commit group
    /// of the sweep), so a deadline already past slows cleaning down but never stops it. The
    /// node gives each step a share of the time the follower spent elsewhere (lane
    /// catchup-1306): a step bounded only by bytes took 11 to 12 s per checkpoint on a cold
    /// store, one QD1 live-table fault per swept record.
    pub fn cleanStepUntil(s: *Store, budget: u64, deadline: u64) Error!PruneReport {
        if (s.batch_active) return error.BatchActive;
        if (s.poisoned) return error.Poisoned;
        var rep: PruneReport = .{};
        const t0 = clock.now();
        errdefer s.poisoned = true;
        switch (s.clean.phase) {
            .idle => {
                if (!s.clean.due or s.aged.items.len == 0) {
                    s.clean.due = false;
                    rep.idle = true;
                } else {
                    s.clean.due = false;
                    try s.startCount();
                }
            },
            .count => try s.countStep(@max(budget, page_size), deadline),
            .sweep => {
                const e = s.clean.target;
                if (s.slotOf(e) == null) {
                    s.clean.phase = .idle;
                } else {
                    s.clean.off = try s.sweepUntil(e, s.clean.off, @max(budget, block), deadline, &rep);
                    if (s.clean.off >= s.slotOf(e).?.end.load(.monotonic)) {
                        try s.finishSegment(e, &rep);
                        s.clean.phase = .idle;
                        s.clean.due = s.aged.items.len > 0;
                    }
                }
            },
        }
        rep.ns = clock.now() - t0;
        return rep;
    }

    fn startCount(s: *Store) Error!void {
        s.gpa.free(s.clean.counts);
        s.clean.counts = &.{};
        s.clean.counts = s.gpa.alloc(u64, s.aged.items.len) catch return error.OutOfMemory;
        @memset(s.clean.counts, 0);
        s.clean.live = s.live.raw;
        s.clean.page = 0;
        s.clean.ahead = 0;
        s.clean.phase = .count;
    }

    fn tablePages(pages: []align(page_size) const table.Page, from: u64, to: u64) []const u8 {
        if (to <= from) return &.{};
        const p: [*]const u8 = @ptrCast(&pages[from]);
        return p[0 .. (to - from) * page_size];
    }

    fn agedIndex(s: *const Store, e: u64) ?usize {
        return std.sort.binarySearch(u64, s.aged.items, e, struct {
            fn cmp(k: u64, x: u64) std.math.Order {
                return std.math.order(k, x);
            }
        }.cmp);
    }

    /// Pages of the count pass between deadline checks (1 MiB of table).
    const count_window: u64 = 256;

    fn countStep(s: *Store, budget: u64, deadline: u64) Error!void {
        const h = s.live.raw.?;
        if (h != s.clean.live or s.clean.counts.len != s.aged.items.len) return s.startCount();
        const pages = h.t.pages;
        const n = @max(1, budget / page_size);
        const want = @min(pages.len, s.clean.page + n);
        const floor = s.oldest_epoch.load(.monotonic);
        // The table is mapped MADV_RANDOM: walked page by page, this pass was one blocking 4 KiB
        // read per page at queue depth 1 on the follower's thread (34 GB at mainnet scale: 8.7M
        // reads, 2 to 3 checkpoints/s for the ~2,100 checkpoints a pass spans in a 12 GB
        // cgroup, after every start and every age-out; lane catchup-io). Ask for this window
        // (when the last step did not) and the next one as large asynchronous reads, then mark
        // the walked pages cold so the pass does not push the lookups' hot pages out.
        const real = s.backend == .real and s.cfg.clean_readahead;
        if (real) {
            if (s.clean.page == 0 or s.clean.ahead < want) io_mod.willNeed(tablePages(pages, @max(s.clean.page, s.clean.ahead), want));
            const next = @min(pages.len, want + n);
            if (next > @max(want, s.clean.ahead)) io_mod.willNeed(tablePages(pages, @max(want, s.clean.ahead), next));
            s.clean.ahead = @max(s.clean.ahead, next);
        }
        // In windows of `count_window` pages, stopping at the deadline after the first: a cold
        // table read at 4 KiB per fault must not hold the follower for the whole budget.
        var end = s.clean.page;
        while (end < want) {
            const w_end = @min(want, end + count_window);
            for (pages[end..w_end]) |*pg| for (pg.locs) |l| {
                if (l == 0 or l & table.tomb != 0) continue;
                const e = format.epochOf(l);
                if (e >= floor) continue;
                if (s.agedIndex(e)) |i| s.clean.counts[i] += 1;
            };
            end = w_end;
            if (pastDeadline(deadline) and end < want) {
                s.clean.cut += 1;
                break;
            }
        }
        if (real) io_mod.cold(tablePages(pages, s.clean.page, end));
        s.clean.page = end;
        if (end < pages.len) return;
        // Pick the sparsest segment under the threshold.
        var best: ?usize = null;
        var best_ppm: u64 = std.math.maxInt(u64);
        for (s.aged.items, 0..) |e, i| {
            const slot = s.slotOf(e) orelse continue;
            const size = @max(slot.end.load(.monotonic), 1);
            const live_b = s.clean.counts[i] *| s.cfg.clean_record_bytes;
            if (live_b *| 100 >= size *| s.cfg.clean_live_pct) continue;
            const ppm = live_b *| 1_000_000 / size;
            if (ppm < best_ppm) {
                best_ppm = ppm;
                best = i;
            }
        }
        if (best) |i| {
            s.clean.target = s.aged.items[i];
            s.clean.off = 0;
            s.clean.phase = .sweep;
        } else s.clean.phase = .idle;
    }

    /// Writes one carried copy of `o` into the open carry batch.
    fn carryOne(s: *Store, o: *const ObjRec) Error!void {
        const b = &s.batch;
        const compact = if (s.cfg.codec) |c| if (c.key(o.bytes)) |k| k.version == o.version and std.mem.eql(u8, &k.id, &o.id) else false else false;
        if (compact) {
            _ = try b.append(.object_c, format.flag_carried, 0, 0, &.{o.bytes});
        } else {
            const f: format.ObjectFixed = .{ .id = o.id, .version = o.version, .digest = o.digest() };
            _ = try b.append(.object, format.flag_carried, o.seq, 0, &.{ std.mem.asBytes(&f), o.bytes });
        }
        b.n_obj += 1;
    }

    const Carry = union(enum) {
        obj: *const ObjRec,
        tomb: struct { f: *align(1) const format.RemoveFixed, seq: u64 },
        hist: struct { o: *const ObjRec, anchor: u64 },
    };

    /// A carried historical copy of a superseded version an in-window xref names: indexed by
    /// (id, version) like any full record, and readable only while the xref at `anchor` (header
    /// `b`) is in the window, so cleaning does not lengthen the version's retention.
    fn carryHist(s: *Store, o: *const ObjRec, anchor: u64) Error!void {
        const b = &s.batch;
        const f: format.ObjectFixed = .{ .id = o.id, .version = o.version, .digest = o.digest() };
        _ = try b.appendB(.object, format.flag_historical | format.flag_carried, o.seq, 0, anchor, &.{ std.mem.asBytes(&f), o.bytes });
        b.n_obj += 1;
    }

    /// The newest in-window xref naming the record at `l` as (id, version), or null (then the
    /// record is history nobody reads any more). A carried copy whose anchor is still in the
    /// window keeps that anchor.
    fn xrefAnchor(s: *Store, snap: *const Snapshot, rec: []const u8, o: *const ObjRec, l: u64) ?u64 {
        return s.xrefAnchorAt(snap, rec, o, l, false);
    }

    /// `xrefAnchor`; `durable`: the window of the durable floors (age-out frees nothing a meta on
    /// disk still keeps in the window).
    fn xrefAnchorAt(s: *Store, snap: *const Snapshot, rec: []const u8, o: *const ObjRec, l: u64, durable: bool) ?u64 {
        if (o.version > std.math.maxInt(i64)) return null; // aux keyspace
        var best: ?u64 = null;
        if (format.short(rec).kind == .object) {
            const hb = format.header(rec).b;
            if (hb != 0 and (if (durable) s.objInWindowDurable(hb) else s.objInWindow(hb))) best = hb;
        }
        var it = Snapshot.KeyLocs.init(snap, .ver, s.verKey(&o.id, o.version));
        while (it.next()) |x| {
            if (!(if (durable) s.objInWindowDurable(x) else s.objInWindow(x)) or format.epochOf(x) == format.epochOf(l)) continue;
            const xr = s.record(x, snap.cepoch) catch continue;
            if (format.short(xr).kind != .xref or xr.len != format.short_len + @sizeOf(format.XrefFixed)) continue;
            const f = format.fixedShort(format.XrefFixed, xr);
            if (f.target != l or f.version != o.version or !std.mem.eql(u8, &f.id, &o.id)) continue;
            if (best == null or x > best.?) best = x;
        }
        return best;
    }

    /// Whether a link record whose index entry is inside the object window (as of the durable
    /// floors) names the compact record at `l` of object `id`: `Snapshot.objectFind` then
    /// still finds that version, so age-out must not free it. (A store without read sets, an
    /// edge, has no cross-reference for a restored version its checkpoints consumed: only this
    /// link.)
    fn linkAnchored(s: *Store, snap: *const Snapshot, id: *const [32]u8, l: u64) bool {
        var lk = Snapshot.KeyLocs.init(snap, .ver, s.verKey(id, aux_superseded));
        while (lk.next()) |x| {
            if (x == l and s.epochInObjWindowDurable(lk.epoch())) return true;
        }
        return false;
    }

    /// Writes one carried record (a live object, or a live tombstone that must outlive its
    /// segment) into the carry batch, opening it, or committing a full one and opening the next.
    fn carryRec(s: *Store, carrying: *bool, cseq: u64, r: Carry) Error!void {
        var tries: u2 = 0;
        while (true) : (tries += 1) {
            if (!carrying.*) {
                try s.startBatch(cseq, s.cur_epoch);
                s.batch.carry = true;
                carrying.* = true;
            }
            const res = switch (r) {
                .obj => |o| s.carryOne(o),
                .tomb => |t| s.carryTomb(t.f, t.seq),
                .hist => |hh| s.carryHist(hh.o, hh.anchor),
            };
            res catch |err| switch (err) {
                error.BatchFull, error.SegmentFull => {
                    if (tries > 0) return err;
                    carrying.* = false;
                    try s.commit(&s.batch);
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    /// A carried tombstone: the same payload and checkpoint, no previous link (nothing older
    /// than it is ever read through it: `latest` stops at a visible tombstone).
    fn carryTomb(s: *Store, f: *align(1) const format.RemoveFixed, seq: u64) Error!void {
        const b = &s.batch;
        const copy: format.RemoveFixed = f.*;
        _ = try b.append(.remove, format.flag_carried, seq, 0, &.{std.mem.asBytes(&copy)});
        b.n_rm += 1;
    }

    /// Sweeps aged segment `e` from `from` for about `budget` bytes (whole groups): live
    /// records are carried into the current segment, live tombstones are dropped. Every object
    /// and remove record is fully checked before its id is trusted: a damaged id would miss its
    /// live-table entry and the object would vanish with the segment, so damage fails instead.
    /// Returns the offset reached.
    fn sweepSome(s: *Store, e: u64, from: u64, budget: u64, rep: *PruneReport) Error!u64 {
        return s.sweepUntil(e, from, budget, 0, rep);
    }

    /// `deadline` (0: none) already passed: stop after the work done so far.
    fn pastDeadline(deadline: u64) bool {
        return deadline != 0 and clock.now() >= deadline;
    }

    /// Asks for the live-table pages that the records of group `gv` (up to `commit_off`) will
    /// look up, all at once (MADV_WILLNEED, asynchronous), so the sweep's lookups wait on reads
    /// already in flight instead of one 4 KiB read at a time. On the restored mainnet store the
    /// table is 34 GB, mapped MADV_RANDOM and mostly not cached: every swept record was a
    /// blocking fault (16k per 16 MiB step, 11 to 12 s per checkpoint, lane catchup-1306). Ids
    /// are read without checks here: a damaged record asks for a useless page, nothing else (the
    /// sweep checks every record before trusting its id). Real files only; returns the pages
    /// asked for.
    fn tableAhead(s: *Store, gv: []const u8, commit_off: u64) u64 {
        if (s.backend != .real) return 0;
        const t = s.lt();
        var asked: u64 = 0;
        var last: u64 = std.math.maxInt(u64);
        var p: u64 = 0;
        while (p + format.short_len <= commit_off) {
            const h = format.short(gv[p..]);
            const len = format.lenOf(h.kind, h.size);
            if (len == 0 or p + len > gv.len) break;
            const rec = gv[p..][0..len];
            const id: ?[32]u8 = switch (h.kind) {
                .object => if (len >= format.header_len + @sizeOf(format.ObjectFixed) and h.flags & format.flag_historical == 0)
                    format.fixed(format.ObjectFixed, rec).id
                else
                    null,
                .object_c => if (h.flags & format.flag_historical != 0) null else if (s.cfg.codec) |c| if (c.key(rec[format.short_len..])) |k| k.id else null else null,
                .remove => if (len >= format.header_len + @sizeOf(format.RemoveFixed)) format.fixed(format.RemoveFixed, rec).id else null,
                else => null,
            };
            p += len;
            const idv = id orelse continue;
            const pg = t.homeSlot(&idv) / table.per_page;
            if (pg == last or pg >= t.pages.len) continue;
            last = pg;
            // A page the writer holds dirty is in memory already.
            if (@atomicLoad(u64, &t.dirty[pg / 64], .monotonic) & (@as(u64, 1) << @intCast(pg % 64)) != 0) continue;
            io_mod.willNeed(tablePages(t.pages, pg, pg + 1));
            asked += 1;
        }
        return asked;
    }

    /// Asks for the compressed frames of logical `[from, to)` of a compressed segment
    /// (POSIX_FADV_WILLNEED; frames moved to the sidecar by the ager are not in file order, so
    /// the kernel's sequential read-ahead misses them).
    fn framesAhead(s: *Store, c: *CSeg, from: u64, to: u64) void {
        if (s.backend != .real) return;
        const d = c.dir.load(.acquire);
        const es = d.slice();
        var lo: usize = 0;
        var hi: usize = es.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (es[mid].end() <= from) lo = mid + 1 else hi = mid;
        }
        var i = lo;
        while (i < es.len and es[i].ls < to) : (i += 1) {
            const en = es[i];
            const fd = if (chunk.isSide(en.phys)) (c.side_fd orelse continue) else c.fd;
            s.backend.willNeedFile(fd, en.phys & ~chunk.side_bit, chunk.frame_len + en.bl);
        }
    }

    fn sweepUntil(s: *Store, e: u64, from: u64, budget: u64, deadline: u64, rep: *PruneReport) Error!u64 {
        const slot = s.slotOf(e) orelse return error.Corrupt;
        const end = slot.end.load(.acquire);
        const c1 = s.committed1.load(.monotonic);
        const cseq = if (c1 == 0) 0 else c1 - 1;
        var carrying = false;
        errdefer if (carrying) s.abort(&s.batch);
        var snap = s.snapshot();
        defer snap.release();
        var off = from;
        var read: u64 = 0;
        if (from < end) {
            if (slot.comp.load(.acquire)) |c| {
                s.framesAhead(c, from, @min(end, from +| budget +| (1 << 20)));
            } else {
                const v = viewOf(slot);
                s.willNeed(v[@min(from, v.len)..@min(end, from +| budget +| (1 << 20), v.len)]);
            }
        }
        while (off < end and read < budget) {
            if (read > 0 and pastDeadline(deadline)) {
                s.clean.cut += 1;
                break;
            }
            const g = (try s.groupAtE(slot, e, off, end, null, false)) orelse {
                if (s.age_debug) s.debugGroup(slot, e, off, end);
                return error.Corrupt;
            };
            const gv = g.g;
            s.clean.table_ahead += s.tableAhead(gv, g.commit_off);
            var p: u64 = 0;
            while (p < g.commit_off) {
                const h = format.short(gv[p..]);
                const l = format.loc(e, off + p);
                switch (h.kind) {
                    .object, .object_c => {
                        const rec = try format.validate(gv, p, l);
                        const o = try s.objRec(rec);
                        var live = false;
                        if (h.flags & format.flag_historical == 0) {
                            const cur = s.lt().lookup(&o.id) orelse 0;
                            if (cur & table.tomb == 0 and table.locOf(cur) == l) {
                                live = true;
                                try s.carryRec(&carrying, cseq, .{ .obj = &o });
                                rep.objects_carried += 1;
                                rep.bytes_carried += rec.len;
                            }
                        }
                        // A superseded version an in-window xref still names (sui-node keeps a
                        // version until the checkpoint that superseded it is pruned).
                        if (!live) if (s.xrefAnchor(&snap, rec, &o, l)) |anchor| {
                            try s.carryRec(&carrying, cseq, .{ .hist = .{ .o = &o, .anchor = anchor } });
                            rep.versions_carried += 1;
                            rep.bytes_carried += rec.len;
                        };
                    },
                    .remove => {
                        const rec = try format.validate(gv, p, l);
                        if (rec.len < format.header_len + @sizeOf(format.RemoveFixed)) return error.Corrupt;
                        const f = format.fixed(format.RemoveFixed, rec);
                        if (s.lt().lookup(&f.id) == l | table.tomb) {
                            // An older aged segment may still hold a live-looking record of
                            // this object (the restored set is never cleaned): a live-table
                            // rebuild replays aged segments oldest first, so without its
                            // tombstone the deleted object would come back. Carry the
                            // tombstone; drop it only when no older segment remains.
                            if (s.aged.items.len > 0 and s.aged.items[0] < e) {
                                try s.carryRec(&carrying, cseq, .{ .tomb = .{ .f = f, .seq = format.header(rec).seq } });
                                rep.tombstones_carried += 1;
                            } else if (s.lt().remove(&f.id, l | table.tomb)) rep.tombstones_dropped += 1;
                        }
                    },
                    else => {},
                }
                p += format.lenOf(h.kind, h.size);
            }
            read += g.len;
            off += g.len;
        }
        if (carrying) {
            carrying = false;
            try s.commit(&s.batch);
        }
        return off;
    }

    /// Deletes a fully swept aged segment: the live table no longer names it (made durable
    /// first), so a crash before the unlink leaves only an unreferenced file that the next
    /// cleaning pass deletes.
    fn finishSegment(s: *Store, e: u64, rep: *PruneReport) Error!void {
        try s.flushLive();
        const slot = s.slotOf(e) orelse return;
        rep.bytes_dropped += slot.end.load(.monotonic);
        rep.runs_dropped += slot.nruns.load(.monotonic);
        const n = slot.nruns.load(.monotonic);
        // The ager may be inside this segment: wait for its step, and hand its finished
        // rewrites to the grace period before the segment itself (they punch its files).
        s.age_yield.store(true, .release);
        s.age_mu.lock();
        defer s.age_mu.unlock();
        s.age_yield.store(false, .release);
        s.ageHandoffLocked();
        s.unpublishSlot(slot, true);
        try s.removeEpochFiles(e, n);
        try s.backend.syncDir();
        if (s.agedIndex(e)) |i| _ = s.aged.orderedRemove(i);
        if (s.clean.phase == .count) s.clean.phase = .idle;
        rep.segments_dropped += 1;
        s.rcuPoll();
    }

    /// Drops every segment older than `epoch` now: `ageOut`, then every aged segment below
    /// `epoch` is swept (its live objects copied into the current segment) and deleted,
    /// however dense. The synchronous form of `ageOut` + `cleanStep` (tests, tools); the node
    /// uses those two so that following never waits on a copy. The current segment is never
    /// dropped.
    pub fn pruneBefore(s: *Store, epoch: u64) Error!PruneReport {
        if (s.batch_active) return error.BatchActive;
        if (s.poisoned) return error.Poisoned;
        const t0 = clock.now();
        if (s.has_segment and epoch > s.cur_epoch) return error.PruneCurrent;
        var rep = try s.ageOut(epoch);
        errdefer s.poisoned = true;
        s.clean.phase = .idle;
        var i: usize = 0;
        while (i < s.aged.items.len) {
            const e = s.aged.items[i];
            if (e >= epoch) {
                i += 1;
                continue;
            }
            _ = try s.sweepSome(e, 0, std.math.maxInt(u64), &rep);
            try s.finishSegment(e, &rep);
        }
        rep.ns = clock.now() - t0;
        return rep;
    }

    /// Prunes to `retention_epochs` before the current epoch.
    pub fn pruneRetained(s: *Store) Error!PruneReport {
        if (!s.has_segment or s.cur_epoch < s.cfg.retention_epochs) return .{};
        return s.pruneBefore(s.cur_epoch - s.cfg.retention_epochs);
    }

    /// Tests and tools: a hash over the logical bytes of segment `e`, group by group as a
    /// reader decodes them (a hole is its header and zeros), or null when the store does not
    /// hold the segment. Two stores with the same hash for every segment hold the same records
    /// and the same holes, wherever age-out put the frames. Writer thread (or a quiet store).
    pub fn segmentLogicalHash(s: *Store, e: u64) Error!?u64 {
        const slot = s.slotOf(e) orelse return null;
        const end = slot.end.load(.acquire);
        var off: u64 = 0;
        var h: u64 = 0x6c6f67;
        while (off < end) {
            const g = (try s.groupAtE(slot, e, off, end, null, false)) orelse return error.Corrupt;
            h = cs.hash(h ^ off, g.g[0..g.len]);
            off += g.len;
        }
        return h;
    }

    /// Bytes the segment files, their sidecars and age logs occupy on disk (st_blocks), and their
    /// logical size (writer or quiescent store).
    pub fn segmentDisk(s: *Store) struct { disk: u64, logical: u64, side: u64 } {
        var r: @TypeOf(s.segmentDisk()) = .{ .disk = 0, .logical = 0, .side = 0 };
        s.age_mu.lock();
        defer s.age_mu.unlock();
        for (s.segs) |*slot| {
            if (slot.epoch.load(.acquire) == no_epoch) continue;
            r.disk += s.backend.allocated(slot.fd) catch 0;
            r.logical += slot.end.load(.acquire);
            if (slot.comp.load(.acquire)) |c| {
                if (c.side_fd) |f| {
                    const b = s.backend.allocated(f) catch 0;
                    r.disk += b;
                    r.side += b;
                }
                if (c.age_fd) |f| r.disk += s.backend.allocated(f) catch 0;
            }
        }
        return r;
    }

    /// Where segment cleaning is (writer thread): phase 0 idle, 1 count (`done` / `total` live
    /// table pages), 2 sweep (`done` / `total` bytes of the target segment); the sweep's table
    /// pages read ahead and the steps cut short by a deadline, since open.
    pub const CleanProgress = struct { phase: u8, done: u64, total: u64, table_ahead: u64, cut: u64 };

    pub fn cleanProgress(s: *const Store) CleanProgress {
        var r: CleanProgress = .{ .phase = 0, .done = 0, .total = 0, .table_ahead = s.clean.table_ahead, .cut = s.clean.cut };
        switch (s.clean.phase) {
            .idle => {},
            .count => {
                r.phase = 1;
                r.done = s.clean.page;
                r.total = if (s.live.raw) |h| h.t.pages.len else 0;
            },
            .sweep => {
                r.phase = 2;
                r.done = s.clean.off;
                r.total = if (s.slotOf(s.clean.target)) |slot| slot.end.load(.monotonic) else 0;
            },
        }
        return r;
    }

    /// Aged segments (below the history window, kept for their live objects) and their bytes.
    pub fn agedSegments(s: *const Store) struct { count: u64, bytes: u64 } {
        var b: u64 = 0;
        for (s.aged.items) |e| if (s.slotOf(e)) |slot| {
            b += slot.end.load(.monotonic);
        };
        return .{ .count = s.aged.items.len, .bytes = b };
    }

    // ------------------------------------------------------------------ age-out (holes)
    //
    // Retention by data type inside a segment. Segments still age out
    // whole (`ageOut`, `cleanStep`); on top of that the ager frees what the floors made
    // unreadable long before the segment goes:
    //   - checkpoint class (checkpoints, transactions, checkpoint-digest aux records) below the
    //     checkpoint floor (the checkpoint record just below it stays: `checkpointHeld`);
    //   - superseded object versions and tombstones once the checkpoint that superseded them is
    //     below the object floor, as sui-node's objects pruner deletes them. The successor's
    //     previous-version link (`a`) names the dead record: a scan over the groups the object
    //     floor passes collects those locations;
    //   - in segments the object window left (whole-segment rule, the reads `objInWindow` already
    //     refuses): every non-live version no in-window xref names, xrefs and links.
    // A sealed compressed segment's group is decoded, its dead records become holes
    // (format.Kind.hole: same length, checksum kept, zero payload) and every chunk that changed
    // enough is compressed again into the segment's sidecar. Logical offsets never move, so no
    // index, live-table entry or reader location changes. Then, in order: the sidecar frames are
    // synced, the age log records naming them are synced, the new directory is published, and
    // after a grace period (no reader can hold the old directory) the old frames are punched
    // (fallocate PUNCH_HOLE) and their decoded copies leave the cache. Live records are never
    // touched. Raw segments are left to whole-segment age-out (cleaning); a raw segment inside
    // the window stops the checkpoint pass, so the checkpoints the store holds stay contiguous.

    pub const AgeReport = struct {
        groups_scanned: u64 = 0,
        groups_rewritten: u64 = 0,
        chunks_rewritten: u64 = 0,
        records_dropped: u64 = 0,
        /// Of those, object versions and tombstones (sui-node `num_pruned_objects`,
        /// `num_pruned_tombstones`).
        objects_dropped: u64 = 0,
        tombstones_dropped: u64 = 0,
        /// Logical bytes turned into holes.
        bytes_dropped: u64 = 0,
        /// Sidecar bytes written, and bytes of old frames queued for punching.
        phys_written: u64 = 0,
        phys_queued: u64 = 0,
        /// Logical bytes read.
        read: u64 = 0,
        idle: bool = false,
    };

    /// When age-out runs. `on`: whenever there is something below the floors. `deferred`: the
    /// same, except while the node says it is far behind the tip (`ageBehind`): then the ager
    /// waits, so catch-up has the disk to itself, until `Config.age_defer_bytes` of history lie
    /// below the checkpoint floor unprocessed (`ageBacklog`); at that point it runs the passes
    /// over that history to their floors in one go (no segment pass) and waits again.
    pub const AgeMode = enum { on, deferred };

    /// What the ager may do now (`ageGate`).
    pub const AgeGate = enum { run, wait, bulk };

    pub const AgeStepOpts = struct {
        /// Leave the segment pass out (a bulk catch-up while the node is behind: that pass
        /// looks up every object of every aged segment, the restore image included).
        skip_seg: bool = false,
    };

    pub const AgeStats = struct {
        steps: std.atomic.Value(u64) = .init(0),
        groups_rewritten: std.atomic.Value(u64) = .init(0),
        chunks_rewritten: std.atomic.Value(u64) = .init(0),
        records_dropped: std.atomic.Value(u64) = .init(0),
        objects_dropped: std.atomic.Value(u64) = .init(0),
        tombstones_dropped: std.atomic.Value(u64) = .init(0),
        bytes_dropped: std.atomic.Value(u64) = .init(0),
        phys_written: std.atomic.Value(u64) = .init(0),
        /// Bytes of old frames punched (after their grace period).
        phys_punched: std.atomic.Value(u64) = .init(0),
        pending: std.atomic.Value(u64) = .init(0),
        pending_full: std.atomic.Value(u64) = .init(0),
        /// Passes over the full pending set to drop what both passes have passed, and
        /// superseded locations never remembered because they were behind both already.
        pending_prunes: std.atomic.Value(u64) = .init(0),
        pending_behind: std.atomic.Value(u64) = .init(0),
        /// Bytes the ager holds (`ageMem`) after its last step or read-ahead, the most it has
        /// held, and of the former the pending set and the old directories of rewrites the
        /// writer has not taken yet; and steps not started because such rewrites waited.
        mem: std.atomic.Value(u64) = .init(0),
        mem_max: std.atomic.Value(u64) = .init(0),
        mem_pending: std.atomic.Value(u64) = .init(0),
        mem_handoff: std.atomic.Value(u64) = .init(0),
        handoff_waits: std.atomic.Value(u64) = .init(0),
        max_step_ns: std.atomic.Value(u64) = .init(0),
        failed: std.atomic.Value(bool) = .init(false),
        /// Deferred mode: checks that found the node behind and waited, bulk catch-ups started
        /// because the backlog passed `age_defer_bytes`, and the backlog at the last check.
        deferred: std.atomic.Value(u64) = .init(0),
        bulk_runs: std.atomic.Value(u64) = .init(0),
        backlog: std.atomic.Value(u64) = .init(0),
        /// Read-ahead (`ageWarm`): groups read ahead of a step and live-table pages asked for;
        /// the steps' live-table lookups, and those whose page had not been asked for (each a
        /// fault of its own on a cold table, with `age_mu` held).
        warm_groups: std.atomic.Value(u64) = .init(0),
        warm_pages: std.atomic.Value(u64) = .init(0),
        lookups: std.atomic.Value(u64) = .init(0),
        lookups_cold: std.atomic.Value(u64) = .init(0),
        /// Time spent reading ahead (no lock), and time the steps held `age_mu`.
        warm_ns: std.atomic.Value(u64) = .init(0),
        locked_ns: std.atomic.Value(u64) = .init(0),
        /// Of `warm_pages`, the pages read: through the io_uring page reader, or by the
        /// fallback (MADV_WILLNEED and a touch); and read-ahead errors (reads the ring
        /// reported failed, or the ring itself failing: after that the fallback reads).
        warm_uring_pages: std.atomic.Value(u64) = .init(0),
        warm_fallback_pages: std.atomic.Value(u64) = .init(0),
        warm_errors: std.atomic.Value(u64) = .init(0),
        /// Segment pass: aged segments it finished. With the live set (`age_live_set`): table
        /// passes finished, table pages read by them, locations marked, records kept without a
        /// lookup because the table named them, and groups and chunks left unexamined because
        /// too little of them could go.
        seg_passes: std.atomic.Value(u64) = .init(0),
        set_builds: std.atomic.Value(u64) = .init(0),
        set_pages: std.atomic.Value(u64) = .init(0),
        set_marked: std.atomic.Value(u64) = .init(0),
        set_kept: std.atomic.Value(u64) = .init(0),
        set_groups_skipped: std.atomic.Value(u64) = .init(0),
        set_chunks_skipped: std.atomic.Value(u64) = .init(0),
        /// Object versions judged dead by a clear bit alone; table passes started over because
        /// a slot moved under them, and passes finished inexact after three of those; and
        /// (`age_set_verify`) clear bits of an exact set whose record the table still named:
        /// the proof in `AgeSet` says never.
        set_dead: std.atomic.Value(u64) = .init(0),
        /// Locations the set took from links (`AgeSet`), and records the lookup rule kept
        /// because a link inside the object window names them.
        set_links: std.atomic.Value(u64) = .init(0),
        link_kept: std.atomic.Value(u64) = .init(0),
        set_restarts: std.atomic.Value(u64) = .init(0),
        set_inexact: std.atomic.Value(u64) = .init(0),
        set_misses: std.atomic.Value(u64) = .init(0),
    };

    const AgePass = enum { scan, obj, cp, seg };

    fn newestEpoch(s: *const Store) ?u64 {
        const t = s.ep_tail.load(.acquire);
        if (t == 0) return null;
        const e = s.ep_ring[(t - 1) & s.seg_mask].load(.acquire);
        return if (e == no_epoch) null else e;
    }

    /// Smallest segment epoch above `e` (null: none), over every published slot (aged ones too).
    fn segAfter(s: *const Store, e: ?u64) ?u64 {
        var best: ?u64 = null;
        for (s.segs) |*slot| {
            const x = slot.epoch.load(.acquire);
            if (x == no_epoch) continue;
            if (e) |ee| if (x <= ee) continue;
            if (best == null or x < best.?) best = x;
        }
        return best;
    }

    /// Location of checkpoint `seq`'s record in the index, if indexed.
    fn cpLocOf(snap: *const Snapshot, seq: u64) ?u64 {
        const st = snap.store;
        const m = st.mem.load(.acquire) orelse return null;
        if (table.cpFind(m.cps.slice(), seq)) |l| return l;
        var i = st.ep_tail.load(.acquire);
        const lo = st.ep_head.load(.acquire);
        while (i > lo) {
            i -= 1;
            const e = st.ep_ring[i & st.seg_mask].load(.monotonic);
            const slot = st.slotOf(e) orelse continue;
            var r = slot.nruns.load(.acquire);
            while (r > 0) {
                r -= 1;
                const run = slot.runs[r].load(.acquire) orelse continue;
                if (run.header.ncp == 0 or seq < run.header.min_seq or seq > run.header.max_seq) continue;
                if (run.findCp(seq)) |l| return l;
            }
        }
        return null;
    }

    const AgeGroup = struct { e: u64, off: u64, len: u64, seq: u64, commit_off: u64, c: *CSeg, d: *chunk.Dir, first: usize, n: usize };

    /// Decodes the group at logical `off` of compressed segment `e` into the ager's buffer.
    fn ageLoadGroup(s: *Store, c: *CSeg, e: u64, off: u64, end: u64) Error!?AgeGroup {
        return s.ageLoadGroupInto(&s.ager.g, c, e, off, end);
    }

    /// `ageLoadGroup` into `buf` (the read-ahead decodes into its own).
    fn ageLoadGroupInto(s: *Store, buf: *std.ArrayList(u8), c: *CSeg, e: u64, off: u64, end: u64) Error!?AgeGroup {
        const d = c.dir.load(.acquire);
        const first = d.indexAt(off) orelse return null;
        const es = d.slice();
        buf.clearRetainingCapacity();
        var i = first;
        var p: usize = 0;
        while (true) {
            if (i >= es.len or es[i].ls >= end) return null;
            if (buf.items.len > s.cfg.max_batch_bytes + block) return error.Corrupt;
            // A group can be tens of MiB of frames: a stop does not wait for the rest of it.
            if (s.ageStopping()) return null;
            try s.chunkInto(c, es[i], buf);
            i += 1;
            const g = buf.items;
            var have_commit = false;
            while (p + format.short_len <= g.len) {
                const h = format.short(g[p..]);
                const n = format.lenOf(h.kind, h.size);
                if (p + n > g.len) break;
                if (h.kind == .commit) {
                    have_commit = true;
                    break;
                }
                p += n;
            }
            if (have_commit) {
                const want = std.mem.alignForward(u64, p + format.recordLen(@sizeOf(format.CommitFixed)), block);
                if (g.len < want) continue;
                break;
            }
        }
        const w = walkGroupRel(buf.items, off, e) orelse return error.Corrupt;
        if (w.end != buf.items.len) return error.Corrupt;
        const seq = format.header(buf.items[w.commit_off..]).seq;
        return .{ .e = e, .off = off, .len = w.end, .seq = seq, .commit_off = w.commit_off, .c = c, .d = d, .first = first, .n = i - first };
    }

    /// The ager's live-table lookup (reader's), counted.
    fn ageLookup(s: *Store, snap: *const Snapshot, id: *const [32]u8) ?u64 {
        const a = &s.ager;
        const t = snap.liveTable();
        a.lookups += 1;
        if (a.warm.on) {
            const pg = t.homeSlot(id) / table.per_page;
            if (std.sort.binarySearch(u64, a.warm.pages.items, pg, struct {
                fn cmp(k: u64, x: u64) std.math.Order {
                    return std.math.order(k, x);
                }
            }.cmp) == null) a.lookups_cold += 1;
        } else a.lookups_cold += 1;
        return t.get(id);
    }

    /// Whether the record `rec` (padded) at `l` may become a hole. Damaged records stay.
    fn ageDrop(s: *Store, snap: *const Snapshot, rec: []const u8, l: u64, cp_ok: bool, seg_rule: bool) bool {
        const h = format.short(rec);
        const cp_floor = s.ager.cp_floor;
        const hl = format.hdrLen(h.kind);
        if (hl + h.size > rec.len) return false;
        const whole = rec[0 .. hl + h.size];
        switch (h.kind) {
            .checkpoint => {
                if (!cp_ok) return false;
                const seq = format.header(rec).seq;
                return seq + 1 < cp_floor;
            },
            .tx => return cp_ok and format.header(rec).seq < cp_floor,
            .object, .object_c => {
                if (format.checksum(l, whole) != h.checksum) return false;
                const o = s.objRec(whole) catch return false;
                if (o.version > std.math.maxInt(i64)) {
                    // Aux keyspace: checkpoint data (loaded lists, checkpoint digests) goes with
                    // the checkpoint floor; the highest-pruned marker and links' key stay.
                    if (o.version == aux_superseded or o.version == aux_highest_pruned) return false;
                    return cp_ok and o.seq < cp_floor;
                }
                if (h.flags & format.flag_historical != 0) {
                    // A carried historical copy lives while the xref it stands in for does.
                    if (h.kind == .object) {
                        const hb = format.header(rec).b;
                        if (hb != 0) return !s.objInWindowDurable(hb);
                    }
                    return seg_rule and s.xrefAnchorAt(snap, whole, &o, l, true) == null;
                }
                // Only a record the scan saw superseded (`pending`) or one under the
                // whole-segment rule can go: for any other the lookup below could only say no,
                // so it is not made (on a cold table it is a page fault per record).
                const pend = s.ager.pending.contains(l);
                if (!pend and !seg_rule and !s.cfg.age_serial) return false;
                // The table pass saw this record as the table's own, or a link in the window
                // names it: it stays, no lookup.
                if (s.ager.set.keeps(l, h.kind == .object_c)) {
                    s.ager.set_kept += 1;
                    return false;
                }
                // An exact pass did not: the record is not its object's live one (`AgeSet`).
                // The rest of the rule decides, no lookup.
                const proven = s.ager.set.proves(l);
                if (proven and !s.cfg.age_set_verify) {
                    // (A clear bit also says that no link in the window names the record.)
                    _ = s.age_stats.set_dead.fetchAdd(1, .monotonic);
                    if (pend) return true;
                    return seg_rule and s.xrefAnchorAt(snap, whole, &o, l, true) == null;
                }
                const cur = s.ageLookup(snap, &o.id) orelse return false;
                if (proven and table.locOf(cur) == l) _ = s.age_stats.set_misses.fetchAdd(1, .monotonic);
                if (table.locOf(cur) <= l) return false; // live (or not superseded here)
                if (pend) return true;
                if (!seg_rule or s.xrefAnchorAt(snap, whole, &o, l, true) != null) return false;
                // Superseded, in a segment below the object window, no cross-reference: still
                // read by version while the link that names it is inside the window.
                if (h.kind == .object_c and s.linkAnchored(snap, &o.id, l)) {
                    _ = s.age_stats.link_kept.fetchAdd(1, .monotonic);
                    return false;
                }
                return true;
            },
            .remove => {
                if (whole.len < format.header_len + @sizeOf(format.RemoveFixed) or format.checksum(l, whole) != h.checksum) return false;
                const f = format.fixed(format.RemoveFixed, whole);
                // Only a tombstone a newer record of the object replaced: a live-table rebuild
                // must never bring an older version back.
                const pend = s.ager.pending.contains(l);
                if (!pend and !seg_rule and !s.cfg.age_serial) return false;
                if (s.ager.set.keeps(l, false)) {
                    s.ager.set_kept += 1;
                    return false;
                }
                // A tombstone the table does not name is still looked up: one whose object the
                // table no longer holds at all must stay (a rebuild must not bring an older
                // version back), and a clear bit cannot tell that from a replaced one.
                const cur = s.ageLookup(snap, &f.id) orelse return false;
                if (s.ager.set.proves(l) and table.locOf(cur) == l) _ = s.age_stats.set_misses.fetchAdd(1, .monotonic);
                if (table.locOf(cur) <= l) return false;
                return pend or seg_rule;
            },
            .xref, .link => return seg_rule,
            else => return false,
        }
    }

    /// Notes the records `g` supersedes (object floor scan): their successors are below the
    /// object floor, so sui-node has pruned them.
    fn ageCollect(s: *Store, g: []const u8, commit_off: u64) void {
        const a = &s.ager;
        const behind = s.ageBehindBoth();
        var p: usize = 0;
        var seen: u32 = 0;
        while (p < commit_off) {
            const h = format.short(g[p..]);
            const n = format.lenOf(h.kind, h.size);
            // (What a stopped scan has noted so far stays noted: each entry is true by itself.)
            seen += 1;
            if (seen & 1023 == 0 and s.ageStopping()) break;
            switch (h.kind) {
                .object, .remove, .link => if (h.flags & format.flag_carried == 0) {
                    const prev = format.header(g[p..]).a;
                    // A location behind both passes is never remembered: no pass will ask for
                    // it (the segment pass asks the table or the live set). On a restored store
                    // most records first supersede a record of the image, which is behind from
                    // the start: remembered, they filled the set with entries of no use.
                    if (prev != 0 and prev < behind) {
                        _ = s.age_stats.pending_behind.fetchAdd(1, .monotonic);
                    } else if (prev != 0) {
                        // Full: one pass to drop what both passes have passed, and another
                        // only once they have moved. A pass per record (as it was) is a walk
                        // over the whole set for each record of the group, with `age_mu` held
                        // and no end in sight when the checkpoint pass cannot move (a raw
                        // segment in the window): 8.4M entries, thousands of records a step,
                        // a close that waited past its deadline.
                        const max = s.agePendingMax();
                        if (a.pending.count() >= max and a.pruned_at != behind) s.agePrunePending();
                        if (a.pending.count() < max) {
                            a.pending.put(s.gpa, prev, {}) catch {};
                        } else _ = s.age_stats.pending_full.fetchAdd(1, .monotonic);
                    }
                },
                else => {},
            }
            p += n;
        }
        s.age_stats.pending.store(a.pending.count(), .monotonic);
    }

    /// The location both the object pass and the checkpoint pass have passed (0 before the
    /// cursors are placed): what lies before it is visited again only by the segment pass,
    /// which does not use the pending set.
    fn ageBehindBoth(s: *const Store) u64 {
        const a = &s.ager;
        if (a.cpc == no_loc or a.objc == no_loc) return 0;
        return @min(a.cpc, a.objc);
    }

    /// Drops pending locations both passes have passed.
    fn agePrunePending(s: *Store) void {
        const a = &s.ager;
        const behind = s.ageBehindBoth();
        a.pruned_at = behind;
        _ = s.age_stats.pending_prunes.fetchAdd(1, .monotonic);
        if (behind == 0) return;
        // In place: no list of what goes (it was 8 bytes an entry on top of the set).
        var it = a.pending.keyIterator();
        var seen: u32 = 0;
        while (it.next()) |k| {
            // 8.4M entries at most: a stop does not wait for the rest of the pass.
            seen +%= 1;
            if (seen & 0xffff == 0 and s.ageStopping()) break;
            if (k.* < behind) a.pending.removeByPtr(k);
        }
    }

    /// Bytes of one slot of the pending set's hash map (a key and its metadata byte).
    const pending_slot_bytes = 9;

    /// Entries the pending set may hold: `age_pending_max`, and no more than fit a quarter of
    /// `age_mem_bytes`. The map keeps its load under 80% and grows by doubling with both tables
    /// alive, so a table of S slots costs up to 1.5 S slots: the largest such S that fits, and
    /// four fifths of it.
    pub fn agePendingMax(s: *const Store) u64 {
        const quarter = s.cfg.age_mem_bytes / 4;
        const slots = std.math.floorPowerOfTwo(u64, @max(quarter * 2 / 3 / pending_slot_bytes, 16));
        return @min(s.cfg.age_pending_max, slots * 4 / 5 - 1);
    }

    /// Bytes the ager holds now: the pending set's table, the lag queue, the group and batch
    /// buffers of the step and of the read-ahead, the read-ahead's page lists, the live set's
    /// bits, and the old directories of finished rewrites the writer has not taken. Under
    /// `age_run`. Also keeps `AgeStats.mem*`.
    fn ageMem(s: *Store) u64 {
        const a = &s.ager;
        const w = &a.warm;
        const pending: u64 = @as(u64, a.pending.capacity()) * pending_slot_bytes;
        const handoff = a.handoff_bytes.load(.monotonic);
        const total = pending + handoff +
            a.lagq.capacity * @sizeOf(Lag) + a.g.capacity + a.out.capacity + w.g.capacity +
            (w.pages.capacity + w.io.capacity) * 8 + a.set.bits.len * 8 +
            (a.drop_new.capacity + a.keep_live.capacity + a.maybe.capacity + a.total.capacity + w.maybe.capacity + w.total.capacity) * 8 +
            a.changes.capacity * @sizeOf(AgeChange) + a.punch.capacity * @sizeOf(PunchRange) + a.recs.capacity * @sizeOf(chunk.AgeRec);
        const st = &s.age_stats;
        st.mem.store(total, .monotonic);
        st.mem_pending.store(pending, .monotonic);
        st.mem_handoff.store(handoff, .monotonic);
        if (total > st.mem_max.load(.monotonic)) st.mem_max.store(total, .monotonic);
        return total;
    }

    /// After a step: a group or batch buffer that grew past an eighth of the ager's memory for
    /// one large group is given back (the next group that needs it grows it again).
    fn ageTrim(s: *Store) void {
        const a = &s.ager;
        const lim = s.cfg.age_mem_bytes / 8;
        if (a.g.capacity > lim) a.g.clearAndFree(s.gpa);
        if (a.out.capacity > lim) a.out.clearAndFree(s.gpa);
        if (a.warm.g.capacity > lim) a.warm.g.clearAndFree(s.gpa);
        _ = s.ageMem();
    }

    const no_loc = std.math.maxInt(u64);

    /// Holes the dead records of group `ag` (decoded in the ager buffer) and queues the chunks
    /// worth rewriting into the batch.
    fn ageRewrite(s: *Store, snap: *const Snapshot, ag: AgeGroup, cp_ok: bool, seg_rule: bool, rep: *AgeReport) Error!void {
        const a = &s.ager;
        const g = a.g.items;
        const es = ag.d.slice()[ag.first..][0..ag.n];
        a.drop_new.clearRetainingCapacity();
        a.keep_live.clearRetainingCapacity();
        a.drop_new.appendNTimes(s.gpa, 0, ag.n) catch return error.OutOfMemory;
        a.keep_live.appendNTimes(s.gpa, 0, ag.n) catch return error.OutOfMemory;
        // With a live set over this group: where can an eighth go at all? A group (rewritten
        // whole) or a chunk whose records that could go are under an eighth of what counts is
        // not rewritten whatever the lookups say, so they are not made.
        const filt = s.ageSetChunks(g, ag, &a.maybe, &a.total);
        const whole_g = ag.len <= s.cfg.age_whole_group_bytes;
        if (filt and whole_g) {
            var m: u64 = 0;
            var t: u64 = 0;
            for (a.maybe.items, a.total.items) |x, y| {
                m += x;
                t += y;
            }
            if (m * 8 < t) {
                _ = s.age_stats.set_groups_skipped.fetchAdd(1, .monotonic);
                return;
            }
        }
        if (filt and !whole_g) {
            var skipped: u64 = 0;
            for (a.maybe.items, a.total.items) |x, y| {
                if (!ageSetCould(x, y)) skipped += 1;
            }
            _ = s.age_stats.set_chunks_skipped.fetchAdd(skipped, .monotonic);
        }
        var ci: usize = 0;
        var p: usize = 0;
        var any = false;
        var keep_cp = false;
        var judged: u32 = 0;
        while (p < ag.commit_off) {
            const h = format.short(g[p..]);
            const n = format.lenOf(h.kind, h.size);
            while (ci + 1 < ag.n and ag.off + p >= es[ci].end()) ci += 1;
            // A record can cost a lookup on a cold table: a stop does not wait for a group's
            // worth of them. Nothing is planned yet, so the group is simply left (the caller
            // does not move its cursor past it).
            judged += 1;
            if (judged & 63 == 0 and s.ageStopping()) return;
            if (h.kind != .hole) {
                const l = format.loc(ag.e, ag.off + p);
                // A chunk that cannot be rewritten: its records stay as they are. Checkpoints
                // and transactions are still judged (no lookup): the group's padding depends
                // on whether any of them stays.
                const judge = !filt or whole_g or ageSetCould(a.maybe.items[ci], a.total.items[ci]) or h.kind == .checkpoint or h.kind == .tx;
                if (judge and s.ageDrop(snap, g[p..][0..n], l, cp_ok, seg_rule)) {
                    // `h` points into the record: its kind is read before the record becomes
                    // a hole (read after, the two counters below never moved).
                    const kind = h.kind;
                    format.makeHole(g[p..][0..n]);
                    a.drop_new.items[ci] += n;
                    rep.records_dropped += 1;
                    switch (kind) {
                        .object, .object_c => rep.objects_dropped += 1,
                        .remove => rep.tombstones_dropped += 1,
                        else => {},
                    }
                    rep.bytes_dropped += n;
                    any = true;
                } else if (h.kind != .segment) {
                    a.keep_live.items[ci] += n;
                    if (h.kind == .checkpoint or h.kind == .tx) keep_cp = true;
                }
            }
            p += n;
        }
        if (!any) return;
        var new_total: u64 = 0;
        var live_total: u64 = 0;
        for (a.drop_new.items, a.keep_live.items) |x, y| {
            new_total += x;
            live_total += y;
        }
        const whole = ag.len <= s.cfg.age_whole_group_bytes;
        if (whole and new_total * 8 < new_total + live_total) return;
        try s.ageBatchFor(ag.c, ag.e);
        const c = ag.c;
        var rewrote: usize = 0;
        var all_main = true;
        var cz: zstd_c.Compressor = .{};
        defer cz.deinit();
        for (es, 0..) |en, i| {
            const take = if (whole) true else a.drop_new.items[i] > 0 and a.drop_new.items[i] * 8 >= a.drop_new.items[i] + a.keep_live.items[i];
            if (!take) continue;
            // Stopped between two chunks: the half-planned group goes with the batch
            // (`ageAbort`), which a stopped step never writes.
            if (s.ageStopping()) return;
            const src = g[en.ls - ag.off ..][0..en.ll];
            const body = chunk.compressChunkAt(s.gpa, &cz, src, if (s.cfg.elide_sums) ag.e else null, en.ls, try s.ageDict(c)) catch return error.OutOfMemory;
            defer if (body) |x| s.gpa.free(x.bytes);
            a.ents.clearRetainingCapacity();
            chunk.appendFrameC(s.gpa, &a.out, chunk.side_bit | c.side_tail, en.ls, src, if (body) |x| x.bytes else null, if (body) |x| x.codec else 0, &a.ents) catch return error.OutOfMemory;
            const ne = a.ents.items[0];
            a.changes.append(s.gpa, .{ .idx = ag.first + i, .ls = en.ls, .ll = en.ll, .phys = ne.phys, .bl = ne.bl, .codec = ne.codec, .old_phys = en.phys, .old_bl = en.bl }) catch return error.OutOfMemory;
            if (chunk.isSide(en.phys)) all_main = false;
            if (!whole) a.punch.append(s.gpa, .{ .side = chunk.isSide(en.phys), .off = en.phys & ~chunk.side_bit, .len = en.span() }) catch return error.OutOfMemory;
            rewrote += 1;
        }
        if (rewrote == 0) return;
        if (whole) {
            // Frames adjacent in order in one file: one range (in the segment file its padding
            // too). Otherwise frame by frame: after a torn age log only a prefix of a rewrite's
            // records applies, so a group's early chunks sit in a newer sidecar batch than its
            // later ones (lo..hi then ran backwards, the ReleaseSafe overflow, or across other
            // groups' live frames).
            const lo = es[0].phys & ~chunk.side_bit;
            var hi = (es[es.len - 1].phys & ~chunk.side_bit) + es[es.len - 1].span();
            var same = true;
            for (es[1..], es[0 .. es.len - 1]) |en, pv| if (chunk.isSide(en.phys) != chunk.isSide(pv.phys) or en.phys != pv.phys + pv.span()) {
                same = false;
            };
            if (same) {
                if (all_main) hi = std.mem.alignForward(u64, hi, block);
                a.punch.append(s.gpa, .{ .side = !all_main, .off = lo, .len = hi - lo }) catch return error.OutOfMemory;
            } else for (es) |en| a.punch.append(s.gpa, .{ .side = chunk.isSide(en.phys), .off = en.phys & ~chunk.side_bit, .len = en.span() }) catch return error.OutOfMemory;
        }
        // Frames that may be rewritten again end on a block, so their punch frees them whole.
        // (Live objects alone stay put until cleaning: no padding for them.)
        if (keep_cp) chunk.padGroup(s.gpa, &a.out, c.side_tail) catch return error.OutOfMemory;
        rep.groups_rewritten += 1;
        rep.chunks_rewritten += rewrote;
    }

    /// Whether a chunk with `maybe` bytes of records that could go out of `total` that count can
    /// reach the rewrite threshold (`ageRewrite`: something dropped, and at least an eighth).
    fn ageSetCould(maybe: u64, total: u64) bool {
        return maybe > 0 and maybe * 8 >= total;
    }

    /// An object version or tombstone at `l` that the live set names (`ageDrop` keeps exactly
    /// these without a lookup: not the aux keyspace, not historical copies).
    fn ageSetKnown(s: *Store, rec: []const u8, l: u64) bool {
        const h = format.short(rec);
        switch (h.kind) {
            .object => {
                if (h.flags & format.flag_historical != 0) return false;
                if (rec.len < format.header_len + @sizeOf(format.ObjectFixed)) return false;
                if (format.fixed(format.ObjectFixed, rec).version > std.math.maxInt(i64)) return false;
            },
            .object_c => if (h.flags & format.flag_historical != 0) return false,
            .remove => {},
            else => return false,
        }
        return s.ager.set.keeps(l, h.kind == .object_c);
    }

    /// For the group `ag` decoded in `g`, when a ready live set covers it: per chunk, the bytes
    /// of records that count toward the rewrite threshold (`total`: not holes, not the segment
    /// record) and of those the bytes that could become holes (`maybe`: every record except
    /// the object versions and tombstones the set names). False: no set covers the group.
    fn ageSetChunks(s: *Store, g: []const u8, ag: AgeGroup, maybe: *std.ArrayList(u64), total: *std.ArrayList(u64)) bool {
        if (!s.ager.set.usable(ag.e, ag.off)) return false;
        const es = ag.d.slice()[ag.first..][0..ag.n];
        maybe.clearRetainingCapacity();
        total.clearRetainingCapacity();
        maybe.appendNTimes(s.gpa, 0, ag.n) catch return false;
        total.appendNTimes(s.gpa, 0, ag.n) catch return false;
        var ci: usize = 0;
        var p: usize = 0;
        while (p < ag.commit_off) {
            const h = format.short(g[p..]);
            const n = format.lenOf(h.kind, h.size);
            while (ci + 1 < ag.n and ag.off + p >= es[ci].end()) ci += 1;
            if (h.kind != .hole and h.kind != .segment) {
                total.items[ci] += n;
                if (!s.ageSetKnown(g[p..][0..n], format.loc(ag.e, ag.off + p))) maybe.items[ci] += n;
            }
            p += n;
        }
        return true;
    }

    /// Plans the live set for the segment pass at `target` from cursor `start`: the stretches
    /// of aged segments the pass walks next, as many as `age_set_bytes` of bits hold.
    fn ageSetPlan(s: *Store, target: u64, start: u64, limit_epoch: u64) void {
        const st = &s.ager.set;
        st.ranges.clearRetainingCapacity();
        st.state = .none;
        st.target = target;
        st.page = 0;
        st.ahead = 0;
        st.last = 0;
        st.exact = false;
        st.restarts = 0;
        const cap_bits: u64 = @max(@min(s.cfg.age_set_bytes, s.cfg.age_mem_bytes / 2), 8) * 8;
        var used: u64 = 0;
        var cur = start;
        while (used < cap_bits) {
            const at = s.ageCursor(&cur, limit_epoch, false) orelse break;
            const next = if (s.segAfter(at.e)) |n| format.loc(n, 0) else no_loc;
            if (at.c.seg_done >= target) {
                cur = next;
                continue;
            }
            const hi = @min(at.end, at.off +| (cap_bits - used) * AgeSet.cell);
            st.ranges.append(s.gpa, .{ .e = at.e, .lo = at.off, .hi = hi, .base = used }) catch break;
            used += (hi - at.off + AgeSet.cell - 1) / AgeSet.cell;
            if (hi < at.end) break;
            cur = next;
        }
        if (st.ranges.items.len == 0) {
            st.failed = true; // no memory for one range
            return;
        }
        const words: usize = @intCast((used + 63) / 64);
        if (st.bits.len < words) {
            s.gpa.free(st.bits);
            st.bits = &.{};
            st.bits = s.gpa.alloc(u64, words) catch {
                st.failed = true;
                st.ranges.clearRetainingCapacity();
                return;
            };
        }
        @memset(st.bits, 0);
        st.state = .building;
    }

    /// One stretch of the live set's table pass: about `budget` bytes of live-table pages, in
    /// order, every location they name marked. Sequential, read ahead in large requests and
    /// marked cold behind, as the cleaner's count pass reads the table. A table replaced since
    /// the pass began starts it over (a pass that mixed two tables would only miss locations,
    /// which costs lookups, never a record). The caller holds a snapshot.
    fn ageSetScan(s: *Store, budget: u64) void {
        const st = &s.ager.set;
        if (st.state == .links) return s.ageSetLinks(budget);
        const lh = s.live.load(.acquire) orelse return;
        const seq = lh.t.seq.load(.acquire);
        if (st.page != 0) {
            const replaced = lh.tg != st.tg;
            const moved = st.exact and seq != st.seq0;
            if (replaced or (moved and st.restarts < 3)) {
                // Start over: a replaced table always, moved slots three times.
                @memset(st.bits, 0);
                st.page = 0;
                st.ahead = 0;
                if (moved and !replaced) st.restarts += 1;
                _ = s.age_stats.set_restarts.fetchAdd(1, .monotonic);
            } else if (moved) st.exact = false;
        }
        if (st.page == 0) {
            // The counter is read before the first slot. Odd: a deletion is moving slots now.
            if (seq & 1 != 0) return;
            st.tg = lh.tg;
            st.seq0 = seq;
            st.exact = true;
        }
        const pages = lh.t.pages;
        var n = @max(1, budget / page_size);
        if (s.cfg.age_set_step_pages != 0) n = @min(n, s.cfg.age_set_step_pages);
        const want = @min(pages.len, st.page + n);
        const real = s.backend == .real;
        if (real) {
            if (st.page == 0 or st.ahead < want) io_mod.willNeed(tablePages(pages, @max(st.page, st.ahead), want));
            const next = @min(pages.len, want + n);
            if (next > @max(want, st.ahead)) io_mod.willNeed(tablePages(pages, @max(want, st.ahead), next));
            st.ahead = @max(st.ahead, next);
        }
        var marked: u64 = 0;
        var done = st.page;
        while (done < want) : (done += 1) {
            // A cold page is a read: a stop does not wait for the stretch. The pages read so
            // far stay read; the pass is not ready until it has read them all.
            if ((done - st.page) & 63 == 63 and s.ageStopping()) break;
            for (&pages[done].locs) |*lp| {
                const v = @atomicLoad(u64, lp, .monotonic);
                if (v == 0) continue;
                if (st.mark(table.locOf(v))) marked += 1;
            }
        }
        if (real) io_mod.cold(tablePages(pages, st.page, done));
        st.credit += (done - st.page) * page_size;
        _ = s.age_stats.set_pages.fetchAdd(done - st.page, .monotonic);
        _ = s.age_stats.set_marked.fetchAdd(marked, .monotonic);
        st.page = done;
        if (done < want) return;
        if (want == pages.len) {
            // And after the last slot. Moved meanwhile: the next call starts over or gives up
            // exactness (above); the set is not ready until then.
            if (st.exact and lh.t.seq.load(.acquire) != st.seq0) {
                if (st.restarts < 3) return;
                st.exact = false;
            }
            // The table has been read: now the links (`AgeSet`), then the set is ready.
            st.state = .links;
            st.lk_mem = false;
            st.lk_epoch = 0;
            st.lk_run = 0;
            st.lk_entry = 0;
            st.amb_lo = std.math.maxInt(u64);
        }
    }

    /// The link phase of the live set (`AgeSet`): marks every location inside the set's ranges
    /// that a version index entry of the memtable or of a run inside the object window (as of
    /// the durable floors) names. About `budget` bytes of index a call; the memtable in one go.
    fn ageSetLinks(s: *Store, budget: u64) void {
        const st = &s.ager.set;
        const real = s.backend == .real;
        var snap = s.snapshot();
        defer snap.release();
        var marked: u64 = 0;
        var read: u64 = 0;
        defer {
            st.credit += read;
            _ = s.age_stats.set_links.fetchAdd(marked, .monotonic);
        }
        if (!st.lk_mem) {
            const m = s.mem.load(.acquire).?;
            st.amb_lo = @min(st.amb_lo, m.start_loc);
            for (m.ver.entries, 0..) |*en, i| {
                // (Stopped: the next call reads the memtable again from its start.)
                if (i & 0xffff == 0xffff and s.ageStopping()) return;
                const l = @atomicLoad(u64, &en.loc, .acquire);
                if (l != 0 and st.mark(l)) marked += 1;
            }
            st.lk_mem = true;
        }
        while (read < budget) {
            // The lowest epoch with runs at or after the cursor.
            var next: ?u64 = null;
            var i = s.ep_head.load(.acquire);
            const tail = s.ep_tail.load(.acquire);
            while (i < tail) : (i += 1) {
                const e = s.ep_ring[i & s.seg_mask].load(.acquire);
                if (e == no_epoch or e < st.lk_epoch) continue;
                if (next == null or e < next.?) next = e;
            }
            const e = next orelse {
                st.state = .ready;
                _ = s.age_stats.set_builds.fetchAdd(1, .monotonic);
                if (!st.exact) _ = s.age_stats.set_inexact.fetchAdd(1, .monotonic);
                return;
            };
            if (e != st.lk_epoch) {
                st.lk_epoch = e;
                st.lk_run = 0;
                st.lk_entry = 0;
            }
            const run: ?*table.Run = blk: {
                // A link in a run below the object window is one no read follows.
                if (!s.epochInObjWindowDurable(e)) break :blk null;
                const slot = s.slotOf(e) orelse break :blk null;
                if (st.lk_run >= slot.nruns.load(.acquire)) break :blk null;
                break :blk slot.runs[st.lk_run].load(.acquire);
            };
            const r = run orelse {
                // No run left in this epoch as it stands now. (A run sealed into it later holds
                // entries the memtable had when the phase began, or newer ones: `AgeSet`.)
                st.lk_epoch = e + 1;
                st.lk_run = 0;
                st.lk_entry = 0;
                continue;
            };
            st.amb_lo = @min(st.amb_lo, r.header.start_loc);
            const ents = r.ver.entries;
            const from: usize = @intCast(@min(st.lk_entry, ents.len));
            var to: usize = @intCast(@min(ents.len, from + @max(1, (budget - read) / @sizeOf(table.KeyEntry))));
            if (real) io_mod.willNeed(std.mem.sliceAsBytes(ents[from..to]));
            var k = from;
            while (k < to) : (k += 1) {
                if (k & 0xffff == 0xffff and s.ageStopping()) {
                    to = k;
                    break;
                }
                const l = ents[k].loc;
                if (l != 0 and st.mark(l)) marked += 1;
            }
            if (real) io_mod.cold(std.mem.sliceAsBytes(ents[from..to]));
            read += (to - from) * @sizeOf(table.KeyEntry);
            st.lk_entry = to;
            if (to == ents.len) {
                st.lk_run += 1;
                st.lk_entry = 0;
            } else if (s.ageStopping()) return;
        }
    }

    /// The segment pass uses a live set: switched on, with the read-ahead, memory for the bits,
    /// and a table that is filled (not during a bulk load, whose table is empty until it ends).
    fn ageSetOn(s: *const Store) bool {
        return s.cfg.age_live_set and !s.cfg.age_serial and !s.ager.set.failed and s.bulk == null;
    }

    /// Starts (or continues) the batch for segment `e`, committing another segment's batch.
    fn ageBatchFor(s: *Store, c: *CSeg, e: u64) Error!void {
        const a = &s.ager;
        if (a.batch_c == c) return;
        if (a.batch_c != null) try s.ageCommit();
        a.side_new = false;
        if (c.side_fd == null) {
            // Opened before any frame is planned: frames are placed at its end.
            var nb: [64]u8 = undefined;
            const created = !s.backend.exists(sideName(&nb, e));
            const f = try s.backend.openFile(sideName(&nb, e), true);
            c.side_tail = std.mem.alignForward(u64, try s.backend.size(f), block);
            c.side_fd = f;
            a.side_new = created;
        }
        a.batch_c = c;
        a.batch_e = e;
    }

    /// Makes the batch durable and visible: sidecar frames, then age records, then the new
    /// directory; the old frames go to the grace period (`ageReclaim` punches them).
    fn ageCommit(s: *Store) Error!void {
        const a = &s.ager;
        const c = a.batch_c orelse return;
        const e = a.batch_e;
        defer {
            a.batch_c = null;
            a.out.clearRetainingCapacity();
            a.changes.clearRetainingCapacity();
            a.punch.clearRetainingCapacity();
            a.mark_cp = null;
            a.mark_seg = null;
            a.side_new = false;
        }
        if (a.changes.items.len == 0 and a.mark_cp == null and a.mark_seg == null) return;
        var nb: [64]u8 = undefined;
        // The dir file must name every frame of the segment file before entries move away.
        if (!c.dir_sealed) {
            try s.dirPersist(e, c, true);
            c.dir_sealed = true;
        }
        var new_files = false;
        if (c.age_fd == null) {
            const f = try s.backend.openFile(ageName(&nb, e), true);
            c.age_fd = f;
            c.age_seed = s.seed ^ (e *% 0x9e3779b97f4a7c15) ^ 0x616765;
            var h: chunk.AgeHeader = .{ .epoch = e, .seed = c.age_seed };
            h.checksum = h.sum();
            var page: [chunk.age_header_len]u8 = @splat(0);
            @memcpy(page[0..@sizeOf(chunk.AgeHeader)], std.mem.asBytes(&h));
            try s.backend.truncate(f, 0);
            try s.backend.write(f, 0, &page);
            c.age_n = 0;
            c.age_cut = false;
            new_files = true;
        }
        if (a.out.items.len > 0) {
            if (a.side_new) new_files = true;
            try s.backend.write(c.side_fd.?, c.side_tail, a.out.items);
            try s.backend.sync(c.side_fd.?);
        }
        if (new_files) try s.backend.syncDir();
        const af = c.age_fd.?;
        if (c.age_cut) {
            try s.backend.truncate(af, chunk.age_header_len + c.age_n * @sizeOf(chunk.AgeRec));
            c.age_cut = false;
        }
        a.recs.clearRetainingCapacity();
        for (a.changes.items) |ch| a.recs.append(s.gpa, .{ .ls = ch.ls, .phys = ch.phys, .old_phys = ch.old_phys, .ll = ch.ll, .bl = ch.bl, .old_bl = ch.old_bl, .codec = chunk.codecOf(ch.codec), .dict = @intCast(chunk.dictOf(ch.codec)), .kind = 0 }) catch return error.OutOfMemory;
        if (a.mark_cp) |x| a.recs.append(s.gpa, .{ .ls = x, .phys = 0, .kind = 1 }) catch return error.OutOfMemory;
        if (a.mark_seg) |x| a.recs.append(s.gpa, .{ .ls = 0, .phys = x, .kind = 2 }) catch return error.OutOfMemory;
        for (a.recs.items, 0..) |*r, i| r.sum = r.calc(c.age_seed, c.age_n + i);
        s.backend.write(af, chunk.age_header_len + c.age_n * @sizeOf(chunk.AgeRec), std.mem.sliceAsBytes(a.recs.items)) catch |err| {
            c.age_cut = true;
            return err;
        };
        s.backend.sync(af) catch |err| {
            c.age_cut = true;
            return err;
        };
        if (s.age_debug) {
            std.debug.print("age commit e {d} cseg {d}: recs {d}..{d}, side {d}+{d}\n", .{ e, c.id, c.age_n, c.age_n + a.recs.items.len, c.side_tail, a.out.items.len });
            for (a.changes.items) |ch| std.debug.print("  ls {d} ll {d} -> {s} {d} bl {d} (was {s} {d} bl {d})\n", .{ ch.ls, ch.ll, if (chunk.isSide(ch.phys)) "side" else "main", ch.phys & ~chunk.side_bit, ch.bl, if (chunk.isSide(ch.old_phys)) "side" else "main", ch.old_phys & ~chunk.side_bit, ch.old_bl });
        }
        c.age_n += a.recs.items.len;
        if (a.mark_cp) |x| c.cp_done = @max(c.cp_done, x);
        if (a.mark_seg) |x| c.seg_done = @max(c.seg_done, x);
        _ = s.age_stats.phys_written.fetchAdd(a.out.items.len, .monotonic);
        c.side_tail += a.out.items.len;
        if (a.changes.items.len == 0) return;
        // Publish the new directory.
        const d = c.dir.load(.acquire);
        const n = d.len();
        const nd = chunk.Dir.create(s.gpa, n) catch return error.OutOfMemory;
        @memcpy(nd.entries[0..n], d.entries[0..n]);
        nd.main_end = d.physEnd();
        for (a.changes.items) |ch| {
            const en = &nd.entries[ch.idx];
            std.debug.assert(en.ls == ch.ls and en.ll == ch.ll);
            en.phys = ch.phys;
            en.bl = ch.bl;
            en.codec = ch.codec;
        }
        nd.n.store(n, .release);
        const done = s.gpa.create(AgeDone) catch {
            nd.destroy(s.gpa);
            return error.OutOfMemory;
        };
        done.* = .{ .c = c, .old = d };
        errdefer {
            done.punch.deinit(s.gpa);
            done.keys.deinit(s.gpa);
            s.gpa.destroy(done);
        }
        done.punch.appendSlice(s.gpa, a.punch.items) catch return error.OutOfMemory;
        done.keys.ensureTotalCapacity(s.gpa, a.changes.items.len) catch return error.OutOfMemory;
        for (a.changes.items) |ch| done.keys.appendAssumeCapacity((c.id << format.offset_bits) | ch.ls);
        a.handoff.append(s.gpa, done) catch return error.OutOfMemory;
        _ = a.handoff_bytes.fetchAdd(d.entries.len * @sizeOf(chunk.Entry), .monotonic);
        c.dir.store(nd, .release);
        a.handoff_n.store(a.handoff.items.len, .release);
    }

    /// Writer: hands finished rewrites to the grace period (never blocks on a running step).
    fn ageHandoff(s: *Store) void {
        if (s.ager.handoff_n.load(.acquire) == 0) return;
        if (!s.age_mu.tryLock()) return;
        defer s.age_mu.unlock();
        s.ageHandoffLocked();
    }

    fn ageHandoffLocked(s: *Store) void {
        const a = &s.ager;
        for (a.handoff.items) |done| s.retire(.{ .aged = done });
        a.handoff.clearRetainingCapacity();
        a.handoff_bytes.store(0, .monotonic);
        a.handoff_n.store(0, .release);
    }

    fn ageReclaim(s: *Store, done: *AgeDone) void {
        const c = done.c;
        for (done.punch.items) |r| {
            const lo = std.mem.alignForward(u64, r.off, block);
            const hi = std.mem.alignBackward(u64, r.off + r.len, block);
            if (hi <= lo) continue;
            const fd = if (r.side) c.side_fd orelse continue else c.fd;
            if (s.age_debug) std.debug.print("age punch cseg {d} {s} {d}..{d}\n", .{ c.id, if (r.side) "side" else "main", lo, hi });
            s.backend.punch(fd, lo, hi - lo) catch continue;
            _ = s.age_stats.phys_punched.fetchAdd(hi - lo, .monotonic);
        }
        for (done.keys.items) |k| s.cache.drop(k);
        done.old.destroy(s.gpa);
        done.punch.deinit(s.gpa);
        done.keys.deinit(s.gpa);
        s.gpa.destroy(done);
    }

    /// The compressed segment at cursor `cur` (null: no segment at or after it, or a raw one
    /// when `stop_raw`); moves the cursor to the next segment's start when it is past the end.
    fn ageCursor(s: *Store, cur: *u64, limit_epoch: u64, stop_raw: bool) ?struct { e: u64, off: u64, end: u64, c: *CSeg } {
        while (cur.* != no_loc) {
            const e = format.epochOf(cur.*);
            if (e >= limit_epoch) return null;
            const slot = s.slotOf(e) orelse {
                cur.* = if (s.segAfter(e)) |n| format.loc(n, 0) else no_loc;
                continue;
            };
            const end = slot.end.load(.acquire);
            const c = slot.comp.load(.acquire) orelse {
                if (stop_raw and e >= s.oldest_epoch.load(.acquire)) return null;
                cur.* = if (s.segAfter(e)) |n| format.loc(n, 0) else no_loc;
                continue;
            };
            const off = format.offsetOf(cur.*);
            if (off >= end) {
                const next = s.segAfter(e) orelse return null; // the newest: more may come
                cur.* = format.loc(next, 0);
                continue;
            }
            return .{ .e = e, .off = off, .end = end, .c = c };
        }
        return null;
    }

    fn ageInit(s: *Store, snap: *const Snapshot) void {
        const a = &s.ager;
        if (a.init) return;
        a.init = true;
        const oldest = s.oldest_epoch.load(.acquire);
        const first = s.segAfter(if (oldest == 0) null else oldest - 1) orelse return;
        _ = snap;
        // The checkpoint pass resumes where its last mark says; the supersession scan starts
        // there too, so every version between the two floors gets its successor seen (on the
        // node about an epoch of reads once per start, in the background).
        a.cpc = format.loc(first, 0);
        if (s.slotOf(first)) |slot| if (slot.comp.load(.acquire)) |c| {
            a.cpc = format.loc(first, c.cp_done);
        };
        a.scan = a.cpc;
        a.objc = a.cpc;
        a.obj_frontier = a.cpc;
    }

    /// One bounded step of age-out on the calling thread (tests, tools, the simulator); the node
    /// runs `startAger`. Reads about `budget` logical bytes.
    pub fn ageStep(s: *Store, budget: u64) Error!AgeReport {
        return s.ageStepOpts(budget, .{});
    }

    pub fn ageStepOpts(s: *Store, budget: u64, opts: AgeStepOpts) Error!AgeReport {
        if (s.batch_active) return error.BatchActive;
        if (s.poisoned) return error.Poisoned;
        s.age_run.lock();
        s.ageWarm(budget, opts, false);
        s.age_mu.lock();
        const r = s.ageStepLocked(budget, opts);
        s.age_mu.unlock();
        _ = s.ageMem();
        s.ageTrim();
        s.age_run.unlock();
        s.rcuPoll();
        return r;
    }

    fn ageWarmStop(s: *Store) bool {
        return s.ageStopping() or s.age_pause.load(.acquire) != 0;
    }

    /// The ager is being stopped (`stopAger`, a close). Every loop of a step and of its
    /// read-ahead asks, at least once per chunk read, per 64 records judged, per chunk
    /// compressed, per 64 table pages, per wave of read-ahead and per 10 ms of sleep, and gives
    /// up: the stop does not wait for a step, a read-ahead or a nap to run its course.
    fn ageStopping(s: *Store) bool {
        if (s.age_stop.load(.acquire)) return true;
        if (s.age_stop_at) |*n| {
            if (n.* == 0) {
                s.age_stop.store(true, .release);
                return true;
            }
            n.* -= 1;
        }
        return false;
    }

    /// A step's loops end here: the writer wants the lock (`age_yield`), or the ager stops.
    fn ageHalt(s: *Store) bool {
        return s.age_yield.load(.acquire) or s.ageStopping();
    }

    /// A stopped step leaves its batch unwritten. Nothing of it is on disk (the sidecar frames,
    /// the age records and the new directory are all written by `ageCommit`), so this is what
    /// a crash before the batch would leave. The cursors moved past groups whose rewrite is
    /// dropped here: they are placed again from the durable marks at the next step.
    fn ageAbort(s: *Store) void {
        const a = &s.ager;
        a.batch_c = null;
        a.out.clearRetainingCapacity();
        a.changes.clearRetainingCapacity();
        a.punch.clearRetainingCapacity();
        a.mark_cp = null;
        a.mark_seg = null;
        a.side_new = false;
        a.init = false;
        a.lagq.clearRetainingCapacity();
        a.lag_head = 0;
        a.scan_wait = no_loc;
        a.cp_wait = no_loc;
        a.seg_target = 0;
        a.segc = no_loc;
        a.set.state = .none;
    }

    /// Sleeps `ns` unless the ager is stopped meanwhile (10 ms at a time).
    fn ageNap(s: *Store, ns: u64) void {
        var left = ns;
        while (left > 0 and !s.age_stop.load(.acquire)) {
            const step: u64 = @min(left, 10 * std.time.ns_per_ms);
            clock.sleep(step);
            left -= step;
        }
    }

    /// Read-ahead for the step `ageStepLocked(budget, opts)` is about to run, without `age_mu`:
    /// a dry run of the step's passes on copies of its cursors. Every frame the step will
    /// decode is read here first, so it is in the page cache, and the live-table pages the
    /// step's lookups will touch are collected and read `age_qd` at a time (`ageWarmTable`).
    /// Before, the step read its frames and took one page fault per lookup with `age_mu` held
    /// (an 8 GiB edge with a 19.6 GiB table: 760 to 1,745 major faults a second, one read in
    /// flight, lane ager-catchup). It changes no ager state and writes nothing: a hint. Any
    /// error ends it, and what was not read ahead the step reads as before. The caller holds
    /// `age_run`; `paced`: the ager thread (`age_share_pct`).
    fn ageWarm(s: *Store, budget: u64, opts: AgeStepOpts, paced: bool) void {
        const a = &s.ager;
        const w = &a.warm;
        w.on = false;
        w.pages.clearRetainingCapacity();
        if (s.cfg.age_serial or !a.init or s.poisoned) return;
        const t0 = clock.now();
        defer _ = s.age_stats.warm_ns.fetchAdd(clock.now() -| t0, .monotonic);
        var snap = s.snapshot();
        var held = true;
        defer if (held) snap.release();
        const newest = s.newestEpoch() orelse return;
        const obj_floor = @min(s.obj_floor.load(.acquire), s.dfloors.obj.load(.acquire));
        const cp_floor = @min(s.cp_floor.load(.acquire), s.dfloors.cp.load(.acquire));
        const oldest = @min(s.oldest_epoch.load(.acquire), s.dfloors.oldest.load(.acquire));
        const ofe = @min(s.obj_floor_epoch.load(.acquire), s.dfloors.obj_epoch.load(.acquire));
        const lag = s.cfg.age_lag_checkpoints;
        var read: u64 = 0;
        var groups: u64 = 0;
        // 1. The scan: frames only (it makes no lookup). Where it ends moves the object pass's
        // frontier, as in the step.
        var frontier = a.obj_frontier;
        var lag_open = true;
        for (a.lagq.items[a.lag_head..]) |q| {
            if (q.seq + lag >= obj_floor) {
                lag_open = false;
                break;
            }
            frontier = q.end;
        }
        var scan = a.scan;
        while (read < budget and !s.ageWarmStop()) {
            const at = s.ageCursor(&scan, newest + 1, false) orelse break;
            if (a.scan_wait == scan and a.scan_wait_seq >= obj_floor) break;
            const ag = (s.ageLoadGroupInto(&w.g, at.c, at.e, at.off, at.end) catch break) orelse break;
            read += ag.len;
            groups += 1;
            if (ag.seq >= obj_floor) break;
            scan = format.loc(at.e, at.off + ag.len);
            if (lag_open and ag.seq + lag < obj_floor) frontier = scan else lag_open = false;
        }
        // 2. Object pass.
        var objc = a.objc;
        while (read < budget and objc < frontier and !s.ageWarmStop()) {
            const at = s.ageCursor(&objc, newest, false) orelse break;
            if (format.loc(at.e, at.off) >= frontier) break;
            const ag = (s.ageLoadGroupInto(&w.g, at.c, at.e, at.off, at.end) catch break) orelse break;
            read += ag.len;
            groups += 1;
            s.ageWarmIds(&snap, ag, at.e < ofe or at.e < oldest);
            objc = format.loc(at.e, at.off + ag.len);
        }
        // 3. Checkpoint pass.
        var cpc = a.cpc;
        while (read < budget and !s.ageWarmStop()) {
            const at = s.ageCursor(&cpc, newest, true) orelse break;
            if (a.cp_wait == cpc and a.cp_wait_seq + 1 >= cp_floor) break;
            const ag = (s.ageLoadGroupInto(&w.g, at.c, at.e, at.off, at.end) catch break) orelse break;
            read += ag.len;
            groups += 1;
            if (ag.seq + 1 >= cp_floor) break;
            s.ageWarmIds(&snap, ag, at.e < ofe or at.e < oldest);
            cpc = format.loc(at.e, at.off + ag.len);
        }
        // 4. Segment pass.
        if (!opts.skip_seg) {
            var seg_target = a.seg_target;
            var segc = a.segc;
            const target = @max(ofe, oldest);
            if (target > seg_target) {
                seg_target = target;
                segc = if (s.segAfter(null)) |f| format.loc(f, 0) else no_loc;
            }
            // The live set first: the step walks nothing it does not cover. Its table pass
            // runs here, a stretch per step, with no lock held.
            var walk = true;
            if (s.ageSetOn() and read < budget) {
                var peek = segc;
                const lim = @min(seg_target, newest);
                const first = while (true) {
                    const at = s.ageCursor(&peek, lim, false) orelse break null;
                    if (at.c.seg_done < seg_target) break at;
                    peek = if (s.segAfter(at.e)) |n| format.loc(n, 0) else no_loc;
                };
                if (first) |at| {
                    if (!a.set.covers(seg_target, at.e, at.off)) s.ageSetPlan(seg_target, peek, lim);
                    if (a.set.state == .building or a.set.state == .links) s.ageSetScan(budget - read);
                    walk = a.set.state == .ready or !s.ageSetOn();
                } else if (a.set.bits.len != 0) a.set.release(s.gpa); // the pass is over
            }
            while (walk and read < budget and !s.ageWarmStop()) {
                const at = s.ageCursor(&segc, @min(seg_target, newest), false) orelse break;
                if (at.c.seg_done >= seg_target) {
                    segc = if (s.segAfter(at.e)) |n| format.loc(n, 0) else no_loc;
                    continue;
                }
                if (s.ageSetOn() and !a.set.usable(at.e, at.off)) break;
                const ag = (s.ageLoadGroupInto(&w.g, at.c, at.e, at.off, at.end) catch break) orelse break;
                read += ag.len;
                groups += 1;
                s.ageWarmIds(&snap, ag, true);
                segc = format.loc(at.e, at.off + ag.len);
            }
        }
        _ = s.age_stats.warm_groups.fetchAdd(groups, .monotonic);
        // The walk's snapshot ends here: the table reads take their own, a slice at a time.
        snap.release();
        held = false;
        s.ageWarmTable(paced);
    }

    /// Notes the live-table page of every record of group `ag` (decoded in the read-ahead's
    /// buffer) that `ageDrop` will look up: object versions and tombstones that are in
    /// `pending` or under the whole-segment rule. Ids are read as `ageDrop` reads them, without
    /// the checksum: a damaged record asks for a useless page, nothing else.
    fn ageWarmIds(s: *Store, snap: *const Snapshot, ag: AgeGroup, seg_rule: bool) void {
        const a = &s.ager;
        const w = &a.warm;
        const g = w.g.items;
        const t = snap.liveTable();
        // As `ageRewrite` will decide: no lookup in a group or chunk that cannot be rewritten,
        // none for a record the live set names.
        const filt = s.ageSetChunks(g, ag, &w.maybe, &w.total);
        const whole_g = ag.len <= s.cfg.age_whole_group_bytes;
        if (filt and whole_g) {
            var m: u64 = 0;
            var tot: u64 = 0;
            for (w.maybe.items, w.total.items) |x, y| {
                m += x;
                tot += y;
            }
            if (m * 8 < tot) return;
        }
        const es = ag.d.slice()[ag.first..][0..ag.n];
        var ci: usize = 0;
        var p: usize = 0;
        while (p + format.short_len <= ag.commit_off) {
            const h = format.short(g[p..]);
            const n = format.lenOf(h.kind, h.size);
            if (n == 0 or p + n > g.len) break;
            const rec = g[p..][0..n];
            const l = format.loc(ag.e, ag.off + p);
            while (ci + 1 < ag.n and ag.off + p >= es[ci].end()) ci += 1;
            p += n;
            if (filt and !whole_g and !ageSetCould(w.maybe.items[ci], w.total.items[ci])) continue;
            if (filt and s.ageSetKnown(rec, l)) continue;
            // An object version with a clear bit in an exact set is judged without a lookup.
            if (filt and h.kind != .remove and !s.cfg.age_set_verify and a.set.proves(l)) continue;
            const hl = format.hdrLen(h.kind);
            if (hl + h.size > rec.len) continue;
            const whole = rec[0 .. hl + h.size];
            const id: [32]u8 = switch (h.kind) {
                .object, .object_c => blk: {
                    if (h.flags & format.flag_historical != 0) continue;
                    if (!seg_rule and !a.pending.contains(l)) continue;
                    const o = s.objRec(whole) catch continue;
                    if (o.version > std.math.maxInt(i64)) continue;
                    break :blk o.id;
                },
                .remove => blk: {
                    if (!seg_rule and !a.pending.contains(l)) continue;
                    if (whole.len < format.header_len + @sizeOf(format.RemoveFixed)) continue;
                    break :blk format.fixed(format.RemoveFixed, whole).id;
                },
                else => continue,
            };
            w.pages.append(s.gpa, t.homeSlot(&id) / table.per_page) catch return;
        }
    }

    /// Reads the collected live-table pages ahead: sorted, each once, `age_qd` in flight through
    /// io_uring (`prefetch.Prefetcher.pages`), or without it MADV_WILLNEED on all of a slice and
    /// then a touch of each page, so the reads are in flight together and are in before the
    /// step takes `age_mu`. Real files only (the simulator's table is memory).
    fn ageWarmTable(s: *Store, paced: bool) void {
        const w = &s.ager.warm;
        std.mem.sort(u64, w.pages.items, {}, std.sort.asc(u64));
        var n: usize = 0;
        for (w.pages.items) |pg| {
            if (n > 0 and w.pages.items[n - 1] == pg) continue;
            w.pages.items[n] = pg;
            n += 1;
        }
        w.pages.shrinkRetainingCapacity(n);
        w.on = true;
        _ = s.age_stats.warm_pages.fetchAdd(n, .monotonic);
        if (s.backend != .real or n == 0) return;
        // A reader for one slice at a time, never across a sleep: while a snapshot is held the
        // store frees nothing it retires (evicted chunks, memtables, old directories), so a
        // read-ahead of seconds under one snapshot would hold all of that back.
        w.io.clearRetainingCapacity();
        {
            var snap = s.snapshot();
            defer snap.release();
            const lh = s.live.load(.acquire) orelse return;
            const t = &lh.t;
            for (w.pages.items) |pg| {
                if (pg >= t.pages.len) continue;
                // A page the writer holds dirty is in memory already.
                if (@atomicLoad(u64, &t.dirty[pg / 64], .monotonic) & (@as(u64, 1) << @intCast(pg % 64)) != 0) continue;
                w.io.append(s.gpa, pg) catch break;
            }
        }
        if (w.io.items.len != 0) _ = s.ageReader();
        const slice: usize = @max(64, @as(usize, s.cfg.age_qd) * 16);
        const share = @max(s.cfg.age_share_pct, 1);
        var i: usize = 0;
        while (i < w.io.items.len and !s.ageWarmStop()) {
            const part = w.io.items[i..@min(w.io.items.len, i + slice)];
            const t0 = clock.now();
            {
                var snap = s.snapshot();
                defer snap.release();
                const lh = s.live.load(.acquire) orelse return;
                s.ageWarmPages(lh, part);
            }
            i += part.len;
            if (paced and share < 100 and i < w.io.items.len) {
                const nap = (clock.now() -| t0) * (100 - share) / share;
                s.ageNap(@min(nap, std.time.ns_per_s));
            }
        }
    }

    fn ageWarmPages(s: *Store, lh: *LiveHandle, part: []const u64) void {
        const t = &lh.t;
        const st = &s.age_stats;
        if (s.ager.warm.pf) |pf| if (!pf.broken) {
            if (s.backend.real.files[lh.fd]) |f| {
                const errs0 = pf.stats.errors.load(.monotonic);
                _ = pf.pages(f.handle, part, &s.age_stop);
                _ = st.warm_errors.fetchAdd(pf.stats.errors.load(.monotonic) -| errs0, .monotonic);
                // A ring that failed in this call read an unknown part: the fallback reads it.
                if (!pf.broken) {
                    _ = st.warm_uring_pages.fetchAdd(part.len, .monotonic);
                    return;
                }
            }
        };
        _ = st.warm_fallback_pages.fetchAdd(part.len, .monotonic);
        var k: usize = 0;
        while (k < part.len) {
            var e = k + 1;
            while (e < part.len and part[e] == part[e - 1] + 1) e += 1;
            io_mod.willNeed(tablePages(t.pages, part[k], part[e - 1] + 1));
            k = e;
        }
        var sum: u64 = 0;
        for (part, 0..) |pg, n| {
            // Each touch can wait for its read: a stop leaves the rest unread.
            if (n & 31 == 31 and s.age_stop.load(.acquire)) break;
            if (pg >= t.pages.len) continue;
            sum +%= @atomicLoad(u64, &t.pages[pg].locs[0], .monotonic);
        }
        std.mem.doNotOptimizeAway(sum);
    }

    /// How the ager reads live-table pages ahead of a step (`ageWarmPages`).
    pub const AgeReader = enum {
        /// No read-ahead (`Config.age_serial`, or not real files): a page fault per lookup.
        none,
        /// io_uring (`prefetch.Prefetcher.pages`), `Config.age_qd` reads in flight.
        uring,
        /// MADV_WILLNEED on a slice of pages, then a touch of each (no io_uring: not Linux, or
        /// the ring could not be set up or failed).
        fallback,
    };

    /// The reader the ager has now. It sets the io_uring reader up at its first read-ahead with
    /// pages to read; `startAgerMode` does that at once, so the answer is known at start.
    pub fn ageReader(s: *Store) AgeReader {
        if (s.cfg.age_serial or s.backend != .real) return .none;
        const w = &s.ager.warm;
        if (!w.pf_tried) {
            w.pf_tried = true;
            w.pf = prefetch.Prefetcher.init(s.gpa, s.cfg.age_qd) catch null;
        }
        if (w.pf) |pf| if (!pf.broken) return .uring;
        return .fallback;
    }

    /// The node's catch-up signal for deferred age-out: true while it is far behind the tip.
    /// Any thread.
    pub fn ageBehind(s: *Store, behind: bool) void {
        s.age_behind.store(behind, .release);
    }

    /// Whether the ager may run now (the ager thread; the simulator drives the same rule).
    /// `run`: not deferred, or the node is at the tip. `wait`: deferred and behind. `bulk`:
    /// deferred and behind, but `age_defer_bytes` of history wait below the checkpoint floor:
    /// run the passes over it (`AgeStepOpts.skip_seg`) until a step is idle, then call
    /// `ageBulkDone`.
    pub fn ageGate(s: *Store) AgeGate {
        if (s.age_mode == .on or !s.age_behind.load(.acquire)) {
            s.age_bulk = false;
            return .run;
        }
        if (s.age_bulk) return .bulk;
        s.age_run.lock();
        const backlog = s.ageBacklog();
        s.age_run.unlock();
        s.age_stats.backlog.store(backlog, .monotonic);
        if (backlog < s.cfg.age_defer_bytes) return .wait;
        s.age_bulk = true;
        _ = s.age_stats.bulk_runs.fetchAdd(1, .monotonic);
        return .bulk;
    }

    /// Logical bytes of history below the durable checkpoint floor that the checkpoint pass has
    /// not passed: what a waiting ager holds back (checkpoints, transactions and aux data, most
    /// of what the store appends, and the object versions superseded there). Sums the segments
    /// from the pass's cursor (its durable mark after a restart) to the record of the last
    /// checkpoint below the floor, over the segments the pass can cross (sealed, compressed).
    /// Under `age_run` (the ager's cursor), not `age_mu`: the index lookup may read a page.
    fn ageBacklog(s: *Store) u64 {
        const a = &s.ager;
        const cp_floor = @min(s.cp_floor.load(.acquire), s.dfloors.cp.load(.acquire));
        if (cp_floor < 2) return 0;
        // A reader from here on: the segment whose mark is read below must not be freed under
        // this call (the writer deletes segments without `age_run`).
        var snap = s.snapshot();
        defer snap.release();
        const newest = s.newestEpoch() orelse return 0;
        const oldest = s.oldest_epoch.load(.acquire);
        const window = s.segAfter(if (oldest == 0) null else oldest - 1) orelse return 0;
        var cur: u64 = undefined;
        if (a.init) {
            if (a.cp_wait == a.cpc and a.cp_wait_seq + 1 >= cp_floor) return 0; // at the floor
            cur = a.cpc;
        } else {
            // As `ageInit` will set it: the first segment of the window, from its durable mark.
            cur = format.loc(window, 0);
            if (s.slotOf(window)) |slot| if (slot.comp.load(.acquire)) |c| {
                cur = format.loc(window, c.cp_done);
            };
        }
        // The pass ends at the group of checkpoint `cp_floor - 1` (kept: `checkpointHeld`). Not
        // indexed means its segment aged out (runs dropped): everything before the window.
        const stop = cpLocOf(&snap, cp_floor - 1) orelse format.loc(window, 0);
        var sum: u64 = 0;
        while (cur != no_loc and cur < stop) {
            const at = s.ageCursor(&cur, newest, true) orelse break;
            if (format.loc(at.e, at.off) >= stop) break;
            if (format.epochOf(stop) == at.e) {
                sum += format.offsetOf(stop) -| at.off;
                break;
            }
            sum += at.end -| at.off;
            cur = if (s.segAfter(at.e)) |n| format.loc(n, 0) else no_loc;
        }
        return sum;
    }

    /// A bulk step was idle: the catch-up is over, the ager waits again.
    pub fn ageBulkDone(s: *Store) void {
        s.age_bulk = false;
    }

    /// Runs `ageStep` until idle, then waits out the grace periods (no snapshot may be open):
    /// every punch is done when it returns.
    pub fn ageAll(s: *Store) Error!AgeReport {
        var tot: AgeReport = .{};
        var guard: u32 = 0;
        while (guard < 1 << 20) : (guard += 1) {
            const r = try s.ageStep(64 << 20);
            inline for (.{ "groups_scanned", "groups_rewritten", "chunks_rewritten", "records_dropped", "bytes_dropped", "phys_written", "phys_queued", "read" }) |name| {
                @field(tot, name) += @field(r, name);
            }
            if (r.idle) break;
        }
        s.rcuPoll();
        s.rcuPoll();
        return tot;
    }

    fn ageStepLocked(s: *Store, budget: u64, opts: AgeStepOpts) Error!AgeReport {
        const t0 = clock.now();
        var rep: AgeReport = .{};
        const a = &s.ager;
        var snap = s.snapshot();
        defer snap.release();
        const newest = s.newestEpoch() orelse {
            rep.idle = true;
            return rep;
        };
        s.ageInit(&snap);
        if (!a.init) {
            rep.idle = true;
            return rep;
        }
        errdefer {
            a.batch_c = null;
            a.out.clearRetainingCapacity();
            a.changes.clearRetainingCapacity();
            a.punch.clearRetainingCapacity();
        }
        // Durable floors only (a crash may bring back the meta before the newest floors).
        const obj_floor = @min(s.obj_floor.load(.acquire), s.dfloors.obj.load(.acquire));
        const cp_floor = @min(s.cp_floor.load(.acquire), s.dfloors.cp.load(.acquire));
        const oldest = @min(s.oldest_epoch.load(.acquire), s.dfloors.oldest.load(.acquire));
        const ofe = @min(s.obj_floor_epoch.load(.acquire), s.dfloors.obj_epoch.load(.acquire));
        const lag = s.cfg.age_lag_checkpoints;
        a.cp_floor = cp_floor;
        a.lookups = 0;
        a.lookups_cold = 0;
        a.set_kept = 0;

        // 1. Supersession scan up to the object floor (any segment, the open one too).
        while (rep.read < budget and !s.ageHalt()) {
            const at = s.ageCursor(&a.scan, newest + 1, false) orelse break;
            if (a.scan_wait == a.scan and a.scan_wait_seq >= obj_floor) break;
            const ag = (try s.ageLoadGroup(at.c, at.e, at.off, at.end)) orelse break;
            rep.read += ag.len;
            if (ag.seq >= obj_floor) {
                a.scan_wait = a.scan;
                a.scan_wait_seq = ag.seq;
                break;
            }
            s.ageCollect(a.g.items, ag.commit_off);
            a.scan = format.loc(at.e, at.off + ag.len);
            a.lagq.append(s.gpa, .{ .end = a.scan, .seq = ag.seq }) catch return error.OutOfMemory;
            rep.groups_scanned += 1;
        }
        // 2. Object pass, `lag` checkpoints behind the scan (sealed segments).
        while (a.lag_head < a.lagq.items.len and a.lagq.items[a.lag_head].seq + lag < obj_floor) : (a.lag_head += 1) a.obj_frontier = a.lagq.items[a.lag_head].end;
        if (a.lag_head > 4096) {
            const rest = a.lagq.items.len - a.lag_head;
            std.mem.copyForwards(Lag, a.lagq.items[0..rest], a.lagq.items[a.lag_head..]);
            a.lagq.shrinkRetainingCapacity(rest);
            a.lag_head = 0;
        }
        while (rep.read < budget and a.objc < a.obj_frontier and !s.ageHalt()) {
            const at = s.ageCursor(&a.objc, newest, false) orelse break;
            if (format.loc(at.e, at.off) >= a.obj_frontier) break;
            const ag = (try s.ageLoadGroup(at.c, at.e, at.off, at.end)) orelse break;
            rep.read += ag.len;
            try s.ageRewrite(&snap, ag, false, at.e < ofe or at.e < oldest, &rep);
            if (s.age_stop.load(.acquire)) break;
            a.objc = format.loc(at.e, at.off + ag.len);
        }
        // 3. Checkpoint pass up to the checkpoint floor (sealed segments; stops at a raw one in
        // the window).
        while (rep.read < budget and !s.ageHalt()) {
            const at = s.ageCursor(&a.cpc, newest, true) orelse break;
            if (a.cp_wait == a.cpc and a.cp_wait_seq + 1 >= cp_floor) break;
            const ag = (try s.ageLoadGroup(at.c, at.e, at.off, at.end)) orelse break;
            rep.read += ag.len;
            if (ag.seq + 1 >= cp_floor) {
                a.cp_wait = a.cpc;
                a.cp_wait_seq = ag.seq;
                break;
            }
            try s.ageRewrite(&snap, ag, true, at.e < ofe or at.e < oldest, &rep);
            if (s.age_stop.load(.acquire)) break;
            a.cpc = format.loc(at.e, at.off + ag.len);
            const noff = at.off + ag.len;
            if (noff >= at.end or noff - at.c.cp_done >= 64 << 20) {
                try s.ageBatchFor(at.c, at.e);
                a.mark_cp = noff;
            }
        }
        // 4. Segment pass over the segments the object window left (once per object floor
        // epoch): the restored live set loses its superseded versions here.
        const target = @max(ofe, oldest);
        if (target > a.seg_target and !opts.skip_seg) {
            a.seg_target = target;
            a.segc = if (s.segAfter(null)) |f| format.loc(f, 0) else no_loc;
        }
        var set_wait = false;
        while (!opts.skip_seg and rep.read < budget and !s.ageHalt()) {
            const at = s.ageCursor(&a.segc, @min(a.seg_target, newest), false) orelse break;
            if (at.c.seg_done >= a.seg_target) {
                a.segc = if (s.segAfter(at.e)) |n| format.loc(n, 0) else no_loc;
                continue;
            }
            // With the live set the pass waits for it (the read-ahead builds it before the
            // next step) instead of looking every record up.
            if (s.ageSetOn() and !(a.set.target == a.seg_target and a.set.usable(at.e, at.off))) {
                set_wait = true;
                break;
            }
            const ag = (try s.ageLoadGroup(at.c, at.e, at.off, at.end)) orelse break;
            rep.read += ag.len;
            try s.ageRewrite(&snap, ag, at.e < oldest, true, &rep);
            if (s.age_stop.load(.acquire)) break;
            // A pass over everything aged, once an epoch: its frames leave the page cache
            // behind it, or it pushes out what the node reads all the time.
            if (s.ageSetOn()) for (ag.d.slice()[ag.first..][0..ag.n]) |en| {
                const fd = if (chunk.isSide(en.phys)) (at.c.side_fd orelse continue) else at.c.fd;
                s.backend.dropCache(fd, en.phys & ~chunk.side_bit, chunk.frame_len + en.bl, false);
            };
            const noff = at.off + ag.len;
            a.segc = format.loc(at.e, noff);
            if (noff >= at.end) {
                try s.ageBatchFor(at.c, at.e);
                a.mark_seg = a.seg_target;
                _ = s.age_stats.seg_passes.fetchAdd(1, .monotonic);
            }
        }
        // Stopped: the batch is not written (two writes and up to four syncs the close would
        // wait for); see `ageAbort`.
        if (s.age_stop.load(.acquire)) {
            s.ageAbort();
            return rep;
        }
        try s.ageCommit();
        // The live set's table pass read this much since the last step: work, not idleness.
        // Nor is a step idle that only waited for the set (the next read-ahead builds it).
        rep.read += a.set.credit;
        a.set.credit = 0;
        if (rep.read == 0 and !set_wait) rep.idle = true;
        const st = &s.age_stats;
        _ = st.steps.fetchAdd(1, .monotonic);
        _ = st.groups_rewritten.fetchAdd(rep.groups_rewritten, .monotonic);
        _ = st.chunks_rewritten.fetchAdd(rep.chunks_rewritten, .monotonic);
        _ = st.records_dropped.fetchAdd(rep.records_dropped, .monotonic);
        _ = st.objects_dropped.fetchAdd(rep.objects_dropped, .monotonic);
        _ = st.tombstones_dropped.fetchAdd(rep.tombstones_dropped, .monotonic);
        _ = st.bytes_dropped.fetchAdd(rep.bytes_dropped, .monotonic);
        _ = st.lookups.fetchAdd(a.lookups, .monotonic);
        _ = st.lookups_cold.fetchAdd(a.lookups_cold, .monotonic);
        _ = st.set_kept.fetchAdd(a.set_kept, .monotonic);
        const ns = clock.now() -| t0;
        _ = st.locked_ns.fetchAdd(ns, .monotonic);
        var cur = st.max_step_ns.load(.monotonic);
        while (ns > cur) cur = st.max_step_ns.cmpxchgWeak(cur, ns, .monotonic, .monotonic) orelse break;
        return rep;
    }

    /// Runs age-out on a background thread (real files): bounded steps, paced to
    /// `age_mbps` of logical bytes read, idle naps when there is nothing to do.
    pub fn startAger(s: *Store) !void {
        return s.startAgerMode(.on);
    }

    /// `startAger` in `mode`. Deferred: the ager waits until the node first says it is at the
    /// tip (`ageBehind(false)`), so a start in catch-up does not begin with a step.
    pub fn startAgerMode(s: *Store, mode: AgeMode) !void {
        if (s.age_thread != null or s.backend != .real) return;
        s.age_mode = mode;
        if (mode == .deferred) s.age_behind.store(true, .release);
        // The reader is set up before the thread starts, so `ageReader` can say which it is.
        _ = s.ageReader();
        s.age_stop.store(false, .release);
        s.age_thread = try std.Thread.spawn(.{}, agerMain, .{s});
    }

    /// Stops the ager thread and returns when it is gone. The thread is told first (the stop
    /// flag, and the yield a running step's loops also watch) and then joined; it gives up
    /// whatever it is doing (`ageStopping`): a read-ahead is left where it is, a step under
    /// `age_mu` ends at its next check without writing its batch (`ageAbort`), a nap ends.
    /// What it cannot give up is the one operation it is inside: a chunk's read and decode, a
    /// chunk's compression, up to 64 lookups, the reads already handed to the ring (`age_qd`),
    /// or, if the stop arrives while a batch is being written, that batch's writes and syncs
    /// (at most `age_budget` of frames, an age log append, a directory file). So a close waits
    /// for the ager for tens of milliseconds, and for one sync of the disk at worst.
    pub fn stopAger(s: *Store) void {
        const th = s.age_thread orelse return;
        s.age_stop.store(true, .release);
        s.age_yield.store(true, .release);
        th.join();
        s.age_thread = null;
    }

    /// Pauses age-out (a snapshot being written reads object chains of an older checkpoint).
    /// Counted (lane index-fast: a snapshot write and a fast-start live scan may overlap). Returns
    /// once no age-out step runs: the ager checks the count only between steps, and a step
    /// already running would punch the holes the pausing reader must not see.
    pub fn agePause(s: *Store, on: bool) void {
        if (on) _ = s.age_pause.fetchAdd(1, .acq_rel) else _ = s.age_pause.fetchSub(1, .acq_rel);
        if (on) {
            s.age_yield.store(true, .release);
            s.age_mu.lock();
            s.age_mu.unlock();
        }
    }

    fn agerMain(s: *Store) void {
        while (!s.age_stop.load(.acquire)) {
            if (s.age_pause.load(.acquire) != 0) {
                s.ageNap(200 * std.time.ns_per_ms);
                continue;
            }
            // Deferred and the node is behind the tip: catch-up has the disk to itself.
            const gate = s.ageGate();
            if (gate == .wait) {
                _ = s.age_stats.deferred.fetchAdd(1, .monotonic);
                s.ageNap(std.time.ns_per_s);
                continue;
            }
            // A finished rewrite holds its segment's old directory until the writer takes it
            // (`ageHandoff`, at each commit, when `age_mu` is free). An ager that went on would
            // pile them up: with the lock held nearly all the time the writer never got them,
            // and each is a copy of the directory (GiBs after a few hundred steps over a
            // restore image). So no step starts while more than an eighth of the ager's
            // memory waits there; the lock is free meanwhile, and the next commit takes them.
            if (s.ager.handoff_bytes.load(.monotonic) > s.cfg.age_mem_bytes / 8) {
                _ = s.age_stats.handoff_waits.fetchAdd(1, .monotonic);
                s.ageNap(std.time.ns_per_ms);
                continue;
            }
            const opts: AgeStepOpts = .{ .skip_seg = gate == .bulk };
            const t0 = clock.now();
            // The disk reads first, with no lock the writer may want: the step then runs on
            // what is in memory.
            s.age_run.lock();
            s.ageWarm(s.cfg.age_budget, opts, true);
            s.age_mu.lock();
            if (s.age_pause.load(.acquire) != 0) {
                // paused between the check above and the lock (agePause waits on this lock)
                s.age_mu.unlock();
                s.age_run.unlock();
                continue;
            }
            // (Not while stopping: `stopAger` raised the yield so that this step's loops end.)
            if (!s.age_stop.load(.acquire)) s.age_yield.store(false, .release);
            const r = s.ageStepLocked(s.cfg.age_budget, opts) catch |err| {
                s.age_mu.unlock();
                s.age_run.unlock();
                std.log.err("store: age-out stopped: {s} (restart to retry)", .{@errorName(err)});
                s.age_stats.failed.store(true, .release);
                return;
            };
            s.age_mu.unlock();
            _ = s.ageMem();
            s.ageTrim();
            s.age_run.unlock();
            if (gate == .bulk and r.idle) s.ageBulkDone();
            if (r.idle) {
                s.ageNap(std.time.ns_per_s);
                continue;
            }
            const busy = clock.now() -| t0;
            const want = r.read * std.time.ns_per_s / (@max(s.cfg.age_mbps, 1) << 20);
            if (want > busy) s.ageNap(want - busy);
        }
    }

    // ------------------------------------------------------------------ reading

    /// MVCC snapshot at the newest committed checkpoint. Readers on any thread.
    pub fn snapshot(s: *Store) Snapshot {
        const p = s.rcu.enter();
        const ce = s.creaders.enter();
        return .{ .store = s, .c1 = s.committed1.load(.acquire), .parity = p, .cepoch = ce };
    }

    /// The record at `l` (header ++ payload), checked, for the snapshot of reader epoch `ep`.
    fn record(s: *Store, l: u64, ep: u64) Error![]const u8 {
        const e = format.epochOf(l);
        const slot = s.slotOf(e) orelse return error.NotFound;
        const end = slot.end.load(.acquire);
        const base = slot.base.load(.acquire);
        const comp = slot.comp.load(.acquire);
        // The slot may have been retired (and reused) since slotOf: then the view is stale.
        if (slot.epoch.load(.seq_cst) != e) return error.NotFound;
        const off = format.offsetOf(l);
        if (off + format.short_len > end) return error.Corrupt;
        if (comp) |c| {
            const en = c.dir.load(.acquire).find(off) orelse return error.Corrupt;
            const data = try s.chunkData(c, en, ep);
            const rel = off - en.ls;
            if (rel + format.short_len <= data.len and format.short(data[rel..]).kind == .hole) return error.NotFound;
            if (s.cfg.verify_reads) return format.validate(data, rel, l);
            if (rel + format.short_len > data.len) return error.Corrupt;
            const h = format.short(data[rel..]);
            const hl = format.hdrLen(h.kind);
            if (rel + hl + h.size > data.len) return error.Corrupt;
            return data[rel..][0 .. hl + h.size];
        }

        const data = @as([*]const u8, @ptrFromInt(base))[0..end];
        if (s.cfg.verify_reads) return format.validate(data, off, l);
        const h = format.short(data[off..]);
        const hl = format.hdrLen(h.kind);
        if (off + hl + h.size > end) return error.Corrupt;
        return data[off..][0 .. hl + h.size];
    }

    /// A walk-private decoded chunk (forEachLive): one buffer reused while consecutive records
    /// share a chunk, never the shared cache. A walk holds one snapshot from start to end, and the
    /// cache's evicted chunks are only freed once every snapshot that could see them is gone, so a
    /// cached walk over a compressed store would pin every chunk it read (OOM at 60 GiB on the
    /// 140 GB epoch-1304 segment).
    pub const WalkBuf = struct {
        key: u64 = std.math.maxInt(u64),
        data: std.ArrayList(u8) = .empty,
        /// Raw segments: a walk in location order reads ahead itself, since store mappings are
        /// MADV_RANDOM (lane fast-start 2295d4f).
        ra: ReadAhead = .{},

        pub fn deinit(wb: *WalkBuf, gpa: std.mem.Allocator) void {
            wb.data.deinit(gpa);
        }
    };

    /// `record`, but a compressed segment's chunk is decoded into `wb` (valid until the next call).
    fn recordWalk(s: *Store, l: u64, wb: *WalkBuf, ep: u64) Error![]const u8 {
        const e = format.epochOf(l);
        const slot = s.slotOf(e) orelse return error.NotFound;
        const comp = slot.comp.load(.acquire) orelse {
            wb.ra.at(s, l);
            return s.record(l, ep);
        };
        const end = slot.end.load(.acquire);
        if (slot.epoch.load(.seq_cst) != e) return error.NotFound;
        const off = format.offsetOf(l);
        if (off + format.short_len > end) return error.Corrupt;
        const en = comp.dir.load(.acquire).find(off) orelse return error.Corrupt;
        const key = (comp.id << format.offset_bits) | en.ls;
        if (wb.key != key) {
            wb.key = std.math.maxInt(u64);
            wb.data.clearRetainingCapacity();
            try s.chunkInto(comp, en, &wb.data);
            wb.key = key;
        }
        const data = wb.data.items;
        const rel = off - en.ls;
        if (rel + format.short_len <= data.len and format.short(data[rel..]).kind == .hole) return error.NotFound;
        if (s.cfg.verify_reads) return format.validate(data, rel, l);
        if (rel + format.short_len > data.len) return error.Corrupt;
        const h = format.short(data[rel..]);
        const hl = format.hdrLen(h.kind);
        if (rel + hl + h.size > data.len) return error.Corrupt;
        return data[rel..][0 .. hl + h.size];
    }

    /// Where the newest group this process committed lies in its segment file (tests and fault
    /// injection): `[phys, phys_end)` holds its frames (compressed) or its bytes (raw).
    pub const TailGroup = struct { epoch: u64, ls: u64, phys: u64, phys_end: u64, compressed: bool };
    pub fn tailGroup(s: *Store) ?TailGroup {
        const base = s.last_group_base orelse return null;
        if (!s.has_segment) return null;
        const slot = s.slotOf(s.cur_epoch) orelse return null;
        if (slot.comp.raw) |c| {
            const d = c.dir.raw;
            const i = d.indexAt(base) orelse return null;
            if (i >= d.slice().len) return null;
            return .{ .epoch = s.cur_epoch, .ls = base, .phys = d.entries[i].phys, .phys_end = d.physEnd(), .compressed = true };
        }
        return .{ .epoch = s.cur_epoch, .ls = base, .phys = base, .phys_end = s.tail, .compressed = false };
    }

    /// Writes and syncs every compressed segment's dir entries (tests and fault injection: the
    /// dir file then proves the groups it names were written whole).
    pub fn syncDirs(s: *Store) Error!void {
        for (s.segs) |*slot| if (slot.epoch.load(.monotonic) != no_epoch) if (slot.comp.raw) |c| try s.dirPersist(slot.epoch.raw, c, true);
    }

    /// Writer's live-table location of `id` (tomb bit cleared), for tests and fault injection.
    pub fn liveLocation(s: *Store, id: *const [32]u8) ?u64 {
        return table.locOf(s.lt().lookup(id) orelse return null);
    }

    /// Object versions in the current memtable (tests).
    pub fn curMemVersions(s: *Store) u64 {
        return s.curMem().ver.count;
    }

    /// Live objects in the index (writer's view; not a snapshot).
    pub fn liveCount(s: *Store) u64 {
        return s.lt().live;
    }

    /// Occupied live-index slots (live objects plus retained tombstones) and capacity.
    pub fn liveSlots(s: *Store) struct { used: u64, capacity: u64, pages: u64 } {
        const t = s.lt();
        return .{ .used = t.count, .capacity = t.nslots, .pages = t.pages.len };
    }

    /// Bytes of memory the indexes use: memtables (allocated) and live-table pages changed
    /// since the last flush (private copies); clean live pages are page cache.
    pub fn indexMemory(s: *Store) struct { memtables: u64, live_dirty: u64, live_file: u64 } {
        const m = s.curMem();
        const one = m.ver.entries.len * 16 + m.tx.entries.len * 16 + m.cps.entries.len * 16;
        return .{
            .memtables = one * (1 + s.mem_pool.items.len),
            .live_dirty = s.lt().ndirty * page_size,
            .live_file = s.lt().pages.len * page_size,
        };
    }

    pub fn committed(s: *const Store) ?u64 {
        const c1 = s.committed1.load(.acquire);
        return if (c1 == 0) null else c1 - 1;
    }

    pub fn currentEpoch(s: *const Store) ?u64 {
        return if (s.has_segment) s.cur_epoch else null;
    }

    /// Runs the given epoch currently has (for tests and reports).
    pub fn runCount(s: *const Store, epoch: u64) u32 {
        const slot = s.slotOf(epoch) orelse return 0;
        return slot.nruns.load(.acquire);
    }

    /// Runs held across every retained epoch.
    pub fn totalRuns(s: *const Store) u64 {
        if (!s.has_segment) return 0;
        var n: u64 = 0;
        var e = s.oldest_epoch.load(.acquire);
        while (e <= s.cur_epoch) : (e += 1) n += s.runCount(e);
        return n;
    }
};

pub const Batch = struct {
    store: *Store,
    seq: u64,
    epoch: u64,
    /// Segment offset of buf[0] (block aligned).
    base: u64,
    /// Bytes this group may span: the batch buffer, bounded by the room left in the segment.
    limit: usize,
    len: usize = 0,
    records: u32 = 0,
    group_hash: u64 = 0,
    new_segment: bool,
    carry: bool = false,
    n_obj: u64 = 0,
    n_rm: u64 = 0,
    n_tx: u64 = 0,
    n_cp: u64 = 0,

    fn append(b: *Batch, kind: Kind, flags: u8, seq: u64, a: u64, parts: []const []const u8) Error!u64 {
        return b.appendB(kind, flags, seq, a, 0, parts);
    }

    fn appendB(b: *Batch, kind: Kind, flags: u8, seq: u64, a: u64, hb: u64, parts: []const []const u8) Error!u64 {
        var size: usize = 0;
        for (parts) |p| size += p.len;
        const n = format.lenOf(kind, size);
        const s = b.store;
        // Room for this record plus the group's commit record and its padding (the commit
        // record itself only needs its own room).
        const reserve: usize = if (kind == .commit) 0 else format.recordLen(@sizeOf(format.CommitFixed));
        const need = std.mem.alignForward(usize, b.len + n + reserve, block);
        if (need > b.limit) return if (need > s.buf.len) error.BatchFull else error.SegmentFull;
        // A group must fit an empty memtable.
        switch (kind) {
            .object, .object_c, .link, .xref => if (b.n_obj + 1 > s.cfg.max_object_versions) return error.BatchFull,
            .tx => if (b.n_tx + 1 > s.cfg.max_transactions) return error.BatchFull,
            .checkpoint => if (b.n_cp + 1 > s.cfg.max_checkpoints) return error.BatchFull,
            else => {},
        }
        const l = format.loc(b.epoch, b.base + b.len);
        _ = format.writeB(s.buf[b.len..], l, kind, flags, seq, a, hb, parts);
        if (kind != .commit) {
            b.group_hash = format.chain(b.group_hash, format.short(s.buf[b.len..]).checksum);
            b.records += 1;
        }
        b.len += n;
        return l;
    }

    fn prevOf(b: *Batch, id: *const [32]u8) u64 {
        const s = b.store;
        if (s.bmap.get(id)) |l| return l;
        const l = s.lt().lookup(id) orelse return 0;
        return table.locOf(l);
    }

    /// Before the live version of `id` is superseded: if it is a compact record (not in the
    /// version index), a link record indexes it by (id, version) so history reads find it.
    /// Costs one read of that record (cold on the first touch of a restored object).
    fn linkSuperseded(b: *Batch, id: *const [32]u8) Error!void {
        const s = b.store;
        if (s.bmap.get(id) != null) return;
        const lv = s.lt().lookup(id) orelse return;
        if (lv & table.tomb != 0 or lv & table.compact == 0) return;
        // Keyed by (id, aux_superseded), not by the version: knowing the version would take a
        // read of the (usually cold) compact record on the write path. Readers check it.
        // Written at commit, and only if no xref of this batch names the record.
        s.pend_links.append(s.gpa, .{ .id = id.*, .loc = table.locOf(lv) }) catch return error.OutOfMemory;
    }

    pub fn checkpoint(b: *Batch, summary_cert: []const u8, contents: []const u8) Error!void {
        const f: format.CheckpointFixed = .{ .epoch = b.epoch, .summary_len = @intCast(summary_cert.len), .contents_len = @intCast(contents.len) };
        _ = try b.append(.checkpoint, 0, b.seq, 0, &.{ std.mem.asBytes(&f), summary_cert, contents });
        b.n_cp += 1;
    }

    pub fn transaction(b: *Batch, tx_digest: *const [32]u8, effects_digest: *const [32]u8, tx: []const u8, effects: []const u8, events: ?[]const u8) Error!void {
        const ev = events orelse &.{};
        const f: format.TxFixed = .{
            .digest = tx_digest.*,
            .effects_digest = effects_digest.*,
            .tx_len = @intCast(tx.len),
            .effects_len = @intCast(effects.len),
            .events_len = @intCast(ev.len),
            .has_events = @intFromBool(events != null),
        };
        _ = try b.append(.tx, 0, b.seq, 0, &.{ std.mem.asBytes(&f), tx, effects, ev });
        b.n_tx += 1;
    }

    pub fn putObject(b: *Batch, id: *const [32]u8, version: u64, digest: *const [32]u8, bytes: []const u8) Error!void {
        if (!b.store.bmap.fits(id)) return error.BatchFull;
        try b.linkSuperseded(id);
        const f: format.ObjectFixed = .{ .id = id.*, .version = version, .digest = digest.* };
        const l = try b.append(.object, 0, b.seq, b.prevOf(id), &.{ std.mem.asBytes(&f), bytes });
        b.n_obj += 1;
        try b.store.bmap.put(id, l);
    }

    /// A live object with no version history in the store (the restored live set): written as a
    /// compact record when the store has a codec (CONTRACTS 6.8), else as `putObject`. Compact
    /// records carry no checkpoint and no previous-version link, so they are visible to every
    /// snapshot; use this only for objects no reader has seen another version of.
    pub fn putBase(b: *Batch, id: *const [32]u8, version: u64, digest: *const [32]u8, bytes: []const u8) Error!void {
        const s = b.store;
        if (!s.bmap.fits(id)) return error.BatchFull;
        if (s.cfg.codec == null or b.prevOf(id) != 0) return b.putObject(id, version, digest, bytes);
        const l = try b.append(.object_c, 0, b.seq, 0, &.{bytes});
        b.n_obj += 1;
        try s.bmap.put(id, l);
    }

    /// An object version that is not (or no longer) the live one: readable with
    /// `Snapshot.objectAt(id, version)` for the segment's retention, but the live table, `latest`
    /// and the batch's live map never see it (for example a transaction's read-only inputs, which
    /// a node started after their write never saw as outputs).
    pub fn putHistorical(b: *Batch, id: *const [32]u8, version: u64, digest: *const [32]u8, bytes: []const u8) Error!void {
        const f: format.ObjectFixed = .{ .id = id.*, .version = version, .digest = digest.* };
        _ = try b.append(.object, format.flag_historical, b.seq, 0, &.{ std.mem.asBytes(&f), bytes });
        b.n_obj += 1;
    }

    /// A cross-reference instead of a copy (CONTRACTS 6.8): makes the object version whose record
    /// is at `target` (found with `Snapshot.objectFind`, usually in an older segment) readable
    /// by (id, version) for this batch's retention, without writing its bytes again. `target`
    /// must be the location of an object record (full or compact) holding exactly that version.
    pub fn putXref(b: *Batch, id: *const [32]u8, version: u64, target: u64) Error!void {
        const f: format.XrefFixed = .{ .id = id.*, .version = version, .target = target };
        _ = try b.append(.xref, 0, b.seq, 0, &.{std.mem.asBytes(&f)});
        b.n_obj += 1;
        b.store.xref_targets.put(b.store.gpa, target, {}) catch return error.OutOfMemory;
    }

    /// Checkpoint digest index (CONTRACTS 6.8): the batch's checkpoint is found by its summary
    /// digest with `Snapshot.checkpointByDigest`. An aux record `(digest, aux_checkpoint_digest)`
    /// holding the sequence number (u64 le), retained with the checkpoint's segment.
    pub fn checkpointDigest(b: *Batch, digest: *const [32]u8) Error!void {
        const seq_le = std.mem.nativeToLittle(u64, b.seq);
        try b.putHistorical(digest, aux_checkpoint_digest, &@as([32]u8, @splat(0)), std.mem.asBytes(&seq_le));
    }

    /// Records `seq` as the highest pruned checkpoint (aux_highest_pruned): checkpoints up to
    /// it are not served even while the store holds them (a snapshot restore's end-of-epoch
    /// checkpoint, whose transactions' input versions the snapshot does not carry).
    pub fn highestPruned(b: *Batch, seq: u64) Error!void {
        const seq_le = std.mem.nativeToLittle(u64, seq);
        try b.putHistorical(&aux_zero_id, aux_highest_pruned, &@as([32]u8, @splat(0)), std.mem.asBytes(&seq_le));
    }

    pub fn removeObject(b: *Batch, id: *const [32]u8, version: u64, kind: RemoveKind) Error!void {
        if (!b.store.bmap.fits(id)) return error.BatchFull;
        try b.linkSuperseded(id);
        const f: format.RemoveFixed = .{ .id = id.*, .version = version, .kind = @intFromEnum(kind) };
        const l = try b.append(.remove, 0, b.seq, b.prevOf(id), &.{std.mem.asBytes(&f)});
        b.n_rm += 1;
        try b.store.bmap.put(id, l);
    }
};

/// The key of checkpoint `seq` in `Store.cert_fix` (the table is keyed by 32 bytes; its search
/// key is the first 8, the sequence number).
pub fn certFixKey(seq: u64) [32]u8 {
    var k: [32]u8 = @splat(0);
    std.mem.writeInt(u64, k[0..8], seq, .little);
    return k;
}

/// Aux keyspace (CONTRACTS 6.8): object versions are at most i64::MAX, so versions 2^63 and up
/// key per-key values stored as historical object records (never live, epoch-retained).
/// u64::MAX: a transaction's unchanged loaded runtime object list (node history.zig).
pub const aux_loaded: u64 = std.math.maxInt(u64);

/// This thread's index-probe counts (hinted lookups; serve's ZUI_LH_PROF reports them).
/// `run_probes`: run index lookups (a cold one reads a page); `filter_skips`: runs a key filter
/// ruled out without a read; `near_hits` / `near_falls`: hinted object lookups answered by the
/// hint / sent to the plain lookup.
pub const ProbeStats = struct { run_probes: u64 = 0, live_probes: u64 = 0, near_hits: u64 = 0, near_falls: u64 = 0, filter_skips: u64 = 0 };
pub threadlocal var probe_stats: ProbeStats = .{};
/// Snapshot.nearOn: 2 = not read yet.
var near_conf: std.atomic.Value(u8) = .init(2);
/// filtersOn: 2 = not read yet.
var filter_conf: std.atomic.Value(u8) = .init(2);

/// Run key filters on (default) or off (`ZUI_STORE_FILTERS=0`, read once).
fn filtersOn() bool {
    const v = filter_conf.load(.monotonic);
    if (v != 2) return v == 1;
    var on = true;
    if (std.c.getenv("ZUI_STORE_FILTERS")) |e| on = !std.mem.eql(u8, std.mem.span(e), "0");
    filter_conf.store(@intFromBool(on), .monotonic);
    return on;
}
/// u64::MAX - 1: checkpoint summary digest -> sequence number (u64 le).
pub const aux_checkpoint_digest: u64 = std.math.maxInt(u64) - 1;
/// u64::MAX - 2: (object id) -> compact records of that object superseded since (link records;
/// the version is checked in the record).
pub const aux_superseded: u64 = std.math.maxInt(u64) - 2;
/// u64::MAX - 3: (all-zero id) -> highest pruned checkpoint (u64 le), written by a formal
/// snapshot restore for the restored end-of-epoch checkpoint (sui-node's restore sets
/// highest_pruned_checkpoint to it, so lowest_available_checkpoint starts one above).
pub const aux_highest_pruned: u64 = std.math.maxInt(u64) - 3;
const aux_zero_id: [32]u8 = @splat(0);

pub const Snapshot = struct {
    store: *Store,
    c1: u64,
    parity: u1,
    /// Reader epoch for the decoded-chunk cache (cache.Readers).
    cepoch: u64,

    pub fn highestCommitted(s: *const Snapshot) ?u64 {
        return if (s.c1 == 0) null else s.c1 - 1;
    }

    fn visible(s: *const Snapshot, seq: u64) bool {
        return s.c1 != 0 and seq < s.c1;
    }

    fn noteCorrupt(s: *const Snapshot) void {
        _ = s.store.stats.corrupt_reads.fetchAdd(1, .monotonic);
    }

    fn liveTable(s: *const Snapshot) *const table.LiveTable {
        return &s.store.live.load(.acquire).?.t;
    }

    /// Newest version or tombstone of `id` as of this snapshot. Errors only on damage.
    pub fn latest(s: *const Snapshot, id: *const [32]u8) Error!?LatestObject {
        const read_t0 = readstats.begin();
        defer readstats.end(.objects, read_t0);
        var l = table.locOf(s.liveTable().get(id) orelse return null);
        // The table's record is another id's only if their slot keys collide (table.zig): `id`
        // is then not in the table. Further down the chain a foreign id is damage.
        var head = true;
        while (true) : (head = false) {
            if (l == 0) return null;
            const rec = s.store.record(l, s.cepoch) catch |e| switch (e) {
                error.NotFound => return null,
                else => return e,
            };
            switch (format.short(rec).kind) {
                .object, .object_c => {
                    const o = try s.store.objRec(rec);
                    if (!std.mem.eql(u8, &o.id, id)) return if (head) null else error.Corrupt;
                    if (!s.visible(o.seq)) {
                        l = o.a;
                        continue;
                    }
                    return .{ .live = o.ref() };
                },
                .remove => {
                    if (rec.len < format.header_len + @sizeOf(format.RemoveFixed)) return error.Corrupt;
                    const h = format.header(rec);
                    const f = format.fixed(format.RemoveFixed, rec);
                    if (!std.mem.eql(u8, &f.id, id)) return if (head) null else error.Corrupt;
                    if (!s.visible(h.seq)) {
                        l = h.a;
                        continue;
                    }
                    return .{ .removed = .{ .version = f.version, .kind = @enumFromInt(f.kind) } };
                },
                else => return error.Corrupt,
            }
        }
    }

    /// Location of the newest record of `id` this snapshot sees, if it is an object (null: no
    /// such id, or removed as of the snapshot). `SegScan` keeps a record only at this location.
    pub fn visibleLoc(s: *const Snapshot, id: *const [32]u8) Error!?u64 {
        var l = table.locOf(s.liveTable().get(id) orelse return null);
        var head = true;
        while (l != 0) : (head = false) {
            const rec = s.store.record(l, s.cepoch) catch |e| switch (e) {
                error.NotFound => return null,
                else => return e,
            };
            switch (format.short(rec).kind) {
                .object, .object_c => {
                    const o = try s.store.objRec(rec);
                    // Another id's record: a slot-key collision (table.zig), `id` is absent.
                    if (head and !std.mem.eql(u8, &o.id, id)) return null;
                    if (s.visible(o.seq)) return l;
                    l = o.a;
                },
                .remove => {
                    const h = format.header(rec);
                    if (s.visible(h.seq)) return null;
                    l = h.a;
                },
                else => return error.Corrupt,
            }
        }
        return null;
    }

    pub fn debugChain(s: *const Snapshot, id: *const [32]u8) void {
        var l = table.locOf(s.liveTable().get(id) orelse {
            std.debug.print("chain: not in table\n", .{});
            return;
        });
        while (l != 0) {
            const rec = s.store.record(l, s.cepoch) catch |e| {
                std.debug.print("chain: {d}:{d} -> {s}\n", .{ l >> 44, l & ((1 << 44) - 1), @errorName(e) });
                return;
            };
            const h = format.header(rec);
            std.debug.print("chain: {d}:{d} kind {s} seq {d} visible {} a {d}:{d} flags {x}\n", .{ l >> 44, l & ((1 << 44) - 1), @tagName(h.kind), h.seq, s.visible(h.seq), h.a >> 44, h.a & ((1 << 44) - 1), h.flags });
            l = h.a;
        }
    }

    pub fn liveObject(s: *const Snapshot, id: *const [32]u8) ?ObjectRef {
        const r = s.latest(id) catch {
            s.noteCorrupt();
            return null;
        } orelse return null;
        return switch (r) {
            .live => |o| o,
            .removed => null,
        };
    }

    /// Every live object of this snapshot: `f(ctx, id, version, bytes)`. Reads the live table
    /// without the writer's lock, so call it only while no batch can commit (node start, before
    /// the follower runs). Derived indexes build their base with it (CONTRACTS 6.8).
    /// Built on `liveIter` (live-table slots hold only a 96-bit key of the id; the iterator
    /// reads the full id from each record, compact ones included).
    /// Records are visited in location order (epoch, offset), not slot order: slot order is hash
    /// order, so on a store larger than the page cache every record read was a random page
    /// fault (772M objects of a 193 GB restore: about a day at QD1); sorted, the walk reads
    /// the segments front to back. Costs 8 bytes per live slot while it runs.
    pub fn forEachLive(s: *const Snapshot, ctx: anytype, comptime f: fn (@TypeOf(ctx), *const [32]u8, u64, []const u8) anyerror!void) !void {
        const gpa = s.store.gpa;
        // 16 location ranges one after the other: the sorted locations of one range at a time
        // (about 390 MB at 772.9M live objects), not of the whole live set (6.2 GB).
        const bounds = try s.liveBounds(gpa, 16);
        defer gpa.free(bounds);
        var wb: Store.WalkBuf = .{};
        defer wb.deinit(gpa);
        for (bounds[0 .. bounds.len - 1], bounds[1..]) |lo, hi| {
            const locs = try s.liveLocationsIn(gpa, lo, hi);
            defer gpa.free(locs);
            for (locs) |l| if (try s.liveAtWalk(l, &wb)) |o| try f(ctx, &o.id, o.version, o.bytes);
        }
    }

    /// Splits the live set into `parts` location ranges of about equal object counts: part p is
    /// every live location in [bounds[p], bounds[p+1]), and a range is a contiguous stretch of the
    /// store (locations order as (epoch, offset)). Two passes over the live table and a 64k-bucket
    /// histogram, no per-object memory. No batch may commit while the bounds are in use, or they
    /// split a different live set. Caller frees; `parts + 1` entries.
    pub fn liveBounds(s: *const Snapshot, gpa: std.mem.Allocator, parts: usize) ![]u64 {
        const t = s.liveTable();
        const out = try gpa.alloc(u64, parts + 1);
        errdefer gpa.free(out);
        var lo: u64 = std.math.maxInt(u64);
        var hi: u64 = 0;
        var n: u64 = 0;
        var i: u64 = 0;
        while (i < t.nslots) : (i += 1) {
            const raw = @atomicLoad(u64, t.locPtr(i), .acquire);
            if (raw == 0 or raw & table.tomb != 0) continue;
            const l = table.locOf(raw);
            lo = @min(lo, l);
            hi = @max(hi, l);
            n += 1;
        }
        if (n == 0) {
            @memset(out, 0);
            return out;
        }
        const nb: u64 = 1 << 16;
        const span: u128 = @as(u128, hi - lo) + 1;
        const hist = try gpa.alloc(u64, nb);
        defer gpa.free(hist);
        @memset(hist, 0);
        i = 0;
        while (i < t.nslots) : (i += 1) {
            const raw = @atomicLoad(u64, t.locPtr(i), .acquire);
            if (raw == 0 or raw & table.tomb != 0) continue;
            hist[@intCast(@as(u128, table.locOf(raw) - lo) * nb / span)] += 1;
        }
        // l is in bucket >= b exactly when l >= start(b)
        const start = struct {
            fn f(lo_: u64, span_: u128, b_: u64) u64 {
                return lo_ + @as(u64, @intCast((@as(u128, b_) * span_ + (1 << 16) - 1) / (1 << 16)));
            }
        }.f;
        out[0] = lo;
        var cum: u64 = 0;
        var p: usize = 1;
        for (0..nb) |bk| {
            while (p < parts and cum >= n * p / parts) : (p += 1) out[p] = start(lo, span, bk);
            cum += hist[bk];
        }
        while (p < parts) : (p += 1) out[p] = hi + 1;
        out[parts] = hi + 1;
        return out;
    }

    /// The live locations in [lo, hi), sorted (store order). One pass over the live table.
    /// Caller frees.
    pub fn liveLocationsIn(s: *const Snapshot, gpa: std.mem.Allocator, lo: u64, hi: u64) ![]u64 {
        const t = s.liveTable();
        var locs: std.ArrayList(u64) = .empty;
        errdefer locs.deinit(gpa);
        var i: u64 = 0;
        while (i < t.nslots) : (i += 1) {
            const raw = @atomicLoad(u64, t.locPtr(i), .acquire);
            if (raw == 0 or raw & table.tomb != 0) continue;
            const l = table.locOf(raw);
            if (l >= lo and l < hi) try locs.append(gpa, l);
        }
        std.mem.sortUnstable(u64, locs.items, {}, std.sort.asc(u64));
        return locs.toOwnedSlice(gpa);
    }

    /// The live object at a location from `liveLocationsIn`, as this snapshot sees it (null: not an
    /// object record, gone, or removed since).
    pub fn liveAt(s: *const Snapshot, l: u64) Error!?LiveIter.Item {
        const it: LiveIter = .{ .snap = s, .t = s.liveTable(), .i = 0, .end = 0 };
        return it.itemAt(l);
    }

    /// `liveAt` for a walk: a compressed segment's chunk is decoded into `wb` (walk-private, valid
    /// until the next call), never the shared cache, so a walk under one long snapshot does not
    /// pin every chunk it reads (f0e8b55).
    pub fn liveAtWalk(s: *const Snapshot, l: u64, wb: *Store.WalkBuf) Error!?LiveIter.Item {
        const it: LiveIter = .{ .snap = s, .t = s.liveTable(), .i = 0, .end = 0 };
        const rec = s.store.recordWalk(l, wb, s.cepoch) catch |e| switch (e) {
            error.NotFound => return null,
            else => return e,
        };
        return it.itemOf(rec);
    }

    /// Bytes of segment `epoch` (null when the store does not hold it). With a store restored from
    /// the formal snapshot of `epoch`, that segment is the restore image (`forEachImageObject`).
    pub fn segmentBytes(s: *const Snapshot, epoch: u64) ?u64 {
        const slot = s.store.slotOf(epoch) orelse return null;
        return slot.end.load(.acquire);
    }

    pub const ImageStats = struct { objects: u64 = 0, bytes: u64 = 0, resyncs: u64 = 0 };

    /// Every compact object record of segment `epoch` that starts in part `part` of `parts` equal
    /// byte ranges, in log order: `f(ctx, id, version, bytes)`. In a store restored from the
    /// formal snapshot of `epoch` these are exactly the restored live set (`Batch.putBase`, one per
    /// object: the end-of-epoch checkpoint's own outputs are full records, never compact, and
    /// cleaning writes its carried compact records into newer segments). Reads the segment front
    /// to back (sequential, read ahead), so the restored set is walked at disk bandwidth instead of
    /// one random read per object as `forEachLive` does; and the segment is immutable, so it may
    /// run while batches commit (fast start, lane fast-start). Part boundaries resync on the first
    /// block-aligned record at or after the boundary: every record belongs to exactly one part.
    /// Records age-out dropped since (holes in the chunks it rewrote) are not listed; every
    /// compact record still in the segment is.
    pub fn forEachImageObject(s: *const Snapshot, epoch: u64, part: u64, parts: u64, stats: *ImageStats, ctx: anytype, comptime f: fn (@TypeOf(ctx), *const [32]u8, u64, []const u8) anyerror!void) !void {
        const st = s.store;
        const slot = st.slotOf(epoch) orelse return error.NotFound;
        const end: u64 = slot.end.load(.acquire);
        if (slot.epoch.load(.seq_cst) != epoch) return error.NotFound;
        const Ctx = @typeInfo(@TypeOf(ctx)).pointer.child;
        const p = @max(parts, 1);
        const lo = std.mem.alignBackward(u64, end * part / p, format.block);
        const hi = if (part + 1 >= p) end else std.mem.alignBackward(u64, end * (part + 1) / p, format.block);
        if (slot.comp.load(.acquire)) |c| return s.imageCompressed(c, slot.fd, epoch, end, lo, hi, stats, ctx, f);
        // Read into a private window with pread and drop each window from the page cache once
        // walked (lane fast-start): the mmapped walk with MADV_WILLNEED filled a memory-capped
        // cgroup with file pages and left the walkers in reclaim (D state) beside the follower.
        var win: ImageWindow = .{ .backend = st.backend, .gpa = st.gpa, .fd = slot.fd, .end = end };
        defer win.deinit();
        var off: u64 = lo;
        // the first record of the part: block-aligned, valid at its location
        while (off < hi) : (off += format.block) {
            if (try win.record(off, epoch) != null) break;
        }
        while (off < end) {
            if (off >= hi and off % format.block == 0) break;
            const rec = try win.record(off, epoch) orelse {
                // padding after a commit record, or a torn tail: the next block
                const nb = std.mem.alignForward(u64, off + 1, format.block);
                if (off % format.block != 0) if (win.peekShort(off)) |h| if (h.checksum != 0) {
                    stats.resyncs += 1;
                };
                off = nb;
                continue;
            };
            if (win.fresh != 0) {
                if (@hasDecl(Ctx, "onWindow")) try ctx.onWindow(win.fresh);
                win.fresh = 0;
            }
            const k = format.short(rec).kind;
            const len = format.lenAt(rec);
            if (k == .object_c) {
                const o = try st.objRec(rec);
                stats.objects += 1;
                stats.bytes += o.bytes.len;
                try f(ctx, &o.id, o.version, o.bytes);
            }
            off += len;
            if (k == .commit) off = std.mem.alignForward(u64, off, format.block);
        }
    }

    /// `forEachImageObject` over a compressed segment (main's default since the compression lane):
    /// the chunks whose logical start is in [lo, hi), in order, each decoded into a walk-private
    /// buffer (never the shared chunk cache; records never straddle chunks, see `recordWalk`),
    /// and the file range read dropped from the page cache every 8 MiB.
    fn imageCompressed(s: *const Snapshot, c: *CSeg, fd: Fd, epoch: u64, end: u64, lo: u64, hi: u64, stats: *ImageStats, ctx: anytype, comptime f: fn (@TypeOf(ctx), *const [32]u8, u64, []const u8) anyerror!void) !void {
        const st = s.store;
        const Ctx = @typeInfo(@TypeOf(ctx)).pointer.child;
        const dir = c.dir.load(.acquire);
        const es = dir.slice();
        // the first chunk starting at or after `lo` (`indexAt` matches a chunk start exactly)
        var i: usize = 0;
        var top: usize = es.len;
        while (i < top) {
            const mid = i + (top - i) / 2;
            if (es[mid].ls < lo) i = mid + 1 else top = mid;
        }
        var data: std.ArrayList(u8) = .empty;
        defer data.deinit(st.gpa);
        var drop_lo: u64 = if (i < es.len and !chunk.isSide(es[i].phys)) es[i].phys else 0;
        var drop_hi: u64 = drop_lo;
        defer if (drop_hi > drop_lo) st.backend.dropCache(fd, drop_lo, drop_hi - drop_lo, false);
        while (i < es.len and es[i].ls < hi and es[i].ls < end) : (i += 1) {
            const en = es[i];
            data.clearRetainingCapacity();
            try st.chunkInto(c, en, &data);
            const pend = if (chunk.isSide(en.phys)) drop_hi else en.phys + chunk.frame_len + en.bl;
            if (pend > drop_hi) drop_hi = pend;
            if (drop_hi - drop_lo >= 8 << 20) {
                st.backend.dropCache(fd, drop_lo, drop_hi - drop_lo, false);
                drop_lo = drop_hi;
            }
            if (@hasDecl(Ctx, "onWindow")) try ctx.onWindow(chunk.frame_len + en.bl);
            const d = data.items;
            var rel: u64 = 0;
            while (rel + format.short_len <= d.len) {
                const off = en.ls + rel;
                // A hole (a record age-out dropped; only in a chunk it rewrote) keeps the dead
                // record's checksum over a zeroed body, so it never validates: stepped over by
                // its length. Taken for padding, the walk went to the next block, the middle of
                // a record, and listed nothing more of the chunk.
                if (format.short(d[rel..]).kind == .hole) {
                    const n = format.lenOf(.hole, format.short(d[rel..]).size);
                    if (n > d.len - rel) return error.Corrupt;
                    rel += n;
                    continue;
                }
                const rec = format.validate(d, rel, format.loc(epoch, off)) catch null orelse {
                    // padding after a commit record: the next block
                    rel = std.mem.alignForward(u64, off + 1, format.block) - en.ls;
                    continue;
                };
                const k = format.short(rec).kind;
                if (k == .object_c) {
                    const o = try st.objRec(rec);
                    stats.objects += 1;
                    stats.bytes += o.bytes.len;
                    try f(ctx, &o.id, o.version, o.bytes);
                }
                rel += format.lenAt(rec);
                if (k == .commit) rel = std.mem.alignForward(u64, en.ls + rel, format.block) - en.ls;
            }
        }
    }

    /// A sliding private read window over a segment file (`forEachImageObject`).
    const ImageWindow = struct {
        backend: io_mod.Backend,
        gpa: std.mem.Allocator,
        fd: Fd,
        end: u64,
        buf: []align(page_size) u8 = &.{},
        lo: u64 = 0,
        hi: u64 = 0,
        /// Bytes read since the caller last looked (pacing).
        fresh: u64 = 0,
        const window: u64 = 8 << 20;
        /// Longest record the walk will read (a bigger size is a damaged header).
        const max_record: u64 = 256 << 20;

        fn deinit(w: *ImageWindow) void {
            if (w.hi > w.lo) w.backend.dropCache(w.fd, w.lo, w.hi - w.lo, false);
            if (w.buf.len > 0) w.gpa.free(w.buf);
        }

        /// Bytes `[off, off + need)` in the window (false: past the end).
        fn ensure(w: *ImageWindow, off: u64, need: u64) !bool {
            if (off + need > w.end) return false;
            if (off >= w.lo and off + need <= w.hi) return true;
            if (w.hi > w.lo) w.backend.dropCache(w.fd, w.lo, w.hi - w.lo, false);
            const from = std.mem.alignBackward(u64, off, page_size);
            const want = @max(window, std.mem.alignForward(u64, off + need - from, page_size));
            if (w.buf.len < want) {
                if (w.buf.len > 0) w.gpa.free(w.buf);
                w.buf = &.{};
                w.buf = try w.gpa.alignedAlloc(u8, .fromByteUnits(page_size), want);
            }
            const len = @min(w.buf.len, w.end - from);
            try w.backend.read(w.fd, from, w.buf[0..len]);
            w.lo = from;
            w.hi = from + len;
            w.fresh += len;
            return true;
        }

        fn peekShort(w: *ImageWindow, off: u64) ?*align(1) const format.Short {
            const ok = w.ensure(off, format.short_len) catch return null;
            if (!ok) return null;
            return format.short(w.buf[off - w.lo ..]);
        }

        /// The valid record at `off` (null: none there).
        fn record(w: *ImageWindow, off: u64, epoch: u64) !?[]const u8 {
            if (!try w.ensure(off, format.short_len)) return null;
            const h = format.short(w.buf[off - w.lo ..]);
            const total = format.hdrLen(h.kind) + @as(u64, h.size);
            if (total > max_record or !try w.ensure(off, total)) return null;
            return format.validate(w.buf[0 .. w.hi - w.lo], off - w.lo, format.loc(epoch, off)) catch null;
        }
    };

    /// Candidate locations of `key` in the version or transaction indexes: the memtable,
    /// then every retained epoch's runs, newest first.
    const Which = enum { ver, tx };
    const KeyLocs = struct {
        snap: *const Snapshot,
        which: Which,
        key: u64,
        it: table.KeyView.Iter,
        ring_i: u64,
        ring_lo: u64,
        slot: ?*SegSlot = null,
        run_i: u32 = 0,

        fn init(snap: *const Snapshot, which: Which, key: u64) KeyLocs {
            const st = snap.store;
            const m = st.mem.load(.acquire).?;
            const kt = switch (which) {
                .ver => &m.ver,
                .tx => &m.tx,
            };
            // No runs anywhere: the memtable is the whole index (after loading it, see sealMem).
            const tail = st.ep_tail.load(.acquire);
            return .{
                .snap = snap,
                .which = which,
                .key = key,
                .it = kt.find(key),
                .ring_i = tail,
                .ring_lo = if (st.runs_total.load(.acquire) == 0) tail else st.ep_head.load(.acquire),
            };
        }

        /// The epoch of the index source the last `next` came from: a run's segment epoch, or
        /// the newest segment's for the memtable (it holds the entries since the last index
        /// flush, so what it names is inside every window). Not `snap.cepoch`: that is the
        /// chunk cache's reader counter, 1 at a process start, and compared with an epoch it
        /// put every link still in the memtable outside the object window until the counter
        /// had passed the object floor's epoch.
        fn epoch(k: *const KeyLocs) u64 {
            if (k.slot) |slot| return slot.epoch.load(.acquire);
            return k.snap.store.newestEpoch() orelse std.math.maxInt(u64);
        }

        fn next(k: *KeyLocs) ?u64 {
            const st = k.snap.store;
            while (true) {
                if (k.it.next()) |l| return l;
                // next run
                while (true) {
                    if (k.slot) |slot| {
                        if (k.run_i > 0) {
                            k.run_i -= 1;
                            const r = slot.runs[k.run_i].load(.acquire) orelse continue;
                            const may = switch (k.which) {
                                .ver => r.mayHaveVer(k.key),
                                .tx => r.mayHaveTx(k.key),
                            };
                            if (!may) {
                                probe_stats.filter_skips += 1;
                                continue;
                            }
                            probe_stats.run_probes += 1;
                            k.it = switch (k.which) {
                                .ver => r.ver.find(k.key),
                                .tx => r.tx.find(k.key),
                            };
                            break;
                        }
                        k.slot = null;
                    }
                    if (k.ring_i <= k.ring_lo) return null;
                    k.ring_i -= 1;
                    const e = st.ep_ring[k.ring_i & st.seg_mask].load(.monotonic);
                    const slot = st.slotOf(e) orelse continue;
                    k.slot = slot;
                    k.run_i = slot.nruns.load(.acquire);
                }
            }
        }
    };

    pub fn objectAtChecked(s: *const Snapshot, id: *const [32]u8, version: u64) Error!?ObjectRef {
        const read_t0 = readstats.begin();
        defer readstats.end(.object_versions, read_t0);
        const f = (try s.objectFind(id, version)) orelse return null;
        return f.ref;
    }

    /// Where `objectAtChecked` found a version: the record's location (its segment's epoch is
    /// `format.epochOf(loc)`) and whether it is the live record. A history writer uses it to
    /// decide whether a transaction's input version outlives the transaction (node history.zig).
    /// `loc` is the index entry's record (an xref's own location for a cross-referenced
    /// version: its segment decides the retention), `data_loc` the record holding the bytes.
    /// `compact`: the live record is a compact one (superseding it needs a link or an xref).
    pub const Found = struct { ref: ObjectRef, loc: u64, live: bool, data_loc: u64, compact: bool = false };

    /// Resolves a version-index candidate at `l` (in the window) to the version's record: a
    /// full or compact object record, a carried historical copy (kept while the xref it stands
    /// in for, header `b`, is in the window), or an xref (followed to its target, which may sit
    /// in an aged segment; a target cleaned away reads as absent). Null: not this version.
    fn resolveVer(s: *const Snapshot, l: u64, id: *const [32]u8, version: u64, damaged: *bool) Error!?struct { o: ObjRec, data_loc: u64 } {
        const rec = s.store.record(l, s.cepoch) catch |e| switch (e) {
            error.NotFound => return null,
            error.Corrupt => {
                damaged.* = true;
                return null;
            },
            else => return e,
        };
        var data_loc = l;
        var orec = rec;
        switch (format.short(rec).kind) {
            .object, .object_c => {},
            .xref => {
                if (rec.len != format.short_len + @sizeOf(format.XrefFixed)) {
                    damaged.* = true;
                    return null;
                }
                const f = format.fixedShort(format.XrefFixed, rec);
                if (f.version != version or !std.mem.eql(u8, &f.id, id)) return null;
                data_loc = f.target;
                orec = s.store.record(f.target, s.cepoch) catch |e| switch (e) {
                    error.NotFound => return null, // cleaned away: a carried copy stands in
                    error.Corrupt => {
                        damaged.* = true;
                        return null;
                    },
                    else => return e,
                };
                const k = format.short(orec).kind;
                if (k != .object and k != .object_c) {
                    damaged.* = true;
                    return null;
                }
            },
            else => return null,
        }
        const o = s.store.objRec(orec) catch {
            damaged.* = true;
            return null;
        };
        if (o.version != version or !std.mem.eql(u8, &o.id, id)) {
            if (data_loc != l) damaged.* = true; // an xref naming the wrong record
            return null;
        }
        if (format.short(orec).kind == .object) {
            const hb = format.header(orec).b;
            if (hb != 0 and !s.store.objInWindow(hb)) return null;
        }
        return .{ .o = o, .data_loc = data_loc };
    }

    pub fn objectFind(s: *const Snapshot, id: *const [32]u8, version: u64) Error!?Found {
        var damaged = false;
        // The live version answers most requests with one probe.
        probe_stats.live_probes += 1;
        if (s.liveTable().get(id)) |lv| live: {
            const rec = s.store.record(table.locOf(lv), s.cepoch) catch |e| switch (e) {
                error.NotFound => break :live,
                error.Corrupt => {
                    damaged = true;
                    break :live;
                },
                else => return e,
            };
            const k = format.short(rec).kind;
            if (k != .object and k != .object_c) break :live;
            const o = s.store.objRec(rec) catch {
                damaged = true;
                break :live;
            };
            if (o.version != version or !std.mem.eql(u8, &o.id, id)) break :live;
            if (!s.visible(o.seq)) return null;
            return .{ .ref = o.ref(), .loc = table.locOf(lv), .live = true, .data_loc = table.locOf(lv), .compact = lv & table.compact != 0 };
        }
        // Every candidate: the version's own record and the xrefs of later epochs may all be in
        // the window; the newest entry (the latest epoch that retains the version) is reported.
        // Aux records (versions 2^63 and up, CONTRACTS 6.8) are checkpoint data; superseded
        // object versions follow the object floor.
        const aux = version > std.math.maxInt(i64) and version != aux_superseded;
        var it = KeyLocs.init(s, .ver, s.store.verKey(id, version));
        var best: ?Found = null;
        while (it.next()) |l| {
            if (!(if (aux) s.store.inWindow(l) else s.store.objInWindow(l))) continue;
            if (best) |bf| if (l <= bf.loc) continue;
            const r = (try s.resolveVer(l, id, version, &damaged)) orelse continue;
            if (!s.visible(r.o.seq)) return null;
            if (aux and !s.store.cpInWindow(r.o.seq)) return null;
            best = .{ .ref = r.o.ref(), .loc = l, .live = false, .data_loc = r.data_loc };
        }
        if (best) |bf| return bf;
        // Compact records are not in the version index: a restored (or carried) version that a
        // newer one superseded is found through its link record (keyed (id, aux_superseded)).
        // The link's epoch (its index run's, or the newest segment's for the memtable) decides the
        // retention, as sui-node keeps a version until the checkpoint that superseded it is pruned.
        // The compact record itself sits in an older segment (the restore's) that is below the
        // object floor by design; a target cleaned away reads as absent.
        var lk = KeyLocs.init(s, .ver, s.store.verKey(id, aux_superseded));
        while (lk.next()) |l| {
            if (!s.store.epochInObjWindow(lk.epoch())) continue;
            const rec = s.store.record(l, s.cepoch) catch |e| switch (e) {
                error.NotFound => continue,
                error.Corrupt => {
                    damaged = true;
                    continue;
                },
                else => return e,
            };
            if (format.short(rec).kind != .object_c) continue;
            const o = s.store.objRec(rec) catch {
                damaged = true;
                continue;
            };
            if (o.version != version or !std.mem.eql(u8, &o.id, id)) continue;
            return .{ .ref = o.ref(), .loc = l, .live = false, .data_loc = l };
        }
        // Without a link (a store written before links), walk the previous-version links back from the
        // live record, a bounded number of steps, inside the history window only.
        if (s.liveTable().get(id)) |lv| {
            var l = table.locOf(lv);
            var steps: u32 = 0;
            while (l != 0 and steps < max_chain) : (steps += 1) {
                const rec = s.store.record(l, s.cepoch) catch |e| switch (e) {
                    error.NotFound => break,
                    error.Corrupt => {
                        damaged = true;
                        break;
                    },
                    else => return e,
                };
                switch (format.short(rec).kind) {
                    .object, .object_c => {
                        const o = s.store.objRec(rec) catch {
                            damaged = true;
                            break;
                        };
                        if (!std.mem.eql(u8, &o.id, id) or o.version < version) break;
                        if (o.version == version) {
                            if (!s.store.objInWindow(l) or !s.visible(o.seq)) break;
                            return .{ .ref = o.ref(), .loc = l, .live = false, .data_loc = l };
                        }
                        l = o.a;
                    },
                    .remove => {
                        if (rec.len < format.header_len + @sizeOf(format.RemoveFixed)) break;
                        const f = format.fixed(format.RemoveFixed, rec);
                        if (!std.mem.eql(u8, &f.id, id) or f.version < version) break;
                        l = format.header(rec).a;
                    },
                    else => break,
                }
            }
        }
        if (damaged) return error.Corrupt;
        return null;
    }

    /// Previous-version links objectAtChecked follows looking for a superseded compact record.
    const max_chain = 64;

    /// Logs every version-index candidate of (id, version) and what it resolves to: a
    /// diagnostic for a read that failed with Corrupt (deepwave check).
    pub fn explainVersion(s: *const Snapshot, id: *const [32]u8, version: u64) void {
        var it = KeyLocs.init(s, .ver, s.store.verKey(id, version));
        var n: u32 = 0;
        while (it.next()) |l| : (n += 1) {
            const ep = format.epochOf(l);
            const off = format.offsetOf(l);
            const rec = s.store.record(l, s.cepoch) catch |e| {
                std.log.err("  candidate {d}:{d} window {} obj {} record: {s}", .{ ep, off, s.store.inWindow(l), s.store.objInWindow(l), @errorName(e) });
                continue;
            };
            const k = format.short(rec).kind;
            var info: [160]u8 = undefined;
            var msg: []const u8 = "";
            if (k == .xref and rec.len == format.short_len + @sizeOf(format.XrefFixed)) {
                const f = format.fixedShort(format.XrefFixed, rec);
                const tr = s.store.record(f.target, s.cepoch) catch |e| {
                    std.log.err("  candidate {d}:{d} window {} obj {} xref v{d} -> {d}:{d}: {s}", .{ ep, off, s.store.inWindow(l), s.store.objInWindow(l), f.version, format.epochOf(f.target), format.offsetOf(f.target), @errorName(e) });
                    continue;
                };
                const tk = format.short(tr).kind;
                const o = s.store.objRec(tr) catch null;
                msg = std.fmt.bufPrint(&info, "xref v{d} -> {d}:{d} kind {d} objRec v{d}", .{ f.version, format.epochOf(f.target), format.offsetOf(f.target), @intFromEnum(tk), if (o) |x| x.version else 0 }) catch "";
            } else if (k == .object or k == .object_c) {
                const o = s.store.objRec(rec) catch null;
                const hb: u64 = if (k == .object) format.header(rec).b else 0;
                msg = std.fmt.bufPrint(&info, "kind {d} objRec v{d} b {d}:{d}", .{ @intFromEnum(k), if (o) |x| x.version else 0, format.epochOf(hb), format.offsetOf(hb) }) catch "";
            } else {
                msg = std.fmt.bufPrint(&info, "kind {d} len {d}", .{ @intFromEnum(k), rec.len }) catch "";
            }
            std.log.err("  candidate {d}:{d} window {} obj {} {s}", .{ ep, off, s.store.inWindow(l), s.store.objInWindow(l), msg });
        }
        if (s.liveTable().get(id)) |lv| std.log.err("  live {d}:{d} compact {}", .{ format.epochOf(table.locOf(lv)), format.offsetOf(table.locOf(lv)), lv & table.compact != 0 });
        if (n == 0) std.log.err("  no version-index candidates", .{});
    }

    /// Sequence number of the committed checkpoint with this summary digest, if the store still
    /// holds it (CONTRACTS 6.8).
    pub fn checkpointByDigest(s: *const Snapshot, digest: *const [32]u8) ?u64 {
        const v = s.objectAt(digest, aux_checkpoint_digest) orelse return null;
        if (v.len != 8) {
            s.noteCorrupt();
            return null;
        }
        const seq = std.mem.readInt(u64, v[0..8], .little);
        if (!s.visible(seq)) return null;
        return seq;
    }

    /// Lowest checkpoint the store holds (sui-node's `lowest_available_checkpoint`): retained
    /// checkpoints are contiguous up to the newest committed one (segments are dropped oldest
    /// first; a snapshot-started store holds no checkpoint below the restored one), so a binary
    /// search over `checkpoint(seq)` finds it in about 40 lookups. Callers cache the result and
    /// refresh it after a prune.
    pub fn lowestCheckpoint(s: *const Snapshot) ?u64 {
        const hi0 = s.highestCommitted() orelse return null;
        if (s.checkpoint(hi0) == null) return null;
        var lo: u64 = 0;
        var hi: u64 = hi0; // invariant: checkpoint(hi) exists
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (s.checkpoint(mid) != null) hi = mid else lo = mid + 1;
        }
        return hi;
    }

    /// The recorded highest pruned checkpoint (`Batch.highestPruned`), while its segment is in
    /// the history window. sui-node's lowest_available_checkpoint is this plus one.
    pub fn highestPruned(s: *const Snapshot) ?u64 {
        const v = s.objectAt(&aux_zero_id, aux_highest_pruned) orelse return null;
        if (v.len != 8) {
            s.noteCorrupt();
            return null;
        }
        return std.mem.readInt(u64, v[0..8], .little);
    }

    /// sui-node's `lowest_available_checkpoint`: the lowest checkpoint held, but above a
    /// recorded highest pruned checkpoint (a snapshot-started store holds its restored
    /// end-of-epoch checkpoint S and reports S + 1, like sui-node, sui-core storage.rs
    /// get_lowest_available_checkpoint = highest_pruned + 1). Null on an empty store.
    pub fn lowestAvailable(s: *const Snapshot) ?u64 {
        const l = s.lowestCheckpoint() orelse return null;
        const hp = s.highestPruned() orelse return l;
        return @max(l, hp +| 1);
    }

    /// The lowest checkpoint at or above `from` whose transactions still read every object
    /// version they read or wrote (sui-node's objects pruner: highest pruned checkpoint + 1,
    /// `get_lowest_available_checkpoint_objects`). Two rules hide a version, and the result is
    /// above both:
    ///   - the object floor (`obj_floor`): the ager frees a version once the checkpoint that
    ///     superseded it is below it, as sui-node deletes it;
    ///   - the object window (`objInWindow`): versions in segments below `obj_floor_epoch` (and
    ///     the aged floor) read as absent, so no checkpoint of an older epoch is whole. The
    ///     object floor's own checkpoint is in that epoch when the node's retention set both
    ///     (one record read here); a store whose window is ahead of its floor (an older deepwave's
    ///     floors) gets the first checkpoint of the window's epoch.
    /// A checkpoint at or above the result holds its inputs in its own segment or a newer one
    /// when the node wrote read sets (node history.zig `inputAction`).
    pub fn objectsFrom(s: *const Snapshot, from: u64) u64 {
        const st = s.store;
        const lo = @max(from, st.obj_floor.load(.acquire));
        const w = @max(st.obj_floor_epoch.load(.acquire), st.oldest_epoch.load(.acquire));
        const hi = s.highestCommitted() orelse return lo;
        if (w == 0 or lo > hi) return lo;
        const epochOf = struct {
            fn f(sn: *const Snapshot, seq: u64) ?u64 {
                return if (sn.checkpointHeld(seq)) |c| c.epoch else null;
            }
        }.f;
        if ((epochOf(s, lo) orelse return lo) >= w) return lo;
        // Nothing the store holds is in the window (the window is at most the newest segment).
        if ((epochOf(s, hi) orelse return lo) < w) return hi + 1;
        var a = lo; // epoch(a) < w <= epoch(b)
        var b = hi;
        while (b - a > 1) {
            const mid = a + (b - a) / 2;
            // An unreadable record counts as below the window: the result only errs upwards.
            if ((epochOf(s, mid) orelse 0) >= w) b = mid else a = mid;
        }
        return b;
    }

    /// What sui-node's RPC surface reports and serves from (sui-rpc-api reader.rs
    /// `get_lowest_available_checkpoint`: the higher of the checkpoint store's and the objects
    /// pruner's lowest available checkpoints): GetServiceInfo's `lowest_available_checkpoint`
    /// (and `_objects`), the `x-sui-lowest-available-*` headers, and the floor of GetCheckpoint,
    /// GetTransaction and the List* methods. Every checkpoint at or above it answers with its
    /// transactions, effects, balance changes and objects. `lowestAvailable` alone is the
    /// checkpoint store's (state sync's GetCheckpointAvailability). Null on an empty store.
    pub fn lowestServed(s: *const Snapshot) ?u64 {
        return s.objectsFrom(s.lowestAvailable() orelse return null);
    }

    pub fn objectAt(s: *const Snapshot, id: *const [32]u8, version: u64) ?[]const u8 {
        const r = s.objectAtChecked(id, version) catch {
            s.noteCorrupt();
            return null;
        } orelse return null;
        return r.bytes;
    }

    fn checkpointAt(s: *const Snapshot, seq: u64, l: u64, damaged: *bool, held: bool) Error!?CheckpointRecord {
        if (!s.store.inWindow(l)) return null;
        if (!held and !s.store.cpInWindow(seq)) return null;
        const rec = s.store.record(l, s.cepoch) catch |e| switch (e) {
            error.NotFound => return null,
            error.Corrupt => {
                damaged.* = true;
                return null;
            },
            else => return e,
        };
        const h = format.header(rec);
        if (h.kind != .checkpoint or h.seq != seq or rec.len < format.header_len + @sizeOf(format.CheckpointFixed)) return null;
        const f = format.fixed(format.CheckpointFixed, rec);
        const p = rec[format.header_len + @sizeOf(format.CheckpointFixed) ..];
        if (p.len != @as(usize, f.summary_len) + f.contents_len) return error.Corrupt;
        // The core's certificate, when this checkpoint came from another source and the edge has
        // since fetched the core's (`Store.cert_fix`): the same summary, another certificate.
        const summary_cert: []const u8 = if (s.store.cert_fix.find(&certFixKey(seq))) |fx| fx.tx else p[0..f.summary_len];
        return .{ .seq = seq, .epoch = f.epoch, .summary_cert = summary_cert, .contents = p[f.summary_len..] };
    }

    pub fn checkpointChecked(s: *const Snapshot, seq: u64) Error!?CheckpointRecord {
        const read_t0 = readstats.begin();
        defer readstats.end(.checkpoints, read_t0);
        return s.checkpointImpl(seq, false);
    }

    /// A checkpoint the store still holds, below the checkpoint floor too (retention needs the
    /// epoch boundaries of pruned checkpoints). Not for serving.
    pub fn checkpointHeld(s: *const Snapshot, seq: u64) ?CheckpointRecord {
        return s.checkpointImpl(seq, true) catch {
            s.noteCorrupt();
            return null;
        };
    }

    fn checkpointImpl(s: *const Snapshot, seq: u64, held: bool) Error!?CheckpointRecord {
        if (!s.visible(seq)) return null;
        const st = s.store;
        var damaged = false;
        const m = st.mem.load(.acquire).?;
        if (table.cpFind(m.cps.slice(), seq)) |l| if (try s.checkpointAt(seq, l, &damaged, held)) |c| return c;
        var i = st.ep_tail.load(.acquire);
        const lo = if (st.runs_total.load(.acquire) == 0) i else st.ep_head.load(.acquire);
        while (i > lo) {
            i -= 1;
            const e = st.ep_ring[i & st.seg_mask].load(.monotonic);
            const slot = st.slotOf(e) orelse continue;
            var r = slot.nruns.load(.acquire);
            while (r > 0) {
                r -= 1;
                const run = slot.runs[r].load(.acquire) orelse continue;
                if (run.header.ncp == 0 or seq < run.header.min_seq or seq > run.header.max_seq) continue;
                if (run.findCp(seq)) |l| if (try s.checkpointAt(seq, l, &damaged, held)) |c| return c;
            }
        }
        if (damaged) return error.Corrupt;
        return null;
    }

    pub fn checkpoint(s: *const Snapshot, seq: u64) ?CheckpointRecord {
        return s.checkpointChecked(seq) catch {
            s.noteCorrupt();
            return null;
        };
    }

    pub fn transactionChecked(s: *const Snapshot, digest: *const [32]u8) Error!?TransactionRecord {
        const read_t0 = readstats.begin();
        defer readstats.end(.transactions, read_t0);
        var it = KeyLocs.init(s, .tx, Store.txKey(digest));
        var damaged = false;
        while (it.next()) |l| switch (try s.txAt(l, digest, &damaged)) {
            .miss => {},
            .hit => |r| return r,
            .hidden => return null,
        };
        if (damaged) return error.Corrupt;
        return null;
    }

    const TxTry = union(enum) { miss, hit: TransactionRecord, hidden };

    /// The transaction-index candidate at `l`: the transaction `digest` (hit), not it (miss), or
    /// it but not visible to this snapshot or below the checkpoint floor (hidden).
    fn txAt(s: *const Snapshot, l: u64, digest: *const [32]u8, damaged: *bool) Error!TxTry {
        if (!s.store.inWindow(l)) return .miss;
        const rec = s.store.record(l, s.cepoch) catch |e| switch (e) {
            error.NotFound => return .miss,
            error.Corrupt => {
                damaged.* = true;
                return .miss;
            },
            else => return e,
        };
        const h = format.header(rec);
        if (h.kind != .tx or rec.len < format.header_len + @sizeOf(format.TxFixed)) return .miss;
        const f = format.fixed(format.TxFixed, rec);
        if (!std.mem.eql(u8, &f.digest, digest)) return .miss;
        if (!s.visible(h.seq) or !s.store.cpInWindow(h.seq)) return .hidden;
        const p = rec[format.header_len + @sizeOf(format.TxFixed) ..];
        const a = @as(usize, f.tx_len);
        const b2 = a + f.effects_len;
        if (p.len != b2 + f.events_len) return error.Corrupt;
        // The submitted signature order, when the sweep found the stored one to be the contents'
        // (txfix.zig): same length and TransactionData, so only the signatures' order changes.
        const tx = if (s.store.tx_fix.find(digest)) |fx| (if (fx.tx.len == a) fx.tx else p[0..a]) else p[0..a];
        return .{ .hit = .{
            .checkpoint = h.seq,
            .digest = &f.digest,
            .effects_digest = &f.effects_digest,
            .tx = tx,
            .effects = p[a..b2],
            .events = if (f.has_events != 0) p[b2..] else null,
            .loc = l,
        } };
    }

    pub fn transaction(s: *const Snapshot, digest: *const [32]u8) ?TransactionRecord {
        return s.transactionChecked(digest) catch {
            s.noteCorrupt();
            return null;
        };
    }

    // ------------------------------------------------------------ hinted lookups (List* reads)
    //
    // `transaction` and `objectAt` probe the memtable and then every index run of every retained
    // epoch (42 runs on a mainnet store holding two epochs), and `objectAt` the live table first:
    // cold, each probe is a 4 KiB read, ~25 for a transaction and ~45 for an object version.
    // A caller that knows where to look passes a hint: the checkpoint that holds a transaction,
    // or the location of the transaction record whose object set is being read (a version it
    // read or wrote was written at or before it). The hinted lookup probes the runs that can hold
    // the record first and stops at the first hit; anything else (a miss, a hidden or damaged
    // candidate) falls back to the plain lookup, so the answer is always the plain lookup's.

    /// Hinted lookups on (default) or off (`ZUI_STORE_NEAR=0`, read once): for A/B timing.
    pub fn nearOn() bool {
        const v = near_conf.load(.monotonic);
        if (v != 2) return v == 1;
        var on = true;
        if (std.c.getenv("ZUI_STORE_NEAR")) |e| on = !std.mem.eql(u8, std.mem.span(e), "0");
        near_conf.store(@intFromBool(on), .monotonic);
        return on;
    }

    /// `transaction(digest)`, probing first the runs whose checkpoints include `cp` (the
    /// checkpoint that holds it, as an index such as ledger history names it).
    pub fn transactionNear(s: *const Snapshot, digest: *const [32]u8, cp: u64) ?TransactionRecord {
        if (nearOn()) if (s.transactionNearTry(digest, cp)) |r| return r;
        return s.transaction(digest);
    }

    fn transactionNearTry(s: *const Snapshot, digest: *const [32]u8, cp: u64) ?TransactionRecord {
        const st = s.store;
        const key = Store.txKey(digest);
        var damaged = false;
        var mit = st.mem.load(.acquire).?.tx.find(key);
        while (mit.next()) |l| switch (s.txAt(l, digest, &damaged) catch return null) {
            .miss => {},
            .hit => |r| return r,
            .hidden => return null,
        };
        var runs = NearRuns.init(s);
        while (runs.next()) |run| {
            const h = &run.header;
            if (h.ncp != 0 and (cp < h.min_seq or cp > h.max_seq)) continue;
            if (!run.mayHaveTx(key)) {
                probe_stats.filter_skips += 1;
                continue;
            }
            probe_stats.run_probes += 1;
            var it = run.tx.find(key);
            while (it.next()) |l| switch (s.txAt(l, digest, &damaged) catch return null) {
                .miss => {},
                .hit => |r| return r,
                .hidden => return null,
            };
        }
        return null;
    }

    /// `objectAt(id, version)` for a version transaction `at` (its record's location,
    /// `TransactionRecord.loc`) read or wrote, or `at`'s aux records (its loaded runtime object
    /// list): probes the memtable and the run holding `at`, the live record, then the older runs
    /// newest first. 0 = no hint.
    pub fn objectNear(s: *const Snapshot, id: *const [32]u8, version: u64, at: u64) ?[]const u8 {
        if (at != 0 and nearOn()) switch (s.objectNearTry(id, version, at)) {
            .hit => |b| {
                probe_stats.near_hits += 1;
                return b;
            },
            .miss, .hidden => probe_stats.near_falls += 1,
        };
        return s.objectAt(id, version);
    }

    const ObjTry = union(enum) { miss, hit: []const u8, hidden };

    fn objectNearTry(s: *const Snapshot, id: *const [32]u8, version: u64, at: u64) ObjTry {
        if (version == aux_superseded) return .miss;
        const st = s.store;
        const aux = version > std.math.maxInt(i64);
        const key = st.verKey(id, version);
        var mit = st.mem.load(.acquire).?.ver.find(key);
        while (mit.next()) |l| {
            const r = s.verAt(l, id, version, aux);
            if (r != .miss) return r;
        }
        // The run holding `at` (outputs and aux records sit in the transaction's own batch).
        var runs = NearRuns.init(s);
        while (runs.next()) |run| {
            const h = &run.header;
            if (h.start_loc > at or at >= h.end_loc) continue;
            const r = s.verRun(run, key, id, version, aux);
            if (r != .miss) return r;
            break; // runs do not overlap
        }
        // The live record (objectFind's first probe): an input nothing has superseded since.
        if (!aux) if (s.liveTable().get(id)) |lv| live: {
            probe_stats.live_probes += 1;
            const rec = st.record(table.locOf(lv), s.cepoch) catch break :live;
            const k = format.short(rec).kind;
            if (k != .object and k != .object_c) break :live;
            const o = st.objRec(rec) catch break :live;
            if (o.version != version or !std.mem.eql(u8, &o.id, id)) break :live;
            if (!s.visible(o.seq)) return .hidden;
            return .{ .hit = o.bytes };
        };
        // Inputs written before the transaction: the older runs, newest first.
        runs = NearRuns.init(s);
        while (runs.next()) |run| {
            if (run.header.end_loc > at) continue;
            const r = s.verRun(run, key, id, version, aux);
            if (r != .miss) return r;
        }
        return .miss;
    }

    fn verRun(s: *const Snapshot, run: *const table.Run, key: u64, id: *const [32]u8, version: u64, aux: bool) ObjTry {
        if (!run.mayHaveVer(key)) {
            probe_stats.filter_skips += 1;
            return .miss;
        }
        probe_stats.run_probes += 1;
        var it = run.ver.find(key);
        while (it.next()) |l| {
            const r = s.verAt(l, id, version, aux);
            if (r != .miss) return r;
        }
        return .miss;
    }

    /// A version-index candidate as `objectFind`'s index loop takes it: in the window, resolved
    /// to (id, version), visible (else hidden: the plain lookup decides).
    fn verAt(s: *const Snapshot, l: u64, id: *const [32]u8, version: u64, aux: bool) ObjTry {
        if (!(if (aux) s.store.inWindow(l) else s.store.objInWindow(l))) return .miss;
        var damaged = false;
        const r = (s.resolveVer(l, id, version, &damaged) catch return .hidden) orelse
            return if (damaged) .hidden else .miss;
        if (!s.visible(r.o.seq)) return .hidden;
        if (aux and !s.store.cpInWindow(r.o.seq)) return .hidden;
        return .{ .hit = r.o.bytes };
    }

    /// Every retained epoch's index runs, newest first (KeyLocs' order without the memtable).
    const NearRuns = struct {
        st: *Store,
        i: u64,
        lo: u64,
        slot: ?*SegSlot = null,
        r: u32 = 0,

        fn init(s: *const Snapshot) NearRuns {
            const st = s.store;
            const tail = st.ep_tail.load(.acquire);
            return .{ .st = st, .i = tail, .lo = if (st.runs_total.load(.acquire) == 0) tail else st.ep_head.load(.acquire) };
        }

        fn next(n: *NearRuns) ?*const table.Run {
            while (true) {
                if (n.slot) |slot| {
                    while (n.r > 0) {
                        n.r -= 1;
                        if (slot.runs[n.r].load(.acquire)) |run| return run;
                    }
                    n.slot = null;
                }
                if (n.i <= n.lo) return null;
                n.i -= 1;
                const e = n.st.ep_ring[n.i & n.st.seg_mask].load(.monotonic);
                const slot = n.st.slotOf(e) orelse continue;
                n.slot = slot;
                n.r = slot.nruns.load(.acquire);
            }
        }
    };

    pub fn release(s: *Snapshot) void {
        const st = s.store;
        const gone = st.creaders.exit(s.cepoch);
        st.rcu.exit(s.parity);
        // A store that only serves reads still frees its evicted chunks.
        if (st.cache.evicted_bytes.load(.monotonic) > 0 or (gone and st.chunk_kept_n.load(.monotonic) > 0)) st.chunkReclaim();
        // Debug/ReleaseSafe: a read through a released snapshot (a `*const Snapshot` kept past
        // release, as State.fromSnapshot did in simulateChain) faults on the poisoned store
        // pointer instead of reading as a live reader that no grace period waits for.
        if (std.debug.runtime_safety) @memset(std.mem.asBytes(s), 0xaa);
    }

    /// For a snapshot held over a long loop (a startup replay): the caller holds no record or
    /// object slice read through this snapshot any more. Chunks it read so far may be freed; the
    /// snapshot keeps its checkpoint and stays usable. Call between units of work (a
    /// checkpoint), or the loop pins every chunk it reads until release.
    pub fn quiesce(s: *Snapshot) void {
        const st = s.store;
        _ = st.creaders.exit(s.cepoch);
        st.creaders.advance();
        st.chunkReclaim();
        s.cepoch = st.creaders.enter();
    }

    /// Every live object as of this snapshot (CONTRACTS 6.8): the base a derived index (owner,
    /// dynamic-field, balance, coin, type indexes) builds from at startup, then follows
    /// `on_batch` from `highestCommitted()`. Part `part` of `parts` disjoint slot ranges, so
    /// builders can run one iterator per thread. Safe on any thread while the writer runs, but
    /// an object whose slot moves meanwhile (tombstone deletion while cleaning, table growth)
    /// can be seen twice or missed; build before following starts, or reconcile with the
    /// batches committed after the snapshot.
    pub fn liveIter(s: *const Snapshot, part: u64, parts: u64) LiveIter {
        const t = s.liveTable();
        const n = t.nslots;
        const p = @max(parts, 1);
        var it: LiveIter = .{ .snap = s, .t = t, .i = n * part / p, .end = n * (part + 1) / p };
        // With compressed segments, walk the segments in order instead: one chunk decoded per
        // ~32 KiB of records, where the slot order would decode a random chunk per object.
        it.scan = LiveIter.Scan.create(s, part, p) catch null;
        return it;
    }
};

/// Explicit read-ahead for walks over mapped segments in location order (the mappings are
/// MADV_RANDOM): MADV_WILLNEED on the next 32 MiB whenever the cursor passes the last window's
/// first half. Point lookups beside the walk keep 4 KiB faults.
pub const ReadAhead = struct {
    epoch: u64 = std.math.maxInt(u64),
    ahead: u64 = 0,
    const window: u64 = 16 << 20;

    pub fn at(ra: *ReadAhead, st: *const Store, l: u64) void {
        if (st.backend != .real) return;
        const e = format.epochOf(l);
        const off = format.offsetOf(l);
        if (e == ra.epoch and off + window <= ra.ahead) return;
        const slot = st.slotOf(e) orelse return;
        // A compressed segment's offsets are logical (not its mapping's); its walk decodes chunks.
        if (slot.comp.load(.acquire) != null) return;
        ra.span(slot.base.load(.acquire), slot.end.load(.acquire), e, off);
    }

    /// `at` over a view whose end is known to the caller (recovery: before `end` is published).
    pub fn span(ra: *ReadAhead, base: usize, end: u64, e: u64, off: u64) void {
        if (e == ra.epoch and off + window <= ra.ahead) return;
        if (base == 0 or off >= end) return;
        const from = std.mem.alignBackward(u64, if (e == ra.epoch) @max(ra.ahead, off) else off, std.heap.pageSize());
        const len = @min(2 * window, end - from);
        if (len > 0) std.posix.madvise(@ptrFromInt(base + from), len, std.posix.MADV.WILLNEED) catch {};
        ra.epoch = e;
        ra.ahead = from + len;
    }
};

pub const LiveIter = struct {
    snap: *const Snapshot,
    t: *const table.LiveTable,
    i: u64,
    end: u64,
    /// Segment-order mode (a store with compressed segments): item bytes are then valid until
    /// the next call to `next` (or `deinit`), not until the snapshot is released.
    scan: ?*Scan = null,

    const Unit = struct { e: u64, lo: usize, hi: usize, raw_end: u64 = 0, raw: bool = false };

    const Scan = struct {
        gpa: std.mem.Allocator,
        units: std.ArrayList(Unit) = .empty,
        ui: usize = 0,
        /// Next chunk of the current unit (compressed) or next group offset (raw).
        ci: u64 = 0,
        started: bool = false,
        buf: std.ArrayList(u8) = .empty,
        /// Logical offset of buf[0] (compressed) and the parse position in buf.
        base: u64 = 0,
        p: usize = 0,
        stop: usize = 0,
        /// Records at or past this location were written after the snapshot was taken.
        tail_loc: u64,

        fn create(snap: *const Snapshot, part: u64, parts: u64) !?*Scan {
            const st = snap.store;
            var any = false;
            var eps: std.ArrayList(u64) = .empty;
            defer eps.deinit(st.gpa);
            for (st.segs) |*slot| {
                const e = slot.epoch.load(.acquire);
                if (e == no_epoch) continue;
                if (slot.comp.load(.acquire) != null) any = true;
                try eps.append(st.gpa, e);
            }
            if (!any) return null;
            std.mem.sort(u64, eps.items, {}, std.sort.asc(u64));
            const sc = try st.gpa.create(Scan);
            errdefer st.gpa.destroy(sc);
            var tail: u64 = 0;
            sc.* = .{ .gpa = st.gpa, .tail_loc = 0 };
            errdefer sc.units.deinit(st.gpa);
            const per = 1024;
            var k: u64 = 0;
            for (eps.items) |e| {
                const slot = st.slotOf(e) orelse continue;
                const end = slot.end.load(.acquire);
                tail = @max(tail, format.loc(e, end));
                if (slot.comp.load(.acquire)) |c| {
                    const d = c.dir.load(.acquire);
                    var hi = d.len();
                    while (hi > 0 and d.entries[hi - 1].ls >= end) hi -= 1;
                    var lo: usize = 0;
                    while (lo < hi) : (lo += per) {
                        if (k % parts == part) try sc.units.append(st.gpa, .{ .e = e, .lo = lo, .hi = @min(hi, lo + per) });
                        k += 1;
                    }
                } else {
                    if (k % parts == part) try sc.units.append(st.gpa, .{ .e = e, .lo = 0, .hi = 0, .raw = true, .raw_end = end });
                    k += 1;
                }
            }
            sc.tail_loc = tail;
            return sc;
        }

        fn destroy(sc: *Scan) void {
            sc.units.deinit(sc.gpa);
            sc.buf.deinit(sc.gpa);
            sc.gpa.destroy(sc);
        }
    };

    pub fn deinit(it: *LiveIter) void {
        if (it.scan) |sc| sc.destroy();
        it.scan = null;
    }

    /// Segment-order: the next object record of the scan, as (location, record).
    fn nextRecord(it: *LiveIter, sc: *Scan) Error!?struct { l: u64, rec: []const u8 } {
        const st = it.snap.store;
        while (sc.ui < sc.units.items.len) {
            const u = sc.units.items[sc.ui];
            const slot = st.slotOf(u.e) orelse {
                sc.ui += 1;
                sc.started = false;
                continue;
            };
            if (!sc.started) {
                sc.started = true;
                sc.ci = if (u.raw) 0 else u.lo;
                sc.p = 0;
                sc.stop = 0;
            }
            // Records left in the loaded bytes.
            while (sc.p + format.short_len <= sc.stop) {
                const data = if (u.raw) Store.viewOf(slot)[0..sc.stop] else sc.buf.items;
                const p = sc.p;
                const h = format.short(data[p..]);
                const n = format.lenOf(h.kind, h.size);
                if (h.kind == .commit) {
                    sc.p = if (u.raw) std.mem.alignForward(usize, p + n, block) else sc.stop;
                    continue;
                }
                sc.p = p + n;
                if (h.kind != .object and h.kind != .object_c) continue;
                if (h.flags & format.flag_historical != 0) continue;
                const off = if (u.raw) p else sc.base + p;
                const l = format.loc(u.e, off);
                const rec = if (st.cfg.verify_reads) try format.validate(data, p, l) else data[p..][0 .. format.hdrLen(h.kind) + h.size];
                return .{ .l = l, .rec = rec };
            }
            if (u.raw) {
                // Whole groups of the raw segment, up to its end at the snapshot.
                if (sc.stop >= u.raw_end) {
                    sc.ui += 1;
                    sc.started = false;
                    continue;
                }
                const w = walkGroup(Store.viewOf(slot)[0..u.raw_end], u.e, sc.stop) orelse return error.Corrupt;
                sc.p = sc.stop;
                sc.stop = w.end;
                continue;
            }
            if (sc.ci >= u.hi) {
                sc.ui += 1;
                sc.started = false;
                continue;
            }
            const c = slot.comp.load(.acquire) orelse return error.Corrupt;
            const en = c.dir.load(.acquire).entries[sc.ci];
            sc.ci += 1;
            sc.buf.clearRetainingCapacity();
            sc.buf.resize(sc.gpa, en.ll) catch return error.OutOfMemory;
            const raw = sc.gpa.alloc(u8, chunk.frame_len + en.bl) catch return error.OutOfMemory;
            defer sc.gpa.free(raw);
            try st.readFrame(c, en, raw);
            const ce = chunk.checkFrame(en.phys, raw) catch return error.Corrupt;
            chunk.decode(ce, c.epoch, c.dicts, raw[chunk.frame_len..][0..en.bl], sc.buf.items) catch return error.Corrupt;
            sc.base = en.ls;
            sc.p = 0;
            sc.stop = en.ll;
        }
        return null;
    }

    fn nextScan(it: *LiveIter, sc: *Scan) Error!?Item {
        const st = it.snap.store;
        while (try it.nextRecord(sc)) |r| {
            const o = try st.objRec(r.rec);
            const lv = it.t.get(&o.id) orelse continue;
            if (lv & table.tomb == 0 and table.locOf(lv) == r.l) {
                if (it.snap.visible(o.seq)) return .{ .id = o.id, .version = o.version, .bytes = o.bytes, .stored_digest = if (o.stored_digest) |d| d.* else null };
            } else if (table.locOf(lv) < sc.tail_loc) continue;
            // Changed after the snapshot: the version the snapshot sees, if it is this record.
            const lat = try it.snap.latest(&o.id) orelse continue;
            switch (lat) {
                .live => |x| if (x.version == o.version) return .{ .id = o.id, .version = o.version, .bytes = o.bytes, .stored_digest = if (o.stored_digest) |d| d.* else null },
                .removed => {},
            }
        }
        return null;
    }

    pub const Item = struct {
        id: [32]u8,
        version: u64,
        bytes: []const u8,
        stored_digest: ?[32]u8,

        pub fn digest(it: *const Item) [32]u8 {
            return it.stored_digest orelse objectDigest(it.bytes);
        }
    };

    /// Slots left to visit (progress reporting).
    pub fn remaining(it: *const LiveIter) u64 {
        return it.end - it.i;
    }

    pub fn next(it: *LiveIter) Error!?Item {
        if (it.scan) |sc| return it.nextScan(sc);
        while (it.i < it.end) {
            const raw = @atomicLoad(u64, it.t.locPtr(it.i), .acquire);
            it.i += 1;
            if (raw == 0 or raw & table.tomb != 0) continue;
            if (try it.itemAt(table.locOf(raw))) |o| return o;
        }
        return null;
    }

    /// The live object a slot location points at, as the snapshot sees it (null: not an
    /// object record, gone, or removed since).
    fn itemAt(it: *const LiveIter, l: u64) Error!?Item {
        const rec = it.snap.store.record(l, it.snap.cepoch) catch |e| switch (e) {
            error.NotFound => return null,
            else => return e,
        };
        return it.itemOf(rec);
    }

    /// The live object of record bytes `rec` as the snapshot sees it (`itemAt`).
    fn itemOf(it: *const LiveIter, rec: []const u8) Error!?Item {
        const st = it.snap.store;
        const k = format.short(rec).kind;
        if (k != .object and k != .object_c) return null;
        const o = try st.objRec(rec);
        if (it.snap.visible(o.seq)) return .{ .id = o.id, .version = o.version, .bytes = o.bytes, .stored_digest = if (o.stored_digest) |d| d.* else null };
        // Written after the snapshot: the version the snapshot sees, if any.
        const lat = try it.snap.latest(&o.id) orelse return null;
        return switch (lat) {
            .live => |r| .{ .id = o.id, .version = r.version, .bytes = r.bytes, .stored_digest = r.digest },
            .removed => null,
        };
    }
};

/// The live object set as of a snapshot that may lie in the past (lane fullnode-ops: formal
/// snapshot producer, `deepwave-tool state-hash`): `Snapshot{ .c1 = S + 1 }` sees the objects live
/// after checkpoint S even once later checkpoints changed them. Unlike `LiveIter` it also visits
/// tombstoned slots, whose chain can hold an object deleted or wrapped after S. Every object
/// live at S is in exactly one slot as long as no slot moved since S (no table growth, no
/// cleaning of the segments involved); callers check `t` against the store's current table.
pub const HistIter = struct {
    snap: *const Snapshot,
    t: *const table.LiveTable,
    i: u64,
    end: u64,

    pub fn init(s: *const Snapshot, from: u64, to: u64) HistIter {
        const t = s.liveTable();
        return .{ .snap = s, .t = t, .i = @min(from, t.nslots), .end = @min(to, t.nslots) };
    }

    pub fn slots(s: *const Snapshot) u64 {
        return s.liveTable().nslots;
    }

    pub fn next(it: *HistIter) Error!?LiveIter.Item {
        const st = it.snap.store;
        while (it.i < it.end) {
            const raw = @atomicLoad(u64, it.t.locPtr(it.i), .acquire);
            it.i += 1;
            if (raw == 0) continue;
            const rec = st.record(table.locOf(raw), it.snap.cepoch) catch |e| switch (e) {
                error.NotFound => continue,
                else => return e,
            };
            var id: [32]u8 = undefined;
            switch (format.short(rec).kind) {
                .object, .object_c => {
                    const o = try st.objRec(rec);
                    if (raw & table.tomb == 0 and it.snap.visible(o.seq))
                        return .{ .id = o.id, .version = o.version, .bytes = o.bytes, .stored_digest = if (o.stored_digest) |d| d.* else null };
                    id = o.id;
                },
                .remove => {
                    if (rec.len < format.header_len + @sizeOf(format.RemoveFixed)) return error.Corrupt;
                    id = format.fixed(format.RemoveFixed, rec).id;
                },
                else => continue,
            }
            const lat = try it.snap.latest(&id) orelse continue;
            switch (lat) {
                .live => |r| return .{ .id = id, .version = r.version, .bytes = r.bytes, .stored_digest = r.digest },
                .removed => continue,
            }
        }
        return null;
    }
};

/// The live object set as of checkpoint `c1 - 1`, in segment order (lane fullnode-ops: formal
/// snapshot producer, state-hash). `HistIter` visits live-table slots in hash order, which on a
/// restored mainnet store is one random segment read per object (hours on EBS); this walks every
/// segment sequentially, commit group by commit group, and keeps a record when it is the version
/// a snapshot at `c1` resolves its id to (same location). Workers share one scanner: `next`
/// hands out the next commit group, `group` yields its live objects. Historical copies, removes
/// and newer versions are skipped, so each live object is yielded exactly once. Safe while the
/// writer runs as long as no segment is cleaned meanwhile (the node pauses cleaning). Raw (uncompressed) segments only; LiveScan reads both.
pub const SegScan = struct {
    store: *Store,
    c1: u64,
    lock: std.atomic.Value(bool) = .init(false),
    seg_i: usize = 0,
    off: u64 = 0,
    /// Bytes of segment handed out so far (progress).
    scanned: std.atomic.Value(u64) = .init(0),
    /// Segment offset up to which read-ahead was asked for (MADV_WILLNEED): page faults one 4 KiB
    /// page at a time would leave the disk at queue depth ~1.
    ahead: u64 = 0,
    /// Segment offset below which this process's pages were dropped (MADV_DONTNEED): a full scan
    /// touches every segment byte, and mapped pages kept resident pushed RSS past 55 GB on a
    /// 256 GB store. Clean file pages; a late reader behind the window just faults them back.
    released: u64 = 0,
    const ahead_window: u64 = 256 << 20;

    pub const Group = struct { slot: usize, epoch: u64, from: u64, to: u64 };

    pub fn init(st: *Store, c1: u64) SegScan {
        return .{ .store = st, .c1 = c1 };
    }

    /// Total bytes of all segments (progress).
    pub fn totalBytes(sc: *const SegScan) u64 {
        var t: u64 = 0;
        for (sc.store.segs) |*sl| if (sl.epoch.load(.acquire) != no_epoch) {
            t += sl.end.load(.acquire);
        };
        return t;
    }

    pub fn next(sc: *SegScan) ?Group {
        while (sc.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
        defer sc.lock.store(false, .release);
        const st = sc.store;
        while (sc.seg_i < st.segs.len) {
            const sl = &st.segs[sc.seg_i];
            const e = sl.epoch.load(.acquire);
            const end = sl.end.load(.acquire);
            if (e == no_epoch or sc.off >= end) {
                sc.seg_i += 1;
                sc.off = 0;
                sc.ahead = 0;
                sc.released = 0;
                continue;
            }
            const p = st.rcu.enter();
            defer st.rcu.exit(p);
            const base = sl.base.load(.acquire);
            const data = @as([*]const u8, @ptrFromInt(base))[0..end];
            if (sc.off + ahead_window / 2 >= sc.ahead and sc.ahead < end) {
                const from = std.mem.alignBackward(u64, @max(sc.ahead, sc.off), std.heap.page_size_min);
                const len = @min(ahead_window, end - from);
                std.posix.madvise(@ptrFromInt(base + from), len, std.posix.MADV.WILLNEED) catch {};
                sc.ahead = from + len;
            }
            if (sc.off > sc.released + 2 * ahead_window) {
                const to = std.mem.alignBackward(u64, sc.off - ahead_window, std.heap.page_size_min);
                if (to > sc.released) {
                    std.posix.madvise(@ptrFromInt(base + sc.released), to - sc.released, std.posix.MADV.DONTNEED) catch {};
                    sc.released = to;
                }
            }
            const g = walkGroup(data, e, sc.off) orelse {
                sc.seg_i += 1;
                sc.off = 0;
                sc.ahead = 0;
                sc.released = 0;
                continue;
            };
            const out: Group = .{ .slot = sc.seg_i, .epoch = e, .from = sc.off, .to = g.commit_off };
            _ = sc.scanned.fetchAdd(g.end - sc.off, .monotonic);
            sc.off = g.end;
            return out;
        }
        return null;
    }

    /// The live-as-of-`c1` objects of group `g`: `f(ctx, item)`.
    pub fn group(sc: *SegScan, g: Group, ctx: anytype, comptime f: fn (@TypeOf(ctx), LiveIter.Item) anyerror!void) !void {
        const st = sc.store;
        var snap: Snapshot = .{ .store = st, .c1 = sc.c1, .parity = st.rcu.enter(), .cepoch = st.creaders.enter() };
        defer snap.release();
        const sl = &st.segs[g.slot];
        if (sl.epoch.load(.acquire) != g.epoch) return error.SegmentMoved;
        const data = @as([*]const u8, @ptrFromInt(sl.base.load(.acquire)))[0..sl.end.load(.acquire)];
        var p = g.from;
        while (p < g.to) {
            const h = format.short(data[p..]);
            const n = format.lenOf(h.kind, h.size);
            defer p += n;
            if (h.kind != .object and h.kind != .object_c) continue;
            if (h.flags & format.flag_historical != 0) continue;
            const rec = data[p..][0 .. format.hdrLen(h.kind) + h.size];
            const o = try st.objRec(rec);
            if (!snap.visible(o.seq)) continue;
            const here = format.loc(g.epoch, p);
            if (try snap.visibleLoc(&o.id) != here) continue;
            try f(ctx, .{ .id = o.id, .version = o.version, .bytes = o.bytes, .stored_digest = if (o.stored_digest) |d| d.* else null });
        }
    }
};

/// The live object set as of checkpoint `c1 - 1` in location order (lane fullnode-ops: formal
/// snapshot producer, state-hash). Replaces `SegScan` there: SegScan read every segment byte and
/// did one live-table lookup per record, random over a table larger than the page cache (box 1,
/// epoch 1304: 1.04 TB read for 127 GB written in 98 min). This is `Snapshot.forEachLive`'s
/// sorted walk for a past view: `init` collects every live-table location (tombstones too: a
/// remove after `c1` hides an object the view still sees) and sorts them by (epoch, offset);
/// workers take ranges with `next` and read the records front to back in `group`. A record the
/// view sees is yielded (object) or dropped (remove); one written after it queues its
/// previous-version location. When every range is done the queued locations are sorted and
/// handed out the same way, and `group` walks each chain back to the version the view sees
/// (`Snapshot.visibleLoc`'s walk). Each live object is yielded exactly once. Costs 8 bytes per
/// live slot. Safe while the writer runs as long as no segment is cleaned meanwhile.
///
/// Memory besides the locations: one decoded chunk per walker (`Store.WalkBuf`). Records of a
/// compressed segment are read through that walk-private buffer, never the shared chunk cache:
/// a scan reads every chunk of the live set once, and through the cache each of them was two
/// allocations freed by whichever thread ran the next reclaim, one thread at a time, while
/// every walker decoded. A test machine, 2026-11-11, 32 walkers over a 301 GB mainnet store: private
/// memory grew 0.8 GB a second through the read, to 152 GB at 775M entries, and fell to 10 GB
/// when the walkers ended. An item `f` receives is valid until `f` returns.
pub const LiveScan = struct {
    gpa: std.mem.Allocator,
    store: *Store,
    c1: u64,
    /// Raw live-table values (location | tomb/compact bits), sorted.
    locs: std.ArrayList(u64) = .empty,
    /// Previous-version locations of records written at or after `c1`, sorted once the first
    /// pass is done.
    late: std.ArrayList(u64) = .empty,
    lock: std.atomic.Value(bool) = .init(false),
    in_late: bool = false,
    pos: usize = 0,
    /// Ranges handed out and not yet finished.
    active: usize = 0,
    failed: std.atomic.Value(bool) = .init(false),
    /// Locations per range.
    chunk: usize = 1 << 16,
    /// Records read so far (progress).
    scanned: std.atomic.Value(u64) = .init(0),

    pub const Group = struct { late: bool, from: usize, to: usize };

    pub fn init(gpa: std.mem.Allocator, st: *Store, c1: u64) !LiveScan {
        var sc: LiveScan = .{ .gpa = gpa, .store = st, .c1 = c1 };
        errdefer sc.locs.deinit(gpa);
        var snap: Snapshot = .{ .store = st, .c1 = c1, .parity = st.rcu.enter(), .cepoch = st.creaders.enter() };
        defer snap.release();
        const t = snap.liveTable();
        // The table is mapped MADV_RANDOM: walked slot by slot, this was one blocking 4 KiB read
        // per table page (a cold 34 GB mainnet table: hours on box 5). Same read-ahead as the
        // cleaner's count pass (lane catchup-io): this 16 MiB window and the next as large
        // asynchronous reads, walked pages marked cold.
        const real = st.backend == .real;
        const n: u64 = (16 << 20) / page_size;
        var pg: u64 = 0;
        while (pg < t.pages.len) : (pg += n) {
            const end = @min(t.pages.len, pg + n);
            if (real) io_mod.willNeed(Store.tablePages(t.pages, pg, @min(t.pages.len, end + n)));
            var i: u64 = pg * table.per_page;
            while (i < @min(t.nslots, end * table.per_page)) : (i += 1) {
                const raw = @atomicLoad(u64, t.locPtr(i), .acquire);
                if (raw != 0) try sc.locs.append(gpa, raw);
            }
            if (real) io_mod.cold(Store.tablePages(t.pages, pg, end));
        }
        // The low bits are flags; ordering raw values orders the locations. In place on every
        // core (lane index-fast: one thread took about a minute for a mainnet table).
        const nt: usize = if (builtin.is_test) 2 else @min(std.Thread.getCpuCount() catch 4, 32);
        @import("psort.zig").sortU64(gpa, sc.locs.items, nt);
        return sc;
    }

    pub fn deinit(sc: *LiveScan) void {
        sc.locs.deinit(sc.gpa);
        sc.late.deinit(sc.gpa);
    }

    /// Live-table entries the scan starts from (progress).
    pub fn total(sc: *const LiveScan) u64 {
        return sc.locs.items.len;
    }

    fn acquire(sc: *LiveScan) void {
        while (sc.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }

    pub fn next(sc: *LiveScan) ?Group {
        sc.acquire();
        defer sc.lock.store(false, .release);
        while (!sc.in_late) {
            if (sc.failed.load(.acquire)) return null;
            if (sc.pos < sc.locs.items.len) return sc.handOut(false, sc.locs.items.len);
            if (sc.active > 0) {
                // The queue is complete only when every first-pass range is done.
                sc.lock.store(false, .release);
                std.atomic.spinLoopHint();
                sc.acquire();
                continue;
            }
            @import("psort.zig").sortU64(sc.gpa, sc.late.items, if (builtin.is_test) 2 else @min(std.Thread.getCpuCount() catch 4, 32));
            sc.in_late = true;
            sc.pos = 0;
        }
        if (sc.failed.load(.acquire)) return null;
        if (sc.pos < sc.late.items.len) return sc.handOut(true, sc.late.items.len);
        return null;
    }

    fn handOut(sc: *LiveScan, late: bool, len: usize) Group {
        const g: Group = .{ .late = late, .from = sc.pos, .to = @min(len, sc.pos + sc.chunk) };
        sc.pos = g.to;
        sc.active += 1;
        return g;
    }

    /// Asks the kernel for the pages of `[lo, hi]` (both locations), segment by segment, when
    /// the span is small enough to be read anyway (a range of the sorted walk is a few MB of a
    /// dense segment). Never MADV_DONTNEED: on an anonymous view (SimIo) it zeroes the pages.
    fn advise(st: *Store, lo: u64, hi: u64) void {
        const page = std.heap.page_size_min;
        var e = format.epochOf(lo);
        while (e <= format.epochOf(hi)) : (e += 1) {
            const slot = st.slotOf(e) orelse continue;
            const end = slot.end.load(.acquire);
            const base = slot.base.load(.acquire);
            if (base == 0 or end == 0) continue;
            const from = if (e == format.epochOf(lo)) @min(format.offsetOf(lo), end) else 0;
            const to = if (e == format.epochOf(hi)) @min(format.offsetOf(hi) + page, end) else end;
            if (to <= from or to - from > 64 << 20) continue;
            const a = std.mem.alignBackward(u64, base + from, page);
            std.posix.madvise(@ptrFromInt(a), std.mem.alignForward(u64, base + to - a, page), std.posix.MADV.WILLNEED) catch {};
        }
    }

    /// The live-as-of-`c1` objects of range `g`: `f(ctx, item)`.
    pub fn group(sc: *LiveScan, g: Group, ctx: anytype, comptime f: fn (@TypeOf(ctx), LiveIter.Item) anyerror!void) !void {
        var queued: std.ArrayList(u64) = .empty;
        defer queued.deinit(sc.gpa);
        var ok = false;
        defer {
            sc.acquire();
            if (ok) {
                sc.late.appendSlice(sc.gpa, queued.items) catch sc.failed.store(true, .release);
            } else sc.failed.store(true, .release);
            sc.active -= 1;
            sc.lock.store(false, .release);
        }
        const items = if (g.late) sc.late.items[g.from..g.to] else sc.locs.items[g.from..g.to];
        var wb: Store.WalkBuf = .{};
        defer wb.deinit(sc.gpa);
        try sc.visit(items, g.late, &queued, &wb, ctx, f);
        ok = true;
    }

    /// Part `part` of `parts` of the live set, complete on its own (lane index-fast: a bulk
    /// index build marks parts done one by one): its share of the sorted locations in 64k
    /// ranges, then the older versions its newer records point to, sorted. Any number of
    /// threads may walk distinct parts at once; `next`/`group` must not be used on the same scan.
    pub fn walkPart(sc: *LiveScan, part: u32, parts: u32, ctx: anytype, comptime f: fn (@TypeOf(ctx), LiveIter.Item) anyerror!void) !void {
        const n = sc.locs.items.len;
        const lo = n * part / parts;
        const hi = n * (part + 1) / parts;
        var queued: std.ArrayList(u64) = .empty;
        defer queued.deinit(sc.gpa);
        // this walker's decoded chunk, kept from range to range
        var wb: Store.WalkBuf = .{};
        defer wb.deinit(sc.gpa);
        var i = lo;
        while (i < hi) {
            const to = @min(hi, i + sc.chunk);
            try sc.visit(sc.locs.items[i..to], false, &queued, &wb, ctx, f);
            i = to;
        }
        std.mem.sortUnstable(u64, queued.items, {}, std.sort.asc(u64));
        var late: std.ArrayList(u64) = .empty;
        defer late.deinit(sc.gpa);
        i = 0;
        while (i < queued.items.len) {
            const to = @min(queued.items.len, i + sc.chunk);
            try sc.visit(queued.items[i..to], true, &late, &wb, ctx, f);
            i = to;
        }
    }

    /// The live-as-of-`c1` objects of `items` (live-table values, or with `late` older-version
    /// locations): `f(ctx, item)`; newer records' previous locations go to `queued`. Records
    /// are read through `wb` (the caller's, one per walker), so an item is valid until `f`
    /// returns.
    fn visit(sc: *LiveScan, items: []const u64, late: bool, queued: *std.ArrayList(u64), wb: *Store.WalkBuf, ctx: anytype, comptime f: fn (@TypeOf(ctx), LiveIter.Item) anyerror!void) !void {
        const st = sc.store;
        var snap: Snapshot = .{ .store = st, .c1 = sc.c1, .parity = st.rcu.enter(), .cepoch = st.creaders.enter() };
        defer snap.release();
        if (items.len == 0) return;
        const lo = table.locOf(items[0]);
        const hi = table.locOf(items[items.len - 1]);
        advise(st, lo, hi);
        for (items) |raw| {
            _ = sc.scanned.fetchAdd(1, .monotonic);
            if (late) {
                if (try visibleFrom(&snap, raw, wb)) |o| try f(ctx, o);
                continue;
            }
            const l = table.locOf(raw);
            const rec = st.recordWalk(l, wb, snap.cepoch) catch |e| switch (e) {
                error.NotFound => continue,
                else => return e,
            };
            switch (format.short(rec).kind) {
                .object, .object_c => {
                    const o = try st.objRec(rec);
                    if (raw & table.tomb != 0) {
                        // A tombstone slot naming an object record: resolve by id (HistIter's
                        // rule). Rare, and through the shared cache (`o.id` is a copy).
                        const lat = try snap.latest(&o.id) orelse continue;
                        switch (lat) {
                            .live => |r| try f(ctx, .{ .id = o.id, .version = r.version, .bytes = r.bytes, .stored_digest = r.digest }),
                            .removed => {},
                        }
                    } else if (snap.visible(o.seq)) {
                        try f(ctx, .{ .id = o.id, .version = o.version, .bytes = o.bytes, .stored_digest = if (o.stored_digest) |d| d.* else null });
                    } else if (o.a != 0) try queued.append(sc.gpa, o.a);
                },
                .remove => {
                    const h = format.header(rec);
                    if (!snap.visible(h.seq) and h.a != 0) try queued.append(sc.gpa, h.a);
                },
                else => {},
            }
        }
    }

    /// The object the view sees on the chain starting at `l` (null: removed or none), read
    /// through `wb` (valid until its next use).
    fn visibleFrom(snap: *const Snapshot, start: u64, wb: *Store.WalkBuf) Error!?LiveIter.Item {
        var l = start;
        while (l != 0) {
            const rec = snap.store.recordWalk(l, wb, snap.cepoch) catch |e| switch (e) {
                error.NotFound => return null,
                else => return e,
            };
            switch (format.short(rec).kind) {
                .object, .object_c => {
                    const o = try snap.store.objRec(rec);
                    if (snap.visible(o.seq)) return .{ .id = o.id, .version = o.version, .bytes = o.bytes, .stored_digest = if (o.stored_digest) |d| d.* else null };
                    l = o.a;
                },
                .remove => {
                    const h = format.header(rec);
                    if (snap.visible(h.seq)) return null;
                    l = h.a;
                },
                else => return error.Corrupt,
            }
        }
        return null;
    }
};

// ---------------------------------------------------------------------- recovery helpers

const GroupInfo = struct { len: u64, seq: u64, commit_checksum: u64 };

/// Validates the commit group at `off` of segment `epoch`. Null when anything is off: a bad
/// checksum, a missing commit, a count or chain mismatch, or a commit naming another start.
fn scanGroup(data: []const u8, epoch: u64, off: u64, expect_prev: ?u64) ?GroupInfo {
    if (off > data.len) return null;
    const g = scanGroupRel(data[off..], off, epoch, expect_prev) orelse return null;
    return .{ .len = g.len, .seq = g.seq, .commit_checksum = g.commit_checksum };
}

/// `scanGroup` for the offline converter (convert.zig).
pub fn scanGroupPub(data: []const u8, epoch: u64, off: u64, expect_prev: ?u64) ?GroupInfo {
    return scanGroup(data, epoch, off, expect_prev);
}

const GroupInfoRel = struct { len: u64, seq: u64, commit_checksum: u64, commit_off: u64 };

/// `scanGroup` over `data`, the logical bytes from offset `base` (the group's start) on.
fn scanGroupRel(data: []const u8, base: u64, epoch: u64, expect_prev: ?u64) ?GroupInfoRel {
    if (base % block != 0) return null;
    const off: u64 = 0;
    var p = off;
    var records: u32 = 0;
    var gh: u64 = 0;
    while (true) {
        const l = format.loc(epoch, base + p);
        // A hole (age-out) keeps the dead record's checksum and length: the chain still holds.
        if (p + format.short_len <= data.len and format.short(data[p..]).kind == .hole) {
            const hh = format.short(data[p..]);
            const n = format.lenOf(.hole, hh.size);
            if (p + n > data.len) return null;
            gh = format.chain(gh, hh.checksum);
            records += 1;
            p += n;
            continue;
        }
        const rec = format.validate(data, p, l) catch return null;
        const h = format.short(rec);
        if (h.kind == .commit) {
            if (h.size != @sizeOf(format.CommitFixed)) return null;
            const c = format.fixed(format.CommitFixed, rec);
            if (c.group_start != format.loc(epoch, base) or c.records != records + 1 or c.group_hash != gh or c.epoch != epoch)
                return null;
            if (expect_prev) |ep| if (c.prev_commit != ep) return null;
            const end = std.mem.alignForward(u64, p + format.recordLen(h.size), block);
            if (end > data.len) return null;
            return .{ .len = end - off, .seq = format.header(rec).seq, .commit_checksum = h.checksum, .commit_off = p };
        }
        switch (h.kind) {
            .segment, .checkpoint, .tx, .object, .remove, .object_c, .link, .xref => {},
            else => return null,
        }
        gh = format.chain(gh, h.checksum);
        records += 1;
        p += format.lenOf(h.kind, h.size);
    }
}

/// Structure of a durable group without hashing payloads: walks record headers, and checks the
/// walk against the (fully validated) commit record's record count and checksum chain. A
/// damaged size or kind field derails the walk and fails the chain.
fn walkGroup(data: []const u8, epoch: u64, off: u64) ?struct { commit_off: u64, end: u64 } {
    if (off > data.len) return null;
    const w = walkGroupRel(data[off..], off, epoch) orelse return null;
    return .{ .commit_off = off + w.commit_off, .end = off + w.end };
}

/// `walkGroup` over the logical bytes from offset `base` (the group's start) on; offsets in the
/// result are relative to `data`.
fn walkGroupRel(data: []const u8, base: u64, epoch: u64) ?struct { commit_off: u64, end: u64 } {
    const off: u64 = 0;
    var p = off;
    var records: u32 = 0;
    var gh: u64 = 0;
    while (true) {
        if (p + format.short_len > data.len) return null;
        const h = format.short(data[p..]);
        if (h.kind == .commit) {
            if (p + format.header_len > data.len) return null;
            const rec = format.validate(data, p, format.loc(epoch, base + p)) catch return null;
            if (h.size != @sizeOf(format.CommitFixed)) return null;
            const c = format.fixed(format.CommitFixed, rec);
            if (c.group_start != format.loc(epoch, base) or c.records != records + 1 or c.group_hash != gh) return null;
            const end = std.mem.alignForward(u64, p + format.recordLen(h.size), block);
            if (end > data.len) return null;
            return .{ .commit_off = p, .end = end };
        }
        switch (h.kind) {
            .segment, .checkpoint, .tx, .object, .remove, .object_c, .link, .xref, .hole => {},
            else => return null,
        }
        gh = format.chain(gh, h.checksum);
        records += 1;
        const n = format.lenOf(h.kind, h.size);
        if (p + n > data.len) return null;
        p += n;
    }
}

/// True when a valid commit record exists at or after `from` whose group starts after
/// `break_loc` (a durable group beyond a broken one); with `break_loc` null, any valid commit.
fn findLaterCommit(data: []const u8, epoch: u64, from: u64, break_loc: ?u64) bool {
    var p = from & ~@as(u64, 7);
    while (p + format.header_len <= data.len) : (p += 8) {
        const h = format.header(data[p..]);
        if (h.kind != .commit or h.size != @sizeOf(format.CommitFixed)) continue;
        const rec = format.validate(data, p, format.loc(epoch, p)) catch continue;
        const c = format.fixed(format.CommitFixed, rec);
        if (break_loc == null or c.group_start > break_loc.?) return true;
    }
    return false;
}
