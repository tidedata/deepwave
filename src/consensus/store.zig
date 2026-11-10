//! consensus_core::storage::Store at mainnet-v1.83.1, as a deepwave interface plus two engines.
//! Owner lane: val-consensus-core. Layout: docs/VALIDATOR-DESIGN.md section 6.1.
//!
//! - `MemStore`: tests and the deterministic simulator.
//! - `LogStore`: `<db>/consensus/<epoch>/consensus.log`, an append-only log of checksummed
//!   records (one write group per `write` call, one fdatasync), with in-memory indexes rebuilt on
//!   open: blocks by ref and by (author, round), commits by index, commit votes, commit info, and
//!   finalized commits with their rejected transactions. Same record discipline as src/store
//!   (checksum seeded with the record location, commit record closes a group, torn tail dropped
//!   on recovery). One directory per epoch, deleted after `db_retention_epochs`.
const std = @import("std");
const types = @import("types.zig");
const bcs = @import("bcs");
const Allocator = std.mem.Allocator;
const err = @import("error.zig");
const digest_mod = @import("digest.zig");

pub const CommitInfoEntry = struct { ref: types.CommitRef, info: types.CommitInfo };
pub const FinalizedEntry = struct { ref: types.CommitRef, rejected: []const types.RejectedInBlock };

/// consensus_core::storage::WriteBatch. Written atomically: after a crash either the whole
/// batch is visible or none of it.
pub const WriteBatch = struct {
    blocks: []const types.VerifiedBlock = &.{},
    commits: []const types.TrustedCommit = &.{},
    commit_info: []const CommitInfoEntry = &.{},
    finalized_commits: []const FinalizedEntry = &.{},
};

/// The Store trait. Reads return blocks whose bytes live in the store (zero copy); result arrays
/// are allocated from the caller's arena.
pub const Store = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        write: *const fn (ctx: *anyopaque, batch: *const WriteBatch) err.Error!void,
        read_blocks: *const fn (ctx: *anyopaque, refs: []const types.BlockRef, out: []?types.VerifiedBlock) err.Error!void,
        contains_blocks: *const fn (ctx: *anyopaque, refs: []const types.BlockRef, out: []bool) err.Error!void,
        /// Blocks of `author` with start_round <= round < end_round, at most `limit`, ascending.
        scan_blocks_by_author: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, author: types.AuthorityIndex, start_round: types.Round, end_round: types.Round, limit: usize) err.Error![]types.VerifiedBlock,
        /// The last `num_of_rounds` blocks of `author` at or before `before_round` (null = all), ascending.
        scan_last_blocks_by_author: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, author: types.AuthorityIndex, num_of_rounds: u64, before_round: ?types.Round) err.Error![]types.VerifiedBlock,
        read_last_commit: *const fn (ctx: *anyopaque) err.Error!?types.TrustedCommit,
        /// Commits with range.start <= index < range.end_exclusive, ascending.
        scan_commits: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, range: types.CommitRange) err.Error![]types.TrustedCommit,
        read_commit_votes: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, index: types.CommitIndex) err.Error![]types.BlockRef,
        read_last_commit_info: *const fn (ctx: *anyopaque) err.Error!?CommitInfoEntry,
        read_last_finalized_commit: *const fn (ctx: *anyopaque) err.Error!?types.CommitRef,
        read_rejected_transactions: *const fn (ctx: *anyopaque, commit: types.CommitRef) err.Error!?[]const types.RejectedInBlock,
    };

    pub fn write(s: Store, batch: *const WriteBatch) err.Error!void {
        return s.vtable.write(s.ctx, batch);
    }
    pub fn readBlocks(s: Store, refs: []const types.BlockRef, out: []?types.VerifiedBlock) err.Error!void {
        return s.vtable.read_blocks(s.ctx, refs, out);
    }
    pub fn containsBlocks(s: Store, refs: []const types.BlockRef, out: []bool) err.Error!void {
        return s.vtable.contains_blocks(s.ctx, refs, out);
    }
    pub fn scanBlocksByAuthor(s: Store, arena: std.mem.Allocator, author: types.AuthorityIndex, start_round: types.Round, end_round: types.Round, limit: usize) err.Error![]types.VerifiedBlock {
        return s.vtable.scan_blocks_by_author(s.ctx, arena, author, start_round, end_round, limit);
    }
    pub fn scanLastBlocksByAuthor(s: Store, arena: std.mem.Allocator, author: types.AuthorityIndex, num_of_rounds: u64, before_round: ?types.Round) err.Error![]types.VerifiedBlock {
        return s.vtable.scan_last_blocks_by_author(s.ctx, arena, author, num_of_rounds, before_round);
    }
    pub fn readLastCommit(s: Store) err.Error!?types.TrustedCommit {
        return s.vtable.read_last_commit(s.ctx);
    }
    pub fn scanCommits(s: Store, arena: std.mem.Allocator, range: types.CommitRange) err.Error![]types.TrustedCommit {
        return s.vtable.scan_commits(s.ctx, arena, range);
    }
    pub fn readCommitVotes(s: Store, arena: std.mem.Allocator, index: types.CommitIndex) err.Error![]types.BlockRef {
        return s.vtable.read_commit_votes(s.ctx, arena, index);
    }
    pub fn readLastCommitInfo(s: Store) err.Error!?CommitInfoEntry {
        return s.vtable.read_last_commit_info(s.ctx);
    }
    pub fn readLastFinalizedCommit(s: Store) err.Error!?types.CommitRef {
        return s.vtable.read_last_finalized_commit(s.ctx);
    }
    pub fn readRejectedTransactions(s: Store, commit: types.CommitRef) err.Error!?[]const types.RejectedInBlock {
        return s.vtable.read_rejected_transactions(s.ctx, commit);
    }
};

fn refLess(_: void, a: types.BlockRef, b: types.BlockRef) bool {
    return a.order(b) == .lt;
}
/// (author, round, digest) order of Rust's `digests_by_authorities`.
fn authorLess(_: void, a: types.BlockRef, b: types.BlockRef) bool {
    if (a.author != b.author) return a.author < b.author;
    if (a.round != b.round) return a.round < b.round;
    return std.mem.order(u8, &a.digest, &b.digest) == .lt;
}
fn commitLess(_: void, a: types.CommitRef, b: types.CommitRef) bool {
    if (a.index != b.index) return a.index < b.index;
    return std.mem.order(u8, &a.digest, &b.digest) == .lt;
}

const BlockMap = std.HashMapUnmanaged(types.BlockRef, types.VerifiedBlock, RefContext, 80);
pub const RefContext = struct {
    pub fn hash(_: RefContext, r: types.BlockRef) u64 {
        return std.mem.readInt(u64, r.digest[0..8], .little) ^ (@as(u64, r.round) *% 0x9e3779b97f4a7c15) ^ r.author;
    }
    pub fn eql(_: RefContext, a: types.BlockRef, b: types.BlockRef) bool {
        return a.eql(b);
    }
};

/// Inserts `item` into the sorted list `list`, ignoring exact duplicates.
fn sortedInsert(comptime T: type, gpa: std.mem.Allocator, list: *std.ArrayList(T), item: T, comptime less: fn (void, T, T) bool) !void {
    const pos = std.sort.lowerBound(T, list.items, item, struct {
        fn cmp(it: T, other: T) std.math.Order {
            if (less({}, it, other)) return .lt;
            if (less({}, other, it)) return .gt;
            return .eq;
        }
    }.cmp);
    if (pos < list.items.len and !less({}, item, list.items[pos]) and !less({}, list.items[pos], item)) return;
    try list.insert(gpa, pos, item);
}

const VoteKey = struct { index: types.CommitIndex, digest: types.CommitDigest, block: types.BlockRef };
fn voteLess(_: void, a: VoteKey, b: VoteKey) bool {
    if (a.index != b.index) return a.index < b.index;
    const d = std.mem.order(u8, &a.digest, &b.digest);
    if (d != .eq) return d == .lt;
    return a.block.order(b.block) == .lt;
}

/// In-memory Store for tests and the deterministic simulator (`storage/mem_store.rs`). Everything
/// stored is deep-copied into the store's own arena, never freed before `deinit`.
pub const MemStore = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    blocks: BlockMap = .empty,
    /// Per author, the block refs in (round, digest) order: inserts land at or near the end of
    /// one author's list instead of shifting every later author's refs.
    by_author: std.ArrayList(std.ArrayList(types.BlockRef)) = .empty,
    commits: std.ArrayList(types.TrustedCommit) = .empty,
    /// Commit votes by commit index, each list in (digest, block) order.
    votes: std.AutoHashMapUnmanaged(types.CommitIndex, std.ArrayList(VoteKey)) = .empty,
    infos: std.ArrayList(CommitInfoEntry) = .empty,
    finalized: std.ArrayList(FinalizedEntry) = .empty,
    /// Evictable mode (LogStore): each block lives in its own arena so `evictBelow` can free it.
    /// Blocks returned by reads stay valid until their round falls below the eviction cutoff.
    evictable: bool = false,
    boxes: std.HashMapUnmanaged(types.BlockRef, *std.heap.ArenaAllocator, RefContext, 80) = .empty,
    max_round: types.Round = 0,

    pub fn init(gpa: std.mem.Allocator) MemStore {
        return .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa) };
    }
    pub fn deinit(self: *MemStore) void {
        self.blocks.deinit(self.gpa);
        for (self.by_author.items) |*l| l.deinit(self.gpa);
        self.by_author.deinit(self.gpa);
        self.commits.deinit(self.gpa);
        var vit = self.votes.valueIterator();
        while (vit.next()) |l| l.deinit(self.gpa);
        self.votes.deinit(self.gpa);
        self.infos.deinit(self.gpa);
        self.finalized.deinit(self.gpa);
        var it = self.boxes.valueIterator();
        while (it.next()) |b| {
            b.*.deinit();
            self.gpa.destroy(b.*);
        }
        self.boxes.deinit(self.gpa);
        self.arena.deinit();
    }

    /// Drops blocks (and the commit votes they cast) of rounds below `cutoff`; evictable mode only.
    pub fn evictBelow(self: *MemStore, cutoff: types.Round) void {
        if (!self.evictable) return;
        var w: usize = 0;
        for (self.by_author.items) |*list| {
            w = 0;
            for (list.items) |r| {
                if (r.round < cutoff) {
                    _ = self.blocks.remove(r);
                    if (self.boxes.fetchRemove(r)) |kv| {
                        kv.value.deinit();
                        self.gpa.destroy(kv.value);
                    }
                } else {
                    list.items[w] = r;
                    w += 1;
                }
            }
            list.shrinkRetainingCapacity(w);
        }
        var vit = self.votes.valueIterator();
        while (vit.next()) |list| {
            w = 0;
            for (list.items) |v| {
                if (v.block.round >= cutoff) {
                    list.items[w] = v;
                    w += 1;
                }
            }
            list.shrinkRetainingCapacity(w);
        }
    }

    fn authorList(self: *MemStore, author: types.AuthorityIndex) !*std.ArrayList(types.BlockRef) {
        while (self.by_author.items.len <= author) try self.by_author.append(self.gpa, .empty);
        return &self.by_author.items[author];
    }

    fn hasCommit(self: *const MemStore, index: types.CommitIndex, digest: types.CommitDigest) bool {
        for (self.commits.items) |c| if (c.commit.index() == index and std.mem.eql(u8, &c.digest, &digest)) return true;
        return false;
    }

    pub fn store(self: *MemStore) Store {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub const vtable: Store.VTable = .{
        .write = writeImpl,
        .read_blocks = readBlocksImpl,
        .contains_blocks = containsBlocksImpl,
        .scan_blocks_by_author = scanByAuthorImpl,
        .scan_last_blocks_by_author = scanLastImpl,
        .read_last_commit = readLastCommitImpl,
        .scan_commits = scanCommitsImpl,
        .read_commit_votes = readVotesImpl,
        .read_last_commit_info = readLastInfoImpl,
        .read_last_finalized_commit = readLastFinalizedImpl,
        .read_rejected_transactions = readRejectedImpl,
    };

    fn self_(ctx: *anyopaque) *MemStore {
        return @ptrCast(@alignCast(ctx));
    }

    pub fn writeImpl(ctx: *anyopaque, batch: *const WriteBatch) err.Error!void {
        const self = self_(ctx);
        const a = self.arena.allocator();
        for (batch.blocks) |b| {
            const ref = b.reference();
            if (self.blocks.contains(ref)) continue;
            var copy: types.VerifiedBlock = undefined;
            if (self.evictable) {
                const box = self.gpa.create(std.heap.ArenaAllocator) catch return error.OutOfMemory;
                box.* = std.heap.ArenaAllocator.init(self.gpa);
                copy = digest_mod.cloneVerified(box.allocator(), &b) catch |e| {
                    box.deinit();
                    self.gpa.destroy(box);
                    return e;
                };
                self.boxes.put(self.gpa, ref, box) catch {
                    box.deinit();
                    self.gpa.destroy(box);
                    return error.OutOfMemory;
                };
            } else copy = try digest_mod.cloneVerified(a, &b);
            if (ref.round > self.max_round) self.max_round = ref.round;
            self.blocks.put(self.gpa, ref, copy) catch return error.OutOfMemory;
            const list = self.authorList(ref.author) catch return error.OutOfMemory;
            sortedInsert(types.BlockRef, self.gpa, list, ref, authorLess) catch return error.OutOfMemory;
            for (copy.block.inner.commitVotes()) |v| {
                const gop = self.votes.getOrPut(self.gpa, v.index) catch return error.OutOfMemory;
                if (!gop.found_existing) gop.value_ptr.* = .empty;
                sortedInsert(VoteKey, self.gpa, gop.value_ptr, .{ .index = v.index, .digest = v.digest, .block = ref }, voteLess) catch return error.OutOfMemory;
            }
        }
        for (batch.commits) |c| {
            const ser = a.dupe(u8, c.serialized) catch return error.OutOfMemory;
            const dec = bcs.decode(types.Commit, a, ser) catch return error.SerializationFailure;
            const tc: types.TrustedCommit = .{ .commit = dec, .serialized = ser, .digest = c.digest };
            const pos = std.sort.lowerBound(types.TrustedCommit, self.commits.items, tc, struct {
                fn cmp(it: types.TrustedCommit, o: types.TrustedCommit) std.math.Order {
                    if (it.commit.index() != o.commit.index()) return std.math.order(it.commit.index(), o.commit.index());
                    return std.mem.order(u8, &it.digest, &o.digest);
                }
            }.cmp);
            if (pos < self.commits.items.len and self.commits.items[pos].commit.index() == tc.commit.index() and std.mem.eql(u8, &self.commits.items[pos].digest, &tc.digest)) continue;
            self.commits.insert(self.gpa, pos, tc) catch return error.OutOfMemory;
        }
        for (batch.commit_info) |e| {
            const info: types.CommitInfo = .{
                .committed_rounds = a.dupe(types.Round, e.info.committed_rounds) catch return error.OutOfMemory,
                .reputation_scores = .{
                    .scores_per_authority = a.dupe(u64, e.info.reputation_scores.scores_per_authority) catch return error.OutOfMemory,
                    .commit_range = e.info.reputation_scores.commit_range,
                },
            };
            const entry: CommitInfoEntry = .{ .ref = e.ref, .info = info };
            const pos = std.sort.lowerBound(CommitInfoEntry, self.infos.items, entry, struct {
                fn cmp(it: CommitInfoEntry, o: CommitInfoEntry) std.math.Order {
                    if (it.ref.index != o.ref.index) return std.math.order(it.ref.index, o.ref.index);
                    return std.mem.order(u8, &it.ref.digest, &o.ref.digest);
                }
            }.cmp);
            if (pos < self.infos.items.len and commitLess({}, e.ref, self.infos.items[pos].ref) == false and commitLess({}, self.infos.items[pos].ref, e.ref) == false) {
                self.infos.items[pos] = entry;
            } else self.infos.insert(self.gpa, pos, entry) catch return error.OutOfMemory;
        }
        for (batch.finalized_commits) |f| {
            const rej = a.alloc(types.RejectedInBlock, f.rejected.len) catch return error.OutOfMemory;
            for (rej, f.rejected) |*o, i| o.* = .{ .block = i.block, .indices = a.dupe(types.TransactionIndex, i.indices) catch return error.OutOfMemory };
            const entry: FinalizedEntry = .{ .ref = f.ref, .rejected = rej };
            const pos = std.sort.lowerBound(FinalizedEntry, self.finalized.items, entry, struct {
                fn cmp(it: FinalizedEntry, o: FinalizedEntry) std.math.Order {
                    if (it.ref.index != o.ref.index) return std.math.order(it.ref.index, o.ref.index);
                    return std.mem.order(u8, &it.ref.digest, &o.ref.digest);
                }
            }.cmp);
            if (pos < self.finalized.items.len and !commitLess({}, f.ref, self.finalized.items[pos].ref) and !commitLess({}, self.finalized.items[pos].ref, f.ref)) {
                self.finalized.items[pos] = entry;
            } else self.finalized.insert(self.gpa, pos, entry) catch return error.OutOfMemory;
        }
    }

    fn readBlocksImpl(ctx: *anyopaque, refs: []const types.BlockRef, out: []?types.VerifiedBlock) err.Error!void {
        const self = self_(ctx);
        for (refs, out[0..refs.len]) |r, *o| o.* = self.blocks.get(r);
    }
    fn containsBlocksImpl(ctx: *anyopaque, refs: []const types.BlockRef, out: []bool) err.Error!void {
        const self = self_(ctx);
        for (refs, out[0..refs.len]) |r, *o| o.* = self.blocks.contains(r);
    }
    fn scanByAuthorImpl(ctx: *anyopaque, arena: std.mem.Allocator, author: types.AuthorityIndex, start_round: types.Round, end_round: types.Round, limit: usize) err.Error![]types.VerifiedBlock {
        const self = self_(ctx);
        var out: std.ArrayList(types.VerifiedBlock) = .empty;
        if (author >= self.by_author.items.len) return out.items;
        for (self.by_author.items[author].items) |r| {
            if (r.round < start_round) continue;
            if (r.round >= end_round or out.items.len >= limit) break;
            out.append(arena, self.blocks.get(r).?) catch return error.OutOfMemory;
        }
        return out.items;
    }
    fn scanLastImpl(ctx: *anyopaque, arena: std.mem.Allocator, author: types.AuthorityIndex, num_of_rounds: u64, before_round: ?types.Round) err.Error![]types.VerifiedBlock {
        const self = self_(ctx);
        const before = before_round orelse std.math.maxInt(types.Round);
        var picked: std.ArrayList(types.BlockRef) = .empty;
        const list: []const types.BlockRef = if (author < self.by_author.items.len) self.by_author.items[author].items else &.{};
        var i = list.len;
        while (i > 0 and picked.items.len < num_of_rounds) {
            i -= 1;
            const r = list[i];
            if (r.round > before) continue;
            picked.append(arena, r) catch return error.OutOfMemory;
        }
        const out = arena.alloc(types.VerifiedBlock, picked.items.len) catch return error.OutOfMemory;
        for (out, 0..) |*o, k| o.* = self.blocks.get(picked.items[picked.items.len - 1 - k]).?;
        return out;
    }
    fn readLastCommitImpl(ctx: *anyopaque) err.Error!?types.TrustedCommit {
        const self = self_(ctx);
        if (self.commits.items.len == 0) return null;
        return self.commits.items[self.commits.items.len - 1];
    }
    fn scanCommitsImpl(ctx: *anyopaque, arena: std.mem.Allocator, range: types.CommitRange) err.Error![]types.TrustedCommit {
        const self = self_(ctx);
        var out: std.ArrayList(types.TrustedCommit) = .empty;
        for (self.commits.items) |c| {
            const idx = c.commit.index();
            if (idx >= range.start and idx < range.end_exclusive) out.append(arena, c) catch return error.OutOfMemory;
        }
        return out.items;
    }
    fn readVotesImpl(ctx: *anyopaque, arena: std.mem.Allocator, index: types.CommitIndex) err.Error![]types.BlockRef {
        const self = self_(ctx);
        var out: std.ArrayList(types.BlockRef) = .empty;
        if (self.votes.get(index)) |list| for (list.items) |v| out.append(arena, v.block) catch return error.OutOfMemory;
        return out.items;
    }
    fn readLastInfoImpl(ctx: *anyopaque) err.Error!?CommitInfoEntry {
        const self = self_(ctx);
        if (self.infos.items.len == 0) return null;
        return self.infos.items[self.infos.items.len - 1];
    }
    fn readLastFinalizedImpl(ctx: *anyopaque) err.Error!?types.CommitRef {
        const self = self_(ctx);
        if (self.finalized.items.len == 0) return null;
        return self.finalized.items[self.finalized.items.len - 1].ref;
    }
    fn readRejectedImpl(ctx: *anyopaque, commit: types.CommitRef) err.Error!?[]const types.RejectedInBlock {
        const self = self_(ctx);
        for (self.finalized.items) |f| if (f.ref.index == commit.index and std.mem.eql(u8, &f.ref.digest, &commit.digest)) return f.rejected;
        return null;
    }
};

/// Durable store: `<db>/consensus/<epoch>/consensus.log`, an append-only log of checksummed records
/// in front of a MemStore that serves reads. One `write` is one group: its records and a closing
/// commit record go out in a single positional write and one fsync before the group becomes
/// visible. Recovery streams the log (never loading it whole), keeps groups up to the last intact
/// commit record and truncates a torn tail. Same discipline as src/store (checksum seeded with the
/// record location, commit record closes a group, torn tails dropped). One directory per epoch,
/// deleted by the owner after `db_retention_epochs`.
///
/// Memory is bounded: blocks live in per-block arenas and are evicted once their round is more
/// than `retain_rounds` below the highest round seen (must exceed the DagState's cached rounds plus
/// the GC depth; blocks handed out by reads stay valid until then). Every block ever written keeps a
/// 16-byte entry (hash of its ref -> log offset) so `readBlockFromDisk` can serve evicted blocks
/// (peer catch-up fetches). Commits, commit info and finalized commits stay resident (refs only).
/// The log itself is not compacted: it is deleted with its epoch directory.
///
/// Record: `u32 len` `u64 checksum` `u8 kind` payload (len counts kind + payload); checksum =
/// Wyhash(seed = file offset of the record, kind ++ payload). Kinds: 1 block (serialized
/// SignedBlock), 2 commit (serialized Commit), 3 commit info (BCS CommitRef ++ BCS CommitInfo),
/// 4 finalized commit (BCS CommitRef ++ BCS Vec<RejectedInBlock>), 255 group commit.
pub const LogStore = struct {
    gpa: Allocator,
    io: std.Io,
    file: std.Io.File,
    end: u64,
    mem: MemStore,
    retain_rounds: u32,
    evicted_through: types.Round = 0,
    /// refHash -> offset of the block record (its header start).
    disk_index: std.AutoHashMapUnmanaged(u64, u64) = .empty,

    pub const Options = struct {
        /// `<db>/consensus/<epoch>` (created if missing).
        dir_path: []const u8,
        epoch: types.Epoch,
        /// Blocks older than the highest round seen minus this are evicted from memory.
        retain_rounds: u32 = 4096,
    };

    const magic = "ZUICONS1";
    const header_len = 16;
    const rec_header = 4 + 8;
    /// A record longer than this cannot be a real one (blocks are bounded far below); treated as a
    /// torn tail.
    const max_record_len = 128 << 20;
    /// Eviction runs when the cutoff advanced by at least this many rounds (amortizes the filter).
    const evict_step = 64;
    const Kind = enum(u8) { block = 1, commit = 2, commit_info = 3, finalized = 4, group_commit = 255 };

    fn refKey(r: types.BlockRef) u64 {
        var h = std.hash.Wyhash.init(0x5a55494b);
        h.update(std.mem.asBytes(&r.round));
        h.update(std.mem.asBytes(&r.author));
        h.update(&r.digest);
        return h.final();
    }

    pub fn open(gpa: Allocator, io: std.Io, options: Options) err.Error!*LogStore {
        const dir = std.Io.Dir.cwd();
        dir.createDirPath(io, options.dir_path) catch return error.StoreIo;
        var d = dir.openDir(io, options.dir_path, .{}) catch return error.StoreIo;
        defer d.close(io);
        const file = d.createFile(io, "consensus.log", .{ .read = true, .truncate = false }) catch return error.StoreIo;
        errdefer file.close(io);

        const self = gpa.create(LogStore) catch return error.OutOfMemory;
        errdefer gpa.destroy(self);
        self.* = .{ .gpa = gpa, .io = io, .file = file, .end = 0, .mem = MemStore.init(gpa), .retain_rounds = options.retain_rounds };
        self.mem.evictable = true;
        errdefer self.mem.deinit();
        errdefer self.disk_index.deinit(gpa);

        const len = file.length(io) catch return error.StoreIo;
        if (len == 0) {
            var h: [header_len]u8 = undefined;
            @memcpy(h[0..8], magic);
            std.mem.writeInt(u64, h[8..16], options.epoch, .little);
            file.writePositionalAll(io, &h, 0) catch return error.StoreIo;
            file.sync(io) catch return error.StoreIo;
            self.end = header_len;
            return self;
        }
        if (len < header_len) return error.StoreCorrupt;
        var h: [header_len]u8 = undefined;
        const got = file.readPositionalAll(io, &h, 0) catch return error.StoreIo;
        if (got != header_len or !std.mem.eql(u8, h[0..8], magic)) return error.StoreCorrupt;
        if (std.mem.readInt(u64, h[8..16], .little) != options.epoch) return error.StoreCorrupt;
        // OutOfMemory and decode failures of checksum-valid records propagate without truncating.
        const good = try self.recoverFrom(len);
        if (good < len) {
            file.setLength(io, good) catch return error.StoreIo;
            file.sync(io) catch return error.StoreIo;
        }
        self.end = good;
        return self;
    }

    pub fn close(self: *LogStore) void {
        self.file.close(self.io);
        self.disk_index.deinit(self.gpa);
        self.mem.deinit();
        self.gpa.destroy(self);
    }

    pub fn store(self: *LogStore) Store {
        return .{ .ctx = &self.mem, .vtable = &log_vtable };
    }

    const log_vtable: Store.VTable = blk: {
        var v = MemStore.vtable;
        v.write = logWrite;
        break :blk v;
    };

    /// A block (resident or evicted) with its bytes copied into `arena`; null when unknown.
    pub fn readBlockFromDisk(self: *LogStore, arena: Allocator, ref: types.BlockRef) err.Error!?types.VerifiedBlock {
        if (self.mem.blocks.get(ref)) |b| return try digest_mod.cloneVerified(arena, &b);
        const off = self.disk_index.get(refKey(ref)) orelse return null;
        var hdr: [rec_header + 1]u8 = undefined;
        if ((self.file.readPositionalAll(self.io, &hdr, off) catch return error.StoreIo) != hdr.len) return error.StoreCorrupt;
        const len = std.mem.readInt(u32, hdr[0..4], .little);
        if (len < 1 or len > max_record_len or hdr[rec_header] != @intFromEnum(Kind.block)) return error.StoreCorrupt;
        const body = arena.alloc(u8, len) catch return error.OutOfMemory;
        if ((self.file.readPositionalAll(self.io, body, off + rec_header) catch return error.StoreIo) != len) return error.StoreCorrupt;
        if (std.hash.Wyhash.hash(off, body) != std.mem.readInt(u64, hdr[4..12], .little)) return error.StoreCorrupt;
        const vb = try digest_mod.decodeVerifiedUnchecked(arena, body[1..]);
        if (!vb.reference().eql(ref)) return null; // hash collision on the index
        return vb;
    }

    fn maybeEvict(self: *LogStore) void {
        const top = self.mem.max_round;
        if (top <= self.retain_rounds) return;
        const cutoff = top - self.retain_rounds;
        if (cutoff < self.evicted_through + evict_step) return;
        self.mem.evictBelow(cutoff);
        self.evicted_through = cutoff;
    }

    fn isOom(e: anytype) bool {
        return std.mem.eql(u8, @errorName(e), "OutOfMemory");
    }

    /// Streams intact groups into the MemStore; returns the length of the intact prefix. Only a
    /// short read, a bad checksum, a bad length or an unknown kind mark the torn tail; a record that
    /// passes its checksum but does not decode is `StoreCorrupt`, and OutOfMemory is returned as is.
    fn recoverFrom(self: *LogStore, file_len: u64) err.Error!u64 {
        var group = std.heap.ArenaAllocator.init(self.gpa);
        defer group.deinit();
        const a = group.allocator();
        var pos: u64 = header_len;
        var good: u64 = header_len;

        var body_buf: std.ArrayList(u8) = .empty;
        defer body_buf.deinit(self.gpa);

        var blocks: std.ArrayList(types.VerifiedBlock) = .empty;
        var block_offs: std.ArrayList(u64) = .empty;
        var commits: std.ArrayList(types.TrustedCommit) = .empty;
        var infos: std.ArrayList(CommitInfoEntry) = .empty;
        var fins: std.ArrayList(FinalizedEntry) = .empty;
        while (pos + rec_header + 1 <= file_len) {
            var hdr: [rec_header]u8 = undefined;
            if ((self.file.readPositionalAll(self.io, &hdr, pos) catch return error.StoreIo) != rec_header) break;
            const len = std.mem.readInt(u32, hdr[0..4], .little);
            const sum = std.mem.readInt(u64, hdr[4..12], .little);
            if (len < 1 or len > max_record_len or pos + rec_header + len > file_len) break;
            body_buf.resize(self.gpa, len) catch return error.OutOfMemory;
            const body = body_buf.items;
            if ((self.file.readPositionalAll(self.io, body, pos + rec_header) catch return error.StoreIo) != len) break;
            if (std.hash.Wyhash.hash(pos, body) != sum) break;
            const kind = std.enums.fromInt(Kind, body[0]) orelse break;
            const payload = a.dupe(u8, body[1..]) catch return error.OutOfMemory;
            switch (kind) {
                .block => {
                    const vb = digest_mod.decodeVerifiedUnchecked(a, payload) catch |e| return if (isOom(e)) error.OutOfMemory else error.StoreCorrupt;
                    blocks.append(a, vb) catch return error.OutOfMemory;
                    block_offs.append(a, pos) catch return error.OutOfMemory;
                },
                .commit => {
                    const c = bcs.decode(types.Commit, a, payload) catch |e| return if (isOom(e)) error.OutOfMemory else error.StoreCorrupt;
                    commits.append(a, .{ .commit = c, .serialized = payload, .digest = digest_mod.commitDigest(payload) }) catch return error.OutOfMemory;
                },
                .commit_info => {
                    var r = bcs.Reader.init(payload);
                    const ref = bcs.decodeFrom(types.CommitRef, a, &r) catch |e| return if (isOom(e)) error.OutOfMemory else error.StoreCorrupt;
                    const info = bcs.decodeFrom(types.CommitInfo, a, &r) catch |e| return if (isOom(e)) error.OutOfMemory else error.StoreCorrupt;
                    infos.append(a, .{ .ref = ref, .info = info }) catch return error.OutOfMemory;
                },
                .finalized => {
                    var r = bcs.Reader.init(payload);
                    const ref = bcs.decodeFrom(types.CommitRef, a, &r) catch |e| return if (isOom(e)) error.OutOfMemory else error.StoreCorrupt;
                    const rej = bcs.decodeFrom([]const types.RejectedInBlock, a, &r) catch |e| return if (isOom(e)) error.OutOfMemory else error.StoreCorrupt;
                    fins.append(a, .{ .ref = ref, .rejected = rej }) catch return error.OutOfMemory;
                },
                .group_commit => {
                    const batch: WriteBatch = .{ .blocks = blocks.items, .commits = commits.items, .commit_info = infos.items, .finalized_commits = fins.items };
                    try MemStore.writeImpl(&self.mem, &batch);
                    for (blocks.items, block_offs.items) |b, off| self.disk_index.put(self.gpa, refKey(b.reference()), off) catch return error.OutOfMemory;
                    self.maybeEvict();
                    blocks = .empty;
                    block_offs = .empty;
                    commits = .empty;
                    infos = .empty;
                    fins = .empty;
                    _ = group.reset(.retain_capacity);
                    good = pos + rec_header + len;
                },
            }
            pos += rec_header + len;
        }
        return good;
    }

    fn putRecord(w: *std.ArrayList(u8), gpa: Allocator, base: u64, kind: Kind, parts: []const []const u8) Allocator.Error!void {
        var n: usize = 1;
        for (parts) |p| n += p.len;
        const start = w.items.len;
        try w.appendNTimes(gpa, 0, rec_header);
        try w.append(gpa, @intFromEnum(kind));
        for (parts) |p| try w.appendSlice(gpa, p);
        const body = w.items[start + rec_header ..];
        std.mem.writeInt(u32, w.items[start..][0..4], @intCast(n), .little);
        std.mem.writeInt(u64, w.items[start + 4 ..][0..8], std.hash.Wyhash.hash(base + start, body), .little);
    }

    fn logWrite(ctx: *anyopaque, batch: *const WriteBatch) err.Error!void {
        const m: *MemStore = @ptrCast(@alignCast(ctx));
        const self: *LogStore = @fieldParentPtr("mem", m);
        const gpa = self.gpa;
        var w: std.ArrayList(u8) = .empty;
        defer w.deinit(gpa);
        var offs: std.ArrayList(struct { key: u64, off: u64 }) = .empty;
        defer offs.deinit(gpa);
        var any = false;
        for (batch.blocks) |b| {
            const ref = b.reference();
            if (self.mem.blocks.contains(ref) or self.disk_index.contains(refKey(ref))) continue;
            offs.append(gpa, .{ .key = refKey(ref), .off = self.end + w.items.len }) catch return error.OutOfMemory;
            putRecord(&w, gpa, self.end, .block, &.{b.serialized}) catch return error.OutOfMemory;
            any = true;
        }
        for (batch.commits) |c| {
            // Recovery re-submits stored commits; do not append them again.
            if (self.mem.hasCommit(c.commit.index(), c.digest)) continue;
            putRecord(&w, gpa, self.end, .commit, &.{c.serialized}) catch return error.OutOfMemory;
            any = true;
        }
        for (batch.commit_info) |e| {
            const r = bcs.encodeAlloc(types.CommitRef, gpa, &e.ref) catch return error.OutOfMemory;
            defer gpa.free(r);
            const i = bcs.encodeAlloc(types.CommitInfo, gpa, &e.info) catch return error.OutOfMemory;
            defer gpa.free(i);
            putRecord(&w, gpa, self.end, .commit_info, &.{ r, i }) catch return error.OutOfMemory;
            any = true;
        }
        for (batch.finalized_commits) |f| {
            const r = bcs.encodeAlloc(types.CommitRef, gpa, &f.ref) catch return error.OutOfMemory;
            defer gpa.free(r);
            const rejected: []const types.RejectedInBlock = f.rejected;
            const i = bcs.encodeAlloc([]const types.RejectedInBlock, gpa, &rejected) catch return error.OutOfMemory;
            defer gpa.free(i);
            putRecord(&w, gpa, self.end, .finalized, &.{ r, i }) catch return error.OutOfMemory;
            any = true;
        }
        if (!any) return;
        putRecord(&w, gpa, self.end, .group_commit, &.{}) catch return error.OutOfMemory;
        self.file.writePositionalAll(self.io, w.items, self.end) catch return error.StoreIo;
        self.file.sync(self.io) catch return error.StoreIo;
        self.end += w.items.len;
        try MemStore.writeImpl(&self.mem, batch);
        for (offs.items) |o| self.disk_index.put(gpa, o.key, o.off) catch return error.OutOfMemory;
        self.maybeEvict();
    }
};

test "LogStore: groups survive reopen, a torn tail is dropped" {
    const test_dag = @import("test_dag.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/consensus/0", .{tmp.sub_path});

    var stakes = test_dag.Fixture.equalStakes(4);
    const f = try test_dag.Fixture.init(gpa, .{ .stakes = &stakes });
    defer f.deinit();
    _ = try f.fullLayers(1, 3, f.genesisRefs());

    // Collect the DAG's blocks as VerifiedBlocks.
    var blocks: std.ArrayList(types.VerifiedBlock) = .empty;
    defer blocks.deinit(gpa);
    for (f.dag.order.items) |r| try blocks.append(gpa, f.dag.getBlock(r).?.*);

    {
        const ls = try LogStore.open(gpa, io, .{ .dir_path = path, .epoch = 0 });
        defer ls.close();
        const s = ls.store();
        try s.write(&.{ .blocks = blocks.items[0..4] });
        try s.write(&.{ .blocks = blocks.items[4..8] });
        try s.write(&.{ .blocks = blocks.items[8..12] });
    }
    {
        const ls = try LogStore.open(gpa, io, .{ .dir_path = path, .epoch = 0 });
        defer ls.close();
        var out: [12]bool = undefined;
        var refs: [12]types.BlockRef = undefined;
        for (&refs, blocks.items) |*r, b| r.* = b.reference();
        try ls.store().containsBlocks(&refs, &out);
        for (out) |o| try std.testing.expect(o);
        {
            var tmp_arena = std.heap.ArenaAllocator.init(gpa);
            defer tmp_arena.deinit();
            const got = (try ls.readBlockFromDisk(tmp_arena.allocator(), refs[5])).?;
            try std.testing.expect(got.reference().eql(refs[5]));
            // Evicted blocks are served from the log through the offset index.
            ls.mem.evictBelow(std.math.maxInt(types.Round));
            const again = (try ls.readBlockFromDisk(tmp_arena.allocator(), refs[7])).?;
            try std.testing.expect(again.reference().eql(refs[7]));
            // Re-seed memory for the torn-tail checks below.
        }
        // Tear the last group: cut 5 bytes off the file.
        const len = try ls.file.length(io);
        try ls.file.setLength(io, len - 5);
    }
    {
        const ls = try LogStore.open(gpa, io, .{ .dir_path = path, .epoch = 0 });
        defer ls.close();
        var out: [12]bool = undefined;
        var refs: [12]types.BlockRef = undefined;
        for (&refs, blocks.items) |*r, b| r.* = b.reference();
        try ls.store().containsBlocks(&refs, &out);
        for (out[0..8]) |o| try std.testing.expect(o);
        for (out[8..]) |o| try std.testing.expect(!o);
        // The file was truncated to the intact prefix and accepts new groups.
        try ls.store().write(&.{ .blocks = blocks.items[8..12] });
    }
    {
        const ls = try LogStore.open(gpa, io, .{ .dir_path = path, .epoch = 0 });
        defer ls.close();
        var out: [12]bool = undefined;
        var refs: [12]types.BlockRef = undefined;
        for (&refs, blocks.items) |*r, b| r.* = b.reference();
        try ls.store().containsBlocks(&refs, &out);
        for (out) |o| try std.testing.expect(o);
    }
}
