//! CheckpointAggregator and CheckpointSignatureAggregator (sui-core `checkpoints/mod.rs` and
//! `stake_aggregator.rs`, 1.83.1): collect the CheckpointSignatureV2 messages that consensus
//! sequenced, and certify the checkpoint built locally once validators holding a strong quorum
//! (2f+1 stake) signed *its* digest.
//!
//! Faithful points:
//!  - Signatures are counted per summary digest (`MultiStakeAggregator`); a repeated signer is
//!    ignored, a second different signature of one signer under the same digest is ignored too.
//!  - Nothing is verified until a digest group reaches quorum stake; then the aggregate is
//!    verified against the LOCAL summary (intent ++ BCS(summary) ++ epoch). If that fails every
//!    signature of the group is verified on its own, bad ones are evicted and the stake is
//!    recounted. A group for another digest therefore never certifies.
//!  - Split brain: no digest can reach quorum any more (`uncommitted + plurality < quorum`).
//!  - Signatures for checkpoints at or below the highest certified one are dropped; buffered
//!    ones below the next checkpoint to certify are discarded.
//!
//! Differences: a signature from an authority outside the committee is dropped on entry (the
//! consensus handler already rejected it in Rust); the pending map is bounded (`max_pending`).
const std = @import("std");
const bls = @import("bls");
const checkpoint = @import("checkpoint");
const types = @import("types");
const bcs = @import("bcs");
const iface = @import("../iface.zig");
const messages = @import("../messages.zig");
const create = @import("create.zig");
const store_mod = @import("store.zig");

pub const Error = error{ OutOfMemory, Io };

/// Votes buffered for checkpoints we have not started to certify, across all checkpoints.
pub const max_pending: usize = 1 << 16;
/// Votes are only buffered for checkpoints within this many sequence numbers of the next one to
/// certify; a validator signing far-future sequence numbers cannot fill the buffer.
pub const vote_window: u64 = 1024;
/// Buffered votes per authority (an honest one has at most one per checkpoint of the window).
pub const max_per_authority: u32 = 2 * vote_window;

/// One sequenced signature, reduced to what aggregation needs (the summary itself is not kept:
/// only its digest matters, the certified summary is always the local one).
pub const Vote = struct {
    seq: u64,
    digest: [32]u8,
    epoch: u64,
    authority: [96]u8,
    sig: [48]u8,
};

pub const Cert = struct {
    epoch: u64,
    signature: [48]u8,
    /// Serialized RoaringBitmap of signer indices (the committee's sorted order).
    bitmap: []u8,
};

pub const Outcome = struct {
    cert: ?Cert = null,
    /// `check_for_split_brain` found that no digest can reach quorum.
    split_brain: bool = false,
    /// A quorum formed on a digest other than ours.
    remote_fork: bool = false,
};

/// Serializes a RoaringBitmap exactly as roaring-rs 0.11 does for array containers only (no run
/// containers: the bitmap is built by inserting): cookie 12346, container count, (key, card - 1)
/// descriptors, absolute offsets, then the sorted u16 values. `ids` sorted, unique.
pub fn serializeBitmap(gpa: std.mem.Allocator, ids: []const u32) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    // containers
    var n_containers: u32 = 0;
    var i: usize = 0;
    while (i < ids.len) {
        const key = ids[i] >> 16;
        while (i < ids.len and (ids[i] >> 16) == key) i += 1;
        n_containers += 1;
    }
    try appendInt(gpa, &out, u32, 12346);
    try appendInt(gpa, &out, u32, n_containers);
    i = 0;
    while (i < ids.len) {
        const key = ids[i] >> 16;
        var j = i;
        while (j < ids.len and (ids[j] >> 16) == key) j += 1;
        try appendInt(gpa, &out, u16, @intCast(key));
        try appendInt(gpa, &out, u16, @intCast(j - i - 1));
        i = j;
    }
    var offset: u32 = @intCast(8 + 8 * @as(usize, n_containers));
    i = 0;
    while (i < ids.len) {
        const key = ids[i] >> 16;
        var j = i;
        while (j < ids.len and (ids[j] >> 16) == key) j += 1;
        try appendInt(gpa, &out, u32, offset);
        offset += @intCast(2 * (j - i));
        i = j;
    }
    for (ids) |v| try appendInt(gpa, &out, u16, @intCast(v & 0xffff));
    return out.toOwnedSlice(gpa);
}

fn appendInt(gpa: std.mem.Allocator, out: *std.ArrayList(u8), comptime T: type, v: T) !void {
    var b: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &b, v, .little);
    try out.appendSlice(gpa, &b);
}

fn indexOf(c: *const checkpoint.Committee, name: *const [96]u8) ?u32 {
    var lo: usize = 0;
    var hi: usize = c.members.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, &c.members[mid].name, name)) {
            .eq => return @intCast(mid),
            .lt => lo = mid + 1,
            .gt => hi = mid,
        }
    }
    return null;
}

const GroupVote = struct { idx: u32, sig: [48]u8 };
const Group = struct {
    digest: [32]u8,
    votes: std.ArrayList(GroupVote) = .empty,
    stake: u64 = 0,
};

/// `CheckpointSignatureAggregator`: certifies one local summary.
pub const SignatureAggregator = struct {
    gpa: std.mem.Allocator,
    committee: *const checkpoint.Committee,
    seq: u64,
    epoch: u64,
    digest: [32]u8,
    /// Intent ++ BCS(local summary) ++ epoch: what every signature must be over.
    msg: []u8,
    groups: std.ArrayList(Group) = .empty,
    /// Authorities that voted in any group (`MultiStakeAggregator::total_votes`).
    voted: []bool,

    /// `summary_bcs` is the local summary; it is copied.
    pub fn init(gpa: std.mem.Allocator, committee: *const checkpoint.Committee, seq: u64, epoch: u64, summary_bcs: []const u8) Error!SignatureAggregator {
        const msg = try create.signingMessage(gpa, summary_bcs, epoch);
        errdefer gpa.free(msg);
        const voted = try gpa.alloc(bool, committee.members.len);
        @memset(voted, false);
        return .{
            .gpa = gpa,
            .committee = committee,
            .seq = seq,
            .epoch = epoch,
            .digest = types.digest.checkpointSummaryDigest(summary_bcs),
            .msg = msg,
            .voted = voted,
        };
    }

    pub fn deinit(a: *SignatureAggregator) void {
        for (a.groups.items) |*g| g.votes.deinit(a.gpa);
        a.groups.deinit(a.gpa);
        a.gpa.free(a.msg);
        a.gpa.free(a.voted);
    }

    fn totalVotes(a: *const SignatureAggregator) u64 {
        var t: u64 = 0;
        for (a.voted, 0..) |v, i| if (v) {
            t +%= a.committee.members[i].stake;
        };
        return t;
    }

    fn plurality(a: *const SignatureAggregator) u64 {
        var m: u64 = 0;
        for (a.groups.items) |g| m = @max(m, g.stake);
        return m;
    }

    /// `quorum_unreachable`: not enough uncommitted stake left for any digest to reach quorum.
    pub fn quorumUnreachable(a: *const SignatureAggregator) bool {
        const uncommitted = a.committee.total_stake -% a.totalVotes();
        return uncommitted +% a.plurality() < a.committee.quorum_threshold;
    }

    const Insert = union(enum) {
        quorum: Cert,
        not_enough,
        /// A repeated signer; `conflicting` when its signature differs.
        repeated: bool,
        failed,
    };

    /// `try_aggregate`.
    pub fn tryAggregate(a: *SignatureAggregator, v: Vote) Error!Outcome {
        const idx = indexOf(a.committee, &v.authority) orelse return .{};
        const sig = bls.Signature.fromBytes(&v.sig) orelse return .{};
        _ = sig;
        const r = try a.insert(v.digest, idx, v.epoch, v.sig);
        switch (r) {
            // Rust ignores an identical repeat; a conflicting one is a failed insert, which runs
            // `check_for_split_brain`
            .repeated => |conflicting| return if (conflicting) .{ .split_brain = a.quorumUnreachable() } else .{},
            .failed => return .{ .split_brain = a.quorumUnreachable() },
            .quorum => |cert| {
                if (!std.mem.eql(u8, &v.digest, &a.digest)) {
                    a.gpa.free(cert.bitmap);
                    return .{ .remote_fork = true };
                }
                return .{ .cert = cert };
            },
            .not_enough => return .{ .split_brain = a.quorumUnreachable() },
        }
    }

    fn insert(a: *SignatureAggregator, digest: [32]u8, idx: u32, epoch: u64, sig: [48]u8) Error!Insert {
        if (epoch != a.committee.epoch) return .failed;
        var gi: ?usize = null;
        for (a.groups.items, 0..) |g, i| if (std.mem.eql(u8, &g.digest, &digest)) {
            gi = i;
            break;
        };
        const is_new = gi == null;
        if (is_new) {
            // a failed insert must not leave an empty group behind
            try a.groups.append(a.gpa, .{ .digest = digest });
            gi = a.groups.items.len - 1;
        }
        const g = &a.groups.items[gi.?];
        errdefer if (is_new) {
            var dead = a.groups.pop().?;
            dead.votes.deinit(a.gpa);
        };
        for (g.votes.items) |x| if (x.idx == idx) {
            return .{ .repeated = !std.mem.eql(u8, &x.sig, &sig) };
        };
        const weight = a.committee.members[idx].stake;
        if (weight == 0) {
            if (is_new) {
                var dead = a.groups.pop().?;
                dead.votes.deinit(a.gpa);
            }
            return .failed;
        }
        try g.votes.append(a.gpa, .{ .idx = idx, .sig = sig });
        g.stake +%= weight;
        a.voted[idx] = true;
        if (g.stake < a.committee.quorum_threshold) return .not_enough;

        // Quorum stake: aggregate and verify against the local summary.
        if (try a.aggregateAndVerify(g)) |cert| return .{ .quorum = cert };
        // Fall back to verifying every signature of the group, evicting the bad ones.
        var kept: std.ArrayList(GroupVote) = .empty;
        errdefer kept.deinit(a.gpa);
        var stake: u64 = 0;
        for (g.votes.items) |x| {
            const pk = bls.PublicKey.fromBytes(&a.committee.members[x.idx].name) orelse continue;
            const s = bls.Signature.fromBytes(&x.sig) orelse continue;
            if (bls.verify(&pk, a.msg, &s)) {
                try kept.append(a.gpa, x);
                stake +%= a.committee.members[x.idx].stake;
            } else {
                // voted stays set: Rust's total_votes reads the stake maps, where the bad
                // signature was removed, so un-vote unless another group holds the signer
                a.voted[x.idx] = a.votedElsewhere(g, x.idx);
            }
        }
        g.votes.deinit(a.gpa);
        g.votes = kept;
        g.stake = stake;
        if (g.stake >= a.committee.quorum_threshold) {
            // the evicted-and-recounted quorum is aggregated without a second verification
            return .{ .quorum = (try a.aggregateOnly(g)) orelse return .failed };
        }
        return .not_enough;
    }

    fn votedElsewhere(a: *const SignatureAggregator, except: *const Group, idx: u32) bool {
        for (a.groups.items) |*g| {
            if (g == except) continue;
            for (g.votes.items) |x| if (x.idx == idx) return true;
        }
        return false;
    }

    fn aggregateOnly(a: *SignatureAggregator, g: *const Group) Error!?Cert {
        const sigs = try a.gpa.alloc(bls.Signature, g.votes.items.len);
        defer a.gpa.free(sigs);
        const ids = try a.gpa.alloc(u32, g.votes.items.len);
        defer a.gpa.free(ids);
        for (g.votes.items, sigs, ids) |x, *s, *id| {
            s.* = bls.Signature.fromBytes(&x.sig) orelse return null;
            id.* = x.idx;
        }
        const agg = bls.aggregate(sigs) orelse return null;
        std.mem.sort(u32, ids, {}, std.sort.asc(u32));
        return .{ .epoch = a.committee.epoch, .signature = agg.toBytes(), .bitmap = try serializeBitmap(a.gpa, ids) };
    }

    fn aggregateAndVerify(a: *SignatureAggregator, g: *const Group) Error!?Cert {
        const cert = (try a.aggregateOnly(g)) orelse return null;
        const ids = try a.gpa.alloc(u32, g.votes.items.len);
        defer a.gpa.free(ids);
        for (g.votes.items, ids) |x, *id| id.* = x.idx;
        if (a.committee.prepared.verifyAggregate(ids, a.msg, &cert.signature)) return cert;
        a.gpa.free(cert.bitmap);
        return null;
    }
};

/// `signature_verifier::batch_verify_checkpoints`, which `SuiTxValidator::verify_batch` runs over
/// the CheckpointSignatureV2 messages of every block it validates (consensus_validator.rs): every
/// summary's epoch is the committee's (`verify_epoch`), then for each message the signature's
/// epoch is the committee's, the signer is a member with stake, and the BLS signature over
/// Intent(CheckpointSummary, V0, Sui) ++ BCS(summary) ++ epoch verifies. One failure rejects the
/// whole block. Rust checks the block's signatures as one randomized batch (fastcrypto
/// `batch_verify`); checking each one accepts exactly the blocks a valid batch does.
pub fn verifySignatureMessages(gpa: std.mem.Allocator, committee: *const checkpoint.Committee, msgs: []const *const messages.CheckpointSignatureMessage) std.mem.Allocator.Error!bool {
    for (msgs) |m| if (m.summary.data.epoch != committee.epoch) return false;
    for (msgs) |m| {
        const si = &m.summary.auth_signature;
        if (si.epoch != committee.epoch) return false;
        const idx = indexOf(committee, &si.authority.@"0") orelse return false;
        if (committee.members[idx].stake == 0) return false;
        const pk: bls.PublicKey = .{ .point = committee.prepared.keys[idx] };
        const sig = bls.Signature.fromBytes(&si.signature) orelse return false;
        const sb = try bcs.encodeAlloc(types.CheckpointSummary, gpa, &m.summary.data);
        defer gpa.free(sb);
        const msg = try create.signingMessage(gpa, sb, si.epoch);
        defer gpa.free(msg);
        if (!bls.verify(&pk, msg, &sig)) return false;
    }
    return true;
}

/// BCS(CertifiedCheckpointSummary) = Envelope<CheckpointSummary, AuthorityQuorumSignInfo>:
/// the summary, then epoch, the 48 signature bytes, the length-prefixed signer bitmap.
pub fn certifiedBcs(gpa: std.mem.Allocator, summary_bcs: []const u8, cert: Cert) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, summary_bcs);
    try appendInt(gpa, &out, u64, cert.epoch);
    try out.appendSlice(gpa, &cert.signature);
    var v = cert.bitmap.len;
    while (true) {
        const b: u8 = @intCast(v & 0x7f);
        v >>= 7;
        if (v == 0) {
            try out.append(gpa, b);
            break;
        }
        try out.append(gpa, b | 0x80);
    }
    try out.appendSlice(gpa, cert.bitmap);
    return out.toOwnedSlice(gpa);
}

/// `CheckpointAggregator`.
pub const Aggregator = struct {
    gpa: std.mem.Allocator,
    committee: *const checkpoint.Committee,
    store: store_mod.Store,
    sink: iface.CertifiedSink,

    lock: store_mod.SpinLock = .{},
    inbox: std.ArrayList(Vote) = .empty,
    /// Votes by checkpoint, in arrival order per checkpoint.
    pending: std.AutoArrayHashMapUnmanaged(u64, std.ArrayList(Vote)) = .empty,
    /// Guarded by `lock`, like `pending`, `inbox`, `per_authority` and `dropped_votes`.
    pending_count: usize = 0,
    per_authority: std.AutoHashMapUnmanaged([96]u8, u32) = .empty,
    current: ?SignatureAggregator = null,

    /// Counters a metrics layer can read.
    certified_count: u64 = 0,
    split_brain_count: u64 = 0,
    remote_fork_count: u64 = 0,
    dropped_votes: u64 = 0,
    /// Set when a split brain was seen at this sequence number (the builder's fork marker).
    split_brain_seq: ?u64 = null,

    pub fn init(gpa: std.mem.Allocator, committee: *const checkpoint.Committee, st: store_mod.Store, sink: iface.CertifiedSink) Aggregator {
        return .{ .gpa = gpa, .committee = committee, .store = st, .sink = sink };
    }

    pub fn deinit(a: *Aggregator) void {
        if (a.current) |*c| c.deinit();
        a.inbox.deinit(a.gpa);
        for (a.pending.values()) |*l| l.deinit(a.gpa);
        a.pending.deinit(a.gpa);
        a.per_authority.deinit(a.gpa);
    }

    /// Caller holds `lock`.
    fn releaseVotes(a: *Aggregator, votes: []const Vote) void {
        for (votes) |v| {
            if (a.per_authority.getPtr(v.authority)) |c| {
                if (c.* <= 1) _ = a.per_authority.remove(v.authority) else c.* -= 1;
            }
        }
    }

    /// iface.CheckpointSignatureSink: a sequenced signature from a peer (or from ourselves).
    /// Never blocks on the aggregation work: it only queues.
    pub fn addSignature(a: *Aggregator, from: *const messages.AuthorityName, msg: *const messages.CheckpointSignatureMessage) Error!void {
        _ = from;
        const data = &msg.summary.data;
        if (a.store.highestCertified()) |h| if (data.sequence_number <= h) return;
        const next = a.store.nextToCertify();
        if (data.sequence_number > next +| vote_window) {
            a.lock.lock();
            a.dropped_votes += 1;
            a.lock.unlock();
            return;
        }
        const si = &msg.summary.auth_signature;
        const bytes = bcs.encodeAlloc(types.CheckpointSummary, a.gpa, data) catch return error.OutOfMemory;
        defer a.gpa.free(bytes);
        const vote: Vote = .{
            .seq = data.sequence_number,
            .digest = types.digest.checkpointSummaryDigest(bytes),
            .epoch = si.epoch,
            .authority = si.authority.@"0",
            .sig = si.signature,
        };
        a.lock.lock();
        defer a.lock.unlock();
        if (a.pending_count + a.inbox.items.len >= max_pending) {
            a.dropped_votes += 1;
            return;
        }
        const gop = try a.per_authority.getOrPut(a.gpa, vote.authority);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        if (gop.value_ptr.* >= max_per_authority) {
            a.dropped_votes += 1;
            return;
        }
        a.inbox.append(a.gpa, vote) catch |e| {
            if (gop.value_ptr.* == 0) _ = a.per_authority.remove(vote.authority);
            return e;
        };
        gop.value_ptr.* += 1;
    }

    fn sinkAdd(ctx: *anyopaque, from: *const messages.AuthorityName, msg: *const messages.CheckpointSignatureMessage) void {
        const a: *Aggregator = @ptrCast(@alignCast(ctx));
        a.addSignature(from, msg) catch {
            a.lock.lock();
            defer a.lock.unlock();
            a.dropped_votes += 1;
        };
    }

    const sink_vtable: iface.CheckpointSignatureSink.VTable = .{ .add = sinkAdd };

    pub fn signatureSink(a: *Aggregator) iface.CheckpointSignatureSink {
        return .{ .ctx = a, .vtable = &sink_vtable };
    }

    fn drainInbox(a: *Aggregator) Error!void {
        a.lock.lock();
        defer a.lock.unlock();
        var done: usize = 0;
        // on an error the votes already moved are dropped from the inbox (no double entries)
        errdefer a.inbox.replaceRangeAssumeCapacity(0, done, &.{});
        for (a.inbox.items) |v| {
            const gop = try a.pending.getOrPut(a.gpa, v.seq);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(a.gpa, v);
            a.pending_count += 1;
            done += 1;
        }
        a.inbox.clearRetainingCapacity();
    }

    /// `run_inner` followed by the certified output: certifies as many consecutive checkpoints
    /// as the buffered votes allow. Returns how many were certified. Call it after a checkpoint
    /// was built and whenever signatures arrived (or on a 1 s timer, as Rust does).
    pub fn poll(a: *Aggregator, arena: std.mem.Allocator) Error!u32 {
        try a.drainInbox();
        var done: u32 = 0;
        outer: while (true) {
            const next = a.store.nextToCertify();
            // discard buffered signatures for checkpoints already certified
            {
                a.lock.lock();
                defer a.lock.unlock();
                var k: usize = 0;
                while (k < a.pending.count()) {
                    if (a.pending.keys()[k] < next) {
                        var l = a.pending.values()[k];
                        a.pending_count -= l.items.len;
                        a.releaseVotes(l.items);
                        l.deinit(a.gpa);
                        a.pending.swapRemoveAt(k);
                    } else k += 1;
                }
            }
            if (a.current) |*c| {
                if (c.seq < next) {
                    c.deinit();
                    a.current = null;
                    continue :outer;
                }
            } else {
                const summary = (try a.store.builtSummary(arena, next)) orelse return done;
                a.current = try SignatureAggregator.init(a.gpa, a.committee, next, a.committee.epoch, summary);
            }
            const cur = &a.current.?;
            a.lock.lock();
            var list = if (a.pending.fetchSwapRemove(cur.seq)) |kv| kv.value else {
                a.lock.unlock();
                return done;
            };
            a.pending_count -= list.items.len;
            a.releaseVotes(list.items);
            a.lock.unlock();
            defer list.deinit(a.gpa);
            for (list.items) |v| {
                const out = try cur.tryAggregate(v);
                if (out.split_brain) {
                    a.split_brain_count += 1;
                    a.split_brain_seq = cur.seq;
                }
                if (out.remote_fork) a.remote_fork_count += 1;
                if (out.cert) |cert| {
                    defer a.gpa.free(cert.bitmap);
                    const summary = (try a.store.builtSummary(arena, cur.seq)).?;
                    const cbytes = try certifiedBcs(a.gpa, summary, cert);
                    defer a.gpa.free(cbytes);
                    const seq = cur.seq;
                    try a.store.putCertified(seq, cur.digest, cbytes);
                    const contents = (try a.store.builtContents(arena, seq)) orelse return error.Io;
                    a.sink.certified(seq, cbytes, contents) catch return error.Io;
                    a.certified_count += 1;
                    done += 1;
                    cur.deinit();
                    a.current = null;
                    continue :outer;
                }
            }
            return done;
        }
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "bitmap serialization matches the reader's example and validates" {
    const b = try serializeBitmap(testing.allocator, &.{ 1, 5, 9 });
    defer testing.allocator.free(b);
    const want = [_]u8{ 0x3a, 0x30, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 16, 0, 0, 0, 1, 0, 5, 0, 9, 0 };
    try testing.expectEqualSlices(u8, &want, b);
    _ = try types.roaring.validate(b);
    var s: checkpoint.summary.Signers = undefined;
    try checkpoint.summary.signers(b, &s);
    try testing.expectEqualSlices(u32, &.{ 1, 5, 9 }, s.slice());
}

const TestNet = struct {
    arena: std.heap.ArenaAllocator,
    sks: [4]bls.SecretKey,
    committee: checkpoint.Committee,
    /// committee index -> secret key
    by_index: [4]usize,

    fn init(gpa: std.mem.Allocator, epoch: u64) !TestNet {
        var t: TestNet = undefined;
        t.arena = std.heap.ArenaAllocator.init(gpa);
        const a = t.arena.allocator();
        var members: [4]checkpoint.Member = undefined;
        for (&t.sks, &members, 0..) |*sk, *m, i| {
            var seed: [32]u8 = @splat(0);
            seed[31] = @intCast(i + 1);
            seed[0] = 0x21;
            sk.* = bls.SecretKey.fromBytes(&seed).?;
            m.* = .{ .name = sk.publicKey().toBytes(), .stake = 2500 };
        }
        t.committee = try checkpoint.Committee.init(a, epoch, &members);
        for (t.committee.members, 0..) |m, ci| {
            for (t.sks, 0..) |sk, si| {
                if (std.mem.eql(u8, &sk.publicKey().toBytes(), &m.name)) t.by_index[ci] = si;
            }
        }
        return t;
    }
    fn deinit(t: *TestNet) void {
        t.arena.deinit();
    }
    fn vote(t: *const TestNet, ci: usize, seq: u64, epoch: u64, summary_bcs: []const u8) !Vote {
        const msg = try create.signingMessage(testing.allocator, summary_bcs, epoch);
        defer testing.allocator.free(msg);
        const sk = t.sks[t.by_index[ci]];
        return .{
            .seq = seq,
            .digest = types.digest.checkpointSummaryDigest(summary_bcs),
            .epoch = epoch,
            .authority = t.committee.members[ci].name,
            .sig = sk.sign(msg).toBytes(),
        };
    }
};

test "quorum of 3 of 4 certifies and the certificate verifies" {
    var net = try TestNet.init(testing.allocator, 5);
    defer net.deinit();
    const summary: types.CheckpointSummary = .{
        .epoch = 5,
        .sequence_number = 12,
        .network_total_transactions = 1,
        .content_digest = .{ .@"0" = .{ .@"0" = @splat(1) } },
        .previous_digest = null,
        .epoch_rolling_gas_cost_summary = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .timestamp_ms = 3,
        .checkpoint_commitments = &.{},
        .end_of_epoch_data = null,
        .version_specific_data = &.{},
    };
    const sbytes = try bcs.encodeAlloc(types.CheckpointSummary, testing.allocator, &summary);
    defer testing.allocator.free(sbytes);
    var agg = try SignatureAggregator.init(testing.allocator, &net.committee, 12, 5, sbytes);
    defer agg.deinit();
    try testing.expect((try agg.tryAggregate(try net.vote(0, 12, 5, sbytes))).cert == null);
    // a repeat is ignored
    try testing.expect((try agg.tryAggregate(try net.vote(0, 12, 5, sbytes))).cert == null);
    try testing.expect((try agg.tryAggregate(try net.vote(1, 12, 5, sbytes))).cert == null);
    const out = try agg.tryAggregate(try net.vote(2, 12, 5, sbytes));
    const cert = out.cert.?;
    defer testing.allocator.free(cert.bitmap);
    // the certificate passes the full node's verifier
    const cbytes = try certifiedBcs(testing.allocator, sbytes, cert);
    defer testing.allocator.free(cbytes);
    const split = cbytes.len - (8 + 48 + 1 + cert.bitmap.len);
    const v = checkpoint.verifyCertifiedSummary(&net.committee, .{ .summary = cbytes[0..split], .sig = cbytes[split..] });
    try testing.expect(v.isOk());
}

test "a split vote never certifies and is reported as split brain" {
    var net = try TestNet.init(testing.allocator, 5);
    defer net.deinit();
    const mk = struct {
        fn f(gpa: std.mem.Allocator, ts: u64) ![]u8 {
            const s: types.CheckpointSummary = .{
                .epoch = 5,
                .sequence_number = 12,
                .network_total_transactions = 1,
                .content_digest = .{ .@"0" = .{ .@"0" = @splat(1) } },
                .previous_digest = null,
                .epoch_rolling_gas_cost_summary = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
                .timestamp_ms = ts,
                .checkpoint_commitments = &.{},
                .end_of_epoch_data = null,
                .version_specific_data = &.{},
            };
            return bcs.encodeAlloc(types.CheckpointSummary, gpa, &s);
        }
    }.f;
    const mine = try mk(testing.allocator, 1);
    defer testing.allocator.free(mine);
    const other = try mk(testing.allocator, 2);
    defer testing.allocator.free(other);
    var agg = try SignatureAggregator.init(testing.allocator, &net.committee, 12, 5, mine);
    defer agg.deinit();
    _ = try agg.tryAggregate(try net.vote(0, 12, 5, mine));
    _ = try agg.tryAggregate(try net.vote(1, 12, 5, mine));
    const o3 = try agg.tryAggregate(try net.vote(2, 12, 5, other));
    try testing.expect(o3.cert == null and !o3.split_brain);
    // 2 for mine, 2 for other, nothing uncommitted: 5000 < 6667, no digest can reach quorum
    const o4 = try agg.tryAggregate(try net.vote(3, 12, 5, other));
    try testing.expect(o4.cert == null);
    try testing.expect(o4.split_brain);
    try testing.expect(agg.quorumUnreachable());
}
