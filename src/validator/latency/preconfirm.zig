//! Preconfirmations (docs/VALIDATOR-DESIGN.md 10.5): signed "it is going in" notices for user
//! transactions, emitted when the consensus handler sees a commit, streamed to subscribed apps
//! and tide. zui-only: NOT part of Sui's protocol, never sent to other validators, and a notice
//! is a promise from this node that the transaction was sequenced in a commit, not a finality
//! proof. A transaction can still be rejected (a quorum of reject votes) or cancelled
//! (owned-object conflict) until the `finalized` notice says otherwise, and clients must treat
//! `sequenced` as a hint to show UI, nothing more.
//!
//! OFF by default (Flags.preconfirmations). With no subscriber the hook costs one atomic load
//! and decodes nothing. The notice key is its own Ed25519 key, handed in by the operator: it is
//! never the validator's protocol, network or authority key, and notices use their own signing
//! domain, so a notice signature cannot be replayed as any consensus or checkpoint signature.
//!
//! Wire layout of a notice (little endian, fixed, 194 bytes):
//!   0  u8  version = 1          1  u8  kind (0 sequenced, 1 finalized)
//!   2  u8  flags (bit0 rejected) 3 u8 zero
//!   4  u64 epoch                12 u32 commit index        16 [32] commit digest
//!   48 u64 commit timestamp ms  56 [32] transaction digest
//!   88 u32 block round          92 u32 block author        96 [32] block digest
//!   128 u16 index in block      130 [64] Ed25519 signature over domain ++ bytes[0..130]
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const consensus = @import("consensus");
const messages = @import("../messages.zig");

pub const version: u8 = 1;
pub const body_len = 130;
pub const notice_len = body_len + 64;
pub const domain = "zui-preconfirmation-v1\x00";

pub const Kind = enum(u8) {
    /// The transaction is in a committed sub-dag (before fast-path finalization).
    sequenced = 0,
    /// The finalized sub-dag came out of the commit finalizer: accepted or rejected.
    finalized = 1,
};

pub const Notice = struct {
    kind: Kind,
    rejected: bool = false,
    epoch: u64,
    commit: consensus.types.CommitRef,
    commit_timestamp_ms: u64,
    tx_digest: [32]u8,
    block: consensus.types.BlockRef,
    index: u16,

    pub fn encodeBody(n: *const Notice, out: *[body_len]u8) void {
        out[0] = version;
        out[1] = @intFromEnum(n.kind);
        out[2] = @intFromBool(n.rejected);
        out[3] = 0;
        std.mem.writeInt(u64, out[4..12], n.epoch, .little);
        std.mem.writeInt(u32, out[12..16], n.commit.index, .little);
        @memcpy(out[16..48], &n.commit.digest);
        std.mem.writeInt(u64, out[48..56], n.commit_timestamp_ms, .little);
        @memcpy(out[56..88], &n.tx_digest);
        std.mem.writeInt(u32, out[88..92], n.block.round, .little);
        std.mem.writeInt(u32, out[92..96], n.block.author, .little);
        @memcpy(out[96..128], &n.block.digest);
        std.mem.writeInt(u16, out[128..130], n.index, .little);
    }

    pub const DecodeError = error{ BadLength, BadVersion, BadKind };

    pub fn decodeBody(b: []const u8) DecodeError!Notice {
        if (b.len < body_len) return error.BadLength;
        if (b[0] != version) return error.BadVersion;
        if (b[1] > 1) return error.BadKind;
        return .{
            .kind = @enumFromInt(b[1]),
            .rejected = b[2] & 1 != 0,
            .epoch = std.mem.readInt(u64, b[4..12], .little),
            .commit = .{ .index = std.mem.readInt(u32, b[12..16], .little), .digest = b[16..48].* },
            .commit_timestamp_ms = std.mem.readInt(u64, b[48..56], .little),
            .tx_digest = b[56..88].*,
            .block = .{
                .round = std.mem.readInt(u32, b[88..92], .little),
                .author = std.mem.readInt(u32, b[92..96], .little),
                .digest = b[96..128].*,
            },
            .index = std.mem.readInt(u16, b[128..130], .little),
        };
    }
};

pub const Ed25519 = std.crypto.sign.Ed25519;

pub const SignedNotice = [notice_len]u8;

pub fn sign(kp: Ed25519.KeyPair, n: *const Notice) !SignedNotice {
    var out: SignedNotice = undefined;
    n.encodeBody(out[0..body_len]);
    var msg: [domain.len + body_len]u8 = undefined;
    @memcpy(msg[0..domain.len], domain);
    @memcpy(msg[domain.len..], out[0..body_len]);
    const sig = try kp.sign(&msg, null);
    out[body_len..][0..64].* = sig.toBytes();
    return out;
}

pub const VerifyError = error{ BadSignature, BadLength, BadVersion, BadKind };

/// Checks the signature and returns the decoded notice.
pub fn verify(pk: Ed25519.PublicKey, signed: []const u8) VerifyError!Notice {
    if (signed.len != notice_len) return error.BadLength;
    const n = Notice.decodeBody(signed) catch |e| return e;
    var msg: [domain.len + body_len]u8 = undefined;
    @memcpy(msg[0..domain.len], domain);
    @memcpy(msg[domain.len..], signed[0..body_len]);
    const sig = Ed25519.Signature.fromBytes(signed[body_len..][0..64].*);
    sig.verify(&msg, pk) catch return error.BadSignature;
    return n;
}

// ------------------------------------------------------------------ hub

pub const max_subscribers = 64;
pub const max_watch = 8;
pub const ring_cap = 1024;

pub const Filter = struct {
    /// Empty = every transaction. Otherwise only these digests (max_watch).
    watch: [max_watch][32]u8 = undefined,
    watch_len: u8 = 0,

    pub fn matches(f: *const Filter, d: *const [32]u8) bool {
        if (f.watch_len == 0) return true;
        for (f.watch[0..@min(f.watch_len, max_watch)]) |*w| if (std.mem.eql(u8, w, d)) return true;
        return false;
    }
};

/// `gen << 8 | slot`: a stale id from an earlier subscriber of the same slot never matches.
pub const SubId = u32;

fn subId(slot: usize, gen: u32) SubId {
    return ((gen & 0xff_ffff) << 8) | @as(u32, @intCast(slot));
}

const Sub = struct {
    active: bool = false,
    gen: u32 = 0,
    filter: Filter = .{},
    ring: []SignedNotice = &.{},
    head: u64 = 0, // next to read
    tail: u64 = 0, // next to write
    dropped: u64 = 0,
};

const SpinLock = struct {
    locked: std.atomic.Value(bool) = .init(false),
    fn lock(l: *SpinLock) void {
        while (l.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn unlock(l: *SpinLock) void {
        l.locked.store(false, .release);
    }
};

/// Fan-out of signed notices to pull-based subscribers. Each subscriber has a bounded ring; a
/// slow one loses its oldest notices (counted), never blocks the commit path. A transport (the
/// native protocol's subscription topic, planned) calls `subscribe` per client and `poll` from
/// its own thread.
pub const Hub = struct {
    gpa: std.mem.Allocator,
    subs: [max_subscribers]Sub = @splat(.{}),
    lock: SpinLock = .{},
    active_count: std.atomic.Value(u32) = .init(0),
    published: std.atomic.Value(u64) = .init(0),

    pub fn init(gpa: std.mem.Allocator) Hub {
        return .{ .gpa = gpa };
    }

    pub fn deinit(h: *Hub) void {
        for (&h.subs) |*s| if (s.ring.len != 0) h.gpa.free(s.ring);
    }

    /// Number of live subscribers (one atomic load).
    pub fn active(h: *const Hub) u32 {
        return h.active_count.load(.monotonic);
    }

    /// The live subscriber for `id`, or null for a stale, foreign or unsubscribed id. Lock held.
    fn live(h: *Hub, id: SubId) ?*Sub {
        const slot = id & 0xff;
        if (slot >= max_subscribers) return null;
        const s = &h.subs[slot];
        if (!s.active or (s.gen & 0xff_ffff) != id >> 8) return null;
        return s;
    }

    /// True when some subscriber wants `tx_digest` (the commit path skips signing otherwise).
    pub fn anyMatches(h: *Hub, tx_digest: *const [32]u8) bool {
        h.lock.lock();
        defer h.lock.unlock();
        for (&h.subs) |*s| if (s.active and s.filter.matches(tx_digest)) return true;
        return false;
    }

    pub fn subscribe(h: *Hub, filter: Filter) error{ TooManySubscribers, OutOfMemory, BadFilter }!SubId {
        if (filter.watch_len > max_watch) return error.BadFilter;
        h.lock.lock();
        defer h.lock.unlock();
        for (&h.subs, 0..) |*s, i| {
            if (s.active) continue;
            if (s.ring.len == 0) s.ring = try h.gpa.alloc(SignedNotice, ring_cap);
            s.active = true;
            s.gen +%= 1;
            s.filter = filter;
            s.head = 0;
            s.tail = 0;
            s.dropped = 0;
            _ = h.active_count.fetchAdd(1, .monotonic);
            return subId(i, s.gen);
        }
        return error.TooManySubscribers;
    }

    pub fn unsubscribe(h: *Hub, id: SubId) void {
        h.lock.lock();
        defer h.lock.unlock();
        const s = h.live(id) orelse return;
        s.active = false;
        _ = h.active_count.fetchSub(1, .monotonic);
    }

    /// Queues `signed` for every subscriber whose filter matches `tx_digest`.
    pub fn publish(h: *Hub, tx_digest: *const [32]u8, signed: *const SignedNotice) void {
        h.lock.lock();
        defer h.lock.unlock();
        _ = h.published.fetchAdd(1, .monotonic);
        for (&h.subs) |*s| {
            if (!s.active or !s.filter.matches(tx_digest)) continue;
            if (s.tail - s.head == ring_cap) {
                s.head += 1;
                s.dropped += 1;
            }
            s.ring[@intCast(s.tail % ring_cap)] = signed.*;
            s.tail += 1;
        }
    }

    /// Copies up to `out.len` queued notices, oldest first. Returns the count.
    pub fn poll(h: *Hub, id: SubId, out: []SignedNotice) usize {
        h.lock.lock();
        defer h.lock.unlock();
        const s = h.live(id) orelse return 0;
        var n: usize = 0;
        while (n < out.len and s.head < s.tail) : (n += 1) {
            out[n] = s.ring[@intCast(s.head % ring_cap)];
            s.head += 1;
        }
        return n;
    }

    pub fn droppedFor(h: *Hub, id: SubId) u64 {
        h.lock.lock();
        defer h.lock.unlock();
        return if (h.live(id)) |s| s.dropped else 0;
    }
};

// ------------------------------------------------------------------ notifier

const user_tx_tag: u32 = 9; // ConsensusTransactionKind::UserTransaction
const user_tx_v2_tag: u32 = 12; // ConsensusTransactionKind::UserTransactionV2

/// Transaction digest of a user transaction inside a BCS ConsensusTransaction, or null for every
/// other kind (checkpoint signatures, DKG, JWK, ...) and for anything that does not decode.
/// Walks the fixed prefix (tracking id, variant, one-element SenderSignedData, intent) and
/// hashes the raw TransactionData bytes in place: no decode of the signatures and no re-encode.
/// `arena` holds the decoded TransactionData only (needed to find where it ends).
pub fn userTxDigest(arena: std.mem.Allocator, consensus_tx_bcs: []const u8) ?[32]u8 {
    var r = bcs.Reader.init(consensus_tx_bcs);
    if (r.remaining() < 8) return null;
    r.at += 8; // tracking_id
    const tag = r.uleb32() catch return null;
    if (tag != user_tx_tag and tag != user_tx_v2_tag) return null;
    // Transaction = Envelope<SenderSignedData, EmptySignInfo>: Vec<SenderSignedTransaction>,
    // exactly one element on mainnet.
    const n = r.uleb32() catch return null;
    if (n != 1) return null;
    if (r.remaining() < 3) return null; // Intent: scope, version, app id
    r.at += 3;
    const start = r.pos();
    _ = bcs.decodeFrom(types.TransactionData, arena, &r) catch return null;
    return types.digest.transactionDataDigest(consensus_tx_bcs[start..r.pos()]);
}

pub const Notifier = struct {
    hub: *Hub,
    key: Ed25519.KeyPair,
    epoch: std.atomic.Value(u64),
    /// Sequenced and finalized notices emitted.
    emitted: std.atomic.Value(u64) = .init(0),

    /// Call at epoch change so notices carry the current epoch.
    pub fn setEpoch(n: *Notifier, epoch: u64) void {
        n.epoch.store(epoch, .monotonic);
    }

    /// Hook for the consensus handler: call with every committed sub-dag (kind .sequenced) and
    /// every finalized sub-dag (kind .finalized, which carries rejected_transactions_by_block).
    /// A no-op while the hub has no subscriber.
    pub fn onSubDag(n: *Notifier, gpa: std.mem.Allocator, sub_dag: *const consensus.types.CommittedSubDag, kind: Kind) void {
        if (n.hub.active() == 0) return;
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        for (sub_dag.blocks) |*vb| {
            const ref = vb.reference();
            const txs = vb.block.inner.transactions();
            for (txs, 0..) |t, i| {
                _ = arena_state.reset(.retain_capacity);
                const d = userTxDigest(arena_state.allocator(), t.data) orelse continue;
                // Nobody wants this digest: no signature.
                if (!n.hub.anyMatches(&d)) continue;
                const rejected = kind == .finalized and isRejected(sub_dag, ref, @intCast(i));
                const notice: Notice = .{
                    .kind = kind,
                    .rejected = rejected,
                    .epoch = n.epoch.load(.monotonic),
                    .commit = sub_dag.commit_ref,
                    .commit_timestamp_ms = sub_dag.timestamp_ms,
                    .tx_digest = d,
                    .block = ref,
                    .index = @intCast(i),
                };
                const signed = sign(n.key, &notice) catch continue;
                n.hub.publish(&d, &signed);
                _ = n.emitted.fetchAdd(1, .monotonic);
            }
        }
    }
};

fn isRejected(sd: *const consensus.types.CommittedSubDag, ref: consensus.types.BlockRef, idx: u16) bool {
    for (sd.rejected_transactions_by_block) |r| {
        if (r.block.round != ref.round or r.block.author != ref.author or !std.mem.eql(u8, &r.block.digest, &ref.digest)) continue;
        for (r.indices) |x| if (x == idx) return true;
    }
    return false;
}

fn testNotice(i: u8) Notice {
    return .{
        .kind = .sequenced,
        .epoch = 5,
        .commit = .{ .index = 100 + i, .digest = @as([32]u8, @splat(i)) },
        .commit_timestamp_ms = 1_700_000_000_000,
        .tx_digest = @as([32]u8, @splat(i)),
        .block = .{ .round = 7, .author = 3, .digest = @as([32]u8, @splat(0xee)) },
        .index = i,
    };
}

test "sign, verify, tamper" {
    const kp = Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(4))) catch unreachable;
    const n = testNotice(2);
    var s = try sign(kp, &n);
    const back = try verify(kp.public_key, &s);
    try std.testing.expectEqual(n.commit.index, back.commit.index);
    try std.testing.expectEqualSlices(u8, &n.tx_digest, &back.tx_digest);
    s[60] ^= 1;
    try std.testing.expectError(error.BadSignature, verify(kp.public_key, &s));
    try std.testing.expectError(error.BadLength, verify(kp.public_key, s[0..10]));
}

test "hub filters, orders and drops oldest" {
    var h = Hub.init(std.testing.allocator);
    defer h.deinit();
    const kp = Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(4))) catch unreachable;
    var f: Filter = .{};
    f.watch[0] = @as([32]u8, @splat(2));
    f.watch_len = 1;
    const all = try h.subscribe(.{});
    const watcher = try h.subscribe(f);
    try std.testing.expectEqual(@as(u32, 2), h.active());
    for (0..4) |i| {
        const n = testNotice(@intCast(i));
        const s = try sign(kp, &n);
        h.publish(&n.tx_digest, &s);
    }
    var out: [8]SignedNotice = undefined;
    try std.testing.expectEqual(@as(usize, 4), h.poll(all, &out));
    try std.testing.expectEqual(@as(u32, 100), (try Notice.decodeBody(&out[0])).commit.index);
    try std.testing.expectEqual(@as(usize, 1), h.poll(watcher, &out));
    try std.testing.expectEqual(@as(u16, 2), (try Notice.decodeBody(&out[0])).index);
    // overflow
    const n = testNotice(9);
    const s = try sign(kp, &n);
    for (0..ring_cap + 10) |_| h.publish(&n.tx_digest, &s);
    try std.testing.expectEqual(@as(u64, 10), h.droppedFor(all));
    h.unsubscribe(all);
    try std.testing.expectEqual(@as(u32, 1), h.active());
    // stale id: the slot is reused by a new subscriber, the old id sees nothing
    const again = try h.subscribe(.{});
    try std.testing.expect(again != all);
    try std.testing.expectEqual(@as(usize, 0), h.poll(all, &out));
    h.unsubscribe(all); // no effect on the new subscriber
    try std.testing.expectEqual(@as(u32, 2), h.active());
    // bad filter
    var bad: Filter = .{};
    bad.watch_len = max_watch + 1;
    try std.testing.expectError(error.BadFilter, h.subscribe(bad));
}

test "notifier with no subscriber does nothing, non-user transactions are skipped" {
    var h = Hub.init(std.testing.allocator);
    defer h.deinit();
    var nf: Notifier = .{ .hub = &h, .key = Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(4))) catch unreachable, .epoch = .init(1) };
    var buf: [8 + 1 + 1 + 96]u8 = undefined;
    @memset(buf[0..8], 0xab);
    buf[8] = 2; // EndOfPublish
    buf[9] = 96;
    @memset(buf[10..], 0x11);
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expect(userTxDigest(arena.allocator(), &buf) == null);
    try std.testing.expect(userTxDigest(arena.allocator(), "garbage") == null);

    const sd: consensus.types.CommittedSubDag = .{
        .leader = consensus.types.BlockRef.MIN,
        .blocks = &.{},
        .timestamp_ms = 0,
        .commit_ref = .{ .index = 1, .digest = @as([32]u8, @splat(0)) },
        .decided_with_local_blocks = true,
        .recovered_rejected_transactions = false,
        .rejected_transactions_by_block = &.{},
    };
    nf.onSubDag(std.testing.allocator, &sd, .sequenced);
    _ = try h.subscribe(.{});
    nf.onSubDag(std.testing.allocator, &sd, .sequenced);
    try std.testing.expectEqual(@as(u64, 0), nf.emitted.load(.monotonic));
}
