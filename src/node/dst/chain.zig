//! The synthetic chain the node simulation tester follows: real BCS checkpoint blobs
//! (`0x01 ++ BCS(CheckpointData)`) with no transactions, certified by real BLS aggregate
//! signatures from per-epoch committees (the end-of-epoch checkpoint of epoch e carries the
//! committee of e + 1). The node under test verifies them with the production code
//! (sync.verify, sync.Committee); only the keys are ours.
//!
//! The chain is the oracle: `Chain.blob(seq)` are the bytes every honest source serves, and the
//! tester compares everything the node commits against `digest(seq)` and `contents(seq)`.
//! Forgeries (`forge`) are built here as well: a certificate by the wrong committee, a fork that
//! links elsewhere and is certified by the real committee, a replay of another sequence number.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const bls = @import("bls");
const sync = @import("sync");
const Committee = sync.Committee;

pub const max_validators = 8;

/// Most certificate verdicts a chain remembers (cleared when full).
const memo_cap = 1 << 16;

pub const Validator = struct {
    sk: bls.SecretKey,
    pk: [96]u8,
    stake: u64,
};

/// One epoch's committee with its secret keys, sorted by public key (committee index order).
pub const Epoch = struct {
    vals: []const Validator,

    pub fn keys(e: *const Epoch, gpa: std.mem.Allocator) ![][96]u8 {
        const k = try gpa.alloc([96]u8, e.vals.len);
        for (e.vals, k) |v, *o| o.* = v.pk;
        return k;
    }
    pub fn stakes(e: *const Epoch, gpa: std.mem.Allocator) ![]u64 {
        const k = try gpa.alloc(u64, e.vals.len);
        for (e.vals, k) |v, *o| o.* = v.stake;
        return k;
    }
};

pub const Params = struct {
    seed: u64,
    checkpoints: u32 = 48,
    /// Checkpoints per epoch: uniform in [epoch_min, epoch_max].
    epoch_min: u32 = 3,
    epoch_max: u32 = 9,
    validators: u32 = 4,
};

pub const Cp = struct {
    seq: u64,
    epoch: u64,
    eoe: bool,
    /// BCS of the summary, of the signature info, of the contents.
    summary: []const u8,
    sig: []const u8,
    contents: []const u8,
    blob: []const u8,
    digest: [32]u8,
};

pub const Chain = struct {
    arena: std.heap.ArenaAllocator,
    epochs: []Epoch,
    cps: []Cp,
    /// Fork: same prefix up to `fork_at - 1`, then other content signed by the real committee.
    fork: []Cp = &.{},
    fork_at: u64 = 0,
    /// Memo of certificate verdicts by (epoch, hash of summary and signature): checkCert is a
    /// pure function of those and the committee of the epoch, and the pairing dominates a run.
    memo: std.AutoHashMapUnmanaged(u128, sync.verify.Verdict) = .empty,
    memo_gpa: std.mem.Allocator,
    /// Guards `memo` (runs on several threads share a chain).
    lock: std.atomic.Value(bool) = .init(false),

    fn lockMemo(c: *Chain) void {
        while (c.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn unlockMemo(c: *Chain) void {
        c.lock.store(false, .release);
    }

    pub fn deinit(c: *Chain) void {
        const gpa = c.memo_gpa;
        c.memo.deinit(gpa);
        c.arena.deinit();
        gpa.destroy(c);
    }

    pub fn len(c: *const Chain) u64 {
        return c.cps.len;
    }

    pub fn genesisCommittee(c: *const Chain, arena: std.mem.Allocator) !Committee {
        const k = try c.epochs[0].keys(arena);
        const s = try c.epochs[0].stakes(arena);
        return Committee.init(arena, 0, k, s);
    }

    /// Signs `summary_bytes` for `epoch` with a quorum of `vals` (picked by `rnd`), returning the
    /// BCS of the AuthorityQuorumSignInfo.
    fn certify(a: std.mem.Allocator, rnd: std.Random, vals: []const Validator, epoch: u64, summary_bytes: []const u8) ![]u8 {
        const msg = try a.alloc(u8, 3 + summary_bytes.len + 8);
        defer a.free(msg);
        msg[0..3].* = .{ 2, 0, 0 };
        @memcpy(msg[3..][0..summary_bytes.len], summary_bytes);
        std.mem.writeInt(u64, msg[3 + summary_bytes.len ..][0..8], epoch, .little);
        // A random signer order; stop once the stake reaches the quorum.
        var order: [max_validators]u32 = undefined;
        for (0..vals.len) |i| order[i] = @intCast(i);
        rnd.shuffle(u32, order[0..vals.len]);
        var picked: [max_validators]u32 = undefined;
        var n: usize = 0;
        var stake: u64 = 0;
        for (order[0..vals.len]) |i| {
            picked[n] = i;
            n += 1;
            stake += vals[i].stake;
            if (stake >= sync.committee.quorum_threshold) break;
        }
        std.mem.sort(u32, picked[0..n], {}, std.sort.asc(u32));
        var sigs: [max_validators]bls.Signature = undefined;
        for (picked[0..n], 0..) |i, k| sigs[k] = vals[i].sk.sign(msg);
        const agg = bls.aggregate(sigs[0..n]) orelse return error.NoSigners;
        return encodeSigInfo(a, epoch, agg.toBytes(), picked[0..n]);
    }

    pub fn encodeSigInfo(a: std.mem.Allocator, epoch: u64, sig: [48]u8, signers: []const u32) ![]u8 {
        // RoaringBitmap, no-run cookie, one container (all signers are < 65536).
        var bm: std.ArrayList(u8) = .empty;
        defer bm.deinit(a);
        try bm.appendSlice(a, &std.mem.toBytes(@as(u32, 12346)));
        if (signers.len == 0) {
            try bm.appendSlice(a, &std.mem.toBytes(@as(u32, 0)));
        } else {
            try bm.appendSlice(a, &std.mem.toBytes(@as(u32, 1)));
            try bm.appendSlice(a, &std.mem.toBytes(@as(u16, 0)));
            try bm.appendSlice(a, &std.mem.toBytes(@as(u16, @intCast(signers.len - 1))));
            try bm.appendSlice(a, &std.mem.toBytes(@as(u32, 16)));
            for (signers) |s| try bm.appendSlice(a, &std.mem.toBytes(@as(u16, @intCast(s))));
        }
        const info: types.gen.AuthorityQuorumSignInfo = .{ .epoch = epoch, .signature = sig, .signers_map = .{ .@"0" = bm.items } };
        return bcs.encodeAlloc(types.gen.AuthorityQuorumSignInfo, a, &info);
    }

    /// One checkpoint blob: summary (`prev` links it), contents, certificate by `vals` for
    /// `cert_epoch`.
    fn make(a: std.mem.Allocator, rnd: std.Random, o: struct {
        seq: u64,
        epoch: u64,
        prev: ?[32]u8,
        ts: u64,
        next: ?[]const Validator,
        cert_vals: []const Validator,
        cert_epoch: u64,
    }) !Cp {
        const contents_v: types.gen.CheckpointContents = .{ .V1 = .{ .transactions = &.{}, .user_signatures = &.{} } };
        const contents = try bcs.encodeAlloc(types.gen.CheckpointContents, a, &contents_v);
        const cdig = hash.blake2b256(&.{ "CheckpointContents::", contents });
        var members: []struct { types.hand.AuthorityPublicKeyBytes, u64 } = &.{};
        if (o.next) |nv| {
            members = try a.alloc(struct { types.hand.AuthorityPublicKeyBytes, u64 }, nv.len);
            for (nv, members) |v, *m| m.* = .{ .{ .@"0" = v.pk }, v.stake };
        }
        const sum: types.gen.CheckpointSummary = .{
            .epoch = o.epoch,
            .sequence_number = o.seq,
            .network_total_transactions = o.seq,
            .content_digest = .{ .@"0" = .{ .@"0" = cdig } },
            .previous_digest = if (o.prev) |p| .{ .@"0" = .{ .@"0" = p } } else null,
            .epoch_rolling_gas_cost_summary = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
            .timestamp_ms = o.ts,
            .checkpoint_commitments = &.{},
            .end_of_epoch_data = if (o.next != null) .{ .nextEpochCommittee = members, .nextEpochProtocolVersion = .{ .@"0" = 1 }, .epochCommitments = &.{} } else null,
            .version_specific_data = &.{},
        };
        const sb = try bcs.encodeAlloc(types.gen.CheckpointSummary, a, &sum);
        const sg = try certify(a, rnd, o.cert_vals, o.cert_epoch, sb);
        var blob: std.ArrayList(u8) = .empty;
        try blob.append(a, 1);
        try blob.appendSlice(a, sb);
        try blob.appendSlice(a, sg);
        try blob.appendSlice(a, contents);
        try blob.append(a, 0); // no transactions
        return .{
            .seq = o.seq,
            .epoch = o.epoch,
            .eoe = o.next != null,
            .summary = sb,
            .sig = sg,
            .contents = contents,
            .blob = blob.items,
            .digest = hash.blake2b256(&.{ "CheckpointSummary::", sb }),
        };
    }

    fn makeEpoch(a: std.mem.Allocator, rnd: std.Random, n: u32) !Epoch {
        const vals = try a.alloc(Validator, n);
        // Stakes: random, each at least 1, summing to 10000.
        var left: u64 = sync.committee.total_voting_power - n;
        for (vals, 0..) |*v, i| {
            const take = if (i + 1 == n) left else rnd.uintAtMost(u64, left / 2 + left / 4);
            left -= take;
            v.stake = 1 + take;
            while (true) {
                var kb: [32]u8 = undefined;
                rnd.bytes(&kb);
                kb[0] = 0; // below r
                if (bls.SecretKey.fromBytes(&kb)) |sk| {
                    v.sk = sk;
                    v.pk = sk.publicKey().toBytes();
                    break;
                }
            }
        }
        std.mem.sort(Validator, vals, {}, struct {
            fn lt(_: void, x: Validator, y: Validator) bool {
                return std.mem.order(u8, &x.pk, &y.pk) == .lt;
            }
        }.lt);
        return .{ .vals = vals };
    }

    /// Generates a chain of `p.checkpoints` checkpoints from seed `p.seed`.
    pub fn generate(gpa: std.mem.Allocator, p: Params) !*Chain {
        const c = try gpa.create(Chain);
        errdefer gpa.destroy(c);
        c.* = .{ .arena = .init(gpa), .epochs = &.{}, .cps = &.{}, .memo_gpa = gpa };
        errdefer c.arena.deinit();
        const a = c.arena.allocator();
        var prng: std.Random.DefaultPrng = .init(p.seed ^ 0xc4a1_2e00);
        const rnd = prng.random();
        // Epoch boundaries first, then one committee per epoch.
        var ends: std.ArrayList(u64) = .empty; // last seq of each epoch
        var at: u64 = 0;
        while (at < p.checkpoints) {
            at += rnd.intRangeAtMost(u32, p.epoch_min, p.epoch_max);
            try ends.append(a, at - 1);
        }
        const n_ep = ends.items.len;
        c.epochs = try a.alloc(Epoch, n_ep + 1);
        for (c.epochs) |*e| e.* = try makeEpoch(a, rnd, p.validators);
        c.cps = try a.alloc(Cp, p.checkpoints);
        var epoch: u64 = 0;
        var prev: ?[32]u8 = null;
        var ts: u64 = 1_700_000_000_000;
        for (c.cps, 0..) |*cp, i| {
            const eoe = ends.items[epoch] == i;
            ts += 200 + rnd.uintAtMost(u64, 100);
            cp.* = try make(a, rnd, .{
                .seq = i,
                .epoch = epoch,
                .prev = prev,
                .ts = ts,
                .next = if (eoe) c.epochs[epoch + 1].vals else null,
                .cert_vals = c.epochs[epoch].vals,
                .cert_epoch = epoch,
            });
            prev = cp.digest;
            if (eoe) epoch += 1;
        }
        // A fork from the middle of the chain, certified by the real committee of each epoch.
        if (p.checkpoints >= 6) {
            const f: u64 = 2 + rnd.uintLessThan(u64, p.checkpoints - 4);
            c.fork_at = f;
            c.fork = try a.alloc(Cp, p.checkpoints - f);
            var fp: ?[32]u8 = c.cps[f - 1].digest;
            var fe = c.cps[f].epoch;
            for (c.fork, 0..) |*cp, k| {
                const seq = f + k;
                const eoe_f = c.cps[seq].eoe;
                ts = 1_700_100_000_000 + seq * 777;
                cp.* = try make(a, rnd, .{
                    .seq = seq,
                    .epoch = fe,
                    .prev = fp,
                    .ts = ts,
                    .next = if (eoe_f) c.epochs[fe + 1].vals else null,
                    .cert_vals = c.epochs[fe].vals,
                    .cert_epoch = fe,
                });
                fp = cp.digest;
                if (eoe_f) fe += 1;
            }
        }
        return c;
    }

    pub const Forgery = enum {
        /// Valid summary, certified by a committee the node does not know (random keys).
        unknown_committee,
        /// Valid summary, certified by another epoch's committee, claiming this epoch.
        other_epoch_keys,
        /// The fork's checkpoint (links elsewhere, real committee), only from `fork_at + 1`.
        fork,
        /// A genuine blob of another sequence number.
        replay,
        /// Genuine but the signature info truncated.
        short_sig,
        /// Genuine summary and contents, signers bitmap emptied.
        no_signers,
    };

    /// A forged blob for `seq` (allocated from `a`), or null when the kind does not apply.
    pub fn forge(c: *Chain, a: std.mem.Allocator, rnd: std.Random, kind: Forgery, seq: u64) !?[]const u8 {
        const cp = c.cps[seq];
        switch (kind) {
            .fork => {
                if (c.fork.len == 0 or seq <= c.fork_at) return null;
                return c.fork[seq - c.fork_at].blob;
            },
            .replay => {
                if (c.cps.len < 2) return null;
                var o = rnd.uintLessThan(u64, c.cps.len);
                if (o == seq) o = (o + 1) % c.cps.len;
                return c.cps[o].blob;
            },
            .unknown_committee => {
                const ep = try makeEpoch(a, rnd, 4);
                return try c.resign(a, rnd, seq, ep.vals, cp.epoch);
            },
            .other_epoch_keys => {
                if (c.epochs.len < 2) return null;
                const other = (cp.epoch + 1) % c.epochs.len;
                return try c.resign(a, rnd, seq, c.epochs[other].vals, cp.epoch);
            },
            .short_sig => {
                const cut = cp.blob.len - cp.contents.len - 1;
                const out = try a.alloc(u8, cp.blob.len - 5);
                @memcpy(out[0 .. cut - 5], cp.blob[0 .. cut - 5]);
                @memcpy(out[cut - 5 ..], cp.blob[cut..]);
                return out;
            },
            .no_signers => {
                const sg = try encodeSigInfo(a, cp.epoch, (bls.Signature.decode(cp.sig[8..56]) orelse return null).toBytes(), &.{});
                var b: std.ArrayList(u8) = .empty;
                try b.append(a, 1);
                try b.appendSlice(a, cp.summary);
                try b.appendSlice(a, sg);
                try b.appendSlice(a, cp.contents);
                try b.append(a, 0);
                return b.items;
            },
        }
    }

    fn resign(c: *Chain, a: std.mem.Allocator, rnd: std.Random, seq: u64, vals: []const Validator, claim_epoch: u64) ![]const u8 {
        const cp = c.cps[seq];
        const sg = try certify(a, rnd, vals, claim_epoch, cp.summary);
        var b: std.ArrayList(u8) = .empty;
        try b.append(a, 1);
        try b.appendSlice(a, cp.summary);
        try b.appendSlice(a, sg);
        try b.appendSlice(a, cp.contents);
        try b.append(a, 0);
        return b.items;
    }

    /// Certificate verdict, memoised (see `memo`).
    pub fn checkCert(c: *Chain, use_memo: bool, scratch: std.mem.Allocator, committee: *const Committee, epoch: u64, summary: []const u8, sig: []const u8) !sync.verify.Verdict {
        if (!use_memo) return try sync.verify.checkCert(scratch, committee, epoch, summary, sig);
        var h: std.hash.Wyhash = .init(epoch ^ committee.epoch << 32);
        h.update(summary);
        h.update(std.mem.asBytes(&summary.len));
        h.update(sig);
        // Distinct committees of the same epoch number cannot occur in one chain (one per epoch).
        const key: u128 = (@as(u128, h.final()) << 64) | (std.hash.Wyhash.hash(0x5eed, sig) ^ (@as(u64, committee.keys.len) << 56) ^ committee.keys[0][0]);
        c.lockMemo();
        const hit = c.memo.get(key);
        c.unlockMemo();
        if (hit) |v| {
            // The real check allocates its message buffer from `scratch` once it gets past the
            // cheap rules; do the same here so the allocation pattern (and with it the OOM
            // schedule of a run) does not depend on how warm the memo is.
            switch (v) {
                .decode, .epoch_mismatch, .bad_bitmap, .insufficient_stake => {},
                else => _ = try scratch.alloc(u8, 3 + summary.len + 8),
            }
            return v;
        }
        const v = try sync.verify.checkCert(scratch, committee, epoch, summary, sig);
        c.lockMemo();
        defer c.unlockMemo();
        // Bounded: forgeries signed with fresh random keys never hit again.
        if (c.memo.count() >= memo_cap) c.memo.clearRetainingCapacity();
        try c.memo.put(c.memo_gpa, key, v);
        return v;
    }
};

test "generated chain verifies with the production checks" {
    const gpa = std.testing.allocator;
    const c = try Chain.generate(gpa, .{ .seed = 1, .checkpoints = 14 });
    defer c.deinit();
    var arena_s: std.heap.ArenaAllocator = .init(gpa);
    defer arena_s.deinit();
    const arena = arena_s.allocator();
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var committee = try c.genesisCommittee(arena);
    var prev: ?[32]u8 = null;
    var epoch: u64 = 0;
    for (c.cps) |cp| {
        const v = try sync.verify.full(arena, cp.blob, &idx, &committee, prev);
        try std.testing.expectEqualStrings("ok", v.name());
        prev = cp.digest;
        if (cp.eoe) {
            epoch += 1;
            const k = try c.epochs[epoch].keys(arena);
            const s = try c.epochs[epoch].stakes(arena);
            committee = try Committee.init(arena, epoch, k, s);
        }
    }
}

test "forgeries are rejected" {
    const gpa = std.testing.allocator;
    const c = try Chain.generate(gpa, .{ .seed = 2, .checkpoints = 14 });
    defer c.deinit();
    var arena_s: std.heap.ArenaAllocator = .init(gpa);
    defer arena_s.deinit();
    const arena = arena_s.allocator();
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var prng: std.Random.DefaultPrng = .init(7);
    const rnd = prng.random();
    const committee = try c.genesisCommittee(arena);
    // Checkpoint 1 is in epoch 0 (epochs have at least 3 checkpoints).
    for (std.enums.values(Chain.Forgery)) |kind| {
        if (try c.forge(arena, rnd, kind, 1)) |b| {
            const v = try sync.verify.full(arena, b, &idx, &committee, c.cps[0].digest);
            if (v == .ok) {
                std.debug.print("forgery {t} accepted\n", .{kind});
                return error.ForgeryAccepted;
            }
        }
    }
}

test "a run's trace does not depend on how warm the certificate memo is" {
    const gpa = std.testing.allocator;
    const run = @import("run.zig");
    const c = try Chain.generate(gpa, .{ .seed = 11, .checkpoints = 20 });
    defer c.deinit();
    const cold = try run.run(gpa, .{ .seed = 77, .chain = c });
    var k: u64 = 100;
    while (k < 104) : (k += 1) _ = try run.run(gpa, .{ .seed = k, .chain = c });
    const warm = try run.run(gpa, .{ .seed = 77, .chain = c });
    try std.testing.expectEqual(cold.trace, warm.trace);
    try std.testing.expectEqual(cold.commits, warm.commits);
    try std.testing.expectEqual(cold.oom_exits, warm.oom_exits);
}
