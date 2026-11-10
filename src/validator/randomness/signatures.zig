//! The round signature collector: the protocol logic of sui-network `randomness/mod.rs`
//! (RandomnessEventLoop) without the anemo transport. Each validator sends its partial
//! signatures for every requested round to all peers (`SendSignatures`), records the ones it
//! receives, and as soon as `t` valid partials (or one valid full signature) are in, recovers
//! the round's full BLS signature, whose 48 bytes are the round's randomness.
//!
//! The transport (anemo p2p, resend every `partial_signature_retry_interval`) is a thin shell
//! around this: it feeds `receivePartial` / `receiveFull`, drains `events`, and builds the
//! outgoing request with `requestFor(round)`. Peers are party ids (the transport maps its peer
//! ids); round numbers are the beacon rounds.
const std = @import("std");
const group = @import("group.zig");
const wire = @import("wire.zig");
const poly = @import("poly.zig");
const tbls = @import("tbls.zig");
const nodes_mod = @import("nodes.zig");
const SecureRandom = @import("secure.zig").SecureRandom;
const G1P = group.G1P;
const G2P = group.G2P;

pub const Config = struct {
    /// RandomnessConfig defaults at 1.83.1.
    max_partial_sigs_rounds_ahead: u64 = 50,
    max_partial_sigs_concurrent_sends: usize = 20,
    partial_signature_retry_interval_ms: u64 = 5_000,
    max_ignored_peer_weight_factor: f64 = 0.2,
};

pub const Event = union(enum) {
    /// Start (or continue) sending this round's partial signatures to all peers.
    start_sending: u64,
    /// The full signature of a round is ready: hand `bytes` (BCS of the G1 element, the
    /// RandomnessStateUpdate random_bytes) to the state update builder.
    signature: struct { epoch: u64, round: u64, bytes: [48]u8 },
    /// A peer sent invalid signatures; the transport should stop talking to it.
    ignore_peer: u16,
};

pub const Error = error{ InvalidRequest, OutOfMemory } || wire.Error;

const RoundState = struct {
    partials: []?[]tbls.PartialSignature, // per party id
    completed: ?G1P = null,
    sending: bool = false,
};

pub const Collector = struct {
    gpa: std.mem.Allocator,
    cfg: Config,
    epoch: u64 = 0,
    own_id: ?u16 = null,
    threshold: u16 = 0,
    ready: bool = false, // DKG output installed for `epoch`
    vss_pk: []G2P = &.{},
    ranges: []nodes_mod.ShareRange = &.{},
    total_weight: u16 = 0,
    own_shares: []poly.Share = &.{},
    blocked: []bool = &.{},
    blocked_shares: usize = 0,
    highest_requested: ?u64 = null,
    highest_completed: ?u64 = null,
    rounds: std.AutoArrayHashMapUnmanaged(u64, RoundState) = .empty,
    /// Partial signatures received for epoch + 1 before our DKG output is installed.
    future: std.ArrayList(Future) = .empty,
    events: std.ArrayList(Event) = .empty,
    /// Test-only deterministic rng; production uses `io.randomSecure`.
    test_rng: ?std.Random = null,
    io: ?std.Io = null,
    /// A local request for a later epoch, held until `updateEpoch` installs that epoch.
    future_request: ?struct { epoch: u64, round: u64 } = null,

    const Future = struct { peer: u16, epoch: u64, round: u64, sigs: [][]u8 };

    pub fn init(gpa: std.mem.Allocator, cfg: Config, io: std.Io) Collector {
        return .{ .gpa = gpa, .cfg = cfg, .io = io };
    }

    /// Test-only: deterministic rng for the batch-verification weights.
    pub fn initForTesting(gpa: std.mem.Allocator, cfg: Config, rng: std.Random) Collector {
        return .{ .gpa = gpa, .cfg = cfg, .test_rng = rng };
    }

    pub fn deinit(c: *Collector) void {
        c.clearEpochState();
        for (c.future.items) |f| freeFuture(c.gpa, f);
        c.future.deinit(c.gpa);
        c.events.deinit(c.gpa);
        c.rounds.deinit(c.gpa);
    }

    fn freeFuture(gpa: std.mem.Allocator, f: Future) void {
        for (f.sigs) |s| gpa.free(s);
        gpa.free(f.sigs);
    }

    fn freeRound(c: *Collector, rs: *RoundState) void {
        for (rs.partials) |p| if (p) |x| c.gpa.free(x);
        c.gpa.free(rs.partials);
    }

    fn clearEpochState(c: *Collector) void {
        for (c.rounds.values()) |*rs| c.freeRound(rs);
        c.rounds.clearRetainingCapacity();
        c.gpa.free(c.vss_pk);
        c.gpa.free(c.ranges);
        c.gpa.free(c.own_shares);
        c.gpa.free(c.blocked);
        c.vss_pk = &.{};
        c.ranges = &.{};
        c.own_shares = &.{};
        c.blocked = &.{};
    }

    pub fn drainEvents(c: *Collector, out: *std.ArrayList(Event)) !void {
        try out.appendSlice(c.gpa, c.events.items);
        c.events.clearRetainingCapacity();
    }

    // ------------------------------------------------------------------------- epoch

    /// `update_epoch`: the DKG of `new_epoch` finished. `ranges` are the share ranges per party
    /// (Nodes.shareRange), `own_shares` this validator's shares (empty for no shares).
    pub fn updateEpoch(
        c: *Collector,
        new_epoch: u64,
        own_id: ?u16,
        vss_pk: []const G2P,
        ranges: []const nodes_mod.ShareRange,
        total_weight: u16,
        own_shares: []const poly.Share,
        threshold: u16,
        recovered_highest_completed: ?u64,
    ) Error!void {
        if (vss_pk.len == 0) return error.InvalidRequest;
        c.clearEpochState();
        c.epoch = new_epoch;
        c.own_id = own_id;
        c.threshold = threshold;
        c.vss_pk = try c.gpa.dupe(G2P, vss_pk);
        c.ranges = try c.gpa.dupe(nodes_mod.ShareRange, ranges);
        c.own_shares = try c.gpa.dupe(poly.Share, own_shares);
        c.blocked = try c.gpa.alloc(bool, ranges.len);
        @memset(c.blocked, false);
        c.blocked_shares = 0;
        c.total_weight = total_weight;
        c.ready = true;
        c.highest_completed = recovered_highest_completed;
        c.highest_requested = null;
        if (c.future_request) |fr| {
            if (fr.epoch == new_epoch) c.highest_requested = fr.round;
            if (fr.epoch <= new_epoch) c.future_request = null;
        }
        try c.maybeStartPendingTasks();
        // aggregate anything received early for this epoch
        const pending = c.future;
        c.future = .empty;
        defer c.gpa.free(pending.items.ptr[0..pending.capacity]);
        for (pending.items) |f| {
            defer freeFuture(c.gpa, f);
            try c.receivePartial(f.peer, f.epoch, f.round, f.sigs);
        }
        var keys: std.ArrayList(u64) = .empty;
        defer keys.deinit(c.gpa);
        try keys.appendSlice(c.gpa, c.rounds.keys());
        for (keys.items) |r| try c.maybeAggregate(new_epoch, r);
    }

    // ------------------------------------------------------------------------- local requests

    /// `send_partial_signatures`: the consensus handler reserved `round`.
    pub fn sendPartialSignatures(c: *Collector, epoch: u64, round: u64) Error!void {
        if (c.ready and epoch < c.epoch) return;
        if (epoch > c.epoch) {
            // hold the request until that epoch's output is installed (Rust keeps per-epoch rounds)
            if (c.future_request) |fr| {
                if (fr.epoch > epoch or (fr.epoch == epoch and fr.round >= round)) return;
            }
            c.future_request = .{ .epoch = epoch, .round = round };
            return;
        }
        if (epoch == c.epoch and c.highest_completed != null and round <= c.highest_completed.?) return;
        if (c.highest_requested == null or round > c.highest_requested.?) c.highest_requested = round;
        try c.maybeStartPendingTasks();
    }

    /// `complete_round`: the round's RandomnessStateUpdate is in a checkpoint.
    pub fn completeRound(c: *Collector, epoch: u64, round: u64) Error!void {
        if (epoch != c.epoch) return;
        if (c.highest_completed == null or round > c.highest_completed.?) c.highest_completed = round else return;
        var i: usize = 0;
        while (i < c.rounds.count()) {
            if (c.rounds.keys()[i] <= round) {
                var rs = c.rounds.values()[i];
                c.freeRound(&rs);
                c.rounds.swapRemoveAt(i);
            } else i += 1;
        }
        try c.maybeStartPendingTasks();
    }

    fn roundState(c: *Collector, round: u64) Error!*RoundState {
        const gop = try c.rounds.getOrPut(c.gpa, round);
        if (!gop.found_existing) {
            const p = try c.gpa.alloc(?[]tbls.PartialSignature, c.ranges.len);
            @memset(p, null);
            gop.value_ptr.* = .{ .partials = p };
        }
        return gop.value_ptr;
    }

    fn sendingCount(c: *const Collector) usize {
        var n: usize = 0;
        for (c.rounds.values()) |rs| if (rs.sending) {
            n += 1;
        };
        return n;
    }

    fn rngFor(c: *const Collector, sr: *SecureRandom) std.Random {
        if (c.test_rng) |r| return r;
        sr.* = .{ .io = c.io.? };
        return sr.interface();
    }

    fn maybeStartPendingTasks(c: *Collector) Error!void {
        if (!c.ready or c.own_shares.len == 0) return;
        const highest = c.highest_requested orelse return;
        var start: u64 = if (c.highest_completed) |h| h + 1 else 0;
        // after the most recent started round
        for (c.rounds.keys(), c.rounds.values()) |r, rs| if (rs.sending and r + 1 > start) {
            start = r + 1;
        };
        var round = start;
        var started: std.ArrayList(u64) = .empty;
        defer started.deinit(c.gpa);
        while (round <= highest) : (round += 1) {
            if (c.sendingCount() >= c.cfg.max_partial_sigs_concurrent_sends) break;
            const rs = try c.roundState(round);
            if (rs.sending) continue;
            rs.sending = true;
            var arena = std.heap.ArenaAllocator.init(c.gpa);
            defer arena.deinit();
            const msg = tbls.roundMessage(round);
            const own = try tbls.partialSignBatch(arena.allocator(), c.own_shares, &msg);
            if (rs.completed == null and c.own_id != null) {
                const slot = &rs.partials[c.own_id.?];
                if (slot.*) |old| c.gpa.free(old);
                slot.* = try c.gpa.dupe(tbls.PartialSignature, own);
                try started.append(c.gpa, round);
            }
            try c.events.append(c.gpa, .{ .start_sending = round });
        }
        for (started.items) |r| try c.maybeAggregate(c.epoch, r);
    }

    // ------------------------------------------------------------------------- receive

    /// `receive_partial_signatures`: `sig_bytes` are the BCS partial signatures of one peer.
    pub fn receivePartial(c: *Collector, peer: u16, epoch: u64, round: u64, sig_bytes: []const []const u8) Error!void {
        if (epoch < c.epoch) return;
        if (epoch > c.epoch + 1) return;
        if (c.ready and epoch == c.epoch) {
            if (c.rounds.get(round)) |rs| if (rs.completed != null) return;
        }
        // Rust reads `highest_completed_round.get(&epoch)`: the completed round of the epoch the
        // sigs are for. Ours is only known for `c.epoch`; early sigs for epoch + 1 must not be
        // compared against this epoch's progress.
        if (epoch == c.epoch) if (c.highest_completed) |h| if (h >= round) return;
        if (epoch != c.epoch or !c.ready) {
            if (round >= c.cfg.max_partial_sigs_rounds_ahead) return;
            // keep one entry per (epoch, round, peer)
            for (c.future.items) |*f| if (f.peer == peer and f.epoch == epoch and f.round == round) {
                freeFuture(c.gpa, f.*);
                f.sigs = try dupeAll(c.gpa, sig_bytes);
                return;
            };
            try c.future.append(c.gpa, .{ .peer = peer, .epoch = epoch, .round = round, .sigs = try dupeAll(c.gpa, sig_bytes) });
            return;
        }
        if (peer >= c.ranges.len) return;
        const expected = c.ranges[peer];
        if (sig_bytes.len != expected.count) return;
        var last_completed: u64 = c.highest_completed orelse 0;
        for (c.rounds.keys(), c.rounds.values()) |r, rs| if (rs.completed != null and r > last_completed) {
            last_completed = r;
        };
        if (round >= last_completed +| c.cfg.max_partial_sigs_rounds_ahead) return;

        const parsed = try c.gpa.alloc(tbls.PartialSignature, sig_bytes.len);
        errdefer c.gpa.free(parsed);
        for (sig_bytes, parsed, 0..) |b, *p, i| {
            p.* = tbls.PartialSignature.fromBytes(b) catch {
                c.gpa.free(parsed);
                return; // undecodable: dropped like Rust ("failed to deserialize partial sigs")
            };
            // the share ids must be exactly the peer's range, in order
            if (p.index != expected.first + @as(u16, @intCast(i))) {
                c.gpa.free(parsed);
                return;
            }
        }
        const rs = try c.roundState(round);
        if (rs.partials[peer]) |old| c.gpa.free(old);
        rs.partials[peer] = parsed;
        try c.maybeAggregate(epoch, round);
    }

    /// `receive_full_signature`: verify against the DKG public key and complete the round.
    pub fn receiveFull(c: *Collector, peer: u16, epoch: u64, round: u64, sig: G1P) Error!void {
        if (!c.ready or epoch != c.epoch) return;
        if (c.rounds.get(round)) |rs| if (rs.completed != null) return;
        if (c.highest_completed) |h| if (h >= round) return;
        const req = c.highest_requested orelse return;
        if (round > req) return;
        const msg = tbls.roundMessage(round);
        tbls.verify(c.vss_pk[0], &msg, sig) catch {
            try c.maybeIgnorePeer(peer);
            return;
        };
        try c.processValidFull(epoch, round, sig);
    }

    fn processValidFull(c: *Collector, epoch: u64, round: u64, sig: G1P) Error!void {
        const rs = try c.roundState(round);
        rs.completed = sig;
        for (rs.partials) |*p| if (p.*) |x| {
            c.gpa.free(x);
            p.* = null;
        };
        try c.events.append(c.gpa, .{ .signature = .{ .epoch = epoch, .round = round, .bytes = group.g1ToBytes(sig) } });
    }

    fn maybeAggregate(c: *Collector, epoch: u64, round: u64) Error!void {
        if (c.highest_completed) |h| if (round <= h) return;
        const req = c.highest_requested orelse return;
        if (round > req) return; // wait until local consensus catches up
        if (epoch != c.epoch or !c.ready) return;
        const rs = c.rounds.getPtr(round) orelse return;
        if (rs.completed != null) return;

        var arena = std.heap.ArenaAllocator.init(c.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const msg = tbls.roundMessage(round);
        var all = try c.flatten(a, rs);
        var sig = tbls.aggregate(a, c.threshold, all) catch |e| switch (e) {
            error.NotEnoughInputs => return,
            else => return,
        };
        var sr: SecureRandom = undefined;
        if (tbls.verify(c.vss_pk[0], &msg, sig)) |_| {} else |_| {
            // some inputs are invalid: find the bad peers one by one and drop them
            for (rs.partials, 0..) |*slot, peer| {
                const sigs = slot.* orelse continue;
                if (tbls.partialVerifyBatch(a, c.vss_pk, &msg, sigs, c.rngFor(&sr))) |_| {} else |_| {
                    c.gpa.free(sigs);
                    slot.* = null;
                    try c.maybeIgnorePeer(@intCast(peer));
                }
            }
            all = try c.flatten(a, rs);
            sig = tbls.aggregate(a, c.threshold, all) catch return;
            tbls.verify(c.vss_pk[0], &msg, sig) catch return;
        }
        try c.processValidFull(epoch, round, sig);
    }

    fn flatten(c: *Collector, a: std.mem.Allocator, rs: *const RoundState) Error![]tbls.PartialSignature {
        _ = c;
        var out: std.ArrayList(tbls.PartialSignature) = .empty;
        for (rs.partials) |p| if (p) |x| try out.appendSlice(a, x);
        return out.items;
    }

    fn maybeIgnorePeer(c: *Collector, peer: u16) Error!void {
        if (!c.ready or peer >= c.ranges.len or c.blocked[peer]) return;
        const count = c.ranges[peer].count;
        const max_ignored: usize = @intFromFloat(c.cfg.max_ignored_peer_weight_factor * @as(f64, @floatFromInt(c.total_weight)));
        if (c.blocked_shares + count > max_ignored) return;
        c.blocked_shares += count;
        c.blocked[peer] = true;
        try c.events.append(c.gpa, .{ .ignore_peer = peer });
    }

    pub fn isBlocked(c: *const Collector, peer: u16) bool {
        return peer < c.blocked.len and c.blocked[peer];
    }

    // ------------------------------------------------------------------------- outgoing

    /// The `SendSignaturesRequest` BCS for a round we are sending: the partial signatures, or
    /// the full signature once the round is aggregated. Caller frees.
    pub fn requestFor(c: *Collector, round: u64) Error!?[]u8 {
        const rs = c.rounds.getPtr(round) orelse return null;
        if (!rs.sending) return null;
        var w = wire.Writer.init(c.gpa);
        errdefer w.deinit();
        try w.u64_(c.epoch);
        try w.u64_(round);
        if (rs.completed) |sig| {
            try w.uleb(0);
            try w.u8_(1);
            try w.g1(sig);
        } else {
            var arena = std.heap.ArenaAllocator.init(c.gpa);
            defer arena.deinit();
            const msg = tbls.roundMessage(round);
            const own = try tbls.partialSignBatch(arena.allocator(), c.own_shares, &msg);
            try w.uleb(own.len);
            for (own) |*p| try w.bytesVec(&p.toBytes());
            try w.u8_(0);
        }
        return try w.toOwnedSlice();
    }
};

fn dupeAll(gpa: std.mem.Allocator, items: []const []const u8) ![][]u8 {
    const out = try gpa.alloc([]u8, items.len);
    var n: usize = 0;
    errdefer {
        for (out[0..n]) |x| gpa.free(x);
        gpa.free(out);
    }
    for (items, out) |s, *d| {
        d.* = try gpa.dupe(u8, s);
        n += 1;
    }
    return out;
}

/// `SendSignaturesRequest { epoch, round, partial_sigs: Vec<Vec<u8>>, sig: Option<G1> }`.
pub const SendSignaturesRequest = struct {
    epoch: u64,
    round: u64,
    partial_sigs: [][]const u8,
    sig: ?G1P,

    /// `arena` owns the returned slices.
    pub fn decode(arena: std.mem.Allocator, bytes: []const u8) wire.Error!SendSignaturesRequest {
        var r = wire.Reader.init(bytes);
        const epoch = try r.u64_();
        const round = try r.u64_();
        const n = try r.seqLen(1);
        if (n > 4096) return error.TooLarge;
        const ps = try arena.alloc([]const u8, n);
        for (ps) |*p| {
            const len = try r.seqLen(1);
            p.* = try r.take(len);
        }
        const sig: ?G1P = switch (try r.u8_()) {
            0 => null,
            1 => try r.g1(),
            else => return error.InvalidEncoding,
        };
        try r.finish();
        return .{ .epoch = epoch, .round = round, .partial_sigs = ps, .sig = sig };
    }
};

test "collector aggregates partials from four parties and ignores a bad peer" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(77);
    const rng = prng.random();
    const t: u16 = 3;
    const sk = try poly.randPrivate(a, t - 1, rng);
    const vss = try poly.commit(a, sk);
    // 4 parties, weights 2,1,1,2 -> share ids 1-2, 3, 4, 5-6
    const ranges = [_]nodes_mod.ShareRange{ .{ .first = 1, .count = 2 }, .{ .first = 3, .count = 1 }, .{ .first = 4, .count = 1 }, .{ .first = 5, .count = 2 } };
    var own: [2]poly.Share = .{ .{ .index = 1, .value = poly.evalPrivate(sk, 1) }, .{ .index = 2, .value = poly.evalPrivate(sk, 2) } };

    var col = Collector.initForTesting(gpa, .{}, rng);
    defer col.deinit();
    try col.updateEpoch(9, 0, vss, &ranges, 6, &own, t, null);
    try col.sendPartialSignatures(9, 0);
    // own 2 partials are not enough (t = 3)
    var evs: std.ArrayList(Event) = .empty;
    defer evs.deinit(gpa);
    try col.drainEvents(&evs);
    try std.testing.expect(evs.items.len == 1 and evs.items[0] == .start_sending);
    evs.clearRetainingCapacity();

    const msg = tbls.roundMessage(0);
    // party 1 sends a corrupted partial
    const bad = tbls.partialSign(.{ .index = 3, .value = poly.evalPrivate(sk, 3).add(@TypeOf(sk[0]).one) }, &msg);
    const badb = bad.toBytes();
    try col.receivePartial(1, 9, 0, &.{&badb});
    try col.drainEvents(&evs);
    // 3 partials now but the aggregate fails verification: the bad peer is found and dropped
    try std.testing.expect(evs.items.len == 1 and evs.items[0] == .ignore_peer and evs.items[0].ignore_peer == 1);
    evs.clearRetainingCapacity();
    // a good party-2 partial completes it
    const good = tbls.partialSign(.{ .index = 4, .value = poly.evalPrivate(sk, 4) }, &msg);
    const goodb = good.toBytes();
    try col.receivePartial(2, 9, 0, &.{&goodb});
    try col.drainEvents(&evs);
    try std.testing.expect(evs.items.len == 1 and evs.items[0] == .signature);
    const sig = group.g1FromBytes(&evs.items[0].signature.bytes).?;
    try tbls.verify(vss[0], &msg, sig);
    // the outgoing request now carries the full signature and decodes
    const req = (try col.requestFor(0)).?;
    defer gpa.free(req);
    const dec = try SendSignaturesRequest.decode(a, req);
    try std.testing.expect(dec.sig != null and dec.partial_sigs.len == 0);
    try col.completeRound(9, 0);
    try std.testing.expect((try col.requestFor(0)) == null);
}

test "early partials for the next epoch are kept even when this epoch completed later rounds" {
    // receive_partial_signatures compares against highest_completed_round.get(&epoch) of the
    // incoming epoch; epoch 9 having completed round 30 must not drop epoch 10 round 2.
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(78);
    const rng = prng.random();
    const t: u16 = 3;
    const ranges = [_]nodes_mod.ShareRange{ .{ .first = 1, .count = 2 }, .{ .first = 3, .count = 1 }, .{ .first = 4, .count = 1 }, .{ .first = 5, .count = 2 } };
    const sk9 = try poly.randPrivate(a, t - 1, rng);
    var own9: [2]poly.Share = .{ .{ .index = 1, .value = poly.evalPrivate(sk9, 1) }, .{ .index = 2, .value = poly.evalPrivate(sk9, 2) } };
    var col = Collector.initForTesting(gpa, .{}, rng);
    defer col.deinit();
    try col.updateEpoch(9, 0, try poly.commit(a, sk9), &ranges, 6, &own9, t, 30);

    // epoch 10: a peer already sends round 2 before our DKG of epoch 10 completes
    const sk10 = try poly.randPrivate(a, t - 1, rng);
    const msg = tbls.roundMessage(2);
    const p3 = tbls.partialSign(.{ .index = 4, .value = poly.evalPrivate(sk10, 4) }, &msg).toBytes();
    try col.receivePartial(2, 10, 2, &.{&p3});
    try std.testing.expectEqual(@as(usize, 1), col.future.items.len);

    // epoch 10 installed and round 2 requested: our 2 shares + the early one reach t
    var own10: [2]poly.Share = .{ .{ .index = 1, .value = poly.evalPrivate(sk10, 1) }, .{ .index = 2, .value = poly.evalPrivate(sk10, 2) } };
    const vss10 = try poly.commit(a, sk10);
    try col.sendPartialSignatures(10, 2);
    try col.updateEpoch(10, 0, vss10, &ranges, 6, &own10, t, null);
    var evs: std.ArrayList(Event) = .empty;
    defer evs.deinit(gpa);
    try col.drainEvents(&evs);
    var got_sig = false;
    for (evs.items) |e| if (e == .signature and e.signature.epoch == 10 and e.signature.round == 2) {
        got_sig = true;
        try tbls.verify(vss10[0], &msg, group.g1FromBytes(&e.signature.bytes).?);
    };
    try std.testing.expect(got_sig);
}
