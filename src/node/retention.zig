//! Retention as sui-node 1.83.1 computes it (crates/sui-core/src/authority/authority_store_pruner.rs,
//! CONTRACTS 6.8): two pruning watermarks, the objects pruner's highest pruned checkpoint
//! (`num-epochs-to-retain`, the box: 1) and the checkpoint pruner's
//! (`num-epochs-to-retain-for-checkpoints`, the box: 2), advanced once per tick of
//! min(epoch duration / 2, 10 s). A checkpoint of epoch E is prunable once the current epoch is
//! at least E + N. With `smooth` (the default) each tick moves a watermark only 1/(epoch / tick)
//! of the way to its target, so in steady state about 2.58 epochs of checkpoints and 1.58 epochs
//! of superseded object versions are held. The checkpoint pruner never passes the objects
//! pruner. `lowest_available_checkpoint` = checkpoint pruner's highest pruned + 1. A snapshot
//! restore sets both watermarks to the restored end-of-epoch checkpoint S.
//!
//! The store applies them (`store.Store.setFloors`): checkpoint data by checkpoint, object
//! versions by whole segment (deepwave keeps a superset of sui-node's versions inside the partially
//! pruned epoch).
const std = @import("std");

/// Mainnet's epoch duration (sui-node reads it from the system state; every mainnet epoch so far
/// is 24 h).
pub const epoch_ms_default: u64 = 24 * 3600 * 1000;

pub fn tickMs(epoch_ms: u64) u64 {
    return @min(epoch_ms / 2, 10_000);
}

/// Epoch boundaries the formula needs: the last checkpoint of an epoch, when known.
pub const Chain = struct {
    ctx: *anyopaque,
    last_of: *const fn (ctx: *anyopaque, epoch: u64) ?u64,

    fn last(c: Chain, epoch: u64) ?u64 {
        return c.last_of(c.ctx, epoch);
    }
};

pub const Config = struct {
    /// `num-epochs-to-retain-for-checkpoints`.
    checkpoint_epochs: u64 = 2,
    /// `num-epochs-to-retain`.
    object_epochs: u64 = 1,
    smooth: bool = true,
    epoch_ms: u64 = epoch_ms_default,
};

/// `smoothed_max_eligible_checkpoint_number`.
pub fn smoothed(chain: Chain, max_eligible: u64, pruned: u64, epoch: u64, epoch_ms: u64, n: u64) u64 {
    if (epoch < n) return 0;
    const last = chain.last(epoch - n) orelse 0;
    const m = @min(max_eligible, last);
    if (m == 0) return 0;
    const t = tickMs(epoch_ms);
    const intervals: u64 = if (t == 0) 0 else epoch_ms / t;
    const delta: u64 = if (intervals == 0) 1 else (m -| pruned) / intervals;
    return pruned + delta;
}

/// `prune_for_eligible_epochs`: from `pruned + 1`, every checkpoint whose epoch is at most
/// `cur - n` and whose number is below `max_eligible`. Returns the new highest pruned checkpoint.
pub fn pruneTo(chain: Chain, pruned: u64, max_eligible: u64, n: u64, cur: u64) u64 {
    if (max_eligible == 0 or n > cur) return pruned;
    var hi = max_eligible - 1;
    if (n > 0) hi = @min(hi, chain.last(cur - n) orelse return pruned);
    return @max(pruned, hi);
}

pub const Marks = struct {
    /// Highest pruned checkpoint of each pruner (sui-node's `unwrap_or_default`: 0 = none).
    objects: u64 = 0,
    checkpoints: u64 = 0,
};

/// One pruning tick of both pruners. `highest` is the highest executed checkpoint and `cur`
/// its epoch.
pub fn tick(cfg: Config, chain: Chain, m: Marks, highest: u64, cur: u64) Marks {
    var out = m;
    // Objects (`prune_objects_for_eligible_epochs`).
    var max_o = highest;
    if (cfg.smooth and cfg.object_epochs > 0) max_o = smoothed(chain, max_o, m.objects, cur, cfg.epoch_ms, cfg.object_epochs);
    out.objects = pruneTo(chain, m.objects, max_o, cfg.object_epochs, cur);
    // Checkpoints (`prune_checkpoints_for_eligible_epochs`): never past the objects pruner.
    var max_c = @min(highest, out.objects);
    if (cfg.smooth) max_c = smoothed(chain, max_c, m.checkpoints, cur, cfg.epoch_ms, cfg.checkpoint_epochs);
    out.checkpoints = pruneTo(chain, m.checkpoints, max_c, cfg.checkpoint_epochs, cur);
    return out;
}

/// The highest pruned checkpoint of each pruner is at least `lowest_available - 1`: a checkpoint
/// the store no longer holds is pruned, whatever the store's recorded floors say. sui-node starts
/// both watermarks at the restored checkpoint S after a snapshot restore (lowest available
/// S + 1). A store restored by an older deepwave records neither S nor a floor: its watermarks
/// started at 0 and the smoothed formula then walked them up from checkpoint 0, about 40k
/// checkpoints per tick, far below anything the store holds (the epoch 1306 stall, lane
/// catchup-1306).
pub fn liftToLowest(m: Marks, lowest_available: u64) Marks {
    const floor = lowest_available -| 1;
    return .{ .objects = @max(m.objects, floor), .checkpoints = @max(m.checkpoints, floor) };
}

/// Checkpoint epochs as the store holds them.
pub const Held = struct {
    ctx: *anyopaque,
    epoch_of: *const fn (ctx: *anyopaque, seq: u64) ?u64,
};

/// The epoch of checkpoint `seq`, the first one a watermark has not pruned, for the store's
/// floors (`store.Store.Floors.cp_epoch` / `obj_epoch`: segments below both age out). Past the
/// highest executed checkpoint `top`: `cur`. A checkpoint the store holds: its epoch. Below the
/// lowest checkpoint the store holds (`lowest`, the watermark trails what was restored): the
/// epoch of that lowest one, so nothing the store still holds ages out. Anything else (a gap,
/// or nothing held): 0, nothing ages.
///
/// Before lane catchup-1306 every checkpoint the store did not hold counted as `cur`. On a store
/// whose watermark trailed its lowest checkpoint by 343M, the first tick after the epoch 1305 to
/// 1306 boundary aged segment 1305 at once (lowest available jumped to the first checkpoint of
/// 1306, below sui-node's 2 epochs of checkpoints) and the cleaner's sweep of it held the
/// follower at 0.1 checkpoints/s.
pub fn floorEpoch(h: Held, seq: u64, lowest: ?u64, top: u64, cur: u64) u64 {
    if (seq > top) return cur;
    if (h.epoch_of(h.ctx, seq)) |e| return @min(e, cur);
    const lo = lowest orelse return 0;
    if (seq < lo) return @min(h.epoch_of(h.ctx, lo) orelse return 0, cur);
    return 0;
}

/// Pacing of segment cleaning on the follower's thread (lane catchup-1306): the cleaner earns
/// `share_pct` percent of the time the thread spends outside it (apply, commit, waiting for the
/// next checkpoint) and spends it in steps of at most `step_max_ns`; a step that overruns (one
/// cold commit group) is paid back before the next one. At the tip (a checkpoint about every
/// 250 ms) a step gets about 50 ms; in catch-up at 70 checkpoints/s about 3 ms, so cleaning costs
/// at most share / (100 + share) of the follower's throughput however slow the disk is. Before,
/// a step was bounded by bytes only (16 MiB): 11 to 12 s per checkpoint on a cold store.
pub const Pace = struct {
    /// 0: cleaning off; 100 or more: unpaced (a step is bounded by its byte budget only).
    share_pct: u64 = 20,
    credit_max_ns: u64 = std.time.ns_per_s,
    step_max_ns: u64 = 250 * std.time.ns_per_ms,
    /// Debt is paid back in full, but at most this much is ever owed.
    debt_max_ns: u64 = 30 * std.time.ns_per_s,
    credit: i64 = 0,
    mark: u64 = 0,
    steps: u64 = 0,
    skipped: u64 = 0,

    pub const unlimited: u64 = 0;

    /// Before a step at `now` (monotonic ns): the step's deadline (`unlimited` = none), or null
    /// to skip cleaning at this checkpoint.
    pub fn begin(p: *Pace, now: u64) ?u64 {
        if (p.share_pct == 0) return null;
        if (p.share_pct >= 100) {
            p.mark = now;
            p.steps += 1;
            return unlimited;
        }
        if (p.mark != 0 and now > p.mark) {
            const earned: u64 = @min((now - p.mark) / 100 * p.share_pct, p.credit_max_ns);
            p.credit = @min(p.credit + @as(i64, @intCast(earned)), @as(i64, @intCast(p.credit_max_ns)));
        }
        p.mark = now;
        if (p.credit <= 0) {
            p.skipped += 1;
            return null;
        }
        p.steps += 1;
        return now + @min(@as(u64, @intCast(p.credit)), p.step_max_ns);
    }

    /// After the step `begin` allowed, at `now`.
    pub fn end(p: *Pace, now: u64) void {
        const spent: u64 = @min(now -| p.mark, p.debt_max_ns);
        if (p.share_pct < 100) p.credit = @max(p.credit - @as(i64, @intCast(spent)), -@as(i64, @intCast(p.debt_max_ns)));
        p.mark = now;
    }
};

// ---------------------------------------------------------------------- tests

const Fake = struct {
    /// last[e] = last checkpoint of epoch e (epochs of 100 checkpoints: e*100 .. e*100+99).
    known_upto: u64,
    fn lastOf(ctx: *anyopaque, e: u64) ?u64 {
        const f: *Fake = @ptrCast(@alignCast(ctx));
        if (e >= f.known_upto) return null;
        return e * 100 + 99;
    }
    fn chain(f: *Fake) Chain {
        return .{ .ctx = f, .last_of = lastOf };
    }
};

test "retention: no smoothing prunes whole epochs at cur - N, checkpoints capped by objects" {
    var f: Fake = .{ .known_upto = 5 };
    const cfg: Config = .{ .smooth = false };
    // In epoch 5 at checkpoint 550: objects prune epochs <= 4 (up to 499), checkpoints <= 3.
    const m = tick(cfg, f.chain(), .{}, 550, 5);
    try std.testing.expectEqual(@as(u64, 499), m.objects);
    try std.testing.expectEqual(@as(u64, 399), m.checkpoints);
    // N = 0 for both: everything below the highest executed checkpoint.
    const z = tick(.{ .smooth = false, .object_epochs = 0, .checkpoint_epochs = 0 }, f.chain(), .{}, 550, 5);
    try std.testing.expectEqual(@as(u64, 549), z.objects);
    // The checkpoint pruner's bound is the objects pruner's watermark, exclusive.
    try std.testing.expectEqual(@as(u64, 548), z.checkpoints);
    // The checkpoint pruner waits for the objects pruner.
    const c = tick(.{ .smooth = false, .object_epochs = 3, .checkpoint_epochs = 1 }, f.chain(), .{}, 550, 5);
    try std.testing.expectEqual(@as(u64, 299), c.objects);
    try std.testing.expectEqual(@as(u64, 298), c.checkpoints);
}

test "retention: smoothing moves 1/8640 of the gap per 10 s tick and converges to ~2.58 epochs held" {
    var f: Fake = .{ .known_upto = 1000 };
    // Real-sized epochs: 864,000 checkpoints of 100 ms, 8640 ticks of 10 s per epoch.
    const per: u64 = 864_000;
    const Big = struct {
        fn lastOf(ctx: *anyopaque, e: u64) ?u64 {
            _ = ctx;
            return e * per + per - 1;
        }
    };
    const chain: Chain = .{ .ctx = &f, .last_of = Big.lastOf };
    try std.testing.expectEqual(@as(u64, 10_000), tickMs(epoch_ms_default));
    // One tick from 0 in epoch 3, objects N = 1: target = last of epoch 2.
    const s1 = smoothed(chain, 3 * per, 0, 3, epoch_ms_default, 1);
    try std.testing.expectEqual((3 * per - 1) / 8640, s1);
    // Simulate 40 epochs of ticks (checkpoints advance 100 per tick).
    var m: Marks = .{};
    var highest: u64 = 0;
    var held_cp: f64 = 0;
    var held_obj: f64 = 0;
    var samples: f64 = 0;
    var t: u64 = 0;
    while (t < 40 * 8640) : (t += 1) {
        highest += 100;
        const cur = highest / per;
        m = tick(.{}, chain, m, highest, cur);
        if (t > 30 * 8640) {
            held_cp += @as(f64, @floatFromInt(highest - m.checkpoints)) / @as(f64, @floatFromInt(per));
            held_obj += @as(f64, @floatFromInt(highest - m.objects)) / @as(f64, @floatFromInt(per));
            samples += 1;
        }
    }
    const cp_avg = held_cp / samples;
    const obj_avg = held_obj / samples;
    // e/(e-1) + 1 = 2.58 and e/(e-1) = 1.58 (the backlog's steady state).
    try std.testing.expect(cp_avg > 2.5 and cp_avg < 2.66);
    try std.testing.expect(obj_avg > 1.5 and obj_avg < 1.66);
}

test "retention: an unknown epoch boundary stops pruning (sui-node unwrap_or_default)" {
    var f: Fake = .{ .known_upto = 0 };
    const m = tick(.{}, f.chain(), .{ .objects = 7, .checkpoints = 3 }, 550, 5);
    try std.testing.expectEqual(@as(u64, 7), m.objects);
    try std.testing.expectEqual(@as(u64, 3), m.checkpoints);
}

const HeldFake = struct {
    lo: u64,
    hi: u64,
    fn epochOf(ctx: *anyopaque, seq: u64) ?u64 {
        const f: *HeldFake = @ptrCast(@alignCast(ctx));
        if (seq < f.lo or seq > f.hi) return null;
        return seq / 100;
    }
    fn held(f: *HeldFake) Held {
        return .{ .ctx = f, .epoch_of = epochOf };
    }
};

test "retention: a watermark below the lowest held checkpoint ages nothing the store holds (epoch 1306 stall)" {
    // The store holds checkpoints 1250..1430 (epochs 12 to 14), the restore point S = 1249.
    var f: HeldFake = .{ .lo = 1250, .hi = 1430 };
    // Watermark at 18 (walked up from 0): checkpoint 19 is not held. Before the fix it read as
    // the current epoch, 14, and every segment below 14 aged out.
    try std.testing.expectEqual(@as(u64, 12), floorEpoch(f.held(), 19, 1250, 1430, 14));
    try std.testing.expectEqual(@as(u64, 13), floorEpoch(f.held(), 1350, 1250, 1430, 14));
    try std.testing.expectEqual(@as(u64, 14), floorEpoch(f.held(), 1431, 1250, 1430, 14));
    // Nothing known: nothing ages.
    try std.testing.expectEqual(@as(u64, 0), floorEpoch(f.held(), 19, null, 1430, 14));
    // A hole above the lowest held checkpoint: nothing ages.
    var g: HeldFake = .{ .lo = 1300, .hi = 1430 };
    try std.testing.expectEqual(@as(u64, 0), floorEpoch(g.held(), 1299, 1290, 1430, 14));
}

test "retention: watermarks start at the lowest available checkpoint, then follow sui-node's formula" {
    // Epochs of 100 checkpoints; the store was restored at S = 1199 (end of epoch 11), holds
    // 1200.. and is in epoch 13 at 1350. Its recorded floors are 0 / 18 (an older deepwave).
    var f: Fake = .{ .known_upto = 13 };
    const lifted = liftToLowest(.{ .objects = 18, .checkpoints = 0 }, 1200);
    try std.testing.expectEqual(@as(u64, 1199), lifted.objects);
    try std.testing.expectEqual(@as(u64, 1199), lifted.checkpoints);
    // Floors already above it stay.
    const kept = liftToLowest(.{ .objects = 1260, .checkpoints = 1210 }, 1200);
    try std.testing.expectEqual(@as(u64, 1260), kept.objects);
    try std.testing.expectEqual(@as(u64, 1210), kept.checkpoints);
    // Genesis-synced store: nothing changes.
    try std.testing.expectEqual(@as(u64, 7), liftToLowest(.{ .objects = 7, .checkpoints = 3 }, 0).objects);
    // Unsmoothed, epoch 13: objects prune epoch 12 and below, checkpoints epoch 11 and below.
    const m = tick(.{ .smooth = false }, f.chain(), lifted, 1350, 13);
    try std.testing.expectEqual(@as(u64, 1299), m.objects);
    try std.testing.expectEqual(@as(u64, 1199), m.checkpoints);
    // Smoothed, the first tick of epoch 13 moves 1/8640 of the way from S, not from 0.
    const sm = tick(.{}, f.chain(), lifted, 1350, 13);
    try std.testing.expect(sm.objects >= 1199 and sm.objects < 1210);
    try std.testing.expectEqual(@as(u64, 1199), sm.checkpoints);
}

test "retention: cleaning pace keeps the cleaner to its share and pays back an overrun" {
    const ms = std.time.ns_per_ms;
    var p: Pace = .{ .share_pct = 20 };
    // The first call only sets the mark.
    try std.testing.expect(p.begin(1000 * ms) == null);
    // 100 ms elsewhere: 20 ms of credit, so the step's deadline is 20 ms out.
    try std.testing.expectEqual(@as(?u64, 1120 * ms), p.begin(1100 * ms));
    // The step overran: 2 s on one cold group. That is owed before the next step.
    p.end(3100 * ms);
    var t: u64 = 3100 * ms;
    var skipped: u64 = 0;
    while (p.begin(t + 100 * ms) == null) : (skipped += 1) {
        t += 100 * ms;
        try std.testing.expect(skipped < 200);
    }
    // 2 s - 20 ms owed at 20 ms per 100 ms: about 99 checkpoints skipped.
    try std.testing.expect(skipped >= 95 and skipped <= 100);
    // Steps never exceed step_max, however much credit there is.
    var q: Pace = .{ .share_pct = 20 };
    _ = q.begin(1);
    const d = q.begin(1 + 60 * std.time.ns_per_s).?;
    try std.testing.expectEqual(@as(u64, 1 + 60 * std.time.ns_per_s + 250 * ms), d);
    // Long idle earns at most credit_max.
    try std.testing.expectEqual(@as(i64, std.time.ns_per_s), q.credit);
    // Over a long run the cleaner's share of the time stays near share / (100 + share).
    var r: Pace = .{ .share_pct = 20 };
    var now: u64 = 1;
    var clean_ns: u64 = 0;
    _ = r.begin(now);
    r.end(now);
    for (0..100_000) |_| {
        now += 14 * ms; // apply and commit of one checkpoint in catch-up
        if (r.begin(now)) |dl| {
            const spent = @min(dl - now + 5 * ms, 40 * ms); // a step overruns its deadline a bit
            now += spent;
            clean_ns += spent;
            r.end(now);
        }
    }
    const frac = @as(f64, @floatFromInt(clean_ns)) / @as(f64, @floatFromInt(now));
    try std.testing.expect(frac > 0.12 and frac < 0.19);
    // 0: off; 100: unpaced.
    var off: Pace = .{ .share_pct = 0 };
    try std.testing.expect(off.begin(5) == null);
    var unpaced: Pace = .{ .share_pct = 100 };
    try std.testing.expectEqual(@as(?u64, Pace.unlimited), unpaced.begin(5));
}
