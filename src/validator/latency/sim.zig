//! A deterministic synthetic pipeline that drives the tracer the way a localnet validator
//! would, so the budget table can be produced (and its tooling tested) before the validator runs:
//! `deepwave-validator budget --demo`. The delays are a model (uniform jitter around the given
//! centres, in us), not measurements: the real table comes from marks emitted by the validator
//! lanes on a test machine. Used by the tests and the demo only.
const std = @import("std");
const tracer = @import("tracer.zig");

pub const Model = struct {
    validate_us: u64 = 450,
    submit_us: u64 = 60,
    queue_to_block_us: u64 = 30_000, // wait for the next proposal (min_round_delay 50 ms)
    block_to_commit_us: u64 = 90_000, // two more rounds and the leader
    sequence_us: u64 = 1_500,
    execute_us: u64 = 3_500,
    serve_us: u64 = 250,
    recv_verify_us: u64 = 300,
    verify_accept_us: u64 = 120,
    commit_finalize_us: u64 = 900,
    checkpoint_build_us: u64 = 45_000,
    checkpoint_sign_us: u64 = 700,
    checkpoint_certify_us: u64 = 38_000,
    jitter_pct: u64 = 40,
};

fn jitter(rng: *std.Random.DefaultPrng, centre_us: u64, pct: u64) u64 {
    const span = centre_us * pct / 100;
    if (span == 0) return centre_us * 1000;
    const lo = centre_us - span;
    return (lo + rng.random().uintLessThan(u64, 2 * span + 1)) * 1000;
}

/// Runs `n_txs` transactions (and `n_txs / 64 + 1` blocks and checkpoints) through `t`.
pub fn run(t: *tracer.StageTracer, m: Model, n_txs: usize, seed: u64) void {
    var rng = std.Random.DefaultPrng.init(seed);
    const tr = t.validatorTracer();
    var now: u64 = 1_000_000;
    for (0..n_txs) |i| {
        var key: [32]u8 = @as([32]u8, @splat(0));
        std.mem.writeInt(u64, key[0..8], i *% 0x9e3779b97f4a7c15 +% 1, .little);
        std.mem.writeInt(u64, key[8..16], seed, .little);
        now += jitter(&rng, 800, 90);
        tr.mark(.tx_received, &key, now);
        now += jitter(&rng, m.validate_us, m.jitter_pct);
        tr.mark(.tx_validated, &key, now);
        now += jitter(&rng, m.submit_us, m.jitter_pct);
        tr.mark(.tx_submitted, &key, now);
        now += jitter(&rng, m.queue_to_block_us, m.jitter_pct);
        tr.mark(.tx_in_proposed_block, &key, now);
        now += jitter(&rng, m.block_to_commit_us, m.jitter_pct);
        now += jitter(&rng, m.sequence_us, m.jitter_pct);
        tr.mark(.tx_sequenced, &key, now);
        now += jitter(&rng, m.execute_us, m.jitter_pct);
        tr.mark(.tx_executed, &key, now);
        now += jitter(&rng, m.serve_us, m.jitter_pct);
        tr.mark(.effects_served, &key, now);
    }
    for (0..n_txs / 64 + 1) |i| {
        var key: [32]u8 = @as([32]u8, @splat(0xb1));
        std.mem.writeInt(u64, key[0..8], i *% 0x9e3779b97f4a7c15 +% 3, .little);
        var b = now;
        tr.mark(.block_received, &key, b);
        b += jitter(&rng, m.recv_verify_us, m.jitter_pct);
        tr.mark(.block_verified, &key, b);
        b += jitter(&rng, m.verify_accept_us, m.jitter_pct);
        t.mark(.block_accepted, &key, b);
        b += jitter(&rng, m.block_to_commit_us, m.jitter_pct);
        tr.mark(.leader_committed, &key, b);
        b += jitter(&rng, m.commit_finalize_us, m.jitter_pct);
        tr.mark(.sub_dag_finalized, &key, b);

        var ck: [32]u8 = @as([32]u8, @splat(0xc4));
        std.mem.writeInt(u64, ck[0..8], i *% 0x9e3779b97f4a7c15 +% 5, .little);
        var c = b;
        tr.mark(.checkpoint_built, &ck, c);
        c += jitter(&rng, m.checkpoint_build_us, m.jitter_pct);
        tr.mark(.checkpoint_signed, &ck, c);
        c += jitter(&rng, m.checkpoint_certify_us, m.jitter_pct);
        tr.mark(.checkpoint_certified, &ck, c);
    }
}

test "demo run fills every chain" {
    const t = try tracer.StageTracer.create(std.testing.allocator, 1 << 10);
    defer t.destroy();
    run(t, .{}, 500, 42);
    try std.testing.expectEqual(@as(u64, 500), t.budget.total(.tx).count());
    try std.testing.expect(t.budget.total(.block).count() >= 8);
    try std.testing.expect(t.budget.total(.checkpoint).count() >= 8);
    const p50 = t.budget.total(.tx).percentileUs(0.5);
    try std.testing.expect(p50 > 100_000 and p50 < 160_000);
    try std.testing.expectEqual(@as(u64, 0), t.budget.evicted.load(.monotonic));
}
