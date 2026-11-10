//! The validator speed bench (docs/VALIDATOR-SPEED.md): every validator stage against Mysten
//! sui 1.83.1 on the same inputs, single process, no network. Rust writes its outputs and timings
//! (tools/truth/val-bench); these suites read the same inputs, time deepwave, print timing lines and
//! compare every output line with Rust's.
const harness = @import("harness");

pub const suites = [_]harness.Suite{
    .{ .name = "val-bench-intake", .lane = "val-bench", .doc = "user tx signature verification (all schemes) on mainnet txs: outputs equal Mysten's verify_sender_signed_data_message_signatures, timed cold/warm/1-4 threads/batched", .run = @import("intake.zig").run },
    .{ .name = "val-bench-commit", .lane = "val-bench", .doc = "commit decision and finalization over consensus-core DAGs (4/10/100, timeouts): commit lines equal Mysten's UniversalCommitter+Linearizer, final lines (released commits with their rejected transactions) equal its CommitFinalizer, timed per round", .run = @import("commit.zig").run },
    .{ .name = "val-bench-blocks", .lane = "val-bench", .doc = "block create (sign+serialize) and verify on consensus-core blocks: bytes equal, timed 1 and 4 threads", .run = @import("blocks.zig").run },
    .{ .name = "val-bench-ckpt", .lane = "val-bench", .doc = "checkpoint contents+summary from recorded effects: digests equal Mysten's CausalOrder+CheckpointSummary, timed", .run = @import("ckpt.zig").run },
    .{ .name = "val-bench-versions", .lane = "val-bench", .doc = "shared-object version assignment and congestion control per commit: equal to SharedObjVerManager and SharedObjectCongestionTracker, timed", .run = @import("versions.zig").run },
};
