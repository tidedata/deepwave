//! edgewire has no Mysten ground truth (the feed is deepwave's own format); its round trip against
//! corpus checkpoints is the `edge-feed` suite in src/edge/conformance.zig.
const harness = @import("harness");

pub const suites = [_]harness.Suite{};
