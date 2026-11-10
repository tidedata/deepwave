//! The native lane has no Mysten ground truth (zui/1 is deepwave's own protocol); its tests are unit
//! tests under `zig build test -Dlane=native` and the tools/native client and interop runs.
const harness = @import("harness");

pub const suites = [_]harness.Suite{};
