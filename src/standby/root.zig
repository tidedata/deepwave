//! standby: hot standby lease/fencing protocol, watchdogs and alerts (docs/STANDBY.md).
pub const lease = @import("lease.zig");
pub const watch = @import("watch.zig");
pub const net = @import("net.zig");

test {
    _ = @import("lease.zig");
    _ = @import("sim_test.zig");
    _ = @import("watch.zig");
    _ = @import("net.zig");
}
