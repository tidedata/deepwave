//! val-fast-finality: the under-200 ms finality work
//! (docs/VALIDATOR-DESIGN.md 10). Everything here is
//! measurement or OFF by default; nothing signs with a validator key.
//!   - tracer/hist/report: per-stage latency budget (iface.Stage and consensus Tracer), fixed
//!     bucket histograms, budget table, dump file. `deepwave-validator budget`.
//!   - fastpath: the Mysticeti fast-path finalization rule of 1.83.1 (vote tracker, direct
//!     finalize) plus a passive observer of DAG-certificate lead over commit.
//!   - preconfirm: signed "it is going in" notices at commit time, zui-only, behind a flag.
//!   - routes: DoubleZero / colocation alternate consensus addresses, as config.
//!   - Shadow: observe-only consensus beside a Mysten validator (needs the consensus lanes).
const std = @import("std");
const iface = @import("../iface.zig");

pub const hist = @import("hist.zig");
pub const tracer = @import("tracer.zig");
pub const report = @import("report.zig");
pub const sim = @import("sim.zig");
pub const cli = @import("cli.zig");
pub const fastpath = @import("fastpath.zig");
pub const preconfirm = @import("preconfirm.zig");
pub const routes = @import("routes.zig");

pub const Error = error{ Unimplemented, OutOfMemory };

pub const Flags = struct {
    /// Collect the stage budget (StageTracer, Observer).
    trace: bool = false,
    shadow: bool = false,
    /// Emit signed preconfirmation notices to subscribers (zui-only, not Sui protocol).
    preconfirmations: bool = false,
    /// Reserved: an active early-execution path. 1.83.1 has none to follow, so enabling it is
    /// refused (fastpath.Observer.refuseExperimental).
    experimental_fast_path: bool = false,
};

pub const StageTracer = tracer.StageTracer;

/// Wires the flagged parts together for one validator process. With every flag off, `init`
/// allocates nothing and `tracer()` hands back the null tracers (one branch per mark site).
pub const Latency = struct {
    flags: Flags,
    stage: ?*StageTracer = null,
    hub: ?*preconfirm.Hub = null,
    notifier: ?preconfirm.Notifier = null,

    pub const Config = struct {
        flags: Flags = .{},
        /// In-flight timelines the tracer tracks.
        trace_capacity: usize = 1 << 14,
        /// Ed25519 seed of the preconfirmation notice key (never a validator key); required with
        /// flags.preconfirmations.
        notice_seed: ?[32]u8 = null,
        epoch: u64 = 0,
    };

    pub fn init(gpa: std.mem.Allocator, cfg: Config) !Latency {
        try fastpath.Observer.refuseExperimental(cfg.flags.experimental_fast_path);
        var l: Latency = .{ .flags = cfg.flags };
        errdefer l.deinit(gpa);
        if (cfg.flags.trace) l.stage = try StageTracer.create(gpa, cfg.trace_capacity);
        if (cfg.flags.preconfirmations) {
            const seed = cfg.notice_seed orelse return error.NoticeKeyRequired;
            const hub = try gpa.create(preconfirm.Hub);
            hub.* = preconfirm.Hub.init(gpa);
            l.hub = hub;
            const kp = try preconfirm.Ed25519.KeyPair.generateDeterministic(seed);
            l.notifier = .{ .hub = hub, .key = kp, .epoch = .init(cfg.epoch) };
        }
        return l;
    }

    pub fn deinit(l: *Latency, gpa: std.mem.Allocator) void {
        if (l.stage) |s| s.destroy();
        if (l.hub) |h| {
            h.deinit();
            gpa.destroy(h);
        }
        l.* = .{ .flags = .{} };
    }

    /// The ZBUD1 dump of the running budget, for the process's periodic timer to write to the
    /// dump file (`deepwave-validator budget <file>` prints it). Empty when tracing is off.
    pub fn encodeDump(l: *const Latency, out: *std.ArrayList(u8), gpa: std.mem.Allocator) !void {
        if (l.stage) |s| try report.encode(out, gpa, &s.budget);
    }

    /// Epoch change: notices carry the new epoch from now on.
    pub fn setEpoch(l: *Latency, epoch: u64) void {
        if (l.notifier) |*n| n.setEpoch(epoch);
    }

    pub fn validatorTracer(l: *const Latency) iface.Tracer {
        return if (l.stage) |s| s.validatorTracer() else .{};
    }
    pub fn consensusTracer(l: *const Latency) @import("consensus").iface.Tracer {
        return if (l.stage) |s| s.consensusTracer() else .{};
    }
};

pub const Shadow = struct {
    pub fn compare(self: *Shadow) Error!void {
        _ = self;
        return error.Unimplemented;
    }
};

test {
    std.testing.refAllDecls(@This());
    _ = hist;
    _ = tracer;
    _ = report;
    _ = sim;
    _ = fastpath;
    _ = preconfirm;
    _ = routes;
}

test "Latency: all flags off allocates nothing and yields null tracers" {
    var l = try Latency.init(std.testing.allocator, .{});
    defer l.deinit(std.testing.allocator);
    try std.testing.expect(l.validatorTracer().vtable == null);
    try std.testing.expect(l.consensusTracer().vtable == null);
    try std.testing.expectError(error.ExperimentalRefused, Latency.init(std.testing.allocator, .{ .flags = .{ .experimental_fast_path = true } }));
    try std.testing.expectError(error.NoticeKeyRequired, Latency.init(std.testing.allocator, .{ .flags = .{ .preconfirmations = true } }));
}

test "Latency: trace and preconfirmations on" {
    var l = try Latency.init(std.testing.allocator, .{ .flags = .{ .trace = true, .preconfirmations = true }, .notice_seed = @as([32]u8, @splat(1)), .trace_capacity = 64 });
    defer l.deinit(std.testing.allocator);
    try std.testing.expect(l.validatorTracer().vtable != null);
    try std.testing.expect(l.notifier != null);
}
