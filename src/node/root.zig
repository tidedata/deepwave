//! node: the deepwave full node. Composes the lanes into one process (ARCHITECTURE.md 3.3, 7.1):
//! source (S3 archive, our node's gRPC, or a local directory) -> sync.Follower (BLS
//! certificate, contents and effects digests, output objects against effects) -> optional
//! execution through exec -> store (crash-safe, one durable write per checkpoint) -> serve
//! (sui.rpc.v2 from the same store) and metrics.
//! Owner lane: node. Interface: CONTRACTS.md 6.7. Only the node lane edits files in src/node/.
const std = @import("std");

pub const conformance = @import("conformance.zig");
pub const convert = @import("convert.zig");
pub const s3 = @import("s3.zig");
pub const http = @import("http.zig");
pub const stream = @import("stream.zig");
pub const sigorder = @import("sigorder.zig");
pub const p2p = @import("p2p.zig");
pub const p2p_exec = @import("p2p_exec.zig");
pub const reconcile = @import("reconcile.zig");
pub const p2p_only = @import("p2p_only.zig");
pub const p2p_serve = @import("p2p_serve.zig");
pub const p2p_probe = @import("p2p_probe.zig");
pub const p2p_config = @import("p2p_config.zig");
pub const netguard = @import("netguard.zig");
pub const ops = @import("ops.zig");
pub const source = @import("source.zig");
pub const trust = @import("trust.zig");
pub const execute = @import("execute.zig");
pub const bump = @import("bump.zig");
pub const memstat = @import("memstat.zig");
pub const check = @import("check.zig");
pub const history = @import("history.zig");
pub const retention = @import("retention.zig");
pub const lhfill = @import("lhfill.zig");
pub const history_bench = @import("history_bench.zig");
pub const removal_log = @import("removal_log.zig");
pub const snapshot = @import("snapshot.zig");
pub const snapwrite = @import("snapwrite.zig");
pub const conservation = @import("conservation.zig");
pub const dbcheckpoint = @import("dbcheckpoint.zig");
pub const du = @import("du.zig");
pub const fullnode_yaml = @import("fullnode_yaml.zig");
pub const node = @import("node.zig");
pub const dst = @import("dst/root.zig");
pub const network = @import("network.zig");
pub const pkgfetch = @import("pkgfetch.zig");
pub const rpc = @import("rpc.zig");
pub const native_hooks = @import("native_hooks.zig");

pub const Node = node.Node;
pub const Config = node.Config;
pub const Mode = node.Mode;
pub const installSignalHandlers = node.installSignalHandlers;
pub const store = @import("store");
pub const sig = @import("sig");
pub const gpu = @import("gpu");
pub const serve = @import("serve");
pub const core = @import("core");
pub const types = @import("types");
pub const sync = @import("sync");

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
    _ = @import("rpcmetrics.zig");
    _ = @import("opsmetrics.zig");
    _ = @import("statehash.zig");
    _ = @import("upgrade.zig");
    _ = @import("handoff.zig");
    _ = @import("conservation.zig");
    _ = @import("admin.zig");
    _ = @import("logfilter.zig");
    _ = @import("logout.zig");
    _ = @import("metricspush.zig");
    _ = @import("stageprof.zig");
}
