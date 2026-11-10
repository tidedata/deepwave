//! deepwave-consensus-localnet: N consensus authorities on loopback in one process, generated keys,
//! loopback only (it cannot reach a real validator). See localnet.zig.
//!
//!   deepwave-consensus-localnet [--n 4] [--seed 1] [--mode toy|real] [--commits 10] [--timeout-ms 30000]
//!                          [--no-wait-all] [--late-node I] [--late-after-commits 5]
//!                          [--batch-size 100] [--cached-rounds 500] [--sink-full-every K] [--protocol 141]
//!                          [--restart-node I [--restart-after-commits C] [--restart-down-ms MS] [--restart-torn]]
//!                          [--partition-node I [--partition-after-commits C] [--partition-ms MS]
//!                           [--partition-mode blackhole|drop]]
//! Exit 0 when every node reached the commit target with identical commit sequences, 1 otherwise,
//! 3 when the mode needs the consensus core and it is not implemented yet.
const std = @import("std");
const consensus_net = @import("consensus_net");
const localnet = consensus_net.localnet;

pub fn main(init: std.process.Init) !u8 {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var cfg: localnet.Config = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--no-wait-all")) {
            cfg.wait_all = false;
            continue;
        }
        if (std.mem.eql(u8, a, "--restart-torn")) {
            cfg.restart_torn = true;
            continue;
        }
        if (i + 1 >= args.len) return usage();
        const v = args[i + 1];
        i += 1;
        if (std.mem.eql(u8, a, "--n")) cfg.n = std.fmt.parseInt(usize, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--seed")) cfg.seed = std.fmt.parseInt(u64, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--commits")) cfg.target_commits = std.fmt.parseInt(u32, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--timeout-ms")) cfg.timeout_ms = std.fmt.parseInt(u64, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--late-node")) cfg.late_node = std.fmt.parseInt(usize, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--late-after-commits")) cfg.late_start_commits = std.fmt.parseInt(u32, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--batch-size")) cfg.commit_sync_batch_size = std.fmt.parseInt(u32, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--cached-rounds")) cfg.dag_state_cached_rounds = std.fmt.parseInt(u32, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--sink-full-every")) cfg.sink_full_every = std.fmt.parseInt(u32, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--protocol")) cfg.protocol_version = std.fmt.parseInt(u64, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--restart-node")) cfg.restart_node = std.fmt.parseInt(usize, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--restart-after-commits")) cfg.restart_after_commits = std.fmt.parseInt(u32, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--restart-down-ms")) cfg.restart_down_ms = std.fmt.parseInt(u64, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--partition-node")) cfg.partition_node = std.fmt.parseInt(usize, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--partition-after-commits")) cfg.partition_after_commits = std.fmt.parseInt(u32, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--partition-ms")) cfg.partition_ms = std.fmt.parseInt(u64, v, 10) catch return usage() else if (std.mem.eql(u8, a, "--partition-mode")) {
            cfg.partition_mode = std.meta.stringToEnum(@TypeOf(cfg.partition_mode), v) orelse return usage();
        } else if (std.mem.eql(u8, a, "--mode")) {
            cfg.mode = std.meta.stringToEnum(localnet.Mode, v) orelse return usage();
        } else return usage();
    }
    if (cfg.n < 1 or cfg.n > consensus_net.testkit.max_test_authorities) return usage();
    if (cfg.restart_node != null and cfg.partition_node != null) return usage();
    var rep = localnet.run(init.gpa, init.io, cfg) catch |e| switch (e) {
        error.Unimplemented => {
            std.debug.print("deepwave-consensus-localnet: mode {s} needs the consensus core (val-consensus-core), not implemented yet\n", .{@tagName(cfg.mode)});
            return 3;
        },
        else => {
            std.debug.print("deepwave-consensus-localnet: {s}\n", .{@errorName(e)});
            return 1;
        },
    };
    defer rep.deinit(init.gpa);
    for (rep.nodes, 0..) |n, idx| {
        std.debug.print("node {d}: commits={d} proposed_round={d} received={d} invalid={d} streamed={d} synced_commit_batches={d} fetched={d}\n", .{ idx, n.commits, n.last_proposed, n.blocks_received, n.blocks_invalid, n.blocks_streamed, n.commit_batches_synced, n.blocks_fetched });
    }
    var invalid: u64 = 0;
    for (rep.nodes) |n| invalid += n.blocks_invalid;
    if (rep.event) |e| {
        std.debug.print("event: {s} node {d} for {d} ms: others min commits {d} -> {d} during it, node at {d} when back, recovered in ", .{ @tagName(e.kind), e.node, e.event_ms, e.others_min_at_start, e.others_min_at_end, e.node_at_end });
        if (e.recover_ms) |ms| std.debug.print("{d} ms\n", .{ms}) else std.debug.print("never\n", .{});
    }
    std.debug.print("deepwave-consensus-localnet: {s} in {d} ms, min commits {d}, consistent={}, invalid={d}\n", .{ if (rep.ok) "PASS" else "FAIL", rep.elapsed_ms, rep.min_commits, rep.consistent, invalid });
    return if (rep.ok) 0 else 1;
}

fn usage() u8 {
    std.debug.print("usage: deepwave-consensus-localnet [--n N] [--seed S] [--mode toy|real] [--commits C] [--timeout-ms MS] [--no-wait-all] [--late-node I] [--late-after-commits C] [--batch-size B] [--cached-rounds R] [--sink-full-every K] [--protocol V] [--restart-node I [--restart-after-commits C] [--restart-down-ms MS] [--restart-torn]] [--partition-node I [--partition-after-commits C] [--partition-ms MS] [--partition-mode blackhole|drop]]\n", .{});
    return 2;
}
