//! Durable DKG and beacon-round state of the randomness manager (authority_per_epoch_store
//! tables `dkg_processed_messages_v2`, `dkg_used_messages_v2`, `dkg_confirmations_v2`,
//! `dkg_output`, `randomness_next_round`, `randomness_last_round_timestamp`, mainnet-v1.83.1).
//!
//! The manager's `Batch` of one commit is encoded here and written by the consensus handler in
//! that commit's durable group (authority/state.zig `Batch.ext`, tag `ext_randomness`), so what is
//! on disk always matches the commits the handler processed. After a restart the groups' records
//! are folded in order (`Restore`) and loaded into a fresh `Manager` before the handler replays the
//! commits after the durable point.
//!
//! The failed verdict is a record of its own (`output_failed`). Sui PR 26846 fixed the bug where
//! a DKG that timed out was never written: after a restart that validator saw a pending DKG while
//! the rest of the committee had cancelled randomness for the epoch, and it diverged (mainnet halt
//! #3, 2026-05-28/29). Here a timed-out DKG is persisted in the same group as the commit whose
//! round crossed the timeout, and `Restore` gives it precedence over everything but a success.
const std = @import("std");
const manager = @import("manager.zig");

pub const Error = error{ OutOfMemory, Corrupt };

const R = struct {
    const processed: u8 = 1;
    const confirmation: u8 = 2;
    const used: u8 = 3;
    const own_confirmation: u8 = 4;
    const output_success: u8 = 5;
    const output_failed: u8 = 6;
    const reserved_round: u8 = 7;
};

const version: u8 = 1;

fn putU32(out: *std.ArrayList(u8), gpa: std.mem.Allocator, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try out.appendSlice(gpa, &b);
}
fn putU64(out: *std.ArrayList(u8), gpa: std.mem.Allocator, v: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    try out.appendSlice(gpa, &b);
}
fn putBlob(out: *std.ArrayList(u8), gpa: std.mem.Allocator, bytes: []const u8) !void {
    try putU32(out, gpa, @intCast(bytes.len));
    try out.appendSlice(gpa, bytes);
}

pub fn isEmpty(b: *const manager.Batch) bool {
    return b.processed.items.len == 0 and b.confirmations.items.len == 0 and b.used_messages == null and
        b.own_confirmation == null and b.dkg_output == null and b.reserved_round == null;
}

/// Encodes one commit's batch (null when it holds nothing). Output in `arena`.
pub fn encode(arena: std.mem.Allocator, b: *const manager.Batch) error{OutOfMemory}!?[]const u8 {
    if (isEmpty(b)) return null;
    var out: std.ArrayList(u8) = .empty;
    try out.append(arena, version);
    for (b.processed.items) |r| {
        try out.append(arena, R.processed);
        try putU32(&out, arena, r.sender);
        try putBlob(&out, arena, r.bytes);
    }
    for (b.confirmations.items) |r| {
        try out.append(arena, R.confirmation);
        try putU32(&out, arena, r.sender);
        try putBlob(&out, arena, r.bytes);
    }
    if (b.used_messages) |u| {
        try out.append(arena, R.used);
        try putBlob(&out, arena, u);
    }
    if (b.own_confirmation) |c| {
        try out.append(arena, R.own_confirmation);
        try putBlob(&out, arena, c);
    }
    if (b.dkg_output) |o| switch (o) {
        .success => |bytes| {
            try out.append(arena, R.output_success);
            try putBlob(&out, arena, bytes);
        },
        .failed => try out.append(arena, R.output_failed),
    };
    if (b.reserved_round) |rr| {
        try out.append(arena, R.reserved_round);
        try putU64(&out, arena, rr.next_round);
        try putU64(&out, arena, rr.timestamp_ms);
    }
    return out.items;
}

/// The epoch's records folded in group order: the state the tables would hold.
pub const Restore = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    /// Latest bytes per sender.
    processed: std.AutoArrayHashMapUnmanaged(u16, []const u8) = .empty,
    confirmations: std.AutoArrayHashMapUnmanaged(u16, []const u8) = .empty,
    used: ?[]const u8 = null,
    own_confirmation: ?[]const u8 = null,
    output: union(enum) { unset, success: []const u8, failed } = .unset,
    next_round: ?u64 = null,
    last_timestamp_ms: ?u64 = null,
    records: u64 = 0,

    pub fn init(gpa: std.mem.Allocator) Restore {
        return .{ .gpa = gpa, .arena = .init(gpa) };
    }

    pub fn deinit(r: *Restore) void {
        r.processed.deinit(r.gpa);
        r.confirmations.deinit(r.gpa);
        r.arena.deinit();
    }

    /// Folds one encoded batch (the bytes of an `ext_randomness` record).
    pub fn add(r: *Restore, bytes: []const u8) Error!void {
        const a = r.arena.allocator();
        var i: usize = 0;
        const rd = struct {
            fn n(buf: []const u8, at: *usize, k: usize) Error![]const u8 {
                if (buf.len - at.* < k) return error.Corrupt;
                defer at.* += k;
                return buf[at.*..][0..k];
            }
            fn u32_(buf: []const u8, at: *usize) Error!u32 {
                return std.mem.readInt(u32, (try n(buf, at, 4))[0..4], .little);
            }
            fn u64_(buf: []const u8, at: *usize) Error!u64 {
                return std.mem.readInt(u64, (try n(buf, at, 8))[0..8], .little);
            }
            fn blob(buf: []const u8, at: *usize) Error![]const u8 {
                const len = try u32_(buf, at);
                return n(buf, at, len);
            }
        };
        if ((try rd.n(bytes, &i, 1))[0] != version) return error.Corrupt;
        while (i < bytes.len) {
            const tag = (try rd.n(bytes, &i, 1))[0];
            r.records += 1;
            switch (tag) {
                R.processed, R.confirmation => {
                    const sender = try rd.u32_(bytes, &i);
                    if (sender > std.math.maxInt(u16)) return error.Corrupt;
                    const b = try a.dupe(u8, try rd.blob(bytes, &i));
                    const map = if (tag == R.processed) &r.processed else &r.confirmations;
                    try map.put(r.gpa, @intCast(sender), b);
                },
                R.used => r.used = try a.dupe(u8, try rd.blob(bytes, &i)),
                R.own_confirmation => r.own_confirmation = try a.dupe(u8, try rd.blob(bytes, &i)),
                R.output_success => r.output = .{ .success = try a.dupe(u8, try rd.blob(bytes, &i)) },
                // a success is final; a failure can only follow an unset output
                R.output_failed => if (r.output != .success) {
                    r.output = .failed;
                },
                R.reserved_round => {
                    r.next_round = try rd.u64_(bytes, &i);
                    r.last_timestamp_ms = try rd.u64_(bytes, &i);
                },
                else => return error.Corrupt,
            }
        }
    }

    /// Loads the folded state into a manager created for the same epoch, in the order
    /// `RandomnessManager::try_new` reads its tables: the output first; without one the
    /// processed and used messages and the confirmations; the own confirmation; the rounds.
    pub fn apply(r: *const Restore, m: *manager.Manager, highest_completed: ?u64) manager.Error!void {
        switch (r.output) {
            .success => |b| try m.loadOutput(b),
            .failed => m.loadOutputFailed(),
            .unset => {
                var it = r.processed.iterator();
                while (it.next()) |e| try m.loadProcessed(e.key_ptr.*, e.value_ptr.*);
                if (r.used) |u| try m.loadUsed(u);
                var ci = r.confirmations.iterator();
                while (ci.next()) |e| try m.loadConfirmation(e.key_ptr.*, e.value_ptr.*);
            },
        }
        if (r.own_confirmation) |c| try m.loadOwnConfirmation(c);
        m.loadRounds(r.next_round, r.last_timestamp_ms, highest_completed);
    }
};

// ---------------------------------------------------------------------------------------- tests

const group = @import("group.zig");
const hooks_mod = @import("hooks.zig");
const iface = @import("../iface.zig");

fn testCommittee(rng: std.Random, secrets: *[4][32]u8, members: *[4]manager.Member) void {
    for (0..4) |i| {
        const s = group.scalarRand(rng);
        secrets[i] = group.scalarToBytes(s);
        members[i] = .{ .name = group.g2ToBytes(group.mulPublic(group.G2, group.g2Generator(), s)), .stake = 2500 };
    }
}

/// A node of the mock committee: its manager and the durable records it wrote so far.
const Node = struct {
    mgr: *manager.Manager,
    adapter: hooks_mod.Adapter,
    log: std.ArrayList([]u8) = .empty,
    gpa: std.mem.Allocator,

    fn deinit(n: *Node) void {
        n.adapter.deinit();
        n.mgr.destroy();
        for (n.log.items) |b| n.gpa.free(b);
        n.log.deinit(n.gpa);
    }

    /// The handler's group write: the adapter's records of this commit.
    fn persist(n: *Node) !void {
        var arena = std.heap.ArenaAllocator.init(n.gpa);
        defer arena.deinit();
        const hk = n.adapter.hooks();
        if (try hk.vtable.take_records.?(hk.ctx, arena.allocator())) |bytes| try n.log.append(n.gpa, try n.gpa.dupe(u8, bytes));
    }

    /// kill -9 and restart: a new manager (fresh randomness, as Rust's try_new) restored from the log.
    fn restart(n: *Node, params: manager.Params, secret: *const [32]u8, rng: std.Random) !void {
        n.adapter.deinit();
        n.mgr.destroy();
        n.mgr = try manager.Manager.createForTesting(n.gpa, params, secret, rng);
        var rs = Restore.init(n.gpa);
        defer rs.deinit();
        for (n.log.items) |b| try rs.add(b);
        try rs.apply(n.mgr, null);
        n.adapter = hooks_mod.Adapter.init(n.gpa, n.mgr, null, params.members[0].name);
    }
};

/// A consensus commit of the mock: the DKG transactions sequenced in it, fed to every node.
const Seq = struct { from: u16, kind: enum { message, confirmation }, bytes: []u8 };

fn runCommit(nodes: []Node, members: []const manager.Member, seqs: []const Seq, round: u32, out: *std.ArrayList(Seq), gpa: std.mem.Allocator) !void {
    for (nodes, 0..) |*n, i| {
        n.adapter.beginCommit(round, 1000 + round);
        const hk = n.adapter.hooks();
        for (seqs) |s| {
            const from: iface.AuthorityName = .{ .@"0" = members[s.from].name };
            switch (s.kind) {
                .message => hk.vtable.dkg_message(hk.ctx, &from, s.bytes),
                .confirmation => hk.vtable.dkg_confirmation(hk.ctx, &from, s.bytes),
            }
        }
        var adv = try n.mgr.advanceDkg(&n.adapter.batch, round);
        defer adv.deinit(gpa);
        if (adv.confirmation_to_submit) |c| try out.append(gpa, .{ .from = @intCast(i), .kind = .confirmation, .bytes = try gpa.dupe(u8, c) });
        try n.persist();
    }
}

test "restart at every step of the DKG: every node ends with the same key, nothing is lost" {
    const gpa = std.testing.allocator;
    // crash point k: node (k % 4) is killed and restarted after commit k
    var crash_at: u32 = 0;
    while (crash_at < 6) : (crash_at += 1) {
        var prng = std.Random.DefaultPrng.init(77 + crash_at);
        const rng = prng.random();
        var secrets: [4][32]u8 = undefined;
        var members: [4]manager.Member = undefined;
        testCommittee(rng, &secrets, &members);
        const params: manager.Params = .{ .epoch = 3, .chain_id = @splat(0x5c), .members = &members, .protocol = .{ .random_beacon_reduction_lower_bound = 8, .random_beacon_reduction_allowed_delta = 800 } };
        var nodes: [4]Node = undefined;
        for (&nodes, 0..) |*n, i| {
            const m = try manager.Manager.createForTesting(gpa, params, &secrets[i], rng);
            n.* = .{ .mgr = m, .adapter = hooks_mod.Adapter.init(gpa, m, null, members[i].name), .gpa = gpa };
        }
        defer for (&nodes) |*n| n.deinit();
        // epoch start: every party deals
        var pending: std.ArrayList(Seq) = .empty;
        defer {
            for (pending.items) |s| gpa.free(s.bytes);
            pending.deinit(gpa);
        }
        for (&nodes, 0..) |*n, i| if (try n.mgr.startDkg()) |b| try pending.append(gpa, .{ .from = @intCast(i), .kind = .message, .bytes = b });
        var round: u32 = 1;
        while (round < 12) : (round += 1) {
            // one transaction per commit, in submission order
            var next: std.ArrayList(Seq) = .empty;
            defer next.deinit(gpa);
            const take = if (pending.items.len > 0) pending.items[0..1] else pending.items[0..0];
            try runCommit(&nodes, &members, take, round, &next, gpa);
            if (take.len == 1) {
                gpa.free(take[0].bytes);
                _ = pending.orderedRemove(0);
            }
            try pending.appendSlice(gpa, next.items);
            if (round == crash_at + 1) {
                const k = crash_at % 4;
                try nodes[k].restart(params, &secrets[k], rng);
                // a restarted party re-sends its message (deduplicated by consensus key in the
                // handler; here simply dropped as a duplicate)
                if (try nodes[k].mgr.startDkg()) |b| gpa.free(b);
            }
        }
        for (&nodes) |*n| try std.testing.expectEqual(manager.DkgStatus.successful, n.mgr.dkgStatus());
        const pk0 = group.g2ToBytes(nodes[0].mgr.publicKey().?);
        for (nodes[1..]) |*n| try std.testing.expectEqualSlices(u8, &pk0, &group.g2ToBytes(n.mgr.publicKey().?));
        // a restart after completion keeps the output (no new DKG message)
        try nodes[2].restart(params, &secrets[2], rng);
        try std.testing.expectEqual(manager.DkgStatus.successful, nodes[2].mgr.dkgStatus());
        try std.testing.expect((try nodes[2].mgr.startDkg()) == null);
        try std.testing.expectEqualSlices(u8, &pk0, &group.g2ToBytes(nodes[2].mgr.publicKey().?));
    }
}

test "a timed-out DKG stays failed after a restart (Sui PR 26846)" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(26846);
    const rng = prng.random();
    var secrets: [4][32]u8 = undefined;
    var members: [4]manager.Member = undefined;
    testCommittee(rng, &secrets, &members);
    var params: manager.Params = .{ .epoch = 9, .chain_id = @splat(0x26), .members = &members, .protocol = .{ .random_beacon_reduction_lower_bound = 8, .random_beacon_reduction_allowed_delta = 800 } };
    params.protocol.random_beacon_dkg_timeout_round = 5;
    params.protocol.allow_dkg_completion_after_timeout = false;
    params.protocol.always_advance_dkg_to_resolution = true;
    const m = try manager.Manager.createForTesting(gpa, params, &secrets[0], rng);
    var nodes = [_]Node{.{ .mgr = m, .adapter = undefined, .gpa = gpa }};
    const n = &nodes[0];
    n.adapter = hooks_mod.Adapter.init(gpa, m, null, members[0].name);
    defer n.deinit();
    // only our own message is ever sequenced: no quorum, the DKG can only time out
    const own = (try n.mgr.startDkg()).?;
    defer gpa.free(own);
    var next: std.ArrayList(Seq) = .empty;
    defer next.deinit(gpa);
    try runCommit(&nodes, &members, &.{.{ .from = 0, .kind = .message, .bytes = own }}, 1, &next, gpa);
    var round: u32 = 2;
    while (round <= 7) : (round += 1) try runCommit(&nodes, &members, &.{}, round, &next, gpa);
    try std.testing.expectEqual(manager.DkgStatus.timed_out, n.mgr.dkgStatus());
    // the verdict is on disk: restart and it is still timed out, even for an early commit round
    try n.restart(params, &secrets[0], rng);
    try std.testing.expectEqual(manager.DkgStatus.timed_out, n.mgr.dkgStatus());
    try std.testing.expectEqual(manager.DkgStatus.timed_out, n.mgr.dkgStatusForCommitRound(1));
    try std.testing.expect((try n.mgr.startDkg()) == null);
    // without the verdict's record (the pre-26846 bug) the restarted node would read pending
    var rs = Restore.init(gpa);
    defer rs.deinit();
    for (n.log.items[0 .. n.log.items.len - 1]) |bytes| try rs.add(bytes);
    try std.testing.expect(rs.output == .unset);
}

test "encode and fold round trip" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var b = manager.Batch.init(gpa);
    defer b.deinit();
    try std.testing.expect((try encode(arena.allocator(), &b)) == null);
    try b.processed.append(gpa, .{ .sender = 2, .bytes = try gpa.dupe(u8, "p2") });
    try b.confirmations.append(gpa, .{ .sender = 1, .bytes = try gpa.dupe(u8, "c1") });
    b.dkg_output = .failed;
    b.reserved_round = .{ .next_round = 4, .timestamp_ms = 99 };
    const bytes = (try encode(arena.allocator(), &b)).?;
    var r = Restore.init(gpa);
    defer r.deinit();
    try r.add(bytes);
    try std.testing.expectEqualStrings("p2", r.processed.get(2).?);
    try std.testing.expectEqualStrings("c1", r.confirmations.get(1).?);
    try std.testing.expect(r.output == .failed);
    try std.testing.expectEqual(@as(?u64, 4), r.next_round);
    try std.testing.expectError(error.Corrupt, r.add(bytes[0 .. bytes.len - 3]));
}
