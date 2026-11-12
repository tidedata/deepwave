//! Tests of the index check (verify.zig, `deepwave-tool verify-index`): a stale owner row and a wrong
//! balance row, left the way a replay that could not read an old version leaves them, are
//! reported exactly; a correct index is identical, at the store tip and below it.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const index = @import("root.zig");
const lsm = @import("lsm.zig");
const verify = @import("verify.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;

fn addr(n: u8) [32]u8 {
    var a: [32]u8 = @splat(0);
    a[31] = n;
    return a;
}

/// BCS(Object) of a `Coin<SUI>` of `owner` (an address, or a parent object).
fn coin(a: Allocator, id: [32]u8, version: u64, balance: u64, owner: [32]u8, object_owned: bool) ![]const u8 {
    var contents: [40]u8 = undefined;
    @memcpy(contents[0..32], &id);
    std.mem.writeInt(u64, contents[32..40], balance, .little);
    const o: types.Object = .{
        .data = .{ .Move = .{ .type_ = .{ .@"0" = .GasCoin }, .has_public_transfer = true, .version = .{ .@"0" = version }, .contents = &contents } },
        .owner = if (object_owned) .{ .ObjectOwner = .{ .@"0" = owner } } else .{ .AddressOwner = .{ .@"0" = owner } },
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(7) } },
        .storage_rebate = 0,
    };
    return bcs.encodeAlloc(types.Object, a, &o);
}

fn has(text: []const u8, s: []const u8) bool {
    return std.mem.indexOf(u8, text, s) != null;
}

const owner_a = addr(0xa1);
const owner_b = addr(0xb2);
const owner_c = addr(0xc3);
const coin1 = addr(0xc1);
const coin2 = addr(0xc2);
const coin3 = addr(0xd3);
const coin4 = addr(0xd4);

/// The objects of the story both tests tell. Checkpoint 1: A owns coin1 (100) and coin2 (200),
/// C owns coin3 (70). Checkpoint 2 sends coin1 and coin3 to B (version 6 each).
const Story = struct {
    c1v5: []const u8,
    c2v5: []const u8,
    c3v5: []const u8,
    c1v6: []const u8,
    c3v6: []const u8,

    fn make(a: Allocator) !Story {
        return .{
            .c1v5 = try coin(a, coin1, 5, 100, owner_a, false),
            .c2v5 = try coin(a, coin2, 5, 200, owner_a, false),
            .c3v5 = try coin(a, coin3, 5, 70, owner_c, false),
            .c1v6 = try coin(a, coin1, 6, 100, owner_b, false),
            .c3v6 = try coin(a, coin3, 6, 70, owner_b, false),
        };
    }

    /// Checkpoint 2 as it is, and as a replay that could not read the old versions made it
    /// (`feed.changesFromStore` with missing_old: the new rows go in, the old ones stay).
    fn right(s: *const Story) [2]index.Index.Change {
        return .{ .{ .old = s.c1v5, .new = s.c1v6 }, .{ .old = s.c3v5, .new = s.c3v6 } };
    }
    fn stale(s: *const Story) [2]index.Index.Change {
        return .{ .{ .old = null, .new = s.c1v6 }, .{ .old = null, .new = s.c3v6 } };
    }
};

/// What the stale index must be reported as: A still lists coin1 and C coin3 (two stale owner
/// rows), A's SUI balance is 300 for 200 (differs), C still has a balance row of 70 (stale).
fn expectStaleReport(d: *const verify.Diff) !void {
    try testing.expect(!d.identical());
    try testing.expectEqual(@as(u64, 2), d.count(.owner_stale));
    try testing.expectEqual(@as(u64, 1), d.count(.balance_differs));
    try testing.expectEqual(@as(u64, 1), d.count(.balance_stale));
    for ([_]verify.Class{ .owner_missing, .owner_version, .balance_missing, .coin_stale, .coin_missing }) |c| try testing.expectEqual(@as(u64, 0), d.count(c));
    try testing.expectEqual(@as(u64, 3), d.stale());
    try testing.expectEqual(@as(u64, 0), d.missing());
    try testing.expectEqual(@as(u64, 1), d.differing());

    // the stale owner rows, in key order: A's coin1 at version 5, then C's coin3 at version 5
    const so = d.examplesOf(.owner_stale);
    try testing.expectEqual(@as(usize, 2), so.len);
    for (so, [_][32]u8{ owner_a, owner_c }, [_][32]u8{ coin1, coin3 }, [_]u64{ 100, 70 }) |e, owner, id, bal| {
        try testing.expectEqual(@as(u8, @intFromEnum(index.Table.owner)), e.key[0]);
        try testing.expectEqual(@as(u8, @intFromEnum(index.Kind.address)), e.key[1]);
        try testing.expectEqualSlices(u8, &owner, e.key[2..34]);
        const row = try index.splitOwnerSuffix(e.key[34..]);
        try testing.expectEqualSlices(u8, &id, row.id);
        try testing.expectEqual(@as(?u64, bal), row.balance);
        try testing.expectEqual(@as(u64, 5), e.serving.?.version());
        try testing.expect(e.scratch == null);
    }
    // A's balance: 300 in the serving index, 200 by the live set
    const bd = d.examplesOf(.balance_differs);
    try testing.expectEqual(@as(usize, 1), bd.len);
    try testing.expectEqualSlices(u8, &owner_a, bd[0].key[1..33]);
    try testing.expectEqual(@as(i128, 300), bd[0].serving.?.pair()[0]);
    try testing.expectEqual(@as(i128, 200), bd[0].scratch.?.pair()[0]);
    // C's balance row should be gone
    const bs = d.examplesOf(.balance_stale);
    try testing.expectEqual(@as(usize, 1), bs.len);
    try testing.expectEqualSlices(u8, &owner_c, bs[0].key[1..33]);
    try testing.expectEqual(@as(i128, 70), bs[0].serving.?.pair()[0]);
    try testing.expect(bs[0].scratch == null);
}

fn expectStaleText(t: []const u8) !void {
    try testing.expect(has(t, "owner rows only in the serving index (stale): 2\n"));
    try testing.expect(has(t, "owner rows only in the scratch build (missing): 0\n"));
    try testing.expect(has(t, "balance rows only in the serving index (stale): 1\n"));
    try testing.expect(has(t, "balance rows that differ: 1\n"));
    // owner, type, object id, version
    try testing.expect(has(t, "  owner 0x00000000000000000000000000000000000000000000000000000000000000a1 (address) type "));
    try testing.expect(has(t, "::coin::Coin<"));
    try testing.expect(has(t, "::sui::SUI>"));
    try testing.expect(has(t, " object 0x00000000000000000000000000000000000000000000000000000000000000c1 coin balance 100 version 5\n"));
    try testing.expect(has(t, " object 0x00000000000000000000000000000000000000000000000000000000000000d3 coin balance 70 version 5\n"));
    // the two balances
    try testing.expect(has(t, ": serving coins 300 address balance 0, scratch coins 200 address balance 0\n"));
    try testing.expect(has(t, ": serving coins 70 address balance 0\n"));
}

/// The list for a script: A and C by object type (their owned lists are wrong), A and C by
/// coin type (their balances are), one line each.
fn expectAffected(d: *const verify.Diff, t: []const u8) !void {
    try testing.expectEqual(@as(u64, 4), d.affected_total);
    try testing.expectEqual(@as(usize, 4), d.affected.items.len);
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, t, "\naffected\t"));
    const two = "0x0000000000000000000000000000000000000000000000000000000000000002";
    const coin_t = two ++ "::coin::Coin<" ++ two ++ "::sui::SUI>";
    const sui_t = two ++ "::sui::SUI";
    try testing.expect(has(t, "\naffected\towned\t0x00000000000000000000000000000000000000000000000000000000000000a1\t" ++ coin_t ++ "\n"));
    try testing.expect(has(t, "\naffected\towned\t0x00000000000000000000000000000000000000000000000000000000000000c3\t" ++ coin_t ++ "\n"));
    try testing.expect(has(t, "\naffected\tbalance\t0x00000000000000000000000000000000000000000000000000000000000000a1\t" ++ sui_t ++ "\n"));
    try testing.expect(has(t, "\naffected\tbalance\t0x00000000000000000000000000000000000000000000000000000000000000c3\t" ++ sui_t ++ "\n"));
}

test "verify: the row comparison reports a stale owner row and a wrong balance exactly, and nothing for equal indexes" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const s = try Story.make(a);

    // the live set after checkpoint 2
    var want = try index.Index.init(gpa);
    defer want.deinit();
    for ([_][]const u8{ s.c1v6, s.c2v5, s.c3v6 }) |raw| try want.insert(raw);

    // checkpoint 1's live set, then checkpoint 2 applied without the old versions
    var bad = try index.Index.init(gpa);
    defer bad.deinit();
    for ([_][]const u8{ s.c1v5, s.c2v5, s.c3v5 }) |raw| try bad.insert(raw);
    try bad.applyChanges(2, &s.stale());
    {
        var d = verify.Diff.init(gpa);
        defer d.deinit();
        try verify.diffDbs(gpa, &bad.db, &want.db, &d, null);
        try expectStaleReport(&d);
        // owner rows: A coin1 (stale), A coin2, B coin1, B coin3, C coin3 (stale); balances: A, B, C
        try testing.expectEqual(@as(u64, 8), d.compared);
        try testing.expectEqual(@as(u64, 8), d.serving_rows);
        try testing.expectEqual(@as(u64, 5), d.scratch_rows);
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        try d.print(&out.writer);
        try d.printAffected(&out.writer);
        const t = out.writer.buffered();
        try testing.expect(has(t, "rows compared: 8 (serving index 8, scratch build 5)\n"));
        try expectStaleText(t);
        try expectAffected(&d, t);
    }
    // the other way round the same rows are missing
    {
        var d = verify.Diff.init(gpa);
        defer d.deinit();
        try verify.diffDbs(gpa, &want.db, &bad.db, &d, null);
        try testing.expectEqual(@as(u64, 2), d.count(.owner_missing));
        try testing.expectEqual(@as(u64, 1), d.count(.balance_missing));
        try testing.expectEqual(@as(u64, 1), d.count(.balance_differs));
        try testing.expectEqual(@as(u64, 0), d.stale());
    }

    // checkpoint 2 applied with the old versions: the same rows as the live set
    var good = try index.Index.init(gpa);
    defer good.deinit();
    for ([_][]const u8{ s.c1v5, s.c2v5, s.c3v5 }) |raw| try good.insert(raw);
    try good.applyChanges(2, &s.right());
    var d = verify.Diff.init(gpa);
    defer d.deinit();
    try verify.diffDbs(gpa, &good.db, &want.db, &d, null);
    try testing.expect(d.identical());
    try testing.expectEqual(@as(u64, 5), d.compared);
    try testing.expectEqual(d.serving_rows, d.scratch_rows);
    // C's SUI balance was emptied by checkpoint 2: the fed index keeps that row at zero until a
    // bottom merge (ListBalances lists it, as sui-node does), a build from the live set has no
    // such row. It is counted on its own and is not a stale row.
    try testing.expectEqual(@as(u64, 1), d.held_zero);
    try testing.expectEqual(@as(u64, 0), d.stale());
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try d.print(&out.writer);
    try testing.expect(has(out.writer.buffered(), "rows compared: 5 (serving index 5, scratch build 5)\n"));
    try testing.expect(has(out.writer.buffered(), "balance rows emptied to zero that the serving index keeps until a bottom merge (not differences, not compared): 1\n"));
    try testing.expect(has(out.writer.buffered(), "balance rows only in the serving index (stale): 0\n"));
    // a kept zero row is not "missing" either when the build is the serving side
    var back = verify.Diff.init(gpa);
    defer back.deinit();
    try verify.diffDbs(gpa, &want.db, &good.db, &back, null);
    try testing.expectEqual(@as(u64, 1), back.count(.balance_missing));
    try testing.expectEqual(@as(u64, 0), back.held_zero);
}

/// An on-disk index over `st` at checkpoint 1 (built from the live set), taken to checkpoint 2
/// by `changes` and closed, so its durable watermark is 2.
fn servingIndex(gpa: Allocator, st: *store.Store, dir: []const u8, changes: []const index.Index.Change) !void {
    const ix = try index.Index.open(gpa, testing.io, dir, .{ .build_threads = 3, .build_mem_bytes = 16 << 20, .sync = .none });
    defer {
        ix.deinit();
        gpa.destroy(ix);
    }
    var f = index.feed.Feed.init(gpa, ix, st);
    defer f.deinit();
    const rep = try f.start();
    try testing.expect(rep.built);
    try testing.expectEqual(@as(?u64, 1), ix.db.watermark());
    try ix.applyChanges(2, changes);
}

fn check(gpa: Allocator, st: *store.Store, state_dir: []const u8, scratch: []const u8, out: *std.Io.Writer.Allocating, free: ?u64) !verify.Result {
    return verify.run(gpa, testing.io, st, .{ .state_dir = state_dir, .scratch = scratch, .threads = 3, .build_mem_bytes = 16 << 20, .free_override = free }, &out.writer);
}

test "verify: a serving index with stale rows is reported against a build from the store's live set; a correct one is identical, also when the store has moved on" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var cfg: store.Config = .{
        .max_live_objects = 8192,
        .max_object_versions = 16384,
        .max_transactions = 1024,
        .max_checkpoints = 1024,
        .max_batch_bytes = 4 << 20,
        .max_batch_objects = 4096,
        .max_segments = 64,
        .index_flush_interval = 8,
        .segment_reserve = 16 << 20,
        .seed = 47,
    };
    const sim = try store.SimIo.init(gpa, 47, .{}, 64 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    const s = try Story.make(a);
    var prng = std.Random.DefaultPrng.init(9);
    const r = prng.random();

    // checkpoint 1: the story's three coins among 600 others of other owners and parents
    {
        const b = try st.begin(1, 0);
        for ([_]struct { raw: []const u8, id: [32]u8 }{ .{ .raw = s.c1v5, .id = coin1 }, .{ .raw = s.c2v5, .id = coin2 }, .{ .raw = s.c3v5, .id = coin3 } }) |o| try b.putObject(&o.id, 5, &types.digest.objectDigest(o.raw), o.raw);
        for (0..600) |i| {
            var id: [32]u8 = undefined;
            r.bytes(&id);
            id[0] = 0x10; // never one of the story's ids
            const raw = try coin(a, id, 3 + i % 5, r.uintLessThan(u64, 1000) + 1, addr(1 + r.uintLessThan(u8, 60)), i % 7 == 0);
            try b.putObject(&id, 3 + i % 5, &types.digest.objectDigest(raw), raw);
        }
        try b.checkpoint("summary", "contents");
        try st.commit(b);
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const good_dir = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/good", .{tmp.sub_path});
    const bad_dir = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/bad", .{tmp.sub_path});
    const scratch = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/scratch", .{tmp.sub_path});
    const scratch_ix = try std.fs.path.join(a, &.{ scratch, verify.scratch_sub });

    // Two serving indexes built at checkpoint 1 and taken to checkpoint 2: one with the old
    // versions (right), one as a replay that could not read them leaves it (stale rows).
    try servingIndex(gpa, st, good_dir, &s.right());
    try servingIndex(gpa, st, bad_dir, &s.stale());
    {
        const b = try st.begin(2, 0);
        try b.putObject(&coin1, 6, &types.digest.objectDigest(s.c1v6), s.c1v6);
        try b.putObject(&coin3, 6, &types.digest.objectDigest(s.c3v6), s.c3v6);
        try b.checkpoint("summary", "contents");
        try st.commit(b);
    }

    // The stale index: exactly its two stale owner rows and its two wrong balance rows.
    {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var res = try check(gpa, st, bad_dir, scratch, &out, null);
        defer res.deinit();
        try testing.expectEqual(verify.Outcome.different, res.outcome);
        try testing.expectEqual(@as(?u64, 2), res.watermark);
        try testing.expectEqual(@as(?u64, 2), res.tip);
        try testing.expectEqual(@as(u64, 603), res.objects);
        try expectStaleReport(&res.diff.?);
        const t = out.writer.buffered();
        try expectStaleText(t);
        try expectAffected(&res.diff.?, t);
        try testing.expect(has(t, "last stop: "));
        try testing.expect(has(t, "verdict: DIFFERENT: the state index at checkpoint 2 has 3 stale, 0 missing and 1 differing rows"));
        // the scratch index is removed again
        try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(testing.io, scratch_ix, .{}));
    }
    // The right index: identical.
    {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var res = try check(gpa, st, good_dir, scratch, &out, null);
        defer res.deinit();
        try testing.expectEqual(verify.Outcome.identical, res.outcome);
        try testing.expect(res.diff.?.identical());
        try testing.expect(res.diff.?.compared > 600);
        try testing.expectEqual(res.diff.?.serving_rows, res.diff.?.scratch_rows);
        try testing.expect(has(out.writer.buffered(), "verdict: IDENTICAL: the state index at checkpoint 2 equals"));
    }
    // Too little scratch space: refused before anything is built.
    {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var res = try check(gpa, st, good_dir, scratch, &out, 0);
        defer res.deinit();
        try testing.expectEqual(verify.Outcome.cannot_check, res.outcome);
        try testing.expect(res.diff == null);
        try testing.expect(has(out.writer.buffered(), "not enough scratch space"));
        try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(testing.io, scratch_ix, .{}));
    }
    // A scratch directory that holds something is left alone.
    {
        try std.Io.Dir.cwd().createDirPath(testing.io, try std.fs.path.join(a, &.{ scratch_ix, "kept" }));
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var res = try check(gpa, st, good_dir, scratch, &out, null);
        defer res.deinit();
        try testing.expectEqual(verify.Outcome.cannot_check, res.outcome);
        try testing.expect(has(out.writer.buffered(), "is not empty"));
        try std.Io.Dir.cwd().access(testing.io, try std.fs.path.join(a, &.{ scratch_ix, "kept" }), .{});
        try std.Io.Dir.cwd().deleteTree(testing.io, scratch_ix);
    }

    // The store moves on (checkpoint 3: coin2 changes, coin3 is deleted, C gets coin4) while
    // both indexes stay at 2, as after a stop that left the index behind: the comparison is
    // at checkpoint 2, from the versions that were live then.
    {
        const b = try st.begin(3, 0);
        const c2v6 = try coin(a, coin2, 6, 250, owner_a, false);
        try b.putObject(&coin2, 6, &types.digest.objectDigest(c2v6), c2v6);
        try b.removeObject(&coin3, 7, .deleted);
        const c4v7 = try coin(a, coin4, 7, 5, owner_c, false);
        try b.putObject(&coin4, 7, &types.digest.objectDigest(c4v7), c4v7);
        try b.checkpoint("summary", "contents");
        try st.commit(b);
    }
    {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var res = try check(gpa, st, good_dir, scratch, &out, null);
        defer res.deinit();
        try testing.expectEqual(verify.Outcome.identical, res.outcome);
        try testing.expectEqual(@as(?u64, 2), res.watermark);
        try testing.expectEqual(@as(?u64, 3), res.tip);
        try testing.expectEqual(@as(u64, 603), res.objects);
        try testing.expect(has(out.writer.buffered(), "the state index is 1 checkpoints behind the store"));
    }
    {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var res = try check(gpa, st, bad_dir, scratch, &out, null);
        defer res.deinit();
        try testing.expectEqual(verify.Outcome.different, res.outcome);
        try expectStaleReport(&res.diff.?);
        try expectStaleText(out.writer.buffered());
    }
    // Nothing of either serving index changed: both still open at watermark 2 with no build.
    for ([_][]const u8{ good_dir, bad_dir }) |dir| {
        const ix = try index.Index.open(gpa, testing.io, dir, .{ .read_only = true, .sync = .none });
        defer {
            ix.deinit();
            gpa.destroy(ix);
        }
        try testing.expectEqual(@as(?u64, 2), ix.db.watermark());
        try testing.expect(ix.db.buildPending() == null);
    }
}

test "verify: no index, and an index that was never built, are not checked" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var cfg: store.Config = .{ .max_live_objects = 1024, .max_object_versions = 4096, .max_transactions = 1024, .max_checkpoints = 1024, .max_batch_bytes = 1 << 20, .max_batch_objects = 256, .max_segments = 64, .index_flush_interval = 8, .segment_reserve = 8 << 20, .seed = 48 };
    const sim = try store.SimIo.init(gpa, 48, .{}, 8 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const none_dir = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/none", .{tmp.sub_path});
    const empty_dir = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/empty", .{tmp.sub_path});
    const scratch = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/scratch", .{tmp.sub_path});
    {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var res = try check(gpa, st, none_dir, scratch, &out, null);
        defer res.deinit();
        try testing.expectEqual(verify.Outcome.cannot_check, res.outcome);
        try testing.expect(has(out.writer.buffered(), "no state index at "));
        // a read-only check does not create the directory it was pointed at
        try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(testing.io, none_dir, .{}));
    }
    {
        // an index directory a node opened and never built into
        const ix = try index.Index.open(gpa, testing.io, empty_dir, .{ .sync = .none });
        ix.deinit();
        gpa.destroy(ix);
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var res = try check(gpa, st, empty_dir, scratch, &out, null);
        defer res.deinit();
        try testing.expectEqual(verify.Outcome.cannot_check, res.outcome);
        try testing.expect(has(out.writer.buffered(), "verdict: NOT CHECKED"));
    }
}

fn putCoin(b: *store.Batch, raw: []const u8, id: [32]u8, version: u64) !void {
    try b.putObject(&id, version, &types.digest.objectDigest(raw), raw);
}

test "verify: on a store of real files it says whether the last stop was clean, and checks the index after a clean stop and after a kill" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const ix_dir = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/state-index", .{tmp.sub_path});
    const scratch = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/scratch", .{tmp.sub_path});
    var cfg: store.Config = .{ .dir = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/store", .{tmp.sub_path}), .max_live_objects = 1 << 12, .segment_reserve = 8 << 20 };
    const s = try Story.make(a);
    var prng = std.Random.DefaultPrng.init(11);
    const r = prng.random();

    // The node's life: checkpoint 1, the index built, checkpoint 2 in the store and the index,
    // a clean stop.
    {
        const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        {
            const b = try h.store.begin(1, 0);
            try putCoin(b, s.c1v5, coin1, 5);
            try putCoin(b, s.c2v5, coin2, 5);
            try putCoin(b, s.c3v5, coin3, 5);
            for (0..200) |i| {
                var id: [32]u8 = undefined;
                r.bytes(&id);
                id[0] = 0x10;
                try putCoin(b, try coin(a, id, 4, r.uintLessThan(u64, 1000) + 1, addr(1 + r.uintLessThan(u8, 60)), i % 5 == 0), id, 4);
            }
            try b.checkpoint("summary", "contents");
            try h.store.commit(b);
        }
        try servingIndex(gpa, h.store, ix_dir, &s.right());
        {
            const b = try h.store.begin(2, 0);
            try putCoin(b, s.c1v6, coin1, 6);
            try putCoin(b, s.c3v6, coin3, 6);
            try b.checkpoint("summary", "contents");
            try h.store.commit(b);
        }
        try h.store.close();
    }
    // The stopped node, as deepwave-tool opens it (and leaves it: no flush).
    {
        const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        defer h.store.deinit();
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var res = try check(gpa, h.store, ix_dir, scratch, &out, null);
        defer res.deinit();
        try testing.expectEqual(verify.Outcome.identical, res.outcome);
        try testing.expect(res.clean_stop);
        try testing.expectEqual(@as(u64, 203), res.objects);
        try testing.expect(has(out.writer.buffered(), "last stop: clean"));
    }
    // The node runs again, commits checkpoint 3 (coin2 changes, coin3 is deleted) and is
    // killed: the index stays at 2.
    {
        const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        defer h.store.deinit();
        const b = try h.store.begin(3, 0);
        try putCoin(b, try coin(a, coin2, 6, 250, owner_a, false), coin2, 6);
        try b.removeObject(&coin3, 7, .deleted);
        try b.checkpoint("summary", "contents");
        try h.store.commit(b);
    }
    {
        const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        defer h.store.deinit();
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var res = try check(gpa, h.store, ix_dir, scratch, &out, null);
        defer res.deinit();
        const t = out.writer.buffered();
        try testing.expect(!res.clean_stop);
        try testing.expect(has(t, "last stop: NOT clean ("));
        try testing.expectEqual(@as(?u64, 2), res.watermark);
        try testing.expectEqual(@as(?u64, 3), res.tip);
        // compared at checkpoint 2, from the versions live then
        try testing.expectEqual(verify.Outcome.identical, res.outcome);
        try testing.expectEqual(@as(u64, 203), res.objects);
    }
}

test "verify: the private and the file-backed resident size are read from a /proc status text" {
    const text =
        \\Name:   deepwave-tool
        \\VmPeak: 412345678 kB
        \\VmHWM:  131801088 kB
        \\VmRSS:   98765432 kB
        \\RssAnon:   9123456 kB
        \\RssFile: 89641976 kB
        \\RssShmem:        0 kB
        \\Threads: 40
        \\
    ;
    const r = verify.parseStatus(text);
    try testing.expectEqual(@as(u64, 9123456), r.anon_kb);
    try testing.expectEqual(@as(u64, 89641976), r.file_kb);
    try testing.expectEqual(@as(u64, 0), r.shmem_kb);
    try testing.expectEqual(@as(u64, 131801088), r.hwm_kb);
    // not a status text: zeros, no failure
    try testing.expectEqual(@as(u64, 0), verify.parseStatus("VmHWM:\nRssAnon: x kB").anon_kb);
    // this process, where the kernel says (Linux)
    if (verify.readRss()) |now| {
        try testing.expect(now.anon_kb > 0);
        try testing.expect(now.hwm_kb >= now.anon_kb);
    }
}

test "verify: the memory it needs is said up front, and a machine with less is refused" {
    // mainnet's shape: 775M live-table entries, a 2 GiB build, the tool's 256 MiB chunk cache,
    // and 1.5 GiB held by the open store and the serving index
    const need = verify.memoryNeed(775_000_000, 2 << 30, 256 << 20, 3 << 29);
    try testing.expect(need > 9 << 30 and need < 10 << 30);
    try testing.expectEqual(@as(?u64, 13_000_000 << 10), verify.parseMemAvailable("MemTotal:       32000000 kB\nMemFree:          100000 kB\nMemAvailable:   13000000 kB\n"));
    try testing.expectEqual(@as(?u64, null), verify.parseMemAvailable("MemTotal: 1 kB\n"));

    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var cfg: store.Config = .{ .max_live_objects = 1024, .max_object_versions = 4096, .max_transactions = 1024, .max_checkpoints = 1024, .max_batch_bytes = 1 << 20, .max_batch_objects = 256, .max_segments = 64, .index_flush_interval = 8, .segment_reserve = 8 << 20, .cache_bytes = 4 << 20, .seed = 49 };
    const sim = try store.SimIo.init(gpa, 49, .{}, 8 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    const s = try Story.make(a);
    {
        const b = try st.begin(1, 0);
        try putCoin(b, s.c1v5, coin1, 5);
        try putCoin(b, s.c2v5, coin2, 5);
        try putCoin(b, s.c3v5, coin3, 5);
        try b.checkpoint("summary", "contents");
        try st.commit(b);
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const ix_dir = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/state-index", .{tmp.sub_path});
    const scratch = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/scratch", .{tmp.sub_path});
    try servingIndex(gpa, st, ix_dir, &s.right());
    {
        const b = try st.begin(2, 0);
        try putCoin(b, s.c1v6, coin1, 6);
        try putCoin(b, s.c3v6, coin3, 6);
        try b.checkpoint("summary", "contents");
        try st.commit(b);
    }
    const opts: verify.Options = .{ .state_dir = ix_dir, .scratch = scratch, .threads = 2, .build_mem_bytes = 16 << 20 };
    // What it will say it needs beyond what the open store and serving index hold already
    // (in a test that base is added up, not measured): 3 entries, the budget, the cache.
    const want = verify.memoryNeed(3, 16 << 20, 4 << 20, 0);
    // one byte short: refused before anything is built
    {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var o = opts;
        o.mem_override = want - 1;
        var res = try verify.run(gpa, testing.io, st, o, &out.writer);
        defer res.deinit();
        const t = out.writer.buffered();
        try testing.expectEqual(verify.Outcome.cannot_check, res.outcome);
        try testing.expect(has(t, "not enough memory: "));
        // the base it counted: the store's memtables and the serving index, more than nothing
        try testing.expect(res.mem_need > want + st.indexMemory().memtables);
        try testing.expect(has(t, try std.fmt.allocPrint(a, "needs: about {d} MiB of private memory at its peak", .{res.mem_need >> 20})));
        try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(testing.io, try std.fs.path.join(a, &.{ scratch, verify.scratch_sub }), .{}));
    }
    // enough: checked
    {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var o = opts;
        o.mem_override = want;
        var res = try verify.run(gpa, testing.io, st, o, &out.writer);
        defer res.deinit();
        try testing.expectEqual(verify.Outcome.identical, res.outcome);
        try testing.expect(has(out.writer.buffered(), try std.fmt.allocPrint(a, "available memory: {d} MiB\n", .{want >> 20})));
    }
}
