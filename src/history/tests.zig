//! Unit tests of the history index on corpus checkpoints ($ZUI_CORPUS/chk; skipped without it).
const std = @import("std");
const root = @import("root.zig");
const bcs = @import("bcs");
const types = @import("types");

fn corpusChks(a: std.mem.Allocator, io: std.Io, n: usize) !?[]const []const u8 {
    const corpus = std.c.getenv("ZUI_CORPUS") orelse return null;
    var dir = std.Io.Dir.cwd().openDir(io, std.mem.span(corpus), .{}) catch return null;
    defer dir.close(io);
    const names = [_][]const u8{ "342456120", "342456121", "342456122", "342456123", "342456124", "342456125" };
    var out: std.ArrayList([]const u8) = .empty;
    for (names[0..n]) |nm| {
        const p = try std.fmt.allocPrint(a, "chk/{s}.chk", .{nm});
        const b = dir.readFileAlloc(io, p, a, .limited(1 << 30)) catch return null;
        try out.append(a, b);
    }
    return out.items;
}

test "index, read back, persist, replay, prune" {
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const blobs = (try corpusChks(a, io, 6)) orelse return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/hist", .{tmp.sub_path});

    var firsts: [6]u64 = undefined;
    var seqs: [6]u64 = undefined;
    var sender0: [32]u8 = undefined;
    var digest0: [32]u8 = undefined;
    for (blobs, 0..) |b, i| {
        const cp = try bcs.decode(types.CheckpointData, a, b[1..]);
        seqs[i] = cp.checkpoint_summary.data.sequence_number;
        firsts[i] = cp.checkpoint_summary.data.network_total_transactions - cp.transactions.len;
        if (i == 0) {
            const t = &cp.transactions[cp.transactions.len - 1];
            sender0 = t.transaction.data.@"0".element().intent_message.value.V1.sender.@"0";
            digest0 = switch (t.effects) {
                .V2 => |v| v.transaction_digest.@"0".@"0",
                .V1 => |v| v.transaction_digest.@"0".@"0",
            };
        }
    }
    var key: [33]u8 = undefined;
    key[0] = @intFromEnum(root.Dim.sender);
    key[1..].* = sender0;

    {
        const ix = try root.Index.init(gpa, io, dir);
        defer ix.deinit();
        for (blobs, seqs) |b, s| {
            try ix.addCheckpoint(s, b);
            try ix.addCheckpoint(s, b); // idempotent
        }
        {
            var r = ix.reader();
            defer r.release();
            try std.testing.expect(r.range() == null); // nothing published yet
        }
        ix.publish(seqs[5]);
        var r = ix.reader();
        defer r.release();
        const rg = r.range().?;
        try std.testing.expectEqual(seqs[0], rg.lo);
        try std.testing.expectEqual(seqs[5], rg.hi);
        const c1 = r.checkpointTxs(seqs[1]).?;
        try std.testing.expectEqual(firsts[1], c1.first);
        try std.testing.expectEqual(firsts[2] - firsts[1], c1.count);
        const last0 = firsts[1] - 1;
        try std.testing.expectEqual(seqs[0], r.checkpointOfTx(last0).?);
        try std.testing.expectEqual(seqs[1], r.checkpointOfTx(firsts[1]).?);
        const row = r.txRow(last0).?;
        try std.testing.expectEqualSlices(u8, &digest0, &row.digest);
        try std.testing.expectEqual(@as(u32, @intCast(last0 - firsts[0])), row.tx_offset);
        try std.testing.expectEqual(last0, r.txSeqOfDigest(&digest0).?);
        const bs = r.buckets(.tx, &key);
        try std.testing.expect(bs.len >= 1);
        var found = false;
        for (bs) |bk| for (bk.bits) |bit| {
            if (bk.id * root.tx_bucket_size + bit == last0) found = true;
        };
        try std.testing.expect(found);
    }
    // Reopen: replay the log.
    {
        const ix = try root.Index.init(gpa, io, dir);
        defer ix.deinit();
        try std.testing.expectEqual(seqs[5], ix.indexedHi().?);
        ix.publish(seqs[5]);
        var r = ix.reader();
        const rg = r.range().?;
        try std.testing.expectEqual(seqs[5], rg.hi);
        try std.testing.expect(r.buckets(.tx, &key).len >= 1);
        r.release();
        ix.pruneBelow(seqs[2]);
        var r2 = ix.reader();
        defer r2.release();
        try std.testing.expectEqual(seqs[2], r2.range().?.lo);
        try std.testing.expect(r2.txRow(last0Of(firsts)) == null);
        try std.testing.expect(r2.txRow(firsts[2]) != null);
    }
    // Reopen after prune: snapshot + fresh log.
    {
        const ix = try root.Index.init(gpa, io, dir);
        defer ix.deinit();
        try ix.addCheckpoint(seqs[5], blobs[5]); // already there: skipped
        ix.publish(seqs[5]);
        var r = ix.reader();
        defer r.release();
        try std.testing.expectEqual(seqs[2], r.range().?.lo);
        try std.testing.expectEqual(seqs[5], r.range().?.hi);
        // Same bucket contents as before the prune for the sender (the bucket is not below the floor).
        try std.testing.expect(r.buckets(.tx, &key).len >= 1);
    }
    // A hole restarts the index at the new checkpoint.
    {
        const ix = try root.Index.init(gpa, io, null);
        defer ix.deinit();
        try ix.addCheckpoint(seqs[0], blobs[0]);
        try ix.addCheckpoint(seqs[2], blobs[2]);
        ix.publish(seqs[2]);
        var r = ix.reader();
        defer r.release();
        try std.testing.expectEqual(seqs[2], r.range().?.lo);
        try std.testing.expect(r.buckets(.tx, &key).len == 0 or r.checkpointOfTx(firsts[0]) == null);
    }
}

test "prune then crash-free reopen keeps the same content (corpus)" {
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const blobs = (try corpusChks(a, io, 6)) orelse return error.SkipZigTest;
    var seqs: [6]u64 = undefined;
    for (blobs, 0..) |b, i| seqs[i] = (try bcs.decode(types.CheckpointData, a, b[1..])).checkpoint_summary.data.sequence_number;

    const want = blk: {
        const ix = try root.Index.init(gpa, io, null);
        defer ix.deinit();
        for (blobs[0..4], seqs[0..4]) |b, s| try ix.addCheckpoint(s, b);
        ix.pruneBelow(seqs[2]);
        for (blobs[4..], seqs[4..]) |b, s| try ix.addCheckpoint(s, b);
        try std.testing.expectEqual(seqs[2], ix.indexedLo().?);
        break :blk try ix.contentHash();
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/hist", .{tmp.sub_path});
    {
        const ix = try root.Index.init(gpa, io, dir);
        defer ix.deinit();
        for (blobs[0..4], seqs[0..4]) |b, s| try ix.addCheckpoint(s, b);
        ix.pruneBelow(seqs[2]);
        for (blobs[4..], seqs[4..]) |b, s| try ix.addCheckpoint(s, b);
        try std.testing.expectEqual(want, try ix.contentHash());
    }
    {
        const ix = try root.Index.init(gpa, io, dir);
        defer ix.deinit();
        try std.testing.expectEqual(want, try ix.contentHash());
        ix.pruneBelow(seqs[4]);
        try std.testing.expectEqual(seqs[4], ix.indexedLo().?);
    }
    {
        const ix = try root.Index.init(gpa, io, dir);
        defer ix.deinit();
        try std.testing.expectEqual(seqs[4], ix.indexedLo().?);
        try std.testing.expectEqual(seqs[5], ix.indexedHi().?);
    }
}

test "a hole resets the index before the extraction (fresh key ids)" {
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const blobs = (try corpusChks(a, io, 6)) orelse return error.SkipZigTest;
    var seqs: [6]u64 = undefined;
    for (blobs, 0..) |b, i| seqs[i] = (try bcs.decode(types.CheckpointData, a, b[1..])).checkpoint_summary.data.sequence_number;
    const want = blk: {
        const ix = try root.Index.init(gpa, io, null);
        defer ix.deinit();
        for (blobs[3..], seqs[3..]) |b, s| try ix.addCheckpoint(s, b);
        break :blk try ix.contentHash();
    };
    const ix = try root.Index.init(gpa, io, null);
    defer ix.deinit();
    for (blobs[0..2], seqs[0..2]) |b, s| try ix.addCheckpoint(s, b);
    for (blobs[3..], seqs[3..]) |b, s| try ix.addCheckpoint(s, b);
    try std.testing.expectEqual(want, try ix.contentHash());
}

fn last0Of(firsts: [6]u64) u64 {
    return firsts[1] - 1;
}

// Memory per transaction over a contiguous corpus run: ZUI_HISTORY_MEMTEST=<first>-<last> runs it
// (run the test binary directly; it prints one line).
test "memory over a contiguous run" {
    const spec = std.c.getenv("ZUI_HISTORY_MEMTEST") orelse return error.SkipZigTest;
    const corpus = std.c.getenv("ZUI_CORPUS") orelse return error.SkipZigTest;
    const gpa = std.heap.c_allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const s = std.mem.span(spec);
    const dash = std.mem.indexOfScalar(u8, s, '-').?;
    const lo = try std.fmt.parseInt(u64, s[0..dash], 10);
    const hi = try std.fmt.parseInt(u64, s[dash + 1 ..], 10);
    var dir = try std.Io.Dir.cwd().openDir(io, std.mem.span(corpus), .{});
    defer dir.close(io);
    const ix = try root.Index.init(gpa, io, null);
    defer ix.deinit();
    var seq = lo;
    var buf: [64]u8 = undefined;
    var ts0: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts0);
    while (seq <= hi) : (seq += 1) {
        const p = try std.fmt.bufPrint(&buf, "chk/{d}.chk", .{seq});
        const b = try dir.readFileAlloc(io, p, gpa, .limited(1 << 30));
        defer gpa.free(b);
        try ix.addCheckpoint(seq, b);
    }
    var ts1: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts1);
    const cpu_ms = (ts1.sec - ts0.sec) * 1000 + @divTrunc(ts1.nsec - ts0.nsec, 1_000_000);
    const txs = ix.txCount();
    const bytes = ix.memoryBytes();
    std.debug.print("history memtest: {d} checkpoints, {d} txs, {d} bytes, {d} bytes/tx, {d} MB per 1M txs, {d} ms wall\n", .{ hi - lo + 1, txs, bytes, bytes / txs, bytes * 1_000_000 / txs / 1_000_000, cpu_ms });
}
