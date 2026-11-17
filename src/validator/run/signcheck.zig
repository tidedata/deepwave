//! `deepwave-validator signcheck`: the double-sign audit of a localnet run. Read-only: it never opens a
//! store for writing, never truncates a torn tail and never takes the signer lock.
//!
//! What it checks, over every validator database given (`--db DIR`, optionally `DIR:INDEX` with
//! the validator's consensus authority index):
//!
//!   1. Block equivocation: every checksum-valid block record of every consensus log
//!      (`<db>/consensus/<epoch>/consensus.log`) is indexed by (epoch, author, round). Two
//!      different block digests for one slot, in any two stores (a node stores its own blocks and
//!      every peer block it accepted), are evidence that `author` signed twice for that round.
//!   2. Checkpoint double signing: every CheckpointSignature / CheckpointSignatureV2 consensus
//!      transaction carried by those blocks names (authority, epoch, sequence) and a summary. Two
//!      different summary digests for one (authority, epoch, sequence) are a double signature.
//!   3. Watermarks: for a database with a known authority index, the signer's persisted watermark
//!      (`<db>/validator/signer/watermarks`, the higher valid slot) must be at or above the highest
//!      own block found anywhere; a block above it means a signature left the signer before its
//!      watermark was durable.
//!
//! Exit 0 when nothing is found, 1 with findings (each printed), 2 on bad arguments or I/O.
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const consensus = @import("consensus");
const messages = @import("../messages.zig");
const signer = @import("../signer.zig");
const signer_impl = @import("../keys/signer_impl.zig");

const Allocator = std.mem.Allocator;
const ctypes = consensus.types;
const digest_mod = consensus.digest;

pub const usage =
    \\deepwave-validator signcheck --db DIR[:INDEX] [--db DIR[:INDEX]...]
    \\  --db DIR[:INDEX]   a validator database (the one holding consensus/ and validator/signer/);
    \\                     INDEX = its consensus authority index, enables the watermark check
    \\  exit 0: no double signing found; 1: findings (listed); 2: bad arguments or I/O
    \\
;

pub const Db = struct { path: []const u8, own: ?u32 = null };

const Slot = struct { epoch: u64, author: u32, round: u32 };
const SlotSeen = struct { digest: [32]u8, src: u16 };

const CommitKey = struct { epoch: u64, index: u32 };
const CommitSeen = struct { digest: [32]u8, src: u16 };

/// Commits of one database in one epoch (the localnet verdict's commit rate).
pub const EpochStat = struct { db: u16, epoch: u64, commits: u64 = 0, last_index: u32 = 0, first_ts_ms: u64 = 0, last_ts_ms: u64 = 0 };

const CkptKey = struct { authority: [96]u8, epoch: u64, seq: u64 };
const CkptSeen = struct { digest: [32]u8, src: u16 };

pub const Finding = union(enum) {
    equivocation: struct { epoch: u64, author: u32, round: u32, a: [32]u8, b: [32]u8, src_a: u16, src_b: u16 },
    commit_fork: struct { epoch: u64, index: u32, a: [32]u8, b: [32]u8, src_a: u16, src_b: u16 },
    checkpoint_double: struct { authority: [96]u8, epoch: u64, seq: u64, a: [32]u8, b: [32]u8, src_a: u16, src_b: u16 },
    beyond_watermark: struct { db: u16, epoch: u64, round: u32, wm_epoch: ?u64, wm_round: ?u32 },
    unreadable: struct { db: u16, what: []const u8 },
};

/// (epoch, round) of a block.
pub const Mark = struct { epoch: u64, round: u32 };

pub const Report = struct {
    files: u32 = 0,
    blocks: u64 = 0,
    distinct_slots: u64 = 0,
    checkpoint_sigs: u64 = 0,
    commits: u64 = 0,
    epochs: std.ArrayList(EpochStat) = .empty,
    torn_tails: u32 = 0,
    findings: std.ArrayList(Finding) = .empty,
    /// Per database: highest own block (epoch, round) found in any store, and its watermark.
    own_high: []?Mark = &.{},
    watermarks: []?signer.Watermarks = &.{},
};

pub const Checker = struct {
    gpa: Allocator,
    io: Io,
    arena: std.heap.ArenaAllocator,
    dbs: []const Db,
    slots: std.AutoHashMapUnmanaged(Slot, SlotSeen) = .empty,
    ckpts: std.AutoHashMapUnmanaged(CkptKey, CkptSeen) = .empty,
    commits: std.AutoHashMapUnmanaged(CommitKey, CommitSeen) = .empty,
    report: Report = .{},

    pub fn init(gpa: Allocator, io: Io, dbs: []const Db) !Checker {
        var c: Checker = .{ .gpa = gpa, .io = io, .arena = .init(gpa), .dbs = dbs };
        const a = c.arena.allocator();
        c.report.own_high = try a.alloc(?Mark, dbs.len);
        @memset(c.report.own_high, null);
        c.report.watermarks = try a.alloc(?signer.Watermarks, dbs.len);
        @memset(c.report.watermarks, null);
        return c;
    }

    pub fn deinit(c: *Checker) void {
        c.slots.deinit(c.gpa);
        c.ckpts.deinit(c.gpa);
        c.commits.deinit(c.gpa);
        c.report.epochs.deinit(c.gpa);
        c.report.findings.deinit(c.gpa);
        c.arena.deinit();
    }

    fn finding(c: *Checker, f: Finding) !void {
        try c.report.findings.append(c.gpa, f);
    }

    /// Scans every database, then the watermarks.
    pub fn run(c: *Checker) !void {
        for (c.dbs, 0..) |db, i| try c.scanDb(@intCast(i), db.path);
        for (c.dbs, 0..) |db, i| try c.checkWatermark(@intCast(i), db);
    }

    fn scanDb(c: *Checker, src: u16, path: []const u8) !void {
        const a = c.arena.allocator();
        // <db>/consensus/<epoch>/consensus.log; a path that already is the consensus dir works too
        const roots = [_][]const u8{ try std.fmt.allocPrint(a, "{s}/consensus", .{path}), path };
        var found = false;
        for (roots) |root| {
            var dir = Io.Dir.cwd().openDir(c.io, root, .{ .iterate = true }) catch continue;
            defer dir.close(c.io);
            var names: std.ArrayList([]const u8) = .empty;
            var it = dir.iterate();
            while (it.next(c.io) catch null) |e| {
                if (e.kind != .directory) continue;
                _ = std.fmt.parseInt(u64, e.name, 10) catch continue;
                try names.append(a, try a.dupe(u8, e.name));
            }
            for (names.items) |n| {
                const file = try std.fmt.allocPrint(a, "{s}/{s}/consensus.log", .{ root, n });
                if (try c.scanLog(src, file)) found = true;
            }
            if (found) break;
        }
        if (!found) try c.finding(.{ .unreadable = .{ .db = src, .what = "no consensus/<epoch>/consensus.log" } });
    }

    const magic = "ZUICONS1";
    const header_len = 16;
    const rec_header = 12;
    const max_record_len = 128 << 20;
    const kind_block: u8 = 1;
    const kind_commit: u8 = 2;

    /// One consensus.log, record by record (same framing as consensus.store.LogStore). Stops at the
    /// first record that fails its checksum (a torn tail); never writes.
    pub fn scanLog(c: *Checker, src: u16, path: []const u8) !bool {
        const f = Io.Dir.cwd().openFile(c.io, path, .{}) catch return false;
        defer f.close(c.io);
        const len = f.length(c.io) catch return false;
        if (len < header_len) return false;
        var h: [header_len]u8 = undefined;
        if ((f.readPositionalAll(c.io, &h, 0) catch return false) != header_len) return false;
        if (!std.mem.eql(u8, h[0..8], magic)) return false;
        const file_epoch = std.mem.readInt(u64, h[8..16], .little);
        c.report.files += 1;
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(c.gpa);
        var block_arena = std.heap.ArenaAllocator.init(c.gpa);
        defer block_arena.deinit();
        try c.report.epochs.append(c.gpa, .{ .db = src, .epoch = file_epoch });
        const es = &c.report.epochs.items[c.report.epochs.items.len - 1];
        var pos: u64 = header_len;
        while (pos + rec_header + 1 <= len) {
            var hdr: [rec_header]u8 = undefined;
            if ((f.readPositionalAll(c.io, &hdr, pos) catch break) != rec_header) break;
            const rl = std.mem.readInt(u32, hdr[0..4], .little);
            const sum = std.mem.readInt(u64, hdr[4..12], .little);
            if (rl < 1 or rl > max_record_len or pos + rec_header + rl > len) break;
            try body.resize(c.gpa, rl);
            if ((f.readPositionalAll(c.io, body.items, pos + rec_header) catch break) != rl) break;
            if (std.hash.Wyhash.hash(pos, body.items) != sum) break;
            if (body.items[0] == kind_block) {
                _ = block_arena.reset(.retain_capacity);
                if (digest_mod.decodeVerifiedUnchecked(block_arena.allocator(), body.items[1..])) |vb| {
                    try c.addBlock(src, file_epoch, &vb);
                } else |_| try c.finding(.{ .unreadable = .{ .db = src, .what = "a checksum-valid block record does not decode" } });
            } else if (body.items[0] == kind_commit) {
                try c.addCommit(src, file_epoch, body.items[1..], es);
            }
            pos += rec_header + rl;
        }
        if (pos < len) c.report.torn_tails += 1;
        return true;
    }

    /// Commit V1 BCS: variant 0, index u32, previous digest 32, timestamp u64, ... Two different
    /// commits at one (epoch, index) in two stores is a fork of the committed sequence.
    pub fn addCommit(c: *Checker, src: u16, epoch: u64, payload: []const u8, es: *EpochStat) !void {
        if (payload.len < 45 or payload[0] != 0) return;
        const index = std.mem.readInt(u32, payload[1..5], .little);
        const ts = std.mem.readInt(u64, payload[37..45], .little);
        c.report.commits += 1;
        es.commits += 1;
        if (index >= es.last_index) {
            es.last_index = index;
            es.last_ts_ms = ts;
        }
        if (es.first_ts_ms == 0 or ts < es.first_ts_ms) es.first_ts_ms = ts;
        const d = digest_mod.commitDigest(payload);
        const gop = try c.commits.getOrPut(c.gpa, .{ .epoch = epoch, .index = index });
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .digest = d, .src = src };
        } else if (!std.mem.eql(u8, &gop.value_ptr.digest, &d)) {
            try c.finding(.{ .commit_fork = .{ .epoch = epoch, .index = index, .a = gop.value_ptr.digest, .b = d, .src_a = gop.value_ptr.src, .src_b = src } });
        }
    }

    pub fn addBlock(c: *Checker, src: u16, file_epoch: u64, vb: *const ctypes.VerifiedBlock) !void {
        c.report.blocks += 1;
        const inner = &vb.block.inner;
        const ep = inner.epoch();
        _ = file_epoch;
        const slot: Slot = .{ .epoch = ep, .author = inner.author(), .round = inner.round() };
        const gop = try c.slots.getOrPut(c.gpa, slot);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .digest = vb.digest, .src = src };
            c.report.distinct_slots += 1;
        } else if (!std.mem.eql(u8, &gop.value_ptr.digest, &vb.digest)) {
            // genesis blocks (round 0) have no signature: identical by construction, never differ
            try c.finding(.{ .equivocation = .{ .epoch = ep, .author = slot.author, .round = slot.round, .a = gop.value_ptr.digest, .b = vb.digest, .src_a = gop.value_ptr.src, .src_b = src } });
        }
        // own block high-water mark per database with a known index
        for (c.dbs, 0..) |db, i| {
            const own = db.own orelse continue;
            if (own != slot.author or slot.round == 0) continue;
            const cur = &c.report.own_high[i];
            if (cur.* == null or ep > cur.*.?.epoch or (ep == cur.*.?.epoch and slot.round > cur.*.?.round)) cur.* = .{ .epoch = ep, .round = slot.round };
        }
        for (inner.transactions()) |t| try c.addConsensusTx(src, t.data);
    }

    const KindTag = std.meta.Tag(messages.ConsensusTransactionKind);
    const tag_ck1: u8 = @intFromEnum(KindTag.CheckpointSignature);
    const tag_ck2: u8 = @intFromEnum(KindTag.CheckpointSignatureV2);

    /// ConsensusTransaction BCS: tracking_id [8]u8, then the kind's ULEB tag (one byte: fewer
    /// than 128 kinds). Only the two checkpoint signature kinds are decoded.
    fn addConsensusTx(c: *Checker, src: u16, data: []const u8) !void {
        if (data.len < 10) return;
        const tag = data[8];
        if (tag != tag_ck1 and tag != tag_ck2) return;
        var ar = std.heap.ArenaAllocator.init(c.gpa);
        defer ar.deinit();
        const ct = bcs.decode(messages.ConsensusTransaction, ar.allocator(), data) catch return;
        const msg = switch (ct.kind) {
            .CheckpointSignature => |m| m,
            .CheckpointSignatureV2 => |m| m,
            else => return,
        };
        c.report.checkpoint_sigs += 1;
        const summary_bcs = bcs.encodeAlloc(types.CheckpointSummary, ar.allocator(), &msg.summary.data) catch return;
        const d = types.digest.checkpointSummaryDigest(summary_bcs);
        const key: CkptKey = .{ .authority = msg.summary.auth_signature.authority.@"0", .epoch = msg.summary.data.epoch, .seq = msg.summary.data.sequence_number };
        const gop = try c.ckpts.getOrPut(c.gpa, key);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .digest = d, .src = src };
        } else if (!std.mem.eql(u8, &gop.value_ptr.digest, &d)) {
            try c.finding(.{ .checkpoint_double = .{ .authority = key.authority, .epoch = key.epoch, .seq = key.seq, .a = gop.value_ptr.digest, .b = d, .src_a = gop.value_ptr.src, .src_b = src } });
        }
    }

    fn checkWatermark(c: *Checker, i: u16, db: Db) !void {
        const a = c.arena.allocator();
        const path = try std.fmt.allocPrint(a, "{s}/validator/signer/watermarks", .{db.path});
        const wm = readWatermarks(c.io, path);
        c.report.watermarks[i] = wm;
        const own = db.own orelse return;
        _ = own;
        const high = c.report.own_high[i] orelse return;
        const w = wm orelse {
            try c.finding(.{ .beyond_watermark = .{ .db = i, .epoch = high.epoch, .round = high.round, .wm_epoch = null, .wm_round = null } });
            return;
        };
        const b = w.block orelse {
            try c.finding(.{ .beyond_watermark = .{ .db = i, .epoch = high.epoch, .round = high.round, .wm_epoch = null, .wm_round = null } });
            return;
        };
        const beyond = high.epoch > b.epoch or (high.epoch == b.epoch and high.round > b.round);
        if (beyond) try c.finding(.{ .beyond_watermark = .{ .db = i, .epoch = high.epoch, .round = high.round, .wm_epoch = b.epoch, .wm_round = b.round } });
    }

    pub fn print(c: *const Checker, w: *std.Io.Writer) !void {
        const r = &c.report;
        try w.print("signcheck: {d} logs, {d} block records, {d} distinct slots, {d} commit records, {d} checkpoint signatures, {d} torn tails\n", .{ r.files, r.blocks, r.distinct_slots, r.commits, r.checkpoint_sigs, r.torn_tails });
        for (r.epochs.items) |e| try w.print("  commits db={d} epoch={d} commits={d} last_index={d} first_ts_ms={d} last_ts_ms={d}\n", .{ e.db, e.epoch, e.commits, e.last_index, e.first_ts_ms, e.last_ts_ms });
        for (c.dbs, 0..) |db, i| {
            try w.print("  db {d} {s}", .{ i, db.path });
            if (db.own) |o| try w.print(" own={d}", .{o});
            if (r.own_high[i]) |hh| try w.print(" own_high=e{d}/r{d}", .{ hh.epoch, hh.round });
            if (r.watermarks[i]) |wm| {
                if (wm.block) |b| try w.print(" wm_block=e{d}/r{d}", .{ b.epoch, b.round });
                if (wm.checkpoint) |ck| try w.print(" wm_ckpt=e{d}/s{d}", .{ ck.epoch, ck.seq });
            } else try w.print(" wm=none", .{});
            try w.print("\n", .{});
        }
        for (r.findings.items) |f| switch (f) {
            .equivocation => |e| try w.print("FINDING equivocation epoch={d} author={d} round={d} {x} (db {d}) vs {x} (db {d})\n", .{ e.epoch, e.author, e.round, e.a[0..8], e.src_a, e.b[0..8], e.src_b }),
            .commit_fork => |e| try w.print("FINDING commit fork epoch={d} index={d} {x} (db {d}) vs {x} (db {d})\n", .{ e.epoch, e.index, e.a[0..8], e.src_a, e.b[0..8], e.src_b }),
            .checkpoint_double => |e| try w.print("FINDING checkpoint double signature authority={x} epoch={d} seq={d} {x} (db {d}) vs {x} (db {d})\n", .{ e.authority[0..8], e.epoch, e.seq, e.a[0..8], e.src_a, e.b[0..8], e.src_b }),
            .beyond_watermark => |e| {
                try w.print("FINDING own block e{d}/r{d} in db {d} is above the signer watermark ", .{ e.epoch, e.round, e.db });
                if (e.wm_epoch) |we| try w.print("e{d}/r{d}\n", .{ we, e.wm_round.? }) else try w.print("(none persisted)\n", .{});
            },
            .unreadable => |e| try w.print("FINDING db {d}: {s}\n", .{ e.db, e.what }),
        };
        try w.print("RESULT {s}\n", .{if (r.findings.items.len == 0) "CLEAN" else "DOUBLE-SIGN FINDINGS"});
    }
};

/// The persisted watermark (the higher valid slot), or null when absent or unreadable.
pub fn readWatermarks(io: Io, path: []const u8) ?signer.Watermarks {
    const f = Io.Dir.cwd().openFile(io, path, .{}) catch return null;
    defer f.close(io);
    var raw: [2 * signer_impl.slot_len]u8 = @splat(0);
    _ = f.readPositionalAll(io, &raw, 0) catch return null;
    var best: ?struct { seq: u64, w: signer.Watermarks } = null;
    for (0..2) |i| {
        if (signer_impl.decodeSlot(raw[i * signer_impl.slot_len ..][0..signer_impl.slot_len])) |d| {
            if (best == null or d.seq > best.?.seq) best = .{ .seq = d.seq, .w = d.w };
        }
    }
    return if (best) |b| b.w else null;
}

pub fn parseDb(arg: []const u8) ?Db {
    if (std.mem.lastIndexOfScalar(u8, arg, ':')) |i| {
        const idx = std.fmt.parseInt(u32, arg[i + 1 ..], 10) catch return .{ .path = arg };
        return .{ .path = arg[0..i], .own = idx };
    }
    return .{ .path = arg };
}

pub fn main(gpa: Allocator, io: Io, args: []const []const u8) u8 {
    var dbs: std.ArrayList(Db) = .empty;
    defer dbs.deinit(gpa);
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--db") and i + 1 < args.len) {
            i += 1;
            dbs.append(gpa, parseDb(args[i]) orelse return bad()) catch return 2;
        } else return bad();
    }
    if (dbs.items.len == 0) return bad();
    var c = Checker.init(gpa, io, dbs.items) catch return 2;
    defer c.deinit();
    c.run() catch |e| {
        std.debug.print("deepwave-validator signcheck: {s}\n", .{@errorName(e)});
        return 2;
    };
    var buf: [1 << 16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    c.print(&w) catch {};
    std.debug.print("{s}", .{w.buffered()});
    return if (c.report.findings.items.len == 0) 0 else 1;
}

fn bad() u8 {
    std.debug.print("{s}", .{usage});
    return 2;
}

// ------------------------------------------------------------------ tests

fn testBlock(a: Allocator, author: u32, round: u32, ts: u64, txs: []const ctypes.Transaction) !ctypes.VerifiedBlock {
    const blk: ctypes.Block = .{ .V2 = .{
        .epoch = 0,
        .round = round,
        .author = author,
        .timestamp_ms = ts,
        .ancestors = &.{},
        .transactions = txs,
        .transaction_votes = &.{},
        .commit_votes = &.{},
        .misbehavior_reports = &.{},
    } };
    return digest_mod.verifiedForTest(a, blk);
}

fn writeStore(io: Io, dir: []const u8, blocks: []const ctypes.VerifiedBlock) !void {
    const ls = try consensus.store.LogStore.open(std.testing.allocator, io, .{ .dir_path = dir, .epoch = 0 });
    defer ls.close();
    try ls.store().write(&.{ .blocks = blocks });
}

fn tmpPath(tmp: *std.testing.TmpDir, buf: []u8) ![]const u8 {
    return buf[0..try tmp.dir.realPath(std.testing.io, buf)];
}

test "signcheck: clean stores, then an equivocating author across two stores" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmpPath(&tmp, &pb);
    var ar = std.heap.ArenaAllocator.init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    const b1 = try testBlock(a, 1, 5, 100, &.{});
    const b2 = try testBlock(a, 2, 5, 100, &.{});
    const b1_other = try testBlock(a, 1, 5, 101, &.{}); // same slot, different content
    const db0 = try std.fmt.allocPrint(a, "{s}/db0", .{root});
    const db1 = try std.fmt.allocPrint(a, "{s}/db1", .{root});
    try writeStore(io, try std.fmt.allocPrint(a, "{s}/consensus/0", .{db0}), &.{ b1, b2 });
    try writeStore(io, try std.fmt.allocPrint(a, "{s}/consensus/0", .{db1}), &.{ b1, b2 });
    {
        const dbs = [_]Db{ .{ .path = db0 }, .{ .path = db1 } };
        var c = try Checker.init(gpa, io, &dbs);
        defer c.deinit();
        try c.run();
        try std.testing.expectEqual(@as(usize, 0), c.report.findings.items.len);
        try std.testing.expectEqual(@as(u64, 4), c.report.blocks);
        try std.testing.expectEqual(@as(u64, 2), c.report.distinct_slots);
    }
    const db2 = try std.fmt.allocPrint(a, "{s}/db2", .{root});
    try writeStore(io, try std.fmt.allocPrint(a, "{s}/consensus/0", .{db2}), &.{b1_other});
    {
        const dbs = [_]Db{ .{ .path = db0 }, .{ .path = db1 }, .{ .path = db2 } };
        var c = try Checker.init(gpa, io, &dbs);
        defer c.deinit();
        try c.run();
        try std.testing.expectEqual(@as(usize, 1), c.report.findings.items.len);
        const f = c.report.findings.items[0].equivocation;
        try std.testing.expectEqual(@as(u32, 1), f.author);
        try std.testing.expectEqual(@as(u32, 5), f.round);
        try std.testing.expectEqual(@as(u16, 2), f.src_b);
    }
}

test "signcheck: own block above the persisted watermark is a finding, below is clean" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmpPath(&tmp, &pb);
    var ar = std.heap.ArenaAllocator.init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    const db = try std.fmt.allocPrint(a, "{s}/db", .{root});
    try writeStore(io, try std.fmt.allocPrint(a, "{s}/consensus/0", .{db}), &.{ try testBlock(a, 3, 7, 1, &.{}), try testBlock(a, 3, 9, 2, &.{}) });
    const sdir = try std.fmt.allocPrint(a, "{s}/validator/signer", .{db});
    try Io.Dir.cwd().createDirPath(io, sdir);
    const wpath = try std.fmt.allocPrint(a, "{s}/watermarks", .{sdir});
    var w: signer.Watermarks = .{};
    w.recordBlock(0, 8);
    var slot: [signer_impl.slot_len]u8 = undefined;
    signer_impl.encodeSlot(&slot, 1, &w);
    {
        const f = try Io.Dir.cwd().createFile(io, wpath, .{});
        defer f.close(io);
        try f.writePositionalAll(io, &slot, signer_impl.slot_len); // slot of seq 1
    }
    const dbs = [_]Db{.{ .path = db, .own = 3 }};
    {
        var c = try Checker.init(gpa, io, &dbs);
        defer c.deinit();
        try c.run();
        try std.testing.expectEqual(@as(usize, 1), c.report.findings.items.len);
        try std.testing.expectEqual(@as(u32, 9), c.report.findings.items[0].beyond_watermark.round);
    }
    w.recordBlock(0, 9);
    signer_impl.encodeSlot(&slot, 2, &w);
    {
        const f = try Io.Dir.cwd().openFile(io, wpath, .{ .mode = .read_write });
        defer f.close(io);
        try f.writePositionalAll(io, &slot, 0); // slot of seq 2
    }
    {
        var c = try Checker.init(gpa, io, &dbs);
        defer c.deinit();
        try c.run();
        try std.testing.expectEqual(@as(usize, 0), c.report.findings.items.len);
    }
}

test "signcheck: two checkpoint signatures for one sequence with different summaries" {
    const gpa = std.testing.allocator;
    var ar = std.heap.ArenaAllocator.init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    const dbs = [_]Db{.{ .path = "/nonexistent" }};
    var c = try Checker.init(gpa, std.testing.io, &dbs);
    defer c.deinit();
    var summary: types.CheckpointSummary = std.mem.zeroes(types.CheckpointSummary);
    summary.epoch = 2;
    summary.sequence_number = 40;
    const name: messages.AuthorityName = .{ .@"0" = @splat(7) };
    const mk = struct {
        fn f(al: Allocator, s: types.CheckpointSummary, n: messages.AuthorityName) ![]const u8 {
            const ct: messages.ConsensusTransaction = .{ .tracking_id = @splat(1), .kind = .{ .CheckpointSignatureV2 = .{ .summary = .{ .data = s, .auth_signature = .{ .epoch = s.epoch, .authority = n, .signature = @splat(0) } } } } };
            return bcs.encodeAlloc(messages.ConsensusTransaction, al, &ct);
        }
    }.f;
    const t1 = try mk(a, summary, name);
    try c.addConsensusTx(0, t1);
    try c.addConsensusTx(1, t1); // the same signature seen in another store: fine
    try std.testing.expectEqual(@as(usize, 0), c.report.findings.items.len);
    summary.timestamp_ms = 99;
    try c.addConsensusTx(1, try mk(a, summary, name));
    try std.testing.expectEqual(@as(usize, 1), c.report.findings.items.len);
    try std.testing.expectEqual(@as(u64, 40), c.report.findings.items[0].checkpoint_double.seq);
}

test "signcheck: two different commits at one index are a fork; the same commit twice is not" {
    const gpa = std.testing.allocator;
    const dbs = [_]Db{ .{ .path = "/nonexistent" }, .{ .path = "/nonexistent2" } };
    var c = try Checker.init(gpa, std.testing.io, &dbs);
    defer c.deinit();
    var es: EpochStat = .{ .db = 0, .epoch = 1 };
    var p: [45]u8 = @splat(0);
    std.mem.writeInt(u32, p[1..5], 12, .little);
    std.mem.writeInt(u64, p[37..45], 1000, .little);
    try c.addCommit(0, 1, &p, &es);
    try c.addCommit(1, 1, &p, &es);
    try std.testing.expectEqual(@as(usize, 0), c.report.findings.items.len);
    try std.testing.expectEqual(@as(u32, 12), es.last_index);
    p[10] = 1; // other previous digest
    try c.addCommit(1, 1, &p, &es);
    try std.testing.expectEqual(@as(usize, 1), c.report.findings.items.len);
    try std.testing.expectEqual(@as(u32, 12), c.report.findings.items[0].commit_fork.index);
}
