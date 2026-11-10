//! The node's data behind the admin port's db-shell routes (admin_dbshell.zig `Source`): the
//! store (checkpoints, the checkpoint digest index, transactions), the saved committees
//! (node/epochs/E.json, trust.zig) and, with `--serve`, the epoch index's start and end records.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const store = @import("store");
const serve = @import("serve");
const trust = @import("trust.zig");
const db = @import("admin_dbshell.zig");

pub const AdminStore = struct {
    st: *store.Store,
    io: Io,
    epochs_dir: Io.Dir,
    /// The node's epoch index slot (set after the admin port starts, or never).
    rpc: *const ?*serve.rpcindex.Index,

    pub fn source(s: *AdminStore) db.Source {
        return .{
            .ctx = s,
            .range = range,
            .epochOf = epochOf,
            .checkpoint = checkpoint,
            .byDigest = byDigest,
            .scan = scan,
            .transaction = transaction,
            .epochs = epochs,
            .committee = committee,
            .epochEnd = epochEnd,
            .epochStart = epochStart,
        };
    }

    fn self(ctx: *anyopaque) *AdminStore {
        return @ptrCast(@alignCast(ctx));
    }

    fn range(ctx: *anyopaque) ?db.Range {
        var snap = self(ctx).st.snapshot();
        defer snap.release();
        const hi = snap.highestCommitted() orelse return null;
        const lo = snap.lowestCheckpoint() orelse return null;
        return .{ .lo = lo, .hi = hi };
    }

    fn epochOf(ctx: *anyopaque, seq: u64) ?u64 {
        var snap = self(ctx).st.snapshot();
        defer snap.release();
        const c = snap.checkpoint(seq) orelse return null;
        return c.epoch;
    }

    fn checkpoint(ctx: *anyopaque, arena: Allocator, seq: u64) anyerror!?db.Checkpoint {
        var snap = self(ctx).st.snapshot();
        defer snap.release();
        const c = snap.checkpoint(seq) orelse return null;
        return .{ .epoch = c.epoch, .summary_cert = try arena.dupe(u8, c.summary_cert), .contents = try arena.dupe(u8, c.contents) };
    }

    fn byDigest(ctx: *anyopaque, d: *const [32]u8) ?u64 {
        var snap = self(ctx).st.snapshot();
        defer snap.release();
        return snap.checkpointByDigest(d);
    }

    /// One snapshot per 4096 checkpoints, so a long scan does not hold back the store's
    /// reclamation.
    fn scan(ctx: *anyopaque, lo: u64, hi: u64, down: bool, v: db.Visitor) anyerror!void {
        const s = self(ctx);
        if (hi < lo) return;
        var snap = s.st.snapshot();
        defer snap.release();
        var n: u64 = 0;
        var i: u64 = 0;
        const total = hi - lo + 1;
        while (i < total) : (i += 1) {
            const seq = if (down) hi - i else lo + i;
            n += 1;
            if (n % 4096 == 0) {
                snap.release();
                snap = s.st.snapshot();
            }
            const c = snap.checkpoint(seq) orelse continue;
            if (!try v.f(v.ctx, seq, c.summary_cert, c.contents)) return;
        }
    }

    fn transaction(ctx: *anyopaque, arena: Allocator, d: *const [32]u8) anyerror!?db.Tx {
        var snap = self(ctx).st.snapshot();
        defer snap.release();
        const t = snap.transaction(d) orelse return null;
        return .{ .tx = try arena.dupe(u8, t.tx), .effects = try arena.dupe(u8, t.effects), .effects_digest = t.effects_digest.* };
    }

    fn epochs(ctx: *anyopaque, arena: Allocator) anyerror![]const u64 {
        const s = self(ctx);
        var d = try s.epochs_dir.openDir(s.io, ".", .{ .iterate = true });
        defer d.close(s.io);
        var out: std.ArrayList(u64) = .empty;
        var it = d.iterate();
        while (try it.next(s.io)) |ent| {
            if (!std.mem.endsWith(u8, ent.name, ".json") or ent.name[0] == '.') continue;
            const e = std.fmt.parseInt(u64, ent.name[0 .. ent.name.len - 5], 10) catch continue;
            try out.append(arena, e);
        }
        std.mem.sort(u64, out.items, {}, std.sort.asc(u64));
        return out.items;
    }

    fn committee(ctx: *anyopaque, arena: Allocator, epoch: u64) anyerror!?db.Committee {
        const s = self(ctx);
        const info = (try trust.load(arena, s.io, s.epochs_dir, epoch)) orelse return null;
        return .{ .keys = info.keys, .stakes = info.stakes };
    }

    fn epochEnd(ctx: *anyopaque, epoch: u64) ?u64 {
        const x = self(ctx).rpc.* orelse return null;
        const t = x.enter();
        defer x.exit(t);
        const r = x.epoch(epoch) orelse return null;
        return if (r.end) |e| e.end_checkpoint else null;
    }

    fn epochStart(ctx: *anyopaque, epoch: u64) ?u64 {
        const x = self(ctx).rpc.* orelse return null;
        const t = x.enter();
        defer x.exit(t);
        const r = x.epoch(epoch) orelse return null;
        return if (r.start) |st| st.start_checkpoint else null;
    }
};
