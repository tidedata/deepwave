//! Package objects for replay (CONTRACTS 4.1 `packages/` part).
//!
//! - Non-system packages are immutable per id: `packages/<id hex>.obj` holds the raw BCS
//!   `Object` (fetched by `tools/truth/exec packages` from Mysten's archive gRPC and checked
//!   against the reported digest).
//! - System packages (0x1, 0x2, 0x3, 0xb, 0xdee9 and the other framework ids) change in place at
//!   epoch changes. The corpus holds every epoch's last checkpoint, whose end-of-epoch
//!   transaction writes the upgraded system packages, and checkpoint 0 (genesis), which writes
//!   the first ones. The package a transaction of epoch E loads is the newest such write from a
//!   checkpoint of an epoch below E (or genesis).
const std = @import("std");
const types = @import("types");
const harness = @import("harness");
const objects = @import("objects.zig");

const Allocator = std.mem.Allocator;

/// sui-types `SYSTEM_PACKAGE_ADDRESSES`.
pub fn isSystemPackage(id: *const [32]u8) bool {
    for (id[0..30]) |b| if (b != 0) return false;
    const tail = std.mem.readInt(u16, id[30..32], .big);
    return switch (tail) {
        0x1, 0x2, 0x3, 0xb, 0xdee9 => true,
        else => false,
    };
}

pub const SystemWrite = struct { epoch: u64, raw: []const u8 };

pub const Store = struct {
    /// id -> object bytes (non-system).
    user: std.AutoHashMapUnmanaged([32]u8, []const u8) = .empty,
    /// id -> writes in ascending epoch of the writing checkpoint (genesis has epoch 0 and is
    /// visible from epoch 0; an end-of-epoch write in epoch e is visible from e + 1).
    system: std.AutoHashMapUnmanaged([32]u8, std.ArrayList(SystemWrite)) = .empty,
    loaded: bool = false,
    /// Behind the in-memory maps: a live source (a node store snapshot, a remote node) asked for
    /// any package the maps do not hold. Must be safe to call from several threads; the bytes it
    /// returns must stay valid as long as the Store (packages are immutable per id, system
    /// packages per epoch). Requested by the node lane (CONTRACTS 6.7) and rpc-exec's simulate.
    lookup: ?Lookup = null,

    pub const Lookup = struct {
        ctx: *const anyopaque,
        get: *const fn (ctx: *const anyopaque, id: *const [32]u8, epoch: u64) ?[]const u8,
    };

    /// The package object a transaction of `epoch` loads for `id`, or null if neither the
    /// corpus nor the lookup holds it.
    pub fn get(s: *const Store, id: *const [32]u8, epoch: u64) ?[]const u8 {
        if (isSystemPackage(id)) {
            if (s.system.get(id.*)) |list| {
                var best: ?[]const u8 = null;
                for (list.items) |w| if (w.epoch <= epoch) {
                    best = w.raw;
                };
                if (best) |b| return b;
            }
        } else if (s.user.get(id.*)) |raw| return raw;
        const l = s.lookup orelse return null;
        return l.get(l.ctx, id, epoch);
    }
};

/// Load `packages/*.obj` and the system package writes of checkpoint 0 and every epoch's last
/// checkpoint (`epochs`: `last` per epoch; a missing blob is skipped).
pub fn load(ctx: *harness.Ctx, arena: Allocator, epoch_last: []const ?u64) !Store {
    var s: Store = .{};
    var dir = ctx.corpus.openDir(ctx.io, "packages", .{ .iterate = true }) catch return s;
    defer dir.close(ctx.io);
    var it = dir.iterate();
    while (try it.next(ctx.io)) |e| {
        if (!std.mem.endsWith(u8, e.name, ".obj") or e.name.len != 64 + 4) continue;
        var id: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&id, e.name[0..64]) catch continue;
        const raw = try dir.readFileAlloc(ctx.io, e.name, arena, .limited(1 << 28));
        try s.user.put(arena, id, raw);
    }
    try addSystemWrites(ctx, arena, &s, 0, 0);
    for (epoch_last, 0..) |last, e| if (last) |seq| {
        try addSystemWrites(ctx, arena, &s, seq, e + 1);
    };
    s.loaded = true;
    return s;
}

fn addSystemWrites(ctx: *harness.Ctx, arena: Allocator, s: *Store, seq: u64, visible_from: u64) !void {
    const path = try std.fmt.allocPrint(arena, "chk/{d}.chk", .{seq});
    const blob = ctx.corpus.readFileAlloc(ctx.io, path, arena, .limited(1 << 30)) catch return;
    var idx = try types.CheckpointIndex.init(std.heap.page_allocator);
    defer idx.deinit(std.heap.page_allocator);
    try types.indexCheckpointData(blob, &idx);
    for (0..idx.tx_count) |i| {
        const tx = idx.txAt(i);
        for (idx.objs[tx.out_first..][0..tx.out_count]) |r| {
            const raw = r.slice(blob);
            const v = objects.ObjectView.parse(raw) catch continue;
            if (!v.is_package or !isSystemPackage(&v.id)) continue;
            const gop = try s.system.getOrPut(arena, v.id);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(arena, .{ .epoch = visible_from, .raw = raw });
        }
    }
}

test "system package ids" {
    var id: [32]u8 = @splat(0);
    id[31] = 2;
    try std.testing.expect(isSystemPackage(&id));
    id[30] = 0xde;
    id[31] = 0xe9;
    try std.testing.expect(isSystemPackage(&id));
    id[31] = 0xe8;
    try std.testing.expect(!isSystemPackage(&id));
}
