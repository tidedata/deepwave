//! A copy-on-write view over a pre-state: objects the caller overrides ("what if this pool had
//! that balance") and the outputs of earlier steps of a chained simulation sit in a small map in
//! the request's arena; everything else reads through to the base (a zero-copy store snapshot).
//! Nothing here writes to the store.
const std = @import("std");
const rpc_exec = @import("rpc_exec");
const exec = @import("exec");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const State = rpc_exec.State;
const rpc_state = rpc_exec.state;
const ObjectView = exec.objects.ObjectView;

pub const Overlay = struct {
    base: State,
    /// id -> the newest raw object (null: deleted or wrapped by an earlier step).
    map: std.AutoHashMapUnmanaged(Id, ?Entry) = .empty,

    pub const Entry = struct { version: u64, raw: []const u8 };

    pub fn init(base: State) Overlay {
        return .{ .base = base };
    }

    /// Puts a raw BCS `Object` over the base (replacing the id's live version).
    pub fn put(o: *Overlay, arena: Allocator, raw: []const u8) !void {
        const v = try ObjectView.parse(raw);
        try o.map.put(arena, v.id, .{ .version = v.version, .raw = raw });
    }

    /// Hides `id` (a deleted or wrapped object).
    pub fn remove(o: *Overlay, arena: Allocator, id: *const Id) !void {
        try o.map.put(arena, id.*, null);
    }

    /// The overlay's own entry for `id`: null when the base answers, `.gone` when hidden.
    pub fn own(o: *const Overlay, id: *const Id) ?union(enum) { gone, obj: Entry } {
        const e = o.map.get(id.*) orelse return null;
        return if (e) |x| .{ .obj = x } else .gone;
    }

    pub fn state(o: *const Overlay) State {
        if (o.map.count() == 0) return o.base;
        return .{ .ctx = o, .vtable = vtableOf(o.base) };
    }

    fn of(ctx: *const anyopaque) *const Overlay {
        return @ptrCast(@alignCast(ctx));
    }
    fn latest(ctx: *const anyopaque, id: *const Id) ?[]const u8 {
        const o = of(ctx);
        if (o.map.get(id.*)) |e| return if (e) |x| x.raw else null;
        return o.base.latest(id);
    }
    fn at(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        const o = of(ctx);
        if (o.map.get(id.*)) |e| if (e) |x| if (x.version == version) return x.raw;
        // Older versions stay readable (an owned input at its pre-override version is still the
        // base's object; the signing checks then reject it as stale, as sui-node would).
        return o.base.at(id, version);
    }
    fn childAtMost(ctx: *const anyopaque, id: *const Id, upper: u64) ?[]const u8 {
        const o = of(ctx);
        if (o.map.get(id.*)) |e| {
            const x = e orelse return null;
            return if (x.version <= upper) x.raw else o.base.childAtMost(id, upper);
        }
        return o.base.childAtMost(id, upper);
    }
    fn ownedGasCoins(ctx: *const anyopaque, arena: Allocator, owner: *const Id, limit: usize) rpc_state.OwnedError![]const Id {
        // the base's owner index; overlaid coins are read through `latest` by gas selection
        return (try of(ctx).base.ownedGasCoins(arena, owner, limit)) orelse &.{};
    }
    fn vtableOf(base: State) *const State.VTable {
        return if (base.vtable.owned_gas_coins != null) &vtable_indexed else &vtable_plain;
    }
    const vtable_plain: State.VTable = .{ .latest = latest, .at = at, .child_at_most = childAtMost };
    const vtable_indexed: State.VTable = .{ .latest = latest, .at = at, .child_at_most = childAtMost, .owned_gas_coins = ownedGasCoins };
};

test "overlay answers its own objects first and hides removed ids" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var m: rpc_exec.state.MapState = .{};
    defer m.map.deinit(gpa);
    const x: Id = @splat(1);
    const y: Id = @splat(2);
    try m.put(gpa, x, 3, "x3");
    try m.put(gpa, y, 4, "y4");
    var o = Overlay.init(m.state());
    try std.testing.expect(o.state().ctx == m.state().ctx); // nothing over the base: no indirection
    try o.map.put(a, x, .{ .version = 9, .raw = "x9" });
    try o.remove(a, &y);
    const s = o.state();
    try std.testing.expectEqualStrings("x9", s.latest(&x).?);
    try std.testing.expectEqualStrings("x9", s.at(&x, 9).?);
    try std.testing.expectEqualStrings("x3", s.at(&x, 3).?);
    try std.testing.expect(s.childAtMost(&x, 8) != null);
    try std.testing.expect(s.latest(&y) == null);
    try std.testing.expect(s.childAtMost(&y, 100) == null);
}
