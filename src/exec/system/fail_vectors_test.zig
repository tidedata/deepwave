//! System Move calls that fail with a VM error other than ABORTED (PARITY G9), from Mysten's
//! executor: `zui-truth-exec-system system-fail-vectors` (tools/truth/exec-system/src/settle.rs)
//! runs a RandomnessStateUpdate over a `Random` whose inner `randomness_round` is u64::MAX, so
//! `new_round == inner.randomness_round + 1` overflows (ARITHMETIC_ERROR) at protocol 141.
//! `setup_randomness_state_update` returns the execution error and the engine writes Failure
//! effects with `MovePrimitiveRuntimeError` (convert_vm_error). deepwave must produce the same
//! effects bytes.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const natives = @import("natives");
const protocol = @import("protocol");
const objects = @import("../objects.zig");
const sys = @import("root.zig");

const Allocator = std.mem.Allocator;
const testing = std.testing;
const Id = [32]u8;
const text = @embedFile("../testdata/system_fail.jsonl");

fn unhex(a: Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

const Src = struct {
    objects: std.AutoHashMapUnmanaged(Id, []const u8) = .empty,
    packages: std.AutoHashMapUnmanaged(Id, []const u8) = .empty,

    fn of(ctx: *const anyopaque) *const Src {
        return @ptrCast(@alignCast(ctx));
    }
    fn input(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        const raw = of(ctx).objects.get(id.*) orelse return null;
        const v = objects.ObjectView.parse(raw) catch return null;
        return if (v.version == version) raw else null;
    }
    fn child(ctx: *const anyopaque, _: *const Id, c: *const Id, bound: u64) error{NotAvailable}!?[]const u8 {
        const raw = of(ctx).objects.get(c.*) orelse return null;
        const v = objects.ObjectView.parse(raw) catch return error.NotAvailable;
        return if (v.version <= bound) raw else null;
    }
    fn package(ctx: *const anyopaque, id: *const Id) ?[]const u8 {
        return of(ctx).packages.get(id.*);
    }
    fn source(s: *const Src) sys.Source {
        return .{ .ctx = s, .input = input, .child = child, .package = package };
    }
};

test "system call failing with a non-abort VM error: Failure effects as Rust" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    var n: usize = 0;
    while (lines.next()) |line| {
        const v = (try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{})).object;
        const pv: u64 = @intCast(v.get("pv").?.integer);
        const cfg = try protocol.get(pv, .mainnet);
        var src: Src = .{};
        const versions = try natives.framework.load(a);
        const snap = natives.framework.snapshot(versions, pv).?;
        const genesis: Id = @splat(0);
        for (snap.packages) |*p| try src.packages.put(a, p.id, try natives.framework.packageObjectBcs(a, p, 1, &genesis));
        var ivs: std.ArrayList(sys.InputVersion) = .empty;
        for (v.get("objects").?.array.items) |h| {
            const raw = try unhex(a, h.string);
            const ov = try objects.ObjectView.parse(raw);
            try src.objects.put(a, ov.id, raw);
            try ivs.append(a, .{ .id = ov.id, .version = ov.version });
        }
        const data = try unhex(a, v.get("data").?.string);
        const td = try bcs.decode(types.TransactionData, a, data);
        var digest: Id = undefined;
        _ = try std.fmt.hexToBytes(&digest, v.get("digest").?.string);
        const env: sys.Env = .{ .cfg = cfg, .epoch = @intCast(v.get("epoch").?.integer), .epoch_start_ms = @intCast(v.get("epoch_start_ms").?.integer), .tx_digest = digest };
        const res = try sys.execute(a, &env, data, &td.V1, ivs.items, src.source());
        const out = switch (res) {
            .done => |o| o,
            .unsupported => |why| {
                std.debug.print("{s}: unsupported: {s}\n", .{ v.get("name").?.string, why });
                return error.Unsupported;
            },
        };
        const fx = (try bcs.decode(types.TransactionEffects, a, out.effects)).V2;
        try testing.expect(fx.status == .Failure);
        try testing.expect(fx.status.Failure.@"error" == .MovePrimitiveRuntimeError);
        try testing.expectEqualSlices(u8, try unhex(a, v.get("effects").?.string), out.effects);
        n += 1;
    }
    try testing.expectEqual(@as(usize, 2), n);
}
