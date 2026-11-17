//! Accumulator settlement vectors (testdata/settle_vectors.jsonl) from Mysten's own code:
//! `zui-truth-exec-system settle-vectors` (tools/truth/exec-system/src/settle.rs) builds the
//! settlement transactions of synthetic root effects with sui-core's
//! `MockCheckpointBuilder::get_settlement_txns` (AccumulatorSettlementTxBuilder::new + build_tx)
//! and the barrier with `get_barrier_tx`, and runs them through Mysten's executor at protocol 141.
//! The cases mix authenticated event streams (`EventDigest`: several streams, several events per
//! stream and transaction, MMR extension over existing heads, more updates than
//! max_updates_per_settlement_txn) with `Integer` balances; `integer-tuple` records Rust's panic.
//!
//! deepwave must rebuild every settlement and barrier byte for byte (data and digest) with
//! `ckpt_env.buildSettlementsOf` / `barrierTx`, and exec.system must produce the same effects.
//! Protocol 142 (1.84, e83d6906) must give the same bytes: sui-core accumulators/mod.rs,
//! sui-adapter accumulator_settlement.rs, sui-types build_event_merkle_root and fastcrypto
//! merkle.rs (da61cd46 vs 0a263279) are identical between the trees and the 142 config changes
//! none of their inputs, so each case also runs at 142 against the 141 vector.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const exec = @import("exec");
const natives = @import("natives");
const protocol = @import("protocol");
const ckpt_env = @import("ckpt_env.zig");

const Allocator = std.mem.Allocator;
const testing = std.testing;
const Id = [32]u8;
const text = @embedFile("testdata/settle_vectors.jsonl");

fn unhex(a: Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn unhex32(s: []const u8) !Id {
    var out: Id = undefined;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

/// The store a settlement runs over: objects by id (one version each) and the framework.
const Src = struct {
    objects: std.AutoHashMapUnmanaged(Id, []const u8) = .empty,
    packages: std.AutoHashMapUnmanaged(Id, []const u8) = .empty,

    fn put(s: *Src, a: Allocator, raw: []const u8) !void {
        const v = try exec.objects.ObjectView.parse(raw);
        try s.objects.put(a, v.id, raw);
    }
    fn of(ctx: *const anyopaque) *const Src {
        return @ptrCast(@alignCast(ctx));
    }
    fn input(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        const raw = of(ctx).objects.get(id.*) orelse return null;
        const v = exec.objects.ObjectView.parse(raw) catch return null;
        return if (v.version == version) raw else null;
    }
    fn child(ctx: *const anyopaque, _: *const Id, c: *const Id, bound: u64) error{NotAvailable}!?[]const u8 {
        const raw = of(ctx).objects.get(c.*) orelse return null;
        const v = exec.objects.ObjectView.parse(raw) catch return error.NotAvailable;
        return if (v.version <= bound) raw else null;
    }
    fn package(ctx: *const anyopaque, id: *const Id) ?[]const u8 {
        return of(ctx).packages.get(id.*);
    }
    fn source(s: *const Src) exec.system.Source {
        return .{ .ctx = s, .input = input, .child = child, .package = package };
    }
};

fn frameworkPackages(a: Allocator, pv: u64, into: *Src) !void {
    const versions = try natives.framework.load(a);
    const snap = natives.framework.snapshot(versions, pv) orelse return error.NoFramework;
    const genesis: Id = @splat(0);
    for (snap.packages) |*p| try into.packages.put(a, p.id, try natives.framework.packageObjectBcs(a, p, 1, &genesis));
}

const Run = struct { effects: []const u8, written: []const exec.system.Written };

fn execute(a: Allocator, cfg: *const protocol.ProtocolConfig, epoch: u64, src: *const Src, t: *const ckpt_env.BuiltTx, root_version: u64) !Run {
    const env: exec.system.Env = .{ .cfg = cfg, .epoch = epoch, .tx_digest = t.digest };
    const iv = [_]exec.system.InputVersion{.{ .id = ckpt_env.accRootId(), .version = root_version }};
    const res = try exec.system.execute(a, &env, t.data, &t.td, &iv, src.source());
    return switch (res) {
        .done => |o| .{ .effects = o.effects, .written = o.written },
        .unsupported => |why| {
            std.debug.print("settlement unsupported: {s}\n", .{why});
            return error.Unsupported;
        },
    };
}

fn expectTx(a: Allocator, want: std.json.Value, got: *const ckpt_env.BuiltTx) !void {
    try testing.expectEqualSlices(u8, try unhex(a, want.object.get("data").?.string), got.data);
    try testing.expectEqualSlices(u8, &try unhex32(want.object.get("digest").?.string), &got.digest);
}

test "settlement vectors: Rust's AccumulatorSettlementTxBuilder, barrier and executed effects" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    var n_cases: usize = 0;
    var n_events: usize = 0;
    while (lines.next()) |line| for ([_]?u64{ null, 142 }) |pv_override| {
        const v = (try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{})).object;
        const name = v.get("name").?.string;
        const pv: u64 = pv_override orelse @intCast(v.get("pv").?.integer);
        const epoch: u64 = @intCast(v.get("epoch").?.integer);
        const cfg = try protocol.get(pv, .mainnet);
        try testing.expect(cfg.feature_flags.enable_authenticated_event_streams);
        var fxs: std.ArrayList(types.TransactionEffectsV2) = .empty;
        for (v.get("root_effects").?.array.items) |h| {
            const fx = (try bcs.decode(types.TransactionEffects, a, try unhex(a, h.string))).V2;
            for (fx.changed_objects) |c| switch (c[1].output_state) {
                .AccumulatorWriteV1 => |w| switch (w.value) {
                    .EventDigest => |ds| n_events += ds.len,
                    else => {},
                },
                else => {},
            };
            try fxs.append(a, fx);
        }
        const params: ckpt_env.SettleParams = .{
            .epoch = epoch,
            .isv = 1, // MockCheckpointBuilder: OBJECT_START_VERSION
            .checkpoint_height = @intCast(v.get("height").?.integer),
            .checkpoint_seq = @intCast(v.get("seq").?.integer),
            .tx_index_offset = @intCast(v.get("tx_index_offset").?.integer),
            .max_updates_per_settlement_txn = cfg.max_updates_per_settlement_txn,
        };
        if (v.get("panic")) |_| {
            // Rust: todo!() in MergedValue::add_move_call (SumU128U128)
            try testing.expectError(error.UnsupportedAccumulatorValue, ckpt_env.buildSettlementsOf(a, fxs.items, params));
            n_cases += 1;
            continue;
        }
        const built = try ckpt_env.buildSettlementsOf(a, fxs.items, params);
        const want_s = v.get("settlements").?.array.items;
        if (built.len != want_s.len) std.debug.print("{s}: {d} settlements, Rust {d}\n", .{ name, built.len, want_s.len });
        try testing.expectEqual(want_s.len, built.len);

        var src: Src = .{};
        try frameworkPackages(a, pv, &src);
        for (v.get("objects").?.array.items) |h| try src.put(a, try unhex(a, h.string));
        const root_version = (try exec.objects.ObjectView.parse(src.objects.get(ckpt_env.accRootId()).?)).version;

        var after: Src = .{ .packages = src.packages };
        var it = src.objects.iterator();
        while (it.next()) |e| try after.objects.put(a, e.key_ptr.*, e.value_ptr.*);
        var views: std.ArrayList(types.TransactionEffectsV2) = .empty;
        for (built, want_s) |*t, w| {
            expectTx(a, w, t) catch |e| {
                std.debug.print("{s}: settlement {d} differs\n", .{ name, views.items.len });
                return e;
            };
            const r = try execute(a, cfg, epoch, &src, t, root_version);
            testing.expectEqualSlices(u8, try unhex(a, w.object.get("effects").?.string), r.effects) catch |e| {
                std.debug.print("{s}: settlement {d} effects differ\n", .{ name, views.items.len });
                return e;
            };
            for (r.written) |o| if (!std.mem.eql(u8, &o.id, &ckpt_env.accRootId())) try after.objects.put(a, o.id, o.bytes);
            try views.append(a, (try bcs.decode(types.TransactionEffects, a, r.effects)).V2);
        }
        const barrier = try ckpt_env.barrierTx(a, epoch, 1, params.checkpoint_height, views.items);
        const wb = v.get("barrier").?;
        expectTx(a, wb, &barrier) catch |e| {
            std.debug.print("{s}: barrier differs\n", .{name});
            return e;
        };
        const r = try execute(a, cfg, epoch, &after, &barrier, root_version);
        testing.expectEqualSlices(u8, try unhex(a, wb.object.get("effects").?.string), r.effects) catch |e| {
            std.debug.print("{s}: barrier effects differ\n", .{name});
            return e;
        };
        n_cases += 1;
    };
    try testing.expectEqual(@as(usize, 12), n_cases);
    try testing.expect(n_events > 100);
}

test "settlement: event merkle root of one leaf is the leaf hash" {
    // EventCommitment { checkpoint_seq 1, transaction_idx 2, event_idx 3, digest [7; 32] }: BCS is
    // three u64 then the 32-byte vector (length 32); the leaf is Blake2b-256(0x00 || BCS)
    var bytes: [24 + 1 + 32]u8 = undefined;
    std.mem.writeInt(u64, bytes[0..8], 1, .little);
    std.mem.writeInt(u64, bytes[8..16], 2, .little);
    std.mem.writeInt(u64, bytes[16..24], 3, .little);
    bytes[24] = 32;
    @memset(bytes[25..], 7);
    const want = @import("hash").blake2b256(&.{ &[_]u8{0}, &bytes });
    const digest: Id = @splat(7);
    var leaves = [_]Id{ckpt_env.eventLeaf(1, 2, 3, &digest)};
    try testing.expectEqualSlices(u8, &want, &leaves[0]);
    try testing.expectEqualSlices(u8, &want, &ckpt_env.eventMerkleRoot(&leaves));
    try testing.expectEqualSlices(u8, &@as(Id, @splat(0)), &ckpt_env.eventMerkleRoot(&.{}));
}
