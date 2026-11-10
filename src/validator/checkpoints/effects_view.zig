//! A decoded view of one TransactionEffects (V1 or V2) with the accessors the checkpoint builder
//! needs: `TransactionEffectsAPI::{transaction_digest, dependencies, gas_cost_summary,
//! accessed_consensus_objects, written}` of sui-types 1.83.1 (`effects/effects_v1.rs`,
//! `effects_v2.rs`). Nothing here validates the effects: they come from this node's own executor.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");

pub const Error = error{ BadEffects, OutOfMemory };

/// (object id, version): sui-types `ObjectKey`.
pub const Key = struct {
    id: [32]u8,
    version: u64,

    pub fn bytes(k: Key) [40]u8 {
        var b: [40]u8 = undefined;
        b[0..32].* = k.id;
        std.mem.writeInt(u64, b[32..40], k.version, .little);
        return b;
    }
};

/// How a transaction touched a consensus object, reduced to what `RWLockDependencyBuilder` reads:
/// `read` = ReadOnly and ReadConsensusStreamEnded, `overwrite` = Mutate and
/// MutateConsensusStreamEnded. Cancelled and PerEpochConfig are not accesses.
pub const AccessKind = enum { read, overwrite };
pub const Access = struct { kind: AccessKind, key: Key };

/// `ObjectRef` of `TransactionEffectsAPI::written()`.
pub const ObjRef = struct { id: [32]u8, version: u64, digest: [32]u8 };

pub const GasSummary = struct {
    computation_cost: u64 = 0,
    storage_cost: u64 = 0,
    storage_rebate: u64 = 0,
    non_refundable_storage_fee: u64 = 0,
};

/// OBJECT_DIGEST_DELETED and OBJECT_DIGEST_WRAPPED (sui-types `ObjectDigest`): 32 bytes of 99
/// and of 88.
pub const object_digest_deleted: [32]u8 = @splat(99);
pub const object_digest_wrapped: [32]u8 = @splat(88);

pub const View = struct {
    raw: []const u8,
    fx: types.TransactionEffects,
    tx: [32]u8,
    /// Digest of the effects (Blake2b256 of "TransactionEffects::" ++ BCS).
    digest: [32]u8,

    /// Decodes `raw` into `arena`. `raw` is borrowed and must outlive the view.
    pub fn parse(arena: std.mem.Allocator, raw: []const u8) Error!View {
        const fx = bcs.decode(types.TransactionEffects, arena, raw) catch |e| {
            return if (e == error.OutOfMemory) error.OutOfMemory else error.BadEffects;
        };
        const tx = switch (fx) {
            .V1 => |v| v.transaction_digest.@"0".@"0",
            .V2 => |v| v.transaction_digest.@"0".@"0",
        };
        return .{ .raw = raw, .fx = fx, .tx = tx, .digest = types.digest.effectsDigest(raw) };
    }

    pub fn dependencies(v: *const View) []const types.TransactionDigest {
        return switch (v.fx) {
            .V1 => |*x| x.dependencies,
            .V2 => |*x| x.dependencies,
        };
    }

    pub fn gas(v: *const View) GasSummary {
        const g = switch (v.fx) {
            .V1 => |*x| x.gas_used,
            .V2 => |*x| x.gas_used,
        };
        return .{
            .computation_cost = g.computationCost,
            .storage_cost = g.storageCost,
            .storage_rebate = g.storageRebate,
            .non_refundable_storage_fee = g.nonRefundableStorageFee,
        };
    }

    pub fn lamportVersion(v: *const View) ?u64 {
        return switch (v.fx) {
            .V1 => null,
            .V2 => |*x| x.lamport_version.@"0",
        };
    }

    /// `accessed_consensus_objects`, appended to `out` in Rust's order.
    pub fn accessed(v: *const View, gpa: std.mem.Allocator, out: *std.ArrayList(Access)) Error!void {
        switch (v.fx) {
            .V1 => |*x| {
                for (x.shared_objects) |s| {
                    var modified = false;
                    for (x.modified_at_versions) |m| {
                        if (std.mem.eql(u8, &m[0].@"0".@"0", &s[0].@"0".@"0")) {
                            modified = true;
                            break;
                        }
                    }
                    try out.append(gpa, .{
                        .kind = if (modified) .overwrite else .read,
                        .key = .{ .id = s[0].@"0".@"0", .version = s[1].@"0" },
                    });
                }
            },
            .V2 => |*x| {
                for (x.changed_objects) |c| {
                    switch (c[1].input_state) {
                        .Exist => |e| if (isConsensus(&e[1])) {
                            try out.append(gpa, .{
                                .kind = .overwrite,
                                .key = .{ .id = c[0].@"0".@"0", .version = e[0][0].@"0" },
                            });
                        },
                        .NotExist => {},
                    }
                }
                for (x.unchanged_consensus_objects) |u| {
                    const id = u[0].@"0".@"0";
                    switch (u[1]) {
                        .ReadOnlyRoot => |r| try out.append(gpa, .{ .kind = .read, .key = .{ .id = id, .version = r[0].@"0" } }),
                        .MutateConsensusStreamEnded => |s| try out.append(gpa, .{ .kind = .overwrite, .key = .{ .id = id, .version = s.@"0" } }),
                        .ReadConsensusStreamEnded => |s| try out.append(gpa, .{ .kind = .read, .key = .{ .id = id, .version = s.@"0" } }),
                        .Cancelled, .PerEpochConfig => {},
                    }
                }
            },
        }
    }

    /// `TransactionEffectsAPI::written()` for V2 effects (the only kind a protocol with
    /// `include_checkpoint_artifacts_digest_in_summary` produces); `error.BadEffects` for V1.
    pub fn written(v: *const View, gpa: std.mem.Allocator, out: *std.ArrayList(ObjRef)) Error!void {
        const x = switch (v.fx) {
            .V1 => return error.BadEffects,
            .V2 => |*x| x,
        };
        const lamport = x.lamport_version.@"0";
        for (x.changed_objects) |c| {
            const id = c[0].@"0".@"0";
            const ch = c[1];
            switch (ch.output_state) {
                .NotExist => switch (ch.id_operation) {
                    .Deleted => try out.append(gpa, .{ .id = id, .version = lamport, .digest = object_digest_deleted }),
                    .None => try out.append(gpa, .{ .id = id, .version = lamport, .digest = object_digest_wrapped }),
                    .Created => {},
                },
                .ObjectWrite => |w| try out.append(gpa, .{ .id = id, .version = lamport, .digest = w[0].@"0".@"0" }),
                .PackageWrite => |p| try out.append(gpa, .{ .id = id, .version = p[0].@"0", .digest = p[1].@"0".@"0" }),
                .AccumulatorWriteV1 => {},
            }
        }
    }
};

fn isConsensus(o: *const types.Owner) bool {
    return switch (o.*) {
        .Shared, .ConsensusAddressOwner, .Party => true,
        else => false,
    };
}

test "gas and digests of V2 effects round trip" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fx: types.TransactionEffects = .{ .V2 = .{
        .status = .Success,
        .executed_epoch = 3,
        .gas_used = .{ .computationCost = 10, .storageCost = 20, .storageRebate = 5, .nonRefundableStorageFee = 1 },
        .transaction_digest = .{ .@"0" = .{ .@"0" = @splat(7) } },
        .gas_object_index = null,
        .events_digest = null,
        .dependencies = &.{},
        .lamport_version = .{ .@"0" = 9 },
        .changed_objects = &.{},
        .unchanged_consensus_objects = &.{},
        .aux_data_digest = null,
    } };
    const raw = try bcs.encodeAlloc(types.TransactionEffects, a, &fx);
    const v = try View.parse(a, raw);
    try std.testing.expectEqual(@as(u8, 7), v.tx[0]);
    try std.testing.expectEqual(@as(u64, 10), v.gas().computation_cost);
    try std.testing.expectEqual(@as(?u64, 9), v.lamportVersion());
    var acc: std.ArrayList(Access) = .empty;
    try v.accessed(a, &acc);
    try std.testing.expectEqual(@as(usize, 0), acc.items.len);
}
