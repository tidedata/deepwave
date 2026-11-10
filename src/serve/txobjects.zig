//! `sui_types::storage::get_transaction_object_set`: the (id, version) keys of the objects a
//! transaction read or wrote, as the node's GetTransaction fetches them: input objects that carry
//! a version, the input and output versions of every object change, ReadOnlyRoot unchanged
//! consensus objects and the unchanged loaded runtime objects. Sorted, without duplicates (a
//! BTreeSet<ObjectKey>).
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types");
const objset = @import("objset.zig");

const Ref = objset.Ref;

fn isCoinReservation(digest: *const [32]u8) bool {
    for (digest[12..32]) |b| if (b != 0xac) return false;
    return true;
}

fn isSystem(k: types.TransactionKind) bool {
    return switch (k) {
        .ProgrammableTransaction => false,
        else => true,
    };
}

fn lessRef(_: void, a: Ref, b: Ref) bool {
    const o = std.mem.order(u8, &a.id, &b.id);
    return if (o == .eq) a.version < b.version else o == .lt;
}

pub fn keys(arena: Allocator, td: types.TransactionData, eff: types.TransactionEffects, loaded: []const Ref) Allocator.Error![]const Ref {
    var out: std.ArrayList(Ref) = .empty;
    const v1 = switch (td) {
        .V1 => |v| v,
    };
    // input objects with versions
    const ptb: ?types.ProgrammableTransaction = switch (v1.kind) {
        .ProgrammableTransaction => |p| p,
        .ProgrammableSystemTransaction => |p| p,
        else => null,
    };
    if (ptb) |p| for (p.inputs) |arg| switch (arg) {
        .Object => |o| switch (o) {
            .ImmOrOwnedObject => |r| if (!isCoinReservation(&r.@"2".@"0".@"0")) try out.append(arena, .{ .id = r.@"0".@"0".@"0", .version = r.@"1".@"0" }),
            else => {},
        },
        else => {},
    };
    if (!isSystem(v1.kind)) for (v1.gas_data.payment) |r| {
        if (!isCoinReservation(&r.@"2".@"0".@"0")) try out.append(arena, .{ .id = r.@"0".@"0".@"0", .version = r.@"1".@"0" });
    };
    switch (eff) {
        .V2 => |v| {
            for (v.changed_objects) |e| {
                const id = e.@"0".@"0".@"0";
                if (e.@"1".output_state == .AccumulatorWriteV1) continue;
                switch (e.@"1".input_state) {
                    .Exist => |x| try out.append(arena, .{ .id = id, .version = x.@"0".@"0".@"0" }),
                    .NotExist => {},
                }
                switch (e.@"1".output_state) {
                    .ObjectWrite => try out.append(arena, .{ .id = id, .version = v.lamport_version.@"0" }),
                    .PackageWrite => |x| try out.append(arena, .{ .id = id, .version = x.@"0".@"0" }),
                    else => {},
                }
            }
            for (v.unchanged_consensus_objects) |e| switch (e.@"1") {
                .ReadOnlyRoot => |r| try out.append(arena, .{ .id = e.@"0".@"0".@"0", .version = r.@"0".@"0" }),
                else => {},
            };
        },
        .V1 => |v| {
            const modifiedAt = struct {
                fn get(m: anytype, id: *const [32]u8) ?u64 {
                    for (m) |e| if (std.mem.eql(u8, &e.@"0".@"0".@"0", id)) return e.@"1".@"0";
                    return null;
                }
            }.get;
            for (v.created) |e| try out.append(arena, .{ .id = e.@"0".@"0".@"0".@"0", .version = e.@"0".@"1".@"0" });
            for (v.mutated) |e| {
                const id = e.@"0".@"0".@"0".@"0";
                if (modifiedAt(v.modified_at_versions, &id)) |iv| try out.append(arena, .{ .id = id, .version = iv });
                try out.append(arena, .{ .id = id, .version = e.@"0".@"1".@"0" });
            }
            for (v.unwrapped) |e| try out.append(arena, .{ .id = e.@"0".@"0".@"0".@"0", .version = e.@"0".@"1".@"0" });
            for (v.deleted) |e| {
                const id = e.@"0".@"0".@"0";
                if (modifiedAt(v.modified_at_versions, &id)) |iv| try out.append(arena, .{ .id = id, .version = iv });
            }
            for (v.wrapped) |e| {
                const id = e.@"0".@"0".@"0";
                if (modifiedAt(v.modified_at_versions, &id)) |iv| try out.append(arena, .{ .id = id, .version = iv });
            }
            for (v.shared_objects) |e| {
                const id = e.@"0".@"0".@"0";
                if (modifiedAt(v.modified_at_versions, &id) == null) try out.append(arena, .{ .id = id, .version = e.@"1".@"0" });
            }
        },
    }
    for (loaded) |r| try out.append(arena, r);
    std.mem.sort(Ref, out.items, {}, lessRef);
    var n: usize = 0;
    for (out.items) |r| {
        if (n > 0 and std.mem.eql(u8, &out.items[n - 1].id, &r.id) and out.items[n - 1].version == r.version) continue;
        out.items[n] = r;
        n += 1;
    }
    return out.items[0..n];
}
