//! GlobalStateHasher (sui-core `global_state_hasher.rs`, 1.83.1): the ECMH accumulator of one
//! checkpoint's effects. Three paths, chosen by the epoch's protocol config exactly as
//! `accumulate_effects` chooses them:
//!
//!   v3 (`enable_effects_v2`): insert the digest of every created, mutated and unwrapped object
//!      write; remove the input digest of every changed object that existed before.
//!   v2 (`simplified_unwrap_then_delete`): insert the same digests; remove the digests of the
//!      objects at `modified_at_versions`, read from the object store.
//!   v1: v2 plus wrapped tombstones (BCS `WrappedObject { id, wrapped_at, OBJECT_DIGEST_WRAPPED }`)
//!      inserted, unwrapped objects excluded from the removals, and a history lookup per
//!      unwrapped object (`get_object_ref_prior_to_key_deprecated`) whose tombstone is removed.
//!
//! The object store here is one checkpoint's own input and output objects (`ObjectTable`).
//! History lookups cannot be answered from one checkpoint; they are reported in `lookups`, and
//! keys absent from the table are reported in `missing` (Rust panics there; the truth tool
//! records the same keys). The v3 path, every checkpoint since effects v2, needs neither.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const sig = @import("sig");
const protocol = @import("protocol");
const objects = @import("objects.zig");

const Allocator = std.mem.Allocator;
const Reader = bcs.Reader;

pub const Path = enum { v1, v2, v3 };

pub fn pathFor(cfg: *const protocol.ProtocolConfig) Path {
    if (cfg.feature_flags.enable_effects_v2) return .v3;
    if (cfg.feature_flags.simplified_unwrap_then_delete) return .v2;
    return .v1;
}

pub const Key = objects.Key;

/// The accumulator of one checkpoint plus what a single checkpoint cannot supply.
pub const CheckpointHash = struct {
    acc: sig.Ecmh = .{},
    lookups: std.ArrayList(Key) = .empty,
    missing: std.ArrayList(Key) = .empty,
};

pub const wrapped_digest: [32]u8 = @splat(88);

/// BCS of sui-core `WrappedObject { id, wrapped_at, digest: OBJECT_DIGEST_WRAPPED }`.
pub fn wrappedObjectBytes(id: *const [32]u8, version: u64) [73]u8 {
    var b: [73]u8 = undefined;
    b[0..32].* = id.*;
    std.mem.writeInt(u64, b[32..40], version, .little);
    b[40] = 32;
    b[41..73].* = wrapped_digest;
    return b;
}

/// Max digests buffered before a paired `insertAll` flush.
const batch = 64;

const Inserter = struct {
    acc: *sig.Ecmh,
    buf: [batch][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *Inserter, item: []const u8) void {
        self.buf[self.n] = item;
        self.n += 1;
        if (self.n == batch) self.flush();
    }
    fn flush(self: *Inserter) void {
        self.acc.insertAll(self.buf[0..self.n]);
        self.n = 0;
    }
};

/// Accumulate one checkpoint. `blob` is the `.chk` blob, `idx` its index. `arena` holds the
/// object table and the decoded v1/v2 effects; the v3 path reads effects in place.
pub fn accumulateCheckpoint(arena: Allocator, path: Path, blob: []const u8, idx: *const types.CheckpointIndex, out: *CheckpointHash) !void {
    switch (path) {
        .v3 => {
            // Digests are borrowed from the blob. fastcrypto sums points, so order is
            // irrelevant: inserts and removals are each hashed in pairs into their own sum, and
            // the removal sum is subtracted once.
            var rem_acc: sig.Ecmh = .{};
            var ins: Inserter = .{ .acc = &out.acc };
            var rem: Inserter = .{ .acc = &rem_acc };
            for (idx.txs[0..idx.tx_count]) |*tx| {
                try scanEffectsV2(tx.effects.slice(blob), &ins, &rem);
            }
            ins.flush();
            rem.flush();
            out.acc.acc = out.acc.acc.sub(rem_acc.acc);
        },
        .v1, .v2 => try accumulateLegacy(arena, path, blob, idx, out),
    }
}

/// Effects V2 in place: `changed_objects` drives both the inserts and the removals.
fn scanEffectsV2(raw: []const u8, ins: *Inserter, rem: *Inserter) !void {
    var r = Reader.init(raw);
    const tag = try r.uleb32();
    if (tag != 1) return error.EffectsV1UnderEffectsV2;
    try bcs.skip(types.ExecutionStatus, &r);
    _ = try r.bytes(8 + 32); // executed_epoch, gas_used
    _ = try r.bytes(1 + 32); // transaction_digest (length 32 + bytes)
    try bcs.skip(?u32, &r); // gas_object_index
    try bcs.skip(?types.TransactionEventsDigest, &r);
    const ndeps = try r.length();
    _ = try r.bytes(ndeps * 33);
    _ = try r.int(u64); // lamport_version
    const n = try r.length();
    for (0..n) |_| {
        _ = try r.bytes(32); // id
        // input_state
        const in_tag = try r.uleb32();
        var existed = false;
        switch (in_tag) {
            0 => {},
            1 => {
                _ = try r.int(u64);
                const d = try digestAt(&r);
                try bcs.skip(types.Owner, &r);
                rem.push(d);
                existed = true;
            },
            else => return error.InvalidValue,
        }
        // output_state
        const out_tag = try r.uleb32();
        var written: ?[]const u8 = null;
        var package = false;
        switch (out_tag) {
            0 => {},
            1 => {
                written = try digestAt(&r);
                try bcs.skip(types.Owner, &r);
            },
            2 => {
                _ = try r.int(u64);
                written = try digestAt(&r);
                package = true;
            },
            3 => try bcs.skip(types.AccumulatorWriteV1, &r),
            else => return error.InvalidValue,
        }
        const id_op = try r.uleb32();
        if (id_op > 2) return error.InvalidValue;
        if (written) |d| {
            // mutated: Exist -> ObjectWrite | PackageWrite (any id op)
            // created: NotExist -> ObjectWrite | PackageWrite with Created
            // unwrapped: NotExist -> ObjectWrite with None
            const counted = existed or id_op == 1 or (!package and id_op == 0);
            if (counted) ins.push(d);
        }
    }
}

fn digestAt(r: *Reader) ![]const u8 {
    const len = try r.uleb32();
    if (len != 32) return error.InvalidValue;
    return r.bytes(32);
}

const Effects = types.TransactionEffects;

fn accumulateLegacy(arena: Allocator, path: Path, blob: []const u8, idx: *const types.CheckpointIndex, out: *CheckpointHash) !void {
    var table: objects.ObjectTable = .{};
    try table.addCheckpoint(arena, blob, idx);

    const fxs = try arena.alloc(Effects, idx.tx_count);
    for (idx.txs[0..idx.tx_count], fxs) |*tx, *fx| fx.* = try bcs.decode(Effects, arena, tx.effects.slice(blob));

    var ins: Inserter = .{ .acc = &out.acc };
    // Inserts: all_changed_objects digests (mutated, created, unwrapped).
    for (fxs) |*fx| switch (fx.*) {
        .V1 => |*v| {
            for (v.mutated) |*e| ins.push(&e[0][2].@"0".@"0");
            for (v.created) |*e| ins.push(&e[0][2].@"0".@"0");
            for (v.unwrapped) |*e| ins.push(&e[0][2].@"0".@"0");
        },
        .V2 => |*v| for (v.changed_objects) |*c| if (changedDigest(&c[1])) |d| ins.push(d),
    };
    ins.flush();

    if (path == .v1) {
        // Wrapped tombstones.
        for (fxs) |*fx| switch (fx.*) {
            .V1 => |*v| for (v.wrapped) |w| {
                const b = wrappedObjectBytes(&w[0].@"0".@"0", w[1].@"0");
                out.acc.insert(&b);
            },
            .V2 => |*v| for (v.changed_objects) |*c| {
                if (c[1].input_state == .Exist and c[1].output_state == .NotExist and c[1].id_operation == .None) {
                    const b = wrappedObjectBytes(&c[0].@"0".@"0", v.lamport_version.@"0");
                    out.acc.insert(&b);
                }
            },
        };
    }

    // Removals: objects at modified_at_versions (filtered by unwrapped ids in v1).
    for (fxs) |*fx| {
        switch (fx.*) {
            .V1 => |*v| for (v.modified_at_versions) |m| {
                const id = &m[0].@"0".@"0";
                if (containsId(v.unwrapped_then_deleted, id)) continue; // trait filter
                if (path == .v1 and unwrappedInTx(v, id)) continue;
                try removeKey(arena, &table, .{ .id = id.*, .version = m[1].@"0" }, out);
            },
            .V2 => |*v| for (v.changed_objects) |*c| switch (c[1].input_state) {
                .Exist => |e| {
                    const id = &c[0].@"0".@"0";
                    if (path == .v1 and unwrappedInTxV2(v, id)) continue;
                    try removeKey(arena, &table, .{ .id = id.*, .version = e[0][0].@"0" }, out);
                },
                .NotExist => {},
            },
        }
    }

    if (path == .v1) {
        // History lookups for every unwrapped and unwrapped-then-deleted object; this store
        // answers None (the tombstone is outside the checkpoint), so nothing is removed.
        for (fxs) |*fx| switch (fx.*) {
            .V1 => |*v| {
                for (v.unwrapped) |e| try out.lookups.append(arena, .{ .id = e[0][0].@"0".@"0", .version = e[0][1].@"0" });
                for (v.unwrapped_then_deleted) |e| try out.lookups.append(arena, .{ .id = e[0].@"0".@"0", .version = e[1].@"0" });
            },
            .V2 => |*v| for (v.changed_objects) |*c| {
                if (c[1].input_state != .NotExist) continue;
                const unwrap = switch (c[1].output_state) {
                    .ObjectWrite => c[1].id_operation == .None,
                    .NotExist => c[1].id_operation == .Deleted,
                    else => false,
                };
                if (unwrap) try out.lookups.append(arena, .{ .id = c[0].@"0".@"0", .version = v.lamport_version.@"0" });
            },
        };
    }
}

pub const ObjectRef = struct { id: [32]u8, version: u64, digest: [32]u8 };

/// Finish one v1-path history lookup (`lookups` of `accumulateCheckpoint`) with the store's
/// answer to `get_object_ref_prior_to_key_deprecated(key)`: `null` removes nothing; `Some(ref)`
/// removes the `WrappedObject { ref.id, ref.version }` tombstone. Rust asserts
/// `!loaded_child_objects_fixed || ref.digest.is_wrapped()` before any removal; that panic is
/// `error.PriorRefNotWrapped`, after which the checkpoint has no accumulator.
pub fn applyHistory(out: *CheckpointHash, key: Key, prior: ?ObjectRef, loaded_child_objects_fixed: bool) error{PriorRefNotWrapped}!void {
    _ = key;
    const r = prior orelse return;
    if (loaded_child_objects_fixed and !std.mem.eql(u8, &r.digest, &wrapped_digest)) return error.PriorRefNotWrapped;
    const b = wrappedObjectBytes(&r.id, r.version);
    out.acc.remove(&b);
}

fn removeKey(arena: Allocator, table: *const objects.ObjectTable, key: Key, out: *CheckpointHash) !void {
    if (table.get(key)) |raw| {
        const d = types.digest.objectDigest(raw);
        out.acc.remove(&d);
    } else try out.missing.append(arena, key);
}

fn changedDigest(c: *const types.EffectsObjectChange) ?[]const u8 {
    const existed = c.input_state == .Exist;
    return switch (c.output_state) {
        .ObjectWrite => |*w| if (existed or c.id_operation != .Deleted) &w[0].@"0".@"0" else null,
        .PackageWrite => |*w| if (existed or c.id_operation == .Created) &w[1].@"0".@"0" else null,
        else => null,
    };
}

fn containsId(list: anytype, id: *const [32]u8) bool {
    for (list) |e| if (std.mem.eql(u8, &e[0].@"0".@"0", id)) return true;
    return false;
}

fn unwrappedInTx(v: *const types.TransactionEffectsV1, id: *const [32]u8) bool {
    for (v.unwrapped) |e| if (std.mem.eql(u8, &e[0][0].@"0".@"0", id)) return true;
    return containsId(v.unwrapped_then_deleted, id);
}

fn unwrappedInTxV2(v: *const types.TransactionEffectsV2, id: *const [32]u8) bool {
    for (v.changed_objects) |*c| {
        if (!std.mem.eql(u8, &c[0].@"0".@"0", id)) continue;
        if (c[1].input_state != .NotExist) continue;
        return switch (c[1].output_state) {
            .ObjectWrite => c[1].id_operation == .None,
            .NotExist => c[1].id_operation == .Deleted,
            else => false,
        };
    }
    return false;
}

test "applyHistory removes the tombstone and asserts the wrapped digest" {
    const id: [32]u8 = @splat(5);
    var a: CheckpointHash = .{};
    const b = wrappedObjectBytes(&id, 9);
    a.acc.insert(&b);
    try applyHistory(&a, .{ .id = id, .version = 10 }, .{ .id = id, .version = 9, .digest = wrapped_digest }, true);
    try std.testing.expectEqualSlices(u8, &(sig.Ecmh{}).toBytes(), &a.acc.toBytes());
    try applyHistory(&a, .{ .id = id, .version = 10 }, null, true);
    try std.testing.expectError(error.PriorRefNotWrapped, applyHistory(&a, .{ .id = id, .version = 10 }, .{ .id = id, .version = 9, .digest = @splat(0x11) }, true));
    try applyHistory(&a, .{ .id = id, .version = 10 }, .{ .id = id, .version = 9, .digest = @splat(0x11) }, false);
}

test "wrapped object bytes" {
    const id: [32]u8 = @splat(7);
    const b = wrappedObjectBytes(&id, 0x0102);
    try std.testing.expectEqual(@as(u8, 0x02), b[32]);
    try std.testing.expectEqual(@as(u8, 32), b[40]);
    try std.testing.expectEqual(@as(u8, 88), b[72]);
}

test "ecmh digest of a known accumulator" {
    var hex: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hex, "a0e00501ee6ab000d16bbe6792d0ee4b636f1f833de94c722ac8907422c3d101");
    const acc = sig.Ecmh.fromBytes(&hex).?;
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "948a9a0e60b7752308740299e0b291c42e8dfeba684fd4788d899eb6174d9ded");
    try std.testing.expectEqualSlices(u8, &hex, &acc.toBytes());
    try std.testing.expectEqualSlices(u8, &want, &acc.digest());
}
