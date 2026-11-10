//! Apply mode: the output objects of a checkpoint against its effects. For every transaction the
//! set of output object references (id, version, Blake2b256("Object::" ++ BCS)) must equal the
//! set of changed objects of its effects (`TransactionEffectsAPI::all_changed_objects`: mutated,
//! created and unwrapped; deleted and wrapped objects have no output object). One direction is
//! the check of sui-light-client's `TransactionProof::verify_objects`; the other direction keeps
//! a missing output object from leaving stale state behind when a store applies the checkpoint.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const verify = @import("verify.zig");
const Verdict = verify.Verdict;

/// id (32) ++ version (u64 LE) ++ digest (32): sorts and compares as plain bytes.
const Ref = [72]u8;

fn refLess(_: void, a: Ref, b: Ref) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

pub const Checker = struct {
    changed: std.ArrayList(Ref) = .empty,
    outs: std.ArrayList(Ref) = .empty,
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator) Checker {
        return .{ .gpa = gpa };
    }

    pub fn deinit(c: *Checker) void {
        c.changed.deinit(c.gpa);
        c.outs.deinit(c.gpa);
    }

    /// `idx` indexes `blob`. Allocates only to grow its two buffers (kept between calls).
    pub fn verifyOutputObjects(c: *Checker, idx: *const types.CheckpointIndex, blob: []const u8) error{OutOfMemory}!Verdict {
        for (0..idx.tx_count) |i| {
            const tx = idx.txAt(i);
            c.changed.clearRetainingCapacity();
            c.outs.clearRetainingCapacity();
            const ok = changedRefs(c, tx.effects.slice(blob)) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return .decode,
            };
            if (!ok) return .decode;
            for (idx.objs[tx.out_first..][0..tx.out_count]) |rg| {
                const ref = outputRef(rg.slice(blob)) orelse return .decode;
                try c.outs.append(c.gpa, ref);
            }
            std.mem.sort(Ref, c.changed.items, {}, refLess);
            std.mem.sort(Ref, c.outs.items, {}, refLess);
            const cmp = compareSets(c.outs.items, c.changed.items);
            if (cmp.out_not_changed) return mismatch(.output_object, i);
            if (cmp.changed_not_out) return mismatch(.missing_output, i);
        }
        return .ok;
    }
};

fn mismatch(what: verify.What, i: usize) Verdict {
    return .{ .digest_mismatch = .{ .what = what, .index = @intCast(@min(i, std.math.maxInt(u32))) } };
}

/// Set comparison of two sorted lists (duplicates collapse, as in a BTreeSet).
fn compareSets(outs: []const Ref, changed: []const Ref) struct { out_not_changed: bool, changed_not_out: bool } {
    var i: usize = 0;
    var j: usize = 0;
    var oc = false;
    var co = false;
    while (i < outs.len or j < changed.len) {
        if (i < outs.len and j < changed.len) {
            switch (std.mem.order(u8, &outs[i], &changed[j])) {
                .eq => {
                    i += 1;
                    j += 1;
                },
                .lt => {
                    oc = true;
                    i += 1;
                },
                .gt => {
                    co = true;
                    j += 1;
                },
            }
        } else if (i < outs.len) {
            oc = true;
            i += 1;
        } else {
            co = true;
            j += 1;
        }
        if (oc and co) break;
    }
    return .{ .out_not_changed = oc, .changed_not_out = co };
}

/// The reference of one `Object` (its BCS bytes): id, version, digest. Null when the contents
/// are too short to hold an id.
fn outputRef(obj: []const u8) ?Ref {
    var r = bcs.Reader.init(obj);
    var ref: Ref = undefined;
    const tag = r.uleb32() catch return null;
    switch (tag) {
        0 => {
            bcs.skip(types.MoveObjectType, &r) catch return null;
            _ = r.int(u8) catch return null; // has_public_transfer
            const version = r.int(u64) catch return null;
            const n = r.length() catch return null;
            const contents = r.bytes(n) catch return null;
            if (contents.len < 32) return null;
            @memcpy(ref[0..32], contents[0..32]);
            std.mem.writeInt(u64, ref[32..40], version, .little);
        },
        1 => {
            const id = r.bytes(32) catch return null;
            const version = r.int(u64) catch return null;
            @memcpy(ref[0..32], id);
            std.mem.writeInt(u64, ref[32..40], version, .little);
        },
        else => return null,
    }
    ref[40..72].* = hash.blake2b256(&.{ "Object::", obj });
    return ref;
}

const Owner = types.Owner;

/// Appends the changed object references of one effects value (mutated, created, unwrapped).
fn changedRefs(c: *Checker, eff: []const u8) !bool {
    var r = bcs.Reader.init(eff);
    const variant = try r.uleb32();
    bcs.skip(types.ExecutionStatus, &r) catch return false;
    _ = try r.bytes(8 + 32); // executed_epoch, gas_used
    switch (variant) {
        0 => {
            // V1: modified_at_versions, shared_objects, transaction_digest, created, mutated,
            // unwrapped (each ((id, version, digest), owner)), ...
            const Skip = struct {
                fn f(rd: *bcs.Reader, comptime T: type) !void {
                    try bcs.skip(T, rd);
                }
            }.f;
            try Skip(&r, @FieldType(types.TransactionEffectsV1, "modified_at_versions"));
            try Skip(&r, @FieldType(types.TransactionEffectsV1, "shared_objects"));
            try Skip(&r, types.TransactionDigest);
            for (0..3) |_| {
                const n = try r.length();
                for (0..n) |_| {
                    var ref: Ref = undefined;
                    @memcpy(ref[0..32], try r.bytes(32));
                    std.mem.writeInt(u64, ref[32..40], try r.int(u64), .little);
                    if ((try r.int(u8)) != 32) return false;
                    @memcpy(ref[40..72], try r.bytes(32));
                    try bcs.skip(Owner, &r);
                    try c.changed.append(c.gpa, ref);
                }
            }
        },
        1 => {
            // V2: transaction_digest, gas_object_index, events_digest, dependencies,
            // lamport_version, changed_objects
            try bcs.skip(types.TransactionDigest, &r);
            try bcs.skip(@FieldType(types.TransactionEffectsV2, "gas_object_index"), &r);
            try bcs.skip(@FieldType(types.TransactionEffectsV2, "events_digest"), &r);
            try bcs.skip(@FieldType(types.TransactionEffectsV2, "dependencies"), &r);
            const lamport = try r.int(u64);
            const n = try r.length();
            for (0..n) |_| {
                var ref: Ref = undefined;
                @memcpy(ref[0..32], try r.bytes(32));
                // EffectsObjectChange { input_state, output_state, id_operation }
                const in_exist = switch (try r.uleb32()) {
                    0 => false,
                    1 => blk: {
                        try bcs.skip(@FieldType(@FieldType(types.ObjectIn, "Exist"), "0"), &r);
                        try bcs.skip(Owner, &r);
                        break :blk true;
                    },
                    else => return false,
                };
                const Kind = enum { none, object, package, other };
                var kind: Kind = .none;
                switch (try r.uleb32()) {
                    0 => {},
                    1 => {
                        if ((try r.int(u8)) != 32) return false;
                        @memcpy(ref[40..72], try r.bytes(32));
                        try bcs.skip(Owner, &r);
                        std.mem.writeInt(u64, ref[32..40], lamport, .little);
                        kind = .object;
                    },
                    2 => {
                        std.mem.writeInt(u64, ref[32..40], try r.int(u64), .little);
                        if ((try r.int(u8)) != 32) return false;
                        @memcpy(ref[40..72], try r.bytes(32));
                        kind = .package;
                    },
                    3 => {
                        try bcs.skip(types.AccumulatorWriteV1, &r);
                        kind = .other;
                    },
                    else => return false,
                }
                const op = try r.uleb32(); // IDOperation: None, Created, Deleted
                if (op > 2) return false;
                // mutated: the input exists. created: no input, id Created. unwrapped: no input,
                // an ObjectWrite, id None. Either write kind counts for mutated and created.
                const wrote = kind == .object or kind == .package;
                if (wrote and (in_exist or op == 1 or (op == 0 and kind == .object))) try c.changed.append(c.gpa, ref);
            }
        },
        else => return false,
    }
    return true;
}

test "set comparison and object references" {
    const t = std.testing;
    var a: Ref = @splat(1);
    var b: Ref = @splat(2);
    var c: Ref = @splat(3);
    try t.expect(!compareSets(&.{ a, b }, &.{ a, b }).out_not_changed);
    try t.expect(!compareSets(&.{ a, b }, &.{ a, b }).changed_not_out);
    try t.expect(compareSets(&.{ a, b, c }, &.{ a, b }).out_not_changed);
    try t.expect(compareSets(&.{ a, b }, &.{ a, b, c }).changed_not_out);
    try t.expect(compareSets(&.{ a, c }, &.{ a, b }).out_not_changed);
    try t.expect(compareSets(&.{ a, c }, &.{ a, b }).changed_not_out);
    a[0] = 0;
    b[0] = 0;
    c[0] = 0;
    // a package object: tag 1, id, version, then anything (module map, ...) after
    var pkg: [32 + 8 + 1 + 1]u8 = undefined;
    pkg[0] = 1;
    @memset(pkg[1..33], 0xab);
    std.mem.writeInt(u64, pkg[33..41], 7, .little);
    pkg[41] = 0;
    const ref = outputRef(pkg[0..42]).?;
    try t.expectEqualSlices(u8, pkg[1..33], ref[0..32]);
    try t.expectEqual(@as(u64, 7), std.mem.readInt(u64, ref[32..40], .little));
    try t.expect(outputRef(&.{2}) == null);
    try t.expect(outputRef(&.{}) == null);
}
