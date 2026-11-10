//! The state accumulator of a validator (sui-core `global_state_hasher.rs`, 1.83.1): the ECMH
//! multiset hash of the live object set, advanced one checkpoint at a time, and the
//! `ECMHLiveObjectSetDigest` committed at the end of every epoch
//! (`commit_root_state_digest`).
//!
//!   checkpoint accumulator = sum of digests inserted by the checkpoint's effects, minus the
//!                            digests of the object versions they consumed (v3 path:
//!                            `enable_effects_v2`, every checkpoint on mainnet since effects v2)
//!   running root(n)        = running root(n - 1) + checkpoint accumulator(n), from genesis
//!   epoch digest           = SHA-256 of the encoded running root at the epoch's last checkpoint
//!
//! The v1 and v2 paths (pre effects-v2 protocols) need the object store and are not supported:
//! `accumulateEffects` returns `error.UnsupportedProtocol` for them, which a validator on a
//! current protocol never meets.
const std = @import("std");
const sig = @import("sig");
const protocol = @import("protocol");
const exec = @import("exec");
const ev = @import("effects_view.zig");

pub const Error = error{ UnsupportedProtocol, OutOfOrder, OutOfMemory };

/// Insert/remove digests borrowed from effects; `insertAll` pairs the hash-to-group work.
pub fn accumulateEffects(gpa: std.mem.Allocator, cfg: *const protocol.ProtocolConfig, effects: []const ev.View) Error!sig.Ecmh {
    if (exec.state_hash.pathFor(cfg) != .v3) return error.UnsupportedProtocol;
    var ins: std.ArrayList([]const u8) = .empty;
    defer ins.deinit(gpa);
    var rem: std.ArrayList([]const u8) = .empty;
    defer rem.deinit(gpa);
    for (effects) |*e| {
        const x = switch (e.fx) {
            .V1 => return error.UnsupportedProtocol,
            .V2 => |*x| x,
        };
        for (x.changed_objects) |*c| {
            const ch = &c[1];
            var existed = false;
            switch (ch.input_state) {
                .NotExist => {},
                .Exist => |*ex| {
                    try rem.append(gpa, &ex[0][1].@"0".@"0");
                    existed = true;
                },
            }
            var written: ?*const [32]u8 = null;
            var package = false;
            switch (ch.output_state) {
                .NotExist, .AccumulatorWriteV1 => {},
                .ObjectWrite => |*w| written = &w[0].@"0".@"0",
                .PackageWrite => |*p| {
                    written = &p[1].@"0".@"0";
                    package = true;
                },
            }
            if (written) |d| {
                // mutated: Exist -> write; created: NotExist -> write with Created;
                // unwrapped: NotExist -> ObjectWrite with None (a package never is)
                const counted = existed or ch.id_operation == .Created or (!package and ch.id_operation == .None);
                if (counted) try ins.append(gpa, d);
            }
        }
    }
    var acc: sig.Ecmh = .{};
    acc.insertAll(ins.items);
    var removed: sig.Ecmh = .{};
    removed.insertAll(rem.items);
    acc.acc = acc.acc.sub(removed.acc);
    return acc;
}

/// The running root over checkpoints. `last_seq` null = nothing accumulated (the first
/// accumulated checkpoint must be sequence number 0, genesis). A builder that starts later
/// must restore the stored root, otherwise `apply` fails with `OutOfOrder` (a root made of only
/// this run's deltas would commit a wrong epoch digest).
pub const RunningRoot = struct {
    root: sig.Ecmh = .{},
    last_seq: ?u64 = null,

    pub fn restore(root_bytes: *const [32]u8, last_seq: u64) ?RunningRoot {
        const r = sig.Ecmh.fromBytes(root_bytes) orelse return null;
        return .{ .root = r, .last_seq = last_seq };
    }

    /// `accumulate_running_root`: idempotent for the checkpoint already applied.
    pub fn apply(self: *RunningRoot, seq: u64, checkpoint_acc: *const sig.Ecmh) Error!void {
        if (self.last_seq) |l| {
            if (seq == l) return;
            if (seq != l + 1) return error.OutOfOrder;
        } else if (seq != 0) return error.OutOfOrder;
        self.root.add(checkpoint_acc);
        self.last_seq = seq;
    }

    /// `digest_epoch`: the digest committed in the last checkpoint of an epoch.
    pub fn epochDigest(self: *const RunningRoot) [32]u8 {
        return self.root.digest();
    }
};

test "running root is order independent and idempotent per checkpoint" {
    var a: sig.Ecmh = .{};
    a.insert("x");
    var b: sig.Ecmh = .{};
    b.insert("y");
    b.remove("x");
    var r1: RunningRoot = .{};
    try r1.apply(0, &a);
    try r1.apply(1, &b);
    try r1.apply(1, &b); // already applied
    var r2: RunningRoot = .{};
    try r2.apply(0, &b);
    try r2.apply(1, &a);
    try std.testing.expectEqual(r1.epochDigest(), r2.epochDigest());
    try std.testing.expectError(error.OutOfOrder, r1.apply(5, &a));
    var only_y: sig.Ecmh = .{};
    only_y.insert("y");
    try std.testing.expectEqual(only_y.digest(), r1.epochDigest());
}

test "running root without a seeded root only accepts genesis" {
    var a: sig.Ecmh = .{};
    a.insert("x");
    var r: RunningRoot = .{};
    try std.testing.expectError(error.OutOfOrder, r.apply(5, &a));
    try r.apply(0, &a);
    const bytes = r.root.toBytes();
    var r2 = RunningRoot.restore(&bytes, 0).?;
    try r2.apply(1, &a);
}
