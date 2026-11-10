//! Coin deny list v2 reads during execution (`check_coin_deny_list_v2_during_execution`): Rust
//! reads the per-type config and its settings through the tracking store, so they show up in
//! `unchanged_loaded_runtime_objects`. exec-move charges for the check and assumes it passes;
//! this replays the reads and reports a pause or a denied owner (the effects would differ).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const exec = @import("exec");
const natives = @import("natives");

const state_mod = @import("state.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const ObjectView = exec.objects.ObjectView;
const State = state_mod.State;
pub const Ref = struct { id: Id, version: u64 };

const deny_list_id: Id = blk: {
    var a: Id = @splat(0);
    a[30] = 0x04;
    a[31] = 0x03;
    break :blk a;
};

/// (coin type, owner) pairs that received funds: exec-move's `Output.deny_pairs` (written
/// `Coin<T>` objects and `Balance<T>` accumulator events of context::finish, SUI excluded).
pub const Pairs = struct {
    items: std.ArrayList(struct { ty: types.TypeTag, owner: Id }) = .empty,
};

pub fn fromPtb(arena: Allocator, list: []const exec.ptb.run.DenyPair) !Pairs {
    var p: Pairs = .{};
    for (list) |x| try p.items.append(arena, .{ .ty = try bcs.decode(types.TypeTag, arena, x.t), .owner = x.o });
    return p;
}

pub const Outcome = union(enum) {
    ok,
    /// A paused coin type or a denied owner: the execution would fail (not modelled).
    denied: []const u8,
};

/// `derive_dynamic_field_id(parent, key_type, key_bytes)`.
fn fieldId(parent: *const Id, key_type_bcs: []const u8, key: []const u8) Id {
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, key.len, .little);
    return hash.blake2b256(&.{ &[_]u8{0xf0}, parent, &len_le, key, key_type_bcs });
}

fn fwStructTag(out: *std.ArrayList(u8), arena: Allocator, module: []const u8, name: []const u8, n_args: u8) !void {
    try out.append(arena, 7); // TypeTag::Struct
    var a: Id = @splat(0);
    a[31] = 2;
    try out.appendSlice(arena, &a);
    try out.append(arena, @intCast(module.len));
    try out.appendSlice(arena, module);
    try out.append(arena, @intCast(name.len));
    try out.appendSlice(arena, name);
    try out.append(arena, n_args);
}

/// Replays the reads for `pairs` and appends each object read to `reads`.
pub fn check(arena: Allocator, state: State, epoch: u64, pairs: *const Pairs, reads: *std.ArrayList(Ref)) !Outcome {
    if (pairs.items.items.len == 0) return .ok;
    var wrapper_tag: std.ArrayList(u8) = .empty;
    try fwStructTag(&wrapper_tag, arena, "dynamic_object_field", "Wrapper", 1);
    try fwStructTag(&wrapper_tag, arena, "deny_list", "ConfigKey", 0);
    var pause_tag: std.ArrayList(u8) = .empty;
    try fwStructTag(&pause_tag, arena, "deny_list", "GlobalPauseKey", 0);
    var addr_tag: std.ArrayList(u8) = .empty;
    try fwStructTag(&addr_tag, arena, "deny_list", "AddressKey", 0);

    // get_per_type_coin_deny_list_v2 for every coin type first (the BTreeMap collect), then
    // check_new_regulated_coin_owners per type.
    var seen: std.ArrayList([]const u8) = .empty;
    for (pairs.items.items) |pr| {
        const name = try natives.abi.canonicalString(arena, &pr.ty, false);
        for (seen.items) |s| {
            if (std.mem.eql(u8, s, name)) break;
        } else {
            try seen.append(arena, name);
        }
    }
    for (seen.items) |name| {
        // DOFWrapper { ConfigKey { per_type_index: 0, per_type_key: name } }
        var key: std.ArrayList(u8) = .empty;
        try key.appendNTimes(arena, 0, 8);
        var lb: [10]u8 = undefined;
        try key.appendSlice(arena, uleb(&lb, name.len));
        try key.appendSlice(arena, name);
        const cid = fieldId(&deny_list_id, wrapper_tag.items, key.items);
        const raw = state.latest(&cid) orelse continue;
        const v = ObjectView.parse(raw) catch continue;
        try reads.append(arena, .{ .id = cid, .version = v.version });
        const c = v.contents();
        if (c.len < 64) continue;
        const config_id: Id = c[c.len - 32 ..][0..32].*;

        if (try setting(arena, state, &config_id, pause_tag.items, &.{0}, epoch, reads))
            return .{ .denied = try std.fmt.allocPrint(arena, "coin type {s} is globally paused", .{name}) };
        for (pairs.items.items) |pr| {
            const n2 = try natives.abi.canonicalString(arena, &pr.ty, false);
            if (!std.mem.eql(u8, n2, name)) continue;
            if (try setting(arena, state, &config_id, addr_tag.items, &pr.owner, epoch, reads))
                return .{ .denied = try std.fmt.allocPrint(arena, "address denied for coin type {s}", .{name}) };
        }
    }
    return .ok;
}

/// `read_config_setting::<K, bool>`: true when the setting reads true at `epoch`.
fn setting(arena: Allocator, state: State, config: *const Id, key_tag: []const u8, key: []const u8, epoch: u64, reads: *std.ArrayList(Ref)) !bool {
    const id = fieldId(config, key_tag, key);
    const raw = state.latest(&id) orelse return false;
    const v = ObjectView.parse(raw) catch return false;
    try reads.append(arena, .{ .id = id, .version = v.version });
    // Field { id, name: K, value: Setting { data: Option<SettingData<bool>> } }
    const c = v.contents();
    if (c.len < 32 + key.len + 1) return false;
    const s = c[32 + key.len ..];
    if (s[0] != 1 or s.len < 1 + 8 + 1) return false;
    const newer_epoch = std.mem.readInt(u64, s[1..9], .little);
    var at: usize = 9;
    const newer: ?bool = if (s[at] == 1) blk: {
        if (s.len < at + 2) return false;
        at += 2;
        break :blk s[at - 1] == 1;
    } else blk: {
        at += 1;
        break :blk null;
    };
    const older: ?bool = if (at < s.len and s[at] == 1 and at + 1 < s.len) s[at + 1] == 1 else null;
    const val = if (epoch > newer_epoch) newer else older;
    return val orelse false;
}

fn uleb(buf: *[10]u8, n: usize) []const u8 {
    var x = n;
    var i: usize = 0;
    while (true) {
        const b: u8 = @intCast(x & 0x7f);
        x >>= 7;
        if (x == 0) {
            buf[i] = b;
            return buf[0 .. i + 1];
        }
        buf[i] = b | 0x80;
        i += 1;
    }
}
