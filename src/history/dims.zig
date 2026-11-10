//! Dimension keys of a checkpoint's transactions and events, exactly as sui-inverted-index 1.83.1
//! `for_each_transaction_dimension` / `for_each_event_dimension` produce them (dimensions.rs), with
//! the object set of `Checkpoint::from(CheckpointData)` (every input and output object of every
//! transaction, keyed by (id, version)). Keys are `[tag][value]` (`encode_dimension_key`).
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");

pub const Dim = enum(u8) {
    sender = 1,
    affected_address = 2,
    affected_object = 3,
    move_call = 4,
    emit_module = 5,
    event_type = 6,
    event_stream_head = 7,
    event_extant = 8,
    tx_universe = 9,
    any_package_write = 10,
};

/// Receives every candidate key. `ev` is null for tx-space keys. Duplicates are possible (the
/// caller's bitmap insert deduplicates, as RoaringBitmap::insert does).
pub const Sink = struct {
    ctx: *anyopaque,
    emit: *const fn (ctx: *anyopaque, tx_off: u32, ev: ?u32, key: []const u8) Allocator.Error!void,
};

const ObjKey = struct { id: [32]u8, version: u64 };

fn objectKey(o: *const types.Object) ?ObjKey {
    return switch (o.data) {
        .Move => |m| if (m.contents.len >= 32) .{ .id = m.contents[0..32].*, .version = m.version.@"0" } else null,
        .Package => |p| .{ .id = p.id.@"0".@"0", .version = p.version.@"0" },
    };
}

fn ownerAddress(owner: *const types.Owner) ?*const [32]u8 {
    return switch (owner.*) {
        .AddressOwner => |*a| &a.@"0",
        .ConsensusAddressOwner => |*c| &c.owner.@"0",
        else => null,
    };
}

const framework = blk: {
    var a: [32]u8 = @splat(0);
    a[31] = 2;
    break :blk a;
};

fn isStruct(ty: *const types.TypeTag, module: []const u8, name: []const u8) ?*const types.StructTag {
    switch (ty.*) {
        .@"struct" => |*s| {
            if (!std.mem.eql(u8, &s.address.@"0", &framework)) return null;
            if (!std.mem.eql(u8, s.module.@"0", module) or !std.mem.eql(u8, s.name.@"0", name)) return null;
            return s;
        },
        else => return null,
    }
}

const Emitter = struct {
    sink: Sink,
    buf: std.ArrayList(u8) = .empty,
    gpa: Allocator,

    fn key(e: *Emitter, tx_off: u32, ev: ?u32, dim: Dim, parts: []const []const u8) Allocator.Error!void {
        e.buf.clearRetainingCapacity();
        try e.buf.append(e.gpa, @intFromEnum(dim));
        for (parts) |p| try e.buf.appendSlice(e.gpa, p);
        try e.sink.emit(e.sink.ctx, tx_off, ev, e.buf.items);
    }
};

const sep: []const u8 = &.{0};
const one_zero: []const u8 = &.{0};

/// Event-space dimensions of one transaction. `tx_space` forwards them (minus event_extant) as
/// tx-space keys instead, as `for_each_transaction_dimension` does.
fn eventDims(e: *Emitter, arena: Allocator, tx_off: u32, sender: *const [32]u8, eff: *const types.TransactionEffects, events: ?*const types.TransactionEvents, tx_space: bool) !void {
    const evs: []const types.Event = if (events) |x| x.data else &.{};
    for (evs, 0..) |*ev, i| {
        const idx: u32 = @intCast(i);
        const slot: ?u32 = if (tx_space) null else idx;
        if (!tx_space) try e.key(tx_off, slot, .event_extant, &.{one_zero});
        try e.key(tx_off, slot, .sender, &.{sender});
        const pkg = &ev.package_id.@"0".@"0";
        try e.key(tx_off, slot, .emit_module, &.{pkg});
        try e.key(tx_off, slot, .emit_module, &.{ pkg, ev.transaction_module.@"0" });
        const st = &ev.type_;
        try e.key(tx_off, slot, .event_type, &.{&st.address.@"0"});
        try e.key(tx_off, slot, .event_type, &.{ &st.address.@"0", st.module.@"0" });
        try e.key(tx_off, slot, .event_type, &.{ &st.address.@"0", st.module.@"0", sep, st.name.@"0" });
        if (st.type_args.len != 0) {
            const params = try bcs.encodeAlloc([]const types.TypeTag, arena, &st.type_args);
            try e.key(tx_off, slot, .event_type, &.{ &st.address.@"0", st.module.@"0", sep, st.name.@"0", sep, params });
        }
    }
    switch (eff.*) {
        .V1 => {},
        .V2 => |*v| for (v.changed_objects) |*c| switch (c.@"1".output_state) {
            .AccumulatorWriteV1 => |*w| switch (w.value) {
                .EventDigest => |list| {
                    if (isStruct(&w.address.ty, "accumulator_settlement", "EventStreamHead") == null) continue;
                    for (list) |item| {
                        if (item.@"0" >= evs.len) return error.InvalidValue;
                        try e.key(tx_off, if (tx_space) null else @intCast(item.@"0"), .event_stream_head, &.{&w.address.address.@"0"});
                    }
                },
                else => {},
            },
            else => {},
        },
    }
}

/// Every key of every transaction of `cp`, tx-space and event-space.
pub fn extract(gpa: Allocator, arena: Allocator, cp: *const types.CheckpointData, sink: Sink) !void {
    var objs: std.AutoHashMapUnmanaged(ObjKey, *const types.Owner) = .empty;
    for (cp.transactions) |*t| {
        for (t.input_objects) |*o| if (objectKey(o)) |k| try objs.put(arena, k, &o.owner);
        for (t.output_objects) |*o| if (objectKey(o)) |k| try objs.put(arena, k, &o.owner);
    }
    var pkgs: std.AutoHashMapUnmanaged(ObjKey, void) = .empty;
    for (cp.transactions) |*t| {
        for (t.input_objects) |*o| if (o.data == .Package) try pkgs.put(arena, objectKey(o).?, {});
        for (t.output_objects) |*o| if (o.data == .Package) try pkgs.put(arena, objectKey(o).?, {});
    }
    var e: Emitter = .{ .sink = sink, .gpa = gpa };
    defer e.buf.deinit(gpa);

    for (cp.transactions, 0..) |*t, i| {
        const off: u32 = @intCast(i);
        const td = &t.transaction.data.@"0".element().intent_message.value.V1;
        const sender = &td.sender.@"0";
        try e.key(off, null, .sender, &.{sender});

        const Change = struct { id: [32]u8, in: ?u64, out: ?u64 };
        var changes: std.ArrayList(Change) = .empty;
        switch (t.effects) {
            .V2 => |*v| for (v.changed_objects) |*c| {
                const id = c.@"0".@"0".@"0";
                const out: ?u64 = switch (c.@"1".output_state) {
                    .NotExist => null,
                    .ObjectWrite => v.lamport_version.@"0",
                    .PackageWrite => |p| p.@"0".@"0",
                    .AccumulatorWriteV1 => continue,
                };
                const in: ?u64 = switch (c.@"1".input_state) {
                    .NotExist => null,
                    .Exist => |x| x.@"0".@"0".@"0",
                };
                try changes.append(arena, .{ .id = id, .in = in, .out = out });
            },
            .V1 => |*v| {
                const modifiedAt = struct {
                    fn get(m: anytype, id: *const [32]u8) ?u64 {
                        for (m) |x| if (std.mem.eql(u8, &x.@"0".@"0".@"0", id)) return x.@"1".@"0";
                        return null;
                    }
                }.get;
                for (v.created) |x| try changes.append(arena, .{ .id = x.@"0".@"0".@"0".@"0", .in = null, .out = x.@"0".@"1".@"0" });
                for (v.mutated) |x| try changes.append(arena, .{ .id = x.@"0".@"0".@"0".@"0", .in = modifiedAt(v.modified_at_versions, &x.@"0".@"0".@"0".@"0"), .out = x.@"0".@"1".@"0" });
                for (v.unwrapped) |x| try changes.append(arena, .{ .id = x.@"0".@"0".@"0".@"0", .in = null, .out = x.@"0".@"1".@"0" });
                for (v.deleted) |x| try changes.append(arena, .{ .id = x.@"0".@"0".@"0", .in = modifiedAt(v.modified_at_versions, &x.@"0".@"0".@"0"), .out = null });
                for (v.unwrapped_then_deleted) |x| try changes.append(arena, .{ .id = x.@"0".@"0".@"0", .in = null, .out = null });
                for (v.wrapped) |x| try changes.append(arena, .{ .id = x.@"0".@"0".@"0", .in = modifiedAt(v.modified_at_versions, &x.@"0".@"0".@"0"), .out = null });
            },
        }
        for (changes.items) |*c| {
            for ([2]?u64{ c.in, c.out }) |ver| if (ver) |vv| {
                if (objs.get(.{ .id = c.id, .version = vv })) |owner| {
                    if (ownerAddress(owner)) |a| try e.key(off, null, .affected_address, &.{a});
                }
            };
            try e.key(off, null, .affected_object, &.{&c.id});
            if (c.out) |vv| if (pkgs.contains(.{ .id = c.id, .version = vv })) try e.key(off, null, .any_package_write, &.{one_zero});
        }
        switch (td.kind) {
            .ProgrammableTransaction => |*p| for (p.commands) |*cmd| switch (cmd.*) {
                .MoveCall => |*m| {
                    const pkg = &m.package.@"0".@"0";
                    try e.key(off, null, .move_call, &.{pkg});
                    try e.key(off, null, .move_call, &.{ pkg, m.module.@"0" });
                    try e.key(off, null, .move_call, &.{ pkg, m.module.@"0", sep, m.function.@"0" });
                },
                else => {},
            },
            else => {},
        }
        const evs: ?*const types.TransactionEvents = if (t.events) |*x| x else null;
        try eventDims(&e, arena, off, sender, &t.effects, evs, true);
        switch (t.effects) {
            .V1 => {},
            .V2 => |*v| for (v.changed_objects) |*c| switch (c.@"1".output_state) {
                .AccumulatorWriteV1 => |*w| if (w.value == .Integer) {
                    if (isStruct(&w.address.ty, "balance", "Balance")) |s| if (s.type_args.len == 1)
                        try e.key(off, null, .affected_address, &.{&w.address.address.@"0"});
                },
                else => {},
            },
        }
        try eventDims(&e, arena, off, sender, &t.effects, evs, false);
    }
}
