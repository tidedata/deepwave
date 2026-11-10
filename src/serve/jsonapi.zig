//! Render API for other lanes (indexes: ListDynamicFields / ListOwnedObjects nested objects;
//! ledger and stream: ListEvents, SubscribeCheckpoints event json). Everything sui-node renders
//! as `json` or `display` goes through here, so every endpoint stays byte-equal to 1.83.1.
//!
//! Usage, one per request (all allocations in the request arena):
//!
//!     var src: service.ObjSource = .{ .snap = snap };             // or any PackageSource
//!     const ctx = try jsonapi.objectCtx(arena, src.packages(), .{});
//!     try jsonapi.writeObject(arena, w, 4, field_object_mask, raw_bcs_object, ctx);   // field_object
//!     try jsonapi.writeEvent(arena, w, 1, event_mask, event, ctx);                      // ListEvents item
//!
//! - `objectCtx(.{ .display = true })` renders `display` too (sui-node renders it wherever an
//!   `Object` message is built with the `display` path in the mask).
//! - `budget`: null gives each value sui-node's `max_json_move_value_size` (1 MiB); a shared
//!   counter (`render_json.default_response_budget`, 16 MiB) is what GetCheckpoint and the
//!   checkpoint streams use across all events of one response. Reset it on a retry.
//! - The package source is consulted for packages (layouts) and, for `display`, for live
//!   Display objects and the dynamic fields templates load.
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types");
const proto = @import("proto.zig");
const mask = @import("mask.zig");
const movelayout = @import("movelayout.zig");
const pbvalue = @import("pbvalue.zig");
const render_object = @import("render_object.zig");
const render_tx = @import("render_tx.zig");
const render_json = @import("render_json.zig");
const objdisplay = @import("objdisplay.zig");

pub const Ctx = render_object.Ctx;
pub const PackageSource = movelayout.PackageSource;
pub const Value = pbvalue.Value;
pub const default_value_budget = render_json.default_value_budget;
pub const default_response_budget = render_json.default_response_budget;

pub const Options = struct {
    /// Render `display` when the mask asks for it.
    display: bool = true,
    /// Shared json budget (see the file comment); null: a fresh 1 MiB per value.
    budget: ?*usize = null,
};

/// The render context for one request over `src`.
pub fn objectCtx(arena: Allocator, src: PackageSource, opts: Options) Allocator.Error!*const Ctx {
    const res = try arena.create(movelayout.Resolver);
    res.* = movelayout.Resolver.init(arena, src);
    const c = try arena.create(Ctx);
    c.* = .{
        .resolver = res,
        .json_budget = opts.budget,
        .display = if (opts.display) try objdisplay.Hook.create(arena, src) else null,
    };
    return c;
}

/// An `Object` message as field `field` from BCS(Object) under mask `m` (`json`, `display`
/// included): ListDynamicFields `field_object` / `child_object`, ListOwnedObjects items.
pub fn writeObject(arena: Allocator, w: *proto.Writer, field: u32, m: mask.Mask, raw: []const u8, ctx: *const Ctx) render_object.Error!void {
    const mm = try w.begin(field, raw.len + 128);
    try render_object.writeObjectCtx(arena, w, m, raw, ctx);
    try w.end(mm);
}

/// One `Event` message as field `field` (ListEvents, streams).
pub fn writeEvent(arena: Allocator, w: *proto.Writer, field: u32, m: mask.Mask, e: types.Event, ctx: *const Ctx) render_object.Error!void {
    return render_tx.writeEventCtx(arena, w, field, m, e, ctx);
}

/// `TransactionEvents` as field `field` (`bcs`, `digest`, `events.*` with json).
pub fn writeEvents(arena: Allocator, w: *proto.Writer, field: u32, m: mask.Mask, raw: []const u8, ev: types.TransactionEvents, ctx: *const Ctx) render_object.Error!void {
    return render_tx.writeEventsCtx(arena, w, field, m, raw, ev, null, ctx);
}

/// The json `Value` of a Move value of struct type `tag` (null where sui-node leaves `json` out).
pub fn moveJson(arena: Allocator, ctx: *const Ctx, tag: *const types.StructTag, contents: []const u8) Allocator.Error!?Value {
    return ctx.json(arena, tag, contents);
}

/// The json of any Move type (e.g. a dynamic field's `name` or `value` of a primitive type).
pub fn typeJson(arena: Allocator, ctx: *const Ctx, tag: *const types.TypeTag, bytes: []const u8) Allocator.Error!?Value {
    const l = (try ctx.resolver.typeLayout(tag)) orelse return null;
    var fresh: usize = render_json.default_value_budget;
    return render_json.render(arena, &l, bytes, ctx.json_budget orelse &fresh);
}

/// Writes `v` as a `google.protobuf.Value` field.
pub fn writeValue(w: *proto.Writer, field: u32, v: *const Value) proto.Error!void {
    return pbvalue.write(w, field, v);
}

test {
    std.testing.refAllDecls(@This());
}
