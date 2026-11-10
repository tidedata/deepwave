//! LedgerService.GetEpoch, as sui-rpc-api 1.83.1 `ledger_service/get_epoch.rs` answers it:
//! - read_mask validated against `Epoch` (default `epoch,first_checkpoint,last_checkpoint,start,end,
//!   reference_gas_price,protocol_config.protocol_version`);
//! - the current epoch is the live system state's (0x5); `epoch` absent means current;
//! - an epoch other than the current one with no epoch record: NOT_FOUND `Epoch N not found`;
//! - from the system state (live for the current epoch, the start record's otherwise): protocol
//!   config, `start`, `reference_gas_price`, the whole `system_state` (any `system_state.*` path
//!   selects all of it); then from the record: `first_checkpoint`, `last_checkpoint`, `start`/
//!   `reference_gas_price`/`protocol_config` when the state did not set them, `end`;
//! - `committee`: the epoch's committee (from its start state, or the live state for the current
//!   epoch); missing: NOT_FOUND `Committee for epoch N not found`;
//! - an unsupported protocol version: NOT_FOUND `Protocol version N not found`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store");
const protocol = @import("protocol");
const proto = @import("proto.zig");
const mask = @import("mask.zig");
const sysstate = @import("sysstate.zig");
const protocfg = @import("protocfg.zig");
const rpcindex = @import("rpcindex.zig");

pub const default_mask = "epoch,first_checkpoint,last_checkpoint,start,end,reference_gas_price,protocol_config.protocol_version";

pub const Outcome = union(enum) {
    ok: []const u8,
    /// NOT_FOUND with this message.
    not_found: []const u8,
    /// INTERNAL (the live system state is missing or does not decode).
    internal: []const u8,
};

fn writeTimestamp(w: *proto.Writer, field: u32, ms: u64) proto.Error!void {
    const m = try w.begin(field, 12);
    if (ms / 1000 != 0) try w.uint(1, ms / 1000);
    if (ms % 1000 != 0) try w.uint(2, (ms % 1000) * 1_000_000);
    try w.end(m);
}

const Plan = struct {
    epoch: u64,
    state: ?sysstate.State,
    summary: ?sysstate.Summary,
    rec: ?*const rpcindex.Record,
    committee: ?[]const sysstate.Member,
    chain: protocol.Chain,
    release_max: u64,
};

/// The GetEpochResponse for `requested` (null = current) under `m`.
/// `release_max`: render the protocol config as a sui-node of that release (`protocfg.write`),
/// raised to the live protocol version (`protocfg.effectiveRelease`).
pub fn getEpoch(arena: Allocator, snap: *const store.Snapshot, index: ?*rpcindex.Index, chain: protocol.Chain, release_max: u64, requested: ?u64, m: mask.Mask) !Outcome {
    const live = rpcindex.liveState(snap) orelse return .{ .internal = "system state not found" };
    const live_sum = sysstate.summary(live) catch return .{ .internal = "system state does not decode" };
    const e = requested orelse live_sum.epoch;
    // records stay valid while this request holds the index's read token
    const tok: ?u1 = if (index) |x| x.enter() else null;
    defer if (index) |x| x.exit(tok.?);
    const rec: ?*const rpcindex.Record = if (index) |x| x.epoch(e) else null;
    if (e != live_sum.epoch and rec == null) return .{ .not_found = try std.fmt.allocPrint(arena, "Epoch {d} not found", .{e}) };
    const state: ?sysstate.State = if (e == live_sum.epoch) live else if (rec.?.start) |s| s.state else null;
    const sum: ?sysstate.Summary = if (e == live_sum.epoch) live_sum else if (state) |s| try sysstate.summary(s) else null;
    // protocol config availability first: get_epoch.rs builds it before the committee
    const pc_mask = m.subtreeDyn("protocol_config");
    if (pc_mask != null) {
        const pv: ?u64 = if (sum) |s| s.protocol_version else if (rec) |r| (if (r.start) |s| s.protocol_version else null) else null;
        if (pv) |v| _ = protocol.get(v, chain) catch return .{ .not_found = try std.fmt.allocPrint(arena, "Protocol version {d} not found", .{v}) };
    }
    // committee: sui-node's `get_committee(epoch)` reads its committee store, independent of the
    // epoch record. deepwave: the record's start state, the live state (current epoch), else the
    // committee the node persisted for the epoch (`Index.committees`).
    var committee: ?[]const sysstate.Member = null;
    if (m.containsDyn("committee")) {
        const cs: ?sysstate.State = if (rec) |r| (if (r.start) |s| s.state else null) else null;
        if (cs orelse (if (e == live_sum.epoch) live else null)) |s| committee = try sysstate.committee(arena, s);
        if (committee == null) if (index) |x| {
            committee = x.committeeOf(arena, e);
        };
        if (committee == null) return .{ .not_found = try std.fmt.allocPrint(arena, "Committee for epoch {d} not found", .{e}) };
    }
    // the release rendered: at least the one the chain's current protocol needs (protocfg.effectiveRelease)
    const rel = protocfg.effectiveRelease(release_max, live_sum.protocol_version);
    const plan: Plan = .{ .epoch = e, .state = state, .summary = sum, .rec = rec, .committee = committee, .chain = chain, .release_max = rel };
    var cap: usize = if (m.containsDyn("system_state")) state_hint(state) else 4096;
    if (pc_mask != null) cap += 64 * 1024;
    while (true) : (cap *= 2) {
        const buf = try arena.alloc(u8, cap);
        var w = proto.Writer.init(buf);
        render(arena, &w, &plan, m, pc_mask) catch |err| switch (err) {
            error.NoSpace => continue,
            else => return err,
        };
        return .{ .ok = w.bytesWritten() };
    }
}

fn state_hint(s: ?sysstate.State) usize {
    return if (s) |x| x.inner.len * 2 + 4096 else 4096;
}

fn render(arena: Allocator, w: *proto.Writer, p: *const Plan, m: mask.Mask, pc_mask: ?mask.Mask) !void {
    const outer = try w.begin(1, 1024);
    if (m.containsDyn("epoch")) try w.uint(1, p.epoch);
    if (p.committee) |c| {
        const cm = try w.begin(2, c.len * 110 + 8);
        try sysstate.writeCommittee(w, p.epoch, c);
        try w.end(cm);
    }
    if (m.containsDyn("system_state")) if (p.state) |s| {
        const sm = try w.begin(3, s.inner.len * 2);
        try sysstate.writeSystemState(arena, w, s);
        try w.end(sm);
    };
    const start_rec: ?rpcindex.Start = if (p.rec) |r| r.start else null;
    if (start_rec) |s| {
        if (m.containsDyn("first_checkpoint")) if (s.start_checkpoint) |c| try w.uint(4, c);
    }
    if (p.rec) |r| if (r.end) |en| if (m.containsDyn("last_checkpoint")) try w.uint(5, en.end_checkpoint);
    if (m.containsDyn("start")) {
        if (p.summary) |s| try writeTimestamp(w, 6, s.epoch_start_timestamp_ms) else if (start_rec) |s| try writeTimestamp(w, 6, s.start_timestamp_ms);
    }
    if (m.containsDyn("end")) if (p.rec) |r| if (r.end) |en| try writeTimestamp(w, 7, en.end_timestamp_ms);
    if (m.containsDyn("reference_gas_price")) {
        if (p.summary) |s| try w.uint(8, s.reference_gas_price) else if (start_rec) |s| try w.uint(8, s.reference_gas_price);
    }
    if (pc_mask) |pm| {
        const pv: ?u64 = if (p.summary) |s| s.protocol_version else if (start_rec) |s| s.protocol_version else null;
        if (pv) |v| {
            const cfg = protocol.get(v, p.chain) catch unreachable; // checked before rendering
            const pcm = try w.begin(9, 64 * 1024);
            try protocfg.write(arena, w, cfg, pm, p.release_max);
            try w.end(pcm);
        }
    }
    try w.end(outer);
}
