//! Conformance suite `dkg-vectors` (lane val-randomness-jwk): fastcrypto-tbls transcripts written
//! by tools/truth/randomness (`dkg`) into vectors/dkg/fastcrypto.jsonl, replayed through the Zig
//! `Manager`: the Zig validators consume the Rust validators' messages and confirmations, must
//! reach the same VSS polynomial and the same shares, produce partial signatures byte equal to
//! Rust's, aggregate them to Rust's full signature, and build the same RandomnessStateUpdate
//! transaction bytes and digest.
const std = @import("std");
const harness = @import("harness");
const core = @import("core");
const manager = @import("manager.zig");
const group = @import("group.zig");
const tbls = @import("tbls.zig");
const poly = @import("poly.zig");
const state_update = @import("state_update.zig");
const dkg = @import("dkg.zig");
const wire = @import("wire.zig");
const txs = @import("txs.zig");

pub const suites = [_]harness.Suite{
    .{ .name = "dkg-vectors", .lane = "val-randomness-jwk", .doc = "fastcrypto-tbls DKG transcripts, shares, threshold signatures and the RandomnessStateUpdate transaction vs the Zig Manager", .run = run },
};

const Line = struct {
    op: []const u8,
    id: []const u8 = "",
    party: ?u64 = null,
    bytes: ?[]const u8 = null,
    ctx: ?[]const u8 = null,
    total_weight: ?u16 = null,
    epoch: ?u64 = null,
    chain_id: ?[]const u8 = null,
    sks: ?[]const []const u8 = null,
    names: ?[]const []const u8 = null,
    stakes: ?[]const u64 = null,
    allowed_delta: ?u16 = null,
    lower_bound: ?u16 = null,
    validity: ?u64 = null,
    t: ?u16 = null,
    weights: ?[]const u16 = null,
    vss_pk: ?[]const []const u8 = null,
    shares: ?std.json.Value = null,
    round: ?u64 = null,
    message: ?[]const u8 = null,
    partials: ?[]const []const []const u8 = null,
    sig: ?[]const u8 = null,
    data: ?[]const u8 = null,
    digest: ?[]const u8 = null,
    initial_shared_version: ?u64 = null,
};

const Case = struct {
    id: []const u8,
    epoch: u64,
    chain_id: [32]u8,
    sks: [][32]u8,
    members: []manager.Member,
    params: manager.Params,
    t: u16,
    weights: []const u16,
    messages: std.ArrayList([]const u8) = .empty, // (party, bytes) in file order
    message_parties: std.ArrayList(u16) = .empty,
    confs: std.ArrayList([]const u8) = .empty,
    conf_parties: std.ArrayList(u16) = .empty,
    total_weight: ?u16 = null,
    mgrs: []*manager.Manager = &.{},
    built: bool = false,
};

fn run(ctx: *harness.Ctx) !void {
    const text = try ctx.readFile("vectors/dkg/fastcrypto.jsonl", 256 << 20);
    var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(0x646b67);
    const rng = prng.random();
    var cur: ?Case = null;
    defer if (cur) |*c| for (c.mgrs) |m| m.destroy();
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (ctx.done()) return;
        const v = try std.json.parseFromSliceLeaky(Line, a, line, .{ .ignore_unknown_fields = true });
        try handle(ctx, a, rng, &cur, &v);
    }
}

fn hexAlloc(a: std.mem.Allocator, s: []const u8) ![]u8 {
    return core.hex.decodeAlloc(a, s);
}

fn handle(ctx: *harness.Ctx, a: std.mem.Allocator, rng: std.Random, cur: *?Case, v: *const Line) !void {
    if (std.mem.eql(u8, v.op, "committee")) {
        if (cur.*) |*c| for (c.mgrs) |m| m.destroy();
        const names = v.names.?;
        const sks = try a.alloc([32]u8, names.len);
        const members = try a.alloc(manager.Member, names.len);
        for (names, 0..) |n, i| {
            sks[i] = (try hexAlloc(a, v.sks.?[i]))[0..32].*;
            members[i] = .{ .name = (try hexAlloc(a, n))[0..96].*, .stake = v.stakes.?[i] };
        }
        const cid = (try hexAlloc(a, v.chain_id.?))[0..32].*;
        cur.* = .{
            .id = try a.dupe(u8, v.id),
            .epoch = v.epoch.?,
            .chain_id = cid,
            .sks = sks,
            .members = members,
            .params = .{
                .epoch = v.epoch.?,
                .chain_id = cid,
                .members = members,
                .validity_threshold = v.validity.?,
                .protocol = .{ .random_beacon_reduction_allowed_delta = v.allowed_delta.?, .random_beacon_reduction_lower_bound = v.lower_bound.? },
            },
            .t = v.t.?,
            .weights = v.weights.?,
            .total_weight = v.total_weight,
        };
        return;
    }
    const c = &(cur.* orelse return);
    if (!ctx.selected(c.id)) return;
    if (std.mem.eql(u8, v.op, "message")) {
        const b = try hexAlloc(a, v.bytes.?);
        try c.messages.append(a, b);
        try c.message_parties.append(a, @intCast(v.party.?));
        try checkWire(ctx, a, c, v, b, .message);
    } else if (std.mem.eql(u8, v.op, "confirmation")) {
        const b = try hexAlloc(a, v.bytes.?);
        try c.confs.append(a, b);
        try c.conf_parties.append(a, @intCast(v.party.?));
        try checkWire(ctx, a, c, v, b, .confirmation);
    } else if (std.mem.eql(u8, v.op, "output")) {
        try checkOutput(ctx, a, rng, c, v);
    } else if (std.mem.eql(u8, v.op, "round")) {
        try checkRound(ctx, a, c, v);
    } else if (std.mem.eql(u8, v.op, "rsu")) {
        try checkRsu(ctx, a, c, v);
    }
}

fn checkOutput(ctx: *harness.Ctx, a: std.mem.Allocator, rng: std.Random, c: *Case, v: *const Line) !void {
    const gpa = ctx.gpa;
    var chk = ctx.check(try std.fmt.allocPrint(a, "{s}/output", .{c.id}));
    defer _ = chk.finish();
    const n = c.members.len;
    c.mgrs = try a.alloc(*manager.Manager, n);
    for (0..n) |i| c.mgrs[i] = try manager.Manager.createForTesting(gpa, c.params, &c.sks[i], rng);
    c.built = true;
    chk.eql("threshold", c.t, c.mgrs[0].threshold());
    if (c.total_weight) |tw| chk.eql("total weight", tw, c.mgrs[0].nodes.total_weight);
    for (c.weights, 0..) |w, i| chk.eql("reduced weight", w, c.mgrs[0].nodes.nodes[i].weight);
    for (c.mgrs, 0..) |m, i| {
        for (c.messages.items, c.message_parties.items) |mb, party| {
            m.addMessage(&c.members[party].name, mb) catch |e| {
                chk.failf("party {d} addMessage from {d}: {s}", .{ i, party, @errorName(e) });
                return;
            };
        }
        var b1 = manager.Batch.init(gpa);
        defer b1.deinit();
        var adv = try m.advanceDkg(&b1, 1);
        defer adv.deinit(gpa);
        // every Party submits its Confirmation (zero weight included, as try_merge_messages); with
        // no complaints the bytes are deterministic and must equal Rust's
        if (adv.confirmation_to_submit) |own| {
            for (c.confs.items, c.conf_parties.items) |cb, party| if (party == i) chk.bytes(try std.fmt.allocPrint(a, "party {d} own confirmation", .{i}), cb, own);
        } else chk.failf("party {d}: no confirmation produced", .{i});
        var b2 = manager.Batch.init(gpa);
        defer b2.deinit();
        for (c.confs.items, c.conf_parties.items) |cb, party| try m.addConfirmation(&b2, &c.members[party].name, cb);
        var adv2 = try m.advanceDkg(&b2, 2);
        defer adv2.deinit(gpa);
        if (m.dkgStatus() != .successful) {
            chk.failf("party {d}: DKG did not complete ({s})", .{ i, @tagName(m.dkgStatus()) });
            continue;
        }
        const out = m.output_().?;
        const want_vss = v.vss_pk.?;
        if (out.vss_pk.len != want_vss.len) {
            chk.failf("party {d}: vss_pk length {d}, want {d}", .{ i, out.vss_pk.len, want_vss.len });
            continue;
        }
        for (out.vss_pk, want_vss, 0..) |g, wh, k| {
            const want = try hexAlloc(a, wh);
            chk.bytes(try std.fmt.allocPrint(a, "party {d} vss_pk[{d}]", .{ i, k }), want, &group.g2ToBytes(g));
        }
        // shares
        const want_shares = v.shares.?.array.items[i].array.items;
        const got = out.shares orelse &[_]poly.Share{};
        if (got.len != want_shares.len) {
            chk.failf("party {d}: {d} shares, want {d}", .{ i, got.len, want_shares.len });
            continue;
        }
        for (got, want_shares) |s, ws| {
            const idx: u16 = @intCast(ws.array.items[0].integer);
            chk.eql("share index", idx, s.index);
            chk.bytes("share value", try hexAlloc(a, ws.array.items[1].string), &group.scalarToBytes(s.value));
        }
    }
}

fn checkRound(ctx: *harness.Ctx, a: std.mem.Allocator, c: *Case, v: *const Line) !void {
    if (!c.built) return;
    var chk = ctx.check(try std.fmt.allocPrint(a, "{s}/round {d}", .{ c.id, v.round.? }));
    defer _ = chk.finish();
    const round = v.round.?;
    chk.bytes("signature message", try hexAlloc(a, v.message.?), &tbls.roundMessage(round));
    var all: std.ArrayList(tbls.PartialSignature) = .empty;
    for (c.mgrs, 0..) |m, i| {
        const want = v.partials.?[i];
        const got = m.partialSignatures(a, round) catch |e| {
            if (want.len != 0) chk.failf("party {d}: partialSignatures {s}", .{ i, @errorName(e) });
            continue;
        };
        if (got.len != want.len) {
            chk.failf("party {d}: {d} partials, want {d}", .{ i, got.len, want.len });
            continue;
        }
        for (got, want) |p, wh| {
            chk.bytes(try std.fmt.allocPrint(a, "party {d} partial {d}", .{ i, p.index }), try hexAlloc(a, wh), &p.toBytes());
            try all.append(a, p);
        }
    }
    const sig = tbls.aggregate(a, c.t, all.items) catch |e| {
        chk.failf("aggregate: {s}", .{@errorName(e)});
        return;
    };
    chk.bytes("full signature", try hexAlloc(a, v.sig.?), &group.g1ToBytes(sig));
}

const WireKind = enum { message, confirmation };

/// The Rust BCS of a VersionedDkgMessage / VersionedDkgConfirmation decodes and re-encodes byte
/// for byte, and the ConsensusTransaction deepwave builds around it (tracking id included) equals the
/// one Rust submits.
fn checkWire(ctx: *harness.Ctx, a: std.mem.Allocator, c: *Case, v: *const Line, b: []const u8, kind: WireKind) !void {
    const party: u16 = @intCast(v.party.?);
    var chk = ctx.check(try std.fmt.allocPrint(a, "{s}/{s} {d}", .{ c.id, @tagName(kind), party }));
    defer _ = chk.finish();
    const gpa = ctx.gpa;
    const re = switch (kind) {
        .message => blk: {
            var dm = dkg.decodeVersionedMessage(gpa, b) catch |e| return chk.failf("decode: {s}", .{@errorName(e)});
            switch (dm) {
                .v0 => return chk.failf("decoded as V0", .{}),
                .v1 => |*o| {
                    defer o.deinit();
                    chk.eql("sender", party, o.value.sender);
                    break :blk try dkg.encodeVersionedMessage(gpa, &o.value);
                },
            }
        },
        .confirmation => blk: {
            var dc = dkg.decodeVersionedConfirmation(gpa, b) catch |e| return chk.failf("decode: {s}", .{@errorName(e)});
            switch (dc) {
                .v0 => return chk.failf("decoded as V0", .{}),
                .v1 => |*o| {
                    defer o.deinit();
                    chk.eql("sender", party, o.value.sender);
                    break :blk try dkg.encodeVersionedConfirmation(gpa, &o.value);
                },
            }
        },
    };
    defer gpa.free(re);
    chk.bytes("re-encoded", b, re);
    if (v.ctx) |want_hex| {
        const name = &c.members[party].name;
        const got = switch (kind) {
            .message => try txs.dkgMessageTx(gpa, name, b),
            .confirmation => try txs.dkgConfirmationTx(gpa, name, b),
        };
        defer gpa.free(got);
        chk.bytes("ConsensusTransaction", try hexAlloc(a, want_hex), got);
    }
}

fn checkRsu(ctx: *harness.Ctx, a: std.mem.Allocator, c: *Case, v: *const Line) !void {
    var chk = ctx.check(try std.fmt.allocPrint(a, "{s}/rsu {d}", .{ c.id, v.round.? }));
    defer _ = chk.finish();
    const sig = try hexAlloc(a, v.sig.?);
    var built = try state_update.build(ctx.gpa, v.epoch.?, v.round.?, sig, v.initial_shared_version.?);
    defer built.deinit(ctx.gpa);
    chk.bytes("TransactionData", try hexAlloc(a, v.data.?), built.data);
    chk.bytes("digest", try hexAlloc(a, v.digest.?), &built.digest);
}
