//! Comparison of deepwave against the Rust vectors of tools/truth/validator-epoch (`deepwave-validator
//! vectors-check DIR`): protocol config digests feed the capability votes, the end-of-epoch system
//! transactions, the consensus transactions of the epoch lifecycle and the Validator API request
//! bodies must match Mysten's bytes. Each case prints `ok <suite> <name>` or `FAIL ...`.
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const keys = @import("../keys/root.zig");
const endofepoch = @import("endofepoch.zig");
const capabilities = @import("capabilities.zig");
const announce = @import("announce.zig");
const wire = @import("../api/wire.zig");

pub const Report = struct { ok: u32 = 0, failed: u32 = 0, missing: u32 = 0 };

const Line = struct {
    name: []const u8,
    sender_signed_data: ?[]const u8 = null,
    digest: ?[]const u8 = null,
    bcs: ?[]const u8 = null,
};

fn unhexAlloc(arena: std.mem.Allocator, h: []const u8) ![]u8 {
    if (h.len % 2 != 0) return error.BadHex;
    const out = try arena.alloc(u8, h.len / 2);
    _ = std.fmt.hexToBytes(out, h) catch return error.BadHex;
    return out;
}

fn readLines(arena: std.mem.Allocator, io: Io, dir: []const u8, name: []const u8) !?[]Line {
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&pb, "{s}/{s}", .{ dir, name });
    const data = (try keys.fsutil.readAll(arena, io, path, 64 << 20)) orelse return null;
    var out: std.ArrayList(Line) = .empty;
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |l| {
        if (std.mem.trim(u8, l, " \r").len == 0) continue;
        const v = try std.json.parseFromSliceLeaky(Line, arena, l, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
        try out.append(arena, v);
    }
    return out.items;
}

fn note(r: *Report, suite: []const u8, name: []const u8, good: bool) void {
    if (good) {
        r.ok += 1;
        std.debug.print("ok {s} {s}\n", .{ suite, name });
    } else {
        r.failed += 1;
        std.debug.print("FAIL {s} {s}\n", .{ suite, name });
    }
}

fn find(lines: []const Line, name: []const u8) ?Line {
    for (lines) |l| if (std.mem.eql(u8, l.name, name)) return l;
    return null;
}

fn seq(v: u64) types.SequenceNumber {
    return .{ .@"0" = v };
}

pub fn check(gpa: std.mem.Allocator, io: Io, dir: []const u8) !Report {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var r: Report = .{};

    // ---- system transactions
    if (try readLines(arena, io, dir, "sys-tx.jsonl")) |lines| {
        const basic = [_]types.EndOfEpochTransactionKind{
            .{ .AuthenticatorStateExpire = .{ .min_epoch = 100, .authenticator_obj_initial_shared_version = seq(7) } },
            .{ .RandomnessStateCreate = {} },
            .{ .DenyListStateCreate = {} },
            .{ .AccumulatorRootCreate = {} },
            .{ .CoinRegistryCreate = {} },
            .{ .DisplayRegistryCreate = {} },
            .{ .AddressAliasStateCreate = {} },
            .{ .ChangeEpoch = .{ .epoch = 801, .protocol_version = .{ .@"0" = 141 }, .storage_charge = 6, .computation_charge = 5, .storage_rebate = 7, .non_refundable_storage_fee = 8, .epoch_start_timestamp_ms = 1_700_000_000_000, .system_packages = &.{} } },
        };
        const b1 = try endofepoch.finish(arena, .{ .EndOfEpochTransaction = &basic }, &basic);
        const legacy_kind: types.TransactionKind = .{ .ChangeEpoch = .{ .epoch = 801, .protocol_version = .{ .@"0" = 5 }, .storage_charge = 2, .computation_charge = 1, .storage_rebate = 3, .non_refundable_storage_fee = 4, .epoch_start_timestamp_ms = 99, .system_packages = &.{} } };
        const b2 = try endofepoch.finish(arena, legacy_kind, &.{});
        const cases = [_]struct { []const u8, endofepoch.Built }{ .{ "eoe-basic", b1 }, .{ "change-epoch-legacy", b2 } };
        for (cases) |c| {
            const want = find(lines, c[0]) orelse {
                r.missing += 1;
                std.debug.print("MISSING sys-tx {s}\n", .{c[0]});
                continue;
            };
            const bytes = try unhexAlloc(arena, want.sender_signed_data orelse "");
            const dig = try unhexAlloc(arena, want.digest orelse "");
            note(&r, "sys-tx", c[0], std.mem.eql(u8, bytes, c[1].sender_signed_bcs) and std.mem.eql(u8, dig, &c[1].digest));
        }
    } else r.missing += 1;

    // ---- protocol digests, then capabilities and consensus transactions
    var table: ?capabilities.DigestTable = null;
    defer if (table) |*t| t.deinit();
    {
        var pb: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&pb, "{s}/protocol-digests.txt", .{dir});
        if (try keys.fsutil.readAll(arena, io, path, 16 << 20)) |text| table = try capabilities.DigestTable.parse(gpa, text);
    }
    if (try readLines(arena, io, dir, "consensus-tx.jsonl")) |lines| {
        if (find(lines, "eop")) |w| {
            const mine = try announce.encodeEndOfPublish(arena, @splat(2), @splat(7));
            note(&r, "consensus-tx", "eop", std.mem.eql(u8, try unhexAlloc(arena, w.bcs orelse ""), mine));
        } else r.missing += 1;
        if (find(lines, "caps")) |w| {
            const caps = try capabilities.buildCapabilities(arena, if (table) |*t| t else null, .unknown, @splat(7), 5000, 139, 141, &.{});
            const mine = try announce.encodeCapabilities(arena, @splat(1), caps);
            note(&r, "consensus-tx", "caps", table != null and std.mem.eql(u8, try unhexAlloc(arena, w.bcs orelse ""), mine));
        } else r.missing += 1;
    } else r.missing += 1;

    // ---- Validator API request bodies
    if (try readLines(arena, io, dir, "grpc-req.jsonl")) |lines| {
        for (lines) |l| {
            const b = try unhexAlloc(arena, l.bcs orelse "");
            var good = false;
            if (std.mem.eql(u8, l.name, "object-info-latest")) {
                const q = wire.decodeObjectInfoRequest(b) catch null;
                good = q != null and q.?.object_id[0] == 1 and !q.?.generate_layout and q.?.version == null;
            } else if (std.mem.eql(u8, l.name, "object-info-past")) {
                const q = wire.decodeObjectInfoRequest(b) catch null;
                good = q != null and q.?.generate_layout and q.?.version != null and q.?.version.? == 9;
            } else if (std.mem.eql(u8, l.name, "tx-info")) {
                const d = wire.decodeTransactionInfoRequest(b) catch null;
                good = d != null and d.?[0] == 7;
            } else if (std.mem.eql(u8, l.name, "checkpoint")) {
                const q = wire.decodeCheckpointRequest(b, false) catch null;
                good = q != null and q.?.sequence_number != null and q.?.sequence_number.? == 5 and q.?.request_content;
            } else if (std.mem.eql(u8, l.name, "checkpoint-v2")) {
                const q = wire.decodeCheckpointRequest(b, true) catch null;
                good = q != null and q.?.sequence_number == null and !q.?.request_content and q.?.certified;
            } else if (std.mem.eql(u8, l.name, "health")) {
                const mine = try wire.healthResponse(arena, .{ .pending_certificates = 0, .inflight_consensus_messages = 3, .consensus_round = 4, .checkpoint_sequence = 5 });
                good = std.mem.eql(u8, mine, b);
            } else continue;
            note(&r, "grpc-req", l.name, good);
        }
    } else r.missing += 1;
    return r;
}
