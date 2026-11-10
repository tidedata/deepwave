//! Serve under prune: GetPackage, GetObject, GetCheckpoint and GetTransaction from several
//! threads while a writer commits epochs and prunes everything but the current one, so segment
//! views unmap and decoded chunks are freed under the readers. Real files, the store's
//! use-after-release guard on (store/guard.zig): a response rendered from a slice whose snapshot
//! is gone faults at the read instead of passing on reused memory.
//!
//! Regression for the shadow rig's SIGSEGV in movepkg.writePackage (train/4): the package cache
//! kept Packages that borrowed the object bytes from the store; the first prune that swept the
//! package's segment made every later GetPackage read an unmapped view.
//!
//! `ZUI_STRESS_SECS` (default 3) sets the run time; the proof run uses 600+.
const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const service = @import("service.zig");
const loopback = @import("loopback.zig");
const proto = @import("proto.zig");
const b58 = @import("b58.zig");
const meta = @import("h2/meta.zig");
const movepkg = @import("movepkg.zig");
const exec_error = @import("exec_error.zig");

const pkg_raw = [_][]const u8{
    @embedFile("vectors/clever/pkg-54f7d3ba.bcs"),
    @embedFile("vectors/clever/pkg-d3a9ec94.bcs"),
};
/// clever_error cases of the two packages (exec_error.zig's vectors/clever test): what
/// writeStatusClever renders for a MoveAbort, through the service's package cache.
const clever_cases = [_]struct { module: []const u8, code: u64, name: []const u8 }{
    .{ .module = "pool", .code = 13836747978885234704, .name = "EInsufficientRepayment" },
    .{ .module = "play_coin", .code = 13906838417772314644, .name = "EInsufficientEscrowAccount" },
};
const n_filler = 256;
const cps_per_epoch = 24;
const readers = 4;
const max_checkpoints = 400_000;

fn cert(gpa: Allocator, seq: u64, epoch: u64) ![]u8 {
    const summary: types.CheckpointSummary = .{
        .epoch = epoch,
        .sequence_number = seq,
        .network_total_transactions = seq,
        .content_digest = .{ .@"0" = .{ .@"0" = @splat(0) } },
        .previous_digest = null,
        .epoch_rolling_gas_cost_summary = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .timestamp_ms = 1_700_000_000_000 + seq,
        .checkpoint_commitments = &.{},
        .end_of_epoch_data = null,
        .version_specific_data = &.{},
    };
    const empty_bitmap = [_]u8{ 0x3a, 0x30, 0, 0, 0, 0, 0, 0 };
    const sig: types.AuthorityQuorumSignInfo = .{ .epoch = epoch, .signature = @splat(0), .signers_map = .{ .@"0" = &empty_bitmap } };
    const a = try bcs.encodeAlloc(types.CheckpointSummary, gpa, &summary);
    defer gpa.free(a);
    const b = try bcs.encodeAlloc(types.AuthorityQuorumSignInfo, gpa, &sig);
    defer gpa.free(b);
    return std.mem.concat(gpa, u8, &.{ a, b });
}

fn txDigest(seq: u64) [32]u8 {
    var d: [32]u8 = @splat(0x5a);
    std.mem.writeInt(u64, d[0..8], seq, .little);
    return d;
}

fn fillerId(i: u64) [32]u8 {
    var d: [32]u8 = @splat(0xf1);
    std.mem.writeInt(u64, d[24..32], i, .big);
    return d;
}

const Shared = struct {
    handler: @import("h2/root.zig").Handler,
    st: *store.Store,
    svc: *service.Service,
    pkg_ids: [pkg_raw.len][66]u8,
    pkg_bin: [pkg_raw.len][32]u8 = undefined,
    /// A module, a datatype and a function of each package, for GetDatatype / GetFunction.
    member: [pkg_raw.len]struct { module: []const u8, datatype: []const u8, function: []const u8 } = undefined,
    /// First GetPackage response of each package (the cache's, once warm): every later one must
    /// equal it byte for byte.
    pkg_first: [pkg_raw.len]?[]u8 = @splat(null),
    first_lock: store.cache.Spin = .{},
    done: std.atomic.Value(bool) = .init(false),
    requests: std.atomic.Value(u64) = .init(0),
    failures: std.atomic.Value(u64) = .init(0),
    pruned: std.atomic.Value(u64) = .init(0),
    gpa: Allocator,

    fn fail(sh: *Shared, comptime fmt: []const u8, args: anytype) void {
        if (sh.failures.fetchAdd(1, .monotonic) < 8) std.debug.print("stress_uaf: " ++ fmt ++ "\n", args);
    }
};

fn reader(sh: *Shared, idx: usize) void {
    var arena_state = std.heap.ArenaAllocator.init(sh.gpa);
    defer arena_state.deinit();
    var rng = std.Random.DefaultPrng.init(0x5eed + idx);
    const r = rng.random();
    var buf: [256]u8 = undefined;
    // the packages arrive with checkpoint 0
    while (sh.st.committed() == null and !sh.done.load(.acquire)) std.Thread.yield() catch {};
    while (!sh.done.load(.acquire)) {
        _ = arena_state.reset(.retain_capacity);
        const arena = arena_state.allocator();
        var w = proto.Writer.init(&buf);
        const pi = r.uintLessThan(usize, pkg_raw.len);
        const pick = r.uintLessThan(u8, 7);
        if (pick == 6) {
            // MoveAbort clever_error: CleverResolver.module (cache hit or insert) + resolveClever,
            // as writeStatusClever does (exec_error.zig) after the lookup's snapshot is gone.
            const cr = service.cleverResolver(sh.svc);
            const cc = clever_cases[pi];
            const cm = cr.module(cr.ctx, arena, &sh.pkg_bin[pi], cc.module) orelse {
                sh.fail("clever {s}::{s}: module not resolved", .{ &sh.pkg_ids[pi], cc.module });
                continue;
            };
            const got = exec_error.resolveClever(arena, cm, cc.code) catch null;
            if (got == null or got.?.constant_name == null or !std.mem.eql(u8, got.?.constant_name.?, cc.name))
                sh.fail("clever {s}::{s}: wrong constant", .{ &sh.pkg_ids[pi], cc.module });
            _ = sh.requests.fetchAdd(1, .monotonic);
            continue;
        }
        const path = switch (pick) {
            0 => blk: {
                w.string(1, &sh.pkg_ids[pi]) catch unreachable;
                break :blk "/sui.rpc.v2.MovePackageService/GetPackage";
            },
            1 => blk: {
                w.string(1, &sh.pkg_ids[pi]) catch unreachable;
                const m = w.begin(3, 32) catch unreachable;
                for ([_][]const u8{ "object_id", "version", "digest", "bcs" }) |f| w.string(1, f) catch unreachable;
                w.end(m) catch unreachable;
                break :blk "/sui.rpc.v2.LedgerService/GetObject";
            },
            2 => blk: {
                const hi = sh.st.committed() orelse 0;
                w.uint(1, hi -| r.uintLessThan(u64, 2 * cps_per_epoch)) catch unreachable;
                const m = w.begin(3, 32) catch unreachable;
                for ([_][]const u8{ "sequence_number", "digest", "summary", "signature", "contents" }) |f| w.string(1, f) catch unreachable;
                w.end(m) catch unreachable;
                break :blk "/sui.rpc.v2.LedgerService/GetCheckpoint";
            },
            4, 5 => blk: {
                const mb = sh.member[pi];
                w.string(1, &sh.pkg_ids[pi]) catch unreachable;
                w.string(2, mb.module) catch unreachable;
                w.string(3, if (pick == 4) mb.datatype else mb.function) catch unreachable;
                break :blk if (pick == 4) "/sui.rpc.v2.MovePackageService/GetDatatype" else "/sui.rpc.v2.MovePackageService/GetFunction";
            },
            else => blk: {
                const hi = sh.st.committed() orelse 0;
                var out: [b58.max_len_32]u8 = undefined;
                w.string(1, b58.encode32(&out, &txDigest(hi -| r.uintLessThan(u64, 2 * cps_per_epoch)))) catch unreachable;
                break :blk "/sui.rpc.v2.LedgerService/GetTransaction";
            },
        };
        const reply = loopback.unary(arena, sh.handler, path, w.bytesWritten()) catch |e| {
            sh.fail("{s}: {s}", .{ path, @errorName(e) });
            continue;
        };
        _ = sh.requests.fetchAdd(1, .monotonic);
        switch (pick) {
            0 => {
                if (reply.status != 0) {
                    sh.fail("GetPackage {s}: status {d} {s}", .{ &sh.pkg_ids[pi], reply.status, reply.grpc_message });
                    continue;
                }
                sh.first_lock.lock();
                defer sh.first_lock.unlock();
                if (sh.pkg_first[pi]) |first| {
                    if (!std.mem.eql(u8, first, reply.message)) sh.fail("GetPackage {s}: response changed", .{&sh.pkg_ids[pi]});
                } else sh.pkg_first[pi] = sh.gpa.dupe(u8, reply.message) catch null;
            },
            4, 5 => if (reply.status != 0)
                sh.fail("{s} {s}: status {d} {s}", .{ path, &sh.pkg_ids[pi], reply.status, reply.grpc_message }),
            1 => if (reply.status != 0 or std.mem.indexOf(u8, reply.message, pkg_raw[pi]) == null)
                sh.fail("GetObject {s}: status {d} {s}, bcs present {}", .{ &sh.pkg_ids[pi], reply.status, reply.grpc_message, std.mem.indexOf(u8, reply.message, pkg_raw[pi]) != null }),
            // pruned or not yet written: NOT_FOUND (5); a render of a stored one: OK. Junk
            // transaction bytes render INTERNAL (13). Anything else is a fault.
            else => if (reply.status != 0 and reply.status != 5 and reply.status != 13)
                sh.fail("{s}: status {d} {s}", .{ path, reply.status, reply.grpc_message }),
        }
    }
}

fn writer(sh: *Shared, secs: u64) !void {
    const gpa = sh.gpa;
    const st = sh.st;
    const t_end = meta.unixS() + secs;
    var seq: u64 = 0;
    var epoch: u64 = 0;
    var filler_ver: [n_filler]u64 = @splat(1);
    var junk: [512]u8 = undefined;
    while (meta.unixS() < t_end and seq < max_checkpoints) : (epoch += 1) {
        var k: u64 = 0;
        while (k < cps_per_epoch) : ({
            k += 1;
            seq += 1;
        }) {
            // Pace on the readers: a few requests per commit.
            const want = sh.requests.load(.monotonic) + 4;
            while (seq > 0 and sh.requests.load(.monotonic) < want and sh.failures.load(.monotonic) == 0) std.Thread.yield() catch {};
            const b = try st.begin(seq, epoch);
            const c = try cert(gpa, seq, epoch);
            defer gpa.free(c);
            try b.checkpoint(c, &.{ 0, 0, 0 });
            if (seq == 0) for (pkg_raw) |raw| {
                var arena_state = std.heap.ArenaAllocator.init(gpa);
                defer arena_state.deinit();
                const obj = try bcs.decode(types.Object, arena_state.allocator(), raw);
                const p = obj.data.Package;
                // distinct per package: the package cache is keyed by object digest
                var dg: [32]u8 = p.id.@"0".@"0";
                dg[31] ^= 0xd0;
                try b.putObject(&p.id.@"0".@"0", p.version.@"0", &dg, raw);
            };
            @memset(&junk, @truncate(seq));
            const td = txDigest(seq);
            try b.transaction(&td, &td, junk[0..64], junk[0..96], null);
            for (0..8) |j| {
                const i = (seq * 8 + j) % n_filler;
                const id = fillerId(i);
                filler_ver[i] += 1;
                var dg: [32]u8 = @splat(0xe0);
                std.mem.writeInt(u64, dg[0..8], filler_ver[i], .little);
                try b.putObject(&id, filler_ver[i], &dg, junk[0 .. 128 + (seq % 256)]);
            }
            try st.commit(b);
        }
        // retention 0: every segment but the current one goes, its live objects swept forward
        if (epoch > 0) {
            _ = try st.pruneBefore(epoch);
            _ = sh.pruned.fetchAdd(1, .monotonic);
        }
    }
}

test "serve under prune: packages, objects, checkpoints, transactions while segments unmap" {
    const gpa = testing.allocator;
    const io = testing.io;
    const secs: u64 = if (std.c.getenv("ZUI_STRESS_SECS")) |v| std.fmt.parseInt(u64, std.mem.span(v), 10) catch 3 else 3;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    const rio = try store.io.RealIo.init(gpa, io, path_buf[0..n], .{ .sync = .none });
    defer rio.deinit();
    const cfg: store.Config = .{
        .max_live_objects = 4096,
        .max_object_versions = 1 << 22,
        .max_transactions = 1 << 20,
        .max_checkpoints = 1 << 20,
        .max_batch_bytes = 4 << 20,
        .max_batch_objects = 256,
        .max_segments = 64,
        .index_flush_interval = 64,
        .segment_reserve = 64 << 20,
        .background_flush = false,
        .cache_bytes = 1 << 20,
        .age_lag_checkpoints = 8,
        .seed = 9,
        .uaf_guard = true,
    };
    const st = try store.Store.open(gpa, .{ .real = rio }, &cfg);
    defer st.deinit();
    try testing.expect(st.uafGuard());
    var svc: service.Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0) };
    defer svc.deinit();
    var sh: Shared = .{ .handler = svc.handler(), .st = st, .svc = &svc, .pkg_ids = undefined, .gpa = gpa };
    var names_arena = std.heap.ArenaAllocator.init(gpa);
    defer names_arena.deinit();
    for (pkg_raw, 0..) |raw, i| {
        var pkg: movepkg.Package = undefined;
        try movepkg.read(names_arena.allocator(), raw, &pkg);
        sh.pkg_bin[i] = pkg.id;
        const md = for (pkg.mods) |m| (if (m.structs.len > 0 and m.funcs.len > 0) break m) else unreachable;
        sh.member[i] = .{ .module = md.name, .datatype = md.structs[0].name, .function = md.funcs[0].name };
    }
    defer for (sh.pkg_first) |f| if (f) |b| gpa.free(b);
    for (pkg_raw, 0..) |raw, i| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const obj = try bcs.decode(types.Object, arena_state.allocator(), raw);
        const id = &obj.data.Package.id.@"0".@"0";
        sh.pkg_ids[i][0..2].* = "0x".*;
        for (id, 0..) |byte, j| {
            sh.pkg_ids[i][2 + 2 * j] = "0123456789abcdef"[byte >> 4];
            sh.pkg_ids[i][3 + 2 * j] = "0123456789abcdef"[byte & 15];
        }
    }
    var threads: [readers]std.Thread = undefined;
    for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, reader, .{ &sh, i });
    const res = writer(&sh, secs);
    sh.done.store(true, .release);
    for (threads) |t| t.join();
    try res;
    std.debug.print("stress_uaf: {d}s, {d} requests, {d} prunes, {d} failures\n", .{ secs, sh.requests.load(.monotonic), sh.pruned.load(.monotonic), sh.failures.load(.monotonic) });
    try testing.expectEqual(@as(u64, 0), sh.failures.load(.monotonic));
    try testing.expect(sh.pruned.load(.monotonic) > 0);
    for (sh.pkg_first) |f| try testing.expect(f != null);
}
