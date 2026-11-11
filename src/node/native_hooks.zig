//! deepwave's zui/1 execution hooks (NATIVE-PROTOCOL.md 4.2): dry_run on the native simulation
//! engine (src/exec/simulate/api.zig, `Rpc.simulator()`), submit_transaction through the node's
//! ExecuteTransaction handler (rpc_exec live node_exec, the same quorum driver and checks as the
//! gRPC path), both on the listener's worker threads.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const store = @import("store");
const serve = @import("serve");
const rpc_exec = @import("rpc_exec");
const simulate = @import("simulate");
const native = @import("native");
const rpc = @import("rpc.zig");
const nproto = native.proto;
const W = nproto.W;
const pb = serve.proto;

pub const Hooks = struct {
    io: Io,
    st: *store.Store,
    rpc: *rpc.Rpc,
    /// node/epochs: the trust walk's committee files (`<epoch>.json` with pv, rgp, start_ms).
    epochs_dir: ?Io.Dir = null,
    /// Last committee file read (I/O thread only: hello and get_epoch_info run there).
    cached: ?native.dispatch.EpochSummary = null,

    pub fn epochFallback(h: *Hooks) ?native.dispatch.EpochFallback {
        if (h.epochs_dir == null) return null;
        return .{ .ctx = h, .get = epochFromFile };
    }

    pub fn simulator(h: *Hooks) native.dispatch.Simulator {
        return .{ .ctx = h, .simulate = dryRun };
    }

    pub fn submitter(h: *Hooks) ?native.dispatch.Submitter {
        if (h.rpc.execute == null) return null;
        return .{ .ctx = h, .submit = submit };
    }
};

fn epochFromFile(ctx: *anyopaque, epoch: u64) ?native.dispatch.EpochSummary {
    const h: *Hooks = @ptrCast(@alignCast(ctx));
    if (h.cached) |c| if (c.epoch == epoch) return c;
    var name: [32]u8 = undefined;
    const file = std.fmt.bufPrint(&name, "{d}.json", .{epoch}) catch return null;
    var buf: [64 << 10]u8 = undefined;
    const text = h.epochs_dir.?.readFile(h.io, file, &buf) catch return null;
    const s = parseCommitteeFile(text, epoch) orelse return null;
    h.cached = s;
    return s;
}

/// `{"epoch":E,"pv":P,"keys":[..],"stakes":[..],"rgp":R,"start_ms":T}`; rgp and start_ms are
/// optional (older walks wrote neither): without rgp the file says nothing useful.
pub fn parseCommitteeFile(text: []const u8, epoch: u64) ?native.dispatch.EpochSummary {
    var fba_buf: [256 << 10]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    const F = struct { epoch: u64, pv: u64 = 0, rgp: ?u64 = null, start_ms: u64 = 0 };
    const v = std.json.parseFromSliceLeaky(F, fba.allocator(), text, .{ .ignore_unknown_fields = true }) catch return null;
    if (v.epoch != epoch) return null;
    return .{ .epoch = v.epoch, .protocol_version = v.pv, .reference_gas_price = v.rgp orelse return null, .epoch_start_timestamp_ms = v.start_ms };
}

test "committee file gives the epoch facts" {
    const s = parseCommitteeFile("{\"epoch\":1304,\"pv\":141,\"keys\":[\"ab\"],\"stakes\":[1],\"rgp\":100,\"start_ms\":1794009944668}", 1304).?;
    try std.testing.expectEqual(@as(u64, 100), s.reference_gas_price);
    try std.testing.expectEqual(@as(u64, 141), s.protocol_version);
    try std.testing.expect(parseCommitteeFile("{\"epoch\":900,\"pv\":95}", 900) == null);
    try std.testing.expect(parseCommitteeFile("{\"epoch\":900,\"rgp\":1}", 901) == null);
}

/// DryRunReq flags 0x01 (checks off) and 0x02 (command results).
fn dryRun(ctx: *anyopaque, a: Allocator, tx_data: []const u8, flags: u8, out: *std.ArrayList(u8)) anyerror!void {
    const h: *Hooks = @ptrCast(@alignCast(ctx));
    const engine = h.rpc.simulator();
    const tip = engine.tip orelse return nproto.errorResponse(out, a, .unavailable, "NoTip", "");
    // Held until the response is written: the Result borrows store bytes through it.
    var snap = tip.store.snapshot();
    defer snap.release();
    const res = engine.simulate(a, &snap, dryRunRequest(tx_data, flags)) catch |e| switch (e) {
        error.NoTip, error.EpochUnavailable => return nproto.errorResponse(out, a, .unavailable, @errorName(e), ""),
        error.OutOfMemory => return e,
        else => return nproto.errorResponse(out, a, .tx_rejected, @errorName(e), ""),
    };
    try writeDryRun(a, res, out);
}

/// The engine request of a DryRunReq: 0x01 runs as dev-inspect, 0x02 tracks per-command results
/// (the same tracked run as gRPC SimulateTransaction's `command_outputs`, with checks on or off).
pub fn dryRunRequest(tx_data: []const u8, flags: u8) simulate.api.Request {
    return .{ .tx = .{ .data = tx_data }, .mode = if (flags & 0x01 != 0) .dev_inspect else .simulate, .results = flags & 0x02 != 0 };
}

/// `DryRunResp` (spec 4.2), or TX_REJECTED when the transaction did not run.
pub fn writeDryRun(a: Allocator, res: simulate.api.Result, out: *std.ArrayList(u8)) !void {
    switch (res) {
        .rejected => |r| return nproto.errorResponse(out, a, .tx_rejected, r.message, ""),
        .executed => |x| {
            try nproto.okHeader(out, a, 0);
            const w: W = .{ .gpa = a, .out = out };
            try w.bytes(x.effects);
            try w.optBytes(x.events);
            try w.uleb(x.written.len);
            for (x.written) |o| try w.bytes(o.bytes);
            switch (x.status) {
                .success => try w.u8_(0),
                .failure => |f| {
                    try w.u8_(1);
                    try w.str(f.message);
                },
            }
            try writeCommandResults(w, x.command_results orelse &.{});
        },
    }
}

/// `results: vector<CommandResult { return_values: vector<bytes>, mutated_refs: vector<bytes> }>`:
/// the BCS of each return value and of each `&mut` argument after the command, in the engine's
/// order (gRPC `command_outputs`' `return_values` and `mutated_by_ref` values).
pub fn writeCommandResults(w: W, results: []const simulate.api.CommandResult) !void {
    try w.uleb(results.len);
    for (results) |r| {
        try w.uleb(r.returns.len);
        for (r.returns) |v| try w.bytes(v.bytes);
        try w.uleb(r.mutated.len);
        for (r.mutated) |v| try w.bytes(v.bytes);
    }
}

/// ExecuteTransactionRequest { transaction { bcs { value } }, signatures [{ bcs { value } }], read_mask }.
fn executeRequest(a: Allocator, data: []const u8, sigs: []const []const u8) ![]const u8 {
    var total: usize = data.len + 512;
    for (sigs) |s| total += s.len + 16;
    const buf = try a.alloc(u8, total);
    var w = pb.Writer.init(buf);
    const t = try w.begin(1, data.len + 16);
    const tb = try w.begin(1, data.len + 8);
    try w.bytes(2, data);
    try w.end(tb);
    try w.end(t);
    for (sigs) |sig| {
        const s = try w.begin(2, sig.len + 8);
        const sb = try w.begin(1, sig.len + 4);
        try w.bytes(2, sig);
        try w.end(sb);
        try w.end(s);
    }
    const m = try w.begin(3, 128);
    for ([_][]const u8{ "digest", "effects", "events", "checkpoint" }) |p| try w.string(1, p);
    try w.end(m);
    return w.bytesWritten();
}

fn field(msg: []const u8, number: u32) ?[]const u8 {
    var r = pb.Reader.init(msg);
    while (r.next() catch return null) |f| if (f.number == number) return pb.Reader.bytesOf(f) catch null;
    return null;
}

fn varintField(msg: []const u8, number: u32) ?u64 {
    var r = pb.Reader.init(msg);
    while (r.next() catch return null) |f| if (f.number == number) return pb.Reader.varintOf(f) catch null;
    return null;
}

fn monoMs(io: Io) u64 {
    return @intCast(@divTrunc(Io.Clock.awake.now(io).toNanoseconds(), std.time.ns_per_ms));
}

fn submit(ctx: *anyopaque, a: Allocator, tx_data: []const u8, sigs: []const []const u8, wait: u8, out: *std.ArrayList(u8)) anyerror!void {
    const h: *Hooks = @ptrCast(@alignCast(ctx));
    const x = h.rpc.execute orelse return nproto.errorResponse(out, a, .unimplemented, "execution is off", "");
    const digest = native.dispatch.txDigest(tx_data);
    const t0 = monoMs(h.io);
    const deadline = t0 + native.dispatch.submit_wait_ms;
    const body = try executeRequest(a, tx_data, sigs);
    const reply = try serve.loopback.unaryTimeout(a, x, rpc_exec.service.prefix ++ "ExecuteTransaction", body, native.dispatch.submit_wait_ms);
    switch (reply.status) {
        0 => {},
        4 => return nproto.errorResponse(out, a, .timeout, "no effects within 30 s", &digest), // DEADLINE_EXCEEDED
        14 => return nproto.errorResponse(out, a, .unavailable, reply.grpc_message, ""),
        12 => return nproto.errorResponse(out, a, .unimplemented, reply.grpc_message, ""),
        else => return nproto.errorResponse(out, a, .tx_rejected, reply.grpc_message, reply.details),
    }
    const txm = field(reply.message, 1) orelse &.{};
    const effects: ?[]const u8 = if (field(txm, 4)) |e| (if (field(e, 1)) |b| field(b, 2) else null) else null;
    const events: ?[]const u8 = if (field(txm, 5)) |e| (if (field(e, 1)) |b| field(b, 2) else null) else null;
    var checkpoint: ?u64 = null;
    if (wait == 2) {
        // until the checkpoint holding the tx is committed locally, within the same 30 s
        while (true) {
            var snap = h.st.snapshot();
            const rec = snap.transaction(&digest);
            const cp = if (rec) |r| r.checkpoint else null;
            const hi = snap.highestCommitted();
            snap.release();
            if (cp) |c| if (hi != null and hi.? >= c) {
                checkpoint = c;
                break;
            };
            if (monoMs(h.io) >= deadline) return nproto.errorResponse(out, a, .timeout, "not checkpointed within 30 s", &digest);
            h.io.sleep(.fromMilliseconds(50), .awake) catch {};
        }
    }
    try nproto.okHeader(out, a, 0);
    const w: W = .{ .gpa = a, .out = out };
    try w.fixed(&digest);
    // wait 0 and 1 both come back after the quorum driver's effects (it has no earlier
    // "accepted" point), so the effects are always there
    try w.optBytes(effects);
    try w.optBytes(events);
    if (checkpoint) |c| {
        try w.u8_(1);
        try w.int(u64, c);
    } else try w.u8_(0);
}

test "ExecuteTransactionRequest carries the data and every signature" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const req = try executeRequest(a, "TXDATA", &.{ "SIG1", "SIG22" });
    try std.testing.expectEqualStrings("TXDATA", field(field(field(req, 1).?, 1).?, 2).?);
    var r = pb.Reader.init(req);
    var sigs: usize = 0;
    while (try r.next()) |f| if (f.number == 2) {
        sigs += 1;
    };
    try std.testing.expectEqual(@as(usize, 2), sigs);
}

/// Decodes a DryRunResp's `results` (after effects, events, objects, error).
fn testDryRunResults(a: Allocator, resp: []const u8) ![]const []const []const u8 {
    var r: nproto.R = .{ .b = resp };
    try std.testing.expectEqual(@as(u8, 0), try r.u8_());
    try std.testing.expectEqual(@as(u64, 0), try r.uleb());
    _ = try r.bytes();
    if (try r.option()) _ = try r.bytes();
    for (0..try r.uleb()) |_| _ = try r.bytes();
    if (try r.option()) _ = try r.str();
    const n = try r.uleb();
    const out = try a.alloc([]const []const u8, n);
    for (out) |*cmd| {
        const nr = try r.uleb();
        const vals = try a.alloc([]const u8, nr);
        for (vals) |*v| v.* = try r.bytes();
        try std.testing.expectEqual(@as(u64, 0), try r.uleb()); // no &mut arguments here
        cmd.* = vals;
    }
    try r.done();
    return out;
}

// zui/1 dry_run returned no per-command results (`results` was always empty), while gRPC
// SimulateTransaction on the same node returned `command_outputs`. With 0x02 they come back, with
// checks on (0x02) and off (0x03); without 0x02 the vector stays empty.
test "dry_run 0x02 returns each command's return values, with checks on and off" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const bcs = @import("bcs");
    const types = @import("types");
    const exec = @import("exec");
    const dt = exec.ptb.devinspect_test;
    var f: dt.Fixture = undefined;
    try f.init(a, std.testing.io);
    defer f.deinit();
    const coin = try dt.coinObject(a, dt.idOf(0x71), 5, 5000, .{ .AddressOwner = .{ .@"0" = dt.sender } });
    try f.add(coin);
    const td = try f.data(.{
        .inputs = &.{ .{ .Pure = &.{ 2, 'h', 'i' } }, .{ .Object = .{ .ImmOrOwnedObject = try dt.refOf(coin) } } },
        .commands = &.{
            dt.moveCall(1, "string", "utf8", &.{}, &.{.{ .Input = 0 }}),
            dt.moveCall(2, "coin", "value", &.{dt.suiInput()}, &.{.{ .Input = 1 }}),
        },
    });
    const tx_raw = try bcs.encodeAlloc(types.TransactionData, a, &td);
    var ms: rpc_exec.state.MapState = .{};
    var it = f.objs.iterator();
    while (it.next()) |kv| try ms.put(a, kv.key_ptr.*, (try exec.objects.ObjectView.parse(kv.value_ptr.*)).version, kv.value_ptr.*);
    const eng: simulate.api.Engine = .{ .core = .{ .gpa = std.heap.page_allocator, .pkgs = &f.pkgs, .dev_inspect = .enabled } };
    const env: simulate.api.EpochEnv = .{ .chain_id = @splat(0), .epoch = f.epoch, .pv = f.pv, .cfg = f.cfg, .rgp = f.rgp, .epoch_start_ms = f.start_ms, .committee_size = 100 };
    for ([_]u8{ 0x00, 0x01, 0x02, 0x03 }) |flags| {
        var out: std.ArrayList(u8) = .empty;
        try writeDryRun(a, try eng.simulateAt(a, &env, ms.state(), dryRunRequest(tx_raw, flags)), &out);
        const res = try testDryRunResults(a, out.items);
        if (flags & 0x02 == 0) {
            try std.testing.expectEqual(@as(usize, 0), res.len);
            continue;
        }
        try std.testing.expectEqual(@as(usize, 2), res.len);
        try std.testing.expectEqual(@as(usize, 1), res[0].len);
        try std.testing.expectEqualSlices(u8, &.{ 2, 'h', 'i' }, res[0][0]);
        try std.testing.expectEqual(@as(usize, 1), res[1].len);
        try std.testing.expectEqualSlices(u8, try dt.u64Bytes(a, 5000), res[1][0]);
    }
}

test "command results: return values then mutated references, per command" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var out: std.ArrayList(u8) = .empty;
    const w: W = .{ .gpa = a, .out = &out };
    const results = [_]simulate.api.CommandResult{
        .{ .returns = &.{ .{ .bytes = &.{7}, .ty = .u8 }, .{ .bytes = &.{ 1, 0 }, .ty = .u16 } }, .mutated = &.{.{ .arg = .{ .Input = 0 }, .bytes = &.{ 9, 9 }, .ty = .u16 }} },
        .{ .returns = &.{}, .mutated = &.{} },
    };
    try writeCommandResults(w, &results);
    try std.testing.expectEqualSlices(u8, &.{ 2, 2, 1, 7, 2, 1, 0, 1, 2, 9, 9, 0, 0 }, out.items);
}
