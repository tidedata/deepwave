//! Suite `rpc-policy`: transaction-deny-config and policy-config answers equal sui-node 1.83.1's
//! recorded ones (src/serve/vectors/rpc-surface/{deny,traffic}/cases.jsonl, captured on a localnet
//! with the node variant configs/<variant>.yaml; lane rpc-surface-truth).
//!
//! Per case the variant's fullnode.yaml goes through fullnode_yaml.zig (the same --tx-deny /
//! --policy items deepwave gets), then:
//!   - admin (`transport: http`): admin.route answers; http status and body byte-equal
//!   - SimulateTransaction: the deny checks on the request's transaction. A recorded denial
//!     ("Transaction is denied: ...") must be deepwave's answer: grpc-status, grpc-message and
//!     grpc-status-details-bin equal; a recorded answer that is not a denial must find the deny
//!     layer silent (the rest of the answer is the simulate suite's business). An executed
//!     transaction is still denied here (sui-node simulates; it never looks for local effects)
//!   - ExecuteTransaction: the orchestrator's head as LiveExecutor runs it: the user signature
//!     check, then `early.head` (early validation with the deny checks, on or off per the
//!     variant's `transaction-driver-config.enable-early-validation`, then the local effects of
//!     a transaction already executed). A rejection compares like a Simulate denial; a local
//!     answer must be recorded as OK with the same effects BCS; a submission must not be a
//!     recorded denial. A submitted transaction recorded as OK with effects counts as executed for
//!     the cases after it (every variant node follows the same localnet), which is how
//!     `deny-user/execute/transfer-a-already-executed` answers its effects past the deny rule
//!   - any other gRPC call (traffic cases): sui-node's full-node RPC never consults the traffic
//!     controller, and deepwave's does not either; the recorded answer must not be the controller's
//!     rejection ("Too many requests"), else the case fails
//! Cases whose deny decision needs a package this suite cannot read (a MoveCall under a package
//! deny list) are skipped with that reason. Missing vector files skip the suite's items.
const std = @import("std");
const harness = @import("harness");
const serve = @import("serve");
const types = @import("types");
const bcs = @import("bcs");
const rpc_exec = @import("rpc_exec");
const admin = @import("admin.zig");
const fullnode_yaml = @import("fullnode_yaml.zig");

const txdeny = rpc_exec.txdeny;
const early = rpc_exec.live.early;
const LocalEffects = rpc_exec.live.local.LocalEffects;
const drv = rpc_exec.driver.driver;
const usersig_mod = struct {
    const check = rpc_exec.live.usersig.check;
    const handler = rpc_exec.driver.handler;
};
const traffic = serve.traffic;
const checks = rpc_exec.checks;
const proto = serve.proto;
const b64 = std.base64.standard.Decoder;

const root_dir = "src/serve/vectors/rpc-surface";

const Resp = struct {
    http_status: ?u16 = null,
    trailers: ?struct {
        @"grpc-status": ?[]const u8 = null,
        @"grpc-message": ?[]const u8 = null,
        @"grpc-status-details-bin": ?[]const u8 = null,
    } = null,
    headers: ?std.json.Value = null,
    body_b64: ?[]const u8 = null,
    messages_b64: []const []const u8 = &.{},
};

const Case = struct {
    name: []const u8,
    variant: []const u8 = "default",
    transport: []const u8 = "h2c",
    path: []const u8,
    method: []const u8 = "POST",
    req_messages_b64: []const []const u8 = &.{},
    req_body_b64: ?[]const u8 = null,
    resp: Resp = .{},
};

pub fn run(ctx: *harness.Ctx) !void {
    var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    cur_variant = "";
    pkg_map = null;
    executed = .empty;
    defer {
        txdeny.install(.{});
        early.enabled.store(true, .monotonic);
        admin.traffic_ctl = null;
        if (ctl_live) ctl_slot.deinit();
        ctl_live = false;
        executed = .empty;
        pkg_map = null;
        cur_variant = "";
    }
    for ([_][]const u8{ "deny", "traffic" }) |feature| {
        const path = try std.fmt.allocPrint(a, "{s}/{s}/cases.jsonl", .{ root_dir, feature });
        const text = std.Io.Dir.cwd().readFileAlloc(ctx.io, path, a, .limited(64 << 20)) catch {
            ctx.skip(path, "vectors not landed yet (lane rpc-surface-truth)");
            continue;
        };
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            if (std.mem.trim(u8, line, " \r\t").len == 0) continue;
            const c = std.json.parseFromSliceLeaky(Case, a, line, .{ .ignore_unknown_fields = true }) catch {
                ctx.fail(path, "unparsable case line", .{});
                continue;
            };
            try runCase(ctx, a, c);
        }
    }
}

var ctl_slot: traffic.Controller = undefined;
var ctl_live = false;
/// The variant installed now: sui-node keeps its state (admin retunes) across the cases of one
/// node, so a variant is installed once per run of consecutive cases.
var cur_variant: []const u8 = "";
/// `transaction-driver-config.enable-early-validation: false` in the variant (Execute then skips
/// the deny checks, as deepwave's executor does with early validation off).
var early_off = false;

fn installVariant(ctx: *harness.Ctx, a: std.mem.Allocator, variant: []const u8) !bool {
    const p = try std.fmt.allocPrint(a, "{s}/configs/{s}.yaml", .{ root_dir, variant });
    if (std.mem.eql(u8, cur_variant, variant)) return true;
    const text = std.Io.Dir.cwd().readFileAlloc(ctx.io, p, a, .limited(1 << 20)) catch return false;
    cur_variant = try a.dupe(u8, variant);
    var e_err: usize = 0;
    const tree = try fullnode_yaml.parse(a, text, &e_err);
    early_off = if (tree.get("transaction-driver-config")) |tdc| if (tdc.get("enable-early-validation")) |ev| ev == .scalar and std.mem.eql(u8, ev.scalar, "false") else false else false;
    early.enabled.store(!early_off, .monotonic);
    const tr = try fullnode_yaml.translate(a, text, .{});
    var deny: std.ArrayList([]const u8) = .empty;
    var pol: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < tr.args.len) : (i += 1) {
        if (i + 1 < tr.args.len and std.mem.eql(u8, tr.args[i], "--tx-deny")) {
            try deny.append(a, tr.args[i + 1]);
            i += 1;
        } else if (i + 1 < tr.args.len and std.mem.eql(u8, tr.args[i], "--policy")) {
            try pol.append(a, tr.args[i + 1]);
            i += 1;
        }
    }
    txdeny.install(try txdeny.parseItems(a, deny.items));
    if (ctl_live) ctl_slot.deinit();
    ctl_live = false;
    admin.traffic_ctl = null;
    if (try traffic.parseItems(a, pol.items)) |pc| {
        ctl_slot = try traffic.Controller.init(ctx.gpa, pc, serve.h2.meta.monoNs);
        ctl_live = true;
        admin.traffic_ctl = &ctl_slot;
    }
    return true;
}

fn decode(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    const out = try a.alloc(u8, try b64.calcSizeForSlice(s));
    try b64.decode(out, s);
    return out;
}

fn runCase(ctx: *harness.Ctx, a: std.mem.Allocator, c: Case) !void {
    const item = try std.fmt.allocPrint(a, "{s}/{s}", .{ c.variant, c.name });
    if (!try installVariant(ctx, a, c.variant)) return ctx.skip(item, "configs/<variant>.yaml missing");
    if (std.mem.eql(u8, c.transport, "http")) return adminCase(ctx, a, item, c);
    const want_status = if (c.resp.trailers) |t| t.@"grpc-status" orelse "0" else "0";
    const want_msg = try percentDecode(a, if (c.resp.trailers) |t| t.@"grpc-message" orelse "" else "");
    const is_exec = std.mem.endsWith(u8, c.path, "/ExecuteTransaction");
    const is_sim = std.mem.endsWith(u8, c.path, "/SimulateTransaction");
    if (!is_exec and !is_sim) {
        // traffic: the full node's RPC never answers for the controller
        if (std.mem.indexOf(u8, want_msg, "Too many requests") != null)
            return ctx.fail(item, "sui-node rejected with \"Too many requests\" on the RPC port; zui's RPC does not consult the traffic controller (as 1.83.1's source reads)", .{});
        return ctx.pass(item);
    }
    if (c.req_messages_b64.len == 0) return ctx.skip(item, "no request message");
    const body = try decode(a, c.req_messages_b64[0]);
    var tx_bcs: ?[]const u8 = null;
    var sigs: std.ArrayList([]const u8) = .empty;
    var r = proto.Reader.init(body);
    while (r.next() catch null) |f| switch (f.number) {
        1 => tx_bcs = bcsValue(proto.Reader.bytesOf(f) catch continue),
        2 => if (is_exec) if (bcsValue(proto.Reader.bytesOf(f) catch continue)) |s| try sigs.append(a, s),
        else => {},
    };
    const raw = tx_bcs orelse return ctx.skip(item, "request without transaction.bcs");
    const data = bcs.decode(types.TransactionData, a, raw) catch return ctx.skip(item, "transaction bcs does not decode");
    const td = switch (data) {
        .V1 => |*v| v,
    };
    const denial = std.mem.indexOf(u8, want_msg, "Transaction is denied: ") != null;
    if (is_exec) return execCase(ctx, a, item, c, raw, &data, sigs.items, want_status, want_msg, denial);

    var kinds: std.ArrayList(checks.InputKind) = .empty;
    var recv: std.ArrayList(checks.Receiving) = .empty;
    _ = try checks.inputKinds(a, td, &kinds, &recv);
    const rules = &txdeny.current().rules;
    const got = try txdeny.check(a, rules, td, sigs.items, kinds.items, recv.items, try localnetPackages(ctx, a));
    if (got) |g| return compareError(ctx, a, item, c, g.code, g.message, want_status, want_msg, denial);
    if (denial) return ctx.fail(item, "sui-node denied ({s}), zui's deny checks pass", .{want_msg});
    ctx.pass(item);
}

/// ExecuteTransaction as LiveExecutor answers it before any submission.
fn execCase(ctx: *harness.Ctx, a: std.mem.Allocator, item: []const u8, c: Case, raw: []const u8, data: *const types.TransactionData, sigs: []const []const u8, want_status: []const u8, want_msg: []const u8, denial: bool) !void {
    const req: usersig_mod.handler.ExecuteRequest = .{ .envelope = "", .data_bcs = raw, .data = data, .digest = types.digest.transactionDataDigest(raw), .signatures = sigs, .include_events = false, .include_input_objects = false, .include_output_objects = false };
    // sui-node: verify_transaction_with_current_aliases before early validation
    if (try usersig_mod.check(a, &.{}, &req, null, null)) |se| {
        const e = try se.toRpcError(a);
        return compareError(ctx, a, item, c, e.code, e.message, want_status, want_msg, true);
    }
    _ = try localnetPackages(ctx, a);
    const lo: early.LiveObjects = .{ .ctx = &executed, .get = SuiteLive.get, .at = SuiteLive.at, .latest = SuiteLive.latest };
    const lf: LocalEffects = .{ .ctx = &executed, .get = Executed.get };
    switch (try early.head(a, lo, lf, &req, false)) {
        .reject => |e| {
            const re = try e.toRpcError(a);
            if (!denial) return ctx.fail(item, "zui rejects early ({s}) where sui-node answered {s} {s}", .{ re.message, want_status, want_msg });
            return compareError(ctx, a, item, c, re.code, re.message, want_status, want_msg, true);
        },
        .local => |q| {
            if (!std.mem.eql(u8, want_status, "0")) return ctx.fail(item, "zui answers the local effects where sui-node answered {s} {s}", .{ want_status, want_msg });
            const want_eff = recordedEffects(a, c) orelse return ctx.fail(item, "sui-node's answer carries no effects bcs", .{});
            if (!std.mem.eql(u8, q.effects, want_eff)) return ctx.fail(item, "local effects differ from sui-node's", .{});
            return ctx.pass(item);
        },
        .submit => {
            if (denial) return ctx.fail(item, "sui-node denied ({s}), zui submits", .{want_msg});
            // the validators' answer is the execute suites' business; an OK one lands the
            // transaction for the cases after it
            if (std.mem.eql(u8, want_status, "0")) if (recordedEffects(a, c)) |eff| try executed.put(a, req.digest, eff);
            return ctx.pass(item);
        },
    }
}

fn compareError(ctx: *harness.Ctx, a: std.mem.Allocator, item: []const u8, c: Case, code: u8, message: []const u8, want_status: []const u8, want_msg: []const u8, denial: bool) !void {
    if (!denial) return ctx.fail(item, "zui denies ({s}) where sui-node answered {s} {s}", .{ message, want_status, want_msg });
    const code_s = try std.fmt.allocPrint(a, "{d}", .{code});
    if (!std.mem.eql(u8, code_s, want_status)) return ctx.fail(item, "grpc-status {s}, want {s}", .{ code_s, want_status });
    if (!std.mem.eql(u8, message, want_msg)) return ctx.fail(item, "grpc-message {s}, want {s}", .{ message, want_msg });
    if (c.resp.trailers) |t| if (t.@"grpc-status-details-bin") |d| {
        const det = try serve.status.plain(a, code, message);
        const enc = try a.alloc(u8, std.base64.standard_no_pad.Encoder.calcSize(det.len));
        _ = std.base64.standard_no_pad.Encoder.encode(enc, det);
        if (!std.mem.eql(u8, std.mem.trimEnd(u8, d, "="), enc)) return ctx.fail(item, "grpc-status-details-bin differs", .{});
    };
    ctx.pass(item);
}

/// Transactions this replay saw land (digest -> effects BCS): sui-node's executed set as far as
/// the recorded cases show it.
var executed: std.AutoHashMapUnmanaged([32]u8, []const u8) = .empty;

const Executed = struct {
    fn get(ctx: *anyopaque, _: std.mem.Allocator, req: *const usersig_mod.handler.ExecuteRequest) ?drv.QuorumResponse {
        const m: *std.AutoHashMapUnmanaged([32]u8, []const u8) = @ptrCast(@alignCast(ctx));
        const eff = m.get(req.digest) orelse return null;
        return .{ .effects_digest = types.digest.effectsDigest(eff), .effects = eff, .events = null, .input_objects = null, .output_objects = null, .source = 0 };
    }
};

/// The node's objects for early validation: no live versions (the version checks belong to the
/// execute suites), no epoch environment (validity_check is skipped), packages from localnet/chk.
const SuiteLive = struct {
    fn get(_: *anyopaque, _: std.mem.Allocator, _: *const [32]u8) ?early.Live {
        return null;
    }
    fn at(_: *anyopaque, _: std.mem.Allocator, _: *const [32]u8, _: u64) ?[]const u8 {
        return null;
    }
    fn latest(_: *anyopaque, _: std.mem.Allocator, id: *const [32]u8) ?[]const u8 {
        const m = pkg_map orelse return null;
        return m.get(id.*);
    }
};

/// `ExecuteTransactionResponse.transaction(1).effects(4).bcs(1).value(2)` of the recorded answer.
fn recordedEffects(a: std.mem.Allocator, c: Case) ?[]const u8 {
    if (c.resp.messages_b64.len == 0) return null;
    const body = decode(a, c.resp.messages_b64[0]) catch return null;
    const tx = field(body, 1) orelse return null;
    const eff = field(tx, 4) orelse return null;
    return bcsValue(eff);
}

fn field(msg: []const u8, n: u32) ?[]const u8 {
    var r = proto.Reader.init(msg);
    while (r.next() catch null) |f| if (f.number == n) return proto.Reader.bytesOf(f) catch null;
    return null;
}

/// Every package the localnet published (localnet/chk: 0x01 ++ BCS CheckpointData), by id, as
/// BCS Objects: the package store sui-node's deny checks read.
var pkg_map: ?std.AutoHashMapUnmanaged([32]u8, []const u8) = null;

const PkgLookup = struct {
    fn get(_: *anyopaque, _: std.mem.Allocator, id: *const [32]u8) ?[]const u8 {
        return pkg_map.?.get(id.*);
    }
};

fn localnetPackages(ctx: *harness.Ctx, a: std.mem.Allocator) !?txdeny.PackageLookup {
    if (pkg_map == null) {
        var m: std.AutoHashMapUnmanaged([32]u8, []const u8) = .empty;
        var seq: usize = 0;
        while (true) : (seq += 1) {
            const p = try std.fmt.allocPrint(a, "{s}/localnet/chk/{d}.chk", .{ root_dir, seq });
            const raw = std.Io.Dir.cwd().readFileAlloc(ctx.io, p, a, .limited(256 << 20)) catch break;
            if (raw.len < 1) continue;
            const cd = bcs.decode(types.CheckpointData, a, raw[1..]) catch continue;
            for (cd.transactions) |t| for (t.output_objects) |*o| switch (o.data) {
                .Package => |pk| try m.put(a, pk.id.@"0".@"0", try bcs.encodeAlloc(types.Object, a, o)),
                else => {},
            };
        }
        pkg_map = m;
    }
    return .{ .ctx = @ptrCast(&pkg_map), .get = PkgLookup.get };
}

/// `Bcs { name = 1; value = 2 }` inside a Transaction / UserSignature message (field 1).
fn bcsValue(msg: []const u8) ?[]const u8 {
    var r = proto.Reader.init(msg);
    while (r.next() catch null) |f| if (f.number == 1) {
        var br = proto.Reader.init(proto.Reader.bytesOf(f) catch return null);
        while (br.next() catch null) |g| if (g.number == 2) return proto.Reader.bytesOf(g) catch null;
    };
    return null;
}

/// grpc-message as recorded (percent-encoded on the wire).
fn percentDecode(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 2 < s.len and std.ascii.isHex(s[i + 1]) and std.ascii.isHex(s[i + 2])) {
            try out.append(a, std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch unreachable);
            i += 2;
            continue;
        }
        try out.append(a, s[i]);
    }
    return out.items;
}

fn adminCase(ctx: *harness.Ctx, a: std.mem.Allocator, item: []const u8, c: Case) !void {
    const Src = struct {
        fn config(_: *anyopaque, w: *std.Io.Writer) anyerror!void {
            _ = w;
        }
        fn version(_: *anyopaque, w: *std.Io.Writer) anyerror!void {
            _ = w;
        }
    };
    var dummy: u8 = 0;
    const src: admin.Source = .{ .ctx = &dummy, .config = Src.config, .version = Src.version };
    const body = if (c.req_body_b64) |x| try decode(a, x) else "";
    var out: std.Io.Writer.Allocating = .init(a);
    const code = try admin.route(a, src, c.method, c.path, body, &out);
    const want_code = c.resp.http_status orelse 200;
    if (code != want_code) return ctx.fail(item, "http status {d}, want {d}", .{ code, want_code });
    const want_body = if (c.resp.body_b64) |x| try decode(a, x) else "";
    if (!std.mem.eql(u8, out.written(), want_body)) return ctx.fail(item, "body differs:\n{s}\nwant:\n{s}", .{ out.written(), want_body });
    ctx.pass(item);
}
