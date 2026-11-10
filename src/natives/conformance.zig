//! Conformance suites of the sui-natives lane (CONTRACTS.md section 3.3).
//!
//! `natives`: every line of `vectors/natives/*.jsonl` (made by tools/truth/sui-natives over
//! `sui_move_natives::all_natives` in Mysten's Move VM) is one item: a sequence of native calls
//! sharing one transaction context and object runtime. Each call's arguments, type arguments
//! and layouts are given as BCS; the item passes when every call's outcome (returned values,
//! `&mut` arguments written back, abort code or VM error) and the gas the VM charged for it
//! equal Rust's exactly.
//!
//! Object-runtime items carry an `env`: the storage objects of the transaction (resolved like
//! Mysten's `InMemoryStorage` over genesis plus these), its input objects, whether it is metered
//! and the settled balances the funds natives read. They also carry Rust's `ObjectRuntime::finish`
//! results (writes, events, accumulator events, loaded children, created and deleted ids,
//! settlement totals, or the error), which the runtime's own finish must equal. A call returning a
//! reference compares the referenced value; `write` stores a value through a returned `&mut`, as
//! the Move code holding it would.
//!
//! `framework`: see framework.zig.
const std = @import("std");
const objrt_mod = @import("objrt.zig");
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const abi = @import("abi.zig");
const table = @import("table.zig");
const framework = @import("framework.zig");

const objrt = abi.objrt;

const groups = [_][]const u8{
    "address", "bcs",        "bls12381", "debug",     "dynamic_field", "ecdsa_k1",        "ecdsa_r1",
    "ecvrf",   "ed25519",    "groth16",  "group_ops", "hash",          "oog",             "poseidon",
    "protocol_config", "string", "sweep", "tx_context", "type_name", "types", "vector",
    // object runtime
    "accumulator", "child", "config", "event", "layout_limits", "object", "package", "scratch", "transfer",
    "zklogin", "disabled", "limits", "review_rt",
    // round 3
    "nitro",
    "validator",
    "event_total",
};

/// Groups also timed on the native body alone (arguments decoded outside the timing), against
/// Rust's own body of the native without the VM (`bench-direct`).
const body_groups = [_][]const u8{ "validator", "nitro", "ed25519", "bls12381", "hash" };

const baselines = blk: {
    var bl: [groups.len + body_groups.len]harness.Baseline = undefined;
    for (groups, 0..) |g, i| bl[i] = .{ .name = g, .argv = &.{ "{release}/zui-truth-sui-natives", "bench", g } };
    for (body_groups, 0..) |g, i| bl[groups.len + i] = .{ .name = g ++ "-body", .argv = &.{ "{release}/zui-truth-sui-natives", "bench-direct", g } };
    break :blk bl;
};

pub const suites = [_]harness.Suite{
    .{
        .name = "natives",
        .lane = "sui-natives",
        .doc = "per-native call vectors: results, aborts and costs equal Rust",
        .run = runNatives,
        .bench = benchNatives,
        .baselines = &baselines,
        .inputs = .{ .dir = "vectors/natives", .suffix = ".jsonl" },
    },
    // exec-history-vm (CONTRACTS 6.6b.2): the same scripts run by Mysten's older cuts
    // (`tools/truth/sui-natives cut`): vectors/natives/cuts/<cut>/<group>.jsonl, each line at a
    // protocol version of the cut's window.
    .{
        .name = "natives-cuts",
        .lane = "exec-history-vm",
        .doc = "natives on the execution cuts v0..v3 (sui-move-natives-vN, move-stdlib-natives-vN)",
        .run = runNativesCuts,
        .inputs = .{ .dir = "vectors/natives/cuts", .suffix = ".jsonl" },
    },
    .{ .name = "framework", .lane = "sui-natives", .doc = "system package bytes per framework version equal sui-framework-snapshot", .run = framework.run },
};

const J = std.json.Value;

fn hexAlloc(a: std.mem.Allocator, h: []const u8) ![]u8 {
    const out = try a.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

fn hex32(h: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, h);
    return out;
}

fn jU64(v: J) u64 {
    return switch (v) {
        .integer => |i| @intCast(i),
        .float => |f| @intFromFloat(f),
        .number_string => |s| std.fmt.parseInt(u64, s, 10) catch 0,
        else => 0,
    };
}

pub const default_tx: abi.TxContext = .{
    .sender = @splat(0x5a),
    .digest = @splat(0xd1),
    .epoch = 1304,
    .epoch_timestamp_ms = 1_762_400_000_000,
    .rgp = 538,
    .gas_price = 750,
    .gas_budget = 50_000_000,
    .sponsor = null,
};

fn txFrom(v: J) !abi.TxContext {
    if (v != .object) return default_tx;
    const o = v.object;
    const sp = o.get("sponsor").?;
    return .{
        .sender = try hex32(o.get("sender").?.string),
        .digest = try hex32(o.get("digest").?.string),
        .epoch = jU64(o.get("epoch").?),
        .epoch_timestamp_ms = jU64(o.get("epoch_ts_ms").?),
        .rgp = jU64(o.get("rgp").?),
        .gas_price = jU64(o.get("gas_price").?),
        .gas_budget = jU64(o.get("gas_budget").?),
        .sponsor = if (sp == .string) try hex32(sp.string) else null,
    };
}

/// One prepared call: decoded type arguments and values.
const Call = struct {
    f: abi.NativeFn,
    tys: []abi.TyArg,
    args: []abi.Value,
    kinds: []u8,
    budget: u64,
};

fn prepare(a: std.mem.Allocator, call: J) !?Call {
    const o = call.object;
    // exec-history-vm: v0..v3 frameworks name the type_name natives `get` / `get_with_original_ids`
    var func = o.get("func").?.string;
    if (std.mem.eql(u8, o.get("module").?.string, "type_name")) {
        if (std.mem.eql(u8, func, "get")) func = "with_defining_ids";
        if (std.mem.eql(u8, func, "get_with_original_ids")) func = "with_original_ids";
    }
    const f = table.lookup(@intCast(jU64(o.get("addr").?)), o.get("module").?.string, func) orelse return null;
    const tys_j = o.get("tys").?.array.items;
    const tys = try a.alloc(abi.TyArg, tys_j.len);
    for (tys, tys_j) |*t, tj| {
        const tag = try a.create(abi.TypeTag);
        tag.* = try bcs.decode(abi.TypeTag, a, try hexAlloc(a, tj.object.get("tag").?.string));
        const lj = tj.object.get("layout").?;
        var lay: ?*const abi.Layout = null;
        if (lj == .string) {
            const l = try a.create(abi.Layout);
            l.* = try bcs.decode(abi.Layout, a, try hexAlloc(a, lj.string));
            lay = l;
        }
        var shape: ?*const abi.Layout = null;
        if (tj.object.get("shape")) |sj| {
            const l = try a.create(abi.Layout);
            l.* = try bcs.decode(abi.Layout, a, try hexAlloc(a, sj.string));
            shape = l;
        }
        var ann: ?*const objrt.ALayout = null;
        if (tj.object.get("ann")) |aj| if (aj == .string) {
            const l = try a.create(objrt.ALayout);
            l.* = try bcs.decode(objrt.ALayout, a, try hexAlloc(a, aj.string));
            ann = l;
        };
        t.* = .{ .tag = tag, .layout = lay, .shape = shape, .annotated = ann };
    }
    const params = o.get("params").?.array.items;
    const args_j = o.get("args").?.array.items;
    const args = try a.alloc(abi.Value, args_j.len);
    const kinds = try a.alloc(u8, args_j.len);
    for (args, kinds, params, args_j) |*v, *k, pj, aj| {
        k.* = @intCast(jU64(pj.array.items[0]));
        const l = try a.create(abi.Layout);
        l.* = try bcs.decode(abi.Layout, a, try hexAlloc(a, pj.array.items[1].string));
        v.* = try types.layout.decodePacked(a, l, try hexAlloc(a, aj.string));
    }
    return .{ .f = f, .tys = tys, .args = args, .kinds = kinds, .budget = jU64(o.get("budget").?) };
}

fn checkCall(c: *harness.Check, a: std.mem.Allocator, i: usize, call: J, out: abi.Outcome, args: []const abi.Value, kinds: []const u8) !void {
    const o = call.object;
    const want = o.get("out").?.object;
    const cost_j = o.get("cost").?.array.items;
    var buf: [64]u8 = undefined;
    const what = std.fmt.bufPrint(&buf, "call[{d}]", .{i}) catch "call";
    if (want.get("ok")) |ok| {
        if (out != .ok) return c.failf("{s}: want ok, have {s}", .{ what, @tagName(out) });
        const rets_j = ok.object.get("rets").?.array.items;
        if (o.get("ret_ref") != null) {
            const r = out.ok.ref orelse return c.failf("{s}: want a reference, have values", .{what});
            if (rets_j.len != 1) return c.failf("{s}: {d} reference rets", .{ what, rets_j.len });
            c.bytes("ret ref", try hexAlloc(a, rets_j[0].string), try types.layout.encodeAlloc(a, r));
        } else {
            if (out.ok.ref != null) return c.failf("{s}: returned a reference, want values", .{what});
            if (rets_j.len != out.ok.rets.len) return c.failf("{s}: {d} rets, want {d}", .{ what, out.ok.rets.len, rets_j.len });
            for (rets_j, out.ok.rets) |rj, *rv| c.bytes("ret", try hexAlloc(a, rj.string), try types.layout.encodeAlloc(a, rv));
        }
        const muts_j = ok.object.get("muts").?.array.items;
        var m: usize = 0;
        for (args, kinds) |*v, k| {
            if (k != 2) continue;
            if (m >= muts_j.len) return c.failf("{s}: more &mut args than truth", .{what});
            c.bytes("mut", try hexAlloc(a, muts_j[m].string), try types.layout.encodeAlloc(a, v));
            m += 1;
        }
        if (m != muts_j.len) c.failf("{s}: {d} muts, want {d}", .{ what, m, muts_j.len });
        if (cost_j.len != 1) return c.failf("{s}: truth cost list {d}", .{ what, cost_j.len });
        c.eql("cost", jU64(cost_j[0]), out.ok.cost);
    } else if (want.get("abort")) |code| {
        if (out != .abort) return c.failf("{s}: want abort {d}, have {s}", .{ what, jU64(code), @tagName(out) });
        c.eql("abort", jU64(code), out.abort.code);
        if (cost_j.len != 1) return c.failf("{s}: truth cost list {d}", .{ what, cost_j.len });
        c.eql("cost", jU64(cost_j[0]), out.abort.cost);
    } else if (want.get("err")) |e| {
        if (out != .err) return c.failf("{s}: want err, have {s}", .{ what, @tagName(out) });
        c.eql("status", jU64(e.object.get("status").?), @intFromEnum(out.err.status));
        const sub_j = e.object.get("sub").?;
        const want_sub: ?u64 = if (sub_j == .null) null else jU64(sub_j);
        c.eql("sub", want_sub, out.err.sub);
        c.eql("cost entries", @as(usize, 0), cost_j.len);
    }
}

// ---- the object world of an item ------------------------------------------------------------

/// Genesis system packages (`BuiltInFramework::genesis_objects`, version 1) as the package
/// natives see them, built from the embedded framework on first use.
const Genesis = struct {
    arena: std.heap.ArenaAllocator,
    /// The truth release's built-in framework version (its max protocol version, `fileBuiltin`).
    builtin: u64,
    pkgs: ?std.AutoHashMapUnmanaged(objrt.Id, objrt.PackageInfo) = null,

    fn init(ctx: *harness.Ctx, builtin: u64) Genesis {
        return .{ .arena = std.heap.ArenaAllocator.init(ctx.gpa), .builtin = builtin };
    }

    fn get(g: *Genesis, id: *const objrt.Id) ?objrt.PackageInfo {
        if (g.pkgs == null) g.build() catch return null;
        return g.pkgs.?.get(id.*);
    }

    fn build(g: *Genesis) !void {
        const a = g.arena.allocator();
        const vers = try framework.load(a);
        // Vectors made by an older release (1.83.1: built-in 141, which is snapshot 140's bytes)
        // see that release's built-in packages, not the blob's newest (142 at 1.84).
        const builtin = framework.snapshot(vers, g.builtin) orelse return error.BadFrameworkBlob;
        var m: std.AutoHashMapUnmanaged(objrt.Id, objrt.PackageInfo) = .empty;
        const prev: [32]u8 = @splat(0);
        for (builtin.packages) |*p| {
            const obj = try bcs.decode(types.Object, a, try framework.packageObjectBcs(a, p, 1, &prev));
            try m.put(a, p.id, try objrt.packageInfo(a, &obj.data.Package));
        }
        g.pkgs = m;
    }
};

/// The built-in framework version of the release that made a natives vector file: its newest
/// item `"pv"`. zui-truth-sui-natives writes every file at its release's max protocol version
/// (plus older `@<pv>` variants), so a file made by 1.83.1 says 141 even when deepwave (or a release
/// overlay's protocol-config and framework truth) is newer. `sweep.jsonl` stops below the max but
/// calls no package native, the only natives that read genesis.
fn fileBuiltin(text: []const u8) u64 {
    const key = "\"pv\":";
    var best: u64 = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, text, i, key)) |at| {
        var j = at + key.len;
        var v: u64 = 0;
        while (j < text.len and text[j] >= '0' and text[j] <= '9') : (j += 1) v = v *| 10 +| (text[j] - '0');
        best = @max(best, v);
        i = j;
    }
    return if (best == 0) protocol.max_protocol_version else best;
}

/// Mysten's `InMemoryStorage` over genesis plus the item's objects, and the settled balances
/// (`ImplicitSystemObjectResolver::object_available_balance`).
const World = struct {
    objects: std.AutoHashMapUnmanaged(objrt.Id, objrt.StoredObject) = .empty,
    packages: std.AutoHashMapUnmanaged(objrt.Id, struct { version: u64, info: objrt.PackageInfo }) = .empty,
    balances: []const Balance = &.{},
    /// The item's Clock contents (`env.clock`, 1.84 vectors): what `ImplicitSystemObjectResolver::clock` hands `clock::borrow`.
    clock: ?[]const u8 = null,
    genesis: *Genesis,

    const Balance = struct { owner: objrt.Id, ty: abi.TypeTag, amount: u128 };

    const vtable: objrt.Resolver.VTable = .{
        .read_child = readChild,
        .received_at = receivedAt,
        .package_at = packageAt,
        .available_balance = availableBalance,
        .clock = clockContents,
    };

    fn resolver(w: *World) objrt.Resolver {
        return .{ .ctx = w, .vtable = &vtable };
    }

    fn readChild(ctx: *anyopaque, parent: *const objrt.Id, child: *const objrt.Id, upper: u64) objrt.ResolveError!?*const objrt.StoredObject {
        const w: *World = @ptrCast(@alignCast(ctx));
        const o = w.objects.getPtr(child.*) orelse return null;
        if (!(o.owner == .object and std.mem.eql(u8, &o.owner.object, parent))) return error.Storage;
        if (o.version > upper) return error.Storage;
        return o;
    }

    fn receivedAt(ctx: *anyopaque, owner: *const objrt.Id, child: *const objrt.Id, version: u64, _: u64) objrt.ResolveError!?*const objrt.StoredObject {
        const w: *World = @ptrCast(@alignCast(ctx));
        const o = w.objects.getPtr(child.*) orelse return null;
        if (!(o.owner == .address and std.mem.eql(u8, &o.owner.address, owner))) return null;
        if (o.version != version) return null;
        return o;
    }

    fn packageAt(ctx: *anyopaque, id: *const objrt.Id, version: u64) ?objrt.PackageInfo {
        const w: *World = @ptrCast(@alignCast(ctx));
        if (w.packages.get(id.*)) |p| return if (p.version == version) p.info else null;
        if (w.objects.contains(id.*)) return null; // a Move object: not a package
        const info = w.genesis.get(id) orelse return null;
        return if (version == 1) info else null;
    }

    fn clockContents(ctx: *anyopaque) objrt.ResolveError!?[]const u8 {
        const w: *World = @ptrCast(@alignCast(ctx));
        return w.clock;
    }

    fn availableBalance(ctx: *anyopaque, owner: *const objrt.Id, ty: *const abi.TypeTag) objrt.ResolveError!u128 {
        const w: *World = @ptrCast(@alignCast(ctx));
        for (w.balances) |*b| if (std.mem.eql(u8, &b.owner, owner) and objrt.tagEql(&b.ty, ty)) return b.amount;
        return 0;
    }
};

/// An item's object world: the storage (`World`) and what `ObjectRuntime::new` is given.
const Env = struct {
    world: *World,
    metered: bool,
    inputs: []const objrt.InputObject,

    /// A fresh runtime for one run of the item.
    fn runtime(e: *const Env, a: std.mem.Allocator, rt: *abi.ObjectRuntime) !void {
        rt.is_metered = e.metered;
        for (e.inputs) |in| try rt.addInput(a, in);
        rt.resolver = e.world.resolver();
    }
};

fn loadEnv(a: std.mem.Allocator, env: J, genesis: *Genesis) !Env {
    const e = env.object;
    const world = try a.create(World);
    world.* = .{ .genesis = genesis };
    const inputs_j = e.get("inputs").?.array.items;
    const inputs = try a.alloc(objrt.InputObject, inputs_j.len);
    for (inputs, inputs_j) |*in, ij| {
        const it = ij.array.items;
        const owner = try bcs.decode(types.Owner, a, try hexAlloc(a, it[2].string));
        const uids_j = it[3].array.items;
        const uids = try a.alloc(objrt.Id, uids_j.len);
        for (uids, uids_j) |*u, uj| u.* = try hex32(uj.string);
        in.* = .{ .id = try hex32(it[0].string), .version = jU64(it[1]), .owner = try objrt.Owner.fromTypes(a, &owner), .contained_uids = uids };
    }
    for (e.get("objects").?.array.items) |oj| {
        const obj = try bcs.decode(types.Object, a, try hexAlloc(a, oj.object.get("obj").?.string));
        switch (obj.data) {
            .Package => |*p| try world.packages.put(a, p.id.@"0".@"0", .{ .version = p.version.@"0", .info = try objrt.packageInfo(a, p) }),
            .Move => |m| {
                const tag = try a.create(abi.TypeTag);
                tag.* = .{ .@"struct" = try bcs.decode(types.StructTag, a, try hexAlloc(a, oj.object.get("type").?.string)) };
                const id = m.contents[0..32].*;
                try world.objects.put(a, id, .{
                    .id = id,
                    .owner = try objrt.Owner.fromTypes(a, &obj.owner),
                    .version = m.version.@"0",
                    .previous_transaction = obj.previous_transaction.@"0".@"0",
                    .storage_rebate = obj.storage_rebate,
                    .move = .{ .type_ = tag, .contents = m.contents },
                });
            },
        }
    }
    const bal_j = e.get("balances").?.array.items;
    const bals = try a.alloc(World.Balance, bal_j.len);
    for (bals, bal_j) |*b, bj| {
        const it = bj.array.items;
        b.* = .{
            .owner = try hex32(it[0].string),
            .ty = try bcs.decode(abi.TypeTag, a, try hexAlloc(a, it[1].string)),
            .amount = try std.fmt.parseInt(u128, it[2].string, 10),
        };
    }
    world.balances = bals;
    if (e.get("clock")) |cj| world.clock = try hexAlloc(a, cj.string);
    return .{ .world = world, .metered = e.get("metered").?.bool, .inputs = inputs };
}

fn hexEq(c: *harness.Check, a: std.mem.Allocator, what: []const u8, want: J, have: []const u8) !void {
    c.bytes(what, try hexAlloc(a, want.string), have);
}

fn structBcs(a: std.mem.Allocator, t: *const abi.TypeTag) ![]u8 {
    return switch (t.*) {
        .@"struct" => |*st| try bcs.encodeAlloc(types.StructTag, a, st),
        else => error.NotAStruct,
    };
}

/// `ObjectRuntime::finish` against Rust's `RuntimeResults` (or its error kind).
fn checkResults(c: *harness.Check, a: std.mem.Allocator, want: J, rt: *abi.ObjectRuntime, cfg: *const protocol.ProtocolConfig) !void {
    const fin = try rt.finishFor(a, cfg);
    if (want.object.get("err")) |ej| {
        if (fin != .err) return c.failf("finish: want error {s}, have ok", .{ej.string});
        const kind: []const u8 = switch (fin.err) {
            .circular => "CircularObjectOwnership",
            .invariant => "InvariantViolation",
        };
        if (!std.mem.eql(u8, kind, ej.string)) c.failf("finish: error {s}, want {s}", .{ kind, ej.string });
        return;
    }
    const ok = want.object.get("ok").?.object;
    if (fin != .ok) return c.failf("finish: want ok, have error {s}", .{@tagName(fin.err)});
    const r = fin.ok;

    const writes_j = ok.get("writes").?.array.items;
    if (writes_j.len != r.writes.len) return c.failf("finish: {d} writes, want {d}", .{ r.writes.len, writes_j.len });
    for (writes_j, r.writes) |wj, *w| {
        const it = wj.array.items;
        try hexEq(c, a, "write id", it[0], &w.id);
        try hexEq(c, a, "write owner", it[1], try w.owner.encode(a));
        try hexEq(c, a, "write type", it[2], try structBcs(a, w.ty));
        try hexEq(c, a, "write value", it[3], try types.layout.encodeAlloc(a, &w.value));
    }
    const events_j = ok.get("events").?.array.items;
    if (events_j.len != r.events.len) return c.failf("finish: {d} events, want {d}", .{ r.events.len, events_j.len });
    for (events_j, r.events) |ej, *e| {
        const it = ej.array.items;
        try hexEq(c, a, "event type", it[0], try structBcs(a, e.ty));
        try hexEq(c, a, "event value", it[1], try types.layout.encodeAlloc(a, &e.value));
    }
    const acc_j = ok.get("acc").?.array.items;
    if (acc_j.len != r.acc_events.len) return c.failf("finish: {d} accumulator events, want {d}", .{ r.acc_events.len, acc_j.len });
    for (acc_j, r.acc_events) |aj, *e| {
        const it = aj.array.items;
        try hexEq(c, a, "acc id", it[0], &e.accumulator_id);
        c.eql("acc action", jU64(it[1]), @intFromEnum(e.action));
        try hexEq(c, a, "acc address", it[2], &e.target_addr);
        try hexEq(c, a, "acc type", it[3], try objrt.tagBcs(a, e.target_ty));
        const kind: u64, const n: u64 = switch (e.value) {
            .u64 => |x| .{ 0, x },
            .event_ref => |x| .{ 1, x },
        };
        c.eql("acc kind", jU64(it[4]), kind);
        c.eql("acc value", jU64(it[5]), n);
    }
    const loaded_j = ok.get("loaded").?.array.items;
    if (loaded_j.len != r.loaded.len) return c.failf("finish: {d} loaded children, want {d}", .{ r.loaded.len, loaded_j.len });
    for (loaded_j, r.loaded) |lj, *l| {
        const it = lj.array.items;
        try hexEq(c, a, "loaded id", it[0], &l.id);
        c.eql("loaded version", jU64(it[1]), l.version);
        // v0 records no modified flag (null in the vectors; `finishFor` reports false)
        c.eql("loaded modified", if (it[2] == .bool) it[2].bool else false, l.modified);
    }
    // exec-history-vm: v0 vectors list the wrapped children (DeleteKind::Wrap) too
    if (ok.get("v0_wrap")) |wj| {
        if (wj.array.items.len != r.v0_wrapped_children.len) return c.failf("finish: {d} v0 wrapped children, want {d}", .{ r.v0_wrapped_children.len, wj.array.items.len });
        for (wj.array.items, r.v0_wrapped_children) |ij, *id| try hexEq(c, a, "v0 wrapped", ij, id);
    }
    inline for (.{ .{ "created", r.created }, .{ "deleted", r.deleted } }) |pair| {
        const ids_j = ok.get(pair[0]).?.array.items;
        if (ids_j.len != pair[1].len) return c.failf("finish: {d} {s}, want {d}", .{ pair[1].len, pair[0], ids_j.len });
        for (ids_j, pair[1]) |ij, *id| try hexEq(c, a, pair[0], ij, id);
    }
    const settle = ok.get("settle").?.array.items;
    c.eql("settlement input", jU64(settle[0]), r.settlement_input_sui);
    c.eql("settlement output", jU64(settle[1]), r.settlement_output_sui);
}

fn runItem(w: *harness.Ctx, genesis: *Genesis, line: []const u8) !void {
    const a = w.scratch();
    const d = try std.json.parseFromSliceLeaky(J, a, line, .{});
    const id = d.object.get("id").?.string;
    if (!w.selected(id)) return;
    const pv = jU64(d.object.get("pv").?);
    const cfg = protocol.get(pv, .mainnet) catch return w.fail(id, "protocol version {d}", .{pv});
    var tx = try txFrom(d.object.get("ctx").?);
    var rt: abi.ObjectRuntime = .{ .epoch = tx.epoch };
    if (d.object.get("env")) |e| try (try loadEnv(a, e, genesis)).runtime(a, &rt);
    var nc = abi.Ctx.init(a, cfg, 0, &tx, &rt);
    var chk = w.check(id);
    for (d.object.get("calls").?.array.items, 0..) |call, i| {
        const p = (try prepare(a, call)) orelse {
            const o = call.object;
            chk.failf("no native {s}::{s}", .{ o.get("module").?.string, o.get("func").?.string });
            break;
        };
        nc.enter(p.budget);
        const out = try p.f(&nc, p.tys, p.args);
        try checkCall(&chk, a, i, call, out, p.args, p.kinds);
        if (!chk.ok()) break;
        if (call.object.get("write")) |wj| {
            try writeThrough(a, call, wj, out);
            // exec-history-vm: a write through a child's `&mut` dirties it under the old rule.
            if (objrt_mod.legacyDirty(cfg)) rt.markDirtySlot(out.ok.ref.?);
        }
    }
    if (chk.ok()) if (d.object.get("results")) |rj| try checkResults(&chk, a, rj, &rt, cfg);
    _ = chk.finish();
}

/// Store `wj` (BCS of the referenced type) through the `&mut` the call returned.
fn writeThrough(a: std.mem.Allocator, call: J, wj: J, out: abi.Outcome) !void {
    const r = out.ok.ref orelse return error.WriteWithoutReference;
    const l = try a.create(abi.Layout);
    l.* = try bcs.decode(abi.Layout, a, try hexAlloc(a, call.object.get("rets").?.array.items[0].string));
    r.* = try types.layout.decodePacked(a, l, try hexAlloc(a, wj.string));
}

fn runFile(_: void, w: *harness.Ctx, name: []const u8) !void {
    var pbuf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&pbuf, "vectors/natives/{s}", .{name});
    // the file stays in the gpa for the whole file; items use the scratch arena
    const text = try w.corpus.readFileAlloc(w.io, path, w.gpa, .limited(1 << 30));
    defer w.gpa.free(text);
    var genesis: Genesis = .init(w, fileBuiltin(text));
    defer genesis.arena.deinit();
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (w.done()) return;
        w.nextItem();
        try runItem(w, &genesis, line);
    }
}

/// exec-history-vm: every `vectors/natives/cuts/<cut>/*.jsonl`, as `cuts/<cut>/<file>`.
fn runNativesCuts(ctx: *harness.Ctx) !void {
    var all: std.ArrayList([]const u8) = .empty;
    defer {
        for (all.items) |n| ctx.gpa.free(n);
        all.deinit(ctx.gpa);
    }
    const cut_dirs = [_][]const u8{ "v0", "v1-21", "v1-22", "v1", "v2", "v3", "v3-75" };
    for (cut_dirs) |cut| {
        var dbuf: [64]u8 = undefined;
        const dir = try std.fmt.bufPrint(&dbuf, "vectors/natives/cuts/{s}", .{cut});
        const names = ctx.listFiles(dir, ".jsonl") catch |e| switch (e) {
            error.FileNotFound => continue,
            else => return e,
        };
        defer ctx.freeNames(names);
        for (names) |n| try all.append(ctx.gpa, try std.fmt.allocPrint(ctx.gpa, "cuts/{s}/{s}", .{ cut, n }));
    }
    if (ctx.opts.filter != null) {
        for (all.items) |n| try runFile({}, ctx, n);
        return;
    }
    try ctx.forEachName(all.items, {}, runFile);
}

fn runNatives(ctx: *harness.Ctx) !void {
    const names = try ctx.listFiles("vectors/natives", ".jsonl");
    defer ctx.freeNames(names);
    if (ctx.opts.filter != null) {
        // -Dfilter selects item ids, not file names
        for (names) |n| try runFile({}, ctx, n);
        return;
    }
    try ctx.forEachName(names, {}, runFile);
}

// ---- bench ----------------------------------------------------------------------------------
//
// Per corpus group, one record per native call: arguments decoded from their BCS bytes, the
// native run, results encoded back to BCS. The Rust baseline runs the same items through
// Mysten's Move VM (`zui-truth-sui-natives bench <group>`), which adds the VM's call entry.

const BenchCall = struct {
    f: abi.NativeFn,
    tys: []abi.TyArg,
    layouts: []*const abi.Layout,
    bytes: [][]u8,
    budget: u64,
    /// a value to store through the returned `&mut`, and the layout to decode it with
    write: ?struct { layout: *const abi.Layout, bytes: []u8 } = null,
};

const BenchItem = struct { calls: []BenchCall, pv: u64, tx: abi.TxContext, env: ?Env };

const BenchState = struct {
    items: []BenchItem,
    arena: *std.heap.ArenaAllocator,
};

fn prepareBench(a: std.mem.Allocator, call: J) !BenchCall {
    const p = (try prepare(a, call)).?;
    const o = call.object;
    const params = o.get("params").?.array.items;
    const args_j = o.get("args").?.array.items;
    const layouts = try a.alloc(*const abi.Layout, params.len);
    const bytes = try a.alloc([]u8, args_j.len);
    for (layouts, bytes, params, args_j) |*l, *b, pj, aj| {
        const lay = try a.create(abi.Layout);
        lay.* = try bcs.decode(abi.Layout, a, try hexAlloc(a, pj.array.items[1].string));
        l.* = lay;
        b.* = try hexAlloc(a, aj.string);
    }
    var out: BenchCall = .{ .f = p.f, .tys = p.tys, .layouts = layouts, .bytes = bytes, .budget = p.budget };
    if (o.get("write")) |wj| {
        const l = try a.create(abi.Layout);
        l.* = try bcs.decode(abi.Layout, a, try hexAlloc(a, o.get("rets").?.array.items[0].string));
        out.write = .{ .layout = l, .bytes = try hexAlloc(a, wj.string) };
    }
    return out;
}

fn benchPass(s: *BenchState) !void {
    for (s.items) |*it| {
        _ = s.arena.reset(.retain_capacity);
        const a = s.arena.allocator();
        var tx = it.tx;
        var rt: abi.ObjectRuntime = .{ .epoch = tx.epoch };
        if (it.env) |*e| try e.runtime(a, &rt);
        const cfg = protocol.get(it.pv, .mainnet) catch unreachable;
        var nc = abi.Ctx.init(a, cfg, 0, &tx, &rt);
        for (it.calls) |*cl| {
            const args = try a.alloc(abi.Value, cl.bytes.len);
            for (args, cl.layouts, cl.bytes) |*v, l, b| v.* = try types.layout.decodePacked(a, l, b);
            nc.enter(cl.budget);
            const out = try cl.f(&nc, cl.tys, args);
            if (out == .ok) {
                for (out.ok.rets) |*r| std.mem.doNotOptimizeAway(try types.layout.encodeAlloc(a, r));
                if (out.ok.ref) |r| {
                    std.mem.doNotOptimizeAway(try types.layout.encodeAlloc(a, r));
                    if (cl.write) |w| r.* = try types.layout.decodePacked(a, w.layout, w.bytes);
                }
            }
        }
        if (it.env != null) std.mem.doNotOptimizeAway(try rt.finish(a));
    }
}

fn benchNatives(ctx: *harness.Ctx) !void {
    var keep = std.heap.ArenaAllocator.init(ctx.gpa);
    defer keep.deinit();
    const ka = keep.allocator();
    var scratch = std.heap.ArenaAllocator.init(ctx.gpa);
    defer scratch.deinit();
    // timing only (results are not compared): the blob's newest framework serves every group
    var genesis: Genesis = .init(ctx, protocol.max_protocol_version);
    defer genesis.arena.deinit();
    for (groups) |g| {
        var items: std.ArrayList(BenchItem) = .empty;
        var n_calls: u64 = 0;
        for (ctx.benchInputs()) |path| {
            const stem = std.fs.path.stem(path);
            if (!std.mem.eql(u8, stem, g)) continue;
            const text = try ctx.corpus.readFileAlloc(ctx.io, path, ka, .limited(1 << 30));
            var it = harness.lines(text);
            while (it.next()) |line| {
                if (line.len == 0) continue;
                const d = try std.json.parseFromSliceLeaky(J, ka, line, .{});
                const cj = d.object.get("calls").?.array.items;
                const calls = try ka.alloc(BenchCall, cj.len);
                for (calls, cj) |*c, j| c.* = try prepareBench(ka, j);
                n_calls += cj.len;
                const env: ?Env = if (d.object.get("env")) |e| try loadEnv(ka, e, &genesis) else null;
                try items.append(ka, .{ .calls = calls, .pv = jU64(d.object.get("pv").?), .tx = try txFrom(d.object.get("ctx").?), .env = env });
            }
        }
        if (n_calls == 0) continue;
        var st: BenchState = .{ .items = items.items, .arena = &scratch };
        try ctx.benchPasses(g, "call", n_calls, &st, benchPass);
        inline for (body_groups) |bg| {
            if (std.mem.eql(u8, bg, g)) try benchBody(ctx, ka, &scratch, items.items, n_calls, bg ++ "-body");
        }
    }
}

fn benchBody(ctx: *harness.Ctx, ka: std.mem.Allocator, scratch: *std.heap.ArenaAllocator, items: []BenchItem, n_calls: u64, name: []const u8) !void {
    var bs: BodyState = .{ .calls = .empty, .arena = scratch };
    for (items) |*it| for (it.calls) |*cl| {
        const args = try ka.alloc(abi.Value, cl.bytes.len);
        for (args, cl.layouts, cl.bytes) |*v, l, b| v.* = try types.layout.decodePacked(ka, l, b);
        try bs.calls.append(ka, .{ .call = cl, .args = args, .pv = it.pv, .tx = it.tx });
    };
    try ctx.benchPasses(name, "call", n_calls, &bs, bodyPass);
}

const BodyCall = struct { call: *const BenchCall, args: []abi.Value, pv: u64, tx: abi.TxContext };
const BodyState = struct { calls: std.ArrayList(BodyCall), arena: *std.heap.ArenaAllocator };

/// The native alone on pre-decoded arguments (these groups never write their arguments).
fn bodyPass(s: *BodyState) !void {
    for (s.calls.items) |*bc| {
        _ = s.arena.reset(.retain_capacity);
        const a = s.arena.allocator();
        var tx = bc.tx;
        var rt: abi.ObjectRuntime = .{ .epoch = tx.epoch };
        const cfg = protocol.get(bc.pv, .mainnet) catch unreachable;
        var nc = abi.Ctx.init(a, cfg, 0, &tx, &rt);
        nc.enter(bc.call.budget);
        std.mem.doNotOptimizeAway(try bc.call.f(&nc, bc.call.tys, bc.args));
    }
}
