//! Conformance suites of the move-vm lane (CONTRACTS.md section 3.3).
//!
//! Truth: `tools/truth/move-vm` runs Mysten's move-vm-runtime (1.83.1, the `latest` execution)
//! with `SuiGasMeter` over function calls into corpus and framework packages. Layout:
//!   vectors/move-vm-gas/packages.bin     every package the calls link against
//!   vectors/move-vm-gas/calls.jsonl      one call and its truth per line
//!   vectors/move-vm-trace/calls.jsonl    the calls that also have a trace
//!   vectors/move-vm-trace/trace/<id>.json.zst   move-trace-format trace of call <id>
//! An item is one call: `<id>/<module>::<fn>`.
const std = @import("std");
const harness = @import("harness");
const protocol = @import("protocol");
const move_format = @import("move_format");
const loader = @import("loader.zig");
const value = @import("value.zig");
const types = @import("types.zig");
const gas = @import("gas.zig");
const interp = @import("interp.zig");
const trace = @import("trace.zig");
const host = @import("host.zig");
const natives = @import("natives");
const bcs = @import("bcs");
const types_mod = @import("types");

/// The transaction context the truth tool runs calls under (tools/truth/sui-natives DEFAULT_CTX).
pub const DEFAULT_TX: natives.abi.TxContext = .{
    .sender = @splat(0x5a),
    .digest = @splat(0xd1),
    .epoch = 1304,
    .epoch_timestamp_ms = 1_762_400_000_000,
    .rgp = 538,
    .gas_price = 750,
    .gas_budget = 50_000_000,
    .sponsor = null,
};

const Allocator = std.mem.Allocator;
const Value = value.Value;

pub const suites = [_]harness.Suite{
    .{
        .name = "move-vm-load",
        .lane = "move-vm",
        .doc = "make_vm for every package's linkage (corpus, framework and synthetic packages at the JIT type limits, with undecodable constants, linking refused or missing packages): loads, or the same status, location and offsets as Rust (missing packages, deserialization and verifier errors through expect_no_verification_errors, JIT type-node limits)",
        .run = runLoad,
        .inputs = .{ .dir = "vectors/move-vm-load", .suffix = ".jsonl" },
    },
    .{
        .name = "move-vm-trace",
        .lane = "move-vm",
        .doc = "per-instruction trace (frames, instructions with gas left, push/pop/read/write/data-load effects with annotated values, reference locations and snapshots, execution errors) equals Rust move-trace-format, event for event and byte for byte",
        .run = runTrace,
        // bench: the traced calls at protocol 141 to their trace (`trace`, `trace-instr`)
        .bench = benchTrace,
        .baselines = &.{
            .{ .name = "trace", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "trace" } },
            .{ .name = "trace-instr", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "trace-instr" } },
        },
        .inputs = .{ .dir = "vectors/move-vm-trace", .suffix = ".jsonl" },
    },
    .{
        .name = "move-vm-gas",
        .lane = "move-vm",
        .doc = "function calls into corpus/framework packages: status, abort/error location, return and mutated-reference bytes, gas left, instruction count, stack height and size (current and high-water) equal Rust's SuiGasMeter",
        .run = runGas,
        .bench = benchGas,
        .baselines = &.{
            .{ .name = "call", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "call" } },
            .{ .name = "instr", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "instr" } },
            .{ .name = "call-interp", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "call-interp" } },
            .{ .name = "instr-interp", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "instr-interp" } },
            .{ .name = "call-native", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "call-native" } },
            .{ .name = "instr-native", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "instr-native" } },
        },
        .inputs = .{ .dir = "vectors/move-vm-gas", .suffix = ".jsonl" },
    },
    .{
        .name = "move-vm-aot",
        .lane = "move-vm",
        .doc = "move-vm-gas with the ahead-of-time tier on: every call whose module is in src/move/vm/aot_gen.zig (deepwave-aot gen --packages vectors/move-vm-gas/packages.bin) runs compiled code and must equal Rust's status, locations, returns and gas exactly like the interpreter; fails when nothing compiled matched",
        .run = runGasAot,
        .bench = benchGasAot,
        .baselines = &.{
            .{ .name = "call", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "call" } },
            .{ .name = "instr", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "instr" } },
            .{ .name = "call-interp", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "call-interp" } },
            .{ .name = "instr-interp", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "instr-interp" } },
            .{ .name = "call-native", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "call-native" } },
            .{ .name = "instr-native", .argv = &.{ "{release}/zui-truth-move-vm", "bench", "instr-native" } },
        },
        .inputs = .{ .dir = "vectors/move-vm-gas", .suffix = ".jsonl" },
    },
    // exec-history-vm (CONTRACTS 6.6b.2): the same calls run by Mysten's older cuts
    // (`tools/truth/move-vm cut`), each at a protocol version of its window with that
    // version's framework. Items are `<cut>/<id>/<module>::<fn>`.
    .{
        .name = "move-vm-gas-cuts",
        .lane = "exec-history-vm",
        .doc = "move-vm-gas on the execution cuts v0..v3 (move-vm-runtime-vN, sui-move-natives-vN, the cut's SuiGasMeter, framework snapshot of the cut's protocol version)",
        .run = runGasCuts,
        .inputs = .{ .dir = "vectors/move-vm-gas/cuts", .suffix = ".jsonl" },
    },
    .{
        .name = "move-vm-trace-cuts",
        .lane = "exec-history-vm",
        .doc = "move-vm-trace on the execution cuts v0..v3",
        .run = runTraceCuts,
        .inputs = .{ .dir = "vectors/move-vm-trace/cuts", .suffix = ".jsonl" },
    },
};

/// exec-history-vm: the cuts with vectors under `vectors/move-vm-*/cuts/<cut>/`.
pub const CUTS = [_][]const u8{ "v0", "v1", "v2", "v3" };

/// The cut's calls and its runtime: the cut's framework overlay (`cuts/<cut>/packages.bin`)
/// over the base packages, binary config and verifier of the calls' protocol version. null when
/// the cut has no vectors.
fn loadCutVectors(ctx: *harness.Ctx, comptime suite_dir: []const u8, cut: []const u8) !?Vectors {
    var path_buf: [160]u8 = undefined;
    const cpath = try std.fmt.bufPrint(&path_buf, "vectors/" ++ suite_dir ++ "/cuts/{s}/calls.jsonl", .{cut});
    const calls = ctx.corpus.readFileAlloc(ctx.io, cpath, ctx.gpa, .limited(1 << 30)) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    errdefer ctx.gpa.free(calls);
    var it = harness.lines(calls);
    const first = it.next() orelse {
        ctx.gpa.free(calls);
        return null;
    };
    const pv = blk: {
        var a = std.heap.ArenaAllocator.init(ctx.gpa);
        defer a.deinit();
        break :blk (try Call.parse(a.allocator(), first)).pv;
    };
    const opath = try std.fmt.bufPrint(&path_buf, "vectors/move-vm-gas/cuts/{s}/packages.bin", .{cut});
    const overlay = try ctx.corpus.readFileAlloc(ctx.io, opath, ctx.gpa, .limited(1 << 30));
    defer ctx.gpa.free(overlay);
    const base = try ctx.corpus.readFileAlloc(ctx.io, "vectors/move-vm-gas/packages.bin", ctx.gpa, .limited(1 << 30));
    errdefer ctx.gpa.free(base);
    // One buffer the runtime borrows: overlay first, then the base packages it does not replace.
    const pk = try ctx.gpa.alloc(u8, overlay.len + base.len);
    errdefer ctx.gpa.free(pk);
    @memcpy(pk[0..overlay.len], overlay);
    @memcpy(pk[overlay.len..], base);
    ctx.gpa.free(base);
    const rt = try ctx.gpa.create(loader.Runtime);
    errdefer ctx.gpa.destroy(rt);
    rt.* = loader.Runtime.init(ctx.gpa, try binaryConfig(pv));
    errdefer rt.deinit();
    rt.validation = try validation(rt.arena_state.allocator(), pv, .mainnet);
    rt.jit_limits = false; // v0..v3 loaders
    try loadPackagesSkipping(rt, pk[0..overlay.len], false);
    try loadPackagesSkipping(rt, pk[overlay.len..], true);
    return .{ .rt = rt, .packages_bytes = pk, .calls_text = calls };
}

fn runGasCuts(ctx: *harness.Ctx) !void {
    inline for (CUTS) |cut| {
        if (try loadCutVectors(ctx, "move-vm-gas", cut)) |v| {
            var vec = v;
            defer vec.deinit(ctx.gpa);
            try runGasOn(ctx, &vec, vec.calls_text, cut ++ "/");
        }
    }
}

fn runTraceCuts(ctx: *harness.Ctx) !void {
    inline for (CUTS) |cut| {
        if (try loadCutVectors(ctx, "move-vm-trace", cut)) |v| {
            var vec = v;
            defer vec.deinit(ctx.gpa);
            try runTraceOn(ctx, &vec, vec.calls_text, cut ++ "/", "vectors/move-vm-trace/cuts/" ++ cut ++ "/trace/");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Vectors

pub const Vectors = struct {
    rt: *loader.Runtime,
    packages_bytes: []u8,
    calls_text: []u8,

    pub fn deinit(v: *Vectors, gpa: Allocator) void {
        v.rt.deinit();
        gpa.destroy(v.rt);
        gpa.free(v.packages_bytes);
        gpa.free(v.calls_text);
    }
};

fn binaryConfig(pv: u64) !move_format.BinaryConfig {
    const cfg = try protocol.get(pv, .mainnet);
    const b = try protocol.derived.binaryConfig(cfg, null);
    var out: move_format.BinaryConfig = .{
        .max_binary_format_version = b.max_binary_format_version,
        .min_binary_format_version = b.min_binary_format_version,
        .check_no_extraneous_bytes = b.check_no_extraneous_bytes,
        .deprecate_global_storage_ops = b.deprecate_global_storage_ops,
        .type_parameter_index_max = b.type_parameter_index_max,
        .table_config = undefined,
    };
    inline for (@typeInfo(@TypeOf(b.table_config)).@"struct".field_names) |f| {
        @field(out.table_config, f) = @field(b.table_config, f);
    }
    return out;
}

/// Reads packages.bin (written by the truth tool) into `rt`, which borrows `bytes`.
pub fn loadPackages(rt: *loader.Runtime, bytes: []const u8) !void {
    return loadPackagesSkipping(rt, bytes, false);
}

/// `loadPackages`; with `skip_present`, a package whose version id is already loaded is skipped
/// (exec-history-vm: a cut's framework overlay replaces the base framework).
pub fn loadPackagesSkipping(rt: *loader.Runtime, bytes: []const u8, skip_present: bool) !void {
    const arena = rt.arena_state.allocator();
    if (bytes.len < 12 or !std.mem.eql(u8, bytes[0..8], "ZUIMVPK1")) return error.BadPackages;
    var r = loader.Reader{ .bytes = bytes, .pos = 8 };
    const n = try rd32(&r);
    for (0..n) |_| {
        // Every field without a default is set below; the rest keep their defaults (`pre` is
        // read by `addPackage`: left undefined it is a wild pointer).
        var in: loader.PackageInput = .{ .version_id = undefined, .original_id = undefined, .version = undefined, .linkage = undefined, .type_origins = undefined, .modules = undefined };
        in.version_id = (try r.take(32))[0..32].*;
        in.original_id = (try r.take(32))[0..32].*;
        in.version = std.mem.readInt(u64, (try r.take(8))[0..8], .little);
        const nl = try rd32(&r);
        const link = try arena.alloc([2]loader.Address, nl);
        for (link) |*l| l.* = .{ (try r.take(32))[0..32].*, (try r.take(32))[0..32].* };
        in.linkage = link;
        const nt = try rd32(&r);
        const origins = try arena.alloc(loader.TypeOrigin, nt);
        for (origins) |*o| {
            const m = try r.take(try rd32(&r));
            const t = try r.take(try rd32(&r));
            o.* = .{ .module = m, .name = t, .defining = (try r.take(32))[0..32].* };
        }
        in.type_origins = origins;
        const nm = try rd32(&r);
        const mods = try arena.alloc(loader.NamedModule, nm);
        for (mods) |*m| {
            const name = try r.take(try rd32(&r));
            m.* = .{ .name = name, .bytes = try r.take(try rd32(&r)) };
        }
        in.modules = mods;
        if (skip_present and rt.package(&in.version_id) != null) continue;
        _ = try rt.addPackage(in);
    }
}

fn rd32(r: *loader.Reader) !u32 {
    return std.mem.readInt(u32, (try r.take(4))[0..4], .little);
}

pub fn loadVectors(ctx: *harness.Ctx) !Vectors {
    return loadVectorsAt(ctx, "vectors/move-vm-gas/packages.bin", "vectors/move-vm-gas/calls.jsonl", protocol.max_protocol_version);
}

/// The protocol 142 set (`zui-truth-move-vm build-v142`, Mysten 1.84): every call at 142 over the
/// 142 framework snapshot, with its own packages.bin. Null when the corpus has none (truth older
/// than 1.84).
fn loadVectors142(ctx: *harness.Ctx) !?Vectors {
    return loadVectorsAt(ctx, "vectors/move-vm-gas/v142/packages.bin", "vectors/move-vm-gas/v142/calls.jsonl", 142) catch |e| switch (e) {
        error.FileNotFound => null,
        else => e,
    };
}

fn loadVectorsAt(ctx: *harness.Ctx, comptime pk_path: []const u8, comptime calls_path: []const u8, pv: u64) !Vectors {
    const pk = try ctx.corpus.readFileAlloc(ctx.io, pk_path, ctx.gpa, .limited(1 << 30));
    errdefer ctx.gpa.free(pk);
    const calls = try ctx.corpus.readFileAlloc(ctx.io, calls_path, ctx.gpa, .limited(1 << 30));
    errdefer ctx.gpa.free(calls);
    const rt = try ctx.gpa.create(loader.Runtime);
    errdefer ctx.gpa.destroy(rt);
    rt.* = loader.Runtime.init(ctx.gpa, try binaryConfig(pv));
    errdefer rt.deinit();
    rt.validation = try validation(rt.arena_state.allocator(), pv, .mainnet);
    try loadPackages(rt, pk);
    return .{ .rt = rt, .packages_bytes = pk, .calls_text = calls };
}

/// The VM's load-time validation for a protocol version on a chain (`verifier_config(None)`,
/// Sui natives).
///
/// The chain matters to one field only. In sui 1.83.1 `ProtocolConfig::get_for_version_impl`
/// (crates/sui-protocol-config/src/lib.rs) sets every value `verifier_config` reads outside its
/// `chain` conditions, except `move_binary_format_version` (the config's `bytecode_version`):
/// 7 from protocol 49 off mainnet and testnet (lib.rs:3686), from 52 off mainnet (lib.rs:3772)
/// and from 55 everywhere (lib.rs:3853). So testnet's config differs from mainnet's at
/// protocols 52 to 54, in `bytecode_version`. No verifier pass reads that field (its one reader
/// in 1.83.1 is the test helper `verify_module_with_config_for_test`, move-bytecode-verifier
/// src/verifier.rs:52, and deepwave's port has none), so the verifier's answer is the same on every
/// chain and `VerifiedSet` may key it by the protocol version alone (`cache_pv`). The test
/// "verifier config across chains" holds both halves: a new field that differs by chain fails
/// it, and the chain must then join the `VerifiedSet` key.
pub fn validation(arena: Allocator, pv: u64, chain: protocol.Chain) !*const loader.Validation {
    const cfg = try protocol.get(pv, chain);
    const v = try protocol.derived.verifierConfig(cfg, null);
    var out: move_format.verifier.verify.Config = .{};
    inline for (@typeInfo(@TypeOf(v)).@"struct".field_names) |f| @field(out, f) = @field(v, f);
    const val = try arena.create(loader.Validation);
    val.* = try loader.Validation.init(arena, out);
    val.cache_pv = pv;
    return val;
}

/// Rust `VMError` as the truth tool writes it (`vm_error_json`).
pub fn loadFailJson(arena: Allocator, f: loader.LoadFail) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.print(arena, "{{\"major\":{d},\"sub\":", .{@intFromEnum(f.err.major)});
    if (f.err.sub_status) |sub| try out.print(arena, "{d}", .{sub}) else try out.appendSlice(arena, "null");
    switch (f.loc) {
        .undefined => try out.appendSlice(arena, ",\"loc\":\"undefined\""),
        .package => |a| try out.print(arena, ",\"loc\":\"package:{x}\"", .{&a}),
        .module => |m| try out.print(arena, ",\"loc\":\"module:{x}::{s}\"", .{ &m.addr, m.name }),
    }
    try out.appendSlice(arena, ",\"off\":[");
    for (f.err.offsets[0..f.err.n_offsets], 0..) |o, i| {
        if (i > 0) try out.append(arena, ',');
        try out.print(arena, "[{d},{d}]", .{ o.fdef, o.offset });
    }
    try out.appendSlice(arena, "]}");
    return out.items;
}

fn jsonCanon(arena: Allocator, v: std.json.Value) ![]const u8 {
    return std.json.Stringify.valueAlloc(arena, v, .{});
}

fn runLoad(ctx: *harness.Ctx) !void {
    const pk = try ctx.corpus.readFileAlloc(ctx.io, "vectors/move-vm-load/packages.bin", ctx.gpa, .limited(1 << 30));
    defer ctx.gpa.free(pk);
    const items = try ctx.corpus.readFileAlloc(ctx.io, "vectors/move-vm-load/items.jsonl", ctx.gpa, .limited(1 << 30));
    defer ctx.gpa.free(items);
    var rt = loader.Runtime.init(ctx.gpa, try binaryConfig(protocol.max_protocol_version));
    defer rt.deinit();
    rt.validation = try validation(rt.arena_state.allocator(), protocol.max_protocol_version, .mainnet);
    try loadPackages(&rt, pk);
    var it = harness.lines(items);
    var name_buf: [128]u8 = undefined;
    while (it.next()) |line| {
        if (ctx.done()) break;
        ctx.nextItem();
        const arena = ctx.scratch();
        const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{});
        const o = v.object;
        const root_hex = o.get("root").?.string;
        const item = try std.fmt.bufPrint(&name_buf, "{s}/{s}", .{ o.get("src").?.string, root_hex });
        if (!ctx.selected(item)) continue;
        const root = try addr(root_hex);
        const p = rt.entry(&root) orelse {
            ctx.fail(item, "root package not in packages.bin", .{});
            continue;
        };
        const got: ?loader.LoadFail = try rt.checkLinkage(p.linkage);
        const truth = o.get("truth").?.object;
        var chk = ctx.check(item);
        const want_ok = std.mem.eql(u8, truth.get("st").?.string, "ok");
        if (want_ok) {
            if (got) |f| chk.failf("rust loads; zui refuses: {s}", .{try loadFailJson(arena, f)});
        } else {
            const want = try jsonCanon(arena, truth.get("err").?);
            if (got) |f| {
                const g = try loadFailJson(arena, f);
                if (!std.mem.eql(u8, want, g)) chk.failf("refusal differs:\n  rust: {s}\n  zui:  {s}", .{ want, g });
            } else chk.failf("rust refuses ({s}); zui loads", .{want});
        }
        _ = chk.finish();
    }
}

// ---------------------------------------------------------------------------------------------
// One call

fn hexBytes(arena: Allocator, s: []const u8) ![]u8 {
    const out = try arena.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn addr(s: []const u8) !loader.Address {
    var a: loader.Address = undefined;
    _ = try std.fmt.hexToBytes(&a, s);
    return a;
}

pub const Call = struct {
    id: u64,
    pv: u64,
    gm: u64,
    root: loader.Address,
    module_addr: loader.Address,
    module_name: []const u8,
    func: []const u8,
    tys: []const []const u8,
    args: []const Arg,
    /// Per return: by value, `&` or `&mut` (the truth holds the referent's bytes).
    ret_kinds: []const Arg.Kind = &.{},
    budget: u64,
    truth: std.json.Value,

    pub const Arg = struct {
        kind: Kind,
        bytes: []const u8,
        pub const Kind = enum { val, ref, mut };
        fn kindOf(k: []const u8) Kind {
            return if (std.mem.eql(u8, k, "val")) .val else if (std.mem.eql(u8, k, "ref")) .ref else .mut;
        }
    };

    pub fn parse(arena: Allocator, line: []const u8) !Call {
        const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{});
        const o = v.object;
        const module = o.get("module").?.string;
        const sep = std.mem.indexOf(u8, module, "::").?;
        const tys_j = o.get("tys_bcs").?.array.items;
        const tys = try arena.alloc([]const u8, tys_j.len);
        for (tys_j, tys) |t, *d| d.* = try hexBytes(arena, t.string);
        const args_j = o.get("args").?.array.items;
        const args = try arena.alloc(Arg, args_j.len);
        for (args_j, args) |a, *d| {
            const k = a.array.items[0].string;
            d.* = .{ .kind = Arg.kindOf(k), .bytes = try hexBytes(arena, a.array.items[1].string) };
        }
        var kinds: []Arg.Kind = &.{};
        if (o.get("ret_kinds")) |rk| {
            kinds = try arena.alloc(Arg.Kind, rk.array.items.len);
            for (rk.array.items, kinds) |k, *d| d.* = Arg.kindOf(k.string);
        }
        return .{
            .id = @intCast(o.get("id").?.integer),
            .pv = @intCast(o.get("pv").?.integer),
            .gm = @intCast(o.get("gm").?.integer),
            .root = try addr(o.get("root").?.string),
            .module_addr = try addr(module[0..sep]),
            .module_name = module[sep + 2 ..],
            .func = o.get("fn").?.string,
            .tys = tys,
            .args = args,
            .ret_kinds = kinds,
            .budget = @intCast(o.get("budget").?.integer),
            .truth = o.get("truth").?,
        };
    }
};

pub const Result = struct {
    meter: gas.Meter,
    outcome: interp.Outcome,
    returns: []const []const u8 = &.{},
    muts: []const struct { idx: usize, bytes: []const u8 } = &.{},
    /// `ObjectRuntime::finish` after the call (any status), through `Host.finish`.
    rt: natives.abi.ObjectRuntime.Finish = undefined,
};

/// Runs one call the way the truth tool does (`execute_function_bypass_visibility`, gas price 1).
pub fn runCall(arena: Allocator, rt: *loader.Runtime, c: *const Call) !Result {
    return runCallTraced(arena, rt, c, null);
}

/// `runCall` with a tracer (move-trace-format events into `tracer`).
pub fn runCallTraced(arena: Allocator, rt: *loader.Runtime, c: *const Call, tracer: ?*trace.Tracer) !Result {
    var cache = interp.LinkCache.init(arena);
    defer cache.deinit();
    return runCallWith(arena, rt, &cache, c, tracer);
}

/// The storage behind the truth tool's native extensions: an empty `InMemoryStorage` (no children,
/// no packages, zero balances) and, for `clock::borrow` (1.84), the Clock `{ id: 0x6, timestamp_ms:
/// 1_762_400_123_456 }` its `ImplicitSystemObjectResolver::clock` returns.
const truth_world: natives.objrt.Resolver.VTable = .{
    .read_child = twReadChild,
    .received_at = twReceivedAt,
    .package_at = twPackageAt,
    .available_balance = twBalance,
    .clock = twClock,
};
const truth_clock: [40]u8 = blk: {
    var b: [40]u8 = @splat(0);
    b[31] = 6;
    std.mem.writeInt(u64, b[32..40], 1_762_400_123_456, .little);
    break :blk b;
};
fn twReadChild(_: *anyopaque, _: *const natives.objrt.Id, _: *const natives.objrt.Id, _: u64) natives.objrt.ResolveError!?*const natives.objrt.StoredObject {
    return null;
}
fn twReceivedAt(_: *anyopaque, _: *const natives.objrt.Id, _: *const natives.objrt.Id, _: u64, _: u64) natives.objrt.ResolveError!?*const natives.objrt.StoredObject {
    return null;
}
fn twPackageAt(_: *anyopaque, _: *const natives.objrt.Id, _: u64) ?natives.objrt.PackageInfo {
    return null;
}
fn twBalance(_: *anyopaque, _: *const natives.objrt.Id, _: *const natives.objrt.TypeTag) natives.objrt.ResolveError!u128 {
    return 0;
}
fn twClock(_: *anyopaque) natives.objrt.ResolveError!?[]const u8 {
    return &truth_clock;
}

/// `runCallTraced` with link contexts (and linkage checks) kept in `cache` across calls.
pub fn runCallWith(arena: Allocator, rt: *loader.Runtime, cache: *interp.LinkCache, c: *const Call, tracer: ?*trace.Tracer) !Result {
    const cfg = try protocol.get(c.pv, .mainnet);
    const gm = try cfg.get("gas_model_version");
    if (gm != c.gm) return error.GasModelMismatch;
    const root = rt.package(&c.root) orelse return error.RootMissing;
    // make_vm: every package of the linkage loads.
    const entry = try cache.get(rt, root);
    if (entry.fail != null) return error.LinkageRefused;
    const link = &entry.link;
    const func = try link.function(&c.module_addr, c.module_name, c.func);
    const ty_args = try arena.alloc(*const loader.Type, c.tys.len);
    for (c.tys, ty_args) |t, *o| o.* = try types.fromTagBytes(arena, rt, t);
    if (c.args.len != func.params.len) return error.ArgCount;
    const heap = value.Heap{ .arena = arena };
    const args = try arena.alloc(Value, c.args.len);
    const ptys = try types.instantiateAll(arena, func.module, func.params, ty_args);
    const slots = try arena.alloc(?*Value, c.args.len);
    var bad_arg = false;
    for (c.args, args, ptys, slots) |a, *v, pt, *slot| {
        slot.* = null;
        // exec-history-vm: the cut vectors include calls with malformed arguments
        const x = (try types.deserializeArg(heap, pt, a.bytes)) orelse {
            bad_arg = true;
            break;
        };
        if (a.kind == .val) {
            v.* = x;
        } else {
            const s = try arena.create(Value);
            s.* = x;
            v.* = Value.refSlot(s);
            if (a.kind == .mut) slot.* = s;
        }
    }
    var res: Result = .{ .meter = gas.Meter.init(gm, c.budget, 1), .outcome = undefined };
    const ecfg = try interp.ExecConfig.fromProtocolAnyCut(cfg); // exec-history-vm: any cut
    var sess = try interp.Session.init(arena, link, &res.meter, ecfg);
    // The native extensions the truth tool builds (sui-natives DEFAULT_CTX).
    const h = try arena.create(host.Host);
    h.* = .{ .cfg = cfg, .tx = DEFAULT_TX };
    h.rt.resolver = .{ .ctx = undefined, .vtable = &truth_world };
    const table = try arena.create(interp.NativeTable);
    table.* = h.table();
    sess.natives = table;
    sess.ext = h;
    if (tracer) |t| {
        t.* = trace.Tracer.init(arena, ecfg);
        sess.tracer = t;
    }
    res.outcome = if (bad_arg) .{ .err = .{ .major = .FAILED_TO_DESERIALIZE_ARGUMENT } } else try sess.run(func, ty_args, args);
    if (res.outcome == .ok) {
        const vals = res.outcome.ok;
        const rtys = try types.instantiateAll(arena, func.module, func.returns, ty_args);
        if (vals.len != rtys.len) return error.ReturnCount;
        const rets = try arena.alloc([]const u8, vals.len);
        for (vals, rtys, rets) |v, t, *o| {
            var out: std.ArrayList(u8) = .empty;
            switch (t.*) {
                // a returned reference: the referent's bytes
                .ref, .mut_ref => |inner| try types.serialize(arena, inner, try value.deref(v, heap), &out),
                else => try types.serialize(arena, t, v, &out),
            }
            o.* = out.items;
        }
        res.returns = rets;
        var muts: std.ArrayList(@typeInfo(@TypeOf(res.muts)).pointer.child) = .empty;
        for (slots, ptys, 0..) |s, pt, i| if (s) |sl| {
            var out: std.ArrayList(u8) = .empty;
            try types.serialize(arena, pt.mut_ref, sl.*, &out);
            try muts.append(arena, .{ .idx = i, .bytes = out.items });
        };
        res.muts = muts.items;
    }
    res.rt = try h.finish(arena);
    return res;
}

fn ju64(v: std.json.Value) u64 {
    return switch (v) {
        .integer => |i| @intCast(i),
        .number_string => |t| std.fmt.parseInt(u64, t, 10) catch std.math.maxInt(u64),
        else => std.math.maxInt(u64),
    };
}

fn jint(o: std.json.ObjectMap, k: []const u8) u64 {
    return ju64(o.get(k).?);
}

fn checkResult(chk: *harness.Check, arena: Allocator, truth: std.json.Value, res: *const Result) !void {
    const t = truth.object;
    if (t.get("rt")) |want| {
        try checkRt(chk, arena, want, res.rt);
    } else chk.failf("truth has no object runtime results (vectors older than the round-3 truth tool)", .{});
    const m = &res.meter;
    chk.eql("gas_left", jint(t, "gas_left"), m.gas_left);
    chk.eql("used", jint(t, "used"), m.gasUsedPreGasPrice());
    chk.eql("instructions", jint(t, "ins"), m.instructions_executed);
    chk.eql("stack height hwm", jint(t, "hwm_h"), m.stack_height_high_water_mark);
    chk.eql("stack size hwm", jint(t, "hwm_s"), m.stack_size_high_water_mark);
    chk.eql("stack height", jint(t, "cur_h"), m.stack_height_current);
    chk.eql("stack size", jint(t, "cur_s"), m.stack_size_current);
    chk.eql("native calls", jint(t, "natives"), m.num_native_calls);
    const st = t.get("st").?.string;
    switch (res.outcome) {
        .ok => {
            if (!std.mem.eql(u8, st, "ok")) {
                chk.failf("status: rust {s}, zig ok", .{st});
                return;
            }
            const rets = t.get("ret").?.array.items;
            if (rets.len != res.returns.len) {
                chk.failf("returns: rust {d}, zig {d}", .{ rets.len, res.returns.len });
            } else for (rets, res.returns) |r, z| chk.bytes("return", try hexBytes(arena, r.string), z);
            const muts = t.get("mut").?.array.items;
            if (muts.len != res.muts.len) {
                chk.failf("mutated refs: rust {d}, zig {d}", .{ muts.len, res.muts.len });
            } else for (muts, res.muts) |r, z| {
                chk.eql("mutated arg", ju64(r.array.items[0]), @as(u64, z.idx));
                chk.bytes("mutated value", try hexBytes(arena, r.array.items[1].string), z.bytes);
            }
        },
        .err => |e| {
            if (!std.mem.eql(u8, st, "err")) {
                chk.failf("status: rust {s}, zig err {s}", .{ st, @tagName(e.major) });
                return;
            }
            const re = t.get("err").?.object;
            const major = jint(re, "major");
            if (major != @backingInt(e.major)) chk.failf("major: rust {d}, zig {d} ({s})", .{ major, @backingInt(e.major), @tagName(e.major) });
            const sub = re.get("sub").?;
            const rs: ?u64 = if (sub == .null) null else ju64(sub);
            if (rs != e.sub) chk.failf("sub status: rust {?d}, zig {?d}", .{ rs, e.sub });
            const loc = re.get("loc").?.string;
            var buf: [300]u8 = undefined;
            const zloc = if (e.module) |mm|
                try std.fmt.bufPrint(&buf, "module:{x}::{s}", .{ &mm.pkg.original_id, mm.name })
            else
                "undefined";
            chk.text("location", loc, zloc);
            const off = re.get("off").?.array.items;
            const zn: usize = if (e.off != null) 1 else 0;
            if (off.len != zn) {
                chk.failf("offsets: rust {d}, zig {d}", .{ off.len, zn });
            } else if (e.off) |o| {
                chk.eql("offset fdef", ju64(off[0].array.items[0]), @as(u64, o.fdef));
                chk.eql("offset pc", ju64(off[0].array.items[1]), @as(u64, o.pc));
            }
        },
    }
}

fn hexEq(c: *harness.Check, a: Allocator, what: []const u8, want: std.json.Value, have: []const u8) !void {
    c.bytes(what, try hexBytes(a, want.string), have);
}

fn structBcs(a: Allocator, t: *const natives.abi.TypeTag) ![]u8 {
    return switch (t.*) {
        .@"struct" => |*st| try bcs.encodeAlloc(types_mod.StructTag, a, st),
        else => error.NotAStruct,
    };
}

/// `ObjectRuntime::finish` after the call against Rust's `RuntimeResults` (or its error kind), in
/// the natives suite's format (src/natives/conformance.zig `checkResults`).
fn checkRt(c: *harness.Check, a: Allocator, want: std.json.Value, fin: natives.abi.ObjectRuntime.Finish) !void {
    const objrt = natives.abi.objrt;
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
        try hexEq(c, a, "write value", it[3], try types_mod.layout.encodeAlloc(a, &w.value));
    }
    const events_j = ok.get("events").?.array.items;
    if (events_j.len != r.events.len) return c.failf("finish: {d} events, want {d}", .{ r.events.len, events_j.len });
    for (events_j, r.events) |ej, *e| {
        const it = ej.array.items;
        try hexEq(c, a, "event type", it[0], try structBcs(a, e.ty));
        try hexEq(c, a, "event value", it[1], try types_mod.layout.encodeAlloc(a, &e.value));
    }
    const acc_j = ok.get("acc").?.array.items;
    if (acc_j.len != r.acc_events.len) return c.failf("finish: {d} accumulator events, want {d}", .{ r.acc_events.len, acc_j.len });
    for (acc_j, r.acc_events) |aj, *e| {
        const it = aj.array.items;
        try hexEq(c, a, "acc id", it[0], &e.accumulator_id);
        c.eql("acc action", ju64(it[1]), @intFromEnum(e.action));
        try hexEq(c, a, "acc address", it[2], &e.target_addr);
        try hexEq(c, a, "acc type", it[3], try objrt.tagBcs(a, e.target_ty));
        const kind: u64, const n: u64 = switch (e.value) {
            .u64 => |x| .{ 0, x },
            .event_ref => |x| .{ 1, x },
        };
        c.eql("acc kind", ju64(it[4]), kind);
        c.eql("acc value", ju64(it[5]), n);
    }
    const loaded_j = ok.get("loaded").?.array.items;
    if (loaded_j.len != r.loaded.len) return c.failf("finish: {d} loaded children, want {d}", .{ r.loaded.len, loaded_j.len });
    for (loaded_j, r.loaded) |lj, *l| {
        const it = lj.array.items;
        try hexEq(c, a, "loaded id", it[0], &l.id);
        c.eql("loaded version", ju64(it[1]), l.version);
        c.eql("loaded modified", @intFromBool(it[2].bool), @intFromBool(l.modified));
    }
    inline for (.{ .{ "created", r.created }, .{ "deleted", r.deleted } }) |pair| {
        const ids_j = ok.get(pair[0]).?.array.items;
        if (ids_j.len != pair[1].len) return c.failf("finish: {d} {s}, want {d}", .{ pair[1].len, pair[0], ids_j.len });
        for (ids_j, pair[1]) |ij, *id| try hexEq(c, a, pair[0], ij, id);
    }
    const settle = ok.get("settle").?.array.items;
    c.eql("settlement input", ju64(settle[0]), r.settlement_input_sui);
    c.eql("settlement output", ju64(settle[1]), r.settlement_output_sui);
}

/// The vectors' native list (`natives.txt`, written by the truth tool from src/natives/table.zig)
/// must equal the table this build runs: stale vectors would skip functions deepwave now runs.
fn checkNativeList(ctx: *harness.Ctx) !bool {
    const text = ctx.corpus.readFileAlloc(ctx.io, "vectors/move-vm-gas/natives.txt", ctx.gpa, .limited(1 << 20)) catch {
        ctx.fail("natives.txt", "vectors/move-vm-gas/natives.txt is missing: regenerate the vectors with tools/truth/move-vm", .{});
        return false;
    };
    defer ctx.gpa.free(text);
    var want: std.StringHashMapUnmanaged(void) = .empty;
    defer want.deinit(ctx.gpa);
    var it = harness.lines(text);
    while (it.next()) |l| if (l.len > 0) try want.put(ctx.gpa, l, {});
    var buf: [256]u8 = undefined;
    var n: usize = 0;
    for (natives.table.entries) |e| {
        const k = try std.fmt.bufPrint(&buf, "{d}::{s}::{s}", .{ e.addr, e.module, e.func });
        // A native newer than the vectors' release (its framework does not declare it yet).
        if (e.since != 0 and !want.contains(k)) continue;
        if (!want.contains(k)) {
            ctx.fail("natives.txt", "native {s} is in src/natives/table.zig but not in the vectors' list: regenerate the vectors", .{k});
            return false;
        }
        n += 1;
    }
    if (n != want.count()) {
        ctx.fail("natives.txt", "the vectors list {d} natives, src/natives/table.zig has {d}: regenerate the vectors", .{ want.count(), n });
        return false;
    }
    return true;
}

/// Every call's whole memory (arguments, session, results: all of the call's arena) must stay
/// under this bound, at any budget: a session holds live data, not a history of its execution.
pub const SESSION_MEMORY_BOUND: usize = 64 << 20;

fn runGas(ctx: *harness.Ctx) !void {
    if (!try checkNativeList(ctx)) return;
    var vec = try loadVectors(ctx);
    defer vec.deinit(ctx.gpa);
    try runGasOn(ctx, &vec, vec.calls_text, "");
    if (try loadVectors142(ctx)) |v| {
        var v142 = v;
        defer v142.deinit(ctx.gpa);
        try runGasOn(ctx, &v142, v142.calls_text, "v142/");
    }
}

fn runGasAot(ctx: *harness.Ctx) !void {
    const aot = @import("aot.zig");
    const n = try aot.enable(null);
    defer aot.disable();
    if (n == 0) {
        // A clean checkout ships an empty registry: not a failure (it would fail every full run),
        // the interpreter runs and the detail says the tier was not exercised.
        ctx.detail("aot: registry empty, tier not exercised (deepwave-aot gen --packages <corpus>/vectors/move-vm-gas/packages.bin --out src/move/vm, rebuild)", .{});
        try runGas(ctx);
        return;
    }
    try runGas(ctx);
    const attached = aot.stats.functions_attached.load(.monotonic);
    ctx.detail("aot: {d} compiled modules, {d} matched, {d} functions attached, {d} digest misses", .{ n, aot.stats.modules_matched.load(.monotonic), attached, aot.stats.modules_digest_miss.load(.monotonic) });
    if (attached == 0) ctx.fail("aot_gen", "the compiled modules matched no loaded module: the aot_gen registry is for other bytecode than the corpus", .{});
}

fn runGasOn(ctx: *harness.Ctx, vec: *Vectors, calls_text: []const u8, comptime prefix: []const u8) !void {
    var it = harness.lines(calls_text);
    var name_buf: [512]u8 = undefined;
    var call_arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer call_arena.deinit();
    var peak: usize = 0;
    var peak_item: [512]u8 = undefined;
    var peak_len: usize = 0;
    while (it.next()) |line| {
        if (ctx.done()) break;
        ctx.nextItem();
        const arena = ctx.scratch();
        const c = try Call.parse(arena, line);
        const item = try std.fmt.bufPrint(&name_buf, prefix ++ "{d}/{s}::{s}", .{ c.id, c.module_name, c.func });
        if (!ctx.selected(item)) continue;
        _ = call_arena.reset(.free_all);
        const res = runCall(call_arena.allocator(), vec.rt, &c) catch |e| {
            ctx.fail(item, "zui could not run the call: {s}", .{@errorName(e)});
            continue;
        };
        const mem = call_arena.queryCapacity();
        if (mem > peak) {
            peak = mem;
            peak_len = item.len;
            @memcpy(peak_item[0..item.len], item);
        }
        var chk = ctx.check(item);
        try checkResult(&chk, arena, c.truth, &res);
        if (mem > SESSION_MEMORY_BOUND) chk.failf("call memory {d} bytes, bound {d}", .{ mem, SESSION_MEMORY_BOUND });
        _ = chk.finish();
    }
    ctx.detail("move-vm-gas: peak call memory {d} bytes ({s})\n", .{ peak, peak_item[0..peak_len] });
}

fn runTrace(ctx: *harness.Ctx) !void {
    if (!try checkNativeList(ctx)) return;
    var vec = try loadVectors(ctx);
    defer vec.deinit(ctx.gpa);
    const calls = try ctx.corpus.readFileAlloc(ctx.io, "vectors/move-vm-trace/calls.jsonl", ctx.gpa, .limited(1 << 30));
    defer ctx.gpa.free(calls);
    try runTraceOn(ctx, &vec, calls, "", "vectors/move-vm-trace/trace/");
    if (try loadVectors142(ctx)) |v| {
        var v142 = v;
        defer v142.deinit(ctx.gpa);
        const calls142 = ctx.corpus.readFileAlloc(ctx.io, "vectors/move-vm-trace/v142/calls.jsonl", ctx.gpa, .limited(1 << 30)) catch |e| switch (e) {
            error.FileNotFound => return,
            else => return e,
        };
        defer ctx.gpa.free(calls142);
        try runTraceOn(ctx, &v142, calls142, "v142/", "vectors/move-vm-trace/v142/trace/");
    }
}

fn runTraceOn(ctx: *harness.Ctx, vec: *Vectors, calls: []const u8, comptime prefix: []const u8, comptime trace_dir: []const u8) !void {
    var it = harness.lines(calls);
    var name_buf: [512]u8 = undefined;
    var path_buf: [128]u8 = undefined;
    while (it.next()) |line| {
        if (ctx.done()) break;
        ctx.nextItem();
        const arena = ctx.scratch();
        const c = try Call.parse(arena, line);
        const item = try std.fmt.bufPrint(&name_buf, prefix ++ "{d}/{s}::{s}", .{ c.id, c.module_name, c.func });
        if (!ctx.selected(item)) continue;
        const path = try std.fmt.bufPrint(&path_buf, trace_dir ++ "{d}.json.zst", .{c.id});
        const want_all = try ctx.readZstd(path, 1 << 31);
        var tr: trace.Tracer = undefined;
        const res = runCallTraced(arena, vec.rt, &c, &tr) catch |e| {
            ctx.fail(item, "zui could not run the call: {s}", .{@errorName(e)});
            continue;
        };
        var chk = ctx.check(item);
        try checkResult(&chk, arena, c.truth, &res);
        // Rust's first line is the format version.
        const nl = std.mem.indexOfScalar(u8, want_all, '\n') orelse want_all.len;
        if (!std.mem.eql(u8, want_all[0..nl], "{\"version\":3}")) chk.failf("trace version line: {s}", .{want_all[0..@min(nl, 40)]});
        const want = if (nl < want_all.len) want_all[nl + 1 ..] else "";
        compareEvents(&chk, want, tr.text());
        _ = chk.finish();
    }
}

/// Event-by-event comparison; reports the first differing event with both sides.
fn compareEvents(chk: *harness.Check, want: []const u8, got: []const u8) void {
    var wi = harness.lines(want);
    var gi = harness.lines(got);
    var n: usize = 0;
    while (true) : (n += 1) {
        const w = wi.next();
        const g = gi.next();
        if (w == null and g == null) return;
        if (w == null or g == null or !std.mem.eql(u8, w.?, g.?)) {
            const ws = w orelse "<end>";
            const gs = g orelse "<end>";
            var d: usize = 0;
            while (d < ws.len and d < gs.len and ws[d] == gs[d]) d += 1;
            const lo = d -| 120;
            chk.failf("event {d} differs at byte {d}:\n  rust: ...{s}\n  zui:  ...{s}", .{ n, d, ws[lo..@min(ws.len, d + 200)], gs[lo..@min(gs.len, d + 200)] });
            return;
        }
    }
}

const BenchState = struct {
    ctx: *harness.Ctx,
    rt: *loader.Runtime,
    calls: []const Call,
    arena: *std.heap.ArenaAllocator,
    /// Link contexts per root package version, kept across calls and passes (as a node keeps
    /// them per package version); the first, untimed pass fills it.
    links: *interp.LinkCache,
};

fn benchPass(st: *BenchState) anyerror!void {
    for (st.calls) |*c| {
        _ = st.arena.reset(.retain_capacity);
        _ = try runCallWith(st.arena.allocator(), st.rt, st.links, c, null);
    }
}

/// Same selection as the Rust baseline: protocol 141 calls with the default budget; `-interp`
/// keeps the calls that reach no native (`truth.natives == 0`), `-native` the others.
fn benchGas(ctx: *harness.Ctx) !void {
    var vec = try loadVectors(ctx);
    defer vec.deinit(ctx.gpa);
    var keep = std.heap.ArenaAllocator.init(ctx.gpa);
    defer keep.deinit();
    const ka = keep.allocator();
    var sets: [3]std.ArrayList(Call) = .{ .empty, .empty, .empty };
    var ins: [3]u64 = .{ 0, 0, 0 };
    var it = harness.lines(vec.calls_text);
    while (it.next()) |line| {
        const c = try Call.parse(ka, line);
        if (c.pv != 141 or c.budget != 1_000_000) continue;
        const n = jint(c.truth.object, "ins");
        const sel: usize = if (jint(c.truth.object, "natives") == 0) 1 else 2;
        for ([_]usize{ 0, sel }) |k| {
            ins[k] += n;
            try sets[k].append(ka, c);
        }
    }
    var scratch = std.heap.ArenaAllocator.init(ctx.gpa);
    defer scratch.deinit();
    var links = interp.LinkCache.init(ctx.gpa);
    defer links.deinit();
    const names = [_][2][]const u8{ .{ "call", "instr" }, .{ "call-interp", "instr-interp" }, .{ "call-native", "instr-native" } };
    for (names, sets, ins) |nm, set, n| {
        var st = BenchState{ .ctx = ctx, .rt = vec.rt, .calls = set.items, .arena = &scratch, .links = &links };
        try ctx.benchPasses(nm[0], "call", set.items.len, &st, benchPass);
        try ctx.benchPasses(nm[1], "instr", n, &st, benchPass);
        try benchDist(ctx, nm[0], &st);
    }
}

/// Per-call latency of a bench set: every call timed on its own over `-Diters` passes (after the
/// warm passes above), then p50 / p99 / mean over all samples and calls per second on one thread.
fn benchDist(ctx: *harness.Ctx, name: []const u8, st: *BenchState) !void {
    const iters = @max(1, ctx.opts.iters);
    const n = st.calls.len * iters;
    if (n == 0) return;
    const ns = try ctx.gpa.alloc(u64, n);
    defer ctx.gpa.free(ns);
    var k: usize = 0;
    var total: u64 = 0;
    for (0..iters) |_| {
        for (st.calls) |*c| {
            _ = st.arena.reset(.retain_capacity);
            const t0 = std.Io.Timestamp.now(ctx.io, .awake);
            _ = try runCallWith(st.arena.allocator(), st.rt, st.links, c, null);
            const d: u64 = @intCast(t0.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).nanoseconds);
            ns[k] = d;
            total += d;
            k += 1;
        }
    }
    std.mem.sort(u64, ns, {}, std.sort.asc(u64));
    const mean = @as(f64, @floatFromInt(total)) / @as(f64, @floatFromInt(n));
    try ctx.stdout.print(
        "{{\"impl\":\"zui\",\"suite\":\"{s}\",\"bench\":\"{s}-dist\",\"mode\":\"{s}\",\"calls\":{d},\"samples\":{d},\"p50_ns\":{d},\"p90_ns\":{d},\"p99_ns\":{d},\"max_ns\":{d},\"mean_ns\":{d:.0},\"calls_per_s\":{d:.0}}}\n",
        .{ ctx.suite.name, name, @tagName(@import("builtin").mode), st.calls.len, n, ns[n / 2], ns[n * 9 / 10], ns[@min(n - 1, n * 99 / 100)], ns[n - 1], mean, 1e9 / mean },
    );
}

/// `bench -Dsuite=move-vm-aot`: move-vm-gas's bench with the AOT tier on (whatever the
/// generated registry holds; the interpreter for everything else).
fn benchGasAot(ctx: *harness.Ctx) !void {
    const aot = @import("aot.zig");
    const m = try aot.enable(null);
    defer aot.disable();
    try benchGas(ctx);
    try ctx.stdout.print("{{\"impl\":\"zui\",\"suite\":\"move-vm-aot\",\"aot_modules\":{d},\"matched\":{d},\"functions_attached\":{d},\"digest_miss\":{d}}}\n", .{ m, aot.stats.modules_matched.load(.monotonic), aot.stats.functions_attached.load(.monotonic), aot.stats.modules_digest_miss.load(.monotonic) });
}

const TraceBench = struct {
    rt: *loader.Runtime,
    calls: []const Call,
    arena: *std.heap.ArenaAllocator,
    links: *interp.LinkCache,
};

fn traceBenchPass(st: *TraceBench) anyerror!void {
    for (st.calls) |*c| {
        _ = st.arena.reset(.retain_capacity);
        var tr: trace.Tracer = undefined;
        _ = try runCallWith(st.arena.allocator(), st.rt, st.links, c, &tr);
        std.mem.doNotOptimizeAway(tr.text().len);
    }
}

/// move-vm-trace calls at protocol 141, run traced to their trace text. The Rust baseline
/// (`bench trace`) runs the same calls with a `MoveTraceBuilder` and takes its trace bytes.
fn benchTrace(ctx: *harness.Ctx) !void {
    var vec = try loadVectors(ctx);
    defer vec.deinit(ctx.gpa);
    var keep = std.heap.ArenaAllocator.init(ctx.gpa);
    defer keep.deinit();
    const ka = keep.allocator();
    const text = try ctx.corpus.readFileAlloc(ctx.io, "vectors/move-vm-trace/calls.jsonl", ka, .limited(1 << 30));
    var set: std.ArrayList(Call) = .empty;
    var ins: u64 = 0;
    var it = harness.lines(text);
    while (it.next()) |line| {
        const c = try Call.parse(ka, line);
        if (c.pv != 141) continue;
        ins += jint(c.truth.object, "ins");
        try set.append(ka, c);
    }
    var scratch = std.heap.ArenaAllocator.init(ctx.gpa);
    defer scratch.deinit();
    var links = interp.LinkCache.init(ctx.gpa);
    defer links.deinit();
    var st: TraceBench = .{ .rt = vec.rt, .calls = set.items, .arena = &scratch, .links = &links };
    try ctx.benchPasses("trace", "call", set.items.len, &st, traceBenchPass);
    try ctx.benchPasses("trace-instr", "instr", ins, &st, traceBenchPass);
}

/// The embedded framework (natives.framework, built-in = 141) loaded into a Runtime.
fn frameworkRuntime(gpa: Allocator) !*loader.Runtime {
    const rt = try gpa.create(loader.Runtime);
    rt.* = loader.Runtime.init(gpa, try binaryConfig(protocol.max_protocol_version));
    const a = rt.arena_state.allocator();
    const vers = try natives.framework.load(a);
    const v = natives.framework.snapshot(vers, 141).?;
    for (v.packages) |p| {
        const mods = try a.alloc(loader.NamedModule, p.modules.len);
        for (p.modules, mods) |b, *m| {
            const cfg: move_format.BinaryConfig = .{};
            const cm = switch (try move_format.deserialize(a, b, &cfg)) {
                .ok => |cm| cm,
                else => return error.BadModule,
            };
            m.* = .{ .name = cm.selfName(), .bytes = b };
        }
        const link = try a.alloc([2]loader.Address, p.deps.len + 1);
        link[0] = .{ p.id, p.id };
        for (p.deps, link[1..]) |d, *l| l.* = .{ d, d };
        _ = try rt.addPackage(.{ .version_id = p.id, .original_id = p.id, .version = 1, .linkage = link, .type_origins = &.{}, .modules = mods });
    }
    return rt;
}

test "loadPackages reads a packages.bin into a runtime (the input's optional fields at their defaults)" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const vers = try natives.framework.load(a);
    const v = natives.framework.snapshot(vers, 141).?;
    // packages.bin as the truth tool writes it: every package of the snapshot.
    var bin: std.ArrayList(u8) = .empty;
    const W = struct {
        fn int(al: Allocator, l: *std.ArrayList(u8), comptime T: type, x: T) !void {
            var b: [@sizeOf(T)]u8 = undefined;
            std.mem.writeInt(T, &b, x, .little);
            try l.appendSlice(al, &b);
        }
    };
    try bin.appendSlice(a, "ZUIMVPK1");
    try W.int(a, &bin, u32, @intCast(v.packages.len));
    for (v.packages) |p| {
        try bin.appendSlice(a, &p.id);
        try bin.appendSlice(a, &p.id);
        try W.int(a, &bin, u64, 1);
        try W.int(a, &bin, u32, @intCast(p.deps.len + 1));
        try bin.appendSlice(a, &p.id);
        try bin.appendSlice(a, &p.id);
        for (p.deps) |d| {
            try bin.appendSlice(a, &d);
            try bin.appendSlice(a, &d);
        }
        try W.int(a, &bin, u32, 0); // type origins
        try W.int(a, &bin, u32, @intCast(p.modules.len));
        for (p.modules) |b| {
            const cfg: move_format.BinaryConfig = .{};
            const cm = switch (try move_format.deserialize(a, b, &cfg)) {
                .ok => |cm| cm,
                else => return error.BadModule,
            };
            try W.int(a, &bin, u32, @intCast(cm.selfName().len));
            try bin.appendSlice(a, cm.selfName());
            try W.int(a, &bin, u32, @intCast(b.len));
            try bin.appendSlice(a, b);
        }
    }
    var rt = loader.Runtime.init(gpa, try binaryConfig(protocol.max_protocol_version));
    defer rt.deinit();
    const before = loader.predecoded_loads.load(.monotonic);
    try loadPackages(&rt, bin.items);
    // Loaded from the bytes: packages.bin carries no predecoded modules.
    try std.testing.expectEqual(before, loader.predecoded_loads.load(.monotonic));
    const want = try frameworkRuntime(gpa);
    defer {
        want.deinit();
        gpa.destroy(want);
    }
    for (v.packages) |p| {
        const got = rt.package(&p.id) orelse return error.PackageNotLoaded;
        try std.testing.expect(got.refused == null);
        try loader.expectSamePackage(want.package(&p.id).?, got);
    }
    // With `skip_present` a second read of the same file adds nothing.
    const count = rt.by_version.count();
    try loadPackagesSkipping(&rt, bin.items, true);
    try std.testing.expectEqual(count, rt.by_version.count());
}

test "verifier config across chains: only bytecode_version differs (testnet 52 to 54), and validation follows the chain" {
    var differs: usize = 0;
    var pv: u64 = protocol.min_protocol_version;
    while (pv <= protocol.max_protocol_version) : (pv += 1) {
        const main = protocol.derived.verifierConfig(try protocol.get(pv, .mainnet), null);
        inline for (.{ protocol.Chain.testnet, protocol.Chain.unknown }) |chain| {
            const other = protocol.derived.verifierConfig(try protocol.get(pv, chain), null);
            // A version without a verifier config has none on any chain.
            try std.testing.expectEqual(std.meta.isError(main), std.meta.isError(other));
            if (main) |m| {
                const o = try other;
                inline for (@typeInfo(@TypeOf(m)).@"struct".field_names) |f| {
                    if (comptime std.mem.eql(u8, f, "bytecode_version")) continue;
                    // Every field a verifier pass reads is the same on every chain, so the
                    // process-wide verified-package set is right to key by protocol version only.
                    try std.testing.expectEqual(@field(m, f), @field(o, f));
                }
                if (chain == .testnet) {
                    // Enums (binary format 7): testnet from protocol 52, mainnet from 55.
                    const early = pv >= 52 and pv <= 54;
                    try std.testing.expectEqual(early, m.bytecode_version != o.bytecode_version);
                    if (early) {
                        try std.testing.expectEqual(@as(u32, 6), m.bytecode_version);
                        try std.testing.expectEqual(@as(u32, 7), o.bytecode_version);
                        differs += 1;
                    }
                }
            } else |_| {}
        }
    }
    try std.testing.expectEqual(@as(usize, 3), differs);
    // `validation` hands the runtime the chain's own config.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try std.testing.expectEqual(@as(u32, 6), (try validation(a, 53, .mainnet)).verifier.bytecode_version);
    try std.testing.expectEqual(@as(u32, 7), (try validation(a, 53, .testnet)).verifier.bytecode_version);
    try std.testing.expectEqual(@as(u32, 7), (try validation(a, 55, .mainnet)).verifier.bytecode_version);
}

test "object-runtime natives in a row keep their state (kiosk::default, kiosk::new)" {
    // kiosk::default: object::new twice (fresh_id), share_object, public_transfer to the sender.
    // Every native's state must outlive the call-scoped scratch the next native reuses.
    const gpa = std.testing.allocator;
    const rt = try frameworkRuntime(gpa);
    defer {
        rt.deinit();
        gpa.destroy(rt);
    }
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var two: loader.Address = @splat(0);
    two[31] = 2;
    // TxContext { sender, tx_hash: vector<u8>, epoch, epoch_timestamp_ms, ids_created }
    var ctx_bytes: std.ArrayList(u8) = .empty;
    try ctx_bytes.appendSlice(a, &DEFAULT_TX.sender);
    try ctx_bytes.append(a, 32);
    try ctx_bytes.appendSlice(a, &DEFAULT_TX.digest);
    inline for (.{ DEFAULT_TX.epoch, DEFAULT_TX.epoch_timestamp_ms, @as(u64, 0) }) |x| {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, x, .little);
        try ctx_bytes.appendSlice(a, &b);
    }
    for ([_][]const u8{ "default", "new" }) |func| {
        const c: Call = .{
            .id = 0,
            .pv = 141,
            .gm = try (try protocol.get(141, .mainnet)).get("gas_model_version"),
            .root = two,
            .module_addr = two,
            .module_name = "kiosk",
            .func = func,
            .tys = &.{},
            .args = &.{.{ .kind = .mut, .bytes = ctx_bytes.items }},
            .budget = 1_000_000,
            .truth = .null,
        };
        const res = try runCall(a, rt, &c);
        try std.testing.expect(res.outcome == .ok);
        try std.testing.expect(res.rt == .ok);
        const r = res.rt.ok;
        try std.testing.expectEqual(@as(usize, 2), r.created.len);
        const ids = [_][32]u8{ natives.abi.TxContext.deriveId(&DEFAULT_TX.digest, 0), natives.abi.TxContext.deriveId(&DEFAULT_TX.digest, 1) };
        try std.testing.expectEqualSlices(u8, &ids[0], &r.created[0]);
        try std.testing.expectEqualSlices(u8, &ids[1], &r.created[1]);
        if (std.mem.eql(u8, func, "default")) {
            // the kiosk is shared, the cap goes to the sender
            try std.testing.expectEqual(@as(usize, 2), r.writes.len);
            var shared: usize = 0;
            var owned: usize = 0;
            for (r.writes) |w| switch (w.owner) {
                .shared => shared += 1,
                .address => |o| {
                    try std.testing.expectEqualSlices(u8, &DEFAULT_TX.sender, &o);
                    owned += 1;
                },
                else => return error.TestUnexpectedResult,
            };
            try std.testing.expectEqual(@as(usize, 1), shared);
            try std.testing.expectEqual(@as(usize, 1), owned);
        } else {
            // kiosk::new returns both objects: nothing transferred
            try std.testing.expectEqual(@as(usize, 0), r.writes.len);
            try std.testing.expectEqual(@as(usize, 2), res.returns.len);
        }
    }
}

/// Runs `code` as `M::f() -> u64` (one u64 local) twice, traced (the unchanged `step` loop)
/// and untraced (the `stepRun` fast paths), with the same budget. Returns both results.
const DiffOut = struct { ok: bool, vals: [4]Value = undefined, n: usize = 0, err: interp.VmError = .{ .major = .EXECUTED }, gas_left: u64 };

fn diffRun(gpa: Allocator, code: []const move_format.file_format.Instr, budget: u64, out: *[2]DiffOut) !void {
    const ff = move_format.file_format;
    const pv = protocol.max_protocol_version;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const u64_sig = [_]ff.Node{.{ .tag = .U64 }};
    const u64_tok = [_]ff.Token{&u64_sig};
    const sigs = [_][]const ff.Token{ &.{}, &u64_tok };
    const idents = [_][]const u8{ "M", "f" };
    const addrs = [_][32]u8{@splat(7)};
    const mhs = [_]ff.ModuleHandle{.{ .address = 0, .name = 0 }};
    const fhs = [_]ff.FunctionHandle{.{ .module = 0, .name = 1, .parameters = 0, .return_ = 1, .type_parameters = &.{} }};
    const fds = [_]ff.FunctionDefinition{.{ .function = 0, .visibility = .Public, .is_entry = false, .acquires = &.{}, .code = .{ .locals = 1, .code = code, .jump_tables = &.{} } }};
    const cm: ff.CompiledModule = .{
        .version = 6,
        .module_handles = &mhs,
        .function_handles = &fhs,
        .signatures = &sigs,
        .identifiers = &idents,
        .address_identifiers = &addrs,
        .function_defs = &fds,
    };
    const bytes = try move_format.serializeAlloc(a, &cm, 6);
    var rt = loader.Runtime.init(gpa, try binaryConfig(pv));
    defer rt.deinit();
    rt.jit_limits = false;
    var id: loader.Address = @splat(7);
    const mods = [_]loader.NamedModule{.{ .name = "M", .bytes = bytes }};
    const link = [_][2]loader.Address{.{ id, id }};
    const p = try rt.addPackage(.{ .version_id = id, .original_id = id, .version = 1, .linkage = &link, .type_origins = &.{}, .modules = &mods });
    id[0] = 0;
    if (p.refused != null) return error.Refused;
    const func = p.module("M").?.functionByName("f").?;
    const cfg = try protocol.get(pv, .mainnet);
    const ecfg = try interp.ExecConfig.fromProtocolAnyCut(cfg);
    const gm = try cfg.get("gas_model_version");
    for (0..2) |i| {
        var lc = interp.LinkCtx.init(&rt, p);
        defer lc.deinit();
        var meter = gas.Meter.init(gm, budget, 1);
        var sess = try interp.Session.init(a, &lc, &meter, ecfg);
        if (i == 0) {
            const t = try a.create(trace.Tracer);
            t.* = trace.Tracer.init(a, ecfg);
            sess.tracer = t;
        }
        const res = try sess.run(func, &.{}, &.{});
        out[i] = switch (res) {
            .ok => |v| blk: {
                var o: DiffOut = .{ .ok = true, .gas_left = meter.gas_left, .n = v.len };
                if (v.len > o.vals.len) return error.TooMany;
                @memcpy(o.vals[0..v.len], v);
                break :blk o;
            },
            .err => |e| .{ .ok = false, .err = e, .gas_left = meter.gas_left },
        };
    }
}

fn expectSame(gpa: Allocator, code: []const move_format.file_format.Instr, budget: u64) !void {
    var r: [2]DiffOut = undefined;
    try diffRun(gpa, code, budget, &r);
    try std.testing.expectEqual(r[0].gas_left, r[1].gas_left);
    try std.testing.expectEqual(r[0].ok, r[1].ok);
    if (r[0].ok) {
        try std.testing.expectEqual(r[0].n, r[1].n);
        for (r[0].vals[0..r[0].n], r[1].vals[0..r[1].n]) |x, y| {
            try std.testing.expectEqual(x.tag, y.tag);
            try std.testing.expectEqual(x.a, y.a);
            try std.testing.expectEqual(x.b, y.b);
        }
    } else {
        try std.testing.expectEqual(r[0].err.major, r[1].err.major);
        try std.testing.expectEqual(r[0].err.sub, r[1].err.sub);
        try std.testing.expectEqual(r[0].err.off, r[1].err.off);
    }
}

fn mk(op: move_format.file_format.Opcode, idx: u16, imm: u64) move_format.file_format.Instr {
    return .{ .op = op, .idx = idx, .imm = imm };
}

test "untraced fast paths match the traced loop (results, gas, error locations)" {
    const gpa = std.testing.allocator;
    const big: u64 = 1_000_000_000;
    // happy path with locals
    try expectSame(gpa, &.{ mk(.LdU64, 0, 9), mk(.StLoc, 0, 0), mk(.CopyLoc, 0, 0), mk(.MoveLoc, 0, 0), mk(.Add, 0, 0), mk(.Ret, 0, 0) }, big);
    // arithmetic overflow and underflow for each width
    try expectSame(gpa, &.{ mk(.LdU8, 0, 200), mk(.LdU8, 0, 100), mk(.Add, 0, 0), mk(.Ret, 0, 0) }, big);
    try expectSame(gpa, &.{ mk(.LdU16, 0, 1), mk(.LdU16, 0, 2), mk(.Sub, 0, 0), mk(.Ret, 0, 0) }, big);
    try expectSame(gpa, &.{ mk(.LdU32, 0, 0x10000), mk(.LdU32, 0, 0x10000), mk(.Mul, 0, 0), mk(.Ret, 0, 0) }, big);
    try expectSame(gpa, &.{ mk(.LdU64, 0, 1), mk(.LdU64, 0, 0), mk(.Div, 0, 0), mk(.Ret, 0, 0) }, big);
    // mismatched operand tags
    try expectSame(gpa, &.{ mk(.LdU8, 0, 1), mk(.LdU64, 0, 2), mk(.Add, 0, 0), mk(.Ret, 0, 0) }, big);
    try expectSame(gpa, &.{ mk(.LdU8, 0, 1), mk(.LdU64, 0, 2), mk(.Lt, 0, 0), mk(.Ret, 0, 0) }, big);
    // empty stack
    try expectSame(gpa, &.{ mk(.Pop, 0, 0), mk(.Ret, 0, 0) }, big);
    try expectSame(gpa, &.{ mk(.LdU64, 0, 1), mk(.Add, 0, 0), mk(.Ret, 0, 0) }, big);
    // moved-from local read
    try expectSame(gpa, &.{ mk(.MoveLoc, 0, 0), mk(.Ret, 0, 0) }, big);
    try expectSame(gpa, &.{ mk(.CopyLoc, 0, 0), mk(.Ret, 0, 0) }, big);
    // operand stack overflow through Ld* and CopyLoc
    try expectSame(gpa, &.{ mk(.LdU64, 0, 1), mk(.Branch, 0, 0) }, big);
    try expectSame(gpa, &.{ mk(.LdU64, 0, 1), mk(.StLoc, 0, 0), mk(.CopyLoc, 0, 0), mk(.Branch, 2, 0) }, big);
    // out of gas inside a fast path, at several budgets
    var b: u64 = 0;
    while (b < 40) : (b += 3) {
        try expectSame(gpa, &.{ mk(.LdU64, 0, 1), mk(.LdU64, 0, 2), mk(.Add, 0, 0), mk(.StLoc, 0, 0), mk(.CopyLoc, 0, 0), mk(.Ret, 0, 0) }, b);
    }
}

test "diff harness sees real results and errors" {
    const gpa = std.testing.allocator;
    var r: [2]DiffOut = undefined;
    try diffRun(gpa, &.{ mk(.LdU64, 0, 9), mk(.LdU64, 0, 9), mk(.Add, 0, 0), mk(.Ret, 0, 0) }, 1_000_000_000, &r);
    try std.testing.expect(r[1].ok and r[1].n == 1 and r[1].vals[0].a == 18);
    try diffRun(gpa, &.{ mk(.LdU8, 0, 200), mk(.LdU8, 0, 100), mk(.Add, 0, 0), mk(.Ret, 0, 0) }, 1_000_000_000, &r);
    try std.testing.expect(!r[1].ok and r[1].err.major == .ARITHMETIC_ERROR and r[1].err.off.?.pc == 2);
    try diffRun(gpa, &.{ mk(.LdU64, 0, 1), mk(.Add, 0, 0), mk(.Ret, 0, 0) }, 1_000_000_000, &r);
    try std.testing.expect(!r[1].ok and r[1].err.major == .EMPTY_VALUE_STACK);
    try diffRun(gpa, &.{ mk(.LdU64, 0, 1), mk(.Branch, 0, 0) }, 1_000_000_000, &r);
    try std.testing.expect(!r[1].ok);
}
