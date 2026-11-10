//! Test support and tests for the DevInspect execution modes of `execute`:
//! `Inputs.skip_all_checks` (`execution_mode::DevInspect<true>`, what SimulateTransaction runs
//! with `checks: DISABLED`) and `Inputs.track_results` (`Mode::TRACK_EXECUTION`, the per-command
//! results behind `command_outputs`).
//!
//! The transactions here call the system packages (0x1, 0x2) over synthetic objects, so the
//! tests need the system packages of one epoch: those the deny-order vectors name, read from the
//! corpus checkpoints (`$ZUI_CORPUS`). Without the corpus they are skipped (`error.SkipZigTest`).
//! The expectations are sui-node 1.83.1's rules, read from `sui-execution/latest/sui-adapter`
//! (each test names the function): the mode's truth vectors are the rpc-simulate records.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const objects = @import("../objects.zig");
const packages = @import("../packages.zig");
const ptb = @import("root.zig");
const vectors = @import("deny_order_vectors.zig");
const synth = @import("synth_suite.zig");
const harness = @import("harness");

const Allocator = std.mem.Allocator;
const Id = [32]u8;

pub fn idOf(b: u8) Id {
    return @splat(b);
}

pub fn framework(b: u8) Id {
    var id: Id = @splat(0);
    id[31] = b;
    return id;
}

pub const sender: Id = idOf(0x55);
pub const gas_id: Id = idOf(0x6a);
pub const gas_version: u64 = 10;
pub const gas_balance: u64 = 1_000_000_000_000;
pub const budget: u64 = 50_000_000;

/// `0x2::sui::SUI` as a type input.
pub fn suiInput() types.TypeInput {
    return .{ .@"struct" = .{ .address = .{ .@"0" = framework(2) }, .module = .{ .@"0" = "sui" }, .name = .{ .@"0" = "SUI" }, .type_args = &.{} } };
}

/// A `Coin<SUI>` object (`MoveObjectType::GasCoin`) as BCS `Object`.
pub fn coinObject(arena: Allocator, id: Id, version: u64, balance: u64, owner: types.Owner) ![]const u8 {
    var contents: [40]u8 = undefined;
    @memcpy(contents[0..32], &id);
    std.mem.writeInt(u64, contents[32..40], balance, .little);
    const obj: types.Object = .{
        .data = .{ .Move = .{ .type_ = .{ .@"0" = .GasCoin }, .has_public_transfer = true, .version = .{ .@"0" = version }, .contents = try arena.dupe(u8, &contents) } },
        .owner = owner,
        .previous_transaction = .{ .@"0" = .{ .@"0" = idOf(0x5a) } },
        .storage_rebate = 988_000,
    };
    return bcs.encodeAlloc(types.Object, arena, &obj);
}

/// The `ImmOrOwnedObject` reference of a stored object.
pub fn refOf(raw: []const u8) !@FieldType(types.ObjectArg, "ImmOrOwnedObject") {
    const v = try objects.ObjectView.parse(raw);
    return .{ .{ .@"0" = .{ .@"0" = v.id } }, .{ .@"0" = v.version }, .{ .@"0" = .{ .@"0" = v.digest() } } };
}

pub fn u64Bytes(arena: Allocator, x: u64) ![]const u8 {
    const b = try arena.alloc(u8, 8);
    std.mem.writeInt(u64, b[0..8], x, .little);
    return b;
}

pub fn moveCall(pkg: u8, module: []const u8, function: []const u8, type_arguments: []const types.TypeInput, arguments: []const types.Argument) types.Command {
    return .{ .MoveCall = .{
        .package = .{ .@"0" = .{ .@"0" = framework(pkg) } },
        .module = .{ .@"0" = module },
        .function = .{ .@"0" = function },
        .type_arguments = type_arguments,
        .arguments = arguments,
    } };
}

/// One epoch's system packages and a pre-state of synthetic objects (one version per id).
pub const Fixture = struct {
    arena: Allocator,
    pkgs: packages.Store,
    cfg: *const protocol.ProtocolConfig,
    pv: u64,
    epoch: u64,
    rgp: u64,
    start_ms: u64,
    objs: std.AutoHashMapUnmanaged(Id, []const u8) = .empty,

    /// `f` must stay where it is until `deinit` (the thread's package caches name `f.pkgs`).
    pub fn init(f: *Fixture, arena: Allocator, io: std.Io) !void {
        var it = std.mem.tokenizeScalar(u8, vectors.text, '\n');
        const v = try std.json.parseFromSliceLeaky(vectors.Line, arena, it.next().?, .{});
        const pkgs = (try vectors.corpusSystemPackages(arena, io, v.system)) orelse return error.SkipZigTest;
        f.* = .{ .arena = arena, .pkgs = pkgs, .cfg = try protocol.get(v.pv, .mainnet), .pv = v.pv, .epoch = v.epoch, .rgp = v.rgp, .start_ms = v.start_ms };
        try f.add(try coinObject(arena, gas_id, gas_version, gas_balance, .{ .AddressOwner = .{ .@"0" = sender } }));
    }

    /// As `init`, over the system packages of the next protocol version (142), which the
    /// corpus has only inside a newer release's synthetic vectors (`synth.path_v142`): the
    /// functions and natives mainnet's packages do not declare yet. Skipped without them.
    pub fn initNext(f: *Fixture, arena: Allocator, io: std.Io) !void {
        const c = std.c.getenv("ZUI_CORPUS") orelse return error.SkipZigTest;
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ std.mem.span(c), synth.path_v142 });
        const z = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 28)) catch return error.SkipZigTest;
        const text = try harness.decompressZstd(arena, z, 1 << 30);
        var it = std.mem.tokenizeScalar(u8, text, '\n');
        const V = struct { pv: u64, epoch: u64, rgp: u64, start_ms: u64, objects: []const []const u8 };
        const v = try std.json.parseFromSliceLeaky(V, arena, it.next() orelse return error.SkipZigTest, .{ .ignore_unknown_fields = true });
        var store: packages.Store = .{};
        for (v.objects) |h| {
            const raw = try vectors.unhex(arena, h);
            const view = objects.ObjectView.parse(raw) catch continue;
            if (!view.is_package or !packages.isSystemPackage(&view.id)) continue;
            const gop = try store.system.getOrPut(arena, view.id);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(arena, .{ .epoch = v.epoch, .raw = raw });
        }
        store.loaded = true;
        f.* = .{ .arena = arena, .pkgs = store, .cfg = try protocol.get(v.pv, .mainnet), .pv = v.pv, .epoch = v.epoch, .rgp = v.rgp, .start_ms = v.start_ms };
        try f.add(try coinObject(arena, gas_id, gas_version, gas_balance, .{ .AddressOwner = .{ .@"0" = sender } }));
    }

    pub fn deinit(f: *Fixture) void {
        _ = f;
        ptb.pkgs.releaseThreadCaches();
    }

    pub fn add(f: *Fixture, raw: []const u8) !void {
        try f.objs.put(f.arena, (try objects.ObjectView.parse(raw)).id, raw);
    }

    fn of(ctx: *const anyopaque) *const Fixture {
        return @ptrCast(@alignCast(ctx));
    }
    fn get(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        const raw = of(ctx).objs.get(id.*) orelse return null;
        const v = objects.ObjectView.parse(raw) catch return null;
        return if (v.version == version) raw else null;
    }
    fn sharedLatest(ctx: *const anyopaque, id: *const Id) ?u64 {
        const raw = of(ctx).objs.get(id.*) orelse return null;
        return (objects.ObjectView.parse(raw) catch return null).version;
    }
    fn childAtMost(ctx: *const anyopaque, child: *const Id, upper: u64) ?[]const u8 {
        const raw = of(ctx).objs.get(child.*) orelse return null;
        const v = objects.ObjectView.parse(raw) catch return null;
        return if (v.version <= upper) raw else null;
    }
    fn addressBalance(_: *const anyopaque, _: *const Id, _: *const types.TypeTag) ?u128 {
        return null;
    }
    const vtable: ptb.PreState.VTable = .{ .shared_latest = sharedLatest, .child_at_most = childAtMost, .address_balance = addressBalance };

    /// The transaction data of a programmable transaction of `sender` paying with the gas coin.
    pub fn data(f: *const Fixture, pt: types.ProgrammableTransaction) !types.TransactionData {
        return f.dataIn(f.arena, pt);
    }

    pub fn dataIn(f: *const Fixture, arena: Allocator, pt: types.ProgrammableTransaction) !types.TransactionData {
        const pay = try arena.alloc(@typeInfo(@FieldType(types.GasData, "payment")).pointer.child, 1);
        const r = try refOf(f.objs.get(gas_id).?);
        pay[0] = .{ r[0], r[1], r[2] };
        return .{ .V1 = .{
            .kind = .{ .ProgrammableTransaction = pt },
            .sender = .{ .@"0" = sender },
            .gas_data = .{ .payment = pay, .owner = .{ .@"0" = sender }, .price = f.rgp, .budget = budget },
            .expiration = .None,
        } };
    }

    pub const Mode = struct { skip_all_checks: bool = false, track_results: bool = true };

    /// Executes `pt` as a simulation over the fixture's objects.
    pub fn run(f: *const Fixture, pt: types.ProgrammableTransaction, mode: Mode) !ptb.Outcome {
        return f.runIn(f.arena, pt, mode);
    }

    /// `run` with everything the execution allocates in `arena`.
    pub fn runIn(f: *const Fixture, arena: Allocator, pt: types.ProgrammableTransaction, mode: Mode) !ptb.Outcome {
        const td = try f.dataIn(arena, pt);
        const raw = try bcs.encodeAlloc(types.TransactionData, arena, &td);
        const env: ptb.Env = .{ .gpa = std.heap.page_allocator, .cfg = f.cfg, .pv = f.pv, .epoch = f.epoch, .epoch_start_ms = f.start_ms, .rgp = f.rgp, .pkgs = &f.pkgs, .authoritative_packages = true };
        return ptb.execute(arena, env, raw, &td.V1, .{
            .objs = .{ .ctx = f, .get = get },
            .effects = null,
            .unchanged_loaded = null,
            .state = .{ .ctx = f, .vtable = &vtable },
            .track_results = mode.track_results,
            .skip_all_checks = mode.skip_all_checks,
        });
    }

    pub fn done(f: *const Fixture, pt: types.ProgrammableTransaction, mode: Mode) !Done {
        const o = switch (try f.run(pt, mode)) {
            .done => |o| o,
            .unsupported => |why| {
                std.debug.print("devinspect test: unsupported: {s}\n", .{why});
                return error.TestUnexpectedResult;
            },
        };
        return .{ .out = o, .fx = (try bcs.decode(types.TransactionEffects, f.arena, o.effects)).V2 };
    }
};

pub const Done = struct {
    out: ptb.Output,
    fx: types.TransactionEffectsV2,

    fn failure(d: *const Done) !types.ExecutionFailure {
        return switch (d.fx.status) {
            .Failure => |x| x,
            .Success => error.TestUnexpectedResult,
        };
    }
    fn success(d: *const Done) ![]const ptb.CommandResult {
        if (d.fx.status != .Success) {
            std.debug.print("devinspect test: expected success, got {s} in command {?d}\n", .{ @tagName(d.fx.status.Failure.@"error"), d.fx.status.Failure.command });
            return error.TestUnexpectedResult;
        }
        return d.out.command_results orelse error.TestUnexpectedResult;
    }
};

fn setup(f: *Fixture, a: *std.heap.ArenaAllocator) !void {
    try f.init(a.allocator(), std.testing.io);
}

const u64_tag: types.TypeTag = .u64;

fn expectU64(tv: *const ptb.TrackedValue, want: u64) !void {
    try std.testing.expect(tv.ty == .u64);
    try std.testing.expectEqual(@as(usize, 8), tv.bytes.len);
    try std.testing.expectEqual(want, std.mem.readInt(u64, tv.bytes[0..8], .little));
}

fn isCoinSui(t: *const types.TypeTag) bool {
    if (t.* != .@"struct") return false;
    const st = &t.@"struct";
    if (!std.mem.eql(u8, &st.address.@"0", &framework(2)) or !std.mem.eql(u8, st.module.@"0", "coin") or !std.mem.eql(u8, st.name.@"0", "Coin") or st.type_args.len != 1) return false;
    const x = &st.type_args[0];
    return x.* == .@"struct" and std.mem.eql(u8, x.@"struct".module.@"0", "sui") and std.mem.eql(u8, x.@"struct".name.@"0", "SUI");
}

/// A tracked `Coin<SUI>`: its balance (and its id when `id` is given).
fn expectCoin(tv: *const ptb.TrackedValue, id: ?Id, balance: u64) !void {
    try std.testing.expect(isCoinSui(&tv.ty));
    try std.testing.expectEqual(@as(usize, 40), tv.bytes.len);
    if (id) |want| try std.testing.expectEqualSlices(u8, &want, tv.bytes[0..32]);
    try std.testing.expectEqual(balance, std.mem.readInt(u64, tv.bytes[32..40], .little));
}

// ---- Mode::allow_arbitrary_function_calls ----------------------------------------------------

// move_functions.rs `check_visibility`: `(Private | Friend, false)` is NonEntryFunctionInvoked
// unless `Mode::allow_arbitrary_function_calls()`.
test "DevInspect<true>: a friend function that is not entry is callable; with checks it is NonEntryFunctionInvoked" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    // `public(package) native fun hash_type_and_key<K: copy + drop>(parent: address, k: K): address`
    const pt: types.ProgrammableTransaction = .{
        .inputs = &.{ .{ .Pure = try arena.dupe(u8, &idOf(0x11)) }, .{ .Pure = try u64Bytes(arena, 7) } },
        .commands = &.{moveCall(2, "dynamic_field", "hash_type_and_key", &.{.u64}, &.{ .{ .Input = 0 }, .{ .Input = 1 } })},
    };
    const checked = try f.done(pt, .{});
    const fail = try checked.failure();
    try std.testing.expect(fail.@"error" == .NonEntryFunctionInvoked);
    try std.testing.expectEqual(@as(?u64, 0), fail.command);
    try std.testing.expect(checked.out.command_results == null);

    const relaxed = try f.done(pt, .{ .skip_all_checks = true });
    const res = try relaxed.success();
    try std.testing.expectEqual(@as(usize, 1), res.len);
    try std.testing.expectEqual(@as(usize, 1), res[0].returns.len);
    try std.testing.expect(res[0].returns[0].ty == .address);
    try std.testing.expectEqual(@as(usize, 32), res[0].returns[0].bytes.len);
    try std.testing.expectEqual(@as(usize, 0), res[0].mutated.len);
}

// move_functions.rs `check_private_generics_v2` has no mode switch: `transfer::transfer` from a
// PTB is NonEntryFunctionInvoked in every mode.
test "DevInspect<true>: the private generics rule still holds" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    const coin = try coinObject(arena, idOf(0x21), 4, 5000, .{ .AddressOwner = .{ .@"0" = sender } });
    try f.add(coin);
    const coin_sui: types.TypeInput = .{ .@"struct" = .{ .address = .{ .@"0" = framework(2) }, .module = .{ .@"0" = "coin" }, .name = .{ .@"0" = "Coin" }, .type_args = &.{suiInput()} } };
    const pt: types.ProgrammableTransaction = .{
        .inputs = &.{ .{ .Object = .{ .ImmOrOwnedObject = try refOf(coin) } }, .{ .Pure = try arena.dupe(u8, &idOf(0x99)) } },
        .commands = &.{moveCall(2, "transfer", "transfer", &.{coin_sui}, &.{ .{ .Input = 0 }, .{ .Input = 1 } })},
    };
    for ([_]bool{ false, true }) |skip| {
        const d = try f.done(pt, .{ .skip_all_checks = skip });
        try std.testing.expect((try d.failure()).@"error" == .NonEntryFunctionInvoked);
    }
}

// ---- Mode::allow_arbitrary_values --------------------------------------------------------------

// input_arguments.rs `check_pure_bytes` returns Ok under `Mode::allow_arbitrary_values()`: a pure
// input instantiates any type from its BCS bytes (context.rs `load_pure_value`).
test "DevInspect<true>: a pure input instantiates a Coin; with checks it is InvalidUsageOfPureArg" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    var coin: [40]u8 = undefined;
    @memcpy(coin[0..32], &idOf(0x31));
    std.mem.writeInt(u64, coin[32..40], 777, .little);
    const pt: types.ProgrammableTransaction = .{
        .inputs = &.{.{ .Pure = try arena.dupe(u8, &coin) }},
        .commands = &.{moveCall(2, "coin", "value", &.{suiInput()}, &.{.{ .Input = 0 }})},
    };
    const fail = try (try f.done(pt, .{})).failure();
    try std.testing.expectEqual(@as(?u64, 0), fail.command);
    try std.testing.expectEqual(@as(u16, 0), fail.@"error".CommandArgumentError.arg_idx);
    try std.testing.expect(fail.@"error".CommandArgumentError.kind == .InvalidUsageOfPureArg);

    const res = try (try f.done(pt, .{ .skip_all_checks = true })).success();
    try expectU64(&res[0].returns[0], 777);
}

// The bytes of a pure input of a primitive type are not validated either: a `String` that is
// not UTF-8 is InvalidBCSBytes with checks and a value without them (its runtime layout is a
// struct of `vector<u8>`).
test "DevInspect<true>: pure bytes are not validated against the primitive layout" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    const pt: types.ProgrammableTransaction = .{
        .inputs = &.{.{ .Pure = &.{ 2, 0xff, 0xfe } }},
        .commands = &.{moveCall(1, "string", "length", &.{}, &.{.{ .Input = 0 }})},
    };
    const fail = try (try f.done(pt, .{})).failure();
    try std.testing.expect(fail.@"error".CommandArgumentError.kind == .InvalidBCSBytes);

    const res = try (try f.done(pt, .{ .skip_all_checks = true })).success();
    try expectU64(&res[0].returns[0], 2);
}

// values.rs `Value::deserialize`: bytes that are not a value of the type (short, or with bytes
// left over) are `invariant_violation!` in the command that first uses the input; the commands
// before it ran, and a failed execution has no results.
test "DevInspect<true>: pure bytes that are not a value of the type fail as InvariantViolation at first use" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    for ([_][]const u8{ &.{ 1, 2, 3 }, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9 } }) |bad| {
        const pt: types.ProgrammableTransaction = .{
            .inputs = &.{ .{ .Pure = try u64Bytes(arena, 7) }, .{ .Pure = bad } },
            .commands = &.{
                moveCall(1, "u64", "max", &.{}, &.{ .{ .Input = 0 }, .{ .Input = 0 } }),
                moveCall(1, "u64", "max", &.{}, &.{ .{ .Input = 0 }, .{ .Input = 1 } }),
            },
        };
        const checked = try (try f.done(pt, .{})).failure();
        try std.testing.expect(checked.@"error".CommandArgumentError.kind == .InvalidBCSBytes);
        try std.testing.expectEqual(@as(u16, 1), checked.@"error".CommandArgumentError.arg_idx);
        try std.testing.expectEqual(@as(?u64, 1), checked.command);

        const relaxed = try f.done(pt, .{ .skip_all_checks = true });
        const fail = try relaxed.failure();
        try std.testing.expect(fail.@"error" == .InvariantViolation);
        try std.testing.expectEqual(@as(?u64, 1), fail.command);
        try std.testing.expect(relaxed.out.command_results == null);
    }
}

// drop_safety.rs `drop_value`: `!abilities.has_drop() && !Mode::allow_arbitrary_values()`.
test "DevInspect<true>: an unused value without drop is left; with checks it is UnusedValueWithoutDrop" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    const pt: types.ProgrammableTransaction = .{
        .inputs = &.{},
        .commands = &.{moveCall(2, "balance", "zero", &.{suiInput()}, &.{})},
    };
    const fail = try (try f.done(pt, .{})).failure();
    try std.testing.expectEqual(@as(u16, 0), fail.@"error".UnusedValueWithoutDrop.result_idx);
    try std.testing.expectEqual(@as(u16, 0), fail.@"error".UnusedValueWithoutDrop.secondary_idx);

    const res = try (try f.done(pt, .{ .skip_all_checks = true })).success();
    try std.testing.expectEqual(@as(usize, 1), res[0].returns.len);
    // Balance<SUI> { value: 0 }
    try std.testing.expectEqualSlices(u8, &@as([8]u8, @splat(0)), res[0].returns[0].bytes);
}

// loading/translate.rs `input`: an `ImmOrOwnedObject` whose object is shared is
// `assert_invariant!(Mode::allow_arbitrary_values(), ..)` and then an owned object with every
// permission; context.rs `finish` hands an input that was not moved back to its owner.
test "DevInspect<true>: a shared object passes as an ImmOrOwnedObject input and stays shared" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    const id = idOf(0x41);
    const coin = try coinObject(arena, id, 6, 4242, .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 3 } } });
    try f.add(coin);
    const pt: types.ProgrammableTransaction = .{
        .inputs = &.{.{ .Object = .{ .ImmOrOwnedObject = try refOf(coin) } }},
        .commands = &.{moveCall(2, "coin", "value", &.{suiInput()}, &.{.{ .Input = 0 }})},
    };
    // with checks the signing checks reject it before execution (`check_one_object`: "Object
    // used as owned is not owned"); the executor alone does not model it
    try std.testing.expect((try f.run(pt, .{})) == .unsupported);

    const d = try f.done(pt, .{ .skip_all_checks = true });
    try expectU64(&(try d.success())[0].returns[0], 4242);
    const w = for (d.out.written) |w| {
        if (std.mem.eql(u8, &w.id, &id)) break w.bytes;
    } else return error.TestUnexpectedResult;
    const obj = try bcs.decode(types.Object, arena, w);
    try std.testing.expectEqual(@as(u64, 3), obj.owner.Shared.initial_shared_version.@"0");
    try std.testing.expectEqual(d.fx.lamport_version.@"0", obj.data.Move.version.@"0");
    // an input by kind, not by owner: no consensus object entry in the effects
    try std.testing.expectEqual(@as(usize, 0), d.fx.unchanged_consensus_objects.len);
}

// ---- Mode::TRACK_EXECUTION ---------------------------------------------------------------------

// interpreter.rs `execute_command` under `Mode::TRACK_EXECUTION`: after each command,
// `argument_updates` (a MoveCall's `&mut` arguments, SplitCoins' coin, MergeCoins' target; the
// TxContext left out) and `tracked_results`, before `charge_command` and before unused results
// are dropped. `skip_all_checks` does not change them, nor the effects.
test "command results: return values and mutated references of a multi-command PTB, with and without checks" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    const owned_id = idOf(0x51);
    const owned = try coinObject(arena, owned_id, 8, 5000, .{ .AddressOwner = .{ .@"0" = sender } });
    try f.add(owned);
    const pt: types.ProgrammableTransaction = .{
        .inputs = &.{
            .{ .Pure = try u64Bytes(arena, 100) },
            .{ .Pure = try u64Bytes(arena, 7) },
            .{ .Pure = try u64Bytes(arena, 9) },
            .{ .Object = .{ .ImmOrOwnedObject = try refOf(owned) } },
        },
        .commands = &.{
            // 0: [Coin 100]
            .{ .SplitCoins = .{ .GasCoin, &.{.{ .Input = 0 }} } },
            // 1: u64::max(7, 9) = 9
            moveCall(1, "u64", "max", &.{}, &.{ .{ .Input = 1 }, .{ .Input = 2 } }),
            // 2: coin::split(&mut Result(0, 0), 7, &mut TxContext): Coin 7, the split coin left at 93
            moveCall(2, "coin", "split", &.{suiInput()}, &.{ .{ .NestedResult = .{ 0, 0 } }, .{ .Input = 1 } }),
            // 3: vector<u64> [9, 9] from a result and an input
            .{ .MakeMoveVec = .{ .u64, &.{ .{ .Result = 1 }, .{ .Input = 2 } } } },
            // 4: both coins into the owned coin: 5000 + 93 + 7
            .{ .MergeCoins = .{ .{ .Input = 3 }, &.{ .{ .NestedResult = .{ 0, 0 } }, .{ .Result = 2 } } } },
            // 5: vector::length(&Result(3)) = 2
            moveCall(1, "vector", "length", &.{.u64}, &.{.{ .Result = 3 }}),
        },
    };
    var effects: [2][]const u8 = undefined;
    for ([_]bool{ false, true }, &effects) |skip, *fx_out| {
        const d = try f.done(pt, .{ .skip_all_checks = skip });
        fx_out.* = d.out.effects;
        const res = try d.success();
        try std.testing.expectEqual(@as(usize, 6), res.len);

        // SplitCoins: the gas coin after the split (its budget is held back while commands run)
        try std.testing.expectEqual(@as(usize, 1), res[0].mutated.len);
        try std.testing.expect(res[0].mutated[0].arg.? == .GasCoin);
        try expectCoin(&res[0].mutated[0], gas_id, gas_balance - budget - 100);
        try std.testing.expectEqual(@as(usize, 1), res[0].returns.len);
        try std.testing.expect(res[0].returns[0].arg == null);
        try expectCoin(&res[0].returns[0], null, 100);
        const split_id: Id = res[0].returns[0].bytes[0..32].*;

        // a call returning a value
        try std.testing.expectEqual(@as(usize, 0), res[1].mutated.len);
        try std.testing.expectEqual(@as(usize, 1), res[1].returns.len);
        try expectU64(&res[1].returns[0], 9);

        // a call mutating a `&mut` argument that is an earlier result: always NestedResult
        try std.testing.expectEqual(@as(usize, 1), res[2].mutated.len);
        try std.testing.expectEqual(@as(u16, 0), res[2].mutated[0].arg.?.NestedResult[0]);
        try std.testing.expectEqual(@as(u16, 0), res[2].mutated[0].arg.?.NestedResult[1]);
        try expectCoin(&res[2].mutated[0], split_id, 93);
        try std.testing.expectEqual(@as(usize, 1), res[2].returns.len);
        try expectCoin(&res[2].returns[0], null, 7);

        // MakeMoveVec
        try std.testing.expectEqual(@as(usize, 0), res[3].mutated.len);
        try std.testing.expect(res[3].returns[0].ty == .vector and res[3].returns[0].ty.vector.* == .u64);
        try std.testing.expectEqualSlices(u8, &.{ 2, 9, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0 }, res[3].returns[0].bytes);

        // MergeCoins: the target by its input index, no return values
        try std.testing.expectEqual(@as(usize, 1), res[4].mutated.len);
        try std.testing.expectEqual(@as(u16, 3), res[4].mutated[0].arg.?.Input);
        try expectCoin(&res[4].mutated[0], owned_id, 5100);
        try std.testing.expectEqual(@as(usize, 0), res[4].returns.len);

        // a nested result used by a later command
        try std.testing.expectEqual(@as(usize, 0), res[5].mutated.len);
        try expectU64(&res[5].returns[0], 2);
    }
    // a transaction that passes every check has the same effects in both modes
    try std.testing.expectEqualSlices(u8, effects[0], effects[1]);

    // tracking is off by default and leaves the effects alone
    const plain = try f.done(pt, .{ .track_results = false });
    try std.testing.expect(plain.out.command_results == null);
    try std.testing.expectEqualSlices(u8, effects[0], plain.out.effects);
}

// ---- per-epoch config reads in a simulation ----------------------------------------------------

fn loadedVersion(loaded: []const ptb.Ref, id: *const Id) ?u64 {
    for (loaded) |l| if (std.mem.eql(u8, &l.id, id)) return l.version;
    return null;
}

// object_store.rs `config_setting_unsequenced_read`: `read_child_object(config, setting,
// SequenceNumber::MAX)` on the backing store. A simulation's backing store is the pre-state
// behind sui-core's `TrackingBackingStore`, so the setting it finds is one of the transaction's
// loaded runtime objects. (`config::read_setting` is `public(package)`: callable from a PTB
// only without checks.)
test "simulation: a per-epoch config setting is read from the pre-state and recorded as loaded" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    const config = idOf(0xc0);
    const name: u64 = 5;
    // the setting's dynamic field id, by the framework's own hash
    const id_res = try (try f.done(.{
        .inputs = &.{ .{ .Pure = try arena.dupe(u8, &config) }, .{ .Pure = try u64Bytes(arena, name) } },
        .commands = &.{moveCall(2, "dynamic_field", "hash_type_and_key", &.{.u64}, &.{ .{ .Input = 0 }, .{ .Input = 1 } })},
    }, .{ .skip_all_checks = true })).success();
    const setting_id: Id = id_res[0].returns[0].bytes[0..32].*;

    const read: types.ProgrammableTransaction = .{
        .inputs = &.{ .{ .Pure = try arena.dupe(u8, &config) }, .{ .Pure = try u64Bytes(arena, name) } },
        .commands = &.{moveCall(2, "config", "read_setting", &.{ .u64, .u64 }, &.{ .{ .Input = 0 }, .{ .Input = 1 } })},
    };
    // no setting in the pre-state: `option::none()`, nothing loaded
    const none = try f.done(read, .{ .skip_all_checks = true });
    try std.testing.expectEqualSlices(u8, &.{0}, (try none.success())[0].returns[0].bytes);
    try std.testing.expect(loadedVersion(none.out.loaded, &setting_id) == null);

    // Field<u64, Setting<u64>> { id, name, value: Setting { data: some(SettingData {
    //   newer_value_epoch: 1, newer_value: some(42), older_value_opt: none }) } }
    var contents: std.ArrayList(u8) = .empty;
    try contents.appendSlice(arena, &setting_id);
    try contents.appendSlice(arena, try u64Bytes(arena, name));
    try contents.append(arena, 1);
    try contents.appendSlice(arena, try u64Bytes(arena, 1));
    try contents.append(arena, 1);
    try contents.appendSlice(arena, try u64Bytes(arena, 42));
    try contents.append(arena, 0);
    const two: types.AccountAddress = .{ .@"0" = framework(2) };
    const setting_ty: types.TypeTag = .{ .@"struct" = .{ .address = two, .module = .{ .@"0" = "config" }, .name = .{ .@"0" = "Setting" }, .type_args = &.{.u64} } };
    const obj: types.Object = .{
        .data = .{ .Move = .{
            .type_ = .{ .@"0" = .{ .Other = .{ .address = two, .module = .{ .@"0" = "dynamic_field" }, .name = .{ .@"0" = "Field" }, .type_args = &.{ .u64, setting_ty } } } },
            .has_public_transfer = false,
            .version = .{ .@"0" = 77 },
            .contents = contents.items,
        } },
        .owner = .{ .ObjectOwner = .{ .@"0" = config } },
        .previous_transaction = .{ .@"0" = .{ .@"0" = idOf(0x5a) } },
        .storage_rebate = 0,
    };
    try f.add(try bcs.encodeAlloc(types.Object, arena, &obj));

    const some = try f.done(read, .{ .skip_all_checks = true });
    // the setting was written before this epoch: `newer_value`, some(42)
    try std.testing.expectEqualSlices(u8, &.{ 1, 42, 0, 0, 0, 0, 0, 0, 0 }, (try some.success())[0].returns[0].bytes);
    try std.testing.expectEqual(@as(?u64, 77), loadedVersion(some.out.loaded, &setting_id));
    // a read: the effects do not change the setting
    for (some.fx.changed_objects) |c| try std.testing.expect(!std.mem.eql(u8, &c[0].@"0".@"0", &setting_id));
}

// ---- natives under arbitrary calls: inputs the fuzz harness (devinspect_fuzz.zig) crashed on ----

fn structInput(addr: u8, module: []const u8, name: []const u8, args: []const types.TypeInput) types.TypeInput {
    return .{ .@"struct" = .{ .address = .{ .@"0" = framework(addr) }, .module = .{ .@"0" = module }, .name = .{ .@"0" = name }, .type_args = args } };
}

fn structTag2(module: []const u8, name: []const u8, args: []const types.TypeTag) types.StructTag {
    return .{ .address = .{ .@"0" = framework(2) }, .module = .{ .@"0" = module }, .name = .{ .@"0" = name }, .type_args = args };
}

/// A dynamic field object of `parent`: type `Field<..>` as `st`, the given contents.
fn fieldObject(arena: Allocator, st: types.StructTag, contents: []const u8, parent: Id) ![]const u8 {
    const obj: types.Object = .{
        .data = .{ .Move = .{ .type_ = .{ .@"0" = .{ .Other = st } }, .has_public_transfer = false, .version = .{ .@"0" = 7 }, .contents = contents } },
        .owner = .{ .ObjectOwner = .{ .@"0" = parent } },
        .previous_transaction = .{ .@"0" = .{ .@"0" = idOf(0x5a) } },
        .storage_rebate = 0,
    };
    return bcs.encodeAlloc(types.Object, arena, &obj);
}

// host.zig `resultTyping`. `withdraw_from_accumulator_address<T>` builds a struct of one u64
// (a `Balance`) whatever `T` is: its Move callers only pass `Balance<_>`. Called with `T = u256`
// under DevInspect<true>, Rust's dynamically typed VM returns the struct as a "u256" (the native
// boundary checks only the number of return values), bytecode that only moves it carries it on,
// and the command fails where `tracked_results` serializes its results with their declared
// layouts: `invariant_violation!("Failed to serialize Move value")`. The bridge here read the
// struct as a u256 (a panic in safe builds). sui-node's answers for these transactions are the
// rpc-exec vectors `devinspect_ill_typed.rec.zst` (rpc_exec's test runs the whole responses).
test "DevInspect<true>: a native result that is not of its declared type fails the command as InvariantViolation" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    var five: [32]u8 = @splat(0);
    five[0] = 5;
    const acc = try arena.dupe(u8, &idOf(0xa1));
    const owner = try arena.dupe(u8, &sender);
    const value = try arena.dupe(u8, &five);
    // Withdrawal<T> { owner, limit: 5 } and Permit<T> (an empty struct: one dummy bool)
    const withdrawal = try std.mem.concat(arena, u8, &.{ owner, value });
    const Call = struct { function: []const u8, inputs: []const types.CallArg };
    const calls = [_]Call{
        // the native itself
        .{ .function = "withdraw_from_accumulator_address", .inputs = &.{ .{ .Pure = acc }, .{ .Pure = owner }, .{ .Pure = value } } },
        // returned by its private Move caller: one `Ret` after the native
        .{ .function = "withdraw_impl", .inputs = &.{ .{ .Pure = owner }, .{ .Pure = value } } },
        // and through two Move frames
        .{ .function = "redeem", .inputs = &.{ .{ .Pure = withdrawal }, .{ .Pure = &.{0} } } },
    };
    const balance = structInput(2, "balance", "Balance", &.{suiInput()});
    for (calls) |c| {
        const args = try arena.alloc(types.Argument, c.inputs.len);
        for (args, 0..) |*x, i| x.* = .{ .Input = @intCast(i) };
        // whether or not the results are tracked: sui-node serializes them in every simulation
        for ([_]bool{ true, false }) |track| {
            for ([_]types.TypeInput{ .u256, .u64, structInput(2, "object", "ID", &.{}) }) |t| {
                const d = try f.done(.{ .inputs = c.inputs, .commands = &.{moveCall(2, "funds_accumulator", c.function, &.{t}, args)} }, .{ .skip_all_checks = true, .track_results = track });
                const fail = try d.failure();
                try std.testing.expect(fail.@"error" == .InvariantViolation);
                try std.testing.expectEqual(@as(?u64, 0), fail.command);
                try std.testing.expect(d.out.command_results == null);
            }
        }
        // a type of the value's layout gets the value: Balance<SUI> { value: 5 }
        const ok = try f.done(.{ .inputs = c.inputs, .commands = &.{moveCall(2, "funds_accumulator", c.function, &.{balance}, args)} }, .{ .skip_all_checks = true });
        try std.testing.expectEqualSlices(u8, &.{ 5, 0, 0, 0, 0, 0, 0, 0 }, (try ok.success())[0].returns[0].bytes);
    }
}

// run.zig `finish` (finish_gas_coin). `dynamic_field::add_child_object` given an object built
// from pure bytes whose UID is the gas coin's id leaves a write under that id that is not a
// coin. Rust's `coin_ref_value` borrows field 1 of the written value and its field 0 as a u64,
// each step `make_invariant_violation!` when the value does not fit: InvariantViolation with no
// command. The refund read the `u64` name of the `Field` as the `Balance` struct (a panic in
// safe builds).
test "DevInspect<true>: a write under the gas coin's id that is not a coin fails as InvariantViolation" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    // Field<u64, u64> { id: UID { the gas coin's id }, name: 1, value: 2 }
    var field: [48]u8 = undefined;
    @memcpy(field[0..32], &gas_id);
    std.mem.writeInt(u64, field[32..40], 1, .little);
    std.mem.writeInt(u64, field[40..48], 2, .little);
    const field_ty = structInput(2, "dynamic_field", "Field", &.{ .u64, .u64 });
    const d = try f.done(.{
        .inputs = &.{ .{ .Pure = try arena.dupe(u8, &idOf(0xc0)) }, .{ .Pure = try arena.dupe(u8, &field) } },
        .commands = &.{moveCall(2, "dynamic_field", "add_child_object", &.{field_ty}, &.{ .{ .Input = 0 }, .{ .Input = 1 } })},
    }, .{ .skip_all_checks = true });
    const fail = try d.failure();
    try std.testing.expect(fail.@"error" == .InvariantViolation);
    try std.testing.expectEqual(@as(?u64, null), fail.command);
}

// objnatives.zig `read_setting_impl`. The setting object is decoded with the layout of the
// caller's `FieldSettingValue` type argument, which a PTB under DevInspect<true> chooses, and
// config.rs `consistent_value_before_current_epoch` then walks it with casts that fail as VM
// errors: `unpack_struct` / `value_as` on a value of another kind or field count
// (UNKNOWN_INVARIANT_VIOLATION_ERROR, INTERNAL_TYPE_ERROR: VMInvariantViolation), and
// `Vector::unpack(ty, 1)` on an option holding two values (VECTOR_OPERATION_ERROR:
// MovePrimitiveRuntimeError). The walk read each step as the kind it expected (a panic in safe
// builds).
test "DevInspect<true>: read_setting_impl over an object that is not a setting fails as the VM error Rust's casts raise" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    const config = idOf(0xc0);
    // a plain Field<u64, u64> under `config`: its third field is a u64, not a Setting
    const plain_id = idOf(0xc1);
    var plain: [48]u8 = undefined;
    @memcpy(plain[0..32], &plain_id);
    std.mem.writeInt(u64, plain[32..40], 5, .little);
    std.mem.writeInt(u64, plain[40..48], 42, .little);
    try f.add(try fieldObject(arena, structTag2("dynamic_field", "Field", &.{ .u64, .u64 }), try arena.dupe(u8, &plain), config));
    // a Field<u64, Setting<u64>> whose `data` option holds two SettingData values
    const two_id = idOf(0xc2);
    var two: std.ArrayList(u8) = .empty;
    try two.appendSlice(arena, &two_id);
    try two.appendSlice(arena, try u64Bytes(arena, 5));
    try two.append(arena, 2);
    for (0..2) |_| {
        try two.appendSlice(arena, try u64Bytes(arena, 1));
        try two.append(arena, 1);
        try two.appendSlice(arena, try u64Bytes(arena, 42));
        try two.append(arena, 0);
    }
    const setting_tag: types.TypeTag = .{ .@"struct" = structTag2("config", "Setting", &.{.u64}) };
    try f.add(try fieldObject(arena, structTag2("dynamic_field", "Field", &.{ .u64, setting_tag }), two.items, config));

    const setting = structInput(2, "config", "Setting", &.{.u64});
    const setting_data = structInput(2, "config", "SettingData", &.{.u64});
    const Case = struct { id: Id, tys: []const types.TypeInput, vm_invariant: bool };
    const cases = [_]Case{
        .{ .id = plain_id, .tys = &.{ structInput(2, "dynamic_field", "Field", &.{ .u64, .u64 }), .u64, .u64, .u64 }, .vm_invariant = true },
        .{ .id = two_id, .tys = &.{ structInput(2, "dynamic_field", "Field", &.{ .u64, setting }), setting, setting_data, .u64 }, .vm_invariant = false },
        // the element kind of the option's vector against `SettingDataValue` comes first
        .{ .id = two_id, .tys = &.{ structInput(2, "dynamic_field", "Field", &.{ .u64, setting }), setting, .u64, .u64 }, .vm_invariant = true },
    };
    for (cases) |c| {
        const d = try f.done(.{
            .inputs = &.{ .{ .Pure = try arena.dupe(u8, &config) }, .{ .Pure = try arena.dupe(u8, &c.id) }, .{ .Pure = try u64Bytes(arena, 9) } },
            .commands = &.{moveCall(2, "config", "read_setting_impl", c.tys, &.{ .{ .Input = 0 }, .{ .Input = 1 }, .{ .Input = 2 } })},
        }, .{ .skip_all_checks = true });
        const fail = try d.failure();
        try std.testing.expectEqual(@as(?u64, 0), fail.command);
        if (c.vm_invariant) try std.testing.expect(fail.@"error" == .VMInvariantViolation) else try std.testing.expect(fail.@"error" == .MovePrimitiveRuntimeError);
    }
}

// objnatives.zig `read_setting_impl`: the per-byte charge sizes the value the native returns,
// `abstract_size(protocol_config, &read_value_opt)` in Rust, a walk of the value as it is. The
// value is `newer_value` or `older_value_opt` of the decoded setting, of the stored value's
// type, and the caller's `Value` can be any other type. The size walk went by `Option<Value>`:
// over a stored `vector<u64>` of one element read as `Option<String>` it took the u64 for a
// struct (a panic in safe builds). Found with sui-node's vector 43 of
// rpc_exec/testdata/devinspect_ill_typed.rec.zst; the fuzz pre-state had no real setting.
test "DevInspect<true>: read_setting_impl sizes the value it returns by the value's own layout" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: Fixture = undefined;
    try setup(&f, &a);
    defer f.deinit();
    const config = idOf(0xc0);
    const id = idOf(0xc1);
    // Field<u64, Setting<u64>> { id, name: 5, value: Setting { data: some(SettingData {
    //   newer_value_epoch: 3, newer_value: some(42), older_value_opt: none }) } }
    var c: std.ArrayList(u8) = .empty;
    try c.appendSlice(arena, &id);
    try c.appendSlice(arena, try u64Bytes(arena, 5));
    try c.append(arena, 1);
    try c.appendSlice(arena, try u64Bytes(arena, 3));
    try c.append(arena, 1);
    try c.appendSlice(arena, try u64Bytes(arena, 42));
    try c.append(arena, 0);
    const setting_tag: types.TypeTag = .{ .@"struct" = structTag2("config", "Setting", &.{.u64}) };
    try f.add(try fieldObject(arena, structTag2("dynamic_field", "Field", &.{ .u64, setting_tag }), c.items, config));
    const setting = structInput(2, "config", "Setting", &.{.u64});
    const tys: []const types.TypeInput = &.{ structInput(2, "dynamic_field", "Field", &.{ .u64, setting }), setting, structInput(2, "config", "SettingData", &.{.u64}), structInput(1, "string", "String", &.{}) };
    const pt: types.ProgrammableTransaction = .{
        .inputs = &.{ .{ .Pure = try arena.dupe(u8, &config) }, .{ .Pure = try arena.dupe(u8, &id) }, .{ .Pure = try u64Bytes(arena, 9) } },
        .commands = &.{moveCall(2, "config", "read_setting_impl", tys, &.{ .{ .Input = 0 }, .{ .Input = 1 }, .{ .Input = 2 } })},
    };
    // the value is not an Option<String>: sui-node cannot serialize the command's result
    const fail = try (try f.done(pt, .{ .skip_all_checks = true })).failure();
    try std.testing.expect(fail.@"error" == .InvariantViolation);
    try std.testing.expectEqual(@as(?u64, 0), fail.command);
}
