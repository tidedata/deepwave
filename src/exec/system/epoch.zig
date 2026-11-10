//! EndOfEpochTransaction (`execution_engine` `TransactionKind::EndOfEpochTransaction`): one
//! system PTB built from the kinds in order (create calls, authenticator expiry, execution time
//! observations, accumulator storage cost), ending with ChangeEpoch's `advance_epoch`
//! (`construct_advance_epoch_pt`: mint the storage and computation rewards, advance, destroy
//! the storage rebates), then `process_system_packages`.
//!
//! `process_system_packages`: a package at a later version replaces the system package in place
//! (`Object::new_system_package`, `upgrade_system_package`).
//!
//! A package at version 1 is a new system package, published in system mode
//! (`publishSystemPackage`). Bridge creation and committee init are setup calls of the same PTB;
//! when advance_epoch aborts, safe mode runs natively (`root.zig`).
//!
//! Not yet: a new system package whose modules have an `init` function (none in the corpus;
//! reported unsupported).
const std = @import("std");
const types = @import("types");
const bcs = @import("bcs");
const sys = @import("root.zig");
const store_mod = @import("store.zig");
const movecall = @import("movecall.zig");
const move_format = @import("move_format");
const objects = @import("../objects.zig");

const Allocator = std.mem.Allocator;
const PArg = movecall.PArg;

fn addr(n: u16) [32]u8 {
    var a: [32]u8 = @splat(0);
    std.mem.writeInt(u16, a[30..32], n, .big);
    return a;
}

const framework = addr(2);
const system = addr(3);
const system_state = addr(5);
const authenticator_state = addr(7);
const bridge = addr(9);
const bridge_pkg = addr(0xb);
/// get_mainnet_chain_identifier / get_testnet_chain_identifier (genesis checkpoint digests).
const mainnet_chain: [32]u8 = hexBytes("35834a8ac17ca48fb14ac8f99c17c98747e95dd07294ae41a46b382246a4499b");
const testnet_chain: [32]u8 = hexBytes("4c78adacf2a2f5ad80f27ed7d54aa69d3a78f1ca67fdef9ecf5754f5b8bb77b0");

fn hexBytes(comptime h: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

const Builder = struct {
    a: Allocator,
    inputs: std.ArrayList(movecall.Arg) = .empty,
    commands: std.ArrayList(movecall.Command) = .empty,

    /// `builder.obj`: one input per object.
    fn obj(b: *Builder, id: [32]u8) !PArg {
        for (b.inputs.items, 0..) |in, i| if (in == .object and std.mem.eql(u8, &in.object, &id)) return .{ .input = @intCast(i) };
        try b.inputs.append(b.a, .{ .object = id });
        return .{ .input = @intCast(b.inputs.items.len - 1) };
    }

    fn pure(b: *Builder, comptime T: type, v: T) !PArg {
        try b.inputs.append(b.a, .{ .pure = try bcs.encodeAlloc(T, b.a, &v) });
        return .{ .input = @intCast(b.inputs.items.len - 1) };
    }

    fn call(b: *Builder, package: [32]u8, module: []const u8, function: []const u8, type_args: []const types.TypeTag, args: []const PArg) !PArg {
        try b.commands.append(b.a, .{ .package = package, .module = module, .function = function, .type_args = type_args, .args = try b.a.dupe(PArg, args) });
        return .{ .result = @intCast(b.commands.items.len - 1) };
    }
};

fn suiType() types.TypeTag {
    return .{ .@"struct" = .{ .address = .{ .@"0" = framework }, .module = .{ .@"0" = "sui" }, .name = .{ .@"0" = "SUI" }, .type_args = &.{} } };
}

pub fn execute(
    arena: Allocator,
    s: *store_mod.Store,
    env: *const sys.Env,
    data: *const types.TransactionDataV1,
    kinds: []const types.EndOfEpochTransactionKind,
    versions: []const sys.InputVersion,
    src: sys.Source,
) !sys.Outcome {
    const cfg = env.cfg;
    var b: Builder = .{ .a = arena };
    const sui = [_]types.TypeTag{suiType()};
    // InputObjects: each kind's shared inputs, deduplicated.
    var shared: std.ArrayList([32]u8) = .empty;
    for (kinds) |*k| {
        const id: ?[32]u8 = switch (k.*) {
            .ChangeEpoch, .StoreExecutionTimeObservations, .WriteAccumulatorStorageCost => system_state,
            .AuthenticatorStateExpire => authenticator_state,
            .BridgeCommitteeInit => bridge,
            else => null,
        };
        const ids = [2]?[32]u8{ id, if (k.* == .BridgeCommitteeInit) system_state else null };
        for (ids) |maybe| if (maybe) |x| {
            const seen = for (shared.items) |y| {
                if (std.mem.eql(u8, &x, &y)) break true;
            } else false;
            if (!seen) try shared.append(arena, x);
        };
    }
    for (shared.items) |*id| {
        const raw = sys.sharedInputOf(src, id, versions) orelse return .{ .unsupported = "shared input not available" };
        try s.addInput(raw, .mutable);
    }

    for (kinds, 0..) |*k, i| switch (k.*) {
        .ChangeEpoch => |*ce| {
            if (i != kinds.len - 1) return error.InvariantViolation;
            // mint_epoch_rewards_in_pt, then advance_epoch, then destroy the storage rebates.
            const sc = try b.pure(u64, ce.storage_charge);
            const storage_rewards = try b.call(framework, "balance", "create_staking_rewards", &sui, &.{sc});
            const cc = try b.pure(u64, ce.computation_charge);
            const computation_rewards = try b.call(framework, "balance", "create_staking_rewards", &sui, &.{cc});
            const args = [_]PArg{
                storage_rewards,
                computation_rewards,
                try b.obj(system_state),
                try b.pure(u64, ce.epoch),
                try b.pure(u64, ce.protocol_version.@"0"),
                try b.pure(u64, ce.storage_rebate),
                try b.pure(u64, ce.non_refundable_storage_fee),
                try b.pure(u64, cfg.get("storage_fund_reinvest_rate") catch return .{ .unsupported = "protocol config" }),
                try b.pure(u64, cfg.get("reward_slashing_rate") catch return .{ .unsupported = "protocol config" }),
                try b.pure(u64, ce.epoch_start_timestamp_ms),
            };
            const rebates = try b.call(system, "sui_system", "advance_epoch", &.{}, &args);
            _ = try b.call(framework, "balance", "destroy_storage_rebates", &sui, &.{rebates});
        },
        .AuthenticatorStateCreate => _ = try b.call(framework, "authenticator_state", "create", &.{}, &.{}),
        .AuthenticatorStateExpire => |*e| {
            const st = try b.obj(authenticator_state);
            const me = try b.pure(u64, e.min_epoch);
            _ = try b.call(framework, "authenticator_state", "expire_jwks", &.{}, &.{ st, me });
        },
        .RandomnessStateCreate => _ = try b.call(framework, "random", "create", &.{}, &.{}),
        .DenyListStateCreate => _ = try b.call(framework, "deny_list", "create", &.{}, &.{}),
        .AccumulatorRootCreate => _ = try b.call(framework, "accumulator", "create", &.{}, &.{}),
        .CoinRegistryCreate => _ = try b.call(framework, "coin_registry", "create", &.{}, &.{}),
        .DisplayRegistryCreate => _ = try b.call(framework, "display_registry", "create", &.{}, &.{}),
        .AddressAliasStateCreate => _ = try b.call(framework, "address_alias", "create", &.{}, &.{}),
        .ForwardingAddressRegistryCreate => _ = try b.call(framework, "forwarding_address", "create", &.{}, &.{}),
        .WriteAccumulatorStorageCost => |*w| {
            const st = try b.obj(system_state);
            const cost = try b.pure(u64, w.storage_cost);
            _ = try b.call(system, "sui_system", "write_accumulator_storage_cost", &.{}, &.{ st, cost });
        },
        .StoreExecutionTimeObservations => |*obs| {
            // Only under the ExecutionTimeEstimate congestion mode; observations chunked by
            // `observations_chunk_size`, each chunk BCS of StoredExecutionTimeObservations::V1.
            const params = switch (cfg.feature_flags.per_object_congestion_control_mode) {
                .ExecutionTimeEstimate => |p| p,
                else => continue,
            };
            const st = try b.obj(system_state);
            const chunk = params.observations_chunk_size orelse {
                // Before chunking (v3 `setup_store_execution_time_estimates`): the whole BCS
                // as one vector<u8>.
                const whole = try bcs.encodeAlloc(types.StoredExecutionTimeObservations, arena, obs);
                const arg = try b.pure([]const u8, whole);
                _ = try b.call(system, "sui_system", "store_execution_time_estimates", &.{}, &.{ st, arg });
                continue;
            };
            const all = obs.V1;
            var chunks: std.ArrayList([]const u8) = .empty;
            if (chunk > 0) {
                var at: usize = 0;
                while (at < all.len) {
                    const end = @min(all.len, at + chunk);
                    const one: types.StoredExecutionTimeObservations = .{ .V1 = all[at..end] };
                    try chunks.append(arena, try bcs.encodeAlloc(types.StoredExecutionTimeObservations, arena, &one));
                    at = end;
                }
            }
            const arg = try b.pure([]const []const u8, chunks.items);
            _ = try b.call(system, "sui_system", "store_execution_time_estimates_v2", &.{}, &.{ st, arg });
        },
        .BridgeStateCreate => |*chain| {
            // setup_bridge_create: bridge::create(UID 0x9 as a pure input, chain id, ctx).
            if (!(cfg.feature_flags.bridge)) return error.InvariantViolation;
            const uid = try b.pure([32]u8, bridge);
            const d = &chain.@"0".@"0".@"0";
            const chain_id: u8 = if (std.mem.eql(u8, d, &mainnet_chain)) 0 else if (std.mem.eql(u8, d, &testnet_chain)) 1 else 2;
            const cid = try b.pure(u8, chain_id);
            _ = try b.call(bridge_pkg, "bridge", "create", &.{}, &.{ uid, cid });
        },
        .BridgeCommitteeInit => {
            // setup_bridge_committee_update: init_bridge_committee(&mut Bridge,
            // validator_voting_powers(&mut SuiSystemState), 7500, ctx).
            const br = try b.obj(bridge);
            const st = try b.obj(system_state);
            const powers = try b.call(system, "sui_system", "validator_voting_powers", &.{}, &.{st});
            const min = try b.pure(u64, 7500);
            _ = try b.call(bridge_pkg, "bridge", "init_bridge_committee", &.{}, &.{ br, powers, min });
        },
    };
    const ptb: movecall.Ptb = .{ .inputs = b.inputs.items, .commands = b.commands.items };
    const events = switch (try movecall.exec(arena, s, env, src, &data.sender.@"0", &data.gas_data, &ptb)) {
        .ok => |e| e,
        .unsupported => |why| return .{ .unsupported = why },
        .aborted => |ab| blk: {
            // advance_epoch failed: drop the writes (nothing was applied), reset the storage
            // cost and rebate (unmetered: none yet) and enter safe mode natively.
            const ce = switch (kinds[kinds.len - 1]) {
                .ChangeEpoch => |*c| c,
                else => return .{ .unsupported = "end of epoch PTB aborted (Rust: Failure effects)" },
            };
            _ = ab;
            if (cfg.feature_flags.advance_epoch_start_time_in_safe_mode) {
                if (try safeMode(arena, s, cfg, ce, src)) |why| return .{ .unsupported = why };
                break :blk null;
            }
            // Older protocols: construct_advance_epoch_safe_mode_pt, which must succeed.
            var sb: Builder = .{ .a = arena };
            const sc = try sb.pure(u64, ce.storage_charge);
            const storage_rewards = try sb.call(framework, "balance", "create_staking_rewards", &sui, &.{sc});
            const cc = try sb.pure(u64, ce.computation_charge);
            const computation_rewards = try sb.call(framework, "balance", "create_staking_rewards", &sui, &.{cc});
            const args = [_]PArg{
                storage_rewards,
                computation_rewards,
                try sb.obj(system_state),
                try sb.pure(u64, ce.epoch),
                try sb.pure(u64, ce.protocol_version.@"0"),
                try sb.pure(u64, ce.storage_rebate),
                try sb.pure(u64, ce.non_refundable_storage_fee),
            };
            _ = try sb.call(system, "sui_system", "advance_epoch_safe_mode", &.{}, &args);
            const sptb: movecall.Ptb = .{ .inputs = sb.inputs.items, .commands = sb.commands.items };
            break :blk switch (try movecall.exec(arena, s, env, src, &data.sender.@"0", &data.gas_data, &sptb)) {
                .ok => |e| e,
                .unsupported => |why| return .{ .unsupported = why },
                .aborted => return error.InvariantViolation, // Rust: "Advance epoch with safe mode must succeed"
            };
        },
    };
    // process_system_packages (after advance_epoch, on a VM over the same protocol).
    if (kinds.len > 0 and kinds[kinds.len - 1] == .ChangeEpoch) {
        if (try upgradeSystemPackages(arena, s, cfg, &kinds[kinds.len - 1].ChangeEpoch, src)) |why| return .{ .unsupported = why };
    }
    return movecall.finish(s, events);
}

/// `TemporaryStore::advance_epoch_safe_mode` (protocols with
/// `advance_epoch_start_time_in_safe_mode`): no Move. The system state inner object (the
/// dynamic field of 0x5 named by its `version`) gets the new epoch, protocol version and start
/// time, `safe_mode = true`, and the epoch's charges and rebates added to its safe mode
/// accumulators (`SuiSystemStateInnerV{1,2}::advance_epoch_safe_mode`); it is written as a
/// mutated child (`mutate_child_object`). Returns an unsupported reason, or null.
pub fn safeMode(
    arena: Allocator,
    s: *store_mod.Store,
    cfg: *const @import("protocol").ProtocolConfig,
    ce: *const types.ChangeEpoch,
    src: sys.Source,
) !?[]const u8 {
    if (!cfg.feature_flags.advance_epoch_start_time_in_safe_mode) return "safe mode through the advance_epoch_safe_mode Move call";
    const wrapper = s.input(&system_state) orelse return error.InvariantViolation;
    const wc = wrapper.contents();
    if (wc.len != 40) return error.InvariantViolation;
    // derive_dynamic_field_id(0x5, u64, bcs(version)).
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, 8, .little);
    const fid = @import("hash").blake2b256(&.{ &[_]u8{0xf0}, &system_state, &len_le, wc[32..40], &[_]u8{2} });
    const old = (src.child(src.ctx, &system_state, &fid, std.math.maxInt(u64)) catch return "system state inner object not available") orelse return error.InvariantViolation;
    const o = bcs.decode(types.Object, arena, old) catch return error.InvariantViolation;
    const mo = switch (o.data) {
        .Move => |m| m,
        .Package => return error.InvariantViolation,
    };
    const tag = try movecall.objectTypeTag(arena, &mo.type_);
    const lay = (try movecall.objectLayouts(arena, cfg, src, &.{system}, tag)) orelse return "framework package not available";
    const field = types.layout.decode(arena, lay.plain, mo.contents) catch return error.InvariantViolation;
    // Field<u64, Inner> { id, name, value }.
    if (lay.annotated.* != .@"struct" or field != .@"struct" or field.@"struct".len != 3) return error.InvariantViolation;
    const inner_lay = lay.annotated.@"struct".fields[2].layout;
    if (inner_lay != .@"struct") return error.InvariantViolation;
    const fields = try arena.dupe(types.layout.Value, field.@"struct"[2].@"struct");
    const names = inner_lay.@"struct".fields;
    if (names.len != fields.len) return error.InvariantViolation;
    const Ix = struct {
        fn of(ns: []const @import("natives").objrt.AField, name: []const u8) !usize {
            for (ns, 0..) |f, i| if (std.mem.eql(u8, f.name.@"0", name)) return i;
            return error.InvariantViolation;
        }
    };
    const add = struct {
        fn u(v: *types.layout.Value, x: u64) !void {
            if (v.* != .u64) return error.InvariantViolation;
            v.u64 = std.math.add(u64, v.u64, x) catch return error.InvariantViolation;
        }
        // Balance { value: u64 }: deposit_for_safe_mode.
        fn bal(a: Allocator, v: *types.layout.Value, x: u64) !void {
            if (v.* != .@"struct" or v.@"struct".len != 1) return error.InvariantViolation;
            const b = try a.dupe(types.layout.Value, v.@"struct");
            try u(&b[0], x);
            v.* = .{ .@"struct" = b };
        }
    };
    fields[try Ix.of(names, "epoch")] = .{ .u64 = ce.epoch };
    fields[try Ix.of(names, "safe_mode")] = .{ .bool = true };
    try add.bal(arena, &fields[try Ix.of(names, "safe_mode_storage_rewards")], ce.storage_charge);
    try add.u(&fields[try Ix.of(names, "safe_mode_storage_rebates")], ce.storage_rebate);
    try add.bal(arena, &fields[try Ix.of(names, "safe_mode_computation_rewards")], ce.computation_charge);
    try add.u(&fields[try Ix.of(names, "safe_mode_non_refundable_storage_fee")], ce.non_refundable_storage_fee);
    fields[try Ix.of(names, "epoch_start_timestamp_ms")] = .{ .u64 = ce.epoch_start_timestamp_ms };
    fields[try Ix.of(names, "protocol_version")] = .{ .u64 = ce.protocol_version.@"0" };
    const outer = try arena.dupe(types.layout.Value, field.@"struct");
    outer[2] = .{ .@"struct" = fields };
    const new_contents = try types.layout.encodeAlloc(arena, &.{ .@"struct" = outer });
    const v = objects.ObjectView.parse(old) catch return error.InvariantViolation;
    try s.loadedChild(old);
    try s.write(.{ .id = fid, .header = old[0..v.version_at], .contents = new_contents, .owner = v.ownerBytes() }, .modified);
    return null;
}

/// `process_system_packages` for packages at a version after the first: each one replaces the
/// system package of its id in place. Returns an unsupported reason, or null.
pub fn upgradeSystemPackages(
    arena: Allocator,
    s: *store_mod.Store,
    cfg: *const @import("protocol").ProtocolConfig,
    ce: *const types.ChangeEpoch,
    src: sys.Source,
) !?[]const u8 {
    if (ce.system_packages.len == 0) return null;
    const bin = movecall.binaryConfig(cfg) catch return "protocol config";
    for (ce.system_packages) |sp| {
        if (sp[0].@"0" == 1) {
            if (try publishSystemPackage(arena, s, cfg, &bin, sp[1], sp[2], src)) |why| return why;
            continue;
        }
        if (sp[0].@"0" == 0) return error.InvariantViolation;
        const new = newSystemPackage(arena, &bin, sp[0].@"0", sp[1], sp[2], &s.tx_digest) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvariantViolation, // Rust unwraps the deserialization
        };
        const id = new[1..33].*;
        const old = src.package(src.ctx, &id) orelse return "system package not available";
        try s.upgradePackage(id, new, old);
    }
    return null;
}

/// A new system package (`OBJECT_START_VERSION`): `Command::Publish(modules, dependencies)` in
/// system mode (`packages_are_predefined`: the package id is the modules' address, no upgrade
/// cap). The package is `MovePackage::new_initial` (modules serialized at their own version, or
/// version 6 when the protocol's binary format is 6 or less; the initial type origin table; a
/// linkage table of the dependencies by original id at their loaded id and version). Modules
/// with an `init` function would run it: reported unsupported (none in the corpus).
fn publishSystemPackage(
    a: Allocator,
    s: *store_mod.Store,
    cfg: *const @import("protocol").ProtocolConfig,
    bin: *const move_format.BinaryConfig,
    modules: []const []const u8,
    deps: []const types.ObjectID,
    src: sys.Source,
) !?[]const u8 {
    if (modules.len == 0) return error.InvariantViolation;
    const ModMap = @FieldType(types.MovePackage, "module_map");
    const LinkMap = @FieldType(types.MovePackage, "linkage_table");
    const ser_version: ?u32 = if ((cfg.move_binary_format_version orelse 0) > 6) null else 6;
    var mods: std.ArrayList(ModMap.Entry) = .empty;
    var origins: std.ArrayList(types.TypeOrigin) = .empty;
    var immediate: std.ArrayList([32]u8) = .empty;
    var self_id: [32]u8 = undefined;
    for (modules, 0..) |bytes, i| {
        const m = switch (try move_format.deserialize(a, bytes, bin)) {
            .ok => |m| m,
            .err => return error.InvariantViolation, // Rust unwraps
        };
        const addr_ = m.selfAddress().*;
        if (i == 0) self_id = addr_;
        const name = m.selfName();
        for (m.function_defs) |fd| if (std.mem.eql(u8, m.identifiers[m.function_handles[fd.function].name], "init"))
            return "new system package with an init function";
        for (m.module_handles) |mh| {
            const dep = m.address_identifiers[mh.address];
            const seen = for (immediate.items) |x| {
                if (std.mem.eql(u8, &x, &dep)) break true;
            } else false;
            if (!seen) try immediate.append(a, dep);
        }
        for (m.struct_defs) |sd| try origins.append(a, .{ .module_name = .{ .@"0" = name }, .datatype_name = .{ .@"0" = m.identifiers[m.datatype_handles[sd.struct_handle].name] }, .package = .{ .@"0" = .{ .@"0" = addr_ } } });
        for (m.enum_defs) |ed| try origins.append(a, .{ .module_name = .{ .@"0" = name }, .datatype_name = .{ .@"0" = m.identifiers[m.datatype_handles[ed.enum_handle].name] }, .package = .{ .@"0" = .{ .@"0" = addr_ } } });
        try mods.append(a, .{ .key = .{ .@"0" = name }, .value = try move_format.serializeAlloc(a, &m, ser_version orelse m.version) });
    }
    // build_linkage_table: every dependency by its original id; every immediate dependency
    // (other than the package itself) must be among them.
    var links: std.ArrayList(LinkMap.Entry) = .empty;
    for (deps) |d| {
        const raw = src.package(src.ctx, &d.@"0".@"0") orelse return "system package dependency not available";
        const o = bcs.decode(types.Object, a, raw) catch return error.InvariantViolation;
        const p = switch (o.data) {
            .Package => |p| p,
            .Move => return error.InvariantViolation,
        };
        const info = @import("natives").objrt.packageInfo(a, &p) catch return error.InvariantViolation;
        for (links.items) |l| if (std.mem.eql(u8, &l.key.@"0".@"0", &info.original_id)) return error.InvariantViolation;
        try links.append(a, .{ .key = .{ .@"0" = .{ .@"0" = info.original_id } }, .value = .{ .upgraded_id = p.id, .upgraded_version = p.version } });
    }
    for (immediate.items) |dep| {
        if (std.mem.eql(u8, &dep, &self_id)) continue;
        const found = for (links.items) |l| {
            if (std.mem.eql(u8, &l.key.@"0".@"0", &dep)) break true;
        } else false;
        if (!found) return error.InvariantViolation; // PublishUpgradeMissingDependency: Rust expects success
    }
    const obj: types.Object = .{
        .data = .{ .Package = .{
            .id = .{ .@"0" = .{ .@"0" = self_id } },
            .version = .{ .@"0" = 1 },
            .module_map = ModMap.fromUnsorted(a, mods.items) catch return error.InvariantViolation,
            .type_origin_table = origins.items,
            .linkage_table = try LinkMap.fromUnsorted(a, links.items),
        } },
        .owner = .Immutable,
        .previous_transaction = .{ .@"0" = .{ .@"0" = s.tx_digest } },
        .storage_rebate = 0,
    };
    try s.createPackage(self_id, try bcs.encodeAlloc(types.Object, a, &obj));
    return null;
}

/// `Object::new_system_package(modules, version, dependencies, prev_tx)` as BCS:
/// `MovePackage::new_system` (modules deserialized with the protocol's binary config and
/// serialized again at their own version, the initial type origin table, a linkage table of
/// the dependencies at version 0), owned Immutable, storage rebate 0. The object is at
/// `version`: Rust decrements it before the write and `update_version_and_previous_tx`
/// increments it again.
pub fn newSystemPackage(
    a: Allocator,
    bin: *const move_format.BinaryConfig,
    version: u64,
    modules: []const []const u8,
    deps: []const types.ObjectID,
    prev_tx: *const [32]u8,
) ![]const u8 {
    if (modules.len == 0) return error.EmptyPackage;
    const ModMap = @FieldType(types.MovePackage, "module_map");
    const LinkMap = @FieldType(types.MovePackage, "linkage_table");
    var mods: std.ArrayList(ModMap.Entry) = .empty;
    var origins: std.ArrayList(types.TypeOrigin) = .empty;
    var storage_id: [32]u8 = undefined;
    for (modules, 0..) |bytes, i| {
        const m = switch (try move_format.deserialize(a, bytes, bin)) {
            .ok => |m| m,
            .err => return error.BadModule,
        };
        const self_addr = m.selfAddress().*;
        if (i == 0) storage_id = self_addr;
        const name = m.selfName();
        for (m.struct_defs) |sd| try origins.append(a, .{
            .module_name = .{ .@"0" = name },
            .datatype_name = .{ .@"0" = m.identifiers[m.datatype_handles[sd.struct_handle].name] },
            .package = .{ .@"0" = .{ .@"0" = self_addr } },
        });
        for (m.enum_defs) |ed| try origins.append(a, .{
            .module_name = .{ .@"0" = name },
            .datatype_name = .{ .@"0" = m.identifiers[m.datatype_handles[ed.enum_handle].name] },
            .package = .{ .@"0" = .{ .@"0" = self_addr } },
        });
        try mods.append(a, .{ .key = .{ .@"0" = name }, .value = try move_format.serializeAlloc(a, &m, m.version) });
    }
    // BTreeMap::from_iter: a repeated dependency collapses into one entry.
    var links: std.ArrayList(LinkMap.Entry) = .empty;
    for (deps) |d| {
        const seen = for (links.items) |l| {
            if (std.mem.eql(u8, &l.key.@"0".@"0", &d.@"0".@"0")) break true;
        } else false;
        if (!seen) try links.append(a, .{ .key = d, .value = .{ .upgraded_id = d, .upgraded_version = .{ .@"0" = 0 } } });
    }
    const obj: types.Object = .{
        .data = .{ .Package = .{
            .id = .{ .@"0" = .{ .@"0" = storage_id } },
            .version = .{ .@"0" = version },
            // Rust panics on a duplicate module name.
            .module_map = ModMap.fromUnsorted(a, mods.items) catch return error.DuplicateModule,
            .type_origin_table = origins.items,
            .linkage_table = try LinkMap.fromUnsorted(a, links.items),
        } },
        .owner = .Immutable,
        .previous_transaction = .{ .@"0" = .{ .@"0" = prev_tx.* } },
        .storage_rebate = 0,
    };
    return bcs.encodeAlloc(types.Object, a, &obj);
}
