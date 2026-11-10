//! Conformance suites of the protocol-config lane (CONTRACTS.md section 3.3).
//!
//! `protocol-config`: one item per (chain, version), 3 x 141. The rendered insta YAML of deepwave's
//!   config must equal, byte for byte, the YAML that Mysten's real `ProtocolConfig::get_for_version`
//!   serializes through insta (vector `yaml/<Chain>_<v>.yaml` from tools/truth/protocol-config,
//!   which itself aborts unless that text equals Mysten's checked-in `.snap` body).
//! `gas-tables`: gas_model tables against `gas.json` from the same tool: items `table/<name>` (tiers
//!   and tier lookups at probe points), `cost_table_for_version/<gm>` (gm 0..40) and `predicates/<gm>`.
const std = @import("std");
const harness = @import("harness");
const root = @import("root.zig");
const gas = @import("gas.zig");

pub const suites = [_]harness.Suite{
    .{
        .name = "protocol-config",
        .lane = "protocol-config",
        .doc = "render of every (version, chain) equals Mysten's insta snapshots",
        .run = runConfig,
        .bench = benchConfig,
        .baselines = &.{
            .{ .name = "get", .argv = &.{ "{release}/zui-pc-truth", "bench", "get" } },
            .{ .name = "render", .argv = &.{ "{release}/zui-pc-truth", "bench", "render" } },
        },
        .inputs = .{ .dir = "vectors/protocol-config/yaml", .suffix = ".yaml" },
    },
    .{
        .name = "protocol-config-getters",
        .lane = "protocol-config",
        .doc = "derived getters, verifier_config, binary_config, feature_map and lookup_feature of every (version, chain) equal Mysten's (panics included)",
        .run = runGetters,
    },
    .{
        .name = "gas-tables",
        .lane = "protocol-config",
        .doc = "gas_model cost tables, tier lookups and gas-model-version predicates equal Mysten's",
        .run = runGas,
    },
};

const chain_names = [_][]const u8{ "Unknown", "Mainnet", "Testnet" };
const chain_enums = [_]root.Chain{ .unknown, .mainnet, .testnet };

/// The max protocol version of the release that made the corpus's truth: its newest
/// `yaml/Unknown_<v>.yaml`.
fn truthMax(ctx: *harness.Ctx) !u64 {
    var v: u64 = root.max_protocol_version;
    while (v > root.min_protocol_version) : (v -= 1) {
        const p = try std.fmt.allocPrint(ctx.scratch(), "vectors/protocol-config/yaml/Unknown_{d}.yaml", .{v});
        if (ctx.corpus.statFile(ctx.io, p, .{})) |_| return v else |_| {}
    }
    return v;
}

/// Feature flags a release whose max protocol is `release_max` has (`root.release_fields`).
fn releaseFeatureCount(release_max: u64) usize {
    var n: usize = 0;
    const info = @typeInfo(root.FeatureFlags).@"struct";
    inline for (info.field_names, info.field_types) |name, FT| {
        if (FT == bool) {
            const r = comptime root.fieldRelease(name);
            if (r <= release_max) n += 1;
        }
    }
    return n;
}

fn runConfig(ctx: *harness.Ctx) !void {
    var item_buf: [32]u8 = undefined;
    // Truth from an older release stops below deepwave's max: the versions above it are gated on the
    // release pipeline's regenerated truth (tools/release), not here.
    const truth_max = try truthMax(ctx);
    for (chain_names, chain_enums) |cname, chain| {
        var v: u64 = root.min_protocol_version;
        while (v <= root.max_protocol_version) : (v += 1) {
            if (ctx.done()) return;
            const item = try std.fmt.bufPrint(&item_buf, "{s}/{d}", .{ cname, v });
            if (!ctx.selected(item)) continue;
            if (v > truth_max) continue;
            ctx.nextItem();
            const path = try std.fmt.allocPrint(ctx.scratch(), "vectors/protocol-config/yaml/{s}_{d}.yaml", .{ cname, v });
            const expected = try ctx.readFile(path, 1 << 20);
            var out: std.Io.Writer.Allocating = .init(ctx.scratch());
            const cfg = root.get(v, chain) catch |e| {
                ctx.fail(item, "get: {s}", .{@errorName(e)});
                continue;
            };
            var c = ctx.check(item);
            if (cfg.version != v) c.failf("version field {d}", .{cfg.version});
            // Rust sets `ret.chain = chain` (serde-skipped, so no snapshot covers it).
            if (cfg.chain != chain) c.failf("chain field {s}", .{@tagName(cfg.chain)});
            try root.renderSnapshot(cfg, &out.writer);
            c.text("rendered snapshot", expected, out.written());
            // Second oracle: the checked-in .snap itself (CONTRACTS.md 3.3), through the tools/sui link.
            const prefix: []const u8 = switch (chain) {
                .unknown => "",
                .mainnet => "Mainnet_",
                .testnet => "Testnet_",
            };
            const snap_path = try std.fmt.allocPrint(ctx.scratch(), "tools/sui/crates/sui-protocol-config/src/snapshots/sui_protocol_config__test__{s}version_{d}.snap", .{ prefix, v });
            // The pinned tree (tools/sui, 1.83.1) has no snapshot of a newer release's versions: those
            // come from the corpus (`vectors/protocol-config/snaps/`, Mysten's own .snap files copied
            // from the release tree that made the truth).
            const snap_res: anyerror![]u8 = blk: {
                if (std.Io.Dir.cwd().readFileAlloc(ctx.io, snap_path, ctx.scratch(), .limited(1 << 20))) |b| break :blk b else |e0| {
                    const alt = try std.fmt.allocPrint(ctx.scratch(), "vectors/protocol-config/snaps/sui_protocol_config__test__{s}version_{d}.snap", .{ prefix, v });
                    if (ctx.corpus.readFileAlloc(ctx.io, alt, ctx.scratch(), .limited(1 << 20))) |b2| break :blk b2 else |_| break :blk e0;
                }
            };
            if (snap_res) |snap| {
                // Header is "---\nsource: ..\nexpression: ..\n---\n"; insta compares modulo trailing whitespace.
                var parts = std.mem.splitSequence(u8, snap, "---\n");
                _ = parts.next();
                _ = parts.next();
                const body = std.mem.trimEnd(u8, parts.rest(), " \n\r\t");
                c.text(".snap body", body, std.mem.trimEnd(u8, out.written(), "\n"));
            } else |e| c.failf("cannot read {s}: {s} (run tools/setup-sui.sh)", .{ snap_path, @errorName(e) });
            _ = c.finish();
        }
    }
    // Out of range must be refused.
    if (!ctx.done() and ctx.selected("range")) {
        var c = ctx.check("range");
        if (root.get(0, .mainnet)) |_| c.failf("version 0 accepted", .{}) else |_| {}
        if (root.get(root.max_protocol_version + 1, .mainnet)) |_| c.failf("version max + 1 accepted", .{}) else |_| {}
        _ = c.finish();
    }
}

fn benchConfig(ctx: *harness.Ctx) !void {
    const inputs = ctx.benchInputs();
    const Item = struct { chain: root.Chain, v: u64 };
    var items = try ctx.gpa.alloc(Item, inputs.len);
    defer ctx.gpa.free(items);
    for (inputs, 0..) |p, i| {
        const base = std.fs.path.basename(p);
        const us = std.mem.indexOfScalar(u8, base, '_') orelse return error.BadBenchInput;
        const dot = std.mem.indexOfScalar(u8, base, '.') orelse return error.BadBenchInput;
        items[i] = .{
            .chain = if (std.mem.eql(u8, base[0..us], "Mainnet")) .mainnet else if (std.mem.eql(u8, base[0..us], "Testnet")) .testnet else .unknown,
            .v = try std.fmt.parseInt(u64, base[us + 1 .. dot], 10),
        };
    }
    const State = struct {
        items: []const Item,
        buf: []u8,
        fn doGet(s: @This()) anyerror!void {
            var acc: u64 = 0;
            for (s.items) |it| {
                const c = try root.get(it.v, it.chain);
                acc +%= c.max_tx_size_bytes orelse 0;
                std.mem.doNotOptimizeAway(c);
            }
            std.mem.doNotOptimizeAway(acc);
        }
        fn doRender(s: @This()) anyerror!void {
            var total: usize = 0;
            for (s.items) |it| {
                var w: std.Io.Writer = .fixed(s.buf);
                try root.renderSnapshot(try root.get(it.v, it.chain), &w);
                total += w.end;
            }
            std.mem.doNotOptimizeAway(total);
        }
    };
    const buf = try ctx.gpa.alloc(u8, 4 << 20);
    defer ctx.gpa.free(buf);
    const st: State = .{ .items = items, .buf = buf };
    try ctx.benchPasses("get", "config", items.len, st, State.doGet);
    try ctx.benchPasses("render", "config", items.len, st, State.doRender);
}

// ---------------------------------------------------------------------------------------------

fn tiersEql(want: std.json.Value, have: []const gas.Tier) bool {
    if (want.array.items.len != have.len) return false;
    for (want.array.items, have) |w, h| {
        if (w.array.items[0].integer != @as(i64, @intCast(h.start))) return false;
        if (w.array.items[1].integer != @as(i64, @intCast(h.mult))) return false;
    }
    return true;
}

fn jsonU64(v: std.json.Value) u64 {
    return switch (v) {
        .integer => |i| @intCast(i),
        .number_string => |s| std.fmt.parseInt(u64, s, 10) catch unreachable,
        else => unreachable,
    };
}

fn checkTable(c: *harness.Check, what: []const u8, want: std.json.Value, have: *const gas.CostTable) void {
    const o = want.object;
    if (!tiersEql(o.get("instruction").?, have.instruction_tiers)) c.failf("{s}: instruction tiers differ", .{what});
    if (!tiersEql(o.get("stack_height").?, have.stack_height_tiers)) c.failf("{s}: stack_height tiers differ", .{what});
    if (!tiersEql(o.get("stack_size").?, have.stack_size_tiers)) c.failf("{s}: stack_size tiers differ", .{what});
}

fn runGas(ctx: *harness.Ctx) !void {
    ctx.nextItem();
    const text = try ctx.readFile("vectors/protocol-config/gas.json", 64 << 20);
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, ctx.scratch(), text, .{});
    const named = [_]struct { []const u8, *const gas.CostTable }{
        .{ "zero", &gas.zero_cost_schedule },
        .{ "unit", &gas.unit_cost_schedule },
        .{ "v1", &gas.initial_cost_schedule_v1 },
        .{ "v2", &gas.initial_cost_schedule_v2 },
        .{ "v3", &gas.initial_cost_schedule_v3 },
        .{ "v4", &gas.initial_cost_schedule_v4 },
        .{ "v5", &gas.initial_cost_schedule_v5 },
    };
    var item_buf: [64]u8 = undefined;
    const tables = doc.object.get("tables").?.object;
    for (named) |n| {
        const item = try std.fmt.bufPrint(&item_buf, "table/{s}", .{n[0]});
        if (ctx.done()) return;
        if (!ctx.selected(item)) continue;
        const e = tables.get(n[0]).?.object;
        var c = ctx.check(item);
        checkTable(&c, "table", e.get("table").?, n[1]);
        const probes = e.get("probes").?.array.items;
        const tiers = e.get("tiers").?.object;
        const kinds = [_][]const u8{ "instruction", "stack_height", "stack_size" };
        const lists = [_][]const gas.Tier{ n[1].instruction_tiers, n[1].stack_height_tiers, n[1].stack_size_tiers };
        for (kinds, lists) |k, list| {
            const want = tiers.get(k).?.array.items;
            if (want.len != probes.len) {
                c.failf("{s}: truth has {d} probes and {d} results", .{ k, probes.len, want.len });
                continue;
            }
            for (probes, want) |p, w| {
                const x = jsonU64(p);
                const got = gas.CostTable.tierAt(list, x);
                const wm = jsonU64(w.array.items[0]);
                const wn: ?u64 = switch (w.array.items[1]) {
                    .null => null,
                    else => |nv| jsonU64(nv),
                };
                if (got[0] != wm or got[1] != wn) {
                    c.failf("{s} tier at {d}: expected ({d}, {?d}), got ({d}, {?d})", .{ k, x, wm, wn, got[0], got[1] });
                }
            }
        }
        _ = c.finish();
    }
    const cts = doc.object.get("cost_table_for_version").?.array.items;
    for (cts, 0..) |want, gm| {
        const item = try std.fmt.bufPrint(&item_buf, "cost_table_for_version/{d}", .{gm});
        if (ctx.done()) return;
        if (!ctx.selected(item)) continue;
        var c = ctx.check(item);
        checkTable(&c, "table", want, gas.costTableForVersion(gm));
        _ = c.finish();
    }
    const preds = doc.object.get("predicates").?.array.items;
    for (preds) |p| {
        const o = p.object;
        const gm = jsonU64(o.get("gm").?);
        const item = try std.fmt.bufPrint(&item_buf, "predicates/{d}", .{gm});
        if (ctx.done()) return;
        if (!ctx.selected(item)) continue;
        var c = ctx.check(item);
        c.eql("dont_charge_budget_on_storage_oog", o.get("dont_charge_budget_on_storage_oog").?.bool, gas.dontChargeBudgetOnStorageOog(gm));
        c.eql("check_for_gas_price_too_high", o.get("check_for_gas_price_too_high").?.bool, gas.checkForGasPriceTooHigh(gm));
        c.eql("charge_input_as_memory", o.get("charge_input_as_memory").?.bool, gas.chargeInputAsMemory(gm));
        c.eql("use_legacy_abstract_size", o.get("use_legacy_abstract_size").?.bool, gas.useLegacyAbstractSize(gm));
        c.eql("charge_upgrades", o.get("charge_upgrades").?.bool, gas.chargeUpgrades(gm));
        c.eql("legacy_charge_native_pops_args", o.get("legacy_charge_native_pops_args").?.bool, gas.legacyChargeNativePopsArgs(gm));
        c.eql("refresh_gas_payment_location", o.get("refresh_gas_payment_location").?.bool, gas.refreshGasPaymentLocation(gm));
        c.eql("bump_only_enabled", o.get("bump_only_enabled").?.bool, gas.bumpOnlyEnabled(gm));
        const nf = o.get("native_function_threshold_exceeded").?.array.items;
        c.eql("native_function_threshold_exceeded(700)", nf[0].bool, gas.nativeFunctionThresholdExceeded(gm, 700));
        c.eql("native_function_threshold_exceeded(701)", nf[1].bool, gas.nativeFunctionThresholdExceeded(gm, 701));
        _ = c.finish();
    }
}

// ---------------------------------------------------------------------------------------------
// protocol-config-getters

const derived = @import("derived.zig");

fn isPanic(v: std.json.Value) bool {
    return v == .object and v.object.get("panic") != null;
}

/// Compares a Zig value of type T with Mysten's JSON for it (u128 as decimal string).
fn eqlJson(comptime T: type, have: T, want: std.json.Value) bool {
    switch (@typeInfo(T)) {
        .bool => return want == .bool and want.bool == have,
        .int => {
            if (T == u128) return want == .string and std.mem.eql(u8, want.string, "") == false and (std.fmt.parseInt(u128, want.string, 10) catch return false) == have;
            return (switch (want) {
                .integer => |i| i >= 0 and @as(u64, @intCast(i)) == have,
                .number_string => |s| (std.fmt.parseInt(u64, s, 10) catch return false) == have,
                else => false,
            });
        },
        .optional => |o| {
            if (have) |h| return eqlJson(o.child, h, want);
            return want == .null;
        },
        .@"enum" => return want == .string and std.mem.eql(u8, want.string, @tagName(have)),
        .@"union" => switch (have) {
            .ExecutionTimeEstimate => |p| {
                if (want != .object) return false;
                const e = want.object.get("ExecutionTimeEstimate") orelse return false;
                if (e != .object) return false;
                // Rust skips default-valued optional params in JSON as well; compare the present ones.
                const info = @typeInfo(@TypeOf(p)).@"struct";
                inline for (info.field_names, info.field_types) |n, FT| {
                    const w = e.object.get(n);
                    const hv = @field(p, n);
                    if (w) |wv| {
                        if (!eqlJson(FT, hv, wv)) return false;
                    } else {
                        const zero = switch (@typeInfo(FT)) {
                            .optional => hv == null,
                            .bool => hv == false,
                            else => hv == 0,
                        };
                        if (!zero) return false;
                    }
                }
                return true;
            },
            else => return want == .string and std.mem.eql(u8, want.string, @tagName(have)),
        },
        .pointer => |p| {
            if (p.child == u8) return eqlJsonStr(have, want);
            if (want != .array or want.array.items.len != have.len) return false;
            for (have, want.array.items) |h, w| if (!eqlJson(p.child, h, w)) return false;
            return true;
        },
        .@"struct" => |s| {
            if (!s.is_tuple) return false;
            if (want != .array or want.array.items.len != s.field_names.len) return false;
            inline for (0..s.field_names.len) |i| if (!eqlJson(s.field_types[i], have[i], want.array.items[i])) return false;
            return true;
        },
        else => @compileError("eqlJson: " ++ @typeName(T)),
    }
}

fn eqlJsonStr(have: []const u8, want: std.json.Value) bool {
    return want == .string and std.mem.eql(u8, want.string, have);
}

fn expectFn(c: *harness.Check, g: std.json.Value, name: []const u8, result: anytype) void {
    const want = g.object.get(name) orelse {
        c.failf("{s}: not in truth", .{name});
        return;
    };
    const R = @TypeOf(result);
    if (@typeInfo(R) == .error_union) {
        if (result) |val| {
            if (isPanic(want)) {
                c.failf("{s}: Rust panics but zui returns a value", .{name});
            } else if (!eqlJson(@TypeOf(val), val, want)) {
                c.failf("{s}: value differs from Rust", .{name});
            }
        } else |_| {
            if (!isPanic(want)) c.failf("{s}: zui errors but Rust returns a value", .{name});
        }
    } else {
        if (isPanic(want)) {
            c.failf("{s}: Rust panics but zui returns a value", .{name});
        } else if (R == []const []const u8) {
            if (want != .array or want.array.items.len != result.len) {
                c.failf("{s}: length differs", .{name});
            } else for (result, want.array.items) |a, b| {
                if (!eqlJsonStr(a, b)) c.failf("{s}: element differs", .{name});
            }
        } else if (!eqlJson(R, result, want)) {
            c.failf("{s}: value differs from Rust", .{name});
        }
    }
}

fn checkStruct(c: *harness.Check, what: []const u8, want: std.json.Value, have_e: anytype) void {
    if (@typeInfo(@TypeOf(have_e)) == .error_union) {
        if (have_e) |have| {
            if (isPanic(want)) return c.failf("{s}: Rust panics but zui returns a value", .{what});
            checkStructValue(c, what, want, have);
        } else |_| {
            if (!isPanic(want)) c.failf("{s}: zui errors but Rust returns a value", .{what});
        }
    }
}

fn checkStructValue(c: *harness.Check, what: []const u8, want: std.json.Value, have: anytype) void {
    const T = @TypeOf(have);
    const info = @typeInfo(T).@"struct";
    inline for (info.field_names, info.field_types) |n, FT| {
        if (comptime std.mem.eql(u8, n, "table_config")) {
            const arr = want.object.get("table").?.array.items;
            const fields = @typeInfo(FT).@"struct".field_names;
            inline for (fields, 0..) |tn, i| {
                if (!eqlJson(u16, @field(have.table_config, tn), arr[i])) c.failf("{s}.table.{s} differs", .{ what, tn });
            }
        } else {
            if (want.object.get(n)) |w| {
                if (!eqlJson(FT, @field(have, n), w)) c.failf("{s}.{s} differs from Rust", .{ what, n });
            } else if (comptime std.mem.eql(u8, n, "type_parameter_index_max")) {
                // truth older than 1.84 has no limits profile: LEGACY everywhere
                if (@field(have, n) != 65536) c.failf("{s}.{s}: {d}, pre-1.84 truth means LEGACY 65536", .{ what, n, @field(have, n) });
            } else c.failf("{s}.{s}: not in truth", .{ what, n });
        }
    }
}

fn runGetters(ctx: *harness.Ctx) !void {
    ctx.nextItem();
    const text = try ctx.readFile("vectors/protocol-config/getters.jsonl", 256 << 20);
    // Truth from an older release lacks the flags newer releases added (1.83.1: 189, 1.84: 191).
    const truth_flags = releaseFeatureCount(try truthMax(ctx));
    var it = harness.lines(text);
    var item_buf: [32]u8 = undefined;
    while (it.next()) |line| {
        if (ctx.done()) return;
        const doc = try std.json.parseFromSliceLeaky(std.json.Value, ctx.scratch(), line, .{});
        const cname = doc.object.get("chain").?.string;
        const v: u64 = @intCast(doc.object.get("v").?.integer);
        const item = try std.fmt.bufPrint(&item_buf, "{s}/{d}", .{ cname, v });
        if (!ctx.selected(item)) continue;
        const chain: root.Chain = if (std.mem.eql(u8, cname, "Mainnet")) .mainnet else if (std.mem.eql(u8, cname, "Testnet")) .testnet else .unknown;
        const cfg = try root.get(v, chain);
        const g = doc.object.get("g").?;
        var c = ctx.check(item);
        expectFn(&c, g, "check_package_upgrades_supported", derived.checkPackageUpgradesSupported(cfg));
        expectFn(&c, g, "zklogin_supported_providers", derived.zkloginSupportedProviders(cfg));
        expectFn(&c, g, "zklogin_circuit_mode", derived.zkloginCircuitMode(cfg));
        expectFn(&c, g, "consensus_transaction_ordering", derived.consensusTransactionOrdering(cfg));
        expectFn(&c, g, "enable_jwk_consensus_updates", derived.enableJwkConsensusUpdates(cfg));
        expectFn(&c, g, "staggered_submission_signal", derived.staggeredSubmissionSignal(cfg));
        expectFn(&c, g, "end_of_epoch_transaction_supported", derived.endOfEpochTransactionSupported(cfg));
        expectFn(&c, g, "dkg_version", derived.dkgVersion(cfg));
        expectFn(&c, g, "bridge", derived.bridge(cfg));
        expectFn(&c, g, "should_try_to_finalize_bridge_committee", derived.shouldTryToFinalizeBridgeCommittee(cfg));
        expectFn(&c, g, "zklogin_max_epoch_upper_bound_delta", derived.zkloginMaxEpochUpperBoundDelta(cfg));
        expectFn(&c, g, "enable_allowances", derived.enableAllowances(cfg));
        expectFn(&c, g, "enable_coin_reservation_obj_refs", derived.enableCoinReservationObjRefs(cfg));
        expectFn(&c, g, "enable_authenticated_event_streams", derived.enableAuthenticatedEventStreams(cfg));
        expectFn(&c, g, "per_object_congestion_control_mode", derived.perObjectCongestionControlMode(cfg));
        expectFn(&c, g, "consensus_choice", derived.consensusChoice(cfg));
        expectFn(&c, g, "consensus_network", derived.consensusNetwork(cfg));
        expectFn(&c, g, "mysticeti_num_leaders_per_round", derived.mysticetiNumLeadersPerRound(cfg));
        expectFn(&c, g, "max_transaction_size_bytes", derived.maxTransactionSizeBytes(cfg));
        expectFn(&c, g, "max_transactions_in_block_bytes", derived.maxTransactionsInBlockBytes(cfg));
        expectFn(&c, g, "max_num_transactions_in_block", derived.maxNumTransactionsInBlock(cfg));
        expectFn(&c, g, "gc_depth", derived.gcDepth(cfg));
        expectFn(&c, g, "consensus_linearize_subdag_v2", derived.consensusLinearizeSubdagV2(cfg));
        expectFn(&c, g, "consensus_median_based_commit_timestamp", derived.consensusMedianBasedCommitTimestamp(cfg));
        expectFn(&c, g, "get_consensus_commit_rate_estimation_window_size", derived.consensusCommitRateEstimationWindowSize(cfg));
        expectFn(&c, g, "consensus_num_requested_prior_commits_at_startup", derived.consensusNumRequestedPriorCommitsAtStartup(cfg));
        expectFn(&c, g, "address_aliases", derived.addressAliases(cfg));
        expectFn(&c, g, "new_vm_enabled", derived.newVmEnabled(cfg));
        expectFn(&c, g, "gasless_allowed_token_types", derived.gaslessAllowedTokenTypes(cfg));
        expectFn(&c, g, "get_gasless_max_unused_inputs", derived.gaslessMaxUnusedInputs(cfg));
        expectFn(&c, g, "get_gasless_max_pure_input_bytes", derived.gaslessMaxPureInputBytes(cfg));
        expectFn(&c, g, "get_gasless_max_tx_size_bytes", derived.gaslessMaxTxSizeBytes(cfg));

        checkStruct(&c, "verifier_config(None)", doc.object.get("verifier").?, derived.verifierConfig(cfg, null));
        checkStruct(&c, "verifier_config(Some(100,200,300))", doc.object.get("verifier_signing").?, derived.verifierConfig(cfg, .{
            .max_back_edges_per_function = 100,
            .max_back_edges_per_module = 200,
            .sanity_check_with_regex_reference_safety = 300,
        }));
        checkStruct(&c, "binary_config(None)", doc.object.get("binary").?, derived.binaryConfig(cfg, null));
        checkStruct(&c, "binary_config(Some(true))", doc.object.get("binary_true").?, derived.binaryConfig(cfg, true));
        checkStruct(&c, "binary_config(Some(false))", doc.object.get("binary_false").?, derived.binaryConfig(cfg, false));
        // feature_map(): every bool flag by name, and nothing else; lookup_feature on other names.
        const fm = doc.object.get("feature_map").?.object;
        if (fm.count() != truth_flags) c.failf("feature_map: Rust has {d} flags, zui {d} at that release ({d} in all)", .{ fm.count(), truth_flags, derived.feature_count });
        for (fm.keys(), fm.values()) |k, want| {
            const have = derived.lookupFeature(cfg, k);
            if (have == null or want != .bool or have.? != want.bool) c.failf("lookup_feature({s}) differs from Rust", .{k});
        }
        for (doc.object.get("lookup_feature").?.array.items) |pr| {
            const name = pr.array.items[0].string;
            if (!eqlJson(?bool, derived.lookupFeature(cfg, name), pr.array.items[1])) c.failf("lookup_feature(\"{s}\") differs from Rust", .{name});
        }
        _ = c.finish();
    }
}
