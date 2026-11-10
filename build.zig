//! Deepwave build. The module graph below is the dependency contract: a module may import
//! only the modules listed before it.
//!
//!   ./zig build                                   build deepwave-conformance
//!   ./zig build test [-Dlane=<module>]            unit tests (all modules or one)
//!   ./zig build test-conformance -Dsuite=<name>   ground-truth suite(s) against $ZUI_CORPUS
//!                                                 (-Dsuite=a,b or a lane name; -Djobs=N worker threads;
//!                                                 builds only the modules declaring them, -Dsplit=false: all)
//!   ./zig build conformance-runners               every deepwave-conformance-<module> runner, in parallel
//!   ./zig build bench -Dsuite=<name> -Doptimize=fast   Zig vs Rust baselines on the same inputs
//!   ./zig build lean                              Lean 4 specs and proofs (lean/check.sh)
const std = @import("std");
const cpu_tiers = @import("src/core/cpu_tiers.zig");

const Mod = struct {
    name: []const u8,
    path: []const u8,
    deps: []const []const u8,
};

/// Layered: a module may import only modules listed before it. Every lane module also gets
/// `harness` (for its conformance.zig) and `core`.
const mods = [_]Mod{
    .{ .name = "bcs", .path = "src/bcs/root.zig", .deps = &.{} },
    .{ .name = "hash", .path = "src/crypto/hash/root.zig", .deps = &.{} },
    .{ .name = "types", .path = "src/types/root.zig", .deps = &.{ "bcs", "hash" } },
    .{ .name = "bls", .path = "src/crypto/bls/root.zig", .deps = &.{"hash"} },
    .{ .name = "zk", .path = "src/crypto/zk/root.zig", .deps = &.{ "hash", "bcs", "types", "bls" } },
    .{ .name = "sig", .path = "src/crypto/sig/root.zig", .deps = &.{ "hash", "bcs", "types", "zk" } },
    // Optional GPU accelerator: Metal / CUDA, off unless asked for.
    .{ .name = "gpu", .path = "src/gpu/root.zig", .deps = &.{ "hash", "bcs", "types", "bls", "zk", "sig" } },
    .{ .name = "move_format", .path = "src/move/format/root.zig", .deps = &.{ "bcs", "types" } },
    .{ .name = "protocol", .path = "src/protocol/root.zig", .deps = &.{} },
    .{ .name = "store", .path = "src/store/root.zig", .deps = &.{"hash"} },
    .{ .name = "rt", .path = "src/rt/root.zig", .deps = &.{} },
    .{ .name = "net", .path = "src/net/root.zig", .deps = &.{ "rt", "hash", "bcs", "sig" } },
    .{ .name = "checkpoint", .path = "src/checkpoint/root.zig", .deps = &.{ "bcs", "types", "hash", "sig", "bls", "protocol" } },
    .{ .name = "natives", .path = "src/natives/root.zig", .deps = &.{ "bcs", "types", "hash", "sig", "bls", "zk", "move_format", "protocol" } },
    .{ .name = "move_vm", .path = "src/move/vm/root.zig", .deps = &.{ "bcs", "types", "hash", "move_format", "protocol", "natives" } },
    .{ .name = "exec", .path = "src/exec/root.zig", .deps = &.{ "bcs", "types", "hash", "sig", "zk", "move_format", "move_vm", "natives", "protocol", "store" } },
    .{ .name = "sync", .path = "src/sync/root.zig", .deps = &.{ "rt", "net", "bcs", "types", "hash", "sig", "checkpoint", "bls", "protocol", "store", "exec" } },
    // Ledger-history index (lane ledger, docs/DROP-IN.md G7): ListCheckpoints/ListTransactions/ListEvents.
    .{ .name = "history", .path = "src/history/root.zig", .deps = &.{ "bcs", "types" } },
    .{ .name = "serve", .path = "src/serve/root.zig", .deps = &.{ "rt", "bcs", "types", "hash", "protocol", "store", "checkpoint", "move_format", "sig", "zk", "history" } },
    // StateService indexes (lane indexes, DROP-IN G4).
    .{ .name = "index", .path = "src/index/root.zig", .deps = &.{ "bcs", "types", "hash", "store", "serve", "move_format" } },
    // Wave C: sui.rpc.v2 TransactionExecutionService (lane rpc-exec, CONTRACTS 6.7).
    .{ .name = "rpc_exec", .path = "src/rpc_exec/root.zig", .deps = &.{ "rt", "bcs", "types", "hash", "sig", "zk", "protocol", "store", "move_format", "move_vm", "natives", "exec", "serve" } },
    // Simulation engine: execution without commit, the native API.
    .{ .name = "simulate", .path = "src/exec/simulate/root.zig", .deps = &.{ "bcs", "types", "hash", "protocol", "store", "move_vm", "exec", "serve", "rpc_exec" } },
    // Edge feed wire and zstd dictionaries (lane edge, docs/EDGE.md): pure bytes, no I/O.
    .{ .name = "edgewire", .path = "src/edge/wire/root.zig", .deps = &.{ "bcs", "types", "hash", "store", "checkpoint" } },
    // zui/1 native serving protocol (lane native-proto, docs/NATIVE-PROTOCOL.md).
    .{ .name = "native", .path = "src/serve/native/root.zig", .deps = &.{ "rt", "net", "bcs", "types", "hash", "store", "serve", "index", "rpc_exec", "edgewire" } },
    // Edge deepwave: zui/1 client, core pool and the node's edge source.
    .{ .name = "edge", .path = "src/edge/root.zig", .deps = &.{ "rt", "net", "bcs", "types", "hash", "store", "checkpoint", "native", "edgewire" } },
    // Wave C: the full node composes every lane (node lane owns this row and the deepwave executable).
    .{ .name = "node", .path = "src/node/root.zig", .deps = &.{ "rt", "net", "bcs", "types", "hash", "sig", "bls", "zk", "move_format", "protocol", "store", "checkpoint", "natives", "move_vm", "exec", "sync", "history", "serve", "index", "rpc_exec", "simulate", "native", "edgewire", "edge", "gpu" } },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const lane_filter = b.option([]const u8, "lane", "Only unit-test this module (e.g. bcs, sig, store)");
    const suite = b.option([]const u8, "suite", "Conformance suite name, lane name, 'all' or 'list'") orelse "all";
    const limit = b.option(u64, "limit", "Smoke run: stop after N items (never counts as done)") orelse 0;
    const filter = b.option([]const u8, "filter", "Only items whose id contains this") orelse "";
    const iters = b.option(u32, "iters", "Bench passes (median reported)") orelse 5;
    const jobs = b.option(u32, "jobs", "Conformance worker threads (default: CPU count, at most 16)") orelse 0;
    const bench_bytes = b.option(u64, "bench-bytes", "Bench input cap in bytes (default 256 MiB)") orelse 0;
    const split = b.option(bool, "split", "Run a single-module -Dsuite on its own deepwave-conformance-<module> runner (default true)") orelse true;

    // Runtime CPU dispatch (src/core/cpu.zig): on x86-64 the hot kernels are compiled again per
    // tier above the target's own (AVX2, AVX-512 IFMA) and picked by CPUID at startup.
    const cpu_dispatch = b.option(bool, "cpu-dispatch", "x86-64: link per-tier kernel objects picked by CPUID at runtime (default true)") orelse true;
    const g = moduleGraph(b, target, optimize, .{ .kernel_tier = 0xff, .linked_mask = if (cpu_dispatch) kernelMask(target) else 0 });
    const core = g.core;
    const harness = g.harness;
    const built = g.built;
    if (cpu_dispatch) addKernelObjects(b, target, optimize, core);

    // Conformance runners (CONTRACTS 3.0). `deepwave-conformance` links every lane module (CI, `all`,
    // `list`, selections that span modules). `deepwave-conformance-<module>` links one module's suites
    // and `deepwave-conformance-harness` the reviewer suites; a -Dsuite whose suites all live in one
    // module runs that runner, which compiles only the code those suites reach. Same harness,
    // same CLI, same summary lines. -Dsplit=false forces the all-in-one runner.
    var every: [mods.len]usize = undefined;
    for (&every, 0..) |*e, i| e.* = i;
    const runner_mod = runnerModule(b, target, optimize, harness, &built, .{ .harness = true, .mods = &every });
    const runner = addExe(b, .{ .name = "deepwave-conformance", .root_module = runner_mod });
    b.installArtifact(runner);

    const routed: ?*std.Build.Step.Compile = if (split) if (routeSuite(b, suite)) |set|
        addExe(b, .{ .name = set.exeName(b), .root_module = runnerModule(b, target, optimize, harness, &built, set) })
    else
        null else null;
    const suite_runner = routed orelse runner;

    // `./zig build conformance-runners`: every per-module runner, compiled in parallel (-j).
    const runners_step = b.step("conformance-runners", "Build and install every deepwave-conformance-<module> runner (in parallel, -j)");
    for (0..mods.len + 1) |i| {
        const set: RunnerSet = if (i == mods.len) .{ .harness = true } else .{ .mods = b.allocator.dupe(usize, &.{i}) catch @panic("OOM") };
        runners_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = set.exeName(b), .root_module = runnerModule(b, target, optimize, harness, &built, set) }), .{}).step);
    }

    const conf_step = b.step("test-conformance", "Run conformance suite(s) against $ZUI_CORPUS (-Dsuite=<name>)");
    const run_conf = b.addRunArtifact(suite_runner);
    run_conf.has_side_effects = true;
    run_conf.setCwd(b.path(".")); // suites that run repo tools (lean_suite.zig) use repo-relative paths
    run_conf.addArgs(&.{ "--suite", suite, "--limit", b.fmt("{d}", .{limit}), "--filter", filter, "--jobs", b.fmt("{d}", .{jobs}) });
    conf_step.dependOn(&run_conf.step);

    const bench_step = b.step("bench", "Run suite benches (-Dsuite=<name>, use -Doptimize=fast)");
    const run_bench = b.addRunArtifact(suite_runner);
    run_bench.has_side_effects = true;
    run_bench.setCwd(b.path("."));
    run_bench.addArgs(&.{ "--bench", "--suite", suite, "--iters", b.fmt("{d}", .{iters}), "--limit", b.fmt("{d}", .{limit}), "--filter", filter, "--bench-bytes", b.fmt("{d}", .{bench_bytes}) });
    bench_step.dependOn(&run_bench.step);
    // tools/perfgate.sh runs the routed runner itself (under perf stat), so it installs it.
    const runner_install_step = b.step("conformance-runner", "Install the runner -Dsuite routes to into zig-out/bin (tools/perfgate.sh)");
    runner_install_step.dependOn(&b.addInstallArtifact(suite_runner, .{}).step);

    // deepwave: the full node (src/node/main.zig). `./zig build node` installs it to zig-out/bin.
    // -Dnode-test-flags: test-only flags (`--snapshot-expect-root`, a trust bypass) in the binary.
    const node_test_opts = b.addOptions();
    node_test_opts.addOption(bool, "test_flags", b.option(bool, "node-test-flags", "deepwave: build test-only flags such as --snapshot-expect-root") orelse false);
    const node_mod = b.createModule(.{
        .root_source_file = b.path("src/node/main.zig"),
        .link_libc = true, // getenv/clock_gettime: implicit on macOS, explicit for Linux (bench machine's setup.sh checks this line)
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "node", .module = built[indexOf("node")] },
            // ExecuteTransaction (src/rpc_exec/live/node_exec.zig, DROP-IN G10)
            .{ .name = "rpc_exec", .module = built[indexOf("rpc_exec")] },
            .{ .name = "move_vm", .module = built[indexOf("move_vm")] }, // --vm-aot (src/move/vm/aot.zig)
            .{ .name = "edge", .module = built[indexOf("edge")] },
            .{ .name = "node_options", .module = node_test_opts.createModule() },
        },
    });
    // `deepwave --version` prints `deepwave <version>-<sha>` (src/node/ops.zig). Only the
    // executable's root module gets the sha, so a new commit rebuilds main.zig and nothing else.
    const node_opts = b.addOptions();
    node_opts.addOption([]const u8, "git_sha", b.option([]const u8, "git-sha", "deepwave --version commit (default: git rev-parse --short=12 HEAD)") orelse gitSha(b));
    node_mod.addOptions("build_options", node_opts);
    const node_exe = addExe(b, .{ .name = "deepwave", .root_module = node_mod });
    const node_step = b.step("node", "Build the deepwave full node binary");
    node_step.dependOn(&b.addInstallArtifact(node_exe, .{}).step);

    // deepwave-tool: sui-tool / db-tool operator commands on a stopped node directory
    // (src/node/tool.zig, lane fullnode-ops). `./zig build tool`.
    const tool_mod = b.createModule(.{
        .root_source_file = b.path("src/node/tool.zig"),
        .link_libc = true,
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "node", .module = built[indexOf("node")] },
            .{ .name = "exec", .module = built[indexOf("exec")] },
            .{ .name = "bcs", .module = built[indexOf("bcs")] },
            .{ .name = "checkpoint", .module = built[indexOf("checkpoint")] },
            .{ .name = "serve", .module = built[indexOf("serve")] },
        },
    });
    const tool_step = b.step("tool", "Build deepwave-tool (sui-tool operator commands for a deepwave node directory)");
    tool_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-tool", .root_module = tool_mod }), .{}).step);

    // deepwave-aot: compiler of the Move VM's ahead-of-time tier (tools/aot/main.zig, lane vm-aot).
    // `./zig build aot`; usage in the file header.
    const aot_mod = b.createModule(.{
        .root_source_file = b.path("tools/aot/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "move_vm", .module = built[indexOf("move_vm")] },
            .{ .name = "move_format", .module = built[indexOf("move_format")] },
        },
    });
    const aot_step = b.step("aot", "Build deepwave-aot (Move bytecode to Zig compiler for the hot-package tier)");
    aot_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-aot", .root_module = aot_mod }), .{}).step);

    // deepwave-gpu-check: GPU-vs-CPU equality harness and bench (src/gpu/check.zig). `./zig build gpu-check`.
    const gpu_check_mod = b.createModule(.{
        .root_source_file = b.path("tools/gpu/check.zig"),
        .link_libc = true,
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "gpu", .module = built[indexOf("gpu")] }},
    });
    const gpu_check_step = b.step("gpu-check", "Build deepwave-gpu-check (GPU vs CPU equality harness and bench)");
    gpu_check_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-gpu-check", .root_module = gpu_check_mod }), .{}).step);

    // deepwave-dst: the node simulation tester over many seeds (src/node/dst/main.zig).
    // `./zig build dst` (use -Doptimize=ReleaseFast for soaks).
    const dst_mod = b.createModule(.{
        .root_source_file = b.path("src/node/dst/main.zig"),
        .link_libc = true,
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "node", .module = built[indexOf("node")] }},
    });
    const dst_step = b.step("dst", "Build deepwave-dst (deterministic simulation tester of the node, many seeds)");
    dst_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-dst", .root_module = dst_mod }), .{}).step);

    // deepwave-native: zui/1 test and bench client (tools/native/client.zig). `./zig build native-client`.
    const native_client_mod = b.createModule(.{
        .root_source_file = b.path("tools/native/client.zig"),
        .link_libc = true,
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "net", .module = built[indexOf("net")] },
            .{ .name = "native", .module = built[indexOf("native")] },
            .{ .name = "serve", .module = built[indexOf("serve")] },
        },
    });
    const native_client_step = b.step("native-client", "Build deepwave-native (zui/1 test and bench client)");
    native_client_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-native", .root_module = native_client_mod }), .{}).step);

    // deepwave-simproxy (rpc-exec, G9 parity tool): SimulateTransaction on deepwave's engine with the
    // pre-state read from an upstream node. `./zig build simproxy`.
    const simproxy_mod = b.createModule(.{
        .root_source_file = b.path("src/rpc_exec/simproxy.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "rpc_exec", .module = built[indexOf("rpc_exec")] },
            .{ .name = "exec", .module = built[indexOf("exec")] },
            .{ .name = "serve", .module = built[indexOf("serve")] },
        },
    });
    const simproxy_step = b.step("simproxy", "Build deepwave-simproxy (SimulateTransaction parity proxy)");
    simproxy_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-simproxy", .root_module = simproxy_mod }), .{}).step);

    // deepwave-execute: live ExecuteTransaction tool (src/rpc_exec/live/main.zig, DROP-IN G10).
    const exec_live_mod = b.createModule(.{
        .root_source_file = b.path("src/rpc_exec/live/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "rpc_exec", .module = built[indexOf("rpc_exec")] },
            .{ .name = "serve", .module = built[indexOf("serve")] },
            .{ .name = "types", .module = built[indexOf("types")] },
            .{ .name = "bcs", .module = built[indexOf("bcs")] },
            .{ .name = "protocol", .module = built[indexOf("protocol")] },
        },
    });
    const exec_live_step = b.step("execute", "Build the deepwave-execute live ExecuteTransaction tool");
    exec_live_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-execute", .root_module = exec_live_mod }), .{}).step);

    // deepwave-hw: hardware report and the every-path comparison harness (tools/hw/main.zig).
    // `./zig build hw`.
    const hw_mod = b.createModule(.{
        .root_source_file = b.path("tools/hw/main.zig"),
        .link_libc = true,
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "core", .module = g.core },
            .{ .name = "hash", .module = built[indexOf("hash")] },
            .{ .name = "sig", .module = built[indexOf("sig")] },
            .{ .name = "bls", .module = built[indexOf("bls")] },
            .{ .name = "zk", .module = built[indexOf("zk")] },
            .{ .name = "gpu", .module = built[indexOf("gpu")] },
        },
    });
    const hw_step = b.step("hw", "Build deepwave-hw (hardware report, every-path comparison harness)");
    hw_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-hw", .root_module = hw_mod }), .{}).step);

    // deepwave-store-bench: restore-shaped commit bench and chunk codec level study
    // (tools/bench/restore_bench.zig, lane fast-compress). `./zig build store-bench -Doptimize=ReleaseFast`.
    const store_bench_mod = b.createModule(.{
        .root_source_file = b.path("tools/bench/restore_bench.zig"),
        .link_libc = true,
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "store", .module = built[indexOf("store")] },
            .{ .name = "bcs", .module = built[indexOf("bcs")] },
            .{ .name = "types", .module = built[indexOf("types")] },
        },
    });
    const store_bench_step = b.step("store-bench", "Build deepwave-store-bench (restore-shaped commit bench, chunk codec study)");
    store_bench_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-store-bench", .root_module = store_bench_mod }), .{}).step);

    // deepwave-standby: hot-standby lease agent/acceptor and the watchdog (src/standby, docs/STANDBY.md).
    // Pure std, no lane modules. `./zig build standby`; its tests run under `./zig build test -Dlane=standby`.
    const standby_mod = b.createModule(.{
        .root_source_file = b.path("src/standby/main.zig"),
        .link_libc = true,
        .target = target,
        .optimize = optimize,
    });
    const standby_step = b.step("standby", "Build deepwave-standby (lease agent, acceptor, watchdog)");
    standby_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-standby", .root_module = standby_mod }), .{}).step);
    const standby_test_mod = b.createModule(.{
        .root_source_file = b.path("src/standby/root.zig"),
        .link_libc = true,
        .target = target,
        .optimize = optimize,
    });

    // deepwave-move: Move tooling over deepwave's store and VM (tools/move/main.zig):
    // gas report, gas profiler, storage-layout advisor, bytecode optimizer, superoptimizer.
    // `./zig build move-tools`.
    const move_tools_mod = b.createModule(.{
        .root_source_file = b.path("tools/move/main.zig"),
        .link_libc = true,
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "node", .module = built[indexOf("node")] },
            .{ .name = "exec", .module = built[indexOf("exec")] },
            .{ .name = "bcs", .module = built[indexOf("bcs")] },
            .{ .name = "types", .module = built[indexOf("types")] },
            .{ .name = "store", .module = built[indexOf("store")] },
            .{ .name = "serve", .module = built[indexOf("serve")] },
            .{ .name = "move_format", .module = built[indexOf("move_format")] },
            .{ .name = "move_vm", .module = built[indexOf("move_vm")] },
            .{ .name = "protocol", .module = built[indexOf("protocol")] },
            .{ .name = "rpc_exec", .module = built[indexOf("rpc_exec")] },
            .{ .name = "simulate", .module = built[indexOf("simulate")] },
        },
    });
    const move_tools_step = b.step("move-tools", "Build deepwave-move (gas report, profiler, layout advisor, optimizer, superoptimizer)");
    move_tools_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-move", .root_module = move_tools_mod }), .{}).step);

    // Unit tests per module.
    const test_step = b.step("test", "Unit tests (all modules, or -Dlane=<module>)");
    const unit = [_]struct { name: []const u8, mod: *std.Build.Module }{
        .{ .name = "core", .mod = core },
        .{ .name = "harness", .mod = harness },
    };
    for (unit) |u| addTest(b, test_step, lane_filter, u.name, u.mod);
    addTestNamed(b, test_step, lane_filter, "harness", "runner", runner_mod);
    for (mods, 0..) |m, i| addTest(b, test_step, lane_filter, m.name, built[i]);
    addTest(b, test_step, lane_filter, "standby", standby_test_mod);

    // Validator (docs/VALIDATOR-DESIGN.md, unaudited): the consensus, consensus_net and validator
    // modules and deepwave-validator. A separate table from `mods`, so deepwave, deepwave-tool, the
    // conformance runners and the plain `test` step never compile them; they build only through
    // `./zig build validator`, `./zig build test-validator` or `-Dlane=<one of them>`.
    // -Dvalidator-unaudited=true (default false) compiles in the gate branch that may allow a
    // non-local network with the runtime flag; off, local test committees are the only option.
    const val_unaudited = b.option(bool, "validator-unaudited", "deepwave-validator: allow non-local networks behind a runtime flag (UNAUDITED; default false)") orelse false;
    addValidator(b, target, optimize, core, harness, &built, test_step, lane_filter, val_unaudited, .{ .suite = suite, .limit = limit, .filter = filter, .jobs = jobs });

    addTest(b, test_step, lane_filter, "move_tools", move_tools_mod); // tools/move (lane move-tools)

    // wasm-light: the verify-only light client. `./zig build wasm-light`
    // installs zig-out/wasm/deepwave-light.wasm; `./zig build test -Dlane=light` runs its unit tests.
    const light_native = b.createModule(.{
        .root_source_file = b.path("src/light/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "bcs", .module = built[indexOf("bcs")] },
            .{ .name = "types", .module = built[indexOf("types")] },
            .{ .name = "hash", .module = built[indexOf("hash")] },
            .{ .name = "bls", .module = built[indexOf("bls")] },
            .{ .name = "checkpoint", .module = built[indexOf("checkpoint")] },
        },
    });
    addTest(b, test_step, lane_filter, "light", light_native);
    addWasmLight(b);
    // Cloudflare Workers (lane edge, clients/ts/light/worker): the same client, size-optimized.
    // `./zig build wasm-worker` installs zig-out/wasm/deepwave-light-worker.wasm.
    addWasmLightBuild(b, .ReleaseSmall, "deepwave-light-worker", "wasm-worker", "Build the wasm32 light client for Cloudflare Workers, size-optimized (zig-out/wasm/deepwave-light-worker.wasm)");

    const lean_step = b.step("lean", "Build Lean 4 specs and proofs, reject sorry (lean/check.sh)");
    const lean_run = b.addSystemCommand(&.{ "bash", "lean/check.sh" });
    lean_run.has_side_effects = true;
    lean_step.dependOn(&lean_run.step);
}

const val_mods = [_]Mod{
    .{ .name = "consensus", .path = "src/consensus/root.zig", .deps = &.{ "bcs", "types", "hash", "sig", "protocol", "store" } },
    .{ .name = "consensus_net", .path = "src/consensus/net/root.zig", .deps = &.{ "rt", "net", "bcs", "types", "hash", "sig", "protocol", "store", "serve", "consensus" } },
    .{ .name = "validator", .path = "src/validator/root.zig", .deps = &.{ "rt", "net", "bcs", "types", "hash", "sig", "bls", "zk", "move_format", "protocol", "store", "checkpoint", "natives", "move_vm", "exec", "sync", "history", "serve", "index", "rpc_exec", "simulate", "native", "node", "gpu", "consensus", "consensus_net" } },
};

/// The validator modules (val_mods), `./zig build validator` (deepwave-validator) and
/// `./zig build test-validator`. Unit tests also run with `./zig build test -Dlane=<name>`.
fn addValidator(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    core: *std.Build.Module,
    harness: *std.Build.Module,
    built: []const *std.Build.Module,
    test_step: *std.Build.Step,
    lane_filter: ?[]const u8,
    unaudited: bool,
    conf: struct { suite: []const u8, limit: u64, filter: []const u8, jobs: u32 },
) void {
    const opts = b.addOptions();
    opts.addOption(bool, "validator_unaudited", unaudited);
    const opts_mod = opts.createModule();
    var vbuilt: [val_mods.len]*std.Build.Module = undefined;
    for (val_mods, 0..) |m, i| {
        const mod = b.createModule(.{ .root_source_file = b.path(m.path), .target = target, .optimize = optimize });
        mod.addImport("core", core);
        mod.addImport("harness", harness);
        mod.addImport("validator_options", opts_mod);
        dep: for (m.deps) |d| {
            for (val_mods[0..i], 0..) |vm, j| if (std.mem.eql(u8, vm.name, d)) {
                mod.addImport(d, vbuilt[j]);
                continue :dep;
            };
            mod.addImport(d, built[indexOf(d)]);
        }
        vbuilt[i] = mod;
    }
    const vtest = b.step("test-validator", "Unit tests of consensus, consensus_net and validator");
    for (val_mods, 0..) |m, i| {
        vtest.dependOn(&b.addRunArtifact(addTestExe(b, .{ .name = b.fmt("test-{s}", .{m.name}), .root_module = vbuilt[i] })).step);
        if (lane_filter) |f| if (std.mem.eql(u8, f, m.name)) addTest(b, test_step, f, m.name, vbuilt[i]);
    }
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/validator/main.zig"),
        .link_libc = true,
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "validator", .module = vbuilt[val_mods.len - 1] }},
    });
    // Conformance of the consensus module: deepwave-conformance-consensus links the consensus suites only
    // (consensus-block, consensus-replay) and reads vectors from $ZUI_CORPUS/consensus/. The shared
    // runner root is src/harness/main.zig; `./zig build test-conformance-consensus` runs it.
    {
        const text = "//! Generated by build.zig: the validator lane modules this conformance runner links.\npub const harness_suites = false;\npub const lanes = .{ @import(\"consensus\") };\n";
        const wf = b.addWriteFiles();
        const lanes_mod = b.createModule(.{ .root_source_file = wf.add("zui_lanes.zig", text), .target = target, .optimize = optimize });
        lanes_mod.addImport("consensus", vbuilt[0]);
        const runner_mod = b.createModule(.{
            .root_source_file = b.path("src/harness/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{ .{ .name = "harness", .module = harness }, .{ .name = "zui_lanes", .module = lanes_mod } },
        });
        const runner = addExe(b, .{ .name = "deepwave-conformance-consensus", .root_module = runner_mod });
        const install_step = b.step("conformance-consensus", "Build and install deepwave-conformance-consensus (validator consensus suites)");
        install_step.dependOn(&b.addInstallArtifact(runner, .{}).step);
        const cconf = b.step("test-conformance-consensus", "Run the consensus conformance suites against $ZUI_CORPUS/consensus/ (UNAUDITED validator code)");
        const run = b.addRunArtifact(runner);
        run.has_side_effects = true;
        run.addArgs(&.{ "--suite", "val-consensus-core", "--jobs", "1" });
        cconf.dependOn(&run.step);
    }
    // Conformance runner of the validator suites (src/validator/conformance.zig): the same harness
    // as deepwave-conformance, linking only the validator module. Pass the runner's own options after
    // the usual -Dsuite, -Dlimit, -Dfilter and -Djobs, e.g.
    // `./zig build test-validator-conformance -Dsuite=checkpoint-build -Djobs=16`.
    const vconf_lanes = b.addWriteFiles().add("zui_lanes.zig", "pub const harness_suites = false;\npub const lanes = .{ @import(\"validator\") };\n");
    const vconf_lanes_mod = b.createModule(.{ .root_source_file = vconf_lanes, .target = target, .optimize = optimize });
    vconf_lanes_mod.addImport("validator", vbuilt[val_mods.len - 1]);
    const vconf_mod = b.createModule(.{
        .root_source_file = b.path("src/harness/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "harness", .module = harness }, .{ .name = "zui_lanes", .module = vconf_lanes_mod } },
    });
    const vconf = addExe(b, .{ .name = "deepwave-conformance-validator", .root_module = vconf_mod });
    const vconf_step = b.step("test-validator-conformance", "Run the validator conformance suites against $ZUI_CORPUS (-Dsuite=<name>)");
    const vconf_run = b.addRunArtifact(vconf);
    vconf_run.has_side_effects = true;
    vconf_run.setCwd(b.path("."));
    vconf_run.addArgs(&.{ "--suite", conf.suite, "--limit", b.fmt("{d}", .{conf.limit}), "--filter", conf.filter, "--jobs", b.fmt("{d}", .{conf.jobs}) });
    vconf_step.dependOn(&vconf_run.step);
    const vconf_build = b.step("validator-conformance-runner", "Build deepwave-conformance-validator");
    vconf_build.dependOn(&b.addInstallArtifact(vconf, .{}).step);

    const step = b.step("validator", "Build deepwave-validator (UNAUDITED; gated to local test committees unless -Dvalidator-unaudited)");
    step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-validator", .root_module = exe_mod }), .{}).step);

    // deepwave-consensus-localnet (val-consensus-net): N consensus authorities on loopback, generated keys.
    const ln_mod = b.createModule(.{
        .root_source_file = b.path("src/consensus/net/localnet_main.zig"),
        .link_libc = true,
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "consensus_net", .module = vbuilt[1] }},
    });
    const ln_step = b.step("consensus-localnet", "Build deepwave-consensus-localnet (loopback test committee, generated keys)");
    ln_step.dependOn(&b.addInstallArtifact(addExe(b, .{ .name = "deepwave-consensus-localnet", .root_module = ln_mod }), .{}).step);
}

/// `zig build wasm-light [-Dwasm-optimize=fast|small]`: the lane modules the light
/// client reaches, rebuilt for wasm32-freestanding with SIMD128 (no libc, no threads).
fn addWasmLight(b: *std.Build) void {
    const wopt = b.option(std.builtin.OptimizeMode, "wasm-optimize", "wasm-light optimize mode (default fast)") orelse .fast;
    addWasmLightBuild(b, wopt, "deepwave-light", "wasm-light", "Build the wasm32 verify-only light client (zig-out/wasm/deepwave-light.wasm)");
}

fn addWasmLightBuild(b: *std.Build, wopt: std.builtin.OptimizeMode, exe_name: []const u8, step_name: []const u8, step_doc: []const u8) void {
    const wt = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
        .cpu_features_add = std.Target.wasm.featureSet(&.{ .simd128, .bulk_memory, .sign_ext, .nontrapping_fptoint, .mutable_globals, .multivalue }),
    });
    const wcore = b.createModule(.{ .root_source_file = b.path("src/core/root.zig"), .target = wt, .optimize = wopt });
    // core/cpu.zig reads cpu_options: no kernel objects off x86-64.
    const wopts = b.addOptions();
    wopts.addOption(u8, "kernel_tier", 0xff);
    wopts.addOption(u8, "linked_mask", 0);
    wcore.addOptions("cpu_options", wopts);
    const names = [_][]const u8{ "bcs", "hash", "types", "bls", "checkpoint" };
    var wm: [names.len]*std.Build.Module = undefined;
    for (names, 0..) |n, i| {
        const m = mods[indexOf(n)];
        wm[i] = b.createModule(.{ .root_source_file = b.path(m.path), .target = wt, .optimize = wopt });
        wm[i].addImport("core", wcore);
        for (m.deps) |d| for (names[0..i], 0..) |pn, j| if (std.mem.eql(u8, pn, d)) wm[i].addImport(d, wm[j]);
    }
    const lmod = b.createModule(.{ .root_source_file = b.path("src/light/root.zig"), .target = wt, .optimize = wopt });
    for (names, 0..) |n, i| lmod.addImport(n, wm[i]);
    const root = b.createModule(.{
        .root_source_file = b.path("src/light/wasm.zig"),
        .target = wt,
        .optimize = wopt,
        .strip = wopt != .debug,
        .imports = &.{.{ .name = "light", .module = lmod }},
    });
    const exe = addExe(b, .{ .name = exe_name, .root_module = root });
    exe.entry = .disabled;
    exe.rdynamic = true;
    exe.stack_size = 1 << 20;
    const step = b.step(step_name, step_doc);
    step.dependOn(&b.addInstallArtifact(exe, .{ .dest_dir = .{ .override = .{ .custom = "wasm" } } }).step);
}

const CpuOptions = struct { kernel_tier: u8, linked_mask: u8 };

const Graph = struct {
    core: *std.Build.Module,
    harness: *std.Build.Module,
    built: [mods.len]*std.Build.Module,
};

/// core, harness and the lane modules for one target. The main graph is named (b.addModule);
/// kernel-object graphs are private copies compiled for a kernel tier.
fn moduleGraph(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, cpu_opts: CpuOptions) Graph {
    const main = cpu_opts.kernel_tier == 0xff;
    const opts = b.addOptions();
    opts.addOption(u8, "kernel_tier", cpu_opts.kernel_tier);
    opts.addOption(u8, "linked_mask", cpu_opts.linked_mask);
    const core_opts: std.Build.Module.CreateOptions = .{
        .root_source_file = b.path("src/core/root.zig"),
        // serve, bls and node call std.c (getenv, getpid): Linux needs libc linked explicitly (macOS always links it).
        .link_libc = true,
        .target = target,
        .optimize = optimize,
        .pic = if (main) null else true,
    };
    const core = if (main) b.addModule("core", core_opts) else b.createModule(core_opts);
    core.addOptions("cpu_options", opts);
    const harness_opts: std.Build.Module.CreateOptions = .{
        .root_source_file = b.path("src/harness/root.zig"),
        .target = target,
        .optimize = optimize,
        .pic = if (main) null else true,
        .imports = &.{.{ .name = "core", .module = core }},
    };
    const harness = if (main) b.addModule("harness", harness_opts) else b.createModule(harness_opts);

    var built: [mods.len]*std.Build.Module = undefined;
    for (mods, 0..) |m, i| {
        const mod_opts: std.Build.Module.CreateOptions = .{
            .root_source_file = b.path(m.path),
            .target = target,
            .optimize = optimize,
            .pic = if (main) null else true,
        };
        const mod = if (main) b.addModule(m.name, mod_opts) else b.createModule(mod_opts);
        mod.addImport("core", core);
        mod.addImport("harness", harness);
        for (m.deps) |d| mod.addImport(d, built[indexOf(d)]);
        if (std.mem.eql(u8, m.name, "store")) addZstd(b, mod);
        built[i] = mod;
    }
    return .{ .core = core, .harness = harness, .built = built };
}

/// Kernel tiers above what `target` already has (none off x86-64).
fn kernelMask(target: std.Build.ResolvedTarget) u8 {
    if (target.result.cpu.arch != .x86_64) return 0;
    const native = cpu_tiers.ofFeatureSet(target.result.cpu.features);
    var mask: u8 = 0;
    for (cpu_tiers.kernel_tiers) |t| {
        if (@intFromEnum(t) > @intFromEnum(native)) mask |= @as(u8, 1) << @intCast(@intFromEnum(t));
    }
    return mask;
}

/// One object per kernel tier (src/cpu_kernels.zig compiled for that tier's CPU), linked through
/// `core` so every x86-64 binary that can dispatch carries them.
fn addKernelObjects(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, core: *std.Build.Module) void {
    const mask = kernelMask(target);
    for (cpu_tiers.kernel_tiers) |t| {
        if ((mask >> @intCast(@intFromEnum(t))) & 1 == 0) continue;
        var q = target.query;
        q.cpu_arch = .x86_64;
        q.cpu_model = .{ .explicit = cpu_tiers.model(t) };
        q.cpu_features_add = std.Target.x86.featureSet(cpu_tiers.features(t));
        q.cpu_features_sub = .empty;
        const kt = b.resolveTargetQuery(q);
        const g = moduleGraph(b, kt, optimize, .{ .kernel_tier = @intFromEnum(t), .linked_mask = 0 });
        const root = b.createModule(.{
            .root_source_file = b.path("src/cpu_kernels.zig"),
            .target = kt,
            .optimize = optimize,
            .pic = true,
            .imports = &.{
                .{ .name = "core", .module = g.core },
                .{ .name = "hash", .module = g.built[indexOf("hash")] },
                .{ .name = "sig", .module = g.built[indexOf("sig")] },
                .{ .name = "bls", .module = g.built[indexOf("bls")] },
                .{ .name = "zk", .module = g.built[indexOf("zk")] },
            },
        });
        // LLVM always: the asm field kernels (secp256r1) are LLVM-only.
        const obj = b.addObject(.{ .name = b.fmt("zui-kernels-{s}", .{@tagName(t)}), .root_module = root, .use_llvm = true });
        core.addObject(obj);
    }
}

/// Zig's own x86 backend (the Debug default on x86-64) assembles inline asm only for the
/// target's CPU features, so a Debug build for a CPU without SHA (-Dcpu=baseline) cannot compile
/// the runtime-dispatched SHA-NI kernel (src/crypto/hash/sha2.zig compress256Ni: "no encoding
/// found for pshufb"). Those builds use LLVM, which assembles it, so the kernel stays compiled
/// and tested; Debug builds for a SHA CPU (native on the boxes) keep the faster backend.
fn llvmFor(mod: *std.Build.Module) ?bool {
    const t = (mod.resolved_target orelse return null).result;
    if (t.cpu.arch != .x86_64 or (mod.optimize orelse .debug) != .debug) return null;
    if (std.Target.x86.featureSetHasAll(t.cpu.features, .{ .sha, .ssse3 })) return null;
    return true;
}

fn addExe(b: *std.Build, opts: std.Build.ExecutableOptions) *std.Build.Step.Compile {
    var o = opts;
    if (o.use_llvm == null) o.use_llvm = llvmFor(o.root_module);
    return b.addExecutable(o);
}

fn addTestExe(b: *std.Build, opts: std.Build.TestOptions) *std.Build.Step.Compile {
    var o = opts;
    if (o.use_llvm == null) o.use_llvm = llvmFor(o.root_module);
    return b.addTest(o);
}

fn addTest(b: *std.Build, step: *std.Build.Step, filter: ?[]const u8, name: []const u8, mod: *std.Build.Module) void {
    addTestNamed(b, step, filter, name, name, mod);
}

fn addTestNamed(b: *std.Build, step: *std.Build.Step, filter: ?[]const u8, name: []const u8, artifact: []const u8, mod: *std.Build.Module) void {
    if (filter) |f| if (!std.mem.eql(u8, f, name)) return;
    const t = addTestExe(b, .{ .name = b.fmt("test-{s}", .{artifact}), .root_module = mod });
    step.dependOn(&b.addRunArtifact(t).step);
}

/// Which suites a runner links: the harness suites and/or some lane modules (indices into `mods`,
/// in table order).
const RunnerSet = struct {
    harness: bool = false,
    mods: []const usize = &.{},

    /// deepwave-conformance (everything), deepwave-conformance-harness, deepwave-conformance-<module>[+<module>..].
    fn exeName(set: RunnerSet, b: *std.Build) []const u8 {
        if (set.harness and set.mods.len == mods.len) return "deepwave-conformance";
        var name: std.ArrayList(u8) = .empty;
        name.appendSlice(b.allocator, "deepwave-conformance") catch @panic("OOM");
        if (set.harness) name.appendSlice(b.allocator, "-harness") catch @panic("OOM");
        for (set.mods, 0..) |i, k| name.print(b.allocator, "{s}{s}", .{ if (k == 0 and !set.harness) "-" else "+", mods[i].name }) catch @panic("OOM");
        return name.items;
    }
};

/// The runner root (src/harness/main.zig) imports `zui_lanes`, a generated file that lists the
/// lane modules this runner links.
fn runnerModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, harness: *std.Build.Module, built: []const *std.Build.Module, set: RunnerSet) *std.Build.Module {
    var text: std.ArrayList(u8) = .empty;
    const a = b.allocator;
    text.appendSlice(a, "//! Generated by build.zig: the lane modules this conformance runner links.\n") catch @panic("OOM");
    text.print(a, "pub const harness_suites = {};\npub const lanes = .{{", .{set.harness}) catch @panic("OOM");
    for (set.mods) |i| text.print(a, " @import(\"{s}\"),", .{mods[i].name}) catch @panic("OOM");
    text.appendSlice(a, " };\n") catch @panic("OOM");
    const wf = b.addWriteFiles();
    const lanes_mod = b.createModule(.{ .root_source_file = wf.add("zui_lanes.zig", text.items), .target = target, .optimize = optimize });
    for (set.mods) |i| lanes_mod.addImport(mods[i].name, built[i]);
    return b.createModule(.{
        .root_source_file = b.path("src/harness/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "harness", .module = harness }, .{ .name = "zui_lanes", .module = lanes_mod } },
    });
}

/// Routes a -Dsuite selection (comma list of suite or lane names) to the smallest runner that
/// holds every selected suite: the modules (and/or harness suites) that declare them. Null (the
/// all-in-one runner) for `all`, `list` and names no suites array declares, so those still get
/// the runner's own answer. Suite and lane names come from each module's `pub const suites`
/// array, read here with the Zig tokenizer.
fn routeSuite(b: *std.Build, selection: []const u8) ?RunnerSet {
    var with_harness = false;
    var picked: [mods.len]bool = @splat(false);
    var it = std.mem.splitScalar(u8, selection, ',');
    var any = false;
    while (it.next()) |raw| {
        const w = std.mem.trim(u8, raw, " ");
        if (w.len == 0) continue;
        var hit = false;
        for ([_][]const u8{ "src/harness/corpus_suite.zig", "src/harness/lean_suite.zig" }) |f| if (declaresSuite(b, f, w)) {
            with_harness = true;
            hit = true;
        };
        for (mods, 0..) |m, i| {
            const conf = b.fmt("{s}/conformance.zig", .{std.fs.path.dirname(m.path).?});
            if (!declaresSuite(b, conf, w)) continue;
            picked[i] = true;
            hit = true;
        }
        if (!hit) return null;
        any = true;
    }
    if (!any) return null;
    var list: std.ArrayList(usize) = .empty;
    for (picked, 0..) |p, i| if (p) list.append(b.allocator, i) catch @panic("OOM");
    return .{ .harness = with_harness, .mods = list.items };
}

/// True if `sub_path`'s top-level `suites` array has an element whose `.name` or `.lane` is `w`.
fn declaresSuite(b: *std.Build, sub_path: []const u8, w: []const u8) bool {
    b.dependOnFileContents(b.path(sub_path));
    const full = b.root.joinString(b.allocator, sub_path) catch @panic("OOM");
    const src = std.Io.Dir.cwd().readFileAllocOptions(b.graph.io, full, b.allocator, .limited(1 << 24), .of(u8), 0) catch return false;
    var tok: std.zig.Tokenizer = .init(src);
    // Find `pub const suites =`, then walk its initializer: depth 1 is the array, depth 2 a Suite.
    var state: u8 = 0;
    var depth: usize = 0;
    var prev: [3]std.zig.Token.Tag = .{ .invalid, .invalid, .invalid };
    var field: []const u8 = "";
    while (true) {
        const t = tok.next();
        if (t.tag == .eof) return false;
        const text = src[t.loc.start..t.loc.end];
        switch (state) {
            0 => if (t.tag == .identifier and std.mem.eql(u8, text, "suites") and prev[2] == .keyword_const and prev[1] == .keyword_pub) {
                state = 1;
            },
            1 => switch (t.tag) {
                .l_brace => depth += 1,
                .r_brace => {
                    depth -= 1;
                    if (depth == 0) return false;
                },
                .identifier => if (depth == 2 and prev[2] == .period) {
                    field = text;
                },
                .string_literal => if (depth == 2 and prev[2] == .equal and (std.mem.eql(u8, field, "name") or std.mem.eql(u8, field, "lane"))) {
                    if (std.mem.eql(u8, text[1 .. text.len - 1], w)) return true;
                },
                else => {},
            },
            else => unreachable,
        }
        if (t.tag != .doc_comment and t.tag != .container_doc_comment) prev = .{ prev[1], prev[2], t.tag };
    }
}

/// The reference zstd library (vendor/zstd, zstd 1.5.7 compress and decompress sides, no
/// multithreading, BSD license in vendor/zstd/LICENSE) compiled into the `store` module for
/// chunk encoding and decoding (src/store/zstd_c.zig). Always built optimized and without UBSan
/// traps: it is vendored C, hot in every read path and on the commit path.
fn addZstd(b: *std.Build, mod: *std.Build.Module) void {
    mod.link_libc = true;
    mod.addCSourceFiles(.{
        .root = b.path("vendor/zstd"),
        .files = &.{
            "common/debug.c",            "common/entropy_common.c",        "common/error_private.c",
            "common/fse_decompress.c",   "common/xxhash.c",                "common/zstd_common.c",
            "decompress/huf_decompress.c", "decompress/zstd_ddict.c",      "decompress/zstd_decompress.c",
            "decompress/zstd_decompress_block.c", "decompress/huf_decompress_amd64.S",
            "compress/fse_compress.c",   "compress/hist.c",                "compress/huf_compress.c",
            "compress/zstd_compress.c",  "compress/zstd_compress_literals.c", "compress/zstd_compress_sequences.c",
            "compress/zstd_compress_superblock.c", "compress/zstd_double_fast.c", "compress/zstd_fast.c",
            "compress/zstd_lazy.c",      "compress/zstd_ldm.c",            "compress/zstd_opt.c",
            "compress/zstd_preSplit.c",
        },
        .flags = &.{ "-O3", "-fno-sanitize=undefined", "-DZSTD_LEGACY_SUPPORT=0", "-DZSTD_TRACE=0", "-DDEBUGLEVEL=0", "-DXXH_NAMESPACE=ZSTD_", "-DZSTD_STRIP_ERROR_STRINGS" },
    });
}

fn indexOf(comptime_name: []const u8) usize {
    for (mods, 0..) |m, i| if (std.mem.eql(u8, m.name, comptime_name)) return i;
    @panic("build.zig: unknown module dependency");
}

/// `git rev-parse --short=12 HEAD`, or "unknown" outside a git checkout (a source tarball).
fn gitSha(b: *std.Build) []const u8 {
    var code: u8 = 0;
    const out = b.runAllowFail(&.{ "git", "rev-parse", "--short=12", "HEAD" }, &code, .ignore) catch return "unknown";
    const t = std.mem.trim(u8, out, " \n\r");
    return if (t.len == 0) "unknown" else t;
}
