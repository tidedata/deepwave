//! Conformance suites of the move-format lane (CONTRACTS.md section 3.3).
//!
//! Truth: `tools/truth/move-format` (Mysten 1.83.1 Rust) over every module in the corpus
//! (published packages, Publish/Upgrade commands), the framework bytecode snapshots, compiled
//! modules in the Mysten tree, and deterministic mutants of all of them. Layout:
//!   vectors/move-binary/configs.jsonl        per protocol version: BinaryConfig, VerifierConfig
//!   vectors/move-binary/packs/pack-NNN.mvp   modules, each u32 LE length + bytes
//!   vectors/move-binary/truth/pack-NNN.jsonl line i = module i: {"h","items":[{"pv","de"}]}
//!   vectors/move-verify/truth/pack-NNN.jsonl line i = module i: {"h","items":[{"pv","move","sui","units"}]}
//! An item is one (module, protocol version) pair.
const std = @import("std");
const harness = @import("harness");
const ff = @import("file_format.zig");
const deser = @import("deserializer.zig");
const ser = @import("serializer.zig");
const vf = @import("verifier/verify.zig");

pub const suites = [_]harness.Suite{
    .{
        .name = "move-binary",
        .lane = "move-format",
        .doc = "every module in corpus packages: deserialize, re-serialize byte-exact, tree equals Rust",
        .run = runBinary,
        .bench = benchBinary,
        .baselines = &.{
            .{ .name = "deserialize", .argv = &.{ "{release}/zui-truth-move-format", "bench", "deserialize" } },
            .{ .name = "serialize", .argv = &.{ "{release}/zui-truth-move-format", "bench", "serialize" } },
        },
        .inputs = .{ .dir = "vectors/move-binary/packs", .suffix = ".mvp" },
    },
    .{
        .name = "move-verify",
        .lane = "move-format",
        .doc = "bytecode verifier + Sui passes per module and protocol version: verdict, status, indices, offsets, Sui message and meter units equal Rust",
        .run = runVerify,
        .bench = benchVerify,
        .baselines = &.{
            .{ .name = "verify", .argv = &.{ "{release}/zui-truth-move-format", "bench", "verify" } },
        },
        .inputs = .{ .dir = "vectors/move-binary/packs", .suffix = ".mvp" },
    },
};

// ---------------------------------------------------------------------------------------------
// Shared vector loading

pub const Config = struct {
    pv: u64,
    binary: deser.BinaryConfig,
    verifier_json: std.json.Value,
    verifier: vf.Config,
    /// vectors/move-verify/natives/<pv>.txt, when present.
    natives: ?vf.Natives = null,
};

pub const Configs = struct {
    list: []Config,
    pub fn get(c: *const Configs, pv: u64) ?*const Config {
        for (c.list) |*x| if (x.pv == pv) return x;
        return null;
    }
};

pub fn loadConfigs(ctx: *harness.Ctx, arena: std.mem.Allocator) !Configs {
    const text = try ctx.corpus.readFileAlloc(ctx.io, "vectors/move-binary/configs.jsonl", arena, .limited(16 << 20));
    var list: std.ArrayList(Config) = .empty;
    var it = harness.lines(text);
    while (it.next()) |line| {
        const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{});
        const b = v.object.get("binary").?.object;
        const t = b.get("table").?.array.items;
        var tc: deser.TableConfig = .{};
        inline for (@typeInfo(deser.TableConfig).@"struct".field_names, 0..) |f, i| {
            @field(tc, f) = @intCast(t[i].integer);
        }
        try list.append(arena, .{
            .pv = @intCast(v.object.get("pv").?.integer),
            .binary = .{
                .max_binary_format_version = @intCast(b.get("max_binary_format_version").?.integer),
                .min_binary_format_version = @intCast(b.get("min_binary_format_version").?.integer),
                .check_no_extraneous_bytes = b.get("check_no_extraneous_bytes").?.bool,
                .deprecate_global_storage_ops = b.get("deprecate_global_storage_ops").?.bool,
                .allow_unpublishable = b.get("allow_unpublishable").?.bool,
                .table_config = tc,
                // 1.84 truth lists the profile's limit; older truth predates profiles (LEGACY)
                .type_parameter_index_max = if (b.get("type_parameter_index_max")) |x| @intCast(x.integer) else 65536,
            },
            .verifier_json = v.object.get("verifier").?,
            .verifier = try vf.Config.fromJson(v.object.get("verifier").?),
        });
    }
    return .{ .list = list.items };
}

/// Modules of one pack file (borrowing `bytes`).
pub fn splitPack(arena: std.mem.Allocator, bytes: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < bytes.len) {
        if (bytes.len - i < 4) return error.BadPack;
        const n = std.mem.readInt(u32, bytes[i..][0..4], .little);
        if (bytes.len - i - 4 < n) return error.BadPack;
        try out.append(arena, bytes[i + 4 ..][0..n]);
        i += 4 + n;
    }
    return out.items;
}

fn packName(truth_name: []const u8) []const u8 {
    return truth_name[0 .. std.mem.indexOfScalar(u8, truth_name, '.') orelse truth_name.len];
}

/// Compares a Zig PartialVmError (with its location) against a Rust error JSON object
/// {"major","sub","loc","idx":[[kind,i]..],"off":[[f,o]..]}.
pub fn checkError(c: *harness.Check, what: []const u8, rust: std.json.Value, zig: ff.PartialVmError, loc: ?ff.Location) void {
    const o = rust.object;
    const major: u64 = @intCast(o.get("major").?.integer);
    if (major != @intFromEnum(zig.major)) {
        c.failf("{s}: major status rust {d} zig {d} ({s})", .{ what, major, @intFromEnum(zig.major), @tagName(zig.major) });
        return;
    }
    const sub = o.get("sub").?;
    const rs: ?u64 = if (sub == .null) null else @intCast(sub.integer);
    if (rs != zig.sub_status) c.failf("{s}: sub status rust {?d} zig {?d}", .{ what, rs, zig.sub_status });
    const idx = o.get("idx").?.array.items;
    if (idx.len != zig.n_indices) {
        c.failf("{s}: {d} indices rust, {d} zig", .{ what, idx.len, zig.n_indices });
    } else for (idx, zig.indexSlice()) |r, z| {
        const kind = r.array.items[0].string;
        const i: u64 = @intCast(r.array.items[1].integer);
        if (!std.mem.eql(u8, kind, @tagName(z.kind)) or i != z.idx)
            c.failf("{s}: index rust ({s},{d}) zig ({s},{d})", .{ what, kind, i, @tagName(z.kind), z.idx });
    }
    const off = o.get("off").?.array.items;
    if (off.len != zig.n_offsets) {
        c.failf("{s}: {d} offsets rust, {d} zig", .{ what, off.len, zig.n_offsets });
    } else for (off, zig.offsetSlice()) |r, z| {
        const f: u64 = @intCast(r.array.items[0].integer);
        const of: u64 = @intCast(r.array.items[1].integer);
        if (f != z.fdef or of != z.offset) c.failf("{s}: offset rust ({d},{d}) zig ({d},{d})", .{ what, f, of, z.fdef, z.offset });
    }
    if (loc) |l| {
        const rl = o.get("loc").?.string;
        var buf: [300]u8 = undefined;
        const zl = switch (l) {
            .undefined => "undefined",
            .module => |name| std.fmt.bufPrint(&buf, "module:{s}", .{name}) catch "?",
            .package => "package",
        };
        if (!std.mem.eql(u8, rl, zl) and !(l == .package and std.mem.startsWith(u8, rl, "package:")))
            c.failf("{s}: location rust {s} zig {s}", .{ what, rl, zl });
    }
}

// ---------------------------------------------------------------------------------------------
// move-binary

const BinaryState = struct { configs: *const Configs };

fn runBinary(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const configs = try loadConfigs(ctx, arena_state.allocator());
    const state: BinaryState = .{ .configs = &configs };
    try ctx.forEachFile("vectors/move-binary/truth", ".jsonl", &state, binaryPack);
}

fn binaryPack(state: *const BinaryState, ctx: *harness.Ctx, name: []const u8) !void {
    const a = ctx.scratch();
    const pack = packName(name);
    const truth_text = try ctx.readFile(try std.fmt.allocPrint(a, "vectors/move-binary/truth/{s}", .{name}), 1 << 30);
    const pack_bytes = try ctx.readFile(try std.fmt.allocPrint(a, "vectors/move-binary/packs/{s}.mvp", .{pack}), 1 << 30);
    const modules = try splitPack(a, pack_bytes);
    var it = harness.lines(truth_text);
    var i: usize = 0;
    var item_arena: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer item_arena.deinit();
    while (it.next()) |line| : (i += 1) {
        if (ctx.done()) return;
        const v = try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{});
        if (i >= modules.len) return error.TruthPackMismatch;
        const bytes = modules[i];
        for (v.object.get("items").?.array.items) |item| {
            const pv: u64 = @intCast(item.object.get("pv").?.integer);
            const id = try std.fmt.allocPrint(a, "{s}:{d}@{d}", .{ pack, i, pv });
            if (!ctx.selected(id)) continue;
            _ = item_arena.reset(.retain_capacity);
            const cfg = state.configs.get(pv) orelse {
                ctx.fail(id, "no config for protocol version {d}", .{pv});
                continue;
            };
            checkBinaryItem(ctx, item_arena.allocator(), id, bytes, &cfg.binary, item.object.get("de").?);
        }
    }
    if (i != modules.len) return error.TruthPackMismatch;
}

fn checkBinaryItem(ctx: *harness.Ctx, arena: std.mem.Allocator, id: []const u8, bytes: []const u8, cfg: *const deser.BinaryConfig, de: std.json.Value) void {
    var c = ctx.check(id);
    const res = deser.deserialize(arena, bytes, cfg) catch {
        c.failf("out of memory", .{});
        _ = c.finish();
        return;
    };
    if (de.object.get("err")) |rerr| {
        switch (res) {
            .ok => c.failf("rust rejects (status {d}), zig accepts", .{rerr.object.get("major").?.integer}),
            .err => |e| checkError(&c, "deserialize", rerr, e, null),
        }
        _ = c.finish();
        return;
    }
    const ok = de.object.get("ok").?.object;
    const m = switch (res) {
        .err => |e| {
            c.failf("rust accepts, zig rejects with {s} ({d})", .{ @tagName(e.major), @intFromEnum(e.major) });
            _ = c.finish();
            return;
        },
        .ok => |m| m,
    };
    // shape: the same counts the truth tool records
    const shape = ok.get("shape").?.array.items;
    var code_total: usize = 0;
    for (m.function_defs) |f| if (f.code) |cu| {
        code_total += cu.code.len;
    };
    const mine = [_]u64{
        m.version,                         @intFromBool(m.publishable),         m.self_module_handle_idx,
        m.module_handles.len,              m.datatype_handles.len,              m.function_handles.len,
        m.field_handles.len,               m.friend_decls.len,                  m.struct_def_instantiations.len,
        m.function_instantiations.len,     m.field_instantiations.len,          m.signatures.len,
        m.identifiers.len,                 m.address_identifiers.len,           m.constant_pool.len,
        m.metadata.len,                    m.struct_defs.len,                   m.function_defs.len,
        m.enum_defs.len,                   m.enum_def_instantiations.len,       m.variant_handles.len,
        m.variant_instantiation_handles.len, code_total,
    };
    if (shape.len != mine.len) {
        c.failf("shape length {d}", .{shape.len});
    } else for (shape, mine, 0..) |s, z, k| {
        if (@as(u64, @intCast(s.integer)) != z) c.failf("shape[{d}] rust {d} zig {d}", .{ k, s.integer, z });
    }
    // re-serialization at the module's own version
    const out = ser.serializeAlloc(arena, &m, m.version);
    const s = ok.get("ser").?;
    switch (s) {
        .string => {
            if (out) |b| c.bytes("reserialize", bytes, b) else |e| c.failf("rust reserializes, zig {s}", .{@errorName(e)});
        },
        .object => |so| {
            if (so.get("hex")) |hx| {
                const want = arena.alloc(u8, hx.string.len / 2) catch {
                    c.failf("oom", .{});
                    _ = c.finish();
                    return;
                };
                _ = std.fmt.hexToBytes(want, hx.string) catch c.failf("bad hex", .{});
                if (out) |b| c.bytes("reserialize", want, b) else |e| c.failf("rust reserializes, zig {s}", .{@errorName(e)});
            } else {
                if (out) |_| c.failf("rust fails to reserialize, zig succeeds", .{}) else |_| {}
            }
        },
        else => c.failf("bad ser truth", .{}),
    }
    _ = c.finish();
}

// ---------------------------------------------------------------------------------------------
// bench: same packs as the Rust baseline, protocol MAX config

const BenchState = struct {
    modules: []const []const u8,
    compiled: []const ff.CompiledModule,
    cfg: *const deser.BinaryConfig,
    arena: *std.heap.ArenaAllocator,
};

fn benchBinary(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const configs = try loadConfigs(ctx, a);
    var max_pv: u64 = 0;
    for (configs.list) |c| max_pv = @max(max_pv, c.pv);
    const cfg = &configs.get(max_pv).?.binary;
    var mods: std.ArrayList([]const u8) = .empty;
    for (ctx.benchInputs()) |name| {
        const bytes = try ctx.corpus.readFileAlloc(ctx.io, name, a, .limited(1 << 30));
        try mods.appendSlice(a, try splitPack(a, bytes));
    }
    var compiled: std.ArrayList(ff.CompiledModule) = .empty;
    for (mods.items) |b| switch (try deser.deserialize(a, b, cfg)) {
        .ok => |m| try compiled.append(a, m),
        .err => {},
    };
    var scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer scratch.deinit();
    const st: BenchState = .{ .modules = mods.items, .compiled = compiled.items, .cfg = cfg, .arena = &scratch };
    try ctx.benchPasses("deserialize", "module", mods.items.len, &st, struct {
        fn f(s: *const BenchState) !void {
            for (s.modules) |b| {
                _ = s.arena.reset(.retain_capacity);
                std.mem.doNotOptimizeAway(try deser.deserialize(s.arena.allocator(), b, s.cfg));
            }
        }
    }.f);
    try ctx.benchPasses("serialize", "module", compiled.items.len, &st, struct {
        fn f(s: *const BenchState) !void {
            for (s.compiled) |*m| {
                _ = s.arena.reset(.retain_capacity);
                var out: std.ArrayList(u8) = .empty;
                ser.serialize(s.arena.allocator(), m, m.version, &out) catch {};
                std.mem.doNotOptimizeAway(out.items.len);
            }
        }
    }.f);
}

// ---------------------------------------------------------------------------------------------
// move-verify

fn loadNatives(ctx: *harness.Ctx, arena: std.mem.Allocator, configs: *Configs) !void {
    for (configs.list) |*cfg| {
        const path = try std.fmt.allocPrint(arena, "vectors/move-verify/natives/{d}.txt", .{cfg.pv});
        const text = ctx.corpus.readFileAlloc(ctx.io, path, arena, .limited(16 << 20)) catch |e| switch (e) {
            error.FileNotFound => continue,
            else => return e,
        };
        var set: vf.Natives = .empty;
        var it = harness.lines(text);
        while (it.next()) |line| try set.put(arena, line, {});
        cfg.natives = set;
    }
}

fn runVerify(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    var configs = try loadConfigs(ctx, arena_state.allocator());
    try loadNatives(ctx, arena_state.allocator(), &configs);
    const state: BinaryState = .{ .configs = &configs };
    try ctx.forEachFile("vectors/move-verify/truth", ".jsonl", &state, verifyPack);
}

fn verifyPack(state: *const BinaryState, ctx: *harness.Ctx, name: []const u8) !void {
    const a = ctx.scratch();
    const pack = packName(name);
    const truth_text = try ctx.readFile(try std.fmt.allocPrint(a, "vectors/move-verify/truth/{s}", .{name}), 1 << 30);
    const pack_bytes = try ctx.readFile(try std.fmt.allocPrint(a, "vectors/move-binary/packs/{s}.mvp", .{pack}), 1 << 30);
    const modules = try splitPack(a, pack_bytes);
    var it = harness.lines(truth_text);
    var i: usize = 0;
    var item_arena: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer item_arena.deinit();
    var scratch: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer scratch.deinit();
    while (it.next()) |line| : (i += 1) {
        if (ctx.done()) return;
        const v = try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{});
        if (i >= modules.len) return error.TruthPackMismatch;
        for (v.object.get("items").?.array.items) |item| {
            const pv: u64 = @intCast(item.object.get("pv").?.integer);
            const id = try std.fmt.allocPrint(a, "{s}:{d}@{d}", .{ pack, i, pv });
            if (!ctx.selected(id)) continue;
            _ = item_arena.reset(.retain_capacity);
            const cfg = state.configs.get(pv) orelse {
                ctx.fail(id, "no config for protocol version {d}", .{pv});
                continue;
            };
            checkVerifyItem(ctx, item_arena.allocator(), &scratch, id, modules[i], cfg, item);
        }
    }
    if (i != modules.len) return error.TruthPackMismatch;
}

fn checkVerifyItem(ctx: *harness.Ctx, arena: std.mem.Allocator, scratch: *std.heap.ArenaAllocator, id: []const u8, bytes: []const u8, cfg: *const Config, item: std.json.Value) void {
    var c = ctx.check(id);
    defer _ = c.finish();
    const m = switch (deser.deserialize(arena, bytes, &cfg.binary) catch return c.failf("out of memory", .{})) {
        .ok => |m| m,
        .err => |e| return c.failf("module does not deserialize ({s})", .{@tagName(e.major)}),
    };
    const natives: ?*const vf.Natives = if (cfg.natives) |*n| n else null;
    if (natives == null) return c.failf("no natives table for protocol version {d}", .{cfg.pv});
    const r = vf.verifyModule(arena, scratch, &cfg.verifier, &m, natives) catch return c.failf("out of memory", .{});
    const o = item.object;
    // Move verdict
    const mv = o.get("move").?;
    switch (mv) {
        .string => if (r.move) |e| c.failf("rust accepts, zig rejects with {s} ({d})", .{ @tagName(e.err.major), @intFromEnum(e.err.major) }),
        .object => |mo| if (r.move) |e| checkError(&c, "move", mo.get("err").?, e.err, e.loc) else c.failf("rust rejects (status {d}), zig accepts", .{mo.get("err").?.object.get("major").?.integer}),
        else => c.failf("bad move truth", .{}),
    }
    // Sui verdict (only when the Move verifier passed)
    if (r.move == null) switch (o.get("sui").?) {
        .string => if (r.sui) |e| c.failf("sui: rust ok, zig {s}: {s}", .{ @tagName(e.kind), e.msg }),
        .object => |so| {
            const err = so.get("err").?.object;
            const kind = err.get("kind").?.string;
            const msg: []const u8 = switch (err.get("msg").?) {
                .string => |x| x,
                else => "",
            };
            if (r.sui) |e| {
                if (!std.mem.eql(u8, kind, @tagName(e.kind))) c.failf("sui kind rust {s} zig {s}", .{ kind, @tagName(e.kind) });
                if (!std.mem.eql(u8, msg, e.msg)) c.failf("sui msg\n  rust {s}\n  zig  {s}", .{ msg, e.msg });
            } else c.failf("sui: rust {s} ({s}), zig ok", .{ kind, msg });
        },
        else => {},
    };
    // meter units
    const u = o.get("units").?.object;
    const want = [_]u64{ @intCast(u.get("mod").?.integer), @intCast(u.get("fun_total").?.integer), @intCast(u.get("fun_max").?.integer), @intCast(u.get("adds").?.integer) };
    const got = [_]u64{ @truncate(r.meter.module), @truncate(r.meter.fun_total), @truncate(r.meter.fun_max), r.meter.adds };
    const names = [_][]const u8{ "mod", "fun_total", "fun_max", "adds" };
    for (want, got, names) |w, g, n| if (w != g) c.failf("units.{s} rust {d} zig {d}", .{ n, w, g });
}

const VerifyBench = struct {
    compiled: []const ff.CompiledModule,
    cfg: *const vf.Config,
    natives: ?*const vf.Natives,
    arena: *std.heap.ArenaAllocator,
    scratch: *std.heap.ArenaAllocator,
};

fn benchVerify(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var configs = try loadConfigs(ctx, a);
    var max_pv: u64 = 0;
    for (configs.list) |c| max_pv = @max(max_pv, c.pv);
    const cfg = configs.get(max_pv).?;
    _ = &configs;
    var compiled: std.ArrayList(ff.CompiledModule) = .empty;
    for (ctx.benchInputs()) |name| {
        const bytes = try ctx.corpus.readFileAlloc(ctx.io, name, a, .limited(1 << 30));
        for (try splitPack(a, bytes)) |b| switch (try deser.deserialize(a, b, &cfg.binary)) {
            .ok => |m| try compiled.append(a, m),
            .err => {},
        };
    }
    var arena2: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena2.deinit();
    var scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer scratch.deinit();
    // Same work as the Rust baseline: Move verifier, then the Sui passes when it passes (no natives check).
    const st: VerifyBench = .{ .compiled = compiled.items, .cfg = &cfg.verifier, .natives = null, .arena = &arena2, .scratch = &scratch };
    try ctx.benchPasses("verify", "module", compiled.items.len, &st, struct {
        fn f(s: *const VerifyBench) !void {
            for (s.compiled) |*m| {
                _ = s.arena.reset(.retain_capacity);
                std.mem.doNotOptimizeAway(try vf.verifyModule(s.arena.allocator(), s.scratch, s.cfg, m, s.natives));
            }
        }
    }.f);
}
