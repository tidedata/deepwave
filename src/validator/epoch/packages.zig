//! The framework side of a protocol upgrade, as sui-core does it:
//!   availableSystemPackages   `AuthorityState::get_available_system_packages` over
//!                             sui-framework `compare_system_package`: for each built-in package
//!                             of this binary (`BuiltInFramework::iter_system_packages` order), the
//!                             ref of the package the binary would install next: the on-chain one
//!                             when the bytes are the same, else the same object one version up
//!                             (after `Compatibility::framework_upgrade_check`), a fresh package at
//!                             version 1 (genesis marker) when none is on chain. Any incompatible
//!                             package empties the whole list (a vote against every upgrade).
//!   systemPackageBytes        `AuthorityState::get_system_package_bytes`: the (version, module
//!                             bytes, dependencies) the ChangeEpoch carries for the winning refs,
//!                             skipping the ones already on chain; null when this binary cannot
//!                             rebuild a ref (the checkpoint builder then waits, as Rust).
//! The binary's built-in framework is the newest entry of natives/framework.bin (the release's
//! max protocol version: 142 at 1.84).
const std = @import("std");
const natives = @import("natives");
const move_format = @import("move_format");
const exec = @import("exec");
const messages = @import("../messages.zig");
const endofepoch = @import("endofepoch.zig");

pub const ObjectRef = messages.ObjectRef;
pub const Package = natives.framework.Package;
const compat = exec.ptb.compat;

pub const Error = error{ OutOfMemory, BadFrameworkBlob, BadObject };

fn shortId(b: u16) [32]u8 {
    var id: [32]u8 = @splat(0);
    std.mem.writeInt(u16, id[30..32], b, .big);
    return id;
}

/// The built-in packages of this binary in Rust's iteration order: MoveStdlib, Sui, SuiSystem,
/// DeepBook, Bridge (each present in the snapshot).
pub fn builtIn(arena: std.mem.Allocator, max_version: u64) Error![]const Package {
    const versions = try natives.framework.load(arena);
    const v = natives.framework.snapshot(versions, max_version) orelse return error.BadFrameworkBlob;
    var out: std.ArrayList(Package) = .empty;
    for ([_]u16{ 0x1, 0x2, 0x3, 0xdee9, 0xb }) |short| {
        const id = shortId(short);
        for (v.packages) |p| if (std.mem.eql(u8, &p.id, &id)) {
            try out.append(arena, p);
            break;
        };
    }
    return out.items;
}

/// Object reads the vote needs: the live object, and an object at a version.
pub const Source = struct {
    ctx: *anyopaque,
    latest: *const fn (ctx: *anyopaque, id: *const [32]u8) ?[]const u8,
    at: *const fn (ctx: *anyopaque, id: *const [32]u8, version: u64) ?[]const u8,
};

fn ref(id: [32]u8, version: u64, digest: [32]u8) ObjectRef {
    return .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = version }, .{ .@"0" = .{ .@"0" = digest } } };
}

fn prevTx(v: *const exec.objects.ObjectView) Error![32]u8 {
    const raw = v.raw[v.prev_tx_at..];
    if (raw.len < 33 or raw[0] != 32) return error.BadObject;
    return raw[1..33].*;
}

/// The modules of a package object, deserialized with `bin` (Rust: `normalize` of the package;
/// a module that does not deserialize fails the comparison).
fn packageModules(arena: std.mem.Allocator, raw: []const u8, bin: *const move_format.BinaryConfig) Error!?[]move_format.CompiledModule {
    const types = @import("types");
    const bcs = @import("bcs");
    const obj = bcs.decode(types.Object, arena, raw) catch return error.BadObject;
    const pkg = switch (obj.data) {
        .Package => |p| p,
        else => return error.BadObject, // Rust: "Framework not package" (an invariant panic)
    };
    const out = try arena.alloc(move_format.CompiledModule, pkg.module_map.entries.len);
    for (pkg.module_map.entries, out) |e, *m| {
        m.* = switch (try move_format.deserialize(arena, e.value, bin)) {
            .ok => |x| x,
            .err => return null,
        };
    }
    return out;
}

fn modulesOf(arena: std.mem.Allocator, p: *const Package, bin: *const move_format.BinaryConfig) Error!?[]move_format.CompiledModule {
    const out = try arena.alloc(move_format.CompiledModule, p.modules.len);
    for (p.modules, out) |bytes, *m| {
        m.* = switch (try move_format.deserialize(arena, bytes, bin)) {
            .ok => |x| x,
            .err => return null,
        };
    }
    return out;
}

fn objectRefOf(arena: std.mem.Allocator, p: *const Package, version: u64, prev_tx: *const [32]u8) Error!ObjectRef {
    const bytes = natives.framework.packageObjectBcs(arena, p, version, prev_tx) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadFrameworkBlob,
    };
    return ref(p.id, version, natives.framework.objectDigest(bytes));
}

/// sui-framework `compare_system_package`.
pub fn compareSystemPackage(arena: std.mem.Allocator, src: Source, p: *const Package, bin: *const move_format.BinaryConfig) Error!?ObjectRef {
    const cur_raw = src.latest(src.ctx, &p.id) orelse {
        // a new framework package: created at OBJECT_START_VERSION over the genesis marker
        const zero: [32]u8 = @splat(0);
        return try objectRefOf(arena, p, 1, &zero);
    };
    const cur = exec.objects.ObjectView.parse(cur_raw) catch return error.BadObject;
    if (!cur.is_package) return error.BadObject;
    const prev = try prevTx(&cur);
    const same = try objectRefOf(arena, p, cur.version, &prev);
    if (std.mem.eql(u8, &same[2].@"0".@"0", &cur.digest())) return ref(p.id, cur.version, cur.digest());
    const old_mods = (try packageModules(arena, cur_raw, bin)) orelse return null;
    const new_mods = (try modulesOf(arena, p, bin)) orelse return null;
    if (!compat.frameworkCheck(old_mods, new_mods)) return null;
    return try objectRefOf(arena, p, cur.version + 1, &prev);
}

/// `AuthorityState::get_available_system_packages`.
pub fn availableSystemPackages(arena: std.mem.Allocator, builtin: []const Package, src: Source, bin: *const move_format.BinaryConfig) Error![]const ObjectRef {
    const out = try arena.alloc(ObjectRef, builtin.len);
    for (builtin, out) |*p, *o| {
        o.* = (try compareSystemPackage(arena, src, p, bin)) orelse return &.{};
    }
    return out;
}

/// `AuthorityState::get_system_package_bytes`: null when a ref cannot be rebuilt from this
/// binary's packages (not built in, predecessor missing, or a different digest).
pub fn systemPackageBytes(arena: std.mem.Allocator, builtin: []const Package, refs: []const ObjectRef, src: Source) Error!?[]const endofepoch.SystemPackage {
    var out: std.ArrayList(endofepoch.SystemPackage) = .empty;
    for (refs) |r| {
        const id = r[0].@"0".@"0";
        const version = r[1].@"0";
        const want = r[2].@"0".@"0";
        if (src.at(src.ctx, &id, version)) |raw| {
            const v = exec.objects.ObjectView.parse(raw) catch return error.BadObject;
            if (std.mem.eql(u8, &v.digest(), &want)) continue; // already on chain
        }
        const prev: [32]u8 = if (version == 1) @splat(0) else blk: {
            const raw = src.at(src.ctx, &id, version - 1) orelse return null;
            const v = exec.objects.ObjectView.parse(raw) catch return error.BadObject;
            break :blk try prevTx(&v);
        };
        const p = for (builtin) |*p| {
            if (std.mem.eql(u8, &p.id, &id)) break p;
        } else return null; // Rust panics in get_package_by_id: not a system package of this binary
        const built = try objectRefOf(arena, p, version, &prev);
        if (!std.mem.eql(u8, &built[2].@"0".@"0", &want)) return null;
        try out.append(arena, .{ .version = version, .modules = p.modules, .deps = p.deps });
    }
    return out.items;
}

/// An `endofepoch.PackageSource` over a built-in package list and an object source.
pub const BytesSource = struct {
    builtin: []const Package,
    src: Source,

    pub fn source(b: *BytesSource) endofepoch.PackageSource {
        return .{ .ctx = b, .lookup = lookup };
    }
    fn lookup(ctx: *anyopaque, arena: std.mem.Allocator, refs: []const ObjectRef) ?[]const endofepoch.SystemPackage {
        const b: *BytesSource = @ptrCast(@alignCast(ctx));
        return systemPackageBytes(arena, b.builtin, refs, b.src) catch null;
    }
};

// ------------------------------------------------------------------ conformance (Rust vectors)
//
// testdata/upgrade/v141 and v142: tools/truth/validator-epoch `upgrade` built against 1.83.1 and
// 1.84 (tools/truth/validator-epoch/upgrade.sh), over the mainnet framework packages and bridge
// objects of epoch 1313 (sui.rpc.v2 GetObject). A store entry is [id, version,
// previous_transaction, object digest]: the object is rebuilt from framework.bin (the newest
// snapshot whose package has that digest).

const protocol = @import("protocol");
const reconfig = @import("reconfig.zig");
const capabilities = @import("capabilities.zig");

const TestStore = struct {
    arena: std.mem.Allocator,
    objs: std.ArrayList(struct { id: [32]u8, version: u64, raw: []const u8 }) = .empty,

    fn source(t: *TestStore) Source {
        return .{ .ctx = t, .latest = latest, .at = at };
    }
    fn latest(ctx: *anyopaque, id: *const [32]u8) ?[]const u8 {
        const t: *TestStore = @ptrCast(@alignCast(ctx));
        var best: ?usize = null;
        for (t.objs.items, 0..) |o, i| if (std.mem.eql(u8, &o.id, id)) {
            if (best == null or o.version > t.objs.items[best.?].version) best = i;
        };
        return if (best) |i| t.objs.items[i].raw else null;
    }
    fn at(ctx: *anyopaque, id: *const [32]u8, version: u64) ?[]const u8 {
        const t: *TestStore = @ptrCast(@alignCast(ctx));
        for (t.objs.items) |o| if (std.mem.eql(u8, &o.id, id) and o.version == version) return o.raw;
        return null;
    }
    fn putRaw(t: *TestStore, raw: []const u8) !void {
        const v = try exec.objects.ObjectView.parse(raw);
        try t.objs.append(t.arena, .{ .id = v.id, .version = v.version, .raw = raw });
    }
    /// Rebuilds a package object from the framework snapshots by its key.
    fn putKey(t: *TestStore, versions: []const natives.framework.Version, key: []const std.json.Value) !void {
        const id = try hexArr(32, key[0].string);
        const version: u64 = @intCast(key[1].integer);
        const prev = try hexArr(32, key[2].string);
        const want = try hexArr(32, key[3].string);
        var i = versions.len;
        while (i > 0) {
            i -= 1;
            for (versions[i].packages) |*p| if (std.mem.eql(u8, &p.id, &id)) {
                const raw = try natives.framework.packageObjectBcs(t.arena, p, version, &prev);
                if (std.mem.eql(u8, &natives.framework.objectDigest(raw), &want)) return t.putRaw(raw);
            };
        }
        return error.NoSnapshotMatches;
    }
};

fn hexArr(comptime n: usize, s: []const u8) ![n]u8 {
    var out: [n]u8 = undefined;
    if (s.len != 2 * n) return error.BadHex;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

fn hexAlloc(a: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn refsOf(a: std.mem.Allocator, arr: []const std.json.Value) ![]ObjectRef {
    const out = try a.alloc(ObjectRef, arr.len);
    for (arr, out) |r, *o| o.* = ref(try hexArr(32, r.array.items[0].string), @intCast(r.array.items[1].integer), try hexArr(32, r.array.items[2].string));
    return out;
}

fn expectRefs(want: []const ObjectRef, have: []const ObjectRef) !void {
    try std.testing.expectEqual(want.len, have.len);
    for (want, have) |w, h| {
        try std.testing.expectEqualSlices(u8, &w[0].@"0".@"0", &h[0].@"0".@"0");
        try std.testing.expectEqual(w[1].@"0", h[1].@"0");
        try std.testing.expectEqualSlices(u8, &w[2].@"0".@"0", &h[2].@"0".@"0");
    }
}

const releases = [_]struct { max: u64, available: []const u8, tx: []const u8 }{
    .{ .max = 141, .available = @embedFile("testdata/upgrade/v141/available-v141.jsonl"), .tx = @embedFile("testdata/upgrade/v141/upgrade-tx-v141.jsonl") },
    .{ .max = 142, .available = @embedFile("testdata/upgrade/v142/available-v142.jsonl"), .tx = @embedFile("testdata/upgrade/v142/upgrade-tx-v142.jsonl") },
};

test "protocol digests: the compiled-in table is Rust's at 1.84 (1..=142) and at 1.83.1 (1..=141)" {
    for ([_][]const u8{ @embedFile("testdata/upgrade/v141/protocol-digests.txt"), @embedFile("testdata/upgrade/v142/protocol-digests.txt") }, [_]u64{ 141, 142 }) |text, max| {
        var t = try capabilities.DigestTable.parse(std.testing.allocator, text);
        defer t.deinit();
        try std.testing.expectEqual(@as(usize, 3 * max), t.map.count());
        for ([_]protocol.Chain{ .unknown, .mainnet, .testnet }) |c| {
            var v: u64 = 1;
            while (v <= max) : (v += 1) try std.testing.expectEqualSlices(u8, &t.get(c, v).?, &capabilities.rustDigest(c, v).?);
        }
    }
    try std.testing.expectEqual(@as(u64, 142), capabilities.supported_max);
}

test "available system packages equal Rust's get_available_system_packages (1.83.1 and 1.84 binaries)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const versions = try natives.framework.load(a);
    const bin = try exec.system.movecall.binaryConfig(try protocol.get(141, .mainnet));
    var cases: usize = 0;
    for (releases) |rel| {
        const builtin = try builtIn(a, rel.max);
        try std.testing.expectEqual(@as(usize, 5), builtin.len);
        var lines = std.mem.splitScalar(u8, rel.available, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const d = try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{});
            var st: TestStore = .{ .arena = a };
            for (d.object.get("store").?.array.items) |k| try st.putKey(versions, k.array.items);
            const have = try availableSystemPackages(a, builtin, st.source(), &bin);
            expectRefs(try refsOf(a, d.object.get("want").?.array.items), have) catch |e| {
                std.debug.print("available v{d} case {s}\n", .{ rel.max, d.object.get("name").?.string });
                return e;
            };
            cases += 1;
        }
    }
    try std.testing.expect(cases >= 5);
}

test "the mainnet 141 -> 142 end-of-epoch transaction is byte-equal to Rust's" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const versions = try natives.framework.load(a);
    const avail = try std.json.parseFromSliceLeaky(std.json.Value, a, std.mem.sliceTo(releases[1].available, '\n'), .{});
    var st: TestStore = .{ .arena = a };
    for (avail.object.get("store").?.array.items) |k| try st.putKey(versions, k.array.items);
    const cfg = try protocol.get(141, .mainnet);
    for (releases) |rel| {
        const d = try std.json.parseFromSliceLeaky(std.json.Value, a, std.mem.sliceTo(rel.tx, '\n'), .{});
        const o = d.object;
        var bs: BytesSource = .{ .builtin = try builtIn(a, rel.max), .src = st.source() };
        const gas = o.get("gas").?.array.items;
        const facts: endofepoch.Facts = .{
            .authenticator_state_exists = true,
            .authenticator_obj_initial_shared_version = @intCast(o.get("authenticator_isv").?.integer),
            .randomness_state_exists = true,
            .bridge_exists = true,
            .bridge_committee_initiated = true,
            .bridge_obj_initial_shared_version = 1,
            .coin_deny_list_state_exists = true,
            .accumulator_root_exists = true,
            .coin_registry_exists = true,
            .display_registry_exists = true,
            .address_alias_state_exists = true,
            .forwarding_address_registry_exists = true,
            .accumulator_object_count = @intCast(o.get("accumulator_object_count").?.integer),
            .execution_time_observations = .{ .V1 = &.{} },
        };
        const built = try endofepoch.build(a, cfg, facts, .{
            .current_epoch = @intCast(o.get("epoch").?.integer),
            .epoch_start_timestamp_ms = @intCast(o.get("epoch_start_timestamp_ms").?.integer),
            .gas = .{ .computation_cost = @intCast(gas[0].integer), .storage_cost = @intCast(gas[1].integer), .storage_rebate = @intCast(gas[2].integer), .non_refundable_storage_fee = @intCast(gas[3].integer) },
            .chosen = .{ .protocol_version = @intCast(o.get("next_version").?.integer), .packages = try refsOf(a, o.get("packages").?.array.items) },
        }, bs.source());
        try std.testing.expectEqualSlices(u8, try hexAlloc(a, o.get("sender_signed_data").?.string), built.sender_signed_bcs);
        try std.testing.expectEqualSlices(u8, &try hexArr(32, o.get("digest").?.string), &built.digest);
    }
}

test "the protocol version vote equals Rust's choose_protocol_version_and_system_packages_v2" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const bcs = @import("bcs");
    const Committee = struct {
        names: []const [96]u8,
        stakes: []const u64,
        fn stake(ctx: *const anyopaque, name: *const [96]u8) u64 {
            const c: *const @This() = @ptrCast(@alignCast(ctx));
            for (c.names, c.stakes) |n, s| if (std.mem.eql(u8, &n, name)) return s;
            return 0;
        }
    };
    var n_cases: usize = 0;
    var lines = std.mem.splitScalar(u8, @embedFile("testdata/upgrade/v142/choose.jsonl"), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const o = (try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{})).object;
        const members = o.get("committee").?.array.items;
        const names = try a.alloc([96]u8, members.len);
        const stakes = try a.alloc(u64, members.len);
        var total: u64 = 0;
        for (members, names, stakes) |m, *n, *s| {
            n.* = try hexArr(96, m.array.items[0].string);
            s.* = @intCast(m.array.items[1].integer);
            total += s.*;
        }
        const committee: Committee = .{ .names = names, .stakes = stakes };
        const caps_j = o.get("caps").?.array.items;
        const caps = try a.alloc(messages.AuthorityCapabilitiesV2, caps_j.len);
        for (caps_j, caps) |c, *cap| cap.* = try bcs.decode(messages.AuthorityCapabilitiesV2, a, try hexAlloc(a, c.string));
        const chosen = try reconfig.chooseFor(a, @intCast(o.get("current").?.integer), reconfig.Thresholds.of(total), Committee.stake, &committee, o.get("advance_to_highest").?.bool, @intCast(o.get("buffer_bps").?.integer), caps);
        std.testing.expectEqual(@as(u64, @intCast(o.get("want_version").?.integer)), chosen.protocol_version) catch |e| {
            std.debug.print("choose case {s}\n", .{o.get("name").?.string});
            return e;
        };
        try expectRefs(try refsOf(a, o.get("want_packages").?.array.items), chosen.packages);
        n_cases += 1;
    }
    try std.testing.expect(n_cases >= 15);
}
