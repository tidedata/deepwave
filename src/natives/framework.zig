//! Sui framework system packages per protocol version, embedded.
//!
//! `framework.bin` is made by `zui-truth-sui-natives framework-blob` from
//! `sui-framework-snapshot` (every bytecode snapshot) and `sui-framework` (the built-in packages,
//! listed as the release's max protocol version, 142 at 1.84, once when it is also a snapshot): each module once, then per version its packages (id, module
//! indices, dependencies). See tools/truth/sui-natives/src/main.rs for the byte layout.
//!
//! `framework` suite: for every version, each package's `SystemPackage` BCS hash and the package
//! object `Object::new_system_package(modules, 9, deps, 0x7e..)` (bytes and digest) equal Rust.
const std = @import("std");
const harness = @import("harness");
const hash = @import("hash");
const move_format = @import("move_format");

pub const blob = @embedFile("framework.bin");

pub const Package = struct {
    id: [32]u8,
    /// Module bytes in snapshot order (slices of the embedded blob).
    modules: []const []const u8,
    deps: []const [32]u8,
};

pub const Version = struct { version: u64, packages: []const Package };

pub const Error = error{ BadFrameworkBlob, OutOfMemory };

const Reader = struct {
    b: []const u8,
    at: usize = 0,
    fn take(r: *Reader, n: usize) Error![]const u8 {
        if (r.b.len - r.at < n) return error.BadFrameworkBlob;
        defer r.at += n;
        return r.b[r.at..][0..n];
    }
    fn int(r: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try r.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }
};

/// Parses the blob into versions (ascending). Memory from `arena`; module bytes stay in the blob.
pub fn load(arena: std.mem.Allocator) Error![]Version {
    var r: Reader = .{ .b = blob };
    if (!std.mem.eql(u8, try r.take(8), "ZUIFW001")) return error.BadFrameworkBlob;
    const n_mod = try r.int(u32);
    const mods = try arena.alloc([]const u8, n_mod);
    for (mods) |*m| m.* = try r.take(try r.int(u32));
    const n_ver = try r.int(u32);
    const vers = try arena.alloc(Version, n_ver);
    for (vers) |*v| {
        v.version = try r.int(u64);
        const pkgs = try arena.alloc(Package, try r.int(u32));
        for (pkgs) |*p| {
            p.id = (try r.take(32))[0..32].*;
            const ms = try arena.alloc([]const u8, try r.int(u32));
            for (ms) |*m| {
                const i = try r.int(u32);
                if (i >= mods.len) return error.BadFrameworkBlob;
                m.* = mods[i];
            }
            const ds = try arena.alloc([32]u8, try r.int(u32));
            for (ds) |*d| d.* = (try r.take(32))[0..32].*;
            p.modules = ms;
            p.deps = ds;
        }
        v.packages = pkgs;
    }
    if (r.at != blob.len) return error.BadFrameworkBlob;
    return vers;
}

/// `load_bytecode_snapshot` semantics over the embedded versions: the packages of the newest
/// version at or below `version` (the built-in framework counts as the max protocol version).
pub fn snapshot(versions: []const Version, version: u64) ?*const Version {
    var best: ?*const Version = null;
    for (versions) |*v| {
        if (v.version <= version) best = v;
    }
    return best;
}

// ---- BCS ------------------------------------------------------------------------------------

const W = struct {
    list: std.ArrayList(u8) = .empty,
    a: std.mem.Allocator,
    fn bytes(w: *W, b: []const u8) Error!void {
        try w.list.appendSlice(w.a, b);
    }
    fn uleb(w: *W, x: usize) Error!void {
        var v = x;
        while (true) {
            const byte: u8 = @truncate(v & 0x7f);
            v >>= 7;
            if (v == 0) return w.list.append(w.a, byte);
            try w.list.append(w.a, byte | 0x80);
        }
    }
    fn vec(w: *W, b: []const u8) Error!void {
        try w.uleb(b.len);
        try w.bytes(b);
    }
    fn int(w: *W, comptime T: type, x: T) Error!void {
        var b: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &b, x, .little);
        try w.bytes(&b);
    }
};

/// BCS of `sui_framework::SystemPackage { id, bytes, dependencies }`.
pub fn systemPackageBcs(a: std.mem.Allocator, p: *const Package) Error![]u8 {
    var w: W = .{ .a = a };
    try w.bytes(&p.id);
    try w.uleb(p.modules.len);
    for (p.modules) |m| try w.vec(m);
    try w.uleb(p.deps.len);
    for (p.deps) |*d| try w.bytes(d);
    return w.list.items;
}

pub const ObjectError = Error || error{ BadModule, Unserializable };

const Named = struct { name: []const u8, bytes: []const u8 };

/// bcs writes map entries sorted by their serialized keys: a String key is its ULEB128 length
/// then its bytes.
fn lessNamed(_: void, x: Named, y: Named) bool {
    var bx: [10]u8 = undefined;
    var by: [10]u8 = undefined;
    const lx = ulebInto(&bx, x.name.len);
    const ly = ulebInto(&by, y.name.len);
    if (!std.mem.eql(u8, lx, ly)) return std.mem.lessThan(u8, lx, ly);
    return std.mem.lessThan(u8, x.name, y.name);
}

fn ulebInto(buf: *[10]u8, x: usize) []const u8 {
    var v = x;
    var i: usize = 0;
    while (true) : (i += 1) {
        const byte: u8 = @truncate(v & 0x7f);
        v >>= 7;
        if (v == 0) {
            buf[i] = byte;
            return buf[0 .. i + 1];
        }
        buf[i] = byte | 0x80;
    }
}

fn lessId(_: void, x: [32]u8, y: [32]u8) bool {
    return std.mem.lessThan(u8, &x, &y);
}

/// BCS of `Object::new_system_package(modules, version, deps, previous_transaction)`:
/// `MovePackage::new_system` (modules re-serialized at their own binary version, the type origin
/// table from struct then enum definitions per module, linkage at upgraded version 0), owner
/// Immutable, storage rebate 0.
pub fn packageObjectBcs(a: std.mem.Allocator, p: *const Package, version: u64, prev_tx: *const [32]u8) ObjectError![]u8 {
    const cfg: move_format.BinaryConfig = .{};
    const named = try a.alloc(Named, p.modules.len);
    var origins: std.ArrayList(u8) = .empty;
    var n_origins: usize = 0;
    var ow: W = .{ .a = a };
    var storage_id: ?[32]u8 = null;
    for (p.modules, named) |bytes, *nm| {
        const m = switch (try move_format.deserialize(a, bytes, &cfg)) {
            .ok => |m| m,
            .err => return error.BadModule,
        };
        if (storage_id == null) storage_id = m.selfAddress().*;
        const name = m.selfName();
        const re = move_format.serializeAlloc(a, &m, m.version) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Unserializable,
        };
        nm.* = .{ .name = name, .bytes = re };
        const addr = m.selfAddress();
        for (m.struct_defs) |sd| {
            try ow.vec(name);
            try ow.vec(m.identifierAt(m.datatype_handles[sd.struct_handle].name));
            try ow.bytes(addr);
            n_origins += 1;
        }
        for (m.enum_defs) |ed| {
            try ow.vec(name);
            try ow.vec(m.identifierAt(m.datatype_handles[ed.enum_handle].name));
            try ow.bytes(addr);
            n_origins += 1;
        }
    }
    origins = ow.list;
    std.mem.sort(Named, named, {}, lessNamed);
    const deps = try a.dupe([32]u8, p.deps);
    std.mem.sort([32]u8, deps, {}, lessId);

    var w: W = .{ .a = a };
    try w.list.append(a, 1); // Data::Package
    try w.bytes(&(storage_id orelse return error.BadModule));
    try w.int(u64, version);
    try w.uleb(named.len);
    for (named) |nm| {
        try w.vec(nm.name);
        try w.vec(nm.bytes);
    }
    try w.uleb(n_origins);
    try w.bytes(origins.items);
    var n_link: usize = 0;
    for (deps, 0..) |d, i| {
        if (i == 0 or !std.mem.eql(u8, &d, &deps[i - 1])) n_link += 1;
    }
    try w.uleb(n_link);
    for (deps, 0..) |d, i| {
        if (i > 0 and std.mem.eql(u8, &d, &deps[i - 1])) continue;
        try w.bytes(&d); // key
        try w.bytes(&d); // upgraded_id
        try w.int(u64, 0); // upgraded_version
    }
    try w.list.append(a, 3); // Owner::Immutable
    try w.vec(prev_tx);
    try w.int(u64, 0); // storage_rebate
    return w.list.items;
}

/// `ObjectDigest`: Blake2b256 over "Object::" and the object's BCS.
pub fn objectDigest(obj_bcs: []const u8) [32]u8 {
    return hash.blake2b256(&.{ "Object::", obj_bcs });
}

// ---- suite ----------------------------------------------------------------------------------

const J = std.json.Value;

fn hexEq(c: *harness.Check, what: []const u8, a: std.mem.Allocator, want_hex: []const u8, have: []const u8) !void {
    const want = try a.alloc(u8, want_hex.len / 2);
    _ = try std.fmt.hexToBytes(want, want_hex);
    c.bytes(what, want, have);
}

pub fn run(ctx: *harness.Ctx) !void {
    var keep = std.heap.ArenaAllocator.init(ctx.gpa);
    defer keep.deinit();
    const versions = try load(keep.allocator());
    const text = try ctx.corpus.readFileAlloc(ctx.io, "vectors/framework/framework.jsonl", keep.allocator(), .limited(1 << 30));
    var it = harness.lines(text);
    const prev: [32]u8 = @splat(0x7e);
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (ctx.done()) return;
        ctx.nextItem();
        const a = ctx.scratch();
        const d = try std.json.parseFromSliceLeaky(J, a, line, .{});
        const ver: u64 = @intCast(d.object.get("version").?.integer);
        const pkgs_j = d.object.get("packages").?.array.items;
        var vbuf: [32]u8 = undefined;
        const vid = try std.fmt.bufPrint(&vbuf, "{d}", .{ver});
        const have_v = snapshot(versions, ver);
        // Truth from an older release lists its built-in framework ("snapshot": false) at its
        // max protocol version (1.83.1: 141), which has no snapshot of its own: the blob of a
        // newer release serves that version from the newest snapshot below it, which must hold
        // the same packages (the per-package checks below compare every byte).
        const builtin_of_older = if (d.object.get("snapshot")) |s| s == .bool and !s.bool and have_v != null and have_v.?.version < ver and ver < versions[versions.len - 1].version else false;
        if (have_v == null or (have_v.?.version != ver and !builtin_of_older) or have_v.?.packages.len != pkgs_j.len) {
            if (ctx.selected(vid)) ctx.fail(vid, "version missing or package count differs", .{});
            continue;
        }
        for (pkgs_j, have_v.?.packages) |pj, *p| {
            const o = pj.object;
            const id_hex = o.get("id").?.string;
            const item = try std.fmt.allocPrint(a, "{d}/{s}", .{ ver, id_hex[60..] });
            if (!ctx.selected(item)) continue;
            var c = ctx.check(item);
            try hexEq(&c, "id", a, id_hex, &p.id);
            c.eql("modules", @as(usize, @intCast(o.get("modules").?.integer)), p.modules.len);
            const deps_j = o.get("deps").?.array.items;
            c.eql("deps", deps_j.len, p.deps.len);
            if (deps_j.len == p.deps.len) for (deps_j, p.deps) |dj, *dp| try hexEq(&c, "dep", a, dj.string, dp);
            const sp = try systemPackageBcs(a, p);
            c.digestHex("system_package_blake2b", o.get("system_package_blake2b").?.string, &hash.blake2b256(&.{sp}));
            const obj = packageObjectBcs(a, p, 9, &prev) catch |e| {
                c.failf("package object: {s}", .{@errorName(e)});
                _ = c.finish();
                continue;
            };
            try hexEq(&c, "object", a, o.get("object").?.string, obj);
            c.digestHex("object_digest", o.get("object_digest").?.string, &objectDigest(obj));
            _ = c.finish();
        }
    }
}

test "blob loads" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const vs = try load(arena.allocator());
    try std.testing.expect(vs.len > 100);
    try std.testing.expectEqual(@as(u64, 142), vs[vs.len - 1].version);
    try std.testing.expect(snapshot(vs, 0) == null or snapshot(vs, 0).?.version == 0);
}
