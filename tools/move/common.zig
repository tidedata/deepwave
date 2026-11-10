//! Shared pieces of deepwave-move: opening a stopped node directory read-only, option parsing, JSON and
//! CSV writers, package loading from a store snapshot.
const std = @import("std");
const Io = std.Io;
const node = @import("node");
const exec = @import("exec");
const bcs = @import("bcs");
const types = @import("types");
const mf = @import("move_format");
const store = node.store;
const dbc = node.dbcheckpoint;

pub const Allocator = std.mem.Allocator;
pub const Id = [32]u8;
pub const ff = mf.file_format;

pub const Opened = struct {
    st: *store.Store,
    rio: *store.RealIo,
    lock_fd: std.c.fd_t,

    pub fn close(o: *Opened) void {
        o.st.close() catch |e| std.log.err("store close: {s}", .{@errorName(e)});
        o.rio.deinit();
        dbc.unlock(o.lock_fd);
    }
};

/// Opens `dir` (a node directory) like deepwave-tool does: takes node/LOCK, so the node must be stopped
/// (or the directory a db-checkpoint copy).
pub fn openNode(gpa: Allocator, io: Io, arena: Allocator, dir: []const u8) !Opened {
    const fd = try dbc.lock(dir);
    errdefer dbc.unlock(fd);
    var scfg: store.Config = .{ .dir = try std.fs.path.join(arena, &.{ dir, "store" }), .codec = exec.objects.store_codec };
    scfg.verify_index_on_open = false;
    const cfg_ptr = try arena.create(store.Config);
    cfg_ptr.* = scfg;
    const o = try store.openDir(gpa, io, cfg_ptr, .{ .sync = .data });
    return .{ .st = o.store, .rio = o.io, .lock_fd = fd };
}

// ---------------------------------------------------------------------------------------------
// Options: `--key value` pairs and `--flag`s after the subcommand.

/// `--protocol N` for the verifier config (default: the build's max protocol version).
pub fn protocolOpt(o: Opts) !?u64 {
    if (o.get("--protocol") == null) return null;
    return try o.num("--protocol", 0);
}

pub const Opts = struct {
    args: []const []const u8,

    pub fn get(o: Opts, key: []const u8) ?[]const u8 {
        var i: usize = 0;
        while (i + 1 < o.args.len) : (i += 1) {
            if (std.mem.eql(u8, o.args[i], key)) return o.args[i + 1];
        }
        return null;
    }
    pub fn flag(o: Opts, key: []const u8) bool {
        for (o.args) |a| if (std.mem.eql(u8, a, key)) return true;
        return false;
    }
    pub fn num(o: Opts, key: []const u8, default: u64) !u64 {
        const v = o.get(key) orelse return default;
        return std.fmt.parseInt(u64, v, 10) catch error.BadNumber;
    }
};

pub fn parseId(text: []const u8) !Id {
    const t = if (std.mem.startsWith(u8, text, "0x")) text[2..] else text;
    if (t.len == 0 or t.len > 64) return error.BadObjectId;
    var padded: [64]u8 = @splat('0');
    @memcpy(padded[64 - t.len ..], t);
    var id: Id = undefined;
    _ = try std.fmt.hexToBytes(&id, &padded);
    return id;
}

/// 0x + 64 hex digits.
pub fn hexId(arena: Allocator, id: *const Id) ![]const u8 {
    return std.fmt.allocPrint(arena, "0x{x}", .{id});
}

/// Short form: 0x1, 0x2 for the framework ids, else the full 0x + 64 digits.
pub fn shortId(arena: Allocator, id: *const Id) ![]const u8 {
    var lead: usize = 0;
    while (lead < 31 and id[lead] == 0) lead += 1;
    if (lead >= 31) return std.fmt.allocPrint(arena, "0x{x}", .{id[31]});
    return hexId(arena, id);
}

// ---------------------------------------------------------------------------------------------
// Output

pub const Format = enum { json, csv };

pub fn jsonStr(w: *Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0...8, 11, 12, 14...31 => try w.print("\\u{x:0>4}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

pub fn csvStr(w: *Io.Writer, s: []const u8) !void {
    var need = false;
    for (s) |c| if (c == ',' or c == '"' or c == '\n') {
        need = true;
    };
    if (!need) return w.writeAll(s);
    try w.writeByte('"');
    for (s) |c| {
        if (c == '"') try w.writeByte('"');
        try w.writeByte(c);
    }
    try w.writeByte('"');
}

/// A tiny streaming JSON writer that tracks commas: begin/end of objects and arrays, keyed values.
pub const Json = struct {
    w: *Io.Writer,
    need_comma: [64]bool = @splat(false),
    depth: usize = 0,
    /// A key was just written: the value follows without a comma.
    after_key: bool = false,

    fn sep(j: *Json) !void {
        if (j.after_key) {
            j.after_key = false;
            return;
        }
        if (j.need_comma[j.depth]) try j.w.writeByte(',');
        j.need_comma[j.depth] = true;
    }
    pub fn beginObj(j: *Json) !void {
        try j.sep();
        try j.w.writeByte('{');
        j.depth += 1;
        j.need_comma[j.depth] = false;
    }
    pub fn endObj(j: *Json) !void {
        j.depth -= 1;
        try j.w.writeByte('}');
    }
    pub fn beginArr(j: *Json) !void {
        try j.sep();
        try j.w.writeByte('[');
        j.depth += 1;
        j.need_comma[j.depth] = false;
    }
    pub fn endArr(j: *Json) !void {
        j.depth -= 1;
        try j.w.writeByte(']');
    }
    pub fn key(j: *Json, k: []const u8) !void {
        try j.sep();
        try jsonStr(j.w, k);
        try j.w.writeByte(':');
        j.after_key = true;
    }
    pub fn objIn(j: *Json, k: []const u8) !void {
        try j.key(k);
        try j.beginObj();
    }
    pub fn arrIn(j: *Json, k: []const u8) !void {
        try j.key(k);
        try j.beginArr();
    }
    pub fn str(j: *Json, k: []const u8, v: []const u8) !void {
        try j.key(k);
        j.after_key = false;
        try jsonStr(j.w, v);
    }
    pub fn int(j: *Json, k: []const u8, v: anytype) !void {
        try j.key(k);
        j.after_key = false;
        try j.w.print("{d}", .{v});
    }
    pub fn float(j: *Json, k: []const u8, v: f64) !void {
        try j.key(k);
        j.after_key = false;
        if (std.math.isFinite(v)) try j.w.print("{d:.4}", .{v}) else try j.w.writeAll("null");
    }
    pub fn boolean(j: *Json, k: []const u8, v: bool) !void {
        try j.key(k);
        j.after_key = false;
        try j.w.writeAll(if (v) "true" else "false");
    }
    pub fn rawStr(j: *Json, v: []const u8) !void {
        try j.sep();
        try jsonStr(j.w, v);
    }
    pub fn rawInt(j: *Json, v: anytype) !void {
        try j.sep();
        try j.w.print("{d}", .{v});
    }
};

// ---------------------------------------------------------------------------------------------
// Packages

pub const LoadedModule = struct { name: []const u8, cm: ff.CompiledModule, raw: []const u8 };

pub const LoadedPackage = struct {
    id: Id,
    version: u64,
    original_id: Id,
    modules: []const LoadedModule,
    /// The BCS Object this was read from.
    object: []const u8,
};

pub const PackageError = error{ NotFound, NotAPackage, BadModule } || bcs.DecodeError || Allocator.Error;

/// Reads package `id` from the snapshot (latest version). All memory is in `arena`.
pub fn loadPackage(arena: Allocator, snap: *const store.Snapshot, id: *const Id) PackageError!LoadedPackage {
    const live = snap.liveObject(id) orelse return error.NotFound;
    return loadPackageBytes(arena, live.bytes);
}

pub fn loadPackageBytes(arena: Allocator, raw_in: []const u8) PackageError!LoadedPackage {
    const raw = try arena.dupe(u8, raw_in);
    const obj = try bcs.decode(types.Object, arena, raw);
    const mp = switch (obj.data) {
        .Package => |p| p,
        .Move => return error.NotAPackage,
    };
    var mods: std.ArrayList(LoadedModule) = .empty;
    var original: ?Id = null;
    for (mp.module_map.entries) |e| {
        const cfg: mf.BinaryConfig = .{};
        const res = try mf.deserialize(arena, e.value, &cfg);
        switch (res) {
            .ok => |m| {
                if (original == null) original = m.selfAddress().*;
                try mods.append(arena, .{ .name = e.key.@"0", .cm = m, .raw = e.value });
            },
            .err => return error.BadModule,
        }
    }
    const id = mp.id.@"0".@"0";
    return .{ .id = id, .version = mp.version.@"0", .original_id = original orelse id, .modules = mods.items, .object = raw };
}

pub fn moduleByName(p: *const LoadedPackage, name: []const u8) ?*const LoadedModule {
    for (p.modules) |*m| if (std.mem.eql(u8, m.name, name)) return m;
    return null;
}

/// Package id -> original id cache over one snapshot.
pub const OriginCache = struct {
    arena: Allocator,
    snap: *const store.Snapshot,
    map: std.AutoHashMapUnmanaged(Id, Id) = .empty,

    pub fn original(c: *OriginCache, id: *const Id) Id {
        if (c.map.get(id.*)) |o| return o;
        var res: Id = id.*;
        if (c.snap.liveObject(id)) |live| {
            // The decode borrows from a temporary arena: only the 32-byte answer is kept.
            var tmp: std.heap.ArenaAllocator = .init(c.arena);
            defer tmp.deinit();
            if (loadPackageBytes(tmp.allocator(), live.bytes)) |p| {
                res = p.original_id;
            } else |_| {}
        }
        c.map.put(c.arena, id.*, res) catch {};
        return res;
    }
};

/// Struct tag text `0xADDR::module::Name<args>` for a Move object type (generic args elided to
/// their count: layouts are per datatype).
pub fn objectTypeName(arena: Allocator, t: types.MoveObjectType) ![]const u8 {
    return switch (t.@"0") {
        .GasCoin => "0x2::coin::Coin<0x2::sui::SUI>",
        .StakedSui => "0x3::staking_pool::StakedSui",
        .Coin => "0x2::coin::Coin",
        .Other => |st| blk: {
            const a = try shortId(arena, &st.address.@"0");
            break :blk try std.fmt.allocPrint(arena, "{s}::{s}::{s}", .{ a, st.module.@"0", st.name.@"0" });
        },
        .SuiBalanceAccumulatorField => "0x2::dynamic_field::Field<0x2::accumulator::Key<0x2::balance::Balance<0x2::sui::SUI>>, 0x2::accumulator::U128>",
        .BalanceAccumulatorField => "0x2::dynamic_field::Field<0x2::accumulator::Key<0x2::balance::Balance>, 0x2::accumulator::U128>",
    };
}

pub fn objectTypeAddress(t: types.MoveObjectType) ?Id {
    return switch (t.@"0") {
        .Other => |st| st.address.@"0",
        .GasCoin, .Coin => blk: {
            var a: Id = @splat(0);
            a[31] = 2;
            break :blk a;
        },
        .StakedSui => blk: {
            var a: Id = @splat(0);
            a[31] = 3;
            break :blk a;
        },
        .SuiBalanceAccumulatorField, .BalanceAccumulatorField => blk: {
            var a: Id = @splat(0);
            a[31] = 2;
            break :blk a;
        },
    };
}

/// Stdout writer over a caller buffer; flush before exit.
pub fn stdout(io: Io, buf: []u8) Io.File.Writer {
    return Io.File.stdout().writer(io, buf);
}

/// What every subcommand gets.
pub const Ctx = struct {
    gpa: Allocator,
    io: Io,
    arena: Allocator,
    w: *Io.Writer,
    opts: Opts,
};

/// The package object `raw_obj` with module `name` replaced by `new_bytes` (BCS Object).
pub fn rebuildPackage(arena: Allocator, raw_obj: []const u8, name: []const u8, new_bytes: []const u8) ![]u8 {
    const raw = try arena.dupe(u8, raw_obj);
    var obj = try bcs.decode(types.Object, arena, raw);
    var mp = switch (obj.data) {
        .Package => |p| p,
        .Move => return error.NotAPackage,
    };
    const Entry = @TypeOf(mp.module_map.entries[0]);
    const entries = try arena.dupe(Entry, mp.module_map.entries);
    var hit = false;
    for (entries) |*e| if (std.mem.eql(u8, e.key.@"0", name)) {
        e.value = new_bytes;
        hit = true;
    };
    if (!hit) return error.ModuleNotFound;
    mp.module_map = .{ .entries = entries };
    obj.data = .{ .Package = mp };
    return bcs.encodeAlloc(types.Object, arena, &obj);
}
