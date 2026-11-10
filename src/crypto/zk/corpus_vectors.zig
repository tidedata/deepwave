//! Test helper: the zkLogin corpus vectors ($ZUI_CORPUS/vectors/zklogin, the zklogin suite's
//! inputs) as parsed authenticators with their JWK lookup, for the batch tests in zk and sig.
//! `load` returns null without the corpus (tests skip).
const std = @import("std");
const builtin = @import("builtin");
const zkl = @import("zklogin.zig");
const Fail = @import("errors.zig").Fail;

pub const Item = struct {
    id: []const u8,
    auth: zkl.Authenticator,
    jwk: Jwk,

    pub fn jwks(it: *const Item) zkl.Jwks {
        return .{ .ctx = &it.jwk, .lookupFn = Jwk.lookup };
    }
};

/// The corpus union of JWKs (when the item uses it) plus the item's own extra JWK (`xjwk`).
pub const Jwk = struct {
    set: *const Set,
    use_union: bool,
    iss: []const u8 = "",
    kid: []const u8 = "",
    n: ?[]const u8 = null,

    fn lookup(ctx: *const anyopaque, iss: []const u8, kid: []const u8) ?[]const u8 {
        const j: *const Jwk = @ptrCast(@alignCast(ctx));
        if (j.n) |n| if (std.mem.eql(u8, iss, j.iss) and std.mem.eql(u8, kid, j.kid)) return n;
        if (!j.use_union) return null;
        var buf: [1024]u8 = undefined;
        if (iss.len + kid.len + 1 > buf.len) return null;
        @memcpy(buf[0..iss.len], iss);
        buf[iss.len] = 0;
        @memcpy(buf[iss.len + 1 ..][0..kid.len], kid);
        return j.set.map.get(buf[0 .. iss.len + 1 + kid.len]);
    }
};

pub const Set = struct {
    arena: std.heap.ArenaAllocator,
    keys: zkl.Keys,
    map: std.StringHashMapUnmanaged([]const u8) = .empty,
    items: []Item = &.{},

    pub fn deinit(s: *Set) void {
        const gpa = s.arena.child_allocator;
        s.arena.deinit();
        gpa.destroy(s);
    }
};

fn str(o: std.json.ObjectMap, k: []const u8) []const u8 {
    const v = o.get(k) orelse return "";
    return if (v == .string) v.string else "";
}

/// Parses every authenticator of `files` (names under vectors/zklogin) that decodes, at most
/// `max_items` of them.
pub fn load(gpa: std.mem.Allocator, io: std.Io, files: []const []const u8, max_items: usize) !?*Set {
    if (!builtin.link_libc) return null;
    const corpus = std.c.getenv("ZUI_CORPUS") orelse return null;
    var dir = std.Io.Dir.cwd().openDir(io, std.mem.span(corpus), .{}) catch return null;
    defer dir.close(io);
    const s = try gpa.create(Set);
    s.* = .{ .arena = .init(gpa), .keys = undefined };
    errdefer s.deinit();
    s.keys.init();
    const a = s.arena.allocator();
    const jt = dir.readFileAlloc(io, "vectors/zklogin/jwks.jsonld", a, .limited(64 << 20)) catch {
        s.deinit();
        return null;
    };
    var jl = std.mem.splitScalar(u8, jt, '\n');
    while (jl.next()) |line| {
        if (line.len == 0) continue;
        const o = (try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{})).object;
        const key = try std.fmt.allocPrint(a, "{s}\x00{s}", .{ str(o, "iss"), str(o, "kid") });
        try s.map.put(a, key, str(o, "n"));
    }
    var items: std.ArrayList(Item) = .empty;
    outer: for (files) |name| {
        const path = try std.fmt.allocPrint(a, "vectors/zklogin/{s}", .{name});
        const text = dir.readFileAlloc(io, path, a, .limited(256 << 20)) catch continue;
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            if (items.items.len >= max_items) break :outer;
            const o = (try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{})).object;
            const h = str(o, "auth");
            const bytes = try a.alloc(u8, h.len / 2);
            _ = std.fmt.hexToBytes(bytes, h) catch continue;
            const scratch = try a.alloc(u8, zkl.scratchLen(bytes.len));
            var item: Item = .{ .id = str(o, "id"), .auth = undefined, .jwk = .{ .set = s, .use_union = o.get("jwks").?.bool } };
            var fail: Fail = .none;
            if (!zkl.Authenticator.parse(bytes, scratch, &item.auth, &fail)) continue;
            if (o.get("xjwk")) |x| if (x == .object) {
                item.jwk.iss = str(x.object, "iss");
                item.jwk.kid = str(x.object, "kid");
                item.jwk.n = str(x.object, "n");
            };
            try items.append(a, item);
        }
    }
    s.items = items.items;
    return s;
}
