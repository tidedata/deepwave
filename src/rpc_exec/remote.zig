//! A pre-state read from another node over gRPC-web (HTTP/1.1, binary): the parity tool for
//! SimulateTransaction before deepwave's own store holds the full live object set (G1). `deepwave-simproxy`
//! serves SimulateTransaction with deepwave's engine and reads every object, package and owned gas coin
//! from the upstream sui-node (through the SSH tunnel, read-only, a few requests per simulation).
//!
//! Nothing here executes or submits anything on the upstream: it only calls GetObject,
//! ListOwnedObjects, GetEpoch and GetServiceInfo.
const std = @import("std");
const protocol = @import("protocol");
const exec = @import("exec");
const serve = @import("serve");

const root = @import("root.zig");
const state_mod = @import("state.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Id = [32]u8;
const proto = serve.proto;
const State = state_mod.State;
const ObjectView = exec.objects.ObjectView;

// ---- tiny protobuf encoder ----------------------------------------------------------------------

fn varint(l: *std.ArrayList(u8), a: Allocator, v: u64) Allocator.Error!void {
    var x = v;
    while (x >= 0x80) : (x >>= 7) try l.append(a, @as(u8, @truncate(x)) | 0x80);
    try l.append(a, @truncate(x));
}
fn fieldBytes(l: *std.ArrayList(u8), a: Allocator, n: u32, b: []const u8) Allocator.Error!void {
    try varint(l, a, (@as(u64, n) << 3) | 2);
    try varint(l, a, b.len);
    try l.appendSlice(a, b);
}
fn fieldUint(l: *std.ArrayList(u8), a: Allocator, n: u32, v: u64) Allocator.Error!void {
    try varint(l, a, @as(u64, n) << 3);
    try varint(l, a, v);
}
fn mask(a: Allocator, paths: []const []const u8) Allocator.Error![]const u8 {
    var l: std.ArrayList(u8) = .empty;
    for (paths) |p| try fieldBytes(&l, a, 1, p);
    return l.items;
}
fn hexId(a: Allocator, id: *const Id) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(a, "0x{x}", .{id});
}

pub const Upstream = struct {
    gpa: Allocator,
    io: Io,
    client: std.http.Client,
    /// `http://127.0.0.1:19007` (no trailing slash).
    base: []const u8,
    mu: Io.Mutex = .init,
    /// Packages by id (gpa-owned, kept for the process lifetime: exec's package caches hold them).
    pkgs: std.AutoHashMapUnmanaged(Id, ?[]const u8) = .empty,
    calls: std.atomic.Value(u64) = .init(0),
    /// Pacing: at most one upstream call per `min_gap_ns` (0 = unpaced). The parity runs keep
    /// sui-node at or below 20 req/s in total (docs/DROP-IN.md), so the proxy takes a share.
    min_gap_ns: u64 = 0,
    pace_mu: Io.Mutex = .init,
    next_ns: i96 = 0,
    /// Objects at an exact version are immutable: kept for the process lifetime (gpa-owned).
    versioned: std.AutoHashMapUnmanaged(struct { Id, u64 }, ?[]const u8) = .empty,
    /// Parity runs: id -> the version `latest` answers (see `setPins`); empty = live reads.
    pins: std.AutoHashMapUnmanaged(Id, u64) = .empty,

    pub fn init(gpa: Allocator, io: Io, base: []const u8) Upstream {
        return .{ .gpa = gpa, .io = io, .client = .{ .allocator = gpa, .io = io }, .base = base };
    }

    /// One unary gRPC-web call; the response message, or null on a non-OK status (NOT_FOUND
    /// arrives as a trailers-only response with an empty body).
    pub fn call(u: *Upstream, arena: Allocator, method: []const u8, msg: []const u8) !?[]const u8 {
        const url = try std.fmt.allocPrint(arena, "{s}/{s}", .{ u.base, method });
        var body: std.ArrayList(u8) = .empty;
        try body.append(arena, 0);
        var len: [4]u8 = undefined;
        std.mem.writeInt(u32, &len, @intCast(msg.len), .big);
        try body.appendSlice(arena, &len);
        try body.appendSlice(arena, msg);
        u.pace();
        _ = u.calls.fetchAdd(1, .monotonic);
        var aw: std.Io.Writer.Allocating = .init(arena);
        var attempt: u32 = 0;
        const res = while (true) : (attempt += 1) {
            aw.writer.end = 0;
            break u.client.fetch(.{
                .location = .{ .url = url },
                .method = .POST,
                .payload = body.items,
                .extra_headers = &.{ .{ .name = "x-grpc-web", .value = "1" }, .{ .name = "content-type", .value = "application/grpc-web+proto" } },
                .response_writer = &aw.writer,
                .headers = .{ .accept_encoding = .omit, .content_type = .omit },
            }) catch |e| {
                if (attempt < 4) continue;
                return e;
            };
        };
        if (res.status != .ok) return error.HttpStatus;
        const got = aw.writer.buffered();
        // frames: [flag u8][len u32 BE][payload]; flag 0x80 = trailers
        var at: usize = 0;
        while (at + 5 <= got.len) {
            const flag = got[at];
            const n = std.mem.readInt(u32, got[at + 1 ..][0..4], .big);
            if (at + 5 + n > got.len) return error.Truncated;
            if (flag & 0x80 == 0) return got[at + 5 ..][0..n];
            at += 5 + n;
        }
        return null;
    }

    /// The pinned version of `id`, if a pin set is active.
    pub fn pinned(u: *Upstream, id: *const Id) ?u64 {
        u.mu.lockUncancelable(u.io);
        defer u.mu.unlock(u.io);
        return u.pins.get(id.*);
    }

    /// Replaces the pin set: `latest` reads of these ids answer exactly these versions, so deepwave
    /// simulates on the versions sui-node's own simulation read (its effects' read set). `raw` is
    /// n x (id 32, version u64 le). The versions are fetched now, 50 per BatchGetObjects call.
    pub fn setPins(u: *Upstream, arena: Allocator, raw: []const u8) !usize {
        if (raw.len % 40 != 0) return error.BadPins;
        u.mu.lockUncancelable(u.io);
        u.pins.clearRetainingCapacity();
        var i: usize = 0;
        while (i < raw.len) : (i += 40) try u.pins.put(u.gpa, raw[i..][0..32].*, std.mem.readInt(u64, raw[i + 32 ..][0..8], .little));
        // the ones not cached yet
        var want: std.ArrayList(struct { Id, u64 }) = .empty;
        var it = u.pins.iterator();
        while (it.next()) |e| if (!u.versioned.contains(.{ e.key_ptr.*, e.value_ptr.* })) try want.append(arena, .{ e.key_ptr.*, e.value_ptr.* });
        u.mu.unlock(u.io);
        var at: usize = 0;
        while (at < want.items.len) : (at += 50) try u.batchVersioned(arena, want.items[at..@min(at + 50, want.items.len)]);
        return want.items.len;
    }

    /// BatchGetObjects `["bcs"]` for exact versions, into the versioned cache.
    fn batchVersioned(u: *Upstream, arena: Allocator, refs: []const struct { Id, u64 }) !void {
        var req: std.ArrayList(u8) = .empty;
        for (refs) |r| {
            var one: std.ArrayList(u8) = .empty;
            try fieldBytes(&one, arena, 1, try hexId(arena, &r[0]));
            try fieldUint(&one, arena, 2, r[1]);
            try fieldBytes(&req, arena, 1, one.items);
        }
        try fieldBytes(&req, arena, 2, try mask(arena, &.{"bcs"}));
        const resp = (try u.call(arena, "sui.rpc.v2.LedgerService/BatchGetObjects", req.items)) orelse return error.UpstreamStatus;
        // BatchGetObjectsResponse.objects(1) = GetObjectResult{ object(1) | error(2) }
        var rd = proto.Reader.init(resp);
        var k: usize = 0;
        while (try rd.next()) |f| if (f.number == 1) {
            defer k += 1;
            if (k >= refs.len) break;
            const obj = (try sub(try proto.Reader.bytesOf(f), 1)) orelse continue;
            const b = (try sub(obj, 1)) orelse continue;
            const bytes = (try sub(b, 2)) orelse continue;
            const owned = try u.gpa.dupe(u8, bytes);
            u.mu.lockUncancelable(u.io);
            defer u.mu.unlock(u.io);
            const gop = try u.versioned.getOrPut(u.gpa, refs[k]);
            if (gop.found_existing) u.gpa.free(owned) else gop.value_ptr.* = owned;
        };
    }

    fn pace(u: *Upstream) void {
        if (u.min_gap_ns == 0) return;
        u.pace_mu.lockUncancelable(u.io);
        const now: i96 = Io.Clock.awake.now(u.io).nanoseconds;
        const at = @max(now, u.next_ns);
        u.next_ns = at + u.min_gap_ns;
        u.pace_mu.unlock(u.io);
        if (at > now) u.io.sleep(.fromNanoseconds(@intCast(at - now)), .awake) catch {};
    }

    /// GetObject `["bcs"]`: raw BCS Object (arena-owned), or null when not found.
    pub fn getObject(u: *Upstream, arena: Allocator, id: *const Id, version: ?u64) ?[]const u8 {
        if (version) |v| return u.getObjectVersioned(arena, id, v);
        return u.getObjectE(arena, id, version) catch |e| {
            std.log.warn("upstream GetObject {x}: {s}", .{ id, @errorName(e) });
            return null;
        };
    }
    fn getObjectVersioned(u: *Upstream, arena: Allocator, id: *const Id, v: u64) ?[]const u8 {
        u.mu.lockUncancelable(u.io);
        const hit = u.versioned.get(.{ id.*, v });
        u.mu.unlock(u.io);
        if (hit) |x| return x;
        const got = u.getObjectE(arena, id, v) catch |e| {
            std.log.warn("upstream GetObject {x}@{d}: {s}", .{ id, v, @errorName(e) });
            return null;
        };
        // only found objects are cached: NOT_FOUND below the node's retention may change after a restart
        const owned = if (got) |g| (u.gpa.dupe(u8, g) catch return got) else return null;
        u.mu.lockUncancelable(u.io);
        defer u.mu.unlock(u.io);
        u.versioned.put(u.gpa, .{ id.*, v }, owned) catch {};
        return owned;
    }

    fn getObjectE(u: *Upstream, arena: Allocator, id: *const Id, version: ?u64) !?[]const u8 {
        var req: std.ArrayList(u8) = .empty;
        try fieldBytes(&req, arena, 1, try hexId(arena, id));
        if (version) |v| try fieldUint(&req, arena, 2, v);
        try fieldBytes(&req, arena, 3, try mask(arena, &.{"bcs"}));
        const resp = (try u.call(arena, "sui.rpc.v2.LedgerService/GetObject", req.items)) orelse return null;
        // GetObjectResponse.object(1).bcs(1).value(2)
        const obj = (try sub(resp, 1)) orelse return null;
        const b = (try sub(obj, 1)) orelse return null;
        return try sub(b, 2);
    }

    /// The package for exec (packages are immutable per id; system packages are read live, which
    /// is right for the current epoch). Thread-safe.
    pub fn package(u: *Upstream, id: *const Id) ?[]const u8 {
        u.mu.lockUncancelable(u.io);
        defer u.mu.unlock(u.io);
        if (u.pkgs.get(id.*)) |p| return p;
        var arena: std.heap.ArenaAllocator = .init(u.gpa);
        defer arena.deinit();
        const raw = u.getObject(arena.allocator(), id, null);
        const owned: ?[]const u8 = if (raw) |r| blk: {
            const v = ObjectView.parse(r) catch break :blk null;
            if (!v.is_package) break :blk null;
            break :blk u.gpa.dupe(u8, r) catch null;
        } else null;
        u.pkgs.put(u.gpa, id.*, owned) catch {};
        return owned;
    }

    pub fn packageLookup(u: *Upstream) exec.packages.Store.Lookup {
        return .{ .ctx = u, .get = struct {
            fn f(ctx: *const anyopaque, id: *const Id, epoch: u64) ?[]const u8 {
                _ = epoch;
                const up: *Upstream = @constCast(@as(*const Upstream, @ptrCast(@alignCast(ctx))));
                return up.package(id);
            }
        }.f };
    }

    /// ListOwnedObjects(owner, Coin<SUI>) ids in the upstream's owner-index order.
    pub fn gasCoins(u: *Upstream, arena: Allocator, owner: *const Id, limit: usize) ![]const Id {
        var out: std.ArrayList(Id) = .empty;
        var token: ?[]const u8 = null;
        while (out.items.len < limit) {
            var req: std.ArrayList(u8) = .empty;
            try fieldBytes(&req, arena, 1, try hexId(arena, owner));
            try fieldUint(&req, arena, 2, 1000);
            if (token) |t| try fieldBytes(&req, arena, 3, t);
            try fieldBytes(&req, arena, 4, try mask(arena, &.{"object_id"}));
            try fieldBytes(&req, arena, 5, "0x2::coin::Coin<0x2::sui::SUI>");
            const resp = (try u.call(arena, "sui.rpc.v2.StateService/ListOwnedObjects", req.items)) orelse return error.UpstreamStatus;
            token = null;
            var r = proto.Reader.init(resp);
            while (try r.next()) |f| switch (f.number) {
                1 => {
                    var orr = proto.Reader.init(try proto.Reader.bytesOf(f));
                    while (try orr.next()) |g| if (g.number == 2) {
                        const s = try proto.Reader.stringOf(g);
                        const id = @import("resolve.zig").parseAddress(s) orelse return error.BadId;
                        try out.append(arena, id);
                    };
                },
                2 => token = try proto.Reader.bytesOf(f),
                else => {},
            };
            if (token == null) break;
        }
        return out.items;
    }

    /// The upstream's current epoch: GetServiceInfo (chain id) and GetEpoch.
    pub fn epochEnv(u: *Upstream, arena: Allocator) !root.EpochEnv {
        const si = (try u.call(arena, "sui.rpc.v2.LedgerService/GetServiceInfo", "")) orelse return error.UpstreamStatus;
        var chain_id: Id = undefined;
        var r = proto.Reader.init(si);
        while (try r.next()) |f| if (f.number == 1) {
            chain_id = serve.b58.decode32(try proto.Reader.stringOf(f)) orelse return error.BadChainId;
        };
        var req: std.ArrayList(u8) = .empty;
        try fieldBytes(&req, arena, 2, try mask(arena, &.{ "epoch", "reference_gas_price", "start", "protocol_config.protocol_version", "committee" }));
        const resp = (try u.call(arena, "sui.rpc.v2.LedgerService/GetEpoch", req.items)) orelse return error.UpstreamStatus;
        const ep = (try sub(resp, 1)) orelse return error.NoEpoch;
        var env: root.EpochEnv = .{ .chain_id = chain_id, .epoch = 0, .pv = 0, .cfg = undefined, .rgp = 0, .epoch_start_ms = 0, .committee_size = 0 };
        var er = proto.Reader.init(ep);
        while (try er.next()) |f| switch (f.number) {
            1 => env.epoch = try proto.Reader.varintOf(f),
            2 => {
                var cr = proto.Reader.init(try proto.Reader.bytesOf(f));
                while (try cr.next()) |g| if (g.number == 2) {
                    env.committee_size += 1;
                };
            },
            6 => {
                var tr = proto.Reader.init(try proto.Reader.bytesOf(f));
                var s: u64 = 0;
                var n: u64 = 0;
                while (try tr.next()) |g| switch (g.number) {
                    1 => s = try proto.Reader.varintOf(g),
                    2 => n = try proto.Reader.varintOf(g),
                    else => {},
                };
                env.epoch_start_ms = s * 1000 + n / 1_000_000;
            },
            8 => env.rgp = try proto.Reader.varintOf(f),
            9 => {
                var pr = proto.Reader.init(try proto.Reader.bytesOf(f));
                while (try pr.next()) |g| if (g.number == 1) {
                    env.pv = try proto.Reader.varintOf(g);
                };
            },
            else => {},
        };
        env.cfg = try protocol.get(env.pv, .mainnet);
        return env;
    }
};

fn sub(msg: []const u8, field: u32) !?[]const u8 {
    var r = proto.Reader.init(msg);
    var found: ?[]const u8 = null;
    while (try r.next()) |f| if (f.number == field) {
        found = try proto.Reader.bytesOf(f);
    };
    return found;
}

/// One request's view of the upstream: `latest` answers are cached so a request sees one answer
/// per id.
pub const Remote = struct {
    up: *Upstream,
    arena: Allocator,
    latest_cache: std.AutoHashMapUnmanaged(Id, ?[]const u8) = .empty,
    /// Set when a child object was newer than its root's version bound (see `childAtMost`).
    stale: bool = false,

    pub fn state(r: *Remote) State {
        return .{ .ctx = r, .vtable = &vtable };
    }

    fn of(ctx: *const anyopaque) *Remote {
        return @constCast(@as(*const Remote, @ptrCast(@alignCast(ctx))));
    }
    fn latest(ctx: *const anyopaque, id: *const Id) ?[]const u8 {
        const r = of(ctx);
        if (r.latest_cache.get(id.*)) |x| return x;
        const got = if (r.up.pinned(id)) |v| r.up.getObject(r.arena, id, v) else r.up.getObject(r.arena, id, null);
        r.latest_cache.put(r.arena, id.*, got) catch {};
        return got;
    }
    fn at(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        const r = of(ctx);
        if (latest(ctx, id)) |raw| {
            const v = ObjectView.parse(raw) catch return null;
            if (v.version == version) return raw;
        }
        return r.up.getObject(r.arena, id, version);
    }
    fn childAtMost(ctx: *const anyopaque, id: *const Id, upper: u64) ?[]const u8 {
        const raw = latest(ctx, id) orelse return null;
        const v = ObjectView.parse(raw) catch return null;
        if (v.version <= upper) return raw;
        // The child moved on after its root was read (the upstream is read object by object, not
        // at one checkpoint): this view is inconsistent, and the caller retries with a fresh one.
        of(ctx).stale = true;
        return null;
    }
    fn ownedGasCoins(ctx: *const anyopaque, arena: Allocator, owner: *const Id, limit: usize) state_mod.OwnedError![]const Id {
        const r = of(ctx);
        return r.up.gasCoins(arena, owner, limit) catch |e| {
            if (e == error.OutOfMemory) return error.OutOfMemory;
            std.log.warn("upstream ListOwnedObjects: {s}", .{@errorName(e)});
            return error.Unavailable;
        };
    }
    const vtable: State.VTable = .{ .latest = latest, .at = at, .child_at_most = childAtMost, .owned_gas_coins = ownedGasCoins };
};
