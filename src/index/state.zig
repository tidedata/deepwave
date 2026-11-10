//! sui.rpc.v2 StateService over the live-state indexes: ListOwnedObjects, ListDynamicFields,
//! GetBalance, ListBalances, GetCoinInfo, following sui-rpc-api 1.83.1
//! (`grpc/v2/state_service/*.rs`) over the `sui-rpc-store` reader (`reader/indexes.rs`):
//! validation order and messages, page sizes (default 50, clamp 1..1000, 512 KiB of rendered
//! items), page tokens (BCS of the node's `PageToken` structs, so tokens are byte-equal and
//! interchangeable with sui-node's), and the dynamic-field and coin-info loading rules.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const serve = @import("serve");
const index = @import("root.zig");
const h2 = serve.h2;
const proto = serve.proto;
const svc_mod = serve.service;
const Service = svc_mod.Service;
const typestr = serve.typestr;
const render_object = serve.render_object;
const schema = serve.schema;
const typeparse = @import("typeparse.zig");
const dflayout = @import("dflayout.zig");

const max_page = 1000;
const default_page = 50;
const max_page_bytes = 512 * 1024;

/// The hook a Service calls for `/sui.rpc.v2.StateService/<method>`.
pub fn hook(ix: *index.Index) svc_mod.StateHook {
    return .{ .ctx = ix, .call = call, .live = live };
}

fn live(ctx: *anyopaque) svc_mod.StateHook.Live {
    const ix: *index.Index = @ptrCast(@alignCast(ctx));
    return .{ .ready = ix.ready.load(.acquire), .checkpoint = ix.liveCheckpoint() };
}

fn call(ctx: *anyopaque, svc: *Service, arena: Allocator, method: []const u8, body: []const u8, rs: *h2.ResponseStream) h2.Status {
    const ix: *index.Index = @ptrCast(@alignCast(ctx));
    const eql = std.mem.eql;
    const Which = enum { owned, fields, balance, balances, coin };
    const which: Which = if (eql(u8, method, "ListOwnedObjects")) .owned else if (eql(u8, method, "ListDynamicFields")) .fields else if (eql(u8, method, "GetBalance")) .balance else if (eql(u8, method, "ListBalances")) .balances else if (eql(u8, method, "GetCoinInfo")) .coin else return .unimplemented;
    if (!ix.ready.load(.acquire)) {
        // fast start: the index is still being built from the restored live set
        rs.setMessage("rpc indexes are being built");
        return .unavailable;
    }
    var pin: Pin = .{ .ix = ix, .st = svc.store };
    defer pin.release();
    const c: Ctx = .{ .svc = svc, .ix = ix, .arena = arena, .pin = &pin, .rs = rs };
    const res = switch (which) {
        .owned => listOwnedObjects(c, body),
        .fields => listDynamicFields(c, body),
        .balance => getBalance(c, body),
        .balances => listBalances(c, body),
        .coin => getCoinInfo(c, body),
    };
    res catch |e| {
        if (@errorReturnTrace()) |t| if (std.c.getenv("ZUI_INDEX_DEBUG") != null) std.debug.dumpErrorReturnTrace(t);
        return svc_mod.fail(arena, rs, e);
    };
    return .ok;
}

const Ctx = struct {
    svc: *Service,
    ix: *index.Index,
    arena: Allocator,
    pin: *Pin,
    rs: *h2.ResponseStream,

    fn snap(c: Ctx) *const store.Snapshot {
        return c.pin.snapshot();
    }

    /// `json`/`display` for loaded objects, as sui-node's `render_object_to_proto` in
    /// list_owned_objects.rs and list_dynamic_fields.rs: packages from the request's snapshot,
    /// each value its own `max_json_move_value_size`.
    fn renderCtx(c: Ctx) !*const render_object.Ctx {
        const src = try c.arena.create(svc_mod.ObjSource);
        src.* = .{ .snap = c.snap() };
        return svc_mod.renderCtx(c.svc, c.arena, src);
    }
};

/// One request's view of the index and the store. The index lock is held shared only while index
/// rows are copied into the request arena (`lock`/`unlock` around a few map and iterator steps),
/// never across store reads, layout resolution or rendering, so a checkpoint's `applyChanges`
/// waits at most for a copy. The store snapshot is taken the first time the lock is held: the
/// index only publishes a checkpoint after the store committed it (feed.zig), so the snapshot is
/// at least as new as every row copied under that first lock, and each row's (id, version) reads
/// (sui-node: the rpc-store index trails the object store, `get_object_by_key` reads history).
const Pin = struct {
    ix: *index.Index,
    st: *store.Store,
    snap: ?store.Snapshot = null,

    fn lock(p: *Pin) void {
        p.ix.lock.lockShared();
        if (p.snap == null) p.snap = p.st.snapshot();
    }
    fn unlock(p: *Pin) void {
        p.ix.lock.unlockShared();
    }
    fn snapshot(p: *Pin) *const store.Snapshot {
        if (p.snap == null) {
            p.lock();
            p.unlock();
        }
        return &p.snap.?;
    }
    fn release(p: *Pin) void {
        if (p.snap) |*sn| sn.release();
    }
};

/// Test hook: called for every row the page loops visit, where they read the store (the index
/// lock must be free there).
pub var test_on_row: ?*const fn (ix: *index.Index) void = null;
fn onRow(ix: *index.Index) void {
    if (builtin.is_test) if (test_on_row) |h| h(ix);
}

/// The rows of one owner set (owner index), copied out of the index under the lock `chunk` at a
/// time from `start` while their key starts with `prefix`. Rows are kept for the whole request, so
/// the repeated render passes of `respond` read the same rows. A refill (only when rows were
/// skipped) resumes after the last copied key.
const OwnerRows = struct {
    pin: *Pin,
    arena: Allocator,
    kind: index.Kind,
    owner: [32]u8,
    prefix: []const u8,
    start: []const u8,
    chunk: usize,
    rows: std.ArrayList(Row) = .empty,
    end: bool = false,

    const Row = struct { key: []const u8, ver: u64 };

    fn fill(r: *OwnerRows) !void {
        r.pin.lock();
        defer r.pin.unlock();
        const resume_at: ?[]const u8 = if (r.rows.items.len > 0) r.rows.items[r.rows.items.len - 1].key else null;
        var it = try r.pin.ix.ownedIter(r.arena, r.kind, &r.owner, resume_at orelse r.start);
        var skip_resume = resume_at != null;
        try r.rows.ensureUnusedCapacity(r.arena, r.chunk);
        var got: usize = 0;
        while (got < r.chunk) {
            const e = (try it.next()) orelse {
                r.end = true;
                return;
            };
            if (skip_resume) {
                skip_resume = false;
                if (std.mem.eql(u8, e.key, resume_at.?)) continue;
            }
            if (!std.mem.startsWith(u8, e.key, r.prefix)) {
                r.end = true;
                return;
            }
            r.rows.appendAssumeCapacity(.{ .key = try r.arena.dupe(u8, e.key), .ver = e.ver });
            got += 1;
        }
    }

    fn at(r: *OwnerRows, i: usize) !?Row {
        while (i >= r.rows.items.len) {
            if (r.end) return null;
            try r.fill();
        }
        return r.rows.items[i];
    }
};

/// First output buffer of a page of `n` items of about `per` bytes each (one render pass for
/// typical pages; `respond` doubles it when an item is larger).
fn pageHint(n: usize, per: usize) usize {
    return @min(n * per + 1024, max_page_bytes + (256 << 10));
}

const Err = svc_mod.Err;

fn malformed(_: anyerror) Err {
    return error.Malformed;
}

/// Grows the output buffer until `render` fits, then sends it.
fn respond(c: Ctx, hint: usize, ctx: anytype, comptime render: anytype) !void {
    var cap: usize = @max(hint, 4096);
    while (true) : (cap *= 2) {
        const buf = try c.arena.alloc(u8, cap);
        var w = proto.Writer.init(buf);
        render(ctx, &w) catch |e| {
            if (e == error.NoSpace) continue;
            return e;
        };
        return c.rs.message(w.bytesWritten());
    }
}

fn pageSize(v: ?u64) usize {
    const s = v orelse return default_page;
    return std.math.clamp(@as(usize, @intCast(s & 0xffff_ffff)), 1, max_page);
}

fn addrString(arena: Allocator, a: *const [32]u8) ![]const u8 {
    const buf = try arena.alloc(u8, 66);
    var o: typestr.Out = .{ .buf = buf };
    try o.address(a);
    return o.str();
}

/// `to_canonical_string(true)` of a StructTag in BCS form.
fn structTagString(arena: Allocator, ty_bcs: []const u8) ![]const u8 {
    const t = try bcs.decode(types.StructTag, arena, ty_bcs);
    return canonical(arena, .{ .@"struct" = t });
}

fn canonical(arena: Allocator, t: types.TypeTag) ![]const u8 {
    var cap: usize = 256;
    while (true) : (cap *= 4) {
        const buf = try arena.alloc(u8, cap);
        var o: typestr.Out = .{ .buf = buf };
        typestr.typeTag(&o, t) catch continue;
        return o.str();
    }
}

/// sui-sdk-types Display of a TypeTag: like the canonical form but `, ` between type arguments.
fn sdkDisplay(arena: Allocator, t: types.TypeTag) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try sdkInto(arena, &out, t);
    return out.items;
}
fn sdkInto(arena: Allocator, out: *std.ArrayList(u8), t: types.TypeTag) !void {
    switch (t) {
        .vector => |inner| {
            try out.appendSlice(arena, "vector<");
            try sdkInto(arena, out, inner.*);
            try out.append(arena, '>');
        },
        .@"struct" => |s| {
            try out.appendSlice(arena, try addrString(arena, &s.address.@"0"));
            try out.print(arena, "::{s}::{s}", .{ s.module.@"0", s.name.@"0" });
            if (s.type_args.len > 0) {
                try out.append(arena, '<');
                for (s.type_args, 0..) |a, i| {
                    if (i > 0) try out.appendSlice(arena, ", ");
                    try sdkInto(arena, out, a);
                }
                try out.append(arena, '>');
            }
        },
        else => try out.appendSlice(arena, try canonical(arena, t)),
    }
}

// ============================================================================ ListOwnedObjects

/// Whether an `Object` mask asks for what needs packages (`json`, `display`).
fn wantsRender(m: serve.mask.Mask) bool {
    return m.contains("json") or m.contains("display");
}

fn listOwnedObjects(c: Ctx, body: []const u8) !void {
    @setEvalBranchQuota(20000);
    var owner_text: ?[]const u8 = null;
    var page_size: ?u64 = null;
    var token: ?[]const u8 = null;
    var type_text: ?[]const u8 = null;
    var mask_field: svc_mod.MaskField = .{};
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => owner_text = proto.Reader.stringOf(f) catch return error.Malformed,
        2 => page_size = proto.Reader.varintOf(f) catch return error.Malformed,
        3 => token = proto.Reader.bytesOf(f) catch return error.Malformed,
        4 => try mask_field.add(c.arena, proto.Reader.bytesOf(f) catch return error.Malformed),
        5 => type_text = proto.Reader.stringOf(f) catch return error.Malformed,
        else => {},
    };
    const a = c.arena;
    const otext = owner_text orelse return svc_mod.badField(a, c.rs, "owner", "", .field_missing);
    const owner = svc_mod.parseObjectId(otext) orelse return svc_mod.badField(a, c.rs, "owner", "invalid owner: Unable to parse Address (must be hex string of length 32)", .field_invalid);
    var filter_bcs: ?[]const u8 = null;
    var filter_tag: ?types.StructTag = null;
    if (type_text) |tt| {
        const t = typeparse.structTag(a, tt) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return svc_mod.badField(a, c.rs, "object_type", try moveCoreTypeError(a, tt), .field_invalid),
        };
        filter_tag = t;
        filter_bcs = try bcs.encodeAlloc(types.StructTag, a, &t);
    }
    const n = pageSize(page_size);
    // PageToken { owner: Address, object_type: Option<StructTag>, inner: OwnedObjectInfo }
    var cursor: ?[]const u8 = null; // owner-index suffix to resume at (inclusive)
    if (token) |tb| {
        const bad = "invalid page_token";
        const t = decodeOwnedToken(a, tb) catch return svc_mod.badField(a, c.rs, "page_token", bad, .field_invalid);
        const same_type = if (filter_bcs) |fb| (t.object_type != null and std.mem.eql(u8, fb, t.object_type.?)) else t.object_type == null;
        if (!std.mem.eql(u8, &t.owner, &owner) or !same_type or !withinFilter(t.ty_bcs, filter_tag, filter_bcs))
            return svc_mod.badField(a, c.rs, "page_token", bad, .field_invalid);
        cursor = try index.ownerSuffix(a, t.ty_bcs, t.balance, &t.id);
    }
    var mk = try svc_mod.parseMask(a, c.rs, &mask_field, "object_id,version,object_type", comptime schema.index("Object"));
    const m = mk.m();
    const load = m.contains("bcs") or m.contains("digest") or m.contains("owner") or m.contains("has_public_transfer") or
        m.contains("contents") or m.contains("previous_transaction") or m.contains("storage_rebate") or m.contains("json");

    // The scan prefix inside the owner's set: the type filter's encoding (no type params: address,
    // module, name only, so every instantiation matches; with params: the full BCS).
    const prefix: []const u8 = if (filter_tag) |ft| (if (ft.type_args.len == 0) filterNoParams(filter_bcs.?) else filter_bcs.?) else "";
    const W = struct {
        c: Ctx,
        rows: *OwnerRows,
        n: usize,
        load: bool,
        m: serve.mask.Mask,
        rctx: ?*const render_object.Ctx,
        owner: [32]u8,
        filter_bcs: ?[]const u8,
        fn render(s: @This(), w: *proto.Writer) !void {
            @setEvalBranchQuota(20000);
            var i: usize = 0;
            var count: usize = 0;
            var size: usize = 0;
            while (try s.rows.at(i)) |e| {
                i += 1;
                onRow(s.c.ix);
                const row = try index.splitOwnerSuffix(e.key);
                const mark = try w.begin(1, 256);
                const body_start = w.len;
                if (s.load) {
                    const raw = s.c.snap().objectAt(row.id, e.ver) orelse {
                        w.len = mark.field_pos - proto.varintLen((1 << 3) | 2);
                        continue;
                    };
                    try render_object.writeObjectCtx(s.c.arena, w, s.m, raw, s.rctx);
                } else {
                    if (s.m.contains("object_id")) try render_object.addrStr(w, 2, row.id);
                    if (s.m.contains("version")) try w.uint(3, e.ver);
                    if (s.m.contains("object_type")) try w.string(6, try structTagString(s.c.arena, row.ty_bcs));
                    if (s.m.contains("balance")) if (row.balance) |b| try w.uint(101, b);
                }
                size += w.len - body_start;
                try w.end(mark);
                count += 1;
                if (count >= s.n or size >= max_page_bytes) break;
            }
            // next_page_token: the next row of the scan, if any
            const nx = (try s.rows.at(i)) orelse return;
            const row = try index.splitOwnerSuffix(nx.key);
            try w.bytes(2, try encodeOwnedToken(s.c.arena, &s.owner, s.filter_bcs, row, nx.ver));
        }
    };
    const start = if (cursor) |cur| (if (std.mem.order(u8, cur, prefix) == .lt) prefix else cur) else prefix;
    var rows: OwnerRows = .{ .pin = c.pin, .arena = a, .kind = .address, .owner = owner, .prefix = prefix, .start = start, .chunk = n + 1 };
    try rows.fill();
    try respond(c, pageHint(n, if (load) 768 else 192), W{ .c = c, .rows = &rows, .n = n, .load = load, .m = m, .rctx = if (wantsRender(m)) try c.renderCtx() else null, .owner = owner, .filter_bcs = filter_bcs }, W.render);
}

/// move-core `StructTag::from_str` error text: "Invalid datatype: <s>", plus ". Got error: <parser
/// error>" when the text is not a type at all. The parser's messages are mirrored for the two
/// common shapes (truncated input, a name without `::`); other parse errors use the truncation text.
fn moveCoreTypeError(a: Allocator, s: []const u8) ![]const u8 {
    if (typeparse.typeTag(a, s)) |_| {
        return std.fmt.allocPrint(a, "invalid object_type: Invalid datatype: {s}", .{s});
    } else |_| {}
    const why = if (std.mem.indexOf(u8, s, "::") == null and std.mem.indexOfScalar(u8, s, ' ') != null)
        "expected token ::, got [identifier]"
    else
        "unexpected end of tokens";
    return std.fmt.allocPrint(a, "invalid object_type: Invalid datatype: {s}. Got error: {s}", .{ s, why });
}

/// BCS(StructTag) without its type-parameter list: `address || module || name`.
fn filterNoParams(full: []const u8) []const u8 {
    var r = bcs.Reader.init(full);
    _ = r.bytes(32) catch return full;
    const ml = r.length() catch return full;
    _ = r.bytes(ml) catch return full;
    const nl = r.length() catch return full;
    _ = r.bytes(nl) catch return full;
    return full[0..r.pos()];
}

/// `cursor_within_type_filter`.
fn withinFilter(cursor_ty: []const u8, filter: ?types.StructTag, filter_bcs: ?[]const u8) bool {
    const ft = filter orelse return true;
    if (ft.type_args.len == 0) {
        const p = filterNoParams(filter_bcs.?);
        return std.mem.eql(u8, filterNoParams(cursor_ty), p);
    }
    return std.mem.eql(u8, cursor_ty, filter_bcs.?);
}

const OwnedToken = struct { owner: [32]u8, object_type: ?[]const u8, ty_bcs: []const u8, balance: ?u64, id: [32]u8, version: u64 };

fn decodeOwnedToken(arena: Allocator, tb: []const u8) !OwnedToken {
    _ = arena;
    var r = bcs.Reader.init(tb);
    var t: OwnedToken = undefined;
    t.owner = (try r.bytes(32))[0..32].*;
    switch (try r.int(u8)) {
        0 => t.object_type = null,
        1 => {
            const s = r.pos();
            try bcs.skip(types.StructTag, &r);
            t.object_type = tb[s..r.pos()];
        },
        else => return error.InvalidValue,
    }
    _ = try r.bytes(32); // inner.owner
    const s = r.pos();
    try bcs.skip(types.StructTag, &r);
    t.ty_bcs = tb[s..r.pos()];
    switch (try r.int(u8)) {
        0 => t.balance = null,
        1 => t.balance = try r.int(u64),
        else => return error.InvalidValue,
    }
    t.id = (try r.bytes(32))[0..32].*;
    t.version = try r.int(u64);
    try r.finish();
    return t;
}

fn encodeOwnedToken(arena: Allocator, owner: *const [32]u8, filter_bcs: ?[]const u8, row: index.OwnerRow, version: u64) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, owner);
    if (filter_bcs) |fb| {
        try out.append(arena, 1);
        try out.appendSlice(arena, fb);
    } else try out.append(arena, 0);
    try out.appendSlice(arena, owner);
    try out.appendSlice(arena, row.ty_bcs);
    if (row.balance) |b| {
        try out.append(arena, 1);
        try out.appendSlice(arena, std.mem.asBytes(&std.mem.nativeToLittle(u64, b)));
    } else try out.append(arena, 0);
    try out.appendSlice(arena, row.id);
    try out.appendSlice(arena, std.mem.asBytes(&std.mem.nativeToLittle(u64, version)));
    return out.items;
}

// ============================================================================ ListDynamicFields

fn listDynamicFields(c: Ctx, body: []const u8) !void {
    var parent_text: ?[]const u8 = null;
    var page_size: ?u64 = null;
    var token: ?[]const u8 = null;
    var mask_field: svc_mod.MaskField = .{};
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => parent_text = proto.Reader.stringOf(f) catch return error.Malformed,
        2 => page_size = proto.Reader.varintOf(f) catch return error.Malformed,
        3 => token = proto.Reader.bytesOf(f) catch return error.Malformed,
        4 => try mask_field.add(c.arena, proto.Reader.bytesOf(f) catch return error.Malformed),
        else => {},
    };
    const a = c.arena;
    const ptext = parent_text orelse return svc_mod.badField(a, c.rs, "parent", "", .field_missing);
    const parent = svc_mod.parseObjectId(ptext) orelse return svc_mod.badField(a, c.rs, "parent", "invalid owner: Unable to parse Address (must be hex string of length 32)", .field_invalid);
    const n = pageSize(page_size);
    // PageToken { parent: Address, field_id: Address, object_type: StructTag }
    var start: []const u8 = "";
    if (token) |tb| {
        const bad = "invalid page_token";
        var tr = bcs.Reader.init(tb);
        const tp = (tr.bytes(32) catch return svc_mod.badField(a, c.rs, "page_token", bad, .field_invalid))[0..32];
        const fid = (tr.bytes(32) catch return svc_mod.badField(a, c.rs, "page_token", bad, .field_invalid))[0..32];
        const ts = tr.pos();
        bcs.skip(types.StructTag, &tr) catch return svc_mod.badField(a, c.rs, "page_token", bad, .field_invalid);
        tr.finish() catch return svc_mod.badField(a, c.rs, "page_token", bad, .field_invalid);
        if (!std.mem.eql(u8, tp, &parent)) return svc_mod.badField(a, c.rs, "page_token", bad, .field_invalid);
        start = try index.ownerSuffix(a, tb[ts..tr.pos()], null, fid);
    }
    var mk = try svc_mod.parseMask(a, c.rs, &mask_field, "parent,field_id", comptime schema.index("DynamicField"));
    const m = mk.m();
    const W = struct {
        c: Ctx,
        rows: *OwnerRows,
        n: usize,
        m: serve.mask.Mask,
        parent: [32]u8,
        sess: *dflayout.Session,
        fn render(s: @This(), w: *proto.Writer) !void {
            @setEvalBranchQuota(20000);
            var i: usize = 0;
            var count: usize = 0;
            var size: usize = 0;
            while (try s.rows.at(i)) |e| {
                i += 1;
                onRow(s.c.ix);
                const row = try index.splitOwnerSuffix(e.key);
                const save = w.len;
                const mark = try w.begin(1, 512);
                const body_start = w.len;
                const ok = try dflayout.writeField(s.sess, w, s.m, &s.parent, row.id);
                if (!ok) {
                    w.len = save;
                    continue;
                }
                size += w.len - body_start;
                try w.end(mark);
                count += 1;
                if (count >= s.n or size >= max_page_bytes) break;
            }
            const nx = (try s.rows.at(i)) orelse return;
            const row = try index.splitOwnerSuffix(nx.key);
            var tok: std.ArrayList(u8) = .empty;
            try tok.appendSlice(s.c.arena, &s.parent);
            try tok.appendSlice(s.c.arena, row.id);
            try tok.appendSlice(s.c.arena, row.ty_bcs);
            try w.bytes(2, tok.items);
        }
    };
    var rows: OwnerRows = .{ .pin = c.pin, .arena = a, .kind = .object, .owner = parent, .prefix = "", .start = start, .chunk = n + 1 };
    try rows.fill();
    var sess = dflayout.Session.init(a, c.snap());
    if (m.subtree("field_object")) |sub| if (wantsRender(sub)) {
        sess.render = try c.renderCtx();
    };
    if (sess.render == null) if (m.subtree("child_object")) |sub| if (wantsRender(sub)) {
        sess.render = try c.renderCtx();
    };
    try respond(c, pageHint(n, if (dflayout.shouldLoad(m)) 1024 else 160), W{ .c = c, .rows = &rows, .n = n, .m = m, .parent = parent, .sess = &sess }, W.render);
}

// ============================================================================ balances

fn writeBalance(w: *proto.Writer, field: u32, coin_type: []const u8, b: index.Bal) !void {
    const coin: u64 = @intCast(std.math.clamp(b.coin, 0, std.math.maxInt(u64)));
    const addr: u64 = @intCast(std.math.clamp(b.address, 0, std.math.maxInt(u64)));
    const mark = try w.begin(field, coin_type.len + 40);
    try w.string(1, coin_type);
    try w.uint(3, coin +| addr);
    if (addr != 0) try w.uint(4, addr);
    if (coin != 0) try w.uint(5, coin);
    try w.end(mark);
}

fn getBalance(c: Ctx, body: []const u8) !void {
    var owner_text: ?[]const u8 = null;
    var type_text: ?[]const u8 = null;
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => owner_text = proto.Reader.stringOf(f) catch return error.Malformed,
        2 => type_text = proto.Reader.stringOf(f) catch return error.Malformed,
        else => {},
    };
    const a = c.arena;
    const otext = owner_text orelse return svc_mod.badField(a, c.rs, "owner", "missing owner", .field_missing);
    const owner = svc_mod.parseObjectId(otext) orelse return svc_mod.badField(a, c.rs, "owner", "invalid owner: Unable to parse Address (must be hex string of length 32)", .field_invalid);
    const tt = type_text orelse return svc_mod.badField(a, c.rs, "coin_type", "missing coin_type", .field_missing);
    const st = typeparse.structTag(a, tt) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return svc_mod.badField(a, c.rs, "coin_type", try std.fmt.allocPrint(a, "invalid coin_type: unable to parse type \"{s}\"", .{tt}), .field_invalid),
    };
    const tag: types.TypeTag = .{ .@"struct" = st };
    const tb = try bcs.encodeAlloc(types.TypeTag, a, &tag);
    var bal: index.Bal = .{};
    c.pin.lock();
    bal = c.ix.balance(a, &owner, tb) catch |e| {
        c.pin.unlock();
        return e;
    };
    c.pin.unlock();
    const ts = try canonical(a, tag);
    const W = struct {
        ts: []const u8,
        bal: index.Bal,
        fn render(s: @This(), w: *proto.Writer) !void {
            try writeBalance(w, 1, s.ts, s.bal);
        }
    };
    try respond(c, 256, W{ .ts = ts, .bal = bal }, W.render);
}

fn listBalances(c: Ctx, body: []const u8) !void {
    var owner_text: ?[]const u8 = null;
    var page_size: ?u64 = null;
    var token: ?[]const u8 = null;
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => owner_text = proto.Reader.stringOf(f) catch return error.Malformed,
        2 => page_size = proto.Reader.varintOf(f) catch return error.Malformed,
        3 => token = proto.Reader.bytesOf(f) catch return error.Malformed,
        else => {},
    };
    const a = c.arena;
    const otext = owner_text orelse return svc_mod.badField(a, c.rs, "owner", "missing owner", .field_missing);
    const owner = svc_mod.parseObjectId(otext) orelse return svc_mod.badField(a, c.rs, "owner", "invalid owner: Unable to parse Address (must be hex string of length 32)", .field_invalid);
    const n = pageSize(page_size);
    // PageToken { owner: Address, coin_type: StructTag }; the scan resumes at TypeTag::Struct(coin_type)
    var start: []const u8 = "";
    if (token) |tb| {
        var tr = bcs.Reader.init(tb);
        const tok_owner = (tr.bytes(32) catch return svc_mod.badField(a, c.rs, "page_token", "invalid page token encoding: unexpected end of input", .field_invalid))[0..32];
        const ts = tr.pos();
        bcs.skip(types.StructTag, &tr) catch return svc_mod.badField(a, c.rs, "page_token", "invalid page token encoding: unexpected end of input", .field_invalid);
        tr.finish() catch return svc_mod.badField(a, c.rs, "page_token", "invalid page token encoding: remaining input", .field_invalid);
        if (!std.mem.eql(u8, tok_owner, &owner)) return svc_mod.badField(a, c.rs, "page_token", "page token owner does not match request owner", .field_invalid);
        const sk = try a.alloc(u8, 1 + tr.pos() - ts);
        sk[0] = 7; // TypeTag::Struct
        @memcpy(sk[1..], tb[ts..tr.pos()]);
        start = sk;
    }
    // Up to n+1 rows (the last one only names the next page) copied out under the lock.
    const Row = struct { key: []const u8, val: index.Bal };
    var rows: std.ArrayList(Row) = .empty;
    {
        c.pin.lock();
        defer c.pin.unlock();
        var it = try c.ix.balanceIter(a, &owner, start);
        while (try it.next()) |e| {
            if (e.key[0] != 7) continue; // non-struct coin types are dropped by balance_iter
            try rows.append(a, .{ .key = try a.dupe(u8, e.key), .val = e.val });
            if (rows.items.len > n) break;
        }
    }
    const W = struct {
        c: Ctx,
        rows: []const Row,
        n: usize,
        owner: [32]u8,
        fn render(s: @This(), w: *proto.Writer) !void {
            @setEvalBranchQuota(20000);
            var count: usize = 0;
            for (s.rows) |e| {
                const tag = try bcs.decode(types.TypeTag, s.c.arena, e.key);
                if (count == s.n) {
                    var tok: std.ArrayList(u8) = .empty;
                    try tok.appendSlice(s.c.arena, &s.owner);
                    try tok.appendSlice(s.c.arena, e.key[1..]);
                    try w.bytes(2, tok.items);
                    return;
                }
                try writeBalance(w, 1, try canonical(s.c.arena, tag), e.val);
                count += 1;
            }
        }
    };
    try respond(c, pageHint(rows.items.len, 160), W{ .c = c, .rows = rows.items, .n = n, .owner = owner }, W.render);
}

// ============================================================================ GetCoinInfo

const sui_framework: [32]u8 = blk: {
    var x: [32]u8 = @splat(0);
    x[31] = 2;
    break :blk x;
};
const coin_registry_id: [32]u8 = blk: {
    var x: [32]u8 = @splat(0);
    x[31] = 0xc;
    break :blk x;
};
const total_supply_mist: u64 = 10_000_000_000 * 1_000_000_000;

fn isGas(st: types.StructTag) bool {
    return std.mem.eql(u8, &st.address.@"0", &sui_framework) and std.mem.eql(u8, st.module.@"0", "sui") and std.mem.eql(u8, st.name.@"0", "SUI") and st.type_args.len == 0;
}

fn ident(s: []const u8) types.Identifier {
    return .{ .@"0" = s };
}

/// `Currency::derive_object_id`: derive_dynamic_field_id(0xc, DerivedObjectKey<CurrencyKey<T>>, bcs(CurrencyKey(false))).
pub fn currencyId(arena: Allocator, coin: types.TypeTag) ![32]u8 {
    const key: types.TypeTag = .{ .@"struct" = .{ .address = .{ .@"0" = sui_framework }, .module = ident("coin_registry"), .name = ident("CurrencyKey"), .type_args = try arena.dupe(types.TypeTag, &.{coin}) } };
    const wrapper: types.TypeTag = .{ .@"struct" = .{ .address = .{ .@"0" = sui_framework }, .module = ident("derived_object"), .name = ident("DerivedObjectKey"), .type_args = try arena.dupe(types.TypeTag, &.{key}) } };
    return dflayout.dynamicFieldId(arena, &coin_registry_id, wrapper, &.{0});
}

const CoinIds = struct { metadata: ?[32]u8, treasury: ?[32]u8, regulated: ?[32]u8 };

const CoinState = struct {
    metadata: ?[]const u8 = null, // rendered CoinMetadata body
    treasury: ?[]const u8 = null, // rendered CoinTreasury body
    regulated: ?[]const u8 = null, // rendered RegulatedCoinMetadata body
};

fn getCoinInfo(c: Ctx, body: []const u8) !void {
    var type_text: []const u8 = "";
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => type_text = proto.Reader.stringOf(f) catch return error.Malformed,
        else => {},
    };
    const a = c.arena;
    const st = typeparse.structTag(a, type_text) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            c.rs.setMessage(try std.fmt.allocPrint(a, "invalid coin_type: unable to parse type \"{s}\"", .{type_text}));
            return error.Reported;
        },
    };
    const tag: types.TypeTag = .{ .@"struct" = st };
    const tb = try bcs.encodeAlloc(types.TypeTag, a, &tag);
    const shown = try sdkDisplay(a, tag);
    var cs: CoinState = .{};
    // The three wrapper ids (the index's only part in GetCoinInfo), read under the lock at once.
    var ids: CoinIds = undefined;
    {
        c.pin.lock();
        defer c.pin.unlock();
        ids = .{ .metadata = try c.ix.coinObject(a, .metadata, tb), .treasury = try c.ix.coinObject(a, .treasury, tb), .regulated = try c.ix.coinObject(a, .regulated, tb) };
    }
    const found = (try fromRegistry(c, st, tag, &ids, &cs)) or (try fromIndex(c, st, &ids, &cs));
    if (!found) {
        c.rs.setMessage(try std.fmt.allocPrint(a, "Coin type {s} not found", .{shown}));
        return error.NotFound;
    }
    const W = struct {
        shown: []const u8,
        cs: CoinState,
        fn render(s: @This(), w: *proto.Writer) !void {
            try w.string(1, s.shown);
            if (s.cs.metadata) |m| try w.bytes(2, m);
            if (s.cs.treasury) |m| try w.bytes(3, m);
            if (s.cs.regulated) |m| try w.bytes(4, m);
        }
    };
    try respond(c, 1024, W{ .shown = shown, .cs = cs }, W.render);
}

fn sdkAddr(arena: Allocator, a: *const [32]u8) ![]const u8 {
    return addrString(arena, a);
}

/// A small proto message built in the arena.
const Msg = struct {
    w: proto.Writer,
    fn init(arena: Allocator, cap: usize) !Msg {
        return .{ .w = proto.Writer.init(try arena.alloc(u8, cap + 128)) };
    }
    fn done(m: *Msg) []const u8 {
        return m.w.bytesWritten();
    }
};

fn regulatedState(arena: Allocator, state: u64) ![]const u8 {
    var m = try Msg.init(arena, 8);
    try m.w.uint(6, state);
    return m.done();
}

fn fromRegistry(c: Ctx, st: types.StructTag, tag: types.TypeTag, ids: *const CoinIds, cs: *CoinState) !bool {
    const a = c.arena;
    const cid = try currencyId(a, tag);
    const obj = c.snap().liveObject(&cid) orelse return false;
    const o = bcs.decode(types.Object, a, obj.bytes) catch return error.Internal;
    const mo = switch (o.data) {
        .Move => |x| x,
        .Package => return error.Internal,
    };
    // Currency<T> { id, decimals, name, symbol, description, icon_url, supply: Option<SupplyState>,
    //   regulated: RegulatedState, treasury_cap_id: Option<ID>, metadata_cap_id: MetadataCapState, extra_fields }
    var r = bcs.Reader.init(mo.contents);
    const cur = parseCurrency(&r) catch {
        c.rs.setMessage(try std.fmt.allocPrint(a, "Failed to deserialize Currency for coin type {s}: unexpected end of input", .{try canonical(a, tag)}));
        return error.Internal;
    };
    {
        var m = try Msg.init(a, 512 + cur.name.len + cur.symbol.len + cur.description.len + cur.icon_url.len);
        try m.w.string(1, try sdkAddr(a, &cur.id));
        try m.w.uint(2, cur.decimals);
        try m.w.string(3, cur.name);
        try m.w.string(4, cur.symbol);
        try m.w.string(5, cur.description);
        try m.w.string(6, cur.icon_url);
        switch (cur.meta_cap) {
            0 => {
                try m.w.string(7, try sdkAddr(a, &cur.meta_cap_id));
                try m.w.uint(8, 1);
            },
            1 => try m.w.uint(8, 2),
            else => try m.w.uint(8, 3),
        }
        cs.metadata = m.done();
    }
    if (isGas(st)) {
        cs.treasury = try suiTreasury(a);
    } else switch (cur.supply) {
        0, 1 => {
            var m = try Msg.init(a, 96);
            if (cur.treasury_cap_id) |tid| try m.w.string(1, try sdkAddr(a, &tid));
            try m.w.uint(2, cur.supply_value);
            try m.w.uint(3, if (cur.supply == 0) 1 else 2);
            cs.treasury = m.done();
        },
        else => {
            const tid = cur.treasury_cap_id orelse ids.treasury;
            if (tid) |t| cs.treasury = try treasuryInfo(c, &t);
        },
    }
    if (cur.regulated != 2) {
        var m = try Msg.init(a, 128);
        if (cur.regulated == 0) {
            try m.w.string(3, try sdkAddr(a, &cur.deny_cap));
            if (cur.allow_global_pause) |p| try m.w.uint(4, @intFromBool(p));
            try m.w.uint(5, cur.variant);
            try m.w.uint(6, 1);
        } else try m.w.uint(6, 2);
        cs.regulated = m.done();
    } else {
        // Unknown in the registry: the legacy RegulatedCoinMetadata decides
        if (ids.regulated) |rid| {
            cs.regulated = (try legacyRegulated(c, &rid, tag)) orelse try regulatedState(a, 2);
        } else cs.regulated = try regulatedState(a, 2);
    }
    return true;
}

fn suiTreasury(arena: Allocator) ![]const u8 {
    var m = try Msg.init(arena, 32);
    try m.w.uint(2, total_supply_mist);
    try m.w.uint(3, 1);
    return m.done();
}

const Currency = struct {
    id: [32]u8,
    decimals: u8,
    name: []const u8,
    symbol: []const u8,
    description: []const u8,
    icon_url: []const u8,
    supply: u8 = 3, // 0 Fixed, 1 BurnOnly, 2 Unknown, 3 None
    supply_value: u64 = 0,
    regulated: u8,
    deny_cap: [32]u8 = @splat(0),
    allow_global_pause: ?bool = null,
    variant: u8 = 0,
    treasury_cap_id: ?[32]u8,
    meta_cap: u8,
    meta_cap_id: [32]u8 = @splat(0),
};

fn str(r: *bcs.Reader) ![]const u8 {
    return bcs.readStr(r);
}

fn parseCurrency(r: *bcs.Reader) !Currency {
    var cur: Currency = undefined;
    cur.id = (try r.bytes(32))[0..32].*;
    cur.decimals = try r.int(u8);
    cur.name = try str(r);
    cur.symbol = try str(r);
    cur.description = try str(r);
    cur.icon_url = try str(r);
    cur.supply = 3;
    cur.supply_value = 0;
    switch (try r.int(u8)) {
        0 => {},
        1 => {
            cur.supply = @intCast(try r.length());
            switch (cur.supply) {
                0, 1 => cur.supply_value = try r.int(u64),
                2 => {},
                else => return error.InvalidValue,
            }
        },
        else => return error.InvalidValue,
    }
    cur.regulated = @intCast(try r.length());
    cur.allow_global_pause = null;
    cur.variant = 0;
    cur.deny_cap = @splat(0);
    switch (cur.regulated) {
        0 => {
            cur.deny_cap = (try r.bytes(32))[0..32].*;
            switch (try r.int(u8)) {
                0 => {},
                1 => cur.allow_global_pause = (try r.int(u8)) != 0,
                else => return error.InvalidValue,
            }
            cur.variant = try r.int(u8);
        },
        1, 2 => {},
        else => return error.InvalidValue,
    }
    cur.treasury_cap_id = switch (try r.int(u8)) {
        0 => null,
        1 => (try r.bytes(32))[0..32].*,
        else => return error.InvalidValue,
    };
    cur.meta_cap = @intCast(try r.length());
    cur.meta_cap_id = @splat(0);
    switch (cur.meta_cap) {
        0 => cur.meta_cap_id = (try r.bytes(32))[0..32].*,
        1, 2 => {},
        else => return error.InvalidValue,
    }
    // extra_fields: VecMap<String, ExtraField { type_: String, value: vector<u8> }>
    const n = try r.length();
    for (0..n) |_| {
        _ = try str(r);
        _ = try str(r);
        _ = try r.bytes(try r.length());
    }
    try r.finish();
    return cur;
}

/// `get_treasury_cap_info`: TreasuryCap<T> { id, total_supply: Supply { value } } with the
/// supply state from its owner (immutable or owned by 0x0: Fixed; else Unknown).
fn treasuryInfo(c: Ctx, id: *const [32]u8) !?[]const u8 {
    const a = c.arena;
    const obj = c.snap().liveObject(id) orelse return null;
    const o = bcs.decode(types.Object, a, obj.bytes) catch return null;
    const mo = switch (o.data) {
        .Move => |x| x,
        .Package => return null,
    };
    const ty = try index.objectStructTag(a, mo.type_);
    if (!(std.mem.eql(u8, &ty.address.@"0", &sui_framework) and std.mem.eql(u8, ty.module.@"0", "coin") and std.mem.eql(u8, ty.name.@"0", "TreasuryCap"))) return null;
    if (mo.contents.len != 40) return null;
    const zero: [32]u8 = @splat(0);
    const fixed = switch (o.owner) {
        .Immutable => true,
        .AddressOwner => |x| std.mem.eql(u8, &x.@"0", &zero),
        .ConsensusAddressOwner => |x| std.mem.eql(u8, &x.owner.@"0", &zero),
        else => false,
    };
    var m = try Msg.init(a, 96);
    try m.w.string(1, try sdkAddr(a, mo.contents[0..32]));
    try m.w.uint(2, std.mem.readInt(u64, mo.contents[32..40], .little));
    try m.w.uint(3, if (fixed) 1 else 0);
    return m.done();
}

/// RegulatedCoinMetadata<T> { id, coin_metadata_object: ID, deny_cap_object: ID }. Null when the
/// object is missing; INTERNAL when it does not read as one.
fn legacyRegulated(c: Ctx, id: *const [32]u8, tag: types.TypeTag) !?[]const u8 {
    const a = c.arena;
    const obj = c.snap().liveObject(id) orelse return null;
    const o = bcs.decode(types.Object, a, obj.bytes) catch return error.Internal;
    const mo = switch (o.data) {
        .Move => |x| x,
        .Package => return error.Internal,
    };
    if (mo.contents.len != 96) {
        c.rs.setMessage(try std.fmt.allocPrint(a, "Unable to read object {s} for coin type {s} as RegulatedCoinMetadata", .{ try addrString(a, id), try canonical(a, tag) }));
        return error.Internal;
    }
    var m = try Msg.init(a, 256);
    try m.w.string(1, try sdkAddr(a, mo.contents[0..32]));
    try m.w.string(2, try sdkAddr(a, mo.contents[32..64]));
    try m.w.string(3, try sdkAddr(a, mo.contents[64..96]));
    try m.w.uint(6, 1);
    return m.done();
}

fn fromIndex(c: Ctx, st: types.StructTag, ids: *const CoinIds, cs: *CoinState) !bool {
    const a = c.arena;
    const meta_id = ids.metadata;
    const treas_id = ids.treasury;
    const reg_id = ids.regulated;
    if (meta_id == null and treas_id == null and reg_id == null) return false;
    const tag: types.TypeTag = .{ .@"struct" = st };
    if (meta_id) |mid| if (c.snap().liveObject(&mid)) |obj| {
        // CoinMetadata<T> { id, decimals: u8, name, symbol, description: String, icon_url: Option<Url> }
        const o = bcs.decode(types.Object, a, obj.bytes) catch return error.Internal;
        const contents = switch (o.data) {
            .Move => |x| x.contents,
            .Package => return error.Internal,
        };
        var r = bcs.Reader.init(contents);
        const parsed = parseMetadata(&r) catch {
            c.rs.setMessage(try std.fmt.allocPrint(a, "Unable to read object {s} for coin type {s} as CoinMetadata", .{ try addrString(a, &mid), try canonical(a, tag) }));
            return error.Internal;
        };
        var m = try Msg.init(a, 512 + contents.len);
        try m.w.string(1, try sdkAddr(a, contents[0..32]));
        try m.w.uint(2, parsed.decimals);
        try m.w.string(3, parsed.name);
        try m.w.string(4, parsed.symbol);
        try m.w.string(5, parsed.description);
        if (parsed.icon_url) |u| try m.w.string(6, u);
        cs.metadata = m.done();
    };
    if (treas_id) |t| {
        cs.treasury = try treasuryInfo(c, &t);
    } else if (isGas(st)) cs.treasury = try suiTreasury(a);
    if (reg_id) |rid| {
        cs.regulated = try legacyRegulated(c, &rid, tag);
    } else cs.regulated = try regulatedState(a, 2);
    return true;
}

fn parseMetadata(r: *bcs.Reader) !struct { decimals: u8, name: []const u8, symbol: []const u8, description: []const u8, icon_url: ?[]const u8 } {
    _ = try r.bytes(32);
    const d = try r.int(u8);
    const n = try str(r);
    const s = try str(r);
    const desc = try str(r);
    const icon: ?[]const u8 = switch (try r.int(u8)) {
        0 => null,
        1 => try str(r),
        else => return error.InvalidValue,
    };
    try r.finish();
    return .{ .decimals = d, .name = n, .symbol = s, .description = desc, .icon_url = icon };
}
