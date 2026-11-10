//! `SimulateTransactionResponse` rendering (sui-rpc-api simulate/mod.rs): the ExecutedTransaction
//! fields 2, 4, 5, 8, 9 through serve's renderers (render_tx, balance, ledger object sets), and
//! render.rs `render_clever_error`, which the RPC applies to every rendered Move abort.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const exec = @import("exec");
const serve = @import("serve");
const mf = @import("move_format");

const root = @import("root.zig");
const state_mod = @import("state.zig");
const sim = @import("simulate.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const proto = serve.proto;
const Writer = proto.Writer;
const Mask = serve.mask.Mask;

pub const Input = struct {
    /// The request's BCS TransactionData (without a mock gas coin) and its digest.
    tx_raw: []const u8,
    td: types.TransactionData,
    tx_digest: [32]u8,
    effects: []const u8,
    eff: types.TransactionEffects,
    events: ?[]const u8,
    objects: []const []const u8,
    loaded: []const sim.Ref,
    /// `json` / `display` rendering of events and objects (`render_events_to_proto`,
    /// `render_object_to_proto` with the output object set as the package overlay); null leaves
    /// them out.
    render: ?*const serve.render_object.Ctx = null,
};

pub const Out = union(enum) {
    ok: []const u8,
    unimplemented: []const u8,
};

pub fn response(arena: Allocator, e: *const sim.Engine, env: *const root.EpochEnv, state: state_mod.State, m: Mask, in: Input) !Out {
    const tm = m.subtree("transaction") orelse return .{ .ok = &.{} };
    var set = try serve.objset.ObjSet.build(arena, in.objects);

    // effects (field 4) first, in their own buffer: the clever error is spliced into the abort
    var eff_bytes: []const u8 = &.{};
    if (tm.subtree("effects")) |em| {
        const rin: serve.render_tx.Input = .{
            .transaction = in.tx_raw,
            .signatures = &.{},
            .effects = in.effects,
            .events = in.events,
            .objects = &set,
            .loaded = in.loaded,
            .decoded_effects = in.eff,
        };
        eff_bytes = try renderGrow(arena, in.effects.len * 2 + 4096, EffCtx{ .arena = arena, .m = em, .in = &rin }, EffCtx.write);
        eff_bytes = try clever(arena, e, env, state, eff_bytes);
    }

    // transaction (field 2) in its own buffer: simulate renders it from sui_sdk_types, whose
    // type tags print generic arguments as "<A, B>" (rpc_proto_conversions prints "<A,B>")
    var tx_bytes: []const u8 = &.{};
    if (tm.subtree("transaction")) |sm| {
        tx_bytes = try renderGrow(arena, in.tx_raw.len * 3 + 1024, TxFieldCtx{ .arena = arena, .m = sm, .in = &in }, TxFieldCtx.write);
        if (needsSdkSeps(&in.td)) tx_bytes = try mapField(arena, tx_bytes, 2, txSeps);
    }

    const ctx: TxCtx = .{ .arena = arena, .m = tm, .in = &in, .set = &set, .eff_bytes = eff_bytes, .tx_bytes = tx_bytes };
    var hint: usize = tx_bytes.len + eff_bytes.len + 8192;
    for (in.objects) |o| hint += o.len * 2 + 256;
    if (in.events) |ev| hint += ev.len * 2;
    return .{ .ok = try renderGrow(arena, hint, ctx, TxCtx.write) };
}

fn renderGrow(arena: Allocator, hint: usize, ctx: anytype, comptime f: anytype) ![]const u8 {
    var cap: usize = @max(hint, 1024);
    while (true) : (cap *= 2) {
        const buf = try arena.alloc(u8, cap);
        var w = Writer.init(buf);
        f(ctx, &w) catch |err| switch (err) {
            error.NoSpace => continue,
            else => return err,
        };
        return w.bytesWritten();
    }
}

const EffCtx = struct {
    arena: Allocator,
    m: Mask,
    in: *const serve.render_tx.Input,

    fn write(c: EffCtx, w: *Writer) !void {
        try serve.render_tx.writeEffects(c.arena, w, 4, c.m, c.in.effects, c.in.decoded_effects.?, c.in);
    }
};

const TxFieldCtx = struct {
    arena: Allocator,
    m: Mask,
    in: *const Input,

    fn write(c: TxFieldCtx, w: *Writer) !void {
        try serve.render_tx.writeTransaction(c.arena, w, 2, c.m, c.in.tx_raw, c.in.td, &c.in.tx_digest);
    }
};

// ---- sdk type-tag spelling ------------------------------------------------------------------

fn typeNeedsSep(t: *const types.TypeInput) bool {
    return switch (t.*) {
        .vector => |inner| typeNeedsSep(inner),
        .@"struct" => |st| blk: {
            if (st.type_args.len > 1) break :blk true;
            for (st.type_args) |*a| if (typeNeedsSep(a)) break :blk true;
            break :blk false;
        },
        else => false,
    };
}

fn needsSdkSeps(td: *const types.TransactionData) bool {
    const ptb = switch (td.*) {
        .V1 => |v| switch (v.kind) {
            .ProgrammableTransaction => |p| p,
            else => return false,
        },
    };
    for (ptb.commands) |c| switch (c) {
        .MoveCall => |mc| for (mc.type_arguments) |*t| if (typeNeedsSep(t)) return true,
        .MakeMoveVec => |mv| if (mv.@"0") |*t| if (typeNeedsSep(t)) return true,
        else => {},
    };
    return false;
}

/// `msg` with every length-delimited field `number` replaced by `f(field data)`.
fn mapField(arena: Allocator, msg: []const u8, number: u32, comptime f: fn (Allocator, []const u8) anyerror![]const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var r = proto.Reader.init(msg);
    var start: usize = 0;
    while (try r.next()) |fl| {
        if (fl.number == number and fl.wire == 2) {
            const inner = try f(arena, fl.data);
            try appendTag(arena, &out, fl.number, 2);
            try appendVarint(arena, &out, inner.len);
            try out.appendSlice(arena, inner);
        } else try out.appendSlice(arena, msg[start..r.pos]);
        start = r.pos;
    }
    return out.items;
}

// Transaction.kind(4).programmable_transaction(2).commands(2): MoveCall(1).type_arguments(4),
// MakeMoveVector(6).element_type(1).
fn txSeps(a: Allocator, m: []const u8) anyerror![]const u8 {
    return mapField(a, m, 4, kindSeps);
}
fn kindSeps(a: Allocator, m: []const u8) anyerror![]const u8 {
    return mapField(a, m, 2, ptbSeps);
}
fn ptbSeps(a: Allocator, m: []const u8) anyerror![]const u8 {
    return mapField(a, m, 2, cmdSeps);
}
fn cmdSeps(a: Allocator, m: []const u8) anyerror![]const u8 {
    return mapField(a, try mapField(a, m, 1, moveCallSeps), 6, makeVecSeps);
}
fn moveCallSeps(a: Allocator, m: []const u8) anyerror![]const u8 {
    return mapField(a, m, 4, commaSpace);
}
fn makeVecSeps(a: Allocator, m: []const u8) anyerror![]const u8 {
    return mapField(a, m, 1, commaSpace);
}
fn commaSpace(a: Allocator, s: []const u8) anyerror![]const u8 {
    const n = std.mem.count(u8, s, ",");
    if (n == 0) return s;
    const out = try a.alloc(u8, s.len + n);
    var j: usize = 0;
    for (s) |ch| {
        out[j] = ch;
        j += 1;
        if (ch == ',') {
            out[j] = ' ';
            j += 1;
        }
    }
    return out;
}

const TxCtx = struct {
    arena: Allocator,
    m: Mask,
    in: *const Input,
    tx_bytes: []const u8,
    set: *serve.objset.ObjSet,
    eff_bytes: []const u8,

    fn write(c: TxCtx, w: *Writer) !void {
        const in = c.in;
        const top = try w.begin(1, 1 << 20);
        try w.rawAppend(c.tx_bytes);
        try w.rawAppend(c.eff_bytes);
        if (c.m.subtree("events")) |sm| if (in.events) |eb| {
            const ev = try bcs.decode(types.TransactionEvents, c.arena, eb);
            try serve.render_tx.writeEventsCtx(c.arena, w, 5, sm, eb, ev, null, in.render);
        };
        if (c.m.contains("balance_changes")) {
            const changes = try serve.balance.derive(c.arena, in.eff, &c.set.map);
            for (changes) |ch| try serve.balance.write(w, 8, ch);
        }
        try serve.ledger.writeObjectSetAtCtx(c.arena, w, 9, c.m, in.objects, in.render);
        try w.end(top);
    }
};

// ---- clever errors ----------------------------------------------------------------------------

/// `render_clever_error` on the rendered effects field (`[tag 4][len][TransactionEffects]`):
/// when status.error.abort is present, its `clever_error` (field 3) is resolved from the abort's
/// location and code as rendered, and appended to the abort message.
pub fn clever(arena: Allocator, e: *const sim.Engine, env: *const root.EpochEnv, state: state_mod.State, field: []const u8) ![]const u8 {
    var r = proto.Reader.init(field);
    const f = (r.next() catch return field) orelse return field;
    const body = proto.Reader.bytesOf(f) catch return field;
    const status = sub(body, 4) orelse return field;
    const err = sub(status, 2) orelse return field;
    const abort = sub(err, 4) orelse return field;
    var code: u64 = 0;
    var loc: ?[]const u8 = null;
    {
        var ar = proto.Reader.init(abort);
        while (ar.next() catch return field) |af| switch (af.number) {
            1 => code = af.varint,
            2 => loc = af.data,
            else => {},
        };
    }
    const l = loc orelse return field;
    var pkg_s: []const u8 = "";
    var module: []const u8 = "";
    {
        var lr = proto.Reader.init(l);
        while (lr.next() catch return field) |lf| switch (lf.number) {
            1 => pkg_s = lf.data,
            2 => module = lf.data,
            else => {},
        };
    }
    const msg = (try resolve(arena, e, env, state, pkg_s, module, code)) orelse return field;
    var add: std.ArrayList(u8) = .empty;
    try appendTag(arena, &add, 3, 2);
    try appendVarint(arena, &add, msg.len);
    try add.appendSlice(arena, msg);
    const new_body = try rebuild(arena, body, &.{ 4, 2, 4 }, add.items);
    var out: std.ArrayList(u8) = .empty;
    try appendTag(arena, &out, f.number, 2);
    try appendVarint(arena, &out, new_body.len);
    try out.appendSlice(arena, new_body);
    return out.items;
}

pub fn sub(msg: []const u8, number: u32) ?[]const u8 {
    var r = proto.Reader.init(msg);
    while (r.next() catch return null) |f| if (f.number == number and f.wire == 2) return f.data;
    return null;
}

fn appendVarint(arena: Allocator, out: *std.ArrayList(u8), v0: u64) Allocator.Error!void {
    var v = v0;
    while (v >= 0x80) : (v >>= 7) try out.append(arena, @as(u8, @truncate(v)) | 0x80);
    try out.append(arena, @truncate(v));
}

fn appendTag(arena: Allocator, out: *std.ArrayList(u8), number: u32, wire: u3) Allocator.Error!void {
    try appendVarint(arena, out, (@as(u64, number) << 3) | wire);
}

/// `msg` with `extra` appended to the nested message at `path` (first occurrence at each level).
fn rebuild(arena: Allocator, msg: []const u8, path: []const u32, extra: []const u8) ![]const u8 {
    if (path.len == 0) {
        const out = try arena.alloc(u8, msg.len + extra.len);
        @memcpy(out[0..msg.len], msg);
        @memcpy(out[msg.len..], extra);
        return out;
    }
    var out: std.ArrayList(u8) = .empty;
    var r = proto.Reader.init(msg);
    var start: usize = 0;
    var done = false;
    while (try r.next()) |f| {
        if (!done and f.number == path[0] and f.wire == 2) {
            done = true;
            const inner = try rebuild(arena, f.data, path[1..], extra);
            try appendTag(arena, &out, f.number, 2);
            try appendVarint(arena, &out, inner.len);
            try out.appendSlice(arena, inner);
        } else try out.appendSlice(arena, msg[start..r.pos]);
        start = r.pos;
    }
    return out.items;
}

fn parseAddr(s: []const u8) ?Id {
    // sui_sdk_types::Address::from_str: 0x + 1..64 hex digits (zero-padded on the left)
    if (s.len < 3 or s.len > 66 or s[0] != '0' or s[1] != 'x') return null;
    var buf: [64]u8 = @splat('0');
    const digits = s[2..];
    @memcpy(buf[64 - digits.len ..], digits);
    var id: Id = undefined;
    _ = std.fmt.hexToBytes(&id, &buf) catch return null;
    return id;
}

/// `CleverError` message bytes for an abort in `module` of package `pkg_s`, or null
/// (`render` in render.rs returns None).
fn resolve(arena: Allocator, e: *const sim.Engine, env: *const root.EpochEnv, state: state_mod.State, pkg_s: []const u8, module: []const u8, code: u64) !?[]const u8 {
    // ErrorBitset::from_u64: version nibble 0b1000 or 0b1100
    const version: u8 = @truncate(code >> 60);
    if (version != 0b1000 and version != 0b1100) return null;
    const error_code_raw: u8 = @truncate(code >> 48);
    const line: u16 = @truncate(code >> 32);
    const ident_idx: u16 = @truncate(code >> 16);
    const const_idx: u16 = @truncate(code);
    const id = parseAddr(pkg_s) orelse return null;
    const raw = blk: {
        if (state.latest(&id)) |r| break :blk r;
        if (e.pkgs.get(&id, env.epoch)) |r| break :blk r;
        return null;
    };
    var pkg: serve.movepkg.Package = undefined;
    serve.movepkg.read(arena, raw, &pkg) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    var cm: ?*const mf.file_format.CompiledModule = null;
    for (pkg.mods) |*md| if (std.mem.eql(u8, md.name, module)) {
        cm = &md.cm;
        break;
    };
    const mod = cm orelse return null;
    if (line == 0xffff) return null;
    const error_code: ?u8 = if (version == 0b1000 or error_code_raw == 0xff) null else error_code_raw;
    const has_ident = ident_idx != 0xffff;
    const has_const = const_idx != 0xffff;

    var out: std.ArrayList(u8) = .empty;
    if (error_code) |c| {
        try appendTag(arena, &out, 1, 0);
        try appendVarint(arena, &out, c);
    }
    try appendTag(arena, &out, 2, 0);
    try appendVarint(arena, &out, line);
    if (!has_ident and !has_const) return out.items;
    if (!has_ident or !has_const) return null;
    if (ident_idx >= mod.constant_pool.len or const_idx >= mod.constant_pool.len) return null;
    const ic = mod.constant_pool[ident_idx];
    const vc = mod.constant_pool[const_idx];
    if (!isVecU8(ic.type_)) return null;
    const ident = bcsBytes(ic.data) orelse return null;
    if (!std.unicode.utf8ValidateSlice(ident)) return null;
    try appendTag(arena, &out, 3, 2);
    try appendVarint(arena, &out, ident.len);
    try out.appendSlice(arena, ident);
    if (try renderConstant(arena, vc)) |s| {
        try appendTag(arena, &out, 5, 2);
        try appendVarint(arena, &out, s.len);
        try out.appendSlice(arena, s);
    } else {
        try appendTag(arena, &out, 6, 2);
        try appendVarint(arena, &out, vc.data.len);
        try out.appendSlice(arena, vc.data);
    }
    return out.items;
}

fn isVecU8(t: mf.file_format.Token) bool {
    return t.len == 2 and t[0].tag == .Vector and t[1].tag == .U8;
}

/// `bcs::from_bytes::<Vec<u8>>`: a ULEB length then exactly that many bytes.
fn bcsBytes(data: []const u8) ?[]const u8 {
    var r = bcs.Reader.init(data);
    const n = r.length() catch return null;
    const b = r.bytes(n) catch return null;
    r.finish() catch return null;
    return b;
}

fn fixedInt(comptime T: type, data: []const u8) ?T {
    if (data.len != @sizeOf(T)) return null;
    return std.mem.readInt(T, data[0..@sizeOf(T)], .little);
}

/// move-command-line-common `try_render_constant`.
fn renderConstant(arena: Allocator, c: mf.file_format.Constant) !?[]const u8 {
    const t = c.type_;
    if (t.len == 0) return null;
    if (isVecU8(t)) {
        const b = bcsBytes(c.data) orelse return null;
        if (!std.unicode.utf8ValidateSlice(b)) return null;
        return b;
    }
    if (t.len != 1) return null;
    return switch (t[0].tag) {
        .U8 => if (fixedInt(u8, c.data)) |v| try std.fmt.allocPrint(arena, "{d}", .{v}) else null,
        .U16 => if (fixedInt(u16, c.data)) |v| try std.fmt.allocPrint(arena, "{d}", .{v}) else null,
        .U32 => if (fixedInt(u32, c.data)) |v| try std.fmt.allocPrint(arena, "{d}", .{v}) else null,
        .U64 => if (fixedInt(u64, c.data)) |v| try std.fmt.allocPrint(arena, "{d}", .{v}) else null,
        .U128 => if (fixedInt(u128, c.data)) |v| try std.fmt.allocPrint(arena, "{d}", .{v}) else null,
        .U256 => if (fixedInt(u256, c.data)) |v| try std.fmt.allocPrint(arena, "{d}", .{v}) else null,
        .Bool => if (c.data.len == 1 and c.data[0] <= 1) (if (c.data[0] == 1) "true" else "false") else null,
        .Address => if (c.data.len == 32) try std.fmt.allocPrint(arena, "0x{s}", .{&std.fmt.bytesToHex(c.data[0..32].*, .lower)}) else null,
        else => null,
    };
}

test "rebuild appends into a nested message" {
    const a = std.testing.allocator;
    var arena_s = std.heap.ArenaAllocator.init(a);
    defer arena_s.deinit();
    const arena = arena_s.allocator();
    // { 1: 5, 4: { 2: { 4: { 1: 7 } } } }
    const msg = [_]u8{ 0x08, 0x05, 0x22, 0x06, 0x12, 0x04, 0x22, 0x02, 0x08, 0x07 };
    const out = try rebuild(arena, &msg, &.{ 4, 2, 4 }, &.{ 0x1a, 0x00 });
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0x05, 0x22, 0x08, 0x12, 0x06, 0x22, 0x04, 0x08, 0x07, 0x1a, 0x00 }, out);
}
