//! LedgerService.ListCheckpoints / ListTransactions / ListEvents (sui-rpc-api 1.83.1
//! `grpc/v2/ledger_service/list_*.rs`, `chunked_scan.rs`, `event_scan.rs`, `ledger_read.rs`,
//! `ledger_history/filter.rs`) over the `history` index (src/history) and the store. Chunking,
//! budgets and limits follow the fullnode.yaml values of a production node (rpc.ledger-history: the
//! built-in defaults except list-checkpoints max 100). Streams are written as one gRPC message
//! per frame; frames, watermarks and terminals match sui-node's.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const history = @import("history");
/// The transaction row an event renders from (`writeListEvent`).
pub const Row = history.TxRow;
const h2 = @import("h2/root.zig");
const proto = @import("proto.zig");
const mask = @import("mask.zig");
const b58 = @import("b58.zig");
const status = @import("status.zig");
const typestr = @import("typestr.zig");
const schema = @import("schema.zig");
const ro = @import("render_object.zig");
const movelayout = @import("movelayout.zig");
const render_checkpoint = @import("render_checkpoint.zig");
const ledger = @import("ledger.zig");
const service = @import("service.zig");
const core = @import("lh_core.zig");
const scan = @import("lh_scan.zig");
const clever = @import("clever.zig");
const exec_error = @import("exec_error.zig");
const pbvalue = @import("pbvalue.zig");
const warm = @import("warm.zig");

const Pos = core.Pos;
const Point = core.Point;
const Position = core.Position;
const Options = core.Options;
const Watermark = core.Watermark;
const fail = core.fail;

/// rpc.ledger-history (fullnode.yaml on a production node).
pub const Limits = struct {
    timeout_ms: u64 = 5000,
    default_limit: u32,
    max_limit: u32,
    chunk_max: usize,
};
pub const Config = struct {
    transactions: Limits = .{ .default_limit = 50, .max_limit = 500, .chunk_max = 32 },
    events: Limits = .{ .default_limit = 50, .max_limit = 1000, .chunk_max = 32 },
    checkpoints: Limits = .{ .default_limit = 10, .max_limit = 50, .chunk_max = 16 }, // rpc_config.rs list_checkpoints
    bitmap_bucket_scan_budget: usize = 1024,
    chunk_bucket_scan_budget: usize = 256,
    max_filter_literals: usize = 10,
};

pub const Method = enum { checkpoints, transactions, events };

pub fn methodOf(name: []const u8) ?Method {
    if (std.mem.eql(u8, name, "ListCheckpoints")) return .checkpoints;
    if (std.mem.eql(u8, name, "ListTransactions")) return .transactions;
    if (std.mem.eql(u8, name, "ListEvents")) return .events;
    return null;
}

const Err = error{ Rpc, OutOfMemory, Malformed, Unsupported, NoSpace, Internal } || anyerror;

// ---------------------------------------------------------------- context

fn nowNs() i128 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

/// Where the frames go: the response stream (or a test's collector).
pub const Sink = struct {
    ctx: *anyopaque,
    send: *const fn (ctx: *anyopaque, bytes: []const u8) anyerror!void,
    cancelled: *const fn (ctx: *anyopaque) bool,

    fn ofStream(rs: *h2.ResponseStream) Sink {
        const S = struct {
            fn send(p: *anyopaque, b: []const u8) anyerror!void {
                const r: *h2.ResponseStream = @ptrCast(@alignCast(p));
                return r.message(b);
            }
            fn cancelled(p: *anyopaque) bool {
                const r: *h2.ResponseStream = @ptrCast(@alignCast(p));
                return r.cancelled();
            }
        };
        return .{ .ctx = rs, .send = S.send, .cancelled = S.cancelled };
    }
};

/// Per-request memory: the request arena holds what outlives a chunk; a chunk arena (scan hits,
/// rows, watermark frames) is reset once the chunk's frames are sent; two item arenas taken in
/// turn hold one item's decoded data and frame (a frame is held back one item, for the
/// ItemLimit end mark).
const Mem = struct {
    chunk: std.heap.ArenaAllocator,
    items: [2]std.heap.ArenaAllocator,

    fn init() Mem {
        const pa = std.heap.page_allocator;
        return .{ .chunk = .init(pa), .items = .{ .init(pa), .init(pa) } };
    }
    fn deinit(m: *Mem) void {
        m.chunk.deinit();
        for (&m.items) |*a| a.deinit();
    }
};

const Ctx = struct {
    arena: Allocator,
    mem: *Mem,
    item_turn: u1 = 0,
    /// null in unit tests (no store-side floor, nothing rendered from the store).
    svc: ?*service.Service,
    ix: *history.Index,
    /// The index read view: held only around index work (resolve, scans, row lookups), never
    /// while a frame is rendered or written, so a slow client or a long request never holds
    /// back the writer (every checkpoint commit takes the index's exclusive lock).
    rd: ?history.Reader = null,
    snap: ?*store.Snapshot,
    cfg: *const Config,
    hi_excl: u64 = 0,
    floor: u64 = 0,
    rs: ?*h2.ResponseStream,
    sink: Sink,
    deadline_ns: i128,
    op: []const u8 = "",
    universe: ?[]const u32 = null,
    held: ?Frame = null,
    covered: ?u64 = null,
    /// ZUI_LH_PROF=1: per-request stage times, logged when the request ends.
    prof_index_ns: u64 = 0,
    prof_render_ns: u64 = 0,
    prof_send_ns: u64 = 0,
    prof_items: u64 = 0,
    prof_warm: u64 = 0,

    fn lock(c: *Ctx) void {
        std.debug.assert(c.rd == null);
        c.rd = c.ix.reader();
        // Retention can raise the floor between two sections: rows that vanished below it are
        // then reported below the floor (Rust's `missing_row_error`), not as missing.
        if (c.rd.?.range()) |rg| c.floor = @max(c.floor, @max(rg.lo, if (c.svc) |s| service.lowestOf(s) else 0));
    }
    fn unlock(c: *Ctx) void {
        if (c.rd) |*r| r.release();
        c.rd = null;
    }
    fn reader(c: *Ctx) *history.Reader {
        return &c.rd.?;
    }
    fn chunkArena(c: *Ctx) Allocator {
        return c.mem.chunk.allocator();
    }
    /// The arena for the next item (the one before the previous item is free again).
    fn itemArena(c: *Ctx) Allocator {
        c.item_turn +%= 1;
        const a = &c.mem.items[c.item_turn];
        _ = a.reset(.{ .retain_with_limit = 8 << 20 });
        return a.allocator();
    }
    fn setMessage(c: *Ctx, text: []const u8) void {
        if (c.rs) |rs| rs.setMessage(text);
    }
    /// Between items and chunks: client cancellation, and the 5 s budget, which (as sui-node's
    /// `with_deadline`) covers producing and sending.
    fn check(c: *Ctx) Err!void {
        if (c.sink.cancelled(c.sink.ctx)) return error.Cancelled;
        if (nowNs() > c.deadline_ns) {
            c.setMessage(std.fmt.allocPrint(c.arena, "{s} request deadline exceeded", .{c.op}) catch "request deadline exceeded");
            return error.Deadline;
        }
    }
    /// One frame out. A deadline reached while the frame waits for the client (flow control)
    /// ends the request like `check` does.
    fn send(c: *Ctx, bytes: []const u8) Err!void {
        const t0 = service.profNs();
        defer c.prof_send_ns += service.profNs() - t0;
        c.sink.send(c.sink.ctx, bytes) catch |e| {
            if (e == error.Deadline) c.setMessage(std.fmt.allocPrint(c.arena, "{s} request deadline exceeded", .{c.op}) catch "request deadline exceeded");
            return e;
        };
    }
    /// Sends the previously held frame and holds `f`.
    fn emit(c: *Ctx, f: Frame) Err!void {
        std.debug.assert(c.rd == null);
        if (f.wm_cp) |cp| c.covered = cp;
        if (c.held) |h| try c.send(h.bytes);
        c.held = f;
        try c.check();
    }
    /// End of a chunk: the held frame goes out, with the ItemLimit end when it is the last one.
    fn flushHeld(c: *Ctx, item_limit: bool) Err!void {
        const h = c.held orelse return;
        c.held = null;
        const bytes = if (h.data and item_limit) try endBytes(c.chunkArena(), h.bytes, .item_limit) else h.bytes;
        try c.send(bytes);
    }

    /// `checkpoint_to_tx_boundary`: the first tx_seq of checkpoint `cp`.
    fn boundary(c: *Ctx, cp: u64) error{Rpc}!u64 {
        if (cp == 0) return 0;
        if (c.reader().checkpointTxs(cp - 1)) |t| return t.first + t.count;
        if (c.reader().checkpointTxs(cp)) |t| return t.first;
        if (cp < c.floor) return fail(.{ .below_floor = c.floor });
        return fail(.{ .internal = std.fmt.allocPrint(c.arena, "missing checkpoint {d} while resolving tx boundary", .{cp - 1}) catch "missing checkpoint" });
    }
    fn boundaryFn(c: *Ctx, cp: u64) error{Rpc}!u64 {
        return c.boundary(cp);
    }
    fn floorTx(c: *Ctx) error{Rpc}!u64 {
        return c.boundary(c.floor);
    }
    fn row(c: *Ctx, tx_seq: u64) error{Rpc}!history.TxRow {
        if (c.reader().txRow(tx_seq)) |r| return r;
        const ftx = c.floorTx() catch 0;
        if (tx_seq < ftx) return fail(.{ .below_floor = c.floor });
        return fail(.{ .internal = std.fmt.allocPrint(c.arena, "missing tx_seq_digest row for tx_seq {d}", .{tx_seq}) catch "missing tx_seq_digest row" });
    }
};

fn explicitLower(start_cp: ?u64, o: *const Options) bool {
    return start_cp != null or o.after != null;
}

/// `reject_window_below_serving_floor`.
fn rejectWindowBelowFloor(c: *Ctx, cp: core.CpRange, start_cp: ?u64, o: *const Options) error{Rpc}!void {
    if (cp.isEmpty() or explicitLower(start_cp, o)) return;
    if (cp.e <= c.floor) return fail(.{ .below_floor = c.floor });
}

/// `serving_floor_error_or`.
fn floorErrorOr(c: *Ctx, start_cp: ?u64, o: *const Options, e: anyerror) anyerror {
    const s = start_cp orelse return e;
    if (o.after != null) return e;
    if (s < c.floor) return fail(.{ .below_floor = c.floor });
    return e;
}

// ---------------------------------------------------------------- frames

const Frame = struct { bytes: []const u8, wm_cp: ?u64, data: bool };

/// Renders one frame (item + watermark). The buffer grows only when the frame writer itself ran
/// out of room, sized from what the failed write needed; any other NoSpace is an error, never
/// a retry.
fn writeFrame(arena: Allocator, item_field_hint: usize, item: anytype, comptime renderItem: anytype, wm: Watermark) ![]const u8 {
    var cap: usize = @max(item_field_hint + 256, 1024);
    while (true) {
        const buf = try arena.alloc(u8, cap);
        var w = proto.Writer.init(buf);
        const ok = blk: {
            renderItem(item, &w) catch |e| break :blk e;
            wm.write(&w, 2) catch |e| break :blk e;
            break :blk {};
        };
        if (ok) |_| return w.bytesWritten() else |e| {
            if (@as(anyerror, e) != error.NoSpace) return e;
            cap = w.retryCap() orelse return error.Internal;
            arena.free(buf);
        }
    }
}

fn noItem(_: void, _: *proto.Writer) !void {}

fn watermarkFrame(arena: Allocator, wm: Watermark) !Frame {
    return .{ .bytes = try writeFrame(arena, 0, {}, noItem, wm), .wm_cp = wm.checkpoint, .data = false };
}

fn endBytes(arena: Allocator, frame: []const u8, reason: core.EndReason) ![]const u8 {
    const out = try arena.alloc(u8, frame.len + 4);
    @memcpy(out[0..frame.len], frame);
    out[frame.len] = (3 << 3) | 2;
    out[frame.len + 1] = 2;
    out[frame.len + 2] = 1 << 3;
    out[frame.len + 3] = @intFromEnum(reason);
    return out;
}

// ---------------------------------------------------------------- chunked scan driver

const ChunkDone = struct {
    produced: usize,
    more: bool,
    terminal: core.Terminal,
    remaining_budget: usize,
};

/// `ChunkedScan` + the per-method stream body: each chunk emits its frames as it renders them
/// (`Ctx.emit`), then the terminal frame or error follows. Chunk memory is dropped once the
/// chunk's frames are out.
fn drive(c: *Ctx, limit: usize, chunk_max: usize, state: anytype, comptime chunk: anytype, op: []const u8) Err!void {
    c.op = op;
    var produced: usize = 0;
    var budget: usize = c.cfg.bitmap_bucket_scan_budget;
    var terminal: core.Terminal = undefined;
    var remaining = limit;
    while (true) {
        try c.check();
        const d: ChunkDone = try chunk(c, state, budget, @min(chunk_max, remaining), remaining);
        std.debug.assert(c.rd == null);
        terminal = d.terminal;
        budget = d.remaining_budget;
        produced += d.produced;
        const spawn_next = produced < limit and d.more;
        try c.flushHeld(!spawn_next and produced == limit);
        if (!spawn_next) break;
        _ = c.mem.chunk.reset(.{ .retain_with_limit = 8 << 20 });
        remaining = limit - produced;
    }
    if (produced == limit) return;
    const reason = terminal.reason() orelse {
        const f = try watermarkFrame(c.chunkArena(), terminal.intoWatermark(c.covered));
        try c.send(f.bytes);
        return fail(.{ .below_floor = terminal.serving_floor.floor });
    };
    const f = try watermarkFrame(c.chunkArena(), terminal.intoWatermark(c.covered));
    try c.send(try endBytes(c.chunkArena(), f.bytes, reason));
}

// ---------------------------------------------------------------- filters (filter.rs)

const Lit = struct { neg: bool, key: []const u8, affected_addr: ?[32]u8 = null };

fn hexNibble(ch: u8) ?u8 {
    return switch (ch) {
        '0'...'9' => ch - '0',
        'a'...'f' => ch - 'a' + 10,
        'A'...'F' => ch - 'A' + 10,
        else => null,
    };
}

/// sui-types `SuiAddress::from_str` (`decode_bytes_hex`: optional 0x, exactly 32 bytes).
fn parseAddress(arena: Allocator, text: []const u8, field: []const u8) error{Rpc}![32]u8 {
    const s = if (std.mem.startsWith(u8, text, "0x")) text[2..] else text;
    var out: [32]u8 = undefined;
    if (s.len != 64) return fail(.{ .field = .{ .field = field, .description = std.fmt.allocPrint(arena, "invalid address: Invalid string length", .{}) catch "invalid address" } });
    for (0..32) |i| {
        const hi = hexNibble(s[2 * i]) orelse return fail(.{ .field = .{ .field = field, .description = "invalid address: Invalid character" } });
        const lo = hexNibble(s[2 * i + 1]) orelse return fail(.{ .field = .{ .field = field, .description = "invalid address: Invalid character" } });
        out[i] = hi << 4 | lo;
    }
    return out;
}

/// `ObjectID::from_str`: a 0x literal of 1 to 64 digits (left-padded), or 64 plain digits.
fn parseObjectIdText(text: []const u8, field: []const u8) error{Rpc}![32]u8 {
    // ObjectID::from_str: 64 hex digits, or a 0x literal of up to 64 (zero-padded, "0x" is zero);
    // every failure ends in from_hex_literal's HexLiteralPrefixMissing.
    const bad = "invalid object_id: ObjectID hex literal must start with 0x";
    var s = text;
    const lit = std.mem.startsWith(u8, s, "0x");
    if (lit) s = s[2..];
    if (s.len > 64 or (!lit and s.len != 64)) return fail(.{ .field = .{ .field = field, .description = bad } });
    var out: [32]u8 = @splat(0);
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const d = hexNibble(s[s.len - 1 - i]) orelse return fail(.{ .field = .{ .field = field, .description = bad } });
        out[31 - i / 2] |= if (i % 2 == 0) d else d << 4;
    }
    return out;
}

fn dimKey(arena: Allocator, tag: u8, parts: []const []const u8) ![]const u8 {
    var n: usize = 1;
    for (parts) |p| n += p.len;
    const k = try arena.alloc(u8, n);
    k[0] = tag;
    var at: usize = 1;
    for (parts) |p| {
        @memcpy(k[at..][0..p.len], p);
        at += p.len;
    }
    return k;
}

fn movePath(arena: Allocator, tag: u8, text: []const u8, max_parts: usize, field: []const u8, expect: []const u8) Err![]const u8 {
    var parts: [4][]const u8 = undefined;
    var np: usize = 0;
    var it = std.mem.splitSequence(u8, text, "::");
    while (it.next()) |p| {
        if (np == max_parts) return fail(.{ .field = .{ .field = field, .description = expect } });
        parts[np] = p;
        np += 1;
    }
    const addr = try parseAddress(arena, parts[0], field);
    var pieces: [5][]const u8 = undefined;
    var n: usize = 0;
    pieces[n] = try arena.dupe(u8, &addr);
    n += 1;
    if (np > 1) {
        pieces[n] = parts[1];
        n += 1;
        if (np > 2) {
            pieces[n] = "\x00";
            pieces[n + 1] = parts[2];
            n += 2;
        }
    }
    return dimKey(arena, tag, pieces[0..n]);
}

fn eventTypeKey(arena: Allocator, text: []const u8, field: []const u8) Err![]const u8 {
    const lt = std.mem.indexOfScalar(u8, text, '<');
    const head = if (lt) |i| text[0..i] else text;
    var parts: [3][]const u8 = undefined;
    var np: usize = 0;
    var it = std.mem.splitSequence(u8, head, "::");
    while (it.next()) |p| {
        if (np == 3) return fail(.{ .field = .{ .field = field, .description = "expected `address[::module[::Name[<type_params>]]]`" } });
        parts[np] = p;
        np += 1;
    }
    const addr = try parseAddress(arena, parts[0], field);
    if (lt != null and np < 3) return fail(.{ .field = .{ .field = field, .description = "generic instantiation requires a type name" } });
    var pieces: [6][]const u8 = undefined;
    var n: usize = 0;
    pieces[n] = try arena.dupe(u8, &addr);
    n += 1;
    if (np > 1) {
        pieces[n] = parts[1];
        n += 1;
        if (np > 2) {
            pieces[n] = "\x00";
            pieces[n + 1] = parts[2];
            n += 2;
            if (lt != null) {
                var tp = TypeParser{ .s = text, .arena = arena };
                const params = tp.structParams() catch |e| return fail(.{ .field = .{ .field = field, .description = if (e == error.TypeLimit) TypeParser.limit_text else "invalid type" } });
                pieces[n] = "\x00";
                pieces[n + 1] = params;
                n += 2;
            }
        }
    }
    return dimKey(arena, 6, pieces[0..n]);
}

/// A Move type-tag parser that produces the BCS of a struct tag's `type_params` (Vec<TypeTag>),
/// enough for `parse_sui_type_tag` on event filter strings. Depth and node count are capped as
/// move-core-types' parser does (`MAX_TYPE_DEPTH` 128, `MAX_TYPE_NODE_COUNT` 256, the top-level
/// type at depth 0), so a client-supplied `vector<vector<...` cannot run the recursion (and the
/// connection thread's stack) out; past the caps the error is sui-node's text.
const TypeParser = struct {
    s: []const u8,
    i: usize = 0,
    arena: Allocator,
    out: std.ArrayList(u8) = .empty,
    /// Type nodes parsed so far (the top-level struct counts).
    count: u64 = 0,

    const max_depth: u64 = 128;
    const max_nodes: u64 = 256;
    const limit_text = "invalid type: Type exceeds maximum nesting depth or node count";

    fn ws(p: *TypeParser) void {
        while (p.i < p.s.len and p.s[p.i] == ' ') p.i += 1;
    }
    fn isAt(p: *TypeParser, ch: u8) bool {
        p.ws();
        return p.i < p.s.len and p.s[p.i] == ch;
    }
    fn ident(p: *TypeParser) ![]const u8 {
        p.ws();
        const st = p.i;
        while (p.i < p.s.len and (std.ascii.isAlphanumeric(p.s[p.i]) or p.s[p.i] == '_')) p.i += 1;
        if (p.i == st) return error.Bad;
        return p.s[st..p.i];
    }
    fn uleb(p: *TypeParser, v: usize) !void {
        var x = v;
        while (x >= 0x80) : (x >>= 7) try p.out.append(p.arena, @as(u8, @truncate(x)) | 0x80);
        try p.out.append(p.arena, @truncate(x));
    }
    fn expect(p: *TypeParser, lit: []const u8) !void {
        p.ws();
        if (!std.mem.startsWith(u8, p.s[p.i..], lit)) return error.Bad;
        p.i += lit.len;
    }
    /// `parse_type_impl`'s entry check.
    fn node(p: *TypeParser, depth: u64) !void {
        p.count += 1;
        if (depth > max_depth or p.count > max_nodes) return error.TypeLimit;
    }
    /// Parses `addr::mod::Name<...>` at the start and returns the BCS of its type params.
    fn structParams(p: *TypeParser) ![]const u8 {
        try p.node(0);
        _ = try p.ident();
        try p.expect("::");
        _ = try p.ident();
        try p.expect("::");
        _ = try p.ident();
        try p.params(1);
        p.ws();
        if (p.i != p.s.len) return error.Bad;
        return p.out.items;
    }
    /// `parse_type_args_impl`: `<T, ...>` (a trailing comma is accepted, an empty list is not);
    /// no `<` is an empty list.
    fn params(p: *TypeParser, depth: u64) anyerror!void {
        if (!p.isAt('<')) {
            try p.uleb(0);
            return;
        }
        p.i += 1;
        var tags: std.ArrayList([]const u8) = .empty;
        while (!p.isAt('>')) {
            var sub = TypeParser{ .s = p.s, .i = p.i, .arena = p.arena, .count = p.count };
            try sub.tag(depth);
            p.i = sub.i;
            p.count = sub.count;
            try tags.append(p.arena, sub.out.items);
            if (p.isAt('>')) break;
            try p.expect(",");
        }
        try p.expect(">");
        if (tags.items.len == 0) return error.Bad;
        try p.uleb(tags.items.len);
        for (tags.items) |t| try p.out.appendSlice(p.arena, t);
    }
    fn tag(p: *TypeParser, depth: u64) anyerror!void {
        try p.node(depth);
        const id = try p.ident();
        const prims = [_]struct { []const u8, u8 }{ .{ "bool", 0 }, .{ "u8", 1 }, .{ "u64", 2 }, .{ "u128", 3 }, .{ "address", 4 }, .{ "signer", 5 }, .{ "u16", 8 }, .{ "u32", 9 }, .{ "u256", 10 } };
        p.ws();
        const is_path = p.i + 1 < p.s.len and p.s[p.i] == ':' and p.s[p.i + 1] == ':';
        if (!is_path) {
            for (prims) |pr| if (std.mem.eql(u8, id, pr[0])) return p.out.append(p.arena, pr[1]);
            if (std.mem.eql(u8, id, "vector")) {
                try p.out.append(p.arena, 6);
                try p.expect("<");
                try p.tag(depth + 1);
                try p.expect(">");
                return;
            }
            return error.Bad;
        }
        try p.out.append(p.arena, 7);
        try p.out.appendSlice(p.arena, &(try addressOf(id)));
        try p.expect("::");
        const m = try p.ident();
        try p.uleb(m.len);
        try p.out.appendSlice(p.arena, m);
        try p.expect("::");
        const nm = try p.ident();
        try p.uleb(nm.len);
        try p.out.appendSlice(p.arena, nm);
        try p.params(depth + 1);
    }
    /// A 0x literal, plain hex, or one of sui's named addresses (`resolve_address`).
    fn addressOf(id: []const u8) ![32]u8 {
        const named = [_]struct { []const u8, []const u8 }{ .{ "deepbook", "dee9" }, .{ "std", "1" }, .{ "sui", "2" }, .{ "sui_system", "3" }, .{ "bridge", "b" } };
        var hex = if (std.mem.startsWith(u8, id, "0x")) id[2..] else id;
        if (!std.mem.startsWith(u8, id, "0x")) for (named) |n| if (std.mem.eql(u8, id, n[0])) {
            hex = n[1];
        };
        if (hex.len == 0 or hex.len > 64) return error.Bad;
        var addr: [32]u8 = @splat(0);
        for (0..hex.len) |k| {
            const d = hexNibble(hex[hex.len - 1 - k]) orelse return error.Bad;
            addr[31 - k / 2] |= if (k % 2 == 0) d else d << 4;
        }
        return addr;
    }
};

test "TypeParser: nesting past move-core-types' caps is a field error, not a stack overflow" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const field = "filter.terms.literals.event_type.event_type";
    const head = "0x0000000000000000000000000000000000000000000000000000000000000002::m::S<";
    // 3 MB of `vector<` (~430k levels): rejected at depth 129 without recursing further.
    const levels = 430_000;
    var deep: std.ArrayList(u8) = .empty;
    try deep.appendSlice(a, head);
    for (0..levels) |_| try deep.appendSlice(a, "vector<");
    try deep.appendSlice(a, "u8");
    for (0..levels + 1) |_| try deep.append(a, '>');
    try std.testing.expectError(error.Rpc, eventTypeKey(a, deep.items, field));
    const f = core.takeFailure();
    try std.testing.expectEqualStrings(TypeParser.limit_text, f.field.description);
    // depth: the top struct is 0, its argument 1; 127 nested vectors put u8 at 128 (allowed), 128 at 129
    for ([_]struct { usize, bool }{ .{ 127, true }, .{ 128, false } }) |case| {
        var t: std.ArrayList(u8) = .empty;
        try t.appendSlice(a, head);
        for (0..case[0]) |_| try t.appendSlice(a, "vector<");
        try t.appendSlice(a, "u8");
        for (0..case[0] + 1) |_| try t.append(a, '>');
        if (case[1]) {
            _ = try eventTypeKey(a, t.items, field);
        } else {
            try std.testing.expectError(error.Rpc, eventTypeKey(a, t.items, field));
            _ = core.takeFailure();
        }
    }
    // node count: 255 arguments + the top struct = 256 nodes (allowed), 256 arguments = 257
    for ([_]struct { usize, bool }{ .{ 255, true }, .{ 256, false } }) |case| {
        var t: std.ArrayList(u8) = .empty;
        try t.appendSlice(a, head);
        for (0..case[0]) |k| try t.appendSlice(a, if (k == 0) "u8" else ",u8");
        try t.append(a, '>');
        if (case[1]) {
            _ = try eventTypeKey(a, t.items, field);
        } else {
            try std.testing.expectError(error.Rpc, eventTypeKey(a, t.items, field));
            try std.testing.expectEqualStrings(TypeParser.limit_text, core.takeFailure().field.description);
        }
    }
    // named addresses and a trailing comma, as move-core-types parses them
    const k1 = try eventTypeKey(a, "0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<sui::sui::SUI,>", field);
    const k2 = try eventTypeKey(a, "0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x2::sui::SUI>", field);
    try std.testing.expectEqualSlices(u8, k2, k1);
}

fn parseFilterString(sub: []const u8) Err!?[]const u8 {
    var r = proto.Reader.init(sub);
    var v: ?[]const u8 = null;
    while (r.next() catch return error.Malformed) |f| if (f.number == 1) {
        v = proto.Reader.stringOf(f) catch return error.Malformed;
    };
    return v;
}

const field_lit = "filter.terms.literals";

/// One TransactionLiteral / EventLiteral.
fn parseLiteral(arena: Allocator, data: []const u8, events: bool) Err!Lit {
    var neg = false;
    var pred: ?struct { num: u32, sub: []const u8 } = null;
    var r = proto.Reader.init(data);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => neg = (proto.Reader.varintOf(f) catch return error.Malformed) != 0,
        2...9 => pred = .{ .num = f.number, .sub = proto.Reader.bytesOf(f) catch return error.Malformed },
        else => {},
    };
    const p = pred orelse return fail(.{ .field = .{ .field = field_lit, .description = "predicate variant is required", .missing = true } });
    const num: u32 = if (events) switch (p.num) {
        2 => 2,
        3 => 6,
        4 => 7,
        5 => 8,
        else => return fail(.{ .field = .{ .field = field_lit, .description = "unknown predicate variant" } }),
    } else p.num;
    const text = try parseFilterString(p.sub);
    const need = struct {
        fn f(t: ?[]const u8, field: []const u8, what: []const u8) error{Rpc}![]const u8 {
            return t orelse fail(.{ .field = .{ .field = field, .description = what, .missing = true } });
        }
    }.f;
    switch (num) {
        2 => {
            const fld = field_lit ++ ".sender.address";
            const a = try parseAddress(arena, try need(text, fld, "address is required"), fld);
            return .{ .neg = neg, .key = try dimKey(arena, 1, &.{&a}) };
        },
        3 => {
            const fld = field_lit ++ ".affected_address.address";
            const a = try parseAddress(arena, try need(text, fld, "address is required"), fld);
            return .{ .neg = neg, .key = try dimKey(arena, 2, &.{&a}), .affected_addr = a };
        },
        4 => {
            const fld = field_lit ++ ".affected_object.object_id";
            const a = try parseObjectIdText(try need(text, fld, "object_id is required"), fld);
            return .{ .neg = neg, .key = try dimKey(arena, 3, &.{&a}) };
        },
        5 => {
            const fld = field_lit ++ ".move_call.function";
            return .{ .neg = neg, .key = try movePath(arena, 4, try need(text, fld, "function is required"), 3, fld, "expected `package[::module[::function]]`") };
        },
        6 => {
            const fld = field_lit ++ ".emit_module.module";
            return .{ .neg = neg, .key = try movePath(arena, 5, try need(text, fld, "module is required"), 2, fld, "expected `package[::module]`") };
        },
        7 => {
            const fld = field_lit ++ ".event_type.event_type";
            return .{ .neg = neg, .key = try eventTypeKey(arena, try need(text, fld, "type is required"), fld) };
        },
        8 => {
            const fld = field_lit ++ ".event_stream_head.stream_id";
            const a = try parseAddress(arena, try need(text, fld, "stream_id is required"), fld);
            return .{ .neg = neg, .key = try dimKey(arena, 7, &.{&a}) };
        },
        9 => return .{ .neg = neg, .key = "\x0a\x00" },
        else => unreachable,
    }
}

const QB = struct {
    arena: Allocator,
    keys: std.ArrayList([]const u8) = .empty,
    terms: std.ArrayList(scan.Term) = .empty,

    fn idx(b: *QB, key: []const u8) !usize {
        for (b.keys.items, 0..) |k, i| if (std.mem.eql(u8, k, key)) return i;
        try b.keys.append(b.arena, key);
        return b.keys.items.len - 1;
    }
    fn addTerm(b: *QB, lits: []const Lit) !void {
        var inc: std.ArrayList(usize) = .empty;
        var exc: std.ArrayList(usize) = .empty;
        for (lits) |l| try (if (l.neg) &exc else &inc).append(b.arena, try b.idx(l.key));
        try b.terms.append(b.arena, .{ .includes = inc.items, .excludes = exc.items });
    }
};

/// `transaction_filter_to_query` / `event_filter_to_query`.
fn parseFilter(arena: Allocator, data: []const u8, events: bool, max_literals: usize) Err!scan.Query {
    var term_bytes: std.ArrayList([]const u8) = .empty;
    var r = proto.Reader.init(data);
    while (r.next() catch return error.Malformed) |f| if (f.number == 1) try term_bytes.append(arena, proto.Reader.bytesOf(f) catch return error.Malformed);
    if (term_bytes.items.len == 0) return fail(.{ .field = .{ .field = "filter.terms", .description = "at least one filter term is required", .missing = true } });
    var terms: std.ArrayList([]const []const u8) = .empty;
    var total: usize = 0;
    for (term_bytes.items) |tb| {
        var lits: std.ArrayList([]const u8) = .empty;
        var tr = proto.Reader.init(tb);
        while (tr.next() catch return error.Malformed) |f| if (f.number == 1) try lits.append(arena, proto.Reader.bytesOf(f) catch return error.Malformed);
        total += lits.items.len;
        if (total > max_literals) return fail(.{ .field = .{ .field = "filter.terms.literals", .description = try std.fmt.allocPrint(arena, "filter contains {d} literals; at most {d} are allowed", .{ total, max_literals }) } });
        try terms.append(arena, lits.items);
    }
    var qb = QB{ .arena = arena };
    if (!events) {
        // validate_expanded_term_count
        var expanded_total: usize = 0;
        for (terms.items) |lits| {
            var splits: u6 = 0;
            for (lits) |lb| {
                var neg = false;
                var aa = false;
                var lr = proto.Reader.init(lb);
                while (lr.next() catch return error.Malformed) |f| switch (f.number) {
                    1 => neg = (proto.Reader.varintOf(f) catch return error.Malformed) != 0,
                    2...9 => aa = f.number == 3,
                    else => {},
                };
                if (aa and !neg) splits +|= 1;
            }
            if (splits == 0) continue;
            expanded_total +|= if (splits >= 63) std.math.maxInt(usize) else @as(usize, 1) << splits;
            if (expanded_total > 64) return fail(.{ .field = .{ .field = "filter.terms", .description = "affected_address literals expand this filter to more than 64 terms (each non-negated affected_address literal doubles its term because it also matches the transaction sender)" } });
        }
    }
    for (terms.items) |lits| {
        var parsed: std.ArrayList(Lit) = .empty;
        for (lits) |lb| try parsed.append(arena, try parseLiteral(arena, lb, events));
        var has_include = false;
        for (parsed.items) |l| has_include = has_include or !l.neg;
        const anchor: Lit = .{ .neg = false, .key = if (events) "\x08\x00" else "\x09\x00" };
        if (events) {
            var all: std.ArrayList(Lit) = .empty;
            if (!has_include) try all.append(arena, anchor);
            try all.appendSlice(arena, parsed.items);
            try qb.addTerm(all.items);
            continue;
        }
        var expanded: std.ArrayList(std.ArrayList(Lit)) = .empty;
        var first: std.ArrayList(Lit) = .empty;
        if (!has_include) try first.append(arena, anchor);
        try expanded.append(arena, first);
        for (parsed.items) |l| {
            const a = l.affected_addr orelse {
                for (expanded.items) |*t| try t.append(arena, l);
                continue;
            };
            const sender: Lit = .{ .neg = l.neg, .key = try dimKey(arena, 1, &.{&a}) };
            if (l.neg) {
                for (expanded.items) |*t| {
                    try t.append(arena, sender);
                    try t.append(arena, l);
                }
            } else {
                var next: std.ArrayList(std.ArrayList(Lit)) = .empty;
                for (expanded.items) |t| {
                    var with_sender = try t.clone(arena);
                    try with_sender.append(arena, sender);
                    var with_affected = try t.clone(arena);
                    try with_affected.append(arena, l);
                    try next.append(arena, with_sender);
                    try next.append(arena, with_affected);
                }
                expanded = next;
            }
        }
        for (expanded.items) |t| try qb.addTerm(t.items);
    }
    return .{ .keys = qb.keys.items, .terms = qb.terms.items };
}

// ---------------------------------------------------------------- requests

const Req = struct {
    mask_field: std.ArrayList([]const u8) = .empty,
    start_cp: ?u64 = null,
    end_cp: ?u64 = null,
    filter: ?[]const u8 = null,
    options: ?core.RawOptions = null,
    start_tx: ?u64 = null,
    end_tx: ?u64 = null,
    start_ev: ?u32 = null,
    end_ev: ?u32 = null,
};

fn mergeBytes(arena: Allocator, prev: ?[]const u8, data: []const u8) ![]const u8 {
    const p = prev orelse return data;
    return std.mem.concat(arena, u8, &.{ p, data });
}

fn parseRequest(arena: Allocator, m: Method, body: []const u8) Err!Req {
    var q: Req = .{};
    var opt_bytes: ?[]const u8 = null;
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => try q.mask_field.append(arena, proto.Reader.bytesOf(f) catch return error.Malformed),
        2 => q.start_cp = proto.Reader.varintOf(f) catch return error.Malformed,
        3 => q.end_cp = proto.Reader.varintOf(f) catch return error.Malformed,
        4 => q.filter = try mergeBytes(arena, q.filter, proto.Reader.bytesOf(f) catch return error.Malformed),
        5 => opt_bytes = try mergeBytes(arena, opt_bytes, proto.Reader.bytesOf(f) catch return error.Malformed),
        6 => if (m != .checkpoints) {
            q.start_tx = proto.Reader.varintOf(f) catch return error.Malformed;
        },
        7 => if (m == .transactions) {
            q.end_tx = proto.Reader.varintOf(f) catch return error.Malformed;
        } else if (m == .events) {
            q.start_ev = @truncate(proto.Reader.varintOf(f) catch return error.Malformed);
        },
        8 => if (m == .events) {
            q.end_tx = proto.Reader.varintOf(f) catch return error.Malformed;
        },
        9 => if (m == .events) {
            q.end_ev = @truncate(proto.Reader.varintOf(f) catch return error.Malformed);
        },
        else => {},
    };
    if (opt_bytes) |ob| {
        var o: core.RawOptions = .{};
        var orr = proto.Reader.init(ob);
        while (orr.next() catch return error.Malformed) |f| switch (f.number) {
            1 => o.limit = @truncate(proto.Reader.varintOf(f) catch return error.Malformed),
            2 => o.after = proto.Reader.bytesOf(f) catch return error.Malformed,
            3 => o.before = proto.Reader.bytesOf(f) catch return error.Malformed,
            4 => o.ordering = @truncate(@as(i64, @bitCast(proto.Reader.varintOf(f) catch return error.Malformed))),
            else => {},
        };
        q.options = o;
    }
    return q;
}

fn requireWhenSet(required: bool, rname: []const u8, when: bool, wname: []const u8, arena: Allocator) error{Rpc}!void {
    if (when and !required) return fail(.{ .field = .{ .field = rname, .description = std.fmt.allocPrint(arena, "{s} is required when {s} is set", .{ rname, wname }) catch "required", .missing = true } });
}

fn validateMask(arena: Allocator, parts: []const []const u8, default: []const u8, root: i16) Err!mask.Mask {
    if (parts.len == 0) {
        const t = try arena.create(mask.Tree); // the Mask points at it for the whole request
        t.* = try mask.Tree.parse(arena, default);
        return t.mask();
    }
    var paths: std.ArrayList([]const u8) = .empty;
    for (parts) |data| {
        var r = proto.Reader.init(data);
        while (r.next() catch return error.Malformed) |f| {
            if (f.number == 1) try paths.append(arena, proto.Reader.stringOf(f) catch return error.Malformed);
        }
    }
    if (status.invalidPath(root, paths.items)) |p| return fail(.{ .field = .{ .field = "read_mask", .description = try std.fmt.allocPrint(arena, "invalid read_mask path: {s}", .{p}) } });
    const t = try arena.create(mask.Tree);
    t.* = try mask.Tree.fromPaths(arena, paths.items);
    return t.mask();
}

// ---------------------------------------------------------------- entry

/// The service's entry: under a streaming runtime the request is validated here (sui-node
/// validates before it returns the stream: those errors stay trailers-only) and then streamed by
/// a pump (`ListPump`) with flow control, so a response is never held whole in memory; without
/// one (tests, tools) it is answered inline through `rs`.
pub fn callStream(svc: *service.Service, cfg: *const Config, arena: Allocator, m: Method, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    // Without the index the request still validates first, then the stream (already started,
    // its HEADERS out) ends UNAVAILABLE "rpc indexes are disabled", as sui-node's does inside its
    // first chunk (rpc-surface list-checkpoints/noidx-*: not trailers-only).
    if (!h2.streaming()) return call(svc, cfg, arena, m, req.body, rs);
    _ = parse(arena, cfg, m, req.body) catch |e| return failWith(arena, rs, e);
    const j = ListPump.create(svc, cfg, m, req.body) catch return call(svc, cfg, arena, m, req.body, rs);
    if (!h2.attach(req.stream_id, j.pump())) {
        ListPump.done(j);
        return call(svc, cfg, arena, m, req.body, rs);
    }
    return .deferred;
}

/// One List* stream on its own pump thread (h2c) or the connection's thread (gRPC-web). Frames
/// go out as they are rendered; before each one the pump waits while earlier bytes still wait
/// for the client's h2 window (gRPC-web writes block on the socket instead). What one call
/// holds is then bounded by the client's window plus one frame, whatever the response size.
pub const ListPump = struct {
    svc: ?*service.Service,
    cfg: *const Config,
    m: Method,
    body: []u8,
    /// Writes the response through `rs` (the List* call; tests plug their own).
    answer: *const fn (j: *ListPump, arena: Allocator, rs: *h2.ResponseStream) h2.Status = answerList,
    /// Bumped by the runtime on window updates and connection close.
    wakes: std.atomic.Value(u32) = .init(0),

    const gpa = std.heap.page_allocator;

    fn create(svc: ?*service.Service, cfg: *const Config, m: Method, body: []const u8) !*ListPump {
        const j = try gpa.create(ListPump);
        errdefer gpa.destroy(j);
        j.* = .{ .svc = svc, .cfg = cfg, .m = m, .body = try gpa.dupe(u8, body) };
        return j;
    }
    fn answerList(j: *ListPump, arena: Allocator, rs: *h2.ResponseStream) h2.Status {
        return call(j.svc.?, j.cfg, arena, j.m, j.body, rs);
    }
    /// Test hook: a pump that answers with `answer` (see test_transport.zig).
    pub fn attachTest(stream_id: u32, body: []const u8, answer: *const fn (j: *ListPump, arena: Allocator, rs: *h2.ResponseStream) h2.Status) bool {
        const j = create(null, &test_config, .events, body) catch return false;
        j.answer = answer;
        if (!h2.attach(stream_id, j.pump())) {
            done(j);
            return false;
        }
        return true;
    }
    const test_config: Config = .{};
    pub fn requestBody(j: *const ListPump) []const u8 {
        return j.body;
    }
    fn pump(j: *ListPump) h2.Pump {
        return .{ .ctx = j, .run = runFn, .wake = wakeFn, .done = doneFn };
    }
    fn done(j: *ListPump) void {
        gpa.free(j.body);
        gpa.destroy(j);
    }
    fn doneFn(ctx: *anyopaque) void {
        done(@ptrCast(@alignCast(ctx)));
    }
    fn wakeFn(ctx: *anyopaque) void {
        const j: *ListPump = @ptrCast(@alignCast(ctx));
        _ = j.wakes.fetchAdd(1, .release);
    }
    fn runFn(ctx: *anyopaque, link: *h2.Link) void {
        const j: *ListPump = @ptrCast(@alignCast(ctx));
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        var ls: LinkSink = .{ .link = link, .j = j };
        var rs: h2.ResponseStream = .{ .gpa = std.heap.smp_allocator, .impl = &ls, .vt = &LinkSink.vt };
        defer rs.release();
        const st = j.answer(j, arena_state.allocator(), &rs);
        if (st == .ok) link.finish(.ok, "") else link.finishDetails(st, rs.msg, rs.details_bin);
    }
};

/// `ResponseStream` writes of a `ListPump` (identity encoding: the link compresses as the stream
/// negotiated).
const LinkSink = struct {
    link: *h2.Link,
    j: *ListPump,
    /// The request's deadline (`run` sets it): a frame waiting for window past it ends the call.
    deadline_ns: i128 = std.math.maxInt(i128),
    /// Longest wait between two looks at the window (a wake ends a wait early).
    const max_wait_ms = 8;

    fn write(impl: *anyopaque, _: *const [5]u8, payload: []const u8) anyerror!void {
        const ls: *LinkSink = @ptrCast(@alignCast(impl));
        var wait_ms: u64 = 1;
        while (true) {
            const seen = ls.j.wakes.load(.acquire);
            const blocked = ls.link.blocked() orelse return error.Cancelled;
            if (!blocked) break;
            if (nowNs() > ls.deadline_ns) return error.Deadline;
            var slept: u64 = 0;
            while (slept < wait_ms and ls.j.wakes.load(.acquire) == seen) : (slept += 1) h2.sock.sleepMs(1);
            wait_ms = @min(wait_ms * 2, max_wait_ms);
        }
        ls.link.send(payload) catch return error.Cancelled;
    }
    fn cancelled(impl: *anyopaque) bool {
        const ls: *LinkSink = @ptrCast(@alignCast(impl));
        return ls.link.blocked() == null;
    }
    const vt: h2.ResponseStream.VTable = .{ .write = write, .cancelled = cancelled };
};

pub fn call(svc: *service.Service, cfg: *const Config, arena: Allocator, m: Method, body: []const u8, rs: *h2.ResponseStream) h2.Status {
    const ix = svc.history orelse {
        rs.setMessage("rpc indexes are disabled");
        return withDetails(arena, rs, .unavailable);
    };
    var snap = svc.store.snapshot();
    defer snap.release();
    var mem = Mem.init();
    defer mem.deinit();
    run(svc, ix, cfg, arena, &mem, m, body, rs, &snap) catch |e| return failWith(arena, rs, e);
    return .ok;
}

fn withDetails(arena: Allocator, rs: *h2.ResponseStream, code: h2.Status) h2.Status {
    if (rs.details_bin.len == 0) {
        if (status.plain(arena, @intFromEnum(code), rs.msg)) |bin| rs.details(bin) else |_| {}
    }
    return code;
}

fn failWith(arena: Allocator, rs: *h2.ResponseStream, e: anyerror) h2.Status {
    switch (e) {
        error.Rpc => return reportFailure(arena, rs, core.takeFailure()),
        error.Malformed => {
            rs.setMessage("failed to decode Protobuf message");
            return .internal;
        },
        error.Unsupported => {
            rs.setMessage("read_mask selects a field this server does not render yet");
            return .unimplemented;
        },
        error.Deadline => return withDetails(arena, rs, .deadline_exceeded),
        error.Cancelled => {
            rs.setMessage("request cancelled");
            return .cancelled;
        },
        error.Unfiltered => {
            rs.setMessage("filtered ListCheckpoints is not served yet");
            return .unimplemented;
        },
        else => {
            if (rs.msg.len == 0) rs.setMessage("internal error");
            return withDetails(arena, rs, .internal);
        },
    }
}

fn reportFailure(arena: Allocator, rs: *h2.ResponseStream, f: core.Failure) h2.Status {
    switch (f) {
        .field => |v| {
            const bin = status.badRequest(arena, 3, v.field, v.description, if (v.missing) .field_missing else .field_invalid) catch "";
            rs.setMessage(v.description);
            rs.details(bin);
            return .invalid_argument;
        },
        .below_floor => |floor| {
            const msg = std.fmt.allocPrint(arena, "requested data below earliest available; lowest available checkpoint is {d}", .{floor}) catch "below earliest available";
            const fl = std.fmt.allocPrint(arena, "{d}", .{floor}) catch "";
            rs.setMessage(msg);
            rs.details(errorInfo(arena, 11, msg, "BELOW_EARLIEST_AVAILABLE", &.{.{ "lowestAvailableCheckpoint", fl }}) catch "");
            return .out_of_range;
        },
        .above_latest => |a| {
            const msg = if (std.mem.eql(u8, a.bound, "cursor"))
                std.fmt.allocPrint(arena, "requested data above latest available; cursor is at checkpoint {d}, and only checkpoints below {d} are available", .{ a.requested, a.hi_exclusive }) catch ""
            else
                std.fmt.allocPrint(arena, "requested data above latest available; {s} is {d}, and only checkpoints below {d} are available", .{ a.bound, a.requested, a.hi_exclusive }) catch "";
            rs.setMessage(msg);
            const req = std.fmt.allocPrint(arena, "{d}", .{a.requested}) catch "";
            const hi = std.fmt.allocPrint(arena, "{d}", .{a.hi_exclusive}) catch "";
            rs.details(errorInfo(arena, 11, msg, "ABOVE_LATEST_AVAILABLE", &.{ .{ "bound", a.bound }, .{ "firstUnavailableCheckpoint", hi }, .{ "requestedCheckpoint", req } }) catch "");
            return .out_of_range;
        },
        .internal => |t| {
            rs.setMessage(t);
            return withDetails(arena, rs, .internal);
        },
        .unavailable => |t| {
            rs.setMessage(t);
            return withDetails(arena, rs, .unavailable);
        },
    }
}

/// google.rpc.Status { code, message, details: [Any(ErrorInfo { reason, domain "sui.io", metadata })] }.
fn errorInfo(arena: Allocator, code: u32, msg: []const u8, reason: []const u8, md: []const [2][]const u8) ![]const u8 {
    const buf = try arena.alloc(u8, 1024 + msg.len);
    var w = proto.Writer.init(buf);
    try w.uint(1, code);
    try w.bytes(2, msg);
    const any = try w.begin(3, 512);
    try w.bytes(1, "/google.rpc.ErrorInfo"); // as sui-node 1.83.1 sends it (rpc-surface list-checkpoints/err-desc-above-tip)
    const v = try w.begin(2, 400);
    try w.bytes(1, reason);
    try w.bytes(2, "sui.io");
    for (md) |kv| {
        const e = try w.begin(3, 64);
        try w.bytes(1, kv[0]);
        try w.bytes(2, kv[1]);
        try w.end(e);
    }
    try w.end(v);
    try w.end(any);
    return w.bytesWritten();
}

/// A parsed and validated request (everything before the index is consulted).
const Parsed = struct {
    q: Req,
    pos: core.CpPositions,
    rmask: mask.Mask,
    opts: Options,
    query: ?scan.Query,
    timeout_ms: u64,
};

fn parse(arena: Allocator, cfg: *const Config, m: Method, body: []const u8) Err!Parsed {
    const q = try parseRequest(arena, m, body);
    try core.validateCheckpointBounds(q.start_cp, q.end_cp);
    var pos: core.CpPositions = .{ .start_cp = q.start_cp, .end_cp = q.end_cp };
    switch (m) {
        .checkpoints => {},
        .transactions => {
            try requireWhenSet(q.start_cp != null, "start_checkpoint", q.start_tx != null, "start_transaction_index", arena);
            try requireWhenSet(q.end_cp != null, "end_checkpoint", q.end_tx != null, "end_transaction_index", arena);
            if (q.start_tx) |t| pos.start = .{ .tx = t };
            if (q.end_tx) |t| pos.end = .{ .tx = t };
        },
        .events => {
            try requireWhenSet(q.start_cp != null, "start_checkpoint", q.start_tx != null, "start_transaction_index", arena);
            try requireWhenSet(q.start_tx != null, "start_transaction_index", q.start_ev != null, "start_event_index", arena);
            try requireWhenSet(q.end_cp != null, "end_checkpoint", q.end_tx != null, "end_transaction_index", arena);
            try requireWhenSet(q.end_tx != null, "end_transaction_index", q.end_ev != null, "end_event_index", arena);
            if (q.start_tx) |t| pos.start = .{ .tx = t, .ev = q.start_ev orelse 0 };
            if (q.end_tx) |t| pos.end = .{ .tx = t, .ev = q.end_ev orelse 0 };
        },
    }
    const root: i16 = switch (m) {
        .checkpoints => comptime schema.index("Checkpoint"),
        .transactions => comptime schema.index("ExecutedTransaction"),
        .events => comptime schema.index("Event"),
    };
    const default_mask = switch (m) {
        .checkpoints => "sequence_number,digest",
        .transactions => "digest",
        .events => "event_type",
    };
    const rmask = try validateMask(arena, q.mask_field.items, default_mask, root);
    const lim = switch (m) {
        .checkpoints => cfg.checkpoints,
        .transactions => cfg.transactions,
        .events => cfg.events,
    };
    const space: core.Space = switch (m) {
        .checkpoints => .checkpoints,
        .transactions => .transactions,
        .events => .events,
    };
    const opts = try core.parseOptions(q.options, space, lim.default_limit, lim.max_limit);
    const query: ?scan.Query = if (q.filter) |fb| try parseFilter(arena, fb, m == .events, cfg.max_filter_literals) else null;
    return .{ .q = q, .pos = pos, .rmask = rmask, .opts = opts, .query = query, .timeout_ms = lim.timeout_ms };
}

fn run(svc: *service.Service, ix: *history.Index, cfg: *const Config, arena: Allocator, mem: *Mem, m: Method, body: []const u8, rs: *h2.ResponseStream, snap: *store.Snapshot) Err!void {
    const started = nowNs();
    var cctx: clever.Ctx = .{ .svc = svc, .snap = snap, .arena = arena };
    exec_error.clever_hook = cctx.hook();
    defer exec_error.clever_hook = null;
    const p = try parse(arena, cfg, m, body);
    var c = Ctx{
        .arena = arena,
        .mem = mem,
        .svc = svc,
        .ix = ix,
        .snap = snap,
        .cfg = cfg,
        .rs = rs,
        .sink = Sink.ofStream(rs),
        .deadline_ns = started + @as(i128, p.timeout_ms) * std.time.ns_per_ms,
    };
    if (rs.vt == &LinkSink.vt) @as(*LinkSink, @ptrCast(@alignCast(rs.impl))).deadline_ns = c.deadline_ns;
    defer c.unlock();
    const prof_on = profOn();
    if (prof_on) service.prof = .{};
    const ps0 = store.probeStats().*;
    defer if (prof_on) {
        const sp = service.prof;
        const ps = store.probeStats().*;
        const ms = struct {
            fn f(ns: u64) u64 {
                return ns / std.time.ns_per_ms;
            }
        }.f;
        std.log.info("lh prof {s}: {d} ms, {d} items, index {d} ms, render {d} ms (tx reads {d} in {d} ms, object reads {d} in {d} ms, read ahead {d} objects, waited {d} ms), send {d} ms, warm workers {d}, probes render runs {d} live {d} near {d}/{d} filtered {d}, workers runs {d} live {d} near {d}/{d} filtered {d}", .{
            @tagName(m),                                 @as(u64, @intCast(@divTrunc(nowNs() - started, std.time.ns_per_ms))), c.prof_items, ms(c.prof_index_ns), ms(c.prof_render_ns),
            sp.txs,                                      ms(sp.tx_ns),                                                           sp.objs, ms(sp.obj_ns), sp.pre_objs, ms(sp.wait_ns), ms(c.prof_send_ns),
            c.prof_warm,                                 ps.run_probes - ps0.run_probes,                                       ps.live_probes - ps0.live_probes,
            ps.near_hits - ps0.near_hits,                ps.near_falls - ps0.near_falls,                                         ps.filter_skips - ps0.filter_skips,
            sp.w_runs,                                   sp.w_live,                                                              sp.w_hits,
            sp.w_falls,                                  sp.w_skips,
        });
    };
    return serve(&c, m, &p, snap.highestCommitted() orelse return fail(.{ .unavailable = "rpc index is empty" }));
}

var prof_conf: std.atomic.Value(u8) = .init(2);
fn profOn() bool {
    const v = prof_conf.load(.monotonic);
    if (v != 2) return v == 1;
    const on: u8 = if (std.c.getenv("ZUI_LH_PROF")) |e| @intFromBool(e[0] == '1') else 0;
    prof_conf.store(on, .monotonic);
    return on == 1;
}

/// Resolves the request against the index (one short read section), then streams it.
fn serve(c: *Ctx, m: Method, p: *const Parsed, committed: u64) Err!void {
    c.lock();
    const range = c.reader().range() orelse return fail(.{ .unavailable = "rpc index is empty" });
    c.hi_excl = @min(range.hi, committed) + 1;
    const cp = try core.CpRange.fromRequest(p.q.start_cp, p.q.end_cp, c.hi_excl, &p.opts);
    switch (m) {
        .checkpoints => try listCheckpoints(c, cp, p.q, p.opts, p.rmask, p.query),
        .transactions => try listTransactions(c, cp, p.q, p.pos, p.opts, p.rmask, p.query),
        .events => try listEvents(c, cp, p.q, p.pos, p.opts, p.rmask, p.query),
    }
}

// ---------------------------------------------------------------- ListCheckpoints

const CpState = struct { range: [2]u64, end: core.RangeEnd, m: mask.Mask, o: Options, filt: ?*CpFilter = null };

/// `CheckpointScanState::Filtered`: a transaction-bitmap scan whose hits map to their checkpoints.
const CpFilter = struct {
    query: scan.Query,
    tx_range: ?[2]u64,
    pending: ?scan.Pending = null,
    /// Mapped checkpoints past the chunk's item target, in scan order (request arena).
    buffered: std.ArrayList(u64) = .empty,
    last_cp: ?u64 = null,
    covered: ?u64 = null,
    /// The window's first checkpoint in scan direction; no coverage claim passes it.
    entry: u64,
};

fn listCheckpoints(c: *Ctx, cpr: core.CpRange, q: Req, o: Options, m: mask.Mask, query: ?scan.Query) Err!void {
    try rejectWindowBelowFloor(c, cpr, q.start_cp, &o);
    const window = core.Window{ .s = .{ .a = cpr.s }, .e = .{ .a = cpr.e }, .ledger = core.LedgerWindow.checkpoints(cpr.s, cpr.e, q.start_cp, q.end_cp) };
    var r = core.Scan.resolve(cpr, window, &o, false) catch |e| {
        return floorErrorOr(c, q.start_cp, &o, e);
    };
    if (!r.isEmpty()) {
        const start = r.range()[0];
        if (start < c.floor) {
            if (explicitLower(q.start_cp, &o)) return fail(.{ .below_floor = c.floor });
            try r.applyServingFloor(.{ .a = c.floor }, c.floor, &o);
        }
    }
    var end = r.rangeEnd(window, &o, .checkpoints);
    if (r.isEmpty() or r.range()[0] >= r.range()[1]) {
        c.unlock();
        var empty = CpState{ .range = .{ 0, 0 }, .end = end, .m = m, .o = o };
        return drive(c, o.limit, c.cfg.checkpoints.chunk_max, &empty, cpChunk, "list_checkpoints");
    }
    const range = r.range();
    const qq = query orelse {
        c.unlock(); // rendering reads only the store
        var st = CpState{ .range = range, .end = end, .m = m, .o = o };
        return drive(c, o.limit, c.cfg.checkpoints.chunk_max, &st, cpChunk, "list_checkpoints");
    };
    // checkpoint_to_tx_range, then the tx-space serving floor (a backstop: the checkpoint window
    // is already clamped to the floor checkpoint).
    var tx_range: [2]u64 = .{ try c.boundary(range[0]), try c.boundary(range[1]) };
    if (tx_range[0] < tx_range[1]) {
        const ftx = try c.floorTx();
        if (tx_range[0] < ftx) {
            if (explicitLower(q.start_cp, &o)) return fail(.{ .below_floor = c.floor });
            // apply_serving_floor_to_filtered_window
            if (ftx >= tx_range[1]) return fail(.{ .below_floor = c.floor });
            tx_range[0] = ftx;
            if (o.asc) {
                r.entry_checkpoint = @max(r.entry_checkpoint, c.floor);
            } else {
                r.end_checkpoint = c.floor;
                r.end_position = .{ .a = c.floor };
                r.exhaustion = .{ .serving_floor = c.floor };
            }
            end = r.rangeEnd(window, &o, .checkpoints);
        }
    }
    c.unlock();
    if (tx_range[0] >= tx_range[1]) {
        var empty = CpState{ .range = .{ 0, 0 }, .end = end, .m = m, .o = o };
        return drive(c, o.limit, c.cfg.checkpoints.chunk_max, &empty, cpChunk, "list_checkpoints");
    }
    const f = try c.arena.create(CpFilter);
    f.* = .{ .query = qq, .tx_range = tx_range, .entry = r.entry_checkpoint };
    var st = CpState{ .range = range, .end = end, .m = m, .o = o, .filt = f };
    return drive(c, o.limit, c.cfg.checkpoints.chunk_max, &st, cpFilteredChunk, "list_checkpoints");
}

fn cpChunk(c: *Ctx, st: *CpState, budget: usize, chunk_limit: usize, remaining: usize) Err!ChunkDone {
    _ = remaining;
    if (st.range[0] >= st.range[1]) return .{ .produced = 0, .more = false, .terminal = st.end.terminal(), .remaining_budget = budget };
    var covered: ?u64 = null;
    var n: usize = 0;
    const want_txs = st.m.subtree("transactions") != null;
    const want_objects = st.m.subtree("objects") != null or (if (st.m.subtree("transactions")) |t| service.needsObjectSet(t) else false);
    const t_chunk = service.profNs();
    const send0 = c.prof_send_ns;
    var wj: warm.Job = .{ .svc = c.svc, .snap = c.snap, .digests = &.{}, .objects = want_objects };
    defer wj.finish();
    if (c.svc != null and (want_txs or want_objects)) if (warm.workers() > 0) {
        const cd = try chunkDigests(c, st, chunk_limit);
        wj.digests = cd.digests;
        wj.cps = cd.cps;
        try wj.start(c.chunkArena(), warm.workers());
        c.prof_warm = @max(c.prof_warm, wj.n);
    };
    var base: usize = 0;
    defer {
        c.prof_render_ns += (service.profNs() - t_chunk) -| (c.prof_send_ns - send0);
        c.prof_items += n;
    }
    while (n < chunk_limit and st.range[0] < st.range[1]) : (n += 1) {
        const seq = if (st.o.asc) st.range[0] else st.range[1] - 1;
        covered = core.mergeCovered(covered, seq, st.o.asc);
        base += try renderCheckpointSeq(c, st, seq, covered, wj.pre(base));
        if (st.o.asc) st.range[0] += 1 else st.range[1] -= 1;
    }
    return .{ .produced = n, .more = st.range[0] < st.range[1], .terminal = st.end.terminal(), .remaining_budget = budget };
}

/// The transaction digests of the chunk's next `chunk_limit` checkpoints, in render order, and
/// each one's checkpoint (for the read-ahead workers; a checkpoint missing here is reported by
/// the render).
fn chunkDigests(c: *Ctx, st: *const CpState, chunk_limit: usize) Err!struct { digests: []const [32]u8, cps: []const u64 } {
    const ca = c.chunkArena();
    var out: std.ArrayList([32]u8) = .empty;
    var cps: std.ArrayList(u64) = .empty;
    var r = st.range;
    var k: usize = 0;
    while (k < chunk_limit and r[0] < r[1]) : (k += 1) {
        const seq = if (st.o.asc) r[0] else r[1] - 1;
        if (st.o.asc) r[0] += 1 else r[1] -= 1;
        const rec = c.snap.?.checkpoint(seq) orelse continue;
        const contents = bcs.decode(types.CheckpointContents, ca, rec.contents) catch continue;
        switch (contents) {
            .V1 => |v| for (v.transactions) |t| try out.append(ca, t.transaction.@"0".@"0"),
            .V2 => |v| for (v.transactions) |t| try out.append(ca, t.digest.transaction.@"0".@"0"),
        }
        try cps.appendNTimes(ca, seq, out.items.len - cps.items.len);
    }
    return .{ .digests = out.items, .cps = cps.items };
}

/// `render_checkpoint_seq`: GetCheckpoint's message plus the item watermark under the chunk's
/// running `covered` bound. `pre`: the chunk's read-ahead object sets from this checkpoint's
/// first transaction on (`.{}` = none). Returns the checkpoint's transaction count (the next
/// checkpoint's read-ahead base).
fn renderCheckpointSeq(c: *Ctx, st: *const CpState, seq: u64, covered: ?u64, pre: service.PreObjects) Err!usize {
    const a = c.itemArena(); // one checkpoint's data at a time, not the chunk's
    const want_txs = st.m.subtree("transactions") != null;
    const want_objects = st.m.subtree("objects") != null or (if (st.m.subtree("transactions")) |t| service.needsObjectSet(t) else false);
    const wm = core.itemWatermark(.{ .space = .checkpoints, .checkpoint = seq }, .{ .cp = seq }, st.o.asc, covered);
    if (c.svc == null) { // unit tests: no store, the frame carries only the watermark
        try c.emit(.{ .bytes = try writeFrame(a, 0, {}, noItem, wm), .wm_cp = wm.checkpoint, .data = true });
        return 0;
    }
    const rec = c.snap.?.checkpoint(seq) orelse return fail(.{ .internal = "checkpoint missing from the store" });
    const d = try service.loadCheckpointDataPre(c.svc.?, a, c.snap.?, rec, want_txs, want_objects, pre);
    const Item = struct {
        arena: Allocator,
        m: mask.Mask,
        d: @TypeOf(d),
        fn render(it: @This(), w: *proto.Writer) !void {
            // writes `checkpoint = 1` itself (GetCheckpointResponse and ListCheckpointsResponse share it)
            try ledger.getCheckpoint(it.arena, w, it.m, it.d.cert, it.d.contents, it.d.objects, it.d.txs);
        }
    };
    const bytes = try writeFrame(a, 4096 + rec.contents.len * 2, Item{ .arena = a, .m = st.m, .d = d }, Item.render, wm);
    try c.emit(.{ .bytes = bytes, .wm_cp = wm.checkpoint, .data = true });
    return d.txs.len;
}

/// `merge_checkpoint_seqs`: consecutive hits of one checkpoint collapse to one item.
fn mergeCheckpointSeq(c: *Ctx, f: *CpFilter, cps: *std.ArrayList(u64), ca: Allocator, cp: u64, item_limit: usize, remaining: usize) !bool {
    if (f.last_cp == cp) return true;
    f.last_cp = cp;
    if (cps.items.len < item_limit) {
        try cps.append(ca, cp);
    } else if (cps.items.len + f.buffered.items.len < remaining) {
        try f.buffered.append(c.arena, cp);
    } else return false;
    return true;
}

/// `scan_checkpoint_watermark` + `checkpoint_frontier_watermark`: the transaction-space frontier
/// of a scan budget that ran out, resolved to checkpoint space.
fn scanCheckpointWatermark(c: *Ctx, asc: bool, frontier: u64, covered: ?u64, entry: u64) error{Rpc}!Watermark {
    const placed = try placeFrontier(c, .{ .a = frontier }, asc);
    const boundary = if (placed.cp) |cp| core.advanceCoveredBefore(covered, cp, entry, asc) else covered;
    var cursor_cp = core.scanFrontierCursorCp(placed.cp, frontier, asc) orelse
        return fail(.{ .internal = std.fmt.allocPrint(c.arena, "checkpoint scan frontier transaction {d} has no checkpoint mapping", .{frontier}) catch "checkpoint scan frontier has no checkpoint mapping" });
    // clamp_checkpoint_frontier_past_covered
    if (covered) |cv| cursor_cp = if (asc) @max(cursor_cp, cv +| 1) else @min(cursor_cp, cv);
    return core.boundaryWatermark(.{ .space = .checkpoints, .checkpoint = cursor_cp }, .{ .cp = cursor_cp }, boundary);
}

/// `next_filtered_checkpoint_chunk`.
fn cpFilteredChunk(c: *Ctx, st: *CpState, budget: usize, chunk_limit: usize, remaining: usize) Err!ChunkDone {
    const f = st.filt.?;
    const asc = st.o.asc;
    const ca = c.chunkArena();
    const item_limit = @min(chunk_limit, remaining);
    var remaining_budget = budget;
    var cps: std.ArrayList(u64) = .empty;
    {
        const take = @min(item_limit, f.buffered.items.len);
        try cps.appendSlice(ca, f.buffered.items[0..take]);
        const rest = f.buffered.items.len - take;
        std.mem.copyForwards(u64, f.buffered.items[0..rest], f.buffered.items[take..]);
        f.buffered.items.len = rest;
    }
    var frontier: ?u64 = null;
    var chunk_budget = @min(remaining_budget, c.cfg.chunk_bucket_scan_budget);
    var terminal = st.end.terminal();
    var more = false;
    var wm_only: ?Watermark = null;
    {
        c.lock();
        defer c.unlock();
        const u: ?[]const u32 = if (anyUniverse(f.query)) try universeBits(c) else null;
        while (cps.items.len < item_limit and (f.pending != null or f.tx_range != null) and chunk_budget > 0) {
            const tx_hit_limit = remaining -| (cps.items.len + f.buffered.items.len);
            if (tx_hit_limit == 0) break;
            const src: SrcCtx = .{ .rd = c.reader(), .space = .tx };
            const hits = try scan.drain(ca, .{ .ctx = &src, .buckets = bucketsOf, .universe_ok = true }, f.query, scan.tx_bucket_size, f.pending, f.tx_range, asc, tx_hit_limit, chunk_budget, u);
            for (hits.items) |s| {
                const cp = (try c.row(s)).checkpoint;
                if (!try mergeCheckpointSeq(c, f, &cps, ca, cp, item_limit, remaining)) break;
            }
            if (hits.scan_limit_frontier != null) {
                // Hits earned before the frontier stay ahead of the terminal.
                try cps.appendSlice(ca, f.buffered.items);
                f.buffered.items.len = 0;
            }
            remaining_budget -= @intCast(hits.buckets_scanned);
            chunk_budget -= @intCast(hits.buckets_scanned);
            f.pending = try keepPending(c.arena, f.pending, hits.pending);
            f.tx_range = hits.next_range;
            if (hits.scan_limit_frontier) |fr| {
                frontier = fr;
                break;
            }
            if (hits.items.len == 0) break;
        }
        if (cps.items.len + f.buffered.items.len == remaining) {
            f.pending = null;
            f.tx_range = null;
        }
        if (frontier == null and remaining_budget == 0) if (continuationFrontier(f.pending, f.tx_range, asc)) |fr| {
            // The request budget is spent with scan state left (a drain stopped at its hit limit
            // inside the bucket that took the last of the budget). Every later chunk would get a
            // zero chunk budget, scan nothing and leave the state as it is, so `drive` would spin
            // on empty chunks until the deadline. End here as the evaluator's own budget stop does:
            // SCAN_LIMIT at the first unscanned position, every mapped checkpoint ahead of it.
            frontier = fr;
            try cps.appendSlice(ca, f.buffered.items);
            f.buffered.items.len = 0;
        };
        if (cps.items.len > 0) f.covered = core.mergeCovered(f.covered, cps.items[cps.items.len - 1], asc);
        const req_limit = frontier != null and (remaining_budget == 0 or (f.tx_range == null and f.pending == null and f.buffered.items.len == 0));
        var fwm: ?Watermark = null;
        if (frontier) |fr| if (req_limit or cps.items.len == 0) {
            fwm = try scanCheckpointWatermark(c, asc, fr, f.covered, f.entry);
        };
        if (fwm) |w| if (w.checkpoint) |cp| {
            f.covered = core.mergeCovered(f.covered, cp, asc);
        };
        if (req_limit) {
            terminal = .{ .scan_limit = fwm.? };
        } else {
            more = f.buffered.items.len > 0 or f.pending != null or f.tx_range != null;
            if (cps.items.len == 0) wm_only = fwm;
        }
    }
    var covered: ?u64 = null;
    for (cps.items) |seq| {
        covered = core.mergeCovered(covered, seq, asc);
        _ = try renderCheckpointSeq(c, st, seq, covered, .{});
    }
    if (wm_only) |w| try c.emit(try watermarkFrame(ca, w));
    return .{ .produced = cps.items.len, .more = more, .terminal = terminal, .remaining_budget = remaining_budget };
}

/// The first unscanned transaction position of a filtered scan's continuation state, in the
/// evaluator's scan-limit frontier form: ascending, inclusive (the scan resumes at it);
/// descending, the exclusive upper bound (everything at or above it is scanned). A pending bucket
/// comes before `tx_range` in scan order. Null: nothing is left to scan.
fn continuationFrontier(pending: ?scan.Pending, tx_range: ?[2]u64, asc: bool) ?u64 {
    if (pending) |p| return if (asc) p.rem[0] else p.rem[1];
    const r = tx_range orelse return null;
    return if (asc) r[0] else r[1];
}

test "continuationFrontier: a pending bucket's remainder first, then the next range, in scan direction" {
    const bits = [_]u32{ 3, 9 };
    const p: scan.Pending = .{ .bucket = 1, .bits = &bits, .rem = .{ 65_540, 65_545 } };
    try std.testing.expectEqual(@as(?u64, 65_540), continuationFrontier(p, .{ 131_072, 200_000 }, true));
    try std.testing.expectEqual(@as(?u64, 65_545), continuationFrontier(p, .{ 0, 65_536 }, false));
    try std.testing.expectEqual(@as(?u64, 131_072), continuationFrontier(null, .{ 131_072, 200_000 }, true));
    try std.testing.expectEqual(@as(?u64, 65_536), continuationFrontier(null, .{ 0, 65_536 }, false));
    try std.testing.expectEqual(@as(?u64, null), continuationFrontier(null, null, true));
}

// ---------------------------------------------------------------- shared: resolve a tx/event scan

fn resolveTxScan(c: *Ctx, cpr: core.CpRange, q: Req, pos: core.CpPositions, o: *const Options, intra: bool) Err!struct { scan: core.Scan, window: core.Window } {
    try rejectWindowBelowFloor(c, cpr, q.start_cp, o);
    const window = try pos.narrow(cpr.s, cpr.e, intra, c, Ctx.boundaryFn);
    var r = core.Scan.resolve(cpr, window, o, intra) catch |e| {
        return floorErrorOr(c, q.start_cp, o, e);
    };
    if (!r.isEmpty()) {
        const start_tx: u64 = switch (r.bounds.lo) {
            .inc, .exc => |p| p.a,
            .unb => 0,
        };
        const ftx = try c.floorTx();
        if (start_tx < ftx) {
            if (explicitLower(q.start_cp, o)) return fail(.{ .below_floor = c.floor });
            try r.applyServingFloor(.{ .a = ftx }, c.floor, o);
        }
    }
    return .{ .scan = r, .window = window };
}

fn placeFrontier(c: *Ctx, frontier: Pos, asc: bool) error{Rpc}!struct { cp: ?u64, point: Point } {
    // RowPlacement::event_boundary
    if (asc and frontier.b == 0) {
        if (frontier.a == 0) return .{ .cp = null, .point = Point.genesis };
        const r = try c.row(frontier.a - 1);
        return .{ .cp = r.checkpoint, .point = .{ .cp = r.checkpoint, .tx = @as(u64, r.tx_offset) + 1 } };
    }
    const r = try c.row(frontier.a);
    return .{ .cp = r.checkpoint, .point = .{ .cp = r.checkpoint, .tx = r.tx_offset, .ev = frontier.b } };
}

fn frontierWatermark(c: *Ctx, space: core.Space, frontier: Pos, entry: u64, asc: bool) error{Rpc}!Watermark {
    const placed = try placeFrontier(c, frontier, asc);
    const boundary = if (placed.cp) |cp| core.advanceCoveredBefore(null, cp, entry, asc) else null;
    const cursor_cp = core.scanFrontierCursorCp(placed.cp, frontier.a, asc) orelse return fail(.{ .internal = "scan frontier has no checkpoint mapping" });
    return core.boundaryWatermark(Position.at(space, cursor_cp, frontier), placed.point, boundary);
}

fn universeBits(c: *Ctx) ![]const u32 {
    if (c.universe) |u| return u;
    const u = try c.arena.alloc(u32, scan.tx_bucket_size);
    for (u, 0..) |*x, i| x.* = @intCast(i);
    c.universe = u;
    return u;
}

fn bucketsOf(ctx: *const anyopaque, key: []const u8) []const scan.Bucket {
    const sc: *const SrcCtx = @ptrCast(@alignCast(ctx));
    return sc.rd.buckets(sc.space, key);
}
const SrcCtx = struct { rd: *history.Reader, space: history.Space };

/// A pending bucket carried to the next chunk: its bits may point into the index (the open
/// bucket's list, which the writer grows, or a sealed bucket a prune frees) or into the chunk
/// arena, so the next chunk gets its own copy.
fn keepPending(arena: Allocator, prev: ?scan.Pending, p: ?scan.Pending) !?scan.Pending {
    var v = p orelse return null;
    if (prev) |old| if (old.bits.ptr == v.bits.ptr and old.bits.len == v.bits.len) return v; // already ours
    v.bits = try arena.dupe(u32, v.bits);
    return v;
}

// ---------------------------------------------------------------- ListTransactions

const TxState = struct {
    m: mask.Mask,
    o: Options,
    end: core.RangeEnd,
    entry: u64,
    range: ?[2]u64,
    query: ?scan.Query,
    pending: ?scan.Pending = null,
    render_contents: bool,
    empty: bool,
};

fn renderContents(m: mask.Mask, paths: []const []const u8) bool {
    _ = m;
    if (paths.len == 0 or paths.len > 3) return true;
    for (paths) |p| if (!std.mem.eql(u8, p, "digest") and !std.mem.eql(u8, p, "checkpoint") and !std.mem.eql(u8, p, "transaction_index")) return true;
    return false;
}

fn maskPaths(arena: Allocator, parts: []const []const u8, default: []const u8) ![]const []const u8 {
    var paths: std.ArrayList([]const u8) = .empty;
    if (parts.len == 0) {
        var it = std.mem.splitScalar(u8, default, ',');
        while (it.next()) |p| try paths.append(arena, p);
        return paths.items;
    }
    for (parts) |data| {
        var r = proto.Reader.init(data);
        while (r.next() catch return error.Malformed) |f| if (f.number == 1) try paths.append(arena, proto.Reader.stringOf(f) catch return error.Malformed);
    }
    return paths.items;
}

fn listTransactions(c: *Ctx, cpr: core.CpRange, q: Req, pos: core.CpPositions, o: Options, m: mask.Mask, query: ?scan.Query) Err!void {
    const res = try resolveTxScan(c, cpr, q, pos, &o, false);
    c.unlock();
    const end = res.scan.rangeEnd(res.window, &o, .transactions);
    const paths = try maskPaths(c.arena, q.mask_field.items, "digest");
    var st = TxState{
        .m = m,
        .o = o,
        .end = end,
        .entry = res.scan.entry_checkpoint,
        .range = res.scan.range(),
        .query = query,
        .render_contents = renderContents(m, paths),
        .empty = res.scan.isEmpty() or res.scan.range()[0] >= res.scan.range()[1],
    };
    return drive(c, o.limit, c.cfg.transactions.chunk_max, &st, txChunk, "list_transactions");
}

fn txChunk(c: *Ctx, st: *TxState, budget: usize, chunk_limit: usize, remaining: usize) Err!ChunkDone {
    if (st.empty) return .{ .produced = 0, .more = false, .terminal = st.end.terminal(), .remaining_budget = budget };
    const asc = st.o.asc;
    const ca = c.chunkArena();
    var rows: std.ArrayList(history.TxRow) = .empty;
    var terminal = st.end.terminal();
    var remaining_budget = budget;
    var more = false;
    var wm_only: ?Watermark = null;
    {
        // Index work only: the scan, the rows (copied out) and the frontier.
        const t_ix = service.profNs();
        defer c.prof_index_ns += service.profNs() - t_ix;
        c.lock();
        defer c.unlock();
        if (st.query) |qq| {
            const src: SrcCtx = .{ .rd = c.reader(), .space = .tx };
            const hit_limit = @min(chunk_limit, remaining);
            const chunk_budget = @min(remaining_budget, c.cfg.chunk_bucket_scan_budget);
            const u: ?[]const u32 = if (anyUniverse(qq)) try universeBits(c) else null;
            const hits = try scan.drain(ca, .{ .ctx = &src, .buckets = bucketsOf, .universe_ok = true }, qq, scan.tx_bucket_size, st.pending, st.range, asc, hit_limit, chunk_budget, u);
            remaining_budget -= @intCast(hits.buckets_scanned);
            const req_limit = hits.scan_limit_frontier != null and (remaining_budget == 0 or (hits.next_range == null and hits.pending == null));
            for (hits.items) |s| try rows.append(ca, try c.row(s));
            if (!req_limit) {
                more = hits.pending != null or hits.next_range != null;
                st.range = hits.next_range;
                st.pending = try keepPending(c.arena, st.pending, hits.pending);
            }
            var fwm: ?Watermark = null;
            if (hits.scan_limit_frontier) |f| if (req_limit or rows.items.len == 0) {
                fwm = try frontierWatermark(c, .transactions, .{ .a = f }, st.entry, asc);
            };
            if (req_limit) terminal = .{ .scan_limit = fwm.? };
            if (!req_limit and rows.items.len == 0) wm_only = fwm;
        } else {
            // unfiltered: consecutive rows
            const r = st.range.?;
            var n: usize = 0;
            while (n < chunk_limit) : (n += 1) {
                const seq = if (asc) r[0] + n else r[1] - 1 - n;
                if (asc and seq >= r[1]) break;
                if (!asc and (r[1] - n == r[0])) break;
                try rows.append(ca, try c.row(seq));
            }
            if (rows.items.len > 0) {
                const lastseq = rows.items[rows.items.len - 1].tx_seq;
                st.range = scan.remainingAfter(r, lastseq, asc);
                more = st.range != null;
            }
        }
    }
    try renderTxRows(c, st, rows.items);
    if (wm_only) |w| try c.emit(try watermarkFrame(ca, w));
    return .{ .produced = rows.items.len, .more = more, .terminal = terminal, .remaining_budget = remaining_budget };
}

fn anyUniverse(q: scan.Query) bool {
    for (q.keys) |k| if (k.len > 0 and k[0] == 9) return true;
    return false;
}

fn renderTxRows(c: *Ctx, st: *TxState, rows: []const history.TxRow) Err!void {
    var boundary: ?u64 = null;
    const want_index = st.m.contains("transaction_index");
    const t_chunk = service.profNs();
    const send0 = c.prof_send_ns;
    defer {
        c.prof_render_ns += (service.profNs() - t_chunk) -| (c.prof_send_ns - send0);
        c.prof_items += rows.len;
    }
    var wj: warm.Job = .{ .svc = c.svc, .snap = c.snap, .digests = &.{}, .objects = service.needsObjectSet(st.m), .checkpoint = true };
    defer wj.finish();
    if (st.render_contents and rows.len > 1 and warm.workers() > 0) {
        const dgs = try c.chunkArena().alloc([32]u8, rows.len);
        const cps = try c.chunkArena().alloc(u64, rows.len);
        for (rows, dgs, cps) |r, *d, *cp| {
            d.* = r.digest;
            cp.* = r.checkpoint;
        }
        wj.digests = dgs;
        wj.cps = cps;
        try wj.start(c.chunkArena(), warm.workers());
        c.prof_warm = @max(c.prof_warm, wj.n);
    }
    for (rows, 0..) |row, ri| {
        const a = c.itemArena();
        boundary = core.advanceCoveredBefore(boundary, row.checkpoint, st.entry, st.o.asc);
        const wm = core.itemWatermark(.{ .space = .transactions, .checkpoint = row.checkpoint, .tx_seq = row.tx_seq }, .{ .cp = row.checkpoint, .tx = row.tx_offset }, st.o.asc, boundary);
        const Item = struct {
            c: *Ctx,
            a: Allocator,
            st: *TxState,
            row: history.TxRow,
            want_index: bool,
            wj: *warm.Job,
            i: usize,
            fn render(it: @This(), w: *proto.Writer) !void {
                const mk = try w.begin(1, 4096);
                if (it.st.render_contents) {
                    var missing: []const u8 = "";
                    service.txBodyPub(it.c.svc.?, it.a, w, it.c.snap.?, it.st.m, &it.row.digest, &missing, it.wj.objectsOf(it.i, &it.row.digest), it.row.checkpoint) catch |e| {
                        if (e == error.Internal and missing.len > 0) it.c.setMessage(missing);
                        return e;
                    };
                } else {
                    if (it.st.m.contains("digest")) {
                        var dbuf: [b58.max_len_32]u8 = undefined;
                        try w.bytes(1, b58.encode32(&dbuf, &it.row.digest));
                    }
                    if (it.st.m.contains("checkpoint")) try w.uint(6, it.row.checkpoint);
                }
                if (it.want_index) try w.uint(10, it.row.tx_offset);
                try w.end(mk);
            }
        };
        const bytes = try writeFrame(a, 8192, Item{ .c = c, .a = a, .st = st, .row = row, .want_index = want_index, .wj = &wj, .i = ri }, Item.render, wm);
        try c.emit(.{ .bytes = bytes, .wm_cp = wm.checkpoint, .data = true });
    }
}

// ---------------------------------------------------------------- ListEvents

/// The last transaction's decoded events: refs arrive grouped by transaction (up to 1,024
/// events each), so each transaction's TransactionEvents is decoded once, not once per event.
const EventsCache = struct {
    arena: std.heap.ArenaAllocator,
    digest: ?[32]u8 = null,
    evs: types.TransactionEvents = .{ .data = &.{} },
    decodes: usize = 0,

    fn init() EventsCache {
        return .{ .arena = .init(std.heap.page_allocator) };
    }
    fn deinit(ec: *EventsCache) void {
        ec.arena.deinit();
    }
    /// The events of `digest`; `load` gives the raw BCS (decoded into the cache's own arena).
    fn get(ec: *EventsCache, digest: *const [32]u8, ctx: anytype, comptime load: fn (@TypeOf(ctx), *const [32]u8) Err![]const u8) Err!types.TransactionEvents {
        if (ec.digest) |d| if (std.mem.eql(u8, &d, digest)) return ec.evs;
        ec.digest = null;
        _ = ec.arena.reset(.{ .retain_with_limit = 4 << 20 });
        const raw = try load(ctx, digest);
        ec.evs = try bcs.decode(types.TransactionEvents, ec.arena.allocator(), raw);
        ec.digest = digest.*;
        ec.decodes += 1;
        return ec.evs;
    }
};

/// The raw events of the row's transaction; `cp` (the row's checkpoint) is the lookup hint
/// (Snapshot.transactionNear).
const EvLoad = struct {
    c: *Ctx,
    cp: u64,
    fn load(l: EvLoad, digest: *const [32]u8) Err![]const u8 {
        const rec = l.c.snap.?.transactionNear(digest, l.cp) orelse return fail(.{ .internal = "selected event transaction has no events" });
        return rec.events orelse fail(.{ .internal = "selected event transaction has no events" });
    }
};

const EvState = struct {
    m: mask.Mask,
    o: Options,
    end: core.RangeEnd,
    entry: u64,
    bounds: ?core.Bounds,
    query: ?scan.Query,
    pending: ?scan.Pending = null,
    row_budget: usize,
    empty: bool,
    cache: EventsCache,
    /// The `json` renderer (null without `json` in the mask, or without a store in unit tests).
    render: ?*const ro.Ctx = null,
};

/// The json render context of one ListEvents request. render.rs `render_event_to_proto` with an
/// empty ObjectSet: layouts from the store's packages only, and a fresh
/// `max_json_move_value_size` budget per event (`render_json`, not the shared-budget variant).
fn eventRenderCtx(c: *Ctx, m: mask.Mask) Err!?*const ro.Ctx {
    if (!m.contains("json")) return null;
    const svc = c.svc orelse return null;
    const snap = c.snap orelse return null;
    const src = try c.arena.create(service.ObjSource);
    src.* = .{ .snap = snap };
    const res = try c.arena.create(movelayout.Resolver);
    res.* = movelayout.Resolver.init(c.arena, src.packages());
    const rc = try c.arena.create(ro.Ctx);
    rc.* = .{ .resolver = res, .json_on = svc.json }; // no Display hook: events have none
    return rc;
}

fn listEvents(c: *Ctx, cpr: core.CpRange, q: Req, pos: core.CpPositions, o: Options, m: mask.Mask, query: ?scan.Query) Err!void {
    const res = try resolveTxScan(c, cpr, q, pos, &o, true);
    c.unlock();
    const end = res.scan.rangeEnd(res.window, &o, .events);
    var st = EvState{
        .m = m,
        .o = o,
        .end = end,
        .entry = res.scan.entry_checkpoint,
        .bounds = res.scan.bounds,
        .query = query,
        .row_budget = c.cfg.events.max_limit,
        .empty = res.scan.isEmpty(),
        .cache = .init(),
        .render = try eventRenderCtx(c, m),
    };
    defer st.cache.deinit();
    return drive(c, o.limit, c.cfg.events.chunk_max, &st, evChunk, "list_events");
}

const EvRef = struct { pos: Pos, row: history.TxRow };

fn boundsFromPacked(r: [2]u64) core.Bounds {
    return .{ .lo = .{ .inc = core.decodeEventSeq(r[0]) }, .hi = .{ .exc = core.decodeEventSeq(r[1]) } };
}

fn evChunk(c: *Ctx, st: *EvState, budget: usize, chunk_limit: usize, remaining: usize) Err!ChunkDone {
    if (st.empty) return .{ .produced = 0, .more = false, .terminal = st.end.terminal(), .remaining_budget = budget };
    const asc = st.o.asc;
    const ca = c.chunkArena();
    var refs: std.ArrayList(EvRef) = .empty;
    var terminal = st.end.terminal();
    var remaining_budget = budget;
    var more = false;
    var scan_wm: ?Watermark = null;
    {
        // Index work only: the scan, every ref's row (copied out) and the frontier.
        c.lock();
        defer c.unlock();
        if (st.query) |qq| {
            const src: SrcCtx = .{ .rd = c.reader(), .space = .event };
            const hit_limit = @min(chunk_limit, remaining);
            const chunk_budget = @min(remaining_budget, c.cfg.chunk_bucket_scan_budget);
            const packed_range: ?[2]u64 = if (st.bounds) |b| core.packedRange(b.lo, b.hi) else null;
            const hits = try scan.drain(ca, .{ .ctx = &src, .buckets = bucketsOf, .universe_ok = false }, qq, scan.event_bucket_size, st.pending, packed_range, asc, hit_limit, chunk_budget, null);
            remaining_budget -= @intCast(hits.buckets_scanned);
            const req_limit = hits.scan_limit_frontier != null and (remaining_budget == 0 or (hits.next_range == null and hits.pending == null));
            var last: ?history.TxRow = null;
            for (hits.items) |s| {
                const p = core.decodeEventSeq(s);
                const r = if (last) |l| (if (l.tx_seq == p.a) l else try c.row(p.a)) else try c.row(p.a);
                last = r;
                try refs.append(ca, .{ .pos = p, .row = r });
            }
            if (!req_limit) {
                more = hits.pending != null or hits.next_range != null;
                st.bounds = if (hits.next_range) |nr| boundsFromPacked(nr) else null;
                st.pending = try keepPending(c.arena, st.pending, hits.pending);
            }
            var fwm: ?Watermark = null;
            if (hits.scan_limit_frontier) |f| if (req_limit or refs.items.len == 0) {
                fwm = try frontierWatermark(c, .events, core.decodeEventSeq(f), st.entry, asc);
            };
            if (req_limit) terminal = .{ .scan_limit = fwm.? };
            if (!req_limit and refs.items.len == 0) scan_wm = fwm;
        } else {
            // next_unfiltered_event_refs
            const row_limit = @min(st.row_budget, c.cfg.chunk_bucket_scan_budget);
            const b = st.bounds.?;
            var rows_scanned: usize = 0;
            var next_bounds: ?core.Bounds = null;
            var filled = false;
            var filled_next: ?core.Bounds = null;
            if (b.txRange()) |tr| {
                var k: u64 = 0;
                while (rows_scanned < row_limit) : (k += 1) {
                    const seq = if (asc) tr[0] + k else tr[1] - 1 - k;
                    if (asc and seq >= tr[1]) break;
                    if (!asc and tr[1] - k == tr[0]) break;
                    const row = try c.row(seq);
                    rows_scanned += 1;
                    var nb: ?core.Bounds = null;
                    if (row.event_count > 0) {
                        var i: u32 = 0;
                        while (i < row.event_count) : (i += 1) {
                            const idx = if (asc) i else row.event_count - 1 - i;
                            const p = Pos{ .a = row.tx_seq, .b = idx };
                            if (!b.contains(p)) continue;
                            try refs.append(ca, .{ .pos = p, .row = row });
                            var bb = b;
                            if (asc) bb.lo = .{ .exc = p } else bb.hi = .{ .exc = p };
                            nb = if (bb.isEmpty()) null else bb;
                            if (refs.items.len == chunk_limit) break;
                        }
                    }
                    if (refs.items.len == chunk_limit) {
                        filled = true;
                        filled_next = nb;
                        break;
                    }
                    var bb = b;
                    if (asc) bb.lo = .{ .inc = .{ .a = row.tx_seq +| 1 } } else bb.hi = .{ .exc = .{ .a = row.tx_seq } };
                    next_bounds = if (bb.isEmpty()) null else bb;
                }
            }
            if (filled) {
                st.row_budget -= rows_scanned;
                st.bounds = filled_next;
                more = filled_next != null;
            } else {
                const row_limit_reached = rows_scanned == row_limit and next_bounds != null;
                st.row_budget -= rows_scanned;
                const req_limit = row_limit_reached and st.row_budget == 0;
                if (!req_limit) {
                    st.bounds = next_bounds;
                    more = next_bounds != null;
                }
                if (row_limit_reached) {
                    const nbv = next_bounds.?;
                    const frontier: Pos = if (asc) switch (nbv.lo) {
                        .inc, .exc => |p| p,
                        .unb => return fail(.{ .internal = "event row scan limit missing authoritative frontier" }),
                    } else switch (nbv.hi) {
                        .inc, .exc => |p| p,
                        .unb => return fail(.{ .internal = "event row scan limit missing authoritative frontier" }),
                    };
                    if (req_limit or refs.items.len == 0) {
                        const w = try frontierWatermark(c, .events, frontier, st.entry, asc);
                        if (req_limit) terminal = .{ .scan_limit = w } else scan_wm = w;
                    }
                }
            }
        }
    }
    try renderEvents(c, st, refs.items);
    const produced = refs.items.len;
    if (scan_wm) |w| try c.emit(try watermarkFrame(ca, w));
    return .{ .produced = produced, .more = more, .terminal = terminal, .remaining_budget = remaining_budget };
}

/// The canonical type string of an event's StructTag (any length).
fn structTagAlloc(arena: Allocator, tag: anytype) ![]const u8 {
    var o = typestr.scratch();
    try typestr.structTag(&o, tag);
    return arena.dupe(u8, o.str());
}

/// One ListEventsResponse `event` (field 1): render.rs `render_event_to_proto` fields 1-6, then the
/// ledger position fields 7-10 list_events.rs sets on the same message (prost: field order).
const ListEventItem = struct {
    m: mask.Mask,
    ty: []const u8,
    e: types.Event,
    row: history.TxRow,
    idx: u32,
    json: ?pbvalue.Value,
    fn render(it: @This(), w: *proto.Writer) !void {
        const em = it.m;
        const mk = try w.begin(1, it.e.contents.len + 300);
        if (em.contains("package_id")) try ro.addrStr(w, 1, &it.e.package_id.@"0".@"0");
        if (em.contains("module")) try w.string(2, it.e.transaction_module.str());
        if (em.contains("sender")) try ro.addrStr(w, 3, &it.e.sender.@"0");
        if (em.contains("event_type")) try w.string(4, it.ty);
        if (em.contains("contents")) {
            const b = try w.begin(5, it.e.contents.len + it.ty.len + 8);
            try w.string(1, it.ty);
            try w.bytes(2, it.e.contents);
            try w.end(b);
        }
        if (it.json) |*v| try pbvalue.write(w, 6, v);
        if (em.contains("checkpoint")) try w.uint(7, it.row.checkpoint);
        if (em.contains("transaction_digest")) {
            var dbuf: [b58.max_len_32]u8 = undefined;
            try w.string(8, b58.encode32(&dbuf, &it.row.digest));
        }
        if (em.contains("transaction_index")) try w.uint(9, it.row.tx_offset);
        if (em.contains("event_index")) try w.uint(10, it.idx);
        try w.end(mk);
    }
};

fn listEventItem(arena: Allocator, m: mask.Mask, e: types.Event, row: history.TxRow, idx: u32, rc: ?*const ro.Ctx) Err!ListEventItem {
    const json: ?pbvalue.Value = if (m.contains("json")) if (rc) |c| try c.json(arena, &e.type_, e.contents) else null else null;
    return .{ .m = m, .ty = try structTagAlloc(arena, e.type_), .e = e, .row = row, .idx = idx, .json = json };
}

/// One ListEvents item's `Event` message (the response's field 1) exactly as a ListEvents stream
/// writes it; `rc` renders `json` (null: no json). For the render-json suite's ListEvents vectors.
pub fn writeListEvent(arena: Allocator, w: *proto.Writer, m: mask.Mask, e: types.Event, row: history.TxRow, idx: u32, rc: ?*const ro.Ctx) Err!void {
    const item = try listEventItem(arena, m, e, row, idx, rc);
    try item.render(w);
}

fn renderEvents(c: *Ctx, st: *EvState, refs: []const EvRef) Err!void {
    var boundary: ?u64 = null;
    for (refs) |ref| {
        const row = ref.row;
        const evs = try st.cache.get(&row.digest, EvLoad{ .c = c, .cp = row.checkpoint }, EvLoad.load);
        if (ref.pos.b >= evs.data.len) return fail(.{ .internal = "selected event index out of range" });
        const e = evs.data[ref.pos.b];
        const a = c.itemArena();
        boundary = core.advanceCoveredBefore(boundary, row.checkpoint, st.entry, st.o.asc);
        const wm = core.itemWatermark(.{ .space = .events, .checkpoint = row.checkpoint, .tx_seq = ref.pos.a, .event_index = ref.pos.b }, .{ .cp = row.checkpoint, .tx = row.tx_offset, .ev = ref.pos.b }, st.o.asc, boundary);
        // json is rendered here, once, before the frame (a NoSpace retry of the frame writer reuses it).
        const item = try listEventItem(a, st.m, e, row, ref.pos.b, st.render);
        const bytes = try writeFrame(a, e.contents.len + 512, item, ListEventItem.render, wm);
        try c.emit(.{ .bytes = bytes, .wm_cp = wm.checkpoint, .data = true });
    }
}

// ---------------------------------------------------------------- tests

test "writeFrame: grows on the frame writer's own overflow, never on another NoSpace" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const wm: Watermark = .{ .cursor = undefined, .checkpoint = null, .position = null };
    _ = wm;
    const Big = struct {
        fn render(n: usize, w: *proto.Writer) !void {
            var chunk: [1000]u8 = @splat(7);
            for (0..n) |_| try w.bytes(1, &chunk);
        }
        fn inner(_: void, _: *proto.Writer) !void {
            // a type string or other fixed buffer inside the renderer
            return error.NoSpace;
        }
    };
    var w0 = proto.Writer.init(try a.alloc(u8, 16));
    try std.testing.expectError(error.NoSpace, Big.render(3, &w0));
    try std.testing.expect(w0.retryCap().? >= 1003);
    var w1 = proto.Writer.init(try a.alloc(u8, 4096));
    try std.testing.expectError(error.NoSpace, Big.inner({}, &w1));
    try std.testing.expect(w1.retryCap() == null);
}

test "ListEvents item: json is field 6 (between contents and checkpoint); fields 1-5 equal GetTransaction's Event" {
    // Regression (integration round 1): any ListEvents mask with `json` answered UNIMPLEMENTED.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // BCS Event { package_id, transaction_module, sender, type_: StructTag, contents }
    var raw: std.ArrayList(u8) = .empty;
    try raw.appendNTimes(a, 0xab, 32);
    try raw.appendSlice(a, "\x04pool");
    try raw.appendNTimes(a, 0xcd, 32);
    try raw.appendNTimes(a, 0xab, 32);
    try raw.appendSlice(a, "\x04pool\x07Swapped\x00");
    try raw.appendSlice(a, "\x03\x01\x02\x03");
    const e = try bcs.decode(types.Event, a, raw.items);
    const ty = try structTagAlloc(a, e.type_);
    const ents = [_]pbvalue.Entry{
        .{ .key = "amount", .value = .{ .string = "515" } },
        .{ .key = "pool", .value = .{ .bool = true } },
    };
    const json: pbvalue.Value = .{ .@"struct" = &ents };
    const row: history.TxRow = .{ .tx_seq = 1, .digest = @splat(9), .checkpoint = 343111000, .tx_offset = 7, .event_count = 3 };

    var tree = try mask.Tree.parse(a, "package_id,module,sender,event_type,contents,json,checkpoint,event_index");
    var w = proto.Writer.init(try a.alloc(u8, 4096));
    try ListEventItem.render(.{ .m = tree.mask(), .ty = ty, .e = e, .row = row, .idx = 2, .json = json }, &w);
    var r = proto.Reader.init(w.bytesWritten());
    const outer = (try r.next()).?;
    try std.testing.expectEqual(@as(u32, 1), outer.number);
    var ir = proto.Reader.init(outer.data);
    var order: std.ArrayList(u32) = .empty;
    var json_bytes: []const u8 = &.{};
    while (try ir.next()) |f| {
        try order.append(a, f.number);
        if (f.number == 6) json_bytes = f.data;
    }
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 3, 4, 5, 6, 7, 10 }, order.items);
    var jw = proto.Writer.init(try a.alloc(u8, 512));
    try pbvalue.write(&jw, 6, &json);
    var jr = proto.Reader.init(jw.bytesWritten());
    try std.testing.expectEqualSlices(u8, (try jr.next()).?.data, json_bytes);

    // fields 1-5 are byte-equal to render_tx.writeEventCtx (GetTransaction / checkpoint events)
    var t2 = try mask.Tree.parse(a, "package_id,module,sender,event_type,contents");
    var w1 = proto.Writer.init(try a.alloc(u8, 4096));
    try ListEventItem.render(.{ .m = t2.mask(), .ty = ty, .e = e, .row = row, .idx = 2, .json = null }, &w1);
    var w2 = proto.Writer.init(try a.alloc(u8, 4096));
    try @import("render_tx.zig").writeEventCtx(a, &w2, 1, t2.mask(), e, null);
    try std.testing.expectEqualSlices(u8, w2.bytesWritten(), w1.bytesWritten());
}

test "EventsCache: one decode per transaction, not per event" {
    var cache = EventsCache.init();
    defer cache.deinit();
    const Loader = struct {
        loads: usize = 0,
        fn load(l: *@This(), _: *const [32]u8) Err![]const u8 {
            l.loads += 1;
            return "\x00"; // TransactionEvents { data: [] }
        }
    };
    var l: Loader = .{};
    const d1: [32]u8 = @splat(1);
    const d2: [32]u8 = @splat(2);
    for (0..1000) |_| _ = try cache.get(&d1, &l, Loader.load);
    _ = try cache.get(&d2, &l, Loader.load);
    _ = try cache.get(&d2, &l, Loader.load);
    _ = try cache.get(&d1, &l, Loader.load);
    try std.testing.expectEqual(@as(usize, 3), cache.decodes);
    try std.testing.expectEqual(@as(usize, 3), l.loads);
}

fn testCorpus(a: Allocator, io: std.Io) !?[]const []const u8 {
    const corpus = std.c.getenv("ZUI_CORPUS") orelse return null;
    var dir = std.Io.Dir.cwd().openDir(io, std.mem.span(corpus), .{}) catch return null;
    defer dir.close(io);
    var out: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{ "342456120", "342456121", "342456122", "342456123", "342456124", "342456125" }) |nm| {
        const p = try std.fmt.allocPrint(a, "chk/{s}.chk", .{nm});
        try out.append(a, dir.readFileAlloc(io, p, a, .limited(1 << 30)) catch return null);
    }
    return out.items;
}

const TestSink = struct {
    ix: *history.Index,
    io: std.Io,
    frames: usize = 0,
    /// Prune the index below this checkpoint when the first frame goes out (retention racing a request).
    prune_at: ?u64 = null,
    cancel_after: ?usize = null,

    fn send(p: *anyopaque, _: []const u8) anyerror!void {
        const t: *TestSink = @ptrCast(@alignCast(p));
        t.frames += 1;
        // No index read section is open while a frame is written: the writer could take the lock now.
        try std.testing.expect(t.ix.lock.tryLock(t.io));
        t.ix.lock.unlock(t.io);
        if (t.frames == 1) if (t.prune_at) |cp| t.ix.pruneBelow(cp);
    }
    fn cancelled(p: *anyopaque) bool {
        const t: *TestSink = @ptrCast(@alignCast(p));
        return if (t.cancel_after) |n| t.frames >= n else false;
    }
};

fn testRequest(a: Allocator, start_cp: u64, limit: u64, sender: ?*const [32]u8) ![]const u8 {
    const buf = try a.alloc(u8, 512);
    var w = proto.Writer.init(buf);
    const m = try w.begin(1, 8);
    try w.string(1, "digest");
    try w.end(m);
    try w.uint(2, start_cp);
    if (sender) |s| {
        var hex: [66]u8 = undefined;
        _ = try std.fmt.bufPrint(&hex, "0x{x}", .{s});
        const f = try w.begin(4, 100);
        const t = try w.begin(1, 90);
        const l = try w.begin(1, 80);
        const sp = try w.begin(2, 70);
        try w.string(1, &hex);
        try w.end(sp);
        try w.end(l);
        try w.end(t);
        try w.end(f);
    }
    const o = try w.begin(5, 4);
    try w.uint(1, limit);
    try w.end(o);
    return w.bytesWritten();
}

test "List*: no index read section while frames are written; a floor raised mid-stream ends below it; cancellation stops it" {
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const blobs = (try testCorpus(a, io)) orelse return error.SkipZigTest;
    var seqs: [6]u64 = undefined;
    var ntx: [6]u64 = undefined;
    var sender: [32]u8 = undefined;
    for (blobs, 0..) |b, i| {
        const cp = try bcs.decode(types.CheckpointData, a, b[1..]);
        seqs[i] = cp.checkpoint_summary.data.sequence_number;
        ntx[i] = cp.transactions.len;
        if (i == 0) sender = cp.transactions[cp.transactions.len - 1].transaction.data.@"0".element().intent_message.value.V1.sender.@"0";
    }
    const cfg: Config = .{};
    const Run = struct {
        fn go(ix: *history.Index, aa: Allocator, conf: *const Config, sink: *TestSink, body: []const u8, top: u64) Err!void {
            var mem = Mem.init();
            defer mem.deinit();
            const p = try parse(aa, conf, .transactions, body);
            var c = Ctx{ .arena = aa, .mem = &mem, .svc = null, .ix = ix, .snap = null, .cfg = conf, .rs = null, .sink = .{ .ctx = sink, .send = TestSink.send, .cancelled = TestSink.cancelled }, .deadline_ns = std.math.maxInt(i64) };
            defer c.unlock();
            try serve(&c, .transactions, &p, top);
        }
    };
    var total: u64 = 0;
    for (ntx) |n| total += n;
    // unfiltered and filtered, every frame written with the index unlocked
    {
        const ix = try history.Index.init(gpa, io, null);
        defer ix.deinit();
        for (blobs, seqs) |b, s| try ix.addCheckpoint(s, b);
        ix.publish(seqs[5]);
        var sink: TestSink = .{ .ix = ix, .io = io };
        try Run.go(ix, a, &cfg, &sink, try testRequest(a, seqs[0], 500, null), seqs[5]);
        try std.testing.expectEqual(total + 1, sink.frames); // every row, then the terminal
        var fsink: TestSink = .{ .ix = ix, .io = io };
        try Run.go(ix, a, &cfg, &fsink, try testRequest(a, seqs[0], 500, &sender), seqs[5]);
        try std.testing.expect(fsink.frames >= 2);
    }
    // retention raises the floor after the first chunk: the rows below it are reported below
    // the floor (sui-node's missing_row_error), not as missing
    {
        var k: usize = 1;
        var below: u64 = ntx[0];
        while (below <= cfg.transactions.chunk_max and k < 5) : (k += 1) below += ntx[k];
        if (below <= cfg.transactions.chunk_max) return error.SkipZigTest;
        const ix = try history.Index.init(gpa, io, null);
        defer ix.deinit();
        for (blobs, seqs) |b, s| try ix.addCheckpoint(s, b);
        ix.publish(seqs[5]);
        var sink: TestSink = .{ .ix = ix, .io = io, .prune_at = seqs[k] };
        try std.testing.expectError(error.Rpc, Run.go(ix, a, &cfg, &sink, try testRequest(a, seqs[0], 500, null), seqs[5]));
        const f = core.takeFailure();
        try std.testing.expectEqual(seqs[k], f.below_floor);
    }
    // a cancelled stream stops at the next item
    {
        const ix = try history.Index.init(gpa, io, null);
        defer ix.deinit();
        for (blobs, seqs) |b, s| try ix.addCheckpoint(s, b);
        ix.publish(seqs[5]);
        var sink: TestSink = .{ .ix = ix, .io = io, .cancel_after = 3 };
        try std.testing.expectError(error.Cancelled, Run.go(ix, a, &cfg, &sink, try testRequest(a, seqs[0], 500, null), seqs[5]));
        try std.testing.expectEqual(@as(usize, 3), sink.frames);
    }
}

test "List* over an index that begins above the node's lowest checkpoint (a backfill under way or given up): a start in the unindexed range is below the earliest available, with the index's low end; no start lists from that low end with no row missing after it" {
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const blobs = (try testCorpus(a, io)) orelse return error.SkipZigTest;
    var seqs: [6]u64 = undefined;
    var ntx: [6]u64 = undefined;
    for (blobs, 0..) |b, i| {
        const cp = try bcs.decode(types.CheckpointData, a, b[1..]);
        seqs[i] = cp.checkpoint_summary.data.sequence_number;
        ntx[i] = cp.transactions.len;
    }
    const cfg: Config = .{};
    const Run = struct {
        fn go(ix: *history.Index, aa: Allocator, conf: *const Config, sink: *TestSink, body: []const u8, top: u64) Err!void {
            var mem = Mem.init();
            defer mem.deinit();
            const p = try parse(aa, conf, .transactions, body);
            var c = Ctx{ .arena = aa, .mem = &mem, .svc = null, .ix = ix, .snap = null, .cfg = conf, .rs = null, .sink = .{ .ctx = sink, .send = TestSink.send, .cancelled = TestSink.cancelled }, .deadline_ns = std.math.maxInt(i64) };
            defer c.unlock();
            try serve(&c, .transactions, &p, top);
        }
    };
    // the store serves all six checkpoints; the index holds the last three
    const ix = try history.Index.init(gpa, io, null);
    defer ix.deinit();
    for (blobs[3..], seqs[3..]) |b, s| try ix.addCheckpoint(s, b);
    ix.publish(seqs[5]);
    // a start inside the unindexed range: OUT_OF_RANGE BELOW_EARLIEST_AVAILABLE naming the
    // index's low end as the lowest available checkpoint (sui-node's answer below its floor),
    // not a list that silently begins later
    for ([_]u64{ seqs[0], seqs[1], seqs[2] }) |start| {
        var sink: TestSink = .{ .ix = ix, .io = io };
        try std.testing.expectError(error.Rpc, Run.go(ix, a, &cfg, &sink, try testRequest(a, start, 500, null), seqs[5]));
        try std.testing.expectEqual(seqs[3], core.takeFailure().below_floor);
        try std.testing.expectEqual(@as(usize, 0), sink.frames);
    }
    // a start at the index's low end: every transaction of the indexed checkpoints, then the terminal
    {
        var sink: TestSink = .{ .ix = ix, .io = io };
        try Run.go(ix, a, &cfg, &sink, try testRequest(a, seqs[3], 500, null), seqs[5]);
        try std.testing.expectEqual(ntx[3] + ntx[4] + ntx[5] + 1, sink.frames);
    }
    // no start at all: the list begins at the index's low end, as on a sui-node whose index
    // begins there, and is whole from there on (no row of an indexed checkpoint is missing)
    {
        const buf = try a.alloc(u8, 64);
        var w = proto.Writer.init(buf);
        const m = try w.begin(1, 8);
        try w.string(1, "digest");
        try w.end(m);
        const o = try w.begin(5, 4);
        try w.uint(1, 500);
        try w.end(o);
        var sink: TestSink = .{ .ix = ix, .io = io };
        try Run.go(ix, a, &cfg, &sink, w.bytesWritten(), seqs[5]);
        try std.testing.expectEqual(ntx[3] + ntx[4] + ntx[5] + 1, sink.frames);
    }
}

test "ListCheckpoints filtered: one item per checkpoint holding a match, in scan order, then the terminal; a sparse filter under a small budget ends SCAN_LIMIT" {
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const blobs = (try testCorpus(a, io)) orelse return error.SkipZigTest;
    var seqs: [6]u64 = undefined;
    var sender: [32]u8 = undefined;
    var senders: [6]std.ArrayList([32]u8) = @splat(.empty);
    for (blobs, 0..) |b, i| {
        const cp = try bcs.decode(types.CheckpointData, a, b[1..]);
        seqs[i] = cp.checkpoint_summary.data.sequence_number;
        for (cp.transactions) |t| try senders[i].append(a, t.transaction.data.@"0".element().intent_message.value.V1.sender.@"0");
        if (i == 0) sender = cp.transactions[cp.transactions.len - 1].transaction.data.@"0".element().intent_message.value.V1.sender.@"0";
    }
    // the checkpoints with a transaction from `sender`, ascending
    var want: std.ArrayList(u64) = .empty;
    for (senders, seqs) |list, s| for (list.items) |x| if (std.mem.eql(u8, &x, &sender)) {
        try want.append(a, s);
        break;
    };
    const Rec = struct {
        cps: std.ArrayList(?u64) = .empty,
        a: Allocator,
        fn send(p: *anyopaque, bytes: []const u8) anyerror!void {
            const r: *@This() = @ptrCast(@alignCast(p));
            // ListCheckpointsResponse { checkpoint = 1, watermark = 2, end = 3 }: the watermark's checkpoint (field 2)
            var rd = proto.Reader.init(bytes);
            var cp: ?u64 = null;
            var data = true; // unit-test items carry no checkpoint message; the terminal has `end`
            while (try rd.next()) |f| switch (f.number) {
                3 => data = false,
                2 => {
                    var wr = proto.Reader.init(f.data);
                    while (try wr.next()) |wf| if (wf.number == 2) {
                        cp = wf.varint;
                    };
                },
                else => {},
            };
            try r.cps.append(r.a, if (data) cp else null);
        }
        fn cancelled(_: *anyopaque) bool {
            return false;
        }
    };
    const ix = try history.Index.init(gpa, io, null);
    defer ix.deinit();
    for (blobs, seqs) |b, s| try ix.addCheckpoint(s, b);
    ix.publish(seqs[5]);
    for ([_]bool{ true, false }) |asc| {
        const body = blk: {
            const buf = try a.alloc(u8, 512);
            var w = proto.Writer.init(buf);
            try w.uint(2, seqs[0]);
            var hex: [66]u8 = undefined;
            _ = try std.fmt.bufPrint(&hex, "0x{x}", .{&sender});
            const f = try w.begin(4, 100);
            const t = try w.begin(1, 90);
            const l = try w.begin(1, 80);
            const sp = try w.begin(2, 70);
            try w.string(1, &hex);
            try w.end(sp);
            try w.end(l);
            try w.end(t);
            try w.end(f);
            const o = try w.begin(5, 8);
            try w.uint(1, 100);
            if (!asc) try w.uint(4, 1); // ORDERING_DESCENDING
            try w.end(o);
            break :blk w.bytesWritten();
        };
        var mem = Mem.init();
        defer mem.deinit();
        const cfg: Config = .{};
        var rec: Rec = .{ .a = a };
        const p = try parse(a, &cfg, .checkpoints, body);
        var c = Ctx{ .arena = a, .mem = &mem, .svc = null, .ix = ix, .snap = null, .cfg = &cfg, .rs = null, .sink = .{ .ctx = &rec, .send = Rec.send, .cancelled = Rec.cancelled }, .deadline_ns = std.math.maxInt(i64) };
        defer c.unlock();
        try serve(&c, .checkpoints, &p, seqs[5]);
        // data frames: each matching checkpoint once, in scan order; then one terminal frame
        try std.testing.expectEqual(want.items.len + 1, rec.cps.items.len);
        for (want.items, 0..) |cp, i| {
            // an item's watermark covers its own checkpoint (the chunk's running bound)
            const got = rec.cps.items[if (asc) i else want.items.len - 1 - i];
            try std.testing.expectEqual(@as(?u64, cp), got);
        }
        try std.testing.expect(rec.cps.items[rec.cps.items.len - 1] == null);
    }
    // the same filter with a 1-bucket budget: the scan stops at its frontier with SCAN_LIMIT
    {
        const body = try testRequest(a, seqs[0], 100, &sender);
        var mem = Mem.init();
        defer mem.deinit();
        const cfg: Config = .{ .bitmap_bucket_scan_budget = 1, .chunk_bucket_scan_budget = 1 };
        var sink: TestSink = .{ .ix = ix, .io = io };
        const p = try parse(a, &cfg, .checkpoints, body);
        var c = Ctx{ .arena = a, .mem = &mem, .svc = null, .ix = ix, .snap = null, .cfg = &cfg, .rs = null, .sink = .{ .ctx = &sink, .send = TestSink.send, .cancelled = TestSink.cancelled }, .deadline_ns = std.math.maxInt(i64) };
        defer c.unlock();
        try serve(&c, .checkpoints, &p, seqs[5]);
        try std.testing.expect(sink.frames >= 1);
    }
}

test "ListCheckpoints filtered: a request budget spent inside a dense bucket ends SCAN_LIMIT (no spin on empty chunks)" {
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const blobs = (try testCorpus(a, io)) orelse return error.SkipZigTest;
    var seqs: [6]u64 = undefined;
    var sender: [32]u8 = undefined;
    var others: u64 = 0; // transactions not from `sender`: the hits of NOT sender
    for (blobs, 0..) |b, i| {
        const cp = try bcs.decode(types.CheckpointData, a, b[1..]);
        seqs[i] = cp.checkpoint_summary.data.sequence_number;
        if (i == 0) sender = cp.transactions[cp.transactions.len - 1].transaction.data.@"0".element().intent_message.value.V1.sender.@"0";
    }
    for (blobs) |b| {
        const cp = try bcs.decode(types.CheckpointData, a, b[1..]);
        for (cp.transactions) |t| {
            const from: [32]u8 = t.transaction.data.@"0".element().intent_message.value.V1.sender.@"0";
            if (!std.mem.eql(u8, &from, &sender)) others += 1;
        }
    }
    const Rec = struct {
        a: Allocator,
        data: usize = 0,
        frames: usize = 0,
        end: ?u64 = null,
        /// `drive` asks once per chunk: a scan that makes no progress keeps asking.
        polls: usize = 0,
        fn send(p: *anyopaque, bytes: []const u8) anyerror!void {
            const r: *@This() = @ptrCast(@alignCast(p));
            r.frames += 1;
            var rd = proto.Reader.init(bytes);
            var end: ?u64 = null;
            while (try rd.next()) |f| if (f.number == 3) {
                var er = proto.Reader.init(f.data);
                end = 0;
                while (try er.next()) |ef| if (ef.number == 1) {
                    end = ef.varint;
                };
            };
            // the last item of a full request carries ITEM_LIMIT on its own frame: still an item
            if (end) |e| {
                r.end = e;
                if (e == @intFromEnum(core.EndReason.item_limit)) r.data += 1;
            } else r.data += 1;
        }
        fn cancelled(p: *anyopaque) bool {
            const r: *@This() = @ptrCast(@alignCast(p));
            r.polls += 1;
            return r.polls > 100_000;
        }
    };
    const ix = try history.Index.init(gpa, io, null);
    defer ix.deinit();
    for (blobs, seqs) |b, s| try ix.addCheckpoint(s, b);
    ix.publish(seqs[5]);
    for ([_]bool{ true, false }) |asc| {
        // NOT sender: the tx universe minus one sender, so the first bucket the budget pays for
        // holds more hits than the request takes
        const body = blk: {
            const buf = try a.alloc(u8, 512);
            var w = proto.Writer.init(buf);
            try w.uint(2, seqs[0]);
            var hex: [66]u8 = undefined;
            _ = try std.fmt.bufPrint(&hex, "0x{x}", .{&sender});
            const f = try w.begin(4, 100);
            const t = try w.begin(1, 90);
            const l = try w.begin(1, 80);
            try w.uint(1, 1); // negated
            const sp = try w.begin(2, 70);
            try w.string(1, &hex);
            try w.end(sp);
            try w.end(l);
            try w.end(t);
            try w.end(f);
            const o = try w.begin(5, 8);
            try w.uint(1, 2);
            if (!asc) try w.uint(4, 1); // ORDERING_DESCENDING
            try w.end(o);
            break :blk w.bytesWritten();
        };
        var mem = Mem.init();
        defer mem.deinit();
        const cfg: Config = .{ .bitmap_bucket_scan_budget = 1, .chunk_bucket_scan_budget = 1 };
        var rec: Rec = .{ .a = a };
        const p = try parse(a, &cfg, .checkpoints, body);
        var c = Ctx{ .arena = a, .mem = &mem, .svc = null, .ix = ix, .snap = null, .cfg = &cfg, .rs = null, .sink = .{ .ctx = &rec, .send = Rec.send, .cancelled = Rec.cancelled }, .deadline_ns = std.math.maxInt(i64) };
        defer c.unlock();
        try serve(&c, .checkpoints, &p, seqs[5]);
        try std.testing.expect(rec.polls < 100); // a handful of chunks, not a spin
        try std.testing.expect(rec.data >= 1 and rec.data <= 2);
        if (rec.data < 2) {
            // fewer items than the limit: the terminal follows, and with hits left it is the budget stop
            try std.testing.expectEqual(rec.data + 1, rec.frames);
            if (others >= 3) try std.testing.expectEqual(@as(?u64, @intFromEnum(core.EndReason.scan_limit)), rec.end);
        } else {
            // two distinct checkpoints from the first drain: the request is full, ITEM_LIMIT on the last item
            try std.testing.expectEqual(@as(usize, 2), rec.frames);
            try std.testing.expectEqual(@as(?u64, @intFromEnum(core.EndReason.item_limit)), rec.end);
        }
    }
}

test "mergeCheckpointSeq: consecutive hits of one checkpoint are one item; past the chunk target they buffer; past the request limit they stop" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var mem = Mem.init();
    defer mem.deinit();
    const cfg: Config = .{};
    var ix_dummy: history.Index = undefined;
    var c = Ctx{ .arena = a, .mem = &mem, .svc = null, .ix = &ix_dummy, .snap = null, .cfg = &cfg, .rs = null, .sink = undefined, .deadline_ns = 0 };
    var f: CpFilter = .{ .query = undefined, .tx_range = null, .entry = 0 };
    var cps: std.ArrayList(u64) = .empty;
    for ([_]u64{ 5, 5, 5, 6, 7, 7, 8 }) |cp| _ = try mergeCheckpointSeq(&c, &f, &cps, a, cp, 2, 3);
    try std.testing.expectEqualSlices(u64, &.{ 5, 6 }, cps.items);
    try std.testing.expectEqualSlices(u64, &.{7}, f.buffered.items);
    try std.testing.expect(!(try mergeCheckpointSeq(&c, &f, &cps, a, 9, 2, 3)));
}
