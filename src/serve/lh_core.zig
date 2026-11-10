//! Ledger-history core (sui-rpc-api 1.83.1 `ledger_history/*`, `sui-rpc-cursor`): positions,
//! cursors, query options, checkpoint and scan-window resolution, watermarks and terminals. Pure
//! logic over plain values; the index reads come in through `Boundary` callbacks. Every function
//! names its Rust original; behaviour (including the odd corners) follows it line by line.
const std = @import("std");
const proto = @import("proto.zig");

// ---------------------------------------------------------------- positions

pub const Space = enum { checkpoints, transactions, events };

/// A scan coordinate: `a` is the checkpoint (checkpoint space), the tx_seq (transaction space)
/// or the tx_seq of an IntraTxCoordinate (event space, `b` = event index). Ordered by (a, b).
pub const Pos = struct {
    a: u64,
    b: u32 = 0,

    pub fn lt(x: Pos, y: Pos) bool {
        return x.a < y.a or (x.a == y.a and x.b < y.b);
    }
    pub fn le(x: Pos, y: Pos) bool {
        return !lt(y, x);
    }
    pub fn eq(x: Pos, y: Pos) bool {
        return x.a == y.a and x.b == y.b;
    }
    pub fn max(x: Pos, y: Pos) Pos {
        return if (lt(x, y)) y else x;
    }
    pub fn min(x: Pos, y: Pos) Pos {
        return if (lt(y, x)) y else x;
    }
    /// `ScanPosition::successor` (u64 or IntraTxCoordinate).
    pub fn successor(x: Pos, intra: bool) ?Pos {
        if (intra) {
            if (x.b < std.math.maxInt(u32)) return .{ .a = x.a, .b = x.b + 1 };
            if (x.a == std.math.maxInt(u64)) return null;
            return .{ .a = x.a + 1, .b = 0 };
        }
        if (x.a == std.math.maxInt(u64)) return null;
        return .{ .a = x.a + 1 };
    }
};

pub const Bound = union(enum) {
    inc: Pos,
    exc: Pos,
    unb,
};

pub const Bounds = struct {
    lo: Bound,
    hi: Bound,

    pub fn fromRange(s: Pos, e: Pos) Bounds {
        return .{ .lo = .{ .inc = s }, .hi = .{ .exc = e } };
    }
    pub fn emptyAt(p: Pos) Bounds {
        return .{ .lo = .{ .inc = p }, .hi = .{ .exc = p } };
    }
    pub fn isEmpty(b: Bounds) bool {
        return switch (b.lo) {
            .unb => false,
            .inc => |a| switch (b.hi) {
                .unb => false,
                .exc => |h| !Pos.lt(a, h),
                .inc => |h| Pos.lt(h, a),
            },
            .exc => |a| switch (b.hi) {
                .unb => false,
                .exc, .inc => |h| !Pos.lt(a, h),
            },
        };
    }
    pub fn contains(b: Bounds, p: Pos) bool {
        const above = switch (b.lo) {
            .inc => |l| Pos.le(l, p),
            .exc => |l| Pos.lt(l, p),
            .unb => true,
        };
        const below = switch (b.hi) {
            .inc => |h| Pos.le(p, h),
            .exc => |h| Pos.lt(p, h),
            .unb => true,
        };
        return above and below;
    }
    pub fn admitsNoPosition(b: Bounds, intra: bool) bool {
        var lo = b.lo;
        if (b.lo == .exc) {
            const s = b.lo.exc.successor(intra) orelse return true;
            lo = .{ .inc = s };
        }
        return (Bounds{ .lo = lo, .hi = b.hi }).isEmpty();
    }
    /// `ScanBounds<u64>::to_range`.
    pub fn toRange(b: Bounds) [2]u64 {
        const s: u64 = switch (b.lo) {
            .inc => |p| p.a,
            .exc => |p| p.a +| 1,
            .unb => 0,
        };
        const e: u64 = switch (b.hi) {
            .inc => |p| p.a +| 1,
            .exc => |p| p.a,
            .unb => std.math.maxInt(u64),
        };
        return .{ s, e };
    }
    /// `ScanBounds<IntraTxCoordinate>::tx_range`.
    pub fn txRange(b: Bounds) ?[2]u64 {
        const s: u64 = switch (b.lo) {
            .inc, .exc => |p| p.a,
            .unb => 0,
        };
        const e: u64 = switch (b.hi) {
            .exc => |p| if (p.b == 0) p.a else p.a +| 1,
            .inc => |p| p.a +| 1,
            .unb => std.math.maxInt(u64),
        };
        return if (s < e) .{ s, e } else null;
    }
};

/// `LedgerPoint`: (checkpoint, transaction_index, event_index), lexicographic.
pub const Point = struct {
    cp: u64,
    tx: u64 = 0,
    ev: u32 = 0,

    pub const genesis: Point = .{ .cp = 0 };
    pub fn lt(x: Point, y: Point) bool {
        if (x.cp != y.cp) return x.cp < y.cp;
        if (x.tx != y.tx) return x.tx < y.tx;
        return x.ev < y.ev;
    }
    pub fn itemResume(p: Point, space: Space, asc: bool) Point {
        if (!asc) return p;
        return switch (space) {
            .checkpoints => .{ .cp = p.cp +| 1 },
            .transactions => .{ .cp = p.cp, .tx = p.tx +| 1 },
            .events => .{ .cp = p.cp, .tx = p.tx, .ev = p.ev +| 1 },
        };
    }
    pub fn publicPosition(p: Point, space: Space) ?Point {
        return switch (space) {
            .checkpoints => null,
            .transactions => .{ .cp = p.cp, .tx = p.tx, .ev = 0 },
            .events => p,
        };
    }
};

// ---------------------------------------------------------------- cursors (sui-rpc-cursor)

pub const Kind = enum(u8) { item = 1, boundary = 2 };

pub const Position = struct {
    space: Space,
    checkpoint: u64,
    tx_seq: u64 = 0,
    event_index: u32 = 0,

    pub fn coordinate(p: Position) Pos {
        return switch (p.space) {
            .checkpoints => .{ .a = p.checkpoint },
            .transactions => .{ .a = p.tx_seq },
            .events => .{ .a = p.tx_seq, .b = p.event_index },
        };
    }
    pub fn at(space: Space, checkpoint: u64, pos: Pos) Position {
        return switch (space) {
            .checkpoints => .{ .space = space, .checkpoint = pos.a },
            .transactions => .{ .space = space, .checkpoint = checkpoint, .tx_seq = pos.a },
            .events => .{ .space = space, .checkpoint = checkpoint, .tx_seq = pos.a, .event_index = pos.b },
        };
    }
};

pub const Cursor = struct {
    kind: Kind,
    pos: Position,
    public: ?Point = null,

    pub fn coordinate(c: Cursor) Pos {
        return c.pos.coordinate();
    }

    /// `CursorToken::encode`: prost, fields in tag order (kind 5, position 6/7/8, public 9).
    pub fn encode(c: Cursor, out: *[64]u8) []const u8 {
        var w = proto.Writer.init(out);
        w.uint(5, @intFromEnum(c.kind)) catch unreachable;
        const tag: u32 = switch (c.pos.space) {
            .checkpoints => 6,
            .transactions => 7,
            .events => 8,
        };
        const m = w.begin(tag, 32) catch unreachable;
        w.uint(1, c.pos.checkpoint) catch unreachable;
        if (c.pos.space != .checkpoints) w.uint(2, c.pos.tx_seq) catch unreachable;
        if (c.pos.space == .events) w.uint(3, c.pos.event_index) catch unreachable;
        w.end(m) catch unreachable;
        if (c.public) |p| {
            const pm = w.begin(9, 32) catch unreachable;
            if (p.cp != 0) w.uint(1, p.cp) catch unreachable;
            if (p.tx != 0) w.uint(2, p.tx) catch unreachable;
            if (p.ev != 0) w.uint(3, p.ev) catch unreachable;
            w.end(pm) catch unreachable;
        }
        return w.bytesWritten();
    }

    /// `CursorToken::decode` (current format, then the legacy one).
    pub fn decode(bytes: []const u8) ?Cursor {
        return decodeCurrent(bytes) catch null orelse (decodeLegacy(bytes) catch null);
    }

    fn decodeCurrent(bytes: []const u8) !?Cursor {
        var kind: i64 = 0;
        var space: ?Space = null;
        var pos_bytes: []const u8 = "";
        var public: ?Point = null;
        var r = proto.Reader.init(bytes);
        while (try r.next()) |f| switch (f.number) {
            5 => kind = @bitCast(try proto.Reader.varintOf(f)),
            6, 7, 8 => {
                space = switch (f.number) {
                    6 => .checkpoints,
                    7 => .transactions,
                    else => .events,
                };
                pos_bytes = try proto.Reader.bytesOf(f);
            },
            9 => {
                var p: Point = public orelse .{ .cp = 0 };
                var pr = proto.Reader.init(try proto.Reader.bytesOf(f));
                while (try pr.next()) |g| switch (g.number) {
                    1 => p.cp = try proto.Reader.varintOf(g),
                    2 => p.tx = try proto.Reader.varintOf(g),
                    3 => p.ev = @truncate(try proto.Reader.varintOf(g)),
                    else => {},
                };
                public = p;
            },
            else => {},
        };
        const k: Kind = switch (@as(i32, @truncate(kind))) {
            1 => .item,
            2 => .boundary,
            else => return null,
        };
        const sp = space orelse return null;
        var cp: ?u64 = null;
        var tx: ?u64 = null;
        var ev: ?u32 = null;
        var pr = proto.Reader.init(pos_bytes);
        while (try pr.next()) |g| switch (g.number) {
            1 => cp = try proto.Reader.varintOf(g),
            2 => tx = try proto.Reader.varintOf(g),
            3 => ev = @truncate(try proto.Reader.varintOf(g)),
            else => {},
        };
        const pos: Position = switch (sp) {
            .checkpoints => .{ .space = sp, .checkpoint = cp orelse return null },
            .transactions => .{ .space = sp, .checkpoint = cp orelse 0, .tx_seq = tx orelse return null },
            .events => .{ .space = sp, .checkpoint = cp orelse 0, .tx_seq = tx orelse return null, .event_index = ev orelse return null },
        };
        return .{ .kind = k, .pos = pos, .public = public };
    }

    fn decodeLegacy(bytes: []const u8) !?Cursor {
        var qt: i64 = 0;
        var kind: i64 = 0;
        var cp: ?u64 = null;
        var position: ?u64 = null;
        var r = proto.Reader.init(bytes);
        while (try r.next()) |f| switch (f.number) {
            1 => qt = @bitCast(try proto.Reader.varintOf(f)),
            2 => kind = @bitCast(try proto.Reader.varintOf(f)),
            3 => cp = try proto.Reader.varintOf(f),
            4 => position = try proto.Reader.varintOf(f),
            else => {},
        };
        const k: Kind = switch (@as(i32, @truncate(kind))) {
            1 => .item,
            2 => .boundary,
            else => return null,
        };
        const c = cp orelse return null;
        const p = position orelse return null;
        const pos: Position = switch (@as(i32, @truncate(qt))) {
            1 => .{ .space = .checkpoints, .checkpoint = p },
            2 => .{ .space = .transactions, .checkpoint = c, .tx_seq = p },
            3 => .{ .space = .events, .checkpoint = c, .tx_seq = p >> 16, .event_index = @truncate(p & 0xFFFF) },
            else => return null,
        };
        return .{ .kind = k, .pos = pos };
    }
};

/// `LedgerPoint::of_cursor`.
pub fn pointOfCursor(c: Cursor) ?Point {
    return switch (c.pos.space) {
        .checkpoints => .{ .cp = c.pos.checkpoint },
        else => c.public,
    };
}

// ---------------------------------------------------------------- watermarks

pub const Watermark = struct {
    cursor: Cursor,
    checkpoint: ?u64,
    /// cursor_position as a ledger point, written per the cursor's space.
    position: ?Point,

    /// Watermark { cursor = 1, checkpoint = 2, cursor_position = 4 }.
    pub fn write(wm: Watermark, w: *proto.Writer, field: u32) proto.Error!void {
        const m = try w.begin(field, 96);
        var buf: [64]u8 = undefined;
        try w.bytes(1, wm.cursor.encode(&buf));
        if (wm.checkpoint) |c| try w.uint(2, c);
        if (wm.position) |p| {
            const pm = try w.begin(4, 32);
            try w.uint(1, p.cp);
            switch (wm.cursor.pos.space) {
                .checkpoints => {},
                .transactions => try w.uint(2, p.tx),
                .events => {
                    try w.uint(2, p.tx);
                    try w.uint(3, p.ev);
                },
            }
            try w.end(pm);
        }
        try w.end(m);
    }
};

pub const Tlp = struct {
    cursor_position: ?Point = null,
    cursor_point: ?Point = null,

    pub fn known(p: Point) Tlp {
        return .{ .cursor_position = p, .cursor_point = p };
    }
};

pub fn cursorWatermark(position: Position, kind: Kind, ledger: Tlp, boundary: ?u64) Watermark {
    return .{
        .cursor = .{ .kind = kind, .pos = position, .public = if (ledger.cursor_point) |p| p.publicPosition(position.space) else null },
        .checkpoint = boundary,
        .position = ledger.cursor_position,
    };
}

pub fn itemWatermark(position: Position, key: Point, asc: bool, boundary: ?u64) Watermark {
    return cursorWatermark(position, .item, .{ .cursor_position = key.itemResume(position.space, asc), .cursor_point = key }, boundary);
}

pub fn boundaryWatermark(position: Position, cursor_position: Point, boundary: ?u64) Watermark {
    return cursorWatermark(position, .boundary, Tlp.known(cursor_position), boundary);
}

pub fn mergeCovered(covered: ?u64, candidate: u64, asc: bool) ?u64 {
    const b = covered orelse return candidate;
    return if (asc) @max(b, candidate) else @min(b, candidate);
}

/// `advance_covered_bound_before_checkpoint`.
pub fn advanceCoveredBefore(covered: ?u64, incomplete: u64, entry: u64, asc: bool) ?u64 {
    const cand: ?u64 = if (asc)
        (if (incomplete > 0 and incomplete - 1 >= entry) incomplete - 1 else null)
    else
        (if (incomplete < std.math.maxInt(u64) and incomplete + 1 <= entry) incomplete + 1 else null);
    if (cand) |c| return mergeCovered(covered, c, asc);
    return covered;
}

/// `scan_frontier_cursor_cp`.
pub fn scanFrontierCursorCp(checkpoint: ?u64, frontier: u64, asc: bool) ?u64 {
    if (checkpoint) |cp| return if (asc) cp else cp +| 1;
    if ((asc and frontier == 0) or (!asc and frontier == std.math.maxInt(u64))) return frontier;
    return null;
}

pub const Exhaustion = union(enum) {
    ledger_tip,
    checkpoint_bound,
    cursor_bound: Kind,
    serving_floor: u64,
};

pub const RangeEnd = struct {
    exhaustion: Exhaustion,
    position: Position,
    ledger: Tlp,
    natural_end_claim: ?u64,

    pub fn terminal(r: RangeEnd) Terminal {
        return switch (r.exhaustion) {
            .ledger_tip => .{ .natural = .{ .reason = .ledger_tip, .position = r.position, .ledger = r.ledger, .claim = r.natural_end_claim } },
            .checkpoint_bound => .{ .natural = .{ .reason = .checkpoint_bound, .position = r.position, .ledger = r.ledger, .claim = r.natural_end_claim } },
            .cursor_bound => |k| .{ .cursor_bound = .{ .position = r.position, .ledger = r.ledger, .kind = k } },
            .serving_floor => |f| .{ .serving_floor = .{ .position = r.position, .ledger = r.ledger, .floor = f } },
        };
    }
};

pub const EndReason = enum(u8) { unknown = 0, item_limit = 1, scan_limit = 2, checkpoint_bound = 3, cursor_bound = 4, ledger_tip = 5 };

pub const Terminal = union(enum) {
    scan_limit: Watermark,
    natural: struct { reason: EndReason, position: Position, ledger: Tlp, claim: ?u64 },
    cursor_bound: struct { position: Position, ledger: Tlp, kind: Kind },
    serving_floor: struct { position: Position, ledger: Tlp, floor: u64 },

    /// null = the serving-floor error (`below_serving_floor`).
    pub fn reason(t: Terminal) ?EndReason {
        return switch (t) {
            .scan_limit => .scan_limit,
            .natural => |n| n.reason,
            .cursor_bound => .cursor_bound,
            .serving_floor => null,
        };
    }
    pub fn intoWatermark(t: Terminal, covered: ?u64) Watermark {
        return switch (t) {
            .scan_limit => |w| w,
            .natural => |n| cursorWatermark(n.position, .boundary, n.ledger, n.claim),
            .cursor_bound => |c| cursorWatermark(c.position, c.kind, c.ledger, covered),
            .serving_floor => |s| cursorWatermark(s.position, .boundary, s.ledger, s.floor),
        };
    }
};

// ---------------------------------------------------------------- errors

pub const Failure = union(enum) {
    /// FieldViolation (INVALID_ARGUMENT with BadRequest).
    field: struct { field: []const u8, description: []const u8, missing: bool = false },
    /// OUT_OF_RANGE BELOW_EARLIEST_AVAILABLE.
    below_floor: u64,
    /// OUT_OF_RANGE ABOVE_LATEST_AVAILABLE.
    above_latest: struct { bound: []const u8, requested: u64, hi_exclusive: u64 },
    internal: []const u8,
    unavailable: []const u8,
};

pub var last_failure: Failure = .{ .internal = "" };
threadlocal var failure_tls: Failure = .{ .internal = "" };

pub fn fail(f: Failure) error{Rpc} {
    failure_tls = f;
    return error.Rpc;
}
pub fn takeFailure() Failure {
    return failure_tls;
}

// ---------------------------------------------------------------- query options

pub const Options = struct {
    limit: usize,
    asc: bool,
    after: ?Cursor,
    before: ?Cursor,
};

pub const RawOptions = struct {
    limit: ?u32 = null,
    after: ?[]const u8 = null,
    before: ?[]const u8 = null,
    ordering: ?i32 = null,
};

/// `QueryOptions::*_from_proto`.
pub fn parseOptions(raw: ?RawOptions, space: Space, default_limit: u32, max_limit: u32) error{Rpc}!Options {
    const o = raw orelse RawOptions{};
    const limit = std.math.clamp(o.limit orelse default_limit, 1, max_limit);
    const asc = if (o.ordering) |v| switch (v) {
        0 => true,
        1 => false,
        else => return fail(.{ .field = .{ .field = "options.ordering", .description = "invalid ordering" } }),
    } else true;
    return .{
        .limit = limit,
        .asc = asc,
        .after = try parseCursor("options.after", o.after, space),
        .before = try parseCursor("options.before", o.before, space),
    };
}

fn parseCursor(field: []const u8, bytes: ?[]const u8, space: Space) error{Rpc}!?Cursor {
    const b = bytes orelse return null;
    const c = Cursor.decode(b) orelse return fail(.{ .field = .{ .field = field, .description = "invalid cursor" } });
    if (c.pos.space != space) return fail(.{ .field = .{ .field = field, .description = "invalid cursor" } });
    return c;
}

pub fn validateCheckpointBounds(start: ?u64, end: ?u64) error{Rpc}!void {
    if (end) |e| if (e < (start orelse 0))
        return fail(.{ .field = .{ .field = "end_checkpoint", .description = "end_checkpoint must be greater than or equal to start_checkpoint" } });
}

// ---------------------------------------------------------------- checkpoint range

pub const CpRange = struct {
    s: u64,
    e: u64,
    exhaustion: Exhaustion,
    reaches_tip: bool,

    pub fn isEmpty(r: CpRange) bool {
        return r.s >= r.e;
    }
    fn emptyAt(cp: u64, ex: Exhaustion, tip: bool) CpRange {
        return .{ .s = cp, .e = cp, .exhaustion = ex, .reaches_tip = tip };
    }
    fn terminalCheckpoint(r: CpRange, asc: bool) u64 {
        return if (asc) r.e else r.s;
    }

    /// `ResolvedCheckpointRange::from_request`.
    pub fn fromRequest(start_cp: ?u64, end_cp: ?u64, hi_excl: u64, o: *const Options) error{Rpc}!CpRange {
        try validateCheckpointBounds(start_cp, end_cp);
        const start = start_cp orelse 0;
        if (!o.asc) {
            if (end_cp) |e| {
                if (e > hi_excl) return fail(.{ .above_latest = .{ .bound = "end_checkpoint", .requested = e, .hi_exclusive = hi_excl } });
            } else if (start >= hi_excl) return fail(.{ .above_latest = .{ .bound = "start_checkpoint", .requested = start, .hi_exclusive = hi_excl } });
        }
        const requested_end = end_cp orelse hi_excl;
        const reaches = end_cp == null or requested_end > hi_excl;
        const end = @min(requested_end, hi_excl);
        const ex: Exhaustion = if (o.asc and reaches) .ledger_tip else .checkpoint_bound;
        if (o.asc and start >= hi_excl) return emptyAt(hi_excl, .ledger_tip, reaches);
        if (start >= end) {
            const cp = if (o.asc) end else start;
            return emptyAt(cp, ex, reaches and cp == hi_excl);
        }
        return .{ .s = start, .e = end, .exhaustion = ex, .reaches_tip = reaches and end == hi_excl };
    }
};

pub const LedgerWindow = struct {
    start: Point,
    end: Point,
    requested: ?[2]Point = null,

    /// `LedgerWindow::checkpoints`.
    pub fn checkpoints(s: u64, e: u64, start_cp: ?u64, end_cp: ?u64) LedgerWindow {
        return .{
            .start = .{ .cp = s },
            .end = .{ .cp = e },
            .requested = if (s >= e) .{ .{ .cp = start_cp orelse 0 }, .{ .cp = end_cp orelse e } } else null,
        };
    }
};

pub const Window = struct {
    s: Pos,
    e: Pos,
    start_cuts: bool = false,
    end_cuts: bool = false,
    ledger: LedgerWindow,
};

/// `CheckpointPositions` (start/end position within the edge checkpoints).
pub const InCp = struct { tx: u64, ev: u32 = 0 };

pub const CpPositions = struct {
    start: ?InCp = null,
    end: ?InCp = null,
    start_cp: ?u64 = null,
    end_cp: ?u64 = null,

    fn requestedStart(p: CpPositions) Point {
        const cp = p.start_cp orelse 0;
        return if (p.start) |s| .{ .cp = cp, .tx = s.tx, .ev = s.ev } else .{ .cp = cp };
    }
    fn requestedEnd(p: CpPositions) ?Point {
        const e = p.end_cp orelse return null;
        if (p.end) |en| if (e > 0) return .{ .cp = e - 1, .tx = en.tx, .ev = en.ev };
        return .{ .cp = e };
    }

    /// `CheckpointPositions::narrow`: `boundary(cp)` = first tx_seq of checkpoint cp.
    pub fn narrow(p: CpPositions, ws: u64, we: u64, intra: bool, ctx: anytype, comptime boundary: fn (@TypeOf(ctx), u64) error{Rpc}!u64) error{Rpc}!Window {
        const window_start = try boundary(ctx, ws);
        const sot = Pos{ .a = window_start };
        if (ws >= we) {
            const edge_point = Point{ .cp = ws };
            return .{ .s = sot, .e = sot, .ledger = .{ .start = edge_point, .end = edge_point, .requested = .{ p.requestedStart(), p.requestedEnd() orelse edge_point } } };
        }
        const window_end = try boundary(ctx, we);
        var start: Pos = sot;
        var lstart: Point = .{ .cp = ws };
        if (p.start) |st| {
            const next_cp = try boundary(ctx, ws + 1);
            const tx_seq = window_start +| st.tx;
            if (tx_seq < next_cp) {
                start = .{ .a = tx_seq, .b = if (intra) st.ev else 0 };
                lstart = .{ .cp = ws, .tx = st.tx, .ev = st.ev };
            } else {
                start = .{ .a = next_cp };
                lstart = .{ .cp = ws + 1 };
            }
        }
        var end: Pos = .{ .a = window_end };
        var lend: Point = .{ .cp = we };
        if (p.end) |en| if (p.end_cp != null and p.end_cp.? == we) {
            const tx_seq = (try boundary(ctx, we - 1)) +| en.tx;
            if (tx_seq < window_end) {
                end = .{ .a = tx_seq, .b = if (intra) en.ev else 0 };
                lend = .{ .cp = we - 1, .tx = en.tx, .ev = en.ev };
            }
        };
        return .{
            .s = start,
            .e = end,
            .start_cuts = !start.eq(sot),
            .end_cuts = !end.eq(.{ .a = window_end }),
            .ledger = .{ .start = lstart, .end = lend },
        };
    }
};

// ---------------------------------------------------------------- resolved scan

pub const Scan = struct {
    bounds: Bounds,
    entry_checkpoint: u64,
    end_checkpoint: u64,
    end_position: Pos,
    exhaustion: Exhaustion,
    window_terminal_checkpoint: ?u64,
    intra: bool,

    pub fn isEmpty(s: Scan) bool {
        return s.bounds.isEmpty();
    }

    /// `ResolvedScan::resolve`.
    pub fn resolve(cp: CpRange, window: Window, o: *const Options, intra: bool) error{Rpc}!Scan {
        if (cp.reaches_tip) try rejectDescendingCursorsPastTip(o, window.e, cp.e, intra);
        var rs = window.s;
        var re = window.e;
        if (!rs.le(re)) {
            if (o.asc) rs = re else re = rs;
        }
        const entry = if (cp.isEmpty()) cp.e else if (o.asc) cp.s else cp.e - 1;
        const terminal_cp = if (o.asc and window.end_cuts) cp.e - 1 else if (!o.asc and window.start_cuts) cp.s + 1 else cp.terminalCheckpoint(o.asc);
        var r = Scan{
            .bounds = Bounds.fromRange(rs, re),
            .entry_checkpoint = entry,
            .end_checkpoint = terminal_cp,
            .end_position = if (o.asc) re else rs,
            .exhaustion = cp.exhaustion,
            .window_terminal_checkpoint = if (!cp.isEmpty()) terminal_cp else null,
            .intra = intra,
        };
        r.applyCursorBounds(o);
        if (cp.reaches_tip) if (ascendingAfterPastTipEnd(o, re, intra)) |x| {
            r.bounds = Bounds.emptyAt(x.pos);
            r.end_checkpoint = x.cp;
            r.end_position = x.pos;
            r.exhaustion = x.ex;
            r.window_terminal_checkpoint = null;
            return r;
        };
        if (!cp.isEmpty() and r.bounds.admitsNoPosition(intra)) if (startingCursorEnd(o, terminal_cp, rs, re, intra)) |x| {
            r.bounds = Bounds.emptyAt(x.pos);
            r.end_checkpoint = x.cp;
            r.end_position = x.pos;
            r.exhaustion = cp.exhaustion;
            return r;
        };
        return r;
    }

    fn setTerminal(s: *Scan, cp: u64, pos: Pos, ex: Exhaustion) void {
        s.end_checkpoint = cp;
        s.end_position = pos;
        s.exhaustion = ex;
    }

    fn applyCursorBounds(s: *Scan, o: *const Options) void {
        if (s.isEmpty()) return;
        var term = s.applyAfter(o);
        if (s.applyBefore(o)) |t| term = t;
        if (term) |t| {
            s.setTerminal(t.cp, t.pos, .{ .cursor_bound = t.kind });
            s.bounds = Bounds.emptyAt(s.end_position);
        }
    }

    const CursorTerm = struct { cp: u64, pos: Pos, kind: Kind };

    fn applyAfter(s: *Scan, o: *const Options) ?CursorTerm {
        const c = o.after orelse return null;
        const cp = c.pos.checkpoint;
        const pos = c.coordinate();
        const cand: Bound = if (c.kind == .item) .{ .exc = pos } else .{ .inc = pos };
        if (!lowerBoundGte(cand, s.bounds.lo)) return null;
        const dt = afterResume(pos, c.kind, s.intra);
        if (!o.asc) s.setTerminal(cp, dt.pos, .{ .cursor_bound = dt.kind });
        s.bounds.lo = cand;
        if (!s.bounds.isEmpty()) return null;
        return if (o.asc) .{ .cp = cp, .pos = pos, .kind = c.kind } else .{ .cp = cp, .pos = dt.pos, .kind = dt.kind };
    }

    fn applyBefore(s: *Scan, o: *const Options) ?CursorTerm {
        const c = o.before orelse return null;
        const cp = c.pos.checkpoint;
        const pos = c.coordinate();
        const admits = switch (s.bounds.hi) {
            .inc, .exc => |h| pos.le(h),
            .unb => true,
        };
        if (!admits) return null;
        if (o.asc) s.setTerminal(cp, pos, .{ .cursor_bound = .boundary });
        s.bounds.hi = .{ .exc = pos };
        if (!s.bounds.isEmpty()) return null;
        return .{ .cp = cp, .pos = pos, .kind = .boundary };
    }

    /// `ResolvedScan::apply_serving_floor`.
    pub fn applyServingFloor(s: *Scan, floor: Pos, floor_cp: u64, o: *const Options) error{Rpc}!void {
        const floored = Bounds{ .lo = .{ .inc = floor }, .hi = s.bounds.hi };
        if (floored.isEmpty()) return fail(.{ .below_floor = floor_cp });
        s.bounds.lo = .{ .inc = floor };
        if (o.asc) {
            s.entry_checkpoint = @max(s.entry_checkpoint, floor_cp);
        } else {
            s.setTerminal(floor_cp, floor, .{ .serving_floor = floor_cp });
        }
    }

    pub fn naturalEndClaim(s: Scan, o: *const Options) ?u64 {
        const w = s.window_terminal_checkpoint orelse return null;
        if (o.asc) {
            if (w == 0) return null;
            return if (w - 1 >= s.entry_checkpoint) w - 1 else null;
        }
        return if (w <= s.entry_checkpoint) w else null;
    }

    pub fn rangeEnd(s: Scan, window: Window, o: *const Options, space: Space) RangeEnd {
        return .{
            .exhaustion = s.exhaustion,
            .position = Position.at(space, s.end_checkpoint, s.end_position),
            .ledger = s.endLedgerPosition(window, o),
            .natural_end_claim = s.naturalEndClaim(o),
        };
    }

    fn endLedgerPosition(s: Scan, window: Window, o: *const Options) Tlp {
        if (s.exhaustion == .serving_floor) return Tlp.known(.{ .cp = s.exhaustion.serving_floor });
        const cursor_point: ?Point = if (requestCursorPoint(o, s.end_position, s.intra)) |p| p else windowEdgePoint(window, o.asc, s.end_position);
        if (window.ledger.requested) |req| {
            return .{ .cursor_position = if (o.asc) req[0] else req[1], .cursor_point = cursor_point };
        }
        const position: Pos = if (o.asc) blk: {
            const entry = if (o.after) |a| afterResume(a.coordinate(), a.kind, s.intra).pos.max(window.s) else window.s;
            break :blk s.end_position.max(entry);
        } else blk: {
            const entry = if (o.before) |b| b.coordinate().min(window.e) else window.e;
            break :blk s.end_position.min(entry);
        };
        const cursor_position: ?Point = windowEdgePoint(window, o.asc, position) orelse (if (requestCursorPoint(o, position, s.intra)) |p| p else null);
        return .{ .cursor_position = cursor_position, .cursor_point = cursor_point };
    }

    pub fn range(s: Scan) [2]u64 {
        return s.bounds.toRange();
    }
};

fn lowerBoundGte(cand: Bound, cur: Bound) bool {
    const ck = lowerKey(cand) orelse return false;
    const uk = lowerKey(cur) orelse return true;
    if (ck.p.eq(uk.p)) return ck.x >= uk.x;
    return uk.p.lt(ck.p);
}
fn lowerKey(b: Bound) ?struct { p: Pos, x: u8 } {
    return switch (b) {
        .inc => |p| .{ .p = p, .x = 0 },
        .exc => |p| .{ .p = p, .x = 1 },
        .unb => null,
    };
}

const Resumed = struct { pos: Pos, kind: Kind };

/// `after_resume`.
fn afterResume(pos: Pos, kind: Kind, intra: bool) Resumed {
    if (kind == .boundary) return .{ .pos = pos, .kind = kind };
    if (pos.successor(intra)) |n| return .{ .pos = n, .kind = .boundary };
    return .{ .pos = pos, .kind = kind };
}

/// `request_cursor_point`: null = None, .{null} = Some(None).
fn requestCursorPoint(o: *const Options, position: Pos, intra: bool) ??Point {
    var after: ??Point = null;
    if (o.after) |a| {
        const r = afterResume(a.coordinate(), a.kind, intra);
        if (r.pos.eq(position)) after = afterResumePoint(a, r.kind, intra);
    }
    var before: ??Point = null;
    if (o.before) |b| if (b.coordinate().eq(position)) {
        before = pointOfCursor(b);
    };
    if (after) |x| if (x) |p| return p;
    if (before) |x| if (x) |p| return p;
    return after orelse before;
}

fn afterResumePoint(after: Cursor, resumed: Kind, intra: bool) ?Point {
    _ = intra;
    const p = pointOfCursor(after) orelse return null;
    if (after.kind == .item and resumed == .boundary) return p.itemResume(after.pos.space, true);
    return p;
}

fn windowEdgePoint(w: Window, asc: bool, position: Pos) ?Point {
    const term_pos = if (asc) w.e else w.s;
    const term_pt = if (asc) w.ledger.end else w.ledger.start;
    const entry_pos = if (asc) w.s else w.e;
    const entry_pt = if (asc) w.ledger.start else w.ledger.end;
    if (position.eq(term_pos)) return term_pt;
    if (position.eq(entry_pos)) return entry_pt;
    return null;
}

const CpPosEx = struct { cp: u64, pos: Pos, ex: Exhaustion };

fn ascendingAfterPastTipEnd(o: *const Options, tip: Pos, intra: bool) ?CpPosEx {
    if (!o.asc) return null;
    const a = o.after orelse return null;
    const r = afterResume(a.coordinate(), a.kind, intra);
    if (r.pos.le(tip)) return null;
    if (o.before) |b| if (b.coordinate().le(r.pos)) {
        return .{ .cp = b.pos.checkpoint, .pos = b.coordinate(), .ex = .{ .cursor_bound = .boundary } };
    };
    const ex: Exhaustion = if (r.kind == .boundary) .ledger_tip else .{ .cursor_bound = r.kind };
    return .{ .cp = a.pos.checkpoint, .pos = r.pos, .ex = ex };
}

fn startingCursorEnd(o: *const Options, wtc: u64, ws: Pos, we: Pos, intra: bool) ?struct { cp: u64, pos: Pos } {
    if (o.asc) {
        if (o.before) |b| if (b.coordinate().le(we)) return null;
        const a = o.after orelse return null;
        const first = if (a.kind == .item) (a.coordinate().successor(intra) orelse return null) else a.coordinate();
        if (first.lt(we)) return null;
        if (first.eq(we)) return .{ .cp = wtc, .pos = we };
        return .{ .cp = a.pos.checkpoint, .pos = first };
    }
    if (o.after) |a| if (ws.le(a.coordinate())) return null;
    const b = o.before orelse return null;
    const upper = b.coordinate();
    if (ws.lt(upper)) return null;
    if (upper.eq(ws)) return .{ .cp = wtc, .pos = ws };
    return .{ .cp = b.pos.checkpoint, .pos = upper };
}

fn rejectDescendingCursorsPastTip(o: *const Options, tip: Pos, hi_excl: u64, intra: bool) error{Rpc}!void {
    _ = intra;
    if (o.asc) return;
    for ([_]?Cursor{ o.before, o.after }) |mc| {
        const c = mc orelse continue;
        const p = c.coordinate();
        const past = if (c.kind == .item) tip.le(p) else tip.lt(p);
        if (past) {
            const req = if (c.public) |pp| pp.cp else c.pos.checkpoint;
            return fail(.{ .above_latest = .{ .bound = "cursor", .requested = req, .hi_exclusive = hi_excl } });
        }
    }
}

// ---------------------------------------------------------------- event seq packing (sui-inverted-index event_seq.rs)

pub const event_bits: u6 = 16;
pub const max_events_per_tx: u64 = 1 << event_bits;
pub const max_tx_seq: u64 = std.math.maxInt(u64) >> event_bits;

pub fn encodeEventSeq(tx: u64, idx: u32) u64 {
    return (tx << event_bits) | idx;
}
pub fn decodeEventSeq(s: u64) Pos {
    return .{ .a = s >> event_bits, .b = @truncate(s & (max_events_per_tx - 1)) };
}
fn saturatingLo(tx: u64, idx: u32) u64 {
    if (tx > max_tx_seq) return std.math.maxInt(u64);
    if (idx >= max_events_per_tx) {
        if (tx +| 1 > max_tx_seq or tx == std.math.maxInt(u64)) return std.math.maxInt(u64);
        return (tx + 1) << event_bits;
    }
    return encodeEventSeq(tx, idx);
}
fn saturatingSuccessor(tx: u64, idx: u32) u64 {
    if (idx +| 1 < max_events_per_tx) return saturatingLo(tx, idx + 1);
    return saturatingLo(tx +| 1, 0);
}
/// `event_seq::packed_range`.
pub fn packedRange(lo: Bound, hi: Bound) [2]u64 {
    const s: u64 = switch (lo) {
        .inc => |p| saturatingLo(p.a, p.b),
        .exc => |p| saturatingSuccessor(p.a, p.b),
        .unb => 0,
    };
    const e: u64 = switch (hi) {
        .inc => |p| saturatingSuccessor(p.a, p.b),
        .exc => |p| saturatingLo(p.a, p.b),
        .unb => std.math.maxInt(u64),
    };
    return .{ s, e };
}

test "cursor roundtrip" {
    var buf: [64]u8 = undefined;
    const c = Cursor{ .kind = .item, .pos = .{ .space = .events, .checkpoint = 5, .tx_seq = 77, .event_index = 0 }, .public = .{ .cp = 5, .tx = 0, .ev = 0 } };
    const enc = c.encode(&buf);
    const d = Cursor.decode(enc).?;
    try std.testing.expectEqual(c.kind, d.kind);
    try std.testing.expectEqual(c.pos.tx_seq, d.pos.tx_seq);
    try std.testing.expect(d.public != null);
}
