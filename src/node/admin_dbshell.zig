//! The admin port's db-shell routes (sui-node 1.83.1 `db_shell.rs`, the proxy mode of
//! `sui-tool db-shell`) over deepwave's store:
//!
//!   GET    /db-shell/ls?path=P[&limit=N][&cursor=true]   JSON `[{"name":..,"is_dir":..}]`
//!   GET    /db-shell/read?path=P[&format=json|debug|bcs|raw-bcs]
//!   DELETE /db-shell/delete?path=P                       501, as sui-node (not implemented there)
//!
//! The virtual file system, its parse errors, listing order, `limit` (default 30, at most 1000),
//! `cursor` (the last path component is the first entry listed) and the status codes and texts
//! are sui-node's. What each path lists or reads, from which deepwave data:
//!
//!   /epochs                       epochs with a saved committee (node/epochs/E.json), ascending
//!   /epochs/E/committee           that committee as sui-node's `Committee` value
//!   /epochs/E/last-checkpoint     the summary of epoch E's last checkpoint: the epoch index
//!                                 (`--serve`), else the store (a checkpoint of a later epoch, or
//!                                 an end-of-epoch summary, ends it); the current epoch has none
//!   /epochs/E/first-checkpoint    last checkpoint of E-1 plus one (0 for epoch 0)
//!   /epochs/E/checkpoints         sequence numbers of an ended epoch's checkpoints still held
//!   /checkpoints/seq              held checkpoints from the lowest, ascending
//!   /checkpoints/digest           their digests in byte order (sui-node's key order)
//!   /checkpoint-contents          contents digests of held checkpoints with contents, byte order
//!   /transactions                 digests of the transactions in held checkpoints, byte order,
//!                                 each followed by `D.fx-E` (its effects)
//!   /consensus/...                a full node has no consensus store: 501 where sui-node says so
//!
//! deepwave keeps no digest-ordered index of checkpoints, contents or transactions, so the three
//! digest-ordered listings (and a read of /checkpoint-contents/D) scan every held checkpoint
//! (one record read and a hash each; the transaction listing also decodes the contents): seconds
//! to minutes on a store holding days of mainnet, while the admin port answers nothing else.
//!
//! Formats: `bcs` is standard base64 (with padding) of the value's BCS as text/plain, `raw-bcs`
//! the bytes as application/octet-stream, both exact for every value. `json` (serde_json, compact)
//! and `debug` (Rust `{:#?}`) are rendered for checkpoint summaries, checkpoint contents and
//! committees; a committee's two HashMaps print in key order (sui-node: hash order). Contents
//! debug renders Ed25519/Secp256k1/Secp256r1 user signatures as Rust does and other schemes as a
//! marker. Transactions and effects in json or debug are 501 (deepwave gap; use bcs).
const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const util = @import("admin_util.zig");

pub const default_limit = 30;
pub const max_limit = 1000;

pub const Range = struct { lo: u64, hi: u64 };

pub const Checkpoint = struct {
    epoch: u64,
    /// `CertifiedCheckpointSummary` BCS (summary ++ AuthorityStrongQuorumSignInfo).
    summary_cert: []const u8,
    /// `CheckpointContents` BCS; empty when the store holds none for it.
    contents: []const u8,
};

pub const Tx = struct {
    /// `SenderSignedData` BCS (a `Transaction` envelope's data; EmptySignInfo adds no bytes).
    tx: []const u8,
    /// `TransactionEffects` BCS.
    effects: []const u8,
    effects_digest: [32]u8,
};

pub const Committee = struct {
    /// Sorted by key.
    keys: []const [96]u8,
    stakes: []const u64,
};

/// Called per checkpoint by `Source.scan` (borrowed bytes, valid during the call); false stops.
pub const Visitor = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, seq: u64, summary_cert: []const u8, contents: []const u8) anyerror!bool,
};

/// The node's data (node.zig `AdminStore`; a fake in the tests).
pub const Source = struct {
    ctx: *anyopaque,
    /// Lowest and highest held checkpoint.
    range: *const fn (ctx: *anyopaque) ?Range,
    epochOf: *const fn (ctx: *anyopaque, seq: u64) ?u64,
    /// A held checkpoint, copied into `arena`.
    checkpoint: *const fn (ctx: *anyopaque, arena: Allocator, seq: u64) anyerror!?Checkpoint,
    byDigest: *const fn (ctx: *anyopaque, digest: *const [32]u8) ?u64,
    /// Every held checkpoint in [lo, hi], ascending (or descending with `down`).
    scan: *const fn (ctx: *anyopaque, lo: u64, hi: u64, down: bool, v: Visitor) anyerror!void,
    transaction: *const fn (ctx: *anyopaque, arena: Allocator, digest: *const [32]u8) anyerror!?Tx,
    /// Epochs with a committee, ascending.
    epochs: *const fn (ctx: *anyopaque, arena: Allocator) anyerror![]const u64,
    committee: *const fn (ctx: *anyopaque, arena: Allocator, epoch: u64) anyerror!?Committee,
    /// Last checkpoint of an ended epoch, or first of an epoch, from an epoch index (null: the
    /// index does not know, or there is none).
    epochEnd: *const fn (ctx: *anyopaque, epoch: u64) ?u64,
    epochStart: *const fn (ctx: *anyopaque, epoch: u64) ?u64,
};

pub const Answer = struct {
    code: u16,
    body: []const u8,
    content_type: []const u8 = text_plain,
};

pub const text_plain = "text/plain; charset=utf-8";
pub const app_json = "application/json";
pub const octet = "application/octet-stream";

const no_consensus = "consensus store not available (node is not a validator)";

fn fail(code: u16, body: []const u8) Answer {
    return .{ .code = code, .body = body };
}

fn failf(arena: Allocator, code: u16, comptime fmt: []const u8, args: anytype) !Answer {
    return .{ .code = code, .body = try std.fmt.allocPrint(arena, fmt, args) };
}

fn b58(d: *const [32]u8) B58 {
    return .{ .d = d };
}
const B58 = struct {
    d: *const [32]u8,
    pub fn format(self: B58, w: *Writer) Writer.Error!void {
        var buf: [64]u8 = undefined;
        const s = (util.b58Encode(&buf, self.d));
        try w.writeAll(s);
    }
};

// ------------------------------------------------------------------ query parameters

const Format = enum { json, debug, bcs, raw_bcs };

const Params = struct {
    path: ?[]const u8 = null,
    limit: usize = default_limit,
    cursor: bool = false,
    format: Format = .json,
};

/// serde's derive over serde_urlencoded, as axum's `Query` reports it: fields in the order the
/// query names them, a duplicate or bad value is the first error, then a missing `path`.
fn parseParams(arena: Allocator, query: []const u8, comptime fields: []const []const u8) !union(enum) { ok: Params, err: Answer } {
    var p: Params = .{};
    var seen: [fields.len]bool = @splat(false);
    for (try util.pairs(arena, query)) |kv| {
        inline for (fields, 0..) |name, i| if (std.mem.eql(u8, kv.key, name)) {
            if (seen[i]) return .{ .err = try failf(arena, 400, util.query_reject ++ "duplicate field `{s}`", .{name}) };
            seen[i] = true;
            if (comptime std.mem.eql(u8, name, "path")) {
                p.path = kv.value;
            } else if (comptime std.mem.eql(u8, name, "limit")) {
                p.limit = util.parseUint(usize, kv.value) catch |e| return .{ .err = try failf(arena, 400, util.query_reject ++ "limit: {s}", .{util.intErrorText(e)}) };
            } else if (comptime std.mem.eql(u8, name, "cursor")) {
                p.cursor = util.parseBool(kv.value) orelse return .{ .err = try failf(arena, 400, util.query_reject ++ "cursor: {s}", .{util.bool_error}) };
            } else if (comptime std.mem.eql(u8, name, "format")) {
                const v = kv.value;
                p.format = if (std.mem.eql(u8, v, "json")) .json else if (std.mem.eql(u8, v, "debug")) .debug else if (std.mem.eql(u8, v, "bcs")) .bcs else if (std.mem.eql(u8, v, "raw-bcs")) .raw_bcs else return .{ .err = try failf(arena, 400, util.query_reject ++ "format: unknown variant `{s}`, expected one of `json`, `debug`, `bcs`, `raw-bcs`", .{v}) };
            }
        };
    }
    if (p.path == null) return .{ .err = fail(400, util.query_reject ++ "missing field `path`") };
    return .{ .ok = p };
}

// ------------------------------------------------------------------ paths

const Vfs = union(enum) {
    root,
    epochs,
    epoch: u64,
    epoch_first: u64,
    epoch_last: u64,
    epoch_committee: u64,
    epoch_checkpoints: u64,
    epoch_cp_seq: struct { e: u64, seq: u64 },
    epoch_cp_digest: struct { e: u64, d: [32]u8 },
    cps_root,
    cps_seq_root,
    cp_seq: u64,
    cp_seq_summary: u64,
    cp_seq_contents: u64,
    cp_seq_contents_short: u64,
    cps_digest_root,
    cp_digest: [32]u8,
    cp_digest_summary: [32]u8,
    cp_digest_contents: [32]u8,
    cp_digest_contents_short: [32]u8,
    contents_root,
    contents: [32]u8,
    txs_root,
    tx: [32]u8,
    tx_fx: struct { tx: [32]u8, fx: [32]u8 },
    consensus_root,
    consensus_latest,
    consensus_commits_root,
    consensus_commit_dir: u32,
    consensus_commit_summary: u32,
};

const PathResult = union(enum) { ok: Vfs, err: Answer };

/// `parse_path`: components split on '/', empty ones dropped.
fn parsePath(arena: Allocator, s: []const u8) !PathResult {
    var parts_buf: [8][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, s, '/');
    var too_many = false;
    while (it.next()) |p| {
        if (p.len == 0) continue;
        if (n == parts_buf.len) {
            too_many = true;
            break;
        }
        parts_buf[n] = p;
        n += 1;
    }
    const unknown = PathResult{ .err = try failf(arena, 400, "unknown path: {s}", .{s}) };
    if (too_many) return unknown;
    const parts = parts_buf[0..n];
    const eql = std.mem.eql;
    const P = struct {
        fn is(ps: []const []const u8, comptime want: []const ?[]const u8) bool {
            if (ps.len != want.len) return false;
            inline for (want, 0..) |w, i| if (w) |x| if (!std.mem.eql(u8, ps[i], x)) return false;
            return true;
        }
    };
    if (n == 0) return .{ .ok = .root };
    if (P.is(parts, &.{"epochs"})) return .{ .ok = .epochs };
    if (eql(u8, parts[0], "epochs") and n >= 2) {
        const kind: ?u8 = if (n == 2) 0 else if (P.is(parts, &.{ null, null, "first-checkpoint" })) 1 else if (P.is(parts, &.{ null, null, "last-checkpoint" })) 2 else if (P.is(parts, &.{ null, null, "committee" })) 3 else if (P.is(parts, &.{ null, null, "checkpoints" })) 4 else if (P.is(parts, &.{ null, null, "checkpoints", null })) 5 else null;
        if (kind) |k| {
            const e = util.parseUint(u64, parts[1]) catch return .{ .err = try failf(arena, 400, "invalid epoch: {s}", .{parts[1]}) };
            return .{ .ok = switch (k) {
                0 => .{ .epoch = e },
                1 => .{ .epoch_first = e },
                2 => .{ .epoch_last = e },
                3 => .{ .epoch_committee = e },
                4 => .{ .epoch_checkpoints = e },
                else => blk: {
                    const r = parts[3];
                    if (util.parseUint(u64, r)) |seq| break :blk .{ .epoch_cp_seq = .{ .e = e, .seq = seq } } else |_| {}
                    const d = util.digestFromBase58(r) orelse return .{ .err = try failf(arena, 400, "invalid checkpoint ref: {s}", .{r}) };
                    break :blk .{ .epoch_cp_digest = .{ .e = e, .d = d } };
                },
            } };
        }
        return unknown;
    }
    if (P.is(parts, &.{"checkpoints"})) return .{ .ok = .cps_root };
    if (P.is(parts, &.{ "checkpoints", "seq" })) return .{ .ok = .cps_seq_root };
    if (P.is(parts, &.{ "checkpoints", "digest" })) return .{ .ok = .cps_digest_root };
    if (n >= 3 and n <= 4 and eql(u8, parts[0], "checkpoints") and (eql(u8, parts[1], "seq") or eql(u8, parts[1], "digest"))) {
        const leaf: ?u8 = if (n == 3) 0 else if (eql(u8, parts[3], "summary")) 1 else if (eql(u8, parts[3], "contents")) 2 else if (eql(u8, parts[3], "contents-short")) 3 else null;
        const k = leaf orelse return unknown;
        if (eql(u8, parts[1], "seq")) {
            const seq = util.parseUint(u64, parts[2]) catch return .{ .err = try failf(arena, 400, "invalid sequence: {s}", .{parts[2]}) };
            return .{ .ok = switch (k) {
                0 => .{ .cp_seq = seq },
                1 => .{ .cp_seq_summary = seq },
                2 => .{ .cp_seq_contents = seq },
                else => .{ .cp_seq_contents_short = seq },
            } };
        }
        const d = util.digestFromBase58(parts[2]) orelse return .{ .err = try failf(arena, 400, "invalid digest: {s}", .{parts[2]}) };
        return .{ .ok = switch (k) {
            0 => .{ .cp_digest = d },
            1 => .{ .cp_digest_summary = d },
            2 => .{ .cp_digest_contents = d },
            else => .{ .cp_digest_contents_short = d },
        } };
    }
    if (P.is(parts, &.{"checkpoint-contents"})) return .{ .ok = .contents_root };
    if (P.is(parts, &.{ "checkpoint-contents", null })) {
        const d = util.digestFromBase58(parts[1]) orelse return .{ .err = try failf(arena, 400, "invalid contents digest: {s}", .{parts[1]}) };
        return .{ .ok = .{ .contents = d } };
    }
    if (P.is(parts, &.{"transactions"})) return .{ .ok = .txs_root };
    if (P.is(parts, &.{ "transactions", null })) {
        const seg = parts[1];
        if (std.mem.indexOf(u8, seg, ".fx-")) |i| {
            const tx_s = seg[0..i];
            const fx_s = seg[i + 4 ..];
            const tx = util.digestFromBase58(tx_s) orelse return .{ .err = try failf(arena, 400, "invalid transaction digest: {s}", .{tx_s}) };
            const fx = util.digestFromBase58(fx_s) orelse return .{ .err = try failf(arena, 400, "invalid effects digest: {s}", .{fx_s}) };
            return .{ .ok = .{ .tx_fx = .{ .tx = tx, .fx = fx } } };
        }
        const tx = util.digestFromBase58(seg) orelse return .{ .err = try failf(arena, 400, "invalid transaction digest: {s}", .{seg}) };
        return .{ .ok = .{ .tx = tx } };
    }
    if (P.is(parts, &.{"consensus"})) return .{ .ok = .consensus_root };
    if (P.is(parts, &.{ "consensus", "latest" })) return .{ .ok = .consensus_latest };
    if (P.is(parts, &.{ "consensus", "commits" })) return .{ .ok = .consensus_commits_root };
    if (P.is(parts, &.{ "consensus", "commits", null }) or P.is(parts, &.{ "consensus", "commits", null, "summary" })) {
        const i = util.parseUint(u32, parts[2]) catch return .{ .err = try failf(arena, 400, "invalid commit index: {s}", .{parts[2]}) };
        return .{ .ok = if (n == 3) .{ .consensus_commit_dir = i } else .{ .consensus_commit_summary = i } };
    }
    return unknown;
}

// ------------------------------------------------------------------ ls

const Entry = struct { name: []const u8, is_dir: bool };

fn entriesJson(arena: Allocator, es: []const Entry) !Answer {
    var out: Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.writeByte('[');
    for (es, 0..) |e, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"name\":");
        try jsonStr(w, e.name);
        try w.print(",\"is_dir\":{s}}}", .{if (e.is_dir) "true" else "false"});
    }
    try w.writeByte(']');
    return .{ .code = 200, .body = out.written(), .content_type = app_json };
}

fn static(arena: Allocator, comptime es: []const Entry) !Answer {
    return entriesJson(arena, es);
}

/// `GET /db-shell/ls`.
pub fn ls(arena: Allocator, src: Source, query: []const u8) !Answer {
    const p = switch (try parseParams(arena, query, &.{ "path", "limit", "cursor" })) {
        .ok => |x| x,
        .err => |a| return a,
    };
    const path = switch (try parsePath(arena, p.path.?)) {
        .ok => |v| v,
        .err => |a| return a,
    };
    const limit = @min(p.limit, max_limit);
    var es: std.ArrayList(Entry) = .empty;
    if (p.cursor) switch (path) {
        .cp_seq => |seq| {
            try listSeq(arena, src, seq, limit, &es);
            return entriesJson(arena, es.items);
        },
        .cp_digest => |d| {
            try listDigests(arena, src, .checkpoints, &d, limit, &es);
            return entriesJson(arena, es.items);
        },
        .epoch_cp_seq => |x| {
            try listEpochCps(arena, src, x.e, x.seq, limit, &es);
            return entriesJson(arena, es.items);
        },
        .contents => |d| {
            try listDigests(arena, src, .contents, &d, limit, &es);
            return entriesJson(arena, es.items);
        },
        .tx => |d| {
            try listDigests(arena, src, .transactions, &d, limit, &es);
            return entriesJson(arena, es.items);
        },
        .consensus_commit_dir => return fail(501, no_consensus),
        else => {},
    };
    switch (path) {
        .root => return static(arena, &.{
            .{ .name = "epochs", .is_dir = true },
            .{ .name = "checkpoints", .is_dir = true },
            .{ .name = "checkpoint-contents", .is_dir = true },
            .{ .name = "transactions", .is_dir = true },
            .{ .name = "consensus", .is_dir = true },
        }),
        .epochs => {
            const eps = try src.epochs(src.ctx, arena);
            for (eps[0..@min(eps.len, limit)]) |e| try es.append(arena, .{ .name = try std.fmt.allocPrint(arena, "{d}", .{e}), .is_dir = true });
        },
        .epoch => return static(arena, &.{
            .{ .name = "first-checkpoint", .is_dir = false },
            .{ .name = "last-checkpoint", .is_dir = false },
            .{ .name = "committee", .is_dir = false },
            .{ .name = "checkpoints", .is_dir = true },
        }),
        .epoch_checkpoints => |e| try listEpochCps(arena, src, e, null, limit, &es),
        .cps_root => return static(arena, &.{ .{ .name = "seq", .is_dir = true }, .{ .name = "digest", .is_dir = true } }),
        .cps_seq_root => try listSeq(arena, src, null, limit, &es),
        .cp_seq, .cp_digest => return static(arena, &.{
            .{ .name = "summary", .is_dir = false },
            .{ .name = "contents", .is_dir = false },
            .{ .name = "contents-short", .is_dir = false },
        }),
        .cps_digest_root => try listDigests(arena, src, .checkpoints, null, limit, &es),
        .contents_root => try listDigests(arena, src, .contents, null, limit, &es),
        .txs_root => try listDigests(arena, src, .transactions, null, limit, &es),
        .consensus_root => return static(arena, &.{ .{ .name = "latest", .is_dir = false }, .{ .name = "commits", .is_dir = true } }),
        .consensus_commits_root => return fail(501, no_consensus),
        .consensus_commit_dir => return static(arena, &.{.{ .name = "summary", .is_dir = false }}),
        else => return fail(400, "path is not a directory"),
    }
    return entriesJson(arena, es.items);
}

/// `list_checkpoints_from_seq`: held checkpoints from `start` (or the lowest), ascending.
fn listSeq(arena: Allocator, src: Source, start: ?u64, limit: usize, es: *std.ArrayList(Entry)) !void {
    const r = src.range(src.ctx) orelse return;
    var seq = @max(start orelse r.lo, r.lo);
    while (seq <= r.hi and es.items.len < limit) : (seq += 1) {
        if (src.epochOf(src.ctx, seq) == null) continue;
        try es.append(arena, .{ .name = try std.fmt.allocPrint(arena, "{d}", .{seq}), .is_dir = true });
    }
}

/// `list_epoch_checkpoints`: nothing for an epoch without a known last checkpoint (the current
/// one too), else its held checkpoints from `start`.
fn listEpochCps(arena: Allocator, src: Source, epoch: u64, start: ?u64, limit: usize, es: *std.ArrayList(Entry)) !void {
    const last = epochLast(src, epoch) orelse return;
    const first: u64 = if (epoch == 0) 0 else if (epochLast(src, epoch - 1)) |l| l + 1 else 0;
    const r = src.range(src.ctx) orelse return;
    var seq = @max(@max(start orelse first, first), r.lo);
    while (seq <= @min(last, r.hi) and es.items.len < limit) : (seq += 1) {
        if (src.epochOf(src.ctx, seq) == null) continue;
        try es.append(arena, .{ .name = try std.fmt.allocPrint(arena, "{d}", .{seq}), .is_dir = false });
    }
}

const DigestTable = enum { checkpoints, contents, transactions };

/// The `limit` smallest digests at or after `start` (byte order), with a payload (effects).
const TopK = struct {
    keys: std.ArrayList([32]u8) = .empty,
    vals: std.ArrayList([32]u8) = .empty,
    k: usize,
    start: ?*const [32]u8,
    arena: Allocator,

    fn offer(t: *TopK, key: *const [32]u8, val: *const [32]u8) !void {
        if (t.k == 0) return;
        if (t.start) |s| if (std.mem.order(u8, key, s) == .lt) return;
        const items = t.keys.items;
        if (items.len == t.k and std.mem.order(u8, key, &items[items.len - 1]) != .lt) return;
        var lo: usize = 0;
        var hi: usize = items.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (std.mem.order(u8, &items[mid], key) == .lt) lo = mid + 1 else hi = mid;
        }
        if (lo < items.len and std.mem.eql(u8, &items[lo], key)) return;
        if (items.len == t.k) {
            _ = t.keys.pop();
            _ = t.vals.pop();
        }
        try t.keys.insert(t.arena, lo, key.*);
        try t.vals.insert(t.arena, lo, val.*);
    }
};

const ScanCtx = struct {
    top: *TopK,
    table: DigestTable,
    scratch: std.heap.ArenaAllocator,

    fn visit(ctx: *anyopaque, _: u64, cert: []const u8, contents: []const u8) anyerror!bool {
        const s: *ScanCtx = @ptrCast(@alignCast(ctx));
        switch (s.table) {
            .checkpoints => {
                const sum = summaryOf(cert) catch return true;
                const d = summaryDigest(sum);
                try s.top.offer(&d, &d);
            },
            .contents => {
                if (contents.len == 0) return true;
                const sum = summaryOf(cert) catch return true;
                const d = contentDigestOf(sum) orelse return true;
                try s.top.offer(d, d);
            },
            .transactions => {
                if (contents.len == 0) return true;
                _ = s.scratch.reset(.retain_capacity);
                const c = bcs.decode(types.CheckpointContents, s.scratch.allocator(), contents) catch return true;
                switch (c) {
                    .V1 => |v| for (v.transactions) |ed| try s.top.offer(&ed.transaction.@"0".@"0", &ed.effects.@"0".@"0"),
                    .V2 => |v| for (v.transactions) |t| try s.top.offer(&t.digest.transaction.@"0".@"0", &t.digest.effects.@"0".@"0"),
                }
            },
        }
        return true;
    }
};

/// A digest-ordered table (`checkpoint_by_digest`, `checkpoint_content`, `transactions`): a scan
/// of every held checkpoint (see the file comment).
fn listDigests(arena: Allocator, src: Source, table: DigestTable, start: ?*const [32]u8, limit: usize, es: *std.ArrayList(Entry)) !void {
    if (limit == 0) return;
    const r = src.range(src.ctx) orelse return;
    var top: TopK = .{ .k = limit, .start = start, .arena = arena };
    var sc: ScanCtx = .{ .top = &top, .table = table, .scratch = .init(std.heap.page_allocator) };
    defer sc.scratch.deinit();
    try src.scan(src.ctx, r.lo, r.hi, false, .{ .ctx = &sc, .f = ScanCtx.visit });
    for (top.keys.items, top.vals.items) |*k, *v| {
        const name = try std.fmt.allocPrint(arena, "{f}", .{b58(k)});
        switch (table) {
            .checkpoints => try es.append(arena, .{ .name = name, .is_dir = true }),
            .contents => try es.append(arena, .{ .name = name, .is_dir = false }),
            .transactions => {
                try es.append(arena, .{ .name = name, .is_dir = false });
                try es.append(arena, .{ .name = try std.fmt.allocPrint(arena, "{s}.fx-{f}", .{ name, b58(v) }), .is_dir = false });
            },
        }
    }
}

// ------------------------------------------------------------------ epochs

/// `epoch_last_checkpoint_map[epoch]`: the epoch index, else the store: the last held checkpoint
/// of `epoch` when a later epoch's checkpoint is held or it is an end-of-epoch checkpoint.
pub fn epochLast(src: Source, epoch: u64) ?u64 {
    if (src.epochEnd(src.ctx, epoch)) |s| return s;
    const r = src.range(src.ctx) orelse return null;
    const lo_e = src.epochOf(src.ctx, r.lo) orelse return null;
    if (lo_e > epoch) return null;
    // first held checkpoint of an epoch above `epoch`, in (lo, hi + 1]
    var lo = r.lo;
    var hi = r.hi + 1;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const e = src.epochOf(src.ctx, mid) orelse return null;
        if (e > epoch) hi = mid else lo = mid + 1;
    }
    const cand = lo - 1;
    if (src.epochOf(src.ctx, cand) != epoch) return null;
    if (lo <= r.hi) return cand;
    // the newest held checkpoint: the last of its epoch only if it ends it
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const cp = (src.checkpoint(src.ctx, arena_state.allocator(), cand) catch return null) orelse return null;
    const sum = summaryOf(cp.summary_cert) catch return null;
    return if (isEndOfEpoch(sum)) cand else null;
}

/// `get_epoch_first_checkpoint_seq`: 0 for epoch 0, else the last of `epoch - 1` plus one.
fn epochFirst(src: Source, epoch: u64) ?u64 {
    if (epoch == 0) return 0;
    if (epochLast(src, epoch - 1)) |l| return l + 1;
    return src.epochStart(src.ctx, epoch);
}

// ------------------------------------------------------------------ read

const Value = union(enum) {
    summary: []const u8,
    contents: []const u8,
    committee: Committee,
    epoch_committee: u64,
    tx: []const u8,
    effects: []const u8,
};

/// `GET /db-shell/read`.
pub fn read(arena: Allocator, src: Source, query: []const u8) !Answer {
    const p = switch (try parseParams(arena, query, &.{ "path", "format" })) {
        .ok => |x| x,
        .err => |a| return a,
    };
    const path = switch (try parsePath(arena, p.path.?)) {
        .ok => |v| v,
        .err => |a| return a,
    };
    const f = p.format;
    switch (path) {
        .epoch_first => |e| {
            const first = epochFirst(src, e) orelse return failf(arena, 404, "no data for epoch {d}", .{e});
            const cp = (try src.checkpoint(src.ctx, arena, first)) orelse return failf(arena, 404, "checkpoint {d} not found", .{first});
            return renderSummary(arena, cp.summary_cert, f);
        },
        .epoch_last => |e| {
            const last = epochLast(src, e) orelse return failf(arena, 404, "no last checkpoint for epoch {d}", .{e});
            const cp = (try src.checkpoint(src.ctx, arena, last)) orelse return failf(arena, 404, "no last checkpoint for epoch {d}", .{e});
            return renderSummary(arena, cp.summary_cert, f);
        },
        .epoch_committee => |e| {
            const c = (try src.committee(src.ctx, arena, e)) orelse return failf(arena, 404, "no committee for epoch {d}", .{e});
            return renderCommittee(arena, e, c, f);
        },
        .epoch_cp_seq => |x| return readSummaryBySeq(arena, src, x.seq, f),
        .cp_seq_summary => |seq| return readSummaryBySeq(arena, src, seq, f),
        .epoch_cp_digest => |x| return readSummaryByDigest(arena, src, &x.d, f),
        .cp_digest_summary => |d| return readSummaryByDigest(arena, src, &d, f),
        .cp_seq_contents, .cp_seq_contents_short => |seq| {
            const cp = (try src.checkpoint(src.ctx, arena, seq)) orelse return failf(arena, 404, "checkpoint {d} not found", .{seq});
            if (cp.contents.len == 0) return failf(arena, 404, "contents for checkpoint {d} not found", .{seq});
            return if (path == .cp_seq_contents) renderContents(arena, cp.contents, f) else renderContentsShort(arena, cp.contents, f);
        },
        .cp_digest_contents, .cp_digest_contents_short => |d| {
            const cp = try checkpointByDigest(arena, src, &d) orelse return failf(arena, 404, "checkpoint {f} not found", .{b58(&d)});
            if (cp.contents.len == 0) return failf(arena, 404, "contents for checkpoint {f} not found", .{b58(&d)});
            return if (path == .cp_digest_contents) renderContents(arena, cp.contents, f) else renderContentsShort(arena, cp.contents, f);
        },
        .contents => |d| {
            const bytes = try contentsByDigest(arena, src, &d) orelse return failf(arena, 404, "checkpoint contents {f} not found", .{b58(&d)});
            return renderContents(arena, bytes, f);
        },
        .tx => |d| {
            const t = (try src.transaction(src.ctx, arena, &d)) orelse return failf(arena, 404, "transaction {f} not found", .{b58(&d)});
            return renderOpaque(arena, t.tx, f, "transactions");
        },
        .tx_fx => |x| {
            const t = try src.transaction(src.ctx, arena, &x.tx);
            if (t == null or !std.mem.eql(u8, &t.?.effects_digest, &x.fx))
                return failf(arena, 404, "effects {f} for tx {f} not found", .{ b58(&x.fx), b58(&x.tx) });
            return renderOpaque(arena, t.?.effects, f, "effects");
        },
        .consensus_latest, .consensus_commit_summary => return fail(501, no_consensus),
        .epoch => |e| return failf(arena, 400, "epoch {d} is a directory", .{e}),
        else => return fail(400, "path is not a readable file"),
    }
}

/// `DELETE /db-shell/delete`: sui-node 1.83.1 implements no deletion either.
pub fn delete(arena: Allocator, query: []const u8) !Answer {
    const p = switch (try parseParams(arena, query, &.{"path"})) {
        .ok => |x| x,
        .err => |a| return a,
    };
    return failf(arena, 501, "delete not yet implemented for path: {s}", .{p.path.?});
}

fn readSummaryBySeq(arena: Allocator, src: Source, seq: u64, f: Format) !Answer {
    const cp = (try src.checkpoint(src.ctx, arena, seq)) orelse return failf(arena, 404, "checkpoint {d} not found", .{seq});
    return renderSummary(arena, cp.summary_cert, f);
}

fn readSummaryByDigest(arena: Allocator, src: Source, d: *const [32]u8, f: Format) !Answer {
    const cp = try checkpointByDigest(arena, src, d) orelse return failf(arena, 404, "checkpoint {f} not found", .{b58(d)});
    return renderSummary(arena, cp.summary_cert, f);
}

fn checkpointByDigest(arena: Allocator, src: Source, d: *const [32]u8) !?Checkpoint {
    const seq = src.byDigest(src.ctx, d) orelse return null;
    return src.checkpoint(src.ctx, arena, seq);
}

const FindCtx = struct {
    want: *const [32]u8,
    arena: Allocator,
    found: ?[]const u8 = null,
    fn visit(ctx: *anyopaque, _: u64, cert: []const u8, contents: []const u8) anyerror!bool {
        const s: *FindCtx = @ptrCast(@alignCast(ctx));
        if (contents.len == 0) return true;
        const sum = summaryOf(cert) catch return true;
        const d = contentDigestOf(sum) orelse return true;
        if (!std.mem.eql(u8, d, s.want)) return true;
        s.found = try s.arena.dupe(u8, contents);
        return false;
    }
};

/// `checkpoint_content[digest]`: a scan from the newest held checkpoint down.
fn contentsByDigest(arena: Allocator, src: Source, d: *const [32]u8) !?[]const u8 {
    const r = src.range(src.ctx) orelse return null;
    var fc: FindCtx = .{ .want = d, .arena = arena };
    try src.scan(src.ctx, r.lo, r.hi, true, .{ .ctx = &fc, .f = FindCtx.visit });
    return fc.found;
}

// ------------------------------------------------------------------ BCS helpers

/// The `CheckpointSummary` part of a certified summary.
pub fn summaryOf(cert: []const u8) ![]const u8 {
    var r = bcs.Reader.init(cert);
    try bcs.skip(types.CheckpointSummary, &r);
    return cert[0..r.pos()];
}

pub fn summaryDigest(summary: []const u8) [32]u8 {
    return hash.blake2b256(&.{ "CheckpointSummary::", summary });
}

/// `content_digest`: after epoch, sequence_number and network_total_transactions (3 x u64), a
/// 32-byte vector.
fn contentDigestOf(summary: []const u8) ?*const [32]u8 {
    if (summary.len < 25 + 32 or summary[24] != 32) return null;
    return summary[25..57];
}

fn isEndOfEpoch(summary: []const u8) bool {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const s = bcs.decode(types.CheckpointSummary, arena_state.allocator(), summary) catch return false;
    return s.end_of_epoch_data != null;
}

/// sui-node's `Committee` BCS: epoch, voting_rights, then expanded_keys and index_map (HashMaps,
/// which BCS writes sorted by key bytes: the voting_rights order).
pub fn committeeBcs(arena: Allocator, epoch: u64, c: Committee) ![]u8 {
    var out: Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.writeInt(u64, epoch, .little);
    const n = c.keys.len;
    try uleb(w, n);
    for (c.keys, c.stakes) |*k, s| {
        try w.writeByte(96);
        try w.writeAll(k);
        try w.writeInt(u64, s, .little);
    }
    try uleb(w, n);
    for (c.keys) |*k| {
        try w.writeByte(96);
        try w.writeAll(k);
        try w.writeAll(k); // BLS12381PublicKey: 96 bytes, no length
    }
    try uleb(w, n);
    for (c.keys, 0..) |*k, i| {
        try w.writeByte(96);
        try w.writeAll(k);
        try w.writeInt(u64, i, .little);
    }
    return out.written();
}

fn uleb(w: *Writer, n0: usize) !void {
    var n = n0;
    while (n >= 0x80) : (n >>= 7) try w.writeByte(@as(u8, @truncate(n)) | 0x80);
    try w.writeByte(@intCast(n));
}

// ------------------------------------------------------------------ rendering

fn bytesAnswer(arena: Allocator, bytes: []const u8, f: Format) !?Answer {
    switch (f) {
        .bcs => {
            const enc = std.base64.standard.Encoder;
            const out = try arena.alloc(u8, enc.calcSize(bytes.len));
            return .{ .code = 200, .body = enc.encode(out, bytes) };
        },
        .raw_bcs => return .{ .code = 200, .body = bytes, .content_type = octet },
        else => return null,
    }
}

fn renderOpaque(arena: Allocator, bytes: []const u8, f: Format, comptime what: []const u8) !Answer {
    if (try bytesAnswer(arena, bytes, f)) |a| return a;
    return fail(501, "zui renders " ++ what ++ " as format=bcs or format=raw-bcs only (json and debug are not implemented)");
}

fn renderSummary(arena: Allocator, cert: []const u8, f: Format) !Answer {
    const sum = summaryOf(cert) catch return fail(500, "corrupt checkpoint summary");
    if (try bytesAnswer(arena, sum, f)) |a| return a;
    const s = bcs.decode(types.CheckpointSummary, arena, sum) catch return fail(500, "corrupt checkpoint summary");
    var out: Writer.Allocating = .init(arena);
    if (f == .json) {
        try summaryJson(&out.writer, &s);
        return .{ .code = 200, .body = out.written(), .content_type = app_json };
    }
    try summaryDebug(&out.writer, &s);
    return .{ .code = 200, .body = out.written() };
}

fn renderContents(arena: Allocator, bytes: []const u8, f: Format) !Answer {
    if (try bytesAnswer(arena, bytes, f)) |a| return a;
    const c = bcs.decode(types.CheckpointContents, arena, bytes) catch return fail(500, "corrupt checkpoint contents");
    var out: Writer.Allocating = .init(arena);
    if (f == .json) {
        try contentsJson(&out.writer, &c);
        return .{ .code = 200, .body = out.written(), .content_type = app_json };
    }
    try contentsDebug(&out.writer, &c);
    return .{ .code = 200, .body = out.written() };
}

/// `render_contents_short`.
fn renderContentsShort(arena: Allocator, bytes: []const u8, f: Format) !Answer {
    if (f == .bcs or f == .raw_bcs) return fail(400, "bcs not supported for contents-short; use 'contents' instead");
    const c = bcs.decode(types.CheckpointContents, arena, bytes) catch return fail(500, "corrupt checkpoint contents");
    var out: Writer.Allocating = .init(arena);
    const w = &out.writer;
    if (f == .json) try w.writeByte('[');
    var i: usize = 0;
    const Pairs = struct {
        fn one(wr: *Writer, json: bool, k: usize, tx: *const [32]u8, fx: *const [32]u8) !void {
            if (json) {
                if (k > 0) try wr.writeByte(',');
                try wr.print("{{\"transaction\":\"{f}\",\"effects\":\"{f}\"}}", .{ b58(tx), b58(fx) });
            } else try wr.print("{f} {f}\n", .{ b58(tx), b58(fx) });
        }
    };
    switch (c) {
        .V1 => |v| for (v.transactions) |ed| {
            try Pairs.one(w, f == .json, i, &ed.transaction.@"0".@"0", &ed.effects.@"0".@"0");
            i += 1;
        },
        .V2 => |v| for (v.transactions) |t| {
            try Pairs.one(w, f == .json, i, &t.digest.transaction.@"0".@"0", &t.digest.effects.@"0".@"0");
            i += 1;
        },
    }
    if (f == .json) {
        try w.writeByte(']');
        return .{ .code = 200, .body = out.written(), .content_type = app_json };
    }
    return .{ .code = 200, .body = out.written() };
}

fn renderCommittee(arena: Allocator, epoch: u64, c: Committee, f: Format) !Answer {
    if (f == .bcs or f == .raw_bcs) return (try bytesAnswer(arena, try committeeBcs(arena, epoch, c), f)).?;
    var out: Writer.Allocating = .init(arena);
    const w = &out.writer;
    if (f == .json) {
        try w.print("{{\"epoch\":{d},\"voting_rights\":[", .{epoch});
        for (c.keys, c.stakes, 0..) |*k, s, i| {
            if (i > 0) try w.writeByte(',');
            try w.print("[\"{f}\",{d}]", .{ b64(k), s });
        }
        try w.writeAll("],\"expanded_keys\":{");
        for (c.keys, 0..) |*k, i| {
            if (i > 0) try w.writeByte(',');
            try w.print("\"{f}\":\"{f}\"", .{ b64(k), b64(k) });
        }
        try w.writeAll("},\"index_map\":{");
        for (c.keys, 0..) |*k, i| {
            if (i > 0) try w.writeByte(',');
            try w.print("\"{f}\":{d}", .{ b64(k), i });
        }
        try w.writeAll("}}");
        return .{ .code = 200, .body = out.written(), .content_type = app_json };
    }
    var d: Dbg = .{ .w = w };
    try d.open("Committee {");
    try d.field("epoch");
    try w.print("{d},\n", .{epoch});
    try d.field("voting_rights");
    if (c.keys.len == 0) try w.writeAll("[],\n") else {
        try d.open("[");
        for (c.keys, c.stakes) |*k, s| {
            try d.item();
            try d.open("(");
            try d.item();
            try w.print("k#{x},\n", .{k});
            try d.item();
            try w.print("{d},\n", .{s});
            try d.close("),");
        }
        try d.close("],");
    }
    try d.field("expanded_keys");
    if (c.keys.len == 0) try w.writeAll("{},\n") else {
        try d.open("{");
        for (c.keys) |*k| {
            try d.item();
            try w.print("k#{x}: {f},\n", .{ k, b64(k) });
        }
        try d.close("},");
    }
    try d.field("index_map");
    if (c.keys.len == 0) try w.writeAll("{},\n") else {
        try d.open("{");
        for (c.keys, 0..) |*k, i| {
            try d.item();
            try w.print("k#{x}: {d},\n", .{ k, i });
        }
        try d.close("},");
    }
    try d.closeLast("}");
    return .{ .code = 200, .body = out.written() };
}

// ---- JSON (serde_json, human-readable serde of the sui-types values)

fn jsonStr(w: *Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |ch| switch (ch) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0x08 => try w.writeAll("\\b"),
        0x0c => try w.writeAll("\\f"),
        0...7, 0x0b, 0x0e...0x1f => try w.print("\\u{x:0>4}", .{ch}),
        else => try w.writeByte(ch),
    };
    try w.writeByte('"');
}

fn b64(bytes: []const u8) B64 {
    return .{ .b = bytes };
}
const B64 = struct {
    b: []const u8,
    pub fn format(self: B64, w: *Writer) Writer.Error!void {
        const enc = std.base64.standard.Encoder;
        var buf: [256]u8 = undefined;
        var i: usize = 0;
        // 3-byte groups so chunks need no padding but the last
        while (i < self.b.len) {
            const n = @min(self.b.len - i, 189);
            try w.writeAll(enc.encode(&buf, self.b[i .. i + n]));
            i += n;
        }
    }
};

fn commitmentJson(w: *Writer, c: *const types.CheckpointCommitment) !void {
    switch (c.*) {
        .ECMHLiveObjectSetDigest => |d| try w.print("{{\"ECMHLiveObjectSetDigest\":{{\"digest\":\"{f}\"}}}}", .{b58(&d.digest.@"0")}),
        .CheckpointArtifactsDigest => |d| try w.print("{{\"CheckpointArtifactsDigest\":\"{f}\"}}", .{b58(&d.@"0".@"0")}),
    }
}

fn summaryJson(w: *Writer, s: *const types.CheckpointSummary) !void {
    try w.print("{{\"epoch\":{d},\"sequence_number\":{d},\"network_total_transactions\":{d},\"content_digest\":\"{f}\",\"previous_digest\":", .{ s.epoch, s.sequence_number, s.network_total_transactions, b58(&s.content_digest.@"0".@"0") });
    if (s.previous_digest) |d| try w.print("\"{f}\"", .{b58(&d.@"0".@"0")}) else try w.writeAll("null");
    const g = s.epoch_rolling_gas_cost_summary;
    try w.print(",\"epoch_rolling_gas_cost_summary\":{{\"computationCost\":\"{d}\",\"storageCost\":\"{d}\",\"storageRebate\":\"{d}\",\"nonRefundableStorageFee\":\"{d}\"}},\"timestamp_ms\":{d},\"checkpoint_commitments\":[", .{ g.computationCost, g.storageCost, g.storageRebate, g.nonRefundableStorageFee, s.timestamp_ms });
    for (s.checkpoint_commitments, 0..) |*c, i| {
        if (i > 0) try w.writeByte(',');
        try commitmentJson(w, c);
    }
    try w.writeAll("],\"end_of_epoch_data\":");
    if (s.end_of_epoch_data) |e| {
        try w.writeAll("{\"nextEpochCommittee\":[");
        for (e.nextEpochCommittee, 0..) |m, i| {
            if (i > 0) try w.writeByte(',');
            try w.print("[\"{f}\",\"{d}\"]", .{ b64(&m[0].@"0"), m[1] });
        }
        try w.print("],\"nextEpochProtocolVersion\":\"{d}\",\"epochCommitments\":[", .{e.nextEpochProtocolVersion.@"0"});
        for (e.epochCommitments, 0..) |*c, i| {
            if (i > 0) try w.writeByte(',');
            try commitmentJson(w, c);
        }
        try w.writeAll("]}");
    } else try w.writeAll("null");
    try w.writeAll(",\"version_specific_data\":[");
    for (s.version_specific_data, 0..) |b, i| {
        if (i > 0) try w.writeByte(',');
        try w.print("{d}", .{b});
    }
    try w.writeAll("]}");
}

fn digestsJson(w: *Writer, ed: *const types.ExecutionDigests) !void {
    try w.print("{{\"transaction\":\"{f}\",\"effects\":\"{f}\"}}", .{ b58(&ed.transaction.@"0".@"0"), b58(&ed.effects.@"0".@"0") });
}

fn contentsJson(w: *Writer, c: *const types.CheckpointContents) !void {
    switch (c.*) {
        .V1 => |v| {
            try w.writeAll("{\"V1\":{\"transactions\":[");
            for (v.transactions, 0..) |*ed, i| {
                if (i > 0) try w.writeByte(',');
                try digestsJson(w, ed);
            }
            try w.writeAll("],\"user_signatures\":[");
            for (v.user_signatures, 0..) |sigs, i| {
                if (i > 0) try w.writeByte(',');
                try w.writeByte('[');
                for (sigs, 0..) |sig, k| {
                    if (k > 0) try w.writeByte(',');
                    try w.print("\"{f}\"", .{b64(sig.@"0")});
                }
                try w.writeByte(']');
            }
            try w.writeAll("]}}");
        },
        .V2 => |v| {
            try w.writeAll("{\"V2\":{\"transactions\":[");
            for (v.transactions, 0..) |*t, i| {
                if (i > 0) try w.writeByte(',');
                try w.writeAll("{\"digest\":");
                try digestsJson(w, &t.digest);
                try w.writeAll(",\"user_signatures\":[");
                for (t.user_signatures, 0..) |us, k| {
                    if (k > 0) try w.writeByte(',');
                    try w.print("[\"{f}\",", .{b64(us[0].@"0")});
                    if (us[1]) |v2| try w.print("{d}]", .{v2.@"0"}) else try w.writeAll("null]");
                }
                try w.writeAll("]}");
            }
            try w.writeAll("]}}");
        },
    }
}

// ---- Debug (Rust `{:#?}`)

/// Rust's pretty Debug layout: four spaces per level, a trailing comma after every field.
const Dbg = struct {
    w: *Writer,
    depth: usize = 0,

    fn indent(d: *Dbg) !void {
        for (0..d.depth) |_| try d.w.writeAll("    ");
    }
    /// Writes `head` (e.g. `Name {`) and a newline, one level deeper.
    fn open(d: *Dbg, head: []const u8) !void {
        try d.w.writeAll(head);
        try d.w.writeByte('\n');
        d.depth += 1;
    }
    fn field(d: *Dbg, name: []const u8) !void {
        try d.indent();
        try d.w.print("{s}: ", .{name});
    }
    fn item(d: *Dbg) !void {
        try d.indent();
    }
    /// One level up, `tail` (e.g. `},`) and a newline.
    fn close(d: *Dbg, tail: []const u8) !void {
        d.depth -= 1;
        try d.indent();
        try d.w.writeAll(tail);
        try d.w.writeByte('\n');
    }
    fn closeLast(d: *Dbg, tail: []const u8) !void {
        d.depth -= 1;
        try d.indent();
        try d.w.writeAll(tail);
    }
    /// `Name(\n    value,\n)` with a plain one-line value.
    fn tuple1(d: *Dbg, name: []const u8, comptime fmt: []const u8, args: anytype) !void {
        try d.w.print("{s}(\n", .{name});
        d.depth += 1;
        try d.indent();
        try d.w.print(fmt ++ ",\n", args);
        try d.close("),");
    }
    fn bytes(d: *Dbg, b: []const u8, tail: []const u8) !void {
        if (b.len == 0) {
            try d.w.writeAll("[]");
            try d.w.writeAll(tail[1..]);
            try d.w.writeByte('\n');
            return;
        }
        try d.open("[");
        for (b) |x| {
            try d.item();
            try d.w.print("{d},\n", .{x});
        }
        try d.close(tail);
    }
};

fn commitmentsDebug(d: *Dbg, cs: []const types.CheckpointCommitment) !void {
    if (cs.len == 0) return d.w.writeAll("[],\n");
    try d.open("[");
    for (cs) |c| {
        try d.item();
        switch (c) {
            .ECMHLiveObjectSetDigest => |x| {
                try d.open("ECMHLiveObjectSetDigest(");
                try d.item();
                try d.open("ECMHLiveObjectSetDigest {");
                try d.field("digest");
                try d.w.print("{f},\n", .{b58(&x.digest.@"0")});
                try d.close("},");
                try d.close("),");
            },
            .CheckpointArtifactsDigest => |x| {
                try d.open("CheckpointArtifactsDigest(");
                try d.item();
                try d.tuple1("CheckpointArtifactsDigest", "{f}", .{b58(&x.@"0".@"0")});
                try d.close("),");
            },
        }
    }
    try d.close("],");
}

fn summaryDebug(w: *Writer, s: *const types.CheckpointSummary) !void {
    var d: Dbg = .{ .w = w };
    try d.open("CheckpointSummary {");
    try d.field("epoch");
    try w.print("{d},\n", .{s.epoch});
    try d.field("sequence_number");
    try w.print("{d},\n", .{s.sequence_number});
    try d.field("network_total_transactions");
    try w.print("{d},\n", .{s.network_total_transactions});
    try d.field("content_digest");
    try d.tuple1("CheckpointContentsDigest", "{f}", .{b58(&s.content_digest.@"0".@"0")});
    try d.field("previous_digest");
    if (s.previous_digest) |pd| {
        try d.open("Some(");
        try d.item();
        try d.tuple1("CheckpointDigest", "{f}", .{b58(&pd.@"0".@"0")});
        try d.close("),");
    } else try w.writeAll("None,\n");
    const g = s.epoch_rolling_gas_cost_summary;
    try d.field("epoch_rolling_gas_cost_summary");
    try d.open("GasCostSummary {");
    try d.field("computation_cost");
    try w.print("{d},\n", .{g.computationCost});
    try d.field("storage_cost");
    try w.print("{d},\n", .{g.storageCost});
    try d.field("storage_rebate");
    try w.print("{d},\n", .{g.storageRebate});
    try d.field("non_refundable_storage_fee");
    try w.print("{d},\n", .{g.nonRefundableStorageFee});
    try d.close("},");
    try d.field("timestamp_ms");
    try w.print("{d},\n", .{s.timestamp_ms});
    try d.field("checkpoint_commitments");
    try commitmentsDebug(&d, s.checkpoint_commitments);
    try d.field("end_of_epoch_data");
    if (s.end_of_epoch_data) |e| {
        try d.open("Some(");
        try d.item();
        try d.open("EndOfEpochData {");
        try d.field("next_epoch_committee");
        if (e.nextEpochCommittee.len == 0) try w.writeAll("[],\n") else {
            try d.open("[");
            for (e.nextEpochCommittee) |m| {
                try d.item();
                try d.open("(");
                try d.item();
                try w.print("k#{x},\n", .{&m[0].@"0"});
                try d.item();
                try w.print("{d},\n", .{m[1]});
                try d.close("),");
            }
            try d.close("],");
        }
        try d.field("next_epoch_protocol_version");
        try d.tuple1("ProtocolVersion", "{d}", .{e.nextEpochProtocolVersion.@"0"});
        try d.field("epoch_commitments");
        try commitmentsDebug(&d, e.epochCommitments);
        try d.close("},");
        try d.close("),");
    } else try w.writeAll("None,\n");
    try d.field("version_specific_data");
    try d.bytes(s.version_specific_data, "],");
    try d.closeLast("}");
}

fn digestsDebug(d: *Dbg, ed: *const types.ExecutionDigests) !void {
    try d.open("ExecutionDigests {");
    try d.field("transaction");
    try d.tuple1("TransactionDigest", "{f}", .{b58(&ed.transaction.@"0".@"0")});
    try d.field("effects");
    try d.tuple1("TransactionEffectsDigest", "{f}", .{b58(&ed.effects.@"0".@"0")});
    try d.close("},");
}

/// GenericSignature Debug for the single-key schemes (flag ++ signature ++ public key in a
/// fixed array); other schemes as a marker (deepwave gap).
fn sigDebug(d: *Dbg, sig: []const u8) !void {
    const name: ?[]const u8 = if (sig.len == 97 and sig[0] == 0) "Ed25519SuiSignature" else if (sig.len == 98 and sig[0] == 1) "Secp256k1SuiSignature" else if (sig.len == 98 and sig[0] == 2) "Secp256r1SuiSignature" else null;
    const n = name orelse return d.w.print("<zui: Debug of signature scheme {d} not rendered>,\n", .{if (sig.len > 0) sig[0] else 0});
    try d.open("Signature(");
    try d.item();
    try d.w.print("{s}(\n", .{n});
    d.depth += 1;
    try d.item();
    try d.bytes(sig, "],");
    try d.close("),");
    try d.close("),");
}

fn contentsDebug(w: *Writer, c: *const types.CheckpointContents) !void {
    var d: Dbg = .{ .w = w };
    switch (c.*) {
        .V1 => |v| {
            try d.open("V1(");
            try d.item();
            try d.open("CheckpointContentsV1 {");
            try d.field("digest");
            try w.writeAll("OnceCell(Uninit),\n");
            try d.field("transactions");
            if (v.transactions.len == 0) try w.writeAll("[],\n") else {
                try d.open("[");
                for (v.transactions) |*ed| {
                    try d.item();
                    try digestsDebug(&d, ed);
                }
                try d.close("],");
            }
            try d.field("user_signatures");
            if (v.user_signatures.len == 0) try w.writeAll("[],\n") else {
                try d.open("[");
                for (v.user_signatures) |sigs| {
                    try d.item();
                    if (sigs.len == 0) {
                        try w.writeAll("[],\n");
                        continue;
                    }
                    try d.open("[");
                    for (sigs) |sig| {
                        try d.item();
                        try sigDebug(&d, sig.@"0");
                    }
                    try d.close("],");
                }
                try d.close("],");
            }
            try d.close("},");
            try d.closeLast(")");
        },
        .V2 => |v| {
            try d.open("V2(");
            try d.item();
            try d.open("CheckpointContentsV2 {");
            try d.field("digest");
            try w.writeAll("OnceCell(Uninit),\n");
            try d.field("transactions");
            if (v.transactions.len == 0) try w.writeAll("[],\n") else {
                try d.open("[");
                for (v.transactions) |*t| {
                    try d.item();
                    try d.open("CheckpointTransactionContents {");
                    try d.field("digest");
                    try digestsDebug(&d, &t.digest);
                    try d.field("user_signatures");
                    if (t.user_signatures.len == 0) try w.writeAll("[],\n") else {
                        try d.open("[");
                        for (t.user_signatures) |us| {
                            try d.item();
                            try d.open("(");
                            try d.item();
                            try sigDebug(&d, us[0].@"0");
                            try d.item();
                            if (us[1]) |sn| {
                                try d.open("Some(");
                                try d.item();
                                try d.tuple1("SequenceNumber", "{d}", .{sn.@"0"});
                                try d.close("),");
                            } else try w.writeAll("None,\n");
                            try d.close("),");
                        }
                        try d.close("],");
                    }
                    try d.close("},");
                }
                try d.close("],");
            }
            try d.close("},");
            try d.closeLast(")");
        },
    }
}
