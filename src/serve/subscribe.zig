//! sui.rpc.v2 SubscriptionService: SubscribeCheckpoints, SubscribeTransactions and SubscribeEvents
//! (unfiltered and filtered), after sui-rpc-api 1.83.1 `subscription/{mod,matcher}.rs` and
//! `grpc/v2/subscription_service.rs`.
//!
//! Fan-out. `Hub.publish(seq)` runs once per committed checkpoint, in order (the watcher thread
//! follows `Store.committed()`, so a subscriber that sees checkpoint N can read N right away, as
//! sui-node holds a checkpoint back until its index committed it). It decides each subscriber's
//! update with the matcher's rules and puts it in the subscriber's queue:
//!   * unfiltered checkpoint stream: every checkpoint, no start frame;
//!   * filtered checkpoint stream and every transaction stream: first a start tick naming the
//!     checkpoint before entry, then a match, or a progress tick after `watermark_interval` (25)
//!     checkpoints without a frame;
//!   * unfiltered transaction stream: every transaction of every checkpoint.
//!   * event streams: as transaction streams, in event space (per-event dimension keys, every
//!     event of a checkpoint unfiltered; a checkpoint without events is not a match).
//! Queues hold `queue_cap` (256) updates, sui-node's `SUBSCRIPTION_CHANNEL_SIZE`. A full queue
//! ends the subscription as `slow_consumer`: like tokio's mpsc after the sender is dropped, the
//! consumer still delivers what is queued, then the stream ends with status OK (no error: clients
//! reconnect and backfill). At most `max_subscribers` (1024) streams; one more is UNAVAILABLE.
//! As in sui-node, whose actor drops the subscriber from its table on `try_send` Full, a stream
//! the hub ends (slow consumer, source lag, shutdown) gives its slot back at once, while its pump
//! still drains what is queued. A pump whose peer stops reading for `stall_timeout_ms` after the
//! hub ended it finishes the stream and frees the subscriber.
//!
//! Rendering. The pump of each stream renders its own frames from a store snapshot with the same
//! code as GetCheckpoint/GetTransaction (service.zig), so masks behave identically. Frames carry
//! `cursor` (checkpoints) or `watermark` (transactions) as sui-node builds them. A snapshot is an
//! RCU read-side section, so the pump renders every frame of an update into owned buffers,
//! releases the snapshot, and only then sends: a peer that stops reading never pins store memory.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const h2 = @import("h2/root.zig");
const proto = @import("proto.zig");
const mask = @import("mask.zig");
const ledger = @import("ledger.zig");
const objset = @import("objset.zig");
const schema = @import("schema.zig");
const reqdecode = @import("reqdecode.zig");
const render_tx = @import("render_tx.zig");
const rc_mod = @import("render_checkpoint.zig");
const render_json = @import("render_json.zig");
const service = @import("service.zig");
const stream_conn = @import("stream_conn.zig");
const txfilter = @import("txfilter.zig");
const watermark = @import("watermark.zig");
const lh_service = @import("lh_service.zig");
const ro = @import("render_object.zig");
const rpcevents = @import("conformance_rpcevents.zig");

pub const prefix = "/sui.rpc.v2.SubscriptionService/";
pub const queue_cap = 256;
pub const default_max_subscribers = 1024;
pub const default_watermark_interval = 25;
/// Ten minutes: long enough that a client pausing its reads (GC, debugger, the G5 stall check's
/// 150 s) still gets the queued frames and an OK end as from sui-node, short enough that a
/// silently dead path (h2 window at zero, so TCP has nothing to time out) cannot pin a pump.
pub const default_stall_timeout_ms = 600_000;

/// The end of a local checkpoint stream whose mask renders certificates, at the first
/// checkpoint whose certificate is not the core's (an edge with a core upstream).
pub const foreign_cert_text = "edge holds another certificate for this checkpoint than its core; reconnect";

pub const Kind = enum { checkpoints, transactions, events };
pub const Reason = enum(u8) { client_closed, slow_consumer, source_lag, service_shutdown };

const Range = struct { lo: u32, hi: u32 };
/// One matched event: transaction index in the checkpoint, event index in the transaction.
const EvRef = struct { tx: u32, ev: u32 };

const Update = struct {
    tag: enum { matched, tick },
    /// matched: the checkpoint; tick: the checkpoint the tick follows.
    cp: u64,
    /// tick: the exclusive transaction upper bound after `cp`.
    tx_hi: u64 = 0,
    /// matched transaction stream: matched transaction index runs (gpa-owned; null = all).
    ranges: ?[]Range = null,
    /// matched event stream: matched events, ascending (gpa-owned; null = every event).
    evs: ?[]EvRef = null,

    fn free(u: Update, gpa: Allocator) void {
        if (u.ranges) |r| gpa.free(r);
        if (u.evs) |e| gpa.free(e);
    }
};

pub const Sub = struct {
    hub: *Hub,
    kind: Kind,
    arena: std.heap.ArenaAllocator,
    mask_tree: mask.Tree,
    query: ?txfilter.Query,
    ring: [queue_cap]Update = undefined,
    head: usize = 0,
    len: usize = 0,
    /// Set by the hub: no update follows what is queued.
    end: ?Reason = null,
    /// With `end`: the stream ends UNAVAILABLE with this text instead of OK (`endAllUnavailable`).
    end_unavailable: ?[]const u8 = null,
    /// Set by the consumer once its stream is over; the hub drops the subscriber.
    gone: bool = false,
    needs_start: bool,
    /// Holds a slot (`reserved`, `stats.subscribers`, `filtered_count` when `txKeyed`). Cleared under `hub.mu`
    /// when the hub ends the stream or the consumer releases it, whichever comes first.
    counted: bool = true,
    since_frame: u32 = 0,
    /// Futex word: bumped by the hub (new update, end) and by the connection (window, close).
    ev: Atomic(u32) = .init(0),
    // consumer-side watermark state (transaction streams)
    boundary: ?u64 = null,
    entry_cp: ?u64 = null,

    fn filtered(s: *const Sub) bool {
        return s.query != null;
    }

    /// Matched on per-transaction keys (`filtered_count`): filtered checkpoint and transaction
    /// streams. Event streams match per-event keys, computed on their own.
    fn txKeyed(s: *const Sub) bool {
        return s.query != null and s.kind != .events;
    }

    fn bump(s: *Sub) void {
        _ = s.ev.fetchAdd(1, .release);
        s.hub.io.futexWake(u32, &s.ev.raw, std.math.maxInt(u32));
    }

    /// Hub side, under `hub.mu`.
    fn offer(s: *Sub, u: Update) bool {
        if (s.len == queue_cap) {
            u.free(s.hub.gpa);
            return false;
        }
        s.ring[(s.head + s.len) % queue_cap] = u;
        s.len += 1;
        return true;
    }
};

pub const Stats = struct {
    subscribers: Atomic(u64) = .init(0),
    frames: Atomic(u64) = .init(0),
    bytes: Atomic(u64) = .init(0),
    published: Atomic(u64) = .init(0),
    terminations: [4]Atomic(u64) = @splat(.init(0)),
    /// Local checkpoint streams ended at a checkpoint whose certificate is not the core's
    /// (`foreign_cert_text`; an edge with a core upstream).
    foreign_cert_ends: Atomic(u64) = .init(0),
    /// Wall clock (ms) minus the checkpoint timestamp when the hub published it, last value.
    publish_lag_ms: Atomic(u64) = .init(0),
};

pub const Hub = struct {
    gpa: Allocator,
    io: Io,
    svc: *service.Service,
    mu: Io.Mutex = .init,
    subs: std.ArrayList(*Sub) = .empty,
    reserved: Atomic(usize) = .init(0),
    filtered_count: Atomic(usize) = .init(0),
    max_subscribers: usize = default_max_subscribers,
    watermark_interval: u32 = default_watermark_interval,
    max_filter_literals: u32 = txfilter.default_max_literals,
    /// Last checkpoint handed to `publish` (null until the watcher starts).
    published: ?u64 = null,
    stop_flag: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    stats: Stats = .{},
    /// A pump whose stream the hub ended gives up after its peer accepted nothing for this long.
    stall_timeout_ms: u64 = default_stall_timeout_ms,
    /// Released subscribers kept for reuse (see `freeSub`).
    spare: std.ArrayList(*Sub) = .empty,
    spare_mu: Io.Mutex = .init,

    pub fn init(gpa: Allocator, io: Io, svc: *service.Service) Hub {
        return .{ .gpa = gpa, .io = io, .svc = svc };
    }

    /// Starts the watcher that publishes every newly committed checkpoint.
    pub fn start(h: *Hub) !void {
        h.thread = try std.Thread.spawn(.{}, watch, .{h});
    }

    pub fn stop(h: *Hub) void {
        h.stop_flag.store(true, .release);
        if (h.thread) |t| t.join();
        h.thread = null;
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        for (h.subs.items) |s| if (s.end == null) h.endSub(s, .service_shutdown);
        h.dropUncounted();
    }

    /// Frees subscribers whose streams are over (call after every pump has returned).
    pub fn deinit(h: *Hub) void {
        for (h.subs.items) |s| h.freeSub(s);
        h.subs.deinit(h.gpa);
        for (h.spare.items) |s| h.gpa.destroy(s);
        h.spare.deinit(h.gpa);
    }

    fn watch(h: *Hub) void {
        while (!h.stop_flag.load(.acquire)) {
            // sui-node gates delivery on the live-object index (`indexed_checkpoint_fn`): a
            // subscriber that sees checkpoint N can read N's owned objects and balances
            const committed = if (h.svc.store.committed()) |c| service.boundByIndex(h.svc, c) else null;
            if (committed) |c| {
                if (h.published == null) h.published = c; // streams start at the tip
                while (h.published.? < c and !h.stop_flag.load(.acquire)) h.publish(h.published.? + 1);
            }
            const idle = h.stats.subscribers.load(.monotonic) == 0;
            h.io.sleep(.fromMilliseconds(if (idle) 20 else 1), .awake) catch {};
        }
    }

    /// Ends every open stream with UNAVAILABLE and `text` (a static string): an edge that fell
    /// behind its core closes its local streams so their clients reconnect and are forwarded
    /// (src/edge/forward.zig, the freshness guard). What is already queued is dropped: it is
    /// what the edge is behind on. Counted under `source_lag`. Returns how many it ended.
    pub fn endAllUnavailable(h: *Hub, text: []const u8) usize {
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        var n: usize = 0;
        for (h.subs.items) |s| if (s.end == null) {
            while (s.len > 0) {
                s.ring[s.head].free(h.gpa);
                s.head = (s.head + 1) % queue_cap;
                s.len -= 1;
            }
            s.end_unavailable = text;
            h.endSub(s, .source_lag);
            n += 1;
        };
        h.dropUncounted();
        return n;
    }

    /// Under `h.mu`. A hub-side end (anything but `client_closed`) frees the slot now; the
    /// entry leaves `h.subs` at the next `dropUncounted` (callers may be iterating it).
    fn endSub(h: *Hub, s: *Sub, why: Reason) void {
        s.end = why;
        _ = h.stats.terminations[@backingInt(why)].fetchAdd(1, .monotonic);
        if (why != .client_closed) h.uncount(s);
        s.bump();
    }

    /// Under `h.mu`: gives the subscriber's slot back (once).
    fn uncount(h: *Hub, s: *Sub) void {
        if (!s.counted) return;
        s.counted = false;
        if (s.txKeyed()) _ = h.filtered_count.fetchSub(1, .monotonic);
        _ = h.stats.subscribers.fetchSub(1, .monotonic);
        _ = h.reserved.fetchSub(1, .monotonic);
    }

    /// Under `h.mu`: removes ended subscribers whose slot is already free from the fan-out list.
    fn dropUncounted(h: *Hub) void {
        var i: usize = 0;
        while (i < h.subs.items.len) {
            if (h.subs.items[i].counted) i += 1 else _ = h.subs.swapRemove(i);
        }
    }

    fn freeSub(h: *Hub, s: *Sub) void {
        while (s.len > 0) {
            s.ring[s.head].free(h.gpa);
            s.head = (s.head + 1) % queue_cap;
            s.len -= 1;
        }
        s.arena.deinit();
        s.arena = .init(h.gpa);
        // Kept for reuse, never freed while the hub lives: a runtime may still call the pump's
        // `wake` on it after `run` returned (a spurious futex wake is harmless; freed memory is
        // not). Bounded by the most subscribers ever open at once.
        h.spare_mu.lockUncancelable(h.io);
        defer h.spare_mu.unlock(h.io);
        h.spare.append(h.gpa, s) catch {};
    }

    fn newSub(h: *Hub) ?*Sub {
        {
            h.spare_mu.lockUncancelable(h.io);
            defer h.spare_mu.unlock(h.io);
            if (h.spare.pop()) |s| {
                s.arena.deinit();
                return s;
            }
        }
        return h.gpa.create(Sub) catch null;
    }

    /// Admits a subscriber (null at the limit). `query` and the mask live in the sub's arena.
    fn subscribe(h: *Hub, kind: Kind) ?*Sub {
        const prev = h.reserved.fetchAdd(1, .monotonic);
        if (prev >= h.max_subscribers) {
            _ = h.reserved.fetchSub(1, .monotonic);
            return null;
        }
        const s = h.newSub() orelse {
            _ = h.reserved.fetchSub(1, .monotonic);
            return null;
        };
        s.* = .{ .hub = h, .kind = kind, .arena = .init(h.gpa), .mask_tree = undefined, .query = null, .needs_start = kind != .checkpoints };
        return s;
    }

    fn activate(h: *Hub, s: *Sub) !void {
        if (s.kind == .checkpoints and s.query != null) s.needs_start = true;
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        try h.subs.append(h.gpa, s);
        if (s.txKeyed()) _ = h.filtered_count.fetchAdd(1, .monotonic);
        _ = h.stats.subscribers.fetchAdd(1, .monotonic);
    }

    /// Consumer side: the stream is over (finished or the client left). Called exactly once per
    /// admitted subscriber.
    fn release(h: *Hub, s: *Sub) void {
        h.mu.lockUncancelable(h.io);
        if (s.end == null) h.endSub(s, .client_closed);
        for (h.subs.items, 0..) |x, i| if (x == s) {
            _ = h.subs.swapRemove(i);
            break;
        };
        h.uncount(s);
        h.mu.unlock(h.io);
        h.freeSub(s);
    }

    /// Takes a subscriber slot with no stream behind it (the rpc-events suite: a capture's other
    /// open subscription). Null when the hub is full.
    pub fn holdSlot(h: *Hub, kind: Kind) !?*Sub {
        const s = h.subscribe(kind) orelse return null;
        s.mask_tree = try mask.Tree.parse(s.arena.allocator(), "event_type");
        try h.activate(s);
        return s;
    }

    pub fn releaseHeld(h: *Hub, s: *Sub) void {
        h.release(s);
    }

    /// Fans checkpoint `seq` out to every subscriber. Called in checkpoint order.
    pub fn publish(h: *Hub, seq: u64) void {
        h.published = seq;
        _ = h.stats.published.fetchAdd(1, .monotonic);
        if (h.stats.subscribers.load(.monotonic) == 0) return;
        var arena_state = std.heap.ArenaAllocator.init(h.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var info = h.checkpointInfo(arena, seq, h.filtered_count.load(.monotonic) > 0) catch |e| {
            std.log.err("subscriptions: checkpoint {d} unreadable ({s}); ending every stream", .{ seq, @errorName(e) });
            h.mu.lockUncancelable(h.io);
            defer h.mu.unlock(h.io);
            for (h.subs.items) |s| if (s.end == null) h.endSub(s, .source_lag);
            h.dropUncounted();
            return;
        };
        h.stats.publish_lag_ms.store(nowMs() -| info.timestamp_ms, .monotonic);
        const tx_lo = info.tx_hi - info.tx_count;

        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        defer h.dropUncounted();
        for (h.subs.items) |s| {
            if (s.end != null) continue;
            if (s.needs_start) {
                s.needs_start = false;
                if (seq > 0) {
                    if (!s.offer(.{ .tag = .tick, .cp = seq - 1, .tx_hi = tx_lo })) {
                        h.endSub(s, .slow_consumer);
                        continue;
                    }
                    s.since_frame = 0;
                }
            }
            var upd: ?Update = null;
            if (s.query) |*q| {
                if (s.kind == .events) {
                    if (info.ev_keys == null) info.ev_keys = h.checkpointEventKeys(arena, seq) catch |e| {
                        std.log.err("subscriptions: checkpoint {d} event keys ({s}); ending the stream", .{ seq, @errorName(e) });
                        h.endSub(s, .source_lag);
                        continue;
                    };
                    var refs: std.ArrayList(EvRef) = .empty;
                    var oom = false;
                    for (info.ev_keys.?, 0..) |tx_keys, i| for (tx_keys, 0..) |*k, j| if (txfilter.matches(q, k)) {
                        refs.append(h.gpa, .{ .tx = @intCast(i), .ev = @intCast(j) }) catch {
                            oom = true;
                        };
                    };
                    if (oom) {
                        refs.deinit(h.gpa);
                        h.endSub(s, .slow_consumer);
                        continue;
                    }
                    if (refs.items.len > 0) {
                        const owned = refs.toOwnedSlice(h.gpa) catch {
                            refs.deinit(h.gpa);
                            h.endSub(s, .slow_consumer);
                            continue;
                        };
                        upd = .{ .tag = .matched, .cp = seq, .evs = owned };
                    }
                } else {
                // A filtered subscriber can join after `checkpointInfo` ran without keys.
                if (info.keys == null) info.keys = h.checkpointKeys(arena, seq) catch |e| {
                    std.log.err("subscriptions: checkpoint {d} keys ({s}); ending the stream", .{ seq, @errorName(e) });
                    h.endSub(s, .source_lag);
                    continue;
                };
                const keys = info.keys.?;
                switch (s.kind) {
                    .checkpoints => for (keys) |*k| {
                        if (txfilter.matches(q, k)) {
                            upd = .{ .tag = .matched, .cp = seq };
                            break;
                        }
                    },
                    .transactions => {
                        var runs: std.ArrayList(Range) = .empty;
                        for (keys, 0..) |*k, i| if (txfilter.matches(q, k)) {
                            const ii: u32 = @intCast(i);
                            if (runs.items.len > 0 and runs.items[runs.items.len - 1].hi == ii) {
                                runs.items[runs.items.len - 1].hi = ii + 1;
                            } else runs.append(h.gpa, .{ .lo = ii, .hi = ii + 1 }) catch {
                                runs.deinit(h.gpa);
                                h.endSub(s, .slow_consumer);
                                break;
                            };
                        };
                        if (s.end != null) continue;
                        if (runs.items.len > 0) {
                            upd = .{ .tag = .matched, .cp = seq, .ranges = runs.toOwnedSlice(h.gpa) catch null };
                            if (upd.?.ranges == null) {
                                runs.deinit(h.gpa);
                                h.endSub(s, .slow_consumer);
                                continue;
                            }
                        }
                    },
                    .events => unreachable,
                }
                }
            } else switch (s.kind) {
                .checkpoints => upd = .{ .tag = .matched, .cp = seq },
                .transactions => if (info.tx_count > 0) {
                    upd = .{ .tag = .matched, .cp = seq };
                },
                .events => {
                    // AllEvents: never for a checkpoint without events.
                    if (info.any_events == null) info.any_events = h.checkpointHasEvents(arena, seq) catch |e| {
                        std.log.err("subscriptions: checkpoint {d} events ({s}); ending the stream", .{ seq, @errorName(e) });
                        h.endSub(s, .source_lag);
                        continue;
                    };
                    if (info.any_events.?) upd = .{ .tag = .matched, .cp = seq };
                },
            }
            const u = upd orelse blk: {
                s.since_frame += 1;
                if (s.since_frame < h.watermark_interval) continue;
                break :blk Update{ .tag = .tick, .cp = seq, .tx_hi = info.tx_hi };
            };
            if (s.offer(u)) {
                s.since_frame = 0;
                s.bump();
            } else h.endSub(s, .slow_consumer);
        }
    }

    const Info = struct {
        tx_hi: u64,
        tx_count: u64,
        timestamp_ms: u64,
        /// Per-transaction dimension keys, when a filtered subscriber exists.
        keys: ?[]txfilter.KeySet = null,
        /// Per-transaction, per-event dimension keys, when a filtered event subscriber exists.
        ev_keys: ?[]const []txfilter.KeySet = null,
        /// Whether any transaction of the checkpoint has events (unfiltered event streams).
        any_events: ?bool = null,
    };

    fn checkpointInfo(h: *Hub, arena: Allocator, seq: u64, want_keys: bool) !Info {
        var snap = h.svc.store.snapshot();
        defer snap.release();
        const rec = snap.checkpoint(seq) orelse return error.NotFound;
        const cert = try rc_mod.Cert.parse(arena, rec.summary_cert);
        const contents = try bcs.decode(types.CheckpointContents, arena, rec.contents);
        const n: u64 = switch (contents) {
            .V1 => |v| v.transactions.len,
            .V2 => |v| v.transactions.len,
        };
        var info: Info = .{ .tx_hi = cert.summary.network_total_transactions, .tx_count = n, .timestamp_ms = cert.summary.timestamp_ms };
        if (want_keys) info.keys = try keysOf(h, arena, &snap, rec);
        return info;
    }

    fn checkpointKeys(h: *Hub, arena: Allocator, seq: u64) ![]txfilter.KeySet {
        var snap = h.svc.store.snapshot();
        defer snap.release();
        const rec = snap.checkpoint(seq) orelse return error.NotFound;
        return keysOf(h, arena, &snap, rec);
    }

    /// Per-transaction, per-event dimension keys of a checkpoint (`extract_checkpoint_keys`,
    /// event space): EventExtant plus the event dimensions of each event.
    fn checkpointEventKeys(h: *Hub, arena: Allocator, seq: u64) ![]const []txfilter.KeySet {
        var snap = h.svc.store.snapshot();
        defer snap.release();
        const rec = snap.checkpoint(seq) orelse return error.NotFound;
        const d = try service.loadCheckpointData(h.svc, arena, &snap, rec, true, false);
        const out = try arena.alloc([]txfilter.KeySet, d.txs.len);
        for (d.txs, out) |t, *o| {
            const tx = try bcs.decode(types.TransactionData, arena, t.transaction);
            const eff = try bcs.decode(types.TransactionEffects, arena, t.effects);
            const evs: ?types.TransactionEvents = if (t.events) |b| try bcs.decode(types.TransactionEvents, arena, b) else null;
            o.* = try txfilter.eventKeysDecoded(arena, &tx, &eff, if (evs) |*e| e else null);
        }
        return out;
    }

    fn checkpointHasEvents(h: *Hub, arena: Allocator, seq: u64) !bool {
        var snap = h.svc.store.snapshot();
        defer snap.release();
        const rec = snap.checkpoint(seq) orelse return error.NotFound;
        const d = try service.loadCheckpointData(h.svc, arena, &snap, rec, true, false);
        for (d.txs) |t| if (eventCount(t.events) > 0) return true;
        return false;
    }

    /// Per-transaction dimension keys of a checkpoint (`extract_checkpoint_keys`).
    fn keysOf(h: *Hub, arena: Allocator, snap: *store.Snapshot, rec: store.CheckpointRecord) ![]txfilter.KeySet {
        const d = try service.loadCheckpointData(h.svc, arena, snap, rec, true, true);
        var set = try objset.ObjSet.build(arena, d.objects);
        const keys = try arena.alloc(txfilter.KeySet, d.txs.len);
        for (d.txs, keys) |t, *k| k.* = try txfilter.transactionKeys(arena, t.transaction, t.effects, t.events, &set);
        return keys;
    }
};

fn nowMs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

// ---------------------------------------------------------------- gRPC handlers

const subscribe_checkpoints_request = reqdecode.subscribe_checkpoints_request;
const subscribe_transactions_request = reqdecode.subscribe_transactions_request;

pub fn call(svc: *service.Service, arena: Allocator, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    const method = req.path[prefix.len..];
    const kind: Kind = if (std.mem.eql(u8, method, "SubscribeCheckpoints"))
        .checkpoints
    else if (std.mem.eql(u8, method, "SubscribeTransactions"))
        .transactions
    else if (std.mem.eql(u8, method, "SubscribeEvents"))
        .events
    else
        return .unimplemented;
    const shape = switch (kind) {
        .checkpoints => &subscribe_checkpoints_request,
        .transactions => &subscribe_transactions_request,
        .events => &reqdecode.subscribe_events_request,
    };
    if (reqdecode.check(arena, shape, req.body)) |text| {
        rs.setMessage(text);
        return .internal;
    }
    return start(svc, arena, req, rs, kind) catch |e| service.fail(arena, rs, e);
}

fn start(svc: *service.Service, arena: Allocator, req: *const h2.Request, rs: *h2.ResponseStream, kind: Kind) !h2.Status {
    // Everything the subscriber keeps (mask names borrow from the request bytes) lives in its own
    // arena, moved into the subscriber once it is admitted.
    var keep_arena = std.heap.ArenaAllocator.init(svc.gpa);
    var owned = false;
    defer if (!owned) keep_arena.deinit();
    const a = keep_arena.allocator();
    const body = try a.dupe(u8, req.body);
    // SubscribeXRequest { read_mask = 1; filter = 2 }: a repeated message field merges, and the
    // concatenation of encoded messages is their merge.
    var mask_field: service.MaskField = .{};
    var filter_bytes: std.ArrayList(u8) = .empty;
    var has_filter = false;
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => try mask_field.add(arena, proto.Reader.bytesOf(f) catch return error.Malformed),
        2 => {
            has_filter = true;
            try filter_bytes.appendSlice(arena, proto.Reader.bytesOf(f) catch return error.Malformed);
        },
        else => {},
    };
    // sui-node order: read mask, filter, then registration.
    const mk = switch (kind) {
        .checkpoints => try service.parseMask(a, rs, &mask_field, "sequence_number,digest", comptime schema.index("Checkpoint")),
        .transactions => try service.parseMask(a, rs, &mask_field, "digest", comptime schema.index("ExecutedTransaction")),
        .events => try service.parseMask(a, rs, &mask_field, "event_type", comptime schema.index("Event")),
    };
    const max_literals = if (svc.hub) |hb| hb.max_filter_literals else txfilter.default_max_literals;
    const query: ?txfilter.Query = if (!has_filter) null else switch (kind) {
        .events => try txfilter.compileEventFilter(a, filter_bytes.items, max_literals, rs),
        else => try txfilter.compileTransactionFilter(a, filter_bytes.items, max_literals, rs),
    };
    const hub = svc.hub orelse {
        rs.setMessage("subscription service not enabled");
        return .unimplemented;
    };
    if (!stream_conn.streaming()) {
        rs.setMessage("server streaming is not available on this connection");
        return .unimplemented;
    }
    const s = hub.subscribe(kind) orelse {
        rs.setMessage("subscription service is unavailable");
        return .unavailable;
    };
    s.arena.deinit();
    s.arena = keep_arena;
    owned = true;
    s.mask_tree = mk.tree;
    s.query = query;
    hub.activate(s) catch {
        _ = hub.reserved.fetchSub(1, .monotonic);
        hub.freeSub(s);
        return error.OutOfMemory;
    };
    var pump: stream_conn.Pump = .{ .ctx = s, .run = pumpRun, .wake = pumpWake };
    if (comptime runtime_done) pump.done = pumpDone;
    if (!stream_conn.attach(req.stream_id, pump)) {
        hub.release(s);
        rs.setMessage("server streaming is not available on this connection");
        return .unimplemented;
    }
    return .deferred;
}

fn pumpWake(ctx: *anyopaque) void {
    const s: *Sub = @ptrCast(@alignCast(ctx));
    s.bump();
}

/// Whether the runtime calls `Pump.done` exactly once, after `run` or in its place. Then the
/// subscriber is released there and only there: `pumpRun` releasing it would put it on the spare
/// list while the runtime still holds it, and the next stream could take it before `done` ran.
const runtime_done = @hasField(stream_conn.Pump, "done");

/// stream_conn.Pump.done: the runtime's last use of the subscriber.
fn pumpDone(ctx: *anyopaque) void {
    const s: *Sub = @ptrCast(@alignCast(ctx));
    s.hub.release(s);
}

fn pumpRun(ctx: *anyopaque, link: *stream_conn.Link) void {
    const s: *Sub = @ptrCast(@alignCast(ctx));
    const h = s.hub;
    // Released in `pumpDone` (or here for a runtime without `done`), then kept for reuse: a late
    // `wake` from the runtime stays harmless.
    defer if (!runtime_done) h.release(s);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(h.gpa);
    // Since when (monotonic ms) the link has stayed blocked after the hub ended the stream.
    var stalled_since: ?u64 = null;
    while (true) {
        const seen = s.ev.load(.acquire);
        const blocked = link.blocked() orelse return; // stream reset or connection gone
        var next: ?Update = null;
        var ended = false;
        var hub_ended = false;
        {
            h.mu.lockUncancelable(h.io);
            defer h.mu.unlock(h.io);
            if (!blocked and s.len > 0) {
                next = s.ring[s.head];
                s.head = (s.head + 1) % queue_cap;
                s.len -= 1;
            } else if (s.len == 0 and s.end != null) ended = true;
            hub_ended = s.end != null;
        }
        if (ended) {
            // sui-node: the stream ends when the actor drops the subscriber; tonic sends OK.
            if (s.end_unavailable) |text| link.finish(.unavailable, text) else link.finish(.ok, "");
            return;
        }
        if (blocked and hub_ended) {
            // The slot is already free; do not keep the thread and the queue for a peer that
            // stopped reading (a silently dead path never closes the connection by itself).
            const now = monoMs();
            const since = stalled_since orelse now;
            stalled_since = since;
            if (now - since >= h.stall_timeout_ms) {
                link.finish(.unavailable, "subscriber stalled");
                return;
            }
        } else stalled_since = null;
        const u = next orelse {
            h.io.futexWaitTimeout(u32, &s.ev.raw, seen, .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(200), .clock = .awake } }) catch {};
            continue;
        };
        defer u.free(h.gpa);
        sendUpdate(s, link, u, &out) catch |e| switch (e) {
            error.Closed => return,
            error.ForeignCert => {
                _ = h.stats.foreign_cert_ends.fetchAdd(1, .monotonic);
                link.finish(.unavailable, foreign_cert_text);
                return;
            },
            else => {
                std.log.err("subscription frame for checkpoint {d}: {s}", .{ u.cp, @errorName(e) });
                link.finish(.internal, @errorName(e));
                return;
            },
        };
    }
}

fn monoMs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

/// Renders the update's frames under a store snapshot, releases it, then sends. A snapshot is an
/// RCU read-side section: holding it across `link.send`, which may block on a peer that stopped
/// reading, would stop the store from reclaiming anything.
fn sendUpdate(s: *Sub, link: *stream_conn.Link, u: Update, out: *std.ArrayList(u8)) !void {
    const h = s.hub;
    var arena_state = std.heap.ArenaAllocator.init(h.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    switch (s.kind) {
        .checkpoints => {
            const bytes = try renderCheckpointUpdate(s, arena, u, out);
            try sendFrame(h, link, bytes);
        },
        .transactions => {
            var frames: std.ArrayList([]const u8) = .empty;
            try renderTransactionUpdate(s, arena, u, out, &frames);
            for (frames.items) |bytes| try sendFrame(h, link, bytes);
        },
        .events => {
            var frames: std.ArrayList([]const u8) = .empty;
            try renderEventUpdate(s, arena, u, out, &frames);
            for (frames.items) |bytes| try sendFrame(h, link, bytes);
        },
    }
}

/// The number of events in BCS TransactionEvents (its leading ULEB128 length).
fn eventCount(events: ?[]const u8) u64 {
    const b = events orelse return 0;
    var r = bcs.Reader.init(b);
    return r.length() catch 0;
}

/// Every frame of the event stream's update `u` (subscription_service.rs `subscribe_events`), each
/// copied into `arena`; no snapshot is held on return.
fn renderEventUpdate(s: *Sub, arena: Allocator, u: Update, out: *std.ArrayList(u8), frames: *std.ArrayList([]const u8)) !void {
    const h = s.hub;
    const m = s.mask_tree.mask();
    switch (u.tag) {
        .tick => {
            watermark.recordTick(&s.boundary, &s.entry_cp, u.cp);
            const bytes = try renderInto(h.gpa, out, EvTick{ .cp = u.cp, .tx_hi = u.tx_hi, .boundary = s.boundary }, EvTick.render);
            try frames.append(arena, try arena.dupe(u8, bytes));
        },
        .matched => {
            var snap = h.svc.store.snapshot();
            defer snap.release();
            const rec = snap.checkpoint(u.cp) orelse return error.CheckpointGone;
            const cert = try rc_mod.Cert.parse(arena, rec.summary_cert);
            const want_json = m.contains("json");
            const d = try service.loadCheckpointData(h.svc, arena, &snap, rec, true, want_json);
            const digests = try txDigests(arena, rec.contents);
            const entry = s.entry_cp orelse u.cp;
            s.entry_cp = entry;
            const tx_hi = cert.summary.network_total_transactions;
            const tx_lo = tx_hi - d.txs.len;
            // render_event_to_proto(event, mask, &checkpoint.object_set): json resolves types
            // against the checkpoint's objects, each event with its own max_json_move_value_size.
            var rctx: ?*const ro.Ctx = null;
            if (want_json) {
                const src = try arena.create(service.ObjSource);
                src.* = .{ .snap = &snap, .overlay = d.objects };
                rctx = try service.renderCtx(h.svc, arena, src);
            }
            var refs: std.ArrayList(EvRef) = .empty;
            const pairs: []const EvRef = u.evs orelse blk: {
                for (d.txs, 0..) |t, i| {
                    var j: u64 = 0;
                    while (j < eventCount(t.events)) : (j += 1) try refs.append(arena, .{ .tx = @intCast(i), .ev = @intCast(j) });
                }
                break :blk refs.items;
            };
            var cur_tx: ?u32 = null;
            var evs: types.TransactionEvents = .{ .data = &.{} };
            for (pairs) |p| {
                if (cur_tx != p.tx) {
                    const b = d.txs[p.tx].events orelse return error.Internal; // matched event implies events
                    evs = try bcs.decode(types.TransactionEvents, arena, b);
                    cur_tx = p.tx;
                }
                if (p.ev >= evs.data.len) return error.Internal;
                var ev_arena = std.heap.ArenaAllocator.init(h.gpa);
                defer ev_arena.deinit();
                s.boundary = watermark.advanceBeforeCheckpoint(s.boundary, u.cp, entry);
                const bytes = try renderInto(h.gpa, out, EvFrame{
                    .arena = ev_arena.allocator(),
                    .m = m,
                    .e = evs.data[p.ev],
                    .row = .{ .tx_seq = tx_lo + p.tx, .digest = digests[p.tx], .checkpoint = u.cp, .tx_offset = p.tx, .event_count = @intCast(evs.data.len) },
                    .ev = p.ev,
                    .rc = rctx,
                    .tx_lo = tx_lo,
                    .boundary = s.boundary,
                }, EvFrame.render);
                try frames.append(arena, try arena.dupe(u8, bytes));
            }
        },
    }
}

/// The checkpoint stream's frame for `u`, rendered into `out`; no snapshot is held on return.
fn renderCheckpointUpdate(s: *Sub, arena: Allocator, u: Update, out: *std.ArrayList(u8)) ![]const u8 {
    const h = s.hub;
    const m = s.mask_tree.mask();
    switch (u.tag) {
        .tick => return renderInto(h.gpa, out, CpTick{ .cp = u.cp }, CpTick.render),
        .matched => {
            // An edge with a core upstream: the certificate of a checkpoint it did not take
            // from a core is not the core's (docs/EDGE.md section 13). A stream cannot be
            // handed over, so it ends here and its client comes back through the routing.
            // Asked before the record is read, as GetCheckpoint does.
            // With no core reachable the certificate the edge holds goes out (it verifies).
            if (m.contains("signature")) switch (service.certState(h.svc, u.cp)) {
                .core => {},
                .withhold => return error.ForeignCert,
                .held => if (h.svc.foreign_cert) |fc| fc.served_held(fc.ctx),
            };
            var snap = h.svc.store.snapshot();
            defer snap.release();
            const rec = snap.checkpoint(u.cp) orelse return error.CheckpointGone;
            const want_txs = m.subtree("transactions") != null;
            const want_objects = m.subtree("objects") != null or (if (m.subtree("transactions")) |t| service.needsObjectSet(t) else false);
            const d = try service.loadCheckpointData(h.svc, arena, &snap, rec, want_txs, want_objects);
            const budget = try arena.create(usize);
            budget.* = render_json.default_response_budget;
            if (want_txs) {
                // event and object json/display, rendered as GetCheckpoint does
                const src = try arena.create(service.ObjSource);
                src.* = .{ .snap = &snap, .overlay = d.objects };
                const rctx = try service.renderCtx(h.svc, arena, src);
                rctx.json_budget = budget;
                for (d.txs) |*t| t.render = rctx;
            }
            return renderInto(h.gpa, out, CpFrame{ .arena = arena, .m = m, .seq = u.cp, .d = d, .budget = budget }, CpFrame.render);
        },
    }
}

/// Every frame of the transaction stream's update `u`, each copied into `arena`; no snapshot is
/// held on return. Advances the stream's watermark state as the frames are rendered.
fn renderTransactionUpdate(s: *Sub, arena: Allocator, u: Update, out: *std.ArrayList(u8), frames: *std.ArrayList([]const u8)) !void {
    const h = s.hub;
    const m = s.mask_tree.mask();
    switch (u.tag) {
        .tick => {
            // record_watermark_tick_coverage
            watermark.recordTick(&s.boundary, &s.entry_cp, u.cp);
            const bytes = try renderInto(h.gpa, out, TxTick{ .cp = u.cp, .tx_hi = u.tx_hi, .boundary = s.boundary }, TxTick.render);
            try frames.append(arena, try arena.dupe(u8, bytes));
        },
        .matched => {
            var snap = h.svc.store.snapshot();
            defer snap.release();
            const rec = snap.checkpoint(u.cp) orelse return error.CheckpointGone;
            const cert = try rc_mod.Cert.parse(arena, rec.summary_cert);
            const d = try service.loadCheckpointData(h.svc, arena, &snap, rec, true, false);
            const digests = try txDigests(arena, rec.contents);
            const entry = s.entry_cp orelse u.cp;
            s.entry_cp = entry;
            const tx_hi = cert.summary.network_total_transactions;
            const tx_lo = tx_hi - d.txs.len;
            const all = [_]Range{.{ .lo = 0, .hi = @intCast(d.txs.len) }};
            const runs: []const Range = u.ranges orelse &all;
            for (runs) |run| {
                var i = run.lo;
                while (i < run.hi) : (i += 1) {
                    var tx_arena = std.heap.ArenaAllocator.init(h.gpa);
                    defer tx_arena.deinit();
                    const ta = tx_arena.allocator();
                    s.boundary = watermark.advanceBeforeCheckpoint(s.boundary, u.cp, entry);
                    var t = d.txs[i];
                    var objs: std.ArrayList([]const u8) = .empty;
                    if (service.needsObjectSet(m)) {
                        const txr = snap.transactionNear(&digests[i], rec.seq) orelse return error.Internal;
                        var missing: []const u8 = "";
                        try service.collectObjects(h.svc, ta, &snap, txr, &objs, &missing);
                    }
                    const budget = try ta.create(usize);
                    budget.* = render_json.default_response_budget;
                    const src = try ta.create(service.ObjSource);
                    src.* = .{ .snap = &snap, .overlay = objs.items };
                    const rctx = try service.renderCtx(h.svc, ta, src);
                    rctx.json_budget = budget;
                    t.render = rctx;
                    const bytes = try renderInto(h.gpa, out, TxFrame{
                        .arena = ta,
                        .m = m,
                        .t = t,
                        .cp = u.cp,
                        .ts_ms = cert.summary.timestamp_ms,
                        .objs = objs.items,
                        .index = i,
                        .tx_lo = tx_lo,
                        .boundary = s.boundary,
                        .budget = budget,
                    }, TxFrame.render);
                    try frames.append(arena, try arena.dupe(u8, bytes));
                }
            }
        },
    }
}

fn txDigests(arena: Allocator, contents_bytes: []const u8) ![]const [32]u8 {
    const contents = try bcs.decode(types.CheckpointContents, arena, contents_bytes);
    switch (contents) {
        .V1 => |v| {
            const out = try arena.alloc([32]u8, v.transactions.len);
            for (v.transactions, out) |t, *o| o.* = t.transaction.@"0".@"0";
            return out;
        },
        .V2 => |v| {
            const out = try arena.alloc([32]u8, v.transactions.len);
            for (v.transactions, out) |t, *o| o.* = t.digest.transaction.@"0".@"0";
            return out;
        },
    }
}

/// Renders one response into `out` (grown until it fits); the bytes live until `out` changes.
fn renderInto(gpa: Allocator, out: *std.ArrayList(u8), ctx: anytype, comptime render: anytype) ![]const u8 {
    var cap: usize = @max(out.capacity, 4096);
    while (true) : (cap *= 2) {
        try out.ensureTotalCapacity(gpa, cap);
        out.items.len = out.capacity;
        var w = proto.Writer.init(out.items);
        render(ctx, &w) catch |e| {
            if (e == error.NoSpace) continue;
            return e;
        };
        return w.bytesWritten();
    }
}

fn sendFrame(h: *Hub, link: *stream_conn.Link, bytes: []const u8) !void {
    try link.send(bytes);
    _ = h.stats.frames.fetchAdd(1, .monotonic);
    _ = h.stats.bytes.fetchAdd(bytes.len, .monotonic);
}

const CpTick = struct {
    cp: u64,
    fn render(c: CpTick, w: *proto.Writer) !void {
        try w.uint(1, c.cp);
    }
};

const CpFrame = struct {
    arena: Allocator,
    m: mask.Mask,
    seq: u64,
    d: service.CheckpointData,
    /// One event-json budget for the whole checkpoint (subscription_service.rs
    /// render_checkpoint_message, as GetCheckpoint), fresh on each render attempt.
    budget: *usize,
    fn render(c: CpFrame, w: *proto.Writer) !void {
        c.budget.* = render_json.default_response_budget;
        try w.uint(1, c.seq);
        try ledger.checkpointAt(c.arena, w, 2, c.m, c.d.cert, c.d.contents, c.d.objects, c.d.txs);
    }
};

const EvTick = struct {
    cp: u64,
    tx_hi: u64,
    boundary: ?u64,
    fn render(c: EvTick, w: *proto.Writer) !void {
        try watermark.writeEventTick(w, 2, c.cp, c.tx_hi, c.boundary);
    }
};

/// SubscribeEventsResponse { event = 1 (render_event_to_proto + the ledger position fields), watermark = 2 }.
const EvFrame = struct {
    arena: Allocator,
    m: mask.Mask,
    e: types.Event,
    row: lh_service.Row,
    ev: u32,
    rc: ?*const ro.Ctx,
    tx_lo: u64,
    boundary: ?u64,
    fn render(c: EvFrame, w: *proto.Writer) !void {
        try lh_service.writeListEvent(c.arena, w, c.m, c.e, c.row, c.ev, c.rc);
        try watermark.writeEventItem(w, 2, c.row.checkpoint, c.tx_lo, c.row.tx_offset, c.ev, c.boundary);
    }
};

const TxTick = struct {
    cp: u64,
    tx_hi: u64,
    boundary: ?u64,
    fn render(c: TxTick, w: *proto.Writer) !void {
        try watermark.writeTxTick(w, 2, c.cp, c.tx_hi, c.boundary);
    }
};

const TxFrame = struct {
    arena: Allocator,
    m: mask.Mask,
    t: render_tx.Input,
    cp: u64,
    ts_ms: u64,
    objs: []const []const u8,
    index: u32,
    tx_lo: u64,
    boundary: ?u64,
    /// One event-json budget per frame (subscription_service.rs render_transaction_message:
    /// max_json_move_value_response_size shared by the frame's events, unlike GetTransaction).
    budget: *usize,
    fn render(c: TxFrame, w: *proto.Writer) !void {
        c.budget.* = render_json.default_response_budget;
        const mm = try w.begin(1, c.t.transaction.len + c.t.effects.len + 256);
        try ledger.writeExecutedBody(c.arena, w, c.m, c.t, c.cp, c.ts_ms, c.objs);
        if (c.m.contains("transaction_index")) try w.uint(10, c.index);
        try w.end(mm);
        try watermark.writeTxItem(w, 2, c.cp, c.tx_lo, c.index, c.boundary);
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

/// A store holding checkpoints 0..n-1 (empty contents, zero signature: what the hub and the
/// checkpoint render read).
const TestNode = struct {
    sim: *store.SimIo,
    st: *store.Store,
    svc: service.Service,
    hub: Hub,
    cfg: store.Config,

    fn init(self: *TestNode, n: u64) !void {
        const gpa = testing.allocator;
        self.cfg = .{
            .max_live_objects = 1024,
            .max_object_versions = 4096,
            .max_transactions = 1024,
            .max_checkpoints = 1024,
            .max_batch_bytes = 1 << 20,
            .max_batch_objects = 256,
            .max_segments = 64,
            .index_flush_interval = 8,
            .segment_reserve = 8 << 20,
            .seed = 5,
        };
        self.sim = try store.SimIo.init(gpa, 11, .{}, 16 << 20);
        errdefer self.sim.deinit();
        self.st = try store.Store.open(gpa, .{ .sim = self.sim }, &self.cfg);
        errdefer self.st.deinit();
        const contents = [_]u8{ 0, 0, 0 }; // CheckpointContents::V1 { [], [] }
        var seq: u64 = 0;
        while (seq < n) : (seq += 1) {
            const cert = try testCert(gpa, seq);
            defer gpa.free(cert);
            const b = try self.st.begin(seq, 0);
            try b.checkpoint(cert, &contents);
            try self.st.commit(b);
        }
        self.svc = .{ .gpa = gpa, .store = self.st, .chain_id = @splat(0) };
        self.hub = Hub.init(gpa, testing.io, &self.svc);
        self.svc.hub = &self.hub;
    }

    fn deinit(self: *TestNode) void {
        self.hub.deinit();
        self.svc.deinit();
        self.st.deinit();
        self.sim.deinit();
    }

    /// Admits a checkpoint subscriber with the default mask, as `start` does.
    fn subscribe(self: *TestNode) !?*Sub {
        const s = self.hub.subscribe(.checkpoints) orelse return null;
        s.mask_tree = try mask.Tree.parse(s.arena.allocator(), "sequence_number,digest");
        try self.hub.activate(s);
        return s;
    }

    fn readers(self: *TestNode) u64 {
        return self.st.rcu.counts[0].v.load(.seq_cst) + self.st.rcu.counts[1].v.load(.seq_cst);
    }
};

fn testCert(gpa: Allocator, seq: u64) ![]u8 {
    const summary: types.CheckpointSummary = .{
        .epoch = 0,
        .sequence_number = seq,
        .network_total_transactions = 0,
        .content_digest = .{ .@"0" = .{ .@"0" = @splat(0) } },
        .previous_digest = null,
        .epoch_rolling_gas_cost_summary = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .timestamp_ms = 1_700_000_000_000 + seq,
        .checkpoint_commitments = &.{},
        .end_of_epoch_data = null,
        .version_specific_data = &.{},
    };
    // An empty roaring bitmap (cookie 12346, zero containers).
    const empty_bitmap = [_]u8{ 0x3a, 0x30, 0, 0, 0, 0, 0, 0 };
    const sig: types.AuthorityQuorumSignInfo = .{ .epoch = 0, .signature = @splat(0), .signers_map = .{ .@"0" = &empty_bitmap } };
    const a = try bcs.encodeAlloc(types.CheckpointSummary, gpa, &summary);
    defer gpa.free(a);
    const b = try bcs.encodeAlloc(types.AuthorityQuorumSignInfo, gpa, &sig);
    defer gpa.free(b);
    return std.mem.concat(gpa, u8, &.{ a, b });
}

/// A Link that records what the pump does. `send` notes whether a store snapshot is open.
const FakeLink = struct {
    node: *TestNode,
    always_blocked: bool = false,
    sent: u32 = 0,
    sent_under_snapshot: u32 = 0,
    finished: ?h2.Status = null,

    const vt: stream_conn.Link.VTable = .{ .send = send, .finish = finish, .blocked = blocked };

    fn link(f: *FakeLink) stream_conn.Link {
        return .{ .impl = f, .vt = &vt, .stream_id = 1 };
    }
    fn send(ctx: *anyopaque, _: u32, payload: []const u8) error{Closed}!void {
        const f: *FakeLink = @ptrCast(@alignCast(ctx));
        _ = payload;
        f.sent += 1;
        if (f.node.readers() != 0) f.sent_under_snapshot += 1;
    }
    fn finish(ctx: *anyopaque, _: u32, status: h2.Status, text: []const u8, details_bin: []const u8) void {
        _ = text;
        _ = details_bin;
        const f: *FakeLink = @ptrCast(@alignCast(ctx));
        f.finished = status;
    }
    fn blocked(ctx: *anyopaque, _: u32) ?bool {
        const f: *FakeLink = @ptrCast(@alignCast(ctx));
        return f.always_blocked;
    }
};

test "slow consumer frees its slot at once; the pump drains without a snapshot held across send" {
    var node: TestNode = undefined;
    try node.init(queue_cap + 2);
    defer node.deinit();
    const h = &node.hub;
    h.max_subscribers = 1;

    const s = (try node.subscribe()).?;
    try testing.expect((try node.subscribe()) == null); // at the limit: UNAVAILABLE
    var seq: u64 = 0;
    while (seq <= queue_cap) : (seq += 1) h.publish(seq); // queue_cap fit, one more ends it
    try testing.expectEqual(@as(?Reason, .slow_consumer), s.end);
    try testing.expectEqual(@as(usize, queue_cap), s.len);
    // sui-node drops the subscriber from the actor's table on Full: the slot is free already.
    try testing.expectEqual(@as(usize, 0), h.reserved.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), h.stats.subscribers.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), h.subs.items.len);
    const s2 = (try node.subscribe()).?;
    try testing.expect(s2 != s);
    try testing.expectEqual(@as(usize, 1), h.reserved.load(.monotonic));

    // The ended stream still delivers what was queued, then ends OK; never under a snapshot.
    var fl: FakeLink = .{ .node = &node };
    var l = fl.link();
    pumpRun(s, &l);
    try testing.expectEqual(@as(u32, queue_cap), fl.sent);
    try testing.expectEqual(@as(u32, 0), fl.sent_under_snapshot);
    try testing.expectEqual(@as(?h2.Status, .ok), fl.finished);
    try testing.expectEqual(@as(u64, 0), node.readers());
    try testing.expectEqual(@as(usize, 0), h.spare.items.len); // held until the runtime's `done`
    pumpDone(s);
    // Its release does not give the slot back a second time (s2 still holds the only one).
    try testing.expectEqual(@as(usize, 1), h.reserved.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), h.stats.subscribers.load(.monotonic));

    // s2: a live subscriber released by its consumer.
    h.publish(queue_cap + 1);
    try testing.expectEqual(@as(usize, 1), s2.len);
    h.mu.lockUncancelable(h.io);
    h.endSub(s2, .service_shutdown);
    h.dropUncounted();
    h.mu.unlock(h.io);
    var fl2: FakeLink = .{ .node = &node };
    var l2 = fl2.link();
    pumpRun(s2, &l2);
    pumpDone(s2);
    try testing.expectEqual(@as(u32, 1), fl2.sent);
    try testing.expectEqual(@as(u32, 0), fl2.sent_under_snapshot);
    try testing.expectEqual(@as(usize, 0), h.reserved.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), h.stats.subscribers.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), h.stats.terminations[@backingInt(Reason.slow_consumer)].load(.monotonic));
}

test "an edge's local checkpoint stream ends UNAVAILABLE at the first checkpoint whose certificate is not its core's when its mask renders the certificate; a stream that does not render it goes on" {
    var node: TestNode = undefined;
    try node.init(6);
    defer node.deinit();
    const h = &node.hub;
    // checkpoint 4 came from another source than the core and is not replaced yet
    const Marks = struct {
        var no_core: bool = false;
        var served: u32 = 0;
        fn state(_: *anyopaque, seq: u64) service.CertState {
            if (seq != 4) return .core;
            return if (no_core) .held else .withhold;
        }
        fn servedHeld(_: *anyopaque) void {
            served += 1;
        }
    };
    Marks.no_core = false;
    Marks.served = 0;
    var ctx: u8 = 0;
    node.svc.foreign_cert = .{ .ctx = &ctx, .state = Marks.state, .served_held = Marks.servedHeld };
    const with_cert = h.subscribe(.checkpoints).?;
    with_cert.mask_tree = try mask.Tree.parse(with_cert.arena.allocator(), "sequence_number,signature");
    try h.activate(with_cert);
    const without = (try node.subscribe()).?;
    for ([_]u64{ 3, 4, 5 }) |seq| h.publish(seq);
    h.mu.lockUncancelable(h.io);
    h.endSub(with_cert, .service_shutdown);
    h.endSub(without, .service_shutdown);
    h.dropUncounted();
    h.mu.unlock(h.io);
    // checkpoint 3 goes out; at 4 the stream ends, and nothing of 4 or 5 was sent
    var fl: FakeLink = .{ .node = &node };
    var l = fl.link();
    pumpRun(with_cert, &l);
    pumpDone(with_cert);
    try testing.expectEqual(@as(u32, 1), fl.sent);
    try testing.expectEqual(@as(?h2.Status, .unavailable), fl.finished);
    try testing.expectEqual(@as(u64, 1), h.stats.foreign_cert_ends.load(.monotonic));
    // the default mask renders no certificate: all three, then the hub's own end
    var fl2: FakeLink = .{ .node = &node };
    var l2 = fl2.link();
    pumpRun(without, &l2);
    pumpDone(without);
    try testing.expectEqual(@as(u32, 3), fl2.sent);
    try testing.expectEqual(@as(?h2.Status, .ok), fl2.finished);
    try testing.expectEqual(@as(u64, 1), h.stats.foreign_cert_ends.load(.monotonic));
    // no core reachable: the stream goes on, checkpoint 4 with the certificate the edge holds
    Marks.no_core = true;
    const held = h.subscribe(.checkpoints).?;
    held.mask_tree = try mask.Tree.parse(held.arena.allocator(), "sequence_number,signature");
    try h.activate(held);
    for ([_]u64{ 3, 4, 5 }) |seq| h.publish(seq);
    h.mu.lockUncancelable(h.io);
    h.endSub(held, .service_shutdown);
    h.dropUncounted();
    h.mu.unlock(h.io);
    var fl4: FakeLink = .{ .node = &node };
    var l4 = fl4.link();
    pumpRun(held, &l4);
    pumpDone(held);
    try testing.expectEqual(@as(u32, 3), fl4.sent);
    try testing.expectEqual(@as(?h2.Status, .ok), fl4.finished);
    try testing.expectEqual(@as(u32, 1), Marks.served);
    try testing.expectEqual(@as(u64, 1), h.stats.foreign_cert_ends.load(.monotonic));
    // no hook (every node that is not an edge with a core upstream): the stream is as before
    node.svc.foreign_cert = null;
    const plain = h.subscribe(.checkpoints).?;
    plain.mask_tree = try mask.Tree.parse(plain.arena.allocator(), "sequence_number,signature");
    try h.activate(plain);
    for ([_]u64{ 3, 4, 5 }) |seq| h.publish(seq);
    h.mu.lockUncancelable(h.io);
    h.endSub(plain, .service_shutdown);
    h.dropUncounted();
    h.mu.unlock(h.io);
    var fl3: FakeLink = .{ .node = &node };
    var l3 = fl3.link();
    pumpRun(plain, &l3);
    pumpDone(plain);
    try testing.expectEqual(@as(u32, 3), fl3.sent);
    try testing.expectEqual(@as(?h2.Status, .ok), fl3.finished);
}

test "a pump whose peer never reads after the hub ended it gives up and frees the subscriber" {
    var node: TestNode = undefined;
    try node.init(queue_cap + 1);
    defer node.deinit();
    const h = &node.hub;
    h.max_subscribers = 1;
    h.stall_timeout_ms = 30;
    const s = (try node.subscribe()).?;
    var seq: u64 = 0;
    while (seq <= queue_cap) : (seq += 1) h.publish(seq);
    try testing.expectEqual(@as(?Reason, .slow_consumer), s.end);
    // The window never opens: the pump must still return (and release) after the timeout.
    var fl: FakeLink = .{ .node = &node, .always_blocked = true };
    var l = fl.link();
    pumpRun(s, &l);
    try testing.expectEqual(@as(u32, 0), fl.sent);
    try testing.expectEqual(@as(?h2.Status, .unavailable), fl.finished);
    try testing.expectEqual(@as(usize, 0), h.reserved.load(.monotonic));

    // Between `run` returning and the runtime's `done`, a new stream cannot take `s`: it is not
    // on the spare list yet (the race where `done` then released the new owner's subscriber).
    try testing.expectEqual(@as(usize, 0), h.spare.items.len);
    const s3 = (try node.subscribe()).?;
    try testing.expect(s3 != s);
    pumpDone(s3); // a runtime that never started this pump releases it in place of `run`
    try testing.expectEqual(@as(usize, 0), h.reserved.load(.monotonic));
    pumpDone(s); // the runtime's `done` after `run`
    try testing.expectEqual(@as(usize, 2), h.spare.items.len);
    try testing.expectEqual(@as(usize, 0), h.reserved.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), h.stats.subscribers.load(.monotonic));
    // Recycled after `done`: the next stream gets a clean subscriber and a fresh slot.
    const s2 = (try node.subscribe()).?;
    try testing.expect(s2 == s);
    try testing.expect(s2.counted and s2.end == null and s2.len == 0);
    try testing.expectEqual(@as(usize, 1), h.reserved.load(.monotonic));
    pumpDone(s2);
    try testing.expectEqual(@as(usize, 0), h.reserved.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), h.stats.subscribers.load(.monotonic));
}

test "filtered count and slots stay exact across hub ends and consumer releases" {
    var node: TestNode = undefined;
    try node.init(1);
    defer node.deinit();
    const h = &node.hub;
    const s = h.subscribe(.checkpoints).?;
    s.mask_tree = try mask.Tree.parse(s.arena.allocator(), "sequence_number");
    s.query = .{ .terms = &.{} };
    try h.activate(s);
    try testing.expectEqual(@as(usize, 1), h.filtered_count.load(.monotonic));
    h.mu.lockUncancelable(h.io);
    h.endSub(s, .source_lag);
    h.endSub(s, .source_lag); // a second hub end does not free twice
    h.dropUncounted();
    h.mu.unlock(h.io);
    try testing.expectEqual(@as(usize, 0), h.filtered_count.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), h.reserved.load(.monotonic));
    h.release(s);
    try testing.expectEqual(@as(usize, 0), h.filtered_count.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), h.reserved.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), h.stats.subscribers.load(.monotonic));
}

test "SubscribeEvents hub: per-event DNF matching on corpus checkpoints, the start tick, unfiltered streams skip checkpoints without events" {
    const gpa = testing.allocator;
    const corpus = std.c.getenv("ZUI_CORPUS") orelse return error.SkipZigTest;
    var ar = std.heap.ArenaAllocator.init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    var dir = std.Io.Dir.cwd().openDir(testing.io, std.mem.span(corpus), .{}) catch return error.SkipZigTest;
    defer dir.close(testing.io);
    var blobs: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{ "342456120", "342456121", "342456122", "342456123", "342456124", "342456125" }) |nm| {
        const p = try std.fmt.allocPrint(a, "chk/{s}.chk", .{nm});
        try blobs.append(a, dir.readFileAlloc(testing.io, p, a, .limited(1 << 30)) catch return error.SkipZigTest);
    }
    var cfg: store.Config = .{ .max_live_objects = 1 << 16, .max_object_versions = 1 << 17, .max_transactions = 1 << 14, .max_checkpoints = 64, .max_batch_bytes = 256 << 20, .max_batch_objects = 1 << 16, .max_segments = 64, .segment_reserve = 32 << 20, .seed = 5 };
    const sim = try store.SimIo.init(gpa, 11, .{}, 96 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    var idx = try types.index.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var seqs: std.ArrayList(u64) = .empty;
    for (blobs.items) |b| try seqs.append(a, (try rpcevents.ingestBlob(gpa, st, &idx, b)).seq);

    // the type of the first event, and every (checkpoint, tx, event) of that exact type
    var ty: ?types.StructTag = null;
    const Hit = struct { cp: u64, tx: u32, ev: u32 };
    var want: std.ArrayList(Hit) = .empty;
    var with_events: std.ArrayList(u64) = .empty;
    for (blobs.items, seqs.items) |b, seq| {
        const cpd = try bcs.decode(types.CheckpointData, a, b[1..]);
        var any = false;
        for (cpd.transactions, 0..) |t, i| if (t.events) |evs| for (evs.data, 0..) |e, j| {
            any = true;
            if (ty == null) ty = e.type_;
            const x = try bcs.encodeAlloc(types.StructTag, a, &e.type_);
            const y = try bcs.encodeAlloc(types.StructTag, a, &ty.?);
            if (std.mem.eql(u8, x, y)) try want.append(a, .{ .cp = seq, .tx = @intCast(i), .ev = @intCast(j) });
        };
        if (any) try with_events.append(a, seq);
    }
    const t = ty orelse return error.SkipZigTest;
    const inst: ?[]const u8 = if (t.type_args.len > 0) try bcs.encodeAlloc([]const types.TypeTag, a, &t.type_args) else null;
    const key = try txfilter.encodeKey(a, .event_type, try txfilter.eventTypeValue(a, &t.address.@"0", t.module.@"0", t.name.@"0", inst));
    const lits = [_]txfilter.Literal{.{ .include = true, .key = key }};
    const q: txfilter.Query = .{ .terms = &.{.{ .includes = &.{key}, .excludes = &.{}, .literals = &lits }} };

    var svc: service.Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0) };
    defer svc.deinit();
    var hub = Hub.init(gpa, testing.io, &svc);
    defer hub.deinit();
    svc.hub = &hub;
    const filtered = hub.subscribe(.events).?;
    filtered.mask_tree = try mask.Tree.parse(filtered.arena.allocator(), "event_type");
    filtered.query = q;
    try hub.activate(filtered);
    const all = hub.subscribe(.events).?;
    all.mask_tree = try mask.Tree.parse(all.arena.allocator(), "event_type");
    try hub.activate(all);
    for (seqs.items) |seq| hub.publish(seq);

    // filtered: the start tick before entry, then exactly the matching events, in order
    try testing.expect(filtered.len >= 1);
    try testing.expectEqual(.tick, filtered.ring[filtered.head].tag);
    try testing.expectEqual(seqs.items[0] - 1, filtered.ring[filtered.head].cp);
    var got: std.ArrayList(Hit) = .empty;
    var i: usize = 1;
    while (i < filtered.len) : (i += 1) {
        const u = filtered.ring[(filtered.head + i) % queue_cap];
        try testing.expectEqual(.matched, u.tag);
        for (u.evs.?) |r| try got.append(a, .{ .cp = u.cp, .tx = r.tx, .ev = r.ev });
    }
    try testing.expectEqualSlices(Hit, want.items, got.items);
    // unfiltered: every checkpoint with an event (AllEvents), after the start tick
    try testing.expectEqual(with_events.items.len + 1, all.len);
    i = 1;
    while (i < all.len) : (i += 1) {
        const u = all.ring[(all.head + i) % queue_cap];
        try testing.expect(u.evs == null);
        try testing.expectEqual(with_events.items[i - 1], u.cp);
    }
    hub.release(filtered);
    hub.release(all);
}
