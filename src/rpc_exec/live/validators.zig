//! The live ExecuteTransaction path: the committee with network keys and addresses (from a
//! `GetEpoch` response), a pool of TLS gRPC connections to validators (one per validator, pinned
//! to its network key, reconnected after a 2 s cooldown like `NetworkAuthorityClient`), the
//! driver's `Transport`/`Waiter`/`Clock` over that pool, and the orchestrator's executor:
//! in-flight de-duplication by digest, an optional local-effects lookup, then the driver.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const serve = @import("serve");
const proto = serve.proto;
const driver_root = @import("../driver/root.zig");
const drv = driver_root.driver;
const cm = driver_root.committee;
const handler = driver_root.handler;
const grpc = @import("grpc_client.zig");
const errors = driver_root.errors;
const local = @import("local.zig");
const usersig = @import("usersig.zig");
const early = @import("early.zig");
const pending_log = @import("pending_log.zig");
/// sui-node's tx_orchestrator_*, transaction_driver_*, validator_client_* (lane ops-metrics).
const submit_metrics = @import("submit_metrics.zig");
const sm = &submit_metrics.global;
const prom = @import("core").prom;
const bcs = @import("bcs");
const types = @import("types");

const ns_per_ms = std.time.ns_per_ms;

pub fn monotonicNs(io: Io) u64 {
    return @intCast(Io.Clock.awake.now(io).nanoseconds);
}

// ------------------------------------------------------------------------------------------
// committee from GetEpoch

/// `/dns/<host>/tcp/<port>/http`, `/ip4/<a.b.c.d>/tcp/<port>/...`, `/ip6/<addr>/tcp/<port>/...`
/// (mysten-network `parse_dns`/`parse_ip4`/`parse_ip6`). TLS is always used for validators.
pub const HostPort = struct { host: []const u8, port: u16 };

pub fn parseMultiaddr(addr: []const u8) ?HostPort {
    var it = std.mem.splitScalar(u8, addr, '/');
    if ((it.next() orelse return null).len != 0) return null;
    const proto_name = it.next() orelse return null;
    if (!(std.mem.eql(u8, proto_name, "dns") or std.mem.eql(u8, proto_name, "ip4") or std.mem.eql(u8, proto_name, "ip6") or
        std.mem.eql(u8, proto_name, "dns4") or std.mem.eql(u8, proto_name, "dns6"))) return null;
    const host = it.next() orelse return null;
    if (!std.mem.eql(u8, it.next() orelse return null, "tcp")) return null;
    const port = std.fmt.parseInt(u16, it.next() orelse return null, 10) catch return null;
    if (host.len == 0) return null;
    return .{ .host = host, .port = port };
}

pub const EpochInfo = struct {
    epoch: u64,
    reference_gas_price: u64,
    committee: cm.Committee,
    /// `protocol_config.protocol_version` (0: not in the response).
    protocol_version: u64 = 0,
};

/// The `GetEpoch` read mask this module needs.
pub const epoch_mask = [_][]const u8{
    "epoch",
    "committee",
    "reference_gas_price",
    "protocol_config.protocol_version",
    "system_state.validators.active_validators.name",
    "system_state.validators.active_validators.protocol_public_key",
    "system_state.validators.active_validators.network_public_key",
    "system_state.validators.active_validators.network_address",
};

/// `GetEpochRequest { read_mask }` for the current epoch.
pub fn getEpochRequest(arena: Allocator) ![]const u8 {
    var buf = try arena.alloc(u8, 1024);
    var w = proto.Writer.init(buf[0..]);
    const m = try w.begin(2, 512);
    for (epoch_mask) |p| try w.string(1, p);
    try w.end(m);
    return w.bytesWritten();
}

/// `GetEpochResponse` -> committee members (voting power from `committee`, network data from the
/// active validators, matched by protocol key) like sui-node's `AuthorityAggregator`.
pub fn parseEpoch(arena: Allocator, body: []const u8) !EpochInfo {
    const R = proto.Reader;
    var epoch_msg: []const u8 = "";
    var r = R.init(body);
    while (try r.next()) |f| if (f.number == 1) {
        epoch_msg = try R.bytesOf(f);
    };
    var epoch: u64 = 0;
    var rgp: u64 = 0;
    var pv: u64 = 0;
    var committee_msg: []const u8 = "";
    var system_msg: []const u8 = "";
    r = R.init(epoch_msg);
    while (try r.next()) |f| switch (f.number) {
        1 => epoch = try R.varintOf(f),
        2 => committee_msg = try R.bytesOf(f),
        3 => system_msg = try R.bytesOf(f),
        8 => rgp = try R.varintOf(f),
        9 => {
            var pr = R.init(try R.bytesOf(f));
            while (try pr.next()) |g| if (g.number == 1) {
                pv = try R.varintOf(g);
            };
        },
        else => {},
    };
    const Net = struct { name: []const u8 = "", key: [96]u8 = undefined, net_key: [32]u8 = @splat(0), addr: []const u8 = "", has_key: bool = false };
    var nets: std.ArrayList(Net) = .empty;
    r = R.init(system_msg);
    while (try r.next()) |f| if (f.number == 4) {
        var vs = R.init(try R.bytesOf(f));
        while (try vs.next()) |g| if (g.number == 2) {
            var n: Net = .{};
            var vr = R.init(try R.bytesOf(g));
            while (try vr.next()) |h| switch (h.number) {
                1 => n.name = try R.stringOf(h),
                7 => {
                    const k = try R.bytesOf(h);
                    if (k.len == 96) {
                        @memcpy(&n.key, k);
                        n.has_key = true;
                    }
                },
                10 => {
                    const k = try R.bytesOf(h);
                    if (k.len == 32) @memcpy(&n.net_key, k);
                },
                13 => n.addr = try R.stringOf(h),
                else => {},
            };
            try nets.append(arena, n);
        };
    };
    var members: std.ArrayList(cm.Member) = .empty;
    r = R.init(committee_msg);
    while (try r.next()) |f| if (f.number == 2) {
        var m: cm.Member = .{ .name = undefined, .stake = 0 };
        var have = false;
        var mr = R.init(try R.bytesOf(f));
        while (try mr.next()) |g| switch (g.number) {
            1 => {
                const k = try R.bytesOf(g);
                if (k.len != 96) return error.InvalidCommittee;
                @memcpy(&m.name, k);
                have = true;
            },
            2 => m.stake = try R.varintOf(g),
            else => {},
        };
        if (!have) return error.InvalidCommittee;
        for (nets.items) |n| if (n.has_key and std.mem.eql(u8, &n.key, &m.name)) {
            m.network_address = n.addr;
            m.network_key = n.net_key;
            m.display_name = if (n.name.len > 0) n.name else null;
        };
        try members.append(arena, m);
    };
    return .{ .epoch = epoch, .reference_gas_price = rgp, .protocol_version = pv, .committee = try cm.Committee.init(arena, epoch, members.items) };
}

// ------------------------------------------------------------------------------------------
// connection pool

/// One connection per committee member, opened lazily (or by `warm`), replaced after it dies.
pub const Pool = struct {
    gpa: Allocator,
    io: Io,
    committee: *const cm.Committee,
    mu: Io.Mutex = .init,
    conns: []?*grpc.Conn,
    /// `RECONNECT_COOLDOWN`.
    reconnect_cooldown: u64 = 2 * std.time.ns_per_s,
    /// deepwave: a member whose connections keep failing before they are ready (down, firewalled:
    /// about 20 of 111 testnet validators from the Mac) waits twice as long after each failure,
    /// up to `max_reconnect_cooldown`, so drives do not keep spawning connects to it.
    max_reconnect_cooldown: u64 = 60 * std.time.ns_per_s,
    connect_fails: []u8 = &.{},
    /// `ValidatorClientMonitor` (validator_client_monitor/stats.rs), per member.
    stats: []Stats,

    /// `MAX_LATENCY`: the score of a member with no finality sample yet, and the unit of the
    /// reliability penalty.
    pub const max_latency_ns: u64 = 10 * std.time.ns_per_s;
    /// `reliability_weight` (default 2.0).
    pub const reliability_weight: u64 = 2;
    /// Smoothing: latencies move 1/4 toward each sample, reliability 1/16 (sui-node keeps moving
    /// windows of 40; a shorter memory moves a validator that turned slow out of the top within a
    /// few drives).
    const lat_shift = 2;
    const rel_window: u64 = 16;
    const rel_one: u64 = 1 << 20;

    pub const Stats = struct {
        /// Smoothed latencies in ns (0: no sample yet): submission, effects acknowledgment,
        /// finality through this member as the submission target (`SharedObjectFinality`).
        submit: std.atomic.Value(u64) = .init(0),
        effects: std.atomic.Value(u64) = .init(0),
        finality: std.atomic.Value(u64) = .init(0),
        /// Reliability in units of 1/rel_one (starts at 1.0).
        reliability: std.atomic.Value(u64) = .init(rel_one),
        failures: std.atomic.Value(u64) = .init(0),
    };

    pub fn init(gpa: Allocator, io: Io, committee: *const cm.Committee) !Pool {
        const conns = try gpa.alloc(?*grpc.Conn, committee.members.len);
        @memset(conns, null);
        errdefer gpa.free(conns);
        const stats = try gpa.alloc(Stats, committee.members.len);
        errdefer gpa.free(stats);
        for (stats) |*x| x.* = .{};
        const fails = try gpa.alloc(u8, committee.members.len);
        @memset(fails, 0);
        return .{ .gpa = gpa, .io = io, .committee = committee, .conns = conns, .stats = stats, .connect_fails = fails };
    }

    pub fn deinit(p: *Pool) void {
        for (p.conns) |c| if (c) |x| x.release();
        p.gpa.free(p.conns);
        p.gpa.free(p.stats);
        p.gpa.free(p.connect_fails);
    }

    /// `record_interaction_result`: a latency sample for `op`, or (null) a failure.
    pub fn record(p: *Pool, i: u32, op: drv.Op, latency_ns: ?u64) void {
        if (i >= p.stats.len) return;
        defer p.reportMetrics(i, op, latency_ns);
        const st = &p.stats[i];
        const rel = st.reliability.load(.monotonic);
        const ok: u64 = if (latency_ns != null) rel_one else 0;
        st.reliability.store(rel - rel / rel_window + ok / rel_window, .monotonic);
        const l = latency_ns orelse {
            _ = st.failures.fetchAdd(1, .monotonic);
            return;
        };
        const slot = switch (op) {
            .submit => &st.submit,
            .effects => &st.effects,
            .finality => &st.finality,
        };
        const old = slot.load(.monotonic);
        const next = if (old == 0) l else old - (old >> lat_shift) + (l >> lat_shift);
        slot.store(@max(next, 1), .monotonic);
    }

    /// `ValidatorClientMetrics` for member `i` (the drive's kind and ping flag from the thread).
    fn reportMetrics(p: *Pool, i: u32, op: drv.Op, latency_ns: ?u64) void {
        if (i >= p.committee.members.len) return;
        const name = p.committee.displayName(i);
        sm.interaction(name, op, submit_metrics.cur_tx, submit_metrics.cur_ping, latency_ns);
        const st = &p.stats[i];
        const f = st.finality.load(.monotonic);
        sm.performance(name, (if (f == 0) max_latency_ns else f) + penalty(st));
    }

    fn penalty(st: *const Stats) u64 {
        const rel = st.reliability.load(.monotonic);
        return (max_latency_ns / rel_one) * (rel_one - @min(rel, rel_one)) * reliability_weight;
    }

    /// `calculate_client_latency`: finality through the member plus the reliability penalty
    /// (no finality sample yet: `MAX_LATENCY` plus the penalty). The driver's `latencies`.
    pub fn latencies(p: *Pool, arena: Allocator) ![]const u64 {
        const out = try arena.alloc(u64, p.stats.len);
        for (out, p.stats) |*o, *st| {
            const f = st.finality.load(.monotonic);
            o.* = (if (f == 0) max_latency_ns else f) + penalty(st);
        }
        return out;
    }

    /// The `n` members whose effects acknowledgments arrive soonest (reliability included):
    /// the driver's `detail_acks`.
    pub fn fastestEffects(p: *Pool, arena: Allocator, n: usize) ![]const u32 {
        const Score = struct { i: u32, s: u64 };
        var all = try arena.alloc(Score, p.stats.len);
        var k: usize = 0;
        for (p.stats, 0..) |*st, i| {
            const e = st.effects.load(.monotonic);
            if (e == 0) continue;
            all[k] = .{ .i = @intCast(i), .s = e + penalty(st) };
            k += 1;
        }
        all = all[0..k];
        std.sort.pdq(Score, all, {}, struct {
            fn lt(_: void, a: Score, b: Score) bool {
                return a.s < b.s;
            }
        }.lt);
        const out = try arena.alloc(u32, @min(n, all.len));
        for (out, all[0..out.len]) |*o, x| o.* = x.i;
        return out;
    }

    /// Members with a finality sample (the latency check has reached them).
    pub fn measured(p: *Pool) usize {
        var n: usize = 0;
        for (p.stats) |*st| n += @intFromBool(st.finality.load(.monotonic) != 0);
        return n;
    }

    /// Opens every connection now (sui-node keeps them open).
    pub fn warm(p: *Pool) void {
        for (0..p.conns.len) |i| p.warmOne(@intCast(i));
    }

    /// The live connection to member `i`, retained for the caller (drop it with `unref`); null
    /// when its address does not parse. A dead connection is handed out (it fails calls at once)
    /// until the reconnect cooldown has passed; then the pool drops its own reference and opens a
    /// new one, while callers still holding the old one keep it alive until they unref it.
    pub fn get(p: *Pool, i: u32) ?*grpc.Conn {
        p.mu.lockUncancelable(p.io);
        defer p.mu.unlock(p.io);
        if (p.conns[i]) |c| {
            const cooldown = @min(p.reconnect_cooldown << @intCast(@min(p.connect_fails[i], 8)), @max(p.max_reconnect_cooldown, p.reconnect_cooldown));
            if (!c.isDead() or monotonicNs(p.io) -| c.died_at < cooldown) {
                c.retain();
                return c;
            }
            p.connect_fails[i] = if (c.was_ready) 0 else p.connect_fails[i] +| 1;
            c.release();
            p.conns[i] = null;
        }
        const m = p.committee.members[i];
        const hp = parseMultiaddr(m.network_address) orelse return null;
        const c = grpc.Conn.open(p.gpa, p.io, .{ .host = hp.host, .port = hp.port, .security = .{ .pinned = m.network_key } }) catch return null;
        p.conns[i] = c;
        c.retain();
        return c;
    }

    /// Opens every connection now (sui-node keeps them open).
    fn warmOne(p: *Pool, i: u32) void {
        if (p.get(i)) |c| c.unref();
    }
};

// ------------------------------------------------------------------------------------------
// one drive: Transport + Waiter + Clock over the pool

/// Diagnostics: a drive that took at least this long prints every validator call it made (0: off;
/// `ZUI_EXEC_TRACE_MS` in deepwave-execute).
pub var trace_slow_ms: u64 = 0;

pub const Session = struct {
    gpa: Allocator,
    io: Io,
    pool: *Pool,
    arena: Allocator,
    mu: Io.Mutex = .init,
    cond: Io.Condition = .init,
    inbox: std.ArrayList(Item) = .empty,
    calls: std.AutoHashMapUnmanaged(drv.CallId, *CallRec) = .empty,
    /// The driver's per-call timeout (`SUBMIT_TRANSACTION_TIMEOUT` / `WAIT_FOR_EFFECTS_TIMEOUT`):
    /// a call cancelled unanswered after this long counts as a failure for the latency monitor,
    /// like `ValidatorClientMonitor` records timeouts.
    call_timeout_ns: u64 = 10 * std.time.ns_per_s,
    /// Per-call trace of this drive (diagnostics, `trace_slow_ms`): arena lines, start time.
    log: std.ArrayList(u8) = .empty,
    t0: u64 = 0,

    const Item = struct { call: drv.CallId, ok: bool, code: u8, a: []u8, b: []u8, at: u64 };
    /// `conn` is retained (from `Pool.get`) for as long as the record exists.
    const CallRec = struct { conn: ?*grpc.Conn, slot: u32 = 0, validator: u32, started: u64, method: drv.Method = .submit_transaction };

    fn trace(s: *Session, comptime fmt: []const u8, args: anytype) void {
        if (trace_slow_ms == 0) return;
        const ms = (monotonicNs(s.io) -| s.t0) / std.time.ns_per_ms;
        s.log.print(s.arena, "  +{d} " ++ fmt ++ "\n", .{ms} ++ args) catch {};
    }

    pub fn init(gpa: Allocator, io: Io, pool: *Pool, arena: Allocator) Session {
        return .{ .gpa = gpa, .io = io, .pool = pool, .arena = arena };
    }

    fn dropRec(s: *Session, rec: *CallRec) void {
        if (rec.conn) |c| c.unref();
        s.gpa.destroy(rec);
    }

    /// Cancels every call still open (no delivery after this) and frees the inbox.
    pub fn deinit(s: *Session) void {
        var it = s.calls.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.*.conn) |c| c.cancel(&kv.value_ptr.*.slot, kv.key_ptr.*);
            s.dropRec(kv.value_ptr.*);
        }
        s.calls.deinit(s.gpa);
        for (s.inbox.items) |x| {
            s.gpa.free(x.a);
            s.gpa.free(x.b);
        }
        s.inbox.deinit(s.gpa);
    }

    pub fn transport(s: *Session) drv.Transport {
        return .{ .ctx = s, .vtable = &.{ .start = start, .cancel = cancel } };
    }

    pub fn waiter(s: *Session) drv.Waiter {
        return .{ .ctx = s, .waitFn = wait };
    }

    pub fn clock(s: *Session) drv.Clock {
        return .{ .ctx = s, .nowFn = now };
    }

    fn now(ctx: *anyopaque) u64 {
        const s: *Session = @ptrCast(@alignCast(ctx));
        return monotonicNs(s.io);
    }

    fn start(ctx: *anyopaque, call: drv.CallId, validator: u32, method: drv.Method, body: []const u8) void {
        const s: *Session = @ptrCast(@alignCast(ctx));
        const rec = s.gpa.create(CallRec) catch return s.push(call, false, 8, "out of memory", "");
        rec.* = .{ .conn = s.pool.get(validator), .validator = validator, .started = monotonicNs(s.io), .method = method };
        s.trace("start v{d} {s}", .{ validator, @tagName(method) });
        s.calls.put(s.gpa, call, rec) catch {
            s.dropRec(rec);
            return s.push(call, false, 8, "out of memory", "");
        };
        const c = rec.conn orelse return s.push(call, false, 14, "transport error: invalid validator network address", "");
        c.start(&rec.slot, method.path(), body, .{ .ctx = s, .done = done }, call, null);
    }

    fn cancel(ctx: *anyopaque, call: drv.CallId) void {
        const s: *Session = @ptrCast(@alignCast(ctx));
        const kv = s.calls.fetchRemove(call) orelse return;
        s.trace("cancel v{d} {s} after {d}ms", .{ kv.value.validator, @tagName(kv.value.method), (monotonicNs(s.io) -| kv.value.started) / std.time.ns_per_ms });
        if (kv.value.conn) |c| {
            c.cancel(&kv.value.slot, call);
            // unanswered at the driver's per-call deadline: a timeout for the monitor (a call
            // cancelled earlier, at quorum, says nothing about the validator)
            if (monotonicNs(s.io) -| kv.value.started >= s.call_timeout_ns) s.pool.record(kv.value.validator, .submit, null);
        }
        s.dropRec(kv.value);
    }

    fn done(ctx: *anyopaque, tag: u64, r: grpc.Result) void {
        const s: *Session = @ptrCast(@alignCast(ctx));
        switch (r) {
            .ok => |b| s.push(@intCast(tag), true, 0, b, ""),
            .status => |st| s.push(@intCast(tag), false, st.code, st.message, st.details),
        }
    }

    fn push(s: *Session, call: drv.CallId, ok: bool, code: u8, a: []const u8, b: []const u8) void {
        const ac = s.gpa.dupe(u8, a) catch return;
        const bc = s.gpa.dupe(u8, b) catch {
            s.gpa.free(ac);
            return;
        };
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        s.inbox.append(s.gpa, .{ .call = call, .ok = ok, .code = code, .a = ac, .b = bc, .at = monotonicNs(s.io) }) catch {
            s.gpa.free(ac);
            s.gpa.free(bc);
            return;
        };
        s.cond.signal(s.io);
    }

    fn wait(ctx: *anyopaque, d: *drv.Driver, deadline: ?u64) anyerror!void {
        const s: *Session = @ptrCast(@alignCast(ctx));
        var batch: std.ArrayList(Item) = .empty;
        defer batch.deinit(s.gpa);
        {
            s.mu.lockUncancelable(s.io);
            defer s.mu.unlock(s.io);
            while (s.inbox.items.len == 0) {
                const t = monotonicNs(s.io);
                if (deadline) |dl| {
                    if (t >= dl) return;
                    const left: i64 = @intCast(dl - t);
                    s.cond.waitTimeout(s.io, &s.mu, .{ .duration = .{ .raw = .fromNanoseconds(left), .clock = .awake } }) catch {};
                } else {
                    s.cond.waitUncancelable(s.io, &s.mu);
                }
            }
            try batch.appendSlice(s.gpa, s.inbox.items);
            s.inbox.clearRetainingCapacity();
        }
        for (batch.items) |x| {
            defer {
                s.gpa.free(x.a);
                s.gpa.free(x.b);
            }
            if (s.calls.fetchRemove(x.call)) |kv| {
                s.trace("done v{d} {s} {d}ms code {d} {s}", .{ kv.value.validator, @tagName(kv.value.method), (x.at -| kv.value.started) / std.time.ns_per_ms, x.code, if (x.ok) "" else x.a[0..@min(x.a.len, 100)] });
                const transport_ok = x.ok or (x.code != 14 and x.code != 4);
                if (kv.value.conn != null and !transport_ok) s.pool.record(kv.value.validator, .submit, null);
                s.dropRec(kv.value);
            }
            const a = try s.arena.dupe(u8, x.a);
            const res: drv.RpcResult = if (x.ok) .{ .ok = a } else .{ .status = .{ .code = x.code, .message = a, .details = try s.arena.dupe(u8, x.b) } };
            try d.onResponse(x.call, res);
        }
    }
};

// ------------------------------------------------------------------------------------------
// the executor (TransactionOrchestrator in front of the driver)


/// Packages for event `json`: the transaction's own objects first, then `lookup` (copied into
/// the request arena).
pub const RenderSource = struct {
    arena: Allocator,
    overlay: []const []const u8,
    ctx: *anyopaque,
    lookup: *const fn (ctx: *anyopaque, arena: Allocator, id: *const [32]u8) ?[]const u8,

    fn get(c: *const anyopaque, id: *const [32]u8) ?[]const u8 {
        const s: *const RenderSource = @ptrCast(@alignCast(c));
        // BCS Object: data enum tag 1 = Package, whose first field is its id
        for (s.overlay) |raw| if (raw.len > 33 and raw[0] == 1 and std.mem.eql(u8, raw[1..33], id)) return raw;
        return s.lookup(s.ctx, s.arena, id);
    }

    /// A render context (json only) over `lookup`.
    pub fn make(arena: Allocator, objects: []const []const u8, ctx: *anyopaque, lookup: *const fn (ctx: *anyopaque, arena: Allocator, id: *const [32]u8) ?[]const u8) ?*const serve.render_object.Ctx {
        const src = arena.create(RenderSource) catch return null;
        src.* = .{ .arena = arena, .overlay = objects, .ctx = ctx, .lookup = lookup };
        const res = arena.create(serve.movelayout.Resolver) catch return null;
        res.* = serve.movelayout.Resolver.init(arena, .{ .ctx = src, .get = get });
        const c = arena.create(serve.render_object.Ctx) catch return null;
        c.* = .{ .resolver = res };
        return c;
    }
};

pub const LocalEffects = local.LocalEffects;

/// One epoch's committee and its connections; replaced at reconfiguration, kept alive while a
/// drive uses it.
pub const EpochState = struct {
    arena: std.heap.ArenaAllocator,
    info: EpochInfo,
    pool: Pool,
    refs: std.atomic.Value(u32) = .init(1),

    fn unref(e: *EpochState, gpa: Allocator) void {
        if (e.refs.fetchSub(1, .acq_rel) != 1) return;
        e.pool.deinit();
        e.arena.deinit();
        gpa.destroy(e);
    }
};

/// `TransactionSubmissionError::is_retriable` (sui-types transaction_driver_types.rs).
pub fn isRetriable(e: *const errors.SubmissionError) bool {
    return switch (e.*) {
        .TransactionDriverInternalError, .InvalidUserSignature, .ObjectsDoubleUsed => false,
        .TimeoutBeforeFinality, .TimeoutBeforeFinalityWithErrors, .FailedWithTransientErrorAfterMaximumAttempts => true,
        .NonRecoverableTransactionError => false,
        .SystemOverload, .SystemOverloadRetryAfter => true,
        .TxAlreadyFinalizedWithDifferentUserSignatures => false,
        .TransactionFailed => |f| f.category.isSubmissionRetriable(),
    };
}

/// `early_validation_rejections{reason}`: the rejected error's SuiErrorKind variant
/// (`to_variant_name`). deepwave's early checks reject input errors (UserInputError) and disabled
/// features (UnsupportedFeatureError).
fn earlyReason(e: *const errors.SubmissionError) []const u8 {
    return switch (e.*) {
        .TransactionFailed => |f| if (std.mem.startsWith(u8, f.details, "Use of disabled feature")) "UnsupportedFeatureError" else "UserInputError",
        else => @tagName(e.*),
    };
}

/// The orchestrator's counters (sui-node `TransactionOrchestratorMetrics` names in comments).
pub const Counters = struct {
    /// early_cached_response
    local_answers: std.atomic.Value(u64) = .init(0),
    /// joined an in-flight drive of the same digest (the submission guard)
    joined: std.atomic.Value(u64) = .init(0),
    /// rejected before submission with InvalidUserSignature
    bad_signatures: std.atomic.Value(u64) = .init(0),
    /// Drives answered by the node's own execution while still pending.
    local_races: std.atomic.Value(u64) = .init(0),
    /// background_retry_started
    retry_started: std.atomic.Value(u64) = .init(0),
    /// background_retry_attempts{success, retriable, non-retriable}
    retry_success: std.atomic.Value(u64) = .init(0),
    retry_retriable: std.atomic.Value(u64) = .init(0),
    retry_non_retriable: std.atomic.Value(u64) = .init(0),
    drives: std.atomic.Value(u64) = .init(0),
    /// early_validation_rejections
    early_rejections: std.atomic.Value(u64) = .init(0),
    /// a retry not queued: one for the digest already pending, or the queue full
    retry_deduped: std.atomic.Value(u64) = .init(0),
    retry_dropped: std.atomic.Value(u64) = .init(0),
    /// transactions resubmitted from the pending-tx log at start (`start_task_to_recover_txes_in_log`)
    recovered: std.atomic.Value(u64) = .init(0),
};

/// Which path answered a request (`LiveExecutor.last_path`, per thread): the compare tool reports
/// equality per path, so a reply rendered from the reference's own data never counts as a drive.
pub const Path = enum { none, signature, early, local, joined, drive };
pub threadlocal var last_path: Path = .none;

/// The server deadline of the request this thread is answering (ns left when the handler
/// started; sui-node's `grpc-timeout-ms` 60 s, or a shorter client `grpc-timeout`). A drive
/// stops waiting there; the transaction keeps going in the background (sui-node's orchestrator
/// task outlives the timed-out request), and `deadline_hit` tells the handler to answer
/// DEADLINE_EXCEEDED "Timeout expired" like sui-http's GrpcTimeout.
pub threadlocal var server_budget_ns: ?u64 = null;
pub threadlocal var deadline_hit: bool = false;
/// `serve.h2.meta.monoNs` when the handler took the request (the budget origin).
pub threadlocal var handler_start_ns: u64 = 0;

/// Called after a drive failed (the node's committee refresh: a wrong-epoch or halted-at-epoch-end
/// answer means the committee may have changed).
pub const DriveErrorHook = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, err: *const errors.SubmissionError) void,
};

pub const LiveExecutor = struct {
    gpa: Allocator,
    io: Io,
    mu: Io.Mutex = .init,
    current: ?*EpochState = null,
    local: ?LocalEffects = null,
    /// User signature verification before submission (null: validators verify everything).
    sig_env: ?usersig.Env = null,
    /// How often (ms) a pending drive asks `local` whether the node executed the transaction
    /// itself (sui-node's `notify_read_executed_effects` arm). 0: never (an upstream-backed
    /// `local` costs a remote call per ask).
    local_race_ms: u64 = 0,
    /// Early validation of owned input versions (null: validators decide).
    live_objects: ?early.LiveObjects = null,
    /// The background retry after a retriable error (`execute_transaction_with_retry`).
    background_retry: bool = true,
    /// First retry delay and cap (sui-node: ExponentialBackoff 1 s .. 300 s, 10 attempts).
    retry_first_ms: u64 = 1000,
    retry_max_ms: u64 = 300_000,
    retry_attempts: u32 = 10,
    options: drv.Options = .{ .reference_gas_price = 0 },
    /// Digest -> the drive in progress (`TransactionSubmissionGuard`).
    inflight: std.AutoHashMapUnmanaged([32]u8, *Flight) = .empty,
    seed: std.atomic.Value(u64) = .init(0x5eed),
    counters: Counters = .{},
    on_drive_error: ?DriveErrorHook = null,
    /// Background retries: a fixed set of worker threads over one deadline-ordered queue (not a
    /// thread per retry), at most one pending retry per digest, at most `retry_capacity` queued.
    retry_workers: u32 = 4,
    retry_capacity: u32 = 4096,
    retry: RetryQueue = .{},
    /// sui-node's `fullnode_pending_transactions` (pending_log.zig): a transaction is written
    /// before its submission and removed when the submission and its background retries are
    /// over; `recoverPending` resubmits what a killed process left. null: no log.
    pending: ?*pending_log.PendingLog = null,
    /// Test seam: replaces the drive through the validators.
    drive_hook: ?DriveHook = null,
    /// Event `json` in responses (the node's packages); null leaves it out.
    render: ?handler.RenderHook = null,
    /// deepwave: submit to this many of the best-ranked validators at once (sui-node: 1 at the
    /// reference gas price; see `drv.Options.min_amplification`).
    min_amplification: u64 = 3,
    /// deepwave: this many of the fastest validators answer their acknowledgment with the full
    /// effects (`drv.Options.detail_acks`).
    detail_acks: u32 = 4,
    /// sui-node `run_latency_checks`: a consensus ping through every committee member every
    /// `check_interval_ms`, so the ranking knows each member's finality latency before real
    /// transactions need it. Started by `setEpoch` when true.
    latency_checks: bool = false,
    check_interval_ms: u64 = 15_000,
    check_timeout_ms: u64 = 5_000,
    check_threads: u32 = 8,
    checks_stop: std.atomic.Value(bool) = .init(false),
    checks_thread: ?std.Thread = null,

    pub const DriveHook = struct {
        ctx: *anyopaque,
        f: *const fn (ctx: *anyopaque, arena: Allocator, req: *const handler.ExecuteRequest) Allocator.Error!drv.Outcome,
    };

    const Flight = struct {
        waiters: u32 = 0,
        done: bool = false,
        cond: Io.Condition = .init,
        /// gpa copy of the leader's successful outcome, unfiltered (each joiner applies its own
        /// read mask); null when the leader failed.
        ok: ?drv.QuorumResponse = null,
    };

    pub fn init(gpa: Allocator, io: Io) LiveExecutor {
        var s: [8]u8 = undefined;
        io.random(&s);
        var e: LiveExecutor = .{ .gpa = gpa, .io = io };
        e.seed.store(std.mem.readInt(u64, &s, .little), .monotonic);
        return e;
    }

    /// Stops the background retry workers (dropping what is still queued) and frees the in-flight
    /// table. Epoch states are left alone (a node's executor lives as long as the process).
    pub fn deinit(self: *LiveExecutor) void {
        self.checks_stop.store(true, .release);
        if (self.checks_thread) |t| t.join();
        self.checks_thread = null;
        const q = &self.retry;
        q.mu.lockUncancelable(self.io);
        q.stopping = true;
        q.cond.broadcast(self.io);
        while (q.alive > 0) q.cond.waitUncancelable(self.io, &q.mu);
        for (q.jobs.items) |j| self.freeJob(j);
        q.jobs.deinit(self.gpa);
        q.pending.deinit(self.gpa);
        q.mu.unlock(self.io);
        self.inflight.deinit(self.gpa);
    }

    pub fn executor(self: *LiveExecutor) handler.Executor {
        return .{ .ctx = self, .executeFn = run, .render = self.render };
    }

    /// The current epoch, or null before the first committee.
    pub fn epoch(self: *LiveExecutor) ?u64 {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return if (self.current) |c| c.info.epoch else null;
    }

    /// Installs a committee from a `GetEpoch` response (same epoch: no change). Connections open now.
    pub fn setEpoch(self: *LiveExecutor, get_epoch_response: []const u8) !u64 {
        const st = try self.gpa.create(EpochState);
        errdefer self.gpa.destroy(st);
        st.* = .{ .arena = .init(self.gpa), .info = undefined, .pool = undefined };
        errdefer st.arena.deinit();
        st.info = try parseEpoch(st.arena.allocator(), try st.arena.allocator().dupe(u8, get_epoch_response));
        self.mu.lockUncancelable(self.io);
        if (self.current) |cur| if (cur.info.epoch == st.info.epoch) {
            self.mu.unlock(self.io);
            st.arena.deinit();
            self.gpa.destroy(st);
            return cur.info.epoch;
        };
        st.pool = try Pool.init(self.gpa, self.io, &st.info.committee);
        // deepwave: carry the monitor over an epoch change (by authority name), so the first drives of
        // the new epoch are ranked before the next latency-check round
        if (self.current) |cur| for (st.info.committee.members, st.pool.stats) |m, *dst| {
            for (cur.info.committee.members, cur.pool.stats) |om, *src| if (std.mem.eql(u8, &om.name, &m.name)) {
                dst.submit.store(src.submit.load(.monotonic), .monotonic);
                dst.effects.store(src.effects.load(.monotonic), .monotonic);
                dst.finality.store(src.finality.load(.monotonic), .monotonic);
                dst.reliability.store(src.reliability.load(.monotonic), .monotonic);
                break;
            };
        };
        const old = self.current;
        self.current = st;
        self.mu.unlock(self.io);
        st.pool.warm();
        if (old) |o| o.unref(self.gpa);
        if (self.latency_checks and self.checks_thread == null)
            self.checks_thread = std.Thread.spawn(.{ .stack_size = 1 << 20 }, latencyLoop, .{self}) catch null;
        return st.info.epoch;
    }

    /// `TransactionDriver::preferred_proposers` (sui-core transaction_driver/mod.rs): null before
    /// any latency was observed (the ranking would be an arbitrary shuffle); else the first `max`
    /// of `select_shuffled_preferred_validators(committee, SELECT_LATENCY_DELTA)` (shuffle, sort
    /// by latency, shuffle those within 2% of the lowest) as committee indices, sorted, with the
    /// committee's epoch. Simulate's gas selection restricts transactions to this set.
    pub fn preferredProposers(self: *LiveExecutor, arena: Allocator, max: usize) Allocator.Error!?types.AllowedProposers {
        const st = self.acquire() orelse return null;
        defer st.unref(self.gpa);
        if (st.pool.measured() == 0) return null;
        const lat = try st.pool.latencies(arena);
        if (lat.len == 0 or max == 0) return null;
        const order = try arena.alloc(u32, lat.len);
        for (order, 0..) |*o, i| o.* = @intCast(i);
        var prng = std.Random.DefaultPrng.init(self.seed.fetchAdd(0x9e3779b97f4a7c15, .monotonic));
        const r = prng.random();
        r.shuffle(u32, order);
        // `sort_by_key` is stable: equal latencies keep their shuffled order
        std.sort.insertion(u32, order, lat, struct {
            fn lt(l: []const u64, a: u32, b: u32) bool {
                return l[a] < l[b];
            }
        }.lt);
        const lowest = lat[order[0]];
        // `Duration::mul_f64(1.0 + delta)`
        const threshold: u64 = @intFromFloat(@as(f64, @floatFromInt(lowest)) * 1.02);
        var k: usize = order.len;
        for (order, 0..) |v, i| if (lat[v] > threshold) {
            k = i;
            break;
        };
        r.shuffle(u32, order[0..k]);
        const out = try arena.dupe(u32, order[0..@min(max, order.len)]);
        std.mem.sort(u32, out, {}, std.sort.asc(u32));
        return .{ .epoch = st.info.epoch, .proposers = out };
    }

    /// The current committee's epoch, reference gas price, protocol version and size.
    pub const EpochFacts = struct { epoch: u64, rgp: u64, protocol_version: u64, size: u32 };

    pub fn epochFacts(self: *LiveExecutor) ?EpochFacts {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        const c = self.current orelse return null;
        return .{ .epoch = c.info.epoch, .rgp = c.info.reference_gas_price, .protocol_version = c.info.protocol_version, .size = @intCast(c.info.committee.members.len) };
    }

    fn acquire(self: *LiveExecutor) ?*EpochState {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        const st = self.current orelse return null;
        _ = st.refs.fetchAdd(1, .acq_rel);
        return st;
    }

    /// `execute_transaction_with_retry`: one attempt now; after a retriable error the same
    /// request keeps going in the background while the caller gets the first error.
    fn run(ctx: *anyopaque, arena: Allocator, req: *const handler.ExecuteRequest) Allocator.Error!drv.Outcome {
        const self: *LiveExecutor = @ptrCast(@alignCast(ctx));
        const t_req = prom.monoNs();
        // verify_transaction_with_current_aliases -> InvalidUserSignature (no submission)
        last_path = .none;
        var ee_buf: usersig.EpochEnv = undefined;
        const ee: ?*const usersig.EpochEnv = blk: {
            const lo = self.live_objects orelse break :blk null;
            const src = lo.env orelse break :blk null;
            ee_buf = src.get(src.ctx) orelse break :blk null;
            break :blk &ee_buf;
        };
        var jw: usersig.LatestJwks = undefined;
        const jwp: ?*usersig.LatestJwks = blk: {
            const lo = self.live_objects orelse break :blk null;
            jw = .{ .ctx = lo.ctx, .latest = lo.latest orelse break :blk null };
            break :blk &jw;
        };
        if (self.sig_env) |*env| if (try usersig.check(arena, env, req, ee, jwp)) |e| {
            _ = self.counters.bad_signatures.fetchAdd(1, .monotonic);
            last_path = .signature;
            return .{ .err = e };
        };
        const o = self.attempt(arena, req, false) catch |e| {
            self.finishPending(&req.digest);
            return e;
        };
        if (o == .err and self.background_retry and isRetriable(&o.err)) self.spawnRetry(req);
        self.finishPending(&req.digest);
        if (o == .ok) sm.requestOk(submit_metrics.TxType.of(req.data), prom.monoNs() -| t_req);
        return o;
    }

    /// The submission is over (`TransactionSubmissionGuard` drop): out of the pending-tx log,
    /// unless a background retry of the digest is queued or running (deepwave keeps it there until
    /// the retries end, so a restart in between resubmits it; sui-node's retries are in memory).
    fn finishPending(self: *LiveExecutor, digest: *const [32]u8) void {
        const l = self.pending orelse return;
        const q = &self.retry;
        q.mu.lockUncancelable(self.io);
        defer q.mu.unlock(self.io);
        if (!q.pending.contains(digest.*)) l.finish(digest);
    }

    /// `start_task_to_recover_txes_in_log`: on a thread, once a committee is installed, each
    /// transaction the pending-tx log holds is submitted again (no signature check: it passed
    /// one before it was logged). A retriable failure goes to the background retry like a fresh
    /// request's; anything else ends it and it leaves the log.
    pub fn recoverPending(self: *LiveExecutor) !void {
        const l = self.pending orelse return;
        if (l.count() == 0) return;
        (try std.Thread.spawn(.{ .stack_size = 8 << 20 }, recoverMain, .{self})).detach();
    }

    fn recoverMain(self: *LiveExecutor) void {
        const l = self.pending.?;
        while (self.drive_hook == null and self.epoch() == null) {
            if (self.checks_stop.load(.acquire)) return;
            Io.sleep(self.io, .fromMilliseconds(200), .awake) catch {};
        }
        var a = std.heap.ArenaAllocator.init(self.gpa);
        defer a.deinit();
        const all = l.snapshot(a.allocator()) catch |e| {
            std.log.err("execute: pending-tx log: {s}", .{@errorName(e)});
            return;
        };
        std.log.info("execute: recovering {d} pending transactions from the pending-tx log", .{all.len});
        var ok: usize = 0;
        for (all) |*p| {
            var ta = std.heap.ArenaAllocator.init(self.gpa);
            defer ta.deinit();
            const req = requestOf(ta.allocator(), p.digest, p.entry) catch {
                std.log.warn("execute: pending-tx log: undecodable transaction {x}; dropped", .{p.digest[0..]});
                l.finish(&p.digest);
                continue;
            };
            const o = self.attempt(ta.allocator(), &req, false) catch {
                self.finishPending(&p.digest);
                continue;
            };
            _ = self.counters.recovered.fetchAdd(1, .monotonic);
            if (o == .ok) ok += 1;
            if (o == .err and self.background_retry and isRetriable(&o.err)) self.spawnRetry(&req);
            self.finishPending(&p.digest);
        }
        std.log.info("execute: recovery finished: {d} of {d} pending transactions executed, the rest retried or ended", .{ ok, all.len });
    }

    /// `execute_transaction_with_effects_waiting` after the signature check.
    fn attempt(self: *LiveExecutor, arena: Allocator, req: *const handler.ExecuteRequest, enforce_live: bool) Allocator.Error!drv.Outcome {
        // early validation (its rejection skipped for a transaction already executed here), then
        // the local effects of an executed transaction
        switch (try early.head(arena, self.live_objects, self.local, req, enforce_live)) {
            .local => |q| {
                _ = self.counters.local_answers.fetchAdd(1, .monotonic);
                _ = sm.early_cached.fetchAdd(1, .monotonic);
                last_path = .local;
                return .{ .ok = q };
            },
            .reject => |e| {
                _ = self.counters.early_rejections.fetchAdd(1, .monotonic);
                sm.earlyRejected(earlyReason(&e));
                last_path = .early;
                return .{ .err = e };
            },
            .submit => {},
        }
        // `TransactionSubmissionGuard::new`: into the pending-tx log before anything is submitted
        // (a digest already there, in flight or waiting for a retry, is not written again). A
        // transaction answered above (local effects or an early rejection) is never written.
        if (self.pending) |l| _ = l.writeMaybe(&req.digest, .{ .envelope = req.envelope, .data_bcs = req.data_bcs, .signatures = req.signatures });

        // join a drive of the same transaction already in flight
        self.mu.lockUncancelable(self.io);
        if (self.inflight.get(req.digest)) |f| {
            _ = self.counters.joined.fetchAdd(1, .monotonic);
            f.waiters += 1;
            while (!f.done) f.cond.waitUncancelable(self.io, &self.mu);
            f.waiters -= 1;
            const got = if (f.ok) |q| copyQuorum(arena, q) catch null else null;
            if (f.waiters == 0) self.freeFlight(f);
            self.mu.unlock(self.io);
            // the joiner's own read mask (sui-node builds each waiter's response from local
            // effects with that waiter's flags)
            if (got) |q| {
                last_path = .joined;
                return handler.filtered(.{ .ok = q }, req);
            }
            // the leader failed: executed here meanwhile, or drive it ourselves (validators
            // de-duplicate)
            if (self.local) |l| if (l.get(l.ctx, arena, req)) |q| {
                last_path = .local;
                return handler.filtered(.{ .ok = q }, req);
            };
            return handler.filtered(try self.drive(arena, req), req);
        }
        const f = self.gpa.create(Flight) catch {
            self.mu.unlock(self.io);
            return handler.filtered(try self.drive(arena, req), req);
        };
        f.* = .{};
        self.inflight.put(self.gpa, req.digest, f) catch {
            self.gpa.destroy(f);
            self.mu.unlock(self.io);
            return handler.filtered(try self.drive(arena, req), req);
        };
        self.mu.unlock(self.io);

        // unfiltered: joiners may ask for more than the leader did
        const outcome = self.drive(arena, req) catch |e| {
            self.finishFlight(f, req, null);
            return e;
        };
        // local effects were built for this request's read mask: joiners read their own
        self.finishFlight(f, req, if (outcome == .ok and last_path != .local) outcome.ok else null);
        return handler.filtered(outcome, req);
    }

    /// The leader is done: wake the joiners with a copy of the full quorum response.
    fn finishFlight(self: *LiveExecutor, f: *Flight, req: *const handler.ExecuteRequest, ok: ?drv.QuorumResponse) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        _ = self.inflight.remove(req.digest);
        f.done = true;
        if (f.waiters > 0) {
            if (ok) |q| f.ok = copyQuorum(self.gpa, q) catch null;
            f.cond.broadcast(self.io);
        } else self.gpa.destroy(f);
    }

    fn freeFlight(self: *LiveExecutor, f: *Flight) void {
        if (f.ok) |q| freeQuorum(self.gpa, q);
        self.gpa.destroy(f);
    }

    /// One drive through the validators. The outcome is NOT filtered by the read mask.
    fn drive(self: *LiveExecutor, arena: Allocator, req: *const handler.ExecuteRequest) Allocator.Error!drv.Outcome {
        last_path = .drive;
        // `execute_transaction_impl`: in flight, waiting for finality, settled
        const tx = submit_metrics.TxType.of(req.data);
        const t0 = prom.monoNs();
        sm.driveBegin(tx);
        const o = self.driveInner(arena, req) catch |e| {
            sm.driveEnd(tx, false, 0);
            return e;
        };
        sm.driveEnd(tx, o == .ok, prom.monoNs() -| t0);
        if (o == .err and (o.err == .TimeoutBeforeFinality or o.err == .TimeoutBeforeFinalityWithErrors)) _ = sm.wait_timeout.fetchAdd(1, .monotonic);
        if (o == .err) if (self.on_drive_error) |h| h.f(h.ctx, &o.err);
        return o;
    }

    fn driveInner(self: *LiveExecutor, arena: Allocator, req: *const handler.ExecuteRequest) Allocator.Error!drv.Outcome {
        if (self.drive_hook) |h| {
            _ = self.counters.drives.fetchAdd(1, .monotonic);
            return h.f(h.ctx, arena, req);
        }
        const st = self.acquire() orelse return .{ .err = .{ .TransactionDriverInternalError = .{ .Unknown = .{ .@"0" = "no committee yet" } } } };
        defer st.unref(self.gpa);
        _ = self.counters.drives.fetchAdd(1, .monotonic);
        const tx = submit_metrics.TxType.of(req.data);
        submit_metrics.cur_tx = tx;
        submit_metrics.cur_ping = false;
        sm.submitted_(tx, false);
        var sess = Session.init(self.gpa, self.io, &st.pool, arena);
        sess.call_timeout_ns = @min(self.options.timing.submit_timeout, self.options.timing.wait_for_effects_timeout);
        defer sess.deinit();
        sess.t0 = monotonicNs(self.io);
        var opts = self.options;
        opts.reference_gas_price = st.info.reference_gas_price;
        opts.seed = self.seed.fetchAdd(0x9E37_79B9_7F4A_7C15, .monotonic);
        opts.latencies = try st.pool.latencies(arena);
        // the server deadline before the 90 s finality timeout (WAIT_FOR_FINALITY_TIMEOUT)
        var deadline_bound = false;
        if (server_budget_ns) |b| {
            const used = serve.h2.meta.monoNs() -| handler_start_ns;
            const left = b -| used;
            if (opts.finality_timeout == null or left < opts.finality_timeout.?) {
                opts.finality_timeout = left;
                opts.drive_timeout = left;
                deadline_bound = true;
            }
        }
        opts.min_amplification = self.min_amplification;
        opts.detail_acks = try st.pool.fastestEffects(arena, self.detail_acks);
        opts.feedback = .{ .ctx = &st.pool, .f = poolFeedback, .attempt_error = attemptError };
        var d = try drv.Driver.init(arena, &st.info.committee, sess.transport(), sess.clock(), req.driverRequest(), opts);
        // notify_read_executed_effects: the node's own execution of the transaction (checkpoint
        // executor) answers a drive still pending
        const Race = struct {
            l: local.LocalEffects,
            arena: Allocator,
            req: *const handler.ExecuteRequest,
            fn get(ctx: *anyopaque) ?drv.QuorumResponse {
                const r: *@This() = @ptrCast(@alignCast(ctx));
                return r.l.get(r.l.ctx, r.arena, r.req);
            }
        };
        var race: Race = undefined;
        const run_res: anyerror!drv.RaceResult = blk: {
            if (self.local_race_ms > 0) if (self.local) |l| {
                race = .{ .l = l, .arena = arena, .req = req };
                break :blk drv.runRacing(&d, sess.waiter(), .{ .ctx = &race, .get = Race.get, .every_ns = self.local_race_ms * std.time.ns_per_ms });
            };
            break :blk if (drv.runBlocking(&d, sess.waiter())) |x| .{ .outcome = x, .local = false } else |e| e;
        };
        const res: drv.RaceResult = run_res catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => drv.RaceResult{ .outcome = .{ .err = .{ .TransactionDriverInternalError = .{ .Unknown = .{ .@"0" = @errorName(e) } } } }, .local = false },
        };
        const o = res.outcome;
        if (res.local) {
            _ = self.counters.local_races.fetchAdd(1, .monotonic);
            _ = sm.concurrent.fetchAdd(1, .monotonic);
            last_path = .local;
        } else sm.driveDone(tx, false, o == .ok, o == .err and !isRetriable(&o.err), d.attempts, monotonicNs(self.io) -| sess.t0);
        if (deadline_bound and o == .err and (o.err == .TimeoutBeforeFinality or o.err == .TimeoutBeforeFinalityWithErrors)) {
            deadline_hit = true;
            if (self.background_retry) self.spawnRetry(req);
        }
        if (trace_slow_ms > 0) {
            const ms = (monotonicNs(self.io) -| sess.t0) / std.time.ns_per_ms;
            if (ms >= trace_slow_ms) {
                var b58: [serve.b58.max_len_32]u8 = undefined;
                std.debug.print("slow drive {s} {d}ms attempts {d} {s}\n{s}", .{ serve.b58.encode32(&b58, &req.digest), ms, d.attempts, @tagName(o), sess.log.items });
            }
        }
        return o;
    }

    // ---------------------------------------------------------------- latency checks

    /// `run_latency_checks`: every interval, one ping per committee member (the member is the
    /// only submission target), `check_threads` at a time.
    fn latencyLoop(self: *LiveExecutor) void {
        while (!self.checks_stop.load(.acquire)) {
            const t0 = monotonicNs(self.io);
            if (self.acquire()) |st| {
                defer st.unref(self.gpa);
                _ = sm.latency_check_runs.fetchAdd(1, .monotonic);
                var next: std.atomic.Value(u32) = .init(0);
                var threads: [64]?std.Thread = @splat(null);
                for (threads[0..@min(self.check_threads, threads.len)]) |*t|
                    t.* = std.Thread.spawn(.{ .stack_size = 1 << 20 }, checkWorker, .{ self, st, &next }) catch null;
                for (threads) |t| if (t) |x| x.join();
            }
            const until = t0 + self.check_interval_ms * std.time.ns_per_ms;
            while (!self.checks_stop.load(.acquire) and monotonicNs(self.io) < until)
                Io.sleep(self.io, .fromMilliseconds(100), .awake) catch {};
        }
    }

    fn checkWorker(self: *LiveExecutor, st: *EpochState, next: *std.atomic.Value(u32)) void {
        const n: u32 = @intCast(st.info.committee.members.len);
        while (!self.checks_stop.load(.acquire)) {
            const i = next.fetchAdd(1, .monotonic);
            if (i >= n) return;
            self.ping(st, i) catch {};
        }
    }

    /// One consensus ping through member `i` (`SubmitTxRequest::new_ping`, `PING_REQUEST_TIMEOUT`).
    /// A ping that does not finalize counts as a finality failure for `i`.
    pub fn ping(self: *LiveExecutor, st: *EpochState, i: u32) !void {
        var a = std.heap.ArenaAllocator.init(self.gpa);
        defer a.deinit();
        const arena = a.allocator();
        var sess = Session.init(self.gpa, self.io, &st.pool, arena);
        sess.call_timeout_ns = self.check_timeout_ms * std.time.ns_per_ms;
        defer sess.deinit();
        var opts = self.options;
        opts.reference_gas_price = st.info.reference_gas_price;
        opts.seed = self.seed.fetchAdd(0x9E37_79B9_7F4A_7C15, .monotonic);
        opts.latencies = try st.pool.latencies(arena);
        opts.only_validator = i;
        opts.finality_timeout = self.check_timeout_ms * std.time.ns_per_ms;
        opts.drive_timeout = self.check_timeout_ms * std.time.ns_per_ms;
        opts.feedback = .{ .ctx = &st.pool, .f = poolFeedback, .attempt_error = attemptError };
        submit_metrics.cur_tx = .shared_object;
        submit_metrics.cur_ping = true;
        defer submit_metrics.cur_ping = false;
        sm.submitted_(.shared_object, true);
        const t0 = monotonicNs(self.io);
        var d = try drv.Driver.init(arena, &st.info.committee, sess.transport(), sess.clock(), .{ .transaction = null }, opts);
        const o = drv.runBlocking(&d, sess.waiter()) catch return;
        sm.driveDone(.shared_object, true, o == .ok, o == .err and !isRetriable(&o.err), d.attempts, monotonicNs(self.io) -| t0);
        if (o == .err) st.pool.record(i, .finality, null);
    }

    fn poolFeedback(ctx: *anyopaque, validator: u32, op: drv.Op, latency_ns: ?u64, _: bool) void {
        const pool: *Pool = @ptrCast(@alignCast(ctx));
        pool.record(validator, op, latency_ns);
    }

    fn attemptError(_: *anyopaque, cat: errors.ErrorCategory, is_ping: bool) void {
        sm.attemptError(cat, if (is_ping) .shared_object else submit_metrics.cur_tx, is_ping);
    }

    // ---------------------------------------------------------------- background retry

    const RetryJob = struct {
        arena: std.heap.ArenaAllocator,
        req: handler.ExecuteRequest,
        /// Monotonic ns of the next attempt.
        next_at: u64,
        /// Attempts made so far, and the sleep after the next failure.
        attempts: u32 = 0,
        delay_ms: u64,
    };

    /// The pending retries (deadline order by a scan: at most `retry_capacity` entries) and the
    /// digests they belong to.
    pub const RetryQueue = struct {
        mu: Io.Mutex = .init,
        cond: Io.Condition = .init,
        jobs: std.ArrayList(*RetryJob) = .empty,
        /// Digests queued or being attempted.
        pending: std.AutoHashMapUnmanaged([32]u8, void) = .empty,
        started: u32 = 0,
        running: u32 = 0,
        /// Worker threads not yet exited, and the stop request (`deinit`).
        alive: u32 = 0,
        stopping: bool = false,
    };

    /// Queues a background retry of `req` (the caller's arena dies with the RPC, so it is
    /// copied). Not queued when one for the same digest is pending or the queue is full.
    fn spawnRetry(self: *LiveExecutor, req: *const handler.ExecuteRequest) void {
        const q = &self.retry;
        q.mu.lockUncancelable(self.io);
        defer q.mu.unlock(self.io);
        if (q.pending.contains(req.digest)) {
            _ = self.counters.retry_deduped.fetchAdd(1, .monotonic);
            return;
        }
        if (q.pending.count() >= self.retry_capacity) {
            _ = self.counters.retry_dropped.fetchAdd(1, .monotonic);
            return;
        }
        const job = self.gpa.create(RetryJob) catch return;
        job.* = .{ .arena = .init(self.gpa), .req = undefined, .next_at = monotonicNs(self.io), .delay_ms = self.retry_first_ms };
        job.req = copyRequest(job.arena.allocator(), req) catch return self.freeJob(job);
        q.pending.put(self.gpa, req.digest, {}) catch return self.freeJob(job);
        q.jobs.append(self.gpa, job) catch {
            _ = q.pending.remove(req.digest);
            return self.freeJob(job);
        };
        _ = self.counters.retry_started.fetchAdd(1, .monotonic);
        _ = sm.retry_started.fetchAdd(1, .monotonic);
        // workers start on first use and live as long as the executor's process
        while (q.started < self.retry_workers and q.started < q.jobs.items.len + q.running) {
            const t = std.Thread.spawn(.{ .stack_size = 8 << 20 }, retryWorker, .{self}) catch break;
            t.detach();
            q.started += 1;
            q.alive += 1;
        }
        q.cond.signal(self.io);
    }

    fn freeJob(self: *LiveExecutor, job: *RetryJob) void {
        job.arena.deinit();
        self.gpa.destroy(job);
    }

    /// Pending background retries (queued plus running).
    pub fn retriesPending(self: *LiveExecutor) usize {
        self.retry.mu.lockUncancelable(self.io);
        defer self.retry.mu.unlock(self.io);
        return self.retry.pending.count();
    }

    /// The earliest due job, removed from the queue; null after waiting (caller loops).
    fn takeDue(self: *LiveExecutor) ?*RetryJob {
        const q = &self.retry;
        if (q.stopping) return null;
        if (q.jobs.items.len == 0) {
            q.cond.waitUncancelable(self.io, &q.mu);
            return null;
        }
        var best: usize = 0;
        for (q.jobs.items, 0..) |j, i| if (j.next_at < q.jobs.items[best].next_at) {
            best = i;
        };
        const now = monotonicNs(self.io);
        const at = q.jobs.items[best].next_at;
        if (at > now) {
            q.cond.waitTimeout(self.io, &q.mu, .{ .duration = .{ .raw = .fromNanoseconds(@intCast(at - now)), .clock = .awake } }) catch {};
            return null;
        }
        return q.jobs.swapRemove(best);
    }

    fn retryWorker(self: *LiveExecutor) void {
        const q = &self.retry;
        q.mu.lockUncancelable(self.io);
        while (true) {
            if (q.stopping) {
                q.alive -= 1;
                q.cond.broadcast(self.io);
                q.mu.unlock(self.io);
                return;
            }
            const job = self.takeDue() orelse continue;
            q.running += 1;
            q.mu.unlock(self.io);
            const again = self.retryOnce(job);
            q.mu.lockUncancelable(self.io);
            q.running -= 1;
            if (again and !q.stopping) {
                job.next_at = monotonicNs(self.io) + job.delay_ms * ns_per_ms;
                var rb: [8]u8 = undefined;
                self.io.random(&rb);
                job.delay_ms = pending_log.nextDelayMs(job.delay_ms, self.retry_max_ms, self.retry_first_ms, std.mem.readInt(u64, &rb, .little));
                q.jobs.append(self.gpa, job) catch {
                    _ = q.pending.remove(job.req.digest);
                    if (self.pending) |l| l.finish(&job.req.digest);
                    self.freeJob(job);
                };
            } else if (q.stopping and again) {
                // shutting down with attempts left: the job stays in the pending-tx log
                _ = q.pending.remove(job.req.digest);
                self.freeJob(job);
            } else {
                _ = q.pending.remove(job.req.digest);
                if (self.pending) |l| l.finish(&job.req.digest);
                self.freeJob(job);
            }
        }
    }

    /// One background attempt; true when another one is due (`execute_transaction_with_retry`:
    /// `ExponentialBackoff::new(1 s, 300 s)` between attempts (x1.2 plus up to 1 s of jitter),
    /// 10 attempts, live input versions enforced from the fifth).
    fn retryOnce(self: *LiveExecutor, job: *RetryJob) bool {
        var a = std.heap.ArenaAllocator.init(self.gpa);
        defer a.deinit();
        const o = self.attempt(a.allocator(), &job.req, job.attempts > 3) catch return false;
        job.attempts += 1;
        switch (o) {
            .ok => {
                _ = self.counters.retry_success.fetchAdd(1, .monotonic);
                sm.retryAttempt(.success);
                return false;
            },
            .err => |*e| if (!isRetriable(e)) {
                _ = self.counters.retry_non_retriable.fetchAdd(1, .monotonic);
                sm.retryAttempt(.non_retriable);
                return false;
            } else {
                _ = self.counters.retry_retriable.fetchAdd(1, .monotonic);
                sm.retryAttempt(.retriable);
                return job.attempts < self.retry_attempts;
            },
        }
    }
};

/// A request rebuilt from a pending-tx log entry (no read mask: nobody waits for the answer).
pub fn requestOf(a: Allocator, digest: [32]u8, e: pending_log.Entry) !handler.ExecuteRequest {
    const data = try a.create(types.TransactionData);
    data.* = try bcs.decode(types.TransactionData, a, e.data_bcs);
    return .{
        .envelope = e.envelope,
        .data_bcs = e.data_bcs,
        .data = data,
        .digest = digest,
        .signatures = e.signatures,
        .include_events = false,
        .include_input_objects = false,
        .include_output_objects = false,
    };
}

fn copyRequest(a: Allocator, r: *const handler.ExecuteRequest) !handler.ExecuteRequest {
    const data_bcs = try a.dupe(u8, r.data_bcs);
    const data = try a.create(types.TransactionData);
    data.* = try bcs.decode(types.TransactionData, a, data_bcs);
    const sigs = try a.alloc([]const u8, r.signatures.len);
    for (r.signatures, sigs) |s, *o| o.* = try a.dupe(u8, s);
    return .{
        .envelope = try a.dupe(u8, r.envelope),
        .data_bcs = data_bcs,
        .data = data,
        .digest = r.digest,
        .signatures = sigs,
        .include_events = r.include_events,
        .include_input_objects = r.include_input_objects,
        .include_output_objects = r.include_output_objects,
    };
}

fn copyQuorum(a: Allocator, q: drv.QuorumResponse) Allocator.Error!drv.QuorumResponse {
    var out = q;
    out.effects = try a.dupe(u8, q.effects);
    out.events = if (q.events) |e| try a.dupe(u8, e) else null;
    out.input_objects = if (q.input_objects) |xs| try dupeAll(a, xs) else null;
    out.output_objects = if (q.output_objects) |xs| try dupeAll(a, xs) else null;
    return out;
}

fn dupeAll(a: Allocator, xs: []const []const u8) Allocator.Error![]const []const u8 {
    const out = try a.alloc([]const u8, xs.len);
    for (xs, out) |x, *o| o.* = try a.dupe(u8, x);
    return out;
}

fn freeQuorum(a: Allocator, q: drv.QuorumResponse) void {
    a.free(q.effects);
    if (q.events) |e| a.free(e);
    for ([_]?[]const []const u8{ q.input_objects, q.output_objects }) |maybe| if (maybe) |xs| {
        for (xs) |x| a.free(x);
        a.free(xs);
    };
}

const testing = std.testing;

test "multiaddr" {
    const a = parseMultiaddr("/dns/testnet.sui.blockscope.net/tcp/8080/http").?;
    try testing.expectEqualStrings("testnet.sui.blockscope.net", a.host);
    try testing.expectEqual(@as(u16, 8080), a.port);
    const b = parseMultiaddr("/ip4/1.2.3.4/tcp/8080/https").?;
    try testing.expectEqualStrings("1.2.3.4", b.host);
    try testing.expect(parseMultiaddr("/dns/x/udp/8084") == null);
    try testing.expect(parseMultiaddr("dns/x/tcp/1") == null);
}

// ------------------------------------------------------------------------------------------
// review fixes

/// The first local vector's request, parsed (a real signed testnet transaction).
fn vectorRequest(a: Allocator) !handler.ExecuteRequest {
    const vectors = @embedFile("testdata/local_vectors.bin");
    if (vectors.len < 4) return error.SkipZigTest;
    const lr = std.mem.readInt(u32, vectors[0..4], .little);
    const Cap = struct {
        a: Allocator,
        got: ?handler.ExecuteRequest = null,
        fn run(ctx: *anyopaque, _: Allocator, req: *const handler.ExecuteRequest) Allocator.Error!drv.Outcome {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            c.got = copyRequest(c.a, req) catch return error.OutOfMemory;
            return .{ .err = .TimeoutBeforeFinality };
        }
    };
    var cap: Cap = .{ .a = a };
    _ = try handler.executeTransaction(a, .{ .ctx = &cap, .executeFn = Cap.run }, vectors[4..][0..lr]);
    return cap.got orelse error.TestUnexpectedResult;
}

const Gate = struct {
    ex: *LiveExecutor,
    digest: [32]u8,
    fn drive(ctx: *anyopaque, arena: Allocator, _: *const handler.ExecuteRequest) Allocator.Error!drv.Outcome {
        const g: *Gate = @ptrCast(@alignCast(ctx));
        // hold the drive until the joiner waits on it
        var spins: u32 = 0;
        while (spins < 5000) : (spins += 1) {
            g.ex.mu.lockUncancelable(g.ex.io);
            const w = if (g.ex.inflight.get(g.digest)) |f| f.waiters else 0;
            g.ex.mu.unlock(g.ex.io);
            if (w > 0) break;
            Io.sleep(g.ex.io, .fromMilliseconds(1), .awake) catch {};
        }
        const ins = try arena.alloc([]const u8, 1);
        ins[0] = "input";
        return .{ .ok = .{ .effects_digest = @splat(1), .effects = "effects", .events = "events", .input_objects = ins, .output_objects = ins, .source = 0 } };
    }
};

test "a joined duplicate gets its own read mask, not the leader's" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ex = LiveExecutor.init(gpa, testing.io);
    defer ex.deinit();
    ex.background_retry = false;
    var lean = try vectorRequest(a);
    lean.include_events = false;
    lean.include_input_objects = false;
    lean.include_output_objects = false;
    var full = lean;
    full.include_events = true;
    full.include_input_objects = true;
    full.include_output_objects = true;
    var gate: Gate = .{ .ex = &ex, .digest = lean.digest };
    ex.drive_hook = .{ .ctx = &gate, .f = Gate.drive };

    const Leader = struct {
        fn run(e: *LiveExecutor, r: *const handler.ExecuteRequest, out: *?drv.Outcome) void {
            var la = std.heap.ArenaAllocator.init(testing.allocator);
            defer la.deinit();
            const o = e.attempt(la.allocator(), r, false) catch return;
            out.* = o;
            if (o == .ok) out.*.?.ok = .{ .effects_digest = o.ok.effects_digest, .effects = "", .events = o.ok.events, .input_objects = o.ok.input_objects, .output_objects = o.ok.output_objects, .source = 0 };
        }
    };
    var leader_out: ?drv.Outcome = null;
    const t = try std.Thread.spawn(.{}, Leader.run, .{ &ex, &lean, &leader_out });
    // join once the leader's flight exists
    var spins: u32 = 0;
    while (spins < 5000) : (spins += 1) {
        ex.mu.lockUncancelable(ex.io);
        const there = ex.inflight.contains(lean.digest);
        ex.mu.unlock(ex.io);
        if (there) break;
        try Io.sleep(testing.io, .fromMilliseconds(1), .awake);
    }
    const joined = try ex.attempt(a, &full, false);
    t.join();
    try testing.expectEqual(Path.joined, last_path);
    try testing.expect(joined == .ok);
    try testing.expectEqualStrings("events", joined.ok.events.?);
    try testing.expect(joined.ok.input_objects != null and joined.ok.output_objects != null);
    // the leader still gets its own (lean) mask
    try testing.expect(leader_out.? == .ok);
    try testing.expect(leader_out.?.ok.events == null and leader_out.?.ok.input_objects == null);
    try testing.expectEqual(@as(u64, 1), ex.counters.drives.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), ex.counters.joined.load(.monotonic));
}

const Overloaded = struct {
    calls: std.atomic.Value(u32) = .init(0),
    fn drive(ctx: *anyopaque, _: Allocator, _: *const handler.ExecuteRequest) Allocator.Error!drv.Outcome {
        const o: *Overloaded = @ptrCast(@alignCast(ctx));
        _ = o.calls.fetchAdd(1, .monotonic);
        return .{ .err = .TimeoutBeforeFinality };
    }
};

test "background retries: one per digest, bounded queue, fixed workers, stopped by deinit" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ex = LiveExecutor.init(gpa, testing.io);
    var ov: Overloaded = .{};
    ex.drive_hook = .{ .ctx = &ov, .f = Overloaded.drive };
    ex.retry_first_ms = 60_000; // after its first background attempt the job waits a minute
    ex.retry_capacity = 2;
    ex.retry_workers = 2;
    const req = try vectorRequest(a);
    const exe = ex.executor();
    // the same digest five times: one retry
    for (0..5) |_| try testing.expect((try exe.execute(a, &req)) == .err);
    try testing.expectEqual(@as(u64, 1), ex.counters.retry_started.load(.monotonic));
    try testing.expectEqual(@as(u64, 4), ex.counters.retry_deduped.load(.monotonic));
    // two more digests: one fits, one is dropped (capacity 2)
    var r2 = req;
    r2.digest[0] ^= 1;
    var r3 = req;
    r3.digest[0] ^= 2;
    _ = try exe.execute(a, &r2);
    _ = try exe.execute(a, &r3);
    try testing.expectEqual(@as(u64, 2), ex.counters.retry_started.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), ex.counters.retry_dropped.load(.monotonic));
    try testing.expectEqual(@as(usize, 2), ex.retriesPending());
    try testing.expect(ex.retry.started <= 2);
    // the immediate background attempts ran
    var spins: u32 = 0;
    while (ov.calls.load(.monotonic) < 7 + 2 and spins < 5000) : (spins += 1) try Io.sleep(testing.io, .fromMilliseconds(1), .awake);
    try testing.expectEqual(@as(u32, 9), ov.calls.load(.monotonic));
    ex.deinit(); // stops the workers; the queued jobs are freed (testing.allocator checks)
}

const Scripted = struct {
    calls: std.atomic.Value(u32) = .init(0),
    /// what the drive answers: retriable (TimeoutBeforeFinality) or not (ObjectsDoubleUsed)
    retriable: bool = true,
    /// the pending-tx log must hold the digest while the drive runs
    log: ?*pending_log.PendingLog = null,
    saw_logged: std.atomic.Value(u32) = .init(0),
    fn drive(ctx: *anyopaque, _: Allocator, req: *const handler.ExecuteRequest) Allocator.Error!drv.Outcome {
        const o: *Scripted = @ptrCast(@alignCast(ctx));
        _ = o.calls.fetchAdd(1, .monotonic);
        if (o.log) |l| if (l.contains(&req.digest)) {
            _ = o.saw_logged.fetchAdd(1, .monotonic);
        };
        return if (o.retriable) .{ .err = .TimeoutBeforeFinality } else .{ .err = .{ .ObjectsDoubleUsed = &.{} } };
    }
};

fn walPath(buf: []u8, tmp: *testing.TmpDir) ![]const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}/pending", .{tmp.sub_path});
}

test "pending-tx log: held during the drive, removed after a non-retriable end" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [256]u8 = undefined;
    const log = try pending_log.PendingLog.open(gpa, testing.io, try walPath(&pb, &tmp));
    defer log.close();
    var ex = LiveExecutor.init(gpa, testing.io);
    defer ex.deinit();
    var sc: Scripted = .{ .retriable = false, .log = log };
    ex.drive_hook = .{ .ctx = &sc, .f = Scripted.drive };
    ex.pending = log;
    const req = try vectorRequest(a);
    try testing.expect((try ex.executor().execute(a, &req)) == .err);
    try testing.expectEqual(@as(u32, 1), sc.saw_logged.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), log.count());
}

test "pending-tx log: kept while a retry waits, recovered after a restart, ended by the retries" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [256]u8 = undefined;
    const path = try walPath(&pb, &tmp);
    const req = try vectorRequest(a);
    {
        const log = try pending_log.PendingLog.open(gpa, testing.io, path);
        defer log.close();
        var ex = LiveExecutor.init(gpa, testing.io);
        var sc: Scripted = .{ .retriable = true, .log = log };
        ex.drive_hook = .{ .ctx = &sc, .f = Scripted.drive };
        ex.pending = log;
        ex.retry_first_ms = 60_000; // the second background attempt is a minute away
        try testing.expect((try ex.executor().execute(a, &req)) == .err);
        var spins: u32 = 0;
        while (sc.calls.load(.monotonic) < 2 and spins < 5000) : (spins += 1) try Io.sleep(testing.io, .fromMilliseconds(1), .awake);
        try testing.expectEqual(@as(u32, 2), sc.calls.load(.monotonic)); // the RPC's and the first retry
        try testing.expectEqual(@as(usize, 1), log.count()); // a retry is due: still pending
        ex.deinit(); // the node stops with the retry queued
        try testing.expectEqual(@as(usize, 1), log.count());
    }
    // restart: the log replays the transaction; recovery resubmits it once a committee is there
    const log = try pending_log.PendingLog.open(gpa, testing.io, path);
    defer log.close();
    try testing.expectEqual(@as(usize, 1), log.count());
    var ex = LiveExecutor.init(gpa, testing.io);
    defer ex.deinit();
    var sc: Scripted = .{ .retriable = true };
    ex.drive_hook = .{ .ctx = &sc, .f = Scripted.drive };
    ex.pending = log;
    ex.retry_first_ms = 1; // fast retries for the test
    ex.retry_max_ms = 2;
    try ex.recoverPending();
    var spins: u32 = 0;
    while (log.count() != 0 and spins < 10_000) : (spins += 1) try Io.sleep(testing.io, .fromMilliseconds(1), .awake);
    try testing.expectEqual(@as(usize, 0), log.count());
    try testing.expectEqual(@as(u64, 1), ex.counters.recovered.load(.monotonic));
    // the recovery attempt, then 10 background attempts, then it gives up and leaves the log
    try testing.expectEqual(@as(u32, 1 + 10), sc.calls.load(.monotonic));
    try testing.expectEqual(@as(u64, 10), ex.counters.retry_retriable.load(.monotonic));
}

// kill -9 of a process in the middle of writing: a forked child writes and finishes entries,
// then SIGKILLs itself without closing anything; the parent reopens and must see exactly the
// pending ones (Linux only; skipped elsewhere).
test "pending-tx log: kill -9 mid-run keeps every write the process made" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [256]u8 = undefined;
    const path = try walPath(&pb, &tmp);
    const rounds: u32 = 500;
    const pid_rc = linux.fork();
    if (linux.errno(pid_rc) != .SUCCESS) return error.SkipZigTest;
    if (pid_rc == 0) {
        // child: page allocator only (no locks another thread of the runner might hold)
        const l = pending_log.PendingLog.open(std.heap.page_allocator, testing.io, path) catch linux.exit_group(2);
        l.compact_min = 16 << 10; // compactions happen during the run too
        var body: [300]u8 = @splat('t');
        var i: u32 = 0;
        while (i < rounds) : (i += 1) {
            var d: [32]u8 = @splat(0);
            std.mem.writeInt(u32, d[0..4], i, .little);
            _ = l.writeMaybe(&d, .{ .envelope = &body, .data_bcs = body[1..], .signatures = &.{body[0..65]} });
            if (i % 3 != 0) l.finish(&d);
        }
        // the last one is half written: its header without the body (a crash mid-record)
        var hdr: [8]u8 = undefined;
        std.mem.writeInt(u32, hdr[0..4], 400, .little);
        std.mem.writeInt(u32, hdr[4..8], 0xdeadbeef, .little);
        l.file.writePositionalAll(testing.io, &hdr, l.end) catch {};
        _ = linux.kill(linux.getpid(), linux.SIG.KILL);
        linux.exit_group(3);
    }
    const pid: i32 = @intCast(pid_rc);
    var status: i32 = 0;
    _ = linux.waitpid(pid, &status, 0);
    // killed by SIGKILL (not exited)
    try testing.expectEqual(@as(u32, @intFromEnum(linux.SIG.KILL)), @as(u32, @bitCast(status)) & 0x7f);
    const l = try pending_log.PendingLog.open(testing.allocator, testing.io, path);
    defer l.close();
    try testing.expectEqual(@as(usize, (rounds + 2) / 3), l.count());
    try testing.expect(l.torn_bytes == 8);
    var i: u32 = 0;
    while (i < rounds) : (i += 1) {
        var d: [32]u8 = @splat(0);
        std.mem.writeInt(u32, d[0..4], i, .little);
        try testing.expectEqual(i % 3 == 0, l.contains(&d));
    }
}

test "a failed drive tells the committee refresher; the path is recorded" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ex = LiveExecutor.init(gpa, testing.io);
    defer ex.deinit();
    ex.background_retry = false;
    const Hook = struct {
        n: u32 = 0,
        fn f(ctx: *anyopaque, _: *const errors.SubmissionError) void {
            const h: *@This() = @ptrCast(@alignCast(ctx));
            h.n += 1;
        }
    };
    var h: Hook = .{};
    ex.on_drive_error = .{ .ctx = &h, .f = Hook.f };
    const req = try vectorRequest(a);
    const o = try ex.executor().execute(a, &req); // no committee yet
    try testing.expect(o == .err);
    try testing.expectEqual(@as(u32, 1), h.n);
    try testing.expectEqual(Path.drive, last_path);
}

/// Waits until a connection's reader thread is gone (its Io work uses the test allocator).
fn waitReaderDone(c: *grpc.Conn) !void {
    var spins: u32 = 0;
    while (spins < 10_000) : (spins += 1) {
        c.mu.lockUncancelable(c.io);
        const d = c.reader_done;
        c.mu.unlock(c.io);
        if (d) return;
        try Io.sleep(testing.io, .fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

/// A one-member committee whose address nobody listens on.
fn deadCommittee(a: Allocator, port: u16) !cm.Committee {
    const members = try a.alloc(cm.Member, 1);
    members[0] = .{ .name = @splat(7), .stake = 10_000 };
    members[0].network_address = try std.fmt.allocPrint(a, "/ip4/127.0.0.1/tcp/{d}/http", .{port});
    members[0].network_key = @splat(0);
    return cm.Committee.init(a, 1, members);
}

test "pool connections are retained by callers across a reconnect" {
    const gpa = std.heap.smp_allocator; // reader threads outlive the test's allocator checks
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const committee = try deadCommittee(arena_state.allocator(), 1);
    var pool = try Pool.init(gpa, testing.io, &committee);
    defer pool.deinit();
    pool.reconnect_cooldown = 0;
    const c1 = pool.get(0).?;
    var spins: u32 = 0;
    while (!c1.isDead() and spins < 5000) : (spins += 1) try Io.sleep(testing.io, .fromMilliseconds(1), .awake);
    try testing.expect(c1.isDead());
    // the pool replaces it and drops its own reference; ours keeps it alive
    const c2 = pool.get(0).?;
    try testing.expect(c2 != c1);
    try testing.expect(c1.refs.load(.acquire) >= 1);
    // a call on the dead connection still answers UNAVAILABLE (no use after free)
    const r = try grpc.callBlocking(arena_state.allocator(), c1, "/x/Y", "", 1000);
    try testing.expectEqual(@as(u8, 14), r.status.code);
    try waitReaderDone(c1);
    try waitReaderDone(c2);
    c1.unref();
    c2.unref();
}

test "a call cancelled unanswered at its deadline counts as a validator failure" {
    const gpa = std.heap.smp_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const committee = try deadCommittee(a, 1);
    var pool = try Pool.init(gpa, testing.io, &committee);
    defer pool.deinit();
    var sess = Session.init(gpa, testing.io, &pool, a);
    defer sess.deinit();
    sess.call_timeout_ns = 0;
    const t = sess.transport();
    t.vtable.start(t.ctx, 0, 0, .submit_transaction, "");
    t.vtable.cancel(t.ctx, 0);
    try testing.expectEqual(@as(u64, 1), pool.stats[0].failures.load(.monotonic));
    try waitReaderDone(pool.conns[0].?);
    // cancelled before its deadline (quorum reached elsewhere): no sample
    var pool2 = try Pool.init(gpa, testing.io, &committee);
    defer pool2.deinit();
    var s2 = Session.init(gpa, testing.io, &pool2, a);
    defer s2.deinit();
    const t2 = s2.transport();
    t2.vtable.start(t2.ctx, 0, 0, .submit_transaction, "");
    t2.vtable.cancel(t2.ctx, 0);
    try testing.expectEqual(@as(u64, 0), pool2.stats[0].failures.load(.monotonic));
    try waitReaderDone(pool2.conns[0].?);
}

test "zui: the monitor ranks by finality and moves unreliable members back" {
    const gpa = std.heap.smp_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const members = try a.alloc(cm.Member, 3);
    for (members, 0..) |*m, k| m.* = .{ .name = @splat(@intCast(k + 1)), .stake = if (k == 0) 3334 else 3333 };
    const committee = try cm.Committee.init(a, 1, members);
    var pool = try Pool.init(gpa, testing.io, &committee);
    defer pool.deinit();
    pool.record(0, .finality, 400 * ns_per_ms);
    pool.record(1, .finality, 300 * ns_per_ms);
    var lat = try pool.latencies(a);
    try testing.expect(lat[1] < lat[0] and lat[0] < lat[2]); // member 2: no sample, MAX_LATENCY
    try testing.expectEqual(Pool.max_latency_ns, lat[2]);
    // failures add the reliability penalty: member 1 falls behind member 0
    for (0..4) |_| pool.record(1, .submit, null);
    lat = try pool.latencies(a);
    try testing.expect(lat[0] < lat[1]);
    pool.record(2, .effects, 100 * ns_per_ms);
    pool.record(0, .effects, 200 * ns_per_ms);
    const fast = try pool.fastestEffects(a, 1);
    try testing.expectEqualSlices(u32, &.{2}, fast);
}
