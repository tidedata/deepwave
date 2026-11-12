//! The gate a serving path asks before it routes a call (docs/GATE.md).
//!
//!   admit(call)   who is calling (key or address), may the call run, what does it cost
//!   settle(...)   after routing: count it local or forwarded, book the forward multiplier
//!   stream*(...)  a server stream: its slot, its messages, its per-minute units
//!
//! `admit` for a key the node has resolved takes no lock and allocates nothing: a keyed hash of
//! the key, a lookup in a fixed table, one compare-and-swap on the key's bucket, one on its
//! lease. Everything that talks to the gate service happens on the gate's own threads: resolver
//! threads take keys from a bounded queue, a sender posts usage batches and refreshes the free
//! tier, a tick journals the usage counters once a second. A call for a key that is being
//! resolved gets `.wait` (the caller may wait up to `wait_ms`, `admitWait`), or free-tier
//! treatment at once when the queue is full, the gate is unreachable or too many calls wait.
//!
//! Every step a thread loops over is also a function a test calls with its own clock
//! (`resolveStep`, `sendStep`, `refreshFree`, `tick`).
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Atomic = std.atomic.Value;
const Allocator = std.mem.Allocator;
const contract = @import("contract.zig");
const ident = @import("ident.zig");
const methods_mod = @import("methods.zig");
const state = @import("state.zig");
const meter_mod = @import("meter.zig");
const spool_mod = @import("spool.zig");
const Methods = methods_mod.Methods;
const Counters = contract.Counters;
const KeyStatus = state.KeyStatus;
const ns_per_s = std.time.ns_per_s;
const ns_per_ms = std.time.ns_per_ms;

pub const Clock = struct {
    ctx: ?*anyopaque = null,
    /// Monotonic ns (never 0).
    mono: *const fn (ctx: ?*anyopaque) u64 = realMono,
    /// Wall clock ms since the epoch.
    wall: *const fn (ctx: ?*anyopaque) u64 = realWall,

    fn clockNs(comptime id: anytype) u64 {
        var ts: std.posix.timespec = undefined;
        if (builtin.os.tag == .linux) {
            _ = std.os.linux.clock_gettime(id, &ts);
        } else {
            _ = std.c.clock_gettime(id, &ts);
        }
        return @as(u64, @intCast(ts.sec)) * ns_per_s + @as(u64, @intCast(ts.nsec));
    }
    fn realMono(_: ?*anyopaque) u64 {
        return clockNs(.MONOTONIC) + ns_per_s;
    }
    fn realWall(_: ?*anyopaque) u64 {
        return clockNs(.REALTIME) / ns_per_ms;
    }
};

pub const HttpRequest = struct {
    post: bool,
    url: []const u8,
    /// Sent as `Authorization: Bearer <token>`. Never logged.
    token: []const u8,
    body: []const u8 = "",
    timeout_ms: u32,
};

/// The HTTPS client the node lends the gate (the node's own client; the gate has none).
pub const Reply = struct {
    status: u16,
    /// The answer's `Retry-After` header, when it had one (`contract.retryAfterMs`).
    retry_after_ms: ?u32 = null,
};

pub const Transport = struct {
    ctx: *anyopaque,
    /// One request. The answer body is appended to `out`; the HTTP status is returned. Must
    /// come back within `timeout_ms`, or at once after `cancel`.
    call: *const fn (ctx: *anyopaque, req: *const HttpRequest, out: *std.ArrayList(u8), gpa: Allocator) anyerror!Reply,
    /// The gate is stopping: requests in flight end now.
    cancel: ?*const fn (ctx: *anyopaque) void = null,
};

pub const Config = struct {
    /// The gate's base URL; `resolve`, `free` and `usage` are appended.
    base_url: []const u8,
    token: []const u8,
    edge_id: []const u8,
    /// Where the free tier and the usage spool are kept (null: memory only).
    dir: ?Io.Dir = null,
    proxies: []const ident.Cidr = &.{},
    methods: *const Methods,
    transport: Transport,
    clock: Clock = .{},
    /// A fixed boot id (tests); otherwise 16 random hex digits per start.
    boot_id: ?[]const u8 = null,
    key_capacity: u32 = 16384,
    address_capacity: u32 = 65536,
    spool_cap: u64 = spool_mod.default_cap,
    /// How long a call for a key that is being resolved may wait.
    wait_ms: u32 = 150,
    /// Calls waiting at once; one more gets free-tier treatment without waiting.
    max_waiters: u32 = 64,
    /// Resolves of keys the node has never seen, per second (and at once).
    resolve_rps: u32 = 50,
    resolve_burst: u32 = 100,
    /// Resolver threads: the bound on resolves in flight.
    resolvers: u32 = 4,
    resolve_timeout_ms: u32 = 2000,
    usage_timeout_ms: u32 = 10_000,
    /// How long a known key keeps its answer past `ttl_s` when the gate cannot be asked.
    grace_ns: u64 = 3600 * ns_per_s,
    cut_ns: u64 = 5 * ns_per_s,
    /// After a failed resolve of an unknown key: free-tier treatment this long, then ask again.
    unresolved_ns: u64 = 5 * ns_per_s,
    /// After a failed refresh of a known key, and between two resolves of one key.
    retry_ns: u64 = 5 * ns_per_s,
    min_refresh_ns: u64 = ns_per_s,
    /// An address bucket idle this long is freed.
    address_idle_s: u32 = 120,
    /// Where the gate's log lines go (null: std.log). Tests read them back.
    log: ?LogSink = null,
    /// Tests: `stop` and `deinit` behave like a crash (no final journal entry).
    crash_on_stop: bool = false,
};

pub const LogSink = struct {
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, err: bool, line: []const u8) void,
};

/// The built-in floor when no free tier was ever fetched.
pub const floor: contract.Free = .{ .rps_per_ip = 2, .burst = 4, .max_streams = 1, .ttl_s = 300 };
const deny_default_ns: u64 = 300 * ns_per_s;
const deny_max_ms: u64 = 48 * 3600 * 1000;
const free_retry_ns: u64 = 10 * ns_per_s;
const pend_size = 256;

pub const Reason = enum(u8) {
    limited,
    invalid,
    suspended,
    exhausted,
    /// The key's lease is spent and the gate gave no new one.
    lease,
    streams,
    unknown_status,
    /// A stream's key could not be checked again for longer than the grace period.
    unverified,

    pub const count = @typeInfo(Reason).@"enum".field_names.len;
};

/// The gRPC meaning of a refusal: UNAUTHENTICATED for a key nobody knows, PERMISSION_DENIED
/// for a key that is known and may not call, RESOURCE_EXHAUSTED for a limit or spent credits.
pub const Code = enum { resource_exhausted, permission_denied, unauthenticated };

pub const Deny = struct {
    reason: Reason,
    /// For `limited`: when the same call would pass.
    retry_after_ms: u32 = 0,
    /// What to tell the caller: the gate's own text when it sent one, else a plain default.
    message: []const u8,

    pub fn code(d: *const Deny) Code {
        return switch (d.reason) {
            .limited, .exhausted, .lease, .streams, .unverified => .resource_exhausted,
            .invalid => .unauthenticated,
            .suspended, .unknown_status => .permission_denied,
        };
    }
};

pub fn defaultText(r: Reason) []const u8 {
    return switch (r) {
        .limited => "rate limit exceeded",
        .invalid => "invalid API key",
        .suspended => "key revoked",
        .exhausted, .lease => "out of credits",
        .streams => "too many concurrent streams",
        .unknown_status => "key not accepted",
        .unverified => "key could not be verified, reconnect",
    };
}

pub const Route = enum { local, forwarded };

pub const Call = struct {
    /// The caller's API key ("": none).
    key: []const u8 = "",
    /// The socket peer.
    peer: ident.Ip,
    /// The request's forwarded-for header ("": none); read only behind a trusted proxy.
    forwarded_for: []const u8 = "",
    method: u8,
    /// Items a batch read asks for (null: not known).
    items: ?u32 = null,
    /// False: never answer `.wait`.
    may_wait: bool = true,
};

pub const Ticket = struct {
    kind: enum(u8) { free, key, ip } = .free,
    method: u8 = 0,
    plan: u8 = state.Plans.free,
    /// Holds a stream slot until `streamClose`.
    stream: bool = false,
    leased: bool = false,
    /// Units charged at admission.
    cost: u32 = 0,
    forward_milli: u32 = 1000,
    idx: u32 = 0,
    tenant: u32 = 0,
    /// Low half of the key's hash (keys), for the usage row.
    h: u64 = 0,
    prefix: u64 = 0,
    slot: ?*state.IpSlot = null,
    interval_ns: u64 = 0,
    per_minute: u32 = 0,
    opened_ns: u64 = 0,
    minutes: u32 = 0,
    checked_ns: u64 = 0,
    lease_strikes: u8 = 0,
};

pub const Decision = union(enum) {
    allow: Ticket,
    /// The key is being resolved (or its lease renewed): ask again shortly.
    wait,
    deny: Deny,
};

pub const Metrics = struct {
    allowed: [state.Plans.size][methods_mod.max_methods]Atomic(u64) = @splat(@splat(.init(0))),
    limited: [state.Plans.size][methods_mod.max_methods]Atomic(u64) = @splat(@splat(.init(0))),
    /// Refusals by `Reason` (`zui_gate_refused{reason}`), rate-limit refusals included.
    denied: [Reason.count]Atomic(u64) = @splat(.init(0)),
    resolves: Atomic(u64) = .init(0),
    resolve_errors: Atomic(u64) = .init(0),
    /// Unknown keys given free-tier treatment because the resolve budget or queue was used up.
    resolve_capped: Atomic(u64) = .init(0),
    resolve_ns: Atomic(u64) = .init(0),
    resolve_buckets: [latency_bounds_ms.len + 1]Atomic(u64) = @splat(.init(0)),
    cache_full: Atomic(u64) = .init(0),
    batches_sent: Atomic(u64) = .init(0),
    batches_failed: Atomic(u64) = .init(0),
    /// Batches the gate refused for good (HTTP 400 or 413), set aside as dead letters.
    batches_dead: Atomic(u64) = .init(0),
    rows_sent: Atomic(u64) = .init(0),
    /// Rows of delivered batches the gate did not take (`rejected` in its answer).
    rows_rejected: Atomic(u64) = .init(0),
    free_fetches: Atomic(u64) = .init(0),
    free_errors: Atomic(u64) = .init(0),
    config_errors: Atomic(u64) = .init(0),
    waits: Atomic(u64) = .init(0),
    wait_timeouts: Atomic(u64) = .init(0),
    denies_applied: Atomic(u64) = .init(0),
    spool_bytes: Atomic(u64) = .init(0),
    spool_rows: Atomic(u64) = .init(0),
    spool_merges: Atomic(u64) = .init(0),
    spool_dropped_rows: Atomic(u64) = .init(0),
    spool_collapsed_rows: Atomic(u64) = .init(0),
    spool_write_errors: Atomic(u64) = .init(0),
    /// `forward_weight_mult` (thousandths) of the last answer the gate gave: a resolve answer
    /// for a key in good standing, and the free tier. 0: no such answer yet.
    forward_milli_resolve: Atomic(u64) = .init(0),
    forward_milli_free: Atomic(u64) = .init(0),

    pub const latency_bounds_ms = [_]u32{ 5, 25, 100, 250, 1000 };
};

const Pend = struct {
    state: enum(u8) { free, queued, running } = .free,
    known: bool = false,
    len: u16 = 0,
    h: u128 = 0,
    key: [contract.max_key_len]u8 = undefined,
};

const FreeCfg = struct {
    seq: Atomic(u32) = .init(0),
    interval_ns: Atomic(u64) = .init(0),
    burst_ns: Atomic(u64) = .init(0),
    /// forward_milli | max_streams << 32
    limits: Atomic(u64) = .init(0),
    set: Atomic(u32) = .init(state.Prices.none),

    const View = struct { interval_ns: u64, burst_ns: u64, forward_milli: u32, max_streams: u32, set: u16 };

    fn read(f: *const FreeCfg) View {
        while (true) {
            const s1 = f.seq.load(.acquire);
            if (s1 & 1 == 0) {
                const lim = f.limits.load(.monotonic);
                const v: View = .{
                    .interval_ns = f.interval_ns.load(.monotonic),
                    .burst_ns = f.burst_ns.load(.monotonic),
                    .forward_milli = @truncate(lim),
                    .max_streams = @truncate(lim >> 32),
                    .set = @truncate(f.set.load(.monotonic)),
                };
                if (f.seq.load(.acquire) == s1) return v;
            }
            std.atomic.spinLoopHint();
        }
    }
};

pub const Gate = struct {
    gpa: Allocator,
    io: Io,
    cfg: Config,
    methods: *const Methods,
    secret: [16]u8,
    boot: [16]u8 = undefined,
    boot_len: u8 = 0,
    keys: state.KeyTable,
    ips: state.IpTable,
    ipdeny: *state.IpDeny,
    prices: *state.Prices,
    plans: state.Plans,
    messages: *state.Messages,
    /// Writers of the tables above (resolver threads, the sender, the tick). Never taken by
    /// `admit`.
    wmu: state.SpinLock = .{},
    free: FreeCfg = .{},
    /// A free tier came from the gate or from `--gate-dir` (false: the built-in floor).
    free_known: Atomic(bool) = .init(false),
    free_next_ns: u64 = 0,
    meter: *meter_mod.Meter,
    spool: spool_mod.Spool,
    spool_mu: Io.Mutex = .init,
    batch_counter: u64 = 0,
    send_backoff_ns: u64 = 0,
    last_cut_ns: u64,
    last_tick_wall_ms: u64,
    sweep_keys_at: u32 = 0,
    sweep_ips_at: u32 = 0,
    pend: *[pend_size]Pend,
    pend_lock: state.SpinLock = .{},
    pend_n: Atomic(u32) = .init(0),
    /// Bumped when a resolve is queued (resolver threads sleep on it).
    resolve_seq: Atomic(u32) = .init(0),
    /// Bumped when a resolve ends (waiting calls sleep on it).
    done_seq: Atomic(u32) = .init(0),
    resolve_tat: Atomic(u64) = .init(0),
    waiters: Atomic(u32) = .init(0),
    reachable: Atomic(bool) = .init(true),
    last_log_ns: Atomic(u64) = .init(0),
    last_usage_log_ns: Atomic(u64) = .init(0),
    stopping: Atomic(bool) = .init(false),
    threads: std.ArrayList(std.Thread) = .empty,
    m: *Metrics,

    const Sip = std.crypto.auth.siphash.SipHash128(1, 3);

    pub fn init(gpa: Allocator, io: Io, cfg: Config) !*Gate {
        const g = try gpa.create(Gate);
        errdefer gpa.destroy(g);
        var secret: [16]u8 = undefined;
        io.random(&secret);
        var keys = try state.KeyTable.init(gpa, cfg.key_capacity);
        errdefer keys.deinit(gpa);
        var ips = try state.IpTable.init(gpa, cfg.address_capacity, std.mem.readInt(u64, secret[0..8], .little));
        errdefer ips.deinit(gpa);
        const ipdeny = try gpa.create(state.IpDeny);
        errdefer gpa.destroy(ipdeny);
        ipdeny.* = .{};
        const prices = try gpa.create(state.Prices);
        errdefer gpa.destroy(prices);
        prices.* = .{};
        const messages = try gpa.create(state.Messages);
        errdefer gpa.destroy(messages);
        messages.* = .{};
        const pend = try gpa.create([pend_size]Pend);
        errdefer gpa.destroy(pend);
        pend.* = @splat(.{});
        const m = try gpa.create(Metrics);
        errdefer gpa.destroy(m);
        m.* = .{};
        const meter = try meter_mod.Meter.init(gpa);
        errdefer meter.deinit();
        var sp = try spool_mod.Spool.open(gpa, io, cfg.dir, cfg.spool_cap);
        errdefer sp.deinit();
        const now = cfg.clock.mono(cfg.clock.ctx);
        g.* = .{
            .gpa = gpa,
            .io = io,
            .cfg = cfg,
            .methods = cfg.methods,
            .secret = secret,
            .keys = keys,
            .ips = ips,
            .ipdeny = ipdeny,
            .prices = prices,
            .plans = state.Plans.init(),
            .messages = messages,
            .meter = meter,
            .spool = sp,
            .last_cut_ns = now,
            .last_tick_wall_ms = cfg.clock.wall(cfg.clock.ctx),
            .pend = pend,
            .m = m,
        };
        if (cfg.boot_id) |b| {
            g.boot_len = @intCast(@min(b.len, g.boot.len));
            @memcpy(g.boot[0..g.boot_len], b[0..g.boot_len]);
        } else {
            var rb: [8]u8 = undefined;
            io.random(&rb);
            g.boot = std.fmt.bytesToHex(rb, .lower);
            g.boot_len = 16;
        }
        // the free tier: the last one the gate gave (kept in the directory), else the floor
        g.applyFree(&floor, now, g.last_tick_wall_ms) catch {};
        g.loadFree(now);
        g.gauges();
        return g;
    }

    pub fn deinit(g: *Gate) void {
        g.stop();
        const gpa = g.gpa;
        g.spool.deinit();
        g.meter.deinit();
        g.keys.deinit(gpa);
        g.ips.deinit(gpa);
        gpa.destroy(g.ipdeny);
        gpa.destroy(g.prices);
        gpa.destroy(g.messages);
        std.crypto.secureZero(u8, std.mem.asBytes(g.pend));
        gpa.destroy(g.pend);
        gpa.destroy(g.m);
        g.threads.deinit(gpa);
        gpa.destroy(g);
    }

    fn monoNow(g: *const Gate) u64 {
        return g.cfg.clock.mono(g.cfg.clock.ctx);
    }
    fn wallNow(g: *const Gate) u64 {
        return g.cfg.clock.wall(g.cfg.clock.ctx);
    }

    pub fn keyHash(g: *const Gate, key: []const u8) u128 {
        return Sip.toInt(key, &g.secret);
    }

    // ------------------------------------------------------------ admission

    /// A refused call. Every refusal is counted by reason in the node's own metrics. Only a
    /// rate-limit refusal goes into the usage rows (`limited`): a call refused for its key (an
    /// unknown key, a suspended one, spent credits) is nobody's usage, and an unknown key in
    /// particular must never count toward the caller's prefix at the gate.
    fn refuse(g: *Gate, reason: Reason, msg: u8, retry_ns: u64, who: meter_mod.Who, method: u8, plan: u8) Decision {
        _ = g.m.denied[@intFromEnum(reason)].fetchAdd(1, .monotonic);
        if (reason == .limited) {
            _ = g.m.limited[plan][method].fetchAdd(1, .monotonic);
            g.meter.add(who, method, plan, .{ .limited = 1 });
        }
        const text = g.messages.get(msg);
        return .{ .deny = .{
            .reason = reason,
            .retry_after_ms = @intCast(@min((retry_ns +| (ns_per_ms - 1)) / ns_per_ms, @as(u64, 3_600_000))),
            .message = if (text.len != 0) text else defaultText(reason),
        } };
    }

    fn statusReason(s: KeyStatus) Reason {
        return switch (s) {
            .invalid => .invalid,
            .suspended => .suspended,
            .exhausted => .exhausted,
            else => .unknown_status,
        };
    }

    /// May this call run? See the module text. `now`: monotonic ns.
    pub fn admit(g: *Gate, c: *const Call, now: u64) Decision {
        const kind = g.methods.kinds[c.method];
        if (kind == .free) return .{ .allow = .{ .kind = .free, .method = c.method } };
        const ip = ident.caller(c.peer, c.forwarded_for, g.cfg.proxies);
        const prefix = ip.prefixKey();
        if (c.key.len != 0) keyed: {
            if (!contract.validKey(c.key)) return g.refuse(.invalid, 0, 0, .{ .ip = prefix }, c.method, state.Plans.free);
            const h = g.keyHash(c.key);
            const f = g.keys.find(h) orelse {
                if (g.wantResolve(c, h, false, now)) return .wait;
                break :keyed;
            };
            const cfg = f.cfg;
            const e = &g.keys.entries[f.idx];
            if (cfg.status == .unresolved) {
                // asked a moment ago without an answer: free tier until it is time to ask again
                if (now >= cfg.expires_ns and g.wantResolve(c, h, false, now)) return .wait;
                break :keyed;
            }
            if (now >= cfg.expires_ns) {
                if (now -| cfg.expires_ns > g.cfg.grace_ns) {
                    // out of grace: an unknown key again
                    if (g.wantResolve(c, h, false, now)) return .wait;
                    break :keyed;
                }
                g.refresh(e, c.key, h, cfg, now);
            }
            const who: meter_mod.Who = .{ .key = .{ .h = @truncate(h), .entry = e, .tenant = f.tenant, .prefix = prefix } };
            var status = cfg.status;
            var msg = cfg.msg;
            if (cfg.deny_until_ns > now) {
                status = cfg.deny_status;
                msg = cfg.deny_msg;
            }
            if (status != .ok) return g.refuse(statusReason(status), msg, 0, who, c.method, cfg.plan);
            const p = g.prices.get(cfg.set, c.method);
            const cost = methods_mod.price(p.w, p.per_item, p.per_minute, kind, c.items);
            if (cfg.leased and cost != 0) {
                const left = e.lease_left.fetchSub(@as(i64, cost), .monotonic) - @as(i64, cost);
                if (left < 0) {
                    _ = e.lease_left.fetchAdd(@as(i64, cost), .monotonic);
                    g.refresh(e, c.key, h, cfg, now);
                    if (c.may_wait and e.refreshing.load(.acquire)) return .wait;
                    return g.refuse(.lease, msg, 0, who, c.method, cfg.plan);
                }
                // renew early, so calls do not stop at the lease's end while the gate answers
                if (@as(u64, @intCast(left)) < cfg.lease_total / 4) g.refresh(e, c.key, h, cfg, now);
            }
            if (kind == .stream) {
                if (e.streams.fetchAdd(1, .monotonic) >= cfg.max_streams) {
                    _ = e.streams.fetchSub(1, .monotonic);
                    if (cfg.leased) _ = e.lease_left.fetchAdd(@as(i64, cost), .monotonic);
                    return g.refuse(.streams, 0, 0, who, c.method, cfg.plan);
                }
            }
            if (state.take(&e.tat, now, cfg.interval_ns, cfg.burst_ns, cost)) |wait_ns| {
                if (kind == .stream) _ = e.streams.fetchSub(1, .monotonic);
                if (cfg.leased) _ = e.lease_left.fetchAdd(@as(i64, cost), .monotonic);
                return g.refuse(.limited, 0, wait_ns, who, c.method, cfg.plan);
            }
            const now_s: u32 = @truncate(now / ns_per_s);
            if (e.last_s.load(.monotonic) != now_s) e.last_s.store(now_s, .monotonic);
            return .{ .allow = .{
                .kind = .key,
                .method = c.method,
                .plan = cfg.plan,
                .stream = kind == .stream,
                .leased = cfg.leased,
                .cost = cost,
                .forward_milli = cfg.forward_milli,
                .idx = f.idx,
                .tenant = f.tenant,
                .h = @truncate(h),
                .prefix = prefix,
                .interval_ns = cfg.interval_ns,
                .per_minute = if (kind == .stream) p.per_minute else 0,
                .opened_ns = now,
                .minutes = 1,
                .checked_ns = now,
            } };
        }
        // free-tier treatment: no key, an unknown key, or a key out of grace
        const who: meter_mod.Who = .{ .ip = prefix };
        if (g.ipdeny.find(prefix, now)) |hit| return g.refuse(statusReason(hit.status), hit.msg, 0, who, c.method, state.Plans.free);
        const fv = g.free.read();
        const p = g.prices.get(fv.set, c.method);
        const cost = methods_mod.price(p.w, p.per_item, p.per_minute, kind, c.items);
        const slot = g.ips.get(ip.limitKey(), @truncate(now / ns_per_s));
        if (kind == .stream) {
            if (slot.streams.fetchAdd(1, .monotonic) >= fv.max_streams) {
                _ = slot.streams.fetchSub(1, .monotonic);
                return g.refuse(.streams, 0, 0, who, c.method, state.Plans.free);
            }
        }
        if (state.take(&slot.tat, now, fv.interval_ns, fv.burst_ns, cost)) |wait_ns| {
            if (kind == .stream) _ = slot.streams.fetchSub(1, .monotonic);
            return g.refuse(.limited, 0, wait_ns, who, c.method, state.Plans.free);
        }
        return .{ .allow = .{
            .kind = .ip,
            .method = c.method,
            .stream = kind == .stream,
            .cost = cost,
            .forward_milli = fv.forward_milli,
            .prefix = prefix,
            .slot = slot,
            .interval_ns = fv.interval_ns,
            .per_minute = if (kind == .stream) p.per_minute else 0,
            .opened_ns = now,
            .minutes = 1,
            .checked_ns = now,
        } };
    }

    pub const KeyCheck = union(enum) { ok, wait, deny: Deny };

    /// Is this key refused outright (invalid, suspended, a status this build does not know)?
    /// For a connection that states its key once, up front (the zui/1 hello). A key the gate has
    /// not answered for yet is `.wait` while a call may wait, then `.ok`: its requests get
    /// free-tier treatment until the answer is in. An exhausted key is `.ok` here and refused per
    /// request, since a top-up brings it back without a new connection.
    pub fn checkKey(g: *Gate, key: []const u8, peer: ident.Ip, may_wait: bool, now: u64) KeyCheck {
        if (!contract.validKey(key)) return .{ .deny = g.streamDeny(.invalid, 0) };
        const h = g.keyHash(key);
        const c: Call = .{ .key = key, .peer = peer, .method = Methods.other, .may_wait = may_wait };
        const f = g.keys.find(h) orelse return if (g.wantResolve(&c, h, false, now)) .wait else .ok;
        const cfg = f.cfg;
        if (cfg.status == .unresolved) return if (now >= cfg.expires_ns and g.wantResolve(&c, h, false, now)) .wait else .ok;
        if (now >= cfg.expires_ns) {
            if (now -| cfg.expires_ns > g.cfg.grace_ns) return if (g.wantResolve(&c, h, false, now)) .wait else .ok;
            g.refresh(&g.keys.entries[f.idx], key, h, cfg, now);
        }
        var status = cfg.status;
        var msg = cfg.msg;
        if (cfg.deny_until_ns > now) {
            status = cfg.deny_status;
            msg = cfg.deny_msg;
        }
        return switch (status) {
            .invalid, .suspended, .unknown => .{ .deny = g.streamDeny(statusReason(status), msg) },
            else => .ok,
        };
    }

    /// Queues a resolve of an unknown key. True when the call should wait for it.
    fn wantResolve(g: *Gate, c: *const Call, h: u128, known: bool, now: u64) bool {
        const queued = g.requestResolve(c.key, h, known, now);
        return queued and c.may_wait and g.reachable.load(.monotonic);
    }

    /// A known key needs a new answer (ttl over, lease low or spent): queue one resolve, not
    /// more often than the entry's `retry_ns` allows.
    fn refresh(g: *Gate, e: *state.Entry, key: []const u8, h: u128, cfg: state.Cfg, now: u64) void {
        if (now < cfg.retry_ns) return;
        if (e.refreshing.cmpxchgStrong(false, true, .acq_rel, .monotonic) != null) return;
        if (!g.requestResolve(key, h, true, now)) e.refreshing.store(false, .release);
    }

    /// True when a resolve of this key is queued or running.
    fn requestResolve(g: *Gate, key: []const u8, h: u128, known: bool, now: u64) bool {
        g.pend_lock.lock();
        defer g.pend_lock.unlock();
        var free: ?*Pend = null;
        for (g.pend) |*p| {
            if (p.state == .free) {
                if (free == null) free = p;
            } else if (p.h == h) return true;
        }
        const slot = free orelse {
            _ = g.m.resolve_capped.fetchAdd(1, .monotonic);
            return false;
        };
        if (!known) {
            // Keys nobody has seen: a budget, so made-up keys cannot make the node call the gate
            // without bound. While the gate is unreachable, one a second keeps probing it.
            const reach = g.reachable.load(.monotonic);
            const iv: u64 = if (reach) ns_per_s / @max(g.cfg.resolve_rps, 1) else ns_per_s;
            const burst: u64 = if (reach) iv * g.cfg.resolve_burst else iv;
            if (state.take(&g.resolve_tat, now, iv, burst, 1) != null) {
                _ = g.m.resolve_capped.fetchAdd(1, .monotonic);
                return false;
            }
        }
        slot.* = .{ .state = .queued, .known = known, .len = @intCast(key.len), .h = h };
        @memcpy(slot.key[0..key.len], key);
        _ = g.pend_n.fetchAdd(1, .monotonic);
        _ = g.resolve_seq.fetchAdd(1, .release);
        g.io.futexWake(u32, &g.resolve_seq.raw, 1);
        return true;
    }

    /// `admit`, waiting up to `wait_ms` when the key is being resolved. Never answers `.wait`.
    /// Uses the real clock: serving threads call this, tests of the logic call `admit`.
    pub fn admitWait(g: *Gate, c: *const Call) Decision {
        var now = g.monoNow();
        var d = g.admit(c, now);
        if (d != .wait) return d;
        if (g.waiters.fetchAdd(1, .monotonic) < g.cfg.max_waiters) {
            _ = g.m.waits.fetchAdd(1, .monotonic);
            const deadline = now + @as(u64, g.cfg.wait_ms) * ns_per_ms;
            while (d == .wait and now < deadline and !g.stopping.load(.acquire)) {
                const seen = g.done_seq.load(.acquire);
                d = g.admit(c, now);
                if (d != .wait) break;
                g.io.futexWaitTimeout(u32, &g.done_seq.raw, seen, .{ .duration = .{ .raw = Io.Duration.fromNanoseconds(@intCast(@min(deadline - now, 20 * ns_per_ms))), .clock = .awake } }) catch {};
                now = g.monoNow();
            }
            if (d == .wait) _ = g.m.wait_timeouts.fetchAdd(1, .monotonic);
        }
        _ = g.waiters.fetchSub(1, .monotonic);
        if (d != .wait) return d;
        var c2 = c.*;
        c2.may_wait = false;
        return g.admit(&c2, now);
    }

    fn whoOf(g: *Gate, t: *const Ticket) meter_mod.Who {
        return switch (t.kind) {
            .key => .{ .key = .{ .h = t.h, .entry = &g.keys.entries[t.idx], .tenant = t.tenant, .prefix = t.prefix } },
            else => .{ .ip = t.prefix },
        };
    }

    /// Units spent after admission (a forwarded call's extra, a stream's next minute).
    fn charge(g: *Gate, t: *const Ticket, units: u32, now: u64) void {
        if (units == 0) return;
        switch (t.kind) {
            .key => {
                const e = &g.keys.entries[t.idx];
                if (e.tenant.load(.monotonic) != t.tenant) return;
                state.debit(&e.tat, now, t.interval_ns, units);
                if (t.leased) _ = e.lease_left.fetchSub(@as(i64, units), .monotonic);
            },
            .ip => if (t.slot) |s| state.debit(&s.tat, now, t.interval_ns, units),
            .free => {},
        }
    }

    /// After routing: counts the call as answered here or forwarded, with its units (times the
    /// forward multiplier when forwarded). A call that failed (`ok` false) is counted and costs
    /// no units.
    pub fn settle(g: *Gate, t: *const Ticket, route: Route, ok: bool, now: u64) void {
        if (t.kind == .free) return;
        var c: Counters = .{};
        if (route == .forwarded) c.forwarded = 1 else c.local = 1;
        if (ok) {
            c.units = t.cost;
            if (route == .forwarded and t.forward_milli > 1000) {
                c.units = methods_mod.forwarded(t.cost, t.forward_milli);
                g.charge(t, @intCast(c.units - t.cost), now);
            }
        } else if (t.kind == .key and t.leased and t.cost != 0) {
            const e = &g.keys.entries[t.idx];
            if (e.tenant.load(.monotonic) == t.tenant) _ = e.lease_left.fetchAdd(@as(i64, t.cost), .monotonic);
        }
        g.meter.add(g.whoOf(t), t.method, t.plan, c);
    }

    // ------------------------------------------------------------ streams

    /// Books the minutes a stream priced per minute has started since the last call. A leased
    /// key that had nothing left at the start of two minutes in a row (a renewal was asked for
    /// in between) loses the stream: at most one minute's units are spent past a lease.
    fn streamMinutes(g: *Gate, t: *Ticket, key: ?[]const u8, now: u64) ?Deny {
        if (t.per_minute == 0) return null;
        const started: u32 = @intCast(@min((now -| t.opened_ns) / (60 * ns_per_s) + 1, std.math.maxInt(u32)));
        if (started <= t.minutes) return null;
        if (t.kind == .key and t.leased) {
            const e = &g.keys.entries[t.idx];
            if (e.tenant.load(.monotonic) == t.tenant) {
                if (e.lease_left.load(.monotonic) <= 0) {
                    t.lease_strikes += 1;
                    if (t.lease_strikes >= 2 and key != null) return g.streamDeny(.lease, 0);
                    var hi: u64 = 0;
                    if (key) |k| if (e.read(&hi)) |cfg| g.refresh(e, k, g.keyHash(k), cfg, now);
                } else t.lease_strikes = 0;
            }
        }
        const units: u32 = (started - t.minutes) *| t.per_minute;
        t.minutes = started;
        g.charge(t, units, now);
        g.meter.add(g.whoOf(t), t.method, t.plan, .{ .units = units });
        return null;
    }

    /// Call as a stream sends (at least every few seconds while it is open): books the minutes
    /// started since, and, at most once a second, checks that the caller may still hold the
    /// stream. `key` is the stream's API key ("" for a keyless one). A `Deny` ends the stream.
    pub fn streamTick(g: *Gate, t: *Ticket, key: []const u8, now: u64) ?Deny {
        if (t.kind == .free) return null;
        if (g.streamMinutes(t, key, now)) |d| return d;
        if (now -| t.checked_ns < ns_per_s) return null;
        t.checked_ns = now;
        switch (t.kind) {
            .ip => if (g.ipdeny.find(t.prefix, now)) |hit| return g.streamDeny(statusReason(hit.status), hit.msg),
            .key => {
                const e = &g.keys.entries[t.idx];
                var hi: u64 = 0;
                const cfg = e.read(&hi) orelse return null;
                if (e.tenant.load(.monotonic) != t.tenant) return g.streamDeny(.unverified, 0);
                const h = g.keyHash(key);
                if (now >= cfg.expires_ns) {
                    if (now -| cfg.expires_ns > g.cfg.grace_ns) return g.streamDeny(.unverified, 0);
                    g.refresh(e, key, h, cfg, now);
                }
                if (cfg.deny_until_ns > now and cfg.deny_status != .ok) return g.streamDeny(statusReason(cfg.deny_status), cfg.deny_msg);
                if (cfg.status != .ok) return g.streamDeny(statusReason(cfg.status), cfg.msg);
            },
            .free => {},
        }
        return null;
    }

    fn streamDeny(g: *Gate, reason: Reason, msg: u8) Deny {
        _ = g.m.denied[@intFromEnum(reason)].fetchAdd(1, .monotonic);
        const text = g.messages.get(msg);
        return .{ .reason = reason, .message = if (text.len != 0) text else defaultText(reason) };
    }

    pub fn streamMsgs(g: *Gate, t: *const Ticket, n: u32) void {
        if (t.kind == .free or n == 0) return;
        g.meter.add(g.whoOf(t), t.method, t.plan, .{ .stream_msgs = n });
    }

    /// The stream ended: its last started minute is booked and its slot is free again.
    pub fn streamClose(g: *Gate, t: *Ticket, now: u64) void {
        if (!t.stream) return;
        t.stream = false;
        _ = g.streamMinutes(t, null, now);
        switch (t.kind) {
            .key => {
                const e = &g.keys.entries[t.idx];
                if (e.tenant.load(.monotonic) == t.tenant) _ = e.streams.fetchSub(1, .monotonic);
            },
            .ip => if (t.slot) |s| {
                _ = s.streams.fetchSub(1, .monotonic);
            },
            .free => {},
        }
    }

    // ------------------------------------------------------------ resolves

    fn logf(g: *Gate, err: bool, comptime fmt: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, fmt, args) catch buf[0..];
        if (g.cfg.log) |sink| return sink.write(sink.ctx, err, line);
        if (err) std.log.err("{s}", .{line}) else std.log.warn("{s}", .{line});
    }

    fn logLimited(g: *Gate, now: u64) bool {
        const last = g.last_log_ns.load(.monotonic);
        if (last != 0 and now -| last < 60 * ns_per_s) return false;
        return g.last_log_ns.cmpxchgStrong(last, now, .monotonic, .monotonic) == null;
    }

    /// A gate answer that is not an answer. 401 and 403 mean this node's own credential or edge
    /// id is wrong: said clearly, at most once a minute. Everything is "gate unreachable".
    fn gateFailed(g: *Gate, what: []const u8, status: ?u16, err: ?anyerror, now: u64) void {
        g.reachable.store(false, .release);
        const config = status != null and (status.? == 401 or status.? == 403);
        if (config) _ = g.m.config_errors.fetchAdd(1, .monotonic);
        if (!g.logLimited(now)) return;
        if (config) {
            g.logf(true, "gate: {s} refused with HTTP {d}: this node's --gate-token-file or --gate-edge-id does not match what the gate expects; keys keep their last answer for the grace period, new keys get the free tier", .{ what, status.? });
        } else if (status) |s| {
            g.logf(false, "gate: {s} answered HTTP {d}; treating the gate as unreachable", .{ what, s });
        } else if (err) |e| {
            g.logf(false, "gate: {s} failed: {s}; treating the gate as unreachable", .{ what, @errorName(e) });
        }
    }

    fn observe(g: *Gate, ns: u64) void {
        _ = g.m.resolve_ns.fetchAdd(ns, .monotonic);
        const ms = ns / ns_per_ms;
        var i: usize = 0;
        while (i < Metrics.latency_bounds_ms.len and ms > Metrics.latency_bounds_ms[i]) i += 1;
        _ = g.m.resolve_buckets[i].fetchAdd(1, .monotonic);
    }

    /// Takes one queued key and asks the gate about it. False when nothing was queued.
    pub fn resolveStep(g: *Gate) bool {
        var key_buf: [contract.max_key_len]u8 = undefined;
        var key_len: usize = 0;
        var h: u128 = 0;
        var known = false;
        var slot: ?*Pend = null;
        {
            g.pend_lock.lock();
            defer g.pend_lock.unlock();
            for (g.pend) |*p| if (p.state == .queued) {
                p.state = .running;
                key_len = p.len;
                @memcpy(key_buf[0..key_len], p.key[0..key_len]);
                h = p.h;
                known = p.known;
                slot = p;
                break;
            };
        }
        const p = slot orelse return false;
        defer {
            std.crypto.secureZero(u8, &key_buf);
            g.pend_lock.lock();
            std.crypto.secureZero(u8, &p.key);
            p.* = .{};
            g.pend_lock.unlock();
            _ = g.pend_n.fetchSub(1, .monotonic);
            _ = g.done_seq.fetchAdd(1, .release);
            g.io.futexWake(u32, &g.done_seq.raw, std.math.maxInt(u32));
        }
        g.resolveKey(key_buf[0..key_len], h, known);
        return true;
    }

    fn resolveKey(g: *Gate, key: []const u8, h: u128, known: bool) void {
        _ = g.m.resolves.fetchAdd(1, .monotonic);
        var arena_state = std.heap.ArenaAllocator.init(g.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var ub: [640]u8 = undefined;
        var body: std.ArrayList(u8) = .empty;
        var out: std.ArrayList(u8) = .empty;
        defer {
            // the request body holds the key
            std.crypto.secureZero(u8, body.allocatedSlice());
            body.deinit(g.gpa);
            out.deinit(g.gpa);
        }
        const t0 = g.monoNow();
        const url = contract.joinUrl(&ub, g.cfg.base_url, contract.path_resolve) catch return g.resolveFailed(h, known, t0);
        contract.resolveBody(&body, g.gpa, g.cfg.edge_id, key) catch return g.resolveFailed(h, known, t0);
        const req: HttpRequest = .{ .post = true, .url = url, .token = g.cfg.token, .body = body.items, .timeout_ms = g.cfg.resolve_timeout_ms };
        const status = (g.cfg.transport.call(g.cfg.transport.ctx, &req, &out, g.gpa) catch |e| {
            const now = g.monoNow();
            g.observe(now -| t0);
            g.gateFailed("resolve", null, e, now);
            return g.resolveFailed(h, known, now);
        }).status;
        const now = g.monoNow();
        g.observe(now -| t0);
        if (status != 200) {
            g.gateFailed("resolve", status, null, now);
            return g.resolveFailed(h, known, now);
        }
        const ans = contract.parseResolve(arena, out.items) catch {
            if (g.logLimited(now)) g.logf(false, "gate: a resolve answer could not be read (HTTP 200, {d} bytes)", .{out.items.len});
            return g.resolveFailed(h, known, now);
        };
        g.reachable.store(true, .release);
        // (an answer for a key that is refused prices nothing: its multiplier is not the gate's word on forwards)
        if (ans.status == .ok) g.m.forward_milli_resolve.store(ans.pricing.forward_milli, .monotonic);
        g.install(h, &ans, now) catch return g.resolveFailed(h, known, now);
    }

    fn resolveFailed(g: *Gate, h: u128, known: bool, now: u64) void {
        _ = known;
        _ = g.m.resolve_errors.fetchAdd(1, .monotonic);
        g.wmu.lock();
        defer g.wmu.unlock();
        const pl = g.keys.place(h, EvictCtx{ .g = g, .now = now }, evictScore) orelse return;
        const e = &g.keys.entries[pl.idx];
        if (pl.existing) {
            var hi: u64 = 0;
            var cfg = e.read(&hi) orelse return;
            if (cfg.status == .unresolved) {
                cfg.expires_ns = now + g.unresolvedNs();
            } else {
                // a known key keeps its answer; no new attempt for a while
                cfg.retry_ns = now + g.cfg.retry_ns;
            }
            e.write(hi, cfg);
            e.refreshing.store(false, .release);
            return;
        }
        // Not cached as invalid: free-tier treatment for a short while, then asked again.
        if (pl.victim) g.dropLocked(pl.idx);
        e.setKid("");
        e.tat.store(0, .monotonic);
        e.streams.store(0, .monotonic);
        e.last_s.store(@truncate(now / ns_per_s), .monotonic);
        e.write(@truncate(h >> 64), .{ .status = .unresolved, .expires_ns = now + g.unresolvedNs() });
        g.keys.publish(pl.idx, h);
    }

    fn unresolvedNs(g: *const Gate) u64 {
        return if (g.reachable.load(.monotonic)) g.cfg.unresolved_ns else g.cfg.unresolved_ns * 6;
    }

    const EvictCtx = struct { g: *Gate, now: u64 };

    /// Which entry of a full window gives way to a new key (highest score; 0 stays): one that
    /// holds no answer, one out of grace, a refused key, else the one idle longest (a minute or
    /// more). A key with a stream open always stays.
    fn evictScore(ctx: EvictCtx, e: *const state.Entry, cfg: state.Cfg) u64 {
        if (e.streams.load(.monotonic) != 0) return 0;
        if (cfg.status == .unresolved) return std.math.maxInt(u64);
        if (ctx.now > cfg.expires_ns and ctx.now - cfg.expires_ns > ctx.g.cfg.grace_ns) return std.math.maxInt(u64) - 1;
        const now_s: u32 = @truncate(ctx.now / ns_per_s);
        const idle: u64 = now_s -| e.last_s.load(.monotonic);
        if (cfg.status != .ok) return (@as(u64, 1) << 40) + idle;
        return if (idle >= 60) idle else 0;
    }

    /// Writer lock held.
    fn dropLocked(g: *Gate, idx: u32) void {
        var hi: u64 = 0;
        if (g.keys.entries[idx].read(&hi)) |cfg| g.prices.release(cfg.set);
        g.keys.remove(idx);
    }

    fn install(g: *Gate, h: u128, ans: *const contract.Resolve, now: u64) !void {
        const set_data = methods_mod.PriceSet.build(g.methods, ans.pricing);
        g.wmu.lock();
        defer g.wmu.unlock();
        const pl = g.keys.place(h, EvictCtx{ .g = g, .now = now }, evictScore) orelse {
            _ = g.m.cache_full.fetchAdd(1, .monotonic);
            return;
        };
        const set = g.prices.intern(&set_data) orelse {
            if (g.logLimited(now)) g.logf(false, "gate: more than {d} distinct price tables in use; a resolve answer was dropped", .{state.Prices.size});
            return error.TooManyPriceTables;
        };
        const e = &g.keys.entries[pl.idx];
        if (pl.victim) g.dropLocked(pl.idx);
        if (pl.existing) {
            var hi: u64 = 0;
            if (e.read(&hi)) |old| g.prices.release(old.set);
            if (!e.kidEquals(ans.key_id)) e.setKid(ans.key_id);
        } else {
            e.setKid(ans.key_id);
            e.tat.store(0, .monotonic);
            e.streams.store(0, .monotonic);
            e.last_s.store(@truncate(now / ns_per_s), .monotonic);
        }
        const iv = state.intervalNs(ans.rps);
        const cfg: state.Cfg = .{
            .status = KeyStatus.from(ans.status),
            .plan = g.plans.intern(ans.plan),
            .msg = g.messages.intern(ans.message),
            .set = set,
            .interval_ns = iv,
            .burst_ns = @as(u64, ans.burst) *| iv,
            .forward_milli = ans.pricing.forward_milli,
            .max_streams = ans.max_streams,
            .expires_ns = now + @as(u64, ans.ttl_s) * ns_per_s,
            .retry_ns = now + g.cfg.min_refresh_ns,
            .leased = ans.lease_units != null,
            .lease_total = ans.lease_units orelse 0,
        };
        // A resolve answer replaces what was left of the previous lease.
        e.lease_left.store(@intCast(@min(cfg.lease_total, std.math.maxInt(i62))), .monotonic);
        e.write(@truncate(h >> 64), cfg);
        g.keys.publish(pl.idx, h);
        e.refreshing.store(false, .release);
    }

    // ------------------------------------------------------------ deny lists and the free tier

    fn untilNs(item: *const contract.DenyItem, is_key: bool, now: u64, wall_ms: u64) ?u64 {
        const u = item.until_ms orelse return if (is_key) std.math.maxInt(u64) else now + deny_default_ns;
        if (u <= wall_ms) return null;
        return now +| @as(u64, @min(u - wall_ms, deny_max_ms)) * ns_per_ms;
    }

    /// Applies a deny list from the gate at once: keys by key id, keyless callers by prefix.
    pub fn applyDeny(g: *Gate, items: []const contract.DenyItem, now: u64, wall_ms: u64) void {
        if (items.len == 0) return;
        var arena_state = std.heap.ArenaAllocator.init(g.gpa);
        defer arena_state.deinit();
        var by_kid: std.StringHashMapUnmanaged(*const contract.DenyItem) = .empty;
        g.wmu.lock();
        defer g.wmu.unlock();
        for (items) |*it| {
            if (it.key_id.len != 0) {
                by_kid.put(arena_state.allocator(), it.key_id, it) catch {};
                continue;
            }
            const pk = ident.parsePrefix(it.ip_prefix) orelse continue;
            const until = untilNs(it, false, now, wall_ms) orelse continue;
            g.ipdeny.put(pk, until, KeyStatus.from(it.status), g.messages.intern(it.message), now);
            _ = g.m.denies_applied.fetchAdd(1, .monotonic);
        }
        if (by_kid.count() == 0) return;
        var kb: [contract.max_key_id_len]u8 = undefined;
        for (g.keys.tags, g.keys.entries) |*tag, *e| {
            if (tag.load(.monotonic) == 0) continue;
            const kid = e.readKid(e.tenant.load(.acquire), &kb) orelse continue;
            if (kid.len == 0) continue;
            const it = by_kid.get(kid) orelse continue;
            const until = untilNs(it, true, now, wall_ms) orelse continue;
            var hi: u64 = 0;
            var cfg = e.read(&hi) orelse continue;
            cfg.deny_status = KeyStatus.from(it.status);
            cfg.deny_until_ns = until;
            cfg.deny_msg = g.messages.intern(it.message);
            e.write(hi, cfg);
            _ = g.m.denies_applied.fetchAdd(1, .monotonic);
        }
    }

    fn applyFree(g: *Gate, f: *const contract.Free, now: u64, wall_ms: u64) !void {
        const set_data = methods_mod.PriceSet.build(g.methods, f.pricing);
        {
            g.wmu.lock();
            defer g.wmu.unlock();
            const set = g.prices.intern(&set_data) orelse return error.TooManyPriceTables;
            const old: u16 = @truncate(g.free.set.load(.monotonic));
            const iv = state.intervalNs(f.rps_per_ip);
            _ = g.free.seq.fetchAdd(1, .acq_rel);
            g.free.interval_ns.store(iv, .monotonic);
            g.free.burst_ns.store(@as(u64, f.burst) *| iv, .monotonic);
            g.free.limits.store(@as(u64, f.pricing.forward_milli) | (@as(u64, f.max_streams) << 32), .monotonic);
            g.free.set.store(set, .monotonic);
            _ = g.free.seq.fetchAdd(1, .acq_rel);
            g.prices.release(old);
        }
        g.applyDeny(f.deny, now, wall_ms);
    }

    const free_file = "free.json";
    const free_tmp = "free.json.tmp";

    fn loadFree(g: *Gate, now: u64) void {
        const d = g.cfg.dir orelse return;
        const text = d.readFileAlloc(g.io, free_file, g.gpa, .limited(contract.max_answer_bytes)) catch return;
        defer g.gpa.free(text);
        var arena_state = std.heap.ArenaAllocator.init(g.gpa);
        defer arena_state.deinit();
        const f = contract.parseFree(arena_state.allocator(), text) catch return;
        g.applyFree(&f, now, g.wallNow()) catch return;
        g.m.forward_milli_free.store(f.pricing.forward_milli, .monotonic);
        g.free_known.store(true, .release);
    }

    /// Asks the gate for the free tier and keeps the answer in the directory. Returns when to
    /// ask again (monotonic ns).
    pub fn refreshFree(g: *Gate) u64 {
        var ub: [640]u8 = undefined;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(g.gpa);
        const url = contract.freeUrl(&ub, g.cfg.base_url, g.cfg.edge_id) catch return g.monoNow() + free_retry_ns;
        const req: HttpRequest = .{ .post = false, .url = url, .token = g.cfg.token, .timeout_ms = g.cfg.resolve_timeout_ms };
        _ = g.m.free_fetches.fetchAdd(1, .monotonic);
        const status = (g.cfg.transport.call(g.cfg.transport.ctx, &req, &out, g.gpa) catch |e| {
            const now = g.monoNow();
            _ = g.m.free_errors.fetchAdd(1, .monotonic);
            g.gateFailed("free tier", null, e, now);
            return now + free_retry_ns;
        }).status;
        const now = g.monoNow();
        if (status != 200) {
            _ = g.m.free_errors.fetchAdd(1, .monotonic);
            g.gateFailed("free tier", status, null, now);
            return now + free_retry_ns;
        }
        var arena_state = std.heap.ArenaAllocator.init(g.gpa);
        defer arena_state.deinit();
        const f = contract.parseFree(arena_state.allocator(), out.items) catch {
            _ = g.m.free_errors.fetchAdd(1, .monotonic);
            return now + free_retry_ns;
        };
        g.applyFree(&f, now, g.wallNow()) catch return now + free_retry_ns;
        g.m.forward_milli_free.store(f.pricing.forward_milli, .monotonic);
        g.reachable.store(true, .release);
        g.free_known.store(true, .release);
        if (g.cfg.dir) |d| {
            // the bytes the gate sent, so a restart during an outage starts from them
            if (d.writeFile(g.io, .{ .sub_path = free_tmp, .data = out.items })) |_| {
                d.rename(free_tmp, d, free_file, g.io) catch {};
            } else |_| {}
        }
        return now + @as(u64, f.ttl_s) * ns_per_s;
    }

    // ------------------------------------------------------------ usage

    /// Posts the waiting usage batch (sealing the next one first when none waits). Returns how
    /// long to wait before the next step: 0 when the batch left the queue, a back-off after a
    /// failure, null when there is nothing to send.
    ///
    /// What the gate's answer means for the batch:
    /// - 2xx: delivered. Rows it names as `rejected` are counted and said once; they are not
    ///   sent again.
    /// - 400 or 413: the gate will never take these bytes. The batch is written to
    ///   `dead-letter/` in the gate directory and leaves the queue, so the batches behind it go
    ///   out.
    /// - 401 or 403: this node's credential or edge id is wrong. The batch stays; back-off.
    /// - anything else (429, 5xx, no answer): the batch stays; back-off, at least the answer's
    ///   `Retry-After` when it has one.
    pub fn sendStep(g: *Gate) ?u64 {
        var body: []const u8 = undefined;
        var id: []const u8 = undefined;
        var rows: u32 = 0;
        {
            g.spool_mu.lockUncancelable(g.io);
            defer g.spool_mu.unlock(g.io);
            const have = g.spool.seal(g.cfg.edge_id, g.boot[0..g.boot_len], &g.batch_counter) catch false;
            if (!have) return null;
            // owned by the spool until `ack`, which only this step calls
            body = g.spool.sealed.?.body;
            id = g.spool.sealed.?.id;
            rows = g.spool.sealed.?.rows;
        }
        var ub: [640]u8 = undefined;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(g.gpa);
        const url = contract.joinUrl(&ub, g.cfg.base_url, contract.path_usage) catch return g.sendFailed(null);
        const req: HttpRequest = .{ .post = true, .url = url, .token = g.cfg.token, .body = body, .timeout_ms = g.cfg.usage_timeout_ms };
        const reply = g.cfg.transport.call(g.cfg.transport.ctx, &req, &out, g.gpa) catch |e| {
            g.gateFailed("usage", null, e, g.monoNow());
            return g.sendFailed(null);
        };
        const now = g.monoNow();
        if (reply.status == 400 or reply.status == 413) {
            g.reachable.store(true, .release);
            g.deadLetter(body);
            if (g.usageLogLimited(now)) g.logf(false, "gate: usage batch {s} ({d} rows) refused for good with HTTP {d}; kept in {s}/ and taken off the queue", .{ id, rows, reply.status, dead_dir });
            g.spool_mu.lockUncancelable(g.io);
            g.spool.ack();
            g.spool_mu.unlock(g.io);
            g.send_backoff_ns = 0;
            return 0;
        }
        if (reply.status / 100 != 2) {
            g.gateFailed("usage", reply.status, null, now);
            return g.sendFailed(reply.retry_after_ms);
        }
        g.reachable.store(true, .release);
        var arena_state = std.heap.ArenaAllocator.init(g.gpa);
        defer arena_state.deinit();
        if (contract.parseUsageAnswer(arena_state.allocator(), out.items)) |ans| {
            g.applyDeny(ans.deny, now, g.wallNow());
            if (ans.rejected != 0) {
                _ = g.m.rows_rejected.fetchAdd(ans.rejected, .monotonic);
                if (g.usageLogLimited(now)) {
                    // row numbers only: no key id, no prefix
                    var lb: [300]u8 = undefined;
                    var n: usize = 0;
                    for (ans.rejected_rows) |r| {
                        const part = std.fmt.bufPrint(lb[n..], "{s}{d}", .{ if (n == 0) "" else ",", r }) catch break;
                        n += part.len;
                    }
                    g.logf(false, "gate: usage batch {s}: the gate did not take {d} of {d} rows (rows {s}); they are not sent again", .{ id, ans.rejected, rows, lb[0..n] });
                }
            }
        } else |_| {}
        {
            g.spool_mu.lockUncancelable(g.io);
            defer g.spool_mu.unlock(g.io);
            g.spool.ack();
        }
        _ = g.m.batches_sent.fetchAdd(1, .monotonic);
        _ = g.m.rows_sent.fetchAdd(rows, .monotonic);
        g.send_backoff_ns = 0;
        return 0;
    }

    /// The back-off after a failed post: 1 s doubling to 30 s, and never under what the gate
    /// asked for (`Retry-After`, at most five minutes).
    fn sendFailed(g: *Gate, retry_after_ms: ?u32) u64 {
        _ = g.m.batches_failed.fetchAdd(1, .monotonic);
        g.send_backoff_ns = std.math.clamp(g.send_backoff_ns * 2, ns_per_s, 30 * ns_per_s);
        const asked: u64 = @as(u64, @min(retry_after_ms orelse 0, 300_000)) * ns_per_ms;
        return @max(g.send_backoff_ns, asked);
    }

    fn usageLogLimited(g: *Gate, now: u64) bool {
        const last = g.last_usage_log_ns.load(.monotonic);
        if (last != 0 and now -| last < 60 * ns_per_s) return false;
        return g.last_usage_log_ns.cmpxchgStrong(last, now, .monotonic, .monotonic) == null;
    }

    pub const dead_dir = "dead-letter";
    /// Dead letters kept: the newest 32 batches (a batch is at most 1,000 rows, a few hundred
    /// KiB). The next slot is kept in `dead-letter/next`, so a restart goes on from there.
    pub const dead_keep = 32;

    fn deadLetter(g: *Gate, body: []const u8) void {
        _ = g.m.batches_dead.fetchAdd(1, .monotonic);
        const d = g.cfg.dir orelse return;
        d.createDirPath(g.io, dead_dir) catch return;
        var slot: u32 = 0;
        if (d.readFileAlloc(g.io, dead_dir ++ "/next", g.gpa, .limited(16))) |t| {
            defer g.gpa.free(t);
            slot = std.fmt.parseInt(u32, std.mem.trim(u8, t, " \r\n"), 10) catch 0;
        } else |_| {}
        var nb: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, dead_dir ++ "/batch-{d:0>2}.json", .{slot % dead_keep}) catch return;
        d.writeFile(g.io, .{ .sub_path = name, .data = body }) catch return;
        var sb: [16]u8 = undefined;
        const next = std.fmt.bufPrint(&sb, "{d}", .{(slot + 1) % dead_keep}) catch return;
        d.writeFile(g.io, .{ .sub_path = dead_dir ++ "/next", .data = next }) catch {};
    }

    /// Once a second: the serving threads' counters go into the spool's journal (synced), a
    /// window is closed every five seconds, the tables shed what is idle or over.
    pub fn tick(g: *Gate, now: u64, wall_ms: u64) void {
        var rows: std.ArrayList(meter_mod.Row) = .empty;
        defer rows.deinit(g.gpa);
        g.meter.collect(&rows, g.gpa) catch {};
        var arena_state = std.heap.ArenaAllocator.init(g.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var out: std.ArrayList(contract.Row) = .empty;
        for (rows.items) |*r| {
            _ = g.m.allowed[r.plan % state.Plans.size][r.method].fetchAdd(r.c.local + r.c.forwarded, .monotonic);
            var sb: [contract.max_key_id_len + 1]u8 = undefined;
            const subject = arena.dupe(u8, meter_mod.subjectText(&sb, r)) catch continue;
            out.append(arena, .{ .subject = subject, .method = g.methods.name_(r.method), .c = r.c }) catch continue;
        }
        {
            g.spool_mu.lockUncancelable(g.io);
            defer g.spool_mu.unlock(g.io);
            const from = @min(g.last_tick_wall_ms, wall_ms);
            g.spool.addDelta(out.items, from, wall_ms) catch {
                g.spool.stats.write_errors += 1;
            };
            g.last_tick_wall_ms = wall_ms;
            if (now -| g.last_cut_ns >= g.cfg.cut_ns) {
                g.spool.cut() catch {};
                g.last_cut_ns = now;
            }
            g.spool.enforce();
            g.spool.sync();
        }
        g.sweep(now);
        g.gauges();
    }

    fn gauges(g: *Gate) void {
        g.spool_mu.lockUncancelable(g.io);
        defer g.spool_mu.unlock(g.io);
        const st = g.spool.stats;
        g.m.spool_bytes.store(if (g.spool.file != null) g.spool.end else g.spool.live, .monotonic);
        g.m.spool_rows.store(g.spool.pendingRows() + if (g.spool.sealed) |b| b.rows else 0, .monotonic);
        g.m.spool_merges.store(st.merges, .monotonic);
        g.m.spool_dropped_rows.store(st.dropped_rows, .monotonic);
        g.m.spool_collapsed_rows.store(st.collapsed_rows, .monotonic);
        g.m.spool_write_errors.store(st.write_errors, .monotonic);
    }

    fn sweep(g: *Gate, now: u64) void {
        const now_s: u32 = @truncate(now / ns_per_s);
        g.sweep_ips_at = g.ips.sweep(now_s, g.cfg.address_idle_s, g.sweep_ips_at, @max(g.ips.mask / 16, 64));
        g.wmu.lock();
        defer g.wmu.unlock();
        g.ipdeny.sweep(now);
        // a sixteenth of the key table a tick: entries without an answer whose time is up, and
        // entries out of grace
        var n: u32 = @max(g.keys.mask / 16, 64);
        var i = g.sweep_keys_at;
        while (n > 0) : (n -= 1) {
            const idx = i & g.keys.mask;
            i +%= 1;
            if (g.keys.tags[idx].load(.monotonic) == 0) continue;
            const e = &g.keys.entries[idx];
            var hi: u64 = 0;
            const cfg = e.read(&hi) orelse continue;
            if (e.streams.load(.monotonic) != 0) continue;
            const gone = if (cfg.status == .unresolved) now >= cfg.expires_ns else now > cfg.expires_ns and now - cfg.expires_ns > g.cfg.grace_ns;
            if (gone) g.dropLocked(idx);
        }
        g.sweep_keys_at = i & g.keys.mask;
    }

    // ------------------------------------------------------------ threads

    /// Starts the gate's threads: resolvers, the sender and the tick.
    pub fn start(g: *Gate) !void {
        var i: u32 = 0;
        while (i < @max(g.cfg.resolvers, 1)) : (i += 1) try g.threads.append(g.gpa, try std.Thread.spawn(.{}, resolverMain, .{g}));
        try g.threads.append(g.gpa, try std.Thread.spawn(.{}, senderMain, .{g}));
        try g.threads.append(g.gpa, try std.Thread.spawn(.{}, tickMain, .{g}));
    }

    /// Stops the threads (bounded: every wait is 100 ms at most, requests in flight are
    /// canceled) and journals what the serving threads counted since the last tick. Nothing
    /// counted is lost: what the gate has not acknowledged stays in the spool for the next start.
    pub fn stop(g: *Gate) void {
        if (g.stopping.swap(true, .acq_rel)) return;
        if (g.cfg.transport.cancel) |f| f(g.cfg.transport.ctx);
        _ = g.resolve_seq.fetchAdd(1, .release);
        g.io.futexWake(u32, &g.resolve_seq.raw, std.math.maxInt(u32));
        _ = g.done_seq.fetchAdd(1, .release);
        g.io.futexWake(u32, &g.done_seq.raw, std.math.maxInt(u32));
        for (g.threads.items) |t| t.join();
        g.threads.clearRetainingCapacity();
        if (g.cfg.crash_on_stop) return;
        g.tick(g.monoNow(), g.wallNow());
        g.spool_mu.lockUncancelable(g.io);
        g.spool.cut() catch {};
        g.spool.sync();
        g.spool_mu.unlock(g.io);
    }

    fn nap(g: *Gate, ms: u32) void {
        g.io.sleep(.fromMilliseconds(ms), .awake) catch {};
    }

    fn resolverMain(g: *Gate) void {
        while (!g.stopping.load(.acquire)) {
            const seen = g.resolve_seq.load(.acquire);
            if (g.resolveStep()) continue;
            g.io.futexWaitTimeout(u32, &g.resolve_seq.raw, seen, .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(100), .clock = .awake } }) catch {};
        }
    }

    fn senderMain(g: *Gate) void {
        var next_send: u64 = 0;
        while (!g.stopping.load(.acquire)) {
            const now = g.monoNow();
            if (now >= g.free_next_ns) g.free_next_ns = g.refreshFree();
            if (g.stopping.load(.acquire)) return;
            if (now >= next_send) {
                if (g.sendStep()) |wait_ns| {
                    next_send = g.monoNow() + wait_ns;
                    if (wait_ns == 0) continue;
                } else next_send = now + 200 * ns_per_ms;
            }
            g.nap(100);
        }
    }

    fn tickMain(g: *Gate) void {
        var next = g.monoNow() + ns_per_s;
        while (!g.stopping.load(.acquire)) {
            const now = g.monoNow();
            if (now >= next) {
                g.tick(now, g.wallNow());
                next += ns_per_s;
                if (next < now) next = now + ns_per_s;
                continue;
            }
            g.nap(@intCast(@min((next - now) / ns_per_ms + 1, 100)));
        }
    }

    // ------------------------------------------------------------ metrics

    pub fn renderMetrics(g: *Gate, w: *Io.Writer) !void {
        const m = g.m;
        try w.writeAll("# TYPE zui_gate_allowed counter\n");
        for (&m.allowed, 0..) |*by_method, plan| for (by_method, 0..) |*v, method| {
            const n = v.load(.monotonic);
            if (n != 0) try w.print("zui_gate_allowed{{plan=\"{s}\",method=\"{s}\"}} {d}\n", .{ g.plans.name(@intCast(plan)), g.methods.name_(@intCast(method)), n });
        };
        try w.writeAll("# TYPE zui_gate_limited counter\n");
        for (&m.limited, 0..) |*by_method, plan| for (by_method, 0..) |*v, method| {
            const n = v.load(.monotonic);
            if (n != 0) try w.print("zui_gate_limited{{plan=\"{s}\",method=\"{s}\"}} {d}\n", .{ g.plans.name(@intCast(plan)), g.methods.name_(@intCast(method)), n });
        };
        // every refusal by reason (a rate-limit refusal is `over_limit`); none but `over_limit`
        // is ever in a usage row
        try w.writeAll("# TYPE zui_gate_refused counter\n");
        for (std.meta.tags(Reason)) |reason| {
            try w.print("zui_gate_refused{{reason=\"{s}\"}} {d}\n", .{ if (reason == .limited) "over_limit" else @tagName(reason), m.denied[@intFromEnum(reason)].load(.monotonic) });
        }
        try w.print("# TYPE zui_gate_resolves counter\nzui_gate_resolves {d}\n# TYPE zui_gate_resolve_errors counter\nzui_gate_resolve_errors {d}\n# TYPE zui_gate_resolve_capped counter\nzui_gate_resolve_capped {d}\n", .{ m.resolves.load(.monotonic), m.resolve_errors.load(.monotonic), m.resolve_capped.load(.monotonic) });
        try w.writeAll("# TYPE zui_gate_resolve_seconds histogram\n");
        var cum: u64 = 0;
        for (Metrics.latency_bounds_ms, 0..) |b, i| {
            cum += m.resolve_buckets[i].load(.monotonic);
            try w.print("zui_gate_resolve_seconds_bucket{{le=\"{d}.{d:0>3}\"}} {d}\n", .{ b / 1000, b % 1000, cum });
        }
        cum += m.resolve_buckets[Metrics.latency_bounds_ms.len].load(.monotonic);
        const sum_ns = m.resolve_ns.load(.monotonic);
        try w.print("zui_gate_resolve_seconds_bucket{{le=\"+Inf\"}} {d}\nzui_gate_resolve_seconds_sum {d}.{d:0>6}\nzui_gate_resolve_seconds_count {d}\n", .{ cum, sum_ns / ns_per_s, (sum_ns % ns_per_s) / 1000, cum });
        try w.print("# TYPE zui_gate_resolves_pending gauge\nzui_gate_resolves_pending {d}\n# TYPE zui_gate_waits counter\nzui_gate_waits {d}\n# TYPE zui_gate_wait_timeouts counter\nzui_gate_wait_timeouts {d}\n", .{ g.pend_n.load(.monotonic), m.waits.load(.monotonic), m.wait_timeouts.load(.monotonic) });
        try w.print("# TYPE zui_gate_cache_keys gauge\nzui_gate_cache_keys {d}\n# TYPE zui_gate_cache_addresses gauge\nzui_gate_cache_addresses {d}\n# TYPE zui_gate_cache_full counter\nzui_gate_cache_full {d}\n# TYPE zui_gate_address_overflow counter\nzui_gate_address_overflow {d}\n", .{ g.keys.used.load(.monotonic), g.ips.count(), m.cache_full.load(.monotonic), g.ips.overflowed.load(.monotonic) });
        try w.print("# TYPE zui_gate_denied_prefixes gauge\nzui_gate_denied_prefixes {d}\n# TYPE zui_gate_denies_applied counter\nzui_gate_denies_applied {d}\n", .{ g.ipdeny.n.load(.monotonic), m.denies_applied.load(.monotonic) });
        try w.print("# TYPE zui_gate_spool_bytes gauge\nzui_gate_spool_bytes {d}\n# TYPE zui_gate_spool_rows gauge\nzui_gate_spool_rows {d}\n# TYPE zui_gate_spool_merges counter\nzui_gate_spool_merges {d}\n# TYPE zui_gate_spool_dropped_rows counter\nzui_gate_spool_dropped_rows {d}\n# TYPE zui_gate_spool_collapsed_rows counter\nzui_gate_spool_collapsed_rows {d}\n# TYPE zui_gate_spool_write_errors counter\nzui_gate_spool_write_errors {d}\n", .{ m.spool_bytes.load(.monotonic), m.spool_rows.load(.monotonic), m.spool_merges.load(.monotonic), m.spool_dropped_rows.load(.monotonic), m.spool_collapsed_rows.load(.monotonic), m.spool_write_errors.load(.monotonic) });
        try w.print("# TYPE zui_gate_usage_batches_sent counter\nzui_gate_usage_batches_sent {d}\n# TYPE zui_gate_usage_batches_failed counter\nzui_gate_usage_batches_failed {d}\n# TYPE zui_gate_usage_rows_sent counter\nzui_gate_usage_rows_sent {d}\n# TYPE zui_gate_usage_lost_units counter\nzui_gate_usage_lost_units {d}\n", .{ m.batches_sent.load(.monotonic), m.batches_failed.load(.monotonic), m.rows_sent.load(.monotonic), g.meter.lost_units.load(.monotonic) });
        try w.print("# TYPE zui_gate_usage_batches_dead counter\nzui_gate_usage_batches_dead {d}\n# TYPE zui_gate_usage_rows_rejected counter\nzui_gate_usage_rows_rejected {d}\n", .{ m.batches_dead.load(.monotonic), m.rows_rejected.load(.monotonic) });
        try w.print("# TYPE zui_gate_free_tier_known gauge\nzui_gate_free_tier_known {d}\n# TYPE zui_gate_free_tier_errors counter\nzui_gate_free_tier_errors {d}\n# TYPE zui_gate_config_errors counter\nzui_gate_config_errors {d}\n# TYPE zui_gate_reachable gauge\nzui_gate_reachable {d}\n", .{ @intFromBool(g.free_known.load(.monotonic)), m.free_errors.load(.monotonic), m.config_errors.load(.monotonic), @intFromBool(g.reachable.load(.monotonic)) });
        // the forward multiplier the gate last gave (0 until it gave one), as it reads in the contract
        const fr = m.forward_milli_resolve.load(.monotonic);
        const ff = m.forward_milli_free.load(.monotonic);
        try w.print("# TYPE zui_gate_forward_weight_mult gauge\nzui_gate_forward_weight_mult{{answer=\"resolve\"}} {d}.{d:0>3}\nzui_gate_forward_weight_mult{{answer=\"free\"}} {d}.{d:0>3}\n", .{ fr / 1000, fr % 1000, ff / 1000, ff % 1000 });
    }
};
