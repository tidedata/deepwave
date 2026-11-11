//! Edge forwarding (docs/EDGE.md section 11): the sui.rpc.v2 handler of an edge with a core
//! upstream. Every client points at the edge; for each request `route.zig` says whether the edge
//! answers from its own store or passes the request to the core, and this file does it:
//!
//! - `Forwarder.handler()` wraps the node's own handler (`serve.service.Service.handler()`).
//! - A local answer is the node's own code path, written straight to the client: nothing is
//!   copied or buffered. The local handler runs with `serve.service.gap_watch` set, so an answer
//!   that would not be the core's (a missing batch item, an unknown signature order) ends before
//!   its first byte and the request is passed on instead.
//! - A forwarded call carries the same request bytes to the core over `Transport` and relays the
//!   response as it arrives: each message's bytes, then `grpc-status`, `grpc-message` and the
//!   status details exactly as the core sent them. The client's deadline goes along minus the
//!   time already spent; a client that leaves cancels the upstream call.
//! - `Transport` is the seam for a second way to the core (opaque sui.rpc.v2 calls on the zui/1
//!   connection): routing, relay, read-after-write and the guard do not know which one runs.
//! - Read-after-write (`ExecMode`, `Pending`): a successful ExecuteTransaction is held until the
//!   edge has applied the transaction's checkpoint (bounded), so the client's next read here
//!   sees it. The table of executed-but-not-applied digests is its own structure with the apply
//!   notification, so a later mode can answer at once and gate reads on it instead.
//! - The freshness guard (`route.Guard`) runs on `Forwarder.tick`: the node feeds it the edge's
//!   lag and how long its sources have been silent.
//! - Every finished call passes `Forwarder.meter` once, with its method, outcome, reason and
//!   caller: the metrics below are counted there, and a per-key meter can sit there too.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const serve = @import("serve");
const store = @import("store");
const rpc_exec = @import("rpc_exec");
const route = @import("route.zig");
const certs_mod = @import("certs.zig");
const h2 = serve.h2;
const service = serve.service;
const proto = serve.proto;
const grpc = rpc_exec.live.grpc_client;
const Upstream = rpc_exec.live.upstream.Upstream;
const log = std.log.scoped(.edge_forward);

pub const Method = route.Method;
pub const Reason = route.Reason;

// ---------------------------------------------------------------- upstream address

pub const UpstreamError = error{ BadUpstream, PlainNotLoopback, BadPin };

fn isLoopback(host: []const u8) bool {
    return std.mem.eql(u8, host, "localhost") or std.mem.startsWith(u8, host, "127.") or std.mem.eql(u8, host, "::1") or std.mem.eql(u8, host, "[::1]");
}

/// `--core-upstream`: the core's sui.rpc.v2 gRPC address, spelled as `--execute-epoch-from`
/// spells its own, with a pin added:
///
///   HOST:PORT              TLS, certificate checked against the system CAs and HOST (WebPKI);
///                          a loopback HOST without a suffix is cleartext h2c
///   HOST:PORT/pin=HEX      TLS, the core's leaf certificate must have this SHA-256 (64 hex
///                          digits: the value a core logs for `--serve-tls`); or `pin` from a flag
///   HOST:PORT/plain        cleartext h2c, said out loud (a private link, a test)
///
/// An optional `https://` or `http://` in front is accepted (`http://` means `/plain`). An edge
/// never relays answers it cannot authenticate by accident: cleartext to a host that is not
/// loopback happens only with the explicit `/plain` (or `http://`).
pub fn parseUpstream(text: []const u8, pin_flag: ?[]const u8) UpstreamError!grpc.Endpoint {
    var s = text;
    var plain = false;
    var tls = false;
    if (std.mem.startsWith(u8, s, "https://")) {
        s = s["https://".len..];
        tls = true;
    } else if (std.mem.startsWith(u8, s, "http://")) {
        s = s["http://".len..];
        plain = true;
    }
    var pin_text: ?[]const u8 = pin_flag;
    if (std.mem.indexOfScalar(u8, s, '/')) |slash| {
        const suffix = s[slash + 1 ..];
        s = s[0..slash];
        if (std.mem.eql(u8, suffix, "plain")) {
            plain = true;
        } else if (std.mem.startsWith(u8, suffix, "pin=")) {
            pin_text = suffix["pin=".len..];
        } else if (suffix.len != 0) return error.BadUpstream;
    }
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.BadUpstream;
    if (colon == 0) return error.BadUpstream;
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return error.BadUpstream;
    const host = s[0..colon];
    if (pin_text) |p| {
        if (plain) return error.BadPin; // a pin with cleartext is a mistake, not a choice
        var pin: [32]u8 = undefined;
        const hex = if (std.mem.startsWith(u8, p, "sha256:")) p["sha256:".len..] else p;
        if (hex.len != 64) return error.BadPin;
        _ = std.fmt.hexToBytes(&pin, hex) catch return error.BadPin;
        return .{ .host = host, .port = port, .security = .{ .pinned_cert = pin } };
    }
    if (plain and tls) return error.BadUpstream;
    if (plain) return .{ .host = host, .port = port, .security = .plain };
    if (!tls and isLoopback(host)) return .{ .host = host, .port = port, .security = .plain };
    return .{ .host = host, .port = port, .security = .ca };
}

// ---------------------------------------------------------------- transport seam

/// One call to the core as its caller sees it: response bytes as they arrive, then the end.
/// Owned by the relaying thread; a transport calls `onData` / `onDone` from its own threads and
/// never after `Transport.cancel` returned or after `onDone`.
pub const Call = struct {
    io: Io,
    gpa: Allocator,
    mu: Io.Mutex = .init,
    cond: Io.Condition = .init,
    /// gRPC frames received and not yet relayed (cut anywhere).
    buf: std.ArrayList(u8) = .empty,
    done: bool = false,
    code: u8 = 2,
    message: []u8 = &.{},
    details: []u8 = &.{},
    /// The end came from the way to the core, not from the core (no connection, a reset).
    transport_error: bool = false,
    oom: bool = false,
    // the transport's own state for this call
    slot: u32 = 0,
    conn: ?*anyopaque = null,

    pub fn deinit(c: *Call) void {
        c.buf.deinit(c.gpa);
        c.gpa.free(c.message);
        c.gpa.free(c.details);
    }

    pub fn onData(c: *Call, bytes: []const u8) void {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        c.buf.appendSlice(c.gpa, bytes) catch {
            c.oom = true;
        };
        c.cond.signal(c.io);
    }

    pub fn onDone(c: *Call, code: u8, message: []const u8, details: []const u8, transport_error: bool) void {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        if (c.done) return;
        c.code = code;
        c.message = c.gpa.dupe(u8, message) catch &.{};
        c.details = c.gpa.dupe(u8, details) catch &.{};
        c.transport_error = transport_error;
        c.done = true;
        c.cond.signal(c.io);
    }
};

pub const CallOpts = struct {
    /// Time left for the call (the client's `grpc-timeout` minus what the edge spent).
    timeout_ms: ?u64 = null,
    client_protocol_version: ?u64 = null,
};

/// A way to send one opaque sui.rpc.v2 call to the core. `start` never blocks on the network;
/// the response comes to `call`. `cancel` ends the call upstream and guarantees no callback
/// after it returns. `credit` gives back response bytes the caller has passed on (flow
/// control). `finish` releases what the transport holds for the call (after `onDone` or
/// `cancel`).
pub const Transport = struct {
    ctx: *anyopaque,
    vt: *const VTable,

    pub const VTable = struct {
        start: *const fn (ctx: *anyopaque, call: *Call, path: []const u8, body: []const u8, opts: CallOpts) void,
        cancel: *const fn (ctx: *anyopaque, call: *Call) void,
        credit: *const fn (ctx: *anyopaque, call: *Call, n: usize) void,
        finish: *const fn (ctx: *anyopaque, call: *Call) void,
    };
};

/// The gRPC transport: the node's existing h2 client (`rpc_exec.live.grpc_client`, the one
/// ExecuteTransaction and `--execute-epoch-from` use) over a reconnecting `Upstream`.
pub const GrpcTransport = struct {
    up: *Upstream,

    pub fn init(gpa: Allocator, io: Io, ep: grpc.Endpoint) !GrpcTransport {
        return .{ .up = try Upstream.init(gpa, io, ep) };
    }

    pub fn deinit(t: *GrpcTransport) void {
        t.up.deinit();
    }

    pub fn transport(t: *GrpcTransport) Transport {
        return .{ .ctx = t, .vt = &vtable };
    }

    const vtable: Transport.VTable = .{ .start = start, .cancel = cancel, .credit = credit, .finish = finish };

    fn start(ctx: *anyopaque, call: *Call, path: []const u8, body: []const u8, opts: CallOpts) void {
        const t: *GrpcTransport = @ptrCast(@alignCast(ctx));
        const c = t.up.acquire() orelse return call.onDone(14, "transport error: upstream connect failed", "", true);
        call.conn = c;
        c.startOpts(&call.slot, path, body, .{ .ctx = call, .done = sinkDone }, 0, .{
            .timeout_ms = opts.timeout_ms,
            .raw = .{ .on_data = sinkData },
            .client_protocol_version = opts.client_protocol_version,
        });
    }

    fn sinkData(ctx: *anyopaque, _: u64, bytes: []const u8) void {
        const call: *Call = @ptrCast(@alignCast(ctx));
        call.onData(bytes);
    }

    fn sinkDone(ctx: *anyopaque, _: u64, r: grpc.Result) void {
        const call: *Call = @ptrCast(@alignCast(ctx));
        switch (r) {
            .ok => call.onDone(13, "protocol error: decoded reply on a raw call", "", true),
            .status => |s| {
                // The client's own failures (no connection, GOAWAY, a reset stream, its caps)
                // have these texts and never details; the core's statuses come from trailers.
                const own = s.details.len == 0 and (std.mem.startsWith(u8, s.message, "transport error") or std.mem.startsWith(u8, s.message, "h2 protocol error"));
                call.onDone(s.code, s.message, s.details, own);
            },
        }
    }

    fn connOf(call: *Call) ?*grpc.Conn {
        return if (call.conn) |p| @ptrCast(@alignCast(p)) else null;
    }

    fn cancel(_: *anyopaque, call: *Call) void {
        if (connOf(call)) |c| c.cancel(&call.slot, 0);
    }

    fn credit(_: *anyopaque, call: *Call, n: usize) void {
        if (connOf(call)) |c| c.credit(&call.slot, n);
    }

    fn finish(_: *anyopaque, call: *Call) void {
        if (connOf(call)) |c| c.unref();
        call.conn = null;
    }
};

// ---------------------------------------------------------------- read-after-write

/// The mode, the table of executed-but-not-applied transactions and the write set (raw.zig).
pub const raw = @import("raw.zig");
pub const ExecMode = raw.ExecMode;
pub const Pending = raw.Pending;
pub const StopFn = raw.StopFn;
const slice_ns = raw.slice_ns;

// ---------------------------------------------------------------- metrics

/// Seconds buckets of the two histograms (forward latency, execute hold).
pub const buckets_s = [_]f64{ 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60 };
const bucket_le = [_][]const u8{ "0.001", "0.0025", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2", "5", "10", "30", "60" };
const bucket_ns = blk: {
    var out: [buckets_s.len]u64 = undefined;
    for (buckets_s, 0..) |b, i| out[i] = @intFromFloat(b * 1e9);
    break :blk out;
};

pub const Hist = struct {
    counts: [buckets_s.len]Atomic(u64) = @splat(.init(0)),
    sum_ns: Atomic(u64) = .init(0),
    n: Atomic(u64) = .init(0),

    pub fn observe(h: *Hist, ns: u64) void {
        for (bucket_ns, 0..) |b, i| if (ns <= b) {
            _ = h.counts[i].fetchAdd(1, .monotonic);
            break;
        };
        _ = h.sum_ns.fetchAdd(ns, .monotonic);
        _ = h.n.fetchAdd(1, .monotonic);
    }

    fn render(h: *const Hist, w: *Io.Writer, comptime name: []const u8, labels: []const u8) !void {
        var cum: u64 = 0;
        const sep: []const u8 = if (labels.len > 0) "," else "";
        for (bucket_le, 0..) |le, i| {
            cum += h.counts[i].load(.monotonic);
            try w.print(name ++ "_bucket{{{s}{s}le=\"{s}\"}} {d}\n", .{ labels, sep, le, cum });
        }
        const total = h.n.load(.monotonic);
        try w.print(name ++ "_bucket{{{s}{s}le=\"+Inf\"}} {d}\n", .{ labels, sep, total });
        if (labels.len > 0) {
            try w.print(name ++ "_sum{{{s}}} {d:.6}\n" ++ name ++ "_count{{{s}}} {d}\n", .{ labels, @as(f64, @floatFromInt(h.sum_ns.load(.monotonic))) / 1e9, labels, total });
        } else {
            try w.print(name ++ "_sum {d:.6}\n" ++ name ++ "_count {d}\n", .{ @as(f64, @floatFromInt(h.sum_ns.load(.monotonic))) / 1e9, total });
        }
    }
};

pub const PerMethod = struct {
    served_local: Atomic(u64) = .init(0),
    forwarded: [Reason.count]Atomic(u64) = @splat(.init(0)),
    upstream_errors: Atomic(u64) = .init(0),
    denied: Atomic(u64) = .init(0),
    forward_latency: Hist = .{},
};

pub const Metrics = struct {
    methods: [Method.count]PerMethod = @splat(.{}),
    guard_trips: Atomic(u64) = .init(0),
    guard_recoveries: Atomic(u64) = .init(0),
    /// Current lag in checkpoints (`lag_unknown` while the edge cannot tell).
    lag: Atomic(u64) = .init(lag_unknown),
    execute_hold: Hist = .{},
    execute_hold_timeouts: Atomic(u64) = .init(0),
    /// `reads`: executes recorded with their write set; executes held instead (no effects to
    /// read, or the table was full); reads that waited (and for how long), reads passed to the
    /// core because the wait was over or too many were waiting.
    raw_recorded: Atomic(u64) = .init(0),
    raw_held_instead: Atomic(u64) = .init(0),
    raw_read_wait: Hist = .{},
    raw_reads_late: Atomic(u64) = .init(0),
    raw_reads_over_limit: Atomic(u64) = .init(0),
    raw_strip_failures: Atomic(u64) = .init(0),
    streams_closed: Atomic(u64) = .init(0),

    pub const lag_unknown = std.math.maxInt(u64);

    pub fn forwardedTotal(m: *const Metrics, method: Method) u64 {
        var n: u64 = 0;
        for (&m.methods[@intFromEnum(method)].forwarded) |*c| n += c.load(.monotonic);
        return n;
    }
};

pub const Outcome = enum { local, forwarded, denied };

/// One finished call, as the meter sees it.
pub const Metered = struct {
    method: Method,
    outcome: Outcome,
    /// Why it was forwarded (meaningful for `.forwarded`).
    reason: Reason = .other,
    /// gRPC status the client got.
    code: u8,
    caller: route.Caller,
    elapsed_ns: u64,
    /// Time spent on the core's answer (0 for a local call).
    upstream_ns: u64 = 0,
    /// The way to the core failed (not the core's own status).
    upstream_error: bool = false,
};

/// A second meter beside the built-in counters (per-key accounting, later).
pub const MeterHook = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, m: *const Metered) void,
};

// ---------------------------------------------------------------- the forwarder

pub const Config = struct {
    /// `--edge-ahead-wait-ms`: how long a request naming a checkpoint or an object version
    /// ahead of the edge waits for the follower before it is passed on.
    ahead_wait_ms: u32 = 300,
    /// `--edge-execute-wait-ms`: the read-after-write bound (0: off).
    execute_wait_ms: u32 = 2000,
    /// `--edge-max-lag`.
    max_lag: u64 = 5,
    /// A source silent for this long trips the guard.
    stale_ms: u32 = 3000,
    /// The guard recovers after this long within half the limit.
    hold_ms: u32 = 500,
    /// How often the core's lowest available checkpoint is read (GetServiceInfo).
    floor_refresh_ms: u32 = 5000,
    /// Tick period when no commit wakes the tick earlier.
    tick_ms: u32 = 100,
    /// `--edge-raw`: what read-after-write does (`execute_wait_ms` 0 turns it off whatever this says).
    raw: ExecMode = .reads,
    /// `reads`: a transaction the edge has not applied after this long leaves the table (it
    /// never landed, or the edge is far behind and the guard has it); no read waits or is
    /// passed on for it afterwards.
    raw_expiry_ms: u32 = 30_000,
    /// `reads`: reads waiting at once. A waiting read keeps its serve worker (the serve path
    /// has no way to park a unary call), so the bound keeps the pool free for everything else:
    /// past it a read that would wait is passed to the core instead. The node sets it from the
    /// worker pool's size.
    raw_max_waiters: u32 = 8,
    /// `reads`: bounds of the table (transactions, and object ids plus addresses over all of
    /// them). A new execute that does not fit is held instead.
    raw_max_entries: u32 = 4096,
    raw_max_keys: u32 = 1 << 16,

    pub fn execMode(c: *const Config) ExecMode {
        return if (c.execute_wait_ms == 0) .off else c.raw;
    }
};

/// What the node tells the guard about its sources.
pub const SourceView = struct {
    ctx: *anyopaque,
    /// The newest checkpoint known to exist at the edge's sources (null: unknown, as in
    /// catch-up, when the fetcher has not met the tip yet).
    known_tip: *const fn (ctx: *anyopaque) ?u64,
    /// Nanoseconds since a source last answered a request for the tip.
    silent_ns: *const fn (ctx: *anyopaque) u64,
    /// The edge takes its checkpoints from its fallback now (null: it has none): the ones to
    /// come carry certificates that are not the core's.
    on_fallback: ?*const fn (ctx: *anyopaque) bool = null,
};

const floor_unknown = std.math.maxInt(u64);
const path_service_info = "/sui.rpc.v2.LedgerService/GetServiceInfo";

pub const Forwarder = struct {
    gpa: Allocator,
    io: Io,
    svc: *service.Service,
    /// The node's own handler: local answers, and everything a transport front asks about a
    /// path (known, compress, bidi, health).
    inner: h2.Handler,
    transport: Transport,
    cfg: Config,
    source: ?SourceView = null,
    guard: route.Guard,
    guard_mu: Io.Mutex = .init,
    /// `route.GuardState` for request threads (one load).
    guard_state: Atomic(u8) = .init(@intFromEnum(route.GuardState.tripped)),
    pending: Pending,
    metrics: Metrics = .{},
    meter_hook: ?MeterHook = null,
    /// The core's lowest available checkpoint (`floor_unknown` until first read).
    core_floor: Atomic(u64) = .init(floor_unknown),
    floor_ev: Atomic(u32) = .init(0),
    floor_thread: ?std.Thread = null,
    /// Reads waiting on `pending` now (`Config.raw_max_waiters`).
    raw_waiters: Atomic(u32) = .init(0),
    stop_flag: Atomic(bool) = .init(false),
    /// The server drains (`endStreams`): forwarded streams end, the rest goes on.
    streams_stop: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    /// Tests: called at the end of every tick.
    on_tick: ?*const fn (f: *Forwarder) void = null,
    /// The checkpoints whose certificate is not the core's yet (`setCerts`; null: none are
    /// tracked, and no read is passed on for a certificate).
    certs: ?*certs_mod.Certs = null,
    /// `upstreamDown`. Set and cleared by every call's end (`Relay.run`).
    upstream_down: Atomic(bool) = .init(false),

    /// A stream that renders certificates is started locally only when the newest marked
    /// checkpoint is more than this many checkpoints behind the edge's tip (and the edge is
    /// not on its fallback): around a switch the sources interleave for a few checkpoints.
    pub const foreign_hold: u64 = 8;

    /// Gives the forwarder the edge's marked checkpoints: from here on GetCheckpoint and
    /// SubscribeCheckpoints with `signature` in their mask go to the core for a marked
    /// checkpoint (route.zig `foreign_cert`), and the local handler says so when it meets one.
    pub fn setCerts(f: *Forwarder, c: *certs_mod.Certs) void {
        f.certs = c;
        f.svc.foreign_cert = .{ .ctx = f, .state = certState, .served_held = certServedHeld };
    }

    /// `service.ForeignCert`: a marked certificate is the core's to answer while the core can
    /// be reached, and the edge's own (the one it holds, which verifies) while it cannot:
    /// surviving a core outage is what the fallback is for.
    fn certState(ctx: *anyopaque, seq: u64) service.CertState {
        const f = of(ctx);
        const c = f.certs orelse return .core;
        if (!c.isMarked(seq)) return .core;
        return if (f.upstreamDown()) .held else .withhold;
    }

    fn certServedHeld(ctx: *anyopaque) void {
        if (of(ctx).certs) |c| c.noteHeld(.grpc);
    }

    /// The way to the core is known to be down: the last call on it ended in a connection-class
    /// failure (no connection, a reset; never the core's own status) and none has been answered
    /// since. Any answer of the core clears it, and while it is set the floor thread asks the
    /// core every second, so forwards resume within about a second of the core's return. No
    /// request probes for it.
    pub fn upstreamDown(f: *const Forwarder) bool {
        return f.upstream_down.load(.acquire);
    }

    /// The edge is in a foreign period at its tip (`route.Facts.foreign` for a stream).
    fn foreignPeriod(f: *Forwarder) bool {
        const c = f.certs orelse return false;
        if (f.source) |src| if (src.on_fallback) |fb| if (fb(src.ctx)) return true;
        return c.recentAt(f.tip() orelse return false, foreign_hold);
    }

    pub fn create(gpa: Allocator, io: Io, svc: *service.Service, transport: Transport, cfg: Config) !*Forwarder {
        const f = try gpa.create(Forwarder);
        f.* = .{
            .gpa = gpa,
            .io = io,
            .svc = svc,
            .inner = svc.handler(),
            .transport = transport,
            .cfg = cfg,
            .guard = .{ .max_lag = cfg.max_lag, .hold_ns = @as(u64, cfg.hold_ms) * std.time.ns_per_ms, .stale_ns = @as(u64, cfg.stale_ms) * std.time.ns_per_ms },
            .pending = .{ .gpa = gpa, .io = io, .ttl_ns = @as(u64, cfg.raw_expiry_ms) * std.time.ns_per_ms, .max = cfg.raw_max_entries, .max_keys = cfg.raw_max_keys },
        };
        svc.reported_lowest = &f.core_floor;
        return f;
    }

    /// Starts the tick thread (guard, pending digests) and the thread that reads the core's
    /// floor (its own: a core that does not answer must not hold up the guard).
    pub fn start(f: *Forwarder) !void {
        f.thread = try std.Thread.spawn(.{}, tickLoop, .{f});
        f.floor_thread = try std.Thread.spawn(.{}, floorLoop, .{f});
    }

    /// The node's server stops taking calls and drains (node.zig `gracefulStop`): the forwarded
    /// streams end now, as the local ones do (`Hub.stop`). A stream does not end by itself, so
    /// one left open held the drain for all of `--drain-ms`. Unary calls in flight finish under
    /// the drain, and the tick and the floor thread go on until `stop`: answers stay routed as
    /// before while the follower still applies.
    pub fn endStreams(f: *Forwarder) void {
        f.streams_stop.store(true, .release);
    }

    fn streamsEnding(f: *const Forwarder) bool {
        return f.streams_stop.load(.acquire) or f.stop_flag.load(.acquire);
    }

    /// Tells the tick, the floor thread (a call to the core in flight is cancelled at its next
    /// slice) and the forwarded streams to end, without waiting for any of them. The node calls
    /// it before the first join of its shutdown, so `stop` finds the threads gone.
    pub fn requestStop(f: *Forwarder) void {
        f.stop_flag.store(true, .release);
        f.pending.applied(); // wakes the tick
        _ = f.floor_ev.fetchAdd(1, .release);
        f.io.futexWake(u32, &f.floor_ev.raw, std.math.maxInt(u32));
    }

    pub fn stop(f: *Forwarder) void {
        f.requestStop();
        if (f.thread) |t| t.join();
        f.thread = null;
        if (f.floor_thread) |t| t.join();
        f.floor_thread = null;
    }

    fn floorLoop(f: *Forwarder) void {
        while (!f.stop_flag.load(.acquire)) {
            const seen = f.floor_ev.load(.acquire);
            f.refreshFloor(h2.meta.monoNs());
            if (f.stop_flag.load(.acquire)) break;
            // until the first answer: every second
            // (and while the way to the core is down: this is what notices its return)
            const ms: u32 = if (f.core_floor.load(.monotonic) == floor_unknown or f.upstreamDown()) @min(1000, f.cfg.floor_refresh_ms) else f.cfg.floor_refresh_ms;
            f.io.futexWaitTimeout(u32, &f.floor_ev.raw, seen, .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(ms), .clock = .awake } }) catch {};
        }
    }

    pub fn destroy(f: *Forwarder) void {
        f.stop();
        if (f.svc.reported_lowest == &f.core_floor) f.svc.reported_lowest = null;
        if (f.certs != null) f.svc.foreign_cert = null;
        f.pending.deinit();
        f.gpa.destroy(f);
    }

    /// The follower committed checkpoint(s): wakes the tick and everything waiting on the tip.
    pub fn noteApplied(f: *Forwarder) void {
        f.pending.applied();
    }

    pub fn guardState(f: *const Forwarder) route.GuardState {
        return @enumFromInt(f.guard_state.load(.acquire));
    }

    pub fn handler(f: *Forwarder) h2.Handler {
        return .{ .ctx = f, .call = call, .bidi = hBidi, .known = hKnown, .method = hMethod, .compress = hCompress, .info = hInfo, .health = hHealth };
    }

    fn of(ctx: *anyopaque) *Forwarder {
        return @ptrCast(@alignCast(ctx));
    }
    fn hBidi(ctx: *anyopaque, path: []const u8) bool {
        return of(ctx).inner.isBidi(path);
    }
    fn hKnown(ctx: *anyopaque, path: []const u8) bool {
        return of(ctx).inner.isKnown(path);
    }
    fn hMethod(ctx: *anyopaque, path: []const u8) bool {
        return of(ctx).inner.methodExists(path);
    }
    fn hCompress(ctx: *anyopaque, path: []const u8) bool {
        return of(ctx).inner.compresses(path);
    }
    fn hInfo(ctx: *anyopaque, out: *h2.meta.Info) void {
        // the node's own tip; its lowest is the core's once known (`Service.reported_lowest`)
        _ = of(ctx).inner.getInfo(out);
    }
    fn hHealth(ctx: *anyopaque, threshold_s: ?u32) bool {
        const f = of(ctx);
        return if (f.inner.health) |h| h(f.inner.ctx, threshold_s) else true;
    }

    // ------------------------------------------------------------ state

    fn tip(f: *const Forwarder) ?u64 {
        return service.boundByIndex(f.svc, f.svc.store.committed() orelse return null);
    }

    pub fn state(f: *const Forwarder) route.State {
        return .{ .forwarding = true, .guard = f.guardState(), .tip = f.tip(), .floor = service.lowestOf(f.svc) };
    }

    /// One pass of the background work: the guard, the pending digests, the core's floor.
    /// The tick thread calls it after every commit and at least every `tick_ms`; tests call it.
    pub fn tick(f: *Forwarder) void {
        const now = h2.meta.monoNs();
        if (f.source) |src| {
            const known = src.known_tip(src.ctx);
            const lag: ?u64 = if (known) |k| k -| (f.tip() orelse 0) else null;
            f.metrics.lag.store(lag orelse Metrics.lag_unknown, .monotonic);
            f.observe(now, .{ .lag = if (f.tip() == null) null else lag, .source_age_ns = src.silent_ns(src.ctx) });
        }
        _ = f.pending.resolve(now, .{ .ctx = f, .f = isApplied });
        if (f.on_tick) |cb| cb(f);
    }

    /// Feeds the guard one observation (the tick does; tests drive it directly).
    pub fn observe(f: *Forwarder, now_ns: u64, o: route.Guard.Obs) void {
        f.guard_mu.lockUncancelable(f.io);
        const change = f.guard.update(now_ns, o);
        f.guard_state.store(@intFromEnum(f.guard.state), .release);
        f.guard_mu.unlock(f.io);
        switch (change) {
            .none => {},
            .tripped => {
                _ = f.metrics.guard_trips.fetchAdd(1, .monotonic);
                // local streams end UNAVAILABLE: their clients reconnect and are forwarded
                const closed = if (f.svc.hub) |hub| hub.endAllUnavailable(guard_stream_text) else 0;
                _ = f.metrics.streams_closed.fetchAdd(closed, .monotonic);
                log.warn("freshness guard tripped (lag {?d} checkpoints, sources silent {d} ms): forwarding everything to the core; {d} local streams closed", .{ o.lag, o.source_age_ns / std.time.ns_per_ms, closed });
            },
            .recovered => {
                _ = f.metrics.guard_recoveries.fetchAdd(1, .monotonic);
                log.info("freshness guard recovered (lag {?d} checkpoints): serving locally again", .{o.lag});
            },
        }
    }

    pub const guard_stream_text = "edge is behind its core; reconnect";

    fn tickLoop(f: *Forwarder) void {
        while (!f.stop_flag.load(.acquire)) {
            const seen = f.pending.commits.load(.acquire);
            f.tick();
            if (f.stop_flag.load(.acquire)) break;
            f.io.futexWaitTimeout(u32, &f.pending.commits.raw, seen, .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(f.cfg.tick_ms), .clock = .awake } }) catch {};
        }
    }

    fn isApplied(ctx: *anyopaque, digest: *const [32]u8) bool {
        const f = of(ctx);
        var snap = f.svc.store.snapshot();
        defer snap.release();
        const rec = snap.transaction(digest) orelse return false;
        const t = service.latestOf(f.svc, &snap) orelse return false;
        return rec.checkpoint <= t;
    }

    /// Reads the core's lowest available checkpoint (GetServiceInfo field 6) over the transport.
    pub fn refreshFloor(f: *Forwarder, now: u64) void {
        var cap: Capture = .{ .gpa = f.gpa };
        defer cap.deinit();
        var rs = cap.stream(.identity);
        defer rs.release();
        var r: Relay = .{ .f = f, .deadline_ns = now + 2 * std.time.ns_per_s, .stop = .{ .ctx = f, .f = stopping } };
        const st = r.run(path_service_info, "", &rs);
        if (st != .ok) return;
        var it = cap.frames();
        const frame = it.next() orelse return;
        var rd = proto.Reader.init(frame.payload);
        while (rd.next() catch return) |fld| if (fld.number == 6) {
            f.core_floor.store(proto.Reader.varintOf(fld) catch return, .release);
            return;
        };
        f.core_floor.store(0, .release); // proto3: an absent field is 0
    }

    fn stopping(ctx: *anyopaque) bool {
        return of(ctx).stop_flag.load(.acquire);
    }

    // ------------------------------------------------------------ one request

    fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const f = of(ctx);
        const method = route.methodOf(req.path);
        if (method == .own) return f.inner.call(f.inner.ctx, req, rs);
        const t0 = h2.meta.monoNs();
        // the read mask's paths (slices into the request) live on the stack: no allocation on
        // the way to a local answer. A mask with more paths than fit is passed on (`scan`).
        var scratch: [2048]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch);
        var facts = f.scan(fba.allocator(), method, req);
        var st = f.state();
        var d = route.decide(&facts, &st);
        if (d == .wait) {
            const caught = f.waitFor(d.wait, &facts, req, rs);
            st = f.state();
            d = route.afterWait(&facts, &st, caught);
        }
        // read-after-write: a read of what a transaction executed through this edge wrote, while
        // the edge has not applied it. One load while nothing is pending.
        if (!f.pending.idle() and d == .local) {
            if (!f.pendingGate(method, req, rs)) d = .{ .forward = .ahead };
        }
        var m: Metered = .{ .method = method, .outcome = .local, .code = 0, .caller = facts.caller, .elapsed_ns = 0 };
        const status: h2.Status = sw: switch (d) {
            .wait => unreachable,
            .deny => |x| {
                m.outcome = .denied;
                rs.setMessage(x.message);
                break :sw @enumFromInt(x.code);
            },
            .local => {
                const local = f.runLocal(&facts, req, rs);
                if (local.status == .deferred or local.status == .held) break :sw local.status;
                const why = route.afterLocal(&facts, &st, .{ .code = @intFromEnum(local.status), .has_details = rs.details_bin.len > 0, .gap = local.gap }) orelse break :sw local.status;
                // nothing of the local answer may have left (a local handler writes its one
                // message last; a gap ends it before that)
                if (rs.messages != 0) break :sw local.status;
                resetStatus(rs);
                break :sw f.forwardCert(method, why, &facts, req, rs, &m);
            },
            .forward => |why| f.forwardCert(method, why, &facts, req, rs, &m),
        };
        m.code = switch (status) {
            .deferred, .held => 0,
            else => @intFromEnum(status),
        };
        m.elapsed_ns = h2.meta.monoNs() -| t0;
        f.meter(&m);
        return status;
    }

    fn resetStatus(rs: *h2.ResponseStream) void {
        rs.release();
        rs.msg = "";
        rs.details_bin = "";
    }

    /// The one place every routed call passes when it is over (a forwarded stream: when its
    /// relay starts; its bytes are the relay's business).
    pub fn meter(f: *Forwarder, m: *const Metered) void {
        const pm = &f.metrics.methods[@intFromEnum(m.method)];
        switch (m.outcome) {
            .local => _ = pm.served_local.fetchAdd(1, .monotonic),
            .forwarded => {
                _ = pm.forwarded[@intFromEnum(m.reason)].fetchAdd(1, .monotonic);
                if (m.upstream_ns != 0) pm.forward_latency.observe(m.upstream_ns); // (a stream's relay has none)
                if (m.upstream_error) _ = pm.upstream_errors.fetchAdd(1, .monotonic);
            },
            .denied => _ = pm.denied.fetchAdd(1, .monotonic),
        }
        if (f.meter_hook) |hk| hk.f(hk.ctx, m);
    }

    /// `forward`. A read passed on for a marked checkpoint's certificate (`foreign_cert`) whose
    /// way to the core fails before any byte (a connection-class failure: the core's own
    /// errors are its answer and go out as they are) is answered here after all, with the
    /// certificate the edge holds: it is valid, and no core can be asked. `upstream_down` is
    /// set by then, so the handler renders it (`certState`) and the next such read does not
    /// try the core first.
    fn forwardCert(f: *Forwarder, method: Method, why: Reason, facts: *const route.Facts, req: *const h2.Request, rs: *h2.ResponseStream, m: *Metered) h2.Status {
        const st = f.forward(method, why, req, rs, m);
        if (why != .foreign_cert or !m.upstream_error or rs.messages != 0 or st == .deferred or st == .held) return st;
        resetStatus(rs);
        const local = f.runLocal(facts, req, rs);
        if (local.gap == .none) {
            m.outcome = .local;
            return local.status;
        }
        // the core came back meanwhile (or the answer met another gap): the failed call stands
        if (rs.messages == 0) resetStatus(rs);
        rs.setMessage("edge: core upstream unavailable");
        return .unavailable;
    }

    const Local = struct { status: h2.Status, gap: route.Gap };

    fn runLocal(f: *Forwarder, facts: *const route.Facts, req: *const h2.Request, rs: *h2.ResponseStream) Local {
        service.gap = .none;
        service.gap_watch = true;
        service.gap_sigs = facts.needs.signatures;
        service.gap_cert = facts.needs.cert;
        defer {
            service.gap_watch = false;
            service.gap_sigs = false;
            service.gap_cert = false;
        }
        const st = f.inner.call(f.inner.ctx, req, rs);
        return .{ .status = st, .gap = @enumFromInt(@intFromEnum(service.gap)) };
    }

    /// The request as `route.decide` wants it. Anything that does not scan is `malformed`: the
    /// local handler then gives its own decode error.
    fn scan(f: *Forwarder, arena: Allocator, method: Method, req: *const h2.Request) route.Facts {
        var facts: route.Facts = .{ .method = method, .caller = .{ .api_key = req.api_key, .peer = req.peer } };
        f.scanInto(arena, &facts, req.body) catch |e| switch (e) {
            // too many mask paths to look at: whatever they select, the core answers
            error.OutOfMemory => facts.needs = .{ .object_set = true, .signatures = true },
            else => facts.malformed = true,
        };
        return facts;
    }

    fn maskPaths(arena: Allocator, list: *?std.ArrayList([]const u8), field: proto.Reader.Field) !void {
        if (list.* == null) list.* = .empty;
        var r = proto.Reader.init(try proto.Reader.bytesOf(field));
        while (try r.next()) |p| if (p.number == 1) try list.*.?.append(arena, try proto.Reader.stringOf(p));
    }

    fn scanInto(f: *Forwarder, arena: Allocator, facts: *route.Facts, body: []const u8) !void {
        var paths: ?std.ArrayList([]const u8) = null;
        var r = proto.Reader.init(body);
        switch (facts.method) {
            .get_service_info => facts.info_ready = f.core_floor.load(.acquire) != floor_unknown,
            .get_object => {
                var id_text: ?[]const u8 = null;
                while (try r.next()) |fld| switch (fld.number) {
                    1 => id_text = try proto.Reader.stringOf(fld),
                    2 => facts.version = try proto.Reader.varintOf(fld),
                    else => {},
                };
                if (facts.version != null) {
                    // an id that does not parse gets the local handler's INVALID_ARGUMENT
                    const id = service.parseObjectId(id_text orelse return error.Malformed) orelse return error.Malformed;
                    var snap = f.svc.store.snapshot();
                    defer snap.release();
                    if (snap.liveObject(&id)) |o| facts.live_version = o.version;
                }
            },
            .get_transaction, .batch_get_transactions => {
                while (try r.next()) |fld| if (fld.number == 2) try maskPaths(arena, &paths, fld);
                facts.by_digest = true;
                facts.needs = route.maskNeeds(.transaction, if (paths) |p| p.items else null);
            },
            .get_checkpoint => {
                var digest_text: []const u8 = "";
                while (try r.next()) |fld| switch (fld.number) {
                    1 => {
                        facts.seq = try proto.Reader.varintOf(fld);
                        facts.by_digest = false;
                    },
                    2 => {
                        digest_text = try proto.Reader.stringOf(fld);
                        facts.by_digest = true;
                        facts.seq = null;
                    },
                    3 => try maskPaths(arena, &paths, fld),
                    else => {},
                };
                facts.needs = route.maskNeeds(.checkpoint, if (paths) |p| p.items else null);
                // the certificate of the checkpoint this names: is it the core's?
                if (facts.needs.cert) if (f.certs) |c| if (c.pending() != 0) {
                    const named: ?u64 = if (facts.seq) |s| s else if (facts.by_digest) by: {
                        const dg = serve.b58.decode32(digest_text) orelse break :by null;
                        var snap = f.svc.store.snapshot();
                        defer snap.release();
                        break :by snap.checkpointByDigest(&dg);
                    } else f.tip();
                    // (with no way to the core the edge answers with what it holds)
                    if (named) |s| facts.foreign = c.isMarked(s) and !f.upstreamDown();
                };
            },
            .subscribe_checkpoints => {
                while (try r.next()) |fld| if (fld.number == 1) try maskPaths(arena, &paths, fld);
                facts.needs = route.maskNeeds(.checkpoint, if (paths) |p| p.items else null);
                if (facts.needs.cert) facts.foreign = f.foreignPeriod() and !f.upstreamDown();
            },
            .get_epoch => {
                while (try r.next()) |fld| if (fld.number == 1) {
                    facts.epoch = try proto.Reader.varintOf(fld);
                };
                var snap = f.svc.store.snapshot();
                defer snap.release();
                const live = serve.rpcindex.liveState(&snap) orelse return;
                const cur = (serve.sysstate.summary(live) catch return).epoch;
                facts.current_epoch = cur;
                const e = facts.epoch orelse cur;
                const x = f.svc.rpc orelse return;
                const tok = x.enter();
                defer x.exit(tok);
                const rec = x.epoch(e) orelse return;
                const start_rec = rec.start orelse return;
                facts.epoch_complete = start_rec.start_checkpoint != null and (e == cur or rec.end != null);
            },
            .get_package => {
                while (try r.next()) |fld| if (fld.number == 2 or fld.number == 3) {
                    facts.selector = true;
                };
            },
            else => {},
        }
    }

    /// Waits (bounded by `ahead_wait_ms`, the request's deadline and its client) for the edge
    /// to reach what the request named. Sleeps on the commit word; no polling.
    fn waitFor(f: *Forwarder, w: route.Wait, facts: *route.Facts, req: *const h2.Request, rs: *h2.ResponseStream) bool {
        const t0 = h2.meta.monoNs();
        var limit = @as(u64, f.cfg.ahead_wait_ms) * std.time.ns_per_ms;
        if (req.deadline_ns) |dl| limit = @min(limit, dl -| t0);
        var id: [32]u8 = undefined;
        if (w == .version) {
            var r = proto.Reader.init(req.body);
            var text: []const u8 = "";
            while (r.next() catch return false) |fld| if (fld.number == 1) {
                text = proto.Reader.stringOf(fld) catch return false;
            };
            id = service.parseObjectId(text) orelse return false;
        }
        while (true) {
            const seen = f.pending.commits.load(.acquire);
            switch (w) {
                .checkpoint => |seq| if (f.tip()) |t| if (t >= seq) return true,
                .version => |v| {
                    var snap = f.svc.store.snapshot();
                    defer snap.release();
                    if (snap.liveObject(&id)) |o| {
                        facts.live_version = o.version;
                        if (o.version >= v) return true;
                    }
                },
            }
            const spent = h2.meta.monoNs() -| t0;
            if (spent >= limit or rs.cancelled() or f.guardState() == .tripped) return false;
            const left = @min(limit - spent, slice_ns);
            f.io.futexWaitTimeout(u32, &f.pending.commits.raw, seen, .{ .duration = .{ .raw = Io.Duration.fromNanoseconds(@intCast(left)), .clock = .awake } }) catch {};
        }
    }

    // ------------------------------------------------------------ forwarding

    fn forward(f: *Forwarder, method: Method, why: Reason, req: *const h2.Request, rs: *h2.ResponseStream, m: *Metered) h2.Status {
        m.outcome = .forwarded;
        m.reason = why;
        if (method.streams() and h2.streaming()) {
            // a server stream outlives this call: its relay runs on a pump
            const p = StreamRelay.create(f, req) catch {
                rs.setMessage("out of memory");
                return .resource_exhausted;
            };
            if (h2.attach(req.stream_id, p.pump())) return .deferred;
            StreamRelay.destroy(p);
        }
        const t0 = h2.meta.monoNs();
        var relay: Relay = .{ .f = f, .deadline_ns = req.deadline_ns, .stop = .{ .ctx = rs, .f = rsCancelled }, .client_protocol_version = req.client_protocol_version };
        const status = if (method == .execute_transaction and f.cfg.execMode() != .off)
            f.executeRaw(&relay, req, rs)
        else
            relay.run(req.path, req.body, rs);
        m.upstream_ns = h2.meta.monoNs() -| t0;
        m.upstream_error = relay.transport_error;
        return status;
    }

    fn rsCancelled(ctx: *anyopaque) bool {
        const rs: *h2.ResponseStream = @ptrCast(@alignCast(ctx));
        return rs.cancelled();
    }

    /// ExecuteTransaction with read-after-write. The core's answer is taken whole.
    /// `reads`: a success is recorded in `pending` with what it wrote (from `effects.bcs` in the
    /// answer; the edge adds that path to the core's request when the client's mask lacks it and
    /// takes the field out again) and goes out at once. `hold`, and `reads` whenever the write
    /// set cannot be had or the table is full: a success is held until the edge has applied
    /// the transaction, at most `execute_wait_ms`. A failed execute is never held or recorded.
    fn executeRaw(f: *Forwarder, relay: *Relay, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        var arena_state = std.heap.ArenaAllocator.init(f.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var cap: Capture = .{ .gpa = f.gpa };
        defer cap.deinit();
        var crs = cap.stream(.identity);
        defer crs.release();
        const mode = f.cfg.execMode();
        var body = req.body;
        var use: raw.MaskUse = .{ .has_bcs = true, .any_effects = true };
        var added = false;
        if (mode == .reads) {
            use = raw.maskUse(req.body);
            if (!use.has_bcs) if (raw.withEffectsBcs(arena, req.body) catch null) |more| {
                body = more;
                added = true;
            };
        }
        const status = relay.run(req.path, body, &crs);
        var it = cap.frames();
        const first: ?Capture.Frame = it.next();
        const single = first != null and it.next() == null and !first.?.compressed;
        if (status == .ok) raw_done: {
            const t0 = h2.meta.monoNs();
            const digest = executedDigest(req.body, &cap) orelse break :raw_done;
            const wait_ns = @as(u64, f.cfg.execute_wait_ms) * std.time.ns_per_ms;
            if (mode == .reads and single) recorded: {
                const eff = raw.nested(first.?.payload, &.{ 1, 4, 1, 2 }) orelse break :recorded;
                const w = raw.writesOf(arena, eff, raw.nested(req.body, &.{ 1, 1, 2 })) catch break :recorded;
                // applied before the answer came back: nothing is pending
                if (!isApplied(f, &digest)) {
                    if (!f.pending.addWrites(&digest, t0, t0 + wait_ns, w)) break :recorded;
                    // (it may have been applied between the look and the add: the tick drops it)
                }
                _ = f.metrics.raw_recorded.fetchAdd(1, .monotonic);
                break :raw_done;
            }
            if (mode == .reads) _ = f.metrics.raw_held_instead.fetchAdd(1, .monotonic);
            f.pending.add(&digest, t0);
            if (isApplied(f, &digest)) f.pending.remove(&digest);
            var limit = wait_ns;
            if (req.deadline_ns) |dl| limit = @min(limit, dl -| t0);
            // a table too full for the digest: the store is asked at every commit instead
            var hold_stop: GateStop = .{ .fwd = f, .rs = rs, .deadline_ns = null };
            const done = if (f.pending.contains(&digest) or isApplied(f, &digest))
                f.pending.wait(&digest, limit, .{ .ctx = &hold_stop, .f = GateStop.f })
            else
                f.waitApplied(&digest, limit, rs);
            f.metrics.execute_hold.observe(h2.meta.monoNs() -| t0);
            if (!done) _ = f.metrics.execute_hold_timeouts.fetchAdd(1, .monotonic);
        }
        // the answer: as the core sent it, less the field the edge asked for on its own account
        if (added and status == .ok and single) {
            if (raw.stripEffectsBcs(arena, first.?.payload, use.any_effects)) |clean| {
                rs.message(clean) catch return .cancelled;
            } else |_| {
                _ = f.metrics.raw_strip_failures.fetchAdd(1, .monotonic);
                rs.message(first.?.payload) catch return .cancelled;
            }
        } else {
            var again = cap.frames();
            while (again.next()) |fr| rs.message(fr.payload) catch return .cancelled;
        }
        if (crs.msg.len > 0) rs.setMessage(crs.msg);
        if (crs.details_bin.len > 0) rs.details(crs.details_bin);
        return status;
    }

    /// Waits for the edge to serve transaction `digest` without a table entry (the table was
    /// full): looks at the store after every commit. True once applied. Ends at the forwarder's
    /// stop (`requestStop` wakes the commit word), before another look at the store.
    fn waitApplied(f: *Forwarder, digest: *const [32]u8, limit_ns: u64, rs: *h2.ResponseStream) bool {
        const t0 = h2.meta.monoNs();
        while (true) {
            const seen = f.pending.commits.load(.acquire);
            if (f.stop_flag.load(.acquire)) return false;
            if (isApplied(f, digest)) return true;
            const spent = h2.meta.monoNs() -| t0;
            if (spent >= limit_ns or rs.cancelled()) return false;
            const left = @min(limit_ns - spent, slice_ns);
            f.io.futexWaitTimeout(u32, &f.pending.commits.raw, seen, .{ .duration = .{ .raw = Io.Duration.fromNanoseconds(@intCast(left)), .clock = .awake } }) catch {};
        }
    }

    /// A read while transactions are pending. True: answer as usual (it names nothing a pending
    /// transaction wrote, or it waited and the edge has applied it). False: pass it to the core
    /// (the wait is over, or too many reads are waiting): the edge's own answer could be the
    /// state before the transaction.
    fn pendingGate(f: *Forwarder, method: Method, req: *const h2.Request, rs: *h2.ResponseStream) bool {
        var keys_buf: [64]raw.Key = undefined;
        var n: usize = 0;
        var digest_buf: [32]u8 = undefined;
        var digest: ?*const [32]u8 = null;
        var more = false; // a batch with more items than `keys_buf`: asked in rounds
        var r = proto.Reader.init(req.body);
        const now = h2.meta.monoNs();
        var worst: Pending.Touch = .clear;
        switch (method) {
            .get_object, .list_dynamic_fields, .list_owned_objects, .get_balance, .list_balances => {
                const kind: raw.Kind = if (method == .get_object or method == .list_dynamic_fields) .object else .address;
                while (r.next() catch return true) |fld| if (fld.number == 1) {
                    const text = proto.Reader.stringOf(fld) catch return true;
                    if (service.parseObjectId(text)) |id| {
                        keys_buf[0] = .{ .kind = kind, .id = id };
                        n = 1;
                    } else n = 0;
                };
            },
            .batch_get_objects => {
                while (r.next() catch return true) |fld| if (fld.number == 1) {
                    var q = proto.Reader.init(proto.Reader.bytesOf(fld) catch return true);
                    while (q.next() catch return true) |g| if (g.number == 1) {
                        const id = service.parseObjectId(proto.Reader.stringOf(g) catch return true) orelse continue;
                        if (n == keys_buf.len) {
                            worst = worse(worst, f.pending.touch(keys_buf[0..n], null, now));
                            n = 0;
                            more = true;
                        }
                        keys_buf[n] = .{ .kind = .object, .id = id };
                        n += 1;
                    };
                };
            },
            .get_transaction => {
                while (r.next() catch return true) |fld| if (fld.number == 1) {
                    if (serve.b58.decode32(proto.Reader.stringOf(fld) catch return true)) |d| {
                        digest_buf = d;
                        digest = &digest_buf;
                    } else digest = null;
                };
            },
            else => return true,
        }
        if (n == 0 and digest == null and !more) return true;
        worst = worse(worst, f.pending.touch(keys_buf[0..n], digest, now));
        switch (worst) {
            .clear => return true,
            .late => {
                _ = f.metrics.raw_reads_late.fetchAdd(1, .monotonic);
                return false;
            },
            .wait => {},
        }
        if (f.raw_waiters.fetchAdd(1, .acq_rel) >= f.cfg.raw_max_waiters) {
            _ = f.raw_waiters.fetchSub(1, .acq_rel);
            _ = f.metrics.raw_reads_over_limit.fetchAdd(1, .monotonic);
            return false;
        }
        defer _ = f.raw_waiters.fetchSub(1, .acq_rel);
        var gate_stop: GateStop = .{ .fwd = f, .rs = rs, .deadline_ns = req.deadline_ns };
        // a batch past the buffer waits on its last round's keys and is looked at whole again
        var clear = f.pending.waitClear(keys_buf[0..n], digest, .{ .ctx = &gate_stop, .f = GateStop.f });
        if (clear and more) clear = f.batchClear(req.body);
        f.metrics.raw_read_wait.observe(h2.meta.monoNs() -| now);
        if (!clear) _ = f.metrics.raw_reads_late.fetchAdd(1, .monotonic);
        return clear;
    }

    /// What ends a wait on `pending` before its bound: the client left, the request's deadline,
    /// or the forwarder stops (`requestStop`). After a stop nothing more is applied, so nothing
    /// a waiter waits for can come: a waiting read is passed to the core as at the bound (it is
    /// not answered from the store, which the stop is about to close), a held execute gets its
    /// answer, and a read that arrives later does not wait at all. A waiter looks every
    /// `raw.slice_ns`, so it is gone within one slice of the stop.
    const GateStop = struct {
        fwd: *const Forwarder,
        rs: *h2.ResponseStream,
        deadline_ns: ?u64,
        fn f(ctx: *anyopaque) bool {
            const s: *GateStop = @ptrCast(@alignCast(ctx));
            if (s.fwd.stop_flag.load(.acquire)) return true;
            if (s.deadline_ns) |d| if (h2.meta.monoNs() >= d) return true;
            return s.rs.cancelled();
        }
    };

    fn worse(a: Pending.Touch, b: Pending.Touch) Pending.Touch {
        return switch (a) {
            .late => a,
            .clear => b,
            .wait => |x| switch (b) {
                .late => b,
                .clear => a,
                .wait => |y| .{ .wait = @max(x, y) },
            },
        };
    }

    /// Every item of a BatchGetObjects request is clear of the pending table.
    fn batchClear(f: *Forwarder, body: []const u8) bool {
        var r = proto.Reader.init(body);
        const now = h2.meta.monoNs();
        while (r.next() catch return true) |fld| if (fld.number == 1) {
            var q = proto.Reader.init(proto.Reader.bytesOf(fld) catch return true);
            while (q.next() catch return true) |g| if (g.number == 1) {
                const id = service.parseObjectId(proto.Reader.stringOf(g) catch return true) orelse continue;
                if (f.pending.touch(&.{.{ .kind = .object, .id = id }}, null, now) != .clear) return false;
            };
        };
        return true;
    }
};

/// The digest of the transaction an ExecuteTransaction call executed: from the request's
/// `transaction.bcs.value` (BCS TransactionData; ExecuteTransactionRequest.transaction = 1,
/// Transaction.bcs = 1, Bcs.value = 2), else from the response's `transaction.digest`
/// (ExecuteTransactionResponse.transaction = 1, ExecutedTransaction.digest = 1).
pub fn executedDigest(request: []const u8, cap: *const Capture) ?[32]u8 {
    if (nested(request, &.{ 1, 1, 2 })) |data| {
        var h = std.crypto.hash.blake2.Blake2b256.init(.{});
        h.update("TransactionData::");
        h.update(data);
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    var it = cap.frames();
    const frame = it.next() orelse return null;
    if (frame.compressed) return null;
    const text = nested(frame.payload, &.{ 1, 1 }) orelse return null;
    return serve.b58.decode32(text);
}

/// The bytes of the length-delimited field at `path` (last occurrence at each level).
fn nested(msg: []const u8, path: []const u32) ?[]const u8 {
    var cur = msg;
    for (path) |n| {
        var found: ?[]const u8 = null;
        var r = proto.Reader.init(cur);
        while (r.next() catch return null) |fld| if (fld.number == n) {
            found = proto.Reader.bytesOf(fld) catch return null;
        };
        cur = found orelse return null;
    }
    return cur;
}

// ---------------------------------------------------------------- relay

/// One forwarded call on the calling thread: starts it on the transport and writes the core's
/// messages to `rs` as they arrive. Returns the core's status with its message and details set
/// on `rs`, or the edge's own when the way to the core failed (UNAVAILABLE, naming the reason),
/// the deadline passed (DEADLINE_EXCEEDED `Timeout expired`, as a node answers) or the client left.
const Relay = struct {
    f: *Forwarder,
    /// Monotonic ns (`h2.meta.monoNs`), null: none.
    deadline_ns: ?u64,
    stop: StopFn,
    client_protocol_version: ?u64 = null,
    transport_error: bool = false,
    messages: u64 = 0,
    /// The call ended with the core's own status (trailers from the core).
    core_answered: bool = false,

    /// `runInner`, and what its end says about the way to the core (`Forwarder.upstream_down`):
    /// down after a connection-class failure, up after anything the core itself sent.
    fn run(r: *Relay, path: []const u8, body: []const u8, rs: *h2.ResponseStream) h2.Status {
        const st = r.runInner(path, body, rs);
        if (r.transport_error) {
            r.f.upstream_down.store(true, .release);
        } else if (r.core_answered or r.messages != 0) {
            if (r.f.upstream_down.load(.monotonic)) r.f.upstream_down.store(false, .release);
        }
        return st;
    }

    /// The deadline bounds the wait for the first message (h2.Request.deadline_ns: a stream that
    /// has started has none); the core gets the same `grpc-timeout` and applies the same rule.
    fn runInner(r: *Relay, path: []const u8, body: []const u8, rs: *h2.ResponseStream) h2.Status {
        const f = r.f;
        const now = h2.meta.monoNs();
        var opts: CallOpts = .{ .client_protocol_version = r.client_protocol_version };
        if (r.deadline_ns) |dl| {
            if (dl <= now) return rs.deadlineExceeded();
            opts.timeout_ms = @max(1, (dl - now) / std.time.ns_per_ms);
        }
        var call: Call = .{ .io = f.io, .gpa = f.gpa };
        defer call.deinit();
        const tr = f.transport;
        tr.vt.start(tr.ctx, &call, path, body, opts);
        defer tr.vt.finish(tr.ctx, &call);
        var chunk: std.ArrayList(u8) = .empty;
        defer chunk.deinit(f.gpa);
        var carry: usize = 0; // bytes at the front of `chunk` kept from the last round (a partial frame)
        while (true) {
            var done = false;
            var oom = false;
            {
                call.mu.lockUncancelable(f.io);
                defer call.mu.unlock(f.io);
                while (call.buf.items.len == 0 and !call.done) {
                    const t = h2.meta.monoNs();
                    const first_pending = r.messages == 0;
                    if (r.stop.f(r.stop.ctx) or (first_pending and r.deadline_ns != null and t >= r.deadline_ns.?)) {
                        call.mu.unlock(f.io);
                        tr.vt.cancel(tr.ctx, &call);
                        call.mu.lockUncancelable(f.io);
                        if (r.stop.f(r.stop.ctx)) return .cancelled;
                        return rs.deadlineExceeded();
                    }
                    var wait_ns = slice_ns;
                    if (first_pending) if (r.deadline_ns) |dl| {
                        wait_ns = @min(wait_ns, dl - t);
                    };
                    call.cond.waitTimeout(f.io, &call.mu, .{ .duration = .{ .raw = Io.Duration.fromNanoseconds(@intCast(@max(wait_ns, 1))), .clock = .awake } }) catch {};
                }
                chunk.appendSlice(f.gpa, call.buf.items) catch {
                    oom = true;
                };
                call.buf.clearRetainingCapacity();
                done = call.done;
                oom = oom or call.oom;
            }
            if (oom) {
                tr.vt.cancel(tr.ctx, &call);
                rs.setMessage("edge: out of memory relaying the core's answer");
                return .resource_exhausted;
            }
            // every whole frame in `chunk` goes out; a partial one waits for its rest
            var off: usize = 0;
            while (chunk.items.len - off >= 5) {
                const n = std.mem.readInt(u32, chunk.items[off + 1 ..][0..4], .big);
                if (chunk.items.len - off - 5 < n) break;
                if (chunk.items[off] != 0) {
                    // the edge asked for identity; a compressed frame cannot be re-framed
                    tr.vt.cancel(tr.ctx, &call);
                    rs.setMessage("edge: the core sent a compressed message");
                    return .internal;
                }
                rs.message(chunk.items[off + 5 ..][0..n]) catch {
                    tr.vt.cancel(tr.ctx, &call);
                    return .cancelled;
                };
                r.messages += 1;
                off += 5 + n;
            }
            // the window gets back what arrived this round (the carried bytes were given back
            // when they arrived)
            tr.vt.credit(tr.ctx, &call, chunk.items.len - carry);
            const rest = chunk.items.len - off;
            std.mem.copyForwards(u8, chunk.items[0..rest], chunk.items[off..]);
            chunk.items.len = rest;
            carry = rest;
            if (!done) continue;
            if (call.transport_error) {
                r.transport_error = true;
                var mb: [256]u8 = undefined;
                rs.setMessage(std.fmt.bufPrint(&mb, "edge: core upstream unavailable ({s})", .{call.message[0..@min(call.message.len, 200)]}) catch "edge: core upstream unavailable");
                return .unavailable;
            }
            if (rest != 0) {
                rs.setMessage("edge: the core's answer ended inside a message");
                return .internal;
            }
            r.core_answered = true;
            if (call.message.len > 0) rs.setMessage(call.message);
            if (call.details.len > 0) rs.details(call.details);
            return if (call.code > 16) .unknown else @enumFromInt(call.code);
        }
    }
};

/// A `ResponseStream` that keeps its frames in memory (the held ExecuteTransaction answer, the
/// floor refresh), compressed as the real stream would have, and replays them unchanged.
pub const Capture = struct {
    gpa: Allocator,
    bytes: std.ArrayList(u8) = .empty,
    failed: bool = false,

    pub fn deinit(c: *Capture) void {
        c.bytes.deinit(c.gpa);
    }

    pub fn stream(c: *Capture, encoding: h2.conn.Encoding) h2.ResponseStream {
        return .{ .gpa = c.gpa, .impl = c, .vt = &vt, .encoding = encoding };
    }

    const vt: h2.ResponseStream.VTable = .{ .write = write, .cancelled = never };

    fn write(impl: *anyopaque, hdr: *const [5]u8, payload: []const u8) anyerror!void {
        const c: *Capture = @ptrCast(@alignCast(impl));
        try c.bytes.appendSlice(c.gpa, hdr);
        try c.bytes.appendSlice(c.gpa, payload);
    }
    fn never(_: *anyopaque) bool {
        return false;
    }

    pub const Frame = struct { hdr: *const [5]u8, compressed: bool, payload: []const u8 };
    pub const Iter = struct {
        b: []const u8,
        pub fn next(it: *Iter) ?Frame {
            if (it.b.len < 5) return null;
            const n = std.mem.readInt(u32, it.b[1..5], .big);
            if (it.b.len - 5 < n) return null;
            const fr: Frame = .{ .hdr = it.b[0..5], .compressed = it.b[0] != 0, .payload = it.b[5..][0..n] };
            it.b = it.b[5 + n ..];
            return fr;
        }
    };
    pub fn frames(c: *const Capture) Iter {
        return .{ .b = c.bytes.items };
    }

    /// Writes the kept frames to `rs` as they are (already in `rs`'s encoding).
    pub fn replay(c: *const Capture, rs: *h2.ResponseStream) !void {
        var it = c.frames();
        while (it.next()) |fr| {
            try rs.vt.write(rs.impl, fr.hdr, fr.payload);
            rs.messages += 1;
        }
    }
};

/// A forwarded server stream on its own pump thread (h2/pump.zig): the same `Relay`, writing
/// through the stream's `Link`.
const StreamRelay = struct {
    f: *Forwarder,
    path: []u8,
    body: []u8,
    deadline_ns: ?u64,
    client_protocol_version: ?u64,
    wakes: Atomic(u32) = .init(0),
    link: ?*h2.Link = null,

    const gpa = std.heap.page_allocator;

    fn create(f: *Forwarder, req: *const h2.Request) !*StreamRelay {
        const p = try gpa.create(StreamRelay);
        errdefer gpa.destroy(p);
        const path = try gpa.dupe(u8, req.path);
        errdefer gpa.free(path);
        p.* = .{ .f = f, .path = path, .body = try gpa.dupe(u8, req.body), .deadline_ns = req.deadline_ns, .client_protocol_version = req.client_protocol_version };
        return p;
    }
    fn destroy(p: *StreamRelay) void {
        gpa.free(p.path);
        gpa.free(p.body);
        gpa.destroy(p);
    }
    fn pump(p: *StreamRelay) h2.Pump {
        return .{ .ctx = p, .run = runFn, .wake = wakeFn, .done = doneFn };
    }
    fn doneFn(ctx: *anyopaque) void {
        destroy(@ptrCast(@alignCast(ctx)));
    }
    fn wakeFn(ctx: *anyopaque) void {
        const p: *StreamRelay = @ptrCast(@alignCast(ctx));
        _ = p.wakes.fetchAdd(1, .release);
    }
    fn runFn(ctx: *anyopaque, link: *h2.Link) void {
        const p: *StreamRelay = @ptrCast(@alignCast(ctx));
        p.link = link;
        var rs: h2.ResponseStream = .{ .gpa = std.heap.smp_allocator, .impl = p, .vt = &vt };
        defer rs.release();
        var relay: Relay = .{ .f = p.f, .deadline_ns = p.deadline_ns, .stop = .{ .ctx = p, .f = gone }, .client_protocol_version = p.client_protocol_version };
        const st = relay.run(p.path, p.body, &rs);
        if (st == .cancelled and link.blocked() == null) return; // the client left: nobody to tell
        link.finishDetails(st, rs.msg, rs.details_bin);
    }
    fn gone(ctx: *anyopaque) bool {
        const p: *StreamRelay = @ptrCast(@alignCast(ctx));
        return p.link.?.blocked() == null or p.f.streamsEnding();
    }
    /// One message to the client, after earlier bytes found room in its h2 window (the link
    /// compresses as the stream negotiated). Holding here is what holds the core: the bytes
    /// are only given back to the upstream window once they are sent.
    fn write(impl: *anyopaque, _: *const [5]u8, payload: []const u8) anyerror!void {
        const p: *StreamRelay = @ptrCast(@alignCast(impl));
        const link = p.link.?;
        var wait_ms: u64 = 1;
        while (true) {
            const seen = p.wakes.load(.acquire);
            const blocked = link.blocked() orelse return error.Cancelled;
            // looked at for every message: a stream the core keeps feeding never reaches the
            // idle check in `Relay.run`
            if (p.f.streamsEnding()) return error.Cancelled;
            if (!blocked) break;
            var slept: u64 = 0;
            while (slept < wait_ms and p.wakes.load(.acquire) == seen) : (slept += 1) h2.sock.sleepMs(1);
            wait_ms = @min(wait_ms * 2, 8);
        }
        link.send(payload) catch return error.Cancelled;
    }
    fn cancelled(impl: *anyopaque) bool {
        return gone(impl);
    }
    const vt: h2.ResponseStream.VTable = .{ .write = write, .cancelled = cancelled };
};

// ---------------------------------------------------------------- metrics text

/// The `zui_edge_route_*` lines (docs/EDGE.md 11.6).
pub fn renderMetrics(f: *const Forwarder, w: *Io.Writer) !void {
    const m = &f.metrics;
    try w.writeAll("# TYPE zui_edge_route_served_local counter\n");
    for (route.paths) |e| try w.print("zui_edge_route_served_local{{method=\"{s}\"}} {d}\n", .{ e.path, m.methods[@intFromEnum(e.method)].served_local.load(.monotonic) });
    try w.writeAll("# TYPE zui_edge_route_forwarded counter\n");
    for (route.paths) |e| try w.print("zui_edge_route_forwarded{{method=\"{s}\"}} {d}\n", .{ e.path, m.forwardedTotal(e.method) });
    try w.writeAll("# TYPE zui_edge_route_forward_reason counter\n");
    for (route.paths) |e| {
        inline for (comptime std.meta.fieldNames(Reason), 0..) |name, i| {
            const n = m.methods[@intFromEnum(e.method)].forwarded[i].load(.monotonic);
            if (n != 0) try w.print("zui_edge_route_forward_reason{{method=\"{s}\",reason=\"{s}\"}} {d}\n", .{ e.path, name, n });
        }
    }
    try w.writeAll("# TYPE zui_edge_route_upstream_errors counter\n");
    for (route.paths) |e| try w.print("zui_edge_route_upstream_errors{{method=\"{s}\"}} {d}\n", .{ e.path, m.methods[@intFromEnum(e.method)].upstream_errors.load(.monotonic) });
    try w.writeAll("# TYPE zui_edge_route_forward_latency_seconds histogram\n");
    for (route.paths) |e| {
        const h = &m.methods[@intFromEnum(e.method)].forward_latency;
        if (h.n.load(.monotonic) == 0) continue;
        var lb: [160]u8 = undefined;
        try h.render(w, "zui_edge_route_forward_latency_seconds", std.fmt.bufPrint(&lb, "method=\"{s}\"", .{e.path}) catch unreachable);
    }
    try w.print("# TYPE zui_edge_route_upstream_down gauge\nzui_edge_route_upstream_down {d}\n", .{@intFromBool(f.upstreamDown())});
    try w.print("# TYPE zui_edge_route_guard gauge\nzui_edge_route_guard {d}\n", .{@intFromEnum(f.guardState())});
    try w.print("# TYPE zui_edge_route_guard_trips counter\nzui_edge_route_guard_trips {d}\n", .{m.guard_trips.load(.monotonic)});
    try w.print("# TYPE zui_edge_route_guard_recoveries counter\nzui_edge_route_guard_recoveries {d}\n", .{m.guard_recoveries.load(.monotonic)});
    try w.print("# TYPE zui_edge_route_streams_closed counter\nzui_edge_route_streams_closed {d}\n", .{m.streams_closed.load(.monotonic)});
    if (f.svc.hub) |hub| try w.print("# TYPE zui_edge_route_streams_closed_foreign_cert counter\nzui_edge_route_streams_closed_foreign_cert {d}\n", .{hub.stats.foreign_cert_ends.load(.monotonic)});
    const lag = m.lag.load(.monotonic);
    // -1 while the edge cannot tell (catch-up, no checkpoint yet)
    if (lag == Metrics.lag_unknown) try w.writeAll("# TYPE zui_edge_route_lag_checkpoints gauge\nzui_edge_route_lag_checkpoints -1\n") else try w.print("# TYPE zui_edge_route_lag_checkpoints gauge\nzui_edge_route_lag_checkpoints {d}\n", .{lag});
    try w.writeAll("# TYPE zui_edge_route_execute_hold_seconds histogram\n");
    try m.execute_hold.render(w, "zui_edge_route_execute_hold_seconds", "");
    try w.print("# TYPE zui_edge_route_execute_hold_timeouts counter\nzui_edge_route_execute_hold_timeouts {d}\n", .{m.execute_hold_timeouts.load(.monotonic)});
    try w.print("# TYPE zui_edge_route_pending_transactions gauge\nzui_edge_route_pending_transactions {d}\n", .{f.pending.n.load(.monotonic)});
    // read-after-write, mode `reads`
    try w.print("# TYPE zui_edge_route_raw_mode gauge\nzui_edge_route_raw_mode{{mode=\"{s}\"}} 1\n", .{@tagName(f.cfg.execMode())});
    try w.print("# TYPE zui_edge_route_raw_recorded counter\nzui_edge_route_raw_recorded {d}\n", .{m.raw_recorded.load(.monotonic)});
    try w.print("# TYPE zui_edge_route_raw_held_instead counter\nzui_edge_route_raw_held_instead {d}\n", .{m.raw_held_instead.load(.monotonic)});
    try w.writeAll("# TYPE zui_edge_route_raw_read_wait_seconds histogram\n");
    try m.raw_read_wait.render(w, "zui_edge_route_raw_read_wait_seconds", "");
    try w.print("# TYPE zui_edge_route_raw_reads_late counter\nzui_edge_route_raw_reads_late {d}\n", .{m.raw_reads_late.load(.monotonic)});
    try w.print("# TYPE zui_edge_route_raw_reads_over_limit counter\nzui_edge_route_raw_reads_over_limit {d}\n", .{m.raw_reads_over_limit.load(.monotonic)});
    try w.print("# TYPE zui_edge_route_raw_waiters gauge\nzui_edge_route_raw_waiters {d}\n", .{f.raw_waiters.load(.monotonic)});
    try w.print("# TYPE zui_edge_route_raw_pending_keys gauge\nzui_edge_route_raw_pending_keys {d}\n", .{f.pending.n_keys});
    const fl = f.core_floor.load(.monotonic);
    if (fl != floor_unknown) try w.print("# TYPE zui_edge_route_core_lowest_checkpoint gauge\nzui_edge_route_core_lowest_checkpoint {d}\n", .{fl});
}

test {
    _ = @import("forward_tests.zig");
}
