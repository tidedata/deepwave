//! sui-node's traffic controller (`policy-config`; sui-types 1.83.1 `traffic_control.rs`,
//! sui-core `traffic_controller/{mod,policies}.rs`).
//!
//! Where sui-node 1.83.1 uses it: `AuthorityState` builds one from `policy-config` (default
//! `PolicyConfig::default_dos_protection_policy`: spam FreqThreshold 1000 req/s over a 5 s window,
//! error FreqThreshold 50 req/s over 5 s, 1 s update interval, dry run on; `policy-config: null`
//! is the kill switch), and only the validator gRPC service (`ValidatorService`,
//! authority_server.rs `handle_with_decoration`) checks and tallies requests. The full node's
//! sui.rpc.v2 server (sui-rpc-api) never consults it, so a sui-node full node never answers
//! "Too many requests" on 9000, whatever the config. deepwave's RPC server does the same: the
//! controller backs the admin route (`POST /traffic-control`, `adminReconfigure`) and `Gate` is
//! the validator path's decision logic, for a server that opts in (not the default: not parity).
//!
//! Decisions, as sui-core:
//!   - client id: the socket address, or `x-forwarded-for` with N hops (the value split on ',',
//!     trimmed, the entry `len - N`; N = 0 or fewer entries than N: no client id, nothing checked)
//!   - FreqThreshold: per client a ring of `window / interval` buckets (the window rounded down to
//!     a multiple of the interval); a tally rotates once per elapsed interval (each rotation
//!     restarts the interval clock), counts, and blocks the client when
//!     `sum / window_secs >= threshold` (a rate per second, so 1000 means 5000 requests in 5 s)
//!   - spam tallies are sampled (`spam_sample_rate`), error tallies count only errors of weight 1
//!     (`normalize`: signature errors and WrongEpoch)
//!   - a blocked client is added to the blocklist until now + connection-blocklist-ttl-sec; a
//!     check after expiry removes it. In dry run a blocked client is still served.
//!   - rejection: `tonic::Status::from_error(SuiErrorKind::TooManyRequests)` = UNKNOWN (2),
//!     "Too many requests", no details.
//!
//! Memory is bounded whatever the clients do (many addresses, e.g. rotating IPv6): a tally bucket
//! keeps exact counts for at most `sketch-capacity` clients and folds the rest into a fixed array
//! of counters by address hash (over-counting, as sui-node's count-min sketch does past its
//! capacity); the blocklist drops expired entries on a timer and holds at most `max_blocklist`
//! clients (when full, the entry expiring first makes room).
const std = @import("std");

pub const IpAddr = struct {
    v6: bool,
    b: [16]u8,

    pub fn eql(a: IpAddr, o: IpAddr) bool {
        return a.v6 == o.v6 and std.mem.eql(u8, &a.b, &o.b);
    }
};

/// `parse_ip`: an IpAddr, else a SocketAddr's ip.
pub fn parseIp(s: []const u8) ?IpAddr {
    if (parseV4(s)) |a| return a;
    if (std.mem.indexOfScalar(u8, s, ':') != null and !std.mem.startsWith(u8, s, "[")) {
        if (parseV6(s)) |a| return a;
    }
    // SocketAddr: a.b.c.d:port or [v6]:port
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    const port = s[colon + 1 ..];
    _ = std.fmt.parseInt(u16, port, 10) catch return null;
    if (port.len == 0 or port[0] == '+') return null;
    const host = s[0..colon];
    if (std.mem.startsWith(u8, host, "[") and std.mem.endsWith(u8, host, "]")) return parseV6(host[1 .. host.len - 1]);
    return parseV4(host);
}

fn parseV4(s: []const u8) ?IpAddr {
    var out: IpAddr = .{ .v6 = false, .b = @splat(0) };
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i == 4 or part.len == 0 or part.len > 3) return null;
        if (part.len > 1 and part[0] == '0') return null; // Rust rejects leading zeros
        for (part) |c| if (c < '0' or c > '9') return null;
        out.b[i] = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    return if (i == 4) out else null;
}

fn parseV6(s: []const u8) ?IpAddr {
    const a = std.Io.net.Ip6Address.parse(s, 0) catch return null;
    return .{ .v6 = true, .b = a.bytes };
}

pub const ClientIdSource = union(enum) {
    socket_addr,
    x_forwarded_for: usize,
};

/// The client id for one request (`get_client_ip_addr`). `xff`: the first x-forwarded-for value.
pub fn clientId(src: ClientIdSource, peer: ?IpAddr, xff: ?[]const u8) ?IpAddr {
    switch (src) {
        .socket_addr => return peer,
        .x_forwarded_for => |hops| {
            const v = xff orelse return null;
            if (hops == 0) return null;
            var n: usize = 0;
            var it = std.mem.splitScalar(u8, v, ',');
            while (it.next()) |_| n += 1;
            if (n < hops) return null;
            it = std.mem.splitScalar(u8, v, ',');
            var i: usize = 0;
            while (it.next()) |part| : (i += 1) {
                if (i == n - hops) return parseIp(std.mem.trim(u8, part, " \t\r\n"));
            }
            return null;
        },
    }
}

pub const FreqThreshold = struct {
    client_threshold: u64 = 1_000_000,
    proxied_client_threshold: u64 = 10,
    window_size_secs: u64 = 30,
    update_interval_secs: u64 = 5,
    sketch_capacity: usize = 50_000,
    sketch_probability: f64 = 0.999,
    sketch_tolerance: f64 = 0.2,
};

pub const PolicyType = union(enum) {
    no_op,
    freq_threshold: FreqThreshold,
};

pub const PolicyConfig = struct {
    client_id_source: ClientIdSource = .socket_addr,
    connection_blocklist_ttl_sec: u64 = 60,
    proxy_blocklist_ttl_sec: u64 = 0,
    spam_policy_type: PolicyType = .no_op,
    error_policy_type: PolicyType = .no_op,
    channel_capacity: usize = 100,
    spam_sample_rate: f32 = 0.2,
    dry_run: bool = true,
    /// Some: allowlist mode (no policies, only these clients pass).
    allow_list: ?[]const IpAddr = null,

    /// `PolicyConfig::default_dos_protection_policy` (sui-node's default `policy-config`).
    pub fn dosDefault() PolicyConfig {
        return .{
            .spam_policy_type = .{ .freq_threshold = .{ .client_threshold = 1000, .window_size_secs = 5, .update_interval_secs = 1 } },
            .error_policy_type = .{ .freq_threshold = .{ .client_threshold = 50, .window_size_secs = 5, .update_interval_secs = 1 } },
            .channel_capacity = 6000,
            .spam_sample_rate = 1.0,
            .dry_run = true,
        };
    }
};

pub const ParseError = error{ UnknownKey, BadValue, OutOfMemory };

/// `--policy KEY=VALUE` items (fullnode.yaml `policy-config`, flattened by fullnode_yaml.zig):
/// none = sui-node's default (`dosDefault`), `off` = `policy-config: null` (no controller, null),
/// otherwise serde's per-field defaults with the items applied. Keys: client-id-source
/// (`socket-addr` | `x-forwarded-for:N`), connection-blocklist-ttl-sec, proxy-blocklist-ttl-sec,
/// channel-capacity, spam-sample-rate, dry-run, allow-list (comma list), spam-policy-type /
/// error-policy-type (`no-op` | `freq-threshold`) and `spam-policy-type.<freq key>=N`.
pub fn parseItems(arena: std.mem.Allocator, items: []const []const u8) ParseError!?PolicyConfig {
    if (items.len == 0) return PolicyConfig.dosDefault();
    var c: PolicyConfig = .{};
    for (items) |it| {
        if (std.mem.eql(u8, it, "off")) return null;
        const eq = std.mem.indexOfScalar(u8, it, '=') orelse return error.BadValue;
        const k = it[0..eq];
        const v = it[eq + 1 ..];
        const int = struct {
            fn f(x: []const u8) ParseError!u64 {
                return std.fmt.parseInt(u64, x, 10) catch error.BadValue;
            }
        }.f;
        if (std.mem.eql(u8, k, "client-id-source")) {
            if (std.mem.eql(u8, v, "socket-addr")) {
                c.client_id_source = .socket_addr;
            } else if (std.mem.startsWith(u8, v, "x-forwarded-for:")) {
                c.client_id_source = .{ .x_forwarded_for = try int(v["x-forwarded-for:".len..]) };
            } else return error.BadValue;
        } else if (std.mem.eql(u8, k, "connection-blocklist-ttl-sec")) {
            c.connection_blocklist_ttl_sec = try int(v);
        } else if (std.mem.eql(u8, k, "proxy-blocklist-ttl-sec")) {
            c.proxy_blocklist_ttl_sec = try int(v);
        } else if (std.mem.eql(u8, k, "channel-capacity")) {
            c.channel_capacity = try int(v);
        } else if (std.mem.eql(u8, k, "spam-sample-rate")) {
            const r = std.fmt.parseFloat(f32, v) catch return error.BadValue;
            if (!(r >= 0 and r <= 1)) return error.BadValue; // "spam-sample-rate must be between 0.0 and 1.0"
            c.spam_sample_rate = r;
        } else if (std.mem.eql(u8, k, "dry-run")) {
            c.dry_run = if (std.mem.eql(u8, v, "true")) true else if (std.mem.eql(u8, v, "false")) false else return error.BadValue;
        } else if (std.mem.eql(u8, k, "allow-list")) {
            var l: std.ArrayList(IpAddr) = .empty;
            var sp = std.mem.splitScalar(u8, v, ',');
            while (sp.next()) |x| if (x.len > 0) try l.append(arena, parseIp(x) orelse return error.BadValue);
            c.allow_list = l.items;
        } else if (std.mem.startsWith(u8, k, "spam-policy-type") or std.mem.startsWith(u8, k, "error-policy-type")) {
            const pt = if (k[0] == 's') &c.spam_policy_type else &c.error_policy_type;
            const base = if (k[0] == 's') "spam-policy-type" else "error-policy-type";
            if (k.len == base.len) {
                if (std.mem.eql(u8, v, "no-op") or std.mem.eql(u8, v, "NoOp")) {
                    pt.* = .no_op;
                } else if (std.mem.eql(u8, v, "freq-threshold") or std.mem.eql(u8, v, "FreqThreshold")) {
                    if (pt.* != .freq_threshold) pt.* = .{ .freq_threshold = .{} };
                } else return error.BadValue;
                continue;
            }
            if (k[base.len] != '.') return error.UnknownKey;
            if (pt.* != .freq_threshold) pt.* = .{ .freq_threshold = .{} };
            const f = &pt.freq_threshold;
            const sub = k[base.len + 1 ..];
            if (std.mem.eql(u8, sub, "client-threshold")) f.client_threshold = try int(v) //
            else if (std.mem.eql(u8, sub, "proxied-client-threshold")) f.proxied_client_threshold = try int(v) //
            else if (std.mem.eql(u8, sub, "window-size-secs")) f.window_size_secs = try int(v) //
            else if (std.mem.eql(u8, sub, "update-interval-secs")) f.update_interval_secs = try int(v) //
            else if (std.mem.eql(u8, sub, "sketch-capacity")) f.sketch_capacity = try int(v) //
            else if (std.mem.eql(u8, sub, "sketch-probability")) f.sketch_probability = std.fmt.parseFloat(f64, v) catch return error.BadValue //
            else if (std.mem.eql(u8, sub, "sketch-tolerance")) f.sketch_tolerance = std.fmt.parseFloat(f64, v) catch return error.BadValue //
            else return error.UnknownKey;
        } else return error.UnknownKey;
    }
    return c;
}

const ns_per_s: u64 = std.time.ns_per_s;

/// Exact-count clients per tally bucket at most (`sketch-capacity` is clamped to this).
pub const max_exact_clients: usize = 1 << 18;
/// Overflow counters per tally bucket (clients past the exact capacity, by address hash).
pub const overflow_slots: usize = 4096;
/// Blocklist entries at most.
pub const max_blocklist: u32 = 1 << 16;
/// How often expired blocklist entries are dropped (besides on a check of that client).
const sweep_interval_ns: u64 = 10 * ns_per_s;

fn ipHash(ip: IpAddr) u64 {
    var h = std.hash.Wyhash.init(0x7a75692d74726166);
    h.update(&.{@intFromBool(ip.v6)});
    h.update(&ip.b);
    return h.final();
}

/// The overflow counter of a client in a bucket of `n` slots.
fn slotOf(ip: IpAddr, n: usize) usize {
    return @as(usize, @truncate(ipHash(ip))) % n;
}

/// One interval's tallies: exact counts for up to `cap` clients, the rest by hash slot.
const Bucket = struct {
    exact: std.AutoHashMapUnmanaged(IpAddr, u32) = .empty,
    overflow: []u32,
    overflowed: bool = false,

    fn get(b: *const Bucket, ip: IpAddr) u64 {
        if (b.exact.get(ip)) |n| return n;
        return if (b.overflowed) b.overflow[slotOf(ip, b.overflow.len)] else 0;
    }

    fn add(b: *Bucket, gpa: std.mem.Allocator, ip: IpAddr, cap: usize) void {
        if (b.exact.getPtr(ip)) |n| {
            n.* +|= 1;
            return;
        }
        if (b.exact.count() < cap) {
            // out of memory: count it by slot instead
            if (b.exact.put(gpa, ip, 1)) {
                return;
            } else |_| {}
        }
        b.overflowed = true;
        const slot = &b.overflow[slotOf(ip, b.overflow.len)];
        slot.* +|= 1;
    }

    /// Empties the bucket for a new interval; a table far larger than its last use is freed.
    fn reset(b: *Bucket, gpa: std.mem.Allocator) void {
        if (b.exact.capacity() > 1024 and @as(usize, b.exact.count()) * 4 < b.exact.capacity())
            b.exact.clearAndFree(gpa)
        else
            b.exact.clearRetainingCapacity();
        if (b.overflowed) @memset(b.overflow, 0);
        b.overflowed = false;
    }
};

/// FreqThresholdPolicy with exact counts (the count-min sketch's estimate without collisions)
/// up to `sketch-capacity` clients per interval.
const Freq = struct {
    threshold: u64,
    window_s: u64,
    interval_ns: u64,
    cap: usize,
    buckets: []Bucket,
    cur: usize = 0,
    last_reset: u64,

    fn init(gpa: std.mem.Allocator, c: FreqThreshold, now: u64) !Freq {
        const n = c.window_size_secs / @max(c.update_interval_secs, 1);
        if (c.update_interval_secs < 1 or n < 2 or n > 10 or c.window_size_secs >= 600) return error.InvalidPolicy;
        const b = try gpa.alloc(Bucket, n);
        var made: usize = 0;
        errdefer {
            for (b[0..made]) |*x| gpa.free(x.overflow);
            gpa.free(b);
        }
        for (b) |*x| {
            const ov = try gpa.alloc(u32, overflow_slots);
            @memset(ov, 0);
            x.* = .{ .overflow = ov };
            made += 1;
        }
        return .{ .threshold = c.client_threshold, .window_s = n * c.update_interval_secs, .interval_ns = c.update_interval_secs * ns_per_s, .cap = std.math.clamp(c.sketch_capacity, 1, max_exact_clients), .buckets = b, .last_reset = now };
    }

    fn deinit(f: *Freq, gpa: std.mem.Allocator) void {
        for (f.buckets) |*x| {
            x.exact.deinit(gpa);
            gpa.free(x.overflow);
        }
        gpa.free(f.buckets);
    }

    /// handle_tally for a direct client: true = block.
    fn tally(f: *Freq, gpa: std.mem.Allocator, ip: IpAddr, now: u64) bool {
        // one rotation per elapsed interval, each restarting the interval clock; after a whole
        // window of rotations every bucket is empty, so a long idle spell stops there
        var elapsed = now -| f.last_reset;
        var rotations: usize = 0;
        while (elapsed >= f.interval_ns) {
            if (rotations < f.buckets.len) {
                f.cur = (f.cur + 1) % f.buckets.len;
                f.buckets[f.cur].reset(gpa);
                rotations += 1;
            }
            f.last_reset = now;
            elapsed = if (rotations < f.buckets.len) elapsed - f.interval_ns else 0;
        }
        f.buckets[f.cur].add(gpa, ip, f.cap);
        var sum: u64 = 0;
        for (f.buckets) |*x| sum +|= x.get(ip);
        const rate = @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(f.window_s));
        return rate >= @as(f64, @floatFromInt(f.threshold));
    }
};

/// A small lock: spins briefly, then yields the CPU (a holder that is descheduled, or freeing a
/// large tally table, does not keep the waiters burning cores).
const Spin = struct {
    v: std.atomic.Value(bool) = .init(false),
    fn lock(s: *Spin) void {
        var spins: u32 = 0;
        while (s.v.swap(true, .acquire)) {
            spins +%= 1;
            if (spins < 64) std.atomic.spinLoopHint() else std.Thread.yield() catch {};
        }
    }
    fn unlock(s: *Spin) void {
        s.v.store(false, .release);
    }
};

pub const Params = struct {
    error_threshold: ?u64 = null,
    spam_threshold: ?u64 = null,
    dry_run: ?bool = null,
};

pub const Controller = struct {
    gpa: std.mem.Allocator,
    mu: Spin = .{},
    cfg: PolicyConfig,
    spam: ?Freq = null,
    err: ?Freq = null,
    /// The policies exist (blocklist mode); with NoOp they are present but not FreqThreshold.
    has_policies: bool,
    blocklist: std.AutoHashMapUnmanaged(IpAddr, u64) = .empty,
    now: *const fn () u64,
    rng: std.Random.DefaultPrng,
    blocked: u64 = 0,
    blocked_dry_run: u64 = 0,
    /// When expired blocklist entries were last dropped.
    last_sweep: u64 = 0,
    /// Blocklist entries pushed out early because the list was full.
    evicted: u64 = 0,

    pub fn init(gpa: std.mem.Allocator, cfg: PolicyConfig, now: *const fn () u64) !Controller {
        const t = now();
        var c: Controller = .{ .gpa = gpa, .cfg = cfg, .has_policies = cfg.allow_list == null, .now = now, .rng = .init(t), .last_sweep = t };
        if (cfg.allow_list == null) {
            if (cfg.spam_policy_type == .freq_threshold) c.spam = try Freq.init(gpa, cfg.spam_policy_type.freq_threshold, t);
            errdefer if (c.spam) |*f| f.deinit(gpa);
            if (cfg.error_policy_type == .freq_threshold) c.err = try Freq.init(gpa, cfg.error_policy_type.freq_threshold, t);
        }
        return c;
    }

    pub fn deinit(c: *Controller) void {
        if (c.spam) |*f| f.deinit(c.gpa);
        if (c.err) |*f| f.deinit(c.gpa);
        c.blocklist.deinit(c.gpa);
    }

    /// `TrafficController::check`: false = reject the request.
    pub fn check(c: *Controller, client: ?IpAddr) bool {
        c.mu.lock();
        defer c.mu.unlock();
        const allowed = if (c.cfg.allow_list) |al| blk: {
            const ip = client orelse break :blk true;
            for (al) |x| if (x.eql(ip)) break :blk true;
            break :blk false;
        } else blk: {
            const ip = client orelse break :blk true;
            const exp = c.blocklist.get(ip) orelse break :blk true;
            if (c.now() >= exp) {
                _ = c.blocklist.remove(ip);
                break :blk true;
            }
            break :blk false;
        };
        if (allowed) return true;
        if (c.cfg.dry_run) {
            c.blocked_dry_run += 1;
            return true;
        }
        c.blocked += 1;
        return false;
    }

    /// True with probability `w` (0 never, 1 always: the draw is in [0, 1)).
    fn sampled(c: *Controller, w: f32) bool {
        return c.rng.random().float(f32) < w;
    }

    /// `TrafficController::tally` (processed inline): `spam_weight` per request (1), `error_weight`
    /// 1 for the errors `normalize` counts, else 0 (or null: no error).
    pub fn tally(c: *Controller, client: ?IpAddr, spam_weight: f32, error_weight: ?f32) void {
        const ip = client orelse return;
        c.mu.lock();
        defer c.mu.unlock();
        if (c.cfg.allow_list != null) return;
        const now = c.now();
        if (now -| c.last_sweep >= sweep_interval_ns) c.sweep(now);
        if (c.spam) |*f| if (c.sampled(spam_weight) and c.sampled(c.cfg.spam_sample_rate)) {
            if (f.tally(c.gpa, ip, now)) c.block(ip, now);
        };
        if (error_weight) |w| if (c.err) |*f| if (w > 0 and c.sampled(w)) {
            if (f.tally(c.gpa, ip, now)) c.block(ip, now);
        };
    }

    fn block(c: *Controller, ip: IpAddr, now: u64) void {
        // a huge configured TTL saturates (blocked for good) instead of overflowing
        const until = now +| (c.cfg.connection_blocklist_ttl_sec *| ns_per_s);
        if (c.blocklist.getPtr(ip)) |e| {
            e.* = until;
            return;
        }
        if (c.blocklist.count() >= max_blocklist) {
            c.sweep(now);
            if (c.blocklist.count() >= max_blocklist) c.evictSoonest();
        }
        c.blocklist.put(c.gpa, ip, until) catch {};
    }

    /// Drops the expired blocklist entries.
    fn sweep(c: *Controller, now: u64) void {
        c.last_sweep = now;
        var buf: [256]IpAddr = undefined;
        while (true) {
            var n: usize = 0;
            var it = c.blocklist.iterator();
            while (it.next()) |e| {
                if (now < e.value_ptr.*) continue;
                buf[n] = e.key_ptr.*;
                n += 1;
                if (n == buf.len) break;
            }
            for (buf[0..n]) |ip| _ = c.blocklist.remove(ip);
            if (n < buf.len) break;
        }
    }

    /// Makes room in a full blocklist: the entry that would expire first goes.
    fn evictSoonest(c: *Controller) void {
        var it = c.blocklist.iterator();
        var victim: ?IpAddr = null;
        var soonest: u64 = std.math.maxInt(u64);
        while (it.next()) |e| if (victim == null or e.value_ptr.* < soonest) {
            victim = e.key_ptr.*;
            soonest = e.value_ptr.*;
        };
        if (victim) |v| {
            _ = c.blocklist.remove(v);
            c.evicted += 1;
        }
    }

    pub const Reconfig = union(enum) {
        ok: Params,
        /// 500 body (SuiError Display).
        err: []const u8,
        /// sui-node unwraps a missing policy (allowlist mode) and the handler panics: the
        /// connection closes with no response.
        panic,
    };

    /// `admin_reconfigure`: error threshold, then spam threshold (each fails on a non-FreqThreshold
    /// policy, after earlier changes stuck), then dry run; answers `get_current_state`.
    pub fn adminReconfigure(c: *Controller, p: Params) Reconfig {
        c.mu.lock();
        defer c.mu.unlock();
        const unsupported = "Invalid admin request: Unsupported prior policy type during traffic control reconfiguration";
        if (p.error_threshold) |t| {
            if (!c.has_policies) return .panic;
            if (c.err) |*f| f.threshold = t else return .{ .err = unsupported };
        }
        if (p.spam_threshold) |t| {
            if (!c.has_policies) return .panic;
            if (c.spam) |*f| f.threshold = t else return .{ .err = unsupported };
        }
        if (p.dry_run) |d| c.cfg.dry_run = d;
        return .{ .ok = .{
            .error_threshold = if (c.err) |f| f.threshold else null,
            .spam_threshold = if (c.spam) |f| f.threshold else null,
            .dry_run = c.cfg.dry_run,
        } };
    }
};

/// The validator service's per-request decision for a server that opts in.
pub const Gate = struct {
    ctl: *Controller,

    pub const rejection_code: u8 = 2; // UNKNOWN
    pub const rejection_message = "Too many requests";

    pub fn admit(g: Gate, peer: ?IpAddr, xff: ?[]const u8) ?IpAddr {
        return clientId(g.ctl.cfg.client_id_source, peer, xff);
    }
};

/// `normalize`: the SuiError kinds the error policy counts, by their Display prefix.
pub fn errorWeight(message: []const u8) f32 {
    const counted = [_][]const u8{
        "Transaction was not signed by the correct sender: ",
        "Signature is not valid: ",
        "Required Signature from ",
        "Expect ",
        "Value was not signed by the correct sender: ",
        "Signature is not valid, but a retry may result in a valid one: ",
        "Wrong epoch, expected ",
    };
    for (counted) |p| if (std.mem.startsWith(u8, message, p)) return 1;
    return 0;
}

// ---- admin POST /traffic-control ---------------------------------------------------------------

pub const AdminAnswer = struct {
    /// 0: close the connection without a response (sui-node's handler panics).
    code: u16,
    body: []const u8,
};

/// `POST /traffic-control?error_threshold=N&spam_threshold=N&dry_run=B` as sui-node's axum
/// handler: `Query<TrafficControlReconfigParams>` (400 "Failed to deserialize query string: ..."),
/// then the controller (500 when there is none or the policy is not FreqThreshold).
pub fn admin(arena: std.mem.Allocator, ctl: ?*Controller, query: []const u8) !AdminAnswer {
    var p: Params = .{};
    var seen: [3]bool = .{ false, false, false };
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |kv| {
        if (kv.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, kv, '=');
        const k = try formDecode(arena, if (eq) |i| kv[0..i] else kv);
        const v = try formDecode(arena, if (eq) |i| kv[i + 1 ..] else "");
        const which: ?usize = if (std.mem.eql(u8, k, "error_threshold")) 0 else if (std.mem.eql(u8, k, "spam_threshold")) 1 else if (std.mem.eql(u8, k, "dry_run")) 2 else null;
        const w = which orelse continue;
        if (seen[w]) return .{ .code = 400, .body = try std.fmt.allocPrint(arena, "Failed to deserialize query string: duplicate field `{s}`", .{k}) };
        seen[w] = true;
        if (w == 2) {
            p.dry_run = if (std.mem.eql(u8, v, "true")) true else if (std.mem.eql(u8, v, "false")) false else return .{ .code = 400, .body = try std.fmt.allocPrint(arena, "Failed to deserialize query string: {s}: provided string was not `true` or `false`", .{k}) };
        } else {
            const n = parseU64(v) catch |e| return .{ .code = 400, .body = try std.fmt.allocPrint(arena, "Failed to deserialize query string: {s}: {s}", .{ k, switch (e) {
                error.Empty => "cannot parse integer from empty string",
                error.Invalid => "invalid digit found in string",
                error.Overflow => "number too large to fit in target type",
            } }) };
            if (w == 0) p.error_threshold = n else p.spam_threshold = n;
        }
    }
    const c = ctl orelse return .{ .code = 500, .body = "Invalid admin request: Traffic controller is not configured on this node" };
    return switch (c.adminReconfigure(p)) {
        .panic => .{ .code = 0, .body = "" },
        .err => |e| .{ .code = 500, .body = e },
        .ok => |s| .{ .code = 200, .body = try std.fmt.allocPrint(arena, "Traffic control configured with:\nError threshold: {f}\nSpam threshold: {f}\nDry run: {f}\n", .{ OptFmt(u64){ .v = s.error_threshold }, OptFmt(u64){ .v = s.spam_threshold }, OptFmt(bool){ .v = s.dry_run } }) },
    };
}

/// Rust `{:?}` of an Option.
fn OptFmt(comptime T: type) type {
    return struct {
        v: ?T,
        pub fn format(self: @This(), w: *std.Io.Writer) std.Io.Writer.Error!void {
            if (self.v) |x| try w.print("Some({})", .{x}) else try w.writeAll("None");
        }
    };
}

/// u64::from_str (a leading '+' is allowed).
fn parseU64(s0: []const u8) error{ Empty, Invalid, Overflow }!u64 {
    const s = if (s0.len > 0 and s0[0] == '+') s0[1..] else s0;
    if (s0.len == 0) return error.Empty;
    if (s.len == 0) return error.Invalid;
    var n: u64 = 0;
    for (s) |ch| {
        if (ch < '0' or ch > '9') return error.Invalid;
        n = std.math.mul(u64, n, 10) catch return error.Overflow;
        n = std.math.add(u64, n, ch - '0') catch return error.Overflow;
    }
    return n;
}

/// application/x-www-form-urlencoded decoding ('+' is a space, %XX a byte).
fn formDecode(arena: std.mem.Allocator, s: []const u8) ![]const u8 {
    if (std.mem.indexOfAny(u8, s, "+%") == null) return s;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '+') {
            try out.append(arena, ' ');
        } else if (s[i] == '%' and i + 2 < s.len and std.ascii.isHex(s[i + 1]) and std.ascii.isHex(s[i + 2])) {
            try out.append(arena, std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch unreachable);
            i += 2;
        } else try out.append(arena, s[i]);
    }
    return out.items;
}

// ---- tests ------------------------------------------------------------------------------------

const testing = std.testing;

var fake_now: u64 = 1_000 * ns_per_s;
fn fakeNow() u64 {
    return fake_now;
}

fn ip4(a: u8, b: u8, c: u8, d: u8) IpAddr {
    var x: IpAddr = .{ .v6 = false, .b = @splat(0) };
    x.b[0..4].* = .{ a, b, c, d };
    return x;
}

test "traffic: spam threshold is a per-second rate over the window" {
    fake_now = 1_000 * ns_per_s;
    var cfg = PolicyConfig.dosDefault();
    cfg.spam_policy_type.freq_threshold.client_threshold = 10; // 10 req/s over 5 s = 50 requests
    cfg.dry_run = false;
    var c = try Controller.init(testing.allocator, cfg, fakeNow);
    defer c.deinit();
    const a = ip4(10, 0, 0, 1);
    for (0..49) |_| c.tally(a, 1, null);
    try testing.expect(c.check(a));
    c.tally(a, 1, null);
    try testing.expect(!c.check(a));
    // another client is unaffected
    try testing.expect(c.check(ip4(10, 0, 0, 2)));
    // blocklist TTL (60 s default): blocked until expiry, then removed
    fake_now += 59 * ns_per_s;
    try testing.expect(!c.check(a));
    fake_now += 1 * ns_per_s;
    try testing.expect(c.check(a));
    try testing.expectEqual(@as(u32, 0), c.blocklist.count());
}

test "traffic: window slides per update interval" {
    fake_now = 1_000 * ns_per_s;
    var cfg = PolicyConfig.dosDefault();
    cfg.spam_policy_type.freq_threshold.client_threshold = 10;
    cfg.dry_run = false;
    var c = try Controller.init(testing.allocator, cfg, fakeNow);
    defer c.deinit();
    const a = ip4(10, 0, 0, 1);
    // 40 requests, then 5 s later (the old buckets rotated out) 49 more stay under 50
    for (0..40) |_| c.tally(a, 1, null);
    fake_now += 5 * ns_per_s;
    for (0..49) |_| c.tally(a, 1, null);
    try testing.expect(c.check(a));
    // within the window the counts add up
    fake_now += 1 * ns_per_s;
    c.tally(a, 1, null);
    try testing.expect(!c.check(a));
}

test "traffic: error policy counts weighted errors only" {
    fake_now = 1_000 * ns_per_s;
    var cfg = PolicyConfig.dosDefault(); // error 50 req/s over 5 s = 250 errors
    cfg.dry_run = false;
    var c = try Controller.init(testing.allocator, cfg, fakeNow);
    defer c.deinit();
    const a = ip4(1, 2, 3, 4);
    for (0..1000) |_| c.tally(a, 0, 0); // errors of weight 0, no spam weight
    try testing.expect(c.check(a));
    for (0..249) |_| c.tally(a, 0, 1);
    try testing.expect(c.check(a));
    c.tally(a, 0, 1);
    try testing.expect(!c.check(a));
    try testing.expectEqual(@as(f32, 1), errorWeight("Signature is not valid: x"));
    try testing.expectEqual(@as(f32, 0), errorWeight("Error checking transaction input objects: x"));
}

test "traffic: dry run serves blocked clients" {
    fake_now = 1_000 * ns_per_s;
    var cfg = PolicyConfig.dosDefault();
    cfg.spam_policy_type.freq_threshold.client_threshold = 1;
    var c = try Controller.init(testing.allocator, cfg, fakeNow);
    defer c.deinit();
    const a = ip4(1, 1, 1, 1);
    for (0..5) |_| c.tally(a, 1, null);
    try testing.expect(c.check(a));
    try testing.expectEqual(@as(u64, 1), c.blocked_dry_run);
    _ = c.adminReconfigure(.{ .dry_run = false });
    try testing.expect(!c.check(a));
}

test "traffic: many clients keep the tally buckets bounded and still block the heavy one" {
    fake_now = 1_000 * ns_per_s;
    var cfg = PolicyConfig.dosDefault();
    cfg.spam_policy_type.freq_threshold.client_threshold = 10; // 50 requests in the 5 s window
    cfg.spam_policy_type.freq_threshold.sketch_capacity = 100;
    cfg.dry_run = false;
    var c = try Controller.init(testing.allocator, cfg, fakeNow);
    defer c.deinit();
    // 10,000 distinct one-request clients (rotating addresses)
    for (0..10_000) |i| {
        var x: IpAddr = .{ .v6 = true, .b = @splat(0) };
        std.mem.writeInt(u64, x.b[8..16], i, .little);
        c.tally(x, 1, null);
    }
    const f = &c.spam.?;
    for (f.buckets) |*b| try testing.expect(b.exact.count() <= 100);
    // a client past the capacity is still counted (by slot) and blocked
    const heavy = ip4(7, 7, 7, 7);
    for (0..50) |_| c.tally(heavy, 1, null);
    try testing.expect(!c.check(heavy));
    // a whole window later every bucket is empty again
    fake_now += 3600 * ns_per_s;
    c.tally(ip4(8, 8, 8, 8), 1, null);
    var total: usize = 0;
    for (f.buckets) |*b| total += b.exact.count();
    try testing.expectEqual(@as(usize, 1), total);
}

test "traffic: the blocklist drops expired entries on a timer and stays under its cap" {
    fake_now = 1_000 * ns_per_s;
    var cfg = PolicyConfig.dosDefault();
    cfg.spam_policy_type.freq_threshold.client_threshold = 1; // 5 requests in the window block
    cfg.connection_blocklist_ttl_sec = 5;
    cfg.dry_run = false;
    var c = try Controller.init(testing.allocator, cfg, fakeNow);
    defer c.deinit();
    for (0..300) |i| {
        const x = ip4(10, 1, @intCast(i >> 8), @intCast(i & 0xff));
        for (0..5) |_| c.tally(x, 1, null);
    }
    try testing.expectEqual(@as(u32, 300), c.blocklist.count());
    // the blocked clients never come back; a later tally from anyone sweeps them out
    fake_now += 20 * ns_per_s;
    c.tally(ip4(10, 9, 9, 9), 1, null);
    try testing.expectEqual(@as(u32, 0), c.blocklist.count());
    // a huge TTL saturates instead of overflowing
    var big = cfg;
    big.connection_blocklist_ttl_sec = std.math.maxInt(u64);
    var d = try Controller.init(testing.allocator, big, fakeNow);
    defer d.deinit();
    for (0..5) |_| d.tally(ip4(1, 1, 1, 1), 1, null);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), d.blocklist.get(ip4(1, 1, 1, 1)).?);
}

test "traffic: a full blocklist evicts the entry expiring first" {
    fake_now = 1_000 * ns_per_s;
    var c = try Controller.init(testing.allocator, .{ .dry_run = false }, fakeNow);
    defer c.deinit();
    var i: u32 = 0;
    while (i < max_blocklist) : (i += 1) {
        var x: IpAddr = .{ .v6 = true, .b = @splat(0) };
        std.mem.writeInt(u32, x.b[12..16], i, .little);
        // entry i expires at now + ttl + i ns, so entry 0 expires first
        try c.blocklist.put(testing.allocator, x, fake_now + 60 * ns_per_s + i);
    }
    c.block(ip4(2, 2, 2, 2), fake_now);
    try testing.expectEqual(max_blocklist, c.blocklist.count());
    try testing.expectEqual(@as(u64, 1), c.evicted);
    var first: IpAddr = .{ .v6 = true, .b = @splat(0) };
    std.mem.writeInt(u32, first.b[12..16], 0, .little);
    try testing.expect(c.blocklist.get(first) == null);
    try testing.expect(!c.check(ip4(2, 2, 2, 2)));
}

test "traffic: weight 0 is never sampled, weight 1 always" {
    fake_now = 1_000 * ns_per_s;
    var c = try Controller.init(testing.allocator, PolicyConfig.dosDefault(), fakeNow);
    defer c.deinit();
    for (0..100_000) |_| {
        try testing.expect(!c.sampled(0));
        try testing.expect(c.sampled(1));
    }
}

test "traffic: x-forwarded-for hops" {
    const xff = "1.1.1.1, 2.2.2.2 ,3.3.3.3:443";
    try testing.expect(clientId(.{ .x_forwarded_for = 1 }, null, xff).?.eql(ip4(3, 3, 3, 3)));
    try testing.expect(clientId(.{ .x_forwarded_for = 2 }, null, xff).?.eql(ip4(2, 2, 2, 2)));
    try testing.expect(clientId(.{ .x_forwarded_for = 3 }, null, xff).?.eql(ip4(1, 1, 1, 1)));
    try testing.expect(clientId(.{ .x_forwarded_for = 4 }, null, xff) == null);
    try testing.expect(clientId(.{ .x_forwarded_for = 0 }, null, xff) == null);
    try testing.expect(clientId(.{ .x_forwarded_for = 1 }, ip4(9, 9, 9, 9), null) == null);
    try testing.expect(clientId(.socket_addr, ip4(9, 9, 9, 9), xff).?.eql(ip4(9, 9, 9, 9)));
    try testing.expect(clientId(.{ .x_forwarded_for = 1 }, null, "garbage") == null);
    try testing.expect(parseIp("::1").?.v6);
    try testing.expect(parseIp("[::1]:80").?.v6);
    try testing.expect(parseIp("01.2.3.4") == null);
}

test "traffic: policy items" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const d = (try parseItems(ar, &.{})).?;
    try testing.expectEqual(@as(u64, 1000), d.spam_policy_type.freq_threshold.client_threshold);
    try testing.expectEqual(@as(u64, 50), d.error_policy_type.freq_threshold.client_threshold);
    try testing.expect(d.dry_run);
    try testing.expect((try parseItems(ar, &.{"off"})) == null);
    // a policy-config section starts from serde's per-field defaults (NoOp policies)
    const p = (try parseItems(ar, &.{ "dry-run=false", "client-id-source=x-forwarded-for:2", "error-policy-type.client-threshold=7" })).?;
    try testing.expect(!p.dry_run);
    try testing.expect(p.spam_policy_type == .no_op);
    try testing.expectEqual(@as(u64, 7), p.error_policy_type.freq_threshold.client_threshold);
    try testing.expectEqual(@as(u64, 30), p.error_policy_type.freq_threshold.window_size_secs);
    try testing.expectEqual(@as(usize, 2), p.client_id_source.x_forwarded_for);
    try testing.expectEqual(@as(u64, 60), p.connection_blocklist_ttl_sec);
    try testing.expectError(error.BadValue, parseItems(ar, &.{"spam-sample-rate=1.5"}));
    try testing.expectError(error.UnknownKey, parseItems(ar, &.{"nope=1"}));
}

test "traffic: admin reconfigure texts" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    fake_now = 1_000 * ns_per_s;
    var c = try Controller.init(testing.allocator, PolicyConfig.dosDefault(), fakeNow);
    defer c.deinit();
    var r = try admin(ar, &c, "");
    try testing.expectEqualStrings("Traffic control configured with:\nError threshold: Some(50)\nSpam threshold: Some(1000)\nDry run: Some(true)\n", r.body);
    r = try admin(ar, &c, "error_threshold=100&spam_threshold=200&dry_run=false&other=x");
    try testing.expectEqual(@as(u16, 200), r.code);
    try testing.expectEqualStrings("Traffic control configured with:\nError threshold: Some(100)\nSpam threshold: Some(200)\nDry run: Some(false)\n", r.body);
    r = try admin(ar, &c, "error_threshold=abc");
    try testing.expectEqual(@as(u16, 400), r.code);
    try testing.expectEqualStrings("Failed to deserialize query string: error_threshold: invalid digit found in string", r.body);
    r = try admin(ar, &c, "dry_run=yes");
    try testing.expectEqualStrings("Failed to deserialize query string: dry_run: provided string was not `true` or `false`", r.body);
    r = try admin(ar, &c, "spam_threshold=");
    try testing.expectEqualStrings("Failed to deserialize query string: spam_threshold: cannot parse integer from empty string", r.body);
    r = try admin(ar, null, "dry_run=true");
    try testing.expectEqual(@as(u16, 500), r.code);
    try testing.expectEqualStrings("Invalid admin request: Traffic controller is not configured on this node", r.body);
    // NoOp policies: thresholds are not settable
    var n = try Controller.init(testing.allocator, .{}, fakeNow);
    defer n.deinit();
    r = try admin(ar, &n, "spam_threshold=5");
    try testing.expectEqual(@as(u16, 500), r.code);
    try testing.expectEqualStrings("Invalid admin request: Unsupported prior policy type during traffic control reconfiguration", r.body);
    r = try admin(ar, &n, "dry_run=false");
    try testing.expectEqualStrings("Traffic control configured with:\nError threshold: None\nSpam threshold: None\nDry run: Some(false)\n", r.body);
    // allowlist mode: a threshold panics sui-node's handler
    var al = try Controller.init(testing.allocator, .{ .allow_list = &.{ip4(1, 2, 3, 4)}, .dry_run = false }, fakeNow);
    defer al.deinit();
    try testing.expectEqual(@as(u16, 0), (try admin(ar, &al, "error_threshold=1")).code);
    try testing.expect(al.check(ip4(1, 2, 3, 4)));
    try testing.expect(!al.check(ip4(1, 2, 3, 5)));
    try testing.expect(al.check(null));
}
