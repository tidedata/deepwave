//! Watchdog core: Prometheus text parsing, the health checks that matter, and the alert state
//! machine (debounce, repeat, recovery). Pure: the daemon (main.zig) scrapes and sends.
//!
//! Full-node checks (metric names are sui-node's, which deepwave serves, and deepwave's own):
//!   scrape     metrics endpoint answers
//!   lag        now - last_executed_checkpoint_timestamp_ms above a limit (checkpoint lag)
//!   stall      last_executed_checkpoint did not move for N seconds
//!   behind     highest_known_checkpoint - last_executed_checkpoint above a limit
//!   peers      sum of zui_p2p_known_peers below a floor (only when the node reports it)
//!   serve      share of 5xx-class RPC answers in a window above a limit (needs a minimum volume)
//!   store      zui_store_age_failed != 0
//!   state      zui_state_hash_* / zui_sui_conservation_* mismatch or failure counters above zero
//!   standby    two targets (primary, standby): checkpoint gap above a limit
//! Generic rules cover validators later (votes, round lag): `GaugeRule` on any metric, and
//! `StakeRule`, which sums the stake of the peers whose series is bad and alerts when that
//! stake is above a share of the total (1/3 is where a Sui validator loses liveness to faults).
const std = @import("std");

pub const Severity = enum {
    warn,
    crit,
    pub fn name(s: Severity) []const u8 {
        return if (s == .crit) "CRIT" else "WARN";
    }
};

// ------------------------------------------------------------------------------- Prometheus

pub const Sample = struct { name: []const u8, labels: []const u8, value: f64 };

/// Parsed exposition text. Slices point into `body`, which the caller keeps alive.
pub const Scrape = struct {
    samples: std.ArrayList(Sample) = .empty,

    pub fn deinit(s: *Scrape, gpa: std.mem.Allocator) void {
        s.samples.deinit(gpa);
    }

    pub fn parse(gpa: std.mem.Allocator, body: []const u8) !Scrape {
        var s: Scrape = .{};
        errdefer s.deinit(gpa);
        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            var name_end: usize = 0;
            while (name_end < line.len and line[name_end] != '{' and line[name_end] != ' ' and line[name_end] != '\t') name_end += 1;
            if (name_end == 0 or name_end == line.len) continue;
            var labels: []const u8 = "";
            var rest = name_end;
            if (line[name_end] == '{') {
                // the closing brace outside quotes
                var i = name_end + 1;
                var inq = false;
                while (i < line.len) : (i += 1) {
                    const ch = line[i];
                    if (ch == '\\' and inq) {
                        i += 1;
                        continue;
                    }
                    if (ch == '"') inq = !inq else if (ch == '}' and !inq) break;
                }
                if (i >= line.len) continue;
                labels = line[name_end + 1 .. i];
                rest = i + 1;
            }
            var it = std.mem.tokenizeAny(u8, line[rest..], " \t");
            const vtxt = it.next() orelse continue;
            const v = parseValue(vtxt) orelse continue;
            try s.samples.append(gpa, .{ .name = line[0..name_end], .labels = labels, .value = v });
        }
        return s;
    }

    fn parseValue(t: []const u8) ?f64 {
        if (std.mem.eql(u8, t, "NaN") or std.mem.eql(u8, t, "+Inf") or std.mem.eql(u8, t, "-Inf") or std.mem.eql(u8, t, "Inf")) return null;
        return std.fmt.parseFloat(f64, t) catch null;
    }

    /// The series `name` with no labels, else the first one.
    pub fn get(s: *const Scrape, name: []const u8) ?f64 {
        var first: ?f64 = null;
        for (s.samples.items) |x| {
            if (!std.mem.eql(u8, x.name, name)) continue;
            if (x.labels.len == 0) return x.value;
            if (first == null) first = x.value;
        }
        return first;
    }

    /// The first series of `name` whose labels contain `key="value"`.
    pub fn getLabeled(s: *const Scrape, name: []const u8, key: []const u8, value: []const u8) ?f64 {
        for (s.samples.items) |x| {
            if (!std.mem.eql(u8, x.name, name)) continue;
            const v = labelValue(x.labels, key) orelse continue;
            if (std.mem.eql(u8, v, value)) return x.value;
        }
        return null;
    }

    /// Sum over `name` series; `status_5xx_only` keeps `status` label values that are server errors
    /// (`internal`, `unavailable`, `data-loss`, `unknown`, `deadline-exceeded`, or 5xx numbers).
    pub fn sum(s: *const Scrape, name: []const u8, only_errors: bool) f64 {
        var t: f64 = 0;
        for (s.samples.items) |x| {
            if (!std.mem.eql(u8, x.name, name)) continue;
            if (only_errors) {
                const st = labelValue(x.labels, "status") orelse continue;
                if (!isServerError(st)) continue;
            }
            t += x.value;
        }
        return t;
    }
};

/// Float from a scrape to u64: negative, NaN and fractions clamp, huge values saturate (never panics).
pub fn toU64(v: f64) u64 {
    return if (!(v > 0)) 0 else if (v >= 1.8e19) std.math.maxInt(u64) else @intFromFloat(v);
}

pub fn isServerError(status: []const u8) bool {
    const names = [_][]const u8{ "internal", "unavailable", "data-loss", "unknown", "deadline-exceeded" };
    for (names) |n| if (std.mem.eql(u8, status, n)) return true;
    const code = std.fmt.parseInt(u16, status, 10) catch return false;
    return code >= 500;
}

/// Value of label `key` in `labels` (the text between the braces), quotes stripped, no unescape.
pub fn labelValue(labels: []const u8, key: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < labels.len) {
        while (i < labels.len and (labels[i] == ',' or labels[i] == ' ')) i += 1;
        const eq = std.mem.indexOfScalarPos(u8, labels, i, '=') orelse return null;
        const k = std.mem.trim(u8, labels[i..eq], " ");
        if (eq + 1 >= labels.len or labels[eq + 1] != '"') return null;
        var j = eq + 2;
        while (j < labels.len and labels[j] != '"') : (j += 1) {
            if (labels[j] == '\\') j += 1;
        }
        if (j >= labels.len) return null;
        if (std.mem.eql(u8, k, key)) return labels[eq + 2 .. j];
        i = j + 1;
    }
    return null;
}

// ------------------------------------------------------------------------------ alert states

pub const NoticeKind = enum { fire, repeat, resolve };

pub const Notice = struct {
    kind: NoticeKind,
    key: []const u8,
    severity: Severity,
    /// Seconds the condition has held (fire/repeat) or held before it cleared (resolve).
    held_s: u64,
};

/// Debounced alert states keyed by name. A condition must be bad for `for_s` before it fires; it
/// repeats every `repeat_s`; it resolves after being good for `clear_s` (so a flapping series
/// does not send a storm).
pub const Book = struct {
    gpa: std.mem.Allocator,
    map: std.StringHashMapUnmanaged(St) = .empty,

    const St = struct {
        bad_since: ?u64 = null,
        good_since: ?u64 = null,
        firing: bool = false,
        last_sent: u64 = 0,
        fired_at: u64 = 0,
        sev: Severity = .warn,
    };

    pub fn init(gpa: std.mem.Allocator) Book {
        return .{ .gpa = gpa };
    }

    pub fn deinit(b: *Book) void {
        var it = b.map.iterator();
        while (it.next()) |e| b.gpa.free(e.key_ptr.*);
        b.map.deinit(b.gpa);
    }

    pub const Opts = struct { for_s: u64 = 0, repeat_s: u64 = 1800, clear_s: u64 = 30 };

    pub fn isFiring(b: *const Book, key: []const u8) bool {
        return if (b.map.get(key)) |s| s.firing else false;
    }

    pub fn observe(b: *Book, key: []const u8, bad: bool, sev: Severity, now_s: u64, o: Opts) !?Notice {
        const gop = try b.map.getOrPut(b.gpa, key);
        if (!gop.found_existing) {
            errdefer _ = b.map.remove(key);
            gop.key_ptr.* = try b.gpa.dupe(u8, key);
            gop.value_ptr.* = .{};
        }
        const s = gop.value_ptr;
        const k = gop.key_ptr.*;
        if (bad) {
            s.good_since = null;
            if (s.bad_since == null) s.bad_since = now_s;
            const held = now_s - s.bad_since.?;
            if (!s.firing) {
                if (held >= o.for_s) {
                    s.firing = true;
                    s.sev = sev;
                    s.fired_at = now_s;
                    s.last_sent = now_s;
                    return .{ .kind = .fire, .key = k, .severity = sev, .held_s = held };
                }
            } else if (now_s - s.last_sent >= o.repeat_s or (sev == .crit and s.sev == .warn)) {
                s.sev = sev;
                s.last_sent = now_s;
                return .{ .kind = .repeat, .key = k, .severity = sev, .held_s = held };
            }
        } else {
            s.bad_since = null;
            if (s.firing) {
                if (s.good_since == null) s.good_since = now_s;
                if (now_s - s.good_since.? >= o.clear_s) {
                    s.firing = false;
                    s.good_since = null;
                    return .{ .kind = .resolve, .key = k, .severity = s.sev, .held_s = now_s - s.fired_at };
                }
            } else s.good_since = null;
        }
        return null;
    }
};

// ------------------------------------------------------------------------------------- rules

pub const Op = enum {
    gt,
    lt,
    ge,
    le,
    eq,
    ne,
    pub fn parse(t: []const u8) ?Op {
        const m = [_]struct { []const u8, Op }{ .{ ">", .gt }, .{ "<", .lt }, .{ ">=", .ge }, .{ "<=", .le }, .{ "==", .eq }, .{ "!=", .ne } };
        for (m) |e| if (std.mem.eql(u8, t, e[0])) return e[1];
        return null;
    }
    pub fn holds(o: Op, v: f64, thr: f64) bool {
        return switch (o) {
            .gt => v > thr,
            .lt => v < thr,
            .ge => v >= thr,
            .le => v <= thr,
            .eq => v == thr,
            .ne => v != thr,
        };
    }
    pub fn text(o: Op) []const u8 {
        return switch (o) {
            .gt => ">",
            .lt => "<",
            .ge => ">=",
            .le => "<=",
            .eq => "==",
            .ne => "!=",
        };
    }
};

/// `name:metric[{k=v}]:op:threshold[:for_s[:warn|crit]]`. A missing series counts as bad.
pub const GaugeRule = struct {
    name: []const u8,
    metric: []const u8,
    label_key: []const u8 = "",
    label_val: []const u8 = "",
    op: Op,
    threshold: f64,
    for_s: u64 = 0,
    sev: Severity = .crit,

    pub fn parse(spec: []const u8) ?GaugeRule {
        var it = std.mem.splitScalar(u8, spec, ':');
        const name = it.next() orelse return null;
        var metric = it.next() orelse return null;
        const op = Op.parse(it.next() orelse return null) orelse return null;
        const thr = std.fmt.parseFloat(f64, it.next() orelse return null) catch return null;
        var r: GaugeRule = .{ .name = name, .metric = metric, .op = op, .threshold = thr };
        if (std.mem.indexOfScalar(u8, metric, '{')) |b| {
            const e = std.mem.indexOfScalar(u8, metric, '}') orelse return null;
            const kv = metric[b + 1 .. e];
            const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return null;
            r.label_key = kv[0..eq];
            r.label_val = std.mem.trim(u8, kv[eq + 1 ..], "\"");
            metric = metric[0..b];
            r.metric = metric;
        }
        if (it.next()) |f| r.for_s = std.fmt.parseInt(u64, f, 10) catch return null;
        if (it.next()) |sv| r.sev = if (std.mem.eql(u8, sv, "warn")) .warn else if (std.mem.eql(u8, sv, "crit")) .crit else return null;
        return r;
    }

    /// null: the series is missing.
    pub fn value(r: GaugeRule, sc: *const Scrape) ?f64 {
        return if (r.label_key.len > 0) sc.getLabeled(r.metric, r.label_key, r.label_val) else sc.get(r.metric);
    }
};

pub const StakeEntry = struct { id: []const u8, stake: u64 };

/// Stake table: `id stake` per line (`#` comments). Slices point into the file text.
pub fn parseStake(gpa: std.mem.Allocator, text: []const u8) !std.ArrayList(StakeEntry) {
    var out: std.ArrayList(StakeEntry) = .empty;
    errdefer out.deinit(gpa);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| {
        const t = std.mem.trim(u8, l, " \t\r");
        if (t.len == 0 or t[0] == '#') continue;
        var it = std.mem.tokenizeAny(u8, t, " \t=");
        const id = it.next() orelse continue;
        const st = std.fmt.parseInt(u64, it.next() orelse continue, 10) catch continue;
        try out.append(gpa, .{ .id = id, .stake = st });
    }
    return out;
}

/// `name:metric:label:op:threshold:max_bad_pct[:for_s[:warn|crit]]`: peers are the values of `label`
/// on `metric`; a peer is bad when its value satisfies `op threshold` or its series is missing; the
/// rule is bad when the bad peers hold more than `max_bad_pct` percent of the stake.
pub const StakeRule = struct {
    name: []const u8,
    metric: []const u8,
    label: []const u8,
    op: Op,
    threshold: f64,
    max_bad_pct: f64,
    for_s: u64 = 0,
    sev: Severity = .crit,

    pub fn parse(spec: []const u8) ?StakeRule {
        var it = std.mem.splitScalar(u8, spec, ':');
        var r: StakeRule = .{
            .name = it.next() orelse return null,
            .metric = it.next() orelse return null,
            .label = it.next() orelse return null,
            .op = Op.parse(it.next() orelse return null) orelse return null,
            .threshold = std.fmt.parseFloat(f64, it.next() orelse return null) catch return null,
            .max_bad_pct = std.fmt.parseFloat(f64, it.next() orelse return null) catch return null,
        };
        if (it.next()) |f| r.for_s = std.fmt.parseInt(u64, f, 10) catch return null;
        if (it.next()) |sv| r.sev = if (std.mem.eql(u8, sv, "warn")) .warn else if (std.mem.eql(u8, sv, "crit")) .crit else return null;
        return r;
    }

    pub const Result = struct { bad_stake: u64, total: u64, bad_pct: f64, bad: bool };

    pub fn evaluate(r: StakeRule, sc: *const Scrape, table: []const StakeEntry) Result {
        var total: u64 = 0;
        var bad_stake: u64 = 0;
        for (table) |e| {
            total += e.stake;
            const v = sc.getLabeled(r.metric, r.label, e.id);
            if (v == null or r.op.holds(v.?, r.threshold)) bad_stake += e.stake;
        }
        const pct = if (total == 0) 0 else @as(f64, @floatFromInt(bad_stake)) * 100.0 / @as(f64, @floatFromInt(total));
        return .{ .bad_stake = bad_stake, .total = total, .bad_pct = pct, .bad = total > 0 and pct > r.max_bad_pct };
    }
};

// ---------------------------------------------------------------------------------- node checks

pub const Limits = struct {
    lag_warn_s: u64 = 30,
    lag_crit_s: u64 = 120,
    stall_s: u64 = 90,
    behind: u64 = 200,
    min_peers: u64 = 2,
    serve_err_pct: f64 = 5.0,
    serve_min_requests: u64 = 200,
    standby_gap: u64 = 50,
};

pub const Finding = struct {
    /// Alert key: `<target>/<check>`.
    key: []const u8,
    bad: bool,
    sev: Severity,
    detail: []const u8,
};

/// Per-target memory between scrapes (counters, last change of the checkpoint).
pub const NodeState = struct {
    last_cp: u64 = 0,
    cp_changed_s: u64 = 0,
    seen: bool = false,
    req_total: f64 = 0,
    req_err: f64 = 0,
    have_req: bool = false,
};

/// One finding per check for one target. Text goes into `arena`; the checks that need a
/// metric the node does not report stay good (a deepwave without p2p has no peer floor).
pub fn nodeFindings(arena: std.mem.Allocator, name: []const u8, st: *NodeState, sc: ?*const Scrape, now_s: u64, now_ms: u64, lim: Limits, out: *std.ArrayList(Finding)) !void {
    const K = struct {
        fn key(a: std.mem.Allocator, n: []const u8, c: []const u8) ![]u8 {
            return std.fmt.allocPrint(a, "{s}/{s}", .{ n, c });
        }
    };
    const s = sc orelse {
        try out.append(arena, .{ .key = try K.key(arena, name, "scrape"), .bad = true, .sev = .crit, .detail = "metrics endpoint does not answer" });
        return;
    };
    try out.append(arena, .{ .key = try K.key(arena, name, "scrape"), .bad = false, .sev = .crit, .detail = "" });

    const exec = s.get("last_executed_checkpoint");
    const ts = s.get("last_executed_checkpoint_timestamp_ms");
    // lag
    if (ts) |t| {
        const t_ms = toU64(t);
        const lag_s: u64 = if (now_ms > t_ms) (now_ms - t_ms) / 1000 else 0;
        const sev: Severity = if (lag_s >= lim.lag_crit_s) .crit else .warn;
        try out.append(arena, .{ .key = try K.key(arena, name, "lag"), .bad = lag_s >= lim.lag_warn_s, .sev = sev, .detail = try std.fmt.allocPrint(arena, "newest executed checkpoint is {d} s old (limit {d} s)", .{ lag_s, lim.lag_warn_s }) });
    } else {
        try out.append(arena, .{ .key = try K.key(arena, name, "lag"), .bad = true, .sev = .crit, .detail = "node reports no executed checkpoint" });
    }
    // stall
    if (exec) |e| {
        const cp: u64 = toU64(e);
        if (!st.seen or cp != st.last_cp) {
            st.seen = true;
            st.last_cp = cp;
            st.cp_changed_s = now_s;
        }
        const idle = now_s - st.cp_changed_s;
        try out.append(arena, .{ .key = try K.key(arena, name, "stall"), .bad = idle >= lim.stall_s, .sev = .crit, .detail = try std.fmt.allocPrint(arena, "checkpoint {d} has not moved for {d} s", .{ cp, idle }) });
    }
    // behind the source
    if (exec != null) if (s.get("highest_known_checkpoint")) |k| {
        const known: u64 = toU64(k);
        const cp: u64 = toU64(exec.?);
        const gap = if (known > cp) known - cp else 0;
        try out.append(arena, .{ .key = try K.key(arena, name, "behind"), .bad = gap > lim.behind, .sev = .warn, .detail = try std.fmt.allocPrint(arena, "{d} checkpoints behind the highest known (limit {d})", .{ gap, lim.behind }) });
    };
    // peers
    if (s.get("zui_p2p_known_peers") != null) {
        const up: u64 = toU64(s.sum("zui_p2p_known_peers", false));
        try out.append(arena, .{ .key = try K.key(arena, name, "peers"), .bad = up < lim.min_peers, .sev = if (up == 0) .crit else .warn, .detail = try std.fmt.allocPrint(arena, "{d} known p2p peers (floor {d})", .{ up, lim.min_peers }) });
    }
    // serve errors: share of server-error answers since the previous scrape
    {
        const total = s.sum("rpc_requests", false);
        const errs = s.sum("rpc_requests", true);
        if (st.have_req and total >= st.req_total and errs >= st.req_err) {
            const dt = total - st.req_total;
            const de = errs - st.req_err;
            const bad = dt >= @as(f64, @floatFromInt(lim.serve_min_requests)) and de * 100.0 / dt > lim.serve_err_pct;
            if (dt >= @as(f64, @floatFromInt(lim.serve_min_requests))) {
                try out.append(arena, .{ .key = try K.key(arena, name, "serve"), .bad = bad, .sev = .warn, .detail = try std.fmt.allocPrint(arena, "{d:.1}% of {d:.0} RPC answers were server errors (limit {d:.1}%)", .{ if (dt > 0) de * 100.0 / dt else 0, dt, lim.serve_err_pct }) });
            }
        }
        // Counters reset on a restart: re-baseline instead of reading a negative delta.
        if (!st.have_req or total < st.req_total or dt_ok(total, st.req_total, lim)) {
            st.req_total = total;
            st.req_err = errs;
            st.have_req = true;
        }
    }
    // state integrity checks the node runs on itself (ECMH state hash per epoch, SUI conservation)
    {
        const names = [_][]const u8{ "zui_state_hash_mismatches", "zui_state_hash_failed", "zui_sui_conservation_mismatches", "zui_sui_conservation_failed" };
        var bad_name: ?[]const u8 = null;
        var seen = false;
        for (names) |n| if (s.get(n)) |v| {
            seen = true;
            if (v != 0 and bad_name == null) bad_name = n;
        };
        if (seen) try out.append(arena, .{ .key = try K.key(arena, name, "state"), .bad = bad_name != null, .sev = .crit, .detail = try std.fmt.allocPrint(arena, "{s} is not zero: the state differs from the certified one", .{bad_name orelse ""}) });
    }
    if (s.get("zui_store_age_failed")) |f| {
        try out.append(arena, .{ .key = try K.key(arena, name, "store"), .bad = f != 0, .sev = .crit, .detail = "age-out failed (zui_store_age_failed)" });
    }
}

/// The serve window moves on once it holds enough requests to judge.
fn dt_ok(total: f64, base: f64, lim: Limits) bool {
    return total - base >= @as(f64, @floatFromInt(lim.serve_min_requests));
}

/// Primary vs standby checkpoint gap.
pub fn standbyFinding(arena: std.mem.Allocator, primary: ?*const Scrape, standby: ?*const Scrape, lim: Limits, out: *std.ArrayList(Finding)) !void {
    const p = (primary orelse return).get("last_executed_checkpoint") orelse return;
    const s = (standby orelse return).get("last_executed_checkpoint") orelse return;
    const a: u64 = toU64(p);
    const b: u64 = toU64(s);
    const gap = if (a > b) a - b else 0; // a standby ahead of the primary is not a problem
    try out.append(arena, .{ .key = "pair/standby-gap", .bad = gap > lim.standby_gap, .sev = .warn, .detail = try std.fmt.allocPrint(arena, "standby is {d} checkpoints behind the primary (limit {d})", .{ gap, lim.standby_gap }) });
}

// ------------------------------------------------------------------------------------- tests

const sample_text =
    \\# HELP last_executed_checkpoint Last executed checkpoint
    \\# TYPE last_executed_checkpoint gauge
    \\last_executed_checkpoint 1000
    \\last_executed_checkpoint_timestamp_ms 1700000000000
    \\highest_known_checkpoint 1010
    \\zui_p2p_known_peers{v="1"} 1
    \\rpc_requests{path="/sui.rpc.v2.LedgerService/GetCheckpoint",status="ok"} 900
    \\rpc_requests{path="/sui.rpc.v2.LedgerService/GetCheckpoint",status="internal"} 100
    \\consensus_peer_round{authority="a1"} 10
    \\consensus_peer_round{authority="a2"} 99
    \\weird{a="x\"}y",b="z"} 5
    \\
;

test "parse: names, labels, values, quoted braces" {
    var sc = try Scrape.parse(std.testing.allocator, sample_text);
    defer sc.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(f64, 1000), sc.get("last_executed_checkpoint").?);
    try std.testing.expectEqual(@as(f64, 99), sc.getLabeled("consensus_peer_round", "authority", "a2").?);
    try std.testing.expectEqual(@as(f64, 1000), sc.sum("rpc_requests", false));
    try std.testing.expectEqual(@as(f64, 100), sc.sum("rpc_requests", true));
    try std.testing.expectEqual(@as(f64, 5), sc.getLabeled("weird", "b", "z").?);
    try std.testing.expect(sc.get("nothing") == null);
}

test "book: debounce, repeat, resolve" {
    var b = Book.init(std.testing.allocator);
    defer b.deinit();
    const o: Book.Opts = .{ .for_s = 10, .repeat_s = 100, .clear_s = 5 };
    try std.testing.expect((try b.observe("x", true, .warn, 0, o)) == null);
    try std.testing.expect((try b.observe("x", true, .warn, 9, o)) == null);
    try std.testing.expect((try b.observe("x", false, .warn, 10, o)) == null); // flap: reset
    try std.testing.expect((try b.observe("x", true, .warn, 11, o)) == null);
    const f = (try b.observe("x", true, .warn, 21, o)).?;
    try std.testing.expectEqual(NoticeKind.fire, f.kind);
    try std.testing.expect((try b.observe("x", true, .warn, 50, o)) == null);
    // escalation repeats at once
    try std.testing.expectEqual(NoticeKind.repeat, (try b.observe("x", true, .crit, 60, o)).?.kind);
    try std.testing.expectEqual(NoticeKind.repeat, (try b.observe("x", true, .crit, 160, o)).?.kind);
    try std.testing.expect((try b.observe("x", false, .warn, 170, o)) == null);
    try std.testing.expect((try b.observe("x", true, .warn, 172, o)) == null); // blip while clearing
    try std.testing.expect((try b.observe("x", false, .warn, 180, o)) == null);
    const r = (try b.observe("x", false, .warn, 186, o)).?;
    try std.testing.expectEqual(NoticeKind.resolve, r.kind);
    try std.testing.expect(!b.isFiring("x"));
}

test "node findings: lag, stall, peers, serve errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const arena = arena_i.allocator();
    var sc = try Scrape.parse(std.testing.allocator, sample_text);
    defer sc.deinit(std.testing.allocator);
    var st: NodeState = .{};
    var out: std.ArrayList(Finding) = .empty;
    const lim: Limits = .{};
    // 200 s after the checkpoint timestamp: crit lag; first scrape never says stall
    try nodeFindings(arena, "zui", &st, &sc, 1000, 1700000200000, lim, &out);
    var lag: ?Finding = null;
    var peers: ?Finding = null;
    for (out.items) |f| {
        if (std.mem.endsWith(u8, f.key, "/lag")) lag = f;
        if (std.mem.endsWith(u8, f.key, "/peers")) peers = f;
        if (std.mem.endsWith(u8, f.key, "/stall")) try std.testing.expect(!f.bad);
    }
    try std.testing.expect(lag.?.bad and lag.?.sev == .crit);
    try std.testing.expect(peers.?.bad and peers.?.sev == .warn);
    // 100 s later with the same checkpoint: stall
    out.clearRetainingCapacity();
    try nodeFindings(arena, "zui", &st, &sc, 1100, 1700000300000, lim, &out);
    for (out.items) |f| if (std.mem.endsWith(u8, f.key, "/stall")) try std.testing.expect(f.bad);
    // unreachable
    out.clearRetainingCapacity();
    try nodeFindings(arena, "zui", &st, null, 1200, 0, lim, &out);
    try std.testing.expect(out.items.len == 1 and out.items[0].bad and out.items[0].sev == .crit);
}

test "rules: gauge spec and stake-weighted rule" {
    const g = GaugeRule.parse("round_lag:consensus_round_lag:>:5:30:warn").?;
    try std.testing.expect(g.op == .gt and g.threshold == 5 and g.for_s == 30 and g.sev == .warn);
    const g2 = GaugeRule.parse("vote:consensus_votes{authority=\"me\"}:<:1").?;
    try std.testing.expectEqualStrings("authority", g2.label_key);
    try std.testing.expectEqualStrings("me", g2.label_val);
    try std.testing.expect(GaugeRule.parse("bad") == null);
    var sc = try Scrape.parse(std.testing.allocator, sample_text);
    defer sc.deinit(std.testing.allocator);
    var tbl = try parseStake(std.testing.allocator, "a1 300\na2 600\na3 100\n# c\n");
    defer tbl.deinit(std.testing.allocator);
    const r = StakeRule.parse("lag:consensus_peer_round:authority:<:50:33").?;
    const res = r.evaluate(&sc, tbl.items);
    // a1 (10 < 50) and a3 (missing) are bad: 400 of 1000
    try std.testing.expectEqual(@as(u64, 400), res.bad_stake);
    try std.testing.expect(res.bad);
    const lax = StakeRule.parse("lag:consensus_peer_round:authority:<:50:40").?;
    try std.testing.expect(!lax.evaluate(&sc, tbl.items).bad);
}

test "standby gap only counts a lagging standby" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    var a = try Scrape.parse(std.testing.allocator, "last_executed_checkpoint 1000\n");
    defer a.deinit(std.testing.allocator);
    var b = try Scrape.parse(std.testing.allocator, "last_executed_checkpoint 900\n");
    defer b.deinit(std.testing.allocator);
    var out: std.ArrayList(Finding) = .empty;
    try standbyFinding(arena_i.allocator(), &a, &b, .{}, &out);
    try std.testing.expect(out.items[0].bad);
    out.clearRetainingCapacity();
    try standbyFinding(arena_i.allocator(), &b, &a, .{}, &out);
    try std.testing.expect(!out.items[0].bad);
}
