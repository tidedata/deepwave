//! Metrics push (lane ops-metrics): sui-metrics-push-client. Every `interval` (sui-node: 60 s,
//! fullnode.yaml `metrics.push-interval-seconds`) the whole /metrics registry goes to
//! `metrics.push-url` as an HTTP POST:
//!
//!   body     prometheus `ProtobufEncoder`: length-delimited `io.prometheus.client.MetricFamily`
//!            messages, every metric stamped with the collection time (`timestamp_ms`), then
//!            snappy-compressed as one raw block (`snap::raw::Encoder`)
//!   headers  Content-Encoding: snappy
//!            Content-Type: application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited
//!
//! A failed push logs a warning (an error from the tenth failure in a row) and the client is
//! made anew, as sui-node. deepwave renders text, so the protobuf is built from the text exposition
//! (`encodeText`): families, label pairs, histogram buckets, counters and gauges.
//!
//! Not built: sui-node presents a self-signed client certificate made from the network key
//! (mTLS, what Mysten's metrics-proxy checks). std.http has no client certificates; a proxy
//! that accepts plain HTTP or server-side TLS works.
const std = @import("std");
const Allocator = std.mem.Allocator;
const snappy = @import("net").snappy;
const netguard = @import("netguard.zig");

pub const content_type = "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited";

const Kind = enum(u8) { counter = 0, gauge = 1, summary = 2, untyped = 3, histogram = 4 };

// ------------------------------------------------------------------ protobuf writer

fn varint(out: *std.ArrayList(u8), a: Allocator, v: u64) !void {
    var x = v;
    while (x >= 0x80) : (x >>= 7) try out.append(a, @as(u8, @truncate(x)) | 0x80);
    try out.append(a, @truncate(x));
}

fn tag(out: *std.ArrayList(u8), a: Allocator, field: u32, wire: u3) !void {
    try varint(out, a, (@as(u64, field) << 3) | wire);
}

fn bytesField(out: *std.ArrayList(u8), a: Allocator, field: u32, b: []const u8) !void {
    try tag(out, a, field, 2);
    try varint(out, a, b.len);
    try out.appendSlice(a, b);
}

fn doubleField(out: *std.ArrayList(u8), a: Allocator, field: u32, v: f64) !void {
    try tag(out, a, field, 1);
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, @bitCast(v), .little);
    try out.appendSlice(a, &b);
}

fn uintField(out: *std.ArrayList(u8), a: Allocator, field: u32, v: u64) !void {
    try tag(out, a, field, 0);
    try varint(out, a, v);
}

// ------------------------------------------------------------------ text parsing

const Label = struct { name: []const u8, value: []const u8 };

const Sample = struct {
    name: []const u8,
    labels: []Label,
    value: f64,
};

fn parseValue(s: []const u8) ?f64 {
    if (std.mem.eql(u8, s, "+Inf")) return std.math.inf(f64);
    if (std.mem.eql(u8, s, "-Inf")) return -std.math.inf(f64);
    if (std.mem.eql(u8, s, "NaN")) return std.math.nan(f64);
    return std.fmt.parseFloat(f64, s) catch null;
}

/// `name{a="x",b="y"} value [timestamp]`; label values unescaped into `a`.
fn parseSample(a: Allocator, line: []const u8) !?Sample {
    var i: usize = 0;
    while (i < line.len and line[i] != '{' and line[i] != ' ') i += 1;
    const name = line[0..i];
    var labels: std.ArrayList(Label) = .empty;
    if (i < line.len and line[i] == '{') {
        i += 1;
        while (i < line.len and line[i] != '}') {
            const ls = i;
            while (i < line.len and line[i] != '=') i += 1;
            if (i + 1 >= line.len or line[i + 1] != '"') return null;
            const lname = line[ls..i];
            i += 2;
            var v: std.ArrayList(u8) = .empty;
            while (i < line.len and line[i] != '"') : (i += 1) {
                if (line[i] == '\\' and i + 1 < line.len) {
                    i += 1;
                    try v.append(a, if (line[i] == 'n') '\n' else line[i]);
                } else try v.append(a, line[i]);
            }
            if (i >= line.len) return null;
            i += 1; // closing quote
            try labels.append(a, .{ .name = lname, .value = v.items });
            if (i < line.len and line[i] == ',') i += 1;
        }
        if (i >= line.len) return null;
        i += 1; // '}'
    }
    var rest = std.mem.tokenizeScalar(u8, line[i..], ' ');
    const vs = rest.next() orelse return null;
    return .{ .name = name, .labels = labels.items, .value = parseValue(vs) orelse return null };
}

const Family = struct {
    name: []const u8,
    help: []const u8 = "",
    kind: Kind = .untyped,
    metrics: std.ArrayList(u8) = .empty,
    /// Histogram being assembled: its labels (without `le`), buckets, sum.
    h_labels: ?[]Label = null,
    h_buckets: std.ArrayList([2]f64) = .empty,
    h_sum: f64 = 0,
};

fn sameLabels(x: []const Label, y: []const Label) bool {
    if (x.len != y.len) return false;
    for (x, y) |p, q| if (!std.mem.eql(u8, p.name, q.name) or !std.mem.eql(u8, p.value, q.value)) return false;
    return true;
}

fn labelPairs(m: *std.ArrayList(u8), a: Allocator, labels: []const Label) !void {
    for (labels) |l| {
        var lp: std.ArrayList(u8) = .empty;
        try bytesField(&lp, a, 1, l.name);
        try bytesField(&lp, a, 2, l.value);
        try bytesField(m, a, 1, lp.items);
    }
}

/// One `Metric` message appended to the family.
fn addMetric(f: *Family, a: Allocator, labels: []const Label, body_field: u32, body: []const u8, ts_ms: i64) !void {
    var m: std.ArrayList(u8) = .empty;
    try labelPairs(&m, a, labels);
    try bytesField(&m, a, body_field, body);
    try uintField(&m, a, 6, @bitCast(ts_ms));
    try bytesField(&f.metrics, a, 4, m.items);
}

fn flushHistogram(f: *Family, a: Allocator, count: f64, ts_ms: i64) !void {
    const labels = f.h_labels orelse return;
    var h: std.ArrayList(u8) = .empty;
    try uintField(&h, a, 1, @intFromFloat(@max(count, 0)));
    try doubleField(&h, a, 2, f.h_sum);
    for (f.h_buckets.items) |b| {
        if (std.math.isInf(b[0])) continue; // +Inf is implied by sample_count
        var bk: std.ArrayList(u8) = .empty;
        try uintField(&bk, a, 1, @intFromFloat(@max(b[1], 0)));
        try doubleField(&bk, a, 2, b[0]);
        try bytesField(&h, a, 3, bk.items);
    }
    try addMetric(f, a, labels, 7, h.items, ts_ms);
    f.h_labels = null;
    f.h_buckets.clearRetainingCapacity();
    f.h_sum = 0;
}

fn finishFamily(out: *std.ArrayList(u8), a: Allocator, f: *Family) !void {
    if (f.metrics.items.len == 0) return;
    var mf: std.ArrayList(u8) = .empty;
    try bytesField(&mf, a, 1, f.name);
    if (f.help.len > 0) try bytesField(&mf, a, 2, f.help);
    try uintField(&mf, a, 3, @intFromEnum(f.kind));
    try mf.appendSlice(a, f.metrics.items);
    try varint(out, a, mf.items.len);
    try out.appendSlice(a, mf.items);
}

fn kindOf(s: []const u8) Kind {
    if (std.mem.eql(u8, s, "counter")) return .counter;
    if (std.mem.eql(u8, s, "gauge")) return .gauge;
    if (std.mem.eql(u8, s, "histogram")) return .histogram;
    if (std.mem.eql(u8, s, "summary")) return .summary;
    return .untyped;
}

/// The text exposition as delimited `MetricFamily` protobufs, each metric stamped `ts_ms`.
pub fn encodeText(a: Allocator, text: []const u8, ts_ms: i64) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var cur: ?Family = null;
    var help_name: []const u8 = "";
    var help_text: []const u8 = "";
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "# HELP ")) {
            const r = line[7..];
            const sp = std.mem.indexOfScalar(u8, r, ' ') orelse r.len;
            help_name = r[0..sp];
            help_text = if (sp < r.len) r[sp + 1 ..] else "";
            continue;
        }
        if (std.mem.startsWith(u8, line, "# TYPE ")) {
            var it = std.mem.tokenizeScalar(u8, line[7..], ' ');
            const name = it.next() orelse continue;
            const k = kindOf(it.next() orelse "untyped");
            if (cur) |*f| try finishFamily(&out, a, f);
            cur = .{ .name = name, .kind = k, .help = if (std.mem.eql(u8, help_name, name)) help_text else "" };
            continue;
        }
        if (line[0] == '#') continue;
        const s = (try parseSample(a, line)) orelse continue;
        // a sample outside the current family starts an untyped one
        const in_family = if (cur) |*f| blk: {
            if (std.mem.eql(u8, s.name, f.name)) break :blk true;
            if (f.kind == .histogram and std.mem.startsWith(u8, s.name, f.name)) {
                const suf = s.name[f.name.len..];
                break :blk std.mem.eql(u8, suf, "_bucket") or std.mem.eql(u8, suf, "_sum") or std.mem.eql(u8, suf, "_count");
            }
            break :blk false;
        } else false;
        if (!in_family) {
            if (cur) |*f| try finishFamily(&out, a, f);
            cur = .{ .name = s.name, .kind = .untyped, .help = if (std.mem.eql(u8, help_name, s.name)) help_text else "" };
        }
        const f = &cur.?;
        switch (f.kind) {
            .histogram => {
                const suf = s.name[f.name.len..];
                if (std.mem.eql(u8, suf, "_bucket")) {
                    var le: f64 = std.math.inf(f64);
                    var rest: std.ArrayList(Label) = .empty;
                    for (s.labels) |l| {
                        if (std.mem.eql(u8, l.name, "le")) le = parseValue(l.value) orelse le else try rest.append(a, l);
                    }
                    if (f.h_labels == null or !sameLabels(f.h_labels.?, rest.items)) f.h_labels = rest.items;
                    try f.h_buckets.append(a, .{ le, s.value });
                } else if (std.mem.eql(u8, suf, "_sum")) {
                    f.h_sum = s.value;
                    if (f.h_labels == null) f.h_labels = s.labels;
                } else if (std.mem.eql(u8, suf, "_count")) {
                    if (f.h_labels == null) f.h_labels = s.labels;
                    try flushHistogram(f, a, s.value, ts_ms);
                }
            },
            .counter, .gauge, .untyped, .summary => {
                var b: std.ArrayList(u8) = .empty;
                try doubleField(&b, a, 1, s.value);
                const field: u32 = switch (f.kind) {
                    .counter => 3,
                    .gauge => 2,
                    else => 5,
                };
                try addMetric(f, a, s.labels, field, b.items, ts_ms);
            },
        }
    }
    if (cur) |*f| try finishFamily(&out, a, f);
    return out.items;
}

/// `snap::raw::Encoder::compress_vec`.
pub fn compress(a: Allocator, raw: []const u8) ![]u8 {
    const out = try a.alloc(u8, snappy.maxCompressedLen(raw.len));
    return out[0..snappy.compressBlock(raw, out)];
}

pub const Source = struct {
    ctx: *anyopaque,
    render: *const fn (ctx: *anyopaque, w: *std.Io.Writer) anyerror!void,
};

pub const Pusher = struct {
    gpa: Allocator,
    io: std.Io,
    url: []const u8,
    interval_s: u64 = 60,
    source: Source,
    stop: std.atomic.Value(bool) = .init(false),
    /// One push (connect, request, response) is bounded by this, and ends within ~100 ms of
    /// `stop` (netguard.timed). std.http has no timeout: a push to an endpoint that had gone
    /// silent held the thread for ever, and `deinit`, which joins it, with it: the node's stop
    /// waited on the network.
    timeout_ms: u64 = 15_000,
    pushes: std.atomic.Value(u64) = .init(0),
    failures: std.atomic.Value(u64) = .init(0),
    thread: ?std.Thread = null,

    pub fn start(p: *Pusher) !void {
        std.log.info("Started Metrics Push Service push_url={s} interval={d}s", .{ p.url, p.interval_s });
        p.thread = try std.Thread.spawn(.{ .stack_size = 4 << 20 }, run, .{p});
    }

    /// Stops the thread and joins it. A push in flight is ended (see `timeout_ms`), so the join
    /// is a matter of milliseconds whatever the endpoint does.
    pub fn deinit(p: *Pusher) void {
        p.stop.store(true, .release);
        if (p.thread) |t| t.join();
        p.thread = null;
    }

    fn run(p: *Pusher) void {
        var client: std.http.Client = .{ .allocator = p.gpa, .io = p.io };
        defer client.deinit();
        var errors: u32 = 0;
        // tokio::time::interval: the first tick fires at once
        while (!p.stop.load(.acquire)) {
            if (p.pushOnce(&client)) |_| {
                errors = 0;
                _ = p.pushes.fetchAdd(1, .monotonic);
            } else |e| {
                // a push the stop ended is not a failure of the endpoint
                if (p.stop.load(.acquire)) break;
                errors += 1;
                _ = p.failures.fetchAdd(1, .monotonic);
                if (errors >= 10)
                    std.log.err("unable to push metrics: {s}; new client will be created", .{@errorName(e)})
                else
                    std.log.warn("unable to push metrics: {s}; new client will be created", .{@errorName(e)});
                client.deinit();
                client = .{ .allocator = p.gpa, .io = p.io };
            }
            var waited: u64 = 0;
            while (waited < p.interval_s * 10 and !p.stop.load(.acquire)) : (waited += 1)
                std.Io.sleep(p.io, .fromMilliseconds(100), .awake) catch {};
        }
    }

    fn pushOnce(p: *Pusher, client: *std.http.Client) !void {
        var arena = std.heap.ArenaAllocator.init(p.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var text: std.Io.Writer.Allocating = .init(a);
        try p.source.render(p.source.ctx, &text.writer);
        var ts: std.posix.timespec = undefined;
        _ = std.c.clock_gettime(.REALTIME, &ts);
        const now_ms: i64 = @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
        const pb = try encodeText(a, text.writer.buffered(), now_ms);
        const body = try compress(a, pb);
        var resp: std.Io.Writer.Allocating = .init(a);
        var ab: netguard.Abort = .{};
        const status = try netguard.timed(p.io, p.timeout_ms, &p.stop, &ab, postOnce, .{ client, p.url, body, &resp.writer, &ab });
        if (@intFromEnum(status) / 100 != 2) {
            const b = resp.writer.buffered();
            std.log.warn("metrics push failed: [{d}]:{s}", .{ @intFromEnum(status), b[0..@min(b.len, 200)] });
            return error.PushRejected;
        }
    }
};

/// One POST of `body` (as http.zig's `fetchOnce`: the connection's socket is armed in `abort`,
/// so the timeout or a stop wakes a blocked read or write at once).
fn postOnce(c: *std.http.Client, url: []const u8, body: []u8, w: *std.Io.Writer, abort: *netguard.Abort) !std.http.Status {
    const uri = try std.Uri.parse(url);
    var req = try c.request(.POST, uri, .{
        .redirect_behavior = .unhandled,
        .headers = .{ .content_type = .{ .override = content_type }, .accept_encoding = .omit },
        .extra_headers = &.{.{ .name = "content-encoding", .value = "snappy" }},
    });
    defer req.deinit();
    // Any failure: the connection is not reused (see http.zig fetchOnce).
    errdefer if (req.connection) |conn| {
        conn.closing = true;
    };
    try abort.arm(netguard.socketOf(req.connection.?));
    defer abort.disarm();
    try req.sendBodyComplete(body);
    var res = try req.receiveHead(&.{});
    const reader = res.reader(&.{});
    _ = reader.streamRemaining(w) catch |err| switch (err) {
        error.ReadFailed => return res.bodyErr() orelse error.ReadFailed,
        else => |e| return e,
    };
    return res.head.status;
}

test "metrics push: a stop ends a push in flight to an endpoint that never answers; the join does not wait for the network" {
    const io = std.testing.io;
    var srv: netguard.TestServer = undefined;
    try srv.start(io, null); // accepts, never answers
    var srv_up = true;
    defer if (srv_up) srv.stop();
    var ub: [64]u8 = undefined;
    const R = struct {
        fn render(_: *anyopaque, w: *std.Io.Writer) anyerror!void {
            try w.writeAll("# TYPE zui_test counter\nzui_test 1\n");
        }
        var ctx: u8 = 0;
    };
    var p: Pusher = .{ .gpa = std.testing.allocator, .io = io, .url = srv.url(&ub), .interval_s = 60, .source = .{ .ctx = &R.ctx, .render = R.render } };
    try p.start();
    // the push is in flight: the endpoint has the connection and says nothing
    var waited: u32 = 0;
    while (srv.accepts.load(.acquire) == 0 and waited < 5000) : (waited += 1) io.sleep(.fromMilliseconds(1), .awake) catch {};
    try std.testing.expect(srv.accepts.load(.acquire) >= 1);
    io.sleep(.fromMilliseconds(100), .awake) catch {};
    // the stop, on its own thread so the test stays bounded if the join hangs
    const J = struct {
        p: *Pusher,
        done_ms: std.atomic.Value(u64) = .init(0),
        fn run(j: *@This()) void {
            j.p.deinit();
            j.done_ms.store(netguard.wallMs(), .release);
        }
    };
    var j: J = .{ .p = &p };
    const t0 = netguard.wallMs();
    const th = try std.Thread.spawn(.{}, J.run, .{&j});
    waited = 0;
    while (j.done_ms.load(.acquire) == 0 and waited < 3000) : (waited += 1) io.sleep(.fromMilliseconds(1), .awake) catch {};
    const in_time = j.done_ms.load(.acquire) != 0;
    // not in time: the endpoint hangs up, which ends the push the old way, and the test fails
    if (!in_time) {
        srv.stop();
        srv_up = false;
    }
    th.join();
    try std.testing.expect(in_time);
    try std.testing.expect(j.done_ms.load(.acquire) - t0 < 1_000);
    // a push the stop ended is not counted against the endpoint
    try std.testing.expectEqual(@as(u64, 0), p.failures.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), p.pushes.load(.monotonic));
}

// ------------------------------------------------------------------ tests

/// Minimal protobuf reader for the tests.
const Reader = struct {
    b: []const u8,
    i: usize = 0,
    fn varint(r: *Reader) u64 {
        var v: u64 = 0;
        var s: u6 = 0;
        while (true) {
            const c = r.b[r.i];
            r.i += 1;
            v |= @as(u64, c & 0x7f) << s;
            if (c < 0x80) return v;
            s += 7;
        }
    }
    fn bytes(r: *Reader) []const u8 {
        const n: usize = @intCast(r.varint());
        defer r.i += n;
        return r.b[r.i..][0..n];
    }
    fn double(r: *Reader) f64 {
        defer r.i += 8;
        return @bitCast(std.mem.readInt(u64, r.b[r.i..][0..8], .little));
    }
};

test "push body: text exposition as delimited MetricFamily protobufs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text =
        \\# HELP uptime uptime of the node service in seconds
        \\# TYPE uptime counter
        \\uptime{chain_identifier="35834a8a",process="fullnode",version="0.1.0-abc"} 5
        \\# HELP last_executed_checkpoint Last executed checkpoint
        \\# TYPE last_executed_checkpoint gauge
        \\last_executed_checkpoint 342933373
        \\# HELP x_latency X
        \\# TYPE x_latency histogram
        \\x_latency_bucket{route="/a",le="0.1"} 1
        \\x_latency_bucket{route="/a",le="1"} 2
        \\x_latency_bucket{route="/a",le="+Inf"} 3
        \\x_latency_sum{route="/a"} 7.5
        \\x_latency_count{route="/a"} 3
        \\zui_store_object_floor_epoch 4
        \\
    ;
    const pb = try encodeText(a, text, 1794125265123);
    var r: Reader = .{ .b = pb };
    var names: std.ArrayList([]const u8) = .empty;
    var kinds: std.ArrayList(u64) = .empty;
    var hist_count: u64 = 0;
    var hist_buckets: usize = 0;
    var gauge_value: f64 = 0;
    var label_values: std.ArrayList([]const u8) = .empty;
    var stamp: u64 = 0;
    while (r.i < pb.len) {
        var mf: Reader = .{ .b = r.bytes() };
        while (mf.i < mf.b.len) {
            const t = mf.varint();
            switch (t >> 3) {
                1 => try names.append(a, mf.bytes()),
                2 => _ = mf.bytes(),
                3 => try kinds.append(a, mf.varint()),
                4 => {
                    var m: Reader = .{ .b = mf.bytes() };
                    while (m.i < m.b.len) {
                        const mt = m.varint();
                        switch (mt >> 3) {
                            1 => {
                                var lp: Reader = .{ .b = m.bytes() };
                                _ = lp.varint();
                                _ = lp.bytes();
                                _ = lp.varint();
                                try label_values.append(a, lp.bytes());
                            },
                            2 => {
                                var g: Reader = .{ .b = m.bytes() };
                                _ = g.varint();
                                gauge_value = g.double();
                            },
                            3, 5 => _ = m.bytes(),
                            6 => stamp = m.varint(),
                            7 => {
                                var h: Reader = .{ .b = m.bytes() };
                                while (h.i < h.b.len) {
                                    const ht = h.varint();
                                    switch (ht >> 3) {
                                        1 => hist_count = h.varint(),
                                        2 => _ = h.double(),
                                        3 => {
                                            _ = h.bytes();
                                            hist_buckets += 1;
                                        },
                                        else => unreachable,
                                    }
                                }
                            },
                            else => unreachable,
                        }
                    }
                },
                else => unreachable,
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 4), names.items.len);
    try std.testing.expectEqualStrings("uptime", names.items[0]);
    try std.testing.expectEqualStrings("x_latency", names.items[2]);
    try std.testing.expectEqualStrings("zui_store_object_floor_epoch", names.items[3]);
    try std.testing.expectEqualSlices(u64, &.{ 0, 1, 4, 3 }, kinds.items);
    try std.testing.expectEqual(@as(f64, 342933373), gauge_value);
    try std.testing.expectEqual(@as(u64, 3), hist_count);
    try std.testing.expectEqual(@as(usize, 2), hist_buckets);
    try std.testing.expectEqual(@as(u64, 1794125265123), stamp);
    try std.testing.expectEqualStrings("35834a8a", label_values.items[0]);
    try std.testing.expectEqualStrings("/a", label_values.items[3]);
    // snappy round trip
    const z = try compress(a, pb);
    const back = try a.alloc(u8, try snappy.blockLen(z));
    try snappy.decompressBlock(z, back);
    try std.testing.expectEqualSlices(u8, pb, back);
}
