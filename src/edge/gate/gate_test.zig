//! The gate against the mock gate service, under a test clock: every step a thread would take
//! is called by hand, so each test is deterministic. Two tests at the end run the real threads
//! with bounded waits.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const contract = @import("contract.zig");
const ident = @import("ident.zig");
const methods_mod = @import("methods.zig");
const state = @import("state.zig");
const spool_mod = @import("spool.zig");
const gate_mod = @import("gate.zig");
const mock_mod = @import("mock.zig");
const Gate = gate_mod.Gate;
const Decision = gate_mod.Decision;
const ns_per_s = std.time.ns_per_s;
const ns_per_ms = std.time.ns_per_ms;

const defs = [_]methods_mod.Def{
    .{ .name = "/a.A/Get" },
    .{ .name = "/a.A/Put" },
    .{ .name = "/a.A/Batch", .kind = .batch },
    .{ .name = "/a.A/Watch", .kind = .stream },
    .{ .name = "/grpc.health.v1.Health/Check", .kind = .free },
};

const token = "test-token-0123456789abcdef-xyz";

const TestClock = struct {
    mono: u64 = 1000 * ns_per_s,
    wall: u64 = 1_794_000_000_000,

    fn monoFn(ctx: ?*anyopaque) u64 {
        const c: *TestClock = @ptrCast(@alignCast(ctx.?));
        return c.mono;
    }
    fn wallFn(ctx: ?*anyopaque) u64 {
        const c: *TestClock = @ptrCast(@alignCast(ctx.?));
        return c.wall;
    }
    fn clock(c: *TestClock) gate_mod.Clock {
        return .{ .ctx = c, .mono = monoFn, .wall = wallFn };
    }
    fn advanceMs(c: *TestClock, ms: u64) void {
        c.mono += ms * ns_per_ms;
        c.wall += ms;
    }
};

const Logs = struct {
    text: std.ArrayList(u8) = .empty,
    lines: u32 = 0,
    errors: u32 = 0,
    lock: state.SpinLock = .{},

    fn write(ctx: *anyopaque, err: bool, line: []const u8) void {
        const l: *Logs = @ptrCast(@alignCast(ctx));
        l.lock.lock();
        defer l.lock.unlock();
        l.text.appendSlice(testing.allocator, line) catch {};
        l.text.append(testing.allocator, '\n') catch {};
        l.lines += 1;
        if (err) l.errors += 1;
    }
};

const Opts = struct {
    dir: ?Io.Dir = null,
    proxies: []const ident.Cidr = &.{},
    key_capacity: u32 = 1024,
    address_capacity: u32 = 1024,
    real_clock: bool = false,
    crash_on_stop: bool = false,
    cut_ns: u64 = 5 * ns_per_s,
    boot_id: []const u8 = "boot1",
    wait_ms: u32 = 150,
    wall: ?u64 = null,
    /// In place of the mock's own transport (a transport that misbehaves on the way).
    transport: ?gate_mod.Transport = null,
};

/// A gate wired to a mock gate service.
const Rig = struct {
    clock: *TestClock,
    mock: *mock_mod.MockGate,
    methods: *methods_mod.Methods,
    logs: *Logs,
    g: *Gate,
    get: u8,
    put: u8,
    batch: u8,
    watch: u8,
    health: u8,

    fn init(o: Opts) !Rig {
        const gpa = testing.allocator;
        const clock = try gpa.create(TestClock);
        clock.* = .{};
        if (o.wall) |w| clock.wall = w;
        const mock = try gpa.create(mock_mod.MockGate);
        mock.* = .{ .gpa = gpa, .token = token, .io = testing.io };
        const m = try gpa.create(methods_mod.Methods);
        m.* = methods_mod.Methods.init(&defs);
        const logs = try gpa.create(Logs);
        logs.* = .{};
        var r: Rig = .{ .clock = clock, .mock = mock, .methods = m, .logs = logs, .g = undefined, .get = m.id("/a.A/Get"), .put = m.id("/a.A/Put"), .batch = m.id("/a.A/Batch"), .watch = m.id("/a.A/Watch"), .health = m.id("/grpc.health.v1.Health/Check") };
        r.g = try r.open(o);
        return r;
    }

    fn open(r: *Rig, o: Opts) !*Gate {
        return Gate.init(testing.allocator, testing.io, .{
            .base_url = "https://gate.example/v1/gate",
            .token = token,
            .edge_id = "e1",
            .dir = o.dir,
            .proxies = o.proxies,
            .methods = r.methods,
            .transport = o.transport orelse r.mock.transport(),
            .clock = if (o.real_clock) .{} else r.clock.clock(),
            .boot_id = o.boot_id,
            .key_capacity = o.key_capacity,
            .address_capacity = o.address_capacity,
            .log = .{ .ctx = r.logs, .write = Logs.write },
            .crash_on_stop = o.crash_on_stop,
            .cut_ns = o.cut_ns,
            .wait_ms = o.wait_ms,
        });
    }

    fn deinit(r: *Rig) void {
        const gpa = testing.allocator;
        r.g.deinit();
        r.mock.deinit();
        r.logs.text.deinit(gpa);
        gpa.destroy(r.logs);
        gpa.destroy(r.methods);
        gpa.destroy(r.mock);
        gpa.destroy(r.clock);
    }

    fn call(r: *Rig, key: []const u8, ip: []const u8, method: u8) Decision {
        return r.g.admit(&.{ .key = key, .peer = ident.Ip.parse(ip).?, .method = method }, r.clock.mono);
    }
    fn callNoWait(r: *Rig, key: []const u8, ip: []const u8, method: u8) Decision {
        return r.g.admit(&.{ .key = key, .peer = ident.Ip.parse(ip).?, .method = method, .may_wait = false }, r.clock.mono);
    }
    /// A call that runs and is counted as answered here.
    fn run(r: *Rig, key: []const u8, ip: []const u8, method: u8) bool {
        const d = r.callNoWait(key, ip, method);
        if (d != .allow) return false;
        r.g.settle(&d.allow, .local, true, r.clock.mono);
        return true;
    }
    /// Runs every queued resolve.
    fn pump(r: *Rig) void {
        while (r.g.resolveStep()) {}
    }
    /// The first call for a key: it waits for the resolve; run the resolve.
    fn learn(r: *Rig, key: []const u8) !void {
        try testing.expect(r.call(key, "198.51.100.1", r.get) == .wait);
        r.pump();
    }
    /// One second passes and the tick runs.
    fn second(r: *Rig) void {
        r.clock.advanceMs(1000);
        r.g.tick(r.clock.mono, r.clock.wall);
    }
    /// Closes the window and posts every batch the gate accepts.
    fn flush(r: *Rig) void {
        r.clock.advanceMs(5000);
        r.g.tick(r.clock.mono, r.clock.wall);
        while (r.g.sendStep()) |wait_ns| if (wait_ns != 0) break;
    }
};

fn okKey(buf: []u8, kid: []const u8, rest: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "{{\"key_id\":\"{s}\",\"status\":\"ok\",\"plan\":\"developer\",\"weights\":{{\"default\":1}},\"forward_weight_mult\":1{s}}}", .{ kid, rest }) catch unreachable;
}

test "gate: every status, with the gate's own text or a plain default" {
    var r = try Rig.init(.{});
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-ok", okKey(&b, "kid_ok", ",\"rps\":100,\"burst\":100,\"max_streams\":2,\"ttl_s\":60,\"lease_units\":null"));
    try r.mock.setKey("key-susp", "{\"key_id\":\"kid_susp\",\"status\":\"suspended\",\"plan\":\"free\",\"ttl_s\":300,\"lease_units\":0,\"message\":\"This key was revoked. See gate.example/keys.\"}");
    try r.mock.setKey("key-exh", "{\"key_id\":\"kid_exh\",\"status\":\"exhausted\",\"plan\":\"free\",\"rps\":25,\"burst\":50,\"ttl_s\":30,\"lease_units\":0}");
    try r.mock.setKey("key-odd", "{\"key_id\":\"kid_odd\",\"status\":\"under_review\",\"ttl_s\":60}");
    // a health check needs no key and no resolve
    const hd = r.call("", "198.51.100.1", r.health);
    try testing.expect(hd == .allow and hd.allow.kind == .free);
    try testing.expect(r.call("key-bad", "198.51.100.1", r.health) == .allow);
    try testing.expectEqual(@as(u32, 0), r.g.pend_n.load(.monotonic));

    inline for (.{ "key-ok", "key-susp", "key-exh", "key-odd", "key-bad" }) |k| try r.learn(k);
    try testing.expectEqual(@as(u32, 5), r.mock.resolves);

    const ok = r.call("key-ok", "198.51.100.1", r.get);
    try testing.expect(ok == .allow and ok.allow.kind == .key);
    try testing.expectEqualStrings("developer", r.g.plans.name(ok.allow.plan));

    const susp = r.call("key-susp", "198.51.100.1", r.get).deny;
    try testing.expectEqual(gate_mod.Reason.suspended, susp.reason);
    try testing.expectEqual(gate_mod.Code.permission_denied, susp.code());
    try testing.expectEqualStrings("This key was revoked. See gate.example/keys.", susp.message);

    const exh = r.call("key-exh", "198.51.100.1", r.get).deny;
    try testing.expectEqual(gate_mod.Reason.exhausted, exh.reason);
    try testing.expectEqual(gate_mod.Code.resource_exhausted, exh.code());
    try testing.expectEqualStrings("out of credits", exh.message);

    const odd = r.call("key-odd", "198.51.100.1", r.get).deny;
    try testing.expectEqual(gate_mod.Reason.unknown_status, odd.reason);
    try testing.expectEqual(gate_mod.Code.permission_denied, odd.code());

    // a key nobody knows is UNAUTHENTICATED; a key that is known and may not call is
    // PERMISSION_DENIED
    const bad = r.call("key-bad", "198.51.100.1", r.get).deny;
    try testing.expectEqual(gate_mod.Reason.invalid, bad.reason);
    try testing.expectEqual(gate_mod.Code.unauthenticated, bad.code());
    try testing.expectEqualStrings("invalid API key", bad.message);

    // a key no gate could know is refused here, without a call
    const junk = r.call("has a space", "198.51.100.1", r.get).deny;
    try testing.expectEqual(gate_mod.Reason.invalid, junk.reason);
    try testing.expectEqual(gate_mod.Code.unauthenticated, junk.code());
    try testing.expectEqual(@as(u32, 5), r.mock.resolves);

    // every answer is cached, the refusals too: a bad key cannot hammer the gate
    for (0..200) |_| _ = r.call("key-bad", "198.51.100.1", r.get);
    try testing.expectEqual(@as(u32, 5), r.mock.resolves);

    // A call refused for its key is nobody's usage: no row is made or changed for it, under the
    // key or under the caller's prefix, and nothing is posted. The node counts it by reason.
    r.g.tick(r.clock.mono, r.clock.wall);
    try testing.expectEqual(@as(u64, 0), r.g.spool.pendingRows());
    r.flush();
    try testing.expectEqual(@as(usize, 0), r.mock.batches.count());
    try testing.expectEqual(@as(u32, 0), r.mock.usage_posts);
    const refused = struct {
        fn of(g: *Gate, reason: gate_mod.Reason) u64 {
            return g.m.denied[@intFromEnum(reason)].load(.monotonic);
        }
    }.of;
    try testing.expectEqual(@as(u64, 202), refused(r.g, .invalid)); // key-bad once, the junk key, 200 more
    try testing.expectEqual(@as(u64, 1), refused(r.g, .suspended));
    try testing.expectEqual(@as(u64, 1), refused(r.g, .exhausted));
    try testing.expectEqual(@as(u64, 1), refused(r.g, .unknown_status));
    try testing.expectEqual(@as(u64, 0), refused(r.g, .limited));
}

test "gate: an invalid-key call makes no usage row and changes none; only the node's metric moves" {
    var r = try Rig.init(.{});
    defer r.deinit();
    r.mock.free_json = "{\"rps_per_ip\":5,\"burst\":10}";
    _ = r.g.refreshFree();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-ok", okKey(&b, "kid_ok", ",\"rps\":1,\"burst\":2,\"ttl_s\":60,\"lease_units\":null"));
    try r.learn("key-ok");
    try r.learn("key-unknown");
    // rows that exist: a keyed one with a rate-limit refusal, and a keyless one for the same address
    for (0..3) |_| _ = r.run("key-ok", "198.51.100.1", r.get);
    try testing.expect(r.run("", "198.51.100.1", r.get));
    r.g.tick(r.clock.mono, r.clock.wall);
    const before = r.g.spool.totals();
    try testing.expectEqual(contract.Counters{ .local = 3, .units = 3, .limited = 1 }, before);
    const rows_before = r.g.spool.pendingRows();
    const refused_before = r.g.m.denied[@intFromEnum(gate_mod.Reason.invalid)].load(.monotonic);
    // unknown keys from that address, on a method with a row and on one without
    for (0..25) |_| {
        try testing.expectEqual(gate_mod.Code.unauthenticated, r.call("key-unknown", "198.51.100.1", r.get).deny.code());
        try testing.expectEqual(gate_mod.Code.unauthenticated, r.call("key-unknown", "198.51.100.1", r.put).deny.code());
        try testing.expectEqual(gate_mod.Code.unauthenticated, r.call("not a key at all", "198.51.100.1", r.get).deny.code());
    }
    r.g.tick(r.clock.mono, r.clock.wall);
    try testing.expectEqual(before, r.g.spool.totals());
    try testing.expectEqual(rows_before, r.g.spool.pendingRows());
    try testing.expectEqual(refused_before + 75, r.g.m.denied[@intFromEnum(gate_mod.Reason.invalid)].load(.monotonic));
    // the address's own free-tier bucket was not touched either: of its burst of ten, one was
    // used before, so nine more keyless calls pass
    var passed: u32 = 0;
    for (0..20) |_| {
        if (r.run("", "198.51.100.1", r.get)) passed += 1;
    }
    try testing.expectEqual(@as(u32, 9), passed);
    // what reaches the gate: the same two rows, nothing about the unknown key
    r.flush();
    try testing.expectEqual(@as(usize, 2), r.mock.rows.count());
    try testing.expectEqual(contract.Counters{ .local = 2, .units = 2, .limited = 1 }, r.mock.row("kkid_ok", "a.A/Get"));
    try testing.expectEqual(contract.Counters{ .local = 10, .units = 10, .limited = 11 }, r.mock.row("i198.51.100.0/24", "a.A/Get"));
    try testing.expectEqual(contract.Counters{}, r.mock.row("i198.51.100.0/24", "a.A/Put"));
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try r.g.renderMetrics(&out.writer);
    try testing.expect(std.mem.indexOf(u8, out.writer.buffered(), "zui_gate_refused{reason=\"invalid\"} 75\n") != null);
    try testing.expect(std.mem.indexOf(u8, out.writer.buffered(), "zui_gate_refused{reason=\"over_limit\"} 12\n") != null);
}

test "gate: a key stated up front (a hello) is refused when invalid or suspended, not when exhausted" {
    var r = try Rig.init(.{});
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-ok", okKey(&b, "kid_ok", ",\"rps\":100,\"burst\":100,\"ttl_s\":60,\"lease_units\":null"));
    try r.mock.setKey("key-susp", "{\"key_id\":\"kid_susp\",\"status\":\"suspended\",\"ttl_s\":300,\"message\":\"Key revoked.\"}");
    try r.mock.setKey("key-exh", "{\"key_id\":\"kid_exh\",\"status\":\"exhausted\",\"ttl_s\":30,\"lease_units\":0}");
    const peer = ident.Ip.parse("198.51.100.1").?;
    inline for (.{ "key-ok", "key-susp", "key-exh", "key-none" }) |k| {
        try testing.expect(r.g.checkKey(k, peer, true, r.clock.mono) == .wait);
        r.pump();
    }
    try testing.expect(r.g.checkKey("key-ok", peer, true, r.clock.mono) == .ok);
    try testing.expect(r.g.checkKey("key-exh", peer, true, r.clock.mono) == .ok);
    const susp = r.g.checkKey("key-susp", peer, true, r.clock.mono).deny;
    try testing.expectEqual(gate_mod.Code.permission_denied, susp.code());
    try testing.expectEqualStrings("Key revoked.", susp.message);
    const none = r.g.checkKey("key-none", peer, true, r.clock.mono).deny;
    try testing.expectEqual(gate_mod.Reason.invalid, none.reason);
    try testing.expectEqual(gate_mod.Code.unauthenticated, none.code());
    try testing.expectEqual(gate_mod.Reason.invalid, r.g.checkKey("not a key", peer, true, r.clock.mono).deny.reason);
    try testing.expectEqual(@as(u32, 4), r.mock.resolves);
    // the gate is away: a new key's hello is not held up and not refused
    r.mock.down = true;
    r.clock.advanceMs(1000);
    try testing.expect(r.g.checkKey("key-later", peer, false, r.clock.mono) == .ok);
    r.pump();
    try testing.expect(r.g.checkKey("key-later", peer, true, r.clock.mono) == .ok);
}

test "gate: an answer is used for ttl_s, then asked for again while the old one still serves" {
    var r = try Rig.init(.{});
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":100,\"burst\":100,\"ttl_s\":60,\"lease_units\":null"));
    try r.learn("key-a");
    r.clock.advanceMs(59_000);
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    try testing.expectEqual(@as(u32, 0), r.g.pend_n.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), r.mock.resolves);
    // past the ttl: the call is served from the old answer and one resolve is queued, once
    r.clock.advanceMs(2_000);
    try r.mock.setKey("key-a", "{\"key_id\":\"kid_a\",\"status\":\"suspended\",\"ttl_s\":300}");
    for (0..10) |_| try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    try testing.expectEqual(@as(u32, 1), r.g.pend_n.load(.monotonic));
    r.pump();
    try testing.expectEqual(@as(u32, 2), r.mock.resolves);
    try testing.expectEqual(gate_mod.Reason.suspended, r.call("key-a", "198.51.100.1", r.get).deny.reason);
    // an invalid key is asked about again only after its own ttl
    try r.learn("key-none");
    try testing.expectEqual(@as(u32, 3), r.mock.resolves);
    r.clock.advanceMs(59_000);
    try testing.expect(r.call("key-none", "198.51.100.1", r.get) == .deny);
    r.pump();
    try testing.expectEqual(@as(u32, 3), r.mock.resolves);
    r.clock.advanceMs(2_000);
    try testing.expect(r.call("key-none", "198.51.100.1", r.get) == .deny);
    r.pump();
    try testing.expectEqual(@as(u32, 4), r.mock.resolves);
}

test "gate: a lease is spent, renewed early, and refused when the gate gives no new one" {
    var r = try Rig.init(.{});
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":1000,\"burst\":1000,\"ttl_s\":3600,\"lease_units\":10"));
    try r.learn("key-a");
    r.clock.advanceMs(2_000);
    // eight units leave two: no renewal yet (a quarter of ten, rounded down, is two)
    for (0..8) |_| try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    try testing.expectEqual(@as(u32, 0), r.g.pend_n.load(.monotonic));
    // the ninth leaves one: a renewal is queued while calls go on
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    try testing.expectEqual(@as(u32, 1), r.g.pend_n.load(.monotonic));
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    // the lease is spent and the renewal is still on its way: wait, or be refused
    try testing.expect(r.call("key-a", "198.51.100.1", r.get) == .wait);
    const spent = r.callNoWait("key-a", "198.51.100.1", r.get).deny;
    try testing.expectEqual(gate_mod.Reason.lease, spent.reason);
    try testing.expectEqual(gate_mod.Code.resource_exhausted, spent.code());
    // the renewal arrives: a new lease of ten replaces what was left
    r.pump();
    try testing.expectEqual(@as(u32, 2), r.mock.resolves);
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    try testing.expectEqual(@as(i64, 9), r.g.keys.entries[r.g.keys.find(r.g.keyHash("key-a")).?.idx].lease_left.load(.monotonic));

    // the gate is gone when the lease runs out: refused, never unlimited
    r.mock.down = true;
    r.clock.advanceMs(2_000);
    var passed: u32 = 0;
    for (0..40) |_| {
        if (r.run("key-a", "198.51.100.1", r.get)) passed += 1;
        r.pump();
    }
    try testing.expectEqual(@as(u32, 9), passed);
    try testing.expectEqual(gate_mod.Reason.lease, r.call("key-a", "198.51.100.1", r.get).deny.reason);
    // not one resolve per refused call: the next attempt waits for the retry time
    const tries = r.g.m.resolves.load(.monotonic);
    for (0..100) |_| {
        _ = r.call("key-a", "198.51.100.1", r.get);
        r.pump();
    }
    try testing.expectEqual(tries, r.g.m.resolves.load(.monotonic));

    // the gate is back and says the account is out of credits: refused as exhausted
    r.mock.down = false;
    try r.mock.setKey("key-a", "{\"key_id\":\"kid_a\",\"status\":\"exhausted\",\"ttl_s\":30,\"lease_units\":0}");
    r.clock.advanceMs(6_000);
    _ = r.call("key-a", "198.51.100.1", r.get);
    r.pump();
    try testing.expectEqual(gate_mod.Reason.exhausted, r.call("key-a", "198.51.100.1", r.get).deny.reason);
    // and after a top-up the next resolve (ttl 30 s) lets it through again
    try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":1000,\"burst\":1000,\"ttl_s\":60,\"lease_units\":5"));
    r.clock.advanceMs(31_000);
    _ = r.call("key-a", "198.51.100.1", r.get);
    r.pump();
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    // ten units and one more passed before the outage, nine in it, one now: what the usage says
    r.flush();
    try testing.expectEqual(@as(u64, 21), r.mock.row("kkid_a", "a.A/Get").units);
}

test "gate: unreachable gate, a known key keeps its answer for an hour of grace, then the free tier" {
    var r = try Rig.init(.{});
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":100,\"burst\":200,\"ttl_s\":60,\"lease_units\":null"));
    try r.learn("key-a");
    _ = r.g.refreshFree();
    r.mock.down = true;
    // past the ttl the resolve fails; the cached answer serves
    r.clock.advanceMs(61_000);
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    r.pump();
    try testing.expect(!r.g.reachable.load(.monotonic));
    var t: u64 = 0;
    while (t < 59 * 60) : (t += 60) {
        r.clock.advanceMs(60_000);
        const d = r.callNoWait("key-a", "198.51.100.1", r.get);
        try testing.expect(d == .allow and d.allow.kind == .key);
        r.pump();
    }
    // an hour after the ttl ended: the free tier, by the caller's address
    r.clock.advanceMs(2 * 60_000);
    const d = r.call("key-a", "198.51.100.1", r.get);
    try testing.expect(d == .allow and d.allow.kind == .ip);
    r.pump();
    // and that is limited like any keyless caller (the fixture's free tier: 5 a second, burst 10)
    var passed: u32 = 1;
    for (0..50) |_| {
        if (r.run("key-a", "198.51.100.1", r.get)) passed += 1;
        r.pump();
    }
    try testing.expectEqual(@as(u32, 10), passed);
    // an unknown key while the gate is away: the free tier at once, no wait, not cached as
    // invalid, and asked about again once the gate answers
    r.clock.advanceMs(2_000);
    const new1 = r.call("key-new", "198.51.100.77", r.get);
    try testing.expect(new1 == .allow and new1.allow.kind == .ip);
    r.pump();
    const f = r.g.keys.find(r.g.keyHash("key-new")).?;
    try testing.expectEqual(state.KeyStatus.unresolved, f.cfg.status);
    try r.mock.setKey("key-new", okKey(&b, "kid_new", ",\"rps\":100,\"burst\":200,\"ttl_s\":60,\"lease_units\":null"));
    r.mock.down = false;
    r.clock.advanceMs(31_000);
    _ = r.call("key-new", "198.51.100.77", r.get);
    r.pump();
    const new2 = r.call("key-new", "198.51.100.77", r.get);
    try testing.expect(new2 == .allow and new2.allow.kind == .key);
    try testing.expect(r.g.reachable.load(.monotonic));
}

test "gate: down at start, the built-in floor without a kept free tier, the kept one with it" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        // never fetched: 2 requests a second per address
        var r = try Rig.init(.{ .dir = tmp.dir });
        defer r.deinit();
        r.mock.down = true;
        _ = r.g.refreshFree();
        try testing.expect(!r.g.free_known.load(.monotonic));
        var passed: u32 = 0;
        var ms: u32 = 0;
        while (ms < 10_000) : (ms += 10) {
            r.clock.advanceMs(10);
            if (r.run("", "203.0.113.5", r.get)) passed += 1;
        }
        // 2 a second for ten seconds, and the burst of 4
        try testing.expect(passed >= 23 and passed <= 24);
        // an address of its own has a bucket of its own
        try testing.expect(r.run("", "203.0.113.6", r.get));
        // the gate comes back: its free tier is fetched and kept
        r.mock.down = false;
        const next = r.g.refreshFree();
        try testing.expectEqual(r.clock.mono + 300 * ns_per_s, next);
        try testing.expect(r.g.free_known.load(.monotonic));
    }
    {
        // a restart during an outage starts from the kept values (5 a second, burst 10)
        var r = try Rig.init(.{ .dir = tmp.dir, .boot_id = "boot2" });
        defer r.deinit();
        r.mock.down = true;
        _ = r.g.refreshFree();
        try testing.expect(r.g.free_known.load(.monotonic));
        var passed: u32 = 0;
        for (0..50) |_| {
            if (r.run("", "198.51.100.5", r.get)) passed += 1;
        }
        try testing.expectEqual(@as(u32, 10), passed);
        // the kept deny list applies too (the fixture denies 203.0.113.0/24 until a time ahead
        // of the test clock)
        try testing.expectEqual(gate_mod.Reason.exhausted, r.call("", "203.0.113.5", r.get).deny.reason);
        try testing.expect(r.call("", "203.0.114.5", r.get) == .allow);
    }
    {
        // once that time has passed on the wall clock, a restart no longer applies it
        var r = try Rig.init(.{ .dir = tmp.dir, .boot_id = "boot3", .wall = 1_794_441_600_000 + 1 });
        defer r.deinit();
        try testing.expect(r.call("", "203.0.113.5", r.get) == .allow);
    }
}

test "gate: a flood of made-up keys, resolves and memory stay bounded" {
    var r = try Rig.init(.{ .key_capacity = 256 });
    defer r.deinit();
    _ = r.g.refreshFree();
    var kb: [40]u8 = undefined;
    var passed: u32 = 0;
    var waited: u32 = 0;
    var n: u32 = 0;
    // 20,000 distinct keys in ten seconds from one address
    while (n < 20_000) : (n += 1) {
        if (n % 2 == 0) r.clock.advanceMs(1);
        const key = std.fmt.bufPrint(&kb, "made-up-key-{d}", .{n}) catch unreachable;
        var d = r.call(key, "198.51.100.200", r.get);
        if (d == .wait) {
            waited += 1;
            d = r.callNoWait(key, "198.51.100.200", r.get);
        }
        if (d == .allow) {
            passed += 1;
            try testing.expectEqual(@as(@TypeOf(d.allow.kind), .ip), d.allow.kind);
        }
        try testing.expect(r.g.pend_n.load(.monotonic) <= 256);
        if (n % 7 == 0) r.pump();
    }
    r.pump();
    // the gate was asked at most the budget: 100 at once and 50 a second
    try testing.expect(r.mock.resolves <= 100 + 50 * 10 + 1);
    try testing.expect(r.mock.resolves >= 400);
    try testing.expectEqual(waited, r.g.m.resolves.load(.monotonic));
    try testing.expect(r.g.m.resolve_capped.load(.monotonic) >= 19_000);
    // the table holds what fits and no more
    try testing.expect(r.g.keys.used.load(.monotonic) <= 256);
    // and every one of those calls was under the caller's free-tier bucket (5 a second, burst 10)
    try testing.expect(passed <= 10 + 5 * 10 + 1);
    // a real key still gets resolved afterwards
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-real", okKey(&b, "kid_real", ",\"rps\":100,\"burst\":100,\"ttl_s\":60,\"lease_units\":null"));
    r.clock.advanceMs(1000);
    _ = r.call("key-real", "198.51.100.9", r.get);
    r.pump();
    const d = r.call("key-real", "198.51.100.9", r.get);
    try testing.expect(d == .allow and d.allow.kind == .key);
}

test "gate: a flood of addresses, buckets stay bounded and idle ones are freed" {
    var r = try Rig.init(.{ .address_capacity = 256 });
    defer r.deinit();
    var ib: [20]u8 = undefined;
    var n: u32 = 0;
    while (n < 5000) : (n += 1) {
        const ip = std.fmt.bufPrint(&ib, "100.{d}.{d}.7", .{ n / 250, n % 250 }) catch unreachable;
        _ = r.call("", ip, r.get);
    }
    try testing.expect(r.g.ips.count() <= 256);
    try testing.expect(r.g.ips.overflowed.load(.monotonic) > 0);
    // the callers past the table share one bucket: still limited, at the free-tier rate
    var passed: u32 = 0;
    n = 0;
    while (n < 1000) : (n += 1) {
        const ip = std.fmt.bufPrint(&ib, "101.{d}.{d}.7", .{ n / 250, n % 250 }) catch unreachable;
        if (r.call("", ip, r.get) == .allow) passed += 1;
    }
    try testing.expect(passed <= 300);
    // two idle minutes later the ticks have freed every bucket
    r.clock.advanceMs(121_000);
    for (0..20) |_| r.second();
    try testing.expectEqual(@as(u32, 0), r.g.ips.count());
}

test "gate: the bucket through admit, burst then rate, with a retry-after" {
    var r = try Rig.init(.{});
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":50,\"burst\":100,\"ttl_s\":3600,\"lease_units\":null"));
    try r.learn("key-a");
    var passed: u32 = 0;
    var limited: u32 = 0;
    var ms: u32 = 0;
    // 1,000 calls a second for a minute
    while (ms < 60_000) : (ms += 1) {
        r.clock.advanceMs(1);
        const d = r.callNoWait("key-a", "198.51.100.1", r.get);
        switch (d) {
            .allow => passed += 1,
            .deny => |x| {
                limited += 1;
                try testing.expectEqual(gate_mod.Reason.limited, x.reason);
                try testing.expectEqual(gate_mod.Code.resource_exhausted, x.code());
                try testing.expectEqualStrings("rate limit exceeded", x.message);
                try testing.expect(x.retry_after_ms >= 1 and x.retry_after_ms <= 20);
            },
            .wait => unreachable,
        }
    }
    const want: f64 = 100 + 50 * 60;
    try testing.expect(@abs(@as(f64, @floatFromInt(passed)) - want) <= want * 0.01);
    try testing.expectEqual(@as(u32, 60_000), passed + limited);
    // a limited call is counted and costs nothing
    r.g.tick(r.clock.mono, r.clock.wall);
    // (the tick also closed the window: a minute has passed)
    try testing.expectEqual(@as(u64, limited), r.g.spool.windows.items[0].rows.get("kkid_a\x00a.A/Get").?.limited);
    try testing.expectEqual(@as(u64, limited), r.g.m.limited[r.g.plans.intern("developer")][r.get].load(.monotonic));
}

test "gate: max_streams per key and per address" {
    var r = try Rig.init(.{});
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":100,\"burst\":100,\"max_streams\":2,\"ttl_s\":3600,\"lease_units\":null"));
    try r.learn("key-a");
    _ = r.g.refreshFree();
    var s1 = r.call("key-a", "198.51.100.1", r.watch).allow;
    var s2 = r.call("key-a", "198.51.100.2", r.watch).allow;
    const third = r.call("key-a", "198.51.100.3", r.watch).deny;
    try testing.expectEqual(gate_mod.Reason.streams, third.reason);
    try testing.expectEqual(gate_mod.Code.resource_exhausted, third.code());
    // unary calls are not streams
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    r.g.streamClose(&s1, r.clock.mono);
    r.g.streamClose(&s1, r.clock.mono); // closing twice frees one slot, not two
    var s3 = r.call("key-a", "198.51.100.3", r.watch).allow;
    try testing.expect(r.call("key-a", "198.51.100.3", r.watch) == .deny);
    r.g.streamClose(&s2, r.clock.mono);
    r.g.streamClose(&s3, r.clock.mono);
    // keyless: one stream per address (the fixture's free tier)
    var k1 = r.call("", "192.0.2.5", r.watch).allow;
    try testing.expectEqual(gate_mod.Reason.streams, r.call("", "192.0.2.5", r.watch).deny.reason);
    var k2 = r.call("", "192.0.2.6", r.watch).allow;
    r.g.streamClose(&k1, r.clock.mono);
    var k3 = r.call("", "192.0.2.5", r.watch).allow;
    r.g.streamClose(&k2, r.clock.mono);
    r.g.streamClose(&k3, r.clock.mono);
}

test "gate: weights, the forward multiplier, per item, per minute, and failed calls cost nothing" {
    var r = try Rig.init(.{});
    defer r.deinit();
    try r.mock.setKey("key-a", "{\"key_id\":\"kid_a\",\"status\":\"ok\",\"plan\":\"business\",\"rps\":1000,\"burst\":1000,\"max_streams\":4,\"ttl_s\":3600,\"lease_units\":1000," ++
        "\"weights\":{\"default\":1,\"a.A/Put\":5,\"a.A/Batch\":2,\"a.A/Watch\":10},\"forward_weight_mult\":3,\"per_item\":{\"a.A/Batch\":10},\"per_minute\":{\"a.A/Watch\":10}}");
    try r.learn("key-a");
    const peer = ident.Ip.parse("198.51.100.1").?;
    const now = r.clock.mono;
    const e = &r.g.keys.entries[r.g.keys.find(r.g.keyHash("key-a")).?.idx];
    // a read answered here: its weight
    const get = r.g.admit(&.{ .key = "key-a", .peer = peer, .method = r.get }, now).allow;
    r.g.settle(&get, .local, true, now);
    try testing.expectEqual(@as(i64, 999), e.lease_left.load(.monotonic));
    // a write that was forwarded: weight 5 times 3, the extra ten booked after routing
    const put = r.g.admit(&.{ .key = "key-a", .peer = peer, .method = r.put }, now).allow;
    try testing.expectEqual(@as(u32, 5), put.cost);
    try testing.expectEqual(@as(i64, 994), e.lease_left.load(.monotonic));
    r.g.settle(&put, .forwarded, true, now);
    try testing.expectEqual(@as(i64, 984), e.lease_left.load(.monotonic));
    // the bucket too: 1 + 15 units of 1 ms each are owed
    try testing.expectEqual(now + 16 * ns_per_ms, e.tat.load(.monotonic));
    // a batch of 25 items: 1 + ceil(25 / 10)
    const batch = r.g.admit(&.{ .key = "key-a", .peer = peer, .method = r.batch, .items = 25 }, now).allow;
    try testing.expectEqual(@as(u32, 4), batch.cost);
    r.g.settle(&batch, .local, true, now);
    // a batch whose size is not known: the flat weight
    const flat = r.g.admit(&.{ .key = "key-a", .peer = peer, .method = r.batch }, now).allow;
    try testing.expectEqual(@as(u32, 2), flat.cost);
    r.g.settle(&flat, .local, true, now);
    // a call that failed: counted, no units, the lease gets its units back
    const before = e.lease_left.load(.monotonic);
    const failed = r.g.admit(&.{ .key = "key-a", .peer = peer, .method = r.put }, now).allow;
    r.g.settle(&failed, .forwarded, false, now);
    try testing.expectEqual(before, e.lease_left.load(.monotonic));
    // a stream: one call and the first minute at open, a minute's units for every minute started
    var w = r.g.admit(&.{ .key = "key-a", .peer = peer, .method = r.watch }, now).allow;
    try testing.expectEqual(@as(u32, 10), w.cost);
    r.g.settle(&w, .local, true, now);
    r.g.streamMsgs(&w, 3);
    try testing.expect(r.g.streamTick(&w, "key-a", now + 59 * ns_per_s) == null);
    try testing.expectEqual(@as(u32, 1), w.minutes);
    try testing.expect(r.g.streamTick(&w, "key-a", now + 61 * ns_per_s) == null);
    try testing.expectEqual(@as(u32, 2), w.minutes);
    r.g.streamMsgs(&w, 4);
    // closed in its fourth minute without a message in between: minutes three and four are booked
    r.g.streamClose(&w, now + 185 * ns_per_s);
    try testing.expectEqual(@as(u32, 0), e.streams.load(.monotonic));
    r.flush();
    try testing.expectEqual(contract.Counters{ .local = 1, .units = 1 }, r.mock.row("kkid_a", "a.A/Get"));
    try testing.expectEqual(contract.Counters{ .forwarded = 2, .units = 15 }, r.mock.row("kkid_a", "a.A/Put"));
    try testing.expectEqual(contract.Counters{ .local = 2, .units = 6 }, r.mock.row("kkid_a", "a.A/Batch"));
    try testing.expectEqual(contract.Counters{ .local = 1, .units = 40, .stream_msgs = 7 }, r.mock.row("kkid_a", "a.A/Watch"));
    // the lease saw the same units the usage reports
    try testing.expectEqual(@as(i64, 1000 - 1 - 15 - 6 - 40), e.lease_left.load(.monotonic));
    // the keyless tier has its own table and multiplier (the fixture: weight 1, multiplier 1)
    _ = r.g.refreshFree();
    const kl = r.g.admit(&.{ .peer = peer, .method = r.put }, r.clock.mono).allow;
    try testing.expectEqual(@as(u32, 1), kl.cost);
    r.g.settle(&kl, .forwarded, true, r.clock.mono);
    r.flush();
    try testing.expectEqual(contract.Counters{ .forwarded = 1, .units = 1 }, r.mock.row("i198.51.100.0/24", "a.A/Put"));
}

test "gate: the forward multiplier the gate last gave is a gauge (resolve answers of keys in good standing, the free tier)" {
    var r = try Rig.init(.{});
    defer r.deinit();
    const Shown = struct {
        fn expect(g: *gate_mod.Gate, comptime resolve: []const u8, comptime free: []const u8) !void {
            var out: Io.Writer.Allocating = .init(testing.allocator);
            defer out.deinit();
            try g.renderMetrics(&out.writer);
            const text = out.writer.buffered();
            inline for (.{
                "# TYPE zui_gate_forward_weight_mult gauge\n",
                "zui_gate_forward_weight_mult{answer=\"resolve\"} " ++ resolve ++ "\n",
                "zui_gate_forward_weight_mult{answer=\"free\"} " ++ free ++ "\n",
            }) |want| {
                if (std.mem.indexOf(u8, text, want) == null) {
                    std.debug.print("missing metric line: {s}\n{s}\n", .{ want, text });
                    return error.TestExpectedMetric;
                }
            }
        }
    };
    // nothing asked yet: no answer, no multiplier (the built-in free floor is not the gate's word)
    try Shown.expect(r.g, "0.000", "0.000");
    try r.mock.setKey("key-a", "{\"key_id\":\"kid_a\",\"status\":\"ok\",\"plan\":\"business\",\"rps\":1000,\"burst\":1000,\"ttl_s\":3600,\"lease_units\":1000,\"weights\":{\"default\":1},\"forward_weight_mult\":3}");
    try r.learn("key-a");
    try Shown.expect(r.g, "3.000", "0.000");
    // the free tier's own answer (the fixture: 1)
    _ = r.g.refreshFree();
    try Shown.expect(r.g, "3.000", "1.000");
    // a later answer replaces it, fractions as the contract writes them
    try r.mock.setKey("key-b", "{\"key_id\":\"kid_b\",\"status\":\"ok\",\"plan\":\"business\",\"rps\":1000,\"burst\":1000,\"ttl_s\":3600,\"lease_units\":1000,\"weights\":{\"default\":1},\"forward_weight_mult\":1.5}");
    try r.learn("key-b");
    try Shown.expect(r.g, "1.500", "1.000");
    // an answer for a key that is refused does not: it prices nothing
    try r.mock.setKey("key-bad2", "{\"key_id\":null,\"status\":\"invalid\",\"plan\":null,\"rps\":0,\"burst\":0,\"weights\":{\"default\":1},\"forward_weight_mult\":7,\"max_streams\":0,\"ttl_s\":60,\"lease_units\":0}");
    try r.learn("key-bad2");
    try Shown.expect(r.g, "1.500", "1.000");
}

test "gate: a stream ends when its key is denied, suspended or out of lease" {
    var r = try Rig.init(.{});
    defer r.deinit();
    try r.mock.setKey("key-a", "{\"key_id\":\"kid_a\",\"status\":\"ok\",\"rps\":100,\"burst\":100,\"max_streams\":4,\"ttl_s\":60,\"lease_units\":25,\"per_minute\":{\"a.A/Watch\":10}}");
    try r.learn("key-a");
    var w = r.call("key-a", "198.51.100.1", r.watch).allow;
    r.g.settle(&w, .local, true, r.clock.mono);
    // minute two and three: 30 units against a lease of 25, the renewal brings 25 more
    r.clock.advanceMs(61_000);
    try testing.expect(r.g.streamTick(&w, "key-a", r.clock.mono) == null);
    r.pump();
    r.clock.advanceMs(60_000);
    try testing.expect(r.g.streamTick(&w, "key-a", r.clock.mono) == null);
    r.pump();
    try testing.expect(r.mock.resolves >= 2);
    // the gate stops renewing: the stream is stopped once the lease is spent and stays spent
    try r.mock.setKey("key-a", "{\"key_id\":\"kid_a\",\"status\":\"ok\",\"rps\":100,\"burst\":100,\"max_streams\":4,\"ttl_s\":60,\"lease_units\":0}");
    var ended: ?gate_mod.Deny = null;
    for (0..6) |_| {
        r.clock.advanceMs(61_000);
        ended = r.g.streamTick(&w, "key-a", r.clock.mono);
        r.pump();
        if (ended != null) break;
    }
    try testing.expectEqual(gate_mod.Reason.lease, ended.?.reason);
    r.g.streamClose(&w, r.clock.mono);
    // a suspended key: its open stream ends at the next check
    try r.mock.setKey("key-b", "{\"key_id\":\"kid_b\",\"status\":\"ok\",\"rps\":100,\"burst\":100,\"max_streams\":4,\"ttl_s\":60,\"lease_units\":null}");
    try r.learn("key-b");
    var w2 = r.call("key-b", "198.51.100.1", r.watch).allow;
    try r.mock.setKey("key-b", "{\"key_id\":\"kid_b\",\"status\":\"suspended\",\"ttl_s\":300}");
    r.clock.advanceMs(61_000);
    try testing.expect(r.g.streamTick(&w2, "key-b", r.clock.mono) == null); // this check queues the resolve
    r.pump();
    r.clock.advanceMs(1_000);
    const d2 = r.g.streamTick(&w2, "key-b", r.clock.mono).?;
    try testing.expectEqual(gate_mod.Reason.suspended, d2.reason);
    try testing.expectEqual(gate_mod.Code.permission_denied, d2.code());
    r.g.streamClose(&w2, r.clock.mono);
}

test "gate: the gate's own text for an unknown key, an exhausted and a revoked one (the service's examples)" {
    var r = try Rig.init(.{});
    defer r.deinit();
    r.mock.invalid_json = contract.fixtures.resolve_invalid;
    try r.mock.setKey("key-exh", contract.fixtures.resolve_exhausted);
    try r.mock.setKey("key-susp", contract.fixtures.resolve_suspended);
    inline for (.{ "key-unknown", "key-exh", "key-susp" }) |k| try r.learn(k);
    const unknown = r.call("key-unknown", "198.51.100.1", r.get).deny;
    try testing.expectEqual(gate_mod.Code.unauthenticated, unknown.code());
    try testing.expectEqualStrings("Unknown API key. Get one at gate.example.", unknown.message);
    const exh = r.call("key-exh", "198.51.100.1", r.get).deny;
    try testing.expectEqual(gate_mod.Code.resource_exhausted, exh.code());
    try testing.expectEqualStrings("Out of credits. Top up at gate.example.", exh.message);
    const susp = r.call("key-susp", "198.51.100.1", r.get).deny;
    try testing.expectEqual(gate_mod.Code.permission_denied, susp.code());
    try testing.expectEqualStrings("This API key was revoked. Create a new one at gate.example.", susp.message);
    // the deny examples: the usage answer's, and the free tier's
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-a", okKey(&b, "kid_3fJ9aQ2xLm0p", ",\"rps\":100,\"burst\":100,\"ttl_s\":60,\"lease_units\":null"));
    try r.learn("key-a");
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    r.clock.wall = 1_794_441_600_000 - 3_600_000;
    r.mock.usage_answer = contract.fixtures.usage_answer;
    r.flush();
    try testing.expectEqualStrings("Out of credits. Top up at gate.example.", r.call("key-a", "198.51.100.1", r.get).deny.message);
    const pfx = r.call("", "203.0.113.5", r.get).deny;
    try testing.expectEqual(gate_mod.Code.resource_exhausted, pfx.code());
    try testing.expectEqualStrings("Free daily limit reached. Add an API key from gate.example for more.", pfx.message);
}

test "gate: an answer without lease_units spends nothing; the key is asked about once a second at most and refused in between" {
    var r = try Rig.init(.{});
    defer r.deinit();
    // status ok, a rate, and no lease field at all
    try r.mock.setKey("key-a", "{\"key_id\":\"kid_a\",\"status\":\"ok\",\"plan\":\"developer\",\"rps\":1000,\"burst\":1000,\"ttl_s\":60}");
    try r.learn("key-a");
    var passed: u32 = 0;
    var refused: u32 = 0;
    var ms: u32 = 0;
    // 100 calls a second for ten seconds, the resolver running all along
    while (ms < 10_000) : (ms += 10) {
        r.clock.advanceMs(10);
        const d = r.callNoWait("key-a", "198.51.100.1", r.get);
        switch (d) {
            .allow => passed += 1,
            .deny => |x| {
                refused += 1;
                try testing.expectEqual(gate_mod.Reason.lease, x.reason);
                try testing.expectEqual(gate_mod.Code.resource_exhausted, x.code());
                try testing.expectEqualStrings("out of credits", x.message);
            },
            .wait => unreachable,
        }
        r.pump();
    }
    try testing.expectEqual(@as(u32, 0), passed);
    try testing.expectEqual(@as(u32, 1000), refused);
    // one resolve at the start, then one a second: never a resolve per call
    try testing.expect(r.mock.resolves >= 9 and r.mock.resolves <= 12);
    // an explicit null is the only "no cap"
    try r.mock.setKey("key-a", "{\"key_id\":\"kid_a\",\"status\":\"ok\",\"plan\":\"developer\",\"rps\":1000,\"burst\":1000,\"ttl_s\":60,\"lease_units\":null}");
    r.clock.advanceMs(1_100);
    _ = r.callNoWait("key-a", "198.51.100.1", r.get);
    r.pump();
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
}

test "gate: usage answers: rejected rows are counted and not resent; 400 and 413 go to dead letters; 429 and 5xx wait as asked" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    var r = try Rig.init(.{ .dir = tmp.dir });
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":1000,\"burst\":1000,\"ttl_s\":3600,\"lease_units\":null"));
    try r.learn("key-a");
    const lines0 = r.logs.lines;

    // 1. delivered with two rows the gate did not take
    for (0..3) |_| try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    try testing.expect(r.run("key-a", "198.51.100.1", r.put));
    r.mock.usage_answer = "{\"ok\":true,\"duplicate\":false,\"rows\":2,\"rejected\":2,\"rejected_rows\":[0,1]}";
    r.flush();
    try testing.expectEqual(@as(u64, 1), r.g.m.batches_sent.load(.monotonic));
    try testing.expectEqual(@as(u64, 2), r.g.m.rows_rejected.load(.monotonic));
    try testing.expect(r.g.spool.sealed == null); // delivered: off the queue
    try testing.expectEqual(lines0 + 1, r.logs.lines);
    try testing.expect(std.mem.indexOf(u8, r.logs.text.items, "did not take 2 of 2 rows (rows 0,1)") != null);
    try testing.expect(std.mem.indexOf(u8, r.logs.text.items, "kid_a") == null);
    r.mock.usage_answer = "{\"ok\":true}";

    // 2. a batch the gate refuses for good (400), then one it finds too large (413): each is
    // set aside, and the batch behind it goes out
    inline for (.{ 400, 413 }) |status| {
        try testing.expect(r.run("key-a", "198.51.100.1", r.get));
        r.mock.usage_status = status;
        r.mock.usage_status_n = 1;
        r.clock.advanceMs(5000);
        r.g.tick(r.clock.mono, r.clock.wall);
        try testing.expectEqual(@as(?u64, 0), r.g.sendStep()); // off the queue at once, no back-off
        try testing.expect(r.g.spool.sealed == null);
        try testing.expect(r.run("key-a", "198.51.100.1", r.put));
        r.flush();
    }
    try testing.expectEqual(@as(u64, 2), r.g.m.batches_dead.load(.monotonic));
    try testing.expectEqual(@as(u64, 3), r.g.m.batches_sent.load(.monotonic));
    try testing.expectEqual(@as(u64, 3), r.mock.row("kkid_a", "a.A/Put").local);
    // the dead letters are the bodies as they were posted, in numbered slots
    const d0 = try tmp.dir.readFileAlloc(io, "dead-letter/batch-00.json", testing.allocator, .unlimited);
    defer testing.allocator.free(d0);
    try testing.expect(std.mem.indexOf(u8, d0, "\"batch_id\":\"e1-boot1-1\"") != null);
    const d1 = try tmp.dir.readFileAlloc(io, "dead-letter/batch-01.json", testing.allocator, .unlimited);
    defer testing.allocator.free(d1);
    try testing.expect(std.mem.indexOf(u8, d1, "\"batch_id\":\"e1-boot1-3\"") != null);
    // bounded: far more refused batches than slots, never more than `dead_keep` files
    var k: u32 = 0;
    while (k < Gate.dead_keep + 5) : (k += 1) {
        try testing.expect(r.run("key-a", "198.51.100.1", r.get));
        r.mock.usage_status = 400;
        r.mock.usage_status_n = 1;
        r.flush();
    }
    var nb: [64]u8 = undefined;
    var present: u32 = 0;
    k = 0;
    while (k < Gate.dead_keep + 8) : (k += 1) {
        const name = std.fmt.bufPrint(&nb, "dead-letter/batch-{d:0>2}.json", .{k}) catch unreachable;
        if (tmp.dir.readFileAlloc(io, name, testing.allocator, .unlimited)) |t| {
            testing.allocator.free(t);
            present += 1;
        } else |_| {}
    }
    try testing.expectEqual(@as(u32, Gate.dead_keep), present);

    // 3. 429 and 503: the batch stays, with the same id and body, and the node waits at least
    // what the gate asked for
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    r.clock.advanceMs(5000);
    r.g.tick(r.clock.mono, r.clock.wall);
    const posts0 = r.mock.usage_posts;
    r.mock.retry_after_s = 7;
    r.mock.usage_status = 429;
    r.mock.usage_status_n = 1;
    try testing.expectEqual(@as(?u64, 7 * ns_per_s), r.g.sendStep());
    const id_kept = try testing.allocator.dupe(u8, r.g.spool.sealed.?.id);
    defer testing.allocator.free(id_kept);
    r.mock.usage_status = 503;
    r.mock.usage_status_n = 1;
    try testing.expectEqual(@as(?u64, 7 * ns_per_s), r.g.sendStep());
    r.mock.retry_after_s = null;
    r.mock.usage_status = 500;
    r.mock.usage_status_n = 1;
    try testing.expectEqual(@as(?u64, 4 * ns_per_s), r.g.sendStep()); // its own back-off: 1, 2, 4 s
    try testing.expectEqualStrings(id_kept, r.g.spool.sealed.?.id);
    // a Retry-After of a day is not obeyed past five minutes
    r.mock.retry_after_s = 86_400;
    r.mock.usage_status = 429;
    r.mock.usage_status_n = 1;
    try testing.expectEqual(@as(?u64, 300 * ns_per_s), r.g.sendStep());
    r.mock.retry_after_s = null;
    // 401: a configuration error; the batch stays too
    r.mock.status = 401;
    try testing.expect(r.g.sendStep().? >= ns_per_s);
    try testing.expectEqualStrings(id_kept, r.g.spool.sealed.?.id);
    r.mock.status = null;
    try testing.expectEqual(@as(?u64, 0), r.g.sendStep());
    try testing.expectEqual(posts0 + 5, r.mock.usage_posts); // (the 401 was the whole gate's answer)
    try testing.expectEqual(@as(u64, 2 + Gate.dead_keep + 5), r.g.m.batches_dead.load(.monotonic));
    // nothing was counted twice on the way: the three Gets of the first batch and this one
    // arrived, the dead-lettered ones did not
    try testing.expectEqual(@as(u64, 4), r.mock.row("kkid_a", "a.A/Get").local);
}

test "gate: a usage batch is posted again with the same id and body until the gate takes it" {
    var r = try Rig.init(.{});
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":100,\"burst\":100,\"ttl_s\":3600,\"lease_units\":null"));
    try r.learn("key-a");
    for (0..7) |_| try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    for (0..3) |_| try testing.expect(r.run("", "203.0.113.5", r.get));
    r.clock.advanceMs(5000);
    r.g.tick(r.clock.mono, r.clock.wall);
    // two posts fail; the gate had in fact taken the first one (its answer was lost)
    r.mock.fail_usage = 2;
    r.mock.usage_applied = true;
    try testing.expectEqual(@as(?u64, ns_per_s), r.g.sendStep());
    try testing.expectEqual(@as(?u64, 2 * ns_per_s), r.g.sendStep());
    try testing.expectEqual(@as(u64, 2), r.g.m.batches_failed.load(.monotonic));
    try testing.expectEqual(@as(?u64, 0), r.g.sendStep());
    try testing.expectEqual(@as(?u64, null), r.g.sendStep());
    try testing.expectEqual(@as(u32, 3), r.mock.usage_posts);
    try testing.expectEqual(@as(usize, 1), r.mock.batches.count());
    try testing.expectEqualStrings("e1-boot1-0", r.mock.batches.keys()[0]);
    try testing.expectEqual(@as(u32, 2), r.mock.duplicates_same);
    try testing.expectEqual(@as(u32, 0), r.mock.duplicates_differ);
    // counted once
    try testing.expectEqual(@as(u64, 7), r.mock.row("kkid_a", "a.A/Get").local);
    try testing.expectEqual(@as(u64, 3), r.mock.row("i203.0.113.0/24", "a.A/Get").local);
    try testing.expectEqual(@as(u64, 10), r.mock.total.units);
    // the window the rows cover
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), r.mock.batches.values()[0], .{});
    try testing.expectEqualStrings("e1", v.object.get("edge").?.string);
    try testing.expectEqual(@as(i64, 1_794_000_000_000), v.object.get("from_ms").?.integer);
    try testing.expectEqual(@as(i64, 1_794_000_005_000), v.object.get("to_ms").?.integer);
    // the next batch has the next id
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    r.flush();
    try testing.expectEqualStrings("e1-boot1-1", r.mock.batches.keys()[1]);
    try testing.expectEqual(@as(u64, 2), r.g.m.batches_sent.load(.monotonic));
}

test "gate: more rows than one batch holds go out as several batches of at most 1,000" {
    var r = try Rig.init(.{ .address_capacity = 8192 });
    defer r.deinit();
    var ib: [20]u8 = undefined;
    var n: u32 = 0;
    while (n < 2300) : (n += 1) {
        const ip = std.fmt.bufPrint(&ib, "100.{d}.{d}.7", .{ n / 250, n % 250 }) catch unreachable;
        try testing.expect(r.run("", ip, r.get));
    }
    r.flush();
    try testing.expectEqual(@as(usize, 3), r.mock.batches.count());
    try testing.expectEqual(@as(usize, 1000), r.mock.max_rows_in_batch);
    try testing.expectEqual(@as(u64, 2300), r.mock.total.local);
    try testing.expectEqual(@as(usize, 2300), r.mock.rows.count());
}

test "gate: a crash loses at most the last second, a torn tail is cut, the rest is sent after the restart" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    var b: [512]u8 = undefined;
    {
        var r = try Rig.init(.{ .dir = tmp.dir, .crash_on_stop = true });
        defer r.deinit();
        try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":100,\"burst\":100,\"ttl_s\":3600,\"lease_units\":null"));
        try r.learn("key-a");
        r.mock.down = true; // nothing reaches the gate before the crash
        for (0..5) |_| try testing.expect(r.run("key-a", "198.51.100.1", r.get));
        r.second();
        for (0..4) |_| try testing.expect(r.run("key-a", "198.51.100.1", r.put));
        r.second();
        // counted in the last second, never journalled: this is what a crash may lose
        for (0..3) |_| try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    }
    // the crash tore the record that was being written
    {
        const whole = try tmp.dir.readFileAlloc(io, spool_mod.file_name, testing.allocator, .unlimited);
        defer testing.allocator.free(whole);
        var torn: std.ArrayList(u8) = .empty;
        defer torn.deinit(testing.allocator);
        try torn.appendSlice(testing.allocator, whole);
        try torn.appendSlice(testing.allocator, &.{ 40, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef, 1, 9, 9, 9 });
        try tmp.dir.writeFile(io, .{ .sub_path = spool_mod.file_name, .data = torn.items });
    }
    {
        var r = try Rig.init(.{ .dir = tmp.dir, .boot_id = "boot2" });
        defer r.deinit();
        try testing.expectEqual(@as(u64, 12), r.g.spool.stats.torn_bytes);
        r.flush();
        try testing.expectEqual(@as(u64, 5), r.mock.row("kkid_a", "a.A/Get").local);
        try testing.expectEqual(@as(u64, 4), r.mock.row("kkid_a", "a.A/Put").local);
        try testing.expectEqual(@as(u64, 9), r.mock.total.units);
        try testing.expectEqualStrings("e1-boot2-0", r.mock.batches.keys()[0]);
    }
    // a clean stop loses nothing, not even the second in progress
    {
        var r = try Rig.init(.{ .dir = tmp.dir, .boot_id = "boot3" });
        try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":100,\"burst\":100,\"ttl_s\":3600,\"lease_units\":null"));
        try r.learn("key-a");
        r.mock.down = true;
        for (0..6) |_| try testing.expect(r.run("key-a", "198.51.100.1", r.get));
        r.deinit();
    }
    {
        var r = try Rig.init(.{ .dir = tmp.dir, .boot_id = "boot4" });
        defer r.deinit();
        r.flush();
        try testing.expectEqual(@as(u64, 6), r.mock.row("kkid_a", "a.A/Get").local);
    }
}

test "gate: a sealed batch survives a crash and is posted again with its old id and body" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var b: [512]u8 = undefined;
    var first_body: []u8 = &.{};
    defer testing.allocator.free(first_body);
    {
        var r = try Rig.init(.{ .dir = tmp.dir, .crash_on_stop = true });
        defer r.deinit();
        try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":100,\"burst\":100,\"ttl_s\":3600,\"lease_units\":null"));
        try r.learn("key-a");
        for (0..5) |_| try testing.expect(r.run("key-a", "198.51.100.1", r.get));
        // the post reaches the gate, the answer is lost, then the node dies
        r.mock.fail_usage = 1;
        r.mock.usage_applied = true;
        r.flush();
        try testing.expectEqual(@as(usize, 1), r.mock.batches.count());
        first_body = try testing.allocator.dupe(u8, r.mock.batches.values()[0]);
    }
    {
        var r = try Rig.init(.{ .dir = tmp.dir, .boot_id = "boot2" });
        defer r.deinit();
        // (this mock is a new one: it sees the old batch for the first time, with the old id)
        r.flush();
        try testing.expectEqualStrings("e1-boot1-0", r.mock.batches.keys()[0]);
        try testing.expectEqualStrings(first_body, r.mock.batches.values()[0]);
        try testing.expectEqual(@as(u64, 5), r.mock.total.local);
    }
}

test "gate: a deny list from the usage answer and from the free tier applies at once" {
    var r = try Rig.init(.{});
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":100,\"burst\":100,\"ttl_s\":60,\"lease_units\":null"));
    try r.mock.setKey("key-b", okKey(&b, "kid_b", ",\"rps\":100,\"burst\":100,\"ttl_s\":60,\"lease_units\":null"));
    try r.learn("key-a");
    try r.learn("key-b");
    r.mock.free_json = "{\"rps_per_ip\":5,\"burst\":10}";
    _ = r.g.refreshFree();
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    try testing.expect(r.run("", "203.0.113.5", r.get));
    var ub: [512]u8 = undefined;
    r.mock.usage_answer = std.fmt.bufPrint(&ub, "{{\"ok\":true,\"duplicate\":false,\"rows\":2,\"deny\":[" ++
        "{{\"key_id\":\"kid_a\",\"status\":\"exhausted\",\"until_ms\":null,\"message\":\"Out of credits. Top up at gate.example.\"}}," ++
        "{{\"ip_prefix\":\"203.0.113.0/24\",\"status\":\"exhausted\",\"until_ms\":{d}}}," ++
        "{{\"key_id\":\"kid_not_here\",\"status\":\"suspended\",\"until_ms\":null}}]}}", .{r.clock.wall + 5_000 + 3_600_000}) catch unreachable;
    r.flush();
    // the key: refused with the gate's text until the gate's next resolve answer
    const da = r.call("key-a", "198.51.100.1", r.get).deny;
    try testing.expectEqual(gate_mod.Reason.exhausted, da.reason);
    try testing.expectEqualStrings("Out of credits. Top up at gate.example.", da.message);
    try testing.expect(r.run("key-b", "198.51.100.1", r.get));
    // the prefix: every address in it, no other
    try testing.expectEqual(gate_mod.Reason.exhausted, r.call("", "203.0.113.5", r.get).deny.reason);
    try testing.expectEqual(gate_mod.Reason.exhausted, r.call("", "203.0.113.250", r.get).deny.reason);
    try testing.expectEqualStrings("out of credits", r.call("", "203.0.113.250", r.get).deny.message);
    try testing.expect(r.run("", "203.0.114.5", r.get));
    // a key someone presents from a denied prefix is still that key
    try testing.expect(r.run("key-b", "203.0.113.5", r.get));
    r.mock.usage_answer = "{\"ok\":true}";
    // the prefix is free again when its time is up (robust to the wall clock: counted on the
    // monotonic clock from the moment the deny arrived)
    r.clock.advanceMs(3_599_000);
    r.clock.wall -= 86_400_000; // the wall clock jumps back a day
    try testing.expect(r.call("", "203.0.113.5", r.get) == .deny);
    r.clock.advanceMs(2_000);
    try testing.expect(r.run("", "203.0.113.5", r.get));
    // the key stays denied past its ttl until a resolve says otherwise
    try testing.expect(r.call("key-a", "198.51.100.1", r.get) == .deny);
    r.pump();
    try testing.expect(r.run("key-a", "198.51.100.1", r.get));
    // the free tier's own deny list
    var fb: [512]u8 = undefined;
    r.mock.free_json = std.fmt.bufPrint(&fb, "{{\"rps_per_ip\":5,\"burst\":10,\"deny\":[{{\"ip_prefix\":\"2001:db8:7::/48\",\"status\":\"exhausted\",\"until_ms\":{d}}}]}}", .{r.clock.wall + 60_000}) catch unreachable;
    _ = r.g.refreshFree();
    try testing.expect(r.call("", "2001:db8:7:1::5", r.get) == .deny);
    try testing.expect(r.call("", "2001:db8:8:1::5", r.get) == .allow);
    // an entry whose time is already over denies nothing
    r.mock.free_json = "{\"rps_per_ip\":5,\"burst\":10,\"deny\":[{\"ip_prefix\":\"192.0.2.0/24\",\"status\":\"exhausted\",\"until_ms\":1000}]}";
    _ = r.g.refreshFree();
    try testing.expect(r.call("", "192.0.2.9", r.get) == .allow);
}

test "gate: the forwarded-for header counts only behind a trusted proxy" {
    const proxies = [_]ident.Cidr{ident.Cidr.parse("10.0.0.0/8").?};
    const proxy = ident.Ip.parse("10.0.0.7").?;
    inline for (.{ false, true }) |on| {
        var r = try Rig.init(.{ .proxies = if (on) &proxies else &.{} });
        defer r.deinit();
        r.mock.free_json = "{\"rps_per_ip\":5,\"burst\":10}";
        _ = r.g.refreshFree();
        var a: u32 = 0;
        var bcount: u32 = 0;
        for (0..30) |_| {
            const da = r.g.admit(&.{ .peer = proxy, .forwarded_for = "198.51.100.4", .method = r.get }, r.clock.mono);
            if (da == .allow) {
                a += 1;
                r.g.settle(&da.allow, .local, true, r.clock.mono);
            }
            const db = r.g.admit(&.{ .peer = proxy, .forwarded_for = "198.51.100.4, 203.0.113.9", .method = r.get }, r.clock.mono);
            if (db == .allow) {
                bcount += 1;
                r.g.settle(&db.allow, .local, true, r.clock.mono);
            }
        }
        r.flush();
        if (on) {
            // two callers, a bucket and a usage row each
            try testing.expectEqual(@as(u32, 10), a);
            try testing.expectEqual(@as(u32, 10), bcount);
            try testing.expectEqual(@as(u64, 10), r.mock.row("i198.51.100.0/24", "a.A/Get").local);
            try testing.expectEqual(@as(u64, 10), r.mock.row("i203.0.113.0/24", "a.A/Get").local);
            try testing.expectEqual(@as(u64, 0), r.mock.row("i10.0.0.0/24", "a.A/Get").local);
        } else {
            // off: the header is ignored, both are the socket peer
            try testing.expectEqual(@as(u32, 10), a + bcount);
            try testing.expectEqual(@as(u64, 10), r.mock.row("i10.0.0.0/24", "a.A/Get").local);
            try testing.expectEqual(@as(u64, 0), r.mock.row("i198.51.100.0/24", "a.A/Get").local);
        }
    }
}

test "gate: a wrong token or edge id is a configuration error, said at most once a minute, and nothing is unlimited" {
    var r = try Rig.init(.{});
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":100,\"burst\":100,\"ttl_s\":60,\"lease_units\":null"));
    try r.learn("key-a");
    inline for (.{ 403, 401 }) |status| {
        r.mock.status = status;
        r.clock.advanceMs(61_000);
        const lines = r.logs.lines;
        const errs = r.logs.errors;
        // resolve, free tier and usage all fail
        try testing.expect(r.run("key-a", "198.51.100.1", r.get)); // the cached answer, in grace
        r.pump();
        _ = r.g.refreshFree();
        r.clock.advanceMs(5000);
        r.g.tick(r.clock.mono, r.clock.wall);
        try testing.expect(r.g.sendStep().? != 0);
        for (0..50) |_| {
            _ = r.call("key-new", "203.0.113.9", r.get);
            r.pump();
            r.clock.advanceMs(100);
        }
        try testing.expect(!r.g.reachable.load(.monotonic));
        try testing.expectEqual(lines + 1, r.logs.lines);
        try testing.expectEqual(errs + 1, r.logs.errors);
        try testing.expect(r.g.m.config_errors.load(.monotonic) >= 3);
        // an unknown key is under the free tier, not waved through
        var passed: u32 = 0;
        for (0..100) |_| {
            if (r.run("key-other", "203.0.113.77", r.get)) passed += 1;
        }
        try testing.expect(passed <= 10);
    }
    try testing.expect(std.mem.indexOf(u8, r.logs.text.items, "--gate-token-file") != null);
    try testing.expect(std.mem.indexOf(u8, r.logs.text.items, "HTTP 403") != null);
    // the usage is still in the spool, and goes out when the credential is fixed
    r.mock.status = null;
    r.clock.advanceMs(61_000);
    while (r.g.sendStep()) |w| if (w != 0) break;
    try testing.expect(r.mock.row("kkid_a", "a.A/Get").local >= 2);
    try testing.expect(r.g.reachable.load(.monotonic));
}

test "gate: no key and no token in any log line, spool byte, kept file or metric" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const secrets = [_][]const u8{ "key-SECRET-alpha-1111", "key-SECRET-beta-2222", "key-SECRET-gamma-3333", "key-SECRET-delta-4444", token };
    var r = try Rig.init(.{ .dir = tmp.dir });
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey(secrets[0], okKey(&b, "kid_alpha", ",\"rps\":5,\"burst\":5,\"max_streams\":1,\"ttl_s\":60,\"lease_units\":20"));
    try r.mock.setKey(secrets[1], "{\"key_id\":\"kid_beta\",\"status\":\"suspended\",\"ttl_s\":300}");
    _ = r.g.refreshFree();
    try r.learn(secrets[0]);
    try r.learn(secrets[1]);
    try r.learn(secrets[2]); // invalid
    for (0..30) |_| {
        _ = r.run(secrets[0], "198.51.100.1", r.get); // allowed, limited, lease spent
        _ = r.call(secrets[1], "198.51.100.1", r.get);
        _ = r.call(secrets[2], "198.51.100.1", r.get);
        r.pump();
    }
    var w = r.call(secrets[0], "198.51.100.1", r.watch);
    if (w == .allow) r.g.streamClose(&w.allow, r.clock.mono);
    r.flush();
    // failures of every kind, each of which logs
    r.clock.advanceMs(61_000);
    r.mock.down = true;
    _ = r.call(secrets[3], "198.51.100.1", r.get);
    _ = r.run(secrets[0], "198.51.100.1", r.get);
    r.pump();
    r.clock.advanceMs(61_000);
    r.mock.down = false;
    r.mock.status = 403;
    _ = r.run(secrets[0], "198.51.100.1", r.get);
    r.pump();
    _ = r.g.refreshFree();
    r.clock.advanceMs(61_000);
    r.mock.status = 500;
    r.flush();
    r.clock.advanceMs(61_000);
    r.mock.status = null;
    try r.mock.setKey(secrets[3], "this is not json");
    r.clock.advanceMs(61_000);
    _ = r.call(secrets[3], "198.51.100.1", r.get);
    r.pump();
    r.second();
    try testing.expect(r.logs.lines >= 3);
    var metrics: Io.Writer.Allocating = .init(testing.allocator);
    defer metrics.deinit();
    try r.g.renderMetrics(&metrics.writer);
    const spool_bytes = try tmp.dir.readFileAlloc(io, spool_mod.file_name, testing.allocator, .unlimited);
    defer testing.allocator.free(spool_bytes);
    const free_bytes = try tmp.dir.readFileAlloc(io, "free.json", testing.allocator, .unlimited);
    defer testing.allocator.free(free_bytes);
    try testing.expect(spool_bytes.len > 8);
    for (secrets) |s| {
        try testing.expect(std.mem.indexOf(u8, r.logs.text.items, s) == null);
        try testing.expect(std.mem.indexOf(u8, spool_bytes, s) == null);
        try testing.expect(std.mem.indexOf(u8, free_bytes, s) == null);
        try testing.expect(std.mem.indexOf(u8, metrics.writer.buffered(), s) == null);
        // nor in what the gate was sent as usage
        for (r.mock.batches.values()) |body| try testing.expect(std.mem.indexOf(u8, body, s) == null);
    }
    // the usage names the key by its id, and metric labels carry neither keys nor key ids
    try testing.expect(std.mem.indexOf(u8, spool_bytes, "kid_alpha") != null or r.mock.row("kkid_alpha", "a.A/Get").local > 0);
    try testing.expect(std.mem.indexOf(u8, metrics.writer.buffered(), "kid_") == null);
    try testing.expect(std.mem.indexOf(u8, metrics.writer.buffered(), "198.51.100") == null);
    // the gate did get the keys, in resolve bodies and nowhere else
    try testing.expectEqualStrings(secrets[0], r.mock.asked.items[0]);
}

test "gate: metrics in the node's style, labelled by plan and method" {
    var r = try Rig.init(.{});
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":2,\"burst\":2,\"ttl_s\":60,\"lease_units\":null"));
    try r.learn("key-a");
    try r.learn("key-bad");
    _ = r.g.refreshFree();
    for (0..5) |_| _ = r.run("key-a", "198.51.100.1", r.get);
    _ = r.run("", "198.51.100.1", r.put);
    _ = r.call("key-bad", "198.51.100.1", r.get);
    r.flush();
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try r.g.renderMetrics(&out.writer);
    const text = out.writer.buffered();
    inline for (.{
        "zui_gate_allowed{plan=\"developer\",method=\"a.A/Get\"} 2\n",
        "zui_gate_allowed{plan=\"keyless\",method=\"a.A/Put\"} 1\n",
        "zui_gate_limited{plan=\"developer\",method=\"a.A/Get\"} 3\n",
        "zui_gate_refused{reason=\"invalid\"} 1\n",
        "zui_gate_refused{reason=\"suspended\"} 0\n",
        "zui_gate_refused{reason=\"over_limit\"} 3\n",
        "zui_gate_refused{reason=\"exhausted\"} 0\n",
        "zui_gate_refused{reason=\"unknown_status\"} 0\n",
        "zui_gate_resolves 2\n",
        "zui_gate_resolve_errors 0\n",
        "zui_gate_resolve_seconds_count 2\n",
        "zui_gate_resolve_seconds_bucket{le=\"0.005\"} 2\n",
        "zui_gate_cache_keys 2\n",
        "zui_gate_cache_addresses 1\n",
        "zui_gate_spool_bytes ",
        "zui_gate_usage_batches_sent 1\n",
        "zui_gate_usage_batches_failed 0\n",
        "zui_gate_free_tier_known 1\n",
        "zui_gate_reachable 1\n",
    }) |want| {
        if (std.mem.indexOf(u8, text, want) == null) {
            std.debug.print("missing metric line: {s}\n{s}\n", .{ want, text });
            return error.TestExpectedMetric;
        }
    }
}

test "gate: many price tables stay bounded and are given back with their keys" {
    var r = try Rig.init(.{ .key_capacity = 256 });
    defer r.deinit();
    var kb: [32]u8 = undefined;
    var jb: [512]u8 = undefined;
    var n: u32 = 0;
    // every key its own price table
    while (n < 40) : (n += 1) {
        const key = std.fmt.bufPrint(&kb, "key-{d}", .{n}) catch unreachable;
        var idb: [16]u8 = undefined;
        const kid = std.fmt.bufPrint(&idb, "kid_{d}", .{n}) catch unreachable;
        try r.mock.setKey(key, std.fmt.bufPrint(&jb, "{{\"key_id\":\"{s}\",\"status\":\"ok\",\"rps\":10,\"burst\":10,\"ttl_s\":60,\"lease_units\":null,\"weights\":{{\"default\":1,\"a.A/Get\":{d}}}}}", .{ kid, n + 2 }) catch unreachable);
        r.clock.advanceMs(100);
        _ = r.call(key, "198.51.100.1", r.get);
        r.pump();
        const d = r.callNoWait(key, "198.51.100.1", r.get);
        try testing.expect(d == .allow and d.allow.cost == n + 2);
    }
    const in_use = r.g.prices.inUse();
    try testing.expect(in_use >= 40 and in_use <= 42);
    // out of grace, the sweep drops the keys and their tables go back to the pool
    r.clock.advanceMs((3600 + 61 + 5) * 1000);
    for (0..20) |_| r.second();
    try testing.expectEqual(@as(u32, 0), r.g.keys.used.load(.monotonic));
    try testing.expect(r.g.prices.inUse() <= 2);
}

// ---------------------------------------------------------------- with the real threads

fn waitFor(comptime what: []const u8, ctx: anytype, comptime pred: fn (@TypeOf(ctx)) bool, timeout_ms: u32) !void {
    var waited: u32 = 0;
    while (waited < timeout_ms) : (waited += 5) {
        if (pred(ctx)) return;
        testing.io.sleep(.fromMilliseconds(5), .awake) catch {};
    }
    std.debug.print("timed out waiting for: {s}\n", .{what});
    return error.TestTimedOut;
}

test "gate threads: a first call waits for its resolve, a slow gate costs at most the wait, never the serving thread" {
    var r = try Rig.init(.{ .real_clock = true, .wait_ms = 150 });
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-fast", okKey(&b, "kid_fast", ",\"rps\":100,\"burst\":100,\"ttl_s\":60,\"lease_units\":null"));
    try r.mock.setKey("key-slow", okKey(&b, "kid_slow", ",\"rps\":100,\"burst\":100,\"ttl_s\":60,\"lease_units\":null"));
    try r.g.start();
    const peer = ident.Ip.parse("198.51.100.1").?;
    const clock: gate_mod.Clock = .{};
    // a gate that answers in 20 ms: the first call comes back as the key, well inside the wait
    r.mock.delay_ms = 20;
    var t0 = clock.mono(null);
    const fast = r.g.admitWait(&.{ .key = "key-fast", .peer = peer, .method = r.get });
    var took = (clock.mono(null) - t0) / ns_per_ms;
    try testing.expect(fast == .allow and fast.allow.kind == .key);
    try testing.expect(took < 140);
    // a gate that takes 600 ms: the call gets free-tier treatment after about 150 ms
    r.mock.delay_ms = 600;
    t0 = clock.mono(null);
    const slow = r.g.admitWait(&.{ .key = "key-slow", .peer = peer, .method = r.get });
    took = (clock.mono(null) - t0) / ns_per_ms;
    try testing.expect(slow == .allow and slow.allow.kind == .ip);
    try testing.expect(took >= 140 and took < 450);
    try testing.expectEqual(@as(u64, 1), r.g.m.wait_timeouts.load(.monotonic));
    // meanwhile a known key is not held up at all
    t0 = clock.mono(null);
    for (0..50) |_| try testing.expect(r.g.admitWait(&.{ .key = "key-fast", .peer = peer, .method = r.get }) == .allow);
    try testing.expect((clock.mono(null) - t0) / ns_per_ms < 50);
    // and the resolve finishes behind the scenes
    const Ctx = struct {
        g: *Gate,
        fn resolved(c: @This()) bool {
            const f = c.g.keys.find(c.g.keyHash("key-slow")) orelse return false;
            return f.cfg.status == .ok;
        }
    };
    try waitFor("the slow key's resolve", Ctx{ .g = r.g }, Ctx.resolved, 3000);
    const later = r.g.admitWait(&.{ .key = "key-slow", .peer = peer, .method = r.get });
    try testing.expect(later == .allow and later.allow.kind == .key);
    r.mock.delay_ms = 0;
}

test "gate threads: calls from many threads are all counted and reach the gate; stop is bounded" {
    var r = try Rig.init(.{ .real_clock = true, .cut_ns = 0 });
    defer r.deinit();
    var b: [512]u8 = undefined;
    try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":1000000,\"burst\":1000000,\"ttl_s\":60,\"lease_units\":null"));
    try r.g.start();
    const peer = ident.Ip.parse("198.51.100.1").?;
    const first = r.g.admitWait(&.{ .key = "key-a", .peer = peer, .method = r.get });
    try testing.expect(first == .allow and first.allow.kind == .key);
    r.g.settle(&first.allow, .local, true, 1);
    const Worker = struct {
        fn run(g: *Gate, method: u8) void {
            const p = ident.Ip.parse("198.51.100.1").?;
            for (0..5000) |_| {
                const d = g.admitWait(&.{ .key = "key-a", .peer = p, .method = method });
                if (d == .allow) g.settle(&d.allow, .local, true, 1);
            }
        }
    };
    var threads: [8]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{ r.g, r.get });
    for (threads) |t| t.join();
    const Ctx = struct {
        m: *mock_mod.MockGate,
        fn all(c: @This()) bool {
            return c.m.row("kkid_a", "a.A/Get").local == 40_001;
        }
    };
    try waitFor("every call in the gate's usage", Ctx{ .m = r.mock }, Ctx.all, 8000);
    try testing.expectEqual(@as(u64, 40_001), r.mock.total.units);
    try testing.expectEqual(@as(u32, 0), r.mock.duplicates_differ);
    const clock: gate_mod.Clock = .{};
    const t0 = clock.mono(null);
    r.g.stop();
    try testing.expect((clock.mono(null) - t0) / ns_per_ms < 2000);
}

/// A way to the gate on which usage posts never get an answer: the call returns only when the
/// gate cancels it (as the node's client does at a stop).
const HangingUsage = struct {
    mock: *mock_mod.MockGate = undefined,
    canceled: std.atomic.Value(bool) = .init(false),
    in_post: std.atomic.Value(u32) = .init(0),

    fn call(ctx: *anyopaque, req: *const gate_mod.HttpRequest, out: *std.ArrayList(u8), gpa: std.mem.Allocator) anyerror!gate_mod.Reply {
        const h: *HangingUsage = @ptrCast(@alignCast(ctx));
        if (std.mem.endsWith(u8, req.url, "/usage")) {
            _ = h.in_post.fetchAdd(1, .monotonic);
            while (!h.canceled.load(.acquire)) testing.io.sleep(.fromMilliseconds(2), .awake) catch {};
            return error.Stopped;
        }
        const t = h.mock.transport();
        return t.call(t.ctx, req, out, gpa);
    }
    fn cancel(ctx: *anyopaque) void {
        const h: *HangingUsage = @ptrCast(@alignCast(ctx));
        h.canceled.store(true, .release);
    }
    fn transport(h: *HangingUsage) gate_mod.Transport {
        return .{ .ctx = h, .call = call, .cancel = cancel };
    }
};

test "gate threads: a stop during a usage post that never answers returns at once, with everything counted in the spool" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var b: [512]u8 = undefined;
    const peer = ident.Ip.parse("198.51.100.1").?;
    {
        var hang: HangingUsage = .{};
        var r = try Rig.init(.{ .dir = tmp.dir, .real_clock = true, .cut_ns = 0, .transport = hang.transport() });
        defer r.deinit();
        hang.mock = r.mock;
        try r.mock.setKey("key-a", okKey(&b, "kid_a", ",\"rps\":1000,\"burst\":1000,\"ttl_s\":60,\"lease_units\":null"));
        try r.g.start();
        for (0..5) |_| {
            const d = r.g.admitWait(&.{ .key = "key-a", .peer = peer, .method = r.get });
            try testing.expect(d == .allow and d.allow.kind == .key);
            r.g.settle(&d.allow, .local, true, 1);
        }
        const Posting = struct {
            h: *HangingUsage,
            fn now(c: @This()) bool {
                return c.h.in_post.load(.monotonic) >= 1;
            }
        };
        try waitFor("the usage post in flight", Posting{ .h = &hang }, Posting.now, 8000);
        // counted while that post hangs: in no batch yet
        for (0..3) |_| {
            const d = r.g.admitWait(&.{ .key = "key-a", .peer = peer, .method = r.put });
            try testing.expect(d == .allow);
            r.g.settle(&d.allow, .local, true, 1);
        }
        // the stop does not wait for the answer that never comes (the usage timeout is 10 s)
        const clock: gate_mod.Clock = .{};
        const t0 = clock.mono(null);
        r.g.stop();
        try testing.expect((clock.mono(null) - t0) / ns_per_ms < 1500);
        try testing.expectEqual(@as(usize, 0), r.mock.batches.count());
    }
    // on disk: the batch that was being posted, with its id and body, and the three calls after it
    {
        var sp = try spool_mod.Spool.open(testing.allocator, testing.io, tmp.dir, spool_mod.default_cap);
        defer sp.deinit();
        try testing.expectEqualStrings("e1-boot1-0", sp.sealed.?.id);
        try testing.expect(std.mem.indexOf(u8, sp.sealed.?.body, "\"key_id\":\"kid_a\",\"method\":\"a.A/Get\"") != null);
        // (the five Gets are in the sealed batch, or split with the next window when a tick
        // fell between them; with the three Puts that is eight calls in all)
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const v = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), sp.sealed.?.body, .{});
        var sealed_calls: u64 = 0;
        for (v.object.get("rows").?.array.items) |row| sealed_calls += @intCast(row.object.get("local").?.integer);
        try testing.expect(sealed_calls >= 1);
        try testing.expectEqual(@as(u64, 8), sealed_calls + sp.totals().local);
        try testing.expectEqual(@as(u64, 8), sealed_calls + sp.totals().units);
        try testing.expectEqual(@as(u64, 0), sp.stats.torn_bytes);
    }
    // the next start posts it with the same id, then the rest
    {
        var r = try Rig.init(.{ .dir = tmp.dir, .boot_id = "boot2" });
        defer r.deinit();
        r.flush();
        try testing.expectEqualStrings("e1-boot1-0", r.mock.batches.keys()[0]);
        try testing.expectEqual(@as(u64, 5), r.mock.row("kkid_a", "a.A/Get").local);
        try testing.expectEqual(@as(u64, 3), r.mock.row("kkid_a", "a.A/Put").local);
    }
}
