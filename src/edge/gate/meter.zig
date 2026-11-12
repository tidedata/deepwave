//! Usage counters on the serving path. Each serving thread counts into its own stripe (a small
//! table behind a lock nobody else takes while the thread count is at or under `stripes`), so
//! counting a call writes no cache line another serving thread reads. Once a second the gate's
//! tick takes every stripe's rows (`collect`) and journals them.
//!
//! A row is (who, method): who is a key, by the hash of the key with its key id copied in when
//! the row is made, or a keyless caller's prefix. A stripe that has no room for a new row sends
//! it to `spill`, a table under a lock, which grows up to `spill_max` rows; past that, keyless
//! rows fold into one catch-all row per method and keyed rows are counted as lost (a number the
//! gate reports; with the default sizes that takes more than 290,000 distinct (who, method)
//! pairs within one second).
const std = @import("std");
const Atomic = std.atomic.Value;
const Allocator = std.mem.Allocator;
const contract = @import("contract.zig");
const state = @import("state.zig");
const ident = @import("ident.zig");
const methods = @import("methods.zig");
const Counters = contract.Counters;

pub const stripes = 64;
pub const rows_per_stripe = 512;
pub const probe = 8;
pub const spill_max = 1 << 18;

pub const Kind = enum(u8) { key, ip };

pub const Row = struct {
    used: bool = false,
    kind: Kind = .ip,
    method: u8 = 0,
    plan: u8 = 0,
    kid_len: u8 = 0,
    /// The key's hash, or the prefix key.
    h: u64 = 0,
    kid: [contract.max_key_id_len]u8 = undefined,
    c: Counters = .{},
};

/// Who a count belongs to.
pub const Who = union(Kind) {
    /// A resolved key: its table entry and the tenant seen at admission, the hash of the key,
    /// and the caller's prefix in case the entry changed hands before the row was made.
    key: struct { h: u64, entry: *const state.Entry, tenant: u32, prefix: u64 },
    ip: u64,
};

const Stripe = struct {
    lock: state.SpinLock align(std.atomic.cache_line) = .{},
    n: u32 = 0,
    used: [rows_per_stripe]u16 = undefined,
    rows: [rows_per_stripe]Row = @splat(.{}),
};

threadlocal var my_stripe: u32 = std.math.maxInt(u32);

pub const Meter = struct {
    gpa: Allocator,
    next_stripe: Atomic(u32) = .init(0),
    stripe: []Stripe,
    spill_lock: state.SpinLock = .{},
    spill: std.AutoHashMapUnmanaged(SpillKey, Row) = .empty,
    catch_all: [methods.max_methods][2]Counters = @splat(@splat(.{})),
    /// Counts that found no row anywhere (see the module text).
    lost_calls: Atomic(u64) = .init(0),
    lost_units: Atomic(u64) = .init(0),
    spilled: Atomic(u64) = .init(0),

    const SpillKey = struct { h: u64, method: u8, kind: Kind };

    pub fn init(gpa: Allocator) !*Meter {
        const m = try gpa.create(Meter);
        errdefer gpa.destroy(m);
        const st = try gpa.alloc(Stripe, stripes);
        for (st) |*s| {
            s.lock = .{};
            s.n = 0;
            for (&s.rows) |*r| r.used = false;
        }
        m.* = .{ .gpa = gpa, .stripe = st };
        return m;
    }

    pub fn deinit(m: *Meter) void {
        m.spill.deinit(m.gpa);
        m.gpa.free(m.stripe);
        m.gpa.destroy(m);
    }

    fn stripeOf(m: *Meter) *Stripe {
        if (my_stripe == std.math.maxInt(u32)) my_stripe = m.next_stripe.fetchAdd(1, .monotonic) % stripes;
        return &m.stripe[my_stripe];
    }

    /// Adds `c` to the row of (`who`, `method`). No allocation unless the stripe is full.
    pub fn add(m: *Meter, who: Who, method: u8, plan: u8, c: Counters) void {
        const kind: Kind = who;
        const h: u64 = switch (who) {
            .key => |k| k.h,
            .ip => |p| p,
        };
        const s = m.stripeOf();
        const base: u32 = @truncate((h ^ (@as(u64, method) *% 0x9e3779b97f4a7c15)) >> 7);
        s.lock.lock();
        var free: ?u32 = null;
        var i: u32 = 0;
        while (i < probe) : (i += 1) {
            const idx = (base +% i) % rows_per_stripe;
            const r = &s.rows[idx];
            if (!r.used) {
                if (free == null) free = idx;
                continue;
            }
            if (r.h == h and r.method == method and r.kind == kind) {
                r.c.add(c);
                s.lock.unlock();
                return;
            }
        }
        var row: Row = .{ .used = true, .kind = kind, .method = method, .plan = plan, .h = h, .c = c };
        switch (who) {
            .ip => {},
            .key => |k| {
                const kid = k.entry.readKid(k.tenant, &row.kid) orelse {
                    // the slot went to another key between admission and here: the count goes
                    // to the caller's prefix instead of to the wrong key
                    s.lock.unlock();
                    return m.add(.{ .ip = k.prefix }, method, state.Plans.free, c);
                };
                if (kid.len == 0) {
                    s.lock.unlock();
                    return m.add(.{ .ip = k.prefix }, method, state.Plans.free, c);
                }
                row.kid_len = @intCast(kid.len);
            },
        }
        if (free) |idx| {
            s.rows[idx] = row;
            s.used[s.n] = @intCast(idx);
            s.n += 1;
            s.lock.unlock();
            return;
        }
        s.lock.unlock();
        m.spillRow(row);
    }

    fn spillRow(m: *Meter, row: Row) void {
        _ = m.spilled.fetchAdd(1, .monotonic);
        m.spill_lock.lock();
        defer m.spill_lock.unlock();
        const key: SpillKey = .{ .h = row.h, .method = row.method, .kind = row.kind };
        if (m.spill.getPtr(key)) |r| return r.c.add(row.c);
        if (m.spill.count() < spill_max) {
            if (m.spill.put(m.gpa, key, row)) |_| return else |_| {}
        }
        if (row.kind == .ip) {
            m.catch_all[row.method][@intFromBool(row.h >> 56 == 6)].add(row.c);
            return;
        }
        _ = m.lost_calls.fetchAdd(row.c.local + row.c.forwarded + row.c.limited, .monotonic);
        _ = m.lost_units.fetchAdd(row.c.units, .monotonic);
    }

    /// Moves every row out (appended to `out`) and leaves the meter empty.
    pub fn collect(m: *Meter, out: *std.ArrayList(Row), gpa: Allocator) !void {
        for (m.stripe) |*s| {
            if (@atomicLoad(u32, &s.n, .monotonic) == 0) continue;
            try out.ensureUnusedCapacity(gpa, rows_per_stripe);
            s.lock.lock();
            for (s.used[0..s.n]) |idx| {
                out.appendAssumeCapacity(s.rows[idx]);
                s.rows[idx].used = false;
            }
            s.n = 0;
            s.lock.unlock();
        }
        {
            m.spill_lock.lock();
            var spill = m.spill;
            m.spill = .empty;
            const ca = m.catch_all;
            m.catch_all = @splat(@splat(.{}));
            m.spill_lock.unlock();
            defer spill.deinit(m.gpa);
            var it = spill.valueIterator();
            while (it.next()) |r| try out.append(gpa, r.*);
            for (ca, 0..) |pair, method| for (pair, 0..) |c, v6| {
                if (c.zero()) continue;
                try out.append(gpa, .{ .used = true, .kind = .ip, .method = @intCast(method), .plan = state.Plans.free, .h = if (v6 == 1) ident.prefix_other_v6 else ident.prefix_other_v4, .c = c });
            };
        }
    }
};

/// A row's subject as the spool and the usage body write it: `k<key id>` or `i<prefix>`.
pub fn subjectText(buf: *[contract.max_key_id_len + 1]u8, r: *const Row) []const u8 {
    switch (r.kind) {
        .key => {
            buf[0] = 'k';
            @memcpy(buf[1..][0..r.kid_len], r.kid[0..r.kid_len]);
            return buf[0 .. 1 + @as(usize, r.kid_len)];
        },
        .ip => {
            buf[0] = 'i';
            var pb: [ident.prefix_text_max]u8 = undefined;
            const t = ident.prefixText(&pb, r.h);
            @memcpy(buf[1..][0..t.len], t);
            return buf[0 .. 1 + t.len];
        },
    }
}

const testing = std.testing;

test "meter: rows by who and method, key ids copied in, collected and emptied" {
    const gpa = testing.allocator;
    const m = try Meter.init(gpa);
    defer m.deinit();
    var e: state.Entry = .{};
    e.setKid("kid_one");
    const tenant = e.tenant.load(.monotonic);
    const who: Who = .{ .key = .{ .h = 0x1234_5678_9abc, .entry = &e, .tenant = tenant, .prefix = (ident.Ip.parse("203.0.113.9").?).prefixKey() } };
    m.add(who, 3, 2, .{ .local = 1, .units = 5 });
    m.add(who, 3, 2, .{ .forwarded = 1, .units = 10 });
    m.add(who, 4, 2, .{ .limited = 1 });
    m.add(.{ .ip = (ident.Ip.parse("2001:db8:1::9").?).prefixKey() }, 3, 0, .{ .local = 2, .units = 2, .stream_msgs = 7 });
    var out: std.ArrayList(Row) = .empty;
    defer out.deinit(gpa);
    try m.collect(&out, gpa);
    try testing.expectEqual(@as(usize, 3), out.items.len);
    var sb: [contract.max_key_id_len + 1]u8 = undefined;
    var seen: u32 = 0;
    for (out.items) |*r| {
        const subj = subjectText(&sb, r);
        if (r.kind == .key and r.method == 3) {
            try testing.expectEqualStrings("kkid_one", subj);
            try testing.expectEqual(Counters{ .local = 1, .forwarded = 1, .units = 15 }, r.c);
            seen |= 1;
        } else if (r.kind == .key) {
            try testing.expectEqual(@as(u64, 1), r.c.limited);
            seen |= 2;
        } else {
            try testing.expectEqualStrings("i2001:db8:1::/48", subj);
            try testing.expectEqual(@as(u64, 7), r.c.stream_msgs);
            seen |= 4;
        }
    }
    try testing.expectEqual(@as(u32, 7), seen);
    out.clearRetainingCapacity();
    try m.collect(&out, gpa);
    try testing.expectEqual(@as(usize, 0), out.items.len);
    // the slot changed hands before the row was made: the count goes to the caller's prefix
    e.setKid("kid_two");
    m.add(who, 3, 2, .{ .local = 1, .units = 1 });
    try m.collect(&out, gpa);
    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqualStrings("i203.0.113.0/24", subjectText(&sb, &out.items[0]));
}

test "meter: more rows in a second than a stripe holds spill over, nothing is lost" {
    const gpa = testing.allocator;
    const m = try Meter.init(gpa);
    defer m.deinit();
    const n = 20_000;
    var i: u64 = 0;
    while (i < n) : (i += 1) m.add(.{ .ip = (@as(u64, 4) << 56) | i }, 1, 0, .{ .local = 1, .units = 2 });
    try testing.expect(m.spilled.load(.monotonic) > 0);
    var out: std.ArrayList(Row) = .empty;
    defer out.deinit(gpa);
    try m.collect(&out, gpa);
    var total: Counters = .{};
    for (out.items) |r| total.add(r.c);
    try testing.expectEqual(@as(u64, n), total.local);
    try testing.expectEqual(@as(u64, 2 * n), total.units);
    try testing.expectEqual(@as(usize, n), out.items.len);
    try testing.expectEqual(@as(u64, 0), m.lost_calls.load(.monotonic));
}

test "meter: threads count on their own stripes and every count arrives" {
    const gpa = testing.allocator;
    const m = try Meter.init(gpa);
    defer m.deinit();
    const Worker = struct {
        fn run(mm: *Meter, id: u64) void {
            var k: u64 = 0;
            while (k < 20_000) : (k += 1) mm.add(.{ .ip = (@as(u64, 4) << 56) | (k % 50) }, @intCast(id % 4), 0, .{ .local = 1, .units = 1 });
        }
    };
    var threads: [8]std.Thread = undefined;
    for (&threads, 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ m, id });
    var out: std.ArrayList(Row) = .empty;
    defer out.deinit(gpa);
    // collect while they run, as the tick does
    var rounds: u32 = 0;
    while (rounds < 20) : (rounds += 1) try m.collect(&out, gpa);
    for (threads) |t| t.join();
    try m.collect(&out, gpa);
    var total: u64 = 0;
    for (out.items) |r| total += r.c.local;
    try testing.expectEqual(@as(u64, 8 * 20_000), total);
}
