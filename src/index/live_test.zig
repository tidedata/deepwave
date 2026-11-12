//! Unit tests of the indexes against a live commit path (review round 1 of lane indexes):
//! the index trails the store (prepare before the commit, publish after), a request's snapshot is
//! taken under the index lock, the lock is free while pages read the store and render, and the
//! futex-backed RwLock under contention.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const serve = @import("serve");
const index = @import("root.zig");
const state = @import("state.zig");
const feed = @import("feed.zig");

const testing = std.testing;
const proto = serve.proto;

fn addr(n: u8) [32]u8 {
    var a: [32]u8 = @splat(0);
    a[31] = n;
    return a;
}

fn cfgSmall() store.Config {
    return .{
        .max_live_objects = 1024,
        .max_object_versions = 4096,
        .max_transactions = 1024,
        .max_checkpoints = 1024,
        .max_batch_bytes = 1 << 20,
        .max_batch_objects = 256,
        .max_segments = 64,
        .index_flush_interval = 8,
        .segment_reserve = 8 << 20,
        .seed = 41,
    };
}

/// BCS(Object) of a `Coin<SUI>` owned by `owner_kind`/`owner`.
fn coin(a: std.mem.Allocator, id: [32]u8, version: u64, balance: u64, owner: [32]u8, object_owned: bool) ![]const u8 {
    var contents: [40]u8 = undefined;
    @memcpy(contents[0..32], &id);
    std.mem.writeInt(u64, contents[32..40], balance, .little);
    const o: types.Object = .{
        .data = .{ .Move = .{ .type_ = .{ .@"0" = .GasCoin }, .has_public_transfer = true, .version = .{ .@"0" = version }, .contents = &contents } },
        .owner = if (object_owned) .{ .ObjectOwner = .{ .@"0" = owner } } else .{ .AddressOwner = .{ .@"0" = owner } },
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(7) } },
        .storage_rebate = 0,
    };
    return bcs.encodeAlloc(types.Object, a, &o);
}

fn putRaw(b: *store.Batch, raw: []const u8, id: [32]u8, version: u64) !void {
    try b.putObject(&id, version, &types.digest.objectDigest(raw), raw);
}

const Env = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    sim: *store.SimIo,
    st: *store.Store,
    ix: index.Index,
    svc: serve.service.Service,
    cfg: store.Config,

    fn init(e: *Env) !void {
        const gpa = testing.allocator;
        e.gpa = gpa;
        e.arena = .init(gpa);
        e.cfg = cfgSmall();
        e.sim = try store.SimIo.init(gpa, 41, .{}, 8 << 20);
        e.st = try store.Store.open(gpa, .{ .sim = e.sim }, &e.cfg);
        e.ix = try index.Index.init(gpa);
        e.svc = .{ .gpa = gpa, .store = e.st, .chain_id = @splat(0) };
        e.svc.state = state.hook(&e.ix);
    }

    fn deinit(e: *Env) void {
        e.svc.deinit();
        e.ix.deinit();
        e.st.deinit();
        e.sim.deinit();
        e.arena.deinit();
    }

    /// Commits `objs` as checkpoint `seq` (no index work).
    fn commit(e: *Env, seq: u64, objs: []const struct { raw: []const u8, id: [32]u8, v: u64 }) !void {
        const b = try e.st.begin(seq, 0);
        for (objs) |o| try putRaw(b, o.raw, o.id, o.v);
        try b.checkpoint("summary", "contents");
        try e.st.commit(b);
    }

    fn call(e: *Env, a: std.mem.Allocator, method: []const u8, body: []const u8) !serve.loopback.Reply {
        const path = try std.fmt.allocPrint(a, "/sui.rpc.v2.StateService/{s}", .{method});
        return serve.loopback.unary(a, e.svc.handler(), path, body);
    }
};

fn hexAddr(a: std.mem.Allocator, x: *const [32]u8) ![]const u8 {
    return std.fmt.allocPrint(a, "0x{s}", .{&std.fmt.bytesToHex(x.*, .lower)});
}

/// ListOwnedObjects (or ListDynamicFields with `fields`) request: owner/parent, read-mask paths.
fn listBody(a: std.mem.Allocator, owner: *const [32]u8, paths: []const []const u8) ![]const u8 {
    const mask_buf = try a.alloc(u8, 512);
    var mw = proto.Writer.init(mask_buf);
    for (paths) |p| try mw.string(1, p);
    const buf = try a.alloc(u8, 1024);
    var w = proto.Writer.init(buf);
    try w.string(1, try hexAddr(a, owner));
    if (paths.len > 0) try w.bytes(4, mw.bytesWritten());
    return w.bytesWritten();
}

fn balanceBody(a: std.mem.Allocator, owner: *const [32]u8) ![]const u8 {
    const buf = try a.alloc(u8, 256);
    var w = proto.Writer.init(buf);
    try w.string(1, try hexAddr(a, owner));
    try w.string(2, "0x2::sui::SUI");
    return w.bytesWritten();
}

/// The `version` (field 3) of every listed object (field 1) of a ListOwnedObjectsResponse.
fn versions(a: std.mem.Allocator, msg: []const u8) ![]u64 {
    var out: std.ArrayList(u64) = .empty;
    var r = proto.Reader.init(msg);
    while (try r.next()) |f| {
        if (f.number != 1) continue;
        var ir = proto.Reader.init(try proto.Reader.bytesOf(f));
        var v: u64 = 0;
        while (try ir.next()) |g| if (g.number == 3) {
            v = try proto.Reader.varintOf(g);
        };
        try out.append(a, v);
    }
    std.mem.sort(u64, out.items, {}, std.sort.asc(u64));
    return out.items;
}

/// Balance.balance (field 3) of a GetBalanceResponse { balance = 1 }.
fn balanceOf(msg: []const u8) !u64 {
    var r = proto.Reader.init(msg);
    while (try r.next()) |f| if (f.number == 1) {
        var ir = proto.Reader.init(try proto.Reader.bytesOf(f));
        while (try ir.next()) |g| if (g.number == 3) return proto.Reader.varintOf(g);
    };
    return 0;
}

const owner_a = addr(0xa1);
const coin1 = addr(0xc1);
const coin2 = addr(0xc2);

/// Checkpoint 1: two SUI coins of owner A (100 at v5, 200 at v5), in the store and the index.
fn seed(e: *Env) !struct { c1v5: []const u8, c2v5: []const u8 } {
    const a = e.arena.allocator();
    const c1v5 = try coin(a, coin1, 5, 100, owner_a, false);
    const c2v5 = try coin(a, coin2, 5, 200, owner_a, false);
    try e.commit(1, &.{ .{ .raw = c1v5, .id = coin1, .v = 5 }, .{ .raw = c2v5, .id = coin2, .v = 5 } });
    try e.ix.insert(c1v5);
    try e.ix.insert(c2v5);
    e.ix.checkpoint = 1;
    return .{ .c1v5 = c1v5, .c2v5 = c2v5 };
}

/// ListOwnedObjects with a loading mask (bcs) and GetBalance at one point of the commit path.
fn expectPage(e: *Env, want_versions: []const u64, want_balance: u64) !void {
    var arena_state = std.heap.ArenaAllocator.init(e.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const rep = try e.call(a, "ListOwnedObjects", try listBody(a, &owner_a, &.{ "object_id", "version", "bcs" }));
    try testing.expectEqual(@as(u8, 0), rep.status);
    try testing.expectEqualSlices(u64, want_versions, try versions(a, rep.message));
    const def = try e.call(a, "ListOwnedObjects", try listBody(a, &owner_a, &.{}));
    try testing.expectEqualSlices(u64, want_versions, try versions(a, def.message));
    const bal = try e.call(a, "GetBalance", try balanceBody(a, &owner_a));
    try testing.expectEqual(@as(u8, 0), bal.status);
    try testing.expectEqual(want_balance, try balanceOf(bal.message));
}

test "index trails the store: every point of a checkpoint's commit lists every row" {
    var e: Env = undefined;
    try e.init();
    defer e.deinit();
    const s = try seed(&e);
    const a = e.arena.allocator();
    const c1v6 = try coin(a, coin1, 6, 150, owner_a, false);

    var f = feed.Feed.init(e.gpa, &e.ix, e.st);
    defer f.deinit();
    // on_checkpoint: changes computed and held; neither the store nor the index moved
    try f.stage(2, &.{.{ .old = s.c1v5, .new = c1v6 }});
    try expectPage(&e, &.{ 5, 5 }, 300);
    // the commit: the store is at 2, the index still at 1; coin1 v5 is superseded but readable
    try e.commit(2, &.{.{ .raw = c1v6, .id = coin1, .v = 6 }});
    try expectPage(&e, &.{ 5, 5 }, 300);
    // on_committed: the index moves to 2
    try f.publish(2);
    try testing.expectEqual(@as(?u64, 2), e.ix.checkpoint);
    try expectPage(&e, &.{ 5, 6 }, 350);

    // The old order (index applied before the commit) drops coin1 from a loading page.
    var bad: Env = undefined;
    try bad.init();
    defer bad.deinit();
    const sb = try seed(&bad);
    const ba = bad.arena.allocator();
    const b1v6 = try coin(ba, coin1, 6, 150, owner_a, false);
    try bad.ix.applyChanges(2, &.{.{ .old = sb.c1v5, .new = b1v6 }});
    var arena_state = std.heap.ArenaAllocator.init(e.gpa);
    defer arena_state.deinit();
    const ta = arena_state.allocator();
    const rep = try bad.call(ta, "ListOwnedObjects", try listBody(ta, &owner_a, &.{ "object_id", "version", "bcs" }));
    try testing.expectEqualSlices(u64, &.{5}, try versions(ta, rep.message));
}

test "publish applies only the prepared checkpoint" {
    var e: Env = undefined;
    try e.init();
    defer e.deinit();
    const s = try seed(&e);
    const a = e.arena.allocator();
    var f = feed.Feed.init(e.gpa, &e.ix, e.st);
    defer f.deinit();
    // a commit with nothing prepared, and a prepare for another checkpoint, leave the index alone
    try f.publish(2);
    try f.stage(3, &.{.{ .old = s.c1v5, .new = try coin(a, coin1, 6, 150, owner_a, false) }});
    try f.publish(2);
    try testing.expectEqual(@as(u64, 2), f.unprepared);
    try testing.expectEqual(@as(?u64, 1), e.ix.checkpoint);
    // a newer prepare replaces one whose commit failed
    try f.stage(2, &.{.{ .old = s.c2v5, .new = null }});
    try f.publish(2);
    try testing.expectEqual(@as(?u64, 2), e.ix.checkpoint);
    const key = [_]u8{7} ++ comptime suiTagBcs();
    try testing.expect((try e.ix.balance(e.arena.allocator(), &owner_a, &key)).coin == 100);
}

fn suiTagBcs() [32 + 1 + 3 + 1 + 3 + 1]u8 {
    var b: [32 + 1 + 3 + 1 + 3 + 1]u8 = undefined;
    @memcpy(b[0..32], &addr(2));
    b[32] = 3;
    @memcpy(b[33..36], "sui");
    b[36] = 3;
    @memcpy(b[37..40], "SUI");
    b[40] = 0;
    return b;
}

const Reader = struct {
    e: *Env,
    got: []u64 = &.{},
    arena: std.heap.ArenaAllocator,
    err: ?anyerror = null,
    fn run(r: *Reader) void {
        const a = r.arena.allocator();
        const body = listBody(a, &owner_a, &.{ "object_id", "version", "bcs" }) catch |err| {
            r.err = err;
            return;
        };
        const rep = r.e.call(a, "ListOwnedObjects", body) catch |err| {
            r.err = err;
            return;
        };
        r.got = versions(a, rep.message) catch |err| {
            r.err = err;
            return;
        };
    }
};

test "a request's snapshot is at least as new as the index rows it reads" {
    var e: Env = undefined;
    try e.init();
    defer e.deinit();
    const s = try seed(&e);
    const a = e.arena.allocator();
    const c1v6 = try coin(a, coin1, 6, 150, owner_a, false);

    // The writer holds the lock; a request arrives and sleeps on it; the store commits 2 and the
    // index publishes 2; the request then copies rows at 2 and must read them at a snapshot >= 2.
    e.ix.lock.lock();
    var r: Reader = .{ .e = &e, .arena = .init(e.gpa) };
    defer r.arena.deinit();
    const t = try std.Thread.spawn(.{}, Reader.run, .{&r});
    while (!e.ix.lock.hasSleepers()) std.atomic.spinLoopHint();
    try e.commit(2, &.{.{ .raw = c1v6, .id = coin1, .v = 6 }});
    _ = try e.ix.applyChangesHeld(2, &.{.{ .old = s.c1v5, .new = c1v6 }});
    e.ix.lock.unlock();
    t.join();
    if (r.err) |err| return err;
    try testing.expectEqualSlices(u64, &.{ 5, 6 }, r.got);
}

var row_visits: usize = 0;
var row_locked: usize = 0;
fn checkFree(ix: *index.Index) void {
    row_visits += 1;
    if (ix.lock.tryLock()) ix.lock.unlock() else row_locked += 1;
}

test "the index lock is free while pages read the store and render" {
    var e: Env = undefined;
    try e.init();
    defer e.deinit();
    _ = try seed(&e);
    // a coin owned by object coin2 (a child row for ListDynamicFields; not a Field, so bare)
    const a = e.arena.allocator();
    const child_id = addr(0xd1);
    const child = try coin(a, child_id, 9, 1, coin2, true);
    try e.commit(2, &.{.{ .raw = child, .id = child_id, .v = 9 }});
    try e.ix.insert(child);

    row_visits = 0;
    row_locked = 0;
    state.test_on_row = checkFree;
    defer state.test_on_row = null;
    var arena_state = std.heap.ArenaAllocator.init(e.gpa);
    defer arena_state.deinit();
    const ta = arena_state.allocator();
    _ = try e.call(ta, "ListOwnedObjects", try listBody(ta, &owner_a, &.{ "object_id", "version", "bcs", "contents" }));
    _ = try e.call(ta, "ListOwnedObjects", try listBody(ta, &owner_a, &.{}));
    const df = try e.call(ta, "ListDynamicFields", try listBody(ta, &coin2, &.{ "parent", "field_id", "kind", "name", "value" }));
    try testing.expectEqual(@as(u8, 0), df.status);
    try testing.expect(row_visits >= 5);
    try testing.expectEqual(@as(usize, 0), row_locked);
    try testing.expectEqual(@as(u32, 0), e.ix.lock.readersInside());
}

test "RwLock: readers never see a half-applied write, and everyone finishes" {
    const Shared = struct {
        lock: index.RwLock = .{},
        x: u64 = 0,
        y: u64 = 0,
        torn: std.atomic.Value(u64) = .init(0),
        fn reader(s: *@This()) void {
            for (0..20_000) |_| {
                s.lock.lockShared();
                const x = @atomicLoad(u64, &s.x, .monotonic);
                for (0..8) |_| std.atomic.spinLoopHint();
                const y = @atomicLoad(u64, &s.y, .monotonic);
                s.lock.unlockShared();
                if (x != y) _ = s.torn.fetchAdd(1, .monotonic);
            }
        }
        fn writer(s: *@This()) void {
            for (0..3_000) |_| {
                s.lock.lock();
                @atomicStore(u64, &s.x, s.x + 1, .monotonic);
                for (0..64) |_| std.atomic.spinLoopHint();
                @atomicStore(u64, &s.y, s.y + 1, .monotonic);
                s.lock.unlock();
            }
        }
    };
    var sh: Shared = .{};
    var ts: [6]std.Thread = undefined;
    for (ts[0..5]) |*t| t.* = try std.Thread.spawn(.{}, Shared.reader, .{&sh});
    ts[5] = try std.Thread.spawn(.{}, Shared.writer, .{&sh});
    for (ts) |t| t.join();
    try testing.expectEqual(@as(u64, 0), sh.torn.load(.monotonic));
    try testing.expectEqual(@as(u64, 3_000), sh.x);
    try testing.expectEqual(@as(u32, 0), sh.lock.readersInside());
    try testing.expect(!sh.lock.writerIn());
}

// Reads during a commit (lane serve-tail 5982bb1, ported to the disk index): a checkpoint's
// objects are decoded before the index write lock is taken, so StateService requests served while
// the commit plans its rows neither wait nor see a half-applied checkpoint.
var plan_env: ?*Env = null;
var plan_calls: usize = 0;
var plan_locked: usize = 0;
var plan_bad: usize = 0;

fn readMidCommit(ix: *index.Index) void {
    plan_calls += 1;
    if (!ix.lock.tryLockShared()) {
        plan_locked += 1; // a request here would wait for the commit (or deadlock this thread)
        return;
    }
    ix.lock.unlockShared();
    const e = plan_env.?;
    var arena_state = std.heap.ArenaAllocator.init(e.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const lo = e.call(a, "ListOwnedObjects", listBody(a, &owner_a, &.{}) catch unreachable) catch {
        plan_bad += 1;
        return;
    };
    const gb = e.call(a, "GetBalance", balanceBody(a, &owner_a) catch unreachable) catch {
        plan_bad += 1;
        return;
    };
    const lb = e.call(a, "ListBalances", listBody(a, &owner_a, &.{}) catch unreachable) catch {
        plan_bad += 1;
        return;
    };
    // the checkpoint being planned is not visible yet: both v5 coins, 100 + 200
    const vs = versions(a, lo.message) catch &.{};
    const bal = balanceOf(gb.message) catch 0;
    if (lo.status != 0 or gb.status != 0 or lb.status != 0 or vs.len != 2 or bal != 300) plan_bad += 1;
}

test "reads are not blocked while a commit decodes its objects" {
    var e: Env = undefined;
    try e.init();
    defer e.deinit();
    const s = try seed(&e);
    const a = e.arena.allocator();
    const c1v6 = try coin(a, coin1, 6, 150, owner_a, false);
    const c2v6 = try coin(a, coin2, 6, 250, owner_a, false);
    try e.commit(2, &.{ .{ .raw = c1v6, .id = coin1, .v = 6 }, .{ .raw = c2v6, .id = coin2, .v = 6 } });

    plan_env = &e;
    plan_calls = 0;
    plan_locked = 0;
    plan_bad = 0;
    index.Index.test_on_plan = readMidCommit;
    defer index.Index.test_on_plan = null;
    try e.ix.applyChanges(2, &.{ .{ .old = s.c1v5, .new = c1v6 }, .{ .old = s.c2v5, .new = c2v6 } });
    index.Index.test_on_plan = null;
    try testing.expectEqual(@as(usize, 2), plan_calls);
    try testing.expectEqual(@as(usize, 0), plan_locked);
    try testing.expectEqual(@as(usize, 0), plan_bad);
    // after the commit: the new versions and the new sum
    var arena_state = std.heap.ArenaAllocator.init(e.gpa);
    defer arena_state.deinit();
    const ta = arena_state.allocator();
    const gb = try e.call(ta, "GetBalance", try balanceBody(ta, &owner_a));
    try testing.expectEqual(@as(u64, 400), try balanceOf(gb.message));
    const lo = try e.call(ta, "ListOwnedObjects", try listBody(ta, &owner_a, &.{}));
    try testing.expectEqualSlices(u64, &.{ 6, 6 }, try versions(ta, lo.message));
}

// ---------------------------------------------------------------- balances emptied to zero
//
// sui-node 1.83.1 keeps a balance row whose (coin, address) sum went to zero: the merge operator
// sums it to zero and only the compaction filter removes it later (sui-rpc-store schema/balance.rs
// `merge`, `compact`); `balance_iter` (reader/indexes.rs) has no zero filter, so ListBalances lists
// it, rendered by get_balance.rs `render_balance` as `balance: 0` with no coin_balance or
// address_balance (recorded: `recorded_page`). The owner is the live case of 2026-11-10: all its SUI is an address balance,
// and its USDC address balance was drained (the settlement then deletes the accumulator field,
// accumulator_settlement.move).

const owner_ab: [32]u8 = blk: {
    var x: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&x, "8b7fac6ee4bd36dfff6ed0b342820d10acdc16e0ba834fc93f2203b9386f1d10") catch unreachable;
    break :blk x;
};
const usdc_pkg: [32]u8 = blk: {
    var x: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&x, "dba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7") catch unreachable;
    break :blk x;
};
const sui_str = "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";
const usdc_str = "0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC";
/// ListBalances for `owner_ab`, page_size 50, from a public sui-node 1.83.1 on 2026-11-11, as the
/// Sui gRPC client decoded it (proto3 JSON, not the raw message bytes): SUI as an address balance,
/// and USDC with `balance` "0" and neither `addressBalance` nor `coinBalance` present.
const recorded_page = @embedFile("vectors/listbalances-drained-usdc-sui-node-1.83.1.json");
/// The recording's SUI amount; the test's state holds the same, so the whole page compares.
const recorded_sui: u64 = 647035315152;

/// `recorded_page` back to wire bytes: each entry as field 1, its fields in number order (as prost
/// writes them), a component only when the JSON has it.
fn recordedMessage(a: std.mem.Allocator, buf: []u8) ![]const u8 {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, a, recorded_page, .{});
    var w = proto.Writer.init(buf);
    for (v.object.get("balances").?.array.items) |b| {
        const o = b.object;
        const m = try w.begin(1, 128);
        try w.string(1, o.get("coinType").?.string);
        try w.uint(3, try std.fmt.parseInt(u64, o.get("balance").?.string, 10));
        if (o.get("addressBalance")) |x| try w.uint(4, try std.fmt.parseInt(u64, x.string, 10));
        if (o.get("coinBalance")) |x| try w.uint(5, try std.fmt.parseInt(u64, x.string, 10));
        try w.end(m);
    }
    return w.bytesWritten();
}

test "the recorded ListBalances page has the shape this file expects" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena_state.allocator(), recorded_page, .{});
    const items = v.object.get("balances").?.array.items;
    try testing.expectEqual(@as(usize, 2), items.len);
    try testing.expectEqualStrings(sui_str, items[0].object.get("coinType").?.string);
    try testing.expectEqual(recorded_sui, try std.fmt.parseInt(u64, items[0].object.get("balance").?.string, 10));
    try testing.expectEqualStrings(items[0].object.get("balance").?.string, items[0].object.get("addressBalance").?.string);
    try testing.expect(items[0].object.get("coinBalance") == null);
    try testing.expectEqualStrings(usdc_str, items[1].object.get("coinType").?.string);
    try testing.expectEqualStrings("0", items[1].object.get("balance").?.string);
    try testing.expect(items[1].object.get("addressBalance") == null);
    try testing.expect(items[1].object.get("coinBalance") == null);
    try testing.expectEqual(@as(usize, 2), items[1].object.count());
}

/// bcs(StructTag 0xdba3..::usdc::USDC): the coin_type half of a page token.
const usdc_tag_bcs = usdc_pkg ++ [_]u8{4} ++ "usdc".* ++ [_]u8{4} ++ "USDC".* ++ [_]u8{0};

fn usdcType() types.TypeTag {
    return .{ .@"struct" = .{ .address = .{ .@"0" = usdc_pkg }, .module = .{ .@"0" = "usdc" }, .name = .{ .@"0" = "USDC" }, .type_args = &.{} } };
}

/// BCS(Object) of an address balance: `Field<Key<Balance<T>>, U128>` under 0xacc (null T: SUI).
fn accField(a: std.mem.Allocator, id: [32]u8, version: u64, owner: [32]u8, t: ?types.TypeTag, value: u128) ![]const u8 {
    const c = try a.alloc(u8, 80);
    @memcpy(c[0..32], &id);
    @memcpy(c[32..64], &owner);
    std.mem.writeInt(u128, c[64..80], value, .little);
    const o: types.Object = .{
        .data = .{ .Move = .{ .type_ = .{ .@"0" = if (t) |x| .{ .BalanceAccumulatorField = x } else .SuiBalanceAccumulatorField }, .has_public_transfer = false, .version = .{ .@"0" = version }, .contents = c } },
        .owner = .{ .ObjectOwner = .{ .@"0" = index.accumulator_root } },
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(7) } },
        .storage_rebate = 0,
    };
    return bcs.encodeAlloc(types.Object, a, &o);
}

/// BCS(Object) of a `Coin<T>` owned by `owner`.
fn typedCoin(a: std.mem.Allocator, id: [32]u8, version: u64, balance: u64, owner: [32]u8, t: types.TypeTag) ![]const u8 {
    const c = try a.alloc(u8, 40);
    @memcpy(c[0..32], &id);
    std.mem.writeInt(u64, c[32..40], balance, .little);
    const o: types.Object = .{
        .data = .{ .Move = .{ .type_ = .{ .@"0" = .{ .Coin = t } }, .has_public_transfer = true, .version = .{ .@"0" = version }, .contents = c } },
        .owner = .{ .AddressOwner = .{ .@"0" = owner } },
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(7) } },
        .storage_rebate = 0,
    };
    return bcs.encodeAlloc(types.Object, a, &o);
}

fn listBalancesBody(a: std.mem.Allocator, owner: *const [32]u8, page_size: ?u32, token: ?[]const u8) ![]const u8 {
    const buf = try a.alloc(u8, 512);
    var w = proto.Writer.init(buf);
    try w.string(1, try hexAddr(a, owner));
    if (page_size) |n| try w.uint(2, n);
    if (token) |t| try w.bytes(3, t);
    return w.bytesWritten();
}

fn getBalanceBody(a: std.mem.Allocator, owner: *const [32]u8, coin_type: []const u8) ![]const u8 {
    const buf = try a.alloc(u8, 512);
    var w = proto.Writer.init(buf);
    try w.string(1, try hexAddr(a, owner));
    try w.string(2, coin_type);
    return w.bytesWritten();
}

/// `Balance { coin_type = 1, balance = 3, address_balance = 4 (if != 0), coin_balance = 5 (if != 0) }`
/// as field `field`, written field by field from render_balance (not through state.zig).
fn wantBalance(w: *proto.Writer, field: u32, coin_type: []const u8, coin_half: u64, address: u64) !void {
    const m = try w.begin(field, 128);
    try w.string(1, coin_type);
    try w.uint(3, coin_half + address);
    if (address != 0) try w.uint(4, address);
    if (coin_half != 0) try w.uint(5, coin_half);
    try w.end(m);
}

test "ListBalances lists a coin type emptied to zero with balance 0, as sui-node's uncompacted row" {
    var e: Env = undefined;
    try e.init();
    defer e.deinit();
    const a = e.arena.allocator();
    const sui_field = try accField(a, addr(0xf1), 9, owner_ab, null, recorded_sui);
    const usdc_field = try accField(a, addr(0xf2), 9, owner_ab, usdcType(), 2_500_000);
    try e.ix.insert(sui_field);
    try e.ix.insert(usdc_field);
    // a second owner whose USDC was a coin object, spent whole
    const owner_b = addr(0xb2);
    const usdc_coin = try typedCoin(a, addr(0xc9), 4, 100, owner_b, usdcType());
    try e.ix.insert(usdc_coin);
    e.ix.checkpoint = 1;
    // the settlement drains and deletes the USDC accumulator field; owner B's coin is destroyed
    try e.ix.applyChanges(2, &.{ .{ .old = usdc_field, .new = null }, .{ .old = usdc_coin, .new = null } });

    var arena_state = std.heap.ArenaAllocator.init(e.gpa);
    defer arena_state.deinit();
    const ta = arena_state.allocator();
    const buf = try ta.alloc(u8, 4096);

    // full page: SUI (address balance only), then USDC at 0; no next_page_token. Recorded
    // (decoded JSON, transcoded back); the derived bytes say the same.
    {
        const rep = try e.call(ta, "ListBalances", try listBalancesBody(ta, &owner_ab, 50, null));
        try testing.expectEqual(@as(u8, 0), rep.status);
        try testing.expectEqualSlices(u8, try recordedMessage(ta, buf), rep.message);
        var w = proto.Writer.init(try ta.alloc(u8, 4096));
        try wantBalance(&w, 1, sui_str, 0, recorded_sui);
        try wantBalance(&w, 1, usdc_str, 0, 0);
        try testing.expectEqualSlices(u8, w.bytesWritten(), rep.message);
    }
    // page_size 1: SUI and a token naming USDC (BCS PageToken { owner, coin_type: StructTag })
    const token = owner_ab ++ usdc_tag_bcs;
    {
        const rep = try e.call(ta, "ListBalances", try listBalancesBody(ta, &owner_ab, 1, null));
        try testing.expectEqual(@as(u8, 0), rep.status);
        var w = proto.Writer.init(buf);
        try wantBalance(&w, 1, sui_str, 0, recorded_sui);
        try w.bytes(2, &token);
        try testing.expectEqualSlices(u8, w.bytesWritten(), rep.message);
    }
    {
        const rep = try e.call(ta, "ListBalances", try listBalancesBody(ta, &owner_ab, 1, &token));
        try testing.expectEqual(@as(u8, 0), rep.status);
        var w = proto.Writer.init(buf);
        try wantBalance(&w, 1, usdc_str, 0, 0);
        try testing.expectEqualSlices(u8, w.bytesWritten(), rep.message);
    }
    // owner B: the spent coin's type at 0
    {
        const rep = try e.call(ta, "ListBalances", try listBalancesBody(ta, &owner_b, null, null));
        try testing.expectEqual(@as(u8, 0), rep.status);
        var w = proto.Writer.init(buf);
        try wantBalance(&w, 1, usdc_str, 0, 0);
        try testing.expectEqualSlices(u8, w.bytesWritten(), rep.message);
    }
    // GetBalance: an emptied type and a never-held type answer alike (unwrap_or_default)
    for ([_][]const u8{ usdc_str, "0x3::never::HELD" }, [_][]const u8{ usdc_str, "0x0000000000000000000000000000000000000000000000000000000000000003::never::HELD" }) |ask, canon| {
        const rep = try e.call(ta, "GetBalance", try getBalanceBody(ta, &owner_ab, ask));
        try testing.expectEqual(@as(u8, 0), rep.status);
        var w = proto.Writer.init(buf);
        try wantBalance(&w, 1, canon, 0, 0);
        try testing.expectEqualSlices(u8, w.bytesWritten(), rep.message);
    }
    // a zero-value coin received at the tip creates no row (no non-zero change: no merge operand)
    const owner_c = addr(0xb3);
    try e.ix.applyChanges(3, &.{.{ .old = null, .new = try typedCoin(a, addr(0xca), 5, 0, owner_c, usdcType()) }});
    const rep = try e.call(ta, "ListBalances", try listBalancesBody(ta, &owner_c, null, null));
    try testing.expectEqual(@as(u8, 0), rep.status);
    try testing.expectEqual(@as(usize, 0), rep.message.len);
}
