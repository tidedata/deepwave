//! Test support: the coin deny list v2 vectors of `../testdata/deny_order.jsonl`, made by
//! Mysten's executor (`zui-truth-exec deny-order`, tools/truth/exec/src/deny_order.rs).
//!
//! Each vector is one coin-only programmable transaction over synthetic objects (a sender, its
//! gas coin, `Coin<T>` objects whose `T` is a struct of a system package), the deny-list state
//! the store holds (`latest`), Rust's effects and written objects, and `reads`: every
//! `ObjectStore::get_object` call the executor made on the backing store, in call order, with
//! whether the store held the object. Those are the reads of
//! `check_coin_deny_list_v2_during_execution`.
//!
//! `run` executes the vectors through the coin executor or the Move-call executor and requires
//! the effects and written objects byte for byte and the same `ObjectLookup.latest` calls in
//! the same order. The Move-call executor needs the system packages of the vectors' epoch,
//! read from the corpus checkpoints each vector names (`$ZUI_CORPUS`); the coin executor needs
//! nothing outside the file.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const objects = @import("../objects.zig");
const packages = @import("../packages.zig");
const coin_ptb = @import("../coin_ptb.zig");
const replay = @import("../replay.zig");
const ptb = @import("root.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;

pub const text = @embedFile("../testdata/deny_order.jsonl");

pub const Read = struct { id: []const u8, hit: bool, what: []const u8 };
pub const SystemWrite = struct { seq: u64, epoch: u64 };

pub const Line = struct {
    name: []const u8,
    pv: u64,
    epoch: u64,
    rgp: u64,
    start_ms: u64,
    tx: []const u8,
    objects: []const []const u8,
    latest: []const []const u8,
    /// The corpus checkpoints that wrote the system packages the executor loaded, each with
    /// the first epoch that sees them.
    system: []const SystemWrite,
    reads: []const Read,
    /// Rust's `{:?}` of the execution status (for the reader; the effects carry it).
    status: []const u8,
    effects: []const u8,
    written: []const []const u8,
};

pub const Path = enum { coin, move };

/// The vectors named `out-of-gas/...` run out of gas at or before the deny-list charge; the
/// others are charged in full.
pub const Part = enum { charged, out_of_gas };

/// What Mysten's code gives for each vector, by reading it (deny_list_v2.rs
/// `check_new_regulated_coin_owners`, context.rs `finish`): the status the effects must carry.
/// `a` is `0x1::ascii::String`, `b` is `0x2::clock::Clock` (a sorts first); the sender 0x55..
/// sorts between the recipients `lo` 0x11.. and `hi` 0x99...
const Want = union(enum) {
    success,
    insufficient_gas,
    pause: u8,
    address: struct { ty: u8, owner: u8 },
};

const expected = [_]struct { []const u8, Want }{
    // no config object: nothing to check, the charge still applies
    .{ "none/two-types", .success },
    .{ "none/first-type-only", .success },
    .{ "control/two-types", .success },
    .{ "control/split", .success },
    // two coin types: the first type's denial wins, in type string order
    .{ "two/first-address-denied", .{ .address = .{ .ty = 'a', .owner = 0x99 } } },
    .{ "two/first-paused", .{ .pause = 'a' } },
    .{ "two/second-address-denied", .{ .address = .{ .ty = 'b', .owner = 0x99 } } },
    .{ "two/second-paused", .{ .pause = 'b' } },
    .{ "two/both-denied", .{ .address = .{ .ty = 'a', .owner = 0x99 } } },
    .{ "two/first-no-config-second-paused", .{ .pause = 'b' } },
    // the global pause: in force when written before this epoch, also when lifted from the next
    .{ "pause/now", .{ .pause = 'a' } },
    .{ "pause/next-epoch", .success },
    .{ "pause/lifted-next-epoch", .{ .pause = 'a' } },
    .{ "pause/now-and-addresses", .{ .pause = 'a' } },
    // the sender keeps the rest of the split coin, so both are owners; address order decides
    .{ "address/sender-now", .{ .address = .{ .ty = 'a', .owner = 0x55 } } },
    .{ "address/recipient-now", .{ .address = .{ .ty = 'a', .owner = 0x99 } } },
    .{ "address/both-now", .{ .address = .{ .ty = 'a', .owner = 0x55 } } },
    .{ "address/both-now-recipient-sorts-first", .{ .address = .{ .ty = 'a', .owner = 0x11 } } },
    .{ "address/sender-next-epoch", .success },
    .{ "address/recipient-next-epoch", .success },
    .{ "address/sender-now-recipient-next-epoch", .{ .address = .{ .ty = 'a', .owner = 0x55 } } },
    .{ "address/sender-next-epoch-recipient-now", .{ .address = .{ .ty = 'a', .owner = 0x99 } } },
    .{ "address/sender-lifted-next-epoch", .{ .address = .{ .ty = 'a', .owner = 0x55 } } },
    .{ "address/recipient-lifted-next-epoch", .{ .address = .{ .ty = 'a', .owner = 0x99 } } },
    // `charge_coin_transfers(..)?` comes before `result?`: out of gas whatever the check found
    .{ "out-of-gas/charge", .insufficient_gas },
    .{ "out-of-gas/charge-sender-denied", .insufficient_gas },
    .{ "out-of-gas/charge-recipient-denied", .insufficient_gas },
    .{ "out-of-gas/charge-paused", .insufficient_gas },
    .{ "out-of-gas/charge-no-config", .insufficient_gas },
    .{ "out-of-gas/before-finish", .insufficient_gas },
};

const type_a = "0000000000000000000000000000000000000000000000000000000000000001::ascii::String";
const type_b = "0000000000000000000000000000000000000000000000000000000000000002::clock::Clock";

const Store = struct {
    arena: Allocator,
    objs: std.AutoHashMapUnmanaged(objects.Key, []const u8) = .empty,
    latest: std.AutoHashMapUnmanaged(Id, []const u8) = .empty,
    /// Every `latest` call, in call order.
    log: std.ArrayList(Id) = .empty,
    failed: bool = false,

    fn get(p: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        const s: *const Store = @ptrCast(@alignCast(p));
        return s.objs.get(.{ .id = id.*, .version = version });
    }
    fn getLatest(p: *const anyopaque, id: *const Id) ?[]const u8 {
        const s: *Store = @ptrCast(@alignCast(@constCast(p)));
        s.log.append(s.arena, id.*) catch {
            s.failed = true;
        };
        return s.latest.get(id.*);
    }
    fn lookup(s: *const Store) coin_ptb.ObjectLookup {
        return .{ .ctx = s, .get = get, .latest = getLatest };
    }
};

pub fn unhex(arena: Allocator, h: []const u8) ![]u8 {
    const out = try arena.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

/// One (coin type, owner) pair of a vector's transaction.
pub const Receiver = struct { ty: types.TypeTag, owner: Id };

/// The (coin type, owner) pairs `context::finish` sees for a vector's transaction, in command
/// order (not the check's order): the two shapes the tool makes. A split of `Coin<T>` sent to
/// the last input leaves the rest with the sender (the sender, then the recipient); a transfer
/// of the coin inputs gives each coin's type the recipient. (For `out-of-gas/before-finish`
/// `finish` never runs: the executor has no pairs.)
pub fn receivers(a: Allocator, v: *const Line) ![]const Receiver {
    const td = try bcs.decode(types.TransactionData, a, try unhex(a, v.tx));
    const data = &td.V1;
    const pt = &data.kind.ProgrammableTransaction;
    const recipient: Id = pt.inputs[pt.inputs.len - 1].Pure[0..32].*;
    const split = pt.commands[0] == .SplitCoins;
    var out: std.ArrayList(Receiver) = .empty;
    for (pt.inputs) |in| {
        if (in != .Object) continue;
        const id = in.Object.ImmOrOwnedObject[0].@"0".@"0";
        const obj = for (v.objects) |h| {
            const raw = try unhex(a, h);
            if (std.mem.eql(u8, &(try objects.keyOf(raw)).id, &id)) break try bcs.decode(types.Object, a, raw);
        } else return error.TestUnexpectedResult;
        const ty = obj.data.Move.type_.@"0".Coin;
        if (split) try out.append(a, .{ .ty = ty, .owner = data.sender.@"0" });
        try out.append(a, .{ .ty = ty, .owner = recipient });
    }
    return out.items;
}

/// The system packages the vectors' executor loaded, from the corpus checkpoints `system`
/// names (in ascending order, as `packages.load` lists a package's writes). null when the
/// corpus is not there or lacks one of the checkpoints.
pub fn corpusSystemPackages(arena: Allocator, io: std.Io, system: []const SystemWrite) !?packages.Store {
    const c = std.c.getenv("ZUI_CORPUS") orelse return null;
    var s: packages.Store = .{};
    var idx = try types.CheckpointIndex.init(std.heap.page_allocator);
    defer idx.deinit(std.heap.page_allocator);
    for (system) |w| {
        const path = try std.fmt.allocPrint(arena, "{s}/chk/{d}.chk", .{ std.mem.span(c), w.seq });
        const blob = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 30)) catch return null;
        try types.indexCheckpointData(blob, &idx);
        for (0..idx.tx_count) |i| {
            const tx = idx.txAt(i);
            for (idx.objs[tx.out_first..][0..tx.out_count]) |r| {
                const raw = r.slice(blob);
                const v = objects.ObjectView.parse(raw) catch continue;
                if (!v.is_package or !packages.isSystemPackage(&v.id)) continue;
                const gop = try s.system.getOrPut(arena, v.id);
                if (!gop.found_existing) gop.value_ptr.* = .empty;
                try gop.value_ptr.append(arena, .{ .epoch = w.epoch, .raw = raw });
            }
        }
    }
    s.loaded = true;
    return s;
}

fn fail(comptime fmt: []const u8, args: anytype) error{TestUnexpectedResult} {
    std.debug.print("deny order vectors: " ++ fmt ++ "\n", args);
    return error.TestUnexpectedResult;
}

fn checkStatus(a: Allocator, name: []const u8, effects: []const u8) !void {
    const want: Want = for (expected) |x| {
        if (std.mem.eql(u8, x[0], name)) break x[1];
    } else return fail("{s}: no expected status for this vector", .{name});
    const fx = (try bcs.decode(types.TransactionEffects, a, effects)).V2;
    switch (want) {
        .success => if (fx.status != .Success) return fail("{s}: expected success", .{name}),
        else => {
            if (fx.status != .Failure) return fail("{s}: expected a failure", .{name});
            const f = fx.status.Failure;
            // context::finish errors carry no command index
            if (f.command != null) return fail("{s}: failure with a command index", .{name});
            switch (want) {
                .success => unreachable,
                .insufficient_gas => if (f.@"error" != .InsufficientGas) return fail("{s}: expected InsufficientGas, got {s}", .{ name, @tagName(f.@"error") }),
                .pause => |t| {
                    if (f.@"error" != .CoinTypeGlobalPause) return fail("{s}: expected CoinTypeGlobalPause, got {s}", .{ name, @tagName(f.@"error") });
                    try std.testing.expectEqualStrings(if (t == 'a') type_a else type_b, f.@"error".CoinTypeGlobalPause.coin_type.@"0");
                },
                .address => |x| {
                    if (f.@"error" != .AddressDeniedForCoin) return fail("{s}: expected AddressDeniedForCoin, got {s}", .{ name, @tagName(f.@"error") });
                    const d = f.@"error".AddressDeniedForCoin;
                    try std.testing.expectEqualStrings(if (x.ty == 'a') type_a else type_b, d.coin_type.@"0");
                    try std.testing.expectEqualSlices(u8, &@as(Id, @splat(x.owner)), &d.address.@"0");
                },
            }
        },
    }
}

fn readNames(a: Allocator, v: *const Line, ids: []const Id) ![]const u8 {
    var w: std.Io.Writer.Allocating = .init(a);
    for (ids) |*id| {
        const name: ?[]const u8 = for (v.reads) |r| {
            const rid = try unhex(a, r.id);
            if (std.mem.eql(u8, rid, id)) break r.what;
        } else null;
        if (name) |n| try w.writer.print(" {s}", .{n}) else try w.writer.print(" {x}", .{id});
    }
    return w.written();
}

/// Runs the vectors of `part` through `path`; returns how many ran. The Move-call executor
/// reads the system packages from the corpus: `error.SkipZigTest` without it.
pub fn run(gpa: Allocator, io: std.Io, part: Part, path: Path) !usize {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var pkg_arena: std.heap.ArenaAllocator = .init(gpa);
    defer pkg_arena.deinit();
    var pkgs: ?packages.Store = null;
    // the thread's package caches name `pkgs` by address: none may outlive it
    defer if (path == .move) ptb.pkgs.releaseThreadCaches();
    var n: usize = 0;
    var seen: usize = 0;
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        _ = arena_state.reset(.retain_capacity);
        const a = arena_state.allocator();
        const v = try std.json.parseFromSliceLeaky(Line, a, line, .{});
        seen += 1;
        if (std.mem.startsWith(u8, v.name, "out-of-gas/") != (part == .out_of_gas)) continue;
        const cfg = try protocol.get(v.pv, .mainnet);
        const tx_raw = try unhex(a, v.tx);
        const td = try bcs.decode(types.TransactionData, a, tx_raw);
        const data = &td.V1;
        var store: Store = .{ .arena = a };
        for (v.objects) |h| {
            const raw = try unhex(a, h);
            try store.objs.put(a, (try objects.ObjectView.parse(raw)).key(), raw);
        }
        for (v.latest) |h| {
            const raw = try unhex(a, h);
            try store.latest.put(a, (try objects.keyOf(raw)).id, raw);
        }
        const want_fx = try unhex(a, v.effects);
        const out: coin_ptb.Output = switch (path) {
            .coin => switch (try coin_ptb.execute(a, cfg, v.epoch, v.rgp, tx_raw, data, store.lookup())) {
                .unsupported => |why| return fail("{s}: coin executor: unsupported: {s}", .{ v.name, why }),
                .done => |o| o,
            },
            .move => blk: {
                if (pkgs == null) pkgs = (try corpusSystemPackages(pkg_arena.allocator(), io, v.system)) orelse return error.SkipZigTest;
                const fx = try bcs.decode(types.TransactionEffects, a, want_fx);
                const env: ptb.Env = .{ .gpa = std.heap.page_allocator, .cfg = cfg, .pv = v.pv, .epoch = v.epoch, .epoch_start_ms = v.start_ms, .rgp = v.rgp, .pkgs = &pkgs.?, .authoritative_packages = true };
                switch (try ptb.execute(a, env, tx_raw, data, .{ .objs = store.lookup(), .effects = &fx.V2, .unchanged_loaded = &.{} })) {
                    .unsupported => |why| return fail("{s}: Move-call executor: unsupported: {s}", .{ v.name, why }),
                    .done => |o| break :blk .{ .effects = o.effects, .written = o.written },
                }
            },
        };
        if (store.failed) return error.OutOfMemory;

        // status, error, gas summary and every other effects byte
        if (!std.mem.eql(u8, want_fx, out.effects))
            return fail("{s} ({s}): effects differ from Rust ({s}): {s}", .{ v.name, @tagName(path), v.status, replay.effectsDiff(a, out.effects, want_fx) });
        try checkStatus(a, v.name, out.effects);

        // the store reads, in order
        var same = store.log.items.len == v.reads.len;
        if (same) for (store.log.items, v.reads) |*got, r| {
            if (!std.mem.eql(u8, got, try unhex(a, r.id))) same = false;
        };
        if (!same) {
            var want_ids: std.ArrayList(Id) = .empty;
            for (v.reads) |r| try want_ids.append(a, (try unhex(a, r.id))[0..32].*);
            return fail("{s} ({s}): deny list reads differ\n  Rust:{s}\n  zui: {s}", .{ v.name, @tagName(path), try readNames(a, &v, want_ids.items), try readNames(a, &v, store.log.items) });
        }
        // the vector's store answers as Rust's did
        for (store.log.items, v.reads) |*got, r| {
            if (store.latest.contains(got.*) != r.hit) return fail("{s}: read {s}: the store holds it: {}, Rust: {}", .{ v.name, r.what, !r.hit, r.hit });
        }

        // written objects: the same set of byte strings
        if (out.written.len != v.written.len) return fail("{s}: {d} written objects, Rust {d}", .{ v.name, out.written.len, v.written.len });
        for (v.written) |h| {
            const want = try unhex(a, h);
            const k = try objects.keyOf(want);
            const got = for (out.written) |w| {
                if (std.mem.eql(u8, &w.id, &k.id)) break w.bytes;
            } else return fail("{s}: written object missing", .{v.name});
            try std.testing.expectEqualSlices(u8, want, got);
        }
        n += 1;
    }
    if (seen != expected.len) return fail("{d} vectors, {d} expected statuses", .{ seen, expected.len });
    return n;
}
