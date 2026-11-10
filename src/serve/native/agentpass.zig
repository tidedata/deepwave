//! Agent Pass on the node (docs/NATIVE-PROTOCOL.md section 6.1): the wallet's `AgentPassConfig`
//! (clients/ts/packages/wallet/src/agentpass.ts) as BCS, bound to an API key in the
//! `--native-keys` file, and enforced before submit_transaction with the same rules the wallet
//! runs on its pre-sign dry-run: expiry, gas budget cap, package and function allowlists,
//! denyUnknownCommands, per-transaction caps, rolling budgets, recipient allowlist,
//! denyObjectTransfers, requireSuccess and the per-minute / per-hour rate.
//!
//! What the transaction would move (balance changes, objects changing owner, success) comes from
//! a `Preview` hook: the node runs its simulation engine on the exact bytes. Budgets are reserved
//! when a transaction is allowed and released when the submit path says it never landed
//! (TX_REJECTED), so concurrent submits of one key cannot overspend. The ledger (allowed
//! transactions inside the longest window) is kept in a file next to the keys file, so a restart
//! forgets nothing.
//!
//! Keys file (`--native-keys FILE`), one key per line, `#` comments:
//!
//!   <key> <tier> [<AgentPassConfig BCS as hex>]
//!
//! The key is the token a client sends (hello, `?token=`, `authorization: Bearer`). Its
//! principal id is its line number. A line with a pass limits every submit of that principal.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const proto = @import("proto.zig");
const dispatch = @import("dispatch.zig");
const R = proto.R;

pub const wire_version: u8 = 1;
pub const flag_require_success: u8 = 0x01;
pub const flag_deny_unknown_commands: u8 = 0x02;
pub const flag_deny_object_transfers: u8 = 0x04;

pub const CoinAmount = struct { coin_type: []const u8, amount: u128 };
pub const Budget = struct { coin_type: []const u8, cap: u128, window_ms: u64 };

/// `AgentPassConfig` on the wire (BCS, spec 6.1). Coin types, packages, functions and
/// recipients are in Sui's long form (the TS encoder normalizes them).
pub const Config = struct {
    id: []const u8,
    expires_at_ms: ?u64 = null,
    per_tx: []const CoinAmount = &.{},
    budgets: []const Budget = &.{},
    max_gas_budget: ?u64 = null,
    allowed_packages: ?[]const [32]u8 = null,
    allowed_functions: ?[]const []const u8 = null,
    allowed_recipients: ?[]const [32]u8 = null,
    per_minute: ?u32 = null,
    per_hour: ?u32 = null,
    flags: u8 = flag_require_success,

    /// Decodes into `a` (every slice is a copy).
    pub fn decode(a: Allocator, b: []const u8) !Config {
        var r: R = .{ .b = b };
        if (try r.u8_() != wire_version) return error.Malformed;
        var c: Config = .{ .id = try a.dupe(u8, try r.str()) };
        if (try r.option()) c.expires_at_ms = try r.int(u64);
        const per_tx = try a.alloc(CoinAmount, try count(&r));
        for (per_tx) |*x| x.* = .{ .coin_type = try a.dupe(u8, try r.str()), .amount = try r.int(u128) };
        c.per_tx = per_tx;
        const budgets = try a.alloc(Budget, try count(&r));
        for (budgets) |*x| x.* = .{ .coin_type = try a.dupe(u8, try r.str()), .cap = try r.int(u128), .window_ms = try r.int(u64) };
        c.budgets = budgets;
        if (try r.option()) c.max_gas_budget = try r.int(u64);
        if (try r.option()) c.allowed_packages = try addrs(a, &r);
        if (try r.option()) {
            const fs = try a.alloc([]const u8, try count(&r));
            for (fs) |*f| f.* = try a.dupe(u8, try r.str());
            c.allowed_functions = fs;
        }
        if (try r.option()) c.allowed_recipients = try addrs(a, &r);
        if (try r.option()) c.per_minute = try r.int(u32);
        if (try r.option()) c.per_hour = try r.int(u32);
        c.flags = try r.u8_();
        if (c.flags & ~@as(u8, 0x07) != 0) return error.Malformed;
        try r.done();
        for (c.budgets) |x| if (x.window_ms == 0) return error.Malformed;
        return c;
    }

    /// Whether a rule needs the dry-run outcome (otherwise no simulation runs).
    pub fn needsOutcome(c: *const Config) bool {
        return c.flags & (flag_require_success | flag_deny_object_transfers) != 0 or c.per_tx.len > 0 or
            c.budgets.len > 0 or c.allowed_recipients != null;
    }

    fn longestWindow(c: *const Config) u64 {
        var w: u64 = 3_600_000;
        for (c.budgets) |b| w = @max(w, b.window_ms);
        return w;
    }
};

fn count(r: *R) !usize {
    const n = try r.uleb();
    if (n > r.b.len - r.p) return error.Malformed; // every element takes at least a byte
    return @intCast(n);
}

fn addrs(a: Allocator, r: *R) ![]const [32]u8 {
    const n = try r.uleb();
    if (n > (r.b.len - r.p) / 32) return error.Malformed;
    const out = try a.alloc([32]u8, @intCast(n));
    for (out) |*x| x.* = (try r.fixed(32)).*;
    return out;
}

// ---------------------------------------------------------------- what a transaction does

pub const Call = struct { package: [32]u8, module: []const u8, function: []const u8 };

/// Read from the TransactionData alone.
pub const Static = struct {
    digest: [32]u8,
    sender: [32]u8,
    gas_budget: u64,
    commands: usize,
    calls: []const Call,
};

pub fn staticFacts(a: Allocator, tx_data: []const u8) !Static {
    const td = bcs.decode(types.TransactionData, a, tx_data) catch return error.Malformed;
    const v = td.V1;
    var calls: std.ArrayList(Call) = .empty;
    var commands: usize = 0;
    switch (v.kind) {
        .ProgrammableTransaction => |pt| {
            commands = pt.commands.len;
            for (pt.commands) |cmd| switch (cmd) {
                .MoveCall => |mc| try calls.append(a, .{ .package = mc.package.@"0".@"0", .module = mc.module.@"0", .function = mc.function.@"0" }),
                else => {},
            };
        },
        else => {},
    }
    return .{ .digest = dispatch.txDigest(tx_data), .sender = v.sender.@"0", .gas_budget = v.gas_data.budget, .commands = commands, .calls = calls.items };
}

pub const BalanceChange = struct { address: [32]u8, coin_type: []const u8, amount: i128 };
/// An object that ends up owned by another address than before (`coin`: a Coin or the gas coin).
pub const Transfer = struct { id: [32]u8, to: [32]u8, coin: bool };

/// What the dry-run says the transaction does.
pub const Outcome = struct {
    success: bool,
    error_message: []const u8 = "",
    balance_changes: []const BalanceChange = &.{},
    transfers: []const Transfer = &.{},
};

/// Runs the transaction without committing it (the node's simulation engine). Null result: no
/// outcome (the engine is missing or the transaction did not run); a pass that needs one denies.
pub const Preview = struct {
    ctx: *anyopaque,
    run: *const fn (ctx: *anyopaque, a: Allocator, tx_data: []const u8) ?Outcome,
};

/// One object the transaction wrote or touched: its BCS before (null: created) and after (null:
/// deleted or wrapped).
pub const Change = struct { id: [32]u8, before: ?[]const u8, after: ?[]const u8 };

/// Objects that change owner to an address, as the wallet judges them: the new owner of an
/// object owned by another object is the owner of that parent when the parent is among the
/// changes, else the object is not counted. Unchanged owners are skipped.
pub fn transfers(a: Allocator, changes: []const Change) ![]const Transfer {
    const Out = struct { owner: ?types.Owner, coin: bool };
    const outs = try a.alloc(Out, changes.len);
    for (changes, outs) |c, *o| {
        o.* = .{ .owner = null, .coin = false };
        const b = c.after orelse continue;
        const obj = bcs.decode(types.Object, a, b) catch continue;
        o.owner = obj.owner;
        o.coin = switch (obj.data) {
            .Move => |m| switch (m.type_.@"0") {
                .GasCoin, .Coin => true,
                else => false,
            },
            .Package => false,
        };
    }
    var list: std.ArrayList(Transfer) = .empty;
    for (changes, outs) |c, o| {
        const owner = o.owner orelse continue;
        if (c.before) |b| if (bcs.decode(types.Object, a, b)) |prev| {
            if (sameOwner(prev.owner, owner)) continue;
        } else |_| {};
        const to: [32]u8 = addrOf(owner) orelse blk: {
            const parent = switch (owner) {
                .ObjectOwner => |p| p.@"0",
                else => continue,
            };
            for (changes, outs) |pc, po| if (std.mem.eql(u8, &pc.id, &parent)) {
                if (po.owner) |pw| if (addrOf(pw)) |x| break :blk x;
            };
            continue;
        };
        try list.append(a, .{ .id = c.id, .to = to, .coin = o.coin });
    }
    return list.items;
}

fn addrOf(o: types.Owner) ?[32]u8 {
    return switch (o) {
        .AddressOwner => |x| x.@"0",
        .ConsensusAddressOwner => |x| x.owner.@"0",
        else => null,
    };
}

fn sameOwner(x: types.Owner, y: types.Owner) bool {
    if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    return switch (x) {
        .AddressOwner => |v| std.mem.eql(u8, &v.@"0", &y.AddressOwner.@"0"),
        .ObjectOwner => |v| std.mem.eql(u8, &v.@"0", &y.ObjectOwner.@"0"),
        .Shared => |v| v.initial_shared_version.@"0" == y.Shared.initial_shared_version.@"0",
        .Immutable => true,
        .ConsensusAddressOwner => |v| v.start_version.@"0" == y.ConsensusAddressOwner.start_version.@"0" and
            std.mem.eql(u8, &v.owner.@"0", &y.ConsensusAddressOwner.owner.@"0"),
        .Party => |v| v.start_version.@"0" == y.Party.start_version.@"0",
    };
}

// ---------------------------------------------------------------- one pass

pub const Entry = struct {
    digest: [32]u8,
    at_ms: u64,
    /// Outflow per budget, in `Config.budgets` order.
    out: []u128,
    pending: bool,
};

pub const max_ledger = 5000;

pub const Pass = struct {
    gpa: Allocator,
    cfg: Config,
    mu: std.atomic.Mutex = .unlocked,
    ledger: std.ArrayList(Entry) = .empty,

    pub fn deinit(p: *Pass) void {
        for (p.ledger.items) |e| p.gpa.free(e.out);
        p.ledger.deinit(p.gpa);
    }

    fn lock(p: *Pass) void {
        while (!p.mu.tryLock()) std.atomic.spinLoopHint();
    }

    fn prune(p: *Pass, now: u64) void {
        const cut = now -| p.cfg.longestWindow();
        var keep: usize = 0;
        const drop = p.ledger.items.len -| max_ledger;
        for (p.ledger.items, 0..) |e, i| {
            if (e.at_ms < cut or i < drop) {
                p.gpa.free(e.out);
                continue;
            }
            p.ledger.items[keep] = e;
            keep += 1;
        }
        p.ledger.items.len = keep;
    }

    fn spentIn(p: *const Pass, bi: usize, now: u64) u128 {
        const cut = now -| p.cfg.budgets[bi].window_ms;
        var s: u128 = 0;
        for (p.ledger.items) |e| if (e.at_ms >= cut) {
            s +|= e.out[bi];
        };
        return s;
    }

    fn countIn(p: *const Pass, window: u64, now: u64) usize {
        const cut = now -| window;
        var n: usize = 0;
        for (p.ledger.items) |e| if (e.at_ms >= cut) {
            n += 1;
        };
        return n;
    }

    fn find(p: *const Pass, d: *const [32]u8) ?usize {
        for (p.ledger.items, 0..) |e, i| if (std.mem.eql(u8, &e.digest, d)) return i;
        return null;
    }

    /// The wallet's `evaluate`: allow (and reserve) or deny with the reason (allocated in `a`).
    /// `outcome` must be set when `cfg.needsOutcome()`.
    pub fn evaluate(p: *Pass, a: Allocator, st: Static, outcome: ?Outcome, now: u64) !?[]const u8 {
        const cfg = &p.cfg;
        if (cfg.expires_at_ms) |e| if (now >= e) return "pass expired";
        if (cfg.needsOutcome() and outcome == null) return "dry-run unavailable";
        if (cfg.flags & flag_require_success != 0) if (outcome) |o| if (!o.success)
            return try std.fmt.allocPrint(a, "dry-run failed: {s}", .{if (o.error_message.len > 0) o.error_message else "unknown"});

        p.lock();
        defer p.mu.unlock();
        p.prune(now);
        // the same signed bytes that already executed are one transaction: allow the retry
        if (p.find(&st.digest)) |i| if (!p.ledger.items[i].pending) return null;

        if (cfg.max_gas_budget) |cap| if (st.gas_budget > cap)
            return try std.fmt.allocPrint(a, "gas budget {d} over cap {d}", .{ st.gas_budget, cap });
        var touched = false;
        for (st.calls) |c| {
            touched = true;
            if (cfg.allowed_packages) |ps| {
                const ok = for (ps) |x| {
                    if (std.mem.eql(u8, &x, &c.package)) break true;
                } else false;
                if (!ok) return try std.fmt.allocPrint(a, "package 0x{x} not allowed", .{&c.package});
            }
            if (cfg.allowed_functions) |fs| {
                const full = try std.fmt.allocPrint(a, "0x{x}::{s}::{s}", .{ &c.package, c.module, c.function });
                const ok = for (fs) |f| {
                    if (std.mem.eql(u8, full, f)) break true;
                    if (full.len > f.len + 2 and std.mem.startsWith(u8, full, f) and std.mem.eql(u8, full[f.len..][0..2], "::")) break true;
                } else false;
                if (!ok) return try std.fmt.allocPrint(a, "function {s}::{s} not allowed", .{ c.module, c.function });
            }
        }
        if (cfg.flags & flag_deny_unknown_commands != 0) {
            if (st.commands == 0) return "empty transaction";
            if ((cfg.allowed_packages != null or cfg.allowed_functions != null) and !touched) return "no MoveCall into an allowed target";
        }

        // what the sender loses per coin type (positive; SUI includes gas)
        const changes: []const BalanceChange = if (outcome) |o| o.balance_changes else &.{};
        const outflow = struct {
            fn of(cs: []const BalanceChange, sender: *const [32]u8, coin: []const u8) u128 {
                var s: u128 = 0;
                for (cs) |c| if (c.amount < 0 and std.mem.eql(u8, &c.address, sender) and std.mem.eql(u8, c.coin_type, coin)) {
                    s +|= @intCast(-c.amount);
                };
                return s;
            }
        }.of;
        for (cfg.per_tx) |cap| {
            const spent = outflow(changes, &st.sender, cap.coin_type);
            if (spent > cap.amount) return try std.fmt.allocPrint(a, "spend {d} of {s} over per-tx cap {d}", .{ spent, cap.coin_type, cap.amount });
        }
        if (outcome) |o| if (cfg.allowed_recipients != null or cfg.flags & flag_deny_object_transfers != 0) {
            if (cfg.allowed_recipients) |rs| for (o.balance_changes) |c| {
                if (std.mem.eql(u8, &c.address, &st.sender) or c.amount <= 0) continue;
                if (!contains(rs, &c.address)) return try std.fmt.allocPrint(a, "recipient 0x{x} not allowed", .{&c.address});
            };
            for (o.transfers) |t| {
                if (std.mem.eql(u8, &t.to, &st.sender)) continue;
                if (cfg.flags & flag_deny_object_transfers != 0 and !t.coin)
                    return try std.fmt.allocPrint(a, "object 0x{x} to 0x{x} not allowed", .{ &t.id, &t.to });
                if (cfg.allowed_recipients) |rs| if (!contains(rs, &t.to))
                    return try std.fmt.allocPrint(a, "object 0x{x} to 0x{x}: recipient not allowed", .{ &t.id, &t.to });
            }
        };
        const out = try p.gpa.alloc(u128, cfg.budgets.len);
        var keep_out = false;
        defer if (!keep_out) p.gpa.free(out);
        for (cfg.budgets, out, 0..) |b, *o, bi| {
            o.* = outflow(changes, &st.sender, b.coin_type);
            if (o.* == 0) continue;
            const spent = p.spentIn(bi, now);
            if (spent +| o.* > b.cap) return try std.fmt.allocPrint(a, "budget: {d} + {d} of {s} over {d} per {d} ms", .{ spent, o.*, b.coin_type, b.cap, b.window_ms });
        }
        if (cfg.per_minute) |n| if (p.countIn(60_000, now) >= n) return try std.fmt.allocPrint(a, "rate over {d}/min", .{n});
        if (cfg.per_hour) |n| if (p.countIn(3_600_000, now) >= n) return try std.fmt.allocPrint(a, "rate over {d}/h", .{n});

        // replace an earlier pending reservation of the same bytes
        if (p.find(&st.digest)) |i| {
            p.gpa.free(p.ledger.items[i].out);
            _ = p.ledger.orderedRemove(i);
        }
        try p.ledger.append(p.gpa, .{ .digest = st.digest, .at_ms = now, .out = out, .pending = true });
        keep_out = true;
        return null;
    }

    /// The submit path's answer: `executed` = it may have reached the network (counts), false =
    /// it provably did not (the reservation is freed).
    pub fn settle(p: *Pass, digest: *const [32]u8, executed: bool) void {
        p.lock();
        defer p.mu.unlock();
        const i = p.find(digest) orelse return;
        if (executed) {
            p.ledger.items[i].pending = false;
        } else if (p.ledger.items[i].pending) {
            p.gpa.free(p.ledger.items[i].out);
            _ = p.ledger.orderedRemove(i);
        }
    }

    /// Ledger file: one line per entry, `<at_ms> <digest hex> <p|x> <out_0> ... <out_n>`.
    pub fn writeLedger(p: *Pass, w: *std.ArrayList(u8), a: Allocator) !void {
        p.lock();
        defer p.mu.unlock();
        for (p.ledger.items) |e| {
            try w.print(a, "{d} {x} {c}", .{ e.at_ms, &e.digest, @as(u8, if (e.pending) 'p' else 'x') });
            for (e.out) |o| try w.print(a, " {d}", .{o});
            try w.append(a, '\n');
        }
    }

    /// Loads a ledger file written by `writeLedger`. Pending entries count as spent (a restart
    /// lost the submit that would have settled them). Lines that do not parse are skipped.
    pub fn readLedger(p: *Pass, text: []const u8) !void {
        p.lock();
        defer p.mu.unlock();
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |line| {
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            const at = std.fmt.parseInt(u64, f.next() orelse continue, 10) catch continue;
            const dh = f.next() orelse continue;
            if (dh.len != 64) continue;
            var d: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&d, dh) catch continue;
            _ = f.next() orelse continue;
            const out = try p.gpa.alloc(u128, p.cfg.budgets.len);
            for (out) |*o| o.* = std.fmt.parseInt(u128, f.next() orelse "0", 10) catch 0;
            if (p.find(&d) != null) {
                p.gpa.free(out);
                continue;
            }
            try p.ledger.append(p.gpa, .{ .digest = d, .at_ms = at, .out = out, .pending = false });
        }
    }
};

fn contains(xs: []const [32]u8, x: *const [32]u8) bool {
    for (xs) |y| if (std.mem.eql(u8, &y, x)) return true;
    return false;
}

// ---------------------------------------------------------------- keys file and the hooks

pub const Key = struct { key: []const u8, principal: dispatch.Principal, pass: ?*Pass };

/// `--native-keys`: API keys (dispatch.Auth) and their passes (dispatch.AgentPass).
pub const Policy = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    io: Io,
    keys: []Key = &.{},
    preview: ?Preview = null,
    /// Ledger files live here as `<pass id>.<principal id>.ledger` (null: memory only).
    ledger_dir: ?[]const u8 = null,
    now_ms: *const fn (io: Io) u64 = realNow,

    fn realNow(io: Io) u64 {
        return @intCast(@divTrunc(Io.Clock.real.now(io).toNanoseconds(), std.time.ns_per_ms));
    }

    /// Parses a keys file's text. Errors name the line.
    pub fn parse(gpa: Allocator, io: Io, text: []const u8, err_line: *usize) !*Policy {
        const p = try gpa.create(Policy);
        p.* = .{ .gpa = gpa, .arena = .init(gpa), .io = io };
        errdefer p.deinit();
        const a = p.arena.allocator();
        var keys: std.ArrayList(Key) = .empty;
        var it = std.mem.splitScalar(u8, text, '\n');
        var line_no: usize = 0;
        while (it.next()) |raw| {
            line_no += 1;
            err_line.* = line_no;
            const line = std.mem.trim(u8, if (std.mem.indexOfScalar(u8, raw, '#')) |h| raw[0..h] else raw, " \t\r");
            if (line.len == 0) continue;
            var f = std.mem.tokenizeAny(u8, line, " \t");
            const key = f.next().?;
            const tier = std.fmt.parseInt(u8, f.next() orelse return error.BadKeyLine, 10) catch return error.BadKeyLine;
            var pass: ?*Pass = null;
            if (f.next()) |hex| {
                if (hex.len % 2 != 0) return error.BadKeyLine;
                const b = try a.alloc(u8, hex.len / 2);
                _ = std.fmt.hexToBytes(b, hex) catch return error.BadKeyLine;
                const cfg = Config.decode(a, b) catch return error.BadAgentPass;
                const ps = try a.create(Pass);
                ps.* = .{ .gpa = gpa, .cfg = cfg };
                pass = ps;
            }
            if (f.next() != null) return error.BadKeyLine;
            for (keys.items) |k| if (std.mem.eql(u8, k.key, key)) return error.DuplicateKey;
            try keys.append(a, .{ .key = try a.dupe(u8, key), .principal = .{ .id = line_no, .tier = tier }, .pass = pass });
        }
        p.keys = keys.items;
        return p;
    }

    pub fn deinit(p: *Policy) void {
        for (p.keys) |k| if (k.pass) |ps| ps.deinit();
        p.arena.deinit();
        p.gpa.destroy(p);
    }

    pub fn auth(p: *Policy) dispatch.Auth {
        return .{ .ctx = p, .check = check };
    }

    pub fn agentPass(p: *Policy) dispatch.AgentPass {
        return .{ .ctx = p, .check = gate, .settle = settleHook };
    }

    pub fn passes(p: *const Policy) usize {
        var n: usize = 0;
        for (p.keys) |k| if (k.pass != null) {
            n += 1;
        };
        return n;
    }

    fn check(ctx: *anyopaque, token: []const u8) ?dispatch.Principal {
        const p: *Policy = @ptrCast(@alignCast(ctx));
        var found: ?dispatch.Principal = null;
        for (p.keys) |k| {
            // constant time over the key's length
            if (k.key.len != token.len) continue;
            var diff: u8 = 0;
            for (k.key, token) |x, y| diff |= x ^ y;
            if (diff == 0) found = k.principal;
        }
        return found;
    }

    fn passOf(p: *Policy, principal: ?dispatch.Principal) ?*Pass {
        const pr = principal orelse return null;
        if (pr.id == 0 or pr.id > std.math.maxInt(usize)) return null;
        for (p.keys) |k| if (k.principal.id == pr.id) return k.pass;
        return null;
    }

    fn gate(ctx: *anyopaque, a: Allocator, principal: ?dispatch.Principal, m: proto.Method, tx_data: []const u8) dispatch.AgentPass.Verdict {
        const p: *Policy = @ptrCast(@alignCast(ctx));
        // dry_run moves nothing: a pass limits what reaches the chain
        if (m != .submit_transaction) return .allow;
        const ps = p.passOf(principal) orelse return .allow;
        const st = staticFacts(a, tx_data) catch return .{ .deny = "transaction does not decode" };
        const outcome: ?Outcome = if (ps.cfg.needsOutcome()) (if (p.preview) |pv| pv.run(pv.ctx, a, tx_data) else null) else null;
        const why = ps.evaluate(a, st, outcome, p.now_ms(p.io)) catch return .{ .deny = "agent pass: out of memory" };
        if (why) |w| return .{ .deny = w };
        p.save(ps, principal.?.id);
        return .allow;
    }

    fn settleHook(ctx: *anyopaque, principal: ?dispatch.Principal, tx_data: []const u8, executed: bool) void {
        const p: *Policy = @ptrCast(@alignCast(ctx));
        const ps = p.passOf(principal) orelse return;
        ps.settle(&dispatch.txDigest(tx_data), executed);
        p.save(ps, principal.?.id);
    }

    fn ledgerName(buf: []u8, ps: *const Pass, id: u64) ![]const u8 {
        // the id is free text: keep it to a safe file name
        var clean: [64]u8 = undefined;
        const n = @min(ps.cfg.id.len, clean.len);
        for (ps.cfg.id[0..n], clean[0..n]) |c, *o| o.* = if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_') c else '_';
        return std.fmt.bufPrint(buf, "{s}.{d}.ledger", .{ clean[0..n], id });
    }

    /// Writes the pass's ledger (tmp file, then rename). Best effort: a failed write is logged.
    fn save(p: *Policy, ps: *Pass, id: u64) void {
        const dir_path = p.ledger_dir orelse return;
        var nb: [128]u8 = undefined;
        const name = ledgerName(&nb, ps, id) catch return;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(p.gpa);
        ps.writeLedger(&buf, p.gpa) catch return;
        var dir = Io.Dir.cwd().openDir(p.io, dir_path, .{}) catch |e| return std.log.warn("agent pass ledger {s}: {s}", .{ dir_path, @errorName(e) });
        defer dir.close(p.io);
        var tb: [140]u8 = undefined;
        const tmp = std.fmt.bufPrint(&tb, "{s}.tmp", .{name}) catch return;
        dir.writeFile(p.io, .{ .sub_path = tmp, .data = buf.items }) catch |e| return std.log.warn("agent pass ledger {s}: {s}", .{ name, @errorName(e) });
        dir.rename(tmp, dir, name, p.io) catch |e| std.log.warn("agent pass ledger {s}: {s}", .{ name, @errorName(e) });
    }

    /// Reads every pass's ledger from `ledger_dir` (missing files are empty ledgers).
    pub fn load(p: *Policy) void {
        const dir_path = p.ledger_dir orelse return;
        var dir = Io.Dir.cwd().openDir(p.io, dir_path, .{}) catch return;
        defer dir.close(p.io);
        for (p.keys) |k| {
            const ps = k.pass orelse continue;
            var nb: [128]u8 = undefined;
            const name = ledgerName(&nb, ps, k.principal.id) catch continue;
            const text = dir.readFileAlloc(p.io, name, p.gpa, .limited(64 << 20)) catch continue;
            defer p.gpa.free(text);
            ps.readLedger(text) catch {};
        }
    }
};

// ---------------------------------------------------------------- tests

const sui_long = "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";

fn testConfig(a: Allocator) !Config {
    var pkg: [32]u8 = @splat(0);
    pkg[31] = 0xaa;
    var friend: [32]u8 = @splat(0);
    friend[31] = 0xf1;
    const pkgs = try a.dupe([32]u8, &.{pkg});
    const rcp = try a.dupe([32]u8, &.{friend});
    return .{
        .id = "perps-agent",
        .expires_at_ms = 10_000_000,
        .per_tx = try a.dupe(CoinAmount, &.{.{ .coin_type = sui_long, .amount = 3_000 }}),
        .budgets = try a.dupe(Budget, &.{.{ .coin_type = sui_long, .cap = 5_000, .window_ms = 86_400_000 }}),
        .max_gas_budget = 50_000_000,
        .allowed_packages = pkgs,
        .allowed_recipients = rcp,
        .per_minute = 3,
        .flags = flag_require_success | flag_deny_object_transfers,
    };
}

fn encodeConfig(a: Allocator, c: Config) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    const w: proto.W = .{ .gpa = a, .out = &out };
    try w.u8_(wire_version);
    try w.str(c.id);
    if (c.expires_at_ms) |x| {
        try w.u8_(1);
        try w.int(u64, x);
    } else try w.u8_(0);
    try w.uleb(c.per_tx.len);
    for (c.per_tx) |x| {
        try w.str(x.coin_type);
        try w.int(u128, x.amount);
    }
    try w.uleb(c.budgets.len);
    for (c.budgets) |x| {
        try w.str(x.coin_type);
        try w.int(u128, x.cap);
        try w.int(u64, x.window_ms);
    }
    if (c.max_gas_budget) |x| {
        try w.u8_(1);
        try w.int(u64, x);
    } else try w.u8_(0);
    inline for (.{ c.allowed_packages, null, c.allowed_recipients }, 0..) |list, i| {
        if (i == 1) {
            if (c.allowed_functions) |fs| {
                try w.u8_(1);
                try w.uleb(fs.len);
                for (fs) |f| try w.str(f);
            } else try w.u8_(0);
        } else if (list) |xs| {
            try w.u8_(1);
            try w.uleb(xs.len);
            for (xs) |x| try w.fixed(&x);
        } else try w.u8_(0);
    }
    inline for (.{ c.per_minute, c.per_hour }) |x| if (x) |v| {
        try w.u8_(1);
        try w.int(u32, v);
    } else try w.u8_(0);
    try w.u8_(c.flags);
    return out.items;
}

test "AgentPassConfig wire round trip and rejects" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try testConfig(a);
    const b = try encodeConfig(a, c);
    const d = try Config.decode(a, b);
    try std.testing.expectEqualStrings("perps-agent", d.id);
    try std.testing.expectEqual(@as(u128, 5_000), d.budgets[0].cap);
    try std.testing.expectEqual(@as(?u32, 3), d.per_minute);
    try std.testing.expectEqual(@as(?u32, null), d.per_hour);
    try std.testing.expect(d.allowed_functions == null);
    try std.testing.expectEqual(@as(usize, 1), d.allowed_packages.?.len);
    try std.testing.expect(d.needsOutcome());
    try std.testing.expectError(error.Malformed, Config.decode(a, b[0 .. b.len - 1]));
    var bad = try a.dupe(u8, b);
    bad[0] = 2;
    try std.testing.expectError(error.Malformed, Config.decode(a, bad));
    // a pass with only static rules needs no dry-run
    const s = try Config.decode(a, try encodeConfig(a, .{ .id = "x", .max_gas_budget = 1, .flags = 0 }));
    try std.testing.expect(!s.needsOutcome());
}

test "the golden AgentPassConfig the TS encoder writes decodes" {
    // clients/ts/packages/wallet/test/agentpass-wire.test.ts writes the same bytes
    const hex = golden_ts_hex;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const b = try a.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(b, hex);
    const c = try Config.decode(a, b);
    try std.testing.expectEqualStrings("perps-agent", c.id);
    try std.testing.expectEqual(@as(?u64, 1_800_000_000_000), c.expires_at_ms);
    try std.testing.expectEqualStrings(sui_long, c.per_tx[0].coin_type);
    try std.testing.expectEqual(@as(u128, 1_000_000_000), c.per_tx[0].amount);
    try std.testing.expectEqual(@as(u128, 5_000_000_000), c.budgets[0].cap);
    try std.testing.expectEqual(@as(u64, 86_400_000), c.budgets[0].window_ms);
    try std.testing.expectEqual(@as(?u64, 50_000_000), c.max_gas_budget);
    try std.testing.expectEqual(@as(u8, 0xab), c.allowed_packages.?[0][31]);
    try std.testing.expectEqualStrings("0x00000000000000000000000000000000000000000000000000000000000000ab::perps::open", c.allowed_functions.?[0]);
    try std.testing.expectEqual(@as(u8, 0xcd), c.allowed_recipients.?[0][31]);
    try std.testing.expectEqual(@as(?u32, 30), c.per_minute);
    try std.testing.expectEqual(@as(?u32, null), c.per_hour);
    try std.testing.expectEqual(flag_require_success | flag_deny_unknown_commands, c.flags);
}

/// Written by the TS encoder (agentpass-wire.test.ts prints it); keep the two in step.
const golden_ts_hex = @embedFile("agentpass_golden.hex");

test "pass rules: caps, budgets, recipients, transfers, rate, replay, settle" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var ps: Pass = .{ .gpa = gpa, .cfg = try testConfig(a) };
    defer ps.deinit();
    var me: [32]u8 = @splat(0);
    me[31] = 0x11;
    var pkg: [32]u8 = @splat(0);
    pkg[31] = 0xaa;
    var friend: [32]u8 = @splat(0);
    friend[31] = 0xf1;
    var stranger: [32]u8 = @splat(0);
    stranger[31] = 0x99;
    const call: []const Call = &.{.{ .package = pkg, .module = "perps", .function = "open" }};
    var st: Static = .{ .digest = @splat(1), .sender = me, .gas_budget = 1_000_000, .commands = 1, .calls = call };
    const spend = struct {
        fn of(who: [32]u8, to: [32]u8, n: i128) [2]BalanceChange {
            return .{ .{ .address = who, .coin_type = sui_long, .amount = -n }, .{ .address = to, .coin_type = sui_long, .amount = n - 10 } };
        }
    }.of;
    var bc = spend(me, friend, 2_000);
    const ok: Outcome = .{ .success = true, .balance_changes = &bc };

    try std.testing.expect(try ps.evaluate(a, st, ok, 1000) == null);
    try std.testing.expectEqual(@as(usize, 1), ps.ledger.items.len);
    // replaying the same pending bytes re-reserves, not doubles
    try std.testing.expect(try ps.evaluate(a, st, ok, 1001) == null);
    try std.testing.expectEqual(@as(usize, 1), ps.ledger.items.len);
    ps.settle(&st.digest, true);
    // an executed digest is allowed again without a new reservation
    try std.testing.expect(try ps.evaluate(a, st, ok, 1002) == null);
    try std.testing.expectEqual(@as(usize, 1), ps.ledger.items.len);

    // budget: 2000 spent, another 2000 fits (4000 <= 5000), a third does not
    st.digest = @splat(2);
    try std.testing.expect(try ps.evaluate(a, st, ok, 2000) == null);
    st.digest = @splat(3);
    try std.testing.expect(std.mem.startsWith(u8, (try ps.evaluate(a, st, ok, 3000)).?, "budget:"));
    // a rejected submit frees its reservation
    ps.settle(&@as([32]u8, @splat(2)), false);
    try std.testing.expect(try ps.evaluate(a, st, ok, 3000) == null);

    // per-tx cap
    var big = spend(me, friend, 3_500);
    st.digest = @splat(4);
    try std.testing.expect(std.mem.startsWith(u8, (try ps.evaluate(a, st, .{ .success = true, .balance_changes = &big }, 4000)).?, "spend 3500"));
    // recipient allowlist
    var odd = spend(me, stranger, 100);
    try std.testing.expect(std.mem.startsWith(u8, (try ps.evaluate(a, st, .{ .success = true, .balance_changes = &odd }, 4000)).?, "recipient"));
    // a non-coin object leaving the sender
    const tr: []const Transfer = &.{.{ .id = @splat(7), .to = friend, .coin = false }};
    try std.testing.expect(std.mem.startsWith(u8, (try ps.evaluate(a, st, .{ .success = true, .transfers = tr }, 4000)).?, "object"));
    // failed dry-run, other package, gas cap, expiry
    try std.testing.expect(std.mem.startsWith(u8, (try ps.evaluate(a, st, .{ .success = false, .error_message = "MoveAbort" }, 4000)).?, "dry-run failed: MoveAbort"));
    var other = st;
    other.calls = &.{.{ .package = @splat(5), .module = "m", .function = "f" }};
    try std.testing.expect(std.mem.startsWith(u8, (try ps.evaluate(a, other, ok, 4000)).?, "package"));
    other = st;
    other.gas_budget = 60_000_000;
    try std.testing.expect(std.mem.startsWith(u8, (try ps.evaluate(a, other, ok, 4000)).?, "gas budget"));
    try std.testing.expect(std.mem.eql(u8, (try ps.evaluate(a, st, ok, 10_000_000)).?, "pass expired"));
    try std.testing.expect(std.mem.eql(u8, (try ps.evaluate(a, st, null, 4000)).?, "dry-run unavailable"));

    // rate: 3 per minute (entries 1, 3 and this one are inside the minute)
    var tiny = spend(me, friend, 1);
    st.digest = @splat(8);
    try std.testing.expect(try ps.evaluate(a, st, .{ .success = true, .balance_changes = &tiny }, 5000) == null);
    st.digest = @splat(9);
    try std.testing.expect(std.mem.startsWith(u8, (try ps.evaluate(a, st, .{ .success = true, .balance_changes = &tiny }, 5000)).?, "rate"));

    // the ledger survives a write and a read (pending entries come back as spent)
    var text: std.ArrayList(u8) = .empty;
    try ps.writeLedger(&text, a);
    var back: Pass = .{ .gpa = gpa, .cfg = ps.cfg };
    defer back.deinit();
    try back.readLedger(text.items);
    try std.testing.expectEqual(ps.ledger.items.len, back.ledger.items.len);
    try std.testing.expectEqual(ps.spentIn(0, 5000), back.spentIn(0, 5000));
}

test "keys file: auth, principals and passes" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const pass_hex = try std.fmt.allocPrint(a, "{x}", .{try encodeConfig(a, .{ .id = "bot", .max_gas_budget = 10, .flags = 0 })});
    const text = try std.fmt.allocPrint(a, "# keys\nalpha 1\n\nbeta 2 {s}  # limited\n", .{pass_hex});
    var line: usize = 0;
    const p = try Policy.parse(gpa, std.testing.io, text, &line);
    defer p.deinit();
    try std.testing.expectEqual(@as(usize, 1), p.passes());
    const au = p.auth();
    try std.testing.expectEqual(@as(u64, 2), au.check(au.ctx, "alpha").?.id);
    try std.testing.expectEqual(@as(u8, 2), au.check(au.ctx, "beta").?.tier);
    try std.testing.expect(au.check(au.ctx, "gamma") == null);
    try std.testing.expect(au.check(au.ctx, "alph") == null);
    const ap = p.agentPass();
    // not a submit, or a key without a pass: allowed; the limited key is checked
    try std.testing.expect(ap.check(ap.ctx, a, au.check(au.ctx, "beta"), .dry_run, "junk") == .allow);
    try std.testing.expect(ap.check(ap.ctx, a, au.check(au.ctx, "alpha"), .submit_transaction, "junk") == .allow);
    try std.testing.expect(ap.check(ap.ctx, a, null, .submit_transaction, "junk") == .allow);
    switch (ap.check(ap.ctx, a, au.check(au.ctx, "beta"), .submit_transaction, "junk")) {
        .deny => |w| try std.testing.expectEqualStrings("transaction does not decode", w),
        .allow => return error.TestUnexpectedResult,
    }
    try std.testing.expectError(error.BadKeyLine, Policy.parse(gpa, std.testing.io, "k x\n", &line));
    try std.testing.expectError(error.DuplicateKey, Policy.parse(gpa, std.testing.io, "k 1\nk 2\n", &line));
    try std.testing.expectError(error.BadAgentPass, Policy.parse(gpa, std.testing.io, "k 1 0102\n", &line));
    try std.testing.expectEqual(@as(usize, 1), line);
}
