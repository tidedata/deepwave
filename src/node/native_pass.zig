//! deepwave's Agent Pass (docs/NATIVE-PROTOCOL.md section 6.1): `--native-keys FILE` gives the
//! zui/1 listener its API keys and the passes bound to them (src/serve/native/agentpass.zig), and
//! this file gives the passes what a transaction would do: a dry-run of the exact bytes on the
//! node's simulation engine (the same engine as dry_run, called, not changed), reduced to the
//! balance changes, the objects that change owner, and success.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const serve = @import("serve");
const native = @import("native");
const native_hooks = @import("native_hooks.zig");
const ap = native.agentpass;

pub fn preview(h: *native_hooks.Hooks) ap.Preview {
    return .{ .ctx = h, .run = run };
}

fn run(ctx: *anyopaque, a: Allocator, tx_data: []const u8) ?ap.Outcome {
    const h: *native_hooks.Hooks = @ptrCast(@alignCast(ctx));
    const engine = h.rpc.simulator();
    const tip = engine.tip orelse return null;
    // the Result borrows store bytes through the snapshot: everything kept is copied into `a`
    var snap = tip.store.snapshot();
    defer snap.release();
    const res = engine.simulate(a, &snap, .{ .tx = .{ .data = tx_data } }) catch return null;
    const x = switch (res) {
        .rejected => |r| return .{ .success = false, .error_message = a.dupe(u8, r.message) catch "rejected" },
        .executed => |x| x,
    };
    var bc: std.ArrayList(ap.BalanceChange) = .empty;
    for (x.balance_changes) |c| {
        var o = serve.typestr.scratch();
        serve.typestr.typeTag(&o, c.coin_type) catch return null;
        bc.append(a, .{ .address = c.address, .coin_type = a.dupe(u8, o.str()) catch return null, .amount = c.coin + c.addr }) catch return null;
    }
    const changes = a.alloc(ap.Change, x.object_changes.len) catch return null;
    for (x.object_changes, changes) |c, *o| o.* = .{ .id = c.id, .before = c.previous, .after = c.object };
    const tr = ap.transfers(a, changes) catch return null;
    return switch (x.status) {
        .success => .{ .success = true, .balance_changes = bc.items, .transfers = tr },
        .failure => |f| .{ .success = false, .error_message = a.dupe(u8, f.message) catch f.name, .balance_changes = bc.items, .transfers = tr },
    };
}

/// Loads `--native-keys` (keys, tiers, passes) and the passes' ledgers from `ledger_dir`
/// (created when missing). The policy lives until the node exits.
pub fn load(gpa: Allocator, io: Io, keys_path: []const u8, ledger_dir: []const u8, h: *native_hooks.Hooks) !*ap.Policy {
    const text = try Io.Dir.cwd().readFileAlloc(io, keys_path, gpa, .limited(16 << 20));
    defer gpa.free(text);
    var line: usize = 0;
    const p = ap.Policy.parse(gpa, io, text, &line) catch |e| {
        std.log.err("--native-keys {s}: line {d}: {s}", .{ keys_path, line, @errorName(e) });
        return e;
    };
    errdefer p.deinit();
    Io.Dir.cwd().createDirPath(io, ledger_dir) catch |e| {
        std.log.err("agent pass ledger dir {s}: {s}", .{ ledger_dir, @errorName(e) });
        return e;
    };
    p.ledger_dir = try p.arena.allocator().dupe(u8, ledger_dir);
    p.preview = preview(h);
    p.load();
    std.log.info("zui/1: {d} API keys, {d} with an agent pass (ledgers in {s})", .{ p.keys.len, p.passes(), ledger_dir });
    return p;
}
