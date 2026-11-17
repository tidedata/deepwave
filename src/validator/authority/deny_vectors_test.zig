//! Golden vectors of the shared transaction-deny config (PARITY.md G21), computed by Mysten's
//! sui-core 1.83.1 (tools/truth/validity, suite `denycfg`; the notation is documented in
//! tools/truth/validity/src/denycfg.rs): `evaluate_deny_configs`, `PeerDenySyncConfig::validate`,
//! the manager's apply / committee / restart sequences, and `check_transaction_for_signing` under
//! the effective config.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const harness = @import("harness");
const rpc_exec = @import("rpc_exec");
const txdeny = rpc_exec.txdeny;
const checks = rpc_exec.checks;
const messages = @import("../messages.zig");
const dm = @import("deny_manager.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;

const compressed = @embedFile("testdata/denycfg.txt.zst");

fn idOf(b: u8) Id {
    var x: Id = @splat(0);
    x[31] = b;
    return x;
}

fn byteList(a: Allocator, s: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |x| if (x.len > 0) try out.append(a, try std.fmt.parseInt(u8, x, 10));
    return out.items;
}

fn idList(a: Allocator, s: []const u8) ![]const Id {
    const bs = try byteList(a, s);
    const out = try a.alloc(Id, bs.len);
    for (bs, out) |b, *o| o.* = idOf(b);
    std.mem.sort(Id, out, {}, struct {
        fn lt(_: void, x: Id, y: Id) bool {
            return std.mem.order(u8, &x, &y) == .lt;
        }
    }.lt);
    return out;
}

fn rules(a: Allocator, s: []const u8) !dm.Rules {
    var r: dm.Rules = .{};
    if (std.mem.eql(u8, s, "-")) return r;
    var it = std.mem.splitScalar(u8, s, ';');
    while (it.next()) |item| {
        if (std.mem.indexOfScalar(u8, item, ':')) |c| {
            const l = item[c + 1 ..];
            switch (item[0]) {
                'o' => r.object_deny_list = try idList(a, l),
                'p' => r.package_deny_list = try idList(a, l),
                'a' => r.address_deny_list = try idList(a, l),
                'z' => {
                    var ps: std.ArrayList([]const u8) = .empty;
                    var pi = std.mem.splitScalar(u8, l, ',');
                    while (pi.next()) |p| if (p.len > 0) try ps.append(a, p);
                    std.mem.sort([]const u8, ps.items, {}, struct {
                        fn lt(_: void, x: []const u8, y: []const u8) bool {
                            return std.mem.order(u8, x, y) == .lt;
                        }
                    }.lt);
                    r.zklogin_disabled_providers = ps.items;
                },
                else => return error.BadVector,
            }
        } else if (std.mem.eql(u8, item, "publish")) r.package_publish_disabled = true //
        else if (std.mem.eql(u8, item, "upgrade")) r.package_upgrade_disabled = true //
        else if (std.mem.eql(u8, item, "shared")) r.shared_object_disabled = true //
        else if (std.mem.eql(u8, item, "user")) r.user_transaction_disabled = true //
        else if (std.mem.eql(u8, item, "gasless")) r.gasless_disabled = true //
        else if (std.mem.eql(u8, item, "receiving")) r.receiving_objects_disabled = true //
        else if (std.mem.eql(u8, item, "zksig")) r.zklogin_sig_disabled = true //
        else return error.BadVector;
    }
    return r;
}

fn canon(a: Allocator, r: *const dm.Rules) ![]const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    const lists = [_]struct { u8, []const Id }{ .{ 'o', r.object_deny_list }, .{ 'p', r.package_deny_list }, .{ 'a', r.address_deny_list } };
    for (lists) |l| if (l[1].len > 0) {
        var t: std.ArrayList(u8) = .empty;
        try t.print(a, "{c}:", .{l[0]});
        for (l[1], 0..) |x, i| try t.print(a, "{s}{d}", .{ if (i > 0) "," else "", x[31] });
        try parts.append(a, t.items);
    };
    if (r.zklogin_disabled_providers.len > 0) {
        var t: std.ArrayList(u8) = .empty;
        try t.appendSlice(a, "z:");
        for (r.zklogin_disabled_providers, 0..) |p, i| try t.print(a, "{s}{s}", .{ if (i > 0) "," else "", p });
        try parts.append(a, t.items);
    }
    const flags = [_]struct { bool, []const u8 }{
        .{ r.package_publish_disabled, "publish" },     .{ r.package_upgrade_disabled, "upgrade" },
        .{ r.shared_object_disabled, "shared" },        .{ r.user_transaction_disabled, "user" },
        .{ r.gasless_disabled, "gasless" },             .{ r.receiving_objects_disabled, "receiving" },
        .{ r.zklogin_sig_disabled, "zksig" },
    };
    for (flags) |f| if (f[0]) try parts.append(a, f[1]);
    if (parts.items.len == 0) return "-";
    return std.mem.join(a, ";", parts.items);
}

fn committee(a: Allocator, s: []const u8) ![]const dm.Member {
    var out: std.ArrayList(dm.Member) = .empty;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |e| {
        if (e.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, e, '=') orelse return error.BadVector;
        try out.append(a, .{ .name = @splat(try std.fmt.parseInt(u8, e[0..eq], 10)), .stake = try std.fmt.parseInt(u64, e[eq + 1 ..], 10) });
    }
    return out.items;
}

fn names(a: Allocator, s: []const u8) ![]const dm.Name {
    const bs = try byteList(a, s);
    const out = try a.alloc(dm.Name, bs.len);
    for (bs, out) |b, *o| o.* = @splat(b);
    return out;
}

fn eligibility(a: Allocator, s: []const u8) !dm.Eligibility {
    if (std.mem.eql(u8, s, "all")) return .{ .denylist = &.{} };
    if (std.mem.startsWith(u8, s, "allow:")) return .{ .allowlist = try names(a, s[6..]) };
    if (std.mem.startsWith(u8, s, "deny:")) return .{ .denylist = try names(a, s[5..]) };
    return error.BadVector;
}

fn syncConfig(a: Allocator, s: []const u8) !dm.SyncConfig {
    var c: dm.SyncConfig = .{};
    if (std.mem.eql(u8, s, "-")) return c;
    var rs: std.ArrayList(dm.Ruleset) = .empty;
    var bs: std.ArrayList(dm.Bucket) = .empty;
    var it = std.mem.splitScalar(u8, s, ' ');
    while (it.next()) |item| {
        if (std.mem.eql(u8, item, "startup")) {
            c.broadcast_on_startup = true;
            continue;
        }
        if (std.mem.eql(u8, item, "epoch")) {
            c.broadcast_on_epoch_change = true;
            continue;
        }
        var f = std.mem.splitScalar(u8, item[1..], '|');
        const nm = f.next() orelse return error.BadVector;
        const th: dm.Threshold = .{ .eligibility = try eligibility(a, f.next() orelse return error.BadVector), .stake_threshold_percent = try std.fmt.parseInt(u16, f.next() orelse return error.BadVector, 10) };
        const last = f.next() orelse return error.BadVector;
        switch (item[0]) {
            'R' => try rs.append(a, .{ .name = nm, .rules = try rules(a, last), .threshold = th }),
            'B' => {
                var ks: dm.KindSet = .empty;
                var ki = std.mem.splitScalar(u8, last, ',');
                while (ki.next()) |k| if (k.len > 0) ks.insert(dm.Kind.parse(k) orelse return error.BadVector);
                try bs.append(a, .{ .name = nm, .element_kinds = ks, .threshold = th });
            },
            else => return error.BadVector,
        }
    }
    c.rulesets = rs.items;
    c.default_buckets = bs.items;
    return c;
}

fn votes(a: Allocator, s: []const u8) ![]const dm.Vote {
    var out: std.ArrayList(dm.Vote) = .empty;
    if (std.mem.eql(u8, s, "-")) return out.items;
    var it = std.mem.splitScalar(u8, s, ' ');
    while (it.next()) |v| {
        const at = std.mem.indexOfScalar(u8, v, '@') orelse return error.BadVector;
        const r = try a.create(dm.Rules);
        r.* = try rules(a, v[at + 1 ..]);
        try out.append(a, .{ .name = @splat(try std.fmt.parseInt(u8, v[0..at], 10)), .rules = r });
    }
    return out.items;
}

fn msgs(a: Allocator, s: []const u8) ![]const messages.SharedTransactionDenyConfig {
    var out: std.ArrayList(messages.SharedTransactionDenyConfig) = .empty;
    var it = std.mem.splitScalar(u8, s, ' ');
    while (it.next()) |m| {
        var f = std.mem.splitScalar(u8, m, '#');
        const w = try std.fmt.parseInt(u8, f.next() orelse return error.BadVector, 10);
        const g = f.next() orelse return error.BadVector;
        const generation = if (std.mem.eql(u8, g, "max")) std.math.maxInt(u64) else try std.fmt.parseInt(u64, g, 10);
        const rs = f.next() orelse return error.BadVector;
        const wire: ?messages.TransactionDenyRules = if (std.mem.eql(u8, rs, "none")) null else try dm.toWire(a, &try rules(a, rs));
        try out.append(a, .{ .V1 = .{ .authority = .{ .@"0" = @splat(w) }, .generation = generation, .rules = wire } });
    }
    return out.items;
}

fn evalText(a: Allocator, f: []const []const u8) !struct { dm.Rules, []const u8 } {
    const sc = try syncConfig(a, f[1]);
    const local = try rules(a, f[2]);
    const ev = try dm.evaluate(a, &local, &sc, try votes(a, f[3]), try committee(a, f[0]));
    var t: std.ArrayList(u8) = .empty;
    try t.print(a, "eff={s} pre=", .{try canon(a, &ev.effective)});
    for (ev.prelisted, 0..) |p, i| try t.print(a, "{s}{d}/{d}/{d}", .{ if (i > 0) "," else "", p.voted_stake, p.eligible_stake, @intFromBool(p.active) });
    try t.appendSlice(a, " def=");
    for (ev.defaults, 0..) |d, i| try t.print(a, "{s}{d}/{d}", .{ if (i > 0) "," else "", d.eligible_stake, d.applied });
    return .{ ev.effective, t.items };
}

fn mgrState(a: Allocator, m: *dm.Manager) ![]const u8 {
    var t: std.ArrayList(u8) = .empty;
    try t.print(a, "eff={s} peers=", .{try canon(a, &try m.effectiveRules(a))});
    const peers = try m.peerSnapshot(a);
    if (peers.len == 0) try t.append(a, '-');
    for (peers, 0..) |p, i| {
        const rs = if (p.rules) |*r| try canon(a, r) else "none";
        try t.print(a, "{s}{d}#{d}#{s}", .{ if (i > 0) " " else "", p.name[0], p.generation, rs });
    }
    return t.items;
}

fn fixedNow() u64 {
    return 1_800_000_000_000;
}

const Scenario = struct {
    m: ?*dm.Manager = null,
    local: *txdeny.Config,
    sync: dm.SyncConfig = .{},
    slot: txdeny.Slot = .{},
    path: []const u8 = "",
};

test "denycfg vectors: evaluation, validation, manager sequences and signing checks match sui-core" {
    const gpa = std.testing.allocator;
    const text = try harness.decompressZstd(gpa, compressed, 64 << 20);
    defer gpa.free(text);
    var ar = std.heap.ArenaAllocator.init(gpa);
    defer ar.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = pbuf[0..try tmp.dir.realPath(std.testing.io, &pbuf)];

    var sc: Scenario = .{ .local = try ar.allocator().create(txdeny.Config) };
    defer {
        if (sc.m) |m| m.destroy();
        sc.slot.publish(null);
    }
    var cur_scenario: []const u8 = "";
    var counts: [4]usize = @splat(0);
    var failures: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var la = std.heap.ArenaAllocator.init(gpa);
        defer la.deinit();
        const a = la.allocator();
        var fl: std.ArrayList([]const u8) = .empty;
        var fi = std.mem.splitScalar(u8, line, '\t');
        while (fi.next()) |f| try fl.append(a, f);
        const f = fl.items;
        const want = f[f.len - 1];
        var got: []const u8 = undefined;
        if (std.mem.eql(u8, f[0], "eval")) {
            counts[0] += 1;
            got = try std.fmt.allocPrint(a, "ok {s}", .{(try evalText(a, f[1..5]))[1]});
        } else if (std.mem.eql(u8, f[0], "validate")) {
            counts[1] += 1;
            const c = try syncConfig(a, f[1]);
            got = if (try c.validate(a)) |e| try std.fmt.allocPrint(a, "err {s}", .{e}) else "ok";
        } else if (std.mem.eql(u8, f[0], "mgr")) {
            counts[2] += 1;
            const pa = ar.allocator();
            const op = f[2];
            if (!std.mem.eql(u8, f[1], cur_scenario)) {
                // a scenario starts with `new`: a fresh file
                if (sc.m) |m| m.destroy();
                sc.m = null;
                cur_scenario = try pa.dupe(u8, f[1]);
                sc.path = try std.fmt.allocPrint(pa, "{s}/deny-sync-{s}", .{ dir, f[1] });
            }
            if (std.mem.eql(u8, op, "new")) {
                sc.local.* = .{ .rules = try rules(pa, f[6]) };
                sc.sync = try syncConfig(pa, f[5]);
                sc.m = try dm.Manager.create(gpa, .{ .self_name = @splat(try std.fmt.parseInt(u8, f[3], 10)), .local = sc.local, .sync = sc.sync, .committee = try committee(a, f[4]), .slot = &sc.slot, .path = sc.path, .io = std.testing.io, .now_ms = fixedNow });
            } else if (std.mem.eql(u8, op, "apply")) {
                const from: dm.Name = @splat(try std.fmt.parseInt(u8, f[3], 10));
                sc.m.?.applyUpdates(&from, try msgs(a, f[4]));
            } else if (std.mem.eql(u8, op, "committee")) {
                try sc.m.?.updateForCommittee(try committee(a, f[3]));
            } else if (std.mem.eql(u8, op, "restart")) {
                sc.m.?.destroy();
                sc.m = try dm.Manager.create(gpa, .{ .self_name = @splat(try std.fmt.parseInt(u8, f[3], 10)), .local = sc.local, .sync = sc.sync, .committee = try committee(a, f[4]), .slot = &sc.slot, .path = sc.path, .io = std.testing.io, .now_ms = fixedNow });
            } else return error.BadVector;
            got = try std.fmt.allocPrint(a, "ok {s}", .{try mgrState(a, sc.m.?)});
            // the published snapshot is the manager's effective config
            var g = sc.slot.acquire();
            defer g.release();
            try std.testing.expect(dm.rulesEql(&g.config().rules, &try sc.m.?.effectiveRules(a)));
        } else if (std.mem.eql(u8, f[0], "sign")) {
            counts[3] += 1;
            const eff = (try evalText(a, f[1..5]))[0];
            const raw = try a.alloc(u8, f[5].len / 2);
            _ = try std.fmt.hexToBytes(raw, f[5]);
            const tdata = try bcs.decode(types.TransactionData, a, raw);
            const td = switch (tdata) {
                .V1 => |*v| v,
            };
            var kinds: std.ArrayList(checks.InputKind) = .empty;
            var recv: std.ArrayList(checks.Receiving) = .empty;
            if (try checks.inputKinds(a, td, &kinds, &recv)) |fail| {
                got = try std.fmt.allocPrint(a, "err {s}", .{fail.message});
            } else if (try txdeny.check(a, &eff, td, &.{}, kinds.items, recv.items, null)) |fail| {
                got = try std.fmt.allocPrint(a, "err {s}", .{fail.message});
            } else got = "ok";
        } else return error.BadVector;
        if (!std.mem.eql(u8, got, want)) {
            failures += 1;
            if (failures <= 20) std.debug.print("denycfg mismatch: {s}\n  want {s}\n  got  {s}\n", .{ line[0..@min(line.len, 300)], want, got });
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
    // every section is present
    for (counts) |n| try std.testing.expect(n > 0);
}
