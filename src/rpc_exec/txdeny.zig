//! `transaction-deny-config` (sui-config 1.83.1 `transaction_deny_config.rs`, the rules are
//! sui-types `TransactionDenyRules`) and the signing-time deny checks
//! (`sui_transaction_checks::deny::check_transaction_for_signing`).
//!
//! sui-node runs the checks in `pre_object_load_checks`: after `validity_check`, before the
//! funds-withdrawal checks and the input loader. That is the same point in Execute's early
//! validation (`check_transaction_validity` -> `handle_transaction_deny_checks`, with the request's
//! signatures) and in Simulate (`transaction_simulation::simulate_transaction`, no signatures, the
//! input kinds computed before the mock gas coin is added). A denial is
//! `UserInputError::TransactionDenied`: "Error checking transaction input objects: Transaction is
//! denied: <why>", INVALID_ARGUMENT in Simulate and `TransactionFailed { InvalidTransaction }` in
//! Execute (no validator is contacted).
//!
//! Order (the first failing rule answers): user transactions disabled, gasless disabled, each
//! top-level zkLogin signature (zkLogin disabled, then its provider), package publish / upgrade per
//! command; denied signer addresses (sender, sponsor, then each signature's address); input objects
//! in input order (denied id, then shared); packages used (publish/upgrade deps, the upgraded
//! package, each MoveCall package's linkage `upgraded_id`s in linkage-table order then the package
//! itself); receiving objects (disabled, then denied ids).
//!
//! `dynamic-transaction-checks` (a Starlark predicate) is not run by deepwave: a config with one is
//! accepted (the admin dump says `has_dynamic_transaction_checks: true`) and the node logs that the
//! predicate is ignored.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const sig = @import("sig");
const checks = @import("checks.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const Fail = checks.Fail;

pub const Rules = struct {
    /// Sorted, unique (BTreeSet<ObjectID>).
    object_deny_list: []const Id = &.{},
    package_deny_list: []const Id = &.{},
    address_deny_list: []const Id = &.{},
    package_publish_disabled: bool = false,
    package_upgrade_disabled: bool = false,
    shared_object_disabled: bool = false,
    user_transaction_disabled: bool = false,
    gasless_disabled: bool = false,
    receiving_objects_disabled: bool = false,
    zklogin_sig_disabled: bool = false,
    /// Sorted (byte order), unique (BTreeSet<String>).
    zklogin_disabled_providers: []const []const u8 = &.{},

    pub fn isEmpty(r: *const Rules) bool {
        return r.object_deny_list.len == 0 and r.package_deny_list.len == 0 and r.address_deny_list.len == 0 and
            !r.package_publish_disabled and !r.package_upgrade_disabled and !r.shared_object_disabled and
            !r.user_transaction_disabled and !r.gasless_disabled and !r.receiving_objects_disabled and
            !r.zklogin_sig_disabled and r.zklogin_disabled_providers.len == 0;
    }
};

pub const Config = struct {
    rules: Rules = .{},
    /// `dynamic-transaction-checks` was given.
    has_dynamic_transaction_checks: bool = false,
    /// Its program text (deepwave evaluates constant expressions only, see `dynamic`).
    dynamic_program: []const u8 = "",

    /// Anything to check: a rule, or a dynamic predicate alone (sui-node runs the predicate even
    /// when every rule is empty: `deny-dyn-*` truth).
    pub fn active(c: *const Config) bool {
        return !c.rules.isEmpty() or c.has_dynamic_transaction_checks;
    }
};

var global_cfg: Config = .{};

/// The node's config (set once at startup, before serving).
pub fn install(c: Config) void {
    global_cfg = c;
}

pub fn current() *const Config {
    return &global_cfg;
}

// ---- config from run flags --------------------------------------------------------------------

/// The keys of `transaction-deny-config` (kebab-case, as in fullnode.yaml).
pub const keys = [_][]const u8{
    "object-deny-list",           "package-deny-list",          "address-deny-list",
    "package-publish-disabled",   "package-upgrade-disabled",   "shared-object-disabled",
    "user-transaction-disabled",  "gasless-disabled",           "receiving-objects-disabled",
    "zklogin-sig-disabled",       "zklogin-disabled-providers", "dynamic-transaction-checks",
};

pub fn knownKey(k: []const u8) bool {
    for (keys) |x| if (std.mem.eql(u8, x, k)) return true;
    return false;
}

pub const ParseError = error{ UnknownKey, BadValue, OutOfMemory };

/// Builds a Config from `--tx-deny KEY=VALUE` items. Lists take comma-separated values and
/// accumulate over repeated items; `KEY=` alone is an empty list.
pub fn parseItems(arena: Allocator, items: []const []const u8) ParseError!Config {
    var c: Config = .{};
    var objs: std.ArrayList(Id) = .empty;
    var pkgs: std.ArrayList(Id) = .empty;
    var addrs: std.ArrayList(Id) = .empty;
    var provs: std.ArrayList([]const u8) = .empty;
    for (items) |it| {
        const eq = std.mem.indexOfScalar(u8, it, '=') orelse return error.BadValue;
        const k = it[0..eq];
        const v = it[eq + 1 ..];
        const r = &c.rules;
        if (std.mem.eql(u8, k, "object-deny-list")) {
            try idList(arena, &objs, v);
        } else if (std.mem.eql(u8, k, "package-deny-list")) {
            try idList(arena, &pkgs, v);
        } else if (std.mem.eql(u8, k, "address-deny-list")) {
            try idList(arena, &addrs, v);
        } else if (std.mem.eql(u8, k, "zklogin-disabled-providers")) {
            var sp = std.mem.splitScalar(u8, v, ',');
            while (sp.next()) |s| if (s.len > 0) try provs.append(arena, try arena.dupe(u8, s));
        } else if (std.mem.eql(u8, k, "dynamic-transaction-checks")) {
            c.has_dynamic_transaction_checks = v.len > 0;
            c.dynamic_program = try arena.dupe(u8, v);
        } else {
            const b = std.meta.stringToEnum(enum { true, false }, v) orelse return error.BadValue;
            const val = b == .true;
            if (std.mem.eql(u8, k, "package-publish-disabled")) r.package_publish_disabled = val //
            else if (std.mem.eql(u8, k, "package-upgrade-disabled")) r.package_upgrade_disabled = val //
            else if (std.mem.eql(u8, k, "shared-object-disabled")) r.shared_object_disabled = val //
            else if (std.mem.eql(u8, k, "user-transaction-disabled")) r.user_transaction_disabled = val //
            else if (std.mem.eql(u8, k, "gasless-disabled")) r.gasless_disabled = val //
            else if (std.mem.eql(u8, k, "receiving-objects-disabled")) r.receiving_objects_disabled = val //
            else if (std.mem.eql(u8, k, "zklogin-sig-disabled")) r.zklogin_sig_disabled = val //
            else return error.UnknownKey;
        }
    }
    c.rules.object_deny_list = sortedIds(objs.items);
    c.rules.package_deny_list = sortedIds(pkgs.items);
    c.rules.address_deny_list = sortedIds(addrs.items);
    std.mem.sort([]const u8, provs.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    var n: usize = 0;
    for (provs.items) |p| {
        if (n > 0 and std.mem.eql(u8, provs.items[n - 1], p)) continue;
        provs.items[n] = p;
        n += 1;
    }
    c.rules.zklogin_disabled_providers = provs.items[0..n];
    return c;
}

fn idList(arena: Allocator, out: *std.ArrayList(Id), v: []const u8) ParseError!void {
    var sp = std.mem.splitScalar(u8, v, ',');
    while (sp.next()) |s0| {
        const s = std.mem.trim(u8, s0, " \"'");
        if (s.len == 0) continue;
        try out.append(arena, parseId(s) orelse return error.BadValue);
    }
}

/// `ObjectID` / `SuiAddress` from a hex literal (0x optional, short forms left-padded).
pub fn parseId(s: []const u8) ?Id {
    const d = if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) s[2..] else s;
    if (d.len == 0 or d.len > 64) return null;
    var buf: [64]u8 = @splat('0');
    @memcpy(buf[64 - d.len ..], d);
    var id: Id = undefined;
    _ = std.fmt.hexToBytes(&id, &buf) catch return null;
    return id;
}

fn lessId(_: void, a: Id, b: Id) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

fn sortedIds(l: []Id) []const Id {
    std.mem.sort(Id, l, {}, lessId);
    var n: usize = 0;
    for (l) |x| {
        if (n > 0 and std.mem.eql(u8, &l[n - 1], &x)) continue;
        l[n] = x;
        n += 1;
    }
    return l[0..n];
}

fn contains(set: []const Id, id: *const Id) bool {
    var lo: usize = 0;
    var hi: usize = set.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        switch (std.mem.order(u8, &set[mid], id)) {
            .eq => return true,
            .lt => lo = mid + 1,
            .gt => hi = mid,
        }
    }
    return false;
}

// ---- admin GET /transaction-deny-config --------------------------------------------------------

/// sui-node `transaction_deny_config_dump` (serde_json pretty, insertion-ordered maps) and the
/// trailing newline. On a full node `effective` is the local config (no peer votes) and the voting
/// sections are empty.
pub fn writeDump(w: *std.Io.Writer, c: *const Config) std.Io.Writer.Error!void {
    try w.writeAll("{\n  \"local\": {\n    \"rules\": ");
    try writeRules(w, &c.rules, 4);
    try w.print(",\n    \"has_dynamic_transaction_checks\": {}\n  }},\n  \"peers\": {{}},\n  \"effective\": {{\n    \"rules\": ", .{c.has_dynamic_transaction_checks});
    try writeRules(w, &c.rules, 4);
    try w.print(",\n    \"has_dynamic_transaction_checks\": {}\n  }},\n  \"voting\": {{\n    \"prelisted\": [],\n    \"defaults\": []\n  }}\n}}\n", .{c.has_dynamic_transaction_checks});
}

fn pad(w: *std.Io.Writer, n: usize) !void {
    try w.splatByteAll(' ', n);
}

fn writeIdList(w: *std.Io.Writer, l: []const Id, ind: usize) !void {
    if (l.len == 0) return w.writeAll("[]");
    try w.writeAll("[\n");
    for (l, 0..) |id, i| {
        try pad(w, ind + 2);
        try w.print("\"0x{x}\"", .{&id});
        if (i + 1 < l.len) try w.writeByte(',');
        try w.writeByte('\n');
    }
    try pad(w, ind);
    try w.writeByte(']');
}

fn writeJsonString(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |ch| switch (ch) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0x08 => try w.writeAll("\\b"),
        0x0c => try w.writeAll("\\f"),
        0...0x07, 0x0b, 0x0e...0x1f => try w.print("\\u{x:0>4}", .{ch}),
        else => try w.writeByte(ch),
    };
    try w.writeByte('"');
}

fn writeRules(w: *std.Io.Writer, r: *const Rules, ind: usize) !void {
    const in = ind + 2;
    try w.writeAll("{\n");
    try pad(w, in);
    try w.writeAll("\"object-deny-list\": ");
    try writeIdList(w, r.object_deny_list, in);
    try w.writeAll(",\n");
    try pad(w, in);
    try w.writeAll("\"package-deny-list\": ");
    try writeIdList(w, r.package_deny_list, in);
    try w.writeAll(",\n");
    try pad(w, in);
    try w.writeAll("\"address-deny-list\": ");
    try writeIdList(w, r.address_deny_list, in);
    try w.writeAll(",\n");
    const bools = [_]struct { []const u8, bool }{
        .{ "package-publish-disabled", r.package_publish_disabled },
        .{ "package-upgrade-disabled", r.package_upgrade_disabled },
        .{ "shared-object-disabled", r.shared_object_disabled },
        .{ "user-transaction-disabled", r.user_transaction_disabled },
        .{ "gasless-disabled", r.gasless_disabled },
        .{ "receiving-objects-disabled", r.receiving_objects_disabled },
        .{ "zklogin-sig-disabled", r.zklogin_sig_disabled },
    };
    for (bools) |b| {
        try pad(w, in);
        try w.print("\"{s}\": {},\n", .{ b[0], b[1] });
    }
    try pad(w, in);
    try w.writeAll("\"zklogin-disabled-providers\": ");
    if (r.zklogin_disabled_providers.len == 0) {
        try w.writeAll("[]");
    } else {
        try w.writeAll("[\n");
        for (r.zklogin_disabled_providers, 0..) |p, i| {
            try pad(w, in + 2);
            try writeJsonString(w, p);
            if (i + 1 < r.zklogin_disabled_providers.len) try w.writeByte(',');
            try w.writeByte('\n');
        }
        try pad(w, in);
        try w.writeByte(']');
    }
    try w.writeByte('\n');
    try pad(w, ind);
    try w.writeByte('}');
}

// ---- the checks -------------------------------------------------------------------------------

/// BCS `Object` of a package by its exact id (`BackingPackageStore::get_package_object`).
pub const PackageLookup = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, arena: Allocator, id: *const Id) ?[]const u8,
};

fn denied(arena: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error!Fail {
    return checks.userInput(arena, "Transaction is denied: " ++ fmt, args);
}

/// `OIDCProvider::from_iss(iss).to_string()` (null: from_iss fails).
pub fn providerName(arena: Allocator, iss: []const u8) Allocator.Error!?[]const u8 {
    const P = sig.user.OidcProvider;
    if (P.fromIss(iss)) |p| return switch (p) {
        .google => "Google",
        .twitch => "Twitch",
        .facebook => "Facebook",
        .kakao => "Kakao",
        .apple => "Apple",
        .slack => "Slack",
        .test_issuer => "TestIssuer",
        .test_issuer_key8192 => "TestIssuerKey8192",
        .microsoft => "Microsoft",
        .karrier_one => "KarrierOne",
        .credenza3 => "Credenza3",
        .playtron => "Playtron",
        .threedos => "Threedos",
        .onefc => "Onefc",
        .fan_tv => "FanTV",
        .arden => "Arden",
        .eve_frontier => "EveFrontier",
        .test_eve_frontier => "TestEveFrontier",
    };
    // regex `https://cognito-idp\.(?P<region>[^.]+)\.amazonaws\.com/(?P<tenant_id>[^/]+)`, unanchored
    const pre = "https://cognito-idp.";
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, iss, from, pre)) |at| : (from = at + 1) {
        const rs = at + pre.len;
        const dot = std.mem.indexOfScalarPos(u8, iss, rs, '.') orelse continue;
        if (dot == rs) continue;
        const mid = ".amazonaws.com/";
        if (!std.mem.startsWith(u8, iss[dot..], mid)) continue;
        const ts = dot + mid.len;
        var te = ts;
        while (te < iss.len and iss[te] != '/') te += 1;
        if (te == ts) continue;
        return try std.fmt.allocPrint(arena, "AwsTenant-region:{s}-tenant_id:{s}", .{ iss[rs..dot], iss[ts..te] });
    }
    return null;
}

fn providerDisabled(r: *const Rules, name: []const u8) bool {
    for (r.zklogin_disabled_providers) |p| if (std.mem.eql(u8, p, name)) return true;
    return false;
}

/// `check_transaction_for_signing`. `kinds`/`recv` are `TransactionData::input_objects` and
/// `receiving_objects` (checks.inputKinds); `sigs` the raw GenericSignatures (none in Simulate).
/// `pkgs` serves MoveCall packages when the package deny list is not empty.
pub fn check(arena: Allocator, r: *const Rules, td: *const types.TransactionDataV1, sigs: []const []const u8, kinds: []const checks.InputKind, recv: []const checks.Receiving, pkgs: ?PackageLookup) Allocator.Error!?Fail {
    // check_disabled_features
    if (r.user_transaction_disabled) return try denied(arena, "Transaction signing is temporarily disabled", .{});
    if (r.gasless_disabled and checks.gasPaidFromAddressBalance(td) and td.gas_data.price == 0)
        return try denied(arena, "Gasless transactions are temporarily disabled", .{});
    for (sigs) |s| {
        if (s.len == 0 or s[0] != 5) continue; // GenericSignature::ZkLoginAuthenticator
        var parsed: sig.user.Parsed = undefined;
        const scratch = try arena.alloc(u8, sig.user.scratchLen(s.len));
        if (sig.user.parse(s, &parsed, scratch) != null or parsed != .zklogin) continue;
        if (r.zklogin_sig_disabled) return try denied(arena, "zkLogin authenticator is temporarily disabled", .{});
        const iss = parsed.zklogin.auth.iss;
        const name = (try providerName(arena, iss)) orelse
            return Fail{ .code = 13, .message = try std.fmt.allocPrint(arena, "Unexpected message: {s}", .{iss}) };
        if (providerDisabled(r, name)) return try denied(arena, "zkLogin OAuth provider is temporarily disabled", .{});
    }
    const pt = checks.ptbOf(td);
    if (r.package_publish_disabled or r.package_upgrade_disabled) if (pt) |p| for (p.commands) |*c| {
        if (r.package_publish_disabled and c.* == .Publish) return try denied(arena, "Package publish is temporarily disabled", .{});
        if (r.package_upgrade_disabled and c.* == .Upgrade) return try denied(arena, "Package upgrade is temporarily disabled", .{});
    };

    // check_signers
    if (r.address_deny_list.len > 0) {
        const sender = td.sender.@"0";
        if (contains(r.address_deny_list, &sender)) return try denied(arena, "Access to account address {s} is temporarily disabled", .{checks.hex(&sender).s()});
        const owner = td.gas_data.owner.@"0";
        if (!std.mem.eql(u8, &owner, &sender) and contains(r.address_deny_list, &owner))
            return try denied(arena, "Access to account address {s} is temporarily disabled", .{checks.hex(&owner).s()});
        for (sigs) |s| {
            var parsed: sig.user.Parsed = undefined;
            const scratch = try arena.alloc(u8, sig.user.scratchLen(s.len));
            if (sig.user.parse(s, &parsed, scratch) != null) continue;
            const a = switch (sig.user.address(&parsed) catch continue) {
                .ok => |x| x,
                .err => continue,
            };
            if (contains(r.address_deny_list, &a)) return try denied(arena, "Access to account address {s} is temporarily disabled", .{checks.hex(&a).s()});
        }
    }

    // check_input_objects
    if (r.object_deny_list.len > 0 or r.shared_object_disabled) for (kinds) |*k| {
        if (contains(r.object_deny_list, k.id())) return try denied(arena, "Access to input object {s} is temporarily disabled", .{checks.hex(k.id()).s()});
        if (r.shared_object_disabled and k.* == .shared) return try denied(arena, "Usage of shared object in transactions is temporarily disabled", .{});
    };

    // check_package_dependencies
    if (r.package_deny_list.len > 0) if (pt) |p| {
        var deps: std.ArrayList(Id) = .empty;
        for (p.commands) |*c| switch (c.*) {
            .Publish => |x| for (x[1]) |d| try deps.append(arena, d.@"0".@"0"),
            .Upgrade => |x| {
                for (x[1]) |d| try deps.append(arena, d.@"0".@"0");
                try deps.append(arena, x[2].@"0".@"0");
            },
            .MoveCall => |m| {
                const pid = m.package.@"0".@"0";
                const raw = if (pkgs) |l| l.get(l.ctx, arena, &pid) else null;
                const obj = if (raw) |b| bcs.decode(types.Object, arena, b) catch null else null;
                const pkg = if (obj) |o| switch (o.data) {
                    .Package => |pk| pk,
                    else => null,
                } else null;
                const pk = pkg orelse return try checks.userInput(arena, "Could not find the referenced object {s} at version None", .{checks.hex(&pid).s()});
                for (pk.linkage_table.entries) |e| try deps.append(arena, e.value.upgraded_id.@"0".@"0");
                try deps.append(arena, pk.id.@"0".@"0");
            },
            else => {},
        };
        for (deps.items) |*d| if (contains(r.package_deny_list, d)) return try denied(arena, "Access to package {s} is temporarily disabled", .{checks.hex(d).s()});
    };

    // check_receiving_objects
    if (r.receiving_objects_disabled and recv.len > 0) return try denied(arena, "Receiving objects is temporarily disabled", .{});
    for (recv) |*o| if (contains(r.object_deny_list, &o.id)) return try denied(arena, "Access to object {s} is temporarily disabled", .{checks.hex(&o.id).s()});
    // dynamic_transaction_checks (signing time only): the installed config's program
    if (r == &global_cfg.rules and global_cfg.has_dynamic_transaction_checks) return dynamic(arena, global_cfg.dynamic_program);
    return null;
}

/// The Starlark predicate for programs that are one constant expression (True, False, an
/// integer, `a // b`): sui-node's answers for them. Any other program is not evaluated (deepwave has
/// no Starlark interpreter; the node warns at start) and passes.
pub fn dynamic(arena: Allocator, program: []const u8) Allocator.Error!?Fail {
    const p = std.mem.trim(u8, program, " \t\r\n");
    if (std.mem.eql(u8, p, "True")) return null;
    if (std.mem.eql(u8, p, "False")) return try denied(arena, "Dynamic transaction predicate failed", .{});
    if (std.fmt.parseInt(i64, p, 10)) |n| {
        return try denied(arena, "Failed to execute Starlark program -- invalid return type expected a bool but got {d}", .{n});
    } else |_| {}
    if (std.mem.indexOf(u8, p, "//")) |i| {
        const l = std.fmt.parseInt(i64, std.mem.trim(u8, p[0..i], " "), 10) catch return null;
        const rr = std.fmt.parseInt(i64, std.mem.trim(u8, p[i + 2 ..], " "), 10) catch return null;
        if (rr == 0) return try denied(arena, "Failed to execute Starlark program: Floor division by zero: {d} // {d}", .{ l, rr });
        return try denied(arena, "Failed to execute Starlark program -- invalid return type expected a bool but got {d}", .{@divFloor(l, rr)});
    }
    return null;
}

// ---- tests ------------------------------------------------------------------------------------

const testing = std.testing;

fn tid(b: u8) Id {
    return @splat(b);
}
fn oid(b: u8) types.ObjectID {
    return .{ .@"0" = .{ .@"0" = tid(b) } };
}
fn oref(b: u8) struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest } {
    return .{ oid(b), .{ .@"0" = 3 }, .{ .@"0" = .{ .@"0" = tid(0xdd) } } };
}

const Tx = struct {
    inputs: []const types.CallArg = &.{},
    commands: []const types.Command = &.{},
    sender: u8 = 0xa1,
    owner: u8 = 0xa1,
    gas: bool = true,
    price: u64 = 1000,

    fn data(t: Tx, arena: Allocator) !*types.TransactionDataV1 {
        const td = try arena.create(types.TransactionDataV1);
        const pay = try arena.alloc(@typeInfo(@TypeOf(td.gas_data.payment)).pointer.child, if (t.gas) 1 else 0);
        if (t.gas) pay[0] = oref(0x99);
        td.* = .{
            .kind = .{ .ProgrammableTransaction = .{ .inputs = t.inputs, .commands = t.commands } },
            .sender = .{ .@"0" = tid(t.sender) },
            .gas_data = .{ .payment = pay, .owner = .{ .@"0" = tid(t.owner) }, .price = t.price, .budget = 5_000_000 },
            .expiration = .None,
        };
        return td;
    }
};

fn run(arena: Allocator, items: []const []const u8, tx: Tx, sigs: []const []const u8, pkgs: ?PackageLookup) !?[]const u8 {
    const c = try parseItems(arena, items);
    const td = try tx.data(arena);
    var kinds: std.ArrayList(checks.InputKind) = .empty;
    var recv: std.ArrayList(checks.Receiving) = .empty;
    try testing.expect((try checks.inputKinds(arena, td, &kinds, &recv)) == null);
    const f = (try check(arena, &c.rules, td, sigs, kinds.items, recv.items, pkgs)) orelse return null;
    try testing.expectEqual(@as(u8, 3), f.code);
    const pre = "Error checking transaction input objects: Transaction is denied: ";
    if (std.mem.startsWith(u8, f.message, pre)) return f.message[pre.len..];
    return f.message;
}

const owned_in = [_]types.CallArg{.{ .Object = .{ .ImmOrOwnedObject = oref(0x11) } }};
const shared_in = [_]types.CallArg{.{ .Object = .{ .SharedObject = .{ .id = oid(0x22), .initial_shared_version = .{ .@"0" = 1 }, .mutability = .Mutable } } }};
const recv_in = [_]types.CallArg{.{ .Object = .{ .Receiving = oref(0x33) } }};
const publish_cmd = [_]types.Command{.{ .Publish = .{ &.{}, &.{ oid(0x41), oid(0x42) } } }};
const upgrade_cmd = [_]types.Command{.{ .Upgrade = .{ &.{}, &.{oid(0x43)}, oid(0x44), .GasCoin } }};
const call_cmd = [_]types.Command{.{ .MoveCall = .{ .package = oid(0x50), .module = .{ .@"0" = "m" }, .function = .{ .@"0" = "f" }, .type_arguments = &.{}, .arguments = &.{} } }};

test "txdeny: empty config denies nothing" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    try testing.expect((try run(a.allocator(), &.{}, .{ .inputs = &shared_in, .commands = &publish_cmd }, &.{}, null)) == null);
    try testing.expect((try parseItems(a.allocator(), &.{})).rules.isEmpty());
}

test "txdeny: every field" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const h11 = "0x" ++ "1111111111111111111111111111111111111111111111111111111111111111";
    try testing.expectEqualStrings("Transaction signing is temporarily disabled", (try run(ar, &.{"user-transaction-disabled=true"}, .{}, &.{}, null)).?);
    try testing.expect((try run(ar, &.{"user-transaction-disabled=false"}, .{}, &.{}, null)) == null);
    // gasless: address-balance gas at price 0
    try testing.expectEqualStrings("Gasless transactions are temporarily disabled", (try run(ar, &.{"gasless-disabled=true"}, .{ .gas = false, .price = 0 }, &.{}, null)).?);
    try testing.expect((try run(ar, &.{"gasless-disabled=true"}, .{ .gas = false, .price = 1 }, &.{}, null)) == null);
    try testing.expect((try run(ar, &.{"gasless-disabled=true"}, .{ .price = 0 }, &.{}, null)) == null);
    try testing.expectEqualStrings("Package publish is temporarily disabled", (try run(ar, &.{"package-publish-disabled=true"}, .{ .commands = &publish_cmd }, &.{}, null)).?);
    try testing.expect((try run(ar, &.{"package-publish-disabled=true"}, .{ .commands = &upgrade_cmd }, &.{}, null)) == null);
    try testing.expectEqualStrings("Package upgrade is temporarily disabled", (try run(ar, &.{"package-upgrade-disabled=true"}, .{ .commands = &upgrade_cmd }, &.{}, null)).?);
    try testing.expectEqualStrings("Access to account address 0x" ++ "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" ++ " is temporarily disabled", (try run(ar, &.{"address-deny-list=0x" ++ "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}, .{}, &.{}, null)).?);
    try testing.expectEqualStrings("Access to account address 0x" ++ "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2" ++ " is temporarily disabled", (try run(ar, &.{"address-deny-list=0x" ++ "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"}, .{ .owner = 0xb2 }, &.{}, null)).?);
    try testing.expectEqualStrings("Access to input object " ++ h11 ++ " is temporarily disabled", (try run(ar, &.{"object-deny-list=" ++ h11}, .{ .inputs = &owned_in }, &.{}, null)).?);
    // the gas coin is an input object too
    try testing.expectEqualStrings("Access to input object 0x" ++ "9999999999999999999999999999999999999999999999999999999999999999" ++ " is temporarily disabled", (try run(ar, &.{"object-deny-list=0x" ++ "9999999999999999999999999999999999999999999999999999999999999999"}, .{}, &.{}, null)).?);
    try testing.expectEqualStrings("Usage of shared object in transactions is temporarily disabled", (try run(ar, &.{"shared-object-disabled=true"}, .{ .inputs = &shared_in }, &.{}, null)).?);
    try testing.expect((try run(ar, &.{"shared-object-disabled=true"}, .{ .inputs = &owned_in }, &.{}, null)) == null);
    try testing.expectEqualStrings("Receiving objects is temporarily disabled", (try run(ar, &.{"receiving-objects-disabled=true"}, .{ .inputs = &recv_in }, &.{}, null)).?);
    try testing.expectEqualStrings("Access to object 0x" ++ "3333333333333333333333333333333333333333333333333333333333333333" ++ " is temporarily disabled", (try run(ar, &.{"object-deny-list=0x" ++ "3333333333333333333333333333333333333333333333333333333333333333"}, .{ .inputs = &recv_in }, &.{}, null)).?);
    // packages: publish deps, upgrade deps then the upgraded package
    try testing.expectEqualStrings("Access to package 0x" ++ "4242424242424242424242424242424242424242424242424242424242424242" ++ " is temporarily disabled", (try run(ar, &.{"package-deny-list=0x" ++ "4242424242424242424242424242424242424242424242424242424242424242"}, .{ .commands = &publish_cmd }, &.{}, null)).?);
    try testing.expectEqualStrings("Access to package 0x" ++ "4444444444444444444444444444444444444444444444444444444444444444" ++ " is temporarily disabled", (try run(ar, &.{"package-deny-list=0x" ++ "4444444444444444444444444444444444444444444444444444444444444444"}, .{ .commands = &upgrade_cmd }, &.{}, null)).?);
    // MoveCall without the package: ObjectNotFound (only with a package deny list)
    try testing.expectEqualStrings("Error checking transaction input objects: Could not find the referenced object 0x" ++ "5050505050505050505050505050505050505050505050505050505050505050" ++ " at version None", (try run(ar, &.{"package-deny-list=0x01"}, .{ .commands = &call_cmd }, &.{}, null)).?);
    try testing.expect((try run(ar, &.{"object-deny-list=0x01"}, .{ .commands = &call_cmd }, &.{}, null)) == null);
}

const PkgStore = struct {
    raw: []const u8,
    fn lookup(p: *PkgStore) PackageLookup {
        return .{ .ctx = p, .get = get };
    }
    fn get(ctx: *anyopaque, _: Allocator, id: *const Id) ?[]const u8 {
        const p: *PkgStore = @ptrCast(@alignCast(ctx));
        return if (std.mem.eql(u8, id, &tid(0x50))) p.raw else null;
    }
};

test "txdeny: MoveCall packages through the linkage table" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const E = @TypeOf(@as(types.MovePackage, undefined).linkage_table).Entry;
    const link = [_]E{
        .{ .key = oid(0x60), .value = .{ .upgraded_id = oid(0x61), .upgraded_version = .{ .@"0" = 2 } } },
        .{ .key = oid(0x70), .value = .{ .upgraded_id = oid(0x71), .upgraded_version = .{ .@"0" = 2 } } },
    };
    const obj: types.Object = .{
        .data = .{ .Package = .{ .id = oid(0x50), .version = .{ .@"0" = 1 }, .module_map = .{ .entries = &.{} }, .type_origin_table = &.{}, .linkage_table = .{ .entries = &link } } },
        .owner = .Immutable,
        .previous_transaction = .{ .@"0" = .{ .@"0" = tid(0) } },
        .storage_rebate = 0,
    };
    var ps: PkgStore = .{ .raw = try bcs.encodeAlloc(types.Object, ar, &obj) };
    try testing.expectEqualStrings("Access to package 0x" ++ "7171717171717171717171717171717171717171717171717171717171717171" ++ " is temporarily disabled", (try run(ar, &.{"package-deny-list=0x" ++ "7171717171717171717171717171717171717171717171717171717171717171"}, .{ .commands = &call_cmd }, &.{}, ps.lookup())).?);
    // the original id of a dependency is not checked (only upgraded ids), the called package is
    try testing.expect((try run(ar, &.{"package-deny-list=0x" ++ "6060606060606060606060606060606060606060606060606060606060606060"}, .{ .commands = &call_cmd }, &.{}, ps.lookup())) == null);
    try testing.expectEqualStrings("Access to package 0x" ++ "5050505050505050505050505050505050505050505050505050505050505050" ++ " is temporarily disabled", (try run(ar, &.{"package-deny-list=0x" ++ "5050505050505050505050505050505050505050505050505050505050505050"}, .{ .commands = &call_cmd }, &.{}, ps.lookup())).?);
    // linkage order: the first denied in the list answers
    try testing.expectEqualStrings("Access to package 0x" ++ "6161616161616161616161616161616161616161616161616161616161616161" ++ " is temporarily disabled", (try run(ar, &.{ "package-deny-list=0x" ++ "7171717171717171717171717171717171717171717171717171717171717171", "package-deny-list=0x" ++ "6161616161616161616161616161616161616161616161616161616161616161" ++ ",0x" ++ "5050505050505050505050505050505050505050505050505050505050505050" }, .{ .commands = &call_cmd }, &.{}, ps.lookup())).?);
}

test "txdeny: precedence" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const all = [_][]const u8{
        "user-transaction-disabled=true",  "gasless-disabled=true",     "package-publish-disabled=true",
        "address-deny-list=0x" ++ "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", "object-deny-list=0x" ++ "1111111111111111111111111111111111111111111111111111111111111111" ++ ",0x" ++ "3333333333333333333333333333333333333333333333333333333333333333",
        "shared-object-disabled=true",     "package-deny-list=0x" ++ "4141414141414141414141414141414141414141414141414141414141414141", "receiving-objects-disabled=true",
    };
    const tx: Tx = .{ .inputs = &(owned_in ++ shared_in ++ recv_in), .commands = &publish_cmd };
    // disabled features, then signers, then input objects, then packages, then receiving
    try testing.expectEqualStrings("Transaction signing is temporarily disabled", (try run(ar, &all, tx, &.{}, null)).?);
    try testing.expectEqualStrings("Package publish is temporarily disabled", (try run(ar, all[1..], tx, &.{}, null)).?);
    try testing.expectEqualStrings("Access to account address 0x" ++ "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" ++ " is temporarily disabled", (try run(ar, all[3..], tx, &.{}, null)).?);
    try testing.expectEqualStrings("Access to input object 0x" ++ "1111111111111111111111111111111111111111111111111111111111111111" ++ " is temporarily disabled", (try run(ar, all[4..], tx, &.{}, null)).?);
    try testing.expectEqualStrings("Usage of shared object in transactions is temporarily disabled", (try run(ar, all[5..], tx, &.{}, null)).?);
    try testing.expectEqualStrings("Access to package 0x" ++ "4141414141414141414141414141414141414141414141414141414141414141" ++ " is temporarily disabled", (try run(ar, all[6..], tx, &.{}, null)).?);
    try testing.expectEqualStrings("Receiving objects is temporarily disabled", (try run(ar, all[7..], tx, &.{}, null)).?);
    // per input: the denied id before the shared check of the same input; input order wins
    try testing.expectEqualStrings("Access to input object 0x" ++ "2222222222222222222222222222222222222222222222222222222222222222" ++ " is temporarily disabled", (try run(ar, &.{ "shared-object-disabled=true", "object-deny-list=0x" ++ "2222222222222222222222222222222222222222222222222222222222222222" }, .{ .inputs = &(shared_in ++ owned_in) }, &.{}, null)).?);
    // receiving disabled before a denied receiving id
    try testing.expectEqualStrings("Receiving objects is temporarily disabled", (try run(ar, &.{ "receiving-objects-disabled=true", "object-deny-list=0x" ++ "3333333333333333333333333333333333333333333333333333333333333333" }, .{ .inputs = &recv_in }, &.{}, null)).?);
}

test "txdeny: zkLogin provider names" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try testing.expectEqualStrings("Google", (try providerName(ar, "https://accounts.google.com")).?);
    try testing.expectEqualStrings("Microsoft", (try providerName(ar, "https://login.microsoftonline.com/abc/v2.0")).?);
    try testing.expectEqualStrings("AwsTenant-region:us-east-1-tenant_id:pool1", (try providerName(ar, "https://cognito-idp.us-east-1.amazonaws.com/pool1/x")).?);
    try testing.expect((try providerName(ar, "https://example.com")) == null);
}

test "txdeny: admin dump" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    var out: std.Io.Writer.Allocating = .init(a.allocator());
    try writeDump(&out.writer, &.{});
    try testing.expect(std.mem.startsWith(u8, out.written(),
        \\{
        \\  "local": {
        \\    "rules": {
        \\      "object-deny-list": [],
        \\      "package-deny-list": [],
        \\      "address-deny-list": [],
        \\      "package-publish-disabled": false,
    ));
    try testing.expect(std.mem.endsWith(u8, out.written(),
        \\      "zklogin-disabled-providers": []
        \\    },
        \\    "has_dynamic_transaction_checks": false
        \\  },
        \\  "voting": {
        \\    "prelisted": [],
        \\    "defaults": []
        \\  }
        \\}
        \\
    ));
    out.clearRetainingCapacity();
    const c = try parseItems(a.allocator(), &.{ "zklogin-disabled-providers=Google,Apple,Google", "object-deny-list=0x2,0x1" });
    try writeDump(&out.writer, &c);
    try testing.expect(std.mem.indexOf(u8, out.written(), "\"object-deny-list\": [\n        \"0x" ++ "00000000000000000000000000000000000000000000000000000000000000" ++ "01\",\n        \"0x" ++ "00000000000000000000000000000000000000000000000000000000000000" ++ "02\"\n      ],") != null);
    try testing.expect(std.mem.indexOf(u8, out.written(), "\"zklogin-disabled-providers\": [\n        \"Apple\",\n        \"Google\"\n      ]\n") != null);
    try testing.expectError(error.UnknownKey, parseItems(a.allocator(), &.{"nope=true"}));
    try testing.expectError(error.BadValue, parseItems(a.allocator(), &.{"gasless-disabled=yes"}));
}
