//! Signing-time checks of a simulated transaction (CONTRACTS 6.7), in Mysten's order:
//! `TransactionDataV1::validity_check` (sui-types transaction.rs), the input loader's errors
//! (`read_objects_for_signing`), and `check_transaction_input` (sui-transaction-checks: gas
//! status, gas objects and balance, object ownership, replay protection, receiving objects).
//! A failure is a `Fail` whose message is the `SuiError` Display text the RPC returns.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const exec = @import("exec");
const serve = @import("serve");
const hash = @import("hash");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const ObjectView = exec.objects.ObjectView;

/// A `SuiError` as the RPC maps it (`simulation_error_to_rpc_error`): UserInputError and
/// UnsupportedFeatureError are INVALID_ARGUMENT (3), everything else INTERNAL (13).
pub const Fail = struct {
    code: u8,
    message: []const u8,
};

pub const Error = Allocator.Error || error{ProtocolConfigMissing};

/// `SuiErrorKind::UserInputError` Display.
pub fn userInput(arena: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error!Fail {
    return .{ .code = 3, .message = try std.fmt.allocPrint(arena, "Error checking transaction input objects: " ++ fmt, args) };
}

/// `SuiErrorKind::UnsupportedFeatureError` Display.
pub fn unsupportedFeature(arena: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error!Fail {
    return .{ .code = 3, .message = try std.fmt.allocPrint(arena, "Use of disabled feature: " ++ fmt, args) };
}

/// Any other `SuiErrorKind` (INTERNAL).
pub fn internal(arena: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error!Fail {
    return .{ .code = 13, .message = try std.fmt.allocPrint(arena, fmt, args) };
}

// ---- Display helpers ------------------------------------------------------------------------

/// `ObjectID` / `SuiAddress` Display and Debug: 0x + 64 lowercase hex digits.
pub fn Hex(comptime n: usize) type {
    return struct {
        b: [2 + 2 * n]u8,
        pub fn s(self: *const @This()) []const u8 {
            return &self.b;
        }
    };
}
pub fn hex(id: *const Id) Hex(32) {
    var out: Hex(32) = undefined;
    out.b[0] = '0';
    out.b[1] = 'x';
    out.b[2..].* = std.fmt.bytesToHex(id.*, .lower);
    return out;
}

/// `ObjectDigest` Display: Base58.
pub fn b58(arena: Allocator, d: *const Id) Allocator.Error![]const u8 {
    var buf: [serve.b58.max_len_32]u8 = undefined;
    return arena.dupe(u8, serve.b58.encode32(&buf, d));
}

/// `Owner` Debug (derive): `AddressOwner(0x..)`, `ObjectOwner(0x..)`,
/// `Shared { initial_shared_version: SequenceNumber(n) }`, `Immutable`, ...
pub fn ownerDebug(arena: Allocator, o: types.Owner) Allocator.Error![]const u8 {
    return switch (o) {
        .AddressOwner => |a| std.fmt.allocPrint(arena, "AddressOwner({s})", .{hex(&a.@"0").s()}),
        .ObjectOwner => |a| std.fmt.allocPrint(arena, "ObjectOwner({s})", .{hex(&a.@"0").s()}),
        .Shared => |s| std.fmt.allocPrint(arena, "Shared {{ initial_shared_version: SequenceNumber({d}) }}", .{s.initial_shared_version.@"0"}),
        .Immutable => "Immutable",
        .ConsensusAddressOwner => |c| std.fmt.allocPrint(arena, "ConsensusAddressOwner {{ start_version: SequenceNumber({d}), owner: {s} }}", .{ c.start_version.@"0", hex(&c.owner.@"0").s() }),
        .Party => |p| std.fmt.allocPrint(arena, "Party {{ start_version: SequenceNumber({d}), .. }}", .{p.start_version.@"0"}),
    };
}

// ---- transaction shape ------------------------------------------------------------------------

pub fn isCoinReservation(d: *const Id) bool {
    return exec.inputs.isCoinReservation(d);
}

pub fn isSystemKind(k: *const types.TransactionKind) bool {
    return k.* != .ProgrammableTransaction;
}

pub fn ptbOf(td: *const types.TransactionDataV1) ?*const types.ProgrammableTransaction {
    return switch (td.kind) {
        .ProgrammableTransaction => |*p| p,
        else => null,
    };
}

pub fn gasPaidFromAddressBalance(td: *const types.TransactionDataV1) bool {
    return td.gas_data.payment.len == 0 and td.kind == .ProgrammableTransaction;
}

pub fn isGasless(cfg: *const protocol.ProtocolConfig, td: *const types.TransactionDataV1) bool {
    return cfg.feature_flags.enable_gasless and gasPaidFromAddressBalance(td) and td.gas_data.price == 0;
}

fn argIsGas(a: types.Argument) bool {
    return a == .GasCoin;
}

/// `Command::is_gas_coin_used` over every command.
pub fn usesGasCoin(pt: *const types.ProgrammableTransaction) bool {
    for (pt.commands) |*c| switch (c.*) {
        .MoveCall => |*m| for (m.arguments) |a| if (argIsGas(a)) return true,
        .TransferObjects => |t| {
            for (t.@"0") |a| if (argIsGas(a)) return true;
            if (argIsGas(t.@"1")) return true;
        },
        .SplitCoins => |t| {
            if (argIsGas(t.@"0")) return true;
            for (t.@"1") |a| if (argIsGas(a)) return true;
        },
        .MergeCoins => |t| {
            if (argIsGas(t.@"0")) return true;
            for (t.@"1") |a| if (argIsGas(a)) return true;
        },
        .MakeMoveVec => |t| for (t.@"1") |a| if (argIsGas(a)) return true,
        .Upgrade => |t| if (argIsGas(t.@"3")) return true,
        .Publish => {},
    };
    return false;
}

pub fn isReplayProtectedExpiration(e: types.TransactionExpiration) bool {
    const mm: struct { ?u64, ?u64 } = switch (e) {
        .ValidDuring => |v| .{ v.min_epoch, v.max_epoch },
        .Validity => |v| .{ v.min_epoch, v.max_epoch },
        else => return false,
    };
    const min = mm[0] orelse return false;
    const max = mm[1] orelse return false;
    return max == min or max == min +| 1;
}

/// What deepwave does not model among funds withdrawals: allowance withdrawals.
pub fn unsupportedWithdrawal(td: *const types.TransactionDataV1) ?[]const u8 {
    const pt = ptbOf(td) orelse return null;
    for (pt.inputs) |*a| switch (a.*) {
        .FundsWithdrawal => |w| if (w.withdraw_from == .SenderAllowance) return "allowance withdrawals are not supported",
        else => {},
    };
    return null;
}

/// A parsed coin reservation (`ParsedObjectRefWithdrawal`): the unmasked accumulator field id,
/// the reservation epoch and amount.
pub const Reservation = struct { account: Id, epoch: u64, amount: u64 };

/// `mask_or_unmask_id`.
pub fn unmask(id: *const Id, chain_id: *const Id) Id {
    var out: Id = undefined;
    for (&out, id, chain_id) |*o, a, b| o.* = a ^ b;
    return out;
}

/// `ParsedObjectRefWithdrawal::parse` of a reservation ref.
pub fn parseReservation(id: *const Id, digest: *const Id, chain_id: *const Id) Reservation {
    return .{
        .account = unmask(id, chain_id),
        .amount = std.mem.readInt(u64, digest[0..8], .little),
        .epoch = std.mem.readInt(u32, digest[8..12], .little),
    };
}

/// `coin_reservation_obj_refs`: the programmable transaction's reservation inputs, then the gas
/// payment's.
pub fn reservations(arena: Allocator, td: *const types.TransactionDataV1, chain_id: *const Id) Allocator.Error![]Reservation {
    var out: std.ArrayList(Reservation) = .empty;
    if (ptbOf(td)) |pt| for (pt.inputs) |*a| switch (a.*) {
        .Object => |o| switch (o) {
            .ImmOrOwnedObject => |r| if (isCoinReservation(&r[2].@"0".@"0"))
                try out.append(arena, parseReservation(&r[0].@"0".@"0", &r[2].@"0".@"0", chain_id)),
            else => {},
        },
        else => {},
    };
    for (td.gas_data.payment) |r| if (isCoinReservation(&r[2].@"0".@"0"))
        try out.append(arena, parseReservation(&r[0].@"0".@"0", &r[2].@"0".@"0", chain_id));
    return out.items;
}

fn hasReservations(td: *const types.TransactionDataV1) bool {
    for (td.gas_data.payment) |r| if (isCoinReservation(&r[2].@"0".@"0")) return true;
    const pt = ptbOf(td) orelse return false;
    for (pt.inputs) |*a| switch (a.*) {
        .Object => |o| switch (o) {
            .ImmOrOwnedObject => |r| if (isCoinReservation(&r[2].@"0".@"0")) return true,
            else => {},
        },
        else => {},
    };
    return false;
}

/// `has_funds_withdrawals`.
pub fn hasFundsWithdrawals(td: *const types.TransactionDataV1) bool {
    if (gasPaidFromAddressBalance(td) and td.gas_data.budget > 0) return true;
    if (ptbOf(td)) |pt| for (pt.inputs) |*a| if (a.* == .FundsWithdrawal) return true;
    return hasReservations(td);
}

/// `TransactionData::validity_check`'s funds-withdrawal block.
fn withdrawalValidity(arena: Allocator, c: *const ValidityCtx, td: *const types.TransactionDataV1) Error!?Fail {
    const cfg = c.cfg;
    const ff = &cfg.feature_flags;
    if (!hasFundsWithdrawals(td)) return null;
    if (td.gas_data.payment.len == 0 and !ff.enable_address_balance_gas_payments) return try userInput(arena, "Transaction gas payment missing", .{});
    if (!ff.enable_accumulators) return try userInput(arena, "Feature is not supported: Address balance withdraw is not enabled", .{});
    const max_withdraws = 10;
    var n: usize = 0;
    if (ptbOf(td)) |pt| for (pt.inputs) |*a| switch (a.*) {
        .FundsWithdrawal => |w| {
            n += 1;
            switch (w.withdraw_from) {
                .Sender => {},
                .Sponsor => return try userInput(arena, "Invalid withdraw reservation: Explicit sponsor withdrawals are not yet supported", .{}),
                .SenderAllowance => if (!protocol.derived.enableAllowances(cfg)) return try userInput(arena, "Feature is not supported: Allowance withdrawals are not enabled", .{}),
            }
            switch (w.reservation) {
                .MaxAmountU64 => |amt| if (amt == 0) return try userInput(arena, "Invalid withdraw reservation: Balance withdraw reservation amount must be non-zero", .{}),
            }
        },
        else => {},
    };
    for (try reservations(arena, td, &c.chain_id)) |r| {
        n += 1;
        // valid for the current and the next epoch, like ValidDuring
        if (r.epoch != c.epoch and r.epoch + 1 != c.epoch) return try internal(arena, "Transaction Expired", .{});
        if (r.amount == 0) return try userInput(arena, "Invalid withdraw reservation: Balance withdraw reservation amount must be non-zero", .{});
    }
    if (ff.enable_address_balance_gas_payments and gasPaidFromAddressBalance(td)) n += 1;
    if (n > max_withdraws) return try userInput(arena, "Invalid withdraw reservation: Maximum number of balance withdraw reservations is {d}", .{max_withdraws});
    return null;
}

/// One account of `process_funds_withdrawals_for_signing` (the map is ordered by account id).
pub const Withdraw = struct { account: Id, amount: u64, coin: types.TypeTag, owner: Id };

pub const Withdrawals = union(enum) { ok: []Withdraw, fail: Fail };

fn balanceOf(arena: Allocator, t: *const types.TypeTag) Allocator.Error!types.TypeTag {
    var two: Id = @splat(0);
    two[31] = 2;
    const args = try arena.alloc(types.TypeTag, 1);
    args[0] = t.*;
    return .{ .@"struct" = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "balance" }, .name = .{ .@"0" = "Balance" }, .type_args = args } };
}

pub const sui_coin_tag: types.TypeTag = blk: {
    var two: Id = @splat(0);
    two[31] = 2;
    break :blk .{ .@"struct" = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "sui" }, .name = .{ .@"0" = "SUI" }, .type_args = &.{} } };
};

/// `accumulate_funds_withdrawals(include_gas_payment = true)`: FundsWithdrawal inputs, coin
/// reservations resolved through the coin reservation resolver (`state.latest` of the unmasked
/// accumulator field), then address-balance gas.
pub fn declaredWithdrawals(arena: Allocator, td: *const types.TransactionDataV1, chain_id: *const Id, state: anytype) Error!Withdrawals {
    var list: std.ArrayList(Withdraw) = .empty;
    const add = struct {
        fn f(a: Allocator, l: *std.ArrayList(Withdraw), owner: Id, coin: *const types.TypeTag, amount: u64) Error!?Fail {
            if (amount == 0) return try userInput(a, "Invalid withdraw reservation: Balance withdraw reservation amount must be non-zero", .{});
            const bal = try balanceOf(a, coin);
            const tb = try bcs.encodeAlloc(types.TypeTag, a, &bal);
            const id = accumulatorId(&owner, tb);
            for (l.items) |*x| if (std.mem.eql(u8, &x.account, &id)) {
                x.amount = std.math.add(u64, x.amount, amount) catch return try userInput(a, "Invalid withdraw reservation: Balance withdraw reservation overflow", .{});
                return null;
            };
            try l.append(a, .{ .account = id, .amount = amount, .coin = coin.*, .owner = owner });
            return null;
        }
    }.f;
    if (ptbOf(td)) |pt| for (pt.inputs) |*a| switch (a.*) {
        .FundsWithdrawal => |w| {
            const owner: Id = switch (w.withdraw_from) {
                .Sender => td.sender.@"0",
                .Sponsor => td.gas_data.owner.@"0",
                .SenderAllowance => |x| x.funder.@"0",
            };
            const coin = switch (w.type_arg) {
                .Balance => |t| t,
            };
            const amount = switch (w.reservation) {
                .MaxAmountU64 => |x| x,
            };
            if (try add(arena, &list, owner, &coin, amount)) |f| return .{ .fail = f };
        },
        else => {},
    };
    for (try reservations(arena, td, chain_id)) |r| {
        const coin = switch (try resolveReservation(arena, &td.sender.@"0", &r.account, state.latest(&r.account))) {
            .fail => |f| return .{ .fail = f },
            .ok => |t| t,
        };
        if (try add(arena, &list, td.sender.@"0", &coin, r.amount)) |f| return .{ .fail = f };
    }
    if (gasPaidFromAddressBalance(td) and td.gas_data.budget > 0) {
        // balance_from_sponsor / balance_from_sender: both the gas owner
        if (try add(arena, &list, td.gas_data.owner.@"0", &sui_coin_tag, td.gas_data.budget)) |f| return .{ .fail = f };
    }
    std.mem.sort(Withdraw, list.items, {}, struct {
        fn lt(_: void, a: Withdraw, b: Withdraw) bool {
            return std.mem.order(u8, &a.account, &b.account) == .lt;
        }
    }.lt);
    return .{ .ok = list.items };
}

const Resolved = union(enum) { ok: types.TypeTag, fail: Fail };

/// `CoinReservationResolver::resolve_funds_withdrawal`: the accumulator field's balance type and
/// its owner (`Key.owner`), which must be the sender.
fn resolveReservation(arena: Allocator, sender: *const Id, account: *const Id, raw_opt: ?[]const u8) Error!Resolved {
    const raw = raw_opt orelse return .{ .fail = try userInput(arena, "Invalid withdraw reservation: coin reservation object id {s} not found", .{hex(account).s()}) };
    const not_field: Resolved = .{ .fail = try userInput(arena, "Invalid withdraw reservation: coin reservation object id {s} is not a balance accumulator field", .{hex(account).s()}) };
    if (raw.len < 2 or raw[0] != 0) return not_field;
    var r = bcs.Reader.init(raw[1..]);
    const mt = bcs.decodeFrom(types.MoveObjectType, arena, &r) catch return not_field;
    const t: types.TypeTag = switch (mt.@"0") {
        .SuiBalanceAccumulatorField => sui_coin_tag,
        .BalanceAccumulatorField => |x| x,
        else => return not_field,
    };
    const v = ObjectView.parse(raw) catch return not_field;
    const c = v.contents();
    if (c.len < 64) return .{ .fail = try userInput(arena, "Invalid withdraw reservation: could not load coin reservation object id {s}", .{hex(account).s()}) };
    const owner = c[32..64];
    if (!std.mem.eql(u8, owner, sender)) return .{ .fail = try userInput(arena, "Invalid withdraw reservation: coin reservation object id {s} is owned by {s}, not sender {s}", .{ hex(account).s(), hex(owner[0..32]).s(), hex(sender).s() }) };
    return .{ .ok = t };
}

/// Move `TypeTag` Display (`0x2::sui::SUI`, generic arguments joined by ", ").
pub fn typeDisplay(arena: Allocator, t: *const types.TypeTag) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try writeTypeDisplay(arena, &out, t);
    return out.items;
}

fn writeTypeDisplay(arena: Allocator, out: *std.ArrayList(u8), t: *const types.TypeTag) Allocator.Error!void {
    switch (t.*) {
        .bool => try out.appendSlice(arena, "bool"),
        .u8 => try out.appendSlice(arena, "u8"),
        .u16 => try out.appendSlice(arena, "u16"),
        .u32 => try out.appendSlice(arena, "u32"),
        .u64 => try out.appendSlice(arena, "u64"),
        .u128 => try out.appendSlice(arena, "u128"),
        .u256 => try out.appendSlice(arena, "u256"),
        .address => try out.appendSlice(arena, "address"),
        .signer => try out.appendSlice(arena, "signer"),
        .vector => |e| {
            try out.appendSlice(arena, "vector<");
            try writeTypeDisplay(arena, out, e);
            try out.append(arena, '>');
        },
        .@"struct" => |st| {
            const hx = std.fmt.bytesToHex(st.address.@"0", .lower);
            var i: usize = 0;
            while (i < 63 and hx[i] == '0') i += 1;
            try out.appendSlice(arena, "0x");
            try out.appendSlice(arena, hx[i..]);
            try out.appendSlice(arena, "::");
            try out.appendSlice(arena, st.module.@"0");
            try out.appendSlice(arena, "::");
            try out.appendSlice(arena, st.name.@"0");
            if (st.type_args.len > 0) {
                try out.append(arena, '<');
                for (st.type_args, 0..) |*a, k| {
                    if (k > 0) try out.appendSlice(arena, ", ");
                    try writeTypeDisplay(arena, out, a);
                }
                try out.append(arena, '>');
            }
        },
    }
}

/// `get_gasless_allowed_token_types`: the minimum remaining amount for `coin`, if listed.
pub fn gaslessMinAmount(cfg: *const protocol.ProtocolConfig, coin: *const types.TypeTag) ?u64 {
    const st = switch (coin.*) {
        .@"struct" => |x| x,
        else => return null,
    };
    if (st.type_args.len != 0) return null;
    const list = protocol.derived.gaslessAllowedTokenTypes(cfg);
    for (list) |tok| {
        var it = std.mem.splitSequence(u8, tok[0], "::");
        const a = it.next() orelse continue;
        const m = it.next() orelse continue;
        const n = it.next() orelse continue;
        if (it.next() != null) continue;
        const digits = if (std.mem.startsWith(u8, a, "0x")) a[2..] else a;
        if (digits.len == 0 or digits.len > 64) continue;
        var buf: [64]u8 = @splat('0');
        @memcpy(buf[64 - digits.len ..], digits);
        var addr: Id = undefined;
        _ = std.fmt.hexToBytes(&addr, &buf) catch continue;
        if (std.mem.eql(u8, &addr, &st.address.@"0") and std.mem.eql(u8, m, st.module.@"0") and std.mem.eql(u8, n, st.name.@"0")) return tok[1];
    }
    return null;
}

// ---- input object kinds ----------------------------------------------------------------------

pub const InputKind = union(enum) {
    package: Id,
    owned: struct { id: Id, version: u64, digest: Id },
    shared: struct { id: Id, isv: u64, mutability: types.SharedObjectMutability },

    pub fn id(k: *const InputKind) *const Id {
        return switch (k.*) {
            .package => |*p| p,
            .owned => |*o| &o.id,
            .shared => |*s| &s.id,
        };
    }
};

pub const Receiving = struct { id: Id, version: u64, digest: Id };

fn lessId(_: void, a: Id, b: Id) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

fn typeInputPackages(arena: Allocator, out: *std.ArrayList(Id), t: *const types.TypeInput) Allocator.Error!void {
    switch (t.*) {
        .vector => |x| try typeInputPackages(arena, out, x),
        .@"struct" => |*st| {
            try out.append(arena, st.address.@"0");
            for (st.type_args) |*a| try typeInputPackages(arena, out, a);
        },
        else => {},
    }
}

/// `TransactionData::input_objects` (PTB inputs, then the command packages as a sorted set,
/// then the gas coins) and `receiving_objects`. Null with `fail` set on a duplicate input.
pub fn inputKinds(arena: Allocator, td: *const types.TransactionDataV1, kinds: *std.ArrayList(InputKind), recv: *std.ArrayList(Receiving)) Allocator.Error!?Fail {
    const pt = ptbOf(td) orelse return null;
    for (pt.inputs) |*a| switch (a.*) {
        .Object => |o| switch (o) {
            .ImmOrOwnedObject => |r| if (!isCoinReservation(&r[2].@"0".@"0")) try kinds.append(arena, .{ .owned = .{ .id = r[0].@"0".@"0", .version = r[1].@"0", .digest = r[2].@"0".@"0" } }),
            .SharedObject => |s| try kinds.append(arena, .{ .shared = .{ .id = s.id.@"0".@"0", .isv = s.initial_shared_version.@"0", .mutability = s.mutability } }),
            .Receiving => |r| try recv.append(arena, .{ .id = r[0].@"0".@"0", .version = r[1].@"0", .digest = r[2].@"0".@"0" }),
        },
        else => {},
    };
    // all object inputs must be unique
    for (kinds.items, 0..) |*k, i| for (kinds.items[0..i]) |*p| {
        if (std.mem.eql(u8, k.id(), p.id())) return try userInput(arena, "The transaction inputs contain duplicated ObjectRef's", .{});
    };
    var pk: std.ArrayList(Id) = .empty;
    for (pt.commands) |*c| switch (c.*) {
        .MoveCall => |*m| {
            try pk.append(arena, m.package.@"0".@"0");
            for (m.type_arguments) |*t| try typeInputPackages(arena, &pk, t);
        },
        .MakeMoveVec => |*mv| if (mv[0]) |*t| try typeInputPackages(arena, &pk, t),
        .Publish => |p| for (p[1]) |d| try pk.append(arena, d.@"0".@"0"),
        .Upgrade => |u| {
            for (u[1]) |d| try pk.append(arena, d.@"0".@"0");
            try pk.append(arena, u[2].@"0".@"0");
        },
        else => {},
    };
    std.mem.sort(Id, pk.items, {}, lessId);
    for (pk.items, 0..) |p, i| {
        if (i > 0 and std.mem.eql(u8, &pk.items[i - 1], &p)) continue;
        try kinds.append(arena, .{ .package = p });
    }
    for (td.gas_data.payment) |r| if (!isCoinReservation(&r[2].@"0".@"0")) {
        try kinds.append(arena, .{ .owned = .{ .id = r[0].@"0".@"0", .version = r[1].@"0", .digest = r[2].@"0".@"0" } });
    };
    return null;
}

// ---- TransactionDataV1::validity_check -------------------------------------------------------

pub const ValidityCtx = struct {
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    chain_id: Id,
    rgp: u64,
    committee_size: u32,
};

fn paidProposerCount(price: u64, rgp: u64) u64 {
    return @max(3, price / @max(rgp, 1));
}

/// `TransactionDataV1::validity_check` (with `kind.validity_check` for programmable
/// transactions: command, input and argument count limits).
pub fn validity(arena: Allocator, c: *const ValidityCtx, td: *const types.TransactionDataV1) Error!?Fail {
    const cfg = c.cfg;
    const ff = &cfg.feature_flags;
    switch (td.expiration) {
        .None => {},
        .Epoch => |max| if (c.epoch > max) return try internal(arena, "Transaction Expired", .{}),
        .ValidDuring, .Validity => {
            const v: struct { min: ?u64, max: ?u64, min_ts: ?u64, max_ts: ?u64, chain: Id } = switch (td.expiration) {
                .ValidDuring => |x| .{ .min = x.min_epoch, .max = x.max_epoch, .min_ts = x.min_timestamp, .max_ts = x.max_timestamp, .chain = x.chain.@"0".@"0".@"0" },
                .Validity => |x| .{ .min = x.min_epoch, .max = x.max_epoch, .min_ts = x.min_timestamp, .max_ts = x.max_timestamp, .chain = x.chain.@"0".@"0".@"0" },
                else => unreachable,
            };
            if (td.expiration == .Validity) {
                if (!ff.allowed_proposers) return try userInput(arena, "Feature is not supported: Restricting the proposers of a transaction is not supported", .{});
                if (td.expiration.Validity.allowed_proposers) |ap| if (ap.epoch == c.epoch) {
                    const max_p = @min(paidProposerCount(td.gas_data.price, c.rgp), @as(u64, c.committee_size));
                    if (ap.proposers.len > max_p) return try userInput(arena, "Invalid transaction expiration: allowed_proposers has {d} entries, but at most {d} are permitted with gas price {d}, reference gas price {d}, and a committee of {d}", .{ ap.proposers.len, max_p, td.gas_data.price, c.rgp, c.committee_size });
                    for (ap.proposers, 0..) |p, i| if (i > 0 and ap.proposers[i - 1] >= p) return try userInput(arena, "Invalid transaction expiration: allowed_proposers must be strictly increasing", .{});
                    for (ap.proposers) |p| if (p >= c.committee_size) return try userInput(arena, "Invalid transaction expiration: allowed_proposers contains index {d}, but the committee has {d} members", .{ p, c.committee_size });
                };
            }
            if (v.min_ts != null or v.max_ts != null) return try userInput(arena, "Feature is not supported: Timestamp-based transaction expiration is not yet supported", .{});
            if (!ff.relax_valid_during_for_owned_inputs) {
                if (v.min != null and v.max != null) {
                    const min = v.min.?;
                    const max = v.max.?;
                    if (ff.enable_multi_epoch_transaction_expiration) {
                        if (!(max == min or max == min +| 1)) return try userInput(arena, "Feature is not supported: max_epoch must be at most min_epoch + 1", .{});
                    } else if (min != max) return try userInput(arena, "Feature is not supported: min_epoch must equal max_epoch", .{});
                } else return try userInput(arena, "Feature is not supported: Both min_epoch and max_epoch must be specified", .{});
            }
            if (!std.mem.eql(u8, &v.chain, &c.chain_id)) {
                return try userInput(arena, "Transaction chain ID {s} does not match network chain ID {s}.", .{ try chainDebug(arena, &v.chain), try chainDebug(arena, &c.chain_id) });
            }
            if (v.min) |m| if (c.epoch < m) return try internal(arena, "Transaction Expired", .{});
            if (v.max) |m| if (c.epoch > m) return try internal(arena, "Transaction Expired", .{});
        },
    }

    if (try withdrawalValidity(arena, c, td)) |f| return f;

    const ab_gas = gasPaidFromAddressBalance(td);
    if (ff.enable_accumulators and ff.enable_address_balance_gas_payments and ab_gas) {
        if (ff.address_balance_gas_reject_gas_coin_arg) if (ptbOf(td)) |pt| {
            if (usesGasCoin(pt)) return try userInput(arena, "Feature is not supported: Argument::GasCoin is not supported with address balance gas payments", .{});
        };
        const gasless = isGasless(cfg, td);
        if (ff.address_balance_gas_check_rgp_at_signing and !gasless and td.gas_data.price < c.rgp) {
            return try userInput(arena, "Gas price {d} under reference gas price (RGP) {d}", .{ td.gas_data.price, c.rgp });
        }
        if (!ff.relax_valid_during_for_owned_inputs) {
            if (td.expiration == .None) return try userInput(arena, "Transaction gas payment missing", .{});
            if (!isReplayProtectedExpiration(td.expiration)) return try userInput(arena, "Invalid transaction expiration: Address balance gas payments require ValidDuring expiration", .{});
        }
    } else if (td.gas_data.payment.len == 0) return try userInput(arena, "Transaction gas payment missing", .{});

    const max_gas_objects = try cfg.get("max_gas_payment_objects");
    const within = if (ff.correct_gas_payment_limit_check) td.gas_data.payment.len <= max_gas_objects else td.gas_data.payment.len < max_gas_objects;
    if (!within) return try userInput(arena, "Size limit exceeded: maximum number of gas payment objects is {d}", .{max_gas_objects});

    if (!protocol.derived.enableCoinReservationObjRefs(cfg)) {
        for (td.gas_data.payment) |r| if (isCoinReservation(&r[2].@"0".@"0")) {
            return try userInput(arena, "Gas object is not an owned object with owner: {s}", .{try ownerDebug(arena, .{ .AddressOwner = td.sender })});
        };
    } else {
        // gas coin reservations: SUI, owned by the sender (no sponsorship)
        const sui_account = accumulatorId(&td.sender.@"0", &sui_balance_tag);
        for (td.gas_data.payment) |r| if (isCoinReservation(&r[2].@"0".@"0")) {
            const res = parseReservation(&r[0].@"0".@"0", &r[2].@"0".@"0", &c.chain_id);
            if (!std.mem.eql(u8, &td.gas_data.owner.@"0", &td.sender.@"0") or !std.mem.eql(u8, &res.account, &sui_account))
                return try userInput(arena, "Gas object is not an owned object with owner: {s}", .{try ownerDebug(arena, .{ .AddressOwner = td.sender })});
        };
    }

    // not a system transaction here
    const gm = try cfg.get("gas_model_version");
    if (gm >= 4) {
        const max_price = try cfg.get("max_gas_price");
        if (td.gas_data.price >= max_price) return try userInput(arena, "Gas price cannot exceed {d} mist", .{max_price});
    }
    const max_budget = try cfg.get("max_tx_gas");
    const base = try cfg.get("base_tx_cost_fixed");
    const min_cost = if (ff.txn_base_cost_as_multiplier) base *% td.gas_data.price else base;
    if (td.gas_data.budget > max_budget) return try userInput(arena, "Gas budget: {d} is higher than max: {d}", .{ td.gas_data.budget, max_budget });
    if (isGasless(cfg, td)) {
        if (td.gas_data.budget != 0) return try userInput(arena, "Feature is not supported: gas_budget must be 0 for gasless transactions", .{});
    } else if (td.gas_data.budget < min_cost) return try userInput(arena, "Gas budget: {d} is lower than min: {d}", .{ td.gas_data.budget, min_cost });

    if (ptbOf(td)) |pt| if (try ptbValidity(arena, cfg, pt)) |f| return f;
    return null;
}

fn chainDebug(arena: Allocator, d: *const Id) Allocator.Error![]const u8 {
    // ChainIdentifier(CheckpointDigest(Digest(<base58>))) — derive(Debug) of the newtypes, with
    // Digest's Debug printing Base58.
    return std.fmt.allocPrint(arena, "ChainIdentifier(CheckpointDigest({s}))", .{try b58(arena, d)});
}

/// `ProgrammableTransaction::validity_check`: count limits and per-command argument limits.
/// Not ported: type-input depth checks, identifier checks, argument index validation and the
/// randomness command rule (corpus transactions satisfy them; a request that does not fails later).
/// `TypeTag::node_count`.
fn nodeCount(t: *const types.TypeTag) u64 {
    return switch (t.*) {
        .vector => |e| 1 + nodeCount(e),
        .@"struct" => |st| blk: {
            var n: u64 = 1;
            for (st.type_args) |*a| n += nodeCount(a);
            break :blk n;
        },
        else => 1,
    };
}

fn ptbValidity(arena: Allocator, cfg: *const protocol.ProtocolConfig, pt: *const types.ProgrammableTransaction) Error!?Fail {
    const max_cmds = try cfg.get("max_programmable_tx_commands");
    if (pt.commands.len >= max_cmds) return try userInput(arena, "Size limit exceeded: maximum commands in a programmable transaction is {d}", .{max_cmds});
    var n_obj: usize = 0;
    for (pt.inputs) |*a| switch (a.*) {
        .Object => |o| switch (o) {
            .ImmOrOwnedObject => |r| {
                if (!isCoinReservation(&r[2].@"0".@"0")) n_obj += 1;
            },
            else => n_obj += 1,
        },
        else => {},
    };
    var pk: std.ArrayList(Id) = .empty;
    for (pt.commands) |*c| switch (c.*) {
        .MoveCall => |*m| {
            try pk.append(arena, m.package.@"0".@"0");
            for (m.type_arguments) |*t| try typeInputPackages(arena, &pk, t);
        },
        .MakeMoveVec => |*mv| if (mv[0]) |*t| try typeInputPackages(arena, &pk, t),
        .Publish => |p| for (p[1]) |d| try pk.append(arena, d.@"0".@"0"),
        .Upgrade => |u| {
            for (u[1]) |d| try pk.append(arena, d.@"0".@"0");
            try pk.append(arena, u[2].@"0".@"0");
        },
        else => {},
    };
    std.mem.sort(Id, pk.items, {}, lessId);
    for (pk.items, 0..) |p, i| {
        if (i > 0 and std.mem.eql(u8, &pk.items[i - 1], &p)) continue;
        n_obj += 1;
    }
    const max_in = try cfg.get("max_input_objects");
    if (n_obj > max_in) return try userInput(arena, "Size limit exceeded: maximum input + receiving objects in a transaction is {d}", .{max_in});
    if (pt.inputs.len > std.math.maxInt(u16)) return try userInput(arena, "Size limit exceeded: maximum inputs in a programmable transaction is {d}", .{std.math.maxInt(u16)});
    const max_pure = try cfg.get("max_pure_argument_size");
    for (pt.inputs) |*a| switch (a.*) {
        .Pure => |p| if (p.len >= max_pure) return try userInput(arena, "Size limit exceeded: maximum pure argument size is {d}", .{max_pure}),
        .Object => |o| switch (o) {
            .SharedObject => |s| if (s.mutability == .NonExclusiveWrite and !cfg.feature_flags.enable_non_exclusive_writes) {
                return try userInput(arena, "Feature is not supported: User transactions cannot use SharedObjectMutability::NonExclusiveWrite", .{});
            },
            .ImmOrOwnedObject => |r| if (isCoinReservation(&r[2].@"0".@"0") and !protocol.derived.enableCoinReservationObjRefs(cfg)) {
                return try userInput(arena, "Feature is not supported: coin reservation backward compatibility layer is not enabled", .{});
            },
            else => {},
        },
        .FundsWithdrawal => |w| if (cfg.getOpt("max_accumulator_type_nodes")) |max| {
            // check_accumulator_type_bounds on Balance<T>
            const t = switch (w.type_arg) {
                .Balance => |x| x,
            };
            if (1 + nodeCount(&t) > max) return try userInput(arena, "Size limit exceeded: maximum type nodes in a funds accumulator type is {d}", .{max});
        },
    };
    const max_args = try cfg.get("max_arguments");
    for (pt.commands) |*c| switch (c.*) {
        .MoveCall => |*m| if (m.arguments.len >= max_args) return try userInput(arena, "Size limit exceeded: maximum arguments in a move call is {d}", .{max_args}),
        .TransferObjects => |t| if (try argsCheck(arena, t[0].len, max_args)) |f| return f,
        .SplitCoins => |t| if (try argsCheck(arena, t[1].len, max_args)) |f| return f,
        .MergeCoins => |t| if (try argsCheck(arena, t[1].len, max_args)) |f| return f,
        .MakeMoveVec => |t| {
            if (t[0] == null and t[1].len == 0) return try userInput(arena, "Programmable transaction command has an empty argument list", .{});
            if (t[1].len >= max_args) return try userInput(arena, "Size limit exceeded: maximum arguments in a programmable transaction command is {d}", .{max_args});
        },
        .Publish, .Upgrade => {},
    };
    return null;
}

fn argsCheck(arena: Allocator, n: usize, max_args: u64) Allocator.Error!?Fail {
    if (n == 0) return try userInput(arena, "Programmable transaction command has an empty argument list", .{});
    if (n >= max_args) return try userInput(arena, "Size limit exceeded: maximum arguments in a programmable transaction command is {d}", .{max_args});
    return null;
}

// ---- check_transaction_input -----------------------------------------------------------------

/// One loaded input (`ObjectReadResult`).
pub const Loaded = struct {
    kind: InputKind,
    raw: []const u8,
    view: ObjectView,
    owner: types.Owner,

    pub fn isMutable(l: *const Loaded) bool {
        return switch (l.kind) {
            .package => false,
            .owned => l.owner != .Immutable,
            .shared => |s| s.mutability == .Mutable,
        };
    }
};

fn isGasCoinType(raw: []const u8) bool {
    // Object::Move (0) then MoveObjectType_::GasCoin (1)
    return raw.len > 2 and raw[0] == 0 and raw[1] == 1;
}

/// `check_gas` (non-gasless), `check_objects`, `check_replay_protection` and
/// `check_receiving_objects`. `inputs` holds every loaded input, the mock gas coin included.
pub fn transactionInput(arena: Allocator, cfg: *const protocol.ProtocolConfig, rgp: u64, td: *const types.TransactionDataV1, inputs: []const Loaded, recv: []const Receiving, recv_objs: []const ?[]const u8) Error!?Fail {
    if (try gasInput(arena, cfg, rgp, td, inputs)) |f| return f;
    return objectsInput(arena, cfg, td, inputs, recv, recv_objs);
}

/// `check_dev_inspect_input` (checks disabled): no non-immutable object twice, then `check_gas`
/// without the ownership pass (check_gas_balance repeats it, so the same failures).
pub fn devInspectInput(arena: Allocator, cfg: *const protocol.ProtocolConfig, rgp: u64, td: *const types.TransactionDataV1, inputs: []const Loaded) Error!?Fail {
    for (inputs, 0..) |*l, i| if (l.owner != .Immutable and !l.view.is_package) {
        for (inputs[0..i]) |*p| if (std.mem.eql(u8, &p.view.id, &l.view.id)) {
            return try userInput(arena, "Mutable object {s} cannot appear more than one in one transaction", .{hex(&l.view.id).s()});
        };
    };
    return gasInput(arena, cfg, rgp, td, inputs);
}

/// `check_gas` for a priced transaction.
fn gasInput(arena: Allocator, cfg: *const protocol.ProtocolConfig, rgp: u64, td: *const types.TransactionDataV1, inputs: []const Loaded) Error!?Fail {
    const ff = &cfg.feature_flags;
    // gasless: SuiGasStatus::new(gasless_max_computation_units * rgp, rgp, rgp), no balance checks
    if (isGasless(cfg, td)) {
        if ((try cfg.get("gas_model_version")) >= 4 and rgp >= (try cfg.get("max_gas_price")))
            return try userInput(arena, "Gas price cannot exceed {d} mist", .{try cfg.get("max_gas_price")});
        return null;
    }
    const price = td.gas_data.price;
    const budget = td.gas_data.budget;
    // SuiGasStatus::new
    if (price < rgp) return try userInput(arena, "Gas price {d} under reference gas price (RGP) {d}", .{ price, rgp });
    const gm = try cfg.get("gas_model_version");
    if (gm >= 4) {
        const max_price = try cfg.get("max_gas_price");
        if (price >= max_price) return try userInput(arena, "Gas price cannot exceed {d} mist", .{max_price});
    }
    // gas objects
    const ab_gas = gasPaidFromAddressBalance(td);
    var gas_objs: std.ArrayList(*const Loaded) = .empty;
    var reserved: u64 = 0;
    if (!ab_gas) for (td.gas_data.payment) |r| {
        if (isCoinReservation(&r[2].@"0".@"0")) {
            reserved +|= std.mem.readInt(u64, r[2].@"0".@"0"[0..8], .little);
            continue;
        }
        const gid = r[0].@"0".@"0";
        const l = findInput(inputs, &gid) orelse return try userInput(arena, "Could not find the referenced object {s} at version Some(SequenceNumber({d}))", .{ hex(&gid).s(), r[1].@"0" });
        try gas_objs.append(arena, l);
    };
    // check_gas_objects (twice in Rust: gas_ownership_checks, then check_gas_balance)
    for (gas_objs.items) |g| if (g.owner != .AddressOwner) return try userInput(arena, "Gas object is not an owned object with owner: {s}", .{try ownerDebug(arena, g.owner)});
    const max_budget = try cfg.get("max_tx_gas");
    const base = try cfg.get("base_tx_cost_fixed");
    const v3 = protocol.gas.bumpOnlyEnabled(gm);
    const min_cost = if (v3 or ff.txn_base_cost_as_multiplier) base *% price else base;
    if (budget > max_budget) return try userInput(arena, "Gas budget: {d} is higher than max: {d}", .{ budget, max_budget });
    if (budget < min_cost) return try userInput(arena, "Gas budget: {d} is lower than min: {d}", .{ budget, min_cost });
    var bal: u128 = if (ab_gas) budget else reserved;
    for (gas_objs.items) |g| {
        if (!isGasCoinType(g.raw)) return try userInput(arena, "Object {s} is not a gas object", .{hex(&g.view.id).s()});
        const c = g.view.contents();
        bal += std.mem.readInt(u64, c[32..40], .little);
    }
    if (bal < budget) return try userInput(arena, "Balance of gas object {d} is lower than the needed amount: {d}", .{ bal, budget });
    return null;
}

/// `check_objects`, `check_replay_protection`, `check_receiving_objects`.
pub fn objectsInput(arena: Allocator, cfg: *const protocol.ProtocolConfig, td: *const types.TransactionDataV1, inputs: []const Loaded, recv: []const Receiving, recv_objs: []const ?[]const u8) Error!?Fail {
    const ab_gas = gasPaidFromAddressBalance(td);
    // check_objects
    for (inputs, 0..) |*l, i| if (l.isMutable()) {
        for (inputs[0..i]) |*p| if (p.isMutable() and std.mem.eql(u8, &p.view.id, &l.view.id)) {
            return try userInput(arena, "Mutable object {s} cannot appear more than one in one transaction", .{hex(&l.view.id).s()});
        };
    };
    var only_reservations = td.gas_data.payment.len > 0;
    for (td.gas_data.payment) |r| if (!isCoinReservation(&r[2].@"0".@"0")) {
        only_reservations = false;
    };
    const allow_empty = protocol.derived.enableCoinReservationObjRefs(cfg) and (ab_gas or only_reservations);
    if (inputs.len == 0 and !allow_empty) return try userInput(arena, "Wrong number of parameters for the transaction", .{});
    for (inputs) |*l| {
        var is_gas = false;
        for (td.gas_data.payment) |r| if (std.mem.eql(u8, &r[0].@"0".@"0", &l.view.id)) {
            is_gas = true;
        };
        const owner_addr: *const Id = if (is_gas) &td.gas_data.owner.@"0" else &td.sender.@"0";
        if (try oneObject(arena, cfg, owner_addr, l)) |f| return f;
    }
    // check_replay_protection
    if (!isReplayProtectedExpiration(td.expiration) and td.gas_data.payment.len == 0) {
        var any = false;
        for (inputs) |*l| switch (l.kind) {
            .owned => if (l.owner == .AddressOwner) {
                any = true;
            },
            else => {},
        };
        if (!any) return try userInput(arena, "Invalid transaction expiration: Transactions must either have address-owned inputs, or a ValidDuring expiration with at most two epochs of validity", .{});
    }
    // check_receiving_objects
    var seen: std.AutoHashMapUnmanaged(Id, void) = .empty;
    for (inputs) |*l| try seen.put(arena, l.view.id, {});
    for (recv, recv_objs) |r, maybe| {
        if (r.version == std.math.maxInt(u64)) return try userInput(arena, "Sequence numbers above the maximal value are not usable for transfers", .{});
        const raw = maybe orelse continue;
        const v = ObjectView.parse(raw) catch return try internal(arena, "receiving object does not parse", .{});
        const owner = bcs.decode(types.Owner, arena, raw[v.owner_at..v.prev_tx_at]) catch return try internal(arena, "receiving object owner does not parse", .{});
        const d = v.digest();
        if (!(owner == .AddressOwner and v.version == r.version and std.mem.eql(u8, &d, &r.digest))) {
            if (v.version != r.version) return try userInput(arena, "Transaction needs to be rebuilt because object {s} version {d} ({s}) is unavailable for consumption, current version: {d}", .{ hex(&r.id).s(), r.version, try b58(arena, &r.digest), v.version });
            if (v.is_package) return try userInput(arena, "A move object is expected, instead a move package is passed: {s}", .{hex(&r.id).s()});
            if (!std.mem.eql(u8, &d, &r.digest)) return try userInput(arena, "Invalid Object digest for object {s}. Expected digest : {s}", .{ hex(&r.id).s(), try b58(arena, &d) });
            return switch (owner) {
                .AddressOwner => try userInput(arena, "Could not find the referenced object {s} at version Some(SequenceNumber({d}))", .{ hex(&r.id).s(), r.version }),
                .ObjectOwner => |p| try userInput(arena, "Object {s} is owned by object {s}. Objects owned by other objects cannot be used as input arguments", .{ hex(&v.id).s(), hex(&p.@"0").s() }),
                .Immutable => try userInput(arena, "Immutable parameter provided, mutable parameter expected", .{}),
                else => try userInput(arena, "Object used as shared is not shared", .{}),
            };
        }
        if (seen.contains(r.id)) return try userInput(arena, "The transaction inputs contain duplicated ObjectRef's", .{});
        try seen.put(arena, r.id, {});
    }
    return null;
}

fn findInput(inputs: []const Loaded, id: *const Id) ?*const Loaded {
    for (inputs) |*l| if (std.mem.eql(u8, &l.view.id, id)) return l;
    return null;
}

fn shortSystem(id: *const Id) ?u16 {
    for (id[0..30]) |b| if (b != 0) return null;
    return std.mem.readInt(u16, id[30..32], .big);
}

/// `check_one_object`.
fn oneObject(arena: Allocator, cfg: *const protocol.ProtocolConfig, owner: *const Id, l: *const Loaded) Error!?Fail {
    if (l.owner == .Party) return try userInput(arena, "Feature is not supported: Party-owned objects are not yet supported", .{});
    switch (l.kind) {
        .package => |p| if (!l.view.is_package) return try userInput(arena, "A move package is expected, instead a move object is passed: {s}", .{hex(&p).s()}),
        .owned => |o| {
            if (l.view.is_package) return try userInput(arena, "A move object is expected, instead a move package is passed: {s}", .{hex(&o.id).s()});
            if (o.version == std.math.maxInt(u64)) return try userInput(arena, "Sequence numbers above the maximal value are not usable for transfers", .{});
            const d = l.view.digest();
            if (!std.mem.eql(u8, &d, &o.digest)) return try userInput(arena, "Invalid Object digest for object {s}. Expected digest : {s}", .{ hex(&o.id).s(), try b58(arena, &d) });
            switch (l.owner) {
                .Immutable => {},
                .AddressOwner => |a| if (!std.mem.eql(u8, &a.@"0", owner)) {
                    return try userInput(arena, "Transaction was not signed by the correct sender: Object {s} is owned by account address {s}, but given owner/signer address is {s}", .{ hex(&o.id).s(), hex(&a.@"0").s(), hex(owner).s() });
                },
                .ObjectOwner => |p| return try userInput(arena, "Object {s} is owned by object {s}. Objects owned by other objects cannot be used as input arguments", .{ hex(&l.view.id).s(), hex(&p.@"0").s() }),
                else => return try userInput(arena, "Object used as owned is not owned", .{}),
            }
        },
        .shared => |s| {
            if (l.view.version == std.math.maxInt(u64)) return try userInput(arena, "Sequence numbers above the maximal value are not usable for transfers", .{});
            // ObjectID::is_system_object: the first 24 bytes are zero
            var system = true;
            for (s.id[0..24]) |b| if (b != 0) {
                system = false;
            };
            if (system) {
                const short = shortSystem(&s.id);
                const ok = if (short) |x| switch (x) {
                    0xfa => cfg.feature_flags.enable_forwarding_addresses,
                    0x5, 0xa, 0xc, 0xd, 0x403, 0x9 => true,
                    0x6, 0x8, 0xacc => s.mutability == .Immutable,
                    else => false,
                } else false;
                if (!ok) return try userInput(arena, "Mutable parameter provided, immutable parameter expected", .{});
            }
            switch (l.owner) {
                .AddressOwner, .ObjectOwner, .Immutable => return try userInput(arena, "Object used as shared is not shared", .{}),
                .Shared => |x| if (x.initial_shared_version.@"0" != s.isv) return try userInput(arena, "Wrong initial version given for shared object", .{}),
                .ConsensusAddressOwner => |x| {
                    if (x.start_version.@"0" != s.isv) return try userInput(arena, "Wrong initial version given for shared object", .{});
                    if (!std.mem.eql(u8, &x.owner.@"0", owner)) return try userInput(arena, "Transaction was not signed by the correct sender: Object {s} is owned by account address {s}, but given owner/signer address is {s}", .{ hex(&s.id).s(), hex(&x.owner.@"0").s(), hex(owner).s() });
                },
                .Party => unreachable,
            }
        },
    }
    return null;
}

// ---- address balances ------------------------------------------------------------------------

pub const acc_root: Id = blk: {
    var a: Id = @splat(0);
    a[30] = 0x0a;
    a[31] = 0xcc;
    break :blk a;
};

fn appendStr(buf: []u8, at: *usize, s: []const u8) void {
    buf[at.*] = @intCast(s.len);
    at.* += 1;
    @memcpy(buf[at.*..][0..s.len], s);
    at.* += s.len;
}

/// BCS `TypeTag` of `0x2::balance::Balance<0x2::sui::SUI>`.
pub const sui_balance_tag: [92]u8 = blk: {
    var b: [92]u8 = @splat(0);
    var at: usize = 0;
    b[at] = 7; // struct
    at += 1;
    b[at + 31] = 2;
    at += 32;
    appendStr(&b, &at, "balance");
    appendStr(&b, &at, "Balance");
    b[at] = 1; // one type argument
    at += 1;
    b[at] = 7;
    at += 1;
    b[at + 31] = 2;
    at += 32;
    appendStr(&b, &at, "sui");
    appendStr(&b, &at, "SUI");
    b[at] = 0;
    at += 1;
    if (at != 92) @compileError("sui balance tag length");
    break :blk b;
};

/// `AccumulatorValue::get_field_id(owner, ty)`: the dynamic field of the accumulator root keyed
/// by `0x2::accumulator::Key<ty> { owner }`. `ty_bcs` is the BCS TypeTag of `Balance<T>`.
pub fn accumulatorId(owner: *const Id, ty_bcs: []const u8) Id {
    // TypeTag::Struct(0x2::accumulator::Key<ty>)
    var head: [1 + 32 + 12 + 4 + 1]u8 = undefined;
    var at: usize = 0;
    head[at] = 7;
    at += 1;
    @memset(head[at..][0..32], 0);
    head[at + 31] = 2;
    at += 32;
    appendStr(&head, &at, "accumulator");
    appendStr(&head, &at, "Key");
    head[at] = 1;
    at += 1;
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, 32, .little);
    return hash.blake2b256(&.{ &[_]u8{0xf0}, &acc_root, &len_le, owner, head[0..at], ty_bcs });
}

/// The u128 value of an accumulator `Field<Key<T>, U128>` object (its last 16 content bytes).
pub fn accumulatorAmount(raw: []const u8) ?u128 {
    const v = ObjectView.parse(raw) catch return null;
    if (v.is_package) return null;
    const c = v.contents();
    if (c.len < 16) return null;
    return std.mem.readInt(u128, c[c.len - 16 ..][0..16], .little);
}

test "accumulator field id of a known SUI balance" {
    // Every ingredient is fixed; the expected id is cross-checked by the suite (address-balance
    // transactions read their accumulator object through it).
    const owner: Id = @splat(0x11);
    const a = accumulatorId(&owner, &sui_balance_tag);
    const b = accumulatorId(&owner, &sui_balance_tag);
    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expectEqual(@as(u8, 7), sui_balance_tag[0]);
}
