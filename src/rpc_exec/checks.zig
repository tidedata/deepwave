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

/// One account's reservation in `process_funds_withdrawals_for_execution`.
pub const Reserve = struct { account: Id, amount: u64 };

/// `process_funds_withdrawals_for_execution`: the declared maximum per accumulator account
/// (FundsWithdrawal inputs, address-balance gas, then coin reservations by their unmasked id,
/// unresolved), summed per account in account order (the BTreeMap). Signing checked amounts
/// and overflow; a certified transaction is not checked again (saturating here).
pub fn executionWithdrawals(arena: Allocator, td: *const types.TransactionDataV1, chain_id: *const Id) Allocator.Error![]Reserve {
    var list: std.ArrayList(Reserve) = .empty;
    const add = struct {
        fn f(a: Allocator, l: *std.ArrayList(Reserve), id: Id, amount: u64) Allocator.Error!void {
            for (l.items) |*x| if (std.mem.eql(u8, &x.account, &id)) {
                x.amount +|= amount;
                return;
            };
            try l.append(a, .{ .account = id, .amount = amount });
        }
    }.f;
    const account = struct {
        fn f(a: Allocator, owner: *const Id, coin: *const types.TypeTag) Allocator.Error!Id {
            const bal = try balanceOf(a, coin);
            return accumulatorId(owner, try bcs.encodeAlloc(types.TypeTag, a, &bal));
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
            try add(arena, &list, try account(arena, &owner, &coin), amount);
        },
        else => {},
    };
    if (gasPaidFromAddressBalance(td) and td.gas_data.budget > 0) {
        // balance_from_sponsor / balance_from_sender: the gas owner either way
        try add(arena, &list, try account(arena, &td.gas_data.owner.@"0", &sui_coin_tag), td.gas_data.budget);
    }
    for (try reservations(arena, td, chain_id)) |r| try add(arena, &list, r.account, r.amount);
    std.mem.sort(Reserve, list.items, {}, struct {
        fn lt(_: void, a: Reserve, b: Reserve) bool {
            return std.mem.order(u8, &a.account, &b.account) == .lt;
        }
    }.lt);
    return list.items;
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
    return inputKindsOpt(arena, td, kinds, recv, true);
}

/// `inputKinds`; with `check_dups` false a duplicated input is kept (the caller runs
/// `validity_check`, which reports it at Rust's position).
pub fn inputKindsOpt(arena: Allocator, td: *const types.TransactionDataV1, kinds: *std.ArrayList(InputKind), recv: *std.ArrayList(Receiving), check_dups: bool) Allocator.Error!?Fail {
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
    if (check_dups) for (kinds.items, 0..) |*k, i| for (kinds.items[0..i]) |*p| {
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

    // kind.validity_check, then validate_gasless_transaction (check_sponsorship needs nothing:
    // every non-programmable kind was refused as a system transaction)
    if (ptbOf(td)) |pt| {
        if (try ptbValidity(arena, cfg, pt)) |f| return f;
        if (isGasless(cfg, td)) if (try gaslessValidity(arena, cfg, pt)) |f| return f;
    }
    return null;
}

fn chainDebug(arena: Allocator, d: *const Id) Allocator.Error![]const u8 {
    // ChainIdentifier(CheckpointDigest(Digest(<base58>))) — derive(Debug) of the newtypes, with
    // Digest's Debug printing Base58.
    return std.fmt.allocPrint(arena, "ChainIdentifier(CheckpointDigest({s}))", .{try b58(arena, d)});
}

// ---- ProgrammableTransaction::validity_check ------------------------------------------------
//
// Line for line with sui-types transaction.rs (mainnet-v1.83.1, identical at 1.84): the command
// count, the input object count (duplicates first), each input's `CallArg::validity_check`, the
// publish/upgrade count, each command's `Command::validity_check` in order (type inputs, argument
// counts, identifiers, modules and dependencies), argument indices, then the randomness rule.
// Golden vectors: src/validator/authority/testdata/validity.txt.zst (tools/truth/validity).

/// `move_core_types::identifier::is_valid`.
pub fn isValidIdentifier(s: []const u8) bool {
    if (s.len == 0) return false;
    const start: usize = switch (s[0]) {
        'a'...'z', 'A'...'Z' => 1,
        '_' => if (s.len > 1) 1 else return false,
        else => return false,
    };
    for (s[start..]) |c| switch (c) {
        '_', 'a'...'z', 'A'...'Z', '0'...'9' => {},
        else => return false,
    };
    return true;
}

fn sizeLimit(arena: Allocator, limit: []const u8, value: anytype) Allocator.Error!Fail {
    return userInput(arena, "Size limit exceeded: {s} is {d}", .{ limit, value });
}

fn invalidIdentifier(arena: Allocator, s: []const u8) Allocator.Error!Fail {
    return userInput(arena, "Invalid identifier found in the transaction: {s}", .{s});
}

const empty_command_input = "TransferObjects, MergeCoin, and Publish cannot have empty arguments. If MakeMoveVec has empty arguments, it must have a type specified";

/// `type_input_validity_check`: a depth-first walk with an explicit stack (children pushed in
/// order, so the last type parameter is visited first), counting every node into `count`.
fn typeInputValidity(arena: Allocator, cfg: *const protocol.ProtocolConfig, root: *const types.TypeInput, count: *u64) Error!?Fail {
    const max_args = try cfg.get("max_type_arguments");
    const max_depth = try cfg.get("max_type_argument_depth");
    const Item = struct { t: *const types.TypeInput, depth: u64 };
    var stack: std.ArrayList(Item) = .empty;
    try stack.append(arena, .{ .t = root, .depth = 1 });
    while (stack.pop()) |it| {
        count.* += 1;
        if (count.* >= max_args) return try sizeLimit(arena, "maximum type arguments in a call transaction", max_args);
        if (it.depth >= max_depth) return try sizeLimit(arena, "maximum type argument depth in a call transaction", max_depth);
        switch (it.t.*) {
            .vector => |inner| try stack.append(arena, .{ .t = inner, .depth = it.depth + 1 }),
            .@"struct" => |*st| {
                if (cfg.feature_flags.validate_identifier_inputs) {
                    if (!isValidIdentifier(st.module.@"0")) return try invalidIdentifier(arena, st.module.@"0");
                    if (!isValidIdentifier(st.name.@"0")) return try invalidIdentifier(arena, st.name.@"0");
                }
                for (st.type_args) |*a| try stack.append(arena, .{ .t = a, .depth = it.depth + 1 });
            },
            else => {},
        }
    }
    return null;
}

/// `Command::arguments`: the command's arguments in command-argument order.
fn commandArgs(arena: Allocator, c: *const types.Command) Allocator.Error![]const types.Argument {
    return switch (c.*) {
        .MoveCall => |*m| m.arguments,
        .TransferObjects => |t| blk: {
            const out = try arena.alloc(types.Argument, t[0].len + 1);
            @memcpy(out[0..t[0].len], t[0]);
            out[t[0].len] = t[1];
            break :blk out;
        },
        .SplitCoins, .MergeCoins => |t| blk: {
            const out = try arena.alloc(types.Argument, t[1].len + 1);
            out[0] = t[0];
            @memcpy(out[1..], t[1]);
            break :blk out;
        },
        .MakeMoveVec => |t| t[1],
        .Upgrade => |u| blk: {
            const out = try arena.alloc(types.Argument, 1);
            out[0] = u[3];
            break :blk out;
        },
        .Publish => &.{},
    };
}

fn argUsesInput(args: []const types.Argument, i: u16) bool {
    for (args) |a| switch (a) {
        .Input => |x| if (x == i) return true,
        else => {},
    };
    return false;
}

/// `Command::validity_check`.
fn commandValidity(arena: Allocator, cfg: *const protocol.ProtocolConfig, c: *const types.Command) Error!?Fail {
    const max_args = try cfg.get("max_arguments");
    switch (c.*) {
        .MoveCall => |*m| {
            // BLOCKED_MOVE_FUNCTIONS is empty at 1.83.1 and 1.84
            var count: u64 = 0;
            for (m.type_arguments) |*t| if (try typeInputValidity(arena, cfg, t, &count)) |f| return f;
            if (m.arguments.len >= max_args) return try sizeLimit(arena, "maximum arguments in a move call", max_args);
            if (cfg.feature_flags.validate_identifier_inputs) {
                if (!isValidIdentifier(m.module.@"0")) return try invalidIdentifier(arena, m.module.@"0");
                // Rust reports the module here too (`error: self.module.clone()`)
                if (!isValidIdentifier(m.function.@"0")) return try invalidIdentifier(arena, m.module.@"0");
            }
        },
        .TransferObjects => |t| if (try argsCheck(arena, t[0].len, max_args)) |f| return f,
        .SplitCoins, .MergeCoins => |t| if (try argsCheck(arena, t[1].len, max_args)) |f| return f,
        .MakeMoveVec => |*t| {
            if (t[0] == null and t[1].len == 0) return try userInput(arena, empty_command_input, .{});
            if (t[0]) |*ty| {
                var count: u64 = 0;
                if (try typeInputValidity(arena, cfg, ty, &count)) |f| return f;
            }
            if (t[1].len >= max_args) return try sizeLimit(arena, "maximum arguments in a programmable transaction command", max_args);
        },
        .Publish, .Upgrade => {
            const modules, const deps = switch (c.*) {
                .Publish => |p| .{ p[0], p[1] },
                .Upgrade => |u| .{ u[0], u[1] },
                else => unreachable,
            };
            if (modules.len == 0) return try userInput(arena, empty_command_input, .{});
            const max_mod = try cfg.get("max_modules_in_publish");
            if (modules.len >= max_mod) return try sizeLimit(arena, "maximum modules in a programmable transaction upgrade command", max_mod);
            if (cfg.getOpt("max_package_dependencies")) |max_deps| {
                if (deps.len >= max_deps) return try sizeLimit(arena, "maximum package dependencies", max_deps);
            }
        },
    }
    return null;
}

fn argsCheck(arena: Allocator, n: usize, max_args: u64) Allocator.Error!?Fail {
    if (n == 0) return try userInput(arena, empty_command_input, .{});
    if (n >= max_args) return try sizeLimit(arena, "maximum arguments in a programmable transaction command", max_args);
    return null;
}

fn ptbValidity(arena: Allocator, cfg: *const protocol.ProtocolConfig, pt: *const types.ProgrammableTransaction) Error!?Fail {
    const max_cmds = try cfg.get("max_programmable_tx_commands");
    if (pt.commands.len >= max_cmds) return try sizeLimit(arena, "maximum commands in a programmable transaction", max_cmds);

    // input_objects(): input arguments' objects (unique by id), then the command packages as a
    // set; plus receiving_objects()
    var arg_ids: std.ArrayList(Id) = .empty;
    var n_recv: usize = 0;
    for (pt.inputs) |*a| switch (a.*) {
        .Object => |o| switch (o) {
            .ImmOrOwnedObject => |r| if (!isCoinReservation(&r[2].@"0".@"0")) try arg_ids.append(arena, r[0].@"0".@"0"),
            .SharedObject => |sh| try arg_ids.append(arena, sh.id.@"0".@"0"),
            .Receiving => n_recv += 1,
        },
        else => {},
    };
    {
        const sorted = try arena.dupe(Id, arg_ids.items);
        std.mem.sort(Id, sorted, {}, lessId);
        for (sorted, 0..) |x, i| if (i > 0 and std.mem.eql(u8, &sorted[i - 1], &x))
            return try userInput(arena, "The transaction inputs contain duplicated ObjectRef's", .{});
    }
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
    var n_pkg: usize = 0;
    for (pk.items, 0..) |p, i| {
        if (i > 0 and std.mem.eql(u8, &pk.items[i - 1], &p)) continue;
        n_pkg += 1;
    }
    const max_in = try cfg.get("max_input_objects");
    if (arg_ids.items.len + n_pkg + n_recv > max_in) return try sizeLimit(arena, "maximum input + receiving objects in a transaction", max_in);
    if (pt.inputs.len > std.math.maxInt(u16)) return try sizeLimit(arena, "maximum inputs in a programmable transaction", @as(u64, std.math.maxInt(u16)));

    // CallArg::validity_check, input by input
    const max_pure = try cfg.get("max_pure_argument_size");
    for (pt.inputs) |*a| switch (a.*) {
        .Pure => |p| if (p.len >= max_pure) return try sizeLimit(arena, "maximum pure argument size", max_pure),
        .Object => |o| switch (o) {
            .ImmOrOwnedObject => |r| if (isCoinReservation(&r[2].@"0".@"0") and !protocol.derived.enableCoinReservationObjRefs(cfg)) {
                return try userInput(arena, "Feature is not supported: coin reservation backward compatibility layer is not enabled", .{});
            },
            .SharedObject => |sh| if (sh.mutability == .NonExclusiveWrite and !cfg.feature_flags.enable_non_exclusive_writes) {
                return try userInput(arena, "Feature is not supported: User transactions cannot use SharedObjectMutability::NonExclusiveWrite", .{});
            },
            .Receiving => if (!cfg.feature_flags.receive_objects) {
                return try userInput(arena, "Feature is not supported: receiving objects is not supported at ProtocolVersion({d})", .{cfg.version});
            },
        },
        .FundsWithdrawal => |w| {
            // check_accumulator_type_bounds on Balance<T>
            const t = switch (w.type_arg) {
                .Balance => |x| x,
            };
            if (cfg.getOpt("max_accumulator_type_nodes")) |max| if (1 + nodeCount(&t) > max)
                return try sizeLimit(arena, "maximum type nodes in a funds accumulator type", max);
        },
    };

    if (cfg.getOpt("max_publish_or_upgrade_per_ptb")) |max_publish| {
        var n: u64 = 0;
        for (pt.commands) |*c| switch (c.*) {
            .Publish, .Upgrade => n += 1,
            else => {},
        };
        if (n > max_publish) return try userInput(arena, "{d} max publish/upgrade commands allowed, {d} provided", .{ max_publish, n });
    }

    for (pt.commands) |*c| if (try commandValidity(arena, cfg, c)) |f| return f;

    if (cfg.feature_flags.validate_ptb_argument_indices) {
        for (pt.commands, 0..) |*c, ci| {
            for (try commandArgs(arena, c), 0..) |a, ai| {
                const bad: ?u16 = switch (a) {
                    .Input => |i| if (i >= pt.inputs.len) i else null,
                    .Result => |i| if (i >= ci) i else null,
                    .NestedResult => |r| if (r[0] >= ci) r[0] else null,
                    .GasCoin => null,
                };
                if (bad) |i| return try userInput(arena, "Invalid argument at command {d}, argument {d}: index {d} is out of bounds", .{ ci, ai, i });
            }
        }
    }

    // randomness: the first Random input; commands after one that uses it may only transfer or merge
    for (pt.inputs, 0..) |*a, ri| switch (a.*) {
        .Object => |o| switch (o) {
            .SharedObject => |sh| if (std.mem.eql(u8, &sh.id.@"0".@"0", &random_id)) {
                if (!cfg.feature_flags.random_beacon) return try userInput(arena, "Feature is not supported: randomness is not enabled on this network", .{});
                var used = false;
                for (pt.commands) |*c| {
                    if (!used) {
                        used = argUsesInput(try commandArgs(arena, c), @intCast(ri));
                    } else switch (c.*) {
                        .TransferObjects, .MergeCoins => {},
                        else => return try userInput(arena, "Commands following a command with Random can only be TransferObjects or MergeCoins", .{}),
                    }
                }
                break;
            },
            else => {},
        },
        else => {},
    };
    return null;
}

const random_id: Id = blk: {
    var a: Id = @splat(0);
    a[31] = 8;
    break :blk a;
};

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

// ---- ProgrammableTransaction::validate_gasless_transaction ------------------------------------

/// `TypeInput` Display (`0x2::balance::Balance<0x2::sui::SUI>`, `vector<u8>`).
pub fn typeInputDisplay(arena: Allocator, t: *const types.TypeInput) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try writeTypeInput(arena, &out, t);
    return out.items;
}

fn writeTypeInput(arena: Allocator, out: *std.ArrayList(u8), t: *const types.TypeInput) Allocator.Error!void {
    switch (t.*) {
        .vector => |e| {
            try out.appendSlice(arena, "vector<");
            try writeTypeInput(arena, out, e);
            try out.append(arena, '>');
        },
        .@"struct" => |*st| {
            const hx = std.fmt.bytesToHex(st.address.@"0", .lower);
            var i: usize = 0;
            while (i < 63 and hx[i] == '0') i += 1;
            try out.appendSlice(arena, "0x");
            try out.appendSlice(arena, hx[i..]);
            try out.appendSlice(arena, "::");
            try out.appendSlice(arena, st.module.@"0");
            try out.appendSlice(arena, "::");
            try out.appendSlice(arena, st.name.@"0");
            for (st.type_args, 0..) |*a, k| {
                try out.appendSlice(arena, if (k == 0) "<" else ", ");
                try writeTypeInput(arena, out, a);
            }
            if (st.type_args.len != 0) try out.append(arena, '>');
        },
        else => try out.appendSlice(arena, @tagName(t.*)),
    }
}

fn isFramework(addr: *const Id) bool {
    for (addr[0..31]) |b| if (b != 0) return false;
    return addr[31] == 2;
}

/// The token types a gasless transaction may move (`get_gasless_allowed_token_types`): Rust keys
/// a map by the parsed TypeTag; every listed type is a plain struct, so a fund type matches when
/// it is a struct without type arguments with the same address, module and name.
fn gaslessAllowed(cfg: *const protocol.ProtocolConfig, t: *const types.TypeInput) bool {
    const st = switch (t.*) {
        .@"struct" => |*x| x,
        else => return false,
    };
    if (st.type_args.len != 0) return false;
    const tag: types.TypeTag = .{ .@"struct" = .{ .address = st.address, .module = .{ .@"0" = st.module.@"0" }, .name = .{ .@"0" = st.name.@"0" }, .type_args = &.{} } };
    return gaslessMinAmount(cfg, &tag) != null;
}

fn gaslessUnsupported(arena: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error!Fail {
    return userInput(arena, "Feature is not supported: " ++ fmt, args);
}

const GaslessFn = struct { module: []const u8, function: []const u8, balance_type: bool };
/// `GASLESS_FUNCTIONS`: 0x2 functions with one type argument, the fund type itself or `Balance<T>`.
const gasless_functions = [_]GaslessFn{
    .{ .module = "balance", .function = "send_funds", .balance_type = false },
    .{ .module = "balance", .function = "redeem_funds", .balance_type = false },
    .{ .module = "balance", .function = "split", .balance_type = false },
    .{ .module = "balance", .function = "zero", .balance_type = false },
    .{ .module = "funds_accumulator", .function = "withdrawal_split", .balance_type = true },
    .{ .module = "coin", .function = "into_balance", .balance_type = false },
    .{ .module = "coin", .function = "redeem_funds", .balance_type = false },
    .{ .module = "coin", .function = "send_funds", .balance_type = false },
    .{ .module = "coin", .function = "put", .balance_type = false },
};

/// `validate_gasless_transaction` (with `Command::` and `ProgrammableMoveCall::
/// validate_gasless_transaction` and `validate_gasless_inputs`).
fn gaslessValidity(arena: Allocator, cfg: *const protocol.ProtocolConfig, pt: *const types.ProgrammableTransaction) Error!?Fail {
    if (pt.commands.len == 0) return try gaslessUnsupported(arena, "Gasless transactions must have at least one command", .{});
    for (pt.inputs) |*a| switch (a.*) {
        .Object => |o| if (o == .Receiving) return try gaslessUnsupported(arena, "Gasless transactions do not support Receiving object inputs", .{}),
        else => {},
    };
    for (pt.commands) |*c| switch (c.*) {
        .MoveCall => |*m| {
            const pkg = &m.package.@"0".@"0";
            const entry: ?GaslessFn = for (gasless_functions) |gf| {
                if (isFramework(pkg) and std.mem.eql(u8, gf.module, m.module.@"0") and std.mem.eql(u8, gf.function, m.function.@"0")) break gf;
            } else null;
            const gf = entry orelse return try gaslessUnsupported(arena, "Function {s}::{s}::{s} is not supported in gasless transactions", .{ hex(pkg).s(), m.module.@"0", m.function.@"0" });
            if (m.type_arguments.len != 1) return try gaslessUnsupported(arena, "Function {s}::{s}::{s} requires {d} type arguments, but {d} were provided", .{ hex(pkg).s(), m.module.@"0", m.function.@"0", @as(usize, 1), m.type_arguments.len });
            const ta = &m.type_arguments[0];
            // TypeInput::to_type_tag cannot fail here: the identifiers were validated above
            const fund: *const types.TypeInput = if (!gf.balance_type) ta else blk: {
                const st = switch (ta.*) {
                    .@"struct" => |*x| x,
                    else => null,
                };
                if (st) |b| if (isFramework(&b.address.@"0") and std.mem.eql(u8, b.module.@"0", "balance") and std.mem.eql(u8, b.name.@"0", "Balance") and b.type_args.len == 1) break :blk &b.type_args[0];
                return try gaslessUnsupported(arena, "Expected a type Balance<_> but got {s}", .{try typeInputDisplay(arena, ta)});
            };
            if (!gaslessAllowed(cfg, fund)) return try gaslessUnsupported(arena, "Fund type {s} is not currently allowed in gasless transactions", .{try typeInputDisplay(arena, fund)});
        },
        .MergeCoins, .SplitCoins => {},
        else => return try gaslessUnsupported(arena, "Gasless transactions only support MoveCall, MergeCoins, and SplitCoins commands", .{}),
    };
    // validate_gasless_inputs
    const used = try arena.alloc(bool, pt.inputs.len);
    @memset(used, false);
    for (pt.commands) |*c| for (try commandArgs(arena, c)) |a| switch (a) {
        .Input => |i| if (i < used.len) {
            used[i] = true;
        },
        else => {},
    };
    const max_unused = protocol.derived.gaslessMaxUnusedInputs(cfg);
    const max_pure = protocol.derived.gaslessMaxPureInputBytes(cfg);
    var unused_pure: u64 = 0;
    for (pt.inputs, used, 0..) |*a, u, i| switch (a.*) {
        .Pure => |p| {
            if (p.len > max_pure) return try gaslessUnsupported(arena, "Input {d} has size {d} bytes, but gasless transactions allow at most {d} bytes per Pure input", .{ i, p.len, max_pure });
            if (!u) unused_pure += 1;
        },
        .Object => if (!u) return try gaslessUnsupported(arena, "Gasless transactions do not allow unused Object inputs (input {d})", .{i}),
        .FundsWithdrawal => if (!u) return try gaslessUnsupported(arena, "Gasless transactions do not allow unused FundsWithdrawal inputs (input {d})", .{i}),
    };
    if (unused_pure > max_unused) return try gaslessUnsupported(arena, "Gasless transactions allow at most {d} unused Pure inputs, but found {d}", .{ max_unused, unused_pure });
    return null;
}

// ---- SenderSignedData::validity_check --------------------------------------------------------

/// MultiSig / MultiSigLegacy `uses_mldsa65`: an ML-DSA-65 member key or signature. `inner` is
/// the signature after its flag byte, already validated by the decoder.
fn multisigUsesMldsa65(inner: []const u8, legacy: bool) bool {
    const gen = types.gen;
    var r = bcs.Reader.init(inner);
    const nsigs = r.length() catch return false;
    for (0..nsigs) |_| {
        const at = r.at;
        if ((r.uleb32() catch return false) == 5) return true; // CompressedSignature::MLDSA65
        r.at = at;
        bcs.skip(gen.CompressedSignature, &r) catch return false;
    }
    if (legacy) {
        const bm = r.length() catch return false;
        _ = r.bytes(bm) catch return false;
    } else _ = r.int(u16) catch return false;
    const npk = r.length() catch return false;
    for (0..npk) |_| {
        if (legacy) {
            // Base64 of flag ++ key: the first base64 character carries the flag's top 6 bits
            const s = bcs.readStr(&r) catch return false;
            var buf: [4096]u8 = undefined;
            const d = std.base64.standard.Decoder;
            const n = d.calcSizeForSlice(s) catch return false;
            if (n > buf.len) return false;
            d.decode(buf[0..n], s) catch return false;
            if (n > 0 and buf[0] == 7) return true; // SignatureScheme::MLDSA65 flag
        } else {
            const at = r.at;
            if ((r.uleb32() catch return false) == 5) return true; // PublicKey::MLDSA65
            r.at = at;
            bcs.skip(gen.PublicKey, &r) catch return false;
        }
        _ = r.int(u8) catch return false;
    }
    return false;
}

/// `check_user_signature_protocol_compatibility`.
fn signatureCompat(arena: Allocator, cfg: *const protocol.ProtocolConfig, sigs: []const []const u8) Allocator.Error!?Fail {
    const ff = &cfg.feature_flags;
    for (sigs) |s| {
        const scheme = types.GenericSignature.classify(s) orelse continue;
        switch (scheme) {
            .multisig => {
                if (!ff.upgraded_multisig_supported) return try userInput(arena, "Feature is not supported: upgraded multisig format not enabled on this network", .{});
                if (!ff.mldsa65_auth and multisigUsesMldsa65(s[1..], false)) return try userInput(arena, "Feature is not supported: ML-DSA-65 multisig members are not enabled on this network", .{});
            },
            .multisig_legacy => if (!ff.mldsa65_auth and multisigUsesMldsa65(s[1..], true)) return try userInput(arena, "Feature is not supported: ML-DSA-65 multisig members are not enabled on this network", .{}),
            .zklogin => if (!ff.zklogin_auth) return try userInput(arena, "Feature is not supported: zklogin is not enabled on this network", .{}),
            .passkey => if (!ff.passkey_auth) return try userInput(arena, "Feature is not supported: passkey is not enabled on this network", .{}),
            .mldsa65 => if (!ff.mldsa65_auth) return try userInput(arena, "Feature is not supported: ML-DSA-65 signatures are not enabled on this network", .{}),
            .ed25519, .secp256k1, .secp256r1 => {},
        }
    }
    return null;
}

/// `SenderSignedData::validity_check`: signature schemes against the protocol flags, no system
/// transactions, the serialized size limits (`size` is the BCS size of the SenderSignedData),
/// then `TransactionData::validity_check`.
pub fn senderSignedValidity(arena: Allocator, c: *const ValidityCtx, td: *const types.TransactionDataV1, sigs: []const []const u8, size: usize) Error!?Fail {
    const cfg = c.cfg;
    if (try signatureCompat(arena, cfg, sigs)) |f| return f;
    if (isSystemKind(&td.kind)) return try userInput(arena, "Feature is not supported: SenderSignedData must not contain system transaction", .{});
    const max_size = try cfg.get("max_tx_size_bytes");
    if (size > max_size) return try userInput(arena, "Size limit exceeded: serialized transaction size exceeded maximum of {d} is {d}", .{ max_size, size });
    if (isGasless(cfg, td)) {
        const gmax = protocol.derived.gaslessMaxTxSizeBytes(cfg);
        if (size > gmax) return try userInput(arena, "Size limit exceeded: serialized gasless transaction size exceeded maximum of {d} is {d}", .{ gmax, size });
    }
    return validity(arena, c, td);
}
// ---- check_transaction_input -----------------------------------------------------------------

/// One loaded input (`ObjectReadResult`).
pub const Loaded = struct {
    kind: InputKind,
    raw: []const u8,
    view: ObjectView,
    owner: types.Owner,
    /// `ObjectReadResultKind::ObjectConsensusStreamEnded`: a shared input whose consensus stream
    /// ended (signing only). No object: `raw` is empty, `view` carries only the id, and
    /// `check_objects` skips it after the duplicate check.
    stream_ended: bool = false,

    /// The stream-ended read result of shared input `id` (`kind` must be `.shared`).
    pub fn streamEnded(kind: InputKind, id: Id, start_version: u64) Loaded {
        return .{
            .kind = kind,
            .raw = &.{},
            .view = .{ .raw = &.{}, .is_package = false, .id = id, .version = 0, .version_at = 0, .contents_at = 0, .contents_len = 0, .owner_at = 0, .prev_tx_at = 0, .rebate_at = 0 },
            .owner = .{ .Shared = .{ .initial_shared_version = .{ .@"0" = start_version } } },
            .stream_ended = true,
        };
    }

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
    return transactionInputOpts(arena, cfg, rgp, td, inputs, recv, recv_objs, .signing);
}

/// What the input checks are for. Signing and simulate with checks run `check_transaction_input`.
/// A certified transaction runs `check_certificate_input`, which skips the allowance
/// declarations: the allowance's own Move checks judge the consensus-sequenced state.
pub const InputMode = enum { signing, certificate };

pub fn transactionInputOpts(arena: Allocator, cfg: *const protocol.ProtocolConfig, rgp: u64, td: *const types.TransactionDataV1, inputs: []const Loaded, recv: []const Receiving, recv_objs: []const ?[]const u8, mode: InputMode) Error!?Fail {
    if (try gasInput(arena, cfg, rgp, td, inputs)) |f| return f;
    // check_transaction_input_inner (check_objects, replay protection), then
    // check_allowance_inputs, then check_receiving_objects
    if (try objectsInput(arena, cfg, td, inputs, &.{}, &.{})) |f| return f;
    if (mode == .signing) if (try allowanceInputs(arena, td, inputs)) |f| return f;
    return objectsInput(arena, cfg, td, inputs, recv, recv_objs);
}

/// `TransactionData::check_allowance_inputs`: each `WithdrawFrom::SenderAllowance` names an
/// allowance among the loaded inputs, a shared `0x2::allowance::Allowance<T>` whose funder is the
/// declared funder, whose spender is the sender, and whose `T` is the withdrawal's `Balance<_>`.
pub fn allowanceInputs(arena: Allocator, td: *const types.TransactionDataV1, inputs: []const Loaded) Error!?Fail {
    const pt = ptbOf(td) orelse return null;
    for (pt.inputs) |*a| switch (a.*) {
        .FundsWithdrawal => |*w| switch (w.withdraw_from) {
            .SenderAllowance => |sa| {
                const aid = sa.allowance.@"0".@"0";
                const l = findInput(inputs, &aid) orelse
                    return try invalidWithdraw(arena, "Specified allowance {s} not found among the tx inputs", .{hex(&aid).s()});
                const r = switch (try resolveAllowance(arena, l)) {
                    .ok => |x| x,
                    .fail => |f| return f,
                };
                if (!std.mem.eql(u8, &r.funder, &sa.funder.@"0"))
                    return try invalidWithdraw(arena, "Specified funder {s} does not match the funder of allowance {s}", .{ hex(&sa.funder.@"0").s(), hex(&aid).s() });
                if (r.spender == null or !std.mem.eql(u8, &r.spender.?, &td.sender.@"0"))
                    return try invalidWithdraw(arena, "Transaction sender is not the spender of allowance {s}", .{hex(&aid).s()});
                const requested = try balanceOf(arena, &w.type_arg.Balance);
                const want = try bcs.encodeAlloc(types.TypeTag, arena, &requested);
                const have = try bcs.encodeAlloc(types.TypeTag, arena, &r.funds_type);
                if (!std.mem.eql(u8, want, have))
                    return try invalidWithdraw(arena, "Allowance {s} is for {s}, not {s}", .{ hex(&aid).s(), try typeTagDisplay(arena, &r.funds_type), try typeTagDisplay(arena, &requested) });
            },
            else => {},
        },
        else => {},
    };
    return null;
}

fn invalidWithdraw(arena: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error!Fail {
    return userInput(arena, "Invalid withdraw reservation: " ++ fmt, args);
}

/// `ResolvedAllowance`: the sign-time view of an `Allowance<T>`.
pub const ResolvedAllowance = struct { funder: Id, spender: ?Id, funds_type: types.TypeTag };

/// `parse_allowance_object`.
pub fn resolveAllowance(arena: Allocator, l: *const Loaded) Allocator.Error!union(enum) { ok: ResolvedAllowance, fail: Fail } {
    const id = l.view.id;
    if (l.view.is_package) return .{ .fail = try invalidWithdraw(arena, "Specified allowance {s} is not a Move object", .{hex(&id).s()}) };
    const ty = bcs.decode(types.MoveObjectType, arena, l.raw[1..l.view.version_at - 1]) catch
        return .{ .fail = try internal(arena, "allowance {s} type does not parse", .{hex(&id).s()}) };
    const tag = switch (ty.@"0") {
        .Other => |t| t,
        else => return .{ .fail = try invalidWithdraw(arena, "Specified allowance {s} is not a sui::allowance::Allowance", .{hex(&id).s()}) },
    };
    if (!isAllowanceTag(&tag)) return .{ .fail = try invalidWithdraw(arena, "Specified allowance {s} is not a sui::allowance::Allowance", .{hex(&id).s()}) };
    if (l.owner != .Shared) return .{ .fail = try invalidWithdraw(arena, "Allowance {s} is not a shared object", .{hex(&id).s()}) };
    // Allowance { id: UID, settings: Settings { funder: address, spender: Option<address>, .. }, .. }
    const c = l.view.contents();
    if (c.len < 65 or c[64] > 1 or (c[64] == 1 and c.len < 97))
        return .{ .fail = try invalidWithdraw(arena, "Failed to read allowance {s}", .{hex(&id).s()}) };
    return .{ .ok = .{
        .funder = c[32..64].*,
        .spender = if (c[64] == 1) c[65..97].* else null,
        .funds_type = tag.type_args[0],
    } };
}

/// `Allowance::is_allowance`: `0x2::allowance::Allowance` with one type parameter.
fn isAllowanceTag(t: *const types.StructTag) bool {
    var two: Id = @splat(0);
    two[31] = 2;
    return std.mem.eql(u8, &t.address.@"0", &two) and std.mem.eql(u8, t.module.@"0", "allowance") and
        std.mem.eql(u8, t.name.@"0", "Allowance") and t.type_args.len == 1;
}

/// `TypeTag` Display: `0x{short_str_lossless}::m::S<A, B>`, `vector<T>`, primitives by name.
pub fn typeTagDisplay(arena: Allocator, t: *const types.TypeTag) Allocator.Error![]const u8 {
    var w: std.Io.Writer.Allocating = .init(arena);
    writeTypeTag(&w.writer, t) catch return error.OutOfMemory;
    return w.written();
}

fn writeTypeTag(w: *std.Io.Writer, t: *const types.TypeTag) std.Io.Writer.Error!void {
    switch (t.*) {
        .vector => |e| {
            try w.writeAll("vector<");
            try writeTypeTag(w, e);
            try w.writeAll(">");
        },
        .@"struct" => |*s| {
            const h = std.fmt.bytesToHex(s.address.@"0", .lower);
            var i: usize = 0;
            while (i < h.len and h[i] == '0') i += 1;
            try w.print("0x{s}::{s}::{s}", .{ if (i == h.len) "0" else h[i..], s.module.@"0", s.name.@"0" });
            for (s.type_args, 0..) |*a, k| {
                try w.writeAll(if (k == 0) "<" else ", ");
                try writeTypeTag(w, a);
            }
            if (s.type_args.len > 0) try w.writeAll(">");
        },
        else => try w.writeAll(@tagName(t.*)),
    }
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
        // "We skip checking a removed consensus object because it no longer exists."
        if (l.stream_ended) continue;
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
    // check_gasless_object_inputs
    if (isGasless(cfg, td)) if (try gaslessObjectInputs(arena, cfg, inputs)) |f| return f;
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

/// `check_gasless_object_inputs`: every non-package input is an address-owned (or consensus
/// address-owned) `Coin<T>` with T allow-listed.
fn gaslessObjectInputs(arena: Allocator, cfg: *const protocol.ProtocolConfig, inputs: []const Loaded) Error!?Fail {
    for (inputs) |*l| {
        if (l.stream_ended or l.view.is_package) continue;
        switch (l.owner) {
            .AddressOwner, .ConsensusAddressOwner => {},
            else => return try gaslessUnsupported(arena, "Gasless transactions only support owned object inputs", .{}),
        }
        const coin = try objCoinType(arena, l.raw) orelse return try gaslessUnsupported(arena, "Gasless transactions can only use Coin<T> object inputs, but found a non-Coin object", .{});
        if (gaslessMinAmount(cfg, &coin) == null) return try gaslessUnsupported(arena, "Gasless transactions only support allowlisted types for Coin inputs", .{});
    }
    return null;
}

/// `Object::coin_type_maybe`: T of a `Coin<T>` object (SUI for the gas coin), else null.
pub fn objCoinType(arena: Allocator, raw: []const u8) Allocator.Error!?types.TypeTag {
    if (raw.len < 2 or raw[0] != 0) return null;
    var r = bcs.Reader.init(raw[1..]);
    const mt = bcs.decodeFrom(types.MoveObjectType, arena, &r) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    return switch (mt.@"0") {
        .GasCoin => sui_coin_tag,
        .Coin => |t| t,
        else => null,
    };
}

/// `pre_object_load_checks` after the deny config: `process_funds_withdrawals_for_signing`,
/// `check_amounts_available` against the latest account objects, then, for a gasless
/// transaction, `check_remaining_amounts_after_withdrawal`. The declared withdrawals in account
/// id order.
pub fn fundsForSigning(arena: Allocator, cfg: *const protocol.ProtocolConfig, td: *const types.TransactionDataV1, chain_id: *const Id, state: anytype) Error!Withdrawals {
    const list = switch (try declaredWithdrawals(arena, td, chain_id, state)) {
        .fail => |f| return .{ .fail = f },
        .ok => |l| l,
    };
    const amountOf = struct {
        fn f(st: @TypeOf(state), account: *const Id) u128 {
            const raw = st.latest(account) orelse return 0;
            return accumulatorAmount(raw) orelse 0;
        }
    }.f;
    for (list) |w| {
        const actual = amountOf(state, &w.account);
        if (actual < w.amount) return .{ .fail = try userInput(arena, "Invalid withdraw reservation: Insufficient address balance of coin type {s} for address {s}: the transaction requires {d} but only {d} is available. Note that the address balance does not include funds held in Coin objects owned by the address; to spend those funds, use the Coin objects directly as transaction inputs.", .{ try typeDisplay(arena, &w.coin), hex(&w.owner).s(), w.amount, actual }) };
    }
    if (cfg.feature_flags.gasless_verify_remaining_balance and isGasless(cfg, td)) for (list) |w| {
        const remaining = amountOf(state, &w.account) -| w.amount;
        if (remaining == 0) continue;
        const min = gaslessMinAmount(cfg, &w.coin) orelse continue;
        if (min > 0 and remaining < min) return .{ .fail = try userInput(arena, "Invalid withdraw reservation: Invalid gasless withdrawal of coin type {s} from address {s}. Gasless transactions must either use the entire address balance, or leave at least {d}. Remaining amount would be {d}", .{ try typeDisplay(arena, &w.coin), hex(&w.owner).s(), min, remaining }) };
    };
    return .{ .ok = list };
}

/// `handle_coin_deny_list_checks`: the coin types of the input and receiving objects (the gas
/// coin excluded) checked for the sender, and each withdrawal's type for its funder and the
/// sender; v1 when the coin deny list is enabled and its state exists, then v2.
pub fn coinDenyForSigning(arena: Allocator, cfg: *const protocol.ProtocolConfig, td: *const types.TransactionDataV1, state: anytype, inputs: []const Loaded, recv_objs: []const ?[]const u8, withdrawals: []const Withdraw) Error!?Fail {
    const deny = exec.ptb.deny;
    const ff = &cfg.feature_flags;
    if (!ff.enable_coin_deny_list and !ff.enable_coin_deny_list_v2) return null;
    const Entry = struct { ty: []const u8, addrs: std.ArrayList(Id) };
    var map: std.ArrayList(Entry) = .empty;
    const addTo = struct {
        fn f(a: Allocator, m: *std.ArrayList(Entry), ty: []const u8, addr: *const Id) Allocator.Error!void {
            const e = for (m.items) |*x| {
                if (std.mem.eql(u8, x.ty, ty)) break x;
            } else blk: {
                try m.append(a, .{ .ty = ty, .addrs = .empty });
                break :blk &m.items[m.items.len - 1];
            };
            for (e.addrs.items) |x| if (std.mem.eql(u8, &x, addr)) return;
            try e.addrs.append(a, addr.*);
        }
    }.f;
    const sender = &td.sender.@"0";
    var objs: std.ArrayList([]const u8) = .empty;
    for (inputs) |*l| if (!l.stream_ended) try objs.append(arena, l.raw);
    for (recv_objs) |o| if (o) |raw| try objs.append(arena, raw);
    for (objs.items) |raw| {
        if (raw.len >= 2 and raw[0] == 0 and raw[1] == 1) continue; // MoveObjectType::GasCoin
        const t = try objCoinType(arena, raw) orelse continue;
        try addTo(arena, &map, try deny.canonical(arena, &t), sender);
    }
    for (withdrawals) |w| {
        const ty = try deny.canonical(arena, &w.coin);
        try addTo(arena, &map, ty, sender);
        try addTo(arena, &map, ty, &w.owner);
    }
    if (map.items.len == 0) return null;
    std.mem.sort(Entry, map.items, {}, struct {
        fn lt(_: void, a: Entry, b: Entry) bool {
            return std.mem.order(u8, a.ty, b.ty) == .lt;
        }
    }.lt);
    const groups = try arena.alloc(deny.SigningGroup, map.items.len);
    for (map.items, groups) |*e, *g| {
        std.mem.sort(Id, e.addrs.items, {}, lessId);
        g.* = .{ .ty = e.ty, .addrs = e.addrs.items };
    }
    const store: deny.Store = .{ .ctx = state.ctx, .get = state.vtable.latest };
    if (ff.enable_coin_deny_list and state.latest(&deny.deny_list_id) != null) {
        if (try deny.checkSigningV1(arena, store, groups)) |d| return try deniedFail(arena, d);
    }
    if (ff.enable_coin_deny_list_v2) {
        if (try deny.checkSigningV2(arena, store, groups)) |d| return try deniedFail(arena, d);
    }
    return null;
}

fn deniedFail(arena: Allocator, d: exec.ptb.deny.Denied) Allocator.Error!Fail {
    return switch (d) {
        .pause => |t| try userInput(arena, "Coin type is globally paused for use: {s}", .{t}),
        .address => |a| try userInput(arena, "Address {s} is denied for coin {s}", .{ hex(&a.address).s(), a.coin_type }),
    };
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

fn testAllowanceObject(arena: Allocator, id: Id, funder: Id, spender: ?Id, funds: types.TypeTag, owner: types.Owner) ![]const u8 {
    var two: Id = @splat(0);
    two[31] = 2;
    const args = try arena.alloc(types.TypeTag, 1);
    args[0] = funds;
    // Allowance { id, settings: Settings { funder, spender, app: none, lifetime_cap: none,
    // start: none, expiration: none, rate_limit: none, name: "" }, current_spend: 0u256 }
    var c: std.ArrayList(u8) = .empty;
    try c.appendSlice(arena, &id);
    try c.appendSlice(arena, &funder);
    if (spender) |s| {
        try c.append(arena, 1);
        try c.appendSlice(arena, &s);
    } else try c.append(arena, 0);
    try c.appendSlice(arena, &.{ 0, 0, 0, 0, 0, 0 });
    const zero_u256: [32]u8 = @splat(0);
    try c.appendSlice(arena, &zero_u256);
    const obj: types.Object = .{
        .data = .{ .Move = .{
            .type_ = .{ .@"0" = .{ .Other = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "allowance" }, .name = .{ .@"0" = "Allowance" }, .type_args = args } } },
            .has_public_transfer = false,
            .version = .{ .@"0" = 5 },
            .contents = c.items,
        } },
        .owner = owner,
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(0) } },
        .storage_rebate = 0,
    };
    return bcs.encodeAlloc(types.Object, arena, &obj);
}

test "check_allowance_inputs: declared funder, sender as spender, funds type, shared, among the inputs" {
    var ar: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const funder: Id = @splat(0xaa);
    const spender: Id = @splat(0xbb);
    const aid: Id = @splat(0xcc);
    const shared: types.Owner = .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 3 } } };
    const bal_sui = try balanceOf(a, &sui_coin_tag);

    const Case = struct { funder: Id, sender: Id, obj_spender: ?Id, obj_funds: types.TypeTag, owner: types.Owner, in_inputs: bool, want: ?[]const u8 };
    const msg = "Error checking transaction input objects: Invalid withdraw reservation: ";
    const cases = [_]Case{
        .{ .funder = funder, .sender = spender, .obj_spender = spender, .obj_funds = bal_sui, .owner = shared, .in_inputs = true, .want = null },
        .{ .funder = funder, .sender = spender, .obj_spender = spender, .obj_funds = bal_sui, .owner = shared, .in_inputs = false, .want = msg ++ "Specified allowance 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc not found among the tx inputs" },
        .{ .funder = spender, .sender = spender, .obj_spender = spender, .obj_funds = bal_sui, .owner = shared, .in_inputs = true, .want = msg ++ "Specified funder 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb does not match the funder of allowance 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" },
        .{ .funder = funder, .sender = funder, .obj_spender = spender, .obj_funds = bal_sui, .owner = shared, .in_inputs = true, .want = msg ++ "Transaction sender is not the spender of allowance 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" },
        .{ .funder = funder, .sender = spender, .obj_spender = null, .obj_funds = bal_sui, .owner = shared, .in_inputs = true, .want = msg ++ "Transaction sender is not the spender of allowance 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" },
        .{ .funder = funder, .sender = spender, .obj_spender = spender, .obj_funds = sui_coin_tag, .owner = shared, .in_inputs = true, .want = msg ++ "Allowance 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc is for 0x2::sui::SUI, not 0x2::balance::Balance<0x2::sui::SUI>" },
        .{ .funder = funder, .sender = spender, .obj_spender = spender, .obj_funds = bal_sui, .owner = .{ .AddressOwner = .{ .@"0" = funder } }, .in_inputs = true, .want = msg ++ "Allowance 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc is not a shared object" },
    };
    for (cases) |cs| {
        const raw = try testAllowanceObject(a, aid, funder, cs.obj_spender, cs.obj_funds, cs.owner);
        const v = try ObjectView.parse(raw);
        const loaded = [_]Loaded{.{ .kind = .{ .shared = .{ .id = aid, .isv = 3, .mutability = .Mutable } }, .raw = raw, .view = v, .owner = cs.owner }};
        const inputs = [_]types.CallArg{.{ .FundsWithdrawal = .{
            .reservation = .{ .MaxAmountU64 = 400 },
            .type_arg = .{ .Balance = sui_coin_tag },
            .withdraw_from = .{ .SenderAllowance = .{ .funder = .{ .@"0" = cs.funder }, .allowance = .{ .@"0" = .{ .@"0" = aid } } } },
        } }};
        const td: types.TransactionDataV1 = .{
            .kind = .{ .ProgrammableTransaction = .{ .inputs = &inputs, .commands = &.{} } },
            .sender = .{ .@"0" = cs.sender },
            .gas_data = .{ .payment = &.{}, .owner = .{ .@"0" = cs.sender }, .price = 1000, .budget = 1 },
            .expiration = .None,
        };
        const f = try allowanceInputs(a, &td, if (cs.in_inputs) &loaded else &.{});
        if (cs.want) |w| {
            try std.testing.expect(f != null);
            try std.testing.expectEqualStrings(w, f.?.message);
        } else try std.testing.expect(f == null);
    }
}

test "process_funds_withdrawals_for_execution: per account, allowances charge the funder, address-balance gas the gas owner" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const sender: Id = @splat(0x51);
    const funder: Id = @splat(0xf1);
    const inputs = [_]types.CallArg{
        .{ .FundsWithdrawal = .{ .reservation = .{ .MaxAmountU64 = 5 }, .type_arg = .{ .Balance = sui_coin_tag }, .withdraw_from = .Sender } },
        .{ .FundsWithdrawal = .{ .reservation = .{ .MaxAmountU64 = 3 }, .type_arg = .{ .Balance = sui_coin_tag }, .withdraw_from = .{ .SenderAllowance = .{ .funder = .{ .@"0" = funder }, .allowance = .{ .@"0" = .{ .@"0" = @splat(0xa1) } } } } } },
    };
    const td: types.TransactionDataV1 = .{
        .kind = .{ .ProgrammableTransaction = .{ .inputs = &inputs, .commands = &.{} } },
        .sender = .{ .@"0" = sender },
        .gas_data = .{ .payment = &.{}, .owner = .{ .@"0" = sender }, .price = 1000, .budget = 7 },
        .expiration = .None,
    };
    const chain: Id = @splat(0);
    const got = try executionWithdrawals(a, &td, &chain);
    try std.testing.expectEqual(@as(usize, 2), got.len);
    const sa = accumulatorId(&sender, &sui_balance_tag);
    const fa = accumulatorId(&funder, &sui_balance_tag);
    for (got) |r| {
        if (std.mem.eql(u8, &r.account, &sa)) try std.testing.expectEqual(@as(u64, 12), r.amount) else {
            try std.testing.expectEqualSlices(u8, &fa, &r.account);
            try std.testing.expectEqual(@as(u64, 3), r.amount);
        }
    }
    try std.testing.expect(std.mem.order(u8, &got[0].account, &got[1].account) == .lt);
}
