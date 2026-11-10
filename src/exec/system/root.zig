//! System transactions (CONTRACTS 6.4.2): every transaction kind that is not a user
//! programmable transaction. One entry point, `execute`, with the
//! objects behind a `Source` (a store in a node, the corpus in replay).
//!
//! - ProgrammableSystemTransaction: accumulator settlement, native (`settlement.zig`).
//! - RandomnessStateUpdate, AuthenticatorStateUpdate: one system Move call (`movecall.zig`).
//! - EndOfEpochTransaction: a system PTB ending in advance_epoch (`epoch.zig`).
//! - ChangeEpoch (the standalone kind): the same PTB as end of epoch (`epoch.zig`).
//! - Genesis: raw object creation (`genesis.zig`).
//! - Effects V1 below `enable_effects_v2` (`store.zig`), execution versions 0 to 4.
//! - Consensus commit prologues stay in `../ccp.zig`.
//! - Everything else is reported unsupported with its reason until its executor lands.
const std = @import("std");
const types = @import("types");
const protocol = @import("protocol");
const bcs = @import("bcs");

pub const store = @import("store.zig");
pub const settlement = @import("settlement.zig");
pub const movecall = @import("movecall.zig");
pub const epoch = @import("epoch.zig");
pub const genesis = @import("genesis.zig");

const Allocator = std.mem.Allocator;

pub const Source = struct {
    ctx: *const anyopaque,
    /// The transaction's input objects at the versions it reads (exact id and version).
    input: *const fn (ctx: *const anyopaque, id: *const [32]u8, version: u64) ?[]const u8,
    /// `read_child_object`: newest version of `child` at or below `bound`; null = none.
    child: *const fn (ctx: *const anyopaque, parent: *const [32]u8, child: *const [32]u8, bound: u64) error{NotAvailable}!?[]const u8,
    /// The package object the transaction's epoch loads for `id`.
    package: *const fn (ctx: *const anyopaque, id: *const [32]u8) ?[]const u8,
};

pub const Env = struct {
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    epoch_start_ms: u64 = 0,
    rgp: u64 = 0,
    /// The transaction digest when the caller has it (a node does); null computes it.
    tx_digest: ?[32]u8 = null,
};

pub const Written = store.Written;
pub const Output = store.Output;
pub const Outcome = union(enum) { done: Output, unsupported: []const u8 };

/// The kinds this module executes (prologues are `ccp.zig`'s).
pub fn handles(kind: *const types.TransactionKind) bool {
    return switch (kind.*) {
        .ProgrammableSystemTransaction, .RandomnessStateUpdate, .AuthenticatorStateUpdate, .EndOfEpochTransaction, .ChangeEpoch, .Genesis => true,
        else => false,
    };
}

/// The kinds the exec-system suite counts (every system kind; all of them run since round 2).
pub fn inScope(kind: *const types.TransactionKind) bool {
    return handles(kind) or kind.* == .ChangeEpoch or kind.* == .Genesis;
}

/// One input object of a shared or owned `ObjectArg` as `InputObjects` carries it.
pub fn sharedInputOf(src: Source, id: *const [32]u8, versions: []const InputVersion) ?[]const u8 {
    for (versions) |v| if (std.mem.eql(u8, &v.id, id)) return src.input(src.ctx, id, v.version);
    return null;
}

/// The version at which the transaction reads each shared input (consensus assigns it; the
/// caller supplies it: replay takes it from the checkpoint's input objects).
pub const InputVersion = struct { id: [32]u8, version: u64 };

pub fn execute(
    arena: Allocator,
    env: *const Env,
    tx_data_raw: []const u8,
    data: *const types.TransactionDataV1,
    versions: []const InputVersion,
    src: Source,
) !Outcome {
    const cfg = env.cfg;
    const ev = cfg.execution_version orelse 0;
    // Execution layers v0 to v2 panic on a ProgrammableSystemTransaction; v3 runs it as a
    // System-mode PTB (not accumulator settlement), which this module does not model.
    if (ev < 3 and data.kind == .ProgrammableSystemTransaction) return error.InvariantViolation; // Rust panics
    if (ev == 3 and data.kind == .ProgrammableSystemTransaction) return .{ .unsupported = "ProgrammableSystemTransaction on execution version 3 (a System-mode PTB)" };
    // Execution layer v0 panics on both kinds, v1 on RandomnessStateUpdate; v1 runs
    // AuthenticatorStateUpdate (mainnet enabled JWK consensus at protocol 25, execution
    // version 1) and v2 runs both, as the same system Move call with the legacy TxContext.
    if (ev == 0 and (data.kind == .RandomnessStateUpdate or data.kind == .AuthenticatorStateUpdate)) return error.InvariantViolation;
    if (ev == 1 and data.kind == .RandomnessStateUpdate) return error.InvariantViolation;
    const digest = env.tx_digest orelse types.digest.transactionDataDigest(tx_data_raw);
    var s = store.Store.init(arena, cfg, env.epoch, digest);
    switch (data.kind) {
        .ProgrammableSystemTransaction => |*pt| {
            // InputObjects: the shared inputs at their assigned versions, then the command
            // packages (deduplicated), which only add dependencies.
            for (pt.inputs) |*in| switch (in.*) {
                .Object => |*oa| switch (oa.*) {
                    .SharedObject => |sh| {
                        const raw = sharedInputOf(src, &sh.id.@"0".@"0", versions) orelse return .{ .unsupported = "shared input not available" };
                        try s.addInput(raw, switch (sh.mutability) {
                            .Mutable => .mutable,
                            .NonExclusiveWrite => .non_exclusive,
                            .Immutable => .read,
                        });
                    },
                    else => return .{ .unsupported = "settlement with an owned or receiving input" },
                },
                else => {},
            };
            var pkgs: std.ArrayList([32]u8) = .empty;
            for (pt.commands) |*cmd| switch (cmd.*) {
                .MoveCall => |*mc| {
                    try addPkg(arena, &pkgs, mc.package.@"0".@"0");
                    for (mc.type_arguments) |*t| try typePackages(arena, &pkgs, t);
                },
                else => {},
            };
            for (pkgs.items) |*id| {
                const raw = src.package(src.ctx, id) orelse return .{ .unsupported = "command package not available" };
                try s.addPackageDependency(raw);
            }
            return settlement.execute(arena, &s, &data.sender.@"0", pt, src);
        },
        .RandomnessStateUpdate => |*u| {
            // setup_randomness_state_update: random::update_randomness_state(&mut Random,
            // round, bytes, &TxContext) on the shared 0x8.
            const id = objectAddr(8);
            const raw = sharedInputOf(src, &id, versions) orelse return .{ .unsupported = "shared input not available" };
            try s.addInput(raw, .mutable);
            const round = try bcs.encodeAlloc(u64, arena, &u.randomness_round.@"0");
            const bytes = try bcs.encodeAlloc([]const u8, arena, &u.random_bytes);
            return movecall.run(arena, &s, env, src, &data.sender.@"0", &data.gas_data, &.{
                .package = objectAddr(2),
                .module = "random",
                .function = "update_randomness_state",
                .args = &.{ .{ .object = id }, .{ .pure = round }, .{ .pure = bytes } },
            });
        },
        .AuthenticatorStateUpdate => |*u| {
            // setup_authenticator_state_update: authenticator_state::update_authenticator_state(
            // &mut AuthenticatorState, new_active_jwks, &TxContext) on the shared 0x7.
            const id = objectAddr(7);
            const raw = sharedInputOf(src, &id, versions) orelse return .{ .unsupported = "shared input not available" };
            try s.addInput(raw, .mutable);
            const jwks = try bcs.encodeAlloc([]const types.ActiveJwk, arena, &u.new_active_jwks);
            return movecall.run(arena, &s, env, src, &data.sender.@"0", &data.gas_data, &.{
                .package = objectAddr(2),
                .module = "authenticator_state",
                .function = "update_authenticator_state",
                .args = &.{ .{ .object = id }, .{ .pure = jwks } },
            });
        },
        .EndOfEpochTransaction => |kinds| return epoch.execute(arena, &s, env, data, kinds, versions, src),
        // The standalone ChangeEpoch kind (before end_of_epoch_transaction_supported): the same
        // advance_epoch PTB and system package processing, alone.
        .Genesis => |*g| return .{ .done = genesis.execute(arena, env.epoch, &digest, g, cfg.feature_flags.enable_effects_v2) catch |e| switch (e) {
            error.Unsupported => return .{ .unsupported = "genesis with effects V2" },
            else => |x| return x,
        } },
        .ChangeEpoch => |ce| {
            const one = [_]types.EndOfEpochTransactionKind{.{ .ChangeEpoch = ce }};
            return epoch.execute(arena, &s, env, data, &one, versions, src);
        },
        else => return .{ .unsupported = "not a system transaction kind this module runs" },
    }
}

fn objectAddr(n: u16) [32]u8 {
    var a: [32]u8 = @splat(0);
    std.mem.writeInt(u16, a[30..32], n, .big);
    return a;
}

fn addPkg(a: Allocator, list: *std.ArrayList([32]u8), id: [32]u8) !void {
    for (list.items) |x| if (std.mem.eql(u8, &x, &id)) return;
    try list.append(a, id);
}

/// `Command::input_objects` for a MoveCall: the package and every package in its type
/// arguments (`TypeInput` addresses).
fn typePackages(a: Allocator, list: *std.ArrayList([32]u8), t: *const types.TypeInput) !void {
    switch (t.*) {
        .vector => |e| try typePackages(a, list, e),
        .@"struct" => |*st| {
            try addPkg(a, list, st.address.@"0");
            for (st.type_args) |*x| try typePackages(a, list, x);
        },
        else => {},
    }
}

test {
    std.testing.refAllDecls(@This());
}
