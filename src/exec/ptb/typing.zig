//! Loading, typing and verification of a programmable transaction
//! (`static_programmable_transactions/{loading,typing,metering}`), on move_vm runtime types.
//! The modeled subset: no reference results (a call returning a reference is unsupported),
//! no withdrawals, no Upgrade.
const std = @import("std");
const types = @import("types");
const protocol = @import("protocol");
const move_vm = @import("move_vm");
const move_format = @import("move_format");
const ff = move_format.file_format;
const objects = @import("../objects.zig");
const pkgs = @import("pkgs.zig");
const borrow = @import("borrow.zig");
const versions = @import("../versions/root.zig");

const Allocator = std.mem.Allocator;
const Type = move_vm.Type;
pub const Ty = *const Type;
const Id = pkgs.Id;
const Error = pkgs.Error;
const AbilitySet = ff.AbilitySet;

pub const Perm = enum { all, immutable, legacy_shared };

pub const ObjInput = struct {
    input: u16,
    id: Id,
    raw: []const u8,
    view: objects.ObjectView,
    ty: Ty,
    perm: Perm,
    /// Owner bytes of the input object.
    owner: types.Owner,
    pub fn canUseMutably(o: *const ObjInput) bool {
        return o.perm != .immutable;
    }
};

pub const PureLoc = struct { input: u16, ty: Ty, cmd: u16, arg: u16 };
/// A `FundsWithdrawal` input (`T::WithdrawalInput`): `Withdrawal<Balance<T>>` from `owner`, or
/// `AllowanceWithdrawal<Balance<T>>` permissioned by the `allowance` object.
pub const WdInput = struct {
    input: u16,
    ty: Ty,
    owner: Id,
    amount: u256,
    allowance: ?Id,
    /// A rewritten coin reservation (`from_compatibility_object`): converted to a `Coin<T>`.
    compat: bool = false,
};

/// A coin reservation input (`ParsedObjectRefWithdrawal`): the accumulator object id (unmasked)
/// and the amount. sui-core rewrites it into a sender `FundsWithdrawal` of `Balance<T>`, T being
/// the accumulator object's type.
pub const Reservation = struct { accumulator: Id, amount: u64 };

/// A withdrawal compatibility conversion (`T::WithdrawalCompatibilityConversion`).
pub const Conversion = struct { input: u16, result: u16, owner: Loc, inner: Ty };
pub const RecvLoc = struct { input: u16, ty: Ty, cmd: u16, arg: u16, id: Id, version: u64 };

pub const Loc = union(enum) {
    tx_context,
    gas,
    object: u16,
    withdrawal: u16,
    pure: u16,
    receiving: u16,
    result: [2]u16,

    pub fn eql(a: Loc, b: Loc) bool {
        return std.meta.eql(a, b);
    }
};

pub const ArgKind = enum { use, borrow, read, freeze };

pub const Arg = struct {
    idx: u16,
    kind: ArgKind,
    /// use/read/freeze: the usage moves (else copies).
    move: bool = false,
    /// borrow: mutable.
    mut: bool = false,
    /// copy: the location was borrowed when copied (memory_safety marker).
    borrowed: bool = false,
    loc: Loc,
    ty: Ty,
};

pub const Call = struct {
    pkg: *pkgs.Pkg,
    module: []const u8,
    name: []const u8,
    func: *const move_vm.Function,
    ty_args: []const Ty,
    params: []const Ty,
    returns: []const Ty,
    visibility: ff.Visibility,
    is_entry: bool,
    linkage_entries: usize,
    /// The call's own linkage (`compute_call_linkage`): what it runs under when the unified
    /// linkage is off.
    linkage: []const [2]Id,
};

pub const CmdTag = enum { call, transfer, split, merge, make_vec, publish, upgrade };

/// A `Publish` command as loaded (`L::Command::Publish` with a deserialized payload under the
/// unified linkage): the signed module bytes, their deserialized modules (self address 0x0),
/// the dependencies and `compute_publication_linkage`.
pub const Publish = struct {
    modules: []const []const u8,
    cms: []const ff.CompiledModule,
    deps: []const Id,
    /// (original id, version id) sorted by original id.
    linkage: []const [2]Id,
    /// `linkage_resolution.len()` (all versions table) for the loading meter.
    linkage_entries: usize,
    total_bytes: u64,
    /// `modules_with_init` is not empty.
    has_init: bool,
    /// `modules_with_init`: the modules defining a function named `init`, sorted by name.
    init_modules: []const []const u8 = &.{},
    /// Upgrade: the package being upgraded (`current_package_id`).
    current: ?Id = null,
    /// `MovePackage::compute_digest_for_modules_and_deps(modules, deps, true)`.
    digest: [32]u8 = @splat(0),
};

pub const Cmd = struct {
    tag: CmdTag,
    /// `Command__::arguments` order (transfer: objects then recipient; split/merge: coin then
    /// amounts/coins).
    args: []Arg = &.{},
    call: ?*Call = null,
    publish: ?*Publish = null,
    /// split/merge: the coin type; make_vec: the element type.
    ty: ?Ty = null,
    results: []const Ty = &.{},
    drop: []bool = &.{},
    post_checks: bool = false,
    /// The command index errors report (`Spanned::idx`): the signed command's index; 0 for
    /// injected conversions; the last index for appended returns.
    annot: u16 = 0,
};

const InputKind = union(enum) { pure, receiving, object: u16, withdrawal: u16 };

pub const Ptb = struct {
    arena: Allocator,
    cfg: *const protocol.ProtocolConfig,
    linker: *pkgs.Linker,
    diag: *pkgs.Diag,
    meter: *move_vm.Meter,
    pt: *const types.ProgrammableTransaction,
    /// Object inputs in input order.
    objects: std.ArrayList(ObjInput) = .empty,
    kinds: []InputKind = &.{},
    withdrawals: std.ArrayList(WdInput) = .empty,
    /// The transaction's sender and sponsor (withdrawal owners).
    sender: Id = @splat(0),
    sponsor: ?Id = null,
    /// Per input: a coin reservation to rewrite (empty when the transaction has none).
    reservations: []const ?Reservation = &.{},
    /// Coin types `T` of the `Balance<T>` accumulators the store holds for this transaction
    /// (`resolve_funds_withdrawal` reads the accumulator object's type from the store; replay
    /// reads the type of the accumulator objects the certified effects name). A candidate only:
    /// the reservation's accumulator id is re-derived from it.
    accumulator_types: []const types.TypeTag = &.{},
    /// Inputs appended by the conversion (owner addresses), after the signed inputs.
    extra_pure: std.ArrayList([]const u8) = .empty,
    conversions: std.ArrayList(Conversion) = .empty,
    /// Conversion commands in front of the signed commands (`WithdrawalCompatibilityRemap::lift`).
    lift: u16 = 0,
    pure: std.ArrayList(PureLoc) = .empty,
    receiving: std.ArrayList(RecvLoc) = .empty,
    cmds: std.ArrayList(Cmd) = .empty,
    unified: []const [2]Id = &.{},
    gas_ty: Ty = undefined,
    tx_ctx_ty: Ty = undefined,
    /// Typing context: the command being typed.
    current: u16 = 0,
    /// `execution_mode::DevInspect<true>` (`Inputs.skip_all_checks`): `allow_arbitrary_values`
    /// and `allow_arbitrary_function_calls` answer true, so the checks they gate are skipped
    /// (object input owners, pure input types and bytes, reference returns, visibility, unused
    /// values without drop, hot arguments to private entry functions). Off for every other mode.
    skip_checks: bool = false,

    fn rt(p: *Ptb) *move_vm.Runtime {
        return p.linker.cache.rt;
    }

    fn deduct(p: *Ptb, amount: u64, command: ?u64) Error!void {
        p.meter.deductGas(amount) catch return p.diag.failWith(.InsufficientGas, command);
    }

    fn fail(p: *Ptb, kind: types.ExecutionErrorKind) error{Fail} {
        return p.diag.failWith(kind, null);
    }

    /// The bytes of a pure input (signed, or appended by the conversion).
    pub fn pureBytes(p: *const Ptb, input: u16) []const u8 {
        if (input < p.pt.inputs.len) return p.pt.inputs[input].Pure;
        return p.extra_pure.items[input - p.pt.inputs.len];
    }

    /// The error command index of command position `ci`.
    pub fn annot(p: *const Ptb, ci: usize) u16 {
        return p.cmds.items[ci].annot;
    }

    fn argErr(p: *Ptb, idx: usize, kind: types.CommandArgumentError) error{Fail} {
        return p.fail(.{ .CommandArgumentError = .{ .arg_idx = @intCast(idx), .kind = kind } });
    }
};

// ---------------------------------------------------------------------------------------------
// Types

fn short(addr: *const Id) ?u16 {
    for (addr[0..30]) |b| if (b != 0) return null;
    return std.mem.readInt(u16, addr[30..32], .big);
}

pub fn isDt(t: Ty, addr: u16, module: []const u8, name: []const u8) bool {
    const d = switch (t.*) {
        .datatype => |d| d,
        else => return false,
    };
    return short(&d.dt.defining_id) == addr and std.mem.eql(u8, d.dt.module.name, module) and std.mem.eql(u8, d.dt.name, name);
}

pub fn eql(a: Ty, b: Ty) bool {
    if (a == b) return true;
    return switch (a.*) {
        .vector => |x| b.* == .vector and eql(x, b.vector),
        .ref => |x| b.* == .ref and eql(x, b.ref),
        .mut_ref => |x| b.* == .mut_ref and eql(x, b.mut_ref),
        .datatype => |x| blk: {
            if (b.* != .datatype) break :blk false;
            const y = b.datatype;
            if (x.dt != y.dt and !(std.mem.eql(u8, &x.dt.defining_id, &y.dt.defining_id) and
                std.mem.eql(u8, x.dt.module.name, y.dt.module.name) and std.mem.eql(u8, x.dt.name, y.dt.name))) break :blk false;
            if (x.args.len != y.args.len) break :blk false;
            for (x.args, y.args) |p, q| if (!eql(p, q)) break :blk false;
            break :blk true;
        },
        .param => false,
        else => std.meta.activeTag(a.*) == std.meta.activeTag(b.*),
    };
}

pub fn abilities(t: Ty) AbilitySet {
    return switch (t.*) {
        .bool, .u8, .u16, .u32, .u64, .u128, .u256, .address => AbilitySet.PRIMITIVES,
        .signer => AbilitySet.SIGNER,
        .ref, .mut_ref => AbilitySet.REFERENCES,
        .vector => |e| AbilitySet.polymorphic(AbilitySet.VECTOR, &.{.{ .constraints = AbilitySet.EMPTY, .is_phantom = false }}, &.{abilities(e)}),
        .datatype => |d| blk: {
            const h = handleOf(d.dt);
            var args: [32]AbilitySet = undefined;
            if (d.args.len > args.len) break :blk AbilitySet.EMPTY;
            for (d.args, 0..) |a, i| args[i] = abilities(a);
            break :blk AbilitySet.polymorphic(h.abilities, h.type_parameters, args[0..d.args.len]);
        },
        .param => AbilitySet.EMPTY,
    };
}

fn handleOf(dt: *const move_vm.loader.Datatype) ff.DatatypeHandle {
    const cm = &dt.module.cm;
    const hi = if (dt.is_enum) cm.enum_defs[dt.def_idx].enum_handle else cm.struct_defs[dt.def_idx].struct_handle;
    return cm.datatype_handles[hi];
}

pub fn nodeCount(t: Ty) u64 {
    return switch (t.*) {
        .vector => |e| 1 + nodeCount(e),
        .ref, .mut_ref => |e| 1 + nodeCount(e),
        .datatype => |d| blk: {
            var n: u64 = 1;
            for (d.args) |a| n +|= nodeCount(a);
            break :blk n;
        },
        else => 1,
    };
}

pub fn isRef(t: Ty) bool {
    return t.* == .ref or t.* == .mut_ref;
}

pub fn inner(t: Ty) Ty {
    return switch (t.*) {
        .ref, .mut_ref => |i| i,
        else => t,
    };
}

pub const TxCtxKind = enum { none, mutable, immutable };

pub fn txContextKind(t: Ty) TxCtxKind {
    return switch (t.*) {
        .ref => |i| if (isDt(i, 2, "tx_context", "TxContext")) .immutable else .none,
        .mut_ref => |i| if (isDt(i, 2, "tx_context", "TxContext")) .mutable else .none,
        else => .none,
    };
}

/// `Type::all_addresses`: defining ids, the datatype first then its arguments (IndexSet).
pub fn addresses(arena: Allocator, t: Ty, out: *std.ArrayList(Id)) Allocator.Error!void {
    switch (t.*) {
        .vector, .ref, .mut_ref => |e| try addresses(arena, e, out),
        .datatype => |d| {
            for (out.items) |x| {
                if (std.mem.eql(u8, &x, &d.dt.defining_id)) break;
            } else try out.append(arena, d.dt.defining_id);
            for (d.args) |a| try addresses(arena, a, out);
        },
        else => {},
    }
}

pub fn coinInner(t: Ty) ?Ty {
    if (!isDt(t, 2, "coin", "Coin")) return null;
    if (t.datatype.args.len != 1) return null;
    return t.datatype.args[0];
}

fn mk(arena: Allocator, t: Type) Allocator.Error!Ty {
    const out = try arena.create(Type);
    out.* = t;
    return out;
}

/// A datatype by defining id (the address in a type tag), through the package store.
fn datatypeByDefining(p: *Ptb, defining: *const Id, module: []const u8, name: []const u8) Error!*move_vm.loader.Datatype {
    const pkg = try p.linker.pkg(defining);
    _ = p.linker.cache.load(pkg) catch return p.diag.unsupported("package does not load");
    return p.rt().findDatatype(&pkg.original_id, module, name) catch p.diag.unsupported("datatype not found");
}

/// A runtime type from a type tag (struct addresses are defining ids).
pub fn fromTag(p: *Ptb, tag: *const types.TypeTag) Error!Ty {
    return switch (tag.*) {
        .bool => &Type.t_bool,
        .u8 => &Type.t_u8,
        .u16 => &Type.t_u16,
        .u32 => &Type.t_u32,
        .u64 => &Type.t_u64,
        .u128 => &Type.t_u128,
        .u256 => &Type.t_u256,
        .address => &Type.t_address,
        .signer => &Type.t_signer,
        .vector => |e| try mk(p.arena, .{ .vector = try fromTag(p, e) }),
        .@"struct" => |*st| try fromStruct(p, st),
    };
}

pub fn fromStruct(p: *Ptb, st: *const types.StructTag) Error!Ty {
    const dt = try datatypeByDefining(p, &st.address.@"0", st.module.@"0", st.name.@"0");
    if (dt.n_type_params != st.type_args.len) return p.diag.unsupported("type argument arity");
    const args = try p.arena.alloc(Ty, st.type_args.len);
    for (st.type_args, args) |*a, *o| o.* = try fromTag(p, a);
    return mk(p.arena, .{ .datatype = .{ .dt = dt, .args = args } });
}

/// Which adapter call loads a type input: a Move call's type argument
/// (`convert_type_argument_error`) or a MakeMoveVec element type (v0..v2 `convert_vm_error`).
pub const TypeSite = enum { call, vec };

/// `load_type_input`: struct addresses go through the package's type origin table.
pub fn fromInput(p: *Ptb, idx: usize, ti: *const types.TypeInput) Error!Ty {
    return fromInputAt(p, idx, ti, .call);
}

/// `fromInput` for a type loaded at `site`. The dynamic executor's cuts (v0 to v3 dynamic) load
/// type tags with the old `load_type` (context.rs): a missing package (`package_for_linkage`,
/// `get_package`) or a module missing from the package (the data store's `load_module`) is
/// LINKER_ERROR, a Verification status, so VMVerificationOrDeserializationError for both sites;
/// only a struct missing from a present module is TYPE_RESOLUTION_FAILURE, which a Move call
/// reports as TypeArgumentError TypeNotFound and a v0..v2 MakeMoveVec (`convert_vm_error`) as
/// VMVerificationOrDeserializationError. v3 under `better_adapter_type_resolution_errors`
/// (`resolve_datatype_names`) and the static executor report all three as TypeNotFound.
pub fn fromInputAt(p: *Ptb, idx: usize, ti: *const types.TypeInput, site: TypeSite) Error!Ty {
    return switch (ti.*) {
        .bool => &Type.t_bool,
        .u8 => &Type.t_u8,
        .u16 => &Type.t_u16,
        .u32 => &Type.t_u32,
        .u64 => &Type.t_u64,
        .u128 => &Type.t_u128,
        .u256 => &Type.t_u256,
        .address => &Type.t_address,
        .signer => &Type.t_signer,
        .vector => |e| try mk(p.arena, .{ .vector = try fromInputAt(p, idx, e, site) }),
        .@"struct" => |*si| blk: {
            const not_found: types.ExecutionErrorKind = .{ .TypeArgumentError = .{ .argument_idx = @intCast(idx), .kind = .TypeNotFound } };
            const fl = &p.cfg.feature_flags;
            const v3 = versions.executionVersion(p.cfg) >= 3;
            const legacy = versions.executorOf(p.cfg) == .dynamic and !(v3 and fl.better_adapter_type_resolution_errors);
            const linker_error: types.ExecutionErrorKind = if (legacy) .VMVerificationOrDeserializationError else not_found;
            // (a store miss is a corpus gap unless the store holds every package, as in `Linker.pkg`)
            const pkg = (try p.linker.cache.get(&si.address.@"0")) orelse
                return if (!legacy) p.fail(not_found) else if (p.linker.authoritative) p.fail(linker_error) else p.diag.unsupported("package not in corpus");
            const defining = for (pkg.type_origins) |o| {
                if (std.mem.eql(u8, o.module, si.module.@"0") and std.mem.eql(u8, o.name, si.name.@"0")) break o.defining;
            } else {
                if (!legacy) return p.fail(not_found);
                for (pkg.modules) |m| {
                    if (std.mem.eql(u8, m.name, si.module.@"0")) break;
                } else return p.fail(linker_error);
                // TYPE_RESOLUTION_FAILURE. v3 MakeMoveVec converts it as a type argument (index 0)
                // under `convert_type_argument_error`, or in `to_type_tag` under
                // `resolve_type_input_ids_to_defining_id`, which reports index 0 for a call too.
                const v3_resolve = v3 and fl.resolve_type_input_ids_to_defining_id;
                if (site == .vec and !(v3 and (fl.convert_type_argument_error or v3_resolve))) return p.fail(.VMVerificationOrDeserializationError);
                const at: usize = if (v3_resolve) 0 else idx;
                return p.fail(.{ .TypeArgumentError = .{ .argument_idx = @intCast(at), .kind = .TypeNotFound } });
            };
            const args = try p.arena.alloc(Ty, si.type_args.len);
            for (si.type_args, args) |*a, *o| o.* = try fromInputAt(p, idx, a, site);
            const dt = try datatypeByDefining(p, &defining, si.module.@"0", si.name.@"0");
            if (dt.n_type_params != args.len) return p.diag.unsupported("type argument arity");
            break :blk try mk(p.arena, .{ .datatype = .{ .dt = dt, .args = args } });
        },
    };
}

fn typeInputAddresses(arena: Allocator, ti: *const types.TypeInput, out: *std.ArrayList(Id)) Allocator.Error!void {
    switch (ti.*) {
        .vector => |e| try typeInputAddresses(arena, e, out),
        .@"struct" => |*si| {
            try out.append(arena, si.address.@"0");
            for (si.type_args) |*a| try typeInputAddresses(arena, a, out);
        },
        else => {},
    }
}

fn tagAddresses(arena: Allocator, t: *const types.TypeTag, out: *std.ArrayList(Id)) Allocator.Error!void {
    switch (t.*) {
        .vector => |e| try tagAddresses(arena, e, out),
        .@"struct" => |*st| {
            try out.append(arena, st.address.@"0");
            for (st.type_args) |*a| try tagAddresses(arena, a, out);
        },
        else => {},
    }
}

/// The struct tag of a Move object (`MoveObjectType` into `StructTag`).
pub fn objectTag(arena: Allocator, raw: []const u8) !types.StructTag {
    var r = @import("bcs").Reader.init(raw[1..]);
    const mt = try @import("bcs").decodeFrom(types.MoveObjectType, arena, &r);
    const two: types.AccountAddress = .{ .@"0" = blk: {
        var a: Id = @splat(0);
        a[31] = 2;
        break :blk a;
    } };
    return switch (mt.@"0") {
        .Other => |st| st,
        .GasCoin => blk: {
            const sui_t = try arena.alloc(types.TypeTag, 1);
            sui_t[0] = .{ .@"struct" = .{ .address = two, .module = .{ .@"0" = "sui" }, .name = .{ .@"0" = "SUI" }, .type_args = &.{} } };
            break :blk .{ .address = two, .module = .{ .@"0" = "coin" }, .name = .{ .@"0" = "Coin" }, .type_args = sui_t };
        },
        .StakedSui => blk: {
            var three: Id = @splat(0);
            three[31] = 3;
            break :blk .{ .address = .{ .@"0" = three }, .module = .{ .@"0" = "staking_pool" }, .name = .{ .@"0" = "StakedSui" }, .type_args = &.{} };
        },
        .Coin => |t| blk: {
            const a = try arena.alloc(types.TypeTag, 1);
            a[0] = t;
            break :blk .{ .address = two, .module = .{ .@"0" = "coin" }, .name = .{ .@"0" = "Coin" }, .type_args = a };
        },
        .SuiBalanceAccumulatorField => accumulatorField(arena, two, .{ .@"struct" = .{ .address = two, .module = .{ .@"0" = "sui" }, .name = .{ .@"0" = "SUI" }, .type_args = &.{} } }),
        .BalanceAccumulatorField => |t| accumulatorField(arena, two, t),
    };
}

/// `0x2::dynamic_field::Field<0x2::accumulator::Key<0x2::balance::Balance<T>>, 0x2::accumulator::U128>`
fn accumulatorField(arena: Allocator, two: types.AccountAddress, t: types.TypeTag) !types.StructTag {
    const bal = try arena.alloc(types.TypeTag, 1);
    bal[0] = t;
    const key = try arena.alloc(types.TypeTag, 1);
    key[0] = .{ .@"struct" = .{ .address = two, .module = .{ .@"0" = "balance" }, .name = .{ .@"0" = "Balance" }, .type_args = bal } };
    const args = try arena.alloc(types.TypeTag, 2);
    args[0] = .{ .@"struct" = .{ .address = two, .module = .{ .@"0" = "accumulator" }, .name = .{ .@"0" = "Key" }, .type_args = key } };
    args[1] = .{ .@"struct" = .{ .address = two, .module = .{ .@"0" = "accumulator" }, .name = .{ .@"0" = "U128" }, .type_args = &.{} } };
    return .{ .address = two, .module = .{ .@"0" = "dynamic_field" }, .name = .{ .@"0" = "Field" }, .type_args = args };
}

// ---------------------------------------------------------------------------------------------
// Loading (loading/translate.rs) with the pre-translation and loading meters

pub const ObjSource = struct {
    /// Shared inputs: whether the transaction may use them mutably.
    raw: []const u8,
    shared_mutable: ?bool,
};

pub fn load(p: *Ptb, srcs: []const ?ObjSource) Error!void {
    const cfg = p.cfg;
    const pt = p.pt;
    // pre_translation meter
    try p.deduct(@max(pt.inputs.len, 1) * (cfg.getOpt("translation_per_input_base_charge") orelse 0), null);
    for (pt.inputs) |*a| switch (a.*) {
        .Pure => |b| try p.deduct(@max(b.len, 1) * (cfg.getOpt("translation_pure_input_per_byte_charge") orelse 0), null),
        else => {},
    };
    const per_cmd = cfg.getOpt("translation_per_command_base_charge") orelse 0;
    for (pt.commands) |*c| {
        const n: usize = switch (c.*) {
            .MoveCall => |*mc| mc.type_arguments.len + mc.arguments.len,
            .TransferObjects => |*t| t[0].len + 1,
            .SplitCoins => |*s| s[1].len + 1,
            .MergeCoins => |*m| m[1].len + 1,
            .MakeMoveVec => |*m| m[1].len + 1,
            .Publish => |*x| x[0].len + x[1].len,
            .Upgrade => |*x| x[0].len + x[1].len + 2,
        };
        try p.deduct(@max(n, 1) * per_cmd, null);
    }

    // inputs
    p.kinds = try p.arena.alloc(InputKind, pt.inputs.len);
    for (pt.inputs, 0..) |*a, i| {
        switch (a.*) {
            .Pure => p.kinds[i] = .pure,
            .Object => |*oa| switch (oa.*) {
                .Receiving => p.kinds[i] = .receiving,
                .ImmOrOwnedObject, .SharedObject => {
                    if (p.reservations.len > 0) if (p.reservations[i]) |res| {
                        // the type is the accumulator object's, resolved once the commands load
                        p.kinds[i] = .{ .withdrawal = @intCast(p.withdrawals.items.len) };
                        try p.withdrawals.append(p.arena, .{ .input = @intCast(i), .ty = &Type.t_bool, .owner = p.sender, .amount = res.amount, .allowance = null, .compat = true });
                        continue;
                    };
                    const src = srcs[i].?;
                    const view = objects.ObjectView.parse(src.raw) catch return p.diag.unsupported("input object does not parse");
                    if (view.is_package) return p.diag.unsupported("package as object input");
                    const tag = objectTag(p.arena, src.raw) catch return p.diag.unsupported("accumulator object input");
                    const ty = try fromStruct(p, &tag);
                    const owner = @import("bcs").decode(types.Owner, p.arena, src.raw[view.owner_at..view.prev_tx_at]) catch return p.diag.unsupported("owner does not decode");
                    // loading/translate.rs `input`: an owner the argument kind does not expect is
                    // `assert_invariant!(Mode::allow_arbitrary_values(), ..)`, and then used with
                    // every permission (a Party owner's permissions are not modeled).
                    const perm: Perm = if (src.shared_mutable) |m| blk: {
                        if (!m) break :blk .immutable;
                        break :blk switch (owner) {
                            .Shared => .legacy_shared,
                            .ConsensusAddressOwner => .all,
                            .AddressOwner, .ObjectOwner, .Immutable => if (p.skip_checks) .all else return p.diag.unsupported("shared input owner"),
                            else => return p.diag.unsupported("shared input owner"),
                        };
                    } else switch (owner) {
                        .AddressOwner => .all,
                        .Immutable => .immutable,
                        .ObjectOwner, .Shared, .ConsensusAddressOwner => if (p.skip_checks) .all else return p.diag.unsupported("owned input owner"),
                        else => return p.diag.unsupported("owned input owner"),
                    };
                    p.kinds[i] = .{ .object = @intCast(p.objects.items.len) };
                    try p.objects.append(p.arena, .{ .input = @intCast(i), .id = view.id, .raw = src.raw, .view = view, .ty = ty, .perm = perm, .owner = owner });
                },
            },
            .FundsWithdrawal => |*f| {
                // loading/translate.rs `input`: the fixed type by withdrawal source
                if (!cfg.feature_flags.enable_accumulators) return p.diag.unsupported("withdrawal without accumulators");
                const amount: u256 = switch (f.reservation) {
                    .MaxAmountU64 => |u| u,
                };
                const inner_ty = switch (f.type_arg) {
                    .Balance => |*t| try fromTag(p, t),
                };
                const bal = try frameworkOf(p, "balance", "Balance", inner_ty);
                var owner: Id = p.sender;
                var allowance: ?Id = null;
                switch (f.withdraw_from) {
                    .Sender => {},
                    .Sponsor => owner = p.sponsor orelse return p.diag.unsupported("sponsor withdrawal without a sponsor"),
                    .SenderAllowance => |sa| {
                        owner = sa.funder.@"0";
                        allowance = sa.allowance.@"0".@"0";
                    },
                }
                const ty = if (allowance == null)
                    try frameworkOf(p, "funds_accumulator", "Withdrawal", bal)
                else
                    try frameworkOf(p, "allowance", "AllowanceWithdrawal", bal);
                p.kinds[i] = .{ .withdrawal = @intCast(p.withdrawals.items.len) };
                try p.withdrawals.append(p.arena, .{ .input = @intCast(i), .ty = ty, .owner = owner, .amount = amount, .allowance = allowance });
            },
        }
    }

    // input type resolution linkage (make_vm for the input types)
    {
        var t = try p.linker.withNatives();
        var ids: std.ArrayList(Id) = .empty;
        for (p.kinds) |k| switch (k) {
            .object => |oi| {
                const o = &p.objects.items[oi];
                ids.clearRetainingCapacity();
                const tag = objectTag(p.arena, o.raw) catch unreachable;
                const tt: types.TypeTag = .{ .@"struct" = tag };
                try tagAddresses(p.arena, &tt, &ids);
                try p.linker.addTypeLinkages(&t, ids.items);
            },
            .withdrawal => |wi| if (!p.withdrawals.items[wi].compat) {
                // the Balance type argument's addresses
                ids.clearRetainingCapacity();
                switch (pt.inputs[p.withdrawals.items[wi].input].FundsWithdrawal.type_arg) {
                    .Balance => |*tt| try tagAddresses(p.arena, tt, &ids),
                }
                try p.linker.addTypeLinkages(&t, ids.items);
            },
            else => {},
        };
        for (pt.commands) |*c| switch (c.*) {
            .MoveCall => |*mc| {
                ids.clearRetainingCapacity();
                for (mc.type_arguments) |*ta| try typeInputAddresses(p.arena, ta, &ids);
                try p.linker.addTypeLinkages(&t, ids.items);
                try p.linker.addTypeLinkages(&t, &.{mc.package.@"0".@"0"});
            },
            .MakeMoveVec => |*m| if (m[0]) |*ta| {
                ids.clearRetainingCapacity();
                try typeInputAddresses(p.arena, ta, &ids);
                try p.linker.addTypeLinkages(&t, ids.items);
            },
            .Publish => |*x| {
                ids.clearRetainingCapacity();
                for (x[1]) |d| try ids.append(p.arena, d.@"0".@"0");
                try p.linker.addTypeLinkages(&t, ids.items);
            },
            .Upgrade => |*x| {
                try p.linker.addTypeLinkages(&t, &.{x[2].@"0".@"0"});
                ids.clearRetainingCapacity();
                for (x[1]) |d| try ids.append(p.arena, d.@"0".@"0");
                try p.linker.addTypeLinkages(&t, ids.items);
            },
            else => {},
        };
        const linkage = try pkgs.resolved(p.arena, &t);
        try checkLinkage(p, linkage);
    }

    p.gas_ty = try coinOf(p, try sui(p));
    p.tx_ctx_ty = try mk(p.arena, .{ .datatype = .{ .dt = try p.rt().findDatatype(&framework(2), "tx_context", "TxContext"), .args = &.{} } });

    // commands
    for (pt.commands, 0..) |*c, ci| {
        const cmd = loadCommand(p, c) catch |e| {
            if (e == error.Fail and p.diag.fail.command == null) p.diag.fail.command = ci;
            return e;
        };
        try p.cmds.append(p.arena, cmd);
        p.cmds.items[p.cmds.items.len - 1].annot = @intCast(ci);
    }
    try reservationTypes(p);

    // loading meter
    const node = cfg.getOpt("translation_per_type_node_charge") orelse 0;
    for (p.kinds) |k| switch (k) {
        .object => |oi| try p.deduct(@max(nodeCount(p.objects.items[oi].ty), 1) * node, null),
        .withdrawal => |wi| try p.deduct(@max(nodeCount(p.withdrawals.items[wi].ty), 1) * node, null),
        else => {},
    };
    for (p.cmds.items) |*c| {
        if (c.call) |call| {
            for (call.ty_args) |t| try p.deduct(@max(nodeCount(t), 1) * node, null);
            for (call.params) |t| try p.deduct(@max(nodeCount(t), 1) * node, null);
            for (call.returns) |t| try p.deduct(@max(nodeCount(t), 1) * node, null);
        } else if (c.tag == .make_vec) if (c.ty) |t| try p.deduct(@max(nodeCount(t), 1) * node, null);
    }
    const per_link = cfg.getOpt("translation_per_linkage_entry_charge") orelse 0;
    for (p.cmds.items) |*c| {
        if (c.call) |call| try p.deduct(@max(call.linkage_entries * per_link, 1), null);
        if (c.publish) |pb| try p.deduct(@max(pb.linkage_entries * per_link, 1), null);
    }
    // charge_package_load: the gas charger's charge_publish_package (deserialized payloads)
    for (p.cmds.items) |*c| if (c.publish) |pb| {
        p.meter.chargeBytes(pb.total_bytes, cfg.getOpt("package_publish_cost_per_byte") orelse return p.diag.unsupported("no package_publish_cost_per_byte")) catch return p.diag.failWith(.InsufficientGas, null);
    };

    try refineLinkage(p);
}

/// The mainnet and testnet chain identifiers (genesis checkpoint digests): the coin reservation id
/// mask. sui-types `mask_or_unmask_id` uses the chain the transaction runs on (the protocol
/// config's chain); an unknown chain (local networks) has no fixed identifier and masks with
/// mainnet's here.
const mainnet_chain_id: Id = .{ 0x35, 0x83, 0x4a, 0x8a, 0xc1, 0x7c, 0xa4, 0x8f, 0xb1, 0x4a, 0xc8, 0xf9, 0x9c, 0x17, 0xc9, 0x87, 0x47, 0xe9, 0x5d, 0xd0, 0x72, 0x94, 0xae, 0x41, 0xa4, 0x6b, 0x38, 0x22, 0x46, 0xa4, 0x49, 0x9b };
const testnet_chain_id: Id = .{ 0x4c, 0x78, 0xad, 0xac, 0xf2, 0xa2, 0xf5, 0xad, 0x80, 0xf2, 0x7e, 0xd7, 0xd5, 0x4a, 0xa6, 0x9d, 0x3a, 0x78, 0xf1, 0xca, 0x67, 0xfd, 0xef, 0x9e, 0xcf, 0x57, 0x54, 0xf5, 0xb8, 0xbb, 0x77, 0xb0 };

/// `mask_or_unmask_id` with the chain identifier of `chain`.
pub fn unmaskReservation(chain: protocol.Chain, id: *const Id) Id {
    const mask = if (chain == .testnet) &testnet_chain_id else &mainnet_chain_id;
    var out: Id = undefined;
    for (&out, id, mask) |*o, a, b| o.* = a ^ b;
    return out;
}

/// `AccumulatorValue::get_field_id(owner, Balance<T>)` for a runtime type `T`.
fn balanceFieldId(p: *Ptb, owner: *const Id, t: Ty) Error!Id {
    const inner_tag = try move_vm.host.typeTag(p.arena, t, .defining);
    const two: types.AccountAddress = .{ .@"0" = framework(2) };
    const bal_args = try p.arena.alloc(types.TypeTag, 1);
    bal_args[0] = inner_tag.*;
    const key_args = try p.arena.alloc(types.TypeTag, 1);
    key_args[0] = .{ .@"struct" = .{ .address = two, .module = .{ .@"0" = "balance" }, .name = .{ .@"0" = "Balance" }, .type_args = bal_args } };
    const key: types.TypeTag = .{ .@"struct" = .{ .address = two, .module = .{ .@"0" = "accumulator" }, .name = .{ .@"0" = "Key" }, .type_args = key_args } };
    const tag = try @import("bcs").encodeAlloc(types.TypeTag, p.arena, &key);
    var root: Id = @splat(0);
    root[30] = 0x0a;
    root[31] = 0xcc;
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, 32, .little);
    return @import("hash").blake2b256(&.{ &[_]u8{0xf0}, &root, &len_le, owner, tag });
}

fn typeCandidates(p: *Ptb, out: *std.ArrayList(Ty), t: Ty) Allocator.Error!void {
    switch (t.*) {
        .datatype => |d| {
            try out.append(p.arena, t);
            for (d.args) |a| try typeCandidates(p, out, a);
        },
        .vector, .ref, .mut_ref => |e| try typeCandidates(p, out, e),
        else => {},
    }
}

/// The coin reservations' `Balance<T>`: the T whose balance accumulator field id under the
/// sender is the reservation's accumulator object (SUI, or a type the transaction names).
fn reservationTypes(p: *Ptb) Error!void {
    var cands: std.ArrayList(Ty) = .empty;
    var have = false;
    for (p.withdrawals.items) |*w| if (w.compat) {
        if (!have) {
            have = true;
            try cands.append(p.arena, try sui(p));
            for (p.cmds.items) |*c| {
                if (c.call) |call| for (call.ty_args) |t| try typeCandidates(p, &cands, t);
                if (c.tag == .make_vec) if (c.ty) |t| try typeCandidates(p, &cands, t);
            }
            for (p.objects.items) |*o| try typeCandidates(p, &cands, o.ty);
        }
        const want = p.reservations[w.input].?.accumulator;
        const inner_ty = for (cands.items) |t| {
            if (std.mem.eql(u8, &(try balanceFieldId(p, &w.owner, t)), &want)) break t;
        } else for (p.accumulator_types) |*tag| {
            const t = try fromTag(p, tag);
            if (std.mem.eql(u8, &(try balanceFieldId(p, &w.owner, t)), &want)) break t;
        } else return p.diag.unsupported("coin reservation of a type the transaction does not name");
        w.ty = try frameworkOf(p, "funds_accumulator", "Withdrawal", try frameworkOf(p, "balance", "Balance", inner_ty));
    };
}

fn framework(b: u8) Id {
    var id: Id = @splat(0);
    id[31] = b;
    return id;
}

fn sui(p: *Ptb) Error!Ty {
    return mk(p.arena, .{ .datatype = .{ .dt = p.rt().findDatatype(&framework(2), "sui", "SUI") catch return p.diag.unsupported("framework"), .args = &.{} } });
}

/// `0x2::<module>::<name><t>`.
fn frameworkOf(p: *Ptb, module: []const u8, name: []const u8, t: Ty) Error!Ty {
    const args = try p.arena.alloc(Ty, 1);
    args[0] = t;
    return mk(p.arena, .{ .datatype = .{ .dt = try datatypeByDefining(p, &framework(2), module, name), .args = args } });
}

fn coinOf(p: *Ptb, t: Ty) Error!Ty {
    const args = try p.arena.alloc(Ty, 1);
    args[0] = t;
    return mk(p.arena, .{ .datatype = .{ .dt = p.rt().findDatatype(&framework(2), "coin", "Coin") catch return p.diag.unsupported("framework"), .args = args } });
}

/// `make_vm` for a linkage: every package loads and validates.
fn checkLinkage(p: *Ptb, linkage: []const [2]Id) Error!void {
    for (linkage) |l| {
        const pkg = try p.linker.pkg(&l[1]);
        const v = p.linker.cache.load(pkg) catch return p.diag.unsupported("package does not load");
        if (v.refused != null) return p.diag.unsupported("package refused by the loader");
    }
}

fn loadCommand(p: *Ptb, c: *const types.Command) Error!Cmd {
    return switch (c.*) {
        .MoveCall => |*mc| .{ .tag = .call, .call = try loadFunction(p, mc) },
        .MakeMoveVec => |*m| .{ .tag = .make_vec, .ty = if (m[0]) |*ta| try fromInput(p, 0, ta) else null },
        .TransferObjects => .{ .tag = .transfer },
        .SplitCoins => .{ .tag = .split },
        .MergeCoins => .{ .tag = .merge },
        .Publish => |*x| .{ .tag = .publish, .publish = try loadPublish(p, x[0], x[1]) },
        .Upgrade => |*x| blk: {
            const pb = try loadPublish(p, x[0], x[1]);
            pb.current = x[2].@"0".@"0";
            pb.digest = try packageDigest(p.arena, x[0], pb.deps);
            break :blk .{ .tag = .upgrade, .publish = pb };
        },
    };
}

/// loading/translate.rs `Publish`: `compute_publication_linkage` (the native packages, then each
/// dependency exact) and, under the unified linkage, `Env::deserialize_package`.
fn loadPublish(p: *Ptb, modules: []const []const u8, deps: []const types.ObjectID) Error!*Publish {
    if (!p.cfg.feature_flags.enable_unified_linkage) return p.diag.unsupported("publish without the unified linkage");
    if (modules.len == 0) return p.diag.unsupported("empty package");
    var t = try p.linker.withNatives();
    const dep_ids = try p.arena.alloc(Id, deps.len);
    for (deps, dep_ids) |d, *o| {
        o.* = d.@"0".@"0";
        try p.linker.addAndUnify(&t, &o.*, true);
    }
    const binary = &p.linker.cache.rt.binary;
    const cms = try p.arena.alloc(ff.CompiledModule, modules.len);
    var total: u64 = 0;
    var inits: std.ArrayList([]const u8) = .empty;
    for (modules, cms) |b, *cm| {
        total += b.len;
        cm.* = switch (try move_format.deserialize(p.arena, b, binary)) {
            .ok => |x| x,
            .err => return p.fail(.VMVerificationOrDeserializationError),
        };
        if (moduleHasInit(cm)) {
            const name = cm.selfName();
            for (inits.items) |n| {
                if (std.mem.eql(u8, n, name)) break;
            } else try inits.append(p.arena, name);
        }
    }
    std.mem.sort([]const u8, inits.items, {}, lessStr);
    const has_init = inits.items.len > 0;
    const pb = try p.arena.create(Publish);
    pb.* = .{
        .modules = modules,
        .cms = cms,
        .deps = dep_ids,
        .linkage = try pkgs.resolved(p.arena, &t),
        .linkage_entries = t.all.count(),
        .total_bytes = total,
        .has_init = has_init,
        .init_modules = inits.items,
    };
    return pb;
}

/// `module_has_init`: the module defines a function named `init`.
pub fn moduleHasInit(cm: *const ff.CompiledModule) bool {
    for (cm.function_defs) |fd| {
        if (std.mem.eql(u8, cm.identifierAt(cm.function_handles[fd.function].name), "init")) return true;
    }
    return false;
}

fn lessStr(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// `MovePackage::compute_digest_for_modules_and_deps` with hashed modules: Blake2b-256 over the
/// sorted module digests and dependency ids.
pub fn packageDigest(arena: Allocator, modules: []const []const u8, deps: []const Id) Allocator.Error![32]u8 {
    const hash = @import("hash");
    const parts = try arena.alloc([]const u8, modules.len + deps.len);
    const digests = try arena.alloc([32]u8, modules.len);
    for (modules, digests, 0..) |m, *d, i| {
        d.* = hash.blake2b256(&.{m});
        parts[i] = d;
    }
    for (deps, 0..) |*d, i| parts[modules.len + i] = d;
    std.mem.sort([]const u8, parts, {}, lessStr);
    return hash.blake2b256(parts);
}

fn fdefOf(f: *const move_vm.Function) *const ff.FunctionDefinition {
    return &f.module.cm.function_defs[f.def_idx];
}

pub fn loadFunction(p: *Ptb, mc: *const types.ProgrammableMoveCall) Error!*Call {
    const ty_args = try p.arena.alloc(Ty, mc.type_arguments.len);
    for (mc.type_arguments, ty_args, 0..) |*ta, *o, i| o.* = try fromInput(p, i, ta);
    const pkg_id = mc.package.@"0".@"0";
    // compute_call_linkage (the native packages first; a memo hit skips the table)
    var t: pkgs.Table = .{};
    const pkg = try p.linker.pkg(&pkg_id);
    const vpkg = p.linker.cache.load(pkg) catch return p.diag.unsupported("package does not load");
    if (vpkg.refused != null) return p.diag.unsupported("package refused by the loader");
    // exec-history: every cut before the latest (v3 static here, the dynamic cuts through
    // versions/dynamic.zig) links a call as v3 `compute_call_linkage_` / `set_link_context`.
    const v3 = versions.executionVersion(p.cfg) < versions.latest;
    // v3: a missing module is the old VM's LINKER_ERROR from `load_module` in
    // `check_visibility_and_signature`, which `convert_vm_error` makes
    // VMVerificationOrDeserializationError (dynamic cuts; mainnet 181014257 tx[3] calls
    // `blastfun` on a package version that does not have it). Not modeled on v3 static.
    const m = vpkg.module(mc.module.@"0") orelse return if (!v3)
        p.fail(.FunctionNotFound)
    else if (versions.executorOf(p.cfg) == .dynamic)
        p.fail(.VMVerificationOrDeserializationError)
    else
        p.diag.unsupported("v3: call into a missing module");
    const func = m.functionByName(mc.function.@"0") orelse return p.fail(.FunctionNotFound);
    const fdef = fdefOf(func);
    const public = fdef.visibility == .Public;
    var linked: ?struct { []const [2]Id, usize } = null;
    if (v3) {
        // exec-history, v3 `compute_call_linkage_`: the callee's whole linkage table and the
        // callee itself pinned exact; type arguments add nothing.
        t = try p.linker.withNatives();
        try p.linker.addPackageDepsFirst(&t, &pkg_id, true, true);
        // v3 `load_type_from_struct` loads each type argument's module under its defining
        // package's linkage (`set_linkage`), so the packages its fields name are in the VM even
        // when the callee's linkage lacks them (a child type's layout for the dynamic field
        // natives, e.g. mainnet 35248749 tx[75]).
        var ids: std.ArrayList(Id) = .empty;
        for (ty_args) |ta| try addresses(p.arena, ta, &ids);
        for (ids.items) |*id| try checkLinkage(p, (try p.linker.pkg(id)).linkage);
    } else {
        // compute_call_linkage is a function of the callee, its visibility and the type
        // arguments' packages (fixed per epoch cache): memoized per that key.
        var ids: std.ArrayList(Id) = .empty;
        for (ty_args) |ta| try addresses(p.arena, ta, &ids);
        var key: std.ArrayList(u8) = .empty;
        try key.append(p.arena, if (public) 0x43 else 0x44);
        try key.appendSlice(p.arena, &pkg_id);
        for (ids.items) |*id| try key.appendSlice(p.arena, id);
        if (p.linker.cache.link_memo.get(key.items)) |hit| {
            linked = .{ hit.linkage, hit.entries };
        } else {
            t = try p.linker.withNatives();
            try p.linker.addPackageDepsFirst(&t, &pkg_id, true, !public);
            for (ids.items) |*id| try p.linker.addPackageDepsFirst(&t, id, false, false);
            const lk = try pkgs.resolved(p.arena, &t);
            try checkLinkage(p, lk);
            try p.linker.cache.memoLink(key.items, lk, t.all.count());
            linked = .{ lk, t.all.count() };
        }
    }
    const linkage = if (linked) |l| l[0] else try pkgs.resolved(p.arena, &t);
    if (linked == null) try checkLinkage(p, linkage);
    if (func.n_type_params != ty_args.len) return p.fail(.VMVerificationOrDeserializationError);
    for (ty_args, 0..) |ta, i| {
        const want = m.cm.function_handles[fdef.function].type_parameters[i];
        if (!want.isSubset(abilities(ta))) return p.fail(.VMVerificationOrDeserializationError);
    }
    const params = try move_vm.types.instantiateAll(p.arena, func.module, func.params, ty_args);
    const returns = try move_vm.types.instantiateAll(p.arena, func.module, func.returns, ty_args);
    const call = try p.arena.create(Call);
    call.* = .{
        .pkg = pkg,
        .module = mc.module.@"0",
        .name = mc.function.@"0",
        .func = func,
        .ty_args = ty_args,
        .params = params,
        .returns = returns,
        .visibility = fdef.visibility,
        .is_entry = fdef.is_entry,
        .linkage_entries = if (linked) |l| l[1] else t.all.count(),
        .linkage = linkage,
    };
    return call;
}

/// The linker operations of `refineLinkage` for a transaction without Publish/Upgrade, in
/// order (`ci`: the command an error is attributed to, null after the command loop). The bytes
/// of `key` name the sequence: the unified linkage is a function of it (packages are fixed per
/// epoch cache), so `pkgs.Cache.link_memo` keeps the result per sequence.
const LinkOps = struct {
    const Op = struct { ci: ?usize, self: bool, id: Id = undefined, dep_exact: bool = false, lo: u32 = 0, hi: u32 = 0 };
    ops: std.ArrayList(Op) = .empty,
    ids: std.ArrayList(Id) = .empty,
    key: std.ArrayList(u8) = .empty,

    fn selfFirst(o: *LinkOps, a: Allocator, ci: usize, id: *const Id, dep_exact: bool) Allocator.Error!void {
        try o.ops.append(a, .{ .ci = ci, .self = true, .id = id.*, .dep_exact = dep_exact });
        try o.key.append(a, if (dep_exact) 2 else 1);
        try o.key.appendSlice(a, id);
    }
    fn typeLinks(o: *LinkOps, a: Allocator, ci: ?usize, ids: []const Id) Allocator.Error!void {
        const lo: u32 = @intCast(o.ids.items.len);
        try o.ids.appendSlice(a, ids);
        try o.ops.append(a, .{ .ci = ci, .self = false, .lo = lo, .hi = @intCast(o.ids.items.len) });
        try o.key.append(a, 3);
        var n: [4]u8 = undefined;
        std.mem.writeInt(u32, &n, @intCast(ids.len), .little);
        try o.key.appendSlice(a, &n);
        for (ids) |*x| try o.key.appendSlice(a, x);
    }
};

/// `refineLinkage` for a transaction without Publish/Upgrade: the same linker calls in the same
/// order (with the same error attribution), memoized per operation sequence.
fn refineLinkageMemo(p: *Ptb) Error!void {
    const a = p.arena;
    var o: LinkOps = .{};
    var seen = std.AutoHashMapUnmanaged(u16, void).empty;
    var ids: std.ArrayList(Id) = .empty;
    try o.key.appendSlice(a, &[_]u8{ 0x52, @intFromBool(p.cfg.feature_flags.harden_linkage_consistency) });
    for (p.cmds.items, p.pt.commands, 0..) |*c, *pc, ci| {
        switch (c.tag) {
            .call => {
                const call = c.call.?;
                try o.selfFirst(a, ci, &call.pkg.version_id, call.visibility != .Public);
                ids.clearRetainingCapacity();
                for (call.ty_args) |ta| try addresses(a, ta, &ids);
                try o.typeLinks(a, ci, ids.items);
            },
            .make_vec => if (c.ty) |ty| {
                ids.clearRetainingCapacity();
                try addresses(a, ty, &ids);
                try o.typeLinks(a, ci, ids.items);
            },
            .publish, .upgrade => unreachable,
            .transfer, .split, .merge => {},
        }
        if (p.cfg.feature_flags.harden_linkage_consistency) {
            for (try rawArgs(a, pc)) |arg| switch (arg) {
                .Input => |i| if (i < p.kinds.len and (p.kinds[i] == .object or p.kinds[i] == .withdrawal)) {
                    if ((try seen.getOrPut(a, i)).found_existing) continue;
                    ids.clearRetainingCapacity();
                    const fixed = switch (p.kinds[i]) {
                        .object => |oi| p.objects.items[oi].ty,
                        .withdrawal => |wi| p.withdrawals.items[wi].ty,
                        else => unreachable,
                    };
                    try addresses(a, fixed, &ids);
                    try o.typeLinks(a, ci, ids.items);
                },
                else => {},
            };
        }
    }
    if (p.cfg.feature_flags.harden_linkage_consistency) {
        for (p.withdrawals.items) |*w| if (w.compat) {
            ids.clearRetainingCapacity();
            try addresses(a, w.ty, &ids);
            try o.typeLinks(a, null, ids.items);
        };
    }
    const cache = p.linker.cache;
    if (cache.link_memo.get(o.key.items)) |hit| {
        p.unified = hit.linkage;
        return;
    }
    var t = try p.linker.withNatives();
    for (o.ops.items) |*op| {
        const r = if (op.self) p.linker.addPackageSelfFirst(&t, &op.id, true, op.dep_exact) else p.linker.addTypeLinkages(&t, o.ids.items[op.lo..op.hi]);
        r catch |e| {
            if (op.ci) |ci| if (p.diag.fail.command == null) {
                p.diag.fail.command = ci;
            };
            return e;
        };
    }
    p.unified = try pkgs.resolved(a, &t);
    try checkLinkage(p, p.unified);
    try cache.memoLink(o.key.items, p.unified, 0);
}

/// single_linkage.rs `refine_to_single_linkage` (no Publish/Upgrade here).
fn refineLinkage(p: *Ptb) Error!void {
    // Off: every call keeps its own linkage (run.zig links each call separately).
    if (!p.cfg.feature_flags.enable_unified_linkage) return;
    for (p.cmds.items) |*c| {
        if (c.tag == .publish or c.tag == .upgrade) break;
    } else return refineLinkageMemo(p);
    var t = try p.linker.withNatives();
    var seen = std.AutoHashMapUnmanaged(u16, void).empty;
    var ids: std.ArrayList(Id) = .empty;
    for (p.cmds.items, p.pt.commands, 0..) |*c, *pc, ci| {
        errdefer if (p.diag.fail.command == null) {
            p.diag.fail.command = ci;
        };
        switch (c.tag) {
            .call => {
                const call = c.call.?;
                try p.linker.addPackageSelfFirst(&t, &call.pkg.version_id, true, call.visibility != .Public);
                ids.clearRetainingCapacity();
                for (call.ty_args) |ta| try addresses(p.arena, ta, &ids);
                try p.linker.addTypeLinkages(&t, ids.items);
            },
            .make_vec => if (c.ty) |ty| {
                ids.clearRetainingCapacity();
                try addresses(p.arena, ty, &ids);
                try p.linker.addTypeLinkages(&t, ids.items);
            },
            // `init` runs with the publication linkage: its packages pinned exactly
            .publish => if (c.publish.?.has_init) for (c.publish.?.linkage) |*l| try p.linker.addAndUnify(&t, &l[1], true),
            .upgrade => if (!p.cfg.feature_flags.enable_order_independent_upgrade_init_linkage) try analyzeUpgrade(p, &t, c.publish.?),
            .transfer, .split, .merge => {},
        }
        if (p.cfg.feature_flags.harden_linkage_consistency) {
            for (try rawArgs(p.arena, pc)) |a| switch (a) {
                .Input => |i| if (i < p.kinds.len and (p.kinds[i] == .object or p.kinds[i] == .withdrawal)) {
                    if ((try seen.getOrPut(p.arena, i)).found_existing) continue;
                    ids.clearRetainingCapacity();
                    const fixed = switch (p.kinds[i]) {
                        .object => |oi| p.objects.items[oi].ty,
                        .withdrawal => |wi| p.withdrawals.items[wi].ty,
                        else => unreachable,
                    };
                    try addresses(p.arena, fixed, &ids);
                    try p.linker.addTypeLinkages(&t, ids.items);
                },
                else => {},
            };
        }
    }
    if (p.cfg.feature_flags.harden_linkage_consistency) {
        for (p.withdrawals.items) |*w| if (w.compat) {
            ids.clearRetainingCapacity();
            try addresses(p.arena, w.ty, &ids);
            try p.linker.addTypeLinkages(&t, ids.items);
        };
    }
    if (p.cfg.feature_flags.enable_order_independent_upgrade_init_linkage) {
        for (p.cmds.items, 0..) |*c, ci| if (c.tag == .upgrade) {
            analyzeUpgrade(p, &t, c.publish.?) catch |e| {
                if (e == error.Fail and p.diag.fail.command == null) p.diag.fail.command = ci;
                return e;
            };
        };
    }
    p.unified = try pkgs.resolved(p.arena, &t);
    try checkLinkage(p, p.unified);
}

/// single_linkage.rs `analyze_upgrade_command`: an existing module may not gain an `init`
/// (IncompatibleUpgrade); a new module with an `init` pins the upgrade's own linkage into the
/// transaction's (`add_upgrade_init_linkage_to_table`).
fn analyzeUpgrade(p: *Ptb, t: *pkgs.Table, pb: *const Publish) Error!void {
    if (!p.cfg.feature_flags.enable_init_on_upgrade) return;
    const cur = try p.linker.pkg(&pb.current.?);
    const vpkg = p.linker.cache.load(cur) catch return p.diag.unsupported("package does not load");
    if (vpkg.refused != null) return p.diag.unsupported("package refused by the loader");
    var new_init = false;
    for (pb.init_modules) |name| {
        if (vpkg.module(name)) |m| {
            if (!moduleHasInit(&m.cm)) return p.fail(.{ .PackageUpgradeError = .{ .upgrade_error = .IncompatibleUpgrade } });
        } else new_init = true;
    }
    if (!new_init) return;
    if (!t.res.contains(cur.original_id)) {
        for (pb.linkage) |*l| try p.linker.addAndUnify(t, &l[1], true);
        return;
    }
    for (pb.linkage) |*l| {
        if (t.res.get(l[0])) |existing| {
            if (!std.mem.eql(u8, &existing.id, &l[1])) return p.fail(.InvalidLinkage);
            if (p.cfg.feature_flags.harden_linkage_consistency) try p.linker.addAndUnify(t, &l[1], true);
        } else try p.linker.addAndUnify(t, &l[1], true);
    }
}

/// `Command::arguments` of the signed command, in order.
fn rawArgs(arena: Allocator, c: *const types.Command) Allocator.Error![]const types.Argument {
    const cat = struct {
        fn f(a: Allocator, x: []const types.Argument, y: []const types.Argument) Allocator.Error![]const types.Argument {
            const out = try a.alloc(types.Argument, x.len + y.len);
            @memcpy(out[0..x.len], x);
            @memcpy(out[x.len..], y);
            return out;
        }
    }.f;
    return switch (c.*) {
        .MoveCall => |*mc| mc.arguments,
        .MakeMoveVec => |*m| m[1],
        .TransferObjects => |*t| cat(arena, t[0], (&t[1])[0..1]),
        .SplitCoins => |*x| cat(arena, (&x[0])[0..1], x[1]),
        .MergeCoins => |*x| cat(arena, (&x[0])[0..1], x[1]),
        .Upgrade => |*u| (&u[3])[0..1],
        .Publish => &.{},
    };
}

// ---------------------------------------------------------------------------------------------
// Typing (typing/translate.rs)

const Splat = union(enum) { gas, input: u16, result: [2]u16 };

fn locations(p: *Ptb, start: usize, args: []const types.Argument, out: *std.ArrayList(Splat)) Error!void {
    for (args, 0..) |a, k| {
        const idx = start + k;
        switch (a) {
            .GasCoin => try out.append(p.arena, .gas),
            .Input => |i| {
                // a converted withdrawal reads the conversion's coin (`lift_result_indices`)
                const conv: ?u16 = for (p.conversions.items) |cv| {
                    if (cv.input == i) break cv.result;
                } else null;
                if (conv) |ci| {
                    try out.append(p.arena, .{ .result = .{ ci, 0 } });
                } else {
                    if (i >= p.kinds.len) return p.argErr(idx, .{ .IndexOutOfBounds = .{ .idx = i } });
                    try out.append(p.arena, .{ .input = i });
                }
            },
            .NestedResult => |nr0| {
                const r0 = std.math.add(u16, nr0[0], p.lift) catch return p.diag.unsupported("result index overflow");
                if (r0 >= p.cmds.items.len or r0 >= p.lift + p.current) return p.argErr(idx, .{ .IndexOutOfBounds = .{ .idx = r0 } });
                if (nr0[1] >= p.cmds.items[r0].results.len) return p.argErr(idx, .{ .SecondaryIndexOutOfBounds = .{ .result_idx = r0, .secondary_idx = nr0[1] } });
                try out.append(p.arena, .{ .result = .{ r0, nr0[1] } });
            },
            .Result => |ri| {
                const i = std.math.add(u16, ri, p.lift) catch return p.diag.unsupported("result index overflow");
                if (i >= p.lift + p.current) return p.argErr(idx, .{ .IndexOutOfBounds = .{ .idx = i } });
                if (p.cmds.items[i].results.len != 1) return p.argErr(idx, .{ .InvalidResultArity = .{ .result_idx = i } });
                try out.append(p.arena, .{ .result = .{ i, 0 } });
            },
        }
    }
}

fn oneLocation(p: *Ptb, idx: usize, a: types.Argument) Error!Splat {
    var l: std.ArrayList(Splat) = .empty;
    try locations(p, idx, &.{a}, &l);
    return l.items[0];
}

fn fixedType(p: *Ptb, s: Splat) ?struct { Loc, Ty } {
    return switch (s) {
        .gas => .{ .gas, p.gas_ty },
        .result => |r| .{ .{ .result = r }, p.cmds.items[r[0]].results[r[1]] },
        .input => |i| switch (p.kinds[i]) {
            .object => |o| .{ .{ .object = o }, p.objects.items[o].ty },
            .withdrawal => |w| .{ .{ .withdrawal = w }, p.withdrawals.items[w].ty },
            else => null,
        },
    };
}

fn resolve(p: *Ptb, s: Splat, expected: Ty, arg_idx: usize) Error!struct { Loc, Ty } {
    if (fixedType(p, s)) |f| return f;
    const i = s.input;
    const ty = inner(expected);
    switch (p.kinds[i]) {
        .pure => {
            for (p.pure.items, 0..) |pl, k| if (pl.input == i and eql(pl.ty, ty)) return .{ .{ .pure = @intCast(k) }, ty };
            try p.pure.append(p.arena, .{ .input = i, .ty = ty, .cmd = p.current, .arg = @intCast(arg_idx) });
            return .{ .{ .pure = @intCast(p.pure.items.len - 1) }, ty };
        },
        .receiving => {
            for (p.receiving.items, 0..) |rl, k| if (rl.input == i and eql(rl.ty, ty)) return .{ .{ .receiving = @intCast(k) }, ty };
            const r = p.pt.inputs[i].Object.Receiving;
            try p.receiving.append(p.arena, .{ .input = i, .ty = ty, .cmd = p.current, .arg = @intCast(arg_idx), .id = r[0].@"0".@"0", .version = r[1].@"0" });
            return .{ .{ .receiving = @intCast(p.receiving.items.len - 1) }, ty };
        },
        .object, .withdrawal => unreachable,
    }
}

fn argument(p: *Ptb, idx: usize, s: Splat, expected: Ty) Error!Arg {
    const loc, const actual = try resolve(p, s, expected, idx);
    const mismatch: types.CommandArgumentError = .TypeMismatch;
    var a: Arg = .{ .idx = @intCast(idx), .kind = .use, .loc = loc, .ty = expected };
    if (isRef(actual) and isRef(expected)) {
        if (actual.* == .ref and expected.* == .mut_ref) return p.argErr(idx, mismatch);
        if (!eql(inner(actual), inner(expected))) return p.argErr(idx, mismatch);
        a.kind = if (actual.* == .mut_ref and expected.* == .ref) .freeze else .use;
    } else if (isRef(actual)) {
        if (!eql(inner(actual), expected)) return p.argErr(idx, mismatch);
        if (!abilities(expected).hasCopy()) return p.argErr(idx, mismatch);
        a.kind = .read;
    } else if (isRef(expected)) {
        if (!eql(actual, inner(expected))) return p.argErr(idx, mismatch);
        a.kind = .borrow;
        a.mut = expected.* == .mut_ref;
    } else {
        if (!eql(actual, expected)) return p.argErr(idx, mismatch);
        a.move = !abilities(expected).hasCopy();
    }
    return a;
}

fn constrained(p: *Ptb, idx: usize, s: Splat, need: AbilitySet, err: types.CommandArgumentError) Error!Arg {
    const f = fixedType(p, s) orelse return p.argErr(idx, err);
    if (!need.isSubset(abilities(f[1]))) return p.argErr(idx, err);
    return .{ .idx = @intCast(idx), .kind = .use, .move = !abilities(f[1]).hasCopy(), .loc = f[0], .ty = f[1] };
}

fn coinMutRef(p: *Ptb, s: Splat) Error!Arg {
    const f = fixedType(p, s) orelse return p.argErr(0, .TypeMismatch);
    const t = f[1];
    if (t.* == .mut_ref) {
        if (coinInner(t.mut_ref) == null) return p.argErr(0, .TypeMismatch);
        return .{ .idx = 0, .kind = .use, .loc = f[0], .ty = t };
    }
    if (coinInner(t) == null) return p.argErr(0, .TypeMismatch);
    return .{ .idx = 0, .kind = .borrow, .mut = true, .loc = f[0], .ty = try mk(p.arena, .{ .mut_ref = t }) };
}

pub fn typeTx(p: *Ptb) Error!void {
    try withdrawalCompatibility(p);
    for (p.cmds.items[p.lift..], p.pt.commands, 0..) |*c, *pc, ci| {
        p.current = @intCast(ci);
        typeCommand(p, c, pc) catch |e| {
            if (e == error.Fail and p.diag.fail.command == null) p.diag.fail.command = ci;
            return e;
        };
    }
    scopeAndUnused(p);
    postExecutionChecks(p);
}

/// translate.rs `determine_withdrawal_compatibility_inputs` and
/// `withdrawal_compatibility_conversion`: each converted withdrawal gets its owner as a new pure
/// input and a `coin::redeem_funds<T>(withdrawal, ctx)` command in front of the signed commands.
fn withdrawalCompatibility(p: *Ptb) Error!void {
    var n: usize = 0;
    for (p.withdrawals.items) |*w| {
        if (w.compat) n += 1;
    }
    if (n == 0) return;
    if (!p.cfg.feature_flags.convert_withdrawal_compatibility_ptb_arguments) return p.diag.unsupported("coin reservation without the compatibility conversion");
    const base = p.kinds.len;
    const kinds = try p.arena.alloc(InputKind, base + n);
    @memcpy(kinds[0..base], p.kinds);
    @memset(kinds[base..], .pure);
    p.kinds = kinds;
    var conv: std.ArrayList(Cmd) = .empty;
    var k: usize = 0;
    for (p.withdrawals.items, 0..) |*w, wi| if (w.compat) {
        const owner_input: u16 = @intCast(base + k);
        k += 1;
        try p.extra_pure.append(p.arena, try p.arena.dupe(u8, &w.owner));
        p.current = 0;
        const owner_loc, _ = try resolve(p, .{ .input = owner_input }, &Type.t_address, 0);
        const inner_ty = w.ty.datatype.args[0].datatype.args[0];
        const call = try frameworkCall(p, "coin", "redeem_funds", &.{inner_ty});
        const args = try p.arena.alloc(Arg, 2);
        args[0] = .{ .idx = 0, .kind = .use, .move = true, .loc = .{ .withdrawal = @intCast(wi) }, .ty = w.ty };
        args[1] = .{ .idx = 0, .kind = .borrow, .mut = true, .loc = .tx_context, .ty = try mk(p.arena, .{ .mut_ref = p.tx_ctx_ty }) };
        try conv.append(p.arena, .{ .tag = .call, .call = call, .args = args, .results = call.returns, .annot = 0 });
        try p.conversions.append(p.arena, .{ .input = w.input, .result = @intCast(conv.items.len - 1), .owner = owner_loc, .inner = inner_ty });
    };
    p.lift = @intCast(conv.items.len);
    try conv.appendSlice(p.arena, p.cmds.items);
    p.cmds = conv;
}

/// drop_safety.rs `return_unused_withdrawal_conversions`: a conversion's coin that no command
/// moved goes back to its owner with `coin::send_funds<T>(coin, owner)`.
fn returnUnusedConversions(p: *Ptb) Error!void {
    if (p.conversions.items.len == 0) return;
    var moved = std.AutoHashMapUnmanaged(Loc, void).empty;
    for (p.cmds.items) |*c| for (c.args) |a| if (a.kind != .borrow and a.move) try moved.put(p.arena, a.loc, {});
    for (p.conversions.items) |cv| {
        const loc: Loc = .{ .result = .{ cv.result, 0 } };
        if (moved.contains(loc)) continue;
        const cur: u16 = @intCast(p.cmds.items.len - 1);
        const call = try frameworkCall(p, "coin", "send_funds", &.{cv.inner});
        const args = try p.arena.alloc(Arg, 2);
        args[0] = .{ .idx = cur, .kind = .use, .move = true, .loc = loc, .ty = p.cmds.items[cv.result].results[0] };
        args[1] = .{ .idx = cur, .kind = .use, .move = true, .loc = cv.owner, .ty = &Type.t_address };
        try p.cmds.append(p.arena, .{ .tag = .call, .call = call, .args = args, .results = &.{}, .drop = &.{}, .annot = cur });
    }
}

/// `Env::load_framework_function`: a 0x2 function under the unified linkage.
fn frameworkCall(p: *Ptb, module: []const u8, name: []const u8, ty_args: []const Ty) Error!*Call {
    const id = framework(2);
    const pkg = try p.linker.pkg(&id);
    const vpkg = p.linker.cache.load(pkg) catch return p.diag.unsupported("package does not load");
    const m = vpkg.module(module) orelse return p.diag.unsupported("framework function");
    const func = m.functionByName(name) orelse return p.diag.unsupported("framework function");
    const fdef = fdefOf(func);
    const linkage = if (p.cfg.feature_flags.enable_unified_linkage) p.unified else blk: {
        var t = try p.linker.withNatives();
        break :blk try pkgs.resolved(p.arena, &t);
    };
    const call = try p.arena.create(Call);
    call.* = .{
        .pkg = pkg,
        .module = module,
        .name = name,
        .func = func,
        .ty_args = try p.arena.dupe(Ty, ty_args),
        .params = try move_vm.types.instantiateAll(p.arena, func.module, func.params, ty_args),
        .returns = try move_vm.types.instantiateAll(p.arena, func.module, func.returns, ty_args),
        .visibility = fdef.visibility,
        .is_entry = fdef.is_entry,
        .linkage_entries = 0,
        .linkage = linkage,
    };
    return call;
}

/// `move_call_parameters`: the TxContext kind of parameter `pi`. exec-history: before
/// `flexible_tx_context_positions` (v3) only the last parameter can be the implicit TxContext.
fn paramCtxKind(p: *const Ptb, call: *const Call, t: Ty, pi: usize) TxCtxKind {
    if (!p.cfg.feature_flags.flexible_tx_context_positions and versions.executionVersion(p.cfg) < versions.latest and pi + 1 != call.params.len) return .none;
    return txContextKind(t);
}

fn typeCommand(p: *Ptb, c: *Cmd, pc: *const types.Command) Error!void {
    var locs: std.ArrayList(Splat) = .empty;
    var args: std.ArrayList(Arg) = .empty;
    switch (pc.*) {
        .MoveCall => |*mc| {
            const call = c.call.?;
            try locations(p, 0, mc.arguments, &locs);
            var n_ctx: usize = 0;
            for (call.params, 0..) |t, pi| {
                if (paramCtxKind(p, call, t, pi) != .none) n_ctx += 1;
            }
            if (locs.items.len + n_ctx != call.params.len) return p.fail(.ArityMismatch);
            var k: usize = 0;
            for (call.params, 0..) |t, pi| {
                switch (paramCtxKind(p, call, t, pi)) {
                    .none => {
                        try args.append(p.arena, try argument(p, k, locs.items[k], t));
                        k += 1;
                    },
                    else => |kind| try args.append(p.arena, .{ .idx = @intCast(pi), .kind = .borrow, .mut = kind == .mutable, .loc = .tx_context, .ty = t }),
                }
            }
            c.results = call.returns;
        },
        .TransferObjects => |*to| {
            try locations(p, 0, to[0], &locs);
            const addr = try oneLocation(p, locs.items.len, to[1]);
            const need: AbilitySet = .{ .bits = 0x4 | 0x8 };
            for (locs.items, 0..) |s, i| try args.append(p.arena, try constrained(p, i, s, need, .InvalidTransferObject));
            try args.append(p.arena, try argument(p, locs.items.len, addr, &Type.t_address));
        },
        .SplitCoins => |*sc| {
            const coin_loc = try oneLocation(p, 0, sc[0]);
            try locations(p, 1, sc[1], &locs);
            const coin = try coinMutRef(p, coin_loc);
            c.ty = coin.ty.mut_ref;
            try args.append(p.arena, coin);
            for (locs.items, 1..) |s, i| try args.append(p.arena, try argument(p, i, s, &Type.t_u64));
            const res = try p.arena.alloc(Ty, locs.items.len);
            @memset(res, c.ty.?);
            c.results = res;
        },
        .MergeCoins => |*mc| {
            const target_loc = try oneLocation(p, 0, mc[0]);
            try locations(p, 1, mc[1], &locs);
            const target = try coinMutRef(p, target_loc);
            c.ty = target.ty.mut_ref;
            try args.append(p.arena, target);
            for (locs.items, 1..) |s, i| try args.append(p.arena, try argument(p, i, s, c.ty.?));
        },
        .MakeMoveVec => |*mv| {
            if (c.ty) |ty| {
                try locations(p, 0, mv[1], &locs);
                for (locs.items, 0..) |s, i| try args.append(p.arena, try argument(p, i, s, ty));
            } else {
                if (mv[1].len == 0) return p.diag.unsupported("empty MakeMoveVec without a type");
                const first_loc = try oneLocation(p, 0, mv[1][0]);
                const first = try constrained(p, 0, first_loc, .{ .bits = 0x8 }, .InvalidMakeMoveVecNonObjectArgument);
                c.ty = first.ty;
                try locations(p, 1, mv[1][1..], &locs);
                try args.append(p.arena, first);
                for (locs.items, 1..) |s, i| try args.append(p.arena, try argument(p, i, s, first.ty));
            }
            const res = try p.arena.alloc(Ty, 1);
            res[0] = try mk(p.arena, .{ .vector = c.ty.? });
            c.results = res;
        },
        .Publish => {
            const res = try p.arena.alloc(Ty, 1);
            res[0] = try mk(p.arena, .{ .datatype = .{ .dt = try datatypeByDefining(p, &framework(2), "package", "UpgradeCap"), .args = &.{} } });
            c.results = res;
        },
        .Upgrade => |*x| {
            const loc = try oneLocation(p, 0, x[3]);
            const ticket = try mk(p.arena, .{ .datatype = .{ .dt = try datatypeByDefining(p, &framework(2), "package", "UpgradeTicket"), .args = &.{} } });
            try args.append(p.arena, try argument(p, 0, loc, ticket));
            const res = try p.arena.alloc(Ty, 1);
            res[0] = try mk(p.arena, .{ .datatype = .{ .dt = try datatypeByDefining(p, &framework(2), "package", "UpgradeReceipt"), .args = &.{} } });
            c.results = res;
        },
    }
    c.args = args.items;
}

fn resultLoc(l: Loc) ?u32 {
    return switch (l) {
        .result => |r| (@as(u32, r[0]) << 16) | r[1],
        else => null,
    };
}

/// scope_references (the last usage of a reference result moves it) and unused_results.
fn scopeAndUnused(p: *Ptb) void {
    var scoped = std.AutoHashMapUnmanaged(u32, void).empty;
    var ci = p.cmds.items.len;
    while (ci > 0) {
        ci -= 1;
        const c = &p.cmds.items[ci];
        var ai = c.args.len;
        while (ai > 0) {
            ai -= 1;
            const a = &c.args[ai];
            const handled = switch (a.kind) {
                .borrow => false,
                .read => p.cfg.feature_flags.fix_ptb_generated_reads,
                .use, .freeze => isRef(a.ty),
            };
            if (!handled) continue;
            const k = resultLoc(a.loc) orelse continue;
            const gop = scoped.getOrPut(p.arena, k) catch continue;
            if (!gop.found_existing) a.move = true;
        }
    }
    var used = std.AutoHashMapUnmanaged(u32, void).empty;
    for (p.cmds.items) |*c| for (c.args) |a| if (resultLoc(a.loc)) |k| {
        used.put(p.arena, k, {}) catch {};
    };
    for (p.cmds.items, 0..) |*c, i| {
        c.drop = p.arena.alloc(bool, c.results.len) catch &.{};
        for (c.results, 0..) |t, j| c.drop[j] = abilities(t).hasDrop() and !used.contains((@as(u32, @intCast(i)) << 16) | @as(u32, @intCast(j)));
    }
}

fn postExecutionChecks(p: *Ptb) void {
    const tainted = p.arena.alloc(bool, p.cmds.items.len) catch return;
    for (p.cmds.items, 0..) |*c, ci| {
        var hot = false;
        for (c.args) |a| {
            const t = switch (a.loc) {
                .object => |o| a.kind == .use and a.move and p.objects.items[o].perm == .legacy_shared,
                .result => |r| (a.kind == .use and a.move and tainted[r[0]]) or
                    (a.kind == .borrow and a.mut and p.cfg.feature_flags.granular_post_execution_checks and tainted[r[0]]),
                else => false,
            };
            if (t) {
                hot = true;
                break;
            }
        }
        if (c.tag == .make_vec) {
            tainted[ci] = hot;
        } else {
            tainted[ci] = false;
            c.post_checks = hot;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Typing meter (metering/typing)

pub fn typingMeter(p: *Ptb) Error!void {
    var refs: u64 = 0;
    var nodes: u64 = 0;
    const Acc = struct {
        fn add(r: *u64, n: *u64, t: Ty) void {
            if (isRef(t) and txContextKind(t) == .none) r.* +|= 1;
            n.* +|= nodeCount(t);
        }
    };
    for (p.pure.items) |x| Acc.add(&refs, &nodes, x.ty);
    for (p.objects.items) |x| Acc.add(&refs, &nodes, x.ty);
    for (p.receiving.items) |x| Acc.add(&refs, &nodes, x.ty);
    for (p.cmds.items) |*c| {
        for (c.results) |t| Acc.add(&refs, &nodes, t);
        switch (c.tag) {
            .transfer => {
                Acc.add(&refs, &nodes, c.args[c.args.len - 1].ty);
                for (c.args[0 .. c.args.len - 1]) |a| Acc.add(&refs, &nodes, a.ty);
            },
            .split, .merge, .make_vec => {
                for (c.args) |a| Acc.add(&refs, &nodes, a.ty);
                Acc.add(&refs, &nodes, c.ty.?);
            },
            .call => {
                const call = c.call.?;
                for (c.args) |a| Acc.add(&refs, &nodes, a.ty);
                for (call.ty_args) |t| Acc.add(&refs, &nodes, t);
                for (call.params) |t| Acc.add(&refs, &nodes, t);
                for (call.returns) |t| Acc.add(&refs, &nodes, t);
            },
            .publish => {},
            .upgrade => for (c.args) |a| Acc.add(&refs, &nodes, a.ty),
        }
    }
    try p.deduct(@max(nodes, 1) * (p.cfg.getOpt("translation_per_type_node_charge") orelse 0), null);
    const n = @max(refs, 1);
    try p.deduct(n * (n + 1) / 2 * (p.cfg.getOpt("translation_per_reference_node_charge") orelse 0), null);
    if (p.cfg.getOpt("max_ptb_live_references") != null) try liveReferences(p);
}

/// metering/typing/live_references.rs: the references live at each command (arguments held
/// until the command's results exist, returned references until their last use or drop),
/// charged cubically and limited. Errors carry the command's position in the typed
/// transaction (`enumerate`, conversions included).
fn liveReferences(p: *Ptb) Error!void {
    const max_live = p.cfg.getOpt("max_ptb_live_references").?;
    const max_ret = p.cfg.getOpt("max_ptb_returned_references") orelse return p.diag.unsupported("no max_ptb_returned_references");
    const max_total = p.cfg.getOpt("max_ptb_total_returned_references") orelse return p.diag.unsupported("no max_ptb_total_returned_references");
    const per_live = p.cfg.getOpt("translation_per_live_reference_charge") orelse 0;
    const fix = p.cfg.feature_flags.fix_ptb_generated_reads;
    var live: u64 = 0;
    var total: u64 = 0;
    for (p.cmds.items, 0..) |*c, ci| {
        const cmd: u64 = ci;
        var held: u64 = 0;
        for (c.args) |a| {
            if (txContextKind(a.ty) != .none) continue;
            switch (a.kind) {
                .borrow => {
                    live +|= 1;
                    if (live > max_live) return p.diag.failWith(.InsufficientGas, cmd);
                    held += 1;
                },
                .freeze => {
                    if (!a.move) {
                        live +|= 1;
                        if (live > max_live) return p.diag.failWith(.InsufficientGas, cmd);
                    }
                    if (live == 0) return p.diag.unsupported("live reference count invariant");
                    live -= 1;
                    live +|= 1;
                    if (live > max_live) return p.diag.failWith(.InsufficientGas, cmd);
                    held += 1;
                },
                .read => {
                    // without the fix the usage check on the value type is an invariant violation
                    if (!fix) return p.diag.unsupported("read of a reference result before fix_ptb_generated_reads");
                    if (!a.move) {
                        live +|= 1;
                        if (live > max_live) return p.diag.failWith(.InsufficientGas, cmd);
                    }
                    if (live == 0) return p.diag.unsupported("live reference count invariant");
                    live -= 1;
                },
                .use => if (isRef(a.ty)) {
                    if (!a.move) {
                        live +|= 1;
                        if (live > max_live) return p.diag.failWith(.InsufficientGas, cmd);
                    }
                    held += 1;
                },
            }
        }
        var returned: u64 = 0;
        for (c.results) |t| {
            if (isRef(t)) returned += 1;
        }
        if (returned > max_ret) return p.diag.failWith(.InsufficientGas, cmd);
        total +|= returned;
        if (total > max_total) return p.diag.failWith(.InsufficientGas, cmd);
        live +|= returned;
        if (live > max_live) return p.diag.failWith(.InsufficientGas, cmd);
        if (live < held) return p.diag.unsupported("live reference count invariant");
        live -= held;
        var dropped: u64 = 0;
        for (c.results, 0..) |t, j| {
            if (j < c.drop.len and c.drop[j] and isRef(t)) dropped += 1;
        }
        if (live < dropped) return p.diag.unsupported("live reference count invariant");
        live -= dropped;
        const amount = (live *| (live +| 1) *| (live +| 2)) / 6 *| per_live;
        if (amount != 0) try p.deduct(amount, cmd);
    }
}

// ---------------------------------------------------------------------------------------------
// Verification (typing/verify)

pub fn verify(p: *Ptb) Error!void {
    try inputArguments(p);
    for (p.cmds.items, 0..) |*c, ci| if (c.call) |call| {
        moveFunction(p, call) catch |e| {
            if (e == error.Fail and p.diag.fail.command == null) p.diag.fail.command = p.annot(ci);
            return e;
        };
    };
    try memorySafety(p);
    dropRefine(p);
    try returnUnusedConversions(p);
    try dropVerify(p);
    try privateEntry(p);
}

fn qualified(t: Ty, addr: u16, module: []const u8, name: []const u8, n_args: usize) bool {
    return isDt(t, addr, module, name) and t.datatype.args.len == n_args;
}

pub const Prim = union(enum) { bool, u8, u16, u32, u64, u128, u256, address, ascii, utf8, vector: *const Prim, option: *const Prim };

pub fn primLayout(arena: Allocator, t: Ty) Allocator.Error!?*const Prim {
    const out = try arena.create(Prim);
    out.* = switch (t.*) {
        .bool => .bool,
        .u8 => .u8,
        .u16 => .u16,
        .u32 => .u32,
        .u64 => .u64,
        .u128 => .u128,
        .u256 => .u256,
        .address => .address,
        .vector => |e| .{ .vector = (try primLayout(arena, e)) orelse return null },
        .datatype => |d| blk: {
            if (qualified(t, 1, "option", "Option", 1)) break :blk .{ .option = (try primLayout(arena, d.args[0])) orelse return null };
            if (d.args.len != 0) return null;
            if (isDt(t, 2, "object", "ID")) break :blk .address;
            if (isDt(t, 1, "ascii", "String")) break :blk .ascii;
            if (isDt(t, 1, "string", "String")) break :blk .utf8;
            return null;
        },
        else => return null,
    };
    return out;
}

fn readUleb(b: []const u8, at: *usize) ?u64 {
    var x: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        if (at.* >= b.len) return null;
        const byte = b[at.*];
        at.* += 1;
        const v = @as(u64, byte & 0x7f);
        if (shift == 63 and v > 1) return null;
        x |= v << shift;
        if (byte & 0x80 == 0) {
            // canonical: no trailing zero byte unless the value is 0
            if (byte == 0 and shift != 0) return null;
            if (x > std.math.maxInt(u32)) return null;
            return x;
        }
        if (shift >= 63) return null;
        shift += 7;
    }
}

pub fn validate(b: []const u8, at: *usize, l: *const Prim, depth: u32) bool {
    if (depth > 256) return false;
    const fixed: ?usize = switch (l.*) {
        .bool => blk: {
            if (at.* >= b.len or b[at.*] > 1) return false;
            break :blk 1;
        },
        .u8 => 1,
        .u16 => 2,
        .u32 => 4,
        .u64 => 8,
        .u128 => 16,
        .u256, .address => 32,
        else => null,
    };
    if (fixed) |n| {
        if (b.len - at.* < n) return false;
        at.* += n;
        return true;
    }
    switch (l.*) {
        .ascii, .utf8 => {
            const n = readUleb(b, at) orelse return false;
            if (b.len - at.* < n) return false;
            const s = b[at.*..][0..n];
            at.* += n;
            if (l.* == .ascii) {
                for (s) |ch| if (ch > 0x7f) return false;
                return true;
            }
            return std.unicode.utf8ValidateSlice(s);
        },
        .vector => |e| {
            const n = readUleb(b, at) orelse return false;
            for (0..n) |_| if (!validate(b, at, e, depth + 1)) return false;
            return true;
        },
        .option => |e| {
            const n = readUleb(b, at) orelse return false;
            if (n > 1) return false;
            if (n == 1) return validate(b, at, e, depth + 1);
            return true;
        },
        else => unreachable,
    }
}

fn inputArguments(p: *Ptb) Error!void {
    // `check_pure_bytes`: `if Mode::allow_arbitrary_values() { return Ok(()) }` (any type, any
    // bytes; the value is deserialized when a command first uses it)
    if (!p.skip_checks) for (p.pure.items) |pl| {
        const bytes = p.pureBytes(pl.input);
        const lay = (try primLayout(p.arena, pl.ty)) orelse
            return p.diag.failWith(.{ .CommandArgumentError = .{ .arg_idx = pl.arg, .kind = .InvalidUsageOfPureArg } }, pl.cmd);
        var at: usize = 0;
        if (!validate(bytes, &at, lay, 0) or at != bytes.len)
            return p.diag.failWith(.{ .CommandArgumentError = .{ .arg_idx = pl.arg, .kind = .InvalidBCSBytes } }, pl.cmd);
    };
    for (p.receiving.items) |rl| {
        const ok = qualified(rl.ty, 2, "transfer", "Receiving", 1) and abilities(rl.ty.datatype.args[0]).hasKey();
        if (!ok) return p.diag.failWith(.{ .CommandArgumentError = .{ .arg_idx = rl.arg, .kind = .TypeMismatch } }, rl.cmd);
    }
    for (p.cmds.items, 0..) |*c, ci| {
        for (c.args) |a| {
            const o = switch (a.loc) {
                .object => |o| o,
                else => continue,
            };
            const mutably = p.objects.items[o].canUseMutably();
            if (a.kind == .borrow and a.mut and !mutably)
                return p.diag.failWith(.{ .CommandArgumentError = .{ .arg_idx = a.idx, .kind = .InvalidObjectByMutRef } }, p.annot(ci));
            if (a.kind == .use and a.move and !mutably)
                return p.diag.failWith(.{ .CommandArgumentError = .{ .arg_idx = a.idx, .kind = .InvalidObjectByValue } }, p.annot(ci));
        }
        if (c.tag == .transfer) continue;
        if (c.tag == .call and p.cfg.feature_flags.enable_accumulators and isSendFunds(c.call.?)) continue;
        for (c.args) |a| if (a.loc == .gas and a.kind == .use and a.move)
            return p.diag.failWith(.{ .CommandArgumentError = .{ .arg_idx = a.idx, .kind = .InvalidGasCoinUsage } }, p.annot(ci));
    }
}

pub fn isSendFunds(call: *const Call) bool {
    return short(&call.pkg.original_id) == 2 and std.mem.eql(u8, call.module, "coin") and std.mem.eql(u8, call.name, "send_funds");
}

fn moveFunction(p: *Ptb, call: *const Call) Error!void {
    // `check_signature`: a reference return type passes under `Mode::allow_arbitrary_values()`
    if (!p.cfg.feature_flags.allow_references_in_ptbs and !p.skip_checks) {
        for (call.returns, 0..) |t, i| if (isRef(t)) return p.fail(.{ .InvalidPublicFunctionReturnType = .{ .idx = @intCast(i) } });
    }
    if (p.cfg.feature_flags.ptb_tx_context_restrictions) {
        const bad: types.CommandArgumentError = .InvalidTxContext;
        for (call.params, 0..) |t, i| if (isDt(t, 2, "tx_context", "TxContext")) return p.argErr(i, bad);
        var first_mut: ?usize = null;
        var any_imm = false;
        for (call.params, 0..) |t, i| switch (txContextKind(t)) {
            .mutable => if (first_mut != null) return p.argErr(i, bad) else {
                first_mut = i;
            },
            .immutable => any_imm = true,
            .none => {},
        };
        if (first_mut) |f| if (any_imm) return p.argErr(f, bad);
        for (call.returns, 0..) |t, i| if (txContextKind(t) != .none or isDt(t, 2, "tx_context", "TxContext")) return p.argErr(i, bad);
    }
    const s = short(&call.pkg.original_id);
    const internal = (s == 1 and std.mem.eql(u8, call.module, "internal") and std.mem.eql(u8, call.name, "permit")) or
        (s == 2 and std.mem.eql(u8, call.module, "event") and (std.mem.eql(u8, call.name, "emit") or std.mem.eql(u8, call.name, "emit_authenticated"))) or
        (s == 2 and std.mem.eql(u8, call.module, "coin_registry") and std.mem.eql(u8, call.name, "new_currency")) or
        (s == 2 and std.mem.eql(u8, call.module, "transfer") and for ([_][]const u8{ "transfer", "freeze_object", "share_object", "receive", "party_transfer" }) |n| {
            if (std.mem.eql(u8, call.name, n)) break true;
        } else false);
    // `check_private_generics_v2` holds in every mode; `check_visibility` lets a private or
    // friend function that is not `entry` through under `Mode::allow_arbitrary_function_calls()`
    if (internal) return p.fail(.NonEntryFunctionInvoked);
    if (call.visibility != .Public and !call.is_entry and !p.skip_checks) return p.fail(.NonEntryFunctionInvoked);
}

/// typing/verify/memory_safety.rs over the regex borrow graph (`borrow.zig`): every value is a
/// reference (a graph node) or not; borrowing a location extends the local root by its label,
/// a call's returned references extend its reference arguments by `.*`, and a value cannot be
/// moved while some live reference's path starts at its location.
fn memorySafety(p: *Ptb) Error!void {
    const a = p.arena;
    var ms: Ms = .{ .p = p, .g = borrow.Graph.init(a) };
    ms.root = try ms.g.extendByEpsilon(&.{}, true);
    try ms.vals.put(a, .tx_context, .nonref);
    try ms.vals.put(a, .gas, .nonref);
    for (p.objects.items, 0..) |_, i| try ms.vals.put(a, .{ .object = @intCast(i) }, .nonref);
    for (p.withdrawals.items, 0..) |_, i| try ms.vals.put(a, .{ .withdrawal = @intCast(i) }, .nonref);
    for (p.pure.items, 0..) |_, i| try ms.vals.put(a, .{ .pure = @intCast(i) }, .nonref);
    for (p.receiving.items, 0..) |_, i| try ms.vals.put(a, .{ .receiving = @intCast(i) }, .nonref);
    for (p.cmds.items, 0..) |*c, ci| {
        const res = ms.command(c) catch |e| {
            if (e == error.Fail and p.diag.fail.command == null) p.diag.fail.command = p.annot(ci);
            return e;
        };
        for (res, 0..) |v, j| {
            const loc: Loc = .{ .result = .{ @intCast(ci), @intCast(j) } };
            if (j < c.drop.len and c.drop[j]) {
                ms.consume(v);
                try ms.vals.put(a, loc, null);
            } else try ms.vals.put(a, loc, v);
        }
    }
}

const Ms = struct {
    p: *Ptb,
    g: borrow.Graph,
    root: borrow.Ref = 0,
    /// Locations and their values (null: moved).
    vals: std.AutoHashMapUnmanaged(Loc, ?MsVal) = .empty,
    buf: std.ArrayList(struct { borrow.Ref, []const borrow.Regex }) = .empty,

    const MsVal = union(enum) { nonref, ref: borrow.Ref };

    fn err(ms: *Ms, idx: u16, k: types.CommandArgumentError) error{Fail} {
        return ms.p.diag.failWith(.{ .CommandArgumentError = .{ .arg_idx = idx, .kind = k } }, null);
    }

    fn consume(ms: *Ms, v: MsVal) void {
        switch (v) {
            .nonref => {},
            .ref => |r| ms.g.release(r),
        }
    }

    fn isLocationBorrowed(ms: *Ms, l: Loc) Error!bool {
        try ms.g.borrowedBy(ms.root, &ms.buf);
        for (ms.buf.items) |e| for (e[1]) |path| if (path.startsWith(l)) return true;
        return false;
    }

    fn slot(ms: *Ms, l: Loc) Error!*?MsVal {
        return ms.vals.getPtr(l) orelse ms.p.diag.unsupported("memory safety: unknown location");
    }

    fn moveValue(ms: *Ms, idx: u16, l: Loc) Error!MsVal {
        if (try ms.isLocationBorrowed(l)) return ms.err(idx, .CannotMoveBorrowedValue);
        const s = try ms.slot(l);
        const v = s.* orelse return ms.err(idx, .ArgumentWithoutValue);
        s.* = null;
        return v;
    }

    fn copyValue(ms: *Ms, a: *Arg) Error!MsVal {
        a.borrowed = try ms.isLocationBorrowed(a.loc);
        const v = (try ms.slot(a.loc)).* orelse return ms.err(a.idx, .ArgumentWithoutValue);
        return switch (v) {
            .nonref => .nonref,
            .ref => |r| .{ .ref = try ms.g.extendByEpsilon(&.{r}, ms.g.isMutable(r)) },
        };
    }

    fn usage(ms: *Ms, a: *Arg) Error!MsVal {
        return if (a.move) ms.moveValue(a.idx, a.loc) else ms.copyValue(a);
    }

    fn argument(ms: *Ms, a: *Arg) Error!MsVal {
        switch (a.kind) {
            .use => return ms.usage(a),
            .borrow => {
                _ = (try ms.slot(a.loc)).* orelse return ms.err(a.idx, .ArgumentWithoutValue);
                return .{ .ref = try ms.g.extendByLabel(ms.root, a.mut, a.loc) };
            },
            .freeze => {
                const v = try ms.usage(a);
                const r = switch (v) {
                    .ref => |r| r,
                    .nonref => return ms.p.diag.unsupported("memory safety: freeze of a value"),
                };
                const n = try ms.g.extendByEpsilon(&.{r}, false);
                ms.consume(v);
                return .{ .ref = n };
            },
            .read => {
                const v = try ms.usage(a);
                if (v != .ref) return ms.p.diag.unsupported("memory safety: read of a value");
                ms.consume(v);
                return .nonref;
            },
        }
    }

    fn arguments(ms: *Ms, args: []Arg) Error![]MsVal {
        const out = try ms.p.arena.alloc(MsVal, args.len);
        for (args, out) |*a, *v| v.* = try ms.argument(a);
        return out;
    }

    fn consumeAll(ms: *Ms, vs: []const MsVal) void {
        for (vs) |v| ms.consume(v);
    }

    /// `write_ref` of a coin reference: only a reference no one extended can be written.
    fn writeRef(ms: *Ms, idx: u16, v: MsVal) Error!void {
        const r = switch (v) {
            .ref => |r| r,
            .nonref => return ms.p.diag.unsupported("memory safety: write to a value"),
        };
        try ms.g.borrowedBy(r, &ms.buf);
        for (ms.buf.items) |e| for (e[1]) |path| if (!path.isEpsilon()) return ms.err(idx, .CannotWriteToExtendedReference);
        ms.consume(v);
    }

    fn command(ms: *Ms, c: *Cmd) Error![]MsVal {
        const arena = ms.p.arena;
        const n_res = c.results.len;
        switch (c.tag) {
            .call => {
                const vals = try ms.arguments(c.args);
                return ms.call(c, vals);
            },
            .transfer, .make_vec => {
                ms.consumeAll(try ms.arguments(c.args));
                const out = try arena.alloc(MsVal, n_res);
                @memset(out, .nonref);
                return out;
            },
            .split, .merge => {
                const coin = try ms.argument(&c.args[0]);
                ms.consumeAll(try ms.arguments(c.args[1..]));
                try ms.writeRef(0, coin);
                const out = try arena.alloc(MsVal, n_res);
                @memset(out, .nonref);
                return out;
            },
            .publish => {
                const out = try arena.alloc(MsVal, n_res);
                @memset(out, .nonref);
                return out;
            },
            .upgrade => {
                ms.consumeAll(try ms.arguments(c.args));
                const out = try arena.alloc(MsVal, n_res);
                @memset(out, .nonref);
                return out;
            },
        }
    }

    /// `find_non_transferrable` over the call's reference arguments: an immutable one borrowed
    /// by a mutable one reports the mutable borrower; a mutable one borrowed through a path other
    /// than epsilon, or by another argument, reports itself.
    fn findNonTransferrable(ms: *Ms, refs: []const borrow.Ref) Error!?borrow.Ref {
        for (refs) |r| {
            const is_mut = ms.g.isMutable(r);
            try ms.g.borrowedBy(r, &ms.buf);
            for (ms.buf.items) |e| {
                const borrower = e[0];
                if (!is_mut) {
                    if (std.mem.indexOfScalar(borrow.Ref, refs, borrower) != null and ms.g.isMutable(borrower)) return borrower;
                } else for (e[1]) |path| {
                    if (!path.isEpsilon() or std.mem.indexOfScalar(borrow.Ref, refs, borrower) != null) return r;
                }
            }
        }
        return null;
    }

    fn call(ms: *Ms, c: *Cmd, vals: []MsVal) Error![]MsVal {
        const arena = ms.p.arena;
        const callee = c.call.?;
        var refs: std.ArrayList(borrow.Ref) = .empty;
        for (vals) |v| switch (v) {
            .ref => |r| try refs.append(arena, r),
            .nonref => {},
        };
        std.mem.sort(borrow.Ref, refs.items, {}, std.sort.asc(borrow.Ref));
        if (try ms.findNonTransferrable(refs.items)) |bad| {
            for (vals, 0..) |v, i| {
                if (v == .ref and v.ref == bad and i < callee.params.len and callee.params[i].* == .mut_ref)
                    return ms.err(@intCast(i), .InvalidReferenceArgument);
            }
            return ms.p.diag.unsupported("memory safety: non transferrable value not in the arguments");
        }
        var sources = refs;
        if (ms.p.cfg.feature_flags.allow_references_in_ptbs) {
            sources = .empty;
            for (vals, 0..) |v, i| switch (v) {
                .ref => |r| if (i >= callee.params.len or txContextKind(callee.params[i]) == .none) try sources.append(arena, r),
                .nonref => {},
            };
            std.mem.sort(borrow.Ref, sources.items, {}, std.sort.asc(borrow.Ref));
        }
        var muts: std.ArrayList(bool) = .empty;
        for (c.results) |t| if (isRef(t)) try muts.append(arena, t.* == .mut_ref);
        const new = try ms.g.extendByDotStarForCall(sources.items, muts.items);
        const out = try arena.alloc(MsVal, c.results.len);
        var k: usize = 0;
        for (c.results, out) |t, *o| {
            if (isRef(t)) {
                o.* = .{ .ref = new[k] };
                k += 1;
            } else o.* = .nonref;
        }
        ms.consumeAll(vals);
        return out;
    }
};

/// drop_safety.rs refine: the last usage of a copied location (not borrowed when copied)
/// becomes a move.
fn dropRefine(p: *Ptb) void {
    var used = std.AutoHashMapUnmanaged(Loc, void).empty;
    var ci = p.cmds.items.len;
    while (ci > 0) {
        ci -= 1;
        const c = &p.cmds.items[ci];
        const args = c.args;
        const n = args.len;
        switch (c.tag) {
            .transfer => {
                refineArg(p, &used, &args[n - 1]);
                var k = n - 1;
                while (k > 0) : (k -= 1) refineArg(p, &used, &args[k - 1]);
            },
            .split, .merge => {
                var k = n;
                while (k > 1) : (k -= 1) refineArg(p, &used, &args[k - 1]);
                refineArg(p, &used, &args[0]);
            },
            .call, .make_vec, .upgrade => {
                var k = n;
                while (k > 0) : (k -= 1) refineArg(p, &used, &args[k - 1]);
            },
            .publish => {},
        }
    }
}

fn refineArg(p: *Ptb, used: *std.AutoHashMapUnmanaged(Loc, void), a: *Arg) void {
    const first = !(used.getOrPut(p.arena, a.loc) catch return).found_existing;
    if (a.kind == .borrow) return;
    if (a.move) return;
    if (first and !a.borrowed) a.move = true;
}

fn dropVerify(p: *Ptb) Error!void {
    // `drop_value`: `!abilities.has_drop() && !Mode::allow_arbitrary_values()` is the only error
    if (p.skip_checks) return;
    // Values moved by commands; at the end every result value left must have drop.
    var moved = std.AutoHashMapUnmanaged(Loc, void).empty;
    for (p.cmds.items) |*c| for (c.args) |a| if (a.kind != .borrow and a.move) try moved.put(p.arena, a.loc, {});
    for (p.cmds.items, 0..) |*c, i| for (c.results, 0..) |t, j| {
        if (c.drop[j]) continue;
        const loc: Loc = .{ .result = .{ @intCast(i), @intCast(j) } };
        if (moved.contains(loc)) continue;
        if (!abilities(t).hasDrop()) return p.fail(.{ .UnusedValueWithoutDrop = .{ .result_idx = @intCast(i), .secondary_idx = @intCast(j) } });
    };
}

/// private_entry_arguments.rs: cliques of values with hot counts.
fn privateEntry(p: *Ptb) Error!void {
    const Temp = union(enum) { hot, count: usize };
    const V = struct { clique: usize, heats: bool };
    var parent: std.ArrayList(?usize) = .empty; // null: root
    var temps: std.ArrayList(Temp) = .empty;
    const C = struct {
        fn next(a: Allocator, par: *std.ArrayList(?usize), tm: *std.ArrayList(Temp)) Allocator.Error!usize {
            try par.append(a, null);
            try tm.append(a, .{ .count = 0 });
            return par.items.len - 1;
        }
        fn root(par: []const ?usize, id: usize) usize {
            var cur = id;
            while (par[cur]) |n| cur = n;
            return cur;
        }
        fn isHot(par: []const ?usize, tm: []const Temp, id: usize) bool {
            return switch (tm[root(par, id)]) {
                .hot => true,
                .count => |n| n > 0,
            };
        }
        fn add(par: []const ?usize, tm: []Temp, id: usize, d: isize) void {
            const r = root(par, id);
            switch (tm[r]) {
                .hot => {},
                .count => |n| tm[r] = .{ .count = @intCast(@as(isize, @intCast(n)) + d) },
            }
        }
    };
    const a = p.arena;
    var vals = std.AutoHashMapUnmanaged(Loc, ?V).empty;
    try vals.put(a, .gas, .{ .clique = try C.next(a, &parent, &temps), .heats = false });
    for (p.objects.items, 0..) |_, i| try vals.put(a, .{ .object = @intCast(i) }, .{ .clique = try C.next(a, &parent, &temps), .heats = false });
    for (p.withdrawals.items, 0..) |_, i| try vals.put(a, .{ .withdrawal = @intCast(i) }, .{ .clique = try C.next(a, &parent, &temps), .heats = false });
    for (p.pure.items, 0..) |_, i| try vals.put(a, .{ .pure = @intCast(i) }, .{ .clique = try C.next(a, &parent, &temps), .heats = false });
    for (p.receiving.items, 0..) |_, i| try vals.put(a, .{ .receiving = @intCast(i) }, .{ .clique = try C.next(a, &parent, &temps), .heats = false });
    for (p.cmds.items, 0..) |*c, ci| {
        var arg_cliques: std.ArrayList(struct { u16, usize }) = .empty;
        for (c.args) |arg| {
            if (arg.loc == .tx_context) continue;
            const slot = vals.getPtr(arg.loc) orelse return p.diag.unsupported("private entry: unknown location");
            const v = slot.* orelse return p.diag.unsupported("private entry: moved value");
            if (arg.kind == .use and arg.move) {
                slot.* = null;
                if (v.heats) C.add(parent.items, temps.items, v.clique, -1);
            }
            // copy/borrow: a new value in the clique, released right away
            try arg_cliques.append(a, .{ arg.idx, v.clique });
        }
        // exec-history: before `restrict_hot_or_not_entry_functions` (v3) only private counts
        const non_public = if (versions.executionVersion(p.cfg) < versions.latest and !p.cfg.feature_flags.restrict_hot_or_not_entry_functions) (if (c.call) |call| call.visibility == .Private else false) else (if (c.call) |call| call.visibility != .Public else false);
        // `is_entry && is_non_public && !Mode::allow_arbitrary_values()`
        if (c.call) |call| if (call.is_entry and non_public and !p.skip_checks) {
            for (arg_cliques.items) |ac| if (C.isHot(parent.items, temps.items, ac[1]))
                return p.diag.failWith(.{ .CommandArgumentError = .{ .arg_idx = ac[0], .kind = .InvalidArgumentToPrivateEntryFunction } }, p.annot(ci));
        };
        // merge
        var roots: std.ArrayList(usize) = .empty;
        for (arg_cliques.items) |ac| {
            const r = C.root(parent.items, ac[1]);
            for (roots.items) |x| {
                if (x == r) break;
            } else try roots.append(a, r);
        }
        std.mem.sort(usize, roots.items, {}, std.sort.asc(usize));
        const merged: usize = switch (roots.items.len) {
            0 => try C.next(a, &parent, &temps),
            1 => roots.items[0],
            else => blk: {
                const m = try C.next(a, &parent, &temps);
                var t: Temp = .{ .count = 0 };
                for (roots.items) |r| {
                    t = switch (temps.items[r]) {
                        .hot => .hot,
                        .count => |n| switch (t) {
                            .hot => .hot,
                            .count => |x| .{ .count = x + n },
                        },
                    };
                    parent.items[r] = m;
                }
                temps.items[m] = t;
                for (arg_cliques.items) |ac| parent.items[ac[1]] = m;
                break :blk m;
            },
        };
        if (c.post_checks) temps.items[C.root(parent.items, merged)] = .hot;
        for (c.results, 0..) |t, j| {
            const loc: Loc = .{ .result = .{ @intCast(ci), @intCast(j) } };
            if (c.drop[j]) {
                try vals.put(a, loc, null);
                continue;
            }
            const ab = abilities(t);
            const heats = !ab.hasDrop() and !ab.hasStore();
            if (heats) C.add(parent.items, temps.items, merged, 1);
            try vals.put(a, loc, .{ .clique = merged, .heats = heats });
        }
    }
}

// Mainnet certified effects (TransactionEffects V1, protocol 9, execution version 0) of the four
// transactions whose Move-call type argument or MakeMoveVec element type names a module the
// package lacks: Sui answers LINKER_ERROR, so VMVerificationOrDeserializationError.
const cp1659149_tx9_effects_hex = "00010d010300000000000000150000000000000000c2eb0b00000000c0261e000000000090d91d0000000000304d000000000000027cb0010274f4f86ca0f7a387a72bde497b3c2b7d9fa76400657bb7d9f6f40f925503180000000000ab59f054a27f97adb14c4d5eca7ee4dbccade998285b9c5c5400ab00f8ee672d560318000000000004aeab97f96cf9877fee2883315d459552b2b921edc16d7ceac6eab944dd88919c3b2e1a000000000020e6ce17c0556d9f368be51cf4ff29e69032c93887f071021827518e080683e81000000000000000000000000000000000000000000000000000000000000000060e51190000000000202b2783ca2cebe5de9509b8638a71449c68ddb4b620bc63d63053d3663e049975428b5795904d5256d1eea5991df672934315fb8dcf8f6111134c1a52afd005ca540318000000000020c97ad50afe7130c45034bc11f7dce4e31600e0290a05c644185c2c23212fb6fc9a6d328a6ebd906ed842e6e874e14bea69efa1c421fbfe7f689c33412a43c41c6f01180000000000208a6db7bb4817356e7598d226d654d82557aeda6b2f04b03f7764679f84df97e820dc86ba1be2795d9c9739955001b22f2409de4488f8c95b3b1fe1a2c4db7187fc00027cb0010274f4f86ca0f7a387a72bde497b3c2b7d9fa76400657bb7d9f6f40f923c2e1a00000000002070a96765fa655937b508b4095b876f7c88ca8e740b2b7071aeeeb451f11aaa14008a0fac6e8b1ddbec8b61f2a55a1025c94a60f5dadda8e0990eed4029f52bea39ab59f054a27f97adb14c4d5eca7ee4dbccade998285b9c5c5400ab00f8ee672d3c2e1a000000000020eccd584cbe92fee0f68f8f5070ea5e2d002ba6af053d9c00803fb281423c011d008a0fac6e8b1ddbec8b61f2a55a1025c94a60f5dadda8e0990eed4029f52bea39000000007cb0010274f4f86ca0f7a387a72bde497b3c2b7d9fa76400657bb7d9f6f40f923c2e1a00000000002070a96765fa655937b508b4095b876f7c88ca8e740b2b7071aeeeb451f11aaa14008a0fac6e8b1ddbec8b61f2a55a1025c94a60f5dadda8e0990eed4029f52bea390009200fc17ee3fac132689ac60ebdb3eeb81276a0699eb20ddd62ad1437bd1f6b889b206c2a8845d43f15d7271599fe450e41be0d328253405d4dcb8ac0534d514f51b72089b9b22df4963e7a61e21200064a28e2b2e58d6db613b76b5316023cbb22d5612091cb355499f2cb463eb5811bed46728dde1a3da145e53c1eabfefaa6df59af0420a4310f801c8ef4f231e1787f17110a8e2fc7d9b9976f19aa643400d789dc7a6020b826b2c265af1c129c7d973bfad3b991902bc14b3bd325ddd3844e2202b5684320d0835812c83e5c6451d06aaf3b8708a69b59942425d412e79e91cb49fdab8ddd20dc79bde1c87ec0c2125fa181341890175baf923f34c91b812469bc013e4e8c2d20fc70bef5c9619685807cf9eba5b3a4181cc6f8b979b649aa78759b6f10984419";
const cp1665877_tx5_effects_hex = "00010d0100000000000000001500000000000000102700000000000000000000000000000000000000000000000000000000000001001563d2fe15765226d3f2ae64203d692596a9e15dfe92c38cbc97580a1fe94c0c94190000000000002061f7eeab63107758e6beea523113bcbedfeacfd40fec0c1fc3045ae6e6a35a810001001563d2fe15765226d3f2ae64203d692596a9e15dfe92c38cbc97580a1fe94c0d941900000000002042ed40dd3c053c75d9ea14fd2cfcae10f8842ad9c3e358565d2a589e26b181d600afccb597485e309269dfa77dcf0dd5d798fced36f1194c5ca9b3d7ef4465f3dc00000000001563d2fe15765226d3f2ae64203d692596a9e15dfe92c38cbc97580a1fe94c0d941900000000002042ed40dd3c053c75d9ea14fd2cfcae10f8842ad9c3e358565d2a589e26b181d600afccb597485e309269dfa77dcf0dd5d798fced36f1194c5ca9b3d7ef4465f3dc0003205e96beff4f338529bcc4b3c9dd6dc687726ac2ff58dab1337a5f92e1016a8251209910ec7ed307e534fc5f9b73a792c3816861db75e0138b02485e02e5f131b32c20fc70bef5c9619685807cf9eba5b3a4181cc6f8b979b649aa78759b6f10984419";
const cp1715740_tx12_effects_hex = "00010d010000000000000000160000000000000040420f0000000000a049390000000000c0a347000000000040b9000000000000034181083e2ee2c7b9c023a225479f76cc683a5019367053e8d9e1317ddced026afa3c1a0000000000d8a90e2a2a73567a4c017d386a096c291d954f38789700638ae97e62b44c357ddd851b00000000005b4585df4d59011015494a9854dd956102977f6c2adad9c3f055726e88841498f5b418000000000002d8a90e2a2a73567a4c017d386a096c291d954f38789700638ae97e62b44c357ddd851b000000000020afc8c314c2c81232f42841ffa46660aec24cda6f1643f8bb096b9ce861cc2c2600000000000000000000000000000000000000000000000000000000000000061d2e1a000000000020a34b74b6bd9e910b0b0b37afb1a41269325007554a3786916f97e07f440aa98420f7f4cd0099c15317cba6e431fffc482ddb51b736cac7e21e09c1e4332b1fc41900024181083e2ee2c7b9c023a225479f76cc683a5019367053e8d9e1317ddced026ade851b000000000020a83ae40eb8c1f6633bd06ea24547d5103a467294bf4b0452706545df904e4ac70098e6a947aa699c4160c2441566c6166aeee138331f716432a90ace3c4ba03755d8a90e2a2a73567a4c017d386a096c291d954f38789700638ae97e62b44c357dde851b00000000002055973b3d363f1f191c3a82c7e6cf6e569aaff1255f225595ad0a64fc124418bc0268341b000000000000015b4585df4d59011015494a9854dd956102977f6c2adad9c3f055726e88841498de851b000000000020636363636363636363636363636363636363636363636363636363636363636300004181083e2ee2c7b9c023a225479f76cc683a5019367053e8d9e1317ddced026ade851b000000000020a83ae40eb8c1f6633bd06ea24547d5103a467294bf4b0452706545df904e4ac70098e6a947aa699c4160c2441566c6166aeee138331f716432a90ace3c4ba03755000520914adcfe9d9b6216ffe81b8efa01f3bf3b5dc1b9e3bea8f6940a4088192ef6c820a642ffd7b6b1404ffa91ba1f688479b691bc4112e6d2dc1fe7a938ace1feed5120bbbc1470424f5266e1da7aeab4b3f6dbf3359a9f0bb9e64412aa90ea86eb0dea20c5af9c7e7374b03cd933b80b5102334a26f90541d81274f8a0e499df2b36034a20e6acf8b09b634a6f24f32357ebfd9ccec173520e005ad427238e880a67a6a051";
const cp1727582_tx3_effects_hex = "00010d010100000000000000160000000000000040420f000000000050a5690000000000dc96680000000000740e01000000000004000dd2eac211fb5a67d5d2a59bf67b2bbcc8f3232716023843ad24d63c6d0903ad0b0000000000005ffe2ab9679399bc59c07934542f996c04b7afc7a3f9414d74b4392e4faeb38ead0b000000000000943dda193c8bc6ed063a4f21ba8745b95070b88fc758a9dfc24ed252f16c8347bc0b0000000000009b204ec23b657fe9a8e4e12ca9c2bde95984b057da405dd775a32e992cafd6f8bc0b00000000000001000dd2eac211fb5a67d5d2a59bf67b2bbcc8f3232716023843ad24d63c6d0903ad0b00000000000020a0722473b24c870c9bb0e4be61350addf5abb97c781013fc5ed4e7920637f04b205ff6d01d3b0e23e23248f8824647f5963f9bc19db6d0eff37b3b1bc7679b54d70004000dd2eac211fb5a67d5d2a59bf67b2bbcc8f3232716023843ad24d63c6d0903bd0b0000000000002040c68e357b3ae0b31d03c23ce8392031345c9aabbe3529920ef3845afb9fd96d028d0b0000000000005ffe2ab9679399bc59c07934542f996c04b7afc7a3f9414d74b4392e4faeb38ebd0b0000000000002052d6c4504219d9b49cb93e6d40ea974b5dca384ffcbd92ad6ad90f9a05cdde42002a6f41cf99c51bcee58cd5154e49b7a48a52f715aa34b6606f2ca270d1fbe8a3943dda193c8bc6ed063a4f21ba8745b95070b88fc758a9dfc24ed252f16c8347bd0b00000000000020fd4c54f195d1c1027498bedd14afe734d725d47ef77a9b48579d69c6b41fe0c2002a6f41cf99c51bcee58cd5154e49b7a48a52f715aa34b6606f2ca270d1fbe8a39b204ec23b657fe9a8e4e12ca9c2bde95984b057da405dd775a32e992cafd6f8bd0b00000000000020c896301199598bce1833cd3175de09f1f9ed308a59b05b2231367ed38b87dd0c002a6f41cf99c51bcee58cd5154e49b7a48a52f715aa34b6606f2ca270d1fbe8a300000000943dda193c8bc6ed063a4f21ba8745b95070b88fc758a9dfc24ed252f16c8347bd0b00000000000020fd4c54f195d1c1027498bedd14afe734d725d47ef77a9b48579d69c6b41fe0c2002a6f41cf99c51bcee58cd5154e49b7a48a52f715aa34b6606f2ca270d1fbe8a30005204e45f51390c1ed526f63ad95e90d0ff030962524b0e9bc755945f8b2c25123a62076bf343aca193e20d7fa68af38409024e304d54087b45eba2e54dae236484770209386f74d1337faab006b973046ecfe9d4c32ef1fd2fd3fabc344ae3577c0ae7320bc72ea1ed129702faa5178be9ce3384d911b5bc4c5271860dee2a1a0c2e5650d20cb0956f41626d50a022b388f43d39e2f7f14fc4d765580f211ef1a15dd60f5f8";

fn testHex(comptime h: []const u8) [h.len / 2]u8 {
    @setEvalBranchQuota(100_000);
    var out: [h.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

fn testStruct(addr: Id, module: []const u8, name: []const u8) types.TypeInput {
    return .{ .@"struct" = .{ .address = .{ .@"0" = addr }, .module = .{ .@"0" = module }, .name = .{ .@"0" = name }, .type_args = &.{} } };
}

/// The error `fromInputAt` reports for `ti` at protocol `pv` over the stub packages.
fn testLoadError(gpa: Allocator, pv: u64, stubs: []const *pkgs.Pkg, ti: *const types.TypeInput, idx: usize, site: TypeSite) !types.ExecutionErrorKind {
    var store: @import("../packages.zig").Store = .{ .loaded = true };
    const cache = try pkgs.Cache.init(gpa, &store, 21, pv, .mainnet);
    for (stubs) |s| try cache.map.put(gpa, s.version_id, s);
    const cfg = try protocol.get(pv, .mainnet);
    var diag: pkgs.Diag = .{};
    var linker: pkgs.Linker = .{ .arena = gpa, .cache = cache, .cfg = cfg, .diag = &diag, .authoritative = true };
    var p: Ptb = .{ .arena = gpa, .cfg = cfg, .linker = &linker, .diag = &diag, .meter = undefined, .pt = undefined };
    if (fromInputAt(&p, idx, ti, site)) |_| return error.TestUnexpectedResult else |e| switch (e) {
        error.Fail => return diag.fail.kind,
        else => return e,
    }
}

test "type input naming a module the package lacks (mainnet 1659149, 1665877, 1715740, 1727582)" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // certified: VMVerificationOrDeserializationError in commands 4, 1, 1 and 2
    const certified = [_]struct { []const u8, u64 }{
        .{ &testHex(cp1659149_tx9_effects_hex), 3 },
        .{ &testHex(cp1665877_tx5_effects_hex), 0 },
        .{ &testHex(cp1715740_tx12_effects_hex), 0 },
        .{ &testHex(cp1727582_tx3_effects_hex), 1 },
    };
    for (certified) |c| {
        const fx = (try @import("bcs").decode(types.TransactionEffects, arena, c[0])).V1;
        try std.testing.expect(fx.status.Failure.@"error" == .VMVerificationOrDeserializationError);
        try std.testing.expectEqual(@as(?u64, c[1]), fx.status.Failure.command);
    }
    const hexId = struct {
        fn f(comptime h: []const u8) Id {
            return testHex(h);
        }
    }.f;
    const stub = struct {
        fn f(al: Allocator, id: Id, modules: []const []const u8, origins: []const move_vm.loader.TypeOrigin) !*pkgs.Pkg {
            const ms = try al.alloc(move_vm.loader.NamedModule, modules.len);
            for (modules, ms) |n, *m| m.* = .{ .name = n, .bytes = &.{} };
            const p = try al.create(pkgs.Pkg);
            p.* = .{ .raw = &.{}, .view = undefined, .version_id = id, .original_id = id, .version = 1, .linkage = &.{}, .type_origins = origins, .modules = ms, .gas_size = 0 };
            return p;
        }
    }.f;
    var two: Id = @splat(0);
    two[31] = 2;
    const pyth = hexId("a446c4a37c0bb69d03357c1a52d60da0b434048226d5f3feffdb693586bea861");
    const airdrop = hexId("b33832ed8b4ede0060f3841d1135b636245f0b28f9b71338b6be55d6b55a465c");
    const joysticks = hexId("bcaf501b531e8120f0331eca6076c753f04bff7bc4268ab7d5022b56ffb4509d");
    const stubs = [_]*pkgs.Pkg{
        try stub(arena, two, &.{ "coin", "sui" }, &.{ .{ .module = "coin", .name = "Coin", .defining = two }, .{ .module = "sui", .name = "SUI", .defining = two } }),
        try stub(arena, pyth, &.{ "price", "pyth" }, &.{.{ .module = "price", .name = "Price", .defining = pyth }}),
        try stub(arena, airdrop, &.{"airdrop"}, &.{.{ .module = "airdrop", .name = "Airdrop", .defining = airdrop }}),
        try stub(arena, joysticks, &.{"joysticks"}, &.{.{ .module = "joysticks", .name = "JOYSTICKS", .defining = joysticks }}),
    };
    const Case = struct { ti: types.TypeInput, site: TypeSite };
    const cases = [_]Case{
        .{ .ti = testStruct(pyth, "vaa", "VAA"), .site = .vec }, // 1659149 tx 9, MakeMoveVec<0xa446::vaa::VAA>
        .{ .ti = testStruct(two, "token", "TOKEN"), .site = .call }, // 1665877 tx 5, coin::mint_and_transfer<0x2::token::TOKEN>
        .{ .ti = testStruct(airdrop, "ai_pepe", "SUI_PEPE"), .site = .call }, // 1715740 tx 12, claim_ref_airdrop<..>
        .{ .ti = testStruct(joysticks, "clutchynfts", "ClutchyNft"), .site = .call }, // 1727582 tx 3, init_warehouse<..>
    };
    for (cases) |c| {
        // protocol 9 (execution version 0): LINKER_ERROR, as certified
        try std.testing.expect(try testLoadError(arena, 9, &stubs, &c.ti, 0, c.site) == .VMVerificationOrDeserializationError);
        // the static executor (latest): TypeNotFound
        const latest = try testLoadError(arena, protocol.max_protocol_version, &stubs, &c.ti, 0, c.site);
        try std.testing.expectEqual(types.TypeArgumentError.TypeNotFound, latest.TypeArgumentError.kind);
    }
    // a struct missing from a present module is TYPE_RESOLUTION_FAILURE: TypeNotFound for a call,
    // VMVerificationOrDeserializationError for a v0 MakeMoveVec
    const no_struct = testStruct(airdrop, "airdrop", "Nope");
    const call = try testLoadError(arena, 9, &stubs, &no_struct, 1, .call);
    try std.testing.expectEqual(types.TypeArgumentError.TypeNotFound, call.TypeArgumentError.kind);
    try std.testing.expectEqual(@as(u16, 1), call.TypeArgumentError.argument_idx);
    try std.testing.expect(try testLoadError(arena, 9, &stubs, &no_struct, 0, .vec) == .VMVerificationOrDeserializationError);
}

// ---- DevInspect<true> (`Ptb.skip_checks`): the checks `Mode::allow_arbitrary_values()` and
// `Mode::allow_arbitrary_function_calls()` gate, each against the same input with checks on.

fn testStubPkg(al: Allocator, id: Id) !*pkgs.Pkg {
    const p = try al.create(pkgs.Pkg);
    p.* = .{ .raw = &.{}, .view = undefined, .version_id = id, .original_id = id, .version = 1, .linkage = &.{}, .type_origins = &.{}, .modules = &.{}, .gas_size = 0 };
    return p;
}

fn testCall(pkg: *pkgs.Pkg, module: []const u8, name: []const u8, visibility: ff.Visibility, is_entry: bool, returns: []const Ty) Call {
    return .{ .pkg = pkg, .module = module, .name = name, .func = undefined, .ty_args = &.{}, .params = &.{}, .returns = returns, .visibility = visibility, .is_entry = is_entry, .linkage_entries = 0, .linkage = &.{} };
}

fn testPtb(arena: Allocator, cfg: *const protocol.ProtocolConfig, diag: *pkgs.Diag, pt: *const types.ProgrammableTransaction, skip_checks: bool) Ptb {
    return .{ .arena = arena, .cfg = cfg, .linker = undefined, .diag = diag, .meter = undefined, .pt = pt, .skip_checks = skip_checks };
}

test "skip_checks: check_visibility lets private and friend functions through, check_private_generics_v2 does not" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const cfg = try protocol.get(protocol.max_protocol_version, .mainnet);
    const pt: types.ProgrammableTransaction = .{ .inputs = &.{}, .commands = &.{} };
    const user = try testStubPkg(arena, @splat(0xab));
    var two: Id = @splat(0);
    two[31] = 2;
    const fw = try testStubPkg(arena, two);
    for ([_]ff.Visibility{ .Private, .Friend }) |vis| {
        const call = testCall(user, "m", "f", vis, false, &.{});
        var diag: pkgs.Diag = .{};
        var checked = testPtb(arena, cfg, &diag, &pt, false);
        try std.testing.expectError(error.Fail, moveFunction(&checked, &call));
        try std.testing.expect(diag.fail.kind == .NonEntryFunctionInvoked);
        var relaxed = testPtb(arena, cfg, &diag, &pt, true);
        try moveFunction(&relaxed, &call);
        // entry functions and public functions pass in both modes
        try moveFunction(&checked, &testCall(user, "m", "f", vis, true, &.{}));
    }
    var diag: pkgs.Diag = .{};
    var checked = testPtb(arena, cfg, &diag, &pt, false);
    try moveFunction(&checked, &testCall(user, "m", "f", .Public, false, &.{}));
    // `0x2::transfer::transfer` has an internal type parameter: rejected in every mode
    const internal = testCall(fw, "transfer", "transfer", .Public, false, &.{});
    for ([_]bool{ false, true }) |skip| {
        var d: pkgs.Diag = .{};
        var p = testPtb(arena, cfg, &d, &pt, skip);
        try std.testing.expectError(error.Fail, moveFunction(&p, &internal));
        try std.testing.expect(d.fail.kind == .NonEntryFunctionInvoked);
    }
}

test "skip_checks: check_signature lets a reference return type through before allow_references_in_ptbs" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // the newest protocol version without `allow_references_in_ptbs`
    var v: u64 = protocol.max_protocol_version;
    const cfg = while (v > 0) : (v -= 1) {
        const c = protocol.get(v, .mainnet) catch continue;
        if (!c.feature_flags.allow_references_in_ptbs) break c;
    } else return error.SkipZigTest;
    const pt: types.ProgrammableTransaction = .{ .inputs = &.{}, .commands = &.{} };
    const user = try testStubPkg(arena, @splat(0xab));
    const ref_u64 = try mk(arena, .{ .ref = &Type.t_u64 });
    const call = testCall(user, "m", "f", .Public, false, &.{ &Type.t_u64, ref_u64 });
    var diag: pkgs.Diag = .{};
    var checked = testPtb(arena, cfg, &diag, &pt, false);
    try std.testing.expectError(error.Fail, moveFunction(&checked, &call));
    try std.testing.expectEqual(@as(u16, 1), diag.fail.kind.InvalidPublicFunctionReturnType.idx);
    var relaxed = testPtb(arena, cfg, &diag, &pt, true);
    try moveFunction(&relaxed, &call);
}

test "skip_checks: check_pure_bytes accepts any type and any bytes" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const cfg = try protocol.get(protocol.max_protocol_version, .mainnet);
    const pt: types.ProgrammableTransaction = .{ .inputs = &.{ .{ .Pure = &.{ 1, 2, 3 } }, .{ .Pure = &@as([32]u8, @splat(7)) } }, .commands = &.{} };
    const Case = struct { loc: PureLoc, want: types.CommandArgumentError };
    const cases = [_]Case{
        // three bytes are not a u64
        .{ .loc = .{ .input = 0, .ty = &Type.t_u64, .cmd = 4, .arg = 2 }, .want = .InvalidBCSBytes },
        // a signer is not a primitive argument type
        .{ .loc = .{ .input = 1, .ty = &Type.t_signer, .cmd = 5, .arg = 3 }, .want = .InvalidUsageOfPureArg },
    };
    for (cases) |c| {
        var diag: pkgs.Diag = .{};
        var checked = testPtb(arena, cfg, &diag, &pt, false);
        try checked.pure.append(arena, c.loc);
        try std.testing.expectError(error.Fail, inputArguments(&checked));
        try std.testing.expectEqual(std.meta.activeTag(c.want), std.meta.activeTag(diag.fail.kind.CommandArgumentError.kind));
        try std.testing.expectEqual(c.loc.arg, diag.fail.kind.CommandArgumentError.arg_idx);
        try std.testing.expectEqual(@as(?u64, c.loc.cmd), diag.fail.command);
        var relaxed = testPtb(arena, cfg, &diag, &pt, true);
        try relaxed.pure.append(arena, c.loc);
        try inputArguments(&relaxed);
    }
}

test "skip_checks: a hot argument to a private entry function passes" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const cfg = try protocol.get(protocol.max_protocol_version, .mainnet);
    const pt: types.ProgrammableTransaction = .{ .inputs = &.{.{ .Pure = &@as([8]u8, @splat(0)) }}, .commands = &.{} };
    const user = try testStubPkg(arena, @splat(0xab));
    var call = testCall(user, "m", "f", .Private, true, &.{});
    for ([_]bool{ false, true }) |skip| {
        var diag: pkgs.Diag = .{};
        var p = testPtb(arena, cfg, &diag, &pt, skip);
        try p.pure.append(arena, .{ .input = 0, .ty = &Type.t_u64, .cmd = 0, .arg = 0 });
        // command 0 incurs post-execution checks, which heats the clique of its argument;
        // command 1 passes the same value to a private entry function
        const args0 = try arena.dupe(Arg, &.{.{ .idx = 0, .kind = .use, .loc = .{ .pure = 0 }, .ty = &Type.t_u64 }});
        const args1 = try arena.dupe(Arg, &.{.{ .idx = 0, .kind = .use, .loc = .{ .pure = 0 }, .ty = &Type.t_u64 }});
        try p.cmds.append(arena, .{ .tag = .make_vec, .args = args0, .post_checks = true, .annot = 0 });
        try p.cmds.append(arena, .{ .tag = .call, .call = &call, .args = args1, .annot = 1 });
        if (skip) {
            try privateEntry(&p);
        } else {
            try std.testing.expectError(error.Fail, privateEntry(&p));
            try std.testing.expect(diag.fail.kind.CommandArgumentError.kind == .InvalidArgumentToPrivateEntryFunction);
            try std.testing.expectEqual(@as(u16, 0), diag.fail.kind.CommandArgumentError.arg_idx);
            try std.testing.expectEqual(@as(?u64, 1), diag.fail.command);
        }
    }
}
