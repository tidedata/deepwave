//! Execution of a typed programmable transaction (`execution/{interpreter,context}.rs`):
//! input loading with its gas, argument usage charges, the commands, Move calls through one
//! move_vm Session over the unified linkage, events, and `Context::finish` into results.
const std = @import("std");
const types = @import("types");
const bcs = @import("bcs");
const move_vm = @import("move_vm");
const natives = @import("natives");
const move_format = @import("move_format");
const ff = move_format.file_format;
const typing = @import("typing.zig");
const versions = @import("../versions/root.zig");
const pkgs = @import("pkgs.zig");
const deny = @import("deny.zig");
const compat = @import("compat.zig");

const Allocator = std.mem.Allocator;
const Value = move_vm.Value;
const Ty = typing.Ty;
const Loc = typing.Loc;
const Error = pkgs.Error;
const LV = natives.abi.Value;
const objrt = natives.objrt;
const vm_host = move_vm.host;
const vm_value = move_vm.value;

pub const Write = struct { id: [32]u8, owner: types.Owner, tag: types.StructTag, has_public_transfer: bool, contents: []const u8, old_version: u64 };

/// A package the transaction published: its id and BCS `MovePackage`.
pub const NewPackage = struct { id: [32]u8, version: u64, bytes: []const u8 };

/// A package of `Run.new_pkgs`: the VM-side package and its `MovePackage`.
pub const TxPkg = struct { pkg: *pkgs.Pkg, mp: types.MovePackage };

pub const Results = struct {
    writes: []const Write,
    /// (id, version) of every object the transaction loaded mutably or as a child, modified or not.
    modified: []const [32]u8,
    created: []const [32]u8,
    deleted: []const [32]u8,
    events: []const types.Event,
    /// The per-epoch deny list config was read (coin owners of non-SUI coins).
    deny_list_read: bool,
    non_gas_coin_owners: u64,
    /// The (coin type, owner) pairs behind `non_gas_coin_owners`: the deny list v2 check reads
    /// config for them (rpc-exec replays those tracked reads; a later revert does not undo them).
    deny_pairs: []deny.Pair = &.{},
    /// Loaded child objects (id, version), for their input states.
    children: []const objrt.ObjectRuntime.LoadedChild,
    /// Accumulator events (the object runtime's, then finish_gas_coin's for address-balance gas).
    acc: []const AccWrite = &.{},
    /// Address-balance gas: the ephemeral coin was transferred (the charge then goes to it).
    gas_transferred: bool = false,
    gas_send_to: ?[32]u8 = null,
    gas_id: [32]u8 = @splat(0),
    /// Published packages (`package_store.to_new_packages`), in publication order.
    packages: []const NewPackage = &.{},
    /// `Run.track`: one entry per executed command (`Mode::finish_command`), else null.
    command_results: ?[]const CommandResult = null,
};

/// One value of a DevInspect command result (`ExecutionResults::V2`): BCS bytes and type tag;
/// `arg` is set for a `&mut` argument's value after the command (`mutated_by_ref`).
pub const TrackedValue = struct { arg: ?types.Argument = null, bytes: []const u8, ty: types.TypeTag };
/// One command's DevInspect results: `(argument_updates, return_values)`.
pub const CommandResult = struct { mutated: []const TrackedValue, returns: []const TrackedValue };

/// BCS `TypeTag` of a non-SUI coin type and an owner receiving it.
pub const DenyPair = struct { t: []const u8, o: [32]u8 };

/// One accumulator event of the transaction (context::finish `AccumulatorEvent`).
pub const AccWrite = struct { id: [32]u8, addr: [32]u8, ty: types.TypeTag, op: types.AccumulatorOperation, value: types.AccumulatorValue };

/// `AccumulatorEvent::from_balance_change(addr, Balance<SUI>, change)` (change != 0).
pub fn balanceWrite(arena: Allocator, addr: [32]u8, change: i64) !AccWrite {
    return .{
        .id = balanceAccumulatorId(&addr),
        .addr = addr,
        .ty = try suiBalanceTag(arena),
        .op = if (change < 0) .Split else .Merge,
        .value = .{ .Integer = @abs(change) },
    };
}

fn frameworkStruct(arena: Allocator, module: []const u8, name: []const u8, args: []const types.TypeTag) !types.TypeTag {
    var two: [32]u8 = @splat(0);
    two[31] = 2;
    return .{ .@"struct" = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = module }, .name = .{ .@"0" = name }, .type_args = try arena.dupe(types.TypeTag, args) } };
}

/// `Balance<SUI>`.
pub fn suiBalanceTag(arena: Allocator) !types.TypeTag {
    const sui = try frameworkStruct(arena, "sui", "SUI", &.{});
    return frameworkStruct(arena, "balance", "Balance", &.{sui});
}

/// `AccumulatorValue::get_field_id(addr, Balance<SUI>)`: the dynamic field id of
/// `accumulator::Key<Balance<SUI>> { address }` under the accumulator root 0xacc.
pub fn balanceAccumulatorId(addr: *const [32]u8) [32]u8 {
    var buf: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const a = fba.allocator();
    const bal = suiBalanceTag(a) catch unreachable;
    const key = frameworkStruct(a, "accumulator", "Key", &.{bal}) catch unreachable;
    const tag = bcs.encodeAlloc(types.TypeTag, a, &key) catch unreachable;
    var root: [32]u8 = @splat(0);
    root[30] = 0x0a;
    root[31] = 0xcc;
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, 32, .little);
    return @import("hash").blake2b256(&.{ &[_]u8{0xf0}, &root, &len_le, addr, tag });
}

pub const Run = struct {
    p: *typing.Ptb,
    arena: Allocator,
    host: *move_vm.Host,
    sess: move_vm.Session,
    link: *move_vm.LinkCtx,
    budget: u64,
    sender: [32]u8,
    /// The smashed gas coin, or for address-balance payment the payer (`ephemeral`: the coin is
    /// created by Context::new with the budget as its value).
    /// `amount`: the ephemeral coin's value (`GasPayment::amount`, the total smashed).
    gas: struct { id: [32]u8 = @splat(0), version: u64 = 0, owner: types.Owner, contents: []const u8 = &.{}, ephemeral: bool = false, amount: u64 = 0, absent: bool = false },
    objs: []Value,
    wds: []Value = &.{},
    gas_val: Value = Value.invalid,
    pure: []Value,
    recv: []Value,
    results: std.ArrayList([]Value) = .empty,
    tx_ctx: Value = Value.invalid,
    events: std.ArrayList(types.Event) = .empty,
    gas_moved: bool = false,
    /// `GasCoinTransfer::SendFunds { recipient }`.
    gas_send_to: ?[32]u8 = null,
    events_taken: usize = 0,
    /// Per-call link contexts (unified linkage off), released with the session.
    call_links: std.ArrayList(*move_vm.LinkCtx) = .empty,
    packages: std.ArrayList(NewPackage) = .empty,
    /// Storage ids of every package this transaction added to the VM runtime (removed when it
    /// ends: Rust's package store lives for one transaction).
    published: std.ArrayList([32]u8) = .empty,
    /// The packages this transaction published or upgraded, by storage id (Rust's
    /// `TransactionPackageStore::new_packages`): a later Upgrade's current package or a later
    /// Publish/Upgrade dependency is fetched from here first (`fetch_move_package`).
    new_pkgs: std.AutoArrayHashMapUnmanaged([32]u8, TxPkg) = .empty,
    /// `Mode::TRACK_EXECUTION` (DevInspect): record every command's `&mut` argument values and
    /// return values into `tracked`. Tracking reads values without metering, as Rust's
    /// `argument_updates` / `tracked_results` do, so gas and effects are unchanged.
    track: bool = false,
    tracked: std.ArrayList(CommandResult) = .empty,

    fn heap(r: *Run) vm_value.Heap {
        return r.sess.heap;
    }
    fn meter(r: *Run) *move_vm.Meter {
        return r.p.meter;
    }
    fn diag(r: *Run) *pkgs.Diag {
        return r.p.diag;
    }

    fn gasFail(r: *Run) error{Fail} {
        return r.diag().failWith(.InsufficientGas, null);
    }

    fn charge(r: *Run, comptime f: anytype, args: anytype) Error!void {
        @call(.auto, f, .{r.meter()} ++ args) catch return r.chargeFail();
    }

    fn chargeFail(r: *Run) error{Fail} {
        return r.diag().failWith(convertStatus(r, r.meter().err, null, null), null);
    }

    fn sizeOf(r: *Run, v: Value) u64 {
        return vm_value.size(v, r.meter().plain);
    }

    fn slot(r: *Run, l: Loc) *Value {
        return switch (l) {
            .tx_context => &r.tx_ctx,
            .gas => &r.gas_val,
            .object => |i| &r.objs[i],
            .withdrawal => |i| &r.wds[i],
            .pure => |i| &r.pure[i],
            .receiving => |i| &r.recv[i],
            .result => |x| &r.results.items[x[0]][x[1]],
        };
    }

    /// `Context::location`: loads pure/receiving values on first use, then the usage charge.
    fn location(r: *Run, kind: enum { move, copy, borrow }, l: Loc) Error!Value {
        const s = r.slot(l);
        if (s.tag == .invalid) switch (l) {
            .pure => |i| {
                const pl = r.p.pure.items[i];
                var rd = move_vm.loader.Reader{ .bytes = r.p.pureBytes(pl.input) };
                const v = move_vm.types.deserialize(r.heap(), pl.ty, &rd, 0) catch return r.diag().unsupported("pure value does not deserialize");
                try r.charge(move_vm.Meter.chargeCopyLoc, .{r.sizeOf(v)});
                try r.charge(move_vm.Meter.chargeStoreLoc, .{});
                s.* = v;
            },
            .receiving => |i| {
                const rl = r.p.receiving.items[i];
                const id = try r.heap().pack(.struct_, 0, &.{try r.heap().address(rl.id)});
                const v = try r.heap().pack(.struct_, 0, &.{ id, Value.u64_(rl.version) });
                try r.charge(move_vm.Meter.chargeCopyLoc, .{r.sizeOf(v)});
                try r.charge(move_vm.Meter.chargeStoreLoc, .{});
                s.* = v;
            },
            else => return r.diag().unsupported("use of a value without one"),
        };
        switch (kind) {
            .move => {
                const v = s.*;
                s.* = Value.invalid;
                try r.charge(move_vm.Meter.chargeMoveLoc, .{r.sizeOf(v)});
                if (l == .gas) r.gas_moved = true;
                return v;
            },
            .copy => {
                try r.charge(move_vm.Meter.chargeCopyLoc, .{r.sizeOf(s.*)});
                return try r.heap().copy(s.*);
            },
            .borrow => {
                try r.charge(move_vm.Meter.chargeSimple, .{.MutBorrowLoc});
                return Value.refSlot(s);
            },
        }
    }

    fn argument(r: *Run, a: typing.Arg) Error!Value {
        return switch (a.kind) {
            .use => r.location(if (a.move) .move else .copy, a.loc),
            .borrow => r.location(.borrow, a.loc),
            // freeze is a no-op on the reference value
            .freeze => r.location(if (a.move) .move else .copy, a.loc),
            .read => blk: {
                const ref = try r.location(if (a.move) .move else .copy, a.loc);
                if (!ref.isRef()) break :blk r.diag().unsupported("read of a value that is not a reference");
                try r.charge(move_vm.Meter.chargeReadRef, .{ vm_value.referentSize(ref, r.meter().plain), vm_value.referentSize(ref, r.meter().traversal) });
                break :blk if (ref.tag == .ref_elem) try vm_value.readElem(ref.cont(), ref.b, r.heap()) else try r.heap().copy(ref.slot().*);
            },
        };
    }

    // ---- coins: Coin { UID { ID { address } }, Balance { u64 } }

    fn coinBalance(v: Value) *Value {
        return &v.cont().values()[1].cont().values()[0];
    }
    fn coinId(v: Value) [32]u8 {
        return v.cont().values()[0].cont().values()[0].cont().values()[0].box().*;
    }

    fn newCoin(r: *Run, amount: u64) Error!Value {
        const id = r.host.tx.freshId();
        if (try r.host.rt.newId(r.arena, r.p.cfg, id)) |e| return r.diag().failWith(convertStatus(r, e.status, e.sub, null), null);
        const idv = try r.heap().pack(.struct_, 0, &.{try r.heap().address(id)});
        const uid = try r.heap().pack(.struct_, 0, &.{idv});
        const bal = try r.heap().pack(.struct_, 0, &.{Value.u64_(amount)});
        return r.heap().pack(.struct_, 0, &.{ uid, bal });
    }

    /// `copy_value` of a reference: copy_loc of the reference, then pop.
    fn copyRef(r: *Run, ref: Value) Error!void {
        try r.charge(move_vm.Meter.chargeCopyLoc, .{r.sizeOf(ref)});
        try r.charge(move_vm.Meter.chargePop, .{});
    }

    fn transfer(r: *Run, owner: objrt.Owner, ty: Ty, v: Value, end: bool) Error!void {
        // the runtime's type-argument cache: the tag and the layout to walk (no field types)
        const hit: ?natives.abi.TyArg = if (r.host.ty_cache) |tc| try tc.get(ty, vm_host.Limits.of(r.sess.cfg)) else null;
        const tag = if (hit) |h| h.tag else try vm_host.typeTag(r.arena, ty, .defining);
        const lv = if (hit) |h| try vm_host.toLayoutL(r.arena, h.traversal().?, v) else try vm_host.toLayout(r.arena, ty, v);
        switch (try r.host.rt.transfer(r.arena, r.p.cfg, owner, tag, lv, end)) {
            .ok => {},
            .err => |e| return r.diag().failWith(convertStatus(r, e.status, e.sub, null), null),
        }
    }
};

/// error.rs `convert_vm_error_impl`: `loc` is the error's module location (offsets default to 0).
fn convertStatus(r: *Run, status: anytype, sub: ?u64, loc: ?struct { m: *const move_vm.loader.Module, fdef: u16, pc: u16 }) types.ExecutionErrorKind {
    const code: u64 = @backingInt(status);
    if (code == 4001) return .VMInvariantViolation; // EXECUTED
    if (code == 4016) { // ABORTED
        const s = sub orelse return .VMInvariantViolation;
        // exec-history-vm: before protocol 48 (`resolve_abort_locations_to_package_id`) the abort
        // module stays the runtime id; v0..v2 adapters never relocate (their protocols are all < 48)
        if (loc) |l| return .{ .MoveAbort = .{ moveLocation(r, l.m, l.fdef, l.pc, r.p.cfg.feature_flags.resolve_abort_locations_to_package_id), s } };
    }
    if (code == 4002) return .InsufficientGas; // OUT_OF_GAS
    return switch (code) {
        4000...4999 => .{ .MovePrimitiveRuntimeError = .{ .@"0" = if (loc) |l| moveLocation(r, l.m, l.fdef, l.pc, false) else null } },
        2000...2999 => .VMInvariantViolation,
        else => .VMVerificationOrDeserializationError,
    };
}

fn moveLocation(r: *Run, m: *const move_vm.loader.Module, fdef: u16, pc: u16, relocate: bool) types.MoveLocation {
    var addr = m.pkg.original_id;
    if (relocate) {
        for (r.p.unified) |l| if (std.mem.eql(u8, &l[0], &addr)) {
            addr = l[1];
            break;
        };
    }
    // the name comes from the linked version of the module
    var name: ?[]const u8 = null;
    for (r.p.unified) |l| if (std.mem.eql(u8, &l[0], &m.pkg.original_id)) {
        if (r.p.linker.cache.rt.package(&l[1])) |vp| if (vp.module(m.name)) |vm| {
            if (fdef < vm.cm.function_defs.len) name = vm.cm.identifiers[vm.cm.function_handles[vm.cm.function_defs[fdef].function].name];
        };
        break;
    };
    return .{
        .module = .{ .address = .{ .@"0" = addr }, .name = .{ .@"0" = m.name } },
        .function = fdef,
        .instruction = pc,
        .function_name = if (name) |n| .{ .@"0" = n } else null,
    };
}

pub fn vmError(r: *Run, e: move_vm.VmError) types.ExecutionErrorKind {
    const m = e.module orelse return convertStatus(r, e.major, e.sub, null);
    const o = e.off orelse return convertStatus(r, e.major, e.sub, .{ .m = m, .fdef = 0, .pc = 0 });
    return convertStatus(r, e.major, e.sub, .{ .m = m, .fdef = o.fdef, .pc = o.pc });
}

/// `Context::new`: object inputs (in order), then the gas coin, then the budget held back.
pub fn init(r: *Run) Error!void {
    const p = r.p;
    for (p.objects.items, 0..) |*o, i| {
        const v = try loadObject(r, o.ty, o.view.contents(), o.id, o.view.version, o.owner);
        r.objs[i] = v;
    }
    // load_withdrawal_arg: Withdrawal { owner, limit }, or AllowanceWithdrawal { allowance: ID,
    // is_sponsor: false, inner: Withdrawal }
    r.wds = try r.arena.alloc(Value, p.withdrawals.items.len);
    for (p.withdrawals.items, r.wds) |*w, *slot| {
        var v = try r.heap().pack(.struct_, 0, &.{ try r.heap().address(w.owner), try r.heap().u256_(w.amount) });
        if (w.allowance) |aid| {
            const idv = try r.heap().pack(.struct_, 0, &.{try r.heap().address(aid)});
            v = try r.heap().pack(.struct_, 0, &.{ idv, Value.bool_(false), v });
        }
        try r.charge(move_vm.Meter.chargeCopyLoc, .{r.sizeOf(v)});
        try r.charge(move_vm.Meter.chargeStoreLoc, .{});
        slot.* = v;
    }
    if (r.gas.absent) {
        // gasless (`payment_location` None): no gas coin at all
    } else if (r.gas.ephemeral) {
        // An ephemeral coin of the total smashed, under a fresh id (no charges, not an input).
        r.gas.id = r.host.tx.freshId();
        const idv = try r.heap().pack(.struct_, 0, &.{try r.heap().address(r.gas.id)});
        const uid = try r.heap().pack(.struct_, 0, &.{idv});
        if (r.gas.amount < r.budget) return r.diag().unsupported("address-balance payment below the budget");
        const bal = try r.heap().pack(.struct_, 0, &.{Value.u64_(r.gas.amount)});
        r.gas_val = try r.heap().pack(.struct_, 0, &.{ uid, bal });
    } else r.gas_val = try loadObject(r, p.gas_ty, r.gas.contents, r.gas.id, r.gas.version, r.gas.owner);
    if (!r.gas.absent) {
        if (r.gas.ephemeral) {
            if (try r.host.rt.newId(r.arena, r.p.cfg, r.gas.id)) |e| return r.diag().failWith(convertStatus(r, e.status, e.sub, null), null);
        }
        const b = Run.coinBalance(r.gas_val);
        if (b.a < r.budget) return r.diag().unsupported("gas coin below the budget");
        b.a -= r.budget;
    }
    // TxContext { sender: @0x0, tx_hash, epoch: 0, epoch_timestamp_ms: 0, ids_created: 0 }
    const hash = try r.heap().newContainer(.vec_u8, 32);
    @memcpy(hash.bytes(), &r.host.tx.digest);
    r.tx_ctx = try r.heap().pack(.struct_, 0, &.{ try r.heap().address(@splat(0)), Value.container(hash), Value.u64_(0), Value.u64_(0), Value.u64_(0) });
}

fn loadObject(r: *Run, ty: Ty, contents: []const u8, id: [32]u8, version: u64, owner: types.Owner) Error!Value {
    const lim = vm_host.Limits.of(r.sess.cfg);
    // Layouts from the runtime's type-argument cache when there is one (same functions, kept).
    const hit: ?natives.abi.TyArg = if (r.host.ty_cache) |tc| try tc.get(ty, lim) else null;
    const al = (if (hit) |h| h.annotated else try vm_host.annotatedLimited(r.arena, ty, lim)) orelse return r.diag().unsupported("object layout over the limits");
    const lay = (if (hit) |h| h.layout else try vm_host.layoutLimited(r.arena, ty, lim)) orelse return r.diag().unsupported("object layout over the limits");
    // One decode, straight into VM values; `get_all_uids` walks those (no layout value).
    var rd = move_vm.loader.Reader{ .bytes = contents };
    const v = vm_host.deserializeL(r.heap(), lay, &rd, 0) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return r.diag().unsupported("object contents do not decode"),
    };
    if (rd.pos != contents.len) return r.diag().unsupported("object contents do not decode");
    const uids = try allUidsOf(r.arena, v, al);
    try r.host.rt.addInput(r.arena, .{ .id = id, .version = version, .owner = try objrt.Owner.fromTypes(r.arena, &owner), .contained_uids = uids });
    try r.charge(move_vm.Meter.chargeCopyLoc, .{r.sizeOf(v)});
    try r.charge(move_vm.Meter.chargeStoreLoc, .{});
    return v;
}

/// `get_all_uids` over a VM value (objrt.allUids over its layout value): every address inside a
/// `0x2::object::UID`, sorted and unique.
fn allUidsOf(arena: Allocator, v: Value, l: *const objrt.ALayout) Allocator.Error![][32]u8 {
    var out: std.ArrayList([32]u8) = .empty;
    try collectUids(arena, v, l, false, &out);
    std.mem.sort([32]u8, out.items, {}, objrt.idLess);
    var n: usize = 0;
    for (out.items) |x| {
        if (n > 0 and std.mem.eql(u8, &out.items[n - 1], &x)) continue;
        out.items[n] = x;
        n += 1;
    }
    return out.items[0..n];
}

fn isUidTag(s: *const types.StructTag) bool {
    var two: [32]u8 = @splat(0);
    two[31] = 2;
    return std.mem.eql(u8, &s.address.@"0", &two) and std.mem.eql(u8, s.module.@"0", "object") and
        std.mem.eql(u8, s.name.@"0", "UID") and s.type_args.len == 0;
}

fn collectUids(arena: Allocator, v: Value, l: *const objrt.ALayout, in_uid: bool, out: *std.ArrayList([32]u8)) Allocator.Error!void {
    switch (l.*) {
        .address => if (in_uid) try out.append(arena, v.box().*),
        .vector => |el| {
            const c = v.cont();
            if (c.kind.isPrimVec()) {
                if (in_uid and c.kind == .vec_address) {
                    const b = c.bytes();
                    var i: usize = 0;
                    while (i < b.len) : (i += 32) try out.append(arena, b[i..][0..32].*);
                }
            } else for (c.values()) |e| try collectUids(arena, e, el, in_uid, out);
        },
        .@"struct" => |st| {
            const u = in_uid or isUidTag(&st.type_);
            for (v.cont().values(), st.fields) |f, *fl| try collectUids(arena, f, &fl.layout, u, out);
        },
        .@"enum" => |en| {
            const c = v.cont();
            for (en.variants) |*vr| if (vr.key.tag == c.tag) {
                for (c.values(), vr.fields) |f, *fl| try collectUids(arena, f, &fl.layout, in_uid, out);
                break;
            };
        },
        else => {},
    }
}

pub fn commands(r: *Run) Error!void {
    for (r.p.cmds.items, 0..) |*c, ci| {
        command(r, c) catch |e| {
            if (e == error.Fail and r.diag().fail.command == null) r.diag().fail.command = r.p.annot(ci);
            return e;
        };
    }
}

fn command(r: *Run, c: *typing.Cmd) Error!void {
    const arena = r.arena;
    var out: []Value = &.{};
    var is_call = false;
    switch (c.tag) {
        .call => {
            is_call = true;
            const call = c.call.?;
            const args = try arena.alloc(Value, c.args.len);
            for (c.args, args) |a, *v| v.* = try r.argument(a);
            // `coin::send_funds` of the gas coin: its funds go to the recipient's balance
            if (typing.isSendFunds(call) and c.args.len == 2 and c.args[0].loc == .gas and c.args[0].kind == .use and c.args[0].move)
                r.gas_send_to = args[1].box().*;
            if (!r.p.cfg.feature_flags.enable_unified_linkage) {
                // a VM per call over the call's own linkage; errors relocate through it
                const root = try pkgs.rootPackage(arena, r.link.rt, call.linkage);
                const lc = try arena.create(move_vm.LinkCtx);
                lc.* = move_vm.LinkCtx.init(r.link.rt, root);
                try r.call_links.append(arena, lc);
                r.sess.link = lc;
                r.p.unified = call.linkage;
            }
            const f = r.sess.link.function(&call.pkg.original_id, call.module, call.name) catch return r.diag().unsupported("function does not link");
            const res = r.sess.run(f, call.ty_args, args) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.NativeUnsupported => return r.diag().unsupported("native not implemented"),
                else => return r.diag().unsupported("VM load error"),
            };
            switch (res) {
                .ok => |vals| out = try arena.dupe(Value, vals),
                .err => |e| return r.diag().failWith(vmError(r, e), null),
            }
            try takeEvents(r, call);
        },
        .transfer => {
            const n = c.args.len - 1;
            const vals = try arena.alloc(Value, n);
            for (c.args[0..n], vals) |a, *v| {
                if (a.loc == .gas and a.move) r.gas_moved = true;
                v.* = try r.argument(a);
            }
            const recip = try r.argument(c.args[n]);
            const owner: objrt.Owner = .{ .address = recip.box().* };
            for (c.args[0..n], vals) |a, v| try r.transfer(owner, a.ty, v, false);
        },
        .split => {
            const coin = try r.argument(c.args[0]);
            const amounts = try arena.alloc(u64, c.args.len - 1);
            for (c.args[1..], amounts) |a, *x| x.* = (try r.argument(a)).a;
            var total: u64 = 0;
            for (amounts) |x| total = std.math.add(u64, total, x) catch return r.diag().failWith(.CoinBalanceOverflow, null);
            try r.copyRef(coin);
            const bal = Run.coinBalance(coin.slot().*);
            if (bal.a < total) return r.diag().failWith(.InsufficientCoinBalance, null);
            bal.a -= total;
            out = try arena.alloc(Value, amounts.len);
            for (amounts, out) |x, *v| v.* = try r.newCoin(x);
        },
        .merge => {
            const target = try r.argument(c.args[0]);
            // `context.arguments(coins)?` loads (and charges) every coin before any is destroyed
            const coins = try arena.alloc(Value, c.args.len - 1);
            for (c.args[1..], coins) |a, *v| v.* = try r.argument(a);
            var add: u64 = 0;
            var overflow = false;
            for (coins) |v| {
                const id = Run.coinId(v);
                if (try r.host.rt.deleteId(r.arena, r.p.cfg, id)) |e| return r.diag().failWith(convertStatus(r, e.status, e.sub, null), null);
                const x = Run.coinBalance(v).a;
                if (!overflow) add = std.math.add(u64, add, x) catch blk: {
                    overflow = true;
                    break :blk add;
                };
            }
            if (overflow) return r.diag().failWith(.CoinBalanceOverflow, null);
            try r.copyRef(target);
            const bal = Run.coinBalance(target.slot().*);
            bal.a = std.math.add(u64, bal.a, add) catch return r.diag().failWith(.CoinBalanceOverflow, null);
        },
        .publish => out = try publish(r, c.publish.?),
        .upgrade => out = try upgrade(r, c.publish.?, try r.argument(c.args[0])),
        .make_vec => {
            const ty = c.ty.?;
            const k = ty.vecKind();
            const cont = try r.heap().newContainer(k, c.args.len);
            for (c.args, 0..) |a, i| {
                const v = try r.argument(a);
                if (k.isPrimVec()) {
                    vm_value.writeElem(cont, i, v);
                    r.heap().drop(v);
                } else cont.values()[i] = v;
            }
            out = try arena.alloc(Value, 1);
            out[0] = Value.container(cont);
        },
    }
    // DevInspect: argument updates and results are recorded before charge_command and before
    // unused results are dropped (interpreter.rs `execute_command`).
    if (r.track) try trackCommand(r, c, out);
    // charge_command: pop the arguments (and a call's returns).
    const pops: u64 = c.args.len + if (is_call) out.len else 0;
    try r.charge(move_vm.Meter.charge, .{ 1, 0, pops, 0 });
    for (out, 0..) |v, j| if (c.drop[j]) {
        r.heap().drop(v);
        out[j] = Value.invalid;
    };
    try r.results.append(arena, out);
}

// ---- DevInspect tracking (`Context::argument_updates`, `Context::tracked_results`)

/// One executed command under `Mode::TRACK_EXECUTION`: the values of its `&mut` arguments after
/// the command (a MoveCall's `&mut` parameters, SplitCoins' coin, MergeCoins' target), then its
/// return values. A `&mut` argument whose location no longer holds a value (a reference result
/// moved at its last usage) and the TxContext are left out, as in Rust.
fn trackCommand(r: *Run, c: *const typing.Cmd, out: []const Value) Error!void {
    const arena = r.arena;
    const candidates: []const typing.Arg = switch (c.tag) {
        .call => c.args,
        .split, .merge => if (c.args.len > 0) c.args[0..1] else &.{},
        .transfer, .make_vec, .publish, .upgrade => &.{},
    };
    var mutated: std.ArrayList(TrackedValue) = .empty;
    for (candidates) |a| {
        // MoveCall: only `Reference(true, _)` arguments; SplitCoins/MergeCoins: always `&mut Coin`
        if (a.ty.* != .mut_ref) continue;
        if (try argumentUpdate(r, a)) |tv| try mutated.append(arena, tv);
    }
    if (out.len != c.results.len) return r.diag().unsupported("command results and result types differ");
    const returns = try arena.alloc(TrackedValue, out.len);
    for (out, c.results, returns) |v, t, *tv| tv.* = try trackedValue(r, v, t, null);
    try r.tracked.append(arena, .{ .mutated = mutated.items, .returns = returns });
}

/// `Context::argument_update`: the referent of a `&mut` argument, tagged with the signed
/// `Argument` of its location (inputs by their original input index, results as NestedResult).
fn argumentUpdate(r: *Run, a: typing.Arg) Error!?TrackedValue {
    const tx_arg: types.Argument = switch (a.loc) {
        .tx_context => return null,
        .gas => .GasCoin,
        .object => |i| .{ .Input = r.p.objects.items[i].input },
        .withdrawal => |i| .{ .Input = r.p.withdrawals.items[i].input },
        .pure => |i| .{ .Input = r.p.pure.items[i].input },
        .receiving => |i| .{ .Input = r.p.receiving.items[i].input },
        .result => |x| .{ .NestedResult = .{ x[0], x[1] } },
    };
    const s = r.slot(a.loc);
    if (s.tag == .invalid) return null;
    const v = switch (a.kind) {
        // the location holds a `&mut` reference: read through it
        .use => blk: {
            if (!s.isRef()) return r.diag().unsupported("tracked &mut argument without a reference");
            break :blk try vm_value.deref(s.*, r.heap());
        },
        // the location holds the value itself
        .borrow => s.*,
        .freeze, .read => return r.diag().unsupported("tracked &mut argument through freeze or read"),
    };
    return try trackedValue(r, v, a.ty.mut_ref, tx_arg);
}

/// `Context::tracked_result`: BCS of a value (through a reference) and the type tag of its type.
fn trackedValue(r: *Run, v: Value, t: Ty, arg: ?types.Argument) Error!TrackedValue {
    var inner_t = t;
    var val = v;
    switch (t.*) {
        .ref, .mut_ref => |i| {
            inner_t = i;
            if (!v.isRef()) return r.diag().unsupported("tracked reference result without a reference");
            val = try vm_value.deref(v, r.heap());
        },
        else => {},
    }
    const lv = try vm_host.toLayout(r.arena, inner_t, val);
    const tag = try vm_host.typeTag(r.arena, inner_t, .defining);
    return .{ .arg = arg, .bytes = try types.layout.encodeAlloc(r.arena, &lv), .ty = tag.* };
}

fn takeEvents(r: *Run, call: *const typing.Call) Error!void {
    return takeEventsAt(r, call.pkg.version_id, call.module);
}

fn takeEventsAt(r: *Run, version_id: [32]u8, module: []const u8) Error!void {
    const evs = r.host.rt.events.items;
    if (evs.len == r.events_taken) return;
    const max = r.p.cfg.getOpt("max_num_event_emit") orelse std.math.maxInt(u64);
    if (r.events.items.len + evs.len - r.events_taken > max) return r.diag().unsupported("event count over the limit");
    for (evs[r.events_taken..]) |e| {
        const st = switch (e.ty.*) {
            .@"struct" => |s| s,
            else => return r.diag().unsupported("event type"),
        };
        try r.events.append(r.arena, .{
            .package_id = .{ .@"0" = .{ .@"0" = version_id } },
            .transaction_module = .{ .@"0" = module },
            .sender = .{ .@"0" = r.sender },
            .type_ = st,
            .contents = try types.layout.encodeAlloc(r.arena, &e.value),
        });
    }
    r.events_taken = evs.len;
}

fn isFw(a: *const [32]u8, b: u8) bool {
    for (a[0..31]) |x| if (x != 0) return false;
    return a[31] == b;
}

fn isCoinTag(st: *const types.StructTag) ?*const types.TypeTag {
    for (st.address.@"0"[0..31]) |b| if (b != 0) return null;
    if (st.address.@"0"[31] != 2 or !std.mem.eql(u8, st.module.@"0", "coin") or !std.mem.eql(u8, st.name.@"0", "Coin") or st.type_args.len != 1) return null;
    return &st.type_args[0];
}

fn isSui(t: *const types.TypeTag) bool {
    const st = switch (t.*) {
        .@"struct" => |*s| s,
        else => return false,
    };
    for (st.address.@"0"[0..31]) |b| if (b != 0) return false;
    return st.address.@"0"[31] == 2 and std.mem.eql(u8, st.module.@"0", "sui") and std.mem.eql(u8, st.name.@"0", "SUI") and st.type_args.len == 0;
}

/// `Context::finish` + `context::finish`.
pub fn finish(r: *Run) Error!Results {
    const p = r.p;
    const arena = r.arena;
    var loaded = std.AutoArrayHashMapUnmanaged([32]u8, struct { version: u64, modified: bool }).empty;
    var by_value_shared: std.ArrayList([32]u8) = .empty;
    for (p.objects.items, 0..) |*o, i| {
        if (!o.canUseMutably()) continue;
        try loaded.put(arena, o.id, .{ .version = o.view.version, .modified = true });
        const v = r.objs[i];
        if (v.tag != .invalid) {
            try r.transfer(try objrt.Owner.fromTypes(arena, &o.owner), o.ty, v, true);
        } else switch (o.owner) {
            .Shared => try by_value_shared.append(arena, o.id),
            .ConsensusAddressOwner => |co| if (!std.mem.eql(u8, &co.owner.@"0", &r.sender)) return r.diag().failWith(.SharedObjectOperationNotAllowed, null),
            else => {},
        }
    }
    if (!r.gas.absent) {
        if (!r.gas.ephemeral) try loaded.put(arena, r.gas.id, .{ .version = r.gas.version, .modified = true });
        if (r.gas_val.tag != .invalid) {
            try r.transfer(try objrt.Owner.fromTypes(arena, &r.gas.owner), p.gas_ty, r.gas_val, true);
        } else if (!r.gas_moved) return r.diag().unsupported("gas coin state");
    }
    const fin = try r.host.finish(arena);
    const res = switch (fin) {
        .ok => |x| x,
        .err => |e| switch (e) {
            .circular => |id| return r.diag().failWith(.{ .CircularObjectOwnership = .{ .object = .{ .@"0" = .{ .@"0" = id } } } }, null),
            .invariant => return r.diag().unsupported("object runtime invariant"),
        },
    };
    if (res.events.len != r.events_taken) return r.diag().unsupported("events left in the runtime");

    // finish_gas_coin: refund the budget to the gas coin's write.
    var writes = try arena.dupe(objrt.ObjectRuntime.Write, res.writes);
    var created = res.created;
    var gas_balance_change: i64 = 0;
    var gas_events: std.ArrayList(AccWrite) = .empty;
    if (r.gas.absent) {
        // no gas coin to refund
    } else if (r.gas_send_to) |rcpt| {
        // refund_max_gas_budget: the budget goes to the recipient's balance
        for (writes) |w| if (std.mem.eql(u8, &w.id, &r.gas.id)) return r.diag().unsupported("gas coin written after send_funds");
        // checked_as!/try_into in Rust: an i64 overflow is an invariant violation, never UB here
        try gas_events.append(arena, try balanceWrite(arena, rcpt, std.math.cast(i64, r.budget) orelse return r.diag().unsupported("gas budget over i64")));
        if (r.gas.ephemeral) gas_balance_change = -(std.math.cast(i64, r.gas.amount) orelse return r.diag().unsupported("gas payment amount over i64"));
    } else {
        const wi = for (writes, 0..) |*w, i| {
            if (std.mem.eql(u8, &w.id, &r.gas.id)) break i;
        } else return r.diag().unsupported("gas coin wrapped or destroyed");
        const w = &writes[wi];
        const fields = try arena.dupe(LV, w.value.@"struct");
        const bal = try arena.dupe(LV, fields[1].@"struct");
        bal[0] = .{ .u64 = std.math.add(u64, bal[0].u64, r.budget) catch return r.diag().failWith(.CoinBalanceOverflow, null) };
        fields[1] = .{ .@"struct" = bal };
        w.value = .{ .@"struct" = fields };
        if (r.gas.ephemeral) {
            if (r.gas_moved) {
                // transferred: the payer's balance gives up the whole amount, the coin pays gas
                gas_balance_change = -(std.math.cast(i64, r.gas.amount) orelse return r.diag().unsupported("gas payment amount over i64"));
            } else {
                // left in place: destroyed, the remainder settles back to the balance
                gas_balance_change = std.math.cast(i64, @as(i128, bal[0].u64) - @as(i128, r.gas.amount)) orelse return r.diag().unsupported("gas balance change over i64");
                const nw = try arena.alloc(objrt.ObjectRuntime.Write, writes.len - 1);
                @memcpy(nw[0..wi], writes[0..wi]);
                @memcpy(nw[wi..], writes[wi + 1 ..]);
                writes = nw;
                var nc: std.ArrayList([32]u8) = .empty;
                for (created) |id| if (!std.mem.eql(u8, &id, &r.gas.id)) try nc.append(arena, id);
                created = nc.items;
            }
        }
    }
    for (res.loaded) |l| {
        const gop = try loaded.getOrPut(arena, l.id);
        gop.value_ptr.* = .{ .version = l.version, .modified = l.modified };
    }

    // written objects
    const max_size = p.cfg.getOpt("max_move_object_size");
    const out = try arena.alloc(Write, writes.len);
    var deny_pairs: std.ArrayList(deny.Pair) = .empty;
    // has_public_transfer is the `store` ability of the object's type. A transaction that
    // writes many objects writes few types (coins, the fields of one table), so the type is
    // resolved once per run of writes of the same type instead of once per write: the last few
    // answers are kept, and a type not among them is resolved as before.
    var stores: [4]struct { st: *const types.StructTag, has_store: bool } = undefined;
    var n_stores: usize = 0;
    for (writes, out) |w, *o| {
        const st = switch (w.ty.*) {
            .@"struct" => |s| s,
            else => return r.diag().unsupported("non-struct object type"),
        };
        const has_store = for (stores[0..@min(n_stores, stores.len)]) |known| {
            if (objrt.structEql(known.st, &w.ty.@"struct")) break known.has_store;
        } else blk: {
            const hs = typing.abilities(try typing.fromStruct(p, &st)).hasStore();
            stores[n_stores % stores.len] = .{ .st = &w.ty.@"struct", .has_store = hs };
            n_stores += 1;
            break :blk hs;
        };
        const contents = try types.layout.encodeAlloc(arena, &w.value);
        if (max_size) |m| if (contents.len > m)
            return r.diag().failWith(.{ .MoveObjectTooBig = .{ .object_size = contents.len, .max_object_size = m } }, null);
        const owner: types.Owner = switch (w.owner) {
            .address => |a| .{ .AddressOwner = .{ .@"0" = a } },
            .object => |a| .{ .ObjectOwner = .{ .@"0" = a } },
            .shared => |v| .{ .Shared = .{ .initial_shared_version = .{ .@"0" = v } } },
            .immutable => .Immutable,
            .consensus => |c| .{ .ConsensusAddressOwner = .{ .start_version = .{ .@"0" = c.start }, .owner = .{ .@"0" = c.owner } } },
            .party => return r.diag().unsupported("party owner"),
        };
        o.* = .{
            .id = w.id,
            .owner = owner,
            .tag = st,
            .has_public_transfer = has_store,
            .contents = contents,
            .old_version = if (loaded.get(w.id)) |l| l.version else 0,
        };
        // deny list v2: non-SUI coins and their owner addresses
        if (isCoinTag(&st)) |ct| if (!isSui(ct)) {
            // exec-history: v3 takes `get_owner_address` only under `use_coin_party_owner`,
            // `get_address_owner_address` (address owners only) before it
            const party_owner = versions.executionVersion(r.p.cfg) >= versions.latest or r.p.cfg.feature_flags.use_coin_party_owner;
            const oaddr: ?[32]u8 = switch (w.owner) {
                .address => |a| a,
                .object => |a| if (party_owner) a else null,
                .consensus => |c| if (party_owner) c.owner else null,
                else => null,
            };
            if (oaddr) |a| try deny.addPair(arena, &deny_pairs, try deny.canonical(arena, ct), a, ct.*);
        };
    }

    // context::finish: accumulator events (with their deny-list funds owners)
    var acc: std.ArrayList(AccWrite) = .empty;
    for (res.acc_events) |ae| {
        const value: types.AccumulatorValue = switch (ae.value) {
            .u64 => |x| .{ .Integer = x },
            .event_ref => |idx| blk: {
                if (idx >= r.events.items.len) return r.diag().unsupported("accumulator event reference");
                const raw = try bcs.encodeAlloc(types.Event, arena, &r.events.items[idx]);
                const one = try arena.alloc(@typeInfo(@FieldType(types.AccumulatorValue, "EventDigest")).pointer.child, 1);
                one[0] = .{ idx, .{ .@"0" = types.digest.digestOf("Event", raw) } };
                break :blk .{ .EventDigest = one };
            },
        };
        try acc.append(arena, .{
            .id = ae.accumulator_id,
            .addr = ae.target_addr,
            .ty = ae.target_ty.*,
            .op = if (ae.action == .merge) .Merge else .Split,
            .value = value,
        });
        // Balance<T> targets receive funds of T
        if (ae.target_ty.* == .@"struct") {
            const st = &ae.target_ty.@"struct";
            if (isFw(&st.address.@"0", 2) and std.mem.eql(u8, st.module.@"0", "balance") and std.mem.eql(u8, st.name.@"0", "Balance") and st.type_args.len == 1 and !isSui(&st.type_args[0])) {
                try deny.addPair(arena, &deny_pairs, try deny.canonical(arena, &st.type_args[0]), ae.target_addr, st.type_args[0]);
            }
        }
    }
    try acc.appendSlice(arena, gas_events.items);
    if (gas_balance_change != 0) try acc.append(arena, try balanceWrite(arena, r.gas.owner.AddressOwner.@"0", gas_balance_change));

    // context::finish
    for (by_value_shared.items) |id| {
        const w = for (out) |*w| {
            if (std.mem.eql(u8, &w.id, &id)) break w;
        } else null;
        if (w) |x| {
            if (x.owner != .Shared) return r.diag().failWith(.SharedObjectOperationNotAllowed, null);
        } else {
            for (res.deleted) |d| {
                if (std.mem.eql(u8, &d, &id)) break;
            } else return r.diag().failWith(.SharedObjectOperationNotAllowed, null);
        }
    }

    var modified: std.ArrayList([32]u8) = .empty;
    for (loaded.keys(), loaded.values()) |id, l| if (l.modified) try modified.append(arena, id);
    return .{
        .writes = out,
        .modified = modified.items,
        .created = created,
        .deleted = res.deleted,
        .events = r.events.items,
        .deny_list_read = deny_pairs.items.len > 0,
        .non_gas_coin_owners = deny_pairs.items.len,
        .deny_pairs = deny_pairs.items,
        .children = res.loaded,
        .acc = acc.items,
        .gas_transferred = r.gas.ephemeral and r.gas_moved and r.gas_send_to == null,
        .gas_send_to = r.gas_send_to,
        .gas_id = r.gas.id,
        .packages = r.packages.items,
        .command_results = if (r.track) r.tracked.items else null,
    };
}

fn isZero(a: *const [32]u8) bool {
    for (a) |b| if (b != 0) return false;
    return true;
}

fn lessId(_: void, a: [32]u8, b: [32]u8) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

/// BCS order of a `BTreeMap<String, _>`: by the encoded key (ULEB length, then bytes).
fn lessName(_: void, a: []const u8, b: []const u8) bool {
    // Compare the ULEB128 length prefixes byte for byte, then the names (identifiers can be
    // 128 bytes long, whose prefix 0x80 0x01 sorts after every one-byte prefix).
    var pa: [10]u8 = undefined;
    var pb: [10]u8 = undefined;
    const na = ulebBytes(&pa, a.len);
    const nb = ulebBytes(&pb, b.len);
    return switch (std.mem.order(u8, na, nb)) {
        .lt => true,
        .gt => false,
        .eq => std.mem.order(u8, a, b) == .lt,
    };
}

fn ulebBytes(buf: *[10]u8, n: usize) []const u8 {
    var x = n;
    var i: usize = 0;
    while (true) : (i += 1) {
        const b: u8 = @truncate(x & 0x7f);
        x >>= 7;
        if (x == 0) {
            buf[i] = b;
            return buf[0 .. i + 1];
        }
        buf[i] = b | 0x80;
    }
}

test "module map order is BCS key order (ULEB length prefix, then bytes)" {
    const short = "zz";
    const long: [128]u8 = @splat('a');
    try std.testing.expect(lessName({}, short, &long));
    try std.testing.expect(!lessName({}, &long, short));
    try std.testing.expect(lessName({}, "b", "aa"));
    try std.testing.expect(lessName({}, "aa", "ab"));
    try std.testing.expect(!lessName({}, "ab", "ab"));
}

/// interpreter.rs `Publish` with a deserialized payload: `publish_and_init_package`
/// (fresh id, `substitute_package_id`, `fetch_packages`, `MovePackage::new_initial`,
/// `publish_and_verify_modules`, the `init` functions) and `new_upgrade_cap`.
fn publish(r: *Run, pb: *const typing.Publish) Error![]Value {
    const id = r.host.tx.freshId();
    const mods = try substitute(r, pb, id);
    _ = try buildAndInit(r, pb, mods, .{ .deps = pb.deps, .storage_id = id, .original_id = id, .version = 1, .prev = null, .policy = 0 });
    // new_upgrade_cap(original id): UpgradeCap { id, package, version: 1, policy: COMPATIBLE }
    const cap_id = r.host.tx.freshId();
    if (try r.host.rt.newId(r.arena, r.p.cfg, cap_id)) |e| return r.diag().failWith(convertStatus(r, e.status, e.sub, null), null);
    const idv = try r.heap().pack(.struct_, 0, &.{try r.heap().address(cap_id)});
    const uid = try r.heap().pack(.struct_, 0, &.{idv});
    const pkgv = try r.heap().pack(.struct_, 0, &.{try r.heap().address(id)});
    const out = try r.arena.alloc(Value, 1);
    out[0] = try r.heap().pack(.struct_, 0, &.{ uid, pkgv, Value.u64_(1), Value.u8_(0) });
    return out;
}

/// interpreter.rs `Upgrade`: the ticket (`UpgradeTicket { cap: ID, package: ID, policy: u8,
/// digest: vector<u8> }`) must name the package and the payload digest; then context.rs
/// `upgrade` and `UpgradeReceipt { cap, package: the new storage id }`.
fn upgrade(r: *Run, pb: *const typing.Publish, ticket: Value) Error![]Value {
    const f = ticket.cont().values();
    const cap = f[0].cont().values()[0].box().*;
    const ticket_pkg = f[1].cont().values()[0].box().*;
    const policy: u8 = @truncate(f[2].a);
    const digest = f[3].cont().bytes();
    const current_id = pb.current.?;
    if (!std.mem.eql(u8, &current_id, &ticket_pkg))
        return r.diag().failWith(.{ .PackageUpgradeError = .{ .upgrade_error = .{ .PackageIDDoesNotMatch = .{ .package_id = .{ .@"0" = .{ .@"0" = current_id } }, .ticket_id = .{ .@"0" = .{ .@"0" = ticket_pkg } } } } } }, null);
    if (!std.mem.eql(u8, &pb.digest, digest))
        return r.diag().failWith(.{ .PackageUpgradeError = .{ .upgrade_error = .{ .DigestDoesNotMatch = .{ .digest = try r.arena.dupe(u8, &pb.digest) } } } }, null);
    r.heap().drop(ticket);
    // fetch_package(current)
    const cache = r.p.linker.cache;
    const cur = if (r.new_pkgs.get(current_id)) |n| n.pkg else (try cache.get(&current_id)) orelse return r.diag().failWith(.PublishUpgradeMissingDependency, null);
    const mods = try substitute(r, pb, cur.original_id);
    const version_id = r.host.tx.freshId();
    const new_id = try buildAndInit(r, pb, mods, .{ .deps = pb.deps, .storage_id = version_id, .original_id = cur.original_id, .version = cur.version + 1, .prev = cur, .policy = policy });
    const capv = try r.heap().pack(.struct_, 0, &.{try r.heap().address(cap)});
    const pkgv = try r.heap().pack(.struct_, 0, &.{try r.heap().address(new_id)});
    const out = try r.arena.alloc(Value, 1);
    out[0] = try r.heap().pack(.struct_, 0, &.{ capv, pkgv });
    return out;
}

/// `substitute_package_id`: every module's self address must be 0x0; it becomes `id`.
pub fn substitute(r: *Run, pb: *const typing.Publish, id: [32]u8) Error![]ff.CompiledModule {
    const mods = try r.arena.alloc(ff.CompiledModule, pb.cms.len);
    for (pb.cms, mods) |cm, *m| {
        m.* = cm;
        const h = cm.selfHandle();
        if (h.address >= cm.address_identifiers.len or !isZero(&cm.address_identifiers[h.address]))
            return r.diag().failWith(.PublishErrorNonZeroAddress, null);
        const addrs = try r.arena.dupe([32]u8, cm.address_identifiers);
        addrs[h.address] = id;
        m.address_identifiers = addrs;
    }
    return mods;
}

pub const Build = struct {
    /// The payload's dependency ids.
    deps: []const [32]u8,
    storage_id: [32]u8,
    original_id: [32]u8,
    version: u64,
    /// Upgrade: the package being upgraded.
    prev: ?*pkgs.Pkg,
    policy: u8,
};

/// The package itself: `fetch_packages`, `MovePackage::new_initial` / `new_upgraded`,
/// `publish_and_verify_modules` and `check_compatibility` (upgrades). The package stays in the
/// thread's VM runtime (its storage id in `r.published`); the caller runs the `init` functions
/// and appends `bytes` to `r.packages`. Shared by the dynamic cuts (versions/dynamic.zig).
pub fn buildPackage(r: *Run, mods: []ff.CompiledModule, b: Build) Error!Built {
    const arena = r.arena;

    const cache = r.p.linker.cache;
    const cfg = r.p.cfg;
    // module bytes outlive the transaction: the per-thread runtime keeps them
    const keep = cache.arena.allocator();
    const id = b.storage_id;
    // fetch_packages (BTreeSet order, duplicates once)
    const dep_ids = try arena.dupe([32]u8, b.deps);
    std.mem.sort([32]u8, dep_ids, {}, lessId);
    var deps: std.ArrayList(types.MovePackage) = .empty;
    for (dep_ids, 0..) |d, i| {
        if (i > 0 and std.mem.eql(u8, &dep_ids[i - 1], &d)) continue;
        if (r.new_pkgs.get(d)) |n| {
            try deps.append(arena, n.mp);
            continue;
        }
        const pkg = (try cache.get(&d)) orelse return r.diag().failWith(.PublishUpgradeMissingDependency, null);
        const obj = bcs.decode(types.Object, arena, pkg.raw) catch return r.diag().unsupported("dependency does not decode");
        try deps.append(arena, obj.data.Package);
    }
    // type origins: new_initial (every type defined here) or build_upgraded_type_origin_table
    // (a type keeps the package that first defined it; a type the predecessor had must remain)
    var origins: std.ArrayList(types.TypeOrigin) = .empty;
    {
        const prev_origins: []const move_vm.loader.TypeOrigin = if (b.prev) |pv| pv.type_origins else &.{};
        const used = try arena.alloc(bool, prev_origins.len);
        @memset(used, false);
        for (mods) |*m| {
            const name = m.selfName();
            const Def = struct { h: u16 };
            var defs: std.ArrayList(Def) = .empty;
            for (m.struct_defs) |sd| try defs.append(arena, .{ .h = sd.struct_handle });
            for (m.enum_defs) |ed| try defs.append(arena, .{ .h = ed.enum_handle });
            for (defs.items) |d| {
                const dt_name = m.identifierAt(m.datatype_handles[d.h].name);
                var origin = id;
                for (prev_origins, used) |o, *u| {
                    if (!u.* and std.mem.eql(u8, o.module, name) and std.mem.eql(u8, o.name, dt_name)) {
                        origin = o.defining;
                        u.* = true;
                        break;
                    }
                }
                try origins.append(arena, .{ .module_name = .{ .@"0" = name }, .datatype_name = .{ .@"0" = dt_name }, .package = .{ .@"0" = .{ .@"0" = origin } } });
            }
        }
        for (used) |u| if (!u) {
            if (cfg.feature_flags.missing_type_is_compatibility_error)
                return r.diag().failWith(.{ .PackageUpgradeError = .{ .upgrade_error = .IncompatibleUpgrade } }, null);
            return r.diag().unsupported("package upgrade missing type from previous version");
        };
    }
    // from_module_iter_with_type_origin_table: module map, immediate dependencies, linkage table
    var names: std.ArrayList([]const u8) = .empty;
    var bytes_by_name = std.StringHashMapUnmanaged([]const u8).empty;
    var immediate = std.AutoArrayHashMapUnmanaged([32]u8, void).empty;
    for (mods) |*m| {
        const name = m.selfName();
        for (m.module_handles, 0..) |mh, hi| {
            if (hi == m.self_module_handle_idx) continue;
            try immediate.put(arena, m.address_identifiers[mh.address], {});
        }
        const b_ = move_format.serializer.serializeAlloc(keep, m, m.version) catch return r.diag().unsupported("module does not serialize");
        if ((try bytes_by_name.fetchPut(arena, name, b_)) != null) return r.diag().failWith(.VMVerificationOrDeserializationError, null);
        try names.append(arena, name);
    }
    _ = immediate.swapRemove(b.original_id);
    std.mem.sort([]const u8, names.items, {}, lessName);
    const entries = try arena.alloc(@typeInfo(@FieldType(@FieldType(types.MovePackage, "module_map"), "entries")).pointer.child, names.items.len);
    for (names.items, entries) |n, *e| e.* = .{ .key = .{ .@"0" = n }, .value = bytes_by_name.get(n).? };
    // build_linkage_table (dependency_linkage_error)
    // before dependency_linkage_error: a repeated original id overwrites, and only the immediate
    // dependencies' linkage tables must be superseded
    const dle = cfg.feature_flags.dependency_linkage_error;
    var link = std.AutoArrayHashMapUnmanaged([32]u8, types.UpgradeInfo).empty;
    var checked: std.ArrayList(*const types.MovePackage) = .empty;
    for (deps.items) |*d| {
        const info = natives.objrt.packageInfo(arena, d) catch return r.diag().unsupported("dependency original id");
        const imm = immediate.swapRemove(info.original_id);
        const gop = try link.getOrPut(arena, info.original_id);
        if (gop.found_existing and dle) return r.diag().failWith(.InvalidLinkage, null);
        gop.value_ptr.* = .{ .upgraded_id = d.id, .upgraded_version = d.version };
        if (dle or imm) try checked.append(arena, d);
    }
    if (immediate.count() != 0) return r.diag().failWith(.PublishUpgradeMissingDependency, null);
    for (checked.items) |d| for (d.linkage_table.entries) |le| {
        const ours = link.get(le.key.@"0".@"0") orelse return r.diag().failWith(.PublishUpgradeMissingDependency, null);
        if (ours.upgraded_version.@"0" < le.value.upgraded_version.@"0") return r.diag().failWith(.PublishUpgradeDependencyDowngrade, null);
    };
    const link_keys = try arena.dupe([32]u8, link.keys());
    std.mem.sort([32]u8, link_keys, {}, lessId);
    const link_entries = try arena.alloc(@typeInfo(@FieldType(@FieldType(types.MovePackage, "linkage_table"), "entries")).pointer.child, link_keys.len);
    for (link_keys, link_entries) |k, *e| e.* = .{ .key = .{ .@"0" = .{ .@"0" = k } }, .value = link.get(k).? };
    const mp: types.MovePackage = .{
        .id = .{ .@"0" = .{ .@"0" = id } },
        .version = .{ .@"0" = b.version },
        .module_map = .{ .entries = entries },
        .type_origin_table = origins.items,
        .linkage_table = .{ .entries = link_entries },
    };
    // MovePackage::new: the size limit
    {
        var size: u64 = 8;
        for (entries) |e| size += e.key.@"0".len + e.value.len;
        for (origins.items) |o| size += o.module_name.@"0".len + o.datatype_name.@"0".len + 32;
        size += link_entries.len * (32 + 32 + 8);
        const max = cfg.getOpt("max_move_package_size") orelse return r.diag().unsupported("no max_move_package_size");
        if (size > max) return r.diag().failWith(.{ .MovePackageTooBig = .{ .object_size = size, .max_object_size = max } }, null);
    }
    // publish_and_verify_modules: the VM's validate_package, then the Sui verifier per module
    var vlink = try arena.alloc([2][32]u8, link_entries.len + 1);
    for (link_entries, 0..) |e, i| vlink[i] = .{ e.key.@"0".@"0", e.value.upgraded_id.@"0".@"0" };
    vlink[link_entries.len] = .{ b.original_id, id };
    std.mem.sort([2][32]u8, vlink, {}, struct {
        fn lt(_: void, x: [2][32]u8, y: [2][32]u8) bool {
            return std.mem.order(u8, &x[0], &y[0]) == .lt;
        }
    }.lt);
    const vorigins = try arena.alloc(move_vm.loader.TypeOrigin, origins.items.len);
    for (origins.items, vorigins) |o, *v| v.* = .{ .module = o.module_name.@"0", .name = o.datatype_name.@"0", .defining = o.package.@"0".@"0" };
    const named = try arena.alloc(move_vm.loader.NamedModule, entries.len);
    for (entries, named) |e, *n| n.* = .{ .name = e.key.@"0", .bytes = e.value };
    const vpkg = cache.rt.addPackage(.{ .version_id = id, .original_id = b.original_id, .version = b.version, .linkage = vlink, .type_origins = vorigins, .modules = named }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return r.diag().unsupported("published package does not load"),
    };
    try r.published.append(arena, id);
    if (vpkg.refused != null) return r.diag().unsupported("published package refused by the verifier");
    {
        const tp = try arena.create(pkgs.Pkg);
        tp.* = .{ .raw = &.{}, .view = undefined, .version_id = id, .original_id = b.original_id, .version = b.version, .linkage = vlink, .type_origins = vorigins, .modules = named, .gas_size = 0, .vm = vpkg };
        try cache.tx_pkgs.put(cache.gpa, id, tp);
        // `push_package`: later commands of this transaction fetch it by its storage id
        try r.new_pkgs.put(arena, id, .{ .pkg = tp, .mp = mp });
    }
    const val = cache.rt.validation orelse return r.diag().unsupported("no verifier config");
    {
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        for (mods) |*m| {
            const res = try move_format.verifier.verify.verifyModule(arena, &scratch, &val.verifier, m, &val.natives);
            if (res.move != null or res.sui != null) return r.diag().unsupported("published module fails the Sui verifier");
        }
    }
    // check_compatibility (upgrade); `is_new`: the modules the predecessor did not have
    const is_new: []bool = try arena.alloc(bool, mods.len);
    @memset(is_new, true);
    if (b.prev) |pv| {
        const cur_vm = cache.load(pv) catch return r.diag().unsupported("package does not load");
        if (cur_vm.refused != null) return r.diag().unsupported("package refused by the loader");
        const existing = try arena.alloc(*const ff.CompiledModule, cur_vm.modules.len);
        for (cur_vm.modules, existing) |*m, *x| x.* = &m.cm;
        switch (compat.checkOpts(existing, mods, b.policy, .{ .dep_only_same_modules = cfg.feature_flags.disallow_new_modules_in_deps_only_packages })) {
            .ok => {},
            .err => |e| return r.diag().failWith(.{ .PackageUpgradeError = .{ .upgrade_error = e } }, null),
        }
        for (mods, is_new) |*m, *n| n.* = cur_vm.module(m.selfName()) == null;
    }
    return .{ .vlink = vlink, .is_new = is_new, .bytes = try bcs.encodeAlloc(types.MovePackage, arena, &mp) };
}

pub const Built = struct {
    /// The package's linkage for the VM, (original id, storage id) sorted by original id.
    vlink: [][2][32]u8,
    /// Per module: the predecessor did not have it (all true on publish).
    is_new: []bool,
    /// BCS `MovePackage`.
    bytes: []const u8,
};

/// `fetch_packages`, `MovePackage::new_initial` / `new_upgraded`, `publish_and_verify_modules`,
/// `check_compatibility` (upgrades) and `push_package_and_init_selected_modules`. Returns the
/// storage id. The package stays in the thread's VM runtime until the transaction ends
/// (`root.zig` removes it then, like Rust's per-transaction package store).
fn buildAndInit(r: *Run, pb: *const typing.Publish, mods: []ff.CompiledModule, b: Build) Error![32]u8 {
    const bp = try buildPackage(r, mods, b);
    const cfg = r.p.cfg;
    const id = b.storage_id;
    const arena = r.arena;
    const vlink = bp.vlink;
    const is_new = bp.is_new;
    // the modules whose `init` runs: every module on publish, only the modules the predecessor
    // did not have on upgrade
    var run_init = pb.has_init;
    if (b.prev != null) {
        run_init = false;
        for (mods, is_new) |*m, n| if (n and typing.moduleHasInit(m)) {
            run_init = true;
        };
        if (run_init and !cfg.feature_flags.enable_init_on_upgrade)
            return r.diag().failWith(.FeatureNotYetSupported, null);
    }
    const cache = r.p.linker.cache;
    // init_selected_modules, in the payload's module order, under the package's own linkage
    if (run_init) {
        const root = try pkgs.rootPackage(arena, cache.rt, vlink);
        const lc = try arena.create(move_vm.LinkCtx);
        lc.* = move_vm.LinkCtx.init(cache.rt, root);
        try r.call_links.append(arena, lc);
        const saved = r.sess.link;
        r.sess.link = lc;
        defer r.sess.link = saved;
        for (mods, is_new) |*m, new| {
            if (!new) continue;
            const fd = for (m.function_defs) |fd| {
                if (std.mem.eql(u8, m.identifierAt(m.function_handles[fd.function].name), "init")) break fd;
            } else continue;
            const n_params = m.signatureAt(m.function_handles[fd.function].parameters).len;
            if (n_params > 2) return r.diag().unsupported("init with more than 2 parameters");
            const ctx = try r.location(.borrow, .tx_context);
            try r.charge(move_vm.Meter.chargeStoreLoc, .{});
            const f = r.sess.link.function(&b.original_id, m.selfName(), "init") catch return r.diag().unsupported("init does not link");
            const args: []const Value = if (n_params == 2) &.{ try r.heap().pack(.struct_, 0, &.{Value.bool_(true)}), ctx } else &.{ctx};
            const res = r.sess.run(f, &.{}, args) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.NativeUnsupported => return r.diag().unsupported("native not implemented"),
                else => return r.diag().unsupported("VM load error"),
            };
            switch (res) {
                .ok => |vals| if (vals.len != 0) return r.diag().unsupported("init returned values"),
                .err => |e| return r.diag().failWith(vmError(r, e), null),
            }
            try takeEventsAt(r, id, m.selfName());
        }
    }
    try r.packages.append(arena, .{ .id = id, .version = b.version, .bytes = bp.bytes });
    return id;
}
