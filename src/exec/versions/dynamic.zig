//! exec-history (CONTRACTS 6.6b): the dynamic PTB executor of execution versions 0 to 3
//! (`programmable_transactions/{execution,context}.rs` of `sui-execution/historical-versions/v3`,
//! and the v0..v2 deltas). Commands run one by one over BCS values: arguments are checked
//! when used (`by_value_arg`, `borrow_arg_mut`, `borrow_arg`, `check_param_type`), each Move call
//! deserializes its arguments into the VM and serializes its results back (unmetered), and
//! adapter transfers stay out of the object runtime until `finish`.
//!
//! Reuses exec-move's pieces: the TemporaryStore/gas/effects driver (`ptb/root.zig:execute`),
//! function loading under the callee's own linkage (`typing.loadFunction`, v3
//! `compute_call_linkage_` = `set_link_context`), type inputs (`typing.fromInput`), pure layouts
//! (`typing.primLayout`/`validate`), the VM session and the object runtime. Gas outside the VM is
//! only what the driver charges (input objects, the deny-list charge): `Context::new` and the
//! adapter commands charge nothing.
const std = @import("std");
const types = @import("types");
const bcs = @import("bcs");
const move_vm = @import("move_vm");
const natives = @import("natives");
const move_format = @import("move_format");
const ff = move_format.file_format;
const typing = @import("../ptb/typing.zig");
const run = @import("../ptb/run.zig");
const pkgs = @import("../ptb/pkgs.zig");
const deny = @import("../ptb/deny.zig");
const objects = @import("../objects.zig");
const versions = @import("root.zig");

const Allocator = std.mem.Allocator;
const Ty = typing.Ty;
const Id = [32]u8;
const AbilitySet = ff.AbilitySet;
const Value = move_vm.Value;
const Error = pkgs.Error;
const objrt = natives.objrt;
const vm_host = move_vm.host;
const ArgErr = types.CommandArgumentError;

/// The gas coin: its input object and its contents after smashing.
pub const GasIn = struct { raw: []const u8, contents: []const u8 };
pub const In = struct { budget: u64, sender: Id, gas: ?GasIn };

const Obj = struct {
    ty: Ty,
    public_transfer: bool,
    non_entry: bool,
    /// BCS contents (a coin: id ++ balance).
    bytes: []u8,
    coin: bool,
};

const Loaded = struct { ty: Ty, ab: AbilitySet, non_entry: bool, bytes: []const u8 };

/// execution_value.rs `Value`.
const Val = union(enum) {
    any: []const u8,
    loaded: Loaded,
    object: Obj,
    receiving: struct { id: Id, version: u64, ty: ?Ty },

    fn copyable(v: Val) bool {
        return switch (v) {
            .object, .receiving => false,
            .any => true,
            .loaded => |l| l.ab.hasCopy(),
        };
    }
    fn nonEntry(v: Val) bool {
        return switch (v) {
            .object => |o| o.non_entry,
            .loaded => |l| l.non_entry,
            else => false,
        };
    }
    fn bytesOf(v: Val, arena: Allocator) Allocator.Error![]const u8 {
        return switch (v) {
            .any => |b| b,
            .loaded => |l| l.bytes,
            .object => |o| o.bytes,
            .receiving => |r| blk: {
                const b = try arena.alloc(u8, 40);
                @memcpy(b[0..32], &r.id);
                std.mem.writeInt(u64, b[32..40], r.version, .little);
                break :blk b;
            },
        };
    }
    /// A clone that owns its object bytes (coins are mutated in place).
    fn clone(v: Val, arena: Allocator) Allocator.Error!Val {
        return switch (v) {
            .object => |o| blk: {
                var c = o;
                c.bytes = try arena.dupe(u8, o.bytes);
                break :blk .{ .object = c };
            },
            else => v,
        };
    }
};

const Usage = enum { by_value, borrow_mut, borrow_imm };

const Slot = struct {
    val: ?Val = null,
    last: ?Usage = null,
    shared: std.ArrayList(Id) = .empty,
};

const Meta = union(enum) {
    none,
    object: struct { id: Id, mutable: bool, owner: types.Owner, version: u64 },
    receiving,
};

/// `Arg`: `Arg_::V1(Argument)` before `normalize_ptb_arguments`, `Arg_::V2(NormalizedArg)` from it
/// (a `Result(i)` normalized to `NestedResult(i, 0)`).
const Arg = union(enum) {
    gas,
    input: u16,
    result: u16,
    nested: [2]u16,
};

const CmdKind = enum { make_vec, transfer, split, merge, call, publish, upgrade };

const Write = struct { owner: types.Owner, ty: Ty, public_transfer: bool, bytes: []const u8 };

const Ctx = struct {
    arena: Allocator,
    p: *typing.Ptb,
    host: *move_vm.Host,
    sess: *move_vm.Session,
    rr: *run.Run,
    link: *move_vm.LinkCtx,
    cfg: *const @import("protocol").ProtocolConfig,
    in: In,
    inputs: []Slot,
    metas: []Meta,
    gas: Slot = .{},
    gas_meta: Meta = .none,
    results: std.ArrayList([]Slot) = .empty,
    borrowed: std.AutoArrayHashMapUnmanaged(Arg, bool) = .empty,
    per_command_shared: std.ArrayList(Id) = .empty,
    transfers: std.ArrayList(struct { addr: Id, obj: Obj }) = .empty,
    events: std.ArrayList(types.Event) = .empty,
    events_taken: usize = 0,
    links: std.ArrayList(*move_vm.LinkCtx) = .empty,
    /// The error's argument index for the failing command.
    arg_idx: usize = 0,

    fn diag(c: *Ctx) *pkgs.Diag {
        return c.p.diag;
    }
    fn fail(c: *Ctx, kind: types.ExecutionErrorKind) error{Fail} {
        return c.diag().failWith(kind, null);
    }
    fn argErr(c: *Ctx, idx: usize, kind: ArgErr) error{Fail} {
        return c.fail(.{ .CommandArgumentError = .{ .arg_idx = @intCast(idx), .kind = kind } });
    }
    fn unsupported(c: *Ctx, why: []const u8) error{Unsupported} {
        return c.diag().unsupported(why);
    }
    fn heap(c: *Ctx) move_vm.value.Heap {
        return c.sess.heap;
    }

    // ---- arguments

    fn splatOne(c: *Ctx, out: *std.ArrayList(Arg), a: types.Argument, idx: usize) Error!void {
        if (!c.cfg.feature_flags.normalize_ptb_arguments) {
            try out.append(c.arena, switch (a) {
                .GasCoin => .gas,
                .Input => |i| .{ .input = i },
                .Result => |i| .{ .result = i },
                .NestedResult => |n| .{ .nested = .{ n[0], n[1] } },
            });
            return;
        }
        switch (a) {
            .GasCoin => try out.append(c.arena, .gas),
            .Input => |i| {
                if (i >= c.inputs.len) return c.argErr(idx, .{ .IndexOutOfBounds = .{ .idx = i } });
                try out.append(c.arena, .{ .input = i });
            },
            .NestedResult => |n| {
                if (n[0] >= c.results.items.len) return c.argErr(idx, .{ .IndexOutOfBounds = .{ .idx = n[0] } });
                if (n[1] >= c.results.items[n[0]].len) return c.argErr(idx, .{ .SecondaryIndexOutOfBounds = .{ .result_idx = n[0], .secondary_idx = n[1] } });
                try out.append(c.arena, .{ .nested = .{ n[0], n[1] } });
            },
            .Result => |i| {
                if (i >= c.results.items.len) return c.argErr(idx, .{ .IndexOutOfBounds = .{ .idx = i } });
                if (c.results.items[i].len != 1) return c.argErr(idx, .{ .InvalidResultArity = .{ .result_idx = i } });
                try out.append(c.arena, .{ .nested = .{ i, 0 } });
            },
        }
    }

    fn splat(c: *Ctx, start: usize, args: []const types.Argument) Error![]Arg {
        var out: std.ArrayList(Arg) = .empty;
        for (args, 0..) |a, k| try c.splatOne(&out, a, start + k);
        return out.items;
    }

    fn oneArg(c: *Ctx, idx: usize, a: types.Argument) Error!Arg {
        const s = try c.splat(idx, &.{a});
        if (s.len != 1) return c.argErr(idx, .InvalidArgumentArity);
        return s[0];
    }

    const Ref = struct { meta: Meta, slot: *Slot };

    /// `borrow_mut_impl` (v1: lazy bounds checks; v2: checked by splat).
    fn slotOf(c: *Ctx, a: Arg, idx: usize, usage: ?Usage) Error!Ref {
        const r: Ref = switch (a) {
            .gas => .{ .meta = c.gas_meta, .slot = &c.gas },
            .input => |i| blk: {
                if (i >= c.inputs.len) return c.argErr(idx, .{ .IndexOutOfBounds = .{ .idx = i } });
                break :blk .{ .meta = c.metas[i], .slot = &c.inputs[i] };
            },
            .result => |i| blk: {
                if (i >= c.results.items.len) return c.argErr(idx, .{ .IndexOutOfBounds = .{ .idx = i } });
                if (c.results.items[i].len != 1) return c.argErr(idx, .{ .InvalidResultArity = .{ .result_idx = i } });
                break :blk .{ .meta = .none, .slot = &c.results.items[i][0] };
            },
            .nested => |n| blk: {
                if (n[0] >= c.results.items.len) return c.argErr(idx, .{ .IndexOutOfBounds = .{ .idx = n[0] } });
                if (n[1] >= c.results.items[n[0]].len) return c.argErr(idx, .{ .SecondaryIndexOutOfBounds = .{ .result_idx = n[0], .secondary_idx = n[1] } });
                break :blk .{ .meta = .none, .slot = &c.results.items[n[0]][n[1]] };
            },
        };
        if (usage) |u| r.slot.last = u;
        return r;
    }

    fn isResult(a: Arg) bool {
        return a == .result or a == .nested;
    }

    /// `by_value_arg`.
    fn byValue(c: *Ctx, kind: CmdKind, idx: usize, a: Arg) Error!Val {
        const is_borrowed = c.borrowed.contains(a);
        const r = try c.slotOf(a, idx, .by_value);
        const v = r.slot.val orelse return c.argErr(idx, .InvalidValueUsage);
        const copy = v.copyable();
        if (!copy and is_borrowed) return c.argErr(idx, .InvalidValueUsage);
        if (a == .gas and kind != .transfer) return c.argErr(idx, .InvalidGasCoinUsage);
        switch (r.meta) {
            .object => |m| {
                if (m.owner == .Immutable) return c.argErr(idx, .InvalidObjectByValue);
                if (m.owner == .Shared and !c.cfg.feature_flags.shared_object_deletion) return c.argErr(idx, .InvalidObjectByValue);
                if (!m.mutable) return c.argErr(idx, .InvalidObjectByValue);
            },
            else => {},
        }
        const out = if (copy) try v.clone(c.arena) else v;
        if (!copy) r.slot.val = null;
        if (c.cfg.feature_flags.per_command_shared_object_transfer_rules)
            try c.per_command_shared.appendSlice(c.arena, r.slot.shared.items);
        return out;
    }

    /// `borrow_arg_mut`.
    fn borrowMut(c: *Ctx, idx: usize, a: Arg) Error!Val {
        if (c.borrowed.contains(a)) return c.argErr(idx, .InvalidValueUsage);
        try c.borrowed.put(c.arena, a, true);
        const r = try c.slotOf(a, idx, .borrow_mut);
        const v = r.slot.val orelse return c.argErr(idx, .InvalidValueUsage);
        switch (r.meta) {
            .object => |m| if (!m.mutable) return c.argErr(idx, .InvalidObjectByMutRef),
            else => {},
        }
        const copy = v.copyable();
        const out = if (copy) try v.clone(c.arena) else v;
        if (!copy) r.slot.val = null;
        if (c.cfg.feature_flags.per_command_shared_object_transfer_rules and isResult(a))
            try c.per_command_shared.appendSlice(c.arena, r.slot.shared.items);
        return out;
    }

    /// `borrow_arg`.
    fn borrowImm(c: *Ctx, idx: usize, a: Arg, param: Ty) Error!Val {
        if (c.borrowed.get(a) orelse false) return c.argErr(idx, .InvalidValueUsage);
        try c.borrowed.put(c.arena, a, false);
        const r = try c.slotOf(a, idx, .borrow_imm);
        if (r.slot.val == null) return c.argErr(idx, .InvalidValueUsage);
        switch (r.slot.val.?) {
            .receiving => |*rv| if (rv.ty == null) {
                if (param.* != .ref) return c.argErr(idx, .InvalidValueUsage);
                rv.ty = param.ref;
            },
            else => {},
        }
        return try r.slot.val.?.clone(c.arena);
    }

    /// `restore_arg`.
    fn restore(c: *Ctx, a: Arg, v: Val) Error!void {
        const was = c.borrowed.fetchSwapRemove(a) orelse return c.unsupported("restore of an unborrowed argument");
        if (!was.value) return c.unsupported("restore of an immutable borrow");
        const r = try c.slotOf(a, 0, null);
        if (c.cfg.feature_flags.per_command_shared_object_transfer_rules and isResult(a)) r.slot.shared.clearRetainingCapacity();
        r.slot.val = v;
    }

    fn objectOf(c: *Ctx, idx: usize, v: Val) Error!Obj {
        return switch (v) {
            .object => |o| o,
            else => c.argErr(idx, .TypeMismatch),
        };
    }

    /// `try_from_value_prim` for u64 and address.
    fn prim(c: *Ctx, idx: usize, v: Val, comptime T: type) Error!T {
        const want: Ty = if (T == u64) &move_vm.Type.t_u64 else &move_vm.Type.t_address;
        const bytes = switch (v) {
            .object, .receiving => return c.argErr(idx, .TypeMismatch),
            .any => |b| b,
            .loaded => |l| blk: {
                if (!typing.eql(l.ty, want)) return c.argErr(idx, .TypeMismatch);
                break :blk l.bytes;
            },
        };
        if (T == u64) {
            if (bytes.len != 8) return c.argErr(idx, .InvalidBCSBytes);
            return std.mem.readInt(u64, bytes[0..8], .little);
        }
        if (bytes.len != 32) return c.argErr(idx, .InvalidBCSBytes);
        return bytes[0..32].*;
    }

    // ---- values

    fn makeObject(c: *Ctx, ty: Ty, non_entry: bool, bytes: []const u8) Error!Obj {
        return .{
            .ty = ty,
            .public_transfer = typing.abilities(ty).hasStore(),
            .non_entry = non_entry,
            .bytes = try c.arena.dupe(u8, bytes),
            .coin = typing.coinInner(ty) != null,
        };
    }

    /// `make_value` of a Move call output.
    fn makeValue(c: *Ctx, ty: Ty, non_entry: bool, bytes: []const u8) Error!Val {
        const ab = typing.abilities(ty);
        if (ty.* == .datatype and ab.hasKey()) return .{ .object = try c.makeObject(ty, non_entry, bytes) };
        return .{ .loaded = .{ .ty = ty, .ab = ab, .non_entry = non_entry, .bytes = bytes } };
    }

    /// `check_param_type`.
    fn checkParam(c: *Ctx, idx: usize, v: Val, param: Ty) Error!void {
        switch (v) {
            .any => |bytes| {
                const lay = (try typing.primLayout(c.arena, param)) orelse return c.argErr(idx, .InvalidUsageOfPureArg);
                var at: usize = 0;
                if (!typing.validate(bytes, &at, lay, 0) or at != bytes.len) return c.argErr(idx, .InvalidBCSBytes);
            },
            .loaded => |l| if (!typing.eql(l.ty, param)) return c.argErr(idx, .TypeMismatch),
            .object => |o| if (!typing.eql(o.ty, param)) return c.argErr(idx, .TypeMismatch),
            .receiving => |r| {
                if (r.ty) |t| if (!typing.eql(t, param)) return c.argErr(idx, .TypeMismatch);
                if (!typing.isDt(param, 2, "transfer", "Receiving") or param.datatype.args.len != 1) return c.argErr(idx, .TypeMismatch);
            },
        }
    }

    fn deser(c: *Ctx, ty: Ty, bytes: []const u8) Error!Value {
        // FAILED_TO_DESERIALIZE_ARGUMENT (Location::Undefined), mapped by the adapter (CONTRACTS 6.6b.2)
        return (try move_vm.types.deserializeArg(c.heap(), ty, bytes)) orelse c.fail(.VMVerificationOrDeserializationError);
    }

    fn ser(c: *Ctx, ty: Ty, v: Value) Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        try move_vm.types.serialize(c.arena, ty, v, &out);
        return out.items;
    }

    fn coinBalance(o: *const Obj) u64 {
        return std.mem.readInt(u64, o.bytes[32..40], .little);
    }
    fn setCoinBalance(o: *Obj, b: u64) void {
        std.mem.writeInt(u64, o.bytes[32..40], b, .little);
    }

    fn freshId(c: *Ctx) Error!Id {
        const id = c.host.tx.freshId();
        if (try c.host.rt.newId(c.arena, c.cfg, id)) |e| return c.fail(run.vmError(c.rr, .{ .major = e.status, .sub = e.sub }));
        return id;
    }

    fn vmFail(c: *Ctx, e: move_vm.VmError) error{Fail} {
        var kind = run.vmError(c.rr, e);
        // before `resolve_abort_locations_to_package_id` an abort names the runtime (original) id
        if (kind == .MoveAbort and !c.cfg.feature_flags.resolve_abort_locations_to_package_id) {
            const addr = &kind.MoveAbort[0].module.address.@"0";
            for (c.p.unified) |l| if (std.mem.eql(u8, &l[1], addr)) {
                addr.* = l[0];
                break;
            };
        }
        return c.fail(kind);
    }

    // ---- loading (Context::new)

    /// Loads the packages a type's layout reaches (each named package's linkage table) into the
    /// runtime: Mysten loads types by storage id without a link context.
    fn ensureLoaded(c: *Ctx, ty: Ty) Error!void {
        var ids: std.ArrayList(Id) = .empty;
        try typing.addresses(c.arena, ty, &ids);
        for (ids.items) |*id| {
            const pkg = try c.p.linker.pkg(id);
            for (pkg.linkage) |l| {
                const dp = try c.p.linker.pkg(&l[1]);
                const v = c.p.linker.cache.load(dp) catch return c.unsupported("package does not load");
                if (v.refused != null) return c.unsupported("package refused by the loader");
            }
        }
    }

    fn loadObject(c: *Ctx, raw: []const u8, contents_override: ?[]const u8, mutable_override: ?bool) Error!struct { Meta, Obj } {
        const view = objects.ObjectView.parse(raw) catch return c.unsupported("input object does not parse");
        const owner = bcs.decode(types.Owner, c.arena, raw[view.owner_at..view.prev_tx_at]) catch return c.unsupported("input owner");
        const mutable = switch (owner) {
            .AddressOwner => true,
            .Shared, .ConsensusAddressOwner => mutable_override orelse true,
            .Immutable => false,
            else => return c.unsupported("input owner kind"),
        };
        const st = typing.objectTag(c.arena, raw) catch return c.unsupported("input object type");
        const ty = try typing.fromStruct(c.p, &st);
        try c.ensureLoaded(ty);
        const contents = contents_override orelse view.contents();
        // recompute_has_public_transfer_in_execution (30)
        const ab = typing.abilities(ty);
        const ptransfer = if (c.cfg.feature_flags.recompute_has_public_transfer_in_execution) ab.hasStore() else (raw[view.version_at - 1] != 0);
        const lim = vm_host.Limits.of(c.sess.cfg);
        const al = (try vm_host.annotatedLimited(c.arena, ty, lim)) orelse {
            const nodes_ok = (try vm_host.annotatedLimited(c.arena, ty, .{ .max_depth = lim.max_depth, .max_nodes = std.math.maxInt(u64) })) != null;
            const depth_ok = (try vm_host.annotatedLimited(c.arena, ty, .{ .max_depth = std.math.maxInt(u64), .max_nodes = lim.max_nodes })) != null;
            const none_ok = (try vm_host.annotatedLimited(c.arena, ty, .none)) != null;
            return c.unsupported(if (nodes_ok) "object layout over the node limit" else if (depth_ok) "object layout over the depth limit" else if (none_ok) "object layout over both limits" else "object layout fails without limits");
        };
        const lay = (try vm_host.layoutLimited(c.arena, ty, lim)) orelse return c.unsupported("object layout over the limits");
        const lv = types.layout.decodePacked(c.arena, lay, contents) catch return c.unsupported("object contents do not decode");
        const uids = try objrt.allUids(c.arena, &lv, al);
        try c.host.rt.addInput(c.arena, .{ .id = view.id, .version = view.version, .owner = try objrt.Owner.fromTypes(c.arena, &owner), .contained_uids = uids });
        return .{
            .{ .object = .{ .id = view.id, .mutable = mutable, .owner = owner, .version = view.version } },
            .{ .ty = ty, .public_transfer = ptransfer, .non_entry = false, .bytes = try c.arena.dupe(u8, contents), .coin = typing.coinInner(ty) != null },
        };
    }

    fn init(c: *Ctx, srcs: []const ?typing.ObjSource) Error!void {
        for (c.p.pt.inputs, srcs, c.inputs, c.metas) |*arg, src, *slot, *meta| {
            slot.* = .{};
            meta.* = .none;
            switch (arg.*) {
                .Pure => |b| slot.val = .{ .any = b },
                .Object => |*oa| switch (oa.*) {
                    .Receiving => |r| {
                        meta.* = .receiving;
                        slot.val = .{ .receiving = .{ .id = r[0].@"0".@"0", .version = r[1].@"0", .ty = null } };
                    },
                    else => {
                        const s = src orelse return c.unsupported("object input without a source");
                        const m, const o = try c.loadObject(s.raw, null, s.shared_mutable);
                        meta.* = m;
                        slot.val = .{ .object = o };
                        if (m.object.owner == .Shared) try slot.shared.append(c.arena, m.object.id);
                    },
                },
                .FundsWithdrawal => return c.unsupported("funds withdrawal on a dynamic cut"),
            }
        }
        if (c.in.gas) |g| {
            const m, var o = try c.loadObject(g.raw, g.contents, null);
            if (!o.coin) return c.unsupported("gas object is not a coin");
            const bal = coinBalance(&o);
            if (bal < c.in.budget) return c.unsupported("gas coin below the budget");
            setCoinBalance(&o, bal - c.in.budget);
            c.gas_meta = m;
            c.gas.val = .{ .object = o };
        }
    }

    // ---- commands (`execute_command`)

    fn command(c: *Ctx, cmd: *const types.Command) Error!void {
        var kind: CmdKind = undefined;
        var out: []Val = &.{};
        switch (cmd.*) {
            .MakeMoveVec => |*m| {
                kind = .make_vec;
                out = try c.makeMoveVec(if (m[0]) |*t| t else null, m[1]);
            },
            .TransferObjects => |*t| {
                kind = .transfer;
                try c.transferObjects(t[0], t[1]);
            },
            .SplitCoins => |*s| {
                kind = .split;
                out = try c.splitCoins(s[0], s[1]);
            },
            .MergeCoins => |*m| {
                kind = .merge;
                try c.mergeCoins(m[0], m[1]);
            },
            .MoveCall => |*mc| {
                kind = .call;
                out = try c.moveCall(mc);
            },
            .Publish => |*x| {
                kind = .publish;
                out = try c.publish(x[0], x[1]);
            },
            .Upgrade => |*x| {
                kind = .upgrade;
                out = try c.upgrade(x[0], x[1], x[2].@"0".@"0", x[3]);
            },
        }
        try c.pushResults(kind, out);
    }

    fn vecOf(c: *Ctx, elem: Ty) Allocator.Error!Ty {
        const t = try c.arena.create(move_vm.Type);
        t.* = .{ .vector = elem };
        return t;
    }

    fn makeMoveVec(c: *Ctx, tyin: ?*const types.TypeInput, raw: []const types.Argument) Error![]Val {
        const out = try c.arena.alloc(Val, 1);
        if (raw.len == 0) {
            const t = tyin orelse return c.unsupported("empty MakeMoveVec without a type");
            const vt = try c.vecOf(try typing.fromInputAt(c.p, 0, t, .vec));
            out[0] = .{ .loaded = .{ .ty = vt, .ab = typing.abilities(vt), .non_entry = false, .bytes = &.{0} } };
            return out;
        }
        const args = try c.splat(0, raw);
        var buf: std.ArrayList(u8) = .empty;
        var n = args.len;
        while (true) {
            const b: u8 = @intCast(n & 0x7f);
            n >>= 7;
            try buf.append(c.arena, if (n != 0) b | 0x80 else b);
            if (n == 0) break;
        }
        var non_entry = false;
        var elem: Ty = undefined;
        var start: usize = 0;
        if (tyin) |t| {
            elem = try typing.fromInputAt(c.p, 0, t, .vec);
        } else {
            const o = try c.objectOf(0, try c.byValue(.make_vec, 0, args[0]));
            non_entry = o.non_entry;
            elem = o.ty;
            try buf.appendSlice(c.arena, o.bytes);
            start = 1;
        }
        for (args[start..], start..) |a, idx| {
            const v = try c.byValue(.make_vec, idx, a);
            try c.checkParam(idx, v, elem);
            non_entry = non_entry or v.nonEntry();
            try buf.appendSlice(c.arena, try v.bytesOf(c.arena));
        }
        try c.ensureLoaded(elem);
        const vt = try c.vecOf(elem);
        out[0] = .{ .loaded = .{ .ty = vt, .ab = typing.abilities(vt), .non_entry = non_entry, .bytes = buf.items } };
        return out;
    }

    fn transferObjects(c: *Ctx, raw_objs: []const types.Argument, raw_addr: types.Argument) Error!void {
        const objs = try c.splat(0, raw_objs);
        const addr_arg = try c.oneArg(raw_objs.len, raw_addr);
        const vals = try c.arena.alloc(Obj, objs.len);
        for (objs, vals, 0..) |a, *o, idx| o.* = try c.objectOf(idx, try c.byValue(.transfer, idx, a));
        const addr = try c.prim(objs.len, try c.byValue(.transfer, objs.len, addr_arg), Id);
        for (vals) |o| {
            if (!o.public_transfer) return c.fail(.InvalidTransferObject);
            try c.transfers.append(c.arena, .{ .addr = addr, .obj = o });
        }
    }

    fn splitCoins(c: *Ctx, raw_coin: types.Argument, raw_amounts: []const types.Argument) Error![]Val {
        const coin_arg = try c.oneArg(0, raw_coin);
        const amounts = try c.splat(1, raw_amounts);
        var obj = try c.objectOf(0, try c.borrowMut(0, coin_arg));
        if (!obj.coin) return c.argErr(0, .TypeMismatch);
        const out = try c.arena.alloc(Val, amounts.len);
        for (amounts, out) |a, *o| {
            const amount = try c.prim(1, try c.byValue(.split, 1, a), u64);
            const id = try c.freshId();
            const bal = coinBalance(&obj);
            if (bal < amount) return c.fail(.InsufficientCoinBalance);
            setCoinBalance(&obj, bal - amount);
            const bytes = try c.arena.alloc(u8, 40);
            @memcpy(bytes[0..32], &id);
            std.mem.writeInt(u64, bytes[32..40], amount, .little);
            o.* = .{ .object = .{ .ty = obj.ty, .public_transfer = true, .non_entry = false, .bytes = bytes, .coin = true } };
        }
        try c.restore(coin_arg, .{ .object = obj });
        return out;
    }

    fn mergeCoins(c: *Ctx, raw_target: types.Argument, raw_coins: []const types.Argument) Error!void {
        const target_arg = try c.oneArg(0, raw_target);
        const coin_args = try c.splat(1, raw_coins);
        var target = try c.objectOf(0, try c.borrowMut(0, target_arg));
        if (!target.coin) return c.argErr(0, .TypeMismatch);
        const coins = try c.arena.alloc(Obj, coin_args.len);
        for (coin_args, coins, 0..) |a, *o, k| o.* = try c.objectOf(k + 1, try c.byValue(.merge, k + 1, a));
        for (coins, 0..) |*co, k| {
            if (!typing.eql(target.ty, co.ty)) return c.argErr(k + 1, .TypeMismatch);
            if (try c.host.rt.deleteId(c.arena, c.cfg, co.bytes[0..32].*)) |e| return c.fail(run.vmError(c.rr, .{ .major = e.status, .sub = e.sub }));
            const sum = std.math.add(u64, coinBalance(&target), coinBalance(co)) catch return c.fail(.CoinBalanceOverflow);
            setCoinBalance(&target, sum);
        }
        try c.restore(target_arg, .{ .object = target });
    }

    /// The TxContext argument (`to_bcs_legacy_context`; zeroed fields under the native context).
    fn txContextSlot(c: *Ctx) Error!*Value {
        const native_ctx = c.cfg.feature_flags.move_native_context;
        const tx = &c.host.tx;
        const hash = try c.heap().newContainer(.vec_u8, 32);
        @memcpy(hash.bytes(), &tx.digest);
        const s = try c.arena.create(Value);
        s.* = try c.heap().pack(.struct_, 0, &.{
            try c.heap().address(if (native_ctx) @splat(0) else tx.sender),
            Value.container(hash),
            Value.u64_(if (native_ctx) 0 else tx.epoch),
            Value.u64_(if (native_ctx) 0 else tx.epoch_timestamp_ms),
            Value.u64_(if (native_ctx) 0 else tx.ids_created),
        });
        return s;
    }

    /// `TxContext::update_state` after a call taking `&mut TxContext`: ids_created never decreases.
    fn txContextDone(c: *Ctx, s: *Value, kind: typing.TxCtxKind) Error!void {
        if (kind == .mutable and !c.cfg.feature_flags.move_native_context) {
            const ids = s.cont().values()[4].a;
            if (ids < c.host.tx.ids_created) return c.unsupported("TxContext ids_created decreased");
            c.host.tx.ids_created = ids;
        }
        c.heap().drop(s.*);
    }

    // ---- Publish and Upgrade (`execute_move_publish`, `execute_move_upgrade`)

    fn frameworkTy(c: *Ctx, module: []const u8, name: []const u8) Error!Ty {
        var two: Id = @splat(0);
        two[31] = 2;
        const st: types.StructTag = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = module }, .name = .{ .@"0" = name }, .type_args = &.{} };
        return typing.fromStruct(c.p, &st);
    }

    /// `charge_publish_package` (`charge_upgrade_package` from gas model 7; v0 never charges an
    /// upgrade).
    fn chargePackage(c: *Ctx, modules: []const []const u8) Error!void {
        var total: u64 = 0;
        for (modules) |m| total += m.len;
        const per = c.cfg.getOpt("package_publish_cost_per_byte") orelse return c.unsupported("no package_publish_cost_per_byte");
        c.p.meter.chargeBytes(total, per) catch return c.fail(.InsufficientGas);
    }

    /// `deserialize_modules`: the payload as a `typing.Publish` (no publication linkage: the
    /// dynamic cuts run `init` under the package's own linkage).
    fn payload(c: *Ctx, modules: []const []const u8, deps: []const types.ObjectID) Error!*typing.Publish {
        const binary = &c.p.linker.cache.rt.binary;
        const cms = try c.arena.alloc(ff.CompiledModule, modules.len);
        var has_init = false;
        for (modules, cms) |b, *cm| {
            cm.* = switch (try move_format.deserialize(c.arena, b, binary)) {
                .ok => |x| x,
                .err => return c.fail(.VMVerificationOrDeserializationError),
            };
            if (typing.moduleHasInit(cm)) has_init = true;
        }
        const dep_ids = try c.arena.alloc(Id, deps.len);
        for (deps, dep_ids) |d, *o| o.* = d.@"0".@"0";
        const pb = try c.arena.create(typing.Publish);
        pb.* = .{ .modules = modules, .cms = cms, .deps = dep_ids, .linkage = &.{}, .linkage_entries = 0, .total_bytes = 0, .has_init = has_init };
        return pb;
    }

    /// `init_modules`: every module defining `init`, in payload order, under the package's linkage
    /// (`set_linkage(package)`), as an `Init` call: an optional one-time witness then the TxContext.
    fn initModules(c: *Ctx, id: Id, mods: []const ff.CompiledModule, vlink: [][2][32]u8) Error!void {
        const arena = c.arena;
        const root = try pkgs.rootPackage(arena, c.link.rt, vlink);
        const lc = try arena.create(move_vm.LinkCtx);
        lc.* = move_vm.LinkCtx.init(c.link.rt, root);
        try c.links.append(arena, lc);
        c.sess.link = lc;
        c.p.unified = vlink;
        for (mods) |*m| {
            if (!typing.moduleHasInit(m)) continue;
            const name = m.selfName();
            const f = lc.function(&id, name, "init") catch return c.unsupported("init does not link");
            const params = try move_vm.types.instantiateAll(arena, f.module, f.params, &.{});
            const ctx_kind: typing.TxCtxKind = if (params.len > 0) typing.txContextKind(params[params.len - 1]) else .none;
            const otw = params.len == 2;
            if (@as(usize, @intFromBool(otw)) + @intFromBool(ctx_kind != .none) != params.len) return c.fail(.ArityMismatch);
            const vm_args = try arena.alloc(Value, params.len);
            if (otw) vm_args[0] = try c.deser(params[0], &.{1});
            var ctx_slot: ?*Value = null;
            if (ctx_kind != .none) {
                const s = try c.txContextSlot();
                vm_args[params.len - 1] = Value.refSlot(s);
                ctx_slot = s;
            }
            const res = c.sess.run(f, &.{}, vm_args) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.NativeUnsupported => return c.unsupported("native not implemented"),
                else => return c.unsupported("VM load error"),
            };
            const rets = switch (res) {
                .ok => |x| x,
                .err => |e| return c.vmFail(e),
            };
            if (rets.len != 0) return c.unsupported("init returned values");
            if (ctx_slot) |s| try c.txContextDone(s, ctx_kind);
            try c.takeEventsAt(id, name);
        }
    }

    fn publish(c: *Ctx, modules: []const []const u8, deps: []const types.ObjectID) Error![]Val {
        const arena = c.arena;
        try c.chargePackage(modules);
        const pb = try c.payload(modules, deps);
        if (!c.cfg.feature_flags.package_upgrades) return c.unsupported("publish before package_upgrades");
        const id = c.host.tx.freshId();
        const mods = try run.substitute(c.rr, pb, id);
        const bp = try run.buildPackage(c.rr, mods, .{ .deps = pb.deps, .storage_id = id, .original_id = id, .version = 1, .prev = null, .policy = 0 });
        try c.initModules(id, mods, bp.vlink);
        try c.rr.packages.append(arena, .{ .id = id, .version = 1, .bytes = bp.bytes });
        // UpgradeCap { id, package, version: 1, policy: COMPATIBLE }
        const cap_id = try c.freshId();
        const bytes = try arena.alloc(u8, 32 + 32 + 8 + 1);
        @memcpy(bytes[0..32], &cap_id);
        @memcpy(bytes[32..64], &id);
        std.mem.writeInt(u64, bytes[64..72], 1, .little);
        bytes[72] = 0;
        const out = try arena.alloc(Val, 1);
        out[0] = .{ .object = .{ .ty = try c.frameworkTy("package", "UpgradeCap"), .public_transfer = true, .non_entry = false, .bytes = bytes, .coin = false } };
        return out;
    }

    fn upgrade(c: *Ctx, modules: []const []const u8, deps: []const types.ObjectID, current_id: Id, raw_ticket: types.Argument) Error![]Val {
        const arena = c.arena;
        if (!c.cfg.feature_flags.package_upgrades) return c.fail(.FeatureNotYetSupported);
        const gm = c.cfg.getOpt("gas_model_version") orelse 0;
        if (versions.executionVersion(c.cfg) > 0 and gm >= 7) try c.chargePackage(modules);
        const ticket_ty = try c.frameworkTy("package", "UpgradeTicket");
        const receipt_ty = try c.frameworkTy("package", "UpgradeReceipt");
        const v = try c.byValue(.upgrade, 0, try c.oneArg(0, raw_ticket));
        try c.checkParam(0, v, ticket_ty);
        // UpgradeTicket { cap: ID, package: ID, policy: u8, digest: vector<u8> }
        const tb = try v.bytesOf(arena);
        if (tb.len < 66) return c.argErr(0, .InvalidBCSBytes);
        const cap = tb[0..32].*;
        const ticket_pkg = tb[32..64].*;
        const policy = tb[64];
        var at: usize = 65;
        var n: usize = 0;
        var shift: u6 = 0;
        while (at < tb.len) : (shift += 7) {
            const b = tb[at];
            at += 1;
            n |= @as(usize, b & 0x7f) << shift;
            if (b & 0x80 == 0) break;
        }
        if (at + n != tb.len) return c.argErr(0, .InvalidBCSBytes);
        const digest = tb[at..];
        if (!std.mem.eql(u8, &current_id, &ticket_pkg))
            return c.fail(.{ .PackageUpgradeError = .{ .upgrade_error = .{ .PackageIDDoesNotMatch = .{ .package_id = .{ .@"0" = .{ .@"0" = current_id } }, .ticket_id = .{ .@"0" = .{ .@"0" = ticket_pkg } } } } } });
        if (!c.cfg.feature_flags.package_digest_hash_module) return c.unsupported("upgrade before package_digest_hash_module");
        const dep_ids = try arena.alloc(Id, deps.len);
        for (deps, dep_ids) |d, *o| o.* = d.@"0".@"0";
        const computed = try typing.packageDigest(arena, modules, dep_ids);
        if (!std.mem.eql(u8, &computed, digest))
            return c.fail(.{ .PackageUpgradeError = .{ .upgrade_error = .{ .DigestDoesNotMatch = .{ .digest = try arena.dupe(u8, &computed) } } } });
        if (!c.cfg.feature_flags.disallow_adding_abilities_on_upgrade) return c.unsupported("upgrade before disallow_adding_abilities_on_upgrade");
        const cur = (try c.p.linker.cache.get(&current_id)) orelse return c.fail(.PublishUpgradeMissingDependency);
        const pb = try c.payload(modules, deps);
        const mods = try run.substitute(c.rr, pb, cur.original_id);
        const storage_id = c.host.tx.freshId();
        const bp = try run.buildPackage(c.rr, mods, .{ .deps = pb.deps, .storage_id = storage_id, .original_id = cur.original_id, .version = cur.version + 1, .prev = cur, .policy = policy });
        if (c.cfg.feature_flags.check_for_init_during_upgrade) for (mods, bp.is_new) |*m, new| {
            if (new and typing.moduleHasInit(m)) return c.fail(.FeatureNotYetSupported);
        };
        try c.rr.packages.append(arena, .{ .id = storage_id, .version = cur.version + 1, .bytes = bp.bytes });
        // UpgradeReceipt { cap: ID, package: ID }
        const rb = try arena.alloc(u8, 64);
        @memcpy(rb[0..32], &cap);
        @memcpy(rb[32..64], &storage_id);
        const out = try arena.alloc(Val, 1);
        out[0] = .{ .loaded = .{ .ty = receipt_ty, .ab = typing.abilities(receipt_ty), .non_entry = false, .bytes = rb } };
        return out;
    }

    // ---- Move calls (`execute_move_call`)

    const MutOut = struct { idx: usize, slot: *Value, inner: Ty, was_object: bool, public_transfer: bool };

    fn moveCall(c: *Ctx, mc: *const types.ProgrammableMoveCall) Error![]Val {
        const arena = c.arena;
        const args = try c.splat(0, mc.arguments);
        const call = try typing.loadFunction(c.p, mc);
        // check_visibility_and_signature
        if (c.cfg.feature_flags.ban_entry_init and std.mem.eql(u8, call.name, "init")) return c.fail(.NonEntryFunctionInvoked);
        const Kind = enum { private_entry, public_entry, non_entry };
        const kind: Kind = if (call.is_entry)
            (if (call.visibility == .Public) .public_entry else .private_entry)
        else if (call.visibility == .Public) .non_entry else return c.fail(.NonEntryFunctionInvoked);
        for (call.returns, 0..) |t, i| if (typing.isRef(t)) return c.fail(.{ .InvalidPublicFunctionReturnType = .{ .idx = @intCast(i) } });
        if (privateGeneric(c.cfg, call)) return c.fail(.NonEntryFunctionInvoked);

        // build_move_args: only the last parameter may be the TxContext
        const params = call.params;
        const ctx_kind: typing.TxCtxKind = if (params.len > 0) typing.txContextKind(params[params.len - 1]) else .none;
        if (args.len + @intFromBool(ctx_kind != .none) != params.len) return c.fail(.ArityMismatch);
        const vals = try arena.alloc(Val, args.len);
        const inners = try arena.alloc(Ty, args.len);
        for (args, vals, inners, 0..) |a, *v, *inner, idx| {
            const pt = params[idx];
            switch (pt.*) {
                .mut_ref => |i| {
                    v.* = try c.borrowMut(idx, a);
                    inner.* = i;
                },
                .ref => |i| {
                    v.* = try c.borrowImm(idx, a, pt);
                    inner.* = i;
                },
                else => {
                    v.* = try c.byValue(.call, idx, a);
                    inner.* = pt;
                },
            }
            if (kind == .private_entry and v.nonEntry()) return c.argErr(idx, .InvalidArgumentToPrivateEntryFunction);
            try c.checkParam(idx, v.*, inner.*);
        }

        // vm_move_call: arguments deserialized into the VM (unmetered)
        const vm_args = try arena.alloc(Value, params.len);
        var muts: std.ArrayList(MutOut) = .empty;
        var imms: std.ArrayList(*Value) = .empty;
        for (vals, inners, 0..) |v, inner, idx| {
            const mv = try c.deser(inner, try v.bytesOf(arena));
            switch (params[idx].*) {
                .mut_ref, .ref => {
                    const s = try arena.create(Value);
                    s.* = mv;
                    vm_args[idx] = Value.refSlot(s);
                    if (params[idx].* == .mut_ref) {
                        try muts.append(arena, .{ .idx = idx, .slot = s, .inner = inner, .was_object = v == .object, .public_transfer = if (v == .object) v.object.public_transfer else false });
                    } else try imms.append(arena, s);
                },
                else => vm_args[idx] = mv,
            }
        }
        var ctx_slot: ?*Value = null;
        if (ctx_kind != .none) {
            const s = try c.txContextSlot();
            vm_args[params.len - 1] = Value.refSlot(s);
            ctx_slot = s;
        }

        // set_link_context: the callee's linkage
        const root = try pkgs.rootPackage(arena, c.link.rt, call.linkage);
        const lc = try arena.create(move_vm.LinkCtx);
        lc.* = move_vm.LinkCtx.init(c.link.rt, root);
        try c.links.append(arena, lc);
        c.sess.link = lc;
        c.p.unified = call.linkage;
        const f = c.sess.link.function(&call.pkg.original_id, call.module, call.name) catch return c.unsupported("function does not link");
        const res = c.sess.run(f, call.ty_args, vm_args) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NativeUnsupported => return c.unsupported("native not implemented"),
            else => return c.unsupported("VM load error"),
        };
        const rets = switch (res) {
            .ok => |x| x,
            .err => |e| return c.vmFail(e),
        };
        // returns serialized before the &mut outputs
        const out = try arena.alloc(Val, rets.len);
        const ret_bytes = try arena.alloc([]const u8, rets.len);
        for (rets, call.returns, ret_bytes) |v, t, *b| {
            b.* = try c.ser(t, v);
            c.heap().drop(v);
        }
        const mut_bytes = try arena.alloc([]const u8, muts.items.len);
        for (muts.items, mut_bytes) |m, *b| {
            b.* = try c.ser(m.inner, m.slot.*);
            c.heap().drop(m.slot.*);
        }
        for (imms.items) |s| c.heap().drop(s.*);
        if (ctx_slot) |s| try c.txContextDone(s, ctx_kind);
        try c.takeEvents(call);

        // write_back_results
        const non_entry = kind == .non_entry;
        for (muts.items, mut_bytes) |m, b| {
            const v: Val = if (m.was_object) blk: {
                var o = try c.makeObject(m.inner, non_entry, b);
                if (!c.cfg.feature_flags.recompute_has_public_transfer_in_execution) o.public_transfer = m.public_transfer;
                break :blk .{ .object = o };
            } else .{ .loaded = .{ .ty = m.inner, .ab = typing.abilities(m.inner), .non_entry = non_entry, .bytes = b } };
            try c.restore(args[m.idx], v);
        }
        for (out, ret_bytes, call.returns) |*o, b, t| o.* = try c.makeValue(t, true, b);
        return out;
    }

    /// `take_user_events`; the module is the storage id from `relocate_event_module`.
    fn takeEvents(c: *Ctx, call: *const typing.Call) Error!void {
        const pkg = if (c.cfg.feature_flags.relocate_event_module) call.pkg.version_id else call.pkg.original_id;
        return c.takeEventsAt(pkg, call.module);
    }

    fn takeEventsAt(c: *Ctx, pkg: Id, module: []const u8) Error!void {
        const evs = c.host.rt.events.items;
        if (evs.len == c.events_taken) return;
        const max = c.cfg.getOpt("max_num_event_emit") orelse std.math.maxInt(u64);
        if (c.events.items.len + evs.len - c.events_taken > max) return c.unsupported("event count over the limit");
        for (evs[c.events_taken..]) |e| {
            const st = switch (e.ty.*) {
                .@"struct" => |s| s,
                else => return c.unsupported("event type"),
            };
            try c.events.append(c.arena, .{
                .package_id = .{ .@"0" = .{ .@"0" = pkg } },
                .transaction_module = .{ .@"0" = module },
                .sender = .{ .@"0" = c.in.sender },
                .type_ = st,
                .contents = try types.layout.encodeAlloc(c.arena, &e.value),
            });
        }
        c.events_taken = evs.len;
    }

    /// `push_command_results` with the per-command shared object rules.
    fn pushResults(c: *Ctx, kind: CmdKind, out: []Val) Error!void {
        c.borrowed.clearRetainingCapacity();
        const slots = try c.arena.alloc(Slot, out.len);
        for (slots, out) |*s, v| s.* = .{ .val = v };
        if (c.cfg.feature_flags.per_command_shared_object_transfer_rules) {
            if (kind == .make_vec) {
                try slots[0].shared.appendSlice(c.arena, c.per_command_shared.items);
            } else {
                for (c.per_command_shared.items) |id| {
                    const ok = c.host.rt.deleted_ids.contains(id) or if (c.host.rt.transfers.get(id)) |t| t.owner == .shared else false;
                    if (!ok) return c.fail(.SharedObjectOperationNotAllowed);
                }
            }
            c.per_command_shared.clearRetainingCapacity();
        }
        try c.results.append(c.arena, slots);
    }

    // ---- finish (`ExecutionContext::finish` + `finish`)

    const LoadedRt = struct { version: u64, modified: bool };

    fn finish(c: *Ctx) Error!run.Results {
        const arena = c.arena;
        const cfg = c.cfg;
        var loaded = std.AutoArrayHashMapUnmanaged(Id, LoadedRt).empty;
        var adds = std.AutoArrayHashMapUnmanaged(Id, Write).empty;
        var by_value_shared: std.ArrayList(Id) = .empty;
        var consensus: std.ArrayList(Id) = .empty;
        var all_slots: std.ArrayList(struct { m: Meta, s: *Slot }) = .empty;
        for (c.metas, c.inputs) |m, *s| try all_slots.append(arena, .{ .m = m, .s = s });
        try all_slots.append(arena, .{ .m = c.gas_meta, .s = &c.gas });
        for (all_slots.items) |x| {
            const m = switch (x.m) {
                .object => |o| o,
                else => continue,
            };
            if (!m.mutable) continue;
            try loaded.put(arena, m.id, .{ .version = m.version, .modified = true });
            if (x.s.val) |v| if (v == .object) {
                try adds.put(arena, v.object.bytes[0..32].*, .{ .owner = m.owner, .ty = v.object.ty, .public_transfer = v.object.public_transfer, .bytes = v.object.bytes });
                continue;
            };
            switch (m.owner) {
                .Shared => try by_value_shared.append(arena, m.id),
                .ConsensusAddressOwner => |co| if (!std.mem.eql(u8, &co.owner.@"0", &c.in.sender)) try consensus.append(arena, m.id),
                else => {},
            }
        }
        for (c.results.items, 0..) |r, i| for (r, 0..) |s, j| {
            const v = s.val orelse continue;
            const unused: types.ExecutionErrorKind = .{ .UnusedValueWithoutDrop = .{ .result_idx = @intCast(i), .secondary_idx = @intCast(j) } };
            switch (v) {
                .object => return c.fail(unused),
                .loaded => |l| if (!(l.ab.hasDrop() or (l.ab.hasCopy() and s.last == .by_value))) return c.fail(unused),
                else => {},
            }
        };
        for (c.transfers.items) |t| try adds.put(arena, t.obj.bytes[0..32].*, .{ .owner = .{ .AddressOwner = .{ .@"0" = t.addr } }, .ty = t.obj.ty, .public_transfer = t.obj.public_transfer, .bytes = t.obj.bytes });
        // refund_max_gas_budget
        if (c.gas_meta == .object) {
            const w = adds.getPtr(c.gas_meta.object.id) orelse return c.unsupported("gas coin wrapped or destroyed");
            const b = try arena.dupe(u8, w.bytes);
            const bal = std.mem.readInt(u64, b[32..40], .little);
            std.mem.writeInt(u64, b[32..40], std.math.add(u64, bal, c.in.budget) catch return c.fail(.CoinBalanceOverflow), .little);
            w.bytes = b;
        }
        // v0: the adapter's writes of new ids are WriteKind::Create (`new_ids` before finish)
        var v0_created_adds: std.ArrayList(Id) = .empty;
        if (versions.executionVersion(cfg) == 0) for (adds.keys()) |id| {
            if (c.host.rt.new_ids.contains(id)) try v0_created_adds.append(arena, id);
        };
        const fin = try c.host.finish(arena);
        var res = switch (fin) {
            .ok => |x| x,
            .err => |e| switch (e) {
                .circular => |id| return c.fail(.{ .CircularObjectOwnership = .{ .object = .{ .@"0" = .{ .@"0" = id } } } }),
                .invariant => return c.unsupported("object runtime invariant"),
            },
        };
        if (c.host.rt.config_cache.count() > 0) return c.unsupported("per-epoch config read");
        if (res.events.len != c.events_taken) return c.unsupported("events left in the runtime");
        if (res.acc_events.len > 0) return c.unsupported("accumulator events on a dynamic cut");
        for (res.loaded) |l| try loaded.put(arena, l.id, .{ .version = l.version, .modified = l.modified });
        // v0 (`ObjectRuntimeState::finish` of the v0 cut): loaded children carry no modified flag;
        // the write and delete kinds say it. A loaded child is Mutate when written, Normal when its
        // id is deleted, Wrap when its value left the store and went nowhere the runtime saw
        // (`wrapped_children` minus the adapter's `external_transfers`): those are the modified ones.
        if (versions.executionVersion(cfg) == 0) {
            for (res.writes) |w| if (loaded.getPtr(w.id)) |l| {
                l.modified = true;
            };
            for (res.deleted) |id| if (loaded.getPtr(id)) |l| {
                l.modified = true;
            };
            for (res.v0_wrapped_children) |id| if (!adds.contains(id)) if (loaded.getPtr(id)) |l| {
                l.modified = true;
            };
            if (v0_created_adds.items.len > 0) {
                const cr = try arena.alloc(Id, v0_created_adds.items.len + res.created.len);
                @memcpy(cr[0..v0_created_adds.items.len], v0_created_adds.items);
                @memcpy(cr[v0_created_adds.items.len..], res.created);
                res.created = cr;
            }
        }

        // written objects: the adapter's, then the object runtime's
        const max_size = cfg.getOpt("max_move_object_size");
        var written = std.AutoArrayHashMapUnmanaged(Id, run.Write).empty;
        for (adds.keys(), adds.values()) |id, w| {
            const tag = try vm_host.typeTag(arena, w.ty, .defining);
            const st = switch (tag.*) {
                .@"struct" => |s| s,
                else => return c.unsupported("non-struct object type"),
            };
            if (max_size) |m| if (w.bytes.len > m) return c.fail(.{ .MoveObjectTooBig = .{ .object_size = w.bytes.len, .max_object_size = m } });
            if (loaded.getPtr(id)) |l| l.modified = true;
            try written.put(arena, id, .{ .id = id, .owner = w.owner, .tag = st, .has_public_transfer = w.public_transfer, .contents = w.bytes, .old_version = if (loaded.get(id)) |l| l.version else 0 });
        }
        for (res.writes) |w| {
            const st = switch (w.ty.*) {
                .@"struct" => |s| s,
                else => return c.unsupported("non-struct object type"),
            };
            const ty = try typing.fromStruct(c.p, &st);
            const contents = try types.layout.encodeAlloc(arena, &w.value);
            if (max_size) |m| if (contents.len > m) return c.fail(.{ .MoveObjectTooBig = .{ .object_size = contents.len, .max_object_size = m } });
            const owner: types.Owner = switch (w.owner) {
                .address => |a| .{ .AddressOwner = .{ .@"0" = a } },
                .object => |a| .{ .ObjectOwner = .{ .@"0" = a } },
                .shared => |v| .{ .Shared = .{ .initial_shared_version = .{ .@"0" = v } } },
                .immutable => .Immutable,
                .consensus => |co| .{ .ConsensusAddressOwner = .{ .start_version = .{ .@"0" = co.start }, .owner = .{ .@"0" = co.owner } } },
                .party => return c.unsupported("party owner"),
            };
            try written.put(arena, w.id, .{ .id = w.id, .owner = owner, .tag = st, .has_public_transfer = typing.abilities(ty).hasStore(), .contents = contents, .old_version = if (loaded.get(w.id)) |l| l.version else 0 });
        }

        for (by_value_shared.items) |id| {
            if (written.get(id)) |w| {
                if (w.owner != .Shared) return c.fail(.SharedObjectOperationNotAllowed);
            } else {
                for (res.deleted) |d| {
                    if (std.mem.eql(u8, &d, &id)) break;
                } else return c.fail(.SharedObjectOperationNotAllowed);
            }
        }
        if (consensus.items.len > 0) return c.fail(.SharedObjectOperationNotAllowed);

        // coin deny list v2: non-SUI coin types and their owners (the driver runs
        // check_coin_deny_list_v2_during_execution on them, ptb/deny.zig)
        var deny_pairs: std.ArrayList(deny.Pair) = .empty;
        if (cfg.feature_flags.enable_coin_deny_list_v2) for (written.values()) |w| {
            const ct = coinTagArg(&w.tag) orelse continue;
            if (isSui(ct)) continue;
            const oaddr: ?Id = switch (w.owner) {
                .AddressOwner => |a| a.@"0",
                .ObjectOwner => |a| if (cfg.feature_flags.use_coin_party_owner) a.@"0" else null,
                .ConsensusAddressOwner => |co| if (cfg.feature_flags.use_coin_party_owner) co.owner.@"0" else null,
                else => null,
            };
            const a = oaddr orelse continue;
            try deny.addPair(arena, &deny_pairs, try deny.canonical(arena, ct), a, ct.*);
        };

        var modified: std.ArrayList(Id) = .empty;
        for (loaded.keys(), loaded.values()) |id, l| if (l.modified) try modified.append(arena, id);
        return .{
            .writes = try arena.dupe(run.Write, written.values()),
            .modified = modified.items,
            .created = res.created,
            .deleted = res.deleted,
            .events = c.events.items,
            .deny_list_read = deny_pairs.items.len > 0,
            .non_gas_coin_owners = deny_pairs.items.len,
            .deny_pairs = deny_pairs.items,
            .children = res.loaded,
            .packages = c.rr.packages.items,
        };
    }
};

fn short(a: *const Id) ?u8 {
    for (a[0..31]) |x| if (x != 0) return null;
    return a[31];
}

/// check_private_generics (v1 list) / check_private_generics_v2 (from protocol 100).
fn privateGeneric(cfg: *const @import("protocol").ProtocolConfig, call: *const typing.Call) bool {
    const s = short(&call.pkg.original_id) orelse return false;
    const m = call.module;
    const n = call.name;
    const eq = std.mem.eql;
    const transfer_private = s == 2 and eq(u8, m, "transfer") and for ([_][]const u8{ "transfer", "freeze_object", "share_object", "receive", "party_transfer" }) |x| {
        if (eq(u8, n, x)) break true;
    } else false;
    if (!cfg.feature_flags.private_generics_verifier_v2) return (s == 2 and eq(u8, m, "event")) or transfer_private;
    return (s == 1 and eq(u8, m, "internal") and eq(u8, n, "permit")) or
        (s == 2 and eq(u8, m, "event") and (eq(u8, n, "emit") or eq(u8, n, "emit_authenticated"))) or
        (s == 2 and eq(u8, m, "coin_registry") and eq(u8, n, "new_currency")) or
        transfer_private;
}

fn coinTagArg(st: *const types.StructTag) ?*const types.TypeTag {
    if (short(&st.address.@"0") != 2 or !std.mem.eql(u8, st.module.@"0", "coin") or !std.mem.eql(u8, st.name.@"0", "Coin") or st.type_args.len != 1) return null;
    return &st.type_args[0];
}

fn isSui(t: *const types.TypeTag) bool {
    const st = switch (t.*) {
        .@"struct" => |*s| s,
        else => return false,
    };
    return short(&st.address.@"0") == 2 and std.mem.eql(u8, st.module.@"0", "sui") and std.mem.eql(u8, st.name.@"0", "SUI") and st.type_args.len == 0;
}

/// Runs the commands of `p.pt` on a dynamic cut: Context::new, the commands, finish.
pub fn execute(p: *typing.Ptb, srcs: []const ?typing.ObjSource, host: *move_vm.Host, cache: *pkgs.Cache, in: In) Error!run.Results {
    const arena = p.arena;
    const root = try pkgs.rootPackage(arena, cache.rt, &.{});
    const link = try arena.create(move_vm.LinkCtx);
    link.* = move_vm.LinkCtx.init(cache.rt, root);
    defer link.deinit();
    const ecfg = versions.execConfig(p.cfg) catch return p.diag.unsupported("execution config");
    var sess = try move_vm.Session.init(arena, link, p.meter, ecfg);
    sess.natives = try versions.nativeTable(arena, p.cfg, host.table());
    sess.ext = host;
    var rr: run.Run = .{
        .p = p,
        .arena = arena,
        .host = host,
        .sess = sess,
        .link = link,
        .budget = in.budget,
        .sender = in.sender,
        .gas = .{ .owner = .Immutable },
        .objs = &.{},
        .pure = &.{},
        .recv = &.{},
    };
    var c: Ctx = .{
        .arena = arena,
        .p = p,
        .host = host,
        .sess = &sess,
        .rr = &rr,
        .link = link,
        .cfg = p.cfg,
        .in = in,
        .inputs = try arena.alloc(Slot, p.pt.inputs.len),
        .metas = try arena.alloc(Meta, p.pt.inputs.len),
    };
    defer for (c.links.items) |lc| lc.deinit();
    // Rust's package store lives for one transaction (root.zig runPtb does the same)
    defer cache.endTransaction(rr.published.items);
    try c.init(srcs);
    for (p.pt.commands, 0..) |*cmd, i| c.command(cmd) catch |e| {
        if (e == error.Fail and p.diag.fail.command == null) p.diag.fail.command = i;
        return e;
    };
    return c.finish();
}
