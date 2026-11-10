//! sui.rpc.v2 `ExecutedTransaction` rendering (transaction, signatures, effects, events) from
//! the BCS bytes the store holds, byte-equal to `rpc_proto_conversions.rs` lines 87-175, 557-640,
//! 2246-2330 and 3088-3500. Not ported yet: the resolver-backed annotations of render.rs (event and
//! object `json`, `clever_error` on MoveAbort); they are left out, as the truth tool (no package
//! resolver) leaves them out, so a `*` mask differs from a node with a resolver there.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const proto = @import("proto.zig");
const mask = @import("mask.zig");
const ro = @import("render_object.zig");
const rsig = @import("render_sig.zig");
const rc = @import("render_checkpoint.zig");
const typestr = @import("typestr.zig");
const objset = @import("objset.zig");
const exec_error = @import("exec_error.zig");
const pbvalue = @import("pbvalue.zig");

const Mask = mask.Mask;
const Writer = proto.Writer;
pub const Error = ro.Error;

pub const Input = struct {
    /// BCS TransactionData.
    transaction: []const u8,
    /// Raw GenericSignature bytes (flag byte first), one per signature.
    signatures: []const []const u8,
    /// BCS TransactionEffects.
    effects: []const u8,
    /// BCS TransactionEvents.
    events: ?[]const u8,
    /// Event `json` (render.rs): the resolver and budget; null leaves `json` out.
    render: ?*const ro.Ctx = null,
    /// Objects of the checkpoint (or transaction) for `annotate_effects`; null = no annotation.
    objects: ?*objset.ObjSet = null,
    /// `unchanged_loaded_runtime_objects` of the transaction (effects field 15).
    loaded: []const objset.Ref = &.{},
    /// Digest of `effects` when the caller already has it (checkpoint contents, store record):
    /// saves hashing the effects again.
    effects_digest: ?*const [32]u8 = null,
    /// `effects` already decoded by the caller (balance changes need it too).
    decoded_effects: ?types.TransactionEffects = null,
    /// Package lookup for `clever_error` on a MoveAbort status; null = not rendered.
    clever: ?exec_error.CleverResolver = null,
};

fn bcsMsg(w: *Writer, field: u32, name: []const u8, value: []const u8) proto.Error!void {
    const m = try w.begin(field, name.len + value.len + 8);
    try w.string(1, name);
    try w.bytes(2, value);
    try w.end(m);
}

fn timestampMsg(w: *Writer, field: u32, ms: u64) proto.Error!void {
    const m = try w.begin(field, 12);
    if (ms / 1000 != 0) try w.uint(1, ms / 1000);
    if (ms % 1000 != 0) try w.uint(2, (ms % 1000) * 1_000_000);
    try w.end(m);
}

fn objectRef(w: *Writer, field: u32, id: *const [32]u8, version: u64, digest: *const [32]u8) proto.Error!void {
    const m = try w.begin(field, 120);
    try ro.addrStr(w, 1, id);
    try w.uint(2, version);
    try ro.str32(w, 3, digest);
    try w.end(m);
}

fn writeExpiration(w: *Writer, field: u32, e: types.TransactionExpiration) proto.Error!void {
    const m = try w.begin(field, 64);
    switch (e) {
        .None => try w.uint(1, 1),
        .Epoch => |ep| {
            try w.uint(1, 2);
            try w.uint(2, ep);
        },
        .ValidDuring => |v| {
            try w.uint(1, 3);
            if (v.max_epoch) |x| try w.uint(2, x);
            if (v.min_epoch) |x| try w.uint(3, x);
            if (v.min_timestamp) |x| try timestampMsg(w, 4, x);
            if (v.max_timestamp) |x| try timestampMsg(w, 5, x);
            try ro.str32(w, 6, &v.chain.@"0".@"0".@"0");
            try w.uint(7, v.nonce);
        },
        .Validity => |v| {
            try w.uint(1, 4);
            if (v.max_epoch) |x| try w.uint(2, x);
            if (v.min_epoch) |x| try w.uint(3, x);
            if (v.min_timestamp) |x| try timestampMsg(w, 4, x);
            if (v.max_timestamp) |x| try timestampMsg(w, 5, x);
            try ro.str32(w, 6, &v.chain.@"0".@"0".@"0");
            try w.uint(7, v.nonce);
            if (v.allowed_proposers) |a| {
                const mm = try w.begin(8, 32);
                try w.uint(1, a.epoch);
                var u: std.ArrayList(u64) = .empty;
                _ = &u;
                // packed repeated uint32
                if (a.proposers.len > 0) {
                    var n: usize = 0;
                    for (a.proposers) |p| n += proto.varintLen(p);
                    try w.tag(2, proto.wire_len);
                    try w.varint(n);
                    for (a.proposers) |p| try w.varint(p);
                }
                try w.end(mm);
            }
        },
    }
    try w.end(m);
}

pub fn writeTransaction(arena: Allocator, w: *Writer, field: u32, m: Mask, raw: []const u8, td: types.TransactionData, tx_digest: *const [32]u8) Error!void {
    const mm = try w.begin(field, raw.len + 256);
    if (m.contains("bcs")) try bcsMsg(w, 1, "TransactionData", raw);
    if (m.contains("digest")) try ro.str32(w, 2, tx_digest);
    if (m.contains("version")) try w.uint(3, 1);
    const v1 = switch (td) {
        .V1 => |v| v,
    };
    if (m.contains("kind")) try writeKind(arena, w, v1.kind);
    if (m.contains("sender")) try ro.addrStr(w, 5, &v1.sender.@"0");
    if (m.contains("gas_payment")) {
        const g = try w.begin(6, 200);
        for (v1.gas_data.payment) |p| try objectRef(w, 1, &p.@"0".@"0".@"0", p.@"1".@"0", &p.@"2".@"0".@"0");
        try ro.addrStr(w, 2, &v1.gas_data.owner.@"0");
        try w.uint(3, v1.gas_data.price);
        try w.uint(4, v1.gas_data.budget);
        try w.end(g);
    }
    if (m.contains("expiration")) try writeExpiration(w, 7, v1.expiration);
    try w.end(mm);
}

// ---- transaction kind ----

fn tyStr(w: *Writer, field: u32, t: types.TypeInput) Error!void {
    var o = typestr.scratch();
    try typestr.typeInput(&o, t);
    try w.string(field, o.str());
}

fn writeArgument(w: *Writer, field: u32, a: types.Argument) proto.Error!void {
    const m = try w.begin(field, 12);
    switch (a) {
        .GasCoin => try w.uint(1, 1),
        .Input => |i| {
            try w.uint(1, 2);
            try w.uint(2, i);
        },
        .Result => |r| {
            try w.uint(1, 3);
            try w.uint(3, r);
        },
        .NestedResult => |r| {
            try w.uint(1, 3);
            try w.uint(3, r.@"0");
            try w.uint(4, r.@"1");
        },
    }
    try w.end(m);
}

fn writeInput(w: *Writer, field: u32, c: types.CallArg) Error!void {
    const m = try w.begin(field, 120);
    switch (c) {
        .Pure => |p| {
            try w.uint(1, 1);
            try w.bytes(2, p);
        },
        .Object => |o| switch (o) {
            .ImmOrOwnedObject => |r| {
                try w.uint(1, 2);
                try ro.addrStr(w, 3, &r.@"0".@"0".@"0");
                try w.uint(4, r.@"1".@"0");
                try ro.str32(w, 5, &r.@"2".@"0".@"0");
            },
            .SharedObject => |s| {
                try w.uint(1, 3);
                try ro.addrStr(w, 3, &s.id.@"0".@"0");
                try w.uint(4, s.initial_shared_version.@"0");
                try w.uint(6, @intFromBool(s.mutability == .Mutable));
                try w.uint(7, switch (s.mutability) {
                    .Immutable => 1,
                    .Mutable => 2,
                    .NonExclusiveWrite => 3,
                });
            },
            .Receiving => |r| {
                try w.uint(1, 4);
                try ro.addrStr(w, 3, &r.@"0".@"0".@"0");
                try w.uint(4, r.@"1".@"0");
                try ro.str32(w, 5, &r.@"2".@"0".@"0");
            },
        },
        .FundsWithdrawal => |f| {
            try w.uint(1, 5);
            const fm = try w.begin(8, 100);
            switch (f.reservation) {
                .MaxAmountU64 => |a| try w.uint(1, a),
            }
            var o = typestr.scratch();
            switch (f.type_arg) {
                .Balance => |t| try typestr.typeTag(&o, t),
            }
            try w.string(2, o.str());
            switch (f.withdraw_from) {
                .Sender => try w.uint(3, 1),
                .Sponsor => try w.uint(3, 2),
                .SenderAllowance => |sa| {
                    try w.uint(3, 3);
                    try ro.addrStr(w, 4, &sa.funder.@"0");
                    try ro.addrStr(w, 5, &sa.allowance.@"0".@"0");
                },
            }
            try w.end(fm);
        },
    }
    try w.end(m);
}

fn writeArgs(w: *Writer, field: u32, args: []const types.Argument) proto.Error!void {
    for (args) |a| try writeArgument(w, field, a);
}

fn writeDeps(w: *Writer, field: u32, deps: []const types.ObjectID) proto.Error!void {
    for (deps) |d| try ro.addrStr(w, field, &d.@"0".@"0");
}

fn writeCommand(w: *Writer, c: types.Command) Error!void {
    const outer = try w.begin(2, 100);
    switch (c) {
        .MoveCall => |mc| {
            const m = try w.begin(1, 120);
            try ro.addrStr(w, 1, &mc.package.@"0".@"0");
            try w.string(2, mc.module.@"0");
            try w.string(3, mc.function.@"0");
            for (mc.type_arguments) |t| try tyStr(w, 4, t);
            try writeArgs(w, 5, mc.arguments);
            try w.end(m);
        },
        .TransferObjects => |t| {
            const m = try w.begin(2, 40);
            try writeArgs(w, 1, t.@"0");
            try writeArgument(w, 2, t.@"1");
            try w.end(m);
        },
        .SplitCoins => |t| {
            const m = try w.begin(3, 40);
            try writeArgument(w, 1, t.@"0");
            try writeArgs(w, 2, t.@"1");
            try w.end(m);
        },
        .MergeCoins => |t| {
            const m = try w.begin(4, 40);
            try writeArgument(w, 1, t.@"0");
            try writeArgs(w, 2, t.@"1");
            try w.end(m);
        },
        .Publish => |t| {
            const m = try w.begin(5, 1024);
            for (t.@"0") |mod| try w.bytes(1, mod);
            try writeDeps(w, 2, t.@"1");
            try w.end(m);
        },
        .MakeMoveVec => |t| {
            const m = try w.begin(6, 60);
            if (t.@"0") |ty| try tyStr(w, 1, ty);
            try writeArgs(w, 2, t.@"1");
            try w.end(m);
        },
        .Upgrade => |t| {
            const m = try w.begin(7, 1024);
            for (t.@"0") |mod| try w.bytes(1, mod);
            try writeDeps(w, 2, t.@"1");
            try ro.addrStr(w, 3, &t.@"2".@"0".@"0");
            try writeArgument(w, 4, t.@"3");
            try w.end(m);
        },
    }
    try w.end(outer);
}

fn writePtb(w: *Writer, field: u32, p: types.ProgrammableTransaction) Error!void {
    const m = try w.begin(field, 512);
    for (p.inputs) |i| try writeInput(w, 1, i);
    for (p.commands) |c| try writeCommand(w, c);
    try w.end(m);
}

fn writeVersionAssignments(w: *Writer, field: u32, a: types.ConsensusDeterminedVersionAssignments) proto.Error!void {
    const m = try w.begin(field, 128);
    switch (a) {
        .CancelledTransactions => |list| {
            try w.uint(1, 1);
            for (list) |e| {
                const c = try w.begin(3, 100);
                try ro.str32(w, 1, &e.@"0".@"0".@"0");
                for (e.@"1") |va| {
                    const v = try w.begin(2, 80);
                    try ro.addrStr(w, 1, &va.@"0".@"0".@"0");
                    try w.uint(3, va.@"1".@"0");
                    try w.end(v);
                }
                try w.end(c);
            }
        },
        .CancelledTransactionsV2 => |list| {
            try w.uint(1, 2);
            for (list) |e| {
                const c = try w.begin(3, 100);
                try ro.str32(w, 1, &e.@"0".@"0".@"0");
                for (e.@"1") |va| {
                    const v = try w.begin(2, 80);
                    try ro.addrStr(w, 1, &va.@"0".@"0".@"0".@"0");
                    try w.uint(2, va.@"0".@"1".@"0");
                    try w.uint(3, va.@"1".@"0");
                    try w.end(v);
                }
                try w.end(c);
            }
        },
    }
    try w.end(m);
}

fn tsMsg(w: *Writer, field: u32, ms: u64) proto.Error!void {
    try timestampMsg(w, field, ms);
}

fn writeKind(arena: Allocator, w: *Writer, k: types.TransactionKind) Error!void {
    const m = try w.begin(4, 512);
    switch (k) {
        .ProgrammableTransaction => |p| {
            try w.uint(1, 1);
            try writePtb(w, 2, p);
        },
        .ChangeEpoch => |c| {
            try w.uint(1, 2);
            try writeChangeEpoch(w, 3, c);
        },
        .ConsensusCommitPrologue => |c| {
            try w.uint(1, 4);
            const mm = try w.begin(5, 40);
            try w.uint(1, c.epoch);
            try w.uint(2, c.round);
            try tsMsg(w, 3, c.commit_timestamp_ms);
            try w.end(mm);
        },
        .AuthenticatorStateUpdate => |a| {
            try w.uint(1, 5);
            const mm = try w.begin(6, 200);
            try w.uint(1, a.epoch);
            try w.uint(2, a.round);
            for (a.new_active_jwks) |j| {
                const jm = try w.begin(3, 200);
                const id = try w.begin(1, 60);
                try w.string(1, j.jwk_id.iss.@"0");
                try w.string(2, j.jwk_id.kid.@"0");
                try w.end(id);
                const jk = try w.begin(2, 600);
                try w.string(1, j.jwk.kty.@"0");
                try w.string(2, j.jwk.e.@"0");
                try w.string(3, j.jwk.n.@"0");
                try w.string(4, j.jwk.alg.@"0");
                try w.end(jk);
                try w.uint(3, j.epoch);
                try w.end(jm);
            }
            try w.uint(4, a.authenticator_obj_initial_shared_version.@"0");
            try w.end(mm);
        },
        .RandomnessStateUpdate => |r| {
            try w.uint(1, 7);
            const mm = try w.begin(8, 100);
            try w.uint(1, r.epoch);
            try w.uint(2, r.randomness_round.@"0");
            try w.bytes(3, r.random_bytes);
            try w.uint(4, r.randomness_obj_initial_shared_version.@"0");
            try w.end(mm);
        },
        .ConsensusCommitPrologueV2 => |c| {
            try w.uint(1, 8);
            const mm = try w.begin(5, 80);
            try w.uint(1, c.epoch);
            try w.uint(2, c.round);
            try tsMsg(w, 3, c.commit_timestamp_ms);
            try ro.str32(w, 4, &c.consensus_commit_digest.@"0".@"0");
            try w.end(mm);
        },
        .ConsensusCommitPrologueV3 => |c| {
            try w.uint(1, 9);
            const mm = try w.begin(5, 160);
            try w.uint(1, c.epoch);
            try w.uint(2, c.round);
            try tsMsg(w, 3, c.commit_timestamp_ms);
            try ro.str32(w, 4, &c.consensus_commit_digest.@"0".@"0");
            if (c.sub_dag_index) |x| try w.uint(5, x);
            try writeVersionAssignments(w, 6, c.consensus_determined_version_assignments);
            try w.end(mm);
        },
        .ConsensusCommitPrologueV4 => |c| {
            try w.uint(1, 10);
            const mm = try w.begin(5, 160);
            try w.uint(1, c.epoch);
            try w.uint(2, c.round);
            try tsMsg(w, 3, c.commit_timestamp_ms);
            try ro.str32(w, 4, &c.consensus_commit_digest.@"0".@"0");
            if (c.sub_dag_index) |x| try w.uint(5, x);
            try writeVersionAssignments(w, 6, c.consensus_determined_version_assignments);
            try ro.str32(w, 7, &c.additional_state_digest.@"0".@"0");
            try w.end(mm);
        },
        .ProgrammableSystemTransaction => |p| {
            try w.uint(1, 11);
            try writePtb(w, 2, p);
        },
        .Genesis => |g| {
            try w.uint(1, 3);
            const mm = try w.begin(4, 4096);
            var tree = try mask.Tree.parse(arena, "owner,object_type,has_public_transfer,contents,package");
            for (g.objects) |go| {
                const raw_obj = go.RawObject;
                const om = try w.begin(1, 1024);
                const obj: types.Object = .{ .data = raw_obj.data, .owner = raw_obj.owner, .previous_transaction = std.mem.zeroes(types.TransactionDigest), .storage_rebate = 0 };
                try ro.writeObjectBody(arena, w, tree.mask(), &.{}, obj);
                try w.end(om);
            }
            try w.end(mm);
        },
        .EndOfEpochTransaction => |txs| {
            try w.uint(1, 6);
            const mm = try w.begin(7, 4096);
            for (txs) |t| try writeEoe(w, t);
            try w.end(mm);
        },
    }
    try w.end(m);
}

fn writeEoe(w: *Writer, t: types.EndOfEpochTransactionKind) Error!void {
    const m = try w.begin(1, 256);
    switch (t) {
        .ChangeEpoch => |c| {
            try w.uint(1, 1);
            try writeChangeEpoch(w, 2, c);
        },
        .AuthenticatorStateCreate => try w.uint(1, 2),
        .AuthenticatorStateExpire => |e| {
            try w.uint(1, 3);
            const em = try w.begin(3, 24);
            try w.uint(1, e.min_epoch);
            try w.uint(2, e.authenticator_obj_initial_shared_version.@"0");
            try w.end(em);
        },
        .RandomnessStateCreate => try w.uint(1, 4),
        .DenyListStateCreate => try w.uint(1, 5),
        .BridgeStateCreate => |c| {
            try w.uint(1, 6);
            const hex = "0123456789abcdef";
            var buf: [8]u8 = undefined;
            for (c.@"0".@"0".@"0"[0..4], 0..) |b, i| {
                buf[2 * i] = hex[b >> 4];
                buf[2 * i + 1] = hex[b & 15];
            }
            try w.string(5, &buf);
        },
        .BridgeCommitteeInit => |v| {
            try w.uint(1, 7);
            try w.uint(6, v.@"0");
        },
        .StoreExecutionTimeObservations => |o| {
            try w.uint(1, 8);
            const om = try w.begin(4, 4096);
            switch (o) {
                .V1 => |entries| {
                    try w.uint(1, 1);
                    for (entries) |e| {
                        const em = try w.begin(2, 512);
                        const key = e.@"0";
                        try w.uint(1, switch (key) {
                            .MoveEntryPoint => 1,
                            .TransferObjects => 2,
                            .SplitCoins => 3,
                            .MergeCoins => 4,
                            .Publish => 5,
                            .MakeMoveVec => 6,
                            .Upgrade => 7,
                        });
                        switch (key) {
                            .MoveEntryPoint => |mp| {
                                const cm = try w.begin(2, 256);
                                try ro.addrStr(w, 1, &mp.package.@"0".@"0");
                                try w.string(2, mp.module.@"0");
                                try w.string(3, mp.function.@"0");
                                for (mp.type_arguments) |ta| {
                                    var o2 = typestr.scratch();
                                    try typestr.typeInput(&o2, ta);
                                    try w.string(4, o2.str());
                                }
                                try w.end(cm);
                            },
                            else => {},
                        }
                        for (e.@"1") |vo| {
                            const vm = try w.begin(3, 130);
                            try w.bytes(1, &vo.@"0".@"0");
                            const dm = try w.begin(2, 16);
                            if (vo.@"1".secs != 0) try w.uint(1, vo.@"1".secs);
                            if (vo.@"1".nanos != 0) try w.uint(2, vo.@"1".nanos);
                            try w.end(dm);
                            try w.end(vm);
                        }
                        try w.end(em);
                    }
                },
            }
            try w.end(om);
        },
        .AccumulatorRootCreate => try w.uint(1, 9),
        .CoinRegistryCreate => try w.uint(1, 10),
        .DisplayRegistryCreate => try w.uint(1, 11),
        .AddressAliasStateCreate => try w.uint(1, 12),
        .WriteAccumulatorStorageCost => |c| {
            try w.uint(1, 13);
            try w.uint(7, c.storage_cost);
        },
        .ForwardingAddressRegistryCreate => try w.uint(1, 14),
    }
    try w.end(m);
}

fn writeChangeEpoch(w: *Writer, field: u32, c: types.ChangeEpoch) Error!void {
    const m = try w.begin(field, 512);
    try w.uint(1, c.epoch);
    try w.uint(2, c.protocol_version.@"0");
    try w.uint(3, c.storage_charge);
    try w.uint(4, c.computation_charge);
    try w.uint(5, c.storage_rebate);
    try w.uint(6, c.non_refundable_storage_fee);
    try timestampMsg(w, 7, c.epoch_start_timestamp_ms);
    for (c.system_packages) |sp| {
        const sm = try w.begin(8, 4096);
        try w.uint(1, sp.@"0".@"0");
        for (sp.@"1") |mod| try w.bytes(2, mod);
        try writeDeps(w, 3, sp.@"2");
        try w.end(sm);
    }
    try w.end(m);
}

// ---- effects ----

const Ref = struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest };

const Change = struct {
    id: [32]u8,
    input_state: u8 = 0,
    input_version: ?u64 = null,
    input_digest: ?[32]u8 = null,
    input_owner: ?types.Owner = null,
    output_state: u8 = 0,
    output_version: ?u64 = null,
    output_digest: ?[32]u8 = null,
    output_owner: ?types.Owner = null,
    accumulator: ?types.AccumulatorWriteV1 = null,
    id_operation: u8 = 0,
    object_type: ?[]const u8 = null,

    fn write(c: *const Change, w: *Writer, field: u32) Error!void {
        const m = try w.begin(field, 250);
        try ro.addrStr(w, 1, &c.id);
        try w.uint(2, c.input_state);
        if (c.input_version) |v| try w.uint(3, v);
        if (c.input_digest) |*d| try ro.str32(w, 4, d);
        if (c.input_owner) |o| try ro.writeOwner(w, 5, o);
        try w.uint(6, c.output_state);
        if (c.output_version) |v| try w.uint(7, v);
        if (c.output_digest) |*d| try ro.str32(w, 8, d);
        if (c.output_owner) |o| try ro.writeOwner(w, 9, o);
        try w.uint(10, c.id_operation);
        if (c.object_type) |t| try w.string(11, t);
        if (c.accumulator) |a| try writeAccumulator(w, 12, a);
        try w.end(m);
    }
};

fn writeAccumulator(w: *Writer, field: u32, a: types.AccumulatorWriteV1) Error!void {
    const m = try w.begin(field, 150);
    try ro.addrStr(w, 1, &a.address.address.@"0");
    var o = typestr.scratch();
    try typestr.typeTag(&o, a.address.ty);
    try w.string(2, o.str());
    try w.uint(3, switch (a.operation) {
        .Merge => 1,
        .Split => 2,
    });
    switch (a.value) {
        .Integer => |v| try w.uint(5, v),
        else => {}, // Rust leaves tuple and event-digest values unset (TODO upstream)
    }
    try w.end(m);
}

const IdOp = enum(u8) { none = 1, created = 2, deleted = 3 };

fn ownerFrom(o: types.Owner) types.Owner {
    return o;
}

fn changeFromV2(id: [32]u8, c: types.EffectsObjectChange) Change {
    var out: Change = .{ .id = id };
    switch (c.input_state) {
        .NotExist => out.input_state = 1,
        .Exist => |e| {
            out.input_state = 2;
            out.input_version = e.@"0".@"0".@"0";
            out.input_digest = e.@"0".@"1".@"0".@"0";
            out.input_owner = e.@"1";
        },
    }
    switch (c.output_state) {
        .NotExist => out.output_state = 1,
        .ObjectWrite => |e| {
            out.output_state = 2;
            out.output_digest = e.@"0".@"0".@"0";
            out.output_owner = e.@"1";
        },
        .PackageWrite => |e| {
            out.output_state = 3;
            out.output_version = e.@"0".@"0";
            out.output_digest = e.@"1".@"0".@"0";
        },
        .AccumulatorWriteV1 => |a| {
            out.output_state = 4;
            out.accumulator = a;
        },
    }
    out.id_operation = switch (c.id_operation) {
        .None => 1,
        .Created => 2,
        .Deleted => 3,
    };
    return out;
}

const Unchanged = struct {
    kind: u8,
    id: [32]u8,
    version: ?u64 = null,
    digest: ?[32]u8 = null,
    object_type: ?[]const u8 = null,

    fn write(u: *const Unchanged, w: *Writer, field: u32) Error!void {
        const m = try w.begin(field, 120);
        try w.uint(1, u.kind);
        try ro.addrStr(w, 2, &u.id);
        if (u.version) |v| try w.uint(3, v);
        if (u.digest) |*d| try ro.str32(w, 4, d);
        if (u.object_type) |t| try w.string(5, t);
        try w.end(m);
    }
};

fn writeGasUsed(w: *Writer, g: types.GasCostSummary) proto.Error!void {
    try rc.writeGasCostSummary(w, 6, g);
}

fn annotateChange(arena: Allocator, in: *const Input, c: *Change) Error!void {
    const set = in.objects orelse return;
    const v = c.input_version orelse c.output_version orelse 0;
    c.object_type = try set.typeString(arena, &c.id, v);
}

fn annotateUnchanged(arena: Allocator, in: *const Input, u: *Unchanged) Error!void {
    const set = in.objects orelse return;
    u.object_type = try set.typeString(arena, &u.id, u.version orelse 0);
}

pub fn writeEffects(arena: Allocator, w: *Writer, field: u32, m: Mask, raw: []const u8, eff: types.TransactionEffects, in: *const Input) Error!void {
    const mm = try w.begin(field, raw.len + 256);
    if (m.contains("bcs")) try bcsMsg(w, 1, "TransactionEffects", raw);
    if (m.contains("digest")) try ro.str32(w, 2, if (in.effects_digest) |d| d else &types.digest.effectsDigest(raw));
    switch (eff) {
        .V1 => |v| try writeEffectsV1(arena, w, m, v, in),
        .V2 => |v| try writeEffectsV2(arena, w, m, v, in),
    }
    if (m.contains("unchanged_loaded_runtime_objects")) for (in.loaded) |r| {
        const om = try w.begin(15, 60);
        try ro.addrStr(w, 1, &r.id);
        try w.uint(2, r.version);
        try w.end(om);
    };
    try w.end(mm);
}

fn writeEffectsV2(arena: Allocator, w: *Writer, m: Mask, v: types.TransactionEffectsV2, in: *const Input) Error!void {
    if (m.contains("version")) try w.uint(3, 2);
    if (m.contains("status")) try exec_error.writeStatusClever(arena, w, 4, v.status, in.clever);
    if (m.contains("epoch")) try w.uint(5, v.executed_epoch);
    if (m.contains("gas_used")) try writeGasUsed(w, v.gas_used);
    if (m.contains("transaction_digest")) try ro.str32(w, 7, &v.transaction_digest.@"0".@"0");
    const lamport = v.lamport_version.@"0";
    // gas_object (8)
    if (m.contains("gas_object")) if (v.gas_object_index) |idx| {
        if (idx < v.changed_objects.len) {
            const e = v.changed_objects[idx];
            var c = changeFromV2(e.@"0".@"0".@"0", e.@"1");
            if (c.output_digest != null and c.output_version == null) c.output_version = lamport;
            try c.write(w, 8);
        }
    };
    if (m.contains("events_digest")) if (v.events_digest) |d| try ro.str32(w, 9, &d.@"0".@"0");
    if (m.contains("dependencies")) for (v.dependencies) |d| try ro.str32(w, 10, &d.@"0".@"0");
    if (m.contains("lamport_version")) try w.uint(11, lamport);
    if (m.contains("changed_objects")) for (v.changed_objects) |e| {
        var c = changeFromV2(e.@"0".@"0".@"0", e.@"1");
        if (c.output_digest != null and c.output_version == null) c.output_version = lamport;
        try annotateChange(arena, in, &c);
        try c.write(w, 12);
    };
    if (m.contains("unchanged_consensus_objects")) for (v.unchanged_consensus_objects) |e| {
        var u: Unchanged = .{ .kind = 0, .id = e.@"0".@"0".@"0" };
        switch (e.@"1") {
            .ReadOnlyRoot => |r| {
                u.kind = 1;
                u.version = r.@"0".@"0";
                u.digest = r.@"1".@"0".@"0";
            },
            .MutateConsensusStreamEnded => |ver| {
                u.kind = 2;
                u.version = ver.@"0";
            },
            .ReadConsensusStreamEnded => |ver| {
                u.kind = 3;
                u.version = ver.@"0";
            },
            .Cancelled => |ver| {
                u.kind = 4;
                u.version = ver.@"0";
            },
            .PerEpochConfig => u.kind = 5,
        }
        try annotateUnchanged(arena, in, &u);
        try u.write(w, 13);
    };
    if (m.contains("auxiliary_data_digest")) if (v.aux_data_digest) |d| try ro.str32(w, 14, &d.@"0".@"0");
}

fn writeEffectsV1(arena: Allocator, w: *Writer, m: Mask, v: types.TransactionEffectsV1, in: *const Input) Error!void {
    if (m.contains("version")) try w.uint(3, 1);
    if (m.contains("status")) try exec_error.writeStatusClever(arena, w, 4, v.status, in.clever);
    if (m.contains("epoch")) try w.uint(5, v.executed_epoch);
    if (m.contains("gas_used")) try writeGasUsed(w, v.gas_used);
    if (m.contains("transaction_digest")) try ro.str32(w, 7, &v.transaction_digest.@"0".@"0");
    const need_changes = m.contains("changed_objects") or m.contains("unchanged_consensus_objects") or m.contains("gas_object");
    var changes: std.ArrayList(Change) = .empty;
    var unchanged: std.ArrayList(Unchanged) = .empty;
    if (need_changes) {
        for (v.created) |e| try changes.append(arena, .{ .id = e.@"0".@"0".@"0".@"0", .input_state = 1, .output_state = 2, .output_version = e.@"0".@"1".@"0", .output_digest = e.@"0".@"2".@"0".@"0", .output_owner = e.@"1", .id_operation = 2 });
        for (v.mutated) |e| try changes.append(arena, .{ .id = e.@"0".@"0".@"0".@"0", .input_state = 2, .output_state = 2, .output_version = e.@"0".@"1".@"0", .output_digest = e.@"0".@"2".@"0".@"0", .output_owner = e.@"1", .id_operation = 1 });
        for (v.unwrapped) |e| try changes.append(arena, .{ .id = e.@"0".@"0".@"0".@"0", .input_state = 1, .output_state = 2, .output_version = e.@"0".@"1".@"0", .output_digest = e.@"0".@"2".@"0".@"0", .output_owner = e.@"1", .id_operation = 1 });
        for (v.deleted) |e| try changes.append(arena, .{ .id = e.@"0".@"0".@"0", .input_state = 2, .output_state = 1, .output_version = e.@"1".@"0", .output_digest = e.@"2".@"0".@"0", .id_operation = 3 });
        for (v.unwrapped_then_deleted) |e| try changes.append(arena, .{ .id = e.@"0".@"0".@"0", .input_state = 1, .output_state = 1, .output_version = e.@"1".@"0", .output_digest = e.@"2".@"0".@"0", .id_operation = 3 });
        for (v.wrapped) |e| try changes.append(arena, .{ .id = e.@"0".@"0".@"0", .input_state = 2, .output_state = 1, .output_version = e.@"1".@"0", .output_digest = e.@"2".@"0".@"0", .id_operation = 3 });
        for (v.modified_at_versions) |e| {
            for (changes.items) |*c| if (std.mem.eql(u8, &c.id, &e.@"0".@"0".@"0")) {
                c.input_version = e.@"1".@"0";
                break;
            };
        }
        for (v.shared_objects) |e| {
            const id = e.@"0".@"0".@"0";
            var found = false;
            for (changes.items) |*c| if (std.mem.eql(u8, &c.id, &id)) {
                c.input_version = e.@"1".@"0";
                c.input_digest = e.@"2".@"0".@"0";
                found = true;
                break;
            };
            if (!found) try unchanged.append(arena, .{ .kind = 1, .id = id, .version = e.@"1".@"0", .digest = e.@"2".@"0".@"0" });
        }
    }
    if (m.contains("gas_object")) {
        const gid = v.gas_object.@"0".@"0".@"0".@"0";
        for (changes.items) |*c| if (std.mem.eql(u8, &c.id, &gid)) {
            try c.write(w, 8);
            break;
        };
    }
    if (m.contains("events_digest")) if (v.events_digest) |d| try ro.str32(w, 9, &d.@"0".@"0");
    if (m.contains("dependencies")) for (v.dependencies) |d| try ro.str32(w, 10, &d.@"0".@"0");
    if (m.contains("lamport_version")) try w.uint(11, lamportV1(v));
    if (m.contains("changed_objects")) for (changes.items) |*c| {
        try annotateChange(arena, in, c);
        try c.write(w, 12);
    };
    if (m.contains("unchanged_consensus_objects")) for (unchanged.items) |*u| {
        try annotateUnchanged(arena, in, u);
        try u.write(w, 13);
    };
}

/// TransactionEffectsV1::lamport_version = max(modified_at_versions) + 1 (sui-types
/// effects/effects_v1.rs).
fn lamportV1(v: types.TransactionEffectsV1) u64 {
    var max: u64 = 0;
    for (v.modified_at_versions) |e| max = @max(max, e.@"1".@"0");
    return max + 1;
}

pub fn writeEvents(w: *Writer, field: u32, m: Mask, raw: []const u8, ev: types.TransactionEvents, digest: ?*const [32]u8) Error!void {
    return writeEventsCtx(undefined, w, field, m, raw, ev, digest, null);
}

/// `render_events_to_proto` / `annotate_checkpoint_transaction`: with `json` from `ctx`.
pub fn writeEventsCtx(arena: Allocator, w: *Writer, field: u32, m: Mask, raw: []const u8, ev: types.TransactionEvents, digest: ?*const [32]u8, ctx: ?*const ro.Ctx) Error!void {
    const mm = try w.begin(field, raw.len + 128);
    if (m.contains("bcs")) try bcsMsg(w, 1, "TransactionEvents", raw);
    if (m.contains("digest")) try ro.str32(w, 2, if (digest) |d| d else &types.digest.eventsDigest(raw));
    if (m.subtree("events")) |em| {
        for (ev.data) |e| try writeEventCtx(arena, w, 3, em, e, ctx);
    }
    try w.end(mm);
}

/// One `Event` message (`render_event_to_proto`) as field `field`: the unit ListEvents and the
/// subscription streams render. `json` needs `ctx` (its resolver and optional shared budget).
pub fn writeEventCtx(arena: Allocator, w: *Writer, field: u32, em: Mask, e: types.Event, ctx: ?*const ro.Ctx) Error!void {
    const e_m = try w.begin(field, e.contents.len + 200);
    if (em.contains("package_id")) try ro.addrStr(w, 1, &e.package_id.@"0".@"0");
    if (em.contains("module")) try w.string(2, e.transaction_module.str());
    if (em.contains("sender")) try ro.addrStr(w, 3, &e.sender.@"0");
    var o = typestr.scratch();
    try typestr.structTag(&o, e.type_);
    if (em.contains("event_type")) try w.string(4, o.str());
    if (em.contains("contents")) {
        const b = try w.begin(5, e.contents.len + o.len + 8);
        try w.string(1, o.str());
        try w.bytes(2, e.contents);
        try w.end(b);
    }
    if (em.contains("json")) if (ctx) |c| {
        if (try c.json(arena, &e.type_, e.contents)) |v| try pbvalue.write(w, 6, &v);
    };
    try w.end(e_m);
}

/// `ExecutedTransaction` message body for mask `m` (fields 1-5; the caller adds 6-8).
pub fn writeExecuted(arena: Allocator, w: *Writer, m: Mask, in: Input) Error!void {
    const td = try bcs.decode(types.TransactionData, arena, in.transaction);
    const eff = if (in.decoded_effects) |e| e else try bcs.decode(types.TransactionEffects, arena, in.effects);
    // The effects name the transaction and its events by digest (valid data: they equal the
    // hashes); Rust's merge also takes the transaction digest from the effects.
    const tx_digest: [32]u8 = switch (eff) {
        inline else => |v| v.transaction_digest.@"0".@"0",
    };
    const ev_digest: ?[32]u8 = switch (eff) {
        inline else => |v| if (v.events_digest) |d| d.@"0".@"0" else null,
    };
    if (m.contains("digest")) try ro.str32(w, 1, &tx_digest);
    if (m.subtree("transaction")) |sm| try writeTransaction(arena, w, 2, sm, in.transaction, td, &tx_digest);
    if (m.subtree("signatures")) |sm| for (in.signatures) |s| try rsig.writeUserSignature(w, 3, arena, sm, s);
    if (m.subtree("effects")) |sm| try writeEffects(arena, w, 4, sm, in.effects, eff, &in);
    if (m.subtree("events")) |sm| if (in.events) |eb| {
        const ev = try bcs.decode(types.TransactionEvents, arena, eb);
        try writeEventsCtx(arena, w, 5, sm, eb, ev, if (ev_digest) |*d| d else null, in.render);
    };
}
