//! sui.rpc.v2 `Checkpoint` proto -> checkpoint blob `0x01 ++ BCS(CheckpointData)`.
//!
//! The proto is what Mysten's archive stores (`<seq>.binpb.zst`, after zstd) and what a node's
//! `GetCheckpoint` returns with the full read mask. The result is byte-equal to what sui-types
//! produces with `full_checkpoint_content::Checkpoint::try_from(&proto)` followed by
//! `CheckpointData::from(checkpoint)` and `bcs::to_bytes` (zui-dumper `convert`), proven on the
//! corpus by suite `node-convert`:
//!
//!  * summary, contents, transaction data, effects, events and objects are the proto's `bcs`
//!    bytes (canonical BCS, so Rust's decode + re-encode gives the same bytes; the blob is
//!    validated again by the strict indexer before anything uses it);
//!  * the certificate is `AuthorityStrongQuorumSignInfo { epoch, signature (48 bytes),
//!    signers_map (bitmap bytes) }` from `ValidatorAggregatedSignature`;
//!  * each transaction is `SenderSignedData` = `[1] ++ intent (0,0,0) ++ TransactionData ++
//!    user signatures`, the signatures taken from the contents (`into_iter_with_signatures`);
//!  * input objects follow `effects.modified_at_versions()` and output objects follow
//!    `effects.all_changed_objects()` (mutated, created, unwrapped), each looked up in the
//!    checkpoint's object set by (id, version); absent keys are skipped, as in Rust.
//!
//! Protobuf reading follows prost: a scalar or bytes field seen twice keeps the last value, and a
//! message field seen twice is merged (its occurrences are applied in order).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const exec = @import("exec");

pub const Error = error{ Malformed, MissingField, BadSignatureLength, TooManyTransactions } ||
    bcs.DecodeError || std.mem.Allocator.Error;

// ------------------------------------------------------------------ protobuf reading

const Field = struct { number: u32, wire: u3, varint: u64 = 0, data: []const u8 = &.{} };

const Pb = struct {
    buf: []const u8,
    pos: usize = 0,

    fn varint(r: *Pb) Error!u64 {
        var v: u64 = 0;
        var shift: u7 = 0;
        while (true) {
            if (r.pos >= r.buf.len or shift > 63) return error.Malformed;
            const b = r.buf[r.pos];
            r.pos += 1;
            v |= @as(u64, b & 0x7f) << @intCast(shift);
            if (b < 0x80) return v;
            shift += 7;
        }
    }

    fn take(r: *Pb, n: u64) Error![]const u8 {
        if (n > r.buf.len - r.pos) return error.Malformed;
        const s = r.buf[r.pos..][0..@intCast(n)];
        r.pos += @intCast(n);
        return s;
    }

    /// Next field, or null at the end. Groups (wire 3/4) are skipped like prost skips unknown
    /// groups; none of the fields read here is a group.
    fn next(r: *Pb) Error!?Field {
        while (true) {
            if (r.pos == r.buf.len) return null;
            const k = try r.varint();
            const number = k >> 3;
            if (number == 0 or number > 0x1fffffff) return error.Malformed;
            const wire: u3 = @truncate(k);
            var f: Field = .{ .number = @intCast(number), .wire = wire };
            switch (wire) {
                0 => f.varint = try r.varint(),
                1 => f.data = try r.take(8),
                2 => f.data = try r.take(try r.varint()),
                5 => f.data = try r.take(4),
                3 => {
                    try r.skipGroup(@intCast(number), 0);
                    continue;
                },
                else => return error.Malformed,
            }
            return f;
        }
    }

    fn skipGroup(r: *Pb, number: u32, depth: u32) Error!void {
        if (depth > 100) return error.Malformed;
        while (true) {
            const k = try r.varint();
            const n = k >> 3;
            const wire: u3 = @truncate(k);
            switch (wire) {
                0 => _ = try r.varint(),
                1 => _ = try r.take(8),
                2 => _ = try r.take(try r.varint()),
                5 => _ = try r.take(4),
                3 => try r.skipGroup(@intCast(n), depth + 1),
                4 => {
                    if (n != number) return error.Malformed;
                    return;
                },
                else => return error.Malformed,
            }
        }
    }
};

fn expectLen(f: Field) Error![]const u8 {
    if (f.wire != 2) return error.Malformed;
    return f.data;
}

/// `Bcs { name = 1; value = 2 }`: applies one occurrence (merge semantics) into `value`.
fn mergeBcs(value: *?[]const u8, msg: []const u8) Error!void {
    var r: Pb = .{ .buf = msg };
    while (try r.next()) |f| {
        if (f.number == 2) value.* = try expectLen(f);
    }
}

/// A message whose field 1 is a `Bcs` (CheckpointSummary, CheckpointContents, Transaction,
/// TransactionEffects, TransactionEvents, Object).
fn mergeBcsHolder(value: *?[]const u8, msg: []const u8) Error!void {
    var r: Pb = .{ .buf = msg };
    while (try r.next()) |f| {
        if (f.number == 1) try mergeBcs(value, try expectLen(f));
    }
}

const Sig = struct {
    epoch: u64 = 0,
    signature: []const u8 = &.{},
    bitmap: []const u8 = &.{},
};

fn mergeSig(s: *Sig, msg: []const u8) Error!void {
    var r: Pb = .{ .buf = msg };
    while (try r.next()) |f| switch (f.number) {
        1 => {
            if (f.wire != 0) return error.Malformed;
            s.epoch = f.varint;
        },
        2 => s.signature = try expectLen(f),
        3 => s.bitmap = try expectLen(f),
        else => {},
    };
}

const Tx = struct {
    data: ?[]const u8 = null,
    effects: ?[]const u8 = null,
    /// The `events` message is present (Rust: `events_opt()`), and its bcs.
    has_events: bool = false,
    events: ?[]const u8 = null,
    /// `effects.unchanged_loaded_runtime_objects` (TransactionEffects field 15): ObjectReference
    /// messages, appended across merged occurrences like prost's repeated fields.
    loaded: std.ArrayList([]const u8) = .empty,
    /// `signatures[].bcs.value` (GenericSignature bytes) when the source rendered them: the
    /// serving node's stored order (see `txSignatures`).
    sigs: std.ArrayList([]const u8) = .empty,
};

fn mergeTx(arena: std.mem.Allocator, t: *Tx, msg: []const u8) Error!void {
    var r: Pb = .{ .buf = msg };
    while (try r.next()) |f| switch (f.number) {
        2 => try mergeBcsHolder(&t.data, try expectLen(f)),
        4 => {
            const m = try expectLen(f);
            try mergeBcsHolder(&t.effects, m);
            var er: Pb = .{ .buf = m };
            while (try er.next()) |ef| if (ef.number == 15) try t.loaded.append(arena, try expectLen(ef));
        },
        5 => {
            t.has_events = true;
            try mergeBcsHolder(&t.events, try expectLen(f));
        },
        3 => {
            var v: ?[]const u8 = null;
            try mergeBcsHolder(&v, try expectLen(f));
            try t.sigs.append(arena, v orelse return error.MissingField);
        },
        else => {},
    };
}

/// Field-level view of a `Checkpoint` proto. Repeated fields are kept as lists of slices.
pub const Parsed = struct {
    seq: ?u64 = null,
    summary: ?[]const u8 = null,
    sig: Sig = .{},
    has_sig: bool = false,
    contents: ?[]const u8 = null,
    txs: std.ArrayList(Tx) = .empty,
    objects: std.ArrayList([]const u8) = .empty,
};

pub fn parse(arena: std.mem.Allocator, proto: []const u8) Error!Parsed {
    var p: Parsed = .{};
    var r: Pb = .{ .buf = proto };
    while (try r.next()) |f| switch (f.number) {
        1 => {
            if (f.wire != 0) return error.Malformed;
            p.seq = f.varint;
        },
        3 => try mergeBcsHolder(&p.summary, try expectLen(f)),
        4 => {
            p.has_sig = true;
            try mergeSig(&p.sig, try expectLen(f));
        },
        5 => try mergeBcsHolder(&p.contents, try expectLen(f)),
        6 => {
            var t: Tx = .{};
            try mergeTx(arena, &t, try expectLen(f));
            try p.txs.append(arena, t);
        },
        7 => {
            // ObjectSet { repeated Object objects = 1 }
            var o: Pb = .{ .buf = try expectLen(f) };
            while (try o.next()) |of| {
                if (of.number != 1) continue;
                var v: ?[]const u8 = null;
                try mergeBcsHolder(&v, try expectLen(of));
                try p.objects.append(arena, v orelse return error.MissingField);
            }
        },
        else => {},
    };
    return p;
}

// ------------------------------------------------------------------ BCS writing

fn putUleb(out: *std.ArrayList(u8), gpa: std.mem.Allocator, v: u64) !void {
    var x = v;
    while (true) {
        const b: u8 = @truncate(x & 0x7f);
        x >>= 7;
        if (x == 0) {
            try out.append(gpa, b);
            return;
        }
        try out.append(gpa, b | 0x80);
    }
}

/// Byte ranges of each transaction's user signatures inside the contents bytes, already in the
/// `Vec<GenericSignature>` encoding a `SenderSignedTransaction` uses.
pub const SigList = struct {
    /// V1: the contents' own `Vec<GenericSignature>` bytes. V2: the signatures without their
    /// alias versions, so the vector is rebuilt (`count` then each signature's bytes).
    raw: ?[]const u8 = null,
    parts: []const []const u8 = &.{},
};

/// Whether a transaction's own signature list (`SenderSignedData.tx_signatures`) comes from the
/// source's per-transaction `signatures` rather than from the contents. sui-node 1.83.1 serves
/// `signatures` from its stored transaction (`render_executed_transaction`, `tx_signatures()`),
/// which keeps the order the transaction was submitted with: state sync passes peers' stored
/// transactions through (`VersionedFullCheckpointContents`), and so does a node's checkpoint
/// stream (`data_ingestion_handler.rs`: `tx.tx_signatures()`). The contents' `user_signatures`
/// are consensus's normalised order (since protocol 110: `tx.aliases()` order, sender then
/// sponsor), which is all Mysten's archive carries (its protos have no per-transaction
/// `signatures`; Rust's `TryFrom<&proto::Checkpoint>` zips the contents' lists in). No digest
/// covers this order, so the source's list is taken only when it holds exactly the contents'
/// signatures (as a multiset, which the certified contents digest does cover).
fn txSignatures(arena: std.mem.Allocator, sigs: []const []const u8, s: SigList) Error!bool {
    if (sigs.len == 0) return false;
    var cs: std.ArrayList([]const u8) = .empty;
    if (s.raw) |raw| {
        var r = bcs.Reader.init(raw);
        const k = try r.length();
        for (0..k) |_| try cs.append(arena, try r.bytes(try r.length()));
    } else for (s.parts) |part| {
        var r = bcs.Reader.init(part);
        try cs.append(arena, try r.bytes(try r.length()));
    }
    if (cs.items.len != sigs.len) return false;
    if (cs.items.len > 64) return false;
    var used: u64 = 0;
    outer: for (sigs) |sig| {
        for (cs.items, 0..) |c, i| {
            const bit = @as(u64, 1) << @intCast(i);
            if (used & bit == 0 and std.mem.eql(u8, c, sig)) {
                used |= bit;
                continue :outer;
            }
        }
        return false;
    }
    return true;
}

/// ExecutionDigests { transaction, effects }: two digests, each a length-prefixed 32 bytes.
fn skipExecutionDigests(r: *bcs.Reader) Error!void {
    for (0..2) |_| {
        if (try r.length() != 32) return error.Malformed;
        _ = try r.bytes(32);
    }
}

pub fn txSignaturesForTest(arena: std.mem.Allocator, sigs: []const []const u8, s: SigList) Error!bool {
    return txSignatures(arena, sigs, s);
}

pub fn contentSignaturesForTest(arena: std.mem.Allocator, contents: []const u8) Error![]SigList {
    return contentSignatures(arena, contents);
}

fn contentSignatures(arena: std.mem.Allocator, contents: []const u8) Error![]SigList {
    var r = bcs.Reader.init(contents);
    const tag = try r.uleb32();
    switch (tag) {
        0 => {
            // V1 { transactions: Vec<ExecutionDigests>, user_signatures: Vec<Vec<GenericSignature>> }
            const n = try r.length();
            for (0..n) |_| try skipExecutionDigests(&r);
            const m = try r.length();
            if (m > r.remaining()) return error.Malformed;
            const out = try arena.alloc(SigList, m);
            for (out) |*s| {
                const start = r.pos();
                const k = try r.length();
                for (0..k) |_| _ = try r.bytes(try r.length());
                s.* = .{ .raw = contents[start..r.pos()] };
            }
            return out[0..@min(n, m)];
        },
        1 => {
            // V2 { transactions: Vec<CheckpointTransactionContents { digest, user_signatures:
            //      Vec<(GenericSignature, Option<SequenceNumber>)> }> }
            const n = try r.length();
            if (n > r.remaining()) return error.Malformed;
            const out = try arena.alloc(SigList, n);
            for (out) |*s| {
                try skipExecutionDigests(&r);
                const k = try r.length();
                if (k > r.remaining()) return error.Malformed;
                const parts = try arena.alloc([]const u8, k);
                for (parts) |*part| {
                    const start = r.pos();
                    _ = try r.bytes(try r.length());
                    part.* = contents[start..r.pos()];
                    switch (try r.int(u8)) {
                        0 => {},
                        1 => _ = try r.int(u64),
                        else => return error.InvalidEnumTag,
                    }
                }
                s.* = .{ .parts = parts };
            }
            return out;
        },
        else => return error.InvalidEnumTag,
    }
}

const Key = exec.objects.Key;

/// Input keys (`modified_at_versions`) and output keys (`all_changed_objects`) of one effects.
fn effectKeys(arena: std.mem.Allocator, raw: []const u8, ins: *std.ArrayList(Key), outs: *std.ArrayList(Key)) Error!void {
    ins.clearRetainingCapacity();
    outs.clearRetainingCapacity();
    const fx = try bcs.decode(types.TransactionEffects, arena, raw);
    switch (fx) {
        .V1 => |*v| {
            for (v.modified_at_versions) |m| {
                const id = m[0].@"0".@"0";
                const dropped = for (v.unwrapped_then_deleted) |d| {
                    if (std.mem.eql(u8, &d[0].@"0".@"0", &id)) break true;
                } else false;
                if (!dropped) try ins.append(arena, .{ .id = id, .version = m[1].@"0" });
            }
            inline for (.{ "mutated", "created", "unwrapped" }) |list| {
                for (@field(v, list)) |e| try outs.append(arena, .{ .id = e[0][0].@"0".@"0", .version = e[0][1].@"0" });
            }
        },
        .V2 => |*v| {
            const lamport = v.lamport_version.@"0";
            for (v.changed_objects) |c| switch (c[1].input_state) {
                .Exist => |e| try ins.append(arena, .{ .id = c[0].@"0".@"0", .version = e[0][0].@"0" }),
                .NotExist => {},
            };
            // mutated: input exists, output written (object or package)
            for (v.changed_objects) |c| {
                if (c[1].input_state != .Exist) continue;
                switch (c[1].output_state) {
                    .ObjectWrite => try outs.append(arena, .{ .id = c[0].@"0".@"0", .version = lamport }),
                    .PackageWrite => |pw| try outs.append(arena, .{ .id = c[0].@"0".@"0", .version = pw[0].@"0" }),
                    else => {},
                }
            }
            // created: no input, written, id created
            for (v.changed_objects) |c| {
                if (c[1].input_state != .NotExist or c[1].id_operation != .Created) continue;
                switch (c[1].output_state) {
                    .ObjectWrite => try outs.append(arena, .{ .id = c[0].@"0".@"0", .version = lamport }),
                    .PackageWrite => |pw| try outs.append(arena, .{ .id = c[0].@"0".@"0", .version = pw[0].@"0" }),
                    else => {},
                }
            }
            // unwrapped: no input, object written, id operation none
            for (v.changed_objects) |c| {
                if (c[1].input_state != .NotExist or c[1].id_operation != .None) continue;
                if (c[1].output_state == .ObjectWrite) try outs.append(arena, .{ .id = c[0].@"0".@"0", .version = lamport });
            }
        },
    }
}

/// Converts one `Checkpoint` proto into a checkpoint blob appended to `out` (cleared first).
/// `arena` holds temporaries only. Returns the checkpoint's sequence number from the summary.
pub fn protoToChk(gpa: std.mem.Allocator, arena: std.mem.Allocator, proto: []const u8, out: *std.ArrayList(u8)) Error!u64 {
    return protoToChkAux(gpa, arena, proto, out, null);
}

/// `protoToChk`, plus (when `aux` is given) the proto's side data the blob cannot hold (`Aux`):
/// each transaction's unchanged_loaded_runtime_objects and every object of the object set that
/// the blob does not carry as an input or output object.
pub fn protoToChkAux(gpa: std.mem.Allocator, arena: std.mem.Allocator, proto: []const u8, out: *std.ArrayList(u8), aux: ?*std.ArrayList(u8)) Error!u64 {
    return protoToChkOpts(gpa, arena, proto, out, aux, .{});
}

pub const Options = struct {
    /// Take a transaction's own `signatures` order when `txSignatures` accepts it. False: always
    /// the contents' order, as sui-types' `TryFrom<&proto::Checkpoint>` and the bucket give
    /// (stream-check compares a stream blob with the bucket's that way).
    tx_signature_order: bool = true,
    /// A second `Checkpoint` proto of the same checkpoint that carries only (or also) each
    /// transaction's `signatures` (a full node's `GetCheckpoint` with read mask
    /// `transactions.signatures.bcs`, sigorder.zig). Transaction `i` of `proto` that renders no
    /// signatures of its own (every bucket proto) takes overlay transaction `i`'s list, still
    /// only when `txSignatures` accepts it. Ignored when its `sequence_number` names another
    /// checkpoint. Mysten's bucket holds only the contents' signer order; sui-node serves the
    /// submitted order, which this restores for checkpoints the bucket filled.
    sig_overlay: ?[]const u8 = null,
};

/// Whether converting `proto` could differ from sui-node in signature order: it holds no
/// per-transaction `signatures` of its own (a bucket proto) and the contents certify a list of
/// two or more signatures for some transaction (a sponsored or multi-signer transaction, whose
/// submitted order the contents do not keep). Cheap: reads the contents and skims the
/// transactions, no effects or objects.
pub fn wantsSigOrder(arena: std.mem.Allocator, proto: []const u8) Error!bool {
    var contents: ?[]const u8 = null;
    var r: Pb = .{ .buf = proto };
    while (try r.next()) |f| switch (f.number) {
        5 => try mergeBcsHolder(&contents, try expectLen(f)),
        6 => {
            var tr: Pb = .{ .buf = try expectLen(f) };
            while (try tr.next()) |tf| if (tf.number == 3) return false; // the source keeps its order
        },
        else => {},
    };
    const c = contents orelse return false;
    for (try contentSignatures(arena, c)) |s| if (try sigCount(s) >= 2) return true;
    return false;
}

/// Number of signatures in one transaction's certified list.
fn sigCount(s: SigList) Error!u64 {
    if (s.raw) |raw| {
        var r = bcs.Reader.init(raw);
        return try r.length();
    }
    return s.parts.len;
}

/// Each overlay transaction's signature list (empty lists for transactions without any), or null
/// when the overlay is for another checkpoint or does not parse.
fn overlaySigs(arena: std.mem.Allocator, overlay: []const u8, seq: u64) ?[]const []const []const u8 {
    const o = parse(arena, overlay) catch return null;
    if (o.seq) |s| if (s != seq) return null;
    if (o.seq == null) {
        // Without its sequence number an overlay could belong to any checkpoint: a summary, when
        // present, must name this one.
        const sum = o.summary orelse return null;
        var sr = bcs.Reader.init(sum);
        _ = sr.int(u64) catch return null;
        if ((sr.int(u64) catch return null) != seq) return null;
    }
    const out = arena.alloc([]const []const u8, o.txs.items.len) catch return null;
    for (out, o.txs.items) |*d, t| d.* = t.sigs.items;
    return out;
}

pub fn overlaySigsForTest(arena: std.mem.Allocator, overlay: []const u8, seq: u64) ?[]const []const []const u8 {
    return overlaySigs(arena, overlay, seq);
}

/// `protoToChkAux` with `Options`.
pub fn protoToChkOpts(gpa: std.mem.Allocator, arena: std.mem.Allocator, proto: []const u8, out: *std.ArrayList(u8), aux: ?*std.ArrayList(u8), opts: Options) Error!u64 {
    const p = try parse(arena, proto);
    const summary = p.summary orelse return error.MissingField;
    const contents = p.contents orelse return error.MissingField;
    if (p.sig.signature.len != 48) return error.BadSignatureLength;

    // Sequence number from the summary: CheckpointSummary { epoch: u64, sequence_number: u64, .. }.
    var sr = bcs.Reader.init(summary);
    _ = try sr.int(u64);
    const seq = try sr.int(u64);

    const sigs = try contentSignatures(arena, contents);
    // Rust zips the proto transactions with the contents' signature lists.
    const n_tx = @min(p.txs.items.len, sigs.len);
    const overlay: []const []const []const u8 = if (opts.sig_overlay) |ov| overlaySigs(arena, ov, seq) orelse &.{} else &.{};

    var objs: std.AutoHashMapUnmanaged(Key, []const u8) = .empty;
    try objs.ensureTotalCapacity(arena, @intCast(p.objects.items.len));
    for (p.objects.items) |raw| {
        const k = exec.objects.keyOf(raw) catch return error.Malformed;
        objs.putAssumeCapacity(k, raw);
    }

    out.clearRetainingCapacity();
    try out.ensureTotalCapacity(gpa, proto.len + proto.len / 8 + 4096);
    try out.append(gpa, 1);
    // CertifiedCheckpointSummary = summary ++ AuthorityStrongQuorumSignInfo
    try out.appendSlice(gpa, summary);
    var e: [8]u8 = undefined;
    std.mem.writeInt(u64, &e, p.sig.epoch, .little);
    try out.appendSlice(gpa, &e);
    try out.appendSlice(gpa, p.sig.signature);
    try putUleb(out, gpa, p.sig.bitmap.len);
    try out.appendSlice(gpa, p.sig.bitmap);
    try out.appendSlice(gpa, contents);
    try putUleb(out, gpa, n_tx);

    var ins: std.ArrayList(Key) = .empty;
    var outs: std.ArrayList(Key) = .empty;
    var in_blob: std.AutoHashMapUnmanaged(Key, void) = .empty;
    for (p.txs.items[0..n_tx], sigs[0..n_tx], 0..) |t, s, ti| {
        const data = t.data orelse return error.MissingField;
        const fx = t.effects orelse return error.MissingField;
        // Transaction = SenderSignedData([SenderSignedTransaction { intent_message, tx_signatures }])
        try out.appendSlice(gpa, &.{ 1, 0, 0, 0 });
        try out.appendSlice(gpa, data);
        // The proto's own list first; a bucket proto has none, then the overlay's.
        const own: []const []const u8 = if (t.sigs.items.len > 0 or ti >= overlay.len) t.sigs.items else overlay[ti];
        if (opts.tx_signature_order and try txSignatures(arena, own, s)) {
            try putUleb(out, gpa, own.len);
            for (own) |sig| {
                try putUleb(out, gpa, sig.len);
                try out.appendSlice(gpa, sig);
            }
        } else if (s.raw) |raw| {
            try out.appendSlice(gpa, raw);
        } else {
            try putUleb(out, gpa, s.parts.len);
            for (s.parts) |part| try out.appendSlice(gpa, part);
        }
        try out.appendSlice(gpa, fx);
        if (t.has_events) {
            try out.append(gpa, 1);
            try out.appendSlice(gpa, t.events orelse return error.MissingField);
        } else try out.append(gpa, 0);
        try effectKeys(arena, fx, &ins, &outs);
        inline for (.{ &ins, &outs }) |keys| {
            var found: usize = 0;
            for (keys.items) |k| found += @intFromBool(objs.contains(k));
            try putUleb(out, gpa, found);
            for (keys.items) |k| if (objs.get(k)) |raw| {
                try out.appendSlice(gpa, raw);
                if (aux != null) try in_blob.put(arena, k, {});
            };
        }
    }
    if (aux) |a| {
        a.clearRetainingCapacity();
        try a.appendSlice(gpa, aux_magic);
        try putUleb(a, gpa, n_tx);
        for (p.txs.items[0..n_tx]) |t| {
            try putUleb(a, gpa, t.loaded.items.len);
            for (t.loaded.items) |m| {
                const ref = try parseObjectReference(m);
                try a.appendSlice(gpa, &ref.id);
                var vb: [8]u8 = undefined;
                std.mem.writeInt(u64, &vb, ref.version, .little);
                try a.appendSlice(gpa, &vb);
                if (ref.digest) |d| {
                    try a.append(gpa, 1);
                    try a.appendSlice(gpa, &d);
                } else try a.append(gpa, 0);
            }
        }
        var extra: usize = 0;
        for (p.objects.items) |raw| {
            if (!in_blob.contains(exec.objects.keyOf(raw) catch unreachable)) extra += 1;
        }
        try putUleb(a, gpa, extra);
        for (p.objects.items) |raw| {
            if (in_blob.contains(exec.objects.keyOf(raw) catch unreachable)) continue;
            try putUleb(a, gpa, raw.len);
            try a.appendSlice(gpa, raw);
        }
    }
    return seq;
}

// ------------------------------------------------------------------ aux: what the blob cannot hold

pub const aux_magic = "ZUIAUX01";

pub const LoadedRef = struct { id: [32]u8, version: u64, digest: ?[32]u8 };

/// `ObjectReference { optional string object_id = 1; optional uint64 version = 2; optional string
/// digest = 3; }`: id as `0x` + 64 hex, digest as base58.
fn parseObjectReference(msg: []const u8) Error!LoadedRef {
    var ref: LoadedRef = .{ .id = undefined, .version = 0, .digest = null };
    var have_id = false;
    var r: Pb = .{ .buf = msg };
    while (try r.next()) |f| switch (f.number) {
        1 => {
            const t = try expectLen(f);
            const hex = if (std.mem.startsWith(u8, t, "0x")) t[2..] else t;
            if (hex.len == 0 or hex.len > 64) return error.Malformed;
            var full: [64]u8 = @splat('0');
            @memcpy(full[64 - hex.len ..], hex);
            _ = std.fmt.hexToBytes(&ref.id, &full) catch return error.Malformed;
            have_id = true;
        },
        2 => {
            if (f.wire != 0) return error.Malformed;
            ref.version = f.varint;
        },
        3 => ref.digest = b58Digest(try expectLen(f)) orelse return error.Malformed,
        else => {},
    };
    if (!have_id) return error.MissingField;
    return ref;
}

/// Base58 (Bitcoin alphabet) text of exactly 32 bytes.
fn b58Digest(text: []const u8) ?[32]u8 {
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if (text.len == 0 or text.len > 44) return null;
    var num: [33]u8 = @splat(0); // big-endian accumulator
    for (text) |c| {
        var carry: u32 = @intCast(std.mem.indexOfScalar(u8, alphabet, c) orelse return null);
        var i: usize = num.len;
        while (i > 0) {
            i -= 1;
            carry += @as(u32, num[i]) * 58;
            num[i] = @truncate(carry);
            carry >>= 8;
        }
        if (carry != 0) return null;
    }
    if (num[0] != 0) return null;
    return num[1..].*;
}

/// Reader of an aux record (`aux_magic`, then per transaction its loaded runtime objects, then
/// the extra objects). Untrusted input: every length is bounds-checked.
pub const Aux = struct {
    loaded: []const []const LoadedRef,
    objects: []const []const u8,

    pub fn parse(arena: std.mem.Allocator, bytes: []const u8) !Aux {
        return parseInner(arena, bytes) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.BadAux,
        };
    }

    fn parseInner(arena: std.mem.Allocator, bytes: []const u8) !Aux {
        if (!std.mem.startsWith(u8, bytes, aux_magic)) return error.BadAux;
        var r = bcs.Reader.init(bytes[aux_magic.len..]);
        const n_tx = try r.length();
        if (n_tx > r.remaining()) return error.BadAux;
        const loaded = try arena.alloc([]const LoadedRef, n_tx);
        for (loaded) |*l| {
            const k = try r.length();
            if (k * 41 > r.remaining()) return error.BadAux;
            const refs = try arena.alloc(LoadedRef, k);
            for (refs) |*x| {
                x.id = (try r.bytes(32))[0..32].*;
                x.version = try r.int(u64);
                x.digest = switch (try r.int(u8)) {
                    0 => null,
                    1 => (try r.bytes(32))[0..32].*,
                    else => return error.BadAux,
                };
            }
            l.* = refs;
        }
        const n_obj = try r.length();
        if (n_obj > r.remaining()) return error.BadAux;
        const objects = try arena.alloc([]const u8, n_obj);
        for (objects) |*o| o.* = try r.bytes(try r.length());
        if (r.remaining() != 0) return error.BadAux;
        return .{ .loaded = loaded, .objects = objects };
    }
};

/// An aux record of loaded runtime object lists and nothing else: what an edge that keeps read
/// sets spools beside a checkpoint (history.zig `onBatchEdge`, docs/EDGE.md section 12).
/// `lists[i]` is transaction i's list in the stored form, `version: u64 LE ++ id` per entry
/// (edgewire feed.zig `ReadSets`). `out` is replaced.
pub fn auxOfLists(out: *std.ArrayList(u8), gpa: std.mem.Allocator, lists: []const []const u8) !void {
    out.clearRetainingCapacity();
    try out.appendSlice(gpa, aux_magic);
    try putUleb(out, gpa, lists.len);
    for (lists) |l| {
        if (l.len % 40 != 0) return error.Malformed;
        try putUleb(out, gpa, l.len / 40);
        var at: usize = 0;
        while (at < l.len) : (at += 40) {
            try out.appendSlice(gpa, l[at + 8 ..][0..32]);
            try out.appendSlice(gpa, l[at..][0..8]);
            try out.append(gpa, 0);
        }
    }
    try putUleb(out, gpa, 0);
}

/// Cuts the aux record in `aux` down to its loaded lists: the record `auxOfLists` writes for the
/// same lists (no objects, no reference digests), so an edge spools the same bytes whether a
/// checkpoint's read sets came with a core's feed or from the archive. `arena` is scratch.
pub fn auxListsOnly(aux: *std.ArrayList(u8), gpa: std.mem.Allocator, arena: std.mem.Allocator) !void {
    const x = try Aux.parse(arena, aux.items);
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, aux_magic);
    try putUleb(&out, arena, x.loaded.len);
    for (x.loaded) |l| {
        try putUleb(&out, arena, l.len);
        for (l) |r| {
            try out.appendSlice(arena, &r.id);
            var vb: [8]u8 = undefined;
            std.mem.writeInt(u64, &vb, r.version, .little);
            try out.appendSlice(arena, &vb);
            try out.append(arena, 0);
        }
    }
    try putUleb(&out, arena, 0);
    aux.clearRetainingCapacity();
    try aux.appendSlice(gpa, out.items);
}

test "aux records of lists only: from stored lists and cut from a full record are the same bytes" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // a full record: two transactions (two entries with and without a digest; none), one object
    var full: std.ArrayList(u8) = .empty;
    defer full.deinit(gpa);
    try full.appendSlice(gpa, aux_magic);
    try putUleb(&full, gpa, 2);
    try putUleb(&full, gpa, 2);
    try full.appendSlice(gpa, &@as([32]u8, @splat(0x11)));
    try full.appendSlice(gpa, &.{ 7, 0, 0, 0, 0, 0, 0, 0 });
    try full.append(gpa, 1);
    try full.appendSlice(gpa, &@as([32]u8, @splat(0xdd)));
    try full.appendSlice(gpa, &@as([32]u8, @splat(0x22)));
    try full.appendSlice(gpa, &.{ 3, 1, 0, 0, 0, 0, 0, 0 });
    try full.append(gpa, 0);
    try putUleb(&full, gpa, 0);
    try putUleb(&full, gpa, 1);
    try putUleb(&full, gpa, 5);
    try full.appendSlice(gpa, "OBJ_X");
    try auxListsOnly(&full, gpa, arena);

    var l0: [80]u8 = undefined;
    std.mem.writeInt(u64, l0[0..8], 7, .little);
    @memset(l0[8..40], 0x11);
    std.mem.writeInt(u64, l0[40..48], 259, .little);
    @memset(l0[48..80], 0x22);
    var made: std.ArrayList(u8) = .empty;
    defer made.deinit(gpa);
    try auxOfLists(&made, gpa, &.{ &l0, "" });
    try std.testing.expectEqualSlices(u8, made.items, full.items);

    const x = try Aux.parse(arena, made.items);
    try std.testing.expectEqual(@as(usize, 2), x.loaded.len);
    try std.testing.expectEqual(@as(usize, 2), x.loaded[0].len);
    try std.testing.expectEqual(@as(u64, 259), x.loaded[0][1].version);
    try std.testing.expectEqual(@as(?[32]u8, null), x.loaded[0][0].digest);
    try std.testing.expectEqual(@as(usize, 0), x.loaded[1].len);
    try std.testing.expectEqual(@as(usize, 0), x.objects.len);
    try std.testing.expectError(error.Malformed, auxOfLists(&made, gpa, &.{l0[0..79]}));
}

/// Decompresses an archive `<seq>.binpb.zst` file. Caller frees.
/// The frame content size of a single zstd frame (RFC 8878 3.1.1.1), or null when the header
/// does not record it (streamed frames) or the input is not a zstd frame.
pub fn zstdContentSize(b: []const u8) ?u64 {
    if (b.len < 6 or std.mem.readInt(u32, b[0..4], .little) != 0xFD2FB528) return null;
    const fhd = b[4];
    const fcs_flag: u2 = @intCast(fhd >> 6);
    const single: bool = (fhd >> 5) & 1 == 1;
    const did_len: usize = switch (@as(u2, @intCast(fhd & 3))) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
    };
    const fcs_len: usize = switch (fcs_flag) {
        0 => if (single) 1 else return null,
        1 => 2,
        2 => 4,
        3 => 8,
    };
    const at: usize = 5 + @as(usize, if (single) 0 else 1) + did_len;
    if (b.len < at + fcs_len) return null;
    const f = b[at..][0..fcs_len];
    return switch (fcs_len) {
        1 => f[0],
        2 => @as(u64, std.mem.readInt(u16, f[0..2], .little)) + 256,
        4 => std.mem.readInt(u32, f[0..4], .little),
        else => std.mem.readInt(u64, f[0..8], .little),
    };
}

/// `unzstd` for the fetch path: direct mode, decoding straight into the output buffer (which is
/// also the back-reference window): no 8 MiB window buffer and no copy out of it. Exact-size
/// output when the frame header records the content size; else a growing buffer starting at
/// 4x the input (the archive's frames do not record it; protos compress about 3-4x).
pub fn unzstdArena(a: std.mem.Allocator, compressed: []const u8, max_bytes: usize) ![]u8 {
    const zstd = @import("zstd.zig");
    var in: std.Io.Reader = .fixed(compressed);
    var d: zstd.Decompress = .init(&in, &.{}, .{});
    if (zstdContentSize(compressed)) |size| {
        if (size > max_bytes) return error.StreamTooLong;
        const buf = try a.alloc(u8, @as(usize, @intCast(size)) + zstd.block_size_max);
        var w: std.Io.Writer = .fixed(buf);
        _ = d.reader.streamRemaining(&w) catch |e| switch (e) {
            error.ReadFailed => return d.err orelse error.ReadFailed,
            error.WriteFailed => return error.StreamTooLong,
        };
        if (w.end != size) return error.BadSize;
        return buf[0..w.end];
    }
    // No recorded size: grow, but never past `max_bytes` plus one block. The sources are untrusted
    // and a frame's size is the decoder's to find out (RLE blocks expand 4 bytes to 128 KiB), so
    // the output is bounded while decoding, not checked after. The limit stays at least one block
    // (direct mode fails a smaller one with OutputBufferUndersize).
    var w: std.Io.Writer.Allocating = try .initCapacity(a, @min(max_bytes, compressed.len * 4) + zstd.block_size_max);
    while (true) {
        _ = d.reader.stream(&w.writer, .limited((max_bytes -| w.writer.end) + zstd.block_size_max)) catch |e| switch (e) {
            error.EndOfStream => break,
            error.ReadFailed => return d.err orelse error.ReadFailed,
            error.WriteFailed => return error.OutOfMemory,
        };
        if (w.writer.end > max_bytes) return error.StreamTooLong;
    }
    if (w.writer.end > max_bytes) return error.StreamTooLong;
    return w.writer.buffer[0..w.writer.end];
}

pub fn unzstd(gpa: std.mem.Allocator, compressed: []const u8, max_bytes: usize) ![]u8 {
    var in: std.Io.Reader = .fixed(compressed);
    const zstd = @import("zstd.zig");
    const window_buf = try gpa.alloc(u8, zstd.default_window_len + zstd.block_size_max);
    defer gpa.free(window_buf);
    var d: zstd.Decompress = .init(&in, window_buf, .{});
    return d.reader.allocRemaining(gpa, .limited(max_bytes));
}

test "unzstdArena: direct decode equals the windowed one" {
    const gpa = std.testing.allocator;
    // A raw-block frame with a 2-byte content size (FCS flag 1, single segment): 300 bytes.
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(gpa);
    try frame.appendSlice(gpa, &.{ 0x28, 0xB5, 0x2F, 0xFD, 0x60, 44, 0 });
    // Last raw block of 300 bytes: header = last(1) | type raw(0)<<1 | size<<3.
    const bh: u24 = 1 | (300 << 3);
    try frame.appendSlice(gpa, &.{ @truncate(bh), @truncate(bh >> 8), @truncate(bh >> 16) });
    for (0..300) |i| try frame.append(gpa, @truncate(i * 7));
    try std.testing.expectEqual(@as(?u64, 300), zstdContentSize(frame.items));
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = try unzstdArena(arena.allocator(), frame.items, 1 << 20);
    const b = try unzstd(gpa, frame.items, 1 << 20);
    defer gpa.free(b);
    try std.testing.expectEqualSlices(u8, b, a);
}

/// A frame without a content size (FHD 0x00, 1 MiB window) of `blocks` RLE blocks of 128 KiB.
fn rleFrame(gpa: std.mem.Allocator, blocks: usize) !std.ArrayList(u8) {
    var frame: std.ArrayList(u8) = .empty;
    try frame.appendSlice(gpa, &.{ 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x50 });
    for (0..blocks) |i| {
        // header = last | type RLE (1) << 1 | size << 3, then the byte to repeat.
        const bh: u24 = @as(u24, @intFromBool(i + 1 == blocks)) | (1 << 1) | (@as(u24, 1 << 17) << 3);
        try frame.appendSlice(gpa, &.{ @truncate(bh), @truncate(bh >> 8), @truncate(bh >> 16), 0x5A });
    }
    return frame;
}

test "unzstdArena: a frame without a size that expands past max_bytes stops at the limit" {
    const gpa = std.testing.allocator;
    // 2,048 RLE blocks: 8 KiB of frame claiming 256 MiB of output.
    var frame = try rleFrame(gpa, 2048);
    defer frame.deinit(gpa);
    try std.testing.expectEqual(@as(?u64, null), zstdContentSize(frame.items));
    // 32 MiB of memory in all: decoding without a bound would need 256 MiB and fail OutOfMemory.
    // Bounded, the peak is the decoder's 8 MiB window plus a few blocks (12 MiB measured).
    const mem = try gpa.alloc(u8, 32 << 20);
    defer gpa.free(mem);
    var fba: std.heap.FixedBufferAllocator = .init(mem);
    try std.testing.expectError(error.StreamTooLong, unzstdArena(fba.allocator(), frame.items, 1 << 20));
    // Under the limit it decodes in full.
    var small = try rleFrame(gpa, 4);
    defer small.deinit(gpa);
    fba.reset();
    const out = try unzstdArena(fba.allocator(), small.items, 1 << 20);
    try std.testing.expectEqual(@as(usize, 4 << 17), out.len);
    try std.testing.expect(std.mem.allEqual(u8, out, 0x5A));
}

test "uleb" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try putUleb(&out, std.testing.allocator, 300);
    try std.testing.expectEqualSlices(u8, &.{ 0xac, 0x02 }, out.items);
}
