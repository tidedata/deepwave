//! One-pass validation of a checkpoint blob that records where every top-level object lives:
//! the table the truth files describe (docs/CONFORMANCE.md). It validates every byte with the
//! same rules as a full decode (it uses `bcs.skip` on each value) but allocates nothing: the
//! caller supplies the backing arrays.
const std = @import("std");
const bcs = @import("bcs");
const core = @import("core");
const gen = @import("gen.zig");
const hand = @import("hand.zig");
const Reader = bcs.Reader;

/// A byte range in the blob (tag byte included): blob[o..o+n].
pub const Range = struct {
    o: u32,
    n: u32,

    pub fn slice(r: Range, blob: []const u8) []const u8 {
        return blob[r.o..][0..r.n];
    }
};

pub const Tx = struct {
    /// The whole `Transaction` envelope (SenderSignedData with its sizes and signatures).
    transaction: Range,
    /// TransactionData (after the vec length and the 3 intent bytes).
    data: Range,
    /// Signatures: `sigs[sig_first .. sig_first + sig_count]`, each the length-prefixed bytes.
    sig_first: u32,
    sig_count: u32,
    effects: Range,
    events: ?Range,
    /// Input and output objects: `objs[in_first .. in_first + in_count]`, then the outputs.
    in_first: u32,
    in_count: u32,
    out_first: u32,
    out_count: u32,
};

/// Index of one checkpoint blob. The three arrays are caller-owned scratch (see `Buffers`).
pub const CheckpointIndex = struct {
    summary: Range = .{ .o = 0, .n = 0 },
    /// AuthorityStrongQuorumSignInfo.
    sig: Range = .{ .o = 0, .n = 0 },
    contents: Range = .{ .o = 0, .n = 0 },
    tx_count: u32 = 0,
    sig_total: u32 = 0,
    obj_total: u32 = 0,
    txs: []Tx,
    sigs: []Range,
    objs: []Range,

    /// Protocol-maximum capacities: 16,384 transactions, 32,768 signatures, 1,048,576 objects
    /// per checkpoint (mainnet maxima are far below: 10,000 txs per checkpoint).
    pub const max_txs = 1 << 14;
    pub const max_sigs = 1 << 15;
    pub const max_objs = 1 << 20;

    pub fn init(gpa: std.mem.Allocator) !CheckpointIndex {
        const txs = try gpa.alloc(Tx, max_txs);
        errdefer gpa.free(txs);
        const sigs = try gpa.alloc(Range, max_sigs);
        errdefer gpa.free(sigs);
        const objs = try gpa.alloc(Range, max_objs);
        return .{ .txs = txs, .sigs = sigs, .objs = objs };
    }

    pub fn deinit(i: *CheckpointIndex, gpa: std.mem.Allocator) void {
        gpa.free(i.txs);
        gpa.free(i.sigs);
        gpa.free(i.objs);
    }

    pub fn txAt(i: *const CheckpointIndex, k: usize) *const Tx {
        return &i.txs[k];
    }
};

pub const IndexError = core.DecodeError || error{InvalidValue};

fn rangeOf(r: *const Reader, start: usize) Range {
    return .{ .o = @intCast(start), .n = @intCast(r.at - start) };
}

/// Validates `blob` (0x01 ++ BCS(CheckpointData)) completely and fills `out`.
/// Errors: any decode error of the blob, `LengthTooLarge` when `out` is too small.
pub fn indexCheckpointData(blob: []const u8, out: *CheckpointIndex) IndexError!void {
    if (blob.len == 0) return error.EndOfInput;
    if (blob[0] != 1) return error.InvalidEnumTag;
    var r = Reader.init(blob);
    r.at = 1;
    const Summary = gen.CheckpointSummary;
    const Sig = gen.AuthorityQuorumSignInfo;

    // Envelope<CheckpointSummary, AuthorityQuorumSignInfo>: a container (depth), fields in order.
    try r.enter();
    var s = r.at;
    try bcs.skip(Summary, &r);
    out.summary = rangeOf(&r, s);
    s = r.at;
    try bcs.skip(Sig, &r);
    out.sig = rangeOf(&r, s);
    r.leave();
    s = r.at;
    try bcs.skip(gen.CheckpointContents, &r);
    out.contents = rangeOf(&r, s);

    const ntx = try r.length();
    if (ntx > out.txs.len) return error.LengthTooLarge;
    out.tx_count = @intCast(ntx);
    var nsig: u32 = 0;
    var nobj: u32 = 0;
    for (out.txs[0..ntx]) |*tx| {
        // CheckpointTransaction (container).
        try r.enter();
        const tx_start = r.at;
        // Envelope<SenderSignedData, EmptySignInfo> -> SenderSignedData newtype -> SizeOneVec.
        try r.enter(); // Envelope
        try r.enter(); // SenderSignedData
        const count = try r.length();
        // Elements are read before the size check, as the Rust decoder does.
        if (count != 1) {
            var k: usize = 0;
            while (k < count) : (k += 1) try bcs.skip(gen.SenderSignedTransaction, &r);
            return error.InvalidValue;
        }
        try r.enter(); // SenderSignedTransaction
        try r.enter(); // IntentMessage
        const intent_at = r.at;
        try bcs.skip(hand.Intent, &r);
        s = r.at;
        try bcs.skip(gen.TransactionData, &r);
        tx.data = rangeOf(&r, s);
        r.leave(); // IntentMessage
        const nsigs = try r.length();
        if (nsigs > out.sigs.len - nsig) return error.LengthTooLarge;
        tx.sig_first = nsig;
        tx.sig_count = @intCast(nsigs);
        for (out.sigs[nsig..][0..nsigs]) |*sg| {
            s = r.at;
            try bcs.skip(gen.GenericSignature, &r);
            sg.* = rangeOf(&r, s);
        }
        nsig += @intCast(nsigs);
        r.leave(); // SenderSignedTransaction
        // Rust's SenderSignedTransaction Deserialize checks the intent after the whole struct.
        if (!std.mem.eql(u8, blob[intent_at..][0..3], &hand.Intent.sui(.transaction_data).bytes())) return error.InvalidValue;
        r.leave(); // SenderSignedData
        try r.enter(); // EmptySignInfo
        r.leave();
        r.leave(); // Envelope
        tx.transaction = rangeOf(&r, tx_start);

        s = r.at;
        try bcs.skip(gen.TransactionEffects, &r);
        tx.effects = rangeOf(&r, s);

        const tag = try r.int(u8);
        tx.events = switch (tag) {
            0 => null,
            1 => blk: {
                s = r.at;
                try bcs.skip(gen.TransactionEvents, &r);
                break :blk rangeOf(&r, s);
            },
            else => return error.InvalidEnumTag,
        };

        const nin = try r.length();
        if (nin > out.objs.len - nobj) return error.LengthTooLarge;
        tx.in_first = nobj;
        tx.in_count = @intCast(nin);
        for (out.objs[nobj..][0..nin]) |*o| {
            s = r.at;
            try bcs.skip(gen.Object, &r);
            o.* = rangeOf(&r, s);
        }
        nobj += @intCast(nin);
        const nout = try r.length();
        if (nout > out.objs.len - nobj) return error.LengthTooLarge;
        tx.out_first = nobj;
        tx.out_count = @intCast(nout);
        for (out.objs[nobj..][0..nout]) |*o| {
            s = r.at;
            try bcs.skip(gen.Object, &r);
            o.* = rangeOf(&r, s);
        }
        nobj += @intCast(nout);
        r.leave(); // CheckpointTransaction
    }
    out.sig_total = nsig;
    out.obj_total = nobj;
    try r.finish();
}
