//! Suite `sig-order` (node lane): every sponsored or multi-signer transaction of the corpus
//! (`chk/<seq>.chk`, one item each).
//!
//! 1. The contents rule the sweep relies on: in CheckpointContents V2 the certified signatures
//!    are in `required_signers` order (sui-types transaction.rs `required_signers`: sender,
//!    then the gas owner; sui-core authority_per_epoch_store.rs `process_user_signatures` with
//!    `fix_checkpoint_signature_mapping`; messages_checkpoint.rs `CheckpointTransactionContents`).
//!    Signature i's address (`SuiAddress::try_from(&GenericSignature)`) must be required signer
//!    i, unless the contents record an address-alias version for it (then the signer may be an
//!    alias; counted). V1 contents keep the submitted order, which is not asserted (the counts
//!    of V1 transactions in and out of signer order are printed: the submitted order is the
//!    client's choice).
//! 2. The fix the sweep installs (sigorder.reorder) for a node order that is the stored list
//!    reversed: same length, same TransactionData bytes (so the transaction digest holds),
//!    the signatures exactly reversed, and reordering back gives the stored envelope. The
//!    ingest overlay (convert.txSignatures) accepts the same list; a list with one signature
//!    byte changed is refused by both.
const std = @import("std");
const harness = @import("harness");
const types = @import("types");
const bcs = @import("bcs");
const hash = @import("hash");
const usig = @import("sig").user;
const convert = @import("convert.zig");
const sigorder = @import("sigorder.zig");

const max_blob = 1 << 30;

const Counts = struct {
    v2_txs: std.atomic.Value(u64) = .init(0),
    v2_aliased: std.atomic.Value(u64) = .init(0),
    v1_signer_order: std.atomic.Value(u64) = .init(0),
    v1_other_order: std.atomic.Value(u64) = .init(0),
};

pub fn run(ctx: *harness.Ctx) !void {
    var c: Counts = .{};
    try ctx.forEachFile("chk", ".chk", &c, one);
    ctx.stdout.print("sig-order: V2 multi-signer transactions {d} ({d} with an alias version), V1 in signer order {d}, V1 in another order {d}\n", .{ c.v2_txs.load(.monotonic), c.v2_aliased.load(.monotonic), c.v1_signer_order.load(.monotonic), c.v1_other_order.load(.monotonic) }) catch {};
    ctx.stdout.flush() catch {};
}

/// Per transaction of the contents: certified signature count and whether any carries an
/// alias version (V2 only).
const Entry = struct { k: u64, aliased: bool };

fn contentsEntries(a: std.mem.Allocator, contents: []const u8) !struct { v2: bool, e: []Entry } {
    var r = bcs.Reader.init(contents);
    const tag = try r.uleb32();
    const n = try r.length();
    const out = try a.alloc(Entry, n);
    for (out) |*e| {
        _ = try r.bytes(66);
        e.* = .{ .k = 0, .aliased = false };
        if (tag == 1) {
            e.k = try r.length();
            for (0..e.k) |_| {
                _ = try r.bytes(try r.length());
                if (try r.int(u8) == 1) {
                    _ = try r.int(u64);
                    e.aliased = true;
                }
            }
        }
    }
    if (tag == 0) {
        const m = try r.length();
        for (out[0..@min(m, n)]) |*e| {
            e.k = try r.length();
            for (0..e.k) |_| _ = try r.bytes(try r.length());
        }
    }
    return .{ .v2 = tag == 1, .e = out };
}

fn addressOf(a: std.mem.Allocator, g: []const u8) ?usig.Address {
    const scratch = a.alloc(u8, usig.scratchLen(g.len)) catch return null;
    var p: usig.Parsed = undefined;
    if (usig.parse(g, &p, scratch) != null) return null;
    return switch (usig.address(&p) catch return null) {
        .ok => |x| x,
        .err => null,
    };
}

fn one(c: *Counts, ctx: *harness.Ctx, name: []const u8) !void {
    const seq_text = name[0 .. name.len - ".chk".len];
    const a = ctx.scratch();
    const blob = ctx.readFile(try std.fmt.allocPrint(a, "chk/{s}", .{name}), max_blob) catch |e| {
        return ctx.fail(seq_text, "read: {s}", .{@errorName(e)});
    };
    var idx = try types.CheckpointIndex.init(a);
    types.indexCheckpointData(blob, &idx) catch |e| return ctx.fail(seq_text, "index: {s}", .{@errorName(e)});
    const ce = contentsEntries(a, idx.contents.slice(blob)) catch |e| return ctx.fail(seq_text, "contents: {s}", .{@errorName(e)});
    for (idx.txs[0..idx.tx_count], 0..) |t, i| {
        if (t.sig_count < 2) continue;
        const item = try std.fmt.allocPrint(a, "{s}/tx[{d}]", .{ seq_text, i });
        if (!ctx.selected(item)) continue;
        var chk = ctx.check(item);
        const env = t.transaction.slice(blob);
        const data = t.data.slice(blob);
        const e = sigorder.envelopeSigs(a, env) catch |err| {
            chk.failf("envelope: {s}", .{@errorName(err)});
            _ = chk.finish();
            continue;
        };
        if (i >= ce.e.len or ce.e[i].k != e.sigs.len) chk.failf("contents certify {d} signatures, the blob has {d}", .{ if (i < ce.e.len) ce.e[i].k else 0, e.sigs.len });

        // 1. Signer order.
        const signers = usig.txSigners(data) catch {
            chk.failf("TransactionData does not decode", .{});
            _ = chk.finish();
            continue;
        };
        var in_order = signers.n == e.sigs.len;
        if (in_order) for (e.sigs, signers.slice()) |g, want| {
            const got = addressOf(a, g) orelse {
                in_order = false;
                break;
            };
            if (!std.mem.eql(u8, &got, &want)) in_order = false;
        };
        if (ce.v2) {
            _ = c.v2_txs.fetchAdd(1, .monotonic);
            const aliased = i < ce.e.len and ce.e[i].aliased;
            if (aliased) _ = c.v2_aliased.fetchAdd(1, .monotonic);
            if (!in_order and !aliased) chk.failf("V2 contents not in required_signers order (sender, gas owner)", .{});
        } else _ = (if (in_order) &c.v1_signer_order else &c.v1_other_order).fetchAdd(1, .monotonic);

        // 2. The fix for a reversed node order, and back.
        const rev = try a.alloc([]const u8, e.sigs.len);
        for (rev, 0..) |*r, j| r.* = e.sigs[e.sigs.len - 1 - j];
        const distinct = !std.mem.eql(u8, rev[0], e.sigs[0]) or e.sigs.len > 2;
        if (distinct) {
            if (sigorder.reorder(a, env, rev) catch null) |fixed| {
                chk.bytes("length", std.mem.asBytes(&env.len), std.mem.asBytes(&fixed.len));
                const fe = try sigorder.envelopeSigs(a, fixed);
                chk.bytes("TransactionData", env[0..e.head], fixed[0..fe.head]);
                const d0 = hash.blake2b256(&.{ "TransactionData::", data });
                var r2 = bcs.Reader.init(fixed);
                _ = try r2.length();
                _ = try r2.bytes(3);
                const s0 = r2.pos();
                try bcs.skip(types.TransactionData, &r2);
                const d1 = hash.blake2b256(&.{ "TransactionData::", fixed[s0..r2.pos()] });
                chk.bytes("transaction digest", &d0, &d1);
                for (fe.sigs, rev, 0..) |x, y, j| {
                    if (!std.mem.eql(u8, x, y)) chk.failf("signature {d} is not the node's", .{j});
                }
                const back = (sigorder.reorder(a, fixed, e.sigs) catch null) orelse {
                    chk.failf("reordering back refused", .{});
                    _ = chk.finish();
                    continue;
                };
                chk.bytes("back", env, back);
            } else chk.failf("reorder refused a permutation of the stored signatures", .{});
            // The ingest overlay's rule agrees.
            const raw_start = e.head;
            const sl: convert.SigList = .{ .raw = env[raw_start..] };
            if (!(convert.txSignaturesForTest(a, rev, sl) catch false)) chk.failf("convert.txSignatures refused the permutation", .{});
        }
        // A changed signature byte: refused by both.
        const bad = try a.alloc([]const u8, e.sigs.len);
        @memcpy(bad, rev);
        const flipped = try a.dupe(u8, bad[0]);
        flipped[flipped.len - 1] ^= 1;
        bad[0] = flipped;
        if ((sigorder.reorder(a, env, bad) catch null) != null) chk.failf("reorder took a signature the contents do not certify", .{});
        if (convert.txSignaturesForTest(a, bad, .{ .raw = env[e.head..] }) catch false) chk.failf("convert.txSignatures took a signature the contents do not certify", .{});
        _ = chk.finish();
    }
}
