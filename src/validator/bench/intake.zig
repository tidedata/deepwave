//! Stage 1 of the validator speed bench: user transaction signature verification at intake, on
//! the real mainnet transactions of the bench checkpoints (`bench/val-bench/intake.list`, the
//! same list tools/truth/val-bench gives Mysten's `verify_sender_signed_data_message_signatures`).
//!
//! Per user transaction: sig.user.verifyTransaction (signer mapping, aliases, every signature:
//! Ed25519, secp256k1/r1, multisig, zkLogin with Groth16 and the JWK, passkey), with the epoch,
//! verify flags, JWK map and pinned aliases of that checkpoint (sig-corpus header). Inputs (the
//! intent message bytes and signature bytes) are prepared before the clock starts.
//!
//! Modes: cold (sig.fast caches off), warm (sig.fast all on: decoded-key caches, zkLogin proof
//! cache; after a warm-up pass), cold-par / warm-par (the list split over 1 and 4 threads), and
//! batch-par (4 lanes: single-signature Ed25519 transactions checked in one Ed25519 batch on the
//! sig.fast CPU pool after the address check, the rest per transaction on 4 threads). Output per
//! transaction "<seq> <tx> ok <indices>" or "<seq> <tx> err", as Rust prints it.
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const sig = @import("sig");
const common = @import("common.zig");

const Allocator = std.mem.Allocator;
const user = sig.user;
const sc = sig.conformance;

const Item = struct {
    seq: u64,
    tx: u32,
    env: *const user.UserSigEnv,
    intent: []const u8,
    sigs: []const []const u8,
    aliases: []const user.AliasSet,
    class: []const u8,
    /// single Ed25519 signature, sender pays gas, no aliases: batchable
    batchable: bool,
    sender: [32]u8,
};

fn classOf(sigs: []const []const u8) []const u8 {
    var best: u8 = 0;
    for (sigs) |s| {
        const r: u8 = switch (s[0]) {
            0x05 => 5,
            0x03 => 4,
            0x06 => 3,
            0x02 => 2,
            0x01 => 1,
            else => 0,
        };
        best = @max(best, r);
    }
    return switch (best) {
        5 => "zklogin",
        4 => "multisig",
        3 => "passkey",
        2 => "secp256r1",
        1 => "secp256k1",
        else => "ed25519",
    };
}

fn verify(it: *const Item, out: ?*std.Io.Writer) void {
    var buf: [16 << 10]u8 = undefined;
    const need = user.txScratchLen(it.sigs);
    var heap: ?[]u8 = null;
    defer if (heap) |h| std.heap.page_allocator.free(h);
    const scratch: []u8 = if (need <= buf.len) buf[0..need] else blk: {
        heap = std.heap.page_allocator.alloc(u8, need) catch return;
        break :blk heap.?;
    };
    const r = user.verifyTransaction(it.env, it.intent, it.sigs, it.aliases, scratch) catch {
        if (out) |w| w.print("{d} {d} err\n", .{ it.seq, it.tx }) catch {};
        return;
    };
    if (out) |w| switch (r.verdict) {
        .valid => {
            w.print("{d} {d} ok ", .{ it.seq, it.tx }) catch {};
            for (r.indices[0..r.n], 0..) |x, k| w.print("{s}{d}", .{ if (k == 0) "" else ",", x }) catch {};
            w.writeByte('\n') catch {};
        },
        .invalid => w.print("{d} {d} err\n", .{ it.seq, it.tx }) catch {},
    };
}

fn verifyPar(items: []const Item, i: usize) void {
    verify(&items[i], null);
}

pub fn run(ctx: *harness.Ctx) anyerror!void {
    const gpa = ctx.gpa;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const files = try common.readList(ctx, a, "intake");
    var items: std.ArrayList(Item) = .empty;
    for (files) |rel| {
        const seq = try common.seqOf(rel);
        const blob = try ctx.corpus.readFileAlloc(ctx.io, rel, a, .limited(1 << 31));
        if (blob.len == 0 or blob[0] != 1) return error.BadBlob;
        const cp = try bcs.decode(types.CheckpointData, a, blob[1..]);
        // the checkpoint's sig-corpus truth: epoch, flags, JWKs, pinned aliases per tx
        const zp = try std.fmt.allocPrint(a, "vectors/sig-corpus/{d}.jsonl.zst", .{seq});
        const zt = try ctx.corpus.readFileAlloc(ctx.io, zp, a, .limited(1 << 32));
        const tt = try harness.decompressZstd(a, zt, 1 << 32);
        var lit = harness.lines(tt);
        const hdr = try std.json.parseFromSliceLeaky(sc.Header, a, lit.next() orelse return error.EmptyTruth, .{ .ignore_unknown_fields = true });
        const jl = try a.create(sc.JwkList);
        jl.* = .{ .items = hdr.jwks };
        const env = try a.create(user.UserSigEnv);
        env.* = sc.envWithJwks(hdr.epoch, &hdr.flags, jl);
        var aliases_of: std.AutoHashMapUnmanaged(u32, []const user.AliasSet) = .empty;
        while (lit.next()) |text| {
            if (!std.mem.startsWith(u8, text, "{\"k\":\"tx\"")) continue;
            const l = try std.json.parseFromSliceLeaky(sc.Line, a, text, .{ .ignore_unknown_fields = true });
            if (l.aliases) |al| try aliases_of.put(a, l.tx, try sc.parseAliases(a, al));
        }
        for (cp.transactions, 0..) |*t, i| {
            const st = t.transaction.data.@"0".element();
            const td = switch (st.intent_message.value) {
                .V1 => |*v| v,
            };
            if (td.kind != .ProgrammableTransaction) continue; // system transactions
            const td_all: types.TransactionData = .{ .V1 = td.* };
            const enc = try bcs.encodeAlloc(types.TransactionData, a, &td_all);
            const intent = try a.alloc(u8, 3 + enc.len);
            intent[0..3].* = .{ 0, 0, 0 };
            @memcpy(intent[3..], enc);
            const sigs = try a.alloc([]const u8, st.tx_signatures.len);
            for (st.tx_signatures, sigs) |s, *o| o.* = s.@"0";
            const al = aliases_of.get(@intCast(i)) orelse &.{};
            const sender = td.sender.@"0";
            const batchable = sigs.len == 1 and sigs[0].len == 97 and sigs[0][0] == 0 and al.len == 0 and
                std.mem.eql(u8, &td.gas_data.owner.@"0", &sender);
            try items.append(a, .{ .seq = seq, .tx = @intCast(i), .env = env, .intent = intent, .sigs = sigs, .aliases = al, .class = classOf(sigs), .batchable = batchable, .sender = sender });
        }
    }
    const it_all: []const Item = items.items;

    // reference outputs, cold
    sig.fast.configure(.{});
    sig.fast.clearCaches();
    var outw: std.Io.Writer.Allocating = .init(a);
    for (it_all) |*it| verify(it, &outw.writer);
    const mine = outw.written();
    const dg = common.digestHex(mine);
    const reps: usize = 3;

    const classes = [_][]const u8{ "all", "ed25519", "secp256k1", "secp256r1", "multisig", "zklogin", "passkey" };
    // cold and warm, 1 thread: best of `reps` per transaction
    for ([_][]const u8{ "cold", "warm" }) |mode| {
        const warm = std.mem.eql(u8, mode, "warm");
        sig.fast.configure(if (warm) sig.fast.all_on else .{});
        sig.fast.clearCaches();
        if (warm) for (it_all) |*it| verify(it, null);
        const best = try a.alloc(u64, it_all.len);
        @memset(best, std.math.maxInt(u64));
        for (0..reps) |_| for (it_all, best) |*it, *b| {
            const t0 = common.now(ctx.io);
            verify(it, null);
            b.* = @min(b.*, common.since(ctx.io, t0));
        };
        for (classes) |c| {
            var sel: std.ArrayList(u64) = .empty;
            for (it_all, best) |*it, b| if (std.mem.eql(u8, c, "all") or std.mem.eql(u8, it.class, c)) try sel.append(a, b);
            if (sel.items.len == 0) continue;
            var wall: u64 = 0;
            for (sel.items) |x| wall += x;
            common.emit(ctx, .{ .stage = "intake", .case = c, .mode = mode, .threads = 1, .unit = "tx", .items = sel.items, .count = sel.items.len, .wall_ns = wall, .out = if (std.mem.eql(u8, c, "all")) &dg else "" });
        }
    }
    // throughput on 1 and 4 threads
    for ([_]usize{ 1, 4 }) |threads| {
        sig.fast.configure(.{});
        sig.fast.clearCaches();
        var w = common.parWall(ctx.io, it_all.len, threads, reps, it_all, verifyPar);
        common.emit(ctx, .{ .stage = "intake", .case = "all", .mode = "cold-par", .threads = threads, .unit = "tx", .count = it_all.len, .wall_ns = w, .out = &dg });
        sig.fast.configure(sig.fast.all_on);
        for (it_all) |*it| verify(it, null);
        w = common.parWall(ctx.io, it_all.len, threads, reps, it_all, verifyPar);
        common.emit(ctx, .{ .stage = "intake", .case = "all", .mode = "warm-par", .threads = threads, .unit = "tx", .count = it_all.len, .wall_ns = w, .out = &dg });
    }

    // batch-par: Ed25519 single-signature transactions in one batch on the 4-lane pool
    {
        sig.fast.configure(sig.fast.all_on);
        _ = sig.fast.startPool(ctx.io, gpa, 4);
        defer sig.fast.stopPool();
        var batch_idx: std.ArrayList(usize) = .empty;
        var rest: std.ArrayList(Item) = .empty;
        for (it_all, 0..) |it, k| if (it.batchable) try batch_idx.append(a, k) else try rest.append(a, it);
        const digests = try a.alloc([32]u8, batch_idx.items.len);
        const bitems = try a.alloc(sig.ed25519.BatchItem, batch_idx.items.len);
        var best: u64 = std.math.maxInt(u64);
        var batch_ok = true;
        for (0..reps) |_| {
            const t0 = common.now(ctx.io);
            var addr_ok = true;
            for (batch_idx.items, digests, bitems) |k, *d, *b| {
                const it = &it_all[k];
                const s = it.sigs[0];
                d.* = user.intentDigest(it.intent);
                const addr = hash.blake2b256(&.{ &[_]u8{0}, s[65..97] });
                addr_ok = addr_ok and std.mem.eql(u8, &addr, &it.sender);
                b.* = .{ .pk = s[65..97], .msg = d, .sig = s[1..65] };
            }
            const v = sig.fast.verifyBatchParallel(gpa, bitems, .{ .threads = 4 });
            batch_ok = addr_ok and v == .valid;
            _ = common.parWall(ctx.io, rest.items.len, 4, 1, @as([]const Item, rest.items), verifyPar);
            best = @min(best, common.since(ctx.io, t0));
        }
        const extra = try std.fmt.allocPrint(a, ",\"batched\":{d},\"batch_valid\":{}", .{ batch_idx.items.len, batch_ok });
        common.emit(ctx, .{ .stage = "intake", .case = "all", .mode = "batch-par", .threads = 4, .unit = "tx", .count = it_all.len, .wall_ns = best, .out = if (batch_ok) &dg else "batch-invalid", .extra = extra });
    }
    sig.fast.configure(.{});
    _ = try common.compareOut(ctx, a, "intake", mine);
}
