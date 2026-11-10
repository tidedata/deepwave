//! Stage 4 of the validator speed bench: block proposal and block verification, on the very
//! blocks Mysten's consensus-core created (tools/truth/val-bench/consensus/zui_val_bench.rs writes
//! `consensus/val-bench/blocks-<case>.vec`: committee, genesis digests, serialized SignedBlocks).
//!
//!   create  from the block's contents in memory (what the proposer has chosen): BCS of the inner
//!           block, Blake2b-256, the intent signing message, Ed25519 signature (expanded key, as
//!           Rust's ProtocolKeyPair), BCS of the SignedBlock and its digest. The bytes must equal
//!           Rust's (deterministic Ed25519).
//!   verify  as a peer's block arrives: BCS decode, SignedBlockVerifier.verifyAndVote (shape,
//!           epoch, author, ancestors, parent stake, transaction limits, signature; Noop
//!           transaction verifier as on the Rust side: user transactions are stage 1), digest.
//!           Output per block "ok <digest> <rejects>", as Rust prints it.
const std = @import("std");
const harness = @import("harness");
const consensus = @import("consensus");
const sig = @import("sig");
const common = @import("common.zig");

const Allocator = std.mem.Allocator;
const types = consensus.types;

pub const cases = [_][]const u8{ "n10-light", "n10-full", "n100-light", "n100-full" };

pub fn run(ctx: *harness.Ctx) anyerror!void {
    for (cases) |name| {
        if (!ctx.selected(name)) continue;
        try runCase(ctx, name);
    }
}

const Shared = struct {
    verifier: *const consensus.verifier.SignedBlockVerifier,
    blocks: []const []const u8,
    gpa: Allocator,
};

fn verifyOne(gpa: Allocator, v: *const consensus.verifier.SignedBlockVerifier, bytes: []const u8, line: ?*std.Io.Writer) void {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var votes: [256]types.TransactionIndex = undefined;
    var nv: usize = 0;
    var out: types.VerifiedBlock = undefined;
    const verdict = v.verifyAndVote(arena.allocator(), bytes, &out, &votes, &nv) catch |e| {
        if (line) |w| w.print("err {s}", .{@errorName(e)}) catch {};
        return;
    };
    if (line) |w| switch (verdict) {
        .ok => w.print("ok {x} {d}", .{ &out.digest, nv }) catch {},
        .reject => |r| w.print("err {s}", .{@tagName(r)}) catch {},
    };
}

fn verifyPar(s: *const Shared, i: usize) void {
    verifyOne(s.gpa, s.verifier, s.blocks[i], null);
}

fn runCase(ctx: *harness.Ctx, name: []const u8) !void {
    const gpa = ctx.gpa;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const path = try std.fmt.allocPrint(a, "consensus/val-bench/blocks-{s}.vec", .{name});
    const text = ctx.corpus.readFileAlloc(ctx.io, path, a, .limited(4 << 30)) catch |e| {
        ctx.fail(name, "read {s}: {s}", .{ path, @errorName(e) });
        return;
    };
    var lines = std.mem.splitScalar(u8, text, '\n');
    var stakes: std.ArrayList(u64) = .empty;
    var epoch: u64 = 0;
    var start_ms: u64 = 0;
    var genesis: std.ArrayList([32]u8) = .empty;
    var blocks: std.ArrayList([]const u8) = .empty;
    while (lines.next()) |line| {
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = it.next() orelse continue;
        if (std.mem.eql(u8, kind, "bcommittee")) {
            _ = it.next();
            epoch = try std.fmt.parseInt(u64, it.next().?, 10);
            start_ms = try std.fmt.parseInt(u64, it.next().?, 10);
            var parts = std.mem.splitScalar(u8, it.next().?, ',');
            while (parts.next()) |p| try stakes.append(a, try std.fmt.parseInt(u64, p, 10));
        } else if (std.mem.eql(u8, kind, "bgenesis")) {
            var g: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&g, it.next().?);
            try genesis.append(a, g);
        } else if (std.mem.eql(u8, kind, "bblock")) {
            const h = it.next().?;
            const b = try a.alloc(u8, h.len / 2);
            _ = try std.fmt.hexToBytes(b, h);
            try blocks.append(a, b);
        }
    }
    const pc = try consensus.config.ProtocolConfig.fromProtocol(141, .mainnet);
    const fx = try consensus.test_dag.Fixture.init(gpa, .{ .stakes = stakes.items, .epoch = epoch, .epoch_start_ms = start_ms, .protocol = pc, .own_index = null });
    defer fx.deinit();
    const keys = try a.alloc(sig.ed25519.KeyPair, stakes.items.len);
    for (fx.authorities, keys, 0..) |*au, *k, i| {
        const seed: [32]u8 = @splat(@intCast(i + 1));
        k.* = sig.ed25519.KeyPair.fromSeed(&seed);
        au.protocol_key = k.pk;
    }
    var gen_ok = genesis.items.len == fx.dag.genesis.len;
    if (gen_ok) for (fx.dag.genesis, genesis.items) |g, w| {
        gen_ok = gen_ok and std.mem.eql(u8, &g.digest, &w);
    };

    // block contents, as the proposer holds them (decoded outside the clock)
    const inner = try a.alloc(types.Block, blocks.items.len);
    for (blocks.items, inner) |b, *o| o.* = (try consensus.digest.decodeSignedBlock(a, b)).inner;

    // create: sign + serialize + digest, compare bytes with Rust's
    const ct = try a.alloc(u64, blocks.items.len);
    var create_out: std.Io.Writer.Allocating = .init(a);
    var create_diff: usize = 0;
    var bytes_total: u64 = 0;
    for (inner, blocks.items, ct) |*blk, want, *t| {
        var scratch: std.heap.ArenaAllocator = .init(gpa);
        defer scratch.deinit();
        const sa = scratch.allocator();
        const author = blk.author();
        const t0 = common.now(ctx.io);
        // as Core.tryNewBlock: two Blake2b passes, or one with ZUI_BLOCK_ONE_PASS=1
        const pending = try consensus.digest.PendingBlock.init(sa, sa, blk.*);
        const signature = keys[author].sign(&pending.message);
        const vb = try pending.seal(sa, &signature);
        const serialized = vb.serialized;
        t.* = common.since(ctx.io, t0);
        bytes_total += serialized.len;
        try create_out.writer.print("{x}\n", .{&vb.digest});
        if (!std.mem.eql(u8, serialized, want)) {
            create_diff += 1;
            if (create_diff <= 3) ctx.detail("DIFF create {s}: block bytes differ from Rust (len {d} vs {d})\n", .{ name, serialized.len, want.len });
        }
    }
    const cdg = common.digestHex(create_out.written());
    var wall: u64 = 0;
    for (ct) |x| wall += x;
    common.emit(ctx, .{ .stage = "block-create", .case = name, .mode = "sign", .threads = 1, .unit = "block", .items = ct, .count = ct.len, .wall_ns = wall, .out = &cdg, .extra = try std.fmt.allocPrint(a, ",\"bytes\":{d}", .{bytes_total}) });

    // verify, 1 thread
    var noop: consensus.verifier.NoopTransactionVerifier = .{};
    const v = consensus.verifier.SignedBlockVerifier.init(fx.context, noop.verifier(), fx.genesisRefs());
    for (blocks.items[0..@min(64, blocks.items.len)]) |b| verifyOne(gpa, &v, b, null);
    const vt = try a.alloc(u64, blocks.items.len);
    var vout: std.Io.Writer.Allocating = .init(a);
    for (blocks.items, vt) |b, *t| {
        var line: std.Io.Writer.Allocating = .init(a);
        const t0 = common.now(ctx.io);
        verifyOne(gpa, &v, b, &line.writer);
        t.* = common.since(ctx.io, t0);
        try vout.writer.writeAll(line.written());
        try vout.writer.writeByte('\n');
    }
    const vdg = common.digestHex(vout.written());
    wall = 0;
    for (vt) |x| wall += x;
    common.emit(ctx, .{ .stage = "block-verify", .case = name, .mode = "verify", .threads = 1, .unit = "block", .items = vt, .count = vt.len, .wall_ns = wall, .out = &vdg });
    // verify, 4 threads
    const sh: Shared = .{ .verifier = &v, .blocks = blocks.items, .gpa = gpa };
    const w4 = common.parWall(ctx.io, blocks.items.len, 4, 3, &sh, verifyPar);
    common.emit(ctx, .{ .stage = "block-verify", .case = name, .mode = "verify", .threads = 4, .unit = "block", .count = blocks.items.len, .wall_ns = w4, .out = &vdg });

    // equality: Rust's verify lines are not in the vector file, so compare digests with the Rust
    // timing lines (merge script) and check here that every block verified ok and was re-created
    // byte for byte.
    const not_ok = std.mem.count(u8, vout.written(), "err ");
    if (!gen_ok) {
        ctx.fail(name, "genesis digests differ from Rust", .{});
    } else if (create_diff != 0 or not_ok != 0) {
        ctx.fail(name, "{d} created blocks differ from Rust's bytes, {d} blocks not verified", .{ create_diff, not_ok });
    } else ctx.pass(name);
}
