//! Golden vectors for the signing-time checks that read state (testdata/signing.txt.zst, written
//! by tools/truth/validity `signing` from Mysten's sui-core at mainnet-v1.83.1): funds
//! withdrawals and available amounts, gasless object inputs and remaining balances, and the coin
//! deny list v1/v2 with `read_value(None)`. Each case runs `checker.checkInputs` (validity_check
//! first) over the case's objects and must give Rust's verdict and error text.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const exec = @import("exec");
const rpc_exec = @import("rpc_exec");
const messages = @import("../messages.zig");
const checker = @import("checker.zig");
const tx_mod = @import("tx.zig");
const vectors = @import("validity_vectors_test.zig");

test "signing-time checks golden vectors (Mysten 1.83.1)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const vs = try vectors.lines(arena, @embedFile("testdata/signing.txt.zst"));
    var bad: usize = 0;
    var n_ok: usize = 0;
    for (vs) |v| {
        // id pv chain epoch rgp committee chain_id objects ssd
        const f = v.fields;
        const id = f[0];
        const cfg = try protocol.get(try std.fmt.parseInt(u64, f[1], 10), .mainnet);
        var chain_id: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&chain_id, f[6]);
        var ms: rpc_exec.state.MapState = .{};
        {
            var it = std.mem.splitScalar(u8, f[7], ',');
            while (it.next()) |h| {
                if (h.len == 0) continue;
                const raw = try vectors.hexAlloc(arena, h);
                const k = exec.objects.keyOf(raw) catch |e| {
                    std.debug.print("{s}: object does not parse: {s}\n", .{ id, @errorName(e) });
                    return e;
                };
                try ms.put(arena, k.id, k.version, raw);
            }
        }
        const raw = try vectors.hexAlloc(arena, f[8]);
        const ssd = bcs.decode(types.SenderSignedData, arena, raw) catch |e| {
            std.debug.print("{s}: SenderSignedData does not decode: {s}\n", .{ id, @errorName(e) });
            return e;
        };
        const t: messages.PlainTransactionWithClaims = .{ .tx = .{ .data = ssd, .auth_signature = .{} }, .claims = &.{} };
        const u = tx_mod.fromDecoded(arena, raw, t) catch |e| {
            std.debug.print("{s}: fromDecoded: {s}\n", .{ id, @errorName(e) });
            return e;
        };
        const env: checker.Env = .{
            .cfg = cfg,
            .epoch = try std.fmt.parseInt(u64, f[3], 10),
            .chain_id = chain_id,
            .rgp = try std.fmt.parseInt(u64, f[4], 10),
            .committee_size = try std.fmt.parseInt(u32, f[5], 10),
            .state = ms.state(),
            .sig_env = undefined,
        };
        const got = checker.checkInputs(arena, &env, &u, .{}) catch |e| {
            std.debug.print("{s}: checkInputs: {s}\n", .{ id, @errorName(e) });
            return e;
        };
        if (!try vectors.sameVerdict(id, v.verdict, got, arena)) bad += 1;
        if (got == null) n_ok += 1;
    }
    std.debug.print("signing vectors: {d} cases, {d} accepted, {d} mismatches\n", .{ vs.len, n_ok, bad });
    try std.testing.expect(vs.len >= 50);
    try std.testing.expectEqual(@as(usize, 0), bad);
}
