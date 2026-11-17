//! Golden vectors for `SenderSignedData::validity_check` (testdata/validity.txt.zst, written by
//! tools/truth/validity `validity` from Mysten's sui-types at mainnet-v1.83.1): every case's
//! verdict and, for a rejection, the exact SuiError Display text, through
//! `rpc_exec.checks.senderSignedValidity` (what checker.checkValidity runs for the vote and
//! SubmitTransaction).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const rpc_exec = @import("rpc_exec");
const checks = rpc_exec.checks;

pub const Vector = struct {
    fields: [][]const u8,
    verdict: []const u8,
};

/// Lines of a vector file (common.rs format): comments skipped, fields split on tabs.
pub fn lines(arena: std.mem.Allocator, z: []const u8) ![]Vector {
    const text = try @import("harness").decompressZstd(arena, z, 1 << 26);
    var out: std.ArrayList(Vector) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fs: std.ArrayList([]const u8) = .empty;
        var ft = std.mem.splitScalar(u8, line, '\t');
        while (ft.next()) |f| try fs.append(arena, f);
        const all = fs.items;
        try out.append(arena, .{ .fields = all[0 .. all.len - 1], .verdict = all[all.len - 1] });
    }
    return out.items;
}

/// Undoes common.rs `esc`.
pub fn unescape(arena: std.mem.Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '\\' and i + 1 < s.len) {
            i += 1;
            try out.append(arena, switch (s[i]) {
                't' => '\t',
                'n' => '\n',
                else => s[i],
            });
        } else try out.append(arena, s[i]);
    }
    return out.items;
}

pub fn hexAlloc(arena: std.mem.Allocator, h: []const u8) ![]u8 {
    const out = try arena.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

/// Compares deepwave's `?Fail` with a vector verdict. Returns false (after printing) on a mismatch.
pub fn sameVerdict(id: []const u8, verdict: []const u8, got: ?checks.Fail, arena: std.mem.Allocator) !bool {
    if (std.mem.startsWith(u8, verdict, "ok")) {
        if (got) |f| {
            std.debug.print("{s}: Rust accepts, zui rejects: {s}\n", .{ id, f.message });
            return false;
        }
        return true;
    }
    const want = try unescape(arena, verdict["err ".len..]);
    const f = got orelse {
        std.debug.print("{s}: Rust rejects ({s}), zui accepts\n", .{ id, want });
        return false;
    };
    if (!std.mem.eql(u8, f.message, want)) {
        std.debug.print("{s}:\n  rust: {s}\n  zui:  {s}\n", .{ id, want, f.message });
        return false;
    }
    return true;
}

test "validity_check golden vectors (Mysten 1.83.1)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const vs = try lines(arena, @embedFile("testdata/validity.txt.zst"));
    var bad: usize = 0;
    var n_ok: usize = 0;
    for (vs) |v| {
        // id pv chain epoch rgp committee chain_id ssd
        const f = v.fields;
        const id = f[0];
        const pv = try std.fmt.parseInt(u64, f[1], 10);
        const chain: protocol.Chain = if (std.mem.eql(u8, f[2], "mainnet")) .mainnet else if (std.mem.eql(u8, f[2], "testnet")) .testnet else .unknown;
        const cfg = try protocol.get(pv, chain);
        var chain_id: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&chain_id, f[6]);
        const raw = try hexAlloc(arena, f[7]);
        const ssd = bcs.decode(types.SenderSignedData, arena, raw) catch |e| {
            std.debug.print("{s}: zui cannot decode the SenderSignedData: {s}\n", .{ id, @errorName(e) });
            bad += 1;
            continue;
        };
        const st = ssd.@"0".element();
        const td = &st.intent_message.value.V1;
        const sigs = try arena.alloc([]const u8, st.tx_signatures.len);
        for (st.tx_signatures, sigs) |s, *o| o.* = s.@"0";
        try std.testing.expectEqual(raw.len, bcs.encodedLen(types.SenderSignedData, &ssd));
        const ctx: checks.ValidityCtx = .{
            .cfg = cfg,
            .epoch = try std.fmt.parseInt(u64, f[3], 10),
            .chain_id = chain_id,
            .rgp = try std.fmt.parseInt(u64, f[4], 10),
            .committee_size = try std.fmt.parseInt(u32, f[5], 10),
        };
        const got = try checks.senderSignedValidity(arena, &ctx, td, sigs, raw.len);
        if (!try sameVerdict(id, v.verdict, got, arena)) bad += 1;
        if (got == null) n_ok += 1;
    }
    std.debug.print("validity vectors: {d} cases, {d} accepted, {d} mismatches\n", .{ vs.len, n_ok, bad });
    try std.testing.expect(vs.len >= 150);
    try std.testing.expectEqual(@as(usize, 0), bad);
}
