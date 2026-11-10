//! Replays testdata/rust_edge.txt (written by tools/truth/bcs-types/edge from Mysten's
//! sui-types 1.83.1): values whose Rust `Deserialize` checks more than the serde shape.
//! Each case must be accepted or rejected exactly as Rust does; accepted values must re-encode
//! to Rust's re-encoding (BN254 strings excepted: Rust re-renders the reduced value, deepwave keeps
//! the raw signature bytes, so only acceptance is compared for them).
const std = @import("std");
const bcs = @import("bcs");
const gen = @import("gen.zig");
const hand = @import("hand.zig");
const digest = @import("digest.zig");
const layout = @import("layout.zig");
const t = std.testing;

const data = @embedFile("testdata/rust_edge.txt");

fn hexAlloc(a: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    return std.fmt.hexToBytes(out, s);
}

fn check(comptime T: type, a: std.mem.Allocator, name: []const u8, input: []const u8, want_ok: bool, re: ?[]const u8, compare_re: bool) !void {
    const got = bcs.decode(T, a, input);
    var r = bcs.Reader.init(input);
    const skipped = blk: {
        bcs.skip(T, &r) catch break :blk false;
        r.finish() catch break :blk false;
        break :blk true;
    };
    if (got) |v| {
        if (!want_ok) {
            std.debug.print("{s}: zui accepts, Rust rejects\n", .{name});
            return error.TestUnexpectedResult;
        }
        if (compare_re) try t.expectEqualSlices(u8, re.?, try bcs.encodeAlloc(T, a, &v));
    } else |e| {
        if (want_ok) {
            std.debug.print("{s}: zui rejects ({s}), Rust accepts\n", .{ name, @errorName(e) });
            return error.TestUnexpectedResult;
        }
    }
    try t.expectEqual(want_ok, skipped);
}

test "hand-written Deserialize rules match sui-types 1.83.1" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var n: usize = 0;
    var gaps: usize = 0;
    var gaps_open: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, data, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        const name = f.next().?;
        const in_field = f.next().?;
        const verdict = f.next().?;
        if (std.mem.startsWith(u8, name, "val-")) {
            const colon = std.mem.indexOfScalar(u8, in_field, ':').?;
            const lay_bytes = try hexAlloc(a, in_field["in=".len..colon]);
            const val_bytes = try hexAlloc(a, in_field[colon + 1 ..]);
            const lay = try bcs.decode(layout.MoveTypeLayout, a, lay_bytes);
            const res = layout.decode(a, &lay, val_bytes);
            if (std.mem.eql(u8, verdict, "ok")) {
                const v = res catch |e| {
                    std.debug.print("{s}: zui rejects ({s}), Rust accepts\n", .{ name, @errorName(e) });
                    return error.TestUnexpectedResult;
                };
                const want = try hexAlloc(a, f.next().?["re=".len..]);
                try t.expectEqualSlices(u8, want, try layout.encodeAlloc(a, &v));
            } else if (res) |_| {
                std.debug.print("{s}: zui accepts, Rust rejects\n", .{name});
                return error.TestUnexpectedResult;
            } else |_| {}
            n += 1;
            continue;
        }
        const input = try hexAlloc(a, in_field["in=".len..]);
        if (std.mem.startsWith(u8, name, "dg-")) {
            const want = try hexAlloc(a, verdict["d=".len..]);
            const got = if (std.mem.eql(u8, name, "dg-SenderSignedData"))
                digest.senderSignedDataDigest(input)
            else if (std.mem.eql(u8, name, "dg-GlobalStateHash"))
                digest.globalStateHashDigest(input)
            else
                return error.UnknownCase;
            try t.expectEqualSlices(u8, want, &got);
            n += 1;
            continue;
        }
        const ok = std.mem.eql(u8, verdict, "ok");
        const re: ?[]const u8 = if (ok) try hexAlloc(a, f.next().?["re=".len..]) else null;
        if (std.mem.startsWith(u8, name, "party-")) {
            try check(gen.Owner, a, name, input, ok, re, true);
        } else if (std.mem.startsWith(u8, name, "dur-")) {
            try check(hand.Duration, a, name, input, ok, re, true);
        } else if (std.mem.startsWith(u8, name, "fq-")) {
            try check(hand.Bn254Fq, a, name, input, ok, re, true);
        } else if (std.mem.startsWith(u8, name, "fr-")) {
            try check(hand.Bn254Fr, a, name, input, ok, re, true);
        } else if (std.mem.startsWith(u8, name, "ms-") or std.mem.startsWith(u8, name, "lg-")) {
            try check(gen.GenericSignature, a, name, input, ok, null, false);
            if (ok) {
                const g = try bcs.decode(gen.GenericSignature, a, input);
                const canon = try hand.GenericSignature.canonical(a, g.@"0");
                const cg: gen.GenericSignature = .{ .@"0" = canon };
                try t.expectEqualSlices(u8, re.?, try bcs.encodeAlloc(gen.GenericSignature, a, &cg));
            }
        } else if (std.mem.startsWith(u8, name, "depth-typetag-")) {
            try check(gen.TypeTag, a, name, input, ok, re, true);
        } else if (std.mem.startsWith(u8, name, "txdepth-")) {
            // A type argument nested inside TransactionData shares the 500 budget with every
            // enclosing container (Rust: 493 vectors pass, 494 fail).
            try check(gen.TransactionData, a, name, input, ok, re, true);
        } else if (std.mem.startsWith(u8, name, "depth-typeinput-")) {
            try check(gen.TypeInput, a, name, input, ok, re, true);
        } else if (std.mem.startsWith(u8, name, "lay-")) {
            try check(layout.MoveTypeLayout, a, name, input, ok, re, true);
        } else if (std.mem.startsWith(u8, name, "zk-")) {
            try check(gen.GenericSignature, a, name, input, ok, null, false);
            const g = try bcs.decode(gen.GenericSignature, a, input);
            const canon = try hand.GenericSignature.canonical(a, g.@"0");
            const cg: gen.GenericSignature = .{ .@"0" = canon };
            try t.expectEqualSlices(u8, re.?, try bcs.encodeAlloc(gen.GenericSignature, a, &cg));
        } else if (std.mem.startsWith(u8, name, "gap-")) {
            // Rust rejects these and deepwave does not yet (CONTRACTS.md 2.3): gap-zk-* in
            // ZkLoginInputs::init (JWT header / iss claim parsing), gap-lg-* in the public key
            // parsers (point validity). Tracked so that closing a gap is visible: deepwave must never
            // reject what Rust accepts.
            gaps += 1;
            if (ok) {
                _ = bcs.decode(gen.GenericSignature, a, input) catch return error.TestUnexpectedResult;
            } else if (bcs.decode(gen.GenericSignature, a, input)) |_| {
                gaps_open += 1;
            } else |_| {}
        } else if (std.mem.startsWith(u8, name, "ssd-")) {
            try check(gen.SenderSignedData, a, name, input, ok, re, true);
        } else return error.UnknownCase;
        n += 1;
    }
    try t.expect(n >= 150);
    try t.expect(gaps >= 10);
    // Known open gaps (deepwave accepts, Rust rejects): six zkLogin init checks, four key points.
    try t.expectEqual(gaps, gaps_open);
}

test "legacy multisig base64 keys accept every PublicKey::decode_base64 flag and SEC1 tag" {
    const enc = std.base64.standard.Encoder;
    var raw: [1 + 1952]u8 = undefined;
    var buf: [4096]u8 = undefined;
    // flag, key length, SEC1 tag (first key byte), accepted
    for ([_]struct { u8, usize, u8, bool }{
        .{ 0, 32, 0, true },  .{ 1, 33, 2, true },  .{ 1, 33, 3, true },  .{ 1, 65, 4, true },
        .{ 1, 65, 6, true },  .{ 2, 33, 2, true },  .{ 2, 33, 5, true },  .{ 2, 65, 4, true },
        .{ 6, 33, 3, true },  .{ 6, 65, 4, true },  .{ 7, 1952, 0, true }, .{ 1, 33, 0, false },
        .{ 1, 33, 5, false }, .{ 1, 65, 7, false }, .{ 2, 33, 0, false }, .{ 2, 65, 6, false },
        .{ 2, 1, 0, false },  .{ 3, 33, 2, false }, .{ 4, 96, 0, false }, .{ 5, 33, 2, false },
        .{ 6, 32, 2, false }, .{ 7, 1951, 0, false },
    }) |c| {
        @memset(&raw, 0);
        raw[0] = c[0];
        raw[1] = c[2];
        const s = enc.encode(&buf, raw[0 .. 1 + c[1]]);
        var w: [4200]u8 = undefined;
        var bw = bcs.Writer.init(&w);
        try bw.uleb32(@intCast(s.len));
        try bw.bytes(s);
        var r = bcs.Reader.init(bw.written());
        const ok = if (bcs.skip(hand.Base64PublicKey, &r)) true else |_| false;
        try t.expectEqual(c[3], ok);
    }
}

test "View.payload is null for an inactive variant" {
    const E = union(enum) { a: u8, b: u16 };
    const enc = [_]u8{ 1, 0x34, 0x12 };
    const v = try bcs.View(E).init(&enc);
    try t.expect(v.payload("a") == null);
    const p = v.payload("b").?;
    try t.expectEqualSlices(u8, &.{ 0x34, 0x12 }, p.bytes);
}
