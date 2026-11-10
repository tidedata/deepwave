//! Conformance suite `hash` of the crypto-hash lane (CONTRACTS.md 3.3, 5.3).
//!
//! Items (all must pass, no skips):
//!   syn/<line>/<alg>      synthetic.tsv.zst: vectors made by `tools/truth/crypto-hash gen` from
//!                         fastcrypto (Blake2b256, Sha256, Sha512, Sha3_256, Sha3_512, Keccak256,
//!                         hmac_sha3_256, hkdf_sha3_256) and its backend crates (Sha384, HMAC and
//!                         HKDF over SHA-256). Every length 0..=1100 plus block edges up to 5 MiB;
//!                         HMAC keys around block sizes; HKDF with empty/odd salts, output
//!                         lengths 0..10000 including the 255*L limit and its error.
//!                         Each hash vector is also streamed in several chunkings.
//!   chk/<seq>.chk         every corpus checkpoint blob hashed by all seven hashers vs Rust.
//!   nist/..., keccak/..., blake2/..., wycheproof/..., cavp-hmac/...
//!                         official vectors under $ZUI_CORPUS/vectors/hash/upstream/ (sources and
//!                         sha256 in SOURCES.txt): NIST CAVP SHA-2 and SHA-3 (short, long, Monte
//!                         Carlo), Keccak team KATs (byte-aligned lengths: deepwave hashes bytes), BLAKE2
//!                         reference KATs (BLAKE2b, keyed), Wycheproof HMAC-SHA256, HMAC-SHA3-256,
//!                         HKDF-SHA256, NIST CAVP HMAC-SHA256.
const std = @import("std");
const harness = @import("harness");
const blake2b = @import("blake2b.zig");
const sha2 = @import("sha2.zig");
const keccak = @import("keccak.zig");
const hmac = @import("hmac.zig");

const dir = "vectors/hash";

pub const suites = [_]harness.Suite{
    .{
        .name = "hash",
        .lane = "crypto-hash",
        .doc = "hash/HMAC/HKDF outputs vs fastcrypto + NIST/RFC/Wycheproof vectors, and every corpus blob",
        .run = run,
        .bench = bench,
        .baselines = &baselines,
    },
};

const bench_algs = [_][]const u8{ "blake2b256", "sha256", "sha512", "sha3_256", "sha3_512", "keccak256" };
const bench_small = [_]usize{ 32, 128, 512, 4096 };
const small_algs = [_][]const u8{ "blake2b256", "sha256", "keccak256" };

const baselines = blk: {
    var b: [bench_algs.len + bench_small.len * small_algs.len + 1]harness.Baseline = undefined;
    var n = 0;
    for (bench_algs) |a| {
        b[n] = .{ .name = "blob-" ++ a, .argv = &.{ "{release}/zui-truth-hash", "bench", "blob-" ++ a } };
        n += 1;
    }
    for (bench_small) |sz| for (small_algs) |a| {
        const nm = std.fmt.comptimePrint("small{d}-{s}", .{ sz, a });
        b[n] = .{ .name = nm, .argv = &.{ "{release}/zui-truth-hash", "bench", nm } };
        n += 1;
    };
    b[n] = .{ .name = "hmac-sha3-256-small", .argv = &.{ "{release}/zui-truth-hash", "bench", "hmac-sha3-256-small" } };
    break :blk b;
};

// ---------------------------------------------------------------------------------------------
// Algorithms by name

const Alg = enum { blake2b256, sha256, sha384, sha512, sha3_256, sha3_512, keccak256 };
const hash_algs = [_]Alg{ .blake2b256, .sha256, .sha384, .sha512, .sha3_256, .sha3_512, .keccak256 };

fn algOf(name: []const u8) ?Alg {
    return std.meta.stringToEnum(Alg, name);
}

fn digestLen(a: Alg) usize {
    return switch (a) {
        inline else => |x| hasherOf(x).digest_length,
    };
}

fn hasherOf(comptime a: Alg) type {
    return switch (a) {
        .blake2b256 => blake2b.Blake2b256,
        .sha256 => sha2.Sha256,
        .sha384 => sha2.Sha384,
        .sha512 => sha2.Sha512,
        .sha3_256 => keccak.Sha3_256,
        .sha3_512 => keccak.Sha3_512,
        .keccak256 => keccak.Keccak256,
    };
}

fn hashOne(a: Alg, msg: []const u8, out: []u8) void {
    switch (a) {
        inline else => |x| {
            const H = hasherOf(x);
            H.hash(msg, out[0..H.digest_length]);
        },
    }
}

/// Same digest through the streaming interface, feeding `chunk(i)` bytes at a time.
fn hashStreamed(a: Alg, msg: []const u8, pattern: u8, out: []u8) void {
    switch (a) {
        inline else => |x| {
            const H = hasherOf(x);
            var h = H.init();
            var off: usize = 0;
            var i: usize = 0;
            while (off < msg.len) : (i += 1) {
                const want: usize = switch (pattern) {
                    0 => 1 + (i * 7 + 3) % 200, // ragged small chunks
                    1 => 4093, // odd stride, crosses every block edge
                    else => msg.len / 3 + 1,
                };
                const n = @min(want, msg.len - off);
                h.update(msg[off..][0..n]);
                off += n;
            }
            h.final(out[0..H.digest_length]);
        },
    }
}

// ---------------------------------------------------------------------------------------------
// Vector argument decoding

fn splitmix(state: *u64) u64 {
    state.* +%= 0x9E3779B97F4A7C15;
    var z = state.*;
    z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
    z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
    return z ^ (z >> 31);
}

/// `@len,seed` (generated) or lowercase hex.
fn decodeArg(arena: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len > 0 and s[0] == '@') {
        const comma = std.mem.indexOfScalar(u8, s, ',') orelse return error.BadVector;
        const len = try std.fmt.parseInt(usize, s[1..comma], 10);
        var seed = try std.fmt.parseInt(u64, s[comma + 1 ..], 10);
        const out = try arena.alloc(u8, len);
        var i: usize = 0;
        while (i < len) : (i += 8) {
            var w: [8]u8 = undefined;
            std.mem.writeInt(u64, &w, splitmix(&seed), .little);
            const n = @min(8, len - i);
            @memcpy(out[i..][0..n], w[0..n]);
        }
        return out;
    }
    return decodeHex(arena, s);
}

fn decodeHex(arena: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len % 2 != 0) return error.BadVector;
    const out = try arena.alloc(u8, s.len / 2);
    _ = std.fmt.hexToBytes(out, s) catch return error.BadVector;
    return out;
}

/// Truth is lowercase hex of any length, decoded and compared as bytes.
fn cmpHex(arena: std.mem.Allocator, c: *harness.Check, what: []const u8, want_hex: []const u8, got: []const u8) void {
    const want = decodeHex(arena, want_hex) catch {
        c.failf("{s}: truth is not hex: {s}", .{ what, want_hex[0..@min(want_hex.len, 40)] });
        return;
    };
    c.bytes(what, want, got);
}

fn hexLower(arena: std.mem.Allocator, b: []const u8) ![]u8 {
    return std.fmt.allocPrint(arena, "{x}", .{b});
}

// ---------------------------------------------------------------------------------------------
// Shared state

const State = struct {
    synthetic: []const u8,
    /// chk file name -> line of "<alg>=<hex>" tab-separated fields
    blobs: std.StringHashMapUnmanaged([]const u8),
};

const shards = 64;

fn run(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const syn_z = try ctx.corpus.readFileAlloc(ctx.io, dir ++ "/synthetic.tsv.zst", arena, .limited(1 << 30));
    const synthetic = try harness.decompressZstd(arena, syn_z, 1 << 31);
    const blobs_z = try ctx.corpus.readFileAlloc(ctx.io, dir ++ "/corpus-blobs.tsv.zst", arena, .limited(1 << 30));
    const blobs_text = try harness.decompressZstd(arena, blobs_z, 1 << 31);
    var state: State = .{ .synthetic = synthetic, .blobs = .empty };
    {
        var it = harness.lines(blobs_text);
        while (it.next()) |line| {
            const tab = std.mem.indexOfScalar(u8, line, '\t') orelse return error.BadVector;
            try state.blobs.put(arena, line[0..tab], line[tab + 1 ..]);
        }
    }

    // Work units: synthetic shards, upstream files, corpus blobs.
    var names: std.ArrayList([]const u8) = .empty;
    for (0..shards) |k| try names.append(arena, try std.fmt.allocPrint(arena, "syn/{d}", .{k}));
    try names.append(arena, "many/0");
    for (upstream_units) |u| try names.append(arena, try std.fmt.allocPrint(arena, "up/{s}", .{u}));
    const chk = try ctx.listFiles("chk", ".chk");
    defer ctx.freeNames(chk);
    for (chk) |c| try names.append(arena, try std.fmt.allocPrint(arena, "chk/{s}", .{c}));
    // Every blob in the truth must exist in the corpus and vice versa.
    if (chk.len != state.blobs.count()) {
        ctx.fail("chk", "corpus has {d} blobs, truth file has {d}", .{ chk.len, state.blobs.count() });
    }

    try ctx.forEachName(names.items, &state, unit);
}

fn unit(state: *const State, ctx: *harness.Ctx, name: []const u8) anyerror!void {
    if (std.mem.startsWith(u8, name, "syn/")) {
        const k = try std.fmt.parseInt(usize, name[4..], 10);
        return runSynthetic(state, ctx, k);
    }
    if (std.mem.startsWith(u8, name, "many/")) return runMany(state, ctx);
    if (std.mem.startsWith(u8, name, "up/")) return runUpstream(ctx, name[3..]);
    return runBlob(state, ctx, name[4..]);
}

// ---------------------------------------------------------------------------------------------
// Synthetic vectors

fn runSynthetic(state: *const State, ctx: *harness.Ctx, shard: usize) !void {
    var it = harness.lines(state.synthetic);
    var n: usize = 0;
    while (it.next()) |line| : (n += 1) {
        if (n % shards != shard) continue;
        if (ctx.done()) return;
        ctx.nextItem();
        var f: [8][]const u8 = undefined;
        var nf: usize = 0;
        var parts = std.mem.splitScalar(u8, line, '\t');
        while (parts.next()) |p| : (nf += 1) {
            if (nf == f.len) return error.BadVector;
            f[nf] = p;
        }
        const alg = f[0];
        const want = f[nf - 1];
        const args = f[1 .. nf - 1];
        const arena = ctx.scratch();
        const id = try std.fmt.allocPrint(arena, "syn/{d}/{s}", .{ n, alg });
        if (!ctx.selected(id)) continue;
        try synthetic1(ctx, id, alg, args, want);
    }
}

fn synthetic1(ctx: *harness.Ctx, id: []const u8, alg: []const u8, args: []const []const u8, want: []const u8) !void {
    const arena = ctx.scratch();
    var c = ctx.check(id);
    if (algOf(alg)) |a| {
        const msg = try decodeArg(arena, args[0]);
        var out: [64]u8 = undefined;
        const dl = digestLen(a);
        hashOne(a, msg, &out);
        cmpHex(arena, &c, "one-shot", want, out[0..dl]);
        for (0..3) |pat| {
            var o2: [64]u8 = undefined;
            hashStreamed(a, msg, @intCast(pat), &o2);
            c.bytes("streamed", out[0..dl], o2[0..dl]);
        }
        _ = c.finish();
        return;
    }
    const lowered = try std.fmt.allocPrint(arena, "{s}", .{alg});
    if (std.mem.eql(u8, lowered, "hmac_sha3_256")) {
        const key = try decodeArg(arena, args[0]);
        const msg = try decodeArg(arena, args[1]);
        const got = hmac.Hmac(keccak.Sha3_256).mac(key, msg);
        cmpHex(arena, &c, "hmac_sha3_256", want, &got);
        // streamed in two halves
        var m = hmac.Hmac(keccak.Sha3_256).init(key);
        m.update(msg[0 .. msg.len / 2]);
        m.update(msg[msg.len / 2 ..]);
        var o: [32]u8 = undefined;
        m.final(&o);
        c.bytes("hmac streamed", &got, &o);
    } else if (std.mem.eql(u8, lowered, "hmac_sha256")) {
        const key = try decodeArg(arena, args[0]);
        const msg = try decodeArg(arena, args[1]);
        const got = hmac.Hmac(sha2.Sha256).mac(key, msg);
        cmpHex(arena, &c, "hmac_sha256", want, &got);
    } else if (std.mem.eql(u8, lowered, "hkdf_sha3_256")) {
        const ikm = try decodeArg(arena, args[0]);
        const salt = try decodeArg(arena, args[1]);
        const info = try decodeArg(arena, args[2]);
        const len = try std.fmt.parseInt(usize, args[3], 10);
        const out = try arena.alloc(u8, len);
        const K = hmac.Hkdf(keccak.Sha3_256);
        const prk = K.extract(salt, ikm);
        if (K.expand(&prk, info, out)) |_| {
            cmpHex(arena, &c, "hkdf_sha3_256", want, out);
        } else |_| {
            c.bytes("hkdf_sha3_256 error", want, "ERR");
        }
    } else if (std.mem.eql(u8, lowered, "hkdf_sha256_extract")) {
        const salt = try decodeArg(arena, args[0]);
        const ikm = try decodeArg(arena, args[1]);
        const got = hmac.Hkdf(sha2.Sha256).extract(salt, ikm);
        cmpHex(arena, &c, "hkdf_sha256_extract", want, &got);
    } else if (std.mem.eql(u8, lowered, "hkdf_sha256_expand")) {
        const prk_b = try decodeArg(arena, args[0]);
        const info = try decodeArg(arena, args[1]);
        const len = try std.fmt.parseInt(usize, args[2], 10);
        const out = try arena.alloc(u8, len);
        if (prk_b.len != 32) return error.BadVector;
        if (hmac.Hkdf(sha2.Sha256).expand(prk_b[0..32], info, out)) |_| {
            cmpHex(arena, &c, "hkdf_sha256_expand", want, out);
        } else |_| {
            c.bytes("hkdf_sha256_expand error", want, "ERR");
        }
    } else {
        c.failf("unknown vector algorithm {s}", .{alg});
    }
    _ = c.finish();
}

/// Multi-buffer Blake2b-256 over every synthetic blake2b256 vector at once (mixed lengths, each
/// message cut into three parts), against the same truth.
fn runMany(state: *const State, ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var inputs: std.ArrayList([]const []const u8) = .empty;
    var wants: std.ArrayList([]const u8) = .empty;
    var ids: std.ArrayList(usize) = .empty;
    var it = harness.lines(state.synthetic);
    var n: usize = 0;
    while (it.next()) |line| : (n += 1) {
        if (!std.mem.startsWith(u8, line, "blake2b256\t")) continue;
        var parts = std.mem.splitScalar(u8, line, '\t');
        _ = parts.next();
        const msg = try decodeArg(arena, parts.next().?);
        const want = parts.next().?;
        const a = msg.len / 3;
        const b = msg.len / 2;
        const p = try arena.alloc([]const u8, 3);
        p[0] = msg[0..a];
        p[1] = msg[a..b];
        p[2] = msg[b..];
        try inputs.append(arena, p);
        try wants.append(arena, want);
        try ids.append(arena, n);
    }
    const out = try arena.alloc([32]u8, inputs.items.len);
    blake2b.blake2b256Many(inputs.items, out);
    for (out, wants.items, ids.items) |got, want, line_no| {
        const id = try std.fmt.allocPrint(arena, "many/{d}/blake2b256", .{line_no});
        var c = ctx.check(id);
        cmpHex(arena, &c, "blake2b256Many", want, &got);
        _ = c.finish();
    }
}

// ---------------------------------------------------------------------------------------------
// Corpus blobs

fn runBlob(state: *const State, ctx: *harness.Ctx, file: []const u8) !void {
    const arena = ctx.scratch();
    const id = try std.fmt.allocPrint(arena, "chk/{s}", .{file});
    const truth = state.blobs.get(file) orelse {
        ctx.fail(id, "no truth line for this blob", .{});
        return;
    };
    const blob = try ctx.readFile(id, 1 << 30);
    var c = ctx.check(id);
    var fields = std.mem.splitScalar(u8, truth, '\t');
    var seen: usize = 0;
    while (fields.next()) |fld| {
        const eq = std.mem.indexOfScalar(u8, fld, '=') orelse return error.BadVector;
        const a = algOf(fld[0..eq]) orelse {
            c.failf("unknown algorithm {s}", .{fld[0..eq]});
            continue;
        };
        var out: [64]u8 = undefined;
        const dl = digestLen(a);
        hashOne(a, blob, &out);
        cmpHex(arena, &c, @tagName(a), fld[eq + 1 ..], out[0..dl]);
        var o2: [64]u8 = undefined;
        hashStreamed(a, blob, 1, &o2);
        c.bytes("streamed", out[0..dl], o2[0..dl]);
        seen += 1;
    }
    if (seen != hash_algs.len) c.failf("truth line has {d} algorithms, expected {d}", .{ seen, hash_algs.len });
    _ = c.finish();
}

// ---------------------------------------------------------------------------------------------
// Upstream vectors

const up = "vectors/hash/upstream/";
const upstream_units = [_][]const u8{
    "nist/SHA256ShortMsg",              "nist/SHA256LongMsg",              "nist/SHA256Monte",
    "nist/SHA384ShortMsg",              "nist/SHA384LongMsg",              "nist/SHA384Monte",
    "nist/SHA512ShortMsg",              "nist/SHA512LongMsg",              "nist/SHA512Monte",
    "nist/SHA3_256ShortMsg",            "nist/SHA3_256LongMsg",            "nist/SHA3_256Monte",
    "nist/SHA3_512ShortMsg",            "nist/SHA3_512LongMsg",            "nist/SHA3_512Monte",
    "keccak/ShortMsgKAT_256",           "keccak/LongMsgKAT_256",
    "blake2/blake2b",
    "wycheproof/hmac_sha256",           "wycheproof/hmac_sha3_256",        "wycheproof/hkdf_sha256",
    "cavp-hmac/HMAC-SHA256",
};

const NistFamily = struct { name: []const u8, dir: []const u8, alg: Alg };
const nist_families = [_]NistFamily{
    .{ .name = "SHA256", .dir = "x/sha2/shabytetestvectors/", .alg = .sha256 },
    .{ .name = "SHA384", .dir = "x/sha2/shabytetestvectors/", .alg = .sha384 },
    .{ .name = "SHA512", .dir = "x/sha2/shabytetestvectors/", .alg = .sha512 },
    .{ .name = "SHA3_256", .dir = "x/sha3/", .alg = .sha3_256 },
    .{ .name = "SHA3_512", .dir = "x/sha3/", .alg = .sha3_512 },
};

fn runUpstream(ctx: *harness.Ctx, u: []const u8) !void {
    if (std.mem.startsWith(u8, u, "nist/")) {
        const file = u["nist/".len..];
        for (nist_families) |f| {
            for ([_][]const u8{ "ShortMsg", "LongMsg", "Monte" }) |kind| {
                if (file.len != f.name.len + kind.len) continue;
                if (!std.mem.startsWith(u8, file, f.name) or !std.mem.endsWith(u8, file, kind)) continue;
                const path = try std.fmt.allocPrint(ctx.scratch(), up ++ "{s}{s}.rsp", .{ f.dir, file });
                const text = try ctx.readFile(path, 64 << 20);
                if (std.mem.eql(u8, kind, "Monte")) return runMonte(ctx, u, f.alg, text);
                return runLenMsgMd(ctx, u, f.alg, text);
            }
        }
        return error.UnknownUnit;
    }
    if (std.mem.eql(u8, u, "keccak/ShortMsgKAT_256") or std.mem.eql(u8, u, "keccak/LongMsgKAT_256")) {
        const path = try std.fmt.allocPrint(ctx.scratch(), up ++ "x/keccak/KeccakKAT/{s}.txt", .{u[7..]});
        const text = try ctx.readFile(path, 64 << 20);
        return runLenMsgMd(ctx, u, .keccak256, text);
    }
    if (std.mem.eql(u8, u, "blake2/blake2b")) return runBlake2Kat(ctx, u);
    if (std.mem.startsWith(u8, u, "wycheproof/")) return runWycheproof(ctx, u);
    if (std.mem.eql(u8, u, "cavp-hmac/HMAC-SHA256")) return runCavpHmac(ctx, u);
    return error.UnknownUnit;
}

/// "Len = <bits>", "Msg = <hex>", "MD = <hex>" blocks. Only byte-aligned lengths exist in the
/// SHA-2/SHA-3 byte-oriented files; the Keccak team files also have bit lengths, which a
/// byte-oriented hasher has no input for: those blocks are not items.
fn runLenMsgMd(ctx: *harness.Ctx, unit_name: []const u8, alg: Alg, text: []const u8) !void {
    const arena = ctx.scratch();
    var it = harness.lines(text);
    var len_bits: ?usize = null;
    var msg: ?[]const u8 = null;
    var idx: usize = 0;
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (std.mem.startsWith(u8, line, "Len = ")) {
            len_bits = try std.fmt.parseInt(usize, line[6..], 10);
        } else if (std.mem.startsWith(u8, line, "Msg = ")) {
            msg = line[6..];
        } else if (std.mem.startsWith(u8, line, "MD = ")) {
            defer idx += 1;
            const bits = len_bits orelse return error.BadVector;
            if (bits % 8 != 0) continue;
            if (ctx.done()) return;
            const id = try std.fmt.allocPrint(arena, "{s}/{d}/Len={d}", .{ unit_name, idx, bits });
            if (!ctx.selected(id)) continue;
            const m_all = try decodeHex(arena, msg orelse return error.BadVector);
            const m = if (bits == 0) m_all[0..0] else m_all[0 .. bits / 8];
            if (m.len != bits / 8) return error.BadVector;
            const want = try decodeHex(arena, line[5..]);
            var out: [64]u8 = undefined;
            const dl = digestLen(alg);
            hashOne(alg, m, &out);
            var c = ctx.check(id);
            c.bytes("digest", want, out[0..dl]);
            hashStreamed(alg, m, 0, &out);
            c.bytes("streamed", want, out[0..dl]);
            _ = c.finish();
        }
    }
}

/// NIST CAVP Monte Carlo (SHA-2: MD[i] = H(MD[i-3] || MD[i-2] || MD[i-1]); SHA-3: MD[i] = H(MD[i-1])).
fn runMonte(ctx: *harness.Ctx, unit_name: []const u8, alg: Alg, text: []const u8) !void {
    const arena = ctx.scratch();
    const dl = digestLen(alg);
    const is_sha3 = alg == .sha3_256 or alg == .sha3_512;
    var it = harness.lines(text);
    var seed: [64]u8 = undefined;
    var have_seed = false;
    var state: [64]u8 = undefined; // current Seed for the next COUNT
    var count: usize = 0;
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (std.mem.startsWith(u8, line, "Seed = ")) {
            const s = try decodeHex(arena, line[7..]);
            if (s.len != dl) return error.BadVector;
            @memcpy(seed[0..dl], s);
            @memcpy(state[0..dl], s);
            have_seed = true;
        } else if (std.mem.startsWith(u8, line, "MD = ")) {
            if (!have_seed) return error.BadVector;
            if (ctx.done()) return;
            const id = try std.fmt.allocPrint(arena, "{s}/COUNT={d}", .{ unit_name, count });
            defer count += 1;
            var md: [64]u8 = undefined;
            if (is_sha3) {
                var m: [64]u8 = undefined;
                @memcpy(m[0..dl], state[0..dl]);
                for (0..1000) |_| {
                    hashOne(alg, m[0..dl], &md);
                    @memcpy(m[0..dl], md[0..dl]);
                }
            } else {
                var mds: [3][64]u8 = undefined;
                @memcpy(mds[0][0..dl], state[0..dl]);
                @memcpy(mds[1][0..dl], state[0..dl]);
                @memcpy(mds[2][0..dl], state[0..dl]);
                for (3..1003) |_| {
                    var msg: [192]u8 = undefined;
                    @memcpy(msg[0..dl], mds[0][0..dl]);
                    @memcpy(msg[dl .. 2 * dl], mds[1][0..dl]);
                    @memcpy(msg[2 * dl .. 3 * dl], mds[2][0..dl]);
                    mds[0] = mds[1];
                    mds[1] = mds[2];
                    hashOne(alg, msg[0 .. 3 * dl], &mds[2]);
                }
                md = mds[2];
            }
            const want = try decodeHex(arena, line[5..]);
            _ = ctx.expectBytes(id, "monte digest", want, md[0..dl]);
            @memcpy(state[0..dl], md[0..dl]);
        } else if (std.mem.startsWith(u8, line, "COUNT = ")) {
            // MD follows
        }
    }
}

fn parseJson(ctx: *harness.Ctx, rel: []const u8) !std.json.Value {
    const text = try ctx.readFile(rel, 64 << 20);
    return std.json.parseFromSliceLeaky(std.json.Value, ctx.scratch(), text, .{});
}

fn runBlake2Kat(ctx: *harness.Ctx, unit_name: []const u8) !void {
    const arena = ctx.scratch();
    const root = try parseJson(ctx, up ++ "blake2-kat.json");
    var idx: usize = 0;
    for (root.array.items) |e| {
        defer idx += 1;
        const o = e.object;
        if (!std.mem.eql(u8, o.get("hash").?.string, "blake2b")) continue;
        if (ctx.done()) return;
        const in = try decodeHex(arena, o.get("in").?.string);
        const key = try decodeHex(arena, o.get("key").?.string);
        const want = try decodeHex(arena, o.get("out").?.string);
        const id = try std.fmt.allocPrint(arena, "{s}/{d}/in={d}/key={d}", .{ unit_name, idx, in.len, key.len });
        if (!ctx.selected(id)) continue;
        var c = ctx.check(id);
        var h = blake2b.Blake2b.init(@intCast(want.len), key);
        h.update(in);
        var out: [64]u8 = undefined;
        h.final(out[0..want.len]);
        c.bytes("blake2b", want, out[0..want.len]);
        // streamed bytewise
        var h2 = blake2b.Blake2b.init(@intCast(want.len), key);
        for (in) |b| h2.update(&.{b});
        h2.final(out[0..want.len]);
        c.bytes("blake2b bytewise", want, out[0..want.len]);
        _ = c.finish();
    }
}

fn runWycheproof(ctx: *harness.Ctx, unit_name: []const u8) !void {
    const arena = ctx.scratch();
    const file = unit_name["wycheproof/".len..];
    const rel = try std.fmt.allocPrint(arena, up ++ "{s}_test.json", .{file});
    const root = try parseJson(ctx, rel);
    const groups = root.object.get("testGroups").?.array.items;
    for (groups) |g| {
        for (g.object.get("tests").?.array.items) |t| {
            if (ctx.done()) return;
            const o = t.object;
            const tc = o.get("tcId").?.integer;
            const id = try std.fmt.allocPrint(arena, "{s}/tc{d}", .{ unit_name, tc });
            if (!ctx.selected(id)) continue;
            const result = o.get("result").?.string;
            const valid = std.mem.eql(u8, result, "valid");
            var c = ctx.check(id);
            if (std.mem.eql(u8, file, "hkdf_sha256")) {
                const ikm = try decodeHex(arena, o.get("ikm").?.string);
                const salt = try decodeHex(arena, o.get("salt").?.string);
                const info = try decodeHex(arena, o.get("info").?.string);
                const size: usize = @intCast(o.get("size").?.integer);
                const okm = try decodeHex(arena, o.get("okm").?.string);
                const out = try arena.alloc(u8, size);
                const K = hmac.Hkdf(sha2.Sha256);
                const prk = K.extract(salt, ikm);
                if (K.expand(&prk, info, out)) |_| {
                    if (valid) c.bytes("okm", okm, out) else c.failf("expected failure ({s}) but derived {d} bytes", .{ result, size });
                } else |_| {
                    if (valid) c.failf("expected success but OutputTooLong for size {d}", .{size}) else c.eql("rejected", true, true);
                }
            } else {
                const key = try decodeHex(arena, o.get("key").?.string);
                const msg = try decodeHex(arena, o.get("msg").?.string);
                const tag = try decodeHex(arena, o.get("tag").?.string);
                const full: [32]u8 = if (std.mem.eql(u8, file, "hmac_sha256"))
                    hmac.Hmac(sha2.Sha256).mac(key, msg)
                else
                    hmac.Hmac(keccak.Sha3_256).mac(key, msg);
                const tag_len: usize = @intCast(@divExact(g.object.get("tagSize").?.integer, 8));
                if (tag_len > 32) return error.BadVector;
                const eq = tag.len == tag_len and std.mem.eql(u8, tag, full[0..tag_len]);
                if (valid) {
                    c.bytes("tag", tag, full[0..tag_len]);
                } else if (eq) {
                    c.failf("invalid vector ({s}) verified", .{result});
                }
            }
            _ = c.finish();
        }
    }
}

fn runCavpHmac(ctx: *harness.Ctx, unit_name: []const u8) !void {
    const arena = ctx.scratch();
    const text = try ctx.readFile(up ++ "x/hmac/HMAC.rsp", 64 << 20);
    var it = harness.lines(text);
    var in_sha256 = false;
    var count: usize = 0;
    var key: ?[]const u8 = null;
    var msg: ?[]const u8 = null;
    var tlen: usize = 0;
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (std.mem.startsWith(u8, line, "[L=")) {
            in_sha256 = std.mem.eql(u8, line, "[L=32]");
        } else if (!in_sha256) {
            continue;
        } else if (std.mem.startsWith(u8, line, "Count = ")) {
            count = try std.fmt.parseInt(usize, line[8..], 10);
        } else if (std.mem.startsWith(u8, line, "Tlen = ")) {
            tlen = try std.fmt.parseInt(usize, line[7..], 10);
        } else if (std.mem.startsWith(u8, line, "Key = ")) {
            key = line[6..];
        } else if (std.mem.startsWith(u8, line, "Msg = ")) {
            msg = line[6..];
        } else if (std.mem.startsWith(u8, line, "Mac = ")) {
            if (ctx.done()) return;
            const id = try std.fmt.allocPrint(arena, "{s}/Count={d}", .{ unit_name, count });
            if (!ctx.selected(id)) continue;
            const k = try decodeHex(arena, key orelse return error.BadVector);
            const m = try decodeHex(arena, msg orelse return error.BadVector);
            const want = try decodeHex(arena, line[6..]);
            if (want.len != tlen) return error.BadVector;
            const got = hmac.Hmac(sha2.Sha256).mac(k, m);
            _ = ctx.expectBytes(id, "mac", want, got[0..tlen]);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Bench

const BenchState = struct {
    blobs: []const []const u8,
    alg: Alg,
};

fn passBlobs(s: BenchState) !void {
    var out: [64]u8 = undefined;
    for (s.blobs) |b| {
        hashOne(s.alg, b, &out);
        std.mem.doNotOptimizeAway(&out);
    }
}

const SmallState = struct { msgs: []const []const u8, alg: Alg };
fn passSmall(s: SmallState) !void {
    var out: [64]u8 = undefined;
    for (s.msgs) |m| {
        hashOne(s.alg, m, &out);
        std.mem.doNotOptimizeAway(&out);
    }
}

const ManyState = struct { ins: []const []const []const u8, out: [][32]u8 };
fn passMany(s: ManyState) !void {
    blake2b.blake2b256Many(s.ins, s.out);
    std.mem.doNotOptimizeAway(s.out.ptr);
}

const HmacState = struct { msgs: []const []const u8 };
fn passHmac(s: HmacState) !void {
    const key: [32]u8 = @splat(7);
    for (s.msgs) |m| {
        const o = hmac.Hmac(keccak.Sha3_256).mac(&key, m);
        std.mem.doNotOptimizeAway(&o);
    }
}

fn bench(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const names = ctx.benchInputs();
    const blobs = try arena.alloc([]const u8, names.len);
    // The multi-buffer record has no Rust twin (Rust has no batch API); it is compared in BENCH.md
    // against the Rust single-buffer record of the same name minus "-many".
    var bytes: u64 = 0;
    for (names, blobs) |n, *b| {
        b.* = try ctx.corpus.readFileAlloc(ctx.io, n, arena, .limited(1 << 30));
        bytes += b.len;
    }
    // Record names are stored by the harness until the comparison, so they are comptime strings.
    inline for (bench_algs) |an| {
        try ctx.benchPasses("blob-" ++ an, "byte", bytes, BenchState{ .blobs = blobs, .alg = comptime algOf(an).? }, passBlobs);
    }
    inline for (bench_small) |sz| {
        var msgs: std.ArrayList([]const u8) = .empty;
        for (blobs) |b| {
            var off: usize = 0;
            while (off + sz <= b.len and msgs.items.len < 200_000) {
                try msgs.append(arena, b[off..][0..sz]);
                off += 4099;
            }
        }
        {
            const ins = try arena.alloc([]const []const u8, msgs.items.len);
            const ps = try arena.alloc([1][]const u8, msgs.items.len);
            for (msgs.items, ps, ins) |m, *p, *i| {
                p.* = .{m};
                i.* = p;
            }
            const outs = try arena.alloc([32]u8, msgs.items.len);
            try ctx.benchPasses(std.fmt.comptimePrint("small{d}-blake2b256-many", .{sz}), "msg", msgs.items.len, ManyState{ .ins = ins, .out = outs }, passMany);
        }
        inline for (small_algs) |an| {
            try ctx.benchPasses(std.fmt.comptimePrint("small{d}-{s}", .{ sz, an }), "msg", msgs.items.len, SmallState{ .msgs = msgs.items, .alg = comptime algOf(an).? }, passSmall);
        }
    }
    {
        const msgs = try arena.alloc([]const u8, blobs.len);
        for (blobs, msgs) |b, *m| m.* = b[0..@min(256, b.len)];
        try ctx.benchPasses("hmac-sha3-256-small", "msg", msgs.len, HmacState{ .msgs = msgs }, passHmac);
    }
}
