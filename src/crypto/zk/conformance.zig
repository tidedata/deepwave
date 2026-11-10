//! Conformance suites of the crypto-zk lane (CONTRACTS.md section 3.3). Ground truth comes from
//! `tools/truth/crypto-zk` (fastcrypto-zkp da61cd46 and sui-types 1.83.1) under
//! `$ZUI_CORPUS/vectors/{poseidon,groth16,zklogin}`; formats in tools/truth/crypto-zk/README.md.
const std = @import("std");
const harness = @import("harness");
const zk = @import("root.zig");
const Fail = zk.errors.Fail;
const Fr = zk.bn254.Fr;
const Fq = zk.bn254.Fq;
const Value = std.json.Value;

pub const suites = [_]harness.Suite{
    .{
        .name = "groth16",
        .lane = "crypto-zk",
        .doc = "Groth16 prepare/verify on BN254 and BLS12-381 vs fastcrypto-zkp",
        .run = runGroth16,
        .bench = benchGroth16,
        .baselines = &.{
            .{ .name = "groth16-verify", .argv = &.{ "{release}/zui-zk-truth", "bench", "groth16-verify" } },
            .{ .name = "groth16-prepare", .argv = &.{ "{release}/zui-zk-truth", "bench", "groth16-verify" } },
        },
        .inputs = .{ .dir = "vectors/groth16", .suffix = "bn254.jsonl" },
    },
    .{
        .name = "poseidon",
        .lane = "crypto-zk",
        .doc = "Poseidon BN254 hashes vs fastcrypto-zkp",
        .run = runPoseidon,
        .bench = benchPoseidon,
        .baselines = &.{.{ .name = "poseidon", .argv = &.{ "{release}/zui-zk-truth", "bench", "poseidon" } }},
        .inputs = .{ .dir = "vectors/poseidon", .suffix = ".jsonl" },
    },
    .{
        .name = "zklogin",
        .lane = "crypto-zk",
        .doc = "every zkLogin authenticator in corpus: verdict and address equal Rust",
        .run = runZkLogin,
        .bench = benchZkLogin,
        .baselines = &.{.{ .name = "zklogin-verify", .argv = &.{ "{release}/zui-zk-truth", "bench", "zklogin-verify" } }},
        .inputs = .{ .dir = "vectors/zklogin", .suffix = ".items.jsonl" },
    },
    .{ .name = "vdf", .lane = "crypto-zk", .doc = "class-group VDF verify + hash_to_input vs fastcrypto-vdf", .run = notYet },
    .{ .name = "nitro", .lane = "crypto-zk", .doc = "Nitro attestation parse/verify vs fastcrypto", .run = notYet },
};

fn notYet(ctx: *harness.Ctx) !void {
    _ = ctx;
    return error.NotImplemented;
}

// ------------------------------------------------------------------------------------------------
// helpers

const max_file = 256 << 20;

fn parseLine(ctx: *harness.Ctx, line: []const u8) !std.json.ObjectMap {
    const v = try std.json.parseFromSliceLeaky(Value, ctx.scratch(), line, .{});
    return v.object;
}

fn str(o: std.json.ObjectMap, k: []const u8) []const u8 {
    return switch (o.get(k) orelse return "") {
        .string => |s| s,
        else => "",
    };
}

fn isNull(o: std.json.ObjectMap, k: []const u8) bool {
    const v = o.get(k) orelse return true;
    return v == .null;
}

fn int(o: std.json.ObjectMap, k: []const u8) ?u64 {
    return switch (o.get(k) orelse return null) {
        .integer => |i| @intCast(i),
        else => null,
    };
}

fn hexAlloc(a: std.mem.Allocator, h: []const u8) ![]u8 {
    const out = try a.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

fn toHex(a: std.mem.Allocator, b: []const u8) ![]const u8 {
    const out = try a.alloc(u8, b.len * 2);
    const cs = "0123456789abcdef";
    for (b, 0..) |x, i| {
        out[2 * i] = cs[x >> 4];
        out[2 * i + 1] = cs[x & 15];
    }
    return out;
}

fn dbg(a: std.mem.Allocator, f: Fail) ![]const u8 {
    var w: std.Io.Writer.Allocating = .init(a);
    try f.debug(&w.writer);
    return w.written();
}

/// Expected value of a field that is either a string or the result "true"/"false".
fn resText(v: Value) []const u8 {
    return switch (v) {
        .string => |s| s,
        .bool => |b| if (b) "true" else "false",
        .null => "null",
        else => "?",
    };
}

// ------------------------------------------------------------------------------------------------
// poseidon

fn runPoseidon(ctx: *harness.Ctx) !void {
    try ctx.forEachFile("vectors/poseidon", ".jsonl", {}, poseidonFile);
}

fn poseidonFile(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const path = try std.fmt.allocPrint(ctx.scratch(), "vectors/poseidon/{s}", .{name});
    const text = try ctx.readFile(path, max_file);
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) return;
        const o = try parseLine(ctx, line);
        const id = str(o, "id");
        if (!ctx.selected(id)) continue;
        var c = ctx.check(id);
        const a = ctx.scratch();
        const ins = o.get("in").?.array.items;
        var bufs = try a.alloc([]const u8, ins.len);
        for (ins, 0..) |h, i| bufs[i] = try hexAlloc(a, h.string);
        var fail: Fail = .none;
        const f = str(o, "fn");
        var got_out: ?[]const u8 = null;
        if (std.mem.eql(u8, f, "bytes")) {
            var out: [32]u8 = undefined;
            if (zk.poseidon.hashBytes(bufs, &out, &fail)) got_out = try toHex(a, &out);
        } else if (std.mem.eql(u8, f, "merkle")) {
            const frs = try a.alloc(Fr, bufs.len);
            for (bufs, 0..) |b, i| frs[i] = Fr.fromBytesLeCanonical(b[0..32]).?;
            if (zk.poseidon.merkle(frs, &fail)) |h| got_out = try toHex(a, &h.toBytesLe());
        } else {
            c.failf("unknown fn {s}", .{f});
        }
        c.text("out", if (isNull(o, "out")) "null" else str(o, "out"), got_out orelse "null");
        c.text("err", if (isNull(o, "err")) "null" else str(o, "err"), if (got_out != null) "null" else try dbg(a, fail));
        _ = c.finish();
    }
}

const PoseidonBench = struct { items: []const []const []const u8 };

fn benchPoseidon(ctx: *harness.Ctx) !void {
    var list: std.ArrayList([]const []const u8) = .empty;
    const a = ctx.scratch();
    for (ctx.benchInputs()) |p| {
        const text = try ctx.readFile(p, max_file);
        var it = harness.lines(text);
        while (it.next()) |line| {
            const o = try parseLine(ctx, line);
            if (!std.mem.eql(u8, str(o, "fn"), "bytes") or isNull(o, "out")) continue;
            const ins = o.get("in").?.array.items;
            var bufs = try a.alloc([]const u8, ins.len);
            for (ins, 0..) |h, i| bufs[i] = try hexAlloc(a, h.string);
            try list.append(a, bufs);
        }
    }
    const st: PoseidonBench = .{ .items = list.items };
    try ctx.benchPasses("poseidon", "hash", list.items.len, &st, struct {
        fn f(s: *const PoseidonBench) !void {
            var out: [32]u8 = undefined;
            var fail: Fail = .none;
            for (s.items) |x| {
                if (!zk.poseidon.hashBytes(x, &out, &fail)) return error.Unexpected;
                std.mem.doNotOptimizeAway(&out);
            }
        }
    }.f);
}

// ------------------------------------------------------------------------------------------------
// groth16

fn runGroth16(ctx: *harness.Ctx) !void {
    try ctx.forEachFile("vectors/groth16", ".jsonl", {}, groth16File);
}

fn groth16File(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const path = try std.fmt.allocPrint(ctx.scratch(), "vectors/groth16/{s}", .{name});
    const text = try ctx.readFile(path, max_file);
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) return;
        const o = try parseLine(ctx, line);
        const id = str(o, "id");
        if (!ctx.selected(id)) continue;
        if (!std.mem.eql(u8, str(o, "curve"), "bn254")) {
            ctx.skip(id, "BLS12-381 Groth16 needs the crypto-bls field and pairing (not landed)");
            continue;
        }
        const a = ctx.scratch();
        var c = ctx.check(id);
        const op = str(o, "op");
        if (std.mem.eql(u8, op, "prepare")) {
            const vk = try hexAlloc(a, str(o, "vk"));
            if (zk.groth16.preparePvkBytes(a, vk)) |p| {
                if (isNull(o, "pvk")) {
                    c.failf("prepare ok, Rust {s}", .{str(o, "err")});
                } else {
                    const exp = o.get("pvk").?.array.items;
                    c.text("pvk0", exp[0].string, try toHex(a, p.vk_gamma_abc_g1));
                    c.text("pvk1", exp[1].string, try toHex(a, &p.alpha_g1_beta_g2));
                    c.text("pvk2", exp[2].string, try toHex(a, &p.gamma_g2_neg_pc));
                    c.text("pvk3", exp[3].string, try toHex(a, &p.delta_g2_neg_pc));
                }
            } else |e| {
                if (e == error.OutOfMemory) return e;
                c.text("err", if (isNull(o, "err")) "null" else str(o, "err"), "InvalidInput");
            }
            const nin = zk.groth16.publicInputsNum(vk.len);
            if (int(o, "nin")) |n| {
                c.eql("nin", @as(?usize, @intCast(n)), nin);
            } else {
                c.text("nin_err", str(o, "nin_err"), if (nin == null) "InvalidInput" else "ok");
            }
        } else {
            const pvk = o.get("pvk").?.array.items;
            var parts: [4][]const u8 = undefined;
            for (0..4) |i| parts[i] = try hexAlloc(a, pvk[i].string);
            const inputs = try hexAlloc(a, str(o, "inputs"));
            const proof = try hexAlloc(a, str(o, "proof"));
            const v = zk.groth16.verifyInBytes(parts[0], parts[1], parts[2], parts[3], inputs, proof);
            const got = switch (v) {
                .ok => |b| if (b) "true" else "false",
                .err => |f| try dbg(a, f),
            };
            c.text("res", resText(o.get("res").?), got);
        }
        _ = c.finish();
    }
}

const G16Verify = struct { parts: [4][]const u8, inputs: []const u8, proof: []const u8 };
const G16Bench = struct { verify: []const G16Verify, prepare: []const []const u8, arena: *std.heap.ArenaAllocator };

fn benchGroth16(ctx: *harness.Ctx) !void {
    const a = ctx.scratch();
    var vs: std.ArrayList(G16Verify) = .empty;
    var ks: std.ArrayList([]const u8) = .empty;
    for (ctx.benchInputs()) |p| {
        const text = try ctx.readFile(p, max_file);
        var it = harness.lines(text);
        while (it.next()) |line| {
            const o = try parseLine(ctx, line);
            if (!std.mem.eql(u8, str(o, "curve"), "bn254")) continue;
            if (std.mem.eql(u8, str(o, "op"), "verify")) {
                const r = o.get("res").?;
                if (r != .bool or !r.bool) continue;
                const pvk = o.get("pvk").?.array.items;
                var x: G16Verify = undefined;
                for (0..4) |i| x.parts[i] = try hexAlloc(a, pvk[i].string);
                x.inputs = try hexAlloc(a, str(o, "inputs"));
                x.proof = try hexAlloc(a, str(o, "proof"));
                try vs.append(a, x);
            } else if (!isNull(o, "pvk")) {
                try ks.append(a, try hexAlloc(a, str(o, "vk")));
            }
        }
    }
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const st: G16Bench = .{ .verify = vs.items, .prepare = ks.items, .arena = &arena };
    try ctx.benchPasses("groth16-verify", "proof", vs.items.len, &st, struct {
        fn f(s: *const G16Bench) !void {
            for (s.verify) |x| {
                const v = zk.groth16.verifyInBytes(x.parts[0], x.parts[1], x.parts[2], x.parts[3], x.inputs, x.proof);
                if (v != .ok or !v.ok) return error.Unexpected;
            }
        }
    }.f);
    try ctx.benchPasses("groth16-prepare", "vk", ks.items.len, &st, struct {
        fn f(s: *const G16Bench) !void {
            for (s.prepare) |k| {
                _ = s.arena.reset(.retain_capacity);
                const p = try zk.groth16.preparePvkBytes(s.arena.allocator(), k);
                std.mem.doNotOptimizeAway(&p);
            }
        }
    }.f);
}

// ------------------------------------------------------------------------------------------------
// zklogin

const JwkMap = struct {
    map: std.StringHashMapUnmanaged([]const u8) = .empty,
    arena: std.heap.ArenaAllocator,

    fn load(ctx: *harness.Ctx) !*JwkMap {
        const m = try ctx.gpa.create(JwkMap);
        m.* = .{ .arena = .init(ctx.gpa) };
        const a = m.arena.allocator();
        const text = try ctx.corpus.readFileAlloc(ctx.io, "vectors/zklogin/jwks.jsonld", a, .limited(64 << 20));
        var it = harness.lines(text);
        while (it.next()) |line| {
            const v = try std.json.parseFromSliceLeaky(Value, a, line, .{});
            const o = v.object;
            const key = try std.fmt.allocPrint(a, "{s}\x00{s}", .{ str(o, "iss"), str(o, "kid") });
            try m.map.put(a, key, str(o, "n"));
        }
        return m;
    }

    fn deinit(m: *JwkMap, gpa: std.mem.Allocator) void {
        m.arena.deinit();
        gpa.destroy(m);
    }

    fn lookup(ctx: *const anyopaque, iss: []const u8, kid: []const u8) ?[]const u8 {
        const m: *const JwkMap = @ptrCast(@alignCast(ctx));
        var buf: [1024]u8 = undefined;
        if (iss.len + kid.len + 1 > buf.len) return null;
        @memcpy(buf[0..iss.len], iss);
        buf[iss.len] = 0;
        @memcpy(buf[iss.len + 1 ..][0..kid.len], kid);
        return m.map.get(buf[0 .. iss.len + 1 + kid.len]);
    }

    fn jwks(m: *const JwkMap) zk.zklogin.Jwks {
        return .{ .ctx = m, .lookupFn = lookup };
    }
};

const ZkState = struct { keys: *const zk.zklogin.Keys, jwks: *const JwkMap };

const ExtraJwk = struct {
    base: zk.zklogin.Jwks,
    iss: []const u8 = "",
    kid: []const u8 = "",
    n: ?[]const u8 = null,

    fn lookup(ctx: *const anyopaque, iss: []const u8, kid: []const u8) ?[]const u8 {
        const e: *const ExtraJwk = @ptrCast(@alignCast(ctx));
        if (e.n) |n| if (std.mem.eql(u8, iss, e.iss) and std.mem.eql(u8, kid, e.kid)) return n;
        return e.base.lookup(iss, kid);
    }

    fn jwks(e: *const ExtraJwk) zk.zklogin.Jwks {
        return .{ .ctx = e, .lookupFn = lookup };
    }
};

fn runZkLogin(ctx: *harness.Ctx) !void {
    const keys = try ctx.gpa.create(zk.zklogin.Keys);
    defer ctx.gpa.destroy(keys);
    keys.init();
    const jm = try JwkMap.load(ctx);
    defer jm.deinit(ctx.gpa);
    const st: ZkState = .{ .keys = keys, .jwks = jm };
    try ctx.forEachName(&.{"fns.jsonl"}, &st, fnsFile);
    try ctx.forEachFile("vectors/zklogin", ".items.jsonl", &st, zkFile);
}

fn fnsFile(_: *const ZkState, ctx: *harness.Ctx, name: []const u8) !void {
    const path = try std.fmt.allocPrint(ctx.scratch(), "vectors/zklogin/{s}", .{name});
    const text = try ctx.readFile(path, max_file);
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) return;
        const o = try parseLine(ctx, line);
        const id = str(o, "id");
        if (!ctx.selected(id)) continue;
        const a = ctx.scratch();
        var c = ctx.check(id);
        const f = str(o, "fn");
        var fail: Fail = .none;
        var dec: [80]u8 = undefined;
        if (std.mem.eql(u8, f, "ascii")) {
            const r = zk.zklogin.hashAsciiStrToField(str(o, "s"), @intCast(int(o, "max").?), &fail);
            c.text("out", if (isNull(o, "out")) "null" else str(o, "out"), if (r) |x| try toHex(a, &x.toBytesLe()) else "null");
            c.text("err", if (isNull(o, "err")) "null" else str(o, "err"), if (r == null) try dbg(a, fail) else "null");
        } else if (std.mem.eql(u8, f, "dec")) {
            const s = str(o, "s");
            const fr = Fr.fromDecimal(s);
            c.text("fr", if (isNull(o, "fr")) "null" else str(o, "fr"), if (fr) |x| try toHex(a, &x.toBytesBe()) else "null");
            c.text("fr_err", if (isNull(o, "fr_err")) "null" else str(o, "fr_err"), if (fr == null) "InvalidInput" else "null");
            const fq = Fq.fromDecimal(s);
            c.text("fq", if (isNull(o, "fq")) "null" else str(o, "fq"), if (fq) |x| try a.dupe(u8, x.toDecimal(&dec)) else "null");
            c.text("fq_err", if (isNull(o, "fq_err")) "null" else str(o, "fq_err"), if (fq == null) "InvalidInput" else "null");
        } else if (std.mem.eql(u8, f, "addr")) {
            const seed = (Fr.fromDecimal(str(o, "seed")) orelse return error.BadVector).toBytesBe();
            const iss = str(o, "iss");
            c.text("padded", str(o, "padded"), try toHex(a, &zk.zklogin.address(iss, &seed, true)));
            c.text("unpadded", str(o, "unpadded"), try toHex(a, &zk.zklogin.address(iss, &seed, false)));
        } else if (std.mem.eql(u8, f, "seed")) {
            const r = zk.zklogin.genAddressSeed(str(o, "salt"), str(o, "name"), str(o, "value"), str(o, "aud"), &fail);
            c.text("out", if (isNull(o, "out")) "null" else str(o, "out"), if (r) |x| try a.dupe(u8, x.toDecimal(&dec)) else "null");
            c.text("err", if (isNull(o, "err")) "null" else str(o, "err"), if (r == null) try dbg(a, fail) else "null");
        } else if (std.mem.eql(u8, f, "nonce")) {
            const pk = try hexAlloc(a, str(o, "pk"));
            var out: [27]u8 = undefined;
            const ok = zk.zklogin.nonce(pk, int(o, "max_epoch").?, str(o, "rnd"), &out, &fail);
            c.text("out", if (isNull(o, "out")) "null" else str(o, "out"), if (ok) &out else "null");
            c.text("err", if (isNull(o, "err")) "null" else str(o, "err"), if (!ok) try dbg(a, fail) else "null");
        } else if (std.mem.eql(u8, f, "checkid") or std.mem.eql(u8, f, "checkiss")) {
            var addr: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&addr, str(o, "addr"));
            const r = if (std.mem.eql(u8, f, "checkid"))
                zk.zklogin.checkId(&addr, str(o, "name"), str(o, "value"), str(o, "aud"), str(o, "iss"), str(o, "pin"))
            else
                zk.zklogin.checkIss(&addr, str(o, "seed"), str(o, "iss"));
            c.text("res", resText(o.get("res").?), if (r == .none) "true" else try dbg(a, r));
        } else {
            c.failf("unknown fn {s}", .{f});
        }
        _ = c.finish();
    }
}

fn zkFile(st: *const ZkState, ctx: *harness.Ctx, name: []const u8) !void {
    const path = try std.fmt.allocPrint(ctx.scratch(), "vectors/zklogin/{s}", .{name});
    const text = try ctx.readFile(path, max_file);
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (ctx.done()) return;
        const o = try parseLine(ctx, line);
        const id = str(o, "id");
        if (!ctx.selected(id)) continue;
        const a = ctx.scratch();
        var c = ctx.check(id);
        const res = o.get("res").?.object;
        const auth_bytes = try hexAlloc(a, str(o, "auth"));
        const scratch = try a.alloc(u8, zk.zklogin.scratchLen(auth_bytes.len));
        var auth: zk.zklogin.Authenticator = undefined;
        var fail: Fail = .none;
        if (!zk.zklogin.Authenticator.parse(auth_bytes, scratch, &auth, &fail)) {
            c.text("parse", str(res, "parse"), try dbg(a, fail));
            _ = c.finish();
            continue;
        }
        c.text("parse", str(res, "parse"), "ok");
        c.text("iss", str(res, "iss"), auth.iss);
        c.text("kid", str(res, "kid"), auth.kid);
        c.eql("max_epoch", int(res, "max_epoch"), @as(?u64, auth.max_epoch));
        const eph = auth.eph();
        const eph_bytes = try a.alloc(u8, 1 + eph.pk.len);
        eph_bytes[0] = eph.flag;
        @memcpy(eph_bytes[1..], eph.pk);
        c.text("eph", str(res, "eph"), try toHex(a, eph_bytes));
        const unp = zk.zklogin.address(auth.iss, &auth.seed, false);
        const pad = zk.zklogin.address(auth.iss, &auth.seed, true);
        c.text("unpadded", str(res, "unpadded"), try toHex(a, &unp));
        c.text("padded", str(res, "padded"), try toHex(a, &pad));
        var sender: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sender, str(o, "sender"));
        const sm: []const u8 = if (std.mem.eql(u8, &unp, &sender)) "unpadded" else if (std.mem.eql(u8, &pad, &sender)) "padded" else "none";
        c.text("sender_match", str(res, "sender_match"), sm);
        const epoch_ok = zk.zklogin.checkEpoch(auth.max_epoch, int(o, "epoch").?, int(o, "delta"));
        c.eql("epoch_ok", res.get("epoch_ok").?.bool, epoch_ok);
        const use_jwks = o.get("jwks").?.bool;
        // Edge items carry one extra JWK (`xjwk`) for their own (iss, kid), checked before the union.
        var extra: ExtraJwk = .{ .base = if (use_jwks) st.jwks.jwks() else zk.zklogin.Jwks.empty };
        if (o.get("xjwk")) |x| if (x == .object) {
            extra.iss = str(x.object, "iss");
            extra.kid = str(x.object, "kid");
            extra.n = str(x.object, "n");
        };
        const jw = extra.jwks();
        inline for (.{ .{ "v1", zk.zklogin.Mode.v1_only }, .{ "both", zk.zklogin.Mode.both }, .{ "v2", zk.zklogin.Mode.v2_only } }) |m| {
            const env: zk.zklogin.Env = .{ .keys = st.keys, .jwks = jw, .usage = .prod, .mode = m[1] };
            const r = zk.zklogin.verify(&env, &auth);
            c.text(m[0], str(res, m[0]), if (r == .none) "ok" else try dbg(a, r));
        }
        _ = c.finish();
    }
}

const ZkBench = struct { auths: []const []const u8, env: zk.zklogin.Env, scratch: []u8 };

fn benchZkLogin(ctx: *harness.Ctx) !void {
    const a = ctx.scratch();
    const keys = try ctx.gpa.create(zk.zklogin.Keys);
    defer ctx.gpa.destroy(keys);
    keys.init();
    const jm = try JwkMap.load(ctx);
    defer jm.deinit(ctx.gpa);
    var list: std.ArrayList([]const u8) = .empty;
    var max_len: usize = 0;
    for (ctx.benchInputs()) |p| {
        const text = try ctx.readFile(p, max_file);
        var it = harness.lines(text);
        while (it.next()) |line| {
            const o = try parseLine(ctx, line);
            const res = o.get("res").?.object;
            if (!std.mem.eql(u8, str(res, "v1"), "ok") or !o.get("jwks").?.bool) continue;
            const b = try hexAlloc(a, str(o, "auth"));
            max_len = @max(max_len, b.len);
            try list.append(a, b);
        }
    }
    const st: ZkBench = .{
        .auths = list.items,
        .env = .{ .keys = keys, .jwks = jm.jwks(), .usage = .prod, .mode = .v1_only },
        .scratch = try a.alloc(u8, zk.zklogin.scratchLen(max_len)),
    };
    try ctx.benchPasses("zklogin-verify", "sig", list.items.len, &st, struct {
        fn f(s: *const ZkBench) !void {
            for (s.auths) |b| {
                var auth: zk.zklogin.Authenticator = undefined;
                var fail: Fail = .none;
                if (!zk.zklogin.Authenticator.parse(b, s.scratch, &auth, &fail)) return error.Unexpected;
                if (zk.zklogin.verify(&s.env, &auth) != .none) return error.Unexpected;
            }
        }
    }.f);
}
