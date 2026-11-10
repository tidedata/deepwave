//! GPU against the corpus vector sets (Rust truth): the GPU path must give the verdict, hash or
//! point the Rust code gave. Covers sig-vectors (ed25519_verify, ed25519_batch), poseidon
//! (fastcrypto bytes and merkle) and groth16 bn254 verify (the public-input MSM on the GPU, then the
//! pairing with it). Run with `deepwave-gpu-check --vectors <corpus>/vectors`.
const std = @import("std");
const sig = @import("sig");
const zk = @import("zk");
const ops = @import("ops.zig");
const check = @import("check.zig");

const ed25519 = sig.ed25519;
const bn = zk.bn254;
const Fr = bn.Fr;
const Accel = ops.Accel;
const Value = std.json.Value;

fn unhex(a: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len % 2 != 0) return error.BadHex;
    const out = try a.alloc(u8, s.len / 2);
    _ = std.fmt.hexToBytes(out, s) catch return error.BadHex;
    return out;
}

fn str(o: std.json.ObjectMap, k: []const u8) []const u8 {
    const v = o.get(k) orelse return "";
    return if (v == .string) v.string else "";
}

fn readAll(gpa: std.mem.Allocator, io: std.Io, dir: []const u8, rel: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, rel });
    defer gpa.free(path);
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 30));
}

pub const Counts = struct { ed: u64 = 0, ed_batch: u64 = 0, pos: u64 = 0, msm: u64 = 0, pair: u64 = 0 };

pub fn run(gpa: std.mem.Allocator, io: std.Io, accel: *Accel, dir: []const u8, rep: *check.Report, cnt: *Counts) !void {
    const before = ops.Stats.get(&accel.stats.fallbacks);
    try edVectors(gpa, io, accel, dir, rep, cnt);
    try poseidonVectors(gpa, io, accel, dir, rep, cnt);
    try groth16Vectors(gpa, io, accel, dir, rep, cnt);
    const after = ops.Stats.get(&accel.stats.fallbacks);
    if (after != before) rep.miss("{d} GPU launches failed and fell back to the CPU (vectors)", .{after - before});
}

fn edVectors(gpa: std.mem.Allocator, io: std.Io, accel: *Accel, dir: []const u8, rep: *check.Report, cnt: *Counts) !void {
    const text = try readAll(gpa, io, dir, "sig-vectors/vectors.jsonl");
    defer gpa.free(text);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var items: std.ArrayList(ed25519.BatchItem) = .empty;
    var want: std.ArrayList([]const u8) = .empty;
    var ids: std.ArrayList([]const u8) = .empty;
    var batches: std.ArrayList([]const ed25519.BatchItem) = .empty;
    var batch_want: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const o = (try std.json.parseFromSliceLeaky(Value, a, line, .{})).object;
        const op = str(o, "op");
        if (std.mem.eql(u8, op, "ed25519_verify")) {
            const pk = try unhex(a, str(o, "pk"));
            const sg = try unhex(a, str(o, "sig"));
            if (pk.len != 32 or sg.len != 64) continue; // the byte-length errors never reach a kernel
            try items.append(a, .{ .pk = pk[0..32], .msg = try unhex(a, str(o, "msg")), .sig = sg[0..64] });
            try want.append(a, str(o, "v"));
            try ids.append(a, str(o, "id"));
        } else if (std.mem.eql(u8, op, "ed25519_batch")) {
            const arr = o.get("items").?.array.items;
            const bi = try a.alloc(ed25519.BatchItem, arr.len);
            var ok = true;
            for (arr, bi) |t, *b| {
                const pk = try unhex(a, t.array.items[0].string);
                const sg = try unhex(a, t.array.items[2].string);
                if (pk.len != 32 or sg.len != 64) ok = false else b.* = .{ .pk = pk[0..32], .msg = try unhex(a, t.array.items[1].string), .sig = sg[0..64] };
            }
            if (!ok) continue;
            try batches.append(a, bi);
            try batch_want.append(a, str(o, "v"));
        }
    }
    const got = try a.alloc(sig.Verdict, items.items.len);
    accel.ed25519VerifyEach(items.items, got);
    for (got, want.items, ids.items) |g, w, id| {
        cnt.ed += 1;
        rep.checked += 1;
        if (!std.mem.eql(u8, g.truthName(), w)) rep.miss("ed25519 vector {s}: rust {s} gpu {s}", .{ id, w, g.truthName() });
    }
    for (batches.items, batch_want.items, 0..) |b, w, i| {
        cnt.ed_batch += 1;
        rep.checked += 1;
        const g = accel.ed25519VerifyBatch(b);
        if (!std.mem.eql(u8, g.truthName(), w)) rep.miss("ed25519 batch vector {d}: rust {s} gpu {s}", .{ i, w, g.truthName() });
    }
}

fn gpuHash(accel: *Accel, in: []const Fr) Fr {
    var out: [1]Fr = undefined;
    accel.poseidonBatch(in.len, in, &out);
    return out[0];
}

fn gpuMerkle(accel: *Accel, in: []const Fr) Fr {
    if (in.len <= 16) return gpuHash(accel, in);
    var level: [256]Fr = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (i < in.len) : (i += 16) {
        level[n] = gpuHash(accel, in[i..@min(i + 16, in.len)]);
        n += 1;
    }
    return gpuMerkle(accel, level[0..n]);
}

fn poseidonVectors(gpa: std.mem.Allocator, io: std.Io, accel: *Accel, dir: []const u8, rep: *check.Report, cnt: *Counts) !void {
    const text = try readAll(gpa, io, dir, "poseidon/fastcrypto.jsonl");
    defer gpa.free(text);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const o = (try std.json.parseFromSliceLeaky(Value, a, line, .{})).object;
        const outv = o.get("out") orelse continue;
        if (outv != .string) continue; // error vectors never reach the kernel
        const ins = o.get("in").?.array.items;
        const frs = try a.alloc(Fr, ins.len);
        for (ins, frs) |h, *f| f.* = Fr.fromBytesLeCanonical((try unhex(a, h.string))[0..32]) orelse return error.BadVector;
        const f = str(o, "fn");
        const got = if (std.mem.eql(u8, f, "bytes")) gpuHash(accel, frs) else gpuMerkle(accel, frs);
        cnt.pos += 1;
        rep.checked += 1;
        const gb = got.toBytesLe();
        const want = try unhex(a, outv.string);
        if (!std.mem.eql(u8, &gb, want)) rep.miss("poseidon vector {s}", .{str(o, "id")});
    }
}

fn groth16Vectors(gpa: std.mem.Allocator, io: std.Io, accel: *Accel, dir: []const u8, rep: *check.Report, cnt: *Counts) !void {
    const text = try readAll(gpa, io, dir, "groth16/bn254.jsonl");
    defer gpa.free(text);
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const o = (try std.json.parseFromSliceLeaky(Value, a, line, .{})).object;
        if (!std.mem.eql(u8, str(o, "op"), "verify")) continue;
        const pvk = o.get("pvk").?.array.items;
        const g0 = try unhex(a, pvk[0].string);
        const inputs = try unhex(a, str(o, "inputs"));
        if (g0.len % 32 != 0 or inputs.len % 32 != 0 or g0.len == 0) continue;
        const np = g0.len / 32;
        const nin = inputs.len / 32;
        if (np != nin + 1) continue;
        var pts = try a.alloc(bn.G1, nin);
        const ks = try a.alloc([4]u64, nin);
        const p0 = bn.curve.g1FromCompressed(g0[0..32]) catch continue;
        var ok = true;
        for (0..nin) |j| {
            pts[j] = bn.curve.g1FromCompressed(g0[(j + 1) * 32 ..][0..32]) catch {
                ok = false;
                break;
            };
            ks[j] = Fr.limbsLe(inputs[j * 32 ..][0..32]);
            if (!Fr.ltModulus(ks[j])) ok = false;
        }
        if (!ok or nin == 0) continue;
        const gl = p0.toJacobian().add(accel.g1Msm(pts, ks)).toAffine();
        const cl = p0.toJacobian().add(Accel.g1MsmCpu(pts, ks)).toAffine();
        cnt.msm += 1;
        rep.checked += 1;
        if (!gl.eql(cl)) {
            rep.miss("groth16 vector {s}: gpu input accumulation differs", .{str(o, "id")});
            continue;
        }
        // the pairing with the GPU-accumulated point must give Rust's verdict
        const res = o.get("res").?;
        if (res != .bool) continue;
        const ab = try unhex(a, pvk[1].string);
        const gm = try unhex(a, pvk[2].string);
        const dl = try unhex(a, pvk[3].string);
        const pr = try unhex(a, str(o, "proof"));
        if (ab.len < 384 or gm.len < 64 or dl.len < 64 or pr.len < 128) continue;
        const alpha_beta = bn.Fq12.fromBytes(ab[0..384]) orelse continue;
        const gamma = bn.curve.g2FromCompressed(gm[0..64]) catch continue;
        const delta = bn.curve.g2FromCompressed(dl[0..64]) catch continue;
        const pa = bn.curve.g1FromCompressed(pr[0..32]) catch continue;
        const pb = bn.curve.g2FromCompressed(pr[32..96]) catch continue;
        const pc = bn.curve.g1FromCompressed(pr[96..128]) catch continue;
        const gp = bn.G2Prepared.init(gamma);
        const dp = bn.G2Prepared.init(delta);
        cnt.pair += 1;
        rep.checked += 1;
        if (zk.groth16.pairingEquation(gl, alpha_beta, &gp, &dp, pa, pb, pc) != res.bool) rep.miss("groth16 vector {s}: verdict with the GPU input point differs from Rust", .{str(o, "id")});
    }
}
