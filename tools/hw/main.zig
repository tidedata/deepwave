//! deepwave-hw: hardware report and the path-comparison harness.
//!
//!   deepwave-hw report  [--hw SPEC] [--dir PATH]
//!       Detected machine, the profile plan and the kernel per primitive (what `deepwave --hw`
//!       would apply). `--json` prints one JSON line instead.
//!   deepwave-hw compare [--corpus DIR] [--items N] [--max-bytes N] [--reps N] [--hw SPEC]
//!       Runs every alternative path of every dispatched primitive on the same inputs and
//!       compares each to an independent reference (Zig std). A path is a dispatch tier
//!       (baseline, avx2, avx512 as far as the CPU runs them) crossed with SHA-NI on/off. Inputs
//!       are the first --max-bytes of each file under --corpus, or a built-in deterministic set
//!       that covers every block-boundary length. One JSON line per (primitive, path) and a
//!       closing {"suite":"hw-compare",...} line; exit 0 only when every path matched.
//!   deepwave-hw paths
//!       The paths compare would run on this machine.
//!
//! `--hw SPEC` and ZUI_HW use the syntax of core/hw.zig; in compare they restrict the paths
//! (cpu=avx2 stops at avx2, sha_ni=off drops the SHA-NI paths).
const std = @import("std");
const Io = std.Io;
const core = @import("core");
const hash = @import("hash");
const sig = @import("sig");
const bls = @import("bls");
const zk = @import("zk");
const gpu = @import("gpu");
const hw = core.hw;
const cpu = core.cpu;
const builtin = @import("builtin");

fn now() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

const usage =
    \\usage: deepwave-hw report [--hw SPEC] [--dir PATH] [--json]
    \\       deepwave-hw compare [--corpus DIR] [--items N] [--max-bytes N] [--reps N] [--hw SPEC]
    \\       deepwave-hw paths [--hw SPEC]
    \\       deepwave-hw dispatch [--hw SPEC] [--matrix]   batch dispatch table: cached, or calibrated now
    \\                (calibrate=force redoes it); --matrix also prints us/op of every path
    \\
;

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var out_buf: [8192]u8 = undefined;
    var out_w: Io.File.Writer = .init(.stdout(), io, &out_buf);
    const out = &out_w.interface;
    defer out.flush() catch {};

    if (args.len < 2) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    const cmd = args[1];
    var spec: hw.Spec = .{};
    var fail: hw.ParseFail = .{};
    hw.parseEnv(&spec, &fail) catch |e| return specErr(e, &fail);

    var dir: ?[]const u8 = null;
    var corpus: ?[]const u8 = null;
    var json = false;
    var matrix = false;
    var items: usize = 512;
    var max_bytes: usize = 1 << 16;
    var reps: u32 = 3;
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const has_val = i + 1 < args.len;
        if (has_val and std.mem.eql(u8, a, "--hw")) {
            i += 1;
            hw.parse(&spec, args[i], &fail) catch |e| return specErr(e, &fail);
        } else if (has_val and std.mem.eql(u8, a, "--dir")) {
            i += 1;
            dir = args[i];
        } else if (has_val and std.mem.eql(u8, a, "--corpus")) {
            i += 1;
            corpus = args[i];
        } else if (has_val and std.mem.eql(u8, a, "--items")) {
            i += 1;
            items = std.fmt.parseInt(usize, args[i], 10) catch return bad("--items");
        } else if (has_val and std.mem.eql(u8, a, "--max-bytes")) {
            i += 1;
            max_bytes = std.fmt.parseInt(usize, args[i], 10) catch return bad("--max-bytes");
        } else if (has_val and std.mem.eql(u8, a, "--reps")) {
            i += 1;
            reps = std.fmt.parseInt(u32, args[i], 10) catch return bad("--reps");
        } else if (std.mem.eql(u8, a, "--json")) {
            json = true;
        } else if (std.mem.eql(u8, a, "--matrix")) {
            matrix = true;
        } else {
            std.debug.print("unknown argument {s}\n{s}", .{ a, usage });
            return 2;
        }
    }
    if (items == 0 or max_bytes == 0 or reps == 0) return bad("--items/--max-bytes/--reps must be positive");

    const m = hw.detect(dir);
    const p = hw.plan(&m, &spec);

    if (std.mem.eql(u8, cmd, "report")) {
        if (json) {
            try writeJson(out, &m, &p);
        } else {
            try hw.writeReport(out, &m, &p);
        }
        return 0;
    }
    if (std.mem.eql(u8, cmd, "dispatch")) {
        // the batch dispatch table: cached for this machine, or calibrated now (--hw calibrate=force)
        var setup = gpu.calibrate.fromPlan(io, gpa, &p, null, false);
        defer setup.deinit();
        var fp_buf: [512]u8 = undefined;
        try out.print("fingerprint {s}\n", .{gpu.calibrate.fingerprint(&fp_buf, &setup.accel)});
        try out.print("gpu {s} devices {d} pool {d} lanes, table from {s}", .{ @tagName(setup.accel.kind), setup.accel.deviceCount(), setup.accel.poolLanes(), @tagName(setup.source) });
        if (setup.accel.forced) |f| try out.print(", forced {f}", .{f});
        try out.writeByte('\n');
        for (0..setup.accel.deviceCount()) |d| try out.print("device {d} {s} {s}\n", .{ d, setup.accel.deviceName(d), setup.accel.devicePci(d) });
        try setup.accel.table.write(out);
        if (matrix) {
            try out.flush();
            const r = try gpu.calibrate.calibrate(gpa, &setup.accel, .{});
            try r.write(out);
        }
        return 0;
    }
    if (std.mem.eql(u8, cmd, "paths")) {
        var buf: [32]Config = undefined;
        for (configs(&m, &spec, &buf)) |c| try out.print("{s}\n", .{c.label()});
        return 0;
    }
    if (std.mem.eql(u8, cmd, "compare")) {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const set = if (corpus) |c|
            loadCorpus(arena, io, c, items, max_bytes) catch |e| {
                std.debug.print("corpus {s}: {s}\n", .{ c, @errorName(e) });
                return 1;
            }
        else
            try syntheticCorpus(arena, items, max_bytes);
        return compare(arena, out, &m, &spec, set, reps);
    }
    std.debug.print("unknown command {s}\n{s}", .{ cmd, usage });
    return 2;
}

fn bad(what: []const u8) u8 {
    std.debug.print("bad value for {s}\n{s}", .{ what, usage });
    return 2;
}

fn specErr(e: hw.ParseError, f: *const hw.ParseFail) u8 {
    std.debug.print("hw spec: {s} at {s}={s}\n", .{ @errorName(e), f.key[0..f.key_len], f.value[0..f.value_len] });
    return 2;
}

fn writeJson(w: *Io.Writer, m: *const hw.Machine, p: *const hw.Plan) !void {
    try w.print("{{\"cpu\":\"{s}\",\"arch\":\"{s}\",\"os\":\"{s}\",\"tier\":\"{s}\",\"supported\":\"{s}\",\"logical\":{d},\"physical\":{d},\"ram_mib\":{d},\"disk\":\"{s}\",\"profile\":\"{s}\",", .{
        m.brandName(),             @tagName(m.arch),             @tagName(m.os),    @tagName(m.tier), @tagName(m.tier_supported),
        m.logical_cores,           m.physical_cores,             m.ram_bytes >> 20, @tagName(m.disk), @tagName(p.profile),
    });
    try w.writeAll("\"features\":[");
    var first = true;
    inline for (comptime std.meta.fieldNames(hw.Features)) |n| {
        if (@field(m.features, n)) {
            if (!first) try w.writeByte(',');
            try w.print("\"{s}\"", .{n});
            first = false;
        }
    }
    try w.print("],\"plan\":{{\"pin\":{},\"cores\":{d},\"reserve\":{d},\"sha_ni\":{},\"metal\":{},\"gpu\":{},\"exec_cache_mb\":{d},\"chunk_cache_mb\":{d},\"cp_cache_mb\":{d}}}}}\n", .{
        p.pin, p.cores, p.reserve, p.sha_ni, p.metal, p.gpu, p.exec_cache_mb, p.chunk_cache_mb, p.cp_cache_mb,
    });
}

// ---------------------------------------------------------------------------------------------
// Paths

/// One runnable path: a dispatch tier and the toggled paths (SHA-NI on x86; the Arm instruction
/// sets on aarch64, varied one at a time from the base since they are independent).
const Config = struct {
    tier: cpu.Tier,
    sha_ni: bool,
    arm_sha2: bool = true,
    arm_sha512: bool = true,
    arm_sha3: bool = false,
    dit: bool = true,
    name_buf: [48]u8 = undefined,
    name_len: u8 = 0,

    fn label(c: *const Config) []const u8 {
        return c.name_buf[0..c.name_len];
    }
};

const Variant = struct { suffix: []const u8, sha_ni: bool = false, sha2: bool = true, sha512: bool = true, sha3: bool = false, dit: bool = true };

/// Every path this machine can run, after `spec` restrictions (cpu cap, avx*=off, sha_ni=off,
/// arm_*=off).
fn configs(m: *const hw.Machine, spec: *const hw.Spec, buf: []Config) []Config {
    var vbuf: [8]Variant = undefined;
    var nv: usize = 0;
    if (builtin.cpu.arch == .aarch64) {
        const base: Variant = .{ .suffix = "", .sha2 = spec.arm_sha2 != .off and m.features.arm_sha2, .sha512 = spec.arm_sha512 != .off and m.features.arm_sha512, .sha3 = spec.arm_sha3 == .on and m.features.arm_sha3, .dit = spec.dit != .off };
        vbuf[0] = base;
        nv = 1;
        if (base.sha2) {
            vbuf[nv] = base;
            vbuf[nv].suffix = "-arm_sha2";
            vbuf[nv].sha2 = false;
            nv += 1;
        }
        if (base.sha512) {
            vbuf[nv] = base;
            vbuf[nv].suffix = "-arm_sha512";
            vbuf[nv].sha512 = false;
            nv += 1;
        }
        if (!base.sha3 and m.features.arm_sha3 and spec.arm_sha3 != .off) {
            vbuf[nv] = base;
            vbuf[nv].suffix = "+arm_sha3";
            vbuf[nv].sha3 = true;
            nv += 1;
        }
        if (base.dit and m.features.arm_dit) {
            vbuf[nv] = base;
            vbuf[nv].suffix = "-dit";
            vbuf[nv].dit = false;
            nv += 1;
        }
    } else {
        vbuf[0] = .{ .suffix = "" };
        nv = 1;
        if (m.features.sha_ni and spec.sha_ni != .off) {
            vbuf[1] = .{ .suffix = "+sha_ni", .sha_ni = true };
            nv = 2;
        }
    }
    var n: usize = 0;
    for (std.enums.values(cpu.Tier)) |t| {
        if (@intFromEnum(t) > @intFromEnum(m.tier_supported)) continue;
        if (spec.cpu_cap) |c| if (@intFromEnum(t) > @intFromEnum(c)) continue;
        if (t == .avx512 and spec.avx512 == .off) continue;
        if (t != .baseline and spec.avx2 == .off) continue;
        // Skip tiers the binary cannot run (no kernel object linked for them).
        if (!cpu.forceTier(t)) continue;
        for (vbuf[0..nv]) |v| {
            if (n >= buf.len) break;
            const s = std.fmt.bufPrint(&buf[n].name_buf, "{s}{s}", .{ @tagName(t), v.suffix }) catch unreachable;
            buf[n].name_len = @intCast(s.len);
            buf[n].tier = t;
            buf[n].sha_ni = v.sha_ni;
            buf[n].arm_sha2 = v.sha2;
            buf[n].arm_sha512 = v.sha512;
            buf[n].arm_sha3 = v.sha3;
            buf[n].dit = v.dit;
            n += 1;
        }
    }
    cpu.restoreTier();
    return buf[0..n];
}

fn enter(c: *const Config) void {
    _ = cpu.forceTier(c.tier);
    cpu.setShaNi(c.sha_ni);
    cpu.setArmSha2(c.arm_sha2);
    cpu.setArmSha512(c.arm_sha512);
    cpu.setArmSha3(c.arm_sha3);
    cpu.setDit(c.dit);
}

fn leave() void {
    cpu.restoreTier();
    cpu.setShaNi(true);
    cpu.setArmSha2(true);
    cpu.setArmSha512(true);
    cpu.setArmSha3(false);
    cpu.setDit(true);
}

// ---------------------------------------------------------------------------------------------
// Corpus

const Corpus = struct {
    items: []const []const u8,
    total: u64,
    source: []const u8,
};

fn xorshift(s: *u64) u64 {
    s.* ^= s.* << 13;
    s.* ^= s.* >> 7;
    s.* ^= s.* << 17;
    return s.*;
}

/// Deterministic inputs: every length 0..300 (all block boundaries of the 64, 128 and 136 byte
/// block hashes), then a mix up to max_bytes, from a fixed seed.
fn syntheticCorpus(arena: std.mem.Allocator, items: usize, max_bytes: usize) !Corpus {
    var list: std.ArrayList([]const u8) = .empty;
    var seed: u64 = 0x9e3779b97f4a7c15;
    var total: u64 = 0;
    var k: usize = 0;
    while (k < items) : (k += 1) {
        const len: usize = if (k <= 300) k else blk: {
            const r = xorshift(&seed);
            // Mostly small (transaction-sized), some large (checkpoint-sized).
            break :blk if (r & 7 == 0) @as(usize, @intCast((r >> 8) % max_bytes)) + 1 else @as(usize, @intCast((r >> 8) % 2048));
        };
        const l = @min(len, max_bytes);
        const b = try arena.alloc(u8, l);
        for (b) |*x| x.* = @truncate(xorshift(&seed) >> 24);
        total += l;
        try list.append(arena, b);
    }
    return .{ .items = try list.toOwnedSlice(arena), .total = total, .source = "synthetic" };
}

fn loadCorpus(arena: std.mem.Allocator, io: Io, path: []const u8, items: usize, max_bytes: usize) !Corpus {
    var d = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer d.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = d.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .file) continue;
        try names.append(arena, try arena.dupe(u8, e.name));
    }
    // Sorted: the same directory gives the same corpus on every machine.
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    var list: std.ArrayList([]const u8) = .empty;
    var total: u64 = 0;
    const stride = @max(1, names.items.len / items);
    var k: usize = 0;
    while (k < names.items.len and list.items.len < items) : (k += stride) {
        const data = d.readFileAlloc(io, names.items[k], arena, .limited(max_bytes)) catch |e| switch (e) {
            error.StreamTooLong => try readPrefix(arena, io, d, names.items[k], max_bytes),
            else => continue,
        };
        total += data.len;
        try list.append(arena, data);
    }
    if (list.items.len == 0) return error.EmptyCorpus;
    return .{ .items = try list.toOwnedSlice(arena), .total = total, .source = path };
}

fn readPrefix(arena: std.mem.Allocator, io: Io, d: Io.Dir, name: []const u8, max: usize) ![]u8 {
    var f = try d.openFile(io, name, .{});
    defer f.close(io);
    const buf = try arena.alloc(u8, max);
    const n = try f.readPositionalAll(io, buf, 0);
    return buf[0..n];
}

// ---------------------------------------------------------------------------------------------
// Primitives

const Prim = struct {
    name: []const u8,
    /// Fingerprint of the output over the corpus with the code under test (current tier/toggles).
    run: *const fn (set: []const []const u8, fp: *Fp) void,
    /// The same fingerprint from an independent implementation (Zig std).
    reference: *const fn (set: []const []const u8, fp: *Fp) void,
    /// Fed bytes for throughput: all items, or a smaller number for verify (per item).
    bytes_of: *const fn (set: []const []const u8) u64,
};

/// Running SHA-256 (std's, independent of every path under test) over all outputs.
const Fp = struct {
    h: std.crypto.hash.sha2.Sha256 = .init(.{}),
    fn add(f: *Fp, b: []const u8) void {
        f.h.update(b);
    }
    fn done(f: *Fp) [32]u8 {
        return f.h.finalResult();
    }
};

fn allBytes(set: []const []const u8) u64 {
    var n: u64 = 0;
    for (set) |s| n += s.len;
    return n;
}

fn Hasher(comptime Ours: type, comptime Ref: type, comptime len: usize) type {
    return struct {
        fn run(set: []const []const u8, fp: *Fp) void {
            var o: [len]u8 = undefined;
            for (set) |m| {
                Ours.hash(m, &o);
                fp.add(&o);
            }
        }
        fn reference(set: []const []const u8, fp: *Fp) void {
            var o: [len]u8 = undefined;
            for (set) |m| {
                Ref.hash(m, &o, .{});
                fp.add(&o);
            }
        }
    };
}

const sha256_p = Hasher(hash.Sha256, std.crypto.hash.sha2.Sha256, 32);
const sha512_p = Hasher(hash.Sha512, std.crypto.hash.sha2.Sha512, 64);
const blake_p = Hasher(hash.Blake2b256, std.crypto.hash.blake2.Blake2b256, 32);
const keccak_p = Hasher(hash.Keccak256, std.crypto.hash.sha3.Keccak256, 32);
const sha3_p = Hasher(hash.Sha3_256, std.crypto.hash.sha3.Sha3_256, 32);

/// blake2b256Many (the multi-buffer SIMD path) against std one by one.
const many_p = struct {
    const batch = 32;
    fn run(set: []const []const u8, fp: *Fp) void {
        var segs: [batch][1][]const u8 = undefined;
        var inputs: [batch][]const []const u8 = undefined;
        var outs: [batch][32]u8 = undefined;
        var k: usize = 0;
        while (k < set.len) {
            const n = @min(batch, set.len - k);
            for (0..n) |j| {
                segs[j] = .{set[k + j]};
                inputs[j] = &segs[j];
            }
            hash.blake2b256Many(inputs[0..n], outs[0..n]);
            for (outs[0..n]) |*o| fp.add(o);
            k += n;
        }
    }
    fn reference(set: []const []const u8, fp: *Fp) void {
        blake_p.reference(set, fp);
    }
};

/// Ed25519: sign with std (deterministic key per item), every 5th signature corrupted; the
/// fingerprint is the verdict bitstring of our verifier, the reference the known truth.
const ed_p = struct {
    const max_items = 256;
    const max_msg = 1024;
    var built: bool = false;
    var pks: [max_items][32]u8 = undefined;
    var sigs: [max_items][64]u8 = undefined;
    var valid: [max_items]bool = undefined;
    var n: usize = 0;

    fn build(set: []const []const u8) void {
        if (built) return;
        built = true;
        const Ed = std.crypto.sign.Ed25519;
        n = @min(set.len, max_items);
        for (0..n) |k| {
            var seed: [32]u8 = @splat(0);
            std.mem.writeInt(u64, seed[0..8], k, .little);
            const kp = Ed.KeyPair.generateDeterministic(seed) catch {
                n = k;
                return;
            };
            const msg = set[k][0..@min(set[k].len, max_msg)];
            pks[k] = kp.public_key.toBytes();
            sigs[k] = (kp.sign(msg, null) catch {
                n = k;
                return;
            }).toBytes();
            valid[k] = k % 5 != 4;
            if (!valid[k]) sigs[k][40] ^= 1;
        }
    }
    fn run(set: []const []const u8, fp: *Fp) void {
        build(set);
        for (0..n) |k| {
            const msg = set[k][0..@min(set[k].len, max_msg)];
            const ok = sig.ed25519.verify(&pks[k], msg, &sigs[k]).isValid();
            fp.add(&.{@intFromBool(ok)});
        }
    }
    fn reference(set: []const []const u8, fp: *Fp) void {
        build(set);
        for (0..n) |k| fp.add(&.{@intFromBool(valid[k])});
    }
    fn bytes(set: []const []const u8) u64 {
        build(set);
        var t: u64 = 0;
        for (0..n) |k| t += @min(set[k].len, max_msg);
        return t;
    }
};

/// Ed25519 batch verification: batches of 1..9 items from the same signed set, every other batch
/// carrying one corrupted signature. The verdict per batch must match the per-item truth.
const ed_batch_p = struct {
    const n_batches = 24;
    fn lists(set: []const []const u8) void {
        ed_p.build(set);
    }
    fn run(set: []const []const u8, fp: *Fp) void {
        lists(set);
        const per = sig.ed25519.batch_scratch_per_item;
        const scratch = std.heap.page_allocator.alloc(u8, per * 10) catch return;
        defer std.heap.page_allocator.free(scratch);
        var j: usize = 0;
        while (j < n_batches and ed_p.n >= 16) : (j += 1) {
            var items: [10]sig.ed25519.BatchItem = undefined;
            const size = 1 + j % 9;
            var cnt: usize = 0;
            var idx: usize = j * 7;
            while (cnt < size) : (idx += 1) {
                const k = idx % ed_p.n;
                if (ed_p.valid[k] == (!(j % 2 == 1 and cnt == j % size))) {
                    items[cnt] = .{ .pk = &ed_p.pks[k], .msg = set[k][0..@min(set[k].len, ed_p.max_msg)], .sig = &ed_p.sigs[k] };
                    cnt += 1;
                }
            }
            const ok = sig.ed25519.verifyBatch(items[0..cnt], scratch).isValid();
            fp.add(&.{@intFromBool(ok)});
        }
    }
    fn reference(set: []const []const u8, fp: *Fp) void {
        lists(set);
        var j: usize = 0;
        while (j < n_batches and ed_p.n >= 16) : (j += 1) fp.add(&.{@intFromBool(j % 2 == 0)});
    }
    fn bytes(set: []const []const u8) u64 {
        return ed_p.bytes(set);
    }
};

/// ECDSA over secp256k1 or secp256r1: signed with std (low-s), every 5th signature corrupted.
/// Two rows per curve: verify (verdict bits) and public-key recovery (did a recovery id give
/// back the signer's key).
fn EcdsaP(comptime k1: bool) type {
    const Std = if (k1) std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256 else std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const Curve = if (k1) std.crypto.ecc.Secp256k1 else std.crypto.ecc.P256;
    const Ours = if (k1) sig.secp256k1 else sig.secp256r1;
    return struct {
        const max_items = 24;
        const max_msg = 256;
        var built: bool = false;
        var pks: [max_items][33]u8 = undefined;
        var sigs: [max_items][64]u8 = undefined;
        var valid: [max_items]bool = undefined;
        var n: usize = 0;

        fn build(set: []const []const u8) void {
            if (built) return;
            built = true;
            const order: u256 = Curve.scalar.field_order;
            n = @min(set.len, max_items);
            for (0..n) |k| {
                var seed: [32]u8 = @splat(0);
                std.mem.writeInt(u64, seed[0..8], k + 1, .little);
                const kp = Std.KeyPair.generateDeterministic(seed) catch {
                    n = k;
                    return;
                };
                const msg = set[k][0..@min(set[k].len, max_msg)];
                var sg = (kp.sign(msg, null) catch {
                    n = k;
                    return;
                }).toBytes();
                const sv = std.mem.readInt(u256, sg[32..64], .big);
                if (sv > order / 2) std.mem.writeInt(u256, sg[32..64], order - sv, .big);
                pks[k] = kp.public_key.toCompressedSec1();
                sigs[k] = sg;
                valid[k] = k % 5 != 4;
                if (!valid[k]) sigs[k][8] ^= 1; // inside r
            }
        }
        fn runVerify(set: []const []const u8, fp: *Fp) void {
            build(set);
            for (0..n) |k| {
                const msg = set[k][0..@min(set[k].len, max_msg)];
                const ok = Ours.verifySlices(&pks[k], msg, &sigs[k], .sha256).isValid();
                fp.add(&.{@intFromBool(ok)});
            }
        }
        fn runRecover(set: []const []const u8, fp: *Fp) void {
            build(set);
            for (0..n) |k| {
                const msg = set[k][0..@min(set[k].len, max_msg)];
                var matched = false;
                for (0..2) |rid| {
                    var s65: [65]u8 = undefined;
                    @memcpy(s65[0..64], &sigs[k]);
                    s65[64] = @intCast(rid);
                    switch (Ours.recoverSlices(msg, &s65, .sha256)) {
                        .ok => |q| matched = matched or std.mem.eql(u8, &q, &pks[k]),
                        .invalid => {},
                    }
                }
                fp.add(&.{@intFromBool(matched)});
            }
        }
        fn reference(set: []const []const u8, fp: *Fp) void {
            build(set);
            for (0..n) |k| fp.add(&.{@intFromBool(valid[k])});
        }
        fn bytes(set: []const []const u8) u64 {
            build(set);
            var t: u64 = 0;
            for (0..n) |k| t += @min(set[k].len, max_msg);
            return t;
        }
    };
}
const k1_p = EcdsaP(true);
const r1_p = EcdsaP(false);

/// BLS12-381 certificate verification against a fixed 6-member committee: each item is signed by
/// a subset (aggregated), every 5th is checked against a signer list missing one real signer.
const bls_p = struct {
    const members = 6;
    const max_items = 10;
    const max_msg = 64;
    var built: bool = false;
    var arena: std.heap.ArenaAllocator = undefined;
    var committee: ?bls.PreparedCommittee = null;
    var aggs: [max_items][48]u8 = undefined;
    var signers: [max_items][members]u32 = undefined;
    var counts: [max_items]usize = undefined;
    var valid: [max_items]bool = undefined;
    var n: usize = 0;

    fn build(set: []const []const u8) void {
        if (built) return;
        built = true;
        arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        var sks: [members]bls.SecretKey = undefined;
        var pks: [members][96]u8 = undefined;
        for (0..members) |i| {
            var b: [32]u8 = @splat(0);
            std.mem.writeInt(u64, b[24..32], 0x1234_5678 + i * 977, .big);
            sks[i] = bls.SecretKey.fromBytes(&b) orelse return;
            pks[i] = sks[i].publicKey().toBytes();
        }
        committee = bls.PreparedCommittee.init(arena.allocator(), &pks) catch return;
        n = @min(set.len, max_items);
        for (0..n) |k| {
            const msg = set[k][0..@min(set[k].len, max_msg)];
            // Signers: 4 + k%3 members, starting at k%members, wrapping.
            const cnt = 4 + k % 3;
            var sg: [members]bls.Signature = undefined;
            for (0..cnt) |j| {
                const who = (k + j) % members;
                signers[k][j] = @intCast(who);
                sg[j] = sks[who].sign(msg);
            }
            counts[k] = cnt;
            const agg = bls.sig.aggregate(sg[0..cnt]) orelse {
                n = k;
                return;
            };
            aggs[k] = agg.toBytes();
            valid[k] = k % 5 != 4;
            if (!valid[k]) counts[k] = cnt - 1; // drop the last signer from the claimed list
        }
    }
    fn run(set: []const []const u8, fp: *Fp) void {
        build(set);
        const c = &(committee orelse return);
        for (0..n) |k| {
            const msg = set[k][0..@min(set[k].len, max_msg)];
            const ok = c.verifyAggregate(signers[k][0..counts[k]], msg, &aggs[k]);
            fp.add(&.{@intFromBool(ok)});
        }
    }
    fn reference(set: []const []const u8, fp: *Fp) void {
        build(set);
        if (committee == null) return;
        for (0..n) |k| fp.add(&.{@intFromBool(valid[k])});
    }
    fn bytes(set: []const []const u8) u64 {
        build(set);
        var t: u64 = 0;
        for (0..n) |k| t += @min(set[k].len, max_msg);
        return t;
    }
};

/// BN254 Groth16 pairing equation (zkLogin): a one-point key, A = k*g1, B = g2, valid iff
/// C = (k-2)*g1; every other proof gets C = (k-1)*g1.
const bn_p = struct {
    const items = 12;
    fn point(k: u64) [32]u8 {
        const limbs = [4]u64{ k, 0, 0, 0 };
        const q = zk.bn254.G1J.mulLimbs(zk.bn254.curve.g1_generator, &limbs).toAffine();
        return zk.bn254.curve.g1ToCompressed(q);
    }
    fn run(_: []const []const u8, fp: *Fp) void {
        const g1 = zk.bn254.curve.g1ToCompressed(zk.bn254.curve.g1_generator);
        const g2 = zk.bn254.curve.g2ToCompressed(zk.bn254.curve.g2_generator);
        var vk: [32 + 64 * 3 + 8 + 32]u8 = undefined;
        @memcpy(vk[0..32], &g1);
        @memcpy(vk[32..96], &g2);
        @memcpy(vk[96..160], &g2);
        @memcpy(vk[160..224], &g2);
        std.mem.writeInt(u64, vk[224..232], 1, .little);
        @memcpy(vk[232..264], &g1);
        var ab: [8 * 1024]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&ab);
        const pvk = zk.groth16.preparePvkBytes(fba.allocator(), &vk) catch return;
        for (0..items) |j| {
            const k: u64 = 3 + j;
            var proof: [128]u8 = undefined;
            proof[0..32].* = point(k);
            proof[32..96].* = g2;
            proof[96..128].* = point(if (j % 2 == 0) k - 2 else k - 1);
            const v = zk.groth16.verifyInBytes(pvk.vk_gamma_abc_g1, &pvk.alpha_g1_beta_g2, &pvk.gamma_g2_neg_pc, &pvk.delta_g2_neg_pc, &.{}, &proof);
            const ok = v == .ok and v.ok;
            fp.add(&.{@intFromBool(ok)});
        }
    }
    fn reference(_: []const []const u8, fp: *Fp) void {
        for (0..items) |j| fp.add(&.{@intFromBool(j % 2 == 0)});
    }
    fn bytes(_: []const []const u8) u64 {
        return items;
    }
};

/// AES-128-GCM seal and open through core/cpu.zig's dispatch against std: per item the sealed
/// bytes, then an open of the honest tag (must succeed) and of a flipped tag (must fail).
const aes_p = struct {
    const Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const max_len = 2048;
    fn params(k: usize) struct { key: [16]u8, nonce: [12]u8 } {
        var key: [16]u8 = undefined;
        var nonce: [12]u8 = @splat(0);
        std.mem.writeInt(u64, key[0..8], k *% 0x9e3779b97f4a7c15, .little);
        std.mem.writeInt(u64, key[8..16], ~k, .little);
        std.mem.writeInt(u64, nonce[0..8], k, .little);
        return .{ .key = key, .nonce = nonce };
    }
    fn run(set: []const []const u8, fp: *Fp) void {
        var ct: [max_len]u8 = undefined;
        var pt: [max_len]u8 = undefined;
        for (set, 0..) |m0, k| {
            const m = m0[0..@min(m0.len, max_len)];
            const pr = params(k);
            const ad = m[0..@min(m.len, 13)];
            var tag: [16]u8 = undefined;
            cpu.aes.gcmSeal(ct[0..m.len], &tag, m, ad, pr.nonce, pr.key);
            fp.add(ct[0..m.len]);
            fp.add(&tag);
            const good = cpu.aes.gcmOpen(pt[0..m.len], ct[0..m.len], tag, ad, pr.nonce, pr.key);
            fp.add(&.{@intFromBool(good and std.mem.eql(u8, pt[0..m.len], m))});
            var bad_tag = tag;
            bad_tag[3] ^= 0x10;
            fp.add(&.{@intFromBool(cpu.aes.gcmOpen(pt[0..m.len], ct[0..m.len], bad_tag, ad, pr.nonce, pr.key))});
        }
    }
    fn reference(set: []const []const u8, fp: *Fp) void {
        var ct: [max_len]u8 = undefined;
        for (set, 0..) |m0, k| {
            const m = m0[0..@min(m0.len, max_len)];
            const pr = params(k);
            const ad = m[0..@min(m.len, 13)];
            var tag: [16]u8 = undefined;
            Gcm.encrypt(ct[0..m.len], &tag, m, ad, pr.nonce, pr.key);
            fp.add(ct[0..m.len]);
            fp.add(&tag);
            fp.add(&.{1});
            fp.add(&.{0});
        }
    }
};

const prims = [_]Prim{
    .{ .name = "sha256", .run = sha256_p.run, .reference = sha256_p.reference, .bytes_of = allBytes },
    .{ .name = "sha512", .run = sha512_p.run, .reference = sha512_p.reference, .bytes_of = allBytes },
    .{ .name = "blake2b256", .run = blake_p.run, .reference = blake_p.reference, .bytes_of = allBytes },
    .{ .name = "blake2b256_many", .run = many_p.run, .reference = many_p.reference, .bytes_of = allBytes },
    .{ .name = "keccak256", .run = keccak_p.run, .reference = keccak_p.reference, .bytes_of = allBytes },
    .{ .name = "sha3_256", .run = sha3_p.run, .reference = sha3_p.reference, .bytes_of = allBytes },
    .{ .name = "ed25519_verify", .run = ed_p.run, .reference = ed_p.reference, .bytes_of = ed_p.bytes },
    .{ .name = "ed25519_verify_batch", .run = ed_batch_p.run, .reference = ed_batch_p.reference, .bytes_of = ed_batch_p.bytes },
    .{ .name = "secp256k1_verify", .run = k1_p.runVerify, .reference = k1_p.reference, .bytes_of = k1_p.bytes },
    .{ .name = "secp256k1_recover", .run = k1_p.runRecover, .reference = k1_p.reference, .bytes_of = k1_p.bytes },
    .{ .name = "secp256r1_verify", .run = r1_p.runVerify, .reference = r1_p.reference, .bytes_of = r1_p.bytes },
    .{ .name = "secp256r1_recover", .run = r1_p.runRecover, .reference = r1_p.reference, .bytes_of = r1_p.bytes },
    .{ .name = "bls_cert_verify", .run = bls_p.run, .reference = bls_p.reference, .bytes_of = bls_p.bytes },
    .{ .name = "bn254_groth16", .run = bn_p.run, .reference = bn_p.reference, .bytes_of = bn_p.bytes },
    .{ .name = "aes128gcm", .run = aes_p.run, .reference = aes_p.reference, .bytes_of = allBytes },
};

fn hex8(d: [32]u8) [16]u8 {
    return std.fmt.bytesToHex(d[0..8].*, .lower);
}

// ---------------------------------------------------------------------------------------------
// Compare

fn compare(arena: std.mem.Allocator, out: *Io.Writer, m: *const hw.Machine, spec: *const hw.Spec, set: Corpus, reps: u32) !u8 {
    _ = arena;
    var cbuf: [32]Config = undefined;
    const cfgs = configs(m, spec, &cbuf);
    try out.print("{{\"hw_compare\":\"start\",\"corpus\":\"{s}\",\"items\":{d},\"bytes\":{d},\"paths\":{d},\"cpu\":\"{s}\",\"tier_supported\":\"{s}\"}}\n", .{
        set.source, set.items.len, set.total, cfgs.len, m.brandName(), @tagName(m.tier_supported),
    });
    var passed: u32 = 0;
    var failed: u32 = 0;
    defer leave();
    for (prims) |p| {
        var ref_fp: Fp = .{};
        p.reference(set.items, &ref_fp);
        const want = ref_fp.done();
        var base_ns: u64 = 0;
        for (cfgs, 0..) |*c, ci| {
            enter(c);
            var fp: Fp = .{};
            p.run(set.items, &fp);
            const got = fp.done();
            // Timing: best of reps (the first run above also warmed caches).
            var best: u64 = std.math.maxInt(u64);
            var r: u32 = 0;
            while (r < reps) : (r += 1) {
                var f2: Fp = .{};
                const t0 = now();
                p.run(set.items, &f2);
                best = @min(best, now() - t0);
            }
            const ok = std.mem.eql(u8, &want, &got);
            if (ok) passed += 1 else failed += 1;
            if (ci == 0) base_ns = best;
            const bytes = p.bytes_of(set.items);
            const mbs = @as(f64, @floatFromInt(bytes)) / 1e6 / (@as(f64, @floatFromInt(@max(best, 1))) / 1e9);
            const speedup = @as(f64, @floatFromInt(base_ns)) / @as(f64, @floatFromInt(@max(best, 1)));
            try out.print("{{\"hw_compare\":\"{s}\",\"path\":\"{s}\",\"ok\":{},\"mb_per_s\":{d:.1},\"vs_first\":{d:.2},\"fp\":\"{s}\"", .{
                p.name, c.label(), ok, mbs, speedup, &hex8(got),
            });
            if (!ok) try out.print(",\"want\":\"{s}\"", .{&hex8(want)});
            try out.writeAll("}\n");
        }
    }
    // Arm hardware SHA-512 is chosen at compile time: compare its block function to the soft one.
    if (hash.sha2.has_sha512_hw) {
        var good = true;
        var seed: u64 = 7;
        for (0..1000) |_| {
            var st_a: [8]u64 = undefined;
            for (&st_a) |*x| x.* = xorshift(&seed);
            var st_b = st_a;
            var blk: [128]u8 = undefined;
            for (&blk) |*x| x.* = @truncate(xorshift(&seed) >> 11);
            hash.sha2.compress512Hw(&st_a, &blk);
            hash.sha2.compress512Soft(&st_b, &blk);
            if (!std.mem.eql(u64, &st_a, &st_b)) good = false;
        }
        if (good) passed += 1 else failed += 1;
        try out.print("{{\"hw_compare\":\"sha512_block\",\"path\":\"arm-sha512 vs soft\",\"ok\":{}}}\n", .{good});
    }
    try out.print("{{\"suite\":\"hw-compare\",\"passed\":{d},\"failed\":{d}}}\n", .{ passed, failed });
    return if (failed == 0 and passed > 0) 0 else 1;
}
