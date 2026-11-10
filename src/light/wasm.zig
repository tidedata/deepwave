//! WebAssembly exports of the light client (src/light/root.zig). One client per instance.
//!
//! Calling convention (js/deepwave-light.ts wraps all of it): byte inputs are copied into memory
//! from `lc_alloc` and passed as (ptr, len); a zero length means "absent" for optional inputs.
//! Every call returns a `Status` code; results land in the 1 KB buffer at `lc_out()`:
//!
//!   summary calls:  0 digest[32] | 32 content_digest[32] | 64 seq u64 | 72 epoch u64
//!                   | 80 timestamp_ms u64 | 88 network_total_transactions u64 | 96 end_of_epoch u8
//!   tx calls:       128 tx_digest[32] | 160 effects_digest[32] | 192 events_digest[32]
//!                   | 224 index u32 | 228 has_events_digest u8 | 229 events_verified u8 | 230 data_verified u8
//!   object calls:   256 id[32] | 288 version u64 | 296 digest[32]
//!   on digest_mismatch: 512 what u32 | 516 index u32
//!   lc_split_chk:   600 six u32 offsets (summary, sig, contents: start, end)
const std = @import("std");
const light = @import("light");

const gpa = std.heap.wasm_allocator;
var client: ?light.Client = null;
var out: [1024]u8 align(8) = @splat(0);

fn cl() *light.Client {
    if (client == null) client = light.Client.init(gpa) catch @panic("oom");
    return &client.?;
}

fn slice(p: [*]const u8, n: usize) []const u8 {
    return if (n == 0) &.{} else p[0..n];
}

fn opt(p: [*]const u8, n: usize) ?[]const u8 {
    return if (n == 0) null else p[0..n];
}

fn put64(at: usize, v: u64) void {
    std.mem.writeInt(u64, out[at..][0..8], v, .little);
}

fn put32(at: usize, v: u32) void {
    std.mem.writeInt(u32, out[at..][0..4], v, .little);
}

fn done(st: light.Status) u32 {
    const c = cl();
    if (st == .digest_mismatch) {
        put32(512, @intFromEnum(c.last_what));
        put32(516, c.last_index);
    }
    return @intFromEnum(st);
}

fn putVerified(v: *const light.Verified) void {
    @memcpy(out[0..32], &v.digest);
    @memcpy(out[32..64], &v.content_digest);
    put64(64, v.seq);
    put64(72, v.epoch);
    put64(80, v.timestamp_ms);
    put64(88, v.network_total_transactions);
    out[96] = @intFromBool(v.end_of_epoch);
}

fn putTx(t: *const light.TxOut) void {
    @memcpy(out[128..160], &t.tx_digest);
    @memcpy(out[160..192], &t.effects_digest);
    if (t.events_digest) |d| @memcpy(out[192..224], &d) else @memset(out[192..224], 0);
    put32(224, t.index);
    out[228] = @intFromBool(t.events_digest != null);
    out[229] = @intFromBool(t.events_verified);
    out[230] = @intFromBool(t.data_verified);
}

export fn lc_alloc(n: usize) ?[*]u8 {
    const s = gpa.alloc(u8, @max(n, 1)) catch return null;
    return s.ptr;
}

export fn lc_free(p: [*]u8, n: usize) void {
    gpa.free(p[0..@max(n, 1)]);
}

export fn lc_out() [*]u8 {
    return &out;
}

/// Drops every trusted committee and verified summary.
export fn lc_reset() void {
    if (client) |*c| c.deinit();
    client = null;
}

/// Bit 0: verified-summary ring. Bit 1: aggregate-key cache.
export fn lc_set_cache(flags: u32) void {
    cl().cache = flags & 1 != 0;
    cl().cache_agg = flags & 2 != 0;
}

/// `members`: n entries of (96-byte BLS public key, u64 LE stake).
export fn lc_trust_committee(epoch: u64, members: [*]const u8, len: usize) u32 {
    if (len == 0 or len % 104 != 0) return @intFromEnum(light.Status.bad_committee);
    const n = len / 104;
    const ms = gpa.alloc(light.Member, n) catch return @intFromEnum(light.Status.out_of_memory);
    defer gpa.free(ms);
    for (ms, 0..) |*m, i| {
        m.name = members[i * 104 ..][0..96].*;
        m.stake = std.mem.readInt(u64, members[i * 104 + 96 ..][0..8], .little);
    }
    return done(cl().trustCommittee(epoch, ms));
}

export fn lc_trust_pinned(summary: [*]const u8, len: usize, pin: *const [32]u8) u32 {
    return done(cl().trustPinned(slice(summary, len), pin));
}

/// `sig`: BCS `AuthorityStrongQuorumSignInfo`.
export fn lc_verify_summary(summary: [*]const u8, len: usize, sig: [*]const u8, sig_len: usize) u32 {
    var v: light.Verified = undefined;
    const st = cl().verifySummary(slice(summary, len), slice(sig, sig_len), &v);
    if (st == .ok) putVerified(&v);
    return done(st);
}

/// sui.rpc.v2 `ValidatorAggregatedSignature` parts: 48-byte signature and roaring bitmap.
export fn lc_verify_summary_parts(summary: [*]const u8, len: usize, sig_epoch: u64, signature: [*]const u8, sig_len: usize, bitmap: [*]const u8, bitmap_len: usize) u32 {
    var v: light.Verified = undefined;
    const st = cl().verifySummaryParts(slice(summary, len), sig_epoch, slice(signature, sig_len), slice(bitmap, bitmap_len), &v);
    if (st == .ok) putVerified(&v);
    return done(st);
}

/// A sui.rpc.v2 `Checkpoint` or `GetCheckpointResponse`: summary, then contents and
/// transactions when present.
export fn lc_verify_checkpoint_proto(p: [*]const u8, len: usize) u32 {
    var v: light.Verified = undefined;
    const st = cl().verifyCheckpointProto(slice(p, len), &v);
    if (st == .ok) putVerified(&v);
    return done(st);
}

export fn lc_verify_contents(anchor: *const [32]u8, contents: [*]const u8, len: usize) u32 {
    return done(cl().verifyContents(anchor, slice(contents, len)));
}

export fn lc_verify_transaction(anchor: *const [32]u8, contents: [*]const u8, contents_len: usize, effects: [*]const u8, effects_len: usize, data: [*]const u8, data_len: usize, events: [*]const u8, events_len: usize) u32 {
    var t: light.TxOut = .{};
    const st = cl().verifyTransaction(anchor, slice(contents, contents_len), slice(effects, effects_len), opt(data, data_len), opt(events, events_len), &t);
    putTx(&t);
    return done(st);
}

export fn lc_verify_object(anchor: *const [32]u8, contents: [*]const u8, contents_len: usize, effects: [*]const u8, effects_len: usize, object: [*]const u8, object_len: usize) u32 {
    var t: light.TxOut = .{};
    var o: light.ObjOut = .{};
    const st = cl().verifyObject(anchor, slice(contents, contents_len), slice(effects, effects_len), slice(object, object_len), &t, &o);
    putTx(&t);
    @memcpy(out[256..288], &o.id);
    put64(288, o.version);
    @memcpy(out[296..328], &o.digest);
    return done(st);
}

/// Latest trusted committee epoch, or maxInt when none.
export fn lc_latest_epoch() u64 {
    return cl().latestEpoch() orelse std.math.maxInt(u64);
}

/// The head (highest verified checkpoint) into the summary slots; 0 when there is none.
export fn lc_head() u32 {
    const h = cl().head orelse return 0;
    putVerified(&h);
    return 1;
}

/// Members of a trusted epoch into a new buffer (n * 104 bytes, freed with lc_free); its
/// length lands at out[0..4]. Null when the epoch is unknown.
export fn lc_committee(epoch: u64) ?[*]u8 {
    const ms = cl().committeeMembers(epoch) orelse return null;
    const buf = gpa.alloc(u8, ms.len * 104) catch return null;
    for (ms, 0..) |m, i| {
        @memcpy(buf[i * 104 ..][0..96], &m.name);
        std.mem.writeInt(u64, buf[i * 104 + 96 ..][0..8], m.stake, .little);
    }
    put32(0, @intCast(buf.len));
    return buf.ptr;
}

export fn lc_stats(which: u32) u64 {
    const s = cl().stats;
    return switch (which) {
        0 => s.bls_checks,
        1 => s.agg_hits,
        else => s.ring_hits,
    };
}

export fn lc_split_chk(p: [*]const u8, len: usize) u32 {
    const parts = light.splitChk(slice(p, len)) catch return @intFromEnum(light.Status.decode);
    const xs = [_]usize{ parts.summary[0], parts.summary[1], parts.sig[0], parts.sig[1], parts.contents[0], parts.contents[1] };
    for (xs, 0..) |x, i| put32(600 + i * 4, @intCast(x));
    return 0;
}

pub const panic = std.debug.FullPanic(struct {
    fn f(msg: []const u8, ra: ?usize) noreturn {
        _ = msg;
        _ = ra;
        @trap();
    }
}.f);

/// Blake2b("CheckpointSummary::" ++ summary) into out[0..32].
export fn lc_summary_digest(p: [*]const u8, len: usize) void {
    out[0..32].* = light.summaryDigest(slice(p, len));
}

/// BCS `CertifiedCheckpointSummary` (native protocol `ProofCheckpoint.summary`).
export fn lc_verify_certified(p: [*]const u8, len: usize) u32 {
    var v: light.Verified = undefined;
    const st = cl().verifyCertified(slice(p, len), &v);
    if (st == .ok) putVerified(&v);
    return done(st);
}

// ---------------------------------------------------------------------------------------------
// micro-benchmarks of the certificate check's parts (JS times the call): 0 Fp mul, 1 hash to
// G1, 2 G1 subgroup check, 3 Miller loop (one pair + one precomputed), 4 final exponentiation,
// 5 G2 additions (one aggregate key over 60 keys). Returns a value so nothing is optimized out.
const bls = light.bls;
var bench_sink: u64 = 0;

export fn lc_bench(part: u32, iters: u32) u64 {
    const curve = bls.curve;
    const pairing = bls.pairing;
    var acc: u64 = 0;
    var msg: [480]u8 = @splat(7);
    switch (part) {
        0 => {
            var x = bls.Fp.fromU64(123456789);
            const y = bls.Fp.fromU64(987654321);
            for (0..iters) |_| x = x.mul(y);
            acc = x.l[0];
        },
        1 => for (0..iters) |i| {
            msg[0] = @truncate(i);
            acc +%= bls.hashToG1(&msg, bls.min_sig_dst).x.l[0];
        },
        2 => for (0..iters) |_| {
            acc +%= @intFromBool(curve.g1AffineInGroup(curve.g1_generator));
        },
        3 => {
            const S = struct {
                var lines: [pairing.n_lines]pairing.Line = undefined;
                var ready = false;
            };
            if (!S.ready) {
                pairing.precomputeLines(curve.g2_generator, &S.lines);
                S.ready = true;
            }
            for (0..iters) |_| {
                const f = pairing.millerLoop(&.{.{ .p = curve.g1_generator, .q = curve.g2_generator }}, &.{.{ .p = curve.g1_generator.neg(), .lines = &S.lines }});
                acc +%= f.c0.c0.c0.l[0];
            }
        },
        4 => {
            const f = pairing.millerLoop(&.{.{ .p = curve.g1_generator, .q = curve.g2_generator }}, &.{});
            for (0..iters) |_| acc +%= pairing.finalExp(f).c0.c0.c0.l[0];
        },
        5 => for (0..iters) |_| {
            var p = bls.G2Projective.infinity;
            for (0..60) |_| p = p.addAffine(curve.g2_generator);
            acc +%= p.toAffine().x.c0.l[0];
        },
        // self-check of the wasm field code against plain integer arithmetic (toInt goes
        // through the CIOS path, a separate implementation): 0 when every case agrees
        6 => {
            var x = bls.Fp.fromU64(0x1234_5678_9abc_def0);
            var y = bls.Fp.fromU64(0x0fed_cba9_8765_4321);
            const p = bls.field.p_int;
            for (0..iters) |_| {
                const z = x.mul(y);
                const want: u384 = @intCast((@as(u768, x.toInt()) * y.toInt()) % p);
                if (z.toInt() != want) acc += 1;
                const q = x.sqr();
                if (q.toInt() != @as(u384, @intCast((@as(u768, x.toInt()) * x.toInt()) % p))) acc += 1;
                x = z.add(y);
                y = q.sub(x);
            }
        },
        else => {},
    }
    bench_sink +%= acc;
    return acc;
}
