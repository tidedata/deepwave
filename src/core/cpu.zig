//! Runtime CPU dispatch for the SIMD and wide-multiply kernels.
//!
//! Zig compiles a whole compilation for one CPU, so the higher x86-64 tiers (cpu_tiers.zig) are
//! separate kernel objects: build.zig compiles src/cpu_kernels.zig once per tier with that tier's
//! CPU model and links the objects into every x86-64 binary. Each object exports one C-ABI thunk
//! per dispatched primitive, `zui_k_<tier>_<name>`. `call` picks the thunk for `tier()` and falls
//! back to the function compiled into the caller's own compilation.
//!
//! `tier()` is decided once (CPUID, XGETBV for the OS-enabled vector state, then the ZUI_CPU
//! cap) and cached. It is never below the build target's own tier: `-Dcpu=x86_64_v3` makes the
//! portable code AVX2 already, and the build links no object at or below the target's tier, so
//! a build for a known CPU keeps pure comptime selection.
//!
//! ZUI_CPU=baseline|avx2|avx512 caps the tier (to model a smaller CPU on a bigger one, or to
//! fall back); a value the CPU cannot run is ignored.
//!
//! Arguments cross by pointer to the caller's argument tuple and the result by pointer, so
//! the thunks need no C-compatible types. Both sides are built from the same source by the same
//! compiler for the same architecture, so the tuple layouts agree; dispatched functions take
//! and return only integers, arrays, pointers, slices, plain structs and tagged unions of them:
//! no vectors (their alignment can follow CPU features) and no error unions (error values are
//! numbered per compilation).
const std = @import("std");
const builtin = @import("builtin");
const options = @import("cpu_options");
pub const tiers = @import("cpu_tiers.zig");
pub const Tier = tiers.Tier;

const is_x86 = builtin.cpu.arch == .x86_64;

/// Set inside a kernel object: the tier it was compiled for. Dispatch is off there.
pub const kernel_tier: ?Tier = if (options.kernel_tier == 0xff) null else @enumFromInt(options.kernel_tier);

/// Tier of this compilation's own target features.
pub const native_tier: Tier = if (is_x86) tiers.ofFeatureSet(builtin.cpu.features) else .baseline;

/// Tiers whose kernel objects this binary links (none inside a kernel object, none off x86-64).
pub fn linked(comptime t: Tier) bool {
    return kernel_tier == null and is_x86 and (options.linked_mask >> @intCast(@intFromEnum(t))) & 1 == 1 and
        @intFromEnum(t) > @intFromEnum(native_tier);
}

const any_linked = blk: {
    for (tiers.kernel_tiers) |t| if (linked(t)) break :blk true;
    break :blk false;
};

pub fn symbol(comptime t: Tier, comptime name: []const u8) []const u8 {
    return "zui_k_" ++ @tagName(t) ++ "_" ++ name;
}

pub fn Ret(comptime f: anytype) type {
    return @typeInfo(@TypeOf(f)).@"fn".return_type.?;
}
pub fn Args(comptime f: anytype) type {
    return std.meta.ArgsTuple(@TypeOf(f));
}

/// The exported form of `f` in a kernel object (src/cpu_kernels.zig exports these).
pub fn Thunk(comptime f: anytype) type {
    return struct {
        pub fn run(args: *const anyopaque, out: *anyopaque) callconv(.c) void {
            const a: *const Args(f) = @ptrCast(@alignCast(args));
            const r: *Ret(f) = @ptrCast(@alignCast(out));
            r.* = @call(.auto, f, a.*);
        }
    };
}

/// Calls `f(args...)` in the best linked kernel object for `tier()`, or `f` itself.
/// `name` must match the entry for `f` in src/cpu_kernels.zig (a mismatch fails at link time).
/// At comptime (a container-level constant hashed at build time) it is always `f` itself: the
/// tier is a runtime value and the kernel objects cannot run in the compiler.
pub inline fn call(comptime name: []const u8, comptime f: anytype, args: Args(f)) Ret(f) {
    if (comptime any_linked) if (!@inComptime()) {
        const t = tier();
        inline for (comptime .{ Tier.avx512, Tier.avx2 }) |k| {
            if (comptime linked(k)) {
                if (t == k) {
                    const ext = @extern(*const fn (*const anyopaque, *anyopaque) callconv(.c) void, .{ .name = symbol(k, name) });
                    var out: Ret(f) = undefined;
                    ext(@ptrCast(&args), @ptrCast(&out));
                    return out;
                }
            }
        }
    };
    return @call(.auto, f, args);
}

/// AES-128-GCM and single AES-128 blocks (QUIC packet protection, net/qcrypto.zig): std.crypto
/// picks AES-NI and PCLMULQDQ at comptime, so a baseline build runs the software AES unless
/// these dispatch to a kernel object. std-only, so they live here.
pub const aes = struct {
    const Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

    pub fn gcmSeal(c: []u8, tag: *[16]u8, m: []const u8, ad: []const u8, npub: [12]u8, key: [16]u8) void {
        call("aes128gcm_seal", gcmSealImpl, .{ c, tag, m, ad, npub, key });
    }
    pub fn gcmSealImpl(c: []u8, tag: *[16]u8, m: []const u8, ad: []const u8, npub: [12]u8, key: [16]u8) void {
        Gcm.encrypt(c, tag, m, ad, npub, key);
    }

    /// False on an authentication failure (the error value stays on this side of the call).
    pub fn gcmOpen(m: []u8, c: []const u8, tag: [16]u8, ad: []const u8, npub: [12]u8, key: [16]u8) bool {
        return call("aes128gcm_open", gcmOpenImpl, .{ m, c, tag, ad, npub, key });
    }
    pub fn gcmOpenImpl(m: []u8, c: []const u8, tag: [16]u8, ad: []const u8, npub: [12]u8, key: [16]u8) bool {
        Gcm.decrypt(m, c, tag, ad, npub, key) catch return false;
        return true;
    }

    pub fn encryptBlock(key: [16]u8, in: [16]u8) [16]u8 {
        return call("aes128_block", encryptBlockImpl, .{ key, in });
    }
    pub fn encryptBlockImpl(key: [16]u8, in: [16]u8) [16]u8 {
        const ctx = std.crypto.core.aes.Aes128.initEnc(key);
        var out: [16]u8 = undefined;
        ctx.encrypt(&out, &in);
        return out;
    }
};

// ---------------------------------------------------------------------------------------------
// Detection

/// What the CPU and OS support, and what was chosen.
pub const Info = struct {
    /// Highest tier the CPU and OS can run (at least `native_tier`).
    supported: Tier,
    /// The tier in use: `supported` capped by ZUI_CPU, never below `native_tier`.
    tier: Tier,
    /// The ZUI_CPU value was not a tier name, or named a tier the CPU cannot run.
    override_ignored: bool,
    sha_ni: bool,
    brand: [48]u8,
    brand_len: u8,

    pub fn brandName(i: *const Info) []const u8 {
        return std.mem.trim(u8, i.brand[0..i.brand_len], " ");
    }
};

var info_state: std.atomic.Value(u8) = .init(0); // 0 unknown, 1 ready
var info_value: Info = undefined;
var tier_cache: std.atomic.Value(u8) = .init(0xff);

/// The tier every dispatched primitive uses. Decided on the first call; cheap after that.
pub inline fn tier() Tier {
    const v = tier_cache.load(.monotonic);
    if (v != 0xff) return @enumFromInt(v);
    return info().tier;
}

/// Detection result (computed once; concurrent first calls compute the same value).
pub fn info() *const Info {
    if (info_state.load(.acquire) == 1) return &info_value;
    const i = detect();
    info_value = i;
    info_state.store(1, .release);
    tier_cache.store(@intFromEnum(i.tier), .monotonic);
    return &info_value;
}

pub const Regs = struct { a: u32, b: u32, c: u32, d: u32 };

pub fn cpuid(leaf: u32, sub: u32) Regs {
    var a: u32 = undefined;
    var b: u32 = undefined;
    var c: u32 = undefined;
    var d: u32 = undefined;
    asm volatile ("cpuid"
        : [a] "={eax}" (a),
          [b] "={ebx}" (b),
          [c] "={ecx}" (c),
          [d] "={edx}" (d),
        : [leaf] "{eax}" (leaf),
          [sub] "{ecx}" (sub),
    );
    return .{ .a = a, .b = b, .c = c, .d = d };
}

pub fn xcr0() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("xgetbv"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        : [c] "{ecx}" (@as(u32, 0)),
    );
    return (@as(u64, hi) << 32) | lo;
}

inline fn bit(x: u32, comptime n: u5) bool {
    return (x >> n) & 1 == 1;
}

/// Raw CPUID feature test for the tiers' feature lists.
const Cpu = struct {
    l1: Regs,
    l7: Regs,
    e1: Regs,
    os_avx: bool,
    os_avx512: bool,

    fn has(c: Cpu, f: std.Target.x86.Feature) bool {
        return switch (f) {
            .ssse3 => bit(c.l1.c, 9),
            .fma => bit(c.l1.c, 12) and c.os_avx,
            .cx16 => bit(c.l1.c, 13),
            .sse4_2 => bit(c.l1.c, 20),
            .movbe => bit(c.l1.c, 22),
            .popcnt => bit(c.l1.c, 23),
            .aes => bit(c.l1.c, 25),
            .pclmul => bit(c.l1.c, 1),
            .avx => bit(c.l1.c, 28) and c.os_avx,
            .f16c => bit(c.l1.c, 29) and c.os_avx,
            .bmi => bit(c.l7.b, 3),
            .avx2 => bit(c.l7.b, 5) and c.os_avx,
            .bmi2 => bit(c.l7.b, 8),
            .adx => bit(c.l7.b, 19),
            .sha => bit(c.l7.b, 29),
            .avx512f => bit(c.l7.b, 16) and c.os_avx512,
            .avx512dq => bit(c.l7.b, 17) and c.os_avx512,
            .avx512ifma => bit(c.l7.b, 21) and c.os_avx512,
            .avx512cd => bit(c.l7.b, 28) and c.os_avx512,
            .avx512bw => bit(c.l7.b, 30) and c.os_avx512,
            .avx512vl => bit(c.l7.b, 31) and c.os_avx512,
            .sahf => bit(c.e1.c, 0),
            .lzcnt => bit(c.e1.c, 5),
            else => false,
        };
    }
};

fn parseTier(s: []const u8) ?Tier {
    for (std.enums.values(Tier)) |t| {
        if (std.ascii.eqlIgnoreCase(s, @tagName(t))) return t;
    }
    if (std.ascii.eqlIgnoreCase(s, "ifma")) return .avx512;
    if (std.ascii.eqlIgnoreCase(s, "portable") or std.ascii.eqlIgnoreCase(s, "scalar")) return .baseline;
    return null;
}

fn envCap() ?[]const u8 {
    if (comptime !builtin.link_libc) return null;
    const p = std.c.getenv("ZUI_CPU") orelse return null;
    return std.mem.span(p);
}

fn detect() Info {
    var i: Info = .{ .supported = native_tier, .tier = native_tier, .override_ignored = false, .sha_ni = false, .brand = @splat(' '), .brand_len = 0 };
    if (comptime is_x86) {
        const l0 = cpuid(0, 0);
        const l1 = if (l0.a >= 1) cpuid(1, 0) else Regs{ .a = 0, .b = 0, .c = 0, .d = 0 };
        const l7 = if (l0.a >= 7) cpuid(7, 0) else Regs{ .a = 0, .b = 0, .c = 0, .d = 0 };
        const e0 = cpuid(0x80000000, 0);
        const e1 = if (e0.a >= 0x80000001) cpuid(0x80000001, 0) else Regs{ .a = 0, .b = 0, .c = 0, .d = 0 };
        const x: u64 = if (bit(l1.c, 27)) xcr0() else 0; // OSXSAVE
        const c: Cpu = .{
            .l1 = l1,
            .l7 = l7,
            .e1 = e1,
            .os_avx = x & 0x6 == 0x6, // XMM and YMM state
            .os_avx512 = x & 0xe6 == 0xe6, // plus opmask, ZMM_Hi256, Hi16_ZMM
        };
        for (tiers.kernel_tiers) |t| {
            var all = true;
            for (tiers.features(t)) |f| all = all and c.has(f);
            if (all and @intFromEnum(t) > @intFromEnum(i.supported)) i.supported = t;
        }
        i.sha_ni = c.has(.sha) and c.has(.ssse3) and bit(l1.c, 19);
        if (e0.a >= 0x80000004) {
            for (0..3) |k| {
                const r = cpuid(0x80000002 + @as(u32, @intCast(k)), 0);
                inline for (.{ r.a, r.b, r.c, r.d }, 0..) |w, j| std.mem.writeInt(u32, i.brand[k * 16 + j * 4 ..][0..4], w, .little);
            }
            i.brand_len = @intCast(std.mem.indexOfScalar(u8, &i.brand, 0) orelse 48);
        }
    }
    i.tier = i.supported;
    if (envCap()) |s| {
        if (parseTier(s)) |cap| {
            if (@intFromEnum(cap) <= @intFromEnum(i.supported)) {
                i.tier = if (@intFromEnum(cap) < @intFromEnum(native_tier)) native_tier else cap;
            } else i.override_ignored = true;
        } else i.override_ignored = true;
    }
    // Only tiers this binary carries can run; the rest fall back to the highest linked one below.
    while (i.tier != native_tier and !linkedRt(i.tier)) i.tier = @enumFromInt(@intFromEnum(i.tier) - 1);
    return i;
}

// ---------------------------------------------------------------------------------------------
// Runtime path toggles (core/hw.zig applies the user's overrides here; harness mode flips them).

var sha_ni_off: std.atomic.Value(bool) = .init(false);

/// False when SHA-NI is switched off (hw override or harness); hash/sha2.zig then runs the soft
/// compression even on a CPU that has it.
pub inline fn shaNiAllowed() bool {
    return !sha_ni_off.load(.monotonic);
}

pub fn setShaNi(on: bool) void {
    sha_ni_off.store(!on, .monotonic);
}

// Arm: the instruction sets that are compile-time target features still have a runtime soft
// alternative, so the harness can compare them and the user can switch them off. Each flag only
// matters in a build whose target has the feature (hash/sha2.zig, hash/keccak.zig, sig/dit.zig).
var arm_sha2_off: std.atomic.Value(bool) = .init(false);
var arm_sha512_off: std.atomic.Value(bool) = .init(false);
var arm_sha3_on: std.atomic.Value(bool) = .init(false); // default off: Keccak runs the portable rounds today
var dit_off: std.atomic.Value(bool) = .init(false);

pub inline fn armSha2Allowed() bool {
    return !arm_sha2_off.load(.monotonic);
}
pub inline fn armSha512Allowed() bool {
    return !arm_sha512_off.load(.monotonic);
}
/// True when the Keccak-f[1600] EOR3/RAX1/XAR kernel is asked for (opt-in).
pub inline fn armSha3Wanted() bool {
    return arm_sha3_on.load(.monotonic);
}
pub inline fn ditAllowed() bool {
    return !dit_off.load(.monotonic);
}
pub fn setArmSha2(on: bool) void {
    arm_sha2_off.store(!on, .monotonic);
}
pub fn setArmSha512(on: bool) void {
    arm_sha512_off.store(!on, .monotonic);
}
pub fn setArmSha3(on: bool) void {
    arm_sha3_on.store(on, .monotonic);
}
pub fn setDit(on: bool) void {
    dit_off.store(!on, .monotonic);
}

/// Whether `forceTier(t)` would succeed (the CPU runs it, this binary carries it, and it is not
/// below the build's own tier).
pub fn canForce(t: Tier) bool {
    const i = info();
    if (@intFromEnum(t) > @intFromEnum(i.supported)) return false;
    if (@intFromEnum(t) < @intFromEnum(native_tier)) return false;
    return t == native_tier or linkedRt(t);
}

/// Force the dispatch tier (harness and overrides). False, and nothing changed, when the CPU
/// cannot run `t` or this binary carries no object for it.
pub fn forceTier(t: Tier) bool {
    if (!canForce(t)) return false;
    tier_cache.store(@intFromEnum(t), .monotonic);
    return true;
}

/// Back to the tier detection chose (ZUI_CPU cap applied).
pub fn restoreTier() void {
    tier_cache.store(@intFromEnum(info().tier), .monotonic);
}

fn linkedRt(t: Tier) bool {
    inline for (tiers.kernel_tiers) |k| if (t == k) return linked(k);
    return false;
}

// ---------------------------------------------------------------------------------------------
// Reporting: the kernel each primitive runs (startup log line and `zui_cpu_kernel` metric).

pub const Prim = enum { ed25519, secp256k1, secp256r1, bls12381, bn254, blake2b, blake2b_many, sha256, sha512, keccak, aes_gcm };

/// Which toggled paths are in force (the live values, or a plan's).
pub const Sel = struct {
    sha_ni: bool,
    arm_sha2: bool = true,
    arm_sha512: bool = true,
    arm_sha3: bool = false,
};

pub fn liveSel() Sel {
    return .{ .sha_ni = info().sha_ni and shaNiAllowed(), .arm_sha2 = armSha2Allowed(), .arm_sha512 = armSha512Allowed(), .arm_sha3 = armSha3Wanted() };
}

pub fn kernelName(p: Prim, t: Tier, sha_ni: bool) []const u8 {
    var sel = liveSel();
    sel.sha_ni = sha_ni;
    return kernelNameFor(p, t, sel);
}

pub fn kernelNameFor(p: Prim, t: Tier, sel: Sel) []const u8 {
    const sha_ni = sel.sha_ni;
    if (comptime !is_x86) return switch (builtin.cpu.arch) {
        .aarch64 => switch (p) {
            .ed25519 => "radix51-neon",
            .blake2b => "scalar",
            .blake2b_many => "neon-x2",
            .sha256 => if (sel.arm_sha2) "armv8-sha2" else "scalar",
            .sha512 => if (sel.arm_sha512) "armv8-sha512" else "scalar",
            .keccak => if (sel.arm_sha3) "armv8-sha3" else "scalar",
            .aes_gcm => "armv8-aes",
            else => "portable",
        },
        else => "portable",
    };
    return switch (p) {
        .ed25519 => switch (t) {
            .baseline => "radix51",
            .avx2 => "radix51-avx2",
            .avx512 => "ifma",
        },
        .secp256k1, .bls12381, .bn254 => if (t == .baseline) "portable" else "mulx-adx",
        .secp256r1 => if (t == .baseline) "portable" else "mulx-adx-asm",
        .blake2b => if (t == .baseline) "scalar" else "avx2",
        .blake2b_many => switch (t) {
            .baseline => "sse2-x2",
            .avx2 => "avx2-x4",
            .avx512 => "avx512-x8",
        },
        .sha256 => if (sha_ni) "sha-ni" else "scalar",
        .sha512, .keccak => if (t == .baseline) "scalar" else "bmi2",
        .aes_gcm => if (t == .baseline) "soft" else "aesni-pclmul",
    };
}

/// One startup line: tier, CPU, and the kernel per primitive.
pub fn logChoice() void {
    const i = info();
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const live = tier();
    for (std.enums.values(Prim)) |p| w.print(" {s}={s}", .{ @tagName(p), kernelName(p, live, i.sha_ni and shaNiAllowed()) }) catch break;
    var forced_buf: [32]u8 = undefined;
    const forced = if (live != i.tier) std.fmt.bufPrint(&forced_buf, " (forced; detected {s})", .{@tagName(i.tier)}) catch "" else "";
    std.log.info("cpu: tier {s}{s} (supported {s}, build {s}{s}) {s}; kernels:{s}", .{
        @tagName(live),
        forced,
        @tagName(i.supported),
        @tagName(native_tier),
        if (i.override_ignored) ", ZUI_CPU ignored" else "",
        if (i.brand_len > 0) i.brandName() else @tagName(builtin.cpu.arch),
        w.buffered(),
    });
}

/// Prometheus lines: `zui_cpu_kernel{prim="ed25519",kernel="radix51-avx2"} 1` per primitive,
/// plus `zui_cpu_tier{tier="avx2",supported="avx512"} 1`.
pub fn writeMetrics(w: *std.Io.Writer) std.Io.Writer.Error!void {
    const i = info();
    const live = tier();
    try w.print("# TYPE zui_cpu_tier gauge\nzui_cpu_tier{{tier=\"{s}\",detected=\"{s}\",supported=\"{s}\",build=\"{s}\"}} 1\n", .{ @tagName(live), @tagName(i.tier), @tagName(i.supported), @tagName(native_tier) });
    try w.writeAll("# TYPE zui_cpu_kernel gauge\n");
    for (std.enums.values(Prim)) |p| try w.print("zui_cpu_kernel{{prim=\"{s}\",kernel=\"{s}\"}} 1\n", .{ @tagName(p), kernelName(p, live, i.sha_ni and shaNiAllowed()) });
}

test "tier detection is stable and at least the build's own" {
    const a = info();
    const b = info();
    try std.testing.expectEqual(a.tier, b.tier);
    try std.testing.expect(@intFromEnum(a.tier) >= @intFromEnum(native_tier));
    try std.testing.expect(@intFromEnum(a.tier) <= @intFromEnum(a.supported));
    try std.testing.expectEqual(tier(), a.tier);
}

test "parseTier" {
    try std.testing.expectEqual(Tier.avx2, parseTier("AVX2").?);
    try std.testing.expectEqual(Tier.avx512, parseTier("ifma").?);
    try std.testing.expectEqual(Tier.baseline, parseTier("baseline").?);
    try std.testing.expect(parseTier("sse9") == null);
}
