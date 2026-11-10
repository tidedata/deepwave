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

/// An environment variable through libc (null without libc, as for ZUI_CPU).
pub fn envGet(comptime name: [*:0]const u8) ?[]const u8 {
    if (comptime !builtin.link_libc) return null;
    const p = std.c.getenv(name) orelse return null;
    return std.mem.span(p);
}

fn envCap() ?[]const u8 {
    return envGet("ZUI_CPU");
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

// Ed25519 four-way point kernel (crypto/sig/ed25519_avx2.zig): the vector twin of the scalar
// radix-2^51 chains. Off by default; the scalar chains stay compiled in and are what runs until
// this is switched on. `on` uses it on the avx2 tier of x86-64, the one tier it is written for
// and gated on; `force` uses it in every build and on every tier, for equality runs (it is the
// same source everywhere: SSE2 on baseline, NEON on aarch64, AVX-512VL encodings on the avx512
// tier, where the IFMA kernel keeps the single chain and only the batch chain moves).
// ZUI_ED25519_VEC4=1|on|force|0|off sets it from the environment; `setEdVec4` overrides that.
// The value is one exact name (case and surrounding blanks ignored); anything else leaves the
// switch off and logs a warning on the first read.
//
// The switch is read here, in the caller's compilation, and handed to the kernel entry as an
// argument (crypto/sig/ed25519.zig `Opts`): a kernel object has its own copy of every global.
pub const EdVec4 = enum(u8) { off = 0, on = 1, force = 2 };

var ed_vec4: std.atomic.Value(u8) = .init(0xff); // 0xff: environment not read yet

const blanks = " \t\r\n";

pub fn parseEdVec4(text: []const u8) ?EdVec4 {
    const s = std.mem.trim(u8, text, blanks);
    if (std.mem.eql(u8, s, "1") or std.ascii.eqlIgnoreCase(s, "on")) return .on;
    if (std.ascii.eqlIgnoreCase(s, "force")) return .force;
    if (std.mem.eql(u8, s, "0") or std.ascii.eqlIgnoreCase(s, "off")) return .off;
    return null;
}

/// What ZUI_ED25519_VEC4 asks for (off when unset or not a mode name).
pub fn edVec4FromEnv() EdVec4 {
    return if (envGet("ZUI_ED25519_VEC4")) |s| parseEdVec4(s) orelse .off else .off;
}

/// The mode for the variable's text (null: unset). Text that is not a mode name is off, with a
/// warning.
pub fn edVec4Init(text: ?[]const u8) EdVec4 {
    const s = text orelse return .off;
    return parseEdVec4(s) orelse {
        warnSwitch("ZUI_ED25519_VEC4", "0, off, 1, on or force", std.mem.trim(u8, s, blanks));
        return .off;
    };
}

pub fn edVec4() EdVec4 {
    const v = ed_vec4.load(.monotonic);
    if (v != 0xff) return @enumFromInt(v);
    // The first read: a concurrent setEdVec4 wins over the environment default, and the warning
    // for a bad value is logged by the one reader that installs the default.
    const text = envGet("ZUI_ED25519_VEC4");
    const quiet = if (text) |s| parseEdVec4(s) orelse .off else EdVec4.off;
    if (ed_vec4.cmpxchgStrong(0xff, @intFromEnum(quiet), .monotonic, .monotonic)) |now| return @enumFromInt(now);
    return edVec4Init(text);
}

pub fn setEdVec4(m: EdVec4) void {
    ed_vec4.store(@intFromEnum(m), .monotonic);
}

// Ed25519 batch key switches (crypto/sig/ed25519.zig `batchChunkKeyed`), both off by default.
// `cache`: the batch takes decoded keys from the decoded-key cache of sig/fast.zig and stores the
// ones it decodes there (only while that cache is on, `fast.Config.pk_cache`). `merge`: items of
// a chunk that share a key share one table and one summed scalar.
// ZUI_ED25519_BATCH_KEYS sets them from the environment: a comma-separated list of the exact
// names `cache` and `merge` (case and surrounding blanks ignored), or `all` / `1` for both, or
// `off` / `0` alone. A token that is not one of these names (`nomerge`, a typo) leaves BOTH
// switches off and logs a warning on the first read. `setEdBatchKeys` overrides the environment.
// They live here, next to `EdVec4`, for the same reason: read in the caller's compilation.
pub const EdBatchKeys = struct { cache: bool = false, merge: bool = false };

/// A parsed ZUI_ED25519_BATCH_KEYS value. `bad`: the first token that is not a name; `keys` is
/// then all off.
pub const EdBatchKeysText = struct { keys: EdBatchKeys = .{}, bad: ?[]const u8 = null };

pub fn parseEdBatchKeys(text: []const u8) EdBatchKeysText {
    var keys: EdBatchKeys = .{};
    var off: ?[]const u8 = null;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |raw| {
        const t = std.mem.trim(u8, raw, blanks);
        if (t.len == 0) continue;
        n += 1;
        if (std.ascii.eqlIgnoreCase(t, "cache")) {
            keys.cache = true;
        } else if (std.ascii.eqlIgnoreCase(t, "merge")) {
            keys.merge = true;
        } else if (std.ascii.eqlIgnoreCase(t, "all") or std.mem.eql(u8, t, "1")) {
            keys = .{ .cache = true, .merge = true };
        } else if (std.ascii.eqlIgnoreCase(t, "off") or std.mem.eql(u8, t, "0")) {
            off = t;
        } else return .{ .bad = t };
    }
    // off next to a switch name asks for two things at once
    if (off) |t| if (n > 1) return .{ .bad = t };
    return .{ .keys = keys };
}

var ed_batch_keys: std.atomic.Value(u8) = .init(0xff); // 0xff: environment not read yet

fn edBatchKeysBits(k: EdBatchKeys) u8 {
    return @as(u8, @intFromBool(k.cache)) | (@as(u8, @intFromBool(k.merge)) << 1);
}

/// What ZUI_ED25519_BATCH_KEYS asks for (both off when unset or when a token is not a name).
pub fn edBatchKeysFromEnv() EdBatchKeys {
    return if (envGet("ZUI_ED25519_BATCH_KEYS")) |s| parseEdBatchKeys(s).keys else .{};
}

/// The switches for the variable's text (null: unset). A token that is not a name: both off,
/// with a warning.
pub fn edBatchKeysInit(text: ?[]const u8) EdBatchKeys {
    const p = parseEdBatchKeys(text orelse return .{});
    if (p.bad) |t| warnSwitch("ZUI_ED25519_BATCH_KEYS", "a comma-separated list of cache and merge, or all, or off", t);
    return p.keys;
}

pub fn edBatchKeys() EdBatchKeys {
    var v = ed_batch_keys.load(.monotonic);
    if (v == 0xff) {
        // the first read, as in `edVec4`
        const text = envGet("ZUI_ED25519_BATCH_KEYS");
        const quiet = edBatchKeysBits(if (text) |s| parseEdBatchKeys(s).keys else .{});
        if (ed_batch_keys.cmpxchgStrong(0xff, quiet, .monotonic, .monotonic)) |now| {
            v = now;
        } else v = edBatchKeysBits(edBatchKeysInit(text));
    }
    return .{ .cache = v & 1 != 0, .merge = v & 2 != 0 };
}

pub fn setEdBatchKeys(k: EdBatchKeys) void {
    ed_batch_keys.store(edBatchKeysBits(k), .monotonic);
}

/// Test builds count the warnings instead of logging them (the build runner fails a test that
/// writes to stderr) and keep the last variable name.
pub var test_switch_warnings: std.atomic.Value(usize) = .init(0);
pub var test_switch_warned: []const u8 = "";

/// One warning for a switch variable whose value is not understood: the switch stays off, and a
/// run that asked for it must not pass for a run that had it.
fn warnSwitch(comptime name: []const u8, comptime want: []const u8, bad: []const u8) void {
    if (builtin.is_test) {
        test_switch_warned = name;
        _ = test_switch_warnings.fetchAdd(1, .monotonic);
        return;
    }
    std.log.warn(name ++ ": \"{s}\" is not a value it takes (" ++ want ++ "); the switch stays off", .{bad});
}

/// Whether mode `m` runs the four-way kernel on tier `t` of this build.
pub fn edVec4On(m: EdVec4, t: Tier) bool {
    return switch (m) {
        .off => false,
        .on => is_x86 and t == .avx2,
        .force => true,
    };
}

/// Whether the four-way kernel runs now (the live mode on the live tier).
pub fn edVec4Live() bool {
    return edVec4On(edVec4(), tier());
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
    ed_vec4: EdVec4 = .off,
};

pub fn liveSel() Sel {
    return .{ .sha_ni = info().sha_ni and shaNiAllowed(), .arm_sha2 = armSha2Allowed(), .arm_sha512 = armSha512Allowed(), .arm_sha3 = armSha3Wanted(), .ed_vec4 = edVec4() };
}

pub fn kernelName(p: Prim, t: Tier, sha_ni: bool) []const u8 {
    var sel = liveSel();
    sel.sha_ni = sha_ni;
    return kernelNameFor(p, t, sel);
}

pub fn kernelNameFor(p: Prim, t: Tier, sel: Sel) []const u8 {
    if (comptime !is_x86) return switch (builtin.cpu.arch) {
        .aarch64 => switch (p) {
            .ed25519 => if (edVec4On(sel.ed_vec4, t)) "radix25.5x4-neon" else "radix51-neon",
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
    return x86KernelName(p, t, sel, edVec4On(sel.ed_vec4, t));
}

/// The x86-64 names (a plain function of its arguments, so any target can test it). `ed_x4`:
/// the Ed25519 four-way point kernel runs (`edVec4On`).
///
/// Ed25519: the avx2 tier's default kernel is the scalar radix-2^51 code compiled with BMI2 and
/// ADX (`radix51-bmi2`; it has no vector point arithmetic, which the old name `radix51-avx2`
/// suggested). The four-way kernel is `radix25.5x4-<lowering>`. On the avx512 tier the single
/// verify runs the IFMA kernel either way; with the four-way kernel forced, the batch chain runs it.
pub fn x86KernelName(p: Prim, t: Tier, sel: Sel, ed_x4: bool) []const u8 {
    const sha_ni = sel.sha_ni;
    return switch (p) {
        .ed25519 => switch (t) {
            .baseline => if (ed_x4) "radix25.5x4-sse2" else "radix51",
            .avx2 => if (ed_x4) "radix25.5x4-avx2" else "radix51-bmi2",
            .avx512 => if (ed_x4) "ifma+x4-batch" else "ifma",
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

/// The Ed25519 switches as the startup line shows them: the vec4 mode and whether it runs the
/// four-way kernel on tier `t`, then the batch key switches (`cache` only reads the decoded-key
/// cache of sig/fast.zig while that cache is on).
pub fn writeEdSwitches(w: *std.Io.Writer, vec4: EdVec4, t: Tier, keys: EdBatchKeys) std.Io.Writer.Error!void {
    try w.print("ed25519-vec4={s}", .{@tagName(vec4)});
    if (vec4 != .off) try w.writeAll(if (edVec4On(vec4, t)) " (four-way kernel running)" else " (no effect on this tier)");
    try w.print(" ed25519-batch-keys={s}", .{edBatchKeysName(keys)});
}

/// The batch key switches as ZUI_ED25519_BATCH_KEYS spells them.
pub fn edBatchKeysName(k: EdBatchKeys) []const u8 {
    return if (k.cache and k.merge) "cache,merge" else if (k.cache) "cache" else if (k.merge) "merge" else "off";
}

/// The startup line: tier, CPU, the kernel per primitive, and the Ed25519 switches in force.
pub fn writeChoice(w: *std.Io.Writer) std.Io.Writer.Error!void {
    const i = info();
    const live = tier();
    try w.print("cpu: tier {s}", .{@tagName(live)});
    if (live != i.tier) try w.print(" (forced; detected {s})", .{@tagName(i.tier)});
    try w.print(" (supported {s}, build {s}{s}) {s}; kernels:", .{
        @tagName(i.supported),
        @tagName(native_tier),
        if (i.override_ignored) ", ZUI_CPU ignored" else "",
        if (i.brand_len > 0) i.brandName() else @tagName(builtin.cpu.arch),
    });
    for (std.enums.values(Prim)) |p| try w.print(" {s}={s}", .{ @tagName(p), kernelName(p, live, i.sha_ni and shaNiAllowed()) });
    try w.writeAll("; switches: ");
    try writeEdSwitches(w, edVec4(), live, edBatchKeys());
}

/// One startup line (`writeChoice`).
pub fn logChoice() void {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    writeChoice(&w) catch {};
    std.log.info("{s}", .{w.buffered()});
}

/// Prometheus lines: `zui_cpu_kernel{prim="ed25519",kernel="radix51-bmi2"} 1` per primitive,
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

test "kernelName: the Ed25519 name on the avx2 tier says what runs" {
    const sel: Sel = .{ .sha_ni = false };
    // the default avx2-tier kernel is scalar radix-2^51 code (BMI2/ADX): no "avx2" in its name
    try std.testing.expectEqualStrings("radix51-bmi2", x86KernelName(.ed25519, .avx2, sel, false));
    try std.testing.expect(std.mem.indexOf(u8, x86KernelName(.ed25519, .avx2, sel, false), "avx2") == null);
    // the four-way kernel, when it runs
    try std.testing.expectEqualStrings("radix25.5x4-avx2", x86KernelName(.ed25519, .avx2, sel, true));
    try std.testing.expectEqualStrings("radix51", x86KernelName(.ed25519, .baseline, sel, false));
    try std.testing.expectEqualStrings("radix25.5x4-sse2", x86KernelName(.ed25519, .baseline, sel, true));
    try std.testing.expectEqualStrings("ifma", x86KernelName(.ed25519, .avx512, sel, false));
    try std.testing.expectEqualStrings("ifma+x4-batch", x86KernelName(.ed25519, .avx512, sel, true));
    // which tiers each mode covers
    try std.testing.expect(!edVec4On(.off, .avx2) and !edVec4On(.off, .baseline));
    try std.testing.expect(edVec4On(.force, .baseline) and edVec4On(.force, .avx2) and edVec4On(.force, .avx512));
    try std.testing.expect(!edVec4On(.on, .baseline));
    try std.testing.expectEqual(is_x86, edVec4On(.on, .avx2));
    try std.testing.expect(!edVec4On(.on, .avx512));
    // the live name follows the switch
    if (is_x86 or builtin.cpu.arch == .aarch64) {
        const before = edVec4();
        defer setEdVec4(before);
        setEdVec4(.off);
        const off_name = kernelName(.ed25519, tier(), false);
        setEdVec4(.force);
        const on_name = kernelName(.ed25519, tier(), false);
        try std.testing.expect(std.mem.indexOf(u8, on_name, "x4") != null);
        try std.testing.expect(std.mem.indexOf(u8, off_name, "x4") == null);
    }
    try std.testing.expectEqual(EdVec4.on, parseEdVec4("1").?);
    try std.testing.expectEqual(EdVec4.force, parseEdVec4("force").?);
    try std.testing.expectEqual(EdVec4.off, parseEdVec4("off").?);
    try std.testing.expect(parseEdVec4("maybe") == null);
    try std.testing.expectEqual(EdVec4.on, parseEdVec4(" ON ").?);
    try std.testing.expect(parseEdVec4("force,on") == null and parseEdVec4("noforce") == null and parseEdVec4("") == null);
    // the environment read: run the tests with ZUI_ED25519_VEC4 set to check it end to end
    const want: EdVec4 = blk: {
        const v = std.testing.environ.getAlloc(std.testing.allocator, "ZUI_ED25519_VEC4") catch break :blk .off;
        defer std.testing.allocator.free(v);
        break :blk parseEdVec4(v) orelse .off;
    };
    if (comptime builtin.link_libc) try std.testing.expectEqual(want, edVec4FromEnv());
}

test "Ed25519 switch variables: exact tokens, and a warning for a token that is not a name" {
    const K = EdBatchKeys;
    const eq = std.meta.eql;
    try std.testing.expect(eq(parseEdBatchKeys("cache,merge").keys, K{ .cache = true, .merge = true }));
    try std.testing.expect(eq(parseEdBatchKeys("merge, cache").keys, K{ .cache = true, .merge = true }));
    try std.testing.expect(eq(parseEdBatchKeys("all").keys, K{ .cache = true, .merge = true }));
    try std.testing.expect(eq(parseEdBatchKeys("1").keys, K{ .cache = true, .merge = true }));
    try std.testing.expect(eq(parseEdBatchKeys("merge").keys, K{ .merge = true }));
    try std.testing.expect(eq(parseEdBatchKeys("Cache").keys, K{ .cache = true }));
    try std.testing.expect(eq(parseEdBatchKeys("cache,").keys, K{ .cache = true }));
    for ([_][]const u8{ "off", "0", "", " ", "OFF" }) |s| {
        const p = parseEdBatchKeys(s);
        try std.testing.expect(eq(p.keys, K{}) and p.bad == null);
    }
    // a name inside a longer word is not that name: nothing is switched on, and the token is reported
    for ([_][2][]const u8{
        .{ "nomerge", "nomerge" },         .{ "nocache", "nocache" },         .{ "cache,nomerge", "nomerge" }, .{ "merged", "merged" },
        .{ "cache merge", "cache merge" }, .{ "cache;merge", "cache;merge" }, .{ "merge,off", "off" },         .{ "0,cache", "0" },
        .{ "on", "on" },                   .{ "true", "true" },               .{ "all,x", "x" },
    }) |c| {
        const p = parseEdBatchKeys(c[0]);
        try std.testing.expect(eq(p.keys, K{}));
        try std.testing.expectEqualStrings(c[1], p.bad.?);
    }
    // the first read of each variable: a good value makes no warning, a bad one makes one and is off
    const w0 = test_switch_warnings.load(.monotonic);
    try std.testing.expect(eq(edBatchKeysInit(null), K{}) and eq(edBatchKeysInit("merge"), K{ .merge = true }));
    try std.testing.expect(edVec4Init(null) == .off and edVec4Init("force") == .force and edVec4Init("0") == .off);
    try std.testing.expectEqual(w0, test_switch_warnings.load(.monotonic));
    try std.testing.expect(eq(edBatchKeysInit("cache,nomerge"), K{}));
    try std.testing.expectEqual(w0 + 1, test_switch_warnings.load(.monotonic));
    try std.testing.expectEqualStrings("ZUI_ED25519_BATCH_KEYS", test_switch_warned);
    try std.testing.expectEqual(EdVec4.off, edVec4Init("yes"));
    try std.testing.expectEqual(w0 + 2, test_switch_warnings.load(.monotonic));
    try std.testing.expectEqualStrings("ZUI_ED25519_VEC4", test_switch_warned);
    // set and read back
    const before = edBatchKeys();
    defer setEdBatchKeys(before);
    setEdBatchKeys(.{ .merge = true });
    try std.testing.expect(eq(edBatchKeys(), K{ .merge = true }));
    setEdBatchKeys(.{ .cache = true });
    try std.testing.expect(eq(edBatchKeys(), K{ .cache = true }));
    // the environment read: run the tests with ZUI_ED25519_BATCH_KEYS set to check it end to end
    const want: K = blk: {
        const v = std.testing.environ.getAlloc(std.testing.allocator, "ZUI_ED25519_BATCH_KEYS") catch break :blk .{};
        defer std.testing.allocator.free(v);
        break :blk parseEdBatchKeys(v).keys;
    };
    if (comptime builtin.link_libc) try std.testing.expect(eq(want, edBatchKeysFromEnv()));
}

test "startup line: the Ed25519 switches in force and whether vec4 runs on the tier" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeEdSwitches(&w, .off, .avx2, .{});
    try std.testing.expectEqualStrings("ed25519-vec4=off ed25519-batch-keys=off", w.buffered());
    w = .fixed(&buf);
    try writeEdSwitches(&w, .on, .avx2, .{ .cache = true, .merge = true });
    try std.testing.expectEqualStrings(if (is_x86) "ed25519-vec4=on (four-way kernel running) ed25519-batch-keys=cache,merge" else "ed25519-vec4=on (no effect on this tier) ed25519-batch-keys=cache,merge", w.buffered());
    // on: a no-op off the avx2 tier, and the line says so
    for ([_]Tier{ .baseline, .avx512 }) |t| {
        w = .fixed(&buf);
        try writeEdSwitches(&w, .on, t, .{ .merge = true });
        try std.testing.expectEqualStrings("ed25519-vec4=on (no effect on this tier) ed25519-batch-keys=merge", w.buffered());
        w = .fixed(&buf);
        try writeEdSwitches(&w, .force, t, .{ .cache = true });
        try std.testing.expectEqualStrings("ed25519-vec4=force (four-way kernel running) ed25519-batch-keys=cache", w.buffered());
    }
    // the whole line carries the live switches after the kernels
    const vec_before = edVec4();
    defer setEdVec4(vec_before);
    const keys_before = edBatchKeys();
    defer setEdBatchKeys(keys_before);
    var line: [1024]u8 = undefined;
    setEdVec4(.off);
    setEdBatchKeys(.{});
    var lw: std.Io.Writer = .fixed(&line);
    try writeChoice(&lw);
    try std.testing.expect(std.mem.startsWith(u8, lw.buffered(), "cpu: tier "));
    try std.testing.expect(std.mem.indexOf(u8, lw.buffered(), "; kernels: ed25519=") != null);
    try std.testing.expect(std.mem.endsWith(u8, lw.buffered(), "; switches: ed25519-vec4=off ed25519-batch-keys=off"));
    setEdVec4(.force);
    setEdBatchKeys(.{ .cache = true, .merge = true });
    lw = .fixed(&line);
    try writeChoice(&lw);
    try std.testing.expect(std.mem.endsWith(u8, lw.buffered(), "; switches: ed25519-vec4=force (four-way kernel running) ed25519-batch-keys=cache,merge"));
    // and the kernel name in the same line follows the switch
    try std.testing.expect(std.mem.indexOf(u8, lw.buffered(), "x4") != null or !(is_x86 or builtin.cpu.arch == .aarch64));
}

test "parseTier" {
    try std.testing.expectEqual(Tier.avx2, parseTier("AVX2").?);
    try std.testing.expectEqual(Tier.avx512, parseTier("ifma").?);
    try std.testing.expectEqual(Tier.baseline, parseTier("baseline").?);
    try std.testing.expect(parseTier("sse9") == null);
}
