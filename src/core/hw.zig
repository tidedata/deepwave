//! Machine-aware paths: startup hardware detection, profiles, and overrides.
//!
//!   detect()   what the machine has: CPU features (x86 CPUID, Arm via Linux HWCAP or macOS
//!              sysctl), logical and physical cores, RAM, and the kind of disk under a path.
//!   Spec       the user's overrides, parsed from `ZUI_HW` and `--hw`:
//!                profile=auto|small|server|mac|validator
//!                cpu=baseline|avx2|avx512     cap the dispatch tier (same as ZUI_CPU)
//!                avx2=off avx512=off          drop tiers by name
//!                sha_ni=on|off                SHA-NI hashing (x86)
//!                arm_sha2=on|off arm_sha512=on|off arm_sha3=on|off dit=on|off   Arm paths (aarch64;
//!                             arm_sha3 is off unless asked: Keccak runs the portable rounds today)
//!                net_iface=NAME               preferred network interface (validator; read by the net lane)
//!                metal=on|off gpu=on|off      accelerators: off never opens a device; on/auto open
//!                                             them and the dispatch table decides (Plan.gpu_mode)
//!                dispatch=auto|cpu1|pool|gpu|gpuN|mix|mixN   force one batch path for every op
//!                gpu_devices=N                use at most N GPUs
//!                threads=N                    CPU pool lanes for batch work (default: cores)
//!                calibrate=auto|force|off     dispatch calibration: cached, redo now, static table
//!                pin=on|off reserve=N         pin the process to its cores, leaving N for the OS
//!                cores=N ram_gb=N             pretend the machine is smaller (tests, shared boxes)
//!                exec_cache_mb=N chunk_cache_mb=N cp_cache_mb=N   cache budgets
//!              Unknown keys and bad values are errors, never ignored.
//!   plan()     machine + spec -> Plan: the profile and every number it chose.
//!   apply()    pushes the dispatch toggles into core/cpu.zig and (if asked) pins cores.
//!
//! Nothing here changes behaviour unless the caller applies a Plan: the node only does so when
//! `--hw` / `ZUI_HW` is given, so a plain start keeps today's defaults.
const std = @import("std");
const builtin = @import("builtin");
const cpu = @import("cpu.zig");
const dispatch = @import("dispatch.zig");

const is_x86 = builtin.cpu.arch == .x86_64;
const is_arm = builtin.cpu.arch == .aarch64;
const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;

pub const DiskKind = enum { unknown, hdd, ssd, nvme };

/// Instruction-set features the kernels care about. Unused ones for the other arch stay false.
pub const Features = struct {
    // x86-64 (CPUID with the OS vector state checked)
    sse4_2: bool = false,
    avx: bool = false,
    avx2: bool = false,
    bmi2: bool = false,
    adx: bool = false,
    sha_ni: bool = false,
    aes_ni: bool = false,
    pclmul: bool = false,
    avx512f: bool = false,
    avx512bw: bool = false,
    avx512vl: bool = false,
    avx512ifma: bool = false,
    avx512vbmi: bool = false,
    // aarch64 (OS reported: HWCAP on Linux, hw.optional.arm.FEAT_* on macOS)
    arm_aes: bool = false,
    arm_pmull: bool = false,
    arm_sha2: bool = false,
    arm_sha512: bool = false,
    arm_sha3: bool = false,
    arm_crc32: bool = false,
    arm_dit: bool = false,
    arm_lse: bool = false,

    pub fn name(comptime f: std.meta.FieldEnum(Features)) []const u8 {
        return @tagName(f);
    }

    /// `a b c` list of the set features, written into `w`.
    pub fn write(f: Features, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var first = true;
        inline for (comptime std.meta.fieldNames(Features)) |fname| {
            if (@field(f, fname)) {
                if (!first) try w.writeByte(' ');
                try w.writeAll(fname);
                first = false;
            }
        }
        if (first) try w.writeAll("none");
    }
};

pub const Machine = struct {
    arch: std.Target.Cpu.Arch,
    os: std.Target.Os.Tag,
    features: Features,
    /// Dispatch tier core/cpu.zig chose (x86-64; `baseline` elsewhere).
    tier: cpu.Tier,
    tier_supported: cpu.Tier,
    logical_cores: u32,
    /// 0 when unknown. On macOS the performance cores (hw.perflevel0).
    physical_cores: u32,
    ram_bytes: u64,
    /// The data directory's backing device.
    disk: DiskKind,
    /// A compute GPU is present (Linux: NVIDIA or AMD DRM device; macOS: Metal is assumed).
    gpu: bool = false,
    /// Whether core/cpu.zig can switch to each tier (`cpu.canForce`), by tier number. False for
    /// tiers below the build's own and for tiers with no linked kernel object.
    can_force: [3]bool = .{ true, true, true },
    brand: [48]u8 = @splat(' '),
    brand_len: u8 = 0,

    pub fn brandName(m: *const Machine) []const u8 {
        return std.mem.trim(u8, m.brand[0..m.brand_len], " ");
    }
};

// ---------------------------------------------------------------------------------------------
// Detection

/// Detects the machine. `data_dir` (may be null) names the path whose disk is classified.
pub fn detect(data_dir: ?[]const u8) Machine {
    const ci = cpu.info();
    var m: Machine = .{
        .arch = builtin.cpu.arch,
        .os = builtin.os.tag,
        .features = detectFeatures(),
        .tier = ci.tier,
        .tier_supported = ci.supported,
        .logical_cores = logicalCores(),
        .physical_cores = 0,
        .ram_bytes = ramBytes(),
        .disk = .unknown,
        .gpu = detectGpu(),
        .brand = ci.brand,
        .brand_len = ci.brand_len,
    };
    m.physical_cores = physicalCores(m.logical_cores);
    for (std.enums.values(cpu.Tier)) |t| m.can_force[@intFromEnum(t)] = cpu.canForce(t);
    if (m.brand_len == 0 and is_macos and builtin.link_libc) {
        var len: usize = m.brand.len;
        if (std.c.sysctlbyname("machdep.cpu.brand_string", &m.brand, &len, null, 0) == 0 and len > 0)
            m.brand_len = @intCast(@min(m.brand.len, std.mem.indexOfScalar(u8, m.brand[0..len], 0) orelse len));
    }
    if (data_dir) |d| m.disk = diskKind(d);
    if (m.disk == .unknown and is_macos) m.disk = .nvme; // every Mac with Metal boots from soldered NVMe
    return m;
}

fn bitAt(x: u32, comptime n: u5) bool {
    return (x >> n) & 1 == 1;
}

pub fn detectFeatures() Features {
    var f: Features = .{};
    if (comptime is_x86) {
        const l0 = cpu.cpuid(0, 0);
        const zero: cpu.Regs = .{ .a = 0, .b = 0, .c = 0, .d = 0 };
        const l1 = if (l0.a >= 1) cpu.cpuid(1, 0) else zero;
        const l7 = if (l0.a >= 7) cpu.cpuid(7, 0) else zero;
        const x: u64 = if (bitAt(l1.c, 27)) cpu.xcr0() else 0;
        const os_avx = x & 0x6 == 0x6;
        const os_avx512 = x & 0xe6 == 0xe6;
        f.sse4_2 = bitAt(l1.c, 20);
        f.aes_ni = bitAt(l1.c, 25);
        f.pclmul = bitAt(l1.c, 1);
        f.avx = bitAt(l1.c, 28) and os_avx;
        f.avx2 = bitAt(l7.b, 5) and os_avx;
        f.bmi2 = bitAt(l7.b, 8);
        f.adx = bitAt(l7.b, 19);
        f.sha_ni = bitAt(l7.b, 29) and bitAt(l1.c, 9) and bitAt(l1.c, 19);
        f.avx512f = bitAt(l7.b, 16) and os_avx512;
        f.avx512bw = bitAt(l7.b, 30) and os_avx512;
        f.avx512vl = bitAt(l7.b, 31) and os_avx512;
        f.avx512ifma = bitAt(l7.b, 21) and os_avx512;
        f.avx512vbmi = bitAt(l7.c, 1) and os_avx512;
    } else if (comptime is_arm and is_linux) {
        const hwcap: u64 = if (comptime builtin.link_libc) std.c.getauxval(16) else 0; // AT_HWCAP
        f.arm_aes = hwcap & (1 << 3) != 0;
        f.arm_pmull = hwcap & (1 << 4) != 0;
        f.arm_sha2 = hwcap & (1 << 6) != 0;
        f.arm_crc32 = hwcap & (1 << 7) != 0;
        f.arm_lse = hwcap & (1 << 8) != 0;
        f.arm_sha3 = hwcap & (1 << 17) != 0;
        f.arm_sha512 = hwcap & (1 << 21) != 0;
        f.arm_dit = hwcap & (1 << 24) != 0;
    } else if (comptime is_arm and is_macos) {
        f.arm_aes = sysctlFlag("hw.optional.arm.FEAT_AES");
        f.arm_pmull = sysctlFlag("hw.optional.arm.FEAT_PMULL");
        f.arm_sha2 = sysctlFlag("hw.optional.arm.FEAT_SHA256");
        f.arm_sha512 = sysctlFlag("hw.optional.arm.FEAT_SHA512");
        f.arm_sha3 = sysctlFlag("hw.optional.arm.FEAT_SHA3");
        f.arm_crc32 = sysctlFlag("hw.optional.armv8_crc32");
        f.arm_dit = sysctlFlag("hw.optional.arm.FEAT_DIT");
        f.arm_lse = sysctlFlag("hw.optional.arm.FEAT_LSE");
    }
    return f;
}

fn sysctlU64(name: [*:0]const u8) ?u64 {
    if (comptime !(is_macos and builtin.link_libc)) return null;
    var v: u64 = 0;
    var len: usize = @sizeOf(u64);
    if (std.c.sysctlbyname(name, &v, &len, null, 0) != 0) return null;
    // sysctl returns 4 or 8 bytes depending on the key (little endian on every Mac).
    return if (len == 4) @as(u32, @truncate(v)) else v;
}

fn sysctlFlag(name: [*:0]const u8) bool {
    return (sysctlU64(name) orelse 0) != 0;
}

fn logicalCores() u32 {
    if (comptime is_linux) {
        // The affinity mask is what the process may run on (containers, taskset).
        var set: std.os.linux.cpu_set_t = @splat(0);
        if (std.os.linux.sched_getaffinity(0, @sizeOf(std.os.linux.cpu_set_t), &set) == 0) {
            var n: u32 = 0;
            for (set) |w| n += @popCount(w);
            if (n > 0) return capByCgroupCpu(n);
        }
    }
    return @intCast(@max(1, std.Thread.getCpuCount() catch 1));
}

/// A container's CPU quota (cgroup v2 cpu.max, v1 cfs quota) caps the usable core count.
fn capByCgroupCpu(n: u32) u32 {
    if (comptime !is_linux) return n;
    var buf: [128]u8 = undefined;
    // cgroup v2: the tightest cpu.max on the path from this process's own cgroup up to the root
    // (a systemd unit's CPUQuota sits on the unit's cgroup, not on /sys/fs/cgroup itself).
    var db: [256]u8 = undefined;
    if (cgroupV2Dir(&db)) |dir| {
        var best: ?u32 = null;
        var it: CgroupWalk = .{ .dir = dir };
        while (it.next()) |d| {
            var pb: [300]u8 = undefined;
            const path = std.fmt.bufPrint(&pb, "{s}/cpu.max", .{d}) catch break;
            if (readSmall(path, &buf)) |t| if (parseCpuMax(t)) |q| {
                best = if (best) |b| @min(b, q) else q;
            };
        }
        return if (best) |q| @max(1, @min(n, q)) else n;
    }
    var b2: [64]u8 = undefined;
    const q = readSmall("/sys/fs/cgroup/cpu/cpu.cfs_quota_us", &buf) orelse return n;
    const pr = readSmall("/sys/fs/cgroup/cpu/cpu.cfs_period_us", &b2) orelse return n;
    const qv = std.fmt.parseInt(i64, std.mem.trim(u8, q, " \n"), 10) catch return n;
    const pv = std.fmt.parseInt(i64, std.mem.trim(u8, pr, " \n"), 10) catch return n;
    if (qv <= 0 or pv <= 0) return n;
    return @max(1, @min(n, @as(u32, @intCast(@min(@divTrunc(qv + pv - 1, pv), 1 << 20)))));
}

/// Cores allowed by cgroup v2 `cpu.max` text (`max 100000` or `200000 100000`): ceil(quota /
/// period), null when unlimited or malformed.
pub fn parseCpuMax(s: []const u8) ?u32 {
    var it = std.mem.tokenizeAny(u8, s, " \t\n");
    const q = it.next() orelse return null;
    const per = it.next() orelse return null;
    if (std.mem.eql(u8, q, "max")) return null;
    const qv = std.fmt.parseInt(u64, q, 10) catch return null;
    const pv = std.fmt.parseInt(u64, per, 10) catch return null;
    if (qv == 0 or pv == 0) return null;
    return @intCast(@min((qv + pv - 1) / pv, 1 << 20));
}

/// Memory limit of cgroup `memory.max` / `memory.limit_in_bytes` text; null for `max` and for the
/// v1 "no limit" values (near 2^63).
pub fn parseCgroupMem(s: []const u8) ?u64 {
    const t = std.mem.trim(u8, s, " \t\n");
    if (std.mem.eql(u8, t, "max")) return null;
    const v = std.fmt.parseInt(u64, t, 10) catch return null;
    if (v == 0 or v >= (1 << 60)) return null;
    return v;
}

/// Compute GPU present. Linux: /dev/nvidia0, or a DRM card from NVIDIA (10de) or AMD (1002).
fn detectGpu() bool {
    if (comptime is_macos) return builtin.cpu.arch == .aarch64; // Metal on every Apple silicon Mac
    if (comptime !is_linux) return false;
    if (std.os.linux.access("/dev/nvidia0", 0) == 0) return true;
    var buf: [16]u8 = undefined;
    var pb: [64]u8 = undefined;
    for (0..8) |k| {
        const path = std.fmt.bufPrint(&pb, "/sys/class/drm/card{d}/device/vendor", .{k}) catch continue;
        const v = std.mem.trim(u8, readSmall(path, &buf) orelse continue, " \n");
        if (std.ascii.eqlIgnoreCase(v, "0x10de") or std.ascii.eqlIgnoreCase(v, "0x1002")) return true;
    }
    return false;
}

fn physicalCores(logical: u32) u32 {
    if (comptime is_macos) {
        if (sysctlU64("hw.perflevel0.physicalcpu")) |n| if (n > 0) return @intCast(n);
        if (sysctlU64("hw.physicalcpu")) |n| if (n > 0) return @intCast(n);
        return 0;
    }
    if (comptime is_linux) {
        // Sibling count of cpu0 (SMT width): physical = logical / siblings.
        var buf: [128]u8 = undefined;
        const s = readSmall("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list", &buf) orelse return 0;
        const w = countCpuList(std.mem.trim(u8, s, " \n"));
        if (w == 0) return 0;
        return @max(1, logical / w);
    }
    return 0;
}

/// Entries in a kernel cpu list such as `0,24` or `0-1,8-9`.
pub fn countCpuList(s: []const u8) u32 {
    var n: u32 = 0;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        if (std.mem.indexOfScalar(u8, part, '-')) |d| {
            const a = std.fmt.parseInt(u32, part[0..d], 10) catch return 0;
            const b = std.fmt.parseInt(u32, part[d + 1 ..], 10) catch return 0;
            if (b < a) return 0;
            n += b - a + 1;
        } else {
            _ = std.fmt.parseInt(u32, part, 10) catch return 0;
            n += 1;
        }
    }
    return n;
}

fn ramBytes() u64 {
    if (comptime is_macos) return sysctlU64("hw.memsize") orelse 0;
    if (comptime is_linux) {
        var buf: [4096]u8 = undefined;
        const s = readSmall("/proc/meminfo", &buf) orelse return 0;
        var total = parseMemTotal(s);
        // A container's or unit's memory limit is what the OOM killer (memory.max) and the
        // reclaim throttle (memory.high) enforce, not the host's RAM: the tightest of both on the
        // path from this process's own cgroup up to the root (cgroup v2), else cgroup v1's limit.
        var cb: [64]u8 = undefined;
        var db: [256]u8 = undefined;
        if (cgroupV2Dir(&db)) |dir| {
            var it: CgroupWalk = .{ .dir = dir };
            while (it.next()) |d| {
                for ([_][]const u8{ "memory.max", "memory.high" }) |f| {
                    var pb: [300]u8 = undefined;
                    const path = std.fmt.bufPrint(&pb, "{s}/{s}", .{ d, f }) catch continue;
                    if (readSmall(path, &cb)) |t| if (parseCgroupMem(t)) |lim| {
                        if (total == 0 or lim < total) total = lim;
                    };
                }
            }
            return total;
        }
        if (readSmall("/sys/fs/cgroup/memory/memory.limit_in_bytes", &cb)) |t| if (parseCgroupMem(t)) |lim| {
            if (total == 0 or lim < total) total = lim;
        };
        return total;
    }
    return 0;
}

/// This process's cgroup v2 directory (`/sys/fs/cgroup` + the `0::` path of /proc/self/cgroup),
/// or null without a cgroup v2 hierarchy.
fn cgroupV2Dir(out: []u8) ?[]const u8 {
    var buf: [1024]u8 = undefined;
    const s = readSmall("/proc/self/cgroup", &buf) orelse return null;
    const rel = cgroupV2Path(s) orelse return null;
    if (readSmall("/sys/fs/cgroup/cgroup.controllers", out) == null) return null;
    return std.fmt.bufPrint(out, "/sys/fs/cgroup{s}", .{if (std.mem.eql(u8, rel, "/")) "" else rel}) catch null;
}

/// The path of the `0::` (cgroup v2) line of /proc/self/cgroup text.
pub fn cgroupV2Path(s: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, s, '\n');
    while (lines.next()) |ln| {
        if (std.mem.startsWith(u8, ln, "0::")) {
            const p = std.mem.trim(u8, ln[3..], " \r");
            if (p.len == 0 or p[0] != '/') return null;
            return p;
        }
    }
    return null;
}

/// A cgroup directory and each parent up to and including `/sys/fs/cgroup`.
pub const CgroupWalk = struct {
    dir: ?[]const u8,
    pub fn next(w: *CgroupWalk) ?[]const u8 {
        const d = w.dir orelse return null;
        const root = "/sys/fs/cgroup";
        if (d.len <= root.len) {
            w.dir = null;
        } else {
            const cut = std.mem.lastIndexOfScalar(u8, d, '/') orelse root.len;
            w.dir = d[0..@max(cut, root.len)];
        }
        return d;
    }
};

/// MemTotal of /proc/meminfo text, in bytes (0 when absent).
pub fn parseMemTotal(s: []const u8) u64 {
    var lines = std.mem.splitScalar(u8, s, '\n');
    while (lines.next()) |ln| {
        if (!std.mem.startsWith(u8, ln, "MemTotal:")) continue;
        var t = std.mem.trim(u8, ln["MemTotal:".len..], " \t");
        if (std.mem.endsWith(u8, t, "kB")) t = std.mem.trim(u8, t[0 .. t.len - 2], " \t");
        return (std.fmt.parseInt(u64, t, 10) catch return 0) * 1024;
    }
    return 0;
}

/// Reads up to buf.len bytes of a small pseudo file (Linux only; null anywhere else or on error).
fn readSmall(path: []const u8, buf: []u8) ?[]u8 {
    if (comptime !is_linux) return null;
    var pz: [256:0]u8 = undefined;
    if (path.len >= pz.len) return null;
    @memcpy(pz[0..path.len], path);
    pz[path.len] = 0;
    const fd_r = std.os.linux.open(&pz, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (@as(isize, @bitCast(fd_r)) < 0) return null;
    const fd: i32 = @intCast(fd_r);
    defer _ = std.os.linux.close(fd);
    var n: usize = 0;
    while (n < buf.len) {
        const r = std.os.linux.read(fd, buf.ptr + n, buf.len - n);
        if (@as(isize, @bitCast(r)) < 0) return null;
        if (r == 0) break;
        n += r;
    }
    return buf[0..n];
}

/// Kind of the disk backing `path`. Linux: statx device number -> /sys/dev/block/MAJ:MIN
/// (nvme by name, else queue/rotational, looking at the parent disk for a partition).
fn diskKind(path: []const u8) DiskKind {
    if (comptime !is_linux) return .unknown;
    var pz: [4096:0]u8 = undefined;
    if (path.len >= pz.len) return .unknown;
    @memcpy(pz[0..path.len], path);
    pz[path.len] = 0;
    var sx: std.os.linux.Statx = undefined;
    // A fresh node has no data dir yet: classify the nearest parent that exists.
    var plen = path.len;
    while (true) {
        const rc = std.os.linux.statx(std.os.linux.AT.FDCWD, &pz, 0, .{ .TYPE = true }, &sx);
        if (@as(isize, @bitCast(rc)) == 0) break;
        // Strip the last path component ("." when nothing is left).
        var e = plen;
        while (e > 1 and pz[e - 1] == '/') e -= 1;
        while (e > 0 and pz[e - 1] != '/') e -= 1;
        while (e > 1 and pz[e - 1] == '/') e -= 1;
        if (e == 0) {
            if (plen == 1 and pz[0] == '.') return .unknown;
            pz[0] = '.';
            e = 1;
        }
        if (e == plen and pz[e - 1] != '.') return .unknown;
        plen = e;
        pz[plen] = 0;
    }
    return diskKindOfDev(sx.dev_major, sx.dev_minor);
}

pub fn diskKindOfDev(major: u32, minor: u32) DiskKind {
    return diskKindDepth(major, minor, 0);
}

/// First entry name under a directory (Linux getdents64), for /sys/dev/block/M:m/slaves.
fn firstEntry(dir: []const u8, out: *[64]u8) ?[]const u8 {
    if (comptime !is_linux) return null;
    var pz: [256:0]u8 = undefined;
    if (dir.len >= pz.len) return null;
    @memcpy(pz[0..dir.len], dir);
    pz[dir.len] = 0;
    const fd_r = std.os.linux.open(&pz, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (@as(isize, @bitCast(fd_r)) < 0) return null;
    const fd: i32 = @intCast(fd_r);
    defer _ = std.os.linux.close(fd);
    var buf: [1024]u8 align(8) = undefined;
    const n_r = std.os.linux.getdents64(fd, &buf, buf.len);
    if (@as(isize, @bitCast(n_r)) <= 0) return null;
    var off: usize = 0;
    while (off + 19 < n_r) {
        const reclen = std.mem.readInt(u16, buf[off + 16 ..][0..2], .little);
        if (reclen < 19) return null;
        const nm = std.mem.sliceTo(buf[off + 19 .. @min(off + reclen, n_r)], 0);
        if (nm.len > 0 and nm[0] != '.' and nm.len <= out.len) {
            @memcpy(out[0..nm.len], nm);
            return out[0..nm.len];
        }
        off += reclen;
    }
    return null;
}

fn diskKindDepth(major: u32, minor: u32, depth: u32) DiskKind {
    if (comptime !is_linux) return .unknown;
    if (major == 0) return .unknown; // anonymous device: tmpfs, btrfs/overlay subvolume
    var link: [256:0]u8 = undefined;
    var lp: [64:0]u8 = undefined;
    const lps = std.fmt.bufPrint(&lp, "/sys/dev/block/{d}:{d}", .{ major, minor }) catch return .unknown;
    lp[lps.len] = 0;
    const n = std.os.linux.readlink(&lp, &link, link.len);
    if (@as(isize, @bitCast(n)) < 0) return .unknown;
    const target = link[0..n];
    if (std.mem.indexOf(u8, target, "/nvme") != null) return .nvme;
    // Device-mapper and md (LVM, LUKS, RAID): classify the device underneath.
    if (depth < 3 and (std.mem.indexOf(u8, target, "/dm-") != null or std.mem.indexOf(u8, target, "/md") != null)) {
        var sd: [96]u8 = undefined;
        var nm: [64]u8 = undefined;
        const dir = std.fmt.bufPrint(&sd, "/sys/dev/block/{d}:{d}/slaves", .{ major, minor }) catch return .unknown;
        if (firstEntry(dir, &nm)) |slave| {
            if (std.mem.startsWith(u8, slave, "nvme")) return .nvme;
            var dp: [192]u8 = undefined;
            var db: [32]u8 = undefined;
            const dev_path = std.fmt.bufPrint(&dp, "{s}/{s}/dev", .{ dir, slave }) catch return .unknown;
            if (readSmall(dev_path, &db)) |t| {
                const tt = std.mem.trim(u8, t, " \n");
                if (std.mem.indexOfScalar(u8, tt, ':')) |c| {
                    const mj = std.fmt.parseInt(u32, tt[0..c], 10) catch return .unknown;
                    const mn = std.fmt.parseInt(u32, tt[c + 1 ..], 10) catch return .unknown;
                    return diskKindDepth(mj, mn, depth + 1);
                }
            }
        }
    }
    var buf: [16]u8 = undefined;
    var rp: [128]u8 = undefined;
    var s = std.fmt.bufPrint(&rp, "/sys/dev/block/{d}:{d}/queue/rotational", .{ major, minor }) catch return .unknown;
    var v = readSmall(s, &buf);
    if (v == null) {
        s = std.fmt.bufPrint(&rp, "/sys/dev/block/{d}:{d}/../queue/rotational", .{ major, minor }) catch return .unknown;
        v = readSmall(s, &buf);
    }
    const t = std.mem.trim(u8, v orelse return .unknown, " \n");
    if (std.mem.eql(u8, t, "1")) return .hdd;
    if (std.mem.eql(u8, t, "0")) return .ssd;
    return .unknown;
}

// ---------------------------------------------------------------------------------------------
// Overrides

pub const Tri = enum { auto, on, off };

pub const Profile = enum {
    /// Pick from the machine (see `autoProfile`).
    auto,
    /// Verify and serve on a modest box.
    small,
    /// Big server: large in-memory caches, pinned cores.
    server,
    /// Apple silicon: unified memory, Metal, no pinning.
    mac,
    /// Consensus-tuned: server caches, pinned cores, more cores reserved for the network.
    validator,
};

/// The user's wishes. Every field is "no opinion" by default.
pub const Spec = struct {
    profile: Profile = .auto,
    /// Cap the dispatch tier.
    cpu_cap: ?cpu.Tier = null,
    avx2: Tri = .auto,
    avx512: Tri = .auto,
    sha_ni: Tri = .auto,
    metal: Tri = .auto,
    gpu: Tri = .auto,
    arm_sha2: Tri = .auto,
    arm_sha512: Tri = .auto,
    arm_sha3: Tri = .auto,
    dit: Tri = .auto,
    net_iface: [32]u8 = @splat(0),
    net_iface_len: u8 = 0,
    pin: Tri = .auto,
    reserve: ?u32 = null,
    cores: ?u32 = null,
    ram_gb: ?u32 = null,
    exec_cache_mb: ?u32 = null,
    chunk_cache_mb: ?u32 = null,
    cp_cache_mb: ?u32 = null,
    /// Force a batch path (null: the dispatch table); `gpu`/`mix` without a count mean every device.
    dispatch: ?dispatch.Path = null,
    dispatch_all_devices: bool = false,
    gpu_devices: ?u32 = null,
    threads: ?u32 = null,
    calibrate: Calibrate = .auto,
    /// True once any key was set: the node applies a Plan only then.
    any: bool = false,
};

pub const Calibrate = enum { auto, force, off };

pub const ParseError = error{ UnknownKey, BadValue, MissingValue };

/// Where a bad spec failed, for the error message.
pub const ParseFail = struct { key: [32]u8 = @splat(0), key_len: u8 = 0, value: [32]u8 = @splat(0), value_len: u8 = 0 };

fn setFail(fail: ?*ParseFail, k: []const u8, v: []const u8) void {
    const f = fail orelse return;
    f.key_len = @intCast(@min(k.len, f.key.len));
    @memcpy(f.key[0..f.key_len], k[0..f.key_len]);
    f.value_len = @intCast(@min(v.len, f.value.len));
    @memcpy(f.value[0..f.value_len], v[0..f.value_len]);
}

fn parseTri(v: []const u8) ?Tri {
    inline for (.{ .{ "on", Tri.on }, .{ "1", Tri.on }, .{ "true", Tri.on }, .{ "yes", Tri.on }, .{ "force", Tri.on }, .{ "off", Tri.off }, .{ "0", Tri.off }, .{ "false", Tri.off }, .{ "no", Tri.off }, .{ "auto", Tri.auto } }) |e| {
        if (std.ascii.eqlIgnoreCase(v, e[0])) return e[1];
    }
    return null;
}

fn parseTier(v: []const u8) ?cpu.Tier {
    for (std.enums.values(cpu.Tier)) |t| if (std.ascii.eqlIgnoreCase(v, @tagName(t))) return t;
    if (std.ascii.eqlIgnoreCase(v, "portable") or std.ascii.eqlIgnoreCase(v, "scalar")) return .baseline;
    if (std.ascii.eqlIgnoreCase(v, "ifma")) return .avx512;
    return null;
}

/// Parses `key=value,key=value` onto `spec` (later keys win; call twice to layer env then flag).
pub fn parse(spec: *Spec, text: []const u8, fail: ?*ParseFail) ParseError!void {
    var it = std.mem.tokenizeAny(u8, text, ", \t\n");
    while (it.next()) |tok| {
        const eq = std.mem.indexOfScalar(u8, tok, '=') orelse {
            setFail(fail, tok, "");
            return error.MissingValue;
        };
        const k = tok[0..eq];
        const v = tok[eq + 1 ..];
        errdefer setFail(fail, k, v);
        spec.any = true;
        if (std.mem.eql(u8, k, "profile")) {
            spec.profile = std.meta.stringToEnum(Profile, v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "cpu")) {
            spec.cpu_cap = parseTier(v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "avx2")) {
            spec.avx2 = parseTri(v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "avx512")) {
            spec.avx512 = parseTri(v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "sha_ni")) {
            spec.sha_ni = parseTri(v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "metal")) {
            spec.metal = parseTri(v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "gpu")) {
            spec.gpu = parseTri(v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "arm_sha2")) {
            spec.arm_sha2 = parseTri(v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "arm_sha512")) {
            spec.arm_sha512 = parseTri(v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "arm_sha3")) {
            spec.arm_sha3 = parseTri(v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "dit")) {
            spec.dit = parseTri(v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "net_iface")) {
            if (v.len == 0 or v.len > spec.net_iface.len) return error.BadValue;
            @memcpy(spec.net_iface[0..v.len], v);
            spec.net_iface_len = @intCast(v.len);
        } else if (std.mem.eql(u8, k, "pin")) {
            spec.pin = parseTri(v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "reserve")) {
            spec.reserve = std.fmt.parseInt(u32, v, 10) catch return error.BadValue;
        } else if (std.mem.eql(u8, k, "cores")) {
            const n = std.fmt.parseInt(u32, v, 10) catch return error.BadValue;
            if (n == 0) return error.BadValue;
            spec.cores = n;
        } else if (std.mem.eql(u8, k, "ram_gb")) {
            const n = std.fmt.parseInt(u32, v, 10) catch return error.BadValue;
            if (n == 0) return error.BadValue;
            spec.ram_gb = n;
        } else if (std.mem.eql(u8, k, "exec_cache_mb")) {
            spec.exec_cache_mb = std.fmt.parseInt(u32, v, 10) catch return error.BadValue;
        } else if (std.mem.eql(u8, k, "chunk_cache_mb")) {
            spec.chunk_cache_mb = std.fmt.parseInt(u32, v, 10) catch return error.BadValue;
        } else if (std.mem.eql(u8, k, "cp_cache_mb")) {
            spec.cp_cache_mb = std.fmt.parseInt(u32, v, 10) catch return error.BadValue;
        } else if (std.mem.eql(u8, k, "dispatch")) {
            spec.dispatch_all_devices = false;
            if (std.mem.eql(u8, v, "auto")) {
                spec.dispatch = null;
            } else if (std.mem.eql(u8, v, "gpu") or std.mem.eql(u8, v, "mix")) {
                spec.dispatch = if (v[0] == 'g') dispatch.Path.gpu(64) else dispatch.Path.mix(64);
                spec.dispatch_all_devices = true;
            } else spec.dispatch = dispatch.Path.parse(v) orelse return error.BadValue;
        } else if (std.mem.eql(u8, k, "gpu_devices")) {
            const n = std.fmt.parseInt(u32, v, 10) catch return error.BadValue;
            if (n == 0) return error.BadValue;
            spec.gpu_devices = n;
        } else if (std.mem.eql(u8, k, "threads")) {
            const n = std.fmt.parseInt(u32, v, 10) catch return error.BadValue;
            if (n == 0) return error.BadValue;
            spec.threads = n;
        } else if (std.mem.eql(u8, k, "calibrate")) {
            spec.calibrate = std.meta.stringToEnum(Calibrate, v) orelse return error.BadValue;
        } else return error.UnknownKey;
    }
}

/// `ZUI_HW` layered onto `spec` (no-op when unset).
pub fn parseEnv(spec: *Spec, fail: ?*ParseFail) ParseError!void {
    if (comptime !builtin.link_libc) return;
    const p = std.c.getenv("ZUI_HW") orelse return;
    try parse(spec, std.mem.span(p), fail);
}

// ---------------------------------------------------------------------------------------------
// Plan

pub const gib: u64 = 1 << 30;
pub const mib: u64 = 1 << 20;

pub const Plan = struct {
    profile: Profile,
    /// Tier to force at startup (null: leave core/cpu.zig's choice).
    tier: ?cpu.Tier,
    sha_ni: bool,
    arm_sha2: bool = true,
    arm_sha512: bool = true,
    arm_sha3: bool = false,
    dit: bool = true,
    metal: bool,
    gpu: bool,
    /// Batch accelerator: off (never open a device), auto (open, the dispatch table decides), on
    /// (open; same as auto, but noted when there is no device).
    gpu_mode: Tri = .auto,
    /// Forced batch path (null: the dispatch table); `gpu_devices` caps the device count.
    dispatch: ?dispatch.Path = null,
    gpu_devices: ?u32 = null,
    /// CPU pool lanes for batch work.
    pool_threads: u32 = 1,
    calibrate: Calibrate = .auto,
    /// Spinning disk under the data dir: readers should prefer large sequential reads (a flag for
    /// the store lane; nothing reads it yet).
    readahead: bool = false,
    /// Object versions per index run (`--memtable-versions`); null leaves the node default.
    memtable_versions: ?u64 = null,
    /// Request/exec worker count (`--workers`); null leaves the node's auto choice.
    workers: ?u32 = null,
    /// Inbound p2p request threads (`--p2p-listen-threads`); null leaves auto (validator only).
    net_threads: ?u16 = null,
    /// Preferred network interface for the networking lane (validator: the DoubleZero link).
    net_iface: [32]u8 = @splat(0),
    net_iface_len: u8 = 0,
    /// Cores the process may use after pinning (0..count of the available set, minus reserve).
    cores: u32,
    pin: bool,
    reserve: u32,
    exec_cache_mb: u32,
    chunk_cache_mb: u32,
    cp_cache_mb: u32,
    /// Human notes: overrides that could not be honoured and why.
    notes: [10][112]u8 = undefined,
    note_lens: [10]u8 = @splat(0),
    note_count: u8 = 0,

    fn note(p: *Plan, comptime fmt: []const u8, args: anytype) void {
        if (p.note_count >= p.notes.len) return;
        const s = std.fmt.bufPrint(&p.notes[p.note_count], fmt, args) catch &p.notes[p.note_count];
        p.note_lens[p.note_count] = @intCast(s.len);
        p.note_count += 1;
    }

    pub fn netIface(p: *const Plan) []const u8 {
        return p.net_iface[0..p.net_iface_len];
    }

    pub fn noteAt(p: *const Plan, i: usize) []const u8 {
        return p.notes[i][0..p.note_lens[i]];
    }
};

pub fn autoProfile(m: *const Machine) Profile {
    if (m.os == .macos) return .mac;
    if (m.ram_bytes >= 96 * gib and m.logical_cores >= 24) return .server;
    return .small;
}

fn tierName(t: cpu.Tier) []const u8 {
    return @tagName(t);
}

/// Machine + overrides -> the numbers to run with. Pure: nothing is applied.
pub fn plan(m: *const Machine, spec: *const Spec) Plan {
    const profile: Profile = if (spec.profile == .auto) autoProfile(m) else spec.profile;
    const cores_avail: u32 = spec.cores orelse m.logical_cores;
    const ram: u64 = if (spec.ram_gb) |g| @as(u64, g) * gib else m.ram_bytes;
    // Unknown RAM (0): behave like an 8 GiB box.
    const ram_eff: u64 = if (ram == 0) 8 * gib else ram;

    var p: Plan = .{
        .profile = profile,
        .tier = null,
        .sha_ni = true,
        .metal = false,
        .gpu = false,
        .readahead = m.disk == .hdd,
        .cores = cores_avail,
        .pin = false,
        .reserve = 0,
        .exec_cache_mb = 0,
        .chunk_cache_mb = 0,
        .cp_cache_mb = 0,
    };

    // Cache budgets by profile (MiB). The defaults the node has today are exec 3072, chunk 1024,
    // cp 256; a profile only moves them with the RAM it can see.
    const ram_mb: u64 = ram_eff / mib;
    switch (profile) {
        .auto, .small => {
            p.exec_cache_mb = clampMb(ram_mb / 8, 512, 3072);
            p.chunk_cache_mb = clampMb(ram_mb / 16, 256, 1024);
            p.cp_cache_mb = clampMb(ram_mb / 64, 64, 256);
            p.reserve = if (cores_avail >= 8) 1 else 0;
        },
        .server, .validator => {
            p.exec_cache_mb = clampMb(ram_mb / 8, 1024, 32 * 1024);
            p.chunk_cache_mb = clampMb(ram_mb / 4, 1024, 96 * 1024);
            p.cp_cache_mb = clampMb(ram_mb / 64, 256, 4096);
            p.pin = true;
            p.reserve = if (profile == .validator) @max(2, cores_avail / 8) else @max(1, cores_avail / 16);
            // The large in-memory index: bigger runs mean fewer flushes and merges.
            if (ram_mb >= 128 * 1024) p.memtable_versions = 8 << 20;
            p.workers = std.math.clamp(cores_avail / 2, 4, 32);
            if (profile == .validator) {
                // Network and consensus threads live on the reserved cores (hw.pinToReserved).
                p.net_threads = @intCast(@min(p.reserve, 64));
                p.note("validator: reserve, net threads, interface and reserved-core pinning only; no consensus tuning yet", .{});
            }
        },
        .mac => {
            // Unified memory: the GPU and the CPU share it, so leave more to the system.
            p.exec_cache_mb = clampMb(ram_mb / 8, 512, 8 * 1024);
            p.chunk_cache_mb = clampMb(ram_mb / 8, 256, 8 * 1024);
            p.cp_cache_mb = clampMb(ram_mb / 64, 64, 512);
            p.metal = m.os == .macos;
        },
    }
    if (spec.exec_cache_mb) |v| p.exec_cache_mb = v;
    if (spec.chunk_cache_mb) |v| p.chunk_cache_mb = v;
    if (spec.cp_cache_mb) |v| p.cp_cache_mb = v;

    // Pinning needs sched_setaffinity (Linux only).
    if (spec.pin != .auto) p.pin = spec.pin == .on;
    if (p.pin and !is_linux) {
        p.pin = false;
        p.note("pin ignored: no thread affinity on this OS", .{});
    }
    if (spec.reserve) |r| p.reserve = r;
    if (p.reserve >= cores_avail) p.reserve = if (cores_avail > 1) cores_avail - 1 else 0;
    p.cores = if (p.pin) cores_avail - p.reserve else cores_avail;

    // Accelerators. Metal exists on macOS only; there is no GPU kernel yet,
    // so the flags only record the wish for the lane that adds one.
    if (spec.metal != .auto) p.metal = spec.metal == .on;
    if (p.metal and m.os != .macos) {
        p.metal = false;
        p.note("metal ignored: not macOS", .{});
    }
    if (spec.gpu != .auto) p.gpu = spec.gpu == .on;
    if (p.gpu and !m.gpu) {
        p.gpu = false;
        p.note("gpu=on ignored: no GPU found", .{});
    }
    // Batch dispatch (the GPU module reads these: gpu.fromPlan).
    // (gpu=on without a device is already noted above; batches then stay on the CPU)
    p.gpu_mode = if (spec.gpu == .off or (m.os == .macos and spec.metal == .off)) .off else if (spec.gpu == .on or (m.os == .macos and spec.metal == .on)) .on else .auto;
    p.dispatch = spec.dispatch;
    p.gpu_devices = spec.gpu_devices;
    p.pool_threads = spec.threads orelse p.cores;
    p.calibrate = spec.calibrate;
    if (p.gpu_mode == .off) if (p.dispatch) |d| if (d.isGpu()) {
        p.note("dispatch={f} ignored: gpu off", .{d});
        p.dispatch = null;
    };
    if (spec.net_iface_len > 0) {
        p.net_iface = spec.net_iface;
        p.net_iface_len = spec.net_iface_len;
        if (profile != .validator) p.note("net_iface set: only the networking lane reads it", .{});
    }

    // Dispatch tier: start from what detection chose, then apply caps and drops.
    var tier = m.tier;
    if (spec.cpu_cap) |c| {
        if (@intFromEnum(c) < @intFromEnum(tier)) tier = c;
    }
    if (spec.avx512 == .off and tier == .avx512) tier = .avx2;
    if (spec.avx2 == .off and @intFromEnum(tier) >= @intFromEnum(cpu.Tier.avx2)) tier = .baseline;
    // A tier the binary cannot switch to is refused, not planned: below the build's own target
    // the portable code is already compiled for that target; above it needs a linked object.
    if (tier != m.tier and !m.can_force[@intFromEnum(tier)]) {
        if (@intFromEnum(tier) < @intFromEnum(cpu.native_tier))
            p.note("cpu={s} ignored: binary built for {s} (rebuild with -Dtarget=x86_64-linux-gnu)", .{ tierName(tier), tierName(cpu.native_tier) })
        else
            p.note("cpu={s} ignored: no {s} kernel object linked", .{ tierName(tier), tierName(tier) });
        tier = m.tier;
    }
    if (spec.avx512 == .on and @intFromEnum(m.tier_supported) < @intFromEnum(cpu.Tier.avx512))
        p.note("avx512=on ignored: CPU is {s}", .{tierName(m.tier_supported)});
    if (spec.avx2 == .on and @intFromEnum(m.tier_supported) < @intFromEnum(cpu.Tier.avx2))
        p.note("avx2=on ignored: CPU is {s}", .{tierName(m.tier_supported)});
    if (tier != m.tier) p.tier = tier;

    // Arm paths. Each exists only where the CPU has the instructions.
    p.arm_sha2 = armSwitch(&p, "arm_sha2", spec.arm_sha2, m.features.arm_sha2, true);
    p.arm_sha512 = armSwitch(&p, "arm_sha512", spec.arm_sha512, m.features.arm_sha512, true);
    p.arm_sha3 = armSwitch(&p, "arm_sha3", spec.arm_sha3, m.features.arm_sha3, false);
    p.dit = armSwitch(&p, "dit", spec.dit, m.features.arm_dit, true);

    p.sha_ni = switch (spec.sha_ni) {
        .off => false,
        .on => blk: {
            if (!m.features.sha_ni) p.note("sha_ni=on ignored: CPU has no SHA-NI", .{});
            break :blk m.features.sha_ni;
        },
        .auto => true,
    };
    return p;
}

fn armSwitch(p: *Plan, comptime key: []const u8, t: Tri, have: bool, default: bool) bool {
    return switch (t) {
        .auto => default,
        .off => false,
        .on => blk: {
            if (!have) p.note(key ++ "=on ignored: CPU has no such feature", .{});
            break :blk have;
        },
    };
}

fn clampMb(v: u64, lo: u64, hi: u64) u32 {
    return @intCast(@min(hi, @max(lo, v)));
}

// ---------------------------------------------------------------------------------------------
// Apply

pub const ApplyResult = struct {
    /// Tier now in force.
    tier: cpu.Tier,
    /// The plan asked for a tier core/cpu.zig refused (see the plan's notes for why).
    tier_refused: bool = false,
    pinned: bool,
    /// Cores in the mask (0 when not pinned).
    pinned_cores: u32 = 0,
};

/// Pushes the plan into core/cpu.zig and pins the process. Call once at startup before spawning
/// threads (children inherit the mask). A tier the binary cannot run stays at the detected one.
pub fn apply(m: *const Machine, p: *const Plan) ApplyResult {
    cpu.setShaNi(p.sha_ni);
    cpu.setArmSha2(p.arm_sha2);
    cpu.setArmSha512(p.arm_sha512);
    cpu.setArmSha3(p.arm_sha3);
    cpu.setDit(p.dit);
    var refused = false;
    if (p.tier) |t| refused = !cpu.forceTier(t);
    var r: ApplyResult = .{ .tier = cpu.tier(), .tier_refused = refused, .pinned = false };
    if (p.pin) {
        if (pinProcess(p.cores, m)) |n| {
            r.pinned = true;
            r.pinned_cores = n;
        }
    }
    return r;
}

const Mask = if (is_linux) std.os.linux.cpu_set_t else [16]usize;

/// CPUs left out of the process mask by `pinProcess` (whole physical cores). Network and
/// consensus threads call `pinToReserved` so they run there and nowhere else.
var reserved_mask: Mask = @splat(0);
var reserved_count: u32 = 0;

const CpuEnt = struct { pkg: u32, core: u32, cpu: u32 };

fn entLess(_: void, a: CpuEnt, b: CpuEnt) bool {
    if (a.pkg != b.pkg) return a.pkg < b.pkg;
    if (a.core != b.core) return a.core < b.core;
    return a.cpu < b.cpu;
}

fn topoId(cpu_i: usize, comptime leaf: []const u8) ?u32 {
    var pb: [96]u8 = undefined;
    var vb: [16]u8 = undefined;
    const path = std.fmt.bufPrint(&pb, "/sys/devices/system/cpu/cpu{d}/topology/" ++ leaf, .{cpu_i}) catch return null;
    const v = readSmall(path, &vb) orelse return null;
    return std.fmt.parseInt(u32, std.mem.trim(u8, v, " \n"), 10) catch null;
}

/// Restrict the calling thread (and threads it spawns later) to about `count` CPUs of its current
/// affinity mask, taking whole physical cores (both SMT siblings) in package/core order, so the
/// CPUs left for the OS and for `pinToReserved` are whole cores too and one NUMA node fills first.
/// Without topology files it takes the first `count` CPUs in mask order.
pub fn pinProcess(count: u32, m: *const Machine) ?u32 {
    _ = m;
    if (comptime !is_linux) return null;
    var cur: std.os.linux.cpu_set_t = @splat(0);
    if (std.os.linux.sched_getaffinity(0, @sizeOf(std.os.linux.cpu_set_t), &cur) != 0) return null;
    const bits = @bitSizeOf(usize);
    const max_cpus = 1024;
    var ents: [max_cpus]CpuEnt = undefined;
    var n: usize = 0;
    var topo = true;
    var cpu_i: usize = 0;
    while (cpu_i < @min(cur.len * bits, max_cpus)) : (cpu_i += 1) {
        if ((cur[cpu_i / bits] >> @intCast(cpu_i % bits)) & 1 == 0) continue;
        const core = topoId(cpu_i, "core_id");
        const pkg = topoId(cpu_i, "physical_package_id");
        if (core == null or pkg == null) topo = false;
        ents[n] = .{ .pkg = pkg orelse 0, .core = core orelse 0, .cpu = @intCast(cpu_i) };
        n += 1;
    }
    if (n == 0 or count == 0) return null;
    if (!topo) for (ents[0..n]) |*e| {
        e.pkg = 0;
        e.core = e.cpu; // no topology: every CPU its own core, mask order
    };
    std.mem.sort(CpuEnt, ents[0..n], {}, entLess);
    var out: std.os.linux.cpu_set_t = @splat(0);
    var rest: std.os.linux.cpu_set_t = @splat(0);
    var taken: u32 = 0;
    var left: u32 = 0;
    var k: usize = 0;
    while (k < n) {
        var e = k + 1;
        while (e < n and ents[e].pkg == ents[k].pkg and ents[e].core == ents[k].core) e += 1;
        const width: u32 = @intCast(e - k);
        const take = taken < count and (taken + width <= count or taken == 0);
        for (ents[k..e]) |c| {
            const set = if (take) &out else &rest;
            set[c.cpu / bits] |= @as(usize, 1) << @intCast(c.cpu % bits);
        }
        if (take) taken += width else left += width;
        k = e;
    }
    if (taken == 0) return null;
    std.os.linux.sched_setaffinity(0, &out) catch return null;
    reserved_mask = rest;
    reserved_count = left;
    return taken;
}

/// Pin the calling thread to the CPUs `pinProcess` left out (network and consensus threads).
/// False when nothing was reserved or the OS refuses; the thread keeps its current mask then.
pub fn pinToReserved() bool {
    if (comptime !is_linux) return false;
    if (reserved_count == 0) return false;
    std.os.linux.sched_setaffinity(0, &reserved_mask) catch return false;
    return true;
}

// ---------------------------------------------------------------------------------------------
// Reporting

/// Writes the machine, the plan and the kernel per primitive as `key value` lines.
pub fn writeReport(w: *std.Io.Writer, m: *const Machine, p: *const Plan) std.Io.Writer.Error!void {
    try w.print("cpu {s}\n", .{if (m.brand_len > 0) m.brandName() else @tagName(m.arch)});
    try w.print("arch {s} os {s}\n", .{ @tagName(m.arch), @tagName(m.os) });
    try w.writeAll("features ");
    try m.features.write(w);
    try w.writeByte('\n');
    try w.print("tier {s} supported {s} build {s}\n", .{ @tagName(m.tier), @tagName(m.tier_supported), @tagName(cpu.native_tier) });
    try w.print("cores logical {d} physical {d}\n", .{ m.logical_cores, m.physical_cores });
    try w.print("ram {d} MiB\n", .{m.ram_bytes / mib});
    try w.print("disk {s} gpu {s}\n", .{ @tagName(m.disk), if (m.gpu) "yes" else "no" });
    try w.print("profile {s}\n", .{@tagName(p.profile)});
    try w.print("plan tier {s} sha_ni {s} metal {s} gpu {s} pin {s} cores {d} reserve {d}\n", .{
        if (p.tier) |t| @tagName(t) else "keep",
        onOff(p.sha_ni),
        onOff(p.metal),
        onOff(p.gpu),
        onOff(p.pin),
        p.cores,
        p.reserve,
    });
    if (is_arm) try w.print("plan arm sha2 {s} sha512 {s} sha3 {s} dit {s}\n", .{ onOff(p.arm_sha2), onOff(p.arm_sha512), onOff(p.arm_sha3), onOff(p.dit) });
    try w.print("plan caches exec {d} MiB chunk {d} MiB cp {d} MiB\n", .{ p.exec_cache_mb, p.chunk_cache_mb, p.cp_cache_mb });
    if (p.memtable_versions) |v| try w.print("plan memtable_versions {d}\n", .{v});
    if (p.workers) |v| try w.print("plan workers {d}\n", .{v});
    if (p.net_threads) |v| try w.print("plan net_threads {d}\n", .{v});
    if (p.net_iface_len > 0) try w.print("plan net_iface {s}\n", .{p.netIface()});
    if (p.readahead) try w.writeAll("plan readahead on\n");
    try w.print("plan batch gpu {s} pool_threads {d} calibrate {s}", .{ @tagName(p.gpu_mode), p.pool_threads, @tagName(p.calibrate) });
    if (p.dispatch) |d| try w.print(" dispatch {f}", .{d});
    if (p.gpu_devices) |n| try w.print(" gpu_devices {d}", .{n});
    try w.writeByte('\n');
    for (0..p.note_count) |i| try w.print("note {s}\n", .{p.noteAt(i)});
    const eff_tier = p.tier orelse m.tier;
    const sel: cpu.Sel = .{ .sha_ni = m.features.sha_ni and p.sha_ni, .arm_sha2 = p.arm_sha2, .arm_sha512 = p.arm_sha512, .arm_sha3 = p.arm_sha3 };
    for (std.enums.values(cpu.Prim)) |pr| try w.print("kernel {s} {s}\n", .{ @tagName(pr), cpu.kernelNameFor(pr, eff_tier, sel) });
}

fn onOff(b: bool) []const u8 {
    return if (b) "on" else "off";
}

/// One log line for the node's startup.
pub fn logPlan(m: *const Machine, p: *const Plan, applied: ?ApplyResult) void {
    std.log.info("hw: profile {s} cores {d}/{d} ram {d} MiB disk {s}; caches exec {d} chunk {d} cp {d} MiB; pin {s}{s}", .{
        @tagName(p.profile),
        p.cores,
        m.logical_cores,
        m.ram_bytes / mib,
        @tagName(m.disk),
        p.exec_cache_mb,
        p.chunk_cache_mb,
        p.cp_cache_mb,
        onOff(p.pin),
        if (applied) |a| (if (a.pinned) " (pinned)" else "") else " (plan only)",
    });
    for (0..p.note_count) |i| std.log.warn("hw: {s}", .{p.noteAt(i)});
    if (applied) |a| {
        std.log.info("hw: dispatch tier {s}", .{@tagName(a.tier)});
        if (a.tier_refused) std.log.warn("hw: requested tier {s} refused by the dispatcher; running {s}", .{ if (p.tier) |t| @tagName(t) else "none", @tagName(a.tier) });
        if (p.pin and !a.pinned) std.log.warn("hw: pin requested but the affinity call failed", .{});
    }
    if (p.memtable_versions != null or p.workers != null or p.net_threads != null)
        std.log.info("hw: workers {?d} memtable_versions {?d} net_threads {?d}", .{ p.workers, p.memtable_versions, p.net_threads });
}

// ---------------------------------------------------------------------------------------------
// Tests

test "countCpuList" {
    try std.testing.expectEqual(@as(u32, 2), countCpuList("0,24"));
    try std.testing.expectEqual(@as(u32, 4), countCpuList("0-1,8-9"));
    try std.testing.expectEqual(@as(u32, 1), countCpuList("3"));
    try std.testing.expectEqual(@as(u32, 0), countCpuList("a-b"));
    try std.testing.expectEqual(@as(u32, 0), countCpuList("5-2"));
}

test "parseMemTotal" {
    try std.testing.expectEqual(@as(u64, 16384 * 1024), parseMemTotal("MemTotal:       16384 kB\nMemFree: 1 kB\n"));
    try std.testing.expectEqual(@as(u64, 0), parseMemTotal("nothing\n"));
}

test "cgroup parsers" {
    try std.testing.expectEqual(@as(?u32, 2), parseCpuMax("200000 100000\n"));
    try std.testing.expectEqual(@as(?u32, 2), parseCpuMax("150000 100000"));
    try std.testing.expectEqual(@as(?u32, null), parseCpuMax("max 100000"));
    try std.testing.expectEqual(@as(?u32, null), parseCpuMax("0 100000"));
    try std.testing.expectEqual(@as(?u32, null), parseCpuMax("junk"));
    try std.testing.expectEqual(@as(?u64, 4 << 30), parseCgroupMem("4294967296\n"));
    try std.testing.expectEqual(@as(?u64, null), parseCgroupMem("max\n"));
    try std.testing.expectEqual(@as(?u64, null), parseCgroupMem("9223372036854771712\n"));
    try std.testing.expectEqualStrings("/user.slice/u.service/app.slice/zui-run-x.scope", cgroupV2Path("12:pids:/x\n0::/user.slice/u.service/app.slice/zui-run-x.scope\n").?);
    try std.testing.expectEqualStrings("/", cgroupV2Path("0::/\n").?);
    try std.testing.expectEqual(@as(?[]const u8, null), cgroupV2Path("4:memory:/docker/abc\n"));
    var w: CgroupWalk = .{ .dir = "/sys/fs/cgroup/zui.slice/zui-rh-main.service" };
    try std.testing.expectEqualStrings("/sys/fs/cgroup/zui.slice/zui-rh-main.service", w.next().?);
    try std.testing.expectEqualStrings("/sys/fs/cgroup/zui.slice", w.next().?);
    try std.testing.expectEqualStrings("/sys/fs/cgroup", w.next().?);
    try std.testing.expectEqual(@as(?[]const u8, null), w.next());
    var r: CgroupWalk = .{ .dir = "/sys/fs/cgroup" };
    try std.testing.expectEqualStrings("/sys/fs/cgroup", r.next().?);
    try std.testing.expectEqual(@as(?[]const u8, null), r.next());
}

test "unforceable tier is refused with a note, not planned" {
    var m = testMachine(.linux, 8, 16);
    m.can_force = .{ false, true, true };
    var s: Spec = .{};
    try parse(&s, "cpu=baseline", null);
    const p = plan(&m, &s);
    try std.testing.expectEqual(@as(?cpu.Tier, null), p.tier);
    try std.testing.expectEqual(@as(u8, 1), p.note_count);
    try std.testing.expect(std.mem.indexOf(u8, p.noteAt(0), "ignored") != null);
}

test "batch dispatch keys" {
    var s: Spec = .{};
    try parse(&s, "dispatch=gpu2,gpu_devices=1,threads=4,calibrate=force", null);
    try std.testing.expectEqual(@as(usize, 2), s.dispatch.?.gpuDevices());
    try std.testing.expectEqual(@as(?u32, 1), s.gpu_devices);
    try std.testing.expectEqual(@as(?u32, 4), s.threads);
    try std.testing.expectEqual(Calibrate.force, s.calibrate);
    try parse(&s, "dispatch=auto", null);
    try std.testing.expect(s.dispatch == null);
    try parse(&s, "dispatch=mix", null);
    try std.testing.expect(s.dispatch.?.isMix() and s.dispatch_all_devices);
    try std.testing.expectError(error.BadValue, parse(&s, "dispatch=gpu0", null));
    try std.testing.expectError(error.BadValue, parse(&s, "threads=0", null));
    var m = detect(null);
    m.gpu = true;
    var t: Spec = .{};
    try parse(&t, "gpu=off,dispatch=gpu1", null);
    const p = plan(&m, &t);
    try std.testing.expectEqual(Tri.off, p.gpu_mode);
    try std.testing.expect(p.dispatch == null); // gpu off wins, with a note
    var u: Spec = .{};
    try parse(&u, "threads=3", null);
    try std.testing.expectEqual(@as(u32, 3), plan(&m, &u).pool_threads);
}

test "arm switches, validator note, gpu clamp" {
    var m = testMachine(.linux, 32, 64);
    var s: Spec = .{};
    try parse(&s, "profile=validator,arm_sha2=off,arm_sha3=on,dit=on,gpu=on,net_iface=dz0", null);
    const p = plan(&m, &s);
    try std.testing.expect(!p.arm_sha2);
    try std.testing.expect(!p.arm_sha3); // CPU has none
    try std.testing.expect(p.net_threads != null);
    try std.testing.expectEqualStrings("dz0", p.netIface());
    try std.testing.expect(!p.gpu); // none found
    try std.testing.expect(p.note_count >= 3);
    m.gpu = true;
    try std.testing.expect(plan(&m, &s).gpu);
}

test "spec parse layers and rejects" {
    var s: Spec = .{};
    try parse(&s, "profile=server,sha_ni=off,cores=8,chunk_cache_mb=4096", null);
    try parse(&s, "cpu=avx2 pin=on", null);
    try std.testing.expectEqual(Profile.server, s.profile);
    try std.testing.expectEqual(Tri.off, s.sha_ni);
    try std.testing.expectEqual(@as(?u32, 8), s.cores);
    try std.testing.expectEqual(@as(?cpu.Tier, .avx2), s.cpu_cap);
    try std.testing.expectEqual(Tri.on, s.pin);
    var f: ParseFail = .{};
    try std.testing.expectError(error.UnknownKey, parse(&s, "nope=1", &f));
    try std.testing.expectEqualStrings("nope", f.key[0..f.key_len]);
    try std.testing.expectError(error.BadValue, parse(&s, "cores=0", null));
    try std.testing.expectError(error.BadValue, parse(&s, "sha_ni=maybe", null));
    try std.testing.expectError(error.MissingValue, parse(&s, "pin", null));
}

fn testMachine(os: std.Target.Os.Tag, cores: u32, ram_gb: u64) Machine {
    return .{
        .arch = builtin.cpu.arch,
        .os = os,
        .features = .{ .sha_ni = true },
        .tier = .avx512,
        .tier_supported = .avx512,
        .logical_cores = cores,
        .physical_cores = cores / 2,
        .ram_bytes = ram_gb * gib,
        .disk = .nvme,
    };
}

test "auto profile picks by machine" {
    const small = testMachine(.linux, 8, 16);
    const big = testMachine(.linux, 64, 256);
    const mac = testMachine(.macos, 12, 32);
    try std.testing.expectEqual(Profile.small, autoProfile(&small));
    try std.testing.expectEqual(Profile.server, autoProfile(&big));
    try std.testing.expectEqual(Profile.mac, autoProfile(&mac));
}

test "server plan pins and sizes caches from RAM" {
    const big = testMachine(.linux, 64, 256);
    var s: Spec = .{};
    const p = plan(&big, &s);
    try std.testing.expectEqual(Profile.server, p.profile);
    try std.testing.expect(p.pin == is_linux);
    try std.testing.expectEqual(@as(u32, 64 * 1024), p.chunk_cache_mb); // 256 GiB / 4
    try std.testing.expectEqual(@as(u32, 32 * 1024), p.exec_cache_mb); // 256 GiB / 8, at the cap
    if (is_linux) try std.testing.expectEqual(@as(u32, 60), p.cores);
}

test "small plan keeps today's caps and never pins" {
    const m = testMachine(.linux, 8, 64);
    var s: Spec = .{};
    const p = plan(&m, &s);
    try std.testing.expectEqual(Profile.small, p.profile);
    try std.testing.expect(!p.pin);
    try std.testing.expectEqual(@as(u32, 3072), p.exec_cache_mb);
    try std.testing.expectEqual(@as(u32, 1024), p.chunk_cache_mb);
    try std.testing.expectEqual(@as(u32, 256), p.cp_cache_mb);
}

test "overrides force paths off and are clamped to what exists" {
    var m = testMachine(.linux, 8, 16);
    var s: Spec = .{};
    try parse(&s, "avx512=off,sha_ni=off,metal=on,cpu=baseline", null);
    var p = plan(&m, &s);
    try std.testing.expectEqual(@as(?cpu.Tier, .baseline), p.tier);
    try std.testing.expect(!p.sha_ni);
    try std.testing.expect(!p.metal); // not macOS
    try std.testing.expectEqual(@as(u8, 1), p.note_count);

    m.tier = .avx2;
    m.tier_supported = .avx2;
    m.features.sha_ni = false;
    s = .{};
    try parse(&s, "avx512=on,sha_ni=on", null);
    p = plan(&m, &s);
    try std.testing.expectEqual(@as(?cpu.Tier, null), p.tier);
    try std.testing.expectEqual(@as(u8, 2), p.note_count);
}

test "avx2=off drops to baseline, explicit caches win" {
    const m = testMachine(.linux, 8, 16);
    var s: Spec = .{};
    try parse(&s, "avx2=off,exec_cache_mb=100", null);
    const p = plan(&m, &s);
    try std.testing.expectEqual(@as(?cpu.Tier, .baseline), p.tier);
    try std.testing.expectEqual(@as(u32, 100), p.exec_cache_mb);
}

test "detect returns a coherent machine" {
    const m = detect(".");
    try std.testing.expect(m.logical_cores >= 1);
    try std.testing.expect(@intFromEnum(m.tier) <= @intFromEnum(m.tier_supported));
    var s: Spec = .{};
    const p = plan(&m, &s);
    try std.testing.expect(p.exec_cache_mb >= 512);
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeReport(&w, &m, &p);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "kernel sha256") != null);
}
