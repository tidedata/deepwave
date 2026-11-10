//! NVIDIA through the CUDA driver API and NVRTC, both dlopen'ed at runtime (no CUDA toolkit needed
//! at build time, no link flags): the kernel source (kernels.zig) is compiled by NVRTC to PTX, which
//! the driver JIT-compiles for whatever GPU is present. Buffers are managed (unified) memory, so
//! host and device share one pointer.
const std = @import("std");
const builtin = @import("builtin");
const kernels = @import("kernels.zig");
const backend = @import("backend.zig");

pub const available = builtin.os.tag == .linux;

const CUresult = c_int;
const NvrtcResult = c_int;
const CUdevice = c_int;
const Ptr = ?*anyopaque;

const Api = struct {
    cuInit: *const fn (c_uint) callconv(.c) CUresult,
    cuDeviceGet: *const fn (*CUdevice, c_int) callconv(.c) CUresult,
    cuDeviceGetName: *const fn ([*]u8, c_int, CUdevice) callconv(.c) CUresult,
    cuDeviceGetAttribute: *const fn (*c_int, c_int, CUdevice) callconv(.c) CUresult,
    cuDevicePrimaryCtxRetain: *const fn (*Ptr, CUdevice) callconv(.c) CUresult,
    cuDevicePrimaryCtxRelease: *const fn (CUdevice) callconv(.c) CUresult,
    cuCtxSetCurrent: *const fn (Ptr) callconv(.c) CUresult,
    cuCtxSynchronize: *const fn () callconv(.c) CUresult,
    cuModuleLoadData: *const fn (*Ptr, [*]const u8) callconv(.c) CUresult,
    cuModuleUnload: *const fn (Ptr) callconv(.c) CUresult,
    cuModuleGetFunction: *const fn (*Ptr, Ptr, [*:0]const u8) callconv(.c) CUresult,
    cuMemAllocManaged: *const fn (*u64, usize, c_uint) callconv(.c) CUresult,
    cuMemFree: *const fn (u64) callconv(.c) CUresult,
    cuLaunchKernel: *const fn (Ptr, c_uint, c_uint, c_uint, c_uint, c_uint, c_uint, c_uint, Ptr, [*]?*anyopaque, ?*?*anyopaque) callconv(.c) CUresult,
    cuDeviceGetCount: *const fn (*c_int) callconv(.c) CUresult,
    cuDeviceGetPCIBusId: *const fn ([*]u8, c_int, CUdevice) callconv(.c) CUresult,
    cuStreamCreate: *const fn (*Ptr, c_uint) callconv(.c) CUresult,
    cuStreamDestroy: *const fn (Ptr) callconv(.c) CUresult,
    cuStreamSynchronize: *const fn (Ptr) callconv(.c) CUresult,
    cuStreamQuery: *const fn (Ptr) callconv(.c) CUresult,
    cuMemAlloc: *const fn (*u64, usize) callconv(.c) CUresult,
    cuMemHostAlloc: *const fn (*?*anyopaque, usize, c_uint) callconv(.c) CUresult,
    cuMemFreeHost: *const fn (?*anyopaque) callconv(.c) CUresult,
    cuMemHostGetDevicePointer: *const fn (*u64, ?*anyopaque, c_uint) callconv(.c) CUresult,
    cuMemcpyHtoD: *const fn (u64, *const anyopaque, usize) callconv(.c) CUresult,
    cuMemcpyDtoH: *const fn (*anyopaque, u64, usize) callconv(.c) CUresult,
    nvrtcCreateProgram: *const fn (*Ptr, [*:0]const u8, [*:0]const u8, c_int, ?[*]const [*:0]const u8, ?[*]const [*:0]const u8) callconv(.c) NvrtcResult,
    nvrtcCompileProgram: *const fn (Ptr, c_int, [*]const [*:0]const u8) callconv(.c) NvrtcResult,
    nvrtcGetProgramLogSize: *const fn (Ptr, *usize) callconv(.c) NvrtcResult,
    nvrtcGetProgramLog: *const fn (Ptr, [*]u8) callconv(.c) NvrtcResult,
    nvrtcGetPTXSize: *const fn (Ptr, *usize) callconv(.c) NvrtcResult,
    nvrtcGetPTX: *const fn (Ptr, [*]u8) callconv(.c) NvrtcResult,
    nvrtcDestroyProgram: *const fn (*Ptr) callconv(.c) NvrtcResult,
};

pub const max_slots = 2;

pub const Cuda = struct {
    api: Api,
    cu_lib: std.DynLib,
    rtc_lib: std.DynLib,
    ctx: Ptr,
    dev: CUdevice,
    ordinal: u32,
    module: Ptr,
    funcs: [kernels.kernel_count]Ptr,
    /// One stream per pipeline slot (slot 0 also serves synchronous launches).
    streams: [max_slots]Ptr,
    name_buf: [128]u8,
    name_len: usize,
    pci_buf: [32]u8,
    pci_len: usize,

    /// Number of CUDA devices the driver reports (0 when libcuda or NVRTC is missing).
    pub fn deviceCount() usize {
        if (!available) return 0;
        var cu = std.DynLib.open("libcuda.so.1") catch return 0;
        _ = &cu; // stays loaded (see init)
        const cuInit = cu.lookup(*const fn (c_uint) callconv(.c) CUresult, "cuInit") orelse return 0;
        const cuCount = cu.lookup(*const fn (*c_int) callconv(.c) CUresult, "cuDeviceGetCount") orelse return 0;
        if (cuInit(0) != 0) return 0;
        var n: c_int = 0;
        if (cuCount(&n) != 0 or n < 0) return 0;
        var rtc = openRtc() orelse return 0;
        rtc.close();
        return @intCast(n);
    }

    pub fn init() backend.Error!Cuda {
        return initDevice(0);
    }

    pub fn initDevice(ordinal: u32) backend.Error!Cuda {
        if (!available) return error.Unsupported;
        // libcuda stays loaded for the life of the process (its driver threads outlive any context).
        var cu = std.DynLib.open("libcuda.so.1") catch return error.NoDevice;
        var rtc = openRtc() orelse return error.NoDevice;
        errdefer rtc.close();
        var api: Api = undefined;
        inline for (@typeInfo(Api).@"struct".field_names, @typeInfo(Api).@"struct".field_types) |fname, ftype| {
            const lib = if (comptime std.mem.startsWith(u8, fname, "nvrtc")) &rtc else &cu;
            // The driver header maps these to _v2 entry points (the plain names are legacy 32-bit
            // ABIs). Other _v2 names must not be preferred: CUDA 13 gives cuCtxSynchronize_v2 a
            // context argument.
            const versioned = comptime for ([_][]const u8{ "cuMemFree", "cuDevicePrimaryCtxRelease", "cuStreamDestroy", "cuMemAlloc", "cuMemHostGetDevicePointer", "cuMemcpyHtoD", "cuMemcpyDtoH" }) |v| {
                if (std.mem.eql(u8, fname, v)) break true;
            } else false;
            const v2 = std.fmt.comptimePrint("{s}_v2", .{fname});
            @field(api, fname) = (if (versioned) lib.lookup(ftype, v2) else null) orelse lib.lookup(ftype, fname) orelse return error.NoDevice;
        }
        if (api.cuInit(0) != 0) return error.NoDevice;
        var dev: CUdevice = 0;
        if (api.cuDeviceGet(&dev, @intCast(ordinal)) != 0) return error.NoDevice;
        var ctx: Ptr = null;
        if (api.cuDevicePrimaryCtxRetain(&ctx, dev) != 0) return error.NoDevice;
        errdefer _ = api.cuDevicePrimaryCtxRelease(dev);
        if (api.cuCtxSetCurrent(ctx) != 0) return error.NoDevice;
        var major: c_int = 0;
        var minor: c_int = 0;
        _ = api.cuDeviceGetAttribute(&major, 75, dev); // COMPUTE_CAPABILITY_MAJOR
        _ = api.cuDeviceGetAttribute(&minor, 76, dev);

        var self: Cuda = .{ .api = api, .cu_lib = cu, .rtc_lib = rtc, .ctx = ctx, .dev = dev, .ordinal = ordinal, .module = null, .funcs = @splat(null), .streams = @splat(null), .name_buf = undefined, .name_len = 0, .pci_buf = @splat(0), .pci_len = 0 };
        _ = api.cuDeviceGetName(&self.name_buf, @intCast(self.name_buf.len), dev);
        self.name_len = std.mem.sliceTo(&self.name_buf, 0).len;
        _ = api.cuDeviceGetPCIBusId(&self.pci_buf, @intCast(self.pci_buf.len), dev);
        self.pci_len = std.mem.sliceTo(&self.pci_buf, 0).len;

        const ptx = try compilePtx(&api, major, minor);
        if (api.cuModuleLoadData(&self.module, ptx.ptr) != 0) return error.CompileFailed;
        errdefer _ = api.cuModuleUnload(self.module);
        inline for (0..kernels.kernel_count) |i| {
            const k: kernels.Kernel = @enumFromInt(i);
            if (api.cuModuleGetFunction(&self.funcs[i], self.module, k.entry().ptr) != 0) return error.CompileFailed;
        }
        errdefer for (self.streams) |st| if (st != null) {
            _ = api.cuStreamDestroy(st);
        };
        for (&self.streams) |*st| if (api.cuStreamCreate(st, 1) != 0) return error.NoDevice; // CU_STREAM_NON_BLOCKING
        return self;
    }

    pub fn getName(c: *const Cuda) []const u8 {
        return c.name_buf[0..c.name_len];
    }

    pub fn pciId(c: *const Cuda) []const u8 {
        return c.pci_buf[0..c.pci_len];
    }

    pub fn deinit(c: *Cuda) void {
        c.enter() catch {};
        for (c.streams) |st| if (st != null) {
            _ = c.api.cuStreamDestroy(st);
        };
        _ = c.api.cuModuleUnload(c.module);
        _ = c.api.cuDevicePrimaryCtxRelease(c.dev);
        c.rtc_lib.close();
    }

    /// Makes the context current on the calling thread (a CUDA context is per-thread state).
    fn enter(c: *Cuda) backend.Error!void {
        if (c.api.cuCtxSetCurrent(c.ctx) != 0) return error.LaunchFailed;
    }

    /// Pinned, mapped host memory: the CPU writes inputs and reads results in place, kernels read
    /// and write it over the bus (zero copy). For streamed per-item data.
    pub fn alloc(c: *Cuda, len: usize) backend.Error!backend.Buffer {
        try c.enter();
        const n = @max(len, 16);
        var p: ?*anyopaque = null;
        if (c.api.cuMemHostAlloc(&p, n, 0x01 | 0x02) != 0) return error.OutOfMemory; // PORTABLE | DEVICEMAP
        var d: u64 = 0;
        if (c.api.cuMemHostGetDevicePointer(&d, p, 0) != 0) {
            _ = c.api.cuMemFreeHost(p);
            return error.OutOfMemory;
        }
        return .{ .ptr = @ptrCast(p.?), .len = n, .handle = p, .dev = d, .kind = .host };
    }

    /// Device memory (tables, intermediates); fill with `upload`.
    pub fn allocDevice(c: *Cuda, len: usize) backend.Error!backend.Buffer {
        try c.enter();
        const n = @max(len, 16);
        var d: u64 = 0;
        if (c.api.cuMemAlloc(&d, n) != 0) return error.OutOfMemory;
        return .{ .ptr = undefined, .len = n, .handle = null, .dev = d, .kind = .device };
    }

    pub fn upload(c: *Cuda, b: backend.Buffer, off: usize, bytes: []const u8) backend.Error!void {
        if (b.kind == .host) return @memcpy(b.ptr[off..][0..bytes.len], bytes);
        try c.enter();
        if (c.api.cuMemcpyHtoD(b.dev + off, bytes.ptr, bytes.len) != 0) return error.LaunchFailed;
    }

    pub fn download(c: *Cuda, b: backend.Buffer, off: usize, out: []u8) backend.Error!void {
        if (b.kind == .host) return @memcpy(out, b.ptr[off..][0..out.len]);
        try c.enter();
        if (c.api.cuMemcpyDtoH(out.ptr, b.dev + off, out.len) != 0) return error.LaunchFailed;
    }

    pub fn free(c: *Cuda, b: backend.Buffer) void {
        c.enter() catch return;
        switch (b.kind) {
            .host => _ = c.api.cuMemFreeHost(b.handle),
            .device => _ = c.api.cuMemFree(b.dev),
        }
    }

    /// Queues `k` over `n` threads on the slot's stream (returns at once; `wait` collects it).
    pub fn submit(c: *Cuda, slot: usize, k: kernels.Kernel, bufs: []const backend.Buffer, n: usize) backend.Error!void {
        if (n == 0) return;
        try c.enter();
        var dptrs: [8]u64 = undefined;
        var args: [8]?*anyopaque = undefined;
        if (bufs.len > dptrs.len) return error.LaunchFailed;
        for (bufs, 0..) |b, i| {
            dptrs[i] = b.dev + b.off;
            args[i] = &dptrs[i];
        }
        const block: usize = k.blockSize();
        const grid = (n + block - 1) / block;
        const lr = c.api.cuLaunchKernel(c.funcs[@intFromEnum(k)], @intCast(grid), 1, 1, @intCast(block), 1, 1, 0, c.streams[slot], &args, null);
        if (lr != 0) {
            std.debug.print("cuda: cuLaunchKernel({s}) failed with CUresult {d}\n", .{ k.entry(), lr });
            return error.LaunchFailed;
        }
    }

    /// Waits for everything queued on the slot's stream.
    pub fn wait(c: *Cuda, slot: usize) backend.Error!void {
        try c.enter();
        const sr = c.api.cuStreamSynchronize(c.streams[slot]);
        if (sr != 0) {
            std.debug.print("cuda: stream {d} on device {d} failed with CUresult {d}\n", .{ slot, c.ordinal, sr });
            return error.LaunchFailed;
        }
    }

    /// True when the slot's stream has finished (or failed: `wait` reports the error).
    pub fn done(c: *Cuda, slot: usize) bool {
        c.enter() catch return true;
        return c.api.cuStreamQuery(c.streams[slot]) != 600; // CUDA_ERROR_NOT_READY
    }

    pub fn launch(c: *Cuda, k: kernels.Kernel, bufs: []const backend.Buffer, n: usize) backend.Error!void {
        if (n == 0) return;
        try c.submit(0, k, bufs, n);
        try c.wait(0);
    }
};

/// PTX for one compute capability, compiled by NVRTC once per process and architecture.
var ptx_lock: std.atomic.Value(bool) = .init(false);
var ptx_cache: [4]struct { arch: c_int = -1, ptx: [:0]const u8 = "" } = @splat(.{});

fn compilePtx(api: *const Api, major: c_int, minor: c_int) backend.Error![:0]const u8 {
    while (ptx_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.Thread.yield() catch {};
    defer ptx_lock.store(false, .release);
    const arch = major * 10 + minor;
    for (ptx_cache) |e| if (e.arch == arch) return e.ptx;
    var prog: Ptr = null;
    if (api.nvrtcCreateProgram(&prog, kernels.cuda_source.ptr, "zui_gpu.cu", 0, null, null) != 0) return error.CompileFailed;
    defer _ = api.nvrtcDestroyProgram(&prog);
    var arch_buf: [48]u8 = @splat(0);
    _ = std.fmt.bufPrint(arch_buf[0..40], "--gpu-architecture=compute_{d}{d}", .{ major, minor }) catch unreachable;
    const arch_opt: [*:0]const u8 = @ptrCast(&arch_buf);
    const opts = [_][*:0]const u8{ arch_opt, "--std=c++14" };
    if (api.nvrtcCompileProgram(prog, opts.len, &opts) != 0) {
        var n: usize = 0;
        _ = api.nvrtcGetProgramLogSize(prog, &n);
        if (n > 1 and n < (1 << 20)) {
            const log = std.heap.page_allocator.alloc(u8, n) catch return error.CompileFailed;
            defer std.heap.page_allocator.free(log);
            _ = api.nvrtcGetProgramLog(prog, log.ptr);
            std.debug.print("nvrtc: {s}\n", .{log[0 .. n - 1]});
        }
        return error.CompileFailed;
    }
    var ptx_len: usize = 0;
    if (api.nvrtcGetPTXSize(prog, &ptx_len) != 0) return error.CompileFailed;
    const ptx = std.heap.page_allocator.allocSentinel(u8, ptx_len, 0) catch return error.OutOfMemory;
    if (api.nvrtcGetPTX(prog, ptx.ptr) != 0) return error.CompileFailed;
    for (&ptx_cache) |*e| if (e.arch == -1) {
        e.* = .{ .arch = arch, .ptx = ptx };
        break;
    };
    return ptx;
}

fn openRtc() ?std.DynLib {
    const names = [_][]const u8{ "libnvrtc.so", "libnvrtc.so.12", "libnvrtc.so.13", "libnvrtc.so.11.2" };
    for (names) |n| if (std.DynLib.open(n)) |l| return l else |_| {};
    return null;
}
