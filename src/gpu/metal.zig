//! Apple Metal through the Objective-C runtime, called straight from Zig (no Objective-C file, no
//! framework link flag): Metal.framework is dlopen'ed, classes and selectors are looked up with
//! objc_getClass / sel_registerName and messages go through objc_msgSend cast to the exact
//! signature. The shader source (kernels.zig) is compiled by the Metal driver at startup.
//! Buffers are MTLResourceStorageModeShared: the CPU and GPU see the same memory, no copies.
const std = @import("std");
const builtin = @import("builtin");
const kernels = @import("kernels.zig");
const backend = @import("backend.zig");

pub const available = builtin.os.tag == .macos;

const Id = ?*anyopaque;
const Sel = ?*anyopaque;
const Size = extern struct { w: usize, h: usize, d: usize };

/// libobjc entry points, looked up with dlopen so no link flag is needed.
var objc_getClass: *const fn ([*:0]const u8) callconv(.c) Id = undefined;
var sel_registerName: *const fn ([*:0]const u8) callconv(.c) Sel = undefined;
var objc_msgSend: *const fn () callconv(.c) void = undefined;
var objc_autoreleasePoolPush: *const fn () callconv(.c) ?*anyopaque = undefined;
var objc_autoreleasePoolPop: *const fn (?*anyopaque) callconv(.c) void = undefined;

fn sel(comptime name: [:0]const u8) Sel {
    return sel_registerName(name.ptr);
}

fn send(comptime F: type) F {
    return @ptrCast(objc_msgSend);
}

fn m0(obj: Id, s: Sel) Id {
    return send(*const fn (Id, Sel) callconv(.c) Id)(obj, s);
}
fn m1(obj: Id, s: Sel, a: ?*anyopaque) Id {
    return send(*const fn (Id, Sel, ?*anyopaque) callconv(.c) Id)(obj, s, a);
}
fn mv1(obj: Id, s: Sel, a: ?*anyopaque) void {
    send(*const fn (Id, Sel, ?*anyopaque) callconv(.c) void)(obj, s, a);
}
fn mv0(obj: Id, s: Sel) void {
    send(*const fn (Id, Sel) callconv(.c) void)(obj, s);
}
fn mu(obj: Id, s: Sel) usize {
    return send(*const fn (Id, Sel) callconv(.c) usize)(obj, s);
}
fn mcstr(obj: Id, s: Sel) ?[*:0]const u8 {
    return send(*const fn (Id, Sel) callconv(.c) ?[*:0]const u8)(obj, s);
}

const MetalError = backend.Error;

/// 0 = not loaded, 1 = loading, 2 = done (objc_ok says whether it worked).
var objc_state: std.atomic.Value(u8) = .init(0);
var objc_ok: bool = false;

fn objcOnce() void {
    if (objc_state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) {
        objcLoad();
        objc_state.store(2, .release);
        return;
    }
    while (objc_state.load(.acquire) != 2) std.Thread.yield() catch {};
}
var objc_lib: std.DynLib = undefined;

/// Loads the libobjc entry points once per process (the handle stays open for the process life).
fn objcLoad() void {
    objc_lib = std.DynLib.open("/usr/lib/libobjc.A.dylib") catch return;
    const o = &objc_lib;
    objc_getClass = o.lookup(@TypeOf(objc_getClass), "objc_getClass") orelse return;
    sel_registerName = o.lookup(@TypeOf(sel_registerName), "sel_registerName") orelse return;
    objc_msgSend = o.lookup(@TypeOf(objc_msgSend), "objc_msgSend") orelse return;
    objc_autoreleasePoolPush = o.lookup(@TypeOf(objc_autoreleasePoolPush), "objc_autoreleasePoolPush") orelse return;
    objc_autoreleasePoolPop = o.lookup(@TypeOf(objc_autoreleasePoolPop), "objc_autoreleasePoolPop") orelse return;
    objc_ok = true;
}

pub const max_slots = 2;

pub const Metal = struct {
    device: Id,
    queue: Id,
    library: Id,
    pipelines: [kernels.kernel_count]Id,
    max_threads: [kernels.kernel_count]usize,
    name_buf: [96]u8,
    name_len: usize,
    lib: std.DynLib,
    /// Command buffers in flight per pipeline slot (retained until `wait`).
    inflight: [max_slots]Id = @splat(null),

    pub fn init() MetalError!Metal {
        if (!available) return error.Unsupported;
        var lib = std.DynLib.open("/System/Library/Frameworks/Metal.framework/Metal") catch return error.NoDevice;
        errdefer lib.close();
        objcOnce();
        if (!objc_ok) return error.NoDevice;
        const create = lib.lookup(*const fn () callconv(.c) Id, "MTLCreateSystemDefaultDevice") orelse return error.NoDevice;
        const pool = objc_autoreleasePoolPush();
        defer objc_autoreleasePoolPop(pool);
        const device = create() orelse return error.NoDevice;
        errdefer mv0(device, sel("release"));
        const queue = m0(device, sel("newCommandQueue")) orelse return error.NoDevice;
        errdefer mv0(queue, sel("release"));

        const ns_string = objc_getClass("NSString");
        const src = m1(ns_string, sel("stringWithUTF8String:"), @constCast(@ptrCast(kernels.metal_source.ptr)));
        var err: Id = null;
        const library = send(*const fn (Id, Sel, Id, Id, *Id) callconv(.c) Id)(device, sel("newLibraryWithSource:options:error:"), src, null, &err) orelse {
            reportError(err, "metal compile");
            return error.CompileFailed;
        };
        errdefer mv0(library, sel("release"));

        var self: Metal = .{
            .device = device,
            .queue = queue,
            .library = library,
            .pipelines = @splat(null),
            .max_threads = @splat(1),
            .name_buf = undefined,
            .name_len = 0,
            .lib = lib,
        };
        errdefer for (self.pipelines) |p| if (p != null) mv0(p, sel("release"));
        inline for (0..kernels.kernel_count) |i| {
            const k: kernels.Kernel = @enumFromInt(i);
            const fname = m1(ns_string, sel("stringWithUTF8String:"), @constCast(@ptrCast(k.entry().ptr)));
            const func = m1(library, sel("newFunctionWithName:"), fname) orelse return error.CompileFailed;
            defer mv0(func, sel("release"));
            var perr: Id = null;
            self.pipelines[i] = send(*const fn (Id, Sel, Id, *Id) callconv(.c) Id)(device, sel("newComputePipelineStateWithFunction:error:"), func, &perr) orelse {
                reportError(perr, "metal pipeline");
                return error.CompileFailed;
            };
            self.max_threads[i] = mu(self.pipelines[i], sel("maxTotalThreadsPerThreadgroup"));
        }
        if (mcstr(m0(device, sel("name")), sel("UTF8String"))) |n| {
            const s = std.mem.span(n);
            const l = @min(s.len, self.name_buf.len);
            @memcpy(self.name_buf[0..l], s[0..l]);
            self.name_len = l;
        }
        return self;
    }

    pub fn getName(m: *const Metal) []const u8 {
        return m.name_buf[0..m.name_len];
    }

    pub fn deinit(m: *Metal) void {
        for (0..max_slots) |i| m.wait(i) catch {};
        for (m.pipelines) |p| if (p != null) mv0(p, sel("release"));
        mv0(m.library, sel("release"));
        mv0(m.queue, sel("release"));
        mv0(m.device, sel("release"));
        m.lib.close();
    }

    pub fn alloc(m: *Metal, len: usize) MetalError!backend.Buffer {
        const pool = objc_autoreleasePoolPush();
        defer objc_autoreleasePoolPop(pool);
        const n = @max(len, 16);
        const buf = send(*const fn (Id, Sel, usize, usize) callconv(.c) Id)(m.device, sel("newBufferWithLength:options:"), n, 0) orelse return error.OutOfMemory;
        const p: [*]u8 = @ptrCast(m0(buf, sel("contents")) orelse return error.OutOfMemory);
        return .{ .ptr = p, .len = n, .handle = buf, .dev = @intFromPtr(p), .kind = .host };
    }

    /// Unified memory: device buffers are shared buffers too.
    pub fn allocDevice(m: *Metal, len: usize) MetalError!backend.Buffer {
        return m.alloc(len);
    }

    pub fn upload(_: *Metal, b: backend.Buffer, off: usize, bytes: []const u8) MetalError!void {
        @memcpy(b.ptr[off..][0..bytes.len], bytes);
    }

    pub fn download(_: *Metal, b: backend.Buffer, off: usize, out: []u8) MetalError!void {
        @memcpy(out, b.ptr[off..][0..out.len]);
    }

    pub fn free(m: *Metal, b: backend.Buffer) void {
        _ = m;
        mv0(b.handle, sel("release"));
    }

    pub fn launch(m: *Metal, k: kernels.Kernel, bufs: []const backend.Buffer, n: usize) MetalError!void {
        if (n == 0) return;
        try m.submit(0, k, bufs, n);
        try m.wait(0);
    }

    /// Commits `k` over `n` threads into the slot (returns at once; `wait` collects it).
    pub fn submit(m: *Metal, slot: usize, k: kernels.Kernel, bufs: []const backend.Buffer, n: usize) MetalError!void {
        if (n == 0) return;
        if (m.inflight[slot] != null) try m.wait(slot);
        const pool = objc_autoreleasePoolPush();
        defer objc_autoreleasePoolPop(pool);
        const idx = @intFromEnum(k);
        const cmd = m0(m.queue, sel("commandBuffer")) orelse return error.LaunchFailed;
        const enc = m0(cmd, sel("computeCommandEncoder")) orelse return error.LaunchFailed;
        mv1(enc, sel("setComputePipelineState:"), m.pipelines[idx]);
        for (bufs, 0..) |b, i| {
            send(*const fn (Id, Sel, Id, usize, usize) callconv(.c) void)(enc, sel("setBuffer:offset:atIndex:"), b.handle, b.off, i);
        }
        const tg = @min(m.max_threads[idx], k.blockSize());
        send(*const fn (Id, Sel, Size, Size) callconv(.c) void)(enc, sel("dispatchThreads:threadsPerThreadgroup:"), .{ .w = n, .h = 1, .d = 1 }, .{ .w = tg, .h = 1, .d = 1 });
        mv0(enc, sel("endEncoding"));
        mv0(cmd, sel("commit"));
        m.inflight[slot] = m0(cmd, sel("retain"));
    }

    /// Waits for the slot's command buffer.
    pub fn wait(m: *Metal, slot: usize) MetalError!void {
        const cmd = m.inflight[slot] orelse return;
        m.inflight[slot] = null;
        defer mv0(cmd, sel("release"));
        mv0(cmd, sel("waitUntilCompleted"));
        // MTLCommandBufferStatusError = 5
        if (mu(cmd, sel("status")) == 5) {
            const pool = objc_autoreleasePoolPush();
            defer objc_autoreleasePoolPop(pool);
            reportError(m0(cmd, sel("error")), "metal launch");
            return error.LaunchFailed;
        }
    }

    /// True when the slot is idle or its command buffer has completed (or failed).
    pub fn done(m: *Metal, slot: usize) bool {
        const cmd = m.inflight[slot] orelse return true;
        return mu(cmd, sel("status")) >= 4; // Completed = 4, Error = 5
    }

    pub fn pciId(_: *const Metal) []const u8 {
        return "";
    }
};

fn reportError(err: Id, what: []const u8) void {
    const e = err orelse {
        std.debug.print("{s}: failed (no error object)\n", .{what});
        return;
    };
    const d = mcstr(m0(e, sel("localizedDescription")), sel("UTF8String")) orelse return;
    std.debug.print("{s}: {s}\n", .{ what, d });
}
