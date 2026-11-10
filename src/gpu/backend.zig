//! A compute backend: one device, host-visible and device buffers, and kernel launches.
//! Metal: unified memory (MTLResourceStorageModeShared), so every buffer is shared and copies
//! are memcpy. CUDA: `alloc` is pinned mapped host memory (the CPU fills it in place, kernels read
//! it over the bus) and `allocDevice` is device memory filled with `upload`.
//! Launches are synchronous (`launch`) or queued per pipeline slot (`submit`, then `wait`), so
//! a caller can prepare slot 1 while slot 0 runs.
const std = @import("std");
const builtin = @import("builtin");
const kernels = @import("kernels.zig");
const metal = @import("metal.zig");
const cuda = @import("cuda.zig");

pub const Kind = enum { none, metal, cuda };
pub const Kernel = kernels.Kernel;
/// Pipeline slots per device.
pub const max_slots = 2;

pub const Buffer = struct {
    /// Host view (`kind == .host`; undefined for device buffers).
    ptr: [*]u8,
    len: usize,
    handle: ?*anyopaque,
    /// The address kernels see.
    dev: u64 = 0,
    kind: enum { host, device } = .host,
    /// Byte offset kernels see the buffer from (`at`); host views ignore it.
    off: usize = 0,

    pub fn words(b: Buffer) []u32 {
        return @as([*]u32, @ptrCast(@alignCast(b.ptr)))[0 .. b.len / 4];
    }

    /// The same buffer bound from byte `o` on (for per-launch parameter blocks in one buffer).
    pub fn at(b: Buffer, o: usize) Buffer {
        var r = b;
        r.off = o;
        return r;
    }
};

pub const Error = error{ NoDevice, CompileFailed, OutOfMemory, LaunchFailed, Unsupported };

pub const Backend = union(Kind) {
    none: void,
    metal: if (metal.available) metal.Metal else void,
    cuda: if (cuda.available) cuda.Cuda else void,

    pub fn open(want: Kind) Error!Backend {
        return openDevice(want, 0);
    }

    pub fn openDevice(want: Kind, ordinal: u32) Error!Backend {
        switch (want) {
            .none => return .none,
            .metal => if (metal.available and ordinal == 0) return .{ .metal = try metal.Metal.init() } else return error.Unsupported,
            .cuda => if (cuda.available) return .{ .cuda = try cuda.Cuda.initDevice(ordinal) } else return error.Unsupported,
        }
    }

    /// Devices of this kind present (Metal: the system default device only).
    pub fn deviceCount(want: Kind) usize {
        return switch (want) {
            .none => 0,
            .metal => if (metal.available) 1 else 0,
            .cuda => if (cuda.available) cuda.Cuda.deviceCount() else 0,
        };
    }

    /// The best backend present: Metal on Apple, CUDA where libcuda and NVRTC load, else none.
    pub fn detect() Backend {
        if (metal.available) if (Backend.open(.metal)) |b| return b else |_| {};
        if (cuda.available) if (Backend.open(.cuda)) |b| return b else |_| {};
        return .none;
    }

    /// The kind `detect` would open, without keeping a device.
    pub fn detectKind() Kind {
        if (metal.available) return .metal;
        if (cuda.available and cuda.Cuda.deviceCount() > 0) return .cuda;
        return .none;
    }

    pub fn deinit(b: *Backend) void {
        switch (b.*) {
            .none => {},
            inline else => |*x| if (@TypeOf(x.*) != void) x.deinit(),
        }
        b.* = .none;
    }

    pub fn name(b: *const Backend) []const u8 {
        return switch (b.*) {
            .none => "none",
            inline else => |*x| if (@TypeOf(x.*) == void) "none" else x.getName(),
        };
    }

    /// PCI bus id (CUDA) or "" (Metal, none): part of the hardware fingerprint.
    pub fn pciId(b: *const Backend) []const u8 {
        return switch (b.*) {
            .none => "",
            inline else => |*x| if (@TypeOf(x.*) == void) "" else x.pciId(),
        };
    }

    pub fn alloc(b: *Backend, len: usize) Error!Buffer {
        return switch (b.*) {
            .none => error.NoDevice,
            inline else => |*x| if (@TypeOf(x.*) == void) error.NoDevice else x.alloc(len),
        };
    }

    pub fn allocDevice(b: *Backend, len: usize) Error!Buffer {
        return switch (b.*) {
            .none => error.NoDevice,
            inline else => |*x| if (@TypeOf(x.*) == void) error.NoDevice else x.allocDevice(len),
        };
    }

    pub fn upload(b: *Backend, buf: Buffer, off: usize, bytes: []const u8) Error!void {
        return switch (b.*) {
            .none => error.NoDevice,
            inline else => |*x| if (@TypeOf(x.*) == void) error.NoDevice else x.upload(buf, off, bytes),
        };
    }

    pub fn download(b: *Backend, buf: Buffer, off: usize, out: []u8) Error!void {
        return switch (b.*) {
            .none => error.NoDevice,
            inline else => |*x| if (@TypeOf(x.*) == void) error.NoDevice else x.download(buf, off, out),
        };
    }

    pub fn free(b: *Backend, buf: Buffer) void {
        switch (b.*) {
            .none => {},
            inline else => |*x| if (@TypeOf(x.*) != void) x.free(buf),
        }
    }

    /// Runs `k` over `n` threads with `bufs` bound to arguments 0.. and waits.
    pub fn launch(b: *Backend, k: Kernel, bufs: []const Buffer, n: usize) Error!void {
        return switch (b.*) {
            .none => error.NoDevice,
            inline else => |*x| if (@TypeOf(x.*) == void) error.NoDevice else x.launch(k, bufs, n),
        };
    }

    /// Queues `k` on pipeline slot `slot` (< max_slots) and returns.
    pub fn submit(b: *Backend, slot: usize, k: Kernel, bufs: []const Buffer, n: usize) Error!void {
        return switch (b.*) {
            .none => error.NoDevice,
            inline else => |*x| if (@TypeOf(x.*) == void) error.NoDevice else x.submit(slot, k, bufs, n),
        };
    }

    pub fn wait(b: *Backend, slot: usize) Error!void {
        return switch (b.*) {
            .none => error.NoDevice,
            inline else => |*x| if (@TypeOf(x.*) == void) error.NoDevice else x.wait(slot),
        };
    }

    pub fn done(b: *Backend, slot: usize) bool {
        return switch (b.*) {
            .none => true,
            inline else => |*x| if (@TypeOf(x.*) == void) true else x.done(slot),
        };
    }
};

comptime {
    std.debug.assert(metal.max_slots == max_slots and cuda.max_slots == max_slots);
}
