const std = @import("std");

/// std.Random over the OS CSPRNG. Failing to get entropy aborts: signing material must never
/// come from a weak source.
pub const SecureRandom = struct {
    io: std.Io,

    pub fn interface(self: *const SecureRandom) std.Random {
        return .{ .ptr = @constCast(self), .fillFn = fill };
    }

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *const SecureRandom = @ptrCast(@alignCast(ptr));
        self.io.randomSecure(buf) catch std.process.abort();
    }
};
