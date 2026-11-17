//! The truth vectors in `$ZUI_CORPUS/vectors/rpc-execute` (made by tools/truth/rpc-exec-driver).
//! Skipped when there is no corpus (`$ZUI_CORPUS` unset or not a directory), like the other
//! corpus tests. A corpus without these vectors fails the test: generate them with the commands
//! in that tool's README.
const std = @import("std");
const testing = std.testing;
const vectors = @import("vectors.zig");

const Counter = struct {
    passed: usize = 0,
    failed: usize = 0,

    fn sink(c: *Counter) vectors.Sink {
        return .{ .ctx = c, .passFn = pass, .failFn = fail };
    }
    fn pass(ctx: *anyopaque, item: []const u8) void {
        _ = item;
        const c: *Counter = @ptrCast(@alignCast(ctx));
        c.passed += 1;
    }
    fn fail(ctx: *anyopaque, item: []const u8, why: []const u8) void {
        const c: *Counter = @ptrCast(@alignCast(ctx));
        if (c.failed < 12) std.debug.print("FAIL {s}: {s}\n", .{ item, why });
        c.failed += 1;
    }
};

test "rpc-execute truth vectors" {
    const gpa = testing.allocator;
    const corpus = testing.environ.getAlloc(gpa, "ZUI_CORPUS") catch return error.SkipZigTest;
    defer gpa.free(corpus);
    var root = std.Io.Dir.openDirAbsolute(testing.io, corpus, .{}) catch |e| switch (e) {
        error.FileNotFound, error.NotDir => return error.SkipZigTest, // no corpus on this host
        else => {
            std.debug.print("cannot open $ZUI_CORPUS {s}: {t}\n", .{ corpus, e });
            return e;
        },
    };
    defer root.close(testing.io);
    var c: Counter = .{};
    vectors.runAll(gpa, testing.io, root, c.sink(), null) catch |e| {
        std.debug.print("rpc-execute vectors in {s}/{s}: {t} (generate them: tools/truth/rpc-exec-driver/README.md)\n", .{ corpus, vectors.dir, e });
        return e;
    };
    // silent on success: the build runner shows any stderr of a test step under "failed command"
    if (c.passed == 0 or c.failed != 0) std.debug.print("rpc-execute vectors: {d} passed, {d} failed\n", .{ c.passed, c.failed });
    try testing.expect(c.passed > 0);
    try testing.expectEqual(@as(usize, 0), c.failed);
}
