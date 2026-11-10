//! grpc.reflection.v1 and v1alpha ServerReflection (tonic-reflection 0.14 as sui-node 1.83.1
//! registers it) and grpc.health.v1.Health (tonic-health).
//!
//! Reflection serves the descriptor files sui-node registers, byte for byte (`h2/fds/`: every
//! file sui-node returns for file_by_filename equals the bytes in these sets, checked against
//! a production node; `vectors/refl/` holds its replies). Symbols are indexed as tonic-reflection
//! does: messages (nested too), their fields and oneofs, enums and their values, services and
//! their methods, all package-qualified. Each request message gets one reply on the bidi stream;
//! a lookup that fails ends the stream with the status (`symbol 'X' not found`), an empty
//! request with INVALID_ARGUMENT `invalid MessageRequest`, file_containing_extension with
//! NOT_FOUND `extensions are not supported`, and a request that does not decode ends it with
//! OK and no reply (all as captured).
const std = @import("std");
const Allocator = std.mem.Allocator;
const h2 = @import("h2/root.zig");
const proto = @import("proto.zig");

pub const Version = enum { v1, v1alpha };

/// sui-node's registration order: list_services answers services in this order.
const sets = [_][]const u8{
    @embedFile("h2/fds/sui.rpc.v2.fds.bin"),
    @embedFile("h2/fds/sui.rpc.v2alpha.fds.bin"),
    @embedFile("h2/fds/google.protobuf.fds.bin"),
    @embedFile("h2/fds/google.rpc.fds.bin"),
    @embedFile("h2/fds/grpc.health.v1.fds.bin"),
};
const refl_v1 = @embedFile("h2/fds/reflection_v1.fd.bin");
const refl_v1alpha = @embedFile("h2/fds/reflection_v1alpha.fd.bin");

const File = struct { name: []const u8, bytes: []const u8 };

const Index = struct {
    arena: std.heap.ArenaAllocator,
    files: std.ArrayList(File) = .empty,
    /// symbol -> file index
    symbols: std.StringHashMapUnmanaged(u32) = .empty,
    by_name: std.StringHashMapUnmanaged(u32) = .empty,
    services: std.ArrayList([]const u8) = .empty,

    fn addFile(ix: *Index, bytes: []const u8) !void {
        const a = ix.arena.allocator();
        const fi: u32 = @intCast(ix.files.items.len);
        var name: []const u8 = "";
        var pkg: []const u8 = "";
        var r = proto.Reader.init(bytes);
        while (try r.next()) |f| switch (f.number) {
            1 => name = try proto.Reader.stringOf(f),
            2 => pkg = try proto.Reader.stringOf(f),
            else => {},
        };
        try ix.files.append(a, .{ .name = name, .bytes = bytes });
        if (!ix.by_name.contains(name)) try ix.by_name.put(a, name, fi);
        r = proto.Reader.init(bytes);
        while (try r.next()) |f| switch (f.number) {
            4 => try ix.message(fi, pkg, try proto.Reader.bytesOf(f)),
            5 => try ix.enumType(fi, pkg, try proto.Reader.bytesOf(f)),
            6 => {
                const sb = try proto.Reader.bytesOf(f);
                const sname = try ix.qualify(pkg, nameOf(sb));
                try ix.services.append(a, sname);
                try ix.put(sname, fi);
                var sr = proto.Reader.init(sb);
                while (try sr.next()) |m| if (m.number == 2) try ix.put(try ix.qualify(sname, nameOf(try proto.Reader.bytesOf(m))), fi);
            },
            else => {},
        };
    }

    fn message(ix: *Index, fi: u32, prefix: []const u8, b: []const u8) !void {
        const mname = try ix.qualify(prefix, nameOf(b));
        try ix.put(mname, fi);
        var r = proto.Reader.init(b);
        // tonic-reflection order: nested messages, enums, fields, oneofs (only the set matters)
        while (try r.next()) |f| switch (f.number) {
            3 => try ix.message(fi, mname, try proto.Reader.bytesOf(f)),
            4 => try ix.enumType(fi, mname, try proto.Reader.bytesOf(f)),
            2, 8 => try ix.put(try ix.qualify(mname, nameOf(try proto.Reader.bytesOf(f))), fi),
            else => {},
        };
    }

    fn enumType(ix: *Index, fi: u32, prefix: []const u8, b: []const u8) !void {
        const ename = try ix.qualify(prefix, nameOf(b));
        try ix.put(ename, fi);
        var r = proto.Reader.init(b);
        while (try r.next()) |f| if (f.number == 2) try ix.put(try ix.qualify(ename, nameOf(try proto.Reader.bytesOf(f))), fi);
    }

    fn put(ix: *Index, sym: []const u8, fi: u32) !void {
        const gop = try ix.symbols.getOrPut(ix.arena.allocator(), sym);
        gop.value_ptr.* = fi;
    }

    fn qualify(ix: *Index, prefix: []const u8, name: []const u8) ![]const u8 {
        if (prefix.len == 0) return ix.arena.allocator().dupe(u8, name);
        return std.fmt.allocPrint(ix.arena.allocator(), "{s}.{s}", .{ prefix, name });
    }

    fn nameOf(b: []const u8) []const u8 {
        var r = proto.Reader.init(b);
        while (r.next() catch return "") |f| if (f.number == 1) return proto.Reader.stringOf(f) catch "";
        return "";
    }

    fn build(gpa: Allocator, version: Version) !*Index {
        const ix = try gpa.create(Index);
        ix.* = .{ .arena = std.heap.ArenaAllocator.init(gpa) };
        for (sets) |set| {
            var r = proto.Reader.init(set);
            while (try r.next()) |f| if (f.number == 1) try ix.addFile(try proto.Reader.bytesOf(f));
        }
        try ix.addFile(switch (version) {
            .v1 => refl_v1,
            .v1alpha => refl_v1alpha,
        });
        return ix;
    }
};

var index_lock: std.atomic.Value(u32) = .init(0);
var indexes: [2]?*Index = .{ null, null };

/// The process-wide index of a reflection version (built on first use, never freed).
fn getIndex(version: Version) !*const Index {
    while (index_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    defer index_lock.store(0, .release);
    const slot = &indexes[@intFromEnum(version)];
    if (slot.*) |ix| return ix;
    const ix = try Index.build(std.heap.page_allocator, version);
    slot.* = ix;
    return ix;
}

/// Service names list_services answers (also the set the router knows and health reports).
pub fn serviceNames(version: Version) ![]const []const u8 {
    return (try getIndex(version)).services.items;
}

/// True when `/pkg.Service/Method` names a method of a registered service (tonic's generated
/// routers serve exactly the methods of the descriptors reflection serves).
pub fn methodExists(path: []const u8) bool {
    if (path.len < 4 or path[0] != '/') return false;
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return false;
    if (slash == 0 or slash + 1 >= path.len) return false;
    var buf: [256]u8 = undefined;
    if (path.len > buf.len) return false;
    @memcpy(buf[0 .. path.len - 1], path[1..]);
    buf[slash - 1] = '.';
    const sym = buf[0 .. path.len - 1];
    for ([_]Version{ .v1, .v1alpha }) |v| {
        const ix = getIndex(v) catch return false;
        if (ix.symbols.get(sym) != null) return true;
    }
    return false;
}

pub const v1_path = "/grpc.reflection.v1.ServerReflection/";
pub const v1alpha_path = "/grpc.reflection.v1alpha.ServerReflection/";

/// One ServerReflectionRequest on the ServerReflectionInfo bidi stream.
pub fn call(gpa: Allocator, version: Version, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    const base = switch (version) {
        .v1 => v1_path,
        .v1alpha => v1alpha_path,
    };
    if (!std.mem.eql(u8, req.path[base.len..], "ServerReflectionInfo")) return .unimplemented;
    return reply(gpa, version, req.body, rs) catch |e| switch (e) {
        // tonic-reflection 0.14.6 (server/v1.rs): `let Ok(req) = req else { return; }`, so a
        // request that fails to decode ends the response with OK and no reply (h1-refl-bad,
        // h2-refl-bad).
        error.Malformed => {
            rs.end_stream = true;
            return .ok;
        },
        else => {
            rs.setMessage(@errorName(e));
            return .internal;
        },
    };
}

const Which = enum(u32) { none = 0, file_by_filename = 3, file_containing_symbol = 4, file_containing_extension = 5, all_extension_numbers_of_type = 6, list_services = 7 };

fn reply(gpa: Allocator, version: Version, body: []const u8, rs: *h2.ResponseStream) !h2.Status {
    const ix = try getIndex(version);
    var host: []const u8 = "";
    var which: Which = .none;
    var arg: []const u8 = "";
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => host = proto.Reader.stringOf(f) catch return error.Malformed,
        3, 4, 5, 6, 7 => {
            which = @enumFromInt(f.number);
            arg = proto.Reader.bytesOf(f) catch return error.Malformed;
        },
        else => {},
    };
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var text_buf: [512]u8 = undefined;
    // the reply body
    var resp_field: u32 = 0;
    var resp_body: std.ArrayList(u8) = .empty;
    switch (which) {
        .none => {
            rs.setMessage("invalid MessageRequest");
            return .invalid_argument;
        },
        .file_containing_extension => {
            // tonic-reflection: `Err(Status::not_found("extensions are not supported"))`
            // (h1-refl-ext, h2-refl-ext)
            rs.setMessage("extensions are not supported");
            return .not_found;
        },
        .file_by_filename, .file_containing_symbol => {
            const fi = (if (which == .file_by_filename) ix.by_name.get(arg) else ix.symbols.get(arg)) orelse {
                const what = if (which == .file_by_filename) "file" else "symbol";
                rs.setMessage(std.fmt.bufPrint(&text_buf, "{s} '{s}' not found", .{ what, arg }) catch "not found");
                return .not_found;
            };
            const fb = ix.files.items[fi].bytes;
            try lenField(&resp_body, arena, 1, fb);
            resp_field = 4;
        },
        .all_extension_numbers_of_type => resp_field = 5,
        .list_services => {
            for (ix.services.items) |s| {
                var one: std.ArrayList(u8) = .empty;
                try lenField(&one, arena, 1, s);
                try lenField(&resp_body, arena, 1, one.items);
            }
            resp_field = 6;
        },
    }
    // ServerReflectionResponse { valid_host = 1; original_request = 2; message_response }
    var orig: std.ArrayList(u8) = .empty;
    if (host.len > 0) try lenField(&orig, arena, 1, host);
    if (which == .file_containing_extension) unreachable;
    try lenField(&orig, arena, @intFromEnum(which), arg);
    var out: std.ArrayList(u8) = .empty;
    if (host.len > 0) try lenField(&out, arena, 1, host);
    try lenField(&out, arena, 2, orig.items);
    try lenField(&out, arena, resp_field, resp_body.items);
    try rs.message(out.items);
    return .ok;
}

fn lenField(out: *std.ArrayList(u8), a: Allocator, field: u32, data: []const u8) !void {
    var tmp: [20]u8 = undefined;
    var n: usize = 0;
    n += putVarint(tmp[n..], (@as(u64, field) << 3) | 2);
    n += putVarint(tmp[n..], data.len);
    try out.appendSlice(a, tmp[0..n]);
    try out.appendSlice(a, data);
}

fn putVarint(buf: []u8, v0: u64) usize {
    var v = v0;
    var i: usize = 0;
    while (v >= 0x80) : (i += 1) {
        buf[i] = @as(u8, @truncate(v)) | 0x80;
        v >>= 7;
    }
    buf[i] = @intCast(v);
    return i + 1;
}

// ---------------------------------------------------------------- grpc.health.v1.Health

pub const health_path = "/grpc.health.v1.Health/";

/// tonic-health as sui-node sets it up: "" and every registered service but Health itself
/// answer SERVING; anything else NOT_FOUND `service not registered`, for Check and for Watch
/// (tonic-health 0.14.6 server.rs `watch` fails before any stream exists: h1-watch-unknown,
/// h2-watch-unknown).
pub fn healthRegistered(name: []const u8) bool {
    if (name.len == 0) return true;
    if (std.mem.eql(u8, name, "grpc.health.v1.Health")) return false;
    for ([_]Version{ .v1, .v1alpha }) |v| {
        const names = serviceNames(v) catch return false;
        for (names) |n| if (std.mem.eql(u8, n, name)) return true;
    }
    return false;
}

fn healthService(body: []const u8) ![]const u8 {
    var r = proto.Reader.init(body);
    var name: []const u8 = "";
    while (try r.next()) |f| if (f.number == 1) {
        name = try proto.Reader.stringOf(f);
    };
    return name;
}

const serving_msg = [_]u8{ 0x08, 0x01 };

pub fn healthCall(req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    const method = req.path[health_path.len..];
    const name = healthService(req.body) catch {
        rs.setMessage("failed to decode Protobuf message: invalid wire type value");
        return .internal;
    };
    if (std.mem.eql(u8, method, "Check")) {
        if (!healthRegistered(name)) {
            rs.setMessage("service not registered");
            return .not_found;
        }
        rs.message(&serving_msg) catch return .internal;
        return .ok;
    }
    if (std.mem.eql(u8, method, "Watch")) {
        if (!healthRegistered(name)) {
            rs.setMessage("service not registered");
            return .not_found;
        }
        // The current status, then the stream stays open until the client or the server ends
        // it (the status never changes while the node serves). `held`: no pump, no thread.
        rs.message(&serving_msg) catch return .internal;
        return .held;
    }
    return .unimplemented;
}


// ---------------------------------------------------------------- tests

const Frame = struct { flag: u8, data: []const u8 };
const Capture = struct {
    fn frames(body: []const u8, list: *std.ArrayList(Frame), a: Allocator) !void {
        var i: usize = 0;
        while (i + 5 <= body.len) {
            const n = std.mem.readInt(u32, body[i + 1 ..][0..4], .big);
            try list.append(a, .{ .flag = body[i], .data = body[i + 5 ..][0..n] });
            i += 5 + n;
        }
    }
};

const TestSink = struct {
    out: std.ArrayList(u8) = .empty,
    a: Allocator,
    fn write(impl: *anyopaque, hdr: *const [5]u8, payload: []const u8) anyerror!void {
        const s: *TestSink = @ptrCast(@alignCast(impl));
        try s.out.appendSlice(s.a, hdr);
        try s.out.appendSlice(s.a, payload);
    }
    fn cancelled(_: *anyopaque) bool {
        return false;
    }
    const vt: h2.ResponseStream.VTable = .{ .write = write, .cancelled = cancelled };
};

/// `want` is a captured gRPC-web body holding only the trailers frame.
fn expectTrailers(want: []const u8, status: h2.Status, msg: []const u8) !void {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("grpc-status:{d}\r\n", .{@intFromEnum(status)});
    if (msg.len > 0) {
        var enc: std.ArrayList(u8) = .empty;
        defer enc.deinit(std.testing.allocator);
        try h2.codec.percentEncode(&enc, std.testing.allocator, msg);
        try w.print("grpc-message:{s}\r\n", .{enc.items});
    }
    const t = w.buffered();
    try std.testing.expectEqual(@as(u8, 0x80), want[0]);
    try std.testing.expectEqual(@as(u32, @intCast(t.len)), std.mem.readInt(u32, want[1..5], .big));
    try std.testing.expectEqualStrings(want[5..], t);
}

fn runOne(a: Allocator, version: Version, req_body: []const u8) !struct { status: h2.Status, out: []const u8, msg: []const u8, end: bool } {
    var sink: TestSink = .{ .a = a };
    var rs: h2.ResponseStream = .{ .gpa = std.testing.allocator, .impl = &sink, .vt = &TestSink.vt };
    defer rs.release();
    const path = if (version == .v1) v1_path ++ "ServerReflectionInfo" else v1alpha_path ++ "ServerReflectionInfo";
    const req: h2.Request = .{ .path = path, .authority = "", .body = req_body, .stream_id = 1 };
    const st = call(std.testing.allocator, version, &req, &rs);
    return .{ .status = st, .out = sink.out.items, .msg = try a.dupe(u8, rs.msg), .end = rs.end_stream };
}

test "reflection replies equal sui-node's (vectors/refl)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const ok_cases = [_]struct { name: []const u8, v: Version }{
        .{ .name = "sym-sui.rpc.v2.LedgerService", .v = .v1 },
        .{ .name = "sym-sui.rpc.v2.ErrorReason.FIELD_INVALID", .v = .v1 },
        .{ .name = "sym-sui.rpc.v2.GetCheckpointRequest.checkpoint_id", .v = .v1 },
        .{ .name = "sym-grpc.health.v1.HealthCheckResponse.ServingStatus", .v = .v1 },
        .{ .name = "sym-google.protobuf.Timestamp", .v = .v1 },
        .{ .name = "file-sui_rpc_v2_bcs.proto", .v = .v1 },
        .{ .name = "extnums", .v = .v1 },
        .{ .name = "list-host", .v = .v1 },
        .{ .name = "list-alpha", .v = .v1alpha },
        .{ .name = "sym-alpha", .v = .v1alpha },
        .{ .name = "sym-alpha-refl", .v = .v1alpha },
    };
    inline for (ok_cases) |c| {
        const want = @embedFile("h2/vectors/refl/" ++ c.name ++ ".body");
        var fr: std.ArrayList(Frame) = .empty;
        try Capture.frames(want, &fr, a);
        // the request is the reply's original_request (field 2)
        var req_body: []const u8 = "";
        var r = proto.Reader.init(fr.items[0].data);
        while (try r.next()) |f| if (f.number == 2) {
            req_body = try proto.Reader.bytesOf(f);
        };
        const got = try runOne(a, c.v, req_body);
        try std.testing.expectEqual(h2.Status.ok, got.status);
        try std.testing.expectEqualSlices(u8, want[0 .. 5 + fr.items[0].data.len], got.out);
    }
    // errors end the stream with the status
    const nope = try runOne(a, .v1, "\x22\x09nope.Nope");
    try std.testing.expectEqual(h2.Status.not_found, nope.status);
    try std.testing.expectEqualStrings("symbol 'nope.Nope' not found", nope.msg);
    const nofile = try runOne(a, .v1, "\x1a\x0anope.proto");
    try std.testing.expectEqualStrings("file 'nope.proto' not found", nofile.msg);
    const v1_from_alpha = try runOne(a, .v1alpha, "\x22\x23grpc.reflection.v1.ServerReflection");
    try std.testing.expectEqual(h2.Status.not_found, v1_from_alpha.status);
    const empty = try runOne(a, .v1, "");
    try std.testing.expectEqual(h2.Status.invalid_argument, empty.status);
    try std.testing.expectEqualStrings("invalid MessageRequest", empty.msg);
    // file_containing_extension: NOT_FOUND, no reply (vectors/refl/ext.body, captured with
    // these request bytes)
    const ext = try runOne(a, .v1, "\x2a\x15\x0a\x11sui.rpc.v2.Object\x10\x05");
    try std.testing.expectEqual(h2.Status.not_found, ext.status);
    try std.testing.expectEqualStrings("extensions are not supported", ext.msg);
    try std.testing.expectEqual(@as(usize, 0), ext.out.len);
    try expectTrailers(@embedFile("h2/vectors/refl/ext.body"), ext.status, ext.msg);
    // a request that does not decode: the stream ends with OK, no reply (vectors/refl/bad.body)
    const bad = try runOne(a, .v1, "\x0f");
    try std.testing.expectEqual(h2.Status.ok, bad.status);
    try std.testing.expect(bad.end);
    try std.testing.expectEqual(@as(usize, 0), bad.out.len);
    try expectTrailers(@embedFile("h2/vectors/refl/bad.body"), bad.status, bad.msg);
    try std.testing.expect(healthRegistered(""));
    try std.testing.expect(healthRegistered("sui.rpc.v2.StateService"));
    try std.testing.expect(healthRegistered("grpc.reflection.v1alpha.ServerReflection"));
    try std.testing.expect(!healthRegistered("grpc.health.v1.Health"));
    try std.testing.expect(!healthRegistered("nope.Svc"));
}
