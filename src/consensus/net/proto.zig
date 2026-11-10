//! The consensus.ConsensusService wire at mainnet-v1.83.1 (`consensus/core/build.rs`,
//! `network/tonic_network.rs`): gRPC over HTTP/2 over TLS 1.3 (rustls), zstd message
//! compression both ways, prost messages below. Owner lane: val-consensus-net.
//!
//! Methods (path "/consensus.ConsensusService/<Route>"):
//!   SendBlock          unary             SendBlockRequest -> SendBlockResponse (tests only in 1.83)
//!   SubscribeBlocks    bidi streaming    stream SubscribeBlocksRequest -> stream SubscribeBlocksResponse
//!   FetchBlocks        server streaming  FetchBlocksRequest -> stream FetchBlocksResponse
//!   FetchCommits       unary             FetchCommitsRequest -> FetchCommitsResponse
//!   FetchLatestBlocks  server streaming  FetchLatestBlocksRequest -> stream FetchLatestBlocksResponse
//!   GetLatestRounds    unary             GetLatestRoundsRequest -> GetLatestRoundsResponse
//! consensus.ObserverService (StreamBlocks, FetchBlocks, FetchCommits) is for observers and is
//! planned after the validator path (docs/VALIDATOR-DESIGN.md 5.2).
//!
//! Every `bytes` field holds BCS: a SignedBlock, a BlockRef, or a Commit. Messages are decoded
//! as views over the received frame (no copies) with serve/proto.zig's reader.
const std = @import("std");

pub const service_path = "/consensus.ConsensusService/";
pub const Method = enum {
    SendBlock,
    SubscribeBlocks,
    FetchBlocks,
    FetchCommits,
    FetchLatestBlocks,
    GetLatestRounds,

    pub fn path(m: Method) []const u8 {
        return switch (m) {
            inline else => |t| service_path ++ @tagName(t),
        };
    }
};

/// tag 1 bytes: serialized SignedBlock
pub const SendBlockRequest = struct { block: []const u8 };
pub const SendBlockResponse = struct {};
/// tag 1 uint32
pub const SubscribeBlocksRequest = struct { last_received_round: u32 };
/// tag 1 bytes: SignedBlock (or a SerializedBlockEnvelope when slim propagation is on, off on
/// mainnet 141); tag 2 repeated bytes: BCS BlockRefs excluded from the block's ancestors.
pub const SubscribeBlocksResponse = struct { block: []const u8, excluded_ancestors: []const []const u8 };
/// tag 1 repeated bytes (BCS BlockRef), tag 2 packed uint32, tag 3 bool
pub const FetchBlocksRequest = struct { block_refs: []const []const u8, fetch_after_rounds: []const u32, fetch_missing_ancestors: bool };
/// tag 1 repeated bytes (SignedBlock); chunked by `chunk_blocks` under message_size_limit.
pub const FetchBlocksResponse = struct { blocks: []const []const u8 };
/// tag 1 uint32, tag 2 uint32 (inclusive range)
pub const FetchCommitsRequest = struct { start: u32, end: u32 };
/// tag 1 repeated bytes (Commit), tag 2 repeated bytes (SignedBlock certifying the last commit)
pub const FetchCommitsResponse = struct { commits: []const []const u8, certifier_blocks: []const []const u8 };
/// tag 1 packed uint32
pub const FetchLatestBlocksRequest = struct { authorities: []const u32 };
pub const FetchLatestBlocksResponse = struct { blocks: []const []const u8 };
pub const GetLatestRoundsRequest = struct {};
/// tag 1 packed uint32, tag 2 packed uint32 (per authority index)
pub const GetLatestRoundsResponse = struct { highest_received: []const u32, highest_accepted: []const u32 };

pub const Error = error{ Malformed, OutOfMemory };

/// How a method moves messages (tonic's client/server streaming flags in build.rs).
pub const Kind = enum { unary, server_stream, bidi };

pub fn kindOf(m: Method) Kind {
    return switch (m) {
        .SendBlock, .FetchCommits, .GetLatestRounds => .unary,
        .FetchBlocks, .FetchLatestBlocks => .server_stream,
        .SubscribeBlocks => .bidi,
    };
}

pub fn methodFromPath(path: []const u8) ?Method {
    if (!std.mem.startsWith(u8, path, service_path)) return null;
    const name = path[service_path.len..];
    return std.meta.stringToEnum(Method, name);
}

// ---------------------------------------------------------------- prost encoding

fn putVarint(out: *std.ArrayList(u8), gpa: std.mem.Allocator, v: u64) std.mem.Allocator.Error!void {
    var x = v;
    while (x >= 0x80) : (x >>= 7) try out.append(gpa, @as(u8, @truncate(x)) | 0x80);
    try out.append(gpa, @truncate(x));
}

fn putTag(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, wire: u3) std.mem.Allocator.Error!void {
    try putVarint(out, gpa, (@as(u64, field) << 3) | wire);
}

fn putBytes(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, b: []const u8) std.mem.Allocator.Error!void {
    try putTag(out, gpa, field, 2);
    try putVarint(out, gpa, b.len);
    try out.appendSlice(gpa, b);
}

/// Appends the prost encoding of `v` (proto3: tags in field order, defaults omitted, repeated
/// scalars packed, repeated bytes one entry each, empty ones included).
pub fn encodeAppend(comptime T: type, gpa: std.mem.Allocator, out: *std.ArrayList(u8), v: *const T) std.mem.Allocator.Error!void {
    const names = @typeInfo(T).@"struct".field_names;
    const ftypes = @typeInfo(T).@"struct".field_types;
    inline for (names, ftypes, 0..) |name, FT, i| {
        const tag: u32 = i + 1;
        const x = @field(v, name);
        switch (FT) {
            []const u8 => if (x.len != 0) try putBytes(out, gpa, tag, x),
            []const []const u8 => for (x) |e| try putBytes(out, gpa, tag, e),
            []const u32 => if (x.len != 0) {
                var body: std.ArrayList(u8) = .empty;
                defer body.deinit(gpa);
                for (x) |e| try putVarint(&body, gpa, e);
                try putBytes(out, gpa, tag, body.items);
            },
            u32 => if (x != 0) {
                try putTag(out, gpa, tag, 0);
                try putVarint(out, gpa, x);
            },
            bool => if (x) {
                try putTag(out, gpa, tag, 0);
                try putVarint(out, gpa, 1);
            },
            else => @compileError("proto: unsupported field type " ++ @typeName(FT)),
        }
    }
}

/// The prost encoding of `v` in a fresh buffer (caller frees).
pub fn encode(comptime T: type, gpa: std.mem.Allocator, v: *const T) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try encodeAppend(T, gpa, &out, v);
    return out.toOwnedSlice(gpa);
}

fn readVarint(b: []const u8, pos: *usize) Error!u64 {
    var x: u64 = 0;
    var shift: u7 = 0;
    while (true) {
        if (pos.* >= b.len or shift > 63) return error.Malformed;
        const c = b[pos.*];
        pos.* += 1;
        x |= @as(u64, c & 0x7f) << @intCast(shift);
        if (c & 0x80 == 0) return x;
        shift += 7;
    }
}

/// Decodes `bytes` into `T`. Byte fields are views into `bytes`; repeated fields are allocated
/// in `arena`. Unknown fields are skipped, scalars accept the packed and the unpacked form.
pub fn decode(comptime T: type, arena: std.mem.Allocator, bytes: []const u8) Error!T {
    var result: T = std.mem.zeroInit(T, .{});
    const names = @typeInfo(T).@"struct".field_names;
    const ftypes = @typeInfo(T).@"struct".field_types;
    // Repeated fields accumulate as raw element lists first: bytes as slices, u32 as values.
    var bl: [names.len]std.ArrayList([]const u8) = @splat(.empty);
    var ul: [names.len]std.ArrayList(u32) = @splat(.empty);
    var pos: usize = 0;
    while (pos < bytes.len) {
        const key = try readVarint(bytes, &pos);
        const tag = key >> 3;
        const wire: u3 = @truncate(key);
        var matched = false;
        inline for (names, ftypes, 0..) |name, FT, i| {
            if (tag == i + 1) {
                matched = true;
                switch (FT) {
                    []const u8, []const []const u8 => {
                        if (wire != 2) return error.Malformed;
                        const n = try readVarint(bytes, &pos);
                        if (n > bytes.len - pos) return error.Malformed;
                        const view = bytes[pos..][0..@intCast(n)];
                        pos += @intCast(n);
                        if (FT == []const u8) {
                            @field(result, name) = view;
                        } else {
                            try bl[i].append(arena, view);
                        }
                    },
                    []const u32 => switch (wire) {
                        2 => {
                            const n = try readVarint(bytes, &pos);
                            if (n > bytes.len - pos) return error.Malformed;
                            const end = pos + @as(usize, @intCast(n));
                            while (pos < end) {
                                const e = try readVarint(bytes[0..end], &pos);
                                try ul[i].append(arena, std.math.cast(u32, e) orelse return error.Malformed);
                            }
                        },
                        0 => {
                            const e = try readVarint(bytes, &pos);
                            try ul[i].append(arena, std.math.cast(u32, e) orelse return error.Malformed);
                        },
                        else => return error.Malformed,
                    },
                    u32 => {
                        if (wire != 0) return error.Malformed;
                        @field(result, name) = std.math.cast(u32, try readVarint(bytes, &pos)) orelse return error.Malformed;
                    },
                    bool => {
                        if (wire != 0) return error.Malformed;
                        @field(result, name) = (try readVarint(bytes, &pos)) != 0;
                    },
                    else => @compileError("proto: unsupported field type " ++ @typeName(FT)),
                }
            }
        }
        if (!matched) switch (wire) {
            0 => _ = try readVarint(bytes, &pos),
            1 => {
                if (bytes.len - pos < 8) return error.Malformed;
                pos += 8;
            },
            2 => {
                const n = try readVarint(bytes, &pos);
                if (n > bytes.len - pos) return error.Malformed;
                pos += @intCast(n);
            },
            5 => {
                if (bytes.len - pos < 4) return error.Malformed;
                pos += 4;
            },
            else => return error.Malformed,
        };
    }
    inline for (names, ftypes, 0..) |name, FT, i| {
        switch (FT) {
            []const []const u8 => @field(result, name) = try bl[i].toOwnedSlice(arena),
            []const u32 => @field(result, name) = try ul[i].toOwnedSlice(arena),
            else => {},
        }
    }
    return result;
}

/// `chunk_blocks`: groups blocks into responses of at most `limit` bytes each (a response always
/// holds at least one block, so one oversized block travels alone). Writes the exclusive end
/// index of each chunk to `out_ends` and returns the chunk count; null when `out_ends` is full.
pub fn chunkBlocks(blocks: []const []const u8, limit: usize, out_ends: []usize) ?usize {
    var n: usize = 0;
    var size: usize = 0;
    var start: usize = 0;
    for (blocks, 0..) |b, i| {
        if (i > start and size + b.len > limit) {
            if (n >= out_ends.len) return null;
            out_ends[n] = i;
            n += 1;
            start = i;
            size = 0;
        }
        size += b.len;
    }
    if (blocks.len > start) {
        if (n >= out_ends.len) return null;
        out_ends[n] = blocks.len;
        n += 1;
    }
    return n;
}

/// Rust MAX_FETCH_RESPONSE_BYTES (tonic_network.rs).
pub const max_fetch_response_bytes: usize = 4 * 1024 * 1024;

test "method paths" {
    try std.testing.expectEqualStrings("/consensus.ConsensusService/SubscribeBlocks", Method.SubscribeBlocks.path());
    try std.testing.expectEqual(Method.FetchBlocks, methodFromPath("/consensus.ConsensusService/FetchBlocks").?);
    try std.testing.expect(methodFromPath("/consensus.ConsensusService/Nope") == null);
    try std.testing.expect(kindOf(.SubscribeBlocks) == .bidi);
}

test "prost bytes: known encodings" {
    const gpa = std.testing.allocator;
    // FetchCommitsRequest{start:1,end:300}: 08 01 10 ac 02
    const a = try encode(FetchCommitsRequest, gpa, &.{ .start = 1, .end = 300 });
    defer gpa.free(a);
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0x01, 0x10, 0xac, 0x02 }, a);
    // defaults omitted
    const z = try encode(FetchCommitsRequest, gpa, &.{ .start = 0, .end = 0 });
    defer gpa.free(z);
    try std.testing.expectEqual(@as(usize, 0), z.len);
    // packed repeated uint32: 0a 03 01 02 03; empty bytes entry kept in repeated bytes
    const r = try encode(FetchLatestBlocksRequest, gpa, &.{ .authorities = &.{ 1, 2, 3 } });
    defer gpa.free(r);
    try std.testing.expectEqualSlices(u8, &.{ 0x0a, 0x03, 1, 2, 3 }, r);
    const fb = try encode(FetchBlocksResponse, gpa, &.{ .blocks = &.{ "ab", "" } });
    defer gpa.free(fb);
    try std.testing.expectEqualSlices(u8, &.{ 0x0a, 2, 'a', 'b', 0x0a, 0 }, fb);
    // bool true is tag 3 varint 1
    const q = try encode(FetchBlocksRequest, gpa, &.{ .block_refs = &.{}, .fetch_after_rounds = &.{}, .fetch_missing_ancestors = true });
    defer gpa.free(q);
    try std.testing.expectEqualSlices(u8, &.{ 0x18, 0x01 }, q);
}

test "prost round trip, unpacked and unknown fields" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const req: FetchBlocksRequest = .{ .block_refs = &.{ "r1", "r22" }, .fetch_after_rounds = &.{ 0, 5, 200000, 7 }, .fetch_missing_ancestors = true };
    const bytes = try encode(FetchBlocksRequest, gpa, &req);
    defer gpa.free(bytes);
    const back = try decode(FetchBlocksRequest, arena, bytes);
    try std.testing.expectEqual(@as(usize, 2), back.block_refs.len);
    try std.testing.expectEqualStrings("r22", back.block_refs[1]);
    try std.testing.expectEqualSlices(u32, req.fetch_after_rounds, back.fetch_after_rounds);
    try std.testing.expect(back.fetch_missing_ancestors);
    // unpacked repeated uint32 (tag 2 varint x2) plus an unknown fixed32 field 9
    const raw = [_]u8{ 0x10, 0x01, 0x10, 0x02, 0x4d, 1, 2, 3, 4 };
    const u = try decode(FetchBlocksRequest, arena, &raw);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2 }, u.fetch_after_rounds);
    // truncated length-delimited field is malformed
    try std.testing.expectError(error.Malformed, decode(FetchBlocksRequest, arena, &.{ 0x0a, 5, 1 }));
    // wrong wire type for a known field
    try std.testing.expectError(error.Malformed, decode(FetchCommitsRequest, arena, &.{ 0x0a, 0 }));
}

test "chunkBlocks groups under the limit, oversize alone" {
    var ends: [8]usize = undefined;
    const blocks = [_][]const u8{ "aaaa", "bbbb", "cc", "dddddddddd", "e" };
    const n = chunkBlocks(&blocks, 8, &ends).?;
    try std.testing.expectEqualSlices(usize, &.{ 2, 3, 4, 5 }, ends[0..n]);
    try std.testing.expectEqual(@as(?usize, 0), chunkBlocks(&.{}, 8, &ends));
}

fn hexOf(gpa: std.mem.Allocator, b: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, b.len * 2);
    const digits = "0123456789abcdef";
    for (b, 0..) |x, i| {
        out[2 * i] = digits[x >> 4];
        out[2 * i + 1] = digits[x & 15];
    }
    return out;
}

// The same input table as tools/truth/consensus-net/proto-vectors/src/main.rs. Compares with
// prost's output when `tools/truth/consensus-net/vectors/proto.txt` exists.
test "prost vectors" {
    const gpa = std.testing.allocator;
    var table: std.ArrayList(struct { []const u8, []u8 }) = .empty;
    defer {
        for (table.items) |e| gpa.free(e[1]);
        table.deinit(gpa);
    }
    const add = struct {
        fn f(g: std.mem.Allocator, t: anytype, name: []const u8, comptime T: type, v: T) !void {
            const bytes = try encode(T, g, &v);
            defer g.free(bytes);
            try t.append(g, .{ name, try hexOf(g, bytes) });
        }
    }.f;
    const t = &table;
    try add(gpa, t, "send_block", SendBlockRequest, .{ .block = &.{ 1, 2, 3 } });
    try add(gpa, t, "send_block_empty", SendBlockRequest, .{ .block = "" });
    try add(gpa, t, "subscribe_0", SubscribeBlocksRequest, .{ .last_received_round = 0 });
    try add(gpa, t, "subscribe_300", SubscribeBlocksRequest, .{ .last_received_round = 300 });
    try add(gpa, t, "subscribe_resp", SubscribeBlocksResponse, .{ .block = &.{ 9, 9, 9, 9, 9 }, .excluded_ancestors = &.{ &.{ 7, 7, 7 }, "" } });
    try add(gpa, t, "fetch_blocks_req", FetchBlocksRequest, .{ .block_refs = &.{ &.{ 1, 1, 1, 1 }, &.{ 2, 2 } }, .fetch_after_rounds = &.{ 0, 5, 200000, 7 }, .fetch_missing_ancestors = true });
    try add(gpa, t, "fetch_blocks_req_empty", FetchBlocksRequest, .{ .block_refs = &.{}, .fetch_after_rounds = &.{}, .fetch_missing_ancestors = false });
    try add(gpa, t, "fetch_blocks_resp", FetchBlocksResponse, .{ .blocks = &.{ &.{ 5, 5 }, "", &.{6} } });
    try add(gpa, t, "fetch_commits_req", FetchCommitsRequest, .{ .start = 1, .end = 300 });
    try add(gpa, t, "fetch_commits_resp", FetchCommitsResponse, .{ .commits = &.{&.{ 1, 1, 1 }}, .certifier_blocks = &.{ &.{ 2, 2 }, &.{ 3, 3 } } });
    try add(gpa, t, "fetch_latest_req", FetchLatestBlocksRequest, .{ .authorities = &.{ 0, 1, 130, 7 } });
    try add(gpa, t, "latest_rounds_resp", GetLatestRoundsResponse, .{ .highest_received = &.{ 1, 2, 3 }, .highest_accepted = &.{ 0, 0, 9 } });

    const io = std.testing.io;
    const file = std.Io.Dir.cwd().readFileAlloc(io, "tools/truth/consensus-net/vectors/proto.txt", gpa, .limited(1 << 20)) catch return;
    defer gpa.free(file);
    var lines = std.mem.splitScalar(u8, file, '\n');
    var checked: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const sp = std.mem.indexOfScalar(u8, line, ' ') orelse return error.BadVectorFile;
        for (table.items) |e| if (std.mem.eql(u8, e[0], line[0..sp])) {
            try std.testing.expectEqualStrings(line[sp + 1 ..], e[1]);
            checked += 1;
        };
    }
    try std.testing.expectEqual(table.items.len, checked);
}
