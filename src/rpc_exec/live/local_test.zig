//! The store-backed local path renders byte-equal to sui-node.
//!
//! Vectors (testdata/local_vectors.bin): testnet ExecuteTransaction requests and the Mysten
//! fullnode's responses (`deepwave-execute compare --keep N`), each `u32 le len ++ request ++ u32 le
//! len ++ response ++ u32 le len ++ objects`, objects being the input and output objects the
//! effects name (`u32 le len ++ Object BCS` each, read from the fullnode at their versions). The test writes the response's transaction, effects, events and objects into
//! a simulated store, answers the same request through `LiveExecutor` with only `StoreLocal`
//! (no committee: a miss would fail), and compares the bytes.
const std = @import("std");
const store = @import("store");
const serve = @import("serve");
const types = @import("types");
const bcs = @import("bcs");
const proto = serve.proto;
const validators = @import("validators.zig");
const local = @import("local.zig");
const handler = @import("../driver/handler.zig");

const vectors = @embedFile("testdata/local_vectors.bin");

fn field(msg: []const u8, number: u32) ?[]const u8 {
    var r = proto.Reader.init(msg);
    while (r.next() catch return null) |f| if (f.number == number) return proto.Reader.bytesOf(f) catch null;
    return null;
}

fn smallCfg() store.Config {
    return .{
        .max_live_objects = 1024,
        .max_object_versions = 4096,
        .max_transactions = 1024,
        .max_checkpoints = 1024,
        .max_batch_bytes = 4 << 20,
        .max_batch_objects = 256,
        .max_segments = 64,
        .index_flush_interval = 8,
        .segment_reserve = 8 << 20,
        .seed = 99,
    };
}

test "store-backed local effects render as sui-node's ExecuteTransaction" {
    const gpa = std.testing.allocator;
    if (vectors.len == 0) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const sim = try store.SimIo.init(gpa, 7, .{}, 64 << 20);
    defer sim.deinit();
    const cfg = smallCfg();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();

    // load every vector into one checkpoint
    const Vec = struct { req: []const u8, resp: []const u8, objs: []const u8 };
    var vecs: std.ArrayList(Vec) = .empty;
    var p: usize = 0;
    while (p + 4 <= vectors.len) {
        const lr = std.mem.readInt(u32, vectors[p..][0..4], .little);
        const req = vectors[p + 4 ..][0..lr];
        p += 4 + lr;
        const lu = std.mem.readInt(u32, vectors[p..][0..4], .little);
        const resp = vectors[p + 4 ..][0..lu];
        p += 4 + lu;
        const lo = std.mem.readInt(u32, vectors[p..][0..4], .little);
        const objs = vectors[p + 4 ..][0..lo];
        p += 4 + lo;
        try vecs.append(arena, .{ .req = req, .resp = resp, .objs = objs });
    }
    const Key = struct { id: [32]u8, version: u64 };
    var seen: std.ArrayList(Key) = .empty;
    const b = try st.begin(1, 1);
    try b.checkpoint("summary", "contents");
    for (vecs.items) |v| {
        const t = field(v.resp, 1).?;
        const effects = field(field(field(t, 4).?, 1).?, 2).?;
        const events: ?[]const u8 = if (field(t, 5)) |ev| field(field(ev, 1).?, 2).? else null;
        const tx_bcs = field(field(field(v.req, 1).?, 1).?, 2).?;
        const eff = try bcs.decode(types.TransactionEffects, arena, effects);
        const digest = switch (eff) {
            inline else => |e| e.transaction_digest.@"0".@"0",
        };
        const ed = types.digest.effectsDigest(effects);
        try b.transaction(&digest, &ed, tx_bcs, effects, events);
        var q: usize = 0;
        while (q + 4 <= v.objs.len) {
            const ln = std.mem.readInt(u32, v.objs[q..][0..4], .little);
            const raw = v.objs[q + 4 ..][0..ln];
            q += 4 + ln;
            {
                const obj = try bcs.decode(types.Object, arena, raw);
                const id: [32]u8, const version: u64 = switch (obj.data) {
                    .Move => |mo| .{ mo.contents[0..32].*, mo.version.@"0" },
                    .Package => |pk| .{ pk.id.@"0".@"0", pk.version.@"0" },
                };
                const dup = for (seen.items) |k| {
                    if (k.version == version and std.mem.eql(u8, &k.id, &id)) break true;
                } else false;
                if (!dup) {
                    try seen.append(arena, .{ .id = id, .version = version });
                    const od = types.digest.digestOf("Object", raw);
                    try b.putObject(&id, version, &od, raw);
                }
            }
        }
    }
    try st.commit(b);

    var ex = validators.LiveExecutor.init(gpa, std.testing.io);
    defer ex.deinit();
    var sl: local.StoreLocal = .{ .st = st };
    ex.local = sl.localEffects();
    ex.background_retry = false;
    for (vecs.items, 0..) |v, i| {
        const r = try handler.executeTransaction(arena, ex.executor(), v.req);
        switch (r) {
            .ok => |bytes| std.testing.expectEqualSlices(u8, v.resp, bytes) catch |e| {
                std.debug.print("vector {d} differs\n", .{i});
                return e;
            },
            .err => |e| {
                std.debug.print("vector {d}: {d} {s}\n", .{ i, e.code, e.message });
                return error.TestUnexpectedResult;
            },
        }
    }
    try std.testing.expectEqual(@as(u64, vecs.items.len), ex.counters.local_answers.load(.monotonic));
}
