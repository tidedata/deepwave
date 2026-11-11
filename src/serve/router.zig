//! The :9000 router: what sui-node 1.83.1 serves besides the sui.rpc services themselves.
//! - which paths exist (a path outside every service answers HTTP 404, as sui-node's axum
//!   router does; an unknown method of a known service answers UNIMPLEMENTED);
//! - which responses are compressed (`send_compressed` on every sui.rpc service except
//!   SubscriptionService; health and reflection never);
//! - grpc.health.v1.Health and grpc.reflection v1/v1alpha (reflection.zig);
//! - the x-sui-* response metadata (cached per highest committed checkpoint);
//! - `GET /health[?threshold_seconds=N]`.
const std = @import("std");
const h2 = @import("h2/root.zig");
const service = @import("service.zig");
const reflection = @import("reflection.zig");
const render_checkpoint = @import("render_checkpoint.zig");
const b58 = @import("b58.zig");

pub fn handler(svc: *service.Service) h2.Handler {
    return .{ .ctx = svc, .call = call, .known = known, .compress = compress, .info = info, .health = health, .bidi = bidi, .method = method };
}

fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
    const svc: *service.Service = @ptrCast(@alignCast(ctx));
    const p = req.path;
    if (std.mem.startsWith(u8, p, reflection.health_path)) return reflection.healthCall(req, rs);
    if (std.mem.startsWith(u8, p, reflection.v1_path)) return reflection.call(svc.gpa, .v1, req, rs);
    if (std.mem.startsWith(u8, p, reflection.v1alpha_path)) return reflection.call(svc.gpa, .v1alpha, req, rs);
    return service.call(ctx, req, rs);
}

/// `/pkg.Service/Method` -> `pkg.Service` (empty when the path has no such shape).
pub fn serviceOf(path: []const u8) []const u8 {
    if (path.len < 2 or path[0] != '/') return "";
    const e = std.mem.indexOfScalarPos(u8, path, 1, '/') orelse return "";
    return path[1..e];
}

pub fn known(_: *anyopaque, path: []const u8) bool {
    const s = serviceOf(path);
    if (s.len == 0) return false;
    if (std.mem.eql(u8, s, "grpc.reflection.v1alpha.ServerReflection")) return true;
    const names = reflection.serviceNames(.v1) catch return false;
    for (names) |n| if (std.mem.eql(u8, n, s)) return true;
    return false;
}

pub fn method(_: *anyopaque, path: []const u8) bool {
    return reflection.methodExists(path);
}

pub fn compress(_: *anyopaque, path: []const u8) bool {
    if (std.mem.startsWith(u8, path, "/sui.rpc.v2.SubscriptionService/")) return false;
    return std.mem.startsWith(u8, path, "/sui.rpc.v2.") or std.mem.startsWith(u8, path, "/sui.rpc.v2alpha.");
}

pub fn bidi(_: *anyopaque, path: []const u8) bool {
    return std.mem.eql(u8, path, reflection.v1_path ++ "ServerReflectionInfo") or
        std.mem.eql(u8, path, reflection.v1alpha_path ++ "ServerReflectionInfo");
}

/// x-sui-* values for the current tip, recomputed only when the highest committed checkpoint
/// moves (one summary parse per checkpoint, not per request). Read on every response, so it
/// takes no lock (lane serve-tail): a seqlock over atomics. The spin lock it had was taken twice
/// per request by every worker; a holder descheduled on a loaded box made each other request
/// spin for the rest of a time slice.
pub const InfoCache = struct {
    const Atomic = std.atomic.Value;
    const none = std.math.maxInt(u64);
    /// Odd while a writer updates the fields below.
    ver: Atomic(u64) = .init(0),
    /// Writers only (a busy writer lock means another request is storing the same tip).
    wlock: Atomic(u32) = .init(0),
    seq: Atomic(u64) = .init(none),
    epoch: Atomic(u64) = .init(0),
    height: Atomic(u64) = .init(0),
    timestamp_ms: Atomic(u64) = .init(0),
    chain_b58: [b58.max_len_32]u8 = undefined,
    chain_len: Atomic(usize) = .init(0),

    fn read(c: *const InfoCache) ?struct { seq: u64, tip: h2.meta.Tip } {
        while (true) {
            const v1 = c.ver.load(.acquire);
            if (v1 & 1 != 0) {
                std.atomic.spinLoopHint();
                continue;
            }
            const seq = c.seq.load(.acquire);
            const tip: h2.meta.Tip = .{ .epoch = c.epoch.load(.acquire), .height = c.height.load(.acquire), .timestamp_ms = c.timestamp_ms.load(.acquire) };
            if (c.ver.load(.acquire) != v1) continue;
            if (seq == none) return null;
            return .{ .seq = seq, .tip = tip };
        }
    }

    fn store(c: *InfoCache, seq: u64, tip: h2.meta.Tip) void {
        if (c.wlock.cmpxchgStrong(0, 1, .acquire, .monotonic) != null) return;
        defer c.wlock.store(0, .release);
        const cur = c.seq.load(.acquire);
        if (cur != none and cur >= seq) return;
        _ = c.ver.fetchAdd(1, .acq_rel);
        c.seq.store(seq, .release);
        c.epoch.store(tip.epoch, .release);
        c.height.store(tip.height, .release);
        c.timestamp_ms.store(tip.timestamp_ms, .release);
        _ = c.ver.fetchAdd(1, .acq_rel);
    }

    fn chainId(c: *InfoCache, id: *const [32]u8) []const u8 {
        const n = c.chain_len.load(.acquire);
        if (n != 0) return c.chain_b58[0..n];
        while (c.wlock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.Thread.yield() catch {};
        defer c.wlock.store(0, .release);
        if (c.chain_len.load(.acquire) == 0) c.chain_len.store(b58.encode32(&c.chain_b58, id).len, .release);
        return c.chain_b58[0..c.chain_len.load(.acquire)];
    }
};

fn currentTip(svc: *service.Service) ?h2.meta.Tip {
    const c = &svc.info_cache;
    // the index-bounded tip (service.latestOf): what GetServiceInfo and GetCheckpoint serve
    const hi = service.boundByIndex(svc, svc.store.committed() orelse return null) orelse return null;
    if (c.read()) |r| if (r.seq == hi) return r.tip;
    var snap = svc.store.snapshot();
    defer snap.release();
    const seq = service.latestOf(svc, &snap) orelse return null;
    const rec = snap.checkpoint(seq) orelse return null;
    var arena_state = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena_state.deinit();
    const cert = render_checkpoint.Cert.parse(arena_state.allocator(), rec.summary_cert) catch return null;
    const tip: h2.meta.Tip = .{ .epoch = cert.summary.epoch, .height = cert.summary.sequence_number, .timestamp_ms = cert.summary.timestamp_ms };
    c.store(seq, tip);
    return tip;
}

fn info(ctx: *anyopaque, out: *h2.meta.Info) void {
    const svc: *service.Service = @ptrCast(@alignCast(ctx));
    out.chain_id = svc.info_cache.chainId(&svc.chain_id);
    out.chain = svc.chain_name;
    out.tip = currentTip(svc);
    out.lowest = if (out.tip != null) service.reportedLowest(svc) else null;
    out.server = svc.server_header;
}

/// sui-rpc-api `health`: up once the node has a checkpoint, and, with `threshold_seconds`,
/// only while the newest checkpoint (the index-bounded tip) is at most that old; with the
/// live-object index on, also only while that index trails the store's tip by at most 60
/// checkpoints (`service.indexCaughtUp`, health.rs `MAX_HEALTHY_INDEX_LAG`).
fn health(ctx: *anyopaque, threshold_s: ?u32) bool {
    const svc: *service.Service = @ptrCast(@alignCast(ctx));
    const tip = currentTip(svc) orelse return false;
    if (threshold_s) |t| {
        const now_ms = h2.meta.unixS() * 1000;
        if (now_ms -| tip.timestamp_ms > @as(u64, t) * 1000) return false;
    }
    return service.indexCaughtUp(svc, svc.store.committed() orelse return false);
}

test "router paths" {
    var dummy: u8 = 0;
    try std.testing.expect(known(&dummy, "/sui.rpc.v2.LedgerService/GetCheckpoint"));
    try std.testing.expect(known(&dummy, "/sui.rpc.v2.LedgerService/Nope"));
    try std.testing.expect(known(&dummy, "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"));
    try std.testing.expect(known(&dummy, "/grpc.health.v1.Health/Check"));
    try std.testing.expect(!known(&dummy, "/foo.Bar/Baz"));
    try std.testing.expect(!known(&dummy, "/health"));
    try std.testing.expect(compress(&dummy, "/sui.rpc.v2.LedgerService/GetCheckpoint"));
    try std.testing.expect(compress(&dummy, "/sui.rpc.v2alpha.ProofService/GetCheckpointObjectProof"));
    try std.testing.expect(!compress(&dummy, "/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints"));
    try std.testing.expect(!compress(&dummy, "/grpc.health.v1.Health/Check"));
}
