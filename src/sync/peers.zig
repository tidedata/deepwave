//! Peer source (anemo state-sync): header sync. Peers serve certified checkpoint summaries and
//! contents, not output objects or events (sui-node's state sync hands transactions and effects
//! to the checkpoint executor, which re-executes). Without exec this source therefore verifies and
//! records the checkpoint chain only: every summary's BLS certificate against the epoch's
//! committee, the previous-digest link, the epoch rule and the committee hand-over at epoch ends.
//! Output objects (the apply mode's input) come from the archive source.
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const hash = @import("hash");
const types = @import("types");
const net = @import("net");
const store_mod = @import("store");
const verify = @import("verify.zig");
const follower = @import("follower.zig");
const Committee = @import("committee.zig").Committee;
const ss = net.state_sync;
const anemo = net.anemo;

pub const Result = struct {
    first: u64,
    last: u64,
    highest_synced: u64,
    lowest_available: u64,
    epoch: u64,
    requests: u64,
    ns: u64,
};

pub const Error = error{ PeerStatus, Missing, BadCheckpoint } || net.anemo.Error || ss.DecodeError || std.mem.Allocator.Error || store_mod.Error || Committee.Error;

/// Fetches `count` consecutive summaries starting at `anchor.first_seq` from `addr` and verifies
/// them. Stores a checkpoint record (certified summary, no contents) per checkpoint when `st` is given.
pub fn syncHeaders(gpa: std.mem.Allocator, io: Io, st: ?*store_mod.Store, addr: Io.net.IpAddress, anchor: follower.Anchor, count: u64) Error!Result {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const t0 = follower.now();
    const p = try anemo.Peer.connect(gpa, io, addr, .{ .server_name = ss.mainnet_server_name, .handshake_timeout_ms = 10_000 });
    defer p.deinit();
    const timeout_hdr = [_]net.wire.Header{.{ .name = "timeout", .value = "10000000000" }};

    const av = try p.request(a, ss.Route.get_checkpoint_availability, &timeout_hdr, ss.encodeUnitRequest(), 10_000);
    if (av.status != .success) return error.PeerStatus;
    const avail = try ss.splitAvailability(try ss.decodeBody(a, av.body));
    const highest = std.mem.readInt(u64, avail.highest_synced_summary[8..16], .little);

    var committee = anchor.committee;
    var prev = anchor.prev_digest;
    var prev_eoe = anchor.prev_was_eoe;
    var epoch = anchor.committee.epoch;
    var carena = std.heap.ArenaAllocator.init(gpa);
    defer carena.deinit();
    var requests: u64 = 2;
    var seq = anchor.first_seq;
    const end = anchor.first_seq + count;
    while (seq < end) : (seq += 1) {
        _ = arena_state.reset(.retain_capacity);
        const req = try ss.encodeSummaryRequest(a, .{ .seq = seq });
        const r = try p.request(a, ss.Route.get_checkpoint_summary, &timeout_hdr, req, 10_000);
        requests += 1;
        if (r.status != .success) return error.PeerStatus;
        const payload = (try ss.optionPayload(try ss.decodeBody(a, r.body))) orelse return error.Missing;
        // CertifiedCheckpointSummary = summary ++ AuthorityQuorumSignInfo
        var rd = bcs.Reader.init(payload);
        bcs.skip(types.gen.CheckpointSummary, &rd) catch return error.BadCheckpoint;
        const summary_bytes = payload[0..rd.at];
        const sig_bytes = payload[rd.at..];
        const summary = bcs.decode(types.CheckpointSummary, a, summary_bytes) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.BadCheckpoint;
        if (summary.sequence_number != seq) return error.BadCheckpoint;
        if (summary.epoch != epoch) {
            if (!(summary.epoch == epoch + 1 and prev_eoe)) return error.BadCheckpoint;
            epoch = summary.epoch;
        }
        const digest = hash.blake2b256(&.{ "CheckpointSummary::", summary_bytes });
        if (prev) |pd| {
            if (summary.previous_digest == null or !std.mem.eql(u8, &summary.previous_digest.?.@"0".@"0", &pd)) return error.BadCheckpoint;
        }
        if (!(try verify.checkCert(a, &committee, summary.epoch, summary_bytes, sig_bytes)).isOk()) return error.BadCheckpoint;
        if (st) |s| {
            const b = try s.begin(seq, summary.epoch);
            errdefer s.abort(b);
            try b.checkpoint(payload, &.{});
            try s.commit(b);
        }
        if (summary.end_of_epoch_data) |eoe| {
            committee = try Committee.fromEndOfEpoch(carena.allocator(), epoch + 1, eoe);
            prev_eoe = true;
        } else prev_eoe = false;
        prev = digest;
    }
    return .{ .first = anchor.first_seq, .last = end - 1, .highest_synced = highest, .lowest_available = avail.lowest_available_checkpoint, .epoch = epoch, .requests = requests, .ns = follower.now() - t0 };
}

test "live header sync against our own node (ZUI_SYNC_LIVE=host:port, ZUI_CORPUS)" {
    const envutil = net.envutil;
    const text = envutil.get("ZUI_SYNC_LIVE") orelse return error.SkipZigTest;
    const corpus = envutil.get("ZUI_CORPUS") orelse return error.SkipZigTest;
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.SkipZigTest;
    const port = try std.fmt.parseInt(u16, text[colon + 1 ..], 10);
    const addr = try Io.net.IpAddress.parse(text[0..colon], port);
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // Probe the peer's latest, then follow the 64 checkpoints before it under the committee from the vectors.
    const probe = try net.live.probe(gpa, io, addr, null);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const first = probe.latest_seq - 64;
    var pb: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&pb, "{s}/vectors/bls-cert/{d}.jsonl", .{ corpus, probe.highest_epoch });
    const vec = Io.Dir.cwd().readFileAlloc(io, path, a, .limited(1 << 26)) catch return error.SkipZigTest;
    const nl = std.mem.indexOfScalar(u8, vec, '\n') orelse vec.len;
    const comm = try @import("committee.zig").fromJsonLine(a, vec[0..nl]);
    const res = try syncHeaders(gpa, io, null, addr, .{ .committee = comm, .first_seq = first }, 64);
    std.debug.print("\nlive header sync: {d} checkpoints {d}..{d} verified in {d} ms ({d} requests), peer highest {d}\n", .{ 64, res.first, res.last, res.ns / 1_000_000, res.requests, res.highest_synced });
}

