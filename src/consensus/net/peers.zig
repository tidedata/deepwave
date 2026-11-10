//! The client side of ConsensusService (`TonicValidatorClient` at mainnet-v1.83.1): one
//! channel per committee peer (TLS pinned to the peer's network key, our network key as client
//! certificate) and the typed calls with Rust's response-size accounting. Owner lane:
//! val-consensus-net.
const std = @import("std");
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const types = consensus.types;
const grpc = @import("grpc.zig");
const proto = @import("proto.zig");
const tls = @import("tls.zig");
const bc = @import("broadcast.zig");
const addr = @import("addr.zig");

pub const Error = error{ Unavailable, Timeout, PeerRefused, Malformed, OutOfMemory, NoSuchPeer };

pub const Peers = struct {
    gpa: Allocator,
    context: *const consensus.Context,
    identity: tls.Identity,
    server_name: []u8,
    channels: []?*grpc.Channel,

    /// Channels connect lazily on first use. `network_key_seed` is our TLS key (never the
    /// protocol key). `allowed` limits whom we dial: only committee addresses are ever used.
    pub fn init(gpa: Allocator, io: std.Io, context: *const consensus.Context, network_key_seed: *const [32]u8, cfg: grpc.Config) !*Peers {
        const p = try gpa.create(Peers);
        errdefer gpa.destroy(p);
        var name_buf: [48]u8 = undefined;
        const name = try tls.serverName(&name_buf, context.committee.epoch);
        p.* = .{
            .gpa = gpa,
            .context = context,
            .identity = try tls.Identity.init(network_key_seed, name),
            .server_name = try gpa.dupe(u8, name),
            .channels = try gpa.alloc(?*grpc.Channel, context.committee.size()),
        };
        @memset(p.channels, null);
        errdefer p.deinit();
        for (context.committee.authorities, 0..) |a, i| {
            if (context.own_index != null and context.own_index.? == i) continue;
            const hp = addr.parse(a.address) catch return error.BadMultiaddr;
            p.channels[i] = try grpc.Channel.create(gpa, io, cfg, .{ .host = hp.host, .port = hp.port }, p.server_name, &p.identity, &a.network_key);
        }
        return p;
    }

    pub fn deinit(p: *Peers) void {
        for (p.channels) |c| if (c) |ch| ch.destroy();
        p.gpa.free(p.channels);
        p.gpa.free(p.server_name);
        std.crypto.secureZero(u8, std.mem.asBytes(&p.identity.key));
        p.gpa.destroy(p);
    }

    pub fn close(p: *Peers) void {
        for (p.channels) |c| if (c) |ch| ch.close();
    }

    fn channel(p: *Peers, peer: types.AuthorityIndex) Error!*grpc.Channel {
        if (peer >= p.channels.len) return error.NoSuchPeer;
        return p.channels[peer] orelse error.NoSuchPeer;
    }

    fn mapErr(e: grpc.Error) Error {
        return switch (e) {
            error.DeadlineExceeded => error.Timeout,
            error.Status => error.PeerRefused,
            error.Malformed, error.ResourceExhausted => error.Malformed,
            error.OutOfMemory => error.OutOfMemory,
            else => error.Unavailable,
        };
    }

    /// Opens a SubscribeBlocks stream and sends the first request (`last_received_round`). The
    /// request stream stays open (Rust: the request is a stream that yields once and then waits).
    pub fn subscribe(p: *Peers, peer: types.AuthorityIndex, last_received: types.Round) Error!*grpc.Stream {
        const ch = try p.channel(peer);
        const st = ch.startCall(.SubscribeBlocks, 0) catch |e| return mapErr(e);
        errdefer st.release();
        var buf: [16]u8 = undefined;
        const req = proto.encode(proto.SubscribeBlocksRequest, p.gpa, &.{ .last_received_round = last_received }) catch return error.OutOfMemory;
        defer p.gpa.free(req);
        _ = &buf;
        st.send(req) catch |e| {
            st.cancel();
            return mapErr(e);
        };
        return st;
    }

    /// `fetch_blocks`: serialized blocks, stopping at Rust's response byte limit.
    pub fn fetchBlocks(p: *Peers, arena: Allocator, peer: types.AuthorityIndex, refs: []const types.BlockRef, fetch_after_rounds: []const types.Round, fetch_missing_ancestors: bool, timeout_ns: u64) Error![]const []const u8 {
        const ch = try p.channel(peer);
        const ctx = p.context;
        const max_blocks: usize = if (fetch_after_rounds.len != 0 and refs.len != 0) ctx.parameters.max_blocks_per_sync else ctx.parameters.max_blocks_per_fetch;
        const max_bytes = max_blocks *| @as(usize, @intCast(ctx.protocol_config.max_transactions_in_block_bytes)) *| 2;
        const raw = arena.alloc([]const u8, refs.len) catch return error.OutOfMemory;
        for (refs, 0..) |r, i| raw[i] = arena.dupe(u8, &bc.encodeRef(r)) catch return error.OutOfMemory;
        const req = proto.encode(proto.FetchBlocksRequest, arena, &.{ .block_refs = raw, .fetch_after_rounds = fetch_after_rounds, .fetch_missing_ancestors = fetch_missing_ancestors }) catch return error.OutOfMemory;
        return p.collect(arena, ch, .FetchBlocks, req, timeout_ns, max_bytes);
    }

    /// `fetch_latest_blocks`.
    pub fn fetchLatestBlocks(p: *Peers, arena: Allocator, peer: types.AuthorityIndex, authorities: []const u32, timeout_ns: u64) Error![]const []const u8 {
        const ch = try p.channel(peer);
        const max_bytes = authorities.len *| @as(usize, @intCast(p.context.protocol_config.max_transactions_in_block_bytes)) *| 2;
        const req = proto.encode(proto.FetchLatestBlocksRequest, arena, &.{ .authorities = authorities }) catch return error.OutOfMemory;
        return p.collect(arena, ch, .FetchLatestBlocks, req, timeout_ns, max_bytes);
    }

    /// Reads a server-streamed list of blocks; both streaming responses share the wire shape
    /// (repeated bytes at tag 1). A mid-stream failure after some blocks keeps what arrived.
    fn collect(p: *Peers, arena: Allocator, ch: *grpc.Channel, method: proto.Method, req: []const u8, timeout_ns: u64, max_bytes: usize) Error![]const []const u8 {
        _ = p;
        const st = ch.startCall(method, timeout_ns) catch |e| return mapErr(e);
        defer st.release();
        st.send(req) catch |e| {
            st.cancel();
            return mapErr(e);
        };
        st.closeSend() catch |e| {
            st.cancel();
            return mapErr(e);
        };
        var out: std.ArrayList([]const u8) = .empty;
        var total: usize = 0;
        while (true) {
            const m = st.recv(arena, 0) catch |e| {
                if (out.items.len == 0) {
                    st.cancel();
                    return mapErr(e);
                }
                break;
            };
            const msg = m orelse break;
            const resp = proto.decode(proto.FetchBlocksResponse, arena, msg) catch return error.Malformed;
            for (resp.blocks) |b| {
                total += b.len;
                out.append(arena, b) catch return error.OutOfMemory;
            }
            if (total > max_bytes) {
                st.cancel();
                break;
            }
        }
        return out.items;
    }

    pub const Commits = struct { commits: []const []const u8, certifier_blocks: []const []const u8 };

    /// `fetch_commits`: `range` is inclusive on the wire request (start, end).
    pub fn fetchCommits(p: *Peers, arena: Allocator, peer: types.AuthorityIndex, start: types.CommitIndex, end_inclusive: types.CommitIndex, timeout_ns: u64) Error!Commits {
        const ch = try p.channel(peer);
        const req = proto.encode(proto.FetchCommitsRequest, arena, &.{ .start = start, .end = end_inclusive }) catch return error.OutOfMemory;
        const resp = ch.unary(arena, .FetchCommits, req, timeout_ns) catch |e| return mapErr(e);
        const r = proto.decode(proto.FetchCommitsResponse, arena, resp) catch return error.Malformed;
        return .{ .commits = r.commits, .certifier_blocks = r.certifier_blocks };
    }

    pub const Rounds = struct { received: []const u32, accepted: []const u32 };

    pub fn getLatestRounds(p: *Peers, arena: Allocator, peer: types.AuthorityIndex, timeout_ns: u64) Error!Rounds {
        const ch = try p.channel(peer);
        const resp = ch.unary(arena, .GetLatestRounds, "", timeout_ns) catch |e| return mapErr(e);
        const r = proto.decode(proto.GetLatestRoundsResponse, arena, resp) catch return error.Malformed;
        return .{ .received = r.highest_received, .accepted = r.highest_accepted };
    }

    /// `probe_connectivity` (commit syncer): a GetLatestRounds round trip.
    pub fn probe(p: *Peers, arena: Allocator, peer: types.AuthorityIndex, timeout_ns: u64) Error!void {
        _ = try p.getLatestRounds(arena, peer, timeout_ns);
    }
};
