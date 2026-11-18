//! `sui.Randomness/SendSignatures` over anemo, as sui-network 1.83.1 (`randomness/{mod,server,
//! builder,auth}.rs`): a validator sends its partial signatures for a round to every other
//! committee member and resends them every `partial_signature_retry_interval` until the round is
//! completed (its RandomnessStateUpdate is in a checkpoint); once the round is aggregated the
//! full signature is sent instead. The protocol state machine is randomness/signatures.zig
//! (`Collector`); this file is its transport.
//!
//! Wire (byte-identical to sui-node):
//! - route `/sui.Randomness/SendSignatures`, request `SendSignaturesRequest { epoch: u64, round:
//!   u64, partial_sigs: Vec<Vec<u8>>, sig: Option<G1> }`, response `()`, codec
//!   `mysten_network::codec::anemo::BcsSnappyCodec` (BCS, snappy frame format), headers
//!   `content-type: bcs` both ways and `timeout` (10 s, `SEND_PARTIAL_SIGNATURES_TIMEOUT`).
//! - anemo server name `sui-<first 4 bytes of the chain id, hex>`, PeerId = the Ed25519 network
//!   key.
//! - server layers: `RequireAuthorizationLayer(AllowedPeersUpdatable)` outside (a peer not in
//!   the committee, or ignored as byzantine this epoch, or any peer before the first epoch is
//!   installed: 404), `InflightLimitLayer(20, ReturnError)` inside (429), a body that does not
//!   decode: 520 (`Status::from_error`), else 200 with an empty body; the handler never fails
//!   (the Rust server drops what its event loop refuses).
//!
//! Transport: the validator's one anemo endpoint (run/p2p.zig), shared with state sync and
//! discovery as sui-node mounts Randomness on its p2p network: the route is a service of that
//! endpoint, and sends go on its one connection per peer pair.
//!
//! Threads: the endpoint's (listener workers call `serve`), one sender per peer, and one that
//! hands full signatures to the sink outside the lock. `setEpoch`, `sendPartials` and
//! `completeRound` may be called from any thread.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const Ed25519 = std.crypto.sign.Ed25519;
const net = @import("net");
const anemo = net.anemo;
const wire = net.wire;
const snappy = net.snappy;
const randomness = @import("../randomness/root.zig");
const signatures = randomness.signatures;
const nodes_mod = randomness.nodes;
const p2p_mod = @import("p2p.zig");

const log = std.log.scoped(.randomness_net);

pub const route = "/sui.Randomness/SendSignatures";
/// `SEND_PARTIAL_SIGNATURES_TIMEOUT`.
pub const send_timeout_ms: u64 = 10_000;
/// `RandomnessConfig::send_partial_signatures_inflight_limit` default.
pub const inflight_limit: u32 = 20;
/// `RandomnessConfig::partial_signature_retry_interval` default.
pub const default_retry_interval_ms: u64 = 5_000;
/// A decompressed request above this is refused (4096 partials of 100 bytes is 400 KiB).
const max_request_bytes: usize = 4 << 20;

const content_type = wire.Header{ .name = "content-type", .value = "bcs" };
const request_headers = [_]wire.Header{ content_type, .{ .name = wire.timeout_header, .value = "10000000000" } };
const success_headers = [_]wire.Header{content_type};

pub const Peer = struct {
    /// Authority index in the committee (= DKG party id, = the peer's index on the endpoint).
    index: u16,
    /// Protocol (BLS) public key, the AuthorityName.
    name: [96]u8,
    /// Ed25519 network public key = anemo PeerId.
    network_pubkey: [32]u8,
    /// `host:port` or a multiaddr `/ip4/A/udp/P` (net/peer_addr.zig).
    p2p_address: []const u8,
};

pub const Options = struct {
    /// The seat's anemo endpoint; its peer `i` is committee member `i`.
    p2p: *p2p_mod.P2p,
    /// The committee, this validator included (it is not sent to).
    peers: []const Peer,
    own_index: u16,
    retry_interval_ms: u64 = default_retry_interval_ms,
};

pub const FullSigSink = struct {
    ctx: *anyopaque,
    /// A round's aggregated signature (48 bytes, G1 compressed): the round's random bytes.
    f: *const fn (ctx: *anyopaque, epoch: u64, round: u64, sig: []const u8) void,
};

pub const Error = error{CommitteeMismatch} || signatures.Error || Allocator.Error;

pub const Stats = struct {
    sent_ok: Atomic(u64) = .init(0),
    sent_failed: Atomic(u64) = .init(0),
    received: Atomic(u64) = .init(0),
    refused: Atomic(u64) = .init(0),
};

const TaskKey = struct { epoch: u64, round: u64 };
const Full = struct { epoch: u64, round: u64, sig: [48]u8 };

pub const RandomnessNet = struct {
    gpa: Allocator,
    io: Io,
    opts: Options,
    sink: FullSigSink,
    stats: Stats = .{},
    stop_flag: Atomic(bool) = .init(false),
    inflight: Atomic(u32) = .init(0),

    // under mu
    mu: Io.Mutex = .init,
    cv: Io.Condition = .init, // peer senders: rounds changed
    sink_cv: Io.Condition = .init,
    collector: signatures.Collector,
    /// The allowed-peer set is installed (Rust: empty until the first `update_epoch`).
    have_epoch: bool = false,
    /// Rounds being sent: the snappy-framed request in its current form (partials, then full).
    tasks: std.AutoArrayHashMapUnmanaged(TaskKey, []u8) = .empty,
    sink_q: std.ArrayList(Full) = .empty,
    /// Aggregated signatures of the current epoch's rounds, completed ones included (zui-only:
    /// a restarted validator asking for a completed round gets it back, see `serve`).
    fulls: std.AutoHashMapUnmanaged(u64, [48]u8) = .empty,
    fulls_epoch: u64 = 0,
    /// The previous epoch's full signatures (zui-only catch-up across an epoch change: a peer
    /// restarted late in an epoch has no checkpoint sync, so the rounds of the epoch's final
    /// checkpoints are answered from here after everyone else moved on).
    prev_fulls: std.AutoHashMapUnmanaged(u64, [48]u8) = .empty,
    prev_fulls_epoch: ?u64 = null,

    workers: []Worker = &.{},
    sink_thread: ?std.Thread = null,

    pub fn start(gpa: Allocator, io: Io, opts: Options, sink: FullSigSink) !*RandomnessNet {
        const self = try gpa.create(RandomnessNet);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .opts = opts,
            .sink = sink,
            .collector = signatures.Collector.init(gpa, .{ .partial_signature_retry_interval_ms = opts.retry_interval_ms }, io),
        };
        errdefer self.collector.deinit();
        // own copy of the committee
        const peers = try gpa.alloc(Peer, opts.peers.len);
        var copied: usize = 0;
        errdefer {
            for (peers[0..copied]) |p| gpa.free(p.p2p_address);
            gpa.free(peers);
        }
        for (opts.peers, peers) |p, *d| {
            d.* = p;
            d.p2p_address = try gpa.dupe(u8, p.p2p_address);
            copied += 1;
        }
        self.opts.peers = peers;
        for (peers) |p| {
            if (p.index >= opts.p2p.peerCount() or !std.mem.eql(u8, opts.p2p.peerId(p.index), &p.network_pubkey)) return error.CommitteeMismatch;
        }

        var n_workers: usize = 0;
        for (peers) |p| {
            if (p.index != opts.own_index) n_workers += 1;
        }
        self.workers = try gpa.alloc(Worker, n_workers);
        errdefer gpa.free(self.workers);
        var wi: usize = 0;
        for (peers) |*p| {
            if (p.index == opts.own_index) continue;
            self.workers[wi] = .{ .owner = self, .peer = p };
            wi += 1;
        }

        var started: usize = 0;
        errdefer {
            self.stop_flag.store(true, .release);
            self.wakeAll();
            for (self.workers[0..started]) |*w| {
                w.thread.join();
                w.due.deinit(gpa);
                w.oneshot.deinit(gpa);
            }
        }
        for (self.workers) |*w| {
            w.thread = try std.Thread.spawn(.{ .stack_size = 4 << 20 }, Worker.loop, .{w});
            started += 1;
        }
        self.sink_thread = try std.Thread.spawn(.{ .stack_size = 1 << 20 }, sinkLoop, .{self});
        opts.p2p.setService(.randomness, self.handler());
        return self;
    }

    pub fn stop(self: *RandomnessNet) void {
        const gpa = self.gpa;
        // requests in flight on the endpoint's workers finish under the lock before the state goes
        self.opts.p2p.clearService(.randomness);
        self.stop_flag.store(true, .release);
        self.wakeAll();
        for (self.workers) |*w| {
            w.thread.join();
            w.deinit();
        }
        if (self.sink_thread) |t| t.join();
        gpa.free(self.workers);
        self.clearTasks();
        self.tasks.deinit(gpa);
        self.sink_q.deinit(gpa);
        self.fulls.deinit(gpa);
        self.prev_fulls.deinit(gpa);
        self.collector.deinit();
        for (self.opts.peers) |p| gpa.free(p.p2p_address);
        gpa.free(self.opts.peers);
        gpa.destroy(self);
    }

    /// `RandomnessEventLoop::update_epoch` with the epoch's DKG output (the authority info is
    /// `opts.peers`; the recovered highest completed round is the manager's). When the DKG
    /// failed or is not finished there are no rounds this epoch: sends of earlier epochs stop
    /// and nothing else changes (Rust never calls update_epoch then).
    pub fn setEpoch(self: *RandomnessNet, epoch: u64, mgr: *randomness.Manager) !void {
        self.lock();
        defer self.unlock();
        defer self.cv.broadcast(self.io);
        if (self.have_epoch and epoch <= self.collector.epoch) return; // Rust asserts epoch moves forward
        self.clearTasks();
        if (self.fulls.count() != 0 and self.fulls_epoch < epoch) {
            std.mem.swap(std.AutoHashMapUnmanaged(u64, [48]u8), &self.prev_fulls, &self.fulls);
            self.prev_fulls_epoch = self.fulls_epoch;
        }
        self.fulls.clearRetainingCapacity();
        self.fulls_epoch = epoch;
        for (self.workers) |*w| w.oneshot.clearRetainingCapacity();
        const out = mgr.output_() orelse return;
        const nodes = mgr.nodes;
        for (self.opts.peers) |p| {
            if (p.index >= mgr.params.members.len or !std.mem.eql(u8, &p.name, &mgr.params.members[p.index].name)) return error.CommitteeMismatch;
        }
        if (mgr.own_index) |own| if (own != self.opts.own_index) return error.CommitteeMismatch;
        const ranges = try self.gpa.alloc(nodes_mod.ShareRange, nodes.nodes.len);
        defer self.gpa.free(ranges);
        for (ranges, 0..) |*r, i| r.* = nodes.shareRange(@intCast(i)) catch return error.CommitteeMismatch;
        try self.collector.updateEpoch(epoch, mgr.own_index, out.vss_pk, ranges, nodes.total_weight, out.shares orelse &.{}, mgr.threshold(), mgr.highest_completed_round);
        self.have_epoch = true;
        self.afterChange();
    }

    /// `send_partial_signatures`: consensus reserved `round` (Rust `generate_randomness`). Rounds
    /// from the highest completed one up to `round` start sending (at most 20 at once).
    pub fn sendPartials(self: *RandomnessNet, epoch: u64, round: u64) !void {
        self.lock();
        defer self.unlock();
        defer self.cv.broadcast(self.io);
        try self.collector.sendPartialSignatures(epoch, round);
        self.afterChange();
    }

    /// `complete_round`: the round's randomness is in a checkpoint; it and every earlier round
    /// stop being sent.
    pub fn completeRound(self: *RandomnessNet, epoch: u64, round: u64) void {
        self.lock();
        defer self.unlock();
        defer self.cv.broadcast(self.io);
        self.collector.completeRound(epoch, round) catch |e| log.warn("complete round {d}: {s}", .{ round, @errorName(e) });
        var i: usize = 0;
        while (i < self.tasks.count()) {
            const k = self.tasks.keys()[i];
            if (k.epoch < epoch or (k.epoch == epoch and k.round <= round)) {
                self.gpa.free(self.tasks.values()[i]);
                self.tasks.swapRemoveAt(i);
            } else i += 1;
        }
        self.afterChange();
    }

    /// The anemo handler of the route (mounts on any anemo endpoint; 404 for other routes).
    pub fn handler(self: *RandomnessNet) anemo.Handler {
        return .{ .ctx = @ptrCast(self), .serve = serveFn };
    }

    fn serveFn(ctx: *anyopaque, arena: Allocator, from: *const anemo.PeerId, rt: []const u8, body: []const u8) anemo.Reply {
        const self: *RandomnessNet = @ptrCast(@alignCast(ctx));
        return self.serve(arena, from, rt, body);
    }

    pub fn serve(self: *RandomnessNet, arena: Allocator, from: *const anemo.PeerId, rt: []const u8, body: []const u8) anemo.Reply {
        if (!std.mem.eql(u8, rt, route)) return .{ .status = .not_found };
        // RequireAuthorizationLayer(AllowedPeersUpdatable)
        const peer = self.peerIndex(from) orelse {
            log.debug("refused: peer {x} is not in the committee", .{from[0..8]});
            return self.refuse(.not_found);
        };
        {
            self.lock();
            defer self.unlock();
            if (!self.have_epoch or peer >= self.collector.ranges.len or self.collector.isBlocked(peer)) {
                log.debug("refused peer {d}: have_epoch {} ranges {d} blocked {}", .{ peer, self.have_epoch, self.collector.ranges.len, peer < self.collector.ranges.len and self.collector.isBlocked(peer) });
                return self.refuse(.not_found);
            }
        }
        // InflightLimitLayer(send_partial_signatures_inflight_limit, ReturnError)
        if (self.inflight.fetchAdd(1, .acq_rel) >= inflight_limit) {
            _ = self.inflight.fetchSub(1, .acq_rel);
            return self.refuse(.too_many_requests);
        }
        defer _ = self.inflight.fetchSub(1, .acq_rel);
        // BcsSnappyCodec decode; an error is Status::from_error (Unknown)
        const raw = snappy.decompressFrame(arena, body, max_request_bytes) catch return self.refuse(.unknown);
        const req = signatures.SendSignaturesRequest.decode(arena, raw) catch return self.refuse(.unknown);
        _ = self.stats.received.fetchAdd(1, .monotonic);
        {
            self.lock();
            defer self.unlock();
            const r = if (req.sig) |sig|
                self.collector.receiveFull(peer, req.epoch, req.round, sig)
            else
                self.collector.receivePartial(peer, req.epoch, req.round, req.partial_sigs);
            r catch |e| log.debug("signatures from peer {d} round {d}: {s}", .{ peer, req.round, @errorName(e) });
            self.afterChange();
            // zui-only catch-up: a peer still sending a round we completed (a validator that
            // restarted and has no checkpoint sync from us) gets that round's full signature
            // once per request, as the message Rust sends after aggregation.
            if (req.sig == null and req.epoch == self.collector.epoch) if (self.collector.highest_completed) |hc| {
                if (req.round <= hc and self.fulls.contains(req.round)) self.queueOneshot(peer, req.epoch, req.round);
            };
            // and a peer still in the previous epoch gets that epoch's full signatures
            if (req.sig == null and self.prev_fulls_epoch != null and req.epoch == self.prev_fulls_epoch.?) {
                if (self.prev_fulls.contains(req.round)) self.queueOneshot(peer, req.epoch, req.round);
            }
        }
        self.cv.broadcast(self.io);
        // Response<()>: BCS of () is empty, and snappy writes nothing for it
        return .{ .status = .success, .headers = &success_headers };
    }

    fn refuse(self: *RandomnessNet, status: wire.Status) anemo.Reply {
        _ = self.stats.refused.fetchAdd(1, .monotonic);
        return .{ .status = status };
    }

    /// The aggregated signature of `round` (48 bytes) when this net holds it for `epoch`.
    pub fn fullSig(self: *RandomnessNet, epoch: u64, round: u64) ?[48]u8 {
        self.lock();
        defer self.unlock();
        if (epoch != self.fulls_epoch) return null;
        return self.fulls.get(round);
    }

    fn queueOneshot(self: *RandomnessNet, peer: u16, epoch: u64, round: u64) void {
        for (self.workers) |*w| if (w.peer.index == peer) {
            for (w.oneshot.items) |r| if (r.epoch == epoch and r.round == round) return;
            w.oneshot.append(self.gpa, .{ .epoch = epoch, .round = round }) catch {};
            return;
        };
    }

    /// `SendSignaturesRequest { epoch, round, partial_sigs: [], sig: Some(full) }`, snappy framed.
    fn fullRequest(a: Allocator, epoch: u64, round: u64, sig: *const [48]u8) ![]u8 {
        var bcs: [8 + 8 + 1 + 1 + 48]u8 = undefined;
        std.mem.writeInt(u64, bcs[0..8], epoch, .little);
        std.mem.writeInt(u64, bcs[8..16], round, .little);
        bcs[16] = 0; // no partial signatures
        bcs[17] = 1; // Some
        @memcpy(bcs[18..], sig);
        return snappy.compressFrame(a, &bcs);
    }

    fn peerIndex(self: *const RandomnessNet, id: *const anemo.PeerId) ?u16 {
        for (self.opts.peers) |p| if (std.mem.eql(u8, &p.network_pubkey, id)) return p.index;
        return null;
    }

    // ------------------------------------------------------------ under the lock

    fn lock(self: *RandomnessNet) void {
        self.mu.lockUncancelable(self.io);
    }
    fn unlock(self: *RandomnessNet) void {
        self.mu.unlock(self.io);
    }

    fn wakeAll(self: *RandomnessNet) void {
        self.lock();
        defer self.unlock();
        self.cv.broadcast(self.io);
        self.sink_cv.broadcast(self.io);
    }

    fn clearTasks(self: *RandomnessNet) void {
        for (self.tasks.values()) |b| self.gpa.free(b);
        self.tasks.clearRetainingCapacity();
    }

    /// The collector's events: rounds that start sending get their request, an aggregated
    /// round's request turns into the full signature, and full signatures go to the sink.
    fn afterChange(self: *RandomnessNet) void {
        var evs: std.ArrayList(signatures.Event) = .empty;
        defer evs.deinit(self.gpa);
        self.collector.drainEvents(&evs) catch {
            log.err("randomness events lost: out of memory", .{});
            return;
        };
        for (evs.items) |e| switch (e) {
            .start_sending => |round| self.refreshTask(round, true),
            .signature => |s| {
                if (s.epoch == self.collector.epoch) {
                    self.refreshTask(s.round, false);
                    if (s.epoch == self.fulls_epoch) self.fulls.put(self.gpa, s.round, s.bytes) catch {};
                }
                self.sink_q.append(self.gpa, .{ .epoch = s.epoch, .round = s.round, .sig = s.bytes }) catch
                    log.err("full signature of round {d} not delivered: out of memory", .{s.round});
                self.sink_cv.signal(self.io);
            },
            .ignore_peer => |p| log.warn("ignoring byzantine peer {d} for epoch {d}", .{ p, self.collector.epoch }),
        };
    }

    fn refreshTask(self: *RandomnessNet, round: u64, create: bool) void {
        const key: TaskKey = .{ .epoch = self.collector.epoch, .round = round };
        if (!create and !self.tasks.contains(key)) return;
        const bcs = (self.collector.requestFor(round) catch return) orelse return;
        defer self.gpa.free(bcs);
        var tmp = std.heap.ArenaAllocator.init(self.gpa);
        defer tmp.deinit();
        const framed = snappy.compressFrame(tmp.allocator(), bcs) catch return;
        const owned = self.gpa.dupe(u8, framed) catch return;
        const gop = self.tasks.getOrPut(self.gpa, key) catch {
            self.gpa.free(owned);
            return;
        };
        if (gop.found_existing) self.gpa.free(gop.value_ptr.*);
        gop.value_ptr.* = owned;
    }

    fn nowNs(self: *const RandomnessNet) u64 {
        return @intCast(Io.Clock.awake.now(self.io).toNanoseconds());
    }

    fn sinkLoop(self: *RandomnessNet) void {
        var local: std.ArrayList(Full) = .empty;
        defer local.deinit(self.gpa);
        while (true) {
            {
                self.lock();
                defer self.unlock();
                while (self.sink_q.items.len == 0 and !self.stop_flag.load(.acquire)) self.sink_cv.waitUncancelable(self.io, &self.mu);
                if (self.stop_flag.load(.acquire)) return;
                std.mem.swap(std.ArrayList(Full), &local, &self.sink_q);
            }
            for (local.items) |f| self.sink.f(self.sink.ctx, f.epoch, f.round, &f.sig);
            local.clearRetainingCapacity();
        }
    }
};

/// Sends to one peer: every round being sent, again `retry_interval` after each attempt
/// (`send_signatures_task`'s loop per peer).
const Worker = struct {
    owner: *RandomnessNet,
    peer: *const Peer,
    due: std.AutoHashMapUnmanaged(TaskKey, u64) = .empty,
    /// Completed rounds whose full signature this peer asked for (under the owner's lock).
    oneshot: std.ArrayList(TaskKey) = .empty,
    thread: std.Thread = undefined,

    fn deinit(w: *Worker) void {
        w.due.deinit(w.owner.gpa);
        w.oneshot.deinit(w.owner.gpa);
    }

    const Item = struct { key: TaskKey, body: []u8, once: bool = false };

    fn loop(w: *Worker) void {
        const n = w.owner;
        var scratch = std.heap.ArenaAllocator.init(n.gpa);
        defer scratch.deinit();
        const retry_ns = n.opts.retry_interval_ms * std.time.ns_per_ms;
        while (!n.stop_flag.load(.acquire)) {
            _ = scratch.reset(.retain_capacity);
            const a = scratch.allocator();
            var items: std.ArrayList(Item) = .empty;
            var next: u64 = std.math.maxInt(u64);
            const now = n.nowNs();
            {
                n.lock();
                defer n.unlock();
                // forget rounds no longer sent
                var gone: std.ArrayList(TaskKey) = .empty;
                var it = w.due.keyIterator();
                while (it.next()) |k| if (!n.tasks.contains(k.*)) gone.append(a, k.*) catch {};
                for (gone.items) |k| _ = w.due.remove(k);
                var once: std.ArrayList(Item) = .empty;
                for (w.oneshot.items) |r| {
                    const map = if (r.epoch == n.fulls_epoch) &n.fulls else if (n.prev_fulls_epoch != null and r.epoch == n.prev_fulls_epoch.?) &n.prev_fulls else continue;
                    const sig = map.getPtr(r.round) orelse continue;
                    const body = RandomnessNet.fullRequest(a, r.epoch, r.round, sig) catch continue;
                    once.append(a, .{ .key = .{ .epoch = r.epoch, .round = r.round }, .body = body, .once = true }) catch continue;
                }
                w.oneshot.clearRetainingCapacity();
                items.appendSlice(a, once.items) catch {};
                for (n.tasks.keys(), n.tasks.values()) |k, body| {
                    const at = w.due.get(k) orelse 0;
                    if (at <= now) {
                        items.append(a, .{ .key = k, .body = a.dupe(u8, body) catch continue }) catch continue;
                    } else next = @min(next, at);
                }
            }
            if (items.items.len > 0) {
                var failed = false;
                for (items.items) |item| {
                    if (n.stop_flag.load(.acquire)) return;
                    if (!failed) failed = !w.send(a, item.body);
                    if (item.once) continue;
                    // the next attempt `retry_interval` after this one (an unreachable peer
                    // costs one timeout per pass, not one per round)
                    w.due.put(n.gpa, item.key, n.nowNs() + retry_ns) catch {};
                }
                continue;
            }
            const wait_ns = @min(next -| now, 50 * std.time.ns_per_ms);
            n.lock();
            defer n.unlock();
            if (!n.stop_flag.load(.acquire))
                n.cv.waitTimeout(n.io, &n.mu, .{ .duration = .{ .raw = .fromNanoseconds(@intCast(wait_ns)), .clock = .awake } }) catch {};
        }
    }

    /// One attempt; false when the peer could not be reached or did not answer.
    fn send(w: *Worker, a: Allocator, body: []const u8) bool {
        const n = w.owner;
        const r = n.opts.p2p.call(a, w.peer.index, route, &request_headers, body, send_timeout_ms) orelse return w.fail();
        return w.answered(r.status);
    }

    fn answered(w: *Worker, status: wire.Status) bool {
        if (status != .success) {
            log.debug("peer {d} answered {d}", .{ w.peer.index, @intFromEnum(status) });
            _ = w.owner.stats.sent_failed.fetchAdd(1, .monotonic);
        } else _ = w.owner.stats.sent_ok.fetchAdd(1, .monotonic);
        return true; // reachable: the other rounds go too
    }

    fn fail(w: *Worker) bool {
        _ = w.owner.stats.sent_failed.fetchAdd(1, .monotonic);
        return false;
    }
};

// ---------------------------------------------------------------------------------------------
// tests

const testing = std.testing;
const manager_mod = randomness.manager;
const group = randomness.group;
const tbls = randomness.tbls;

const TestSink = struct {
    io: Io,
    mu: Io.Mutex = .init,
    got: std.AutoHashMapUnmanaged(u64, [48]u8) = .empty,
    conflicts: u32 = 0,
    gpa: Allocator,

    fn f(ctx: *anyopaque, epoch: u64, round: u64, sig: []const u8) void {
        const s: *TestSink = @ptrCast(@alignCast(ctx));
        _ = epoch;
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        const gop = s.got.getOrPut(s.gpa, round) catch return;
        if (gop.found_existing and !std.mem.eql(u8, &gop.value_ptr.*, sig)) s.conflicts += 1;
        gop.value_ptr.* = sig[0..48].*;
    }

    fn get(s: *TestSink, round: u64) ?[48]u8 {
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        return s.got.get(round);
    }

    fn sink(s: *TestSink) FullSigSink {
        return .{ .ctx = @ptrCast(s), .f = f };
    }
};

/// Four validators (equal stake) run the DKG through a mock consensus (as manager.zig's test).
fn testDkg(gpa: Allocator, rng: std.Random, members: *[4]manager_mod.Member) ![4]*randomness.Manager {
    var secrets: [4][32]u8 = undefined;
    for (0..4) |i| {
        const s = group.scalarRand(rng);
        secrets[i] = group.scalarToBytes(s);
        members[i] = .{ .name = group.g2ToBytes(group.mulPublic(group.G2, group.g2Generator(), s)), .stake = 2500 };
    }
    const params: manager_mod.Params = .{
        .epoch = 3,
        .chain_id = @splat(0x4c),
        .members = members,
        .protocol = .{ .random_beacon_reduction_lower_bound = 8, .random_beacon_reduction_allowed_delta = 800 },
    };
    var mgrs: [4]*randomness.Manager = undefined;
    for (0..4) |i| mgrs[i] = try randomness.Manager.createForTesting(gpa, params, &secrets[i], rng);
    var msgs: [4][]u8 = undefined;
    for (0..4) |i| msgs[i] = (try mgrs[i].startDkg()).?;
    defer for (msgs) |m| gpa.free(m);
    for (mgrs) |m| for (0..4) |j| try m.addMessage(&members[j].name, msgs[j]);
    var confs: [4]?[]u8 = @splat(null);
    defer for (confs) |c| if (c) |x| gpa.free(x);
    for (mgrs, 0..) |m, i| {
        var batch = manager_mod.Batch.init(gpa);
        defer batch.deinit();
        var adv = try m.advanceDkg(&batch, 10);
        defer adv.deinit(gpa);
        confs[i] = adv.confirmation_to_submit;
        adv.confirmation_to_submit = null;
    }
    for (mgrs) |m| {
        var batch = manager_mod.Batch.init(gpa);
        defer batch.deinit();
        for (0..4) |j| try m.addConfirmation(&batch, &members[j].name, confs[j].?);
        var adv = try m.advanceDkg(&batch, 11);
        defer adv.deinit(gpa);
        try testing.expectEqual(manager_mod.DkgStatus.successful, m.dkgStatus());
    }
    return mgrs;
}

fn freePort(io: Io) !u16 {
    var a: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    const s = try Io.net.IpAddress.bind(&a, io, .{ .mode = .dgram });
    defer s.close(io);
    return s.address.ip4.port;
}

/// Waits until `sinks` all hold `rounds` (20 s at most).
fn waitRounds(io: Io, sinks: []const *TestSink, first: u64, end: u64) !void {
    const deadline = Io.Clock.awake.now(io).toNanoseconds() + 20 * std.time.ns_per_s;
    while (Io.Clock.awake.now(io).toNanoseconds() < deadline) {
        var all = true;
        for (sinks) |s| for (first..end) |r| {
            if (s.get(r) == null) all = false;
        };
        if (all) return;
        try Io.sleep(io, .fromMilliseconds(20), .awake);
    }
    for (sinks, 0..) |s, i| for (first..end) |r| {
        if (s.get(r) == null) std.debug.print("waitRounds: sink {d} has no round {d}\n", .{ i, r });
    };
    return error.Timeout;
}

test "four nets exchange partial signatures over anemo; one stops and the rest go on; it restarts" {
    const gpa = testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var prng = std.Random.DefaultPrng.init(0x5eed);
    var members: [4]manager_mod.Member = undefined;
    const mgrs = try testDkg(gpa, prng.random(), &members);
    defer for (mgrs) |m| m.destroy();
    const epoch: u64 = 3;
    const pk = mgrs[0].publicKey().?;

    var seeds: [4][32]u8 = undefined;
    var addr_bufs: [4][32]u8 = undefined;
    var peers: [4]Peer = undefined;
    for (0..4) |i| {
        seeds[i] = @splat(@intCast(0x60 + i));
        const kp = try Ed25519.KeyPair.generateDeterministic(seeds[i]);
        const addr = try std.fmt.bufPrint(&addr_bufs[i], "127.0.0.1:{d}", .{try freePort(io)});
        peers[i] = .{ .index = @intCast(i), .name = members[i].name, .network_pubkey = kp.public_key.toBytes(), .p2p_address = addr };
    }
    var sinks: [4]TestSink = undefined;
    for (&sinks) |*s| s.* = .{ .io = io, .gpa = gpa };
    defer for (&sinks) |*s| s.got.deinit(gpa);
    const sink_ptrs = [4]*TestSink{ &sinks[0], &sinks[1], &sinks[2], &sinks[3] };

    var eps: [4]?*p2p_mod.P2p = @splat(null);
    var nets: [4]?*RandomnessNet = @splat(null);
    defer for (nets, eps) |m, e| {
        if (m) |x| x.stop();
        if (e) |x| x.stop();
    };
    var p2p_peers: [4]p2p_mod.Peer = undefined;
    for (peers, &p2p_peers) |p, *q| q.* = .{ .network_pubkey = p.network_pubkey, .p2p_address = p.p2p_address };
    const startNode = struct {
        fn f(g: Allocator, io_: Io, pp: []const p2p_mod.Peer, ps: []const Peer, i: usize, seed: *const [32]u8, sk: FullSigSink, ep: *?*p2p_mod.P2p) !*RandomnessNet {
            ep.* = try p2p_mod.P2p.start(g, io_, .{ .listen = pp[i].p2p_address, .peers = pp, .own_index = i, .network_seed = seed, .chain_id = @splat(0x4c), .threads = 2 });
            return RandomnessNet.start(g, io_, .{ .p2p = ep.*.?, .peers = ps, .own_index = @intCast(i), .retry_interval_ms = 200 }, sk);
        }
    }.f;
    for (0..4) |i| nets[i] = try startNode(gpa, io, &p2p_peers, &peers, i, &seeds[i], sinks[i].sink(), &eps[i]);

    // before the epoch is installed every request is refused (empty allowed-peer set)
    {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        try testing.expectEqual(wire.Status.not_found, nets[0].?.serve(a, &peers[1].network_pubkey, route, "").status);
        for (0..4) |i| try nets[i].?.setEpoch(epoch, mgrs[i]);
        // a stranger, another route, a body that does not decode
        const stranger: anemo.PeerId = @splat(1);
        try testing.expectEqual(wire.Status.not_found, nets[0].?.serve(a, &stranger, route, "").status);
        try testing.expectEqual(wire.Status.not_found, nets[0].?.serve(a, &peers[1].network_pubkey, "/sui.Randomness/Other", "").status);
        try testing.expectEqual(wire.Status.unknown, nets[0].?.serve(a, &peers[1].network_pubkey, route, "junk").status);
    }

    // rounds 0..4 from every validator
    for (0..5) |r| for (nets) |m| try m.?.sendPartials(epoch, r);
    try waitRounds(io, &sink_ptrs, 0, 5);
    for (0..5) |r| {
        const sig = sinks[0].get(r).?;
        for (&sinks) |*s| try testing.expectEqualSlices(u8, &sig, &s.get(r).?);
        try tbls.verify(pk, &tbls.roundMessage(r), group.g1FromBytes(&sig).?);
    }
    for (mgrs) |m| _ = m.notifyRandomnessInCheckpoint(4);
    for (nets) |m| m.?.completeRound(epoch, 4);
    for (nets) |m| try testing.expect(m.?.stats.sent_ok.load(.monotonic) > 0);

    // validator 3 goes away: the other three still reach the threshold
    nets[3].?.stop();
    nets[3] = null;
    eps[3].?.stop();
    eps[3] = null;
    for (5..7) |r| for (nets[0..3]) |m| try m.?.sendPartials(epoch, r);
    try waitRounds(io, sink_ptrs[0..3], 5, 7);
    for (5..7) |r| {
        const sig = sinks[0].get(r).?;
        for (sinks[0..3]) |*s| try testing.expectEqualSlices(u8, &sig, &s.get(r).?);
        try tbls.verify(pk, &tbls.roundMessage(r), group.g1FromBytes(&sig).?);
    }

    // the three complete rounds 5 and 6 (checkpointed) and stop sending them
    for (mgrs[0..3]) |m| _ = m.notifyRandomnessInCheckpoint(6);
    for (nets[0..3]) |m| m.?.completeRound(epoch, 6);
    for (5..7) |r| try testing.expectEqualSlices(u8, &sinks[0].get(r).?, &nets[1].?.fullSig(epoch, r).?);
    try testing.expect(nets[1].?.fullSig(epoch + 1, 5) == null);
    try testing.expect(nets[1].?.fullSig(epoch, 99) == null);

    // validator 3 restarts on the same address, sends its partials for 5 and 6, and gets the
    // full signatures of those completed rounds back
    nets[3] = try startNode(gpa, io, &p2p_peers, &peers, 3, &seeds[3], sinks[3].sink(), &eps[3]);
    try nets[3].?.setEpoch(epoch, mgrs[3]);
    for (5..7) |r| try nets[3].?.sendPartials(epoch, r);
    try waitRounds(io, sink_ptrs[3..4], 5, 7);
    for (5..7) |r| try testing.expectEqualSlices(u8, &sinks[0].get(r).?, &sinks[3].get(r).?);
    nets[3].?.completeRound(epoch, 6);
    for (&sinks) |*s| try testing.expectEqual(@as(u32, 0), s.conflicts);
}

test "a failed DKG installs no rounds" {
    const gpa = testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var prng = std.Random.DefaultPrng.init(9);
    var members: [4]manager_mod.Member = undefined;
    var secrets: [4][32]u8 = undefined;
    for (0..4) |i| {
        const s = group.scalarRand(prng.random());
        secrets[i] = group.scalarToBytes(s);
        members[i] = .{ .name = group.g2ToBytes(group.mulPublic(group.G2, group.g2Generator(), s)), .stake = 2500 };
    }
    const mgr = try randomness.Manager.createForTesting(gpa, .{
        .epoch = 1,
        .chain_id = @splat(0x4c),
        .members = &members,
        .protocol = .{ .random_beacon_reduction_lower_bound = 8, .random_beacon_reduction_allowed_delta = 800 },
    }, &secrets[0], prng.random());
    defer mgr.destroy();
    mgr.loadOutputFailed();
    const seed: [32]u8 = @splat(3);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    var addr_buf: [32]u8 = undefined;
    const peers = [_]Peer{.{ .index = 0, .name = members[0].name, .network_pubkey = kp.public_key.toBytes(), .p2p_address = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{try freePort(io)}) }};
    var sink: TestSink = .{ .io = io, .gpa = gpa };
    defer sink.got.deinit(gpa);
    const pp = [_]p2p_mod.Peer{.{ .network_pubkey = peers[0].network_pubkey, .p2p_address = peers[0].p2p_address }};
    const ep = try p2p_mod.P2p.start(gpa, io, .{ .listen = peers[0].p2p_address, .peers = &pp, .own_index = 0, .network_seed = &seed, .chain_id = @splat(0x4c), .threads = 1 });
    defer ep.stop();
    const n = try RandomnessNet.start(gpa, io, .{ .p2p = ep, .peers = &peers, .own_index = 0 }, sink.sink());
    defer n.stop();
    try n.setEpoch(1, mgr);
    try n.sendPartials(1, 0);
    try testing.expectEqual(@as(usize, 0), n.tasks.count());
    try testing.expectEqualStrings("sui-4c4c4c4c", ep.server_name);
}
