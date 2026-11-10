//! Inbound anemo listener: the QUIC server role of a sui-node peer (sui-node listens on
//! `0.0.0.0:8084/udp`). One UDP socket, one I/O thread that owns every connection (conn.zig in
//! server role, demultiplexed by our connection id), and a pool of request workers that call the
//! `anemo.Handler` (store reads can take milliseconds; QUIC processing stays on the I/O thread).
//! Workers hand responses back through a queue and wake the I/O thread with one byte on a
//! loopback socket.
//!
//! Per connection, as anemo's inbound side does (`network/wire.rs::handshake`): after the TLS
//! handshake we open a unidirectional stream with the 8-byte version frame; every bidirectional
//! stream the client opens carries one request (version frame, header frame, body frame) and gets
//! one response. In-flight requests per connection are bounded by the QUIC stream limit we
//! advertise (a stream is credited back only once its response is sent).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const Ed25519 = std.crypto.sign.Ed25519;
const conn_mod = @import("conn.zig");
const anemo = @import("anemo.zig");
const wire = @import("wire.zig");
const p2pm = @import("core").p2p_metrics;
const udpio = @import("udpio.zig");

/// The I/O thread's batched socket state (net/udpio.zig, shared with the zui/1 server):
/// allocated once at start, so receiving and sending a datagram never allocates.
const IoBufs = struct {
    sock: udpio.Sock,
    tx: udpio.TxBatch = .{},
    rx: udpio.RxBatch = .{},
};
const log = std.log.scoped(.p2p_listener);

pub const Options = struct {
    listen: Io.net.IpAddress,
    key: Ed25519.KeyPair,
    /// `state_sync.mainnet_server_name` on mainnet.
    server_name: []const u8,
    handler: anemo.Handler,
    /// Request workers (0 = auto: 4).
    threads: u16 = 0,
    max_connections: u32 = 1000,
    // QUIC settings: sui-node 1.83.1's (`sui-node/src/lib.rs` p2p network setup).
    /// Concurrent requests one client may have open (QUIC bidirectional stream limit).
    max_streams_per_connection: u32 = 500,
    idle_timeout_ms: u64 = 10_000,
    keep_alive_ms: u64 = 5_000,
    stream_receive_window: u64 = 100 << 20,
    receive_window: u64 = 200 << 20,
    max_request_frame: usize = wire.sui_max_request_frame,
};

pub const Stats = struct {
    accepted: Atomic(u64) = .init(0),
    active: Atomic(u64) = .init(0),
    rejected: Atomic(u64) = .init(0),
    handshake_failed: Atomic(u64) = .init(0),
    requests: Atomic(u64) = .init(0),
    bad_requests: Atomic(u64) = .init(0),
    bytes_in: Atomic(u64) = .init(0),
    bytes_out: Atomic(u64) = .init(0),
    datagrams_in: Atomic(u64) = .init(0),
    datagrams_out: Atomic(u64) = .init(0),
};

/// A peer we have an established connection with (for discovery and logs).
pub const InboundPeer = struct { id: anemo.PeerId, addr: Io.net.IpAddress };

/// A connection's next timer in the I/O thread's heap. Entries are not removed when a timer
/// moves: a popped entry whose slot is gone (gen) or not yet due is dropped.
const TimerEnt = struct { at: u64, key: u64, gen: u64 };

fn timerOrder(_: void, a: TimerEnt, b: TimerEnt) std.math.Order {
    return std.math.order(a.at, b.at);
}

const Slot = struct {
    /// I/O pass in which the slot was last put on the active list.
    pass: u64 = 0,
    conn: *conn_mod.Connection,
    addr: Io.net.IpAddress,
    gen: u64,
    key: u64, // our connection id as a map key
    odcid: [20]u8 = undefined,
    odcid_len: u8 = 0,
    peer_id: ?anemo.PeerId = null,
    hello_sent: bool = false,
    hello_stream: ?u64 = null,
    inbound: std.ArrayList(u64) = .empty, // client streams whose request is still arriving
    waiting: u32 = 0, // requests with a worker
    answered: std.ArrayList(u64) = .empty, // response queued, free once sent
};

const Job = struct { slot_key: u64, gen: u64, stream: u64, peer: anemo.PeerId, route: []u8, body: []u8 };
const Done = struct { slot_key: u64, gen: u64, stream: u64, resp: []u8 };

pub const Listener = struct {
    gpa: Allocator,
    io: Io,
    opts: Options,
    stats: Stats = .{},
    sock: Io.net.Socket,
    wake_sock: Io.net.Socket,
    wake_send: Io.net.Socket,
    stop_flag: Atomic(bool) = .init(false),
    io_thread: ?std.Thread = null,
    bufs: *IoBufs = undefined,
    /// The other half of `done`'s double buffer (I/O thread only).
    done_spare: std.ArrayList(Done) = .empty,
    /// I/O thread only: connection timers (min-heap) and the connections to service this pass
    /// (a datagram, a worker's response, or a due timer), so a pass costs O(active), not two
    /// scans of every connection.
    timers: std.PriorityQueue(TimerEnt, void, timerOrder) = .initContext({}),
    active: std.ArrayList(*Slot) = .empty,
    pass: u64 = 1,
    workers: []std.Thread = &.{},
    gen_next: u64 = 1,

    // I/O thread only
    slots: std.AutoHashMapUnmanaged(u64, *Slot) = .empty,

    // shared with workers
    mu: Io.Mutex = .init,
    cv: Io.Condition = .init,
    jobs: std.ArrayList(Job) = .empty,
    done: std.ArrayList(Done) = .empty,

    peers_mu: Io.Mutex = .init,
    peers: std.ArrayList(InboundPeer) = .empty,

    pub fn start(gpa: Allocator, io: Io, opts: Options) !*Listener {
        const l = try gpa.create(Listener);
        errdefer gpa.destroy(l);
        const sock = try Io.net.IpAddress.bind(&opts.listen, io, .{ .mode = .dgram });
        errdefer sock.close(io);
        // sui-node asks for 20 MiB socket buffers; best effort.
        const rcvbuf: c_int = 20 << 20;
        const sndbuf: c_int = 20 << 20;
        std.posix.setsockopt(sock.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&rcvbuf)) catch {};
        std.posix.setsockopt(sock.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&sndbuf)) catch {};
        var lo: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
        const wake_sock = try Io.net.IpAddress.bind(&lo, io, .{ .mode = .dgram });
        errdefer wake_sock.close(io);
        const wake_send = try Io.net.IpAddress.bind(&lo, io, .{ .mode = .dgram });
        errdefer wake_send.close(io);
        l.* = .{ .gpa = gpa, .io = io, .opts = opts, .sock = sock, .wake_sock = wake_sock, .wake_send = wake_send };
        l.bufs = try gpa.create(IoBufs);
        errdefer gpa.destroy(l.bufs);
        l.bufs.* = .{ .sock = udpio.Sock.init(sock.handle) };
        const n: usize = if (opts.threads == 0) 4 else opts.threads;
        l.workers = try gpa.alloc(std.Thread, n);
        var started: usize = 0;
        errdefer {
            l.stop_flag.store(true, .release);
            l.cv.broadcast(l.io);
            for (l.workers[0..started]) |t| t.join();
            gpa.free(l.workers);
        }
        while (started < n) : (started += 1) l.workers[started] = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, workerLoop, .{l});
        l.io_thread = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, ioLoop, .{l});
        return l;
    }

    /// The bound address (the port when the listen port was 0).
    pub fn address(l: *const Listener) Io.net.IpAddress {
        return l.sock.address;
    }

    pub fn stop(l: *Listener) void {
        l.stop_flag.store(true, .release);
        l.wake();
        {
            l.mu.lockUncancelable(l.io);
            defer l.mu.unlock(l.io);
            l.cv.broadcast(l.io);
        }
        if (l.io_thread) |t| t.join();
        for (l.workers) |t| t.join();
        const gpa = l.gpa;
        gpa.free(l.workers);
        var it = l.slots.valueIterator();
        while (it.next()) |sp| l.freeSlot(sp.*);
        l.slots.deinit(gpa);
        for (l.jobs.items) |j| {
            gpa.free(j.route);
            gpa.free(j.body);
        }
        l.jobs.deinit(gpa);
        for (l.done.items) |d| gpa.free(d.resp);
        l.done.deinit(gpa);
        l.peers.deinit(gpa);
        l.done_spare.deinit(gpa);
        l.timers.deinit(gpa);
        l.active.deinit(gpa);
        gpa.destroy(l.bufs);
        l.sock.close(l.io);
        l.wake_sock.close(l.io);
        l.wake_send.close(l.io);
        gpa.destroy(l);
    }

    /// Copies the established inbound peers into `out` (allocated with `a`).
    pub fn inboundPeers(l: *Listener, a: Allocator) ![]InboundPeer {
        l.peers_mu.lockUncancelable(l.io);
        defer l.peers_mu.unlock(l.io);
        return a.dupe(InboundPeer, l.peers.items);
    }

    fn wake(l: *Listener) void {
        l.wake_send.send(l.io, &l.wake_sock.address, &.{1}) catch {};
    }

    fn nowNs(l: *const Listener) u64 {
        return @intCast(Io.Clock.awake.now(l.io).toNanoseconds());
    }

    fn freeSlot(l: *Listener, s: *Slot) void {
        s.conn.deinit();
        s.inbound.deinit(l.gpa);
        s.answered.deinit(l.gpa);
        l.gpa.destroy(s);
    }

    // ------------------------------------------------------------ workers

    fn workerLoop(l: *Listener) void {
        while (true) {
            var job: Job = undefined;
            {
                l.mu.lockUncancelable(l.io);
                defer l.mu.unlock(l.io);
                while (l.jobs.items.len == 0 and !l.stop_flag.load(.acquire)) l.cv.waitUncancelable(l.io, &l.mu);
                if (l.stop_flag.load(.acquire)) return;
                job = l.jobs.orderedRemove(0);
            }
            var arena_state = std.heap.ArenaAllocator.init(l.gpa);
            const a = arena_state.allocator();
            const call = p2pm.inbound.begin(job.route, job.body.len);
            const reply = l.opts.handler.serve(l.opts.handler.ctx, a, &job.peer, job.route, job.body);
            p2pm.inbound.end(call, @intFromEnum(reply.status), reply.body.len);
            const resp = wire.encodeResponse(l.gpa, reply.status, &.{}, reply.body) catch null;
            arena_state.deinit();
            l.gpa.free(job.route);
            l.gpa.free(job.body);
            _ = l.stats.requests.fetchAdd(1, .monotonic);
            {
                l.mu.lockUncancelable(l.io);
                defer l.mu.unlock(l.io);
                l.done.append(l.gpa, .{ .slot_key = job.slot_key, .gen = job.gen, .stream = job.stream, .resp = resp orelse &.{} }) catch if (resp) |r| l.gpa.free(r);
            }
            l.wake();
        }
    }

    // ------------------------------------------------------------ I/O thread

    fn ioLoop(l: *Listener) void {
        defer l.closeAll();
        var wbuf: [64]u8 = undefined;
        while (!l.stop_flag.load(.acquire)) {
            var now = l.nowNs();
            var wait_ns: u64 = 200 * std.time.ns_per_ms;
            if (l.timers.peek()) |t| wait_ns = @min(wait_ns, t.at -| now);
            var fds = [2]std.posix.pollfd{
                .{ .fd = l.sock.handle, .events = std.posix.POLL.IN, .revents = 0 },
                .{ .fd = l.wake_sock.handle, .events = std.posix.POLL.IN, .revents = 0 },
            };
            const ms_wait: i32 = @intCast(@min((wait_ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms, 1000));
            _ = std.posix.poll(&fds, ms_wait) catch 0;
            if (fds[1].revents & std.posix.POLL.IN != 0) {
                // drain wake bytes
                while (true) {
                    var p2 = [1]std.posix.pollfd{.{ .fd = l.wake_sock.handle, .events = std.posix.POLL.IN, .revents = 0 }};
                    const r = std.posix.poll(&p2, 0) catch 0;
                    if (r == 0) break;
                    _ = l.wake_sock.receive(l.io, &wbuf) catch break;
                }
            }
            if (fds[0].revents & std.posix.POLL.IN != 0) {
                // Up to 4096 datagrams per pass, a batch per syscall (recvmmsg / recvmsg_x).
                const rx = &l.bufs.rx;
                var budget: usize = 4096 / udpio.max_batch;
                while (budget > 0) : (budget -= 1) {
                    const got = rx.recv(&l.bufs.sock, false);
                    var bytes: u64 = 0;
                    for (0..got) |k| {
                        const d = rx.data(k);
                        bytes += d.len;
                        l.onDatagram(rx.from(k), d);
                    }
                    _ = l.stats.datagrams_in.fetchAdd(got, .monotonic);
                    _ = l.stats.bytes_in.fetchAdd(bytes, .monotonic);
                    if (got < udpio.max_batch) break;
                }
            }
            l.collectDone();
            now = l.nowNs();
            // due timers join the active list
            while (l.timers.peek()) |t| {
                if (t.at > now) break;
                _ = l.timers.pop();
                const s = l.slots.get(t.key) orelse continue;
                if (s.gen != t.gen) continue;
                const due = s.conn.nextTimeout() orelse continue;
                if (due <= now) l.touch(s);
            }
            // timers, anemo service, transmit, reap: only the active connections
            var dead: std.ArrayList(u64) = .empty;
            defer dead.deinit(l.gpa);
            for (l.active.items) |s| {
                if (s.conn.nextTimeout()) |t| if (now >= t) s.conn.onTimeout(now);
                l.service(s);
                l.flush(s, now);
                if (s.conn.isClosed() and s.waiting == 0) {
                    dead.append(l.gpa, s.key) catch {};
                } else if (s.conn.nextTimeout()) |t| {
                    l.timers.push(l.gpa, .{ .at = t, .key = s.key, .gen = s.gen }) catch {};
                }
            }
            l.active.clearRetainingCapacity();
            l.pass += 1;
            l.bufs.tx.flush(&l.bufs.sock);
            for (dead.items) |k| l.drop(k);
        }
    }

    /// Puts `s` on this pass's active list (once).
    fn touch(l: *Listener, s: *Slot) void {
        if (s.pass == l.pass) return;
        s.pass = l.pass;
        l.active.append(l.gpa, s) catch {};
    }

    fn drop(l: *Listener, key: u64) void {
        const kv = l.slots.fetchRemove(key) orelse return;
        const s = kv.value;
        if (s.peer_id) |id| {
            l.peers_mu.lockUncancelable(l.io);
            defer l.peers_mu.unlock(l.io);
            for (l.peers.items, 0..) |p, i| if (std.mem.eql(u8, &p.id, &id) and p.addr.eql(&s.addr)) {
                _ = l.peers.swapRemove(i);
                break;
            };
        }
        if (s.hello_sent) _ = l.stats.active.fetchSub(1, .monotonic);
        if (s.peer_id == null and s.conn.close != null) {
            _ = l.stats.handshake_failed.fetchAdd(1, .monotonic);
            const cl = s.conn.close.?;
            log.info("inbound handshake from {f} failed: {s} close 0x{x} ({s})", .{ s.addr, if (cl.remote) "peer" else "our", cl.code, cl.reason });
        }
        l.freeSlot(s);
    }

    fn findOdcid(l: *Listener, dcid: []const u8) ?*Slot {
        var it = l.slots.valueIterator();
        while (it.next()) |sp| {
            const s = sp.*;
            if (s.odcid_len == dcid.len and std.mem.eql(u8, s.odcid[0..s.odcid_len], dcid)) return s;
        }
        return null;
    }

    fn onDatagram(l: *Listener, from: Io.net.IpAddress, d: []u8) void {
        if (d.len < 1 + conn_mod.cid_len) return;
        const now = l.nowNs();
        if (d[0] & 0x80 == 0) {
            const key = std.mem.readInt(u64, d[1..][0..8], .little);
            const s = l.slots.get(key) orelse return;
            s.conn.handleDatagram(now, d);
            l.touch(s);
            return;
        }
        // long header
        if (d.len < 7) return;
        const version = std.mem.readInt(u32, d[1..5], .big);
        const dl = d[5];
        if (dl > 20 or d.len < 6 + dl + 1) return;
        const dcid = d[6..][0..dl];
        const sl = d[6 + dl];
        if (sl > 20 or d.len < 7 + dl + sl) return;
        const scid = d[7 + dl ..][0..sl];
        if (dl == conn_mod.cid_len) if (l.slots.get(std.mem.readInt(u64, dcid[0..8], .little))) |s| {
            s.conn.handleDatagram(now, d);
            l.touch(s);
            return;
        };
        if (l.findOdcid(dcid)) |s| {
            s.conn.handleDatagram(now, d);
            l.touch(s);
            return;
        }
        if (version != 1) return; // no version negotiation: anemo speaks QUIC v1 only
        const ty = (d[0] >> 4) & 3;
        if (ty != 0 or d.len < 1200 or dl < 8) return; // only a full-size Initial opens a connection
        if (l.slots.count() >= l.opts.max_connections) {
            _ = l.stats.rejected.fetchAdd(1, .monotonic);
            return;
        }
        var seed: [64]u8 = undefined;
        l.io.random(&seed);
        const now_unix: i64 = @intCast(@divTrunc(Io.Clock.real.now(l.io).toNanoseconds(), std.time.ns_per_s));
        const c = conn_mod.Connection.initServer(l.gpa, .{
            .server_name = l.opts.server_name,
            .identity_seed = l.opts.key.secret_key.seed(),
            .seed = seed,
            .now_unix = now_unix,
            .max_streams_bidi = l.opts.max_streams_per_connection,
            .max_streams_uni = 500,
            .max_data = l.opts.receive_window,
            .max_stream_data = l.opts.stream_receive_window,
            .idle_timeout_ms = l.opts.idle_timeout_ms,
            .keep_alive_ms = l.opts.keep_alive_ms,
        }, now, dcid, scid) catch return;
        const s = l.gpa.create(Slot) catch {
            c.deinit();
            return;
        };
        s.* = .{ .conn = c, .addr = from, .gen = l.gen_next, .key = std.mem.readInt(u64, &c.scid, .little) };
        l.gen_next += 1;
        s.odcid_len = dl;
        @memcpy(s.odcid[0..dl], dcid);
        l.slots.put(l.gpa, s.key, s) catch {
            l.freeSlot(s);
            return;
        };
        _ = l.stats.accepted.fetchAdd(1, .monotonic);
        c.handleDatagram(now, d);
        l.touch(s);
    }

    /// Queues `s`'s datagrams in the pass's batch (written in place); the batch leaves when it
    /// is full and once at the end of every I/O pass.
    fn flush(l: *Listener, s: *Slot, now: u64) void {
        const b = &l.bufs.tx;
        var n_out: u64 = 0;
        var bytes: u64 = 0;
        while (true) {
            if (b.full()) b.flush(&l.bufs.sock);
            const slot = b.slot();
            const n = s.conn.pollTransmit(now, slot[0..@min(slot.len, conn_mod.max_datagram)]) orelse break;
            b.commit(n, &s.addr);
            n_out += 1;
            bytes += n;
        }
        if (n_out == 0) return;
        _ = l.stats.datagrams_out.fetchAdd(n_out, .monotonic);
        _ = l.stats.bytes_out.fetchAdd(bytes, .monotonic);
    }

    /// At stop: every inbound connection gets a CONNECTION_CLOSE (application code 0, as
    /// sui-node's endpoint close), so peers drop us at once instead of after their idle timeout.
    fn closeAll(l: *Listener) void {
        const now = l.nowNs();
        var it = l.slots.valueIterator();
        while (it.next()) |sp| {
            const s = sp.*;
            if (s.conn.isClosed()) continue;
            s.conn.closeApp(0);
            l.flush(s, now);
        }
        l.bufs.tx.flush(&l.bufs.sock);
    }

    fn collectDone(l: *Listener) void {
        // Double buffer: the list workers fill and the one drained here swap, capacity kept.
        var done = l.done_spare;
        done.clearRetainingCapacity();
        defer l.done_spare = done;
        {
            l.mu.lockUncancelable(l.io);
            defer l.mu.unlock(l.io);
            std.mem.swap(std.ArrayList(Done), &done, &l.done);
        }
        for (done.items) |d| {
            defer l.gpa.free(d.resp);
            const s = l.slots.get(d.slot_key) orelse continue;
            if (s.gen != d.gen) continue;
            s.waiting -|= 1;
            l.touch(s);
            if (s.conn.isClosed() or s.conn.stream(d.stream) == null) continue;
            if (d.resp.len == 0) {
                s.conn.streamFree(d.stream);
                continue;
            }
            s.conn.streamWrite(d.stream, d.resp, true) catch {
                s.conn.streamFree(d.stream);
                continue;
            };
            s.answered.append(l.gpa, d.stream) catch {};
        }
    }

    /// anemo on one connection: the version frame once established, requests to the workers,
    /// finished streams released.
    fn service(l: *Listener, s: *Slot) void {
        const c = s.conn;
        if (!c.isEstablished()) return;
        if (!s.hello_sent) {
            s.hello_sent = true;
            s.peer_id = c.peerId();
            _ = l.stats.active.fetchAdd(1, .monotonic);
            if (s.peer_id) |id| {
                // One line per inbound connection: unique peers and addresses come from the log.
                log.info("inbound peer {x} from {f}", .{ id, s.addr });
                l.peers_mu.lockUncancelable(l.io);
                defer l.peers_mu.unlock(l.io);
                l.peers.append(l.gpa, .{ .id = id, .addr = s.addr }) catch {};
            }
            const id = c.openUni() catch {
                c.closeApp(0);
                return;
            };
            c.streamWrite(id, &wire.version_frame, true) catch {};
            s.hello_stream = id;
        }
        if (s.hello_stream) |id| if (c.stream(id)) |st| {
            if (st.fin_sent and st.retx.items.len == 0 and st.send_off >= st.send_buf.items.len) {
                c.streamFree(id);
                s.hello_stream = null;
            }
        };
        // the client opens no unidirectional streams in anemo: drain and drop any
        while (c.acceptUni()) |id| c.streamFree(id);
        while (c.acceptBidi()) |id| s.inbound.append(l.gpa, id) catch {};
        var i: usize = 0;
        while (i < s.inbound.items.len) {
            const id = s.inbound.items[i];
            const st = c.stream(id) orelse {
                _ = s.inbound.orderedRemove(i);
                continue;
            };
            var arena_state = std.heap.ArenaAllocator.init(l.gpa);
            defer arena_state.deinit();
            const parsed = wire.parseRequest(arena_state.allocator(), st.recv.contiguous(), l.opts.max_request_frame) catch {
                _ = l.stats.bad_requests.fetchAdd(1, .monotonic);
                c.streamFree(id);
                _ = s.inbound.orderedRemove(i);
                continue;
            };
            const req = parsed orelse {
                i += 1;
                continue;
            };
            const route = l.gpa.dupe(u8, req.route) catch break;
            const body = l.gpa.dupe(u8, req.body) catch {
                l.gpa.free(route);
                break;
            };
            {
                l.mu.lockUncancelable(l.io);
                defer l.mu.unlock(l.io);
                l.jobs.append(l.gpa, .{ .slot_key = s.key, .gen = s.gen, .stream = id, .peer = s.peer_id orelse @splat(0), .route = route, .body = body }) catch {
                    l.gpa.free(route);
                    l.gpa.free(body);
                    break;
                };
                l.cv.signal(l.io);
            }
            s.waiting += 1;
            _ = s.inbound.orderedRemove(i);
        }
        var j: usize = 0;
        while (j < s.answered.items.len) {
            const id = s.answered.items[j];
            const st = c.stream(id);
            if (st == null or (st.?.fin_sent and st.?.retx.items.len == 0 and st.?.send_off >= st.?.send_buf.items.len)) {
                c.streamFree(id);
                _ = s.answered.swapRemove(j);
            } else j += 1;
        }
    }
};

// ------------------------------------------------------------------ tests

const TestHandler = struct {
    fn serve(ctx: *anyopaque, a: Allocator, from: *const anemo.PeerId, route: []const u8, body: []const u8) anemo.Reply {
        _ = ctx;
        _ = from;
        if (std.mem.eql(u8, route, "/zui.Test/Echo")) return .{ .status = .success, .body = a.dupe(u8, body) catch "" };
        if (std.mem.eql(u8, route, "/zui.Test/Big")) {
            const n = std.mem.readInt(u32, body[0..4], .little);
            const b = a.alloc(u8, n) catch return .{ .status = .internal_server_error };
            for (b, 0..) |*x, i| x.* = @truncate(i *% 31);
            return .{ .status = .success, .body = b };
        }
        return .{ .status = .not_found };
    }
};

test "zui client talks anemo to the zui listener over loopback" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const skey = try Ed25519.KeyPair.generateDeterministic(@splat(42));
    var dummy: u8 = 0;
    const l = try Listener.start(gpa, io, .{
        .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) },
        .key = skey,
        .server_name = "sui-35834a8a",
        .handler = .{ .ctx = @ptrCast(&dummy), .serve = TestHandler.serve },
        .threads = 2,
    });
    defer l.stop();
    const addr = l.address();
    const p = try anemo.Peer.connect(gpa, io, addr, .{ .server_name = "sui-35834a8a", .expected = skey.public_key.toBytes(), .identity_seed = @splat(7) });
    defer p.deinit();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for (0..50) |i| {
        var b: [16]u8 = undefined;
        const s = try std.fmt.bufPrint(&b, "hello {d}", .{i});
        const r = try p.request(a, "/zui.Test/Echo", &.{}, s, 5_000);
        try std.testing.expectEqual(wire.Status.success, r.status);
        try std.testing.expectEqualSlices(u8, s, r.body);
    }
    var nb: [4]u8 = undefined;
    std.mem.writeInt(u32, &nb, 3 << 20, .little);
    const big = try p.request(a, "/zui.Test/Big", &.{}, &nb, 20_000);
    try std.testing.expectEqual(@as(usize, 3 << 20), big.body.len);
    for (big.body, 0..) |x, i| if (x != @as(u8, @truncate(i *% 31))) return error.TestUnexpectedResult;
    const nf = try p.request(a, "/sui.Randomness/SendSignatures", &.{}, "", 5_000);
    try std.testing.expectEqual(wire.Status.not_found, nf.status);
    try std.testing.expectEqual(@as(u64, 1), l.stats.accepted.load(.monotonic));
    const peers = try l.inboundPeers(a);
    try std.testing.expectEqual(@as(usize, 1), peers.len);
    const ckey = try Ed25519.KeyPair.generateDeterministic(@splat(7));
    try std.testing.expectEqual(ckey.public_key.toBytes(), peers[0].id);
}

test "a zui client session to the zui listener stays up past 120 s (ZUI_NET_LONG=1)" {
    // Keep-alive against idle timeout over a long quiet session: polls every 5 s (10x sui-node's
    // keep-alive gap) for 125 s, and the connection must never close or be replaced.
    if (std.c.getenv("ZUI_NET_LONG") == null) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const skey = try Ed25519.KeyPair.generateDeterministic(@splat(43));
    var dummy: u8 = 0;
    const l = try Listener.start(gpa, io, .{
        .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) },
        .key = skey,
        .server_name = "sui-35834a8a",
        .handler = .{ .ctx = @ptrCast(&dummy), .serve = TestHandler.serve },
        .threads = 2,
    });
    defer l.stop();
    const p = try anemo.Peer.connect(gpa, io, l.address(), .{ .server_name = "sui-35834a8a", .expected = skey.public_key.toBytes(), .identity_seed = @splat(8) });
    defer p.deinit();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    for (0..25) |i| {
        _ = arena_state.reset(.retain_capacity);
        const r = try p.request(arena_state.allocator(), "/zui.Test/Echo", &.{}, "ping", 5_000);
        try std.testing.expectEqual(wire.Status.success, r.status);
        _ = i;
        try p.pump(5_000);
    }
    try std.testing.expect(!p.conn.isClosed());
    try std.testing.expectEqual(@as(u64, 1), l.stats.accepted.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), l.stats.active.load(.monotonic));
}
