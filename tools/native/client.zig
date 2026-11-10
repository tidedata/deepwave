//! deepwave-native: zui/1 test and bench client (raw QUIC, ALPN zui/1) on net/conn.zig's client role,
//! plus a minimal h2c gRPC client for the same calls on sui.rpc.v2 (bench baseline).
//!
//!   deepwave-native hello      HOST:PORT KEYHEX
//!   deepwave-native get        HOST:PORT KEYHEX OBJECTHEX [VERSION]
//!   deepwave-native checkpoint HOST:PORT KEYHEX SEQ
//!   deepwave-native sub        HOST:PORT KEYHEX checkpoints|address:HEX FROM COUNT
//!   deepwave-native bench      HOST:PORT KEYHEX GRPC_HOST:PORT OBJECTHEX N CP_FROM CP_COUNT [GRPC_TLS_HOST:PORT|-] [CLIENTS=1,8,64]
//!
//! KEYHEX is the server's zui/1 Ed25519 key (line 2 of --native-cert-hash-file).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const net = @import("net");
const native = @import("native");
const serve = @import("serve");
const conn_mod = net.conn;
const proto = native.proto;

var out_buf: [8192]u8 = undefined;

fn parseAddr(text: []const u8) !Io.net.IpAddress {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.BadAddress;
    return Io.net.IpAddress.parse(text[0..colon], try std.fmt.parseInt(u16, text[colon + 1 ..], 10));
}

fn hex32(s: []const u8) ![32]u8 {
    const t = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    var buf: [64]u8 = @splat('0');
    if (t.len > 64) return error.BadHex;
    @memcpy(buf[64 - t.len ..], t);
    var o: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&o, &buf);
    return o;
}

fn nowNs(io: Io) u64 {
    return @intCast(Io.Clock.awake.now(io).toNanoseconds());
}

// ---------------------------------------------------------------- zui/1 over QUIC

const Client = struct {
    gpa: Allocator,
    io: Io,
    sock: Io.net.Socket,
    addr: Io.net.IpAddress,
    c: *conn_mod.Connection,
    bytes_out: u64 = 0,
    bytes_in: u64 = 0,
    us: net.udpio.Sock = undefined,
    small_in: u64 = 0,
    tx: net.udpio.TxBatch = .{},
    rx: net.udpio.RxBatch = .{},

    fn connect(gpa: Allocator, io: Io, addr: Io.net.IpAddress, key: [32]u8) !*Client {
        const cl = try gpa.create(Client);
        var any: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.unspecified(0) };
        const sock = try Io.net.IpAddress.bind(&any, io, .{ .mode = .dgram });
        var seed: [64]u8 = undefined;
        io.random(&seed);
        var idseed: [32]u8 = undefined;
        io.random(&idseed);
        const now_unix: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).toNanoseconds(), std.time.ns_per_s));
        const c = try conn_mod.Connection.init(gpa, .{
            .server_name = "zui",
            .identity_seed = idseed,
            .expected_peer = key,
            .seed = seed,
            .now_unix = now_unix,
            .alpn = &.{proto.alpn},
            .max_streams_uni = 64,
            .max_streams_bidi = 64,
            .keep_alive_ms = 0,
            .pmtu_max = 1452,
        }, nowNs(io));
        cl.* = .{ .gpa = gpa, .io = io, .sock = sock, .addr = addr, .c = c, .us = .init(sock.handle) };
        const deadline = nowNs(io) + 5 * std.time.ns_per_s;
        while (!c.isEstablished()) {
            if (c.isClosed() or nowNs(io) > deadline) return error.HandshakeFailed;
            try cl.pump(10);
        }
        return cl;
    }

    fn send(cl: *Client, now: u64) void {
        while (true) {
            if (cl.tx.full()) cl.tx.flush(&cl.us);
            const n = cl.c.pollTransmit(now, cl.tx.slot()) orelse break;
            cl.tx.commit(n, &cl.addr);
            cl.bytes_out += n;
        }
        cl.tx.flush(&cl.us);
    }

    /// Sends what is queued, then one batched receive that blocks up to `wait_ms` (or the next
    /// timer) for the first datagram: one send and one receive syscall per round trip.
    fn pump(cl: *Client, wait_ms: i32) !void {
        var now = nowNs(cl.io);
        cl.send(now);
        var wait: u64 = @as(u64, @intCast(wait_ms)) * std.time.ns_per_ms;
        if (cl.c.nextTimeout()) |t| wait = @min(wait, t -| now);
        const block = wait >= std.time.ns_per_ms;
        if (block) cl.us.setWait(wait);
        var n = cl.rx.recv(&cl.us, block);
        while (n > 0) {
            now = nowNs(cl.io);
            for (0..n) |i| {
                const d = cl.rx.data(i);
                cl.bytes_in += d.len;
                if (d.len < 1400) cl.small_in += 1;
                cl.c.handleDatagram(now, d);
            }
            if (n < net.udpio.max_batch) break;
            n = cl.rx.recv(&cl.us, false);
        }
        now = nowNs(cl.io);
        if (cl.c.nextTimeout()) |t| if (now >= t) cl.c.onTimeout(now);
        cl.send(now);
    }

    /// One request; returns the whole response (owned by `a`).
    fn request(cl: *Client, a: Allocator, m: proto.Method, flags: u64, body: []const u8) ![]u8 {
        const id = try cl.c.openBidi();
        var req: std.ArrayList(u8) = .empty;
        try proto.encodeRequest(&req, a, m, flags, body);
        try cl.c.streamWrite(id, req.items, true);
        var resp: std.ArrayList(u8) = .empty;
        const deadline = nowNs(cl.io) + 10 * std.time.ns_per_s;
        while (true) {
            const st = cl.c.stream(id) orelse return error.StreamGone;
            const d = st.recv.contiguous();
            if (d.len > 0) {
                try resp.appendSlice(a, d);
                st.recv.consume(d.len);
            }
            if (st.recv.complete()) break;
            if (cl.c.isClosed() or nowNs(cl.io) > deadline) return error.Timeout;
            try cl.pump(5);
        }
        cl.c.streamFree(id);
        return resp.items;
    }
};

fn objectKey(a: Allocator, id: [32]u8, version: ?u64) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    const w: proto.W = .{ .gpa = a, .out = &b };
    try w.fixed(&id);
    if (version) |v| {
        try w.u8_(1);
        try w.int(u64, v);
    } else try w.u8_(0);
    return b.items;
}

fn checkpointReq(a: Allocator, seq: ?u64, parts: u8) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    const w: proto.W = .{ .gpa = a, .out = &b };
    if (seq) |s| {
        try w.uleb(1);
        try w.int(u64, s);
    } else try w.uleb(0);
    try w.u8_(parts);
    return b.items;
}

fn describe(w: *Io.Writer, resp: []const u8) !void {
    const r = proto.parseResponse(resp) orelse return w.print("bad response ({d} bytes)\n", .{resp.len});
    if (r.status != 0) {
        var rr: proto.R = .{ .b = r.body };
        const code = rr.int(u32) catch 0;
        const msg = rr.str() catch "";
        return w.print("error code {d}: {s}\n", .{ code, msg });
    }
    try w.print("ok flags {d} body {d} bytes\n", .{ r.flags, r.body.len });
}

// ---------------------------------------------------------------- subscriptions

const SubResult = struct { frames: u64, checkpoints: u64, bytes: u64, first_ns: u64, total_ns: u64 };

fn subscribe(cl: *Client, a: Allocator, filter: []const u8, from: u64, count: u64, parts: u8, w: ?*Io.Writer) !SubResult {
    var body: std.ArrayList(u8) = .empty;
    const bw: proto.W = .{ .gpa = a, .out = &body };
    if (std.mem.eql(u8, filter, "checkpoints")) try bw.uleb(0) else if (std.mem.startsWith(u8, filter, "address:")) {
        try bw.uleb(1);
        try bw.fixed(&(try hex32(filter[8..])));
        try bw.u8_(0);
    } else return error.BadFilter;
    try bw.uleb(1);
    try bw.int(u64, from);
    try bw.u8_(parts);
    try bw.int(u32, 1024);
    const t0 = nowNs(cl.io);
    const ctrl = try cl.c.openBidi();
    var req: std.ArrayList(u8) = .empty;
    try proto.encodeRequest(&req, a, .subscribe, 0, body.items);
    try cl.c.streamWrite(ctrl, req.items, false);
    var data: ?u64 = null;
    var buf: std.ArrayList(u8) = .empty;
    var res: SubResult = .{ .frames = 0, .checkpoints = 0, .bytes = 0, .first_ns = 0, .total_ns = 0 };
    var got_id = false;
    const deadline = nowNs(cl.io) + 60 * std.time.ns_per_s;
    while (res.checkpoints < count) {
        if (cl.c.isClosed() or nowNs(cl.io) > deadline) return error.Timeout;
        try cl.pump(5);
        if (cl.c.stream(ctrl)) |st| {
            const d = st.recv.contiguous();
            if (d.len > 0) {
                if (d[0] != 0) {
                    if (w) |o| try describe(o, d);
                    return error.SubscribeRejected;
                }
                st.recv.consume(d.len);
            }
        }
        if (data == null) data = cl.c.acceptUni();
        const ds = cl.c.stream(data orelse continue) orelse return error.StreamGone;
        const d = ds.recv.contiguous();
        if (d.len == 0) continue;
        try buf.appendSlice(a, d);
        res.bytes += d.len;
        ds.recv.consume(d.len);
        var p: usize = 0;
        if (!got_id) {
            _ = proto.getVarint(buf.items, &p) orelse continue;
            got_id = true;
        }
        while (res.checkpoints < count) {
            var q = p;
            const ty = proto.getVarint(buf.items, &q) orelse break;
            const len = proto.getVarint(buf.items, &q) orelse break;
            if (buf.items.len - q < len) break;
            const pl = buf.items[q..][0..@intCast(len)];
            p = q + @as(usize, @intCast(len));
            res.frames += 1;
            if (res.first_ns == 0) res.first_ns = nowNs(cl.io) - t0;
            switch (@as(proto.Frame, @enumFromInt(ty))) {
                .checkpoint, .checkpoint_end => {
                    res.checkpoints += 1;
                    if (w) |o| if (ty == 1) try o.print("checkpoint {d} ({d} bytes)\n", .{ std.mem.readInt(u64, pl[0..8], .little), pl.len }) else try o.print("checkpoint_end {d}\n", .{std.mem.readInt(u64, pl[0..8], .little)});
                },
                .tx_match => if (w) |o| try o.print("tx {x} in checkpoint {d} ({d} bytes)\n", .{ pl[0..32], std.mem.readInt(u64, pl[32..40], .little), pl.len }),
                .end => return error.Ended,
                else => {},
            }
        }
        const rest = buf.items.len - p;
        std.mem.copyForwards(u8, buf.items[0..rest], buf.items[p..]);
        buf.shrinkRetainingCapacity(rest);
    }
    res.total_ns = nowNs(cl.io) - t0;
    cl.c.streamFree(ctrl);
    return res;
}

// ---------------------------------------------------------------- h2 gRPC baseline (h2c or TLS 1.3)

/// TLS 1.3 under the gRPC client: std.crypto.tls.Client (no verification: the node's cert is
/// self-signed) over an Io.net.Stream. Heap-held, the client keeps pointers into it.
const GrpcTls = struct {
    stream: Io.net.Stream,
    sr: Io.net.Stream.Reader,
    sw: Io.net.Stream.Writer,
    cl: std.crypto.tls.Client,
    rb: [std.crypto.tls.Client.min_buffer_len]u8,
    wb: [std.crypto.tls.Client.min_buffer_len]u8,
    crb: [std.crypto.tls.Client.min_buffer_len]u8,
    cwb: [std.crypto.tls.Client.min_buffer_len]u8,
};

/// TCP payload bytes sent and received on `fd` (macOS TCP_CONNECTION_INFO: what the wire
/// carried, TLS records included), or null where unavailable.
fn tcpWireBytes(fd: std.c.fd_t) ?u64 {
    if (comptime !@import("builtin").os.tag.isDarwin()) return null;
    var info: [256]u8 align(8) = undefined;
    var len: std.c.socklen_t = info.len;
    if (std.c.getsockopt(fd, std.c.IPPROTO.TCP, 0x106, &info, &len) != 0 or len < 96) return null;
    return std.mem.readInt(u64, info[64..72], .little) + std.mem.readInt(u64, info[88..96], .little);
}

const Grpc = struct {
    fd: std.c.fd_t,
    tls: ?*GrpcTls = null,
    next: u32 = 1,
    bytes_out: u64 = 0,
    bytes_in: u64 = 0,
    rb: std.ArrayList(u8) = .empty,
    gpa: Allocator,
    io: Io,

    fn connect(gpa: Allocator, io: Io, addr: Io.net.IpAddress, use_tls: bool) !Grpc {
        var g: Grpc = undefined;
        if (use_tls) {
            const t = try gpa.create(GrpcTls);
            t.stream = try addr.connect(io, .{ .mode = .stream });
            const one: c_int = 1;
            _ = std.c.setsockopt(t.stream.socket.handle, std.c.IPPROTO.TCP, std.c.TCP.NODELAY, std.mem.asBytes(&one), @sizeOf(c_int));
            t.sr = t.stream.reader(io, &t.rb);
            t.sw = t.stream.writer(io, &t.wb);
            var ent: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
            io.random(&ent);
            t.cl = try std.crypto.tls.Client.init(&t.sr.interface, &t.sw.interface, .{
                .host = .no_verification,
                .ca = .no_verification,
                .read_buffer = &t.crb,
                .write_buffer = &t.cwb,
                .entropy = &ent,
                .realtime_now = Io.Clock.real.now(io),
            });
            g = .{ .fd = t.stream.socket.handle, .tls = t, .gpa = gpa, .io = io };
        } else {
            const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
            if (fd < 0) return error.Socket;
            var sa: std.c.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, addr.ip4.port), .addr = @bitCast(addr.ip4.bytes) };
            if (std.c.connect(fd, @ptrCast(&sa), @sizeOf(std.c.sockaddr.in)) != 0) return error.Connect;
            const one: c_int = 1;
            _ = std.c.setsockopt(fd, std.c.IPPROTO.TCP, std.c.TCP.NODELAY, std.mem.asBytes(&one), @sizeOf(c_int));
            g = .{ .fd = fd, .gpa = gpa, .io = io };
        }
        var pre: std.ArrayList(u8) = .empty;
        defer pre.deinit(gpa);
        try pre.appendSlice(gpa, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        // SETTINGS: INITIAL_WINDOW_SIZE 2^31-1, MAX_FRAME_SIZE 16 MiB - 1
        try frameHdr(&pre, gpa, 12, 0x4, 0, 0);
        try pre.appendSlice(gpa, &.{ 0, 4, 0x7f, 0xff, 0xff, 0xff, 0, 5, 0x00, 0xff, 0xff, 0xff });
        try frameHdr(&pre, gpa, 4, 0x8, 0, 0); // connection WINDOW_UPDATE
        try pre.appendSlice(gpa, &.{ 0x7f, 0xfe, 0xff, 0xff });
        try g.send(pre.items);
        return g;
    }

    fn close(g: *Grpc) void {
        if (g.tls) |t| {
            t.cl.end() catch {};
            t.sw.interface.flush() catch {};
            t.stream.close(g.io);
            g.gpa.destroy(t);
        } else _ = std.c.close(g.fd);
        g.rb.deinit(g.gpa);
    }

    /// Bytes on the wire so far (TCP payload: TLS records included when over TLS).
    fn wire(g: *const Grpc) u64 {
        return tcpWireBytes(g.fd) orelse g.bytes_in + g.bytes_out;
    }

    fn frameHdr(o: *std.ArrayList(u8), gpa: Allocator, len: usize, ty: u8, fl: u8, sid: u32) !void {
        try o.appendSlice(gpa, &.{ @intCast(len >> 16), @intCast((len >> 8) & 0xff), @intCast(len & 0xff), ty, fl });
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, sid, .big);
        try o.appendSlice(gpa, &b);
    }

    fn send(g: *Grpc, b: []const u8) !void {
        g.bytes_out += b.len;
        if (g.tls) |t| {
            try t.cl.writer.writeAll(b);
            try t.cl.writer.flush();
            try t.sw.interface.flush();
            return;
        }
        var off: usize = 0;
        while (off < b.len) {
            const n = std.c.write(g.fd, b[off..].ptr, b.len - off);
            if (n <= 0) return error.Write;
            off += @intCast(n);
        }
    }

    fn fill(g: *Grpc) !void {
        if (g.tls) |t| {
            const got = t.cl.reader.peekGreedy(1) catch return error.Closed;
            g.bytes_in += got.len;
            try g.rb.appendSlice(g.gpa, got);
            t.cl.reader.toss(got.len);
            return;
        }
        var b: [65536]u8 = undefined;
        const n = std.c.read(g.fd, &b, b.len);
        if (n <= 0) return error.Closed;
        g.bytes_in += @intCast(n);
        try g.rb.appendSlice(g.gpa, b[0..@intCast(n)]);
    }

    /// Unary call; returns the response message (gRPC prefix stripped).
    fn call(g: *Grpc, a: Allocator, path: []const u8, msg: []const u8) ![]u8 {
        const sid = g.next;
        g.next += 2;
        var hb: std.ArrayList(u8) = .empty;
        const hp = serve.h2.hpack;
        try hb.append(a, 0x83); // :method POST
        try hb.append(a, if (g.tls != null) 0x87 else 0x86); // :scheme https / http
        try hp.encodeLiteral(&hb, a, ":path", path);
        try hp.encodeLiteral(&hb, a, ":authority", "localhost");
        try hp.encodeLiteral(&hb, a, "content-type", "application/grpc");
        try hp.encodeLiteral(&hb, a, "te", "trailers");
        var o: std.ArrayList(u8) = .empty;
        try frameHdr(&o, a, hb.items.len, 0x1, 0x4, sid);
        try o.appendSlice(a, hb.items);
        try frameHdr(&o, a, msg.len + 5, 0x0, 0x1, sid);
        try o.append(a, 0);
        var l: [4]u8 = undefined;
        std.mem.writeInt(u32, &l, @intCast(msg.len), .big);
        try o.appendSlice(a, &l);
        try o.appendSlice(a, msg);
        try g.send(o.items);
        var body: std.ArrayList(u8) = .empty;
        while (true) {
            while (g.rb.items.len >= 9) {
                const len = (@as(usize, g.rb.items[0]) << 16) | (@as(usize, g.rb.items[1]) << 8) | g.rb.items[2];
                if (g.rb.items.len < 9 + len) break;
                const ty = g.rb.items[3];
                const fl = g.rb.items[4];
                const fsid = std.mem.readInt(u32, g.rb.items[5..9], .big) & 0x7fff_ffff;
                const pl = g.rb.items[9..][0..len];
                var done = false;
                switch (ty) {
                    0x4 => if (fl & 1 == 0) try g.send(&.{ 0, 0, 0, 4, 1, 0, 0, 0, 0 }), // SETTINGS ack
                    0x6 => if (fl & 1 == 0) {
                        var pong: std.ArrayList(u8) = .empty;
                        try frameHdr(&pong, a, 8, 0x6, 1, 0);
                        try pong.appendSlice(a, pl);
                        try g.send(pong.items);
                    },
                    0x0 => if (fsid == sid) {
                        try body.appendSlice(a, pl);
                        if (len > 0) {
                            var wu: std.ArrayList(u8) = .empty;
                            try frameHdr(&wu, a, 4, 0x8, 0, 0);
                            var v: [4]u8 = undefined;
                            std.mem.writeInt(u32, &v, @intCast(len), .big);
                            try wu.appendSlice(a, &v);
                            try g.send(wu.items);
                        }
                        if (fl & 1 != 0) done = true;
                    },
                    0x1 => if (fsid == sid and fl & 1 != 0) {
                        done = true;
                    },
                    0x3, 0x7 => return error.Reset,
                    else => {},
                }
                const rest = g.rb.items.len - 9 - len;
                std.mem.copyForwards(u8, g.rb.items[0..rest], g.rb.items[9 + len ..]);
                g.rb.shrinkRetainingCapacity(rest);
                if (done) return if (body.items.len >= 5) body.items[5..] else body.items;
            }
            try g.fill();
        }
    }
};

fn pbString(o: *std.ArrayList(u8), a: Allocator, field: u8, s: []const u8) !void {
    try o.append(a, field << 3 | 2);
    var x = s.len;
    while (x >= 0x80) : (x >>= 7) try o.append(a, @as(u8, @truncate(x)) | 0x80);
    try o.append(a, @intCast(x));
    try o.appendSlice(a, s);
}

fn pbMask(o: *std.ArrayList(u8), a: Allocator, paths: []const []const u8) !void {
    var m: std.ArrayList(u8) = .empty;
    for (paths) |p| try pbString(&m, a, 1, p);
    try pbString(o, a, 3, m.items);
}

fn pctl(v: []u64, p: usize) f64 {
    std.sort.pdq(u64, v, {}, std.sort.asc(u64));
    return @as(f64, @floatFromInt(v[@min(v.len - 1, v.len * p / 100)])) / 1000.0;
}

// ---------------------------------------------------------------- main

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    var ow = Io.File.stdout().writer(io, &out_buf);
    const w = &ow.interface;
    defer w.flush() catch {};
    if (args.len < 4) {
        try w.print("usage: deepwave-native hello|get|checkpoint|sub|bench HOST:PORT KEYHEX ...\n", .{});
        return 2;
    }
    const cmd = args[1];
    const addr = try parseAddr(args[2]);
    const key = try hex32(args[3]);
    const cl = try Client.connect(gpa, io, addr, key);
    defer {
        cl.c.deinit();
        cl.sock.close(io);
        gpa.destroy(cl);
    }
    if (std.mem.eql(u8, cmd, "hello")) {
        var b: std.ArrayList(u8) = .empty;
        const bw: proto.W = .{ .gpa = a, .out = &b };
        try bw.str("deepwave-native");
        try bw.int(u16, 0);
        try bw.u8_(0);
        const resp = try cl.request(a, .hello, 0, b.items);
        const r = proto.parseResponse(resp) orelse return 1;
        if (r.status != 0) {
            try describe(w, resp);
            return 1;
        }
        var rr: proto.R = .{ .b = r.body };
        const server = try rr.str();
        _ = try rr.int(u16);
        const chain = try rr.fixed(32);
        const lo = try rr.int(u64);
        const hi = try rr.int(u64);
        const ep = try rr.int(u64);
        try w.print("server {s} chain {x} checkpoints {d}..{d} epoch {d}\n", .{ server, chain, lo, hi, ep });
    } else if (std.mem.eql(u8, cmd, "get")) {
        const v: ?u64 = if (args.len > 5) try std.fmt.parseInt(u64, args[5], 10) else null;
        const resp = try cl.request(a, .get_object, proto.flag_verify, try objectKey(a, try hex32(args[4]), v));
        try describe(w, resp);
    } else if (std.mem.eql(u8, cmd, "checkpoint")) {
        const resp = try cl.request(a, .get_checkpoint, 0, try checkpointReq(a, try std.fmt.parseInt(u64, args[4], 10), 0x0f));
        try describe(w, resp);
    } else if (std.mem.eql(u8, cmd, "sub")) {
        const r = try subscribe(cl, a, args[4], try std.fmt.parseInt(u64, args[5], 10), try std.fmt.parseInt(u64, args[6], 10), 0, w);
        try w.print("frames {d} checkpoints {d} bytes {d} first {d:.2} ms total {d:.2} ms\n", .{ r.frames, r.checkpoints, r.bytes, @as(f64, @floatFromInt(r.first_ns)) / 1e6, @as(f64, @floatFromInt(r.total_ns)) / 1e6 });
    } else if (std.mem.eql(u8, cmd, "bench")) {
        try bench(gpa, io, a, cl, w, args);
        try w.print("client path: mtu {d}, {d} datagrams out in {d} send calls, {d} in over {d} receive calls, {d} packets lost, {d} PTOs, {d} datagrams in under 1400 bytes, {d} bytes in\n", .{ cl.c.mtu, cl.us.stats.sent, cl.us.stats.send_calls, cl.us.stats.received, cl.us.stats.recv_calls, cl.c.pkts_lost, cl.c.ptos, cl.small_in, cl.bytes_in });
    } else return 2;
    return 0;
}

// ---------------------------------------------------------------- bench

const Proto = enum {
    zui,
    grpc,
    grpc_tls,
    fn label(p: Proto) []const u8 {
        return switch (p) {
            .zui => "zui/1 (QUIC + TLS 1.3)",
            .grpc => "gRPC h2c (plaintext)",
            .grpc_tls => "gRPC h2 + TLS 1.3",
        };
    }
};

const BenchCfg = struct {
    io: Io,
    zaddr: Io.net.IpAddress,
    key: [32]u8,
    gaddr: Io.net.IpAddress,
    taddr: ?Io.net.IpAddress,
    zreq: []const u8, // zui/1 get_object body
    greq: []const u8, // gRPC GetObject message
};

/// One client: its own connection (QUIC, or TCP), on its own thread, `lat.len` GetObject calls
/// after the start signal.
const Worker = struct {
    cfg: *const BenchCfg,
    proto: Proto,
    lat: []u64,
    ready: *std.atomic.Value(u32),
    go: *std.atomic.Value(bool),
    wire: u64 = 0,
    err: ?anyerror = null,

    fn main(wk: *Worker) void {
        interactiveQos();
        var readied = false;
        wk.run(&readied) catch |e| {
            wk.err = e;
        };
        if (!readied) _ = wk.ready.fetchAdd(1, .release);
    }

    fn waitGo(wk: *Worker, readied: *bool) void {
        readied.* = true;
        _ = wk.ready.fetchAdd(1, .release);
        while (!wk.go.load(.acquire)) std.Thread.yield() catch {};
    }

    fn run(wk: *Worker, readied: *bool) !void {
        const gpa = std.heap.smp_allocator;
        const io = wk.cfg.io;
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        switch (wk.proto) {
            .zui => {
                const cl = try Client.connect(gpa, io, wk.cfg.zaddr, wk.cfg.key);
                defer {
                    cl.c.deinit();
                    cl.sock.close(io);
                    gpa.destroy(cl);
                }
                _ = try cl.request(a, .get_object, 0, wk.cfg.zreq); // warm
                wk.waitGo(readied);
                const b0 = cl.bytes_in + cl.bytes_out;
                for (wk.lat) |*l| {
                    _ = arena.reset(.retain_capacity);
                    const t = nowNs(io);
                    const r = try cl.request(a, .get_object, 0, wk.cfg.zreq);
                    l.* = nowNs(io) - t;
                    if (r.len < 3 or r[0] != 0) return error.BadResponse;
                }
                wk.wire = cl.bytes_in + cl.bytes_out - b0;
            },
            .grpc, .grpc_tls => {
                const tls = wk.proto == .grpc_tls;
                var g = try Grpc.connect(gpa, io, if (tls) wk.cfg.taddr.? else wk.cfg.gaddr, tls);
                defer g.close();
                _ = try g.call(a, "/sui.rpc.v2.LedgerService/GetObject", wk.cfg.greq); // warm
                wk.waitGo(readied);
                const b0 = g.wire();
                for (wk.lat) |*l| {
                    _ = arena.reset(.retain_capacity);
                    const t = nowNs(io);
                    const r = try g.call(a, "/sui.rpc.v2.LedgerService/GetObject", wk.cfg.greq);
                    l.* = nowNs(io) - t;
                    if (r.len == 0) return error.BadResponse;
                }
                wk.wire = g.wire() - b0;
            },
        }
    }
};

/// macOS: run bench threads at QOS_CLASS_USER_INTERACTIVE like the main thread, so a woken
/// client is not parked on an efficiency core (every protocol gets the same treatment).
fn interactiveQos() void {
    if (comptime @import("builtin").os.tag.isDarwin()) {
        const f = @extern(*const fn (c_uint, c_int) callconv(.c) c_int, .{ .name = "pthread_set_qos_class_self_np" });
        _ = f(0x21, 0);
    }
}

const LoadResult = struct { p50: f64, p99: f64, p999: f64, rps: f64, wire_per_call: u64 };

fn pctlF(v: []u64, permille: usize) f64 {
    return @as(f64, @floatFromInt(v[@min(v.len - 1, v.len * permille / 1000)])) / 1000.0;
}

/// `clients` concurrent clients, `per` calls each; latencies of all calls merged.
fn load(gpa: Allocator, cfg: *const BenchCfg, p: Proto, clients: usize, per: usize) !LoadResult {
    const lat = try gpa.alloc(u64, clients * per);
    defer gpa.free(lat);
    const ws = try gpa.alloc(Worker, clients);
    defer gpa.free(ws);
    const ts = try gpa.alloc(std.Thread, clients);
    defer gpa.free(ts);
    var ready: std.atomic.Value(u32) = .init(0);
    var go: std.atomic.Value(bool) = .init(false);
    for (ws, ts, 0..) |*wk, *t, i| {
        wk.* = .{ .cfg = cfg, .proto = p, .lat = lat[i * per ..][0..per], .ready = &ready, .go = &go };
        t.* = try std.Thread.spawn(.{ .stack_size = 4 << 20 }, Worker.main, .{wk});
    }
    while (ready.load(.acquire) < clients) std.Thread.yield() catch {};
    const t0 = nowNs(cfg.io);
    go.store(true, .release);
    for (ts) |t| t.join();
    const wall = nowNs(cfg.io) - t0;
    var wire: u64 = 0;
    for (ws) |wk| {
        if (wk.err) |e| return e;
        wire += wk.wire;
    }
    std.sort.pdq(u64, lat, {}, std.sort.asc(u64));
    return .{
        .p50 = pctlF(lat, 500),
        .p99 = pctlF(lat, 990),
        .p999 = pctlF(lat, 999),
        .rps = @as(f64, @floatFromInt(clients * per)) * 1e9 / @as(f64, @floatFromInt(wall)),
        .wire_per_call = wire / (clients * per),
    };
}

fn cpMask(a: Allocator, seq: u64) ![]u8 {
    var cm: std.ArrayList(u8) = .empty;
    try cm.append(a, 0x08);
    var x = seq;
    while (x >= 0x80) : (x >>= 7) try cm.append(a, @as(u8, @truncate(x)) | 0x80);
    try cm.append(a, @intCast(x));
    try pbMask(&cm, a, &.{ "sequence_number", "summary.bcs", "signature", "contents.bcs", "transactions.transaction.bcs", "transactions.effects.bcs", "transactions.events.bcs" });
    return cm.items;
}

fn cpRow(w: *Io.Writer, label: []const u8, mode: []const u8, n: u64, ns: u64, wire: u64, p50: ?f64, p99: ?f64) !void {
    const ms = @as(f64, @floatFromInt(ns)) / 1e6;
    const secs = @as(f64, @floatFromInt(ns)) / 1e9;
    try w.print("| {s} | {s} | {d:.1} | {d:.0} | {d:.1} | {d} |", .{ label, mode, ms * 1000.0 / @as(f64, @floatFromInt(n)), @as(f64, @floatFromInt(n)) / secs, @as(f64, @floatFromInt(wire)) / 1e6 / secs, wire / n });
    if (p50) |x| try w.print(" {d:.0} / {d:.0} |\n", .{ x, p99.? }) else try w.print(" - |\n", .{});
}

/// deepwave-native bench HOST:PORT KEYHEX GRPC_HOST:PORT OBJECTHEX N CP_FROM CP_COUNT [GRPC_TLS_HOST:PORT|-] [CLIENTS]
/// N: GetObject calls per client; CLIENTS: comma list (default 1,8,64).
fn bench(gpa: Allocator, io: Io, a: Allocator, cl: *Client, w: *Io.Writer, args: []const []const u8) !void {
    const gaddr = try parseAddr(args[4]);
    const obj = try hex32(args[5]);
    const n = try std.fmt.parseInt(usize, args[6], 10);
    const cp_from = try std.fmt.parseInt(u64, args[7], 10);
    const cp_n = try std.fmt.parseInt(u64, args[8], 10);
    const taddr: ?Io.net.IpAddress = if (args.len > 9 and !std.mem.eql(u8, args[9], "-")) try parseAddr(args[9]) else null;
    const clist = if (args.len > 10) args[10] else "1,8,64";
    var hexid: [66]u8 = undefined;
    _ = try std.fmt.bufPrint(&hexid, "0x{x}", .{&obj});
    var m: std.ArrayList(u8) = .empty;
    try pbString(&m, a, 1, &hexid);
    try pbMask(&m, a, &.{ "object_id", "version", "digest", "bcs" });
    const cfg: BenchCfg = .{ .io = io, .zaddr = cl.addr, .key = try hex32(args[3]), .gaddr = gaddr, .taddr = taddr, .zreq = try objectKey(a, obj, null), .greq = m.items };

    try w.print("\n### GetObject {x} ({d} calls per client, one connection per client)\n\n", .{ obj[30..32], n });
    try w.print("| protocol | clients | p50 us | p99 us | p999 us | req/s | wire bytes/call |\n|---|---:|---:|---:|---:|---:|---:|\n", .{});
    var it = std.mem.splitScalar(u8, clist, ',');
    while (it.next()) |cs| {
        const c = try std.fmt.parseInt(usize, cs, 10);
        for ([_]Proto{ .zui, .grpc, .grpc_tls }) |p| {
            if (p == .grpc_tls and taddr == null) continue;
            const r = load(gpa, &cfg, p, c, n) catch |e| {
                try w.print("| {s} | {d} | error {s} | | | | |\n", .{ p.label(), c, @errorName(e) });
                try w.flush();
                continue;
            };
            try w.print("| {s} | {d} | {d:.1} | {d:.1} | {d:.1} | {d:.0} | {d} |\n", .{ p.label(), c, r.p50, r.p99, r.p999, r.rps, r.wire_per_call });
            try w.flush();
        }
    }

    try w.print("\n### Checkpoints {d}..{d}, full data (summary, signature, contents, transactions, effects, events), one client\n\n", .{ cp_from, cp_from + cp_n - 1 });
    try w.print("| protocol | mode | us/checkpoint | checkpoints/s | wire MB/s | wire bytes/checkpoint | p50 / p99 us |\n|---|---|---:|---:|---:|---:|---|\n", .{});
    // Warm pass (untimed): every row then reads the same decoded chunks from the store's cache,
    // instead of the first row paying the zstd decode of a cold range.
    _ = try subscribe(cl, a, "checkpoints", cp_from, cp_n, 0x0f, null);
    // zui/1 subscription replay
    var b0 = cl.bytes_in + cl.bytes_out;
    const sr = try subscribe(cl, a, "checkpoints", cp_from, cp_n, 0x0f, null);
    try cpRow(w, Proto.zui.label(), "subscribe From(seq)", cp_n, sr.total_ns, cl.bytes_in + cl.bytes_out - b0, null, null);
    const lat = try a.alloc(u64, @intCast(cp_n));
    // zui/1 get_checkpoint request/response
    b0 = cl.bytes_in + cl.bytes_out;
    var t0 = nowNs(io);
    for (lat, 0..) |*l, i| {
        const t = nowNs(io);
        _ = try cl.request(a, .get_checkpoint, 0, try checkpointReq(a, cp_from + i, 0x0f));
        l.* = nowNs(io) - t;
    }
    try cpRow(w, Proto.zui.label(), "get_checkpoint x N", cp_n, nowNs(io) - t0, cl.bytes_in + cl.bytes_out - b0, pctl(lat, 50), pctl(lat, 99));
    try w.flush();
    // gRPC GetCheckpoint, plaintext and TLS
    for ([_]Proto{ .grpc, .grpc_tls }) |p| {
        if (p == .grpc_tls and taddr == null) continue;
        var g = try Grpc.connect(gpa, io, if (p == .grpc_tls) taddr.? else gaddr, p == .grpc_tls);
        defer g.close();
        _ = try g.call(a, "/sui.rpc.v2.LedgerService/GetCheckpoint", try cpMask(a, cp_from));
        const gb0 = g.wire();
        t0 = nowNs(io);
        for (lat, 0..) |*l, i| {
            const req = try cpMask(a, cp_from + i);
            const t = nowNs(io);
            _ = try g.call(a, "/sui.rpc.v2.LedgerService/GetCheckpoint", req);
            l.* = nowNs(io) - t;
        }
        try cpRow(w, p.label(), "GetCheckpoint x N", cp_n, nowNs(io) - t0, g.wire() - gb0, pctl(lat, 50), pctl(lat, 99));
        try w.flush();
    }
}
