//! Tests of the listener's certificates against real handshakes (certs.zig, NATIVE-PROTOCOL.md
//! 1.3): net/conn.zig's client checks the certificate the way a browser checks
//! `serverCertificateHashes` (tls13.Trust.hashes).
const std = @import("std");
const Io = std.Io;
const net = @import("net");
const udpio = net.udpio;
const conn_mod = net.conn;
const store = @import("store");
const proto = @import("proto.zig");
const dispatch = @import("dispatch.zig");
const listener = @import("listener.zig");
const certhttp = @import("certhttp.zig");
const certs = @import("certs.zig");

/// A store, a dispatcher and what a listener needs around them.
pub const Rig = struct {
    gpa: std.mem.Allocator,
    threaded: Io.Threaded,
    cfg: store.Config,
    sim: *store.SimIo,
    st: *store.Store,
    svc: @import("serve").service.Service,
    disp: dispatch.Dispatcher,

    pub fn init(r: *Rig, gpa: std.mem.Allocator) !void {
        r.gpa = gpa;
        r.threaded = .init(gpa, .{});
        r.cfg = .{ .max_live_objects = 1 << 10, .max_object_versions = 1 << 11, .max_transactions = 1 << 10, .max_checkpoints = 16, .max_batch_bytes = 16 << 20, .max_batch_objects = 1 << 10, .max_segments = 16, .segment_reserve = 4 << 20, .seed = 5 };
        r.sim = try store.SimIo.init(gpa, 11, .{}, 32 << 20);
        r.st = try store.Store.open(gpa, .{ .sim = r.sim }, &r.cfg);
        r.svc = .{ .gpa = gpa, .store = r.st, .chain_id = @splat(0x5a) };
        r.disp = .{ .svc = &r.svc };
    }

    pub fn deinit(r: *Rig) void {
        r.svc.deinit();
        r.st.deinit();
        r.sim.deinit();
        r.threaded.deinit();
    }

    pub fn io(r: *Rig) Io {
        return r.threaded.io();
    }
};

/// One client connection to a listener on loopback.
pub const Client = struct {
    io: Io,
    sock: Io.net.Socket,
    us: udpio.Sock,
    to: Io.net.IpAddress,
    c: *conn_mod.Connection,
    tx: *udpio.TxBatch,
    rx: *udpio.RxBatch,

    pub fn open(gpa: std.mem.Allocator, io: Io, to: Io.net.IpAddress, cfg: conn_mod.Config) !Client {
        var lo: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
        const sock = try Io.net.IpAddress.bind(&lo, io, .{ .mode = .dgram });
        errdefer sock.close(io);
        const c = try conn_mod.Connection.init(gpa, cfg, @intCast(Io.Clock.awake.now(io).toNanoseconds()));
        errdefer c.deinit();
        const tx = try gpa.create(udpio.TxBatch);
        errdefer gpa.destroy(tx);
        const rx = try gpa.create(udpio.RxBatch);
        tx.* = .{};
        rx.* = .{};
        return .{ .io = io, .sock = sock, .us = .init(sock.handle), .to = to, .c = c, .tx = tx, .rx = rx };
    }

    pub fn close(t: *Client, gpa: std.mem.Allocator) void {
        t.c.deinit();
        gpa.destroy(t.tx);
        gpa.destroy(t.rx);
        t.sock.close(t.io);
    }

    pub fn pump(t: *Client) void {
        var now: u64 = @intCast(Io.Clock.awake.now(t.io).toNanoseconds());
        while (t.c.pollTransmit(now, t.tx.slot())) |n| {
            t.tx.commit(n, &t.to);
            if (t.tx.full()) t.tx.flush(&t.us);
        }
        t.tx.flush(&t.us);
        t.us.setWait(5 * std.time.ns_per_ms);
        const n = t.rx.recv(&t.us, true);
        now = @intCast(Io.Clock.awake.now(t.io).toNanoseconds());
        for (0..n) |i| t.c.handleDatagram(now, t.rx.data(i));
        if (t.c.nextTimeout()) |d| if (now >= d) t.c.onTimeout(now);
    }

    /// Runs the handshake: true when established, false when it failed (the connection closed).
    pub fn handshake(t: *Client) !bool {
        var rounds: usize = 0;
        while (!t.c.isEstablished()) : (rounds += 1) {
            if (t.c.isClosed()) return false;
            if (rounds > 2000) return error.TestUnexpectedResult;
            t.pump();
        }
        return true;
    }

    /// One zui/1 request on a raw `zui/1` connection; the response bytes (caller frees).
    pub fn request(t: *Client, gpa: std.mem.Allocator, method: proto.Method, body: []const u8) ![]u8 {
        var rounds: usize = 0;
        const id = while (true) : (rounds += 1) {
            if (t.c.openBidi()) |id| break id else |_| {}
            if (rounds > 2000) return error.TestUnexpectedResult;
            t.pump();
        };
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(gpa);
        try proto.encodeRequest(&req, gpa, method, 0, body);
        try t.c.streamWrite(id, req.items, true);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        rounds = 0;
        while (true) : (rounds += 1) {
            const st = t.c.stream(id) orelse return error.TestUnexpectedResult;
            const data = st.recv.contiguous();
            if (data.len > 0) {
                try out.appendSlice(gpa, data);
                st.recv.consume(data.len);
            }
            if (st.recv.complete()) break;
            if (rounds > 4000 or t.c.isClosed()) return error.TestUnexpectedResult;
            t.pump();
        }
        t.c.streamFree(id);
        return out.toOwnedSlice(gpa);
    }
};

/// A browser's connection: ALPN `h3`, the certificate pinned by hash, the page's clock `now_unix`.
pub fn browser(gpa: std.mem.Allocator, io: Io, to: Io.net.IpAddress, hashes: []const [32]u8, now_unix: i64, salt: u8) !Client {
    var seed: [64]u8 = @splat(salt);
    seed[1] = 0x42;
    return Client.open(gpa, io, to, .{
        .server_name = "localhost",
        .identity_seed = @splat(4),
        .trust = .{ .hashes = hashes },
        .seed = seed,
        .now_unix = now_unix,
        .alpn = &.{"h3"},
        .max_streams_uni = 16,
        .max_streams_bidi = 64,
        .keep_alive_ms = 0,
    });
}

/// `request` (one HTTP/1.1 request head) to 127.0.0.1:`port`; the whole answer (caller frees).
pub fn httpGet(gpa: std.mem.Allocator, port: u16, request: []const u8) ![]u8 {
    const c = std.c;
    const fd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    if (fd < 0) return error.Socket;
    defer _ = c.close(fd);
    var sa: c.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) };
    if (c.connect(fd, @ptrCast(&sa), @sizeOf(c.sockaddr.in)) != 0) return error.Connect;
    var off: usize = 0;
    while (off < request.len) {
        const k = c.write(fd, request[off..].ptr, request.len - off);
        if (k <= 0) return error.Write;
        off += @intCast(k);
    }
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var buf: [2048]u8 = undefined;
    while (true) {
        const k = c.read(fd, &buf, buf.len);
        if (k <= 0) break;
        try out.appendSlice(gpa, buf[0..@intCast(k)]);
    }
    return out.toOwnedSlice(gpa);
}

fn httpBody(resp: []const u8) []const u8 {
    const at = std.mem.indexOf(u8, resp, "\r\n\r\n") orelse return "";
    return resp[at + 4 ..];
}

test "zui/1 listener: a pinned hash connects until the rotation and not after; both published hashes connect across it; open connections go on" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    const io = rig.io();
    const p0 = certs.periodOf(1_800_000_000);
    const boundary = (p0 + 1) * certs.period_s;
    var tc = certs.TestClock.init(boundary - 3 * 86400);
    const cs = try certs.Certs.init(gpa, io, .{ .seed = @splat(9), .clock = tc.clock() });
    defer cs.deinit();
    const l = try listener.Listener.start(gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = @splat(9), .certs = cs }, &rig.disp);
    defer l.stop();
    const v = cs.view();
    const old = v.sha256[0];
    const next = v.sha256[1];

    // a page that fetched /native/cert-hash connects, and stays connected through the test
    var first = try browser(gpa, io, l.address(), &.{old}, boundary - 3 * 86400, 1);
    defer first.close(gpa);
    try std.testing.expect(try first.handshake());
    try std.testing.expectEqual(old, first.c.tls.peer_cert_sha256.?);
    // a hash that is not the node's is refused by the client
    {
        var wrong = try browser(gpa, io, l.address(), &.{@as([32]u8, @splat(0xee))}, boundary - 3 * 86400, 2);
        defer wrong.close(gpa);
        try std.testing.expect(!try wrong.handshake());
    }
    // the last second of the period: the old hash still connects
    tc.set(boundary - 1);
    try std.testing.expect(!cs.tick());
    {
        var c = try browser(gpa, io, l.address(), &.{old}, boundary - 1, 3);
        defer c.close(gpa);
        try std.testing.expect(try c.handshake());
        try std.testing.expectEqual(old, c.c.tls.peer_cert_sha256.?);
    }
    // the rotation
    tc.set(boundary);
    try std.testing.expect(cs.tick());
    try std.testing.expectEqual(next, cs.view().sha256[0]);
    // the old hash alone no longer connects: the node presents the new certificate
    {
        var c = try browser(gpa, io, l.address(), &.{old}, boundary, 4);
        defer c.close(gpa);
        try std.testing.expect(!try c.handshake());
        try std.testing.expectEqual(next, c.c.tls.peer_cert_sha256.?);
    }
    // a page that pinned both hashes of /native/cert-hashes before the rotation connects
    {
        var c = try browser(gpa, io, l.address(), &.{ old, next }, boundary, 5);
        defer c.close(gpa);
        try std.testing.expect(try c.handshake());
        try std.testing.expectEqual(next, c.c.tls.peer_cert_sha256.?);
    }
    // and so does one that asks again
    {
        var c = try browser(gpa, io, l.address(), &.{cs.view().sha256[0]}, boundary + 60, 6);
        defer c.close(gpa);
        try std.testing.expect(try c.handshake());
    }
    // the connection made before the rotation is still up
    for (0..20) |_| first.pump();
    try std.testing.expect(first.c.isEstablished() and !first.c.isClosed());
    // a raw zui/1 client (pinned Ed25519 identity) is not touched by any of this
    {
        var seed: [64]u8 = @splat(7);
        seed[0] = 1;
        var c = try Client.open(gpa, io, l.address(), .{
            .server_name = "zui",
            .identity_seed = @splat(4),
            .expected_peer = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(9))).public_key.toBytes(),
            .seed = seed,
            .now_unix = boundary,
            .alpn = &.{proto.alpn},
            .keep_alive_ms = 0,
        });
        defer c.close(gpa);
        try std.testing.expect(try c.handshake());
        const resp = try c.request(gpa, .hello, &.{ 0, 0, 0, 0 });
        defer gpa.free(resp);
        try std.testing.expectEqual(@as(u8, 0), resp[0]);
    }
}

test "zui/1 cert hash endpoint: /native/cert-hash, /native/cert-hashes and the hash file change together at a rotation" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(io, &pb);
    var fb: [std.fs.max_path_bytes]u8 = undefined;
    const file = try std.fmt.bufPrint(&fb, "{s}/native.hash", .{pb[0..n]});
    const p0 = certs.periodOf(1_800_000_000);
    var tc = certs.TestClock.init(p0 * certs.period_s + 3600);
    const cs = try certs.Certs.init(gpa, io, .{ .seed = @splat(6), .clock = tc.clock(), .hash_file = file });
    defer cs.deinit();
    const srv = try certhttp.Server.startCerts(gpa, .{ 127, 0, 0, 1 }, 0, cs, null);
    defer srv.stop(gpa);
    const port = srv.boundPort();
    var want: [2][64]u8 = undefined;
    for (0..2) |round| {
        const v = cs.view();
        for (&want, 0..) |*w, i| w.* = std.fmt.bytesToHex(v.sha256[i], .lower);
        // exactly 64 hex characters, no newline: deployed pages pass the whole body as the hash
        const one = try httpGet(gpa, port, "GET /native/cert-hash HTTP/1.1\r\nhost: x\r\n\r\n");
        defer gpa.free(one);
        try std.testing.expect(std.mem.startsWith(u8, one, "HTTP/1.1 200 OK\r\n"));
        try std.testing.expect(std.mem.indexOf(u8, one, "access-control-allow-origin: *\r\n") != null);
        try std.testing.expect(std.mem.indexOf(u8, one, "cache-control: no-store\r\n") != null);
        try std.testing.expect(std.mem.indexOf(u8, one, "content-length: 64\r\n") != null);
        try std.testing.expectEqualStrings(&want[0], httpBody(one));
        const head = try httpGet(gpa, port, "HEAD /native/cert-hash HTTP/1.1\r\n\r\n");
        defer gpa.free(head);
        try std.testing.expect(std.mem.indexOf(u8, head, "content-length: 64\r\n") != null);
        try std.testing.expectEqualStrings("", httpBody(head));
        // the current and the next certificate, with the seconds between which each is presented
        const all = try httpGet(gpa, port, "GET /native/cert-hashes HTTP/1.1\r\n\r\n");
        defer gpa.free(all);
        var eb: [256]u8 = undefined;
        const expect = try std.fmt.bufPrint(&eb, "{s} {d} {d}\n{s} {d} {d}\n", .{ &want[0], v.from[0], v.until[0], &want[1], v.from[1], v.until[1] });
        try std.testing.expectEqualStrings(expect, httpBody(all));
        try std.testing.expectEqual(v.until[0], v.from[1]);
        // the file says the same
        const f = try certs.readHashFile(gpa, file);
        defer gpa.free(f.text);
        try std.testing.expectEqualStrings(&want[0], f.lines[0]);
        try std.testing.expectEqualStrings(&want[1], f.lines[2]);
        if (round == 0) {
            const next = want[1];
            tc.set((p0 + 1) * certs.period_s);
            try std.testing.expect(cs.tick());
            try std.testing.expectEqualStrings(&next, &std.fmt.bytesToHex(cs.view().sha256[0], .lower));
        }
    }
    const other = try httpGet(gpa, port, "GET /native/other HTTP/1.1\r\n\r\n");
    defer gpa.free(other);
    try std.testing.expect(std.mem.startsWith(u8, other, "HTTP/1.1 404 "));
}

// ---------------------------------------------------------------- --native-cert (a real chain)

const cert_mod = @import("cert.zig");
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// A local CA and the leaves it signs, as PEM files in a temporary directory.
pub const Pki = struct {
    gpa: std.mem.Allocator,
    io: Io,
    tmp: std.testing.TmpDir,
    dir_buf: [std.fs.max_path_bytes]u8 = undefined,
    dir: []const u8 = "",
    ca_key: P256.KeyPair,
    ca_buf: [cert_mod.max_len]u8 = undefined,
    ca: []const u8 = "",
    serial: u8 = 10,

    const ca_name = "zui test CA";

    pub fn init(p: *Pki, gpa: std.mem.Allocator, io: Io, now: i64) !void {
        p.* = .{ .gpa = gpa, .io = io, .tmp = std.testing.tmpDir(.{}), .ca_key = try P256.KeyPair.generateDeterministic(@splat(0x21)) };
        const n = try p.tmp.dir.realPath(io, &p.dir_buf);
        p.dir = p.dir_buf[0..n];
        p.ca = cert_mod.issue(&p.ca_buf, .{ .subject = p.ca_key.public_key, .signer = p.ca_key, .subject_cn = ca_name, .issuer_cn = ca_name, .serial = @splat(1), .not_before = now - 30 * 86400, .not_after = now + 365 * 86400, .ca = true });
    }

    pub fn deinit(p: *Pki) void {
        p.tmp.cleanup();
    }

    /// A leaf for `key` named `dns`, valid from `nb` to `na`, signed by the CA.
    pub fn leaf(p: *Pki, buf: *[cert_mod.max_len]u8, key: P256.KeyPair, dns: []const u8, nb: i64, na: i64) []const u8 {
        p.serial += 1;
        return cert_mod.issue(buf, .{ .subject = key.public_key, .signer = p.ca_key, .subject_cn = dns, .issuer_cn = ca_name, .serial = @splat(p.serial), .not_before = nb, .not_after = na, .dns = dns });
    }

    pub fn path(p: *Pki, buf: []u8, name: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ p.dir, name }) catch unreachable;
    }

    /// `text` at `name`, the way an ACME client replaces a file: a new file renamed over it.
    pub fn put(p: *Pki, name: []const u8, text: []const u8) !void {
        try p.tmp.dir.writeFile(p.io, .{ .sub_path = "new.tmp", .data = text });
        try p.tmp.dir.rename("new.tmp", p.tmp.dir, name, p.io);
    }

    /// The chain file (`certs` as PEM blocks, in order) and the key file (SEC1 `EC PRIVATE KEY`).
    pub fn putPair(p: *Pki, cert_name: []const u8, key_name: []const u8, chain: []const []const u8, key: P256.KeyPair) !void {
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(p.gpa);
        for (chain) |der| try pemBlock(&text, p.gpa, "CERTIFICATE", der);
        try p.put(cert_name, text.items);
        text.clearRetainingCapacity();
        // SEC1 ECPrivateKey: SEQ { INTEGER 1, OCTET STRING d, [0] OID prime256v1 }
        var sec1: [51]u8 = undefined;
        sec1[0..7].* = .{ 0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20 };
        sec1[7..39].* = key.secret_key.toBytes();
        sec1[39..51].* = .{ 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
        try pemBlock(&text, p.gpa, "EC PRIVATE KEY", &sec1);
        try p.put(key_name, text.items);
    }
};

pub fn pemBlock(out: *std.ArrayList(u8), gpa: std.mem.Allocator, label: []const u8, der: []const u8) !void {
    const enc = std.base64.standard.Encoder;
    try out.print(gpa, "-----BEGIN {s}-----\n", .{label});
    const b64 = try gpa.alloc(u8, enc.calcSize(der.len));
    defer gpa.free(b64);
    _ = enc.encode(b64, der);
    var off: usize = 0;
    while (off < b64.len) : (off += 64) {
        try out.appendSlice(gpa, b64[off..@min(off + 64, b64.len)]);
        try out.append(gpa, '\n');
    }
    try out.print(gpa, "-----END {s}-----\n", .{label});
}

pub fn sha(der: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    Sha256.hash(der, &h, .{});
    return h;
}

/// A WebPKI client: ALPN `alpn`, the chain checked against `roots`, the leaf named `host`.
fn webpki(gpa: std.mem.Allocator, io: Io, to: Io.net.IpAddress, alpn: []const u8, host: []const u8, roots: []const []const u8, now_unix: i64, salt: u8) !Client {
    var seed: [64]u8 = @splat(salt);
    seed[1] = 0x43;
    return Client.open(gpa, io, to, .{
        .server_name = host,
        .identity_seed = @splat(4),
        .trust = .{ .roots = roots },
        .seed = seed,
        .now_unix = now_unix,
        .alpn = &.{alpn},
        .max_streams_uni = 16,
        .max_streams_bidi = 64,
        .keep_alive_ms = 0,
    });
}

test "--native-cert: the files are checked at start (chain, key, validity), and nothing rotates" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const now: i64 = 1_800_000_000;
    var pki: Pki = undefined;
    try pki.init(gpa, io, now);
    defer pki.deinit();
    const key_a = try P256.KeyPair.generateDeterministic(@splat(0x31));
    const key_b = try P256.KeyPair.generateDeterministic(@splat(0x32));
    var la: [cert_mod.max_len]u8 = undefined;
    const leaf_a = pki.leaf(&la, key_a, "node.test", now - 86400, now + 60 * 86400);
    var cb: [std.fs.max_path_bytes]u8 = undefined;
    var kb: [std.fs.max_path_bytes]u8 = undefined;
    var hb: [std.fs.max_path_bytes]u8 = undefined;
    const files: certs.Files = .{ .cert = pki.path(&cb, "chain.pem"), .key = pki.path(&kb, "key.pem") };
    const hash_file = pki.path(&hb, "native.hash");
    var tc = certs.TestClock.init(now);
    const id_key: [32]u8 = @splat(0xcd);
    const opts: certs.Options = .{ .seed = @splat(5), .clock = tc.clock(), .files = files, .hash_file = hash_file, .identity_key = id_key, .poll_ticks = 1 };

    // a leaf and its CA, with the leaf's key
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, pki.ca }, key_a);
    {
        const cs = try certs.Certs.init(gpa, io, opts);
        defer cs.deinit();
        try std.testing.expectEqual(@as(u8, 0), cs.view().n); // no hash to pin
        try std.testing.expectEqual(@as(usize, 2), cs.cur.chain.?.certs.len);
        try std.testing.expectEqual(sha(leaf_a), cs.cur.sha256);
        try std.testing.expectEqual(now + 60 * 86400, cs.stats.not_after.load(.acquire));
        // the hash file: an empty first line (nothing to pin), then the zui/1 key
        const f = try certs.readHashFile(gpa, hash_file);
        defer gpa.free(f.text);
        try std.testing.expectEqualStrings("", f.lines[0]);
        try std.testing.expectEqualStrings(&std.fmt.bytesToHex(id_key, .lower), f.lines[1]);
        try std.testing.expectEqualStrings("", f.lines[2]);
        // weeks pass: the same certificate, no rotation, no reload (the files did not change)
        for (1..5) |k| {
            tc.set(now + @as(i64, @intCast(k)) * certs.period_s);
            try std.testing.expect(!cs.tick());
        }
        try std.testing.expectEqual(sha(leaf_a), cs.cur.sha256);
        try std.testing.expectEqual(@as(u64, 0), cs.stats.rotations.load(.monotonic));
        try std.testing.expectEqual(@as(u64, 0), cs.stats.reloads.load(.monotonic));
        tc.set(now);
    }
    // the leaf alone is a chain too
    try pki.putPair("chain.pem", "key.pem", &.{leaf_a}, key_a);
    {
        const cs = try certs.Certs.init(gpa, io, opts);
        defer cs.deinit();
        try std.testing.expectEqual(@as(usize, 1), cs.cur.chain.?.certs.len);
    }
    // a key that is not the leaf's
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, pki.ca }, key_b);
    try std.testing.expectError(error.KeyMismatch, certs.Certs.init(gpa, io, opts));
    // expired, and not valid yet
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, pki.ca }, key_a);
    tc.set(now + 60 * 86400 + 1);
    try std.testing.expectError(error.CertificateExpired, certs.Certs.init(gpa, io, opts));
    tc.set(now - 86400 - 1);
    try std.testing.expectError(error.CertificateNotYetValid, certs.Certs.init(gpa, io, opts));
    tc.set(now);
    // the leaf followed by a certificate that did not issue it: another name, then the right
    // name with another key
    {
        const other_key = try P256.KeyPair.generateDeterministic(@splat(0x41));
        var ob: [cert_mod.max_len]u8 = undefined;
        const other = cert_mod.issue(&ob, .{ .subject = other_key.public_key, .signer = other_key, .subject_cn = "someone else", .issuer_cn = "someone else", .serial = @splat(2), .not_before = now - 86400, .not_after = now + 86400, .ca = true });
        try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, other }, key_a);
        try std.testing.expectError(error.ChainOutOfOrder, certs.Certs.init(gpa, io, opts));
        var ib: [cert_mod.max_len]u8 = undefined;
        const impostor = cert_mod.issue(&ib, .{ .subject = other_key.public_key, .signer = other_key, .subject_cn = Pki.ca_name, .issuer_cn = Pki.ca_name, .serial = @splat(3), .not_before = now - 86400, .not_after = now + 86400, .ca = true });
        try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, impostor }, key_a);
        try std.testing.expectError(error.BadChainSignature, certs.Certs.init(gpa, io, opts));
        // the CA first: its key is not the one in the key file
        try pki.putPair("chain.pem", "key.pem", &.{ pki.ca, leaf_a }, key_a);
        try std.testing.expectError(error.KeyMismatch, certs.Certs.init(gpa, io, opts));
    }
    // files that are not PEM, or not there
    try pki.put("chain.pem", "not a certificate\n");
    try std.testing.expectError(error.NoCertificate, certs.Certs.init(gpa, io, opts));
    try pki.put("chain.pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    try std.testing.expectError(error.BadCertificate, certs.Certs.init(gpa, io, opts));
    try pki.putPair("chain.pem", "key.pem", &.{leaf_a}, key_a);
    try pki.put("key.pem", "no key here\n");
    try std.testing.expectError(error.NoPrivateKey, certs.Certs.init(gpa, io, opts));
    try pki.tmp.dir.deleteFile(io, "key.pem");
    try std.testing.expectError(error.ReadKey, certs.Certs.init(gpa, io, opts));
    try pki.tmp.dir.deleteFile(io, "chain.pem");
    try std.testing.expectError(error.ReadCertificate, certs.Certs.init(gpa, io, opts));
    // every refusal has a sentence for the operator
    try std.testing.expect(std.mem.indexOf(u8, certs.describe(error.KeyMismatch), "does not match") != null);
}

test "--native-cert: handshakes verify against the CA under h3 and zui/1, a reload picks up a new leaf, a bad reload is refused" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    const io = rig.io();
    const now: i64 = 1_800_000_000;
    var pki: Pki = undefined;
    try pki.init(gpa, io, now);
    defer pki.deinit();
    const key_a = try P256.KeyPair.generateDeterministic(@splat(0x31));
    const key_b = try P256.KeyPair.generateDeterministic(@splat(0x32));
    var la: [cert_mod.max_len]u8 = undefined;
    var lb: [cert_mod.max_len]u8 = undefined;
    const leaf_a = pki.leaf(&la, key_a, "node.test", now - 86400, now + 60 * 86400);
    const leaf_b = pki.leaf(&lb, key_b, "node.test", now - 3600, now + 90 * 86400);
    var cb: [std.fs.max_path_bytes]u8 = undefined;
    var kb: [std.fs.max_path_bytes]u8 = undefined;
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, pki.ca }, key_a);
    var tc = certs.TestClock.init(now);
    var hup: std.atomic.Value(bool) = .init(false);
    const cs = try certs.Certs.init(gpa, io, .{ .seed = @splat(9), .clock = tc.clock(), .files = .{ .cert = pki.path(&cb, "chain.pem"), .key = pki.path(&kb, "key.pem") }, .reload = &hup, .poll_ticks = 1 });
    defer cs.deinit();
    const id_seed: [32]u8 = @splat(9);
    const l = try listener.Listener.start(gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = id_seed, .certs = cs }, &rig.disp);
    defer l.stop();
    const roots = [_][]const u8{pki.ca};

    // a browser (h3): the chain verifies against the CA, the leaf names the host
    var first = try webpki(gpa, io, l.address(), "h3", "node.test", &roots, now, 1);
    defer first.close(gpa);
    try std.testing.expect(try first.handshake());
    try std.testing.expectEqual(sha(leaf_a), first.c.tls.peer_cert_sha256.?);
    try std.testing.expectEqual(@as(usize, 2), first.c.tls.peer_chain_len);
    // not under another name, and not for a client that trusts another CA
    {
        var c = try webpki(gpa, io, l.address(), "h3", "other.test", &roots, now, 2);
        defer c.close(gpa);
        try std.testing.expect(!try c.handshake());
        const other_key = try P256.KeyPair.generateDeterministic(@splat(0x41));
        var ob: [cert_mod.max_len]u8 = undefined;
        const other = cert_mod.issue(&ob, .{ .subject = other_key.public_key, .signer = other_key, .subject_cn = Pki.ca_name, .issuer_cn = Pki.ca_name, .serial = @splat(2), .not_before = now - 86400, .not_after = now + 86400, .ca = true });
        var c2 = try webpki(gpa, io, l.address(), "h3", "node.test", &.{other}, now, 3);
        defer c2.close(gpa);
        try std.testing.expect(!try c2.handshake());
    }
    // pinned by hash, the way the self-signed certificate is, it is refused: it is valid for
    // more than 14 days (why the hash endpoints have nothing to say about a real certificate)
    {
        var c = try browser(gpa, io, l.address(), &.{sha(leaf_a)}, now, 4);
        defer c.close(gpa);
        try std.testing.expect(!try c.handshake());
    }
    // raw zui/1 with the node's host name: the same chain, and requests work
    {
        var c = try webpki(gpa, io, l.address(), proto.alpn, "node.test", &roots, now, 5);
        defer c.close(gpa);
        try std.testing.expect(try c.handshake());
        try std.testing.expectEqual(sha(leaf_a), c.c.tls.peer_cert_sha256.?);
        const resp = try c.request(gpa, .hello, &.{ 0, 0, 0, 0 });
        defer gpa.free(resp);
        try std.testing.expectEqual(@as(u8, 0), resp[0]);
    }
    // raw zui/1 as deployed clients and edges connect (the name `zui`, the identity key
    // pinned): still the Ed25519 identity certificate
    {
        var seed: [64]u8 = @splat(7);
        seed[0] = 1;
        var c = try Client.open(gpa, io, l.address(), .{
            .server_name = "zui",
            .identity_seed = @splat(4),
            .expected_peer = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(id_seed)).public_key.toBytes(),
            .seed = seed,
            .now_unix = now,
            .alpn = &.{proto.alpn},
            .keep_alive_ms = 0,
        });
        defer c.close(gpa);
        try std.testing.expect(try c.handshake());
        try std.testing.expect(c.c.tls.peer_cert_sha256 == null);
        const resp = try c.request(gpa, .hello, &.{ 0, 0, 0, 0 });
        defer gpa.free(resp);
        try std.testing.expectEqual(@as(u8, 0), resp[0]);
    }
    // the hash endpoints: nothing to pin
    {
        const srv = try certhttp.Server.startCerts(gpa, .{ 127, 0, 0, 1 }, 0, cs, null);
        defer srv.stop(gpa);
        for ([_][]const u8{ "GET /native/cert-hash HTTP/1.1\r\n\r\n", "GET /native/cert-hashes HTTP/1.1\r\n\r\n" }) |rq| {
            const r = try httpGet(gpa, srv.boundPort(), rq);
            defer gpa.free(r);
            try std.testing.expect(std.mem.startsWith(u8, r, "HTTP/1.1 204 No Content\r\n"));
            try std.testing.expect(std.mem.indexOf(u8, r, "access-control-allow-origin: *\r\n") != null);
            try std.testing.expectEqualStrings("", httpBody(r));
        }
    }

    // the files did not change: nothing is loaded again
    try std.testing.expect(!cs.tick());
    // a renewed leaf arrives (certificate first, then the key, as two renames): between the two
    // the pair does not match and the reload is refused; with both in place it is taken
    std.testing.log_level = .err; // (the refusals warn)
    defer std.testing.log_level = .warn;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    try pemBlock(&text, gpa, "CERTIFICATE", leaf_b);
    try pemBlock(&text, gpa, "CERTIFICATE", pki.ca);
    try pki.put("chain.pem", text.items);
    try std.testing.expect(!cs.tick());
    try std.testing.expectEqual(@as(u64, 1), cs.stats.reload_errors.load(.monotonic));
    try std.testing.expectEqual(sha(leaf_a), cs.cur.sha256);
    try std.testing.expect(!cs.tick()); // not tried again until a file changes
    try std.testing.expectEqual(@as(u64, 1), cs.stats.reload_errors.load(.monotonic));
    {
        var c = try webpki(gpa, io, l.address(), "h3", "node.test", &roots, now, 6);
        defer c.close(gpa);
        try std.testing.expect(try c.handshake());
        try std.testing.expectEqual(sha(leaf_a), c.c.tls.peer_cert_sha256.?);
    }
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_b, pki.ca }, key_b);
    try std.testing.expect(cs.tick());
    try std.testing.expectEqual(@as(u64, 1), cs.stats.reloads.load(.monotonic));
    try std.testing.expectEqual(sha(leaf_b), cs.cur.sha256);
    try std.testing.expectEqual(now + 90 * 86400, cs.stats.not_after.load(.acquire));
    {
        var c = try webpki(gpa, io, l.address(), "h3", "node.test", &roots, now, 7);
        defer c.close(gpa);
        try std.testing.expect(try c.handshake());
        try std.testing.expectEqual(sha(leaf_b), c.c.tls.peer_cert_sha256.?);
    }
    // the connection made with the old leaf is still up
    for (0..20) |_| first.pump();
    try std.testing.expect(first.c.isEstablished() and !first.c.isClosed());
    // SIGHUP (the node's handler sets the flag): loaded again though nothing changed
    hup.store(true, .release);
    try std.testing.expect(cs.tick());
    try std.testing.expectEqual(@as(u64, 2), cs.stats.reloads.load(.monotonic));
    try std.testing.expect(!hup.load(.acquire));
    // SIGHUP with a key that is not the leaf's: refused, the certificate in use stays
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_b, pki.ca }, key_a);
    hup.store(true, .release);
    try std.testing.expect(!cs.tick());
    try std.testing.expectEqual(@as(u64, 2), cs.stats.reload_errors.load(.monotonic));
    try std.testing.expectError(error.KeyMismatch, cs.reload());
    {
        var c = try webpki(gpa, io, l.address(), "h3", "node.test", &roots, now, 8);
        defer c.close(gpa);
        try std.testing.expect(try c.handshake());
        try std.testing.expectEqual(sha(leaf_b), c.c.tls.peer_cert_sha256.?);
    }
}

test "--native-cert: an RSA chain signs the QUIC handshake (rsa_pss_rsae_sha256)" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    const io = rig.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const td = net.tls_identity.testdata;
    try tmp.dir.writeFile(io, .{ .sub_path = "rsa.pem", .data = td.rsa_cert });
    try tmp.dir.writeFile(io, .{ .sub_path = "rsa.key", .data = td.rsa_key });
    var db: [std.fs.max_path_bytes]u8 = undefined;
    const dn = try tmp.dir.realPath(io, &db);
    var cb: [std.fs.max_path_bytes]u8 = undefined;
    var kb: [std.fs.max_path_bytes]u8 = undefined;
    // the test certificate is self-signed (CN=localhost): it is its own root
    var id = try net.tls_identity.load(gpa, td.rsa_cert, td.rsa_key);
    defer id.deinit();
    const parsed = try (std.crypto.Certificate{ .buffer = id.certs[0], .index = 0 }).parse();
    const now: i64 = @intCast(parsed.validity.not_before + 86400);
    var tc = certs.TestClock.init(now);
    const cs = try certs.Certs.init(gpa, io, .{ .seed = @splat(9), .clock = tc.clock(), .files = .{
        .cert = try std.fmt.bufPrint(&cb, "{s}/rsa.pem", .{db[0..dn]}),
        .key = try std.fmt.bufPrint(&kb, "{s}/rsa.key", .{db[0..dn]}),
    } });
    defer cs.deinit();
    try std.testing.expect(cs.cur.chain.?.key == .rsa);
    const l = try listener.Listener.start(gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = @splat(9), .certs = cs }, &rig.disp);
    defer l.stop();
    for ([_][]const u8{ "h3", proto.alpn }, 0..) |alpn, i| {
        var c = try webpki(gpa, io, l.address(), alpn, "localhost", &.{id.certs[0]}, now, @intCast(i + 1));
        defer c.close(gpa);
        try std.testing.expect(try c.handshake());
        try std.testing.expectEqual(sha(id.certs[0]), c.c.tls.peer_cert_sha256.?);
    }
}

test "early_settings: an h3 client has the HTTP/3 control stream with the handshake flight, under the rotating certificate and a --native-cert chain; off, not before its Finished" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    const io = rig.io();
    const now: i64 = 1_800_000_000;
    var pki: Pki = undefined;
    try pki.init(gpa, io, now);
    defer pki.deinit();
    const key = try P256.KeyPair.generateDeterministic(@splat(0x33));
    var lbuf: [cert_mod.max_len]u8 = undefined;
    const leaf = pki.leaf(&lbuf, key, "node.test", now - 86400, now + 60 * 86400);
    var cb: [std.fs.max_path_bytes]u8 = undefined;
    var kb: [std.fs.max_path_bytes]u8 = undefined;
    try pki.putPair("chain.pem", "key.pem", &.{ leaf, pki.ca }, key);
    var tc = certs.TestClock.init(now);
    const roots = [_][]const u8{pki.ca};
    for ([_]bool{ false, true }) |real| for ([_]bool{ false, true }) |want| {
        const cs = try certs.Certs.init(gpa, io, .{ .seed = @splat(9), .clock = tc.clock(), .files = if (real) .{ .cert = pki.path(&cb, "chain.pem"), .key = pki.path(&kb, "key.pem") } else null });
        defer cs.deinit();
        const l = try listener.Listener.start(gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = @splat(9), .certs = cs, .early_settings = want }, &rig.disp);
        defer l.stop();
        // ZUI_NATIVE_EARLY_SETTINGS overrides the option: test what the listener really runs
        const early = l.opts.early_settings;
        var cl = if (real) try webpki(gpa, io, l.address(), "h3", "node.test", &roots, now, 7) else try browser(gpa, io, l.address(), &.{cs.view().sha256[0]}, now, 7);
        defer cl.close(gpa);
        // The client's first Initial, and then it only listens: what arrives is what the server
        // sends before it has heard anything more (no ACK, no Finished).
        var t: u64 = @intCast(Io.Clock.awake.now(io).toNanoseconds());
        while (cl.c.pollTransmit(t, cl.tx.slot())) |n| cl.tx.commit(n, &cl.to);
        cl.tx.flush(&cl.us);
        var n_uni: usize = 0;
        var rounds: usize = 0;
        // on: until the three streams are there; off: 40 waits of 5 ms after the flight
        var quiet: usize = 0;
        while (rounds < 400) : (rounds += 1) {
            cl.us.setWait(5 * std.time.ns_per_ms);
            const n = cl.rx.recv(&cl.us, true);
            t = @intCast(Io.Clock.awake.now(io).toNanoseconds());
            for (0..n) |i| cl.c.handleDatagram(t, cl.rx.data(i));
            while (cl.c.acceptUni()) |_| n_uni += 1;
            if (cl.c.isClosed()) return error.TestUnexpectedResult;
            if (early and n_uni >= 3) break;
            if (cl.c.isEstablished()) quiet += 1;
            if (!early and quiet >= 40) break;
        }
        // the flight alone completes the client's side of the handshake, whichever certificate
        try std.testing.expect(cl.c.isEstablished());
        try std.testing.expectEqual(@as(usize, if (real) 2 else 1), cl.c.tls.peer_chain_len);
        try std.testing.expectEqual(@as(usize, if (early) 3 else 0), n_uni);
        // then the client speaks (its Finished): the control and QPACK streams are there either
        // way, once
        rounds = 0;
        while (n_uni < 3) : (rounds += 1) {
            if (rounds > 2000 or cl.c.isClosed()) return error.TestUnexpectedResult;
            cl.pump();
            while (cl.c.acceptUni()) |_| n_uni += 1;
        }
        for (0..5) |_| {
            cl.pump();
            while (cl.c.acceptUni()) |_| n_uni += 1;
        }
        try std.testing.expectEqual(@as(usize, 3), n_uni);
        // the server's first stream is the control stream: its type, then a SETTINGS frame
        const ctl = cl.c.stream(3).?.recv.contiguous();
        try std.testing.expect(ctl.len >= 2 and ctl[0] == 0x00 and ctl[1] == 0x04);
        try std.testing.expect(!cl.c.isClosed());
    };
}
