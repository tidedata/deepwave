//! TLS 1.3 over TCP for the gRPC port (`--serve-tls`): the handshake is net/tls13_server.zig in
//! its tcp mode (TLS_AES_128_GCM_SHA256, x25519, the P-256 certificate of cert.zig), the record
//! layer is here (RFC 8446 section 5). It plugs into the h2 server as an `h2.sock.Session` per
//! accepted fd, so h2c and HTTP/1.1 run over it unchanged and TLS terminates in the deepwave process
//! (no proxy hop: this is what the zui/1 bench compares against).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const net = @import("net");
const serve = @import("serve");
const cert_mod = @import("cert.zig");
const tls_srv = net.tls13_server;
const qc = net.qcrypto;
const sock = serve.h2.sock;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Ed25519 = std.crypto.sign.Ed25519;
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const max_plain = 16384;
const max_record = 5 + max_plain + 256;
const handshake_timeout_ms = 5000;

/// Traffic keys of one direction.
const Dir = struct {
    key: [16]u8,
    iv: [12]u8,
    seq: u64 = 0,

    fn fromSecret(secret: *const qc.Secret) Dir {
        var d: Dir = .{ .key = undefined, .iv = undefined };
        qc.expandLabel(secret, "key", "", &d.key);
        qc.expandLabel(secret, "iv", "", &d.iv);
        return d;
    }

    fn nonce(d: *Dir) [12]u8 {
        const n = qc.nonce(&d.iv, d.seq);
        d.seq += 1;
        return n;
    }
};

/// What `--serve-tls` holds: the certificate and its key, shared by every connection.
pub const Server = struct {
    gpa: Allocator,
    io: Io,
    cert: cert_mod.Cert,
    identity: Ed25519.KeyPair,
    /// sui-node `rpc.tls`: the operator's PEM chain and key (`--serve-tls-cert/-key`), served
    /// instead of the self-signed `cert`. Owned by the server.
    files: ?net.tls_identity.Identity = null,

    pub fn init(gpa: Allocator, io: Io, cert: cert_mod.Cert) Server {
        var seed: [32]u8 = undefined;
        io.random(&seed);
        return .{ .gpa = gpa, .io = io, .cert = cert, .identity = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable };
    }

    /// A server presenting `files` (cert chain + key loaded with `net.tls_identity.load`).
    pub fn initFiles(gpa: Allocator, io: Io, files: net.tls_identity.Identity) Server {
        var seed: [32]u8 = undefined;
        io.random(&seed);
        const kp = P256.KeyPair.generate(io);
        // `cert` stays a valid placeholder (only `files` is ever served)
        const now_unix: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).toNanoseconds(), std.time.ns_per_s));
        var s = init(gpa, io, cert_mod.generate(kp, seed[0..16].*, now_unix, 1, "zui"));
        s.files = files;
        return s;
    }

    pub fn deinit(s: *Server) void {
        if (s.files) |*f| f.deinit();
        s.files = null;
    }

    pub fn acceptor(s: *Server) sock.Acceptor {
        return .{ .ctx = s, .accept = acceptFn };
    }

    fn acceptFn(ctx: *anyopaque, fd: std.c.fd_t) ?*const sock.Session {
        const s: *Server = @ptrCast(@alignCast(ctx));
        const c = Conn.handshake(s, fd) catch return null;
        return &c.session;
    }
};

pub const Conn = struct {
    gpa: Allocator,
    fd: std.c.fd_t,
    session: sock.Session,
    r: Dir = undefined,
    w: Dir = undefined,
    /// Received bytes: records from `raw[0..raw_len]`; the first record may be decrypted
    /// already, its plaintext at `raw[plain_off..plain_end]`, the record ending at `rec_end`.
    raw: [2 * max_record]u8 = undefined,
    raw_len: usize = 0,
    plain_off: usize = 0,
    plain_end: usize = 0,
    rec_end: usize = 0,
    closed: bool = false,
    /// Outgoing records of one write (one send per `write`).
    out: std.ArrayList(u8) = .empty,

    const vt: sock.Session.VTable = .{ .read = readFn, .write = writeFn, .buffered = bufferedFn, .deinit = deinitFn };

    fn handshake(srv: *Server, fd: std.c.fd_t) !*Conn {
        const gpa = srv.gpa;
        const c = try gpa.create(Conn);
        errdefer gpa.destroy(c);
        c.* = .{ .gpa = gpa, .fd = fd, .session = .{ .ctx = c, .vt = &vt } };
        errdefer c.out.deinit(gpa);
        var rnd: [64]u8 = undefined;
        srv.io.random(&rnd);
        var st = tls_srv.Server.init(.{
            .server_name = "zui",
            .local_tp = "",
            .identity = srv.identity,
            .cert_der = srv.cert.bytes(),
            .now_unix = 0,
            .random = rnd[0..32].*,
            .x25519_secret = rnd[32..64].*,
            .alpn = &.{ "h2", "http/1.1" },
            .client_auth = false,
            .alt = .{ .alpn_index = 0, .cert_der = srv.cert.bytes(), .key = srv.cert.key },
            .tcp = true,
            .chain = if (srv.files) |*f| f else null,
        });
        defer st.deinit(gpa);
        // ClientHello (plaintext handshake records)
        while (st.takeOutput(.initial).len == 0) {
            const rec = try c.nextRecord();
            if (rec.ty != 22) return error.UnexpectedMessage;
            st.feed(gpa, .initial, c.raw[5..rec.end]) catch |e| {
                // a refused ClientHello gets its alert in the clear, as rustls sends it
                sock.rawWriteAll(fd, &.{ 21, 3, 3, 0, 2, 2, alertOf(e) }) catch {};
                return e;
            };
            c.dropRecord(rec.end);
        }
        var hs_w = Dir.fromSecret(&st.s_hs.?);
        var hs_r = Dir.fromSecret(&st.c_hs.?);
        // ServerHello, middlebox ChangeCipherSpec, then EE..Finished under the handshake keys
        try appendRecordHdr(&c.out, gpa, 22, st.takeOutput(.initial).len);
        try c.out.appendSlice(gpa, st.takeOutput(.initial));
        try c.out.appendSlice(gpa, &.{ 20, 3, 3, 0, 1, 1 });
        try sealInto(&c.out, gpa, &hs_w, 22, st.takeOutput(.handshake));
        try sock.rawWriteAll(fd, c.out.items);
        c.out.clearRetainingCapacity();
        // client Finished (a ChangeCipherSpec may come first)
        while (!st.complete) {
            const rec = try c.nextRecord();
            switch (rec.ty) {
                20 => {},
                23 => {
                    const inner = try openRecord(&hs_r, c.raw[0..rec.end]);
                    if (inner.ty != 22) return error.UnexpectedMessage;
                    try st.feed(gpa, .handshake, c.raw[5..][0..inner.len]);
                },
                else => return error.UnexpectedMessage,
            }
            c.dropRecord(rec.end);
        }
        c.w = Dir.fromSecret(&st.s_ap.?);
        c.r = Dir.fromSecret(&st.c_ap.?);
        return c;
    }

    const Rec = struct { ty: u8, end: usize };

    /// Length of the complete record at `raw[0..]`, or null.
    fn completeRecord(c: *const Conn) ?usize {
        if (c.raw_len < 5) return null;
        const len = std.mem.readInt(u16, c.raw[3..5], .big);
        if (c.raw_len < 5 + @as(usize, len)) return null;
        return 5 + @as(usize, len);
    }

    /// Reads until a whole record sits at `raw[0..]` (handshake: with a timeout).
    fn nextRecord(c: *Conn) !Rec {
        while (true) {
            if (c.raw_len >= 5) {
                const len = std.mem.readInt(u16, c.raw[3..5], .big);
                if (len > max_record - 5) return error.RecordOverflow;
            }
            if (c.completeRecord()) |end| return .{ .ty = c.raw[0], .end = end };
            if (!(try sock.waitReadableRaw(c.fd, handshake_timeout_ms))) return error.Timeout;
            const n = try sock.rawRead(c.fd, c.raw[c.raw_len..]);
            if (n == 0) return error.Closed;
            c.raw_len += n;
        }
    }

    fn dropRecord(c: *Conn, end: usize) void {
        std.mem.copyForwards(u8, c.raw[0 .. c.raw_len - end], c.raw[end..c.raw_len]);
        c.raw_len -= end;
    }

    fn readFn(ctx: *anyopaque, buf: []u8) sock.Error!usize {
        const c: *Conn = @ptrCast(@alignCast(ctx));
        while (true) {
            if (c.plain_end > c.plain_off) {
                const n = @min(buf.len, c.plain_end - c.plain_off);
                @memcpy(buf[0..n], c.raw[c.plain_off..][0..n]);
                c.plain_off += n;
                if (c.plain_off == c.plain_end) {
                    c.dropRecord(c.rec_end);
                    c.plain_off = 0;
                    c.plain_end = 0;
                }
                return n;
            }
            if (c.closed) return 0;
            if (c.completeRecord()) |end| {
                if (c.raw[0] != 23) {
                    if (c.raw[0] == 21) return 0; // plaintext alert
                    c.dropRecord(end); // ChangeCipherSpec
                    continue;
                }
                const inner = openRecord(&c.r, c.raw[0..end]) catch return error.Io;
                switch (inner.ty) {
                    23 => {
                        c.plain_off = 5;
                        c.plain_end = 5 + inner.len;
                        c.rec_end = end;
                        if (inner.len == 0) c.dropRecord(end);
                    },
                    21 => {
                        c.closed = true; // close_notify (or any alert): the stream ends
                        return 0;
                    },
                    else => c.dropRecord(end), // post-handshake messages: nothing to do
                }
                continue;
            }
            if (c.raw_len >= 5 and std.mem.readInt(u16, c.raw[3..5], .big) > max_record - 5) return error.Io;
            const n = try sock.rawRead(c.fd, c.raw[c.raw_len..]);
            if (n == 0) return 0;
            c.raw_len += n;
        }
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) sock.Error!void {
        const c: *Conn = @ptrCast(@alignCast(ctx));
        c.out.clearRetainingCapacity();
        var off: usize = 0;
        while (off < bytes.len) {
            const n = @min(max_plain, bytes.len - off);
            sealInto(&c.out, c.gpa, &c.w, 23, bytes[off..][0..n]) catch return error.Io;
            off += n;
        }
        try sock.rawWriteAll(c.fd, c.out.items);
        if (c.out.capacity > 1 << 20) c.out.clearAndFree(c.gpa);
    }

    fn bufferedFn(ctx: *anyopaque) bool {
        const c: *Conn = @ptrCast(@alignCast(ctx));
        return c.plain_end > c.plain_off or c.closed or c.completeRecord() != null;
    }

    fn deinitFn(ctx: *anyopaque) void {
        const c: *Conn = @ptrCast(@alignCast(ctx));
        c.out.deinit(c.gpa);
        c.gpa.destroy(c);
    }
};

/// RFC 8446 6.2 alert description for a refused ClientHello.
fn alertOf(e: anyerror) u8 {
    return switch (e) {
        error.NoApplicationProtocol => 120,
        error.DecodeError => 50,
        error.IllegalParameter => 47,
        else => 40, // handshake_failure (also no x25519 share: zui sends no HelloRetryRequest)
    };
}

fn appendRecordHdr(out: *std.ArrayList(u8), gpa: Allocator, ty: u8, len: usize) !void {
    try out.appendSlice(gpa, &.{ ty, 3, 3, @intCast(len >> 8), @intCast(len & 0xff) });
}

/// Appends `data` as protected records of inner type `ty` (split at 16 KiB).
fn sealInto(out: *std.ArrayList(u8), gpa: Allocator, d: *Dir, ty: u8, data: []const u8) !void {
    var off: usize = 0;
    while (true) {
        const n = @min(max_plain, data.len - off);
        const clen = n + 1 + 16;
        const start = out.items.len;
        try out.ensureUnusedCapacity(gpa, 5 + clen);
        out.appendSliceAssumeCapacity(&.{ 23, 3, 3, @intCast(clen >> 8), @intCast(clen & 0xff) });
        out.appendSliceAssumeCapacity(data[off..][0..n]);
        out.appendAssumeCapacity(ty);
        const body = out.items[start + 5 ..][0 .. n + 1];
        var tag: [16]u8 = undefined;
        Aes128Gcm.encrypt(body, &tag, body, out.items[start..][0..5], d.nonce(), d.key);
        out.appendSliceAssumeCapacity(&tag);
        off += n;
        if (off >= data.len) break;
    }
}

const Inner = struct { ty: u8, len: usize };

/// Decrypts the record `rec` (header included) in place: plaintext at `rec[5..][0..len]`.
fn openRecord(d: *Dir, rec: []u8) !Inner {
    if (rec.len < 5 + 17) return error.DecryptError;
    const ct = rec[5 .. rec.len - 16];
    const tag = rec[rec.len - 16 ..][0..16].*;
    Aes128Gcm.decrypt(ct, ct, tag, rec[0..5], d.nonce(), d.key) catch return error.DecryptError;
    var n = ct.len;
    while (n > 0 and ct[n - 1] == 0) n -= 1; // padding
    if (n == 0) return error.UnexpectedMessage;
    return .{ .ty = ct[n - 1], .len = n - 1 };
}

// ---------------------------------------------------------------- tests

// Echo over TLS: std.crypto.tls.Client (an independent implementation) against `Server`.
test "tcptls: std.crypto.tls.Client handshake and echo (small and multi-record writes)" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var seed: [32]u8 = undefined;
    io.random(&seed);
    const key = try P256.KeyPair.generateDeterministic(seed);
    var serial: [16]u8 = @splat(7);
    serial[0] = 1;
    const now_unix: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).toNanoseconds(), std.time.ns_per_s));
    var srv = Server.init(gpa, io, cert_mod.generate(key, serial, now_unix, 13, "zui"));
    var any: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    var ls = try any.listen(io, .{ .reuse_address = true });
    defer ls.deinit(io);
    const port = ls.socket.address.ip4.port;

    const Echo = struct {
        fn run(s: *Server, l: *Io.net.Server, iox: Io) void {
            const st = l.accept(iox) catch return;
            const fd = st.socket.handle;
            const sess = s.acceptor().accept(s, fd) orelse {
                sock.close(fd);
                return;
            };
            _ = sock.attach(fd, sess);
            defer sock.close(fd);
            var b: [70000]u8 = undefined;
            while (true) {
                const n = sock.read(fd, &b) catch return;
                if (n == 0) return;
                sock.writeAll(fd, b[0..n]) catch return;
            }
        }
    };
    const t = try std.Thread.spawn(.{}, Echo.run, .{ &srv, &ls, io });
    defer t.join();

    var addr: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(port) };
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var rb: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var wb: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var sr = stream.reader(io, &rb);
    var sw = stream.writer(io, &wb);
    var crb: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var cwb: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var ent: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&ent);
    var cl = try std.crypto.tls.Client.init(&sr.interface, &sw.interface, .{
        .host = .no_verification,
        .ca = .no_verification,
        .read_buffer = &crb,
        .write_buffer = &cwb,
        .entropy = &ent,
        .realtime_now = Io.Clock.real.now(io),
    });
    // small message
    try cl.writer.writeAll("hello zui");
    try cl.writer.flush();
    try sw.interface.flush();
    var got: [9]u8 = undefined;
    try cl.reader.readSliceAll(&got);
    try std.testing.expectEqualStrings("hello zui", &got);
    // 50 KB: several records each way
    const big = try gpa.alloc(u8, 50_000);
    defer gpa.free(big);
    for (big, 0..) |*x, i| x.* = @truncate(i *% 31);
    try cl.writer.writeAll(big);
    try cl.writer.flush();
    try sw.interface.flush();
    const back = try gpa.alloc(u8, big.len);
    defer gpa.free(back);
    try cl.reader.readSliceAll(back);
    try std.testing.expectEqualSlices(u8, big, back);
    cl.end() catch {};
    sw.interface.flush() catch {};
    stream.shutdown(io, .both) catch {};
}

// rpc.tls: the operator's PEM chain and key (P-256 from the rpc-surface capture, then RSA-2048:
// rsa_pss_rsae_sha256), checked by std.crypto.tls.Client, an independent implementation.
test "tcptls: a PEM chain and key from files (P-256, RSA-PSS) through std.crypto.tls.Client" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const pairs = [_][2][]const u8{
        .{ net.tls_identity.testdata.p256_cert, net.tls_identity.testdata.p256_key },
        .{ net.tls_identity.testdata.rsa_cert, net.tls_identity.testdata.rsa_key },
    };
    for (pairs) |pair| {
        const id = try net.tls_identity.load(gpa, pair[0], pair[1]);
        var srv = Server.initFiles(gpa, io, id);
        defer srv.deinit();
        var any: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
        var ls = try any.listen(io, .{ .reuse_address = true });
        defer ls.deinit(io);
        const port = ls.socket.address.ip4.port;
        const Echo = struct {
            fn run(s: *Server, l: *Io.net.Server, iox: Io) void {
                const st = l.accept(iox) catch return;
                const fd = st.socket.handle;
                const sess = s.acceptor().accept(s, fd) orelse {
                    sock.close(fd);
                    return;
                };
                _ = sock.attach(fd, sess);
                defer sock.close(fd);
                var b: [4096]u8 = undefined;
                while (true) {
                    const n = sock.read(fd, &b) catch return;
                    if (n == 0) return;
                    sock.writeAll(fd, b[0..n]) catch return;
                }
            }
        };
        const t = try std.Thread.spawn(.{}, Echo.run, .{ &srv, &ls, io });
        defer t.join();
        var addr: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(port) };
        const stream = try addr.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var rb: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
        var wb: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
        var sr = stream.reader(io, &rb);
        var sw = stream.writer(io, &wb);
        var crb: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
        var cwb: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
        var ent: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
        io.random(&ent);
        // std's client checks CertificateVerify against the leaf's public key
        var cl = try std.crypto.tls.Client.init(&sr.interface, &sw.interface, .{
            .host = .no_verification,
            .ca = .no_verification,
            .read_buffer = &crb,
            .write_buffer = &cwb,
            .entropy = &ent,
            .realtime_now = Io.Clock.real.now(io),
        });
        try cl.writer.writeAll("hello rpc.tls");
        try cl.writer.flush();
        try sw.interface.flush();
        var got: [13]u8 = undefined;
        try cl.reader.readSliceAll(&got);
        try std.testing.expectEqualStrings("hello rpc.tls", &got);
        cl.end() catch {};
        sw.interface.flush() catch {};
        stream.shutdown(io, .both) catch {};
    }
}
