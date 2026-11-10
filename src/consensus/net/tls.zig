//! TLS 1.3 over TCP for consensus, as sui-tls / consensus `tonic_tls.rs` at mainnet-v1.83.1:
//! both sides present a self-signed X.509 certificate whose key is the authority's Ed25519
//! network key, server name "consensus_epoch_<epoch>", ALPN "h2", and each side accepts only a
//! certificate whose public key is a committee member's network key (sui-tls `ServerCertVerifier`
//! pins the server key, `ClientCertVerifier` checks the client key against the allowed set; the
//! peer's AuthorityIndex comes from that key, never from a message).
//!
//! The handshake is the sans-I/O engines of src/net (tls13.zig client with `tcp = true`,
//! tls13_server.zig with `tcp = true`, x509.zig); the record layer (RFC 8446 section 5,
//! TLS_AES_128_GCM_SHA256) is here, on a connected fd with blocking I/O (serve/h2/sock.zig raw
//! helpers). One thread reads a session and any number of threads may write it if the caller
//! serializes writes (the h2 layer holds a write lock).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const net = @import("net");
const serve = @import("serve");
const qc = net.qcrypto;
const x509 = net.x509;
const sock = serve.h2.sock;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Ed25519 = std.crypto.sign.Ed25519;
const mon = @import("mon.zig");

/// Records one direction may seal before we rotate its keys with a KeyUpdate (well under the
/// AES-GCM confidentiality limit that rustls also keeps).
pub const default_rekey_after: u64 = 1 << 23;
/// Total time a handshake (all its reads together) may take.
pub const handshake_total_ms = 5000;

const max_plain = 16384;
const max_record = 5 + max_plain + 256;
pub const handshake_timeout_ms = 5000;

pub fn serverName(buf: []u8, epoch: u64) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buf, "consensus_epoch_{d}", .{epoch});
}

pub const PeerKeyCheck = struct {
    ctx: *anyopaque,
    /// Returns the AuthorityIndex for an allowed network key, or null to refuse the handshake.
    lookup: *const fn (ctx: *anyopaque, network_key: *const [32]u8) ?u32,
};

pub const Error = error{ HandshakeFailure, BadCertificate, PeerNotInCommittee, Io, Closed, Timeout, RecordOverflow, OutOfMemory };

/// Our TLS identity: the network key and its self-signed certificate for the epoch's server name.
pub const Identity = struct {
    key: Ed25519.KeyPair,
    cert: [x509.max_cert_len]u8,
    cert_len: usize,

    pub fn init(network_key_seed: *const [32]u8, server_name: []const u8) error{InvalidKey}!Identity {
        const kp = Ed25519.KeyPair.generateDeterministic(network_key_seed.*) catch return error.InvalidKey;
        var id: Identity = .{ .key = kp, .cert = undefined, .cert_len = 0 };
        // Serial from the public key: stable across restarts, distinct per authority.
        var serial: [20]u8 = undefined;
        @memcpy(&serial, kp.public_key.toBytes()[0..20]);
        id.cert_len = x509.generateSelfSigned(&id.cert, kp, serial, server_name);
        return id;
    }
    pub fn certDer(id: *const Identity) []const u8 {
        return id.cert[0..id.cert_len];
    }
    pub fn publicKey(id: *const Identity) [32]u8 {
        return id.key.public_key.toBytes();
    }
};

/// Traffic keys of one direction.
const Dir = struct {
    key: [16]u8,
    iv: [12]u8,
    secret: qc.Secret,
    seq: u64 = 0,

    fn fromSecret(secret: *const qc.Secret) Dir {
        var d: Dir = .{ .key = undefined, .iv = undefined, .secret = secret.* };
        qc.expandLabel(secret, "key", "", &d.key);
        qc.expandLabel(secret, "iv", "", &d.iv);
        return d;
    }

    /// RFC 8446 section 7.2: next application traffic secret, fresh key and iv, sequence 0.
    fn rotate(d: *Dir) void {
        var next: qc.Secret = undefined;
        qc.expandLabel(&d.secret, "traffic upd", "", &next);
        d.* = fromSecret(&next);
        std.crypto.secureZero(u8, &next);
    }

    fn nonce(d: *Dir) [12]u8 {
        const n = qc.nonce(&d.iv, d.seq);
        d.seq += 1;
        return n;
    }
};

/// One TLS session over a connected TCP socket (either side).
pub const Session = struct {
    gpa: Allocator,
    io: Io,
    fd: std.c.fd_t,
    /// Guards `w` and `out`: `writeAll` and the KeyUpdate the reader thread answers with.
    wlock: Io.Mutex = .init,
    rekey_after: u64 = default_rekey_after,
    /// Monotonic ns deadline of the running handshake (0: none).
    hs_deadline_ns: u64 = 0,
    peer_index: u32 = 0,
    peer_key: [32]u8 = @splat(0),
    r: Dir = undefined,
    w: Dir = undefined,
    /// Received bytes: records from `raw[0..raw_len]`; the first record may be decrypted already,
    /// its plaintext at `raw[plain_off..plain_end]`, the record ending at `rec_end`.
    raw: [2 * max_record]u8 = undefined,
    raw_len: usize = 0,
    plain_off: usize = 0,
    plain_end: usize = 0,
    rec_end: usize = 0,
    closed: bool = false,
    out: std.ArrayList(u8) = .empty,

    /// Server side. `check` maps the client's certificate key to an authority; unknown keys are
    /// refused. Takes over nothing: the caller still owns (and closes) `fd`.
    pub fn accept(gpa: Allocator, io: Io, fd: std.c.fd_t, server_name: []const u8, identity: *const Identity, check: PeerKeyCheck) Error!*Session {
        const s = try gpa.create(Session);
        errdefer gpa.destroy(s);
        s.* = .{ .gpa = gpa, .io = io, .fd = fd };
        errdefer s.out.deinit(gpa);
        s.hs_deadline_ns = mon.monoNs(io) +| handshake_total_ms * std.time.ns_per_ms;
        try s.serverHandshake(io, server_name, identity, check);
        s.hs_deadline_ns = 0;
        return s;
    }

    /// Client side: the server's certificate must carry exactly `expected_peer_key`.
    pub fn connect(gpa: Allocator, io: Io, fd: std.c.fd_t, server_name: []const u8, identity: *const Identity, expected_peer_key: *const [32]u8) Error!*Session {
        const s = try gpa.create(Session);
        errdefer gpa.destroy(s);
        s.* = .{ .gpa = gpa, .io = io, .fd = fd };
        errdefer s.out.deinit(gpa);
        s.hs_deadline_ns = mon.monoNs(io) +| handshake_total_ms * std.time.ns_per_ms;
        try s.clientHandshake(io, server_name, identity, expected_peer_key);
        s.hs_deadline_ns = 0;
        return s;
    }

    /// Frees the session (the fd is closed by the caller).
    pub fn deinit(s: *Session) void {
        s.out.deinit(s.gpa);
        const gpa = s.gpa;
        std.crypto.secureZero(u8, std.mem.asBytes(&s.r));
        std.crypto.secureZero(u8, std.mem.asBytes(&s.w));
        gpa.destroy(s);
    }

    fn nowUnix(io: Io) i64 {
        return @intCast(@divTrunc(Io.Clock.real.now(io).toNanoseconds(), std.time.ns_per_s));
    }

    fn serverHandshake(s: *Session, io: Io, server_name: []const u8, identity: *const Identity, check: PeerKeyCheck) Error!void {
        const gpa = s.gpa;
        var rnd: [64]u8 = undefined;
        io.random(&rnd);
        defer std.crypto.secureZero(u8, &rnd);
        var st = net.tls13_server.Server.init(.{
            .server_name = server_name,
            .local_tp = "",
            .identity = identity.key,
            .cert_der = identity.certDer(),
            .now_unix = nowUnix(io),
            .random = rnd[0..32].*,
            .x25519_secret = rnd[32..64].*,
            .alpn = &.{"h2"},
            .client_auth = true,
            .tcp = true,
        });
        defer st.deinit(gpa);
        // ClientHello (plaintext handshake records)
        while (st.takeOutput(.initial).len == 0) {
            const rec = try s.nextRecord(handshake_timeout_ms);
            if (rec.ty != 22) return error.HandshakeFailure;
            st.feed(gpa, .initial, s.raw[5..rec.end]) catch return error.HandshakeFailure;
            s.dropRecord(rec.end);
        }
        var hs_w = Dir.fromSecret(&st.s_hs.?);
        var hs_r = Dir.fromSecret(&st.c_hs.?);
        // ServerHello, middlebox ChangeCipherSpec, then EE..Finished under the handshake keys.
        try appendRecordHdr(&s.out, gpa, 22, st.takeOutput(.initial).len);
        try s.out.appendSlice(gpa, st.takeOutput(.initial));
        try s.out.appendSlice(gpa, &.{ 20, 3, 3, 0, 1, 1 });
        try sealInto(&s.out, gpa, &hs_w, 22, st.takeOutput(.handshake));
        sock.rawWriteAll(s.fd, s.out.items) catch return error.Io;
        s.out.clearRetainingCapacity();
        // client Certificate, CertificateVerify, Finished (a ChangeCipherSpec may come first)
        while (!st.complete) {
            const rec = try s.nextRecord(handshake_timeout_ms);
            switch (rec.ty) {
                20 => {},
                23 => {
                    const inner = openRecord(&hs_r, s.raw[0..rec.end]) catch return error.HandshakeFailure;
                    if (inner.ty != 22) return error.HandshakeFailure;
                    st.feed(gpa, .handshake, s.raw[5..][0..inner.len]) catch |e| return switch (e) {
                        error.OutOfMemory => error.OutOfMemory,
                        error.BadCertificate, error.PeerIdMismatch => error.BadCertificate,
                        else => error.HandshakeFailure,
                    };
                },
                else => return error.HandshakeFailure,
            }
            s.dropRecord(rec.end);
        }
        const pk = st.peer_id orelse return error.BadCertificate;
        s.peer_key = pk;
        s.peer_index = check.lookup(check.ctx, &pk) orelse return error.PeerNotInCommittee;
        s.w = Dir.fromSecret(&st.s_ap.?);
        s.r = Dir.fromSecret(&st.c_ap.?);
    }

    fn clientHandshake(s: *Session, io: Io, server_name: []const u8, identity: *const Identity, expected: *const [32]u8) Error!void {
        const gpa = s.gpa;
        var rnd: [64]u8 = undefined;
        io.random(&rnd);
        defer std.crypto.secureZero(u8, &rnd);
        var st = net.tls13.Client.init(.{
            .server_name = server_name,
            .local_tp = "",
            .identity = identity.key,
            .cert_der = identity.certDer(),
            .expected_peer = expected.*,
            .alpn = "h2",
            .now_unix = nowUnix(io),
            .random = rnd[0..32].*,
            .x25519_secret = rnd[32..64].*,
            .tcp = true,
        });
        defer st.deinit(gpa);
        st.start(gpa) catch return error.HandshakeFailure;
        try appendRecordHdr(&s.out, gpa, 22, st.takeOutput(.initial).len);
        try s.out.appendSlice(gpa, st.takeOutput(.initial));
        st.clearOutput(.initial);
        sock.rawWriteAll(s.fd, s.out.items) catch return error.Io;
        s.out.clearRetainingCapacity();
        // ServerHello (plaintext)
        while (st.s_hs == null) {
            const rec = try s.nextRecord(handshake_timeout_ms);
            if (rec.ty == 20) {
                s.dropRecord(rec.end);
                continue;
            }
            if (rec.ty != 22) return error.HandshakeFailure;
            st.feed(gpa, .initial, s.raw[5..rec.end]) catch return error.HandshakeFailure;
            s.dropRecord(rec.end);
        }
        var hs_r = Dir.fromSecret(&st.s_hs.?);
        var hs_w = Dir.fromSecret(&st.c_hs.?);
        // EE, CertificateRequest, Certificate, CertificateVerify, Finished under the server's
        // handshake keys; the engine queues our Certificate, CertificateVerify and Finished.
        while (!st.complete) {
            const rec = try s.nextRecord(handshake_timeout_ms);
            switch (rec.ty) {
                20 => {},
                23 => {
                    const inner = openRecord(&hs_r, s.raw[0..rec.end]) catch return error.HandshakeFailure;
                    if (inner.ty != 22) return error.HandshakeFailure;
                    st.feed(gpa, .handshake, s.raw[5..][0..inner.len]) catch |e| return switch (e) {
                        error.OutOfMemory => error.OutOfMemory,
                        error.BadCertificate, error.PeerIdMismatch, error.BadSignature => error.BadCertificate,
                        else => error.HandshakeFailure,
                    };
                },
                else => return error.HandshakeFailure,
            }
            s.dropRecord(rec.end);
        }
        s.out.clearRetainingCapacity();
        try s.out.appendSlice(gpa, &.{ 20, 3, 3, 0, 1, 1 });
        try sealInto(&s.out, gpa, &hs_w, 22, st.takeOutput(.handshake));
        sock.rawWriteAll(s.fd, s.out.items) catch return error.Io;
        s.out.clearRetainingCapacity();
        s.peer_key = expected.*;
        s.w = Dir.fromSecret(&st.c_ap.?);
        s.r = Dir.fromSecret(&st.s_ap.?);
    }

    const Rec = struct { ty: u8, end: usize };

    /// Length of the complete record at `raw[0..]`, or null.
    fn completeRecord(s: *const Session) ?usize {
        if (s.raw_len < 5) return null;
        const len = std.mem.readInt(u16, s.raw[3..5], .big);
        if (s.raw_len < 5 + @as(usize, len)) return null;
        return 5 + @as(usize, len);
    }

    /// Reads until a whole record sits at `raw[0..]`, with a timeout per wait.
    fn nextRecord(s: *Session, timeout_ms: i32) Error!Rec {
        while (true) {
            var wait_ms = timeout_ms;
            if (s.hs_deadline_ns != 0) {
                const now = mon.monoNs(s.io);
                if (now >= s.hs_deadline_ns) return error.Timeout;
                const left_ms: u64 = @max((s.hs_deadline_ns - now) / std.time.ns_per_ms, 1);
                wait_ms = @intCast(@min(@as(u64, @intCast(timeout_ms)), left_ms));
            }
            if (s.raw_len >= 5) {
                const len = std.mem.readInt(u16, s.raw[3..5], .big);
                if (len > max_record - 5) return error.RecordOverflow;
            }
            if (s.completeRecord()) |end| return .{ .ty = s.raw[0], .end = end };
            const ready = sock.waitReadableRaw(s.fd, wait_ms) catch return error.Io;
            if (!ready) {
                if (s.hs_deadline_ns != 0 and mon.monoNs(s.io) < s.hs_deadline_ns) continue;
                return error.Timeout;
            }
            const n = sock.rawRead(s.fd, s.raw[s.raw_len..]) catch return error.Io;
            if (n == 0) return error.Closed;
            s.raw_len += n;
        }
    }

    fn dropRecord(s: *Session, end: usize) void {
        std.mem.copyForwards(u8, s.raw[0 .. s.raw_len - end], s.raw[end..s.raw_len]);
        s.raw_len -= end;
    }

    /// True when a read would not block on the socket (buffered plaintext or a whole record).
    pub fn buffered(s: *const Session) bool {
        return s.plain_end > s.plain_off or s.closed or s.completeRecord() != null;
    }

    /// Waits until a read would return (data, close or error). False on timeout.
    pub fn waitReadable(s: *Session, timeout_ms: i32) Error!bool {
        if (s.buffered()) return true;
        return sock.waitReadableRaw(s.fd, timeout_ms) catch return error.Io;
    }

    /// Plaintext into `buf`: blocks until at least one byte. 0 means the stream ended.
    pub fn read(s: *Session, buf: []u8) Error!usize {
        if (buf.len == 0) return 0;
        while (true) {
            if (s.plain_end > s.plain_off) {
                const n = @min(buf.len, s.plain_end - s.plain_off);
                @memcpy(buf[0..n], s.raw[s.plain_off..][0..n]);
                s.plain_off += n;
                if (s.plain_off == s.plain_end) {
                    s.dropRecord(s.rec_end);
                    s.plain_off = 0;
                    s.plain_end = 0;
                }
                return n;
            }
            if (s.closed) return 0;
            if (s.completeRecord()) |end| {
                if (s.raw[0] != 23) {
                    if (s.raw[0] == 21) return 0; // plaintext alert
                    s.dropRecord(end); // ChangeCipherSpec
                    continue;
                }
                const inner = openRecord(&s.r, s.raw[0..end]) catch return error.Io;
                switch (inner.ty) {
                    23 => {
                        s.plain_off = 5;
                        s.plain_end = 5 + inner.len;
                        s.rec_end = end;
                        if (inner.len == 0) {
                            s.dropRecord(end);
                            s.plain_off = 0;
                            s.plain_end = 0;
                        }
                    },
                    21 => {
                        s.closed = true; // close_notify (or any alert): the stream ends
                        return 0;
                    },
                    22 => {
                        // Post-handshake messages: KeyUpdate rotates; the rest (NewSessionTicket) is dropped.
                        const want_reply = s.handlePostHandshake(s.raw[5..][0..inner.len]);
                        s.dropRecord(end);
                        if (want_reply) s.sendKeyUpdate(false) catch return error.Io;
                    },
                    else => s.dropRecord(end),
                }
                continue;
            }
            if (s.raw_len >= 5 and std.mem.readInt(u16, s.raw[3..5], .big) > max_record - 5) return error.RecordOverflow;
            const n = sock.rawRead(s.fd, s.raw[s.raw_len..]) catch return error.Io;
            if (n == 0) return 0;
            s.raw_len += n;
        }
    }

    /// Walks the handshake messages of a decrypted type-22 record. A KeyUpdate (type 24)
    /// rotates the read keys; returns true when the peer asked us to update ours too.
    fn handlePostHandshake(s: *Session, msgs: []const u8) bool {
        var want_reply = false;
        var off: usize = 0;
        while (off + 4 <= msgs.len) {
            const ty = msgs[off];
            const len = std.mem.readInt(u24, msgs[off + 1 ..][0..3], .big);
            if (off + 4 + len > msgs.len) break;
            if (ty == 24 and len == 1) {
                s.r.rotate();
                if (msgs[off + 4] == 1) want_reply = true;
            }
            off += 4 + len;
        }
        return want_reply;
    }

    /// Sends a KeyUpdate and rotates our write keys. `request` asks the peer to rotate too.
    pub fn sendKeyUpdate(s: *Session, request: bool) Error!void {
        s.wlock.lockUncancelable(s.io);
        defer s.wlock.unlock(s.io);
        s.out.clearRetainingCapacity();
        s.keyUpdateLocked(request) catch return error.OutOfMemory;
        sock.rawWriteAll(s.fd, s.out.items) catch return error.Io;
        s.out.clearRetainingCapacity();
    }

    fn keyUpdateLocked(s: *Session, request: bool) !void {
        try sealInto(&s.out, s.gpa, &s.w, 22, &.{ 24, 0, 0, 1, @intFromBool(request) });
        s.w.rotate();
    }

    /// Encrypts and writes all of `bytes`. Callers serialize writes among themselves; the
    /// session's own lock also orders them against a KeyUpdate sent from the reader thread.
    pub fn writeAll(s: *Session, bytes: []const u8) Error!void {
        s.wlock.lockUncancelable(s.io);
        defer s.wlock.unlock(s.io);
        s.out.clearRetainingCapacity();
        var off: usize = 0;
        while (off < bytes.len) {
            if (s.w.seq >= s.rekey_after) s.keyUpdateLocked(false) catch return error.OutOfMemory;
            const n = @min(max_plain, bytes.len - off);
            sealInto(&s.out, s.gpa, &s.w, 23, bytes[off..][0..n]) catch return error.OutOfMemory;
            off += n;
            // Bound the staging buffer: flush every 1 MiB.
            if (s.out.items.len >= 1 << 20) {
                sock.rawWriteAll(s.fd, s.out.items) catch return error.Io;
                s.out.clearRetainingCapacity();
            }
        }
        if (s.out.items.len > 0) sock.rawWriteAll(s.fd, s.out.items) catch return error.Io;
        if (s.out.capacity > 2 << 20) s.out.clearAndFree(s.gpa) else s.out.clearRetainingCapacity();
    }

    /// Wakes a thread blocked in `read` / `waitReadable` and fails further I/O.
    pub fn shutdown(s: *Session) void {
        sock.shutdown(s.fd);
    }
};

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

const TestPeers = struct {
    keys: [3][32]u8,

    fn lookup(ctx: *anyopaque, key: *const [32]u8) ?u32 {
        const self: *TestPeers = @ptrCast(@alignCast(ctx));
        for (self.keys, 0..) |k, i| if (std.mem.eql(u8, &k, key)) return @intCast(i);
        return null;
    }
};

fn testSeedKey(seed_byte: u8) ![32]u8 {
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(seed_byte));
    return kp.public_key.toBytes();
}

const Loop = struct {
    fn serve(gpa: Allocator, io: Io, l: *Io.net.Server, id: *const Identity, check: PeerKeyCheck, name: []const u8, result: *?Error, peer: *u32) void {
        const st = l.accept(io) catch {
            result.* = error.Io;
            return;
        };
        const fd = st.socket.handle;
        defer _ = std.c.close(fd);
        const sess = Session.accept(gpa, io, fd, name, id, check) catch |e| {
            result.* = e;
            return;
        };
        defer sess.deinit();
        peer.* = sess.peer_index;
        var b: [70000]u8 = undefined;
        while (true) {
            const n = sess.read(&b) catch return;
            if (n == 0) return;
            sess.writeAll(b[0..n]) catch return;
        }
    }
};

test "tls: mutual handshake pinned to committee keys, h2 echo over many records" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var name_buf: [40]u8 = undefined;
    const name = try serverName(&name_buf, 7);
    const seed_a: [32]u8 = @splat(1);
    const seed_b: [32]u8 = @splat(2);
    const id_a = try Identity.init(&seed_a, name);
    const id_b = try Identity.init(&seed_b, name);
    var peers: TestPeers = .{ .keys = .{ try testSeedKey(1), try testSeedKey(2), try testSeedKey(3) } };
    const check: PeerKeyCheck = .{ .ctx = &peers, .lookup = TestPeers.lookup };

    var any: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    var ls = try any.listen(io, .{ .reuse_address = true });
    defer ls.deinit(io);
    const port = ls.socket.address.ip4.port;
    var res: ?Error = null;
    var peer_idx: u32 = 99;
    const t = try std.Thread.spawn(.{}, Loop.serve, .{ gpa, io, &ls, &id_a, check, name, &res, &peer_idx });
    defer t.join();

    var addr: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(port) };
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const fd = stream.socket.handle;
    const pub_a = id_a.publicKey();
    const cl = try Session.connect(gpa, io, fd, name, &id_b, &pub_a);
    defer cl.deinit();
    try std.testing.expectEqualSlices(u8, &pub_a, &cl.peer_key);

    try cl.writeAll("hello consensus");
    var got: [15]u8 = undefined;
    try readExact(cl, &got);
    try std.testing.expectEqualStrings("hello consensus", &got);
    const big = try gpa.alloc(u8, 100_000);
    defer gpa.free(big);
    for (big, 0..) |*x, i| x.* = @truncate(i *% 131);
    try cl.writeAll(big);
    const back = try gpa.alloc(u8, big.len);
    defer gpa.free(back);
    try readExact(cl, back);
    try std.testing.expectEqualSlices(u8, big, back);
    cl.shutdown();
    try std.testing.expect(res == null);
    try std.testing.expectEqual(@as(u32, 1), peer_idx); // authority index of key 2
}

test "tls: KeyUpdate rotates both directions (requested and by record count)" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var name_buf: [40]u8 = undefined;
    const name = try serverName(&name_buf, 7);
    const seed_a: [32]u8 = @splat(1);
    const seed_b: [32]u8 = @splat(2);
    const id_a = try Identity.init(&seed_a, name);
    const id_b = try Identity.init(&seed_b, name);
    var peers: TestPeers = .{ .keys = .{ try testSeedKey(1), try testSeedKey(2), try testSeedKey(3) } };
    const check: PeerKeyCheck = .{ .ctx = &peers, .lookup = TestPeers.lookup };
    var any: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    var ls = try any.listen(io, .{ .reuse_address = true });
    defer ls.deinit(io);
    const port = ls.socket.address.ip4.port;
    var res: ?Error = null;
    var peer_idx: u32 = 99;
    const t = try std.Thread.spawn(.{}, Loop.serve, .{ gpa, io, &ls, &id_a, check, name, &res, &peer_idx });
    defer t.join();
    var addr: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(port) };
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const pub_a = id_a.publicKey();
    const cl = try Session.connect(gpa, io, stream.socket.handle, name, &id_b, &pub_a);
    defer cl.deinit();
    cl.rekey_after = 3;
    var got: [5]u8 = undefined;
    for (0..10) |i| {
        if (i == 4) try cl.sendKeyUpdate(true); // the server rotates and answers with its own
        try cl.writeAll("hello");
        try readExact(cl, &got);
        try std.testing.expectEqualStrings("hello", &got);
    }
    try std.testing.expect(cl.w.seq < 3 + 2);
    cl.shutdown();
    try std.testing.expect(res == null);
}

fn readExact(s: *Session, buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = try s.read(buf[off..]);
        if (n == 0) return error.Closed;
        off += n;
    }
}

test "tls: client refuses a server whose key is not the pinned one" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var name_buf: [40]u8 = undefined;
    const name = try serverName(&name_buf, 1);
    const seed_a: [32]u8 = @splat(1);
    const seed_b: [32]u8 = @splat(2);
    const id_a = try Identity.init(&seed_a, name);
    const id_b = try Identity.init(&seed_b, name);
    var peers: TestPeers = .{ .keys = .{ try testSeedKey(1), try testSeedKey(2), try testSeedKey(3) } };
    const check: PeerKeyCheck = .{ .ctx = &peers, .lookup = TestPeers.lookup };
    var any: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    var ls = try any.listen(io, .{ .reuse_address = true });
    defer ls.deinit(io);
    const port = ls.socket.address.ip4.port;
    var res: ?Error = null;
    var peer_idx: u32 = 99;
    const t = try std.Thread.spawn(.{}, Loop.serve, .{ gpa, io, &ls, &id_a, check, name, &res, &peer_idx });
    defer t.join();
    var addr: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(port) };
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const wrong = try testSeedKey(3);
    try std.testing.expectError(error.BadCertificate, Session.connect(gpa, io, stream.socket.handle, name, &id_b, &wrong));
    sock.shutdown(stream.socket.handle);
}

test "tls: server refuses a client key outside the committee" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var name_buf: [40]u8 = undefined;
    const name = try serverName(&name_buf, 1);
    const seed_a: [32]u8 = @splat(1);
    const seed_x: [32]u8 = @splat(9);
    const id_a = try Identity.init(&seed_a, name);
    const id_x = try Identity.init(&seed_x, name);
    var peers: TestPeers = .{ .keys = .{ try testSeedKey(1), try testSeedKey(2), try testSeedKey(3) } };
    const check: PeerKeyCheck = .{ .ctx = &peers, .lookup = TestPeers.lookup };
    var any: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    var ls = try any.listen(io, .{ .reuse_address = true });
    defer ls.deinit(io);
    const port = ls.socket.address.ip4.port;
    var res: ?Error = null;
    var peer_idx: u32 = 99;
    const t = try std.Thread.spawn(.{}, Loop.serve, .{ gpa, io, &ls, &id_a, check, name, &res, &peer_idx });
    var addr: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(port) };
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const pub_a = id_a.publicKey();
    // The client side may complete its handshake before the server's verdict; either way the
    // server session is refused.
    if (Session.connect(gpa, io, stream.socket.handle, name, &id_x, &pub_a)) |c| c.deinit() else |_| {}
    sock.shutdown(stream.socket.handle);
    t.join();
    try std.testing.expectEqual(@as(?Error, error.PeerNotInCommittee), res);
}

test "server name" {
    var b: [40]u8 = undefined;
    try std.testing.expectEqualStrings("consensus_epoch_12", try serverName(&b, 12));
}
