//! TLS 1.3 client handshake for QUIC (RFC 8446 + RFC 9001), exactly what anemo needs: one cipher
//! suite (TLS_AES_128_GCM_SHA256), one group (x25519), one signature scheme (Ed25519), mutual
//! authentication with the self-signed network-key certificate (anemo `crypto.rs`), no resumption,
//! no ALPN. Sans-I/O: the QUIC layer feeds CRYPTO bytes per encryption level and collects the
//! bytes and secrets to install.
const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const Sha256 = crypto.hash.sha2.Sha256;
const X25519 = crypto.dh.X25519;
const Ed25519 = crypto.sign.Ed25519;
const zsig = @import("sig");
const qc = @import("qcrypto.zig");
const x509 = @import("x509.zig");

pub const Level = enum(u2) { initial = 0, handshake = 1, app = 2 };

pub const Error = error{
    UnexpectedMessage,
    DecodeError,
    IllegalParameter,
    HelloRetryRequest,
    HandshakeFailure,
    BadCertificate,
    BadSignature,
    BadFinished,
    MissingTransportParameters,
    PeerIdMismatch,
    OutOfMemory,
};

pub const Config = struct {
    server_name: []const u8,
    /// Encoded QUIC transport parameters (extension 0x39 body).
    local_tp: []const u8,
    identity: Ed25519.KeyPair,
    cert_der: []const u8,
    expected_peer: ?[32]u8 = null,
    /// ALPN protocol to offer (empty: none, the anemo case).
    alpn: []const u8 = "",
    now_unix: i64,
    random: [32]u8,
    x25519_secret: [32]u8,
};

const State = enum { wait_sh, wait_ee, wait_cert_or_req, wait_cert, wait_cert_verify, wait_finished, connected };

const hrr_random = [32]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

pub const Client = struct {
    cfg: Config,
    state: State = .wait_sh,
    transcript: Sha256 = Sha256.init(.{}),
    /// Partial handshake messages per level.
    inbuf: [3]std.ArrayList(u8) = .{ .empty, .empty, .empty },
    /// Handshake bytes to send per level (the QUIC layer drains these).
    outbuf: [3]std.ArrayList(u8) = .{ .empty, .empty, .empty },

    x_pub: [32]u8,
    hs_secret: qc.Secret = undefined,
    master_secret: qc.Secret = undefined,
    c_hs: ?qc.Secret = null,
    s_hs: ?qc.Secret = null,
    c_ap: ?qc.Secret = null,
    s_ap: ?qc.Secret = null,

    cert_request_context: [255]u8 = undefined,
    cert_request_context_len: u8 = 0,
    client_auth: bool = false,
    server_key: [32]u8 = undefined,
    peer_id: ?[32]u8 = null,
    peer_tp: [1024]u8 = undefined,
    peer_tp_len: usize = 0,
    /// Set when the handshake is complete (server Finished verified, ours queued).
    complete: bool = false,

    pub fn init(cfg: Config) Client {
        return .{ .cfg = cfg, .x_pub = X25519.recoverPublicKey(cfg.x25519_secret) };
    }

    pub fn deinit(c: *Client, gpa: Allocator) void {
        for (&c.inbuf) |*b| b.deinit(gpa);
        for (&c.outbuf) |*b| b.deinit(gpa);
    }

    pub fn peerTransportParams(c: *const Client) []const u8 {
        return c.peer_tp[0..c.peer_tp_len];
    }

    /// Takes the bytes queued for `level` (caller frees nothing; valid until the next call).
    pub fn takeOutput(c: *Client, level: Level) []const u8 {
        const b = &c.outbuf[@intFromEnum(level)];
        return b.items;
    }
    pub fn clearOutput(c: *Client, level: Level) void {
        c.outbuf[@intFromEnum(level)].clearRetainingCapacity();
    }

    fn put(c: *Client, gpa: Allocator, level: Level, bytes: []const u8) !void {
        try c.outbuf[@intFromEnum(level)].appendSlice(gpa, bytes);
    }

    // ------------------------------------------------------------ ClientHello

    pub fn start(c: *Client, gpa: Allocator) Error!void {
        var l: std.ArrayList(u8) = .empty;
        defer l.deinit(gpa);
        try l.appendSlice(gpa, &.{ 0x01, 0, 0, 0 }); // type + length placeholder
        try l.appendSlice(gpa, &.{ 0x03, 0x03 });
        try l.appendSlice(gpa, &c.cfg.random);
        try l.append(gpa, 0); // legacy_session_id
        try l.appendSlice(gpa, &.{ 0x00, 0x02, 0x13, 0x01 });
        try l.appendSlice(gpa, &.{ 0x01, 0x00 });
        const ext_len_pos = l.items.len;
        try l.appendSlice(gpa, &.{ 0, 0 });
        const ext_start = l.items.len;
        // server_name
        const sn = c.cfg.server_name;
        try appendU16(&l, gpa, 0x0000);
        try appendU16(&l, gpa, @intCast(sn.len + 5));
        try appendU16(&l, gpa, @intCast(sn.len + 3));
        try l.append(gpa, 0);
        try appendU16(&l, gpa, @intCast(sn.len));
        try l.appendSlice(gpa, sn);
        // supported_groups: x25519
        try l.appendSlice(gpa, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });
        // signature_algorithms: ed25519
        try l.appendSlice(gpa, &.{ 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07 });
        // key_share
        try l.appendSlice(gpa, &.{ 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 });
        try l.appendSlice(gpa, &c.x_pub);
        // supported_versions: TLS 1.3
        try l.appendSlice(gpa, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });
        if (c.cfg.alpn.len > 0) { // application_layer_protocol_negotiation
            try appendU16(&l, gpa, 0x0010);
            try appendU16(&l, gpa, @intCast(c.cfg.alpn.len + 3));
            try appendU16(&l, gpa, @intCast(c.cfg.alpn.len + 1));
            try l.append(gpa, @intCast(c.cfg.alpn.len));
            try l.appendSlice(gpa, c.cfg.alpn);
        }
        // quic_transport_parameters
        try appendU16(&l, gpa, 0x0039);
        try appendU16(&l, gpa, @intCast(c.cfg.local_tp.len));
        try l.appendSlice(gpa, c.cfg.local_tp);
        const ext_total = l.items.len - ext_start;
        std.mem.writeInt(u16, l.items[ext_len_pos..][0..2], @intCast(ext_total), .big);
        const body_len = l.items.len - 4;
        l.items[1] = @intCast(body_len >> 16);
        l.items[2] = @intCast((body_len >> 8) & 0xff);
        l.items[3] = @intCast(body_len & 0xff);
        c.transcript.update(l.items);
        try c.put(gpa, .initial, l.items);
    }

    fn appendU16(l: *std.ArrayList(u8), gpa: Allocator, v: u16) !void {
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, v, .big);
        try l.appendSlice(gpa, &b);
    }

    // ------------------------------------------------------------ receive

    /// Feeds ordered CRYPTO bytes received at `level`.
    pub fn feed(c: *Client, gpa: Allocator, level: Level, data: []const u8) Error!void {
        const buf = &c.inbuf[@intFromEnum(level)];
        try buf.appendSlice(gpa, data);
        while (true) {
            if (buf.items.len < 4) break;
            const mt = buf.items[0];
            const len = (@as(usize, buf.items[1]) << 16) | (@as(usize, buf.items[2]) << 8) | buf.items[3];
            if (len > (1 << 20)) return error.DecodeError;
            if (buf.items.len < 4 + len) break;
            // Copy out: handlers append to other buffers only, but keep it simple and safe.
            try c.handle(gpa, level, mt, buf.items[0 .. 4 + len]);
            const rest = buf.items.len - (4 + len);
            std.mem.copyForwards(u8, buf.items[0..rest], buf.items[4 + len ..]);
            buf.shrinkRetainingCapacity(rest);
        }
    }

    fn transcriptHash(c: *const Client) [32]u8 {
        var t = c.transcript;
        return t.finalResult();
    }

    fn handle(c: *Client, gpa: Allocator, level: Level, mt: u8, msg: []const u8) Error!void {
        const body = msg[4..];
        switch (c.state) {
            .wait_sh => {
                if (level != .initial or mt != 2) return error.UnexpectedMessage;
                try c.serverHello(gpa, body);
                c.transcript.update(msg);
                try c.deriveHandshake();
                c.state = .wait_ee;
            },
            .wait_ee => {
                if (level != .handshake or mt != 8) return error.UnexpectedMessage;
                try c.encryptedExtensions(body);
                c.transcript.update(msg);
                c.state = .wait_cert_or_req;
            },
            .wait_cert_or_req => {
                if (level != .handshake) return error.UnexpectedMessage;
                if (mt == 13) {
                    if (body.len < 1 or body[0] > body.len - 1) return error.DecodeError;
                    c.cert_request_context_len = body[0];
                    @memcpy(c.cert_request_context[0..body[0]], body[1..][0..body[0]]);
                    c.client_auth = true;
                    c.transcript.update(msg);
                    c.state = .wait_cert;
                } else if (mt == 11) {
                    try c.certificate(body);
                    c.transcript.update(msg);
                    c.state = .wait_cert_verify;
                } else return error.UnexpectedMessage;
            },
            .wait_cert => {
                if (level != .handshake or mt != 11) return error.UnexpectedMessage;
                try c.certificate(body);
                c.transcript.update(msg);
                c.state = .wait_cert_verify;
            },
            .wait_cert_verify => {
                if (level != .handshake or mt != 15) return error.UnexpectedMessage;
                try c.certificateVerify(body);
                c.transcript.update(msg);
                c.state = .wait_finished;
            },
            .wait_finished => {
                if (level != .handshake or mt != 20) return error.UnexpectedMessage;
                try c.serverFinished(gpa, body);
                c.transcript.update(msg);
                try c.finishHandshake(gpa);
                c.state = .connected;
            },
            .connected => {
                if (level != .app) return error.UnexpectedMessage;
                // NewSessionTicket (4) and anything else post-handshake: ignored. KeyUpdate is
                // forbidden in QUIC.
                if (mt == 24) return error.UnexpectedMessage;
            },
        }
    }

    fn serverHello(c: *Client, gpa: Allocator, b: []const u8) Error!void {
        _ = gpa;
        if (b.len < 2 + 32 + 1) return error.DecodeError;
        if (!std.mem.eql(u8, b[0..2], &.{ 0x03, 0x03 })) return error.IllegalParameter;
        if (std.mem.eql(u8, b[2..34], &hrr_random)) return error.HelloRetryRequest;
        var p: usize = 34;
        const sid = b[p];
        p += 1;
        if (sid != 0 or b.len < p + sid + 2 + 1 + 2) return error.IllegalParameter;
        if (!std.mem.eql(u8, b[p..][0..2], &.{ 0x13, 0x01 })) return error.HandshakeFailure;
        p += 2;
        if (b[p] != 0) return error.IllegalParameter;
        p += 1;
        const ext_len = std.mem.readInt(u16, b[p..][0..2], .big);
        p += 2;
        if (b.len != p + ext_len) return error.DecodeError;
        var got_version = false;
        var server_pub: ?[32]u8 = null;
        while (p < b.len) {
            if (b.len - p < 4) return error.DecodeError;
            const et = std.mem.readInt(u16, b[p..][0..2], .big);
            const el = std.mem.readInt(u16, b[p + 2 ..][0..2], .big);
            p += 4;
            if (b.len - p < el) return error.DecodeError;
            const ed = b[p..][0..el];
            p += el;
            switch (et) {
                0x002b => {
                    if (el != 2 or !std.mem.eql(u8, ed, &.{ 0x03, 0x04 })) return error.IllegalParameter;
                    got_version = true;
                },
                0x0033 => {
                    if (el != 36 or !std.mem.eql(u8, ed[0..4], &.{ 0x00, 0x1d, 0x00, 0x20 })) return error.IllegalParameter;
                    server_pub = ed[4..36].*;
                },
                else => return error.IllegalParameter,
            }
        }
        if (!got_version or server_pub == null) return error.IllegalParameter;
        const shared = X25519.scalarmult(c.cfg.x25519_secret, server_pub.?) catch return error.IllegalParameter;
        // early secret (no PSK): Extract(0^32 salt, 0^32 ikm)
        const zeros: [32]u8 = @splat(0);
        const early = qc.extract(&zeros, &zeros);
        const derived = qc.deriveSecret(&early, "derived", &qc.empty_hash);
        c.hs_secret = qc.extract(&derived, &shared);
    }

    fn deriveHandshake(c: *Client) Error!void {
        const th = c.transcriptHash();
        c.c_hs = qc.deriveSecret(&c.hs_secret, "c hs traffic", &th);
        c.s_hs = qc.deriveSecret(&c.hs_secret, "s hs traffic", &th);
        const derived = qc.deriveSecret(&c.hs_secret, "derived", &qc.empty_hash);
        const zeros: [32]u8 = @splat(0);
        c.master_secret = qc.extract(&derived, &zeros);
    }

    fn encryptedExtensions(c: *Client, b: []const u8) Error!void {
        if (b.len < 2) return error.DecodeError;
        const tl = std.mem.readInt(u16, b[0..2], .big);
        if (b.len != 2 + tl) return error.DecodeError;
        var p: usize = 2;
        var got = false;
        while (p < b.len) {
            if (b.len - p < 4) return error.DecodeError;
            const et = std.mem.readInt(u16, b[p..][0..2], .big);
            const el = std.mem.readInt(u16, b[p + 2 ..][0..2], .big);
            p += 4;
            if (b.len - p < el) return error.DecodeError;
            if (et == 0x0039) {
                if (el > c.peer_tp.len) return error.IllegalParameter;
                @memcpy(c.peer_tp[0..el], b[p..][0..el]);
                c.peer_tp_len = el;
                got = true;
            }
            p += el;
        }
        if (!got) return error.MissingTransportParameters;
    }

    fn certificate(c: *Client, b: []const u8) Error!void {
        if (b.len < 1) return error.DecodeError;
        const ctx = b[0];
        if (ctx != 0 or b.len < 1 + 3) return error.DecodeError;
        const list_len = (@as(usize, b[1]) << 16) | (@as(usize, b[2]) << 8) | b[3];
        if (b.len != 4 + list_len or list_len < 3) return error.DecodeError;
        const cl = (@as(usize, b[4]) << 16) | (@as(usize, b[5]) << 8) | b[6];
        if (7 + cl > b.len) return error.DecodeError;
        const der = b[7..][0..cl];
        // Only the end-entity certificate matters: the chain is the self-signed certificate.
        const parsed = x509.verifyPeerCert(der, c.cfg.server_name, .server, c.cfg.now_unix) catch return error.BadCertificate;
        if (c.cfg.expected_peer) |e| if (!std.mem.eql(u8, &e, &parsed.public_key)) return error.PeerIdMismatch;
        c.server_key = parsed.public_key;
        c.peer_id = parsed.public_key;
    }

    fn certificateVerify(c: *Client, b: []const u8) Error!void {
        if (b.len < 4) return error.DecodeError;
        const scheme = std.mem.readInt(u16, b[0..2], .big);
        const sl = std.mem.readInt(u16, b[2..4], .big);
        if (scheme != 0x0807 or b.len != 4 + sl or sl != 64) return error.BadSignature;
        const th = c.transcriptHash();
        var msg: [64 + 34 + 32]u8 = undefined;
        @memset(msg[0..64], 0x20);
        @memcpy(msg[64..][0..34], "TLS 1.3, server CertificateVerify\x00");
        @memcpy(msg[98..][0..32], &th);
        if (zsig.ed25519.verify(&c.server_key, &msg, b[4..68]) != .valid) return error.BadSignature;
    }

    fn finishedKey(secret: *const qc.Secret) [32]u8 {
        var k: [32]u8 = undefined;
        qc.expandLabel(secret, "finished", "", &k);
        return k;
    }

    fn serverFinished(c: *Client, gpa: Allocator, b: []const u8) Error!void {
        _ = gpa;
        if (b.len != 32) return error.DecodeError;
        const th = c.transcriptHash();
        const fk = finishedKey(&c.s_hs.?);
        const want = qc.hmac(&fk, &th);
        if (!crypto.timing_safe.eql([32]u8, want, b[0..32].*)) return error.BadFinished;
    }

    fn handshakeMsg(c: *Client, gpa: Allocator, mt: u8, body: []const u8) !void {
        var hdr: [4]u8 = .{ mt, @intCast(body.len >> 16), @intCast((body.len >> 8) & 0xff), @intCast(body.len & 0xff) };
        c.transcript.update(&hdr);
        c.transcript.update(body);
        try c.put(gpa, .handshake, &hdr);
        try c.put(gpa, .handshake, body);
    }

    /// After the server Finished: derive application secrets (transcript through server Finished),
    /// then queue our Certificate, CertificateVerify and Finished.
    fn finishHandshake(c: *Client, gpa: Allocator) Error!void {
        const th_server = c.transcriptHash();
        c.c_ap = qc.deriveSecret(&c.master_secret, "c ap traffic", &th_server);
        c.s_ap = qc.deriveSecret(&c.master_secret, "s ap traffic", &th_server);

        if (c.client_auth) {
            // Certificate
            var cert_msg: std.ArrayList(u8) = .empty;
            defer cert_msg.deinit(gpa);
            try cert_msg.append(gpa, c.cert_request_context_len);
            try cert_msg.appendSlice(gpa, c.cert_request_context[0..c.cert_request_context_len]);
            const list_len = 3 + c.cfg.cert_der.len + 2;
            try cert_msg.appendSlice(gpa, &.{ @intCast(list_len >> 16), @intCast((list_len >> 8) & 0xff), @intCast(list_len & 0xff) });
            try cert_msg.appendSlice(gpa, &.{ @intCast(c.cfg.cert_der.len >> 16), @intCast((c.cfg.cert_der.len >> 8) & 0xff), @intCast(c.cfg.cert_der.len & 0xff) });
            try cert_msg.appendSlice(gpa, c.cfg.cert_der);
            try cert_msg.appendSlice(gpa, &.{ 0, 0 });
            try c.handshakeMsg(gpa, 11, cert_msg.items);
            // CertificateVerify
            const th = c.transcriptHash();
            var msg: [64 + 34 + 32]u8 = undefined;
            @memset(msg[0..64], 0x20);
            @memcpy(msg[64..][0..34], "TLS 1.3, client CertificateVerify\x00");
            @memcpy(msg[98..][0..32], &th);
            const sig = c.cfg.identity.sign(&msg, null) catch return error.HandshakeFailure;
            var cv: [4 + 64]u8 = undefined;
            cv[0] = 0x08;
            cv[1] = 0x07;
            cv[2] = 0;
            cv[3] = 64;
            @memcpy(cv[4..], &sig.toBytes());
            try c.handshakeMsg(gpa, 15, &cv);
        }
        // Finished
        const th = c.transcriptHash();
        const fk = finishedKey(&c.c_hs.?);
        const verify = qc.hmac(&fk, &th);
        try c.handshakeMsg(gpa, 20, &verify);
        c.complete = true;
    }
};
