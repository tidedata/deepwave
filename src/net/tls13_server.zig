//! TLS 1.3 server handshake for QUIC (RFC 8446 + RFC 9001), the counterpart of tls13.zig's
//! client: what an anemo listener needs. One cipher suite (TLS_AES_128_GCM_SHA256), one group
//! (x25519), one signature scheme (Ed25519), mutual authentication with the self-signed
//! network-key certificate (anemo `crypto.rs`: the client must present one), no resumption, no
//! 0-RTT, no ALPN, no HelloRetryRequest (a client without an x25519 key share is refused; rustls
//! and our client always send one). Sans-I/O, the same surface as `tls13.Client`.
const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const Sha256 = crypto.hash.sha2.Sha256;
const X25519 = crypto.dh.X25519;
const Ed25519 = crypto.sign.Ed25519;
const zsig = @import("sig");
const qc = @import("qcrypto.zig");
const x509 = @import("x509.zig");
const tls = @import("tls13.zig");
const tls_identity = @import("tls_identity.zig");

pub const Level = tls.Level;
pub const Error = tls.Error || error{NoApplicationProtocol};

pub const Config = struct {
    /// The anemo server name (`sui-<genesis prefix>`): our certificate's name, and the name the
    /// client's certificate must carry.
    server_name: []const u8,
    /// Encoded QUIC transport parameters (extension 0x39 body).
    local_tp: []const u8,
    identity: Ed25519.KeyPair,
    cert_der: []const u8,
    now_unix: i64,
    random: [32]u8,
    x25519_secret: [32]u8,
    /// ALPN protocols we accept, in preference order (empty: no ALPN, the anemo case). When set,
    /// a ClientHello without one of them is refused (no_application_protocol).
    alpn: []const []const u8 = &.{},
    /// Ask for and verify a client certificate (anemo). zui/1 and WebTransport clients send none.
    client_auth: bool = true,
    /// When the client selects ALPN `cfg.alpn[alt.alpn_index]`, serve `alt.cert_der` and sign
    /// CertificateVerify with this ECDSA P-256 key (ecdsa_secp256r1_sha256) instead of
    /// `identity` (browsers pinning `serverCertificateHashes` need a P-256 certificate).
    alt: ?Alt = null,
    /// TLS over TCP (`--serve-tls`), not QUIC: no quic_transport_parameters either way, ALPN
    /// optional (std.crypto.tls.Client sends none), and `alt`'s certificate always (or `chain`'s).
    tcp: bool = false,
    /// TCP only: a loaded certificate chain and key (sui-node `rpc.tls`, tls_identity.zig),
    /// served instead of `alt`. A client offering ALPN without one of `alpn` is refused
    /// (no_application_protocol, as rustls does).
    chain: ?*const tls_identity.Identity = null,
};

pub const Alt = struct { alpn_index: u8, cert_der: []const u8, key: EcdsaP256.KeyPair };

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const State = enum { wait_ch, wait_cert, wait_cert_verify, wait_finished, connected };

pub const Server = struct {
    cfg: Config,
    state: State = .wait_ch,
    transcript: Sha256 = Sha256.init(.{}),
    inbuf: [3]std.ArrayList(u8) = .{ .empty, .empty, .empty },
    outbuf: [3]std.ArrayList(u8) = .{ .empty, .empty, .empty },

    x_pub: [32]u8,
    hs_secret: qc.Secret = undefined,
    master_secret: qc.Secret = undefined,
    c_hs: ?qc.Secret = null,
    s_hs: ?qc.Secret = null,
    c_ap: ?qc.Secret = null,
    s_ap: ?qc.Secret = null,

    client_key: [32]u8 = undefined,
    peer_id: ?[32]u8 = null,
    peer_tp: [1024]u8 = undefined,
    peer_tp_len: usize = 0,
    /// Set when the client's Finished is verified (the handshake is complete and confirmed).
    complete: bool = false,
    /// Index into `cfg.alpn` of the protocol we selected (null: no ALPN).
    alpn: ?u8 = null,

    pub fn init(cfg: Config) Server {
        return .{ .cfg = cfg, .x_pub = X25519.recoverPublicKey(cfg.x25519_secret) };
    }

    pub fn deinit(s: *Server, gpa: Allocator) void {
        for (&s.inbuf) |*b| b.deinit(gpa);
        for (&s.outbuf) |*b| b.deinit(gpa);
    }

    pub fn peerTransportParams(s: *const Server) []const u8 {
        return s.peer_tp[0..s.peer_tp_len];
    }
    pub fn takeOutput(s: *Server, level: Level) []const u8 {
        return s.outbuf[@intFromEnum(level)].items;
    }
    pub fn clearOutput(s: *Server, level: Level) void {
        s.outbuf[@intFromEnum(level)].clearRetainingCapacity();
    }

    fn transcriptHash(s: *const Server) [32]u8 {
        var t = s.transcript;
        return t.finalResult();
    }

    /// Queues a handshake message at `level` and adds it to the transcript.
    fn msg(s: *Server, gpa: Allocator, level: Level, mt: u8, body: []const u8) !void {
        const hdr: [4]u8 = .{ mt, @intCast(body.len >> 16), @intCast((body.len >> 8) & 0xff), @intCast(body.len & 0xff) };
        s.transcript.update(&hdr);
        s.transcript.update(body);
        const o = &s.outbuf[@intFromEnum(level)];
        try o.appendSlice(gpa, &hdr);
        try o.appendSlice(gpa, body);
    }

    /// Feeds ordered CRYPTO bytes received at `level`.
    pub fn feed(s: *Server, gpa: Allocator, level: Level, data: []const u8) Error!void {
        const b = &s.inbuf[@intFromEnum(level)];
        try b.appendSlice(gpa, data);
        while (true) {
            if (b.items.len < 4) break;
            const mt = b.items[0];
            const len = (@as(usize, b.items[1]) << 16) | (@as(usize, b.items[2]) << 8) | b.items[3];
            if (len > (1 << 16)) return error.DecodeError;
            if (b.items.len < 4 + len) break;
            try s.handle(gpa, level, mt, b.items[0 .. 4 + len]);
            const rest = b.items.len - (4 + len);
            std.mem.copyForwards(u8, b.items[0..rest], b.items[4 + len ..]);
            b.shrinkRetainingCapacity(rest);
        }
    }

    fn handle(s: *Server, gpa: Allocator, level: Level, mt: u8, m: []const u8) Error!void {
        const body = m[4..];
        switch (s.state) {
            .wait_ch => {
                if (level != .initial or mt != 1) return error.UnexpectedMessage;
                const ch = try parseClientHello(body);
                if (s.cfg.tcp) {
                    s.alpn = pickAlpn(s.cfg.alpn, ch.alpn);
                    // rustls: a client that offers ALPN but none of ours is refused
                    if (s.alpn == null and ch.alpn.len > 0 and s.cfg.chain != null) return error.NoApplicationProtocol;
                } else if (s.cfg.alpn.len > 0) {
                    s.alpn = pickAlpn(s.cfg.alpn, ch.alpn) orelse return error.HandshakeFailure;
                }
                if (!s.cfg.tcp and ch.tp == null) return error.MissingTransportParameters;
                const can_sign = if (s.chainOf()) |id| switch (id.key) {
                    .p256 => ch.p256,
                    .p384 => ch.p384,
                    .ed25519 => ch.ed25519,
                    .rsa => ch.rsa_pss,
                } else if (s.useAlt() != null) ch.p256 else ch.ed25519;
                if (!can_sign) return error.HandshakeFailure;
                s.transcript.update(m);
                try s.respond(gpa, ch);
                s.state = if (s.cfg.client_auth) .wait_cert else .wait_finished;
            },
            .wait_cert => {
                if (level != .handshake or mt != 11) return error.UnexpectedMessage;
                try s.certificate(body);
                s.transcript.update(m);
                s.state = .wait_cert_verify;
            },
            .wait_cert_verify => {
                if (level != .handshake or mt != 15) return error.UnexpectedMessage;
                try s.certificateVerify(body);
                s.transcript.update(m);
                s.state = .wait_finished;
            },
            .wait_finished => {
                if (level != .handshake or mt != 20) return error.UnexpectedMessage;
                if (body.len != 32) return error.DecodeError;
                const th = s.transcriptHash();
                const fk = finishedKey(&s.c_hs.?);
                const want = qc.hmac(&fk, &th);
                if (!crypto.timing_safe.eql([32]u8, want, body[0..32].*)) return error.BadFinished;
                s.transcript.update(m);
                s.complete = true;
                s.state = .connected;
            },
            .connected => return error.UnexpectedMessage,
        }
    }

    const ClientHello = struct {
        session_id: []const u8,
        client_pub: [32]u8,
        tp: ?[]const u8,
        alpn: []const u8 = "", // ProtocolNameList body (after its u16 length)
        ed25519: bool = false,
        p256: bool = false,
        p384: bool = false,
        rsa_pss: bool = false,
    };

    fn chainOf(s: *const Server) ?*const tls_identity.Identity {
        return if (s.cfg.tcp) s.cfg.chain else null;
    }

    fn useAlt(s: *const Server) ?Alt {
        const a = s.cfg.alt orelse return null;
        if (s.cfg.tcp) return a;
        return if (s.alpn != null and s.alpn.? == a.alpn_index) a else null;
    }

    fn pickAlpn(ours: []const []const u8, list: []const u8) ?u8 {
        for (ours, 0..) |want, i| {
            var k: usize = 0;
            while (k < list.len) {
                const l = list[k];
                if (k + 1 + l > list.len) return null;
                if (std.mem.eql(u8, list[k + 1 ..][0..l], want)) return @intCast(i);
                k += 1 + l;
            }
        }
        return null;
    }

    fn parseClientHello(b: []const u8) Error!ClientHello {
        var p: usize = 0;
        if (b.len < 2 + 32 + 1) return error.DecodeError;
        if (!std.mem.eql(u8, b[0..2], &.{ 0x03, 0x03 })) return error.IllegalParameter;
        p = 34;
        const sl = b[p];
        p += 1;
        if (sl > 32 or b.len < p + sl + 2) return error.DecodeError;
        const sid = b[p..][0..sl];
        p += sl;
        const csl = std.mem.readInt(u16, b[p..][0..2], .big);
        p += 2;
        if (csl % 2 != 0 or b.len < p + csl + 1) return error.DecodeError;
        var has_suite = false;
        var i: usize = 0;
        while (i < csl) : (i += 2) {
            if (b[p + i] == 0x13 and b[p + i + 1] == 0x01) has_suite = true;
        }
        p += csl;
        const cml = b[p];
        p += 1;
        if (b.len < p + cml + 2) return error.DecodeError;
        p += cml;
        const el = std.mem.readInt(u16, b[p..][0..2], .big);
        p += 2;
        if (b.len != p + el) return error.DecodeError;
        var tls13 = false;
        var ed25519 = false;
        var p256 = false;
        var p384 = false;
        var rsa_pss = false;
        var client_pub: ?[32]u8 = null;
        var tp: ?[]const u8 = null;
        var alpn: []const u8 = "";
        while (p < b.len) {
            if (b.len - p < 4) return error.DecodeError;
            const et = std.mem.readInt(u16, b[p..][0..2], .big);
            const elen = std.mem.readInt(u16, b[p + 2 ..][0..2], .big);
            p += 4;
            if (b.len - p < elen) return error.DecodeError;
            const ed = b[p..][0..elen];
            p += elen;
            switch (et) {
                0x002b => { // supported_versions
                    if (ed.len < 1 or ed[0] + 1 != ed.len or ed[0] % 2 != 0) return error.DecodeError;
                    var k: usize = 1;
                    while (k < ed.len) : (k += 2) if (ed[k] == 0x03 and ed[k + 1] == 0x04) {
                        tls13 = true;
                    };
                },
                0x000d => { // signature_algorithms
                    if (ed.len < 2) return error.DecodeError;
                    const l = std.mem.readInt(u16, ed[0..2], .big);
                    if (l + 2 != ed.len or l % 2 != 0) return error.DecodeError;
                    var k: usize = 2;
                    while (k < ed.len) : (k += 2) {
                        if (ed[k] == 0x08 and ed[k + 1] == 0x07) ed25519 = true;
                        if (ed[k] == 0x04 and ed[k + 1] == 0x03) p256 = true;
                        if (ed[k] == 0x05 and ed[k + 1] == 0x03) p384 = true;
                        if (ed[k] == 0x08 and ed[k + 1] == 0x04) rsa_pss = true;
                    }
                },
                0x0033 => { // key_share
                    if (ed.len < 2) return error.DecodeError;
                    const l = std.mem.readInt(u16, ed[0..2], .big);
                    if (l + 2 != ed.len) return error.DecodeError;
                    var k: usize = 2;
                    while (k + 4 <= ed.len) {
                        const g = std.mem.readInt(u16, ed[k..][0..2], .big);
                        const kl = std.mem.readInt(u16, ed[k + 2 ..][0..2], .big);
                        k += 4;
                        if (ed.len - k < kl) return error.DecodeError;
                        if (g == 0x001d and kl == 32) client_pub = ed[k..][0..32].*;
                        k += kl;
                    }
                },
                0x0039 => tp = ed, // quic_transport_parameters
                0x0010 => { // application_layer_protocol_negotiation
                    if (ed.len < 2 or std.mem.readInt(u16, ed[0..2], .big) + 2 != ed.len) return error.DecodeError;
                    alpn = ed[2..];
                },
                else => {}, // server_name, supported_groups, alpn, psk modes...: nothing to do
            }
        }
        if (!tls13 or !has_suite) return error.HandshakeFailure;
        if (client_pub == null) return error.HelloRetryRequest;
        return .{ .session_id = sid, .client_pub = client_pub.?, .tp = tp, .alpn = alpn, .ed25519 = ed25519, .p256 = p256, .p384 = p384, .rsa_pss = rsa_pss };
    }

    /// ServerHello (Initial), then EncryptedExtensions, CertificateRequest, Certificate,
    /// CertificateVerify and Finished (Handshake); derives every secret.
    fn respond(s: *Server, gpa: Allocator, ch: ClientHello) Error!void {
        const ctp = ch.tp orelse "";
        if (ctp.len > s.peer_tp.len) return error.IllegalParameter;
        @memcpy(s.peer_tp[0..ctp.len], ctp);
        s.peer_tp_len = ctp.len;
        var l: std.ArrayList(u8) = .empty;
        defer l.deinit(gpa);
        // ServerHello
        try l.appendSlice(gpa, &.{ 0x03, 0x03 });
        try l.appendSlice(gpa, &s.cfg.random);
        try l.append(gpa, @intCast(ch.session_id.len));
        try l.appendSlice(gpa, ch.session_id);
        try l.appendSlice(gpa, &.{ 0x13, 0x01, 0x00 });
        try l.appendSlice(gpa, &.{ 0x00, 46 }); // extensions length: 6 + 40
        try l.appendSlice(gpa, &.{ 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 });
        try l.appendSlice(gpa, &.{ 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 });
        try l.appendSlice(gpa, &s.x_pub);
        try s.msg(gpa, .initial, 2, l.items);
        // key schedule
        const shared = X25519.scalarmult(s.cfg.x25519_secret, ch.client_pub) catch return error.IllegalParameter;
        const zeros: [32]u8 = @splat(0);
        const early = qc.extract(&zeros, &zeros);
        const derived = qc.deriveSecret(&early, "derived", &qc.empty_hash);
        s.hs_secret = qc.extract(&derived, &shared);
        const th_sh = s.transcriptHash();
        s.c_hs = qc.deriveSecret(&s.hs_secret, "c hs traffic", &th_sh);
        s.s_hs = qc.deriveSecret(&s.hs_secret, "s hs traffic", &th_sh);
        const d2 = qc.deriveSecret(&s.hs_secret, "derived", &qc.empty_hash);
        s.master_secret = qc.extract(&d2, &zeros);
        // EncryptedExtensions: quic_transport_parameters
        l.clearRetainingCapacity();
        const tpl = s.cfg.local_tp.len;
        const tp_ext: usize = if (s.cfg.tcp) 0 else 4 + tpl;
        const proto: []const u8 = if (s.alpn) |i| s.cfg.alpn[i] else "";
        const alpn_ext: usize = if (s.alpn != null) 4 + 2 + 1 + proto.len else 0;
        try appendU16(&l, gpa, @intCast(tp_ext + alpn_ext));
        if (!s.cfg.tcp) {
            try appendU16(&l, gpa, 0x0039);
            try appendU16(&l, gpa, @intCast(tpl));
            try l.appendSlice(gpa, s.cfg.local_tp);
        }
        if (s.alpn != null) {
            try appendU16(&l, gpa, 0x0010);
            try appendU16(&l, gpa, @intCast(2 + 1 + proto.len));
            try appendU16(&l, gpa, @intCast(1 + proto.len));
            try l.append(gpa, @intCast(proto.len));
            try l.appendSlice(gpa, proto);
        }
        try s.msg(gpa, .handshake, 8, l.items);
        // CertificateRequest: empty context, signature_algorithms = ed25519
        if (s.cfg.client_auth) try s.msg(gpa, .handshake, 13, &.{ 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07 });
        // Certificate
        l.clearRetainingCapacity();
        const one = [_][]const u8{if (s.useAlt()) |a| a.cert_der else s.cfg.cert_der};
        const certs: []const []const u8 = if (s.chainOf()) |id| id.certs else &one;
        try l.append(gpa, 0);
        var list_len: usize = 0;
        for (certs) |cd| list_len += 3 + cd.len + 2;
        try l.appendSlice(gpa, &.{ @intCast(list_len >> 16), @intCast((list_len >> 8) & 0xff), @intCast(list_len & 0xff) });
        for (certs) |cd| {
            try l.appendSlice(gpa, &.{ @intCast(cd.len >> 16), @intCast((cd.len >> 8) & 0xff), @intCast(cd.len & 0xff) });
            try l.appendSlice(gpa, cd);
            try l.appendSlice(gpa, &.{ 0, 0 });
        }
        try s.msg(gpa, .handshake, 11, l.items);
        // CertificateVerify
        {
            const th = s.transcriptHash();
            var m: [64 + 34 + 32]u8 = undefined;
            @memset(m[0..64], 0x20);
            @memcpy(m[64..][0..34], "TLS 1.3, server CertificateVerify\x00");
            @memcpy(m[98..][0..32], &th);
            if (s.chainOf()) |id| {
                // the RSA-PSS salt: fresh per connection, derived from this handshake's secret
                var salt: [32]u8 = undefined;
                var h = Sha256.init(.{});
                h.update("zui tls pss salt");
                h.update(&s.cfg.x25519_secret);
                h.final(&salt);
                var sig_buf: [tls_identity.max_signature_len]u8 = undefined;
                const sig = id.sign(&m, salt, &sig_buf) catch return error.HandshakeFailure;
                const scheme: u16 = @intFromEnum(id.key.scheme());
                var cv: [4 + tls_identity.max_signature_len]u8 = undefined;
                cv[0..4].* = .{ @intCast(scheme >> 8), @intCast(scheme & 0xff), @intCast(sig.len >> 8), @intCast(sig.len & 0xff) };
                @memcpy(cv[4..][0..sig.len], sig);
                try s.msg(gpa, .handshake, 15, cv[0 .. 4 + sig.len]);
            } else if (s.useAlt()) |a| {
                const sig = a.key.sign(&m, null) catch return error.HandshakeFailure;
                var der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
                const der = sig.toDer(&der_buf);
                var cv: [4 + EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
                cv[0..4].* = .{ 0x04, 0x03, 0x00, @intCast(der.len) };
                @memcpy(cv[4..][0..der.len], der);
                try s.msg(gpa, .handshake, 15, cv[0 .. 4 + der.len]);
            } else {
            const sig = s.cfg.identity.sign(&m, null) catch return error.HandshakeFailure;
            var cv: [4 + 64]u8 = undefined;
            cv[0..4].* = .{ 0x08, 0x07, 0x00, 64 };
            @memcpy(cv[4..], &sig.toBytes());
            try s.msg(gpa, .handshake, 15, &cv);
            }
        }
        // Finished
        {
            const th = s.transcriptHash();
            const fk = finishedKey(&s.s_hs.?);
            const v = qc.hmac(&fk, &th);
            try s.msg(gpa, .handshake, 20, &v);
        }
        const th_sf = s.transcriptHash();
        s.c_ap = qc.deriveSecret(&s.master_secret, "c ap traffic", &th_sf);
        s.s_ap = qc.deriveSecret(&s.master_secret, "s ap traffic", &th_sf);
    }

    fn certificate(s: *Server, b: []const u8) Error!void {
        if (b.len < 4) return error.DecodeError;
        if (b[0] != 0) return error.DecodeError; // our request context is empty
        const list_len = (@as(usize, b[1]) << 16) | (@as(usize, b[2]) << 8) | b[3];
        if (b.len != 4 + list_len) return error.DecodeError;
        if (list_len < 3) return error.BadCertificate; // anemo requires a client certificate
        const cl = (@as(usize, b[4]) << 16) | (@as(usize, b[5]) << 8) | b[6];
        if (7 + cl > b.len) return error.DecodeError;
        const parsed = x509.verifyPeerCert(b[7..][0..cl], s.cfg.server_name, .client, s.cfg.now_unix) catch return error.BadCertificate;
        s.client_key = parsed.public_key;
        s.peer_id = parsed.public_key;
    }

    fn certificateVerify(s: *Server, b: []const u8) Error!void {
        if (b.len < 4) return error.DecodeError;
        const scheme = std.mem.readInt(u16, b[0..2], .big);
        const sl = std.mem.readInt(u16, b[2..4], .big);
        if (scheme != 0x0807 or b.len != 4 + sl or sl != 64) return error.BadSignature;
        const th = s.transcriptHash();
        var m: [64 + 34 + 32]u8 = undefined;
        @memset(m[0..64], 0x20);
        @memcpy(m[64..][0..34], "TLS 1.3, client CertificateVerify\x00");
        @memcpy(m[98..][0..32], &th);
        if (zsig.ed25519.verify(&s.client_key, &m, b[4..68]) != .valid) return error.BadSignature;
    }
};

fn finishedKey(secret: *const qc.Secret) [32]u8 {
    var k: [32]u8 = undefined;
    qc.expandLabel(secret, "finished", "", &k);
    return k;
}

fn appendU16(l: *std.ArrayList(u8), gpa: Allocator, v: u16) !void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .big);
    try l.appendSlice(gpa, &b);
}

test "tls13 client and server complete a mutual handshake" {
    const gpa = std.testing.allocator;
    const name = "sui-35834a8a";
    const ckp = try Ed25519.KeyPair.generateDeterministic(@splat(1));
    const skp = try Ed25519.KeyPair.generateDeterministic(@splat(2));
    var ccert: [x509.max_cert_len]u8 = undefined;
    var scert: [x509.max_cert_len]u8 = undefined;
    const cl = x509.generateSelfSigned(&ccert, ckp, @splat(5), name);
    const sl = x509.generateSelfSigned(&scert, skp, @splat(6), name);
    var c = tls.Client.init(.{ .server_name = name, .local_tp = "ctp", .identity = ckp, .cert_der = ccert[0..cl], .expected_peer = skp.public_key.toBytes(), .now_unix = 1_800_000_000, .random = @splat(7), .x25519_secret = @splat(8) });
    defer c.deinit(gpa);
    var s = Server.init(.{ .server_name = name, .local_tp = "stp", .identity = skp, .cert_der = scert[0..sl], .now_unix = 1_800_000_000, .random = @splat(9), .x25519_secret = @splat(10) });
    defer s.deinit(gpa);
    try c.start(gpa);
    try s.feed(gpa, .initial, c.takeOutput(.initial));
    c.clearOutput(.initial);
    try c.feed(gpa, .initial, s.takeOutput(.initial));
    try c.feed(gpa, .handshake, s.takeOutput(.handshake));
    s.clearOutput(.initial);
    s.clearOutput(.handshake);
    try std.testing.expect(c.complete);
    try s.feed(gpa, .handshake, c.takeOutput(.handshake));
    try std.testing.expect(s.complete);
    try std.testing.expectEqualSlices(u8, "stp", c.peerTransportParams());
    try std.testing.expectEqualSlices(u8, "ctp", s.peerTransportParams());
    try std.testing.expectEqual(ckp.public_key.toBytes(), s.peer_id.?);
    try std.testing.expectEqual(c.c_ap.?, s.c_ap.?);
    try std.testing.expectEqual(c.s_ap.?, s.s_ap.?);
    try std.testing.expectEqual(c.c_hs.?, s.c_hs.?);
}

test "tls13 server over TCP with a loaded chain refuses a client whose ALPN list has none of ours" {
    const gpa = std.testing.allocator;
    const tls_id = @import("tls_identity.zig");
    var id = try tls_id.load(gpa, @embedFile("testdata/tls-cert.pem"), @embedFile("testdata/tls-key.pem"));
    defer id.deinit();
    const ckp = try Ed25519.KeyPair.generateDeterministic(@splat(1));
    const skp = try Ed25519.KeyPair.generateDeterministic(@splat(2));
    var ccert: [x509.max_cert_len]u8 = undefined;
    const cl = x509.generateSelfSigned(&ccert, ckp, @splat(5), "x");
    for ([_][]const u8{ "grpc-exp", "h2" }) |proto| {
        var c = tls.Client.init(.{ .server_name = "x", .local_tp = "", .identity = ckp, .cert_der = ccert[0..cl], .now_unix = 1_800_000_000, .random = @splat(7), .x25519_secret = @splat(8), .alpn = proto });
        defer c.deinit(gpa);
        var s = Server.init(.{ .server_name = "zui", .local_tp = "", .identity = skp, .cert_der = "", .now_unix = 0, .random = @splat(9), .x25519_secret = @splat(10), .alpn = &.{ "h2", "http/1.1" }, .client_auth = false, .tcp = true, .chain = &id });
        defer s.deinit(gpa);
        try c.start(gpa);
        const r = s.feed(gpa, .initial, c.takeOutput(.initial));
        if (std.mem.eql(u8, proto, "grpc-exp")) {
            try std.testing.expectError(error.NoApplicationProtocol, r);
        } else {
            // h2 overlaps; the anemo test client offers ed25519 only, so the P-256 chain cannot sign
            try std.testing.expectError(error.HandshakeFailure, r);
            try std.testing.expectEqual(@as(?u8, 0), s.alpn);
        }
    }
}
