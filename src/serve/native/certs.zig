//! The certificate the zui/1 listener presents to browsers (ALPN `h3`), and what
//! `GET /native/cert-hash`, `GET /native/cert-hashes` and `--native-cert-hash-file` say about it
//! (docs/NATIVE-PROTOCOL.md 1.3).
//!
//! Browsers without a WebPKI certificate pin the node's self-signed certificate by hash
//! (WebTransport `serverCertificateHashes`: ECDSA P-256, a validity of at most 14 days), so the
//! certificate has to change while the node runs:
//!
//! - Time is cut into 7-day periods; period `p` starts at unix second `p * 604800` (Thursdays,
//!   00:00 UTC). Period `p` has one certificate, presented to every handshake that starts in it.
//! - Its key and serial are derived from the node's zui/1 identity seed and `p`, and its validity
//!   is fixed by `p`, so the bytes (and the hash) depend on nothing else: a restart presents the
//!   same certificate, and nothing but the identity file is persisted.
//! - A TLS server presents one certificate per handshake and a ClientHello does not say which
//!   hash the page pinned, so the listener cannot offer "old or new" per client. At a period
//!   boundary new handshakes get the new certificate and connections made before it go on. The
//!   overlap is in what is published: the next period's hash is public from the start of the
//!   current one, so a page that pins both hashes connects for 7 to 14 days without asking again.
//! - Validity: from 3 days before the period to 3 days after it (13 days), so clients whose clock
//!   is off by days still accept it.
//!
//! With `--native-cert` and `--native-key` (`Options.files`) the node presents the operator's
//! certificate chain instead, a WebPKI certificate browsers reach with a plain https URL:
//! nothing is derived, nothing rotates and there is no hash to pin (the hash endpoints answer
//! 204). The files are checked at start (the chain parses and is in order, the key is the
//! leaf's, nothing has expired) and loaded again on SIGHUP or when they change on disk; a
//! reload that fails the same checks is refused and the certificate in use stays.
//!
//! The gRPC TLS port keeps `--serve-tls-cert` and `--serve-tls-key` current with the same
//! machinery (`Certs.initLoaded`, tcptls.zig): the node reads the files at start as it always
//! did, and from then on a SIGHUP or a change on disk loads them again under the checks above.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const net = @import("net");
const tls_identity = net.tls_identity;
const cert_mod = @import("cert.zig");
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

/// How long one certificate is presented.
pub const period_s: i64 = 7 * 86400;
/// A certificate is valid from this long before its period starts.
pub const lead_s: i64 = 3 * 86400;
/// Days of validity (Chrome refuses a pinned certificate valid for more than 14).
pub const valid_days: u32 = 13;

/// Unix seconds. Tests inject their own.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: ?*const fn (ctx: ?*anyopaque) i64 = null,

    pub fn now(c: Clock, io: Io) i64 {
        if (c.nowFn) |f| return f(c.ctx);
        return @intCast(@divTrunc(Io.Clock.real.now(io).toNanoseconds(), std.time.ns_per_s));
    }
};

pub fn periodOf(unix: i64) i64 {
    return @divFloor(unix, period_s);
}

/// One certificate. Immutable once made; the listener holds a reference (`Certs.acquire`) for
/// every connection whose handshake uses it, so its bytes outlive a rotation.
pub const Entry = struct {
    /// The self-signed certificate of `period` (with `chain`: a placeholder, never presented).
    cert: cert_mod.Cert,
    /// SHA-256 of the DER certificate browsers are given: `cert`, or the chain's leaf.
    sha256: [32]u8,
    period: i64,
    /// `--native-cert`: the loaded chain and key, presented instead of `cert`. Owned.
    chain: ?tls_identity.Identity = null,
    /// With `chain`: the leaf's notAfter.
    leaf_not_after: i64 = 0,
    /// Guarded by `Certs.mu`.
    refs: u32 = 0,
    retired: bool = false,

    /// Presented to handshakes in `[from, until)`.
    pub fn from(e: *const Entry) i64 {
        return e.period * period_s;
    }
    pub fn until(e: *const Entry) i64 {
        return (e.period + 1) * period_s;
    }
    pub fn notBefore(e: *const Entry) i64 {
        return e.from() - lead_s;
    }
    pub fn notAfter(e: *const Entry) i64 {
        if (e.chain != null) return e.leaf_not_after;
        return e.notBefore() + @as(i64, valid_days) * 86400 - 1;
    }
    /// For the TLS server: the loaded chain, or null (present `cert`).
    pub fn chainPtr(e: *const Entry) ?*const tls_identity.Identity {
        return if (e.chain) |*c| c else null;
    }
};

/// `--native-cert` and `--native-key`: a PEM certificate chain (leaf first) and the leaf's PEM
/// private key (ECDSA P-256 or P-384, Ed25519, RSA 2048 to 4096; net/tls_identity.zig).
pub const Files = struct { cert: []const u8, key: []const u8 };

pub const LoadError = tls_identity.LoadError || error{
    ReadCertificate,
    ReadKey,
    BadCertificate,
    KeyMismatch,
    CertificateExpired,
    CertificateNotYetValid,
    ChainOutOfOrder,
    BadChainSignature,
};

/// A sentence for the operator.
pub fn describe(e: anyerror) []const u8 {
    return switch (e) {
        error.ReadCertificate => "the certificate file cannot be read",
        error.ReadKey => "the key file cannot be read",
        error.NoCertificate => "no CERTIFICATE block in the certificate file",
        error.BadPem => "a PEM block does not decode",
        error.NoPrivateKey => "no private key block in the key file",
        error.EncryptedKey => "the private key is encrypted (not supported)",
        error.UnsupportedKey => "unsupported key type (supported: ECDSA P-256 and P-384, Ed25519, RSA 2048 to 4096)",
        error.BadKey => "the private key does not parse",
        error.RsaKeyTooSmall => "the RSA key is shorter than 2048 bits",
        error.RsaKeyTooLarge => "the RSA key is longer than 4096 bits",
        error.BadCertificate => "a certificate in the chain does not parse",
        error.KeyMismatch => "the private key does not match the leaf certificate's public key",
        error.CertificateExpired => "a certificate in the chain has expired",
        error.CertificateNotYetValid => "a certificate in the chain is not valid yet",
        error.ChainOutOfOrder => "the chain is out of order (the leaf first, each certificate followed by its issuer)",
        error.BadChainSignature => "a certificate in the chain is not signed by the one after it",
        else => @errorName(e),
    };
}

const Checked = struct { sha256: [32]u8, not_after: i64 };

fn stripZeros(b: []const u8) []const u8 {
    var x = b;
    while (x.len > 1 and x[0] == 0) x = x[1..];
    return x;
}

/// The checks a loaded chain and key pass before the listener presents them: every certificate
/// parses, the key is the leaf's, each certificate is followed by its issuer (and signed by it,
/// where std can check the algorithm), and all of them are valid at `now`.
pub fn check(id: *const tls_identity.Identity, now: i64) LoadError!Checked {
    const C = std.crypto.Certificate;
    // (parseCertificate, not std's parser alone: a damaged file must be an error, not a crash)
    const leaf = tls_identity.parseCertificate(id.certs[0]) catch return error.BadCertificate;
    const pk = leaf.pubKey();
    const matches = switch (id.key) {
        .p256 => |kp| leaf.pub_key_algo == .X9_62_id_ecPublicKey and std.mem.eql(u8, pk, &kp.public_key.toUncompressedSec1()),
        .p384 => |kp| leaf.pub_key_algo == .X9_62_id_ecPublicKey and std.mem.eql(u8, pk, &kp.public_key.toUncompressedSec1()),
        .ed25519 => |kp| leaf.pub_key_algo == .curveEd25519 and std.mem.eql(u8, pk, &kp.public_key.toBytes()),
        .rsa => |r| blk: {
            if (leaf.pub_key_algo != .rsaEncryption) break :blk false;
            const parts = C.rsa.PublicKey.parseDer(pk) catch break :blk false;
            var nb: [tls_identity.max_signature_len]u8 = undefined;
            r.n.toBytes(nb[0..r.k], .big) catch break :blk false;
            break :blk std.mem.eql(u8, stripZeros(parts.modulus), stripZeros(nb[0..r.k])) and std.mem.eql(u8, stripZeros(parts.exponent), stripZeros(r.e));
        },
    };
    if (!matches) return error.KeyMismatch;
    const t: u64 = @intCast(@max(now, 0));
    if (t < leaf.validity.not_before) return error.CertificateNotYetValid;
    if (t > leaf.validity.not_after) return error.CertificateExpired;
    var subject = leaf;
    for (id.certs[1..]) |der| {
        const issuer = tls_identity.parseCertificate(der) catch return error.BadCertificate;
        subject.verify(issuer, now) catch |e| switch (e) {
            error.CertificateIssuerMismatch => return error.ChainOutOfOrder,
            error.CertificateExpired => return error.CertificateExpired,
            error.CertificateNotYetValid => return error.CertificateNotYetValid,
            error.CertificateSignatureInvalid => return error.BadChainSignature,
            else => {}, // an algorithm std does not verify: not a reason to refuse the chain
        };
        if (t < issuer.validity.not_before) return error.CertificateNotYetValid;
        if (t > issuer.validity.not_after) return error.CertificateExpired;
        subject = issuer;
    }
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(id.certs[0], &h, .{});
    return .{ .sha256 = h, .not_after = @intCast(leaf.validity.not_after) };
}

/// Size, modification time and inode of both files: a change means "load them again".
pub const Stamp = struct {
    v: [2][3]i128 = @splat(@splat(-1)),

    pub fn of(io: Io, f: Files) Stamp {
        var s: Stamp = .{};
        for ([_][]const u8{ f.cert, f.key }, 0..) |path, i| {
            const st = Io.Dir.cwd().statFile(io, path, .{}) catch continue;
            s.v[i] = .{ @intCast(st.size), st.mtime.toNanoseconds(), @intCast(st.inode) };
        }
        return s;
    }
    fn eql(a: Stamp, b: Stamp) bool {
        return std.meta.eql(a.v, b.v);
    }
};

/// The certificate of `period` for the identity `seed`: the same bytes every time.
pub fn derive(seed: [32]u8, period: i64, name: []const u8) Entry {
    const prk = Hkdf.extract("zui/1 webtransport certificate", &seed);
    var info: [9]u8 = undefined;
    std.mem.writeInt(i64, info[0..8], period, .little);
    var attempt: u8 = 0;
    while (true) : (attempt += 1) {
        info[8] = attempt;
        var okm: [48]u8 = undefined;
        Hkdf.expand(&okm, &info, prk);
        // (a seed that maps to no key: one in 2^128, try the next)
        const key = P256.KeyPair.generateDeterministic(okm[0..32].*) catch continue;
        var e: Entry = .{ .cert = undefined, .sha256 = undefined, .period = period };
        // `generate` backdates notBefore by an hour; the signature is deterministic (no noise)
        e.cert = cert_mod.generate(key, okm[32..48].*, e.notBefore() + 3600, valid_days, name);
        e.sha256 = e.cert.sha256();
        return e;
    }
}

/// What the hash endpoint serves: a copy, taken under the lock.
pub const View = struct {
    /// Certificates listed: the current one, then the next one. 0 with `--native-cert`: a WebPKI
    /// certificate is not pinned by hash.
    n: u8 = 0,
    sha256: [2][32]u8 = undefined,
    from: [2]i64 = undefined,
    until: [2]i64 = undefined,
};

pub const Stats = struct {
    /// Rotations since start (the certificate made at start is not one).
    rotations: Atomic(u64) = .init(0),
    /// notAfter of the certificate presented now, unix seconds.
    not_after: Atomic(i64) = .init(0),
    /// Times the hash file could not be rewritten (it is tried again every tick).
    hash_file_errors: Atomic(u64) = .init(0),
    /// `--native-cert`: reloads that replaced the certificate, and reloads refused.
    reloads: Atomic(u64) = .init(0),
    reload_errors: Atomic(u64) = .init(0),
    /// Unix second of the last reload that replaced the certificate (0: none since start).
    last_reload: Atomic(i64) = .init(0),
};

pub const Options = struct {
    /// The zui/1 identity seed (`--native-identity-file`): certificates derive from it.
    seed: [32]u8,
    /// DNS name in the certificate (browsers do not check names of pinned certificates).
    name: []const u8 = "localhost",
    clock: Clock = .{},
    /// `--native-cert-hash-file`: rewritten (temporary file, then rename) at every rotation.
    hash_file: ?[]const u8 = null,
    /// Line 2 of the hash file: the zui/1 Ed25519 key native clients pin.
    identity_key: [32]u8 = @splat(0),
    /// `--native-cert` and `--native-key`: present this chain; nothing is derived or rotated.
    files: ?Files = null,
    /// Set from outside (the node's SIGHUP handler) to have the files loaded again.
    reload: ?*Atomic(bool) = null,
    /// The files are looked at for a change once in this many ticks (250 ms each).
    poll_ticks: u32 = 20,
    /// What the reload lines in the log start with (the listener the files belong to).
    label: []const u8 = "zui/1",
};

pub const Certs = struct {
    gpa: Allocator,
    io: Io,
    opts: Options,
    mu: Io.Mutex = .init,
    /// Presented now, and in the next period (null with `--native-cert`). Swapped under `mu`.
    cur: *Entry,
    next: ?*Entry,
    stats: Stats = .{},
    /// `--native-cert`: the files as they were when last loaded (or refused), and a tick count.
    stamp: Stamp = .{},
    ticks: u32 = 0,
    /// The last rotation did not get its hash file written.
    file_stale: bool = false,
    stop_flag: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    /// `initLoaded`: why a reload would refuse the chain and key taken at start (null: it
    /// would not).
    start_refusal: ?LoadError = null,

    /// The certificates of the current period (or the loaded chain), and the hash file written.
    /// Nothing rotates or reloads until `start` (or a caller's `tick`).
    pub fn init(gpa: Allocator, io: Io, opts: Options) !*Certs {
        const cs = try gpa.create(Certs);
        errdefer gpa.destroy(cs);
        const now = opts.clock.now(io);
        const p = periodOf(now);
        cs.* = .{ .gpa = gpa, .io = io, .opts = opts, .cur = undefined, .next = null };
        if (opts.files) |f| {
            cs.stamp = Stamp.of(io, f);
            cs.cur = try cs.load(f, now);
        } else {
            cs.cur = try gpa.create(Entry);
            cs.cur.* = derive(opts.seed, p, opts.name);
            errdefer gpa.destroy(cs.cur);
            cs.next = try gpa.create(Entry);
            cs.next.?.* = derive(opts.seed, p + 1, opts.name);
        }
        errdefer {
            cs.destroy(cs.cur);
            if (cs.next) |n| cs.destroy(n);
        }
        cs.stats.not_after.store(cs.cur.notAfter(), .release);
        if (opts.hash_file) |f| {
            var tb: [hash_file_max]u8 = undefined;
            try writeTmp(f, hashFileText(&tb, opts.identity_key, cs.cur, cs.next));
            try renameTmp(f);
        }
        return cs;
    }

    /// For a listener that read and parsed `opts.files` itself (the gRPC TLS port starts with
    /// what sui-node starts with, so nothing is refused here): `id` is presented as it is, and
    /// the files are loaded again, checked, on SIGHUP or once they differ from `stamp` (taken
    /// before the caller read them). No hash file. Takes `id`, also when it fails.
    pub fn initLoaded(gpa: Allocator, io: Io, opts: Options, id: tls_identity.Identity, stamp: Stamp) Allocator.Error!*Certs {
        var chain = id;
        errdefer chain.deinit();
        std.debug.assert(opts.files != null and opts.hash_file == null);
        const cs = try gpa.create(Certs);
        errdefer gpa.destroy(cs);
        const e = try gpa.create(Entry);
        const now = opts.clock.now(io);
        e.* = derive(opts.seed, periodOf(now), opts.name);
        cs.* = .{ .gpa = gpa, .io = io, .opts = opts, .cur = e, .next = null, .stamp = stamp };
        if (check(&chain, now)) |ok| {
            e.sha256 = ok.sha256;
            e.leaf_not_after = ok.not_after;
        } else |why| {
            cs.start_refusal = why;
            std.crypto.hash.sha2.Sha256.hash(chain.certs[0], &e.sha256, .{});
            if (tls_identity.parseCertificate(chain.certs[0])) |leaf| {
                e.leaf_not_after = @intCast(leaf.validity.not_after);
            } else |_| {}
        }
        e.chain = chain;
        cs.stats.not_after.store(e.notAfter(), .release);
        return cs;
    }

    /// Stops the rotation (or reload) thread; the certificates stay, for an owner whose
    /// connection threads may still be in a handshake (the node's gRPC TLS port at stop).
    pub fn halt(cs: *Certs) void {
        cs.stop_flag.store(true, .release);
        if (cs.thread) |t| t.join();
        cs.thread = null;
    }

    /// Stops the rotation thread and frees the certificates. The listener is stopped first (it
    /// holds references).
    pub fn deinit(cs: *Certs) void {
        cs.halt();
        std.debug.assert(cs.cur.refs == 0 and (cs.next == null or cs.next.?.refs == 0));
        cs.destroy(cs.cur);
        if (cs.next) |n| cs.destroy(n);
        cs.gpa.destroy(cs);
    }

    fn destroy(cs: *Certs, e: *Entry) void {
        if (e.chain) |*c| c.deinit();
        cs.gpa.destroy(e);
    }

    /// Reads, parses and checks `f`: an entry ready to present, or why not. The key file's
    /// bytes are wiped before they are freed; nothing of the key is ever logged.
    fn load(cs: *Certs, f: Files, now: i64) LoadError!*Entry {
        const gpa = cs.gpa;
        const cert_pem = Io.Dir.cwd().readFileAlloc(cs.io, f.cert, gpa, .limited(4 << 20)) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.ReadCertificate;
        defer gpa.free(cert_pem);
        const key_pem = Io.Dir.cwd().readFileAlloc(cs.io, f.key, gpa, .limited(1 << 20)) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.ReadKey;
        defer {
            std.crypto.secureZero(u8, key_pem);
            gpa.free(key_pem);
        }
        var id = try tls_identity.load(gpa, cert_pem, key_pem);
        errdefer id.deinit();
        const ok = try check(&id, now);
        const e = try gpa.create(Entry);
        e.* = derive(cs.opts.seed, periodOf(now), cs.opts.name);
        e.sha256 = ok.sha256;
        e.chain = id;
        e.leaf_not_after = ok.not_after;
        return e;
    }

    /// `--native-cert`: loads the files again and presents them to handshakes from now on. On
    /// an error nothing changes.
    pub fn reload(cs: *Certs) LoadError!void {
        const f = cs.opts.files orelse return;
        cs.stamp = Stamp.of(cs.io, f);
        const now = cs.opts.clock.now(cs.io);
        const e = try cs.load(f, now);
        cs.mu.lockUncancelable(cs.io);
        const old = cs.cur;
        const old_hash = old.sha256;
        cs.cur = e;
        cs.retire(old);
        cs.mu.unlock(cs.io);
        cs.stats.not_after.store(e.notAfter(), .release);
        cs.stats.last_reload.store(now, .release);
        _ = cs.stats.reloads.fetchAdd(1, .monotonic);
        std.log.info("{s}: certificate loaded again from {s}: {d} certificate(s), {s} key, leaf sha256 {x} (was {x}), not after unix {d}", .{ cs.opts.label, f.cert, e.chain.?.certs.len, @tagName(e.chain.?.key), &e.sha256, &old_hash, e.notAfter() });
    }

    /// `--native-cert`: a reload when one was asked for (SIGHUP) or the files changed. True
    /// when a new certificate is in place.
    fn tickFiles(cs: *Certs, f: Files) bool {
        const asked = if (cs.opts.reload) |flag| flag.swap(false, .acq_rel) else false;
        cs.ticks +%= 1;
        if (!asked) {
            if (cs.ticks % @max(cs.opts.poll_ticks, 1) != 0) return false;
            if (Stamp.of(cs.io, f).eql(cs.stamp)) return false;
        }
        cs.reload() catch |e| {
            _ = cs.stats.reload_errors.fetchAdd(1, .monotonic);
            std.log.warn("{s}: certificate reload from {s} and {s} refused: {s}; the certificate in use stays", .{ cs.opts.label, f.cert, f.key, describe(e) });
            return false;
        };
        return true;
    }

    /// Rotates in the background: the clock is read four times a second.
    pub fn start(cs: *Certs) !void {
        cs.thread = try std.Thread.spawn(.{}, loop, .{cs});
    }

    fn loop(cs: *Certs) void {
        while (!cs.stop_flag.load(.acquire)) {
            _ = cs.tick();
            cs.io.sleep(.fromMilliseconds(250), .awake) catch return;
        }
    }

    /// Brings the certificates to the clock's period. True when they changed. One caller at a
    /// time: the thread, or a test that moves its own clock.
    pub fn tick(cs: *Certs) bool {
        if (cs.opts.files) |f| return cs.tickFiles(f);
        const p = periodOf(cs.opts.clock.now(cs.io));
        if (p == cs.cur.period) {
            if (cs.file_stale) cs.retryHashFile();
            return false;
        }
        const old_cur = cs.cur;
        const old_next = cs.next.?;
        const old_hash = old_cur.sha256;
        // the usual step is one period forward: the published next certificate becomes current
        const new_cur = if (p == old_next.period) old_next else cs.make(p) orelse return false;
        const new_next = cs.make(p + 1) orelse {
            if (new_cur != old_next) cs.gpa.destroy(new_cur);
            return false;
        };
        // The file's new text is on disk before the swap; the rename and the swap happen under
        // the lock the hash endpoint reads under, so the two change together.
        var wrote = true;
        var tb: [hash_file_max]u8 = undefined;
        if (cs.opts.hash_file) |f| writeTmp(f, hashFileText(&tb, cs.opts.identity_key, new_cur, new_next)) catch {
            wrote = false;
        };
        cs.mu.lockUncancelable(cs.io);
        cs.cur = new_cur;
        cs.next = new_next;
        if (cs.opts.hash_file) |f| if (wrote) renameTmp(f) catch {
            wrote = false;
        };
        cs.retire(old_cur);
        if (old_next != new_cur) cs.retire(old_next);
        cs.mu.unlock(cs.io);
        cs.file_stale = !wrote;
        if (!wrote) {
            _ = cs.stats.hash_file_errors.fetchAdd(1, .monotonic);
            std.log.warn("zui/1: certificate hash file {s} not rewritten at the rotation; trying again", .{cs.opts.hash_file.?});
        }
        cs.stats.not_after.store(new_cur.notAfter(), .release);
        _ = cs.stats.rotations.fetchAdd(1, .monotonic);
        std.log.info("zui/1: WebTransport certificate rotated: sha256 {x} (was {x}), presented until unix {d}, not after {d}; next {x}", .{ &new_cur.sha256, &old_hash, new_cur.until(), new_cur.notAfter(), &new_next.sha256 });
        return true;
    }

    fn make(cs: *Certs, period: i64) ?*Entry {
        const e = cs.gpa.create(Entry) catch return null;
        e.* = derive(cs.opts.seed, period, cs.opts.name);
        return e;
    }

    /// `mu` held. Freed now, or by the `release` of the last connection that used it.
    fn retire(cs: *Certs, e: *Entry) void {
        e.retired = true;
        if (e.refs == 0) cs.destroy(e);
    }

    fn retryHashFile(cs: *Certs) void {
        const f = cs.opts.hash_file orelse return;
        var tb: [hash_file_max]u8 = undefined;
        writeTmp(f, hashFileText(&tb, cs.opts.identity_key, cs.cur, cs.next)) catch return;
        renameTmp(f) catch return;
        cs.file_stale = false;
    }

    /// The certificate for a handshake that starts now. Pair with `release` when the connection
    /// is freed.
    pub fn acquire(cs: *Certs) *Entry {
        cs.mu.lockUncancelable(cs.io);
        defer cs.mu.unlock(cs.io);
        cs.cur.refs += 1;
        return cs.cur;
    }

    pub fn release(cs: *Certs, e: *Entry) void {
        cs.mu.lockUncancelable(cs.io);
        defer cs.mu.unlock(cs.io);
        e.refs -= 1;
        if (e.retired and e.refs == 0) cs.destroy(e);
    }

    pub fn view(cs: *Certs) View {
        cs.mu.lockUncancelable(cs.io);
        defer cs.mu.unlock(cs.io);
        const next = cs.next orelse return .{};
        var v: View = .{ .n = 2 };
        for ([_]*const Entry{ cs.cur, next }, 0..) |e, i| {
            v.sha256[i] = e.sha256;
            v.from[i] = e.from();
            v.until[i] = e.until();
        }
        return v;
    }
};

/// `--native-cert-hash-file`: four lines. 1: sha256 of the certificate presented now. 2: the
/// zui/1 Ed25519 key. 3: sha256 of the next certificate. 4: the unix second line 3 replaces
/// line 1. (Lines 1 and 2 are what the file always held.) With `--native-cert` (`next` null)
/// there is no hash to pin: line 1 is empty, line 2 is the key, and that is all.
pub const hash_file_max = 256;
pub fn hashFileText(buf: *[hash_file_max]u8, identity_key: [32]u8, cur: *const Entry, next: ?*const Entry) []const u8 {
    const n = next orelse return std.fmt.bufPrint(buf, "\n{x}\n", .{&identity_key}) catch unreachable;
    return std.fmt.bufPrint(buf, "{x}\n{x}\n{x}\n{d}\n", .{ &cur.sha256, &identity_key, &n.sha256, n.from() }) catch unreachable;
}

fn tmpPath(buf: *[std.fs.max_path_bytes + 8]u8, path: []const u8) ![:0]const u8 {
    return std.fmt.bufPrintSentinel(buf, "{s}.tmp", .{path}, 0) catch error.NameTooLong;
}

/// `text` into `<path>.tmp`, flushed to disk.
fn writeTmp(path: []const u8, text: []const u8) !void {
    var tb: [std.fs.max_path_bytes + 8]u8 = undefined;
    const tmp = try tmpPath(&tb, path);
    const fd = std.c.open(tmp, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return error.HashFileCreate;
    defer _ = std.c.close(fd);
    var off: usize = 0;
    while (off < text.len) {
        const k = std.c.write(fd, text[off..].ptr, text.len - off);
        if (k <= 0) return error.HashFileWrite;
        off += @intCast(k);
    }
    if (std.c.fsync(fd) != 0) return error.HashFileWrite;
}

/// `<path>.tmp` takes `path`'s place (atomic: a reader sees the old text or the new one).
fn renameTmp(path: []const u8) !void {
    var tb: [std.fs.max_path_bytes + 8]u8 = undefined;
    const tmp = try tmpPath(&tb, path);
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const z = std.fmt.bufPrintSentinel(&pb, "{s}", .{path}, 0) catch return error.NameTooLong;
    if (std.c.rename(tmp, z) != 0) return error.HashFileRename;
}

// ---------------------------------------------------------------- tests

/// A clock tests move by hand.
pub const TestClock = struct {
    t: Atomic(i64),

    pub fn init(unix: i64) TestClock {
        return .{ .t = .init(unix) };
    }
    pub fn set(c: *TestClock, unix: i64) void {
        c.t.store(unix, .release);
    }
    pub fn clock(c: *TestClock) Clock {
        return .{ .ctx = c, .nowFn = read };
    }
    fn read(ctx: ?*anyopaque) i64 {
        const c: *TestClock = @ptrCast(@alignCast(ctx.?));
        return c.t.load(.acquire);
    }
};

fn testPath(tmp: *std.testing.TmpDir, buf: []u8, name: []const u8) ![]const u8 {
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(std.testing.io, &pb);
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ pb[0..n], name });
}

/// The hash file's lines (test helper).
pub fn readHashFile(gpa: Allocator, path: []const u8) !struct { text: []u8, lines: [4][]const u8 } {
    const text = try Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(4096));
    var lines: [4][]const u8 = @splat("");
    var it = std.mem.splitScalar(u8, text, '\n');
    for (&lines) |*l| l.* = it.next() orelse "";
    return .{ .text = text, .lines = lines };
}

test "certs: a period's certificate is the same bytes every time, and fits what browsers pin" {
    const seed: [32]u8 = @splat(7);
    const p = periodOf(1_800_000_000);
    const a = derive(seed, p, "localhost");
    const b = derive(seed, p, "localhost");
    try std.testing.expectEqualSlices(u8, a.cert.bytes(), b.cert.bytes());
    try std.testing.expectEqual(a.sha256, b.sha256);
    // another period or another identity: another key and certificate
    const c = derive(seed, p + 1, "localhost");
    try std.testing.expect(!std.mem.eql(u8, &a.sha256, &c.sha256));
    try std.testing.expect(!std.mem.eql(u8, &a.cert.key.public_key.toUncompressedSec1(), &c.cert.key.public_key.toUncompressedSec1()));
    const d = derive(@splat(8), p, "localhost");
    try std.testing.expect(!std.mem.eql(u8, &a.sha256, &d.sha256));
    // what the DER says: P-256, a validity of at most 14 days that covers the period with 3 days
    // of slack on both sides
    const parsed = try (std.crypto.Certificate{ .buffer = a.cert.bytes(), .index = 0 }).parse();
    try std.testing.expect(parsed.pub_key_algo.X9_62_id_ecPublicKey == .X9_62_prime256v1);
    const nb: i64 = @intCast(parsed.validity.not_before);
    const na: i64 = @intCast(parsed.validity.not_after);
    try std.testing.expectEqual(a.notBefore(), nb);
    try std.testing.expectEqual(a.notAfter(), na);
    try std.testing.expect(na - nb < 14 * 86400);
    try std.testing.expectEqual(a.from() - 3 * 86400, nb);
    try std.testing.expectEqual(a.until() + 3 * 86400 - 1, na);
    try std.testing.expectEqual(p * period_s, a.from());
    try std.testing.expectEqual(a.from() + 7 * 86400, a.until());
}

test "certs: rotation on schedule; the view and the hash file change together; a restart keeps the certificate" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fb: [std.fs.max_path_bytes]u8 = undefined;
    const file = try testPath(&tmp, &fb, "native.hash");
    const seed: [32]u8 = @splat(3);
    const key: [32]u8 = @splat(0xab);
    const p0 = periodOf(1_800_000_000);
    const start = p0 * period_s;
    var tc = TestClock.init(start + 5 * 86400);
    const cs = try Certs.init(gpa, io, .{ .seed = seed, .clock = tc.clock(), .hash_file = file, .identity_key = key });
    defer cs.deinit();
    const v0 = cs.view();
    try std.testing.expectEqual(@as(u8, 2), v0.n);
    try std.testing.expectEqual(start, v0.from[0]);
    try std.testing.expectEqual(start + period_s, v0.until[0]);
    try std.testing.expectEqual(v0.until[0], v0.from[1]);
    try std.testing.expectEqual(derive(seed, p0, "localhost").sha256, v0.sha256[0]);
    try std.testing.expectEqual(derive(seed, p0 + 1, "localhost").sha256, v0.sha256[1]);
    try std.testing.expectEqual(derive(seed, p0, "localhost").notAfter(), cs.stats.not_after.load(.acquire));
    {
        const f = try readHashFile(gpa, file);
        defer gpa.free(f.text);
        try std.testing.expectEqualStrings(&std.fmt.bytesToHex(v0.sha256[0], .lower), f.lines[0]);
        try std.testing.expectEqualStrings(&std.fmt.bytesToHex(key, .lower), f.lines[1]);
        try std.testing.expectEqualStrings(&std.fmt.bytesToHex(v0.sha256[1], .lower), f.lines[2]);
        try std.testing.expectEqual(v0.from[1], try std.fmt.parseInt(i64, f.lines[3], 10));
    }
    // nothing happens inside the period, up to its last second
    try std.testing.expect(!cs.tick());
    tc.set(start + period_s - 1);
    try std.testing.expect(!cs.tick());
    try std.testing.expectEqual(v0.sha256[0], cs.view().sha256[0]);
    try std.testing.expectEqual(@as(u64, 0), cs.stats.rotations.load(.monotonic));
    // the first second of the next period: the published next certificate is the current one
    tc.set(start + period_s);
    try std.testing.expect(cs.tick());
    const v1 = cs.view();
    try std.testing.expectEqual(v0.sha256[1], v1.sha256[0]);
    try std.testing.expectEqual(derive(seed, p0 + 2, "localhost").sha256, v1.sha256[1]);
    try std.testing.expectEqual(@as(u64, 1), cs.stats.rotations.load(.monotonic));
    try std.testing.expectEqual(derive(seed, p0 + 1, "localhost").notAfter(), cs.stats.not_after.load(.acquire));
    {
        const f = try readHashFile(gpa, file);
        defer gpa.free(f.text);
        try std.testing.expectEqualStrings(&std.fmt.bytesToHex(v1.sha256[0], .lower), f.lines[0]);
        try std.testing.expectEqualStrings(&std.fmt.bytesToHex(key, .lower), f.lines[1]);
        try std.testing.expectEqualStrings(&std.fmt.bytesToHex(v1.sha256[1], .lower), f.lines[2]);
        try std.testing.expectEqual(v1.from[1], try std.fmt.parseInt(i64, f.lines[3], 10));
    }
    try std.testing.expect(!cs.tick());
    // a restart in the same period (another instance, same identity): the same certificate
    tc.set(start + period_s + 4 * 86400);
    {
        const again = try Certs.init(gpa, io, .{ .seed = seed, .clock = tc.clock(), .identity_key = key });
        defer again.deinit();
        try std.testing.expectEqual(v1.sha256, again.view().sha256);
        try std.testing.expectEqualSlices(u8, cs.cur.cert.bytes(), again.cur.cert.bytes());
    }
    // a node that was down across a boundary, and a clock that jumped several periods: the
    // certificate is the clock's period's
    tc.set(start + 5 * period_s + 17);
    try std.testing.expect(cs.tick());
    try std.testing.expectEqual(derive(seed, p0 + 5, "localhost").sha256, cs.view().sha256[0]);
    try std.testing.expectEqual(derive(seed, p0 + 6, "localhost").sha256, cs.view().sha256[1]);
}

test "certs: a certificate in use by a connection outlives rotations" {
    const gpa = std.testing.allocator;
    const p0 = periodOf(1_800_000_000);
    var tc = TestClock.init(p0 * period_s);
    const cs = try Certs.init(gpa, std.testing.io, .{ .seed = @splat(1), .clock = tc.clock() });
    defer cs.deinit();
    const held = cs.acquire();
    const want = held.sha256;
    for (1..4) |k| {
        tc.set((p0 + @as(i64, @intCast(k))) * period_s);
        try std.testing.expect(cs.tick());
    }
    try std.testing.expect(held.retired);
    try std.testing.expectEqual(want, held.cert.sha256());
    const now = cs.acquire();
    try std.testing.expect(now != held);
    cs.release(now);
    cs.release(held); // freed here (the testing allocator reports a leak otherwise)
}

test "certs: the thread rotates when the clock passes a boundary" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const p0 = periodOf(1_800_000_000);
    var tc = TestClock.init(p0 * period_s + 100);
    const cs = try Certs.init(gpa, io, .{ .seed = @splat(2), .clock = tc.clock() });
    defer cs.deinit();
    try cs.start();
    const before = cs.view().sha256;
    io.sleep(.fromMilliseconds(600), .awake) catch {};
    try std.testing.expectEqual(@as(u64, 0), cs.stats.rotations.load(.monotonic));
    tc.set((p0 + 1) * period_s);
    var waited: u32 = 0;
    while (cs.stats.rotations.load(.monotonic) == 0 and waited < 5000) : (waited += 50) io.sleep(.fromMilliseconds(50), .awake) catch {};
    try std.testing.expectEqual(@as(u64, 1), cs.stats.rotations.load(.monotonic));
    try std.testing.expectEqual(before[1], cs.view().sha256[0]);
}

test "certs: a hash file that cannot be written at a rotation is retried; the certificate rotates anyway" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "sub", .default_dir);
    var fb: [std.fs.max_path_bytes]u8 = undefined;
    const file = try testPath(&tmp, &fb, "sub/native.hash");
    const p0 = periodOf(1_800_000_000);
    var tc = TestClock.init(p0 * period_s);
    const cs = try Certs.init(gpa, io, .{ .seed = @splat(4), .clock = tc.clock(), .hash_file = file });
    defer cs.deinit();
    const next = cs.view().sha256[1];
    try tmp.dir.deleteTree(io, "sub");
    tc.set((p0 + 1) * period_s);
    // (the rotation warns about the file; keep the test's output clean)
    std.testing.log_level = .err;
    defer std.testing.log_level = .warn;
    try std.testing.expect(cs.tick());
    try std.testing.expectEqual(next, cs.view().sha256[0]);
    try std.testing.expectEqual(@as(u64, 1), cs.stats.hash_file_errors.load(.monotonic));
    try tmp.dir.createDir(io, "sub", .default_dir);
    try std.testing.expect(!cs.tick());
    const f = try readHashFile(gpa, file);
    defer gpa.free(f.text);
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(next, .lower), f.lines[0]);
    // a start with a hash file that cannot be written is refused, as before
    try tmp.dir.deleteTree(io, "sub");
    try std.testing.expectError(error.HashFileCreate, Certs.init(gpa, io, .{ .seed = @splat(4), .clock = tc.clock(), .hash_file = file }));
}
