//! Tests of the gRPC TLS port's certificate reload (`--serve-tls-cert/-key`: certs.zig's
//! `Certs.initLoaded` behind tcptls.zig's `Server.initCerts`): the files as a renewal tool leaves
//! them (whole, damaged, half-written, one before the other), and real handshakes on loopback
//! checked by std.crypto.tls.Client.
const std = @import("std");
const Io = std.Io;
const net = @import("net");
const certs = @import("certs.zig");
const cert_mod = @import("cert.zig");
const tcptls = @import("tcptls.zig");
const h2sock = @import("serve").h2.sock;
const certs_test = @import("certs_test.zig");
const Pki = certs_test.Pki;
const pemBlock = certs_test.pemBlock;
const sha = certs_test.sha;
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Atomic = std.atomic.Value;

/// What the node does at start with `--serve-tls-cert/-key` (node.zig `startServeTls`): the
/// files are read and parsed with no further check, then handed to `Certs.initLoaded`.
fn serveTlsCerts(gpa: std.mem.Allocator, io: Io, files: certs.Files, base: certs.Options) !*certs.Certs {
    const stamp = certs.Stamp.of(io, files);
    const cert_pem = try Io.Dir.cwd().readFileAlloc(io, files.cert, gpa, .limited(4 << 20));
    defer gpa.free(cert_pem);
    const key_pem = try Io.Dir.cwd().readFileAlloc(io, files.key, gpa, .limited(1 << 20));
    defer gpa.free(key_pem);
    const id = try net.tls_identity.load(gpa, cert_pem, key_pem);
    var opts = base;
    opts.files = files;
    opts.label = "rpc tls";
    return certs.Certs.initLoaded(gpa, io, opts, id, stamp);
}

/// The PEM text of a chain file.
fn chainText(out: *std.ArrayList(u8), gpa: std.mem.Allocator, chain: []const []const u8) ![]const u8 {
    out.clearRetainingCapacity();
    for (chain) |der| try pemBlock(out, gpa, "CERTIFICATE", der);
    return out.items;
}

/// `text` written over `name` in place (the same inode), the way a tool that does not rename
/// writes: a reader in the middle of it sees a part of the file.
fn writeInPlace(pki: *Pki, name: []const u8, text: []const u8) !void {
    try pki.tmp.dir.writeFile(pki.io, .{ .sub_path = name, .data = text });
}

/// The leaf the next handshake would present.
fn presented(cs: *certs.Certs) [32]u8 {
    const e = cs.acquire();
    defer cs.release(e);
    return e.sha256;
}

test "--serve-tls-cert: a renewed pair is taken; a damaged chain, a key that is not the leaf's and half-written files are refused and the chain in use stays" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const now: i64 = 1_800_000_000;
    var pki: Pki = undefined;
    try pki.init(gpa, io, now);
    defer pki.deinit();
    const key_a = try P256.KeyPair.generateDeterministic(@splat(0x31));
    const key_b = try P256.KeyPair.generateDeterministic(@splat(0x32));
    const key_c = try P256.KeyPair.generateDeterministic(@splat(0x33));
    const key_d = try P256.KeyPair.generateDeterministic(@splat(0x34));
    var la: [cert_mod.max_len]u8 = undefined;
    var lb: [cert_mod.max_len]u8 = undefined;
    var lc: [cert_mod.max_len]u8 = undefined;
    var ld: [cert_mod.max_len]u8 = undefined;
    const leaf_a = pki.leaf(&la, key_a, "node.test", now - 86400, now + 60 * 86400);
    const leaf_b = pki.leaf(&lb, key_b, "node.test", now - 3600, now + 90 * 86400);
    const leaf_c = pki.leaf(&lc, key_c, "node.test", now - 3600, now + 91 * 86400);
    const leaf_d = pki.leaf(&ld, key_d, "node.test", now - 3600, now + 92 * 86400);
    var cb: [std.fs.max_path_bytes]u8 = undefined;
    var kb: [std.fs.max_path_bytes]u8 = undefined;
    const files: certs.Files = .{ .cert = pki.path(&cb, "chain.pem"), .key = pki.path(&kb, "key.pem") };
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, pki.ca }, key_a);
    var tc = certs.TestClock.init(now);
    var hup: Atomic(bool) = .init(false);
    const cs = try serveTlsCerts(gpa, io, files, .{ .seed = @splat(9), .clock = tc.clock(), .reload = &hup, .poll_ticks = 1 });
    defer cs.deinit();
    try std.testing.expect(cs.start_refusal == null);
    try std.testing.expectEqual(sha(leaf_a), presented(cs));
    try std.testing.expectEqual(now + 60 * 86400, cs.stats.not_after.load(.acquire));
    try std.testing.expectEqual(@as(i64, 0), cs.stats.last_reload.load(.acquire));
    try std.testing.expectEqual(@as(u8, 0), cs.view().n); // nothing to pin by hash

    // the files never change: nothing is loaded again, the chain is the one read at start
    const at_start = cs.cur;
    for (0..8) |_| try std.testing.expect(!cs.tick());
    try std.testing.expect(cs.cur == at_start);
    try std.testing.expectEqual(@as(u64, 0), cs.stats.reloads.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), cs.stats.reload_errors.load(.monotonic));

    std.testing.log_level = .err; // (the refusals warn)
    defer std.testing.log_level = .warn;
    var errors: u64 = 0;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);

    // a renewal as two renames, the chain first: with only the chain in place the key is not
    // the leaf's and nothing is swapped; with both it is taken
    tc.set(now + 100);
    try pki.put("chain.pem", try chainText(&text, gpa, &.{ leaf_b, pki.ca }));
    try std.testing.expect(!cs.tick());
    errors += 1;
    try std.testing.expectEqual(errors, cs.stats.reload_errors.load(.monotonic));
    try std.testing.expect(cs.cur == at_start);
    try std.testing.expect(!cs.tick()); // not tried again until a file changes
    try std.testing.expectEqual(errors, cs.stats.reload_errors.load(.monotonic));
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_b, pki.ca }, key_b);
    try std.testing.expect(cs.tick());
    try std.testing.expectEqual(sha(leaf_b), presented(cs));
    try std.testing.expectEqual(@as(usize, 2), cs.cur.chain.?.certs.len);
    try std.testing.expectEqual(@as(u64, 1), cs.stats.reloads.load(.monotonic));
    try std.testing.expectEqual(now + 100, cs.stats.last_reload.load(.acquire));
    try std.testing.expectEqual(now + 90 * 86400, cs.stats.not_after.load(.acquire));
    const b_entry = cs.cur;

    // damaged chain files, the key untouched
    const damaged = [_][]const u8{
        "",
        "not a certificate\n",
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIIB",
    };
    for (damaged) |bad| {
        try pki.put("chain.pem", bad);
        try std.testing.expect(!cs.tick());
        errors += 1;
        try std.testing.expectEqual(errors, cs.stats.reload_errors.load(.monotonic));
        try std.testing.expect(cs.cur == b_entry);
    }
    // every cut of the leaf's DER, in a PEM block that is whole: none is a certificate, none
    // crashes the parser, none replaces the chain
    var cut: usize = 0;
    while (cut < leaf_b.len) : (cut += 3) {
        try pki.put("chain.pem", try chainText(&text, gpa, &.{ leaf_b[0..cut], pki.ca }));
        try std.testing.expect(!cs.tick());
        errors += 1;
        try std.testing.expect(cs.cur == b_entry);
    }
    try std.testing.expectEqual(errors, cs.stats.reload_errors.load(.monotonic));
    // a byte of the leaf changed, anywhere: whatever the parser makes of it, the node goes on,
    // and a chain it takes is one whose key is the leaf's
    var flipped: [cert_mod.max_len]u8 = undefined;
    var at: usize = 0;
    while (at < leaf_b.len) : (at += 5) {
        @memcpy(flipped[0..leaf_b.len], leaf_b);
        flipped[at] ^= 0x41;
        try pki.put("chain.pem", try chainText(&text, gpa, &.{ flipped[0..leaf_b.len], pki.ca }));
        if (cs.tick()) {
            try std.testing.expect(std.mem.indexOf(u8, cs.cur.chain.?.certs[0], &key_b.public_key.toUncompressedSec1()) != null);
        } else errors += 1;
    }
    try std.testing.expectEqual(errors, cs.stats.reload_errors.load(.monotonic));
    // back to the whole pair
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_b, pki.ca }, key_b);
    try std.testing.expect(cs.tick());
    try std.testing.expectEqual(sha(leaf_b), presented(cs));
    const b_again = cs.cur;

    // a key that is not the leaf's (both files whole): refused, by the watcher and on SIGHUP
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_b, pki.ca }, key_a);
    try std.testing.expect(!cs.tick());
    errors += 1;
    hup.store(true, .release);
    try std.testing.expect(!cs.tick());
    errors += 1;
    try std.testing.expect(!hup.load(.acquire));
    try std.testing.expectError(error.KeyMismatch, cs.reload());
    try std.testing.expectEqual(errors, cs.stats.reload_errors.load(.monotonic));
    try std.testing.expect(cs.cur == b_again);
    try std.testing.expectEqual(sha(leaf_b), presented(cs));
    // a damaged key file
    for ([_][]const u8{ "", "no key here\n", "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n", "-----BEGIN EC PRIVATE KEY-----\nMHcC" }) |bad| {
        try pki.put("key.pem", bad);
        try std.testing.expect(!cs.tick());
        errors += 1;
        try std.testing.expect(cs.cur == b_again);
    }
    try std.testing.expectEqual(errors, cs.stats.reload_errors.load(.monotonic));

    // a chain file written in place, seen half-written (the new key already there): cut in the
    // first block and in the second one it is refused; whole, it is taken
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_b, pki.ca }, key_b);
    try std.testing.expect(cs.tick());
    const b_third = cs.cur;
    try pki.putPair("other.pem", "key.pem", &.{leaf_c}, key_c);
    try std.testing.expect(!cs.tick()); // the key of the next leaf, the chain of this one
    errors += 1;
    const whole_c = try gpa.dupe(u8, try chainText(&text, gpa, &.{ leaf_c, pki.ca }));
    defer gpa.free(whole_c);
    const first_end = std.mem.indexOf(u8, whole_c, "-----END CERTIFICATE-----").? + 26;
    for ([_]usize{ 0, 7, 40, first_end / 2, first_end - 9, first_end + 30, first_end + (whole_c.len - first_end) / 2, whole_c.len - 5 }) |n| {
        try writeInPlace(&pki, "chain.pem", whole_c[0..n]);
        try std.testing.expect(!cs.tick());
        errors += 1;
        try std.testing.expect(cs.cur == b_third);
        try std.testing.expectEqual(sha(leaf_b), presented(cs));
    }
    try std.testing.expectEqual(errors, cs.stats.reload_errors.load(.monotonic));
    tc.set(now + 200);
    try writeInPlace(&pki, "chain.pem", whole_c);
    try std.testing.expect(cs.tick());
    try std.testing.expectEqual(sha(leaf_c), presented(cs));
    try std.testing.expectEqual(@as(usize, 2), cs.cur.chain.?.certs.len);
    try std.testing.expectEqual(now + 200, cs.stats.last_reload.load(.acquire));
    try std.testing.expectEqual(now + 91 * 86400, cs.stats.not_after.load(.acquire));
    const c_entry = cs.cur;

    // the same for a key file written in place, the new chain already there
    try pki.put("chain.pem", try chainText(&text, gpa, &.{ leaf_d, pki.ca }));
    try std.testing.expect(!cs.tick());
    errors += 1;
    try pki.putPair("other.pem", "keyd.pem", &.{leaf_d}, key_d);
    const whole_key = try pki.tmp.dir.readFileAlloc(io, "keyd.pem", gpa, .limited(4096));
    defer gpa.free(whole_key);
    for ([_]usize{ 0, 12, 40, whole_key.len / 2, whole_key.len - 20 }) |n| {
        try writeInPlace(&pki, "key.pem", whole_key[0..n]);
        try std.testing.expect(!cs.tick());
        errors += 1;
        try std.testing.expect(cs.cur == c_entry);
    }
    try std.testing.expectEqual(errors, cs.stats.reload_errors.load(.monotonic));
    try writeInPlace(&pki, "key.pem", whole_key);
    try std.testing.expect(cs.tick());
    try std.testing.expectEqual(sha(leaf_d), presented(cs));

    // files that went away (a tool that removes before it writes): refused, then taken
    try pki.tmp.dir.deleteFile(io, "chain.pem");
    try std.testing.expect(!cs.tick());
    errors += 1;
    try std.testing.expectEqual(sha(leaf_d), presented(cs));
    try pki.put("chain.pem", try chainText(&text, gpa, &.{ leaf_d, pki.ca }));
    try std.testing.expect(cs.tick());

    // a renewed certificate that has expired already, or is not valid yet: refused
    var le: [cert_mod.max_len]u8 = undefined;
    try pki.putPair("chain.pem", "key.pem", &.{ pki.leaf(&le, key_d, "node.test", now - 30 * 86400, now - 86400), pki.ca }, key_d);
    try std.testing.expectError(error.CertificateExpired, cs.reload());
    try pki.putPair("chain.pem", "key.pem", &.{ pki.leaf(&le, key_d, "node.test", now + 86400, now + 30 * 86400), pki.ca }, key_d);
    try std.testing.expectError(error.CertificateNotYetValid, cs.reload());
    try std.testing.expectEqual(sha(leaf_d), presented(cs));

    // SIGHUP with nothing changed on disk: loaded again
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_d, pki.ca }, key_d);
    try std.testing.expect(cs.tick());
    const before = cs.stats.reloads.load(.monotonic);
    try std.testing.expect(!cs.tick());
    hup.store(true, .release);
    try std.testing.expect(cs.tick());
    try std.testing.expectEqual(before + 1, cs.stats.reloads.load(.monotonic));
    try std.testing.expectEqual(sha(leaf_d), presented(cs));
}

test "--serve-tls-cert: a start with a pair a reload would refuse still starts, and says why" {
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
    const files: certs.Files = .{ .cert = pki.path(&cb, "chain.pem"), .key = pki.path(&kb, "key.pem") };
    var tc = certs.TestClock.init(now);
    var hup: Atomic(bool) = .init(false);
    const opts: certs.Options = .{ .seed = @splat(9), .clock = tc.clock(), .reload = &hup, .poll_ticks = 1 };
    std.testing.log_level = .err;
    defer std.testing.log_level = .warn;
    // a key that is not the leaf's: the node started with it before, and still does
    {
        try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, pki.ca }, key_b);
        const cs = try serveTlsCerts(gpa, io, files, opts);
        defer cs.deinit();
        try std.testing.expectEqual(@as(?certs.LoadError, error.KeyMismatch), cs.start_refusal);
        try std.testing.expectEqual(sha(leaf_a), presented(cs));
        try std.testing.expectEqual(now + 60 * 86400, cs.stats.not_after.load(.acquire));
        // SIGHUP: the same files are refused and what the node started with stays
        const at_start = cs.cur;
        hup.store(true, .release);
        try std.testing.expect(!cs.tick());
        try std.testing.expect(cs.cur == at_start);
        try std.testing.expectEqual(@as(u64, 1), cs.stats.reload_errors.load(.monotonic));
        // the right key arrives: taken
        try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, pki.ca }, key_a);
        try std.testing.expect(cs.tick());
        try std.testing.expect(cs.cur.chain.?.key == .p256);
    }
    // an expired chain, and one whose leaf is not a certificate at all
    {
        try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, pki.ca }, key_a);
        tc.set(now + 61 * 86400);
        const cs = try serveTlsCerts(gpa, io, files, opts);
        defer cs.deinit();
        try std.testing.expectEqual(@as(?certs.LoadError, error.CertificateExpired), cs.start_refusal);
        try std.testing.expectEqual(now + 60 * 86400, cs.stats.not_after.load(.acquire));
        tc.set(now);
    }
    {
        try pki.putPair("chain.pem", "key.pem", &.{ leaf_a[0 .. leaf_a.len / 2], pki.ca }, key_a);
        const cs = try serveTlsCerts(gpa, io, files, opts);
        defer cs.deinit();
        try std.testing.expectEqual(@as(?certs.LoadError, error.BadCertificate), cs.start_refusal);
        try std.testing.expectEqual(@as(i64, 0), cs.stats.not_after.load(.acquire));
        try std.testing.expect(!cs.tick());
    }
}

test "--serve-tls-cert: repeated reloads free every chain; chains held by handshakes outlive the reloads" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const now: i64 = 1_800_000_000;
    var pki: Pki = undefined;
    try pki.init(gpa, io, now);
    defer pki.deinit();
    const keys = [2]P256.KeyPair{ try P256.KeyPair.generateDeterministic(@splat(0x31)), try P256.KeyPair.generateDeterministic(@splat(0x32)) };
    var bufs: [2][cert_mod.max_len]u8 = undefined;
    const leaves = [2][]const u8{
        pki.leaf(&bufs[0], keys[0], "node.test", now - 86400, now + 60 * 86400),
        pki.leaf(&bufs[1], keys[1], "node.test", now - 3600, now + 90 * 86400),
    };
    var cb: [std.fs.max_path_bytes]u8 = undefined;
    var kb: [std.fs.max_path_bytes]u8 = undefined;
    const files: certs.Files = .{ .cert = pki.path(&cb, "chain.pem"), .key = pki.path(&kb, "key.pem") };
    try pki.putPair("chain.pem", "key.pem", &.{ leaves[0], pki.ca }, keys[0]);
    var tc = certs.TestClock.init(now);
    var hup: Atomic(bool) = .init(false);
    const cs = try serveTlsCerts(gpa, io, files, .{ .seed = @splat(9), .clock = tc.clock(), .reload = &hup, .poll_ticks = 1 });
    defer cs.deinit(); // (the testing allocator reports any chain a reload left behind)

    // Handshakes on other threads: each takes the chain of its moment, reads all of it (as the
    // Certificate and CertificateVerify messages do) and lets go.
    const Users = struct {
        cs: *certs.Certs,
        stop: Atomic(bool) = .init(false),
        bad: Atomic(u32) = .init(0),
        rounds: Atomic(u64) = .init(0),

        fn run(u: *@This()) void {
            var sig: [net.tls_identity.max_signature_len]u8 = undefined;
            while (!u.stop.load(.acquire)) {
                const e = u.cs.acquire();
                defer u.cs.release(e);
                const id = e.chainPtr() orelse {
                    _ = u.bad.fetchAdd(1, .monotonic);
                    continue;
                };
                if (id.certs.len != 2 or !std.mem.eql(u8, &sha(id.certs[0]), &e.sha256)) _ = u.bad.fetchAdd(1, .monotonic);
                if (id.sign("a handshake transcript", @splat(1), &sig)) |_| {} else |_| {
                    _ = u.bad.fetchAdd(1, .monotonic);
                }
                _ = u.rounds.fetchAdd(1, .monotonic);
            }
        }
    };
    var users: Users = .{ .cs = cs };
    var threads: [3]std.Thread = undefined;
    var started: usize = 0;
    defer {
        users.stop.store(true, .release);
        for (threads[0..started]) |t| t.join();
    }
    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, Users.run, .{&users});
        started += 1;
    }

    std.testing.log_level = .err;
    defer std.testing.log_level = .warn;
    var held: [4]?*certs.Entry = @splat(null);
    defer for (held) |h| if (h) |e| cs.release(e);
    const rounds = 60;
    var k: usize = 0; // the pair on disk
    for (0..rounds) |i| {
        // a handshake that started before this reload and ends some reloads later
        if (i % 5 == 0) {
            const slot = (i / 5) % held.len;
            if (held[slot]) |e| cs.release(e);
            held[slot] = cs.acquire();
        }
        switch (i % 3) {
            // the other pair arrives
            0 => {
                k = 1 - k;
                try pki.putPair("chain.pem", "key.pem", &.{ leaves[k], pki.ca }, keys[k]);
            },
            // SIGHUP, the files as they are
            1 => hup.store(true, .release),
            // the other pair, and SIGHUP between its two renames: one refusal, then the reload
            else => {
                k = 1 - k;
                var text: std.ArrayList(u8) = .empty;
                defer text.deinit(gpa);
                try pki.put("chain.pem", try chainText(&text, gpa, &.{ leaves[k], pki.ca }));
                hup.store(true, .release);
                try std.testing.expect(!cs.tick());
                try pki.putPair("chain.pem", "key.pem", &.{ leaves[k], pki.ca }, keys[k]);
            },
        }
        try std.testing.expect(cs.tick());
        try std.testing.expectEqual(sha(leaves[k]), presented(cs));
        // what a handshake holds is still the whole chain it started with
        for (held) |h| if (h) |e| try std.testing.expectEqual(sha(e.chain.?.certs[0]), e.sha256);
    }
    try std.testing.expectEqual(@as(u64, rounds), cs.stats.reloads.load(.monotonic));
    try std.testing.expectEqual(@as(u64, rounds / 3), cs.stats.reload_errors.load(.monotonic));
    users.stop.store(true, .release);
    for (threads[0..started]) |t| t.join();
    started = 0;
    try std.testing.expectEqual(@as(u32, 0), users.bad.load(.monotonic));
    try std.testing.expect(users.rounds.load(.monotonic) > 0);
}

/// The gRPC TLS port's accept path on loopback (h2/server.zig `serveFd`: the handshake on the
/// connection's own thread), with an echo in place of the h2 server. Every wait has an end:
/// the accept loop and the echo loops poll in 50 ms slices and read `stop`, and a handshake
/// gives up after tcptls's 5 s.
const TlsEcho = struct {
    srv: *tcptls.Server,
    ls: *Io.net.Server,
    io: Io,
    stop: Atomic(bool) = .init(false),
    accepter: ?std.Thread = null,
    conns: [max_conns]std.Thread = undefined,
    n: usize = 0,
    /// Handshakes that completed.
    served: Atomic(u32) = .init(0),

    const max_conns = 96;

    fn start(e: *TlsEcho) !void {
        e.accepter = try std.Thread.spawn(.{}, acceptLoop, .{e});
    }

    fn acceptLoop(e: *TlsEcho) void {
        while (!e.stop.load(.acquire) and e.n < max_conns) {
            if (!(h2sock.waitReadableRaw(e.ls.socket.handle, 50) catch return)) continue;
            const st = e.ls.accept(e.io) catch return;
            e.conns[e.n] = std.Thread.spawn(.{}, connMain, .{ e, st.socket.handle }) catch {
                h2sock.close(st.socket.handle);
                continue;
            };
            e.n += 1;
        }
    }

    fn connMain(e: *TlsEcho, fd: std.c.fd_t) void {
        defer h2sock.close(fd);
        const sess = e.srv.acceptor().accept(e.srv, fd) orelse return;
        if (!h2sock.attach(fd, sess)) return sess.vt.deinit(sess.ctx);
        _ = e.served.fetchAdd(1, .monotonic);
        var b: [4096]u8 = undefined;
        while (!e.stop.load(.acquire)) {
            if (!(h2sock.waitReadable(fd, 50) catch return)) continue;
            const n = h2sock.read(fd, &b) catch return;
            if (n == 0) return;
            h2sock.writeAll(fd, b[0..n]) catch return;
        }
    }

    /// After the clients closed: every thread ends within its next 50 ms slice.
    fn finish(e: *TlsEcho) void {
        e.stop.store(true, .release);
        if (e.accepter) |t| t.join();
        for (e.conns[0..e.n]) |t| t.join();
    }
};

/// The end of every client read in the loopback tests: past the deadline the client sockets
/// are shut down, so a read that would wait forever fails the test instead of hanging it.
const Watchdog = struct {
    fds: [TlsEcho.max_conns]Atomic(i32) = @splat(.init(-1)),
    n: Atomic(usize) = .init(0),
    done: Atomic(bool) = .init(false),
    fired: Atomic(bool) = .init(false),
    limit_ms: u64 = 60_000,
    thread: ?std.Thread = null,

    fn start(w: *Watchdog) !void {
        w.thread = try std.Thread.spawn(.{}, run, .{w});
    }

    fn run(w: *Watchdog) void {
        var waited: u64 = 0;
        while (!w.done.load(.acquire)) : (waited += 50) {
            if (waited >= w.limit_ms) {
                w.fired.store(true, .release);
                for (w.fds[0..w.n.load(.acquire)]) |*f| {
                    const fd = f.load(.acquire);
                    if (fd >= 0) _ = std.c.shutdown(fd, 2); // SHUT_RDWR
                }
                return;
            }
            h2sock.sleepMs(50);
        }
    }

    fn watch(w: *Watchdog, fd: std.c.fd_t) *Atomic(i32) {
        const slot = &w.fds[w.n.fetchAdd(1, .acq_rel)];
        slot.store(fd, .release);
        return slot;
    }

    fn finish(w: *Watchdog) void {
        w.done.store(true, .release);
        if (w.thread) |t| t.join();
    }
};

/// A TLS client on loopback that trusts the roots it is given and nothing else:
/// std.crypto.tls.Client, an implementation independent of deepwave's, which checks the chain
/// against the roots and CertificateVerify against the leaf's key.
const TlsClient = struct {
    const Tls = std.crypto.tls.Client;
    gpa: std.mem.Allocator,
    io: Io,
    stream: Io.net.Stream,
    slot: *Atomic(i32),
    bundle: std.crypto.Certificate.Bundle = .empty,
    lock: Io.RwLock = .init,
    rb: [Tls.min_buffer_len]u8 = undefined,
    wb: [Tls.min_buffer_len]u8 = undefined,
    crb: [Tls.min_buffer_len]u8 = undefined,
    cwb: [Tls.min_buffer_len]u8 = undefined,
    sr: Io.net.Stream.Reader = undefined,
    sw: Io.net.Stream.Writer = undefined,
    cl: Tls = undefined,
    up: bool = false,

    fn connect(gpa: std.mem.Allocator, io: Io, port: u16, wd: *Watchdog) !*TlsClient {
        var addr: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(port) };
        const stream = try addr.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const c = try gpa.create(TlsClient);
        c.* = .{ .gpa = gpa, .io = io, .stream = stream, .slot = wd.watch(stream.socket.handle) };
        return c;
    }

    /// The handshake, the chain checked against `roots` at the clock `now`.
    fn handshake(c: *TlsClient, roots: []const []const u8, now: i64) !void {
        for (roots) |der| {
            const at: u32 = @intCast(c.bundle.bytes.items.len);
            try c.bundle.bytes.appendSlice(c.gpa, der);
            try c.bundle.parseCert(c.gpa, at, now);
        }
        c.sr = c.stream.reader(c.io, &c.rb);
        c.sw = c.stream.writer(c.io, &c.wb);
        var ent: [Tls.Options.entropy_len]u8 = undefined;
        c.io.random(&ent);
        c.cl = try Tls.init(&c.sr.interface, &c.sw.interface, .{
            .host = .no_verification,
            .ca = .{ .bundle = .{ .gpa = c.gpa, .io = c.io, .lock = &c.lock, .bundle = &c.bundle } },
            .read_buffer = &c.crb,
            .write_buffer = &c.cwb,
            .entropy = &ent,
            .realtime_now = .fromNanoseconds(@as(i96, now) * std.time.ns_per_s),
        });
        c.up = true;
    }

    /// `text` there and back.
    fn echo(c: *TlsClient, text: []const u8) !void {
        try c.cl.writer.writeAll(text);
        try c.cl.writer.flush();
        try c.sw.interface.flush();
        var got: [256]u8 = undefined;
        try c.cl.reader.readSliceAll(got[0..text.len]);
        try std.testing.expectEqualStrings(text, got[0..text.len]);
    }

    fn close(c: *TlsClient) void {
        if (c.up) {
            c.cl.end() catch {};
            c.sw.interface.flush() catch {};
        }
        c.slot.store(-1, .release);
        c.stream.shutdown(c.io, .both) catch {};
        c.stream.close(c.io);
        c.bundle.deinit(c.gpa);
        c.gpa.destroy(c);
    }
};

/// A second CA (another name and key than `Pki`'s) and a leaf it signs.
const OtherCa = struct {
    key: P256.KeyPair,
    buf: [cert_mod.max_len]u8 = undefined,
    der: []const u8 = "",

    const name = "zui test CA 2";

    fn init(o: *OtherCa, now: i64) !void {
        o.* = .{ .key = try P256.KeyPair.generateDeterministic(@splat(0x22)) };
        o.der = cert_mod.issue(&o.buf, .{ .subject = o.key.public_key, .signer = o.key, .subject_cn = name, .issuer_cn = name, .serial = @splat(4), .not_before = now - 30 * 86400, .not_after = now + 365 * 86400, .ca = true });
    }

    fn leaf(o: *const OtherCa, buf: *[cert_mod.max_len]u8, key: P256.KeyPair, nb: i64, na: i64) []const u8 {
        return cert_mod.issue(buf, .{ .subject = key.public_key, .signer = o.key, .subject_cn = "node.test", .issuer_cn = name, .serial = @splat(5), .not_before = nb, .not_after = na, .dns = "node.test" });
    }
};

/// Waits (at most `ms`) until `counter` is past `floor`.
fn waitPast(counter: *const Atomic(u64), floor: u64, ms: u64) bool {
    var waited: u64 = 0;
    while (counter.load(.monotonic) <= floor and waited < ms) : (waited += 20) h2sock.sleepMs(20);
    return counter.load(.monotonic) > floor;
}

test "--serve-tls-cert over TCP: a connection made after a reload sees the new chain, the one made before it goes on" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const now: i64 = 1_800_000_000;
    var pki: Pki = undefined;
    try pki.init(gpa, io, now);
    defer pki.deinit();
    var ca2: OtherCa = undefined;
    try ca2.init(now);
    const key_a = try P256.KeyPair.generateDeterministic(@splat(0x31));
    const key_b = try P256.KeyPair.generateDeterministic(@splat(0x32));
    var la: [cert_mod.max_len]u8 = undefined;
    var lb: [cert_mod.max_len]u8 = undefined;
    const leaf_a = pki.leaf(&la, key_a, "node.test", now - 86400, now + 60 * 86400);
    const leaf_b = ca2.leaf(&lb, key_b, now - 3600, now + 90 * 86400);
    var cb: [std.fs.max_path_bytes]u8 = undefined;
    var kb: [std.fs.max_path_bytes]u8 = undefined;
    const files: certs.Files = .{ .cert = pki.path(&cb, "chain.pem"), .key = pki.path(&kb, "key.pem") };
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, pki.ca }, key_a);
    var tc = certs.TestClock.init(now);
    var hup: Atomic(bool) = .init(false);
    const cs = try serveTlsCerts(gpa, io, files, .{ .seed = @splat(9), .clock = tc.clock(), .reload = &hup, .poll_ticks = 1 });
    defer cs.deinit();
    var srv = tcptls.Server.initCerts(gpa, io, cs);
    var any: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    var ls = try any.listen(io, .{ .reuse_address = true });
    defer ls.deinit(io);
    const port = ls.socket.address.ip4.port;
    var echo: TlsEcho = .{ .srv = &srv, .ls = &ls, .io = io };
    defer echo.finish();
    try echo.start();
    var wd: Watchdog = .{};
    defer wd.finish();
    try wd.start();
    std.testing.log_level = .err; // (the refusals warn)
    defer std.testing.log_level = .warn;
    // the reload thread, as in the node: the files are looked at four times a second here
    try cs.start();

    // the first connection: the chain read at start, which verifies against the first CA
    const c1 = try TlsClient.connect(gpa, io, port, &wd);
    defer c1.close();
    try c1.handshake(&.{pki.ca}, now);
    try c1.echo("before the reload");
    // a client that trusts the second CA only is not served that chain
    {
        const c = try TlsClient.connect(gpa, io, port, &wd);
        defer c.close();
        try std.testing.expectError(error.TlsCertificateNotVerified, c.handshake(&.{ca2.der}, now));
    }

    // the renewal: the chain, then the key (two renames), picked up from the disk
    tc.set(now + 500);
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_b, ca2.der }, key_b);
    try std.testing.expect(waitPast(&cs.stats.reloads, 0, 10_000));
    try std.testing.expectEqual(sha(leaf_b), presented(cs));
    try std.testing.expectEqual(now + 500, cs.stats.last_reload.load(.acquire));
    try std.testing.expectEqual(now + 90 * 86400, cs.stats.not_after.load(.acquire));

    // the second connection sees another certificate: it verifies against the second CA,
    // and no longer against the first
    const c2 = try TlsClient.connect(gpa, io, port, &wd);
    defer c2.close();
    try c2.handshake(&.{ca2.der}, now);
    try c2.echo("after the reload");
    {
        const c = try TlsClient.connect(gpa, io, port, &wd);
        defer c.close();
        try std.testing.expectError(error.TlsCertificateNotVerified, c.handshake(&.{pki.ca}, now));
    }
    // the first connection, made with the old chain, still works
    try c1.echo("the old connection, after the reload");

    // SIGHUP (the node's handler sets the flag), nothing changed on disk: loaded again
    // (three ticks first: a reload that read the pair between its two renames has a second one)
    h2sock.sleepMs(750);
    const reloads = cs.stats.reloads.load(.monotonic);
    hup.store(true, .release);
    try std.testing.expect(waitPast(&cs.stats.reloads, reloads, 10_000));
    try std.testing.expect(!hup.load(.acquire));
    // a damaged chain file, then SIGHUP on top of it: refused, the node keeps serving
    const errors = cs.stats.reload_errors.load(.monotonic);
    try pki.put("chain.pem", "-----BEGIN CERTIFICATE-----\nMIIB");
    try std.testing.expect(waitPast(&cs.stats.reload_errors, errors, 10_000));
    hup.store(true, .release);
    try std.testing.expect(waitPast(&cs.stats.reload_errors, errors + 1, 10_000));
    try std.testing.expectEqual(sha(leaf_b), presented(cs));
    const c3 = try TlsClient.connect(gpa, io, port, &wd);
    defer c3.close();
    try c3.handshake(&.{ca2.der}, now);
    try c3.echo("after the refused reload");
    try c1.echo("still here");
    try c2.echo("still here too");
    try std.testing.expectEqual(@as(u32, 3), echo.served.load(.monotonic));
    try std.testing.expect(!wd.fired.load(.acquire));
}

test "--serve-tls-cert over TCP: handshakes while the files are replaced each get one whole chain" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const now: i64 = 1_800_000_000;
    var pki: Pki = undefined;
    try pki.init(gpa, io, now);
    defer pki.deinit();
    var ca2: OtherCa = undefined;
    try ca2.init(now);
    const key_a = try P256.KeyPair.generateDeterministic(@splat(0x31));
    const key_b = try P256.KeyPair.generateDeterministic(@splat(0x32));
    var la: [cert_mod.max_len]u8 = undefined;
    var lb: [cert_mod.max_len]u8 = undefined;
    const leaf_a = pki.leaf(&la, key_a, "node.test", now - 86400, now + 60 * 86400);
    const leaf_b = ca2.leaf(&lb, key_b, now - 3600, now + 90 * 86400);
    var cb: [std.fs.max_path_bytes]u8 = undefined;
    var kb: [std.fs.max_path_bytes]u8 = undefined;
    const files: certs.Files = .{ .cert = pki.path(&cb, "chain.pem"), .key = pki.path(&kb, "key.pem") };
    try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, pki.ca }, key_a);
    var tc = certs.TestClock.init(now);
    var hup: Atomic(bool) = .init(false);
    const cs = try serveTlsCerts(gpa, io, files, .{ .seed = @splat(9), .clock = tc.clock(), .reload = &hup, .poll_ticks = 1 });
    defer cs.deinit();
    var srv = tcptls.Server.initCerts(gpa, io, cs);
    var any: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    var ls = try any.listen(io, .{ .reuse_address = true });
    defer ls.deinit(io);
    var echo: TlsEcho = .{ .srv = &srv, .ls = &ls, .io = io };
    defer echo.finish();
    try echo.start();
    var wd: Watchdog = .{};
    defer wd.finish();
    try wd.start();
    std.testing.log_level = .err;
    defer std.testing.log_level = .warn;

    // Clients that trust both CAs connect one after the other while this thread swaps the
    // pair: whichever chain a handshake gets, it is a whole one with its own key.
    const Dial = struct {
        gpa: std.mem.Allocator,
        io: Io,
        port: u16,
        wd: *Watchdog,
        roots: [2][]const u8,
        now: i64,
        count: u32,
        ok: Atomic(u32) = .init(0),
        failed: Atomic(u32) = .init(0),
        done: Atomic(bool) = .init(false),

        fn run(d: *@This()) void {
            defer d.done.store(true, .release);
            for (0..d.count) |_| {
                d.one() catch {
                    _ = d.failed.fetchAdd(1, .monotonic);
                    continue;
                };
                _ = d.ok.fetchAdd(1, .monotonic);
            }
        }

        fn one(d: *@This()) !void {
            const c = try TlsClient.connect(d.gpa, d.io, d.port, d.wd);
            defer c.close();
            try c.handshake(&d.roots, d.now);
            try c.echo("one whole chain");
        }
    };
    var dials: [2]Dial = undefined;
    for (&dials) |*d| d.* = .{ .gpa = gpa, .io = io, .port = ls.socket.address.ip4.port, .wd = &wd, .roots = .{ pki.ca, ca2.der }, .now = now, .count = 20 };
    var threads: [2]std.Thread = undefined;
    var started: usize = 0;
    defer for (threads[0..started]) |t| t.join(); // (each dial ends: the watchdog bounds its reads)
    for (&threads, &dials) |*t, *d| {
        t.* = try std.Thread.spawn(.{}, Dial.run, .{d});
        started += 1;
    }
    var swaps: u64 = 0;
    while (!(dials[0].done.load(.acquire) and dials[1].done.load(.acquire)) and !wd.fired.load(.acquire)) : (swaps += 1) {
        if (swaps % 2 == 0) {
            try pki.putPair("chain.pem", "key.pem", &.{ leaf_b, ca2.der }, key_b);
        } else {
            try pki.putPair("chain.pem", "key.pem", &.{ leaf_a, pki.ca }, key_a);
        }
        try std.testing.expect(cs.tick());
        if (swaps % 3 == 0) {
            hup.store(true, .release);
            try std.testing.expect(cs.tick());
        }
    }
    for (threads[0..started]) |t| t.join();
    started = 0;
    try std.testing.expect(!wd.fired.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), dials[0].failed.load(.monotonic) + dials[1].failed.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 40), dials[0].ok.load(.monotonic) + dials[1].ok.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 40), echo.served.load(.monotonic));
    try std.testing.expect(swaps > 0);
}
