//! fastcrypto-tbls `ecies_v1` over G2: multi-recipient ECIES with a shared ephemeral key and a
//! DDH-tuple proof of well-formedness, AES-256-CTR with a zero IV (the key is fresh per
//! receiver), and the recovery package used by DKG complaints.
//!
//!   MultiRecipientEncryption wire: c (G2 96) | c_hat (G2 96) | encs: Vec<Vec<u8>> | proof (224)
//!   RecoveryPackage wire:          ephemeral_key (G2 96) | proof (224)
//!
//! All allocations (ciphertexts) come from the allocator the caller passes (an arena in the DKG).
const std = @import("std");
const group = @import("group.zig");
const wire = @import("wire.zig");
const oracle = @import("oracle.zig");
const nizk = @import("nizk.zig");
const G2 = group.G2;
const G2P = group.G2P;
const Scalar = group.Scalar;
const Aes256 = std.crypto.core.aes.Aes256;

pub const Error = error{ InvalidProof, InvalidInput } || oracle.RandomOracle.Error || std.mem.Allocator.Error;

/// The per-receiver key: `encs_ro.evaluate(&(receiver_index as u64, pk_r))`, first 32 bytes.
fn symKey(encs_ro: *const oracle.RandomOracle, receiver_index: usize, shared: G2P) [32]u8 {
    var obj: [8 + 96]u8 = undefined;
    std.mem.writeInt(u64, obj[0..8], receiver_index, .little);
    obj[8..104].* = group.g2ToBytes(shared);
    const d = encs_ro.evaluate(&obj);
    return d[0..32].*;
}

/// AES-256-CTR (128 bit big endian counter, zero IV) in place semantics: dst = src xor stream.
fn ctr(key: [32]u8, dst: []u8, src: []const u8) void {
    const ctx = Aes256.initEnc(key);
    const iv: [16]u8 = @splat(0);
    std.crypto.core.modes.ctr(@TypeOf(ctx), ctx, dst, src, iv, .big);
}

pub const RecoveryPackage = struct {
    ephemeral_key: G2P,
    proof: nizk.DdhTupleNizk,

    pub fn encode(self: *const RecoveryPackage, w: *wire.Writer) wire.Error!void {
        try w.g2(self.ephemeral_key);
        try self.proof.encode(w);
    }
    pub fn decode(r: *wire.Reader) wire.Error!RecoveryPackage {
        const e = try r.g2();
        return .{ .ephemeral_key = e, .proof = try nizk.DdhTupleNizk.decode(r) };
    }
};

pub const MultiRecipientEncryption = struct {
    c: G2P,
    c_hat: G2P,
    encs: []const []const u8,
    proof: nizk.DdhTupleNizk,

    pub const Recipient = struct { pk: G2P, msg: []const u8 };

    fn gHat(ro: *const oracle.RandomOracle, c: G2P) Error!G2P {
        const r = try ro.extend("g_hat");
        const d = r.evaluate(&group.g2ToBytes(c));
        return group.hashToG2(&d);
    }

    pub fn encrypt(
        arena: std.mem.Allocator,
        recipients: []const Recipient,
        encryption_ro: *const oracle.RandomOracle,
        rng: std.Random,
    ) Error!MultiRecipientEncryption {
        const r = group.scalarRand(rng);
        const c = group.mulSecret(G2, group.g2Generator(), r);
        const g_hat = try gHat(encryption_ro, c);
        const c_hat = group.mulSecret(G2, g_hat, r);
        const zk_ro = try encryption_ro.extend("zk");
        const proof = nizk.DdhTupleNizk.create(r, g_hat, c, c_hat, &zk_ro, rng);
        const encs_ro = try encryption_ro.extend("encs");
        const encs = try arena.alloc([]const u8, recipients.len);
        for (recipients, 0..) |rc, i| {
            const pk_r = group.mulSecret(G2, rc.pk, r);
            var k = symKey(&encs_ro, i, pk_r);
            defer std.crypto.secureZero(u8, &k);
            const out = try arena.alloc(u8, rc.msg.len);
            ctr(k, out, rc.msg);
            encs[i] = out;
        }
        return .{ .c = c, .c_hat = c_hat, .encs = encs, .proof = proof };
    }

    /// `verify`: the proof, and every ciphertext non-empty.
    pub fn verify(self: *const MultiRecipientEncryption, encryption_ro: *const oracle.RandomOracle) Error!void {
        const g_hat = try gHat(encryption_ro, self.c);
        const zk_ro = try encryption_ro.extend("zk");
        try self.proof.verify(g_hat, self.c, self.c_hat, &zk_ro);
        for (self.encs) |e| if (e.len == 0) return error.InvalidInput;
    }

    pub fn decrypt(
        self: *const MultiRecipientEncryption,
        arena: std.mem.Allocator,
        sk: Scalar,
        encryption_ro: *const oracle.RandomOracle,
        receiver_index: usize,
    ) Error![]u8 {
        if (receiver_index >= self.encs.len) return error.InvalidInput;
        const encs_ro = try encryption_ro.extend("encs");
        const eph = group.mulSecret(G2, self.c, sk);
        var k = symKey(&encs_ro, receiver_index, eph);
        defer std.crypto.secureZero(u8, &k);
        const out = try arena.alloc(u8, self.encs[receiver_index].len);
        ctr(k, out, self.encs[receiver_index]);
        return out;
    }

    pub fn createRecoveryPackage(
        self: *const MultiRecipientEncryption,
        sk: Scalar,
        recovery_ro: *const oracle.RandomOracle,
        rng: std.Random,
    ) RecoveryPackage {
        const pk = group.mulSecret(G2, group.g2Generator(), sk);
        const eph = group.mulSecret(G2, self.c, sk);
        const proof = nizk.DdhTupleNizk.create(sk, self.c, pk, eph, recovery_ro, rng);
        return .{ .ephemeral_key = eph, .proof = proof };
    }

    pub fn decryptWithRecoveryPackage(
        self: *const MultiRecipientEncryption,
        arena: std.mem.Allocator,
        pkg: *const RecoveryPackage,
        recovery_ro: *const oracle.RandomOracle,
        encryption_ro: *const oracle.RandomOracle,
        receiver_pk: G2P,
        receiver_index: usize,
    ) Error![]u8 {
        if (receiver_index >= self.encs.len) return error.InvalidInput;
        try pkg.proof.verify(self.c, receiver_pk, pkg.ephemeral_key, recovery_ro);
        const encs_ro = try encryption_ro.extend("encs");
        var k = symKey(&encs_ro, receiver_index, pkg.ephemeral_key);
        defer std.crypto.secureZero(u8, &k);
        const out = try arena.alloc(u8, self.encs[receiver_index].len);
        ctr(k, out, self.encs[receiver_index]);
        return out;
    }

    pub fn encode(self: *const MultiRecipientEncryption, w: *wire.Writer) wire.Error!void {
        try w.g2(self.c);
        try w.g2(self.c_hat);
        try w.uleb(self.encs.len);
        for (self.encs) |e| try w.bytesVec(e);
        try self.proof.encode(w);
    }

    pub fn decode(arena: std.mem.Allocator, r: *wire.Reader) wire.Error!MultiRecipientEncryption {
        const c = try r.g2();
        const c_hat = try r.g2();
        const n = try r.seqLen(1);
        const encs = try arena.alloc([]const u8, n);
        for (encs) |*e| {
            const len = try r.seqLen(1);
            e.* = try arena.dupe(u8, try r.take(len));
        }
        return .{ .c = c, .c_hat = c_hat, .encs = encs, .proof = try nizk.DdhTupleNizk.decode(r) };
    }

    pub fn clone(self: *const MultiRecipientEncryption, arena: std.mem.Allocator) std.mem.Allocator.Error!MultiRecipientEncryption {
        const encs = try arena.alloc([]const u8, self.encs.len);
        for (self.encs, encs) |s, *d| d.* = try arena.dupe(u8, s);
        return .{ .c = self.c, .c_hat = self.c_hat, .encs = encs, .proof = self.proof };
    }
};

test "multi recipient encryption roundtrip, verify, recovery" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(7);
    const rng = prng.random();
    var sks: [3]Scalar = undefined;
    var recips: [3]MultiRecipientEncryption.Recipient = undefined;
    const msgs = [_][]const u8{ "hello share one", "two", "a third message of different length" };
    for (0..3) |i| {
        sks[i] = group.scalarRand(rng);
        recips[i] = .{ .pk = group.mulPublic(G2, group.g2Generator(), sks[i]), .msg = msgs[i] };
    }
    const ro = try oracle.RandomOracle.init("ecies test");
    const enc = try MultiRecipientEncryption.encrypt(arena, &recips, &ro, rng);
    try enc.verify(&ro);
    for (0..3) |i| {
        const pt = try enc.decrypt(arena, sks[i], &ro, i);
        try std.testing.expectEqualStrings(msgs[i], pt);
    }
    // wire roundtrip
    var w = wire.Writer.init(std.testing.allocator);
    defer w.deinit();
    try enc.encode(&w);
    var rd = wire.Reader.init(w.buf.items);
    const back = try MultiRecipientEncryption.decode(arena, &rd);
    try rd.finish();
    try back.verify(&ro);
    // recovery
    const rec_ro = try oracle.RandomOracle.init("recovery");
    const pkg = enc.createRecoveryPackage(sks[1], &rec_ro, rng);
    const pt = try enc.decryptWithRecoveryPackage(arena, &pkg, &rec_ro, &ro, recips[1].pk, 1);
    try std.testing.expectEqualStrings(msgs[1], pt);
}
