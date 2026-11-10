//! The only holder of validator signing keys (docs/VALIDATOR-DESIGN.md 8.2). validator-base owns
//! the rules in this file; val-epoch-api-keys implements key loading and watermark persistence
//! (keys/), behind these signatures.
//!
//! Every signing path goes through `Signer`:
//!   - consensus blocks (Ed25519 protocol key, consensus.iface.BlockSigner),
//!   - checkpoint summaries (BLS12-381 authority key, intent CheckpointSummary),
//!   - randomness partial signatures (threshold BLS shares from the DKG output),
//!   - TLS and discovery (Ed25519 network key; not equivocation-relevant).
//!
//! Rules (never two different signatures for one slot, even across crashes and restarts):
//!   1. Opening needs a valid `gate.License`; the license's chain id is bound to every call.
//!   2. An exclusive lock file (`<db>/validator/signer/lock`, flock) is held for the process
//!      lifetime: a second process on the same key directory cannot open (hot standby takes over
//!      only after the lock is released: never two signers).
//!   3. Before a block or checkpoint signature leaves the signer, its watermark is written and
//!      fdatasync'd. Block: (epoch, round) must be strictly above the last signed. Checkpoint:
//!      (epoch, seq) above the last, or the same (epoch, seq) with the same summary digest.
const std = @import("std");
const gate = @import("gate.zig");
const signer_impl = @import("keys/signer_impl.zig");
const material = @import("keys/material.zig");

/// The persisted high-water marks. Pure rules here; persistence in keys/watermark_file.zig.
pub const Watermarks = struct {
    block: ?struct { epoch: u64, round: u32 } = null,
    checkpoint: ?struct { epoch: u64, seq: u64, digest: [32]u8 } = null,

    pub fn allowBlock(w: *const Watermarks, epoch: u64, round: u32) bool {
        const last = w.block orelse return true;
        if (epoch != last.epoch) return epoch > last.epoch;
        return round > last.round;
    }
    pub fn recordBlock(w: *Watermarks, epoch: u64, round: u32) void {
        w.block = .{ .epoch = epoch, .round = round };
    }
    pub fn allowCheckpoint(w: *const Watermarks, epoch: u64, seq: u64, digest: *const [32]u8) bool {
        const last = w.checkpoint orelse return true;
        if (epoch != last.epoch) return epoch > last.epoch;
        if (seq != last.seq) return seq > last.seq;
        return std.mem.eql(u8, digest, &last.digest);
    }
    pub fn recordCheckpoint(w: *Watermarks, epoch: u64, seq: u64, digest: *const [32]u8) void {
        w.checkpoint = .{ .epoch = epoch, .seq = seq, .digest = digest.* };
    }
};

pub const Error = error{ NoLicense, Locked, AlreadySigned, Refused, Io, Unimplemented };

/// Where keys come from. Local test committees derive all keys from a seed in process.
pub const KeySpec = union(gate.KeySource) {
    /// Index of this authority in a committee generated from `seed` (tests, localnet).
    generated: struct { seed: [32]u8, index: u32 },
    /// validator.yaml key pairs (protocol, network, worker), each a file path or an in-place
    /// base64 value as KeyPairWithPath has them. Only with an unaudited license; never used while
    /// deepwave is unaudited. The account key is not here: sui-node never reads it on a validator.
    file: struct { protocol: KeyText, network: KeyText, worker: KeyText },
    /// One seat of a Mysten-generated local committee (`deepwave-validator seat`), decoded by the caller.
    localnet_config: material.KeySet,
};

/// A validator.yaml key pair location (`path:` file or in-place `value:`).
pub const KeyText = union(enum) { path: []const u8, value: []const u8 };

pub const Signer = struct {
    license: gate.License,
    watermarks: Watermarks = .{},
    gpa: std.mem.Allocator,
    state: *signer_impl.State,

    /// Opens the key set and the watermark directory `<db>/validator/signer`, takes the lock and
    /// loads the watermarks. Refuses a key source the license does not allow.
    pub fn open(gpa: std.mem.Allocator, io: std.Io, license: *const gate.License, db_dir: []const u8, keys: KeySpec) Error!*Signer {
        if (!license.valid()) return error.NoLicense;
        if (license.mode == .local_test and keys == .file) return error.Refused;
        const set: material.KeySet = switch (keys) {
            .generated => |g| material.generate(&g.seed, g.index),
            .localnet_config => |k| k,
            .file => |f| try loadFiles(gpa, io, f),
        };
        const self = gpa.create(Signer) catch return error.Io;
        errdefer gpa.destroy(self);
        self.* = .{ .license = license.*, .gpa = gpa, .state = undefined };
        self.state = try signer_impl.State.open(gpa, io, db_dir, set, &self.watermarks);
        return self;
    }
    pub fn close(self: *Signer) void {
        self.state.close();
        self.gpa.destroy(self);
    }

    fn loadFiles(gpa: std.mem.Allocator, io: std.Io, f: anytype) Error!material.KeySet {
        const fsutil = @import("keys/fsutil.zig");
        const rd = struct {
            /// The key text: a file's contents (read_*_from_file) or the in-place value.
            fn go(g: std.mem.Allocator, i: std.Io, k: KeyText) Error![]u8 {
                return switch (k) {
                    .path => |p| (fsutil.readAll(g, i, p, 4096) catch return error.Io) orelse error.Io,
                    .value => |v| g.dupe(u8, v) catch error.Io,
                };
            }
        }.go;
        const pk = try rd(gpa, io, f.protocol);
        defer {
            std.crypto.secureZero(u8, pk);
            gpa.free(pk);
        }
        const nk = try rd(gpa, io, f.network);
        defer {
            std.crypto.secureZero(u8, nk);
            gpa.free(nk);
        }
        const wk = try rd(gpa, io, f.worker);
        defer {
            std.crypto.secureZero(u8, wk);
            gpa.free(wk);
        }
        const authority = material.decodeAuthorityFile(pk) catch return error.Io;
        return .{
            .authority = authority,
            .authority_pk = authority.publicKey().toBytes(),
            // NodeConfig::worker_key_pair / network_key_pair: Ed25519 only
            .worker = material.decodeEd25519File(wk) catch return error.Io,
            .network = material.decodeEd25519File(nk) catch return error.Io,
            .account = null,
        };
    }

    /// Ed25519 protocol-key signature over a consensus block signing message.
    pub fn signBlock(self: *Signer, epoch: u64, round: u32, message: []const u8) Error![64]u8 {
        if (!self.license.valid()) return error.NoLicense;
        self.state.mutex.lockUncancelable(self.state.io);
        defer self.state.mutex.unlock(self.state.io);
        if (!self.watermarks.allowBlock(epoch, round)) return error.AlreadySigned;
        var next = self.watermarks;
        next.recordBlock(epoch, round);
        try self.state.persist(&next);
        self.watermarks = next;
        const sig = self.state.keys.worker.sign(message, null) catch return error.Refused;
        return sig.toBytes();
    }

    /// BLS signature over BCS(IntentMessage(Intent::sui_app(CheckpointSummary), summary)).
    pub fn signCheckpoint(self: *Signer, epoch: u64, seq: u64, summary_digest: *const [32]u8, intent_message: []const u8) Error![48]u8 {
        if (!self.license.valid()) return error.NoLicense;
        self.state.mutex.lockUncancelable(self.state.io);
        defer self.state.mutex.unlock(self.state.io);
        if (!self.watermarks.allowCheckpoint(epoch, seq, summary_digest)) return error.AlreadySigned;
        var next = self.watermarks;
        next.recordCheckpoint(epoch, seq, summary_digest);
        try self.state.persist(&next);
        self.watermarks = next;
        return self.state.keys.authority.sign(intent_message).toBytes();
    }

    /// BLS signature of an executed transaction's effects for `SignedTransactionEffects` answers
    /// (TransactionInfo, WaitForEffects details): `AuthoritySignature::new_secure` over
    /// BCS(IntentMessage(Intent::sui_app(TransactionEffects), effects)) ++ epoch (u64 LE). Effects
    /// are a deterministic function of the executed transaction, so signing is idempotent and
    /// needs no watermark; the license check still applies. (Added by val-epoch-api-keys.)
    pub fn signEffects(self: *Signer, epoch: u64, effects_bcs: []const u8, scratch: std.mem.Allocator) Error![48]u8 {
        if (!self.license.valid()) return error.NoLicense;
        const msg = scratch.alloc(u8, 3 + effects_bcs.len + 8) catch return error.Io;
        defer scratch.free(msg);
        msg[0..3].* = .{ 1, 0, 0 }; // IntentScope::TransactionEffects, IntentVersion::V0, AppId::Sui
        @memcpy(msg[3..][0..effects_bcs.len], effects_bcs);
        std.mem.writeInt(u64, msg[3 + effects_bcs.len ..][0..8], epoch, .little);
        return self.state.keys.authority.sign(msg).toBytes();
    }

    /// Seed of the Ed25519 network key, the TLS identity of the Validator API (sui-tls). It signs
    /// handshakes only, nothing equivocation-relevant.
    pub fn networkSeed(self: *const Signer) [32]u8 {
        return self.state.keys.network.secret_key.seed();
    }

    /// The authority's public BLS key (AuthorityName) and the protocol/network public keys.
    pub fn publicKeys(self: *const Signer) Error!struct { authority: [96]u8, protocol: [32]u8, network: [32]u8 } {
        return .{
            .authority = self.state.keys.authority_pk,
            .protocol = self.state.keys.worker.public_key.toBytes(),
            .network = self.state.keys.network.public_key.toBytes(),
        };
    }
};

test "block watermark never allows the same or an older round" {
    var w: Watermarks = .{};
    try std.testing.expect(w.allowBlock(5, 0));
    w.recordBlock(5, 10);
    try std.testing.expect(!w.allowBlock(5, 10));
    try std.testing.expect(!w.allowBlock(5, 9));
    try std.testing.expect(!w.allowBlock(4, 99));
    try std.testing.expect(w.allowBlock(5, 11));
    try std.testing.expect(w.allowBlock(6, 1));
}

test "checkpoint watermark allows re-signing the same digest only" {
    var w: Watermarks = .{};
    const d1: [32]u8 = @splat(1);
    const d2: [32]u8 = @splat(2);
    w.recordCheckpoint(7, 100, &d1);
    try std.testing.expect(w.allowCheckpoint(7, 100, &d1));
    try std.testing.expect(!w.allowCheckpoint(7, 100, &d2));
    try std.testing.expect(!w.allowCheckpoint(7, 99, &d1));
    try std.testing.expect(w.allowCheckpoint(7, 101, &d2));
}

test "signer refuses without a license" {
    const forged: gate.License = .{ .mode = .local_test, .chain_id = @splat('0'), .seal = 0 };
    try std.testing.expectError(error.NoLicense, Signer.open(std.testing.allocator, undefined, &forged, "", .{ .generated = .{ .seed = @splat(0), .index = 0 } }));
}

fn testLicense() gate.License {
    const addrs = [_][]const u8{"127.0.0.1:1"};
    return gate.decide(.{ .chain_id = "0badc0de", .addresses = &addrs, .key_source = .generated }).allowed;
}

test "signer persists watermarks across restarts and refuses a second process" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = pbuf[0..try tmp.dir.realPath(io, &pbuf)];
    const lic = testLicense();
    const spec: KeySpec = .{ .generated = .{ .seed = @splat(3), .index = 1 } };
    var s = try Signer.open(std.testing.allocator, io, &lic, dir, spec);
    try std.testing.expectError(error.Locked, Signer.open(std.testing.allocator, io, &lic, dir, spec));
    const sig = try s.signBlock(4, 10, "block message");
    try std.testing.expectError(error.AlreadySigned, s.signBlock(4, 10, "other"));
    const digest: [32]u8 = @splat(8);
    const c1 = try s.signCheckpoint(4, 5, &digest, "intent bytes");
    const c2 = try s.signCheckpoint(4, 5, &digest, "intent bytes");
    try std.testing.expectEqualSlices(u8, &c1, &c2);
    const other: [32]u8 = @splat(9);
    try std.testing.expectError(error.AlreadySigned, s.signCheckpoint(4, 5, &other, "x"));
    const keys = try s.publicKeys();
    // the block signature verifies under the protocol key
    const pk = try std.crypto.sign.Ed25519.PublicKey.fromBytes(keys.protocol);
    try std.crypto.sign.Ed25519.Signature.fromBytes(sig).verify("block message", pk);
    s.close();
    var s2 = try Signer.open(std.testing.allocator, io, &lic, dir, spec);
    defer s2.close();
    try std.testing.expectError(error.AlreadySigned, s2.signBlock(4, 10, "again"));
    _ = try s2.signBlock(4, 11, "next");
}
