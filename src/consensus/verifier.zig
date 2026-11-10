//! consensus_core::block_verifier::SignedBlockVerifier at mainnet-v1.83.1: every check, in Rust's
//! order, on a peer block before it enters the DAG: epoch, genesis round, block version, author
//! index, signature, ancestor count and shape (position, round, genesis refs, duplicate authors,
//! parent stake quorum at round - 1), transaction limits, then the TransactionVerifier (batch check
//! or the fast-path vote). Owner lane: val-consensus-core. V3 vote checks are not implemented (V3 off
//! on mainnet; `enable_v3` returns `error.Unsupported`).
//!
//! The verdict per block equals Rust's; peer faults are `BlockVerdict.reject` values, not errors.
//! Signature checks may run in the verify tiles in batches: set `verify_signatures = false` and call
//! `verifySignature` separately.
const std = @import("std");
const sig = @import("sig");
const types = @import("types.zig");
const err = @import("error.zig");
const iface = @import("iface.zig");
const digest_mod = @import("digest.zig");
const Context = @import("context.zig").Context;

const Allocator = std.mem.Allocator;

pub const SignedBlockVerifier = struct {
    context: *const Context,
    tx_verifier: iface.TransactionVerifier,
    /// Genesis refs of this epoch (genesis ancestors must be one of these).
    genesis: []const types.BlockRef,
    verify_signatures: bool = true,

    /// `genesis_refs` is borrowed (e.g. from `digest.genesisBlocks`).
    pub fn init(context: *const Context, tx_verifier: iface.TransactionVerifier, genesis: []const types.BlockRef) SignedBlockVerifier {
        return .{ .context = context, .tx_verifier = tx_verifier, .genesis = genesis };
    }

    fn isGenesis(self: *const SignedBlockVerifier, r: types.BlockRef) bool {
        for (self.genesis) |g| if (g.eql(r)) return true;
        return false;
    }

    /// `SignedBlock::verify_signature`.
    pub fn verifySignature(self: *const SignedBlockVerifier, gpa: Allocator, sb: *const types.SignedBlock) err.Error!err.BlockVerdict {
        return self.verifySignatureWith(gpa, sb, null);
    }

    /// The bytes a block was decoded from, for the one-pass digests (digest.zig): the signature
    /// check hashes them once and leaves the BlockDigest here for the caller.
    const Wire = struct {
        serialized: []const u8,
        block_digest: ?types.BlockDigest = null,
    };

    fn verifySignatureWith(self: *const SignedBlockVerifier, gpa: Allocator, sb: *const types.SignedBlock, wire: ?*Wire) err.Error!err.BlockVerdict {
        const c = &self.context.committee;
        const author = sb.inner.author();
        if (!c.isValidIndex(author)) return .{ .reject = .{ .invalid_authority_index = author } };
        if (sb.signature.len != 64) return .{ .reject = .malformed_signature };
        const msg = msg: {
            if (wire) |w| if (digest_mod.innerLen(sb, w.serialized)) |inner_len| {
                digest_mod.debugCheckInnerPrefix(gpa, &sb.inner, w.serialized[0..inner_len]);
                const d = digest_mod.blockDigestsAt(w.serialized, inner_len);
                w.block_digest = d.block;
                break :msg digest_mod.signingMessage(&d.inner);
            };
            break :msg try digest_mod.blockSigningMessage(gpa, &sb.inner);
        };
        const v = sig.ed25519.verify(&c.authorities[author].protocol_key, &msg, sb.signature[0..64]);
        if (!v.isValid()) return .{ .reject = .signature_verification_failure };
        return .ok;
    }

    /// `verify_block`: every check but the transaction verifier.
    pub fn verifyBlock(self: *const SignedBlockVerifier, gpa: Allocator, sb: *const types.SignedBlock) err.Error!err.BlockVerdict {
        return self.verifyBlockWith(gpa, sb, null);
    }

    fn verifyBlockWith(self: *const SignedBlockVerifier, gpa: Allocator, sb: *const types.SignedBlock, wire: ?*Wire) err.Error!err.BlockVerdict {
        const pc = &self.context.protocol_config;
        if (pc.enable_v3) return error.Unsupported;
        const c = &self.context.committee;
        const b = &sb.inner;
        if (b.epoch() != c.epoch) return .{ .reject = .{ .wrong_epoch = .{ .expected = c.epoch, .actual = b.epoch() } } };
        if (b.round() == 0) return .{ .reject = .genesis_block };
        switch (b.*) {
            .V1, .V2 => {},
            .V3 => return .{ .reject = .unexpected_block_version },
        }
        if (!c.isValidIndex(b.author())) return .{ .reject = .{ .invalid_authority_index = b.author() } };
        if (self.verify_signatures) {
            switch (try self.verifySignatureWith(gpa, sb, wire)) {
                .ok => {},
                .reject => |r| return .{ .reject = r },
            }
        }

        const anc = b.ancestors();
        if (anc.len > c.size()) return .{ .reject = .{ .too_many_ancestors = anc.len } };
        if (anc.len == 0) return .{ .reject = .insufficient_parent_stake };
        var seen: std.StaticBitSet(@import("committee.zig").max_committee_size) = .empty;
        if (c.size() > @import("committee.zig").max_committee_size) return error.Unsupported;
        var parent_stakes: types.Stake = 0;
        for (anc, 0..) |a, i| {
            if (!c.isValidIndex(a.author)) return .{ .reject = .{ .invalid_authority_index = a.author } };
            if ((i == 0 and a.author != b.author()) or (i > 0 and a.author == b.author())) return .{ .reject = .invalid_ancestor_position };
            if (a.round >= b.round()) return .{ .reject = .invalid_ancestor_round };
            if (a.round == types.GENESIS_ROUND and !self.isGenesis(a)) return .{ .reject = .invalid_genesis_ancestor };
            if (seen.isSet(a.author)) return .{ .reject = .{ .duplicated_ancestors_authority = a.author } };
            seen.set(a.author);
            if (a.round == b.round() - 1) parent_stakes += c.stake(a.author);
        }
        if (!c.reachedQuorum(parent_stakes)) return .{ .reject = .insufficient_parent_stake };

        return self.checkTransactions(b.transactions());
    }

    /// `check_transactions`: size and count limits (a limit of 0 disables the check, as in Rust).
    pub fn checkTransactions(self: *const SignedBlockVerifier, txs: []const types.Transaction) err.BlockVerdict {
        const pc = &self.context.protocol_config;
        var total: usize = 0;
        for (txs) |t| {
            if (t.data.len > pc.max_transaction_size_bytes and pc.max_transaction_size_bytes > 0) return .{ .reject = .transaction_too_large };
            total += t.data.len;
        }
        if (txs.len > pc.max_num_transactions_in_block and pc.max_num_transactions_in_block > 0) return .{ .reject = .too_many_transactions };
        if (total > pc.max_transactions_in_block_bytes and pc.max_transactions_in_block_bytes > 0) return .{ .reject = .too_many_transaction_bytes };
        return .ok;
    }

    /// Decodes `serialized` (BCS SignedBlock) into `arena`, checks it, and on `.ok` fills `out`
    /// (digest = Blake2b256(serialized)) and the fast-path reject votes for its transactions
    /// (`reject_votes[0..reject_count.*]`). `reject_votes` needs capacity for one vote per
    /// transaction of the block.
    pub fn verifyAndVote(
        self: *const SignedBlockVerifier,
        arena: Allocator,
        serialized: []const u8,
        out: *types.VerifiedBlock,
        reject_votes: []types.TransactionIndex,
        reject_count: *usize,
    ) err.Error!err.BlockVerdict {
        reject_count.* = 0;
        const sb = digest_mod.decodeSignedBlock(arena, serialized) catch |e| switch (e) {
            error.SerializationFailure => return .{ .reject = .malformed_block },
            else => return e,
        };
        var wire: Wire = .{ .serialized = serialized };
        switch (try self.verifyBlockWith(arena, &sb, if (digest_mod.onePass()) &wire else null)) {
            .ok => {},
            .reject => |r| return .{ .reject = r },
        }
        const vb = verified(sb, &wire);
        const txs = sb.inner.transactions();
        if (self.context.protocol_config.transaction_voting_enabled) {
            if (reject_votes.len < txs.len) return error.Invariant;
            const n = self.tx_verifier.verifyAndVoteBatch(vb.reference(), txs, reject_votes) catch return .{ .reject = .invalid_transaction };
            reject_count.* = n;
        } else {
            self.tx_verifier.verifyBatch(vb.reference(), txs) catch return .{ .reject = .invalid_transaction };
        }
        out.* = vb;
        return .ok;
    }

    /// `VerifiedBlock::new_verified`, with the BlockDigest the signature check already has when
    /// the one-pass digests ran.
    fn verified(sb: types.SignedBlock, wire: *const Wire) types.VerifiedBlock {
        if (wire.block_digest) |d| return .{ .block = sb, .serialized = wire.serialized, .digest = d };
        return digest_mod.newVerified(sb, wire.serialized);
    }

    /// Checks a block that came with a certified commit (CommitSyncer path): shape and signature,
    /// no transaction votes (the commit certifies it).
    pub fn verifyForCommitSync(self: *const SignedBlockVerifier, arena: Allocator, serialized: []const u8, out: *types.VerifiedBlock) err.Error!err.BlockVerdict {
        const sb = digest_mod.decodeSignedBlock(arena, serialized) catch |e| switch (e) {
            error.SerializationFailure => return .{ .reject = .malformed_block },
            else => return e,
        };
        var wire: Wire = .{ .serialized = serialized };
        switch (try self.verifyBlockWith(arena, &sb, if (digest_mod.onePass()) &wire else null)) {
            .ok => {},
            .reject => |r| return .{ .reject = r },
        }
        const vb = verified(sb, &wire);
        self.tx_verifier.verifyBatch(vb.reference(), sb.inner.transactions()) catch return .{ .reject = .invalid_transaction };
        out.* = vb;
        return .ok;
    }
};

/// A TransactionVerifier that accepts everything and never votes to reject (Rust `NoopTransactionVerifier`).
pub const NoopTransactionVerifier = struct {
    pub fn verifier(self: *NoopTransactionVerifier) iface.TransactionVerifier {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable: iface.TransactionVerifier.VTable = .{ .verify_batch = verifyBatch, .verify_and_vote_batch = vote };
    fn verifyBatch(_: *anyopaque, _: types.BlockRef, _: []const types.Transaction) iface.TransactionVerifier.VerifyError!void {}
    fn vote(_: *anyopaque, _: types.BlockRef, _: []const types.Transaction, _: []types.TransactionIndex) iface.TransactionVerifier.VerifyError!usize {
        return 0;
    }
};

test "verifier checks shape, signature and quorum of parents" {
    const test_dag = @import("test_dag.zig");
    const gpa = std.testing.allocator;
    var stakes = test_dag.Fixture.equalStakes(4);
    const f = try test_dag.Fixture.init(gpa, .{ .stakes = &stakes });
    defer f.deinit();
    const a = f.arena();

    // Real keys: authority 0 signs.
    const seed: [32]u8 = @splat(5);
    const kp = sig.ed25519.KeyPair.fromSeed(&seed);
    f.authorities[0].protocol_key = kp.pk;

    var noop: NoopTransactionVerifier = .{};
    const g = f.genesisRefs();
    const v = SignedBlockVerifier.init(f.context, noop.verifier(), g);

    const anc = try a.dupe(types.BlockRef, g[0..3]); // authority 0, 1, 2 at genesis
    const block: types.Block = .{ .V2 = .{ .epoch = 0, .round = 1, .author = 0, .timestamp_ms = 5, .ancestors = anc, .transactions = &.{}, .transaction_votes = &.{}, .commit_votes = &.{}, .misbehavior_reports = &.{} } };
    const msg = try digest_mod.blockSigningMessage(gpa, &block);
    const sg = sig.ed25519.sign(&seed, &msg);
    const sb: types.SignedBlock = .{ .inner = block, .signature = &sg };
    const ser = try digest_mod.serializeSignedBlock(a, &sb);

    var out: types.VerifiedBlock = undefined;
    var votes: [4]types.TransactionIndex = undefined;
    var nv: usize = 0;
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const verdict = try v.verifyAndVote(scratch.allocator(), ser, &out, &votes, &nv);
    try std.testing.expect(verdict == .ok);
    try std.testing.expectEqual(digest_mod.blockDigest(ser), out.digest);

    // A flipped signature byte is rejected.
    var bad = try a.dupe(u8, ser);
    bad[bad.len - 1] ^= 1;
    const v2 = try v.verifyAndVote(scratch.allocator(), bad, &out, &votes, &nv);
    try std.testing.expect(v2 == .reject and v2.reject == .signature_verification_failure);

    // Too few parents at round 0 (genesis counts as round - 1 = 0): only two ancestors.
    const anc2 = try a.dupe(types.BlockRef, g[0..2]);
    const block2: types.Block = .{ .V2 = .{ .epoch = 0, .round = 1, .author = 0, .timestamp_ms = 5, .ancestors = anc2, .transactions = &.{}, .transaction_votes = &.{}, .commit_votes = &.{}, .misbehavior_reports = &.{} } };
    const msg2 = try digest_mod.blockSigningMessage(gpa, &block2);
    const sg2 = sig.ed25519.sign(&seed, &msg2);
    const ser2 = try digest_mod.serializeSignedBlock(a, &.{ .inner = block2, .signature = &sg2 });
    const v3 = try v.verifyAndVote(scratch.allocator(), ser2, &out, &votes, &nv);
    try std.testing.expect(v3 == .reject and v3.reject == .insufficient_parent_stake);

    // Wrong epoch.
    const block3: types.Block = .{ .V2 = .{ .epoch = 9, .round = 1, .author = 0, .timestamp_ms = 5, .ancestors = anc, .transactions = &.{}, .transaction_votes = &.{}, .commit_votes = &.{}, .misbehavior_reports = &.{} } };
    const ser3 = try digest_mod.serializeSignedBlock(a, &.{ .inner = block3, .signature = &sg });
    const v4 = try v.verifyAndVote(scratch.allocator(), ser3, &out, &votes, &nv);
    try std.testing.expect(v4 == .reject and v4.reject == .wrong_epoch);
}

// ---------------------------------------------------------------- one-pass block digests
//
// Rust hashes a block twice (block.rs): InnerBlockDigest = Blake2b256(BCS(Block)) for the
// signature, BlockDigest = Blake2b256(BCS(SignedBlock)) for the BlockRef. `SignedBlock` is
// `{ inner: Block, signature: Bytes }`, so its BCS is BCS(Block) ++ ULEB128(signature length) ++
// signature, and the first message is a prefix of the second: one streaming Blake2b pass with the
// state copied at the prefix boundary gives both digests. The tests below prove that against the
// two-pass code on generated blocks, tampered copies and non-canonical encodings.

const bcs = @import("bcs");
const hash = @import("hash");

/// The one-pass digests written from Blake2b's definition only (no code shared with digest.zig):
/// `[0]` = Blake2b256(serialized[0..inner_len]), `[1]` = Blake2b256(serialized).
fn onePassReference(serialized: []const u8, inner_len: usize) [2]types.BlockDigest {
    var h = hash.Blake2b256.init();
    h.update(serialized[0..inner_len]);
    var fork = h;
    var out: [2]types.BlockDigest = undefined;
    fork.final(&out[0]);
    h.update(serialized[inner_len..]);
    h.final(&out[1]);
    return out;
}

/// Inputs of the one-pass exactness tests: blocks a proposer would make (light and full), copies
/// with defects (bytes flipped, cut, appended, other signature lengths, rule violations signed by
/// the author) and non-canonical encodings of valid blocks.
const BlockCorpus = struct {
    const n_auth = 7;

    gpa: Allocator,
    fx: *test_dag.Fixture,
    keys: [n_auth]sig.ed25519.KeyPair,
    arena_state: std.heap.ArenaAllocator,
    prng: std.Random.DefaultPrng,
    made: std.ArrayList(Made) = .empty,
    inputs: std.ArrayList(Input) = .empty,

    const test_dag = @import("test_dag.zig");
    const config = @import("config.zig");

    const Made = struct { block: types.Block, signer: usize, signature: [64]u8, bytes: []const u8 };
    const Kind = enum { valid, defect, non_canonical };
    const Input = struct { kind: Kind, bytes: []const u8 };

    const Shape = union(enum) {
        /// 0 to 4 transactions of 0 to 300 bytes.
        light,
        /// 120 transactions of 2000 bytes: 240 KB, inside the mainnet 141 limits.
        full,
        /// One transaction of this many bytes in a V2 block with no votes or reports, so the
        /// prefix length grows with it (walks the prefix end over a Blake2b block).
        one_tx: usize,
    };

    const Defect = enum { none, wrong_epoch, genesis_round, bad_author, v3, few_ancestors, ancestor_round, dup_ancestor, too_many_txs };

    fn init(gpa: Allocator, seed: u64) !*BlockCorpus {
        const c = try gpa.create(BlockCorpus);
        errdefer gpa.destroy(c);
        var stakes = test_dag.Fixture.equalStakes(n_auth);
        const pc = try config.ProtocolConfig.fromProtocol(141, .mainnet);
        c.* = .{
            .gpa = gpa,
            .fx = try test_dag.Fixture.init(gpa, .{ .stakes = &stakes, .protocol = pc, .own_index = null }),
            .keys = undefined,
            .arena_state = std.heap.ArenaAllocator.init(gpa),
            .prng = std.Random.DefaultPrng.init(seed),
        };
        for (&c.keys, c.fx.authorities, 0..) |*k, *au, i| {
            const s: [32]u8 = @splat(@intCast(i + 1));
            k.* = sig.ed25519.KeyPair.fromSeed(&s);
            au.protocol_key = k.pk;
        }
        return c;
    }

    fn deinit(c: *BlockCorpus) void {
        const gpa = c.gpa;
        c.fx.deinit();
        c.arena_state.deinit();
        gpa.destroy(c);
    }

    fn randomDigest(c: *BlockCorpus) [32]u8 {
        var d: [32]u8 = undefined;
        c.prng.random().bytes(&d);
        return d;
    }

    fn randomBlock(c: *BlockCorpus, shape: Shape, defect: Defect) !types.Block {
        const a = c.arena_state.allocator();
        const r = c.prng.random();
        const round: types.Round = if (defect == .genesis_round) 0 else 2 + r.uintLessThan(u32, 100_000);
        const author: types.AuthorityIndex = if (defect == .bad_author) n_auth + 3 else r.uintLessThan(u32, n_auth);
        const own: types.AuthorityIndex = if (author < n_auth) author else 0;

        // Own block first, then every other authority in a random order; up to two of them at an
        // older round (the quorum of 5 at round - 1 stays).
        var order: [n_auth]types.AuthorityIndex = undefined;
        order[0] = own;
        var k: usize = 1;
        for (0..n_auth) |i| if (i != own) {
            order[k] = @intCast(i);
            k += 1;
        };
        r.shuffle(types.AuthorityIndex, order[1..]);
        const n_anc: usize = if (defect == .few_ancestors) 3 else n_auth;
        const anc = try a.alloc(types.BlockRef, n_anc);
        const prev = round -| 1;
        const older = r.uintAtMost(usize, 2);
        for (anc, 0..) |*x, i| {
            const back: u32 = if (i >= n_anc - older and prev > 1) 1 else 0;
            x.* = .{ .round = prev - back, .author = order[i], .digest = c.randomDigest() };
        }
        if (defect == .ancestor_round) anc[1 + r.uintLessThan(usize, n_anc - 1)].round = round + r.uintAtMost(u32, 1);
        if (defect == .dup_ancestor) anc[n_anc - 1].author = anc[1].author;

        const n_tx: usize, const tx_len: ?usize = switch (shape) {
            .light => .{ r.uintAtMost(usize, 4), null },
            .full => .{ 120, 2000 },
            .one_tx => |len| .{ 1, len },
        };
        const txs = try a.alloc(types.Transaction, if (defect == .too_many_txs) 129 else n_tx);
        for (txs) |*t| {
            const data = try a.alloc(u8, if (defect == .too_many_txs) 1 else tx_len orelse r.uintAtMost(usize, 300));
            r.bytes(data);
            t.* = .{ .data = data };
        }

        const plain = shape == .one_tx;
        const tx_votes = try a.alloc(types.BlockTransactionVotes, if (plain) 0 else r.uintAtMost(usize, 3));
        for (tx_votes) |*v| {
            const rejects = try a.alloc(types.TransactionIndex, r.uintAtMost(usize, 5));
            for (rejects) |*x| x.* = r.int(u16);
            v.* = .{ .block_ref = .{ .round = r.int(u32), .author = r.uintLessThan(u32, n_auth), .digest = c.randomDigest() }, .rejects = rejects };
        }
        const commit_votes = try a.alloc(types.CommitVote, if (plain) 0 else r.uintAtMost(usize, 3));
        for (commit_votes) |*v| v.* = .{ .index = r.int(u32), .digest = c.randomDigest() };
        const reports = try a.alloc(types.MisbehaviorReport, if (plain) 0 else r.uintAtMost(usize, 2));
        for (reports) |*m| m.* = .{ .target = r.uintLessThan(u32, n_auth), .proof = .{ .InvalidBlock = .{ .round = r.int(u32), .author = r.uintLessThan(u32, n_auth), .digest = c.randomDigest() } } };

        const epoch: types.Epoch = if (defect == .wrong_epoch) 1 + r.uintLessThan(u64, 9) else c.fx.context.committee.epoch;
        const ts = r.int(u64);
        if (defect == .v3) return .{ .V3 = .{ .epoch = epoch, .round = round, .author = author, .timestamp_ms = ts, .ancestors = anc, .transactions = txs, .transaction_votes = tx_votes, .transaction_votes_cutoff_round = r.int(u32), .commit_votes = commit_votes, .misbehavior_reports = reports } };
        if (!plain and r.uintLessThan(u8, 4) == 0) return .{ .V1 = .{ .epoch = epoch, .round = round, .author = author, .timestamp_ms = ts, .ancestors = anc, .transactions = txs, .commit_votes = commit_votes, .misbehavior_reports = reports } };
        return .{ .V2 = .{ .epoch = epoch, .round = round, .author = author, .timestamp_ms = ts, .ancestors = anc, .transactions = txs, .transaction_votes = tx_votes, .commit_votes = commit_votes, .misbehavior_reports = reports } };
    }

    /// Signs and serializes with the two-pass code, as `Core.tryNewBlock` does today.
    fn make(c: *BlockCorpus, block: types.Block, signer: usize) !Made {
        const a = c.arena_state.allocator();
        const msg = try digest_mod.blockSigningMessage(c.gpa, &block);
        const signature = c.keys[signer].sign(&msg);
        const bytes = try digest_mod.serializeSignedBlock(a, &.{ .inner = block, .signature = &signature });
        return .{ .block = block, .signer = signer, .signature = signature, .bytes = bytes };
    }

    fn add(c: *BlockCorpus, kind: Kind, bytes: []const u8) !void {
        try c.inputs.append(c.arena_state.allocator(), .{ .kind = kind, .bytes = bytes });
    }

    /// `bytes` with `bytes[at..][0..drop]` replaced by `put`.
    fn splice(c: *BlockCorpus, bytes: []const u8, at: usize, drop: usize, put: []const u8) ![]u8 {
        const out = try c.arena_state.allocator().alloc(u8, bytes.len - drop + put.len);
        @memcpy(out[0..at], bytes[0..at]);
        @memcpy(out[at..][0..put.len], put);
        @memcpy(out[at + put.len ..], bytes[at + drop ..]);
        return out;
    }

    /// One valid block plus `n_defects` damaged copies of its bytes.
    fn addValid(c: *BlockCorpus, shape: Shape, n_defects: usize) !void {
        const a = c.arena_state.allocator();
        const r = c.prng.random();
        const block = try c.randomBlock(shape, .none);
        const m = try c.make(block, block.author());
        try c.made.append(a, m);
        try c.add(.valid, m.bytes);
        const inner_len = m.bytes.len - 65;
        for (0..n_defects) |i| {
            switch (i % 10) {
                // one byte flipped: anywhere, in the fixed header, in the signature field
                0, 1, 2 => {
                    const copy = try a.dupe(u8, m.bytes);
                    const at = switch (i % 10) {
                        0 => r.uintLessThan(usize, copy.len),
                        1 => r.uintLessThan(usize, @min(copy.len, 32)),
                        else => inner_len + r.uintLessThan(usize, 65),
                    };
                    copy[at] ^= @as(u8, 1) << r.int(u3);
                    try c.add(.defect, copy);
                },
                // cut short
                3 => try c.add(.defect, m.bytes[0 .. m.bytes.len - 1 - r.uintLessThan(usize, @min(m.bytes.len - 1, 80))]),
                // bytes after the end
                4 => {
                    var extra: [3]u8 = undefined;
                    r.bytes(&extra);
                    try c.add(.defect, try c.splice(m.bytes, m.bytes.len, 0, extra[0 .. 1 + r.uintLessThan(usize, 3)]));
                },
                // signature of 0, 63 and 65 bytes, encoded canonically (decodes, then malformed_signature)
                5 => try c.add(.defect, try c.splice(m.bytes, inner_len, 65, &.{0})),
                6 => try c.add(.defect, try c.splice(m.bytes, inner_len, 2, &.{63})),
                7 => try c.add(.defect, try c.splice(m.bytes, inner_len, 1, &.{ 65, r.int(u8) })),
                // signature length byte that disagrees with the bytes present
                8 => try c.add(.defect, try c.splice(m.bytes, inner_len, 1, &.{if (r.boolean()) 63 else 65})),
                // signed by another authority
                else => try c.add(.defect, (try c.make(block, (block.author() + 1 + r.uintLessThan(usize, n_auth - 1)) % n_auth)).bytes),
            }
        }
    }

    /// A block that breaks one verifier rule, signed by its author (or authority 0 when the
    /// author index is out of range).
    fn addRuleDefect(c: *BlockCorpus, shape: Shape, defect: Defect) !void {
        const block = try c.randomBlock(shape, defect);
        const signer = if (block.author() < n_auth) block.author() else 0;
        try c.add(.defect, (try c.make(block, signer)).bytes);
    }

    /// Non-canonical ULEB128 forms of `v` (< 128): padded with zero groups, and 5-byte forms
    /// that overflow a u32.
    fn nonCanonicalUlebs(v: u8) [5][]const u8 {
        const S = struct {
            var b: [5][5]u8 = undefined;
        };
        S.b[0] = .{ v | 0x80, 0x00, 0, 0, 0 };
        S.b[1] = .{ v | 0x80, 0x80, 0x00, 0, 0 };
        S.b[2] = .{ v | 0x80, 0x80, 0x80, 0x80, 0x00 };
        S.b[3] = .{ v | 0x80, 0x80, 0x80, 0x80, 0x10 };
        S.b[4] = .{ 0xff, 0xff, 0xff, 0xff, 0x1f };
        return .{ S.b[0][0..2], S.b[1][0..3], S.b[2][0..5], S.b[3][0..5], S.b[4][0..5] };
    }

    /// Every ULEB128 of a valid block's encoding that is easy to locate (variant tag, ancestor
    /// count, transaction count, first transaction length when short, signature length), each
    /// replaced by its non-canonical forms. The values and all other bytes stay the same.
    fn addNonCanonical(c: *BlockCorpus, m: *const Made) !void {
        const anc_at: usize = 1 + 8 + 4 + 4 + 8;
        const txs_at = anc_at + 1 + m.block.ancestors().len * 40;
        var sites: [5]usize = undefined;
        var n: usize = 0;
        for ([_]usize{ 0, anc_at, txs_at, m.bytes.len - 65 }) |s| {
            sites[n] = s;
            n += 1;
        }
        const txs = m.block.transactions();
        if (txs.len > 0 and txs.len < 128 and txs[0].data.len < 128) {
            sites[n] = txs_at + 1;
            n += 1;
        }
        for (sites[0..n]) |at| {
            const v = m.bytes[at];
            std.debug.assert(v < 0x80);
            for (nonCanonicalUlebs(v)) |form| try c.add(.non_canonical, try c.splice(m.bytes, at, 1, form));
        }
    }

    /// The whole corpus: light and full blocks, every prefix length modulo the Blake2b block,
    /// damaged copies, rule violations and non-canonical encodings.
    fn fill(c: *BlockCorpus, n_light: usize, n_full: usize) !void {
        for (0..n_light) |_| try c.addValid(.light, 10);
        for (0..n_full) |_| try c.addValid(.full, 10);
        for (0..300) |len| try c.addValid(.{ .one_tx = len }, 0);
        inline for (comptime std.enums.values(Defect)) |d| {
            if (d != .none) {
                for (0..6) |_| try c.addRuleDefect(.light, d);
                try c.addRuleDefect(if (d == .too_many_txs) .light else .full, d);
            }
        }
        const n_made = c.made.items.len;
        for (c.made.items[0..@min(n_made, 24)]) |*m| try c.addNonCanonical(m);
        try c.addNonCanonical(&c.made.items[n_light]); // a full block
    }
};

/// What the tests saw, so a corpus that stopped reaching a case fails instead of passing empty.
const CorpusCoverage = struct {
    ok: usize = 0,
    decoded: usize = 0,
    malformed: usize = 0,
    rejects: std.EnumSet(std.meta.Tag(err.BlockReject)) = .empty,
    prefix_mod: std.StaticBitSet(128) = .empty,

    fn check(cov: *const CorpusCoverage) !void {
        try std.testing.expect(cov.ok >= 300);
        try std.testing.expect(cov.decoded > cov.ok + 100);
        try std.testing.expect(cov.malformed >= 100);
        for ([_]std.meta.Tag(err.BlockReject){ .wrong_epoch, .genesis_block, .invalid_authority_index, .malformed_signature, .signature_verification_failure, .insufficient_parent_stake, .invalid_ancestor_round, .duplicated_ancestors_authority, .too_many_transactions, .malformed_block, .unexpected_block_version }) |t| {
            if (!cov.rejects.contains(t)) {
                std.debug.print("corpus never produced reject {s}\n", .{@tagName(t)});
                return error.TestUnexpectedResult;
            }
        }
        // every position of the prefix end inside a 128-byte Blake2b block
        try std.testing.expectEqual(@as(usize, 128), cov.prefix_mod.count());
    }
};

test "one-pass block digests: prefix claim and forked state equal the two-pass digests" {
    const gpa = std.testing.allocator;
    const c = try BlockCorpus.init(gpa, 0x12b1);
    defer c.deinit();
    try c.fill(120, 5);

    var noop: NoopTransactionVerifier = .{};
    const v = SignedBlockVerifier.init(c.fx.context, noop.verifier(), c.fx.genesisRefs());
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    var votes: [256]types.TransactionIndex = undefined;
    var cov: CorpusCoverage = .{};

    for (c.inputs.items) |in| {
        _ = scratch.reset(.retain_capacity);
        const a = scratch.allocator();
        var out: types.VerifiedBlock = undefined;
        var nv: usize = 0;
        const verdict = try v.verifyAndVote(a, in.bytes, &out, &votes, &nv);
        switch (verdict) {
            .ok => cov.ok += 1,
            .reject => |r| cov.rejects.insert(r),
        }
        try std.testing.expectEqual(in.kind == .valid, verdict == .ok);

        const sb = digest_mod.decodeSignedBlock(a, in.bytes) catch |e| {
            // Not a BCS SignedBlock: rejected before any hashing.
            try std.testing.expectEqual(error.SerializationFailure, e);
            try std.testing.expect(verdict == .reject and verdict.reject == .malformed_block);
            cov.malformed += 1;
            continue;
        };
        // A non-canonical encoding never decodes (bcs 0.1.6 rules), so the prefix claim below
        // covers every block the verifier hashes.
        try std.testing.expect(in.kind != .non_canonical);
        cov.decoded += 1;

        // Layout: BCS(Block) ++ ULEB128(signature length) ++ signature, the signature borrowed
        // from the end of the input.
        const tail = bcs.ulebLen(@intCast(sb.signature.len)) + sb.signature.len;
        try std.testing.expect(in.bytes.len >= tail);
        const inner_len = in.bytes.len - tail;
        try std.testing.expectEqual(@intFromPtr(in.bytes.ptr) + in.bytes.len, @intFromPtr(sb.signature.ptr) + sb.signature.len);
        try std.testing.expectEqual(inner_len, bcs.encodedLen(types.Block, &sb.inner));
        const re = try bcs.encodeAlloc(types.Block, a, &sb.inner);
        try std.testing.expectEqualSlices(u8, re, in.bytes[0..inner_len]);
        cov.prefix_mod.set(inner_len % 128);

        // Two passes (today) against one pass with the state forked at the prefix end.
        const two_inner = try digest_mod.innerBlockDigest(a, &sb.inner);
        const two_block = digest_mod.blockDigest(in.bytes);
        const one = onePassReference(in.bytes, inner_len);
        try std.testing.expectEqualSlices(u8, &two_inner, &one[0]);
        try std.testing.expectEqualSlices(u8, &two_block, &one[1]);
        if (verdict == .ok) try std.testing.expectEqualSlices(u8, &two_block, &out.digest);

        // digest.zig's one-pass code: same prefix end, same digests.
        try std.testing.expectEqual(@as(?usize, inner_len), digest_mod.innerLen(&sb, in.bytes));
        const d = digest_mod.blockDigestsAt(in.bytes, inner_len);
        try std.testing.expectEqualSlices(u8, &two_inner, &d.inner);
        try std.testing.expectEqualSlices(u8, &two_block, &d.block);
    }
    try cov.check();
}

/// Everything `verifyAndVote` or `verifyForCommitSync` gives back for one input.
const Outcome = struct {
    failed: ?err.Error = null,
    verdict: err.BlockVerdict = .ok,
    rejects: usize = 0,
    digest: types.BlockDigest = @splat(0),
    block: []const u8 = "",

    fn run(v: *const SignedBlockVerifier, a: Allocator, bytes: []const u8, commit_sync: bool) Outcome {
        var out: types.VerifiedBlock = undefined;
        var votes: [256]types.TransactionIndex = undefined;
        var nv: usize = 0;
        const verdict = (if (commit_sync) v.verifyForCommitSync(a, bytes, &out) else v.verifyAndVote(a, bytes, &out, &votes, &nv)) catch |e| return .{ .failed = e };
        if (verdict != .ok) return .{ .verdict = verdict, .rejects = nv };
        std.debug.assert(out.serialized.ptr == bytes.ptr and out.serialized.len == bytes.len);
        const re = digest_mod.serializeSignedBlock(a, &out.block) catch |e| return .{ .failed = e };
        return .{ .verdict = verdict, .rejects = nv, .digest = out.digest, .block = re };
    }

    fn expectEqual(want: *const Outcome, got: *const Outcome) !void {
        try std.testing.expectEqual(want.failed, got.failed);
        try std.testing.expect(std.meta.eql(want.verdict, got.verdict));
        try std.testing.expectEqual(want.rejects, got.rejects);
        try std.testing.expectEqualSlices(u8, &want.digest, &got.digest);
        try std.testing.expectEqualSlices(u8, want.block, got.block);
    }
};

test "one-pass block digests: verifier verdicts and digests equal the two-pass path" {
    const gpa = std.testing.allocator;
    const c = try BlockCorpus.init(gpa, 0x12b2);
    defer c.deinit();
    try c.fill(120, 5);

    var noop: NoopTransactionVerifier = .{};
    const v = SignedBlockVerifier.init(c.fx.context, noop.verifier(), c.fx.genesisRefs());
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    var cov: CorpusCoverage = .{};
    const was = digest_mod.onePass();
    defer digest_mod.setOnePass(was);

    for (c.inputs.items) |in| {
        inline for (.{ false, true }) |commit_sync| {
            _ = scratch.reset(.retain_capacity);
            const a = scratch.allocator();
            digest_mod.setOnePass(false);
            const two = Outcome.run(&v, a, in.bytes, commit_sync);
            digest_mod.setOnePass(true);
            const one = Outcome.run(&v, a, in.bytes, commit_sync);
            try two.expectEqual(&one);
            try std.testing.expectEqual(in.kind == .valid, one.verdict == .ok);
            if (!commit_sync) switch (one.verdict) {
                .ok => cov.ok += 1,
                .reject => |r| cov.rejects.insert(r),
            };
        }
    }
    try std.testing.expect(cov.ok >= 300);
    try std.testing.expect(cov.rejects.count() >= 11);
}

test "one-pass block digests: a signature that is not the end of the bytes takes the two-pass path" {
    const gpa = std.testing.allocator;
    const c = try BlockCorpus.init(gpa, 0x12b3);
    defer c.deinit();
    try c.addValid(.light, 0);
    try c.addValid(.light, 0);
    const a = c.arena_state.allocator();
    const m = &c.made.items[0];
    const sb = try digest_mod.decodeSignedBlock(a, m.bytes);
    try std.testing.expectEqual(@as(?usize, m.bytes.len - 65), digest_mod.innerLen(&sb, m.bytes));

    // The same block with its signature held elsewhere (as a proposer has it before serializing).
    const apart: types.SignedBlock = .{ .inner = sb.inner, .signature = &m.signature };
    try std.testing.expectEqual(@as(?usize, null), digest_mod.innerLen(&apart, m.bytes));
    // Bytes of another block: the inner block's length does not fit in front of the signature.
    const other = c.made.items[1].bytes;
    const grafted: types.SignedBlock = .{ .inner = sb.inner, .signature = other[other.len - 64 ..] };
    if (other.len != m.bytes.len) try std.testing.expectEqual(@as(?usize, null), digest_mod.innerLen(&grafted, other));
    // An empty signature that is not borrowed from the bytes (genesis blocks, `verifiedForTest`).
    const g = try digest_mod.verifiedForTest(a, sb.inner);
    try std.testing.expectEqual(@as(?usize, null), digest_mod.innerLen(&g.block, g.serialized));
    const g2 = try digest_mod.decodeSignedBlock(a, g.serialized);
    try std.testing.expectEqual(@as(?usize, g.serialized.len - 1), digest_mod.innerLen(&g2, g.serialized));
    const d = digest_mod.blockDigestsAt(g.serialized, g.serialized.len - 1);
    try std.testing.expectEqualSlices(u8, &g.digest, &d.block);
    try std.testing.expectEqualSlices(u8, &(try digest_mod.innerBlockDigest(gpa, &sb.inner)), &d.inner);
}

test "one-pass block digests: created blocks equal the two-pass bytes, signature and digest" {
    const gpa = std.testing.allocator;
    const c = try BlockCorpus.init(gpa, 0x12b4);
    defer c.deinit();
    for (0..120) |_| try c.addValid(.light, 0);
    for (0..5) |_| try c.addValid(.full, 0);
    for (0..300) |len| try c.addValid(.{ .one_tx = len }, 0);

    var noop: NoopTransactionVerifier = .{};
    const v = SignedBlockVerifier.init(c.fx.context, noop.verifier(), c.fx.genesisRefs());
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const was = digest_mod.onePass();
    defer digest_mod.setOnePass(was);

    for (c.made.items) |*m| {
        _ = scratch.reset(.retain_capacity);
        const a = scratch.allocator();
        // `m` was signed and serialized by the calls Core.tryNewBlock made before PendingBlock.
        const want_msg = try digest_mod.blockSigningMessage(gpa, &m.block);
        const want_digest = digest_mod.blockDigest(m.bytes);
        inline for (.{ false, true }) |on| {
            digest_mod.setOnePass(on);
            const pending = try digest_mod.PendingBlock.init(a, gpa, m.block);
            try std.testing.expectEqual(on, pending.one != null);
            try std.testing.expectEqualSlices(u8, &want_msg, &pending.message);
            const signature = c.keys[m.signer].sign(&pending.message);
            try std.testing.expectEqualSlices(u8, &m.signature, &signature);
            const vb = try pending.seal(a, &signature);
            try std.testing.expectEqualSlices(u8, m.bytes, vb.serialized);
            try std.testing.expectEqualSlices(u8, &want_digest, &vb.digest);
            try std.testing.expectEqualSlices(u8, &m.signature, vb.block.signature);
            try std.testing.expectEqualSlices(u8, m.bytes, try digest_mod.serializeSignedBlock(a, &vb.block));
            // and a peer accepts it with the same digest, on either verify path
            inline for (.{ false, true }) |verify_on| {
                digest_mod.setOnePass(verify_on);
                const got = Outcome.run(&v, a, vb.serialized, false);
                try std.testing.expect(got.failed == null and got.verdict == .ok);
                try std.testing.expectEqualSlices(u8, &want_digest, &got.digest);
            }
        }
    }
}

// Local microbench of the two paths, off unless ZUI_BLOCK_HASH_BENCH=1:
//   ZUI_BLOCK_HASH_BENCH=1 ./zig build test -Dlane=consensus -Doptimize=fast
// Per block, as the val-bench block stage times it: a fresh arena, then verifyAndVote, or
// PendingBlock.init + Ed25519 sign + seal. The switch alternates every round so both paths see
// the same machine state. Prints p50 and mean per block.
test "one-pass block digests: microbench (ZUI_BLOCK_HASH_BENCH=1)" {
    if (std.c.getenv("ZUI_BLOCK_HASH_BENCH") == null) return;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const c = try BlockCorpus.init(gpa, 0x12b5);
    defer c.deinit();
    const n_light = 400;
    const n_full = 40;
    for (0..n_light) |_| try c.addValid(.light, 0);
    for (0..n_full) |_| try c.addValid(.full, 0);

    var noop: NoopTransactionVerifier = .{};
    const v = SignedBlockVerifier.init(c.fx.context, noop.verifier(), c.fx.genesisRefs());
    const was = digest_mod.onePass();
    defer digest_mod.setOnePass(was);
    const backing = std.heap.c_allocator;
    const rounds = 15;

    const Bench = struct {
        fn nowNs(i: std.Io) u64 {
            return @intCast(std.Io.Timestamp.now(i, .awake).nanoseconds);
        }
        fn report(name: []const u8, mode: []const u8, samples: []u64) void {
            std.mem.sort(u64, samples, {}, std.sort.asc(u64));
            var sum: u64 = 0;
            for (samples) |x| sum += x;
            const p50 = samples[samples.len / 2];
            std.debug.print("block-hash bench {s:<13} {s:<8} p50 {d:>8.1} us  mean {d:>8.1} us  ({d} samples)\n", .{ name, mode, @as(f64, @floatFromInt(p50)) / 1000.0, @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(samples.len)) / 1000.0, samples.len });
        }
    };

    inline for (.{ .{ "light", 0, n_light }, .{ "full", n_light, n_full } }) |case| {
        const blocks = c.made.items[case[1]..][0..case[2]];
        var bytes_total: usize = 0;
        for (blocks) |*m| bytes_total += m.bytes.len;
        std.debug.print("block-hash bench {s}: {d} blocks, {d} bytes mean, committee {d}\n", .{ case[0], blocks.len, bytes_total / blocks.len, BlockCorpus.n_auth });
        var samples: [2][2][]u64 = undefined; // [verify, create][two-pass, one-pass]
        for (&samples) |*op| for (op) |*s| {
            s.* = try gpa.alloc(u64, blocks.len * rounds);
        };
        defer for (&samples) |*op| for (op) |s| gpa.free(s);
        var sink: u8 = 0;
        for (0..rounds + 1) |round| {
            inline for (.{ false, true }) |on| {
                digest_mod.setOnePass(on);
                for (blocks, 0..) |*m, i| {
                    {
                        var arena: std.heap.ArenaAllocator = .init(backing);
                        defer arena.deinit();
                        var votes: [256]types.TransactionIndex = undefined;
                        var nv: usize = 0;
                        var out: types.VerifiedBlock = undefined;
                        const t0 = Bench.nowNs(io);
                        const verdict = try v.verifyAndVote(arena.allocator(), m.bytes, &out, &votes, &nv);
                        const dt = Bench.nowNs(io) - t0;
                        try std.testing.expect(verdict == .ok);
                        sink ^= out.digest[0];
                        // round 0 warms up
                        if (round > 0) samples[0][@intFromBool(on)][(round - 1) * blocks.len + i] = dt;
                    }
                    {
                        var arena: std.heap.ArenaAllocator = .init(backing);
                        defer arena.deinit();
                        const a = arena.allocator();
                        const t0 = Bench.nowNs(io);
                        const pending = try digest_mod.PendingBlock.init(a, a, m.block);
                        const signature = c.keys[m.signer].sign(&pending.message);
                        const vb = try pending.seal(a, &signature);
                        const dt = Bench.nowNs(io) - t0;
                        try std.testing.expectEqualSlices(u8, m.bytes, vb.serialized);
                        sink ^= vb.digest[0];
                        if (round > 0) samples[1][@intFromBool(on)][(round - 1) * blocks.len + i] = dt;
                    }
                }
            }
        }
        std.mem.doNotOptimizeAway(sink);
        inline for (.{ "verify", "create" }, 0..) |op, k| {
            Bench.report(op ++ "-" ++ case[0], "two-pass", samples[k][0]);
            Bench.report(op ++ "-" ++ case[0], "one-pass", samples[k][1]);
        }
    }
}
