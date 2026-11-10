//! What validators put into consensus blocks, at mainnet-v1.83.1
//! (`crates/sui-types/src/messages_consensus.rs`, `messages_checkpoint.rs`, `transaction.rs`,
//! `supported_protocol_versions.rs`, `transaction_deny_rules.rs`). Each consensus
//! `Transaction.data` is BCS(ConsensusTransaction). Field and variant order are serde's, so
//! `bcs.decode`/`bcs.encode` give Rust's bytes. validator-base owns this file; lanes extend it
//! only through the design doc (docs/VALIDATOR-DESIGN.md 4.2).
//!
//! Not in the sui-format registry snapshot that generates src/types/gen.zig, so declared here.
//! Truth: tools/truth/consensus/ captures ConsensusTransactions from a Mysten localnet's
//! consensus store (suite consensus-messages, planned).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");

/// sui_types::base_types::AuthorityName = AuthorityPublicKeyBytes (96-byte BLS12-381 G2 key).
pub const AuthorityName = types.AuthorityPublicKeyBytes;
/// sui_types::base_types::ObjectRef
pub const ObjectRef = struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest };

/// sui_types::crypto::AuthoritySignInfo (one validator's BLS signature, 48 bytes, no length
/// prefix: fastcrypto's SerializationHelper<48>).
pub const AuthoritySignInfo = struct {
    epoch: u64,
    authority: AuthorityName,
    signature: [48]u8,
};

/// Envelope<CheckpointSummary, AuthoritySignInfo>: serialized as (data, auth_signature).
pub const SignedCheckpointSummary = struct {
    data: types.CheckpointSummary,
    auth_signature: AuthoritySignInfo,
};

/// sui_types::messages_checkpoint::CheckpointSignatureMessage
pub const CheckpointSignatureMessage = struct {
    summary: SignedCheckpointSummary,
};

/// Envelope<SenderSignedData, AuthorityStrongQuorumSignInfo> (deprecated kind, still decodable).
pub const CertifiedTransaction = struct {
    data: types.SenderSignedData,
    auth_signature: types.AuthorityQuorumSignInfo,
};

/// Envelope<SenderSignedData, EmptySignInfo>: EmptySignInfo is an empty struct (zero bytes).
pub const Transaction = struct {
    data: types.SenderSignedData,
    auth_signature: struct {},
};

pub const AliasEntryV1 = struct { types.SuiAddress, ?types.SequenceNumber };
pub const AliasEntryV2 = struct { u8, ?types.SequenceNumber };

/// sui_types::transaction::TransactionClaim
pub const TransactionClaim = union(enum) {
    /// Deprecated. NonEmpty serialized as a Vec (must be non-empty).
    AddressAliases: []const AliasEntryV1,
    ImmutableInputObjects: []const types.ObjectID,
    /// One entry per required signer: (signature index, alias object version). NonEmpty.
    AddressAliasesV2: []const AliasEntryV2,

    /// The same wire shape without the hooks. The alias lists are `nonempty::NonEmpty` in Rust:
    /// an empty one fails to deserialize, which rejects the whole block in `verify_batch`.
    const Wire = union(enum) {
        AddressAliases: []const AliasEntryV1,
        ImmutableInputObjects: []const types.ObjectID,
        AddressAliasesV2: []const AliasEntryV2,
    };
    pub const bcs_min_wire = 1;

    fn fromWire(w: Wire) TransactionClaim {
        return switch (w) {
            .AddressAliases => |x| .{ .AddressAliases = x },
            .ImmutableInputObjects => |x| .{ .ImmutableInputObjects = x },
            .AddressAliasesV2 => |x| .{ .AddressAliasesV2 = x },
        };
    }
    fn toWire(c: TransactionClaim) Wire {
        return switch (c) {
            .AddressAliases => |x| .{ .AddressAliases = x },
            .ImmutableInputObjects => |x| .{ .ImmutableInputObjects = x },
            .AddressAliasesV2 => |x| .{ .AddressAliasesV2 = x },
        };
    }
    pub fn bcsDecode(arena: std.mem.Allocator, r: *bcs.Reader) bcs.DecodeError!TransactionClaim {
        const w = try bcs.decodeFrom(Wire, arena, r);
        switch (w) {
            .AddressAliases => |x| if (x.len == 0) return error.InvalidValue,
            .AddressAliasesV2 => |x| if (x.len == 0) return error.InvalidValue,
            .ImmutableInputObjects => {},
        }
        return fromWire(w);
    }
    pub fn bcsSkip(r: *bcs.Reader) bcs.Error!void {
        var peek = r.*;
        try bcs.skip(Wire, r);
        const tag = try peek.uleb32();
        if (tag != 1 and try peek.length() == 0) return error.InvalidValue;
    }
    pub fn bcsEncode(self: *const TransactionClaim, w: anytype) bcs.EncodeError!void {
        const x = toWire(self.*);
        try bcs.encode(Wire, &x, w);
    }
    pub fn bcsTree(self: *const TransactionClaim, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const x = toWire(self.*);
        try bcs.tree.render(Wire, &x, w);
    }
};

/// sui_types::transaction::PlainTransactionWithClaims = TransactionWithClaims<Transaction>
pub const PlainTransactionWithClaims = struct {
    tx: Transaction,
    claims: []const TransactionClaim,
};

/// sui_types::supported_protocol_versions::SupportedProtocolVersions
pub const SupportedProtocolVersions = struct {
    min: types.ProtocolVersion,
    max: types.ProtocolVersion,
};

/// SupportedProtocolVersionsWithHashes { versions: Vec<(ProtocolVersion, Digest)> }
pub const SupportedProtocolVersionsWithHashes = struct {
    versions: []const struct { types.ProtocolVersion, types.Digest },
};

/// AuthorityCapabilitiesV1 (deprecated kind, still decodable).
pub const AuthorityCapabilitiesV1 = struct {
    authority: AuthorityName,
    generation: u64,
    supported_protocol_versions: SupportedProtocolVersions,
    available_system_packages: []const ObjectRef,
};

/// AuthorityCapabilitiesV2: protocol-upgrade votes (val-epoch-api-keys).
pub const AuthorityCapabilitiesV2 = struct {
    authority: AuthorityName,
    generation: u64,
    supported_protocol_versions: SupportedProtocolVersionsWithHashes,
    available_system_packages: []const ObjectRef,
};

/// ExecutionTimeObservation (congestion control estimates, val-authority).
pub const ExecutionTimeObservation = struct {
    authority: AuthorityName,
    generation: u64,
    estimates: []const struct { types.ExecutionTimeObservationKey, types.Duration },
};

/// sui_types::transaction_deny_rules::TransactionDenyRules (BTreeSets are sorted sequences).
pub const TransactionDenyRules = struct {
    object_deny_list: []const types.ObjectID,
    package_deny_list: []const types.ObjectID,
    address_deny_list: []const types.SuiAddress,
    package_publish_disabled: bool,
    package_upgrade_disabled: bool,
    shared_object_disabled: bool,
    user_transaction_disabled: bool,
    gasless_disabled: bool,
    receiving_objects_disabled: bool,
    zklogin_sig_disabled: bool,
    zklogin_disabled_providers: []const bcs.String,
};

pub const SharedTransactionDenyConfigV1 = struct {
    authority: AuthorityName,
    generation: u64,
    rules: ?TransactionDenyRules,
};

pub const SharedTransactionDenyConfig = union(enum) {
    V1: SharedTransactionDenyConfigV1,
};

/// sui_types::messages_consensus::ConsensusTransactionKind, variant order as in Rust.
pub const ConsensusTransactionKind = union(enum) {
    CertifiedTransaction: CertifiedTransaction,
    CheckpointSignature: CheckpointSignatureMessage,
    EndOfPublish: AuthorityName,
    CapabilityNotification: AuthorityCapabilitiesV1,
    NewJWKFetched: struct { AuthorityName, types.JwkId, types.JWK },
    RandomnessStateUpdate: struct { u64, []const u8 },
    /// Serialized VersionedDkgMessage (fastcrypto_tbls::dkg_v1::Message).
    RandomnessDkgMessage: struct { AuthorityName, []const u8 },
    /// Serialized VersionedDkgConfirmation.
    RandomnessDkgConfirmation: struct { AuthorityName, []const u8 },
    CapabilityNotificationV2: AuthorityCapabilitiesV2,
    UserTransaction: Transaction,
    ExecutionTimeObservation: ExecutionTimeObservation,
    CheckpointSignatureV2: CheckpointSignatureMessage,
    UserTransactionV2: PlainTransactionWithClaims,
    UpdateTransactionDenyConfig: SharedTransactionDenyConfig,
};

/// sui_types::messages_consensus::ConsensusTransaction
pub const ConsensusTransaction = struct {
    tracking_id: [8]u8,
    kind: ConsensusTransactionKind,
};

/// ConsensusTransactionKey: dedup key of a consensus transaction (not serialized on the wire,
/// but stored in the epoch store as processed keys).
pub const ConsensusTransactionKey = union(enum) {
    Certificate: types.TransactionDigest,
    CheckpointSignature: struct { AuthorityName, u64 },
    EndOfPublish: AuthorityName,
    CapabilityNotification: struct { AuthorityName, u64 },
    NewJWKFetched: struct { AuthorityName, types.JwkId, types.JWK },
    RandomnessDkgMessage: AuthorityName,
    RandomnessDkgConfirmation: AuthorityName,
    ExecutionTimeObservation: struct { AuthorityName, u64 },
    CheckpointSignatureV2: struct { AuthorityName, u64, types.CheckpointDigest },
    RandomnessStateUpdate: void,
    UpdateTransactionDenyConfig: struct { AuthorityName, u64 },
};

/// MAX_TOTAL_JWK_SIZE (messages_consensus.rs): iss+kid+kty+alg+e+n byte lengths.
pub const max_total_jwk_size = 4096;

test "decode an EndOfPublish consensus transaction" {
    // AuthorityName is AuthorityPublicKeyBytes, serialized with serde_as Bytes: a ULEB length
    // (96 = 0x60) precedes the key.
    var buf: [8 + 1 + 1 + 96]u8 = undefined;
    @memset(buf[0..8], 0xab);
    buf[8] = 2; // EndOfPublish
    buf[9] = 96;
    @memset(buf[10..], 0x11);
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const tx = try bcs.decode(ConsensusTransaction, arena.allocator(), &buf);
    try std.testing.expect(tx.kind == .EndOfPublish);
}
