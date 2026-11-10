//! types: Sui + Move core types (sui-types 1.83.1, move-core-types) with BCS layouts and digests.
//! Owner lane: bcs-types. Interface: CONTRACTS.md. Only the bcs-types lane edits files in src/types/.
//!
//! Every type of the serde-reflection registry (spec/sui-format-1.83.1.yaml.snap) exists here
//! under its Rust name. They are generated (gen.zig, by tools/truth/bcs-types/gen_types.py);
//! hand.zig holds the wrappers with extra validation. The BCS codec is `bcs`.
const std = @import("std");

pub const conformance = @import("conformance.zig");
pub const hand = @import("hand.zig");
pub const gen = @import("gen.zig");
pub const digest = @import("digest.zig");
pub const index = @import("index.zig");
pub const roaring = @import("roaring.zig");
pub const layout = @import("layout.zig");

// BEGIN GENERATED EXPORTS (tools/truth/bcs-types/gen_types.py)
pub const AccountAddress = gen.AccountAddress;
pub const AccumulatorAddress = gen.AccumulatorAddress;
pub const AccumulatorOperation = gen.AccumulatorOperation;
pub const AccumulatorValue = gen.AccumulatorValue;
pub const AccumulatorWriteV1 = gen.AccumulatorWriteV1;
pub const ActiveJwk = gen.ActiveJwk;
pub const AdditionalConsensusStateDigest = gen.AdditionalConsensusStateDigest;
pub const AllowedProposers = gen.AllowedProposers;
pub const Argument = gen.Argument;
pub const AuthenticatorStateExpire = gen.AuthenticatorStateExpire;
pub const AuthenticatorStateUpdate = gen.AuthenticatorStateUpdate;
pub const AuthorityPublicKeyBytes = gen.AuthorityPublicKeyBytes;
pub const AuthorityQuorumSignInfo = gen.AuthorityQuorumSignInfo;
pub const CallArg = gen.CallArg;
pub const ChainIdentifier = gen.ChainIdentifier;
pub const ChangeEpoch = gen.ChangeEpoch;
pub const CheckpointArtifactsDigest = gen.CheckpointArtifactsDigest;
pub const CheckpointCommitment = gen.CheckpointCommitment;
pub const CheckpointContents = gen.CheckpointContents;
pub const CheckpointContentsDigest = gen.CheckpointContentsDigest;
pub const CheckpointContentsV1 = gen.CheckpointContentsV1;
pub const CheckpointContentsV2 = gen.CheckpointContentsV2;
pub const CheckpointData = gen.CheckpointData;
pub const CheckpointDigest = gen.CheckpointDigest;
pub const CheckpointSummary = gen.CheckpointSummary;
pub const CheckpointTransaction = gen.CheckpointTransaction;
pub const CheckpointTransactionContents = gen.CheckpointTransactionContents;
pub const Command = gen.Command;
pub const CommandArgumentError = gen.CommandArgumentError;
pub const CompressedSignature = gen.CompressedSignature;
pub const CongestedObjects = gen.CongestedObjects;
pub const ConsensusCommitDigest = gen.ConsensusCommitDigest;
pub const ConsensusCommitPrologue = gen.ConsensusCommitPrologue;
pub const ConsensusCommitPrologueV2 = gen.ConsensusCommitPrologueV2;
pub const ConsensusCommitPrologueV3 = gen.ConsensusCommitPrologueV3;
pub const ConsensusCommitPrologueV4 = gen.ConsensusCommitPrologueV4;
pub const ConsensusDeterminedVersionAssignments = gen.ConsensusDeterminedVersionAssignments;
pub const Data = gen.Data;
pub const DeleteKind = gen.DeleteKind;
pub const Digest = gen.Digest;
pub const Duration = gen.Duration;
pub const ECMHLiveObjectSetDigest = gen.ECMHLiveObjectSetDigest;
pub const EffectsAuxDataDigest = gen.EffectsAuxDataDigest;
pub const EffectsObjectChange = gen.EffectsObjectChange;
pub const EmptySignInfo = gen.EmptySignInfo;
pub const EndOfEpochData = gen.EndOfEpochData;
pub const EndOfEpochTransactionKind = gen.EndOfEpochTransactionKind;
pub const Event = gen.Event;
pub const ExecutionData = gen.ExecutionData;
pub const ExecutionDigests = gen.ExecutionDigests;
pub const ExecutionErrorKind = gen.ExecutionErrorKind;
pub const ExecutionFailure = gen.ExecutionFailure;
pub const ExecutionStatus = gen.ExecutionStatus;
pub const ExecutionTimeObservationKey = gen.ExecutionTimeObservationKey;
pub const FullCheckpointContents = gen.FullCheckpointContents;
pub const FundsWithdrawalArg = gen.FundsWithdrawalArg;
pub const GasCostSummary = gen.GasCostSummary;
pub const GasData = gen.GasData;
pub const GenericSignature = gen.GenericSignature;
pub const GenesisObject = gen.GenesisObject;
pub const GenesisTransaction = gen.GenesisTransaction;
pub const IDOperation = gen.IDOperation;
pub const Intent = gen.Intent;
pub const IntentMessage = gen.IntentMessage;
pub const JWK = gen.JWK;
pub const JwkId = gen.JwkId;
pub const ModuleId = gen.ModuleId;
pub const MoveLocation = gen.MoveLocation;
pub const MoveLocationOpt = gen.MoveLocationOpt;
pub const MoveObject = gen.MoveObject;
pub const MoveObjectType = gen.MoveObjectType;
pub const MoveObjectType_ = gen.MoveObjectType_;
pub const MovePackage = gen.MovePackage;
pub const MultiSig = gen.MultiSig;
pub const MultiSigPublicKey = gen.MultiSigPublicKey;
pub const Object = gen.Object;
pub const ObjectArg = gen.ObjectArg;
pub const ObjectDigest = gen.ObjectDigest;
pub const ObjectID = gen.ObjectID;
pub const ObjectIn = gen.ObjectIn;
pub const ObjectInfoRequestKind = gen.ObjectInfoRequestKind;
pub const ObjectOut = gen.ObjectOut;
pub const Owner = gen.Owner;
pub const PackageUpgradeError = gen.PackageUpgradeError;
pub const ProgrammableMoveCall = gen.ProgrammableMoveCall;
pub const ProgrammableTransaction = gen.ProgrammableTransaction;
pub const ProtocolVersion = gen.ProtocolVersion;
pub const PublicKey = gen.PublicKey;
pub const RandomnessRound = gen.RandomnessRound;
pub const RandomnessStateUpdate = gen.RandomnessStateUpdate;
pub const RawPartySerde = gen.RawPartySerde;
pub const Reservation = gen.Reservation;
pub const SenderSignedData = gen.SenderSignedData;
pub const SenderSignedTransaction = gen.SenderSignedTransaction;
pub const SequenceNumber = gen.SequenceNumber;
pub const SharedObjectMutability = gen.SharedObjectMutability;
pub const StoredExecutionTimeObservations = gen.StoredExecutionTimeObservations;
pub const StructInput = gen.StructInput;
pub const StructTag = gen.StructTag;
pub const SuiAddress = gen.SuiAddress;
pub const TransactionData = gen.TransactionData;
pub const TransactionDataV1 = gen.TransactionDataV1;
pub const TransactionDigest = gen.TransactionDigest;
pub const TransactionEffects = gen.TransactionEffects;
pub const TransactionEffectsDigest = gen.TransactionEffectsDigest;
pub const TransactionEffectsV1 = gen.TransactionEffectsV1;
pub const TransactionEffectsV2 = gen.TransactionEffectsV2;
pub const TransactionEvents = gen.TransactionEvents;
pub const TransactionEventsDigest = gen.TransactionEventsDigest;
pub const TransactionExpiration = gen.TransactionExpiration;
pub const TransactionKind = gen.TransactionKind;
pub const TypeArgumentError = gen.TypeArgumentError;
pub const TypeInput = gen.TypeInput;
pub const TypeOrigin = gen.TypeOrigin;
pub const TypeTag = gen.TypeTag;
pub const UnchangedConsensusKind = gen.UnchangedConsensusKind;
pub const UpgradeInfo = gen.UpgradeInfo;
pub const WithdrawFrom = gen.WithdrawFrom;
pub const WithdrawalTypeArg = gen.WithdrawalTypeArg;
pub const WriteAccumulatorStorageCost = gen.WriteAccumulatorStorageCost;
pub const ZkLoginAuthenticatorAsBytes = gen.ZkLoginAuthenticatorAsBytes;
pub const ZkLoginPublicIdentifier = gen.ZkLoginPublicIdentifier;
// END GENERATED EXPORTS

pub const Identifier = hand.Identifier;
pub const Envelope = hand.Envelope;
pub const IntentScope = hand.IntentScope;
pub const IntentVersion = hand.IntentVersion;
pub const AppId = hand.AppId;

pub const digestOf = digest.digestOf;
pub const intentMessageDigest = digest.intentMessageDigest;
pub const CheckpointIndex = index.CheckpointIndex;
pub const indexCheckpointData = index.indexCheckpointData;

pub const mainnet_chain_id = "35834a8a";

test {
    std.testing.refAllDecls(@This());
}

test {
    _ = @import("edge_test.zig");
    _ = @import("variants_test.zig");
    _ = @import("layout.zig");
}

test "random values of every registry type round trip, skip and render" {
    @setEvalBranchQuota(1_000_000);
    const rt = @import("roundtrip_test.zig");
    inline for (gen.registry) |e| try rt.run(e[1], e[0]);
}
