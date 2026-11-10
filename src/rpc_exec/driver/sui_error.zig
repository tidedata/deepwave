//! `SuiError` as validators send it (sui-types `error.rs`, mainnet-v1.83.1): the BCS shape of
//! `SuiErrorKind` and `UserInputError` variant for variant (decoded by `bcs` reflection), their
//! `Display` (thiserror templates) and derived `Debug` texts, `categorize`, `is_retryable`, and
//! `From<tonic::Status> for SuiError`. A rejected transaction carries one of these BCS-encoded in
//! `RawRejectedStatus.error` or in a gRPC status' details, and its text reaches the client in the
//! driver's aggregated error message, so the texts must equal Rust's.
//!
//! Known gaps (no validator sends them on the submission path): `SuiObjectResponseError` is an
//! internally tagged serde enum that BCS cannot deserialize (Rust fails too: decoding it is
//! `error.Unsupported` here); `Owner::Party` and `Committee` Debug print a placeholder; Rust's
//! `escape_debug` escapes non-printable non-ASCII characters as `\u{..}`, deepwave only escapes ASCII
//! controls.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const bcs = @import("bcs");
const types = @import("types");
const serve = @import("serve");
const b58 = serve.b58;

pub const ObjectID = types.ObjectID;
pub const SeqNum = types.SequenceNumber;
pub const ObjectDigest = types.ObjectDigest;
pub const TxDigest = types.TransactionDigest;
pub const EffDigest = types.TransactionEffectsDigest;
pub const ContentsDigest = types.CheckpointContentsDigest;
pub const Owner = types.Owner;
pub const SuiAddress = types.SuiAddress;
pub const AuthorityName = types.AuthorityPublicKeyBytes;
pub const Str = bcs.String;
/// Rust `ObjectRef = (ObjectID, SequenceNumber, ObjectDigest)`.
pub const ObjectRef = struct { ObjectID, SeqNum, ObjectDigest };

/// sui-types `ErrorCategory`, in Rust order.
pub const ErrorCategory = enum(u8) {
    Aborted,
    InvalidTransaction,
    LockConflict,
    Internal,
    ValidatorOverloaded,
    Unavailable,

    /// `ErrorCategory::is_submission_retriable`.
    pub fn isSubmissionRetriable(c: ErrorCategory) bool {
        return switch (c) {
            .Aborted, .ValidatorOverloaded, .Unavailable => true,
            else => false,
        };
    }

    /// `Into<&str>` (strum IntoStaticStr): the variant name.
    pub fn name(c: ErrorCategory) []const u8 {
        return @tagName(c);
    }
};

/// sui-types `Committee` as serde writes it: `expanded_keys` and `index_map` are HashMaps, so
/// their entries come in any order (Rust's own BCS decoder rejects most multi-entry committees
/// as non-canonical maps); deepwave reads them as plain pair lists.
pub const Committee = struct {
    epoch: u64,
    voting_rights: []const struct { AuthorityName, u64 },
    /// The BLS key (fastcrypto) is 96 raw bytes, without a length prefix.
    expanded_keys: []const struct { AuthorityName, [96]u8 },
    index_map: []const struct { AuthorityName, u64 },
};

pub const UserInputError = union(enum) {
    MutableObjectUsedMoreThanOnce: struct { object_id: ObjectID, pub const bcs_no_depth = true; },
    ObjectInputArityViolation: void,
    ObjectNotFound: struct { object_id: ObjectID, version: ?SeqNum, pub const bcs_no_depth = true; },
    ObjectVersionUnavailableForConsumption: struct { provided_obj_ref: ObjectRef, current_version: SeqNum, pub const bcs_no_depth = true; },
    PackageVerificationTimeout: struct { err: Str, pub const bcs_no_depth = true; },
    DependentPackageNotFound: struct { package_id: ObjectID, pub const bcs_no_depth = true; },
    ImmutableParameterExpectedError: struct { object_id: ObjectID, pub const bcs_no_depth = true; },
    SizeLimitExceeded: struct { limit: Str, value: Str, pub const bcs_no_depth = true; },
    InvalidChildObjectArgument: struct { child_id: ObjectID, parent_id: ObjectID, pub const bcs_no_depth = true; },
    InvalidObjectDigest: struct { object_id: ObjectID, expected_digest: ObjectDigest, pub const bcs_no_depth = true; },
    InvalidSequenceNumber: void,
    MovePackageAsObject: struct { object_id: ObjectID, pub const bcs_no_depth = true; },
    MoveObjectAsPackage: struct { object_id: ObjectID, pub const bcs_no_depth = true; },
    IncorrectUserSignature: struct { @"error": Str, pub const bcs_no_depth = true; },
    NotSharedObjectError: void,
    DuplicateObjectRefInput: void,
    MissingGasPayment: void,
    GasObjectNotOwnedObject: struct { owner: Owner, pub const bcs_no_depth = true; },
    GasBudgetTooHigh: struct { gas_budget: u64, max_budget: u64, pub const bcs_no_depth = true; },
    GasBudgetTooLow: struct { gas_budget: u64, min_budget: u64, pub const bcs_no_depth = true; },
    GasBalanceTooLow: struct { gas_balance: u128, needed_gas_amount: u128, pub const bcs_no_depth = true; },
    UnsupportedSponsoredTransactionKind: void,
    GasPriceUnderRGP: struct { gas_price: u64, reference_gas_price: u64, pub const bcs_no_depth = true; },
    GasPriceTooHigh: struct { max_gas_price: u64, pub const bcs_no_depth = true; },
    InvalidGasObject: struct { object_id: ObjectID, pub const bcs_no_depth = true; },
    InsufficientBalanceToCoverMinimalGas: void,
    ObjectSequenceNumberTooHigh: struct { object_id: ObjectID, asked_version: SeqNum, latest_version: SeqNum, pub const bcs_no_depth = true; },
    ObjectDeleted: struct { object_ref: ObjectRef, pub const bcs_no_depth = true; },
    InvalidBatchTransaction: struct { @"error": Str, pub const bcs_no_depth = true; },
    BlockedMoveFunction: void,
    EmptyInputCoins: void,
    UnexpectedGasPaymentObject: void,
    SharedObjectStartingVersionMismatch: void,
    TransferObjectWithoutPublicTransferError: struct { object_id: ObjectID, pub const bcs_no_depth = true; },
    EmptyCommandInput: void,
    TransactionDenied: struct { @"error": Str, pub const bcs_no_depth = true; },
    Unsupported: Str,
    MoveFunctionInputError: Str,
    VerifiedCheckpointNotFound: u64,
    VerifiedCheckpointDigestNotFound: Str,
    LatestCheckpointSequenceNumberNotFound: void,
    CheckpointContentsNotFound: ContentsDigest,
    GenesisTransactionNotFound: void,
    TransactionCursorNotFound: u64,
    InaccessibleSystemObject: struct { object_id: ObjectID, pub const bcs_no_depth = true; },
    MaxPublishCountExceeded: struct { max_publish_commands: u64, publish_count: u64, pub const bcs_no_depth = true; },
    MutableParameterExpected: struct { object_id: ObjectID, pub const bcs_no_depth = true; },
    AddressDeniedForCoin: struct { address: SuiAddress, coin_type: Str, pub const bcs_no_depth = true; },
    PostRandomCommandRestrictions: void,
    InvalidArgumentIndex: struct { command_idx: u64, argument_idx: u64, index: u16, pub const bcs_no_depth = true; },
    TooManyTransactionsInBatch: struct { size: u64, limit: u64, pub const bcs_no_depth = true; },
    TotalTransactionSizeTooLargeInBatch: struct { size: u64, limit: u64, pub const bcs_no_depth = true; },
    NoSharedObjectError: struct { digest: TxDigest, pub const bcs_no_depth = true; },
    AlreadyExecutedInSoftBundleError: struct { digest: TxDigest, pub const bcs_no_depth = true; },
    CertificateAlreadyProcessed: void,
    TransactionAlreadyExecuted: struct { digest: TxDigest, pub const bcs_no_depth = true; },
    GasPriceMismatchError: struct { digest: TxDigest, expected: u64, actual: u64, pub const bcs_no_depth = true; },
    CoinTypeGlobalPause: struct { coin_type: Str, pub const bcs_no_depth = true; },
    InvalidIdentifier: struct { @"error": Str, pub const bcs_no_depth = true; },
    NotOwnedObjectError: void,
    InvalidWithdrawReservation: struct { @"error": Str, pub const bcs_no_depth = true; },
    MissingTransactionExpiration: void,
    InvalidExpiration: struct { @"error": Str, pub const bcs_no_depth = true; },
    InvalidChainId: struct { provided: Str, expected: Str, pub const bcs_no_depth = true; },
    RepeatedTransactions: struct { digest: TxDigest, pub const bcs_no_depth = true; },
    ProposerNotAllowed: struct { proposer: u32, pub const bcs_no_depth = true; },

    /// thiserror templates: `{field}` Display, `{field:?}` Debug, `{field.0}` a tuple element,
    /// `{self}` the payload of a one-field tuple variant.
    pub const display = .{
        .MutableObjectUsedMoreThanOnce = "Mutable object {object_id} cannot appear more than one in one transaction",
        .ObjectInputArityViolation = "Wrong number of parameters for the transaction",
        .ObjectNotFound = "Could not find the referenced object {object_id} at version {version:?}",
        .ObjectVersionUnavailableForConsumption = "Transaction needs to be rebuilt because object {provided_obj_ref.0} version {provided_obj_ref.1} ({provided_obj_ref.2}) is unavailable for consumption, current version: {current_version}",
        .PackageVerificationTimeout = "Package verification failed: {err}",
        .DependentPackageNotFound = "Dependent package not found on-chain: {package_id}",
        .ImmutableParameterExpectedError = "Mutable parameter provided, immutable parameter expected",
        .SizeLimitExceeded = "Size limit exceeded: {limit} is {value}",
        .InvalidChildObjectArgument = "Object {child_id} is owned by object {parent_id}. Objects owned by other objects cannot be used as input arguments",
        .InvalidObjectDigest = "Invalid Object digest for object {object_id}. Expected digest : {expected_digest}",
        .InvalidSequenceNumber = "Sequence numbers above the maximal value are not usable for transfers",
        .MovePackageAsObject = "A move object is expected, instead a move package is passed: {object_id}",
        .MoveObjectAsPackage = "A move package is expected, instead a move object is passed: {object_id}",
        .IncorrectUserSignature = "Transaction was not signed by the correct sender: {error}",
        .NotSharedObjectError = "Object used as shared is not shared",
        .DuplicateObjectRefInput = "The transaction inputs contain duplicated ObjectRef's",
        .MissingGasPayment = "Transaction gas payment missing",
        .GasObjectNotOwnedObject = "Gas object is not an owned object with owner: {owner:?}",
        .GasBudgetTooHigh = "Gas budget: {gas_budget} is higher than max: {max_budget}",
        .GasBudgetTooLow = "Gas budget: {gas_budget} is lower than min: {min_budget}",
        .GasBalanceTooLow = "Balance of gas object {gas_balance} is lower than the needed amount: {needed_gas_amount}",
        .UnsupportedSponsoredTransactionKind = "Transaction kind does not support Sponsored Transaction",
        .GasPriceUnderRGP = "Gas price {gas_price} under reference gas price (RGP) {reference_gas_price}",
        .GasPriceTooHigh = "Gas price cannot exceed {max_gas_price} mist",
        .InvalidGasObject = "Object {object_id} is not a gas object",
        .InsufficientBalanceToCoverMinimalGas = "Gas object does not have enough balance to cover minimal gas spend",
        .ObjectSequenceNumberTooHigh = "Could not find the referenced object {object_id} as the asked version {asked_version:?} is higher than the latest {latest_version:?}",
        .ObjectDeleted = "Object deleted at reference ({object_ref.0}, {object_ref.1:?}, {object_ref.2})",
        .InvalidBatchTransaction = "Invalid Batch Transaction: {error}",
        .BlockedMoveFunction = "This Move function is currently disabled and not available for call",
        .EmptyInputCoins = "Empty input coins for Pay related transaction",
        .UnexpectedGasPaymentObject = "SUI payment transactions use first input coin for gas payment, but found a different gas object",
        .SharedObjectStartingVersionMismatch = "Wrong initial version given for shared object",
        .TransferObjectWithoutPublicTransferError = "Attempt to transfer object {object_id} that does not have public transfer. Object transfer must be done instead using a distinct Move function call",
        .EmptyCommandInput = "TransferObjects, MergeCoin, and Publish cannot have empty arguments. If MakeMoveVec has empty arguments, it must have a type specified",
        .TransactionDenied = "Transaction is denied: {error}",
        .Unsupported = "Feature is not supported: {self}",
        .MoveFunctionInputError = "Query transactions with move function input error: {self}",
        .VerifiedCheckpointNotFound = "Verified checkpoint not found for sequence number: {self}",
        .VerifiedCheckpointDigestNotFound = "Verified checkpoint not found for digest: {self}",
        .LatestCheckpointSequenceNumberNotFound = "Latest checkpoint sequence number not found",
        .CheckpointContentsNotFound = "Checkpoint contents not found for digest: {self}",
        .GenesisTransactionNotFound = "Genesis transaction not found",
        .TransactionCursorNotFound = "Transaction {self} not found",
        .InaccessibleSystemObject = "Object {object_id} is a system object and cannot be accessed by user transactions",
        .MaxPublishCountExceeded = "{max_publish_commands} max publish/upgrade commands allowed, {publish_count} provided",
        .MutableParameterExpected = "Immutable parameter provided, mutable parameter expected",
        .AddressDeniedForCoin = "Address {address} is denied for coin {coin_type}",
        .PostRandomCommandRestrictions = "Commands following a command with Random can only be TransferObjects or MergeCoins",
        .InvalidArgumentIndex = "Invalid argument at command {command_idx}, argument {argument_idx}: index {index} is out of bounds",
        .TooManyTransactionsInBatch = "Number of transactions ({size}) exceeds the maximum allowed ({limit}) in a batch",
        .TotalTransactionSizeTooLargeInBatch = "Total transactions size ({size}) bytes exceeds the maximum allowed ({limit}) bytes in a Soft Bundle",
        .NoSharedObjectError = "Transaction {digest} in Soft Bundle contains no shared objects",
        .AlreadyExecutedInSoftBundleError = "Transaction {digest} in Soft Bundle has already been executed",
        .CertificateAlreadyProcessed = "At least one certificate in Soft Bundle has already been processed",
        .TransactionAlreadyExecuted = "Transaction {digest} was already executed",
        .GasPriceMismatchError = "Gas price for transaction {digest} in Soft Bundle mismatch: want {expected}, have {actual}",
        .CoinTypeGlobalPause = "Coin type is globally paused for use: {coin_type}",
        .InvalidIdentifier = "Invalid identifier found in the transaction: {error}",
        .NotOwnedObjectError = "Object used as owned is not owned",
        .InvalidWithdrawReservation = "Invalid withdraw reservation: {error}",
        .MissingTransactionExpiration = "Transaction with empty gas payment must specify an expiration.",
        .InvalidExpiration = "Invalid transaction expiration: {error}",
        .InvalidChainId = "Transaction chain ID {provided} does not match network chain ID {expected}.",
        .RepeatedTransactions = "Transaction {digest} appears more than once in the request",
        .ProposerNotAllowed = "Validator {proposer} is not an allowed proposer of this transaction",
    };

    pub fn format(self: *const UserInputError, w: *Writer) Writer.Error!void {
        return displayUnion(UserInputError, self, w);
    }
};

/// `SuiObjectResponseError` cannot be read from BCS (internally tagged serde enum); decoding a
/// `SuiErrorKind` that holds it fails like Rust's decoder does.
pub const SuiObjectResponseError = struct {
    pub fn bcsDecode(arena: Allocator, r: *bcs.Reader) bcs.DecodeError!SuiObjectResponseError {
        _ = arena;
        _ = r;
        return error.InvalidValue;
    }
    pub fn bcsSkip(r: *bcs.Reader) bcs.Error!void {
        _ = r;
        return error.InvalidValue;
    }
    pub fn bcsEncode(self: *const SuiObjectResponseError, w: anytype) bcs.EncodeError!void {
        _ = self;
        _ = w;
    }
};

pub const SuiErrorKind = union(enum) {
    UserInputError: struct { @"error": UserInputError, pub const bcs_no_depth = true; },
    SuiObjectResponseError: struct { @"error": SuiObjectResponseError, pub const bcs_no_depth = true; },
    UnexpectedOwnerType: void,
    TooManyTransactionsPendingExecution: struct { queue_len: u64, threshold: u64, pub const bcs_no_depth = true; },
    TooManyTransactionsPendingConsensus: void,
    TooManyTransactionsPendingOnObject: struct { object_id: ObjectID, queue_len: u64, threshold: u64, pub const bcs_no_depth = true; },
    TooOldTransactionPendingOnObject: struct { object_id: ObjectID, txn_age_sec: u64, threshold: u64, pub const bcs_no_depth = true; },
    InvalidTxKindInSoftBundle: void,
    InvalidSignature: struct { @"error": Str, pub const bcs_no_depth = true; },
    SignerSignatureAbsent: struct { expected: Str, actual: []const Str, pub const bcs_no_depth = true; },
    SignerSignatureNumberMismatch: struct { expected: u64, actual: u64, pub const bcs_no_depth = true; },
    IncorrectSigner: struct { @"error": Str, pub const bcs_no_depth = true; },
    UnknownSigner: struct { signer: ?Str, index: ?u32, committee: *const Committee, pub const bcs_no_depth = true; },
    StakeAggregatorRepeatedSigner: struct { signer: AuthorityName, conflicting_sig: bool, pub const bcs_no_depth = true; },
    PotentiallyTemporarilyInvalidSignature: struct { @"error": Str, pub const bcs_no_depth = true; },
    WrongEpoch: struct { expected_epoch: u64, actual_epoch: u64, pub const bcs_no_depth = true; },
    CertificateRequiresQuorum: void,
    DEPRECATED_ErrorWhileProcessingCertificate: void,
    QuorumFailedToGetEffectsQuorumWhenProcessingTransaction: struct { effects_map: bcs.Map(EffDigest, struct { []const AuthorityName, u64 }), pub const bcs_no_depth = true; },
    FailedToVerifyTxCertWithExecutedEffects: struct { validator_name: AuthorityName, @"error": Str, pub const bcs_no_depth = true; },
    TxAlreadyFinalizedWithDifferentUserSigs: void,
    InvalidAuthenticator: void,
    InvalidAddress: void,
    InvalidTransactionDigest: void,
    InvalidDigestLength: struct { expected: u64, actual: u64, pub const bcs_no_depth = true; },
    InvalidDkgMessageSize: void,
    UnexpectedMessage: Str,
    ModuleVerificationFailure: struct { @"error": Str, pub const bcs_no_depth = true; },
    ModuleDeserializationFailure: struct { @"error": Str, pub const bcs_no_depth = true; },
    ModulePublishFailure: struct { @"error": Str, pub const bcs_no_depth = true; },
    ModuleBuildFailure: struct { @"error": Str, pub const bcs_no_depth = true; },
    FunctionNotFound: struct { @"error": Str, pub const bcs_no_depth = true; },
    ModuleNotFound: struct { module_name: Str, pub const bcs_no_depth = true; },
    TypeError: struct { @"error": Str, pub const bcs_no_depth = true; },
    CircularObjectOwnership: void,
    ObjectLockAlreadyInitialized: struct { refs: []const ObjectRef, pub const bcs_no_depth = true; },
    ObjectLockConflict: struct { obj_ref: ObjectRef, pending_transaction: TxDigest, pub const bcs_no_depth = true; },
    ObjectLockedAtFutureEpoch: struct { obj_refs: []const ObjectRef, locked_epoch: u64, new_epoch: u64, locked_by_tx: TxDigest, pub const bcs_no_depth = true; },
    TransactionNotFound: struct { digest: TxDigest, pub const bcs_no_depth = true; },
    TransactionsNotFound: struct { digests: []const TxDigest, pub const bcs_no_depth = true; },
    TransactionEventsNotFound: struct { digest: TxDigest, pub const bcs_no_depth = true; },
    TransactionEffectsNotFound: struct { digest: TxDigest, pub const bcs_no_depth = true; },
    TransactionAlreadyExecuted: struct { digest: TxDigest, pub const bcs_no_depth = true; },
    TransactionRejectReasonNotFound: struct { digest: TxDigest, pub const bcs_no_depth = true; },
    BadObjectType: struct { @"error": Str, pub const bcs_no_depth = true; },
    FailObjectLayout: struct { st: Str, pub const bcs_no_depth = true; },
    ExecutionInvariantViolation: void,
    ByzantineAuthoritySuspicion: struct { authority: AuthorityName, reason: Str, pub const bcs_no_depth = true; },
    StorageError: void,
    GenericStorageError: void,
    InvalidChildObjectAccess: struct { object: ObjectID, given_parent: ObjectID, actual_owner: Owner, pub const bcs_no_depth = true; },
    StorageMissingFieldError: void,
    StorageCorruptedFieldError: void,
    GenericAuthorityError: struct { @"error": Str, pub const bcs_no_depth = true; },
    GenericBridgeError: struct { @"error": Str, pub const bcs_no_depth = true; },
    FailedToDispatchSubscription: struct { @"error": Str, pub const bcs_no_depth = true; },
    OwnerFailedToSerialize: struct { @"error": Str, pub const bcs_no_depth = true; },
    ExtraFieldFailedToDeserialize: struct { @"error": Str, pub const bcs_no_depth = true; },
    TransactionOrchestratorLocalExecutionError: struct { @"error": Str, pub const bcs_no_depth = true; },
    TransactionSerializationError: struct { @"error": Str, pub const bcs_no_depth = true; },
    TransactionDeserializationError: struct { @"error": Str, pub const bcs_no_depth = true; },
    TransactionEffectsSerializationError: struct { @"error": Str, pub const bcs_no_depth = true; },
    TransactionEffectsDeserializationError: struct { @"error": Str, pub const bcs_no_depth = true; },
    TransactionEventsSerializationError: struct { @"error": Str, pub const bcs_no_depth = true; },
    TransactionEventsDeserializationError: struct { @"error": Str, pub const bcs_no_depth = true; },
    ObjectSerializationError: struct { @"error": Str, pub const bcs_no_depth = true; },
    ObjectDeserializationError: struct { @"error": Str, pub const bcs_no_depth = true; },
    NoEventStore: void,
    TooManyIncorrectAuthorities: struct { errors: []const struct { AuthorityName, SuiErrorKind }, action: Str, pub const bcs_no_depth = true; },
    FullNodeInvalidTxRangeQuery: struct { @"error": Str, pub const bcs_no_depth = true; },
    FailedToSubmitToConsensus: Str,
    ConsensusConnectionBroken: Str,
    HandleConsensusTransactionFailure: Str,
    SignatureKeyGenError: Str,
    KeyConversionError: Str,
    InvalidPrivateKey: void,
    FullNodeCantHandleCertificate: void,
    ValidatorHaltedAtEpochEnd: void,
    EpochEnded: u64,
    AdvanceEpochError: struct { @"error": Str, pub const bcs_no_depth = true; },
    TransactionExpired: void,
    RpcError: struct { Str, Str },
    InvalidRpcMethodError: void,
    UnsupportedFeatureError: struct { @"error": Str, pub const bcs_no_depth = true; },
    QuorumDriverCommunicationError: struct { @"error": Str, pub const bcs_no_depth = true; },
    TimeoutError: void,
    ExecutionError: Str,
    InvalidCommittee: Str,
    MissingCommitteeAtEpoch: u64,
    DynamicFieldReadError: Str,
    SuiSystemStateReadError: Str,
    SuiBridgeReadError: Str,
    UnexpectedVersion: Str,
    WrongMessageVersion: struct { @"error": Str, pub const bcs_no_depth = true; },
    Unknown: Str,
    FileIOError: Str,
    JWKRetrievalError: void,
    Storage: Str,
    ValidatorOverloadedRetryAfter: struct { retry_after_secs: u64, pub const bcs_no_depth = true; },
    TooManyRequests: void,
    NoCertificateProvidedError: void,
    NitroAttestationFailedToVerify: Str,
    GrpcMessageSerializeError: struct { type_info: Str, @"error": Str, pub const bcs_no_depth = true; },
    GrpcMessageDeserializeError: struct { type_info: Str, @"error": Str, pub const bcs_no_depth = true; },
    ValidatorConsensusLagging: struct { round: u32, last_committed_round: u32, pub const bcs_no_depth = true; },
    InvalidAdminRequest: Str,
    InvalidRequest: Str,
    AliasesChanged: void,
    ImmutableObjectClaimNotFoundInInput: struct { object_id: ObjectID, pub const bcs_no_depth = true; },
    ImmutableObjectNotClaimed: struct { object_id: ObjectID, pub const bcs_no_depth = true; },
    InvalidImmutableObjectClaim: struct { claimed_object_id: ObjectID, found_object_ref: ObjectRef, pub const bcs_no_depth = true; },
    TransactionRejectedDueToOutbiddingDuringCongestion: struct { min_gas_price: u64, pub const bcs_no_depth = true; },
    TransactionProcessing: struct { digest: TxDigest, status: Str, pub const bcs_no_depth = true; },
    TransactionSubmitted: struct { digest: TxDigest, pub const bcs_no_depth = true; },
    StaggeredSubmissionNotProposer: void,

    pub const display = .{
        .UserInputError = "Error checking transaction input objects: {error}",
        .SuiObjectResponseError = "Error checking transaction object",
        .UnexpectedOwnerType = "Expecting a single owner, shared ownership found",
        .TooManyTransactionsPendingExecution = "There are already {queue_len} transactions pending, above threshold of {threshold}",
        .TooManyTransactionsPendingConsensus = "There are too many transactions pending in consensus",
        .TooManyTransactionsPendingOnObject = "Input {object_id} already has {queue_len} transactions pending, above threshold of {threshold}",
        .TooOldTransactionPendingOnObject = "Input {object_id} has a transaction {txn_age_sec} seconds old pending, above threshold of {threshold} seconds",
        .InvalidTxKindInSoftBundle = "Soft bundle must only contain transactions of UserTransaction kind",
        .InvalidSignature = "Signature is not valid: {error}",
        .SignerSignatureAbsent = "Required Signature from {expected} is absent {actual:?}",
        .SignerSignatureNumberMismatch = "Expect {expected} signer signatures but got {actual}",
        .IncorrectSigner = "Value was not signed by the correct sender: {error}",
        .UnknownSigner = "Value was not signed by a known authority. signer: {signer:?}, index: {index:?}, committee: {committee}",
        .StakeAggregatorRepeatedSigner = "Validator {signer:?} responded multiple signatures for the same message, conflicting: {conflicting_sig:?}",
        .PotentiallyTemporarilyInvalidSignature = "Signature is not valid, but a retry may result in a valid one: {error}",
        .WrongEpoch = "Signature or certificate from wrong epoch, expected {expected_epoch}, got {actual_epoch}",
        .CertificateRequiresQuorum = "Signatures in a certificate must form a quorum",
        .DEPRECATED_ErrorWhileProcessingCertificate = "DEPRECATED",
        .QuorumFailedToGetEffectsQuorumWhenProcessingTransaction = "Failed to get a quorum of signed effects when processing transaction: {effects_map:?}",
        .FailedToVerifyTxCertWithExecutedEffects = "Failed to verify Tx certificate with executed effects, error: {error:?}, validator: {validator_name:?}",
        .TxAlreadyFinalizedWithDifferentUserSigs = "Transaction is already finalized but with different user signatures",
        .InvalidAuthenticator = "Invalid authenticator",
        .InvalidAddress = "Invalid address",
        .InvalidTransactionDigest = "Invalid transaction digest.",
        .InvalidDigestLength = "Invalid digest length. Expected {expected}, got {actual}",
        .InvalidDkgMessageSize = "Invalid DKG message size",
        .UnexpectedMessage = "Unexpected message: {self}",
        .ModuleVerificationFailure = "Failed to verify the Move module, reason: {error}.",
        .ModuleDeserializationFailure = "Failed to deserialize the Move module, reason: {error}.",
        .ModulePublishFailure = "Failed to publish the Move module(s), reason: {error}",
        .ModuleBuildFailure = "Failed to build Move modules: {error}.",
        .FunctionNotFound = "Function resolution failure: {error}.",
        .ModuleNotFound = "Module not found in package: {module_name}.",
        .TypeError = "Type error while binding function arguments: {error}.",
        .CircularObjectOwnership = "Circular object ownership detected",
        .ObjectLockAlreadyInitialized = "Attempt to re-initialize a transaction lock for objects {refs:?}.",
        .ObjectLockConflict = "Object {obj_ref:?} already locked by a different transaction: {pending_transaction:?}",
        .ObjectLockedAtFutureEpoch = "Objects {obj_refs:?} are already locked by a transaction from a future epoch {locked_epoch:?}), attempt to override with a transaction from epoch {new_epoch:?}",
        .TransactionNotFound = "Could not find the referenced transaction [{digest:?}].",
        .TransactionsNotFound = "Could not find the referenced transactions [{digests:?}].",
        .TransactionEventsNotFound = "Could not find the referenced transaction events [{digest:?}].",
        .TransactionEffectsNotFound = "Could not find the referenced transaction effects [{digest:?}].",
        .TransactionAlreadyExecuted = "Attempt to move to `Executed` state an transaction that has already been executed: {digest:?}.",
        .TransactionRejectReasonNotFound = "Transaction reject reason not found for transaction {digest:?}",
        .BadObjectType = "Object ID did not have the expected type",
        .FailObjectLayout = "Fail to retrieve Object layout for {st}",
        .ExecutionInvariantViolation = "Execution invariant violated",
        .ByzantineAuthoritySuspicion = "Validator {authority:?} is faulty in a Byzantine manner: {reason:?}",
        .StorageError = "DEPRECATED",
        .GenericStorageError = "DEPRECATED",
        .InvalidChildObjectAccess = "Attempted to access {object} through parent {given_parent}, but it's actual parent is {actual_owner}",
        .StorageMissingFieldError = "DEPRECATED",
        .StorageCorruptedFieldError = "DEPRECATED",
        .GenericAuthorityError = "Authority Error: {error}",
        .GenericBridgeError = "Generic Bridge Error: {error}",
        .FailedToDispatchSubscription = "Failed to dispatch subscription: {error}",
        .OwnerFailedToSerialize = "Failed to serialize Owner: {error}",
        .ExtraFieldFailedToDeserialize = "Failed to deserialize fields into JSON: {error}",
        .TransactionOrchestratorLocalExecutionError = "Failed to execute transaction locally by Orchestrator: {error}",
        .TransactionSerializationError = "Failure serializing transaction in the requested format: {error}",
        .TransactionDeserializationError = "Failure deserializing transaction from the provided format: {error}",
        .TransactionEffectsSerializationError = "Failure serializing transaction effects from the provided format: {error}",
        .TransactionEffectsDeserializationError = "Failure deserializing transaction effects from the provided format: {error}",
        .TransactionEventsSerializationError = "Failure serializing transaction events from the provided format: {error}",
        .TransactionEventsDeserializationError = "Failure deserializing transaction events from the provided format: {error}",
        .ObjectSerializationError = "Failure serializing object in the requested format: {error}",
        .ObjectDeserializationError = "Failure deserializing object in the requested format: {error}",
        .NoEventStore = "Event store component is not active on this node",
        .TooManyIncorrectAuthorities = "Too many authority errors were detected for {action}: {errors:?}",
        .FullNodeInvalidTxRangeQuery = "Invalid transaction range query to the fullnode: {error}",
        .FailedToSubmitToConsensus = "Failed to submit transaction to consensus: {self}",
        .ConsensusConnectionBroken = "Failed to connect with consensus node: {self}",
        .HandleConsensusTransactionFailure = "Failed to execute handle_consensus_transaction on Sui: {self}",
        .SignatureKeyGenError = "Signature key generation error: {self}",
        .KeyConversionError = "Key Conversion Error: {self}",
        .InvalidPrivateKey = "Invalid Private Key provided",
        .FullNodeCantHandleCertificate = "Fullnode does not support handle_certificate",
        .ValidatorHaltedAtEpochEnd = "Validator temporarily stopped processing transactions due to epoch change",
        .EpochEnded = "Operations for epoch {self} have ended",
        .AdvanceEpochError = "Error when advancing epoch: {error}",
        .TransactionExpired = "Transaction Expired",
        .RpcError = "{1} - {0}",
        .InvalidRpcMethodError = "Method not allowed",
        .UnsupportedFeatureError = "Use of disabled feature: {error}",
        .QuorumDriverCommunicationError = "Unable to communicate with the Quorum Driver channel: {error}",
        .TimeoutError = "Operation timed out",
        .ExecutionError = "Error executing {self}",
        .InvalidCommittee = "Invalid committee composition",
        .MissingCommitteeAtEpoch = "Missing committee information for epoch {self}",
        .DynamicFieldReadError = "Failed to read dynamic field from table in the object store: {self}",
        .SuiSystemStateReadError = "Failed to read or deserialize system state related data structures on-chain: {self}",
        .SuiBridgeReadError = "Failed to read or deserialize bridge related data structures on-chain: {self}",
        .UnexpectedVersion = "Unexpected version error: {self}",
        .WrongMessageVersion = "Message version is not supported at the current protocol version: {error}",
        .Unknown = "unknown error: {self}",
        .FileIOError = "Failed to perform file operation: {self}",
        .JWKRetrievalError = "Failed to get JWK",
        .Storage = "Storage error: {self}",
        .ValidatorOverloadedRetryAfter = "Validator cannot handle the request at the moment. Please retry after at least {retry_after_secs} seconds.",
        .TooManyRequests = "Too many requests",
        .NoCertificateProvidedError = "The request did not contain a certificate",
        .NitroAttestationFailedToVerify = "Nitro attestation verify failed: {self}",
        .GrpcMessageSerializeError = "Failed to serialize {type_info}, error: {error}",
        .GrpcMessageDeserializeError = "Failed to deserialize {type_info}, error: {error}",
        .ValidatorConsensusLagging = "Validator consensus rounds are lagging behind. last committed leader round: {last_committed_round}, requested round: {round}",
        .InvalidAdminRequest = "Invalid admin request: {self}",
        .InvalidRequest = "Invalid request: {self}",
        .AliasesChanged = "The current set of aliases for a required signer changed after the transaction was submitted",
        .ImmutableObjectClaimNotFoundInInput = "Object {object_id} not found among input objects.",
        .ImmutableObjectNotClaimed = "Immutable object {object_id} was not included in immutable claims.",
        .InvalidImmutableObjectClaim = "Claimed object {claimed_object_id} is not immutable. Found object ref: {found_object_ref:?}",
        .TransactionRejectedDueToOutbiddingDuringCongestion = "Transaction was outbid by higher-gas-price transactions in the admission queue (current minimum gas price required: {min_gas_price})",
        .TransactionProcessing = "Transaction {digest} is being processed post-consensus: {status}",
        .TransactionSubmitted = "Transaction {digest} has been recently submitted to this validator.",
        .StaggeredSubmissionNotProposer = "This validator is outside the transaction's staggered-submission proposer set; submit to one of its proposers.",
    };

    pub fn format(self: *const SuiErrorKind, w: *Writer) Writer.Error!void {
        return displayUnion(SuiErrorKind, self, w);
    }

    /// `SuiErrorKind::categorize`.
    pub fn categorize(self: *const SuiErrorKind) ErrorCategory {
        return switch (self.*) {
            .UserInputError => |u| switch (u.@"error") {
                .ObjectNotFound, .DependentPackageNotFound => .Aborted,
                else => .InvalidTransaction,
            },
            .InvalidSignature, .SignerSignatureAbsent, .SignerSignatureNumberMismatch, .IncorrectSigner, .UnknownSigner, .TransactionExpired => .InvalidTransaction,
            .ObjectLockConflict => .LockConflict,
            .Unknown, .GrpcMessageSerializeError, .GrpcMessageDeserializeError, .ByzantineAuthoritySuspicion, .InvalidTxKindInSoftBundle, .UnsupportedFeatureError, .InvalidRequest => .Internal,
            .TooManyTransactionsPendingExecution, .TooManyTransactionsPendingOnObject, .TooOldTransactionPendingOnObject, .TooManyTransactionsPendingConsensus, .TransactionRejectedDueToOutbiddingDuringCongestion, .ValidatorOverloadedRetryAfter => .ValidatorOverloaded,
            .TimeoutError => .Unavailable,
            .StaggeredSubmissionNotProposer => .Aborted,
            else => .Aborted,
        };
    }

    pub const Retryable = struct { retryable: bool, categorized: bool };

    /// `SuiErrorKind::is_retryable`: (retryable, explicitly categorized).
    pub fn isRetryable(self: *const SuiErrorKind) Retryable {
        const r: bool = switch (self.*) {
            .RpcError, .ValidatorHaltedAtEpochEnd, .MissingCommitteeAtEpoch, .WrongEpoch, .EpochEnded => true,
            .UserInputError => |u| switch (u.@"error") {
                .ObjectNotFound, .DependentPackageNotFound => true,
                else => false,
            },
            .PotentiallyTemporarilyInvalidSignature => true,
            .TooManyTransactionsPendingExecution, .TooManyTransactionsPendingOnObject, .TooOldTransactionPendingOnObject, .TooManyTransactionsPendingConsensus, .TransactionRejectedDueToOutbiddingDuringCongestion, .ValidatorOverloadedRetryAfter => true,
            .StaggeredSubmissionNotProposer, .TransactionProcessing, .TransactionSubmitted => true,
            .ExecutionError, .ByzantineAuthoritySuspicion, .QuorumFailedToGetEffectsQuorumWhenProcessingTransaction, .TxAlreadyFinalizedWithDifferentUserSigs, .FailedToVerifyTxCertWithExecutedEffects, .ObjectLockConflict, .TooManyRequests => false,
            else => return .{ .retryable = false, .categorized = false },
        };
        return .{ .retryable = r, .categorized = true };
    }

    /// Display text in `arena`.
    pub fn text(self: *const SuiErrorKind, arena: Allocator) Allocator.Error![]const u8 {
        return allocPrint(arena, self);
    }

    /// `format_transaction_request_error` (transaction_driver/error.rs) for
    /// `RejectedAtValidator(self)`: the inner `UserInputError`'s text, else the error's text.
    pub fn requestErrorText(self: *const SuiErrorKind, arena: Allocator) Allocator.Error![]const u8 {
        return switch (self.*) {
            .UserInputError => |*u| allocPrint(arena, &u.@"error"),
            else => allocPrint(arena, self),
        };
    }
};

/// Display of any formattable value into a fresh arena string.
pub fn allocPrint(arena: Allocator, v: anytype) Allocator.Error![]const u8 {
    var a: Writer.Allocating = .init(arena);
    v.format(&a.writer) catch return error.OutOfMemory;
    return a.written();
}

/// The text of a `bcs::Error` for a deepwave decode error (bcs-0.1.6 `Error` Display). `Custom`
/// texts from serde (an enum variant index out of range) are approximated.
pub fn bcsErrorText(e: anyerror) []const u8 {
    return switch (e) {
        error.EndOfInput => "unexpected end of input",
        error.TrailingBytes => "remaining input",
        error.InvalidBool => "expected boolean",
        error.InvalidUtf8 => "malformed utf8",
        error.NonCanonical => "ULEB128 encoding was not minimal in size",
        error.InvalidUleb => "ULEB128-encoded integer did not fit in the target size",
        error.LengthTooLarge => "exceeded max sequence length",
        error.DepthExceeded => "exceeded max container depth while entering",
        error.InvalidEnumTag => "invalid enum variant index",
        else => "invalid value",
    };
}

/// Decodes a BCS `SuiError` (= `SuiErrorKind`; the Box is transparent).
pub fn decode(arena: Allocator, bytes: []const u8) bcs.DecodeError!SuiErrorKind {
    return bcs.decode(SuiErrorKind, arena, bytes);
}

/// tonic `Code::description()` (tonic 0.14).
pub fn codeDescription(code: u8) []const u8 {
    return switch (code) {
        0 => "The operation completed successfully",
        1 => "The operation was cancelled",
        2 => "Unknown error",
        3 => "Client specified an invalid argument",
        4 => "Deadline expired before operation could complete",
        5 => "Some requested entity was not found",
        6 => "Some entity that we attempted to create already exists",
        7 => "The caller does not have permission to execute the specified operation",
        8 => "Some resource has been exhausted",
        9 => "The system is not in a state required for the operation's execution",
        10 => "The operation was aborted",
        11 => "Operation was attempted past the valid range",
        12 => "Operation is not implemented or not supported",
        13 => "Internal error",
        14 => "The service is currently unavailable",
        15 => "Unrecoverable data loss or corruption",
        16 => "The request does not have valid authentication credentials",
        else => "Unknown error",
    };
}

/// `From<tonic::Status> for SuiError`: "Too many requests" by message, else the BCS SuiError in
/// the details, else `RpcError(message, code description)`. Slices borrow `message`/`details`.
pub fn fromStatus(arena: Allocator, code: u8, message: []const u8, details: []const u8) Allocator.Error!SuiErrorKind {
    if (std.mem.eql(u8, message, "Too many requests")) return .TooManyRequests;
    if (decode(arena, details)) |e| return e else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {},
    }
    // a code outside 0..=16 is Code::Unknown in tonic
    return .{ .RpcError = .{ .{ .@"0" = message }, .{ .@"0" = codeDescription(if (code > 16) 2 else code) } } };
}

// ------------------------------------------------------------------------------------------
// Display / Debug machinery

const Seg = struct { lit: []const u8, path: []const u8 = "", debug: bool = false };

fn parseTemplate(comptime t: []const u8) []const Seg {
    comptime {
        @setEvalBranchQuota(100_000);
        var segs: []const Seg = &.{};
        var lit: []const u8 = "";
        var i = 0;
        while (i < t.len) {
            if (t[i] == '{' and i + 1 < t.len and t[i + 1] == '{') {
                lit = lit ++ "{";
                i += 2;
            } else if (t[i] == '}' and i + 1 < t.len and t[i + 1] == '}') {
                lit = lit ++ "}";
                i += 2;
            } else if (t[i] == '{') {
                const close = std.mem.indexOfScalarPos(u8, t, i, '}').?;
                var inner: []const u8 = t[i + 1 .. close];
                var debug = false;
                if (std.mem.endsWith(u8, inner, ":?")) {
                    debug = true;
                    inner = inner[0 .. inner.len - 2];
                }
                segs = segs ++ [_]Seg{.{ .lit = lit, .path = inner, .debug = debug }};
                lit = "";
                i = close + 1;
            } else {
                lit = lit ++ t[i .. i + 1];
                i += 1;
            }
        }
        if (lit.len > 0) segs = segs ++ [_]Seg{.{ .lit = lit }};
        return segs;
    }
}

fn FieldType(comptime T: type, comptime path: []const u8) type {
    @setEvalBranchQuota(100_000);
    if (std.mem.eql(u8, path, "self")) return T;
    var Cur = T;
    var it = std.mem.splitScalar(u8, path, '.');
    while (it.next()) |c| Cur = @FieldType(Cur, c);
    return Cur;
}

fn fieldAt(payload: anytype, comptime path: []const u8) FieldType(@TypeOf(payload), path) {
    if (comptime std.mem.eql(u8, path, "self")) return payload;
    const dot = comptime std.mem.indexOfScalar(u8, path, '.');
    if (dot) |d| return fieldAt(@field(payload, path[0..d]), path[d + 1 ..]);
    return @field(payload, path);
}

fn displayUnion(comptime U: type, self: *const U, w: *Writer) Writer.Error!void {
    switch (self.*) {
        inline else => |payload, tag| {
            const segs = comptime parseTemplate(@field(U.display, @tagName(tag)));
            inline for (segs) |s| {
                try w.writeAll(s.lit);
                if (s.path.len > 0) {
                    const v = fieldAt(payload, s.path);
                    if (s.debug) try writeDebug(w, v) else try writeDisplay(w, v);
                }
            }
        },
    }
}

fn hex(w: *Writer, b: []const u8) Writer.Error!void {
    const digits = "0123456789abcdef";
    for (b) |x| {
        try w.writeByte(digits[x >> 4]);
        try w.writeByte(digits[x & 15]);
    }
}

fn base58(w: *Writer, d: *const [32]u8) Writer.Error!void {
    var buf: [b58.max_len_32]u8 = undefined;
    try w.writeAll(b58.encode32(&buf, d));
}

/// Rust `str` Debug: quoted, with `escape_debug` of ASCII (see the file comment).
pub fn writeDebugStr(w: *Writer, s: []const u8) Writer.Error!void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0 => try w.writeAll("\\0"),
        1...8, 11, 12, 14...31, 127 => try w.print("\\u{{{x}}}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

/// `AuthorityName` concise form `k#xxxxxxxx..` (first 4 bytes).
pub fn writeConcise(w: *Writer, n: *const AuthorityName) Writer.Error!void {
    try w.writeAll("k#");
    try hex(w, n.@"0"[0..4]);
    try w.writeAll("..");
}

fn writeOwnerDisplay(w: *Writer, o: Owner) Writer.Error!void {
    switch (o) {
        .AddressOwner => |a| {
            try w.writeAll("Account Address ( 0x");
            try hex(w, &a.@"0");
            try w.writeAll(" )");
        },
        .ObjectOwner => |a| {
            try w.writeAll("Object ID: ( 0x");
            try hex(w, &a.@"0");
            try w.writeAll(" )");
        },
        .Immutable => try w.writeAll("Immutable"),
        .Shared => |s| try w.print("Shared( {d} )", .{s.initial_shared_version.@"0"}),
        .ConsensusAddressOwner => |c| {
            try w.print("ConsensusAddressOwner( {d}, 0x", .{c.start_version.@"0"});
            try hex(w, &c.owner.@"0");
            try w.writeAll(" )");
        },
        .Party => |p| try w.print("Party( {d}, .. )", .{p.start_version.@"0"}),
    }
}

fn writeOwnerDebug(w: *Writer, o: Owner) Writer.Error!void {
    switch (o) {
        .AddressOwner => |a| {
            try w.writeAll("AddressOwner(0x");
            try hex(w, &a.@"0");
            try w.writeAll(")");
        },
        .ObjectOwner => |a| {
            try w.writeAll("ObjectOwner(0x");
            try hex(w, &a.@"0");
            try w.writeAll(")");
        },
        .Immutable => try w.writeAll("Immutable"),
        .Shared => |s| try w.print("Shared {{ initial_shared_version: SequenceNumber({d}) }}", .{s.initial_shared_version.@"0"}),
        .ConsensusAddressOwner => |c| {
            try w.print("ConsensusAddressOwner {{ start_version: SequenceNumber({d}), owner: 0x", .{c.start_version.@"0"});
            try hex(w, &c.owner.@"0");
            try w.writeAll(" }");
        },
        .Party => |p| try w.print("Party {{ start_version: SequenceNumber({d}), .. }}", .{p.start_version.@"0"}),
    }
}

fn writeCommitteeDisplay(w: *Writer, c: *const Committee) Writer.Error!void {
    try w.print("Committee (epoch={d}, voting_rights=[", .{c.epoch});
    for (c.voting_rights) |vr| {
        try writeConcise(w, &vr.@"0");
        try w.print(": {d}, ", .{vr.@"1"});
    }
    try w.writeAll("])");
}

/// Rust `Display` of a payload value.
pub fn writeDisplay(w: *Writer, v: anytype) Writer.Error!void {
    const T = @TypeOf(v);
    switch (T) {
        Str => return w.writeAll(v.@"0"),
        ObjectID => {
            try w.writeAll("0x");
            return hex(w, &v.@"0".@"0");
        },
        SuiAddress => {
            try w.writeAll("0x");
            return hex(w, &v.@"0");
        },
        SeqNum => return w.print("0x{x}", .{v.@"0"}),
        ObjectDigest, TxDigest, EffDigest, ContentsDigest => return base58(w, &v.@"0".@"0"),
        AuthorityName => {
            try w.writeAll("k#");
            return hex(w, &v.@"0");
        },
        Owner => return writeOwnerDisplay(w, v),
        UserInputError, SuiErrorKind => return v.format(w),
        *const Committee => return writeCommitteeDisplay(w, v),
        bool => return w.writeAll(if (v) "true" else "false"),
        else => {},
    }
    switch (@typeInfo(T)) {
        .int, .comptime_int => return w.print("{d}", .{v}),
        else => @compileError("no Display for " ++ @typeName(T)),
    }
}

/// Rust `Debug` (derived or hand-written as sui-types has it) of a payload value.
pub fn writeDebug(w: *Writer, v: anytype) Writer.Error!void {
    const T = @TypeOf(v);
    switch (T) {
        Str => return writeDebugStr(w, v.@"0"),
        ObjectID, SuiAddress, AuthorityName, Owner => return if (T == Owner) writeOwnerDebug(w, v) else writeDisplay(w, v),
        SeqNum => return w.print("SequenceNumber({d})", .{v.@"0"}),
        ObjectDigest => {
            try w.writeAll("o#");
            return base58(w, &v.@"0".@"0");
        },
        TxDigest => {
            try w.writeAll("TransactionDigest(");
            try base58(w, &v.@"0".@"0");
            return w.writeAll(")");
        },
        EffDigest => {
            try w.writeAll("TransactionEffectsDigest(");
            try base58(w, &v.@"0".@"0");
            return w.writeAll(")");
        },
        ContentsDigest => {
            try w.writeAll("CheckpointContentsDigest(");
            try base58(w, &v.@"0".@"0");
            return w.writeAll(")");
        },
        *const Committee => return w.print("Committee {{ epoch: {d}, .. }}", .{v.epoch}),
        SuiObjectResponseError => return w.writeAll(".."),
        bool => return w.writeAll(if (v) "true" else "false"),
        else => {},
    }
    switch (@typeInfo(T)) {
        .int => return w.print("{d}", .{v}),
        .optional => {
            if (v) |x| {
                try w.writeAll("Some(");
                try writeDebug(w, x);
                return w.writeAll(")");
            }
            return w.writeAll("None");
        },
        .pointer => |p| {
            if (p.size == .slice) {
                try w.writeByte('[');
                for (v, 0..) |x, i| {
                    if (i > 0) try w.writeAll(", ");
                    try writeDebug(w, x);
                }
                return w.writeByte(']');
            }
            return writeDebug(w, v.*);
        },
        .@"struct" => |s| {
            if (comptime @hasDecl(T, "bcs_map")) {
                // bcs.Map: `{k: v, ...}` in key order
                try w.writeByte('{');
                for (v.entries, 0..) |e, i| {
                    if (i > 0) try w.writeAll(", ");
                    try writeDebug(w, e.key);
                    try w.writeAll(": ");
                    try writeDebug(w, e.value);
                }
                return w.writeByte('}');
            }
            if (s.is_tuple) {
                try w.writeByte('(');
                inline for (s.field_names, 0..) |f, i| {
                    if (i > 0) try w.writeAll(", ");
                    try writeDebug(w, @field(v, f));
                }
                return w.writeByte(')');
            }
            @compileError("no Debug for " ++ @typeName(T));
        },
        .@"union" => return debugUnion(T, v, w),
        else => @compileError("no Debug for " ++ @typeName(T)),
    }
}

/// Derived `Debug` of an enum: `Unit`, `Tuple(x)`, `Named { a: x, b: y }`.
fn debugUnion(comptime U: type, v: U, w: *Writer) Writer.Error!void {
    switch (v) {
        inline else => |payload, tag| {
            try w.writeAll(@tagName(tag));
            const P = @TypeOf(payload);
            if (P == void) return;
            if (@typeInfo(P) == .@"struct" and @hasDecl(P, "bcs_no_depth")) {
                try w.writeAll(" { ");
                inline for (@typeInfo(P).@"struct".field_names, 0..) |f, i| {
                    if (i > 0) try w.writeAll(", ");
                    try w.writeAll(f ++ ": ");
                    try writeDebug(w, @field(payload, f));
                }
                return w.writeAll(" }");
            }
            if (@typeInfo(P) == .@"struct" and @typeInfo(P).@"struct".is_tuple) {
                try w.writeByte('(');
                inline for (@typeInfo(P).@"struct".field_names, 0..) |f, i| {
                    if (i > 0) try w.writeAll(", ");
                    try writeDebug(w, @field(payload, f));
                }
                return w.writeByte(')');
            }
            try w.writeByte('(');
            try writeDebug(w, payload);
            try w.writeByte(')');
        },
    }
}

const testing = std.testing;

test "decode, display and categorize a few errors" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // UserInputError::GasPriceUnderRGP { gas_price: 5, reference_gas_price: 750 }
    var buf: [64]u8 = undefined;
    var bw = bcs.Writer.init(&buf);
    const e: SuiErrorKind = .{ .UserInputError = .{ .@"error" = .{ .GasPriceUnderRGP = .{ .gas_price = 5, .reference_gas_price = 750 } } } };
    try bcs.encode(SuiErrorKind, &e, &bw);
    const d = try decode(arena, bw.written());
    try testing.expectEqualStrings("Error checking transaction input objects: Gas price 5 under reference gas price (RGP) 750", try d.text(arena));
    try testing.expectEqualStrings("Gas price 5 under reference gas price (RGP) 750", try d.requestErrorText(arena));
    try testing.expectEqual(ErrorCategory.InvalidTransaction, d.categorize());
    const nf: SuiErrorKind = .{ .UserInputError = .{ .@"error" = .{ .ObjectNotFound = .{ .object_id = .{ .@"0" = .{ .@"0" = @splat(0xab) } }, .version = .{ .@"0" = 7 } } } } };
    try testing.expectEqual(ErrorCategory.Aborted, nf.categorize());
    try testing.expect(nf.isRetryable().retryable);
    try testing.expectEqualStrings("Error checking transaction input objects: Could not find the referenced object 0xabababababababababababababababababababababababababababababababab at version Some(SequenceNumber(7))", try nf.text(arena));
    const rpc = try fromStatus(arena, 14, "conn reset", "");
    try testing.expectEqualStrings("The service is currently unavailable - conn reset", try rpc.text(arena));
    try testing.expectEqual(SuiErrorKind.TooManyRequests, try fromStatus(arena, 8, "Too many requests", ""));
    const lock: SuiErrorKind = .{ .ObjectLockConflict = .{ .obj_ref = .{ .{ .@"0" = .{ .@"0" = @splat(1) } }, .{ .@"0" = 3 }, .{ .@"0" = .{ .@"0" = @splat(0) } } }, .pending_transaction = .{ .@"0" = .{ .@"0" = @splat(0) } } } };
    try testing.expectEqual(ErrorCategory.LockConflict, lock.categorize());
    const t = try lock.text(arena);
    try testing.expect(std.mem.startsWith(u8, t, "Object (0x0101"));
    try testing.expect(std.mem.indexOf(u8, t, ", SequenceNumber(3), o#11111111111111111111111111111111) already locked by a different transaction: TransactionDigest(11111111111111111111111111111111)") != null);
}
