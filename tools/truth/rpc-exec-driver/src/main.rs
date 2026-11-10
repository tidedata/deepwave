//! zui-truth-rpc-exec-driver: ground truth for deepwave's ExecuteTransaction (src/rpc_exec/driver).
//!
//! `gen <corpus> <out>` writes, for 48 evenly spaced corpus checkpoints at protocol 119 or later,
//! the validator wire messages (sui-types `messages_grpc` Raw* prost messages, made by Mysten's own
//! conversions) and the replies of Mysten's real `sui_rpc_api::RpcService::execute_transaction`
//! (with a fake `TransactionExecutor` that returns the corpus effects, events and objects, filtered
//! like the transaction orchestrator) for a set of request cases.
//!
//! `errors <out>` writes hand-constructed `SuiError` values (BCS, Display, categorize, is_retryable),
//! the `SuiError::from(tonic::Status)` conversion and `TransactionDriverError` texts with the gRPC
//! status tonic sends for them. Formats: README.md. Nothing here talks to a network.
use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use consensus_config::AuthorityIndex;
use consensus_types::block::{BlockDigest, BlockRef};
use sui_core::transaction_driver::TransactionDriverError;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::transaction_execution_service_server::TransactionExecutionService;
use sui_rpc::proto::sui::rpc::v2::{Bcs, ExecuteTransactionRequest, Transaction as ProtoTransaction, UserSignature as ProtoUserSignature};
use sui_types::base_types::{AuthorityName, ObjectID, ObjectRef, SequenceNumber, SuiAddress};
use sui_types::committee::{Committee, EpochId};
use sui_types::message_envelope::Message as _;
use sui_types::digests::{ChainIdentifier, CheckpointContentsDigest, CheckpointDigest, ObjectDigest, TransactionDigest, TransactionEffectsDigest};
use sui_types::effects::{TransactionEffects, TransactionEffectsAPI, TransactionEvents};
use sui_types::error::{ErrorCategory, SuiError, SuiErrorKind, SuiResult, UserInputError};
use sui_types::full_checkpoint_content::{CheckpointData, ObjectSet};
use sui_types::messages_checkpoint::{CheckpointContents, CheckpointSequenceNumber, VerifiedCheckpoint, VersionedFullCheckpointContents};
use sui_types::messages_consensus::ConsensusPosition;
use sui_types::messages_grpc::{
    ExecutedData, PingType, RawSubmitTxResponse, RawSubmitTxResult, RawWaitForEffectsRequest, RawWaitForEffectsResponse, SubmitTxRequest, SubmitTxResult,
    WaitForEffectsRequest, WaitForEffectsResponse,
};
use sui_types::object::{Object, Owner};
use sui_types::storage::{ObjectKey, ObjectStore, PackageObject, RpcIndexes, RpcStateReader};
use sui_types::transaction::{TransactionData, TransactionDataAPI, VerifiedTransaction};
use sui_types::transaction_driver_types::{
    EffectsFinalityInfo, ExecuteTransactionRequestV3, ExecuteTransactionResponseV3, FinalizedEffects, TransactionSubmissionError,
};
use sui_types::transaction_executor::{SimulateTransactionResult, TransactionChecks, TransactionExecutor};

// ------------------------------------------------------------------------------------------
// Encoding helpers

fn put_u32(b: &mut Vec<u8>, x: u32) {
    b.extend_from_slice(&x.to_le_bytes());
}
fn put_u64(b: &mut Vec<u8>, x: u64) {
    b.extend_from_slice(&x.to_le_bytes());
}
fn put_blob(b: &mut Vec<u8>, x: &[u8]) {
    put_u32(b, x.len() as u32);
    b.extend_from_slice(x);
}
fn objects_list(objs: &[Object]) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    put_u32(&mut b, objs.len() as u32);
    for o in objs {
        put_blob(&mut b, &bcs::to_bytes(o)?);
    }
    Ok(b)
}
fn enc<M: prost::Message>(m: &M) -> Vec<u8> {
    prost::Message::encode_to_vec(m)
}

fn cat(c: ErrorCategory) -> u8 {
    match c {
        ErrorCategory::Aborted => 0,
        ErrorCategory::InvalidTransaction => 1,
        ErrorCategory::LockConflict => 2,
        ErrorCategory::Internal => 3,
        ErrorCategory::ValidatorOverloaded => 4,
        ErrorCategory::Unavailable => 5,
    }
}

// ------------------------------------------------------------------------------------------
// Corpus

fn decode_chk(path: &Path) -> Result<CheckpointData> {
    let raw = std::fs::read(path).with_context(|| path.display().to_string())?;
    if raw.first() != Some(&1) {
        bail!("{}: bad blob tag", path.display());
    }
    Ok(bcs::from_bytes(&raw[1..])?)
}

/// Corpus checkpoints at protocol 119 or later (tools/truth/rpc-exec ev4_seqs), then 48 evenly spaced.
fn pick_seqs(corpus: &Path, n: usize) -> Result<Vec<u64>> {
    let mut pv: Vec<u64> = Vec::new();
    for line in std::fs::read_to_string(corpus.join("epochs.jsonl"))?.lines() {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let e = v["epoch"].as_u64().context("epoch")? as usize;
        if pv.len() <= e {
            pv.resize(e + 1, 0);
        }
        pv[e] = v["pv"].as_u64().unwrap_or(0);
    }
    let mut seqs = Vec::new();
    for line in std::fs::read_to_string(corpus.join("manifest.jsonl"))?.lines() {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let (Some(seq), Some(epoch)) = (v["seq"].as_u64(), v["epoch"].as_u64()) else { continue };
        if pv.get(epoch as usize).copied().unwrap_or(0) >= 119 {
            seqs.push(seq);
        }
    }
    let len = seqs.len();
    if len <= n {
        return Ok(seqs);
    }
    Ok((0..n).map(|i| seqs[i * len / n]).collect())
}

// ------------------------------------------------------------------------------------------
// gen (a): validator wire messages

fn first_gas_ref(td: &TransactionData) -> ObjectRef {
    td.gas_data().payment.first().copied().unwrap_or((ObjectID::ZERO, SequenceNumber::from_u64(0), ObjectDigest::new([0; 32])))
}

fn wire_one(seq: u64, data: &CheckpointData) -> Result<Vec<u8>> {
    let epoch = data.checkpoint_summary.epoch;
    let mut rec = Vec::new();
    for (i, t) in data.transactions.iter().enumerate() {
        let td = t.transaction.data().transaction_data();
        if td.kind().is_system_tx() {
            continue;
        }
        let digest = *t.transaction.digest();
        let effects_digest = t.effects.digest();
        let pos = ConsensusPosition {
            epoch,
            block: BlockRef::new(seq as u32, AuthorityIndex::new_for_test(i as u32 % 4), BlockDigest(digest.into_inner())),
            index: i as u16,
        };
        let executed = || ExecutedData {
            effects: t.effects.clone(),
            events: t.events.clone(),
            input_objects: t.input_objects.clone(),
            output_objects: t.output_objects.clone(),
        };
        let gas = first_gas_ref(td);
        let mut blobs: Vec<Vec<u8>> = Vec::new();
        blobs.push(bcs::to_bytes(&t.transaction)?); // 0
        blobs.push(enc(&SubmitTxRequest::new_transaction(t.transaction.clone()).into_raw()?)); // 1
        blobs.push(enc(&SubmitTxRequest::new_ping().into_raw()?)); // 2
        blobs.push(bcs::to_bytes(&pos)?); // 3
        let submitted = RawSubmitTxResponse { results: vec![RawSubmitTxResult::try_from(SubmitTxResult::Submitted { consensus_position: pos })?] };
        blobs.push(enc(&submitted)); // 4
        blobs.push(bcs::to_bytes(&t.effects)?); // 5
        blobs.push(match &t.events {
            Some(e) => bcs::to_bytes(e)?,
            None => vec![],
        }); // 6
        blobs.push(objects_list(&t.input_objects)?); // 7
        blobs.push(objects_list(&t.output_objects)?); // 8
        let exec = RawSubmitTxResponse {
            results: vec![RawSubmitTxResult::try_from(SubmitTxResult::Executed { effects_digest, details: Some(Box::new(executed())) })?],
        };
        blobs.push(enc(&exec)); // 9
        let rejected_err: SuiError = SuiErrorKind::UserInputError {
            error: UserInputError::ObjectVersionUnavailableForConsumption { provided_obj_ref: gas, current_version: gas.1.next() },
        }
        .into();
        let rejected = RawSubmitTxResponse { results: vec![RawSubmitTxResult::try_from(SubmitTxResult::Rejected { error: rejected_err })?] };
        blobs.push(enc(&rejected)); // 10
        let w = |d: Option<TransactionDigest>, p: Option<ConsensusPosition>, det: bool, ping: Option<PingType>| -> Result<Vec<u8>> {
            let r = RawWaitForEffectsRequest::try_from(WaitForEffectsRequest { transaction_digest: d, consensus_position: p, include_details: det, ping_type: ping })?;
            Ok(enc(&r))
        };
        blobs.push(w(Some(digest), Some(pos), true, None)?); // 11
        blobs.push(w(Some(digest), None, false, None)?); // 12
        blobs.push(w(None, Some(pos), false, Some(PingType::Consensus))?); // 13
        let r = |x: WaitForEffectsResponse| -> Result<Vec<u8>> { Ok(enc(&RawWaitForEffectsResponse::try_from(x)?)) };
        blobs.push(r(WaitForEffectsResponse::Executed { effects_digest, details: None })?); // 14
        blobs.push(r(WaitForEffectsResponse::Executed { effects_digest, details: Some(Box::new(executed())) })?); // 15
        blobs.push(r(WaitForEffectsResponse::Rejected { error: Some(SuiErrorKind::ObjectLockConflict { obj_ref: gas, pending_transaction: digest }.into()) })?); // 16
        blobs.push(r(WaitForEffectsResponse::Rejected { error: None })?); // 17
        blobs.push(r(WaitForEffectsResponse::Expired { epoch, round: Some(seq as u32) })?); // 18
        blobs.push(r(WaitForEffectsResponse::Expired { epoch, round: None })?); // 19
        blobs.push(effects_digest.into_inner().to_vec()); // 20
        put_u32(&mut rec, i as u32);
        rec.push(blobs.len() as u8);
        for b in &blobs {
            put_blob(&mut rec, b);
        }
    }
    Ok(rec)
}

// ------------------------------------------------------------------------------------------
// gen (b): RpcService::execute_transaction with a fake executor

/// A state reader with nothing in it: the execute path only asks for the chain id, package
/// layouts (json: none), display objects and packages for clever errors (none).
struct Empty;

impl ObjectStore for Empty {
    fn get_object(&self, _id: &ObjectID) -> Option<Object> {
        None
    }
    fn get_object_by_key(&self, _id: &ObjectID, _v: SequenceNumber) -> Option<Object> {
        None
    }
}
impl sui_types::storage::BackingPackageStore for Empty {
    fn get_package_object(&self, _id: &ObjectID) -> SuiResult<Option<PackageObject>> {
        Ok(None)
    }
}
impl sui_types::storage::RuntimeObjectResolver for Empty {
    fn read_child_object(&self, _p: &ObjectID, _c: &ObjectID, _u: SequenceNumber) -> SuiResult<Option<Object>> {
        Ok(None)
    }
    fn get_object_received_at_version(&self, _o: &ObjectID, _r: &ObjectID, _v: SequenceNumber, _e: EpochId) -> SuiResult<Option<Object>> {
        Ok(None)
    }
}
impl sui_types::storage::ParentSync for Empty {
    fn get_latest_parent_entry_ref_deprecated(&self, _id: ObjectID) -> Option<ObjectRef> {
        None
    }
}
impl sui_types::storage::ReadStore for Empty {
    fn get_committee(&self, _epoch: EpochId) -> Option<Arc<Committee>> {
        None
    }
    fn get_latest_checkpoint(&self) -> sui_types::storage::error::Result<VerifiedCheckpoint> {
        Err(sui_types::storage::error::Error::missing("no checkpoints"))
    }
    fn get_highest_verified_checkpoint(&self) -> sui_types::storage::error::Result<VerifiedCheckpoint> {
        self.get_latest_checkpoint()
    }
    fn get_highest_synced_checkpoint(&self) -> sui_types::storage::error::Result<VerifiedCheckpoint> {
        self.get_latest_checkpoint()
    }
    fn get_lowest_available_checkpoint(&self) -> sui_types::storage::error::Result<CheckpointSequenceNumber> {
        Ok(0)
    }
    fn get_checkpoint_by_digest(&self, _d: &CheckpointDigest) -> Option<VerifiedCheckpoint> {
        None
    }
    fn get_checkpoint_by_sequence_number(&self, _s: CheckpointSequenceNumber) -> Option<VerifiedCheckpoint> {
        None
    }
    fn get_checkpoint_contents_by_digest(&self, _d: &CheckpointContentsDigest) -> Option<CheckpointContents> {
        None
    }
    fn get_checkpoint_contents_by_sequence_number(&self, _s: CheckpointSequenceNumber) -> Option<CheckpointContents> {
        None
    }
    fn get_transaction(&self, _d: &TransactionDigest) -> Option<Arc<VerifiedTransaction>> {
        None
    }
    fn get_transaction_effects(&self, _d: &TransactionDigest) -> Option<TransactionEffects> {
        None
    }
    fn get_events(&self, _d: &TransactionDigest) -> Option<TransactionEvents> {
        None
    }
    fn get_unchanged_loaded_runtime_objects(&self, _d: &TransactionDigest) -> Option<Vec<ObjectKey>> {
        None
    }
    fn get_transaction_checkpoint(&self, _d: &TransactionDigest) -> Option<CheckpointSequenceNumber> {
        None
    }
    fn get_full_checkpoint_contents(&self, _s: Option<CheckpointSequenceNumber>, _d: &CheckpointContentsDigest) -> Option<VersionedFullCheckpointContents> {
        None
    }
}
impl RpcStateReader for Empty {
    fn get_lowest_available_checkpoint_objects(&self) -> sui_types::storage::error::Result<CheckpointSequenceNumber> {
        Ok(0)
    }
    fn get_chain_identifier(&self) -> sui_types::storage::error::Result<ChainIdentifier> {
        Ok(sui_types::digests::get_mainnet_chain_identifier())
    }
    fn indexes(&self) -> Option<&dyn RpcIndexes> {
        None
    }
    fn get_struct_layout_with_overlay(
        &self,
        _t: &move_core_types::language_storage::StructTag,
        _o: &ObjectSet,
    ) -> sui_types::storage::error::Result<Option<move_core_types::annotated_value::MoveTypeLayout>> {
        Ok(None)
    }
}

/// Fake executor: the corpus transaction's effects, events and objects, filtered like
/// `TransactionOrchestrator::execute_transaction_with_effects_waiting` (and empty object lists
/// become None like `EffectsCertifier::get_quorum_transaction_response`), or an error (mode).
struct Fake {
    effects: TransactionEffects,
    events: Option<TransactionEvents>,
    input: Vec<Object>,
    output: Vec<Object>,
    mode: AtomicU8,
}

fn fake_error(mode: u8) -> TransactionSubmissionError {
    use TransactionSubmissionError::*;
    let failed = |category, details: &str| TransactionFailed { category, details: details.to_string() };
    match mode {
        20 => failed(ErrorCategory::InvalidTransaction, "d-invalid"),
        21 => TimeoutBeforeFinality,
        22 => TimeoutBeforeFinalityWithErrors { last_error: "last".into(), attempts: 3, timeout: Duration::from_secs(90) },
        23 => failed(ErrorCategory::Aborted, "d-aborted"),
        24 => failed(ErrorCategory::LockConflict, "d-lock"),
        25 => failed(ErrorCategory::ValidatorOverloaded, "d-overload"),
        26 => failed(ErrorCategory::Unavailable, "d-unavail"),
        27 => failed(ErrorCategory::Internal, "d-internal"),
        28 => InvalidUserSignature(SuiErrorKind::UserInputError { error: UserInputError::IncorrectUserSignature { error: "bad sig".into() } }.into()),
        29 => InvalidUserSignature(SuiErrorKind::InvalidSignature { error: "nope".into() }.into()),
        30 => TxAlreadyFinalizedWithDifferentUserSignatures,
        31 => SystemOverload { overloaded_stake: 5000, errors: vec![] },
        32 => TransactionDriverInternalError(SuiErrorKind::Unknown("boom".into()).into()),
        33 => SystemOverloadRetryAfter { overload_stake: 3400, errors: vec![], retry_after_secs: 7 },
        34 => FailedWithTransientErrorAfterMaximumAttempts { total_attempts: 5 },
        35 => {
            let mut m = BTreeMap::new();
            let (c, _) = Committee::new_simple_test_committee();
            let names: Vec<AuthorityName> = c.names().copied().collect();
            m.insert(TransactionDigest::new([7; 32]), (vec![(names[0], oref(3)), (names[1], oref(4))], 5000));
            ObjectsDoubleUsed { conflicting_txes: m }
        }
        36 => NonRecoverableTransactionError {
            errors: vec![
                (SuiErrorKind::TimeoutError.into(), 2500, vec![]),
                (SuiErrorKind::UserInputError { error: UserInputError::GasBudgetTooHigh { gas_budget: 9, max_budget: 5 } }.into(), 5000, vec![]),
                (SuiErrorKind::InvalidSignature { error: "sig".into() }.into(), 2500, vec![]),
            ],
        },
        _ => unreachable!(),
    }
}

#[async_trait::async_trait]
impl TransactionExecutor for Fake {
    async fn execute_transaction(&self, r: ExecuteTransactionRequestV3, _a: Option<std::net::SocketAddr>) -> Result<ExecuteTransactionResponseV3, TransactionSubmissionError> {
        let mode = self.mode.load(Ordering::Relaxed);
        if mode != 0 {
            return Err(fake_error(mode));
        }
        let nonempty = |v: &Vec<Object>| if v.is_empty() { None } else { Some(v.clone()) };
        Ok(ExecuteTransactionResponseV3 {
            effects: FinalizedEffects { effects: self.effects.clone(), finality_info: EffectsFinalityInfo::QuorumExecuted(self.effects.executed_epoch()) },
            events: if r.include_events { self.events.clone() } else { None },
            input_objects: if r.include_input_objects { nonempty(&self.input) } else { None },
            output_objects: if r.include_output_objects { nonempty(&self.output) } else { None },
            auxiliary_data: None,
        })
    }

    fn simulate_transaction(&self, _t: TransactionData, _c: TransactionChecks, _m: bool) -> Result<SimulateTransactionResult, SuiError> {
        unimplemented!("execute truth never simulates")
    }
}

const CASES: &[(u8, &str)] = &[
    (1, "no read_mask (default `effects`)"),
    (2, "read_mask `*`"),
    (3, "read_mask `digest,transaction,signatures,events,balance_changes`"),
    (4, "read_mask `objects,effects.status,effects.gas_used,effects.changed_objects`"),
    (5, "read_mask `transaction.bcs,effects.bcs,events.bcs,signatures.bcs`"),
    (6, "read_mask present with zero paths"),
    (10, "transaction bcs truncated by one byte (first user tx of a checkpoint only, as are all cases >= 10)"),
    (11, "three signatures (corpus signatures repeated)"),
    (12, "two signatures, the second raw bytes 00 01 02"),
    (13, "read_mask `effects.nope`"),
    (14, "no transaction field"),
    (15, "transaction bcs with one extra 00 byte appended"),
    (16, "one signature = 09 ++ 64 zero bytes"),
    (17, "one signature = empty bytes"),
    (18, "one signature = 00 ++ 96 zero bytes (well-formed ed25519 shape)"),
    (19, "transaction message present with neither bcs nor version"),
    (20, "executor: TransactionFailed{InvalidTransaction, d-invalid}"),
    (21, "executor: TimeoutBeforeFinality"),
    (22, "executor: TimeoutBeforeFinalityWithErrors{last, 3, 90s}"),
    (23, "executor: TransactionFailed{Aborted, d-aborted}"),
    (24, "executor: TransactionFailed{LockConflict, d-lock}"),
    (25, "executor: TransactionFailed{ValidatorOverloaded, d-overload}"),
    (26, "executor: TransactionFailed{Unavailable, d-unavail}"),
    (27, "executor: TransactionFailed{Internal, d-internal}"),
    (28, "executor: InvalidUserSignature(UserInputError::IncorrectUserSignature{bad sig})"),
    (29, "executor: InvalidUserSignature(InvalidSignature{nope})"),
    (30, "executor: TxAlreadyFinalizedWithDifferentUserSignatures"),
    (31, "executor: SystemOverload{5000, []}"),
    (32, "executor: TransactionDriverInternalError(Unknown(boom))"),
    (33, "executor: SystemOverloadRetryAfter{3400, [], 7}"),
    (34, "executor: FailedWithTransientErrorAfterMaximumAttempts{5}"),
    (35, "executor: ObjectsDoubleUsed{one conflicting tx, two authorities}"),
    (36, "executor: NonRecoverableTransactionError{TimeoutError 2500, GasBudgetTooHigh 5000, InvalidSignature 2500}"),
];

fn tx_msg(bcs_value: Option<Vec<u8>>) -> ProtoTransaction {
    let mut t = ProtoTransaction::default();
    if let Some(v) = bcs_value {
        let mut b = Bcs::default();
        b.name = Some("TransactionData".to_owned());
        b.value = Some(v.into());
        t.bcs = Some(b);
    }
    t
}

fn sig_msg(raw: &[u8]) -> ProtoUserSignature {
    let mut s = ProtoUserSignature::default();
    let mut b = Bcs::default();
    b.value = Some(raw.to_vec().into());
    s.bcs = Some(b);
    s
}

fn request(tx: Option<ProtoTransaction>, sigs: &[Vec<u8>], mask: Option<FieldMask>) -> ExecuteTransactionRequest {
    let mut r = ExecuteTransactionRequest::default();
    r.transaction = tx;
    r.signatures = sigs.iter().map(|s| sig_msg(s)).collect();
    r.read_mask = mask;
    r
}

#[derive(Default)]
struct Counts {
    txs: AtomicU64,
    cases: AtomicU64,
    by_code: [AtomicU64; 17],
}

fn handler_one(data: &CheckpointData, counts: &Counts) -> Result<Vec<u8>> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let mut rec = Vec::new();
    let mut first = true;
    for (i, t) in data.transactions.iter().enumerate() {
        let td = t.transaction.data().transaction_data();
        if td.kind().is_system_tx() {
            continue;
        }
        let tx_bcs = bcs::to_bytes(td)?;
        let sigs: Vec<Vec<u8>> = t.transaction.data().tx_signatures().iter().map(|s| s.as_ref().to_vec()).collect();
        let fake = Arc::new(Fake {
            effects: t.effects.clone(),
            events: t.events.clone(),
            input: t.input_objects.clone(),
            output: t.output_objects.clone(),
            mode: AtomicU8::new(0),
        });
        let mut svc = sui_rpc_api::RpcService::new(Arc::new(Empty));
        svc.with_executor(fake.clone());

        let full = || Some(tx_msg(Some(tx_bcs.clone())));
        let mut cases: Vec<(u8, ExecuteTransactionRequest)> = vec![
            (1, request(full(), &sigs, None)),
            (2, request(full(), &sigs, Some(FieldMask::from_str("*")))),
            (3, request(full(), &sigs, Some(FieldMask::from_str("digest,transaction,signatures,events,balance_changes")))),
            (4, request(full(), &sigs, Some(FieldMask::from_str("objects,effects.status,effects.gas_used,effects.changed_objects")))),
            (5, request(full(), &sigs, Some(FieldMask::from_str("transaction.bcs,effects.bcs,events.bcs,signatures.bcs")))),
            (6, request(full(), &sigs, Some(FieldMask::default()))),
        ];
        if first {
            first = false;
            cases.push((10, request(Some(tx_msg(Some(tx_bcs[..tx_bcs.len() - 1].to_vec()))), &sigs, None)));
            let three: Vec<Vec<u8>> = (0..3).map(|k| sigs[k % sigs.len()].clone()).collect();
            cases.push((11, request(full(), &three, None)));
            cases.push((12, request(full(), &[sigs[0].clone(), vec![0, 1, 2]], None)));
            cases.push((13, request(full(), &sigs, Some(FieldMask::from_str("effects.nope")))));
            cases.push((14, request(None, &sigs, None)));
            let mut extra = tx_bcs.clone();
            extra.push(0);
            cases.push((15, request(Some(tx_msg(Some(extra))), &sigs, None)));
            let mut s16 = vec![9u8];
            s16.extend_from_slice(&[0; 64]);
            cases.push((16, request(full(), &[s16], None)));
            cases.push((17, request(full(), &[vec![]], None)));
            let mut s18 = vec![0u8];
            s18.extend_from_slice(&[0; 96]);
            cases.push((18, request(full(), &[s18], None)));
            cases.push((19, request(Some(tx_msg(None)), &sigs, None)));
            for m in 20..=36u8 {
                cases.push((m, request(full(), &sigs, None)));
            }
        }

        put_u32(&mut rec, i as u32);
        put_blob(&mut rec, &tx_bcs);
        put_u32(&mut rec, sigs.len() as u32);
        for s in &sigs {
            put_blob(&mut rec, s);
        }
        put_blob(&mut rec, &bcs::to_bytes(&t.effects)?);
        put_blob(&mut rec, &match &t.events {
            Some(e) => bcs::to_bytes(e)?,
            None => vec![],
        });
        rec.extend_from_slice(&objects_list(&t.input_objects)?);
        rec.extend_from_slice(&objects_list(&t.output_objects)?);
        rec.push(cases.len() as u8);
        for (case, req) in cases {
            fake.mode.store(if case >= 20 { case } else { 0 }, Ordering::Relaxed);
            let req_bytes = enc(&req);
            let r = rt.block_on(TransactionExecutionService::execute_transaction(&svc, tonic::Request::new(req)));
            let (code, msg, det, resp) = match r {
                Ok(resp) => (0u8, String::new(), vec![], enc(resp.get_ref())),
                Err(st) => (st.code() as i32 as u8, st.message().to_string(), st.details().to_vec(), vec![]),
            };
            counts.cases.fetch_add(1, Ordering::Relaxed);
            counts.by_code[code as usize].fetch_add(1, Ordering::Relaxed);
            rec.push(case);
            put_blob(&mut rec, &req_bytes);
            rec.push(code);
            put_blob(&mut rec, msg.as_bytes());
            put_blob(&mut rec, &det);
            put_blob(&mut rec, &resp);
        }
        counts.txs.fetch_add(1, Ordering::Relaxed);
    }
    Ok(rec)
}

fn cmd_gen(corpus: &Path, out: &Path) -> Result<()> {
    let seqs = pick_seqs(corpus, 48)?;
    std::fs::create_dir_all(out.join("wire"))?;
    std::fs::create_dir_all(out.join("handler"))?;
    std::fs::write(out.join("seqs.txt"), seqs.iter().map(|s| format!("{s}\n")).collect::<String>())?;
    std::fs::write(out.join("cases.txt"), CASES.iter().map(|(i, d)| format!("{i}\t{d}\n")).collect::<String>())?;
    let counts = Counts::default();
    let wire_txs = AtomicU64::new(0);
    let errs: Vec<String> = seqs
        .par_iter()
        .filter_map(|seq| {
            let r = (|| -> Result<()> {
                let data = decode_chk(&corpus.join(format!("chk/{seq}.chk")))?;
                let w = wire_one(*seq, &data)?;
                wire_txs.fetch_add(data.transactions.iter().filter(|t| !t.transaction.data().transaction_data().kind().is_system_tx()).count() as u64, Ordering::Relaxed);
                std::fs::write(out.join(format!("wire/{seq}.rec.zst")), zstd::encode_all(&w[..], 9)?)?;
                let h = handler_one(&data, &counts)?;
                std::fs::write(out.join(format!("handler/{seq}.rec.zst")), zstd::encode_all(&h[..], 9)?)?;
                Ok(())
            })();
            r.err().map(|e| format!("{seq}: {e:#}"))
        })
        .collect();
    for e in &errs {
        eprintln!("{e}");
    }
    let by: Vec<String> = counts.by_code.iter().enumerate().filter(|(_, c)| c.load(Ordering::Relaxed) > 0).map(|(i, c)| format!("\"{i}\":{}", c.load(Ordering::Relaxed))).collect();
    println!(
        "{{\"checkpoints\":{},\"errors\":{},\"wire_txs\":{},\"handler_txs\":{},\"cases\":{},\"by_code\":{{{}}}}}",
        seqs.len(),
        errs.len(),
        wire_txs.load(Ordering::Relaxed),
        counts.txs.load(Ordering::Relaxed),
        counts.cases.load(Ordering::Relaxed),
        by.join(",")
    );
    if !errs.is_empty() {
        bail!("{} checkpoints failed", errs.len());
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------
// errors (a): SuiError values

fn bytes32(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = n.wrapping_mul(31).wrapping_add((i as u8).wrapping_mul(17)) ^ 0x5a;
    }
    b
}
fn oid(n: u8) -> ObjectID {
    ObjectID::new(bytes32(n))
}
fn sq(v: u64) -> SequenceNumber {
    SequenceNumber::from_u64(v)
}
fn odig(n: u8) -> ObjectDigest {
    ObjectDigest::new(bytes32(n.wrapping_add(100)))
}
fn tdig(n: u8) -> TransactionDigest {
    TransactionDigest::new(bytes32(n.wrapping_add(200)))
}
fn edig(n: u8) -> TransactionEffectsDigest {
    TransactionEffectsDigest::new(bytes32(n.wrapping_add(50)))
}
fn oref(n: u8) -> ObjectRef {
    (oid(n), sq(n as u64 * 7 + 1), odig(n))
}
fn addr(n: u8) -> SuiAddress {
    SuiAddress::from(oid(n))
}

const WEIRD: &str = "q\"uo\\te\nnl\ttab \u{1} é ✓";

fn owners() -> Vec<Owner> {
    vec![
        Owner::AddressOwner(addr(1)),
        Owner::ObjectOwner(addr(2)),
        Owner::Shared { initial_shared_version: sq(12) },
        Owner::Immutable,
        Owner::ConsensusAddressOwner { start_version: sq(99), owner: addr(3) },
    ]
}

/// Exhaustive (no wildcard): fails to compile when Mysten adds a variant.
fn uie_covered(e: &UserInputError) -> &'static str {
    use UserInputError::*;
    match e {
        MutableObjectUsedMoreThanOnce { .. } => "MutableObjectUsedMoreThanOnce",
        ObjectInputArityViolation => "ObjectInputArityViolation",
        ObjectNotFound { .. } => "ObjectNotFound",
        ObjectVersionUnavailableForConsumption { .. } => "ObjectVersionUnavailableForConsumption",
        PackageVerificationTimeout { .. } => "PackageVerificationTimeout",
        DependentPackageNotFound { .. } => "DependentPackageNotFound",
        ImmutableParameterExpectedError { .. } => "ImmutableParameterExpectedError",
        SizeLimitExceeded { .. } => "SizeLimitExceeded",
        InvalidChildObjectArgument { .. } => "InvalidChildObjectArgument",
        InvalidObjectDigest { .. } => "InvalidObjectDigest",
        InvalidSequenceNumber => "InvalidSequenceNumber",
        MovePackageAsObject { .. } => "MovePackageAsObject",
        MoveObjectAsPackage { .. } => "MoveObjectAsPackage",
        IncorrectUserSignature { .. } => "IncorrectUserSignature",
        NotSharedObjectError => "NotSharedObjectError",
        DuplicateObjectRefInput => "DuplicateObjectRefInput",
        MissingGasPayment => "MissingGasPayment",
        GasObjectNotOwnedObject { .. } => "GasObjectNotOwnedObject",
        GasBudgetTooHigh { .. } => "GasBudgetTooHigh",
        GasBudgetTooLow { .. } => "GasBudgetTooLow",
        GasBalanceTooLow { .. } => "GasBalanceTooLow",
        UnsupportedSponsoredTransactionKind => "UnsupportedSponsoredTransactionKind",
        GasPriceUnderRGP { .. } => "GasPriceUnderRGP",
        GasPriceTooHigh { .. } => "GasPriceTooHigh",
        InvalidGasObject { .. } => "InvalidGasObject",
        InsufficientBalanceToCoverMinimalGas => "InsufficientBalanceToCoverMinimalGas",
        ObjectSequenceNumberTooHigh { .. } => "ObjectSequenceNumberTooHigh",
        ObjectDeleted { .. } => "ObjectDeleted",
        InvalidBatchTransaction { .. } => "InvalidBatchTransaction",
        BlockedMoveFunction => "BlockedMoveFunction",
        EmptyInputCoins => "EmptyInputCoins",
        UnexpectedGasPaymentObject => "UnexpectedGasPaymentObject",
        SharedObjectStartingVersionMismatch => "SharedObjectStartingVersionMismatch",
        TransferObjectWithoutPublicTransferError { .. } => "TransferObjectWithoutPublicTransferError",
        EmptyCommandInput => "EmptyCommandInput",
        TransactionDenied { .. } => "TransactionDenied",
        Unsupported(..) => "Unsupported",
        MoveFunctionInputError(..) => "MoveFunctionInputError",
        VerifiedCheckpointNotFound(..) => "VerifiedCheckpointNotFound",
        VerifiedCheckpointDigestNotFound(..) => "VerifiedCheckpointDigestNotFound",
        LatestCheckpointSequenceNumberNotFound => "LatestCheckpointSequenceNumberNotFound",
        CheckpointContentsNotFound(..) => "CheckpointContentsNotFound",
        GenesisTransactionNotFound => "GenesisTransactionNotFound",
        TransactionCursorNotFound(..) => "TransactionCursorNotFound",
        InaccessibleSystemObject { .. } => "InaccessibleSystemObject",
        MaxPublishCountExceeded { .. } => "MaxPublishCountExceeded",
        MutableParameterExpected { .. } => "MutableParameterExpected",
        AddressDeniedForCoin { .. } => "AddressDeniedForCoin",
        PostRandomCommandRestrictions => "PostRandomCommandRestrictions",
        InvalidArgumentIndex { .. } => "InvalidArgumentIndex",
        TooManyTransactionsInBatch { .. } => "TooManyTransactionsInBatch",
        TotalTransactionSizeTooLargeInBatch { .. } => "TotalTransactionSizeTooLargeInBatch",
        NoSharedObjectError { .. } => "NoSharedObjectError",
        AlreadyExecutedInSoftBundleError { .. } => "AlreadyExecutedInSoftBundleError",
        CertificateAlreadyProcessed => "CertificateAlreadyProcessed",
        TransactionAlreadyExecuted { .. } => "TransactionAlreadyExecuted",
        GasPriceMismatchError { .. } => "GasPriceMismatchError",
        CoinTypeGlobalPause { .. } => "CoinTypeGlobalPause",
        InvalidIdentifier { .. } => "InvalidIdentifier",
        NotOwnedObjectError => "NotOwnedObjectError",
        InvalidWithdrawReservation { .. } => "InvalidWithdrawReservation",
        MissingTransactionExpiration => "MissingTransactionExpiration",
        InvalidExpiration { .. } => "InvalidExpiration",
        InvalidChainId { .. } => "InvalidChainId",
        RepeatedTransactions { .. } => "RepeatedTransactions",
        ProposerNotAllowed { .. } => "ProposerNotAllowed",
    }
}

fn user_input_errors() -> Vec<UserInputError> {
    use UserInputError::*;
    let mut v = vec![
        MutableObjectUsedMoreThanOnce { object_id: oid(1) },
        ObjectInputArityViolation,
        ObjectNotFound { object_id: oid(2), version: Some(sq(5)) },
        ObjectNotFound { object_id: oid(3), version: None },
        ObjectVersionUnavailableForConsumption { provided_obj_ref: oref(4), current_version: sq(300) },
        PackageVerificationTimeout { err: "too slow".into() },
        DependentPackageNotFound { package_id: oid(5) },
        ImmutableParameterExpectedError { object_id: oid(6) },
        SizeLimitExceeded { limit: "maximum pure argument size".into(), value: "16384".into() },
        InvalidChildObjectArgument { child_id: oid(7), parent_id: oid(8) },
        InvalidObjectDigest { object_id: oid(9), expected_digest: odig(9) },
        InvalidSequenceNumber,
        MovePackageAsObject { object_id: oid(10) },
        MoveObjectAsPackage { object_id: oid(11) },
        IncorrectUserSignature { error: WEIRD.into() },
        NotSharedObjectError,
        DuplicateObjectRefInput,
        MissingGasPayment,
    ];
    for o in owners() {
        v.push(GasObjectNotOwnedObject { owner: o });
    }
    v.extend([
        GasBudgetTooHigh { gas_budget: 50_000_000_001, max_budget: 50_000_000_000 },
        GasBudgetTooLow { gas_budget: 1, min_budget: 2000 },
        GasBalanceTooLow { gas_balance: 12, needed_gas_amount: u128::MAX },
        UnsupportedSponsoredTransactionKind,
        GasPriceUnderRGP { gas_price: 999, reference_gas_price: 1000 },
        GasPriceTooHigh { max_gas_price: 100_000_000_000 },
        InvalidGasObject { object_id: oid(12) },
        InsufficientBalanceToCoverMinimalGas,
        ObjectSequenceNumberTooHigh { object_id: oid(13), asked_version: sq(1000), latest_version: sq(17) },
        ObjectDeleted { object_ref: oref(14) },
        InvalidBatchTransaction { error: "bad batch".into() },
        BlockedMoveFunction,
        EmptyInputCoins,
        UnexpectedGasPaymentObject,
        SharedObjectStartingVersionMismatch,
        TransferObjectWithoutPublicTransferError { object_id: oid(15) },
        EmptyCommandInput,
        TransactionDenied { error: "denied by config".into() },
        Unsupported("feature x".into()),
        MoveFunctionInputError("bad input".into()),
        VerifiedCheckpointNotFound(123_456),
        VerifiedCheckpointDigestNotFound("abc".into()),
        LatestCheckpointSequenceNumberNotFound,
        CheckpointContentsNotFound(CheckpointContentsDigest::new(bytes32(77))),
        GenesisTransactionNotFound,
        TransactionCursorNotFound(42),
        InaccessibleSystemObject { object_id: oid(16) },
        MaxPublishCountExceeded { max_publish_commands: 1, publish_count: 3 },
        MutableParameterExpected { object_id: oid(17) },
        AddressDeniedForCoin { address: addr(18), coin_type: "0x2::sui::SUI".into() },
        PostRandomCommandRestrictions,
        InvalidArgumentIndex { command_idx: 3, argument_idx: 1, index: 65535 },
        TooManyTransactionsInBatch { size: 10, limit: 5 },
        TotalTransactionSizeTooLargeInBatch { size: 1_000_000, limit: 500_000 },
        NoSharedObjectError { digest: tdig(1) },
        AlreadyExecutedInSoftBundleError { digest: tdig(2) },
        CertificateAlreadyProcessed,
        TransactionAlreadyExecuted { digest: tdig(3) },
        GasPriceMismatchError { digest: tdig(4), expected: 1000, actual: 750 },
        CoinTypeGlobalPause { coin_type: "0xabc::coin::C".into() },
        InvalidIdentifier { error: "9bad".into() },
        NotOwnedObjectError,
        InvalidWithdrawReservation { error: "too much".into() },
        MissingTransactionExpiration,
        InvalidExpiration { error: "expired".into() },
        InvalidChainId { provided: "35834a8a".into(), expected: "4c78adac".into() },
        RepeatedTransactions { digest: tdig(5) },
        ProposerNotAllowed { proposer: 17 },
    ]);
    v
}

fn sui_kind_covered(e: &SuiErrorKind) -> &'static str {
    e.into()
}

/// Every SuiErrorKind variant with its exhaustive name list checked at compile time below.
fn sui_error_kinds(names: &[AuthorityName], committee: &Committee) -> Vec<SuiErrorKind> {
    use SuiErrorKind::*;
    let s = |x: &str| x.to_string();
    let mut map = BTreeMap::new();
    map.insert(edig(1), (vec![names[0], names[2]], 5000u64));
    map.insert(edig(2), (vec![names[1]], 2500u64));
    let mut v = vec![
        UnexpectedOwnerType,
        TooManyTransactionsPendingExecution { queue_len: 100_000, threshold: 50_000 },
        TooManyTransactionsPendingConsensus,
        TooManyTransactionsPendingOnObject { object_id: oid(20), queue_len: 7, threshold: 5 },
        TooOldTransactionPendingOnObject { object_id: oid(21), txn_age_sec: 30, threshold: 10 },
        InvalidTxKindInSoftBundle,
        InvalidSignature { error: s(WEIRD) },
        SignerSignatureAbsent { expected: s("0xabc"), actual: vec![s("a"), s(WEIRD)] },
        SignerSignatureAbsent { expected: s("0xdef"), actual: vec![] },
        SignerSignatureNumberMismatch { expected: 2, actual: 1 },
        IncorrectSigner { error: s("wrong signer") },
        UnknownSigner { signer: Some(s(WEIRD)), index: Some(3), committee: Box::new(committee.clone()) },
        UnknownSigner { signer: None, index: None, committee: Box::new(committee.clone()) },
        StakeAggregatorRepeatedSigner { signer: names[1], conflicting_sig: true },
        PotentiallyTemporarilyInvalidSignature { error: s("jwk not found") },
        WrongEpoch { expected_epoch: 900, actual_epoch: 899 },
        CertificateRequiresQuorum,
        DEPRECATED_ErrorWhileProcessingCertificate,
        QuorumFailedToGetEffectsQuorumWhenProcessingTransaction { effects_map: map },
        FailedToVerifyTxCertWithExecutedEffects { validator_name: names[3], error: s(WEIRD) },
        TxAlreadyFinalizedWithDifferentUserSigs,
        InvalidAuthenticator,
        InvalidAddress,
        InvalidTransactionDigest,
        InvalidDigestLength { expected: 32, actual: 31 },
        InvalidDkgMessageSize,
        UnexpectedMessage(s("unexpected")),
        ModuleVerificationFailure { error: s("verify") },
        ModuleDeserializationFailure { error: s("deser") },
        ModulePublishFailure { error: s("publish") },
        ModuleBuildFailure { error: s("build") },
        FunctionNotFound { error: s("fn") },
        ModuleNotFound { module_name: s("coin") },
        TypeError { error: s("type") },
        CircularObjectOwnership,
        ObjectLockAlreadyInitialized { refs: vec![oref(22), oref(23)] },
        ObjectLockAlreadyInitialized { refs: vec![] },
        ObjectLockConflict { obj_ref: oref(24), pending_transaction: tdig(6) },
        ObjectLockedAtFutureEpoch { obj_refs: vec![oref(25)], locked_epoch: 10, new_epoch: 9, locked_by_tx: tdig(7) },
        TransactionNotFound { digest: tdig(8) },
        TransactionsNotFound { digests: vec![tdig(9), tdig(10)] },
        TransactionEventsNotFound { digest: tdig(11) },
        TransactionEffectsNotFound { digest: tdig(12) },
        TransactionAlreadyExecuted { digest: tdig(13) },
        TransactionRejectReasonNotFound { digest: tdig(14) },
        BadObjectType { error: s("bad type") },
        FailObjectLayout { st: s("0x2::coin::Coin<0x2::sui::SUI>") },
        ExecutionInvariantViolation,
        ByzantineAuthoritySuspicion { authority: names[0], reason: s(WEIRD) },
        DEPRECATED_StorageError,
        DEPRECATED_GenericStorageError,
        DEPRECATED_StorageMissingFieldError,
        DEPRECATED_StorageCorruptedFieldError,
        GenericAuthorityError { error: s("generic") },
        GenericBridgeError { error: s("bridge") },
        FailedToDispatchSubscription { error: s("dispatch") },
        OwnerFailedToSerialize { error: s("owner") },
        ExtraFieldFailedToDeserialize { error: s("extra") },
        TransactionOrchestratorLocalExecutionError { error: s("local") },
        TransactionSerializationError { error: s("ts") },
        TransactionDeserializationError { error: s("td") },
        TransactionEffectsSerializationError { error: s("tes") },
        TransactionEffectsDeserializationError { error: s("ted") },
        TransactionEventsSerializationError { error: s("tvs") },
        TransactionEventsDeserializationError { error: s("tvd") },
        ObjectSerializationError { error: s("os") },
        ObjectDeserializationError { error: s("od") },
        NoEventStore,
        TooManyIncorrectAuthorities {
            errors: vec![(names[0], TimeoutError.into()), (names[2], UserInputError { error: crate::UserInputError::EmptyInputCoins }.into())],
            action: s("submit"),
        },
        FullNodeInvalidTxRangeQuery { error: s("range") },
        FailedToSubmitToConsensus(s("consensus")),
        ConsensusConnectionBroken(s("broken")),
        HandleConsensusTransactionFailure(s("handle")),
        SignatureKeyGenError(s("keygen")),
        KeyConversionError(s("conv")),
        InvalidPrivateKey,
        FullNodeCantHandleCertificate,
        ValidatorHaltedAtEpochEnd,
        EpochEnded(1001),
        AdvanceEpochError { error: s("advance") },
        TransactionExpired,
        RpcError(s("connection refused"), s("The service is currently unavailable")),
        InvalidRpcMethodError,
        UnsupportedFeatureError { error: s("unsupported") },
        QuorumDriverCommunicationError { error: s("qd") },
        TimeoutError,
        ExecutionError(s("InsufficientGas")),
        InvalidCommittee(s("committee")),
        MissingCommitteeAtEpoch(77),
        DynamicFieldReadError(s("df")),
        SuiSystemStateReadError(s("ss")),
        SuiBridgeReadError(s("br")),
        UnexpectedVersion(s("v")),
        WrongMessageVersion { error: s("wmv") },
        Unknown(s(WEIRD)),
        FileIOError(s("io")),
        JWKRetrievalError,
        Storage(s("rocks")),
        ValidatorOverloadedRetryAfter { retry_after_secs: 30 },
        TooManyRequests,
        NoCertificateProvidedError,
        NitroAttestationFailedToVerify(s("nitro")),
        GrpcMessageSerializeError { type_info: s("RawExecutedData.effects"), error: s("ser") },
        GrpcMessageDeserializeError { type_info: s("RawSubmitTxResult.inner"), error: s("RawSubmitTxResult.inner is None") },
        ValidatorConsensusLagging { round: 100, last_committed_round: 90 },
        InvalidAdminRequest(s("admin")),
        InvalidRequest(s("request")),
        AliasesChanged,
        ImmutableObjectClaimNotFoundInInput { object_id: oid(26) },
        ImmutableObjectNotClaimed { object_id: oid(27) },
        InvalidImmutableObjectClaim { claimed_object_id: oid(28), found_object_ref: oref(29) },
        TransactionRejectedDueToOutbiddingDuringCongestion { min_gas_price: 1500 },
        TransactionProcessing { digest: tdig(15), status: s("executing") },
        TransactionSubmitted { digest: tdig(16) },
        StaggeredSubmissionNotProposer,
    ];
    for o in owners() {
        v.push(InvalidChildObjectAccess { object: oid(30), given_parent: oid(31), actual_owner: o });
    }
    v.push(SuiObjectResponseError { error: sui_types::error::SuiObjectResponseError::NotExists { object_id: oid(32) } });
    v
}

/// Compile-time exhaustiveness of the SuiErrorKind list (no wildcard arm).
#[allow(dead_code)]
fn sui_kind_exhaustive(e: &SuiErrorKind) {
    use SuiErrorKind::*;
    match e {
        UserInputError { .. } | SuiObjectResponseError { .. } | UnexpectedOwnerType | TooManyTransactionsPendingExecution { .. } | TooManyTransactionsPendingConsensus
        | TooManyTransactionsPendingOnObject { .. } | TooOldTransactionPendingOnObject { .. } | InvalidTxKindInSoftBundle | InvalidSignature { .. }
        | SignerSignatureAbsent { .. } | SignerSignatureNumberMismatch { .. } | IncorrectSigner { .. } | UnknownSigner { .. } | StakeAggregatorRepeatedSigner { .. }
        | PotentiallyTemporarilyInvalidSignature { .. } | WrongEpoch { .. } | CertificateRequiresQuorum | DEPRECATED_ErrorWhileProcessingCertificate
        | QuorumFailedToGetEffectsQuorumWhenProcessingTransaction { .. } | FailedToVerifyTxCertWithExecutedEffects { .. } | TxAlreadyFinalizedWithDifferentUserSigs
        | InvalidAuthenticator | InvalidAddress | InvalidTransactionDigest | InvalidDigestLength { .. } | InvalidDkgMessageSize | UnexpectedMessage(..)
        | ModuleVerificationFailure { .. } | ModuleDeserializationFailure { .. } | ModulePublishFailure { .. } | ModuleBuildFailure { .. } | FunctionNotFound { .. }
        | ModuleNotFound { .. } | TypeError { .. } | CircularObjectOwnership | ObjectLockAlreadyInitialized { .. } | ObjectLockConflict { .. }
        | ObjectLockedAtFutureEpoch { .. } | TransactionNotFound { .. } | TransactionsNotFound { .. } | TransactionEventsNotFound { .. }
        | TransactionEffectsNotFound { .. } | TransactionAlreadyExecuted { .. } | TransactionRejectReasonNotFound { .. } | BadObjectType { .. }
        | FailObjectLayout { .. } | ExecutionInvariantViolation | ByzantineAuthoritySuspicion { .. } | DEPRECATED_StorageError | DEPRECATED_GenericStorageError
        | InvalidChildObjectAccess { .. } | DEPRECATED_StorageMissingFieldError | DEPRECATED_StorageCorruptedFieldError | GenericAuthorityError { .. }
        | GenericBridgeError { .. } | FailedToDispatchSubscription { .. } | OwnerFailedToSerialize { .. } | ExtraFieldFailedToDeserialize { .. }
        | TransactionOrchestratorLocalExecutionError { .. } | TransactionSerializationError { .. } | TransactionDeserializationError { .. }
        | TransactionEffectsSerializationError { .. } | TransactionEffectsDeserializationError { .. } | TransactionEventsSerializationError { .. }
        | TransactionEventsDeserializationError { .. } | ObjectSerializationError { .. } | ObjectDeserializationError { .. } | NoEventStore
        | TooManyIncorrectAuthorities { .. } | FullNodeInvalidTxRangeQuery { .. } | FailedToSubmitToConsensus(..) | ConsensusConnectionBroken(..)
        | HandleConsensusTransactionFailure(..) | SignatureKeyGenError(..) | KeyConversionError(..) | InvalidPrivateKey | FullNodeCantHandleCertificate
        | ValidatorHaltedAtEpochEnd | EpochEnded(..) | AdvanceEpochError { .. } | TransactionExpired | RpcError(..) | InvalidRpcMethodError
        | UnsupportedFeatureError { .. } | QuorumDriverCommunicationError { .. } | TimeoutError | ExecutionError(..) | InvalidCommittee(..)
        | MissingCommitteeAtEpoch(..) | DynamicFieldReadError(..) | SuiSystemStateReadError(..) | SuiBridgeReadError(..) | UnexpectedVersion(..)
        | WrongMessageVersion { .. } | Unknown(..) | FileIOError(..) | JWKRetrievalError | Storage(..) | ValidatorOverloadedRetryAfter { .. } | TooManyRequests
        | NoCertificateProvidedError | NitroAttestationFailedToVerify(..) | GrpcMessageSerializeError { .. } | GrpcMessageDeserializeError { .. }
        | ValidatorConsensusLagging { .. } | InvalidAdminRequest(..) | InvalidRequest(..) | AliasesChanged | ImmutableObjectClaimNotFoundInInput { .. }
        | ImmutableObjectNotClaimed { .. } | InvalidImmutableObjectClaim { .. } | TransactionRejectedDueToOutbiddingDuringCongestion { .. }
        | TransactionProcessing { .. } | TransactionSubmitted { .. } | StaggeredSubmissionNotProposer => {}
    }
}

fn request_error_text(e: &SuiError) -> String {
    match e.as_inner() {
        SuiErrorKind::UserInputError { error } => error.to_string(),
        _ => e.to_string(),
    }
}

fn put_str(b: &mut Vec<u8>, s: &str) {
    put_blob(b, s.as_bytes());
}

fn cmd_errors(out: &Path) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let (committee, _) = Committee::new_simple_test_committee();
    let names: Vec<AuthorityName> = committee.names().copied().collect();
    std::fs::write(out.join("committee.txt"), names.iter().enumerate().map(|(i, n)| format!("{i}\t{}\n", hex::encode(n.0))).collect::<String>())?;

    // (a) sui_errors.rec
    let mut all: Vec<SuiError> = user_input_errors().into_iter().map(|e| SuiErrorKind::UserInputError { error: e }.into()).collect();
    all.extend(sui_error_kinds(&names, &committee).into_iter().map(SuiError::from));
    let mut rec = Vec::new();
    let mut txt = String::new();
    let mut n = 0;
    let mut seen_uie = std::collections::BTreeSet::new();
    let mut seen_kind = std::collections::BTreeSet::new();
    for e in &all {
        let b = bcs::to_bytes(e)?;
        let back: Result<SuiError, _> = bcs::from_bytes(&b);
        let name = match e.as_inner() {
            SuiErrorKind::UserInputError { error } => format!("UserInputError::{}", uie_covered(error)),
            k => sui_kind_covered(k).to_string(),
        };
        match back {
            Ok(x) if &x == e => {}
            _ => {
                eprintln!("skipped (no BCS round trip): {name}");
                continue;
            }
        }
        if let SuiErrorKind::UserInputError { error } = e.as_inner() {
            seen_uie.insert(uie_covered(error));
        }
        seen_kind.insert(sui_kind_covered(e.as_inner()));
        let (retryable, categorized) = e.is_retryable();
        put_blob(&mut rec, &b);
        put_str(&mut rec, &e.to_string());
        put_str(&mut rec, &request_error_text(e));
        rec.push(cat(e.categorize()));
        rec.push(retryable as u8);
        rec.push(categorized as u8);
        txt.push_str(&format!("{n}\t{name}\n"));
        n += 1;
    }
    std::fs::write(out.join("sui_errors.rec"), &rec)?;
    std::fs::write(out.join("sui_errors.txt"), txt)?;
    println!("sui_errors: {n} records, {} UserInputError variants, {} SuiErrorKind variants", seen_uie.len(), seen_kind.len());

    // (b) status.rec
    let mut rec = Vec::new();
    let mut statuses: Vec<(i32, String, Vec<u8>)> = vec![(14, "Too many requests".into(), vec![]), (8, "Too many requests".into(), vec![])];
    for c in 0..=16 {
        statuses.push((c, format!("m{c}"), vec![]));
    }
    for e in [
        SuiError::from(SuiErrorKind::TimeoutError),
        SuiErrorKind::UserInputError { error: UserInputError::GasPriceUnderRGP { gas_price: 1, reference_gas_price: 750 } }.into(),
        SuiErrorKind::ValidatorOverloadedRetryAfter { retry_after_secs: 5 }.into(),
    ] {
        statuses.push((13, e.to_string(), bcs::to_bytes(&e)?));
    }
    statuses.push((14, "unavailable".into(), vec![1, 2, 3]));
    statuses.push((13, "trailing".into(), {
        let mut b = bcs::to_bytes(&SuiError::from(SuiErrorKind::TimeoutError))?;
        b.push(0);
        b
    }));
    for (code, msg, det) in &statuses {
        let st = tonic::Status::with_details(tonic::Code::from(*code), msg.clone(), det.clone().into());
        let e = SuiError::from(st);
        rec.push(*code as u8);
        put_str(&mut rec, msg);
        put_blob(&mut rec, det);
        put_blob(&mut rec, &bcs::to_bytes(&e)?);
        put_str(&mut rec, &e.to_string());
        rec.push(cat(e.categorize()));
    }
    std::fs::write(out.join("status.rec"), &rec)?;
    println!("status: {} records", statuses.len());

    // (c) driver_errors.rec
    let specs = driver_specs(&names);
    let mut rec = Vec::new();
    for s in &specs {
        encode_spec(&mut rec, s);
        let e = build_spec(s);
        let category = e.categorize();
        rec.extend_from_slice(&[]);
        put_str(&mut rec, &e.to_string());
        rec.push(cat(category));
        rec.push(category.is_submission_retriable() as u8);
        let sub = match e {
            TransactionDriverError::TimeoutWithLastRetriableError { last_error, attempts, timeout } => {
                TransactionSubmissionError::TimeoutBeforeFinalityWithErrors { last_error: last_error.map(|e| e.to_string()).unwrap_or_default(), attempts, timeout }
            }
            other => TransactionSubmissionError::TransactionFailed { category: other.categorize(), details: other.to_string() },
        };
        let st = tonic::Status::from(sui_rpc_api::RpcError::from(sub));
        rec.push(st.code() as i32 as u8);
        put_str(&mut rec, st.message());
        put_blob(&mut rec, st.details());
    }
    std::fs::write(out.join("driver_errors.rec"), &rec)?;
    println!("driver_errors: {} records", specs.len());
    Ok(())
}

// ------------------------------------------------------------------------------------------
// errors (c): TransactionDriverError values

type Agg = (Vec<(String, Vec<AuthorityName>, u64, ErrorCategory)>, u64);
type Digs = Vec<(TransactionEffectsDigest, Vec<AuthorityName>, u64)>;

enum Spec {
    ClientInternal(String),
    ValidationFailed(String),
    Aborted(Agg, Agg, Digs),
    Rejected(Agg, Agg),
    Forked(Digs, Agg, Agg),
    Timeout(Option<Box<Spec>>, u32, Duration),
}

/// `AggregatedEffectsDigests` is not nameable outside sui-core (private module, no Default);
/// this mirror has its only field, so one empty value can be made and then filled through the
/// public `digests` field.
#[allow(dead_code)]
struct EffMirror {
    digests: Vec<(TransactionEffectsDigest, Vec<AuthorityName>, u64)>,
}

fn build_spec(s: &Spec) -> TransactionDriverError {
    match s {
        Spec::ClientInternal(e) => TransactionDriverError::ClientInternal { error: e.clone() },
        Spec::ValidationFailed(e) => TransactionDriverError::ValidationFailed { error: e.clone() },
        Spec::Aborted(nr, r, d) => {
            let mut e = TransactionDriverError::Aborted {
                submission_non_retriable_errors: Default::default(),
                submission_retriable_errors: Default::default(),
                // SAFETY: EffMirror and AggregatedEffectsDigests are both a struct of one Vec of the same element type.
                observed_effects_digests: unsafe { std::mem::transmute::<EffMirror, _>(EffMirror { digests: vec![] }) },
            };
            if let TransactionDriverError::Aborted { submission_non_retriable_errors: a, submission_retriable_errors: b, observed_effects_digests: c } = &mut e {
                a.errors = nr.0.clone();
                a.total_stake = nr.1;
                b.errors = r.0.clone();
                b.total_stake = r.1;
                c.digests = d.clone();
            }
            e
        }
        Spec::Rejected(nr, r) => {
            let mut e = TransactionDriverError::RejectedByValidators { submission_non_retriable_errors: Default::default(), submission_retriable_errors: Default::default() };
            if let TransactionDriverError::RejectedByValidators { submission_non_retriable_errors: a, submission_retriable_errors: b } = &mut e {
                a.errors = nr.0.clone();
                a.total_stake = nr.1;
                b.errors = r.0.clone();
                b.total_stake = r.1;
            }
            e
        }
        Spec::Forked(d, nr, r) => {
            let mut e = TransactionDriverError::ForkedExecution {
                // SAFETY: as above.
                observed_effects_digests: unsafe { std::mem::transmute::<EffMirror, _>(EffMirror { digests: vec![] }) },
                submission_non_retriable_errors: Default::default(),
                submission_retriable_errors: Default::default(),
            };
            if let TransactionDriverError::ForkedExecution { observed_effects_digests: c, submission_non_retriable_errors: a, submission_retriable_errors: b } = &mut e {
                a.errors = nr.0.clone();
                a.total_stake = nr.1;
                b.errors = r.0.clone();
                b.total_stake = r.1;
                c.digests = d.clone();
            }
            e
        }
        Spec::Timeout(last, attempts, timeout) => {
            TransactionDriverError::TimeoutWithLastRetriableError { last_error: last.as_ref().map(|l| Box::new(build_spec(l))), attempts: *attempts, timeout: *timeout }
        }
    }
}

fn encode_agg(b: &mut Vec<u8>, a: &Agg) {
    put_u32(b, a.0.len() as u32);
    for (s, names, stake, c) in &a.0 {
        put_str(b, s);
        put_u32(b, names.len() as u32);
        for n in names {
            b.extend_from_slice(&n.0);
        }
        put_u64(b, *stake);
        b.push(cat(*c));
    }
    put_u64(b, a.1);
}

fn encode_digs(b: &mut Vec<u8>, d: &Digs) {
    put_u32(b, d.len() as u32);
    for (dg, names, stake) in d {
        b.extend_from_slice(&dg.into_inner());
        put_u32(b, names.len() as u32);
        for n in names {
            b.extend_from_slice(&n.0);
        }
        put_u64(b, *stake);
    }
}

fn encode_spec(b: &mut Vec<u8>, s: &Spec) {
    match s {
        Spec::ClientInternal(e) => {
            b.push(0);
            put_str(b, e);
        }
        Spec::ValidationFailed(e) => {
            b.push(1);
            put_str(b, e);
        }
        Spec::Aborted(nr, r, d) => {
            b.push(2);
            encode_agg(b, nr);
            encode_agg(b, r);
            encode_digs(b, d);
        }
        Spec::Rejected(nr, r) => {
            b.push(3);
            encode_agg(b, nr);
            encode_agg(b, r);
        }
        Spec::Forked(d, nr, r) => {
            b.push(4);
            encode_digs(b, d);
            encode_agg(b, nr);
            encode_agg(b, r);
        }
        Spec::Timeout(last, attempts, timeout) => {
            b.push(5);
            match last {
                Some(l) => {
                    b.push(1);
                    encode_spec(b, l);
                }
                None => b.push(0),
            }
            put_u32(b, *attempts);
            put_u64(b, timeout.as_nanos() as u64);
        }
    }
}

fn driver_specs(n: &[AuthorityName]) -> Vec<Spec> {
    use ErrorCategory::*;
    let e0: Agg = (vec![], 0);
    let uie = UserInputError::ObjectVersionUnavailableForConsumption { provided_obj_ref: oref(4), current_version: sq(300) }.to_string();
    let lock = SuiError::from(SuiErrorKind::ObjectLockConflict { obj_ref: oref(24), pending_transaction: tdig(6) }).to_string();
    let timeout_req = "Request timed out submitting transaction".to_string();
    let expired = "Transaction status expired".to_string();
    let overload = SuiError::from(SuiErrorKind::TooManyTransactionsPendingConsensus).to_string();
    let notfound = UserInputError::ObjectNotFound { object_id: oid(2), version: Some(sq(5)) }.to_string();
    let nr1: Agg = (vec![(uie.clone(), vec![n[0], n[2]], 5000, InvalidTransaction)], 5000);
    let nr2: Agg = (vec![(uie.clone(), vec![n[0], n[1]], 5000, InvalidTransaction), (lock.clone(), vec![n[3]], 2500, LockConflict)], 7500);
    let nr3: Agg = (
        vec![
            (uie.clone(), vec![n[1]], 2500, InvalidTransaction),
            (lock.clone(), vec![n[0]], 2500, LockConflict),
            ("Invalid user signature".into(), vec![n[3]], 2500, InvalidTransaction),
        ],
        7500,
    );
    let r1: Agg = (vec![(timeout_req.clone(), vec![n[3]], 2500, Unavailable)], 2500);
    let r2: Agg = (vec![(expired.clone(), vec![n[0], n[1], n[2]], 7500, Aborted), (overload.clone(), vec![n[3]], 2500, ValidatorOverloaded)], 10000);
    let r3: Agg = (vec![(notfound.clone(), vec![n[2]], 2500, Aborted)], 2500);
    let d1: Digs = vec![(edig(1), vec![n[0], n[1]], 5000)];
    let d2: Digs = vec![(edig(1), vec![n[0], n[1]], 5000), (edig(2), vec![n[2], n[3]], 5000)];
    let d3: Digs = vec![(edig(3), vec![n[0]], 2500), (edig(4), vec![n[1]], 2500), (edig(5), vec![n[2], n[3]], 5000)];
    let gp = UserInputError::GasPriceUnderRGP { gas_price: 1, reference_gas_price: 750 }.to_string();
    vec![
        Spec::ClientInternal("SubmitTxResult::Rejected should have been returned as an error in submit_transaction(): x".into()),
        Spec::ClientInternal(String::new()),
        Spec::ValidationFailed(gp.clone()),
        Spec::Aborted(e0.clone(), e0.clone(), vec![]),
        Spec::Aborted(e0.clone(), r1.clone(), vec![]),
        Spec::Aborted(nr1.clone(), r1.clone(), vec![]),
        Spec::Aborted(e0.clone(), r2.clone(), d1.clone()),
        Spec::Aborted(nr2.clone(), r2.clone(), d3.clone()),
        Spec::Aborted(nr1.clone(), e0.clone(), vec![]),
        Spec::Aborted(e0.clone(), r3.clone(), d2.clone()),
        Spec::Rejected(nr1.clone(), e0.clone()),
        Spec::Rejected(nr2.clone(), r1.clone()),
        Spec::Rejected(nr3.clone(), r2.clone()),
        Spec::Rejected(e0.clone(), r1.clone()),
        Spec::Rejected(e0.clone(), e0.clone()),
        Spec::Forked(d2.clone(), e0.clone(), e0.clone()),
        Spec::Forked(d3.clone(), nr1.clone(), r1.clone()),
        Spec::Forked(vec![], e0.clone(), r2.clone()),
        Spec::Timeout(None, 0, Duration::from_secs(90)),
        Spec::Timeout(Some(Box::new(Spec::Aborted(e0.clone(), r1.clone(), vec![]))), 3, Duration::from_secs(90)),
        Spec::Timeout(Some(Box::new(Spec::Aborted(nr1.clone(), r2.clone(), d1.clone()))), 12, Duration::from_millis(1500)),
        Spec::Timeout(None, 1, Duration::from_millis(100)),
        Spec::Timeout(Some(Box::new(Spec::ValidationFailed(gp))), 2, Duration::from_millis(2500)),
        Spec::Timeout(Some(Box::new(Spec::Timeout(None, 1, Duration::from_secs(5)))), 7, Duration::from_nanos(1_000_001)),
        Spec::Timeout(Some(Box::new(Spec::Rejected(nr3, r3))), 4, Duration::from_micros(2500)),
    ]
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gen") if args.len() >= 3 => cmd_gen(Path::new(&args[1]), Path::new(&args[2])),
        Some("errors") if args.len() >= 2 => cmd_errors(Path::new(&args[1])),
        Some("zcat") if args.len() >= 2 => {
            use std::io::Write;
            std::io::stdout().write_all(&zstd::decode_all(&std::fs::read(&args[1])?[..])?)?;
            Ok(())
        }
        _ => {
            eprintln!("usage: zui-truth-rpc-exec-driver gen <corpus> <out dir> | errors <out dir> | zcat <file>");
            std::process::exit(2)
        }
    }
}
