//! zui-truth-rpc-exec: ground truth for deepwave's sui.rpc.v2 TransactionExecutionService.
//!
//! `gen <corpus> <out dir>` runs Mysten's own SimulateTransaction handler (sui-rpc-api
//! `RpcService` as `TransactionExecutionService`) with an executor that calls
//! `sui_core::transaction_simulation::simulate_transaction` (the function `AuthorityState`
//! calls), over a pre-state built from each corpus transaction's inputs, and records request,
//! gRPC status and response bytes. Format: README.md.
//!
//! Gas selection (`do_gas_selection`) reads an owner index over the pre-state (`RpcIndexes` on
//! `Pre`: the rpc-store `object_by_owner` rows of its objects) and the checkpoint's own summary as
//! the latest checkpoint; DevInspect command outputs render `json` through the executor's type
//! layout resolver over the pre-state's packages (sui-core's `RestReadStore` does the same).
//!
//! `bench simulate --iters N --list <file>` times the same handler per transaction (harness
//! baseline, CONTRACTS section 7).
use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use sui_core::accumulators::funds_read::AccountFundsRead;
use sui_core::transaction_simulation::SimulationInputLoader;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::transaction_execution_service_server::TransactionExecutionService;
use sui_rpc::proto::sui::rpc::v2::{Bcs, SimulateTransactionRequest, Transaction as ProtoTransaction, simulate_transaction_request::TransactionChecks as ProtoChecks};
use sui_types::accumulator_root::AccumulatorObjId;
use sui_types::base_types::{EpochId, ObjectID, ObjectRef, SequenceNumber, SuiAddress, VersionNumber};
use sui_types::committee::Committee;
use sui_types::digests::{ChainIdentifier, CheckpointContentsDigest, CheckpointDigest, TransactionDigest};
use sui_types::effects::{TransactionEffects, TransactionEffectsAPI, TransactionEvents};
use sui_types::error::{SuiError, SuiErrorKind, SuiResult, UserInputError};
use sui_types::full_checkpoint_content::{Checkpoint as FullCheckpoint, CheckpointData, ObjectSet};
use sui_types::messages_checkpoint::{CheckpointContents, CheckpointSequenceNumber, VerifiedCheckpoint, VersionedFullCheckpointContents};
use sui_types::object::{Object, Owner};
use sui_types::storage::{ObjectKey, ObjectStore, OwnedObjectInfo, PackageObject, RpcIndexes, RpcStateReader};
use typed_store_error::TypedStoreError;
use sui_types::transaction::{
    InputObjectKind, InputObjects, ObjectReadResult, ObjectReadResultKind, ReceivingObjectReadResult, ReceivingObjects, TransactionData, TransactionDataAPI,
    TransactionKind, TxValidityCheckContext, VerifiedTransaction,
};
use sui_types::transaction_executor::{SimulateTransactionResult, TransactionChecks, TransactionExecutor};
use sui_types::transaction_driver_types::{ExecuteTransactionRequestV3, ExecuteTransactionResponseV3, TransactionSubmissionError};

/// Response read mask for the recorded cases: every field of SimulateTransactionResponse except
/// the resolver-rendered `json`/`display` fields and `command_outputs` (DevInspect results).
pub const MASK_FULL: &str = "transaction.transaction,transaction.effects,transaction.events.bcs,transaction.events.digest,\
transaction.events.events.package_id,transaction.events.events.module,transaction.events.events.sender,\
transaction.events.events.event_type,transaction.events.events.contents,transaction.balance_changes,\
transaction.objects.objects.bcs,transaction.objects.objects.object_id,transaction.objects.objects.version,\
transaction.objects.objects.digest,transaction.objects.objects.owner,transaction.objects.objects.object_type,\
transaction.objects.objects.has_public_transfer,transaction.objects.objects.contents,transaction.objects.objects.package,\
transaction.objects.objects.previous_transaction,transaction.objects.objects.storage_rebate,transaction.objects.objects.balance,\
suggested_gas_price";
pub const MASK_EFFECTS: &str = "transaction.effects";
/// MASK_FULL plus `command_outputs` (DevInspect results: return values, `&mut` updates, json).
pub const MASK_OUTPUTS_EXTRA: &str = ",command_outputs";

/// Case ids (cases.txt).
const CASES: &[(u8, &str)] = &[
    (1, "bcs transaction, checks enabled, MASK_FULL"),
    (2, "bcs transaction, checks enabled, read_mask transaction.effects"),
    (3, "bcs transaction with gas payment emptied (mock gas coin), checks enabled, MASK_FULL"),
    (4, "bcs transaction, checks DISABLED (dev inspect), MASK_FULL"),
    (5, "bcs transaction with gas payment emptied, do_gas_selection (owner index over the pre-state), MASK_FULL"),
    (6, "as 5 with gas budget max_tx_gas (insufficient balance quote)"),
    (7, "unresolved proto transaction (no bcs, no gas_payment), do_gas_selection: budget estimation + selection, MASK_FULL"),
    (10, "gas price set to reference gas price - 1"),
    (11, "gas budget set to max_tx_gas + 1"),
    (12, "first gas coin version + 1"),
    (13, "first gas coin digest with its first byte flipped"),
    (14, "gas budget 1"),
    (15, "bcs truncated by one byte (first user transaction of a checkpoint)"),
    (16, "read_mask path transaction.nope (first user transaction of a checkpoint)"),
    (17, "no transaction field (first user transaction of a checkpoint)"),
    (18, "a system transaction as bcs (first system transaction of a checkpoint)"),
    (19, "bcs transaction, checks enabled, MASK_FULL + command_outputs"),
    (20, "bcs transaction, checks DISABLED (dev inspect), MASK_FULL + command_outputs"),
];

/// Cases whose answer may carry a server-made expiration (gas selection: address-balance gas and
/// gasless set `ValidDuring` with a random nonce). Such answers are not recorded (`dropped_nonce`).
const GAS_SELECTION_CASES: &[u8] = &[5, 6, 7];

// ------------------------------------------------------------------------------------------
// Corpus environment: epochs, packages, system state per epoch.

#[derive(Clone, Copy, Default)]
struct EpochInfo {
    pv: u64,
    rgp: u64,
    start_ms: u64,
    last: Option<u64>,
}

struct Env {
    epochs: Vec<EpochInfo>,
    packages: HashMap<ObjectID, Object>,
    /// System packages by id: (first visible epoch, object), sorted.
    system: HashMap<ObjectID, Vec<(u64, Object)>>,
    /// Per epoch: the system state wrapper (0x5) and its inner dynamic field as the previous
    /// epoch's last checkpoint wrote them, and the committee size.
    sysstate: HashMap<u64, (Vec<Object>, u32)>,
}

impl Env {
    fn package(&self, id: &ObjectID, epoch: u64) -> Option<Object> {
        if let Some(list) = self.system.get(id) {
            return list.iter().filter(|(e, _)| *e <= epoch).last().map(|(_, o)| o.clone());
        }
        self.packages.get(id).cloned()
    }
}

fn decode_chk(path: &Path) -> Result<CheckpointData> {
    let raw = std::fs::read(path).with_context(|| path.display().to_string())?;
    if raw.first() != Some(&1) {
        bail!("{}: bad blob tag", path.display());
    }
    Ok(bcs::from_bytes(&raw[1..])?)
}

/// The archive proto of a checkpoint (binpb-done, binpb-r4, binpb-exec), as sui-types reads it.
fn archive(corpus: &Path, seq: u64) -> Result<Option<FullCheckpoint>> {
    for d in ["binpb-done", "binpb-r4", "binpb-exec"] {
        let p = corpus.join(d).join(format!("{seq}.binpb.zst"));
        if !p.exists() {
            continue;
        }
        let dec = zstd::decode_all(&std::fs::read(&p)?[..])?;
        let proto = <sui_rpc::proto::sui::rpc::v2::Checkpoint as prost::Message>::decode(&dec[..])?;
        let cp: FullCheckpoint = (&proto).try_into().map_err(|e| anyhow::anyhow!("{}: {e:?}", p.display()))?;
        return Ok(Some(cp));
    }
    Ok(None)
}

fn load_env(corpus: &Path) -> Result<Env> {
    let mut epochs: Vec<EpochInfo> = Vec::new();
    for line in std::fs::read_to_string(corpus.join("epochs.jsonl"))?.lines() {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let e = v["epoch"].as_u64().context("epoch")? as usize;
        if epochs.len() <= e {
            epochs.resize(e + 1, EpochInfo::default());
        }
        epochs[e] = EpochInfo { pv: v["pv"].as_u64().unwrap_or(0), rgp: v["rgp"].as_u64().unwrap_or(0), start_ms: v["start_ms"].as_u64().unwrap_or(0), last: v["last"].as_u64() };
    }
    let mut packages = HashMap::new();
    // the corpus packages, then the ones this tool fetched (`fetch-packages`): original packages
    // of upgraded ones, which execution resolves type defining ids against
    let extra = corpus.join(EXTRA_PKGS);
    for dir in [corpus.join("packages"), extra.clone()] {
        if dir == extra && !dir.exists() {
            continue;
        }
        for ent in std::fs::read_dir(&dir)? {
            let p = ent?.path();
            if p.extension().and_then(|x| x.to_str()) != Some("obj") {
                continue;
            }
            let o: Object = bcs::from_bytes(&std::fs::read(&p)?)?;
            packages.insert(o.id(), o);
        }
    }
    // System packages: genesis writes (visible from epoch 0) and each epoch's last checkpoint
    // (visible from the next epoch), as src/exec/packages.zig. The same last checkpoints carry
    // the next epoch's system state and committee.
    let mut writes: Vec<(u64, u64)> = vec![(0, 0)];
    for (e, ep) in epochs.iter().enumerate() {
        if let Some(last) = ep.last {
            writes.push((last, e as u64 + 1));
        }
    }
    type Part = (Vec<(u64, Object)>, Option<(u64, Vec<Object>, u32)>);
    let parts: Vec<Part> = writes
        .par_iter()
        .map(|(seq, visible)| {
            let p = corpus.join(format!("chk/{seq}.chk"));
            let Ok(cp) = decode_chk(&p) else { return (vec![], None) };
            let mut out = vec![];
            let mut ss = vec![];
            for t in &cp.transactions {
                for o in &t.output_objects {
                    if o.is_package() && sui_types::is_system_package(o.id()) {
                        out.push((*visible, o.clone()));
                    }
                    if o.id() == sui_types::SUI_SYSTEM_STATE_OBJECT_ID || o.owner == Owner::ObjectOwner(sui_types::SUI_SYSTEM_STATE_OBJECT_ID.into()) {
                        ss.push(o.clone());
                    }
                }
            }
            let size = cp.checkpoint_summary.end_of_epoch_data.as_ref().map(|d| d.next_epoch_committee.len() as u32);
            (out, size.map(|n| (*visible, ss, n)))
        })
        .collect();
    let mut system: HashMap<ObjectID, Vec<(u64, Object)>> = HashMap::new();
    let mut sysstate = HashMap::new();
    for (list, ss) in parts {
        for (e, o) in list {
            system.entry(o.id()).or_default().push((e, o));
        }
        if let Some((e, objs, n)) = ss {
            sysstate.insert(e, (objs, n));
        }
    }
    for v in system.values_mut() {
        v.sort_by_key(|(e, _)| *e);
    }
    Ok(Env { epochs, packages, system, sysstate })
}

// ------------------------------------------------------------------------------------------
// Pre-state: the objects one transaction read, at the versions it read them.

struct Pre {
    env: Arc<Env>,
    epoch: u64,
    objs: HashMap<ObjectID, Object>,
    /// The checkpoint the transaction is in (gas selection reads the current epoch from it).
    latest: Option<VerifiedCheckpoint>,
    /// Type layouts (command output json): the epoch's protocol config and executor.
    layouts: Option<(ProtocolConfig, Arc<dyn sui_execution::Executor + Send + Sync>)>,
}

impl Pre {
    fn package(&self, id: &ObjectID) -> Option<Object> {
        self.env.package(id, self.epoch).or_else(|| self.objs.get(id).filter(|o| o.is_package()).cloned())
    }
}

impl ObjectStore for Pre {
    fn get_object(&self, id: &ObjectID) -> Option<Object> {
        self.objs.get(id).cloned().or_else(|| self.package(id))
    }
    fn get_object_by_key(&self, id: &ObjectID, version: VersionNumber) -> Option<Object> {
        self.get_object(id).filter(|o| o.version() == version)
    }
}

/// Package ids execution asked for that neither the corpus nor `vectors/rpc-simulate-pkgs` holds
/// (`gen` writes them to `missing-packages.txt`; `fetch-packages` gets them).
static MISSING_PACKAGES: std::sync::Mutex<std::collections::BTreeSet<ObjectID>> = std::sync::Mutex::new(std::collections::BTreeSet::new());

impl sui_types::storage::BackingPackageStore for Pre {
    fn get_package_object(&self, id: &ObjectID) -> SuiResult<Option<PackageObject>> {
        let p = self.package(id);
        if p.is_none() && !sui_types::is_system_package(*id) && self.objs.get(id).is_none() {
            MISSING_PACKAGES.lock().unwrap().insert(*id);
        }
        Ok(p.map(PackageObject::new))
    }
}

impl sui_types::storage::RuntimeObjectResolver for Pre {
    fn read_child_object(&self, _parent: &ObjectID, child: &ObjectID, upper: SequenceNumber) -> SuiResult<Option<Object>> {
        Ok(self.objs.get(child).filter(|o| o.version() <= upper).cloned())
    }
    fn get_object_received_at_version(&self, owner: &ObjectID, receiving: &ObjectID, version: SequenceNumber, _epoch: EpochId) -> SuiResult<Option<Object>> {
        Ok(self.objs.get(receiving).filter(|o| o.version() == version && o.owner == Owner::AddressOwner((*owner).into())).cloned())
    }
}

impl sui_types::storage::ParentSync for Pre {
    fn get_latest_parent_entry_ref_deprecated(&self, _id: ObjectID) -> Option<ObjectRef> {
        None
    }
}

impl sui_types::storage::ReadStore for Pre {
    fn get_committee(&self, _epoch: EpochId) -> Option<Arc<Committee>> {
        None
    }
    fn get_latest_checkpoint(&self) -> sui_types::storage::error::Result<VerifiedCheckpoint> {
        self.latest.clone().ok_or_else(|| sui_types::storage::error::Error::missing("no checkpoints in a pre-state"))
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

impl RpcStateReader for Pre {
    fn get_lowest_available_checkpoint_objects(&self) -> sui_types::storage::error::Result<CheckpointSequenceNumber> {
        Ok(0)
    }
    fn get_chain_identifier(&self) -> sui_types::storage::error::Result<ChainIdentifier> {
        Ok(sui_types::digests::get_mainnet_chain_identifier())
    }
    fn indexes(&self) -> Option<&dyn RpcIndexes> {
        Some(self)
    }
    /// sui-core `RestReadStore::get_struct_layout_with_overlay`: the executor's layout resolver
    /// over the overlay, then the pre-state's packages. Only `json` fields read layouts; the
    /// recorded masks ask for json only through `command_outputs` (cases 19, 20).
    fn get_struct_layout_with_overlay(&self, t: &move_core_types::language_storage::StructTag, o: &ObjectSet) -> sui_types::storage::error::Result<Option<move_core_types::annotated_value::MoveTypeLayout>> {
        let Some((cfg, executor)) = &self.layouts else { return Ok(None) };
        let store = sui_types::storage::OverlayBackingPackageStore::new(o, self);
        executor
            .type_layout_resolver(cfg, Box::new(store))
            .get_annotated_layout(t)
            .map(|layout| layout.into_layout())
            .map(Some)
            .map_err(sui_types::storage::error::Error::custom)
    }
}

/// The rpc-store indexes over the pre-state. Only `owned_objects_iter` is read by
/// SimulateTransaction (gas selection); the rest are never called on this path.
impl RpcIndexes for Pre {
    fn get_epoch_info(&self, _epoch: EpochId) -> sui_types::storage::error::Result<Option<sui_types::storage::EpochInfo>> {
        Ok(None)
    }

    /// `object_by_owner` (sui-rpc-store schema): `AddressOwner(a)` and
    /// `ConsensusAddressOwner { owner: a }` objects under `AddressOwner(a)`, keyed
    /// `bcs(StructTag) || balance_tag || !balance BE? || object_id`, scanned in key order.
    fn owned_objects_iter(
        &self,
        owner: SuiAddress,
        object_type: Option<move_core_types::language_storage::StructTag>,
        cursor: Option<OwnedObjectInfo>,
    ) -> sui_types::storage::error::Result<Box<dyn Iterator<Item = Result<OwnedObjectInfo, TypedStoreError>> + '_>> {
        let mut rows: Vec<(Vec<u8>, OwnedObjectInfo)> = self
            .objs
            .values()
            .filter_map(|o| {
                let a = match &o.owner {
                    Owner::AddressOwner(a) => *a,
                    Owner::ConsensusAddressOwner { owner, .. } => *owner,
                    _ => return None,
                };
                if a != owner {
                    return None;
                }
                let t = o.struct_tag()?;
                if object_type.as_ref().is_some_and(|f| *f != t) {
                    return None;
                }
                let info = OwnedObjectInfo { owner, object_type: t, balance: o.as_coin_maybe().map(|c| c.balance.value()), object_id: o.id(), version: o.version() };
                Some((owner_key(&info), info))
            })
            .collect();
        rows.sort_by(|x, y| x.0.cmp(&y.0));
        let from = cursor.map(|c| owner_key(&c));
        Ok(Box::new(rows.into_iter().filter(move |(k, _)| from.as_ref().is_none_or(|f| k >= f)).map(|(_, i)| Ok(i))))
    }

    fn dynamic_field_iter(&self, _parent: ObjectID, _cursor: Option<sui_types::storage::DynamicFieldKey>) -> sui_types::storage::error::Result<Box<dyn Iterator<Item = sui_types::storage::DynamicFieldIteratorItem> + '_>> {
        Ok(Box::new(std::iter::empty()))
    }
    fn get_coin_info(&self, _coin_type: &move_core_types::language_storage::StructTag) -> sui_types::storage::error::Result<Option<sui_types::storage::CoinInfo>> {
        Ok(None)
    }
    fn get_balance(&self, _owner: &SuiAddress, _coin_type: &move_core_types::language_storage::StructTag) -> sui_types::storage::error::Result<Option<sui_types::storage::BalanceInfo>> {
        Ok(None)
    }
    fn balance_iter(&self, _owner: &SuiAddress, _cursor: Option<(SuiAddress, move_core_types::language_storage::StructTag)>) -> sui_types::storage::error::Result<sui_types::storage::BalanceIterator<'_>> {
        Ok(Box::new(std::iter::empty()))
    }
    fn package_versions_iter(&self, _original_id: ObjectID, _cursor: Option<u64>) -> sui_types::storage::error::Result<Box<dyn Iterator<Item = Result<(u64, ObjectID), TypedStoreError>> + '_>> {
        Ok(Box::new(std::iter::empty()))
    }
    fn get_package_version_storage_id(&self, _original_id: ObjectID, _version: u64) -> sui_types::storage::error::Result<Option<ObjectID>> {
        Ok(None)
    }
    fn get_package_at_checkpoint(&self, _original_id: ObjectID, _checkpoint: CheckpointSequenceNumber) -> sui_types::storage::error::Result<Option<(u64, ObjectID)>> {
        Ok(None)
    }
    fn get_highest_indexed_checkpoint_seq_number(&self) -> sui_types::storage::error::Result<Option<CheckpointSequenceNumber>> {
        Ok(self.latest.as_ref().map(|c| *c.sequence_number()))
    }
    fn ledger_tx_seq_digest(&self, _tx_seq: u64) -> sui_types::storage::error::Result<Option<sui_types::storage::LedgerTxSeqDigest>> {
        Ok(None)
    }
    fn ledger_tx_seq_digest_iter(&self, _start: u64, _end_exclusive: u64, _descending: bool) -> sui_types::storage::error::Result<sui_types::storage::LedgerTxSeqDigestIterator<'_>> {
        Ok(Box::new(std::iter::empty()))
    }
    fn transaction_bitmap_bucket_iter(&self, _dimension_key: Vec<u8>, _start_bucket: u64, _end_bucket_exclusive: u64, _descending: bool) -> sui_types::storage::error::Result<sui_types::storage::LedgerBitmapBucketIterator<'_>> {
        unimplemented!("not read by SimulateTransaction")
    }
    fn event_bitmap_bucket_iter(&self, _dimension_key: Vec<u8>, _start_bucket: u64, _end_bucket_exclusive: u64, _descending: bool) -> sui_types::storage::error::Result<sui_types::storage::LedgerBitmapBucketIterator<'_>> {
        unimplemented!("not read by SimulateTransaction")
    }
}

/// The `object_by_owner` key suffix of a row (after the owner kind and address).
fn owner_key(i: &OwnedObjectInfo) -> Vec<u8> {
    let mut k = bcs::to_bytes(&i.object_type).expect("bcs StructTag");
    match i.balance {
        None => k.push(0),
        Some(b) => {
            k.push(1);
            k.extend_from_slice(&(!b).to_be_bytes());
        }
    }
    k.extend_from_slice(i.object_id.as_ref());
    k
}

/// sui-core `TransactionInputLoader::read_objects_for_signing` (pub(crate) there) over the
/// pre-state, with `ObjectCacheRead::multi_get_objects_with_more_accurate_error_return`.
impl SimulationInputLoader for Pre {
    fn read_objects_for_simulation(
        &self,
        _transaction_digest: &TransactionDigest,
        input_object_kinds: &[InputObjectKind],
        receiving_object_refs: &[ObjectRef],
        _epoch_id: EpochId,
    ) -> SuiResult<(InputObjects, ReceivingObjects)> {
        let mut input_results = vec![None; input_object_kinds.len()];
        let mut object_refs = Vec::with_capacity(input_object_kinds.len());
        let mut fetch_indices = Vec::with_capacity(input_object_kinds.len());
        for (i, kind) in input_object_kinds.iter().enumerate() {
            match kind {
                InputObjectKind::MovePackage(id) => {
                    let Some(package) = self.package(id) else {
                        return Err(SuiError::from(kind.object_not_found_error()));
                    };
                    input_results[i] = Some(ObjectReadResult { input_object_kind: *kind, object: ObjectReadResultKind::Object(package) });
                }
                InputObjectKind::SharedMoveObject { .. } => {
                    let input_full_id = kind.full_object_id();
                    match self.get_object(&kind.object_id()) {
                        Some(object) if object.full_id() == input_full_id => input_results[i] = Some(ObjectReadResult::new(*kind, object.into())),
                        // no consensus stream end markers in a pre-state
                        _ => return Err(SuiError::from(kind.object_not_found_error())),
                    }
                }
                InputObjectKind::ImmOrOwnedMoveObject(objref) => {
                    object_refs.push(*objref);
                    fetch_indices.push(i);
                }
            }
        }
        let mut objects = Vec::new();
        for object_ref in &object_refs {
            match self.get_object_by_key(&object_ref.0, object_ref.1) {
                Some(o) => objects.push(o),
                None => {
                    let live = self.get_object(&object_ref.0).ok_or(UserInputError::ObjectNotFound { object_id: object_ref.0, version: None })?.compute_object_reference();
                    let error = if live.1 >= object_ref.1 {
                        UserInputError::ObjectVersionUnavailableForConsumption { provided_obj_ref: *object_ref, current_version: live.1 }
                    } else {
                        UserInputError::ObjectNotFound { object_id: object_ref.0, version: Some(object_ref.1) }
                    };
                    return Err(SuiErrorKind::UserInputError { error }.into());
                }
            }
        }
        for (index, object) in fetch_indices.into_iter().zip(objects) {
            input_results[index] = Some(ObjectReadResult { input_object_kind: input_object_kinds[index], object: ObjectReadResultKind::Object(object) });
        }
        let mut receiving = Vec::with_capacity(receiving_object_refs.len());
        for objref in receiving_object_refs {
            let (object_id, version, _) = objref;
            let Some(object) = self.get_object(object_id) else {
                return Err(UserInputError::ObjectNotFound { object_id: *object_id, version: Some(*version) }.into());
            };
            receiving.push(ReceivingObjectReadResult::new(*objref, object.into()));
        }
        Ok((input_results.into_iter().map(Option::unwrap).collect::<Vec<_>>().into(), receiving.into()))
    }
}

/// `WritebackCache`'s `AccountFundsRead` over the pre-state.
impl AccountFundsRead for Pre {
    fn get_latest_account_amount(&self, account_id: &AccumulatorObjId) -> u128 {
        self.get_object(account_id.inner()).map(|o| account_amount(&o)).unwrap_or(0)
    }
    fn get_consistent_latest_account_amount_and_version(&self, account_id: &AccumulatorObjId) -> (u128, SequenceNumber) {
        let root = self.get_object(&sui_types::SUI_ACCUMULATOR_ROOT_OBJECT_ID).map(|o| o.version()).unwrap_or_default();
        (self.get_account_amount_at_version(account_id, root), root)
    }
    fn get_account_amount_at_version(&self, account_id: &AccumulatorObjId, version: SequenceNumber) -> u128 {
        self.objs.get(account_id.inner()).filter(|o| o.version() <= version).map(account_amount).unwrap_or(0)
    }
}

fn account_amount(o: &Object) -> u128 {
    use sui_types::accumulator_root::AccumulatorValue;
    let Some(m) = o.data.try_as_move() else { return 0 };
    let Ok((_, AccumulatorValue::U128(v))) = m.try_into() else { return 0 };
    v.value
}

// ------------------------------------------------------------------------------------------
// The executor behind RpcService: AuthorityState::simulate_transaction's checks, then
// transaction_simulation::simulate_transaction.

struct Sim {
    pre: Arc<Pre>,
    cfg: ProtocolConfig,
    rgp: u64,
    start_ms: u64,
    committee_size: u32,
    executor: Arc<dyn sui_execution::Executor + Send + Sync>,
    verifier_metrics: Arc<sui_types::metrics::BytecodeVerifierMetrics>,
    exec_metrics: Arc<sui_types::metrics::ExecutionMetrics>,
}

#[async_trait::async_trait]
impl TransactionExecutor for Sim {
    async fn execute_transaction(&self, _r: ExecuteTransactionRequestV3, _a: Option<std::net::SocketAddr>) -> Result<ExecuteTransactionResponseV3, TransactionSubmissionError> {
        unimplemented!("rpc-exec truth never executes")
    }

    fn simulate_transaction(&self, transaction: TransactionData, checks: TransactionChecks, allow_mock_gas_coin: bool) -> Result<SimulateTransactionResult, SuiError> {
        if transaction.kind().is_system_tx() {
            return Err(SuiErrorKind::UnsupportedFeatureError { error: "simulate does not support system transactions".to_string() }.into());
        }
        // a full node with dev inspect enabled (the default config)
        let ctx = TxValidityCheckContext {
            config: &self.cfg,
            epoch: self.pre.epoch,
            chain_identifier: sui_types::digests::get_mainnet_chain_identifier(),
            reference_gas_price: self.rgp,
            committee_size: self.committee_size,
        };
        let deny = sui_config::transaction_deny_config::TransactionDenyConfig::default();
        let resolver = sui_types::coin_reservation::BorrowedCoinReservationResolver::new(self.pre.as_ref());
        let r = sui_core::transaction_simulation::simulate_transaction(
            transaction,
            checks,
            allow_mock_gas_coin,
            None,
            ctx,
            self.pre.epoch,
            self.start_ms,
            sui_types::digests::get_mainnet_chain_identifier(),
            &deny,
            &HashSet::new(),
            self.pre.as_ref(),
            self.pre.as_ref(),
            self.pre.as_ref(),
            self.executor.as_ref(),
            &resolver,
            self.pre.as_ref(),
            &sui_config::verifier_signing_config::VerifierSigningConfig::default(),
            &self.verifier_metrics,
            &self.exec_metrics,
        );
        // ZUI_TRUTH_DEBUG=1: the execution error behind a failed status (with its source)
        if std::env::var_os("ZUI_TRUTH_DEBUG").is_some() {
            if let Ok(res) = &r {
                if let Err(e) = &res.execution_result {
                    eprintln!("execution error: {e:?}");
                }
            }
        }
        r
    }
}

struct Executors {
    by_pv: std::sync::Mutex<HashMap<u64, Arc<dyn sui_execution::Executor + Send + Sync>>>,
    verifier_metrics: Arc<sui_types::metrics::BytecodeVerifierMetrics>,
    exec_metrics: Arc<sui_types::metrics::ExecutionMetrics>,
}

impl Executors {
    fn new() -> Self {
        let registry = prometheus::Registry::new();
        Self {
            by_pv: Default::default(),
            verifier_metrics: Arc::new(sui_types::metrics::BytecodeVerifierMetrics::new(&registry)),
            exec_metrics: Arc::new(sui_types::metrics::ExecutionMetrics::new(&registry)),
        }
    }
    fn get(&self, cfg: &ProtocolConfig) -> Result<Arc<dyn sui_execution::Executor + Send + Sync>> {
        let pv = cfg.version.as_u64();
        let mut m = self.by_pv.lock().unwrap();
        if let Some(e) = m.get(&pv) {
            return Ok(e.clone());
        }
        let e = sui_execution::executor(cfg, true)?;
        m.insert(pv, e.clone());
        Ok(e)
    }
}

/// One request through `RpcService` as `TransactionExecutionService`: (code, message,
/// grpc-status-details-bin, response bytes).
fn call(rt: &tokio::runtime::Runtime, svc: &sui_rpc_api::RpcService, req: SimulateTransactionRequest) -> (u8, String, Vec<u8>, Vec<u8>) {
    let r = rt.block_on(TransactionExecutionService::simulate_transaction(svc, tonic::Request::new(req)));
    match r {
        Ok(resp) => (0, String::new(), vec![], prost::Message::encode_to_vec(resp.get_ref())),
        Err(st) => (st.code() as i32 as u8, st.message().to_string(), st.details().to_vec(), vec![]),
    }
}

/// The transaction as an unresolved proto `Transaction`: every field but `bcs`, `digest` and
/// `gas_payment` (so the handler resolves it, defaults the gas owner to the sender, estimates the
/// budget and selects gas). None for kinds the proto cannot carry.
fn unresolved(td: &TransactionData) -> Option<ProtoTransaction> {
    let sdk = sui_sdk_types::Transaction::try_from(td.clone()).ok()?;
    let mut t = ProtoTransaction::from(sdk);
    t.bcs = None;
    t.digest = None;
    t.gas_payment = None;
    Some(t)
}

/// The response's transaction carries an expiration the request did not (`ValidDuring` /
/// `Validity` from address-balance gas or gasless, with a random nonce).
fn server_expiration(resp: &[u8], requested: &sui_types::transaction::TransactionExpiration) -> bool {
    let Ok(r) = <sui_rpc::proto::sui::rpc::v2::SimulateTransactionResponse as prost::Message>::decode(resp) else { return false };
    let Some(b) = r.transaction.and_then(|t| t.transaction).and_then(|t| t.bcs).and_then(|b| b.value) else { return false };
    let Ok(td) = bcs::from_bytes::<TransactionData>(&b) else { return false };
    td.expiration() != requested
}

fn request(tx_bcs: Vec<u8>, mask: Option<&str>, checks: Option<ProtoChecks>) -> SimulateTransactionRequest {
    let mut t = ProtoTransaction::default();
    let mut b = Bcs::default();
    b.name = Some("TransactionData".to_owned());
    b.value = Some(tx_bcs.into());
    t.bcs = Some(b);
    let mut req = SimulateTransactionRequest::default();
    req.transaction = Some(t);
    req.read_mask = mask.map(FieldMask::from_str);
    if let Some(c) = checks {
        req.set_checks(c);
    }
    req
}

// ------------------------------------------------------------------------------------------
// Pre-state keys of one transaction.

fn pre_state_objects(env: &Env, epoch: u64, data: &TransactionData, effects: &TransactionEffects, loaded: &[ObjectKey], set: &dyn Fn(&ObjectKey) -> Option<Object>, acc: &BTreeMap<ObjectID, Object>) -> (Vec<Object>, usize) {
    let mut keys: BTreeMap<ObjectID, SequenceNumber> = BTreeMap::new();
    if let Ok(kinds) = data.input_objects() {
        for k in kinds {
            if let InputObjectKind::ImmOrOwnedMoveObject(r) = k {
                keys.insert(r.0, r.1);
            }
        }
    }
    for r in data.receiving_objects() {
        keys.insert(r.0, r.1);
    }
    for (id, v) in effects.modified_at_versions() {
        keys.insert(id, v);
    }
    for k in effects.accessed_consensus_objects() {
        use sui_types::effects::InputConsensusObject as C;
        if let C::Mutate(r) | C::ReadOnly(r) = k {
            keys.insert(r.0, r.1);
        }
    }
    for k in loaded {
        keys.insert(k.0, k.1);
    }
    let mut out = Vec::new();
    let mut missing = 0usize;
    let mut have: HashSet<ObjectID> = HashSet::new();
    for (id, v) in &keys {
        match set(&ObjectKey(*id, *v)) {
            Some(o) if !o.is_package() => {
                have.insert(*id);
                out.push(o);
            }
            Some(_) => {}
            None => missing += 1,
        }
    }
    // the system state the epoch started with (rgp, protocol version for the handler), unless
    // the transaction read its own version
    if let Some((ss, _)) = env.sysstate.get(&epoch) {
        for o in ss {
            if have.insert(o.id()) {
                out.push(o.clone());
            }
        }
    }
    // address balances (accumulator fields under 0xacc) as of the checkpoint's start: what
    // signing-time balance checks and address-balance gas read
    for (id, o) in acc {
        if have.insert(*id) {
            out.push(o.clone());
        }
    }
    (out, missing)
}

/// Accumulator fields (address balances, owned by the accumulator root 0xacc) at the lowest
/// version the checkpoint's archive object set holds: their value when the checkpoint started.
fn acc_base(arch: Option<&FullCheckpoint>) -> BTreeMap<ObjectID, Object> {
    let mut out: BTreeMap<ObjectID, Object> = BTreeMap::new();
    let Some(a) = arch else { return out };
    let root: SuiAddress = sui_types::SUI_ACCUMULATOR_ROOT_OBJECT_ID.into();
    for o in a.object_set.iter() {
        if o.owner != Owner::ObjectOwner(root) {
            continue;
        }
        match out.get(&o.id()) {
            Some(x) if x.version() <= o.version() => {}
            _ => {
                out.insert(o.id(), o.clone());
            }
        }
    }
    out
}

// ------------------------------------------------------------------------------------------
// gen

fn put_u32(b: &mut Vec<u8>, x: u32) {
    b.extend_from_slice(&x.to_le_bytes());
}
fn put_u64(b: &mut Vec<u8>, x: u64) {
    b.extend_from_slice(&x.to_le_bytes());
}
fn put_bytes(b: &mut Vec<u8>, x: &[u8]) {
    put_u32(b, x.len() as u32);
    b.extend_from_slice(x);
}

struct Stats {
    txs: std::sync::atomic::AtomicU64,
    /// Gas-selection answers with a server-made (random nonce) expiration, not recorded.
    dropped_nonce: std::sync::atomic::AtomicU64,
    eq: std::sync::atomic::AtomicU64,
    ne: std::sync::atomic::AtomicU64,
    missing: std::sync::atomic::AtomicU64,
}

fn gen_one(corpus: &Path, out: &Path, env: &Arc<Env>, exs: &Executors, seq: u64, stats: &Stats) -> Result<()> {
    let data = decode_chk(&corpus.join(format!("chk/{seq}.chk")))?;
    let epoch = data.checkpoint_summary.epoch;
    let ep = env.epochs[epoch as usize];
    let arch = archive(corpus, seq)?;
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(ep.pv), Chain::Mainnet);
    let executor = exs.get(&cfg)?;
    let committee_size = env.sysstate.get(&epoch).map(|x| x.1).unwrap_or(0);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let acc = acc_base(arch.as_ref());
    let mut rec = Vec::new();
    let mut first_user = true;
    let mut first_system = true;
    for (i, t) in data.transactions.iter().enumerate() {
        let td = t.transaction.data().transaction_data().clone();
        let tx_bcs = bcs::to_bytes(&td)?;
        let is_system = td.kind().is_system_tx();
        if is_system && !first_system {
            continue;
        }
        let (loaded, set_fn): (Vec<ObjectKey>, Box<dyn Fn(&ObjectKey) -> Option<Object>>) = match &arch {
            Some(a) => {
                let at = &a.transactions[i];
                let set = &a.object_set;
                (at.unchanged_loaded_runtime_objects.clone(), Box::new(move |k: &ObjectKey| set.get(k).cloned()))
            }
            None => {
                let ins = &t.input_objects;
                (vec![], Box::new(move |k: &ObjectKey| ins.iter().find(|o| o.id() == k.0 && o.version() == k.1).cloned()))
            }
        };
        let (objs, missing) = if is_system {
            // only the system state the handler reads before it looks at the transaction kind
            (env.sysstate.get(&epoch).map(|x| x.0.clone()).unwrap_or_default(), 0)
        } else {
            pre_state_objects(env, epoch, &td, &t.effects, &loaded, &*set_fn, &acc)
        };
        let pre = Arc::new(Pre {
            env: env.clone(),
            epoch,
            objs: objs.iter().map(|o| (o.id(), o.clone())).collect(),
            latest: Some(VerifiedCheckpoint::new_unchecked(data.checkpoint_summary.clone())),
            layouts: Some((cfg.clone(), executor.clone())),
        });
        let sim = Arc::new(Sim {
            pre: pre.clone(),
            cfg: cfg.clone(),
            rgp: ep.rgp,
            start_ms: ep.start_ms,
            committee_size,
            executor: executor.clone(),
            verifier_metrics: exs.verifier_metrics.clone(),
            exec_metrics: exs.exec_metrics.clone(),
        });
        let mut svc = sui_rpc_api::RpcService::new(pre.clone());
        svc.with_executor(sim.clone());

        let mut cases: Vec<(u8, SimulateTransactionRequest)> = Vec::new();
        if is_system {
            first_system = false;
            cases.push((18, request(tx_bcs.clone(), Some(MASK_FULL), None)));
        } else {
            cases.push((1, request(tx_bcs.clone(), Some(MASK_FULL), None)));
            cases.push((2, request(tx_bcs.clone(), Some(MASK_EFFECTS), None)));
            let mut nogas = td.clone();
            nogas.gas_data_mut().payment = vec![];
            cases.push((3, request(bcs::to_bytes(&nogas)?, Some(MASK_FULL), None)));
            cases.push((4, request(tx_bcs.clone(), Some(MASK_FULL), Some(ProtoChecks::Disabled))));
            // gas selection over the pre-state's owner index
            let mut r = request(bcs::to_bytes(&nogas)?, Some(MASK_FULL), None);
            r.do_gas_selection = Some(true);
            cases.push((5, r));
            let mut m = nogas.clone();
            m.gas_data_mut().budget = cfg.max_tx_gas();
            let mut r = request(bcs::to_bytes(&m)?, Some(MASK_FULL), None);
            r.do_gas_selection = Some(true);
            cases.push((6, r));
            if let Some(t) = unresolved(&td) {
                let mut r = SimulateTransactionRequest::default();
                r.transaction = Some(t);
                r.read_mask = Some(FieldMask::from_str(MASK_FULL));
                r.do_gas_selection = Some(true);
                cases.push((7, r));
            }
            let mask_outputs = format!("{MASK_FULL}{MASK_OUTPUTS_EXTRA}");
            cases.push((19, request(tx_bcs.clone(), Some(mask_outputs.as_str()), None)));
            cases.push((20, request(tx_bcs.clone(), Some(mask_outputs.as_str()), Some(ProtoChecks::Disabled))));
            let mut m = td.clone();
            m.gas_data_mut().price = ep.rgp.saturating_sub(1);
            cases.push((10, request(bcs::to_bytes(&m)?, Some(MASK_FULL), None)));
            let mut m = td.clone();
            m.gas_data_mut().budget = cfg.max_tx_gas() + 1;
            cases.push((11, request(bcs::to_bytes(&m)?, Some(MASK_FULL), None)));
            if !td.gas_data().payment.is_empty() {
                let mut m = td.clone();
                m.gas_data_mut().payment[0].1 = m.gas_data().payment[0].1.next();
                cases.push((12, request(bcs::to_bytes(&m)?, Some(MASK_FULL), None)));
                let mut m = td.clone();
                let mut d = m.gas_data().payment[0].2.into_inner();
                d[0] ^= 1;
                m.gas_data_mut().payment[0].2 = sui_types::digests::ObjectDigest::new(d);
                cases.push((13, request(bcs::to_bytes(&m)?, Some(MASK_FULL), None)));
            }
            let mut m = td.clone();
            m.gas_data_mut().budget = 1;
            cases.push((14, request(bcs::to_bytes(&m)?, Some(MASK_FULL), None)));
            if first_user {
                first_user = false;
                cases.push((15, request(tx_bcs[..tx_bcs.len() - 1].to_vec(), Some(MASK_FULL), None)));
                cases.push((16, request(tx_bcs.clone(), Some("transaction.nope"), None)));
                let mut r = request(tx_bcs.clone(), Some(MASK_FULL), None);
                r.transaction = None;
                cases.push((17, r));
            }
        }

        put_u32(&mut rec, i as u32);
        put_u64(&mut rec, epoch);
        put_u64(&mut rec, ep.pv);
        put_u64(&mut rec, ep.rgp);
        put_u64(&mut rec, ep.start_ms);
        put_u32(&mut rec, committee_size);
        put_u32(&mut rec, objs.len() as u32);
        for o in &objs {
            put_bytes(&mut rec, &bcs::to_bytes(o)?);
        }
        let mut answered: Vec<(u8, Vec<u8>, u8, String, Vec<u8>, Vec<u8>, u8)> = Vec::with_capacity(cases.len());
        for (case, req) in cases {
            let req_bytes = prost::Message::encode_to_vec(&req);
            // diagnostic: Rust's simulated effects equal the certified effects (case 1 only)
            let mut flags = 0u8;
            if arch.is_some() {
                flags |= 2;
            }
            if missing > 0 {
                flags |= 4;
            }
            let (code, msg, det, resp) = call(&rt, &svc, req);
            if case == 1 {
                // the response's effects BCS against the certified effects
                let fx = <sui_rpc::proto::sui::rpc::v2::SimulateTransactionResponse as prost::Message>::decode(&resp[..])
                    .ok()
                    .and_then(|r| r.transaction)
                    .and_then(|t| t.effects)
                    .and_then(|e| e.bcs)
                    .and_then(|b| b.value);
                if fx.as_deref() == Some(&bcs::to_bytes(&t.effects)?[..]) {
                    flags |= 1;
                    stats.eq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                } else {
                    stats.ne.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            if GAS_SELECTION_CASES.contains(&case) && code == 0 && server_expiration(&resp, td.expiration()) {
                stats.dropped_nonce.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                continue;
            }
            answered.push((case, req_bytes, code, msg, det, resp, flags));
        }
        rec.push(answered.len() as u8);
        for (case, req_bytes, code, msg, det, resp, flags) in answered {
            rec.push(case);
            put_bytes(&mut rec, &req_bytes);
            rec.push(code);
            put_bytes(&mut rec, msg.as_bytes());
            put_bytes(&mut rec, &det);
            put_bytes(&mut rec, &resp);
            rec.push(flags);
        }
        if !is_system {
            stats.txs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if missing > 0 {
                stats.missing.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
    let z = zstd::encode_all(&rec[..], 3)?;
    std::fs::write(out.join(format!("{seq}.rec.zst")), z)?;
    Ok(())
}

/// Corpus checkpoints at execution version 4 (protocol 119 and later), in sequence order.
fn ev4_seqs(corpus: &Path, env: &Env) -> Result<Vec<u64>> {
    let mut seqs = Vec::new();
    for line in std::fs::read_to_string(corpus.join("manifest.jsonl"))?.lines() {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let (Some(seq), Some(epoch)) = (v["seq"].as_u64(), v["epoch"].as_u64()) else { continue };
        if env.epochs.get(epoch as usize).map(|e| e.pv).unwrap_or(0) >= 119 {
            seqs.push(seq);
        }
    }
    Ok(seqs)
}

const EXTRA_PKGS: &str = "vectors/rpc-simulate-pkgs";

/// `fetch-packages <corpus> <grpc url> <ids file>`: the listed package ids plus their linkage
/// closure into `<corpus>/vectors/rpc-simulate-pkgs/<id>.obj` (raw BCS `Object`), skipping ids the
/// corpus already has. BatchGetObjects of 50 ids, 100 ms apart; each object must decode as the
/// requested package and match the digest the service reports.
fn cmd_fetch_packages(corpus: &Path, url: &str, ids: &Path) -> Result<()> {
    use sui_rpc::proto::sui::rpc::v2::{BatchGetObjectsRequest, GetObjectRequest, get_object_result};
    let dir = corpus.join(EXTRA_PKGS);
    std::fs::create_dir_all(&dir)?;
    let have = |id: &ObjectID| {
        let n = format!("{}.obj", hex::encode(id.as_ref()));
        corpus.join("packages").join(&n).exists() || dir.join(&n).exists()
    };
    let mut queue: std::collections::VecDeque<ObjectID> = std::collections::VecDeque::new();
    let mut seen = std::collections::BTreeSet::new();
    for l in std::fs::read_to_string(ids)?.lines() {
        let l = l.trim();
        if l.is_empty() {
            continue;
        }
        let id = ObjectID::from_hex_literal(&format!("0x{}", l.trim_start_matches("0x")))?;
        if seen.insert(id) && !have(&id) {
            queue.push_back(id);
        }
    }
    let rt = tokio::runtime::Runtime::new()?;
    let _guard = rt.enter();
    let mut client = sui_rpc::Client::new(url.to_string())?;
    let (mut stored, mut not_found, mut requests) = (0u64, Vec::new(), 0u64);
    while !queue.is_empty() {
        let batch: Vec<ObjectID> = (0..50).map_while(|_| queue.pop_front()).collect();
        let mut req = BatchGetObjectsRequest::default();
        req.requests = batch
            .iter()
            .map(|id| {
                let mut r = GetObjectRequest::default();
                r.object_id = Some(id.to_hex_literal());
                r
            })
            .collect();
        req.read_mask = Some(prost_types::FieldMask { paths: vec!["bcs".into(), "digest".into()] });
        let resp = rt.block_on(async { client.ledger_client().batch_get_objects(req).await })?.into_inner();
        requests += 1;
        std::thread::sleep(std::time::Duration::from_millis(100));
        if resp.objects.len() != batch.len() {
            bail!("batch of {} answered {}", batch.len(), resp.objects.len());
        }
        for (id, res) in batch.iter().zip(resp.objects) {
            let Some(get_object_result::Result::Object(o)) = res.result else {
                not_found.push(*id);
                continue;
            };
            let raw = o.bcs.and_then(|b| b.value).context("no bcs")?.to_vec();
            let obj: Object = bcs::from_bytes(&raw).with_context(|| format!("decode {id}"))?;
            if obj.id() != *id {
                bail!("asked {id}, got {}", obj.id());
            }
            let want = o.digest.context("no digest")?;
            if obj.digest().to_string() != want {
                bail!("{id}: digest {} != reported {want}", obj.digest());
            }
            let Some(pkg) = obj.data.try_as_package() else {
                not_found.push(*id);
                continue;
            };
            for x in pkg.linkage_table().values().map(|u| u.upgraded_id) {
                if !sui_types::is_system_package(x) && seen.insert(x) && !have(&x) {
                    queue.push_back(x);
                }
            }
            std::fs::write(dir.join(format!("{}.obj", hex::encode(id.as_ref()))), &raw)?;
            stored += 1;
        }
    }
    eprintln!("fetch-packages: {stored} stored, {} not packages or not found, {requests} batch requests", not_found.len());
    for id in &not_found {
        eprintln!("not found: {id}");
    }
    Ok(())
}

fn cmd_gen(corpus: &Path, out: &Path, only: Option<u64>) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let env = Arc::new(load_env(corpus)?);
    let mut seqs = ev4_seqs(corpus, &env)?;
    if let Some(s) = only {
        seqs.retain(|x| *x == s);
    }
    let exs = Executors::new();
    let stats = Stats { txs: 0.into(), dropped_nonce: 0.into(), eq: 0.into(), ne: 0.into(), missing: 0.into() };
    let mut cases = String::new();
    for (id, d) in CASES {
        cases.push_str(&format!("{id}\t{d}\n"));
    }
    std::fs::write(out.join("cases.txt"), cases)?;
    std::fs::write(out.join("masks.txt"), format!("MASK_FULL\t{MASK_FULL}\nMASK_EFFECTS\t{MASK_EFFECTS}\nMASK_OUTPUTS\t{MASK_FULL}{MASK_OUTPUTS_EXTRA}\n"))?;
    let t0 = Instant::now();
    let errs: Vec<String> = seqs
        .par_iter()
        .filter_map(|seq| gen_one(corpus, out, &env, &exs, *seq, &stats).err().map(|e| format!("{seq}: {e:#}")))
        .collect();
    for e in &errs {
        eprintln!("{e}");
    }
    let missing: Vec<String> = MISSING_PACKAGES.lock().unwrap().iter().map(|id| hex::encode(id.as_ref())).collect();
    std::fs::write(out.join("missing-packages.txt"), missing.iter().map(|l| format!("{l}\n")).collect::<String>())?;
    eprintln!("gen: {} package ids missing (missing-packages.txt)", missing.len());
    let o = std::sync::atomic::Ordering::Relaxed;
    println!(
        "{{\"checkpoints\":{},\"errors\":{},\"user_txs\":{},\"dropped_nonce\":{},\"sim_eq_certified\":{},\"sim_ne_certified\":{},\"pre_state_missing\":{},\"secs\":{:.1}}}",
        seqs.len(),
        errs.len(),
        stats.txs.load(o),
        stats.dropped_nonce.load(o),
        stats.eq.load(o),
        stats.ne.load(o),
        stats.missing.load(o),
        t0.elapsed().as_secs_f64()
    );
    Ok(())
}

// ------------------------------------------------------------------------------------------
// bench simulate: the handler per user transaction, case 1 (MASK_FULL), one thread.

fn cmd_bench(args: &[String]) -> Result<()> {
    let name = args.first().context("bench name")?;
    if name != "simulate" {
        bail!("unknown bench {name}");
    }
    let mut iters = 5usize;
    let mut list = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => {
                iters = args[i + 1].parse()?;
                i += 2;
            }
            "--list" => {
                list = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            x => bail!("unknown arg {x}"),
        }
    }
    // the harness lists the suite's records (<corpus>/vectors/rpc-simulate/<seq>.rec.zst); the
    // requests are rebuilt from the corpus checkpoint of the same sequence number (chk/<seq>.chk)
    let listed: Vec<PathBuf> = std::fs::read_to_string(list.context("--list")?)?.lines().filter(|l| !l.is_empty()).map(PathBuf::from).collect();
    let first = listed.first().context("empty list")?;
    let corpus = if first.to_string_lossy().ends_with(".rec.zst") {
        first.ancestors().nth(3).context("corpus root")?.to_path_buf()
    } else {
        first.ancestors().nth(2).context("corpus root")?.to_path_buf()
    };
    let files: Vec<PathBuf> = listed
        .iter()
        .map(|f| {
            let seq = f.file_name().and_then(|s| s.to_str()).and_then(|s| s.split('.').next()).unwrap_or("");
            corpus.join(format!("chk/{seq}.chk"))
        })
        .collect();
    let env = Arc::new(load_env(&corpus)?);
    let exs = Executors::new();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    // prepared (service, request) per user transaction, from the recorded pre-states
    let mut items: Vec<(sui_rpc_api::RpcService, SimulateTransactionRequest)> = Vec::new();
    for f in &files {
        let seq: u64 = f.file_stem().and_then(|s| s.to_str()).and_then(|s| s.split('.').next()).and_then(|s| s.parse().ok()).context("seq")?;
        let data = decode_chk(f)?;
        let epoch = data.checkpoint_summary.epoch;
        let ep = env.epochs[epoch as usize];
        if ep.pv < 119 {
            continue;
        }
        let arch = archive(&corpus, seq)?;
        let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(ep.pv), Chain::Mainnet);
        let executor = exs.get(&cfg)?;
        let committee_size = env.sysstate.get(&epoch).map(|x| x.1).unwrap_or(0);
        let acc = acc_base(arch.as_ref());
        for (i, t) in data.transactions.iter().enumerate() {
            let td = t.transaction.data().transaction_data().clone();
            if td.kind().is_system_tx() || !matches!(td.kind(), TransactionKind::ProgrammableTransaction(_)) {
                continue;
            }
            let (loaded, set): (Vec<ObjectKey>, Box<dyn Fn(&ObjectKey) -> Option<Object>>) = match &arch {
                Some(a) => {
                    let set = &a.object_set;
                    (a.transactions[i].unchanged_loaded_runtime_objects.clone(), Box::new(move |k: &ObjectKey| set.get(k).cloned()))
                }
                None => {
                    let ins = &t.input_objects;
                    (vec![], Box::new(move |k: &ObjectKey| ins.iter().find(|o| o.id() == k.0 && o.version() == k.1).cloned()))
                }
            };
            let (objs, _) = pre_state_objects(&env, epoch, &td, &t.effects, &loaded, &*set, &acc);
            let pre = Arc::new(Pre { env: env.clone(), epoch, objs: objs.iter().map(|o| (o.id(), o.clone())).collect(), latest: None, layouts: None });
            let sim = Arc::new(Sim { pre: pre.clone(), cfg: cfg.clone(), rgp: ep.rgp, start_ms: ep.start_ms, committee_size, executor: executor.clone(), verifier_metrics: exs.verifier_metrics.clone(), exec_metrics: exs.exec_metrics.clone() });
            let mut svc = sui_rpc_api::RpcService::new(pre);
            svc.with_executor(sim);
            items.push((svc, request(bcs::to_bytes(&td)?, Some(MASK_FULL), None)));
        }
    }
    let run_all = || {
        let mut ok = 0u64;
        for (svc, req) in &items {
            let (code, _, _, resp) = call(&rt, svc, req.clone());
            if code == 0 {
                ok += 1;
            }
            std::hint::black_box(resp);
        }
        ok
    };
    let ok = run_all();
    let mut times = Vec::new();
    for _ in 0..iters {
        let t = Instant::now();
        run_all();
        times.push(t.elapsed().as_nanos() as u64);
    }
    times.sort();
    let med = times[times.len() / 2];
    let units = items.len() as u64;
    println!(
        "{{\"impl\":\"rust\",\"bench\":\"simulate\",\"unit\":\"tx\",\"units\":{units},\"ok\":{ok},\"iters\":{iters},\"median_ns\":{med},\"min_ns\":{},\"ns_per_unit\":{:.2}}}",
        times[0],
        med as f64 / units.max(1) as f64
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gen") if args.len() >= 3 => cmd_gen(Path::new(&args[1]), Path::new(&args[2]), args.get(3).map(|s| s.parse()).transpose()?),
        Some("bench") => cmd_bench(&args[1..]),
        Some("fetch-packages") if args.len() >= 4 => cmd_fetch_packages(Path::new(&args[1]), &args[2], Path::new(&args[3])),
        _ => {
            eprintln!("usage: zui-truth-rpc-exec gen <corpus> <out dir> [seq] | fetch-packages <corpus> <grpc url> <ids file> | bench simulate --iters N --list <file>");
            std::process::exit(2)
        }
    }
}
