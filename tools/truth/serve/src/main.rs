//! zui-serve-truth: sui.rpc.v2 response bytes made by Mysten's own code (sui-types
//! `rpc_proto_conversions` and sui-rpc `Merge`), following sui-rpc-api's get_checkpoint.rs
//! without the package-resolver JSON annotation (json fields are not in any truth mask).
//!
//!   gen <out_dir> <file.chk>...     writes <out_dir>/<seq>.rec.zst and <out_dir>/masks.txt
//!
//! Record file (after zstd): repeated [kind u8][mask_id u8][len u32 le][bytes].
//! kind 1 = GetCheckpointResponse for checkpoint <seq> with masks.txt line <mask_id>.

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use std::io::Write;
use std::path::{Path, PathBuf};
use sui_rpc::field::{FieldMaskTree, FieldMaskUtil};
use sui_rpc::merge::Merge;
use sui_rpc::proto::sui::rpc::v2::{
    Checkpoint, ExecutedTransaction, GetCheckpointResponse, GetObjectResponse, GetTransactionResponse,
    Object, ObjectSet,
};
mod pkgconv;
use sui_types::balance_change::derive_balance_changes_2;
use sui_types::full_checkpoint_content::{Checkpoint as FullCheckpoint, CheckpointData};

const MASKS: &[&str] = &[
    "sequence_number,digest",
    "*",
    "summary,signature,contents",
    "transactions.digest,transactions.effects.status,transactions.effects.gas_used,transactions.checkpoint,transactions.timestamp",
    "transactions.transaction.sender,transactions.transaction.kind,transactions.balance_changes,transactions.events.events.event_type",
    "objects.objects.object_id,objects.objects.version,objects.objects.owner,objects.objects.object_type,objects.objects.has_public_transfer",
    "transactions.transaction.bcs,transactions.effects.bcs,transactions.events.bcs,transactions.signatures.bcs,objects.objects.bcs",
    "summary.bcs,signature.epoch,signature.bitmap,contents.bcs,contents.digest",
    "transactions.digest,transactions.transaction.bcs,transactions.transaction.digest,transactions.transaction.version,transactions.transaction.sender,transactions.transaction.gas_payment,transactions.transaction.expiration,transactions.signatures",
    "transactions.effects.bcs,transactions.effects.digest,transactions.effects.version,transactions.effects.epoch,transactions.effects.gas_used,transactions.effects.transaction_digest,transactions.effects.gas_object,transactions.effects.events_digest,transactions.effects.dependencies,transactions.effects.lamport_version,transactions.effects.changed_objects,transactions.effects.unchanged_consensus_objects,transactions.effects.auxiliary_data_digest,transactions.events,transactions.checkpoint,transactions.timestamp",
    "transactions.transaction.kind",
    "transactions.effects.status",
];

const TX_MASKS: &[&str] = &[
    "digest",
    "digest,transaction.digest,transaction.sender,transaction.kind,signatures.scheme,checkpoint,timestamp",
    "effects,balance_changes",
    "transaction.bcs,effects.bcs,events.bcs,signatures.bcs,effects.unchanged_loaded_runtime_objects,objects.objects.bcs",
    "*",
];

const OBJ_MASKS: &[&str] = &[
    "object_id,version,digest",
    "*",
    "bcs",
    "owner,object_type,has_public_transfer,previous_transaction,storage_rebate",
];

fn tree(s: &str) -> Result<FieldMaskTree> {
    tree_for::<Checkpoint>(s)
}

fn tree_for<M: sui_rpc::field::MessageFields>(s: &str) -> Result<FieldMaskTree> {
    let m = prost_types::FieldMask::from_str(s);
    if let Err(p) = m.validate::<M>() {
        bail!("invalid mask path {p} in {s}");
    }
    Ok(FieldMaskTree::from(m))
}

/// The service's get_checkpoint with the same branching (balance changes derived there).
/// render.rs `object_type_to_string`.
fn object_type_to_string(object_type: sui_types::base_types::ObjectType) -> String {
    match object_type {
        sui_types::base_types::ObjectType::Package => "package".to_owned(),
        sui_types::base_types::ObjectType::Struct(t) => t.to_canonical_string(true),
    }
}

/// render.rs `annotate_effects` without `render_clever_error` (needs the node's package store).
fn annotate_effects(
    effects: &mut sui_rpc::proto::sui::rpc::v2::TransactionEffects,
    objects: &sui_types::full_checkpoint_content::ObjectSet,
    mask: &FieldMaskTree,
) {
    use sui_rpc::proto::sui::rpc::v2::TransactionEffects;
    if mask.contains(TransactionEffects::CHANGED_OBJECTS_FIELD) {
        for changed_object in effects.changed_objects.iter_mut() {
            let Ok(object_id) = changed_object.object_id().parse::<sui_types::base_types::ObjectID>() else {
                continue;
            };
            if let Some(object) = objects.get(&sui_types::storage::ObjectKey(
                object_id,
                changed_object
                    .input_version_opt()
                    .unwrap_or_else(|| changed_object.output_version())
                    .into(),
            )) {
                changed_object.set_object_type(object_type_to_string(object.into()));
            }
        }
    }
    if mask.contains(TransactionEffects::UNCHANGED_CONSENSUS_OBJECTS_FIELD) {
        for unchanged in effects.unchanged_consensus_objects.iter_mut() {
            let Ok(object_id) = unchanged.object_id().parse::<sui_types::base_types::ObjectID>() else {
                continue;
            };
            if let Some(object) = objects.get(&sui_types::storage::ObjectKey(object_id, unchanged.version().into())) {
                unchanged.set_object_type(object_type_to_string(object.into()));
            }
        }
    }
}

fn get_checkpoint(cp: &FullCheckpoint, read_mask: &FieldMaskTree) -> Checkpoint {
    let summary = cp.summary.data();
    let signature = cp.summary.auth_sig();
    let sequence_number = summary.sequence_number;
    let timestamp_ms = summary.timestamp_ms;
    let mut checkpoint = Checkpoint::default();
    checkpoint.merge(summary, read_mask);
    checkpoint.merge(signature.clone(), read_mask);
    if read_mask.contains(Checkpoint::CONTENTS_FIELD.name) {
        checkpoint.merge(&cp.contents, read_mask);
    }
    if let Some(submask) = read_mask
        .subtree(Checkpoint::OBJECTS_FIELD)
        .and_then(|s| s.subtree(ObjectSet::OBJECTS_FIELD))
    {
        let set = cp
            .object_set
            .iter()
            .map(|o| sui_rpc::proto::sui::rpc::v2::Object::merge_from(o, &submask))
            .collect();
        checkpoint.objects = Some(ObjectSet::default().with_objects(set));
    }
    if let Some(submask) = read_mask.subtree(Checkpoint::TRANSACTIONS_FIELD.name) {
        checkpoint.transactions = cp
            .transactions
            .iter()
            .map(|t| {
                let balance_changes = if submask.contains(ExecutedTransaction::BALANCE_CHANGES_FIELD)
                {
                    derive_balance_changes_2(&t.effects, &cp.object_set)
                        .into_iter()
                        .map(Into::into)
                        .collect()
                } else {
                    Vec::new()
                };
                let mut transaction = ExecutedTransaction::merge_from(t, &submask);
                transaction.checkpoint = submask
                    .contains(ExecutedTransaction::CHECKPOINT_FIELD)
                    .then_some(sequence_number);
                transaction.timestamp = submask
                    .contains(ExecutedTransaction::TIMESTAMP_FIELD)
                    .then(|| sui_rpc::proto::timestamp_ms_to_proto(timestamp_ms));
                transaction.balance_changes = balance_changes;
                if let Some(effects_mask) = submask.subtree(ExecutedTransaction::EFFECTS_FIELD)
                    && let Some(effects) = transaction.effects.as_mut()
                {
                    annotate_effects(effects, &cp.object_set, &effects_mask);
                }
                transaction
            })
            .collect();
    }
    checkpoint
}

/// GetTransaction as the node renders it (get_transaction.rs `render_executed_transaction`):
/// the transaction's own object set (`get_transaction_object_set` keys, all must exist) feeds
/// effects annotation, balance changes and `objects`. None when an object is missing (the node
/// answers INTERNAL) and the mask reads the object set.
fn get_transaction(cp: &FullCheckpoint, idx: usize, mask: &FieldMaskTree) -> Option<GetTransactionResponse> {
    let t = &cp.transactions[idx];
    let needs_set = mask.contains(ExecutedTransaction::BALANCE_CHANGES_FIELD)
        || mask.contains(ExecutedTransaction::EFFECTS_FIELD)
        || mask.contains(ExecutedTransaction::OBJECTS_FIELD);
    let mut set = sui_types::full_checkpoint_content::ObjectSet::default();
    if needs_set {
        let keys = sui_types::storage::get_transaction_object_set(&t.transaction, &t.effects, &t.unchanged_loaded_runtime_objects);
        for k in keys {
            set.insert(cp.object_set.get(&k)?.clone());
        }
    }
    let summary = cp.summary.data();
    let mut transaction = ExecutedTransaction::merge_from(t, mask);
    transaction.checkpoint = mask.contains(ExecutedTransaction::CHECKPOINT_FIELD).then_some(summary.sequence_number);
    transaction.timestamp = mask
        .contains(ExecutedTransaction::TIMESTAMP_FIELD)
        .then(|| sui_rpc::proto::timestamp_ms_to_proto(summary.timestamp_ms));
    if mask.contains(ExecutedTransaction::BALANCE_CHANGES_FIELD) {
        transaction.balance_changes = derive_balance_changes_2(&t.effects, &set).into_iter().map(Into::into).collect();
    }
    if let Some(effects_mask) = mask.subtree(ExecutedTransaction::EFFECTS_FIELD)
        && let Some(effects) = transaction.effects.as_mut()
    {
        annotate_effects(effects, &set, &effects_mask);
    }
    if let Some(object_mask) = mask
        .subtree(ExecutedTransaction::OBJECTS_FIELD)
        .and_then(|s| s.subtree(ObjectSet::OBJECTS_FIELD))
    {
        transaction.objects = Some(ObjectSet::default().with_objects(set.iter().map(|o| Object::merge_from(o, &object_mask)).collect()));
    }
    Some(GetTransactionResponse::new(transaction))
}

/// `<corpus>/binpb-done/<seq>.binpb.zst` next to `<corpus>/chk/<seq>.chk`, decoded with sui-types'
/// `TryFrom<&Checkpoint>`.
fn archive_proto(chk: &Path, seq: u64) -> Result<Option<FullCheckpoint>> {
    let Some(corpus) = chk.parent().and_then(Path::parent) else { return Ok(None) };
    // binpb-done: the first archive checkpoints; binpb-r4: the lossy .chk ones, refetched in round 4.
    let Some(p) = ["binpb-done", "binpb-r4"].iter().map(|d| corpus.join(d).join(format!("{seq}.binpb.zst"))).find(|p| p.exists()) else {
        return Ok(None);
    };
    let dec = zstd::decode_all(&std::fs::read(&p)?[..])?;
    let proto = <Checkpoint as prost::Message>::decode(&dec[..])?;
    let cp: FullCheckpoint = (&proto).try_into().map_err(|e| anyhow::anyhow!("{}: {e:?}", p.display()))?;
    Ok(Some(cp))
}

fn gen_one(out: &Path, path: &Path, trees: &[FieldMaskTree]) -> Result<()> {
    let raw = std::fs::read(path)?;
    if raw.first() != Some(&1) {
        bail!("{}: bad blob tag", path.display());
    }
    let data: CheckpointData = bcs::from_bytes(&raw[1..]).context("decode")?;
    let seq = data.checkpoint_summary.data().sequence_number;
    let full: FullCheckpoint = match archive_proto(path, seq)? {
        Some(cp) => cp,
        None => data.into(),
    };
    let mut rec = Vec::new();
    for (i, t) in trees.iter().enumerate() {
        let resp = GetCheckpointResponse::new(get_checkpoint(&full, t));
        let b = prost::Message::encode_to_vec(&resp);
        rec.push(1u8);
        rec.push(i as u8);
        rec.extend_from_slice(&(b.len() as u32).to_le_bytes());
        rec.extend_from_slice(&b);
    }
    let z = zstd::encode_all(&rec[..], 3)?;
    std::fs::write(out.join(format!("{seq}.rec.zst")), z)?;
    gen_tx_obj(out, &full, seq)?;
    Ok(())
}

/// `<out>-tx/<seq>.rec.zst`: repeated [kind u8][mask_id u8][index u32 le][len u32 le][bytes];
/// kind 2 = GetTransactionResponse for transaction `index` of the checkpoint, kind 3 =
/// GetObjectResponse for object `index` of the checkpoint's object set (requested with its version).
fn gen_tx_obj(out: &Path, full: &FullCheckpoint, seq: u64) -> Result<()> {
    let dir = PathBuf::from(format!("{}-tx", out.display()));
    std::fs::create_dir_all(&dir)?;
    let tx_trees = TX_MASKS.iter().map(|m| tree_for::<ExecutedTransaction>(m)).collect::<Result<Vec<_>>>()?;
    let obj_trees = OBJ_MASKS.iter().map(|m| tree_for::<Object>(m)).collect::<Result<Vec<_>>>()?;
    let mut rec = Vec::new();
    let n = full.transactions.len();
    let picks: Vec<usize> = if n <= 6 { (0..n).collect() } else { (0..6).map(|i| i * (n - 1) / 5).collect() };
    for &i in &picks {
        for (mi, t) in tx_trees.iter().enumerate() {
            let Some(resp) = get_transaction(full, i, t) else { continue };
            let b = prost::Message::encode_to_vec(&resp);
            rec.push(2u8);
            rec.push(mi as u8);
            rec.extend_from_slice(&(i as u32).to_le_bytes());
            rec.extend_from_slice(&(b.len() as u32).to_le_bytes());
            rec.extend_from_slice(&b);
        }
    }
    let objs: Vec<&sui_types::object::Object> = full.object_set.iter().collect();
    let m = objs.len();
    let opicks: Vec<usize> = if m <= 4 { (0..m).collect() } else { (0..4).map(|i| i * (m - 1) / 3).collect() };
    for &i in &opicks {
        for (mi, t) in obj_trees.iter().enumerate() {
            let resp = GetObjectResponse::new(Object::merge_from(objs[i], t));
            let b = prost::Message::encode_to_vec(&resp);
            rec.push(3u8);
            rec.push(mi as u8);
            rec.extend_from_slice(&(i as u32).to_le_bytes());
            rec.extend_from_slice(&(b.len() as u32).to_le_bytes());
            rec.extend_from_slice(&b);
        }
    }
    let z = zstd::encode_all(&rec[..], 3)?;
    std::fs::write(dir.join(format!("{seq}.rec.zst")), z)?;
    Ok(())
}

/// Bench mask shared with the Zig bench (src/serve/conformance.zig `bench_mask`).
const BENCH_MASK: &str = "sequence_number,digest,summary,signature,transactions.digest,transactions.transaction.bcs,transactions.transaction.digest,transactions.transaction.sender,transactions.transaction.gas_payment,transactions.transaction.expiration,transactions.transaction.kind,transactions.signatures.bcs,transactions.signatures.scheme,transactions.effects.bcs,transactions.effects.digest,transactions.effects.epoch,transactions.effects.gas_used,transactions.effects.changed_objects,transactions.effects.dependencies,transactions.events.bcs,transactions.events.digest,transactions.checkpoint,transactions.timestamp,transactions.balance_changes";

/// `bench render --iters N --list FILE`: BCS CheckpointData -> GetCheckpointResponse bytes, the
/// whole path a node takes after reading a checkpoint (decode, convert, merge, prost encode).
fn bench_render(args: &[String]) -> Result<()> {
    let mut iters = 5usize;
    let mut list = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => { iters = args[i + 1].parse()?; i += 2; }
            "--list" => { list = Some(args[i + 1].clone()); i += 2; }
            a => bail!("unknown bench argument {a}"),
        }
    }
    let list = list.context("--list FILE")?;
    let files: Vec<PathBuf> = std::fs::read_to_string(&list)?.lines().filter(|l| !l.is_empty()).map(PathBuf::from).collect();
    let blobs: Vec<Vec<u8>> = files.iter().map(std::fs::read).collect::<Result<_, _>>()?;
    let tree = tree(BENCH_MASK)?;
    let mut txs = 0u64;
    for b in &blobs {
        let d: CheckpointData = bcs::from_bytes(&b[1..])?;
        txs += d.transactions.len() as u64;
    }
    let run = || -> Result<usize> {
        let mut n = 0;
        for b in &blobs {
            let d: CheckpointData = bcs::from_bytes(&b[1..])?;
            let full: FullCheckpoint = d.into();
            let resp = GetCheckpointResponse::new(get_checkpoint(&full, &tree));
            n += prost::Message::encode_to_vec(&resp).len();
        }
        Ok(n)
    };
    std::hint::black_box(run()?);
    let mut v = Vec::new();
    for _ in 0..iters.max(1) {
        let t = std::time::Instant::now();
        std::hint::black_box(run()?);
        v.push(t.elapsed().as_nanos());
    }
    v.sort();
    let med = v[v.len() / 2];
    println!("{{\"impl\":\"rust\",\"bench\":\"render-checkpoint\",\"unit\":\"tx\",\"units\":{},\"iters\":{},\"median_ns\":{},\"min_ns\":{},\"ns_per_unit\":{:.2}}}", txs, v.len(), med, v[0], med as f64 / txs.max(1) as f64);
    Ok(())
}

/// `bench pkg <dir> [iters]`: GetFunction and GetDatatype over every package record in the pkg
/// vector directory. "cached" is what the node does per request once its package cache holds the
/// parsed `Package` (module lookup, definition, conversion, prost encode); "parse" also reads the
/// package from the object each time (truth `get_*_response`).
/// The parsing variant times every PARSE_STRIDE-th request of each package (one parse is ~0.5 ms).
const PARSE_STRIDE: usize = 50;

fn bench_pkg(args: &[String]) -> Result<()> {
    use sui_types::object::Object;
    // `bench pkg <dir> [iters]`, or the harness form `bench pkg --list FILE [--iters N]` (the pkg
    // vector directory under $ZUI_CORPUS; the list is the render bench's and is ignored).
    let (dir, iters): (PathBuf, usize) = if args.first().is_some_and(|a| a.starts_with("--")) {
        let it = args.iter().position(|a| a == "--iters").map(|i| args[i + 1].parse()).transpose()?.unwrap_or(5);
        (PathBuf::from(std::env::var("ZUI_CORPUS")?).join("vectors/grpc-v2-pkg"), it)
    } else {
        (PathBuf::from(args.first().context("dir")?), args.get(1).map(|s| s.parse()).transpose()?.unwrap_or(5))
    };
    let mut pkgs = Vec::new();
    for e in std::fs::read_dir(&dir)? {
        let p = e?.path();
        if !p.to_string_lossy().ends_with(".pkg.zst") {
            continue;
        }
        let rec = zstd::decode_all(&std::fs::read(&p)?[..])?;
        let olen = u32::from_le_bytes(rec[0..4].try_into()?) as usize;
        let obj: Object = bcs::from_bytes(&rec[4..4 + olen])?;
        let mut pos = 4 + olen;
        let mut items = Vec::new();
        while pos < rec.len() {
            let kind = rec[pos];
            let ml = u16::from_le_bytes(rec[pos + 1..pos + 3].try_into()?) as usize;
            let m = String::from_utf8(rec[pos + 3..pos + 3 + ml].to_vec())?;
            pos += 3 + ml;
            let nl = u16::from_le_bytes(rec[pos..pos + 2].try_into()?) as usize;
            let n = String::from_utf8(rec[pos + 2..pos + 2 + nl].to_vec())?;
            pos += 2 + nl;
            let st = rec[pos];
            let bl = u32::from_le_bytes(rec[pos + 1..pos + 5].try_into()?) as usize;
            pos += 5 + bl;
            if st == 0 && kind >= 2 && !n.starts_with("NoSuch") && n != "no_such_fn" && m != "no_such_module" {
                items.push((kind, m, n));
            }
        }
        pkgs.push((obj, items));
    }
    let n: usize = pkgs.iter().map(|p| p.1.len()).sum();
    let parsed: Vec<_> = pkgs
        .iter()
        .map(|(o, _)| sui_package_resolver::Package::read_from_package(o.data.try_as_package().unwrap()).map_err(|e| anyhow::anyhow!("{e}")))
        .collect::<Result<_>>()?;
    let cached = || -> Result<usize> {
        let mut bytes = 0;
        for ((o, items), rp) in pkgs.iter().zip(&parsed) {
            let pkg = o.data.try_as_package().unwrap();
            for (kind, m, nm) in items {
                let module = rp.module(m).map_err(|e| anyhow::anyhow!("{e}"))?;
                if *kind == 2 {
                    let d = module.data_def(nm).map_err(|e| anyhow::anyhow!("{e}"))?.unwrap();
                    bytes += prost::Message::encode_to_vec(&sui_rpc::proto::sui::rpc::v2::GetDatatypeResponse::new(pkgconv::convert_datatype(nm, &d, &pkg.id(), m))).len();
                } else {
                    let f = module.function_def(nm).map_err(|e| anyhow::anyhow!("{e}"))?.unwrap();
                    bytes += prost::Message::encode_to_vec(&sui_rpc::proto::sui::rpc::v2::GetFunctionResponse::new(pkgconv::convert_function(nm, &f))).len();
                }
            }
        }
        Ok(bytes)
    };
    let parse = || -> Result<usize> {
        let mut bytes = 0;
        for (o, items) in &pkgs {
            let pkg = o.data.try_as_package().unwrap();
            for (kind, m, nm) in items.iter().step_by(PARSE_STRIDE) {
                bytes += if *kind == 2 {
                    prost::Message::encode_to_vec(&pkgconv::get_datatype_response(pkg, m, nm).map_err(|e| anyhow::anyhow!("{e}"))?).len()
                } else {
                    prost::Message::encode_to_vec(&pkgconv::get_function_response(pkg, m, nm).map_err(|e| anyhow::anyhow!("{e}"))?).len()
                };
            }
        }
        Ok(bytes)
    };
    let n_parse: usize = pkgs.iter().map(|p| p.1.len().div_ceil(PARSE_STRIDE)).sum();
    for (name, units, f) in [("package-member-cached-pkg", n, &cached as &dyn Fn() -> Result<usize>), ("package-member-parse", n_parse, &parse)] {
        std::hint::black_box(f()?);
        let mut v = Vec::new();
        for _ in 0..iters.max(1) {
            let t = std::time::Instant::now();
            std::hint::black_box(f()?);
            v.push(t.elapsed().as_nanos());
        }
        v.sort();
        let med = v[v.len() / 2];
        println!("{{\"impl\":\"rust\",\"bench\":\"{name}\",\"unit\":\"request\",\"units\":{units},\"iters\":{},\"median_ns\":{med},\"min_ns\":{},\"ns_per_unit\":{:.2}}}", v.len(), v[0], med as f64 / units.max(1) as f64);
    }
    Ok(())
}

/// `status <out_dir>`: request handling on an empty store, as sui-rpc-api 1.83.1 does it
/// (get_checkpoint.rs, get_transaction.rs, get_object.rs): the request bytes are decoded with
/// prost (so a repeated `read_mask` merges), validated in the handler's order with sui-rpc's
/// `FieldMaskUtil::validate` and sui-sdk-types' `Digest`/`Address` parsers, and every store
/// lookup misses. One line per case in `<out_dir>/status-r3.txt`:
/// `<case>\t<method>\t<request hex>\t<grpc code>\t<hex>` where `<hex>` is the
/// `grpc-status-details-bin` payload (`RpcError::into_status_proto`) when the code is not 0 and
/// the response message when it is 0 (batch calls with per-item errors).
fn gen_status(out: &Path) -> Result<()> {
    use prost::Message;
    use sui_rpc::proto::google::rpc::{BadRequest, Status, bad_request::FieldViolation};
    use sui_rpc::proto::sui::rpc::v2::{
        BatchGetObjectsRequest, BatchGetObjectsResponse, BatchGetTransactionsRequest, BatchGetTransactionsResponse,
        ErrorReason, GetCheckpointRequest, GetObjectRequest, GetObjectResult, GetTransactionRequest, GetTransactionResult,
        get_checkpoint_request::CheckpointId,
    };
    use sui_sdk_types::{Address, Digest};

    // RpcError as error.rs builds it: (code, message, details)
    struct E(i32, String, Option<BadRequest>);
    fn fv(v: FieldViolation) -> E {
        let msg = v.description.clone();
        E(3, msg, Some(BadRequest::from(v)))
    }
    fn status_proto(e: E) -> Status {
        let details = e.2.map(|b| vec![prost_types::Any::from_msg(&b).unwrap()]).unwrap_or_default();
        Status { code: e.0, message: e.1, details }
    }
    // tonic's prost decoder: Status::internal(DecodeError), no details
    fn dec(e: prost::DecodeError) -> E {
        E(13, e.to_string(), None)
    }
    fn mask_err(path: &str) -> E {
        fv(FieldViolation::new("read_mask")
            .with_description(format!("invalid read_mask path: {path}"))
            .with_reason(ErrorReason::FieldInvalid))
    }
    fn mask_check<M: sui_rpc::field::MessageFields>(m: Option<prost_types::FieldMask>, default: &str) -> Result<(), E> {
        let m = m.unwrap_or_else(|| prost_types::FieldMask::from_str(default));
        m.validate::<M>().map_err(mask_err)
    }
    // error.rs / reader.rs Display impls
    fn tx_not_found(d: Digest) -> E {
        E(5, format!("Transaction {d} not found"), None)
    }
    fn obj_not_found(a: Address, v: Option<u64>) -> E {
        match v {
            Some(v) => E(5, format!("Object {a} with version {v} not found"), None),
            None => E(5, format!("Object {a} not found"), None),
        }
    }

    fn get_checkpoint(b: &[u8]) -> Result<Vec<u8>, E> {
        let r = GetCheckpointRequest::decode(b).map_err(dec)?;
        mask_check::<Checkpoint>(r.read_mask, "sequence_number,digest")?;
        Err(match r.checkpoint_id {
            Some(CheckpointId::SequenceNumber(s)) => E(5, format!("Checkpoint {s} not found"), None),
            Some(CheckpointId::Digest(d)) => match d.parse::<Digest>() {
                Err(e) => fv(FieldViolation::new("digest").with_description(format!("invalid digest: {e}")).with_reason(ErrorReason::FieldInvalid)),
                Ok(d) => E(5, format!("Checkpoint {d} not found"), None),
            },
            _ => unreachable!("latest on an empty store is not a case"),
        })
    }
    fn tx_digest(d: Option<String>, field: FieldViolation) -> Result<Digest, E> {
        let d = d.ok_or_else(|| fv(FieldViolation::new("digest").with_description("missing digest").with_reason(ErrorReason::FieldMissing)))?;
        d.parse::<Digest>().map_err(|e| fv(field.with_description(format!("invalid digest: {e}")).with_reason(ErrorReason::FieldInvalid)))
    }
    fn get_transaction(b: &[u8]) -> Result<Vec<u8>, E> {
        let r = GetTransactionRequest::decode(b).map_err(dec)?;
        let d = tx_digest(r.digest, FieldViolation::new("digest"))?;
        mask_check::<ExecutedTransaction>(r.read_mask, "digest")?;
        Err(tx_not_found(d))
    }
    fn batch_get_transactions(b: &[u8]) -> Result<Vec<u8>, E> {
        let r = BatchGetTransactionsRequest::decode(b).map_err(dec)?;
        mask_check::<ExecutedTransaction>(r.read_mask, "digest")?;
        if r.digests.len() > 200 {
            return Err(E(3, "number of batch requests exceed limit of 200".into(), None));
        }
        let items = r.digests.into_iter().enumerate().map(|(i, d)| {
            let e = match d.parse::<Digest>() {
                Err(e) => fv(FieldViolation::new_at("digests", i).with_description(format!("invalid digest: {e}")).with_reason(ErrorReason::FieldInvalid)),
                Ok(d) => tx_not_found(d),
            };
            GetTransactionResult::new_error(status_proto(e))
        });
        Ok(BatchGetTransactionsResponse::new(items.collect()).encode_to_vec())
    }
    fn object_reqs(reqs: Vec<(Option<String>, Option<u64>)>, m: Option<prost_types::FieldMask>) -> Result<Vec<(Address, Option<u64>)>, E> {
        mask_check::<Object>(m, "object_id,version,digest")?;
        reqs.into_iter()
            .enumerate()
            .map(|(i, (id, v))| {
                let id = id.ok_or_else(|| fv(FieldViolation::new("object_id").with_reason(ErrorReason::FieldMissing).nested_at("requests", i)))?;
                let a = id.parse::<Address>().map_err(|e| {
                    fv(FieldViolation::new("object_id").with_description(format!("invalid object_id: {e}")).with_reason(ErrorReason::FieldInvalid).nested_at("requests", i))
                })?;
                Ok((a, v))
            })
            .collect()
    }
    // MovePackageService on an empty store (move_package_service/{mod,get_package,get_datatype,get_function}.rs)
    fn load_package(id: &str) -> Result<Vec<u8>, E> {
        let _ = id.parse::<sui_types::base_types::ObjectID>().map_err(|e| {
            fv(FieldViolation::new("package_id").with_description(format!("invalid package_id: {e}")).with_reason(ErrorReason::FieldInvalid))
        })?;
        Err(E(5, String::new(), None)) // RpcError::not_found(): no message
    }
    fn missing(f: &str) -> E {
        fv(FieldViolation::new(f).with_description(format!("missing {f}")).with_reason(ErrorReason::FieldMissing))
    }
    fn get_package(b: &[u8]) -> Result<Vec<u8>, E> {
        let r = sui_rpc::proto::sui::rpc::v2::GetPackageRequest::decode(b).map_err(dec)?;
        load_package(r.package_id.as_deref().ok_or_else(|| missing("package_id"))?)
    }
    fn get_member(id: Option<String>, m: Option<String>, n: Option<String>) -> Result<Vec<u8>, E> {
        let id = id.ok_or_else(|| missing("package_id"))?;
        m.ok_or_else(|| missing("module_name"))?;
        n.ok_or_else(|| missing("name"))?;
        load_package(&id)
    }
    fn get_datatype(b: &[u8]) -> Result<Vec<u8>, E> {
        let r = sui_rpc::proto::sui::rpc::v2::GetDatatypeRequest::decode(b).map_err(dec)?;
        get_member(r.package_id, r.module_name, r.name)
    }
    fn get_function(b: &[u8]) -> Result<Vec<u8>, E> {
        let r = sui_rpc::proto::sui::rpc::v2::GetFunctionRequest::decode(b).map_err(dec)?;
        get_member(r.package_id, r.module_name, r.name)
    }
    fn get_object(b: &[u8]) -> Result<Vec<u8>, E> {
        let r = GetObjectRequest::decode(b).map_err(dec)?;
        let reqs = object_reqs(vec![(r.object_id, r.version)], r.read_mask)?;
        Err(obj_not_found(reqs[0].0, reqs[0].1))
    }
    fn batch_get_objects(b: &[u8]) -> Result<Vec<u8>, E> {
        let r = BatchGetObjectsRequest::decode(b).map_err(dec)?;
        if r.requests.len() > 1000 {
            return Err(E(3, "number of batch requests exceed limit of 1000".into(), None));
        }
        let reqs = object_reqs(r.requests.into_iter().map(|q| (q.object_id, q.version)).collect(), r.read_mask)?;
        let items = reqs.into_iter().map(|(a, v)| GetObjectResult::new_error(status_proto(obj_not_found(a, v))));
        Ok(BatchGetObjectsResponse::new(items.collect()).encode_to_vec())
    }

    let fm = |paths: &[&str]| prost_types::FieldMask { paths: paths.iter().map(|p| p.to_string()).collect() };
    let ckpt = |seq: Option<u64>, digest: Option<&str>, mask: Option<prost_types::FieldMask>| {
        let mut r = GetCheckpointRequest::default();
        r.read_mask = mask;
        if let Some(s) = seq {
            r.checkpoint_id = Some(CheckpointId::SequenceNumber(s));
        }
        if let Some(d) = digest {
            r.checkpoint_id = Some(CheckpointId::Digest(d.into()));
        }
        r.encode_to_vec()
    };
    let tx = |d: Option<&str>, mask: Option<prost_types::FieldMask>| {
        let mut r = GetTransactionRequest::default();
        r.digest = d.map(Into::into);
        r.read_mask = mask;
        r.encode_to_vec()
    };
    let obj_req = |id: Option<&str>, v: Option<u64>| {
        let mut r = GetObjectRequest::default();
        r.object_id = id.map(Into::into);
        r.version = v;
        r
    };
    let obj = |id: Option<&str>, v: Option<u64>, mask: Option<prost_types::FieldMask>| {
        let mut r = obj_req(id, v);
        r.read_mask = mask;
        r.encode_to_vec()
    };
    let btx = |ds: Vec<String>, mask: Option<prost_types::FieldMask>| {
        let mut r = BatchGetTransactionsRequest::default();
        r.digests = ds;
        r.read_mask = mask;
        r.encode_to_vec()
    };
    let bobj = |qs: Vec<GetObjectRequest>, mask: Option<prost_types::FieldMask>| {
        let mut r = BatchGetObjectsRequest::default();
        r.requests = qs;
        r.read_mask = mask;
        r.encode_to_vec()
    };
    let cat = |a: Vec<u8>, b: Vec<u8>| [a, b].concat();

    const CP: &str = "GetCheckpoint";
    const TX: &str = "GetTransaction";
    const OB: &str = "GetObject";
    const BT: &str = "BatchGetTransactions";
    const BO: &str = "BatchGetObjects";
    const GP: &str = "MovePackageService/GetPackage";
    const GD: &str = "MovePackageService/GetDatatype";
    const GF: &str = "MovePackageService/GetFunction";
    let gpk = |id: Option<&str>, sel: Option<sui_rpc::proto::sui::rpc::v2::get_package_request::Selector>| {
        let mut r = sui_rpc::proto::sui::rpc::v2::GetPackageRequest::default();
        r.package_id = id.map(Into::into);
        r.selector = sel;
        r.encode_to_vec()
    };
    let gmember = |id: Option<&str>, m: Option<&str>, n: Option<&str>| {
        let mut r = sui_rpc::proto::sui::rpc::v2::GetDatatypeRequest::default();
        r.package_id = id.map(Into::into);
        r.module_name = m.map(Into::into);
        r.name = n.map(Into::into);
        r.encode_to_vec()
    };
    use sui_rpc::proto::sui::rpc::v2::get_package_request::Selector as Sel;
    let cases: Vec<(&str, &str, Vec<u8>)> = vec![
        ("read_mask/summary.nope", CP, ckpt(Some(1), None, Some(fm(&["summary.nope"])))),
        ("read_mask/empty", CP, ckpt(Some(1), None, Some(fm(&[""])))),
        ("read_mask/trailing-dot-ok", CP, ckpt(Some(7), None, Some(fm(&["summary."])))),
        ("read_mask/star-ok", CP, ckpt(Some(7), None, Some(fm(&["*"])))),
        // a message field seen twice is merged by prost: the bad path of the first copy counts
        ("read_mask/merged", CP, cat(ckpt(None, None, Some(fm(&["summary.nope"]))), ckpt(Some(3), None, Some(fm(&["digest"]))))),
        ("read_mask/tx-bad", TX, tx(Some("11111111111111111111111111111111"), Some(fm(&["effects.nope"])))),
        ("read_mask/batch-tx-bad", BT, btx(vec!["x".into()], Some(fm(&["transaction.kind.zzz"])))),
        ("read_mask/obj-bad", OB, obj(Some("0x2"), None, Some(fm(&["json.x", "owner"])))),
        ("checkpoint/not-found", CP, ckpt(Some(123456789), None, None)),
        ("checkpoint/digest-invalid", CP, ckpt(None, Some("0OIl"), None)),
        ("digest/missing", TX, tx(None, None)),
        ("digest/invalid", TX, tx(Some("not-a-digest"), None)),
        ("digest/too-long", TX, tx(Some("JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFGG"), None)),
        ("digest/not-found", TX, tx(Some("JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG"), None)),
        ("digest/short", TX, tx(Some("2"), None)),
        ("digest/empty", TX, tx(Some(""), None)),
        ("digest/ones", TX, tx(Some("1111111111111111111111111111111111"), None)),
        ("digest/leading-one", TX, tx(Some("12"), None)),
        ("digest/bad-before-mask", TX, tx(Some("0"), Some(fm(&["nope"])))),
        ("object_id/invalid", OB, obj(Some("0xzz"), None, None)),
        ("object_id/missing", OB, obj(None, None, None)),
        ("object_id/upper-prefix", OB, obj(Some("0X2"), None, None)),
        ("object_id/bare-0x", OB, obj(Some("0x"), None, None)),
        ("object_id/empty", OB, obj(Some(""), None, None)),
        ("object_id/too-long", OB, obj(Some(&format!("0x{}", "1".repeat(65))), None, None)),
        ("object_id/no-prefix", OB, obj(Some("2"), None, None)),
        ("object_id/odd", OB, obj(Some("0xabc"), Some(9), None)),
        ("object_id/version-zero", OB, obj(Some("0x5"), Some(0), None)),
        ("batch-tx/limit", BT, btx((0..201).map(|_| "x".to_string()).collect(), None)),
        ("batch-tx/limit-ok", BT, btx((0..200).map(|_| "2".to_string()).collect(), None)),
        ("batch-tx/items", BT, btx(vec!["bad!".into(), "2".into(), "".into()], None)),
        ("batch-tx/empty", BT, btx(vec![], None)),
        ("batch-obj/limit", BO, bobj((0..1001).map(|_| obj_req(Some("zz"), None)).collect(), Some(fm(&["nope"])))),
        ("batch-obj/items", BO, bobj(vec![obj_req(Some("0x2"), None), obj_req(Some("0x3"), Some(4))], None)),
        ("batch-obj/second-invalid", BO, bobj(vec![obj_req(Some("0x2"), None), obj_req(Some("0xq"), None)], None)),
        ("pkg/missing-id", GP, gpk(None, None)),
        ("pkg/id-short-no-prefix", GP, gpk(Some("2"), None)),
        ("pkg/id-empty", GP, gpk(Some(""), None)),
        ("pkg/id-0x", GP, gpk(Some("0x"), None)),
        ("pkg/id-0x2", GP, gpk(Some("0x2"), None)),
        ("pkg/id-0X2", GP, gpk(Some("0X2"), None)),
        ("pkg/id-bare64", GP, gpk(Some(&"ab".repeat(32)), None)),
        ("pkg/id-0x64", GP, gpk(Some(&format!("0x{}", "ab".repeat(32))), None)),
        ("pkg/id-0x66", GP, gpk(Some(&format!("0x{}", "ab".repeat(33))), None)),
        ("pkg/id-nonhex", GP, gpk(Some("0xzz"), None)),
        ("pkg/id-odd", GP, gpk(Some("0xabc"), None)),
        ("pkg/id-0x0x", GP, gpk(Some("0x0x5"), None)),
        ("pkg/id-0x-x62", GP, gpk(Some(&format!("0xx{}", "a".repeat(62))), None)),
        ("pkg/id-upper", GP, gpk(Some(&format!("0x{}", "AB".repeat(32))), None)),
        ("pkg/id-nonhex64", GP, gpk(Some(&"zz".repeat(32)), None)),
        ("pkg/version", GP, gpk(Some("0x2"), Some(Sel::Version(3)))),
        ("pkg/at-checkpoint", GP, gpk(Some("0x2"), Some(Sel::AtCheckpoint(3)))),
        ("pkg/selector-invalid-id", GP, gpk(Some("nope"), Some(Sel::Version(3)))),
        ("pkg/dt-missing-id", GD, gmember(None, Some("m"), Some("n"))),
        ("pkg/dt-missing-module", GD, gmember(Some("bad"), None, Some("n"))),
        ("pkg/dt-missing-name", GD, gmember(Some("bad"), Some("m"), None)),
        ("pkg/dt-invalid-id", GD, gmember(Some("bad"), Some("m"), Some("n"))),
        ("pkg/dt-not-found", GD, gmember(Some("0x2"), Some("m"), Some("n"))),
        ("pkg/fn-missing-name", GF, gmember(Some("0x2"), Some("m"), None)),
        ("pkg/fn-not-found", GF, gmember(Some("0x2"), Some("m"), Some("n"))),
        ("pkg/decode-selector-wire", GP, vec![0x12, 0x01, 0x31]),
        ("pkg/decode-id-varint", GD, vec![0x08, 0x01]),
        ("decode/digest-varint", TX, vec![0x08, 0x01]),
        ("decode/seq-string", CP, vec![0x0a, 0x01, 0x31]),
        ("decode/mask-varint", TX, vec![0x10, 0x01]),
        ("decode/mask-path-utf8", TX, vec![0x12, 0x03, 0x0a, 0x01, 0xff]),
        ("decode/digest-utf8", TX, vec![0x0a, 0x01, 0xff]),
        ("decode/underflow", TX, vec![0x0a, 0x05, 0x31]),
        ("decode/key-truncated", TX, vec![0x0a]),
        ("decode/varint-truncated", CP, vec![0x08, 0x80]),
        ("decode/tag-zero", TX, vec![0x00, 0x01]),
        ("decode/wire-6", TX, vec![0x0e]),
        ("decode/varint-long", CP, vec![0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
        ("decode/varint-10b-ok", CP, vec![0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]),
        ("decode/obj-id-varint", BO, vec![0x0a, 0x02, 0x08, 0x01]),
        ("decode/obj-version-string", OB, vec![0x12, 0x01, 0x31]),
        ("decode/delimited-exceeded", BO, vec![0x0a, 0x02, 0x0a, 0x02, 0x31, 0x32]),
        ("decode/group-ok", TX, vec![0x1b, 0x08, 0x01, 0x1c]),
        ("decode/group-mismatch", TX, vec![0x1b, 0x24]),
        ("decode/end-group-unknown", TX, vec![0x24]),
        ("decode/end-group-known", TX, vec![0x0c]),
        ("decode/oneof-wire", CP, vec![0x10, 0x01]),
        ("decode/batch-digest-varint", BT, vec![0x08, 0x01]),
        ("decode/second-bad", BT, vec![0x0a, 0x01, 0x32, 0x0a, 0x01, 0xff]),
        ("decode/mask-in-mask", TX, vec![0x12, 0x02, 0x08, 0x01]),
        ("decode/mask-len", TX, vec![0x12, 0x05, 0x0a]),
        // reviewer (round 3): prost edges the first list lacks
        ("decode/group-depth-100", TX, [vec![0x1b; 100], vec![0x1c; 100]].concat()),
        ("decode/group-depth-101", TX, [vec![0x1b; 101], vec![0x1c; 101]].concat()),
        ("decode/group-depth-100-pkg", GF, [vec![0x2b; 100], vec![0x2c; 100]].concat()),
        ("decode/many-groups", TX, [0x1b, 0x1c].repeat(50_000)),
        ("decode/key-too-large", TX, vec![0x80, 0x80, 0x80, 0x80, 0x10]),
        ("decode/key-u32-max", TX, vec![0xff, 0xff, 0xff, 0xff, 0x0f]),
        ("decode/unknown-len-underflow", TX, vec![0x1a, 0x05, 0x01]),
        ("decode/unknown-fixed64-short", TX, vec![0x19, 0x01, 0x02]),
        ("decode/unknown-fixed32-ok", TX, vec![0x25, 0x01, 0x02, 0x03, 0x04]),
        ("decode/mask-path-wire", OB, vec![0x1a, 0x02, 0x08, 0x01]),
        ("decode/batch-obj-mask-in-item", BO, vec![0x0a, 0x04, 0x1a, 0x02, 0x08, 0x01]),
        ("decode/pkg-name-utf8", GD, vec![0x1a, 0x02, 0xc3, 0x28]),
        ("decode/pkg-at-checkpoint-wire", GP, vec![0x1a, 0x00]),
        ("decode/service-info-garbage", "GetServiceInfo", vec![0x0a, 0x05]),
        ("batch-obj/second-missing", BO, bobj(vec![obj_req(Some("0x2"), None), obj_req(None, Some(1))], None)),
    ];
    std::fs::create_dir_all(out)?;
    let mut f = std::fs::File::create(out.join("status-r3.txt"))?;
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    for (name, method, req) in cases {
        let r = match method {
            CP => get_checkpoint(&req),
            TX => get_transaction(&req),
            OB => get_object(&req),
            BT => batch_get_transactions(&req),
            BO => batch_get_objects(&req),
            GP => get_package(&req),
            GD => get_datatype(&req),
            GF => get_function(&req),
            // only undecodable bodies: a decoded GetServiceInfo needs a populated store
            "GetServiceInfo" => Err(dec(sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest::decode(&req[..]).expect_err("decodes"))),
            _ => unreachable!(),
        };
        let (code, bytes) = match r {
            Ok(resp) => (0, resp),
            // a decode error is a plain Status::internal: no details header, only the message
            Err(E(13, m, None)) => {
                writeln!(f, "{name}\t{method}\t{}\t13\t{}\tdecode", hex(&req), hex(m.as_bytes()))?;
                continue;
            }
            Err(e) => (e.0, status_proto(e).encode_to_vec()),
        };
        writeln!(f, "{name}\t{method}\t{}\t{code}\t{}", hex(&req), hex(&bytes))?;
    }
    Ok(())
}

/// `exec-status <out_dir>`: every `ExecutionErrorKind` variant (and a few value shapes), as
/// `[bcs(ExecutionStatus) len u32][bcs][proto len u32][prost(TransactionEffects { status })]`
/// records in `<out_dir>/exec-status.bin`. The proto side is Mysten's `From<ExecutionStatus>`, whose
/// `description` is the Rust `Debug` text of the error.
fn gen_exec_status(out: &Path) -> Result<()> {
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    use move_core_types::language_storage::ModuleId;
    use sui_rpc::proto::sui::rpc::v2::TransactionEffects as ProtoEffects;
    use sui_types::base_types::{ObjectID, SuiAddress};
    use sui_types::execution_status::{
        CommandArgumentError as C, CongestedObjects, ExecutionFailure, ExecutionStatus as ES, ExecutionErrorKind as E,
        MoveLocation, MoveLocationOpt, PackageUpgradeError as P, TypeArgumentError as T,
    };
    let oid = |b: u8| ObjectID::new([b; 32]);
    let loc = |f: Option<&str>| MoveLocation {
        module: ModuleId::new(AccountAddress::new([0xab; 32]), Identifier::new("my_mod").unwrap()),
        function: 7,
        instruction: 300,
        function_name: f.map(str::to_owned),
    };
    let kinds: Vec<E> = vec![
        E::InsufficientGas, E::InvalidGasObject, E::InvariantViolation, E::FeatureNotYetSupported,
        E::MoveObjectTooBig { object_size: 1, max_object_size: 2 },
        E::MovePackageTooBig { object_size: 300, max_object_size: 70000 },
        E::CircularObjectOwnership { object: oid(3) },
        E::InsufficientCoinBalance, E::CoinBalanceOverflow, E::PublishErrorNonZeroAddress, E::SuiMoveVerificationError,
        E::MovePrimitiveRuntimeError(MoveLocationOpt(None)),
        E::MovePrimitiveRuntimeError(MoveLocationOpt(Some(loc(Some("fun"))))),
        E::MoveAbort(loc(None), 0),
        E::MoveAbort(loc(Some("with \"quote\" and \\ slash\n")), u64::MAX),
        E::VMVerificationOrDeserializationError, E::VMInvariantViolation, E::FunctionNotFound, E::ArityMismatch,
        E::TypeArityMismatch, E::NonEntryFunctionInvoked,
        E::CommandArgumentError { arg_idx: 2, kind: C::TypeMismatch },
        E::CommandArgumentError { arg_idx: 3, kind: C::InvalidBCSBytes },
        E::CommandArgumentError { arg_idx: 3, kind: C::InvalidUsageOfPureArg },
        E::CommandArgumentError { arg_idx: 3, kind: C::InvalidArgumentToPrivateEntryFunction },
        E::CommandArgumentError { arg_idx: 4, kind: C::IndexOutOfBounds { idx: 9 } },
        E::CommandArgumentError { arg_idx: 5, kind: C::SecondaryIndexOutOfBounds { result_idx: 1, secondary_idx: 2 } },
        E::CommandArgumentError { arg_idx: 6, kind: C::InvalidResultArity { result_idx: 4 } },
        E::CommandArgumentError { arg_idx: 6, kind: C::InvalidGasCoinUsage },
        E::CommandArgumentError { arg_idx: 6, kind: C::InvalidValueUsage },
        E::CommandArgumentError { arg_idx: 6, kind: C::InvalidObjectByValue },
        E::CommandArgumentError { arg_idx: 6, kind: C::InvalidObjectByMutRef },
        E::CommandArgumentError { arg_idx: 6, kind: C::SharedObjectOperationNotAllowed },
        E::CommandArgumentError { arg_idx: 6, kind: C::InvalidArgumentArity },
        E::CommandArgumentError { arg_idx: 6, kind: C::InvalidTransferObject },
        E::CommandArgumentError { arg_idx: 6, kind: C::InvalidMakeMoveVecNonObjectArgument },
        E::CommandArgumentError { arg_idx: 6, kind: C::ArgumentWithoutValue },
        E::CommandArgumentError { arg_idx: 6, kind: C::CannotMoveBorrowedValue },
        E::CommandArgumentError { arg_idx: 6, kind: C::CannotWriteToExtendedReference },
        E::CommandArgumentError { arg_idx: 6, kind: C::InvalidReferenceArgument },
        E::CommandArgumentError { arg_idx: 6, kind: C::InvalidTxContext },
        E::TypeArgumentError { argument_idx: 1, kind: T::TypeNotFound },
        E::TypeArgumentError { argument_idx: 1, kind: T::ConstraintNotSatisfied },
        E::UnusedValueWithoutDrop { result_idx: 5, secondary_idx: 6 },
        E::InvalidPublicFunctionReturnType { idx: 8 },
        E::InvalidTransferObject,
        E::EffectsTooLarge { current_size: 10, max_size: 20 },
        E::PublishUpgradeMissingDependency, E::PublishUpgradeDependencyDowngrade,
        E::PackageUpgradeError { upgrade_error: P::UnableToFetchPackage { package_id: oid(4) } },
        E::PackageUpgradeError { upgrade_error: P::NotAPackage { object_id: oid(5) } },
        E::PackageUpgradeError { upgrade_error: P::IncompatibleUpgrade },
        E::PackageUpgradeError { upgrade_error: P::DigestDoesNotMatch { digest: vec![7; 32] } },
        E::PackageUpgradeError { upgrade_error: P::DigestDoesNotMatch { digest: vec![1, 2, 3] } },
        E::PackageUpgradeError { upgrade_error: P::UnknownUpgradePolicy { policy: 9 } },
        E::PackageUpgradeError { upgrade_error: P::PackageIDDoesNotMatch { package_id: oid(6), ticket_id: oid(7) } },
        E::WrittenObjectsTooLarge { current_size: 11, max_size: 12 },
        E::CertificateDenied, E::SuiMoveVerificationTimedout, E::SharedObjectOperationNotAllowed, E::InputObjectDeleted,
        E::ExecutionCancelledDueToSharedObjectCongestion { congested_objects: CongestedObjects(vec![]) },
        E::ExecutionCancelledDueToSharedObjectCongestion { congested_objects: CongestedObjects(vec![oid(8), oid(9)]) },
        E::AddressDeniedForCoin { address: SuiAddress::from(oid(10)), coin_type: "0x2::sui::SUI".to_owned() },
        E::CoinTypeGlobalPause { coin_type: "0xabc::m::T<u8>".to_owned() },
        E::ExecutionCancelledDueToRandomnessUnavailable,
        E::MoveVectorElemTooBig { value_size: 13, max_scaled_size: 14 },
        E::MoveRawValueTooBig { value_size: 15, max_scaled_size: 16 },
        E::InvalidLinkage, E::InsufficientFundsForWithdraw,
        E::NonExclusiveWriteInputObjectModified { id: oid(11) },
    ];
    let mut f: Vec<u8> = Vec::new();
    let mut put = |st: ES| -> Result<()> {
        let b = bcs::to_bytes(&st)?;
        let msg = ProtoEffects::default().with_status(sui_rpc::proto::sui::rpc::v2::ExecutionStatus::from(st));
        let p = prost::Message::encode_to_vec(&msg);
        f.extend_from_slice(&(b.len() as u32).to_le_bytes());
        f.extend_from_slice(&b);
        f.extend_from_slice(&(p.len() as u32).to_le_bytes());
        f.extend_from_slice(&p);
        Ok(())
    };
    put(ES::Success)?;
    for k in kinds {
        put(ES::Failure(ExecutionFailure::new(k.clone(), None)))?;
        put(ES::Failure(ExecutionFailure::new(k, Some(3))))?;
    }
    std::fs::create_dir_all(out)?;
    std::fs::write(out.join("exec-status.bin"), f)?;
    Ok(())
}

/// `pkg <out_dir> <file.chk>...`: MovePackageService truth. For every package object in the
/// checkpoints' output objects (deduplicated by id and version across the whole run), a
/// record file `<out_dir>/<id>-<version>.pkg.zst` (zstd of):
/// `[u32 len][bcs(Object)]` then repeated `[kind u8][u16 mlen][module][u16 nlen][name][status u8][u32 len][bytes]`
/// where kind 1 = GetPackage (module and name empty), 2 = GetDatatype, 3 = GetFunction, and
/// status 0 carries the prost response, status 1 the INTERNAL message. Besides every datatype and
/// function, GetDatatype/GetFunction are asked for a missing module and a missing name.
/// A second record per file kind 4 = object that is not a package (GetPackage -> INVALID_ARGUMENT)
/// is written to `<out_dir>/notpkg-<id>.rec` (one per checkpoint file at most).
fn gen_pkg(out: &Path, files: &[PathBuf]) -> Result<()> {
    use prost::Message;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    std::fs::create_dir_all(out)?;
    let seen: Mutex<BTreeMap<(Vec<u8>, u64), ()>> = Mutex::new(BTreeMap::new());
    let stats = Mutex::new((0u64, 0u64, 0u64)); // packages, resolver errors, notpkg
    files.par_iter().try_for_each(|path| -> Result<()> {
        let raw = std::fs::read(path)?;
        let data: CheckpointData = bcs::from_bytes(&raw[1..]).context("decode")?;
        let mut notpkg_done = false;
        for t in &data.transactions {
            for o in t.input_objects.iter().chain(t.output_objects.iter()) {
                let Some(pkg) = o.data.try_as_package() else {
                    if !notpkg_done && o.data.try_as_move().is_some() && stats.lock().unwrap().2 < 20 {
                        notpkg_done = true;
                        let id = o.id();
                        let mut rec = Vec::new();
                        let ob = bcs::to_bytes(o)?;
                        rec.extend((ob.len() as u32).to_le_bytes());
                        rec.extend(&ob);
                        std::fs::write(out.join(format!("notpkg-{}.rec", hex::encode(id.as_ref()))), rec)?;
                        stats.lock().unwrap().2 += 1;
                    }
                    continue;
                };
                let key = (pkg.id().to_vec(), pkg.version().value());
                if seen.lock().unwrap().insert(key, ()).is_some() {
                    continue;
                }
                let ob = bcs::to_bytes(o)?;
                let mut rec = Vec::new();
                rec.extend((ob.len() as u32).to_le_bytes());
                rec.extend(&ob);
                let mut push = |kind: u8, m: &str, n: &str, r: std::result::Result<Vec<u8>, String>| {
                    rec.push(kind);
                    rec.extend((m.len() as u16).to_le_bytes());
                    rec.extend(m.as_bytes());
                    rec.extend((n.len() as u16).to_le_bytes());
                    rec.extend(n.as_bytes());
                    let (st, b) = match r {
                        Ok(b) => (0u8, b),
                        Err(e) => (1u8, e.into_bytes()),
                    };
                    rec.push(st);
                    rec.extend((b.len() as u32).to_le_bytes());
                    rec.extend(&b);
                };
                let whole = pkgconv::get_package_response(pkg);
                if whole.is_err() {
                    stats.lock().unwrap().1 += 1;
                }
                push(1, "", "", whole.as_ref().map(|r| r.encode_to_vec()).map_err(|e| e.clone()));
                if let Ok(resp) = &whole {
                    let p = resp.package.as_ref().unwrap();
                    for m in &p.modules {
                        let mn = m.name.clone().unwrap();
                        for d in &m.datatypes {
                            let n = d.name.clone().unwrap();
                            push(2, &mn, &n, pkgconv::get_datatype_response(pkg, &mn, &n).map(|r| r.encode_to_vec()));
                        }
                        for f in &m.functions {
                            let n = f.name.clone().unwrap();
                            push(3, &mn, &n, pkgconv::get_function_response(pkg, &mn, &n).map(|r| r.encode_to_vec()));
                        }
                        push(2, &mn, "NoSuchType", pkgconv::get_datatype_response(pkg, &mn, "NoSuchType").map(|r| r.encode_to_vec()));
                        push(3, &mn, "no_such_fn", pkgconv::get_function_response(pkg, &mn, "no_such_fn").map(|r| r.encode_to_vec()));
                    }
                    push(2, "no_such_module", "X", pkgconv::get_datatype_response(pkg, "no_such_module", "X").map(|r| r.encode_to_vec()));
                    push(3, "no_such_module", "f", pkgconv::get_function_response(pkg, "no_such_module", "f").map(|r| r.encode_to_vec()));
                }
                let z = zstd::encode_all(&rec[..], 3)?;
                std::fs::write(out.join(format!("{}-{}.pkg.zst", hex::encode(pkg.id().to_vec()), pkg.version().value())), z)?;
                stats.lock().unwrap().0 += 1;
            }
        }
        Ok(())
    })?;
    let s = stats.lock().unwrap();
    eprintln!("packages {} (resolver errors {}), notpkg {}", s.0, s.1, s.2);
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("exec-status") if args.len() == 2 => gen_exec_status(&PathBuf::from(&args[1])),
        Some("pkg") if args.len() >= 3 => {
            // `@list` reads one chk path per line (the corpus has too many for argv)
            let files: Vec<PathBuf> = if let Some(l) = args[2].strip_prefix('@') {
                std::fs::read_to_string(l)?.lines().filter(|l| !l.is_empty()).map(PathBuf::from).collect()
            } else {
                args[2..].iter().map(PathBuf::from).collect()
            };
            gen_pkg(&PathBuf::from(&args[1]), &files)
        }
        Some("status") if args.len() == 2 => gen_status(&PathBuf::from(&args[1])),
        Some("bench") if args.get(1).map(String::as_str) == Some("render") => bench_render(&args[1..]),
        Some("bench") if args.get(1).map(String::as_str) == Some("pkg") => bench_pkg(&args[2..]),
        Some("gen") if args.len() >= 3 => {
            let out = PathBuf::from(&args[1]);
            std::fs::create_dir_all(&out)?;
            let trees = MASKS.iter().map(|m| tree(m)).collect::<Result<Vec<_>>>()?;
            let mut f = std::fs::File::create(out.join("masks.txt"))?;
            for m in MASKS {
                writeln!(f, "{m}")?;
            }
            let txdir = PathBuf::from(format!("{}-tx", out.display()));
            std::fs::create_dir_all(&txdir)?;
            let mut f = std::fs::File::create(txdir.join("masks.txt"))?;
            for m in TX_MASKS {
                writeln!(f, "{m}")?;
            }
            let mut f = std::fs::File::create(txdir.join("masks-obj.txt"))?;
            for m in OBJ_MASKS {
                writeln!(f, "{m}")?;
            }
            let files: Vec<PathBuf> = args[2..].iter().map(PathBuf::from).collect();
            files.par_iter().try_for_each(|p| gen_one(&out, p, &trees))?;
            eprintln!("wrote {} checkpoints", files.len());
            Ok(())
        }
        _ => bail!("usage: gen <out_dir> <file.chk>..."),
    }
}
