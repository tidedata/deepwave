//! Protocol upgrade truth (docs/PARITY.md G4, G3): `upgrade OUT_DIR MAINNET_OBJECTS.jsonl [EXTRA.jsonl]`.
//! Built against whichever tree tools/sui names (1.83.1: MAX 141, 1.84: MAX 142); every output
//! names the binary's MAX so both runs can live side by side. Sources:
//!   sui-core/src/authority.rs   get_available_system_packages, get_system_package_bytes,
//!                               is_protocol_version_supported_v2,
//!                               choose_protocol_version_and_system_packages_v2,
//!                               create_and_execute_advance_epoch_tx (the kinds and ChangeEpoch)
//!   sui-framework/src/lib.rs    compare_system_package, BuiltInFramework
//!   sui-types/src/bridge.rs     is_bridge_committee_initiated
//! The AuthorityState methods are private to sui-core (whose build is out of reach for a truth
//! tool), so their bodies are copied here line for line (msim branches dropped) over Mysten's own
//! types, orderings and helpers; `compare_system_package`, `Object::new_system_package`,
//! `BuiltInFramework`, `is_bridge_committee_initiated` and the transaction constructors are called.
//!
//! MAINNET_OBJECTS.jsonl: `{"id","version","bcs"}` of the full Object BCS (sui.rpc.v2 GetObject)
//! of 0x1, 0x2, 0x3, 0xdee9, 0xb, the bridge 0x9 and its inner `Field<u64, BridgeInnerV1>`.
//! EXTRA.jsonl (optional): objects of another release's upgrade (`upgraded-objects.jsonl` of the
//! other run), for the case "a binary older than the chain's framework".
use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
use itertools::Itertools;
use move_binary_format::{CompiledModule, binary_config::BinaryConfig};
use serde_json::{Value, json};
use sui_framework::{BuiltInFramework, SystemPackage, compare_system_package};
use sui_protocol_config::{Chain, PerObjectCongestionControlMode, ProtocolConfig, ProtocolVersion};
use sui_types::{
    base_types::{AuthorityName, ObjectID, ObjectRef, SequenceNumber, VersionNumber},
    bridge::{BridgeInnerV1, is_bridge_committee_initiated},
    crypto::AuthorityPublicKeyBytes,
    digests::{Digest, ObjectDigest, TransactionDigest},
    dynamic_field::Field,
    messages_consensus::AuthorityCapabilitiesV2,
    object::{OBJECT_START_VERSION, Object},
    storage::ObjectStore,
    supported_protocol_versions::SupportedProtocolVersionsWithHashes,
    transaction::{EndOfEpochTransactionKind, StoredExecutionTimeObservations, VerifiedTransaction},
};

#[derive(Default, Clone)]
struct Mem(BTreeMap<(ObjectID, SequenceNumber), Object>);

impl Mem {
    fn put(&mut self, o: Object) {
        self.0.insert((o.id(), o.version()), o);
    }
}

impl ObjectStore for Mem {
    fn get_object(&self, id: &ObjectID) -> Option<Object> {
        self.0
            .range((*id, SequenceNumber::MIN)..=(*id, SequenceNumber::MAX))
            .next_back()
            .map(|(_, o)| o.clone())
    }
    fn get_object_by_key(&self, id: &ObjectID, v: VersionNumber) -> Option<Object> {
        self.0.get(&(*id, v)).cloned()
    }
}

fn load(path: &Path) -> Result<Vec<Object>> {
    let mut out = Vec::new();
    for line in fs::read_to_string(path).with_context(|| format!("{}", path.display()))?.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)?;
        let bytes = hex::decode(v["bcs"].as_str().context("bcs")?)?;
        out.push(bcs::from_bytes::<Object>(&bytes)?);
    }
    Ok(out)
}

/// `AuthorityState::get_available_system_packages` (non-msim).
fn available_system_packages(store: &Mem, binary_config: &BinaryConfig) -> Vec<ObjectRef> {
    let mut results = vec![];
    for system_package in BuiltInFramework::iter_system_packages() {
        let modules = system_package.modules().to_vec();
        let Some(obj_ref) = futures::executor::block_on(compare_system_package(
            store,
            &system_package.id,
            &modules,
            system_package.dependencies.to_vec(),
            binary_config,
        )) else {
            return vec![];
        };
        results.push(obj_ref);
    }
    results
}

/// `AuthorityState::get_system_package_bytes` (non-msim).
fn system_package_bytes(
    store: &Mem,
    system_packages: Vec<ObjectRef>,
    binary_config: &BinaryConfig,
) -> Option<Vec<(SequenceNumber, Vec<Vec<u8>>, Vec<ObjectID>)>> {
    let mut res = Vec::with_capacity(system_packages.len());
    for system_package_ref in system_packages {
        if let Some(object) = store.get_object_by_key(&system_package_ref.0, system_package_ref.1)
            && object.compute_object_reference() == system_package_ref
        {
            continue;
        }
        let prev_transaction = if system_package_ref.1 == OBJECT_START_VERSION {
            TransactionDigest::genesis_marker()
        } else {
            let prev_version = system_package_ref.1.one_before().expect("version > start");
            let prev_object = store.get_object_by_key(&system_package_ref.0, prev_version)?;
            prev_object.previous_transaction
        };
        let SystemPackage { id: _, bytes, dependencies } =
            BuiltInFramework::get_package_by_id(&system_package_ref.0).clone();
        let modules: Vec<_> = bytes
            .iter()
            .map(|m| CompiledModule::deserialize_with_config(m, binary_config).unwrap())
            .collect();
        let new_object =
            Object::new_system_package(&modules, system_package_ref.1, dependencies.clone(), prev_transaction);
        if new_object.compute_object_reference() != system_package_ref {
            return None;
        }
        res.push((system_package_ref.1, bytes, dependencies));
    }
    Some(res)
}

/// `AuthorityState::is_protocol_version_supported_v2`; the StakeAggregator<(), true> sum is
/// `committee.weight` of each distinct authority (stake_aggregator.rs insert_generic).
fn is_protocol_version_supported_v2(
    current_protocol_version: ProtocolVersion,
    proposed_protocol_version: ProtocolVersion,
    advance_to_highest_supported_protocol_version: bool,
    committee: &BTreeMap<AuthorityName, u64>,
    capabilities: Vec<AuthorityCapabilitiesV2>,
    mut buffer_stake_bps: u64,
) -> Option<(ProtocolVersion, Vec<ObjectRef>)> {
    if proposed_protocol_version > current_protocol_version + 1 && !advance_to_highest_supported_protocol_version {
        return None;
    }
    if buffer_stake_bps > 10000 {
        buffer_stake_bps = 10000;
    }
    let mut desired_upgrades: Vec<_> = capabilities
        .into_iter()
        .filter_map(|mut cap| {
            if cap.available_system_packages.is_empty() {
                return None;
            }
            cap.available_system_packages.sort();
            cap.supported_protocol_versions
                .get_version_digest(proposed_protocol_version)
                .map(|digest| (digest, cap.available_system_packages, cap.authority))
        })
        .collect();
    desired_upgrades.sort();
    desired_upgrades
        .into_iter()
        .chunk_by(|(digest, packages, _authority)| (*digest, packages.clone()))
        .into_iter()
        .find_map(|((_digest, packages), group)| {
            assert!(!packages.is_empty());
            let mut seen = std::collections::HashSet::new();
            let mut total_votes = 0u64;
            for (_, _, authority) in group {
                if seen.insert(authority) {
                    total_votes += committee.get(&authority).copied().unwrap_or(0);
                }
            }
            // Committee: TOTAL_VOTING_POWER 10_000, QUORUM_THRESHOLD 6_667
            let quorum_threshold = 6_667u64;
            let f = 10_000 - quorum_threshold;
            let buffer_stake = (f * buffer_stake_bps).div_ceil(10000);
            let effective_threshold = quorum_threshold + buffer_stake;
            (total_votes >= effective_threshold).then_some((proposed_protocol_version, packages))
        })
}

/// `AuthorityState::choose_protocol_version_and_system_packages_v2`.
fn choose(
    current: ProtocolVersion,
    advance: bool,
    committee: &BTreeMap<AuthorityName, u64>,
    capabilities: Vec<AuthorityCapabilitiesV2>,
    buffer_stake_bps: u64,
) -> (ProtocolVersion, Vec<ObjectRef>) {
    let mut next_protocol_version = current;
    let mut system_packages = vec![];
    while let Some((version, packages)) = is_protocol_version_supported_v2(
        current,
        next_protocol_version + 1,
        advance,
        committee,
        capabilities.clone(),
        buffer_stake_bps,
    ) {
        next_protocol_version = version;
        system_packages = packages;
    }
    (next_protocol_version, system_packages)
}

fn name(b: u8) -> AuthorityName {
    let mut n = [0u8; 96];
    n[0] = b;
    AuthorityPublicKeyBytes::new(n)
}

fn digest(b: u8) -> Digest {
    Digest::new([b; 32])
}

fn pkgs(tag: u8) -> Vec<ObjectRef> {
    // deliberately unsorted: Rust sorts each validator's list before grouping
    vec![
        (ObjectID::from_single_byte(3), SequenceNumber::from_u64(4), ObjectDigest::new([tag; 32])),
        (ObjectID::from_single_byte(1), SequenceNumber::from_u64(2), ObjectDigest::new([tag; 32])),
        (ObjectID::from_single_byte(2), SequenceNumber::from_u64(3), ObjectDigest::new([tag.wrapping_add(1); 32])),
    ]
}

fn cap(who: u8, versions: &[(u64, u8)], packages: Vec<ObjectRef>) -> AuthorityCapabilitiesV2 {
    AuthorityCapabilitiesV2 {
        authority: name(who),
        generation: 1000 + who as u64,
        supported_protocol_versions: SupportedProtocolVersionsWithHashes {
            versions: versions.iter().map(|(v, d)| (ProtocolVersion::new(*v), digest(*d))).collect(),
        },
        available_system_packages: packages,
    }
}

fn refs_json(refs: &[ObjectRef]) -> Value {
    Value::Array(
        refs.iter()
            .map(|r| json!([hex::encode(r.0.into_bytes()), r.1.value(), hex::encode(r.2.into_inner())]))
            .collect(),
    )
}

fn choose_cases() -> Vec<Value> {
    let even: Vec<(u8, u64)> = vec![(1, 2500), (2, 2500), (3, 2500), (4, 2500)];
    let uneven: Vec<(u8, u64)> = vec![(1, 4000), (2, 3000), (3, 2000), (4, 1000)];
    let up = |d: u8| vec![(141u64, 9u8), (142u64, d)];
    let all = |d: u8, p: u8| (1..=4).map(|i| cap(i, &up(d), pkgs(p))).collect::<Vec<_>>();
    let wide = |hi: u64| (141..=hi).map(|v| (v, v as u8)).collect::<Vec<_>>();
    let mut cases: Vec<(&str, Vec<(u8, u64)>, bool, u64, Vec<AuthorityCapabilitiesV2>)> = vec![
        ("all-four", even.clone(), false, 5000, all(7, 1)),
        ("three-of-four", even.clone(), false, 5000, all(7, 1).into_iter().take(3).collect()),
        ("three-of-four-no-buffer", even.clone(), false, 0, all(7, 1).into_iter().take(3).collect()),
        ("buffer-clamped", even.clone(), false, 20000, all(7, 1)),
        ("buffer-clamped-three", even.clone(), false, 20000, all(7, 1).into_iter().take(3).collect()),
        (
            "one-without-packages",
            even.clone(),
            false,
            5000,
            vec![cap(1, &up(7), pkgs(1)), cap(2, &up(7), pkgs(1)), cap(3, &up(7), pkgs(1)), cap(4, &up(7), vec![])],
        ),
        (
            "split-digest",
            even.clone(),
            false,
            5000,
            vec![cap(1, &up(7), pkgs(1)), cap(2, &up(7), pkgs(1)), cap(3, &up(7), pkgs(1)), cap(4, &up(8), pkgs(1))],
        ),
        (
            "split-packages",
            even.clone(),
            false,
            5000,
            vec![cap(1, &up(7), pkgs(1)), cap(2, &up(7), pkgs(1)), cap(3, &up(7), pkgs(2)), cap(4, &up(7), pkgs(1))],
        ),
        (
            "current-only",
            even.clone(),
            false,
            5000,
            (1..=4).map(|i| cap(i, &[(141, 9)], pkgs(1))).collect(),
        ),
        ("uneven-9000", uneven.clone(), false, 5000, all(7, 1).into_iter().take(3).collect()),
        (
            "uneven-8000",
            uneven.clone(),
            false,
            5000,
            vec![cap(1, &up(7), pkgs(1)), cap(2, &up(7), pkgs(1)), cap(4, &up(7), pkgs(1))],
        ),
        (
            "non-member",
            even.clone(),
            false,
            5000,
            vec![cap(1, &up(7), pkgs(1)), cap(2, &up(7), pkgs(1)), cap(3, &up(7), pkgs(1)), cap(9, &up(7), pkgs(1))],
        ),
        ("skip-no-advance", even.clone(), false, 5000, (1..=4).map(|i| cap(i, &wide(144), pkgs(1))).collect()),
        ("skip-advance", even.clone(), true, 5000, (1..=4).map(|i| cap(i, &wide(144), pkgs(1))).collect()),
        (
            "gap",
            even.clone(),
            true,
            5000,
            (1..=4).map(|i| cap(i, &[(141, 9), (143, 7)], pkgs(1))).collect(),
        ),
        (
            "advance-partial",
            even.clone(),
            true,
            5000,
            vec![
                cap(1, &wide(144), pkgs(1)),
                cap(2, &wide(144), pkgs(1)),
                cap(3, &wide(143), pkgs(1)),
                cap(4, &wide(143), pkgs(1)),
            ],
        ),
        ("none", even.clone(), false, 5000, vec![]),
    ];
    let mut out = Vec::new();
    for (case, members, advance, bps, caps) in cases.drain(..) {
        let committee: BTreeMap<AuthorityName, u64> = members.iter().map(|(b, s)| (name(*b), *s)).collect();
        let (v, refs) = choose(ProtocolVersion::new(141), advance, &committee, caps.clone(), bps);
        out.push(json!({
            "name": case,
            "current": 141,
            "advance_to_highest": advance,
            "buffer_bps": bps,
            "committee": members.iter().map(|(b, s)| json!([hex::encode(name(*b).0), s])).collect::<Vec<_>>(),
            "caps": caps.iter().map(|c| hex::encode(bcs::to_bytes(c).unwrap())).collect::<Vec<_>>(),
            "want_version": v.as_u64(),
            "want_packages": refs_json(&refs),
        }));
    }
    out
}

fn bridge_cases(objs: &[Object]) -> Result<Vec<Value>> {
    let bridge_id = ObjectID::from_single_byte(9);
    let mut out = Vec::new();
    let mut full = Mem::default();
    let mut wrapper = None;
    let mut inner = None;
    for o in objs {
        if o.id() == bridge_id {
            wrapper = Some(o.clone());
            full.put(o.clone());
        } else if o.data.try_as_move().is_some_and(|m| m.type_().is_dynamic_field()) {
            inner = Some(o.clone());
            full.put(o.clone());
        }
    }
    let wrapper = wrapper.context("no bridge object")?;
    let inner = inner.context("no bridge inner field")?;
    let enc = |o: &Object| hex::encode(bcs::to_bytes(o).unwrap());
    out.push(json!({"name": "mainnet", "objects": [enc(&wrapper), enc(&inner)],
        "want": is_bridge_committee_initiated(&full)?}));
    // the same bridge with no committee members (a localnet's bridge before BridgeCommitteeInit)
    let mut field: Field<u64, BridgeInnerV1> = bcs::from_bytes(inner.data.try_as_move().unwrap().contents())?;
    field.value.committee.members.contents.clear();
    let mut empty_inner = inner.clone();
    empty_inner.data.try_as_move_mut().unwrap().set_contents_unsafe(bcs::to_bytes(&field)?);
    let mut empty = Mem::default();
    empty.put(wrapper.clone());
    empty.put(empty_inner.clone());
    out.push(json!({"name": "no-members", "objects": [enc(&wrapper), enc(&empty_inner)],
        "want": is_bridge_committee_initiated(&empty)?}));
    let mut only_wrapper = Mem::default();
    only_wrapper.put(wrapper.clone());
    out.push(json!({"name": "no-inner", "objects": [enc(&wrapper)],
        "want": is_bridge_committee_initiated(&only_wrapper)?}));
    out.push(json!({"name": "no-bridge", "objects": [], "want": is_bridge_committee_initiated(&Mem::default())?}));
    Ok(out)
}

pub fn dump(out: &Path, mainnet: &Path) -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let max = ProtocolVersion::MAX.as_u64();
    let objs = load(mainnet)?;
    let mut store = Mem::default();
    for o in &objs {
        if o.is_package() {
            store.put(o.clone());
        }
    }
    let bc141 = ProtocolConfig::get_for_version(ProtocolVersion::new(141), Chain::Mainnet).binary_config(None);

    // (b) available system packages. A store is listed as package object keys
    // [id, version, previous_transaction, object digest]: deepwave rebuilds each object from its
    // framework snapshot (the on-chain modules are a snapshot's bytes) and checks the digest.
    let keys = |os: &[Object]| -> Value {
        Value::Array(os.iter().filter(|o| o.is_package()).map(|o| {
            let r = o.compute_object_reference();
            json!([hex::encode(r.0.into_bytes()), r.1.value(), hex::encode(o.previous_transaction.inner()), hex::encode(r.2.into_inner())])
        }).collect())
    };
    let mut avail = Vec::new();
    let mainnet_refs = available_system_packages(&store, &bc141);
    avail.push(json!({"name": "mainnet", "store": keys(&objs), "want": refs_json(&mainnet_refs)}));
    avail.push(json!({"name": "empty", "store": [], "want": refs_json(&available_system_packages(&Mem::default(), &bc141))}));
    if let Some(extra) = args.get(4) {
        let mut st = store.clone();
        let extra_objs = load(Path::new(extra))?;
        for o in &extra_objs {
            st.put(o.clone());
        }
        let mut all = objs.clone();
        all.extend(extra_objs.iter().cloned());
        avail.push(json!({"name": "chain-ahead", "store": keys(&all), "want": refs_json(&available_system_packages(&st, &bc141))}));
    }
    write(out, &format!("available-v{max}.jsonl"), avail)?;

    // (d) the end-of-epoch transaction of a mainnet upgrade to this binary's MAX, every capability
    // naming this binary's packages: kinds of create_and_execute_advance_epoch_tx for a mainnet
    // epoch where every system object exists (authenticator, randomness, bridge with a committee,
    // deny list, accumulator root with an object count, registries).
    let mut sorted = mainnet_refs.clone();
    sorted.sort();
    let pkg_bytes = system_package_bytes(&store, sorted.clone(), &bc141).context("package bytes")?;
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(141), Chain::Mainnet);
    let (epoch, ts, auth_isv, acc_count) = (1313u64, 1_763_337_600_000u64, 31_726_386u64, 5u64);
    let (storage, computation, rebate, nonrefundable) = (1_000_000_000u64, 2_000_000u64, 900_000_000u64, 9_000_000u64);
    let mut kinds = Vec::new();
    if cfg.enable_jwk_consensus_updates() {
        let min_epoch = (epoch + 1).saturating_sub(cfg.max_age_of_jwk_in_epochs());
        kinds.push(EndOfEpochTransactionKind::new_authenticator_state_expire(min_epoch, SequenceNumber::from_u64(auth_isv)));
    }
    if let PerObjectCongestionControlMode::ExecutionTimeEstimate(_) = cfg.per_object_congestion_control_mode() {
        kinds.push(EndOfEpochTransactionKind::new_store_execution_time_observations(StoredExecutionTimeObservations::V1(vec![])));
    }
    if cfg.enable_accumulators() {
        kinds.push(EndOfEpochTransactionKind::new_write_accumulator_storage_cost(
            acc_count.saturating_mul(cfg.accumulator_object_storage_cost()),
        ));
    }
    let next = if max > 141 { ProtocolVersion::new(max) } else { ProtocolVersion::new(141) };
    let with_pkgs = if max > 141 { pkg_bytes } else { vec![] };
    kinds.push(EndOfEpochTransactionKind::new_change_epoch(
        epoch + 1,
        next,
        storage,
        computation,
        rebate,
        nonrefundable,
        ts,
        with_pkgs.clone(),
    ));
    let tx = VerifiedTransaction::new_end_of_epoch_transaction(kinds);
    let eoe = vec![json!({
        "name": format!("mainnet-141-to-{}", next.as_u64()),
        "epoch": epoch, "epoch_start_timestamp_ms": ts, "authenticator_isv": auth_isv, "accumulator_object_count": acc_count,
        "gas": [computation, storage, rebate, nonrefundable],
        "next_version": next.as_u64(),
        "packages": refs_json(&sorted),
        "package_versions": with_pkgs.iter().map(|p| p.0.value()).collect::<Vec<_>>(),
        "sender_signed_data": hex::encode(bcs::to_bytes(tx.data())?),
        "digest": hex::encode(tx.digest().inner()),
    })];
    write(out, &format!("upgrade-tx-v{max}.jsonl"), eoe)?;

    // the packages after that upgrade (input to the other release's "chain-ahead" case)
    let mut upgraded = Vec::new();
    for (version, bytes, deps) in &with_pkgs {
        let modules: Vec<_> = bytes.iter().map(|m| CompiledModule::deserialize_with_config(m, &bc141).unwrap()).collect();
        let o = Object::new_system_package(&modules, *version, deps.clone(), TransactionDigest::new([0x42; 32]));
        upgraded.push(json!({"id": o.id().to_hex_literal(), "version": version.value().to_string(), "bcs": hex::encode(bcs::to_bytes(&o)?)}));
    }
    write(out, &format!("upgraded-objects-v{max}.jsonl"), upgraded)?;

    // (c) the vote
    write(out, "choose.jsonl", choose_cases())?;
    // G3
    write(out, "bridge-committee.jsonl", bridge_cases(&objs)?)?;
    println!("upgrade vectors (MAX {max}) in {}", out.display());
    Ok(())
}

fn write(out: &Path, name: &str, lines: Vec<Value>) -> Result<()> {
    let mut text = String::new();
    for l in lines {
        text.push_str(&serde_json::to_string(&l)?);
        text.push('\n');
    }
    fs::write(out.join(name), text)?;
    Ok(())
}
