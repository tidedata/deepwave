// deepwave truth: shared-object version assignment vectors from Mysten's sui-core at mainnet-v1.83.1.
//
// A test module next to crates/sui-core/src/authority/shared_object_version_manager.rs (run.sh drops
// it into a scratch worktree of the sui checkout). Each seeded scenario builds an authority with
// shared objects at chosen versions (TestAuthorityBuilder, as the file's own tests do), a schedule of
// user transactions (shared inputs of every mutability the user can write, owned inputs, receiving
// objects, gas), randomness state updates and consensus commit prologues, cancels some transactions
// (congestion on a subset of their objects, or DKG failure), and runs
// `SharedObjVerManager::assign_versions_from_consensus`. Output (ZUI_VECTORS_OUT):
//
//   vscenario <name> <epoch>
//   vimplicit <id> <isv>                                 implicitly read system objects, in order
//   vobject <id> <version> <start_version|->             the object cache's answer for every id used
//   vtx <key> <TransactionData BCS|-> <shared|-> <non-shared versions csv|-> <cancel>
//        shared: <id>:<isv>:<i|m|n>,...  (Immutable, Mutable, NonExclusiveWrite) as Rust extracted them
//        cancel: none | congestion:<id>,... | dkg
//   vassign <key> <id>:<isv>:<version>,...|- <system id>:<isv>:<version>,...|-
//   vnext <id> <isv> <version>                           shared_input_next_versions, sorted
//   vend <name>
// key: d:<tx digest> | rand:<epoch>:<round> | ccp:<epoch>:<round>:<sub dag index>
use super::*;
use crate::authority::test_authority_builder::TestAuthorityBuilder;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use std::fmt::Write as _;
use std::io::Write as _;
use sui_test_transaction_builder::TestTransactionBuilder;
use sui_types::base_types::{ObjectRef, SuiAddress};
use sui_types::digests::ObjectDigest;
use sui_types::executable_transaction::{CertificateProof, ExecutableTransaction};
use sui_types::object::{Object, Owner};
use sui_types::transaction::{ObjectArg, SenderSignedData};

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        write!(s, "{x:02x}").unwrap();
    }
    s
}

fn id_hex(id: &ObjectID) -> String {
    hex(id.as_ref())
}

fn key_str(k: &TransactionKey) -> String {
    match k {
        TransactionKey::Digest(d) => format!("d:{}", hex(d.inner())),
        TransactionKey::RandomnessRound(e, r) => format!("rand:{e}:{}", r.0),
        TransactionKey::ConsensusCommitPrologue(e, r, i) => format!("ccp:{e}:{r}:{i}"),
        other => panic!("unexpected key {other:?}"),
    }
}

fn rid(rng: &mut StdRng) -> ObjectID {
    let mut b = [0u8; 32];
    rng.fill(&mut b);
    ObjectID::new(b)
}

fn rref(rng: &mut StdRng, version: u64) -> ObjectRef {
    let mut d = [0u8; 32];
    rng.fill(&mut d);
    (rid(rng), SequenceNumber::from_u64(version), ObjectDigest::new(d))
}

struct Pool {
    // (id, isv the transactions name, allowed mutabilities)
    shared: Vec<(ObjectID, SequenceNumber, &'static [SharedObjectMutability])>,
}

const ANY: &[SharedObjectMutability] = &[SharedObjectMutability::Mutable, SharedObjectMutability::Immutable];
const RO: &[SharedObjectMutability] = &[SharedObjectMutability::Immutable];

fn user_tx(
    rng: &mut StdRng,
    shared: &[(ObjectID, SequenceNumber, SharedObjectMutability)],
) -> VerifiedExecutableTransaction {
    let v = rng.gen_range(1..60);
    let gas = rref(rng, v);
    let mut b = TestTransactionBuilder::new(SuiAddress::ZERO, gas, 1000);
    let data = {
        let pb = b.ptb_builder_mut();
        for (id, isv, m) in shared {
            pb.obj(ObjectArg::SharedObject { id: *id, initial_shared_version: *isv, mutability: m.clone() })
                .unwrap();
        }
        for _ in 0..rng.gen_range(0..3) {
            let v = rng.gen_range(1..80);
            let r = rref(rng, v);
            pb.obj(ObjectArg::ImmOrOwnedObject(r)).unwrap();
        }
        if rng.gen_bool(0.25) {
            let v = rng.gen_range(1..80);
            let r = rref(rng, v);
            pb.obj(ObjectArg::Receiving(r)).unwrap();
        }
        b.build()
    };
    VerifiedExecutableTransaction::new_unchecked(ExecutableTransaction::new_from_data_and_sig(
        SenderSignedData::new(data, vec![]),
        CertificateProof::new_system(0),
    ))
}

async fn scenario(out: &mut String, name: &str, seed: u64, n_objects: usize, n_txs: usize) {
    let mut rng = StdRng::seed_from_u64(seed);
    // Shared objects: current version at or above the start version; one in four is a
    // ConsensusAddressOwner object (start_version Some as well).
    let mut objects = Vec::new();
    let mut pool = Pool { shared: Vec::new() };
    for k in 0..n_objects {
        let id = rid(&mut rng);
        let isv = SequenceNumber::from_u64(rng.gen_range(1..20));
        let cur = SequenceNumber::from_u64(isv.value() + rng.gen_range(0..30));
        let owner = if k % 4 == 3 {
            Owner::ConsensusAddressOwner { start_version: isv, owner: SuiAddress::ZERO }
        } else {
            Owner::Shared { initial_shared_version: isv }
        };
        objects.push(Object::with_id_owner_version_for_testing(id, cur, owner));
        pool.shared.push((id, isv, ANY));
        // A transaction that names a later start version than the object's (re-shared object):
        // initialised at the named version.
        if k % 3 == 1 {
            pool.shared.push((id, SequenceNumber::from_u64(isv.value() + rng.gen_range(1..10)), ANY));
        }
    }
    // Objects that do not exist (deleted, or not yet visible): initialised at the named version.
    for _ in 0..2 {
        pool.shared.push((rid(&mut rng), SequenceNumber::from_u64(rng.gen_range(1..40)), ANY));
    }
    let authority = TestAuthorityBuilder::new().with_starting_objects(&objects).build().await;
    let epoch_store = authority.epoch_store_for_testing();
    let cache = authority.get_object_cache_reader();
    let epoch = epoch_store.epoch();
    let rand_isv = epoch_store.epoch_start_config().randomness_obj_initial_shared_version().unwrap();
    pool.shared.push((SUI_RANDOMNESS_STATE_OBJECT_ID, rand_isv, RO));
    pool.shared.push((SUI_CLOCK_OBJECT_ID, SUI_CLOCK_OBJECT_SHARED_VERSION, RO));

    let mut schedule: Vec<Schedulable> = Vec::new();
    let mut round = 0u64;
    let mut rand_round = 0u64;
    for t in 0..n_txs {
        if t % 7 == 0 {
            round += 1;
            schedule.push(Schedulable::ConsensusCommitPrologue(epoch, round, 0));
        }
        if t % 11 == 5 {
            rand_round += 1;
            schedule.push(Schedulable::RandomnessStateUpdate(epoch, RandomnessRound::new(rand_round)));
        }
        let k = rng.gen_range(0..4usize).min(pool.shared.len());
        let mut chosen: Vec<(ObjectID, SequenceNumber, SharedObjectMutability)> = Vec::new();
        for _ in 0..k {
            let (id, isv, ms) = pool.shared[rng.gen_range(0..pool.shared.len())];
            if chosen.iter().any(|c| c.0 == id) {
                continue;
            }
            chosen.push((id, isv, ms[rng.gen_range(0..ms.len())].clone()));
        }
        schedule.push(Schedulable::Transaction(user_tx(&mut rng, &chosen)));
    }
    // Cancellations of transactions that have shared inputs.
    let mut cancelled: BTreeMap<TransactionDigest, CancelConsensusCertificateReason> = BTreeMap::new();
    for s in &schedule {
        let Schedulable::Transaction(tx) = s else { continue };
        let shared: Vec<_> = tx.shared_input_objects().collect();
        if shared.is_empty() || !rng.gen_bool(0.2) {
            continue;
        }
        let reason = if shared.iter().any(|o| o.id == SUI_RANDOMNESS_STATE_OBJECT_ID) && rng.gen_bool(0.5) {
            CancelConsensusCertificateReason::DkgFailed
        } else {
            let ids: Vec<ObjectID> = shared.iter().filter(|_| rng.gen_bool(0.6)).map(|o| o.id).collect();
            CancelConsensusCertificateReason::CongestionOnObjects(ids)
        };
        cancelled.insert(*tx.digest(), reason);
    }

    writeln!(out, "vscenario {name} {epoch}").unwrap();
    for (id, isv) in implicitly_read_system_objects(&epoch_store) {
        writeln!(out, "vimplicit {} {}", id_hex(&id), isv.value()).unwrap();
    }
    // What the cache reader says about every id version assignment may read.
    let mut ids: Vec<ObjectID> = pool.shared.iter().map(|s| s.0).collect();
    ids.extend(implicitly_read_system_objects(&epoch_store).into_iter().map(|(id, _)| id));
    ids.sort();
    ids.dedup();
    for id in &ids {
        match cache.get_object(id) {
            Some(o) => {
                let sv = o.owner.start_version().map(|v| v.value().to_string()).unwrap_or("-".into());
                writeln!(out, "vobject {} {} {sv}", id_hex(id), o.version().value()).unwrap();
            }
            None => {}
        }
    }
    for s in &schedule {
        let key = key_str(&s.key());
        let data = match s {
            Schedulable::Transaction(tx) => hex(&bcs::to_bytes(tx.data().transaction_data()).unwrap()),
            _ => "-".into(),
        };
        let shared: Vec<String> = s
            .shared_input_objects(&epoch_store)
            .map(|o| {
                let m = match o.mutability {
                    SharedObjectMutability::Immutable => "i",
                    SharedObjectMutability::Mutable => "m",
                    SharedObjectMutability::NonExclusiveWrite => "n",
                };
                format!("{}:{}:{m}", id_hex(&o.id), o.initial_shared_version.value())
            })
            .collect();
        let mut ns: Vec<String> = s.non_shared_input_object_keys().iter().map(|k| k.1.value().to_string()).collect();
        ns.extend(s.receiving_object_keys().iter().map(|k| k.1.value().to_string()));
        let cancel = match s.key().as_digest().and_then(|d| cancelled.get(d)) {
            None => "none".to_string(),
            Some(CancelConsensusCertificateReason::DkgFailed) => "dkg".to_string(),
            Some(CancelConsensusCertificateReason::CongestionOnObjects(ids)) if ids.is_empty() => "congestion:-".to_string(),
            Some(CancelConsensusCertificateReason::CongestionOnObjects(ids)) => {
                format!("congestion:{}", ids.iter().map(id_hex).collect::<Vec<_>>().join(","))
            }
        };
        let or_dash = |v: Vec<String>| if v.is_empty() { "-".to_string() } else { v.join(",") };
        writeln!(out, "vtx {key} {data} {} {} {cancel}", or_dash(shared), or_dash(ns)).unwrap();
    }

    let ConsensusSharedObjVerAssignment { shared_input_next_versions, assigned_versions } =
        SharedObjVerManager::assign_versions_from_consensus(&epoch_store, cache.as_ref(), schedule.iter(), &cancelled)
            .unwrap();
    for (key, av) in &assigned_versions.0 {
        let sh: Vec<String> = av
            .shared_object_versions
            .iter()
            .map(|((id, isv), v)| format!("{}:{}:{}", id_hex(id), isv.value(), v.value()))
            .collect();
        let mut sys: Vec<String> = Vec::new();
        for (id, _) in implicitly_read_system_objects(&epoch_store) {
            if let Some(v) = av.system_object_versions.get(&id) {
                sys.push(format!("{}:{}:{}", id_hex(&id), v.initial_shared_version.value(), v.version.value()));
            }
        }
        let or_dash = |v: Vec<String>| if v.is_empty() { "-".to_string() } else { v.join(",") };
        writeln!(out, "vassign {} {} {}", key_str(key), or_dash(sh), or_dash(sys)).unwrap();
    }
    let mut next: Vec<_> = shared_input_next_versions.into_iter().collect();
    next.sort();
    for ((id, isv), v) in next {
        writeln!(out, "vnext {} {} {}", id_hex(&id), isv.value(), v.value()).unwrap();
    }
    writeln!(out, "vend {name}").unwrap();
}

#[tokio::test]
async fn zui_version_vectors() {
    let path = std::env::var("ZUI_VECTORS_OUT").expect("ZUI_VECTORS_OUT");
    let mut out = String::new();
    writeln!(out, "# shared-object version assignment, Mysten sui-core mainnet-v1.83.1 (tools/truth/authority/versions)").unwrap();
    let cases: &[(&str, u64, usize, usize)] = &[
        ("one-object", 1, 1, 12),
        ("few", 2, 3, 30),
        ("many", 3, 8, 60),
        ("contended", 4, 2, 80),
        ("wide", 5, 12, 40),
        ("long", 6, 5, 200),
        ("seed7", 7, 4, 50),
        ("seed8", 8, 6, 50),
    ];
    for (name, seed, objs, txs) in cases {
        scenario(&mut out, name, *seed, *objs, *txs).await;
    }
    std::fs::File::create(&path).unwrap().write_all(out.as_bytes()).unwrap();
    eprintln!("zui_version_vectors: wrote {path}");
}
