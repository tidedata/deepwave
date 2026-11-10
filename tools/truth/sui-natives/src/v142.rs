//! Truth vectors for what protocol 142 (Sui 1.84) changed in the natives, built only with the
//! `sui_184` feature (`zui-truth-sui-natives natives-v142 <corpus>` writes `v142_*.jsonl` into
//! `vectors/natives/`, leaving every 1.83.1 file alone):
//!
//! - `v142_clock`: `clock::native_borrow` (`clock_borrow_cost_base`, the Clock read once from
//!   `ImplicitSystemObjectResolver::clock` into one GlobalValue per runtime), including a missing
//!   or malformed Clock and the native at 141 (no cost parameter).
//! - `v142_object`: `object::is_shared_input_impl` (`input_owner(id)` is `Owner::Shared`).
//! - `v142_groth16`: `check_groth16_pvk_length` (`vk_gamma_abc` must be ceil(len/32)+1 G1 points)
//!   over the corpus groth16 verify vectors with the gamma_abc bytes cut, grown and emptied.
//! - `v142_ecdsa_r1`: `secp256r1_ecrecover` with the strict x check (r + n past 2^256 is an error
//!   instead of a wrap) over crafted r values around 2^256 - n and p - n, plus real signatures.
//!
//! Each item runs at 142 and, for a subset, at 141, so a version gate that is missing shows.

use crate::objrt::{base_env, c2, cat, mobj, oid, push, sender, u64b, with_budget};
use crate::vm::{Call, ObjEnv};
use crate::{Gen, PV_MAX, b8, bv, call};
use move_core_types::language_storage::TypeTag;
use num_bigint::BigUint;
use serde_json::Value as J;
use sui_types::base_types::{ObjectID, SequenceNumber};
use sui_types::object::Owner;

const CLOCK_TY: &str = "0x2::clock::Clock";

fn clock_id() -> ObjectID {
    let mut b = [0u8; 32];
    b[31] = 6;
    ObjectID::new(b)
}

/// The Clock's Move contents: `{ id: UID, timestamp_ms: u64 }`.
fn clock_contents(ms: u64) -> Vec<u8> {
    cat(&[clock_id().as_ref(), &u64b(ms)])
}

fn clock_obj(contents: Vec<u8>) -> sui_types::object::Object {
    mobj(CLOCK_TY, contents, 7, Owner::Shared { initial_shared_version: SequenceNumber::from_u64(1) })
}

fn clock_env(contents: Option<Vec<u8>>) -> ObjEnv {
    ObjEnv { clock: contents.map(clock_obj), ..base_env() }
}

pub fn gen_all(g: &mut Gen) {
    gen_clock(g);
    gen_object(g);
    gen_groth16(g);
    gen_ecdsa_r1(g);
}

fn gen_clock(g: &mut Gen) {
    let borrow = || c2("clock", "native_borrow", vec![], vec![]);
    let ts = 1_762_400_123_456u64;
    for pv in [PV_MAX, 141] {
        let sfx = if pv == PV_MAX { String::new() } else { format!("@{pv}") };
        push(g, "v142_clock", format!("borrow{sfx}"), pv, clock_env(Some(clock_contents(ts))), vec![borrow()]);
        push(g, "v142_clock", format!("borrow_twice{sfx}"), pv, clock_env(Some(clock_contents(ts))), vec![borrow(), borrow()]);
        push(g, "v142_clock", format!("no_clock{sfx}"), pv, clock_env(None), vec![borrow()]);
    }
    for ms in [0u64, 1, u64::MAX] {
        push(g, "v142_clock", format!("borrow/ts-{ms}"), PV_MAX, clock_env(Some(clock_contents(ms))), vec![borrow()]);
    }
    for budget in [0u64, 1, 51, 52, 53] {
        push(g, "v142_clock", format!("oog/{budget}"), PV_MAX, clock_env(Some(clock_contents(ts))), vec![with_budget(borrow(), budget), with_budget(borrow(), budget)]);
        // out of gas before the read: the missing Clock is never looked at
        push(g, "v142_clock", format!("oog_no_clock/{budget}"), PV_MAX, clock_env(None), vec![with_budget(borrow(), budget)]);
    }
    // contents that do not deserialize as `Clock`: short, long, empty
    let mut long = clock_contents(ts);
    long.push(0);
    let mut short = clock_contents(ts);
    short.pop();
    for (name, c) in [("short", short), ("long", long), ("empty", vec![]), ("id_only", clock_id().to_vec())] {
        push(g, "v142_clock", format!("bad_contents/{name}"), PV_MAX, clock_env(Some(c)), vec![borrow()]);
    }
    // the Clock read does not disturb a metered/unmetered runtime and works beside other natives
    let unmetered = ObjEnv { unmetered: true, ..clock_env(Some(clock_contents(ts))) };
    push(g, "v142_clock", "borrow/unmetered", PV_MAX, unmetered, vec![borrow()]);
    push(g, "v142_clock", "borrow_then_fresh_id", PV_MAX, clock_env(Some(clock_contents(ts))), vec![borrow(), c2("tx_context", "fresh_id", vec![], vec![]), borrow()]);
}

fn gen_object(g: &mut Gen) {
    let sh = oid(0x201);
    let sh2 = oid(0x202);
    let owned = oid(0x203);
    let imm = oid(0x204);
    let cao = oid(0x205);
    let objown = oid(0x206);
    let absent = oid(0x207);
    let child = oid(0x208);
    let mut env = base_env();
    env.inputs.extend([
        (sh, 9, Owner::Shared { initial_shared_version: SequenceNumber::from_u64(3) }, vec![sh, child]),
        (sh2, 12, Owner::Shared { initial_shared_version: SequenceNumber::from_u64(12) }, vec![sh2]),
        (owned, 5, Owner::AddressOwner(sender()), vec![owned]),
        (imm, 6, Owner::Immutable, vec![imm]),
        (cao, 8, Owner::ConsensusAddressOwner { start_version: SequenceNumber::from_u64(2), owner: sender() }, vec![cao]),
        (objown, 4, Owner::ObjectOwner(sh.into()), vec![objown]),
    ]);
    let q = |id: ObjectID| c2("object", "is_shared_input_impl", vec![], vec![id.to_vec()]);
    for (name, id) in [("shared", sh), ("shared2", sh2), ("owned", owned), ("immutable", imm), ("consensus_address", cao), ("object_owned", objown), ("absent", absent), ("contained_uid", child), ("p1", crate::objrt::p1())] {
        push(g, "v142_object", format!("{name}"), PV_MAX, env.clone(), vec![q(id)]);
        push(g, "v142_object", format!("{name}@141"), 141, env.clone(), vec![q(id)]);
    }
    push(g, "v142_object", "all", PV_MAX, env.clone(), vec![q(sh), q(owned), q(sh2), q(imm), q(cao), q(absent), q(sh)]);
    push(g, "v142_object", "no_inputs", PV_MAX, ObjEnv::default(), vec![q(sh)]);
    // the zero address and the system object addresses
    for n in [0u16, 1, 5, 6, 8] {
        let mut b = [0u8; 32];
        b[31] = n as u8;
        push(g, "v142_object", format!("system/{n}"), PV_MAX, env.clone(), vec![q(ObjectID::new(b))]);
    }
    for budget in [0u64, 51, 52, 53] {
        push(g, "v142_object", format!("oog/{budget}"), PV_MAX, env.clone(), vec![with_budget(q(sh), budget), with_budget(q(owned), budget)]);
    }
    // an id deleted in the transaction (object::delete_impl) is still an input
    push(g, "v142_object", "deleted_input", PV_MAX, env.clone(), vec![c2("object", "delete_impl", vec![], vec![sh.to_vec()]), q(sh)]);
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn gen_groth16(g: &mut Gen) {
    // (file, curve selector in the native, G1 compressed size)
    for (file, curve, g1) in [("vectors/groth16/bn254.jsonl", 1u8, 32usize), ("vectors/groth16/bls12381.jsonl", 0u8, 48usize)] {
        let rows = g.lines(file);
        let verify: Vec<&J> = rows.iter().filter(|x| x["op"] == "verify").collect();
        let pick = |i: usize| verify.get(i * verify.len() / 24.max(1)).copied();
        for i in 0..24 {
            let Some(x) = pick(i) else { continue };
            let id = x["id"].as_str().unwrap().to_string();
            let p: Vec<Vec<u8>> = x["pvk"].as_array().unwrap().iter().map(|t| unhex(t.as_str().unwrap())).collect();
            let inp = unhex(x["inputs"].as_str().unwrap_or(""));
            let proof = unhex(x["proof"].as_str().unwrap_or(""));
            let gamma = p[0].clone();
            let mk = |gamma: &[u8], inputs: &[u8]| -> Vec<Call> {
                vec![call(2, "groth16", "verify_groth16_proof_internal", vec![], vec![b8(curve), bv(gamma), bv(&p[1]), bv(&p[2]), bv(&p[3]), bv(inputs), bv(&proof)])]
            };
            let mut cut = gamma.clone();
            cut.truncate(gamma.len().saturating_sub(g1));
            let mut grown = gamma.clone();
            grown.extend_from_slice(&gamma[..g1.min(gamma.len())]);
            let mut odd = gamma.clone();
            odd.pop();
            let mut plus1 = gamma.clone();
            plus1.push(0);
            let variants: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
                ("orig", gamma.clone(), inp.clone()),
                ("cut", cut, inp.clone()),
                ("grown", grown, inp.clone()),
                ("empty", vec![], inp.clone()),
                ("odd", odd, inp.clone()),
                ("plus1", plus1, inp.clone()),
                // one more public input than the key has points for, and the opposite
                ("inputs_plus32", gamma.clone(), [inp.clone(), vec![1u8; 32]].concat()),
                ("inputs_minus32", gamma.clone(), inp[..inp.len().saturating_sub(32)].to_vec()),
                ("inputs_partial", gamma.clone(), [inp.clone(), vec![1u8; 5]].concat()),
                // more than max_public_inputs (8) with a key of the wrong length: which check wins
                ("many_inputs_bad_key", gamma[..g1.min(gamma.len())].to_vec(), vec![2u8; 32 * 9]),
                ("many_inputs", gamma.clone(), vec![2u8; 32 * 9]),
            ];
            for (name, gm, inputs) in variants {
                if name != "orig" || i < 4 {
                    push(g, "v142_groth16", format!("{id}/{name}"), PV_MAX, ObjEnv::default(), mk(&gm, &inputs));
                }
                if i < 6 {
                    push(g, "v142_groth16", format!("{id}/{name}@141"), 141, ObjEnv::default(), mk(&gm, &inputs));
                }
            }
        }
    }
}

fn u256_be(x: &BigUint) -> [u8; 32] {
    let b = x.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

fn gen_ecdsa_r1(g: &mut Gen) {
    let n = BigUint::parse_bytes(b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16).unwrap();
    let p = BigUint::parse_bytes(b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16).unwrap();
    let two256: BigUint = BigUint::from(1u8) << 256usize;
    let wrap: BigUint = &two256 - &n; // r >= wrap: r + n overflows 2^256
    let pmn: BigUint = &p - &n; // r >= pmn: r + n >= p
    let one: BigUint = BigUint::from(1u8);
    let rs: Vec<(&str, BigUint)> = vec![
        ("1", one.clone()),
        ("2", BigUint::from(2u8)),
        ("2^224", one.clone() << 224usize),
        ("pmn-1", &pmn - &one),
        ("pmn", pmn.clone()),
        ("pmn+1", &pmn + &one),
        ("wrap-1", &wrap - &one),
        ("wrap", wrap.clone()),
        ("wrap+1", &wrap + &one),
        ("n-1", &n - &one),
    ];
    let msg = b"zui 1.84 ecrecover";
    for (name, r) in &rs {
        for (sname, s) in [("1", one.clone()), ("hi", BigUint::parse_bytes(b"7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8", 16).unwrap())] {
            for recid in 0u8..4 {
                for h in [0u8, 1] {
                    let mut sig = u256_be(r).to_vec();
                    sig.extend_from_slice(&u256_be(&s));
                    sig.push(recid);
                    let id = format!("r={name}/s={sname}/recid={recid}/h={h}");
                    push(g, "v142_ecdsa_r1", id.clone(), PV_MAX, ObjEnv::default(), vec![call(2, "ecdsa_r1", "secp256r1_ecrecover", vec![], vec![bv(&sig), bv(msg), b8(h)])]);
                    if recid >= 2 && h == 1 {
                        push(g, "v142_ecdsa_r1", format!("{id}@141"), 141, ObjEnv::default(), vec![call(2, "ecdsa_r1", "secp256r1_ecrecover", vec![], vec![bv(&sig), bv(msg), b8(h)])]);
                    }
                }
            }
        }
    }
    // real signatures (recid 0 and 1) recover the same at 142 and 141
    let v = g.lines("vectors/sig-vectors/vectors.jsonl");
    let mut n = 0;
    for x in v.iter().filter(|x| x["op"] == "secp256r1_recover") {
        if n >= 80 {
            break;
        }
        n += 1;
        let id = x["id"].as_str().unwrap().to_string();
        let sig = unhex(x["sig"].as_str().unwrap_or(""));
        let m = unhex(x["msg"].as_str().unwrap_or(""));
        let h = if x["h"].as_str() == Some("keccak256") { 0 } else { 1 };
        push(g, "v142_ecdsa_r1", format!("real/{id}"), PV_MAX, ObjEnv::default(), vec![call(2, "ecdsa_r1", "secp256r1_ecrecover", vec![], vec![bv(&sig), bv(&m), b8(h)])]);
        if n <= 20 {
            push(g, "v142_ecdsa_r1", format!("real/{id}@141"), 141, ObjEnv::default(), vec![call(2, "ecdsa_r1", "secp256r1_ecrecover", vec![], vec![bv(&sig), bv(&m), b8(h)])]);
        }
    }
    let _ = TypeTag::Bool;
}
