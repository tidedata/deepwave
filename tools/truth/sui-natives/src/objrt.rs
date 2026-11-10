//! Round 2 generators: natives over the object runtime. Each item is a script of calls in one
//! transaction against a seeded object world (`ObjEnv`: storage objects, input objects, metering,
//! settled balances); the truth carries every call's outcome and charge plus the ObjectRuntime's
//! `finish()` results (writes, events, accumulator events, loaded children, created/deleted ids,
//! settlement totals) or its error.

use crate::vm::{Call, ObjEnv};
use crate::{BIG, Gen, Item, PV_MAX, PV_MIN_V4, b64, bv, call, tag};
use move_core_types::language_storage::{StructTag, TypeTag};
use move_core_types::runtime_value::{MoveStructLayout, MoveTypeLayout};
use serde_json::{Value as J, json};
use sui_types::base_types::{MoveObjectType, ObjectID, SequenceNumber, SuiAddress};
use sui_types::digests::TransactionDigest;
use sui_types::dynamic_field::derive_dynamic_field_id;
use sui_types::object::{Data, MoveObject, Object, Owner};

pub fn object_json(o: &Object) -> J {
    let ty = o.data.try_as_move().map(|m| {
        let st: StructTag = m.type_().clone().into();
        hex::encode(bcs::to_bytes(&st).unwrap())
    });
    json!({"obj": hex::encode(bcs::to_bytes(o).unwrap()), "type": ty})
}

/// The `env` of a vector line back into an `ObjEnv` (the bench reads vectors, not generators).
pub fn env_from_json(e: &serde_json::Map<String, J>) -> anyhow::Result<ObjEnv> {
    let h = |v: &J| hex::decode(v.as_str().unwrap_or_default()).map_err(|e| anyhow::anyhow!("{e}"));
    let mut env = ObjEnv { unmetered: !e["metered"].as_bool().unwrap_or(true), ..Default::default() };
    for i in e["inputs"].as_array().into_iter().flatten() {
        let i = i.as_array().unwrap();
        let uids = i[3].as_array().unwrap().iter().map(|u| ObjectID::from_bytes(h(u)?).map_err(|e| anyhow::anyhow!("{e}"))).collect::<anyhow::Result<Vec<_>>>()?;
        env.inputs.push((ObjectID::from_bytes(h(&i[0])?)?, i[1].as_u64().unwrap(), bcs::from_bytes(&h(&i[2])?)?, uids));
    }
    for o in e["objects"].as_array().into_iter().flatten() {
        env.objects.push(bcs::from_bytes(&h(&o["obj"])?)?);
    }
    for b in e["balances"].as_array().into_iter().flatten() {
        let b = b.as_array().unwrap();
        env.balances.push((SuiAddress::from_bytes(h(&b[0])?)?, bcs::from_bytes(&h(&b[1])?)?, b[2].as_str().unwrap().parse()?));
    }
    Ok(env)
}

pub(crate) fn oid(n: u16) -> ObjectID {
    let mut b = [0xabu8; 32];
    b[30] = (n >> 8) as u8;
    b[31] = n as u8;
    ObjectID::new(b)
}

/// The id `tx_context::fresh_id` hands out as the `n`th creation of the vector's transaction.
fn fresh(n: u64) -> ObjectID {
    ObjectID::derive_id(TransactionDigest::new(crate::vm::DEFAULT_CTX.digest), n)
}

/// `tx_context::fresh_id`, the native that records a new UID (`object::record_new_uid` has no Move
/// declaration in the framework, so no transaction can reach it). The argument is the id it will
/// return, kept for readability: callers pass `fresh(k)` for the k-th creation.
fn rec(_expect: ObjectID) -> Call {
    c2("tx_context", "fresh_id", vec![], vec![])
}

pub(crate) fn sender() -> SuiAddress {
    SuiAddress::from_bytes([0x5a; 32]).unwrap()
}

fn st(s: &str) -> StructTag {
    match tag(s) {
        TypeTag::Struct(s) => *s,
        t => panic!("{t} is not a struct"),
    }
}

pub(crate) fn mobj(ty: &str, contents: Vec<u8>, version: u64, owner: Owner) -> Object {
    let t: MoveObjectType = st(ty).into();
    let mo = unsafe { MoveObject::new_from_execution_with_limit(t, true, SequenceNumber::from_u64(version), contents, 256_000) }.unwrap();
    Object::new_move(mo, owner, TransactionDigest::new([0x77; 32]))
}

pub(crate) fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|p| p.iter().copied()).collect()
}

pub(crate) fn u64b(x: u64) -> Vec<u8> {
    x.to_le_bytes().to_vec()
}

fn u256b(x: u128) -> Vec<u8> {
    let mut b = vec![0u8; 32];
    b[..16].copy_from_slice(&x.to_le_bytes());
    b
}

fn dfid(parent: ObjectID, kty: &str, k: &[u8]) -> ObjectID {
    derive_dynamic_field_id(SuiAddress::from(parent), &tag(kty), k).unwrap()
}

pub(crate) fn c2(module: &'static str, func: &'static str, tys: Vec<&str>, args: Vec<Vec<u8>>) -> Call {
    call(2, module, func, tys, args)
}

pub(crate) fn with_budget(mut c: Call, b: u64) -> Call {
    c.budget = b;
    c
}

fn with_write(mut c: Call, w: Vec<u8>) -> Call {
    c.write = Some(w);
    c
}

const COIN: &str = "0x2::coin::Coin<0x2::sui::SUI>";
const FU64: &str = "0x2::dynamic_field::Field<u64, u64>";
const FU8: &str = "0x2::dynamic_field::Field<u64, u8>";
const FSTR: &str = "0x2::dynamic_field::Field<0x1::string::String, vector<u8>>";
const FTAB: &str = "0x2::dynamic_field::Field<u64, 0x2::table::Table<u64, u64>>";
const FCFG: &str = "0x2::dynamic_field::Field<u64, 0x2::config::Setting<u64>>";

pub(crate) fn push(g: &mut Gen, group: &str, id: impl Into<String>, pv: u64, env: ObjEnv, calls: Vec<Call>) {
    g.items.entry(group.to_string()).or_default().push(Item { id: id.into(), pv, ctx: None, calls, env: Some(env) });
}

/// P1: an address-owned input object at version 10 (root version for its children).
pub(crate) fn p1() -> ObjectID {
    oid(0x100)
}
pub(crate) fn base_env() -> ObjEnv {
    ObjEnv { inputs: vec![(p1(), 10, Owner::AddressOwner(sender()), vec![p1()])], ..Default::default() }
}

fn field_u64(parent: ObjectID, k: u64, v: u64) -> (ObjectID, Vec<u8>) {
    let id = dfid(parent, "u64", &u64b(k));
    (id, cat(&[id.as_ref(), &u64b(k), &u64b(v)]))
}

pub fn gen_all(g: &mut Gen) {
    gen_object(g);
    gen_transfer(g);
    gen_event(g);
    gen_child(g);
    gen_accumulator(g);
    gen_config(g);
    gen_package(g);
    gen_scratch(g);
    gen_limits(g);
    gen_layout_limits(g);
    gen_rt_sweep(g);
}

fn gen_object(g: &mut Gen) {
    let a = fresh(0);
    let b = fresh(1);
    let del = |x: ObjectID| c2("object", "delete_impl", vec![], vec![x.to_vec()]);
    let fh = |p: ObjectID, x: ObjectID| c2("object", "record_new_uid_from_hash", vec![], vec![p.to_vec(), x.to_vec()]);
    push(g, "object", "new", PV_MAX, base_env(), vec![rec(a), rec(b)]);
    push(g, "object", "new_then_delete", PV_MAX, base_env(), vec![rec(a), rec(b), del(a)]);
    push(g, "object", "delete_then_new", PV_MAX, base_env(), vec![del(a), del(b), rec(a)]);
    push(g, "object", "delete_input", PV_MAX, base_env(), vec![del(p1())]);
    push(g, "object", "new_twice", PV_MAX, base_env(), vec![fh(p1(), a), fh(p1(), a), del(a), del(a)]);
    push(g, "object", "from_hash/input_parent", PV_MAX, base_env(), vec![fh(p1(), a), fh(a, b)]);
    push(g, "object", "from_hash/new_parent", PV_MAX, base_env(), vec![rec(a), fh(a, b), del(b)]);
    for pv in [PV_MIN_V4, 130, 135, 139, 140] {
        push(g, "object", format!("from_hash@{pv}"), pv, base_env(), vec![fh(p1(), a)]);
    }
    let coin = cat(&[a.as_ref(), &u64b(5)]);
    push(g, "object", "borrow_uid/coin", PV_MAX, base_env(), vec![c2("object", "borrow_uid", vec![COIN], vec![coin.clone()])]);
    let (_, f) = field_u64(p1(), 3, 4);
    push(g, "object", "borrow_uid/field", PV_MAX, base_env(), vec![c2("object", "borrow_uid", vec![FU64], vec![f])]);
    for budget in [0u64, 51, 52] {
        push(g, "object", format!("oog/{budget}"), PV_MAX, base_env(), vec![
            with_budget(rec(a), budget), with_budget(del(b), budget), with_budget(c2("object", "borrow_uid", vec![COIN], vec![coin.clone()]), budget),
            with_budget(fh(p1(), b), budget.min(1)),
        ]);
    }
}

fn gen_transfer(g: &mut Gen) {
    let a = fresh(0);
    let coin = |x: ObjectID, v: u64| cat(&[x.as_ref(), &u64b(v)]);
    let tr = |o: Vec<u8>, to: [u8; 32]| c2("transfer", "transfer_impl", vec![COIN], vec![o, to.to_vec()]);
    let share = |o: Vec<u8>| c2("transfer", "share_object_impl", vec![COIN], vec![o]);
    let freeze = |o: Vec<u8>| c2("transfer", "freeze_object_impl", vec![COIN], vec![o]);
    let party = |o: Vec<u8>, dflt: u64, addrs: Vec<[u8; 32]>, perms: Vec<u64>| {
        c2("transfer", "party_transfer_impl", vec![COIN], vec![o, u64b(dflt), bcs::to_bytes(&addrs).unwrap(), bcs::to_bytes(&perms).unwrap()])
    };
    let me = [0x5a; 32];
    let other = [0x6b; 32];
    push(g, "transfer", "new/transfer", PV_MAX, base_env(), vec![rec(a), tr(coin(a, 1), other)]);
    push(g, "transfer", "new/share", PV_MAX, base_env(), vec![rec(a), share(coin(a, 1))]);
    push(g, "transfer", "new/freeze", PV_MAX, base_env(), vec![rec(a), freeze(coin(a, 1))]);
    push(g, "transfer", "new/party", PV_MAX, base_env(), vec![rec(a), party(coin(a, 1), 0, vec![other], vec![15])]);
    push(g, "transfer", "new/transfer_twice", PV_MAX, base_env(), vec![rec(a), tr(coin(a, 1), other), tr(coin(a, 2), me)]);
    push(g, "transfer", "input/same_owner", PV_MAX, base_env(), vec![tr(coin(p1(), 1), me)]);
    push(g, "transfer", "input/new_owner", PV_MAX, base_env(), vec![tr(coin(p1(), 1), other)]);
    push(g, "transfer", "input/share_owned", PV_MAX, base_env(), vec![share(coin(p1(), 1))]);
    push(g, "transfer", "input/freeze", PV_MAX, base_env(), vec![freeze(coin(p1(), 1))]);
    let mut shared_env = base_env();
    shared_env.inputs = vec![(p1(), 10, Owner::Shared { initial_shared_version: SequenceNumber::from_u64(4) }, vec![p1()])];
    push(g, "transfer", "input/share_shared", PV_MAX, shared_env.clone(), vec![share(coin(p1(), 1))]);
    let mut cons_env = base_env();
    cons_env.inputs = vec![(p1(), 10, Owner::ConsensusAddressOwner { start_version: SequenceNumber::from_u64(3), owner: SuiAddress::from_bytes(other).unwrap() }, vec![p1()])];
    push(g, "transfer", "input/party_same", PV_MAX, cons_env.clone(), vec![party(coin(p1(), 1), 0, vec![other], vec![15])]);
    push(g, "transfer", "input/party_other", PV_MAX, cons_env, vec![party(coin(p1(), 1), 0, vec![me], vec![15])]);
    let mut imm_env = base_env();
    imm_env.inputs = vec![(p1(), 10, Owner::Immutable, vec![p1()])];
    push(g, "transfer", "input/freeze_immutable", PV_MAX, imm_env, vec![freeze(coin(p1(), 1))]);
    push(g, "transfer", "unknown/share", PV_MAX, base_env(), vec![share(coin(oid(77), 1))]);
    push(g, "transfer", "unknown/transfer", PV_MAX, base_env(), vec![tr(coin(oid(77), 1), other)]);
    // framework objects are new when transferred without being input
    let mut clock = [0u8; 32];
    clock[31] = 6;
    let mut acc_root = [0u8; 32];
    acc_root[30] = 0x0a;
    acc_root[31] = 0xcc;
    push(g, "transfer", "framework/clock", PV_MAX, base_env(), vec![share(coin(ObjectID::new(clock), 0))]);
    push(g, "transfer", "framework/acc_root", PV_MAX, base_env(), vec![share(coin(ObjectID::new(acc_root), 0)), tr(coin(ObjectID::new(acc_root), 0), other)]);
    // party permission shapes that are invariant violations
    for (k, (dflt, addrs, perms)) in [
        (0u64, vec![other], vec![14u64]),
        (1, vec![other], vec![15]),
        (0, vec![other, me], vec![15]),
        (0, vec![], vec![15]),
        (0, vec![other], vec![15, 15]),
        (0, vec![other], vec![]),
    ]
    .into_iter()
    .enumerate()
    {
        push(g, "transfer", format!("party/bad{k}"), PV_MAX, base_env(), vec![rec(a), party(coin(a, 1), dflt, addrs, perms)]);
    }
    // the transferred type must be a struct with an id
    push(g, "transfer", "field_type", PV_MAX, base_env(), vec![rec(fresh(0)), c2("transfer", "transfer_impl", vec![FU64], vec![cat(&[fresh(0).as_ref(), &u64b(1), &u64b(2)]), other.to_vec()])]);
    for budget in [0u64, 51, 52] {
        push(g, "transfer", format!("oog/{budget}"), PV_MAX, base_env(), vec![
            rec(a), with_budget(tr(coin(a, 1), other), budget), with_budget(share(coin(a, 1)), budget),
            with_budget(freeze(coin(a, 1)), budget), with_budget(party(coin(a, 1), 0, vec![other], vec![15]), budget),
        ]);
    }
    for pv in PV_MIN_V4..PV_MAX {
        push(g, "transfer", format!("party@{pv}"), pv, base_env(), vec![rec(a), party(coin(a, 1), 0, vec![other], vec![15])]);
    }
    // receive
    let recv = |ty: &str, parent: ObjectID, child: ObjectID, v: u64| {
        let mut c = c2("transfer", "receive_impl", vec![], vec![parent.to_vec(), child.to_vec(), u64b(v)]);
        c.ty_args = vec![tag(ty)];
        c
    };
    let r1 = oid(0x300);
    let mut env = base_env();
    env.objects.push(mobj(COIN, coin(r1, 42), 7, Owner::AddressOwner(SuiAddress::from(p1()))));
    // a received Table-holding field: its inner UID gets the receive version as root
    let r2 = oid(0x301);
    let inner = oid(0x302);
    env.objects.push(mobj(FTAB, cat(&[r2.as_ref(), &u64b(1), inner.as_ref(), &u64b(0)]), 9, Owner::AddressOwner(SuiAddress::from(p1()))));
    let (ic, icb) = field_u64(inner, 5, 6);
    env.objects.push(mobj(FU64, icb, 8, Owner::ObjectOwner(SuiAddress::from(inner))));
    let r3 = oid(0x303);
    env.objects.push(mobj(COIN, coin(r3, 1), 7, Owner::AddressOwner(SuiAddress::from_bytes(other).unwrap())));
    push(g, "transfer", "receive/ok", PV_MAX, env.clone(), vec![recv(COIN, p1(), r1, 7)]);
    push(g, "transfer", "receive/ok_then_transfer", PV_MAX, env.clone(), vec![recv(COIN, p1(), r1, 7), tr(coin(r1, 42), other)]);
    push(g, "transfer", "receive/wrong_version", PV_MAX, env.clone(), vec![recv(COIN, p1(), r1, 6)]);
    push(g, "transfer", "receive/wrong_type", PV_MAX, env.clone(), vec![recv(FU64, p1(), r1, 7)]);
    push(g, "transfer", "receive/wrong_type_twice", PV_MAX, env.clone(), vec![recv(FU64, p1(), r1, 7), recv(FU64, p1(), r1, 7)]);
    push(g, "transfer", "receive/wrong_type_then_ok", PV_MAX, env.clone(), vec![recv(FU64, p1(), r1, 7), recv(COIN, p1(), r1, 7)]);
    push(g, "transfer", "receive/twice", PV_MAX, env.clone(), vec![recv(COIN, p1(), r1, 7), recv(COIN, p1(), r1, 7)]);
    push(g, "transfer", "receive/missing", PV_MAX, env.clone(), vec![recv(COIN, p1(), oid(0x3ff), 7)]);
    push(g, "transfer", "receive/other_owner", PV_MAX, env.clone(), vec![recv(COIN, p1(), r3, 7)]);
    push(g, "transfer", "receive/table_then_inner", PV_MAX, env.clone(), vec![
        recv(FTAB, p1(), r2, 9),
        c2("dynamic_field", "has_child_object", vec![], vec![inner.to_vec(), ic.to_vec()]),
        c2("dynamic_field", "borrow_child_object", vec![FU64], vec![inner.to_vec(), ic.to_vec()]),
    ]);
    push(g, "transfer", "receive/inner_without_root", PV_MAX, env.clone(), vec![
        c2("dynamic_field", "borrow_child_object", vec![FU64], vec![inner.to_vec(), ic.to_vec()]),
    ]);
    for budget in [0u64, 52, 60, 120] {
        push(g, "transfer", format!("receive/oog/{budget}"), PV_MAX, env.clone(), vec![with_budget(recv(COIN, p1(), r1, 7), budget)]);
    }
    for pv in [PV_MIN_V4, 125, 130, 136, 140] {
        push(g, "transfer", format!("receive/wrong_type_twice@{pv}"), pv, env.clone(), vec![recv(FU64, p1(), r1, 7), recv(FU64, p1(), r1, 7)]);
    }
}

fn gen_event(g: &mut Gen) {
    let em = |ty: &str, v: Vec<u8>| c2("event", "emit", vec![ty], vec![v]);
    let rng_s = |n: usize| vec![b'x'; n];
    push(g, "event", "emit/basic", PV_MAX, base_env(), vec![
        em("0x1::string::String", bv(b"hello")),
        em("0x2::object::ID", vec![9; 32]),
        em("0x1::option::Option<u64>", bcs::to_bytes(&Some(3u64)).unwrap()),
        em("0x1::type_name::TypeName", bv(b"0000000000000000000000000000000000000000000000000000000000000002::sui::SUI")),
    ]);
    push(g, "event", "emit/primitive", PV_MAX, base_env(), vec![em("u64", u64b(1))]);
    push(g, "event", "emit/vector", PV_MAX, base_env(), vec![em("vector<u8>", bv(b"ab"))]);
    push(g, "event", "emit/large", PV_MAX, base_env(), vec![em("0x1::string::String", bv(&rng_s(100_000)))]);
    // value size + tag size over max_event_emit_size (256000)
    push(g, "event", "emit/too_large", PV_MAX, base_env(), vec![em("0x1::string::String", bv(&rng_s(255_960)))]);
    push(g, "event", "emit/at_limit", PV_MAX, base_env(), vec![em("0x1::string::String", bv(&rng_s(255_900)))]);
    for budget in [0u64, 52, 60, 100, 600, 900] {
        push(g, "event", format!("emit/oog/{budget}"), PV_MAX, base_env(), vec![with_budget(em("0x1::string::String", bv(b"hi")), budget)]);
    }
    let auth = |head: &str, ty: &str, v: Vec<u8>| c2("event", "emit_authenticated_impl", vec![head, ty], vec![vec![0xac; 32], vec![0x51; 32], v]);
    push(g, "event", "auth/basic", PV_MAX, base_env(), vec![
        em("0x1::string::String", bv(b"a")),
        auth("0x2::accumulator_settlement::EventStreamHead", "0x1::string::String", bv(b"b")),
        auth("u64", "0x2::object::ID", vec![1; 32]),
    ]);
    for budget in [0u64, 52, 200, 300] {
        push(g, "event", format!("auth/oog/{budget}"), PV_MAX, base_env(), vec![with_budget(auth("u64", "0x1::string::String", bv(b"b")), budget)]);
    }
    for pv in PV_MIN_V4..PV_MAX {
        push(g, "event", format!("auth@{pv}"), pv, base_env(), vec![auth("u64", "0x1::string::String", bv(b"b")), em("0x1::string::String", bv(b"c"))]);
    }
}

fn gen_child(g: &mut Gen) {
    let has = |p: ObjectID, c: ObjectID| c2("dynamic_field", "has_child_object", vec![], vec![p.to_vec(), c.to_vec()]);
    let has_ty = |ty: &str, p: ObjectID, c: ObjectID| {
        let mut x = c2("dynamic_field", "has_child_object_with_ty", vec![], vec![p.to_vec(), c.to_vec()]);
        x.ty_args = vec![tag(ty)];
        x
    };
    let borrow = |ty: &str, p: ObjectID, c: ObjectID| {
        let mut x = c2("dynamic_field", "borrow_child_object", vec![], vec![p.to_vec(), c.to_vec()]);
        x.ty_args = vec![tag(ty)];
        x
    };
    let borrow_mut = |ty: &str, p: ObjectID, c: ObjectID| {
        let mut x = c2("dynamic_field", "borrow_child_object_mut", vec![], vec![p.to_vec(), c.to_vec()]);
        x.ty_args = vec![tag(ty)];
        x
    };
    let remove = |ty: &str, p: ObjectID, c: ObjectID| {
        let mut x = c2("dynamic_field", "remove_child_object", vec![], vec![p.to_vec(), c.to_vec()]);
        x.ty_args = vec![tag(ty)];
        x
    };
    let add = |ty: &str, p: ObjectID, v: Vec<u8>| {
        let mut x = c2("dynamic_field", "add_child_object", vec![], vec![p.to_vec(), v]);
        x.ty_args = vec![tag(ty)];
        x
    };
    let mut env = base_env();
    let (f1, f1b) = field_u64(p1(), 1, 100);
    let (f2, f2b) = field_u64(p1(), 2, 200);
    let sk = bv(b"key");
    let fs = dfid(p1(), "0x1::string::String", &sk);
    let fsb = cat(&[fs.as_ref(), &sk, &bv(&vec![7u8; 300])]);
    let table_uid = oid(0x200);
    let ft = dfid(p1(), "u64", &u64b(9));
    let ftb = cat(&[ft.as_ref(), &u64b(9), table_uid.as_ref(), &u64b(1)]);
    let (ti, tib) = field_u64(table_uid, 11, 12);
    let (tv, tvb) = field_u64(table_uid, 13, 14);
    let p1a = SuiAddress::from(p1());
    env.objects.push(mobj(FU64, f1b.clone(), 5, Owner::ObjectOwner(p1a)));
    env.objects.push(mobj(FU64, f2b.clone(), 10, Owner::ObjectOwner(p1a)));
    env.objects.push(mobj(FSTR, fsb.clone(), 3, Owner::ObjectOwner(p1a)));
    env.objects.push(mobj(FTAB, ftb.clone(), 6, Owner::ObjectOwner(p1a)));
    env.objects.push(mobj(FU64, tib.clone(), 6, Owner::ObjectOwner(SuiAddress::from(table_uid))));
    env.objects.push(mobj(FU64, tvb.clone(), 11, Owner::ObjectOwner(SuiAddress::from(table_uid)))); // newer than the root
    // a child owned by another parent, and a package under a child id
    let (fo, fob) = field_u64(oid(0x101), 1, 1);
    env.objects.push(mobj(FU64, fob, 2, Owner::ObjectOwner(SuiAddress::from(oid(0x101)))));
    let e = env.clone();
    let push_c = |g: &mut Gen, id: &str, calls: Vec<Call>| push(g, "child", id, PV_MAX, e.clone(), calls);
    push_c(g, "has/loaded", vec![has(p1(), f1), has(p1(), f1), has(p1(), oid(0x999)), has(p1(), oid(0x999))]);
    push_c(g, "has_ty", vec![has_ty(FU64, p1(), f1), has_ty(FSTR, p1(), f1), has_ty(FSTR, p1(), fs), has_ty(FU64, p1(), oid(0x998))]);
    push_c(g, "borrow/loaded", vec![borrow(FU64, p1(), f1)]);
    push_c(g, "borrow/twice", vec![borrow(FU64, p1(), f1), borrow(FU64, p1(), f1)]);
    push_c(g, "borrow/after_has", vec![has(p1(), f1), borrow(FU64, p1(), f1), has(p1(), f1), has_ty(FU64, p1(), f1)]);
    push_c(g, "borrow/missing", vec![borrow(FU64, p1(), oid(0x997))]);
    push_c(g, "borrow/wrong_type", vec![borrow(FSTR, p1(), f1), borrow(FU64, p1(), f1), borrow(FSTR, p1(), f1)]);
    push_c(g, "borrow/string", vec![borrow(FSTR, p1(), fs)]);
    push_c(g, "borrow/other_parent", vec![borrow(FU64, p1(), fo)]);
    push_c(g, "has/other_parent", vec![has(p1(), fo)]);
    push_c(g, "borrow_mut/unchanged", vec![with_write(borrow_mut(FU64, p1(), f1), f1b.clone())]);
    push_c(g, "borrow_mut/changed", vec![with_write(borrow_mut(FU64, p1(), f1), field_u64(p1(), 1, 101).1)]);
    push_c(g, "borrow_mut/changed_back", vec![
        with_write(borrow_mut(FU64, p1(), f1), field_u64(p1(), 1, 101).1),
        with_write(borrow_mut(FU64, p1(), f1), f1b.clone()),
    ]);
    push_c(g, "remove/loaded", vec![remove(FU64, p1(), f1)]);
    push_c(g, "remove/twice", vec![remove(FU64, p1(), f1), remove(FU64, p1(), f1), has(p1(), f1)]);
    push_c(g, "remove/cached", vec![borrow(FU64, p1(), f2), remove(FU64, p1(), f2)]);
    push_c(g, "remove/then_add_same", vec![remove(FU64, p1(), f1), add(FU64, p1(), f1b.clone())]);
    push_c(g, "remove/then_add_changed", vec![remove(FU64, p1(), f1), add(FU64, p1(), field_u64(p1(), 1, 5).1)]);
    push_c(g, "remove/then_transfer", vec![remove(FU64, p1(), f1), c2("transfer", "transfer_impl", vec![FU64], vec![f1b.clone(), vec![0x6b; 32]])]);
    push_c(g, "remove/then_delete", vec![remove(FU64, p1(), f1), c2("object", "delete_impl", vec![], vec![f1.to_vec()])]);
    // exec-history-vm: v1 before protocol 22 re-adds a removed child fresh (removing it again
    // leaves no effect); at 22 a re-add must keep the type (dropped at 23)
    push_c(g, "remove/readd_remove", vec![remove(FU64, p1(), f1), add(FU64, p1(), f1b.clone()), remove(FU64, p1(), f1)]);
    push_c(g, "remove/readd_remove_cached", vec![borrow(FU64, p1(), f2), remove(FU64, p1(), f2), add(FU64, p1(), f2b.clone()), remove(FU64, p1(), f2)]);
    push_c(g, "remove/readd_other_type", vec![remove(FU64, p1(), f1), add(FU8, p1(), cat(&[f1.as_ref(), &u64b(1), &[7u8]]))]);
    push_c(g, "remove/readd_other_type_remove", vec![
        remove(FU64, p1(), f1),
        add(FU8, p1(), cat(&[f1.as_ref(), &u64b(1), &[7u8]])),
        remove(FU8, p1(), f1),
    ]);
    push_c(g, "remove/wrong_type", vec![remove(FSTR, p1(), f1)]);
    push_c(g, "remove/missing", vec![remove(FU64, p1(), oid(0x996))]);
    push_c(g, "add/new", vec![add(FU64, p1(), field_u64(p1(), 50, 1).1), has(p1(), field_u64(p1(), 50, 1).0), borrow(FU64, p1(), field_u64(p1(), 50, 1).0)]);
    push_c(g, "add/duplicate", vec![add(FU64, p1(), field_u64(p1(), 50, 1).1), add(FU64, p1(), field_u64(p1(), 50, 2).1)]);
    push_c(g, "add/existing_loaded", vec![borrow(FU64, p1(), f1), add(FU64, p1(), f1b.clone())]);
    push_c(g, "add/over_unloaded", vec![add(FU64, p1(), f1b.clone()), borrow(FU64, p1(), f1)]);
    push_c(g, "add/then_remove", vec![add(FU64, p1(), field_u64(p1(), 51, 1).1), remove(FU64, p1(), field_u64(p1(), 51, 1).0)]);
    push_c(g, "table/nested", vec![borrow(FTAB, p1(), ft), borrow(FU64, table_uid, ti), has(table_uid, ti), has_ty(FU64, table_uid, ti)]);
    push_c(g, "table/nested_too_new", vec![borrow(FTAB, p1(), ft), borrow(FU64, table_uid, tv)]);
    push_c(g, "table/inner_first", vec![has(table_uid, ti)]);
    push_c(g, "table/inner_missing_first", vec![has(table_uid, oid(0x995))]);
    push_c(g, "table/remove_outer", vec![remove(FTAB, p1(), ft), borrow(FU64, table_uid, ti)]);
    // a new parent (fresh id) never has stored children
    let np = fresh(0);
    push_c(g, "new_parent", vec![
        rec(np),
        has(np, field_u64(np, 1, 1).0),
        add(FU64, np, field_u64(np, 1, 1).1),
        borrow(FU64, np, field_u64(np, 1, 1).0),
    ]);
    // cycles through child ownership: A under B and B under A
    let (fa, fab) = field_u64(oid(0x500), 1, 1);
    let fb_parent = fa;
    let (fb, fbb) = (dfid(fb_parent, "u64", &u64b(2)), cat(&[oid(0x500).as_ref(), &u64b(2), &u64b(2)]));
    let _ = fb;
    push_c(g, "cycle", vec![add(FU64, oid(0x500), fab), add(FU64, fb_parent, fbb)]);
    for budget in [0u64, 52, 60, 80, 100, 130, 200, 400] {
        push_c(g, &format!("oog/{budget}"), vec![
            with_budget(has(p1(), f1), budget),
            with_budget(has_ty(FU64, p1(), f2), budget),
            with_budget(borrow(FSTR, p1(), fs), budget),
            with_budget(remove(FU64, p1(), f2), budget),
            with_budget(add(FU64, p1(), field_u64(p1(), 60, 1).1), budget),
        ]);
    }
    for pv in PV_MIN_V4..PV_MAX {
        push(g, "child", format!("mix@{pv}"), pv, env.clone(), vec![
            has(p1(), f1), borrow(FU64, p1(), f1), has_ty(FSTR, p1(), fs), remove(FU64, p1(), f2),
            add(FU64, p1(), field_u64(p1(), 50, 1).1), borrow(FTAB, p1(), ft), borrow(FU64, table_uid, ti),
        ]);
    }
}

fn gen_accumulator(g: &mut Gen) {
    let acc = vec![0xa0u8; 32];
    let dep = |ty: &str, to: u8, n: u64| c2("accumulator", "emit_deposit_event", vec![ty], vec![acc.clone(), vec![to; 32], u64b(n)]);
    let wd = |ty: &str, to: u8, n: u64| c2("accumulator", "emit_withdraw_event", vec![ty], vec![acc.clone(), vec![to; 32], u64b(n)]);
    let bal = "0x2::balance::Balance<0x2::sui::SUI>";
    push(g, "accumulator", "events", PV_MAX, base_env(), vec![dep(bal, 1, 5), wd(bal, 1, 3), dep("u64", 2, 9), dep(bal, 1, 7)]);
    push(g, "accumulator", "merge_overflow", PV_MAX, base_env(), vec![dep(bal, 1, u64::MAX), dep(bal, 2, 1), dep(bal, 1, 1)]);
    push(g, "accumulator", "split_overflow", PV_MAX, base_env(), vec![wd(bal, 1, u64::MAX - 1), wd(bal, 1, 1), wd(bal, 1, 1)]);
    push(g, "accumulator", "settle", PV_MAX, base_env(), vec![
        c2("accumulator_settlement", "record_settlement_sui_conservation", vec![], vec![u64b(10), u64b(7)]),
        c2("accumulator_settlement", "record_settlement_sui_conservation", vec![], vec![u64b(1), u64b(4)]),
    ]);
    let add = |ty: &str, to: u8, n: u64| c2("funds_accumulator", "add_to_accumulator_address", vec![ty], vec![acc.clone(), vec![to; 32], u64b(n)]);
    let wfa = |ty: &str, to: u8, n: u128| c2("funds_accumulator", "withdraw_from_accumulator_address", vec![ty], vec![acc.clone(), vec![to; 32], u256b(n)]);
    let reserve = |ty: &str, owner: u8, n: u128| c2("funds_accumulator", "reserve_object_funds_for_withdrawal", vec![ty], vec![vec![owner; 32], u256b(n)]);
    let mut deep = String::from("u8");
    for _ in 0..15 {
        deep = format!("0x1::option::Option<{deep}>");
    }
    let big = format!("0x2::balance::Balance<{deep}>");
    let mut env = base_env();
    env.balances = vec![(SuiAddress::from_bytes([3; 32]).unwrap(), tag(bal), 150), (SuiAddress::from_bytes([4; 32]).unwrap(), tag(bal), u128::MAX)];
    push(g, "accumulator", "funds/add_withdraw", PV_MAX, env.clone(), vec![add(bal, 1, 10), wfa(bal, 1, 4), wfa(bal, 2, u64::MAX as u128), wfa(bal, 2, u64::MAX as u128 + 1)]);
    push(g, "accumulator", "funds/type_bounds", PV_MAX, env.clone(), vec![add(&big, 1, 1), wfa(&big, 1, 1)]);
    push(g, "accumulator", "funds/reserve", PV_MAX, env.clone(), vec![reserve(bal, 3, 100), reserve(bal, 3, 60), reserve(bal, 3, 50), reserve(bal, 9, 1), reserve(bal, 9, 0)]);
    push(g, "accumulator", "funds/reserve_after_deposit", PV_MAX, env.clone(), vec![add(bal, 3, 20), reserve(bal, 3, 20), reserve(bal, 3, 140), reserve(bal, 3, 11)]);
    push(g, "accumulator", "funds/reserve_overflow", PV_MAX, env.clone(), vec![add(bal, 4, 5), reserve(bal, 4, u128::MAX)]);
    for budget in [0u64, 52, 100, 236] {
        push(g, "accumulator", format!("oog/{budget}"), PV_MAX, env.clone(), vec![
            with_budget(dep(bal, 1, 1), budget), with_budget(add(bal, 1, 1), budget), with_budget(wfa(bal, 1, 1), budget),
            with_budget(reserve(bal, 3, 1), budget), with_budget(reserve(bal, 3, 1), budget),
        ]);
    }
    for pv in PV_MIN_V4..PV_MAX {
        push(g, "accumulator", format!("mix@{pv}"), pv, env.clone(), vec![
            dep(bal, 1, 5), wd(bal, 1, 3), add(bal, 3, 2), wfa(bal, 1, 4), reserve(bal, 3, 100), reserve(bal, 3, 100),
            c2("accumulator_settlement", "record_settlement_sui_conservation", vec![], vec![u64b(10), u64b(7)]),
        ]);
    }
}

fn gen_config(g: &mut Gen) {
    let cfg_obj = oid(0x600);
    let read = |name: ObjectID, epoch: u64| {
        let mut c = c2("config", "read_setting_impl", vec![], vec![cfg_obj.to_vec(), name.to_vec(), u64b(epoch)]);
        c.ty_args = vec![tag(FCFG), tag("0x2::config::Setting<u64>"), tag("0x2::config::SettingData<u64>"), tag("u64")];
        c
    };
    let opt = |v: Option<u64>| bcs::to_bytes(&v).unwrap();
    let setting = |k: u64, data: Option<(u64, Option<u64>, Option<u64>)>| -> (ObjectID, Vec<u8>) {
        let id = dfid(cfg_obj, "u64", &u64b(k));
        let d = match data {
            None => vec![0u8],
            Some((e, n, o)) => cat(&[&[1u8], &u64b(e), &opt(n), &opt(o)]),
        };
        (id, cat(&[id.as_ref(), &u64b(k), &d]))
    };
    let mut env = base_env();
    let (s1, s1b) = setting(1, Some((100, Some(7), Some(6))));
    let (s2, s2b) = setting(2, None);
    let (s3, s3b) = setting(3, Some((5, None, Some(1))));
    let owner = Owner::ObjectOwner(SuiAddress::from(cfg_obj));
    env.objects.push(mobj(FCFG, s1b, 4, owner.clone()));
    env.objects.push(mobj(FCFG, s2b, 4, owner.clone()));
    env.objects.push(mobj(FCFG, s3b, 4, owner));
    push(g, "config", "read", PV_MAX, env.clone(), vec![read(s1, 101), read(s1, 100), read(s1, 0), read(s2, 50), read(s3, 6), read(s3, 5), read(oid(0x6ff), 1)]);
    for budget in [0u64, 99, 100, 140, 300, 420] {
        push(g, "config", format!("oog/{budget}"), PV_MAX, env.clone(), vec![with_budget(read(s1, 101), budget), with_budget(read(oid(0x6ff), 1), budget)]);
    }
    for pv in PV_MIN_V4..PV_MAX {
        push(g, "config", format!("read@{pv}"), pv, env.clone(), vec![read(s1, 101), read(s1, 1), read(s2, 50)]);
    }
}

fn gen_package(g: &mut Gen) {
    let orig = |id: ObjectID, v: u64| c2("package", "original_package_id_impl", vec![], vec![id.to_vec(), u64b(v)]);
    let mut two = [0u8; 32];
    two[31] = 2;
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut env = base_env();
    // an upgraded package (version 3) whose modules carry the original address 0x1
    let fw = sui_framework::BuiltInFramework::get_package_by_id(&ObjectID::new(one));
    let mut map = std::collections::BTreeMap::new();
    for (m, b) in fw.modules().iter().zip(fw.bytes.iter()) {
        map.insert(m.self_id().name().to_string(), b.clone());
    }
    let up = sui_types::move_package::MovePackage::new(oid(0x700), SequenceNumber::from_u64(3), map, u64::MAX, vec![], Default::default()).unwrap();
    env.objects.push(Object::new_package_from_data(Data::Package(up), TransactionDigest::new([0x77; 32])));
    env.objects.push(mobj(COIN, cat(&[oid(0x701).as_ref(), &u64b(1)]), 1, Owner::AddressOwner(sender())));
    push(g, "package", "original_id", PV_MAX, env.clone(), vec![
        orig(ObjectID::new(two), 1), orig(ObjectID::new(two), 2), orig(ObjectID::new(one), 1), orig(oid(0x700), 3), orig(oid(0x700), 1),
        orig(oid(0x701), 1), orig(oid(0x7ff), 1),
    ]);
    for budget in [0u64, 52, 1000] {
        push(g, "package", format!("oog/{budget}"), PV_MAX, env.clone(), vec![with_budget(orig(ObjectID::new(two), 1), budget), with_budget(orig(oid(0x700), 3), budget)]);
    }
    for pv in PV_MIN_V4..PV_MAX {
        push(g, "package", format!("original_id@{pv}"), pv, env.clone(), vec![orig(ObjectID::new(two), 1), orig(oid(0x700), 3)]);
    }
}

fn gen_scratch(g: &mut Gen) {
    let k = |b: u8| vec![b; 32];
    let add = |ty: &str, key: u8, v: Vec<u8>| c2("scratch", "add_impl", vec![ty], vec![k(key), v]);
    let read = |ty: &str, key: u8| c2("scratch", "read_impl", vec![ty], vec![k(key)]);
    let rm = |ty: &str, key: u8| c2("scratch", "remove_impl", vec![ty], vec![k(key)]);
    let ex = |key: u8| c2("scratch", "exists_impl", vec![], vec![k(key)]);
    let exw = |ty: &str, key: u8| c2("scratch", "exists_with_type_impl", vec![ty], vec![k(key)]);
    let s = "0x1::string::String";
    push(g, "scratch", "basic", PV_MAX, base_env(), vec![
        add("u64", 1, u64b(5)), add(s, 2, bv(b"hello")), add("vector<u64>", 3, bcs::to_bytes(&vec![1u64, 2, 3]).unwrap()),
        read("u64", 1), read(s, 2), read("vector<u64>", 3), read("u64", 2), read("u64", 9),
        ex(1), ex(9), exw("u64", 1), exw(s, 1), exw("vector<vector<u64>>", 9),
        add("u8", 1, vec![1]), rm(s, 1), rm("u64", 1), rm("u64", 1), ex(1), add("u8", 1, vec![1]), read("u8", 1),
    ]);
    push(g, "scratch", "big_value", PV_MAX, base_env(), vec![add("vector<u8>", 1, bv(&vec![3u8; 5000])), read("vector<u8>", 1)]);
    for budget in [0u64, 12, 13, 14, 20, 100] {
        push(g, "scratch", format!("oog/{budget}"), PV_MAX, base_env(), vec![
            add("u64", 1, u64b(5)), with_budget(add("u64", 2, u64b(5)), budget), with_budget(read("u64", 1), budget),
            with_budget(ex(1), budget), with_budget(exw("vector<vector<u64>>", 1), budget), with_budget(rm("u64", 1), budget),
        ]);
    }
    for pv in PV_MIN_V4..PV_MAX {
        push(g, "scratch", format!("basic@{pv}"), pv, base_env(), vec![add("u64", 1, u64b(5)), read("u64", 1), ex(1), exw("u64", 1), rm("u64", 1)]);
    }
}

/// Per-transaction limits: ids, transfers, events, accumulator events, cache and store entries,
/// scratch pad size; metered and system (unmetered) where both exist.
fn gen_limits(g: &mut Gen) {
    let id = |n: u32| {
        let mut b = [0xcdu8; 32];
        b[28..].copy_from_slice(&n.to_be_bytes());
        ObjectID::new(b)
    };
    // deleted ids: 2048 metered
    let calls: Vec<Call> = (0..2049).map(|n| c2("object", "delete_impl", vec![], vec![id(n).to_vec()])).collect();
    push(g, "limits", "deleted_ids", PV_MAX, base_env(), calls);
    // transfers: 2048 metered (new objects)
    let mut calls: Vec<Call> = (0..2048).map(|n| rec(fresh(n))).collect();
    calls.extend((0..2049).map(|n| c2("transfer", "transfer_impl", vec![COIN], vec![cat(&[(if n < 2048 { fresh(n as u64) } else { id(n) }).as_ref(), &u64b(n as u64)]), vec![1; 32]])));
    push(g, "limits", "transfers", PV_MAX, base_env(), calls.clone());
    let unmetered = ObjEnv { unmetered: true, ..base_env() };
    push(g, "limits", "transfers_unmetered", PV_MAX, unmetered.clone(), calls);
    // events: 1024
    let calls: Vec<Call> = (0..1025).map(|n| c2("event", "emit", vec!["0x2::object::ID"], vec![id(n).to_vec()])).collect();
    push(g, "limits", "events", PV_MAX, base_env(), calls);
    // accumulator events: 1024
    let calls: Vec<Call> = (0..1025).map(|_| c2("accumulator", "emit_deposit_event", vec!["u8"], vec![vec![0xa0; 32], vec![1; 32], u64b(1)])).collect();
    push(g, "limits", "acc_events", PV_MAX, base_env(), calls);
    // cache: 1000 cached objects (lookups of missing children are cached too)
    let calls: Vec<Call> = (0..1001).map(|n| c2("dynamic_field", "has_child_object", vec![], vec![p1().to_vec(), id(n).to_vec()])).collect();
    push(g, "limits", "cache", PV_MAX, base_env(), calls.clone());
    push(g, "limits", "cache_unmetered", PV_MAX, unmetered.clone(), calls);
    // store: 1000 entries
    let calls: Vec<Call> = (0..1001)
        .map(|n| {
            let mut c = c2("dynamic_field", "add_child_object", vec![], vec![p1().to_vec(), cat(&[id(n).as_ref(), &u64b(n as u64), &u64b(0)])]);
            c.ty_args = vec![tag(FU64)];
            c
        })
        .collect();
    push(g, "limits", "store", PV_MAX, base_env(), calls);
    // borrow fills the store too: the 1001st is the store limit after 1000 loads (cache allows 1000)
    let calls: Vec<Call> = (0..1001)
        .map(|n| {
            let mut c = c2("dynamic_field", "borrow_child_object", vec![], vec![p1().to_vec(), id(n).to_vec()]);
            c.ty_args = vec![tag(FU64)];
            c
        })
        .collect();
    push(g, "limits", "store_borrow", PV_MAX, base_env(), calls);
    // scratch pad: 16384
    let calls: Vec<Call> = (0..16385).map(|n| c2("scratch", "add_impl", vec!["u8"], vec![id(n).to_vec(), vec![1]])).collect();
    push(g, "limits", "scratch", PV_MAX, base_env(), calls);
}

/// Types whose layout exceeds the VM's layout limits (`max_type_to_layout_nodes`, value depth):
/// `type_to_type_layout` gives None. The value itself is tiny (an empty option), so the call
/// still walks it.
fn gen_layout_limits(g: &mut Gen) {
    // Option<Option<...<u8>>>: depth 2 per level, over the value depth limit at 70 levels
    let mut deep = String::from("u8");
    for _ in 0..70 {
        deep = format!("0x1::option::Option<{deep}>");
    }
    // the stand-in shape of an empty Option<T> for T a struct: struct { vector<struct { bool }> }
    let inner = MoveTypeLayout::Struct(Box::new(MoveStructLayout::new(vec![MoveTypeLayout::Bool])));
    let shape = MoveTypeLayout::Struct(Box::new(MoveStructLayout::new(vec![MoveTypeLayout::Vector(Box::new(inner))])));
    let mk = |module: &'static str, func: &'static str, addr: u16, args: Vec<Vec<u8>>| {
        let mut c = call(addr, module, func, vec![], args);
        c.ty_args = vec![tag(&deep)];
        c.shapes = vec![Some(shape.clone())];
        c
    };
    let calls = vec![
        mk("dynamic_field", "hash_type_and_key", 2, vec![vec![0x5c; 32], vec![0]]),
        mk("bcs", "to_bytes", 1, vec![vec![0]]),
        with_budget(mk("dynamic_field", "hash_type_and_key", 2, vec![vec![0x5c; 32], vec![0]]), 60),
        with_budget(mk("bcs", "to_bytes", 1, vec![vec![0]]), 0),
        mk("scratch", "add_impl", 2, vec![vec![1; 32], vec![0]]),
    ];
    for (i, c) in calls.into_iter().enumerate() {
        let mut c = c;
        if c.func == "add_impl" {
            c.args = vec![vec![1; 32], vec![0]];
        }
        push(g, "layout_limits", format!("deep70/{i}/{}", c.func), PV_MAX, base_env(), vec![c]);
    }
    let _ = BIG;
    let _ = b64;
}

/// The object-runtime groups' first scenario per native, at the oldest and a middle version too.
fn gen_rt_sweep(_g: &mut Gen) {}

/// Reviewer edges (round 2), generated after every other group so those files stay unchanged:
/// config cache hits at another type or under another config (both None), a setting owned by
/// another parent (storage error, None), a first read whose contents do not fit the layout
/// (None, nothing cached), and stored children or received objects whose contents do not fit
/// their layout (FAILED_TO_DESERIALIZE_RESOURCE; a received object is then not recorded).
pub fn gen_review_rt(g: &mut Gen) {
    const FCFG8: &str = "0x2::dynamic_field::Field<u64, 0x2::config::Setting<u8>>";
    let cfg_obj = oid(0x600);
    let read_at = |cfg: ObjectID, name: ObjectID, epoch: u64, v: &str| {
        let mut c = c2("config", "read_setting_impl", vec![], vec![cfg.to_vec(), name.to_vec(), u64b(epoch)]);
        let field = format!("0x2::dynamic_field::Field<u64, 0x2::config::Setting<{v}>>");
        c.ty_args = vec![tag(&field), tag(&format!("0x2::config::Setting<{v}>")), tag(&format!("0x2::config::SettingData<{v}>")), tag(v)];
        c
    };
    let opt = |v: Option<u64>| bcs::to_bytes(&v).unwrap();
    let setting = |parent: ObjectID, k: u64, e: u64, n: Option<u64>, o: Option<u64>| -> (ObjectID, Vec<u8>) {
        let id = dfid(parent, "u64", &u64b(k));
        (id, cat(&[id.as_ref(), &u64b(k), &[1u8], &u64b(e), &opt(n), &opt(o)]))
    };
    let mut env = base_env();
    let (s1, s1b) = setting(cfg_obj, 1, 100, Some(7), Some(6));
    let (s4, s4b) = setting(cfg_obj, 4, 3, Some(9), None);
    env.objects.push(mobj(FCFG, s1b, 4, Owner::ObjectOwner(SuiAddress::from(cfg_obj))));
    env.objects.push(mobj(FCFG, s4b, 4, Owner::ObjectOwner(SuiAddress::from(oid(0x602)))));
    // a u8 setting stored under the u64 field type's name: the stored type is never checked
    let (s5, _) = setting(cfg_obj, 5, 0, None, None);
    let s5b = cat(&[s5.as_ref(), &u64b(5), &[1u8], &u64b(2), &[1u8, 0x11], &[0u8]]);
    env.objects.push(mobj(FCFG, s5b, 4, Owner::ObjectOwner(SuiAddress::from(cfg_obj))));
    let e = env.clone();
    let pc = |g: &mut Gen, id: &str, calls: Vec<Call>| push(g, "review_rt", format!("config/{id}"), PV_MAX, e.clone(), calls);
    pc(g, "cache_type_mismatch", vec![read_at(cfg_obj, s1, 101, "u64"), read_at(cfg_obj, s1, 101, "u8"), read_at(cfg_obj, s1, 101, "u64")]);
    pc(g, "cache_other_config", vec![read_at(cfg_obj, s1, 101, "u64"), read_at(oid(0x601), s1, 101, "u64"), read_at(cfg_obj, s1, 0, "u64")]);
    pc(g, "foreign_owner", vec![read_at(cfg_obj, s4, 5, "u64"), read_at(oid(0x602), s4, 5, "u64")]);
    pc(g, "bad_contents_then_ok", vec![read_at(cfg_obj, s1, 101, "u8"), read_at(cfg_obj, s1, 101, "u64")]);
    pc(g, "unchecked_stored_type", vec![read_at(cfg_obj, s5, 3, "u8"), read_at(cfg_obj, s5, 3, "u64")]);
    for budget in [0u64, 100, 200] {
        pc(g, &format!("cache_type_mismatch/oog/{budget}"), vec![read_at(cfg_obj, s1, 101, "u64"), with_budget(read_at(cfg_obj, s1, 101, "u8"), budget)]);
    }

    // children and received objects whose stored contents do not fit their layout
    let p1a = SuiAddress::from(p1());
    let mut env = base_env();
    let (f1, f1b) = field_u64(p1(), 1, 100);
    let (f2, f2b) = field_u64(p1(), 2, 200);
    env.objects.push(mobj(FU64, cat(&[&f1b, &[0u8]]), 5, Owner::ObjectOwner(p1a))); // one trailing byte
    env.objects.push(mobj(FU64, f2b[..f2b.len() - 1].to_vec(), 5, Owner::ObjectOwner(p1a))); // one byte short
    let r1 = oid(0x310);
    env.objects.push(mobj(COIN, cat(&[r1.as_ref(), &u64b(5), &[9u8]]), 7, Owner::AddressOwner(p1a)));
    let borrow = |c: ObjectID| c2("dynamic_field", "borrow_child_object", vec![FU64], vec![p1().to_vec(), c.to_vec()]);
    let remove = |c: ObjectID| c2("dynamic_field", "remove_child_object", vec![FU64], vec![p1().to_vec(), c.to_vec()]);
    let has = |c: ObjectID| c2("dynamic_field", "has_child_object", vec![], vec![p1().to_vec(), c.to_vec()]);
    let has_ty = |c: ObjectID| c2("dynamic_field", "has_child_object_with_ty", vec![FU64], vec![p1().to_vec(), c.to_vec()]);
    let recv = |c: ObjectID| c2("transfer", "receive_impl", vec![COIN], vec![p1().to_vec(), c.to_vec(), u64b(7)]);
    let e = env.clone();
    let pd = |g: &mut Gen, id: &str, calls: Vec<Call>| push(g, "review_rt", format!("bad_contents/{id}"), PV_MAX, e.clone(), calls);
    pd(g, "borrow_trailing", vec![borrow(f1)]);
    pd(g, "borrow_short", vec![borrow(f2)]);
    pd(g, "remove_trailing", vec![remove(f1)]);
    pd(g, "has_then_borrow", vec![has(f1), has_ty(f1), borrow(f1)]);
    pd(g, "receive", vec![recv(r1)]);
}

/// Round 3 reviewer item: the per-transaction event size total (max_event_emit_size_total,
/// TOTAL_EVENT_SIZE_LIMIT_EXCEEDED). Events of `Option<ascii::Char>` (10 abstract bytes per wire
/// byte) fill the total to exactly the limit, a filler `ascii::String` lands on it, and one more
/// empty event crosses it. A second item stops one byte short so the last event still fits.
pub fn gen_event_total(g: &mut Gen) {
    let cfg = sui_protocol_config::ProtocolConfig::get_for_version(PV_MAX.into(), sui_protocol_config::Chain::Mainnet);
    let total = cfg.max_event_emit_size_total();
    let per = cfg.max_event_emit_size();
    const OC: &str = "0x1::option::Option<0x1::ascii::Char>";
    const AS: &str = "0x1::ascii::String";
    let tsize = |s: &str| match tag(s) {
        TypeTag::Struct(st) => u64::from(st.abstract_size_for_gas_metering()),
        _ => unreachable!(),
    };
    let (t_oc, t_as) = (tsize(OC), tsize(AS));
    // Option<Char> is a struct around a vector of structs (2 + 2 + 10 per element); String is a
    // struct around vector<u8> (2 + 2 + 1 per byte).
    let oc = |n: u64| c2("event", "emit", vec![OC], vec![bv(&vec![b'a'; n as usize])]);
    let st = |n: u64| c2("event", "emit", vec![AS], vec![bv(&vec![b'b'; n as usize])]);
    let n_max = (per - t_oc - 4) / 10;
    let ev_max = t_oc + 4 + 10 * n_max;
    let mut k = total / ev_max;
    let mut rest = total - k * ev_max;
    let mut mid = None;
    if rest < t_as + 4 {
        k -= 1;
        rest += ev_max;
        let n2 = n_max - 50;
        mid = Some(n2);
        rest -= t_oc + 4 + 10 * n2;
    }
    let filler = rest - t_as - 4;
    assert!(t_as + 4 + filler <= per && k + 3 <= cfg.max_num_event_emit());
    // exact_then_over: the filler lands on the limit (allowed), one more event crosses it.
    // filler_plus_one: one byte more in the filler crosses it. Together they pin the boundary.
    for (id, extra) in [("exact_then_over", 0u64), ("filler_plus_one", 1)] {
        let mut calls: Vec<Call> = (0..k).map(|_| oc(n_max)).collect();
        if let Some(n2) = mid {
            calls.push(oc(n2));
        }
        calls.push(st(filler + extra));
        if extra == 0 {
            calls.push(st(0));
        }
        push(g, "event_total", id, PV_MAX, base_env(), calls);
    }
}
