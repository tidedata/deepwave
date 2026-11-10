//! Round 2 generators: zklogin_verified_id / zklogin_verified_issuer (fastcrypto-zkp address
//! derivation), and the natives that are off on mainnet (vdf, rangeproofs).

use crate::vm::Call;
use crate::{Gen, PV_MAX, PV_MIN_V4, bv, call};
use fastcrypto_zkp::bn254::poseidon::poseidon_bytes;
use fastcrypto_zkp::bn254::utils::get_zk_login_address;
use fastcrypto_zkp::bn254::zk_login::hash_ascii_str_to_field;
use fastcrypto_zkp::zk_login_utils::Bn254FrElement;
use num_bigint::BigUint;
use std::str::FromStr;

/// The BN254 scalar field modulus r.
fn modulus() -> BigUint {
    BigUint::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495617").unwrap()
}

fn le32(x: &BigUint) -> Vec<u8> {
    let mut v = x.to_bytes_le();
    v.resize(32, 0);
    v
}

fn u256_bytes(x: &BigUint) -> Vec<u8> {
    le32(x)
}

/// (address_seed, salt_hash) of gen_address_seed(salt, name, value, aud).
fn seed(salt: &BigUint, name: &str, value: &str, aud: &str) -> (BigUint, BigUint) {
    let h = |s: &str, n: u16| BigUint::from_str(&hash_ascii_str_to_field(s, n).unwrap().to_string()).unwrap();
    let salt_hash = BigUint::from_bytes_le(&poseidon_bytes(&[le32(salt)]).unwrap());
    let s = poseidon_bytes(&[le32(&h(name, 32)), le32(&h(value, 115)), le32(&h(aud, 145)), le32(&salt_hash)]).unwrap();
    (BigUint::from_bytes_le(&s), salt_hash)
}

fn address(seed: &BigUint, iss: &str) -> Vec<u8> {
    get_zk_login_address(&Bn254FrElement::from_str(&seed.to_string()).unwrap(), iss).unwrap().to_vec()
}

fn id_call(addr: &[u8], name: &[u8], value: &[u8], iss: &[u8], aud: &[u8], pin: &BigUint) -> Call {
    call(2, "zklogin_verified_id", "check_zklogin_id_internal", vec![], vec![addr.to_vec(), bv(name), bv(value), bv(iss), bv(aud), u256_bytes(pin)])
}

fn iss_call(addr: &[u8], seed: &BigUint, iss: &[u8]) -> Call {
    call(2, "zklogin_verified_issuer", "check_zklogin_issuer_internal", vec![], vec![addr.to_vec(), u256_bytes(seed), bv(iss)])
}

fn budget(mut c: Call, b: u64) -> Call {
    c.budget = b;
    c
}

pub fn gen_all(g: &mut Gen) {
    gen_zklogin(g);
    gen_disabled(g);
}

fn gen_zklogin(g: &mut Gen) {
    let salt = BigUint::from_str("248191903847969014646285995941615069143").unwrap();
    let google = "https://accounts.google.com";
    let aud = "25769832374-famecqrhe2gkebt5fvqms2263046lj96.apps.googleusercontent.com";
    let r = modulus();
    let mut cases: Vec<(&str, Vec<Call>)> = Vec::new();

    let (s1, ph1) = seed(&salt, "sub", "106294049240999307923", aud);
    let a1 = address(&s1, google);
    cases.push(("id/valid", vec![id_call(&a1, b"sub", b"106294049240999307923", google.as_bytes(), aud.as_bytes(), &ph1)]));
    let mut bad = a1.clone();
    bad[0] ^= 1;
    cases.push(("id/wrong_address", vec![id_call(&bad, b"sub", b"106294049240999307923", google.as_bytes(), aud.as_bytes(), &ph1)]));
    cases.push(("id/wrong_iss", vec![id_call(&a1, b"sub", b"106294049240999307923", b"https://www.facebook.com", aud.as_bytes(), &ph1)]));
    // the pin hash reduced mod r: the same field element
    cases.push(("id/pin_plus_r", vec![id_call(&a1, b"sub", b"106294049240999307923", google.as_bytes(), aud.as_bytes(), &(&ph1 + &r))]));
    let max_u256 = (BigUint::from(1u8) << 256) - 1u8;
    cases.push(("id/pin_max", vec![id_call(&a1, b"sub", b"1", google.as_bytes(), aud.as_bytes(), &max_u256)]));
    // pin hash 0 (salt hash arbitrary): address made for it
    {
        let h = |s: &str, n: u16| BigUint::from_str(&hash_ascii_str_to_field(s, n).unwrap().to_string()).unwrap();
        let zero = BigUint::from(0u8);
        let s = BigUint::from_bytes_le(&poseidon_bytes(&[le32(&h("email", 32)), le32(&h("a@b.c", 115)), le32(&h("x", 145)), le32(&zero)]).unwrap());
        let a = address(&s, "iss");
        cases.push(("id/pin_zero", vec![id_call(&a, b"email", b"a@b.c", b"iss", b"x", &zero)]));
    }
    // bounds: name 32, value 115, aud 145 characters (not bytes)
    let n32 = "n".repeat(32);
    let v115 = "v".repeat(115);
    let a145 = "a".repeat(145);
    let (sb, phb) = seed(&salt, &n32, &v115, &a145);
    let ab = address(&sb, google);
    cases.push(("id/at_bounds", vec![id_call(&ab, n32.as_bytes(), v115.as_bytes(), google.as_bytes(), a145.as_bytes(), &phb)]));
    cases.push(("id/name_33", vec![id_call(&ab, "n".repeat(33).as_bytes(), v115.as_bytes(), google.as_bytes(), a145.as_bytes(), &phb)]));
    cases.push(("id/value_116", vec![id_call(&ab, n32.as_bytes(), "v".repeat(116).as_bytes(), google.as_bytes(), a145.as_bytes(), &phb)]));
    cases.push(("id/aud_146", vec![id_call(&ab, n32.as_bytes(), v115.as_bytes(), google.as_bytes(), "a".repeat(146).as_bytes(), &phb)]));
    // code points up to 0xff count as one character (two UTF-8 bytes); above 0xff is invalid input
    let latin = "é".repeat(32);
    let (sl, phl) = seed(&salt, &latin, "ü", "ß");
    let al = address(&sl, google);
    cases.push(("id/latin1", vec![id_call(&al, latin.as_bytes(), "ü".as_bytes(), google.as_bytes(), "ß".as_bytes(), &phl)]));
    cases.push(("id/euro", vec![id_call(&al, "€".as_bytes(), b"x", google.as_bytes(), b"y", &phl)]));
    cases.push(("id/iss_euro", vec![id_call(&a1, b"sub", b"106294049240999307923", "€".as_bytes(), aud.as_bytes(), &ph1)]));
    // not UTF-8, in each position
    let bad_utf8: &[u8] = &[0xff, 0xfe];
    cases.push(("id/name_not_utf8", vec![id_call(&a1, bad_utf8, b"x", google.as_bytes(), b"y", &ph1)]));
    cases.push(("id/value_not_utf8", vec![id_call(&a1, b"sub", bad_utf8, google.as_bytes(), b"y", &ph1)]));
    cases.push(("id/iss_not_utf8", vec![id_call(&a1, b"sub", b"x", bad_utf8, b"y", &ph1)]));
    cases.push(("id/aud_not_utf8", vec![id_call(&a1, b"sub", b"x", google.as_bytes(), bad_utf8, &ph1)]));
    cases.push(("id/empty", vec![id_call(&a1, b"", b"", b"", b"", &ph1)]));
    // an issuer longer than 255 bytes: its length byte wraps
    let long_iss = format!("https://{}.example", "l".repeat(300));
    let al2 = address(&s1, &long_iss);
    cases.push(("id/long_iss", vec![id_call(&al2, b"sub", b"106294049240999307923", long_iss.as_bytes(), aud.as_bytes(), &ph1)]));

    // issuer
    cases.push(("iss/valid", vec![iss_call(&a1, &s1, google.as_bytes())]));
    cases.push(("iss/wrong", vec![iss_call(&a1, &s1, b"https://accounts.google.com/")]));
    cases.push(("iss/seed_plus_r", vec![iss_call(&a1, &(&s1 + &r), google.as_bytes())]));
    cases.push(("iss/seed_max", vec![iss_call(&a1, &max_u256, google.as_bytes())]));
    cases.push(("iss/seed_zero", vec![iss_call(&address(&BigUint::from(0u8), google), &BigUint::from(0u8), google.as_bytes())]));
    cases.push(("iss/not_utf8", vec![iss_call(&a1, &s1, bad_utf8)]));
    cases.push(("iss/long", vec![iss_call(&al2, &s1, long_iss.as_bytes())]));
    for (id, calls) in cases {
        g.push("zklogin", id.to_string(), calls);
    }
    for b in [0u64, 1, 199, 200, 201] {
        g.push("zklogin", format!("oog/{b}"), vec![
            budget(id_call(&a1, b"sub", b"106294049240999307923", google.as_bytes(), aud.as_bytes(), &ph1), b),
            budget(iss_call(&a1, &s1, google.as_bytes()), b),
            budget(id_call(&a1, bad_utf8, b"x", google.as_bytes(), b"y", &ph1), b),
        ]);
    }
    for pv in PV_MIN_V4..PV_MAX {
        g.push_full("zklogin", format!("sweep@{pv}"), pv, None, vec![
            id_call(&a1, b"sub", b"106294049240999307923", google.as_bytes(), aud.as_bytes(), &ph1),
            iss_call(&a1, &s1, google.as_bytes()),
        ]);
    }
}

fn gen_disabled(g: &mut Gen) {
    let vdf_verify = || call(2, "vdf", "vdf_verify_internal", vec![], vec![bv(&[1, 2]), bv(&[3]), bv(&[]), 7u64.to_le_bytes().to_vec()]);
    let vdf_hash = || call(2, "vdf", "hash_to_input_internal", vec![], vec![bv(b"msg")]);
    let bp = || {
        call(2, "rangeproofs", "verify_bulletproofs_with_dst_ristretto255_internal", vec![], vec![
            bv(&[0u8; 64]), vec![32], bcs::to_bytes(&vec![vec![0u8; 32]]).unwrap(), bv(b"dst"),
        ])
    };
    for pv in PV_MIN_V4..=PV_MAX {
        g.push_full("disabled", format!("all@{pv}"), pv, None, vec![vdf_verify(), vdf_hash(), bp()]);
    }
    for b in [0u64, 1] {
        g.push("disabled", format!("oog/{b}"), vec![budget(vdf_verify(), b), budget(vdf_hash(), b), budget(bp(), b)]);
    }
}

