//! Edge-case truth for the sui-types values whose Rust `Deserialize` checks more than the
//! serde shape: `Owner::Party` (RawPartySerde + ObjectPermissions), std `Duration` (overflow
//! check and normalization), the BN254 decimal strings of zkLogin inputs (ark-ff `from_str`),
//! and the intent check of `SenderSignedTransaction`. Built against Mysten's sui-types 1.83.1.
//!
//!   source tools/env.sh
//!   cargo build --release --manifest-path tools/truth/bcs-types/edge/Cargo.toml
//!   $CARGO_TARGET_DIR/release/zui-truth-bcs-edge > src/types/testdata/rust_edge.txt
//!
//! One line per case: `<name> in=<hex> ok re=<hex of bcs::to_bytes(decoded)>` or
//! `<name> in=<hex> err <message>`. src/types/edge_test.zig replays every line.
use sui_types::base_types::{ObjectID, SequenceNumber, SuiAddress};
use sui_types::digests::ObjectDigest;
use sui_types::object::Owner;
use sui_types::transaction::{SenderSignedData, TransactionData};
use fastcrypto_zkp::zk_login_utils::{Bn254FqElement, Bn254FrElement};

fn show<T: serde::Serialize + for<'a> serde::Deserialize<'a>>(name: &str, input: &[u8]) {
    match bcs::from_bytes::<T>(input) {
        Ok(v) => println!("{name} in={} ok re={}", hex::encode(input), hex::encode(bcs::to_bytes(&v).unwrap())),
        Err(e) => println!("{name} in={} err {e}", hex::encode(input)),
    }
}

fn party(default: u64, members: &[([u8; 32], u64)]) -> Vec<u8> {
    let mut v = vec![5u8]; // Owner::Party
    v.extend_from_slice(&7u64.to_le_bytes()); // start_version
    v.extend_from_slice(&default.to_le_bytes());
    v.push(members.len() as u8);
    for (a, p) in members {
        v.extend_from_slice(a);
        v.extend_from_slice(&p.to_le_bytes());
    }
    v
}

fn uleb(mut n: usize) -> Vec<u8> {
    let mut v = vec![];
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 { v.push(b); return v; }
        v.push(b | 0x80);
    }
}
fn lp(b: &[u8]) -> Vec<u8> { let mut v = uleb(b.len()); v.extend_from_slice(b); v }
/// A real Ed25519 public key (valid curve point) from a seed.
fn ed_pk(seed: u8) -> [u8; 32] {
    use fastcrypto::ed25519::Ed25519PrivateKey;
    use fastcrypto::traits::{KeyPair, ToFromBytes};
    let sk = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let kp = fastcrypto::ed25519::Ed25519KeyPair::from(sk);
    kp.public().as_bytes().try_into().unwrap()
}
fn cs() -> Vec<u8> { let mut v = vec![0u8]; v.extend_from_slice(&[7u8; 64]); v }
/// MultiSig (non-legacy) GenericSignature wire bytes.
fn ms(nsigs: usize, bitmap: u16, pks: &[(Vec<u8>, u8)], thr: u16, trailing: bool) -> Vec<u8> {
    let mut v = vec![3u8];
    v.extend(uleb(nsigs));
    for _ in 0..nsigs { v.extend(cs()); }
    v.extend_from_slice(&bitmap.to_le_bytes());
    v.extend(uleb(pks.len()));
    for (k, w) in pks { v.extend_from_slice(k); v.push(*w); }
    v.extend_from_slice(&thr.to_le_bytes());
    if trailing { v.push(0); }
    lp(&v)
}
fn pk_e(seed: u8) -> Vec<u8> { let mut v = vec![0u8]; v.extend_from_slice(&ed_pk(seed)); v }
fn bm(vals: &[u32], run_opt: bool) -> Vec<u8> {
    let mut b = roaring::RoaringBitmap::new();
    for x in vals { b.insert(*x); }
    if run_opt { b.optimize(); }
    let mut out = vec![];
    b.serialize_into(&mut out).unwrap();
    out
}
fn b64k(flag_key: &[u8]) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(flag_key).into_bytes()
}
/// MultiSigLegacy GenericSignature wire bytes; keys are raw flag||key.
fn lg(nsigs: usize, bitmap: &[u8], pks: &[(Vec<u8>, u8)], thr: u16) -> Vec<u8> {
    let mut v = vec![3u8];
    v.extend(uleb(nsigs));
    for _ in 0..nsigs { v.extend(cs()); }
    v.extend(lp(bitmap));
    v.extend(uleb(pks.len()));
    for (k, w) in pks { v.extend(lp(&b64k(k))); v.push(*w); }
    v.extend_from_slice(&thr.to_le_bytes());
    lp(&v)
}

fn multisig_cases() {
    use sui_types::signature::GenericSignature as G;
    let k = |i: u8| (pk_e(i), 1u8);
    let ks = |n: u8| (1..=n).map(k).collect::<Vec<_>>();
    show::<G>("ms-valid-2of3", &ms(2, 0b101, &ks(3), 2, false));
    show::<G>("ms-valid-bitmap-count-mismatch", &ms(1, 0b111, &ks(3), 2, false));
    show::<G>("ms-valid-10keys", &ms(10, 0x3ff, &ks(10), 10, false));
    show::<G>("ms-11keys", &ms(1, 1, &ks(11), 1, false));
    show::<G>("ms-no-sigs", &ms(0, 1, &ks(3), 1, false));
    show::<G>("ms-more-sigs-than-keys", &ms(4, 1, &ks(3), 1, false));
    show::<G>("ms-bitmap-0x3ff", &ms(1, 0x3ff, &ks(3), 1, false));
    show::<G>("ms-bitmap-0x400", &ms(1, 0x400, &ks(3), 1, false));
    show::<G>("ms-threshold-0", &ms(1, 1, &ks(3), 0, false));
    show::<G>("ms-no-keys", &ms(0, 1, &[], 1, false));
    show::<G>("ms-weight-0", &ms(1, 1, &[(pk_e(1), 0), (pk_e(2), 5)], 1, false));
    show::<G>("ms-weight-sum-eq", &ms(1, 1, &[(pk_e(1), 2), (pk_e(2), 3)], 5, false));
    show::<G>("ms-weight-sum-lt", &ms(1, 1, &[(pk_e(1), 2), (pk_e(2), 3)], 6, false));
    show::<G>("ms-weight-255x10", &ms(1, 1, &(1..=10).map(|i| (pk_e(i), 255u8)).collect::<Vec<_>>(), 2550, false));
    show::<G>("ms-weight-255x10-thr-over", &ms(1, 1, &(1..=10).map(|i| (pk_e(i), 255u8)).collect::<Vec<_>>(), 2551, false));
    show::<G>("ms-dup-key", &ms(1, 1, &[(pk_e(1), 1), (pk_e(2), 1), (pk_e(1), 1)], 1, false));
    show::<G>("ms-dup-key-diff-weight", &ms(1, 1, &[(pk_e(1), 1), (pk_e(1), 9)], 1, false));
    show::<G>("ms-trailing", &ms(1, 1, &ks(3), 1, true));
    // secp256k1 key with the same 32 bytes vs ed25519 key: not duplicates
    let mut k1 = vec![1u8]; k1.push(2); k1.extend_from_slice(&ed_pk(1));
    show::<G>("ms-k1-ed-not-dup", &ms(1, 1, &[(pk_e(1), 1), (k1, 1)], 1, false));
}

fn legacy_cases() {
    use sui_types::signature::GenericSignature as G;
    let k = |i: u8| (pk_e(i), 1u8);
    let ks = |n: u8| (1..=n).map(k).collect::<Vec<_>>();
    show::<G>("lg-valid", &lg(2, &bm(&[0, 2], false), &ks(3), 2));
    show::<G>("lg-valid-run", &lg(2, &bm(&[0, 1, 2, 3], true), &ks(4), 2));
    show::<G>("lg-valid-run-5", &lg(2, &bm(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], true), &ks(10), 2));
    show::<G>("lg-empty-bitmap", &lg(1, &bm(&[], false), &ks(3), 1));
    show::<G>("lg-bitmap-9", &lg(1, &bm(&[9], false), &ks(10), 1));
    show::<G>("lg-bitmap-10", &lg(1, &bm(&[10], false), &ks(10), 1));
    show::<G>("lg-bitmap-0-and-10", &lg(1, &bm(&[0, 10], false), &ks(10), 1));
    show::<G>("lg-bitmap-65536", &lg(1, &bm(&[65536], false), &ks(3), 1));
    show::<G>("lg-bitmap-run-to-10", &lg(1, &bm(&[5, 6, 7, 8, 9, 10], true), &ks(10), 1));
    show::<G>("lg-bitmap-garbage", &lg(1, &[1, 2, 3], &ks(3), 1));
    show::<G>("lg-no-sigs", &lg(0, &bm(&[0], false), &ks(3), 1));
    show::<G>("lg-more-sigs-than-keys", &lg(4, &bm(&[0], false), &ks(3), 1));
    show::<G>("lg-threshold-0", &lg(1, &bm(&[0], false), &ks(3), 0));
    show::<G>("lg-no-keys", &lg(1, &bm(&[0], false), &[], 1));
    show::<G>("lg-11keys", &lg(1, &bm(&[0], false), &ks(11), 1));
    show::<G>("lg-weight-0", &lg(1, &bm(&[0], false), &[(pk_e(1), 0), (pk_e(2), 3)], 1));
    show::<G>("lg-weight-sum-lt", &lg(1, &bm(&[0], false), &[(pk_e(1), 1), (pk_e(2), 3)], 5));
    show::<G>("lg-dup-key", &lg(1, &bm(&[0], false), &[(pk_e(1), 1), (pk_e(2), 1), (pk_e(1), 1)], 1));
    // same key, two different base64 spellings are impossible with canonical padding; dup after decode
    let mut k1 = vec![1u8]; k1.push(2); k1.extend_from_slice(&ed_pk(1));
    show::<G>("lg-k1-ed-not-dup", &lg(1, &bm(&[0], false), &[(pk_e(1), 1), (k1, 1)], 1));
    // roaring cap
    let big: Vec<u32> = (0..151).collect();
    show::<G>("lg-bitmap-151", &lg(1, &bm(&big, false), &ks(3), 1));
}

fn zk(seed: &str, a0: &str, header_json: &str, claim: &str, idx: u8) -> Vec<u8> {
    use base64::Engine;
    let u = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let a: Vec<String> = vec![a0.into(), "2".into(), "3".into()];
    let b: Vec<Vec<String>> = vec![vec!["4".into(), "5".into()], vec!["6".into(), "7".into()], vec!["8".into(), "9".into()]];
    let c: Vec<String> = vec!["10".into(), "11".into(), "12".into()];
    let mut v = vec![5u8];
    v.extend(bcs::to_bytes(&a).unwrap());
    v.extend(bcs::to_bytes(&b).unwrap());
    v.extend(bcs::to_bytes(&c).unwrap());
    v.extend(bcs::to_bytes(&u.encode(claim)).unwrap());
    v.push(idx);
    v.extend(bcs::to_bytes(&u.encode(header_json)).unwrap());
    v.extend(bcs::to_bytes(&seed.to_string()).unwrap());
    v.extend_from_slice(&9u64.to_le_bytes());
    let mut sig = vec![0u8]; sig.extend_from_slice(&[5u8; 64]); sig.extend_from_slice(&ed_pk(3));
    v.extend(lp(&sig));
    lp(&v)
}

fn zk_cases() {
    use sui_types::signature::GenericSignature as G;
    let hdr = r#"{"alg":"RS256","typ":"JWT","kid":"abc"}"#;
    let claim = r#""iss":"https://a.bc","#;
    let fq = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
    let fr = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    show::<G>("zk-plain", &zk("12345", "1", hdr, claim, 0));
    show::<G>("zk-fq-reduced", &zk("12345", &format!("{fq}7"), hdr, claim, 0));
    show::<G>("zk-fr-reduced", &zk(&format!("{fr}99"), "1", hdr, claim, 0));
    show::<G>("zk-both-p", &zk(fr, fq, hdr, claim, 0));
    // semantic checks Rust performs in inputs.init(); deepwave does not yet (see CONTRACTS 2.3)
    show::<G>("gap-zk-bad-alg", &zk("1", "1", r#"{"alg":"HS256","typ":"JWT","kid":"abc"}"#, claim, 0));
    show::<G>("gap-zk-no-kid", &zk("1", "1", r#"{"alg":"RS256","typ":"JWT"}"#, claim, 0));
    show::<G>("gap-zk-not-json", &zk("1", "1", "nope", claim, 0));
    show::<G>("gap-zk-no-iss", &zk("1", "1", hdr, r#""sub":"https://a.bc","#, 0));
    show::<G>("gap-zk-claim-no-comma", &zk("1", "1", hdr, r#""iss":"https://a.bc"x"#, 0));
    show::<G>("gap-zk-idx3", &zk("1", "1", hdr, claim, 3));
    // legacy base64 ed25519 key 0xff..ff: y = 2^255-1 is non-canonical but decompresses, so
    // Rust accepts it (ed25519-consensus does check decompression: see gap-lg-ed-*)
    let mut bad = vec![0u8]; bad.extend_from_slice(&[0xffu8; 32]);
    show::<G>("lg-ed-unchecked-point", &lg(1, &bm(&[0], false), &[(bad, 1)], 1));
}


/// Review round 2: legacy base64 keys go through fastcrypto `from_bytes` (secp256k1
/// `PublicKey::from_slice`, p256 `VerifyingKey::try_from`, ed25519-consensus decompression),
/// which accept SEC1 uncompressed/hybrid encodings and check the point.
fn legacy_key_cases() {
    use sui_types::signature::GenericSignature as G;
    use fastcrypto::secp256k1::Secp256k1KeyPair;
    use fastcrypto::secp256r1::Secp256r1KeyPair;
    use fastcrypto::traits::{KeyPair, ToFromBytes};
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::from_seed([9u8; 32]);
    let k1 = Secp256k1KeyPair::generate(&mut rng);
    let r1 = Secp256r1KeyPair::generate(&mut rng);
    let k1c = k1.public().as_bytes().to_vec();
    let r1c = r1.public().as_bytes().to_vec();
    let k1u = k1.public().pubkey.serialize_uncompressed().to_vec();
    let r1u = r1.public().pubkey.to_encoded_point(false).as_bytes().to_vec();
    let fk = |flag: u8, b: &[u8]| { let mut v = vec![flag]; v.extend_from_slice(b); v };
    let one = |name: &str, key: Vec<u8>| show::<G>(name, &lg(1, &bm(&[0], false), &[(key, 1)], 1));
    one("lg-k1-compressed", fk(1, &k1c));
    one("lg-k1-uncompressed", fk(1, &k1u));
    let mut hy = k1u.clone(); hy[0] = 6 | (k1u[64] & 1);
    one("lg-k1-hybrid", fk(1, &hy));
    let mut hyb = k1u.clone(); hyb[0] = 6 | ((k1u[64] & 1) ^ 1);
    one("lg-k1-hybrid-bad-parity", fk(1, &hyb));
    one("lg-r1-uncompressed", fk(2, &r1u));
    one("lg-passkey-uncompressed", fk(6, &r1u));
    let mut r1hy = r1u.clone(); r1hy[0] = 6 | (r1u[64] & 1);
    one("lg-r1-hybrid", fk(2, &r1hy));
    // SEC1 compact (0x05 || x): p256 decompacts it, secp256k1 does not
    let mut r1x = r1c.clone(); r1x[0] = 5;
    one("lg-r1-compact", fk(2, &r1x));
    one("lg-passkey-compact", fk(6, &r1x));
    let mut r1x2 = r1c.clone(); r1x2[0] = 5; r1x2[32] ^= 1;
    one("lg-r1-compact-2", fk(2, &r1x2));
    one("lg-r1-identity-33", fk(2, &{ let mut z = vec![0u8; 33]; z[0] = 0; z }));
    let mut bad = vec![2u8]; bad.extend_from_slice(&[0xffu8; 32]);
    one("gap-lg-k1-x-over-p", fk(1, &bad));
    one("gap-lg-r1-x-over-p", fk(2, &bad));
    let mut k1bad_y = k1u.clone(); k1bad_y[64] ^= 1;
    one("gap-lg-k1-uncompressed-off-curve", fk(1, &k1bad_y));
    let mut k1p = k1c.clone(); k1p[0] = 5;
    one("lg-k1-bad-prefix", fk(1, &k1p));
    one("lg-k1-33-zero", fk(1, &[0u8; 33]));
    one("lg-k1-1byte-zero", fk(1, &[0u8]));
    one("lg-r1-1byte-zero", fk(2, &[0u8]));
    // point validity: Rust's key parsers reject these; deepwave has no curve check yet (gap-)
    // ed25519: first small y that does not decompress
    for y in 2u8..=40 {
        let mut b = [0u8; 32]; b[0] = y;
        if fastcrypto::ed25519::Ed25519PublicKey::from_bytes(&b).is_err() {
            one(&format!("gap-lg-ed-y{y}-off-curve"), fk(0, &b));
            break;
        }
    }
    let mut ync = [0xffu8; 32]; ync[31] = 0x7f; // y = 2^255-1 >= p, non-canonical
    one("lg-ed-y-noncanonical", fk(0, &ync));
    // base64 spelling of the legacy key string (fastcrypto Base64 = base64ct, padded, strict)
    let raw = |name: &str, s: &str| {
        let mut v = vec![3u8];
        v.extend(uleb(1)); v.extend(cs());
        v.extend(lp(&bm(&[0], false)));
        v.extend(uleb(1)); v.extend(lp(s.as_bytes())); v.push(1);
        v.extend_from_slice(&1u16.to_le_bytes());
        show::<G>(name, &lp(&v));
    };
    // a 34-byte flag||key (k1 compressed) needs two '=' pads
    let good = String::from_utf8(b64k(&fk(1, &k1c))).unwrap();
    raw("lg-b64-canonical", &good);
    let mut chars: Vec<u8> = good.clone().into_bytes();
    let last = chars.len() - 3; // char before the "==" pad
    let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let pos = alpha.iter().position(|c| *c == chars[last]).unwrap();
    chars[last] = alpha[pos | 1];
    raw("lg-b64-nonzero-pad-bits", std::str::from_utf8(&chars).unwrap());
    raw("lg-b64-no-pad", good.trim_end_matches('='));
    raw("lg-b64-one-pad", &good[..good.len() - 1]);
    raw("lg-b64-extra-pad", &format!("{good}="));
    raw("lg-b64-urlsafe", &good.replace('+', "-").replace('/', "_"));
    raw("lg-b64-space", &format!(" {good}"));
    raw("lg-b64-newline", &format!("{}\n{}", &good[..20], &good[20..]));
    raw("lg-b64-empty", "");
    // duplicate after compression: the same k1 point compressed and uncompressed
    show::<G>("lg-k1-dup-compressed-uncompressed", &lg(1, &bm(&[0], false), &[(fk(1, &k1c), 1), (fk(1, &k1u), 1)], 1));
    show::<G>("lg-r1-dup-compressed-uncompressed", &lg(1, &bm(&[0], false), &[(fk(2, &r1c), 1), (fk(2, &r1u), 1)], 1));
    show::<G>("lg-k1-r1-same-bytes-not-dup", &lg(1, &bm(&[0], false), &[(fk(1, &k1c), 1), (fk(6, &r1c), 1), (fk(2, &r1c), 1)], 1));
}


/// Review round 2: the container-depth budget is shared by the whole value, so a type argument
/// nested inside TransactionData hits the 500 limit sooner than a bare TypeTag. The bytes are
/// built by splicing `vector^k(bool)` over a U256 type argument (bcs cannot serialize them).
fn tx_depth_cases() {
    use move_core_types::identifier::Identifier;
    use move_core_types::language_storage::TypeTag;
    use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
    let mut b = ProgrammableTransactionBuilder::new();
    b.programmable_move_call(ObjectID::from_single_byte(2), Identifier::new("m").unwrap(), Identifier::new("zzzfn").unwrap(), vec![TypeTag::U256], vec![]);
    let data = TransactionData::new_programmable(SuiAddress::from(ObjectID::from_single_byte(9)), vec![(ObjectID::from_single_byte(7), SequenceNumber::from_u64(3), ObjectDigest::new([4; 32]))], b.finish(), 1000, 750);
    let raw = bcs::to_bytes(&data).unwrap();
    let pat = [b"zzzfn".as_slice(), &[1u8, 10]].concat();
    let at = raw.windows(pat.len()).position(|w| w == pat.as_slice()).unwrap() + pat.len() - 1;
    for k in [480usize, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499] {
        let mut v = raw[..at].to_vec();
        v.extend(std::iter::repeat(6u8).take(k));
        v.push(0);
        v.extend_from_slice(&raw[at + 1..]);
        show::<TransactionData>(&format!("txdepth-{k}"), &v);
    }
}

/// `edge <variants_in.txt>`: decode every `<Type> <variant> <hex>` line with the real type.
fn variants(path: &str) {
    use move_core_types::language_storage::TypeTag;
    use sui_types::crypto::{CompressedSignature, PublicKey};
    use sui_types::effects::{AccumulatorValue, UnchangedConsensusKind};
    use sui_types::execution::ExecutionTimeObservationKey;
    use sui_types::execution_status::{CommandArgumentError, ExecutionFailureStatus, PackageUpgradeError, TypeArgumentError};
    use sui_types::messages_grpc::ObjectInfoRequestKind;
    use sui_types::storage::DeleteKind;
    use sui_types::transaction::{EndOfEpochTransactionKind, WithdrawFrom};
    use sui_types::type_input::TypeInput;
    let text = std::fs::read_to_string(path).unwrap();
    for line in text.lines() {
        let mut f = line.split(' ');
        let (ty, k, h) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
        let bytes = hex::decode(h).unwrap();
        let name = format!("{ty}.{k}");
        match ty {
            "ExecutionErrorKind" => show::<ExecutionFailureStatus>(&name, &bytes),
            "CommandArgumentError" => show::<CommandArgumentError>(&name, &bytes),
            "TypeInput" => show::<TypeInput>(&name, &bytes),
            "TypeTag" => show::<TypeTag>(&name, &bytes),
            "PackageUpgradeError" => show::<PackageUpgradeError>(&name, &bytes),
            "CompressedSignature" => show::<CompressedSignature>(&name, &bytes),
            "DeleteKind" => show::<DeleteKind>(&name, &bytes),
            "PublicKey" => show::<PublicKey>(&name, &bytes),
            "AccumulatorValue" => show::<AccumulatorValue>(&name, &bytes),
            "ExecutionTimeObservationKey" => show::<ExecutionTimeObservationKey>(&name, &bytes),
            "ObjectInfoRequestKind" => show::<ObjectInfoRequestKind>(&name, &bytes),
            "TypeArgumentError" => show::<TypeArgumentError>(&name, &bytes),
            "UnchangedConsensusKind" => show::<UnchangedConsensusKind>(&name, &bytes),
            "WithdrawFrom" => show::<WithdrawFrom>(&name, &bytes),
            "EndOfEpochTransactionKind" => show::<EndOfEpochTransactionKind>(&name, &bytes),
            "Owner" => show::<Owner>(&name, &bytes),
            _ => panic!("unknown type {ty}"),
        }
    }
}

/// `dg-<type> in=<bcs hex> d=<default_hash hex>`: Mysten's BcsSignable digest of a value.
fn digest_cases() {
    use fastcrypto::hash::MultisetHash;
    use sui_types::crypto::default_hash;
    use sui_types::global_state_hash::GlobalStateHash;
    let data = TransactionData::new_transfer_sui(SuiAddress::from(ObjectID::from_single_byte(9)), SuiAddress::from(ObjectID::from_single_byte(8)), Some(5), (ObjectID::from_single_byte(7), SequenceNumber::from_u64(3), ObjectDigest::new([4; 32])), 1000, 750);
    let raw = bcs::to_bytes(&data).unwrap();
    let mut v = vec![1u8, 0, 0, 0];
    v.extend_from_slice(&raw);
    v.push(0);
    let ssd: SenderSignedData = bcs::from_bytes(&v).unwrap();
    println!("dg-SenderSignedData in={} d={}", hex::encode(bcs::to_bytes(&ssd).unwrap()), hex::encode(default_hash(&ssd)));
    let g = GlobalStateHash::default();
    println!("dg-GlobalStateHash in={} d={}", hex::encode(bcs::to_bytes(&g).unwrap()), hex::encode(default_hash(&g)));
    let mut g2 = GlobalStateHash::default();
    g2.insert(&[1u8, 2, 3]);
    println!("dg-GlobalStateHash in={} d={}", hex::encode(bcs::to_bytes(&g2).unwrap()), hex::encode(default_hash(&g2)));
}

fn layout_cases() {
    use move_core_types::runtime_value::{MoveStructLayout, MoveTypeLayout as L, MoveEnumLayout, MoveValue};
    let v = |l: &L| Box::new(l.clone());
    let st = |f: Vec<L>| L::Struct(Box::new(MoveStructLayout(Box::new(f))));
    let en = |f: Vec<Vec<L>>| L::Enum(Box::new(MoveEnumLayout(Box::new(f))));
    let layouts: Vec<(&str, L)> = vec![
        ("bool", L::Bool), ("u8", L::U8), ("u16", L::U16), ("u32", L::U32), ("u64", L::U64), ("u128", L::U128),
        ("u256", L::U256), ("address", L::Address), ("signer", L::Signer),
        ("vec-u8", L::Vector(v(&L::U8))),
        ("vec-vec-u64", L::Vector(v(&L::Vector(v(&L::U64))))),
        ("struct-empty", st(vec![])),
        ("struct-mixed", st(vec![L::Bool, L::U64, L::Vector(v(&L::U8)), L::Address])),
        ("struct-nested", st(vec![st(vec![L::U8, st(vec![L::U128])]), L::U256])),
        ("enum-2", en(vec![vec![], vec![L::U64, L::Bool]])),
        ("enum-empty", en(vec![])),
        ("vec-of-enum", L::Vector(v(&en(vec![vec![L::U8], vec![]])))),
    ];
    for (n, l) in &layouts {
        let lb = bcs::to_bytes(l).unwrap();
        show::<L>(&format!("lay-{n}"), &lb);
    }
    show::<L>("lay-bad-variant-12", &[12]);
    show::<L>("lay-bad-variant-255", &[0xff, 0x01]);
    show::<L>("lay-trailing", &[0, 0]);
    // layout depth: vector^n(u8)
    for n in [498usize, 499, 500, 501] {
        let mut b = vec![5u8; n];
        b.push(1);
        show::<L>(&format!("lay-depth-{n}"), &b);
    }
    // values
    let vals: Vec<(&str, usize, Vec<u8>)> = vec![
        ("bool-t", 0, vec![1]), ("bool-bad", 0, vec![2]), ("bool-eof", 0, vec![]),
        ("u8", 1, vec![7]), ("u16", 2, vec![1, 2]), ("u32", 3, vec![1, 2, 3, 4]), ("u64", 4, vec![1; 8]),
        ("u128", 5, vec![9; 16]), ("u256", 6, (0..32).collect()), ("u256-short", 6, vec![0; 31]),
        ("address", 7, vec![3; 32]), ("signer", 8, vec![4; 32]),
        ("vec-u8", 9, vec![3, 1, 2, 3]), ("vec-u8-empty", 9, vec![0]), ("vec-u8-short", 9, vec![3, 1]),
        ("vec-u8-noncanon-len", 9, vec![0x80, 0x00]),
        ("vec-vec-u64", 10, [vec![2], vec![1], vec![5; 8], vec![0]].concat()),
        ("struct-empty", 11, vec![]), ("struct-empty-trailing", 11, vec![0]),
        ("struct-mixed", 12, [vec![1], vec![2; 8], vec![2, 8, 9], vec![6; 32]].concat()),
        ("struct-nested", 13, [vec![1, 2], vec![0; 16], (0..32).collect::<Vec<u8>>()].concat()),
        ("enum-v0", 14, vec![0]), ("enum-v1", 14, [vec![1], vec![1; 8], vec![0]].concat()),
        ("enum-v2-oob", 14, vec![2]), ("enum-tag-127-oob", 14, vec![127]), ("enum-tag-128", 14, vec![128]),
        ("enum-empty-v0", 15, vec![0]),
        ("vec-of-enum", 16, vec![3, 0, 5, 1, 0, 9]),
    ];
    for (n, li, vb) in vals {
        let l = &layouts[li].1;
        let lb = bcs::to_bytes(l).unwrap();
        let inp = format!("{}:{}", hex::encode(&lb), hex::encode(&vb));
        match MoveValue::simple_deserialize(&vb, l) {
            Ok(mv) => println!("val-{n} in={inp} ok re={}", hex::encode(bcs::to_bytes(&mv).unwrap())),
            Err(e) => println!("val-{n} in={inp} err {e}"),
        }
    }
}

fn depth_cases() {
    use move_core_types::language_storage::TypeTag;
    use sui_types::type_input::TypeInput;
    for n in [1usize, 100, 127, 128, 129, 250, 498, 499, 500, 501, 502, 600] {
        let mut v = vec![6u8; n];
        v.push(0); // bool
        show::<TypeTag>(&format!("depth-typetag-{n}"), &v);
        show::<TypeInput>(&format!("depth-typeinput-{n}"), &v);
    }
    // inside TransactionData: a MoveCall type argument nested n deep is covered by the same
    // container-depth counter plus the enclosing containers.
}

fn main() {
    if let Some(p) = std::env::args().nth(1) {
        variants(&p);
        return;
    }
    zk_cases();
    depth_cases();
    layout_cases();
    digest_cases();
    multisig_cases();
    legacy_cases();
    legacy_key_cases();
    tx_depth_cases();
    let a1 = [1u8; 32];
    let a2 = [2u8; 32];
    show::<Owner>("party-valid", &party(1, &[(a1, 3), (a2, 0x7f)]));
    show::<Owner>("party-empty", &party(0, &[]));
    show::<Owner>("party-default-bad-bit", &party(0x80, &[]));
    show::<Owner>("party-default-mut-without-usage", &party(0x04, &[]));
    show::<Owner>("party-member-mut-without-usage", &party(1, &[(a1, 0x40)]));
    show::<Owner>("party-unsorted", &party(1, &[(a2, 3), (a1, 3)]));
    show::<Owner>("party-duplicate", &party(1, &[(a1, 3), (a1, 3)]));
    show::<Owner>("party-consensus-shape", &party(0, &[(a1, 0x7f)]));
    show::<Owner>("party-default1-all", &party(1, &[(a1, 0x7f)]));
    show::<Owner>("party-default0-two", &party(0, &[(a1, 0x7f), (a2, 0x7f)]));

    let dur = |s: u64, n: u32| { let mut v = s.to_le_bytes().to_vec(); v.extend_from_slice(&n.to_le_bytes()); v };
    show::<std::time::Duration>("dur-normal", &dur(5, 999_999_999));
    show::<std::time::Duration>("dur-carry", &dur(0, 1_500_000_000));
    show::<std::time::Duration>("dur-max-ok", &dur(u64::MAX, 999_999_999));
    show::<std::time::Duration>("dur-overflow", &dur(u64::MAX, 1_000_000_000));
    show::<std::time::Duration>("dur-max-nanos", &dur(u64::MAX - 4, u32::MAX));

    let fq = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
    let fr = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    let s = |x: &str| bcs::to_bytes(&x.to_string()).unwrap();
    for (n, x) in [("0", "0".to_string()), ("00", "00".into()), ("01", "01".into()), ("empty", "".into()), ("1a", "1a".into()), ("p", fq.into()), ("p+1", "21888242871839275222246405745257275088696311157297823662689037894645226208584".into()), ("long", format!("{fq}0")), ("plus", "+5".into()), ("12345", "12345".into())] {
        show::<Bn254FqElement>(&format!("fq-{n}"), &s(&x));
    }
    show::<Bn254FrElement>("fr-p", &s(fr));
    show::<Bn254FrElement>("fr-p-minus-1", &s("21888242871839275222246405745257275088548364400416034343698204186575808495616"));

    // SenderSignedData with a real TransactionData and patched intent bytes.
    let data = TransactionData::new_transfer_sui(SuiAddress::from(ObjectID::from_single_byte(9)), SuiAddress::from(ObjectID::from_single_byte(8)), Some(5), (ObjectID::from_single_byte(7), SequenceNumber::from_u64(3), ObjectDigest::new([4; 32])), 1000, 750);
    let raw = bcs::to_bytes(&data).unwrap();
    for (n, intent) in [("000", [0u8, 0, 0]), ("300", [3, 0, 0]), ("001", [0, 0, 1]), ("010", [0, 1, 0]), ("a00", [10, 0, 0])] {
        let mut v = vec![1u8];
        v.extend_from_slice(&intent);
        v.extend_from_slice(&raw);
        v.push(0); // no signatures
        show::<SenderSignedData>(&format!("ssd-intent-{n}"), &v);
        // invalid intent AND truncated after data: which error wins
        let t = &v[..v.len() - 1];
        show::<SenderSignedData>(&format!("ssd-intent-{n}-trunc"), t);
    }
}
