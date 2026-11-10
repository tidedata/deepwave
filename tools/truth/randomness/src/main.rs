//! zui-truth-randomness: ground truth for the validator randomness and JWK lane, computed with
//! Mysten's code (fastcrypto + fastcrypto-tbls da61cd46, sui-types mainnet-v1.83.1).
//!
//! Built as an example of the `sui-types` crate inside a scratch worktree of the sui checkout, so
//! it uses Mysten's own Cargo.lock (run.sh does this). Commands (formats: README.md):
//!   dkg <out_file>   deterministic DKG transcripts (messages, confirmations, outputs, partial and
//!                    full threshold signatures) for several committee shapes
//!   jwk <out_file>   JWK document parsing per provider, ActiveJwk order, NewJWKFetched and
//!                    AuthenticatorStateUpdate encodings
//!
//! The output is pure data (JSON lines); the validator conformance runner replays it
//! (`--suite dkg-vectors`, `--suite jwk-vectors`).
//!
//! Committee handling mirrors `RandomnessManager::try_new` and
//! `randomness_dkg_info_from_committee` (sui-core/src/epoch/randomness.rs): the party id is the
//! authority's index in the `Committee` (members sorted by AuthorityName bytes), the weight is the
//! stake, `t` comes from `Nodes::new_reduced(nodes, committee.validity_threshold(), delta, lb)`,
//! and the random oracle is `RandomOracle::new("dkg {Hex(chain_id)} {epoch}")`.

use anyhow::{Result, bail};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::groups::bls12381;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use fastcrypto_tbls::{
    dkg_v1, ecies_v1,
    nodes::{Node, Nodes},
    random_oracle::RandomOracle,
    tbls::ThresholdBls,
    types::ThresholdBls12381MinSig,
};
use fastcrypto_zkp::bn254::zk_login::{JWK, JwkId, OIDCProvider, parse_jwks};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Write;
use std::str::FromStr;
use sui_types::authenticator_state::ActiveJwk;
use sui_types::base_types::{AuthorityName, SequenceNumber};
use sui_types::committee::Committee;
use sui_types::crypto::{AuthorityKeyPair, RandomnessRound, get_key_pair_from_rng};
use sui_types::messages_consensus::{
    ConsensusTransaction, VersionedDkgConfirmation, VersionedDkgMessage,
};
use sui_types::transaction::{TransactionData, TransactionDataAPI, VerifiedTransaction};

type G = bls12381::G2Element;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("dkg") => cmd_dkg(&args[2..]),
        Some("jwk") => cmd_jwk(&args[2..]),
        _ => bail!("usage: zui-truth-randomness dkg|jwk <out_file>"),
    }
}

fn hx(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

struct Case {
    id: &'static str,
    seed: u64,
    epoch: u64,
    stakes: &'static [u64],
    allowed_delta: u16,
    lower_bound: u16,
}

// Stakes sum to TOTAL_VOTING_POWER (10000) as Committee::new requires; validity_threshold is
// then 3334 like on mainnet. Mainnet 141 uses allowed_delta 800 and lower_bound 500; the
// smaller bounds keep the debug runs short while exercising the same reduction code.
const CASES: &[Case] = &[
    Case { id: "dkg-4-equal", seed: 1, epoch: 3, stakes: &[2500, 2500, 2500, 2500], allowed_delta: 800, lower_bound: 8 },
    Case { id: "dkg-7-skewed", seed: 2, epoch: 9, stakes: &[3000, 2000, 1500, 1200, 900, 800, 600], allowed_delta: 800, lower_bound: 50 },
    Case { id: "dkg-5-zero-weight", seed: 4, epoch: 21, stakes: &[4000, 3000, 2900, 99, 1], allowed_delta: 800, lower_bound: 30 },
    Case { id: "dkg-10-mainnet-like", seed: 3, epoch: 12, stakes: &[1500, 1200, 1100, 1000, 950, 900, 850, 800, 900, 800], allowed_delta: 800, lower_bound: 500 },
];

fn cmd_dkg(args: &[String]) -> Result<()> {
    let out = args.first().ok_or_else(|| anyhow::anyhow!("out_file"))?;
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);
    for c in CASES {
        let mut rng = StdRng::seed_from_u64(c.seed);
        let n = c.stakes.len();
        // validator keys: the BLS protocol key pair is the DKG key pair. The decryption key is
        // `Scalar::from_byte_array(authority_key_pair.private().as_bytes())` and the ECIES public
        // key the committee's G2 public key, exactly as DkgRole::try_new and
        // randomness_dkg_info_from_committee derive them.
        let mut voting = BTreeMap::new();
        let mut sk_of = BTreeMap::new();
        for i in 0..n {
            let (_, kp): (_, AuthorityKeyPair) = get_key_pair_from_rng(&mut rng);
            let name: AuthorityName = kp.public().into();
            let sk_bytes: [u8; 32] = kp.copy().private().as_bytes().try_into()?;
            voting.insert(name, c.stakes[i]);
            sk_of.insert(name, (bls12381::Scalar::from_byte_array(&sk_bytes)?, sk_bytes));
        }
        let committee = Committee::new(c.epoch, voting);
        // randomness_dkg_info_from_committee
        let mut info = Vec::new();
        for (name, stake) in committee.members() {
            let index: u16 = committee.authority_index(name).unwrap().try_into()?;
            let pk = G::from_byte_array(name.as_bytes().try_into()?)?;
            info.push((index, *name, pk, *stake, sk_of[name].0, sk_of[name].1));
        }
        info.sort_by_key(|x| x.0);
        let nodes_in: Vec<Node<G>> = info
            .iter()
            .map(|(id, _, pk, stake, _, _)| Node { id: *id, pk: ecies_v1::PublicKey::from(*pk), weight: (*stake).try_into().unwrap() })
            .collect();
        let validity: u16 = committee.validity_threshold().try_into()?;
        let (nodes, t) = Nodes::new_reduced(nodes_in, validity, c.allowed_delta, c.lower_bound)?;
        let chain_id: [u8; 32] = if c.id == "dkg-10-mainnet-like" {
            *sui_types::digests::get_mainnet_chain_identifier().as_bytes()
        } else {
            [c.seed as u8; 32]
        };
        let ro = RandomOracle::new(&format!("dkg {} {}", Hex::encode(chain_id), c.epoch));
        let parties: Vec<dkg_v1::Party<G, G>> = info
            .iter()
            .map(|x| dkg_v1::Party::<G, G>::new(ecies_v1::PrivateKey::from(x.4), nodes.clone(), t, ro.clone(), &mut rng))
            .collect::<Result<_, _>>()?;
        let weights: Vec<u16> = nodes.iter().map(|n| n.weight).collect();
        let stakes: Vec<u64> = info.iter().map(|x| x.3).collect();
        writeln!(
            f,
            "{}",
            json!({
                "op": "committee", "id": c.id, "epoch": c.epoch, "chain_id": hx(&chain_id),
                "sks": info.iter().map(|x| hx(&x.5)).collect::<Vec<_>>(),
                "names": info.iter().map(|x| hx(x.1.as_ref())).collect::<Vec<_>>(),
                "stakes": stakes, "allowed_delta": c.allowed_delta, "lower_bound": c.lower_bound,
                "validity": validity, "t": t, "weights": weights,
                "total_weight": nodes.total_weight(),
            })
        )?;

        // messages (zero weight parties get IgnoredMessage and send none, as in start_dkg)
        let mut msgs = Vec::new();
        for (i, p) in parties.iter().enumerate() {
            let m = match p.create_message(&mut rng) {
                Ok(m) => m,
                Err(fastcrypto::error::FastCryptoError::IgnoredMessage) => continue,
                Err(e) => bail!("create_message {i}: {e:?}"),
            };
            let v = VersionedDkgMessage::V1(m.clone());
            let ct = ConsensusTransaction::new_randomness_dkg_message(info[i].1, &v);
            writeln!(f, "{}", json!({"op":"message","id":c.id,"party":i,"bytes":hx(&bcs::to_bytes(&v)?),"ctx":hx(&bcs::to_bytes(&ct)?)}))?;
            msgs.push(m);
        }
        // everyone processes everything, merges and confirms (every Party submits its
        // Confirmation, zero weight included, as in try_merge_messages)
        let mut confs = Vec::new();
        let mut used = Vec::new();
        for (i, p) in parties.iter().enumerate() {
            let processed: Vec<_> = msgs.iter().filter_map(|m| p.process_message(m.clone(), &mut rng).ok()).collect();
            let (conf, u) = p.merge(&processed)?;
            let v = VersionedDkgConfirmation::V1(conf.clone());
            let ct = ConsensusTransaction::new_randomness_dkg_confirmation(info[i].1, &v);
            writeln!(f, "{}", json!({"op":"confirmation","id":c.id,"party":i,"bytes":hx(&bcs::to_bytes(&v)?),"ctx":hx(&bcs::to_bytes(&ct)?)}))?;
            confs.push(conf);
            used.push(u);
        }
        let mut outputs = Vec::new();
        for (i, p) in parties.iter().enumerate() {
            outputs.push(p.complete(&used[i], &confs, &mut rng)?);
        }
        let vss: Vec<String> = outputs[0].vss_pk.as_vec().iter().map(|g| hx(&g.to_byte_array())).collect();
        let mut shares = Vec::new();
        for o in &outputs {
            let s: Vec<_> = o
                .shares
                .as_ref()
                .map(|s| s.iter().map(|x| json!([x.index.get(), hx(&x.value.to_byte_array())])).collect())
                .unwrap_or_default();
            shares.push(s);
        }
        writeln!(f, "{}", json!({"op":"output","id":c.id,"vss_pk":vss,"shares":shares}))?;

        // threshold signatures for a few rounds
        for round in [0u64, 1, 41, 1u64 << 40] {
            let r = RandomnessRound(round);
            let msg = r.signature_message();
            let mut all = Vec::new();
            let mut per_party = Vec::new();
            for o in &outputs {
                let Some(sh) = &o.shares else {
                    per_party.push(Vec::new());
                    continue;
                };
                let ps = ThresholdBls12381MinSig::partial_sign_batch(sh.iter(), &msg);
                per_party.push(ps.iter().map(|p| hx(&bcs::to_bytes(p).unwrap())).collect::<Vec<_>>());
                all.extend(ps);
            }
            let full = ThresholdBls12381MinSig::aggregate(t, all.iter())?;
            ThresholdBls12381MinSig::verify(&outputs[0].vss_pk.c0(), &msg, &full)?;
            writeln!(
                f,
                "{}",
                json!({"op":"round","id":c.id,"round":round,"message":hx(&msg),"partials":per_party,"sig":hx(&bcs::to_bytes(&full)?)})
            )?;
            // the RandomnessStateUpdate transaction for this round (random_bytes = BCS of the
            // full signature, as RandomnessEventLoop hands it to the round receiver)
            let tx = VerifiedTransaction::new_randomness_state_update(c.epoch, r, bcs::to_bytes(&full)?, SequenceNumber::from_u64(7));
            let data: &TransactionData = tx.data().transaction_data();
            let _ = data.kind();
            writeln!(f, "{}", json!({"op":"rsu","id":c.id,"epoch":c.epoch,"round":round,"initial_shared_version":7,"sig":hx(&bcs::to_bytes(&full)?),"data":hx(&bcs::to_bytes(data)?),"digest":hx(tx.digest().inner())}))?;
        }
    }
    f.flush()?;
    Ok(())
}

fn cmd_jwk(args: &[String]) -> Result<()> {
    let out = args.first().ok_or_else(|| anyhow::anyhow!("out_file"))?;
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);
    let docs: &[(&str, &str)] = &[
        ("Google", r#"{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k1","n":"abcd==","e":"AQAB"},{"kty":"RSA","alg":"RS512","kid":"k2","n":"x","e":"AQAB"},{"kty":"EC","kid":"k3","n":"x","e":"AQAB"},{"kty":"RSA","kid":"k4","n":"yy","e":"AQAB=="},{"kty":"RSA","kid":"k5","n":"zz","e":"AQAC"},{"kid":"k6"}]}"#),
        ("Twitch", r#"{"keys":[{"kty":"RSA","kid":"1","n":"nnnn","e":"AQAB","alg":"RS256"}]}"#),
        ("AwsTenant-region:eu-west-3-tenant_id:eu-west-3_gGVCx53Es", r#"{"keys":[{"kty":"RSA","kid":"a","n":"q","e":"AQAB","alg":"RS256","x5c":["z"]}]}"#),
        ("Apple", r#"{"keys":[{"kid":"only-bad"}]}"#),
        ("Slack", r#"[1,2]"#),
        ("Facebook", r#"{"keys":[{"kty":"RSA","kid":"dup","n":"a","e":"AQAB","alg":"RS256"},{"kty":"RSA","kid":"dup","n":"b","e":"AQAB","alg":"RS256"}]}"#),
        ("Microsoft", r#"{"keys":[{"kty":"RSA","kid":"m1","n":"zz","e":"AQAB"}]}"#),
        ("KarrierOne", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
        ("Credenza3", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
        ("Playtron", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
        ("Onefc", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
        ("Threedos", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
        ("Kakao", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
        ("Arden", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
        ("FanTV", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
        ("EveFrontier", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
        ("TestEveFrontier", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
        ("AwsTenant-region:us-east-1-tenant_id:us-east-1_LPSLCkC3A", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
        ("TestIssuerKey8192", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
        ("Nope", r#"{}"#),
        ("TestIssuer", r#"{"keys":[{"kty":"RSA","kid":"k","n":"n","e":"AQAB","alg":"RS256"}]}"#),
    ];
    for (name, doc) in docs {
        let Ok(p) = OIDCProvider::from_str(name) else {
            writeln!(f, "{}", json!({"op":"from_str","id":format!("name-{name}"),"provider":name,"ok":false}))?;
            continue;
        };
        let cfg = p.get_config();
        let res = parse_jwks(doc.as_bytes(), &p, true);
        let keys: Vec<_> = match &res {
            Ok(v) => v.iter().map(|(id, j)| json!({"iss": id.iss, "kid": id.kid, "kty": j.kty, "e": j.e, "n": j.n, "alg": j.alg})).collect(),
            Err(_) => vec![],
        };
        writeln!(f, "{}", json!({"op":"parse","id":format!("parse-{name}"),"provider":name,"display":p.to_string(),"iss":cfg.iss,"endpoint":cfg.jwk_endpoint,"doc":doc,"ok":res.is_ok(),"keys":keys}))?;
        writeln!(f, "{}", json!({"op":"from_iss","id":format!("iss-{name}"),"iss":cfg.iss,"provider":OIDCProvider::from_iss(&cfg.iss).map(|p| p.to_string()).ok()}))?;
    }
    for iss in [
        "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
        "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_LPSLCkC3A",
        "https://accounts.google.com/",
        "https://example.com",
        "https://cognito-idp.eu-west-1.amazonaws.com/tenantA/extra",
        "https://login.microsoftonline.com/v2.0",
        "auth.evefrontier.com",
    ] {
        writeln!(f, "{}", json!({"op":"from_iss","id":format!("iss-{iss}"),"iss":iss,"provider":OIDCProvider::from_iss(iss).map(|p| p.to_string()).ok()}))?;
    }
    // ActiveJwk order (jwk_ord: length first) and the AuthenticatorStateUpdate transaction.
    // `input` is the unsorted list; new_authenticator_state_update gets it sorted as
    // authenticator_state_update_transaction does.
    let mk = |iss: &str, kid: &str, n: &str| ActiveJwk {
        jwk_id: JwkId::new(iss.into(), kid.into()),
        jwk: JWK { kty: "RSA".into(), e: "AQAB".into(), n: n.into(), alg: "RS256".into() },
        epoch: 5,
    };
    let cases: &[(&str, u64, u64, u64, &[(&str, &str, &str)])] = &[
        ("asu-1", 5, 77, 11, &[("bb", "x", "n"), ("a", "x", "n"), ("a", "y", "m"), ("a", "x", "zz"), ("a", "x", "z")]),
        // lexicographic and length-first orders disagree on every field here
        ("asu-length-first", 5, 78, 11, &[("https://aa.example", "k", "n"), ("https://b.example", "kid2", "n"), ("https://b.example", "k9", "zz"), ("https://b.example", "k9", "z")]),
        ("asu-empty", 0, 0, 1, &[]),
    ];
    for (id, epoch, round, isv, input) in cases {
        let mut jwks: Vec<ActiveJwk> = input.iter().map(|(i, k, n)| mk(i, k, n)).collect();
        jwks.iter_mut().for_each(|j| j.epoch = *epoch);
        jwks.sort();
        let order: Vec<_> = jwks.iter().map(|j| json!([j.jwk_id.iss, j.jwk_id.kid, j.jwk.n])).collect();
        let tx = VerifiedTransaction::new_authenticator_state_update(*epoch, *round, jwks, SequenceNumber::from_u64(*isv));
        let data: &TransactionData = tx.data().transaction_data();
        writeln!(f, "{}", json!({"op":"asu","id":id,"epoch":epoch,"round":round,"initial_shared_version":isv,"input":input.iter().map(|(i,k,n)| json!([i,k,n])).collect::<Vec<_>>(),"order":order,"data":hx(&bcs::to_bytes(data)?),"digest":hx(tx.digest().inner())}))?;
    }
    // NewJWKFetched consensus transaction
    let auth = [3u8; 96];
    let name = AuthorityName::from_bytes(&auth)?;
    let ct = ConsensusTransaction::new_jwk_fetched(name, JwkId::new("https://accounts.google.com".into(), "abc".into()), JWK { kty: "RSA".into(), e: "AQAB".into(), n: "nn".into(), alg: "RS256".into() });
    writeln!(f, "{}", json!({"op":"ctx_jwk","id":"ctx-jwk-1","authority":hx(&auth),"bytes":hx(&bcs::to_bytes(&ct)?)}))?;
    f.flush()?;
    Ok(())
}
