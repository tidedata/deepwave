// deepwave val-audit (ckpt): checkpoint wire vectors from sui-types at mainnet-v1.83.1.
// Prints `name hex` lines; deepwave pins them in src/validator/checkpoints/rust_vectors.zig.
use crate::base_types::{AuthorityName, SequenceNumber};
use crate::committee::Committee;
use crate::crypto::{
    AuthorityKeyPair, AuthorityPrivateKey, AuthoritySignInfo, AuthorityStrongQuorumSignInfo, RandomnessRound,
};
use crate::digests::{
    CheckpointArtifactsDigest, CheckpointDigest, Digest, TransactionDigest,
    TransactionEffectsDigest,
};
use crate::effects::TransactionEffects;
use crate::gas::GasCostSummary;
use crate::message_envelope::Message;
use crate::messages_checkpoint::*;
use crate::messages_consensus::ConsensusTransaction;
use crate::signature::GenericSignature;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use once_cell::sync::OnceCell;
use std::collections::BTreeMap;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn keys() -> Vec<AuthorityKeyPair> {
    (0..4u8)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = 0x21;
            seed[31] = i + 1;
            AuthorityKeyPair::from(AuthorityPrivateKey::from_bytes(&seed).unwrap())
        })
        .collect()
}

fn sig_a() -> GenericSignature {
    // Ed25519: flag 0, 64 signature bytes, 32 key bytes (not a valid signature; bytes only)
    let mut b = vec![0u8];
    b.extend((0..64u8).map(|i| i ^ 0x5a));
    b.extend((0..32u8).map(|i| i.wrapping_mul(3)));
    GenericSignature::from_bytes(&b).unwrap()
}

fn sig_sys() -> GenericSignature {
    GenericSignature::from_bytes(&[0u8; 97]).unwrap()
}

fn ed(t: u8, e: u8) -> crate::base_types::ExecutionDigests {
    crate::base_types::ExecutionDigests {
        transaction: TransactionDigest::new([t; 32]),
        effects: TransactionEffectsDigest::new([e; 32]),
    }
}

#[test]
fn zui_ckpt_vectors() {
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(141), Chain::Mainnet);
    let mut out = String::new();
    let mut put = |name: &str, b: &[u8]| out.push_str(&format!("{} {}\n", name, hx(b)));

    // contents V1 and V2
    let c1 = CheckpointContents::new_with_digests_and_signatures(
        vec![ed(1, 2), ed(3, 4)],
        vec![vec![sig_sys()], vec![sig_a(), sig_sys()]],
    );
    put("contents_v1", &bcs::to_bytes(&c1).unwrap());
    put("contents_v1_digest", c1.digest().inner());
    let c2 = CheckpointContents::V2(CheckpointContentsV2 {
        digest: OnceCell::new(),
        transactions: vec![
            CheckpointTransactionContents {
                digest: ed(1, 2),
                user_signatures: vec![(sig_sys(), None)],
            },
            CheckpointTransactionContents {
                digest: ed(3, 4),
                user_signatures: vec![(sig_a(), Some(SequenceNumber::from(42))), (sig_sys(), None)],
            },
        ],
    });
    put("contents_v2", &bcs::to_bytes(&c2).unwrap());
    put("contents_v2_digest", c2.digest().inner());

    // a regular summary at protocol 141 (version specific data V1 with two rounds)
    let s1 = CheckpointSummary::new(
        &cfg,
        5,
        12,
        1000,
        &c2,
        Some(CheckpointDigest::new([7; 32])),
        GasCostSummary::new(1, 2, 3, 4),
        None,
        1_700_000_000_123,
        vec![RandomnessRound::new(77), RandomnessRound::new(78)],
        vec![CheckpointArtifactsDigest::new([9; 32]).into()],
    );
    put("summary", &bcs::to_bytes(&s1).unwrap());
    put("summary_digest", s1.digest().inner());

    // committee: 4 x 2500
    let kps = keys();
    let mut rights = BTreeMap::new();
    for kp in &kps {
        put("key", kp.public().as_bytes());
        rights.insert(AuthorityName::from(kp.public()), 2500u64);
    }
    let committee = Committee::new(5, rights.clone());
    for (n, _) in committee.voting_rights.iter() {
        put("committee_name", n.as_ref());
    }

    // end-of-epoch summary
    let eoe = EndOfEpochData {
        next_epoch_committee: committee.voting_rights.clone(),
        next_epoch_protocol_version: ProtocolVersion::new(141),
        epoch_commitments: vec![ECMHLiveObjectSetDigest {
            digest: Digest::new([5; 32]),
        }
        .into()],
    };
    let s2 = CheckpointSummary::new(
        &cfg,
        5,
        13,
        1002,
        &c1,
        Some(s1.digest()),
        GasCostSummary::new(10, 20, 30, 40),
        Some(eoe),
        1_700_000_000_456,
        vec![],
        vec![CheckpointArtifactsDigest::new([8; 32]).into()],
    );
    put("summary_eoe", &bcs::to_bytes(&s2).unwrap());
    put("summary_eoe_digest", s2.digest().inner());

    // signatures of s1 by every key (in key order), as the consensus transaction each submits
    let mut infos = vec![];
    for kp in &kps {
        let signed = SignedCheckpointSummary::new(5, s1.clone(), kp, AuthorityName::from(kp.public()));
        signed.verify_authority_signatures(&committee).unwrap();
        put("sig", signed.auth_sig().signature.as_ref());
        put("signed_summary", &bcs::to_bytes(&signed).unwrap());
        infos.push(signed.auth_sig().clone());
        let tx = ConsensusTransaction::new_checkpoint_signature_message_v2(CheckpointSignatureMessage {
            summary: signed,
        });
        put("consensus_tx", &bcs::to_bytes(&tx).unwrap());
    }

    // strong quorum certificate from keys 0, 1 and 3 (key order, not committee order)
    let three: Vec<AuthoritySignInfo> = vec![infos[0].clone(), infos[1].clone(), infos[3].clone()];
    let cert = AuthorityStrongQuorumSignInfo::new_from_auth_sign_infos(three, &committee).unwrap();
    put("quorum_sign_info", &bcs::to_bytes(&cert).unwrap());
    let certified = CertifiedCheckpointSummary::new_from_data_and_sig(s1.clone(), cert);
    certified.verify_authority_signatures(&committee).unwrap();
    put("certified_summary", &bcs::to_bytes(&certified).unwrap());
    // all four
    let cert4 = AuthorityStrongQuorumSignInfo::new_from_auth_sign_infos(infos.clone(), &committee).unwrap();
    put("quorum_sign_info_all", &bcs::to_bytes(&cert4).unwrap());

    // roaring bitmaps (SuiBitmap = serialize_into bytes)
    for (name, ids) in [
        ("bitmap_one", vec![0u32]),
        ("bitmap_159", vec![1, 5, 9]),
        ("bitmap_range100", (0..100).collect::<Vec<_>>()),
        ("bitmap_two_containers", vec![3, 65536, 70000]),
    ] {
        let mut m = roaring::RoaringBitmap::new();
        for i in ids {
            m.insert(i);
        }
        let mut b = vec![];
        m.serialize_into(&mut b).unwrap();
        put(name, &b);
    }

    // version specific data alone
    let vsd = CheckpointVersionSpecificData::V1(CheckpointVersionSpecificDataV1 {
        randomness_rounds: vec![RandomnessRound::new(77), RandomnessRound::new(78)],
    });
    put("version_specific_data", &bcs::to_bytes(&vsd).unwrap());
    let _ = std::marker::PhantomData::<TransactionEffects>;

    let path = std::env::var("ZUI_VECTORS_OUT").unwrap_or_else(|_| "/dev/stdout".into());
    std::fs::write(path, out).unwrap();
}
