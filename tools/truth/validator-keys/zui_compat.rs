// tools/truth/validator-keys: key file, validator.yaml and validator-epoch vectors from Mysten's own code at 1.83.1.
//
//   ZUI_COMPAT_OUT=<dir> [ZUI_YAML_DIR=<dir with zui-written validator-*.yaml>] \
//     cargo test --release -p sui-swarm-config --test zui_compat -- --nocapture
//
// Writes into ZUI_COMPAT_OUT:
//   keys.jsonl                one line per seed: key files (sui-keys writers), public keys, bech32,
//                             account address, proof of possession
//   keys/                     the key files themselves
//   bad-keys.jsonl            texts Mysten's readers reject or accept
//   mysten-validator-<i>.yaml validator configs from ConfigBuilder (as `sui genesis` saves them)
//   mysten-validator.jsonl    the values deepwave must read from them
//   zui-yaml.jsonl            (with ZUI_YAML_DIR) NodeConfig parse results of deepwave's yaml files
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::traits::{EncodeDecodeBase64, KeyPair, ToFromBytes};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::fmt::Write as _;
use std::net::ToSocketAddrs;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use sui_config::node::{Genesis, NodeConfig};
use sui_keys::keypair_file::{
    read_authority_keypair_from_file, read_keypair_from_file, read_network_keypair_from_file,
    write_authority_keypair_to_file, write_keypair_to_file,
};
use sui_swarm_config::network_config_builder::ConfigBuilder;
use sui_types::base_types::SuiAddress;
use sui_types::crypto::{
    AuthorityKeyPair, NetworkKeyPair, SuiKeyPair, generate_proof_of_possession,
    get_key_pair_from_rng,
};

fn hex(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        write!(s, "{:02x}", x).unwrap();
    }
    s
}

fn out_dir() -> PathBuf {
    PathBuf::from(std::env::var("ZUI_COMPAT_OUT").expect("set ZUI_COMPAT_OUT"))
}

#[test]
fn zui_compat_keys() {
    let out = out_dir();
    std::fs::create_dir_all(out.join("keys")).unwrap();
    let mut lines = String::new();
    for i in 0u8..8 {
        let mut rng = StdRng::from_seed([i; 32]);
        let (_, bls): (_, AuthorityKeyPair) = get_key_pair_from_rng(&mut rng);
        let (_, ed): (_, NetworkKeyPair) = get_key_pair_from_rng(&mut rng);
        let (_, acct): (_, NetworkKeyPair) = get_key_pair_from_rng(&mut rng);
        let (_, k1): (_, fastcrypto::secp256k1::Secp256k1KeyPair) =
            get_key_pair_from_rng(&mut rng);
        let a_path = out.join(format!("keys/authority-{i}.key"));
        let e_path = out.join(format!("keys/ed25519-{i}.key"));
        let k_path = out.join(format!("keys/secp256k1-{i}.key"));
        write_authority_keypair_to_file(&bls, &a_path).unwrap();
        let ed_kp = SuiKeyPair::Ed25519(ed.copy());
        write_keypair_to_file(&ed_kp, &e_path).unwrap();
        let k1_kp = SuiKeyPair::Secp256k1(k1);
        write_keypair_to_file(&k1_kp, &k_path).unwrap();
        // Mysten's readers accept what its writers wrote
        assert_eq!(read_authority_keypair_from_file(&a_path).unwrap().public(), bls.public());
        assert_eq!(read_network_keypair_from_file(&e_path).unwrap().public(), ed.public());
        assert!(read_keypair_from_file(&k_path).is_ok());
        assert!(read_network_keypair_from_file(&k_path).is_err());
        let addr = SuiAddress::from(acct.public());
        let pop = generate_proof_of_possession(&bls, addr);
        let pop_bytes: &[u8] = pop.as_ref();
        writeln!(
            lines,
            "{{\"seed\":{i},\"authority_file\":\"{}\",\"authority_pk\":\"{}\",\"ed25519_file\":\"{}\",\"ed25519_pk\":\"{}\",\"ed25519_bech32\":\"{}\",\"secp256k1_file\":\"{}\",\"account_pk\":\"{}\",\"account_address\":\"{}\",\"pop\":\"{}\"}}",
            std::fs::read_to_string(&a_path).unwrap(),
            hex(bls.public().as_bytes()),
            std::fs::read_to_string(&e_path).unwrap(),
            hex(ed.public().as_bytes()),
            ed_kp.encode().unwrap(),
            std::fs::read_to_string(&k_path).unwrap(),
            hex(acct.public().as_bytes()),
            hex(addr.as_ref()),
            hex(pop_bytes),
        )
        .unwrap();
    }
    std::fs::write(out.join("keys.jsonl"), &lines).unwrap();

    // texts the readers accept or reject (trimmed, as read_*_from_file trims)
    let mut bad = String::new();
    let cases: Vec<(&str, String)> = vec![
        ("bls_scalar_ff", Base64::encode([0xffu8; 32])),
        ("bls_scalar_zero", Base64::encode([0u8; 32])),
        ("bls_31_bytes", Base64::encode([1u8; 31])),
        ("bls_with_flag", Base64::encode({
            let mut v = vec![0u8];
            v.extend_from_slice(&[1u8; 32]);
            v
        })),
        ("ed_no_flag", Base64::encode([1u8; 32])),
        ("ed_flag_9", Base64::encode({
            let mut v = vec![9u8];
            v.extend_from_slice(&[1u8; 32]);
            v
        })),
        ("ed_trailing_newline", format!("{}\n", Base64::encode({
            let mut v = vec![0u8];
            v.extend_from_slice(&[1u8; 32]);
            v
        }))),
    ];
    for (name, text) in cases {
        let p = out.join(format!("keys/case-{name}.key"));
        std::fs::write(&p, &text).unwrap();
        let bls_ok = read_authority_keypair_from_file(&p).is_ok();
        let sui_ok = read_keypair_from_file(&p).is_ok();
        let net_ok = read_network_keypair_from_file(&p).is_ok();
        let _ = AuthorityKeyPair::decode_base64(text.trim());
        writeln!(
            bad,
            "{{\"name\":\"{name}\",\"text\":\"{}\",\"authority_ok\":{bls_ok},\"suikeypair_ok\":{sui_ok},\"network_ok\":{net_ok}}}",
            text.trim()
        )
        .unwrap();
    }
    std::fs::write(out.join("bad-keys.jsonl"), &bad).unwrap();
}

#[test]
fn zui_compat_yaml() {
    let out = out_dir();
    std::fs::create_dir_all(&out).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mut nc = ConfigBuilder::new(tmp.path())
        .committee_size(NonZeroUsize::new(4).unwrap())
        .rng(StdRng::from_seed([0; 32]))
        .build();
    let mut facts = String::new();
    for (i, v) in nc.validator_configs.iter_mut().enumerate() {
        // what `sui genesis` saves (sui_commands.rs: Genesis::new_from_file)
        v.genesis = Genesis::new_from_file("/opt/sui/config/genesis.blob");
        let text = serde_yaml::to_string(&*v).unwrap();
        std::fs::write(out.join(format!("mysten-validator-{i}.yaml")), &text).unwrap();
        // round trip through Mysten's serde
        let back: NodeConfig = serde_yaml::from_str(&text).unwrap();
        let cc = back.consensus_config.as_ref().unwrap();
        writeln!(
            facts,
            "{{\"i\":{i},\"db_path\":\"{}\",\"network_address\":\"{}\",\"metrics_address\":\"{}\",\"admin_interface_port\":{},\"p2p_listen\":\"{}\",\"p2p_external\":\"{}\",\"seed_peers\":{},\"consensus_db\":\"{}\",\"authority_pk\":\"{}\",\"worker_pk\":\"{}\",\"network_pk\":\"{}\",\"jwk_fetch_interval_seconds\":{},\"max_txn_age_in_queue_ms\":{}}}",
            back.db_path.display(),
            back.network_address,
            back.metrics_address,
            back.admin_interface_port,
            back.p2p_config.listen_address,
            back.p2p_config.external_address.as_ref().map(|a| a.to_string()).unwrap_or_default(),
            back.p2p_config.seed_peers.len(),
            cc.db_path.display(),
            hex(back.protocol_key_pair().public().as_bytes()),
            hex(back.worker_key_pair().public().as_bytes()),
            hex(back.network_key_pair().public().as_bytes()),
            back.jwk_fetch_interval_seconds,
            back.authority_overload_config.max_txn_age_in_queue.as_millis(),
        )
        .unwrap();
    }
    std::fs::write(out.join("mysten-validator.jsonl"), &facts).unwrap();

    // zui-written validator yaml files must load with NodeConfig's serde
    if let Ok(dir) = std::env::var("ZUI_YAML_DIR") {
        let mut res = String::new();
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "yaml").unwrap_or(false))
            .collect();
        names.sort();
        assert!(!names.is_empty(), "no yaml in {dir}");
        for p in names {
            let text = std::fs::read_to_string(&p).unwrap();
            let parsed: Result<NodeConfig, _> = serde_yaml::from_str(&text);
            match parsed {
                Ok(c) => {
                    let net_bind = c.network_address.to_socket_addrs().is_ok();
                    let cc = c.consensus_config.as_ref();
                    let cons_listen = cc
                        .and_then(|cc| cc.listen_address.as_ref())
                        .map(|a| a.to_socket_addrs().is_ok())
                        .unwrap_or(true);
                    let seeds_ok = c
                        .p2p_config
                        .seed_peers
                        .iter()
                        .all(|s| s.address.to_anemo_address().is_ok());
                    writeln!(
                        res,
                        "{{\"file\":\"{}\",\"ok\":true,\"network_bind\":{net_bind},\"consensus_listen\":{cons_listen},\"seed_peers\":{},\"seed_peers_anemo\":{seeds_ok},\"db_path\":\"{}\"}}",
                        p.display(),
                        c.p2p_config.seed_peers.len(),
                        c.db_path.display()
                    )
                    .unwrap();
                    assert!(net_bind && cons_listen && seeds_ok, "{}", p.display());
                }
                Err(e) => {
                    writeln!(
                        res,
                        "{{\"file\":\"{}\",\"ok\":false,\"error\":{:?}}}",
                        p.display(),
                        e.to_string()
                    )
                    .unwrap();
                }
            }
        }
        std::fs::write(out.join("zui-yaml.jsonl"), &res).unwrap();
        assert!(!res.contains("\"ok\":false"), "{res}");
    }
}

// The generator of tools/truth/validator-epoch/src/main.rs, run inside the sui workspace (same
// lockfile, shared build). Writes the files `deepwave-validator vectors-check DIR` reads into
// ZUI_COMPAT_OUT/validator-epoch.
mod valepoch {
    use super::hex;
    use std::fmt::Write as _;
    use std::path::Path;
    use sui_protocol_config::{Chain, ProtocolVersion};
    use sui_types::{
        base_types::{ObjectID, SequenceNumber},
        crypto::AuthorityPublicKeyBytes,
        digests::TransactionDigest,
        messages_checkpoint::{CheckpointRequest, CheckpointRequestV2},
        messages_consensus::{
            AuthorityCapabilitiesV2, ConsensusTransaction, ConsensusTransactionKind,
        },
        messages_grpc::{
            LayoutGenerationOption, ObjectInfoRequest, RawValidatorHealthResponse,
            TransactionInfoRequest,
        },
        supported_protocol_versions::{
            SupportedProtocolVersions, SupportedProtocolVersionsWithHashes,
        },
        transaction::{EndOfEpochTransactionKind, VerifiedTransaction},
    };

    fn name_of(b: u8) -> AuthorityPublicKeyBytes {
        AuthorityPublicKeyBytes::new([b; 96])
    }

    pub fn dump(out: &Path) {
        std::fs::create_dir_all(out).unwrap();
        let mut text = String::new();
        for (chain, name) in [
            (Chain::Unknown, "unknown"),
            (Chain::Mainnet, "mainnet"),
            (Chain::Testnet, "testnet"),
        ] {
            for v in 1..=141u64 {
                let s = SupportedProtocolVersionsWithHashes::from_supported_versions(
                    SupportedProtocolVersions::new_for_testing(v, v),
                    chain,
                );
                let d = s.get_version_digest(ProtocolVersion::new(v)).unwrap();
                writeln!(text, "{name} {v} {}", hex(&d.into_inner())).unwrap();
            }
        }
        std::fs::write(out.join("protocol-digests.txt"), text).unwrap();

        let mut sys = String::new();
        let basic = vec![
            EndOfEpochTransactionKind::new_authenticator_state_expire(
                100,
                SequenceNumber::from_u64(7),
            ),
            EndOfEpochTransactionKind::new_randomness_state_create(),
            EndOfEpochTransactionKind::new_deny_list_state_create(),
            EndOfEpochTransactionKind::new_accumulator_root_create(),
            EndOfEpochTransactionKind::new_coin_registry_create(),
            EndOfEpochTransactionKind::new_display_registry_create(),
            EndOfEpochTransactionKind::new_address_alias_state_create(),
            EndOfEpochTransactionKind::new_change_epoch(
                801,
                ProtocolVersion::new(141),
                6,
                5,
                7,
                8,
                1_700_000_000_000,
                vec![],
            ),
        ];
        let tx = VerifiedTransaction::new_end_of_epoch_transaction(basic);
        writeln!(
            sys,
            "{{\"name\":\"eoe-basic\",\"sender_signed_data\":\"{}\",\"digest\":\"{}\"}}",
            hex(&bcs::to_bytes(tx.data()).unwrap()),
            hex(tx.digest().inner())
        )
        .unwrap();
        let legacy =
            VerifiedTransaction::new_change_epoch(801, ProtocolVersion::new(5), 2, 1, 3, 4, 99, vec![]);
        writeln!(
            sys,
            "{{\"name\":\"change-epoch-legacy\",\"sender_signed_data\":\"{}\",\"digest\":\"{}\"}}",
            hex(&bcs::to_bytes(legacy.data()).unwrap()),
            hex(legacy.digest().inner())
        )
        .unwrap();
        std::fs::write(out.join("sys-tx.jsonl"), sys).unwrap();

        let mut ctx = String::new();
        let mut eop = ConsensusTransaction::new_end_of_publish(name_of(7));
        eop.tracking_id = [2; 8];
        writeln!(ctx, "{{\"name\":\"eop\",\"bcs\":\"{}\"}}", hex(&bcs::to_bytes(&eop).unwrap()))
            .unwrap();
        let caps = AuthorityCapabilitiesV2 {
            authority: name_of(7),
            generation: 5000,
            supported_protocol_versions:
                SupportedProtocolVersionsWithHashes::from_supported_versions(
                    SupportedProtocolVersions::new_for_testing(139, 141),
                    Chain::Unknown,
                ),
            available_system_packages: vec![],
        };
        let tx = ConsensusTransaction {
            tracking_id: [1; 8],
            kind: ConsensusTransactionKind::CapabilityNotificationV2(caps),
        };
        writeln!(ctx, "{{\"name\":\"caps\",\"bcs\":\"{}\"}}", hex(&bcs::to_bytes(&tx).unwrap()))
            .unwrap();
        std::fs::write(out.join("consensus-tx.jsonl"), ctx).unwrap();

        let mut g = String::new();
        let id = ObjectID::from_bytes([1u8; 32]).unwrap();
        let latest = ObjectInfoRequest::latest_object_info_request(id, LayoutGenerationOption::None);
        writeln!(g, "{{\"name\":\"object-info-latest\",\"bcs\":\"{}\"}}", hex(&bcs::to_bytes(&latest).unwrap())).unwrap();
        let past = ObjectInfoRequest::past_object_info_debug_request(
            id,
            SequenceNumber::from_u64(9),
            LayoutGenerationOption::Generate,
        );
        writeln!(g, "{{\"name\":\"object-info-past\",\"bcs\":\"{}\"}}", hex(&bcs::to_bytes(&past).unwrap())).unwrap();
        let ti = TransactionInfoRequest {
            transaction_digest: TransactionDigest::new([7u8; 32]),
        };
        writeln!(g, "{{\"name\":\"tx-info\",\"bcs\":\"{}\"}}", hex(&bcs::to_bytes(&ti).unwrap())).unwrap();
        let cp = CheckpointRequest {
            sequence_number: Some(5),
            request_content: true,
        };
        writeln!(g, "{{\"name\":\"checkpoint\",\"bcs\":\"{}\"}}", hex(&bcs::to_bytes(&cp).unwrap())).unwrap();
        let cp2 = CheckpointRequestV2 {
            sequence_number: None,
            request_content: false,
            certified: true,
        };
        writeln!(g, "{{\"name\":\"checkpoint-v2\",\"bcs\":\"{}\"}}", hex(&bcs::to_bytes(&cp2).unwrap())).unwrap();
        let health = RawValidatorHealthResponse {
            pending_certificates: Some(0),
            inflight_consensus_messages: Some(3),
            consensus_round: Some(4),
            checkpoint_sequence: Some(5),
        };
        writeln!(g, "{{\"name\":\"health\",\"bcs\":\"{}\"}}", hex(&prost::Message::encode_to_vec(&health))).unwrap();
        std::fs::write(out.join("grpc-req.jsonl"), g).unwrap();
    }
}

#[test]
fn zui_compat_valepoch() {
    valepoch::dump(&out_dir().join("validator-epoch"));
}
