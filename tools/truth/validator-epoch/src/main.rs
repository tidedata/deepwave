//! zui-valepoch-truth: ground truth for the val-epoch-api-keys lane (see README.md).
//! Sources at mainnet-v1.83.1:
//!   sui-types/src/supported_protocol_versions.rs   protocol config digest, versions with hashes
//!   sui-types/src/messages_consensus.rs            ConsensusTransaction, AuthorityCapabilitiesV2
//!   sui-types/src/transaction.rs                   VerifiedTransaction::new_end_of_epoch_transaction
//!   sui-types/src/messages_grpc.rs                 Validator API request and response types
//!   sui-types/src/messages_checkpoint.rs           CheckpointRequest(V2)
use std::{fs, path::PathBuf};

use anyhow::{Result, bail};
use serde_json::json;
use sui_protocol_config::{Chain, ProtocolVersion};
use sui_types::{
    base_types::{ObjectID, SequenceNumber},
    crypto::AuthorityPublicKeyBytes,
    digests::TransactionDigest,
    messages_checkpoint::{CheckpointRequest, CheckpointRequestV2},
    messages_consensus::{AuthorityCapabilitiesV2, ConsensusTransaction, ConsensusTransactionKind},
    messages_grpc::{
        LayoutGenerationOption, ObjectInfoRequest, RawValidatorHealthResponse, TransactionInfoRequest,
    },
    supported_protocol_versions::{SupportedProtocolVersions, SupportedProtocolVersionsWithHashes},
    transaction::{EndOfEpochTransactionKind, VerifiedTransaction},
};

fn chains() -> [(Chain, &'static str); 3] {
    [(Chain::Unknown, "unknown"), (Chain::Mainnet, "mainnet"), (Chain::Testnet, "testnet")]
}

fn protocol_digests(out: &PathBuf) -> Result<()> {
    let mut text = String::new();
    for (chain, name) in chains() {
        for v in 1..=141u64 {
            let s = SupportedProtocolVersionsWithHashes::from_supported_versions(
                SupportedProtocolVersions::new_for_testing(v, v),
                chain,
            );
            let d = s.get_version_digest(ProtocolVersion::new(v)).expect("version present");
            text.push_str(&format!("{name} {v} {}\n", hex::encode(d.into_inner())));
        }
    }
    fs::write(out.join("protocol-digests.txt"), text)?;
    Ok(())
}

fn sys_tx(out: &PathBuf) -> Result<()> {
    let mut lines = Vec::new();
    // Keep in step with src/validator/epoch/vectors.zig.
    let basic = vec![
        EndOfEpochTransactionKind::new_authenticator_state_expire(100, SequenceNumber::from_u64(7)),
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
    lines.push(json!({
        "name": "eoe-basic",
        "sender_signed_data": hex::encode(bcs::to_bytes(tx.data())?),
        "digest": hex::encode(tx.digest().inner()),
    }));
    let legacy = VerifiedTransaction::new_change_epoch(801, ProtocolVersion::new(5), 2, 1, 3, 4, 99, vec![]);
    lines.push(json!({
        "name": "change-epoch-legacy",
        "sender_signed_data": hex::encode(bcs::to_bytes(legacy.data())?),
        "digest": hex::encode(legacy.digest().inner()),
    }));
    write_lines(out, "sys-tx.jsonl", lines)
}

fn name_of(b: u8) -> AuthorityPublicKeyBytes {
    AuthorityPublicKeyBytes::new([b; 96])
}

fn consensus_tx(out: &PathBuf) -> Result<()> {
    let mut lines = Vec::new();
    let mut eop = ConsensusTransaction::new_end_of_publish(name_of(7));
    eop.tracking_id = [2; 8];
    lines.push(json!({"name": "eop", "bcs": hex::encode(bcs::to_bytes(&eop)?)}));
    let caps = AuthorityCapabilitiesV2 {
        authority: name_of(7),
        generation: 5000,
        supported_protocol_versions: SupportedProtocolVersionsWithHashes::from_supported_versions(
            SupportedProtocolVersions::new_for_testing(139, 141),
            Chain::Unknown,
        ),
        available_system_packages: vec![],
    };
    let tx = ConsensusTransaction {
        tracking_id: [1; 8],
        kind: ConsensusTransactionKind::CapabilityNotificationV2(caps),
    };
    lines.push(json!({"name": "caps", "bcs": hex::encode(bcs::to_bytes(&tx)?)}));
    write_lines(out, "consensus-tx.jsonl", lines)
}

fn grpc_req(out: &PathBuf) -> Result<()> {
    let mut lines = Vec::new();
    let id = ObjectID::from_bytes([1u8; 32])?;
    let latest = ObjectInfoRequest::latest_object_info_request(id, LayoutGenerationOption::None);
    lines.push(json!({"name": "object-info-latest", "bcs": hex::encode(bcs::to_bytes(&latest)?)}));
    let past = ObjectInfoRequest::past_object_info_debug_request(id, SequenceNumber::from_u64(9), LayoutGenerationOption::Generate);
    lines.push(json!({"name": "object-info-past", "bcs": hex::encode(bcs::to_bytes(&past)?)}));
    let ti = TransactionInfoRequest { transaction_digest: TransactionDigest::new([7u8; 32]) };
    lines.push(json!({"name": "tx-info", "bcs": hex::encode(bcs::to_bytes(&ti)?)}));
    let cp = CheckpointRequest { sequence_number: Some(5), request_content: true };
    lines.push(json!({"name": "checkpoint", "bcs": hex::encode(bcs::to_bytes(&cp)?)}));
    let cp2 = CheckpointRequestV2 { sequence_number: None, request_content: false, certified: true };
    lines.push(json!({"name": "checkpoint-v2", "bcs": hex::encode(bcs::to_bytes(&cp2)?)}));
    let health = RawValidatorHealthResponse {
        pending_certificates: Some(0),
        inflight_consensus_messages: Some(3),
        consensus_round: Some(4),
        checkpoint_sequence: Some(5),
    };
    lines.push(json!({"name": "health", "bcs": hex::encode(prost::Message::encode_to_vec(&health))}));
    write_lines(out, "grpc-req.jsonl", lines)
}

fn write_lines(out: &PathBuf, name: &str, lines: Vec<serde_json::Value>) -> Result<()> {
    let mut text = String::new();
    for l in lines {
        text.push_str(&serde_json::to_string(&l)?);
        text.push('\n');
    }
    fs::write(out.join(name), text)?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 || args[1] != "dump" {
        bail!("usage: zui-valepoch-truth dump OUT_DIR");
    }
    let out = PathBuf::from(&args[2]);
    fs::create_dir_all(&out)?;
    protocol_digests(&out)?;
    sys_tx(&out)?;
    consensus_tx(&out)?;
    grpc_req(&out)?;
    println!("wrote {}", out.display());
    Ok(())
}
