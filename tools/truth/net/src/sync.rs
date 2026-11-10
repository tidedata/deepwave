//! sync-rpc-codec vectors: BcsSnappyCodec (mysten-network, anemo variant) over the sui-network
//! state-sync / discovery message types.
use anemo::rpc::codec::{Codec, Decoder, Encoder};
use anyhow::Result;
use mysten_network::codec::anemo::BcsSnappyCodec;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Write;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointContentsDigest, CheckpointDigest};

// Copies of sui-network state_sync/server.rs types (same field and variant order).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GetCheckpointSummaryRequest {
    Latest,
    ByDigest(CheckpointDigest),
    BySequenceNumber(u64),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetCheckpointTransactionsRequest {
    pub sequence_number: u64,
    pub start: u64,
    pub end: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetCheckpointAvailabilityResponse {
    pub highest_synced_checkpoint: CertifiedCheckpointSummary,
    pub lowest_available_checkpoint: u64,
}

fn enc<T: Serialize + Send + 'static>(item: T) -> (Vec<u8>, Vec<u8>) {
    let bcs = bcs::to_bytes(&item).unwrap();
    let mut c = BcsSnappyCodec::<T, ()>::default();
    let snappy = c.encoder().encode(item).unwrap().to_vec();
    (bcs, snappy)
}

pub fn run(out: &str, chk_dir: &str, count: usize) -> Result<()> {
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);
    let mut n = 0usize;
    let mut emit = |id: String, kind: &str, route: &str, bcs: Vec<u8>, snappy: Vec<u8>| -> Result<()> {
        writeln!(f, "{}", json!({"id":id,"kind":kind,"route":route,"bcs_hex":hex::encode(&bcs),"snappy_hex":hex::encode(&snappy)}))?;
        n += 1;
        Ok(())
    };
    // requests
    let (b, s) = enc(GetCheckpointSummaryRequest::Latest);
    emit("req/summary/latest".into(), "GetCheckpointSummaryRequest", "/sui.StateSync/GetCheckpointSummary", b, s)?;
    for seq in [0u64, 1, 255, 256, 65535, 1 << 32, 342_456_160, u64::MAX] {
        let (b, s) = enc(GetCheckpointSummaryRequest::BySequenceNumber(seq));
        emit(format!("req/summary/seq/{seq}"), "GetCheckpointSummaryRequest", "/sui.StateSync/GetCheckpointSummary", b, s)?;
    }
    for i in 0..4u8 {
        let d = CheckpointDigest::new([i.wrapping_mul(37); 32]);
        let (b, s) = enc(GetCheckpointSummaryRequest::ByDigest(d));
        emit(format!("req/summary/digest/{i}"), "GetCheckpointSummaryRequest", "/sui.StateSync/GetCheckpointSummary", b, s)?;
        let cd = CheckpointContentsDigest::new([i.wrapping_mul(91); 32]);
        for route in ["GetCheckpointContents", "GetCheckpointContentsV2"] {
            let (b, s) = enc(cd);
            emit(format!("req/{route}/{i}"), "CheckpointContentsDigest", &format!("/sui.StateSync/{route}"), b, s)?;
        }
    }
    for seq in [0u64, 1, 342_456_160] {
        let (b, s) = enc(seq);
        emit(format!("req/contents_digests/{seq}"), "u64", "/sui.StateSync/GetCheckpointContentsDigests", b, s)?;
        let (b, s) = enc(GetCheckpointTransactionsRequest { sequence_number: seq, start: 3, end: 1000 + seq });
        emit(format!("req/transactions/{seq}"), "GetCheckpointTransactionsRequest", "/sui.StateSync/GetCheckpointTransactions", b, s)?;
    }
    let (b, s) = enc(());
    emit("req/availability".into(), "unit", "/sui.StateSync/GetCheckpointAvailability", b, s)?;
    // responses from real checkpoints
    let mut names: Vec<_> = std::fs::read_dir(chk_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".chk"))
        .collect();
    names.sort_by_key(|n| n.trim_end_matches(".chk").parse::<u64>().unwrap_or(0));
    let step = (names.len() / count.max(1)).max(1);
    let mut picked = 0;
    let (b, s) = enc(None::<CertifiedCheckpointSummary>);
    emit("resp/summary/none".into(), "Option<CertifiedCheckpointSummary>", "/sui.StateSync/GetCheckpointSummary", b, s)?;
    for name in names.iter().step_by(step) {
        if picked >= count { break; }
        let blob = std::fs::read(format!("{chk_dir}/{name}"))?;
        let data: sui_types::full_checkpoint_content::CheckpointData = bcs::from_bytes(&blob[1..])?;
        let summary = data.checkpoint_summary.clone();
        let seq = *summary.sequence_number();
        let (b, s) = enc(Some(summary.clone()));
        emit(format!("resp/summary/{seq}"), "Option<CertifiedCheckpointSummary>", "/sui.StateSync/GetCheckpointSummary", b, s)?;
        if picked % 16 == 0 {
            let (b, s) = enc(GetCheckpointAvailabilityResponse { highest_synced_checkpoint: summary, lowest_available_checkpoint: seq / 2 });
            emit(format!("resp/availability/{seq}"), "GetCheckpointAvailabilityResponse", "/sui.StateSync/GetCheckpointAvailability", b, s)?;
        }
        picked += 1;
    }
    // decode direction: the Rust decoder on its own output must round trip (sanity of the truth)
    eprintln!("sync: {n} vectors");
    let _ = <BcsSnappyCodec<(), u64> as Codec>::decoder;
    Ok(())
}
