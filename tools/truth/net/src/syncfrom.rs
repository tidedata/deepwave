//! `sync-from`: an independent state-sync client that behaves like sui-node 1.83.1 and proves a
//! peer's answers byte-equal to Mysten's public checkpoint bucket.
//!
//! Everything on the wire is Mysten's code: an anemo `Network` with sui-node's QUIC settings
//! (sui-node/src/lib.rs `create_p2p_network`), sui-network's anemo-build generated
//! `StateSyncClient` / `DiscoveryClient` (route names, BcsSnappyCodec, request and response types),
//! sui-storage's archive fetch (`fetch_checkpoint`, the `{seq}.binpb.zst` proto path sui-node's
//! archive fallback uses) and its `verify_checkpoint_with_committee` (the exact summary check
//! state sync runs: previous_digest link, epoch step, BLS quorum over the epoch's committee).
//! Contents are checked with `VersionedFullCheckpointContents::verify_digests` (contents digest ==
//! summary content_digest, every effects.transaction_digest == transaction digest) and the paged
//! pair with sui-node's own page checks (contents digest, per-item `ExecutionData::digests`).
//!
//! The expected bytes are built from the bucket exactly as sui-node's archive path builds them
//! (state_sync/worker.rs `process_archive_checkpoint`): `from_contents_and_execution_data` over
//! `Transaction::from_generic_sig_data`. Every response is compared as BCS bytes.
//!
//!   zui-net-truth sync-from --peer HOST:PORT --peer-id HEX [--server-name sui-35834a8a]
//!       --from N --to M [--concurrency 32] [--bucket URL] [--out results.json]
//!       [--sample K] [--key HEX] [--timeout-s S] [--no-discovery] [--no-signatures] [--strict]
//!
//! Two parts of an answer are not canonical across honest nodes, so they are compared in a
//! normal form unless --strict: a certified summary's aggregate signature (summary bytes must be
//! equal; the certificate must carry a quorum) and the order of a transaction's own signature list
//! (must be the contents' user signatures as a multiset). Both are counted in the report
//! (`cert_bytes_differ`, `sig_order_normalized`); both showed up against Mysten's own sui-node
//! 1.83.1 seed (ewr-00) on 2026-11-08, so a byte-for-byte bucket match there is not the truth.
//!   zui-net-truth serve-probe --peer HOST:PORT --peer-id HEX [--server-name S]
//!       [--interval-s 5] [--count N] [--key HEX]
use anemo::{Network, PeerId, Request, Router};
use anyhow::{Context, Result, anyhow, bail};
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey};
use fastcrypto::traits::{KeyPair, ToFromBytes, VerifyingKey};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sui_network::discovery::{
    DiscoveryClient, GetKnownPeersRequestV3, NodeInfoV2, SignedNodeInfo, SignedVersionedNodeInfo, VersionedNodeInfo,
};
use sui_network::endpoint_manager::EndpointId;
use sui_network::state_sync::{GetCheckpointSummaryRequest, GetCheckpointTransactionsRequest, StateSyncClient};
use sui_storage::object_store::util::{build_object_store, end_of_epoch_data, fetch_checkpoint};
use sui_types::base_types::ExecutionData;
use sui_types::committee::Committee;
use sui_types::full_checkpoint_content::Checkpoint;
use sui_types::signature::GenericSignature;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointDigest, VerifiedCheckpoint, VersionedFullCheckpointContents,
};
use sui_types::transaction::Transaction;

/// Mainnet genesis checkpoint digest (sui-node compares the peer's checkpoint 0 to its own).
pub const MAINNET_GENESIS: &str = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S";

/// sui-network discovery limits (discovery/mod.rs).
const MAX_ADDRESS_LENGTH: usize = 300;
const MAX_ADDRESSES_PER_PEER: usize = 2;

/// sui-node 1.83.1's anemo config (sui-node/src/lib.rs `create_p2p_network`, defaults applied).
pub fn sui_node_anemo_config() -> anemo::Config {
    let mut cfg = anemo::Config::default();
    cfg.max_request_frame_size = Some(1 << 20);
    cfg.max_response_frame_size = Some(128 << 20);
    let mut q = anemo::QuicConfig::default();
    q.socket_send_buffer_size = Some(20 << 20);
    q.socket_receive_buffer_size = Some(20 << 20);
    q.allow_failed_socket_buffer_size_setting = true;
    q.max_concurrent_bidi_streams = Some(500);
    q.max_concurrent_uni_streams = Some(500);
    q.stream_receive_window = Some(100 << 20);
    q.receive_window = Some(200 << 20);
    q.send_window = Some(200 << 20);
    q.crypto_buffer_size = Some(1 << 20);
    q.max_idle_timeout_ms = Some(10_000);
    q.keep_alive_interval_ms = Some(5_000);
    cfg.quic = Some(q);
    cfg
}

/// Field copy of sui-network's `GetCheckpointAvailabilityResponse` (its fields are pub(crate));
/// the response is re-encoded with BCS and decoded into this, so the bytes are the same.
#[derive(Serialize, Deserialize)]
struct Availability {
    highest_synced_checkpoint: CertifiedCheckpointSummary,
    lowest_available_checkpoint: u64,
}

struct Args {
    peer: String,
    peer_id: PeerId,
    server_name: String,
    from: u64,
    to: u64,
    from_s: String,
    to_s: String,
    concurrency: usize,
    bucket: String,
    out: Option<String>,
    sample: u64,
    key: [u8; 32],
    timeout: Duration,
    discovery: bool,
    signatures: bool,
    strict: bool,
    interval: Duration,
    count: u64,
}

fn parse(args: &[String]) -> Result<Args> {
    let mut a = Args {
        peer: String::new(),
        peer_id: PeerId([0; 32]),
        server_name: "sui-35834a8a".into(),
        from: 0,
        to: 0,
        from_s: "0".into(),
        to_s: "0".into(),
        concurrency: 32,
        bucket: "https://checkpoints.mainnet.sui.io".into(),
        out: None,
        sample: 50,
        key: random_key(),
        timeout: Duration::from_secs(60),
        discovery: true,
        signatures: true,
        strict: false,
        interval: Duration::from_secs(5),
        count: u64::MAX,
    };
    let mut have_pid = false;
    let mut i = 0;
    while i < args.len() {
        let v = || args.get(i + 1).cloned().ok_or_else(|| anyhow!("{} needs a value", args[i]));
        match args[i].as_str() {
            "--peer" => a.peer = v()?,
            "--peer-id" => {
                a.peer_id = PeerId(hex::decode(v()?.trim_start_matches("0x"))?.try_into().map_err(|_| anyhow!("peer id is 32 bytes"))?);
                have_pid = true;
            }
            "--server-name" => a.server_name = v()?,
            "--from" => a.from_s = v()?,
            "--to" => a.to_s = v()?,
            "--concurrency" => a.concurrency = v()?.parse()?,
            "--bucket" => a.bucket = v()?,
            "--out" => a.out = Some(v()?),
            "--sample" => a.sample = v()?.parse::<u64>()?.max(1),
            "--key" => a.key = hex::decode(v()?)?.try_into().map_err(|_| anyhow!("key is 32 bytes"))?,
            "--timeout-s" => a.timeout = Duration::from_secs(v()?.parse()?),
            "--interval-s" => a.interval = Duration::from_secs_f64(v()?.parse()?),
            "--count" => a.count = v()?.parse()?,
            "--no-discovery" => { a.discovery = false; i += 1; continue; }
            "--no-signatures" => { a.signatures = false; i += 1; continue; }
            "--strict" => { a.strict = true; i += 1; continue; }
            x => bail!("unknown arg {x}"),
        }
        i += 2;
    }
    if a.peer.is_empty() || !have_pid {
        bail!("--peer HOST:PORT and --peer-id HEX are required");
    }
    Ok(a)
}

fn random_key() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    Sha256::digest(format!("zui-net-truth {t} {}", std::process::id())).into()
}

async fn dial(a: &Args) -> Result<(Network, anemo::Peer, Duration)> {
    // A client-only node: every inbound request (deepwave calling back) is answered 404 by the empty router.
    let network = Network::bind("0.0.0.0:0")
        .server_name(&a.server_name)
        .private_key(a.key)
        .config(sui_node_anemo_config())
        .start(Router::new())?;
    let t = Instant::now();
    let pid = network
        .connect_with_peer_id(a.peer.clone(), a.peer_id)
        .await
        .with_context(|| format!("anemo dial {} (expected peer id {})", a.peer, hex::encode(a.peer_id.0)))?;
    let took = t.elapsed();
    if pid != a.peer_id {
        bail!("connected peer id {} != expected {}", hex::encode(pid.0), hex::encode(a.peer_id.0));
    }
    let peer = network.peer(pid).ok_or_else(|| anyhow!("connected but no peer handle"))?;
    Ok((network, peer, took))
}

// ---- statistics ----

#[derive(Default)]
struct Stats {
    lat: HashMap<&'static str, Vec<u64>>, // micros
    errors: HashMap<&'static str, u64>,
    bytes: u64,
    /// Answers equal only up to the order of a transaction's own signatures (see `canon_exec`).
    sig_order: u64,
    /// Certified summaries whose summary bytes are equal but whose aggregate signature (signer
    /// bitmap and BLS aggregate) differs from the bucket's: both are checked for a quorum.
    cert_differs: u64,
    strict: bool,
    diffs: Vec<serde_json::Value>,
    mismatched: u64,
    missing: u64,
    equal: u64,
    bucket_missing: u64,
    verify_failures: u64,
}

impl Stats {
    fn diff(&mut self, v: serde_json::Value) {
        if self.diffs.len() < 20 {
            self.diffs.push(v);
        }
    }
}

type Shared = Arc<Mutex<Stats>>;

fn first_diff(a: &[u8], b: &[u8]) -> serde_json::Value {
    let off = a.iter().zip(b).position(|(x, y)| x != y).unwrap_or(a.len().min(b.len()));
    let w = |s: &[u8]| hex::encode(&s[off.min(s.len())..(off + 32).min(s.len())]);
    json!({"offset": off, "got_len": a.len(), "want_len": b.len(), "got_hex": w(a), "want_hex": w(b)})
}

async fn timed<T, F: std::future::Future<Output = Result<anemo::Response<T>, anemo::rpc::Status>>>(
    st: &Shared,
    route: &'static str,
    f: F,
) -> Result<T, String> {
    let t = Instant::now();
    let r = f.await;
    let us = t.elapsed().as_micros() as u64;
    let mut s = st.lock().unwrap();
    s.lat.entry(route).or_default().push(us);
    match r {
        Ok(r) => Ok(r.into_inner()),
        Err(e) => {
            *s.errors.entry(route).or_default() += 1;
            Err(format!("{e:?}"))
        }
    }
}

fn pct(v: &mut [u64], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_unstable();
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i] as f64 / 1000.0
}

/// Expected full contents, built like sui-node's archive path (state_sync/worker.rs).
fn expected_full(cp: &Checkpoint) -> VersionedFullCheckpointContents {
    VersionedFullCheckpointContents::from_contents_and_execution_data(
        cp.contents.clone(),
        cp.transactions.iter().map(|t| ExecutionData {
            transaction: Transaction::from_generic_sig_data(t.transaction.clone(), t.signatures.clone()),
            effects: t.effects.clone(),
        }),
    )
}

/// Compares two values as BCS; returns true when equal, records the diff otherwise.
/// Certified summary: the summary bytes must be equal. The aggregate signature is not canonical
/// (each validator aggregates the signatures it collected, so sui-nodes and the bucket hold
/// different signer sets for the same checkpoint); it is counted when it differs, and the chain
/// pass checks it for a quorum with sui-node's verify_checkpoint_with_committee.
fn cmp_summary(st: &Shared, seq: u64, what: &str, got: &CertifiedCheckpointSummary, want: &CertifiedCheckpointSummary) -> bool {
    if !cmp(st, seq, what, got.data(), want.data()) {
        return false;
    }
    if bcs::to_bytes(got.auth_sig()).unwrap() != bcs::to_bytes(want.auth_sig()).unwrap() {
        let mut s = st.lock().unwrap();
        s.cert_differs += 1;
        if s.strict {
            s.diff(json!({"seq": seq, "what": format!("{what}/cert"), "error": "aggregate signature bytes differ (--strict)"}));
            return false;
        }
    }
    true
}

/// A transaction's own signature list (`SenderSignedData.tx_signatures`) is not covered by any
/// digest. sui-node serves the order the transaction arrived with; Mysten's archive conversion
/// (`TryFrom<&proto::Checkpoint>`) replaces it with the checkpoint contents' `user_signatures`
/// for that transaction, which the contents digest does cover. The canonical form here is the
/// contents' order: the answer's list must hold exactly the same signatures (as a multiset), and
/// a different order is counted in `sig_order` (a failure only with --strict).
fn canon_exec(st: &Shared, seq: u64, what: &str, idx: usize, d: &ExecutionData, sigs: &[GenericSignature]) -> Option<ExecutionData> {
    let got = d.transaction.data().tx_signatures();
    if got == sigs {
        return Some(d.clone());
    }
    let sorted = |v: &[GenericSignature]| {
        let mut x: Vec<Vec<u8>> = v.iter().map(|g| bcs::to_bytes(g).unwrap()).collect();
        x.sort();
        x
    };
    let mut s = st.lock().unwrap();
    let strict = s.strict;
    let same_set = sorted(got) == sorted(sigs);
    if !same_set || strict {
        s.diff(json!({"seq": seq, "what": format!("{what}/signatures"), "index": idx,
            "error": if same_set { "signature order differs (--strict)" } else { "transaction signatures are not the contents' user signatures" }}));
        return None;
    }
    s.sig_order += 1;
    Some(ExecutionData {
        transaction: Transaction::from_generic_sig_data(d.transaction.data().transaction_data().clone(), sigs.to_vec()),
        effects: d.effects.clone(),
    })
}

/// Full contents in canonical form (contents-order transaction signatures); None if a
/// transaction's signatures are not the contents' or the shapes differ.
fn canon_full(st: &Shared, seq: u64, what: &str, v: &VersionedFullCheckpointContents, sigs: &[Vec<GenericSignature>]) -> Option<VersionedFullCheckpointContents> {
    if v.size() != sigs.len() {
        return Some(v.clone()); // the byte comparison reports it
    }
    let mut txs = Vec::with_capacity(v.size());
    for (i, d) in v.iter().enumerate() {
        txs.push(canon_exec(st, seq, what, i, d, &sigs[i])?);
    }
    Some(VersionedFullCheckpointContents::from_contents_and_execution_data(v.checkpoint_contents(), txs.into_iter()))
}

fn cmp<A: Serialize, B: Serialize>(st: &Shared, seq: u64, what: &str, got: &A, want: &B) -> bool {
    let g = bcs::to_bytes(got).unwrap();
    let w = bcs::to_bytes(want).unwrap();
    let mut s = st.lock().unwrap();
    s.bytes += g.len() as u64;
    if g == w {
        return true;
    }
    s.diff(json!({"seq": seq, "what": what, "diff": first_diff(&g, &w)}));
    false
}

struct SeqOut {
    seq: u64,
    summary: Option<CertifiedCheckpointSummary>,
    expected: Option<CertifiedCheckpointSummary>,
    ok: bool,
    missing: bool,
}

async fn check_seq(
    seq: u64,
    peer: anemo::Peer,
    store: Arc<dyn object_store::ObjectStore>,
    st: Shared,
    sample: bool,
    timeout: Duration,
) -> SeqOut {
    let mut out = SeqOut { seq, summary: None, expected: None, ok: true, missing: false };
    let mut c = StateSyncClient::new(peer);
    let want = match fetch_checkpoint(&store, seq).await {
        Ok(cp) => cp,
        Err(e) => {
            let mut s = st.lock().unwrap();
            s.bucket_missing += 1;
            s.diff(json!({"seq": seq, "what": "bucket", "error": e.to_string()}));
            out.ok = false;
            return out;
        }
    };
    out.expected = Some(want.summary.clone());
    let req = |r: GetCheckpointSummaryRequest| Request::new(r).with_timeout(timeout);
    let fail = |st: &Shared, what: &str, e: String| {
        st.lock().unwrap().diff(json!({"seq": seq, "what": what, "error": e}));
    };

    // 1. summary by sequence number
    let got = match timed(&st, "GetCheckpointSummary/seq", c.get_checkpoint_summary(req(GetCheckpointSummaryRequest::BySequenceNumber(seq)))).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            out.missing = true;
            fail(&st, "summary/seq", "None".into());
            return out;
        }
        Err(e) => {
            out.ok = false;
            fail(&st, "summary/seq", e);
            return out;
        }
    };
    out.ok &= cmp_summary(&st, seq, "summary/seq", &got, &want.summary);
    out.summary = Some(got.clone());

    // 2. summary by digest (sample)
    if sample {
        match timed(&st, "GetCheckpointSummary/digest", c.get_checkpoint_summary(req(GetCheckpointSummaryRequest::ByDigest(*want.summary.digest())))).await {
            Ok(Some(s)) => out.ok &= cmp_summary(&st, seq, "summary/digest", &s, &want.summary),
            Ok(None) => { out.missing = true; fail(&st, "summary/digest", "None".into()); }
            Err(e) => { out.ok = false; fail(&st, "summary/digest", e); }
        }
    }

    // 3. full contents V2 by the summary's content digest, verified like sui-node
    let full = expected_full(&want);
    let sigs: Vec<Vec<GenericSignature>> = want.contents.clone().into_iter_with_signatures().map(|(_, s)| s).collect();
    let digest = got.content_digest;
    match timed(&st, "GetCheckpointContentsV2", c.get_checkpoint_contents_v2(Request::new(digest).with_timeout(timeout))).await {
        Ok(Some(v)) => {
            if let Err(e) = v.verify_digests(want.summary.content_digest) {
                out.ok = false;
                let mut s = st.lock().unwrap();
                s.verify_failures += 1;
                s.diff(json!({"seq": seq, "what": "contentsV2/verify_digests", "error": e.to_string()}));
            }
            match canon_full(&st, seq, "contentsV2", &v, &sigs) {
                Some(c) => out.ok &= cmp(&st, seq, "contentsV2", &c, &full),
                None => out.ok = false,
            }
        }
        Ok(None) => { out.missing = true; fail(&st, "contentsV2", "None".into()); }
        Err(e) => { out.ok = false; fail(&st, "contentsV2", e); }
    }

    if sample {
        // 4. V1 contents
        match timed(&st, "GetCheckpointContents", c.get_checkpoint_contents(Request::new(digest).with_timeout(timeout))).await {
            Ok(Some(v)) => match canon_full(&st, seq, "contentsV1", &VersionedFullCheckpointContents::V1(v), &sigs) {
                Some(c) => out.ok &= cmp(&st, seq, "contentsV1", &c.into_v1(), &full.clone().into_v1()),
                None => out.ok = false,
            },
            Ok(None) => { out.missing = true; fail(&st, "contentsV1", "None".into()); }
            Err(e) => { out.ok = false; fail(&st, "contentsV1", e); }
        }
        // 5. the 1.83 paged pair: contents digests, then transactions in pages (sui-node's checks)
        match timed(&st, "GetCheckpointContentsDigests", c.get_checkpoint_contents_digests(Request::new(seq).with_timeout(timeout))).await {
            Ok(Some(contents)) => {
                out.ok &= cmp(&st, seq, "contentsDigests", &contents, &want.contents);
                if *contents.digest() != want.summary.content_digest {
                    out.ok = false;
                    let mut s = st.lock().unwrap();
                    s.verify_failures += 1;
                    s.diff(json!({"seq": seq, "what": "contentsDigests/digest", "error": format!("{} != {}", contents.digest(), want.summary.content_digest)}));
                }
                let n = contents.size() as u64;
                let want_tx: Vec<ExecutionData> = full.iter().cloned().collect();
                let mut next = 0u64;
                while next < n {
                    let r = GetCheckpointTransactionsRequest { sequence_number: seq, start: next, end: n };
                    match timed(&st, "GetCheckpointTransactions", c.get_checkpoint_transactions(Request::new(r).with_timeout(timeout))).await {
                        Ok(Some(page)) => {
                            if page.is_empty() || page.len() as u64 > n - next {
                                out.ok = false;
                                fail(&st, "transactions/page", format!("page of {} does not fit [{next},{n})", page.len()));
                                break;
                            }
                            for (k, data) in page.iter().enumerate() {
                                let idx = next as usize + k;
                                let expect = *contents.inner().get_digests(idx).unwrap();
                                if data.digests() != expect {
                                    out.ok = false;
                                    let mut s = st.lock().unwrap();
                                    s.verify_failures += 1;
                                    s.diff(json!({"seq": seq, "what": "transactions/digests", "index": idx}));
                                }
                                match sigs.get(idx).and_then(|sg| canon_exec(&st, seq, "transactions", idx, data, sg)) {
                                    Some(c) => out.ok &= cmp(&st, seq, "transactions", &c, &want_tx[idx]),
                                    None => out.ok = false,
                                }
                            }
                            next += page.len() as u64;
                        }
                        Ok(None) => { out.missing = true; fail(&st, "transactions", "None".into()); break; }
                        Err(e) => { out.ok = false; fail(&st, "transactions", e); break; }
                    }
                }
                // sui-node's server answers 400 for an empty or out-of-range page; so must deepwave
                let bad = GetCheckpointTransactionsRequest { sequence_number: seq, start: n, end: n + 1 };
                match c.get_checkpoint_transactions(Request::new(bad).with_timeout(timeout)).await {
                    Err(e) if e.status() == anemo::types::response::StatusCode::BadRequest => {}
                    other => {
                        out.ok = false;
                        fail(&st, "transactions/out-of-range", format!("want 400 BadRequest, got {:?}", other.map(|r| r.into_inner().map(|v| v.len()))));
                    }
                }
            }
            Ok(None) => { out.missing = true; fail(&st, "contentsDigests", "None".into()); }
            Err(e) => { out.ok = false; fail(&st, "contentsDigests", e); }
        }
    }
    out
}

/// Committee of `epoch`, from the bucket's last checkpoint of epoch-1 (`epochs.json`).
async fn committee(
    store: &Arc<dyn object_store::ObjectStore>,
    epochs: &[u64],
    cache: &mut BTreeMap<u64, Arc<Committee>>,
    epoch: u64,
) -> Result<Arc<Committee>> {
    if let Some(c) = cache.get(&epoch) {
        return Ok(c.clone());
    }
    let prev = epoch.checked_sub(1).ok_or_else(|| anyhow!("no committee source for epoch 0"))?;
    let seq = *epochs.get(prev as usize).ok_or_else(|| anyhow!("epochs.json has no epoch {prev}"))?;
    let cp = fetch_checkpoint(store, seq).await?;
    let eoe = cp.summary.end_of_epoch_data.as_ref().ok_or_else(|| anyhow!("{seq} is not an end-of-epoch checkpoint"))?;
    let c = Arc::new(Committee::new(epoch, eoe.next_epoch_committee.iter().cloned().collect()));
    cache.insert(epoch, c.clone());
    Ok(c)
}

// ---- discovery ----

fn verify_v1(info: &SignedNodeInfo) -> Result<(), &'static str> {
    // sui-network discovery/mod.rs `update_known_peers` checks for V1 infos.
    if info.addresses.len() > MAX_ADDRESSES_PER_PEER {
        return Err("too many addresses");
    }
    if !info.addresses.iter().all(|a| a.len() < MAX_ADDRESS_LENGTH && a.to_anemo_address().is_ok()) {
        return Err("invalid address");
    }
    let pk = Ed25519PublicKey::from_bytes(&info.peer_id.0).map_err(|_| "invalid peer_id public key")?;
    let msg = bcs::to_bytes(info.data()).unwrap();
    pk.verify(&msg, info.auth_sig()).map_err(|_| "signature verification failed")
}

/// Copy of sui-network discovery/mod.rs `verify_versioned_node_info` (private there).
fn verify_versioned(info: &SignedVersionedNodeInfo) -> Result<(), &'static str> {
    let peer_id = info.peer_id().ok_or("missing P2P peer_id")?;
    let pk = Ed25519PublicKey::from_bytes(&peer_id.0).map_err(|_| "invalid peer_id public key")?;
    let msg = bcs::to_bytes(info.data()).unwrap();
    pk.verify(&msg, info.auth_sig()).map_err(|_| "signature verification failed")?;
    match info.data() {
        VersionedNodeInfo::V1(i) => {
            if i.addresses.len() > MAX_ADDRESSES_PER_PEER {
                return Err("too many addresses");
            }
            if !i.addresses.iter().all(|a| a.len() < MAX_ADDRESS_LENGTH && a.to_anemo_address().is_ok()) {
                return Err("invalid address");
            }
        }
        VersionedNodeInfo::V2(i) => {
            let mut seen = Vec::new();
            for e in i.addresses.keys() {
                let d = std::mem::discriminant(e);
                if seen.contains(&d) {
                    return Err("duplicate endpoint variant");
                }
                seen.push(d);
            }
            for (e, addrs) in &i.addresses {
                if addrs.len() > MAX_ADDRESSES_PER_PEER {
                    return Err("too many addresses for endpoint");
                }
                if !addrs.iter().all(|a| a.len() < MAX_ADDRESS_LENGTH) {
                    return Err("address too long");
                }
                if matches!(e, EndpointId::P2p(_)) && !addrs.iter().all(|a| a.to_anemo_address().is_ok()) {
                    return Err("invalid P2P address");
                }
            }
            if !i.addresses.keys().all(|e| match e {
                EndpointId::P2p(_) => true,
                EndpointId::Consensus(pk) => pk.as_bytes() == peer_id.0,
            }) {
                return Err("non-P2P endpoint identity mismatch");
            }
        }
    }
    Ok(())
}

async fn discovery(peer: anemo::Peer, a: &Args, st: &Shared) -> (serde_json::Value, bool) {
    let mut c = DiscoveryClient::new(peer);
    let mut ok = true;
    let mut out = serde_json::Map::new();
    match timed(st, "GetKnownPeersV2", c.get_known_peers_v2(Request::new(()).with_timeout(a.timeout))).await {
        Ok(r) => {
            let own_ok = verify_v1(&r.own_info);
            let own_is_peer = r.own_info.peer_id == a.peer_id;
            let bad = r.known_peers.iter().filter(|p| verify_v1(p).is_err()).count();
            ok &= own_ok.is_ok() && own_is_peer;
            out.insert("v2".into(), json!({
                "own_info": {"peer_id": hex::encode(r.own_info.peer_id.0), "is_dialed_peer": own_is_peer,
                    "addresses": r.own_info.addresses.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
                    "timestamp_ms": r.own_info.timestamp_ms, "access": format!("{:?}", r.own_info.access_type),
                    "verified": own_ok.err().unwrap_or("ok")},
                "known_peers": r.known_peers.len(), "known_peers_rejected": bad}));
        }
        Err(e) => { ok = false; out.insert("v2".into(), json!({"error": e})); }
    }
    // V3 carries our own signed info, as sui-node sends it (VersionedNodeInfo::V2, P2P endpoint only).
    let kp = Ed25519KeyPair::from(Ed25519PrivateKey::from_bytes(&a.key).unwrap());
    let me = PeerId(kp.public().as_bytes().try_into().unwrap());
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let own = VersionedNodeInfo::V2(NodeInfoV2 {
        addresses: BTreeMap::from([(EndpointId::P2p(me), vec![])]),
        timestamp_ms: now,
        access_type: sui_config::p2p::AccessType::Private,
    })
    .sign(&kp);
    match timed(st, "GetKnownPeersV3", c.get_known_peers_v3(Request::new(GetKnownPeersRequestV3 { own_info: own }).with_timeout(a.timeout))).await {
        Ok(r) => {
            let own_ok = verify_versioned(&r.own_info);
            let own_is_peer = r.own_info.peer_id() == Some(a.peer_id);
            let bad = r.known_peers.iter().filter(|p| verify_versioned(p).is_err()).count();
            ok &= own_ok.is_ok() && own_is_peer;
            out.insert("v3".into(), json!({
                "own_info": {"peer_id": r.own_info.peer_id().map(|p| hex::encode(p.0)), "is_dialed_peer": own_is_peer,
                    "version": match r.own_info.data() { VersionedNodeInfo::V1(_) => 1, VersionedNodeInfo::V2(_) => 2 },
                    "p2p_addresses": r.own_info.p2p_addresses().iter().map(|x| x.to_string()).collect::<Vec<_>>(),
                    "timestamp_ms": r.own_info.timestamp_ms(), "access": format!("{:?}", r.own_info.access_type()),
                    "verified": own_ok.err().unwrap_or("ok")},
                "known_peers": r.known_peers.len(), "known_peers_rejected": bad}));
        }
        Err(e) => { ok = false; out.insert("v3".into(), json!({"error": e})); }
    }
    (serde_json::Value::Object(out), ok)
}

// ---- entry points ----

pub async fn run(args: &[String]) -> Result<()> {
    let mut a = parse(args)?;
    let started = Instant::now();
    let st: Shared = Arc::new(Mutex::new(Stats { strict: a.strict, ..Stats::default() }));
    let store = build_object_store(&a.bucket, vec![], vec![]);
    let (network, peer, dial_time) = dial(&a).await?;
    eprintln!("connected to {} peer {} in {:?}", a.peer, hex::encode(a.peer_id.0), dial_time);
    let mut fatal = Vec::<String>::new();
    let mut c = StateSyncClient::new(peer.clone());

    // sui-node's first questions to a new peer: chain identity, then availability.
    let genesis = CheckpointDigest::from_str(MAINNET_GENESIS)?;
    let chain = match timed(&st, "GetCheckpointSummary/seq", c.get_checkpoint_summary(Request::new(GetCheckpointSummaryRequest::BySequenceNumber(0)).with_timeout(a.timeout))).await {
        Ok(Some(s)) => {
            let same = *s.digest() == genesis;
            if !same { fatal.push(format!("checkpoint 0 digest {} != mainnet genesis {genesis}", s.digest())); }
            let bucket_eq = match fetch_checkpoint(&store, 0).await {
                Ok(cp) => { let eq = cmp_summary(&st, 0, "summary/genesis", &s, &cp.summary); if !eq { fatal.push("checkpoint 0 summary bytes differ from the bucket".into()); } Some(eq) }
                Err(_) => None,
            };
            json!({"digest": s.digest().to_string(), "on_same_chain": same, "bucket_equal": bucket_eq})
        }
        Ok(None) => { fatal.push("peer has no checkpoint 0 (sui-node marks it not on the same chain)".into()); json!({"error": "None"}) }
        Err(e) => { fatal.push(format!("checkpoint 0: {e}")); json!({"error": e}) }
    };
    let epochs = if a.signatures { end_of_epoch_data(&a.bucket, vec![]).await.ok() } else { None };
    let mut committees = BTreeMap::new();
    let avail = match timed(&st, "GetCheckpointAvailability", c.get_checkpoint_availability(Request::new(()).with_timeout(a.timeout))).await {
        Ok(r) => {
            let v: Availability = bcs::from_bytes(&bcs::to_bytes(&r)?)?;
            let h = &v.highest_synced_checkpoint;
            let sig = match &epochs {
                Some(ep) => match committee(&store, ep, &mut committees, h.epoch()).await {
                    Ok(cm) => json!(h.verify_authority_signatures(&cm).map(|_| "ok".to_string()).unwrap_or_else(|e| e.to_string())),
                    Err(e) => json!(format!("skipped: {e}")),
                },
                None => json!("skipped"),
            };
            if sig.as_str().is_some_and(|s| s != "ok" && !s.starts_with("skipped")) {
                fatal.push(format!("availability highest checkpoint signature: {sig}"));
            }
            a.from = resolve(&a.from_s, *h.sequence_number(), v.lowest_available_checkpoint)?;
            a.to = resolve(&a.to_s, *h.sequence_number(), v.lowest_available_checkpoint)?;
            let in_window = v.lowest_available_checkpoint <= a.from && a.to <= *h.sequence_number();
            json!({"highest_synced": h.sequence_number(), "highest_epoch": h.epoch(), "highest_signature": sig,
                   "lowest_available": v.lowest_available_checkpoint, "range_in_window": in_window})
        }
        Err(e) => {
            fatal.push(format!("availability: {e}"));
            a.from = a.from_s.parse().context("--from must be a number when availability fails")?;
            a.to = a.to_s.parse().context("--to must be a number when availability fails")?;
            json!({"error": e})
        }
    };
    if a.to < a.from {
        bail!("--to {} must be >= --from {}", a.to, a.from);
    }
    eprintln!("chain {chain}\navailability {avail}\nrange [{}, {}]", a.from, a.to);
    let disc = if a.discovery {
        let (v, ok) = discovery(peer.clone(), &a, &st).await;
        if !ok { fatal.push("discovery check failed".into()); }
        eprintln!("discovery {v}");
        v
    } else {
        json!("skipped")
    };

    // every checkpoint in [from, to], `concurrency` at a time
    let total = a.to - a.from + 1;
    let mut results = futures::stream::iter(a.from..=a.to)
        .map(|seq| {
            let sample = seq == a.from || seq == a.to || (seq - a.from) % a.sample == 0;
            check_seq(seq, peer.clone(), store.clone(), st.clone(), sample, a.timeout)
        })
        .buffer_unordered(a.concurrency.max(1));
    let mut by_seq: BTreeMap<u64, SeqOut> = BTreeMap::new();
    let mut done = 0u64;
    let mut last = Instant::now();
    while let Some(r) = results.next().await {
        {
            let mut s = st.lock().unwrap();
            if r.missing { s.missing += 1; } else if r.ok { s.equal += 1; } else { s.mismatched += 1; }
        }
        done += 1;
        if last.elapsed() > Duration::from_secs(10) {
            let s = st.lock().unwrap();
            eprintln!("progress {done}/{total} equal {} mismatched {} missing {} {:.1} MB", s.equal, s.mismatched, s.missing, s.bytes as f64 / 1e6);
            last = Instant::now();
        }
        // keep only what the chain pass needs
        by_seq.insert(r.seq, SeqOut { seq: r.seq, summary: r.summary, expected: r.expected, ok: r.ok, missing: r.missing });
    }
    drop(results);

    // chain pass, in order, with sui-node's verify_checkpoint_with_committee
    let mut chain_checked = 0u64;
    let mut chain_failed = 0u64;
    let mut sig_skipped: Option<String> = None;
    let mut current: Option<VerifiedCheckpoint> = if a.from == 0 {
        None
    } else {
        fetch_checkpoint(&store, a.from - 1).await.ok().map(|cp| VerifiedCheckpoint::new_unchecked(cp.summary))
    };
    for (seq, r) in by_seq.iter_mut() {
        let Some(got) = r.summary.take() else {
            current = r.expected.take().map(VerifiedCheckpoint::new_unchecked);
            continue;
        };
        let expected = r.expected.take();
        if let Some(cur) = &current {
            let verdict: Result<(), String> = if a.signatures {
                match &epochs {
                    Some(ep) => match committee(&store, ep, &mut committees, got.epoch()).await {
                        Ok(cm) => sui_storage::verify_checkpoint_with_committee(cm, cur, got.clone()).map(|_| ()).map_err(|_| "verify_checkpoint_with_committee rejected it".into()),
                        Err(e) => { sig_skipped.get_or_insert(e.to_string()); link(cur, &got) }
                    },
                    None => { sig_skipped.get_or_insert("no epochs.json".into()); link(cur, &got) }
                }
            } else {
                link(cur, &got)
            };
            chain_checked += 1;
            if let Err(e) = verdict {
                chain_failed += 1;
                let mut s = st.lock().unwrap();
                s.verify_failures += 1;
                s.diff(json!({"seq": seq, "what": "summary/chain", "error": e}));
                if r.ok && !r.missing { r.ok = false; s.equal -= 1; s.mismatched += 1; }
            }
        }
        // continue the chain from the trusted (bucket) summary so one bad answer is one failure
        current = expected.or(Some(got)).map(VerifiedCheckpoint::new_unchecked);
    }

    let mut s = st.lock().unwrap();
    let mut routes = serde_json::Map::new();
    let mut names: Vec<_> = s.lat.keys().copied().collect();
    names.sort();
    for n in names {
        let errs = s.errors.get(n).copied().unwrap_or(0);
        let v = s.lat.get_mut(n).unwrap();
        routes.insert(n.into(), json!({"count": v.len(), "errors": errs, "p50_ms": pct(v, 0.5), "p99_ms": pct(v, 0.99), "max_ms": pct(v, 1.0)}));
    }
    let wall = started.elapsed().as_secs_f64();
    let report = json!({
        "peer": a.peer, "peer_id": hex::encode(a.peer_id.0), "server_name": a.server_name,
        "client_peer_id": hex::encode(network.peer_id().0), "dial_ms": dial_time.as_secs_f64() * 1e3,
        "range": [a.from, a.to], "sample_every": a.sample, "concurrency": a.concurrency, "bucket": a.bucket,
        "chain": chain, "availability": avail, "discovery": disc,
        "requested": total, "equal": s.equal, "mismatched": s.mismatched, "missing": s.missing,
        "bucket_missing": s.bucket_missing, "verify_failures": s.verify_failures,
        "chain_checked": chain_checked, "chain_failed": chain_failed,
        "signatures": if !a.signatures { json!("off") } else { sig_skipped.as_ref().map(|e| json!(format!("partly skipped: {e}"))).unwrap_or(json!("verified")) },
        "strict": a.strict, "sig_order_normalized": s.sig_order, "cert_bytes_differ": s.cert_differs,
        "total_mb": s.bytes as f64 / 1e6, "wall_s": wall, "checkpoints_per_s": total as f64 / wall,
        "routes": routes, "fatal": fatal, "first_diffs": s.diffs,
    });
    let text = serde_json::to_string_pretty(&report)?;
    println!("{text}");
    if let Some(o) = &a.out {
        std::fs::write(o, &text)?;
    }
    let bad = s.mismatched + s.missing + s.bucket_missing + s.verify_failures + chain_failed > 0 || !fatal.is_empty() || s.equal != total;
    drop(s);
    network.shutdown().await.ok();
    if bad {
        bail!("sync-from: NOT equal (see report)");
    }
    eprintln!("sync-from: all {total} checkpoints byte-equal and verified");
    Ok(())
}

/// `N`, `tip`, `tip-N`, `low`, `low+N` (tip = the peer's highest synced, low = its lowest available).
fn resolve(s: &str, tip: u64, low: u64) -> Result<u64> {
    let num = |x: &str| x.parse::<u64>().with_context(|| format!("bad checkpoint spec {s}"));
    Ok(if let Some(r) = s.strip_prefix("tip-") { tip.saturating_sub(num(r)?) }
    else if s == "tip" { tip }
    else if let Some(r) = s.strip_prefix("low+") { low.saturating_add(num(r)?) }
    else if s == "low" { low }
    else { num(s)? })
}

fn link(cur: &VerifiedCheckpoint, got: &CertifiedCheckpointSummary) -> Result<(), String> {
    if got.previous_digest != Some(*cur.digest()) {
        return Err(format!("previous_digest {:?} != digest of {} ({})", got.previous_digest, cur.sequence_number(), cur.digest()));
    }
    Ok(())
}

/// `peer-id FILE`: the anemo peer id (Ed25519 public key, hex) of a network key file as deepwave
/// reads it (`--p2p-key`: a 32-byte seed, raw or as 64 hex characters).
pub fn peer_id(args: &[String]) -> Result<()> {
    let raw = std::fs::read(args.first().ok_or_else(|| anyhow!("usage: peer-id FILE"))?)?;
    let txt = String::from_utf8_lossy(&raw).trim().to_string();
    let seed: [u8; 32] = if raw.len() == 32 { raw.try_into().unwrap() } else {
        hex::decode(txt.trim_start_matches("0x"))?.try_into().map_err(|_| anyhow!("key file is neither 32 bytes nor 64 hex"))?
    };
    let kp = Ed25519KeyPair::from(Ed25519PrivateKey::from_bytes(&seed).map_err(|e| anyhow!("{e}"))?);
    println!("{}", hex::encode(kp.public().as_bytes()));
    Ok(())
}

/// A sui-node-like peer that only connects and asks for availability every `interval`
/// (state sync's peer-height poll), to mimic mainnet peers against a serving node.
pub async fn probe(args: &[String]) -> Result<()> {
    let a = parse(args)?;
    let (network, peer, took) = dial(&a).await?;
    println!("{}", json!({"event": "connected", "peer": a.peer, "dial_ms": took.as_secs_f64() * 1e3, "client_peer_id": hex::encode(network.peer_id().0)}));
    let mut c = StateSyncClient::new(peer.clone());
    let genesis = CheckpointDigest::from_str(MAINNET_GENESIS)?;
    match c.get_checkpoint_summary(Request::new(GetCheckpointSummaryRequest::BySequenceNumber(0)).with_timeout(a.timeout)).await {
        Ok(r) => println!("{}", json!({"event": "chain", "same_chain": r.into_inner().map(|s| *s.digest() == genesis)})),
        Err(e) => println!("{}", json!({"event": "chain", "error": format!("{e:?}")})),
    }
    let (mut ok, mut err) = (0u64, 0u64);
    let mut i = 0u64;
    let mut tick = tokio::time::interval(a.interval.max(Duration::from_millis(1)));
    while i < a.count {
        tick.tick().await;
        i += 1;
        let t = Instant::now();
        let r = c.get_checkpoint_availability(Request::new(()).with_timeout(a.timeout)).await;
        let ms = t.elapsed().as_secs_f64() * 1e3;
        match r {
            Ok(r) => {
                ok += 1;
                let v: Availability = bcs::from_bytes(&bcs::to_bytes(r.inner())?)?;
                println!("{}", json!({"event": "availability", "i": i, "ms": ms, "highest": v.highest_synced_checkpoint.sequence_number(), "lowest": v.lowest_available_checkpoint}));
            }
            Err(e) => {
                err += 1;
                println!("{}", json!({"event": "availability", "i": i, "ms": ms, "error": format!("{e:?}")}));
            }
        }
    }
    println!("{}", json!({"event": "done", "ok": ok, "errors": err}));
    network.shutdown().await.ok();
    if err > 0 { bail!("{err} availability requests failed") }
    Ok(())
}
