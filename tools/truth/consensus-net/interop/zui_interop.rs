// deepwave interop (val-audit net): Mysten's own consensus network stack (TonicManager,
// TonicValidatorClient, sui-tls) against a deepwave consensus_net peer on loopback.
//
// Driven by the zig test "tonic interop" in src/consensus/net/interop.zig, which starts a deepwave
// ConsensusService server (authority 0), writes $ZUI_INTEROP_DIR/zui.txt and runs this test as a
// child process. This side is authority 1: it serves ConsensusService with a recording mock,
// writes $ZUI_INTEROP_DIR/rust_ready, calls every RPC on the deepwave server, then waits for
// $ZUI_INTEROP_DIR/zig_done (deepwave's client calls against this server) and checks what it received.
// Generated keys, loopback only.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use consensus_config::{AuthorityIndex, Committee, NetworkKeyPair};
use consensus_types::block::{BlockDigest, BlockRef, Round};
use fastcrypto::{
    ed25519::{Ed25519KeyPair, Ed25519PrivateKey},
    encoding::{Encoding, Hex},
    traits::ToFromBytes,
};
use futures::{StreamExt as _, stream};
use parking_lot::Mutex;
use sui_tls::rustls::{
    client::danger::ServerCertVerifier as _,
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::ClientCertVerifier as _,
};

use super::{
    BlockStream, ExtendedSerializedBlock, NetworkManager, SerializedBlockForm,
    ValidatorNetworkClient, ValidatorNetworkService, tonic_network::TonicManager,
};
use crate::{
    block::{BlockAPI as _, SignedBlock, TestBlock, VerifiedBlock},
    commit::{CommitAPI as _, CommitDigest, CommitRange, TrustedCommit},
    context::Context,
    error::{ConsensusError, ConsensusResult},
};

#[derive(Default, Debug)]
struct Calls {
    send_block: Vec<(u32, Vec<u8>)>,
    subscribe: Vec<(u32, Round)>,
    fetch_blocks: Vec<(u32, Vec<BlockRef>, Vec<Round>, bool)>,
    fetch_commits: Vec<(u32, u32, u32)>,
    fetch_latest: Vec<(u32, Vec<u32>)>,
    latest_rounds: Vec<u32>,
}

#[derive(Default)]
struct Mock {
    calls: Mutex<Calls>,
}

fn test_block(round: Round, author: u32) -> VerifiedBlock {
    VerifiedBlock::new_for_test(TestBlock::new(round, author).set_timestamp_ms(1000 + round as u64).build())
}

#[async_trait]
impl ValidatorNetworkService for Mock {
    async fn handle_send_block(
        &self,
        peer: AuthorityIndex,
        block: ExtendedSerializedBlock,
    ) -> ConsensusResult<()> {
        let SerializedBlockForm::Full(b) = block.block else {
            return Err(ConsensusError::UnexpectedBlockForm);
        };
        self.calls.lock().send_block.push((peer.value_u32(), b.to_vec()));
        Ok(())
    }

    async fn handle_subscribe_blocks(
        &self,
        peer: AuthorityIndex,
        last_received: Round,
    ) -> ConsensusResult<BlockStream> {
        self.calls.lock().subscribe.push((peer.value_u32(), last_received));
        let blocks: Vec<ExtendedSerializedBlock> = (last_received + 1..=last_received + 3)
            .map(|r| ExtendedSerializedBlock {
                block: SerializedBlockForm::Full(test_block(r, 1).serialized().clone()),
                excluded_ancestors: vec![
                    bcs::to_bytes(&BlockRef::new(
                        r - 1,
                        AuthorityIndex::new_for_test(3),
                        BlockDigest::default(),
                    ))
                    .unwrap(),
                ],
            })
            .collect();
        Ok(Box::pin(stream::iter(blocks).chain(stream::pending())))
    }

    async fn handle_fetch_blocks(
        &self,
        peer: AuthorityIndex,
        block_refs: Vec<BlockRef>,
        fetch_after_rounds: Vec<Round>,
        fetch_missing_ancestors: bool,
    ) -> ConsensusResult<Vec<Bytes>> {
        self.calls.lock().fetch_blocks.push((
            peer.value_u32(),
            block_refs.clone(),
            fetch_after_rounds,
            fetch_missing_ancestors,
        ));
        Ok(block_refs
            .iter()
            .map(|r| test_block(r.round, r.author.value_u32()).serialized().clone())
            .collect())
    }

    async fn handle_fetch_commits(
        &self,
        peer: AuthorityIndex,
        commit_range: CommitRange,
    ) -> ConsensusResult<(Vec<TrustedCommit>, Vec<VerifiedBlock>)> {
        self.calls
            .lock()
            .fetch_commits
            .push((peer.value_u32(), commit_range.start(), commit_range.end()));
        let leader = test_block(10, 0).reference();
        let commits = (commit_range.start()..=commit_range.end().min(commit_range.start() + 1))
            .map(|i| TrustedCommit::new_for_test(i, CommitDigest::MIN, 0, leader, vec![leader]))
            .collect();
        let certifiers = (0..3).map(|a| test_block(11, a)).collect();
        Ok((commits, certifiers))
    }

    async fn handle_fetch_latest_blocks(
        &self,
        peer: AuthorityIndex,
        authorities: Vec<AuthorityIndex>,
    ) -> ConsensusResult<Vec<Bytes>> {
        self.calls.lock().fetch_latest.push((
            peer.value_u32(),
            authorities.iter().map(|a| a.value_u32()).collect(),
        ));
        Ok(authorities
            .iter()
            .map(|a| test_block(7, a.value_u32()).serialized().clone())
            .collect())
    }

    async fn handle_get_latest_rounds(
        &self,
        peer: AuthorityIndex,
    ) -> ConsensusResult<(Vec<Round>, Vec<Round>)> {
        self.calls.lock().latest_rounds.push(peer.value_u32());
        Ok((vec![1, 2, 3, 4], vec![5, 6, 7, 8]))
    }
}

fn keypair(seed: &[u8]) -> NetworkKeyPair {
    let sk = Ed25519PrivateKey::from_bytes(seed).unwrap();
    NetworkKeyPair::new(Ed25519KeyPair::from(sk))
}

fn write_atomic(dir: &PathBuf, name: &str, text: &str) {
    let tmp = dir.join(format!("{name}.tmp"));
    std::fs::write(&tmp, text).unwrap();
    std::fs::rename(&tmp, dir.join(name)).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zui_interop() {
    // The zig side runs this binary with its working directory set to the exchange directory.
    let dir = match std::env::var("ZUI_INTEROP_DIR") {
        Ok(d) => PathBuf::from(d),
        Err(_) if std::path::Path::new("zui.txt").exists() => std::env::current_dir().unwrap(),
        Err(_) => {
            eprintln!("ZUI_INTEROP_DIR not set and no ./zui.txt: skipped");
            return;
        }
    };
    let text = std::fs::read_to_string(dir.join("zui.txt")).expect("zui.txt");
    let mut kv: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(k) = it.next() else { continue };
        kv.entry(k.to_string())
            .or_default()
            .extend(it.map(|s| s.to_string()));
    }
    let one = |k: &str| kv[k][0].clone();
    let zui_port: u16 = one("port").parse().unwrap();
    let epoch: u64 = one("epoch").parse().unwrap();
    let seeds: Vec<Vec<u8>> = kv["seeds"].iter().map(|h| Hex::decode(h).unwrap()).collect();
    assert_eq!(seeds.len(), 4);
    let name = format!("consensus_epoch_{epoch}");

    // 1. Certificates: Mysten's verifiers on deepwave's certificate (both roles), and the converse
    // input for deepwave (rcgen's certificate for our key, written to rust_ready).
    let zui_cert = Hex::decode(&one("zui_cert")).unwrap();
    let der = CertificateDer::from(zui_cert);
    let pk0 = keypair(&seeds[0]).public().into_inner();
    assert_eq!(
        sui_tls::public_key_from_certificate(&der).expect("SPKI parse"),
        pk0,
        "public_key_from_certificate"
    );
    sui_tls::ClientCertVerifier::new(
        sui_tls::AllowPublicKeys::new(BTreeSet::from([pk0.clone()])),
        name.clone(),
    )
    .verify_client_cert(&der, &[], UnixTime::now())
    .expect("Mysten ClientCertVerifier refused zui's certificate");
    sui_tls::ServerCertVerifier::new(pk0.clone(), name.clone())
        .verify_server_cert(
            &der,
            &[],
            &ServerName::try_from("127.0.0.1").unwrap(),
            &[],
            UnixTime::now(),
        )
        .expect("Mysten ServerCertVerifier refused zui's certificate");
    assert!(
        sui_tls::ServerCertVerifier::new(pk0.clone(), "consensus_epoch_999".to_string())
            .verify_server_cert(
                &der,
                &[],
                &ServerName::try_from("127.0.0.1").unwrap(),
                &[],
                UnixTime::now()
            )
            .is_err(),
        "wrong epoch name must be refused"
    );
    eprintln!("INTEROP cert: Mysten verifiers accept zui's certificate (client and server role)");
    let rust_cert = sui_tls::SelfSignedCertificate::new(
        keypair(&seeds[1]).private_key().into_inner(),
        &name,
    )
    .rustls_certificate();

    // 2. Committee: deepwave is authority 0, we are authority 1.
    let (context, _keys) = Context::new_for_test(4);
    let rust_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut authorities: Vec<_> = context
        .committee
        .authorities()
        .map(|(_, a)| a.clone())
        .collect();
    for (i, a) in authorities.iter_mut().enumerate() {
        a.network_key = keypair(&seeds[i]).public();
    }
    authorities[0].address = format!("/ip4/127.0.0.1/udp/{zui_port}").parse().unwrap();
    authorities[1].address = format!("/ip4/127.0.0.1/udp/{rust_port}").parse().unwrap();
    let committee = Committee::new(epoch, authorities);
    let context = Arc::new(
        context
            .with_committee(committee)
            .with_authority_index(AuthorityIndex::new_for_test(1)),
    );

    let mock = Arc::new(Mock::default());
    let mut manager = TonicManager::new(context.clone(), keypair(&seeds[1]));
    manager.start_validator_server(mock.clone()).await;
    write_atomic(
        &dir,
        "rust_ready",
        &format!(
            "port {rust_port}\nrust_cert {}\n",
            Hex::encode(rust_cert.as_ref())
        ),
    );

    // 3. Mysten's client against the deepwave server.
    let client = manager.validator_client();
    let zui = AuthorityIndex::new_for_test(0);
    let t = Duration::from_secs(10);

    let (received, accepted) = client
        .get_latest_rounds(zui, t)
        .await
        .expect("get_latest_rounds");
    assert_eq!(received.len(), 4);
    assert_eq!(accepted, vec![3, 3, 3, 3]);
    eprintln!("INTEROP rust->zui GetLatestRounds ok {received:?} {accepted:?}");

    let decode_ref = |h: &String| -> BlockRef { bcs::from_bytes(&Hex::decode(h).unwrap()).unwrap() };
    let refs: Vec<BlockRef> = kv["refs"].iter().map(decode_ref).collect();
    let check_block = |b: &Bytes| -> SignedBlock {
        let sb: SignedBlock = bcs::from_bytes(b).expect("zui block decodes as a Mysten SignedBlock");
        sb
    };
    let blocks = client
        .fetch_blocks(zui, refs.clone(), vec![], false, t)
        .await
        .expect("fetch_blocks commit-sync shape");
    assert_eq!(blocks.len(), refs.len());
    for (b, r) in blocks.iter().zip(refs.iter()) {
        let sb = check_block(b);
        assert_eq!((sb.round(), sb.author()), (r.round, r.author));
        assert_eq!(VerifiedBlock::compute_digest(b), r.digest, "block digest");
    }
    eprintln!("INTEROP rust->zui FetchBlocks (refs only) ok {}", blocks.len());

    let live_ref = decode_ref(&kv["live_ref"][0]);
    let blocks = client
        .fetch_blocks(zui, vec![live_ref], vec![1, 1, 1, 1], true, t)
        .await
        .expect("fetch_blocks live shape");
    assert_eq!(blocks.len(), 5);
    blocks.iter().for_each(|b| {
        check_block(b);
    });
    eprintln!("INTEROP rust->zui FetchBlocks (live sync) ok {}", blocks.len());

    let blocks = client
        .fetch_blocks(zui, vec![], vec![0, 2, 3, 3], false, t)
        .await
        .expect("fetch_blocks periodic shape");
    assert_eq!(blocks.len(), 2);
    eprintln!("INTEROP rust->zui FetchBlocks (periodic) ok {}", blocks.len());

    let err = client
        .fetch_blocks(zui, vec![], vec![], false, t)
        .await
        .expect_err("an invalid FetchBlocks shape must fail");
    let msg = format!("{err:?}");
    eprintln!("INTEROP rust->zui FetchBlocks invalid shape: {msg}");
    assert!(
        msg.contains("code: Internal"),
        "zui must answer a refused request with INTERNAL like AuthorityService: {msg}"
    );

    let (commits, certifiers) = client
        .fetch_commits(zui, (1..=2).into(), t)
        .await
        .expect("fetch_commits");
    assert_eq!(commits.len(), 1);
    assert_eq!(certifiers.len(), 3);
    let c: crate::commit::Commit = bcs::from_bytes(&commits[0]).expect("zui commit decodes");
    assert_eq!(c.index(), 1);
    certifiers.iter().for_each(|b| {
        check_block(b);
    });
    eprintln!("INTEROP rust->zui FetchCommits ok");

    let blocks = client
        .fetch_latest_blocks(
            zui,
            vec![AuthorityIndex::new_for_test(0), AuthorityIndex::new_for_test(2)],
            t,
        )
        .await
        .expect("fetch_latest_blocks");
    assert_eq!(blocks.len(), 2);
    assert_eq!(check_block(&blocks[0]).author().value(), 0);
    assert_eq!(check_block(&blocks[1]).author().value(), 2);
    eprintln!("INTEROP rust->zui FetchLatestBlocks ok");

    let mut stream = client
        .subscribe_blocks(zui, 1, t)
        .await
        .expect("subscribe_blocks");
    for round in [2, 3] {
        let b = tokio::time::timeout(t, stream.next())
            .await
            .expect("subscription timed out")
            .expect("subscription ended");
        let SerializedBlockForm::Full(bytes) = b.block else {
            panic!("slim form")
        };
        let sb = check_block(&bytes);
        assert_eq!((sb.round(), sb.author().value()), (round, 0));
    }
    drop(stream);
    eprintln!("INTEROP rust->zui SubscribeBlocks ok");

    // 4. deepwave's client against our server.
    let deadline = Instant::now() + Duration::from_secs(90);
    let done = loop {
        if let Ok(s) = std::fs::read_to_string(dir.join("zig_done")) {
            break s;
        }
        assert!(Instant::now() < deadline, "zig_done never appeared");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(done.starts_with("ok"), "zui client side failed: {done}");
    {
        let c = mock.calls.lock();
        eprintln!("INTEROP zui->rust calls: {c:?}");
        assert_eq!(c.latest_rounds, vec![0]);
        assert_eq!(
            c.fetch_blocks,
            vec![(
                0,
                vec![BlockRef::new(
                    5,
                    AuthorityIndex::new_for_test(2),
                    BlockDigest([7u8; 32])
                )],
                vec![1, 2, 3, 4],
                true
            )]
        );
        assert_eq!(c.fetch_commits, vec![(0, 3, 7)]);
        assert_eq!(c.fetch_latest, vec![(0, vec![0, 2])]);
        assert_eq!(c.subscribe, vec![(0, 9)]);
        assert_eq!(c.send_block, vec![(0, b"hello zui".to_vec())]);
    }
    manager.stop().await;
    eprintln!("INTEROP PASS");
}
