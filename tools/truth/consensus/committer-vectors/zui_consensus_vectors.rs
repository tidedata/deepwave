// Truth generator for deepwave's consensus conformance suites (tools/truth/consensus/committer-vectors).
//
// Dropped into `consensus/core/src/` of a sui checkout at mainnet-v1.83.1 by run.sh and registered
// as `#[cfg(test)] mod zui_consensus_vectors;` in lib.rs. Everything below calls Mysten's own code;
// nothing is re-implemented here except the DAG shapes fed to it.
//
// Replay scenarios: seeded DAGs (Mysten's `DagBuilder`, plus `gen_dag` below for stake-aware random
// links, offline authorities, ignored authorities past the GC depth, equivocations, random timestamps
// and blocks with transactions / transaction votes / commit votes) fed round by round to the same
// components `Core::try_commit` uses (DagState, LeaderSchedule with its reputation-score updates
// every 300 commits, the pipelined UniversalCommitter, the Linearizer). Test-mode leader election
// applies (`cfg(test)`: (round + offset) % n), as in the committer unit tests; the deepwave runner uses
// `ElectionMode.round_robin_test` for it. The stake based election has its own vectors (`elect`).
//
// Output format (text, one record per line), path in $ZUI_VECTORS_OUT:
//   scenario <name> <n> <gc_depth> <shuffle 0|1> <num_leaders> [<stakes csv>]   (no csv = equal stakes of 1)
//   genesis <hex digest> (n times)
//   block <hex serialized SignedBlock>
//   step                       blocks since the previous step have been accepted; try_commit ran
//   commit <index> <hex commit digest> <leader round> <leader author> <timestamp_ms> <nblocks> <hex block digests...>
//   swap <range_start> <range_end_exclusive> good=<csv> bad=<csv> scores=<csv>
//   final <index> <hex commit digest> [<hex BlockRef bcs>:<rejected indices csv>...]
//                              commits the CommitFinalizer released after that commit was linearized
//   end
//   elect <n> <round> <offset> <authority> [<stakes csv>]   stake-based election (no csv = equal stakes of 1)
//   swaptable <commit_index> <threshold> stakes=<csv> scores=<csv> good=<csv> bad=<csv>
//   swapsel <leader> <round> <swapped authority or ->        LeaderSwapTable::swap on the last swaptable
//   vcommittee <epoch> <epoch_start_ms> <stakes csv>   committee for the verify lines; protocol key of
//                                                      authority i is Ed25519 from seed [i + 1; 32];
//                                                      protocol config = mainnet 141 consensus values
//   vgenesis <hex digest>                              genesis_blocks() of that context (n times)
//   verify <name> <verdict> <hex serialized>           verdict: ok | malformed | ConsensusError variant
//   bcs <kind> <hex>                                   fixed values, see `bcs_vectors`
//   order <hex BlockRef bcs>...                        BlockRefs sorted by Rust's derived Ord

use std::{fmt::Write as _, sync::Arc};

use bytes::Bytes;
use consensus_config::{
    AuthorityIndex, Committee, ProtocolKeyPair, local_committee_and_keys_with_test_options,
};
use consensus_types::block::{BlockDigest, BlockRef, Round, TransactionIndex};
use fastcrypto::{
    ed25519::{Ed25519KeyPair, Ed25519PrivateKey},
    traits::ToFromBytes as _,
};
use parking_lot::RwLock;
use rand::{Rng as _, SeedableRng as _, prelude::SliceRandom as _, rngs::StdRng};

use crate::{
    block::{
        Block, BlockAPI, BlockTransactionVotes, BlockV1, MisbehaviorProof, MisbehaviorReport,
        SignedBlock, Slot, TestBlock, Transaction, VerifiedBlock, genesis_blocks,
    },
    block_verifier::{BlockVerifier, NoopBlockVerifier, SignedBlockVerifier},
    commit::{Commit, CommitDigest, CommitRange, CommitRef, CommittedSubDag},
    commit_finalizer::CommitFinalizer,
    context::Context,
    dag_state::DagState,
    leader_schedule::{LeaderSchedule, LeaderSwapTable},
    leader_scoring::ReputationScores,
    linearizer::Linearizer,
    storage::mem_store::MemStore,
    test_dag_builder::DagBuilder,
    transaction::NoopTransactionVerifier,
    transaction_vote_tracker::TransactionVoteTracker,
    universal_committer::{
        UniversalCommitter, universal_committer_builder::UniversalCommitterBuilder,
    },
};

/// Test context whose committee has the given stakes (own index 0).
fn context_with_stakes(stakes: &[u64]) -> Context {
    let (context, _keys) = Context::new_for_test(stakes.len());
    let (committee, _) = local_committee_and_keys_with_test_options(0, stakes.to_vec(), false);
    context.with_committee(committee)
}

fn csv<T: ToString>(v: &[T]) -> String {
    v.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(",")
}

/// Heavy-tailed voting powers shaped like mainnet's (sum 10000, no single validator above 1000,
/// every validator at least 1). The real 1.83.1 mainnet committee is not baked in here; this
/// reproduces the spread that matters (a few large stakes, a long tail of small ones).
fn mainnet_like_stakes(n: usize) -> Vec<u64> {
    let total = 10_000u64;
    let raw: Vec<f64> = (0..n).map(|i| ((n - i) as f64).powf(1.6)).collect();
    let sum: f64 = raw.iter().sum();
    let mut v: Vec<u64> = raw
        .iter()
        .map(|r| (((r / sum) * total as f64).floor() as u64).clamp(1, 1000))
        .collect();
    let mut cur: u64 = v.iter().sum();
    let mut i = n - 1; // top up / trim from the small end so the sum is exactly 10000
    while cur < total {
        if v[i] < 1000 {
            v[i] += 1;
            cur += 1;
        }
        i = if i == 0 { n - 1 } else { i - 1 };
    }
    while cur > total {
        if v[i] > 1 {
            v[i] -= 1;
            cur -= 1;
        }
        i = if i == 0 { n - 1 } else { i - 1 };
    }
    v
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn commit_digest(fill: u8) -> CommitDigest {
    bcs::from_bytes(&[fill; 32]).unwrap()
}

fn commit_digest_from(bytes: [u8; 32]) -> CommitDigest {
    bcs::from_bytes(&bytes).unwrap()
}

struct Harness {
    tracker: TransactionVoteTracker,
    finalizer: CommitFinalizer,
    dag_state: Arc<RwLock<DagState>>,
    leader_schedule: Arc<LeaderSchedule>,
    committer: UniversalCommitter,
    linearizer: Linearizer,
    last_decided: Slot,
}

impl Harness {
    fn new(context: Arc<Context>) -> Self {
        let dag_state = Arc::new(RwLock::new(DagState::new(
            context.clone(),
            Arc::new(MemStore::new()),
        )));
        let leader_schedule = Arc::new(LeaderSchedule::new(
            context.clone(),
            LeaderSwapTable::default(),
        ));
        let committer = UniversalCommitterBuilder::new(
            context.clone(),
            leader_schedule.clone(),
            dag_state.clone(),
        )
        .with_number_of_leaders(1)
        .with_pipeline(true)
        .build();
        let linearizer = Linearizer::new(context.clone(), dag_state.clone());
        let last_decided = dag_state.read().last_commit_leader();
        let tracker = TransactionVoteTracker::new(
            context.clone(),
            Arc::new(NoopBlockVerifier {}),
            dag_state.clone(),
        );
        // The finalizer's output channel is unused: `finalize` below reads process_commit's result.
        let (commit_sender, commit_receiver) =
            mysten_metrics::monitored_mpsc::unbounded_channel("zui_vectors_commit_output");
        std::mem::forget(commit_receiver);
        let finalizer = CommitFinalizer::new(
            context.clone(),
            dag_state.clone(),
            tracker.clone(),
            commit_sender,
        );
        Self {
            tracker,
            finalizer,
            dag_state,
            leader_schedule,
            committer,
            linearizer,
            last_decided,
        }
    }

    /// `Core::try_commit` (v2 path, no certified commits) plus the CommitObserver's scoring step.
    /// `CommitFinalizer::run` for one sub-dag, inline: process_commit, then the tracker GC and
    /// the finalized commits recorded in DagState.
    async fn finalize(&mut self, subdag: CommittedSubDag) -> Vec<CommittedSubDag> {
        let finalized = self.finalizer.process_commit(subdag).await.expect("finalize");
        if let Some(last) = finalized.last() {
            let gc = self.dag_state.read().calculate_gc_round(last.leader.round);
            self.tracker.run_gc(gc);
            let mut ds = self.dag_state.write();
            for c in &finalized {
                ds.add_finalized_commit(c.commit_ref, c.rejected_transactions_by_block.clone());
            }
            ds.flush();
        }
        finalized
    }

    fn try_commit(&mut self) -> Vec<CommittedSubDag> {
        let mut out = vec![];
        loop {
            let mut until = self
                .leader_schedule
                .commits_until_leader_schedule_update(self.dag_state.clone());
            if until == 0 {
                self.leader_schedule
                    .update_leader_schedule_v2(&self.dag_state);
                until = self
                    .leader_schedule
                    .commits_until_leader_schedule_update(self.dag_state.clone());
            }
            assert!(until > 0);
            let mut decided = self.committer.try_decide(self.last_decided);
            if decided.len() >= until {
                let _ = decided.split_off(until);
            }
            let Some(last) = decided.last().cloned() else {
                break;
            };
            self.last_decided = last.slot();
            let leaders: Vec<VerifiedBlock> = decided
                .into_iter()
                .filter_map(|l| l.into_committed_block())
                .collect();
            if leaders.is_empty() {
                break;
            }
            let subdags = self.linearizer.handle_commit(leaders);
            self.dag_state
                .write()
                .add_scoring_subdags(subdags.clone());
            out.extend(subdags);
        }
        out
    }
}

fn emit_commits(w: &mut String, subdags: &[CommittedSubDag]) {
    for s in subdags {
        write!(
            w,
            "commit {} {} {} {} {} {}",
            s.commit_ref.index,
            hex(&s.commit_ref.digest.into_inner()),
            s.leader.round,
            s.leader.author.value(),
            s.timestamp_ms,
            s.blocks.len()
        )
        .unwrap();
        for b in &s.blocks {
            write!(w, " {}", hex(b.digest().as_ref())).unwrap();
        }
        w.push('\n');
    }
}

fn emit_finalized(w: &mut String, subdags: &[CommittedSubDag]) {
    for s in subdags {
        write!(w, "final {} {}", s.commit_ref.index, hex(&s.commit_ref.digest.into_inner())).unwrap();
        for (b, idx) in &s.rejected_transactions_by_block {
            write!(w, " {}:{}", hex(&bcs::to_bytes(b).unwrap()), csv(idx)).unwrap();
        }
        w.push('\n');
    }
}

/// Replays rounds of blocks through the harness and emits the scenario.
async fn replay(w: &mut String, name: &str, stakes: &[u64], shuffle: bool, layers: Vec<Vec<VerifiedBlock>>) {
    let n = stakes.len();
    let mut context = context_with_stakes(stakes);
    context.parameters.internal.skip_equivocation_validation = true;
    context
        .protocol_config
        .set_shuffle_commit_blocks_for_testing(shuffle);
    let context = Arc::new(context);
    let mut h = Harness::new(context.clone());

    writeln!(
        w,
        "scenario {} {} {} {} {} {}",
        name,
        n,
        context.protocol_config.gc_depth(),
        context.protocol_config.shuffle_commit_blocks() as u8,
        1,
        csv(stakes)
    )
    .unwrap();
    for g in &genesis_blocks(&context) {
        writeln!(w, "genesis {}", hex(g.digest().as_ref())).unwrap();
    }
    for blocks in layers {
        for b in &blocks {
            writeln!(w, "block {}", hex(b.serialized())).unwrap();
        }
        h.tracker
            .add_voted_blocks(blocks.iter().map(|b| (b.clone(), vec![])).collect());
        h.dag_state.write().accept_blocks(blocks);
        writeln!(w, "step").unwrap();
        let subdags = h.try_commit();
        emit_commits(w, &subdags);
        for sd in subdags {
            let fin = h.finalize(sd).await;
            emit_finalized(w, &fin);
        }
    }
    let table = h.leader_schedule.leader_swap_table.read();
    let range = &table.reputation_scores.commit_range;
    let good: Vec<usize> = table.good_nodes.iter().map(|(a, _, _)| a.value()).collect();
    let bad: Vec<usize> = table.bad_nodes.keys().map(|a| a.value()).collect();
    writeln!(
        w,
        "swap {} {} good={} bad={} scores={}",
        range.start(),
        range.start() + range.size() as u32,
        csv(&good),
        csv(&bad),
        csv(&table.reputation_scores.scores_per_authority)
    )
    .unwrap();
    writeln!(w, "end").unwrap();
}

fn builder_layers(b: &DagBuilder, rounds: Round) -> Vec<Vec<VerifiedBlock>> {
    (1..=rounds).map(|r| b.blocks(r..=r)).collect()
}

fn new_builder(stakes: &[u64]) -> DagBuilder {
    DagBuilder::new(Arc::new(context_with_stakes(stakes)))
}

/// Options of `gen_dag`, a stake-aware random DAG.
#[derive(Default)]
struct Gen {
    stakes: Vec<u64>,
    rounds: Round,
    seed: u64,
    /// Percent of blocks that always link the previous round's (round robin) leader.
    leader_link_pct: u32,
    /// Percent chance to also link another authority's latest older block (weak link).
    weak_link_pct: u32,
    /// (authority, first round, last round): no blocks from the authority in these rounds.
    offline: Vec<(u32, Round, Round)>,
    /// (authority, first round, last round): others do not link the authority's blocks of these rounds.
    ignored: Vec<(u32, Round, Round)>,
    /// (authority, round): the authority proposes two blocks in the round.
    equivocate: Vec<(u32, Round)>,
    random_ts: bool,
    payload: bool,
    /// Reject indices may reach this far past the target's transaction count (Byzantine votes;
    /// V2 votes are not verified). Debug builds of the Rust finalizer overflow on them.
    reject_overshoot: u16,
}

fn in_ranges(r: &[(u32, Round, Round)], a: u32, round: Round) -> bool {
    r.iter().any(|&(x, s, e)| x == a && round >= s && round <= e)
}

fn gen_dag(g: &Gen) -> Vec<Vec<VerifiedBlock>> {
    let n = g.stakes.len();
    let total: u64 = g.stakes.iter().sum();
    let quorum = total - (total - 1) / 3;
    let mut rng = StdRng::seed_from_u64(g.seed);
    let ctx = context_with_stakes(&g.stakes);
    let genesis = genesis_blocks(&ctx);
    // All blocks per authority (round ascending), the last one is "latest".
    let mut by_author: Vec<Vec<BlockRef>> = genesis.iter().map(|b| vec![b.reference()]).collect();
    let mut layers = vec![];
    let mut ntx_of: std::collections::HashMap<BlockRef, usize> = std::collections::HashMap::new();
    for r in 1..=g.rounds {
        let leader_prev = ((r - 1) as usize) % n;
        let mut layer = vec![];
        let mut new_refs: Vec<Vec<BlockRef>> = vec![vec![]; n];
        for a in 0..n {
            if in_ranges(&g.offline, a as u32, r) {
                continue;
            }
            let copies = if g.equivocate.contains(&(a as u32, r)) { 2 } else { 1 };
            for copy in 0..copies {
                // Own latest block first.
                let mut anc: Vec<BlockRef> = vec![*by_author[a].last().unwrap()];
                let mut stake = if anc[0].round == r - 1 { g.stakes[a] } else { 0 };
                let mut chosen = vec![false; n];
                chosen[a] = true;
                let mut others: Vec<usize> = (0..n).filter(|&x| x != a).collect();
                others.shuffle(&mut rng);
                if leader_prev != a && rng.gen_range(0..100) < g.leader_link_pct {
                    others.retain(|&x| x != leader_prev);
                    others.insert(0, leader_prev);
                }
                // Parents at r - 1 in that order until the quorum is reached; the wanted leader
                // (first in the list) is always taken.
                for (k, &o) in others.iter().enumerate() {
                    if stake >= quorum && k > 0 {
                        break;
                    }
                    let cand: Vec<BlockRef> = by_author[o]
                        .iter()
                        .filter(|b| b.round == r - 1 && !in_ranges(&g.ignored, o as u32, b.round))
                        .cloned()
                        .collect();
                    if let Some(b) = cand.choose(&mut rng) {
                        anc.push(*b);
                        chosen[o] = true;
                        stake += g.stakes[o];
                    }
                }
                assert!(stake >= quorum, "round {r} authority {a}: no parent quorum");
                // Weak links to older latest blocks.
                for o in 0..n {
                    if chosen[o] || rng.gen_range(0..100) >= g.weak_link_pct {
                        continue;
                    }
                    if let Some(b) = by_author[o]
                        .iter()
                        .rev()
                        .find(|b| b.round < r && !in_ranges(&g.ignored, o as u32, b.round))
                    {
                        anc.push(*b);
                        chosen[o] = true;
                    }
                }
                let ts = r as u64 * 1000
                    + if g.random_ts {
                        rng.gen_range(0..1000)
                    } else {
                        a as u64 + copy as u64
                    };
                let mut tb = TestBlock::new(r, a as u32)
                    .set_ancestors_raw(anc.clone())
                    .set_timestamp_ms(ts);
                if g.payload || copy > 0 {
                    let ntx = rng.gen_range(0..4) + copy as usize;
                    let txs: Vec<Transaction> = (0..ntx)
                        .map(|_| {
                            let len = rng.gen_range(1..48);
                            Transaction::new((0..len).map(|_| rng.r#gen::<u8>()).collect())
                        })
                        .collect();
                    // Reject votes on parents: every voter rejects transaction 0 of authority 1's
                    // blocks (so quorum rejections happen), plus random rejects on some others
                    // (past the target's transaction count only with `reject_overshoot`).
                    let mut votes = vec![];
                    for b in anc.iter().skip(1) {
                        let target_txs = *ntx_of.get(b).unwrap_or(&0);
                        let mut rejects: Vec<TransactionIndex> = vec![];
                        if b.author.value() == 1 && target_txs > 0 && b.round % 4 != 0 {
                            rejects.push(0);
                        }
                        if target_txs > 0 && rng.gen_range(0..100) < 20 {
                            for _ in 0..rng.gen_range(1..3) {
                                rejects.push(rng.gen_range(0..target_txs as u16 + g.reject_overshoot));
                            }
                        }
                        rejects.sort();
                        rejects.dedup();
                        if !rejects.is_empty() {
                            votes.push(BlockTransactionVotes { block_ref: *b, rejects });
                        }
                    }
                    let cvotes: Vec<CommitRef> = (0..rng.gen_range(0..3))
                        .map(|_| CommitRef::new(rng.gen_range(1..1000), commit_digest_from(rng.r#gen())))
                        .collect();
                    tb = tb
                        .set_transactions(txs)
                        .set_transaction_votes(votes)
                        .set_commit_votes(cvotes);
                }
                let vb = VerifiedBlock::new_for_test(tb.build());
                ntx_of.insert(vb.reference(), vb.transactions().len());
                new_refs[a].push(vb.reference());
                layer.push(vb);
            }
        }
        for a in 0..n {
            by_author[a].extend(new_refs[a].iter().cloned());
        }
        layers.push(layer);
    }
    layers
}

/// mainnet 141 consensus protocol values (`to_consensus_protocol_config` at 141 on Mainnet).
fn mainnet_141(context: &mut Context) {
    let pc = &mut context.protocol_config;
    pc.set_max_transaction_size_bytes_for_testing(262_144);
    pc.set_max_transactions_in_block_bytes_for_testing(294_912);
    pc.set_max_num_transactions_in_block_for_testing(128);
    pc.set_gc_depth_for_testing(60);
    pc.set_transaction_voting_enabled_for_testing(true);
    pc.set_num_leaders_per_round_for_testing(Some(1));
    pc.set_bad_nodes_stake_threshold_for_testing(30);
    pc.set_enable_v3_for_testing(false);
    pc.set_shuffle_commit_blocks_for_testing(false);
}

fn protocol_keypair(i: usize) -> ProtocolKeyPair {
    let sk = Ed25519PrivateKey::from_bytes(&[(i + 1) as u8; 32]).unwrap();
    ProtocolKeyPair::new(Ed25519KeyPair::from(sk))
}

fn verify_vectors(w: &mut String) {
    let stakes = vec![1u64, 2, 3, 4];
    let epoch = 7u64;
    let epoch_start = 1_700_000_000_123u64;
    let (committee, _) = local_committee_and_keys_with_test_options(epoch, stakes.clone(), false);
    let auths: Vec<_> = committee
        .authorities()
        .map(|(i, a)| {
            let mut a = a.clone();
            a.protocol_key = protocol_keypair(i.value()).public();
            a
        })
        .collect();
    let committee = Committee::new(epoch, auths);
    let (context, _) = Context::new_for_test(stakes.len());
    let mut context = context
        .with_committee(committee)
        .with_epoch_start_timestamp_ms(epoch_start);
    mainnet_141(&mut context);
    let context = Arc::new(context);
    writeln!(w, "vcommittee {} {} {}", epoch, epoch_start, csv(&stakes)).unwrap();
    let genesis = genesis_blocks(&context);
    for g in &genesis {
        writeln!(w, "vgenesis {}", hex(g.digest().as_ref())).unwrap();
    }
    let g: Vec<BlockRef> = genesis.iter().map(|b| b.reference()).collect();
    let verifier = SignedBlockVerifier::new(context.clone(), Arc::new(NoopTransactionVerifier));

    let emit_bytes = |w: &mut String, name: &str, bytes: Vec<u8>| {
        let verdict = match bcs::from_bytes::<SignedBlock>(&bytes) {
            Err(_) => "malformed".to_string(),
            Ok(sb) => match verifier.verify_and_vote(sb, Bytes::from(bytes.clone())) {
                Ok(_) => "ok".to_string(),
                Err(e) => {
                    let d = format!("{e:?}");
                    d.split(|c: char| !c.is_alphanumeric()).next().unwrap().to_string()
                }
            },
        };
        writeln!(w, "verify {} {} {}", name, verdict, hex(&bytes)).unwrap();
    };
    let emit = |w: &mut String, name: &str, block: Block, signer: usize| {
        let sb = SignedBlock::new(block, &protocol_keypair(signer)).unwrap();
        emit_bytes(w, name, sb.serialize().unwrap().to_vec());
    };
    let v2 = |round: Round, author: u32, anc: Vec<BlockRef>| {
        TestBlock::new(round, author)
            .set_epoch(epoch)
            .set_timestamp_ms(epoch_start + round as u64)
            .set_ancestors_raw(anc)
    };
    let tx = |len: usize, fill: u8| Transaction::new(vec![fill; len]);
    // Author 3 (stake 4) with authorities 3, 2, 1 at genesis: 9 >= quorum 7 of total 10.
    let q = vec![g[3], g[2], g[1]];
    emit(w, "ok-quorum", v2(1, 3, q.clone()).build(), 3);
    emit(w, "ok-all", v2(1, 3, vec![g[3], g[0], g[1], g[2]]).build(), 3);
    emit(
        w,
        "ok-v1",
        Block::V1(BlockV1::new(epoch, 1, AuthorityIndex::new_for_test(3), epoch_start, q.clone(), vec![tx(10, 1)], vec![], vec![])),
        3,
    );
    emit(w, "v3-off", v2(1, 3, q.clone()).build_v3(0), 3);
    emit(w, "wrong-epoch", v2(1, 3, q.clone()).set_epoch(8).build(), 3);
    emit(w, "genesis-round", v2(0, 3, q.clone()).build(), 3);
    emit(w, "bad-author", v2(1, 4, q.clone()).build(), 3);
    emit(w, "wrong-signer", v2(1, 3, q.clone()).build(), 2);
    {
        let sb = SignedBlock::new(v2(1, 3, q.clone()).build(), &protocol_keypair(3)).unwrap();
        let mut bytes = sb.serialize().unwrap().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        emit_bytes(w, "flipped-signature", bytes.clone());
        // Signature of 63 bytes: shorten the length prefix and drop a byte.
        let mut short = bytes.clone();
        short.truncate(last);
        let len_pos = short.len() - 63 - 1;
        assert_eq!(short[len_pos], 64);
        short[len_pos] = 63;
        emit_bytes(w, "short-signature", short);
        let mut trailing = sb.serialize().unwrap().to_vec();
        trailing.push(0);
        emit_bytes(w, "trailing-byte", trailing);
        let mut cut = sb.serialize().unwrap().to_vec();
        cut.pop();
        emit_bytes(w, "truncated", cut);
        let mut tag = sb.serialize().unwrap().to_vec();
        tag[0] = 3;
        emit_bytes(w, "bad-variant", tag);
    }
    let mut too_many = vec![g[3], g[0], g[1], g[2]];
    too_many.push(BlockRef::new(0, AuthorityIndex::new_for_test(0), BlockDigest::MIN));
    emit(w, "too-many-ancestors", v2(1, 3, too_many).build(), 3);
    emit(w, "no-ancestors", v2(1, 3, vec![]).build(), 3);
    emit(
        w,
        "ancestor-bad-author",
        v2(1, 3, vec![g[3], g[2], BlockRef::new(0, AuthorityIndex::new_for_test(9), BlockDigest::MIN)]).build(),
        3,
    );
    emit(w, "own-not-first", v2(1, 3, vec![g[2], g[3], g[1]]).build(), 3);
    emit(w, "own-twice", v2(1, 3, vec![g[3], g[2], g[3]]).build(), 3);
    let r1 = BlockRef::new(1, AuthorityIndex::new_for_test(2), BlockDigest([5; 32]));
    emit(w, "ancestor-same-round", v2(1, 3, vec![g[3], r1, g[1]]).build(), 3);
    emit(
        w,
        "bad-genesis-ancestor",
        v2(1, 3, vec![g[3], g[2], BlockRef::new(0, AuthorityIndex::new_for_test(1), BlockDigest([9; 32]))]).build(),
        3,
    );
    emit(w, "duplicate-author", v2(1, 3, vec![g[3], g[2], g[2], g[1]]).build(), 3);
    // Total stake 10: f = 3, quorum 7.
    emit(w, "parent-stake-at-quorum", v2(1, 3, vec![g[3], g[2]]).build(), 3);
    emit(w, "low-parent-stake", v2(1, 3, vec![g[3], g[1]]).build(), 3);
    // Round 3 with round-2 parents of stake 4 + 2 and an old round-1 ref: 6 < 7.
    let p = |r: Round, a: u32, f: u8| BlockRef::new(r, AuthorityIndex::new_for_test(a), BlockDigest([f; 32]));
    emit(w, "old-parent-no-quorum", v2(3, 3, vec![p(2, 3, 1), p(2, 1, 2), p(1, 2, 3)]).build(), 3);
    emit(w, "parents-quorum-r3", v2(3, 3, vec![p(2, 3, 1), p(2, 2, 2), p(2, 1, 3), p(1, 0, 4)]).build(), 3);
    emit(w, "tx-max-size", v2(1, 3, q.clone()).set_transactions(vec![tx(262_144, 7)]).build(), 3);
    emit(w, "tx-too-large", v2(1, 3, q.clone()).set_transactions(vec![tx(262_145, 7)]).build(), 3);
    emit(w, "tx-max-count", v2(1, 3, q.clone()).set_transactions((0..128).map(|i| tx(3, i as u8)).collect()).build(), 3);
    emit(w, "tx-too-many", v2(1, 3, q.clone()).set_transactions((0..129).map(|i| tx(3, i as u8)).collect()).build(), 3);
    emit(w, "tx-max-bytes", v2(1, 3, q.clone()).set_transactions(vec![tx(262_144, 1), tx(294_912 - 262_144, 2)]).build(), 3);
    emit(w, "tx-too-many-bytes", v2(1, 3, q.clone()).set_transactions(vec![tx(262_144, 1), tx(294_912 - 262_144 + 1, 2)]).build(), 3);
    // V2 transaction votes are not checked without V3, whatever they say.
    emit(
        w,
        "v2-odd-votes",
        v2(1, 3, q.clone())
            .set_transaction_votes(vec![
                BlockTransactionVotes { block_ref: p(9, 9, 9), rejects: vec![5, 5, 1] },
                BlockTransactionVotes { block_ref: p(9, 9, 9), rejects: vec![] },
            ])
            .set_commit_votes(vec![CommitRef::new(3, commit_digest(4)), CommitRef::new(1, commit_digest(2))])
            .build(),
        3,
    );
}

/// BCS of fixed values; the deepwave suite builds the same values and compares bytes.
fn bcs_vectors(w: &mut String) {
    let br = BlockRef::new(0x0102_0304, AuthorityIndex::new_for_test(5), BlockDigest([0xab; 32]));
    writeln!(w, "bcs blockref {}", hex(&bcs::to_bytes(&br).unwrap())).unwrap();
    let cr = CommitRef::new(0x0a0b_0c0d, commit_digest(0xcd));
    writeln!(w, "bcs commitref {}", hex(&bcs::to_bytes(&cr).unwrap())).unwrap();
    let mr = MisbehaviorReport { target: AuthorityIndex::new_for_test(3), proof: MisbehaviorProof::InvalidBlock(br) };
    writeln!(w, "bcs misbehavior {}", hex(&bcs::to_bytes(&mr).unwrap())).unwrap();
    let tv = BlockTransactionVotes { block_ref: br, rejects: vec![0, 7, 300] };
    writeln!(w, "bcs txvotes {}", hex(&bcs::to_bytes(&tv).unwrap())).unwrap();
    let commit = Commit::new(
        42,
        commit_digest(0x11),
        1_700_000_000_999,
        br,
        vec![
            BlockRef::new(7, AuthorityIndex::new_for_test(1), BlockDigest([1; 32])),
            BlockRef::new(8, AuthorityIndex::new_for_test(0), BlockDigest([2; 32])),
            br,
        ],
    );
    writeln!(w, "bcs commit {}", hex(&commit.serialize().unwrap())).unwrap();
    let anc = vec![br, BlockRef::new(9, AuthorityIndex::new_for_test(2), BlockDigest([3; 32]))];
    let txs = vec![Transaction::new(vec![]), Transaction::new(vec![1, 2, 3])];
    let cvotes = vec![cr];
    let b1 = Block::V1(BlockV1::new(3, 10, AuthorityIndex::new_for_test(5), 99, anc.clone(), txs.clone(), cvotes.clone(), vec![mr.clone()]));
    let base = TestBlock::new(10, 5)
        .set_epoch(3)
        .set_timestamp_ms(99)
        .set_ancestors_raw(anc.clone())
        .set_transactions(txs.clone())
        .set_transaction_votes(vec![tv.clone()])
        .set_commit_votes(cvotes.clone());
    let b2 = base.clone().build();
    let b3 = base.build_v3(4);
    for (kind, b) in [("blockv1", b1), ("blockv2", b2), ("blockv3", b3)] {
        writeln!(w, "bcs {} {}", kind, hex(&bcs::to_bytes(&b).unwrap())).unwrap();
        // SignedBlock with a real signature (key seed [6; 32]) and its digest.
        let sb = SignedBlock::new(b, &protocol_keypair(5)).unwrap();
        let ser = sb.serialize().unwrap();
        writeln!(w, "bcs signed-{} {}", kind, hex(&ser)).unwrap();
        writeln!(w, "bcs digest-{} {}", kind, hex(VerifiedBlock::compute_digest(&ser).as_ref())).unwrap();
    }
    let range = CommitRange::new(301..=600);
    let scores = ReputationScores::new(range, vec![5, 0, 18_446_744_073_709_551_615]);
    writeln!(w, "bcs scores {}", hex(&bcs::to_bytes(&scores).unwrap())).unwrap();
}

fn order_vectors(w: &mut String) {
    let mut rng = StdRng::seed_from_u64(77);
    let mut refs: Vec<BlockRef> = (0..64)
        .map(|_| {
            let mut d = [0u8; 32];
            d[0] = rng.gen_range(0..3);
            d[31] = rng.r#gen();
            BlockRef::new(rng.gen_range(0..4), AuthorityIndex::new_for_test(rng.gen_range(0..3)), BlockDigest(d))
        })
        .collect();
    refs.sort();
    let parts: Vec<String> = refs.iter().map(|r| hex(&bcs::to_bytes(r).unwrap())).collect();
    writeln!(w, "order {}", parts.join(" ")).unwrap();
}

fn swap_vectors(w: &mut String) {
    let cases: Vec<(Vec<u64>, Vec<u64>, u32, u64)> = vec![
        // (stakes, scores, commit index, threshold)
        (vec![1; 7], vec![10, 10, 10, 10, 10, 10, 10], 300, 30),
        (vec![1; 7], vec![3, 9, 1, 9, 0, 5, 1], 600, 30),
        (vec![1; 4], vec![0, 1, 2, 3], 10, 33),
        (vec![1, 2, 3, 4, 5, 6, 7], vec![70, 0, 70, 70, 0, 5, 70], 900, 30),
        (vec![1, 2, 3, 4, 5, 6, 7], vec![1, 2, 3, 4, 5, 6, 7], 300, 20),
        (mainnet_like_stakes(20), (0..20u64).map(|i| (i * 7919) % 13).collect(), 1200, 30),
        (mainnet_like_stakes(100), (0..100u64).map(|i| (i * 104_729) % 17).collect(), 300, 30),
        (mainnet_like_stakes(100), vec![42; 100], 3000, 30),
        (mainnet_like_stakes(100), (0..100u64).map(|i| (i * 31) % 5).collect(), 7, 0),
    ];
    for (stakes, scores, commit_index, threshold) in cases {
        let mut ctx = context_with_stakes(&stakes);
        ctx.protocol_config.set_bad_nodes_stake_threshold_for_testing(threshold);
        let ctx = Arc::new(ctx);
        let rs = ReputationScores::new(CommitRange::new(commit_index.saturating_sub(299)..=commit_index), scores.clone());
        let table = LeaderSwapTable::new(ctx.clone(), commit_index, rs);
        let good: Vec<usize> = table.good_nodes.iter().map(|(a, _, _)| a.value()).collect();
        let bad: Vec<usize> = table.bad_nodes.keys().map(|a| a.value()).collect();
        writeln!(
            w,
            "swaptable {} {} stakes={} scores={} good={} bad={}",
            commit_index,
            threshold,
            csv(&stakes),
            csv(&scores),
            csv(&good),
            csv(&bad)
        )
        .unwrap();
        for leader in 0..stakes.len() {
            for round in [0u32, 1, 2, 3, 17, 300, 65_536, 1_000_003] {
                let leader = AuthorityIndex::new_for_test(leader as u32);
                let s = if table.good_nodes.is_empty() && table.bad_nodes.contains_key(&leader) {
                    "-".to_string() // Rust panics; not a vector
                } else {
                    match table.swap(leader, round, 0) {
                        Some(a) => a.value().to_string(),
                        None => "-".to_string(),
                    }
                };
                writeln!(w, "swapsel {} {} {}", leader.value(), round, s).unwrap();
            }
        }
    }
}

#[tokio::test]
async fn zui_consensus_vectors() {
    let out_path = match std::env::var("ZUI_VECTORS_OUT") {
        Ok(p) => p,
        Err(_) => return, // only produces vectors when asked to
    };
    let mut w = String::new();

    // A: four authorities, fully connected (shuffled and mainnet's authority order).
    let mut b = new_builder(&[1; 4]);
    b.layers(1..=40).build();
    replay(&mut w, "full4", &[1; 4], true, builder_layers(&b, 40)).await;
    replay(&mut w, "full4-noshuffle", &[1; 4], false, builder_layers(&b, 40)).await;

    // B: seven authorities, each block links to 2f+1 random parents and the previous leader.
    let mut b = new_builder(&[1; 7]);
    for r in 1..=60u32 {
        b.layer(r).min_ancestor_links(true, Some(11 + r as u64));
    }
    replay(&mut w, "minlinks7", &[1; 7], true, builder_layers(&b, 60)).await;

    // C: the leader block of every fifth round is never proposed.
    let mut b = new_builder(&[1; 4]);
    for r in 1..=40u32 {
        if r % 5 == 0 {
            b.layer(r).no_leader_block(vec![]).build();
        } else {
            b.layer(r).build();
        }
    }
    replay(&mut w, "noleader4", &[1; 4], true, builder_layers(&b, 40)).await;
    replay(&mut w, "noleader4-noshuffle", &[1; 4], false, builder_layers(&b, 40)).await;

    // D: every third round's blocks omit the link to the previous round's leader.
    let mut b = new_builder(&[1; 4]);
    b.layer(1).build();
    for r in 2..=40u32 {
        if r % 3 == 0 {
            b.layer(r).no_leader_link(r - 1, vec![]);
        } else {
            b.layer(r).build();
        }
    }
    replay(&mut w, "noleaderlink4", &[1; 4], true, builder_layers(&b, 40)).await;

    // E: long run with random 2f+1 links (the leader most rounds): two leader schedule updates.
    let mut b = new_builder(&[1; 7]);
    for r in 1..=700u32 {
        b.layer(r).min_ancestor_links(r % 9 != 0, Some(5 + r as u64));
    }
    replay(&mut w, "long7", &[1; 7], true, builder_layers(&b, 700)).await;

    // Stake-aware random DAGs (gen_dag): quorum by stake, median timestamp by stake, reputation
    // thresholds by stake, offline and ignored authorities, GC pruning, equivocations, payloads.
    let skew7: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7];
    let near7: Vec<u64> = vec![100, 101, 99, 100, 102, 98, 100];
    let main20 = mainnet_like_stakes(20);
    let cases: Vec<(&str, bool, Gen)> = vec![
        ("skew7", true, Gen { stakes: skew7.clone(), rounds: 120, seed: 21, leader_link_pct: 85, weak_link_pct: 10, random_ts: true, ..Default::default() }),
        ("skew7-noshuffle", false, Gen { stakes: skew7.clone(), rounds: 120, seed: 22, leader_link_pct: 85, weak_link_pct: 10, random_ts: true, ..Default::default() }),
        ("near7", true, Gen { stakes: near7.clone(), rounds: 120, seed: 33, leader_link_pct: 70, weak_link_pct: 20, random_ts: true, payload: true, ..Default::default() }),
        ("mainnet20", false, Gen { stakes: main20.clone(), rounds: 700, seed: 7, leader_link_pct: 90, weak_link_pct: 5, random_ts: true, payload: true, ..Default::default() }),
        ("offline10", false, Gen {
            stakes: vec![1; 10], rounds: 700, seed: 101, leader_link_pct: 95, weak_link_pct: 5, random_ts: true,
            offline: vec![(2, 1, 700), (5, 50, 400), (9, 300, 650)], ..Default::default()
        }),
        ("gc7", true, Gen {
            stakes: vec![1; 7], rounds: 400, seed: 55, leader_link_pct: 100, weak_link_pct: 0,
            ignored: vec![(6, 20, 150), (1, 200, 330)], ..Default::default()
        }),
        ("gc7-noshuffle", false, Gen {
            stakes: vec![1; 7], rounds: 400, seed: 56, leader_link_pct: 100, weak_link_pct: 30, random_ts: true,
            ignored: vec![(6, 20, 150), (1, 200, 330)], ..Default::default()
        }),
        ("equiv7", true, Gen {
            stakes: vec![1; 7], rounds: 150, seed: 66, leader_link_pct: 80, weak_link_pct: 10, payload: true,
            equivocate: vec![(3, 10), (3, 11), (4, 40), (6, 41), (0, 70), (1, 100), (2, 101)], ..Default::default()
        }),
        // Byzantine reject votes: indices past the target block's transaction count. V2 votes are
        // not verified, so Mysten validators process them; release builds (no overflow checks,
        // as run.sh sets for this test) are what a validator runs.
        ("byzvotes7", false, Gen {
            stakes: vec![1; 7], rounds: 150, seed: 77, leader_link_pct: 90, weak_link_pct: 10, payload: true,
            reject_overshoot: 3, ..Default::default()
        }),
    ];
    for (name, shuffle, g) in cases {
        let layers = gen_dag(&g);
        replay(&mut w, name, &g.stakes, shuffle, layers).await;
    }

    // Stake-based election (non-test code path), straight from LeaderSchedule: equal stakes and
    // weighted committees (f64 pow, f32 stake conversion).
    let mut elect_sets: Vec<Vec<u64>> = vec![vec![1; 4], vec![1; 7], vec![1; 10], skew7.clone(), near7.clone()];
    elect_sets.push(mainnet_like_stakes(20));
    elect_sets.push(mainnet_like_stakes(100));
    elect_sets.push(mainnet_like_stakes(128));
    for stakes in elect_sets {
        let n = stakes.len();
        let ls = LeaderSchedule::new(Arc::new(context_with_stakes(&stakes)), LeaderSwapTable::default());
        let rounds: Vec<u32> = (0..200u32).chain([1_000, 65_535, 65_536, 1_000_000, u32::MAX - 1]).collect();
        for round in rounds {
            for offset in 0..2u32 {
                let a = ls.elect_leader_stake_based(round, offset);
                writeln!(w, "elect {} {} {} {} {}", n, round, offset, a.value(), csv(&stakes)).unwrap();
            }
        }
    }

    swap_vectors(&mut w);
    verify_vectors(&mut w);
    bcs_vectors(&mut w);
    order_vectors(&mut w);

    std::fs::write(out_path, w).expect("write vectors");
}
