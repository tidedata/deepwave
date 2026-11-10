// Speed baseline for deepwave's validator bench (docs/VALIDATOR-SPEED.md, stages 3 and 4): Mysten's
// consensus-core at mainnet-v1.83.1, in process, no network.
//
// Dropped into `consensus/core/src/` of a sui checkout by ../run.sh and registered as
// `#[cfg(test)] mod zui_val_bench;` in lib.rs (UniversalCommitter, BlockManager, SignedBlock::new
// and SignedBlockVerifier are crate-private). Everything timed below is Mysten's own code; this
// file only builds the inputs and the clock around the calls.
//
// Stage 3, commit decision. Seeded DAGs (committee 4, 10 and 100; the same generator as
// tools/truth/consensus/committer-vectors, with offline authorities for leader timeouts and
// missing blocks) are replayed round by round through BlockManager::try_accept_blocks, the
// pipelined UniversalCommitter (try_decide), the Linearizer and the CommitFinalizer, as
// Core::add_blocks + Core::try_commit + the CommitObserver do. One timed item is one round of
// blocks (a "step"). The replay is written in the committer-vectors text format
// (`<out>/consensus/val-bench/<case>.vec`) so deepwave replays the very same blocks and checks every
// commit line.
//
// Stage 4, block verification and proposal. For committee sizes 10 and 100, blocks of mainnet 141
// shape (V2, transaction votes on) with 16 transactions of 200..2000 bytes ("light") or 128
// transactions of ~2 KB ("full") are created: BlockV2::new, SignedBlock::new (Ed25519 over the
// intent digest), serialize, VerifiedBlock::new_verified (digest). The serialized blocks are then
// verified as authority_service does: bcs::from_bytes::<SignedBlock> then
// SignedBlockVerifier::verify_and_vote (NoopTransactionVerifier: user transactions are stage 1).
// Protocol key of authority i is Ed25519 from seed [i + 1; 32]. Written to
// `<out>/consensus/val-bench/blocks-<case>.vec`:
//   bcommittee <n> <epoch> <epoch_start_ms> <stakes csv>
//   bgenesis <hex digest>                      (n times)
//   bblock <hex serialized SignedBlock>        in creation order
//
// Timing lines (stdout and `<out>/consensus/val-bench/rust.jsonl`), one per measurement:
//   {"impl":"rust","stage":..,"case":..,"threads":..,"unit":..,"items":..,"p50_ns":..,"p99_ns":..,
//    "mean_ns":..,"per_s":..,"out":<blake2b-256 hex of the canonical output lines>}
//
// Run: ZUI_VALBENCH_OUT=<corpus> cargo test --release -p consensus-core --lib zui_val_bench -- --nocapture --test-threads=1

use std::{collections::HashMap, fmt::Write as _, sync::Arc, time::Instant};

use bytes::Bytes;
use consensus_config::{
    AuthorityIndex, Committee, ProtocolKeyPair, local_committee_and_keys_with_test_options,
};
use consensus_types::block::{BlockRef, Round, TransactionIndex};
use fastcrypto::{
    ed25519::{Ed25519KeyPair, Ed25519PrivateKey},
    hash::{Blake2b256, HashFunction as _},
    traits::ToFromBytes as _,
};
use parking_lot::RwLock;
use rand::{Rng as _, SeedableRng as _, prelude::SliceRandom as _, rngs::StdRng};

use crate::{
    block::{
        Block, BlockAPI, BlockTransactionVotes, BlockV2, SignedBlock, Slot, TestBlock,
        Transaction, VerifiedBlock, genesis_blocks,
    },
    block_manager::BlockManager,
    block_verifier::{BlockVerifier, NoopBlockVerifier, SignedBlockVerifier},
    commit::{CommitDigest, CommitRef, CommittedSubDag},
    commit_finalizer::CommitFinalizer,
    context::Context,
    dag_state::DagState,
    leader_schedule::{LeaderSchedule, LeaderSwapTable},
    linearizer::Linearizer,
    storage::mem_store::MemStore,
    transaction::NoopTransactionVerifier,
    transaction_vote_tracker::TransactionVoteTracker,
    universal_committer::{
        UniversalCommitter, universal_committer_builder::UniversalCommitterBuilder,
    },
};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

fn csv<T: ToString>(v: &[T]) -> String {
    v.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(",")
}

fn digest_hex(text: &str) -> String {
    hex(&Blake2b256::digest(text.as_bytes()).digest)
}

fn out_dir() -> std::path::PathBuf {
    let root = std::env::var("ZUI_VALBENCH_OUT").expect("set ZUI_VALBENCH_OUT to the corpus dir");
    let d = std::path::Path::new(&root).join("consensus").join("val-bench");
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Percentiles of per-item nanoseconds, nearest rank.
fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let k = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[k.clamp(1, sorted.len()) - 1]
}

struct Line<'a> {
    stage: &'a str,
    case: &'a str,
    threads: usize,
    unit: &'a str,
    /// Per-item times (ns); empty when only a wall time is known (parallel runs).
    items: Vec<u64>,
    count: u64,
    wall_ns: u64,
    out: String,
    extra: String,
}

fn emit(log: &mut String, l: Line) {
    let mut t = l.items.clone();
    t.sort_unstable();
    let sum: u64 = t.iter().sum();
    let mean = if t.is_empty() { l.wall_ns as f64 / l.count.max(1) as f64 } else { sum as f64 / t.len() as f64 };
    let per_s = if l.wall_ns > 0 { l.count as f64 * 1e9 / l.wall_ns as f64 } else { 0.0 };
    let s = format!(
        "{{\"impl\":\"rust\",\"stage\":\"{}\",\"case\":\"{}\",\"threads\":{},\"unit\":\"{}\",\"items\":{},\"p50_ns\":{},\"p99_ns\":{},\"mean_ns\":{:.1},\"per_s\":{:.1},\"out\":\"{}\"{}}}",
        l.stage,
        l.case,
        l.threads,
        l.unit,
        l.count,
        pct(&t, 50.0),
        pct(&t, 99.0),
        mean,
        per_s,
        l.out,
        l.extra
    );
    println!("{s}");
    log.push_str(&s);
    log.push('\n');
}

fn context_with_stakes(stakes: &[u64]) -> Context {
    let (context, _keys) = Context::new_for_test(stakes.len());
    let (committee, _) = local_committee_and_keys_with_test_options(0, stakes.to_vec(), false);
    context.with_committee(committee)
}

/// Mainnet-like stakes: a few large validators and a long tail (sums to 10_000).
fn mainnet_like_stakes(n: usize) -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(1304);
    let raw: Vec<f64> = (0..n).map(|i| 1.0 / (1.0 + i as f64 * 0.08) + rng.gen_range(0.0..0.05)).collect();
    let total: f64 = raw.iter().sum();
    let mut s: Vec<u64> = raw.iter().map(|x| ((x / total) * 10_000.0).floor().max(1.0) as u64).collect();
    let sum: u64 = s.iter().sum();
    s[0] += 10_000 - sum;
    s
}

fn commit_digest_from(bytes: [u8; 32]) -> CommitDigest {
    bcs::from_bytes(&bytes).unwrap()
}

// ------------------------------------------------------------------------------------- stage 3

struct Harness {
    block_manager: BlockManager,
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
        let dag_state = Arc::new(RwLock::new(DagState::new(context.clone(), Arc::new(MemStore::new()))));
        let leader_schedule = Arc::new(LeaderSchedule::new(context.clone(), LeaderSwapTable::default()));
        let committer = UniversalCommitterBuilder::new(context.clone(), leader_schedule.clone(), dag_state.clone())
            .with_number_of_leaders(1)
            .with_pipeline(true)
            .build();
        let linearizer = Linearizer::new(context.clone(), dag_state.clone());
        let last_decided = dag_state.read().last_commit_leader();
        let tracker = TransactionVoteTracker::new(context.clone(), Arc::new(NoopBlockVerifier {}), dag_state.clone());
        let (commit_sender, commit_receiver) =
            mysten_metrics::monitored_mpsc::unbounded_channel("zui_val_bench_commit_output");
        std::mem::forget(commit_receiver);
        let finalizer = CommitFinalizer::new(context.clone(), dag_state.clone(), tracker.clone(), commit_sender);
        let block_manager = BlockManager::new(context.clone(), dag_state.clone());
        Self { block_manager, tracker, finalizer, dag_state, leader_schedule, committer, linearizer, last_decided }
    }

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

    /// `Core::try_commit` (no certified commits) plus the CommitObserver's scoring step.
    fn try_commit(&mut self) -> Vec<CommittedSubDag> {
        let mut out = vec![];
        loop {
            let mut until = self.leader_schedule.commits_until_leader_schedule_update(self.dag_state.clone());
            if until == 0 {
                self.leader_schedule.update_leader_schedule_v2(&self.dag_state);
                until = self.leader_schedule.commits_until_leader_schedule_update(self.dag_state.clone());
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
            let leaders: Vec<VerifiedBlock> = decided.into_iter().filter_map(|l| l.into_committed_block()).collect();
            if leaders.is_empty() {
                break;
            }
            let subdags = self.linearizer.handle_commit(leaders);
            self.dag_state.write().add_scoring_subdags(subdags.clone());
            out.extend(subdags);
        }
        out
    }
}

fn commit_line(s: &CommittedSubDag) -> String {
    let mut w = format!(
        "commit {} {} {} {} {} {}",
        s.commit_ref.index,
        hex(&s.commit_ref.digest.into_inner()),
        s.leader.round,
        s.leader.author.value(),
        s.timestamp_ms,
        s.blocks.len()
    );
    for b in &s.blocks {
        write!(w, " {}", hex(b.digest().as_ref())).unwrap();
    }
    w
}

fn final_line(s: &CommittedSubDag) -> String {
    let mut w = format!("final {} {}", s.commit_ref.index, hex(&s.commit_ref.digest.into_inner()));
    for (b, idx) in &s.rejected_transactions_by_block {
        write!(w, " {}:{}", hex(&bcs::to_bytes(b).unwrap()), csv(idx)).unwrap();
    }
    w
}

#[derive(Default)]
struct Gen {
    stakes: Vec<u64>,
    rounds: Round,
    seed: u64,
    leader_link_pct: u32,
    weak_link_pct: u32,
    /// (authority, first round, last round): no blocks from the authority in these rounds.
    offline: Vec<(u32, Round, Round)>,
    /// (authority, first round, last round): others do not link the authority's blocks of these rounds.
    ignored: Vec<(u32, Round, Round)>,
    payload: bool,
}

fn in_ranges(r: &[(u32, Round, Round)], a: u32, round: Round) -> bool {
    r.iter().any(|&(x, s, e)| x == a && round >= s && round <= e)
}

/// Stake-aware random DAG (the committer-vectors generator): each block links its own previous
/// block, then random authorities of the previous round until a quorum, optionally the previous
/// round's round-robin leader first, plus weak links to older blocks; payloads carry transactions,
/// reject votes and commit votes.
fn gen_dag(g: &Gen) -> Vec<Vec<VerifiedBlock>> {
    let n = g.stakes.len();
    let total: u64 = g.stakes.iter().sum();
    let quorum = total - (total - 1) / 3;
    let mut rng = StdRng::seed_from_u64(g.seed);
    let ctx = context_with_stakes(&g.stakes);
    let genesis = genesis_blocks(&ctx);
    let mut by_author: Vec<Vec<BlockRef>> = genesis.iter().map(|b| vec![b.reference()]).collect();
    let mut layers = vec![];
    let mut ntx_of: HashMap<BlockRef, usize> = HashMap::new();
    for r in 1..=g.rounds {
        let leader_prev = ((r - 1) as usize) % n;
        let mut layer = vec![];
        let mut new_refs: Vec<Vec<BlockRef>> = vec![vec![]; n];
        for a in 0..n {
            if in_ranges(&g.offline, a as u32, r) {
                continue;
            }
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
            for o in 0..n {
                if chosen[o] || rng.gen_range(0..100) >= g.weak_link_pct {
                    continue;
                }
                if let Some(b) = by_author[o].iter().rev().find(|b| b.round < r && !in_ranges(&g.ignored, o as u32, b.round)) {
                    anc.push(*b);
                    chosen[o] = true;
                }
            }
            let ts = r as u64 * 1000 + rng.gen_range(0..1000);
            let mut tb = TestBlock::new(r, a as u32).set_ancestors_raw(anc.clone()).set_timestamp_ms(ts);
            if g.payload {
                let ntx = rng.gen_range(0..6);
                let txs: Vec<Transaction> = (0..ntx)
                    .map(|_| {
                        let len = rng.gen_range(200..1200);
                        Transaction::new((0..len).map(|_| rng.r#gen::<u8>()).collect())
                    })
                    .collect();
                let mut votes = vec![];
                for b in anc.iter().skip(1) {
                    let target_txs = *ntx_of.get(b).unwrap_or(&0);
                    let mut rejects: Vec<TransactionIndex> = vec![];
                    if b.author.value() == 1 && target_txs > 0 && b.round % 4 != 0 {
                        rejects.push(0);
                    }
                    if target_txs > 0 && rng.gen_range(0..100) < 10 {
                        rejects.push(rng.gen_range(0..target_txs as u16));
                    }
                    rejects.sort();
                    rejects.dedup();
                    if !rejects.is_empty() {
                        votes.push(BlockTransactionVotes { block_ref: *b, rejects });
                    }
                }
                let cvotes: Vec<CommitRef> = (0..rng.gen_range(0..2))
                    .map(|_| CommitRef::new(rng.gen_range(1..1000), commit_digest_from(rng.r#gen())))
                    .collect();
                tb = tb.set_transactions(txs).set_transaction_votes(votes).set_commit_votes(cvotes);
            }
            let vb = VerifiedBlock::new_for_test(tb.build());
            ntx_of.insert(vb.reference(), vb.transactions().len());
            new_refs[a].push(vb.reference());
            layer.push(vb);
        }
        for a in 0..n {
            by_author[a].extend(new_refs[a].iter().cloned());
        }
        layers.push(layer);
    }
    layers
}

/// Replays `layers` through Mysten's components, times each round, writes the vector file.
async fn commit_case(log: &mut String, name: &str, g: &Gen) {
    let layers = gen_dag(g);
    let stakes = &g.stakes;
    let mut context = context_with_stakes(stakes);
    context.parameters.internal.skip_equivocation_validation = true;
    let context = Arc::new(context);
    let mut h = Harness::new(context.clone());

    let mut w = String::new();
    writeln!(
        w,
        "scenario {} {} {} {} {} {}",
        name,
        stakes.len(),
        context.protocol_config.gc_depth(),
        context.protocol_config.shuffle_commit_blocks() as u8,
        1,
        csv(stakes)
    )
    .unwrap();
    for gb in &genesis_blocks(&context) {
        writeln!(w, "genesis {}", hex(gb.digest().as_ref())).unwrap();
    }
    let mut times: Vec<u64> = Vec::with_capacity(layers.len());
    let mut commits = 0u64;
    let mut out_text = String::new();
    let mut blocks_total = 0usize;
    for blocks in layers {
        for b in &blocks {
            writeln!(w, "block {}", hex(b.serialized())).unwrap();
        }
        blocks_total += blocks.len();
        let t0 = Instant::now();
        h.tracker.add_voted_blocks(blocks.iter().map(|b| (b.clone(), vec![])).collect());
        let (accepted, missing) = h.block_manager.try_accept_blocks(blocks);
        let subdags = h.try_commit();
        let mut finals = vec![];
        for sd in subdags.iter().cloned() {
            finals.extend(h.finalize(sd).await);
        }
        times.push(t0.elapsed().as_nanos() as u64);
        assert!(missing.is_empty(), "{name}: missing ancestors");
        let _ = accepted;
        writeln!(w, "step").unwrap();
        for s in &subdags {
            let l = commit_line(s);
            writeln!(w, "{l}").unwrap();
            out_text.push_str(&l);
            out_text.push('\n');
        }
        for s in &finals {
            writeln!(w, "{}", final_line(s)).unwrap();
        }
        commits += subdags.len() as u64;
    }
    // swap table at the end, as the vectors do
    {
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
    }
    writeln!(w, "end").unwrap();
    std::fs::write(out_dir().join(format!("{name}.vec")), &w).unwrap();
    let wall: u64 = times.iter().sum();
    let rounds = times.len() as u64;
    emit(
        log,
        Line {
            stage: "commit",
            case: name,
            threads: 1,
            unit: "round",
            items: times,
            count: rounds,
            wall_ns: wall,
            out: digest_hex(&out_text),
            extra: format!(
                ",\"commits\":{},\"blocks\":{},\"ns_per_commit\":{:.1},\"commits_per_s\":{:.1}",
                commits,
                blocks_total,
                wall as f64 / commits.max(1) as f64,
                commits as f64 * 1e9 / wall.max(1) as f64
            ),
        },
    );
}

// ------------------------------------------------------------------------------------- stage 4

fn protocol_keypair(i: usize) -> ProtocolKeyPair {
    let sk = Ed25519PrivateKey::from_bytes(&[(i + 1) as u8; 32]).unwrap();
    ProtocolKeyPair::new(Ed25519KeyPair::from(sk))
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

/// Inputs of one block, prepared outside the timed region (what the proposer has collected).
struct Spec {
    round: Round,
    author: u32,
    ts: u64,
    ancestors: Vec<BlockRef>,
    txs: Vec<Transaction>,
    votes: Vec<BlockTransactionVotes>,
    cvotes: Vec<CommitRef>,
}

fn block_case(log: &mut String, name: &str, n: usize, rounds: Round, ntx: usize, tx_len: (usize, usize)) {
    let stakes = vec![1u64; n];
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
    let (context, _) = Context::new_for_test(n);
    let mut context = context.with_committee(committee).with_epoch_start_timestamp_ms(epoch_start);
    mainnet_141(&mut context);
    let context = Arc::new(context);
    let keys: Vec<ProtocolKeyPair> = (0..n).map(protocol_keypair).collect();
    let genesis = genesis_blocks(&context);
    let mut w = String::new();
    writeln!(w, "bcommittee {} {} {} {}", n, epoch, epoch_start, csv(&stakes)).unwrap();
    for g in &genesis {
        writeln!(w, "bgenesis {}", hex(g.digest().as_ref())).unwrap();
    }
    let mut rng = StdRng::seed_from_u64(n as u64 * 7919 + ntx as u64);
    let mut prev: Vec<BlockRef> = genesis.iter().map(|b| b.reference()).collect();
    let mut create_ns: Vec<u64> = vec![];
    let mut serialized: Vec<Bytes> = vec![];
    let mut out_text = String::new();
    let mut prev_ntx: usize = 0;
    for r in 1..=rounds {
        let mut cur = vec![];
        for a in 0..n {
            // own previous block first, then every other authority's previous-round block
            let mut ancestors = vec![prev[a]];
            ancestors.extend(prev.iter().enumerate().filter(|(i, _)| *i != a).map(|(_, b)| *b));
            let txs: Vec<Transaction> = (0..ntx)
                .map(|_| {
                    let len = rng.gen_range(tx_len.0..tx_len.1);
                    Transaction::new((0..len).map(|_| rng.r#gen::<u8>()).collect())
                })
                .collect();
            let votes: Vec<BlockTransactionVotes> = if r > 1 && prev_ntx > 0 {
                let mut v = vec![];
                for b in ancestors.iter().skip(1) {
                    if rng.gen_range(0..100) < 5 {
                        v.push(BlockTransactionVotes { block_ref: *b, rejects: vec![rng.gen_range(0..prev_ntx as u16)] });
                    }
                }
                v
            } else {
                vec![]
            };
            let cvotes = if r > 3 { vec![CommitRef::new(r - 3, commit_digest_from(rng.r#gen()))] } else { vec![] };
            let spec = Spec { round: r, author: a as u32, ts: epoch_start + r as u64 * 100 + a as u64, ancestors, txs, votes, cvotes };
            // timed: what Core::try_new_block does once the inputs are chosen
            let t0 = Instant::now();
            let block = Block::V2(BlockV2::new(
                epoch,
                spec.round,
                AuthorityIndex::new_for_test(spec.author),
                spec.ts,
                spec.ancestors,
                spec.txs,
                spec.votes,
                spec.cvotes,
                vec![],
            ));
            let signed = SignedBlock::new(block, &keys[a]).unwrap();
            let bytes = signed.serialize().unwrap();
            let vb = VerifiedBlock::new_verified(signed, bytes.clone());
            create_ns.push(t0.elapsed().as_nanos() as u64);
            writeln!(w, "bblock {}", hex(&bytes)).unwrap();
            writeln!(out_text, "{}", hex(vb.digest().as_ref())).unwrap();
            cur.push(vb.reference());
            serialized.push(bytes);
        }
        prev = cur;
        prev_ntx = ntx;
    }
    std::fs::write(out_dir().join(format!("blocks-{name}.vec")), &w).unwrap();
    let nblocks = serialized.len() as u64;
    let bytes_total: usize = serialized.iter().map(|b| b.len()).sum();
    let wall: u64 = create_ns.iter().sum();
    emit(
        log,
        Line {
            stage: "block-create",
            case: name,
            threads: 1,
            unit: "block",
            items: create_ns,
            count: nblocks,
            wall_ns: wall,
            out: digest_hex(&out_text),
            extra: format!(",\"bytes\":{}", bytes_total),
        },
    );

    // verification: deserialize + verify_and_vote, single thread
    let verifier = SignedBlockVerifier::new(context.clone(), Arc::new(NoopTransactionVerifier));
    let verify_one = |bytes: &Bytes| -> String {
        let sb: SignedBlock = bcs::from_bytes(bytes).expect("decode");
        match verifier.verify_and_vote(sb, bytes.clone()) {
            Ok((vb, rejects)) => format!("ok {} {}", hex(vb.digest().as_ref()), rejects.len()),
            Err(e) => format!("err {e:?}"),
        }
    };
    // warm-up pass (page faults, allocator)
    for b in serialized.iter().take(64) {
        std::hint::black_box(verify_one(b));
    }
    let mut ver_ns = vec![];
    let mut vout = String::new();
    for b in &serialized {
        let t0 = Instant::now();
        let r = verify_one(b);
        ver_ns.push(t0.elapsed().as_nanos() as u64);
        vout.push_str(&r);
        vout.push('\n');
    }
    let wall: u64 = ver_ns.iter().sum();
    emit(
        log,
        Line { stage: "block-verify", case: name, threads: 1, unit: "block", items: ver_ns, count: nblocks, wall_ns: wall, out: digest_hex(&vout), extra: String::new() },
    );
    // 4 threads, blocks split in contiguous chunks
    for threads in [4usize] {
        let reps = 3;
        let mut best = u64::MAX;
        for _ in 0..reps {
            let chunk = serialized.len().div_ceil(threads);
            let t0 = Instant::now();
            std::thread::scope(|s| {
                for part in serialized.chunks(chunk) {
                    let v = &verify_one;
                    s.spawn(move || {
                        for b in part {
                            std::hint::black_box(v(b));
                        }
                    });
                }
            });
            best = best.min(t0.elapsed().as_nanos() as u64);
        }
        emit(
            log,
            Line { stage: "block-verify", case: name, threads, unit: "block", items: vec![], count: nblocks, wall_ns: best, out: digest_hex(&vout), extra: String::new() },
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn zui_val_bench() {
    let only = std::env::var("ZUI_VALBENCH_ONLY").unwrap_or_default();
    let want = |s: &str| only.is_empty() || only.split(',').any(|o| s.starts_with(o));
    let mut log = String::new();

    // stage 3: commit decision
    let cases: Vec<(&str, Gen)> = vec![
        ("n4", Gen { stakes: vec![1; 4], rounds: 3000, seed: 41, leader_link_pct: 90, weak_link_pct: 5, payload: true, ..Default::default() }),
        ("n10", Gen { stakes: vec![1; 10], rounds: 2000, seed: 101, leader_link_pct: 90, weak_link_pct: 5, payload: true, ..Default::default() }),
        ("n100", Gen { stakes: mainnet_like_stakes(100), rounds: 400, seed: 1001, leader_link_pct: 90, weak_link_pct: 3, payload: true, ..Default::default() }),
        (
            "n10-timeouts",
            Gen {
                stakes: vec![1; 10],
                rounds: 2000,
                seed: 102,
                leader_link_pct: 60,
                weak_link_pct: 10,
                // authorities offline for stretches: their leader slots time out (skipped or
                // undecided until a later anchor), their blocks are missing
                offline: vec![(3, 100, 400), (7, 900, 1000), (2, 1500, 1520), (5, 1500, 1520)],
                ignored: vec![(8, 1200, 1300)],
                payload: true,
                ..Default::default()
            },
        ),
        (
            "n100-timeouts",
            Gen {
                stakes: vec![1; 100],
                rounds: 400,
                seed: 1002,
                // 80: at 100 equal stakes a 60% link rate never reaches the 2f+1 votes a
                // direct commit needs, so nothing would ever commit
                leader_link_pct: 80,
                weak_link_pct: 3,
                offline: (0..20u32).map(|a| (a * 5, 50 + a * 7, 120 + a * 9)).collect(),
                ignored: vec![(1, 200, 260), (2, 300, 330)],
                payload: true,
                ..Default::default()
            },
        ),
    ];
    for (name, g) in &cases {
        if want(name) {
            commit_case(&mut log, name, g).await;
        }
    }

    // stage 4: block creation and verification
    let bcases: Vec<(&str, usize, Round, usize, (usize, usize))> = vec![
        ("n10-light", 10, 100, 16, (200, 2000)),
        ("n10-full", 10, 30, 128, (1500, 2200)),
        ("n100-light", 100, 12, 16, (200, 2000)),
        ("n100-full", 100, 3, 128, (1500, 2200)),
    ];
    for (name, n, rounds, ntx, len) in bcases {
        if want(&format!("blocks-{name}")) {
            block_case(&mut log, name, n, rounds, ntx, len);
        }
    }
    std::fs::write(out_dir().join("rust.jsonl"), log).unwrap();
}
