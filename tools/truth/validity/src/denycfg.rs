//! Suite `denycfg`: the transaction-deny config shared through consensus (PARITY.md G21,
//! `share_transaction_deny_config_in_consensus`): sui-core `transaction_deny_config_manager.rs`
//! (`evaluate_deny_configs`, `TransactionDenyConfigManager` over real perpetual tables),
//! sui-config `PeerDenySyncConfig::validate`, and `check_transaction_for_signing` under the
//! effective config.
//!
//! Inputs use a small text notation that the Zig test parses the same way:
//!   name / who      one byte b: AuthorityName = [b; 96]
//!   id              one byte b: ObjectID / SuiAddress = 31 zero bytes then b
//!   rules           `-` (empty) or `;`-separated: `o:1,2` objects, `p:3` packages, `a:4`
//!                   addresses, `z:Google,x` zkLogin providers, and the flags publish, upgrade,
//!                   shared, user, gasless, receiving, zksig
//!   committee       `1=2500,2=2500` (name=stake)
//!   eligibility     `all` (empty denylist), `allow:1,2`, `deny:3`
//!   sync            `-` or space-separated: `R<name>|<elig>|<pct>|<rules>` (pre-listed ruleset),
//!                   `B<name>|<elig>|<pct>|<kind>,<kind>` (default bucket, serde kebab kinds),
//!                   `startup`, `epoch` (broadcast flags)
//!   votes           `-` or space-separated `<who>@<rules>`
//!   msgs / rows     space-separated `<who>#<generation>#<rules or none>` (`max` = u64::MAX)
//!
//! Lines (tab-separated, verdict last, common.rs):
//!   eval      committee  sync  local  votes  -> ok eff=<rules> pre=<voted>/<eligible>/<0|1>,... def=<eligible>/<applied>,...
//!   validate  sync                           -> ok | err <validate message>
//!   mgr  <scenario>  new        self  committee  sync  local
//!   mgr  <scenario>  apply      from  msgs
//!   mgr  <scenario>  committee  committee     (update_for_committee)
//!   mgr  <scenario>  restart    self  committee   (a new manager over the same tables)
//!                                            -> ok eff=<rules> peers=<rows sorted by name>|-
//!   sign      committee  sync  local  votes  TransactionData(BCS hex)  -> ok | err <SuiError Display>
//! Rules print in the notation's order: o, p, a, z, then the flags.

use crate::common::{Out, esc, verdict};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};
use fastcrypto::traits::KeyPair as _;
use rand::SeedableRng;
use rand::rngs::StdRng;
use sui_types::crypto::{AuthorityKeyPair, get_key_pair_from_rng};
use sui_config::transaction_deny_config::{
    DefaultDenyBucket, DenyElementKind, PeerDenySyncConfig, SharedDenyRuleThreshold,
    SharedDenyRuleset, TransactionDenyConfig, TransactionDenyRules, ValidatorEligibility,
};
use sui_core::authority::authority_store_tables::AuthorityPerpetualTables;
use sui_core::transaction_deny_config_manager::{
    TransactionDenyConfigManager, evaluate_deny_configs,
};
use sui_types::base_types::{
    AuthorityName, ObjectDigest, ObjectID, ObjectRef, SequenceNumber, SuiAddress,
};
use sui_types::committee::{Committee, StakeUnit};
use sui_types::crypto::AuthorityPublicKeyBytes;
use sui_types::error::SuiResult;
use sui_types::messages_consensus::{SharedTransactionDenyConfig, SharedTransactionDenyConfigV1};
use sui_types::storage::{BackingPackageStore, PackageObject};
use sui_types::transaction::{
    Argument, CallArg, Command, ObjectArg, ProgrammableTransaction, SharedObjectMutability,
    TransactionData, TransactionDataAPI,
};

/// Committee::new needs real BLS keys: member b is the key from seed [b; 32]. The Zig side only
/// needs distinct names and uses [b; 96] (nothing here depends on the name order: rows print in
/// `who` order).
fn keys() -> &'static Vec<AuthorityName> {
    static KEYS: OnceLock<Vec<AuthorityName>> = OnceLock::new();
    KEYS.get_or_init(|| {
        (0..=255u8)
            .map(|b| {
                let (_, kp): (_, AuthorityKeyPair) = get_key_pair_from_rng(&mut StdRng::from_seed([b; 32]));
                AuthorityPublicKeyBytes::from(kp.public())
            })
            .collect()
    })
}

fn name(b: u8) -> AuthorityName {
    keys()[b as usize]
}

fn who(n: &AuthorityName) -> u8 {
    keys().iter().position(|k| k == n).expect("unknown name") as u8
}

fn id(b: u8) -> ObjectID {
    let mut a = [0u8; 32];
    a[31] = b;
    ObjectID::new(a)
}

fn addr(b: u8) -> SuiAddress {
    SuiAddress::from(id(b))
}

fn last(bytes: &[u8]) -> u8 {
    assert!(bytes[..31].iter().all(|x| *x == 0), "id outside the notation");
    bytes[31]
}

fn bytes_list(s: &str) -> Vec<u8> {
    s.split(',').filter(|x| !x.is_empty()).map(|x| x.parse().unwrap()).collect()
}

fn rules(s: &str) -> TransactionDenyRules {
    let mut r = TransactionDenyRules::default();
    if s == "-" {
        return r;
    }
    for item in s.split(';') {
        match item.split_once(':') {
            Some(("o", l)) => r.object_deny_list.extend(bytes_list(l).into_iter().map(id)),
            Some(("p", l)) => r.package_deny_list.extend(bytes_list(l).into_iter().map(id)),
            Some(("a", l)) => r.address_deny_list.extend(bytes_list(l).into_iter().map(addr)),
            Some(("z", l)) => r
                .zklogin_disabled_providers
                .extend(l.split(',').filter(|x| !x.is_empty()).map(String::from)),
            None => match item {
                "publish" => r.package_publish_disabled = true,
                "upgrade" => r.package_upgrade_disabled = true,
                "shared" => r.shared_object_disabled = true,
                "user" => r.user_transaction_disabled = true,
                "gasless" => r.gasless_disabled = true,
                "receiving" => r.receiving_objects_disabled = true,
                "zksig" => r.zklogin_sig_disabled = true,
                _ => panic!("bad rules item {item}"),
            },
            _ => panic!("bad rules item {item}"),
        }
    }
    r
}

fn canon(r: &TransactionDenyRules) -> String {
    let mut parts: Vec<String> = vec![];
    let ids = |l: Vec<u8>| l.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",");
    if !r.object_deny_list.is_empty() {
        parts.push(format!("o:{}", ids(r.object_deny_list.iter().map(|x| last(x.as_ref())).collect())));
    }
    if !r.package_deny_list.is_empty() {
        parts.push(format!("p:{}", ids(r.package_deny_list.iter().map(|x| last(x.as_ref())).collect())));
    }
    if !r.address_deny_list.is_empty() {
        parts.push(format!("a:{}", ids(r.address_deny_list.iter().map(|x| last(x.as_ref())).collect())));
    }
    if !r.zklogin_disabled_providers.is_empty() {
        parts.push(format!("z:{}", r.zklogin_disabled_providers.iter().cloned().collect::<Vec<_>>().join(",")));
    }
    for (on, n) in [
        (r.package_publish_disabled, "publish"),
        (r.package_upgrade_disabled, "upgrade"),
        (r.shared_object_disabled, "shared"),
        (r.user_transaction_disabled, "user"),
        (r.gasless_disabled, "gasless"),
        (r.receiving_objects_disabled, "receiving"),
        (r.zklogin_sig_disabled, "zksig"),
    ] {
        if on {
            parts.push(n.to_string());
        }
    }
    if parts.is_empty() { "-".to_string() } else { parts.join(";") }
}

fn committee_map(s: &str) -> BTreeMap<AuthorityName, StakeUnit> {
    s.split(',')
        .filter(|x| !x.is_empty())
        .map(|e| {
            let (n, st) = e.split_once('=').unwrap();
            (name(n.parse().unwrap()), st.parse().unwrap())
        })
        .collect()
}

fn eligibility(s: &str) -> ValidatorEligibility {
    let set = |l: &str| -> BTreeSet<AuthorityName> { bytes_list(l).into_iter().map(name).collect() };
    if s == "all" {
        ValidatorEligibility::Denylist(BTreeSet::new())
    } else if let Some(l) = s.strip_prefix("allow:") {
        ValidatorEligibility::Allowlist(set(l))
    } else if let Some(l) = s.strip_prefix("deny:") {
        ValidatorEligibility::Denylist(set(l))
    } else {
        panic!("bad eligibility {s}")
    }
}

fn kind(s: &str) -> DenyElementKind {
    serde_json::from_str(&format!("\"{s}\"")).unwrap_or_else(|_| panic!("bad kind {s}"))
}

fn sync(s: &str) -> PeerDenySyncConfig {
    let mut c = PeerDenySyncConfig::default();
    if s == "-" {
        return c;
    }
    for item in s.split(' ') {
        if item == "startup" {
            c.broadcast_on_startup = true;
            continue;
        }
        if item == "epoch" {
            c.broadcast_on_epoch_change = true;
            continue;
        }
        let f: Vec<&str> = item[1..].split('|').collect();
        assert_eq!(f.len(), 4, "bad sync item {item}");
        let threshold = SharedDenyRuleThreshold {
            eligibility: eligibility(f[1]),
            stake_threshold_percent: f[2].parse().unwrap(),
        };
        match &item[..1] {
            "R" => c.rulesets.push(SharedDenyRuleset { name: f[0].to_string(), rules: rules(f[3]), threshold }),
            "B" => c.default_buckets.push(DefaultDenyBucket {
                name: f[0].to_string(),
                element_kinds: f[3].split(',').filter(|x| !x.is_empty()).map(kind).collect(),
                threshold,
            }),
            _ => panic!("bad sync item {item}"),
        }
    }
    c
}

fn votes(s: &str) -> Vec<(AuthorityName, TransactionDenyRules)> {
    if s == "-" {
        return vec![];
    }
    s.split(' ')
        .map(|v| {
            let (w, r) = v.split_once('@').unwrap();
            (name(w.parse().unwrap()), rules(r))
        })
        .collect()
}

fn msgs(s: &str) -> Vec<SharedTransactionDenyConfig> {
    s.split(' ')
        .map(|m| {
            let f: Vec<&str> = m.split('#').collect();
            let generation = if f[1] == "max" { u64::MAX } else { f[1].parse().unwrap() };
            SharedTransactionDenyConfig::V1(SharedTransactionDenyConfigV1 {
                authority: name(f[0].parse().unwrap()),
                generation,
                rules: if f[2] == "none" { None } else { Some(rules(f[2])) },
            })
        })
        .collect()
}

fn eval_line(committee: &str, sync_s: &str, local: &str, votes_s: &str) -> (TransactionDenyRules, String) {
    let stakes = committee_map(committee);
    let vs = votes(votes_s);
    let vmap: BTreeMap<AuthorityName, &TransactionDenyRules> = vs.iter().map(|(n, r)| (*n, r)).collect();
    let ev = evaluate_deny_configs(&rules(local), &sync(sync_s), &vmap, &stakes);
    let pre = ev
        .prelisted
        .iter()
        .map(|p| format!("{}/{}/{}", p.voted_stake, p.eligible_stake, p.active as u8))
        .collect::<Vec<_>>()
        .join(",");
    let def = ev
        .defaults
        .iter()
        .map(|d| format!("{}/{}", d.eligible_stake, d.applied_elements.len()))
        .collect::<Vec<_>>()
        .join(",");
    let text = format!("eff={} pre={pre} def={def}", canon(&ev.effective_rules));
    (ev.effective_rules, text)
}

// ---- manager scenarios

struct Scenario {
    mgr: Arc<TransactionDenyConfigManager>,
    perpetual: Arc<AuthorityPerpetualTables>,
    local: TransactionDenyConfig,
    sync: PeerDenySyncConfig,
    _dir: TempDir,
}

struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn state(m: &TransactionDenyConfigManager) -> String {
    let eff = canon(m.effective_config().load().rules());
    let mut rows: Vec<(u8, SharedTransactionDenyConfig)> =
        m.peer_configs_snapshot().into_iter().map(|(n, msg)| (who(&n), msg)).collect();
    rows.sort_by_key(|r| r.0);
    let peers = rows
        .iter()
        .map(|(n, msg)| {
            format!(
                "{}#{}#{}",
                n,
                msg.generation(),
                msg.rules().map(canon).unwrap_or_else(|| "none".to_string())
            )
        })
        .collect::<Vec<_>>();
    format!("eff={eff} peers={}", if peers.is_empty() { "-".to_string() } else { peers.join(" ") })
}

fn new_manager(
    self_b: u8,
    committee: &str,
    local: &TransactionDenyConfig,
    sync: &PeerDenySyncConfig,
    perpetual: &Arc<AuthorityPerpetualTables>,
) -> Arc<TransactionDenyConfigManager> {
    TransactionDenyConfigManager::new(
        name(self_b),
        local.clone(),
        sync.clone(),
        Arc::new(Committee::new(0, committee_map(committee))),
        perpetual.clone(),
        &prometheus::Registry::new(),
    )
    .unwrap()
}

// ---- signing checks

struct NoPackages;
impl BackingPackageStore for NoPackages {
    fn get_package_object(&self, _: &ObjectID) -> SuiResult<Option<PackageObject>> {
        Ok(None)
    }
}

fn oref(b: u8) -> ObjectRef {
    (id(b), SequenceNumber::from_u64(3), ObjectDigest::new([b; 32]))
}

fn tx(sender: u8, inputs: Vec<CallArg>, commands: Vec<Command>) -> TransactionData {
    TransactionData::new_programmable(
        addr(sender),
        vec![oref(0xee)],
        ProgrammableTransaction { inputs, commands },
        10_000_000,
        1000,
    )
}

pub fn run(out_path: &str) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async { run_inner(out_path) })
}

fn run_inner(out_path: &str) -> anyhow::Result<()> {
    let mut out = Out::new(
        "suite denycfg: sui-core 1.83.1 TransactionDenyConfigManager / evaluate_deny_configs, PeerDenySyncConfig::validate, check_transaction_for_signing\nformat: see tools/truth/validity/src/denycfg.rs",
    );

    // ---- evaluate_deny_configs
    let c4 = "1=2500,2=2500,3=2500,4=2500";
    let cv = "1=4000,2=3000,3=2000,4=1000";
    let evals: Vec<(&str, &str, &str, &str)> = vec![
        // pre-listed ruleset at 50%: just below, at, above
        (c4, "Rr|all|50|o:1", "-", "1@o:1"),
        (c4, "Rr|all|50|o:1", "-", "1@o:1 2@o:1"),
        (c4, "Rr|all|50|o:1", "-", "1@o:1 2@o:1;p:5 3@o:1,2"),
        (c4, "Rr|all|51|o:1", "-", "1@o:1 2@o:1"),
        (c4, "Rr|all|100|o:1", "-", "1@o:1 2@o:1 3@o:1 4@o:1"),
        (c4, "Rr|all|1|o:1", "-", "4@o:1"),
        // superset votes count for nested / overlapping rulesets; a subset does not
        (c4, "Ra|all|50|o:1 Rb|all|50|o:1,2 Rc|all|50|o:2;publish", "-", "1@o:1,2;publish 2@o:1,2"),
        (c4, "Ra|all|50|o:1,2", "-", "1@o:1 2@o:2 3@o:1"),
        (c4, "Rf|all|75|user;shared", "-", "1@user;shared 2@user;shared;gasless 3@user 4@shared"),
        (c4, "Rz|all|50|z:Google", "-", "1@z:Google,Apple 2@z:Google"),
        // eligibility: allowlist counts only its members' stake; denylist against 10000
        (cv, "Rr|allow:2,3|60|o:1", "-", "1@o:1 2@o:1"),
        (cv, "Rr|allow:2,3|60|o:1", "-", "2@o:1 3@o:1"),
        (cv, "Rr|allow:9|60|o:1", "-", "1@o:1 2@o:1 3@o:1 4@o:1"),
        (cv, "Rr|allow:|50|o:1", "-", "1@o:1"),
        (cv, "Rr|deny:1|50|o:1", "-", "1@o:1 4@o:1"),
        (cv, "Rr|deny:1|50|o:1", "-", "2@o:1"),
        (cv, "Rr|deny:1,2,3,4|50|o:1", "-", "1@o:1 2@o:1"),
        (cv, "Rr|deny:9|40|o:1", "-", "1@o:1"),
        // stakes not summing to 10000: a denylist still counts against 10000
        ("1=10,2=10", "Rr|all|50|o:1", "-", "1@o:1 2@o:1"),
        ("1=10,2=10", "Rr|allow:1,2|50|o:1", "-", "1@o:1"),
        // a vote from outside the stakes counts for nothing
        (c4, "Rr|all|25|o:1 Bd|all|25|object", "-", "9@o:1,2"),
        // default buckets: per element, per bucket kinds and eligibility
        (c4, "Bd|all|50|object,package", "-", "1@o:1,2;p:3 2@o:2;p:3 3@o:4"),
        (c4, "Bd|all|50|object", "-", "1@o:1;p:3;publish 2@o:1;p:3;publish"),
        (c4, "Bo|all|50|object Bp|allow:3,4|100|package,package-publish-disabled", "-", "1@o:1;p:1;publish 2@o:1;p:1 3@p:1;publish 4@p:1;publish"),
        (c4, "Bb|all|75|package-publish-disabled,package-upgrade-disabled,shared-object-disabled,user-transaction-disabled,gasless-disabled,receiving-objects-disabled,zk-login-sig-disabled", "-", "1@publish;upgrade;shared;user;gasless;receiving;zksig 2@publish;upgrade;shared;user;gasless;receiving;zksig 3@publish;upgrade;receiving 4@zksig"),
        (c4, "Ba|all|50|address,zk-login-provider", "-", "1@a:7;z:Facebook,Google 2@a:7,8;z:Google 3@a:8"),
        (cv, "Bd|deny:1|60|object", "-", "1@o:1 2@o:1 3@o:2"),
        (cv, "Bd|deny:1|50|object", "-", "1@o:1 2@o:1 3@o:2"),
        // an element counts for both its ruleset and its bucket
        (c4, "Rr|all|75|o:1 Bd|all|50|object", "-", "1@o:1,2 2@o:1,2"),
        // local rules always apply and merge with what activates
        (c4, "Rr|all|50|o:1", "o:9;p:9;gasless;z:Twitch", "-"),
        (c4, "Rr|all|50|o:1;upgrade Bd|all|50|address", "o:9;a:3", "1@o:1;upgrade;a:4 2@o:1;upgrade;a:4"),
        (c4, "-", "user", "1@o:1 2@o:1 3@o:1 4@o:1"),
        (c4, "-", "-", "-"),
    ];
    for (c, s, l, v) in &evals {
        let (_, text) = eval_line(c, s, l, v);
        out.push(&["eval".into(), c.to_string(), s.to_string(), l.to_string(), v.to_string(), format!("ok {}", esc(&text))]);
    }

    // ---- PeerDenySyncConfig::validate
    let validates = [
        "-",
        "Rr|all|50|o:1 Bd|all|50|object startup epoch",
        "R|all|50|o:1",
        "Rr|all|50|o:1 Rr|all|50|o:2",
        "Rr|all|50|-",
        "Rr|all|0|o:1",
        "Rr|all|101|o:1",
        "Rr|all|100|o:1",
        "B|all|50|object",
        "Rx|all|50|o:1 Bx|all|50|object",
        "Bd|all|50|",
        "Ba|all|50|object,package Bb|all|50|package",
        "Ba|all|50|zk-login-provider Bb|all|50|zk-login-provider",
        "Bd|all|0|object",
        "Bd|all|300|object",
    ];
    for s in validates {
        let r = sync(s).validate();
        out.push(&["validate".into(), s.to_string(), verdict(&r, |_| None)]);
    }

    // ---- manager scenarios
    let scenarios: Vec<Vec<Vec<&str>>> = vec![
        // thresholds, author mismatch, non-member, future generation, stale, withdrawal
        vec![
            vec!["new", "1", c4, "Rr|allow:1,2,3,4|50|o:1 Bd|all|75|package", "publish"],
            vec!["apply", "2", "2#5#o:1;p:7"],
            vec!["apply", "2", "3#6#o:1"],
            vec!["apply", "9", "9#6#o:1"],
            vec!["apply", "3", "3#max#o:1"],
            vec!["apply", "3", "3#6#o:1;p:7"],
            vec!["apply", "3", "3#6#o:2"],
            vec!["apply", "3", "3#5#none"],
            vec!["apply", "4", "4#1#p:7"],
            vec!["apply", "2", "2#5#none 2#6#none"],
            vec!["apply", "4", "4#2#none 2#9#o:1 4#3#p:7"],
            vec!["apply", "1", "1#4#o:1;p:7"],
            vec!["apply", "1", "1#4#none"],
        ],
        // committee change prunes departed members and re-weighs the rest
        vec![
            vec!["new", "1", c4, "Rr|all|50|o:1", "-"],
            vec!["apply", "2", "2#1#o:1"],
            vec!["apply", "3", "3#1#o:1"],
            vec!["committee", "1=2000,2=2000,4=6000"],
            vec!["apply", "3", "3#2#o:1"],
            vec!["apply", "4", "4#1#o:1"],
            vec!["committee", "1=2500,2=2500,3=2500,4=2500"],
            vec!["apply", "3", "3#1#o:1"],
        ],
        // restart: own row and non-members' rows are not voted, rows of members are
        vec![
            vec!["new", "1", c4, "Rr|all|50|o:1", "-"],
            vec!["apply", "1", "1#10#o:1"],
            vec!["apply", "2", "2#10#o:1"],
            vec!["apply", "3", "3#10#o:1"],
            vec!["restart", "1", "1=2500,2=2500,4=5000"],
            vec!["apply", "1", "1#3#o:1"],
            vec!["committee", "1=2500,2=2500,3=2500,4=2500"],
            vec!["restart", "1", c4],
            vec!["apply", "3", "3#10#o:1"],
            vec!["apply", "3", "3#11#o:1"],
            vec!["restart", "2", c4],
        ],
        // withdrawals keep the row (generation) but drop the vote; default bucket per element
        vec![
            vec!["new", "4", cv, "Bo|deny:4|50|object,address", "-"],
            vec!["apply", "1", "1#1#o:1;a:1"],
            vec!["apply", "2", "2#1#o:2;a:1"],
            vec!["apply", "3", "3#1#o:1,2"],
            vec!["apply", "1", "1#2#none"],
            vec!["apply", "1", "1#3#o:2"],
            vec!["committee", "1=1000,2=1000,3=8000"],
        ],
    ];
    for (si, steps) in scenarios.iter().enumerate() {
        let mut sc: Option<Scenario> = None;
        for step in steps {
            let fields: Vec<String> = step.iter().map(|s| s.to_string()).collect();
            match step[0] {
                "new" => {
                    let dir = std::env::temp_dir().join(format!("zui-denycfg-{}-{si}", std::process::id()));
                    let _ = std::fs::remove_dir_all(&dir);
                    std::fs::create_dir_all(&dir)?;
                    let perpetual = Arc::new(AuthorityPerpetualTables::open(&dir, None, None));
                    let local = TransactionDenyConfig::default().with_rules(rules(step[4]));
                    let sy = sync(step[3]);
                    let mgr = new_manager(step[1].parse()?, step[2], &local, &sy, &perpetual);
                    sc = Some(Scenario { _dir: TempDir(dir), perpetual, local, sync: sy, mgr });
                }
                "apply" => {
                    let s = sc.as_ref().unwrap();
                    s.mgr.apply_updates(name(step[1].parse()?), msgs(step[2]));
                }
                "committee" => {
                    let s = sc.as_ref().unwrap();
                    s.mgr.update_for_committee(Arc::new(Committee::new(0, committee_map(step[1]))))?;
                }
                "restart" => {
                    let s = sc.as_mut().unwrap();
                    s.mgr = new_manager(step[1].parse()?, step[2], &s.local, &s.sync, &s.perpetual);
                }
                op => panic!("bad op {op}"),
            }
            let st = state(&sc.as_ref().unwrap().mgr);
            let mut line = vec!["mgr".to_string(), si.to_string()];
            line.extend(fields);
            line.push(format!("ok {}", esc(&st)));
            out.push(&line);
        }
    }

    // ---- check_transaction_for_signing under the effective config
    let recipient = CallArg::Pure(bcs::to_bytes(&addr(0x55))?);
    let owned = |b: u8| CallArg::Object(ObjectArg::ImmOrOwnedObject(oref(b)));
    let shared = |b: u8| CallArg::Object(ObjectArg::SharedObject { id: id(b), initial_shared_version: SequenceNumber::from_u64(1), mutability: SharedObjectMutability::Mutable });
    let receiving = |b: u8| CallArg::Object(ObjectArg::Receiving(oref(b)));
    let transfer = |n: u16| Command::TransferObjects((0..n).map(Argument::Input).collect(), Argument::Input(n));
    let txs: Vec<(&str, TransactionData)> = vec![
        ("transfer", tx(0x21, vec![owned(1), recipient.clone()], vec![transfer(1)])),
        ("shared", tx(0x21, vec![shared(2), recipient.clone()], vec![transfer(1)])),
        ("receiving", tx(0x22, vec![receiving(3), recipient.clone()], vec![transfer(1)])),
        ("publish", tx(0x21, vec![], vec![Command::Publish(vec![vec![0xa1]], vec![id(4), id(5)])])),
        ("upgrade", tx(0x21, vec![owned(6)], vec![Command::Upgrade(vec![vec![1]], vec![id(4)], id(7), Argument::Input(0))])),
    ];
    let configs: Vec<(&str, &str, &str, &str)> = vec![
        (c4, "-", "-", "-"),
        (c4, "Rr|all|50|o:1", "-", "1@o:1 2@o:1"),
        (c4, "Rr|all|50|o:1", "-", "1@o:1"),
        (c4, "Bd|all|50|object,address,package", "-", "1@o:2;a:33;p:5 2@o:2;a:33;p:5 3@p:7"),
        (c4, "Bd|all|50|object,address,package", "-", "1@a:34;p:7 2@a:34;p:7"),
        (c4, "Bf|all|75|shared-object-disabled,receiving-objects-disabled,package-upgrade-disabled", "-", "1@shared;receiving;upgrade 2@shared;receiving;upgrade 3@shared;receiving;upgrade"),
        (c4, "Rr|all|100|publish;user", "-", "1@publish;user 2@publish;user 3@publish;user 4@publish"),
        (c4, "Rr|all|100|publish;user", "-", "1@publish;user 2@publish;user 3@publish;user 4@publish;user"),
        (c4, "Rr|allow:1|100|receiving", "p:5", "1@receiving"),
    ];
    for (c, s, l, v) in &configs {
        let (eff, _) = eval_line(c, s, l, v);
        let cfg = TransactionDenyConfig::default().with_rules(eff);
        for (_tn, t) in &txs {
            let kinds = t.input_objects()?;
            let recv = t.receiving_objects();
            let r = sui_transaction_checks::deny::check_transaction_for_signing(t, &[], &kinds, &recv, &cfg, &NoPackages);
            out.push(&[
                "sign".into(),
                c.to_string(),
                s.to_string(),
                l.to_string(),
                v.to_string(),
                hex::encode(bcs::to_bytes(t)?),
                verdict(&r, |_| None),
            ]);
        }
    }

    out.write(out_path)
}
