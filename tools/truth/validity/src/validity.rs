//! Suite `validity`: `SenderSignedData::validity_check` (sui-types transaction.rs, the first step
//! of both the consensus vote and SubmitTransaction), which includes
//! `check_user_signature_protocol_compatibility`, the system-kind rule, the serialized size
//! limits, `TransactionDataV1::validity_check` and inside it `ProgrammableTransaction::
//! validity_check` and `validate_gasless_transaction`.
//!
//! Line: `id  pv  chain  epoch  rgp  committee  chain_id(hex)  SenderSignedData(BCS hex)  verdict`
//! with verdict `ok <serialized size>` or `err <SuiError Display>`.

use crate::common::{Out, verdict};
use fastcrypto::traits::KeyPair as _;
use fastcrypto::rsa::Encoding as _;
use move_core_types::account_address::AccountAddress;
use move_core_types::language_storage::TypeTag;
use rand::SeedableRng;
use rand::rngs::StdRng;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::base_types::{ObjectDigest, ObjectID, ObjectRef, SequenceNumber, SuiAddress};
use sui_types::crypto::{
    AccountKeyPair, Signature, SuiKeyPair, get_key_pair_from_rng,
};
use sui_types::digests::{ChainIdentifier, CheckpointDigest};
use sui_types::multisig::{MultiSig, MultiSigPublicKey};
use sui_types::passkey_authenticator::PasskeyAuthenticator;
use sui_types::signature::GenericSignature;
use sui_types::transaction::{
    Argument, CallArg, Command, FundsWithdrawalArg, GasData, GenesisTransaction, ObjectArg,
    ProgrammableMoveCall, ProgrammableTransaction, SenderSignedData, SharedObjectMutability,
    Transaction, TransactionData, TransactionDataV1, TransactionExpiration, TransactionKind,
    TxValidityCheckContext,
};
use sui_types::type_input::{StructInput, TypeInput};
use sui_types::{SUI_FRAMEWORK_ADDRESS, SUI_RANDOMNESS_STATE_OBJECT_ID};
use fastcrypto::traits::ToFromBytes;
use shared_crypto::intent::{Intent, IntentMessage};

#[derive(Clone)]
struct Ctx {
    pv: u64,
    chain: Chain,
    epoch: u64,
    rgp: u64,
    committee: u32,
    chain_id: ChainIdentifier,
}

fn mainnet(pv: u64) -> Ctx {
    Ctx {
        pv,
        chain: Chain::Mainnet,
        epoch: 1000,
        rgp: 1000,
        committee: 4,
        chain_id: ChainIdentifier::from(CheckpointDigest::new([0x4a; 32])),
    }
}

struct Gen {
    out: Out,
    kp: AccountKeyPair,
    sender: SuiAddress,
}

fn oid(b: u8) -> ObjectID {
    let mut a = [0u8; 32];
    a[0] = 0x11;
    a[31] = b;
    ObjectID::new(a)
}

fn oref(b: u8) -> ObjectRef {
    (oid(b), SequenceNumber::from_u64(7), ObjectDigest::new([b; 32]))
}

fn gas_ref() -> ObjectRef {
    oref(0xee)
}

fn fw() -> ObjectID {
    ObjectID::from(SUI_FRAMEWORK_ADDRESS)
}

fn call(package: ObjectID, module: &str, function: &str, targs: Vec<TypeInput>, args: Vec<Argument>) -> Command {
    Command::MoveCall(Box::new(ProgrammableMoveCall {
        package,
        module: module.to_string(),
        function: function.to_string(),
        type_arguments: targs,
        arguments: args,
    }))
}

fn st(addr: AccountAddress, module: &str, name: &str, params: Vec<TypeInput>) -> TypeInput {
    TypeInput::Struct(Box::new(StructInput {
        address: addr,
        module: module.to_string(),
        name: name.to_string(),
        type_params: params,
    }))
}

fn tag(s: &str) -> TypeTag {
    s.parse().unwrap()
}

fn tin(s: &str) -> TypeInput {
    TypeInput::from(tag(s))
}

fn vec_depth(n: usize) -> TypeInput {
    let mut t = TypeInput::U8;
    for _ in 0..n {
        t = TypeInput::Vector(Box::new(t));
    }
    t
}

const USDC: &str = "0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC";

impl Gen {
    fn pt_data(&self, pt: ProgrammableTransaction) -> TransactionData {
        TransactionData::new_programmable(self.sender, vec![gas_ref()], pt, 10_000_000, 1000)
    }

    fn base_pt(&self) -> ProgrammableTransaction {
        ProgrammableTransaction {
            inputs: vec![CallArg::Pure(bcs::to_bytes(&self.sender).unwrap())],
            commands: vec![Command::TransferObjects(vec![Argument::GasCoin], Argument::Input(0))],
        }
    }

    fn sign(&self, data: TransactionData) -> SenderSignedData {
        Transaction::from_data_and_signer(data, vec![&self.kp]).into_data()
    }

    fn with_sigs(&self, data: TransactionData, sigs: Vec<GenericSignature>) -> SenderSignedData {
        Transaction::from_generic_sig_data(data, sigs).into_data()
    }

    fn emit(&mut self, id: &str, c: &Ctx, ssd: &SenderSignedData) {
        let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(c.pv), c.chain);
        let ctx = TxValidityCheckContext {
            config: &cfg,
            epoch: c.epoch,
            chain_identifier: c.chain_id,
            reference_gas_price: c.rgp,
            committee_size: c.committee,
        };
        let r = ssd.validity_check(&ctx);
        let chain = match c.chain {
            Chain::Mainnet => "mainnet",
            Chain::Testnet => "testnet",
            Chain::Unknown => "unknown",
        };
        self.out.push(&[
            id.to_string(),
            c.pv.to_string(),
            chain.to_string(),
            c.epoch.to_string(),
            c.rgp.to_string(),
            c.committee.to_string(),
            hex::encode(c.chain_id.as_bytes()),
            hex::encode(bcs::to_bytes(ssd).unwrap()),
            verdict(&r, |n| Some(n.to_string())),
        ]);
    }

    /// A PTB transaction with the base gas, signed.
    fn ptb(&mut self, id: &str, c: &Ctx, pt: ProgrammableTransaction) {
        let ssd = self.sign(self.pt_data(pt));
        self.emit(id, c, &ssd);
    }

    fn data_v1(&mut self, id: &str, c: &Ctx, d: TransactionDataV1) {
        let ssd = self.sign(TransactionData::V1(d));
        self.emit(id, c, &ssd);
    }

    fn v1(&self, pt: ProgrammableTransaction) -> TransactionDataV1 {
        let TransactionData::V1(v) = self.pt_data(pt);
        v
    }

    /// A gasless transaction (no payment, price 0, budget 0), ValidDuring the context epoch.
    fn gasless(&self, c: &Ctx, pt: ProgrammableTransaction) -> TransactionDataV1 {
        TransactionDataV1 {
            kind: TransactionKind::ProgrammableTransaction(pt),
            sender: self.sender,
            gas_data: GasData { payment: vec![], owner: self.sender, price: 0, budget: 0 },
            expiration: TransactionExpiration::ValidDuring {
                min_epoch: Some(c.epoch),
                max_epoch: Some(c.epoch),
                min_timestamp: None,
                max_timestamp: None,
                chain: c.chain_id,
                nonce: 1,
            },
        }
    }
}

/// Pads the Pure input at `idx` so the signed transaction serializes to exactly `target` bytes.
fn pad_to(g: &Gen, mut pt: ProgrammableTransaction, idx: usize, target: usize, gasless: Option<&Ctx>) -> SenderSignedData {
    for _ in 0..8 {
        let data = match gasless {
            Some(c) => TransactionData::V1(g.gasless(c, pt.clone())),
            None => g.pt_data(pt.clone()),
        };
        let ssd = g.sign(data);
        let size = bcs::serialized_size(&ssd).unwrap();
        if size == target {
            return ssd;
        }
        let CallArg::Pure(p) = &mut pt.inputs[idx] else { panic!() };
        let len = p.len() as i64 + target as i64 - size as i64;
        p.resize(len.max(0) as usize, 0);
    }
    panic!("could not pad to {target}");
}

pub fn run(out_path: &str) -> anyhow::Result<()> {
    let mut rng = StdRng::from_seed([7; 32]);
    let (sender, kp): (SuiAddress, AccountKeyPair) = get_key_pair_from_rng(&mut rng);
    let mut g = Gen {
        out: Out::new(
            "suite validity: SenderSignedData::validity_check, Mysten sui mainnet-v1.83.1 (6a567faf)\n\
             fields: id pv chain epoch rgp committee chain_id SenderSignedData verdict",
        ),
        kp,
        sender,
    };
    let m = mainnet(141);

    // ---- baseline and existing rules (ordering anchors)
    g.ptb("base/ok", &m, g.base_pt());
    {
        let mut d = g.v1(g.base_pt());
        d.expiration = TransactionExpiration::Epoch(999);
        g.data_v1("base/epoch-expired", &m, d);
        let mut d = g.v1(g.base_pt());
        d.gas_data.price = 50_000_000_000;
        g.data_v1("base/gas-price-too-high", &m, d);
        let mut d = g.v1(g.base_pt());
        d.gas_data.budget = 999;
        g.data_v1("base/budget-too-low", &m, d);
        let mut d = g.v1(g.base_pt());
        d.gas_data.payment = vec![];
        d.gas_data.budget = 10_000_000;
        g.data_v1("base/ab-gas-none-expiration", &m, d);
        let mut d = g.v1(g.base_pt());
        d.expiration = TransactionExpiration::ValidDuring {
            min_epoch: Some(1000),
            max_epoch: Some(1000),
            min_timestamp: None,
            max_timestamp: None,
            chain: ChainIdentifier::from(CheckpointDigest::new([1; 32])),
            nonce: 0,
        };
        g.data_v1("base/wrong-chain", &m, d);
    }

    // ---- system kinds
    {
        let d = TransactionData::new_with_gas_data(
            TransactionKind::Genesis(GenesisTransaction { objects: vec![] }),
            sender,
            GasData { payment: vec![gas_ref()], owner: sender, price: 1000, budget: 10_000_000 },
        );
        let ssd = g.sign(d);
        g.emit("system/genesis", &m, &ssd);
    }

    // ---- serialized size
    {
        let mut pt = g.base_pt();
        for _ in 0..8 {
            pt.inputs.push(CallArg::Pure(vec![0; 16000]));
        }
        pt.inputs.push(CallArg::Pure(vec![]));
        let last = pt.inputs.len() - 1;
        for (name, target) in [("size/at-limit", 131072), ("size/over-by-1", 131073), ("size/under-by-1", 131071)] {
            let ssd = pad_to(&g, pt.clone(), last, target, None);
            g.emit(name, &m, &ssd);
        }
        // the size check comes before every TransactionData rule
        let mut big = pt.clone();
        big.inputs.push(CallArg::Pure(vec![0; 20000]));
        g.ptb("size/over-and-pure-too-big", &m, big);
        // too many inputs objects cannot fit under the size limit
        let mut many = ProgrammableTransaction { inputs: vec![], commands: vec![] };
        for i in 0..2049u32 {
            let mut a = [0u8; 32];
            a[0] = 0x22;
            a[28..32].copy_from_slice(&i.to_be_bytes());
            many.inputs.push(CallArg::Object(ObjectArg::ImmOrOwnedObject((ObjectID::new(a), SequenceNumber::from_u64(1), ObjectDigest::new([3; 32])))));
        }
        many.commands.push(Command::TransferObjects(vec![Argument::Input(0)], Argument::GasCoin));
        g.ptb("size/2049-objects", &m, many);
    }

    // ---- type arguments: count and depth (type_input_validity_check)
    for n in [14usize, 15, 16, 17] {
        let targs = vec![TypeInput::U8; n];
        let pt = ProgrammableTransaction { inputs: vec![], commands: vec![call(fw(), "coin", "value", targs, vec![Argument::GasCoin])] };
        g.ptb(&format!("targs/count-{n}"), &m, pt);
    }
    for (a, b) in [(7usize, 8usize), (8, 8), (10, 10)] {
        let targs = vec![
            st(AccountAddress::ONE, "m", "S", vec![TypeInput::U64; a - 1]),
            st(AccountAddress::ONE, "m", "S", vec![TypeInput::U64; b - 1]),
        ];
        let pt = ProgrammableTransaction { inputs: vec![], commands: vec![call(fw(), "coin", "value", targs, vec![Argument::GasCoin])] };
        g.ptb(&format!("targs/struct-nodes-{a}+{b}"), &m, pt);
    }
    {
        // the counter is per command
        let mk = || call(fw(), "coin", "value", vec![TypeInput::U8; 10], vec![Argument::GasCoin]);
        g.ptb("targs/two-calls-10-each", &m, ProgrammableTransaction { inputs: vec![], commands: vec![mk(), mk()] });
    }
    for d in [13usize, 14, 15, 16] {
        let pt = ProgrammableTransaction { inputs: vec![], commands: vec![call(fw(), "coin", "value", vec![vec_depth(d)], vec![Argument::GasCoin])] };
        g.ptb(&format!("targs/vector-depth-{d}"), &m, pt);
        let pt = ProgrammableTransaction { inputs: vec![], commands: vec![Command::MakeMoveVec(Some(vec_depth(d)), vec![])] };
        g.ptb(&format!("mvec/vector-depth-{d}"), &m, pt);
    }
    {
        let mut t = TypeInput::U8;
        for _ in 0..15 {
            t = st(AccountAddress::ONE, "m", "S", vec![t]);
        }
        let pt = ProgrammableTransaction { inputs: vec![], commands: vec![call(fw(), "coin", "value", vec![t], vec![Argument::GasCoin])] };
        g.ptb("targs/struct-depth-15", &m, pt);
        let pt = ProgrammableTransaction { inputs: vec![], commands: vec![Command::MakeMoveVec(Some(TypeInput::U8), vec![])] };
        g.ptb("mvec/typed-empty-ok", &m, pt);
        let pt = ProgrammableTransaction { inputs: vec![], commands: vec![Command::MakeMoveVec(None, vec![])] };
        g.ptb("mvec/untyped-empty", &m, pt);
        let wide = st(AccountAddress::ONE, "m", "S", vec![TypeInput::U8; 16]);
        let pt = ProgrammableTransaction { inputs: vec![], commands: vec![Command::MakeMoveVec(Some(wide), vec![])] };
        g.ptb("mvec/type-17-nodes", &m, pt);
    }

    // ---- identifiers
    for (name, module, function) in [
        ("ident/ok-underscore", "_a", "f_1"),
        ("ident/module-digit", "0abc", "f"),
        ("ident/module-empty", "", "f"),
        ("ident/module-underscore-only", "_", "f"),
        ("ident/function-dash", "coin", "bad-fn"),
        ("ident/function-space", "coin", "a b"),
        ("ident/both-bad", "1", "2"),
        ("ident/unicode", "caf\u{e9}", "f"),
    ] {
        let pt = ProgrammableTransaction { inputs: vec![], commands: vec![call(fw(), module, function, vec![], vec![Argument::GasCoin])] };
        g.ptb(name, &m, pt);
        let mut old = m.clone();
        old.pv = 59;
        let pt = ProgrammableTransaction { inputs: vec![], commands: vec![call(fw(), module, function, vec![], vec![Argument::GasCoin])] };
        g.ptb(&format!("{name}@59"), &old, pt);
    }
    for (name, module, sname) in [("ident/struct-module", "9m", "S"), ("ident/struct-name", "m", "S-"), ("ident/struct-name-empty", "m", "")] {
        let pt = ProgrammableTransaction {
            inputs: vec![],
            commands: vec![call(fw(), "coin", "value", vec![st(AccountAddress::ONE, module, sname, vec![])], vec![Argument::GasCoin])],
        };
        g.ptb(name, &m, pt);
        let pt = ProgrammableTransaction { inputs: vec![], commands: vec![Command::MakeMoveVec(Some(st(AccountAddress::ONE, module, sname, vec![])), vec![])] };
        g.ptb(&format!("{name}-mvec"), &m, pt);
    }
    {
        // order inside a MoveCall: type arguments, then the argument count, then identifiers
        let pt = ProgrammableTransaction {
            inputs: vec![],
            commands: vec![call(fw(), "0bad", "f", vec![TypeInput::U8; 16], vec![Argument::GasCoin])],
        };
        g.ptb("ident/after-targs", &m, pt);
        let pt = ProgrammableTransaction {
            inputs: vec![],
            commands: vec![call(fw(), "0bad", "f", vec![], vec![Argument::GasCoin; 512])],
        };
        g.ptb("ident/after-arg-count", &m, pt);
        let pt = ProgrammableTransaction {
            inputs: vec![],
            commands: vec![call(fw(), "coin", "value", vec![st(AccountAddress::ONE, "9", "S", vec![])], vec![Argument::GasCoin; 512])],
        };
        g.ptb("ident/struct-before-arg-count", &m, pt);
    }

    // ---- argument indices (validate_ptb_argument_indices, on at 137)
    for (pv, sfx) in [(141u64, ""), (136, "@136")] {
        let mut c = m.clone();
        c.pv = pv;
        let one_input = vec![CallArg::Pure(vec![1])];
        let cases: Vec<(&str, Vec<Command>)> = vec![
            ("args/input-oob", vec![Command::TransferObjects(vec![Argument::GasCoin], Argument::Input(1))]),
            ("args/result-self", vec![Command::SplitCoins(Argument::GasCoin, vec![Argument::Result(0)])]),
            ("args/nested-forward", vec![
                Command::SplitCoins(Argument::GasCoin, vec![Argument::Input(0)]),
                Command::MergeCoins(Argument::GasCoin, vec![Argument::NestedResult(1, 0)]),
            ]),
            ("args/result-back-ok", vec![
                Command::SplitCoins(Argument::GasCoin, vec![Argument::Input(0)]),
                Command::MergeCoins(Argument::GasCoin, vec![Argument::NestedResult(0, 0), Argument::Result(0)]),
            ]),
            ("args/second-arg-oob", vec![
                Command::SplitCoins(Argument::GasCoin, vec![Argument::Input(0)]),
                call(fw(), "coin", "value", vec![], vec![Argument::Result(0), Argument::Input(9)]),
            ]),
            ("args/upgrade-ticket-oob", vec![Command::Upgrade(vec![vec![0]], vec![], oid(9), Argument::Result(3))]),
            ("args/transfer-recipient-oob", vec![Command::TransferObjects(vec![Argument::Input(0)], Argument::Result(0))]),
            ("args/mvec-oob", vec![Command::MakeMoveVec(None, vec![Argument::Input(0), Argument::Input(65535)])]),
        ];
        for (name, cmds) in cases {
            let pt = ProgrammableTransaction { inputs: one_input.clone(), commands: cmds };
            g.ptb(&format!("{name}{sfx}"), &c, pt);
        }
    }

    // ---- publish / upgrade limits
    {
        let publish = |n_mod: usize, n_dep: usize| Command::Publish(vec![vec![0xa1]; n_mod], (0..n_dep).map(|i| oid(100 + i as u8)).collect());
        for n in [5usize, 6] {
            let pt = ProgrammableTransaction { inputs: vec![], commands: (0..n).map(|_| publish(1, 0)).collect() };
            g.ptb(&format!("publish/count-{n}"), &m, pt);
        }
        let mut old = m.clone();
        old.pv = 23;
        let pt = ProgrammableTransaction { inputs: vec![], commands: (0..6).map(|_| publish(1, 0)).collect() };
        g.ptb("publish/count-6@23", &old, pt);
        let pt = ProgrammableTransaction {
            inputs: vec![],
            commands: vec![
                publish(1, 0),
                Command::Upgrade(vec![vec![1]], vec![], oid(9), Argument::GasCoin),
                Command::Upgrade(vec![vec![1]], vec![], oid(9), Argument::GasCoin),
                publish(1, 0),
                publish(1, 0),
                Command::Upgrade(vec![vec![1]], vec![], oid(9), Argument::GasCoin),
            ],
        };
        g.ptb("publish/mixed-6", &m, pt);
        for (name, cmd) in [
            ("publish/empty-modules", publish(0, 0)),
            ("publish/modules-63", publish(63, 0)),
            ("publish/modules-64", publish(64, 0)),
            ("publish/deps-31", publish(1, 31)),
            ("publish/deps-32", publish(1, 32)),
            ("upgrade/empty-modules", Command::Upgrade(vec![], vec![], oid(9), Argument::GasCoin)),
            ("upgrade/modules-64", Command::Upgrade(vec![vec![1]; 64], vec![], oid(9), Argument::GasCoin)),
            ("upgrade/deps-32", Command::Upgrade(vec![vec![1]], (0..32).map(|i| oid(100 + i as u8)).collect(), oid(9), Argument::GasCoin)),
        ] {
            g.ptb(name, &m, ProgrammableTransaction { inputs: vec![], commands: vec![cmd] });
        }
        let mut old = m.clone();
        old.pv = 37;
        g.ptb("publish/deps-32@37", &old, ProgrammableTransaction { inputs: vec![], commands: vec![publish(1, 32)] });
        // the publish count is checked before any command's own rules
        let mut cmds: Vec<Command> = vec![publish(0, 0)];
        cmds.extend((0..5).map(|_| publish(1, 0)));
        g.ptb("publish/count-before-empty", &m, ProgrammableTransaction { inputs: vec![], commands: cmds });
        // inputs are checked before the publish count
        let mut cmds: Vec<Command> = (0..6).map(|_| publish(1, 0)).collect();
        cmds.push(Command::TransferObjects(vec![Argument::GasCoin], Argument::Input(0)));
        g.ptb("publish/pure-before-count", &m, ProgrammableTransaction { inputs: vec![CallArg::Pure(vec![0; 16384])], commands: cmds });
    }

    // ---- randomness
    {
        let random = CallArg::Object(ObjectArg::SharedObject {
            id: SUI_RANDOMNESS_STATE_OBJECT_ID,
            initial_shared_version: SequenceNumber::from_u64(1),
            mutability: SharedObjectMutability::Immutable,
        });
        let use_random = || call(fw(), "random", "new_generator", vec![], vec![Argument::Input(0)]);
        let cases: Vec<(&str, Vec<Command>)> = vec![
            ("random/then-call", vec![use_random(), call(fw(), "coin", "value", vec![], vec![Argument::GasCoin])]),
            ("random/then-transfer", vec![use_random(), Command::TransferObjects(vec![Argument::GasCoin], Argument::Input(1))]),
            ("random/then-merge", vec![use_random(), Command::MergeCoins(Argument::GasCoin, vec![Argument::Result(0)])]),
            ("random/then-split", vec![use_random(), Command::SplitCoins(Argument::GasCoin, vec![Argument::Input(1)])]),
            ("random/then-mvec", vec![use_random(), Command::MakeMoveVec(None, vec![Argument::Input(1)])]),
            ("random/unused", vec![call(fw(), "coin", "value", vec![], vec![Argument::GasCoin]), call(fw(), "coin", "value", vec![], vec![Argument::GasCoin])]),
            ("random/call-before", vec![call(fw(), "coin", "value", vec![], vec![Argument::GasCoin]), use_random()]),
            ("random/transfer-uses-random", vec![Command::TransferObjects(vec![Argument::Input(0)], Argument::Input(1)), call(fw(), "coin", "value", vec![], vec![Argument::GasCoin])]),
        ];
        for (name, cmds) in cases {
            let pt = ProgrammableTransaction { inputs: vec![random.clone(), CallArg::Pure(vec![1; 32])], commands: cmds };
            g.ptb(name, &m, pt);
        }
        // the random input found is the first one, even when it appears twice
        let pt = ProgrammableTransaction {
            inputs: vec![CallArg::Pure(vec![1; 32]), random.clone(), random.clone()],
            commands: vec![call(fw(), "random", "new_generator", vec![], vec![Argument::Input(2)]), call(fw(), "coin", "value", vec![], vec![Argument::GasCoin])],
        };
        g.ptb("random/duplicate-input", &m, pt);
        let mut old = m.clone();
        old.pv = 53;
        let pt = ProgrammableTransaction { inputs: vec![random.clone()], commands: vec![use_random()] };
        g.ptb("random/off@53", &old, pt);
    }

    // ---- duplicate object inputs (DuplicateObjectRefInput) and its place in the order
    {
        let dup = CallArg::Object(ObjectArg::ImmOrOwnedObject(oref(1)));
        let pt = ProgrammableTransaction { inputs: vec![dup.clone(), dup.clone()], commands: vec![Command::MergeCoins(Argument::Input(0), vec![Argument::Input(1)])] };
        g.ptb("dup/owned", &m, pt);
        let shared = |m: SharedObjectMutability| CallArg::Object(ObjectArg::SharedObject { id: oid(1), initial_shared_version: SequenceNumber::from_u64(1), mutability: m });
        let pt = ProgrammableTransaction { inputs: vec![dup.clone(), shared(SharedObjectMutability::Mutable)], commands: vec![Command::MergeCoins(Argument::Input(0), vec![Argument::Input(1)])] };
        g.ptb("dup/owned-shared", &m, pt);
        let recv = CallArg::Object(ObjectArg::Receiving(oref(1)));
        let pt = ProgrammableTransaction { inputs: vec![dup.clone(), recv], commands: vec![Command::MergeCoins(Argument::Input(0), vec![Argument::Input(1)])] };
        g.ptb("dup/owned-receiving-ok", &m, pt);
        let pt = ProgrammableTransaction { inputs: vec![dup.clone(), dup.clone(), CallArg::Pure(vec![0; 16384])], commands: vec![Command::MergeCoins(Argument::Input(0), vec![Argument::Input(1)])] };
        g.ptb("dup/before-pure-size", &m, pt);
        let pt = ProgrammableTransaction { inputs: vec![dup.clone(), dup], commands: (0..1024).map(|_| Command::MergeCoins(Argument::Input(0), vec![Argument::Input(1)])).collect() };
        g.ptb("dup/after-command-count", &m, pt);
        // the gas coin may also be an input object: not a duplicate for validity_check
        let pt = ProgrammableTransaction { inputs: vec![CallArg::Object(ObjectArg::ImmOrOwnedObject(gas_ref()))], commands: vec![Command::MergeCoins(Argument::GasCoin, vec![Argument::Input(0)])] };
        g.ptb("dup/gas-as-input", &m, pt);
    }

    // ---- signature schemes against the protocol flags
    {
        let data = g.pt_data(g.base_pt());
        let intent = IntentMessage::new(Intent::sui_transaction(), data.clone());
        // multisig of one ed25519 key
        let ed = SuiKeyPair::Ed25519(g.kp.copy());
        let ms_pk = MultiSigPublicKey::new(vec![ed.public()], vec![1], 1).unwrap();
        let s: GenericSignature = Signature::new_secure(&intent, &g.kp).into();
        let ms = MultiSig::combine(vec![s], ms_pk).unwrap();
        let ssd = g.with_sigs(data.clone(), vec![GenericSignature::MultiSig(ms)]);
        g.emit("sig/multisig", &m, &ssd);
        let mut old = m.clone();
        old.pv = 16;
        g.emit("sig/multisig@16", &old, &ssd);
        // zkLogin: a well-formed authenticator (src/types/testdata/rust_edge.txt zk-plain)
        let zk = GenericSignature::from_bytes(&hex::decode(ZK_PLAIN.trim()).unwrap()).expect("zk-plain parses");
        let ssd = g.with_sigs(data.clone(), vec![zk]);
        g.emit("sig/zklogin", &m, &ssd);
        let mut old = m.clone();
        old.pv = 24;
        g.emit("sig/zklogin@24", &old, &ssd);
        // passkey
        let (_, r1): (SuiAddress, fastcrypto::secp256r1::Secp256r1KeyPair) = get_key_pair_from_rng(&mut StdRng::from_seed([9; 32]));
        let r1 = SuiKeyPair::Secp256r1(r1);
        let challenge = fastcrypto::rsa::Base64UrlUnpadded::encode_string(&[7u8; 32]);
        let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"http://localhost:5173","crossOrigin":false}}"#);
        let pk_sig = Signature::new_secure(&IntentMessage::new(Intent::sui_transaction(), [1u8; 4]), &r1);
        let pass = PasskeyAuthenticator::new_for_testing(vec![0; 37], cdj, pk_sig).unwrap();
        let ssd = g.with_sigs(data.clone(), vec![GenericSignature::PasskeyAuthenticator(pass)]);
        g.emit("sig/passkey", &m, &ssd);
        let mut old = m.clone();
        old.pv = 89;
        g.emit("sig/passkey@89", &old, &ssd);
        // ML-DSA-65 (off on mainnet): single and as a multisig member
        let (_, pq): (SuiAddress, fastcrypto_pq::mldsa65::MLDSA65KeyPair) = get_key_pair_from_rng(&mut StdRng::from_seed([5; 32]));
        let pq = SuiKeyPair::MLDSA65(pq);
        let s = Signature::new_secure(&intent, &pq);
        let ssd = g.with_sigs(data.clone(), vec![s.clone().into()]);
        g.emit("sig/mldsa65", &m, &ssd);
        let ms_pk = MultiSigPublicKey::new(vec![pq.public()], vec![1], 1).unwrap();
        let ms = MultiSig::combine(vec![s.into()], ms_pk).unwrap();
        let ssd = g.with_sigs(data.clone(), vec![GenericSignature::MultiSig(ms)]);
        g.emit("sig/multisig-mldsa65", &m, &ssd);
        // the signature check comes before the system-kind rule and the size limit
        let genesis_td = TransactionData::new_with_gas_data(
            TransactionKind::Genesis(GenesisTransaction { objects: vec![] }),
            sender,
            GasData { payment: vec![gas_ref()], owner: sender, price: 1000, budget: 10_000_000 },
        );
        let zk = GenericSignature::from_bytes(&hex::decode(ZK_PLAIN.trim()).unwrap()).unwrap();
        let ssd = g.with_sigs(genesis_td, vec![zk]);
        let mut old = m.clone();
        old.pv = 24;
        g.emit("sig/zklogin-system@24", &old, &ssd);
    }

    // ---- gasless (enable_gasless at 124 on mainnet; validate_gasless_transaction)
    {
        let usdc = || tin(USDC);
        let wd = |amt: u64| CallArg::FundsWithdrawal(FundsWithdrawalArg::balance_from_sender(amt, tag(USDC)));
        let recipient = CallArg::Pure(bcs::to_bytes(&sender).unwrap());
        let send = |args: Vec<Argument>| call(fw(), "balance", "send_funds", vec![usdc()], args);
        let mut gl = |g: &mut Gen, id: &str, c: &Ctx, inputs: Vec<CallArg>, commands: Vec<Command>| {
            let d = g.gasless(c, ProgrammableTransaction { inputs, commands });
            g.data_v1(id, c, d);
        };
        let redeem = call(fw(), "balance", "redeem_funds", vec![usdc()], vec![Argument::Input(0)]);
        gl(&mut g, "gasless/ok", &m, vec![wd(10), recipient.clone()], vec![redeem.clone(), send(vec![Argument::Result(0), Argument::Input(1)])]);
        gl(&mut g, "gasless/no-commands", &m, vec![], vec![]);
        gl(&mut g, "gasless/receiving", &m, vec![CallArg::Object(ObjectArg::Receiving(oref(4)))], vec![send(vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/receiving-and-transfer", &m, vec![CallArg::Object(ObjectArg::Receiving(oref(4))), recipient.clone()], vec![Command::TransferObjects(vec![Argument::Input(0)], Argument::Input(1))]);
        gl(&mut g, "gasless/transfer", &m, vec![CallArg::Object(ObjectArg::ImmOrOwnedObject(oref(4))), recipient.clone()], vec![Command::TransferObjects(vec![Argument::Input(0)], Argument::Input(1))]);
        gl(&mut g, "gasless/mvec", &m, vec![CallArg::Object(ObjectArg::ImmOrOwnedObject(oref(4)))], vec![Command::MakeMoveVec(None, vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/split-merge-ok", &m, vec![CallArg::Object(ObjectArg::ImmOrOwnedObject(oref(4))), CallArg::Pure(vec![1, 0, 0, 0, 0, 0, 0, 0])], vec![
            Command::SplitCoins(Argument::Input(0), vec![Argument::Input(1)]),
            Command::MergeCoins(Argument::Input(0), vec![Argument::Result(0)]),
        ]);
        gl(&mut g, "gasless/fn-not-allowed", &m, vec![wd(10)], vec![call(fw(), "coin", "value", vec![usdc()], vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/wrong-package", &m, vec![wd(10)], vec![call(ObjectID::from(AccountAddress::from_hex_literal("0x3").unwrap()), "balance", "send_funds", vec![usdc()], vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/targ-count-0", &m, vec![wd(10)], vec![call(fw(), "balance", "send_funds", vec![], vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/targ-count-2", &m, vec![wd(10)], vec![call(fw(), "balance", "send_funds", vec![usdc(), usdc()], vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/fund-sui", &m, vec![wd(10)], vec![call(fw(), "balance", "send_funds", vec![tin("0x2::sui::SUI")], vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/fund-vector", &m, vec![wd(10)], vec![call(fw(), "balance", "zero", vec![vec_depth(1)], vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/split-balance-usdc", &m, vec![wd(10), CallArg::Pure(vec![1, 0, 0, 0, 0, 0, 0, 0])], vec![call(fw(), "funds_accumulator", "withdrawal_split", vec![tin(&format!("0x2::balance::Balance<{USDC}>"))], vec![Argument::Input(0), Argument::Input(1)])]);
        gl(&mut g, "gasless/split-not-balance", &m, vec![wd(10), CallArg::Pure(vec![1, 0, 0, 0, 0, 0, 0, 0])], vec![call(fw(), "funds_accumulator", "withdrawal_split", vec![usdc()], vec![Argument::Input(0), Argument::Input(1)])]);
        gl(&mut g, "gasless/split-balance-sui", &m, vec![wd(10), CallArg::Pure(vec![1, 0, 0, 0, 0, 0, 0, 0])], vec![call(fw(), "funds_accumulator", "withdrawal_split", vec![tin("0x2::balance::Balance<0x2::sui::SUI>")], vec![Argument::Input(0), Argument::Input(1)])]);
        for f in ["coin::into_balance", "coin::redeem_funds", "coin::send_funds", "coin::put", "balance::split", "balance::zero", "balance::redeem_funds"] {
            let (module, function) = f.split_once("::").unwrap();
            gl(&mut g, &format!("gasless/allowed-{module}-{function}"), &m, vec![wd(10)], vec![call(fw(), module, function, vec![usdc()], vec![Argument::Input(0)])]);
        }
        gl(&mut g, "gasless/pure-32", &m, vec![wd(10), CallArg::Pure(vec![1; 32])], vec![send(vec![Argument::Input(0), Argument::Input(1)])]);
        gl(&mut g, "gasless/pure-33", &m, vec![wd(10), CallArg::Pure(vec![1; 33])], vec![send(vec![Argument::Input(0), Argument::Input(1)])]);
        gl(&mut g, "gasless/pure-33-unused", &m, vec![wd(10), CallArg::Pure(vec![1; 33])], vec![send(vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/one-unused-pure", &m, vec![wd(10), CallArg::Pure(vec![1; 8])], vec![send(vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/two-unused-pure", &m, vec![wd(10), CallArg::Pure(vec![1; 8]), CallArg::Pure(vec![2; 8])], vec![send(vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/unused-object", &m, vec![wd(10), CallArg::Object(ObjectArg::ImmOrOwnedObject(oref(4)))], vec![send(vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/unused-shared", &m, vec![wd(10), CallArg::Object(ObjectArg::SharedObject { id: oid(5), initial_shared_version: SequenceNumber::from_u64(1), mutability: SharedObjectMutability::Mutable })], vec![send(vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/unused-withdrawal", &m, vec![wd(10), wd(20)], vec![send(vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/unused-object-and-pure", &m, vec![wd(10), CallArg::Pure(vec![1; 40]), CallArg::Object(ObjectArg::ImmOrOwnedObject(oref(4)))], vec![send(vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/command-order", &m, vec![wd(10)], vec![send(vec![Argument::Input(0)]), Command::TransferObjects(vec![Argument::Input(0)], Argument::Input(0)), call(fw(), "coin", "value", vec![usdc()], vec![Argument::Input(0)])]);
        gl(&mut g, "gasless/ptb-rule-first", &m, vec![wd(10)], vec![send(vec![Argument::Input(3)])]);
        // size
        {
            let pt = ProgrammableTransaction { inputs: vec![wd(10), CallArg::Pure(vec![0; 100])], commands: vec![send(vec![Argument::Input(0), Argument::Input(1)])] };
            for (name, target) in [("gasless/size-16384", 16384), ("gasless/size-16385", 16385)] {
                let ssd = pad_to(&g, pt.clone(), 1, target, Some(&m));
                g.emit(name, &m, &ssd);
            }
        }
        // gas rules for gasless
        let mut d = g.gasless(&m, ProgrammableTransaction { inputs: vec![wd(10)], commands: vec![send(vec![Argument::Input(0)])] });
        d.gas_data.budget = 1;
        g.data_v1("gasless/budget-1", &m, d);
        let mut d = g.gasless(&m, ProgrammableTransaction { inputs: vec![wd(10)], commands: vec![call(fw(), "coin", "value", vec![], vec![])] });
        d.gas_data.price = 1;
        g.data_v1("gasless/price-1-not-gasless", &m, d);
        // before gasless existed: a zero-price address-balance payment is not gasless
        let mut old = m.clone();
        old.pv = 123;
        let d = g.gasless(&old, ProgrammableTransaction { inputs: vec![], commands: vec![] });
        g.data_v1("gasless/no-commands@123", &old, d);
        // testnet allow-list (USDC testnet only)
        // (pv 130: get_gasless_allowed_token_types caches by version only, so a testnet config
        // at a version already used for mainnet in this process would see the mainnet list)
        let mut tn = m.clone();
        tn.chain = Chain::Testnet;
        tn.pv = 130;
        gl(&mut g, "gasless/mainnet-usdc@testnet", &tn, vec![wd(10)], vec![send(vec![Argument::Input(0)])]);
        let tusdc = "0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC";
        let twd = CallArg::FundsWithdrawal(FundsWithdrawalArg::balance_from_sender(10, tag(tusdc)));
        gl(&mut g, "gasless/testnet-usdc@testnet", &tn, vec![twd], vec![call(fw(), "balance", "send_funds", vec![tin(tusdc)], vec![Argument::Input(0)])]);
        // the sponsor pays nothing: sponsored gasless
        let mut d = g.gasless(&m, ProgrammableTransaction { inputs: vec![wd(10)], commands: vec![send(vec![Argument::Input(0)])] });
        d.gas_data.owner = SuiAddress::from(oid(77));
        g.data_v1("gasless/sponsored", &m, d);
    }

    g.out.write(out_path)
}

/// `zk-plain` of src/types/testdata/rust_edge.txt: a zkLogin authenticator that decodes.
const ZK_PLAIN: &str = include_str!("zk_plain.hex");
