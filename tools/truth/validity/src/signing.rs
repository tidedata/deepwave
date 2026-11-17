//! Suite `signing`: the checks of the vote and SubmitTransaction after `validity_check` that read
//! state (sui-core authority.rs `handle_transaction_deny_checks`): `pre_object_load_checks`
//! (`process_funds_withdrawals_for_signing`, `check_amounts_available`, the gasless remaining
//! amounts), `check_transaction_input` (with `check_gasless_object_inputs`) over the inputs read
//! at their claimed versions, then `handle_coin_deny_list_checks` (v1 when the 0x403 deny list
//! exists, then v2 with `read_value(None)`). The transaction deny config is empty.
//!
//! Line: `id  pv  chain  epoch  rgp  committee  chain_id(hex)  objects  SenderSignedData(hex)
//! verdict`; objects is a comma-separated list of BCS `Object` hex (empty for none), the whole
//! store the case runs against.

use crate::common::{Out, verdict};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::{StructTag, TypeTag};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::BTreeSet;
use std::sync::Arc;
use sui_config::verifier_signing_config::VerifierSigningConfig;
use sui_core::accumulators::funds_read::AccountFundsRead;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::accumulator_root::{AccumulatorObjId, AccumulatorValue};
use sui_types::balance::Balance;
use sui_types::base_types::{MoveObjectType, ObjectID, SequenceNumber, SuiAddress};
use sui_types::coin_reservation::BorrowedCoinReservationResolver;
use sui_types::config::{Setting, SettingData};
use sui_types::crypto::{AccountKeyPair, get_key_pair_from_rng};
use sui_types::digests::TransactionDigest;
use sui_types::digests::{ChainIdentifier, CheckpointDigest};
use sui_types::dynamic_field::derive_dynamic_field_id;
use sui_types::error::SuiResult;
use sui_types::in_memory_storage::InMemoryStorage;
use sui_types::metrics::BytecodeVerifierMetrics;
use sui_types::object::{MoveObject, Object, Owner};
use sui_types::transaction::{
    Argument, CallArg, Command, FundsWithdrawalArg, GasData, InputObjects, ObjectArg, ObjectReadResult,
    ProgrammableMoveCall, ProgrammableTransaction, ReceivingObjectReadResult, ReceivingObjectReadResultKind,
    ReceivingObjects, SenderSignedData, Transaction, TransactionData, TransactionDataAPI, TransactionDataV1,
    TransactionExpiration, TransactionKind, TxValidityCheckContext, get_gasless_allowed_token_types,
};
use sui_types::type_input::TypeInput;
use sui_types::{SUI_DENY_LIST_OBJECT_ID, SUI_FRAMEWORK_ADDRESS};

const PV: u64 = 141;
const EPOCH: u64 = 1000;
const RGP: u64 = 1000;
const USDC: &str = "0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC";
const REG: &str = "0x77::reg::REG";
const REG2: &str = "0x55::reg::REG";

fn chain_id() -> ChainIdentifier {
    ChainIdentifier::from(CheckpointDigest::new([0x4a; 32]))
}

fn tag(s: &str) -> TypeTag {
    s.parse().unwrap()
}

fn canonical(s: &str) -> String {
    tag(s).to_canonical_string(false)
}

fn oid(b: u8) -> ObjectID {
    let mut a = [0u8; 32];
    a[0] = 0x22;
    a[31] = b;
    ObjectID::new(a)
}

fn addr(b: u8) -> SuiAddress {
    SuiAddress::from(oid(b))
}

fn fw_struct(module: &str, name: &str, params: Vec<TypeTag>) -> StructTag {
    StructTag {
        address: SUI_FRAMEWORK_ADDRESS,
        module: Identifier::new(module).unwrap(),
        name: Identifier::new(name).unwrap(),
        type_params: params,
    }
}

fn fw_tag(module: &str, name: &str, params: Vec<TypeTag>) -> TypeTag {
    TypeTag::Struct(Box::new(fw_struct(module, name, params)))
}

fn balance_of(coin: &str) -> TypeTag {
    fw_tag("balance", "Balance", vec![tag(coin)])
}

fn v(n: u64) -> SequenceNumber {
    SequenceNumber::from_u64(n)
}

fn move_obj(t: StructTag, version: u64, contents: Vec<u8>, owner: Owner) -> Object {
    let mo = unsafe { MoveObject::new_from_execution_with_limit(MoveObjectType::from(t), false, v(version), contents, 1 << 20).unwrap() };
    Object::new_move(mo, owner, TransactionDigest::genesis_marker())
}

fn coin(coin_type: &str, id: ObjectID, value: u64, owner: Owner) -> Object {
    let mo = MoveObject::new_coin(tag(coin_type), v(5), id, value);
    Object::new_move(mo, owner, TransactionDigest::genesis_marker())
}

fn gas_coin(id: ObjectID, value: u64, owner: SuiAddress) -> Object {
    Object::new_move(MoveObject::new_gas_coin(v(5), id, value), Owner::AddressOwner(owner), TransactionDigest::genesis_marker())
}

/// `dynamic_field::Field<K, V>` of `parent` under `key`.
fn field(parent: ObjectID, key_tag: TypeTag, key: Vec<u8>, value_tag: TypeTag, value: Vec<u8>) -> Object {
    let id = derive_dynamic_field_id(parent, &key_tag, &key).unwrap();
    let mut contents = id.to_vec();
    contents.extend(key);
    contents.extend(value);
    move_obj(fw_struct("dynamic_field", "Field", vec![key_tag, value_tag]), 3, contents, Owner::ObjectOwner(parent.into()))
}

fn setting(newer_epoch: u64, newer: Option<bool>, older: Option<bool>) -> Vec<u8> {
    bcs::to_bytes(&Setting {
        data: Some(SettingData { newer_value_epoch: newer_epoch, newer_value: newer, older_value_opt: older }),
    })
    .unwrap()
}

/// Deny list v2 state for `coin`: the per-type config field of 0x403, the global pause setting
/// and the address settings (each a `Setting<bool>` BCS).
fn deny_v2(objs: &mut Vec<Object>, coin: &str, cfg_id: ObjectID, pause: Option<Vec<u8>>, addrs: Vec<(SuiAddress, Vec<u8>)>) {
    let ty = canonical(coin);
    let key = bcs::to_bytes(&(0u64, ty.as_bytes().to_vec())).unwrap();
    let key_tag = fw_tag("dynamic_object_field", "Wrapper", vec![fw_tag("deny_list", "ConfigKey", vec![])]);
    objs.push(field(SUI_DENY_LIST_OBJECT_ID, key_tag, key, fw_tag("object", "ID", vec![]), cfg_id.to_vec()));
    let setting_tag = fw_tag("config", "Setting", vec![TypeTag::Bool]);
    if let Some(p) = pause {
        objs.push(field(cfg_id, fw_tag("deny_list", "GlobalPauseKey", vec![]), vec![0], setting_tag.clone(), p));
    }
    for (a, s) in addrs {
        objs.push(field(cfg_id, fw_tag("deny_list", "AddressKey", vec![]), a.to_vec(), setting_tag.clone(), s));
    }
}

/// Deny list v1 state: the 0x403 `DenyList` with its `lists` bag, entry 0 (`PerTypeList`), the
/// `denied_count` entries and the `denied_addresses` set per coin type.
fn deny_v1(objs: &mut Vec<Object>, counts: Vec<(SuiAddress, u64)>, sets: Vec<(&str, Vec<SuiAddress>)>) {
    let bag = oid(0xb0);
    let per_type = oid(0xb1);
    let count_t = oid(0xb2);
    let addrs_t = oid(0xb3);
    let mut root = SUI_DENY_LIST_OBJECT_ID.to_vec();
    root.extend(bag.to_vec());
    root.extend(1u64.to_le_bytes());
    objs.push(move_obj(fw_struct("deny_list", "DenyList", vec![]), 9, root, Owner::Shared { initial_shared_version: v(1) }));
    let mut ptl = per_type.to_vec();
    ptl.extend(count_t.to_vec());
    ptl.extend((counts.len() as u64).to_le_bytes());
    ptl.extend(addrs_t.to_vec());
    ptl.extend((sets.len() as u64).to_le_bytes());
    objs.push(field(bag, TypeTag::U64, 0u64.to_le_bytes().to_vec(), fw_tag("deny_list", "PerTypeList", vec![]), ptl));
    for (a, n) in counts {
        objs.push(field(count_t, TypeTag::Address, a.to_vec(), TypeTag::U64, n.to_le_bytes().to_vec()));
    }
    for (c, list) in sets {
        let key = bcs::to_bytes(&canonical(c).into_bytes()).unwrap();
        objs.push(field(
            addrs_t,
            TypeTag::Vector(Box::new(TypeTag::U8)),
            key,
            fw_tag("vec_set", "VecSet", vec![TypeTag::Address]),
            bcs::to_bytes(&list).unwrap(),
        ));
    }
}

fn account(owner: SuiAddress, coin: &str, amount: u64) -> Object {
    AccumulatorValue::create_for_testing(owner, balance_of(coin), amount)
}

struct Funds<'a>(&'a InMemoryStorage);

impl AccountFundsRead for Funds<'_> {
    fn get_latest_account_amount(&self, account_id: &AccumulatorObjId) -> u128 {
        // writeback_cache.rs account_amount_from_object
        match self.0.get_object(account_id.inner()) {
            Some(o) => {
                let (_, AccumulatorValue::U128(value)) = o.data.try_as_move().unwrap().try_into().unwrap();
                value.value
            }
            None => 0,
        }
    }
    fn get_consistent_latest_account_amount_and_version(&self, _: &AccumulatorObjId) -> (u128, SequenceNumber) {
        unimplemented!()
    }
    fn get_account_amount_at_version(&self, _: &AccumulatorObjId, _: SequenceNumber) -> u128 {
        unimplemented!()
    }
}

/// `SenderSignedData::validity_check`, then `handle_transaction_deny_checks` as authority.rs runs
/// it (the inputs are always present at their claimed versions here).
fn signing_checks(cfg: &ProtocolConfig, ssd: &SenderSignedData, store: &InMemoryStorage) -> SuiResult<()> {
    let ctx = TxValidityCheckContext { config: cfg, epoch: EPOCH, chain_identifier: chain_id(), reference_gas_price: RGP, committee_size: 4 };
    ssd.validity_check(&ctx)?;
    let tx = &ssd.intent_message().value;
    let kinds = tx.input_objects()?;
    let recv_refs = tx.receiving_objects();

    // pre_object_load_checks (empty transaction deny config)
    let resolver = BorrowedCoinReservationResolver::new(store);
    let declared = tx.process_funds_withdrawals_for_signing(chain_id(), &resolver)?;
    let funds = Funds(store);
    funds.check_amounts_available(&declared)?;
    if cfg.gasless_verify_remaining_balance() && tx.is_gasless_transaction() {
        let min_amounts = get_gasless_allowed_token_types(cfg);
        funds.check_remaining_amounts_after_withdrawal(&declared, &min_amounts)?;
    }

    // read_objects_for_signing
    let reads = kinds
        .iter()
        .map(|k| ObjectReadResult::new(*k, store.get_object(&k.object_id()).unwrap_or_else(|| panic!("case input {} missing", k.object_id())).clone().into()))
        .collect();
    let recv: ReceivingObjects = recv_refs
        .iter()
        .map(|r| ReceivingObjectReadResult::new(*r, ReceivingObjectReadResultKind::Object(store.get_object(&r.0).expect("case receiving object missing").clone())))
        .collect::<Vec<_>>()
        .into();
    let metrics = Arc::new(BytecodeVerifierMetrics::new(&prometheus::Registry::new()));
    let (_, checked) = sui_transaction_checks::check_transaction_input(cfg, RGP, tx, InputObjects::new(reads), &recv, &metrics, &VerifierSigningConfig::default())?;

    // handle_coin_deny_list_checks
    let funds_withdrawals = declared
        .values()
        .filter_map(|(_, type_tag, funder)| Balance::maybe_get_balance_type_param(type_tag).map(|ty| (*funder, ty.to_canonical_string(false))))
        .collect::<BTreeSet<_>>();
    // coin_deny_list_v1_enabled: the flag and the deny list state at epoch start
    if cfg.enable_coin_deny_list() && store.get_object(&SUI_DENY_LIST_OBJECT_ID).is_some() {
        sui_types::deny_list_v1::check_coin_deny_list_v1(tx.sender(), &checked, &recv, funds_withdrawals.clone(), store)?;
    }
    if cfg.enable_coin_deny_list_v2() {
        sui_types::deny_list_v2::check_coin_deny_list_v2_during_signing(tx.sender(), &checked, &recv, funds_withdrawals, store)?;
    }
    Ok(())
}

struct Gen {
    out: Out,
    kp: AccountKeyPair,
    sender: SuiAddress,
    cfg: ProtocolConfig,
}

impl Gen {
    fn emit(&mut self, id: &str, mut objs: Vec<Object>, data: TransactionData) {
        // the packages the commands name (Move call targets and type-argument packages are input
        // objects): empty stand-ins, no modules are read by these checks
        if let Ok(kinds) = data.input_objects() {
            for k in kinds {
                if let sui_types::transaction::InputObjectKind::MovePackage(pid) = k
                    && !objs.iter().any(|o| o.id() == pid)
                {
                    let pkg = sui_types::move_package::MovePackage::new(pid, v(1), std::collections::BTreeMap::new(), 100_000, vec![], std::collections::BTreeMap::new()).unwrap();
                    objs.push(Object::new_from_package(pkg, TransactionDigest::genesis_marker()));
                }
            }
        }
        let ssd = Transaction::from_data_and_signer(data, vec![&self.kp]).into_data();
        let store = InMemoryStorage::new(objs.clone());
        let r = signing_checks(&self.cfg, &ssd, &store);
        let objs_hex = {
            objs.iter().map(|o| hex::encode(bcs::to_bytes(o).unwrap())).collect::<Vec<_>>().join(",")
        };
        self.out.push(&[
            id.to_string(),
            PV.to_string(),
            "mainnet".to_string(),
            EPOCH.to_string(),
            RGP.to_string(),
            "4".to_string(),
            hex::encode(chain_id().as_bytes()),
            objs_hex,
            hex::encode(bcs::to_bytes(&ssd).unwrap()),
            verdict(&r, |_| None),
        ]);
    }

    fn gas(&self) -> Object {
        gas_coin(oid(0xee), 10_000_000_000, self.sender)
    }

    /// A transaction paid with the gas coin `gas()`.
    fn paid(&self, inputs: Vec<CallArg>, commands: Vec<Command>) -> TransactionData {
        TransactionData::new_programmable(self.sender, vec![self.gas().compute_object_reference()], ProgrammableTransaction { inputs, commands }, 10_000_000, RGP)
    }

    fn valid_during(&self) -> TransactionExpiration {
        TransactionExpiration::ValidDuring { min_epoch: Some(EPOCH), max_epoch: Some(EPOCH), min_timestamp: None, max_timestamp: None, chain: chain_id(), nonce: 1 }
    }

    /// Gas paid from the sender's SUI address balance.
    fn ab(&self, budget: u64, inputs: Vec<CallArg>, commands: Vec<Command>) -> TransactionData {
        TransactionData::V1(TransactionDataV1 {
            kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction { inputs, commands }),
            sender: self.sender,
            gas_data: GasData { payment: vec![], owner: self.sender, price: RGP, budget },
            expiration: self.valid_during(),
        })
    }

    fn gasless(&self, inputs: Vec<CallArg>, commands: Vec<Command>) -> TransactionData {
        TransactionData::V1(TransactionDataV1 {
            kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction { inputs, commands }),
            sender: self.sender,
            gas_data: GasData { payment: vec![], owner: self.sender, price: 0, budget: 0 },
            expiration: self.valid_during(),
        })
    }
}

fn call(module: &str, function: &str, coin: &str, args: Vec<Argument>) -> Command {
    Command::MoveCall(Box::new(ProgrammableMoveCall {
        package: ObjectID::from(SUI_FRAMEWORK_ADDRESS),
        module: module.to_string(),
        function: function.to_string(),
        type_arguments: vec![TypeInput::from(tag(coin))],
        arguments: args,
    }))
}

fn owned(o: &Object) -> CallArg {
    CallArg::Object(ObjectArg::ImmOrOwnedObject(o.compute_object_reference()))
}

fn shared(o: &Object, isv: u64) -> CallArg {
    CallArg::Object(ObjectArg::SharedObject { id: o.id(), initial_shared_version: v(isv), mutability: sui_types::transaction::SharedObjectMutability::Mutable })
}

fn wd(coin: &str, amount: u64) -> CallArg {
    CallArg::FundsWithdrawal(FundsWithdrawalArg::balance_from_sender(amount, tag(coin)))
}

pub fn run(out_path: &str) -> anyhow::Result<()> {
    let mut rng = StdRng::from_seed([9; 32]);
    let (sender, kp): (SuiAddress, AccountKeyPair) = get_key_pair_from_rng(&mut rng);
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(PV), Chain::Mainnet);
    let mut g = Gen {
        out: Out::new(
            "zui-truth-validity signing: Mysten sui 1.83.1 (protocol 141, mainnet) signing-time checks after validity_check\n\
             fields: id pv chain epoch rgp committee chain_id objects ssd verdict",
        ),
        kp,
        sender,
        cfg,
    };
    let me = || CallArg::Pure(bcs::to_bytes(&sender).unwrap());
    let other = addr(0x99);
    let mvec = || Command::MakeMoveVec(Some(TypeInput::U8), vec![]);

    // ---- base
    g.emit("base/transfer-gas", vec![g.gas()], g.paid(vec![me()], vec![Command::TransferObjects(vec![Argument::GasCoin], Argument::Input(0))]));

    // ---- funds at signing (G17): address-balance gas and FundsWithdrawal inputs
    let sui = "0x2::sui::SUI";
    g.emit("funds/ab-gas-ok", vec![account(sender, sui, 1_000_000_000)], g.ab(5_000_000, vec![], vec![mvec()]));
    g.emit("funds/ab-gas-exact", vec![account(sender, sui, 5_000_000)], g.ab(5_000_000, vec![], vec![mvec()]));
    g.emit("funds/ab-gas-short", vec![account(sender, sui, 4_999_999)], g.ab(5_000_000, vec![], vec![mvec()]));
    g.emit("funds/ab-gas-no-account", vec![], g.ab(5_000_000, vec![], vec![mvec()]));
    g.emit("funds/ab-gas-other-owner", vec![account(other, sui, 1_000_000_000)], g.ab(5_000_000, vec![], vec![mvec()]));
    let redeem = |c: &str| call("balance", "redeem_funds", c, vec![Argument::Input(0)]);
    g.emit("funds/usdc-ok", vec![g.gas(), account(sender, USDC, 1000)], g.paid(vec![wd(USDC, 500)], vec![redeem(USDC)]));
    g.emit("funds/usdc-short", vec![g.gas(), account(sender, USDC, 400)], g.paid(vec![wd(USDC, 500)], vec![redeem(USDC)]));
    g.emit("funds/usdc-sum-short", vec![g.gas(), account(sender, USDC, 500)], g.paid(vec![wd(USDC, 300), wd(USDC, 300)], vec![redeem(USDC)]));
    g.emit("funds/usdc-sum-ok", vec![g.gas(), account(sender, USDC, 600)], g.paid(vec![wd(USDC, 300), wd(USDC, 300)], vec![redeem(USDC)]));
    g.emit("funds/ab-and-usdc-both-short", vec![account(sender, sui, 1), account(sender, USDC, 1)], g.ab(5_000_000, vec![wd(USDC, 500)], vec![redeem(USDC)]));
    g.emit("funds/ab-ok-usdc-short", vec![account(sender, sui, 1_000_000_000), account(sender, USDC, 1)], g.ab(5_000_000, vec![wd(USDC, 500)], vec![redeem(USDC)]));
    g.emit("funds/sui-withdraw-plus-ab-gas", vec![account(sender, sui, 5_000_100)], g.ab(5_000_000, vec![wd(sui, 101)], vec![redeem(sui)]));
    g.emit("funds/reg-short", vec![g.gas(), account(sender, REG, 7)], g.paid(vec![wd(REG, 8)], vec![redeem(REG)]));

    // ---- gasless (G16): object inputs and remaining balances
    let usdc_coin = coin(USDC, oid(0x10), 50_000, Owner::AddressOwner(sender));
    let send = |c: &str, args: Vec<Argument>| call("coin", "send_funds", c, args);
    g.emit("gasless/coin-ok", vec![usdc_coin.clone()], g.gasless(vec![owned(&usdc_coin), me()], vec![send(USDC, vec![Argument::Input(0), Argument::Input(1)])]));
    let thing = move_obj(StructTag { address: AccountAddress::from_hex_literal("0x77").unwrap(), module: Identifier::new("m").unwrap(), name: Identifier::new("Thing").unwrap(), type_params: vec![] }, 5, oid(0x11).to_vec(), Owner::AddressOwner(sender));
    g.emit("gasless/non-coin-object", vec![thing.clone()], g.gasless(vec![owned(&thing), me()], vec![send(USDC, vec![Argument::Input(0), Argument::Input(1)])]));
    let sui_coin = gas_coin(oid(0x12), 1_000, sender);
    g.emit("gasless/sui-coin", vec![sui_coin.clone()], g.gasless(vec![owned(&sui_coin), me()], vec![send(USDC, vec![Argument::Input(0), Argument::Input(1)])]));
    let reg_coin = coin(REG, oid(0x13), 1_000, Owner::AddressOwner(sender));
    g.emit("gasless/reg-coin", vec![reg_coin.clone()], g.gasless(vec![owned(&reg_coin), me()], vec![send(USDC, vec![Argument::Input(0), Argument::Input(1)])]));
    let shared_usdc = coin(USDC, oid(0x14), 1_000, Owner::Shared { initial_shared_version: v(2) });
    g.emit("gasless/shared-coin", vec![shared_usdc.clone()], g.gasless(vec![shared(&shared_usdc, 2), me()], vec![send(USDC, vec![Argument::Input(0), Argument::Input(1)])]));
    let imm_usdc = coin(USDC, oid(0x15), 1_000, Owner::Immutable);
    g.emit("gasless/immutable-coin", vec![imm_usdc.clone()], g.gasless(vec![owned(&imm_usdc), me()], vec![send(USDC, vec![Argument::Input(0), Argument::Input(1)])]));
    let cons_usdc = coin(USDC, oid(0x16), 1_000, Owner::ConsensusAddressOwner { start_version: v(3), owner: sender });
    g.emit("gasless/consensus-owned-coin", vec![cons_usdc.clone()], g.gasless(vec![shared(&cons_usdc, 3), me()], vec![send(USDC, vec![Argument::Input(0), Argument::Input(1)])]));
    g.emit("gasless/owned-then-shared", vec![usdc_coin.clone(), shared_usdc.clone()], g.gasless(vec![owned(&usdc_coin), shared(&shared_usdc, 2), me()], vec![
        call("coin", "put", USDC, vec![Argument::Input(0), Argument::Input(1)]),
        send(USDC, vec![Argument::Input(1), Argument::Input(2)]),
    ]));
    let bsend = |args: Vec<Argument>| call("balance", "send_funds", USDC, args);
    let gl_wd = |amount: u64| vec![wd(USDC, amount), me()];
    let gl_cmds = || vec![redeem(USDC), bsend(vec![Argument::Result(0), Argument::Input(1)])];
    g.emit("gasless/remaining-under-min", vec![account(sender, USDC, 10_004)], g.gasless(gl_wd(5), gl_cmds()));
    g.emit("gasless/remaining-zero", vec![account(sender, USDC, 10_004)], g.gasless(gl_wd(10_004), gl_cmds()));
    g.emit("gasless/remaining-at-min", vec![account(sender, USDC, 10_004)], g.gasless(gl_wd(4), gl_cmds()));
    g.emit("gasless/remaining-min-minus-1", vec![account(sender, USDC, 10_004)], g.gasless(gl_wd(5), gl_cmds()));
    g.emit("gasless/remaining-large", vec![account(sender, USDC, 1_000_000)], g.gasless(gl_wd(5), gl_cmds()));
    g.emit("gasless/insufficient", vec![account(sender, USDC, 10_004)], g.gasless(gl_wd(20_000), gl_cmds()));
    g.emit("gasless/no-account", vec![], g.gasless(gl_wd(1), gl_cmds()));

    // ---- coin deny list v2 at signing (G18)
    let cfg_id = oid(0xc0);
    let reg_in = |g: &Gen| (vec![g.gas(), reg_coin.clone()], g.paid(vec![owned(&reg_coin), me()], vec![Command::TransferObjects(vec![Argument::Input(0)], Argument::Input(1))]));
    let deny_case = |g: &mut Gen, id: &str, extra: Vec<Object>| {
        let (mut objs, data) = reg_in(&*g);
        objs.extend(extra);
        g.emit(id, objs, data);
    };
    let v2 = |pause: Option<Vec<u8>>, addrs: Vec<(SuiAddress, Vec<u8>)>| {
        let mut o = vec![];
        deny_v2(&mut o, REG, cfg_id, pause, addrs);
        o
    };
    deny_case(&mut g, "deny2/no-config", vec![]);
    deny_case(&mut g, "deny2/sender-denied", v2(None, vec![(sender, setting(0, Some(true), None))]));
    deny_case(&mut g, "deny2/sender-denied-next-epoch", v2(None, vec![(sender, setting(EPOCH, Some(true), Some(false)))]));
    deny_case(&mut g, "deny2/sender-denied-future", v2(None, vec![(sender, setting(5000, Some(true), Some(false)))]));
    deny_case(&mut g, "deny2/sender-undenied-future", v2(None, vec![(sender, setting(5000, Some(false), Some(true)))]));
    deny_case(&mut g, "deny2/sender-newer-none", v2(None, vec![(sender, setting(0, None, Some(true)))]));
    deny_case(&mut g, "deny2/setting-data-none", {
        let mut o = v2(None, vec![]);
        o.push(field(cfg_id, fw_tag("deny_list", "AddressKey", vec![]), sender.to_vec(), fw_tag("config", "Setting", vec![TypeTag::Bool]), vec![0]));
        o
    });
    deny_case(&mut g, "deny2/other-denied", v2(None, vec![(other, setting(0, Some(true), None))]));
    deny_case(&mut g, "deny2/pause", v2(Some(setting(0, Some(true), None)), vec![]));
    deny_case(&mut g, "deny2/pause-and-sender", v2(Some(setting(0, Some(true), None)), vec![(sender, setting(0, Some(true), None))]));
    deny_case(&mut g, "deny2/pause-off-sender", v2(Some(setting(0, Some(false), None)), vec![(sender, setting(0, Some(true), None))]));
    deny_case(&mut g, "deny2/pause-future", v2(Some(setting(5000, Some(true), Some(false))), vec![]));
    {
        // two regulated types, both denying the sender: the first in canonical string order
        let reg2_coin = coin(REG2, oid(0x17), 1_000, Owner::AddressOwner(sender));
        let mut objs = vec![g.gas(), reg_coin.clone(), reg2_coin.clone()];
        objs.extend(v2(None, vec![(sender, setting(0, Some(true), None))]));
        deny_v2(&mut objs, REG2, oid(0xc1), None, vec![(sender, setting(0, Some(true), None))]);
        let data = g.paid(vec![owned(&reg_coin), owned(&reg2_coin), me()], vec![Command::TransferObjects(vec![Argument::Input(0), Argument::Input(1)], Argument::Input(2))]);
        g.emit("deny2/two-types", objs, data);
    }
    {
        // the gas coin is not checked, a SUI withdrawal is
        let mut objs = vec![g.gas()];
        deny_v2(&mut objs, sui, oid(0xc2), None, vec![(sender, setting(0, Some(true), None))]);
        g.emit("deny2/sui-gas-coin-excluded", objs.clone(), g.paid(vec![me()], vec![Command::TransferObjects(vec![Argument::GasCoin], Argument::Input(0))]));
        objs.push(account(sender, sui, 1_000_000_000));
        objs.remove(0);
        g.emit("deny2/sui-ab-gas-checked", objs, g.ab(5_000_000, vec![], vec![mvec()]));
    }
    {
        let mut objs = vec![g.gas(), account(sender, REG, 1_000)];
        objs.extend(v2(None, vec![(sender, setting(0, Some(true), None))]));
        g.emit("deny2/withdrawal", objs, g.paid(vec![wd(REG, 10)], vec![redeem(REG)]));
    }
    {
        // a receiving REG coin (owned by an object's address) is checked for the sender
        let parent = coin(USDC, oid(0x18), 1, Owner::AddressOwner(sender));
        let recv = coin(REG, oid(0x19), 1, Owner::AddressOwner(SuiAddress::from(oid(0x18))));
        let mut objs = vec![g.gas(), parent.clone(), recv.clone()];
        objs.extend(v2(None, vec![(sender, setting(0, Some(true), None))]));
        let data = g.paid(
            vec![owned(&parent), CallArg::Object(ObjectArg::Receiving(recv.compute_object_reference()))],
            vec![Command::MoveCall(Box::new(ProgrammableMoveCall {
                package: ObjectID::from(SUI_FRAMEWORK_ADDRESS),
                module: "transfer".into(),
                function: "public_receive".into(),
                type_arguments: vec![TypeInput::from(fw_tag("coin", "Coin", vec![tag(REG)]))],
                arguments: vec![Argument::Input(0), Argument::Input(1)],
            }))],
        );
        g.emit("deny2/receiving", objs, data);
    }

    // ---- coin deny list v1 at signing
    let v1 = |counts: Vec<(SuiAddress, u64)>, sets: Vec<(&str, Vec<SuiAddress>)>| {
        let mut o = vec![];
        deny_v1(&mut o, counts, sets);
        o
    };
    deny_case(&mut g, "deny1/sender-denied", v1(vec![(sender, 1)], vec![(REG, vec![sender])]));
    deny_case(&mut g, "deny1/count-not-in-set", v1(vec![(sender, 1)], vec![(REG, vec![other])]));
    deny_case(&mut g, "deny1/in-set-no-count", v1(vec![], vec![(REG, vec![sender])]));
    deny_case(&mut g, "deny1/in-set-count-zero", v1(vec![(sender, 0)], vec![(REG, vec![sender])]));
    deny_case(&mut g, "deny1/no-set", v1(vec![(sender, 1)], vec![]));
    deny_case(&mut g, "deny1/other-type-set", v1(vec![(sender, 1)], vec![(REG2, vec![sender])]));
    deny_case(&mut g, "deny1/root-only", {
        let mut o = v1(vec![], vec![]);
        o.truncate(1);
        o
    });
    deny_case(&mut g, "deny1/v1-before-v2", {
        let mut o = v1(vec![(sender, 1)], vec![(REG, vec![sender])]);
        o.extend(v2(Some(setting(0, Some(true), None)), vec![]));
        o
    });
    deny_case(&mut g, "deny1/v1-clear-v2-pause", {
        let mut o = v1(vec![(sender, 1)], vec![(REG, vec![other])]);
        o.extend(v2(Some(setting(0, Some(true), None)), vec![]));
        o
    });
    {
        let mut objs = vec![g.gas(), account(sender, REG, 1_000)];
        objs.extend(v1(vec![(sender, 1)], vec![(REG, vec![sender])]));
        g.emit("deny1/withdrawal", objs, g.paid(vec![wd(REG, 10)], vec![redeem(REG)]));
    }

    g.out.write(out_path)
}
