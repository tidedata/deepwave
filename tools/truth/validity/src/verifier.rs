//! Suite `verifier` (PARITY.md G19): `check_non_system_packages_to_be_published`, the signing-time
//! package verification with the default `VerifierSigningConfig` (2.2M meter units per function,
//! module and package, 10_000 back edges per function and module, regex reference safety sanity
//! check at 2.2M units). One meter is shared by every module of every Publish/Upgrade command.
//!
//! Line: `id \t pv \t commands \t verdict`. `commands` is `;`-separated, each `P:` (Publish) or
//! `U:` (Upgrade) followed by the `,`-separated module bytes in hex (empty for no modules). The
//! verdict is `ok` or `err <UserInputError Display>`.
//!
//! The meter families search the smallest size that times out and record that size and the one
//! below it, so the error text (which names the scope and its current/new/max units) pins the
//! meter accounting down to the unit.

use crate::common::{Out, verdict};
use move_binary_format::file_format::{
    AddressIdentifierIndex, Bytecode, CodeUnit, CompiledModule, FunctionDefinition,
    FunctionHandle, FunctionHandleIndex, IdentifierIndex, ModuleHandle, ModuleHandleIndex,
    Signature, SignatureIndex, SignatureToken, Visibility, empty_module,
};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use std::sync::Arc;
use sui_config::verifier_signing_config::VerifierSigningConfig;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::base_types::{ObjectDigest, ObjectID, SequenceNumber, SuiAddress};
use sui_types::error::UserInputError;
use sui_types::metrics::BytecodeVerifierMetrics;
use sui_types::transaction::{Argument, Command, ProgrammableTransaction, TransactionData};

const PV: u64 = 141;

/// A module under construction: interned identifiers and signatures (the duplication checker
/// rejects repeats).
struct Mod {
    m: CompiledModule,
}

impl Mod {
    fn new(name: &str) -> Self {
        let mut m = empty_module();
        m.identifiers[0] = Identifier::new(name).unwrap();
        m.address_identifiers[0] = AccountAddress::ZERO;
        m.module_handles[0] = ModuleHandle { address: AddressIdentifierIndex(0), name: IdentifierIndex(0) };
        m.self_module_handle_idx = ModuleHandleIndex(0);
        Self { m }
    }

    fn ident(&mut self, s: &str) -> IdentifierIndex {
        if let Some(i) = self.m.identifiers.iter().position(|x| x.as_str() == s) {
            return IdentifierIndex(i as u16);
        }
        // `<SELF>` is not a valid identifier (so it never deserializes); build it unchecked
        self.m.identifiers.push(unsafe { Identifier::new_unchecked(s) });
        IdentifierIndex((self.m.identifiers.len() - 1) as u16)
    }

    fn sig(&mut self, toks: Vec<SignatureToken>) -> SignatureIndex {
        let s = Signature(toks);
        if let Some(i) = self.m.signatures.iter().position(|x| *x == s) {
            return SignatureIndex(i as u16);
        }
        self.m.signatures.push(s);
        SignatureIndex((self.m.signatures.len() - 1) as u16)
    }

    fn fun(&mut self, name: &str, locals: Vec<SignatureToken>, code: Vec<Bytecode>) -> &mut Self {
        let name = self.ident(name);
        let empty = self.sig(vec![]);
        let locals = self.sig(locals);
        self.m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name,
            parameters: empty,
            return_: empty,
            type_parameters: vec![],
        });
        self.m.function_defs.push(FunctionDefinition {
            function: FunctionHandleIndex((self.m.function_handles.len() - 1) as u16),
            visibility: Visibility::Public,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit { locals, code, jump_tables: vec![] }),
        });
        self
    }

    fn bytes(&self) -> Vec<u8> {
        let mut b = vec![];
        self.m.serialize_with_version(self.m.version, &mut b).unwrap();
        b
    }
}

use Bytecode as B;
use SignatureToken as T;

fn ok_mod(name: &str) -> Vec<u8> {
    Mod::new(name).fun("f", vec![], vec![B::Ret]).bytes()
}

/// An extra (unused) `<SELF>` identifier. The deserializer rejects it, so Rust passes these
/// before `meter_module_bytes` reaches its `<SELF>` check.
fn self_mod(name: &str) -> Vec<u8> {
    let mut m = Mod::new(name);
    m.fun("f", vec![], vec![B::Ret]);
    m.ident("<SELF>");
    m.bytes()
}

/// Fails the Move verifier with a status that is not a timeout (a value left on the stack).
fn stack_mod(name: &str) -> Vec<u8> {
    Mod::new(name).fun("f", vec![], vec![B::LdU64(1), B::Ret]).bytes()
}

/// `x = 0; r = &mut x; <tail>`
fn borrow_mod(name: &str, tail: Vec<Bytecode>) -> Vec<u8> {
    let mut code = vec![B::LdU64(0), B::StLoc(0), B::MutBorrowLoc(0), B::StLoc(1)];
    code.extend(tail);
    Mod::new(name).fun("f", vec![T::U64, T::MutableReference(Box::new(T::U64))], code).bytes()
}

/// `n` self loops `loop { if (true) continue }` in each of `fns` functions (the last one gets
/// `extra` more).
fn loops_mod(name: &str, fns: usize, n: usize, extra: usize) -> Vec<u8> {
    let mut m = Mod::new(name);
    for f in 0..fns {
        let k = n + if f + 1 == fns { extra } else { 0 };
        let mut code = vec![];
        for i in 0..k {
            code.push(B::LdTrue);
            code.push(B::BrTrue((2 * i) as u16));
        }
        code.push(B::Ret);
        m.fun(&format!("f{f}"), vec![], code);
    }
    m.bytes()
}

/// Reference-heavy body: `x = 0` then `n` times `r_(i mod R) = &x`.
fn refs_code(n: usize) -> (Vec<SignatureToken>, Vec<Bytecode>) {
    const R: usize = 100;
    let mut locals = vec![T::U64];
    locals.extend((0..R).map(|_| T::Reference(Box::new(T::U64))));
    let mut code = vec![B::LdU64(0), B::StLoc(0)];
    for i in 0..n {
        code.push(B::ImmBorrowLoc(0));
        code.push(B::StLoc((1 + i % R) as u8));
    }
    code.push(B::Ret);
    (locals, code)
}

/// `fns` reference-heavy functions of size `n` (the last one of size `last`).
fn refs_mod(name: &str, fns: usize, n: usize, last: usize) -> Vec<u8> {
    let mut m = Mod::new(name);
    for f in 0..fns {
        let (l, c) = refs_code(if f + 1 == fns { last } else { n });
        m.fun(&format!("f{f}"), l, c);
    }
    m.bytes()
}

/// `fns` functions of `n` `Nop`s (the last one `last`): cheap for the Move verifier, 15 units per
/// instruction for the Sui id leak verifier, whose function units are never reset.
fn nops_mod(name: &str, fns: usize, n: usize, last: usize) -> Vec<u8> {
    let mut m = Mod::new(name);
    for f in 0..fns {
        let k = if f + 1 == fns { last } else { n };
        let mut code = vec![B::Nop; k];
        code.push(B::Ret);
        m.fun(&format!("f{f}"), vec![], code);
    }
    m.bytes()
}

/// A reference-heavy function and then one that fails the Move verifier without timing out.
fn heavy_then_fail_mod(name: &str, n: usize) -> Vec<u8> {
    let mut m = Mod::new(name);
    let (l, c) = refs_code(n);
    m.fun("heavy", l, c);
    m.fun("bad", vec![], vec![B::LdU64(1), B::Ret]);
    m.bytes()
}

enum Cmd {
    P(Vec<Vec<u8>>),
    U(Vec<Vec<u8>>),
}

struct Ctx {
    pv: u64,
    pc: ProtocolConfig,
    metrics: Arc<BytecodeVerifierMetrics>,
    signing: VerifierSigningConfig,
    /// The default config with the regex reference safety sanity check never timing out.
    no_regex: VerifierSigningConfig,
    /// Run cases under `no_regex`.
    regex_off: bool,
    out: Out,
}

impl Ctx {
    fn check(&self, cmds: &[Cmd]) -> Result<(), UserInputError> {
        self.check_with(cmds, if self.regex_off { &self.no_regex } else { &self.signing })
    }

    fn check_with(&self, cmds: &[Cmd], signing: &VerifierSigningConfig) -> Result<(), UserInputError> {
        let commands = cmds
            .iter()
            .map(|c| match c {
                Cmd::P(m) => Command::Publish(m.clone(), vec![]),
                Cmd::U(m) => Command::Upgrade(m.clone(), vec![], ObjectID::from_single_byte(0xab), Argument::Input(0)),
            })
            .collect();
        let pt = ProgrammableTransaction { inputs: vec![], commands };
        let gas = (ObjectID::from_single_byte(0xee), SequenceNumber::from_u64(1), ObjectDigest::new([7; 32]));
        let td = TransactionData::new_programmable(SuiAddress::ZERO, vec![gas], pt, 10_000_000, 1000);
        sui_transaction_checks::check_non_system_packages_to_be_published(&td, &self.pc, &self.metrics, signing)
    }

    /// Why a module passes or fails, unmetered: deserialize, Move verifier, Sui verifier.
    fn diag(&self, b: &[u8]) -> String {
        let bc = self.pc.binary_config(Some(true));
        let m = match CompiledModule::deserialize_with_config(b, &bc) {
            Ok(m) => m,
            Err(e) => return format!("deserialize: {e}"),
        };
        let vc = self.pc.verifier_config(Some(self.signing.limits_for_signing()));
        if let Err(e) = move_bytecode_verifier::verify_module_with_config_unmetered(&vc, &m) {
            return format!("move: {e}");
        }
        match sui_verifier_latest::verifier::sui_verify_module_unmetered(&m, &Default::default(), &vc) {
            Ok(()) => "passes unmetered".to_string(),
            Err(e) => format!("sui: {e}"),
        }
    }

    fn case(&mut self, id: &str, cmds: Vec<Cmd>) -> bool {
        let r = self.check(&cmds);
        let enc: Vec<String> = cmds
            .iter()
            .map(|c| {
                let (tag, m) = match c {
                    Cmd::P(m) => ("P", m),
                    Cmd::U(m) => ("U", m),
                };
                format!("{tag}:{}", m.iter().map(hex::encode).collect::<Vec<_>>().join(","))
            })
            .collect();
        let v = verdict(&r, |_| None);
        let cfg = if self.regex_off {
            "no-regex"
        } else if verdict(&self.check_with(&cmds, &self.no_regex), |_| None) == v {
            "default"
        } else {
            // the regex reference safety sanity check decides this case
            "default-regex"
        };
        self.out.push(&[id.to_string(), self.pv.to_string(), cfg.to_string(), enc.join(";"), v]);
        r.is_err()
    }

    /// Smallest n in (lo, hi] whose commands fail; records n - 1 and n. `lo` must pass and `hi`
    /// must fail.
    fn boundary(&mut self, id: &str, lo: usize, hi: usize, f: impl Fn(usize) -> Vec<Cmd>) -> Option<usize> {
        if self.check(&f(lo)).is_err() || self.check(&f(hi)).is_ok() {
            eprintln!("{id}: no boundary in ({lo}, {hi}]: lo {:?}, hi {:?}", self.check(&f(lo)), self.check(&f(hi)));
            for n in [lo, hi] {
                for cmd in f(n) {
                    let (Cmd::P(ms) | Cmd::U(ms)) = cmd;
                    for b in ms {
                        eprintln!("  n {n}: {}", self.diag(&b));
                    }
                }
            }
            return None;
        }
        let (mut lo, mut hi) = (lo, hi);
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if self.check(&f(mid)).is_err() { hi = mid } else { lo = mid }
        }
        eprintln!("{id}: boundary {hi}");
        self.case(&format!("{id}_{lo}"), f(lo));
        self.case(&format!("{id}_{hi}"), f(hi));
        Some(hi)
    }

    fn set_pv(&mut self, pv: u64) {
        self.pv = pv;
        self.pc = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
    }
}

pub fn run(out_path: &str) -> anyhow::Result<()> {
    let registry = prometheus::Registry::new();
    let mut c = Ctx {
        pv: PV,
        pc: ProtocolConfig::get_for_version(ProtocolVersion::new(PV), Chain::Mainnet),
        metrics: Arc::new(BytecodeVerifierMetrics::new(&registry)),
        signing: VerifierSigningConfig::default(),
        no_regex: {
            let mut c = VerifierSigningConfig::default();
            c.sanity_check_with_regex_reference_safety = Some(usize::MAX);
            c
        },
        regex_off: false,
        out: Out::new(
            "suite verifier: check_non_system_packages_to_be_published (sui 1.83.1), default VerifierSigningConfig\n\
             cfg: default (VerifierSigningConfig::default()), default-regex (the same, but the regex reference safety\n\
             sanity check decides the case: Rust without it answers differently), no-regex (that check never times out)\n\
             id\tpv\tcfg\tcommands (P:|U: then module hex, `,` between modules, `;` between commands)\tverdict",
        ),
    };

    // plain outcomes
    c.case("empty_publish", vec![Cmd::P(vec![])]);
    c.case("pass_one", vec![Cmd::P(vec![ok_mod("a")])]);
    c.case("pass_publish_upgrade", vec![Cmd::P(vec![ok_mod("a"), ok_mod("b")]), Cmd::U(vec![ok_mod("c")])]);
    c.case("move_fail_not_timeout", vec![Cmd::P(vec![stack_mod("a")])]);
    c.case("deserialize_fail", vec![Cmd::P(vec![vec![0xde, 0xad, 0xbe, 0xef]])]);
    c.case("deserialize_fail_hides_self", vec![Cmd::P(vec![self_mod("a"), vec![0xa1, 0x1c, 0xeb, 0x0b]])]);
    c.case("self_identifier", vec![Cmd::P(vec![self_mod("a")])]);
    c.case("self_identifier_upgrade", vec![Cmd::P(vec![ok_mod("a")]), Cmd::U(vec![ok_mod("b"), self_mod("c")])]);
    let borrowloc = || borrow_mod("bl", vec![B::MutBorrowLoc(0), B::Pop, B::Ret]);
    let copyloc = || borrow_mod("cl", vec![B::CopyLoc(0), B::Pop, B::Ret]);
    let moveloc = || borrow_mod("ml", vec![B::MoveLoc(0), B::Pop, B::Ret]);
    c.case("borrowloc_exists_borrow", vec![Cmd::P(vec![borrowloc()])]);
    c.case("copyloc_exists_borrow", vec![Cmd::P(vec![copyloc()])]);
    c.case("moveloc_exists_borrow", vec![Cmd::P(vec![moveloc()])]);
    c.case("self_checked_before_verify", vec![Cmd::P(vec![borrowloc(), self_mod("s")])]);
    c.case("first_package_first", vec![Cmd::P(vec![borrowloc()]), Cmd::P(vec![self_mod("s")])]);
    c.case("second_module_times_out", vec![Cmd::P(vec![ok_mod("a"), copyloc()])]);

    // back edges per module (per function needs more than the 1024 basic blocks allow)
    c.case("back_edges_module_10000", vec![Cmd::P(vec![loops_mod("be", 10, 1000, 0)])]);
    c.case("back_edges_module_10001", vec![Cmd::P(vec![loops_mod("be", 10, 1000, 1)])]);

    // The regex reference safety sanity check's own meter (2.2M units per function) trips long
    // before the shared meter on reference-heavy code.
    c.boundary("fun_meter_regex", 1, 9_500, |n| vec![Cmd::P(vec![refs_mod("fr", 1, n, n)])]);

    // The shared meter, with the regex sanity check out of the way.
    c.regex_off = true;

    // meter boundaries. A basic block holds at most max_push_size (10_000) pushes, so a one-block
    // reference-heavy function stays under 10_000 borrows; the function limit sits below that.
    let b = c.boundary("fun_meter", 1, 9_500, |n| vec![Cmd::P(vec![refs_mod("fm", 1, n, n)])]).expect("fun_meter");
    let (third, part) = (b / 2, b * 3 / 4);
    c.boundary("mod_meter", 1, b - 1, |n| vec![Cmd::P(vec![refs_mod("mm", 3, n, n)])]);
    c.boundary("mod_meter_last_fn", 1, b - 1, move |n| vec![Cmd::P(vec![refs_mod("ml", 2, part, n)])]);
    c.boundary("pkg_meter", 1, b - 1, |n| vec![Cmd::P(vec![refs_mod("p1", 1, n, n), refs_mod("p2", 1, n, n), refs_mod("p3", 1, n, n)])]);
    c.boundary("pkg_meter_across_commands", 1, b - 1, |n| {
        vec![Cmd::P(vec![refs_mod("c1", 1, n, n)]), Cmd::U(vec![refs_mod("c2", 1, n, n)]), Cmd::P(vec![refs_mod("c3", 1, n, n)])]
    });
    c.boundary("pkg_meter_after_move_failure", 1, b - 1, move |n| {
        vec![Cmd::P(vec![heavy_then_fail_mod("h1", part), refs_mod("h2", 1, n, n)])]
    });
    c.boundary("pkg_meter_three_parts", 1, b - 1, move |n| {
        vec![Cmd::P(vec![refs_mod("t1", 1, third, third)]), Cmd::P(vec![refs_mod("t2", 1, third, third)]), Cmd::P(vec![refs_mod("t3", 1, third, third), refs_mod("t4", 1, n, n)])]
    });

    // The Sui verifier's meter: only the id leak verifier charges it, and protocol 140 turned
    // that verifier off (disable_id_leak_verifier), so this runs at 139.
    c.set_pv(139);
    c.case("pv139_pass", vec![Cmd::P(vec![ok_mod("a")])]);
    c.boundary("sui_id_leak_meter", 1, 65_000, |n| vec![Cmd::P(vec![nops_mod("nl", 3, 60_000, n)])]);
    c.boundary("sui_id_leak_meter_second_module", 1, 65_000, |n| vec![Cmd::P(vec![ok_mod("a"), nops_mod("nb", 3, 60_000, n)])]);
    c.set_pv(PV);

    c.out.write(out_path)
}
