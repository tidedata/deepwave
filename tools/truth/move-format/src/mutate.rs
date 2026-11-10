//! Deterministic mutants of real modules: the negative half of the move-binary and move-verify
//! corpora. Mutants are only inputs; their truth still comes from Mysten's code. The generator
//! is seeded by the base module's Blake2b and the mutant index (splitmix64), so a rebuild gives
//! byte-identical vectors.
use move_binary_format::CompiledModule;
use move_binary_format::binary_config::BinaryConfig;
use move_binary_format::file_format::*;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
    /// An index for a table of length n: mostly in range, sometimes just past the end.
    fn index(&mut self, n: usize) -> u16 {
        if self.below(10) == 0 { (n as u64 + self.below(2) as u64).min(u16::MAX as u64) as u16 } else { self.below(n.max(1)) as u16 }
    }
}

pub fn mutants(bytes: &[u8], hash: &[u8; 32], n_byte: usize, n_struct: usize) -> Vec<(Vec<u8>, &'static str)> {
    mutants_ext(bytes, hash, n_byte, n_struct, 0)
}

/// `salt` 0 is the checked-in vector set. A non-zero salt (`ZUI_MF_SALT`) reseeds every mutant
/// and turns on the extended edits (every opcode, enums, variant handles, jump tables), for
/// differential fuzz runs into a scratch vectors dir.
pub fn mutants_ext(bytes: &[u8], hash: &[u8; 32], n_byte: usize, n_struct: usize, salt: u64) -> Vec<(Vec<u8>, &'static str)> {
    let ext = salt != 0;
    let seed = u64::from_le_bytes(hash[..8].try_into().unwrap()) ^ salt.wrapping_mul(0x9e3779b97f4a7c15);
    let mut out = vec![];
    for i in 0..n_byte {
        let mut r = Rng(seed ^ (i as u64).wrapping_mul(0x51afd7ed558ccd));
        if let Some(b) = byte_mutant(bytes, &mut r) {
            out.push((b, "mutant-byte"));
        }
    }
    let Ok(base) = CompiledModule::deserialize_with_config(bytes, &BinaryConfig::legacy_with_flags(false, false)) else {
        return out;
    };
    for i in 0..n_struct {
        let mut r = Rng(seed ^ 0xabcdef ^ (i as u64).wrapping_mul(0x2545f4914f6cdd1d));
        let mut m = base.clone();
        // one to three edits per mutant
        let edits = 1 + r.below(3);
        for _ in 0..edits {
            if ext && r.below(3) == 0 {
                if r.below(2) == 0 {
                    struct_edit_ext(&mut m, &base, &mut r);
                } else {
                    struct_edit_targeted(&mut m, &mut r);
                }
            } else {
                struct_edit(&mut m, &base, &mut r);
            }
        }
        let mut b = vec![];
        if m.serialize_with_version(m.version, &mut b).is_ok() && b != bytes {
            // extended: relabel some as an older binary version (1 to 5), which the serializer
            // cannot write but protocol configs up to 44 still deserialize
            if ext && b.len() >= 8 && r.below(4) == 0 {
                b[4..8].copy_from_slice(&(1 + r.below(5) as u32).to_le_bytes());
            }
            out.push((b, "mutant-struct"));
        }
    }
    out
}

fn byte_mutant(bytes: &[u8], r: &mut Rng) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    let mut b = bytes.to_vec();
    // half the edits target the header and table directory, half anywhere
    let pos = if r.below(2) == 0 { r.below(b.len().min(96)) } else { r.below(b.len()) };
    match r.below(7) {
        0 => b[pos] ^= (1 + r.below(255)) as u8,
        1 => b[pos] = r.next() as u8,
        2 => b.truncate(pos),
        3 => b.insert(pos, r.next() as u8),
        4 => {
            b.remove(pos);
        }
        5 => b.push(r.next() as u8),
        _ => {
            let bit = r.below(8);
            b[pos] ^= 1 << bit;
        }
    }
    Some(b)
}

fn random_token(m: &CompiledModule, r: &mut Rng, depth: usize) -> SignatureToken {
    use SignatureToken as T;
    let k = if depth > 2 { r.below(9) } else { r.below(14) };
    match k {
        0 => T::Bool,
        1 => T::U8,
        2 => T::U64,
        3 => T::U128,
        4 => T::Address,
        5 => T::Signer,
        6 => T::U16,
        7 => T::U32,
        8 => T::TypeParameter(r.below(3) as u16),
        9 => T::Vector(Box::new(random_token(m, r, depth + 1))),
        10 => T::Reference(Box::new(random_token(m, r, depth + 1))),
        11 => T::MutableReference(Box::new(random_token(m, r, depth + 1))),
        12 => T::Datatype(DatatypeHandleIndex(r.index(m.datatype_handles.len()))),
        _ => {
            let idx = r.index(m.datatype_handles.len());
            let n = m.datatype_handles.get(idx as usize).map(|h| h.type_parameters.len()).unwrap_or(1).max(1);
            T::DatatypeInstantiation(Box::new((DatatypeHandleIndex(idx), (0..n).map(|_| random_token(m, r, depth + 1)).collect())))
        }
    }
}

fn random_instr(m: &CompiledModule, r: &mut Rng, code_len: usize, locals: usize) -> Bytecode {
    use Bytecode as B;
    let local = |r: &mut Rng| -> u8 { (if r.below(10) == 0 { locals + r.below(2) } else { r.below(locals.max(1)) }).min(255) as u8 };
    match r.below(40) {
        0 => B::Pop,
        1 => B::Ret,
        2 => B::BrTrue(r.index(code_len)),
        3 => B::BrFalse(r.index(code_len)),
        4 => B::Branch(r.index(code_len)),
        5 => B::LdU8(r.next() as u8),
        6 => B::LdU64(r.next()),
        7 => B::LdConst(ConstantPoolIndex(r.index(m.constant_pool.len()))),
        8 => B::LdTrue,
        9 => B::CopyLoc(local(r)),
        10 => B::MoveLoc(local(r)),
        11 => B::StLoc(local(r)),
        12 => B::Call(FunctionHandleIndex(r.index(m.function_handles.len()))),
        13 => B::CallGeneric(FunctionInstantiationIndex(r.index(m.function_instantiations.len()))),
        14 => B::Pack(StructDefinitionIndex(r.index(m.struct_defs.len()))),
        15 => B::Unpack(StructDefinitionIndex(r.index(m.struct_defs.len()))),
        16 => B::PackGeneric(StructDefInstantiationIndex(r.index(m.struct_def_instantiations.len()))),
        17 => B::ReadRef,
        18 => B::WriteRef,
        19 => B::FreezeRef,
        20 => B::MutBorrowLoc(local(r)),
        21 => B::ImmBorrowLoc(local(r)),
        22 => B::MutBorrowField(FieldHandleIndex(r.index(m.field_handles.len()))),
        23 => B::ImmBorrowField(FieldHandleIndex(r.index(m.field_handles.len()))),
        24 => B::ImmBorrowFieldGeneric(FieldInstantiationIndex(r.index(m.field_instantiations.len()))),
        25 => [B::Add, B::Sub, B::Mul, B::Mod, B::Div, B::BitOr, B::BitAnd, B::Xor][r.below(8)].clone(),
        26 => [B::Or, B::And, B::Not, B::Eq, B::Neq, B::Lt, B::Gt, B::Le, B::Ge][r.below(9)].clone(),
        27 => [B::Abort, B::Nop, B::Shl, B::Shr, B::CastU8, B::CastU64, B::CastU128, B::CastU16, B::CastU32, B::CastU256][r.below(10)].clone(),
        28 => B::VecPack(SignatureIndex(r.index(m.signatures.len())), r.below(3) as u64),
        29 => B::VecLen(SignatureIndex(r.index(m.signatures.len()))),
        30 => B::VecImmBorrow(SignatureIndex(r.index(m.signatures.len()))),
        31 => B::VecMutBorrow(SignatureIndex(r.index(m.signatures.len()))),
        32 => B::VecPushBack(SignatureIndex(r.index(m.signatures.len()))),
        33 => B::VecPopBack(SignatureIndex(r.index(m.signatures.len()))),
        34 => B::VecUnpack(SignatureIndex(r.index(m.signatures.len())), r.below(3) as u64),
        35 => B::VecSwap(SignatureIndex(r.index(m.signatures.len()))),
        36 => B::LdU16(r.next() as u16),
        37 => B::LdU256(Box::new(move_core_types::u256::U256::from(r.next()))),
        38 if m.version >= 7 => B::PackVariant(VariantHandleIndex(r.index(m.variant_handles.len()))),
        38 => B::LdU128(Box::new(r.next() as u128)),
        _ if m.version >= 7 => B::UnpackVariant(VariantHandleIndex(r.index(m.variant_handles.len()))),
        _ => B::LdU32(r.next() as u32),
    }
}

fn struct_edit(m: &mut CompiledModule, base: &CompiledModule, r: &mut Rng) {
    let with_code: Vec<usize> = (0..m.function_defs.len()).filter(|&i| m.function_defs[i].code.is_some()).collect();
    let all_instrs: Vec<(usize, usize)> = base
        .function_defs
        .iter()
        .enumerate()
        .flat_map(|(f, d)| (0..d.code.as_ref().map(|c| c.code.len()).unwrap_or(0)).map(move |i| (f, i)))
        .collect();
    let kind = r.below(20);
    if kind < 9 && !with_code.is_empty() {
        let f = with_code[r.below(with_code.len())];
        let locals_idx = m.function_defs[f].code.as_ref().unwrap().locals.0 as usize;
        let params_idx = m.function_handles.get(m.function_defs[f].function.0 as usize).map(|h| h.parameters.0 as usize);
        let n_locals = m.signatures.get(locals_idx).map(|s| s.0.len()).unwrap_or(0)
            + params_idx.and_then(|p| m.signatures.get(p)).map(|s| s.0.len()).unwrap_or(0);
        let copied = if all_instrs.is_empty() {
            None
        } else {
            let (bf, bi) = all_instrs[r.below(all_instrs.len())];
            Some(base.function_defs[bf].code.as_ref().unwrap().code[bi].clone())
        };
        let fresh = random_instr(base, r, m.function_defs[f].code.as_ref().unwrap().code.len(), n_locals);
        let code = &mut m.function_defs[f].code.as_mut().unwrap().code;
        if code.is_empty() {
            code.push(fresh);
            return;
        }
        let i = r.below(code.len());
        match kind {
            0 | 1 => code[i] = copied.unwrap_or(fresh),
            2 | 3 => code[i] = fresh,
            4 => {
                code.remove(i);
            }
            5 => {
                let j = r.below(code.len());
                code.swap(i, j);
            }
            6 => code.insert(i, copied.unwrap_or(fresh)),
            7 => {
                let len = code.len();
                for ins in code.iter_mut() {
                    if let Bytecode::BrTrue(t) | Bytecode::BrFalse(t) | Bytecode::Branch(t) = ins {
                        if r.below(3) == 0 {
                            *t = r.index(len);
                            break;
                        }
                    }
                }
            }
            _ => {
                for ins in code.iter_mut().skip(i) {
                    if let Bytecode::CopyLoc(l) | Bytecode::MoveLoc(l) | Bytecode::StLoc(l) | Bytecode::MutBorrowLoc(l) | Bytecode::ImmBorrowLoc(l) = ins {
                        *l = r.below(n_locals + 1).min(255) as u8;
                        break;
                    }
                }
            }
        }
        return;
    }
    match kind {
        9 | 10 if !m.signatures.is_empty() => {
            let s = r.below(m.signatures.len());
            let tok = random_token(base, r, 0);
            let sig = &mut m.signatures[s].0;
            if sig.is_empty() || r.below(4) == 0 {
                sig.push(tok);
            } else {
                let i = r.below(sig.len());
                sig[i] = tok;
            }
        }
        11 if !m.datatype_handles.is_empty() => {
            let i = r.below(m.datatype_handles.len());
            m.datatype_handles[i].abilities = AbilitySet::from_u8((r.next() & 0xf) as u8).unwrap();
            if !m.datatype_handles[i].type_parameters.is_empty() && r.below(2) == 0 {
                let j = r.below(m.datatype_handles[i].type_parameters.len());
                let tp = &mut m.datatype_handles[i].type_parameters[j];
                tp.is_phantom = !tp.is_phantom;
                tp.constraints = AbilitySet::from_u8((r.next() & 0xf) as u8).unwrap();
            }
        }
        12 if !m.function_defs.is_empty() => {
            let i = r.below(m.function_defs.len());
            let d = &mut m.function_defs[i];
            match r.below(3) {
                0 => d.is_entry = !d.is_entry,
                1 => d.visibility = [Visibility::Private, Visibility::Public, Visibility::Friend][r.below(3)],
                _ => {
                    if d.code.is_some() {
                        d.code = None;
                    }
                }
            }
        }
        13 if !m.struct_defs.is_empty() => {
            let i = r.below(m.struct_defs.len());
            let tok = random_token(base, r, 0);
            if let StructFieldInformation::Declared(fields) = &mut m.struct_defs[i].field_information {
                if !fields.is_empty() {
                    let j = r.below(fields.len());
                    match r.below(3) {
                        0 => {
                            fields.remove(j);
                        }
                        _ => fields[j].signature = TypeSignature(tok),
                    }
                }
            }
        }
        14 if !m.function_handles.is_empty() => {
            let i = r.below(m.function_handles.len());
            let n = m.signatures.len();
            let h = &mut m.function_handles[i];
            match r.below(3) {
                0 => h.parameters = SignatureIndex(r.index(n)),
                1 => h.return_ = SignatureIndex(r.index(n)),
                _ => {
                    if h.type_parameters.is_empty() || r.below(2) == 0 {
                        h.type_parameters.push(AbilitySet::from_u8((r.next() & 0xf) as u8).unwrap());
                    } else {
                        let j = r.below(h.type_parameters.len());
                        h.type_parameters[j] = AbilitySet::from_u8((r.next() & 0xf) as u8).unwrap();
                    }
                }
            }
        }
        15 if !m.identifiers.is_empty() => {
            let i = r.below(m.identifiers.len());
            let names = ["init", "id", "UID", "TxContext", "new", "share_object", "transfer", "freeze_object", "Self", "x"];
            let new = if r.below(2) == 0 {
                move_core_types::identifier::Identifier::new(names[r.below(names.len())]).unwrap()
            } else {
                m.identifiers[r.below(m.identifiers.len())].clone()
            };
            m.identifiers[i] = new;
        }
        16 if !m.constant_pool.is_empty() => {
            let i = r.below(m.constant_pool.len());
            if r.below(2) == 0 {
                m.constant_pool[i].type_ = random_token(base, r, 1);
            } else if !m.constant_pool[i].data.is_empty() {
                let j = r.below(m.constant_pool[i].data.len());
                m.constant_pool[i].data[j] ^= 0x80;
            } else {
                m.constant_pool[i].data.push(1);
            }
        }
        17 if !with_code.is_empty() => {
            let f = with_code[r.below(with_code.len())];
            let n = m.signatures.len();
            m.function_defs[f].code.as_mut().unwrap().locals = SignatureIndex(r.index(n));
        }
        18 if !m.module_handles.is_empty() => {
            match r.below(3) {
                0 if !m.friend_decls.is_empty() => {
                    let i = r.below(m.friend_decls.len());
                    m.friend_decls.remove(i);
                }
                1 => {
                    let i = r.below(m.module_handles.len());
                    m.friend_decls.push(m.module_handles[i].clone());
                }
                _ => {
                    let n = m.module_handles.len();
                    m.self_module_handle_idx = ModuleHandleIndex(r.index(n));
                }
            }
        }
        _ => {
            if !m.field_handles.is_empty() {
                let i = r.below(m.field_handles.len());
                let n = m.struct_defs.len();
                if r.below(2) == 0 {
                    m.field_handles[i].field = m.field_handles[i].field.wrapping_add(1);
                } else {
                    m.field_handles[i].owner = StructDefinitionIndex(r.index(n));
                }
            } else if !m.function_instantiations.is_empty() {
                let i = r.below(m.function_instantiations.len());
                let n = m.signatures.len();
                m.function_instantiations[i].type_parameters = SignatureIndex(r.index(n));
            }
        }
    }
}

/// Extended instruction pool: every opcode, including the ones `random_instr` never makes.
fn random_instr_ext(m: &CompiledModule, r: &mut Rng, code_len: usize, locals: usize, n_jt: usize) -> Bytecode {
    use Bytecode as B;
    let sd = |r: &mut Rng| StructDefinitionIndex(r.index(m.struct_defs.len()));
    let si = |r: &mut Rng| StructDefInstantiationIndex(r.index(m.struct_def_instantiations.len()));
    let vh = |r: &mut Rng| VariantHandleIndex(r.index(m.variant_handles.len()));
    let vi = |r: &mut Rng| VariantInstantiationHandleIndex(r.index(m.variant_instantiation_handles.len()));
    match r.below(24) {
        0 => B::LdFalse,
        1 => B::MutBorrowFieldGeneric(FieldInstantiationIndex(r.index(m.field_instantiations.len()))),
        2 => B::UnpackGeneric(si(r)),
        3 => B::PackVariantGeneric(vi(r)),
        4 => B::UnpackVariantImmRef(vh(r)),
        5 => B::UnpackVariantMutRef(vh(r)),
        6 => B::UnpackVariantGeneric(vi(r)),
        7 => B::UnpackVariantGenericImmRef(vi(r)),
        8 => B::UnpackVariantGenericMutRef(vi(r)),
        9 | 10 => B::VariantSwitch(VariantJumpTableIndex(r.index(n_jt))),
        11 => B::ExistsDeprecated(sd(r)),
        12 => B::ExistsGenericDeprecated(si(r)),
        13 => B::MoveFromDeprecated(sd(r)),
        14 => B::MoveFromGenericDeprecated(si(r)),
        15 => B::MoveToDeprecated(sd(r)),
        16 => B::MoveToGenericDeprecated(si(r)),
        17 => B::MutBorrowGlobalDeprecated(sd(r)),
        18 => B::MutBorrowGlobalGenericDeprecated(si(r)),
        19 => B::ImmBorrowGlobalDeprecated(sd(r)),
        20 => B::ImmBorrowGlobalGenericDeprecated(si(r)),
        21 => B::LdU128(Box::new(r.next() as u128)),
        22 => B::LdU32(r.next() as u32),
        _ => random_instr(m, r, code_len, locals),
    }
}

fn struct_edit_ext(m: &mut CompiledModule, base: &CompiledModule, r: &mut Rng) {
    let with_code: Vec<usize> = (0..m.function_defs.len()).filter(|&i| m.function_defs[i].code.is_some()).collect();
    match r.below(12) {
        0..=3 if !with_code.is_empty() => {
            let f = with_code[r.below(with_code.len())];
            let n_jt = m.function_defs[f].code.as_ref().unwrap().jump_tables.len();
            let len = m.function_defs[f].code.as_ref().unwrap().code.len();
            let ins = random_instr_ext(base, r, len, 4, n_jt);
            let code = &mut m.function_defs[f].code.as_mut().unwrap().code;
            if code.is_empty() || r.below(2) == 0 {
                let i = r.below(code.len() + 1);
                code.insert(i, ins);
            } else {
                let i = r.below(code.len());
                code[i] = ins;
            }
        }
        4 | 5 if !with_code.is_empty() => {
            // jump tables: retarget, drop or add an offset, change head enum, add/remove a table
            let f = with_code[r.below(with_code.len())];
            let n_enums = m.enum_defs.len();
            let cu = m.function_defs[f].code.as_mut().unwrap();
            let len = cu.code.len();
            if cu.jump_tables.is_empty() || r.below(4) == 0 {
                let n = 1 + r.below(3);
                cu.jump_tables.push(VariantJumpTable {
                    head_enum: EnumDefinitionIndex(r.index(n_enums)),
                    jump_table: JumpTableInner::Full((0..n).map(|_| r.index(len)).collect()),
                });
            } else {
                let t = r.below(cu.jump_tables.len());
                match r.below(4) {
                    0 => cu.jump_tables[t].head_enum = EnumDefinitionIndex(r.index(n_enums)),
                    1 => {
                        let JumpTableInner::Full(v) = &mut cu.jump_tables[t].jump_table;
                        if !v.is_empty() {
                            let k = r.below(v.len());
                            v[k] = r.index(len);
                        }
                    }
                    2 => {
                        let JumpTableInner::Full(v) = &mut cu.jump_tables[t].jump_table;
                        if r.below(2) == 0 && !v.is_empty() {
                            v.pop();
                        } else {
                            v.push(r.index(len));
                        }
                    }
                    _ => {
                        cu.jump_tables.remove(t);
                    }
                }
            }
        }
        6 | 7 if !m.enum_defs.is_empty() => {
            let i = r.below(m.enum_defs.len());
            let tok = random_token(base, r, 0);
            let n_ids = m.identifiers.len();
            let n_dt = m.datatype_handles.len();
            let e = &mut m.enum_defs[i];
            match r.below(5) {
                0 if !e.variants.is_empty() => {
                    let j = r.below(e.variants.len());
                    e.variants.remove(j);
                }
                1 => {
                    let name = IdentifierIndex(r.index(n_ids));
                    e.variants.push(VariantDefinition { variant_name: name, fields: vec![] });
                }
                2 => e.enum_handle = DatatypeHandleIndex(r.index(n_dt)),
                3 if !e.variants.is_empty() => {
                    let j = r.below(e.variants.len());
                    let fs = &mut e.variants[j].fields;
                    if fs.is_empty() || r.below(2) == 0 {
                        fs.push(FieldDefinition { name: IdentifierIndex(r.index(n_ids)), signature: TypeSignature(tok) });
                    } else {
                        let k = r.below(fs.len());
                        fs[k].signature = TypeSignature(tok);
                    }
                }
                _ if e.variants.len() > 1 => {
                    let a = r.below(e.variants.len());
                    let b = r.below(e.variants.len());
                    e.variants.swap(a, b);
                }
                _ => {}
            }
        }
        8 if !m.variant_handles.is_empty() => {
            let i = r.below(m.variant_handles.len());
            let n = m.enum_defs.len();
            if r.below(2) == 0 {
                m.variant_handles[i].variant = m.variant_handles[i].variant.wrapping_add(1 + r.below(2) as u16);
            } else {
                m.variant_handles[i].enum_def = EnumDefinitionIndex(r.index(n));
            }
        }
        9 if !m.variant_instantiation_handles.is_empty() => {
            let i = r.below(m.variant_instantiation_handles.len());
            let n = m.enum_def_instantiations.len();
            if r.below(2) == 0 {
                m.variant_instantiation_handles[i].variant = m.variant_instantiation_handles[i].variant.wrapping_add(1);
            } else {
                m.variant_instantiation_handles[i].enum_def = EnumDefInstantiationIndex(r.index(n));
            }
        }
        10 if !m.struct_def_instantiations.is_empty() || !m.enum_def_instantiations.is_empty() => {
            let n = m.signatures.len();
            if !m.enum_def_instantiations.is_empty() && r.below(2) == 0 {
                let i = r.below(m.enum_def_instantiations.len());
                m.enum_def_instantiations[i].type_parameters = SignatureIndex(r.index(n));
            } else if !m.struct_def_instantiations.is_empty() {
                let i = r.below(m.struct_def_instantiations.len());
                m.struct_def_instantiations[i].type_parameters = SignatureIndex(r.index(n));
            }
        }
        _ => {
            // a deep or wide signature near the limits
            if !m.signatures.is_empty() {
                let s = r.below(m.signatures.len());
                let mut t = random_token(base, r, 0);
                for _ in 0..(1 + r.below(300)) {
                    t = if r.below(2) == 0 { SignatureToken::Vector(Box::new(t)) } else { t };
                }
                m.signatures[s].0.push(t);
            }
        }
    }
}

/// Inserts `seq` at `at`, moving every branch and jump-table target past `at` along.
fn insert_code(cu: &mut CodeUnit, at: usize, seq: Vec<Bytecode>) {
    let n = seq.len() as u16;
    let at16 = at as u16;
    for ins in cu.code.iter_mut() {
        if let Bytecode::BrTrue(t) | Bytecode::BrFalse(t) | Bytecode::Branch(t) = ins {
            if *t > at16 {
                *t = t.saturating_add(n);
            }
        }
    }
    for jt in cu.jump_tables.iter_mut() {
        let JumpTableInner::Full(v) = &mut jt.jump_table;
        for t in v.iter_mut() {
            if *t > at16 {
                *t = t.saturating_add(n);
            }
        }
    }
    // a seq with internal targets is written relative to `at`
    let seq: Vec<Bytecode> = seq
        .into_iter()
        .map(|b| match b {
            Bytecode::BrTrue(t) => Bytecode::BrTrue(t + at16),
            Bytecode::BrFalse(t) => Bytecode::BrFalse(t + at16),
            Bytecode::Branch(t) => Bytecode::Branch(t + at16),
            b => b,
        })
        .collect();
    cu.code.splice(at..at, seq);
}

/// Edits aimed at verifier paths random edits rarely reach: reference safety (stack-neutral
/// borrow/copy/move insertions), loop depth, basic block and definition limits, enum limits,
/// long identifiers, many locals.
fn struct_edit_targeted(m: &mut CompiledModule, r: &mut Rng) {
    use Bytecode as B;
    let with_code: Vec<usize> = (0..m.function_defs.len()).filter(|&i| m.function_defs[i].code.as_ref().map(|c| !c.code.is_empty()).unwrap_or(false)).collect();
    let k = r.below(20);
    if k >= 16 && !with_code.is_empty() {
        hold_ref(m, &with_code, r);
        return;
    }
    if k < 8 && !with_code.is_empty() {
        let f = with_code[r.below(with_code.len())];
        let params = m.function_handles.get(m.function_defs[f].function.0 as usize).and_then(|h| m.signatures.get(h.parameters.0 as usize)).map(|s| s.0.len()).unwrap_or(0);
        let locals_idx = m.function_defs[f].code.as_ref().unwrap().locals.0 as usize;
        let n_locals = params + m.signatures.get(locals_idx).map(|s| s.0.len()).unwrap_or(0);
        let l = r.below(n_locals.max(1)).min(255) as u8;
        let seq = match k {
            0 => vec![B::CopyLoc(l), B::Pop],
            1 => vec![B::MoveLoc(l), B::StLoc(l)],
            2 => vec![B::ImmBorrowLoc(l), B::Pop],
            3 => vec![B::MutBorrowLoc(l), B::Pop],
            4 => vec![B::MutBorrowLoc(l), B::FreezeRef, B::Pop],
            5 => vec![B::CopyLoc(l), B::ReadRef, B::Pop],
            6 => vec![B::CopyLoc(l), B::CopyLoc(l), B::Pop, B::Pop],
            _ => vec![B::MutBorrowLoc(l), B::CopyLoc(l), B::Pop, B::Pop],
        };
        let cu = m.function_defs[f].code.as_mut().unwrap();
        let at = r.below(cu.code.len());
        insert_code(cu, at, seq);
        return;
    }
    match k {
        8 if !with_code.is_empty() => {
            // nested loops, depth 4 to 7 (limit 5)
            let f = with_code[r.below(with_code.len())];
            let depth = 4 + r.below(4) as u16;
            let mut seq: Vec<B> = (0..depth).map(|_| B::Nop).collect();
            for d in (0..depth).rev() {
                seq.push(B::LdTrue);
                seq.push(B::BrTrue(d));
            }
            let cu = m.function_defs[f].code.as_mut().unwrap();
            let at = r.below(cu.code.len());
            insert_code(cu, at, seq);
        }
        9 if !with_code.is_empty() => {
            // a run of Branch(next): basic block count around the 1024 limit
            let f = with_code[r.below(with_code.len())];
            let n = 1000 + r.below(60) as u16;
            let seq: Vec<B> = (0..n).map(|j| B::Branch(j + 1)).collect();
            let cu = m.function_defs[f].code.as_mut().unwrap();
            let at = r.below(cu.code.len());
            insert_code(cu, at, seq);
        }
        10 if !with_code.is_empty() => {
            // many locals (TOO_MANY_LOCALS above 255 with the parameters)
            let f = with_code[r.below(with_code.len())];
            let n = 250 + r.below(12);
            m.signatures.push(Signature((0..n).map(|_| SignatureToken::U64).collect()));
            let si = SignatureIndex((m.signatures.len() - 1) as u16);
            m.function_defs[f].code.as_mut().unwrap().locals = si;
        }
        11 if !m.struct_defs.is_empty() => {
            // fields around the 32 limit
            let i = r.below(m.struct_defs.len());
            let n_ids = m.identifiers.len();
            let n = 30 + r.below(5);
            if let StructFieldInformation::Declared(fields) = &mut m.struct_defs[i].field_information {
                while fields.len() < n {
                    fields.push(FieldDefinition { name: IdentifierIndex(r.below(n_ids.max(1)) as u16), signature: TypeSignature(SignatureToken::U64) });
                }
            }
        }
        12 if !m.enum_defs.is_empty() => {
            let i = r.below(m.enum_defs.len());
            let n_ids = m.identifiers.len();
            if r.below(3) == 0 {
                m.enum_defs[i].variants.clear();
            } else {
                let n = 125 + r.below(6);
                while m.enum_defs[i].variants.len() < n {
                    m.enum_defs[i].variants.push(VariantDefinition { variant_name: IdentifierIndex(r.below(n_ids.max(1)) as u16), fields: vec![] });
                }
            }
        }
        13 if !m.identifiers.is_empty() => {
            let i = r.below(m.identifiers.len());
            let n = 126 + r.below(5);
            let name: String = std::iter::once('a').chain((1..n).map(|_| 'x')).collect();
            m.identifiers[i] = move_core_types::identifier::Identifier::new(name).unwrap();
        }
        14 if !m.function_defs.is_empty() || !m.struct_defs.is_empty() => {
            // definition counts around the limits (1000 functions, 200 data definitions)
            if r.below(2) == 0 && !m.struct_defs.is_empty() {
                let d = m.struct_defs[r.below(m.struct_defs.len())].clone();
                let n = 198 + r.below(5);
                while m.struct_defs.len() + m.enum_defs.len() < n {
                    m.struct_defs.push(d.clone());
                }
            } else if !m.function_defs.is_empty() {
                let mut d = m.function_defs[r.below(m.function_defs.len())].clone();
                d.code = None;
                let n = 998 + r.below(5);
                while m.function_defs.len() < n {
                    m.function_defs.push(d.clone());
                }
            }
        }
        _ => {
            // a wide type in a function signature (type node limit)
            if !m.function_handles.is_empty() && !m.datatype_handles.is_empty() {
                let h = r.below(m.function_handles.len());
                let p = m.function_handles[h].parameters.0 as usize;
                let mut t = SignatureToken::U8;
                for _ in 0..(20 + r.below(80)) {
                    t = SignatureToken::Vector(Box::new(t));
                }
                let w = 1 + r.below(8);
                let toks: Vec<SignatureToken> = (0..w).map(|_| t.clone()).collect();
                if let Some(sig) = m.signatures.get_mut(p) {
                    sig.0.extend(toks);
                }
            }
        }
    }
}

/// Keeps a borrow of a local alive across a stretch of one basic block: pushes
/// `CopyLoc`/`MutBorrowLoc`/`ImmBorrowLoc` of a local at a statement boundary `p` and pops it at
/// a later boundary `q`, so the reference-safety checks between them see an extra borrow.
fn hold_ref(m: &mut CompiledModule, with_code: &[usize], r: &mut Rng) {
    use Bytecode as B;
    let f = with_code[r.below(with_code.len())];
    let params = m.function_handles.get(m.function_defs[f].function.0 as usize).and_then(|h| m.signatures.get(h.parameters.0 as usize)).map(|s| s.0.len()).unwrap_or(0);
    let locals_idx = m.function_defs[f].code.as_ref().unwrap().locals.0 as usize;
    let n_locals = params + m.signatures.get(locals_idx).map(|s| s.0.len()).unwrap_or(0);
    let cu = m.function_defs[f].code.as_mut().unwrap();
    let code = &cu.code;
    let mut targets = std::collections::BTreeSet::new();
    for ins in code {
        if let B::BrTrue(t) | B::BrFalse(t) | B::Branch(t) = ins {
            targets.insert(*t as usize);
        }
    }
    for jt in &cu.jump_tables {
        let JumpTableInner::Full(v) = &jt.jump_table;
        targets.extend(v.iter().map(|t| *t as usize));
    }
    // statement boundaries: start, or just after StLoc / Pop / WriteRef
    let bounds: Vec<usize> = (0..code.len())
        .filter(|&i| i == 0 || matches!(code[i - 1], B::StLoc(_) | B::Pop | B::WriteRef))
        .collect();
    if bounds.is_empty() {
        return;
    }
    let p = bounds[r.below(bounds.len())];
    let mut q = None;
    for &b in bounds.iter().filter(|&&b| b > p) {
        let ok = (p..b).all(|i| !matches!(code[i], B::BrTrue(_) | B::BrFalse(_) | B::Branch(_) | B::Ret | B::Abort | B::VariantSwitch(_)))
            && !targets.range(p + 1..=b).any(|_| true);
        if !ok {
            break;
        }
        q = Some(b);
        if r.below(3) == 0 {
            break;
        }
    }
    let Some(q) = q else { return };
    let l = r.below(n_locals.max(1)).min(255) as u8;
    let push = match r.below(3) {
        0 => B::CopyLoc(l),
        1 => B::MutBorrowLoc(l),
        _ => B::ImmBorrowLoc(l),
    };
    insert_code(cu, q, vec![B::Pop]);
    insert_code(cu, p, vec![push]);
}
