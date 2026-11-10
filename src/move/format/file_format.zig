//! Move binary format (CompiledModule) as Sui 1.83.1 uses it: move-binary-format's
//! `file_format.rs` and `file_format_common.rs`, laid out for speed.
//!
//! Layout choices (semantics are Rust's, representation is ours):
//! - Signature tokens are flat preorder node arrays (`Token = []const Node`). A preorder walk is
//!   a slice walk, equality is `std.mem.eql`, and a sub-token is a slice of its parent.
//! - Instructions are fixed 16-byte records (`Instr`); u128/u256 immediates live in `wide`.
//! - Identifiers, addresses, constant data and metadata borrow the module bytes.
//! - Everything else is allocated in one arena per module.
const std = @import("std");
pub const StatusCode = @import("status.zig").StatusCode;

pub const TableIndex = u16;
pub const CodeOffset = u16;
pub const LocalIndex = u8;

// ---------------------------------------------------------------------------------------------
// Binary format constants (file_format_common.rs)

pub const VERSION_1: u32 = 1;
pub const VERSION_2: u32 = 2;
pub const VERSION_3: u32 = 3;
pub const VERSION_4: u32 = 4;
pub const VERSION_5: u32 = 5;
pub const VERSION_6: u32 = 6;
pub const VERSION_7: u32 = 7;
pub const VERSION_MAX: u32 = VERSION_7;
pub const VERSION_MIN: u32 = VERSION_5;

pub const MOVE_MAGIC = [4]u8{ 0xA1, 0x1C, 0xEB, 0x0B };
pub const UNPUBLISHABLE_MAGIC = [4]u8{ 0xDE, 0xAD, 0xC0, 0xDE };
pub const SUI_FLAVOR: u8 = 0x05;

pub const TABLE_COUNT_MAX: u64 = 255;
pub const TABLE_OFFSET_MAX: u64 = 0xffff_ffff;
pub const TABLE_SIZE_MAX: u64 = 0xffff_ffff;
pub const TABLE_INDEX_MAX: u64 = 65535;
pub const BYTECODE_COUNT_MAX: u64 = 65535;
pub const BYTECODE_INDEX_MAX: u64 = 65535;
pub const LOCAL_INDEX_MAX: u64 = 255;
pub const IDENTIFIER_SIZE_MAX: u64 = 65535;
pub const CONSTANT_SIZE_MAX: u64 = 65535;
pub const METADATA_KEY_SIZE_MAX: u64 = 1023;
pub const METADATA_VALUE_SIZE_MAX: u64 = 65535;
pub const SIGNATURE_SIZE_MAX: u64 = 255;
pub const ACQUIRES_COUNT_MAX: u64 = 255;
pub const FIELD_COUNT_MAX: u64 = 255;
pub const FIELD_OFFSET_MAX: u64 = 255;
pub const VARIANT_COUNT_MAX: u64 = 127;
pub const VARIANT_TAG_MAX_VALUE: u64 = VARIANT_COUNT_MAX - 1;
pub const JUMP_TABLE_INDEX_MAX: u64 = 127;
pub const VARIANT_HANDLE_INDEX_MAX: u64 = 1024;
pub const VARIANT_INSTANTIATION_HANDLE_INDEX_MAX: u64 = 1024;
pub const TYPE_PARAMETER_COUNT_MAX: u64 = 255;
pub const TYPE_PARAMETER_INDEX_MAX: u64 = 65536;
pub const SIGNATURE_TOKEN_DEPTH_MAX: usize = 256;

pub fn encodeVersion(v: u32) u32 {
    if (v <= VERSION_6) return v;
    return (@as(u32, SUI_FLAVOR) << 24) | v;
}

pub const TableType = enum(u8) {
    MODULE_HANDLES = 0x1,
    DATATYPE_HANDLES = 0x2,
    FUNCTION_HANDLES = 0x3,
    FUNCTION_INST = 0x4,
    SIGNATURES = 0x5,
    CONSTANT_POOL = 0x6,
    IDENTIFIERS = 0x7,
    ADDRESS_IDENTIFIERS = 0x8,
    STRUCT_DEFS = 0xA,
    STRUCT_DEF_INST = 0xB,
    FUNCTION_DEFS = 0xC,
    FIELD_HANDLE = 0xD,
    FIELD_INST = 0xE,
    FRIEND_DECLS = 0xF,
    METADATA = 0x10,
    ENUM_DEFS = 0x11,
    ENUM_DEF_INST = 0x12,
    VARIANT_HANDLES = 0x13,
    VARIANT_INST_HANDLES = 0x14,
    _,

    pub fn valid(t: TableType) bool {
        return switch (t) {
            .MODULE_HANDLES, .DATATYPE_HANDLES, .FUNCTION_HANDLES, .FUNCTION_INST, .SIGNATURES, .CONSTANT_POOL, .IDENTIFIERS, .ADDRESS_IDENTIFIERS, .STRUCT_DEFS, .STRUCT_DEF_INST, .FUNCTION_DEFS, .FIELD_HANDLE, .FIELD_INST, .FRIEND_DECLS, .METADATA, .ENUM_DEFS, .ENUM_DEF_INST, .VARIANT_HANDLES, .VARIANT_INST_HANDLES => true,
            _ => false,
        };
    }
};

/// Binary opcodes. The tag value is the byte in the binary.
pub const Opcode = enum(u8) {
    Pop = 0x01,
    Ret = 0x02,
    BrTrue = 0x03,
    BrFalse = 0x04,
    Branch = 0x05,
    LdU64 = 0x06,
    LdConst = 0x07,
    LdTrue = 0x08,
    LdFalse = 0x09,
    CopyLoc = 0x0A,
    MoveLoc = 0x0B,
    StLoc = 0x0C,
    MutBorrowLoc = 0x0D,
    ImmBorrowLoc = 0x0E,
    MutBorrowField = 0x0F,
    ImmBorrowField = 0x10,
    Call = 0x11,
    Pack = 0x12,
    Unpack = 0x13,
    ReadRef = 0x14,
    WriteRef = 0x15,
    Add = 0x16,
    Sub = 0x17,
    Mul = 0x18,
    Mod = 0x19,
    Div = 0x1A,
    BitOr = 0x1B,
    BitAnd = 0x1C,
    Xor = 0x1D,
    Or = 0x1E,
    And = 0x1F,
    Not = 0x20,
    Eq = 0x21,
    Neq = 0x22,
    Lt = 0x23,
    Gt = 0x24,
    Le = 0x25,
    Ge = 0x26,
    Abort = 0x27,
    Nop = 0x28,
    ExistsDeprecated = 0x29,
    MutBorrowGlobalDeprecated = 0x2A,
    ImmBorrowGlobalDeprecated = 0x2B,
    MoveFromDeprecated = 0x2C,
    MoveToDeprecated = 0x2D,
    FreezeRef = 0x2E,
    Shl = 0x2F,
    Shr = 0x30,
    LdU8 = 0x31,
    LdU128 = 0x32,
    CastU8 = 0x33,
    CastU64 = 0x34,
    CastU128 = 0x35,
    MutBorrowFieldGeneric = 0x36,
    ImmBorrowFieldGeneric = 0x37,
    CallGeneric = 0x38,
    PackGeneric = 0x39,
    UnpackGeneric = 0x3A,
    ExistsGenericDeprecated = 0x3B,
    MutBorrowGlobalGenericDeprecated = 0x3C,
    ImmBorrowGlobalGenericDeprecated = 0x3D,
    MoveFromGenericDeprecated = 0x3E,
    MoveToGenericDeprecated = 0x3F,
    VecPack = 0x40,
    VecLen = 0x41,
    VecImmBorrow = 0x42,
    VecMutBorrow = 0x43,
    VecPushBack = 0x44,
    VecPopBack = 0x45,
    VecUnpack = 0x46,
    VecSwap = 0x47,
    LdU16 = 0x48,
    LdU32 = 0x49,
    LdU256 = 0x4A,
    CastU16 = 0x4B,
    CastU32 = 0x4C,
    CastU256 = 0x4D,
    PackVariant = 0x4E,
    PackVariantGeneric = 0x4F,
    UnpackVariant = 0x50,
    UnpackVariantImmRef = 0x51,
    UnpackVariantMutRef = 0x52,
    UnpackVariantGeneric = 0x53,
    UnpackVariantGenericImmRef = 0x54,
    UnpackVariantGenericMutRef = 0x55,
    VariantSwitch = 0x56,
    _,

    pub fn isValid(op: Opcode) bool {
        const b = @intFromEnum(op);
        return b >= 0x01 and b <= 0x56;
    }

    /// Rust `Bytecode::is_conditional_branch`.
    pub fn isConditionalBranch(op: Opcode) bool {
        return op == .BrTrue or op == .BrFalse;
    }

    /// Rust `Bytecode::is_unconditional_branch` (VariantSwitch is exhaustive, so unconditional).
    pub fn isUnconditionalBranch(op: Opcode) bool {
        return switch (op) {
            .Ret, .Abort, .Branch, .VariantSwitch => true,
            else => false,
        };
    }

    /// Rust `Bytecode::is_branch`: conditional or unconditional (includes Ret/Abort/VariantSwitch).
    pub fn isBranch(op: Opcode) bool {
        return op.isConditionalBranch() or op.isUnconditionalBranch();
    }

    /// BrTrue/BrFalse/Branch: the instructions whose `idx` is a code offset.
    pub fn hasOffset(op: Opcode) bool {
        return op == .BrTrue or op == .BrFalse or op == .Branch;
    }
};

/// One instruction. `idx` holds every u16 operand (table index, local, code offset, jump table);
/// `imm` holds LdU8/16/32/64 values, the VecPack/VecUnpack count, or the `wide` index for
/// LdU128/LdU256.
pub const Instr = extern struct {
    op: Opcode,
    _pad0: u8 = 0,
    idx: u16 = 0,
    _pad1: u32 = 0,
    imm: u64 = 0,

    /// Rust `Bytecode::get_successors` offsets / `offsets()` for branches.
    pub fn branchTarget(i: Instr) ?u16 {
        return if (i.op.hasOffset()) i.idx else null;
    }
};

comptime {
    std.debug.assert(@sizeOf(Instr) == 16);
}

// ---------------------------------------------------------------------------------------------
// Abilities

pub const Ability = enum(u8) { Copy = 0x1, Drop = 0x2, Store = 0x4, Key = 0x8 };

pub const AbilitySet = packed struct(u8) {
    bits: u8,

    pub const EMPTY: AbilitySet = .{ .bits = 0 };
    pub const ALL: AbilitySet = .{ .bits = 0xF };
    pub const PRIMITIVES: AbilitySet = .{ .bits = 0x1 | 0x2 | 0x4 };
    pub const REFERENCES: AbilitySet = .{ .bits = 0x1 | 0x2 };
    pub const SIGNER: AbilitySet = .{ .bits = 0x2 };
    pub const VECTOR: AbilitySet = .{ .bits = 0x1 | 0x2 | 0x4 };

    pub fn has(s: AbilitySet, a: Ability) bool {
        return s.bits & @intFromEnum(a) == @intFromEnum(a);
    }
    pub fn hasCopy(s: AbilitySet) bool {
        return s.has(.Copy);
    }
    pub fn hasDrop(s: AbilitySet) bool {
        return s.has(.Drop);
    }
    pub fn hasStore(s: AbilitySet) bool {
        return s.has(.Store);
    }
    pub fn hasKey(s: AbilitySet) bool {
        return s.has(.Key);
    }
    pub fn with(s: AbilitySet, a: Ability) AbilitySet {
        return .{ .bits = s.bits | @intFromEnum(a) };
    }
    pub fn remove(s: AbilitySet, a: Ability) AbilitySet {
        return .{ .bits = s.bits & ~@intFromEnum(a) };
    }
    pub fn intersect(a: AbilitySet, b: AbilitySet) AbilitySet {
        return .{ .bits = a.bits & b.bits };
    }
    pub fn unite(a: AbilitySet, b: AbilitySet) AbilitySet {
        return .{ .bits = a.bits | b.bits };
    }
    pub fn isSubset(a: AbilitySet, b: AbilitySet) bool {
        return a.bits & b.bits == a.bits;
    }
    pub fn eql(a: AbilitySet, b: AbilitySet) bool {
        return a.bits == b.bits;
    }

    /// Rust `Ability::requires`: what a type argument needs for the containing type to have `a`.
    pub fn requires(a: Ability) Ability {
        return switch (a) {
            .Copy => .Copy,
            .Drop => .Drop,
            .Store => .Store,
            .Key => .Store,
        };
    }

    /// Rust `Ability::required_by`.
    pub fn requiredBy(a: Ability) AbilitySet {
        return switch (a) {
            .Copy => .{ .bits = 0x1 },
            .Drop => .{ .bits = 0x2 },
            .Store => .{ .bits = 0x4 | 0x8 },
            .Key => EMPTY,
        };
    }

    /// Rust `AbilitySet::polymorphic_abilities` (declared abilities of a generic datatype given
    /// its instantiation's abilities). Callers check the length match (Rust returns an error).
    pub fn polymorphic(declared: AbilitySet, phantoms: []const DatatypeTyParameter, args: []const AbilitySet) AbilitySet {
        var acc = declared;
        for (args, phantoms) |arg, p| {
            if (p.is_phantom) continue;
            var req: AbilitySet = EMPTY;
            inline for (.{ Ability.Copy, Ability.Drop, Ability.Store, Ability.Key }) |ab| {
                if (arg.has(ab)) req = req.unite(requiredBy(ab));
            }
            acc = acc.intersect(req);
        }
        return acc;
    }
};

// ---------------------------------------------------------------------------------------------
// Signature tokens (flat preorder)

pub const Tag = enum(u8) {
    Bool,
    U8,
    U64,
    U128,
    Address,
    Signer,
    Vector,
    Datatype,
    DatatypeInstantiation,
    Reference,
    MutableReference,
    TypeParameter,
    U16,
    U32,
    U256,
};

/// One preorder node. `Datatype`: `idx` = datatype handle. `DatatypeInstantiation`: `idx` =
/// handle, `arity` = number of argument subtrees that follow (1..255). `TypeParameter`: `idx`.
/// `Vector`/`Reference`/`MutableReference`: one subtree follows.
pub const Node = extern struct {
    tag: Tag,
    arity: u8 = 0,
    idx: u16 = 0,

    pub fn eql(a: Node, b: Node) bool {
        return a.tag == b.tag and a.arity == b.arity and a.idx == b.idx;
    }
};

pub const Token = []const Node;

pub fn tokenEql(a: Token, b: Token) bool {
    // Node is 4 bytes with no padding: compare the preorder arrays as bytes.
    return std.mem.eql(u8, std.mem.sliceAsBytes(a), std.mem.sliceAsBytes(b));
}

/// Length in nodes of the subtree starting at `t[0]`.
pub fn subtreeLen(t: Token) usize {
    var need: usize = 1;
    var i: usize = 0;
    while (need > 0) : (i += 1) {
        need -= 1;
        need += childCount(t[i]);
    }
    return i;
}

pub fn childCount(n: Node) usize {
    return switch (n.tag) {
        .Vector, .Reference, .MutableReference => 1,
        .DatatypeInstantiation => n.arity,
        else => 0,
    };
}

/// The inner token of Vector/Reference/MutableReference.
pub fn inner(t: Token) Token {
    return t[1..];
}

/// Iterator over the argument subtrees of a DatatypeInstantiation token.
pub const ArgIter = struct {
    rest: Token,
    left: usize,
    pub fn init(t: Token) ArgIter {
        return .{ .rest = t[1..], .left = t[0].arity };
    }
    pub fn next(it: *ArgIter) ?Token {
        if (it.left == 0) return null;
        it.left -= 1;
        const n = subtreeLen(it.rest);
        const r = it.rest[0..n];
        it.rest = it.rest[n..];
        return r;
    }
};

/// Rust `SignatureToken::preorder_traversal_with_depth` depth of every node (root = 1).
pub fn maxDepth(t: Token) usize {
    var open: [512]u32 = undefined; // remaining children of each open ancestor
    var sp: usize = 0;
    var max: usize = 0;
    for (t) |n| {
        const depth = sp + 1;
        if (depth > max) max = depth;
        const c = childCount(n);
        if (c > 0) {
            if (sp == open.len) return depth; // far beyond any limit callers compare against
            open[sp] = @intCast(c);
            sp += 1;
        } else {
            while (sp > 0) {
                open[sp - 1] -= 1;
                if (open[sp - 1] > 0) break;
                sp -= 1;
            }
        }
    }
    return max;
}

pub fn isReference(t: Token) bool {
    return t[0].tag == .Reference or t[0].tag == .MutableReference;
}
pub fn isMutableReference(t: Token) bool {
    return t[0].tag == .MutableReference;
}
pub fn isInteger(t: Token) bool {
    return switch (t[0].tag) {
        .U8, .U16, .U32, .U64, .U128, .U256 => true,
        else => false,
    };
}
pub fn isSigner(t: Token) bool {
    return t[0].tag == .Signer;
}

// ---------------------------------------------------------------------------------------------
// Tables

pub const ModuleHandle = struct { address: TableIndex, name: TableIndex };

pub const DatatypeTyParameter = struct { constraints: AbilitySet, is_phantom: bool };

pub const DatatypeHandle = struct {
    module: TableIndex,
    name: TableIndex,
    abilities: AbilitySet,
    type_parameters: []const DatatypeTyParameter,
};

pub const FunctionHandle = struct {
    module: TableIndex,
    name: TableIndex,
    parameters: TableIndex,
    return_: TableIndex,
    type_parameters: []const AbilitySet,
};

pub const FieldHandle = struct { owner: TableIndex, field: u16 };
pub const StructDefInstantiation = struct { def: TableIndex, type_parameters: TableIndex };
pub const FunctionInstantiation = struct { handle: TableIndex, type_parameters: TableIndex };
pub const FieldInstantiation = struct { handle: TableIndex, type_parameters: TableIndex };

pub const FieldDefinition = struct { name: TableIndex, signature: Token };

pub const StructDefinition = struct {
    struct_handle: TableIndex,
    /// `StructFieldInformation::Native` when true; `fields` is then empty.
    native: bool,
    fields: []const FieldDefinition,

    pub fn declaredFields(s: *const StructDefinition) ?[]const FieldDefinition {
        return if (s.native) null else s.fields;
    }
};

pub const VariantDefinition = struct { variant_name: TableIndex, fields: []const FieldDefinition };
pub const EnumDefinition = struct { enum_handle: TableIndex, variants: []const VariantDefinition };
pub const EnumDefInstantiation = struct { def: TableIndex, type_parameters: TableIndex };
pub const VariantHandle = struct { enum_def: TableIndex, variant: u16 };
pub const VariantInstantiationHandle = struct { enum_def: TableIndex, variant: u16 };

pub const Visibility = enum(u8) {
    Private = 0x0,
    Public = 0x1,
    Friend = 0x3,
    pub const DEPRECATED_SCRIPT: u8 = 0x2;
};

pub const JumpTable = struct { head_enum: TableIndex, offsets: []const CodeOffset };

pub const CodeUnit = struct {
    locals: TableIndex,
    code: []const Instr,
    jump_tables: []const JumpTable,
};

pub const FunctionDefinition = struct {
    function: TableIndex,
    visibility: Visibility,
    is_entry: bool,
    acquires: []const TableIndex,
    code: ?CodeUnit,

    pub const DEPRECATED_PUBLIC_BIT: u8 = 0b01;
    pub const NATIVE: u8 = 0b10;
    pub const ENTRY: u8 = 0b100;

    pub fn isNative(f: *const FunctionDefinition) bool {
        return f.code == null;
    }
};

pub const Constant = struct { type_: Token, data: []const u8 };
pub const Metadata = struct { key: []const u8, value: []const u8 };

pub const CompiledModule = struct {
    version: u32,
    publishable: bool = true,
    self_module_handle_idx: TableIndex = 0,
    module_handles: []const ModuleHandle = &.{},
    datatype_handles: []const DatatypeHandle = &.{},
    function_handles: []const FunctionHandle = &.{},
    field_handles: []const FieldHandle = &.{},
    friend_decls: []const ModuleHandle = &.{},
    struct_def_instantiations: []const StructDefInstantiation = &.{},
    function_instantiations: []const FunctionInstantiation = &.{},
    field_instantiations: []const FieldInstantiation = &.{},
    signatures: []const []const Token = &.{},
    identifiers: []const []const u8 = &.{},
    address_identifiers: []const [32]u8 = &.{},
    constant_pool: []const Constant = &.{},
    metadata: []const Metadata = &.{},
    struct_defs: []const StructDefinition = &.{},
    function_defs: []const FunctionDefinition = &.{},
    enum_defs: []const EnumDefinition = &.{},
    enum_def_instantiations: []const EnumDefInstantiation = &.{},
    variant_handles: []const VariantHandle = &.{},
    variant_instantiation_handles: []const VariantInstantiationHandle = &.{},
    /// LdU128 / LdU256 immediates, little endian (u128 zero-extended).
    wide: []const [32]u8 = &.{},

    pub fn selfHandle(m: *const CompiledModule) ModuleHandle {
        return m.module_handles[m.self_module_handle_idx];
    }
    pub fn selfName(m: *const CompiledModule) []const u8 {
        return m.identifiers[m.selfHandle().name];
    }
    pub fn selfAddress(m: *const CompiledModule) *const [32]u8 {
        return &m.address_identifiers[m.selfHandle().address];
    }
    pub fn identifierAt(m: *const CompiledModule, i: TableIndex) []const u8 {
        return m.identifiers[i];
    }
    pub fn signatureAt(m: *const CompiledModule, i: TableIndex) []const Token {
        return m.signatures[i];
    }
    pub fn functionHandleAt(m: *const CompiledModule, i: TableIndex) *const FunctionHandle {
        return &m.function_handles[i];
    }
    pub fn datatypeHandleAt(m: *const CompiledModule, i: TableIndex) *const DatatypeHandle {
        return &m.datatype_handles[i];
    }
    pub fn moduleHandleAt(m: *const CompiledModule, i: TableIndex) *const ModuleHandle {
        return &m.module_handles[i];
    }
    /// Rust `module_id_for_handle` equality: same address bytes and same name.
    pub fn sameModule(m: *const CompiledModule, a: *const ModuleHandle, b: *const ModuleHandle) bool {
        return std.mem.eql(u8, &m.address_identifiers[a.address], &m.address_identifiers[b.address]) and
            std.mem.eql(u8, m.identifiers[a.name], m.identifiers[b.name]);
    }
    pub fn isSelfHandle(m: *const CompiledModule, mh_idx: TableIndex) bool {
        return mh_idx == m.self_module_handle_idx;
    }
};

// ---------------------------------------------------------------------------------------------
// Errors (move-binary-format errors.rs)

pub const IndexKind = enum(u8) {
    ModuleHandle,
    DatatypeHandle,
    FunctionHandle,
    FieldHandle,
    FriendDeclaration,
    FunctionInstantiation,
    FieldInstantiation,
    StructDefinition,
    StructDefInstantiation,
    FunctionDefinition,
    FieldDefinition,
    Signature,
    Identifier,
    AddressIdentifier,
    ConstantPool,
    LocalPool,
    CodeDefinition,
    TypeParameter,
    MemberCount,
    EnumDefinition,
    EnumDefInstantiation,
    VariantHandle,
    VariantInstantiationHandle,
    VariantJumpTable,
    VariantTag,
};

pub const max_error_entries = 8;

/// Rust `PartialVMError` minus the message: major status, sub status, index and offset trail.
pub const PartialVmError = struct {
    major: StatusCode,
    sub_status: ?u64 = null,
    n_indices: u8 = 0,
    n_offsets: u8 = 0,
    indices: [max_error_entries]struct { kind: IndexKind, idx: TableIndex } = undefined,
    offsets: [max_error_entries]struct { fdef: TableIndex, offset: CodeOffset } = undefined,

    pub fn new(major: StatusCode) PartialVmError {
        return .{ .major = major };
    }
    pub fn atIndex(e: PartialVmError, kind: IndexKind, idx: TableIndex) PartialVmError {
        var r = e;
        if (r.n_indices < max_error_entries) {
            r.indices[r.n_indices] = .{ .kind = kind, .idx = idx };
            r.n_indices += 1;
        }
        return r;
    }
    pub fn atCodeOffset(e: PartialVmError, fdef: TableIndex, offset: CodeOffset) PartialVmError {
        var r = e;
        if (r.n_offsets < max_error_entries) {
            r.offsets[r.n_offsets] = .{ .fdef = fdef, .offset = offset };
            r.n_offsets += 1;
        }
        return r;
    }
    pub fn withSubStatus(e: PartialVmError, s: u64) PartialVmError {
        var r = e;
        r.sub_status = s;
        return r;
    }
    pub fn indexSlice(e: *const PartialVmError) []const @TypeOf(e.indices[0]) {
        return e.indices[0..e.n_indices];
    }
    pub fn offsetSlice(e: *const PartialVmError) []const @TypeOf(e.offsets[0]) {
        return e.offsets[0..e.n_offsets];
    }
};

pub const Location = union(enum) {
    undefined,
    /// Module(ModuleId): we keep the module name (the address is the module's own).
    module: []const u8,
    package,
};

/// Rust `VMError`: a finished PartialVmError with its location.
pub const VmError = struct {
    err: PartialVmError,
    location: Location,
};

pub fn boundsError(kind: IndexKind, idx: TableIndex) PartialVmError {
    return PartialVmError.new(.INDEX_OUT_OF_BOUNDS).atIndex(kind, idx);
}

pub fn verificationError(status: StatusCode, kind: IndexKind, idx: TableIndex) PartialVmError {
    return PartialVmError.new(status).atIndex(kind, idx);
}

test "instr and node sizes" {
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(Node));
    const t = [_]Node{ .{ .tag = .DatatypeInstantiation, .arity = 2, .idx = 3 }, .{ .tag = .Vector }, .{ .tag = .U8 }, .{ .tag = .Bool } };
    try std.testing.expectEqual(@as(usize, 4), subtreeLen(&t));
    var it = ArgIter.init(&t);
    try std.testing.expectEqual(@as(usize, 2), it.next().?.len);
    try std.testing.expectEqual(@as(usize, 1), it.next().?.len);
    try std.testing.expect(it.next() == null);
    try std.testing.expectEqual(@as(usize, 3), maxDepth(&t));
}
