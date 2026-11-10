//! Loaded-package cache, runtime types and link contexts.
//!
//! - `Runtime` owns every loaded package (keyed by storage/version id), deserialized once with
//!   move_format and kept with precomputed per-module tables (constants, call targets inside
//!   the package, resolved datatypes). It is immutable once loaded and is meant to be shared.
//! - Datatype layouts do not depend on linkage (upgrades keep layouts), so a datatype handle is
//!   resolved once, globally, by (runtime address, module, name).
//! - Threads: `addPackage` needs exclusive access (load packages before sessions start, or under
//!   the caller's write lock); everything else is read-only or atomic, so any number of
//!   sessions may share one Runtime. `local_calls` are built at load; datatype handles resolve
//!   lazily with atomic slots; a `LinkCtx` belongs to one session.
//! - Function bodies do depend on linkage: calls across packages resolve through a `LinkCtx`
//!   built from the root package's linkage table, as Rust's `LinkageContext` does.
const std = @import("std");
const move_format = @import("move_format");
const value = @import("value.zig");
const gas = @import("gas.zig");

const Allocator = std.mem.Allocator;
const ff = move_format.file_format;
const vf = move_format.verifier.verify;
pub const Token = ff.Token;
const Value = value.Value;

pub const Address = [32]u8;

// ---------------------------------------------------------------------------------------------
// Runtime types

pub const Type = union(enum) {
    bool,
    u8,
    u16,
    u32,
    u64,
    u128,
    u256,
    address,
    signer,
    vector: *const Type,
    datatype: Inst,
    ref: *const Type,
    mut_ref: *const Type,
    param: u16,

    pub const Inst = struct { dt: *Datatype, args: []const *const Type };

    pub const t_bool: Type = .bool;
    pub const t_u8: Type = .u8;
    pub const t_u16: Type = .u16;
    pub const t_u32: Type = .u32;
    pub const t_u64: Type = .u64;
    pub const t_u128: Type = .u128;
    pub const t_u256: Type = .u256;
    pub const t_address: Type = .address;
    pub const t_signer: Type = .signer;

    /// The vector kind a value of `vector<self>` has (`VectorSpecialization`).
    pub fn vecKind(t: *const Type) value.Kind {
        return switch (t.*) {
            .u8 => .vec_u8,
            .u16 => .vec_u16,
            .u32 => .vec_u32,
            .u64 => .vec_u64,
            .u128 => .vec_u128,
            .u256 => .vec_u256,
            .bool => .vec_bool,
            .address => .vec_address,
            else => .vec,
        };
    }
};

pub fn primType(tag: ff.Tag) ?*const Type {
    return switch (tag) {
        .Bool => &Type.t_bool,
        .U8 => &Type.t_u8,
        .U16 => &Type.t_u16,
        .U32 => &Type.t_u32,
        .U64 => &Type.t_u64,
        .U128 => &Type.t_u128,
        .U256 => &Type.t_u256,
        .Address => &Type.t_address,
        .Signer => &Type.t_signer,
        else => null,
    };
}

/// Vector kind for an element token when it does not depend on type parameters.
pub fn tokenVecKind(t: Token) ?value.Kind {
    return switch (t[0].tag) {
        .U8 => .vec_u8,
        .U16 => .vec_u16,
        .U32 => .vec_u32,
        .U64 => .vec_u64,
        .U128 => .vec_u128,
        .U256 => .vec_u256,
        .Bool => .vec_bool,
        .Address => .vec_address,
        .Vector, .Datatype, .DatatypeInstantiation, .Signer => .vec,
        .TypeParameter, .Reference, .MutableReference => null,
    };
}

pub const Datatype = struct {
    module: *Module,
    name: []const u8,
    def_idx: u16,
    is_enum: bool,
    n_type_params: u16,
    /// The package id that first defined this type (type tags carry it).
    defining_id: Address,
    /// Struct fields, or variant fields for enums (tokens in `module`).
    fields: []const ff.FieldDefinition = &.{},
    variants: []const ff.VariantDefinition = &.{},
    /// The type with no type arguments (`types.instantiate` of a plain Datatype token returns
    /// this one instead of allocating a copy).
    plain: Type = undefined,
};

// ---------------------------------------------------------------------------------------------
// Packages, modules, functions

pub const TypeOrigin = struct { module: []const u8, name: []const u8, defining: Address };
pub const NamedModule = struct { name: []const u8, bytes: []const u8 };

/// A Move package as stored (sui `MovePackage`, after the linkage table is flattened).
pub const PackageInput = struct {
    version_id: Address,
    original_id: Address,
    version: u64,
    /// (original/runtime id, storage/version id), the package itself included.
    linkage: []const [2]Address,
    type_origins: []const TypeOrigin,
    modules: []const NamedModule,
};

pub const Package = struct {
    rt: *Runtime,
    /// Set when the package cannot be loaded (Rust `make_vm` fails for any linkage that names
    /// it); a refused package has no modules and serves no types or functions.
    refused: ?Refusal = null,
    version_id: Address,
    original_id: Address,
    version: u64,
    linkage: []const [2]Address,
    type_origins: []const TypeOrigin,
    modules: []Module, // sorted by name

    pub fn module(p: *const Package, name: []const u8) ?*Module {
        var lo: usize = 0;
        var hi: usize = p.modules.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            switch (std.mem.order(u8, p.modules[mid].name, name)) {
                .eq => return &p.modules[mid],
                .lt => lo = mid + 1,
                .gt => hi = mid,
            }
        }
        return null;
    }

    pub fn linked(p: *const Package, original: *const Address) ?Address {
        for (p.linkage) |l| if (std.mem.eql(u8, &l[0], original)) return l[1];
        return null;
    }
};

pub const Constant = struct {
    value: Value,
    /// Abstract size (charge_ld_const_abstract_size) and serialized length.
    abstract_size: u64,
    byte_len: u64,
};

pub const Function = struct {
    module: *Module,
    def_idx: u16,
    name: []const u8,
    is_native: bool,
    code: []const ff.Instr = &.{},
    jump_tables: []const ff.JumpTable = &.{},
    params: []const Token,
    /// Non-parameter locals (`params ++ locals` is every local).
    locals: []const Token = &.{},
    returns: []const Token,
    n_locals: u16,
    n_type_params: u16,
    /// A native's resolved entry (interp.Native's call and data), kept for the native table
    /// whose `memo_key` it was looked up in (0: none).
    native_memo_key: u64 = 0,
    native_memo: [2]?*const anyopaque = .{ null, null },
};

pub const Module = struct {
    pkg: *Package,
    name: []const u8,
    cm: ff.CompiledModule,
    functions: []Function,
    structs: []Datatype,
    enums: []Datatype,
    constants: []Constant,
    /// Datatype handle -> definition (resolved on first use).
    dt_handles: []?*Datatype,
    /// Function handle -> target when it is in the same package (null: other package).
    local_calls: []?*Function,

    pub fn functionByName(m: *const Module, name: []const u8) ?*Function {
        for (m.functions) |*f| if (std.mem.eql(u8, f.name, name)) return f;
        return null;
    }

    pub fn moduleHandleAddress(m: *const Module, mh: u16) *const Address {
        return &m.cm.address_identifiers[m.cm.module_handles[mh].address];
    }
    pub fn moduleHandleName(m: *const Module, mh: u16) []const u8 {
        return m.cm.identifiers[m.cm.module_handles[mh].name];
    }

    /// Resolves a datatype handle (global, linkage independent). Sessions on several threads
    /// may resolve the same handle at once: every thread computes the same pointer, and the
    /// cache slot is read and written atomically.
    pub fn datatype(m: *Module, h: u16) LoadError!*Datatype {
        if (@atomicLoad(?*Datatype, &m.dt_handles[h], .acquire)) |d| return d;
        const dh = m.cm.datatype_handles[h];
        const d = try m.pkg.rt.findDatatype(m.moduleHandleAddress(dh.module), m.moduleHandleName(dh.module), m.cm.identifiers[dh.name]);
        @atomicStore(?*Datatype, &m.dt_handles[h], d, .release);
        return d;
    }
};

pub const LoadError = error{ LinkageMissing, ModuleMissing, DatatypeMissing, FunctionMissing, BadModule, BadConstant } || Allocator.Error;

// ---------------------------------------------------------------------------------------------
// Load-time validation (move-vm-runtime package_resolution.rs, validation/, jit translate)

/// Rust `Location` of a finished `VMError`.
pub const Loc = union(enum) {
    undefined,
    package: Address,
    module: struct { addr: Address, name: []const u8 },
};

/// A finished Rust `VMError` (status, sub status, indices, offsets) and its location.
pub const LoadFail = struct {
    err: ff.PartialVmError,
    loc: Loc,
};

/// Why a package is refused, and at which stage (errors from earlier stages win across a
/// linkage: Rust loads, then validates, then JIT-translates every package of the linkage).
pub const Refusal = struct {
    stage: enum { validate, jit },
    fail: LoadFail,
};

/// What `validate_package` needs: the VM's verifier config (`verifier_config(None)`) and the
/// native function table (`check_natives`).
pub const Validation = struct {
    verifier: vf.Config,
    natives: vf.Natives,
    /// The protocol version this config was derived from (`conformance.validation`). When set,
    /// a package the bytecode verifier accepted under it is recorded in `verified` and every
    /// runtime (any thread, any epoch of that version) skips the verifier for the same bytes.
    /// Null (a hand-built config) always verifies.
    cache_pv: ?u64 = null,

    /// Sui's native table (`all_natives` of 1.84: the same 133 functions for every protocol
    /// version; 1.84 added clock::native_borrow, clock::native_set_timestamp_ms_for_testing and
    /// object::is_shared_input_impl), as "addr64::module::function".
    pub const sui_natives = @embedFile("natives.txt");

    pub fn init(arena: Allocator, verifier: vf.Config) Allocator.Error!Validation {
        var v: Validation = .{ .verifier = verifier, .natives = .empty };
        var it = std.mem.tokenizeScalar(u8, sui_natives, '\n');
        while (it.next()) |line| try v.natives.put(arena, line, {});
        return v;
    }
};

/// Packages the Move bytecode verifier accepted, process-wide: Blake2b256 over the protocol
/// version and the sorted (name, bytes) modules. The verifier's answer is a pure function of
/// those, so a hit skips it (deserialization, the package shape checks and the JIT limits still
/// run). Only acceptances are recorded; a refusal is recomputed (rare, and it keeps the error
/// location exact). Shared by the replay/execute workers and every simulation worker.
pub const VerifiedSet = struct {
    lock: std.atomic.Value(u32) = .init(0),
    set: std.AutoHashMapUnmanaged([32]u8, void) = .empty,
    hits: std.atomic.Value(u64) = .init(0),
    misses: std.atomic.Value(u64) = .init(0),
    /// Bounds the set (32 bytes per entry plus the map's overhead); past it nothing new is
    /// recorded and those packages simply verify again.
    max_entries: usize = 1 << 20,

    fn acquire(v: *VerifiedSet) void {
        while (v.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn release(v: *VerifiedSet) void {
        v.lock.store(0, .release);
    }
    pub fn contains(v: *VerifiedSet, k: *const [32]u8) bool {
        v.acquire();
        defer v.release();
        return v.set.contains(k.*);
    }
    pub fn insert(v: *VerifiedSet, k: *const [32]u8) void {
        v.acquire();
        defer v.release();
        if (v.set.count() >= v.max_entries) return;
        v.set.put(std.heap.smp_allocator, k.*, {}) catch {};
    }
    pub fn count(v: *VerifiedSet) usize {
        v.acquire();
        defer v.release();
        return v.set.count();
    }

    pub fn key(pv: u64, sorted: []const NamedModule) [32]u8 {
        var h = std.crypto.hash.blake2.Blake2b256.init(.{});
        var b8: [8]u8 = undefined;
        std.mem.writeInt(u64, &b8, pv, .little);
        h.update(&b8);
        for (sorted) |m| {
            std.mem.writeInt(u64, &b8, m.name.len, .little);
            h.update(&b8);
            h.update(m.name);
            std.mem.writeInt(u64, &b8, m.bytes.len, .little);
            h.update(&b8);
            h.update(m.bytes);
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
};

/// The process's verified-package set (see `VerifiedSet`). `enabled = false` turns sharing off.
pub var verified: VerifiedSet = .{};
pub var verified_enabled: bool = true;

/// Rust `StatusType` by code range.
fn statusType(code: ff.StatusCode) enum { validation, verification, invariant, deserialization, execution, unknown } {
    const c = @intFromEnum(code);
    return if (c < 1000) .validation else if (c < 2000) .verification else if (c < 3000) .invariant else if (c < 4000) .deserialization else if (c < 5000) .execution else .unknown;
}

/// `expect_no_verification_errors`: deserialization and verification statuses become
/// UNEXPECTED_DESERIALIZATION_ERROR / UNEXPECTED_VERIFIER_ERROR (sub status dropped; location,
/// indices and offsets kept).
pub fn expectNoVerificationErrors(f: LoadFail) LoadFail {
    const major: ff.StatusCode = switch (statusType(f.err.major)) {
        .deserialization => .UNEXPECTED_DESERIALIZATION_ERROR,
        .verification => .UNEXPECTED_VERIFIER_ERROR,
        else => return f,
    };
    var e = f.err;
    e.major = major;
    e.sub_status = null;
    return .{ .err = e, .loc = f.loc };
}

/// JIT `make_arena_type` limits (`TypeSize::for_type_traversal`): 128 nodes, depth 256. Nodes
/// count in preorder, so the node limit always trips before the depth limit (a token deeper
/// than 256 has more than 128 nodes).
const MAX_TYPE_INSTANTIATION_NODES = 128;

fn tokenOverLimit(t: Token) bool {
    return t.len > MAX_TYPE_INSTANTIATION_NODES;
}

/// The JIT's per-token checks over everything `translate_module` converts with
/// `make_arena_type`: datatype fields, the signature pool (parameters, returns, locals,
/// instantiations) and constant types.
fn jitTypesOk(cm: *const ff.CompiledModule) bool {
    for (cm.struct_defs) |sd| for (sd.fields) |f| if (tokenOverLimit(f.signature)) return false;
    for (cm.enum_defs) |ed| for (ed.variants) |v| for (v.fields) |f| if (tokenOverLimit(f.signature)) return false;
    for (cm.signatures) |sig| for (sig) |t| if (tokenOverLimit(t)) return false;
    for (cm.constant_pool) |c| if (tokenOverLimit(c.type_)) return false;
    return true;
}

pub const Runtime = struct {
    gpa: Allocator,
    arena_state: std.heap.ArenaAllocator,
    binary: move_format.BinaryConfig,
    /// Rust's load-time validation; null skips it (deserialization and JIT limits still run).
    validation: ?*const Validation = null,
    /// exec-history-vm: the latest VM's JIT per-token type limits at load. The v0..v3 loaders
    /// have none (`cuts.Rules.legacyVm`): a runtime that serves only those cuts sets this false.
    jit_limits: bool = true,
    by_version: std.AutoHashMapUnmanaged(Address, *Package) = .empty,
    by_original: std.AutoHashMapUnmanaged(Address, std.ArrayList(*Package)) = .empty,

    pub fn init(gpa: Allocator, binary: move_format.BinaryConfig) Runtime {
        return .{ .gpa = gpa, .arena_state = std.heap.ArenaAllocator.init(gpa), .binary = binary };
    }

    pub fn deinit(rt: *Runtime) void {
        var it = rt.by_original.valueIterator();
        while (it.next()) |l| l.deinit(rt.gpa);
        rt.by_original.deinit(rt.gpa);
        rt.by_version.deinit(rt.gpa);
        rt.arena_state.deinit();
    }

    /// A loaded package that is not refused.
    pub fn package(rt: *const Runtime, version_id: *const Address) ?*Package {
        const p = rt.by_version.get(version_id.*) orelse return null;
        return if (p.refused == null) p else null;
    }

    /// Any package added, refused or not.
    pub fn entry(rt: *const Runtime, version_id: *const Address) ?*Package {
        return rt.by_version.get(version_id.*);
    }

    /// Loads a package (bytes must outlive the runtime). Idempotent per version id. A package
    /// Rust would refuse is kept with `refused` set (the outcome is deterministic, so keeping it
    /// is the same as Rust retrying it on every make_vm); `package` does not return it.
    ///
    /// With `validation` set this is Rust's `validate_package` (deserialize with the package
    /// checks, the bytecode verifier, native checks) followed by the JIT's type limits;
    /// without it only deserialization, the JIT limits and constant decoding run.
    pub fn addPackage(rt: *Runtime, in: PackageInput) LoadError!*Package {
        if (rt.by_version.get(in.version_id)) |p| return p;
        const arena = rt.arena_state.allocator();
        const p = try arena.create(Package);
        p.* = .{
            .rt = rt,
            .version_id = in.version_id,
            .original_id = in.original_id,
            .version = in.version,
            .linkage = try arena.dupe([2]Address, in.linkage),
            .type_origins = try arena.dupe(TypeOrigin, in.type_origins),
            .modules = &.{},
        };
        try rt.by_version.put(rt.gpa, in.version_id, p);
        const sorted = try arena.dupe(NamedModule, in.modules);
        std.mem.sort(NamedModule, sorted, {}, struct {
            fn lt(_: void, a: NamedModule, b: NamedModule) bool {
                return std.mem.order(u8, a.name, b.name) == .lt;
            }
        }.lt);
        const cms = try arena.alloc(ff.CompiledModule, sorted.len);
        if (try rt.validate(p, sorted, cms)) |r| {
            p.refused = r;
            return p;
        }
        // JIT translation: per-token type limits, then constant decoding (which the verifier
        // already guarantees when validation runs).
        for (cms) |*cm| if (rt.jit_limits and !jitTypesOk(cm)) {
            p.refused = .{ .stage = .jit, .fail = .{ .err = ff.PartialVmError.new(.VM_MAX_TYPE_NODES_REACHED), .loc = .{ .package = in.version_id } } };
            return p;
        };
        const mods = try arena.alloc(Module, sorted.len);
        for (sorted, cms, mods) |nm, cm, *m| {
            _ = nm;
            initModule(arena, p, m, cm) catch |e| switch (e) {
                error.BadConstant => {
                    p.refused = .{ .stage = .jit, .fail = .{ .err = ff.PartialVmError.new(.VERIFIER_INVARIANT_VIOLATION), .loc = .{ .package = in.version_id } } };
                    return p;
                },
                else => |x| return x,
            };
        }
        p.modules = mods;
        // Same-package call targets need every module of the package.
        for (mods) |*m| try linkLocalCalls(m);
        const gop = try rt.by_original.getOrPut(rt.gpa, in.original_id);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(rt.gpa, p);
        return p;
    }

    /// `deserialization::translate::package` then `verification::translate::package`, with
    /// the errors as `expect_no_verification_errors` reports them. Fills `cms`.
    fn validate(rt: *Runtime, p: *const Package, sorted: []const NamedModule, cms: []ff.CompiledModule) LoadError!?Refusal {
        const arena = rt.arena_state.allocator();
        const vid = p.version_id;
        const at_pkg: Loc = .{ .package = vid };
        const refuse = struct {
            fn f(err: ff.PartialVmError, loc: Loc) Refusal {
                return .{ .stage = .validate, .fail = expectNoVerificationErrors(.{ .err = err, .loc = loc }) };
            }
        }.f;
        for (sorted, cms, 0..) |nm, *cm, i| {
            cm.* = switch (try move_format.deserialize(arena, nm.bytes, &rt.binary)) {
                .ok => |x| x,
                .err => |e| return refuse(e, at_pkg),
            };
            if (rt.validation == null) continue;
            if (!std.mem.eql(u8, nm.name, cm.selfName()))
                return refuse(ff.PartialVmError.new(.UNKNOWN_INVARIANT_VIOLATION_ERROR), at_pkg);
            if (!std.mem.eql(u8, cm.selfAddress(), &p.original_id))
                return refuse(ff.verificationError(.MISMATCHED_MODULE_IDS_IN_PACKAGE, .AddressIdentifier, cm.self_module_handle_idx), at_pkg);
            if (i > 0 and std.mem.eql(u8, sorted[i - 1].name, nm.name))
                return refuse(ff.PartialVmError.new(.DUPLICATE_MODULE_NAME), at_pkg);
        }
        const val = rt.validation orelse return null;
        if (sorted.len == 0) return refuse(ff.PartialVmError.new(.EMPTY_PACKAGE), at_pkg);
        const vkey: ?[32]u8 = if (verified_enabled) if (val.cache_pv) |pv| VerifiedSet.key(pv, sorted) else null else null;
        if (vkey) |k| if (verified.contains(&k)) {
            _ = verified.hits.fetchAdd(1, .monotonic);
            return null;
        };
        var scratch = std.heap.ArenaAllocator.init(rt.gpa);
        defer scratch.deinit();
        var tmp = std.heap.ArenaAllocator.init(rt.gpa);
        defer tmp.deinit();
        for (cms) |*cm| {
            _ = tmp.reset(.retain_capacity);
            // The Sui passes that verifyModule runs after the Move verifier are not part of
            // the load path; only the Move result is used.
            const r = try vf.verifyModule(tmp.allocator(), &scratch, &val.verifier, cm, &val.natives);
            if (r.move) |e| {
                const loc: Loc = switch (e.loc) {
                    .undefined => .undefined,
                    .package => at_pkg,
                    .module => |name| .{ .module = .{ .addr = cm.selfAddress().*, .name = try arena.dupe(u8, name) } },
                };
                return refuse(e.err, loc);
            }
        }
        if (vkey) |k| {
            _ = verified.misses.fetchAdd(1, .monotonic);
            verified.insert(&k);
        }
        return null;
    }

    /// Rust `make_vm`'s package loading for a linkage table (original id, version id): the
    /// first missing package (LINKER_ERROR, in version-id order), else the first package
    /// refused while validating, else the first refused by the JIT, else (shape checks of
    /// `validate_against_link_context`) null.
    pub fn checkLinkage(rt: *const Runtime, linkage: []const [2]Address) Allocator.Error!?LoadFail {
        var ids: std.ArrayList(Address) = .empty;
        defer ids.deinit(rt.gpa);
        for (linkage) |l| try ids.append(rt.gpa, l[1]);
        std.mem.sort(Address, ids.items, {}, struct {
            fn lt(_: void, a: Address, b: Address) bool {
                return std.mem.order(u8, &a, &b) == .lt;
            }
        }.lt);
        for (ids.items) |*id| if (rt.by_version.get(id.*) == null)
            return expectNoVerificationErrors(.{ .err = ff.PartialVmError.new(.LINKER_ERROR), .loc = .{ .package = id.* } });
        inline for (.{ .validate, .jit }) |stage| {
            for (ids.items) |*id| {
                const p = rt.by_version.get(id.*).?;
                if (p.refused) |r| if (r.stage == stage) return r.fail;
            }
        }
        // validate_against_link_context: every package is linked under its own original id.
        for (linkage) |l| {
            const p = rt.by_version.get(l[1]).?;
            if (!std.mem.eql(u8, &p.original_id, &l[0]))
                return .{ .err = ff.PartialVmError.new(.UNKNOWN_INVARIANT_VIOLATION_ERROR), .loc = .undefined };
        }
        return null;
    }

    /// Forgets a package a transaction published or upgraded (Rust keeps such packages in a
    /// per-transaction store; the committed object is loaded from storage like any other).
    /// Its memory stays in the runtime arena; pointers into it remain valid.
    pub fn removePackage(rt: *Runtime, version_id: *const Address) void {
        const kv = rt.by_version.fetchRemove(version_id.*) orelse return;
        const list = rt.by_original.getPtr(kv.value.original_id) orelse return;
        for (list.items, 0..) |x, i| if (x == kv.value) {
            _ = list.orderedRemove(i);
            break;
        };
    }

    /// A datatype by runtime (original) address, module and name, from any loaded version.
    pub fn findDatatype(rt: *Runtime, addr: *const Address, module_name: []const u8, name: []const u8) LoadError!*Datatype {
        const list = rt.by_original.get(addr.*) orelse return error.LinkageMissing;
        for (list.items) |p| {
            const m = p.module(module_name) orelse continue;
            for (m.structs) |*d| if (std.mem.eql(u8, d.name, name)) return d;
            for (m.enums) |*d| if (std.mem.eql(u8, d.name, name)) return d;
        }
        return error.DatatypeMissing;
    }

    /// A datatype from a type tag address (the defining id) via the type origin tables.
    pub fn datatypeByDefiningId(rt: *Runtime, defining: *const Address, module_name: []const u8, name: []const u8) LoadError!*Datatype {
        var it = rt.by_version.valueIterator();
        while (it.next()) |pp| {
            const p = pp.*;
            for (p.type_origins) |o| {
                if (std.mem.eql(u8, &o.defining, defining) and std.mem.eql(u8, o.module, module_name) and std.mem.eql(u8, o.name, name))
                    return rt.findDatatype(&p.original_id, module_name, name);
            }
        }
        return error.DatatypeMissing;
    }
};

fn initModule(arena: Allocator, p: *Package, m: *Module, cm: ff.CompiledModule) LoadError!void {
    m.* = .{
        .pkg = p,
        .name = cm.selfName(),
        .cm = cm,
        .functions = try arena.alloc(Function, cm.function_defs.len),
        .structs = try arena.alloc(Datatype, cm.struct_defs.len),
        .enums = try arena.alloc(Datatype, cm.enum_defs.len),
        .constants = try arena.alloc(Constant, cm.constant_pool.len),
        .dt_handles = try arena.alloc(?*Datatype, cm.datatype_handles.len),
        .local_calls = try arena.alloc(?*Function, cm.function_handles.len),
    };
    @memset(m.dt_handles, null);
    @memset(m.local_calls, null);
    for (cm.struct_defs, m.structs, 0..) |sd, *d, i| {
        const h = cm.datatype_handles[sd.struct_handle];
        d.* = .{ .module = m, .name = cm.identifiers[h.name], .def_idx = @intCast(i), .is_enum = false, .n_type_params = @intCast(h.type_parameters.len), .defining_id = definingId(p, m.name, cm.identifiers[h.name]), .fields = sd.fields };
        d.plain = .{ .datatype = .{ .dt = d, .args = &.{} } };
        // a struct's own handle resolves to itself
        m.dt_handles[sd.struct_handle] = d;
    }
    for (cm.enum_defs, m.enums, 0..) |ed, *d, i| {
        const h = cm.datatype_handles[ed.enum_handle];
        d.* = .{ .module = m, .name = cm.identifiers[h.name], .def_idx = @intCast(i), .is_enum = true, .n_type_params = @intCast(h.type_parameters.len), .defining_id = definingId(p, m.name, cm.identifiers[h.name]), .variants = ed.variants };
        d.plain = .{ .datatype = .{ .dt = d, .args = &.{} } };
        m.dt_handles[ed.enum_handle] = d;
    }
    for (cm.function_defs, m.functions, 0..) |fd, *f, i| {
        const h = cm.function_handles[fd.function];
        const params = cm.signatures[h.parameters];
        var n_locals: usize = params.len;
        if (fd.code) |c| n_locals += cm.signatures[c.locals].len;
        f.* = .{
            .module = m,
            .def_idx = @intCast(i),
            .name = cm.identifiers[h.name],
            .is_native = fd.code == null,
            .code = if (fd.code) |c| c.code else &.{},
            .jump_tables = if (fd.code) |c| c.jump_tables else &.{},
            .params = params,
            .locals = if (fd.code) |c| cm.signatures[c.locals] else &.{},
            .returns = cm.signatures[h.return_],
            .n_locals = @intCast(n_locals),
            .n_type_params = @intCast(h.type_parameters.len),
        };
    }
    const heap = value.Heap{ .arena = arena };
    const plain = gas.SizeCfg{ .traverse_references = false, .include_vector_size = true };
    for (cm.constant_pool, m.constants) |c, *k| {
        var r = Reader{ .bytes = c.data };
        const v = constValue(heap, c.type_, &r) catch return error.BadConstant;
        if (r.pos != r.bytes.len) return error.BadConstant;
        k.* = .{ .value = v, .abstract_size = value.size(v, plain), .byte_len = c.data.len };
    }
}

fn definingId(p: *const Package, module_name: []const u8, name: []const u8) Address {
    for (p.type_origins) |o| {
        if (std.mem.eql(u8, o.module, module_name) and std.mem.eql(u8, o.name, name)) return o.defining;
    }
    return p.original_id;
}

fn linkLocalCalls(m: *Module) LoadError!void {
    const self_addr = m.cm.selfAddress();
    for (m.cm.function_handles, m.local_calls) |h, *t| {
        if (!std.mem.eql(u8, m.moduleHandleAddress(h.module), self_addr)) continue;
        const target = m.pkg.module(m.moduleHandleName(h.module)) orelse return error.ModuleMissing;
        t.* = target.functionByName(m.cm.identifiers[h.name]) orelse return error.FunctionMissing;
    }
}

// ---------------------------------------------------------------------------------------------
// BCS reading for constants and arguments

pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn take(r: *Reader, n: usize) error{EndOfInput}![]const u8 {
        if (r.bytes.len - r.pos < n) return error.EndOfInput;
        defer r.pos += n;
        return r.bytes[r.pos..][0..n];
    }
    pub fn byte(r: *Reader) error{EndOfInput}!u8 {
        return (try r.take(1))[0];
    }
    pub fn uleb(r: *Reader) error{ EndOfInput, BadUleb }!u64 {
        var x: u64 = 0;
        var shift: u6 = 0;
        while (true) {
            const b = try r.byte();
            x |= @as(u64, b & 0x7f) << shift;
            if (b & 0x80 == 0) {
                if (b == 0 and shift > 0) return error.BadUleb;
                if (x > std.math.maxInt(u32)) return error.BadUleb;
                return x;
            }
            if (shift >= 28) return error.BadUleb;
            shift += 7;
        }
    }
};

pub const DecodeError = error{ EndOfInput, BadUleb, BadBool, BadTag, TooDeep } || Allocator.Error || LoadError;

/// Constant values: primitive types and vectors of them only (`constant_sig_token_to_layout`).
fn constValue(h: value.Heap, t: Token, r: *Reader) DecodeError!Value {
    return switch (t[0].tag) {
        .Vector => blk: {
            const n = try r.uleb();
            const elem = t[1..];
            // Every element takes at least one byte: check before allocating `n` slots.
            if (n > r.bytes.len - r.pos) return error.EndOfInput;
            if (tokenVecKind(elem)) |k| if (k != .vec) {
                const bytes = try r.take(n * k.width());
                const c = try h.newContainer(k, n);
                if (k == .vec_bool) for (bytes) |b| if (b > 1) return error.BadBool;
                @memcpy(c.bytes(), bytes);
                break :blk Value.container(c);
            };
            const c = try h.newContainer(.vec, n);
            for (c.values()) |*v| v.* = try constValue(h, elem, r);
            break :blk Value.container(c);
        },
        else => primValue(h, (primType(t[0].tag) orelse return error.BadTag).*, r),
    };
}

pub fn primValue(h: value.Heap, t: Type, r: *Reader) DecodeError!Value {
    return switch (t) {
        .bool => blk: {
            const b = try r.byte();
            if (b > 1) return error.BadBool;
            break :blk Value.bool_(b == 1);
        },
        .u8 => Value.u8_(try r.byte()),
        .u16 => Value.u16_(std.mem.readInt(u16, (try r.take(2))[0..2], .little)),
        .u32 => Value.u32_(std.mem.readInt(u32, (try r.take(4))[0..4], .little)),
        .u64 => Value.u64_(std.mem.readInt(u64, (try r.take(8))[0..8], .little)),
        .u128 => Value.u128_(std.mem.readInt(u128, (try r.take(16))[0..16], .little)),
        .u256 => Value.boxed(.u256, try h.box32((try r.take(32))[0..32].*)),
        .address => Value.boxed(.address, try h.box32((try r.take(32))[0..32].*)),
        .signer => try h.pack(.struct_, 0, &.{Value.boxed(.address, try h.box32((try r.take(32))[0..32].*))}),
        else => error.BadTag,
    };
}

test "a huge vector length fails on the input, not the allocator" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const h = value.Heap{ .arena = arena_state.allocator() };
    const tok = [_]ff.Node{ .{ .tag = .Vector }, .{ .tag = .U64 } };
    var r = Reader{ .bytes = &.{ 0xff, 0xff, 0xff, 0xff, 0x0f } };
    try std.testing.expectError(error.EndOfInput, constValue(h, &tok, &r));
}

test "reader uleb" {
    var r = Reader{ .bytes = &.{ 0x80, 0x01 } };
    try std.testing.expectEqual(@as(u64, 128), try r.uleb());
}
