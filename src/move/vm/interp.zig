//! The interpreter: move-vm-runtime 1.83 `execution/interpreter` (eval.rs, state.rs) with the
//! Sui gas meter, instruction for instruction.
//!
//! Every charge happens at the same point and with the same arguments as in Rust, so gas left,
//! instruction counts, stack height and stack size (with their high-water marks) match, also on
//! the failing paths (out of gas in the middle of a call, errors after a charge).
const std = @import("std");
const move_format = @import("move_format");
const protocol = @import("protocol");
const loader = @import("loader.zig");
const value = @import("value.zig");
const types = @import("types.zig");
const gas = @import("gas.zig");
const trace = @import("trace.zig");
const profile = @import("profile.zig");
const loopaccel = @import("loopaccel.zig"); // loop accelerator hook, see stepRun

const Allocator = std.mem.Allocator;
const ff = move_format.file_format;
const StatusCode = move_format.StatusCode;
const Value = value.Value;
const Type = loader.Type;
const Function = loader.Function;
const Module = loader.Module;
const Datatype = loader.Datatype;

pub const OPERAND_STACK_SIZE_LIMIT: usize = 1024;
pub const CALL_STACK_SIZE_LIMIT: usize = 1024;

/// Vector operation sub-statuses (`NFE_VECTOR_ERROR_BASE` = 0).
pub const INDEX_OUT_OF_BOUNDS: u64 = 1;
pub const POP_EMPTY_VEC: u64 = 2;
pub const VEC_UNPACK_PARITY_MISMATCH: u64 = 3;
pub const VEC_SIZE_LIMIT_REACHED: u64 = 4;
/// `MAX_TYPE_INSTANTIATION_NODES`: cap on the nodes of every type built by substitution.
pub const MAX_TYPE_INSTANTIATION_NODES: u64 = 128;

/// The VM limits and flags the runtime takes from the protocol config (`vm_config`).
/// The execution version this VM implements (sui-execution `latest`).
pub const LATEST_EXECUTION_VERSION: u64 = 4;
const cuts = @import("cuts.zig");

pub const ExecConfig = struct {
    vector_len_max: u64,
    max_value_depth: ?u64,
    max_type_nodes: u64,
    ld_const_abstract_size: bool,
    /// exec-history-vm (CONTRACTS 6.6b.2): the per-cut VM rules of the execution version
    /// (`cuts.Rules.of`); latest unless built by `fromProtocolAnyCut`.
    rules: cuts.Rules = .latest,

    /// Only the latest execution (`execution_version` 4, protocol 119 and later on mainnet) is
    /// implemented; older protocol versions are refused (ARCHITECTURE.md, Move VM).
    pub fn fromProtocol(cfg: *const protocol.ProtocolConfig) error{ ProtocolConfigMissing, UnsupportedExecutionVersion }!ExecConfig {
        if ((cfg.execution_version orelse 0) != LATEST_EXECUTION_VERSION) return error.UnsupportedExecutionVersion;
        return .{
            .vector_len_max = try cfg.get("max_move_vector_len"),
            .max_value_depth = cfg.getOpt("max_move_value_depth"),
            .max_type_nodes = cfg.getOpt("max_type_to_layout_nodes") orelse 256, // HISTORICAL_MAX_TYPE_TO_LAYOUT_NODES
            .ld_const_abstract_size = cfg.feature_flags.charge_ld_const_abstract_size,
        };
    }

    /// exec-history-vm: `fromProtocol` for any execution version (v0..v3 run the latest VM with
    /// the cut's `rules`).
    pub fn fromProtocolAnyCut(cfg: *const protocol.ProtocolConfig) error{ProtocolConfigMissing}!ExecConfig {
        return .{
            .vector_len_max = try cfg.get("max_move_vector_len"),
            .max_value_depth = cfg.getOpt("max_move_value_depth"),
            .max_type_nodes = cfg.getOpt("max_type_to_layout_nodes") orelse 256,
            .ld_const_abstract_size = cfg.feature_flags.charge_ld_const_abstract_size,
            .rules = cuts.Rules.of(cfg),
        };
    }
};

/// A finished `VMError`: status, location (module of the frame) and code offset.
pub const VmError = struct {
    major: StatusCode,
    sub: ?u64 = null,
    module: ?*const Module = null,
    off: ?struct { fdef: u16, pc: u16 } = null,
};

/// `finalize_execution_error`: an error with a verification status (1000-1999) raised while
/// executing becomes UNKNOWN_INVARIANT_VIOLATION_ERROR at the same location, without sub
/// status or code offset (Rust finishes a fresh error with the old location only).
pub fn finalizeExecutionError(e: VmError) VmError {
    const c = @intFromEnum(e.major);
    if (c < 1000 or c >= 2000) return e;
    return .{ .major = .UNKNOWN_INVARIANT_VIOLATION_ERROR, .module = e.module };
}

/// Calls resolve across packages through the root package's linkage.
pub const LinkCtx = struct {
    rt: *loader.Runtime,
    root: *loader.Package,
    ext: std.AutoHashMapUnmanaged(Key, *Function) = .empty,
    /// Inline cache in front of `ext`: direct mapped by (module, handle), so a hot cross-package
    /// call site costs one compare instead of a hash lookup. Entries are only ever filled from
    /// `ext`, so they are as valid as it is.
    ic: ?*[IC_SIZE]IcEntry = null,

    const Key = struct { m: *const Module, h: u16 };
    const IC_SIZE = 64;
    const IcEntry = struct { m: ?*const Module = null, h: u16 = 0, f: ?*Function = null };

    inline fn icSlot(m: *const Module, h: u16) usize {
        return ((@intFromPtr(m) >> 6) ^ (@as(usize, h) *% 0x9E37)) & (IC_SIZE - 1);
    }

    pub fn init(rt: *loader.Runtime, root: *loader.Package) LinkCtx {
        return .{ .rt = rt, .root = root };
    }
    pub fn deinit(c: *LinkCtx) void {
        c.ext.deinit(c.rt.gpa);
        if (c.ic) |t| c.rt.gpa.destroy(t);
        c.ic = null;
    }

    pub fn resolve(c: *LinkCtx, m: *Module, fh: u16) loader.LoadError!*Function {
        if (m.local_calls[fh]) |f| return f;
        const si = icSlot(m, fh);
        if (c.ic) |t| {
            const slot = &t[si];
            if (slot.m == m and slot.h == fh) return slot.f.?;
        }
        if (c.ext.get(.{ .m = m, .h = fh })) |f| {
            c.icFill(si, m, fh, f);
            return f;
        }
        const h = m.cm.function_handles[fh];
        const vid = c.root.linked(m.moduleHandleAddress(h.module)) orelse return error.LinkageMissing;
        const p = c.rt.package(&vid) orelse return error.LinkageMissing;
        const tm = p.module(m.moduleHandleName(h.module)) orelse return error.ModuleMissing;
        const f = tm.functionByName(m.cm.identifiers[h.name]) orelse return error.FunctionMissing;
        try c.ext.put(c.rt.gpa, .{ .m = m, .h = fh }, f);
        c.icFill(si, m, fh, f);
        return f;
    }

    /// Fills a cache slot; the table is created on the first miss (short-lived contexts that
    /// never call across packages pay nothing). Failing to allocate just skips the cache.
    fn icFill(c: *LinkCtx, si: usize, m: *const Module, fh: u16, f: *Function) void {
        if (c.ic == null) {
            const t = c.rt.gpa.create([IC_SIZE]IcEntry) catch return;
            t.* = @splat(.{});
            c.ic = t;
        }
        c.ic.?[si] = .{ .m = m, .h = fh, .f = f };
    }

    /// The function `name` of module `module_name` in the root package's linkage.
    pub fn function(c: *LinkCtx, runtime_addr: *const loader.Address, module_name: []const u8, name: []const u8) loader.LoadError!*Function {
        const vid = c.root.linked(runtime_addr) orelse return error.LinkageMissing;
        const p = c.rt.package(&vid) orelse return error.LinkageMissing;
        const m = p.module(module_name) orelse return error.ModuleMissing;
        return m.functionByName(name) orelse error.FunctionMissing;
    }
};

/// Link contexts kept across calls, one per root package version, with what `make_vm` reports
/// for the root's linkage (`Runtime.checkLinkage`). A cache belongs to one thread, like the
/// `LinkCtx`s in it; the Runtime must not gain packages while a cache is in use.
pub const LinkCache = struct {
    gpa: Allocator,
    map: std.AutoHashMapUnmanaged(loader.Address, *Entry) = .empty,

    pub const Entry = struct { link: LinkCtx, fail: ?loader.LoadFail };

    pub fn init(gpa: Allocator) LinkCache {
        return .{ .gpa = gpa };
    }
    pub fn deinit(c: *LinkCache) void {
        var it = c.map.valueIterator();
        while (it.next()) |e| {
            e.*.link.deinit();
            c.gpa.destroy(e.*);
        }
        c.map.deinit(c.gpa);
    }
    pub fn get(c: *LinkCache, rt: *loader.Runtime, root: *loader.Package) Allocator.Error!*Entry {
        const gop = try c.map.getOrPut(c.gpa, root.version_id);
        if (gop.found_existing) return gop.value_ptr.*;
        errdefer _ = c.map.remove(root.version_id);
        const e = try c.gpa.create(Entry);
        e.* = .{ .link = LinkCtx.init(rt, root), .fail = try rt.checkLinkage(root.linkage) };
        gop.value_ptr.* = e;
        return e;
    }
};

pub const Frame = struct {
    func: *const Function,
    pc: u16,
    /// Where this frame's locals, type arguments and node counts start in the LIFO region;
    /// `Ret` releases everything above it.
    mark: Lifo.Mark = .{},
    locals: []Value,
    ty_args: []const *const Type,
    /// `count_type_nodes` of each type argument (saturating above the limit) and their sum.
    ty_nodes: []const u64 = &.{},
    ty_nodes_sum: u64 = 0,
};

pub const Error = error{NativeUnsupported} || loader.LoadError;
pub const StepError = Session.Fail || Error;
/// A compiled function (aot.zig): runs the current frame's instructions from `f.pc` until a
/// call, a return or an error, exactly like `stepRun`, and returns what `stepRun` returns.
pub const AotFn = *const fn (s: *Session, f: *Frame) StepError!bool;

/// Depth formula of a datatype (`DepthFormula`): max(constant, depth(T_i) + c_i).
const Formula = struct {
    terms: []const [2]u64 = &.{}, // (type parameter, factor), sorted by parameter
    constant: u64,

    fn solve(f: Formula, depths: []const u64) ?u64 {
        var d = f.constant;
        for (f.terms) |t| {
            if (t[0] >= depths.len) return null;
            d = @max(d, depths[t[0]] +| t[1]);
        }
        return d;
    }
};

const TypeSize = struct {
    depth: u64 = 0,
    nodes: u64 = 0,
    max_depth: u64,
    max_nodes: u64,

    fn check(ts: *const TypeSize) ?StatusCode {
        if (ts.depth > ts.max_depth) return .VM_MAX_TYPE_DEPTH_REACHED;
        if (ts.nodes > ts.max_nodes) return .VM_MAX_TYPE_NODES_REACHED;
        return null;
    }
};

pub const Outcome = union(enum) {
    ok: []const Value,
    err: VmError,
};

// ---------------------------------------------------------------------------------------------
// Natives (CONTRACTS.md 6.2). The natives lane supplies the table; the interpreter does the
// calling protocol of `call_native_impl` / `call_native_with_args`: pop the arguments, charge
// `charge_native_function_before_execution`, run, charge `charge_native_function` with the
// returns (or none on abort), check the arity, push. Every failure in there is located at the
// native function itself, offset (its definition index, 0).

pub const NativeResult = struct {
    /// Internal gas units the native costs (`NativeResult::cost`).
    cost: u64,
    outcome: union(enum) { ok: []const Value, abort: u64 },
};

pub const NativeContext = struct {
    session: *Session,
    /// The native function being called (its parameter and return tokens).
    func: *const Function,
    /// `NativeContext::gas_budget`: the meter's remaining internal gas when the native started.
    gas_budget: u64,
    /// Opaque per-transaction state of the natives lane (object runtime and the like).
    ext: ?*anyopaque,

    pub fn heap(ctx: *NativeContext) value.Heap {
        return ctx.session.heap;
    }
    pub fn arena(ctx: *NativeContext) Allocator {
        return ctx.session.arena;
    }
    /// Memory for the duration of the call only (released when the native returns).
    pub fn scratch(ctx: *NativeContext) Allocator {
        return ctx.session.lifo.allocator();
    }
    /// A native's `PartialVMError` (status, sub status); the caller attaches the location.
    pub fn fail(ctx: *NativeContext, major: StatusCode, sub: ?u64) error{Vm} {
        ctx.session.pending = .{ .major = major, .sub = sub };
        return error.Vm;
    }
};

/// `data` is the pointer the table returned with the function (an adapter can carry the
/// natives lane's own function there). Returned slices must not alias `args` (they are written
/// over the arguments' stack slots). By-value arguments are owned by the native: it moves them
/// into its results or drops them (`ctx.heap().drop`); returned values must be owned (pool
/// memory), never pointers into the arguments. `error.Vm` is a native `PartialVMError` set with
/// `ctx.fail`: no native charge, located at the native.
pub const NativeFn = *const fn (ctx: *NativeContext, data: ?*const anyopaque, ty_args: []const *const Type, args: []Value) (error{Vm} || loader.LoadError)!NativeResult;

pub const Native = struct { call: NativeFn, data: ?*const anyopaque = null };

pub const NativeTable = struct {
    ctx: ?*const anyopaque = null,
    lookupFn: *const fn (ctx: ?*const anyopaque, addr: *const [32]u8, module: []const u8, func: []const u8) ?Native,
    /// Nonzero: every table with this key resolves every function to the same entry, so a
    /// function keeps its entry (`Function.native_memo`) across sessions. 0: look up per call.
    memo_key: u64 = 0,

    /// By the module's self address (the package's original id), module name and function name.
    pub fn lookup(t: *const NativeTable, addr: *const [32]u8, module: []const u8, func: []const u8) ?Native {
        return t.lookupFn(t.ctx, addr, module, func);
    }
};

/// A last-in-first-out region for frame-scoped memory (locals, type arguments, per-frame node
/// counts) and per-instruction scratch types. Chunks never move, so pointers into a live frame's
/// locals stay valid; a frame's memory is released when it returns, so a session's footprint is
/// bounded by its call depth, not by the number of calls it makes.
pub const Lifo = struct {
    backing: Allocator,
    chunks: std.ArrayList([]u8) = .empty,
    ci: usize = 0,
    off: usize = 0,
    /// Bytes ever reserved from the backing allocator.
    reserved: u64 = 0,
    largest: usize = 0,

    pub const Mark = struct { ci: usize = 0, off: usize = 0 };
    const CHUNK: usize = 64 * 1024;

    pub fn mark(l: *const Lifo) Mark {
        return .{ .ci = l.ci, .off = l.off };
    }
    pub fn reset(l: *Lifo, m: Mark) void {
        l.ci = m.ci;
        l.off = m.off;
    }

    fn bump(l: *Lifo, n: usize, a: usize) Allocator.Error![*]u8 {
        while (true) {
            if (l.ci < l.chunks.items.len) {
                const c = l.chunks.items[l.ci];
                const start = std.mem.alignForward(usize, @intFromPtr(c.ptr) + l.off, a) - @intFromPtr(c.ptr);
                if (start + n <= c.len) {
                    l.off = start + n;
                    return c.ptr + start;
                }
                if (l.ci + 1 < l.chunks.items.len) {
                    l.ci += 1;
                    l.off = 0;
                    continue;
                }
            }
            // Requests past a chunk grow geometrically, so a frame-scoped request that grows
            // from call to call (a native's view of a growing vector) allocates O(log) times.
            const size = if (n + a <= CHUNK) CHUNK else @max(n + a, 2 * l.largest);
            l.largest = @max(l.largest, size);
            const mem = try l.backing.alignedAlloc(u8, .@"16", size);
            l.reserved += size;
            try l.chunks.append(l.backing, mem);
            l.ci = l.chunks.items.len - 1;
            l.off = 0;
        }
    }

    pub fn alloc(l: *Lifo, comptime T: type, n: usize) Allocator.Error![]T {
        if (n == 0) return &.{};
        const p = try l.bump(n * @sizeOf(T), @alignOf(T));
        const t: [*]T = @ptrCast(@alignCast(p));
        return t[0..n];
    }

    pub fn allocator(l: *Lifo) Allocator {
        return .{ .ptr = l, .vtable = &vtable };
    }

    const vtable: Allocator.VTable = .{
        .alloc = vAlloc,
        .resize = Allocator.noResize,
        .remap = Allocator.noRemap,
        .free = Allocator.noFree,
    };

    fn vAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
        const l: *Lifo = @ptrCast(@alignCast(ctx));
        return l.bump(len, alignment.toByteUnits()) catch null;
    }
};

const GenKey = struct { m: *const Module, i: u16 };

pub const Session = struct {
    link: *LinkCtx,
    natives: ?*const NativeTable = null,
    ext: ?*anyopaque = null,
    arena: Allocator,
    heap: value.Heap,
    lifo: *Lifo,
    meter: *gas.Meter,
    cfg: ExecConfig,
    stack: []Value,
    sp: usize = 0,
    frames: std.ArrayList(Frame) = .empty,
    depth_cache: std.AutoHashMapUnmanaged(*const Datatype, Formula) = .empty,
    /// Instantiated type arguments of `CallGeneric` sites that do not depend on the frame
    /// (`Module.gen_concrete`); see `callTypeArgs`.
    gen_cache: std.AutoHashMapUnmanaged(GenKey, []const *const Type) = .empty,
    /// The partial error of the failing operation (status and sub status).
    pending: VmError = .{ .major = .EXECUTED },
    /// Set to trace the run (move-trace-format). Null runs the untraced loop, which has no
    /// tracing code in it.
    tracer: ?*trace.Tracer = null,
    /// exec-history-vm: the pending error leaves without the v0..v3 core-dump remap.
    raw_err: bool = false,
    /// DevInspect<true> only (set by the native host under `Host.arbitrary_calls`): a value on
    /// the operand stack or in a local is not of its declared type. Rust's VM carries such a
    /// value through every instruction that only moves values; the handlers here trust the
    /// declared types, so from this point `taintedLoop` runs and lets nothing else execute.
    tainted: bool = false,
    /// `taintedLoop` stopped at an instruction that is not a move: not modeled.
    taint_stopped: bool = false,
    /// exec-history-vm: set by the host while a child object is mutably borrowed under the
    /// v0..v2 / pre-`minimize_child_object_mutations` rule; told the address every write
    /// instruction writes through (a Value slot or a container header), with `ext`.
    write_hook: ?*const fn (?*anyopaque, usize) void = null,

    pub fn init(arena: Allocator, link: *LinkCtx, meter: *gas.Meter, cfg: ExecConfig) Allocator.Error!Session {
        const pool = try arena.create(value.Pool);
        pool.* = .init(arena);
        const lifo = try arena.create(Lifo);
        lifo.* = .{ .backing = arena };
        // Gas profiler (profile.zig): off unless the thread activated one.
        var prof_tracer: ?*trace.Tracer = null;
        if (profile.active) |p| {
            const t = try arena.create(trace.Tracer);
            t.* = trace.Tracer.init(arena, cfg);
            t.prof = p;
            prof_tracer = t;
        }
        return .{
            .tracer = prof_tracer,
            .link = link,
            .arena = arena,
            .heap = .{ .arena = arena, .pool = pool },
            .lifo = lifo,
            .meter = meter,
            .cfg = cfg,
            .stack = try arena.alloc(Value, OPERAND_STACK_SIZE_LIMIT),
        };
    }

    /// Bytes the session holds for values (pool) and frames (LIFO): its memory high-water mark,
    /// apart from the fixed operand stack and per-datatype caches.
    pub fn reservedBytes(s: *const Session) u64 {
        return s.heap.pool.?.reserved + s.lifo.reserved;
    }

    /// Where frame-scoped and per-instruction types go: the LIFO region, or the arena when
    /// tracing (the tracer keeps type pointers past the frame).
    fn typeAlloc(s: *Session) Allocator {
        return if (s.tracer != null) s.arena else s.lifo.allocator();
    }

    // ---- operand stack -------------------------------------------------------------------

    /// `Tainted`: a native call just pushed a value that is not of its declared type
    /// (`tainted`); raised by `callNative` after the call completed, so that whatever tier ran
    /// the calling frame hands over to `taintedLoop`.
    pub const Fail = error{ Vm, Tainted };

    fn fail(s: *Session, major: StatusCode, sub: ?u64) Fail {
        s.pending = .{ .major = major, .sub = sub };
        return error.Vm;
    }
    fn failAt(s: *Session, f: *const Frame, major: StatusCode, sub: ?u64) Fail {
        s.pending = .{ .major = major, .sub = sub };
        s.atFrame(f);
        return error.Vm;
    }
    fn chargeFail(s: *Session) Fail {
        s.pending = .{ .major = s.meter.err };
        return error.Vm;
    }

    inline fn push(s: *Session, v: Value) Fail!void {
        if (s.sp >= OPERAND_STACK_SIZE_LIMIT) return s.fail(.EXECUTION_STACK_OVERFLOW, null);
        s.stack[s.sp] = v;
        s.sp += 1;
    }
    inline fn pop(s: *Session) Fail!Value {
        if (s.sp == 0) return s.fail(.EMPTY_VALUE_STACK, null);
        s.sp -= 1;
        return s.stack[s.sp];
    }
    fn popN(s: *Session, n: usize) Fail![]Value {
        if (s.sp < n) return s.fail(.EMPTY_VALUE_STACK, null);
        s.sp -= n;
        return s.stack[s.sp..][0..n];
    }

    // ---- instantiation size (MAX_TYPE_INSTANTIATION_NODES) ---------------------------------
    //
    // Rust's `subst` walks the result in preorder with `TypeSize::for_type_traversal` (256 depth,
    // 128 nodes, depth checked first); nodes always run out first, so the only error is
    // VM_MAX_TYPE_NODES_REACHED. The substituted type parameter counts once as itself and again
    // for every node of its argument. `count_type_nodes` counts plain nodes.

    /// Nodes of a runtime type, saturating just above the limit.
    fn typeNodes(t: *const Type) u64 {
        return switch (t.*) {
            .vector, .ref, .mut_ref => |e| 1 + typeNodes(e),
            .datatype => |d| blk: {
                var n: u64 = 1;
                for (d.args) |a| {
                    n += typeNodes(a);
                    if (n > MAX_TYPE_INSTANTIATION_NODES) break;
                }
                break :blk n;
            },
            else => 1,
        };
    }

    /// Nodes `subst` visits for signature token `tok` under the frame's type arguments.
    fn substNodes(tok: ff.Token, ty_nodes: []const u64) u64 {
        var n: u64 = tok.len;
        if (ty_nodes.len == 0) return n;
        for (tok) |nd| if (nd.tag == .TypeParameter and nd.idx < ty_nodes.len) {
            n +|= ty_nodes[nd.idx];
        };
        return n;
    }

    inline fn noteWrite(s: *const Session, addr: usize) void {
        if (s.write_hook) |hk| hk(s.ext, addr);
    }

    /// `finalizeExecutionError`, per cut. exec-history-vm: v0..v3 `maybe_core_dump` turns a
    /// verification status raised inside an instruction into VERIFICATION_ERROR (2006) at the
    /// same module without sub status or offsets; a failed CallGeneric instantiation leaves as is.
    fn finalize(s: *const Session, e: VmError) VmError {
        if (!s.cfg.rules.legacyVm()) return finalizeExecutionError(e);
        const c = @intFromEnum(e.major);
        if (s.raw_err or c < 1000 or c >= 2000) return e;
        return .{ .major = .VERIFICATION_ERROR, .module = e.module };
    }

    inline fn checkSubst(s: *Session, tok: ff.Token, f: *const Frame) Fail!void {
        if (s.cfg.rules.legacyVm()) {
            // exec-history-vm: v0..v3 `instantiate_single_type` substitutes only with type
            // arguments.
            if (f.ty_nodes.len == 0) return;
            return s.checkSubstLegacy(tok, f);
        }
        if (tok.len == 1 and f.ty_nodes.len == 0) return;
        if (substNodes(tok, f.ty_nodes) > MAX_TYPE_INSTANTIATION_NODES) return s.fail(.VM_MAX_TYPE_NODES_REACHED, null);
    }

    /// exec-history-vm: v0..v3 `Loader::subst`: only a datatype instantiation is checked, before
    /// substituting: 1 + the frame's type argument nodes + the template's argument nodes (type
    /// parameters count 1 each) over 128 is TOO_MANY_TYPE_NODES. There is no cap on the result.
    fn checkSubstLegacy(s: *Session, tok: ff.Token, f: *const Frame) Fail!void {
        if (tok[0].tag != .DatatypeInstantiation) return;
        if (f.ty_nodes_sum +| tok.len > MAX_TYPE_INSTANTIATION_NODES) return s.fail(.TOO_MANY_TYPE_NODES, null);
    }

    /// The status of an instantiation over MAX_TYPE_INSTANTIATION_NODES (v0..v3:
    /// TOO_MANY_TYPE_NODES).
    fn nodesStatus(s: *const Session) StatusCode {
        return if (s.cfg.rules.legacyVm()) .TOO_MANY_TYPE_NODES else .VM_MAX_TYPE_NODES_REACHED;
    }

    /// `instantiate_datatype_common`: 1 + template nodes + frame type argument nodes, then subst.
    fn checkDatatypeInst(s: *Session, params: []const ff.Token, f: *const Frame) Fail!void {
        var sum: u64 = 1 +| f.ty_nodes_sum;
        for (params) |t| sum +|= t.len;
        if (sum > MAX_TYPE_INSTANTIATION_NODES) return s.fail(s.nodesStatus(), null);
        if (s.cfg.rules.legacyVm()) {
            for (params) |t| try s.checkSubstLegacy(t, f);
            return;
        }
        for (params) |t| try s.checkSubst(t, f);
    }

    /// `instantiate_generic_function`: subst every argument, then 1 + caller type argument nodes
    /// + instantiated argument nodes.
    fn checkCallInst(s: *Session, sig: []const ff.Token, f: *const Frame) Fail!void {
        var sum: u64 = 1 +| f.ty_nodes_sum;
        const legacy = s.cfg.rules.legacyVm();
        for (sig) |t| {
            const n = substNodes(t, f.ty_nodes);
            if (legacy) {
                try s.checkSubstLegacy(t, f); // exec-history-vm: v0..v3 subst, no per-result cap
            } else if (n > MAX_TYPE_INSTANTIATION_NODES) return s.fail(.VM_MAX_TYPE_NODES_REACHED, null);
            sum +|= n - typeParamCount(t);
        }
        if (sum > MAX_TYPE_INSTANTIATION_NODES) return s.fail(s.nodesStatus(), null);
    }

    fn typeParamCount(tok: ff.Token) u64 {
        var n: u64 = 0;
        for (tok) |nd| n += @intFromBool(nd.tag == .TypeParameter);
        return n;
    }

    // ---- depth checks (check_depth_of_type) -----------------------------------------------

    fn checkDepth(s: *Session, ty: *const Type) (Fail || Error)!void {
        const max = s.cfg.max_value_depth orelse return;
        const mk = s.lifo.mark();
        defer s.lifo.reset(mk);
        _ = try s.depthOf(ty, 0, max);
    }

    fn chk(s: *Session, cur: u64, add: u64, max: u64) Fail!u64 {
        if (cur +| add > max) return s.fail(.VM_MAX_VALUE_DEPTH_REACHED, null);
        return cur +| add;
    }

    fn depthOf(s: *Session, ty: *const Type, cur: u64, max: u64) (Fail || Error)!u64 {
        switch (ty.*) {
            .vector, .ref, .mut_ref => |t| return s.depthOf(t, try s.chk(cur, 1, max), max),
            .datatype => |d| {
                if (d.args.len == 0) {
                    const f = try s.formula(d.dt);
                    return s.chk(cur, f.solve(&.{}) orelse return s.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null), max);
                }
                var buf: [8]u64 = undefined;
                const depths = if (d.args.len <= buf.len) buf[0..d.args.len] else try s.lifo.alloc(u64, d.args.len);
                for (d.args, depths) |a, *o| o.* = try s.depthOf(a, try s.chk(cur, 0, max), max);
                const f = try s.formula(d.dt);
                return s.chk(cur, f.solve(depths) orelse return s.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null), max);
            },
            .param => return s.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null),
            else => return s.chk(cur, 1, max),
        }
    }

    fn formula(s: *Session, dt: *Datatype) (Fail || Error)!Formula {
        var ts = TypeSize{ .max_depth = s.cfg.max_value_depth orelse 128, .max_nodes = s.cfg.max_type_nodes };
        // exec-history-vm: the v0..v3 depth formulas have no type-size limits.
        if (s.cfg.rules.legacyVm()) ts = .{ .max_depth = std.math.maxInt(u64), .max_nodes = std.math.maxInt(u64) };
        return s.formulaDt(dt, &ts);
    }

    fn formulaDt(s: *Session, dt: *Datatype, ts: *TypeSize) (Fail || Error)!Formula {
        if (ts.check()) |e| return s.fail(e, null);
        if (s.depth_cache.get(dt)) |f| return f;
        var parts: std.ArrayList(Formula) = .empty;
        if (dt.is_enum) {
            for (dt.variants) |v| for (v.fields) |f| {
                var i: usize = 0;
                try parts.append(s.arena, try s.formulaTok(dt.module, f.signature, &i, ts));
            };
        } else for (dt.fields) |f| {
            var i: usize = 0;
            try parts.append(s.arena, try s.formulaTok(dt.module, f.signature, &i, ts));
        }
        var f = try s.normalize(parts.items);
        f = try s.addTo(f, 1);
        try s.depth_cache.put(s.arena, dt, f);
        if (ts.check()) |e| return s.fail(e, null);
        return f;
    }

    fn formulaTok(s: *Session, m: *Module, tok: ff.Token, i: *usize, ts: *TypeSize) (Fail || Error)!Formula {
        ts.depth +|= 1;
        ts.nodes +|= 1;
        if (ts.check()) |e| return s.fail(e, null);
        const r = s.formulaTokInner(m, tok, i, ts);
        if (ts.check()) |e| return s.fail(e, null);
        ts.depth -= 1;
        return r;
    }

    fn formulaTokInner(s: *Session, m: *Module, tok: ff.Token, i: *usize, ts: *TypeSize) (Fail || Error)!Formula {
        const n = tok[i.*];
        i.* += 1;
        switch (n.tag) {
            .Vector, .Reference, .MutableReference => {
                const inner = try s.formulaTok(m, tok, i, ts);
                return s.addTo(inner, 1);
            },
            .TypeParameter => {
                const t = try s.arena.alloc([2]u64, 1);
                t[0] = .{ n.idx, 0 };
                return .{ .terms = t, .constant = 0 };
            },
            .Datatype => return s.formulaDt(try m.datatype(n.idx), ts),
            .DatatypeInstantiation => {
                const args = try s.arena.alloc(Formula, n.arity);
                for (args) |*a| a.* = try s.formulaTok(m, tok, i, ts);
                const df = try s.formulaDt(try m.datatype(n.idx), ts);
                // subst: constant plus each term's argument formula shifted by its factor
                var parts: std.ArrayList(Formula) = .empty;
                try parts.append(s.arena, .{ .constant = df.constant });
                for (df.terms) |t| {
                    if (t[0] >= args.len) return s.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null);
                    try parts.append(s.arena, try s.addTo(args[t[0]], t[1]));
                }
                return s.normalize(parts.items);
            },
            else => return .{ .constant = 1 },
        }
    }

    fn addTo(s: *Session, f: Formula, c: u64) Allocator.Error!Formula {
        const t = try s.arena.alloc([2]u64, f.terms.len);
        for (f.terms, t) |a, *b| b.* = .{ a[0], a[1] +| c };
        return .{ .terms = t, .constant = f.constant +| c };
    }

    fn normalize(s: *Session, fs: []const Formula) Allocator.Error!Formula {
        var terms: std.ArrayList([2]u64) = .empty;
        var constant: u64 = 0;
        for (fs) |f| {
            for (f.terms) |t| {
                for (terms.items) |*e| {
                    if (e[0] == t[0]) {
                        e[1] = @max(e[1], t[1]);
                        break;
                    }
                } else try terms.append(s.arena, t);
            }
            constant = @max(constant, f.constant);
        }
        std.mem.sort([2]u64, terms.items, {}, struct {
            fn lt(_: void, a: [2]u64, b: [2]u64) bool {
                return a[0] < b[0];
            }
        }.lt);
        return .{ .terms = terms.items, .constant = constant };
    }

    // ---- entry ---------------------------------------------------------------------------

    /// Runs `func` with `args` as its first locals (`execute_function_bypass_visibility`).
    /// Return values are the operand stack at the end.
    pub fn run(s: *Session, func: *const Function, ty_args: []const *const Type, args: []const Value) Error!Outcome {
        if (func.is_native) return s.runNative(func, ty_args, args);
        if (args.len != func.params.len) return .{ .err = .{ .major = .NUMBER_OF_ARGUMENTS_MISMATCH, .module = func.module } };
        if (s.tracer) |t| try t.enterInitialFrame(s, func, ty_args, args);
        const mk = s.lifo.mark();
        const locals = try s.lifo.alloc(Value, func.n_locals);
        @memcpy(locals[0..args.len], args);
        @memset(locals[args.len..], Value.invalid);
        s.frames.clearRetainingCapacity();
        try s.frames.append(s.arena, try s.newFrame(func, locals, ty_args, mk));
        s.sp = 0;
        return if (s.tracer != null) s.loop(true) else s.loop(false);
    }

    /// A native as the outermost function (`interpreter::run` → `call_native_with_args`):
    /// no call charge, errors at (function, 0) in its module.
    fn runNative(s: *Session, func: *const Function, ty_args: []const *const Type, args: []const Value) Error!Outcome {
        if (s.tracer) |t| if (t.prof == null) return error.NativeUnsupported;
        const table = s.natives orelse return error.NativeUnsupported;
        const m = func.module;
        const nf = table.lookup(&m.pkg.original_id, m.name, func.name) orelse return error.NativeUnsupported;
        const at: VmError = .{ .major = .EMPTY_VALUE_STACK, .module = m, .off = .{ .fdef = func.def_idx, .pc = 0 } };
        if (args.len != func.params.len) return .{ .err = at };
        s.frames.clearRetainingCapacity();
        s.sp = 0;
        for (args) |a| s.push(a) catch return .{ .err = s.finalize(s.pending) };
        s.nativeCall(nf, func, ty_args) catch |e| switch (e) {
            error.Vm => {
                s.pending.module = m;
                s.pending.off = at.off;
                return .{ .err = s.finalize(s.pending) };
            },
            // only `callNative` (a native called by bytecode) raises it
            error.Tainted => unreachable,
            else => |x| return x,
        };
        return .{ .ok = s.stack[0..s.sp] };
    }

    fn loop(s: *Session, comptime traced: bool) Error!Outcome {
        while (true) {
            const r = (if (traced) s.step(true) else s.stepRun()) catch |e| switch (e) {
                error.Vm => return .{ .err = s.finalize(s.pending) },
                error.Tainted => return s.taintedLoop(traced),
                else => |x| return x,
            };
            if (r) return .{ .ok = s.stack[0..s.sp] };
        }
    }

    /// The rest of a run once a value that is not of its declared type is live (`tainted`). Rust's
    /// interpreter keeps running: its values carry their own kind, an instruction that only
    /// moves a value never looks at it, and the charges of those instructions come from the
    /// value as it is. The same instructions here read only the value's own tag (`Ret`, `Pop`,
    /// `StLoc`, `MoveLoc`, `CopyLoc`, `Branch`, `Nop`), so they run through `step` unchanged,
    /// with their charges. Anything else may read the value by its declared type: the run stops
    /// (`taint_stopped`, `error.NativeUnsupported`). The framework's callers of the natives that
    /// can return such a value return it straight to their own caller.
    fn taintedLoop(s: *Session, comptime traced: bool) Error!Outcome {
        while (true) {
            const f = &s.frames.items[s.frames.items.len - 1];
            const moves_only = f.pc < f.func.code.len and switch (f.func.code[f.pc].op) {
                .Ret, .Pop, .StLoc, .MoveLoc, .CopyLoc, .Branch, .Nop => true,
                else => false,
            };
            if (!moves_only) {
                s.taint_stopped = true;
                return error.NativeUnsupported;
            }
            const r = s.step(traced) catch |e| switch (e) {
                error.Vm => return .{ .err = s.finalize(s.pending) },
                // no instruction of the set calls a native
                error.Tainted => continue,
                else => |x| return x,
            };
            if (r) return .{ .ok = s.stack[0..s.sp] };
        }
    }

    pub fn atFrame(s: *Session, f: *const Frame) void {
        s.pending.module = f.func.module;
        s.pending.off = .{ .fdef = f.func.def_idx, .pc = f.pc };
    }

    /// Untraced: runs the current frame's instructions until a call or return (handled by
    /// `step`), with the frame and its code held across instructions. Same effects as `step`
    /// per instruction.
    ///
    /// Threaded dispatch: a labeled switch where each hot handler ends in its own indirect jump
    /// to the next instruction's handler (`continue :sw`), so the branch predictor sees one
    /// jump site per opcode instead of one shared site. Hot handlers are fast paths over inline
    /// (non-boxed) values: each one checks everything it needs BEFORE any side effect (stack
    /// depth, operand tags, overflow) and otherwise leaves the instruction to `op`, which does
    /// the full work, so charges, results and errors are those of `op`.
    fn stepRun(s: *Session) (Fail || Error)!bool {
        const f = &s.frames.items[s.frames.items.len - 1];
        // aot tier: compiled code for this function runs the same instructions (see aot.zig)
        if (f.func.aot) |a| return @as(AotFn, @ptrCast(@alignCast(a)))(s, f);
        // loop accelerator hook: a function with a loop accelerator attached runs through loopaccel.run
        // (off unless loopaccel.enable() or ZUI_VM_LOOPACCEL=1; nothing else in this file knows about it)
        if (f.func.accel != null and loopaccel.live()) return loopaccel.run(s, f);
        const code = f.func.code;
        const meter = s.meter;
        // the pc lives in a register here; the frame gets it before every instruction (stores
        // only: error locations and `step` read it there)
        var pc = f.pc;
        while (true) {
            f.pc = pc;
            if (pc >= code.len) return s.step(false);
            sw: switch (code[pc].op) {
                .Ret, .Call, .CallGeneric => return s.step(false),
                .LdU8 => if (s.sp < OPERAND_STACK_SIZE_LIMIT) {
                    meter.chargeSimple(.LdU8) catch return s.atErr(f, s.chargeFail());
                    s.stack[s.sp] = Value.u8_(@intCast(code[pc].imm));
                    s.sp += 1;
                    pc += 1;
                    f.pc = pc;
                    if (pc >= code.len) return s.step(false);
                    continue :sw code[pc].op;
                } else break :sw,
                .LdU16 => if (s.sp < OPERAND_STACK_SIZE_LIMIT) {
                    meter.chargeSimple(.LdU16) catch return s.atErr(f, s.chargeFail());
                    s.stack[s.sp] = Value.u16_(@intCast(code[pc].imm));
                    s.sp += 1;
                    pc += 1;
                    f.pc = pc;
                    if (pc >= code.len) return s.step(false);
                    continue :sw code[pc].op;
                } else break :sw,
                .LdU32 => if (s.sp < OPERAND_STACK_SIZE_LIMIT) {
                    meter.chargeSimple(.LdU32) catch return s.atErr(f, s.chargeFail());
                    s.stack[s.sp] = Value.u32_(@intCast(code[pc].imm));
                    s.sp += 1;
                    pc += 1;
                    f.pc = pc;
                    if (pc >= code.len) return s.step(false);
                    continue :sw code[pc].op;
                } else break :sw,
                .LdU64 => if (s.sp < OPERAND_STACK_SIZE_LIMIT) {
                    meter.chargeSimple(.LdU64) catch return s.atErr(f, s.chargeFail());
                    s.stack[s.sp] = Value.u64_(code[pc].imm);
                    s.sp += 1;
                    pc += 1;
                    f.pc = pc;
                    if (pc >= code.len) return s.step(false);
                    continue :sw code[pc].op;
                } else break :sw,
                .LdTrue => if (s.sp < OPERAND_STACK_SIZE_LIMIT) {
                    meter.chargeSimple(.LdTrue) catch return s.atErr(f, s.chargeFail());
                    s.stack[s.sp] = Value.bool_(true);
                    s.sp += 1;
                    pc += 1;
                    f.pc = pc;
                    if (pc >= code.len) return s.step(false);
                    continue :sw code[pc].op;
                } else break :sw,
                .LdFalse => if (s.sp < OPERAND_STACK_SIZE_LIMIT) {
                    meter.chargeSimple(.LdFalse) catch return s.atErr(f, s.chargeFail());
                    s.stack[s.sp] = Value.bool_(false);
                    s.sp += 1;
                    pc += 1;
                    f.pc = pc;
                    if (pc >= code.len) return s.step(false);
                    continue :sw code[pc].op;
                } else break :sw,
                .CopyLoc => {
                    const v = f.locals[code[pc].idx];
                    if (isInline(v.tag) and s.sp < OPERAND_STACK_SIZE_LIMIT) {
                        meter.chargeCopyLoc(value.size(v, meter.plain)) catch return s.atErr(f, s.chargeFail());
                        s.stack[s.sp] = v;
                        s.sp += 1;
                        pc += 1;
                        f.pc = pc;
                        if (pc >= code.len) return s.step(false);
                        continue :sw code[pc].op;
                    } else break :sw;
                },
                .MoveLoc => {
                    const v = f.locals[code[pc].idx];
                    if (v.tag != .invalid and s.sp < OPERAND_STACK_SIZE_LIMIT) {
                        f.locals[code[pc].idx] = Value.invalid;
                        const sz = if (meter.moveLocNeedsSize()) value.size(v, meter.plain) else 0;
                        meter.chargeMoveLoc(sz) catch return s.atErr(f, s.chargeFail());
                        s.stack[s.sp] = v;
                        s.sp += 1;
                        pc += 1;
                        f.pc = pc;
                        if (pc >= code.len) return s.step(false);
                        continue :sw code[pc].op;
                    } else break :sw;
                },
                .StLoc => {
                    if (s.sp > 0 and isInlineOrInvalid(f.locals[code[pc].idx].tag)) {
                        s.sp -= 1;
                        const v = s.stack[s.sp];
                        meter.chargeStoreLoc() catch return s.atErr(f, s.chargeFail());
                        f.locals[code[pc].idx] = v;
                        pc += 1;
                        f.pc = pc;
                        if (pc >= code.len) return s.step(false);
                        continue :sw code[pc].op;
                    } else break :sw;
                },
                .Pop => {
                    if (s.sp > 0 and isInlineOrInvalid(s.stack[s.sp - 1].tag)) {
                        s.sp -= 1;
                        meter.chargePop() catch return s.atErr(f, s.chargeFail());
                        pc += 1;
                        f.pc = pc;
                        if (pc >= code.len) return s.step(false);
                        continue :sw code[pc].op;
                    } else break :sw;
                },
                .ImmBorrowLoc => if (s.sp < OPERAND_STACK_SIZE_LIMIT) {
                    meter.chargeSimple(.ImmBorrowLoc) catch return s.atErr(f, s.chargeFail());
                    s.stack[s.sp] = Value.refSlot(&f.locals[code[pc].idx]);
                    s.sp += 1;
                    pc += 1;
                    f.pc = pc;
                    if (pc >= code.len) return s.step(false);
                    continue :sw code[pc].op;
                } else break :sw,
                .MutBorrowLoc => if (s.sp < OPERAND_STACK_SIZE_LIMIT) {
                    meter.chargeSimple(.MutBorrowLoc) catch return s.atErr(f, s.chargeFail());
                    s.stack[s.sp] = Value.refSlot(&f.locals[code[pc].idx]);
                    s.sp += 1;
                    pc += 1;
                    f.pc = pc;
                    if (pc >= code.len) return s.step(false);
                    continue :sw code[pc].op;
                } else break :sw,
                .BrTrue => {
                    if (s.sp > 0 and s.stack[s.sp - 1].tag == .bool) {
                        meter.chargeSimple(.BrTrue) catch return s.atErr(f, s.chargeFail());
                        s.sp -= 1;
                        pc = if (s.stack[s.sp].a != 0) code[pc].idx else pc + 1;
                        f.pc = pc;
                        if (pc >= code.len) return s.step(false);
                        continue :sw code[pc].op;
                    } else break :sw;
                },
                .BrFalse => {
                    if (s.sp > 0 and s.stack[s.sp - 1].tag == .bool) {
                        meter.chargeSimple(.BrFalse) catch return s.atErr(f, s.chargeFail());
                        s.sp -= 1;
                        pc = if (s.stack[s.sp].a == 0) code[pc].idx else pc + 1;
                        f.pc = pc;
                        if (pc >= code.len) return s.step(false);
                        continue :sw code[pc].op;
                    } else break :sw;
                },
                .Branch => {
                    meter.chargeSimple(.Branch) catch return s.atErr(f, s.chargeFail());
                    pc = code[pc].idx;
                    f.pc = pc;
                    if (pc >= code.len) return s.step(false);
                    continue :sw code[pc].op;
                },
                .Not => {
                    if (s.sp > 0 and s.stack[s.sp - 1].tag == .bool) {
                        meter.chargeSimple(.Not) catch return s.atErr(f, s.chargeFail());
                        const t = &s.stack[s.sp - 1];
                        t.a = @intFromBool(t.a == 0);
                        pc += 1;
                        f.pc = pc;
                        if (pc >= code.len) return s.step(false);
                        continue :sw code[pc].op;
                    } else break :sw;
                },
                inline .Add, .Sub, .Mul, .Div, .Mod, .BitOr, .BitAnd, .Xor => |o| {
                    const k = comptime switch (o) {
                        .Add => Arith.add,
                        .Sub => Arith.sub,
                        .Mul => Arith.mul,
                        .Div => Arith.div,
                        .Mod => Arith.mod,
                        .BitOr => Arith.bor,
                        .BitAnd => Arith.band,
                        else => Arith.xor,
                    };
                    if (s.fastArith(k)) |r| {
                        meter.chargeSimple(@field(gas.Meter.Simple, @tagName(o))) catch return s.atErr(f, s.chargeFail());
                        s.sp -= 1;
                        s.stack[s.sp - 1].a = r;
                        pc += 1;
                        f.pc = pc;
                        if (pc >= code.len) return s.step(false);
                        continue :sw code[pc].op;
                    } else break :sw;
                },
                inline .Lt, .Gt, .Le, .Ge => |o| {
                    const k = comptime switch (o) {
                        .Lt => Cmp.lt,
                        .Gt => Cmp.gt,
                        .Le => Cmp.le,
                        else => Cmp.ge,
                    };
                    if (s.fastCmp(k)) |r| {
                        meter.chargeSimple(@field(gas.Meter.Simple, @tagName(o))) catch return s.atErr(f, s.chargeFail());
                        s.sp -= 1;
                        s.stack[s.sp - 1] = Value.bool_(r);
                        pc += 1;
                        f.pc = pc;
                        if (pc >= code.len) return s.step(false);
                        continue :sw code[pc].op;
                    } else break :sw;
                },
                else => break :sw,
            }
            // Everything the fast paths did not take.
            pc = @call(.always_inline, op, .{ s, f, code[pc], pc }) catch |e| {
                if (e == error.Vm) s.atFrame(f);
                return e;
            };
        }
    }

    inline fn atErr(s: *Session, f: *const Frame, e: Fail) Fail {
        s.atFrame(f);
        return e;
    }

    /// Values with no heap ownership (nothing to copy or drop).
    inline fn isInline(t: value.Tag) bool {
        return switch (t) {
            .u8, .u16, .u32, .u64, .u128, .bool => true,
            else => false,
        };
    }
    inline fn isInlineOrInvalid(t: value.Tag) bool {
        return t == .invalid or isInline(t);
    }

    const small_max = [_]u64{ 0, 0xff, 0xffff, 0xffff_ffff, std.math.maxInt(u64) };

    /// u8..u64 binary op on the top two values with no error: the result, else null (the full
    /// path decides, and reports any error). No side effects.
    inline fn fastArith(s: *Session, comptime k: Arith) ?u64 {
        if (s.sp < 2) return null;
        const rhs = s.stack[s.sp - 1];
        const lhs = s.stack[s.sp - 2];
        const ti = @intFromEnum(lhs.tag);
        if (lhs.tag != rhs.tag or ti < 1 or ti > 4) return null;
        const a = lhs.a;
        const b = rhs.a;
        return switch (k) {
            .add => blk: {
                const x = @addWithOverflow(a, b);
                break :blk if (x[1] != 0 or x[0] > small_max[ti]) null else x[0];
            },
            .sub => if (a < b) null else a - b,
            .mul => blk: {
                const x = @mulWithOverflow(a, b);
                break :blk if (x[1] != 0 or x[0] > small_max[ti]) null else x[0];
            },
            .div => if (b == 0) null else a / b,
            .mod => if (b == 0) null else a % b,
            .bor => a | b,
            .band => a & b,
            .xor => a ^ b,
        };
    }

    inline fn fastCmp(s: *Session, comptime k: Cmp) ?bool {
        if (s.sp < 2) return null;
        const rhs = s.stack[s.sp - 1];
        const lhs = s.stack[s.sp - 2];
        const ti = @intFromEnum(lhs.tag);
        if (lhs.tag != rhs.tag or ti < 1 or ti > 4) return null;
        return switch (k) {
            .lt => lhs.a < rhs.a,
            .gt => lhs.a > rhs.a,
            .le => lhs.a <= rhs.a,
            .ge => lhs.a >= rhs.a,
        };
    }

    /// `step` untraced, for compiled code (aot.zig) that reaches a call, a return or a bad pc.
    pub fn stepUntraced(s: *Session) (Fail || Error)!bool {
        return s.step(false);
    }

    /// One instruction. Returns true when the outermost frame returned.
    fn step(s: *Session, comptime traced: bool) (Fail || Error)!bool {
        const f = &s.frames.items[s.frames.items.len - 1];
        const code = f.func.code;
        if (f.pc >= code.len) {
            s.pending = .{ .major = .PC_OVERFLOW };
            s.atFrame(f);
            return error.Vm;
        }
        const ins = code[f.pc];
        if (traced) try s.tracer.?.startInstruction(s, ins, f.pc);
        switch (ins.op) {
            .Ret => {
                const charged = s.meter.chargeSimple(.Ret);
                if (traced) try s.tracer.?.endInstruction(s, null);
                charged catch return s.failAt(f, s.meter.err, null);
                // drop_all_values: locals still holding values are dropped with the frame.
                for (f.locals) |v| s.heap.drop(v);
                if (traced) try s.tracer.?.exitFrame(s, f.func, null);
                if (s.frames.items.len == 1) return true;
                s.lifo.reset(f.mark);
                _ = s.frames.pop();
                const caller = &s.frames.items[s.frames.items.len - 1];
                caller.pc += 1;
                return false;
            },
            .Call => {
                if (traced) try s.tracer.?.endInstruction(s, null);
                const target = try s.link.resolve(f.func.module, ins.idx);
                try s.callFunction(traced, f, target, &.{}, s.lifo.mark());
                return false;
            },
            .CallGeneric => {
                if (traced) try s.tracer.?.endInstruction(s, null);
                const fi = f.func.module.cm.function_instantiations[ins.idx];
                const sig = f.func.module.cm.signatures[fi.type_parameters];
                s.checkCallInst(sig, f) catch {
                    s.atFrame(f);
                    s.raw_err = s.cfg.rules.legacyVm(); // exec-history-vm: no core-dump remap
                    return error.Vm;
                };
                const mk = s.lifo.mark();
                const targs = try s.callTypeArgs(f, ins.idx, sig);
                const target = try s.link.resolve(f.func.module, fi.handle);
                try s.callFunction(traced, f, target, targs, mk);
                return false;
            },
            else => {
                f.pc = s.op(f, ins, f.pc) catch |e| {
                    if (e == error.Vm) {
                        s.atFrame(f);
                        if (traced) try s.tracer.?.endInstruction(s, s.pending.major);
                    }
                    return e;
                };
                if (traced) try s.tracer.?.endInstruction(s, null);
                return false;
            },
        }
    }

    /// The type arguments of a `CallGeneric`. When the signature mentions no type parameter the
    /// instantiation is the same at every execution, so an untraced session builds it once
    /// (in the arena, so it outlives the frame) and shares it: no per-call type allocation.
    /// Everything else (and every traced run) instantiates per call in the frame's region.
    fn callTypeArgs(s: *Session, f: *const Frame, idx: u16, sig: []const ff.Token) Error![]const *const Type {
        const m = f.func.module;
        if (s.tracer != null) return types.instantiateAll(s.typeAlloc(), m, sig, f.ty_args);
        if (!m.gen_concrete[idx]) return types.instantiateAll(s.typeAlloc(), m, sig, f.ty_args);
        const key: GenKey = .{ .m = m, .i = idx };
        if (s.gen_cache.get(key)) |c| return c;
        const targs = try types.instantiateAll(s.arena, m, sig, f.ty_args);
        try s.gen_cache.put(s.arena, key, targs);
        return targs;
    }

    fn callFunction(s: *Session, comptime traced: bool, caller: *Frame, target: *const Function, ty_args: []const *const Type, mk: Lifo.Mark) (Fail || Error)!void {
        if (traced) try s.tracer.?.enterFrame(s, target, ty_args);
        const n = target.params.len;
        if (s.sp < n) return s.failAt(caller, .EMPTY_VALUE_STACK, null);
        s.meter.chargeCall(n) catch return s.failAt(caller, s.meter.err, null);
        if (target.is_native) {
            try s.callNative(traced, caller, target, ty_args);
            s.lifo.reset(mk);
            return;
        }
        const args = s.stack[s.sp - n .. s.sp];
        s.sp -= n;
        const locals = try s.lifo.alloc(Value, target.n_locals);
        @memcpy(locals[0..n], args);
        @memset(locals[n..], Value.invalid);
        if (s.frames.items.len - 1 >= CALL_STACK_SIZE_LIMIT) {
            s.pending = .{ .major = .CALL_STACK_OVERFLOW, .module = target.module, .off = .{ .fdef = target.def_idx, .pc = 0 } };
            // exec-history-vm: v0..v3 `call_stack.push` fails with the caller's frame info.
            if (s.cfg.rules.legacyVm()) s.atFrame(caller);
            return error.Vm;
        }
        try s.frames.append(s.arena, try s.newFrame(target, locals, ty_args, mk));
    }

    fn newFrame(s: *Session, func: *const Function, locals: []Value, ty_args: []const *const Type, mk: Lifo.Mark) Allocator.Error!Frame {
        var fr: Frame = .{ .func = func, .pc = 0, .mark = mk, .locals = locals, .ty_args = ty_args };
        if (ty_args.len != 0) {
            const nodes = try s.lifo.alloc(u64, ty_args.len);
            for (ty_args, nodes) |t, *n| {
                n.* = typeNodes(t);
                fr.ty_nodes_sum +|= n.*;
            }
            fr.ty_nodes = nodes;
        }
        return fr;
    }

    fn callNative(s: *Session, comptime traced: bool, caller: *Frame, target: *const Function, ty_args: []const *const Type) (Fail || Error)!void {
        const table = s.natives orelse return error.NativeUnsupported;
        const m = target.module;
        const nf: Native = if (table.memo_key != 0 and target.native_memo_key == table.memo_key)
            .{ .call = @ptrCast(@alignCast(target.native_memo[0].?)), .data = target.native_memo[1] }
        else blk: {
            const x = table.lookup(&m.pkg.original_id, m.name, target.name) orelse return error.NativeUnsupported;
            if (table.memo_key != 0) {
                const tf: *Function = @constCast(target);
                tf.native_memo = .{ @ptrCast(x.call), x.data };
                tf.native_memo_key = table.memo_key;
            }
            break :blk x;
        };
        s.nativeCall(nf, target, ty_args) catch |e| {
            if (e == error.Vm) {
                s.pending.module = m;
                s.pending.off = .{ .fdef = target.def_idx, .pc = 0 };
                if (traced) try s.tracer.?.exitFrame(s, target, s.pending.major);
            }
            return e;
        };
        if (traced) try s.tracer.?.exitFrame(s, target, null);
        caller.pc += 1;
        // the call is complete (values pushed, charged, the caller past it): hand over
        if (s.tainted) return error.Tainted;
    }

    fn nativeCall(s: *Session, nf: Native, target: *const Function, ty_args: []const *const Type) (Fail || Error)!void {
        const n = target.params.len;
        const args = try s.popN(n);
        const meter = s.meter;
        // Rust builds the NativeContext (and its gas budget) before the pre-execution charge.
        const budget = meter.remainingGas();
        meter.chargeNativeBefore(n) catch return s.chargeFail();
        var ctx: NativeContext = .{ .session = s, .func = target, .gas_budget = budget, .ext = s.ext };
        const r = try nf.call(&ctx, nf.data, ty_args, args);
        switch (r.outcome) {
            .ok => |vals| {
                var size: u64 = 0;
                for (vals) |v| size +|= value.size(v, meter.plain);
                meter.chargeNative(r.cost, .{ .n = vals.len, .size = size }) catch return s.chargeFail();
                if (vals.len != target.returns.len) return s.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null);
                for (vals) |v| try s.push(v);
            },
            .abort => |code| {
                meter.chargeNative(r.cost, null) catch return s.chargeFail();
                return s.fail(.ABORTED, code);
            },
        }
    }

    // ---- integer helpers -------------------------------------------------------------------

    fn intOf(v: Value) u256 {
        return switch (v.tag) {
            .u8, .u16, .u32, .u64 => v.a,
            .u128 => v.asU128(),
            .u256 => v.asU256(),
            else => 0,
        };
    }

    fn mkInt(s: *Session, tag: value.Tag, x: u256) Allocator.Error!Value {
        return switch (tag) {
            .u8 => Value.u8_(@intCast(x)),
            .u16 => Value.u16_(@intCast(x)),
            .u32 => Value.u32_(@intCast(x)),
            .u64 => Value.u64_(@intCast(x)),
            .u128 => Value.u128_(@intCast(x)),
            .u256 => s.heap.u256_(x),
            else => unreachable,
        };
    }

    fn maxOf(tag: value.Tag) u256 {
        return switch (tag) {
            .u8 => std.math.maxInt(u8),
            .u16 => std.math.maxInt(u16),
            .u32 => std.math.maxInt(u32),
            .u64 => std.math.maxInt(u64),
            .u128 => std.math.maxInt(u128),
            else => std.math.maxInt(u256),
        };
    }

    fn bitsOf(tag: value.Tag) u16 {
        return switch (tag) {
            .u8 => 8,
            .u16 => 16,
            .u32 => 32,
            .u64 => 64,
            .u128 => 128,
            else => 256,
        };
    }

    const Arith = enum { add, sub, mul, div, mod, bor, band, xor };

    fn arith(s: *Session, comptime k: Arith) (Fail || Allocator.Error)!void {
        const rhs = try s.pop();
        const lhs = try s.pop();
        if (lhs.tag != rhs.tag) return s.fail(.INTERNAL_TYPE_ERROR, null);
        // fast path for u64 and smaller
        if (lhs.tag != .u128 and lhs.tag != .u256) {
            const a = lhs.a;
            const b = rhs.a;
            const max: u64 = @intCast(maxOf(lhs.tag));
            const r: u64 = switch (k) {
                .add => blk: {
                    const x = @addWithOverflow(a, b);
                    if (x[1] != 0 or x[0] > max) return s.fail(.ARITHMETIC_ERROR, null);
                    break :blk x[0];
                },
                .sub => if (a < b) return s.fail(.ARITHMETIC_ERROR, null) else a - b,
                .mul => blk: {
                    const x = @mulWithOverflow(a, b);
                    if (x[1] != 0 or x[0] > max) return s.fail(.ARITHMETIC_ERROR, null);
                    break :blk x[0];
                },
                .div => if (b == 0) return s.fail(.ARITHMETIC_ERROR, null) else a / b,
                .mod => if (b == 0) return s.fail(.ARITHMETIC_ERROR, null) else a % b,
                .bor => a | b,
                .band => a & b,
                .xor => a ^ b,
            };
            return s.push(.{ .tag = lhs.tag, .a = r });
        }
        if (lhs.tag == .u128) {
            const a = lhs.asU128();
            const b = rhs.asU128();
            const r: u128 = switch (k) {
                .add => blk: {
                    const x = @addWithOverflow(a, b);
                    if (x[1] != 0) return s.fail(.ARITHMETIC_ERROR, null);
                    break :blk x[0];
                },
                .sub => if (a < b) return s.fail(.ARITHMETIC_ERROR, null) else a - b,
                .mul => blk: {
                    const x = @mulWithOverflow(a, b);
                    if (x[1] != 0) return s.fail(.ARITHMETIC_ERROR, null);
                    break :blk x[0];
                },
                .div => if (b == 0) return s.fail(.ARITHMETIC_ERROR, null) else a / b,
                .mod => if (b == 0) return s.fail(.ARITHMETIC_ERROR, null) else a % b,
                .bor => a | b,
                .band => a & b,
                .xor => a ^ b,
            };
            return s.push(Value.u128_(r));
        }
        if (lhs.tag != .u256) return s.fail(.INTERNAL_TYPE_ERROR, null);
        const a = lhs.asU256();
        const b = rhs.asU256();
        const r: u256 = switch (k) {
            .add => blk: {
                const x = @addWithOverflow(a, b);
                if (x[1] != 0) return s.fail(.ARITHMETIC_ERROR, null);
                break :blk x[0];
            },
            .sub => if (a < b) return s.fail(.ARITHMETIC_ERROR, null) else a - b,
            .mul => blk: {
                const x = @mulWithOverflow(a, b);
                if (x[1] != 0) return s.fail(.ARITHMETIC_ERROR, null);
                break :blk x[0];
            },
            .div => if (b == 0) return s.fail(.ARITHMETIC_ERROR, null) else a / b,
            .mod => if (b == 0) return s.fail(.ARITHMETIC_ERROR, null) else a % b,
            .bor => a | b,
            .band => a & b,
            .xor => a ^ b,
        };
        // The result reuses the left operand's box (values own their boxes).
        std.mem.writeInt(u256, @constCast(lhs.box()), r, .little);
        s.heap.drop(rhs);
        return s.push(lhs);
    }

    fn shift(s: *Session, comptime left: bool) (Fail || Allocator.Error)!void {
        const rhs = try s.pop();
        const lhs = try s.pop();
        if (rhs.tag != .u8) return s.fail(.INTERNAL_TYPE_ERROR, null);
        const n: u16 = @intCast(rhs.a);
        const bits = bitsOf(lhs.tag);
        if (n >= bits) return s.fail(.ARITHMETIC_ERROR, null);
        const a = intOf(lhs);
        s.heap.drop(lhs);
        const sh: u8 = @intCast(n);
        const r: u256 = if (left) (a << sh) & maxOf(lhs.tag) else a >> sh;
        return s.push(try s.mkInt(lhs.tag, r));
    }

    const Cmp = enum { lt, gt, le, ge };

    fn compare(s: *Session, comptime k: Cmp) Fail!void {
        const rhs = try s.pop();
        const lhs = try s.pop();
        if (lhs.tag != rhs.tag) return s.fail(.INTERNAL_TYPE_ERROR, null);
        if (lhs.tag != .u128 and lhs.tag != .u256) return s.push(Value.bool_(switch (k) {
            .lt => lhs.a < rhs.a,
            .gt => lhs.a > rhs.a,
            .le => lhs.a <= rhs.a,
            .ge => lhs.a >= rhs.a,
        }));
        const a = intOf(lhs);
        const b = intOf(rhs);
        s.heap.drop(lhs);
        s.heap.drop(rhs);
        return s.push(Value.bool_(switch (k) {
            .lt => a < b,
            .gt => a > b,
            .le => a <= b,
            .ge => a >= b,
        }));
    }

    fn cast(s: *Session, comptime to: value.Tag) (Fail || Allocator.Error)!void {
        const v = try s.pop();
        const x = intOf(v);
        s.heap.drop(v);
        if (x > maxOf(to)) return s.fail(.ARITHMETIC_ERROR, null);
        return s.push(try s.mkInt(to, x));
    }

    // ---- references and containers ----------------------------------------------------------

    fn refContainer(s: *Session, r: Value) Fail!*value.Container {
        if (r.tag != .ref_slot) return s.fail(.INTERNAL_TYPE_ERROR, null);
        const v = r.slot().*;
        if (v.tag != .container) return s.fail(.INTERNAL_TYPE_ERROR, null);
        return v.cont();
    }

    fn vecElemType(s: *Session, f: *const Frame, sig: u16) Error!*const Type {
        const tok = f.func.module.cm.signatures[sig][0];
        return types.instantiate(s.typeAlloc(), f.func.module, tok, f.ty_args);
    }

    fn packFields(s: *Session, kind: value.Kind, tag: u16, n: usize) (Fail || Allocator.Error)!void {
        const fields = try s.popN(n);
        return s.push(try s.heap.pack(kind, tag, fields));
    }

    fn unpackVariantRef(s: *Session, expected: u16) (Fail || Allocator.Error)!void {
        const r = try s.pop();
        const c = try s.refContainer(r);
        if (c.tag != expected) return s.fail(.VARIANT_TAG_MISMATCH, null);
        const fields = c.values();
        s.meter.chargeUnpack(fields.len) catch return s.chargeFail();
        for (fields) |*fld| try s.push(Value.refSlot(fld));
    }

    fn unpackVariant(s: *Session, expected: u16) Fail!void {
        const v = try s.pop();
        const c = v.cont();
        s.meter.chargeUnpack(c.len) catch return s.chargeFail();
        if (c.tag != expected) return s.fail(.VARIANT_TAG_MISMATCH, null);
        for (c.values()) |fld| try s.push(fld);
        s.heap.freeShell(c);
    }

    fn enumInstType(s: *Session, f: *const Frame, edi_idx: u16) Error!*const Type {
        const m = f.func.module;
        const edi = m.cm.enum_def_instantiations[edi_idx];
        const dt = &m.enums[edi.def];
        const args = try types.instantiateAll(s.typeAlloc(), m, m.cm.signatures[edi.type_parameters], f.ty_args);
        const t = try s.typeAlloc().create(Type);
        t.* = .{ .datatype = .{ .dt = dt, .args = args } };
        return t;
    }

    /// One instruction other than Call, CallGeneric and Ret at `pc` (also in `f.pc`); returns
    /// the next pc.
    pub fn op(s: *Session, f: *Frame, ins: ff.Instr, pc: u16) (Fail || Error)!u16 {
        const m = f.func.module;
        const meter = s.meter;
        switch (ins.op) {
            .BrTrue, .BrFalse => {
                if (ins.op == .BrTrue) meter.chargeSimple(.BrTrue) catch return s.chargeFail() else meter.chargeSimple(.BrFalse) catch return s.chargeFail();
                const v = try s.pop();
                if (v.tag != .bool) return s.fail(.INTERNAL_TYPE_ERROR, null);
                const take = (v.a != 0) == (ins.op == .BrTrue);
                return if (take) ins.idx else pc + 1;
            },
            .Branch => {
                meter.chargeSimple(.Branch) catch return s.chargeFail();
                return ins.idx;
            },
            .VariantSwitch => {
                const r = try s.pop();
                const c = try s.refContainer(r);
                meter.chargeVariantSwitch() catch return s.chargeFail();
                const jt = f.func.jump_tables[ins.idx];
                if (c.tag >= jt.offsets.len) return s.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null);
                return jt.offsets[c.tag];
            },
            .Pop => {
                const v = try s.pop();
                meter.chargePop() catch return s.chargeFail();
                s.heap.drop(v);
            },
            .LdU8 => {
                meter.chargeSimple(.LdU8) catch return s.chargeFail();
                try s.push(Value.u8_(@intCast(ins.imm)));
            },
            .LdU16 => {
                meter.chargeSimple(.LdU16) catch return s.chargeFail();
                try s.push(Value.u16_(@intCast(ins.imm)));
            },
            .LdU32 => {
                meter.chargeSimple(.LdU32) catch return s.chargeFail();
                try s.push(Value.u32_(@intCast(ins.imm)));
            },
            .LdU64 => {
                meter.chargeSimple(.LdU64) catch return s.chargeFail();
                try s.push(Value.u64_(ins.imm));
            },
            .LdU128 => {
                meter.chargeSimple(.LdU128) catch return s.chargeFail();
                try s.push(Value.u128_(std.mem.readInt(u128, m.cm.wide[ins.imm][0..16], .little)));
            },
            .LdU256 => {
                meter.chargeSimple(.LdU256) catch return s.chargeFail();
                try s.push(Value.boxed(.u256, try s.heap.box32(m.cm.wide[ins.imm])));
            },
            .LdConst => {
                const k = &m.constants[ins.idx];
                meter.chargeLdConst(if (s.cfg.ld_const_abstract_size) k.abstract_size else k.byte_len) catch return s.chargeFail();
                try s.push(try s.heap.copy(k.value));
            },
            .LdTrue => {
                meter.chargeSimple(.LdTrue) catch return s.chargeFail();
                try s.push(Value.bool_(true));
            },
            .LdFalse => {
                meter.chargeSimple(.LdFalse) catch return s.chargeFail();
                try s.push(Value.bool_(false));
            },
            .CopyLoc => {
                const v = f.locals[ins.idx];
                if (v.tag == .invalid) return s.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null);
                meter.chargeCopyLoc(value.size(v, meter.plain)) catch return s.chargeFail();
                try s.push(try s.heap.copy(v));
            },
            .MoveLoc => {
                const v = f.locals[ins.idx];
                if (v.tag == .invalid) return s.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null);
                f.locals[ins.idx] = Value.invalid;
                const sz = if (meter.moveLocNeedsSize()) value.size(v, meter.plain) else 0;
                meter.chargeMoveLoc(sz) catch return s.chargeFail();
                try s.push(v);
            },
            .StLoc => {
                const v = try s.pop();
                meter.chargeStoreLoc() catch return s.chargeFail();
                s.heap.drop(f.locals[ins.idx]);
                f.locals[ins.idx] = v;
            },
            .MutBorrowLoc => {
                meter.chargeSimple(.MutBorrowLoc) catch return s.chargeFail();
                try s.push(Value.refSlot(&f.locals[ins.idx]));
            },
            .ImmBorrowLoc => {
                meter.chargeSimple(.ImmBorrowLoc) catch return s.chargeFail();
                try s.push(Value.refSlot(&f.locals[ins.idx]));
            },
            .ImmBorrowField, .MutBorrowField, .ImmBorrowFieldGeneric, .MutBorrowFieldGeneric => {
                switch (ins.op) {
                    .ImmBorrowField => meter.chargeSimple(.ImmBorrowField) catch return s.chargeFail(),
                    .MutBorrowField => meter.chargeSimple(.MutBorrowField) catch return s.chargeFail(),
                    .ImmBorrowFieldGeneric => meter.chargeSimple(.ImmBorrowFieldGeneric) catch return s.chargeFail(),
                    else => meter.chargeSimple(.MutBorrowFieldGeneric) catch return s.chargeFail(),
                }
                const fh = if (ins.op == .ImmBorrowField or ins.op == .MutBorrowField) ins.idx else m.cm.field_instantiations[ins.idx].handle;
                const offset = m.cm.field_handles[fh].field;
                const c = try s.refContainer(try s.pop());
                if (offset >= c.len) return s.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR, null);
                try s.push(Value.refSlot(&c.values()[offset]));
            },
            .Pack => {
                const dt = &m.structs[ins.idx];
                const t = Type{ .datatype = .{ .dt = dt, .args = &.{} } };
                try s.checkDepth(&t);
                meter.chargePack(dt.fields.len) catch return s.chargeFail();
                try s.packFields(.struct_, 0, dt.fields.len);
            },
            .PackGeneric => {
                const sdi = m.cm.struct_def_instantiations[ins.idx];
                const dt = &m.structs[sdi.def];
                try s.checkDatatypeInst(m.cm.signatures[sdi.type_parameters], f);
                const mk = s.lifo.mark();
                defer s.lifo.reset(mk);
                const args = try types.instantiateAll(s.typeAlloc(), m, m.cm.signatures[sdi.type_parameters], f.ty_args);
                const t = Type{ .datatype = .{ .dt = dt, .args = args } };
                try s.checkDepth(&t);
                meter.chargePack(dt.fields.len) catch return s.chargeFail();
                try s.packFields(.struct_, 0, dt.fields.len);
            },
            .Unpack, .UnpackGeneric => {
                const v = try s.pop();
                if (v.tag != .container) return s.fail(.INTERNAL_TYPE_ERROR, null);
                const c = v.cont();
                meter.chargeUnpack(c.len) catch return s.chargeFail();
                for (c.values()) |fld| try s.push(fld);
                s.heap.freeShell(c);
            },
            .ReadRef => {
                const r = try s.pop();
                if (!r.isRef()) return s.fail(.INTERNAL_TYPE_ERROR, null);
                meter.chargeReadRef(value.referentSize(r, meter.plain), value.referentSize(r, meter.traversal)) catch return s.chargeFail();
                try s.push(if (r.tag == .ref_elem) try value.readElem(r.cont(), r.b, s.heap) else try s.heap.copy(r.slot().*));
            },
            .WriteRef => {
                const r = try s.pop();
                const v = try s.pop();
                if (!r.isRef()) return s.fail(.INTERNAL_TYPE_ERROR, null);
                meter.chargeWriteRef(value.size(v, meter.plain)) catch return s.chargeFail();
                s.noteWrite(if (r.tag == .ref_slot) @intFromPtr(r.slot()) else @intFromPtr(r.cont()));
                switch (r.tag) {
                    .ref_slot => {
                        s.heap.drop(r.slot().*);
                        r.slot().* = v;
                    },
                    else => {
                        value.writeElem(r.cont(), r.b, v);
                        s.heap.drop(v);
                    },
                }
            },
            .CastU8 => {
                meter.chargeSimple(.CastU8) catch return s.chargeFail();
                try s.cast(.u8);
            },
            .CastU16 => {
                meter.chargeSimple(.CastU16) catch return s.chargeFail();
                try s.cast(.u16);
            },
            .CastU32 => {
                meter.chargeSimple(.CastU32) catch return s.chargeFail();
                try s.cast(.u32);
            },
            .CastU64 => {
                meter.chargeSimple(.CastU64) catch return s.chargeFail();
                try s.cast(.u64);
            },
            .CastU128 => {
                meter.chargeSimple(.CastU128) catch return s.chargeFail();
                try s.cast(.u128);
            },
            .CastU256 => {
                meter.chargeSimple(.CastU256) catch return s.chargeFail();
                try s.cast(.u256);
            },
            .Add => {
                meter.chargeSimple(.Add) catch return s.chargeFail();
                try s.arith(.add);
            },
            .Sub => {
                meter.chargeSimple(.Sub) catch return s.chargeFail();
                try s.arith(.sub);
            },
            .Mul => {
                meter.chargeSimple(.Mul) catch return s.chargeFail();
                try s.arith(.mul);
            },
            .Mod => {
                meter.chargeSimple(.Mod) catch return s.chargeFail();
                try s.arith(.mod);
            },
            .Div => {
                meter.chargeSimple(.Div) catch return s.chargeFail();
                try s.arith(.div);
            },
            .BitOr => {
                meter.chargeSimple(.BitOr) catch return s.chargeFail();
                try s.arith(.bor);
            },
            .BitAnd => {
                meter.chargeSimple(.BitAnd) catch return s.chargeFail();
                try s.arith(.band);
            },
            .Xor => {
                meter.chargeSimple(.Xor) catch return s.chargeFail();
                try s.arith(.xor);
            },
            .Shl => {
                meter.chargeSimple(.Shl) catch return s.chargeFail();
                try s.shift(true);
            },
            .Shr => {
                meter.chargeSimple(.Shr) catch return s.chargeFail();
                try s.shift(false);
            },
            .Or, .And => {
                if (ins.op == .Or) meter.chargeSimple(.Or) catch return s.chargeFail() else meter.chargeSimple(.And) catch return s.chargeFail();
                const rhs = try s.pop();
                const lhs = try s.pop();
                if (lhs.tag != .bool or rhs.tag != .bool) return s.fail(.INTERNAL_TYPE_ERROR, null);
                const r = if (ins.op == .Or) (lhs.a | rhs.a) else (lhs.a & rhs.a);
                try s.push(Value.bool_(r != 0));
            },
            .Lt => {
                meter.chargeSimple(.Lt) catch return s.chargeFail();
                try s.compare(.lt);
            },
            .Gt => {
                meter.chargeSimple(.Gt) catch return s.chargeFail();
                try s.compare(.gt);
            },
            .Le => {
                meter.chargeSimple(.Le) catch return s.chargeFail();
                try s.compare(.le);
            },
            .Ge => {
                meter.chargeSimple(.Ge) catch return s.chargeFail();
                try s.compare(.ge);
            },
            .Abort => {
                meter.chargeSimple(.Abort) catch return s.chargeFail();
                const v = try s.pop();
                if (v.tag != .u64) return s.fail(.INTERNAL_TYPE_ERROR, null);
                return s.fail(.ABORTED, v.a);
            },
            .Eq, .Neq => {
                const lhs = try s.pop();
                const rhs = try s.pop();
                const a = value.size(lhs, meter.traversal);
                const b = value.size(rhs, meter.traversal);
                if (ins.op == .Eq) meter.chargeEq(a, b) catch return s.chargeFail() else meter.chargeNeq(a, b) catch return s.chargeFail();
                const eq = value.equals(lhs, rhs);
                s.heap.drop(lhs);
                s.heap.drop(rhs);
                try s.push(Value.bool_(if (ins.op == .Eq) eq else !eq));
            },
            .FreezeRef => meter.chargeSimple(.FreezeRef) catch return s.chargeFail(),
            .Not => {
                meter.chargeSimple(.Not) catch return s.chargeFail();
                const v = try s.pop();
                if (v.tag != .bool) return s.fail(.INTERNAL_TYPE_ERROR, null);
                try s.push(Value.bool_(v.a == 0));
            },
            .Nop => meter.chargeSimple(.Nop) catch return s.chargeFail(),
            .VecPack => {
                const n: usize = @intCast(ins.imm);
                try s.checkSubst(m.cm.signatures[ins.idx][0], f);
                const mk = s.lifo.mark();
                defer s.lifo.reset(mk);
                const ty = try s.vecElemType(f, ins.idx);
                try s.checkDepth(ty);
                meter.chargeVecPack(n) catch return s.chargeFail();
                const elems = try s.popN(n);
                const k = ty.vecKind();
                const c = try s.heap.newContainer(k, n);
                if (k.isPrimVec()) {
                    for (elems, 0..) |e, i| {
                        value.writeElem(c, i, e);
                        s.heap.drop(e);
                    }
                } else @memcpy(c.values(), elems);
                try s.push(Value.container(c));
            },
            .VecLen => {
                const c = try s.refContainer(try s.pop());
                try s.checkSubst(m.cm.signatures[ins.idx][0], f);
                meter.chargeVecLen() catch return s.chargeFail();
                try s.push(Value.u64_(c.len));
            },
            .VecImmBorrow, .VecMutBorrow => {
                const idx = try s.pop();
                const c = try s.refContainer(try s.pop());
                const ok = idx.a < c.len;
                try s.checkSubst(m.cm.signatures[ins.idx][0], f);
                meter.chargeVecBorrow() catch return s.chargeFail();
                if (!ok) return s.fail(.VECTOR_OPERATION_ERROR, INDEX_OUT_OF_BOUNDS);
                if (c.kind.isPrimVec()) try s.push(Value.refElem(c, idx.a)) else try s.push(Value.refSlot(&c.values()[idx.a]));
            },
            .VecPushBack => {
                const e = try s.pop();
                const c = try s.refContainer(try s.pop());
                try s.checkSubst(m.cm.signatures[ins.idx][0], f);
                meter.chargeVecPushBack() catch return s.chargeFail(); s.noteWrite(@intFromPtr(c));
                if (c.len >= s.cfg.vector_len_max) return s.fail(.VECTOR_OPERATION_ERROR, VEC_SIZE_LIMIT_REACHED);
                try s.heap.reserveOne(c);
                c.len += 1;
                if (c.kind.isPrimVec()) {
                    value.writeElem(c, c.len - 1, e);
                    s.heap.drop(e);
                } else c.values()[c.len - 1] = e;
            },
            .VecPopBack => {
                const c = try s.refContainer(try s.pop());
                try s.checkSubst(m.cm.signatures[ins.idx][0], f);
                var v: Value = Value.invalid;
                if (c.len > 0) {
                    v = if (c.kind.isPrimVec()) try value.readElem(c, c.len - 1, s.heap) else c.values()[c.len - 1];
                    c.len -= 1;
                }
                meter.chargeVecPopBack() catch return s.chargeFail(); s.noteWrite(@intFromPtr(c));
                if (v.tag == .invalid) return s.fail(.VECTOR_OPERATION_ERROR, POP_EMPTY_VEC);
                try s.push(v);
            },
            .VecUnpack => {
                const v = try s.pop();
                if (v.tag != .container) return s.fail(.INTERNAL_TYPE_ERROR, null);
                const c = v.cont();
                try s.checkSubst(m.cm.signatures[ins.idx][0], f);
                meter.chargeVecUnpack(ins.imm) catch return s.chargeFail();
                if (c.len != ins.imm) return s.fail(.VECTOR_OPERATION_ERROR, VEC_UNPACK_PARITY_MISMATCH);
                if (c.kind.isPrimVec()) {
                    for (0..c.len) |i| try s.push(try value.readElem(c, i, s.heap));
                } else for (c.values()) |e| try s.push(e);
                s.heap.freeShell(c);
            },
            .VecSwap => {
                const idx2 = try s.pop();
                const idx1 = try s.pop();
                const c = try s.refContainer(try s.pop());
                try s.checkSubst(m.cm.signatures[ins.idx][0], f);
                meter.chargeVecSwap() catch return s.chargeFail(); s.noteWrite(@intFromPtr(c));
                if (idx1.a >= c.len or idx2.a >= c.len) return s.fail(.VECTOR_OPERATION_ERROR, INDEX_OUT_OF_BOUNDS);
                const w = c.kind.width();
                const i = idx1.a * w;
                const j = idx2.a * w;
                if (i != j) {
                    var tmp: [32]u8 = undefined;
                    @memcpy(tmp[0..w], c.data[i..][0..w]);
                    @memcpy(c.data[i..][0..w], c.data[j..][0..w]);
                    @memcpy(c.data[j..][0..w], tmp[0..w]);
                }
            },
            .PackVariant => {
                const vh = m.cm.variant_handles[ins.idx];
                const dt = &m.enums[vh.enum_def];
                const t = Type{ .datatype = .{ .dt = dt, .args = &.{} } };
                const n = dt.variants[vh.variant].fields.len;
                try s.checkDepth(&t);
                meter.chargePack(n) catch return s.chargeFail();
                try s.packFields(.variant, vh.variant, n);
            },
            .PackVariantGeneric => {
                const vih = m.cm.variant_instantiation_handles[ins.idx];
                try s.checkDatatypeInst(m.cm.signatures[m.cm.enum_def_instantiations[vih.enum_def].type_parameters], f);
                const mk = s.lifo.mark();
                defer s.lifo.reset(mk);
                const t = try s.enumInstType(f, vih.enum_def);
                const n = t.datatype.dt.variants[vih.variant].fields.len;
                try s.checkDepth(t);
                meter.chargePack(n) catch return s.chargeFail();
                try s.packFields(.variant, vih.variant, n);
            },
            .UnpackVariant => try s.unpackVariant(m.cm.variant_handles[ins.idx].variant),
            .UnpackVariantGeneric => try s.unpackVariant(m.cm.variant_instantiation_handles[ins.idx].variant),
            .UnpackVariantImmRef, .UnpackVariantMutRef => try s.unpackVariantRef(m.cm.variant_handles[ins.idx].variant),
            .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => try s.unpackVariantRef(m.cm.variant_instantiation_handles[ins.idx].variant),
            else => return s.fail(.UNREACHABLE, null),
        }
        return pc + 1;
    }
};

test "only the latest execution runs" {
    try std.testing.expectError(error.UnsupportedExecutionVersion, ExecConfig.fromProtocol(try protocol.get(118, .mainnet)));
    _ = try ExecConfig.fromProtocol(try protocol.get(119, .mainnet));
    _ = try ExecConfig.fromProtocol(try protocol.get(protocol.max_protocol_version, .mainnet));
}

test "finalize_execution_error" {
    const e: VmError = .{ .major = .LINKER_ERROR, .sub = 3, .off = .{ .fdef = 1, .pc = 2 } };
    const f = finalizeExecutionError(e);
    try std.testing.expectEqual(StatusCode.UNKNOWN_INVARIANT_VIOLATION_ERROR, f.major);
    try std.testing.expect(f.sub == null and f.off == null);
    const g: VmError = .{ .major = .ARITHMETIC_ERROR, .off = .{ .fdef = 0, .pc = 4 } };
    try std.testing.expectEqual(g, finalizeExecutionError(g));
}
