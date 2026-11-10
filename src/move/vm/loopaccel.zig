//! loopaccel: exact accelerators for the hottest Move loops.
//!
//! OFF by default. `enable()` or the environment variable ZUI_VM_LOOPACCEL=1 (read once, at the
//! first package load of the process) turns it on for packages loaded from then on. Only the
//! exact value 1 does: unset, empty and 0 are off, and any other value ("on", "true", "off",
//! ...) is reported with a warning and leaves it off (`parseSwitch`). With
//! ZUI_VM_LOOPACCEL_STATS=1 as well, the process prints, when it exits, what was attached and
//! how many loop heads, iterations and instructions were applied natively, in all and per
//! kind of loop (two lines; the format is at `formatTotals`).
//!
//! What it does. A handful of small loops (stdlib `vector::reverse` / `append` / `remove` of the
//! framework versions before protocol 140, Wormhole `bytes::take_bytes` and its big-endian
//! integer readers, the Pyth merkle byte copies) move one element per 13 to 22 interpreted
//! instructions. When the interpreter is at
//! the head of such a loop, `accelerate` computes k, the number of whole iterations that are
//! certain to run with no event of any kind:
//!   - the loop's own guard holds and no instruction faults (index in range, vector length limit,
//!     no arithmetic overflow, operand stack and call depth limits, type instantiation limits),
//!   - no charge leaves `Meter.charge`'s fast path: no tier start of the instruction count, the
//!     stack size or the stack height is passed, and there is gas for all of it.
//! It then applies those k iterations to the VM values in one native step (a reversal, a move, a
//! copy), sets the loop's locals to what k iterations leave, and commits exactly what k
//! iterations charge: `gas_left`, `instructions_executed`, the stack size and height counters
//! and their high-water marks. The pc stays at the loop head. The interpreter then runs the exit
//! test and whatever is left one instruction at a time, so the iteration that crosses a tier,
//! runs out of gas, aborts or faults is executed by the interpreter itself, on the same
//! instruction, from the same state.
//!
//! Why the commit is exact. Inside the window every charge is `Meter.charge`'s fast path, which
//! is linear: it adds the instruction's pushes, size increase and instruction count to the
//! counters and deducts `im*n + sm*size + hm*pushes` with the three tier multipliers unchanged.
//! Every charge of these loop bodies has arguments that do not depend on the data (they depend
//! only on the gas model version and, for one MoveLoc before gas model 11, on the element
//! width), so k iterations charge k times one iteration. One iteration's charges are not typed
//! in: `summarize` replays the loop body against a scratch `Meter` with the meter's own charge
//! functions (`chargeCopyLoc`, `chargeVecSwap`, ...) for the session's gas model version and
//! reads the pushes, pops and size increase of every instruction off it.
//!
//! Recognition. A loop is accelerated only in a module whose code digest (`codeDigest`: the
//! module name and every function's instruction stream, the same as `aot_rt.digestModule`
//! without the address) is in `registry`, in the function of that name and definition index,
//! and only if the loop body at the registered head equals the template instruction for
//! instruction, with every table operand resolved: the signature token of each vector
//! instruction, the type arguments and the target of each call (a function of the same
//! package, whose module digest and whole body are checked too), the field offset of each field
//! borrow. The address is left out because the same bytecode is published more than once: the
//! modules of the second Wormhole and Pyth deployments on mainnet (0x99de..25b4 and
//! 0x5530..e2c0) are the bytes of the first with other address identifiers. The digest only
//! narrows the candidates; what makes a loop safe to accelerate is the template match, which
//! holds or fails on the loop's own instructions and resolved operands wherever the module is
//! published. Anything else, including every other version of these modules, runs in the
//! interpreter; `attach_stats` counts the modules of a known deployment that have another
//! bytecode (digest misses), and the functions whose module has the registered code while the
//! module they call into, or a table entry, does not match (template mismatches).
//!
//! The runner. A function with accelerators attached runs through `run` instead of the inline
//! handlers of `Session.stepRun`: the same `Session.op` per instruction that the traced loop and
//! the aot tier use, plus the head test. Nothing in the interpreter loop changes.
//!
//! Not accelerated (the interpreter runs as before): traced and profiled sessions (they never
//! reach `stepRun`), unmetered sessions, sessions with a write hook (exec-history child-object
//! rule), frames whose type arguments are large (more than `MAX_TY_NODES` nodes in total), and
//! any state the head check does not recognise.
//!
//! Coupling: `commit` and `window` read and write the fields of `gas.Meter` directly, and
//! `summarize` mirrors which meter function `Session.op` calls for each opcode. A change to
//! either must keep loopaccel_test.zig green (it compares the whole meter after every run).
const std = @import("std");
const move_format = @import("move_format");
const loader = @import("loader.zig");
const interp = @import("interp.zig");
const value = @import("value.zig");
const gas = @import("gas.zig");

const ff = move_format.file_format;
const Value = value.Value;
const Container = value.Container;
const Session = interp.Session;
const Frame = interp.Frame;

// ---------------------------------------------------------------------------------------------
// The switch

/// The environment switches: the accelerators, and their totals at exit (which need the
/// accelerators on). Both are read by `parseSwitch`.
pub const ENV = "ZUI_VM_LOOPACCEL";
pub const ENV_STATS = ENV ++ "_STATS";

pub const Switch = enum { off, on, unrecognised };

/// What the value of an environment switch means (null: the variable is not set). Exactly "1"
/// is on. Unset, empty and "0" are off, silently. Anything else ("on", "true", "off", "2",
/// "1 ") is unrecognised: `decide` warns about it and leaves the switch off, so no value
/// that might have been meant as off can turn a switch on.
pub fn parseSwitch(v: ?[]const u8) Switch {
    const s = v orelse return .off;
    if (s.len == 0 or std.mem.eql(u8, s, "0")) return .off;
    if (std.mem.eql(u8, s, "1")) return .on;
    return .unrecognised;
}

/// What the values of the two variables turn on, and which of them get a warning.
pub const Decision = struct { accel: bool, stats: bool, warn_accel: bool, warn_stats: bool };

pub fn decideFrom(accel: ?[]const u8, stats_value: ?[]const u8) Decision {
    const a = parseSwitch(accel);
    const t = parseSwitch(stats_value);
    return .{ .accel = a == .on, .stats = a == .on and t == .on, .warn_accel = a == .unrecognised, .warn_stats = t == .unrecognised };
}

var decided: std.atomic.Value(bool) = .init(false);
var on: std.atomic.Value(bool) = .init(false);
var built: std.atomic.Value(bool) = .init(false);
var build_lock: std.atomic.Value(u32) = .init(0);

/// True while accelerated functions run through `run`. The interpreter hook reads this, so
/// `disable` takes effect at the next frame entry even for functions attached earlier.
pub inline fn live() bool {
    return on.load(.monotonic);
}

/// Turns the accelerators on for packages loaded from now on (packages loaded earlier stay
/// interpreted, like the aot tier).
pub fn enable() void {
    if (!built.load(.acquire)) {
        while (build_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
        defer build_lock.store(0, .release);
        if (!built.load(.acquire)) {
            buildSummaries();
            built.store(true, .release);
        }
    }
    on.store(true, .release);
    decided.store(true, .release);
}

/// Turns them off: every function runs in the plain interpreter from its next frame entry.
pub fn disable() void {
    on.store(false, .release);
    decided.store(true, .release);
}

fn envValue(name: [*:0]const u8) ?[]const u8 {
    return if (std.c.getenv(name)) |v| std.mem.span(v) else null;
}

fn warnUnrecognised(name: []const u8, v: []const u8, what: []const u8) void {
    std.log.warn("vm-loopaccel: {s}={s} is not recognised (only the value 1 turns {s} on); left off", .{ name, v[0..@min(v.len, 40)], what });
}

fn decide() void {
    const accel = envValue(ENV);
    const stats_value = envValue(ENV_STATS);
    const d = decideFrom(accel, stats_value);
    if (d.warn_accel) warnUnrecognised(ENV, accel.?, "the loop accelerators");
    if (d.warn_stats) warnUnrecognised(ENV_STATS, stats_value.?, "the loop accelerator totals");
    if (d.stats and !count_totals.swap(true, .acq_rel)) _ = atexit(printTotals);
    if (d.accel) return enable();
    decided.store(true, .release);
}

/// The loops by what they are, for the totals: every shape belongs to one group (the two
/// bytecodes of `vector::reverse` are one group, the three big-endian readers are one group).
pub const Group = enum(u8) {
    /// Move stdlib `vector::reverse`, `vector::remove` and `vector::append`.
    reverse,
    remove,
    append,
    /// Wormhole `bytes::take_bytes`, and `bytes::take_u16_be` / `take_u32_be` / `take_u64_be`.
    take_bytes,
    take_be,
    /// Pyth `merkle_tree::hash`, `leaf_hash` and `node_hash`.
    pyth_hash,
    pyth_leaf_hash,
    pyth_node_hash,
};
pub const N_GROUPS = @typeInfo(Group).@"enum".field_names.len;

/// One group's counters since the process started (relaxed atomics).
pub const GroupTotals = struct {
    /// Functions that got an accelerator (`attach`), and functions of a registered digest
    /// that did not match their template. Always counted.
    attached: std.atomic.Value(u64) = .init(0),
    mismatches: std.atomic.Value(u64) = .init(0),
    /// Loop heads where at least one iteration was applied natively, the iterations applied
    /// and the bytecode instructions they stand for. Counted only under
    /// ZUI_VM_LOOPACCEL_STATS (three atomic adds per accelerated head).
    heads: std.atomic.Value(u64) = .init(0),
    iters: std.atomic.Value(u64) = .init(0),
    instrs: std.atomic.Value(u64) = .init(0),
};

/// Process-wide totals per group, printed at exit under ZUI_VM_LOOPACCEL_STATS.
pub const Totals = struct {
    groups: [N_GROUPS]GroupTotals = @splat(.{}),

    pub fn of(t: *Totals, g: Group) *GroupTotals {
        return &t.groups[@intFromEnum(g)];
    }
};
pub var totals: Totals = .{};
var count_totals: std.atomic.Value(bool) = .init(false);

/// Turns the per-head counters of `totals` on or off (the environment switch
/// ZUI_VM_LOOPACCEL_STATS turns them on and also registers the exit report).
pub fn countTotals(v: bool) void {
    count_totals.store(v, .release);
}

extern "c" fn atexit(f: *const fn () callconv(.c) void) c_int;

/// The exit report of ZUI_VM_LOOPACCEL_STATS=1: two lines on stderr, written once when the
/// process exits, after whatever stderr already holds (`writeAtEnd`). Every field is `key=<decimal>`; the keys, their order and the order of the
/// groups never change, and a count that is zero is printed as 0 (nothing is left out), so a
/// script can match a whole line.
///
///   vm-loopaccel: modules_matched=N digest_misses=N functions_attached=N template_mismatches=N heads=N iters=N instrs=N
///   vm-loopaccel-shapes: reverse:attached=N,mismatches=N,heads=N,iters=N,instrs=N remove:... append:... take_bytes:... take_be:... pyth_hash:... pyth_leaf_hash:... pyth_node_hash:...
///
/// Line 1, the whole process: modules whose code digest is registered, modules of a known
/// deployment with another bytecode (`AttachStats.modules_digest_miss`), then the sums of the
/// per-group counts of line 2.
/// Line 2, one space-separated entry per `Group`, in the order of the enum, each
/// `<group>:` followed by five comma-separated fields: `attached` functions that got an
/// accelerator (counted per package load), `mismatches` functions of a registered digest that
/// did not match their template, `heads` loop heads where iterations were applied natively,
/// `iters` those iterations, `instrs` the bytecode instructions they stand for.
///
/// A gate that requires every group to be attached and exercised is one extended regular
/// expression over line 2:
///   ^vm-loopaccel-shapes:( [a-z0-9_]+:attached=[1-9][0-9]*,mismatches=[0-9]+,heads=[1-9][0-9]*,iters=[1-9][0-9]*,instrs=[1-9][0-9]*){8}$
/// (`mismatches=0` in place of `mismatches=[0-9]+` also requires that every function of
/// registered code was attached; a mismatch is not an error, see `AttachStats`.)
pub fn formatTotals(buf: []u8) []const u8 {
    var sum: [5]u64 = @splat(0);
    var per: [N_GROUPS][5]u64 = undefined;
    for (&totals.groups, &per) |*g, *row| {
        row.* = .{ g.attached.load(.monotonic), g.mismatches.load(.monotonic), g.heads.load(.monotonic), g.iters.load(.monotonic), g.instrs.load(.monotonic) };
        for (&sum, row) |*x, y| x.* += y;
    }
    var n: usize = 0;
    n += (std.fmt.bufPrint(buf[n..], "vm-loopaccel: modules_matched={d} digest_misses={d} functions_attached={d} template_mismatches={d} heads={d} iters={d} instrs={d}\nvm-loopaccel-shapes:", .{
        attach_stats.modules_matched.load(.monotonic),
        attach_stats.modules_digest_miss.load(.monotonic),
        sum[0],
        sum[1],
        sum[2],
        sum[3],
        sum[4],
    }) catch return buf[0..n]).len;
    for (per, 0..) |row, i| {
        const g: Group = @enumFromInt(@as(u8, @intCast(i)));
        n += (std.fmt.bufPrint(buf[n..], " {s}:attached={d},mismatches={d},heads={d},iters={d},instrs={d}", .{ @tagName(g), row[0], row[1], row[2], row[3], row[4] }) catch return buf[0..n]).len;
    }
    n += (std.fmt.bufPrint(buf[n..], "\n", .{}) catch return buf[0..n]).len;
    return buf[0..n];
}

extern "c" fn lseek(fd: c_int, offset: i64, whence: c_int) i64;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;

/// Writes `bytes` after everything `fd` already holds. The exit report goes out this way and
/// not through `std.debug.print`: when stderr is redirected to a regular file together with
/// stdout (`> log 2>&1`), std's stderr writer and a program's own stdout and stderr writers
/// each write the file positionally from their own offset 0, so a report printed through
/// std lands on top of the first lines of the log (in a conformance run: on the suite's
/// summary line). Seeking to the end first puts it after them. On a pipe or a terminal the
/// seek fails and this is a plain write.
pub fn writeAtEnd(fd: c_int, bytes: []const u8) void {
    _ = lseek(fd, 0, 2); // SEEK_END
    var rest = bytes;
    while (rest.len != 0) {
        const n = write(fd, rest.ptr, rest.len);
        if (n <= 0) return;
        rest = rest[@intCast(n)..];
    }
}

fn printTotals() callconv(.c) void {
    var buf: [4096]u8 = undefined;
    writeAtEnd(2, formatTotals(&buf));
}

/// What the accelerators did on this thread (plain counters: a session belongs to one thread).
pub const Stats = struct {
    /// Loop heads reached in the runner.
    heads: u64 = 0,
    /// Heads where at least one iteration was applied natively.
    hits: u64 = 0,
    /// Iterations applied natively, and the bytecode instructions they stand for.
    iters: u64 = 0,
    instrs: u64 = 0,
};
pub threadlocal var stats: Stats = .{};

/// What `attach` did since the process started (relaxed atomics; for the node's metrics/log).
pub const AttachStats = struct {
    modules_matched: std.atomic.Value(u64) = .init(0),
    /// A module of a known deployment (`known`) whose bytecode has no template (an upgrade):
    /// its loops run in the interpreter.
    modules_digest_miss: std.atomic.Value(u64) = .init(0),
    functions_attached: std.atomic.Value(u64) = .init(0),
    /// A function of a module with a registered digest that did not match its template. The
    /// digest covers the instruction streams of that one module, and the template also checks
    /// what the instructions resolve to, so this is expected whenever something outside the
    /// digest differs: the module the loop calls into has another bytecode (Wormhole `cursor`
    /// upgraded in a package version whose `bytes` is unchanged), or a table entry of either
    /// module (a signature, a field or function handle) is not the registered one. The
    /// function runs in the interpreter, which is always correct; the count says how much
    /// registered code is not accelerated.
    template_mismatch: std.atomic.Value(u64) = .init(0),
};
pub var attach_stats: AttachStats = .{};

// ---------------------------------------------------------------------------------------------
// Templates

/// Token of a vector instruction or of a call's single type argument.
pub const TP0: i32 = 0; // TypeParameter(0)
pub const TU8: i32 = 1; // U8

/// One template instruction. `x` is, by opcode: the local index (CopyLoc, MoveLoc, StLoc,
/// ImmBorrowLoc, MutBorrowLoc); the branch target relative to the loop head (BrTrue, BrFalse,
/// Branch); the element token `TP0` / `TU8` (Vec*); the type argument token of the call
/// (CallGeneric, whose target is the shape's callee); the field offset (borrow field). `imm` is
/// the immediate (LdU8, LdU64).
pub const SI = struct { op: ff.Opcode, x: i32 = 0, imm: u64 = 0 };

/// Abstract value kinds of `summarize` (and the head check of the frame's locals).
pub const AK = enum(u8) {
    /// A local the loop never touches (not checked).
    any,
    invalid,
    u8,
    u16,
    u32,
    u64,
    bool,
    /// A reference in a slot (`ref_slot`).
    ref,
    /// A reference to an element of a primitive vector.
    ref_elem,
    /// An owned vector.
    vec,
    /// An element of the loop's vector.
    elem,
};

pub const Kind = enum {
    /// `while (i < j) { swap(v, i, j); i = i + 1; j = j - 1 }`
    reverse,
    /// `while (i < j) { swap(v, i, i + 1); i = i + 1 }`
    rotate,
    /// `while (guard) push_back(dst, pop_back(src))`, counted (`i < j`, `i = i + 1`) or while
    /// `src` is not empty.
    push_pop,
    /// `while (i < bound) { push_back(dst, *borrow(src, i)); i = i + 1 }`
    copy,
    /// `while (i < bound) { acc = (acc << 8) + (pop_back(src) as T); i = i + 1 }`, acc in local `j`
    /// of type T (u16, u32 or u64): a big-endian integer read off a byte vector's tail.
    be_acc,
};

pub const Access = enum {
    none,
    /// The local holds a reference to the vector.
    ref_local,
    /// The local holds the vector.
    owned_local,
    /// The local holds a reference to a struct whose field `field` is the vector.
    ref_field,
};
pub const VecAt = struct { how: Access = .none, local: u16 = 0, field: u16 = 0 };

pub const Bound = enum {
    /// `i < j`, both locals.
    local,
    /// `i < bound_imm`.
    imm,
    /// `i < length(src)`.
    src_len,
    /// `src` is not empty (no counter).
    nonempty,
};

/// A function of the same package called once per iteration.
pub const Callee = struct {
    module: []const u8,
    name: []const u8,
    /// Code digest of the callee's module; null: it is the caller's own module.
    digest: ?[32]u8 = null,
    n_params: u16,
    /// Abstract kinds of its locals at entry (parameters first; the rest are invalid).
    locals: []const AK,
    /// The whole function body, Ret included.
    body: []const SI,
};

pub const Shape = struct {
    name: []const u8,
    /// The group whose totals this loop counts in.
    group: Group,
    kind: Kind,
    /// The loop body from the head to the backward Branch.
    body: []const SI,
    callee: ?*const Callee = null,
    /// Abstract kinds of the frame's locals whenever the pc is at the head.
    locals: []const AK,
    /// The function has exactly one type parameter (the element type); else none.
    generic: bool,
    /// The element token is U8: both vectors are `vector<u8>`.
    elem_u8: bool = false,
    dst: VecAt,
    src: VecAt = .{},
    i: u16 = 0,
    j: u16 = 0,
    bound: Bound = .local,
    bound_imm: u64 = 0,
    /// Locals an iteration leaves moved-out.
    temps: []const u16 = &.{},
};

fn si(comptime op: ff.Opcode, comptime x: i32) SI {
    return .{ .op = op, .x = x };
}
fn ld(comptime v: u64) SI {
    return .{ .op = .LdU64, .imm = v };
}
fn ld8(comptime v: u64) SI {
    return .{ .op = .LdU8, .imm = v };
}

const is_empty_callee: Callee = .{
    .module = "vector",
    .name = "is_empty",
    .n_params = 1,
    .locals = &.{.ref},
    .body = &.{ si(.MoveLoc, 0), si(.VecLen, TP0), ld(0), si(.Eq, 0), si(.Ret, 0) },
};

const poke_callee: Callee = .{
    .module = "cursor",
    .name = "poke",
    .digest = hex32("a2f0dd58d07b9405c6859a9a0fa59a3438bdd6a4dab9bd79105860e8514c4155"),
    .n_params = 1,
    .locals = &.{.ref},
    .body = &.{ si(.MoveLoc, 0), si(.MutBorrowFieldGeneric, 0), si(.VecPopBack, TP0), si(.Ret, 0) },
};

/// `while (i < bound) { push_back(&mut dst, *borrow(&src, i)); i = i + 1 }` over `vector<u8>`
/// locals `dst` and `src` with a constant bound (the Pyth merkle byte copies).
fn copyImmShape(comptime name: []const u8, comptime group: Group, comptime locals: []const AK, comptime dst: u16, comptime src: u16, comptime i: u16, comptime bound: u64) Shape {
    return .{
        .name = name,
        .group = group,
        .kind = .copy,
        .body = &.{
            si(.CopyLoc, i),       ld(bound),          si(.Lt, 0),            si(.BrFalse, 16), si(.Branch, 5), si(.MutBorrowLoc, dst),
            si(.ImmBorrowLoc, src), si(.CopyLoc, i),   si(.VecImmBorrow, TU8), si(.ReadRef, 0),  si(.VecPushBack, TU8), si(.MoveLoc, i),
            ld(1),                 si(.Add, 0),        si(.StLoc, i),         si(.Branch, 0),
        },
        .locals = locals,
        .generic = false,
        .elem_u8 = true,
        .dst = .{ .how = .owned_local, .local = dst },
        .src = .{ .how = .owned_local, .local = src },
        .i = i,
        .bound = .imm,
        .bound_imm = bound,
    };
}

/// Wormhole bytes::take_u16_be / take_u32_be / take_u64_be: `bound` bytes folded into local 2.
fn beShape(comptime name: []const u8, comptime cast: ff.Opcode, comptime acc: AK, comptime bound: u64) Shape {
    return .{
        .name = name,
        .group = .take_be,
        .kind = .be_acc,
        .body = &.{
            si(.CopyLoc, 1), ld(bound),                 si(.Lt, 0),            si(.BrFalse, 18), si(.Branch, 5), si(.MoveLoc, 2),
            ld8(8),          si(.Shl, 0),               si(.CopyLoc, 0),       si(.CallGeneric, TU8), si(cast, 0), si(.Add, 0),
            si(.StLoc, 2),   si(.MoveLoc, 1),           ld(1),                 si(.Add, 0),      si(.StLoc, 1),  si(.Branch, 0),
        },
        .callee = &poke_callee,
        .locals = &.{ .ref, .u64, acc },
        .generic = false,
        .elem_u8 = true,
        .dst = .{ .how = .ref_field, .local = 0, .field = 0 },
        .src = .{ .how = .ref_field, .local = 0, .field = 0 },
        .i = 1,
        .j = 2,
        .bound = .imm,
        .bound_imm = bound,
    };
}

/// Every loop shape. `registry` points into this array; the index is the summary table's.
pub const shapes = [_]Shape{
    // 0: vector::reverse, framework snapshot 3 (an extra Branch after the guard)
    .{
        .name = "reverse_a",
        .group = .reverse,
        .kind = .reverse,
        .body = &.{
            si(.CopyLoc, 2), si(.CopyLoc, 1), si(.Lt, 0),        si(.BrFalse, 18), si(.Branch, 5), si(.CopyLoc, 0),
            si(.CopyLoc, 2), si(.CopyLoc, 1), si(.VecSwap, TP0), si(.MoveLoc, 2),  ld(1),          si(.Add, 0),
            si(.StLoc, 2),   si(.MoveLoc, 1), ld(1),             si(.Sub, 0),      si(.StLoc, 1),  si(.Branch, 0),
        },
        .locals = &.{ .ref, .u64, .u64, .any },
        .generic = true,
        .dst = .{ .how = .ref_local, .local = 0 },
        .i = 2,
        .j = 1,
    },
    // 1: vector::reverse, framework snapshots 42 to 122
    .{
        .name = "reverse_b",
        .group = .reverse,
        .kind = .reverse,
        .body = &.{
            si(.CopyLoc, 2), si(.CopyLoc, 1),   si(.Lt, 0),      si(.BrFalse, 17), si(.CopyLoc, 0), si(.CopyLoc, 2),
            si(.CopyLoc, 1), si(.VecSwap, TP0), si(.MoveLoc, 2), ld(1),            si(.Add, 0),     si(.StLoc, 2),
            si(.MoveLoc, 1), ld(1),             si(.Sub, 0),     si(.StLoc, 1),    si(.Branch, 0),
        },
        .locals = &.{ .ref, .u64, .u64, .any },
        .generic = true,
        .dst = .{ .how = .ref_local, .local = 0 },
        .i = 2,
        .j = 1,
    },
    // 2: vector::remove, framework snapshot 3
    .{
        .name = "remove_a",
        .group = .remove,
        .kind = .rotate,
        .body = &.{
            si(.CopyLoc, 1), si(.CopyLoc, 4), si(.Lt, 0),      si(.BrFalse, 18), si(.Branch, 5),  si(.CopyLoc, 0),
            si(.StLoc, 3),   si(.CopyLoc, 1), si(.StLoc, 2),   si(.MoveLoc, 1),  ld(1),           si(.Add, 0),
            si(.StLoc, 1),   si(.MoveLoc, 3), si(.MoveLoc, 2), si(.CopyLoc, 1),  si(.VecSwap, TP0), si(.Branch, 0),
        },
        .locals = &.{ .ref, .u64, .invalid, .invalid, .u64 },
        .generic = true,
        .dst = .{ .how = .ref_local, .local = 0 },
        .i = 1,
        .j = 4,
        .temps = &.{ 2, 3 },
    },
    // 3: vector::remove, framework snapshots 42 to 122
    .{
        .name = "remove_b",
        .group = .remove,
        .kind = .rotate,
        .body = &.{
            si(.CopyLoc, 1), si(.CopyLoc, 4), si(.Lt, 0),      si(.BrFalse, 17), si(.CopyLoc, 0),   si(.StLoc, 3),
            si(.CopyLoc, 1), si(.StLoc, 2),   si(.MoveLoc, 1), ld(1),            si(.Add, 0),       si(.StLoc, 1),
            si(.MoveLoc, 3), si(.MoveLoc, 2), si(.CopyLoc, 1), si(.VecSwap, TP0), si(.Branch, 0),
        },
        .locals = &.{ .ref, .u64, .invalid, .invalid, .u64 },
        .generic = true,
        .dst = .{ .how = .ref_local, .local = 0 },
        .i = 1,
        .j = 4,
        .temps = &.{ 2, 3 },
    },
    // 4: vector::append, framework snapshots 3 to 60: while (!is_empty(&other))
    .{
        .name = "append_a",
        .group = .append,
        .kind = .push_pop,
        .body = &.{
            si(.ImmBorrowLoc, 1), si(.CallGeneric, TP0), si(.Not, 0),          si(.BrFalse, 10),      si(.Branch, 5),
            si(.CopyLoc, 0),      si(.MutBorrowLoc, 1),  si(.VecPopBack, TP0), si(.VecPushBack, TP0), si(.Branch, 0),
        },
        .callee = &is_empty_callee,
        .locals = &.{ .ref, .vec },
        .generic = true,
        .dst = .{ .how = .ref_local, .local = 0 },
        .src = .{ .how = .owned_local, .local = 1 },
        .bound = .nonempty,
    },
    // 5: vector::append, framework snapshot 68: while (length(&other) != 0)
    .{
        .name = "append_b",
        .group = .append,
        .kind = .push_pop,
        .body = &.{
            si(.ImmBorrowLoc, 1), si(.VecLen, TP0),  ld(0),                si(.Neq, 0),          si(.BrFalse, 11),      si(.Branch, 6),
            si(.CopyLoc, 0),      si(.MutBorrowLoc, 1), si(.VecPopBack, TP0), si(.VecPushBack, TP0), si(.Branch, 0),
        },
        .locals = &.{ .ref, .vec },
        .generic = true,
        .dst = .{ .how = .ref_local, .local = 0 },
        .src = .{ .how = .owned_local, .local = 1 },
        .bound = .nonempty,
    },
    // 6: vector::append, framework snapshots 70 to 122: a counted loop
    .{
        .name = "append_c",
        .group = .append,
        .kind = .push_pop,
        .body = &.{
            si(.CopyLoc, 4),      si(.CopyLoc, 5),      si(.Lt, 0),    si(.BrFalse, 17), si(.CopyLoc, 4), si(.Pop, 0),
            si(.MutBorrowLoc, 6), si(.VecPopBack, TP0), si(.StLoc, 3), si(.CopyLoc, 0),  si(.MoveLoc, 3), si(.VecPushBack, TP0),
            si(.MoveLoc, 4),      ld(1),                si(.Add, 0),   si(.StLoc, 4),    si(.Branch, 0),
        },
        .locals = &.{ .ref, .any, .any, .invalid, .u64, .u64, .vec },
        .generic = true,
        .dst = .{ .how = .ref_local, .local = 0 },
        .src = .{ .how = .owned_local, .local = 6 },
        .i = 4,
        .j = 5,
        .temps = &.{3},
    },
    // 7: Wormhole bytes::take_bytes: while (i < n) { push_back(&mut out, cursor::poke(cur)); i = i + 1 }
    .{
        .name = "take_bytes",
        .group = .take_bytes,
        .kind = .push_pop,
        .body = &.{
            si(.CopyLoc, 2), si(.CopyLoc, 1),       si(.Lt, 0),            si(.BrFalse, 14), si(.Branch, 5), si(.MutBorrowLoc, 3),
            si(.CopyLoc, 0), si(.CallGeneric, TU8), si(.VecPushBack, TU8), si(.MoveLoc, 2),  ld(1),          si(.Add, 0),
            si(.StLoc, 2),   si(.Branch, 0),
        },
        .callee = &poke_callee,
        .locals = &.{ .ref, .u64, .u64, .vec },
        .generic = false,
        .elem_u8 = true,
        .dst = .{ .how = .owned_local, .local = 3 },
        .src = .{ .how = .ref_field, .local = 0, .field = 0 },
        .i = 2,
        .j = 1,
    },
    // 8: Pyth merkle_tree::hash: the first 20 bytes of the keccak digest
    copyImmShape("pyth_hash", .pyth_hash, &.{ .any, .vec, .vec, .u64 }, 1, 2, 3, 20),
    // 9: Pyth merkle_tree::leaf_hash: while (i < length(data)) push_back(&mut out, *borrow(data, i))
    .{
        .name = "pyth_leaf_hash",
        .group = .pyth_leaf_hash,
        .kind = .copy,
        .body = &.{
            si(.CopyLoc, 1),      si(.CopyLoc, 0), si(.VecLen, TU8), si(.Lt, 0),            si(.BrFalse, 17), si(.Branch, 6),
            si(.MutBorrowLoc, 2), si(.CopyLoc, 0), si(.CopyLoc, 1),  si(.VecImmBorrow, TU8), si(.ReadRef, 0),  si(.VecPushBack, TU8),
            si(.MoveLoc, 1),      ld(1),           si(.Add, 0),      si(.StLoc, 1),         si(.Branch, 0),
        },
        .locals = &.{ .ref, .u64, .vec },
        .generic = false,
        .elem_u8 = true,
        .dst = .{ .how = .owned_local, .local = 2 },
        .src = .{ .how = .ref_local, .local = 0 },
        .i = 1,
        .bound = .src_len,
    },
    // 10, 11: Pyth merkle_tree::node_hash: the two 20-byte children, one loop each
    copyImmShape("pyth_node_hash_l", .pyth_node_hash, &.{ .any, .any, .vec, .any, .u64, .any, .vec }, 6, 2, 4, 20),
    copyImmShape("pyth_node_hash_r", .pyth_node_hash, &.{ .any, .any, .any, .vec, .any, .u64, .vec }, 6, 3, 5, 20),
    // 12, 13, 14: Wormhole bytes::take_u16_be / take_u32_be / take_u64_be
    beShape("take_u16_be", .CastU16, .u16, 2),
    beShape("take_u32_be", .CastU32, .u32, 4),
    beShape("take_u64_be", .CastU64, .u64, 8),
};

pub const LoopT = struct { head: u16, shape: *const Shape };
pub const FnT = struct { name: []const u8, def_idx: u16, loops: []const LoopT };
pub const ModT = struct { name: []const u8, digest: [32]u8, fns: []const FnT };

fn vectorFns(comptime rev: u16, comptime rev_shape: usize, comptime app: u16, comptime app_head: u16, comptime app_shape: usize, comptime rem: u16, comptime rem_shape: usize) []const FnT {
    return &.{
        .{ .name = "reverse", .def_idx = rev, .loops = &.{.{ .head = 17, .shape = &shapes[rev_shape] }} },
        .{ .name = "append", .def_idx = app, .loops = &.{.{ .head = app_head, .shape = &shapes[app_shape] }} },
        .{ .name = "remove", .def_idx = rem, .loops = &.{.{ .head = 16, .shape = &shapes[rem_shape] }} },
    };
}

/// The modules with templates, by module name and code digest (`codeDigest`). An entry with no
/// functions is a known version without these loops, listed so it does not count as a miss.
pub const registry = [_]ModT{
    // Move stdlib `vector`, framework snapshot 3 (protocol 3 to 41)
    .{ .name = "vector", .digest = hex32("bf9660d5fd876e7bf7f4079d414856c256277f66a538090ef2c182c1cd6c77fc"), .fns = vectorFns(9, 0, 10, 2, 4, 14, 2) },
    // snapshots 42 (protocol 42 to 59) and 60 (60 to 67)
    .{ .name = "vector", .digest = hex32("e43405d1283e4f48da0fab771cf4bf3201cb8bae7c92d976e53cbfbcc91f0799"), .fns = vectorFns(9, 1, 10, 2, 4, 14, 3) },
    .{ .name = "vector", .digest = hex32("031a5d258865ceae89d5570aa7d1a5e5a9b58bc75917378372bd789afb55ae7c"), .fns = vectorFns(9, 1, 10, 2, 4, 14, 3) },
    // snapshot 68 (68 to 69)
    .{ .name = "vector", .digest = hex32("1229df190237c89946f9ae9e98c74a4cae4511fee75408f2f10953ad1bee6768"), .fns = vectorFns(9, 1, 10, 2, 5, 14, 3) },
    // snapshots 70 (70 to 89) and 90 (90 to 121)
    .{ .name = "vector", .digest = hex32("44b7b751b0fd8e320181f5f2e985b1b36069781c2f25863caa87a03bbc5357a3"), .fns = vectorFns(9, 1, 10, 11, 6, 14, 3) },
    .{ .name = "vector", .digest = hex32("83603dd5c1fd865fe615136e8ec0e30f8ac0510c7954feb20ec3051d7bad8b07"), .fns = vectorFns(9, 1, 10, 11, 6, 14, 3) },
    // snapshot 122 (122 to 139)
    .{ .name = "vector", .digest = hex32("39140f24c26538a56a6ecfb8a8f794d3664cf0619b89d2cbeafb39f7fc243e9d"), .fns = vectorFns(7, 1, 8, 11, 6, 12, 3) },
    // snapshots 140 and 142 (the 1.83 stdlib): `reverse` is native and `append` / `remove` call
    // the `replace_range` native: no loops left
    .{ .name = "vector", .digest = hex32("af7b18c67c3800679d620cfe8e40c29ff610b63f3c4f5bf5c30b16cbfce3afb7"), .fns = &.{} },
    // Wormhole `bytes` (0x5306..fb6a version 1; the same code at 0x99de..25b4)
    .{ .name = "bytes", .digest = hex32("6e6da9e6a2138e01f35363ebe0dd772a134e09649350fcd12173c3733ea2803e"), .fns = &.{
        .{ .name = "take_bytes", .def_idx = 12, .loops = &.{.{ .head = 4, .shape = &shapes[7] }} },
        .{ .name = "take_u16_be", .def_idx = 7, .loops = &.{.{ .head = 4, .shape = &shapes[12] }} },
        .{ .name = "take_u32_be", .def_idx = 8, .loops = &.{.{ .head = 4, .shape = &shapes[13] }} },
        .{ .name = "take_u64_be", .def_idx = 9, .loops = &.{.{ .head = 4, .shape = &shapes[14] }} },
    } },
    // Pyth `merkle_tree` (0x8d97..5a9e version 2, package 0x04e2..ad91; the same code at
    // 0x5530..e2c0)
    .{ .name = "merkle_tree", .digest = hex32("80c8a71d809a8c7bf256d9bfc43252b13b8a693c673d968e653638791ce2de82"), .fns = &.{
        .{ .name = "hash", .def_idx = 0, .loops = &.{.{ .head = 7, .shape = &shapes[8] }} },
        .{ .name = "leaf_hash", .def_idx = 2, .loops = &.{.{ .head = 5, .shape = &shapes[9] }} },
        .{ .name = "node_hash", .def_idx = 3, .loops = &.{ .{ .head = 19, .shape = &shapes[10] }, .{ .head = 37, .shape = &shapes[11] } } },
    } },
};

comptime {
    // a function's loops count in one group (`attach` counts the function there)
    for (registry) |e| for (e.fns) |ft| for (ft.loops) |l| {
        if (l.shape.group != ft.loops[0].shape.group) @compileError("loopaccel: the loops of " ++ ft.name ++ " are in different groups");
    };
}

/// The deployments whose modules are expected to match: one of these with another bytecode is
/// counted (and logged) as a digest miss. Modules of the same name anywhere else are not.
pub const std_addr: [32]u8 = hex32("0000000000000000000000000000000000000000000000000000000000000001");
pub const wormhole_addr: [32]u8 = hex32("5306f64e312b581766351c07af79c72fcb1cd25147157fdc2f8ad76de9a3fb6a");
pub const wormhole2_addr: [32]u8 = hex32("99de5c967d8206ef4b75c0afab3df2a59eb02b05c282821db803831008ac25b4");
pub const pyth_addr: [32]u8 = hex32("8d97f1cd6ac663735be08d1d2b6d02a159e711586461306ce60a2b7a6a565a9e");
pub const pyth2_addr: [32]u8 = hex32("55300367a2d40813727ccac4ecee977a39fb9cdb46f2e6b2c354b9798f5de2c0");
// (Pyth's first deployment is not listed: its version 1 code, which has none of these loops,
// has the same self address as the version 2 code that matches.)
const known = [_]struct { name: []const u8, addr: [32]u8 }{
    .{ .name = "vector", .addr = std_addr },
    .{ .name = "bytes", .addr = wormhole_addr },
    .{ .name = "bytes", .addr = wormhole2_addr },
    .{ .name = "merkle_tree", .addr = pyth2_addr },
};

/// Digest of a module's code without its address: the module name and every function's
/// instruction stream and jump tables, fields fully decoded (what `aot_rt.digestModule` hashes,
/// minus the self address). Equal for every deployment of the same bytecode.
pub fn codeDigest(cm: *const ff.CompiledModule) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2b256.init(.{});
    h.update("zui-loopaccel-v1");
    const name = cm.selfName();
    hashInt(&h, u32, @intCast(name.len));
    h.update(name);
    hashInt(&h, u32, @intCast(cm.function_defs.len));
    for (cm.function_defs) |fd| {
        const c = fd.code orelse {
            h.update(&.{0});
            continue;
        };
        h.update(&.{1});
        hashInt(&h, u32, @intCast(cm.signatures[cm.function_handles[fd.function].parameters].len));
        hashInt(&h, u32, @intCast(cm.signatures[c.locals].len));
        hashInt(&h, u32, @intCast(c.code.len));
        for (c.code) |ins| {
            h.update(&.{@intFromEnum(ins.op)});
            hashInt(&h, u16, ins.idx);
            hashInt(&h, u64, ins.imm);
        }
        hashInt(&h, u32, @intCast(c.jump_tables.len));
        for (c.jump_tables) |jt| {
            hashInt(&h, u16, jt.head_enum);
            hashInt(&h, u32, @intCast(jt.offsets.len));
            for (jt.offsets) |o| hashInt(&h, u16, o);
        }
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn hashInt(h: *std.crypto.hash.blake2.Blake2b256, comptime T: type, v: T) void {
    var b: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &b, v, .little);
    h.update(&b);
}

fn hex32(comptime s: *const [64]u8) [32]u8 {
    @setEvalBranchQuota(4000);
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn shapeIndex(shape: *const Shape) usize {
    return (@intFromPtr(shape) - @intFromPtr(&shapes[0])) / @sizeOf(Shape);
}

// ---------------------------------------------------------------------------------------------
// One iteration's charges, measured on the meter's own functions

/// What one iteration charges and needs, under constant tier multipliers.
pub const Summary = struct {
    valid: bool = false,
    /// Instructions (the caller's and the callee's).
    n: u64 = 0,
    /// Sum of the size increases and of the pushes.
    s: u64 = 0,
    p: u64 = 0,
    /// Net change of the meter's stack height (not zero where a gas model's charge pops less
    /// than the instruction does).
    d: i64 = 0,
    /// Highest height an instruction reaches after its pushes, and lowest height after an
    /// instruction's pops, both relative to the height at the head.
    hmax: i64 = 0,
    hmin: i64 = 0,
    /// Most operand stack slots in use above the head's depth.
    depth: u32 = 0,
};

/// The highest gas model version there is in sui 1.83.1: 15, set at protocol 138 (the last
/// `gas_model_version` of `sui-protocol-config`, and of deepwave's protocol tables). The summaries
/// are built for the versions up to it. A session with a later one is never accelerated: a
/// gas model nobody has seen stays in the interpreter until this is raised and the tests
/// (which cover every version up to this) are run for it.
pub const MAX_GM: u64 = 15;
const N_EK = @typeInfo(value.Kind).@"enum".field_names.len;

var summaries: [shapes.len][MAX_GM + 1][N_EK]Summary = undefined;

fn buildSummaries() void {
    for (&shapes, 0..) |*shape, i| {
        for (0..MAX_GM + 1) |gm| {
            for (0..N_EK) |ek| summaries[i][gm][ek] = summarize(shape, gm, @enumFromInt(@as(u8, @intCast(ek))));
        }
    }
}

/// The summary of `shape` for gas model `gm` when the loop's vector has kind `ek` (invalid when
/// the gas model is later than `MAX_GM`, a charge would depend on the data, or the body does
/// something `Abs` does not model).
pub fn summarize(shape: *const Shape, gm: u64, ek: value.Kind) Summary {
    if (gm > MAX_GM) return .{};
    if (!ek.isVector()) return .{};
    if (shape.elem_u8 and ek != .vec_u8) return .{};
    var a: Abs = .{ .m = gas.Meter.init(gm, 0, 1), .ek = ek };
    // a meter that never leaves the fast path: no tier ahead, plenty of gas, a height far
    // from zero; the multipliers are 1 so the gas deducted counts the three charge parts
    a.m.gas_left = 1 << 60;
    a.m.initial_budget = 1 << 60;
    a.m.stack_height_current = Abs.BASE;
    a.m.stack_height_next_tier_start = null;
    a.m.stack_size_next_tier_start = null;
    a.m.instructions_next_tier_start = null;
    a.m.stack_height_current_tier_mult = 1;
    a.m.stack_size_current_tier_mult = 1;
    a.m.instructions_current_tier_mult = 1;
    var locals: [16]AK = undefined;
    if (shape.locals.len > locals.len) return .{};
    @memcpy(locals[0..shape.locals.len], shape.locals);
    const frame = locals[0..shape.locals.len];
    for (shape.body, 0..) |ins, idx| {
        const last = idx + 1 == shape.body.len;
        switch (ins.op) {
            // the path through an iteration is straight: guards fall through, an inner Branch
            // goes to the next instruction, the last Branch goes back to the head
            .Branch => if (ins.x != (if (last) 0 else @as(i32, @intCast(idx)) + 1)) return .{},
            .BrFalse, .BrTrue => if (ins.x >= 0 and @as(usize, @intCast(ins.x)) < shape.body.len) return .{},
            .CallGeneric, .Call => {
                const callee = shape.callee orelse return .{};
                a.call(callee) catch return .{};
                continue;
            },
            .Ret => return .{},
            else => if (last) return .{},
        }
        a.step(frame, ins) catch return .{};
    }
    // periodic: the operand stack is back at the head's depth and the locals are as declared
    if (a.sp != 0) return .{};
    for (frame, shape.locals) |x, y| if (x != y) return .{};
    a.sum.valid = true;
    return a.sum;
}

const Abs = struct {
    m: gas.Meter,
    ek: value.Kind,
    stack: [16]AK = undefined,
    sp: u32 = 0,
    sum: Summary = .{},
    /// Meter height relative to the head.
    rel: i64 = 0,

    const BASE: u64 = 1 << 40;
    const Unsupported = error{Unsupported};

    fn push(a: *Abs, k: AK) Unsupported!void {
        if (a.sp >= a.stack.len) return error.Unsupported;
        a.stack[a.sp] = k;
        a.sp += 1;
        a.sum.depth = @max(a.sum.depth, a.sp);
    }
    fn pop(a: *Abs) Unsupported!AK {
        if (a.sp == 0) return error.Unsupported;
        a.sp -= 1;
        return a.stack[a.sp];
    }
    fn popIs(a: *Abs, k: AK) Unsupported!void {
        if (try a.pop() != k) return error.Unsupported;
    }

    /// Abstract size of a value of kind `k` under `cfg`, when it does not depend on the data.
    fn size(a: *const Abs, k: AK, cfg: gas.SizeCfg) Unsupported!u64 {
        var slot: Value = Value.invalid;
        const zero: [32]u8 = @splat(0);
        return switch (k) {
            .u8 => value.size(Value.u8_(0), cfg),
            .u16 => value.size(Value.u16_(0), cfg),
            .u32 => value.size(Value.u32_(0), cfg),
            .u64 => value.size(Value.u64_(0), cfg),
            .bool => value.size(Value.bool_(false), cfg),
            // a reference counts its referent only under a traversing config
            .ref, .ref_elem => if (cfg.traverse_references) error.Unsupported else value.size(Value.refSlot(&slot), cfg),
            .elem => blk: {
                const t = a.ek.elemTag();
                if (t == .invalid) return error.Unsupported;
                break :blk value.size(.{ .tag = t, .a = @intFromPtr(&zero) }, cfg);
            },
            else => error.Unsupported,
        };
    }

    /// Values a slot can be overwritten with or popped without freeing anything.
    fn plain(k: AK) bool {
        return switch (k) {
            .invalid, .u8, .u16, .u32, .u64, .bool, .ref, .ref_elem => true,
            else => false,
        };
    }

    fn begin(a: *Abs) gas.Meter {
        a.m.stack_height_high_water_mark = a.m.stack_height_current;
        return a.m;
    }

    /// Reads what the charge just made did to the meter: (pushes, pops, size increase).
    fn account(a: *Abs, b: *const gas.Meter) Unsupported!void {
        const m = &a.m;
        const pushes = m.stack_height_high_water_mark - b.stack_height_current;
        const pops = b.stack_height_current + pushes - m.stack_height_current;
        const incr = m.stack_size_current - b.stack_size_current;
        const n = m.instructions_executed - b.instructions_executed;
        // the three multipliers are 1: the gas deducted is the sum of the three parts
        if (b.gas_left - m.gas_left != n + incr + pushes) return error.Unsupported;
        if (n != 1 or pushes > 64 or pops > 64 or incr > (1 << 20)) return error.Unsupported;
        a.sum.n += n;
        a.sum.s += incr;
        a.sum.p += pushes;
        const top = a.rel + @as(i64, @intCast(pushes));
        a.sum.hmax = @max(a.sum.hmax, top);
        a.rel = top - @as(i64, @intCast(pops));
        a.sum.hmin = @min(a.sum.hmin, a.rel);
        a.sum.d = a.rel;
    }

    /// One instruction other than a call, as `Session.op` charges and executes it.
    fn step(a: *Abs, locals: []AK, ins: SI) Unsupported!void {
        const b = a.begin();
        const m = &a.m;
        const x: usize = if (ins.x >= 0) @intCast(ins.x) else 0;
        switch (ins.op) {
            .CopyLoc => {
                if (x >= locals.len) return error.Unsupported;
                const k = locals[x];
                if (k == .invalid or k == .any or !plain(k)) return error.Unsupported;
                m.chargeCopyLoc(try a.size(k, m.plain)) catch return error.Unsupported;
                try a.push(k);
            },
            .MoveLoc => {
                if (x >= locals.len) return error.Unsupported;
                const k = locals[x];
                if (k == .invalid or k == .any) return error.Unsupported;
                locals[x] = .invalid;
                const sz = if (m.moveLocNeedsSize()) try a.size(k, m.plain) else 0;
                m.chargeMoveLoc(sz) catch return error.Unsupported;
                try a.push(k);
            },
            .StLoc => {
                if (x >= locals.len) return error.Unsupported;
                const k = try a.pop();
                m.chargeStoreLoc() catch return error.Unsupported;
                if (!plain(locals[x])) return error.Unsupported;
                locals[x] = k;
            },
            .Pop => {
                const k = try a.pop();
                m.chargePop() catch return error.Unsupported;
                if (!plain(k)) return error.Unsupported;
            },
            .LdU8 => {
                m.chargeSimple(.LdU8) catch return error.Unsupported;
                try a.push(.u8);
            },
            .LdU64 => {
                m.chargeSimple(.LdU64) catch return error.Unsupported;
                try a.push(.u64);
            },
            .ImmBorrowLoc, .MutBorrowLoc => {
                if (x >= locals.len or locals[x] != .vec) return error.Unsupported;
                (if (ins.op == .ImmBorrowLoc) m.chargeSimple(.ImmBorrowLoc) else m.chargeSimple(.MutBorrowLoc)) catch return error.Unsupported;
                try a.push(.ref);
            },
            .ImmBorrowFieldGeneric, .MutBorrowFieldGeneric => {
                (if (ins.op == .ImmBorrowFieldGeneric) m.chargeSimple(.ImmBorrowFieldGeneric) else m.chargeSimple(.MutBorrowFieldGeneric)) catch return error.Unsupported;
                try a.popIs(.ref);
                try a.push(.ref);
            },
            .BrFalse, .BrTrue => {
                (if (ins.op == .BrFalse) m.chargeSimple(.BrFalse) else m.chargeSimple(.BrTrue)) catch return error.Unsupported;
                try a.popIs(.bool);
            },
            .Branch => m.chargeSimple(.Branch) catch return error.Unsupported,
            .Not => {
                m.chargeSimple(.Not) catch return error.Unsupported;
                try a.popIs(.bool);
                try a.push(.bool);
            },
            .Add, .Sub => {
                (if (ins.op == .Add) m.chargeSimple(.Add) else m.chargeSimple(.Sub)) catch return error.Unsupported;
                const r = try a.pop();
                const l = try a.pop();
                if (l != r or !(l == .u16 or l == .u32 or l == .u64)) return error.Unsupported;
                try a.push(l);
            },
            .Shl => {
                m.chargeSimple(.Shl) catch return error.Unsupported;
                try a.popIs(.u8);
                const l = try a.pop();
                if (!(l == .u16 or l == .u32 or l == .u64)) return error.Unsupported;
                try a.push(l);
            },
            .CastU16, .CastU32, .CastU64 => {
                switch (ins.op) {
                    .CastU16 => m.chargeSimple(.CastU16) catch return error.Unsupported,
                    .CastU32 => m.chargeSimple(.CastU32) catch return error.Unsupported,
                    else => m.chargeSimple(.CastU64) catch return error.Unsupported,
                }
                // only a byte is cast (it always fits)
                const k = try a.pop();
                if (!(k == .u8 or (k == .elem and a.ek == .vec_u8))) return error.Unsupported;
                try a.push(switch (ins.op) {
                    .CastU16 => .u16,
                    .CastU32 => .u32,
                    else => .u64,
                });
            },
            .Lt => {
                m.chargeSimple(.Lt) catch return error.Unsupported;
                try a.popIs(.u64);
                try a.popIs(.u64);
                try a.push(.bool);
            },
            .Eq, .Neq => {
                const l = try a.pop();
                const r = try a.pop();
                if (l != .u64 or r != .u64) return error.Unsupported;
                const ls = try a.size(l, m.traversal);
                const rs = try a.size(r, m.traversal);
                (if (ins.op == .Eq) m.chargeEq(ls, rs) else m.chargeNeq(ls, rs)) catch return error.Unsupported;
                try a.push(.bool);
            },
            .VecLen => {
                try a.popIs(.ref);
                m.chargeVecLen() catch return error.Unsupported;
                try a.push(.u64);
            },
            .VecImmBorrow => {
                try a.popIs(.u64);
                try a.popIs(.ref);
                m.chargeVecBorrow() catch return error.Unsupported;
                // an element of a primitive vector is borrowed by index; anything else by slot
                if (!a.ek.isPrimVec()) return error.Unsupported;
                try a.push(.ref_elem);
            },
            .ReadRef => {
                try a.popIs(.ref_elem);
                var dummy: Container = .{ .kind = a.ek, .len = 1, .cap = 1, .data = undefined };
                const r = Value.refElem(&dummy, 0);
                m.chargeReadRef(value.referentSize(r, m.plain), value.referentSize(r, m.traversal)) catch return error.Unsupported;
                try a.push(.elem);
            },
            .VecPushBack => {
                try a.popIs(.elem);
                try a.popIs(.ref);
                m.chargeVecPushBack() catch return error.Unsupported;
            },
            .VecPopBack => {
                try a.popIs(.ref);
                m.chargeVecPopBack() catch return error.Unsupported;
                try a.push(.elem);
            },
            .VecSwap => {
                try a.popIs(.u64);
                try a.popIs(.u64);
                try a.popIs(.ref);
                m.chargeVecSwap() catch return error.Unsupported;
            },
            else => return error.Unsupported,
        }
        try a.account(&b);
    }

    /// A call of `callee`: the Call charge, the body, the Ret.
    fn call(a: *Abs, callee: *const Callee) Unsupported!void {
        var locals: [8]AK = undefined;
        if (callee.locals.len > locals.len or callee.n_params > callee.locals.len) return error.Unsupported;
        const frame = locals[0..callee.locals.len];
        @memset(frame, .invalid);
        {
            const b = a.begin();
            a.m.chargeCall(callee.n_params) catch return error.Unsupported;
            var i: usize = callee.n_params;
            while (i > 0) : (i -= 1) {
                frame[i - 1] = try a.pop();
                if (frame[i - 1] != callee.locals[i - 1]) return error.Unsupported;
            }
            try a.account(&b);
        }
        for (callee.body, 0..) |ins, idx| {
            if (idx + 1 == callee.body.len) {
                if (ins.op != .Ret) return error.Unsupported;
                const b = a.begin();
                a.m.chargeSimple(.Ret) catch return error.Unsupported;
                // the frame's locals are dropped: nothing in them may own memory
                for (frame) |k| if (!plain(k)) return error.Unsupported;
                try a.account(&b);
                return;
            }
            switch (ins.op) {
                .Ret, .Call, .CallGeneric, .Branch, .BrFalse, .BrTrue => return error.Unsupported,
                else => try a.step(frame, ins),
            }
        }
        return error.Unsupported;
    }
};

// ---------------------------------------------------------------------------------------------
// Attaching

pub const Loop = struct {
    head: u16,
    shape: *const Shape,
    shape_idx: u16,
};

/// What `Function.accel` points to.
pub const Attached = struct {
    loops: []const Loop,
};

/// The loader's attach point: called with every newly loaded, accepted package. Sets
/// `Function.accel` for every function whose module digest and loop bodies match a template.
pub fn attach(p: *loader.Package) void {
    if (!decided.load(.acquire)) decide();
    if (!on.load(.monotonic)) return;
    for (p.modules) |*m| {
        // hash the module's code only when a module of this name is registered
        const named = for (&registry) |*r| {
            if (std.mem.eql(u8, r.name, m.name)) break true;
        } else false;
        if (!named) continue;
        const digest = codeDigest(&m.cm);
        const e = for (&registry) |*r| {
            if (std.mem.eql(u8, &r.digest, &digest) and std.mem.eql(u8, r.name, m.name)) break r;
        } else {
            // another module of that name: a miss only in a deployment that should match
            const expected = for (&known) |*k| {
                if (std.mem.eql(u8, k.name, m.name) and std.mem.eql(u8, &k.addr, m.cm.selfAddress())) break true;
            } else false;
            if (expected and attach_stats.modules_digest_miss.fetchAdd(1, .monotonic) < 8)
                std.log.info("vm-loopaccel: {x}::{s} has bytecode with no loop template (code digest {x}); it runs in the interpreter", .{ m.cm.selfAddress().*, m.name, digest });
            continue;
        };
        _ = attach_stats.modules_matched.fetchAdd(1, .monotonic);
        for (e.fns) |*ft| {
            const g = totals.of(ft.loops[0].shape.group);
            if (attachFn(p, m, ft)) {
                _ = attach_stats.functions_attached.fetchAdd(1, .monotonic);
                _ = g.attached.fetchAdd(1, .monotonic);
                continue;
            }
            _ = g.mismatches.fetchAdd(1, .monotonic);
            if (attach_stats.template_mismatch.fetchAdd(1, .monotonic) < 8) {
                std.log.warn("vm-loopaccel: {x}::{s}::{s} has registered code, but what its loop resolves to (the module it calls, or a table entry) is not the registered template, as after an upgrade of the called module alone; it runs in the interpreter", .{ m.cm.selfAddress().*, m.name, ft.name });
            }
        }
    }
}

fn attachFn(p: *loader.Package, m: *loader.Module, ft: *const FnT) bool {
    if (ft.def_idx >= m.functions.len) return false;
    const f = &m.functions[ft.def_idx];
    if (f.is_native or !std.mem.eql(u8, f.name, ft.name)) return false;
    for (ft.loops) |lt| if (!matches(m, f, lt.head, lt.shape)) return false;
    const arena = p.rt.arena_state.allocator();
    const at = arena.create(Attached) catch return false;
    const loops = arena.alloc(Loop, ft.loops.len) catch return false;
    for (ft.loops, loops) |lt, *l| l.* = .{ .head = lt.head, .shape = lt.shape, .shape_idx = @intCast(shapeIndex(lt.shape)) };
    at.* = .{ .loops = loops };
    f.accel = at;
    return true;
}

/// The loop body of `shape` is at `head` in `f`, instruction for instruction, with every table
/// operand resolved in `m`.
fn matches(m: *loader.Module, f: *const loader.Function, head: u16, shape: *const Shape) bool {
    if (f.n_locals != shape.locals.len) return false;
    if (f.n_type_params != @intFromBool(shape.generic)) return false;
    if (@as(usize, head) + shape.body.len > f.code.len) return false;
    for (shape.body, f.code[head..][0..shape.body.len]) |t, ins| {
        if (!sameInstr(m, f, head, t, ins, shape.callee)) return false;
    }
    return true;
}

fn tokenIs(m: *const loader.Module, sig: u16, want: i32) bool {
    if (sig >= m.cm.signatures.len) return false;
    const s = m.cm.signatures[sig];
    if (s.len != 1 or s[0].len != 1) return false;
    const node = s[0][0];
    return switch (want) {
        TP0 => node.tag == .TypeParameter and node.idx == 0,
        TU8 => node.tag == .U8,
        else => false,
    };
}

fn sameInstr(m: *loader.Module, f: *const loader.Function, head: u16, t: SI, ins: ff.Instr, callee: ?*const Callee) bool {
    if (ins.op != t.op) return false;
    switch (t.op) {
        .CopyLoc, .MoveLoc, .StLoc, .ImmBorrowLoc, .MutBorrowLoc => return ins.imm == 0 and @as(i32, ins.idx) == t.x and ins.idx < f.n_locals,
        .BrTrue, .BrFalse, .Branch => return ins.imm == 0 and @as(i32, ins.idx) == @as(i32, head) + t.x,
        .LdU8, .LdU64 => return ins.idx == 0 and ins.imm == t.imm,
        .VecLen, .VecImmBorrow, .VecMutBorrow, .VecPushBack, .VecPopBack, .VecSwap => return ins.imm == 0 and tokenIs(m, ins.idx, t.x),
        .ImmBorrowFieldGeneric, .MutBorrowFieldGeneric => {
            if (ins.imm != 0 or ins.idx >= m.cm.field_instantiations.len) return false;
            const fh = m.cm.field_instantiations[ins.idx].handle;
            return fh < m.cm.field_handles.len and @as(i32, m.cm.field_handles[fh].field) == t.x;
        },
        .CallGeneric => {
            const c = callee orelse return false;
            if (ins.imm != 0 or ins.idx >= m.cm.function_instantiations.len) return false;
            const fi = m.cm.function_instantiations[ins.idx];
            if (!tokenIs(m, fi.type_parameters, t.x)) return false;
            // the target is fixed at load: a function of the same package
            const target = m.local_calls[fi.handle] orelse return false;
            return calleeMatches(m, target, c);
        },
        .Add, .Sub, .Lt, .Not, .Eq, .Neq, .Pop, .ReadRef, .Ret, .Shl, .CastU16, .CastU32, .CastU64 => return ins.idx == 0 and ins.imm == 0,
        else => return false,
    }
}

fn calleeMatches(caller: *const loader.Module, target: *const loader.Function, c: *const Callee) bool {
    if (target.is_native or !std.mem.eql(u8, target.name, c.name)) return false;
    const tm = target.module;
    if (!std.mem.eql(u8, tm.name, c.module)) return false;
    if (c.digest) |d| {
        const have = codeDigest(&tm.cm);
        if (!std.mem.eql(u8, &have, &d)) return false;
    } else if (tm != caller) return false;
    if (target.params.len != c.n_params or target.n_locals != c.locals.len or target.n_type_params != 1) return false;
    if (target.code.len != c.body.len) return false;
    for (c.body, target.code) |t, ins| {
        // a callee body is straight-line code with no calls (`Abs.call` refuses anything else)
        switch (t.op) {
            .BrTrue, .BrFalse, .Branch, .Call, .CallGeneric => return false,
            else => {},
        }
        if (!sameInstr(tm, target, 0, t, ins, null)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------------------------
// The runner and the accelerator

/// The interpreter hook (`Session.stepRun`): runs the current frame's instructions from `f.pc`
/// until a call, a return or an error, exactly like `stepRun`, and returns what it returns.
/// Every instruction goes through `Session.op`, the same implementation the traced loop and the
/// aot tier use, so charges, results and error locations are the interpreter's; at a loop head
/// `accelerate` may first apply whole iterations.
pub fn run(s: *Session, f: *Frame) interp.StepError!bool {
    const at: *const Attached = @ptrCast(@alignCast(f.func.accel.?));
    const code = f.func.code;
    var pc = f.pc;
    while (true) {
        f.pc = pc;
        if (pc >= code.len) return s.stepUntraced();
        for (at.loops) |*lp| if (lp.head == pc) {
            accelerate(s, f, lp);
            break;
        };
        const ins = code[pc];
        switch (ins.op) {
            .Ret, .Call, .CallGeneric => return s.stepUntraced(),
            else => {},
        }
        pc = Session.op(s, f, ins, pc) catch |e| {
            if (e == error.Vm) s.atFrame(f);
            return e;
        };
    }
}

/// Frames with more type nodes in their type arguments than this are left to the interpreter.
/// Under it no instantiation check of a template can fail: a template's tokens are a single
/// type parameter or a primitive, so `checkSubst` sees at most 1 + 16 nodes and `checkCallInst`
/// at most 1 + 16 + 16 against the limit of 128, in the latest VM and in the v0..v3 rules.
pub const MAX_TY_NODES: u64 = 16;
/// Slack kept below the operand stack and call depth limits.
const LIMIT_SLACK: usize = 8;

const Plan = struct {
    kmax: u64,
    dst: *Container,
    src: ?*Container = null,
    i: u64 = 0,
    j: u64 = 0,
};

fn vecAt(f: *const Frame, at: VecAt) ?*Container {
    if (at.local >= f.locals.len) return null;
    const l = f.locals[at.local];
    const c: *Container = switch (at.how) {
        .none => return null,
        .owned_local => blk: {
            if (l.tag != .container) return null;
            break :blk l.cont();
        },
        .ref_local => blk: {
            if (l.tag != .ref_slot) return null;
            const v = l.slot().*;
            if (v.tag != .container) return null;
            break :blk v.cont();
        },
        .ref_field => blk: {
            if (l.tag != .ref_slot) return null;
            const v = l.slot().*;
            if (v.tag != .container) return null;
            const st = v.cont();
            if (st.kind != .struct_ or at.field >= st.len) return null;
            const fv = st.values()[at.field];
            if (fv.tag != .container) return null;
            break :blk fv.cont();
        },
    };
    return if (c.kind.isVector()) c else null;
}

/// Checks the frame against the shape and returns how many iterations the guard allows with no
/// fault, and what they work on. Null: not a state this shape accelerates.
fn plan(s: *const Session, f: *const Frame, shape: *const Shape) ?Plan {
    if (f.locals.len != shape.locals.len) return null;
    for (shape.locals, f.locals) |ak, v| {
        const ok = switch (ak) {
            .any => true,
            .invalid => v.tag == .invalid,
            .u8 => v.tag == .u8,
            .u16 => v.tag == .u16,
            .u32 => v.tag == .u32,
            .u64 => v.tag == .u64,
            .bool => v.tag == .bool,
            .ref => v.tag == .ref_slot,
            .vec => v.tag == .container,
            .ref_elem, .elem => false,
        };
        if (!ok) return null;
    }
    const dst = vecAt(f, shape.dst) orelse return null;
    if (shape.elem_u8 and dst.kind != .vec_u8) return null;
    const len_max: u64 = @min(s.cfg.vector_len_max, std.math.maxInt(u32));
    switch (shape.kind) {
        .reverse => {
            const i = f.locals[shape.i].a;
            const j = f.locals[shape.j].a;
            // swap(i, j) with i < j is in range when j is
            if (i >= j or j >= dst.len) return null;
            return .{ .kmax = (j - i + 1) / 2, .dst = dst, .i = i, .j = j };
        },
        .rotate => {
            const i = f.locals[shape.i].a;
            const j = f.locals[shape.j].a;
            // swap(i, i + 1) is in range while i + 1 < len
            if (i >= j or dst.len == 0 or i >= dst.len - 1) return null;
            return .{ .kmax = @min(j - i, dst.len - 1 - i), .dst = dst, .i = i, .j = j };
        },
        .push_pop => {
            const src = vecAt(f, shape.src) orelse return null;
            if (src == dst or src.kind != dst.kind) return null;
            var k: u64 = src.len;
            var i: u64 = 0;
            if (shape.bound == .local) {
                i = f.locals[shape.i].a;
                const j = f.locals[shape.j].a;
                if (i >= j) return null;
                k = @min(k, j - i);
            } else if (shape.bound != .nonempty) return null;
            if (dst.len >= len_max) return null;
            k = @min(k, len_max - dst.len);
            return .{ .kmax = k, .dst = dst, .src = src, .i = i };
        },
        .copy => {
            const src = vecAt(f, shape.src) orelse return null;
            if (src == dst or src.kind != dst.kind or !dst.kind.isPrimVec()) return null;
            const i = f.locals[shape.i].a;
            const bound: u64 = switch (shape.bound) {
                .imm => shape.bound_imm,
                .src_len => src.len,
                else => return null,
            };
            if (i >= bound or i >= src.len or dst.len >= len_max) return null;
            return .{ .kmax = @min(bound - i, src.len - i, len_max - dst.len), .dst = dst, .src = src, .i = i };
        },
        .be_acc => {
            // dst is the source here (one vector, read from its tail)
            if (shape.bound != .imm or dst.kind != .vec_u8) return null;
            const i = f.locals[shape.i].a;
            if (i >= shape.bound_imm) return null;
            return .{ .kmax = @min(shape.bound_imm - i, dst.len), .dst = dst, .i = i };
        },
    }
}

/// How many of `kmax` iterations stay inside `Meter.charge`'s fast path from the meter's state:
/// no tier start passed by any counter, no pop below zero, gas for all of them.
fn window(m: *const gas.Meter, sum: *const Summary, kmax: u64) u64 {
    const far: u64 = 1 << 62;
    const im = m.instructions_current_tier_mult;
    const sm = m.stack_size_current_tier_mult;
    const hm = m.stack_height_current_tier_mult;
    if (m.instructions_executed >= far or m.stack_size_current >= far or m.stack_height_current >= far) return 0;
    if (im >= (1 << 24) or sm >= (1 << 24) or hm >= (1 << 24)) return 0;
    var k: u64 = @min(kmax, 1 << 32);
    // instruction count: instr + k*n <= next
    if (m.instructions_next_tier_start) |next| {
        if (next < m.instructions_executed) return 0;
        k = @min(k, (next - m.instructions_executed) / sum.n);
    }
    // stack size (it only grows): size + k*s <= next
    if (m.stack_size_next_tier_start) |next| {
        if (next < m.stack_size_current) return 0;
        if (sum.s != 0) k = @min(k, (next - m.stack_size_current) / sum.s);
    }
    // stack height: iteration t (from 0) reaches h + t*d + hmax and goes down to h + t*d + hmin
    const h: i128 = m.stack_height_current;
    if (h + sum.hmin < 0) return 0;
    const next_h: ?i128 = if (m.stack_height_next_tier_start) |next| next else null;
    if (next_h) |next| {
        if (h + sum.hmax > next) return 0;
        if (sum.d > 0) k = @min(k, @as(u64, @intCast(@divFloor(next - h - sum.hmax, @as(i128, sum.d)))) + 1);
    }
    if (sum.d < 0) k = @min(k, @as(u64, @intCast(@divFloor(h + sum.hmin, -@as(i128, sum.d)))) + 1);
    // gas: one iteration costs im*n + sm*s + hm*p (no product can overflow: see the bounds above
    // and in `Abs.account`)
    const cost = im * sum.n + sm * sum.s + hm * sum.p;
    if (cost != 0) k = @min(k, m.gas_left / cost);
    return k;
}

/// What `k` iterations charge (k is inside `window`).
fn commit(m: *gas.Meter, sum: *const Summary, k: u64) void {
    const cost = m.instructions_current_tier_mult * sum.n + m.stack_size_current_tier_mult * sum.s + m.stack_height_current_tier_mult * sum.p;
    m.gas_left -= k * cost;
    m.instructions_executed += k * sum.n;
    m.stack_size_current += k * sum.s;
    m.stack_size_high_water_mark = @max(m.stack_size_high_water_mark, m.stack_size_current);
    const h: i128 = m.stack_height_current;
    const drift: i128 = @as(i128, sum.d) * @as(i128, k - 1);
    const peak: i128 = h + sum.hmax + @max(drift, 0);
    m.stack_height_high_water_mark = @max(m.stack_height_high_water_mark, @as(u64, @intCast(peak)));
    m.stack_height_current = @intCast(h + @as(i128, sum.d) * @as(i128, k));
}

/// At the head of `lp` in frame `f`: applies as many whole iterations as are certain to run
/// with no event, and charges them. Leaves everything untouched when there are none.
fn accelerate(s: *Session, f: *Frame, lp: *const Loop) void {
    stats.heads += 1;
    const shape = lp.shape;
    const meter = s.meter;
    if (!meter.charge_enabled or s.write_hook != null or s.tracer != null) return;
    if (meter.gas_model_version > MAX_GM) return;
    // type instantiation limits (see MAX_TY_NODES)
    if (shape.generic) {
        if (f.ty_nodes.len != 1 or f.ty_nodes_sum > MAX_TY_NODES) return;
    } else if (f.ty_nodes.len != 0) return;
    const pl = plan(s, f, shape) orelse return;
    const sum = &summaries[lp.shape_idx][@intCast(meter.gas_model_version)][@backingInt(pl.dst.kind)];
    if (!sum.valid) return;
    // pushes inside the iterations stay under the operand stack limit, calls under the depth limit
    if (s.sp + sum.depth + LIMIT_SLACK > interp.OPERAND_STACK_SIZE_LIMIT) return;
    if (shape.callee != null and s.frames.items.len + LIMIT_SLACK > interp.CALL_STACK_SIZE_LIMIT) return;
    const k = window(meter, sum, pl.kmax);
    if (k == 0) return;

    // the k iterations, natively
    const dst = pl.dst;
    switch (shape.kind) {
        .reverse => {
            swapPairs(dst, pl.i, pl.j, k);
            f.locals[shape.i] = Value.u64_(pl.i + k);
            f.locals[shape.j] = Value.u64_(pl.j - k);
        },
        .rotate => {
            rotateLeft(dst, pl.i, k);
            f.locals[shape.i] = Value.u64_(pl.i + k);
        },
        .push_pop => {
            const src = pl.src.?;
            s.heap.ensureCap(dst, @as(usize, dst.len) + k) catch return;
            moveTailReversed(dst, src, k);
            if (shape.bound == .local) f.locals[shape.i] = Value.u64_(pl.i + k);
        },
        .copy => {
            const src = pl.src.?;
            s.heap.ensureCap(dst, @as(usize, dst.len) + k) catch return;
            const w: usize = dst.kind.width();
            @memcpy(dst.data[@as(usize, dst.len) * w ..][0 .. k * w], src.data[pl.i * w ..][0 .. k * w]);
            dst.len += @intCast(k);
            f.locals[shape.i] = Value.u64_(pl.i + k);
        },
        .be_acc => {
            // acc = (acc << 8) + byte, in the width of acc: the shift drops the high bits and
            // the sum cannot carry (the low byte of the shifted value is zero)
            const old = f.locals[shape.j];
            const mask: u64 = switch (old.tag) {
                .u16 => 0xffff,
                .u32 => 0xffff_ffff,
                else => std.math.maxInt(u64),
            };
            var acc = old.a;
            var p = dst.data + dst.len;
            var n = k;
            while (n > 0) : (n -= 1) {
                p -= 1;
                acc = ((acc << 8) & mask) + p[0];
            }
            dst.len -= @intCast(k);
            f.locals[shape.j] = .{ .tag = old.tag, .a = acc };
            f.locals[shape.i] = Value.u64_(pl.i + k);
        },
    }
    for (shape.temps) |t| f.locals[t] = Value.invalid;
    commit(meter, sum, k);
    stats.hits += 1;
    stats.iters += k;
    stats.instrs += k * sum.n;
    if (count_totals.load(.monotonic)) {
        const g = totals.of(shape.group);
        _ = g.heads.fetchAdd(1, .monotonic);
        _ = g.iters.fetchAdd(k, .monotonic);
        _ = g.instrs.fetchAdd(k * sum.n, .monotonic);
    }
}

/// swap(i, j), swap(i + 1, j - 1), ... k times.
fn swapPairs(c: *Container, i: u64, j: u64, k: u64) void {
    const w: usize = c.kind.width();
    if (w == 1 and k == (j - i + 1) / 2) return std.mem.reverse(u8, c.data[@intCast(i)..@intCast(j + 1)]);
    var a = c.data + i * w;
    var b = c.data + j * w;
    switch (w) {
        inline 1, 2, 4, 8, 16, 24, 32 => |cw| {
            var n = k;
            while (n > 0) : (n -= 1) {
                const t: [cw]u8 = a[0..cw].*;
                a[0..cw].* = b[0..cw].*;
                b[0..cw].* = t;
                a += cw;
                b -= cw;
            }
        },
        else => unreachable,
    }
}

/// swap(i, i + 1), swap(i + 1, i + 2), ... k times: element i moves to i + k, the k elements
/// after it move down by one.
fn rotateLeft(c: *Container, i: u64, k: u64) void {
    const w: usize = c.kind.width();
    var tmp: [32]u8 = undefined;
    const p = c.data + i * w;
    @memcpy(tmp[0..w], p[0..w]);
    std.mem.copyForwards(u8, p[0 .. k * w], p[w .. (k + 1) * w]);
    @memcpy(p[k * w ..][0..w], tmp[0..w]);
}

/// push_back(dst, pop_back(src)) k times (dst has room for them).
fn moveTailReversed(dst: *Container, src: *Container, k: u64) void {
    const w: usize = dst.kind.width();
    var d = dst.data + @as(usize, dst.len) * w;
    var p = src.data + @as(usize, src.len) * w;
    switch (w) {
        inline 1, 2, 4, 8, 16, 24, 32 => |cw| {
            var n = k;
            while (n > 0) : (n -= 1) {
                p -= cw;
                d[0..cw].* = p[0..cw].*;
                d += cw;
            }
        },
        else => unreachable,
    }
    // a bool goes through a Value on its way (readElem, writeElem): any nonzero byte is true
    if (dst.kind == .vec_bool) for (dst.data[dst.len..][0..k]) |*x| {
        x.* = @intFromBool(x.* != 0);
    };
    dst.len += @intCast(k);
    src.len -= @intCast(k);
}

test {
    _ = @import("loopaccel_test.zig");
}
