//! Move runtime values.
//!
//! Semantics are move-vm-runtime 1.83 `values_impl.rs`; the representation is ours:
//! - `Value` is 24 bytes. Small integers, bools and u128 are inline; u256 and addresses point to
//!   immutable 32-byte boxes (so copies share them); containers are pointers.
//! - A container holds its fields/elements in one array that never moves while it can be
//!   borrowed (Move reference safety forbids growing a vector with a live element reference).
//!   A reference is a pointer to a `Value` slot (local, field, element of a boxed vector) or a
//!   (primitive vector, index) pair, mirroring Rust's `Reference::Value` / `Reference::Indexed`.
//! - Primitive vectors (u8..u256, bool, address) store packed elements: the same classes Rust
//!   specialises as `PrimVec`, so abstract memory sizes match exactly.
//! - Every value slot owns its containers and 32-byte boxes (copies duplicate them), so a value
//!   is freed exactly where Rust drops it (Pop, StLoc over a value, Ret, WriteRef, Eq, consumed
//!   operands, unpacked shells). Freed blocks go to a `Pool` of free lists (one per power-of-two
//!   size class, one for container headers) and are reused, so a session's memory is bounded by
//!   its live data, not by the instructions it runs. Without a pool (constants, test values) the
//!   arena is used and nothing is freed.
const std = @import("std");
const gas = @import("gas.zig");

const Allocator = std.mem.Allocator;

pub const Tag = enum(u8) { invalid, u8, u16, u32, u64, u128, u256, bool, address, container, ref_slot, ref_elem };

pub const Kind = enum(u8) {
    struct_,
    variant,
    vec,
    vec_u8,
    vec_u16,
    vec_u32,
    vec_u64,
    vec_u128,
    vec_u256,
    vec_bool,
    vec_address,

    pub fn isPrimVec(k: Kind) bool {
        return @backingInt(k) >= @backingInt(Kind.vec_u8);
    }
    pub fn isVector(k: Kind) bool {
        return @backingInt(k) >= @backingInt(Kind.vec);
    }
    /// Element width in bytes (`size_of_val` per element in Rust).
    pub fn width(k: Kind) u32 {
        return switch (k) {
            .vec_u8, .vec_bool => 1,
            .vec_u16 => 2,
            .vec_u32 => 4,
            .vec_u64 => 8,
            .vec_u128 => 16,
            .vec_u256, .vec_address => 32,
            else => @sizeOf(Value),
        };
    }
    pub fn elemTag(k: Kind) Tag {
        return switch (k) {
            .vec_u8 => .u8,
            .vec_u16 => .u16,
            .vec_u32 => .u32,
            .vec_u64 => .u64,
            .vec_u128 => .u128,
            .vec_u256 => .u256,
            .vec_bool => .bool,
            .vec_address => .address,
            else => .invalid,
        };
    }
};

pub const Container = struct {
    kind: Kind,
    /// Size class of `data` when it came from a pool (`NO_CLASS`: allocated elsewhere).
    cls: u8 = NO_CLASS,
    tag: u16 = 0, // variant tag
    len: u32,
    cap: u32,
    data: [*]u8,

    pub fn values(c: *const Container) []Value {
        std.debug.assert(!c.kind.isPrimVec());
        const p: [*]Value = @ptrCast(@alignCast(c.data));
        return p[0..c.len];
    }
    pub fn bytes(c: *const Container) []u8 {
        return c.data[0 .. @as(usize, c.len) * c.kind.width()];
    }
};

pub const Value = extern struct {
    tag: Tag,
    _pad: [7]u8 = @splat(0),
    a: u64 = 0,
    b: u64 = 0,

    pub const invalid: Value = .{ .tag = .invalid };

    pub inline fn u8_(x: u8) Value {
        return .{ .tag = .u8, .a = x };
    }
    pub inline fn u16_(x: u16) Value {
        return .{ .tag = .u16, .a = x };
    }
    pub inline fn u32_(x: u32) Value {
        return .{ .tag = .u32, .a = x };
    }
    pub inline fn u64_(x: u64) Value {
        return .{ .tag = .u64, .a = x };
    }
    pub inline fn u128_(x: u128) Value {
        return .{ .tag = .u128, .a = @truncate(x), .b = @truncate(x >> 64) };
    }
    pub inline fn bool_(x: bool) Value {
        return .{ .tag = .bool, .a = @intFromBool(x) };
    }
    pub inline fn container(c: *Container) Value {
        return .{ .tag = .container, .a = @intFromPtr(c) };
    }
    pub inline fn refSlot(p: *Value) Value {
        return .{ .tag = .ref_slot, .a = @intFromPtr(p) };
    }
    pub inline fn refElem(c: *Container, i: u64) Value {
        return .{ .tag = .ref_elem, .a = @intFromPtr(c), .b = i };
    }
    /// u256 and address values point to an immutable 32-byte box.
    pub inline fn boxed(t: Tag, p: *const [32]u8) Value {
        return .{ .tag = t, .a = @intFromPtr(p) };
    }

    pub inline fn asU128(v: Value) u128 {
        return (@as(u128, v.b) << 64) | v.a;
    }
    pub inline fn box(v: Value) *const [32]u8 {
        return @ptrFromInt(v.a);
    }
    pub inline fn asU256(v: Value) u256 {
        return std.mem.readInt(u256, v.box(), .little);
    }
    pub inline fn cont(v: Value) *Container {
        return @ptrFromInt(v.a);
    }
    pub inline fn slot(v: Value) *Value {
        return @ptrFromInt(v.a);
    }
    pub inline fn isRef(v: Value) bool {
        return v.tag == .ref_slot or v.tag == .ref_elem;
    }
};

comptime {
    std.debug.assert(@sizeOf(Value) == 24);
}

pub const NO_CLASS: u8 = 0xff;
const MIN_SHIFT = 3; // smallest block: 8 bytes (one free-list link)
const N_CLASSES = 40;

/// Free lists for value memory. Blocks come from `arena` and are never returned to it; a freed
/// block is reused by the next allocation of its size class.
pub const Pool = struct {
    arena: Allocator,
    heads: [N_CLASSES]?*Node = @splat(null),
    headers: ?*Node = null,
    /// Bytes ever taken from the arena (the pool's high-water mark).
    reserved: u64 = 0,

    const Node = struct { next: ?*Node };

    pub fn init(arena: Allocator) Pool {
        return .{ .arena = arena };
    }

    /// The class whose blocks hold `n` bytes.
    fn classFor(n: usize) u8 {
        const need = @max(n, 1 << MIN_SHIFT);
        const bits: u8 = @intCast(std.math.log2_int_ceil(usize, need));
        return bits - MIN_SHIFT;
    }

    /// The largest class a block of `n` bytes can serve (blocks not made by the pool).
    fn classOf(n: usize) ?u8 {
        if (n < (1 << MIN_SHIFT)) return null;
        return @as(u8, @intCast(std.math.log2_int(usize, n))) - MIN_SHIFT;
    }

    fn take(p: *Pool, cls: u8) Allocator.Error![*]u8 {
        if (p.heads[cls]) |n| {
            p.heads[cls] = n.next;
            return @ptrCast(n);
        }
        const bytes = @as(usize, 1) << @intCast(cls + MIN_SHIFT);
        p.reserved += bytes;
        const mem = try p.arena.alignedAlloc(u8, .of(Value), bytes);
        return mem.ptr;
    }

    fn give(p: *Pool, ptr: [*]u8, cls: u8) void {
        // Poisoning the whole freed block is a debugging aid: Debug builds only (ReleaseSafe
        // runs the node, and a freed 64 KiB vector would cost a 64 KiB write).
        if (@import("builtin").mode == .debug) @memset(ptr[0 .. @as(usize, 1) << @intCast(cls + MIN_SHIFT)], 0xaa);
        const n: *Node = @ptrCast(@alignCast(ptr));
        n.next = p.heads[cls];
        p.heads[cls] = n;
    }

    fn takeHeader(p: *Pool) Allocator.Error!*Container {
        if (p.headers) |n| {
            p.headers = n.next;
            return @ptrCast(@alignCast(n));
        }
        p.reserved += @sizeOf(Container);
        return p.arena.create(Container);
    }

    fn giveHeader(p: *Pool, c: *Container) void {
        if (std.debug.runtime_safety) c.* = undefined;
        const n: *Node = @ptrCast(@alignCast(c));
        n.next = p.headers;
        p.headers = n;
    }
};

/// Allocation on the session arena, through the session's pool when it has one.
pub const Heap = struct {
    arena: Allocator,
    pool: ?*Pool = null,

    pub fn box32(h: Heap, b: [32]u8) Allocator.Error!*const [32]u8 {
        // 8-aligned either way, so a box made without a pool can still be freed into one.
        const p: *[32]u8 = if (h.pool) |pl| @ptrCast(try pl.take(Pool.classFor(32))) else (try h.arena.alignedAlloc(u8, .of(Value), 32))[0..32];
        p.* = b;
        return p;
    }
    pub fn u256_(h: Heap, x: u256) Allocator.Error!Value {
        var b: [32]u8 = undefined;
        std.mem.writeInt(u256, &b, x, .little);
        return Value.boxed(.u256, try h.box32(b));
    }
    pub fn address(h: Heap, a: [32]u8) Allocator.Error!Value {
        return Value.boxed(.address, try h.box32(a));
    }

    /// Data for `n` bytes: from the pool (with its class) or the arena.
    fn data(h: Heap, n: usize) Allocator.Error!struct { [*]u8, u8, usize } {
        if (h.pool) |pl| {
            const cls = Pool.classFor(n);
            return .{ try pl.take(cls), cls, @as(usize, 1) << @intCast(cls + MIN_SHIFT) };
        }
        const mem = try h.arena.alignedAlloc(u8, .of(Value), @max(n, 1));
        return .{ mem.ptr, NO_CLASS, mem.len };
    }

    pub fn newContainer(h: Heap, kind: Kind, len: usize) Allocator.Error!*Container {
        const c = if (h.pool) |pl| try pl.takeHeader() else try h.arena.create(Container);
        const w = kind.width();
        const d = try h.data(@max(len, 1) * w);
        c.* = .{ .kind = kind, .cls = d[1], .len = @intCast(len), .cap = @intCast(@max(d[2] / w, 1)), .data = d[0] };
        return c;
    }

    /// A struct (or variant) from `fields`, copied into a new container.
    pub fn pack(h: Heap, kind: Kind, tag: u16, fields: []const Value) Allocator.Error!Value {
        const c = try h.newContainer(kind, fields.len);
        c.tag = tag;
        @memcpy(c.values(), fields);
        return Value.container(c);
    }

    /// Grows a vector's storage to hold at least one more element.
    pub fn reserveOne(h: Heap, c: *Container) Allocator.Error!void {
        if (c.len < c.cap) return;
        const w = c.kind.width();
        const d = try h.data(@max(4, @as(usize, c.cap) * 2) * w);
        @memcpy(d[0][0 .. @as(usize, c.len) * w], c.data[0 .. @as(usize, c.len) * w]);
        h.freeData(c);
        c.data = d[0];
        c.cls = d[1];
        c.cap = @intCast(d[2] / w);
    }

    /// Grows a vector's storage to hold at least `n` elements (length unchanged).
    pub fn ensureCap(h: Heap, c: *Container, n: usize) Allocator.Error!void {
        if (n <= c.cap) return;
        const w = c.kind.width();
        const d = try h.data(@max(n, @as(usize, c.cap) * 2) * w);
        @memcpy(d[0][0 .. @as(usize, c.len) * w], c.data[0 .. @as(usize, c.len) * w]);
        h.freeData(c);
        c.data = d[0];
        c.cls = d[1];
        c.cap = @intCast(d[2] / w);
    }

    /// Deep copy (`copy_value`): containers and boxes are duplicated.
    pub fn copy(h: Heap, v: Value) Allocator.Error!Value {
        switch (v.tag) {
            .u256, .address => return Value.boxed(v.tag, try h.box32(v.box().*)),
            .container => {},
            else => return v,
        }
        const src = v.cont();
        const c = try h.newContainer(src.kind, src.len);
        c.tag = src.tag;
        if (src.kind.isPrimVec()) {
            @memcpy(c.bytes(), src.bytes());
        } else {
            for (c.values(), src.values()) |*d, s| d.* = try h.copy(s);
        }
        return Value.container(c);
    }

    // ---- freeing (no-ops without a pool) -----------------------------------------------------

    fn freeData(h: Heap, c: *Container) void {
        const pl = h.pool orelse return;
        if (c.cls != NO_CLASS) return pl.give(c.data, c.cls);
        if (Pool.classOf(@as(usize, c.cap) * c.kind.width())) |cls| pl.give(c.data, cls);
    }

    /// Frees a container's storage and header, not its fields (they were moved out).
    pub fn freeShell(h: Heap, c: *Container) void {
        const pl = h.pool orelse return;
        h.freeData(c);
        pl.giveHeader(c);
    }

    /// Drops an owned value: its boxes and containers, recursively. References own nothing.
    pub fn drop(h: Heap, v: Value) void {
        const pl = h.pool orelse return;
        switch (v.tag) {
            .u256, .address => pl.give(@ptrCast(@constCast(v.box())), Pool.classFor(32)),
            .container => {
                const c = v.cont();
                if (!c.kind.isPrimVec()) for (c.values()) |f| h.drop(f);
                h.freeShell(c);
            },
            else => {},
        }
    }
};

// ---------------------------------------------------------------------------------------------
// Primitive vector elements

pub fn readElem(c: *const Container, i: usize, h: Heap) Allocator.Error!Value {
    const w = c.kind.width();
    const p = c.data + i * w;
    return switch (c.kind) {
        .vec_u8 => Value.u8_(p[0]),
        .vec_bool => Value.bool_(p[0] != 0),
        .vec_u16 => Value.u16_(std.mem.readInt(u16, p[0..2], .little)),
        .vec_u32 => Value.u32_(std.mem.readInt(u32, p[0..4], .little)),
        .vec_u64 => Value.u64_(std.mem.readInt(u64, p[0..8], .little)),
        .vec_u128 => Value.u128_(std.mem.readInt(u128, p[0..16], .little)),
        .vec_u256 => Value.boxed(.u256, try h.box32(p[0..32].*)),
        .vec_address => Value.boxed(.address, try h.box32(p[0..32].*)),
        else => unreachable,
    };
}

pub fn writeElem(c: *Container, i: usize, v: Value) void {
    const w = c.kind.width();
    const p = c.data + i * w;
    switch (c.kind) {
        .vec_u8 => p[0] = @truncate(v.a),
        .vec_bool => p[0] = @truncate(v.a),
        .vec_u16 => std.mem.writeInt(u16, p[0..2], @truncate(v.a), .little),
        .vec_u32 => std.mem.writeInt(u32, p[0..4], @truncate(v.a), .little),
        .vec_u64 => std.mem.writeInt(u64, p[0..8], v.a, .little),
        .vec_u128 => std.mem.writeInt(u128, p[0..16], v.asU128(), .little),
        .vec_u256, .vec_address => p[0..32].* = v.box().*,
        else => unreachable,
    }
}

/// Reads through a reference (the referent value, not copied).
pub fn deref(r: Value, h: Heap) Allocator.Error!Value {
    return switch (r.tag) {
        .ref_slot => r.slot().*,
        .ref_elem => readElem(r.cont(), r.b, h),
        else => unreachable,
    };
}

// ---------------------------------------------------------------------------------------------
// Abstract memory size (`ValueView::abstract_memory_size`, saturating)

const PRIMITIVE_SIZE: u64 = 8;
const U128_SIZE: u64 = 16;
const U256_SIZE: u64 = 32;
const ADDRESS_SIZE: u64 = 32;

const LEGACY_CONST_SIZE: u64 = 16;

fn primSize(t: Tag, cfg: gas.SizeCfg) u64 {
    if (!cfg.fine_grained) return if (t == .address) ADDRESS_SIZE else LEGACY_CONST_SIZE;
    return switch (t) {
        .u8, .u16, .u32, .u64, .bool => PRIMITIVE_SIZE,
        .u128 => U128_SIZE,
        .u256 => U256_SIZE,
        .address => ADDRESS_SIZE,
        else => 0,
    };
}

pub fn size(v: Value, cfg: gas.SizeCfg) u64 {
    return switch (v.tag) {
        .invalid => 0,
        .u8, .u16, .u32, .u64, .bool, .u128, .u256, .address => primSize(v.tag, cfg),
        .container => containerSize(v.cont(), cfg),
        .ref_slot => if (cfg.traverse_references) gas.REFERENCE_SIZE +| size(v.slot().*, cfg) else gas.REFERENCE_SIZE,
        .ref_elem => if (cfg.traverse_references) gas.REFERENCE_SIZE +| primSize(v.cont().kind.elemTag(), cfg) else gas.REFERENCE_SIZE,
    };
}

pub fn containerSize(c: *const Container, cfg: gas.SizeCfg) u64 {
    if (c.kind.isPrimVec()) {
        const base: u64 = if (cfg.include_vector_size) gas.STRUCT_SIZE else 0;
        return base +| (@as(u64, c.len) * c.kind.width());
    }
    var acc: u64 = gas.STRUCT_SIZE;
    for (c.values()) |f| acc +|= size(f, cfg);
    return acc;
}

/// Size of the value behind a reference (`Reference::value_view`, no reference size).
pub fn referentSize(r: Value, cfg: gas.SizeCfg) u64 {
    return switch (r.tag) {
        .ref_slot => size(r.slot().*, cfg),
        .ref_elem => primSize(r.cont().kind.elemTag(), cfg),
        else => unreachable,
    };
}

// ---------------------------------------------------------------------------------------------
// Equality (`Value::equals`; values are well typed after verification)

pub fn equals(x: Value, y: Value) bool {
    switch (x.tag) {
        .ref_slot, .ref_elem => {
            if (x.tag == .ref_slot and y.tag == .ref_slot and x.a == y.a) return true;
            return refEquals(x, y);
        },
        .u8, .u16, .u32, .u64, .bool => return x.a == y.a,
        .u128 => return x.a == y.a and x.b == y.b,
        .u256, .address => return std.mem.eql(u8, x.box(), y.box()),
        .container => return containerEquals(x.cont(), y.cont()),
        .invalid => return false,
    }
}

fn elemBytes(c: *const Container, i: usize) []const u8 {
    const w = c.kind.width();
    return c.data[i * w ..][0..w];
}

fn refEquals(x: Value, y: Value) bool {
    if (x.tag == .ref_elem and y.tag == .ref_elem) {
        return std.mem.eql(u8, elemBytes(x.cont(), x.b), elemBytes(y.cont(), y.b));
    }
    if (x.tag == .ref_slot and y.tag == .ref_slot) return equals(x.slot().*, y.slot().*);
    // one indexed, one boxed: compare the primitive values
    const s = if (x.tag == .ref_slot) x.slot().* else y.slot().*;
    const e = if (x.tag == .ref_elem) x else y;
    return primEqualsElem(s, e.cont(), e.b);
}

fn primEqualsElem(v: Value, c: *const Container, i: usize) bool {
    const p = elemBytes(c, i);
    return switch (v.tag) {
        .u8, .bool => p[0] == @as(u8, @truncate(v.a)),
        .u16 => std.mem.readInt(u16, p[0..2], .little) == v.a,
        .u32 => std.mem.readInt(u32, p[0..4], .little) == v.a,
        .u64 => std.mem.readInt(u64, p[0..8], .little) == v.a,
        .u128 => std.mem.readInt(u128, p[0..16], .little) == v.asU128(),
        .u256, .address => std.mem.eql(u8, p[0..32], v.box()),
        else => false,
    };
}

fn containerEquals(x: *const Container, y: *const Container) bool {
    if (x.len != y.len) return false;
    if (x.kind == .variant and x.tag != y.tag) return false;
    if (x.kind.isPrimVec()) return std.mem.eql(u8, x.bytes(), y.bytes());
    for (x.values(), y.values()) |a, b| if (!equals(a, b)) return false;
    return true;
}

test "sizes" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const h = Heap{ .arena = arena_state.allocator() };
    const plain = gas.SizeCfg{ .traverse_references = false, .include_vector_size = true };
    const c = try h.newContainer(.vec_u8, 3);
    try std.testing.expectEqual(@as(u64, 5), containerSize(c, plain));
    const s = try h.pack(.struct_, 0, &.{ Value.u64_(1), Value.container(c) });
    try std.testing.expectEqual(@as(u64, 2 + 8 + 5), size(s, plain));
    var slot = s;
    const r = Value.refSlot(&slot);
    try std.testing.expectEqual(@as(u64, 8), size(r, plain));
    try std.testing.expectEqual(@as(u64, 8 + 15), size(r, .{ .traverse_references = true, .include_vector_size = true }));
}
