//! Type instantiation, type tags and value (de)serialization by runtime type.
const std = @import("std");
const move_format = @import("move_format");
const loader = @import("loader.zig");
const value = @import("value.zig");

const Allocator = std.mem.Allocator;
const ff = move_format.file_format;
const Token = ff.Token;
const Type = loader.Type;
const Value = value.Value;
const Module = loader.Module;
const Reader = loader.Reader;
pub const DecodeError = loader.DecodeError;

/// Substitutes `args` into a signature token of module `m` (`instantiate_single_type`).
pub fn instantiate(arena: Allocator, m: *Module, tok: Token, args: []const *const Type) loader.LoadError!*const Type {
    var i: usize = 0;
    return inst(arena, m, tok, &i, args);
}

fn inst(arena: Allocator, m: *Module, tok: Token, i: *usize, args: []const *const Type) loader.LoadError!*const Type {
    const n = tok[i.*];
    i.* += 1;
    if (loader.primType(n.tag)) |p| return p;
    switch (n.tag) {
        .TypeParameter => {
            if (n.idx >= args.len) return error.BadModule;
            return args[n.idx];
        },
        .Vector, .Reference, .MutableReference => {
            const e = try inst(arena, m, tok, i, args);
            const t = try arena.create(Type);
            t.* = switch (n.tag) {
                .Vector => .{ .vector = e },
                .Reference => .{ .ref = e },
                else => .{ .mut_ref = e },
            };
            return t;
        },
        .Datatype => return &(try m.datatype(n.idx)).plain,
        .DatatypeInstantiation => {
            const dt = try m.datatype(n.idx);
            const targs = try arena.alloc(*const Type, n.arity);
            for (targs) |*a| a.* = try inst(arena, m, tok, i, args);
            const t = try arena.create(Type);
            t.* = .{ .datatype = .{ .dt = dt, .args = targs } };
            return t;
        },
        else => unreachable,
    }
}

/// Instantiates every token of a signature.
pub fn instantiateAll(arena: Allocator, m: *Module, toks: []const Token, args: []const *const Type) loader.LoadError![]const *const Type {
    const out = try arena.alloc(*const Type, toks.len);
    for (toks, out) |t, *o| o.* = try instantiate(arena, m, t, args);
    return out;
}

/// True if the token mentions a type parameter.
pub fn tokenIsGeneric(tok: Token) bool {
    for (tok) |n| if (n.tag == .TypeParameter) return true;
    return false;
}

// ---------------------------------------------------------------------------------------------
// TypeTag (move-core-types BCS): bool 0, u8 1, u64 2, u128 3, address 4, signer 5, vector 6,
// struct 7, u16 8, u32 9, u256 10. Struct tags carry the defining id.

pub fn fromTag(arena: Allocator, rt: *loader.Runtime, r: *Reader, depth: u32) DecodeError!*const Type {
    if (depth > 256) return error.TooDeep;
    const tag = try r.uleb();
    return switch (tag) {
        0 => &Type.t_bool,
        1 => &Type.t_u8,
        2 => &Type.t_u64,
        3 => &Type.t_u128,
        4 => &Type.t_address,
        5 => &Type.t_signer,
        6 => blk: {
            const t = try arena.create(Type);
            t.* = .{ .vector = try fromTag(arena, rt, r, depth + 1) };
            break :blk t;
        },
        7 => blk: {
            const addr = (try r.take(32))[0..32];
            const mname = try r.take(try r.uleb());
            const name = try r.take(try r.uleb());
            const n = try r.uleb();
            const args = try arena.alloc(*const Type, n);
            for (args) |*a| a.* = try fromTag(arena, rt, r, depth + 1);
            const dt = try rt.datatypeByDefiningId(addr, mname, name);
            const t = try arena.create(Type);
            t.* = .{ .datatype = .{ .dt = dt, .args = args } };
            break :blk t;
        },
        8 => &Type.t_u16,
        9 => &Type.t_u32,
        10 => &Type.t_u256,
        else => error.BadTag,
    };
}

pub fn fromTagBytes(arena: Allocator, rt: *loader.Runtime, bytes: []const u8) DecodeError!*const Type {
    var r = Reader{ .bytes = bytes };
    const t = try fromTag(arena, rt, &r, 0);
    if (r.pos != bytes.len) return error.BadTag;
    return t;
}

// ---------------------------------------------------------------------------------------------
// Values from / to BCS (`Value::simple_deserialize` / `typed_serialize`)

pub fn deserialize(h: value.Heap, t: *const Type, r: *Reader, depth: u32) DecodeError!Value {
    if (depth > 1024) return error.TooDeep;
    switch (t.*) {
        .vector => |e| {
            const n = try r.uleb();
            const k = e.vecKind();
            // Every element takes at least one byte: check before allocating `n` slots.
            if (n > r.bytes.len - r.pos) return error.EndOfInput;
            if (k != .vec) {
                const bytes = try r.take(n * k.width());
                const c = try h.newContainer(k, n);
                if (k == .vec_bool) for (bytes) |b| if (b > 1) return error.BadBool;
                @memcpy(c.bytes(), bytes);
                return Value.container(c);
            }
            const c = try h.newContainer(.vec, n);
            for (c.values()) |*v| v.* = try deserialize(h, e, r, depth + 1);
            return Value.container(c);
        },
        .datatype => |d| {
            if (d.dt.is_enum) {
                const tag = try r.uleb();
                if (tag >= d.dt.variants.len) return error.BadTag;
                const fields = d.dt.variants[tag].fields;
                const c = try h.newContainer(.variant, fields.len);
                c.tag = @intCast(tag);
                for (fields, c.values()) |f, *v| {
                    const ft = try instantiate(h.arena, d.dt.module, f.signature, d.args);
                    v.* = try deserialize(h, ft, r, depth + 1);
                }
                return Value.container(c);
            }
            const c = try h.newContainer(.struct_, d.dt.fields.len);
            for (d.dt.fields, c.values()) |f, *v| {
                const ft = try instantiate(h.arena, d.dt.module, f.signature, d.args);
                v.* = try deserialize(h, ft, r, depth + 1);
            }
            return Value.container(c);
        },
        .ref, .mut_ref, .param => return error.BadTag,
        else => return loader.primValue(h, t.*, r),
    }
}

/// exec-history-vm: argument `i` of a v0..v3 `execute_function` (`Runtime::deserialize_args`):
/// the referent of a reference parameter or the value itself, strict BCS over the whole input.
/// null: the call fails with FAILED_TO_DESERIALIZE_ARGUMENT at `Location::Undefined`, before any
/// gas charge and before later arguments are read (the dynamic executor passes serialized
/// arguments; the latest VM takes values and has no such step).
pub fn deserializeArg(h: value.Heap, param: *const Type, bytes: []const u8) Allocator.Error!?Value {
    const inner = switch (param.*) {
        .ref, .mut_ref => |t| t,
        else => param,
    };
    var r = Reader{ .bytes = bytes };
    const x = deserialize(h, inner, &r, 0) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    if (r.pos != bytes.len) return null;
    return x;
}

pub fn serialize(arena: Allocator, t: *const Type, v: Value, out: *std.ArrayList(u8)) (Allocator.Error || loader.LoadError)!void {
    switch (t.*) {
        .bool, .u8 => try out.append(arena, @truncate(v.a)),
        .u16 => try out.appendSlice(arena, std.mem.asBytes(&std.mem.nativeToLittle(u16, @truncate(v.a)))),
        .u32 => try out.appendSlice(arena, std.mem.asBytes(&std.mem.nativeToLittle(u32, @truncate(v.a)))),
        .u64 => try out.appendSlice(arena, std.mem.asBytes(&std.mem.nativeToLittle(u64, v.a))),
        .u128 => try out.appendSlice(arena, std.mem.asBytes(&std.mem.nativeToLittle(u128, v.asU128()))),
        .u256, .address => try out.appendSlice(arena, v.box()),
        .signer => try out.appendSlice(arena, v.cont().values()[0].box()),
        .vector => |e| {
            const c = v.cont();
            try uleb(arena, out, c.len);
            if (c.kind.isPrimVec()) {
                try out.appendSlice(arena, c.bytes());
            } else for (c.values()) |x| try serialize(arena, e, x, out);
        },
        .datatype => |d| {
            const c = v.cont();
            if (d.dt.is_enum) {
                try uleb(arena, out, c.tag);
                for (d.dt.variants[c.tag].fields, c.values()) |f, x| {
                    try serialize(arena, try instantiate(arena, d.dt.module, f.signature, d.args), x, out);
                }
            } else for (d.dt.fields, c.values()) |f, x| {
                try serialize(arena, try instantiate(arena, d.dt.module, f.signature, d.args), x, out);
            }
        },
        .ref, .mut_ref, .param => unreachable,
    }
}

fn uleb(arena: Allocator, out: *std.ArrayList(u8), x0: u64) Allocator.Error!void {
    var x = x0;
    while (true) {
        const b: u8 = @truncate(x & 0x7f);
        x >>= 7;
        if (x == 0) return out.append(arena, b);
        try out.append(arena, b | 0x80);
    }
}
