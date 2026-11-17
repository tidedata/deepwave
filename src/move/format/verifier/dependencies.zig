//! Linking a package being published against its dependencies (1.83.1):
//! move-vm-runtime validation/verification/linkage.rs `verify_linkage_and_cyclic_checks_for_publication`
//! over the package's own modules, with move-bytecode-verifier dependencies.rs `verify_module` and
//! cyclic_dependencies.rs `verify_module`. It runs after every module passed the bytecode verifier.
//!
//! Every failure is a Verification status (MISSING_DEPENDENCY, LOOKUP_FAILED, TYPE_MISMATCH,
//! CYCLIC_MODULE_DEPENDENCY), which the adapter reports as VMVerificationOrDeserializationError,
//! so the first failing code is all a caller needs.
//!
//! Not ported: the dependency packages' own re-check (stored packages link under the linkage
//! the publish computed, which never downgrades them) and `verify_all_script_visibility_usage`
//! (modules below binary version 5, which the publish binary config does not deserialize).
const std = @import("std");
const ff = @import("../file_format.zig");

const Allocator = std.mem.Allocator;
const CompiledModule = ff.CompiledModule;
const StatusCode = ff.StatusCode;
const Token = ff.Token;

/// Modules by runtime (original) address and name: the package's own modules and those of
/// every package in its linkage.
pub const Resolver = struct {
    ctx: *const anyopaque,
    /// null: no package at `addr` in the linkage, or no such module in it (MISSING_DEPENDENCY).
    find: *const fn (ctx: *const anyopaque, addr: *const [32]u8, name: []const u8) ?*const CompiledModule,

    fn get(r: Resolver, addr: *const [32]u8, name: []const u8) ?*const CompiledModule {
        return r.find(r.ctx, addr, name);
    }
};

fn handleAddr(m: *const CompiledModule, h: ff.ModuleHandle) *const [32]u8 {
    return &m.address_identifiers[h.address];
}

fn handleName(m: *const CompiledModule, h: ff.ModuleHandle) []const u8 {
    return m.identifiers[h.name];
}

/// `pkg`: the package's modules sorted by name (one address). Null when it links.
pub fn verifyPackage(arena: Allocator, pkg: []const *const CompiledModule, r: Resolver) Allocator.Error!?StatusCode {
    // verify_package_valid_linkage
    for (pkg) |m| if (verifyModule(m, r)) |code| return code;
    // verify_package_no_cyclic_relationships: the largest module id first; every module a
    // traversal visits is not traversed from again
    const done = try arena.alloc(bool, pkg.len);
    @memset(done, false);
    var i = pkg.len;
    while (i > 0) {
        i -= 1;
        if (done[i]) continue;
        done[i] = true;
        var visited: std.StringHashMapUnmanaged(void) = .empty;
        if (try cyclic(arena, pkg[i], r, &visited)) |code| return code;
        var it = visited.keyIterator();
        while (it.next()) |k| for (pkg, 0..) |m, j| {
            if (std.mem.eql(u8, k.*[0..32], m.selfAddress()) and std.mem.eql(u8, k.*[32..], m.selfName())) done[j] = true;
        };
    }
    return null;
}

/// cyclic_dependencies.rs `verify_module_impl`: depth-first from each immediate dependency;
/// reaching `m` again is CYCLIC_MODULE_DEPENDENCY.
fn cyclic(arena: Allocator, m: *const CompiledModule, r: Resolver, visited: *std.StringHashMapUnmanaged(void)) Allocator.Error!?StatusCode {
    for (m.module_handles, 0..) |h, hi| {
        if (hi == m.self_module_handle_idx) continue;
        switch (try detect(arena, m, handleAddr(m, h), handleName(m, h), r, visited)) {
            .no => {},
            .cycle => return .CYCLIC_MODULE_DEPENDENCY,
            .missing => return .MISSING_DEPENDENCY,
        }
    }
    return null;
}

fn detect(arena: Allocator, target: *const CompiledModule, addr: *const [32]u8, name: []const u8, r: Resolver, visited: *std.StringHashMapUnmanaged(void)) Allocator.Error!enum { no, cycle, missing } {
    if (std.mem.eql(u8, addr, target.selfAddress()) and std.mem.eql(u8, name, target.selfName())) return .cycle;
    const key = try std.mem.concat(arena, u8, &.{ addr, name });
    if ((try visited.getOrPut(arena, key)).found_existing) return .no;
    const cur = r.get(addr, name) orelse return .missing;
    for (cur.module_handles, 0..) |h, hi| {
        if (hi == cur.self_module_handle_idx) continue;
        switch (try detect(arena, target, handleAddr(cur, h), handleName(cur, h), r, visited)) {
            .no => {},
            else => |x| return x,
        }
    }
    return .no;
}

/// linkage.rs `verify_module_dependencies` then dependencies.rs `verify_module`.
fn verifyModule(m: *const CompiledModule, r: Resolver) ?StatusCode {
    const self_idx = m.self_module_handle_idx;
    // every immediate dependency resolves (verify_imported_modules is then implied)
    for (m.module_handles, 0..) |h, hi| {
        if (hi == self_idx) continue;
        _ = r.get(handleAddr(m, h), handleName(m, h)) orelse return .MISSING_DEPENDENCY;
    }
    // verify_imported_structs
    for (m.datatype_handles) |dh| {
        if (dh.module == self_idx) continue;
        const mh = m.module_handles[dh.module];
        const owner = r.get(handleAddr(m, mh), handleName(m, mh)).?;
        const def = defHandle(owner, m.identifiers[dh.name]) orelse return .LOOKUP_FAILED;
        if (!dh.abilities.isSubset(def.abilities)) return .TYPE_MISMATCH;
        if (dh.type_parameters.len != def.type_parameters.len) return .TYPE_MISMATCH;
        for (dh.type_parameters, def.type_parameters) |l, d| {
            if (l.is_phantom and !d.is_phantom) return .TYPE_MISMATCH;
            if (!d.constraints.isSubset(l.constraints)) return .TYPE_MISMATCH;
        }
    }
    // verify_imported_functions
    for (m.function_handles) |fh| {
        if (fh.module == self_idx) continue;
        const mh = m.module_handles[fh.module];
        const owner = r.get(handleAddr(m, mh), handleName(m, mh)).?;
        const def = callable(owner, m, m.identifiers[fh.name]) orelse return .LOOKUP_FAILED;
        if (fh.type_parameters.len != def.type_parameters.len) return .TYPE_MISMATCH;
        for (fh.type_parameters, def.type_parameters) |l, d| {
            if (!d.isSubset(l)) return .TYPE_MISMATCH;
        }
        if (!sameSignature(m, m.signatures[fh.parameters], owner, owner.signatures[def.parameters])) return .TYPE_MISMATCH;
        if (!sameSignature(m, m.signatures[fh.return_], owner, owner.signatures[def.return_])) return .TYPE_MISMATCH;
    }
    return null;
}

/// `datatype_name_to_handle_map`: a struct or enum the owner defines (enums win a name clash,
/// as the map's later insert).
fn defHandle(owner: *const CompiledModule, name: []const u8) ?*const ff.DatatypeHandle {
    var out: ?*const ff.DatatypeHandle = null;
    for (owner.struct_defs) |sd| if (std.mem.eql(u8, owner.identifiers[owner.datatype_handles[sd.struct_handle].name], name)) {
        out = &owner.datatype_handles[sd.struct_handle];
    };
    for (owner.enum_defs) |ed| if (std.mem.eql(u8, owner.identifiers[owner.datatype_handles[ed.enum_handle].name], name)) {
        out = &owner.datatype_handles[ed.enum_handle];
    };
    return out;
}

/// `callable_function_info`: the owner's function `name` (the last definition of that name),
/// if `caller` may call it (public, or friend and `caller` is one of the owner's friends).
fn callable(owner: *const CompiledModule, caller: *const CompiledModule, name: []const u8) ?*const ff.FunctionHandle {
    var found: ?*const ff.FunctionDefinition = null;
    for (owner.function_defs) |*fd| if (std.mem.eql(u8, owner.identifiers[owner.function_handles[fd.function].name], name)) {
        found = fd;
    };
    const fd = found orelse return null;
    switch (fd.visibility) {
        .Public => {},
        .Private => return null,
        .Friend => {
            const friend = for (owner.friend_decls) |f| {
                if (std.mem.eql(u8, handleAddr(owner, f), caller.selfAddress()) and std.mem.eql(u8, handleName(owner, f), caller.selfName())) break true;
            } else false;
            if (!friend) return null;
        },
    }
    return &owner.function_handles[fd.function];
}

/// `compare_cross_module_signatures`: same length, each pair `compare_types`.
fn sameSignature(hm: *const CompiledModule, hs: []const Token, dm: *const CompiledModule, ds: []const Token) bool {
    if (hs.len != ds.len) return false;
    for (hs, ds) |a, b| if (!sameType(hm, a, dm, b)) return false;
    return true;
}

/// `compare_types` over two preorder tokens: the same shape node by node, datatypes naming the
/// same module id and name, type parameters the same index.
fn sameType(hm: *const CompiledModule, a: Token, dm: *const CompiledModule, b: Token) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x.tag != y.tag) return false;
        switch (x.tag) {
            .TypeParameter => if (x.idx != y.idx) return false,
            .DatatypeInstantiation, .Datatype => {
                if (x.arity != y.arity) return false;
                const xh = hm.datatype_handles[x.idx];
                const yh = dm.datatype_handles[y.idx];
                const xm = hm.module_handles[xh.module];
                const ym = dm.module_handles[yh.module];
                if (!std.mem.eql(u8, handleAddr(hm, xm), handleAddr(dm, ym))) return false;
                if (!std.mem.eql(u8, handleName(hm, xm), handleName(dm, ym))) return false;
                if (!std.mem.eql(u8, hm.identifiers[xh.name], dm.identifiers[yh.name])) return false;
            },
            else => {},
        }
    }
    return true;
}

test "sameType: shapes, datatype names and type parameters" {
    const t = std.testing;
    const addr: [32]u8 = @splat(0);
    const m: CompiledModule = .{
        .version = 7,
        .module_handles = &.{.{ .address = 0, .name = 0 }},
        .datatype_handles = &.{ .{ .module = 0, .name = 1, .abilities = .EMPTY, .type_parameters = &.{} }, .{ .module = 0, .name = 2, .abilities = .EMPTY, .type_parameters = &.{} } },
        .identifiers = &.{ "m", "A", "B" },
        .address_identifiers = &.{addr},
    };
    const va: []const ff.Node = &.{ .{ .tag = .Vector }, .{ .tag = .Datatype, .idx = 0 } };
    const vb: []const ff.Node = &.{ .{ .tag = .Vector }, .{ .tag = .Datatype, .idx = 1 } };
    const p0: []const ff.Node = &.{.{ .tag = .TypeParameter, .idx = 0 }};
    const p1: []const ff.Node = &.{.{ .tag = .TypeParameter, .idx = 1 }};
    try t.expect(sameType(&m, va, &m, va));
    try t.expect(!sameType(&m, va, &m, vb));
    try t.expect(!sameType(&m, p0, &m, p1));
    try t.expect(!sameType(&m, p0, &m, va));
}
