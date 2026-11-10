//! `clever_error` on a MoveAbort (sui-rpc-api 1.83.1 `render.rs` `render_clever_error`,
//! sui-package-resolver `Package::resolve_clever_error`, move-command-line-common `ErrorBitset`
//! and `try_render_constant`). The abort location's package is read from the store's live set
//! (`get_object`), parsed like `Package::read_from_object` (any failure: no clever_error), and
//! the abort code's bitset picks the line number, error code and the identifier/value constants
//! of the module's constant pool.
//!
//! The renderers have no store, so the service installs a per-request hook
//! (`exec_error.clever_hook`, thread-local) for the duration of a request; without it MoveAbort
//! renders as before.
const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store");
const mf = @import("move_format");
const proto = @import("proto.zig");
const movepkg = @import("movepkg.zig");
const exec_error = @import("exec_error.zig");
const service = @import("service.zig");

const ff = mf.file_format;

/// `ErrorBitset::from_u64`: msb0 layout | version 4 | reserved 4 | code 8 | line 16 | ident 16 |
/// const 16 |; versions 0b1000 and 0b1100.
pub const Bitset = struct {
    version: u8,
    error_code: u8,
    line: u16,
    ident: u16,
    constant: u16,

    pub fn fromU64(bits: u64) ?Bitset {
        const v: u8 = @intCast(bits >> 60);
        if (v != 0b1000 and v != 0b1100) return null;
        return .{
            .version = v,
            .error_code = @truncate(bits >> 48),
            .line = @truncate(bits >> 32),
            .ident = @truncate(bits >> 16),
            .constant = @truncate(bits),
        };
    }
    fn sentinel16(x: u16) ?u16 {
        return if (x == std.math.maxInt(u16)) null else x;
    }
    pub fn lineNumber(b: Bitset) ?u16 {
        return sentinel16(b.line);
    }
    pub fn identifierIndex(b: Bitset) ?u16 {
        return sentinel16(b.ident);
    }
    pub fn constantIndex(b: Bitset) ?u16 {
        return sentinel16(b.constant);
    }
    pub fn errorCode(b: Bitset) ?u8 {
        if (b.version == 0b1000) return null;
        return if (b.error_code == std.math.maxInt(u8)) null else b.error_code;
    }
};

pub const Info = union(enum) {
    none,
    rendered: struct { identifier: []const u8, constant: []const u8 },
    raw: struct { identifier: []const u8, bytes: []const u8 },
};

pub const Clever = struct {
    info: Info,
    line: u16,
    error_code: ?u8,
};

/// `bcs::from_bytes::<Vec<u8>>`: ULEB128 length, then exactly that many bytes, nothing after.
fn bcsBytes(data: []const u8) ?[]const u8 {
    var len: u64 = 0;
    var shift: u6 = 0;
    var i: usize = 0;
    while (true) {
        if (i >= data.len) return null;
        const c = data[i];
        i += 1;
        len |= @as(u64, c & 0x7f) << shift;
        if (c & 0x80 == 0) {
            // canonical ULEB128 only (bcs rejects a trailing zero group), u32 range
            if (c == 0 and i > 1) return null;
            break;
        }
        if (shift >= 28) return null;
        shift += 7;
    }
    if (len > std.math.maxInt(u32)) return null;
    if (data.len - i != len) return null;
    return data[i..];
}

fn leInt(comptime T: type, data: []const u8) ?T {
    if (data.len != @sizeOf(T)) return null;
    return std.mem.readInt(T, data[0..@sizeOf(T)], .little);
}

const Rendered = union(enum) { string: []const u8, value: []const u8, not_rendered };

/// `try_render_constant`.
pub fn renderConstant(arena: Allocator, c: ff.Constant) Allocator.Error!Rendered {
    const t = c.type_;
    if (t.len == 0) return .not_rendered;
    const d = c.data;
    switch (t[0].tag) {
        .Vector => {
            if (t.len == 2 and t[1].tag == .U8) {
                const b = bcsBytes(d) orelse return .not_rendered;
                if (!std.unicode.utf8ValidateSlice(b)) return .not_rendered;
                return .{ .string = b };
            }
            return .not_rendered;
        },
        .U8 => return if (leInt(u8, d)) |x| .{ .value = try std.fmt.allocPrint(arena, "{d}", .{x}) } else .not_rendered,
        .U16 => return if (leInt(u16, d)) |x| .{ .value = try std.fmt.allocPrint(arena, "{d}", .{x}) } else .not_rendered,
        .U32 => return if (leInt(u32, d)) |x| .{ .value = try std.fmt.allocPrint(arena, "{d}", .{x}) } else .not_rendered,
        .U64 => return if (leInt(u64, d)) |x| .{ .value = try std.fmt.allocPrint(arena, "{d}", .{x}) } else .not_rendered,
        .U128 => return if (leInt(u128, d)) |x| .{ .value = try std.fmt.allocPrint(arena, "{d}", .{x}) } else .not_rendered,
        .U256 => return if (leInt(u256, d)) |x| .{ .value = try std.fmt.allocPrint(arena, "{d}", .{x}) } else .not_rendered,
        .Address => {
            if (d.len != 32) return .not_rendered;
            return .{ .value = try std.fmt.allocPrint(arena, "0x{x}", .{d}) };
        },
        .Bool => {
            if (d.len != 1 or d[0] > 1) return .not_rendered;
            return .{ .value = if (d[0] == 1) "true" else "false" };
        },
        else => return .not_rendered,
    }
}

fn findModule(pkg: *const movepkg.Package, name: []const u8) ?*const ff.CompiledModule {
    for (pkg.mods) |*m| if (std.mem.eql(u8, m.name, name)) return &m.cm;
    return null;
}

/// `Package::resolve_clever_error` on a parsed package.
pub fn resolve(arena: Allocator, pkg: *const movepkg.Package, module_name: []const u8, abort_code: u64) Allocator.Error!?Clever {
    const bits = Bitset.fromU64(abort_code) orelse return null;
    const cm = findModule(pkg, module_name) orelse return null;
    const line = bits.lineNumber() orelse return null;
    const code = bits.errorCode();
    const ii = bits.identifierIndex();
    const ci = bits.constantIndex();
    if (ii == null and ci == null) return .{ .info = .none, .line = line, .error_code = code };
    if (ii == null or ci == null) return null;
    if (ii.? >= cm.constant_pool.len or ci.? >= cm.constant_pool.len) return null;
    const ident_c = cm.constant_pool[ii.?];
    const value_c = cm.constant_pool[ci.?];
    if (!(ident_c.type_.len == 2 and ident_c.type_[0].tag == .Vector and ident_c.type_[1].tag == .U8)) return null;
    const ident = bcsBytes(ident_c.data) orelse return null;
    if (!std.unicode.utf8ValidateSlice(ident)) return null;
    return switch (try renderConstant(arena, value_c)) {
        .not_rendered => .{ .info = .{ .raw = .{ .identifier = ident, .bytes = value_c.data } }, .line = line, .error_code = code },
        .string, .value => |s| .{ .info = .{ .rendered = .{ .identifier = ident, .constant = s } }, .line = line, .error_code = code },
    };
}

/// CleverError { error_code = 1, line_number = 2, constant_name = 3, rendered = 5 | raw = 6 }.
pub fn write(w: *proto.Writer, field: u32, c: Clever) proto.Error!void {
    const hint = switch (c.info) {
        .none => 0,
        .rendered => |r| r.identifier.len + r.constant.len,
        .raw => |r| r.identifier.len + r.bytes.len,
    };
    const m = try w.begin(field, hint + 32);
    if (c.error_code) |e| try w.uint(1, e);
    try w.uint(2, c.line);
    switch (c.info) {
        .none => {},
        .rendered => |r| {
            try w.string(3, r.identifier);
            try w.string(5, r.constant);
        },
        .raw => |r| {
            try w.string(3, r.identifier);
            try w.bytes(6, r.bytes);
        },
    }
    try w.end(m);
}

/// Per-request resolver state behind `exec_error.clever_hook`.
pub const Ctx = struct {
    svc: *service.Service,
    snap: *store.Snapshot,
    arena: Allocator,

    pub fn hook(c: *Ctx) exec_error.CleverHook {
        return .{ .ctx = c, .write = writeHook };
    }
};

fn writeHook(ctx: *anyopaque, w: *proto.Writer, field: u32, package: *const [32]u8, module_name: []const u8, abort_code: u64) proto.Error!void {
    const c: *Ctx = @ptrCast(@alignCast(ctx));
    if (Bitset.fromU64(abort_code) == null) return; // most aborts: no package read
    const pkg = service.packageForClever(c.svc, c.arena, c.snap, package) orelse return;
    const r = (resolve(c.arena, pkg, module_name, abort_code) catch return) orelse return;
    try write(w, field, r);
}

test "bitset" {
    // version 1, code 3, line 42, ident 1, const 2
    const b = Bitset.fromU64((@as(u64, 0b1100) << 60) | (@as(u64, 3) << 48) | (@as(u64, 42) << 32) | (1 << 16) | 2).?;
    try std.testing.expectEqual(@as(?u16, 42), b.lineNumber());
    try std.testing.expectEqual(@as(?u8, 3), b.errorCode());
    try std.testing.expectEqual(@as(?u16, 1), b.identifierIndex());
    try std.testing.expectEqual(@as(?u16, 2), b.constantIndex());
    try std.testing.expect(Bitset.fromU64(7) == null);
    try std.testing.expectEqual(@as(?u8, null), Bitset.fromU64((@as(u64, 0b1000) << 60) | (@as(u64, 3) << 48)).?.errorCode());
    try std.testing.expectEqualStrings("abc", bcsBytes("\x03abc").?);
    try std.testing.expect(bcsBytes("\x03ab") == null);
}
