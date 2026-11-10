//! CompiledModule deserializer: a check-for-check port of move-binary-format `deserializer.rs`
//! (Mysten 1.83.1). Every rejection returns the same StatusCode Rust returns, found in the same
//! order. Followed by the bounds checker, as `CompiledModule::deserialize_with_config` does.
const std = @import("std");
const ff = @import("file_format.zig");
const check_bounds = @import("check_bounds.zig");
const Allocator = std.mem.Allocator;
const StatusCode = ff.StatusCode;
const PartialVmError = ff.PartialVmError;
const Node = ff.Node;
const Token = ff.Token;

/// move-binary-format `TableConfig`: per-table maximum entry counts.
pub const TableConfig = struct {
    module_handles: u16 = std.math.maxInt(u16),
    datatype_handles: u16 = std.math.maxInt(u16),
    function_handles: u16 = std.math.maxInt(u16),
    function_instantiations: u16 = std.math.maxInt(u16),
    signatures: u16 = std.math.maxInt(u16),
    constant_pool: u16 = std.math.maxInt(u16),
    identifiers: u16 = std.math.maxInt(u16),
    address_identifiers: u16 = std.math.maxInt(u16),
    struct_defs: u16 = std.math.maxInt(u16),
    struct_def_instantiations: u16 = std.math.maxInt(u16),
    function_defs: u16 = std.math.maxInt(u16),
    field_handles: u16 = std.math.maxInt(u16),
    field_instantiations: u16 = std.math.maxInt(u16),
    friend_decls: u16 = std.math.maxInt(u16),
    enum_defs: u16 = std.math.maxInt(u16),
    enum_def_instantiations: u16 = std.math.maxInt(u16),
    variant_handles: u16 = std.math.maxInt(u16),
    variant_instantiation_handles: u16 = std.math.maxInt(u16),
};

/// move-binary-format `BinaryConfig`, filled by the caller from the protocol config
/// (`ProtocolConfig::binary_config(None)`).
pub const BinaryConfig = struct {
    max_binary_format_version: u32 = ff.VERSION_MAX,
    min_binary_format_version: u32 = ff.VERSION_1,
    check_no_extraneous_bytes: bool = true,
    deprecate_global_storage_ops: bool = true,
    table_config: TableConfig = .{},
    allow_unpublishable: bool = false,
    /// `BinaryFormatLimits::type_parameter_index_max`, the one limit the 1.84 profiles differ in:
    /// LEGACY 65536 (a 65536 then fails the u16 conversion, UNKNOWN_INVARIANT_VIOLATION_ERROR),
    /// V1 (protocol 142 on, and `new_unpublishable`) 65535 (MALFORMED).
    type_parameter_index_max: u64 = ff.TYPE_PARAMETER_INDEX_MAX,
};

pub const Result = union(enum) { ok: ff.CompiledModule, err: PartialVmError };

const Fail = error{ Vm, OutOfMemory };

const Table = struct { kind: ff.TableType, offset: u32, count: u32 };

const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn readU8(c: *Cursor) ?u8 {
        if (c.pos >= c.buf.len) return null;
        const b = c.buf[c.pos];
        c.pos += 1;
        return b;
    }
    fn readExact(c: *Cursor, n: usize) ?[]const u8 {
        if (c.buf.len - c.pos < n) return null;
        const s = c.buf[c.pos..][0..n];
        c.pos += n;
        return s;
    }
    /// file_format_common `read_uleb128_as_u64`.
    fn readUleb(c: *Cursor) ?u64 {
        var value: u64 = 0;
        var shift: u32 = 0;
        while (c.readU8()) |byte| {
            const cur: u64 = byte & 0x7f;
            const sh: u6 = @intCast(shift);
            if ((cur << sh) >> sh != cur) return null;
            value |= cur << sh;
            if (byte & 0x80 == 0) {
                if (shift > 0 and cur == 0) return null;
                return value;
            }
            shift += 7;
            if (shift > 64) break;
        }
        return null;
    }
};

const D = struct {
    arena: Allocator,
    cfg: *const BinaryConfig,
    bin: []const u8,
    version: u32,
    data_offset: usize = 0,
    err: PartialVmError = undefined,
    // scratch for signature tokens, reused across tokens
    tok_nodes: std.ArrayList(Node) = .empty,

    fn fail(d: *D, code: StatusCode) Fail {
        d.err = PartialVmError.new(code);
        return error.Vm;
    }

    fn uleb(d: *D, c: *Cursor, max: u64) Fail!u64 {
        const x = c.readUleb() orelse return d.fail(.MALFORMED);
        if (x > max) return d.fail(.MALFORMED);
        return x;
    }
    fn idx(d: *D, c: *Cursor) Fail!u16 {
        return @intCast(try d.uleb(c, ff.TABLE_INDEX_MAX));
    }
    fn byte(d: *D, c: *Cursor) Fail!u8 {
        return c.readU8() orelse d.fail(.MALFORMED);
    }

    fn cursor(d: *D, t: Table) Cursor {
        const start = @as(usize, t.offset) + d.data_offset;
        return .{ .buf = d.bin[start .. start + t.count] };
    }
};

/// `CompiledModule::deserialize_with_config`: deserialize, then bounds-check.
/// The module borrows `bytes` (identifiers, addresses, constants, metadata) and allocates the
/// rest in `arena`.
pub fn deserialize(arena: Allocator, bytes: []const u8, cfg: *const BinaryConfig) Allocator.Error!Result {
    var d: D = .{ .arena = arena, .cfg = cfg, .bin = bytes, .version = 0 };
    const m = deserializeCompiledModule(&d) catch |e| switch (e) {
        error.Vm => return .{ .err = d.err },
        error.OutOfMemory => return error.OutOfMemory,
    };
    if (try check_bounds.verifyModule(arena, &m, cfg.deprecate_global_storage_ops)) |e| return .{ .err = e };
    return .{ .ok = m };
}

/// Deserialize without the bounds check (Rust `deserialize_no_check_bounds` shape, our config).
pub fn deserializeNoCheckBounds(arena: Allocator, bytes: []const u8, cfg: *const BinaryConfig) Allocator.Error!Result {
    var d: D = .{ .arena = arena, .cfg = cfg, .bin = bytes, .version = 0 };
    const m = deserializeCompiledModule(&d) catch |e| switch (e) {
        error.Vm => return .{ .err = d.err },
        error.OutOfMemory => return error.OutOfMemory,
    };
    return .{ .ok = m };
}

fn deserializeCompiledModule(d: *D) Fail!ff.CompiledModule {
    const bin = d.bin;
    var c: Cursor = .{ .buf = bin };
    // magic
    var publishable = true;
    if (bin.len < 4) return d.fail(.BAD_MAGIC);
    const magic = bin[0..4];
    c.pos = 4;
    if (std.mem.eql(u8, magic, &ff.MOVE_MAGIC)) {
        publishable = true;
    } else if (std.mem.eql(u8, magic, &ff.UNPUBLISHABLE_MAGIC)) {
        if (!d.cfg.allow_unpublishable) return d.fail(.BAD_MAGIC);
        publishable = false;
    } else return d.fail(.BAD_MAGIC);

    const vb = c.readExact(4) orelse return d.fail(.MALFORMED);
    const flavored = std.mem.readInt(u32, vb[0..4], .little);
    const version: u32 = if (flavored <= ff.VERSION_6) flavored else flavored & 0x00FF_FFFF;
    const flavor: ?u8 = if (flavored <= ff.VERSION_6) null else @intCast(flavored >> 24);
    if (version < d.cfg.min_binary_format_version) return d.fail(.UNKNOWN_VERSION);
    if (version > @min(d.cfg.max_binary_format_version, ff.VERSION_MAX)) return d.fail(.UNKNOWN_VERSION);
    if (version >= ff.VERSION_7 and flavor != ff.SUI_FLAVOR) return d.fail(.UNKNOWN_VERSION);
    d.version = version;

    // table headers
    const table_count: usize = @intCast(try d.uleb(&c, ff.TABLE_COUNT_MAX));
    var tables_buf: [255]Table = undefined;
    const tables = tables_buf[0..table_count];
    for (tables) |*t| {
        const kind = c.readU8() orelse return d.fail(.MALFORMED);
        const off: u32 = @intCast(try d.uleb(&c, ff.TABLE_OFFSET_MAX));
        const cnt: u32 = @intCast(try d.uleb(&c, ff.TABLE_SIZE_MAX));
        const tt: ff.TableType = @enumFromInt(kind);
        if (!tt.valid()) return d.fail(.UNKNOWN_TABLE_TYPE);
        t.* = .{ .kind = tt, .offset = off, .count = cnt };
    }
    // check_tables: stable sort by offset, contiguous from 0, non-empty, no duplicate kinds
    std.sort.insertion(Table, tables, {}, struct {
        fn lt(_: void, a: Table, b: Table) bool {
            return a.offset < b.offset;
        }
    }.lt);
    var current: u32 = 0;
    var seen: [256]bool = @splat(false);
    for (tables) |t| {
        if (t.offset != current) return d.fail(.BAD_HEADER_TABLE);
        if (t.count == 0) return d.fail(.BAD_HEADER_TABLE);
        current = std.math.add(u32, current, t.count) catch return d.fail(.BAD_HEADER_TABLE);
        if (seen[@intFromEnum(t.kind)]) return d.fail(.DUPLICATE_TABLE);
        seen[@intFromEnum(t.kind)] = true;
        if (current > bin.len) return d.fail(.BAD_HEADER_TABLE);
    }
    const table_size = current;
    if (@as(u64, table_size) + c.pos > bin.len) return d.fail(.MALFORMED);
    d.data_offset = c.pos;

    // self module handle index, after the table contents
    c.pos = d.data_offset + table_size;
    const self_idx = try d.idx(&c);
    const end_pos = c.pos;

    var m: ff.CompiledModule = .{ .version = version, .publishable = publishable, .self_module_handle_idx = self_idx };
    try buildCommonTables(d, tables, &m);
    try buildModuleTables(d, tables, &m);

    if (d.cfg.check_no_extraneous_bytes and end_pos < bin.len) return d.fail(.TRAILING_BYTES);
    return m;
}

fn checkSize(d: *D, len: usize, max: u16) Fail!void {
    if (len > max) return d.fail(.MALFORMED);
}

fn buildCommonTables(d: *D, tables: []const Table, m: *ff.CompiledModule) Fail!void {
    const tc = &d.cfg.table_config;
    for (tables) |t| {
        switch (t.kind) {
            .MODULE_HANDLES => {
                m.module_handles = try loadModuleHandles(d, t);
                try checkSize(d, m.module_handles.len, tc.module_handles);
            },
            .DATATYPE_HANDLES => {
                m.datatype_handles = try loadDatatypeHandles(d, t);
                try checkSize(d, m.datatype_handles.len, tc.datatype_handles);
            },
            .FUNCTION_HANDLES => {
                m.function_handles = try loadFunctionHandles(d, t);
                try checkSize(d, m.function_handles.len, tc.function_handles);
            },
            .FUNCTION_INST => {
                m.function_instantiations = try loadPairs(ff.FunctionInstantiation, d, t);
                try checkSize(d, m.function_instantiations.len, tc.function_instantiations);
            },
            .SIGNATURES => {
                m.signatures = try loadSignatures(d, t);
                try checkSize(d, m.signatures.len, tc.signatures);
            },
            .CONSTANT_POOL => {
                m.constant_pool = try loadConstants(d, t);
                try checkSize(d, m.constant_pool.len, tc.constant_pool);
            },
            .METADATA => {
                if (d.cfg.check_no_extraneous_bytes or d.version < ff.VERSION_5) return d.fail(.MALFORMED);
                m.metadata = try loadMetadata(d, t);
            },
            .IDENTIFIERS => {
                m.identifiers = try loadIdentifiers(d, t);
                try checkSize(d, m.identifiers.len, tc.identifiers);
            },
            .ADDRESS_IDENTIFIERS => {
                if (t.count % 32 != 0) return d.fail(.MALFORMED);
                const start = @as(usize, t.offset) + d.data_offset;
                const raw = d.bin[start .. start + t.count];
                m.address_identifiers = @as([*]const [32]u8, @ptrCast(raw.ptr))[0 .. t.count / 32];
                try checkSize(d, m.address_identifiers.len, tc.address_identifiers);
            },
            .FUNCTION_DEFS, .STRUCT_DEFS, .STRUCT_DEF_INST, .FIELD_HANDLE, .FIELD_INST => {},
            .ENUM_DEFS, .ENUM_DEF_INST, .VARIANT_HANDLES, .VARIANT_INST_HANDLES => {
                if (d.version < ff.VERSION_7) return d.fail(.MALFORMED);
            },
            .FRIEND_DECLS => {
                if (d.version < ff.VERSION_2) return d.fail(.MALFORMED);
            },
            _ => unreachable,
        }
    }
}

fn buildModuleTables(d: *D, tables: []const Table, m: *ff.CompiledModule) Fail!void {
    const tc = &d.cfg.table_config;
    for (tables) |t| {
        switch (t.kind) {
            .ENUM_DEFS => {
                m.enum_defs = try loadEnumDefs(d, t);
                try checkSize(d, m.enum_defs.len, tc.enum_defs);
            },
            .ENUM_DEF_INST => {
                if (d.version < ff.VERSION_7) return d.fail(.MALFORMED);
                m.enum_def_instantiations = try loadPairs(ff.EnumDefInstantiation, d, t);
                try checkSize(d, m.enum_def_instantiations.len, tc.enum_def_instantiations);
            },
            .STRUCT_DEFS => {
                m.struct_defs = try loadStructDefs(d, t);
                try checkSize(d, m.struct_defs.len, tc.struct_defs);
            },
            .STRUCT_DEF_INST => {
                m.struct_def_instantiations = try loadPairs(ff.StructDefInstantiation, d, t);
                try checkSize(d, m.struct_def_instantiations.len, tc.struct_def_instantiations);
            },
            .FUNCTION_DEFS => {
                m.function_defs = try loadFunctionDefs(d, t, m);
                try checkSize(d, m.function_defs.len, tc.function_defs);
            },
            .FIELD_HANDLE => {
                m.field_handles = try loadFieldHandles(d, t);
                try checkSize(d, m.field_handles.len, tc.field_handles);
            },
            .FIELD_INST => {
                m.field_instantiations = try loadPairs(ff.FieldInstantiation, d, t);
                try checkSize(d, m.field_instantiations.len, tc.field_instantiations);
            },
            .FRIEND_DECLS => {
                m.friend_decls = try loadModuleHandles(d, t);
                try checkSize(d, m.friend_decls.len, tc.friend_decls);
            },
            .VARIANT_HANDLES => {
                if (d.version < ff.VERSION_7) return d.fail(.MALFORMED);
                m.variant_handles = try loadVariantHandles(ff.VariantHandle, d, t, 0);
                try checkSize(d, m.variant_handles.len, tc.variant_handles);
            },
            .VARIANT_INST_HANDLES => {
                if (d.version < ff.VERSION_7) return d.fail(.MALFORMED);
                m.variant_instantiation_handles = try loadVariantHandles(ff.VariantInstantiationHandle, d, t, 0);
                try checkSize(d, m.variant_instantiation_handles.len, tc.variant_instantiation_handles);
            },
            else => {},
        }
    }
}

fn loadModuleHandles(d: *D, t: Table) Fail![]const ff.ModuleHandle {
    var c = d.cursor(t);
    var out: std.ArrayList(ff.ModuleHandle) = .empty;
    while (c.pos < t.count) {
        const address = try d.idx(&c);
        const name = try d.idx(&c);
        try out.append(d.arena, .{ .address = address, .name = name });
    }
    return out.items;
}

/// Tables of two index fields (`a` read first): instantiations.
fn loadPairs(comptime T: type, d: *D, t: Table) Fail![]const T {
    var c = d.cursor(t);
    var out: std.ArrayList(T) = .empty;
    const fields = @typeInfo(T).@"struct".field_names;
    while (c.pos < t.count) {
        var v: T = undefined;
        @field(v, fields[0]) = try d.idx(&c);
        @field(v, fields[1]) = try d.idx(&c);
        try out.append(d.arena, v);
    }
    return out.items;
}

fn loadVariantHandles(comptime T: type, d: *D, t: Table, comptime _: u64) Fail![]const T {
    var c = d.cursor(t);
    var out: std.ArrayList(T) = .empty;
    while (c.pos < t.count) {
        const e = try d.idx(&c);
        const variant: u16 = @intCast(try d.uleb(&c, ff.VARIANT_TAG_MAX_VALUE));
        try out.append(d.arena, .{ .enum_def = e, .variant = variant });
    }
    return out.items;
}

const AbilityPos = enum { function_type_parameters, datatype_ty_parameters, datatype_handle };

fn loadAbilitySet(d: *D, c: *Cursor, pos: AbilityPos) Fail!ff.AbilitySet {
    if (d.version < 2) {
        const b = c.readU8() orelse return d.fail(.MALFORMED);
        switch (pos) {
            .datatype_handle => return switch (b) {
                0x1 => .{ .bits = 0x4 | 0x8 },
                0x2 => .{ .bits = 0x4 | 0x1 | 0x2 },
                else => d.fail(.UNKNOWN_ABILITY),
            },
            else => {
                const set: ff.AbilitySet = switch (b) {
                    0x1 => ff.AbilitySet.EMPTY,
                    0x2 => .{ .bits = 0x1 | 0x2 },
                    0x3 => .{ .bits = 0x8 },
                    else => return d.fail(.UNKNOWN_ABILITY),
                };
                return if (pos == .function_type_parameters) set.with(.Store) else set;
            },
        }
    }
    const u = try d.uleb(c, 0xF);
    return .{ .bits = @intCast(u) };
}

fn loadDatatypeHandles(d: *D, t: Table) Fail![]const ff.DatatypeHandle {
    var c = d.cursor(t);
    var out: std.ArrayList(ff.DatatypeHandle) = .empty;
    while (c.pos < t.count) {
        const module = try d.idx(&c);
        const name = try d.idx(&c);
        const abilities = try loadAbilitySet(d, &c, .datatype_handle);
        const n: usize = @intCast(try d.uleb(&c, ff.TYPE_PARAMETER_COUNT_MAX));
        const tps = try d.arena.alloc(ff.DatatypeTyParameter, n);
        for (tps) |*tp| {
            const constraints = try loadAbilitySet(d, &c, .datatype_ty_parameters);
            const is_phantom = if (d.version < ff.VERSION_3) false else (try d.uleb(&c, 1)) != 0;
            tp.* = .{ .constraints = constraints, .is_phantom = is_phantom };
        }
        try out.append(d.arena, .{ .module = module, .name = name, .abilities = abilities, .type_parameters = tps });
    }
    return out.items;
}

fn loadFunctionHandles(d: *D, t: Table) Fail![]const ff.FunctionHandle {
    var c = d.cursor(t);
    var out: std.ArrayList(ff.FunctionHandle) = .empty;
    while (c.pos < t.count) {
        const module = try d.idx(&c);
        const name = try d.idx(&c);
        const params = try d.idx(&c);
        const ret = try d.idx(&c);
        const n: usize = @intCast(try d.uleb(&c, ff.TYPE_PARAMETER_COUNT_MAX));
        const tps = try d.arena.alloc(ff.AbilitySet, n);
        for (tps) |*a| a.* = try loadAbilitySet(d, &c, .function_type_parameters);
        try out.append(d.arena, .{ .module = module, .name = name, .parameters = params, .return_ = ret, .type_parameters = tps });
    }
    return out.items;
}

/// Rust `Identifier::is_valid`.
pub fn isValidIdentifier(s: []const u8) bool {
    if (s.len == 0) return false;
    const first = s[0];
    if (std.ascii.isAlphabetic(first)) {
        // ok
    } else if (first == '_' and s.len > 1) {
        // ok
    } else return false;
    for (s[1..]) |ch| {
        if (!(ch == '_' or std.ascii.isAlphanumeric(ch))) return false;
    }
    return true;
}

fn loadIdentifiers(d: *D, t: Table) Fail![]const []const u8 {
    var c = d.cursor(t);
    var out: std.ArrayList([]const u8) = .empty;
    while (c.pos < t.count) {
        const size: usize = @intCast(try d.uleb(&c, ff.IDENTIFIER_SIZE_MAX));
        if (c.buf.len - c.pos < size) return d.fail(.MALFORMED);
        const s = c.buf[c.pos..][0..size];
        c.pos += size;
        if (!isValidIdentifier(s)) return d.fail(.MALFORMED);
        try out.append(d.arena, s);
    }
    return out.items;
}

fn loadBlob(d: *D, c: *Cursor, max: u64) Fail![]const u8 {
    const size: usize = @intCast(try d.uleb(c, max));
    if (c.buf.len - c.pos < size) return d.fail(.MALFORMED);
    const s = c.buf[c.pos..][0..size];
    c.pos += size;
    return s;
}

fn loadConstants(d: *D, t: Table) Fail![]const ff.Constant {
    var c = d.cursor(t);
    var out: std.ArrayList(ff.Constant) = .empty;
    while (c.pos < t.count) {
        const ty = try loadToken(d, &c);
        const data = try loadBlob(d, &c, ff.CONSTANT_SIZE_MAX);
        try out.append(d.arena, .{ .type_ = ty, .data = data });
    }
    return out.items;
}

fn loadMetadata(d: *D, t: Table) Fail![]const ff.Metadata {
    var c = d.cursor(t);
    var out: std.ArrayList(ff.Metadata) = .empty;
    while (c.pos < t.count) {
        const key = try loadBlob(d, &c, ff.METADATA_KEY_SIZE_MAX);
        const value = try loadBlob(d, &c, ff.METADATA_VALUE_SIZE_MAX);
        try out.append(d.arena, .{ .key = key, .value = value });
    }
    return out.items;
}

fn loadSignatures(d: *D, t: Table) Fail![]const []const Token {
    var c = d.cursor(t);
    var out: std.ArrayList([]const Token) = .empty;
    while (c.pos < t.count) {
        const len: usize = @intCast(try d.uleb(&c, ff.SIGNATURE_SIZE_MAX));
        const toks = try d.arena.alloc(Token, len);
        for (toks) |*tok| tok.* = try loadToken(d, &c);
        try out.append(d.arena, toks);
    }
    return out.items;
}

/// `load_signature_token`: the same builder stack as Rust, so the depth error triggers at the
/// same point. Nodes come out in preorder as they are read.
fn loadToken(d: *D, c: *Cursor) Fail!Token {
    d.tok_nodes.clearRetainingCapacity();
    // Builder frames: true = saturated (a finished token on the stack), else an open
    // constructor with `left` arguments still to come.
    var stack_buf: [ff.SIGNATURE_TOKEN_DEPTH_MAX + 2]Frame = undefined;
    var sp: usize = 0;

    var first = try readNext(d, c);
    if (first.saturated) return try d.arena.dupe(Node, d.tok_nodes.items);
    stack_buf[0] = first;
    sp = 1;
    while (true) {
        if (sp > ff.SIGNATURE_TOKEN_DEPTH_MAX) return d.fail(.MALFORMED);
        if (stack_buf[sp - 1].saturated) {
            sp -= 1; // pop the finished token
            if (sp == 0) return try d.arena.dupe(Node, d.tok_nodes.items);
            // apply it to its parent
            const parent = &stack_buf[sp - 1];
            parent.left -= 1;
            if (parent.left == 0) parent.saturated = true;
        } else {
            first = try readNext(d, c);
            stack_buf[sp] = first;
            sp += 1;
        }
    }
}

const Frame = struct { saturated: bool, left: u16 };

fn readNext(d: *D, c: *Cursor) Fail!Frame {
    const b = c.readU8() orelse return d.fail(.MALFORMED);
    if (b < 0x1 or b > 0xF) return d.fail(.UNKNOWN_SERIALIZED_TYPE);
    if ((b == 0xD or b == 0xE or b == 0xF) and d.version < ff.VERSION_6) return d.fail(.MALFORMED);
    const leaf: Frame = .{ .saturated = true, .left = 0 };
    switch (b) {
        0x1 => try d.tok_nodes.append(d.arena, .{ .tag = .Bool }),
        0x2 => try d.tok_nodes.append(d.arena, .{ .tag = .U8 }),
        0x3 => try d.tok_nodes.append(d.arena, .{ .tag = .U64 }),
        0x4 => try d.tok_nodes.append(d.arena, .{ .tag = .U128 }),
        0x5 => try d.tok_nodes.append(d.arena, .{ .tag = .Address }),
        0xC => try d.tok_nodes.append(d.arena, .{ .tag = .Signer }),
        0xD => try d.tok_nodes.append(d.arena, .{ .tag = .U16 }),
        0xE => try d.tok_nodes.append(d.arena, .{ .tag = .U32 }),
        0xF => try d.tok_nodes.append(d.arena, .{ .tag = .U256 }),
        0x6 => {
            try d.tok_nodes.append(d.arena, .{ .tag = .Reference });
            return .{ .saturated = false, .left = 1 };
        },
        0x7 => {
            try d.tok_nodes.append(d.arena, .{ .tag = .MutableReference });
            return .{ .saturated = false, .left = 1 };
        },
        0xA => {
            try d.tok_nodes.append(d.arena, .{ .tag = .Vector });
            return .{ .saturated = false, .left = 1 };
        },
        0x8 => {
            const i = try d.idx(c);
            try d.tok_nodes.append(d.arena, .{ .tag = .Datatype, .idx = i });
        },
        0xB => {
            const i = try d.idx(c);
            const arity = try d.uleb(c, ff.TYPE_PARAMETER_COUNT_MAX);
            if (arity == 0) return d.fail(.MALFORMED);
            try d.tok_nodes.append(d.arena, .{ .tag = .DatatypeInstantiation, .idx = i, .arity = @intCast(arity) });
            return .{ .saturated = false, .left = @intCast(arity) };
        },
        0x9 => {
            const x = try d.uleb(c, d.cfg.type_parameter_index_max);
            // Rust: u64 -> u16 try_into after the max check (65536 fails here)
            if (x > std.math.maxInt(u16)) return d.fail(.UNKNOWN_INVARIANT_VIOLATION_ERROR);
            try d.tok_nodes.append(d.arena, .{ .tag = .TypeParameter, .idx = @intCast(x) });
        },
        else => unreachable,
    }
    return leaf;
}

fn loadFieldDefs(d: *D, c: *Cursor) Fail![]const ff.FieldDefinition {
    const n: usize = @intCast(try d.uleb(c, ff.FIELD_COUNT_MAX));
    const fields = try d.arena.alloc(ff.FieldDefinition, n);
    for (fields) |*f| {
        const name = try d.idx(c);
        const sig = try loadToken(d, c);
        f.* = .{ .name = name, .signature = sig };
    }
    return fields;
}

fn loadStructDefs(d: *D, t: Table) Fail![]const ff.StructDefinition {
    var c = d.cursor(t);
    var out: std.ArrayList(ff.StructDefinition) = .empty;
    while (c.pos < t.count) {
        const handle = try d.idx(&c);
        const flag = c.readU8() orelse return d.fail(.MALFORMED);
        switch (flag) {
            0x1 => try out.append(d.arena, .{ .struct_handle = handle, .native = true, .fields = &.{} }),
            0x2 => {
                const fields = try loadFieldDefs(d, &c);
                try out.append(d.arena, .{ .struct_handle = handle, .native = false, .fields = fields });
            },
            else => return d.fail(.UNKNOWN_NATIVE_STRUCT_FLAG),
        }
    }
    return out.items;
}

fn loadEnumDefs(d: *D, t: Table) Fail![]const ff.EnumDefinition {
    if (t.count > 0 and d.version < ff.VERSION_7) return d.fail(.MALFORMED);
    var c = d.cursor(t);
    var out: std.ArrayList(ff.EnumDefinition) = .empty;
    while (c.pos < t.count) {
        const handle = try d.idx(&c);
        const flag = c.readU8() orelse return d.fail(.MALFORMED);
        if (flag != 0x2) return d.fail(.UNKNOWN_ENUM_FLAG);
        const n: usize = @intCast(try d.uleb(&c, ff.VARIANT_COUNT_MAX));
        if (n == 0) return d.fail(.MALFORMED);
        const variants = try d.arena.alloc(ff.VariantDefinition, n);
        for (variants) |*v| {
            const name = try d.idx(&c);
            const fields = try loadFieldDefs(d, &c);
            v.* = .{ .variant_name = name, .fields = fields };
        }
        try out.append(d.arena, .{ .enum_handle = handle, .variants = variants });
    }
    return out.items;
}

fn loadFieldHandles(d: *D, t: Table) Fail![]const ff.FieldHandle {
    var c = d.cursor(t);
    var out: std.ArrayList(ff.FieldHandle) = .empty;
    while (c.pos != t.count) {
        const owner = try d.idx(&c);
        const field: u16 = @intCast(try d.uleb(&c, ff.FIELD_OFFSET_MAX));
        try out.append(d.arena, .{ .owner = owner, .field = field });
    }
    return out.items;
}

fn loadFunctionDefs(d: *D, t: Table, m: *ff.CompiledModule) Fail![]const ff.FunctionDefinition {
    var c = d.cursor(t);
    var out: std.ArrayList(ff.FunctionDefinition) = .empty;
    var wide: std.ArrayList([32]u8) = .empty;
    while (c.pos < t.count) {
        try out.append(d.arena, try loadFunctionDef(d, &c, &wide));
    }
    m.wide = wide.items;
    return out.items;
}

fn loadFunctionDef(d: *D, c: *Cursor, wide: *std.ArrayList([32]u8)) Fail!ff.FunctionDefinition {
    const function = try d.idx(c);
    var flags = c.readU8() orelse return d.fail(.MALFORMED);
    var visibility: ff.Visibility = .Private;
    var is_entry = false;
    var extra: u8 = 0;
    if (d.version == ff.VERSION_1) {
        if (flags & ff.FunctionDefinition.DEPRECATED_PUBLIC_BIT != 0) {
            flags ^= ff.FunctionDefinition.DEPRECATED_PUBLIC_BIT;
            visibility = .Public;
        }
        extra = flags;
    } else if (d.version < ff.VERSION_5) {
        if (flags == ff.Visibility.DEPRECATED_SCRIPT) {
            visibility = .Public;
            is_entry = true;
        } else {
            visibility = visibilityFrom(flags) orelse return d.fail(.MALFORMED);
        }
        extra = c.readU8() orelse return d.fail(.MALFORMED);
    } else {
        visibility = visibilityFrom(flags) orelse return d.fail(.MALFORMED);
        extra = c.readU8() orelse return d.fail(.MALFORMED);
        is_entry = extra & ff.FunctionDefinition.ENTRY != 0;
        if (is_entry) extra ^= ff.FunctionDefinition.ENTRY;
    }
    const n_acq: usize = @intCast(try d.uleb(c, ff.ACQUIRES_COUNT_MAX));
    const acquires = try d.arena.alloc(u16, n_acq);
    for (acquires) |*a| a.* = try d.idx(c);
    if (n_acq != 0 and d.cfg.deprecate_global_storage_ops) return d.fail(.DEPRECATED_BYTECODE_FORMAT);
    var code: ?ff.CodeUnit = null;
    if (extra & ff.FunctionDefinition.NATIVE != 0) {
        extra ^= ff.FunctionDefinition.NATIVE;
    } else {
        code = try loadCodeUnit(d, c, wide);
    }
    if (extra != 0) return d.fail(.INVALID_FLAG_BITS);
    return .{ .function = function, .visibility = visibility, .is_entry = is_entry, .acquires = acquires, .code = code };
}

fn visibilityFrom(b: u8) ?ff.Visibility {
    return switch (b) {
        0x0 => .Private,
        0x1 => .Public,
        0x3 => .Friend,
        else => null,
    };
}

fn loadCodeUnit(d: *D, c: *Cursor, wide: *std.ArrayList([32]u8)) Fail!ff.CodeUnit {
    const locals = try d.idx(c);
    const count: usize = @intCast(try d.uleb(c, ff.BYTECODE_COUNT_MAX));
    const code = try d.arena.alloc(ff.Instr, count);
    for (code) |*ins| ins.* = try loadInstr(d, c, wide);
    var jts: []ff.JumpTable = &.{};
    if (d.version >= ff.VERSION_7) {
        const n: usize = @intCast(try d.uleb(c, ff.JUMP_TABLE_INDEX_MAX));
        jts = try d.arena.alloc(ff.JumpTable, n);
        for (jts) |*jt| {
            const head = try d.idx(c);
            const branches: usize = @intCast(try d.uleb(c, ff.VARIANT_COUNT_MAX));
            const flag = c.readU8() orelse return d.fail(.MALFORMED);
            if (flag != 0x1) return d.fail(.UNKNOWN_JUMP_TABLE_FLAG);
            const offs = try d.arena.alloc(u16, branches);
            for (offs) |*o| o.* = @intCast(try d.uleb(c, ff.BYTECODE_INDEX_MAX));
            jt.* = .{ .head_enum = head, .offsets = offs };
        }
    }
    return .{ .locals = locals, .code = code, .jump_tables = jts };
}

fn loadInstr(d: *D, c: *Cursor, wide: *std.ArrayList([32]u8)) Fail!ff.Instr {
    const b = c.readU8() orelse return d.fail(.MALFORMED);
    const op: ff.Opcode = @enumFromInt(b);
    if (!op.isValid()) return d.fail(.UNKNOWN_OPCODE);
    switch (op) {
        .VecPack, .VecLen, .VecImmBorrow, .VecMutBorrow, .VecPushBack, .VecPopBack, .VecUnpack, .VecSwap => {
            if (d.version < ff.VERSION_4) return d.fail(.MALFORMED);
        },
        .LdU16, .LdU32, .LdU256, .CastU16, .CastU32, .CastU256 => {
            if (d.version < ff.VERSION_6) return d.fail(.MALFORMED);
        },
        else => {},
    }
    var ins: ff.Instr = .{ .op = op };
    switch (op) {
        .Pop, .Ret, .CastU8, .CastU64, .CastU128, .LdTrue, .LdFalse, .ReadRef, .WriteRef, .Add, .Sub, .Mul, .Mod, .Div, .BitOr, .BitAnd, .Xor, .Shl, .Shr, .Or, .And, .Not, .Eq, .Neq, .Lt, .Gt, .Le, .Ge, .Abort, .Nop, .FreezeRef, .CastU16, .CastU32, .CastU256 => {},
        .BrTrue, .BrFalse, .Branch => ins.idx = @intCast(try d.uleb(c, ff.BYTECODE_INDEX_MAX)),
        .LdU8 => ins.imm = c.readU8() orelse return d.fail(.MALFORMED),
        .LdU64 => {
            const s = c.readExact(8) orelse return d.fail(.BAD_U64);
            ins.imm = std.mem.readInt(u64, s[0..8], .little);
        },
        .LdU16 => {
            const s = c.readExact(2) orelse return d.fail(.BAD_U16);
            ins.imm = std.mem.readInt(u16, s[0..2], .little);
        },
        .LdU32 => {
            const s = c.readExact(4) orelse return d.fail(.BAD_U32);
            ins.imm = std.mem.readInt(u32, s[0..4], .little);
        },
        .LdU128 => {
            const s = c.readExact(16) orelse return d.fail(.BAD_U128);
            var w: [32]u8 = @splat(0);
            @memcpy(w[0..16], s);
            ins.imm = wide.items.len;
            try wide.append(d.arena, w);
        },
        .LdU256 => {
            const s = c.readExact(32) orelse return d.fail(.BAD_U256);
            ins.imm = wide.items.len;
            try wide.append(d.arena, s[0..32].*);
        },
        .CopyLoc, .MoveLoc, .StLoc, .MutBorrowLoc, .ImmBorrowLoc => ins.idx = @intCast(try d.uleb(c, ff.LOCAL_INDEX_MAX)),
        .LdConst, .MutBorrowField, .MutBorrowFieldGeneric, .ImmBorrowField, .ImmBorrowFieldGeneric, .Call, .CallGeneric, .Pack, .PackGeneric, .Unpack, .UnpackGeneric, .VecLen, .VecImmBorrow, .VecMutBorrow, .VecPushBack, .VecPopBack, .VecSwap => ins.idx = try d.idx(c),
        .VecPack, .VecUnpack => {
            ins.idx = try d.idx(c);
            const s = c.readExact(8) orelse return d.fail(.BAD_U64);
            ins.imm = std.mem.readInt(u64, s[0..8], .little);
        },
        .PackVariant, .UnpackVariant, .UnpackVariantImmRef, .UnpackVariantMutRef => {
            if (d.version < ff.VERSION_7) return d.fail(.MALFORMED);
            ins.idx = @intCast(try d.uleb(c, ff.VARIANT_HANDLE_INDEX_MAX));
        },
        .PackVariantGeneric, .UnpackVariantGeneric, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => {
            if (d.version < ff.VERSION_7) return d.fail(.MALFORMED);
            ins.idx = @intCast(try d.uleb(c, ff.VARIANT_INSTANTIATION_HANDLE_INDEX_MAX));
        },
        .VariantSwitch => {
            if (d.version < ff.VERSION_7) return d.fail(.MALFORMED);
            ins.idx = @intCast(try d.uleb(c, ff.JUMP_TABLE_INDEX_MAX));
        },
        .ExistsDeprecated, .ExistsGenericDeprecated, .MutBorrowGlobalDeprecated, .MutBorrowGlobalGenericDeprecated, .ImmBorrowGlobalDeprecated, .ImmBorrowGlobalGenericDeprecated, .MoveFromDeprecated, .MoveFromGenericDeprecated, .MoveToDeprecated, .MoveToGenericDeprecated => {
            if (d.cfg.deprecate_global_storage_ops) return d.fail(.DEPRECATED_BYTECODE_FORMAT);
            ins.idx = try d.idx(c);
        },
        _ => unreachable,
    }
    return ins;
}

test "type parameter index limit: LEGACY 65536 then u16 conversion, V1 (protocol 142) 65535" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // SignatureToken::TypeParameter (0x9) with uleb index 65535 / 65536
    const ok_bytes = [_]u8{ 0x9, 0xff, 0xff, 0x03 };
    const big_bytes = [_]u8{ 0x9, 0x80, 0x80, 0x04 };
    const legacy: BinaryConfig = .{};
    const v1: BinaryConfig = .{ .type_parameter_index_max = 65535 };
    const cases = [_]struct { *const BinaryConfig, []const u8, ?StatusCode }{
        .{ &legacy, &ok_bytes, null },
        .{ &v1, &ok_bytes, null },
        .{ &legacy, &big_bytes, .UNKNOWN_INVARIANT_VIOLATION_ERROR },
        .{ &v1, &big_bytes, .MALFORMED },
    };
    for (cases) |cs| {
        var d: D = .{ .arena = a, .cfg = cs[0], .bin = cs[1], .version = ff.VERSION_MAX };
        var c: Cursor = .{ .buf = cs[1] };
        if (readNext(&d, &c)) |_| {
            try std.testing.expect(cs[2] == null);
            try std.testing.expectEqual(@as(u16, 65535), d.tok_nodes.items[0].idx);
        } else |e| {
            try std.testing.expectEqual(error.Vm, e);
            try std.testing.expectEqual(cs[2].?, d.err.major);
        }
    }
}
