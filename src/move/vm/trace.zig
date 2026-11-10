//! The execution tracer: move-vm-runtime 1.83 `execution/tracing/tracer.rs` with the
//! `move-trace-format` output (format version 3), event for event.
//!
//! The interpreter calls the hooks only when it runs with a tracer (`Session.tracer`), through a
//! comptime-specialised step loop, so an untraced run has no tracing code in it at all.
//!
//! Like Rust, the tracer keeps its own mirror of the operand stack (`ts`: a layout and, for
//! references, the rooted location) and of every frame's locals, and reads the interpreter's
//! values when it snapshots. Layouts are fully instantiated runtime types (`*const Type`); a
//! layout Rust cannot compute (value depth or node limits) is null here too. Every `?` in the
//! Rust code is an `orelse return null` here, so tracer failures surface at the same events.
//!
//! Output: one JSON line per event, exactly as `serde_json::to_writer(&TraceEvent)` writes it,
//! without the leading `{"version":3}` line.
const std = @import("std");
const move_format = @import("move_format");
const loader = @import("loader.zig");
const value = @import("value.zig");
const types = @import("types.zig");
const interp = @import("interp.zig");

const Allocator = std.mem.Allocator;
const ff = move_format.file_format;
const StatusCode = move_format.StatusCode;
const Type = loader.Type;
const Value = value.Value;
const Session = interp.Session;
const Function = loader.Function;

/// A location a reference is rooted in (`RuntimeLocation`). `stack` never appears in output.
pub const Loc = union(enum) {
    stack: usize,
    local: [2]usize, // (frame trace index, local index)
    indexed: struct { base: *const Loc, i: usize },
    global: usize,
};

const Ref = struct { mut: bool, loc: *const Loc };
const StackType = struct { layout: *const Type, ref: ?Ref = null };
const RefKind = union(enum) { value, empty: bool, filled: Ref };
const LocalType = struct { layout: ?*const Type, kind: RefKind };
/// A type tag with its layout (null: not computable) and reference kind.
const TagInfo = struct { ty: *const Type, layout: ?*const Type, ref: ?bool };
const FrameInfo = struct { id: usize, is_native: bool, locals: []LocalType, returns: []const TagInfo };
const TV = struct { kind: enum { val, imm, mut }, loc: ?*const Loc = null, snap: []const u8 };
const GLoc = union(enum) { local: [2]usize, stack: usize };
const Global = struct { snap: TV, locs: std.ArrayList(GLoc) = .empty };
/// A registered effect: its JSON, plus what later steps of the same instruction read back.
const Eff = struct { json: []const u8, loc: ?*const Loc = null, idx: ?u64 = null };

const TYPE_DEPTH_MAX: u64 = 256;
const MAX_TYPE_INSTANTIATION_NODES: u64 = 128;

pub const Tracer = struct {
    arena: Allocator,
    /// Event lines, each ending in '\n'.
    out: std.ArrayList(u8) = .empty,
    count: usize = 0,
    pc: ?u16 = null,
    ins: ff.Instr = .{ .op = .Nop },
    frames: std.ArrayList(FrameInfo) = .empty,
    ts: std.ArrayList(StackType) = .empty,
    globals: std.AutoArrayHashMapUnmanaged(usize, Global) = .empty,
    effects: std.ArrayList(Eff) = .empty,
    /// Layout limits (`TypeSize::from_vm_config_for_value_depth`).
    max_depth: u64,
    max_nodes: u64,
    /// exec-history-vm: the v3 tracer (`tracing2`) keeps one state per global (`GlobalValue`:
    /// a value, the first local it was stored in, or a stack offset) and never drops frame or
    /// local roots. Here: `locs` holds at most one entry.
    v3_globals: bool = false,

    pub fn init(arena: Allocator, cfg: interp.ExecConfig) Tracer {
        return .{ .arena = arena, .max_depth = cfg.max_value_depth orelse 128, .max_nodes = cfg.max_type_nodes, .v3_globals = cfg.rules.execution_version < 4 };
    }

    const E = Allocator.Error;

    // ---- output ---------------------------------------------------------------------------

    fn push(t: *Tracer, json: []const u8) E!void {
        t.count += 1;
        try t.out.appendSlice(t.arena, json);
        try t.out.append(t.arena, '\n');
    }

    fn effectNow(t: *Tracer, eff_json: []const u8) E!void {
        var b: std.ArrayList(u8) = .empty;
        try b.appendSlice(t.arena, "{\"Effect\":");
        try b.appendSlice(t.arena, eff_json);
        try b.append(t.arena, '}');
        try t.push(b.items);
    }

    fn reportError(t: *Tracer, msg: []const u8) E!void {
        const j = try std.fmt.allocPrint(t.arena, "{{\"ExecutionError\":\"!! TRACING ERROR !! Err: {s}. Events below this may be incorrect.\"}}", .{msg});
        try t.effectNow(j);
    }

    fn execError(t: *Tracer, msg: []const u8) E![]const u8 {
        return std.fmt.allocPrint(t.arena, "{{\"ExecutionError\":\"{s}\"}}", .{msg});
    }

    fn instruction(t: *Tracer, ty_params: []const u8, gas_left: u64, pc: u16) E!void {
        const j = try std.fmt.allocPrint(t.arena, "{{\"Instruction\":{{\"type_parameters\":{s},\"pc\":{d},\"gas_left\":{d},\"instruction\":\"{s}\"}}}}", .{ ty_params, pc, gas_left, opName(t.ins.op) });
        try t.push(j);
        for (t.effects.items) |e| try t.effectNow(e.json);
        t.effects.clearRetainingCapacity();
    }

    fn register(t: *Tracer, json: []const u8) E!void {
        try t.effects.append(t.arena, .{ .json = json });
    }

    // ---- frames ----------------------------------------------------------------------------

    fn cur(t: *Tracer) ?*FrameInfo {
        if (t.frames.items.len == 0) return null;
        return &t.frames.items[t.frames.items.len - 1];
    }
    fn curId(t: *Tracer) ?usize {
        return (t.cur() orelse return null).id;
    }
    fn frameById(t: *Tracer, id: usize) ?*FrameInfo {
        for (t.frames.items) |*f| if (f.id == id) return f;
        return null;
    }
    /// `trace_index_to_frame_index`: position of the last active frame opened at or before `id`.
    fn frameIndex(t: *Tracer, id: usize) ?usize {
        var n: usize = 0;
        for (t.frames.items) |f| {
            if (f.id > id) break;
            n += 1;
        }
        return if (n == 0) null else n - 1;
    }

    fn newLoc(t: *Tracer, l: Loc) E!*const Loc {
        const p = try t.arena.create(Loc);
        p.* = l;
        return p;
    }

    // ---- globals ---------------------------------------------------------------------------

    fn removeFrameGlobals(t: *Tracer, fid: usize) void {
        if (t.v3_globals) return;
        for (t.globals.values()) |*g| {
            while (g.locs.items.len > 0) {
                const l = g.locs.items[g.locs.items.len - 1];
                if (l == .local and l.local[0] == fid) _ = g.locs.pop() else break;
            }
        }
    }

    fn removeLocalGlobals(t: *Tracer, fid: usize, li: usize) void {
        if (t.v3_globals) return;
        for (t.globals.values()) |*g| {
            var i: usize = 0;
            while (i < g.locs.items.len) {
                const l = g.locs.items[i];
                if (l == .local and l.local[0] == fid and l.local[1] == li) _ = g.locs.orderedRemove(i) else i += 1;
            }
        }
    }

    fn recordGlobalStore(t: *Tracer, fid: usize, li: usize, gid: usize) E!?void {
        const g = t.globals.getPtr(gid) orelse return null;
        if (t.v3_globals) {
            // v3: a global already rooted in a local stays there
            if (g.locs.items.len > 0 and g.locs.items[0] == .local) return {};
            g.locs.clearRetainingCapacity();
            try g.locs.append(t.arena, .{ .local = .{ fid, li } });
            return {};
        }
        if (g.locs.items.len > 0) {
            const l = g.locs.items[g.locs.items.len - 1];
            if (l == .local and l.local[0] == fid and l.local[1] == li) return {};
        }
        try g.locs.append(t.arena, .{ .local = .{ fid, li } });
        return {};
    }

    fn storeGlobal(t: *Tracer, s: *Session, fid: usize, stack_idx: usize, li: usize) E!?void {
        if (stack_idx >= s.sp) return null;
        if (t.ts.items.len == 0 or t.ts.items.len - 1 < stack_idx) return null;
        const st = t.ts.items[t.ts.items.len - 1 - stack_idx];
        if (st.ref) |r| if (r.loc.* == .global) return t.recordGlobalStore(fid, li, r.loc.global);
        return {};
    }

    /// `record_global_push`: a global held by local `li` of the current frame moves to the stack.
    fn recordGlobalPush(t: *Tracer, s: *Session, loc: *const Loc, li: usize) E!?void {
        if (loc.* != .global) return {};
        const gid = loc.global;
        const fid = t.curId() orelse return null;
        const g = t.globals.getPtr(gid) orelse return null;
        if (t.v3_globals) {
            // v3: an alias of a local further up the stack stays; any other state than a local
            // of this frame fails the tracer (whatever the local index)
            if (g.locs.items.len > 0 and g.locs.items[0] == .local and g.locs.items[0].local[0] != fid) return {};
            if (g.locs.items.len == 0 or g.locs.items[0] != .local) return null;
            g.locs.items[0] = .{ .stack = s.sp -% 1 };
            const v = (try t.resolveStack(s, 0)) orelse return null;
            const g2 = t.globals.getPtr(gid) orelse return null;
            g2.snap = v;
            g2.locs.clearRetainingCapacity();
            return {};
        }
        var pos: ?usize = null;
        var i = g.locs.items.len;
        while (i > 0) {
            i -= 1;
            const l = g.locs.items[i];
            if (l == .local and l.local[0] == fid and l.local[1] == li) {
                pos = i;
                break;
            }
        }
        const p = pos orelse return {};
        g.locs.items[p] = .{ .stack = s.sp -% 1 };
        const v = (try t.resolveStack(s, 0)) orelse return null;
        const g2 = t.globals.getPtr(gid) orelse return null;
        if (p >= g2.locs.items.len or g2.locs.items[p] != .stack) return null;
        g2.snap = v;
        _ = g2.locs.orderedRemove(p);
        return {};
    }

    fn gLoc(t: *Tracer, l: GLoc) E!*const Loc {
        return switch (l) {
            .local => |x| t.newLoc(.{ .local = x }),
            .stack => |x| t.newLoc(.{ .stack = x }),
        };
    }

    // ---- resolution ------------------------------------------------------------------------

    fn traceLoc(l: *const Loc) ?*const Loc {
        return switch (l.*) {
            .stack => null,
            .indexed => |x| if (traceLoc(x.base) == null) null else l,
            else => l,
        };
    }

    fn resolveStack(t: *Tracer, s: *Session, stack_idx: usize) E!?TV {
        if (stack_idx >= s.sp) return null;
        if (t.ts.items.len == 0 or t.ts.items.len - 1 < stack_idx) return null;
        const l = try t.newLoc(.{ .stack = t.ts.items.len - 1 - stack_idx });
        return t.resolveLocation(s, l);
    }

    fn resolveLocal(t: *Tracer, s: *Session, li: usize) E!?TV {
        const fid = t.curId() orelse return null;
        return t.resolveLocation(s, try t.newLoc(.{ .local = .{ fid, li } }));
    }

    fn makeTV(t: *Tracer, s: *Session, loc: *const Loc, ref: ?bool) E!?TV {
        const snap = (try t.rootSnapshot(s, loc)) orelse return null;
        const r = ref orelse return .{ .kind = .val, .snap = snap };
        const tl = traceLoc(loc) orelse return null;
        return .{ .kind = if (r) .mut else .imm, .loc = tl, .snap = snap };
    }

    fn resolveLocation(t: *Tracer, s: *Session, loc: *const Loc) E!?TV {
        switch (loc.*) {
            .stack => |i| {
                if (i >= t.ts.items.len) return null;
                const ty = t.ts.items[i];
                const target = if (ty.ref) |r| r.loc else loc;
                return t.makeTV(s, target, if (ty.ref) |r| r.mut else null);
            },
            .local => |x| {
                const f = t.frameById(x[0]) orelse return null;
                if (x[1] >= f.locals.len) return null;
                const lt = f.locals[x[1]];
                return switch (lt.kind) {
                    .value => t.makeTV(s, loc, null),
                    .empty => null,
                    .filled => |r| t.makeTV(s, r.loc, r.mut),
                };
            },
            .indexed => |x| return t.resolveLocation(s, x.base),
            .global => |id| {
                const g = t.globals.getPtr(id) orelse return null;
                if (g.locs.items.len == 0) return g.snap;
                return t.resolveLocation(s, try t.gLoc(g.locs.items[g.locs.items.len - 1]));
            },
        }
    }

    fn rootSnapshot(t: *Tracer, s: *Session, loc: *const Loc) E!?[]const u8 {
        switch (loc.*) {
            .local => |x| {
                const f = t.frameById(x[0]) orelse return null;
                if (x[1] >= f.locals.len) return null;
                const lt = f.locals[x[1]];
                const ci = t.frameIndex(x[0]) orelse return null;
                const direct = switch (lt.kind) {
                    .value => true,
                    .filled => |r| r.loc.* == .global,
                    .empty => return null,
                };
                if (!direct) return t.rootSnapshot(s, lt.kind.filled.loc);
                const n = s.frames.items.len;
                if (n == 0) return null;
                const mf = &s.frames.items[@min(ci, n - 1)];
                if (x[1] >= mf.locals.len) return null;
                const v = mf.locals[x[1]];
                if (v.tag == .invalid) return null;
                return t.render(v, lt.layout orelse return null);
            },
            .stack => |i| {
                if (i >= t.ts.items.len) return null;
                const ty = t.ts.items[i];
                if (ty.ref) |r| if (r.loc.* != .global) return t.rootSnapshot(s, r.loc);
                if (i >= s.sp) return null;
                return t.render(s.stack[i], ty.layout);
            },
            .indexed => |x| return t.rootSnapshot(s, x.base),
            .global => |id| {
                const g = t.globals.getPtr(id) orelse return null;
                if (g.locs.items.len == 0) return g.snap.snap;
                return t.rootSnapshot(s, try t.gLoc(g.locs.items[g.locs.items.len - 1]));
            },
        }
    }

    // ---- JSON rendering ----------------------------------------------------------------------

    fn render(t: *Tracer, v: Value, layout: *const Type) E!?[]const u8 {
        var b: std.ArrayList(u8) = .empty;
        if (!try t.renderInto(&b, v, layout)) return null;
        return b.items;
    }

    /// `Value::as_annotated_move_value` followed by `SerializableMoveValue` serialization.
    fn renderInto(t: *Tracer, b: *std.ArrayList(u8), v: Value, layout: *const Type) E!bool {
        const a = t.arena;
        if (v.tag == .ref_slot) return t.renderInto(b, v.slot().*, layout);
        if (v.tag == .ref_elem) {
            // An indexed reference into a primitive vector yields the whole vector, and only
            // for a vector layout (`Reference::as_annotated_move_value`).
            if (layout.* != .vector) return false;
            return t.renderInto(b, Value.container(v.cont()), layout);
        }
        switch (layout.*) {
            .u8, .u16, .u32, .u64, .bool => {
                const want: value.Tag = switch (layout.*) {
                    .u8 => .u8,
                    .u16 => .u16,
                    .u32 => .u32,
                    .u64 => .u64,
                    else => .bool,
                };
                if (v.tag != want) return false;
                try primJson(a, b, want, v);
            },
            .u128 => {
                if (v.tag != .u128) return false;
                try primJson(a, b, .u128, v);
            },
            .u256 => {
                if (v.tag != .u256) return false;
                try primJson(a, b, .u256, v);
            },
            .address => {
                if (v.tag != .address) return false;
                try primJson(a, b, .address, v);
            },
            .signer => {
                if (v.tag != .container) return false;
                const c = v.cont();
                if (c.kind != .struct_ or c.len != 1) return false;
                const x = c.values()[0];
                if (x.tag != .address) return false;
                try primJson(a, b, .address, x);
            },
            .vector => |inner| {
                if (v.tag != .container) return false;
                const c = v.cont();
                if (!c.kind.isVector()) return false;
                if (c.kind.isPrimVec()) {
                    const et = c.kind.elemTag();
                    const ok = switch (inner.*) {
                        .u8 => et == .u8,
                        .u16 => et == .u16,
                        .u32 => et == .u32,
                        .u64 => et == .u64,
                        .u128 => et == .u128,
                        .u256 => et == .u256,
                        .bool => et == .bool,
                        .address => et == .address,
                        else => false,
                    };
                    if (!ok) return false;
                    try b.appendSlice(a, "{\"type\":\"Vector\",\"value\":[");
                    for (0..c.len) |i| {
                        if (i != 0) try b.append(a, ',');
                        try elemJson(a, b, c, i);
                    }
                    try b.appendSlice(a, "]}");
                } else {
                    try b.appendSlice(a, "{\"type\":\"Vector\",\"value\":[");
                    for (c.values(), 0..) |e, i| {
                        if (i != 0) try b.append(a, ',');
                        if (!try t.renderInto(b, e, inner)) return false;
                    }
                    try b.appendSlice(a, "]}");
                }
            },
            .datatype => |d| {
                if (v.tag != .container) return false;
                const c = v.cont();
                const m = d.dt.module;
                if (d.dt.is_enum) {
                    if (c.kind != .variant) return false;
                    if (c.tag >= d.dt.variants.len) return false;
                    const vd = d.dt.variants[c.tag];
                    try b.appendSlice(a, "{\"type\":\"Variant\",\"value\":{\"type_\":");
                    try structTagJson(a, b, d.dt, d.args);
                    try b.print(a, ",\"variant_name\":\"{s}\",\"tag\":{d},\"fields\":[", .{ m.cm.identifiers[vd.variant_name], c.tag });
                    const n = @min(c.len, vd.fields.len);
                    for (vd.fields[0..n], c.values()[0..n], 0..) |fd, x, i| {
                        if (i != 0) try b.append(a, ',');
                        try b.print(a, "[\"{s}\",", .{m.cm.identifiers[fd.name]});
                        const ft = types.instantiate(a, m, fd.signature, d.args) catch return false;
                        if (!try t.renderInto(b, x, ft)) return false;
                        try b.append(a, ']');
                    }
                    try b.appendSlice(a, "]}}");
                } else {
                    if (c.kind != .struct_) return false;
                    try b.appendSlice(a, "{\"type\":\"Struct\",\"value\":{\"type_\":");
                    try structTagJson(a, b, d.dt, d.args);
                    try b.appendSlice(a, ",\"fields\":[");
                    const n = @min(c.len, d.dt.fields.len);
                    for (d.dt.fields[0..n], c.values()[0..n], 0..) |fd, x, i| {
                        if (i != 0) try b.append(a, ',');
                        try b.print(a, "[\"{s}\",", .{m.cm.identifiers[fd.name]});
                        const ft = types.instantiate(a, m, fd.signature, d.args) catch return false;
                        if (!try t.renderInto(b, x, ft)) return false;
                        try b.append(a, ']');
                    }
                    try b.appendSlice(a, "]}}");
                }
            },
            .ref, .mut_ref, .param => return false,
        }
        return true;
    }

    fn tvJson(t: *Tracer, b: *std.ArrayList(u8), v: TV) E!void {
        const a = t.arena;
        switch (v.kind) {
            .val => {
                try b.appendSlice(a, "{\"RuntimeValue\":{\"value\":");
                try b.appendSlice(a, v.snap);
                try b.appendSlice(a, "}}");
            },
            .imm, .mut => {
                try b.appendSlice(a, if (v.kind == .imm) "{\"ImmRef\":{\"location\":" else "{\"MutRef\":{\"location\":");
                try locJson(a, b, v.loc.?);
                try b.appendSlice(a, ",\"snapshot\":");
                try b.appendSlice(a, v.snap);
                try b.appendSlice(a, "}}");
            },
        }
    }

    fn tvEffect(t: *Tracer, comptime kind: []const u8, v: TV) E![]const u8 {
        var b: std.ArrayList(u8) = .empty;
        try b.appendSlice(t.arena, "{\"" ++ kind ++ "\":");
        try t.tvJson(&b, v);
        try b.append(t.arena, '}');
        return b.items;
    }

    fn popEff(t: *Tracer, v: TV) E!Eff {
        return .{ .json = try t.tvEffect("Pop", v), .loc = v.loc, .idx = if (v.kind == .val and std.mem.startsWith(u8, v.snap, "{\"type\":\"U64\",\"value\":")) std.fmt.parseInt(u64, v.snap[22 .. v.snap.len - 1], 10) catch null else null };
    }

    fn readEff(t: *Tracer, loc: *const Loc, v: TV, moved: bool) E![]const u8 {
        var b: std.ArrayList(u8) = .empty;
        try b.appendSlice(t.arena, "{\"Read\":{\"location\":");
        try locJson(t.arena, &b, loc);
        try b.appendSlice(t.arena, ",\"root_value_read\":");
        try t.tvJson(&b, v);
        try b.print(t.arena, ",\"moved\":{s}}}}}", .{if (moved) "true" else "false"});
        return b.items;
    }

    fn writeEff(t: *Tracer, loc: *const Loc, v: TV) E![]const u8 {
        var b: std.ArrayList(u8) = .empty;
        try b.appendSlice(t.arena, "{\"Write\":{\"location\":");
        try locJson(t.arena, &b, loc);
        try b.appendSlice(t.arena, ",\"root_value_after_write\":");
        try t.tvJson(&b, v);
        try b.appendSlice(t.arena, "}}");
        return b.items;
    }

    // ---- layouts and type info ---------------------------------------------------------------

    /// `type_to_type_tag` succeeds (TypeSize::for_type_traversal).
    fn tagOk(ty: *const Type) bool {
        var ts = TS{ .maxd = TYPE_DEPTH_MAX, .maxn = MAX_TYPE_INSTANTIATION_NODES };
        return tagWalk(ty, &ts);
    }

    /// `type_to_fully_annotated_layout` succeeds.
    fn layoutOk(t: *Tracer, ty: *const Type) bool {
        var ts = TS{ .maxd = t.max_depth, .maxn = t.max_nodes };
        return t.layoutWalk(ty, &ts);
    }

    fn layoutWalk(t: *Tracer, ty: *const Type, ts: *TS) bool {
        ts.depth +|= 1;
        ts.nodes +|= 1;
        if (!ts.ok()) return false;
        switch (ty.*) {
            .vector => |e| if (!t.layoutWalk(e, ts)) return false,
            .datatype => |d| {
                if (!ts.ok()) return false;
                var tts = TS{ .maxd = TYPE_DEPTH_MAX, .maxn = MAX_TYPE_INSTANTIATION_NODES };
                for (d.args) |x| if (!tagWalk(x, &tts)) return false;
                if (!tts.ok()) return false;
                const m = d.dt.module;
                if (d.dt.is_enum) {
                    for (d.dt.variants) |vd| {
                        ts.nodes +|= 1;
                        if (ts.nodes > ts.maxn) return false;
                        for (vd.fields) |fd| {
                            const ft = substOk(t.arena, m, fd.signature, d.args) orelse return false;
                            if (!t.layoutWalk(ft, ts)) return false;
                        }
                    }
                } else for (d.dt.fields) |fd| {
                    const ft = substOk(t.arena, m, fd.signature, d.args) orelse return false;
                    if (!t.layoutWalk(ft, ts)) return false;
                }
                if (!ts.ok()) return false;
            },
            .ref, .mut_ref, .param => return false,
            else => {},
        }
        if (!ts.ok()) return false;
        ts.depth -= 1;
        return true;
    }

    fn layoutOf(t: *Tracer, ty: *const Type) ?*const Type {
        return if (t.layoutOk(ty)) ty else null;
    }

    /// `subst_and_layout_type` of `FunctionTypeInfo::new`.
    fn tagInfo(t: *Tracer, m: *loader.Module, tok: ff.Token, ty_args: []const *const Type) ?TagInfo {
        const full = substOk(t.arena, m, tok, ty_args) orelse return null;
        var ty = full;
        var ref: ?bool = null;
        switch (full.*) {
            .ref => |x| {
                ty = x;
                ref = false;
            },
            .mut_ref => |x| {
                ty = x;
                ref = true;
            },
            .param => return null,
            else => {},
        }
        if (!tagOk(ty)) return null;
        return .{ .ty = ty, .layout = t.layoutOf(ty), .ref = ref };
    }

    const FnInfo = struct { ty_args: []const *const Type, locals: []TagInfo, returns: []TagInfo };

    fn fnInfo(t: *Tracer, func: *const Function, ty_args: []const *const Type) E!?FnInfo {
        const m = func.module;
        const locals = try t.arena.alloc(TagInfo, func.params.len + func.locals.len);
        for (func.params, 0..) |tok, i| locals[i] = t.tagInfo(m, tok, ty_args) orelse return null;
        for (func.locals, 0..) |tok, i| locals[func.params.len + i] = t.tagInfo(m, tok, ty_args) orelse return null;
        const rets = try t.arena.alloc(TagInfo, func.returns.len);
        for (func.returns, rets) |tok, *o| o.* = t.tagInfo(m, tok, ty_args) orelse return null;
        for (ty_args) |a| {
            if (a.* == .param) return null;
            if (!tagOk(a)) return null;
        }
        return .{ .ty_args = ty_args, .locals = locals, .returns = rets };
    }

    fn tagListJson(t: *Tracer, tys: []const *const Type) E![]const u8 {
        var b: std.ArrayList(u8) = .empty;
        try b.append(t.arena, '[');
        for (tys, 0..) |x, i| {
            if (i != 0) try b.append(t.arena, ',');
            try tagJson(t.arena, &b, x);
        }
        try b.append(t.arena, ']');
        return b.items;
    }

    fn tagRefsJson(t: *Tracer, b: *std.ArrayList(u8), infos: []const TagInfo) E!void {
        try b.append(t.arena, '[');
        for (infos, 0..) |x, i| {
            if (i != 0) try b.append(t.arena, ',');
            try b.appendSlice(t.arena, "{\"type_\":");
            try tagJson(t.arena, b, x.ty);
            try b.appendSlice(t.arena, if (x.ref) |r| (if (r) ",\"ref_type\":\"Mut\"}" else ",\"ref_type\":\"Imm\"}") else ",\"ref_type\":null}");
        }
        try b.append(t.arena, ']');
    }

    fn openFrame(t: *Tracer, func: *const Function, info: FnInfo, params: []const TV, gas_left: u64) E!void {
        const a = t.arena;
        const m = func.module;
        var b: std.ArrayList(u8) = .empty;
        try b.print(a, "{{\"OpenFrame\":{{\"frame\":{{\"frame_id\":{d},\"function_name\":\"{s}\",\"module\":{{\"address\":\"{x}\",\"name\":\"{s}\"}},\"version_id\":\"{x}\",\"binary_member_index\":{d},\"type_instantiation\":", .{ t.curId().?, func.name, m.cm.selfAddress(), m.name, &m.pkg.version_id, func.def_idx });
        try b.appendSlice(a, try t.tagListJson(info.ty_args));
        try b.appendSlice(a, ",\"parameters\":[");
        for (params, 0..) |p, i| {
            if (i != 0) try b.append(a, ',');
            try t.tvJson(&b, p);
        }
        try b.appendSlice(a, "],\"return_types\":");
        try t.tagRefsJson(&b, info.returns);
        try b.appendSlice(a, ",\"locals_types\":");
        try t.tagRefsJson(&b, info.locals);
        try b.print(a, ",\"is_native\":{s}}},\"gas_left\":{d}}}}}", .{ if (func.is_native) "true" else "false", gas_left });
        try t.push(b.items);
    }

    fn closeFrame(t: *Tracer, fid: usize, rets: []const TV, gas_left: u64) E!void {
        const a = t.arena;
        var b: std.ArrayList(u8) = .empty;
        try b.print(a, "{{\"CloseFrame\":{{\"frame_id\":{d},\"return_\":[", .{fid});
        for (rets, 0..) |r, i| {
            if (i != 0) try b.append(a, ',');
            try t.tvJson(&b, r);
        }
        try b.print(a, "],\"gas_left\":{d}}}}}", .{gas_left});
        try t.push(b.items);
    }

    /// `emit_data_load`: a DataLoad effect now, and the global's trace value.
    fn dataLoad(t: *Tracer, snap: []const u8, mut: bool) E!struct { usize, TV } {
        const id = t.count;
        const loc = try t.newLoc(.{ .global = id });
        var b: std.ArrayList(u8) = .empty;
        try b.print(t.arena, "{{\"DataLoad\":{{\"ref_type\":\"{s}\",\"location\":", .{if (mut) "Mut" else "Imm"});
        try locJson(t.arena, &b, loc);
        try b.appendSlice(t.arena, ",\"snapshot\":");
        try b.appendSlice(t.arena, snap);
        try b.appendSlice(t.arena, "}}");
        try t.effectNow(b.items);
        return .{ id, .{ .kind = if (mut) .mut else .imm, .loc = loc, .snap = snap } };
    }

    // ---- entry points -------------------------------------------------------------------------

    pub fn enterInitialFrame(t: *Tracer, s: *Session, func: *const Function, ty_args: []const *const Type, args: []const Value) E!void {
        if (!try t.enterInitialFrameImpl(s, func, ty_args, args)) try t.reportError("Unknown");
    }

    fn enterInitialFrameImpl(t: *Tracer, s: *Session, func: *const Function, ty_args: []const *const Type, args: []const Value) E!bool {
        const info = (try t.fnInfo(func, ty_args)) orelse return false;
        const n = @min(args.len, info.locals.len);
        const params = try t.arena.alloc(TV, n);
        const gids = try t.arena.alloc(?usize, n);
        for (args[0..n], info.locals[0..n], params, gids) |v, li, *p, *g| {
            const layout = li.layout orelse return false;
            const snap = (try t.render(v, layout)) orelse return false;
            if (li.ref) |mut| {
                const r = try t.dataLoad(snap, mut);
                try t.globals.put(t.arena, r[0], .{ .snap = r[1] });
                p.* = r[1];
                g.* = r[0];
            } else {
                p.* = .{ .kind = .val, .snap = snap };
                g.* = null;
            }
        }
        const fid = t.count;
        const locals = try t.arena.alloc(LocalType, info.locals.len);
        for (info.locals, locals, 0..) |li, *lt, i| {
            lt.* = .{ .layout = li.layout, .kind = .value };
            if (li.ref) |mut| {
                if (i < n and gids[i] != null) {
                    if ((try t.recordGlobalStore(fid, i, gids[i].?)) == null) return false;
                    lt.kind = .{ .filled = .{ .mut = mut, .loc = try t.newLoc(.{ .global = gids[i].? }) } };
                } else lt.kind = .{ .empty = mut };
            }
        }
        try t.frames.append(t.arena, .{ .id = fid, .is_native = func.is_native, .locals = locals, .returns = info.returns });
        try t.openFrame(func, info, params, s.meter.remainingGas());
        return true;
    }

    pub fn enterFrame(t: *Tracer, s: *Session, func: *const Function, ty_args: []const *const Type) E!void {
        if (!try t.enterFrameImpl(s, func, ty_args)) try t.reportError("Unknown");
    }

    fn enterFrameImpl(t: *Tracer, s: *Session, func: *const Function, ty_args: []const *const Type) E!bool {
        const fid = t.count;
        const n = func.params.len;
        if (t.ts.items.len < n) return false;
        const arg_start = t.ts.items.len - n;
        const params = try t.arena.alloc(TV, n);
        var ok = true;
        for (params, 0..) |*p, local_idx| {
            const stack_idx = n - 1 - local_idx;
            const v = (try t.resolveStack(s, stack_idx)) orelse {
                ok = false;
                break;
            };
            if ((try t.storeGlobal(s, fid, stack_idx, local_idx)) == null) {
                ok = false;
                break;
            }
            p.* = v;
        }
        const arg_types = try t.arena.dupe(StackType, t.ts.items[arg_start..]);
        t.ts.shrinkRetainingCapacity(arg_start);
        if (!ok) return false;
        const info = (try t.fnInfo(func, ty_args)) orelse return false;
        const locals = try t.arena.alloc(LocalType, info.locals.len);
        for (info.locals, locals, 0..) |li, *lt, i| {
            if (i < arg_types.len) {
                const at = arg_types[i];
                lt.* = .{ .layout = at.layout, .kind = if (at.ref) |r| .{ .filled = r } else .value };
            } else {
                lt.* = .{ .layout = li.layout, .kind = if (li.ref) |m| .{ .empty = m } else .value };
            }
        }
        try t.frames.append(t.arena, .{ .id = fid, .is_native = func.is_native, .locals = locals, .returns = info.returns });
        try t.openFrame(func, info, params, s.meter.remainingGas());
        return true;
    }

    /// `exit_frame`: a returning frame (Ret, or a native call that finished). `err` is the
    /// failing status of a native call.
    pub fn exitFrame(t: *Tracer, s: *Session, func: *const Function, err: ?StatusCode) E!void {
        if (err) |e| {
            try t.effectNow(try t.execError(@tagName(e)));
            return;
        }
        if (!try t.exitFrameImpl(s, func)) try t.reportError("Unknown");
    }

    fn exitFrameImpl(t: *Tracer, s: *Session, func: *const Function) E!bool {
        if (func.is_native) {
            if (!try t.nativeReturn(s)) try t.reportError("Native function return failed -- this should not happen.");
        }
        const n = func.returns.len;
        const rets = try t.arena.alloc(TV, n);
        for (rets, 0..) |*r, k| r.* = (try t.resolveStack(s, n - 1 - k)) orelse return false;
        if (func.is_native) for (rets) |r| try t.effectNow(try t.tvEffect("Push", r));
        const fid = t.curId() orelse return false;
        try t.closeFrame(fid, rets, s.meter.remainingGas());
        t.removeFrameGlobals(fid);
        if (t.frames.pop() == null) try t.reportError("Unbalanced frame close");
        return true;
    }

    /// `handle_native_return`: references a native returns become globals.
    fn nativeReturn(t: *Tracer, s: *Session) E!bool {
        const f = t.cur() orelse return false;
        const rets = f.returns;
        for (rets, 0..) |r, i| {
            const layout = r.layout orelse return false;
            if (i + 1 > s.sp) return false;
            const v = s.stack[s.sp - i - 1];
            var ref: ?Ref = null;
            if (try t.render(v, layout)) |snap| if (r.ref) |mut| {
                const d = try t.dataLoad(snap, mut);
                try t.globals.put(t.arena, d[0], .{ .snap = d[1] });
                ref = .{ .mut = mut, .loc = d[1].loc.? };
            };
            try t.ts.append(t.arena, .{ .layout = layout, .ref = ref });
        }
        return true;
    }

    // ---- instructions ------------------------------------------------------------------------

    fn popn(t: *Tracer, s: *Session, n: usize) E!?void {
        for (0..n) |i| {
            const v = (try t.resolveStack(s, i)) orelse return null;
            try t.effects.append(t.arena, try t.popEff(v));
        }
        return {};
    }

    fn insertLocal(t: *Tracer, li: usize, st: StackType) ?void {
        const f = t.cur() orelse return null;
        if (li >= f.locals.len) return null;
        f.locals[li] = .{ .layout = st.layout, .kind = if (st.ref) |r| .{ .filled = r } else .value };
    }

    pub fn startInstruction(t: *Tracer, s: *Session, ins: ff.Instr, pc: u16) E!void {
        t.pc = pc;
        t.ins = ins;
        if ((try t.startImpl(s, ins)) == null) try t.reportError("Unknown");
    }

    fn startImpl(t: *Tracer, s: *Session, ins: ff.Instr) E!?void {
        const f = &s.frames.items[s.frames.items.len - 1];
        const m = f.func.module;
        switch (ins.op) {
            .Nop, .Branch, .Ret, .LdU8, .LdU16, .LdU32, .LdU64, .LdU128, .LdU256, .LdFalse, .LdTrue, .LdConst => t.effects.clearRetainingCapacity(),
            .MutBorrowField, .ImmBorrowField, .MutBorrowFieldGeneric, .ImmBorrowFieldGeneric, .FreezeRef, .Not, .Abort, .Unpack, .UnpackGeneric, .CastU8, .CastU16, .CastU32, .CastU64, .CastU128, .CastU256, .Pop, .BrTrue, .BrFalse, .VecUnpack, .VecLen, .VecPopBack, .VariantSwitch, .UnpackVariantImmRef, .UnpackVariantMutRef, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef, .UnpackVariant, .UnpackVariantGeneric => return t.popn(s, 1),
            .Add, .Sub, .Mul, .Mod, .Div, .BitOr, .BitAnd, .Xor, .Shl, .Shr, .Lt, .Gt, .Le, .Ge, .Eq, .Neq, .Or, .And, .WriteRef, .VecImmBorrow, .VecMutBorrow, .VecPushBack => return t.popn(s, 2),
            .VecSwap => return t.popn(s, 3),
            .VecPack => return t.popn(s, @intCast(ins.imm)),
            .MoveLoc, .CopyLoc => {
                const v = (try t.resolveLocal(s, ins.idx)) orelse return null;
                const loc = try t.newLoc(.{ .local = .{ t.curId() orelse return null, ins.idx } });
                try t.register(try t.readEff(loc, v, ins.op == .MoveLoc));
            },
            .StLoc => {
                const v = (try t.resolveStack(s, 0)) orelse return null;
                try t.effects.append(t.arena, try t.popEff(v));
                if (t.ts.items.len == 0) return null;
                const ty = t.ts.items[t.ts.items.len - 1];
                const fid = t.curId() orelse return null;
                t.removeLocalGlobals(fid, ins.idx);
                (try t.storeGlobal(s, fid, 0, ins.idx)) orelse return null;
                t.insertLocal(ins.idx, ty) orelse return null;
            },
            .ImmBorrowLoc, .MutBorrowLoc => {
                const v = (try t.resolveLocal(s, ins.idx)) orelse return null;
                const loc = try t.newLoc(.{ .local = .{ t.curId() orelse return null, ins.idx } });
                try t.register(try t.readEff(loc, v, false));
            },
            .Call, .CallGeneric => {},
            .Pack => return t.popn(s, m.structs[ins.idx].fields.len),
            .PackGeneric => return t.popn(s, m.structs[m.cm.struct_def_instantiations[ins.idx].def].fields.len),
            .PackVariant => {
                const vh = m.cm.variant_handles[ins.idx];
                return t.popn(s, m.enums[vh.enum_def].variants[vh.variant].fields.len);
            },
            .PackVariantGeneric => {
                const vh = m.cm.variant_instantiation_handles[ins.idx];
                return t.popn(s, m.enums[m.cm.enum_def_instantiations[vh.enum_def].def].variants[vh.variant].fields.len);
            },
            .ReadRef => {
                const rv = (try t.resolveStack(s, 0)) orelse return null;
                const loc = rv.loc orelse return null;
                try t.effects.append(t.arena, try t.popEff(rv));
                const v = (try t.resolveLocation(s, loc)) orelse return null;
                try t.register(try t.readEff(loc, v, false));
            },
            else => {},
        }
        return {};
    }

    /// `end_instruction`: `err` is the status of a failed operation.
    pub fn endInstruction(t: *Tracer, s: *Session, err: ?StatusCode) E!void {
        const gas = s.meter.remainingGas();
        const pc = t.pc orelse {
            try t.reportError("PC always set by this point by `open_instruction`");
            return;
        };
        const r = try t.endImpl(s, gas, pc);
        if (r == null) {
            const msg = if (err) |e| @tagName(e) else "VM tracer failed to close instruction but interpreter was OK -- this is most likely a bug in the tracer";
            try t.register(try t.execError(msg));
            try t.instruction("[]", gas, pc);
        } else if (err) |e| {
            try t.effectNow(try t.execError(@tagName(e)));
        }
    }

    fn pushTop(t: *Tracer, s: *Session, st: StackType) E!?void {
        try t.ts.append(t.arena, st);
        const v = (try t.resolveStack(s, 0)) orelse return null;
        try t.register(try t.tvEffect("Push", v));
        return {};
    }

    fn popTs(t: *Tracer) ?StackType {
        return t.ts.pop();
    }

    fn fieldType(t: *Tracer, d: Type.Inst, fields: []const ff.FieldDefinition, i: usize) ?*const Type {
        if (i >= fields.len) return null;
        return types.instantiate(t.arena, d.dt.module, fields[i].signature, d.args) catch null;
    }

    fn endImpl(t: *Tracer, s: *Session, gas: u64, pc: u16) E!?void {
        const ins = t.ins;
        const f = &s.frames.items[s.frames.items.len - 1];
        const m = f.func.module;
        switch (ins.op) {
            .Pop, .BrTrue, .BrFalse, .Abort, .VariantSwitch => _ = t.popTs() orelse return null,
            .Branch, .Ret, .Call, .CallGeneric, .Nop => {},
            .LdU8, .LdU16, .LdU32, .LdU64, .LdU128, .LdU256, .LdFalse, .LdTrue => {
                const ty: *const Type = switch (ins.op) {
                    .LdU8 => &Type.t_u8,
                    .LdU16 => &Type.t_u16,
                    .LdU32 => &Type.t_u32,
                    .LdU64 => &Type.t_u64,
                    .LdU128 => &Type.t_u128,
                    .LdU256 => &Type.t_u256,
                    else => &Type.t_bool,
                };
                (try t.pushTop(s, .{ .layout = ty })) orelse return null;
            },
            .LdConst => {
                const ct = types.instantiate(t.arena, m, m.cm.constant_pool[ins.idx].type_, &.{}) catch return null;
                const layout = t.layoutOf(ct) orelse return null;
                (try t.pushTop(s, .{ .layout = layout })) orelse return null;
            },
            .MoveLoc, .CopyLoc => {
                const fr = t.cur() orelse return null;
                if (ins.idx >= fr.locals.len) return null;
                const lt = fr.locals[ins.idx];
                const st: StackType = .{
                    .layout = lt.layout orelse return null,
                    .ref = switch (lt.kind) {
                        .value => null,
                        .empty => return null,
                        .filled => |r| r,
                    },
                };
                try t.ts.append(t.arena, st);
                if (ins.op == .MoveLoc) {
                    // invalidate_local
                    const fr2 = t.cur() orelse return null;
                    switch (fr2.locals[ins.idx].kind) {
                        .filled => |r| {
                            fr2.locals[ins.idx].kind = .{ .empty = r.mut };
                            (try t.recordGlobalPush(s, r.loc, ins.idx)) orelse return null;
                        },
                        else => {},
                    }
                }
                const v = (try t.resolveStack(s, 0)) orelse return null;
                try t.register(try t.tvEffect("Push", v));
            },
            .CastU8, .CastU16, .CastU32, .CastU64, .CastU128, .CastU256 => {
                const ty: *const Type = switch (ins.op) {
                    .CastU8 => &Type.t_u8,
                    .CastU16 => &Type.t_u16,
                    .CastU32 => &Type.t_u32,
                    .CastU64 => &Type.t_u64,
                    .CastU128 => &Type.t_u128,
                    else => &Type.t_u256,
                };
                _ = t.popTs() orelse return null;
                (try t.pushTop(s, .{ .layout = ty })) orelse return null;
            },
            .StLoc => {
                const ty = t.popTs() orelse return null;
                t.insertLocal(ins.idx, ty) orelse return null;
                const v = (try t.resolveLocal(s, ins.idx)) orelse return null;
                const loc = try t.newLoc(.{ .local = .{ t.curId() orelse return null, ins.idx } });
                try t.register(try t.writeEff(loc, v));
            },
            .Add, .Sub, .Mul, .Mod, .Div, .BitOr, .BitAnd, .Xor, .Shl, .Shr => {
                _ = t.popTs() orelse return null;
                const a_ty = t.popTs() orelse return null;
                (try t.pushTop(s, a_ty)) orelse return null;
            },
            .Lt, .Gt, .Le, .Ge, .Eq, .Neq, .Or, .And => {
                _ = t.popTs() orelse return null;
                _ = t.popTs() orelse return null;
                (try t.pushTop(s, .{ .layout = &Type.t_bool })) orelse return null;
            },
            .Not => {
                const a_ty = t.popTs() orelse return null;
                (try t.pushTop(s, a_ty)) orelse return null;
            },
            .Pack, .PackGeneric, .PackVariant, .PackVariantGeneric => {
                var ty: *const Type = undefined;
                var n: usize = 0;
                var tparams: []const u8 = "[]";
                switch (ins.op) {
                    .Pack => {
                        const dt = &m.structs[ins.idx];
                        n = dt.fields.len;
                        ty = try mkDatatype(t.arena, dt, &.{});
                    },
                    .PackGeneric => {
                        const sdi = m.cm.struct_def_instantiations[ins.idx];
                        const dt = &m.structs[sdi.def];
                        n = dt.fields.len;
                        const args = instAll(t.arena, m, m.cm.signatures[sdi.type_parameters], f.ty_args) orelse return null;
                        ty = try mkDatatype(t.arena, dt, args);
                    },
                    .PackVariant => {
                        const vh = m.cm.variant_handles[ins.idx];
                        const dt = &m.enums[vh.enum_def];
                        n = dt.variants[vh.variant].fields.len;
                        ty = try mkDatatype(t.arena, dt, &.{});
                    },
                    else => {
                        const vh = m.cm.variant_instantiation_handles[ins.idx];
                        const edi = m.cm.enum_def_instantiations[vh.enum_def];
                        const dt = &m.enums[edi.def];
                        n = dt.variants[vh.variant].fields.len;
                        const args = instAll(t.arena, m, m.cm.signatures[edi.type_parameters], f.ty_args) orelse return null;
                        ty = try mkDatatype(t.arena, dt, args);
                    },
                }
                if (t.ts.items.len < n) return null;
                t.ts.shrinkRetainingCapacity(t.ts.items.len - n);
                const layout = t.layoutOf(ty) orelse return null;
                try t.ts.append(t.arena, .{ .layout = layout });
                if (ins.op == .PackGeneric) {
                    if (!tagOk(ty)) return null;
                    tparams = try t.tagListJson(ty.datatype.args);
                }
                const v = (try t.resolveStack(s, 0)) orelse return null;
                try t.register(try t.tvEffect("Push", v));
                try t.instruction(tparams, gas, pc);
                return {};
            },
            .Unpack, .UnpackGeneric => {
                const ty = t.popTs() orelse return null;
                if (ty.layout.* != .datatype or ty.layout.datatype.dt.is_enum) return null;
                const d = ty.layout.datatype;
                const n = d.dt.fields.len;
                for (0..n) |i| try t.ts.append(t.arena, .{ .layout = t.fieldType(d, d.dt.fields, i) orelse return null });
                var i = n;
                while (i > 0) {
                    i -= 1;
                    const v = (try t.resolveStack(s, i)) orelse return null;
                    try t.register(try t.tvEffect("Push", v));
                }
            },
            .ReadRef => {
                const rt = t.popTs() orelse return null;
                (try t.pushTop(s, .{ .layout = rt.layout })) orelse return null;
            },
            .ImmBorrowLoc, .MutBorrowLoc => {
                const fr = t.cur() orelse return null;
                if (ins.idx >= fr.locals.len) return null;
                const layout = fr.locals[ins.idx].layout orelse return null;
                const loc = try t.newLoc(.{ .local = .{ fr.id, ins.idx } });
                (try t.pushTop(s, .{ .layout = layout, .ref = .{ .mut = ins.op == .MutBorrowLoc, .loc = loc } })) orelse return null;
            },
            .WriteRef => {
                const rt = t.popTs() orelse return null;
                _ = t.popTs() orelse return null;
                const r = rt.ref orelse return null;
                const v = (try t.resolveLocation(s, r.loc)) orelse return null;
                try t.register(try t.writeEff(traceLoc(r.loc) orelse return null, v));
            },
            .FreezeRef => {
                var rt = t.popTs() orelse return null;
                if (rt.ref == null) return null;
                rt.ref.?.mut = false;
                (try t.pushTop(s, rt)) orelse return null;
            },
            .MutBorrowField, .ImmBorrowField, .MutBorrowFieldGeneric, .ImmBorrowFieldGeneric => {
                const vt = t.popTs() orelse return null;
                if (vt.layout.* != .datatype or vt.layout.datatype.dt.is_enum) return null;
                const d = vt.layout.datatype;
                const generic = ins.op == .MutBorrowFieldGeneric or ins.op == .ImmBorrowFieldGeneric;
                const fh = if (generic) m.cm.field_instantiations[ins.idx].handle else ins.idx;
                const off = m.cm.field_handles[fh].field;
                const fl = t.fieldType(d, d.dt.fields, off) orelse return null;
                const base = (vt.ref orelse return null).loc;
                const loc = try t.newLoc(.{ .indexed = .{ .base = base, .i = off } });
                const mut = ins.op == .MutBorrowField or ins.op == .MutBorrowFieldGeneric;
                try t.ts.append(t.arena, .{ .layout = fl, .ref = .{ .mut = mut, .loc = loc } });
                const tparams = if (generic) try t.tagListJson(d.args) else "[]";
                const v = (try t.resolveStack(s, 0)) orelse return null;
                try t.register(try t.tvEffect("Push", v));
                try t.instruction(tparams, gas, pc);
                return {};
            },
            .VecPack => {
                const et = substOk(t.arena, m, m.cm.signatures[ins.idx][0], f.ty_args) orelse return null;
                const el = t.layoutOf(et) orelse return null;
                const vt = try t.arena.create(Type);
                vt.* = .{ .vector = el };
                const n: usize = @intCast(ins.imm);
                if (t.ts.items.len < n) return null;
                t.ts.shrinkRetainingCapacity(t.ts.items.len - n);
                (try t.pushTop(s, .{ .layout = vt })) orelse return null;
            },
            .VecImmBorrow, .VecMutBorrow => {
                _ = t.popTs() orelse return null;
                const rt = t.popTs() orelse return null;
                if (rt.layout.* != .vector) return null;
                if (t.effects.items.len == 0) return null;
                const i = t.effects.items[0].idx orelse return null;
                const base = (rt.ref orelse return null).loc;
                const loc = try t.newLoc(.{ .indexed = .{ .base = base, .i = @intCast(i) } });
                (try t.pushTop(s, .{ .layout = rt.layout.vector, .ref = .{ .mut = ins.op == .VecMutBorrow, .loc = loc } })) orelse return null;
            },
            .VecLen => {
                _ = t.popTs() orelse return null;
                (try t.pushTop(s, .{ .layout = &Type.t_u64 })) orelse return null;
            },
            .VecPushBack => {
                _ = t.popTs() orelse return null;
                _ = t.popTs() orelse return null;
                if (t.effects.items.len < 2) return null;
                const loc = t.effects.items[1].loc orelse return null;
                const v = (try t.resolveLocation(s, loc)) orelse return null;
                try t.register(try t.writeEff(loc, v));
            },
            .VecPopBack => {
                const rt = t.popTs() orelse return null;
                if (rt.layout.* != .vector) return null;
                (try t.pushTop(s, .{ .layout = rt.layout.vector })) orelse return null;
            },
            .VecUnpack => {
                const vt = t.popTs() orelse return null;
                if (vt.layout.* != .vector) return null;
                const n: usize = @intCast(ins.imm);
                for (0..n) |_| try t.ts.append(t.arena, .{ .layout = vt.layout.vector });
                var i = n;
                while (i > 0) {
                    i -= 1;
                    const v = (try t.resolveStack(s, i)) orelse return null;
                    try t.register(try t.tvEffect("Push", v));
                }
            },
            .VecSwap => {
                _ = t.popTs() orelse return null;
                _ = t.popTs() orelse return null;
                const vr = t.popTs() orelse return null;
                const r = vr.ref orelse return null;
                const v = (try t.resolveLocation(s, r.loc)) orelse return null;
                try t.register(try t.writeEff(traceLoc(r.loc) orelse return null, v));
            },
            .UnpackVariant, .UnpackVariantGeneric, .UnpackVariantImmRef, .UnpackVariantMutRef, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => {
                const ty = t.popTs() orelse return null;
                const generic = switch (ins.op) {
                    .UnpackVariantGeneric, .UnpackVariantGenericImmRef, .UnpackVariantGenericMutRef => true,
                    else => false,
                };
                const tag = if (generic) m.cm.variant_instantiation_handles[ins.idx].variant else m.cm.variant_handles[ins.idx].variant;
                if (ty.layout.* != .datatype or !ty.layout.datatype.dt.is_enum) return null;
                const d = ty.layout.datatype;
                if (tag >= d.dt.variants.len) return null;
                const fields = d.dt.variants[tag].fields;
                const by_ref = switch (ins.op) {
                    .UnpackVariant, .UnpackVariantGeneric => false,
                    else => true,
                };
                const mut = ins.op == .UnpackVariantMutRef or ins.op == .UnpackVariantGenericMutRef;
                if (by_ref) {
                    const base = (ty.ref orelse return null).loc;
                    for (0..fields.len) |i| {
                        const loc = try t.newLoc(.{ .indexed = .{ .base = base, .i = i } });
                        try t.ts.append(t.arena, .{ .layout = t.fieldType(d, fields, i) orelse return null, .ref = .{ .mut = mut, .loc = loc } });
                    }
                } else for (0..fields.len) |i| try t.ts.append(t.arena, .{ .layout = t.fieldType(d, fields, i) orelse return null });
                // exec-history-vm: the v3 tracer pushes from the top of the stack (last field first)
                for (0..fields.len) |k| {
                    const i = if (t.v3_globals) k else fields.len - 1 - k;
                    const v = (try t.resolveStack(s, i)) orelse return null;
                    try t.register(try t.tvEffect("Push", v));
                }
            },
            else => return null,
        }
        try t.instruction("[]", gas, pc);
        return {};
    }

    /// The events as text (one JSON object per line).
    pub fn text(t: *const Tracer) []const u8 {
        return t.out.items;
    }
};

// ---------------------------------------------------------------------------------------------
// Helpers

const TS = struct {
    depth: u64 = 0,
    nodes: u64 = 0,
    maxd: u64,
    maxn: u64,
    fn ok(ts: *const TS) bool {
        return ts.depth <= ts.maxd and ts.nodes <= ts.maxn;
    }
};

fn tagWalk(ty: *const Type, ts: *TS) bool {
    ts.depth +|= 1;
    ts.nodes +|= 1;
    if (!ts.ok()) return false;
    switch (ty.*) {
        .vector => |e| if (!tagWalk(e, ts)) return false,
        .datatype => |d| {
            if (!ts.ok()) return false;
            for (d.args) |a| if (!tagWalk(a, ts)) return false;
            if (!ts.ok()) return false;
        },
        .ref, .mut_ref, .param => return false,
        else => {},
    }
    if (!ts.ok()) return false;
    ts.depth -= 1;
    return true;
}

fn nodesOf(t: *const Type) u64 {
    return switch (t.*) {
        .vector, .ref, .mut_ref => |e| 1 +| nodesOf(e),
        .datatype => |d| blk: {
            var n: u64 = 1;
            for (d.args) |a| n +|= nodesOf(a);
            break :blk n;
        },
        else => 1,
    };
}

/// `ArenaType::subst` (fails above 128 nodes), as a runtime type.
fn substOk(arena: Allocator, m: *loader.Module, tok: ff.Token, args: []const *const Type) ?*const Type {
    var n: u64 = tok.len;
    for (tok) |nd| if (nd.tag == .TypeParameter) {
        if (nd.idx >= args.len) return null;
        n +|= nodesOf(args[nd.idx]);
    };
    if (n > MAX_TYPE_INSTANTIATION_NODES) return null;
    return types.instantiate(arena, m, tok, args) catch null;
}

fn instAll(arena: Allocator, m: *loader.Module, toks: []const ff.Token, args: []const *const Type) ?[]const *const Type {
    const out = arena.alloc(*const Type, toks.len) catch return null;
    for (toks, out) |tok, *o| o.* = substOk(arena, m, tok, args) orelse return null;
    return out;
}

fn mkDatatype(arena: Allocator, dt: *loader.Datatype, args: []const *const Type) Allocator.Error!*const Type {
    const t = try arena.create(Type);
    t.* = .{ .datatype = .{ .dt = dt, .args = args } };
    return t;
}

fn locJson(a: Allocator, b: *std.ArrayList(u8), l: *const Loc) Allocator.Error!void {
    switch (l.*) {
        .local => |x| try b.print(a, "{{\"Local\":[{d},{d}]}}", .{ x[0], x[1] }),
        .global => |id| try b.print(a, "{{\"Global\":{d}}}", .{id}),
        .indexed => |x| {
            try b.appendSlice(a, "{\"Indexed\":[");
            try locJson(a, b, x.base);
            try b.print(a, ",{d}]}}", .{x.i});
        },
        .stack => unreachable,
    }
}

fn tagJson(a: Allocator, b: *std.ArrayList(u8), ty: *const Type) Allocator.Error!void {
    switch (ty.*) {
        .bool => try b.appendSlice(a, "\"bool\""),
        .u8 => try b.appendSlice(a, "\"u8\""),
        .u16 => try b.appendSlice(a, "\"u16\""),
        .u32 => try b.appendSlice(a, "\"u32\""),
        .u64 => try b.appendSlice(a, "\"u64\""),
        .u128 => try b.appendSlice(a, "\"u128\""),
        .u256 => try b.appendSlice(a, "\"u256\""),
        .address => try b.appendSlice(a, "\"address\""),
        .signer => try b.appendSlice(a, "\"signer\""),
        .vector => |e| {
            try b.appendSlice(a, "{\"vector\":");
            try tagJson(a, b, e);
            try b.append(a, '}');
        },
        .datatype => |d| {
            try b.appendSlice(a, "{\"struct\":");
            try structTagJson(a, b, d.dt, d.args);
            try b.append(a, '}');
        },
        .ref, .mut_ref, .param => unreachable,
    }
}

fn structTagJson(a: Allocator, b: *std.ArrayList(u8), dt: *const loader.Datatype, args: []const *const Type) Allocator.Error!void {
    try b.print(a, "{{\"address\":\"{x}\",\"module\":\"{s}\",\"name\":\"{s}\",\"type_args\":[", .{ &dt.defining_id, dt.module.name, dt.name });
    for (args, 0..) |x, i| {
        if (i != 0) try b.append(a, ',');
        try tagJson(a, b, x);
    }
    try b.appendSlice(a, "]}");
}

fn primJson(a: Allocator, b: *std.ArrayList(u8), tag: value.Tag, v: Value) Allocator.Error!void {
    switch (tag) {
        .u8 => try b.print(a, "{{\"type\":\"U8\",\"value\":{d}}}", .{v.a}),
        .u16 => try b.print(a, "{{\"type\":\"U16\",\"value\":{d}}}", .{v.a}),
        .u32 => try b.print(a, "{{\"type\":\"U32\",\"value\":{d}}}", .{v.a}),
        .u64 => try b.print(a, "{{\"type\":\"U64\",\"value\":{d}}}", .{v.a}),
        .bool => try b.print(a, "{{\"type\":\"Bool\",\"value\":{s}}}", .{if (v.a != 0) "true" else "false"}),
        .u128 => try b.print(a, "{{\"type\":\"U128\",\"value\":{d}}}", .{v.asU128()}),
        .u256 => try u256Json(a, b, v.box()),
        .address => try b.print(a, "{{\"type\":\"Address\",\"value\":\"{x}\"}}", .{v.box()}),
        else => unreachable,
    }
}

fn u256Json(a: Allocator, b: *std.ArrayList(u8), bytes: *const [32]u8) Allocator.Error!void {
    try b.appendSlice(a, "{\"type\":\"U256\",\"value\":[");
    for (bytes, 0..) |x, i| {
        if (i != 0) try b.append(a, ',');
        try b.print(a, "{d}", .{x});
    }
    try b.appendSlice(a, "]}");
}

fn elemJson(a: Allocator, b: *std.ArrayList(u8), c: *const value.Container, i: usize) Allocator.Error!void {
    const w = c.kind.width();
    const p = c.data + i * w;
    switch (c.kind) {
        .vec_u8 => try b.print(a, "{{\"type\":\"U8\",\"value\":{d}}}", .{p[0]}),
        .vec_bool => try b.print(a, "{{\"type\":\"Bool\",\"value\":{s}}}", .{if (p[0] != 0) "true" else "false"}),
        .vec_u16 => try b.print(a, "{{\"type\":\"U16\",\"value\":{d}}}", .{std.mem.readInt(u16, p[0..2], .little)}),
        .vec_u32 => try b.print(a, "{{\"type\":\"U32\",\"value\":{d}}}", .{std.mem.readInt(u32, p[0..4], .little)}),
        .vec_u64 => try b.print(a, "{{\"type\":\"U64\",\"value\":{d}}}", .{std.mem.readInt(u64, p[0..8], .little)}),
        .vec_u128 => try b.print(a, "{{\"type\":\"U128\",\"value\":{d}}}", .{std.mem.readInt(u128, p[0..16], .little)}),
        .vec_u256 => try u256Json(a, b, p[0..32]),
        .vec_address => try b.print(a, "{{\"type\":\"Address\",\"value\":\"{x}\"}}", .{p[0..32]}),
        else => unreachable,
    }
}

/// `Opcodes` Debug names (LdU8 -> LD_U8), built at compile time.
fn opName(op: ff.Opcode) []const u8 {
    switch (op) {
        inline else => |o| {
            const name = comptime upperSnake(@tagName(o));
            return name;
        },
        _ => return "UNKNOWN",
    }
}

fn upperSnake(comptime s: []const u8) []const u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var out: []const u8 = "";
        for (s, 0..) |c, i| {
            if (std.ascii.isUpper(c) and i != 0) out = out ++ "_";
            out = out ++ &[_]u8{std.ascii.toUpper(c)};
        }
        return out;
    }
}

test "opcode names" {
    try std.testing.expectEqualStrings("LD_U8", opName(.LdU8));
    try std.testing.expectEqualStrings("UNPACK_VARIANT_GENERIC_IMM_REF", opName(.UnpackVariantGenericImmRef));
    try std.testing.expectEqualStrings("CALL", opName(.Call));
}
