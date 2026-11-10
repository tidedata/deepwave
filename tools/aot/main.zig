//! deepwave-aot: the compiler of the Move VM's ahead-of-time tier.
//!
//!   deepwave-aot gen    <sources> [--hot FILE] [--top N] --out <src/move/vm>
//!   deepwave-aot digest <sources>
//!   deepwave-aot hot    <sources> [--hot FILE]      lists what `gen` would compile
//!
//! <sources>: any number of `--packages FILE` (a ZUIMVPK1 packages.bin: the truth tool's corpus
//! and framework packages, or one written by a store dump) and `--module FILE.mv` (one serialized
//! module). The modules must be ones the chain accepted (published code is always verified), so
//! this tool deserializes them but does not run the verifier again.
//!
//! `gen` writes <out>/aot_gen/m_<digest>.zig per module with selected functions and <out>/aot_gen.zig,
//! the registry the VM builds in (aot.zig); rebuild deepwave to use it. Without --hot every function
//! with code is compiled; with it only the listed functions (see aot.HotList; --top N keeps the N
//! lines with the most instructions). Existing <out>/aot_gen/ is replaced.
const std = @import("std");
const Io = std.Io;
const move_vm = @import("move_vm");
const move_format = @import("move_format");

const aot = move_vm.aot;
const loader = move_vm.loader;

const Source = struct { name: []const u8, bytes: []const u8 };

const Args = struct {
    cmd: []const u8,
    packages: std.ArrayList([]const u8) = .empty,
    modules: std.ArrayList([]const u8) = .empty,
    hot: ?[]const u8 = null,
    top: ?usize = null,
    out: ?[]const u8 = null,
};

fn usage() u8 {
    std.debug.print("usage: deepwave-aot gen|digest|hot (--packages FILE | --module FILE.mv)... [--hot FILE] [--top N] [--out DIR]\n", .{});
    return 2;
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena);
    if (argv.len < 2) return usage();
    var a: Args = .{ .cmd = argv[1] };
    var i: usize = 2;
    while (i < argv.len) : (i += 1) {
        const k = argv[i];
        if (i + 1 >= argv.len) return usage();
        const v = argv[i + 1];
        if (std.mem.eql(u8, k, "--packages")) try a.packages.append(arena, v) else if (std.mem.eql(u8, k, "--module")) try a.modules.append(arena, v) else if (std.mem.eql(u8, k, "--hot")) a.hot = v else if (std.mem.eql(u8, k, "--top")) a.top = std.fmt.parseInt(usize, v, 10) catch return usage() else if (std.mem.eql(u8, k, "--out")) a.out = v else return usage();
        i += 1;
    }
    const gen = std.mem.eql(u8, a.cmd, "gen");
    if (!gen and !std.mem.eql(u8, a.cmd, "digest") and !std.mem.eql(u8, a.cmd, "hot")) return usage();
    if (gen and a.out == null) return usage();
    if (a.packages.items.len + a.modules.items.len == 0) return usage();

    const cwd = Io.Dir.cwd();
    var hot: ?aot.HotList = null;
    if (a.hot) |hp| {
        const text = try cwd.readFileAlloc(io, hp, arena, .limited(64 << 20));
        hot = try aot.HotList.parse(arena, text);
        if (a.top) |n| hot.?.top(n);
    }

    // every module, deduplicated by digest
    var cms: std.ArrayList(move_format.file_format.CompiledModule) = .empty;
    var seen: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
    const bcfg: move_format.BinaryConfig = .{};
    var n_in: usize = 0;
    for (a.packages.items) |p| {
        const bytes = try cwd.readFileAlloc(io, p, arena, .limited(4 << 30));
        try readPackages(arena, bytes, &bcfg, &cms, &seen, &n_in);
    }
    for (a.modules.items) |p| {
        const bytes = try cwd.readFileAlloc(io, p, arena, .limited(64 << 20));
        try addModule(arena, bytes, &bcfg, &cms, &seen, &n_in);
    }

    const sel: aot_sel = .{ .hot = if (hot) |*h| h else null };
    const select: move_vm.aot_emit.Select = .{ .ctx = &sel, .f = aot_sel.wants };

    if (std.mem.eql(u8, a.cmd, "digest")) {
        for (cms.items) |*cm| std.debug.print("{x}::{s} {x}\n", .{ cm.selfAddress(), cm.selfName(), &aot.digestModule(cm) });
        return 0;
    }

    var out_files: std.ArrayList(u8) = .empty;
    defer out_files.deinit(gpa);
    var stems: std.ArrayList([]const u8) = .empty;
    var n_fns: u32 = 0;
    if (gen) {
        const root = a.out.?;
        const gdir = try std.fmt.allocPrint(arena, "{s}/aot_gen", .{root});
        try cwd.deleteTree(io, gdir);
        try cwd.createDirPath(io, gdir);
    }
    for (cms.items) |*cm| {
        out_files.clearRetainingCapacity();
        const n = try move_vm.aot_emit.emitModule(gpa, &out_files, cm, select);
        if (n == 0) continue;
        n_fns += n;
        if (!gen) {
            std.debug.print("{x}::{s} {d} functions\n", .{ cm.selfAddress(), cm.selfName(), n });
            continue;
        }
        const stem = try std.fmt.allocPrint(arena, "m_{x}", .{aot.digestModule(cm)[0..12]});
        try stems.append(arena, stem);
        const path = try std.fmt.allocPrint(arena, "{s}/aot_gen/{s}.zig", .{ a.out.?, stem });
        try cwd.writeFile(io, .{ .sub_path = path, .data = out_files.items });
    }
    if (gen) {
        out_files.clearRetainingCapacity();
        try move_vm.aot_emit.emitIndex(gpa, &out_files, stems.items);
        const path = try std.fmt.allocPrint(arena, "{s}/aot_gen.zig", .{a.out.?});
        try cwd.writeFile(io, .{ .sub_path = path, .data = out_files.items });
    }
    std.debug.print("deepwave-aot: {d} modules read, {d} compiled modules, {d} functions\n", .{ n_in, stems.items.len, n_fns });
    _ = loader;
    return 0;
}

const aot_sel = struct {
    hot: ?*const aot.HotList,
    fn wants(ctx: ?*const anyopaque, addr: *const [32]u8, module: []const u8, func: []const u8) bool {
        const s: *const aot_sel = @ptrCast(@alignCast(ctx.?));
        const h = s.hot orelse return true;
        return h.contains(addr, module, func);
    }
};

fn addModule(
    arena: std.mem.Allocator,
    bytes: []const u8,
    bcfg: *const move_format.BinaryConfig,
    cms: *std.ArrayList(move_format.file_format.CompiledModule),
    seen: *std.AutoHashMapUnmanaged([32]u8, void),
    n_in: *usize,
) !void {
    n_in.* += 1;
    switch (try move_format.deserialize(arena, bytes, bcfg)) {
        .ok => |cm| {
            const d = aot.digestModule(&cm);
            if ((try seen.getOrPut(arena, d)).found_existing) return;
            try cms.append(arena, cm);
        },
        .err => |e| std.debug.print("deepwave-aot: skipping a module that does not deserialize: {s}\n", .{@tagName(e.major)}),
    }
}

/// packages.bin (ZUIMVPK1), as written by tools/truth/move-vm and read by move-vm's conformance.
fn readPackages(
    arena: std.mem.Allocator,
    bytes: []const u8,
    bcfg: *const move_format.BinaryConfig,
    cms: *std.ArrayList(move_format.file_format.CompiledModule),
    seen: *std.AutoHashMapUnmanaged([32]u8, void),
    n_in: *usize,
) !void {
    if (bytes.len < 12 or !std.mem.eql(u8, bytes[0..8], "ZUIMVPK1")) return error.BadPackages;
    var r = loader.Reader{ .bytes = bytes, .pos = 8 };
    const n = try rd32(&r);
    for (0..n) |_| {
        _ = try r.take(32 + 32 + 8); // version id, original id, version
        const nl = try rd32(&r);
        for (0..nl) |_| _ = try r.take(64);
        const nt = try rd32(&r);
        for (0..nt) |_| {
            _ = try r.take(try rd32(&r));
            _ = try r.take(try rd32(&r));
            _ = try r.take(32);
        }
        const nm = try rd32(&r);
        for (0..nm) |_| {
            _ = try r.take(try rd32(&r)); // module name
            const mb = try r.take(try rd32(&r));
            try addModule(arena, mb, bcfg, cms, seen, n_in);
        }
    }
}

fn rd32(r: *loader.Reader) !u32 {
    return std.mem.readInt(u32, (try r.take(4))[0..4], .little);
}
