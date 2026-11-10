//! deepwave-move: Move tooling over deepwave's store, VM and verifier. One binary,
//! subcommands:
//!
//!   gas-report   per package / function / object type gas and storage spend from a node store
//!   layout       storage-layout advisor over a package (static, plus optional on-chain sizes)
//!   profile      re-run recent mainnet calls of a package with per-instruction gas attribution
//!   optimize     bytecode-to-bytecode optimizer passes on a module, verifier checked
//!   equiv        equivalence check of an optimized module against the original (verifier +
//!                differential execution on recorded calls)
//!   superopt     superoptimizer search over straight-line windows driven by a fast simulator
//!
//! The node directory must be stopped or a db-checkpoint copy (the store lock is taken, as deepwave-tool does).
const std = @import("std");
const Io = std.Io;
const common = @import("common.zig");
const gasreport = @import("gasreport.zig");
const layout = @import("layout.zig");
const profile = @import("profile.zig");
const optimize = @import("optimize.zig");
const equiv = @import("equiv.zig");
const superopt = @import("superopt.zig");

pub const Ctx = common.Ctx;

const usage =
    \\deepwave-move <command> [options]
    \\  gas-report --dir DIR [--from SEQ] [--to SEQ] [--checkpoints N] [--top N]
    \\             [--format json|csv] [--table packages|functions|types|txs]
    \\                    ecosystem gas and storage spend per package/function/object type (default: the newest 2000 checkpoints)
    \\  layout     --dir DIR --package 0xID [--module NAME] [--format json|text]
    \\             | --module-file FILE.mv [--format json|text]
    \\                    storage-layout advisor: field sizes, inline vs dynamic fields, rebate-earning deletes
    \\  profile    --dir DIR --package 0xID [--module NAME] [--function NAME] [--checkpoints N] [--limit N] [--top N]
    \\                    re-run recent calls on the live state with per-instruction gas attribution
    \\  optimize   (--dir DIR --package 0xID | --module-file FILE.mv) [--module NAME] [--out FILE.mv] [--passes LIST] [--format json|text]
    \\                    bytecode optimizer: every rewrite is checked by the Move and Sui verifiers
    \\  equiv      --dir DIR --package 0xID --module NAME --optimized FILE.mv [--checkpoints N] [--limit N]
    \\                    verifier + differential execution of recorded calls, original vs optimized module
    \\  superopt   [--max-len N] [--budget N] [--seed N] [--window "OP;OP;..."] | --module-file FILE.mv [--function NAME]
    \\                    search shorter equivalent straight-line integer sequences by fast simulation; --out applies exhaustive proofs only
    \\  optimize, equiv and superopt take [--protocol N] (default: the build's max); equiv also [--min-runs N] (default 1)
    \\
;

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    var obuf: [64 << 10]u8 = undefined;
    var ow = common.stdout(io, &obuf);
    const w = &ow.interface;
    defer w.flush() catch {};
    var ctx: Ctx = .{ .gpa = gpa, .io = io, .arena = arena, .w = w, .opts = .{ .args = args[2..] } };
    const cmd = args[1];
    const r = dispatch(&ctx, cmd) catch |e| {
        w.flush() catch {};
        std.debug.print("deepwave-move {s}: {s}\n", .{ cmd, @errorName(e) });
        return 1;
    };
    return r;
}

fn dispatch(ctx: *Ctx, cmd: []const u8) !u8 {
    if (std.mem.eql(u8, cmd, "gas-report")) return gasReportCmd(ctx);
    if (std.mem.eql(u8, cmd, "layout")) return layout.run(ctx);
    if (std.mem.eql(u8, cmd, "profile")) return profile.run(ctx);
    if (std.mem.eql(u8, cmd, "optimize")) return optimize.run(ctx);
    if (std.mem.eql(u8, cmd, "equiv")) return equiv.run(ctx);
    if (std.mem.eql(u8, cmd, "superopt")) return superopt.run(ctx);
    std.debug.print("unknown command {s}\n{s}", .{ cmd, usage });
    return 2;
}

fn gasReportCmd(ctx: *Ctx) !u8 {
    const dir = ctx.opts.get("--dir") orelse {
        std.debug.print("gas-report: --dir is required\n{s}", .{usage});
        return 2;
    };
    var o = try common.openNode(ctx.gpa, ctx.io, ctx.arena, dir);
    defer o.close();
    var snap = o.st.snapshot();
    defer snap.release();
    const tip = o.st.committed() orelse {
        try ctx.w.writeAll("empty store\n");
        return 1;
    };
    const to = try ctx.opts.num("--to", tip);
    const n = try ctx.opts.num("--checkpoints", 2000);
    const low = snap.lowestAvailable() orelse 0;
    const from = try ctx.opts.num("--from", @max(low, to -| (n -| 1)));
    const top = try ctx.opts.num("--top", 200);
    const fmt: common.Format = if (ctx.opts.get("--format")) |f| (std.meta.stringToEnum(common.Format, f) orelse return error.BadFormat) else .json;
    const table: gasreport.Table = if (ctx.opts.get("--table")) |t| (std.meta.stringToEnum(gasreport.Table, t) orelse return error.BadTable) else .functions;
    var rep = try gasreport.scan(ctx.gpa, ctx.arena, &snap, from, to, @intCast(top));
    try gasreport.write(ctx.w, ctx.arena, &rep, fmt, table, @intCast(top));
    return 0;
}

test {
    _ = @import("superopt.zig");
    _ = @import("rewrite.zig");
    _ = @import("optimize.zig");
}
