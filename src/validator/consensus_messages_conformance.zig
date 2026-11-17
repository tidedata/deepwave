//! Suite `consensus-messages` (val-truth): every ConsensusTransaction that Mysten's own validators
//! put in their blocks on a localnet under load (the capture `consensus-localnet` replays,
//! `$ZUI_CORPUS/consensus/localnet/epoch-N.vec`, tools/truth/consensus/capture.sh) decodes in deepwave
//! and re-encodes to the same bytes, and every user transaction parses into deepwave's UserTx (inputs,
//! digest) without a reject. Mysten accepted every one of these blocks, so a deepwave decode failure is a
//! block deepwave would reject. Items are blocks (`epochN/R/A`); the kinds seen are reported.
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const consensus = @import("consensus");
const messages = @import("messages.zig");
const tx_mod = @import("authority/tx.zig");
const tx_validator = @import("authority/tx_validator.zig");

const dir = "consensus/localnet";

pub const suites = [_]harness.Suite{
    .{ .name = "consensus-messages", .lane = "val-truth", .doc = "ConsensusTransactions in Mysten localnet blocks: decode, byte-equal re-encode, UserTx parse", .run = run },
};

fn run(ctx: *harness.Ctx) anyerror!void {
    const gpa = ctx.gpa;
    const names = ctx.listFiles(dir, ".vec") catch |e| {
        ctx.skip(dir, @errorName(e));
        return;
    };
    defer ctx.freeNames(names);
    if (names.len == 0) {
        ctx.skip(dir, "no epoch-N.vec files (tools/truth/consensus/capture.sh)");
        return;
    }
    var kinds: [14]usize = @splat(0);
    var total: usize = 0;
    for (names) |name| {
        if (ctx.done()) break;
        const base = if (std.mem.lastIndexOfScalar(u8, name, '/')) |i| name[i + 1 ..] else name;
        const p = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, base });
        defer gpa.free(p);
        const text = ctx.corpus.readFileAlloc(ctx.io, p, gpa, .limited(1 << 34)) catch |e| {
            ctx.skip(p, @errorName(e));
            continue;
        };
        defer gpa.free(text);
        const label = std.mem.trimEnd(u8, base, ".vec");
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            if (ctx.done()) break;
            var it = std.mem.tokenizeScalar(u8, line, ' ');
            const k = it.next() orelse continue;
            if (!std.mem.eql(u8, k, "block")) continue;
            const round = it.next().?;
            const author = it.next().?;
            _ = it.next();
            const hexs = it.next().?;
            var nb: [128]u8 = undefined;
            const item = std.fmt.bufPrint(&nb, "{s}/{s}/{s}", .{ label, round, author }) catch "block";
            if (!ctx.selected(item)) continue;
            ctx.nextItem();
            const a = ctx.scratch();
            const bytes = try a.alloc(u8, hexs.len / 2);
            _ = try std.fmt.hexToBytes(bytes, hexs);
            var c = ctx.check(item);
            const sb = consensus.digest.decodeSignedBlock(a, bytes) catch |e| {
                c.failf("block decode: {s}", .{@errorName(e)});
                _ = c.finish();
                continue;
            };
            for (sb.inner.transactions(), 0..) |t, ti| {
                var tr = bcs.decode(messages.ConsensusTransaction, a, t.data) catch |e| {
                    c.failf("transaction {d}: decode {s}", .{ ti, @errorName(e) });
                    continue;
                };
                total += 1;
                kinds[@backingInt(tr.kind)] += 1;
                switch (tr.kind) {
                    .UpdateTransactionDenyConfig => |*m| switch (m.*) {
                        .V1 => |*cfg| if (cfg.rules) |*r| {
                            cfg.rules = try tx_validator.normalizedDenyRules(a, r);
                        },
                    },
                    else => {},
                }
                const re = try bcs.encodeAlloc(messages.ConsensusTransaction, a, &tr);
                c.bytes("re-encoded ConsensusTransaction", t.data, re);
                switch (tr.kind) {
                    .UserTransactionV2 => |u| {
                        // The payload as the handler sees it: BCS(PlainTransactionWithClaims).
                        const raw = try bcs.encodeAlloc(messages.PlainTransactionWithClaims, a, &u);
                        _ = tx_mod.parse(a, raw) catch |e| c.failf("transaction {d}: UserTx parse {s}", .{ ti, @errorName(e) });
                    },
                    else => {},
                }
            }
            _ = c.finish();
        }
    }
    ctx.detail("INFO consensus-messages: {d} transactions; per kind index {any}\n", .{ total, kinds });
}
