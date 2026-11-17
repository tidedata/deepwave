//! Signing-time package verification parity (PARITY.md G19): every case of
//! testdata/verifier.txt.zst, which Mysten's `check_non_system_packages_to_be_published` (sui
//! 1.83.1, default `VerifierSigningConfig`) answered in tools/truth/validity (suite `verifier`),
//! through rpc_exec.pkgverify.check, the call checker.checkInputs makes. The meter cases sit on
//! the exact size where Rust starts to time out, so the error text (scope name, current, new and
//! max units) pins deepwave's meter accounting to the unit. Those cases run with the regex reference
//! safety sanity check out of the way (cfg `no-regex`); the cases that check decides
//! (`default-regex`) are skipped, since deepwave does not run it.
const std = @import("std");
const types = @import("types");
const protocol = @import("protocol");
const rpc_exec = @import("rpc_exec");
const harness = @import("harness");

const vectors_zst = @embedFile("testdata/verifier.txt.zst");

fn unhex(a: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

/// The common.rs escaping undone (`\\`, `\t`, `\n`).
fn unesc(a: std.mem.Allocator, s: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '\\' and i + 1 < s.len) {
            i += 1;
            try out.append(a, switch (s[i]) {
                't' => '\t',
                'n' => '\n',
                else => s[i],
            });
        } else try out.append(a, s[i]);
    }
    return out.items;
}

test "pkgverify: Mysten signing-time package verification vectors" {
    const gpa = std.testing.allocator;
    const text = try harness.decompressZstd(gpa, vectors_zst, 1 << 30);
    defer gpa.free(text);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var cases: usize = 0;
    var failures: usize = 0;
    var regex_cases: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        _ = arena_state.reset(.retain_capacity);
        const a = arena_state.allocator();
        var f = std.mem.splitScalar(u8, line, '\t');
        const id = f.next().?;
        const pv = try std.fmt.parseInt(u64, f.next().?, 10);
        const cfg_name = f.next().?;
        // deepwave has no regex reference safety sanity check (PARITY.md G19 log): Rust decides
        // these cases there, and deepwave answers what Rust answers without it
        if (std.mem.eql(u8, cfg_name, "default-regex")) {
            regex_cases += 1;
            continue;
        }
        const cmds_s = f.next().?;
        const want = try unesc(a, f.next().?);

        var cmds: std.ArrayList(types.Command) = .empty;
        var cit = std.mem.splitScalar(u8, cmds_s, ';');
        while (cit.next()) |cs| {
            var mods: std.ArrayList([]const u8) = .empty;
            if (cs.len > 2) {
                var mit = std.mem.splitScalar(u8, cs[2..], ',');
                while (mit.next()) |h| try mods.append(a, try unhex(a, h));
            }
            const zero: types.ObjectID = .{ .@"0" = .{ .@"0" = @splat(0) } };
            try cmds.append(a, switch (cs[0]) {
                'P' => .{ .Publish = .{ mods.items, &.{} } },
                'U' => .{ .Upgrade = .{ mods.items, &.{}, zero, .{ .Input = 0 } } },
                else => return error.BadVector,
            });
        }
        const td: types.TransactionDataV1 = .{
            .kind = .{ .ProgrammableTransaction = .{ .inputs = &.{}, .commands = cmds.items } },
            .sender = .{ .@"0" = @splat(0) },
            .gas_data = .{ .payment = &.{}, .owner = .{ .@"0" = @splat(0) }, .price = 1000, .budget = 10_000_000 },
            .expiration = .None,
        };
        const cfg = try protocol.get(pv, .mainnet);
        const got: []const u8 = if (try rpc_exec.pkgverify.check(a, cfg, &td)) |fail|
            try std.fmt.allocPrint(a, "err {s}", .{fail.message})
        else
            "ok";
        // checker's SuiError is UserInputError's Display behind the SuiErrorKind prefix
        const exp: []const u8 = if (std.mem.startsWith(u8, want, "err "))
            try std.fmt.allocPrint(a, "err Error checking transaction input objects: {s}", .{want[4..]})
        else
            want;
        cases += 1;
        if (!std.mem.eql(u8, got, exp)) {
            failures += 1;
            std.debug.print("pkgverify {s}:\n  want {s}\n  got  {s}\n", .{ id, exp, got });
        }
    }
    try std.testing.expect(cases >= 20);
    try std.testing.expect(regex_cases <= 2);
    try std.testing.expectEqual(@as(usize, 0), failures);
}
