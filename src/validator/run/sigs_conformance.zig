//! Conformance suite `sig-validator` (lane sigs, PARITY G10 and G11): every transaction of the
//! mainnet sig-corpus checkpoints (vectors/sig-corpus/<seq>.jsonl.zst, Rust's
//! `verify_sender_signed_data_message_signatures` verdicts and signature indices) put through
//! the validator's own signature environment instead of the truth header's:
//!
//!   - the `VerifyParams` flags from the protocol config of the checkpoint's version
//!     (`usersig.flagsOf`), compared with the flags Rust used;
//!   - the zkLogin side as an epoch builds it (run/zklogin.zig): the `JwkMap` filled with the
//!     JWKs the validators held, `ZkLoginEnv::Prod` by the mainnet chain id, the circuit mode
//!     from the protocol config;
//!   - the alias sets as `verify_tx_with_current_aliases` reads them: each required signer's
//!     AddressAliases object (derived under 0xa) from the object state, holding the aliases the
//!     checkpoint pins (`checker.currentAliases`).
const std = @import("std");
const harness = @import("harness");
const types = @import("types");
const bcs = @import("bcs");
const protocol = @import("protocol");
const rpc_exec = @import("rpc_exec");
const sig = @import("sig");
const zklogin = @import("zklogin.zig");
const checker = @import("../authority/checker.zig");
const tx_mod = @import("../authority/tx.zig");
const messages = @import("../messages.zig");
const fixture = @import("../authority/preverify_fixture.zig");

const sc = sig.conformance;
const user = sig.user;
const usersig = rpc_exec.live.usersig;

pub const suites = [_]harness.Suite{
    .{
        .name = "sig-validator",
        .lane = "sigs",
        .doc = "mainnet corpus transactions through the validator's signature environment (protocol-config flags, epoch JWK map, zkLogin env, AddressAliases from state): verdict and indices equal Rust",
        .run = run,
        .inputs = .{ .dir = "vectors/sig-corpus", .suffix = ".jsonl.zst" },
    },
};

fn run(ctx: *harness.Ctx) !void {
    try ctx.forEachFile("vectors/sig-corpus", ".jsonl.zst", {}, file);
}

fn file(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const a = ctx.scratch();
    const seq = try sc.seqOfName(name);
    var pbuf: [96]u8 = undefined;
    const truth_text = try ctx.readZstd(try std.fmt.bufPrint(&pbuf, "vectors/sig-corpus/{s}", .{name}), 1 << 32);
    var it = harness.lines(truth_text);
    const hdr = try std.json.parseFromSliceLeaky(sc.Header, a, it.next() orelse return error.EmptyTruth, .{ .ignore_unknown_fields = true });
    if (hdr.seq != seq) return error.MalformedTruth;
    const blob = try ctx.readFile(try std.fmt.bufPrint(&pbuf, "chk/{d}.chk", .{seq}), 1 << 31);
    const txs = try sc.loadTxBytes(ctx, a, seq, blob);

    var ibuf: [128]u8 = undefined;
    const cfg = protocol.get(hdr.pv, .mainnet) catch {
        ctx.skip(try std.fmt.bufPrint(&ibuf, "{d}", .{seq}), "protocol version not built");
        return;
    };

    // the flags the validator derives equal the ones Rust verified with
    const flags = usersig.flagsOf(cfg) orelse {
        ctx.fail(try std.fmt.bufPrint(&ibuf, "{d}/flags", .{seq}), "unknown zkLogin provider in protocol {d}", .{hdr.pv});
        return;
    };
    {
        var c = ctx.check(try std.fmt.bufPrint(&ibuf, "{d}/flags", .{seq}));
        const hf = &hdr.flags;
        c.eql("accept_zklogin_in_multisig", hf.accept_zklogin_in_multisig, flags.accept_zklogin_in_multisig);
        c.eql("accept_passkey_in_multisig", hf.accept_passkey_in_multisig, flags.accept_passkey_in_multisig);
        c.eql("accept_mldsa65_in_multisig", hf.accept_mldsa65_in_multisig, flags.accept_mldsa65_in_multisig);
        c.eql("additional_multisig_checks", hf.additional_multisig_checks, flags.additional_multisig_checks);
        c.eql("validate_zklogin_public_identifier", hf.validate_zklogin_public_identifier, flags.validate_zklogin_public_identifier);
        c.eql("verify_legacy_zklogin_address", hf.verify_legacy_zklogin_address, flags.verify_legacy_zklogin_address);
        c.eql("zklogin_max_epoch_upper_bound_delta", hf.zklogin_max_epoch_upper_bound_delta, flags.zklogin_max_epoch_upper_bound_delta);
        c.eql("zklogin_circuit_mode", hf.zklogin_circuit_mode, cfg.feature_flags.zklogin_circuit_mode);
        var want: user.ProviderSet = .empty;
        for (hf.zklogin_supported_providers) |p| want.insert(user.OidcProvider.fromName(p) orelse return error.MalformedTruth);
        c.eql("zklogin_supported_providers", true, want.eql(flags.zklogin_supported_providers));
        _ = c.finish();
    }

    // the epoch's JWK map, as the epoch start and the AuthenticatorStateUpdates fill it
    var jm = zklogin.JwkMap.init(ctx.gpa);
    defer jm.deinit();
    for (hdr.jwks) |j| _ = try jm.insert(.{ .iss = j.iss, .kid = j.kid, .kty = "RSA", .e = "AQAB", .n = j.n, .alg = "RS256" });
    const sig_env: user.UserSigEnv = .{ .epoch = hdr.epoch, .flags = flags, .zklogin = zklogin.env(&jm, &usersig.mainnet_chain_id, cfg) };

    var map: rpc_exec.state.MapState = .{};
    defer map.map.deinit(ctx.gpa);
    const env: checker.Env = .{ .cfg = cfg, .epoch = hdr.epoch, .chain_id = usersig.mainnet_chain_id, .rgp = 1000, .committee_size = 100, .state = map.state(), .sig_env = &sig_env };

    while (it.next()) |text| {
        if (!std.mem.startsWith(u8, text, "{\"k\":\"tx\"")) continue;
        const l = try std.json.parseFromSliceLeaky(sc.Line, a, text, .{ .ignore_unknown_fields = true });
        if (l.system orelse false) continue;
        if (l.tx >= txs.len) return error.MalformedTruth;
        const tb = &txs[l.tx];
        const item = try std.fmt.bufPrint(&ibuf, "{d}/tx{d}", .{ seq, l.tx });
        if (!ctx.selected(item)) continue;
        var c = ctx.check(item);

        const u = userTx(a, tb) catch |e| {
            c.failf("TransactionData: {s}", .{@errorName(e)});
            _ = c.finish();
            continue;
        };
        // the AddressAliases objects holding the pinned aliases (version: 1 + the tx index)
        map.map.clearRetainingCapacity();
        const pinned = try sc.parseAliases(a, l.aliases orelse &.{});
        for (pinned) |p| if (!(p.aliases.len == 1 and std.mem.eql(u8, &p.aliases[0], &p.signer)))
            try putAliases(ctx.gpa, a, &map, &p.signer, 1 + @as(u64, l.tx), p.aliases);

        var versions: [2]?u64 = .{ null, null };
        const sets = try checker.currentAliases(a, &env, &u, &versions);
        const sigs = try a.alloc([]const u8, u.signatures().len);
        for (u.signatures(), sigs) |s, *o| o.* = s.@"0";
        const scratch = try a.alloc(u8, user.txScratchLen(sigs));
        const r = user.verifyTransaction(env.sig_env, tb.intent, sigs, sets, scratch) catch |e| {
            c.failf("{s}", .{@errorName(e)});
            _ = c.finish();
            continue;
        };
        sc.checkTxResult(&c, l.v, l.idx, &r);
        _ = c.finish();
    }
}

/// The transaction as the validator holds it: TransactionData from the intent message's bytes,
/// the signatures as sequenced.
fn userTx(a: std.mem.Allocator, tb: *const sc.TxBytes) !tx_mod.UserTx {
    if (tb.intent.len < 3) return error.NoTransactionData;
    const td = try bcs.decode(types.TransactionData, a, tb.intent[3..]);
    const gs = try a.alloc(types.GenericSignature, tb.sigs.items.len);
    for (tb.sigs.items, gs) |s, *g| g.* = .{ .@"0" = s };
    const sst = try a.alloc(types.SenderSignedTransaction, 1);
    sst[0] = .{ .intent_message = .{ .intent = types.Intent.sui(.transaction_data), .value = td }, .tx_signatures = gs };
    const t: messages.PlainTransactionWithClaims = .{ .tx = .{ .data = .{ .@"0" = .{ .items = sst } }, .auth_signature = .{} }, .claims = &.{} };
    return tx_mod.fromDecoded(a, &.{}, t) catch |e| switch (e) {
        // an input-shape rejection (not a signature matter): the signers are still known
        error.Malformed => {
            var u: tx_mod.UserTx = undefined;
            u.tx = t;
            return u;
        },
        else => |x| return x,
    };
}

fn putAliases(gpa: std.mem.Allocator, a: std.mem.Allocator, map: *rpc_exec.state.MapState, owner: *const [32]u8, version: u64, aliases: []const [32]u8) !void {
    const oid = usersig.aliasesObjectId(owner);
    var w: std.Io.Writer.Allocating = .init(a);
    try w.writer.writeAll(&oid);
    var n = aliases.len;
    while (n >= 0x80) : (n >>= 7) try w.writer.writeByte(@as(u8, @truncate(n)) | 0x80);
    try w.writer.writeByte(@intCast(n));
    for (aliases) |x| try w.writer.writeAll(&x);
    try map.put(gpa, oid, version, try fixture.moveObject(a, w.written(), version, .{ .ObjectOwner = .{ .@"0" = @splat(0) } }));
}
