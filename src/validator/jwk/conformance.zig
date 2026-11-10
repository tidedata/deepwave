//! Conformance suite `jwk-vectors` (lane val-randomness-jwk): vectors/jwk/fastcrypto.jsonl written
//! by tools/truth/randomness (`jwk`): zkLogin JWK document parsing per provider, issuer and
//! endpoint tables, the ActiveJwk order, and the BCS of the AuthenticatorStateUpdate transaction
//! and the NewJWKFetched ConsensusTransaction, all against Mysten's code.
const std = @import("std");
const harness = @import("harness");
const core = @import("core");
const bcs = @import("bcs");
const types = @import("types");
const providers = @import("providers.zig");
const parse = @import("parse.zig");
const aggregator = @import("aggregator.zig");
const state_update = @import("state_update.zig");
const txs = @import("txs.zig");

pub const suites = [_]harness.Suite{
    .{ .name = "jwk-vectors", .lane = "val-randomness-jwk", .doc = "zkLogin JWK parsing, providers, ActiveJwk order, AuthenticatorStateUpdate and NewJWKFetched encodings vs Mysten's code", .run = run },
};

const Line = struct {
    op: []const u8,
    id: []const u8 = "",
    provider: ?[]const u8 = null,
    display: ?[]const u8 = null,
    iss: ?[]const u8 = null,
    endpoint: ?[]const u8 = null,
    doc: ?[]const u8 = null,
    ok: ?bool = null,
    keys: ?[]const struct { iss: []const u8, kid: []const u8, kty: []const u8, e: []const u8, n: []const u8, alg: []const u8 } = null,
    epoch: ?u64 = null,
    round: ?u64 = null,
    initial_shared_version: ?u64 = null,
    order: ?[]const [3][]const u8 = null,
    input: ?[]const [3][]const u8 = null,
    data: ?[]const u8 = null,
    digest: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    bytes: ?[]const u8 = null,
};

fn run(ctx: *harness.Ctx) !void {
    const text = try ctx.readFile("vectors/jwk/fastcrypto.jsonl", 64 << 20);
    var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (ctx.done()) return;
        _ = arena_state.reset(.retain_capacity);
        const v = try std.json.parseFromSliceLeaky(Line, a, line, .{ .ignore_unknown_fields = true });
        if (!ctx.selected(v.id)) continue;
        one(ctx, a, &v) catch |e| ctx.fail(v.id, "error {s}", .{@errorName(e)});
    }
}

fn hexAlloc(a: std.mem.Allocator, s: []const u8) ![]u8 {
    return core.hex.decodeAlloc(a, s);
}

fn one(ctx: *harness.Ctx, a: std.mem.Allocator, v: *const Line) !void {
    var chk = ctx.check(v.id);
    defer _ = chk.finish();
    if (std.mem.eql(u8, v.op, "from_str")) {
        // a name Rust's OIDCProvider::from_str rejects
        chk.eql("from_str rejects", v.ok.?, providers.Provider.fromName(v.provider.?) != null);
    } else if (std.mem.eql(u8, v.op, "parse")) {
        const p = providers.Provider.fromName(v.provider.?) orelse return chk.failf("unknown provider {s}", .{v.provider.?});
        if (v.display) |d| {
            var nb: [512]u8 = undefined;
            chk.text("Display", d, try p.name(&nb));
        }
        var buf: [512]u8 = undefined;
        const cfg = try p.config(&buf);
        chk.text("iss", v.iss.?, cfg.iss);
        chk.text("endpoint", v.endpoint.?, cfg.jwk_endpoint);
        const got = parse.parseJwks(a, v.doc.?, p) catch null;
        chk.eql("parse ok", v.ok.?, got != null);
        if (got) |g| {
            const want = v.keys.?;
            chk.eql("key count", want.len, g.len);
            if (want.len == g.len) for (want, g) |w, k| {
                chk.text("iss", w.iss, k.id.iss.@"0");
                chk.text("kid", w.kid, k.id.kid.@"0");
                chk.text("kty", w.kty, k.jwk.kty.@"0");
                chk.text("e", w.e, k.jwk.e.@"0");
                chk.text("n", w.n, k.jwk.n.@"0");
                chk.text("alg", w.alg, k.jwk.alg.@"0");
            };
        }
    } else if (std.mem.eql(u8, v.op, "from_iss")) {
        const got = providers.Provider.fromIss(v.iss.?);
        if (v.provider) |name| {
            const want = providers.Provider.fromName(name) orelse return chk.failf("truth provider {s} unknown", .{name});
            chk.eql("from_iss matches", true, got != null and got.?.eql(want));
        } else chk.eql("from_iss none", true, got == null);
    } else if (std.mem.eql(u8, v.op, "asu")) {
        // the truth's unsorted input list
        const input = v.input.?;
        const jwks = try a.alloc(types.ActiveJwk, input.len);
        for (input, jwks) |in, *j| j.* = .{ .jwk_id = .{ .iss = .{ .@"0" = in[0] }, .kid = .{ .@"0" = in[1] } }, .jwk = .{ .kty = .{ .@"0" = "RSA" }, .e = .{ .@"0" = "AQAB" }, .n = .{ .@"0" = in[2] }, .alg = .{ .@"0" = "RS256" } }, .epoch = v.epoch.? };
        // the ActiveJwk order (length first, as authenticator_state.move jwk_lt)
        const sorted = try a.dupe(types.ActiveJwk, jwks);
        std.mem.sort(types.ActiveJwk, sorted, {}, struct {
            fn less(_: void, x: types.ActiveJwk, y: types.ActiveJwk) bool {
                return aggregator.activeJwkOrder(x, y) == .lt;
            }
        }.less);
        const want_order = v.order.?;
        chk.eql("order length", want_order.len, sorted.len);
        if (want_order.len == sorted.len) for (want_order, sorted) |w, g| {
            chk.text("order iss", w[0], g.jwk_id.iss.@"0");
            chk.text("order kid", w[1], g.jwk_id.kid.@"0");
            chk.text("order n", w[2], g.jwk.n.@"0");
        };
        var built = try state_update.authenticatorStateUpdate(ctx.gpa, v.epoch.?, v.round.?, jwks, v.initial_shared_version.?);
        defer built.deinit(ctx.gpa);
        chk.bytes("TransactionData", try hexAlloc(a, v.data.?), built.data);
        chk.bytes("digest", try hexAlloc(a, v.digest.?), &built.digest);
    } else if (std.mem.eql(u8, v.op, "ctx_jwk")) {
        const auth = (try hexAlloc(a, v.authority.?))[0..96].*;
        const id: types.JwkId = .{ .iss = .{ .@"0" = "https://accounts.google.com" }, .kid = .{ .@"0" = "abc" } };
        const jwk: types.JWK = .{ .kty = .{ .@"0" = "RSA" }, .e = .{ .@"0" = "AQAB" }, .n = .{ .@"0" = "nn" }, .alg = .{ .@"0" = "RS256" } };
        const got = try txs.newJwkFetchedTx(ctx.gpa, &auth, id, jwk);
        defer ctx.gpa.free(got);
        chk.bytes("ConsensusTransaction", try hexAlloc(a, v.bytes.?), got);
    }
}
