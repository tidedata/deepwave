//! OIDC providers of zkLogin (fastcrypto-zkp `bn254::zk_login::OIDCProvider`, mainnet-v1.83.1
//! rev da61cd46): issuer string, JWK endpoint, name parsing, issuer parsing, and the default
//! provider set per chain (`sui-config` `default_zklogin_oauth_providers`).
const std = @import("std");

pub const Kind = enum {
    Google,
    Twitch,
    Facebook,
    Kakao,
    Apple,
    Slack,
    Microsoft,
    AwsTenant,
    KarrierOne,
    Credenza3,
    TestIssuer,
    TestIssuerKey8192,
    Playtron,
    Threedos,
    Onefc,
    FanTV,
    Arden,
    EveFrontier,
    TestEveFrontier,
};

/// A provider; `region` and `tenant_id` are set for AwsTenant only (borrowed from the input).
pub const Provider = struct {
    kind: Kind,
    region: []const u8 = "",
    tenant_id: []const u8 = "",

    pub fn eql(a: Provider, b: Provider) bool {
        return a.kind == b.kind and std.mem.eql(u8, a.region, b.region) and std.mem.eql(u8, a.tenant_id, b.tenant_id);
    }

    /// `Display`: the name `FromStr` takes back (AwsTenant formatted into `buf`).
    pub fn name(p: Provider, buf: []u8) error{NoSpaceLeft}![]const u8 {
        return switch (p.kind) {
            .AwsTenant => std.fmt.bufPrint(buf, "AwsTenant-region:{s}-tenant_id:{s}", .{ p.region, p.tenant_id }),
            else => @tagName(p.kind),
        };
    }

    pub const Config = struct { iss: []const u8, jwk_endpoint: []const u8 };

    /// `get_config`. For AwsTenant the strings are formatted into `buf`.
    pub fn config(p: Provider, buf: []u8) error{NoSpaceLeft}!Config {
        return switch (p.kind) {
            .Google => .{ .iss = "https://accounts.google.com", .jwk_endpoint = "https://www.googleapis.com/oauth2/v2/certs" },
            .Twitch => .{ .iss = "https://id.twitch.tv/oauth2", .jwk_endpoint = "https://id.twitch.tv/oauth2/keys" },
            .Facebook => .{ .iss = "https://www.facebook.com", .jwk_endpoint = "https://www.facebook.com/.well-known/oauth/openid/jwks/" },
            .Kakao => .{ .iss = "https://kauth.kakao.com", .jwk_endpoint = "https://kauth.kakao.com/.well-known/jwks.json" },
            .Apple => .{ .iss = "https://appleid.apple.com", .jwk_endpoint = "https://appleid.apple.com/auth/keys" },
            .Slack => .{ .iss = "https://slack.com", .jwk_endpoint = "https://slack.com/openid/connect/keys" },
            .Microsoft => .{ .iss = "https://login.microsoftonline.com/v2.0", .jwk_endpoint = "https://login.microsoftonline.com/common/discovery/v2.0/keys" },
            .AwsTenant => blk: {
                const iss = try std.fmt.bufPrint(buf, "https://cognito-idp.{s}.amazonaws.com/{s}", .{ p.region, p.tenant_id });
                const ep = try std.fmt.bufPrint(buf[iss.len..], "https://cognito-idp.{s}.amazonaws.com/{s}/.well-known/jwks.json", .{ p.region, p.tenant_id });
                break :blk .{ .iss = iss, .jwk_endpoint = ep };
            },
            .KarrierOne => .{ .iss = "https://accounts.karrier.one/", .jwk_endpoint = "https://accounts.karrier.one/.well-known/jwks" },
            .Credenza3 => .{ .iss = "https://accounts.credenza3.com", .jwk_endpoint = "https://accounts.credenza3.com/jwks" },
            .TestIssuer => .{ .iss = "https://oauth.sui.io", .jwk_endpoint = "https://jwt-tester.mystenlabs.com/.well-known/jwks.json" },
            .TestIssuerKey8192 => .{ .iss = "https://jwt-tester.mystenlabs.com", .jwk_endpoint = "https://jwt-tester.mystenlabs.com/8192/jwks.json" },
            .Playtron => .{ .iss = "https://oauth2.playtron.one", .jwk_endpoint = "https://oauth2.playtron.one/.well-known/jwks.json" },
            .Threedos => .{ .iss = "https://auth.3dos.io", .jwk_endpoint = "https://auth.3dos.io/.well-known/jwks.json" },
            .Onefc => .{
                .iss = "https://login.onepassport.onefc.com/de3ee5c1-5644-4113-922d-e8336569a462/v2.0/",
                .jwk_endpoint = "https://login.onepassport.onefc.com/de3ee5c1-5644-4113-922d-e8336569a462/b2c_1a_prod_signupsignin_onesuizklogin/discovery/v2.0/keys",
            },
            .FanTV => .{ .iss = "https://accounts.fantv.world", .jwk_endpoint = "https://fantv-apis.fantiger.com/v1/web3/jwks.json" },
            .Arden => .{ .iss = "https://oidc.arden.cc", .jwk_endpoint = "https://api.arden.cc/auth/jwks" },
            .EveFrontier => .{ .iss = "auth.evefrontier.com", .jwk_endpoint = "https://auth.evefrontier.com/.well-known/jwks.json" },
            .TestEveFrontier => .{ .iss = "test.auth.evefrontier.com", .jwk_endpoint = "https://test.auth.evefrontier.com/.well-known/jwks.json" },
        };
    }

    /// `FromStr`: "Google", ... or "AwsTenant-region:<region>-tenant_id:<tenant>" (the regex
    /// `AwsTenant-region:(?P<region>[^.]+)-tenant_id:(?P<tenant_id>[^/]+)` searched anywhere).
    pub fn fromName(s: []const u8) ?Provider {
        inline for (comptime std.meta.tags(Kind)) |k| {
            if (k != .AwsTenant and std.mem.eql(u8, s, @tagName(k))) return .{ .kind = k };
        }
        return parseAwsName(s);
    }

    fn parseAwsName(s: []const u8) ?Provider {
        const head = "AwsTenant-region:";
        const mid = "-tenant_id:";
        var from: usize = 0;
        while (std.mem.indexOfPos(u8, s, from, head)) |at| : (from = at + 1) {
            const rstart = at + head.len;
            // region = [^.]+ followed by mid: the longest dot free run that is followed by mid
            var rend: usize = rstart;
            while (rend < s.len and s[rend] != '.') rend += 1;
            var cut: ?usize = null;
            var i = rend;
            while (i > rstart) {
                i -= 1;
                if (std.mem.startsWith(u8, s[i..], mid)) {
                    cut = i;
                    break;
                }
            }
            const c = cut orelse continue;
            if (c == rstart) continue; // region needs at least one char
            const tstart = c + mid.len;
            var tend = tstart;
            while (tend < s.len and s[tend] != '/') tend += 1;
            if (tend == tstart) continue;
            return .{ .kind = .AwsTenant, .region = s[rstart..c], .tenant_id = s[tstart..tend] };
        }
        return null;
    }

    /// `from_iss`.
    pub fn fromIss(iss: []const u8) ?Provider {
        const table = [_]struct { []const u8, Kind }{
            .{ "https://accounts.google.com", .Google },
            .{ "https://id.twitch.tv/oauth2", .Twitch },
            .{ "https://www.facebook.com", .Facebook },
            .{ "https://kauth.kakao.com", .Kakao },
            .{ "https://appleid.apple.com", .Apple },
            .{ "https://slack.com", .Slack },
            .{ "https://oauth.sui.io", .TestIssuer },
            .{ "https://jwt-tester.mystenlabs.com", .TestIssuerKey8192 },
            .{ "https://accounts.karrier.one/", .KarrierOne },
            .{ "https://accounts.credenza3.com", .Credenza3 },
            .{ "https://oauth2.playtron.one", .Playtron },
            .{ "https://auth.3dos.io", .Threedos },
            .{ "https://login.onepassport.onefc.com/de3ee5c1-5644-4113-922d-e8336569a462/v2.0/", .Onefc },
            .{ "https://accounts.fantv.world", .FanTV },
            .{ "https://oidc.arden.cc", .Arden },
            .{ "auth.evefrontier.com", .EveFrontier },
            .{ "test.auth.evefrontier.com", .TestEveFrontier },
        };
        for (table) |e| if (std.mem.eql(u8, iss, e[0])) return .{ .kind = e[1] };
        if (std.mem.startsWith(u8, iss, "https://login.microsoftonline.com/") and std.mem.endsWith(u8, iss, "/v2.0"))
            return .{ .kind = .Microsoft };
        return parseAwsIss(iss);
    }

    /// regex `https://cognito-idp\.(?P<region>[^.]+)\.amazonaws\.com/(?P<tenant_id>[^/]+)` anywhere.
    fn parseAwsIss(s: []const u8) ?Provider {
        const head = "https://cognito-idp.";
        const mid = ".amazonaws.com/";
        var from: usize = 0;
        while (std.mem.indexOfPos(u8, s, from, head)) |at| : (from = at + 1) {
            const rstart = at + head.len;
            var rend = rstart;
            while (rend < s.len and s[rend] != '.') rend += 1;
            if (rend == rstart) continue;
            if (!std.mem.startsWith(u8, s[rend..], mid)) continue;
            const tstart = rend + mid.len;
            var tend = tstart;
            while (tend < s.len and s[tend] != '/') tend += 1;
            if (tend == tstart) continue;
            return .{ .kind = .AwsTenant, .region = s[rstart..rend], .tenant_id = s[tstart..tend] };
        }
        return null;
    }
};

pub const Chain = enum { mainnet, testnet, unknown };

/// Provider names fetched per chain (`default_zklogin_oauth_providers`); validators can override
/// the set in validator.yaml (`zklogin-oauth-providers`).
pub fn defaultProviderNames(chain: Chain) []const []const u8 {
    const prod = [_][]const u8{
        "Google",                                                                   "Facebook",
        "Twitch",                                                                   "Apple",
        "KarrierOne",                                                               "Credenza3",
        "Playtron",                                                                 "Onefc",
        "Threedos",                                                                 "AwsTenant-region:eu-west-3-tenant_id:eu-west-3_gGVCx53Es",
        "Arden",                                                                    "FanTV",
        "EveFrontier",                                                              "TestEveFrontier",
        "AwsTenant-region:ap-southeast-1-tenant_id:ap-southeast-1_2QQPyQXDz",       "AwsTenant-region:eu-north-1-tenant_id:eu-north-1_Bpct2JyBg",
        "AwsTenant-region:eu-north-1-tenant_id:eu-north-1_4HdQTpt3E",
    };
    const experimental = [_][]const u8{
        "Google",                                                                   "Facebook",
        "Twitch",                                                                   "Kakao",
        "Apple",                                                                    "Slack",
        "TestIssuer",                                                               "TestIssuerKey8192",
        "Microsoft",                                                                "KarrierOne",
        "Credenza3",                                                                "Playtron",
        "Threedos",                                                                 "Onefc",
        "FanTV",                                                                    "Arden",
        "AwsTenant-region:eu-west-3-tenant_id:eu-west-3_gGVCx53Es",                 "EveFrontier",
        "TestEveFrontier",                                                          "AwsTenant-region:ap-southeast-1-tenant_id:ap-southeast-1_2QQPyQXDz",
        "AwsTenant-region:eu-north-1-tenant_id:eu-north-1_Bpct2JyBg",               "AwsTenant-region:eu-north-1-tenant_id:eu-north-1_4HdQTpt3E",
    };
    return switch (chain) {
        .mainnet, .testnet => &prod,
        .unknown => &experimental,
    };
}

test "provider names, issuers and endpoints" {
    const g = Provider.fromName("Google").?;
    var buf: [256]u8 = undefined;
    const c = try g.config(&buf);
    try std.testing.expectEqualStrings("https://accounts.google.com", c.iss);
    try std.testing.expect(Provider.fromIss(c.iss).?.eql(g));
    try std.testing.expect(Provider.fromName("Nope") == null);

    const aws = Provider.fromName("AwsTenant-region:eu-west-3-tenant_id:eu-west-3_gGVCx53Es").?;
    try std.testing.expectEqualStrings("eu-west-3", aws.region);
    try std.testing.expectEqualStrings("eu-west-3_gGVCx53Es", aws.tenant_id);
    const ac = try aws.config(&buf);
    try std.testing.expectEqualStrings("https://cognito-idp.eu-west-3.amazonaws.com/eu-west-3_gGVCx53Es", ac.iss);
    try std.testing.expectEqualStrings("https://cognito-idp.eu-west-3.amazonaws.com/eu-west-3_gGVCx53Es/.well-known/jwks.json", ac.jwk_endpoint);
    const back = Provider.fromIss(ac.iss).?;
    try std.testing.expect(back.eql(aws));

    try std.testing.expect(Provider.fromIss("https://login.microsoftonline.com/abc/v2.0").?.kind == .Microsoft);
    try std.testing.expect(Provider.fromIss("https://example.com") == null);
    for (defaultProviderNames(.mainnet)) |n| try std.testing.expect(Provider.fromName(n) != null);
    for (defaultProviderNames(.unknown)) |n| try std.testing.expect(Provider.fromName(n) != null);
}
