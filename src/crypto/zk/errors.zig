//! Mirror of `fastcrypto::error::FastCryptoError` as the zk lane's functions return it. The
//! suites compare `debug()` with Rust's `format!("{:?}", e)` byte for byte.
const std = @import("std");

pub const Fail = union(enum) {
    none,
    invalid_input,
    invalid_proof,
    invalid_signature,
    input_length_wrong: usize,
    input_too_short: usize,
    input_too_long: usize,
    /// GeneralError with a fixed message.
    general: []const u8,
    /// GeneralError("JWK not found ({iss} - {kid})").
    jwk_not_found: struct { iss: []const u8, kid: []const u8 },

    /// Rust `{:?}` of the FastCryptoError value.
    pub fn debug(f: Fail, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (f) {
            .none => try w.writeAll("None"),
            .invalid_input => try w.writeAll("InvalidInput"),
            .invalid_proof => try w.writeAll("InvalidProof"),
            .invalid_signature => try w.writeAll("InvalidSignature"),
            .input_length_wrong => |n| try w.print("InputLengthWrong({d})", .{n}),
            .input_too_short => |n| try w.print("InputTooShort({d})", .{n}),
            .input_too_long => |n| try w.print("InputTooLong({d})", .{n}),
            .general => |m| {
                try w.writeAll("GeneralError(\"");
                try escapeDebug(w, m);
                try w.writeAll("\")");
            },
            .jwk_not_found => |j| {
                try w.writeAll("GeneralError(\"JWK not found (");
                try escapeDebug(w, j.iss);
                try w.writeAll(" - ");
                try escapeDebug(w, j.kid);
                try w.writeAll(")\")");
            },
        }
    }

    /// Rust `{}` (thiserror Display) of the FastCryptoError value: what sui-types puts in
    /// `SuiErrorKind::InvalidSignature { error: e.to_string() }`.
    pub fn display(f: Fail, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (f) {
            .none => try w.writeAll("None"),
            .invalid_input => try w.writeAll("Invalid value was given to the function"),
            .invalid_proof => try w.writeAll("Invalid proof was given to the function"),
            .invalid_signature => try w.writeAll("Invalid signature was given to the function"),
            .input_length_wrong => |n| try w.print("Expected input of length exactly {d}", .{n}),
            .input_too_short => |n| try w.print("Expected input of length at least {d}", .{n}),
            .input_too_long => |n| try w.print("Expected input of length at most {d}", .{n}),
            .general => |m| try w.print("General cryptographic error: {s}", .{m}),
            .jwk_not_found => |j| try w.print("General cryptographic error: JWK not found ({s} - {s})", .{ j.iss, j.kid }),
        }
    }

    pub fn debugAlloc(f: Fail, buf: []u8) []const u8 {
        var w: std.Io.Writer = .fixed(buf);
        f.debug(&w) catch return buf[0..w.end];
        return w.buffered();
    }
};

/// Rust `str::escape_debug` inside a Debug string literal (ASCII rules; other code points pass
/// through, which matches Rust for printable characters).
pub fn escapeDebug(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0 => try w.writeAll("\\0"),
        1...8, 11, 12, 14...31, 127 => try w.print("\\u{{{x}}}", .{c}),
        else => try w.writeByte(c),
    };
}
