//! Verdicts: protocol-visible outcomes of signature checks, as values (CONTRACTS.md 2.2).
//! `Reason` mirrors the Rust error at the point it is raised; `truthName` is the exact string the
//! truth tool (tools/truth/crypto-sig) writes for it.
const std = @import("std");

pub const Reason = enum {
    // fastcrypto primitives: "<stage>:<FastCryptoError variant>"
    pk_invalid_input,
    sig_invalid_input,
    sig_input_length_wrong,
    verify_invalid_signature,
    verify_invalid_input,
    verify_general_error,
    recover_general_opaque_error,
    recover_invalid_signature,
    recover_invalid_input,
    // GenericSignature::from_bytes failures: "parse:<FastCryptoError variant>"
    parse_invalid_input,
    parse_invalid_signature,
    parse_input_too_short,
    // ... and the other FastCryptoError values ZkLoginAuthenticator::from_bytes can return
    parse_input_too_long,
    parse_input_length_wrong,
    parse_invalid_proof,
    parse_general_error,
    // SuiErrorKind variants raised by user-signature and transaction-signature checks
    InvalidSignature,
    IncorrectSigner,
    /// zkLogin: the author is neither the unpadded nor (legacy flag on) the padded address
    InvalidAddress,
    KeyConversionError,
    UnsupportedFeatureError,
    SignerSignatureNumberMismatch,
    SignerSignatureAbsent,
    UserInputError,

    pub fn truthName(r: Reason) []const u8 {
        return switch (r) {
            .pk_invalid_input => "pk:InvalidInput",
            .sig_invalid_input => "sig:InvalidInput",
            .sig_input_length_wrong => "sig:InputLengthWrong",
            .verify_invalid_signature => "verify:InvalidSignature",
            .verify_invalid_input => "verify:InvalidInput",
            .verify_general_error => "verify:GeneralError",
            .recover_general_opaque_error => "recover:GeneralOpaqueError",
            .recover_invalid_signature => "recover:InvalidSignature",
            .recover_invalid_input => "recover:InvalidInput",
            .parse_invalid_input => "parse:InvalidInput",
            .parse_invalid_signature => "parse:InvalidSignature",
            .parse_input_too_short => "parse:InputTooShort",
            .parse_input_too_long => "parse:InputTooLong",
            .parse_input_length_wrong => "parse:InputLengthWrong",
            .parse_invalid_proof => "parse:InvalidProof",
            .parse_general_error => "parse:GeneralError",
            else => @tagName(r),
        };
    }
};

pub const Verdict = union(enum) {
    valid,
    invalid: Reason,

    pub fn truthName(v: Verdict) []const u8 {
        return switch (v) {
            .valid => "ok",
            .invalid => |r| r.truthName(),
        };
    }

    pub fn isValid(v: Verdict) bool {
        return v == .valid;
    }
};

test "truth names" {
    try std.testing.expectEqualStrings("ok", (Verdict{ .valid = {} }).truthName());
    try std.testing.expectEqualStrings("IncorrectSigner", (Verdict{ .invalid = .IncorrectSigner }).truthName());
    try std.testing.expectEqualStrings("verify:GeneralError", (Verdict{ .invalid = .verify_general_error }).truthName());
}
