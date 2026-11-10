//! Hand-written parts of the types module: wrappers whose Rust (De)Serialize validates more
//! than the serde-reflection shape shows. The rest of the types is generated into gen.zig.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const Reader = bcs.Reader;
const roaring = @import("roaring.zig");

/// A fixed-size byte string serialized as BCS bytes (length prefix N) inside a newtype struct:
/// Rust `Digest(#[serde_as(as = "Bytes")] [u8; 32])`. Decode rejects any other length.
pub fn ByteArray(comptime N: usize) type {
    return struct {
        @"0": [N]u8,
        const Self = @This();
        pub const bcs_min_wire = 1 + N;
        pub const bcs_byte_array = true;
        pub const bcs_newtype = true;

        fn read(r: *Reader) bcs.Error!*const [N]u8 {
            try r.enter();
            const n = try r.length();
            const b = try r.bytes(n);
            if (n != N) return error.InvalidValue;
            r.leave();
            return b[0..N];
        }
        pub fn bcsDecode(arena: Allocator, r: *Reader) bcs.DecodeError!Self {
            _ = arena;
            return .{ .@"0" = (try read(r)).* };
        }
        pub fn bcsSkip(r: *Reader) bcs.Error!void {
            _ = try read(r);
        }
        pub fn bcsEncode(self: *const Self, w: anytype) bcs.EncodeError!void {
            try w.uleb32(N);
            try w.bytes(&self.@"0");
        }
        pub fn bcsTree(self: *const Self, w: *std.Io.Writer) std.Io.Writer.Error!void {
            try bcs.tree.writeHex(w, &self.@"0");
        }
    };
}

pub const Digest = ByteArray(32);
pub const AuthorityPublicKeyBytes = ByteArray(96);

/// move_core_types::Identifier: a string that must match [a-zA-Z][a-zA-Z0-9_]* or _[a-zA-Z0-9_]+.
pub const Identifier = struct {
    @"0": []const u8,
    pub const bcs_min_wire = 1;
    pub const bcs_string = true;

    pub fn isValid(s: []const u8) bool {
        if (s.len == 0) return false;
        const c0 = s[0];
        const start_ok = std.ascii.isAlphabetic(c0) or (c0 == '_' and s.len > 1);
        if (!start_ok) return false;
        for (s[1..]) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_')) return false;
        return true;
    }
    fn read(r: *Reader) bcs.Error![]const u8 {
        const s = try bcs.readStr(r);
        if (!isValid(s)) return error.InvalidValue;
        return s;
    }
    pub fn bcsDecode(arena: Allocator, r: *Reader) bcs.DecodeError!Identifier {
        _ = arena;
        return .{ .@"0" = try read(r) };
    }
    pub fn bcsSkip(r: *Reader) bcs.Error!void {
        _ = try read(r);
    }
    pub fn bcsEncode(self: *const Identifier, w: anytype) bcs.EncodeError!void {
        try w.uleb32(@intCast(self.@"0".len));
        try w.bytes(self.@"0");
    }
    pub fn str(self: Identifier) []const u8 {
        return self.@"0";
    }
};

/// sui_types::base_types::SizeOneVec<T>: a Vec<T> on the wire that must hold exactly one item.
/// Rust decodes the whole Vec first and checks the length afterwards; so do we.
pub fn SizeOneVec(comptime T: type) type {
    return struct {
        items: []const T,
        const Self = @This();
        pub const bcs_min_wire = 1;

        pub fn element(self: *const Self) *const T {
            return &self.items[0];
        }
        pub fn bcsDecode(arena: Allocator, r: *Reader) bcs.DecodeError!Self {
            const items = try bcs.decodeFrom([]const T, arena, r);
            if (items.len != 1) return error.InvalidValue;
            return .{ .items = items };
        }
        pub fn bcsSkip(r: *Reader) bcs.Error!void {
            const start = r.at;
            _ = start;
            const n = try r.length();
            var i: usize = 0;
            while (i < n) : (i += 1) try bcs.skip(T, r);
            if (n != 1) return error.InvalidValue;
        }
        pub fn bcsEncode(self: *const Self, w: anytype) bcs.EncodeError!void {
            try bcs.encode([]const T, &self.items, w);
        }
        pub fn bcsTree(self: *const Self, w: *std.Io.Writer) std.Io.Writer.Error!void {
            try bcs.tree.render([]const T, &self.items, w);
        }
    };
}

// ---------------------------------------------------------------- structs with Rust-side checks

/// Encode and tree text of a plain struct whose type also carries decode hooks.
fn encodeFields(comptime T: type, v: *const T, w: anytype) bcs.EncodeError!void {
    inline for (@typeInfo(T).@"struct".field_names, @typeInfo(T).@"struct".field_types) |n, ft| try bcs.encode(ft, &@field(v.*, n), w);
}
fn treeFields(comptime T: type, v: *const T, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeByte('{');
    inline for (@typeInfo(T).@"struct".field_names, @typeInfo(T).@"struct".field_types, 0..) |n, ft, i| {
        if (i > 0) try w.writeByte(',');
        try bcs.tree.writeJsonStr(w, n);
        try w.writeByte(':');
        try bcs.tree.render(ft, &@field(v.*, n), w);
    }
    try w.writeByte('}');
}

/// std::time::Duration as serde (de)serializes it: struct { secs: u64, nanos: u32 }. Decode
/// rejects `secs + nanos / 1e9` overflowing u64 (serde `check_overflow`) and normalizes like
/// `Duration::new`, so a decoded value re-encodes to exactly what Rust re-encodes.
pub const Duration = struct {
    secs: u64,
    nanos: u32,
    pub const bcs_min_wire = 12;
    const nanos_per_sec: u32 = 1_000_000_000;

    fn read(r: *Reader) bcs.Error!Duration {
        try r.enter();
        const secs = try r.int(u64);
        const nanos = try r.int(u32);
        r.leave();
        const carry = std.math.add(u64, secs, nanos / nanos_per_sec) catch return error.InvalidValue;
        return .{ .secs = carry, .nanos = nanos % nanos_per_sec };
    }
    pub fn bcsDecode(arena: Allocator, r: *Reader) bcs.DecodeError!Duration {
        _ = arena;
        return read(r);
    }
    pub fn bcsSkip(r: *Reader) bcs.Error!void {
        _ = try read(r);
    }
    pub fn bcsEncode(self: *const Duration, w: anytype) bcs.EncodeError!void {
        try encodeFields(Duration, self, w);
    }
    pub fn bcsTree(self: *const Duration, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try treeFields(Duration, self, w);
    }
};

/// sui_types::object::ObjectPermissions bit rules (`ObjectPermissions::new`).
pub const object_permissions = struct {
    pub const immutable_usage: u64 = 1 << 0;
    pub const mutable_usage: u64 = 1 << 1;
    pub const mutable_bits: u64 = (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6);
    pub const all: u64 = mutable_bits | mutable_usage | immutable_usage;
    pub fn valid(bits: u64) bool {
        if (bits & ~all != 0) return false;
        return bits & mutable_bits == 0 or bits & mutable_usage != 0;
    }
};

/// sui_types::object::Party on the wire (`#[serde(try_from = "RawPartySerde")]`):
/// `{ default_permissions: ObjectPermissions, members: Vec<(SuiAddress, ObjectPermissions)> }`.
/// Every ObjectPermissions is checked as it is read (serde `try_from = "u64"`); after the whole
/// struct, members must be strictly increasing by address and the party must not be the
/// ConsensusAddressOwner shape (default NONE, exactly one member with ALL).
pub fn RawPartySerdeOf(comptime SuiAddress: type) type {
    return struct {
        default_permissions: u64,
        members: []const struct { SuiAddress, u64 },
        const Self = @This();
        pub const bcs_min_wire = 9;
        pub const bcs_party = true;

        fn perm(r: *Reader) bcs.Error!u64 {
            const p = try r.int(u64);
            if (!object_permissions.valid(p)) return error.InvalidValue;
            return p;
        }
        /// SuiAddress is a newtype of [u8; 32]: each member is 32 address bytes + 8 permission bytes.
        const stride = 32 + 8;
        comptime {
            std.debug.assert(@FieldType(SuiAddress, "0") == [32]u8);
        }

        const Checked = struct { default_permissions: u64, n: usize, raw: []const u8 };

        /// Validates one value at the cursor in Rust's order; returns the member bytes.
        fn check(r: *Reader) bcs.Error!Checked {
            try r.enter();
            const default_permissions = try perm(r);
            const n = try r.length();
            const start = r.at;
            var i: usize = 0;
            while (i < n) : (i += 1) {
                try bcs.skip(SuiAddress, r);
                _ = try perm(r);
            }
            r.leave();
            const raw = r.buf[start..r.at];
            var k: usize = 1;
            while (k < n) : (k += 1) {
                const prev = raw[(k - 1) * stride ..][0..32];
                const cur = raw[k * stride ..][0..32];
                if (std.mem.order(u8, prev, cur) != .lt) return error.InvalidValue;
            }
            if (default_permissions == 0 and n == 1 and std.mem.readInt(u64, raw[32..40], .little) == object_permissions.all) return error.InvalidValue;
            return .{ .default_permissions = default_permissions, .n = n, .raw = raw };
        }
        pub fn bcsDecode(arena: Allocator, r: *Reader) bcs.DecodeError!Self {
            const c = try check(r);
            const m = try arena.alloc(struct { SuiAddress, u64 }, c.n);
            for (m, 0..) |*e, j| {
                e.* = .{ .{ .@"0" = c.raw[j * stride ..][0..32].* }, std.mem.readInt(u64, c.raw[j * stride + 32 ..][0..8], .little) };
            }
            return .{ .default_permissions = c.default_permissions, .members = m };
        }
        pub fn bcsSkip(r: *Reader) bcs.Error!void {
            _ = try check(r);
        }
        pub fn bcsEncode(self: *const Self, w: anytype) bcs.EncodeError!void {
            try encodeFields(Self, self, w);
        }
        pub fn bcsTree(self: *const Self, w: *std.Io.Writer) std.Io.Writer.Error!void {
            try treeFields(Self, self, w);
        }
    };
}

/// sui_types::transaction::SenderSignedTransaction: decodes the whole struct, then rejects any
/// intent other than `Intent::sui_transaction()` (scope TransactionData, V0, app Sui), as the
/// hand-written Rust `Deserialize` does.
pub fn SenderSignedTransactionOf(comptime TransactionData: type) type {
    return struct {
        intent_message: IntentMessage(Intent, TransactionData),
        tx_signatures: []const GenericSignature,
        const Self = @This();
        pub const bcs_min_wire = 4;

        fn checkIntent(i: Intent) bcs.Error!void {
            if (!std.mem.eql(u8, &i.bytes(), &Intent.sui(.transaction_data).bytes())) return error.InvalidValue;
        }
        pub fn bcsDecode(arena: Allocator, r: *Reader) bcs.DecodeError!Self {
            try r.enter();
            const im = try bcs.decodeFrom(IntentMessage(Intent, TransactionData), arena, r);
            const sigs = try bcs.decodeFrom([]const GenericSignature, arena, r);
            r.leave();
            try checkIntent(im.intent);
            return .{ .intent_message = im, .tx_signatures = sigs };
        }
        pub fn bcsSkip(r: *Reader) bcs.Error!void {
            try r.enter();
            const s = r.at;
            try bcs.skip(IntentMessage(Intent, TransactionData), r);
            try bcs.skip([]const GenericSignature, r);
            r.leave();
            // IntentMessage is a struct, Intent its first field: the 3 intent bytes come first.
            const ib = r.buf[s..][0..3];
            if (!std.mem.eql(u8, ib, &Intent.sui(.transaction_data).bytes())) return error.InvalidValue;
        }
        pub fn bcsEncode(self: *const Self, w: anytype) bcs.EncodeError!void {
            try encodeFields(Self, self, w);
        }
        pub fn bcsTree(self: *const Self, w: *std.Io.Writer) std.Io.Writer.Error!void {
            try treeFields(Self, self, w);
        }
    };
}

/// sui_types::message_envelope::Envelope<T, S>: the signed data and its authority signature.
pub fn Envelope(comptime D: type, comptime S: type) type {
    return struct {
        data: D,
        auth_signature: S,
    };
}

/// shared_crypto::intent::IntentMessage<T>.
pub fn IntentMessage(comptime I: type, comptime V: type) type {
    return struct {
        intent: I,
        value: V,
    };
}

pub const IntentScope = enum(u8) {
    transaction_data = 0,
    transaction_effects = 1,
    checkpoint_summary = 2,
    personal_message = 3,
    sender_signed_transaction = 4,
    proof_of_possession = 5,
    header_digest = 6,
    bridge_event_unused = 7,
    consensus_block = 8,
    discovery_peers = 9,
};
pub const IntentVersion = enum(u8) { v0 = 0 };
pub const AppId = enum(u8) { sui = 0, narwhal = 1, consensus = 2 };

/// shared_crypto::intent::Intent: three bytes on the wire.
pub const Intent = struct {
    scope: IntentScope,
    version: IntentVersion,
    app_id: AppId,

    pub fn sui(scope: IntentScope) Intent {
        return .{ .scope = scope, .version = .v0, .app_id = .sui };
    }
    pub fn bytes(self: Intent) [3]u8 {
        return .{ @intFromEnum(self.scope), @intFromEnum(self.version), @intFromEnum(self.app_id) };
    }
};

// ---------------------------------------------------------------- signatures

/// sui_types::crypto::Signature: flag byte ++ signature ++ public key, serialized as BCS bytes.
/// Decode checks the flag and the exact length, as `Signature::from_bytes` does.
pub const SuiSignature = struct {
    @"0": []const u8,
    pub const bcs_min_wire = 1;
    pub const bcs_byte_string = true;

    pub fn valid(b: []const u8) bool {
        if (b.len == 0) return false;
        return switch (b[0]) {
            0 => b.len == 1 + 64 + 32,
            1, 2 => b.len == 1 + 64 + 33,
            7 => b.len == 1 + 3309 + 1952,
            else => false,
        };
    }
    fn read(r: *Reader) bcs.Error![]const u8 {
        const n = try r.length();
        const b = try r.bytes(n);
        if (!valid(b)) return error.InvalidValue;
        return b;
    }
    pub fn bcsDecode(arena: Allocator, r: *Reader) bcs.DecodeError!SuiSignature {
        _ = arena;
        return .{ .@"0" = try read(r) };
    }
    pub fn bcsSkip(r: *Reader) bcs.Error!void {
        _ = try read(r);
    }
    pub fn bcsEncode(self: *const SuiSignature, w: anytype) bcs.EncodeError!void {
        try w.uleb32(@intCast(self.@"0".len));
        try w.bytes(self.@"0");
    }
    pub fn bcsTree(self: *const SuiSignature, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.@"0".len == 0) return w.writeAll("[]");
        try bcs.tree.writeHex(w, self.@"0");
    }
};

/// A BN254 field element serialized as a decimal string (fastcrypto-zkp `Bn254FqElement` /
/// `Bn254FrElement`). Decode accepts exactly what ark-ff 0.4.2 `Fp::from_str` accepts: "0", or
/// ASCII digits with no leading zero, of ANY length. ark-ff accumulates the digits with field
/// arithmetic, so a value at or above the modulus is reduced, not rejected (its
/// `is_geq_modulus` check can never fire). Rust re-serializes the reduced value; deepwave keeps the
/// signature's raw bytes, so only acceptance has to match here.
pub fn FieldElement(comptime modulus: []const u8) type {
    return struct {
        @"0": []const u8,
        pub const bcs_min_wire = 1;
        pub const bcs_string = true;
        pub const modulus_decimal = modulus;

        pub fn valid(s: []const u8) bool {
            if (s.len == 0) return false;
            if (s.len > 1 and s[0] == '0') return false;
            for (s) |c| if (c < '0' or c > '9') return false;
            return true;
        }
        fn read(r: *Reader) bcs.Error![]const u8 {
            const s = try bcs.readStr(r);
            if (!valid(s)) return error.InvalidValue;
            return s;
        }
        pub fn bcsDecode(arena: Allocator, r: *Reader) bcs.DecodeError!@This() {
            _ = arena;
            return .{ .@"0" = try read(r) };
        }
        pub fn bcsSkip(r: *Reader) bcs.Error!void {
            _ = try read(r);
        }
        /// Rust re-renders the reduced value (ark-ff `from_str` reduces modulo the field
        /// prime, Display prints the canonical residue), so a decimal at or above the modulus
        /// does not re-encode to its input.
        pub fn bcsEncode(self: *const @This(), w: anytype) bcs.EncodeError!void {
            var buf: [80]u8 = undefined;
            const s = reduced(self.@"0", &buf);
            try w.uleb32(@intCast(s.len));
            try w.bytes(s);
        }
        /// The canonical decimal of `dec mod p` (`dec` must satisfy `valid`).
        pub fn reduced(dec: []const u8, buf: *[80]u8) []const u8 {
            if (dec.len < modulus.len or (dec.len == modulus.len and std.mem.order(u8, dec, modulus) == .lt)) return dec;
            const p = comptime blk: {
                @setEvalBranchQuota(1_000_000);
                break :blk std.fmt.parseInt(u256, modulus, 10) catch unreachable;
            };
            var acc: u256 = 0;
            for (dec) |c| {
                const t: u512 = @as(u512, acc) * 10 + (c - '0');
                acc = @intCast(t % p);
            }
            return std.fmt.bufPrint(buf, "{d}", .{acc}) catch unreachable;
        }
    };
}
pub const Bn254Fq = FieldElement("21888242871839275222246405745257275088696311157297823662689037894645226208583");
pub const Bn254Fr = FieldElement("21888242871839275222246405745257275088548364400416034343698204186575808495617");

pub const Claim = struct { value: bcs.String, indexMod4: u8 };
pub const ZkLoginProof = struct { a: []const Bn254Fq, b: []const []const Bn254Fq, c: []const Bn254Fq };
pub const ZkLoginInputs = struct {
    proofPoints: ZkLoginProof,
    issBase64Details: Claim,
    headerBase64: bcs.String,
    addressSeed: Bn254Fr,
};
/// sui_types::zk_login_authenticator::ZkLoginAuthenticator (BCS after the 0x05 flag byte).
pub const ZkLoginAuthenticator = struct {
    inputs: ZkLoginInputs,
    maxEpoch: u64,
    userSignature: SuiSignature,
};
/// sui_types::passkey_authenticator::RawPasskeyAuthenticator (BCS after the 0x06 flag byte).
pub const RawPasskeyAuthenticator = struct {
    authenticator_data: []const u8,
    client_data_json: bcs.String,
    user_signature: SuiSignature,
};

/// A base64-encoded `PublicKey` string (flag ++ key), as MultiSigLegacy stores its pk_map.
pub const Base64PublicKey = struct {
    @"0": []const u8,
    pub const bcs_min_wire = 1;
    pub const bcs_string = true;

    /// Longest decoded key: MLDSA65 flag ++ 1952 bytes.
    pub const max_decoded = 1 + 1952;

    pub fn valid(s: []const u8) bool {
        var buf: [max_decoded]u8 = undefined;
        return decodeCanonical(s, &buf) != null;
    }

    /// `PublicKey::decode_base64` (fastcrypto Base64: padded, strict) followed by the key's
    /// `as_ref`: returns flag ++ key bytes exactly as Rust re-encodes them, or null when Rust
    /// rejects the string. The SEC1 rules are those of the key parsers Rust calls:
    /// - Ed25519 (0): 32 bytes, kept as given.
    /// - Secp256k1 (1), `secp256k1::PublicKey::from_slice`: 33 bytes with prefix 02/03, or 65
    ///   bytes with prefix 04 or hybrid 06/07 (hybrid parity must match y). Re-encoded compressed.
    /// - Secp256r1 (2) and Passkey (6), p256 `VerifyingKey::try_from`: 33 bytes with prefix 02,
    ///   03 or compact 05, kept as given (fastcrypto caches the 33 input bytes); or 65 bytes with
    ///   prefix 04, re-encoded compressed. Hybrid is rejected.
    /// - MLDSA65 (7): 1952 bytes.
    /// Point validity (on-curve, x < p, ed25519 decompression) is not checked here: those
    /// vectors are tracked as `gap-lg-*` in testdata/rust_edge.txt (CONTRACTS.md 2.3).
    pub fn decodeCanonical(s: []const u8, buf: *[max_decoded]u8) ?[]const u8 {
        const dec = std.base64.standard.Decoder;
        const n = dec.calcSizeForSlice(s) catch return null;
        if (n == 0 or n > buf.len) return null;
        dec.decode(buf[0..n], s) catch return null;
        const b = buf[0..n];
        const k = b[1..];
        switch (b[0]) {
            0 => return if (k.len == 32) b else null,
            1 => switch (k.len) {
                33 => return if (k[0] == 2 or k[0] == 3) b else null,
                65 => {
                    const odd = k[64] & 1;
                    switch (k[0]) {
                        4 => {},
                        6, 7 => if (k[0] & 1 != odd) return null,
                        else => return null,
                    }
                    k[0] = 2 | odd;
                    return b[0 .. 1 + 33];
                },
                else => return null,
            },
            2, 6 => switch (k.len) {
                33 => return if (k[0] == 2 or k[0] == 3 or k[0] == 5) b else null,
                65 => {
                    if (k[0] != 4) return null;
                    k[0] = 2 | (k[64] & 1);
                    return b[0 .. 1 + 33];
                },
                else => return null,
            },
            7 => return if (k.len == 1952) b else null,
            else => return null,
        }
    }
    fn read(r: *Reader) bcs.Error![]const u8 {
        const s = try bcs.readStr(r);
        if (!valid(s)) return error.InvalidValue;
        return s;
    }
    pub fn bcsDecode(arena: Allocator, r: *Reader) bcs.DecodeError!Base64PublicKey {
        _ = arena;
        return .{ .@"0" = try read(r) };
    }
    pub fn bcsSkip(r: *Reader) bcs.Error!void {
        _ = try read(r);
    }
    pub fn bcsEncode(self: *const Base64PublicKey, w: anytype) bcs.EncodeError!void {
        try w.uleb32(@intCast(self.@"0".len));
        try w.bytes(self.@"0");
    }
};
pub const MultiSigPublicKeyLegacy = struct {
    pk_map: []const struct { Base64PublicKey, u8 },
    threshold: u16,
};
pub fn MultiSigLegacyOf(comptime CompressedSignature: type) type {
    return struct {
        sigs: []const CompressedSignature,
        bitmap: SuiBitmap,
        multisig_pk: MultiSigPublicKeyLegacy,
    };
}

/// sui_types::signature::GenericSignature: a newtype around the signature bytes (flag byte
/// first). Decode validates the flag and the structure of the inner value, the way
/// `GenericSignature::from_bytes` parses it, including MultiSig::init_and_validate and the
/// MultiSigLegacy bitmap and key rules. Still open (CONTRACTS.md 2.3): passkey client data,
/// zkLogin header/iss parsing and public key point validity.
pub const GenericSignature = struct {
    @"0": []const u8,
    pub const bcs_newtype = true;
    pub const bcs_min_wire = 2;

    pub const Scheme = enum { ed25519, secp256k1, secp256r1, multisig, multisig_legacy, zklogin, passkey, mldsa65 };

    /// Classifies and validates signature bytes. `null` for invalid input.
    pub fn classify(b: []const u8) ?Scheme {
        if (b.len == 0) return null;
        switch (b[0]) {
            0, 1, 2, 7 => {
                if (!SuiSignature.valid(b)) return null;
                return switch (b[0]) {
                    0 => .ed25519,
                    1 => .secp256k1,
                    2 => .secp256r1,
                    else => .mldsa65,
                };
            },
            3 => {
                // Rust: MultiSig::from_bytes (parse + init_and_validate), else MultiSigLegacy.
                if (multiSigOk(b[1..])) return .multisig;
                if (multiSigLegacyOk(b[1..])) return .multisig_legacy;
                return null;
            },
            5 => return if (innerOk(ZkLoginAuthenticator, b[1..])) .zklogin else null,
            6 => return if (innerOk(RawPasskeyAuthenticator, b[1..])) .passkey else null,
            else => return null,
        }
    }

    const max_signers = 10;
    const max_bitmap_value: u16 = 0b1111111111;

    /// MultiSigPublicKey::validate over `n` keys with their weights; `keys[i]` are comparable
    /// byte strings (equal bytes <=> equal PublicKey).
    fn pkValid(n: usize, keys: []const []const u8, weights: []const u8, threshold: u16) bool {
        if (threshold == 0 or n == 0 or n > max_signers) return false;
        var sum: u32 = 0;
        for (weights[0..n]) |w| {
            if (w == 0) return false;
            sum += w;
        }
        if (sum < threshold) return false;
        for (0..n) |i| for (i + 1..n) |j| if (std.mem.eql(u8, keys[i], keys[j])) return false;
        return true;
    }

    /// `MultiSig::from_bytes` after the flag byte: strict BCS parse, then `init_and_validate`.
    pub fn multiSigOk(inner: []const u8) bool {
        const gen = @import("gen.zig");
        var r = Reader.init(inner);
        const nsigs = r.length() catch return false;
        for (0..nsigs) |_| bcs.skip(gen.CompressedSignature, &r) catch return false;
        const bitmap = r.int(u16) catch return false;
        const npk = r.length() catch return false;
        var keys: [max_signers][]const u8 = undefined;
        var weights: [max_signers]u8 = undefined;
        for (0..npk) |i| {
            const start = r.at;
            bcs.skip(gen.PublicKey, &r) catch return false;
            const w = r.int(u8) catch return false;
            // More than 10 keys can never validate; the parse result no longer matters.
            if (i >= max_signers) return false;
            keys[i] = inner[start..r.at -| 1];
            weights[i] = w;
        }
        const threshold = r.int(u16) catch return false;
        r.finish() catch return false;
        if (nsigs > npk or nsigs == 0 or bitmap > max_bitmap_value) return false;
        return pkValid(npk, &keys, &weights, threshold);
    }

    /// `MultiSigLegacy::from_bytes` after the flag byte: strict BCS parse, then `validate`
    /// (bitmap values < 10, sig count, and the key list rules on the decoded keys).
    pub fn multiSigLegacyOk(inner: []const u8) bool {
        const gen = @import("gen.zig");
        var r = Reader.init(inner);
        const nsigs = r.length() catch return false;
        for (0..nsigs) |_| bcs.skip(gen.CompressedSignature, &r) catch return false;
        const bm = r.length() catch return false;
        const bm_bytes = r.bytes(bm) catch return false;
        const info = roaring.validateInfo(bm_bytes) catch return false;
        const npk = r.length() catch return false;
        var store: [max_signers][Base64PublicKey.max_decoded]u8 = undefined;
        var keys: [max_signers][]const u8 = undefined;
        var weights: [max_signers]u8 = undefined;
        for (0..npk) |i| {
            // More than 10 keys never validate, whatever they parse to.
            if (i >= max_signers) return false;
            const s = bcs.readStr(&r) catch return false;
            const w = r.int(u8) catch return false;
            const key = Base64PublicKey.decodeCanonical(s, &store[i]) orelse return false;
            // Rust compares decoded PublicKeys: flag ++ key in its re-encoded (compressed) form.
            keys[i] = key;
            weights[i] = w;
        }
        const threshold = r.int(u16) catch return false;
        r.finish() catch return false;
        if (info.max) |m| if (m >= max_signers) return false;
        if (nsigs > npk or nsigs == 0) return false;
        return pkValid(npk, &keys, &weights, threshold);
    }

    /// The bytes Rust re-serializes for these (valid) signature bytes: `GenericSignature`'s
    /// `AsRef` re-encodes the parsed value. Differs from the input only for MultiSigLegacy (the
    /// roaring bitmap is rebuilt as array containers) and zkLogin (decimals reduced mod p).
    /// Returns `sig` itself when nothing changes; otherwise memory comes from `a`.
    pub fn canonical(a: Allocator, sig: []const u8) bcs.DecodeError![]const u8 {
        const gen = @import("gen.zig");
        switch (classify(sig) orelse return error.InvalidValue) {
            .multisig_legacy => {
                // Rust re-serializes the parsed value: the roaring bitmap as array containers
                // and every key as base64 of its re-encoded bytes (SEC1 uncompressed -> compressed).
                // Keys only shrink; the bitmap can grow (a run container expands to an array).
                const inner = sig[1..];
                var r = Reader.init(inner);
                const nsigs = try r.length();
                for (0..nsigs) |_| try bcs.skip(gen.CompressedSignature, &r);
                const head_end = r.at;
                const bm = try r.bytes(try r.length());
                var tmp: [roaring.max_canonical]u8 = undefined;
                const cb = roaring.canonical(bm, &tmp) catch return error.InvalidValue;
                var out = try a.alloc(u8, sig.len + 5 + cb.len);
                var w = bcs.Writer.init(out);
                w.bytes(sig[0..1]) catch unreachable;
                w.bytes(inner[0..head_end]) catch unreachable;
                w.uleb32(@intCast(cb.len)) catch unreachable;
                w.bytes(cb) catch unreachable;
                const npk = try r.length();
                w.uleb32(@intCast(npk)) catch unreachable;
                var kbuf: [Base64PublicKey.max_decoded]u8 = undefined;
                var sbuf: [std.base64.standard.Encoder.calcSize(Base64PublicKey.max_decoded)]u8 = undefined;
                for (0..npk) |_| {
                    const s = try bcs.readStr(&r);
                    const key = Base64PublicKey.decodeCanonical(s, &kbuf) orelse return error.InvalidValue;
                    const enc = std.base64.standard.Encoder.encode(&sbuf, key);
                    w.uleb32(@intCast(enc.len)) catch unreachable;
                    w.bytes(enc) catch unreachable;
                    w.bytes(&.{try r.int(u8)}) catch unreachable;
                }
                w.bytes(inner[r.at..]) catch unreachable;
                out = out[0..w.at];
                if (std.mem.eql(u8, out, sig)) {
                    a.free(out);
                    return sig;
                }
                return out;
            },
            .zklogin => {
                const z = try bcs.decode(ZkLoginAuthenticator, a, sig[1..]);
                const enc = try bcs.encodeAlloc(ZkLoginAuthenticator, a, &z);
                if (std.mem.eql(u8, enc, sig[1..])) return sig;
                const out = try a.alloc(u8, 1 + enc.len);
                out[0] = sig[0];
                @memcpy(out[1..], enc);
                return out;
            },
            else => return sig,
        }
    }

    fn innerOk(comptime T: type, inner: []const u8) bool {
        var r = Reader.init(inner);
        bcs.skip(T, &r) catch return false;
        return r.at == inner.len;
    }

    fn read(r: *Reader) bcs.Error![]const u8 {
        try r.enter();
        const n = try r.length();
        const b = try r.bytes(n);
        if (classify(b) == null) return error.InvalidValue;
        r.leave();
        return b;
    }
    pub fn bcsDecode(arena: Allocator, r: *Reader) bcs.DecodeError!GenericSignature {
        _ = arena;
        return .{ .@"0" = try read(r) };
    }
    pub fn bcsSkip(r: *Reader) bcs.Error!void {
        _ = try read(r);
    }
    pub fn bcsEncode(self: *const GenericSignature, w: anytype) bcs.EncodeError!void {
        try w.uleb32(@intCast(self.@"0".len));
        try w.bytes(self.@"0");
    }
    pub fn bcsTree(self: *const GenericSignature, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.@"0".len == 0) return w.writeAll("[]");
        try bcs.tree.writeHex(w, self.@"0");
    }
};

/// A serialized RoaringBitmap carried as BCS bytes (`SuiBitmap`): decode validates the bitmap as
/// the roaring crate and sui's cardinality cap do. Keeps the bytes (zero-copy).
pub const SuiBitmap = struct {
    @"0": []const u8,
    pub const bcs_min_wire = 1;
    pub const bcs_byte_string = true;

    fn read(r: *Reader) bcs.Error![]const u8 {
        const n = try r.length();
        const b = try r.bytes(n);
        _ = roaring.validate(b) catch return error.InvalidValue;
        return b;
    }
    pub fn bcsDecode(arena: Allocator, r: *Reader) bcs.DecodeError!SuiBitmap {
        _ = arena;
        return .{ .@"0" = try read(r) };
    }
    pub fn bcsSkip(r: *Reader) bcs.Error!void {
        _ = try read(r);
    }
    pub fn bcsEncode(self: *const SuiBitmap, w: anytype) bcs.EncodeError!void {
        try w.uleb32(@intCast(self.@"0".len));
        try w.bytes(self.@"0");
    }
    pub fn bcsTree(self: *const SuiBitmap, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.@"0".len == 0) return w.writeAll("[]");
        try bcs.tree.writeHex(w, self.@"0");
    }
};

test "identifier rules" {
    try std.testing.expect(Identifier.isValid("coin"));
    try std.testing.expect(Identifier.isValid("_x"));
    try std.testing.expect(Identifier.isValid("A1_b"));
    try std.testing.expect(!Identifier.isValid("_"));
    try std.testing.expect(!Identifier.isValid("1a"));
    try std.testing.expect(!Identifier.isValid(""));
    try std.testing.expect(!Identifier.isValid("a-b"));
}

test "digest byte array wire form" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var raw: [33]u8 = undefined;
    raw[0] = 32;
    @memset(raw[1..], 0xab);
    const d = try bcs.decode(Digest, a, &raw);
    try std.testing.expectEqual(@as(u8, 0xab), d.@"0"[31]);
    raw[0] = 31;
    try std.testing.expectError(error.InvalidValue, bcs.decode(Digest, a, raw[0..32]));
}
