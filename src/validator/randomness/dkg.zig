//! fastcrypto-tbls `dkg_v1` over BLS12-381 G2 (the instantiation Sui 1.83.1 uses: `PkG = EncG =
//! G2Element`): the weighted DKG with verifiable secret sharing, ECIES encrypted shares,
//! complaints through confirmations, and the read-only `Observer`.
//!
//! Flow (docs/VALIDATOR-DESIGN.md 5.5): every party deals a `Message` (its VSS commitment and the
//! encrypted shares); on receipt `processMessage` checks and decrypts; once enough weight of
//! messages has been processed `merge` fixes the used set and yields the `Confirmation` (with
//! complaints for bad shares); `complete` takes the used messages plus 2t-1 weight of
//! confirmations, drops dealers that were validly accused, and aggregates the shares into the
//! `Output` (the VSS public polynomial whose c0 is the beacon public key, and this party's shares).
//!
//! Memory: every value that owns data is an `Owned(T)` with its own arena, built by `create*`/
//! `decode*`/`clone`. The functions never panic on input.
const std = @import("std");
const group = @import("group.zig");
const wire = @import("wire.zig");
const oracle = @import("oracle.zig");
const nizk = @import("nizk.zig");
const ecies = @import("ecies.zig");
const poly = @import("poly.zig");
const nodes_mod = @import("nodes.zig");
const Scalar = group.Scalar;
const G2 = group.G2;
const G2P = group.G2P;
const Nodes = nodes_mod.Nodes;
const PartyId = nodes_mod.PartyId;
pub const Share = poly.Share;

/// Upper bound on a serialized message or confirmation (DKG_MESSAGES_MAX_SIZE).
pub const messages_max_size = 400_000;
/// A sanity bound on vss polynomial length when decoding (t <= total_weight / 2 <= 32767).
pub const max_poly_len = 32768;

pub const Error = error{
    InvalidInput,
    InvalidMessage,
    NotEnoughInputs,
    IgnoredMessage,
    GeneralError,
} || wire.Error || oracle.RandomOracle.Error || ecies.Error || poly.Error || nodes_mod.Error;

pub fn Owned(comptime T: type) type {
    return struct {
        arena: std.heap.ArenaAllocator,
        value: T,
        pub fn deinit(self: *@This()) void {
            self.arena.deinit();
        }
    };
}

// ---------------------------------------------------------------------------------------------
// wire types

pub const Message = struct {
    sender: PartyId,
    vss_pk: []const G2P,
    encrypted_shares: ecies.MultiRecipientEncryption,

    pub fn encode(self: *const Message, w: *wire.Writer) wire.Error!void {
        try w.u16_(self.sender);
        try w.uleb(self.vss_pk.len);
        for (self.vss_pk) |p| try w.g2(p);
        try self.encrypted_shares.encode(w);
    }

    pub fn decodeFrom(arena: std.mem.Allocator, r: *wire.Reader) wire.Error!Message {
        const sender = try r.u16_();
        const n = try r.seqLen(96);
        if (n > max_poly_len) return error.TooLarge;
        const vss = try arena.alloc(G2P, n);
        for (vss) |*p| p.* = try r.g2();
        return .{ .sender = sender, .vss_pk = vss, .encrypted_shares = try ecies.MultiRecipientEncryption.decode(arena, r) };
    }

    pub fn clone(self: *const Message, arena: std.mem.Allocator) std.mem.Allocator.Error!Message {
        return .{
            .sender = self.sender,
            .vss_pk = try arena.dupe(G2P, self.vss_pk),
            .encrypted_shares = try self.encrypted_shares.clone(arena),
        };
    }
};

pub const Complaint = struct {
    accused_sender: PartyId,
    proof: ecies.RecoveryPackage,

    pub fn encode(self: *const Complaint, w: *wire.Writer) wire.Error!void {
        try w.u16_(self.accused_sender);
        try self.proof.encode(w);
    }
    pub fn decode(r: *wire.Reader) wire.Error!Complaint {
        const a = try r.u16_();
        return .{ .accused_sender = a, .proof = try ecies.RecoveryPackage.decode(r) };
    }
};

pub const Confirmation = struct {
    sender: PartyId,
    complaints: []const Complaint,

    pub fn encode(self: *const Confirmation, w: *wire.Writer) wire.Error!void {
        try w.u16_(self.sender);
        try w.uleb(self.complaints.len);
        for (self.complaints) |*c| try c.encode(w);
    }

    pub fn decodeFrom(arena: std.mem.Allocator, r: *wire.Reader) wire.Error!Confirmation {
        const sender = try r.u16_();
        const n = try r.seqLen(2 + 96 + 224);
        const cs = try arena.alloc(Complaint, n);
        for (cs) |*c| c.* = try Complaint.decode(r);
        return .{ .sender = sender, .complaints = cs };
    }

    pub fn clone(self: *const Confirmation, arena: std.mem.Allocator) std.mem.Allocator.Error!Confirmation {
        return .{ .sender = self.sender, .complaints = try arena.dupe(Complaint, self.complaints) };
    }
};

pub const ProcessedMessage = struct {
    message: Message,
    shares: []const Share,
    complaint: ?Complaint,

    pub fn encode(self: *const ProcessedMessage, w: *wire.Writer) wire.Error!void {
        try self.message.encode(w);
        try w.uleb(self.shares.len);
        for (self.shares) |s| {
            try w.u16_(s.index);
            try w.scalar(s.value);
        }
        if (self.complaint) |*c| {
            try w.u8_(1);
            try c.encode(w);
        } else try w.u8_(0);
    }

    pub fn decodeFrom(arena: std.mem.Allocator, r: *wire.Reader) wire.Error!ProcessedMessage {
        const m = try Message.decodeFrom(arena, r);
        const n = try r.seqLen(34);
        const shares = try arena.alloc(Share, n);
        for (shares) |*s| {
            const idx = try r.u16_();
            if (idx == 0) return error.InvalidEncoding;
            s.* = .{ .index = idx, .value = try r.scalar() };
        }
        const complaint: ?Complaint = switch (try r.u8_()) {
            0 => null,
            1 => try Complaint.decode(r),
            else => return error.InvalidEncoding,
        };
        return .{ .message = m, .shares = shares, .complaint = complaint };
    }

    pub fn clone(self: *const ProcessedMessage, arena: std.mem.Allocator) std.mem.Allocator.Error!ProcessedMessage {
        return .{
            .message = try self.message.clone(arena),
            .shares = try arena.dupe(Share, self.shares),
            .complaint = self.complaint,
        };
    }
};

/// `UsedProcessedMessages`: the messages the merge fixed, in sender order.
pub const UsedProcessedMessages = struct {
    items: []const ProcessedMessage,

    pub fn encode(self: *const UsedProcessedMessages, w: *wire.Writer) wire.Error!void {
        try w.uleb(self.items.len);
        for (self.items) |*m| try m.encode(w);
    }

    pub fn decodeFrom(arena: std.mem.Allocator, r: *wire.Reader) wire.Error!UsedProcessedMessages {
        const n = try r.seqLen(2);
        const items = try arena.alloc(ProcessedMessage, n);
        for (items) |*m| m.* = try ProcessedMessage.decodeFrom(arena, r);
        return .{ .items = items };
    }
};

/// DKG output: the public VSS polynomial (c0 = the beacon public key) and, for a party with
/// weight that kept all its shares, its shares (ascending index).
pub const Output = struct {
    vss_pk: []const G2P,
    shares: ?[]const Share,

    pub fn publicKey(self: *const Output) G2P {
        return if (self.vss_pk.len == 0) G2P.infinity else self.vss_pk[0];
    }

    /// Local persistence form: Vec<G2> vss_pk, Option<Vec<(u16, Scalar)>> shares.
    pub fn encode(self: *const Output, w: *wire.Writer) wire.Error!void {
        try w.uleb(self.vss_pk.len);
        for (self.vss_pk) |p| try w.g2(p);
        if (self.shares) |sh| {
            try w.u8_(1);
            try w.uleb(sh.len);
            for (sh) |s| {
                try w.u16_(s.index);
                try w.scalar(s.value);
            }
        } else try w.u8_(0);
    }

    pub fn decodeFrom(arena: std.mem.Allocator, r: *wire.Reader) wire.Error!Output {
        const n = try r.seqLen(96);
        if (n > max_poly_len) return error.TooLarge;
        if (n == 0) return error.InvalidEncoding;
        const vss = try arena.alloc(G2P, n);
        for (vss) |*p| p.* = try r.g2();
        var shares: ?[]Share = null;
        switch (try r.u8_()) {
            0 => {},
            1 => {
                const k = try r.seqLen(34);
                const sh = try arena.alloc(Share, k);
                for (sh) |*s| {
                    const idx = try r.u16_();
                    if (idx == 0) return error.InvalidEncoding;
                    s.* = .{ .index = idx, .value = try r.scalar() };
                }
                shares = sh;
            },
            else => return error.InvalidEncoding,
        }
        return .{ .vss_pk = vss, .shares = shares };
    }
};

/// Decode helpers returning Owned values (copying `bytes` is not needed: data is re-allocated).
pub fn decodeMessage(gpa: std.mem.Allocator, bytes: []const u8) Error!Owned(Message) {
    if (bytes.len > messages_max_size) return error.TooLarge;
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    var r = wire.Reader.init(bytes);
    const m = try Message.decodeFrom(arena.allocator(), &r);
    try r.finish();
    return .{ .arena = arena, .value = m };
}

pub fn decodeConfirmation(gpa: std.mem.Allocator, bytes: []const u8) Error!Owned(Confirmation) {
    if (bytes.len > messages_max_size) return error.TooLarge;
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    var r = wire.Reader.init(bytes);
    const c = try Confirmation.decodeFrom(arena.allocator(), &r);
    try r.finish();
    return .{ .arena = arena, .value = c };
}

/// VersionedDkgMessage / VersionedDkgConfirmation: ULEB variant (0 = deprecated empty V0, 1 = V1).
pub fn encodeVersionedMessage(gpa: std.mem.Allocator, m: *const Message) Error![]u8 {
    var w = wire.Writer.init(gpa);
    errdefer w.deinit();
    try w.u8_(1);
    try m.encode(&w);
    return w.toOwnedSlice();
}

pub fn encodeVersionedConfirmation(gpa: std.mem.Allocator, c: *const Confirmation) Error![]u8 {
    var w = wire.Writer.init(gpa);
    errdefer w.deinit();
    try w.u8_(1);
    try c.encode(&w);
    return w.toOwnedSlice();
}

pub const VersionedMessage = union(enum) { v0, v1: Owned(Message) };
pub const VersionedConfirmation = union(enum) { v0, v1: Owned(Confirmation) };

pub fn decodeVersionedMessage(gpa: std.mem.Allocator, bytes: []const u8) Error!VersionedMessage {
    if (bytes.len == 0) return error.Truncated;
    return switch (bytes[0]) {
        0 => if (bytes.len == 1) .v0 else error.TrailingBytes,
        1 => .{ .v1 = try decodeMessage(gpa, bytes[1..]) },
        else => error.InvalidEncoding,
    };
}

pub fn decodeVersionedConfirmation(gpa: std.mem.Allocator, bytes: []const u8) Error!VersionedConfirmation {
    if (bytes.len == 0) return error.Truncated;
    return switch (bytes[0]) {
        0 => if (bytes.len == 1) .v0 else error.TrailingBytes,
        1 => .{ .v1 = try decodeConfirmation(gpa, bytes[1..]) },
        else => error.InvalidEncoding,
    };
}

// ---------------------------------------------------------------------------------------------
// shared checks

fn encryptionRo(ro: *const oracle.RandomOracle, sender: PartyId) oracle.RandomOracle.Error!oracle.RandomOracle {
    return ro.extendFmt("encs {}", .{sender});
}

fn recoveryRo(ro: *const oracle.RandomOracle, accuser: PartyId, accused: PartyId) oracle.RandomOracle.Error!oracle.RandomOracle {
    return ro.extendFmt("recovery of {} received from {}", .{ accuser, accused });
}

/// `Message::sanity_check`.
pub fn sanityCheck(msg: *const Message, nodes: *const Nodes, t: u16, ro: *const oracle.RandomOracle) Error!void {
    const node = nodes.nodeOf(msg.sender) catch return error.InvalidMessage;
    if (node.weight == 0) return error.InvalidMessage;
    if (@as(usize, t) != poly.degreeBound(msg.vss_pk.len) + 1) return error.InvalidMessage;
    if (msg.vss_pk.len == 0 or group.g2IsZero(msg.vss_pk[0])) return error.InvalidMessage;
    if (nodes.numNodes() != msg.encrypted_shares.encs.len) return error.InvalidMessage;
    const ero = try encryptionRo(ro, msg.sender);
    msg.encrypted_shares.verify(&ero) catch return error.InvalidMessage;
}

/// Decrypted shares are `BCS(Vec<Scalar>)`; null when malformed.
fn parseShares(arena: std.mem.Allocator, bytes: []const u8) ?[]const Scalar {
    var r = wire.Reader.init(bytes);
    const n = r.seqLen(32) catch return null;
    const out = arena.alloc(Scalar, n) catch return null;
    for (out) |*s| s.* = r.scalar() catch return null;
    r.finish() catch return null;
    return out;
}

/// `Party::check_complaint_proof`: true when the COMPLAINT IS VALID (Rust returns Ok(()) in that
/// case, and an error when the recovery package is bad or the accused shares were fine).
fn complaintIsValid(
    scratch: std.mem.Allocator,
    nodes: *const Nodes,
    ro: *const oracle.RandomOracle,
    complaint: *const Complaint,
    accuser: PartyId,
    related: *const Message,
    rng: std.Random,
) bool {
    const accuser_node = nodes.nodeOf(accuser) catch return false;
    const rec_ro = recoveryRo(ro, accuser, complaint.accused_sender) catch return false;
    const enc_ro = encryptionRo(ro, complaint.accused_sender) catch return false;
    const buffer = related.encrypted_shares.decryptWithRecoveryPackage(
        scratch,
        &complaint.proof,
        &rec_ro,
        &enc_ro,
        accuser_node.pk,
        accuser,
    ) catch return false;
    const shares = parseShares(scratch, buffer) orelse return true; // undecodable shares: complaint valid
    const range = nodes.shareRange(accuser) catch return false;
    if (shares.len != range.count) return true;
    const evals = scratch.alloc(Share, shares.len) catch return false;
    for (shares, evals, 0..) |s, *e, i| e.* = .{ .index = range.first + @as(u16, @intCast(i)), .value = s };
    poly.verifyPolyEvals(scratch, evals, related.vss_pk, rng) catch return true;
    return false; // shares verify: the complaint is false
}

/// The common part of `process_confirmations` (Party and Observer): returns, per party id, whether
/// the party's message is excluded. NotEnoughInputs until 2t-1 weight of confirmations is in.
fn processConfirmations(
    gpa: std.mem.Allocator,
    nodes: *const Nodes,
    t: u16,
    ro: *const oracle.RandomOracle,
    used: []const *const Message,
    confirmations: []const *const Confirmation,
    rng: std.Random,
) Error![]bool {
    var scratch_state = std.heap.ArenaAllocator.init(gpa);
    defer scratch_state.deinit();
    const scratch = scratch_state.allocator();
    const required: u32 = 2 * @as(u32, t) - 1;

    // ignore invalid senders and zero weights, one confirmation per sender
    var kept: std.ArrayList(*const Confirmation) = .empty;
    defer kept.deinit(gpa);
    var total: u32 = 0;
    const seen = try gpa.alloc(bool, nodes.numNodes());
    defer gpa.free(seen);
    @memset(seen, false);
    for (confirmations) |c| {
        const w = nodes.weightOf(c.sender) catch continue;
        if (w == 0 or seen[c.sender]) continue;
        seen[c.sender] = true;
        try kept.append(gpa, c);
        total += w;
    }
    if (total < required) return error.NotEnoughInputs;

    const by_sender = try gpa.alloc(?*const Message, nodes.numNodes());
    defer gpa.free(by_sender);
    @memset(by_sender, null);
    for (used) |m| if (m.sender < by_sender.len) {
        by_sender[m.sender] = m;
    };

    const excluded = try gpa.alloc(bool, nodes.numNodes());
    errdefer gpa.free(excluded);
    @memset(excluded, false);
    outer: for (kept.items) |m2| {
        for (m2.complaints) |*complaint| {
            const accused = complaint.accused_sender;
            const accuser = m2.sender;
            const valid = if (accused < by_sender.len and by_sender[accused] != null)
                complaintIsValid(scratch, nodes, ro, complaint, accuser, by_sender[accused].?, rng)
            else
                false;
            if (valid) {
                excluded[accused] = true; // continue with this accuser's other complaints
            } else {
                excluded[accuser] = true; // ignore the accuser from now on
                continue :outer;
            }
            _ = scratch_state.reset(.retain_capacity);
        }
    }
    var any = false;
    for (used) |m| {
        if (m.sender < excluded.len and !excluded[m.sender]) any = true;
    }
    if (!any) return error.GeneralError;
    return excluded;
}

// ---------------------------------------------------------------------------------------------
// Party

pub const Party = struct {
    id: PartyId,
    nodes: *const Nodes,
    t: u16,
    ro: oracle.RandomOracle,
    enc_sk: Scalar,
    vss_sk: []Scalar,
    secret_arena: std.heap.ArenaAllocator,

    /// `Party::new`: t <= total_weight / 2, my ECIES public key must be one of the nodes.
    pub fn init(
        gpa: std.mem.Allocator,
        enc_sk: Scalar,
        nodes: *const Nodes,
        t: u16,
        ro: oracle.RandomOracle,
        rng: std.Random,
    ) Error!Party {
        if (t > nodes.total_weight / 2) return error.InvalidInput;
        if (t > nodes.total_weight or t == 0) return error.InvalidInput;
        const enc_pk = group.mulSecret(G2, group.g2Generator(), enc_sk);
        var my: ?PartyId = null;
        for (nodes.nodes) |n| {
            if (n.pk.eql(enc_pk)) {
                my = n.id;
                break;
            }
        }
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const sk = try poly.randPrivate(arena.allocator(), t - 1, rng);
        return .{ .id = my orelse return error.InvalidInput, .nodes = nodes, .t = t, .ro = ro, .enc_sk = enc_sk, .vss_sk = sk, .secret_arena = arena };
    }

    pub fn deinit(self: *Party) void {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.vss_sk));
        self.enc_sk = Scalar.zero;
        self.secret_arena.deinit();
    }

    /// `create_message`: IgnoredMessage when this party has weight zero.
    pub fn createMessage(self: *const Party, gpa: std.mem.Allocator, rng: std.Random) Error!Owned(Message) {
        const node = try self.nodes.nodeOf(self.id);
        if (node.weight == 0) return error.IgnoredMessage;
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        const vss_pk = try poly.commit(a, self.vss_sk);
        const ero = try encryptionRo(&self.ro, self.id);
        const recips = try a.alloc(ecies.MultiRecipientEncryption.Recipient, self.nodes.numNodes());
        for (self.nodes.nodes, recips) |n, *rc| {
            const range = try self.nodes.shareRange(n.id);
            var w = wire.Writer.init(a);
            try w.uleb(range.count);
            var k: u16 = 0;
            while (k < range.count) : (k += 1) {
                try w.scalar(poly.evalPrivate(self.vss_sk, range.first + k));
            }
            rc.* = .{ .pk = n.pk, .msg = w.buf.items };
        }
        const enc = try ecies.MultiRecipientEncryption.encrypt(a, recips, &ero, rng);
        return .{ .arena = arena, .value = .{ .sender = self.id, .vss_pk = vss_pk, .encrypted_shares = enc } };
    }

    /// `process_message`: sanity check (error: ignore the message), decrypt, verify shares;
    /// a message with bad shares yields a processed message carrying a complaint.
    pub fn processMessage(self: *const Party, gpa: std.mem.Allocator, message: *const Message, rng: std.Random) Error!Owned(ProcessedMessage) {
        try sanityCheck(message, self.nodes, self.t, &self.ro);
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        const owned_msg = try message.clone(a);
        const my_range = try self.nodes.shareRange(self.id);
        const eros = try encryptionRo(&self.ro, message.sender);
        var scratch_state = std.heap.ArenaAllocator.init(gpa);
        defer scratch_state.deinit();
        const scratch = scratch_state.allocator();
        const buffer = try message.encrypted_shares.decrypt(scratch, self.enc_sk, &eros, self.id);

        const decrypted = parseShares(scratch, buffer);
        const bad = decrypted == null or decrypted.?.len != my_range.count;
        var shares_ok = false;
        var evals: []const Share = &.{};
        if (!bad) {
            const ev = try a.alloc(Share, decrypted.?.len);
            evals = ev;
            for (decrypted.?, ev, 0..) |s, *e, i| e.* = .{ .index = my_range.first + @as(u16, @intCast(i)), .value = s };
            shares_ok = if (poly.verifyPolyEvals(scratch, evals, message.vss_pk, rng)) true else |_| false;
        }
        if (bad or !shares_ok) {
            const rro = try recoveryRo(&self.ro, self.id, message.sender);
            const complaint: Complaint = .{
                .accused_sender = message.sender,
                .proof = message.encrypted_shares.createRecoveryPackage(self.enc_sk, &rro, rng),
            };
            return .{ .arena = arena, .value = .{ .message = owned_msg, .shares = &.{}, .complaint = complaint } };
        }
        return .{ .arena = arena, .value = .{ .message = owned_msg, .shares = evals, .complaint = null } };
    }

    pub const Merged = struct { confirmation: Owned(Confirmation), used: Owned(UsedProcessedMessages) };

    /// `merge`: `processed` in ascending sender order, one per sender. NotEnoughInputs until the
    /// weight of the senders reaches t.
    pub fn merge(self: *const Party, gpa: std.mem.Allocator, processed: []const *const ProcessedMessage) Error!Merged {
        var total: u32 = 0;
        for (processed) |m| total += try self.nodes.weightOf(m.message.sender);
        if (total < self.t) return error.NotEnoughInputs;
        var all_complaints = true;
        for (processed) |m| if (m.complaint == null) {
            all_complaints = false;
        };
        if (all_complaints) return error.GeneralError;

        var carena = std.heap.ArenaAllocator.init(gpa);
        errdefer carena.deinit();
        const ca = carena.allocator();
        var complaints: std.ArrayList(Complaint) = .empty;
        for (processed) |m| if (m.complaint) |c| try complaints.append(ca, c);
        const conf: Confirmation = .{ .sender = self.id, .complaints = try complaints.toOwnedSlice(ca) };

        var uarena = std.heap.ArenaAllocator.init(gpa);
        errdefer uarena.deinit();
        const ua = uarena.allocator();
        const items = try ua.alloc(ProcessedMessage, processed.len);
        for (processed, items) |m, *d| d.* = try m.clone(ua);
        return .{
            .confirmation = .{ .arena = carena, .value = conf },
            .used = .{ .arena = uarena, .value = .{ .items = items } },
        };
    }

    /// `complete`: NotEnoughInputs until 2t-1 weight of confirmations.
    pub fn complete(
        self: *const Party,
        gpa: std.mem.Allocator,
        used: *const UsedProcessedMessages,
        confirmations: []const *const Confirmation,
        rng: std.Random,
    ) Error!Owned(Output) {
        const msgs = try gpa.alloc(*const Message, used.items.len);
        defer gpa.free(msgs);
        for (used.items, msgs) |*m, *d| d.* = &m.message;
        const excluded = try processConfirmations(gpa, self.nodes, self.t, &self.ro, msgs, confirmations, rng);
        defer gpa.free(excluded);
        return self.aggregate(gpa, used, excluded);
    }

    fn aggregate(self: *const Party, gpa: std.mem.Allocator, used: *const UsedProcessedMessages, excluded: []const bool) Error!Owned(Output) {
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        const my_range = try self.nodes.shareRange(self.id);
        const final = try a.alloc(Share, my_range.count);
        for (final, 0..) |*s, i| s.* = .{ .index = my_range.first + @as(u16, @intCast(i)), .value = Scalar.zero };
        var vss: []const G2P = &.{G2P.infinity};
        var has_invalid_share = false;
        for (used.items) |*m| {
            if (m.message.sender >= excluded.len or excluded[m.message.sender]) continue;
            vss = try poly.addPublic(a, vss, m.message.vss_pk);
            for (m.shares) |sh| {
                if (sh.index < my_range.first or sh.index - my_range.first >= my_range.count) return error.GeneralError;
                const slot = &final[sh.index - my_range.first];
                slot.value = slot.value.add(sh.value);
            }
            if (m.complaint != null) has_invalid_share = true;
        }
        const has_zero_shares = my_range.count == 0;
        return .{
            .arena = arena,
            .value = .{ .vss_pk = vss, .shares = if (!has_invalid_share and !has_zero_shares) final else null },
        };
    }
};

// ---------------------------------------------------------------------------------------------
// Observer: follows a DKG without voting rights (full nodes)

pub const Observer = struct {
    nodes: *const Nodes,
    t: u16,
    ro: oracle.RandomOracle,

    pub fn init(nodes: *const Nodes, t: u16, ro: oracle.RandomOracle) Error!Observer {
        if (t > nodes.total_weight or t == 0) return error.InvalidInput;
        return .{ .nodes = nodes, .t = t, .ro = ro };
    }

    pub fn processMessage(self: *const Observer, message: *const Message) Error!void {
        try sanityCheck(message, self.nodes, self.t, &self.ro);
    }

    /// `merge`: NotEnoughInputs until the weight of the senders reaches t.
    pub fn merge(self: *const Observer, messages: []const *const Message) Error!void {
        var total: u32 = 0;
        for (messages) |m| total += try self.nodes.weightOf(m.sender);
        if (total < self.t) return error.NotEnoughInputs;
    }

    pub fn complete(
        self: *const Observer,
        gpa: std.mem.Allocator,
        used: []const *const Message,
        confirmations: []const *const Confirmation,
        rng: std.Random,
    ) Error!Owned(Output) {
        const excluded = try processConfirmations(gpa, self.nodes, self.t, &self.ro, used, confirmations, rng);
        defer gpa.free(excluded);
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        var vss: []const G2P = &.{G2P.infinity};
        for (used) |m| {
            if (m.sender >= excluded.len or excluded[m.sender]) continue;
            vss = try poly.addPublic(a, vss, m.vss_pk);
        }
        return .{ .arena = arena, .value = .{ .vss_pk = vss, .shares = null } };
    }
};

// ---------------------------------------------------------------------------------------------
// tests: a full 4 party weighted DKG

const TestNet = struct {
    arena: std.heap.ArenaAllocator,
    nodes: Nodes,
    sks: []Scalar,
    ro: oracle.RandomOracle,

    fn init(gpa: std.mem.Allocator, weights: []const u16, rng: std.Random) !TestNet {
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        const sks = try a.alloc(Scalar, weights.len);
        const in = try a.alloc(nodes_mod.Node, weights.len);
        for (weights, 0..) |w, i| {
            sks[i] = group.scalarRand(rng);
            in[i] = .{ .id = @intCast(i), .pk = group.mulPublic(G2, group.g2Generator(), sks[i]), .weight = w };
        }
        return .{ .arena = arena, .nodes = try Nodes.init(a, in), .sks = sks, .ro = try oracle.RandomOracle.init("dkg test 1") };
    }
};

test "four party dkg: all honest" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(99);
    const rng = prng.random();
    var net = try TestNet.init(gpa, &.{ 2, 1, 1, 2 }, rng);
    defer net.arena.deinit();
    const t: u16 = 3;
    var parties: [4]Party = undefined;
    var made: usize = 0;
    defer for (parties[0..made]) |*p| p.deinit();
    for (0..4) |i| {
        parties[i] = try Party.init(gpa, net.sks[i], &net.nodes, t, net.ro, rng);
        made += 1;
    }
    var msgs: [4]Owned(Message) = undefined;
    for (0..4) |i| msgs[i] = try parties[i].createMessage(gpa, rng);
    defer for (&msgs) |*m| m.deinit();

    // wire roundtrip of one message
    {
        const bytes = try encodeVersionedMessage(gpa, &msgs[0].value);
        defer gpa.free(bytes);
        var v = try decodeVersionedMessage(gpa, bytes);
        defer v.v1.deinit();
        try std.testing.expectEqual(msgs[0].value.sender, v.v1.value.sender);
    }

    // every party processes every message
    var processed: [4][4]Owned(ProcessedMessage) = undefined;
    for (0..4) |i| for (0..4) |j| {
        processed[i][j] = try parties[i].processMessage(gpa, &msgs[j].value, rng);
        try std.testing.expect(processed[i][j].value.complaint == null);
    };
    defer for (&processed) |*row| for (row) |*p| p.deinit();

    var confs: [4]Owned(Confirmation) = undefined;
    var useds: [4]Owned(UsedProcessedMessages) = undefined;
    for (0..4) |i| {
        var ptrs: [4]*const ProcessedMessage = undefined;
        for (0..4) |j| ptrs[j] = &processed[i][j].value;
        const m = try parties[i].merge(gpa, &ptrs);
        confs[i] = m.confirmation;
        useds[i] = m.used;
    }
    defer for (&confs) |*c| c.deinit();
    defer for (&useds) |*u| u.deinit();

    var cptrs: [4]*const Confirmation = undefined;
    for (0..4) |i| cptrs[i] = &confs[i].value;
    var outs: [4]Owned(Output) = undefined;
    for (0..4) |i| outs[i] = try parties[i].complete(gpa, &useds[i].value, &cptrs, rng);
    defer for (&outs) |*o| o.deinit();

    // all parties agree on the key; shares are consistent with the public polynomial
    const pk = outs[0].value.publicKey();
    for (0..4) |i| {
        try std.testing.expect(outs[i].value.publicKey().eql(pk));
        const sh = outs[i].value.shares.?;
        for (sh) |s| {
            const want = poly.evalPublic(G2, outs[i].value.vss_pk, s.index);
            try std.testing.expect(want.eql(group.mulPublic(G2, group.g2Generator(), s.value)));
        }
    }
    // an observer reaches the same public key
    const ro_obs = try Observer.init(&net.nodes, t, net.ro);
    var used_msgs: [4]*const Message = undefined;
    for (0..4) |j| used_msgs[j] = &msgs[j].value;
    try ro_obs.merge(&used_msgs);
    var oout = try ro_obs.complete(gpa, &used_msgs, &cptrs, rng);
    defer oout.deinit();
    try std.testing.expect(oout.value.publicKey().eql(pk));
}

test "a dealer sending a corrupted share is excluded by complaint" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(100);
    const rng = prng.random();
    var net = try TestNet.init(gpa, &.{ 1, 1, 1, 1 }, rng);
    defer net.arena.deinit();
    const t: u16 = 2;
    var parties: [4]Party = undefined;
    var made: usize = 0;
    defer for (parties[0..made]) |*p| p.deinit();
    for (0..4) |i| {
        parties[i] = try Party.init(gpa, net.sks[i], &net.nodes, t, net.ro, rng);
        made += 1;
    }
    var msgs: [4]Owned(Message) = undefined;
    for (0..4) |i| msgs[i] = try parties[i].createMessage(gpa, rng);
    defer for (&msgs) |*m| m.deinit();

    // dealer 3 re-deals with a wrong share for receiver 1 (encrypts garbage for it)
    {
        const bad = &parties[3];
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const eros = try encryptionRo(&bad.ro, 3);
        const recips = try a.alloc(ecies.MultiRecipientEncryption.Recipient, 4);
        for (bad.nodes.nodes, recips) |n, *rc| {
            var w = wire.Writer.init(a);
            try w.uleb(1);
            const v = poly.evalPrivate(bad.vss_sk, @intCast(n.id + 1));
            try w.scalar(if (n.id == 1) v.add(Scalar.one) else v);
            rc.* = .{ .pk = n.pk, .msg = w.buf.items };
        }
        const enc = try ecies.MultiRecipientEncryption.encrypt(msgs[3].arena.allocator(), recips, &eros, rng);
        msgs[3].value.encrypted_shares = enc;
    }

    var processed: [4][4]Owned(ProcessedMessage) = undefined;
    for (0..4) |i| for (0..4) |j| {
        processed[i][j] = try parties[i].processMessage(gpa, &msgs[j].value, rng);
    };
    defer for (&processed) |*row| for (row) |*p| p.deinit();
    try std.testing.expect(processed[1][3].value.complaint != null);
    try std.testing.expect(processed[0][3].value.complaint == null);

    var confs: [4]Owned(Confirmation) = undefined;
    var useds: [4]Owned(UsedProcessedMessages) = undefined;
    for (0..4) |i| {
        var ptrs: [4]*const ProcessedMessage = undefined;
        for (0..4) |j| ptrs[j] = &processed[i][j].value;
        const m = try parties[i].merge(gpa, &ptrs);
        confs[i] = m.confirmation;
        useds[i] = m.used;
    }
    defer for (&confs) |*c| c.deinit();
    defer for (&useds) |*u| u.deinit();
    try std.testing.expectEqual(@as(usize, 1), confs[1].value.complaints.len);

    var cptrs: [4]*const Confirmation = undefined;
    for (0..4) |i| cptrs[i] = &confs[i].value;
    var outs: [4]Owned(Output) = undefined;
    for (0..4) |i| outs[i] = try parties[i].complete(gpa, &useds[i].value, &cptrs, rng);
    defer for (&outs) |*o| o.deinit();
    const pk = outs[0].value.publicKey();
    for (0..4) |i| {
        try std.testing.expect(outs[i].value.publicKey().eql(pk));
        // party 1 saw the complaint itself, so its own shares missing is "invalid share" only if
        // dealer 3 stayed in; it was excluded, so every party keeps shares
        try std.testing.expect(outs[i].value.shares != null);
    }
}
