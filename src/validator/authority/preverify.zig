//! Signature pre-verification for the validator's transaction intake (zui-only and local:
//! nothing on the wire, in consensus or in any vote changes).
//!
//! Both intake paths check their transactions one by one, in order, and stop at the first
//! failing check of each (sui-core is serial too: `SuiTxValidator::vote_transactions` and
//! `handle_submit_transaction_inner` loop over the transactions and call
//! `verify_transaction_with_current_aliases` per transaction):
//!   - consensus blocks from peers (tx_validator.zig `verifyAndVote`): every UserTransactionV2
//!     is voted on; the user signatures are step 3 of the vote, after the validity check and the
//!     overload hook;
//!   - SubmitTransaction (submit.zig `Submit.handle`, up to 128 transactions): signatures after
//!     decoding, validity, the proposer check, duplicates and the overload checks.
//! The signature check is by far the most expensive of those steps and is a pure function of the
//! transaction (and the epoch's `UserSigEnv`), so this stage runs it for every transaction of the
//! batch at once, across the lanes of the shared CPU pool (`core.pool`), before the serial loop.
//! The serial loop then takes the stored result at exactly the point where it used to call
//! `checker.verifySignatures`, so every accept and reject, every reason string and every counter
//! is the one the serial code gives. A transaction the serial loop never reaches the signature
//! check for (rejected earlier, after a request-level failure) may have been verified here; its
//! result is simply not used. A slot without a stored result (decoding failed here, the stage
//! decided the verdict was not needed) makes the serial loop compute the step itself, as before.
//!
//! The decode and the validity check (`checker.checkValidity`, also pure) run in the same pass and
//! their results are reused the same way.
//!
//! Hook point: `Config.pre_steps` run, in order, over every collected (intent, signatures) item
//! after decoding and before the per-transaction signature pass. They exist for batch work that
//! warms verdict-neutral caches the per-transaction check then hits: (a) a zkLogin batch Groth16
//! check filling the sig.fast zk proof cache, (b) a GPU or pool Ed25519 batch. A pre-step must
//! never decide a verdict itself: whatever it does, the per-transaction check decides.
//!
//! Threads: each slot owns an arena (the callers' arenas are not thread safe); `gpa` must be
//! thread safe. Pool calls from inside another pool job, or while the pool is busy, run inline.
const std = @import("std");
const bcs = @import("bcs");
const core = @import("core");
const sig = @import("sig");
const messages = @import("../messages.zig");
const tx_mod = @import("tx.zig");
const checker = @import("checker.zig");

const Allocator = std.mem.Allocator;
const Pool = core.pool.Pool;
const Atomic = std.atomic.Value;

/// `--sig-preverify`: on, off, or auto (on when the pool has more than one lane and the batch
/// has at least `Config.auto_min` user transactions).
pub const Mode = enum {
    off,
    on,
    auto,

    pub fn parse(s: []const u8) ?Mode {
        return std.meta.stringToEnum(Mode, s);
    }
};

/// One transaction's signatures as a pre-step sees them.
pub const Item = struct {
    /// Position in the batch (block index or request index).
    index: usize,
    /// `IntentMessage` BCS ([0, 0, 0] ++ BCS(TransactionData)); `digest` is its Blake2b-256,
    /// the message every user signature signs.
    intent: []const u8,
    digest: [32]u8,
    /// GenericSignature bytes (flag byte first), in transaction order.
    sigs: []const []const u8,
};

/// A batch step run over every collected item before the per-transaction signature pass.
/// It may only fill caches that change no verdict (sig.fast); the per-transaction check decides.
pub const PreStep = struct {
    name: []const u8,
    ctx: ?*anyopaque = null,
    run: *const fn (ctx: ?*anyopaque, pool: ?*Pool, env: *const sig.user.UserSigEnv, items: []const Item) void,
    /// Whether the step has work for a signature with this scheme flag in a batch of `batch_n`
    /// transactions (null: every signature). On the vote path a transaction no step wants is
    /// verified in the first pass, so batches without such signatures keep the one-pass cost.
    wants: ?*const fn (ctx: ?*anyopaque, batch_n: usize, flag: u8) bool = null,
};

pub const Config = struct {
    mode: Mode = .auto,
    /// Pool to use; null = `core.pool.shared()` (none installed: everything inline).
    pool: ?*Pool = null,
    /// Smallest batch (user transactions) that auto mode pre-verifies.
    auto_min: usize = 2,
    /// Batch pre-steps (zkLogin Groth16 batch, Ed25519 batch); empty by default.
    pre_steps: []const PreStep = &.{},

    pub fn poolOf(c: *const Config) ?*Pool {
        return c.pool orelse core.pool.shared();
    }

    /// Whether a batch of `n` user transactions goes through the stage.
    pub fn active(c: *const Config, n: usize) bool {
        if (n == 0) return false;
        return switch (c.mode) {
            .off => false,
            .on => true,
            .auto => n >= @max(1, c.auto_min) and if (c.poolOf()) |p| p.lanes() > 1 else false,
        };
    }
};

/// Counters of the stage (atomics: both intake paths run on several threads).
pub const Stats = struct {
    batches: Atomic(u64) = .init(0),
    txs: Atomic(u64) = .init(0),
    verified: Atomic(u64) = .init(0),
};

/// One transaction of the batch: its inputs, then what the stage computed. A null result means
/// "not computed here": the serial loop computes it itself.
pub const Slot = struct {
    arena: std.heap.ArenaAllocator,
    /// Submit path: BCS `Transaction`.
    raw: []const u8 = &.{},
    /// Vote path: the block's decoded transaction (read only here).
    plain: ?*const messages.PlainTransactionWithClaims = null,

    t: ?messages.Transaction = null,
    u: ?tx_mod.UserTx = null,
    validity: ?(checker.Error!?checker.Fail) = null,
    intent: ?[]const u8 = null,
    /// Blake2b-256 of `intent` (set with it, for the pre-steps).
    digest: [32]u8 = undefined,
    /// Set by the caller between the passes (submit) or by the fused pass (vote).
    need_sig: bool = false,
    sig: ?(checker.Error!checker.SigResult) = null,

    /// The validity check passed here (the signature step is reachable).
    pub fn validityOk(s: *const Slot) bool {
        const r = s.validity orelse return false;
        const f = r catch return false;
        return f == null;
    }
};

pub const Batch = struct {
    gpa: Allocator,
    cfg: *const Config,
    env: *const checker.Env,
    pool: ?*Pool,
    slots: []Slot,
    /// Vote path: decode, validity and signatures in one pass, except for transactions a
    /// pre-step wants (their signatures wait for `verify`, after the pre-steps).
    fused: bool = false,
    stats: ?*Stats = null,

    /// Slots for a block's user transactions; `plains[i] == null` marks a non-user transaction.
    /// `slots` memory comes from `arena` (the caller's); each slot's arena from `gpa`.
    pub fn initPlain(gpa: Allocator, arena: Allocator, cfg: *const Config, env: *const checker.Env, plains: []const ?*const messages.PlainTransactionWithClaims) Allocator.Error!Batch {
        const slots = try arena.alloc(Slot, plains.len);
        for (slots, plains) |*s, p| s.* = .{ .arena = .init(gpa), .plain = p };
        return .{ .gpa = gpa, .cfg = cfg, .env = env, .pool = cfg.poolOf(), .slots = slots, .fused = true };
    }

    /// Slots for a SubmitTransaction request's raw transactions.
    pub fn initRaw(gpa: Allocator, arena: Allocator, cfg: *const Config, env: *const checker.Env, raws: []const []const u8) Allocator.Error!Batch {
        const slots = try arena.alloc(Slot, raws.len);
        for (slots, raws) |*s, r| s.* = .{ .arena = .init(gpa), .raw = r };
        return .{ .gpa = gpa, .cfg = cfg, .env = env, .pool = cfg.poolOf(), .slots = slots };
    }

    /// Frees every slot's arena: after the serial loop is done with the results (messages it
    /// keeps must be copied first).
    pub fn deinit(b: *Batch) void {
        for (b.slots) |*s| s.arena.deinit();
    }

    /// Pass 1: decode and validity (and, fused, the signatures of every transaction whose
    /// validity passed).
    pub fn decode(b: *Batch) void {
        if (b.stats) |st| {
            _ = st.batches.fetchAdd(1, .monotonic);
            _ = st.txs.fetchAdd(b.slots.len, .monotonic);
        }
        core.pool.forRange(b.pool, b.slots.len, 1, 0, b, decodeRange);
    }

    /// Pre-steps over the slots that need a signature verdict, then pass 2: their signatures.
    /// Not needed after a fused `decode` without pre-steps (`needVerify`).
    pub fn verify(b: *Batch, arena: Allocator) Allocator.Error!void {
        if (b.cfg.pre_steps.len != 0) {
            var items: std.ArrayList(Item) = .empty;
            for (b.slots, 0..) |*s, i| {
                if (!s.need_sig or s.sig != null) continue;
                const u = &(s.u orelse continue);
                const intent = s.intent orelse continue;
                const raw_sigs = try arena.alloc([]const u8, u.signatures().len);
                for (u.signatures(), raw_sigs) |g, *o| o.* = g.@"0";
                try items.append(arena, .{ .index = i, .intent = intent, .digest = s.digest, .sigs = raw_sigs });
            }
            if (items.items.len != 0) for (b.cfg.pre_steps) |step| step.run(step.ctx, b.pool, b.env.sig_env, items.items);
        }
        core.pool.forRange(b.pool, b.slots.len, 1, 0, b, sigRange);
    }

    /// Whether `verify` still has work after `decode`.
    pub fn needVerify(b: *const Batch) bool {
        return !b.fused or b.cfg.pre_steps.len != 0;
    }

    fn decodeRange(b: *Batch, lo: usize, hi: usize) void {
        for (b.slots[lo..hi]) |*s| {
            b.decodeOne(s);
            if (b.fused) {
                s.need_sig = s.validityOk();
                if (s.intent == null) b.sigOne(s);
            }
        }
    }

    /// A pre-step has work for one of the slot's signatures.
    fn wanted(b: *const Batch, s: *const Slot) bool {
        const u = &(s.u orelse return false);
        for (u.signatures()) |g| {
            const raw = g.@"0";
            if (raw.len == 0) continue;
            for (b.cfg.pre_steps) |step| {
                const w = step.wants orelse return true;
                if (w(step.ctx, b.slots.len, raw[0])) return true;
            }
        }
        return false;
    }

    fn sigRange(b: *Batch, lo: usize, hi: usize) void {
        for (b.slots[lo..hi]) |*s| b.sigOne(s);
    }

    fn decodeOne(b: *Batch, s: *Slot) void {
        const a = s.arena.allocator();
        if (s.plain) |p| {
            s.u = tx_mod.fromDecoded(a, &.{}, p.*) catch return;
        } else if (s.raw.len != 0) {
            const t = bcs.decode(messages.Transaction, a, s.raw) catch return;
            s.t = t;
            s.u = tx_mod.fromDecoded(a, s.raw, .{ .tx = t, .claims = &.{} }) catch return;
        } else return;
        s.validity = checker.checkValidity(a, b.env, &s.u.?);
        if (b.cfg.pre_steps.len != 0 and s.validityOk() and (!b.fused or b.wanted(s))) {
            s.intent = checker.intentMessage(a, &s.u.?) catch null;
            if (s.intent) |m| s.digest = sig.user.intentDigest(m);
        }
    }

    fn sigOne(b: *Batch, s: *Slot) void {
        if (!s.need_sig or s.sig != null) return;
        const u = &(s.u orelse return);
        const a = s.arena.allocator();
        s.sig = if (s.intent) |intent| checker.verifySignaturesIntent(a, b.env, u, intent, &.{}) else checker.verifySignatures(a, b.env, u, &.{});
        if (b.stats) |st| _ = st.verified.fetchAdd(1, .monotonic);
    }
};

test "mode parse and auto rule" {
    try std.testing.expectEqual(Mode.auto, Mode.parse("auto").?);
    try std.testing.expectEqual(Mode.off, Mode.parse("off").?);
    try std.testing.expect(Mode.parse("yes") == null);
    var c: Config = .{ .mode = .off };
    try std.testing.expect(!c.active(100));
    c.mode = .on;
    try std.testing.expect(c.active(1));
    try std.testing.expect(!c.active(0));
    const pool = try Pool.init(std.testing.io, std.testing.allocator, 3);
    defer pool.deinit();
    c = .{ .mode = .auto, .pool = pool };
    try std.testing.expect(!c.active(1));
    try std.testing.expect(c.active(2));
    const one = try Pool.init(std.testing.io, std.testing.allocator, 1);
    defer one.deinit();
    c.pool = one;
    try std.testing.expect(!c.active(64));
}
