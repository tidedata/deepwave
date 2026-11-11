//! zui/1 request methods (NATIVE-PROTOCOL.md section 4) on the node's store and serve hooks. One
//! snapshot per request; chain values go out as the stored BCS bytes inside a BCS envelope.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const serve = @import("serve");
const index = @import("index");
const proto = @import("proto.zig");
const indexq = @import("indexq.zig");
const edgefeed = @import("edgefeed.zig");
const dicts_mod = @import("dicts.zig");
const hello_mod = @import("hello.zig");
const W = proto.W;
const R = proto.R;
const Code = proto.Code;

/// dry_run hook (the simulation engine). Null: UNIMPLEMENTED. Runs on a listener worker
/// thread (never the I/O thread).
pub const Simulator = struct {
    ctx: *anyopaque,
    /// Writes the whole response to `out`: `okHeader` + `DryRunResp`, or an error response
    /// (TX_REJECTED with the engine's message when the transaction did not run).
    simulate: *const fn (ctx: *anyopaque, arena: Allocator, tx_data: []const u8, flags: u8, out: *std.ArrayList(u8)) anyerror!void,
};

/// submit_transaction hook (the node's existing submit path). Null: UNIMPLEMENTED. Runs on a
/// listener worker thread.
pub const Submitter = struct {
    ctx: *anyopaque,
    /// Writes the whole response to `out`: `okHeader` + `SubmitResp`, or an error response
    /// (TX_REJECTED, or TIMEOUT with the 32-byte digest after `submit_wait_ms`).
    submit: *const fn (ctx: *anyopaque, arena: Allocator, tx_data: []const u8, sigs: []const []const u8, wait: u8, out: *std.ArrayList(u8)) anyerror!void,
};

/// Submit waits at most this long, then answers TIMEOUT with the digest (spec 4.2).
pub const submit_wait_ms = 30_000;

/// Sui's transaction digest: blake2b256("TransactionData::" ++ BCS TransactionData).
pub fn txDigest(tx_data: []const u8) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2b256.init(.{});
    h.update("TransactionData::");
    h.update(tx_data);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Hello feature bit of the edge feed (`get_checkpoint_feed`, `get_dictionary`). Bits 8..31 are
/// reserved for subscription filter variants (8 + k), so this one sits outside that range.
pub const feature_edge_feed_bit: u6 = 32;

/// Methods that may block for long (execution): the listener runs them on worker threads.
pub fn slowMethod(m: proto.Method) bool {
    return m == .dry_run or m == .submit_transaction;
}

/// Edge feed assembly (a checkpoint's whole transactions and objects, then compression): its own
/// worker pool, so feed traffic never queues in front of a wallet's submit_transaction.
pub fn feedMethod(m: proto.Method) bool {
    return m == .get_checkpoint_feed;
}

/// Token check (section 6). Null: everyone is anonymous.
pub const Auth = struct {
    ctx: *anyopaque,
    check: *const fn (ctx: *anyopaque, token: []const u8) ?Principal,
};
pub const Principal = struct { id: u64, tier: u8 };

/// Agent Pass policy hook (section 6.1, agentpass.zig): runs before dry_run and submit, on the
/// worker thread, with the request arena `a` (a deny reason may live there).
pub const AgentPass = struct {
    ctx: *anyopaque,
    check: *const fn (ctx: *anyopaque, a: Allocator, principal: ?Principal, method: proto.Method, tx_data: []const u8) Verdict,
    /// After an allowed submit: `executed` false when the transaction provably never reached the
    /// network (TX_REJECTED from the submit path), so the pass frees what it reserved.
    settle: ?*const fn (ctx: *anyopaque, principal: ?Principal, tx_data: []const u8, executed: bool) void = null,
    pub const Verdict = union(enum) { allow, deny: []const u8 };
};

/// Current-epoch facts for nodes without a live SuiSystemState (verify-only): the trust walk's
/// committee file. Null: get_epoch_info needs the live object.
pub const EpochFallback = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, epoch: u64) ?EpochSummary,
};
pub const EpochSummary = struct { epoch: u64, protocol_version: u64, reference_gas_price: u64, epoch_start_timestamp_ms: u64 };

pub const Hooks = struct {
    epoch_fallback: ?EpochFallback = null,
    simulator: ?Simulator = null,
    submitter: ?Submitter = null,
    auth: ?Auth = null,
    agent_pass: ?AgentPass = null,
};

pub const Dispatcher = struct {
    svc: *serve.service.Service,
    hooks: Hooks = .{},
    server: []const u8 = "zui/0.1",
    /// The node's owner/balance index (`--indexes`); null: index methods answer UNAVAILABLE.
    ix: ?*index.Index = null,
    /// Edge feed (`--edge-feed`, docs/EDGE.md); null: get_checkpoint_feed is UNIMPLEMENTED.
    edge: ?*edgefeed.Feeder = null,
    /// Response dictionaries (hello, get_dictionary, ZSTD frames); null: plain zstd only and
    /// get_dictionary answers NOT_FOUND.
    dicts: ?*const dicts_mod.Dicts = null,
    /// The node's software version (`<version>-<git sha>`): hello's `server` is `zui/<this>` for
    /// clients of minor 1 and later. Minor 0 clients read `server`, as they always did.
    software: []const u8 = "",
    /// Who said hello with which minor, and the hellos refused (hello.zig).
    hello: hello_mod.Stats = .{},

    /// Answers one request into `out` (a whole response: header, body, proof).
    pub fn handle(d: *Dispatcher, a: Allocator, req: proto.Request, principal: ?Principal, out: *std.ArrayList(u8)) void {
        defer dicts_mod.Dicts.compressResponse(d.dicts, a, req.method, req.flags, out) catch {};
        d.handleInner(a, req, principal, out) catch |e| {
            const code: Code = switch (e) {
                error.Malformed, error.EndOfStream, error.InvalidValue => .bad_request,
                error.TooLarge => .too_large,
                error.Unimplemented => .unimplemented,
                error.Unavailable => .unavailable,
                else => .internal,
            };
            proto.errorResponse(out, a, code, @errorName(e), "") catch {};
        };
    }

    fn handleInner(d: *Dispatcher, a: Allocator, req: proto.Request, principal: ?Principal, out: *std.ArrayList(u8)) !void {
        if (req.flags & ~(proto.flag_verify | proto.flag_zstd_ok) != 0) return error.Malformed;
        const verify = req.flags & proto.flag_verify != 0;
        var r: R = .{ .b = req.body };
        var snap = d.svc.store.snapshot();
        defer snap.release();
        const w: W = .{ .gpa = a, .out = out };
        var proof: Proof = .{};
        switch (req.method) {
            .hello => {
                const client = try r.str();
                const cminor = try r.int(u16);
                var authed = false;
                if (try r.option()) {
                    const tok = try r.bytes();
                    if (d.hooks.auth) |au| authed = au.check(au.ctx, tok) != null;
                }
                // minor 1: what the client requires of the node (absent from older clients)
                const want = try hello_mod.Want.read(&r);
                try r.done();
                const ei = d.epochInfo(&snap);
                try proto.okHeader(out, a, 0);
                if (cminor >= 1 and d.software.len > 0) {
                    try w.uleb(4 + d.software.len);
                    try w.fixed("zui/");
                    try w.fixed(d.software);
                } else try w.str(d.server);
                try w.int(u16, @min(cminor, proto.server_minor));
                try w.fixed(&d.svc.chain_id);
                try w.int(u64, snap.lowestAvailable() orelse 0);
                try w.int(u64, snap.highestCommitted() orelse 0);
                try w.int(u64, d.svc.store.currentEpoch() orelse 0);
                // verified mode, subscriptions, pair relay, epoch info; filters: checkpoints,
                // address, objects, event type, package
                var feat: u64 = 1 | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12);
                if (ei != null) feat |= 1 << 7;
                if (d.ix != null) feat |= 1 << 2;
                if (d.hooks.simulator != null) feat |= 1 << 3;
                if (d.hooks.submitter != null) feat |= 1 << 4;
                feat |= 1 << 1; // ZSTD responses (spec 2.2), with or without dictionaries
                if (d.edge != null) feat |= @as(u64, 1) << feature_edge_feed_bit;
                const refusal = if (want) |wn| hello_mod.refuse(wn, &d.svc.chain_id, feat) else null;
                _ = d.hello.record(client, cminor, if (refusal) |rf| rf.code else null, hello_mod.monoMs());
                if (refusal) |rf| return proto.errorResponse(out, a, rf.code, rf.message, rf.detail());
                try w.int(u64, feat);
                // Limits
                try w.int(u32, 128);
                try w.int(u32, 16);
                try w.int(u32, proto.max_request_bytes);
                try w.int(u32, proto.max_batch_objects);
                try w.int(u64, 0);
                if (d.dicts) |ds| try ds.writeInfos(w) else try w.uleb(0);
                try w.int(u64, if (ei) |e| e.reference_gas_price else 0);
                try w.u8_(if (authed or principal != null) 1 else 0);
                return;
            },
            .get_object => {
                const k = try readKey(&r);
                try r.done();
                try proto.okHeader(out, a, if (verify) proto.resp_proof else 0);
                try d.object(a, &snap, w, k, if (verify) &proof else null);
            },
            .batch_get_objects => {
                const n = try r.uleb();
                if (n > proto.max_batch_objects) return error.TooLarge;
                const keys = try a.alloc(Key, @intCast(n));
                for (keys) |*k| k.* = try readKey(&r);
                try r.done();
                try proto.okHeader(out, a, if (verify) proto.resp_proof else 0);
                try w.uleb(n);
                for (keys) |k| try d.object(a, &snap, w, k, if (verify) &proof else null);
            },
            .get_checkpoint => {
                const seq: ?u64 = switch (try r.uleb()) {
                    0 => snap.highestCommitted(),
                    1 => try r.int(u64),
                    2 => snap.checkpointByDigest((try r.fixed(32))),
                    else => return error.Malformed,
                };
                const parts = try r.u8_();
                try r.done();
                if (seq) |s| if (snap.lowestAvailable()) |lo| if (s < lo) return pruned(out, a, lo);
                try proto.okHeader(out, a, 0); // the certified summary is its own proof
                const rec = if (seq) |s| snap.checkpoint(s) else null;
                if (rec) |c| {
                    try w.u8_(1);
                    try writeCheckpoint(a, &snap, w, c, parts);
                } else try w.u8_(0);
            },
            .get_transaction => {
                const dg = try r.fixed(32);
                const parts = try r.u8_();
                try r.done();
                try proto.okHeader(out, a, if (verify) proto.resp_proof else 0);
                try d.txOpt(a, &snap, w, dg, parts, if (verify) &proof else null);
            },
            .batch_get_transactions => {
                const n = try r.uleb();
                if (n > proto.max_batch_txs) return error.TooLarge;
                const ds = try a.alloc(*const [32]u8, @intCast(n));
                for (ds) |*x| x.* = try r.fixed(32);
                const parts = try r.u8_();
                try r.done();
                try proto.okHeader(out, a, if (verify) proto.resp_proof else 0);
                try w.uleb(n);
                for (ds) |dg| try d.txOpt(a, &snap, w, dg, parts, if (verify) &proof else null);
            },
            .dry_run => {
                const sim = d.hooks.simulator orelse return error.Unimplemented;
                const tx = try r.bytes();
                const fl = try r.u8_();
                try r.done();
                if (fl & ~@as(u8, 0x03) != 0) return error.Malformed;
                if (try d.denied(a, principal, req.method, tx, out)) return;
                try sim.simulate(sim.ctx, a, tx, fl, out);
                return;
            },
            .submit_transaction => {
                const tx = try r.bytes();
                const n = try r.uleb();
                if (n > 16) return error.Malformed;
                const sigs = try a.alloc([]const u8, @intCast(n));
                for (sigs) |*s| s.* = try r.bytes();
                const wait = try r.u8_();
                try r.done();
                if (wait > 2) return error.Malformed;
                // the pass first: its reason is the answer even where submit is not served
                if (try d.denied(a, principal, req.method, tx, out)) return;
                const sub = d.hooks.submitter orelse {
                    if (d.hooks.agent_pass) |ap| if (ap.settle) |f| f(ap.ctx, principal, tx, false);
                    return error.Unimplemented;
                };
                sub.submit(sub.ctx, a, tx, sigs, wait, out) catch |e| {
                    // unknown whether it was sent: the pass keeps the reservation
                    if (d.hooks.agent_pass) |ap| if (ap.settle) |f| f(ap.ctx, principal, tx, true);
                    return proto.errorResponse(out, a, .tx_rejected, @errorName(e), "");
                };
                if (d.hooks.agent_pass) |ap| if (ap.settle) |f|
                    f(ap.ctx, principal, tx, !(out.items.len > 0 and out.items[0] == @intFromEnum(Code.tx_rejected)));
                return;
            },
            .get_epoch_info => {
                try r.done();
                const e = d.epochInfo(&snap) orelse return error.Unavailable;
                try proto.okHeader(out, a, 0);
                try w.int(u64, e.epoch);
                try w.int(u64, e.protocol_version);
                try w.int(u64, e.reference_gas_price);
                try w.int(u64, e.epoch_start_timestamp_ms);
                try w.int(u64, snap.highestCommitted() orelse 0);
                return;
            },
            .list_owned_objects, .get_balance, .list_balances => {
                const ix = d.ix orelse return error.Unavailable;
                snap.release(); // the index methods pin their own snapshot under the index lock
                snap = d.svc.store.snapshot();
                switch (req.method) {
                    .list_owned_objects => try indexq.listOwned(a, ix, d.svc.store, req.body, w),
                    .get_balance => try indexq.getBalance(a, ix, d.svc.store, req.body, w),
                    else => try indexq.listBalances(a, ix, d.svc.store, req.body, w),
                }
                return;
            },
            .get_epoch_proof => {
                const e = try r.int(u64);
                try r.done();
                try proto.okHeader(out, a, 0);
                if (d.epochProof(&snap, e)) |cert| {
                    try w.u8_(1);
                    try w.bytes(cert);
                } else try w.u8_(0);
                return;
            },
            .get_dictionary => {
                const id = try r.int(u32);
                try r.done();
                const x = (if (d.dicts) |ds| ds.byId(id) else null) orelse
                    return proto.errorResponse(out, a, .not_found, "unknown dictionary", "");
                try proto.okHeader(out, a, 0);
                try w.bytes(x.content);
                return;
            },
            .get_checkpoint_feed => {
                const fd = d.edge orelse return error.Unimplemented;
                return fd.handle(a, &snap, req, out);
            },
            .subscribe, .pair_relay => return error.Malformed, // handled by the listener
            _ => return error.Unimplemented,
        }
        // VERIFY attaches a Proof only on 0x01, 0x02, 0x04, 0x05 (spec 7); elsewhere it is ignored
        if (verify and out.items.len > 0 and proofMethod(req.method)) try proof.write(w);
    }

    fn epochInfo(d: *Dispatcher, snap: *store.Snapshot) ?EpochSummary {
        if (liveEpochInfo(snap)) |e| return e;
        const fb = d.hooks.epoch_fallback orelse return null;
        return fb.get(fb.ctx, d.svc.store.currentEpoch() orelse return null);
    }

    /// The certified end-of-epoch summary of epoch `e - 1` (it names epoch `e`'s committee), when
    /// the store still holds that checkpoint. Epoch 0's committee is genesis: none.
    fn epochProof(d: *Dispatcher, snap: *store.Snapshot, e: u64) ?[]const u8 {
        if (e == 0) return null;
        const x = d.svc.rpc orelse return null;
        const tok = x.enter();
        defer x.exit(tok);
        const seq: u64 = blk: {
            if (x.epoch(e - 1)) |rec| if (rec.end) |end| break :blk end.end_checkpoint;
            if (x.epoch(e)) |rec| if (rec.start) |st| if (st.start_checkpoint) |sc| if (sc > 0) break :blk sc - 1;
            return null;
        };
        const c = snap.checkpoint(seq) orelse return null;
        return c.summary_cert;
    }

    fn denied(d: *Dispatcher, a: Allocator, principal: ?Principal, m: proto.Method, tx: []const u8, out: *std.ArrayList(u8)) !bool {
        const ap = d.hooks.agent_pass orelse return false;
        switch (ap.check(ap.ctx, a, principal, m, tx)) {
            .allow => return false,
            .deny => |why| {
                try proto.errorResponse(out, a, .permission_denied, why, "");
                return true;
            },
        }
    }

    fn object(d: *Dispatcher, a: Allocator, snap: *store.Snapshot, w: W, k: Key, proof: ?*Proof) !void {
        _ = d;
        const ref: ?store.ObjectRef = if (k.version) |v| try snap.objectAtChecked(&k.id, v) else blk: {
            const l = (try snap.latest(&k.id)) orelse break :blk null;
            switch (l) {
                .live => |o| break :blk o,
                .removed => |rm| {
                    try w.uleb(2);
                    try w.int(u64, rm.version);
                    try w.u8_(@intCast(@intFromEnum(rm.kind)));
                    if (proof) |p| try p.none(a);
                    return;
                },
            }
        };
        const o = ref orelse {
            try w.uleb(if (k.version != null) 3 else 1);
            if (proof) |p| try p.none(a);
            return;
        };
        try w.uleb(0);
        try w.int(u64, o.version);
        try w.fixed(&o.digest);
        try w.bytes(o.bytes);
        if (proof) |p| {
            const prev = proto.objectPrevTx(o.bytes) orelse return p.none(a);
            const t = snap.transaction(&prev) orelse return p.none(a);
            try p.item(a, snap, .object, t);
        }
    }

    fn txOpt(d: *Dispatcher, a: Allocator, snap: *store.Snapshot, w: W, dg: *const [32]u8, parts: u8, proof: ?*Proof) !void {
        _ = d;
        const t = snap.transaction(dg) orelse {
            try w.u8_(0);
            if (proof) |p| try p.none(a);
            return;
        };
        try w.u8_(1);
        try writeTx(w, t, parts);
        if (proof) |p| try p.item(a, snap, .tx, t);
    }
};

fn proofMethod(m: proto.Method) bool {
    return switch (m) {
        .get_object, .batch_get_objects, .get_transaction, .batch_get_transactions => true,
        else => false,
    };
}

/// The live SuiSystemState summary (epoch, protocol version, reference gas price).
fn liveEpochInfo(snap: *store.Snapshot) ?EpochSummary {
    const st = serve.rpcindex.liveState(snap) orelse return null;
    const s = serve.sysstate.summary(st) catch return null;
    return .{ .epoch = s.epoch, .protocol_version = s.protocol_version, .reference_gas_price = s.reference_gas_price, .epoch_start_timestamp_ms = s.epoch_start_timestamp_ms };
}

fn pruned(out: *std.ArrayList(u8), a: Allocator, lo: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, lo, .little);
    try proto.errorResponse(out, a, .pruned, "below the lowest available checkpoint", &b);
}

/// The token of a `HelloReq` body, if it carries one (the listener sets the connection's
/// principal from it, spec 6).
pub fn helloToken(body: []const u8) ?[]const u8 {
    var r: R = .{ .b = body };
    _ = r.str() catch return null;
    _ = r.int(u16) catch return null;
    if (!(r.option() catch return null)) return null;
    return r.bytes() catch null;
}

pub const Key = struct { id: [32]u8, version: ?u64 };

fn readKey(r: *R) !Key {
    const id = (try r.fixed(32)).*;
    const v: ?u64 = if (try r.option()) try r.int(u64) else null;
    return .{ .id = id, .version = v };
}

/// `Tx` (section 4.1) from a stored record.
pub fn writeTx(w: W, t: store.TransactionRecord, parts: u8) !void {
    try w.fixed(t.digest);
    try w.int(u64, t.checkpoint);
    try w.optBytes(if (parts & proto.part_tx != 0) t.tx else null);
    try w.optBytes(if (parts & proto.part_effects != 0) t.effects else null);
    try w.optBytes(if (parts & proto.part_events != 0) t.events else null);
}

/// Transaction digests of a checkpoint's contents, in order.
pub fn contentDigests(a: Allocator, contents: []const u8) ![]const [32]u8 {
    const c = try bcs.decode(types.CheckpointContents, a, contents);
    switch (c) {
        .V1 => |v| {
            const out = try a.alloc([32]u8, v.transactions.len);
            for (v.transactions, out) |t, *o| o.* = t.transaction.@"0".@"0";
            return out;
        },
        .V2 => |v| {
            const out = try a.alloc([32]u8, v.transactions.len);
            for (v.transactions, out) |t, *o| o.* = t.digest.transaction.@"0".@"0";
            return out;
        },
    }
}

/// `Checkpoint` (section 4.1) body.
pub fn writeCheckpoint(a: Allocator, snap: *store.Snapshot, w: W, c: store.CheckpointRecord, parts: u8) !void {
    try w.int(u64, c.seq);
    try w.bytes(c.summary_cert);
    try w.optBytes(if (parts & proto.part_contents != 0) c.contents else null);
    if (parts & (proto.part_tx | proto.part_effects | proto.part_events) == 0) return w.uleb(0);
    const ds = try contentDigests(a, c.contents);
    try w.uleb(ds.len);
    for (ds) |*dg| {
        const t = snap.transaction(dg) orelse return error.Internal;
        try writeTx(w, t, parts);
    }
}

/// Verified-mode proof (section 7), built alongside the body.
/// `ProofCheckpoint` (spec 7): the certified summary and the contents, as stored.
pub fn writeProofCheckpoint(w: W, c: store.CheckpointRecord) !void {
    try w.bytes(c.summary_cert);
    try w.bytes(c.contents);
}

const Proof = struct {
    cps: std.ArrayList(store.CheckpointRecord) = .empty,
    items: std.ArrayList(Item) = .empty,

    const Item = union(enum) { none, tx: struct { cp: u32, effects: []const u8 }, object: struct { cp: u32, effects: []const u8 } };

    fn none(p: *Proof, a: Allocator) !void {
        try p.items.append(a, .none);
    }

    fn item(p: *Proof, a: Allocator, snap: *store.Snapshot, comptime kind: enum { tx, object }, t: store.TransactionRecord) !void {
        const c = snap.checkpoint(t.checkpoint) orelse return p.none(a);
        var idx: ?u32 = null;
        for (p.cps.items, 0..) |x, i| if (x.seq == c.seq) {
            idx = @intCast(i);
        };
        if (idx == null) {
            idx = @intCast(p.cps.items.len);
            try p.cps.append(a, c);
        }
        try p.items.append(a, switch (kind) {
            .tx => .{ .tx = .{ .cp = idx.?, .effects = t.effects } },
            .object => .{ .object = .{ .cp = idx.?, .effects = t.effects } },
        });
    }

    fn write(p: *const Proof, w: W) !void {
        try w.uleb(p.cps.items.len);
        for (p.cps.items) |c| {
            try w.bytes(c.summary_cert);
            try w.bytes(c.contents);
        }
        try w.uleb(p.items.items.len);
        for (p.items.items) |it| switch (it) {
            .none => try w.uleb(0),
            .tx => |x| {
                try w.uleb(1);
                try w.int(u32, x.cp);
                try w.bytes(x.effects);
            },
            .object => |x| {
                try w.uleb(2);
                try w.int(u32, x.cp);
                try w.bytes(x.effects);
            },
        };
    }
};
