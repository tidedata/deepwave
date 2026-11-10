//! The epoch SimulateTransaction runs in, read from a store snapshot (what sui-node's
//! `AuthorityPerEpochStore` and the system state give `simulate_transaction`): the protocol
//! version and config, the reference gas price, the epoch start time and the committee size, all
//! decoded from the live `0x5` system state (`SuiSystemState` wrapper plus its
//! `Field<u64, SuiSystemStateInnerV2>`) with the framework's own layout.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const store = @import("store");
const exec = @import("exec");
const hash = @import("hash");

const root = @import("root.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const sys = exec.system;
const movecall = sys.movecall;

const system_state: Id = blk: {
    var a: Id = @splat(0);
    a[31] = 5;
    break :blk a;
};
const system_pkg: Id = blk: {
    var a: Id = @splat(0);
    a[31] = 3;
    break :blk a;
};

pub const Error = error{ NoSystemState, BadSystemState, NoFramework, UnknownProtocolVersion } || Allocator.Error;

/// The fields simulate needs from `SuiSystemStateInnerV2`.
pub const SystemSummary = struct {
    epoch: u64,
    protocol_version: u64,
    reference_gas_price: u64,
    epoch_start_timestamp_ms: u64,
    active_validators: u32,
    /// Version of the `0x5` wrapper the summary was read from (a cache key).
    wrapper_version: u64,
};

/// `sys.Source` over a store snapshot: objects at exact versions, live children under a bound,
/// live packages.
fn snapSource(snap: *const store.Snapshot) sys.Source {
    const S = struct {
        fn of(ctx: *const anyopaque) *const store.Snapshot {
            return @ptrCast(@alignCast(ctx));
        }
        fn input(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
            return of(ctx).objectAt(id, version);
        }
        fn child(ctx: *const anyopaque, parent: *const Id, c: *const Id, bound: u64) error{NotAvailable}!?[]const u8 {
            _ = parent;
            const r = of(ctx).liveObject(c) orelse return null;
            return if (r.version <= bound) r.bytes else null;
        }
        fn package(ctx: *const anyopaque, id: *const Id) ?[]const u8 {
            const r = of(ctx).liveObject(id) orelse return null;
            return r.bytes;
        }
    };
    return .{ .ctx = snap, .input = S.input, .child = S.child, .package = S.package };
}

/// Decodes the live system state of `snap`. `cfg` only selects the VM limits for the layout
/// (any recent config works; the caller passes the previous epoch's or the newest known).
pub fn readSystem(arena: Allocator, snap: *const store.Snapshot, cfg: *const protocol.ProtocolConfig) Error!SystemSummary {
    const wrapper = snap.liveObject(&system_state) orelse return error.NoSystemState;
    const wv = exec.objects.ObjectView.parse(wrapper.bytes) catch return error.BadSystemState;
    const wc = wv.contents();
    // SuiSystemState { id: UID, version: u64 }
    if (wc.len != 40) return error.BadSystemState;
    // derive_dynamic_field_id(0x5, u64, bcs(version))
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, 8, .little);
    const fid = hash.blake2b256(&.{ &[_]u8{0xf0}, &system_state, &len_le, wc[32..40], &[_]u8{2} });
    const inner = snap.liveObject(&fid) orelse return error.NoSystemState;
    const o = bcs.decode(types.Object, arena, inner.bytes) catch return error.BadSystemState;
    const mo = switch (o.data) {
        .Move => |m| m,
        .Package => return error.BadSystemState,
    };
    const tag = movecall.objectTypeTag(arena, &mo.type_) catch return error.BadSystemState;
    const lay = (movecall.objectLayouts(arena, cfg, snapSource(snap), &.{system_pkg}, tag) catch return error.NoFramework) orelse return error.NoFramework;
    const field = types.layout.decode(arena, lay.plain, mo.contents) catch return error.BadSystemState;
    // Field<u64, Inner> { id, name, value }
    if (lay.annotated.* != .@"struct" or field != .@"struct" or field.@"struct".len != 3) return error.BadSystemState;
    const inner_lay = lay.annotated.@"struct".fields[2].layout;
    if (inner_lay != .@"struct") return error.BadSystemState;
    const vals = field.@"struct"[2];
    if (vals != .@"struct") return error.BadSystemState;
    const names = inner_lay.@"struct".fields;
    if (names.len != vals.@"struct".len) return error.BadSystemState;
    var out: SystemSummary = .{ .epoch = 0, .protocol_version = 0, .reference_gas_price = 0, .epoch_start_timestamp_ms = 0, .active_validators = 0, .wrapper_version = wrapper.version };
    var seen: u8 = 0;
    for (names, vals.@"struct") |f, v| {
        const n = f.name.@"0";
        if (std.mem.eql(u8, n, "epoch")) {
            out.epoch = try u64Of(v);
            seen |= 1;
        } else if (std.mem.eql(u8, n, "protocol_version")) {
            out.protocol_version = try u64Of(v);
            seen |= 2;
        } else if (std.mem.eql(u8, n, "reference_gas_price")) {
            out.reference_gas_price = try u64Of(v);
            seen |= 4;
        } else if (std.mem.eql(u8, n, "epoch_start_timestamp_ms")) {
            out.epoch_start_timestamp_ms = try u64Of(v);
            seen |= 8;
        } else if (std.mem.eql(u8, n, "validators")) {
            // ValidatorSet { total_stake, active_validators: vector<Validator>, ... }
            if (v != .@"struct" or v.@"struct".len < 2 or v.@"struct"[1] != .vector) return error.BadSystemState;
            out.active_validators = @intCast(v.@"struct"[1].vector.len);
            seen |= 16;
        }
    }
    if (seen != 31) return error.BadSystemState;
    return out;
}

fn u64Of(v: types.layout.Value) error{BadSystemState}!u64 {
    return switch (v) {
        .u64 => |x| x,
        else => error.BadSystemState,
    };
}

/// The `EpochEnv` of the snapshot's live system state.
pub fn fromSnapshot(arena: Allocator, snap: *const store.Snapshot, chain_id: Id, layout_cfg: *const protocol.ProtocolConfig) Error!root.EpochEnv {
    const s = try readSystem(arena, snap, layout_cfg);
    const cfg = protocol.get(s.protocol_version, .mainnet) catch return error.UnknownProtocolVersion;
    return .{
        .chain_id = chain_id,
        .epoch = s.epoch,
        .pv = s.protocol_version,
        .cfg = cfg,
        .rgp = s.reference_gas_price,
        .epoch_start_ms = s.epoch_start_timestamp_ms,
        .committee_size = s.active_validators,
    };
}

/// A thread-safe cache over a store for `service.EnvSource`: decodes the system state again only
/// when the `0x5` wrapper object changed (every epoch change and staking call mutates it).
pub const Cache = struct {
    gpa: Allocator,
    io: std.Io,
    st: *store.Store,
    chain_id: Id,
    /// Protocol config used to build the layout VM before the first decode (the newest known).
    layout_cfg: *const protocol.ProtocolConfig,
    mu: std.Io.Mutex = .init,
    env: ?root.EpochEnv = null,
    wrapper_version: u64 = 0,
    failures: u64 = 0,

    pub fn source(c: *Cache) @import("service.zig").EnvSource {
        return .{ .ctx = c, .get = get };
    }

    fn get(ctx: *const anyopaque) ?root.EpochEnv {
        const c: *Cache = @ptrCast(@alignCast(@constCast(ctx)));
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        var snap = c.st.snapshot();
        defer snap.release();
        const w = snap.liveObject(&system_state) orelse return c.env;
        if (c.env != null and w.version == c.wrapper_version) return c.env;
        var arena: std.heap.ArenaAllocator = .init(c.gpa);
        defer arena.deinit();
        const cfg = if (c.env) |e| e.cfg else c.layout_cfg;
        const env = fromSnapshot(arena.allocator(), &snap, c.chain_id, cfg) catch |e| {
            c.failures += 1;
            if (c.failures < 5 or c.failures % 1000 == 0) std.log.warn("rpc_exec: system state decode: {s}", .{@errorName(e)});
            return c.env;
        };
        c.env = env;
        c.wrapper_version = w.version;
        return env;
    }
};
