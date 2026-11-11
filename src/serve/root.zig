//! serve: gRPC v2 read API (sui.rpc.v2) over HTTP/2, protobuf rendering from raw BCS.
//! Owner lane: serve. Interface: CONTRACTS.md. Only the serve lane edits files in src/serve/.
const std = @import("std");

pub const conformance = @import("conformance.zig");
pub const proto = @import("proto.zig");
pub const mask = @import("mask.zig");
pub const b58 = @import("b58.zig");
pub const render_checkpoint = @import("render_checkpoint.zig");
pub const render_sig = @import("render_sig.zig");
pub const typestr = @import("typestr.zig");
pub const render_object = @import("render_object.zig");
pub const render_tx = @import("render_tx.zig");
pub const h2 = @import("h2/root.zig");
pub const balance = @import("balance.zig");
pub const service = @import("service.zig");
pub const objset = @import("objset.zig");
pub const exec_error = @import("exec_error.zig");
pub const txobjects = @import("txobjects.zig");
pub const status = @import("status.zig");
pub const traffic = @import("traffic.zig");
pub const schema = @import("schema.zig");
pub const ledger = @import("ledger.zig");
pub const movepkg = @import("movepkg.zig");
pub const reqdecode = @import("reqdecode.zig");
pub const router = @import("router.zig");
pub const reflection = @import("reflection.zig");
pub const stream_conn = @import("stream_conn.zig");
pub const lh_core = @import("lh_core.zig");
pub const lh_scan = @import("lh_scan.zig");
pub const lh_service = @import("lh_service.zig");
pub const clever = @import("clever.zig");
pub const txfilter = @import("txfilter.zig");
pub const watermark = @import("watermark.zig");
pub const subscribe = @import("subscribe.zig");
// epoch-pkg lane (DROP-IN G6, G8)
pub const sysstate = @import("sysstate.zig");
pub const protocfg = @import("protocfg.zig");
pub const rpcindex = @import("rpcindex.zig");
pub const epoch = @import("epoch.zig");
pub const names = @import("names.zig");
pub const movelayout = @import("movelayout.zig");
pub const loopback = @import("loopback.zig");
pub const pbvalue = @import("pbvalue.zig");
pub const render_json = @import("render_json.zig");
pub const objdisplay = @import("objdisplay.zig");
pub const cpcache = @import("cpcache.zig");
pub const display = @import("display/root.zig");
pub const jsonapi = @import("jsonapi.zig");
pub const verifysig = @import("verifysig.zig");
pub const sdkjson = @import("sdkjson.zig");
// sui.rpc.v2alpha.ProofService (lane rpc-rest-proof)
pub const merkle = @import("merkle.zig");
pub const proof = @import("proof.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("test_transport.zig");
    _ = @import("stress_uaf.zig");
    _ = @import("test_stop_store.zig");
    std.testing.refAllDecls(lh_core);
    std.testing.refAllDecls(lh_scan);
    std.testing.refAllDecls(lh_service);
    _ = &service.Service.handler;
}
