//! Deferred server streams, transport-neutral (the contract the stream lane's `stream_conn.zig`
//! introduced, kept as is):
//! - a handler that keeps its stream open calls `attach(req.stream_id, pump)` and returns
//!   `Status.deferred`;
//! - the runtime then sends the response headers and runs `pump.run(ctx, &link)`: on its own
//!   thread for h2c (many streams share a connection), on the connection's thread for gRPC-web
//!   over HTTP/1.1 (one response at a time);
//! - the pump writes messages with `Link.send` (compressed and framed for the transport), ends the
//!   stream with `Link.finish`, and polls `Link.blocked` (true while earlier bytes wait for h2
//!   window; null once the stream or the connection is gone);
//! - `pump.wake` is called when the connection reads frames (window updates) or closes;
//! - `pump.done` (optional) is called exactly once, after `run` or instead of it.
const std = @import("std");
const Status = @import("conn.zig").Status;

pub const Pump = struct {
    ctx: *anyopaque,
    /// Runs until the stream ends.
    run: *const fn (ctx: *anyopaque, link: *Link) void,
    /// Wakes a pump waiting for work (window update, connection closing). Thread-safe. A
    /// runtime may call it after `run` returned (the context must stay valid until `done`),
    /// never once `done` started: `done` may free the context.
    wake: *const fn (ctx: *anyopaque) void,
    /// Optional (the stream lane's contract): called exactly once, after `run` returns, or in
    /// place of `run` when the pump never starts (the client left before the headers went
    /// out, the stream was refused at `max_pumps`, no thread could be spawned, the connection
    /// ended first). A pump releases what it holds here (subscribe.zig: the hub slot).
    done: ?*const fn (ctx: *anyopaque) void = null,
};

pub const Link = struct {
    impl: *anyopaque,
    vt: *const VTable,
    stream_id: u32,

    pub const VTable = struct {
        send: *const fn (impl: *anyopaque, stream_id: u32, payload: []const u8) error{Closed}!void,
        finish: *const fn (impl: *anyopaque, stream_id: u32, status: Status, text: []const u8, details_bin: []const u8) void,
        blocked: *const fn (impl: *anyopaque, stream_id: u32) ?bool,
    };

    /// Queues one gRPC message (compressed when the stream negotiated it) and writes what the
    /// transport allows.
    pub fn send(l: *Link, payload: []const u8) error{Closed}!void {
        return l.vt.send(l.impl, l.stream_id, payload);
    }
    /// Ends the stream with trailers.
    pub fn finish(l: *Link, status: Status, text: []const u8) void {
        l.vt.finish(l.impl, l.stream_id, status, text, "");
    }
    pub fn finishDetails(l: *Link, status: Status, text: []const u8, details_bin: []const u8) void {
        l.vt.finish(l.impl, l.stream_id, status, text, details_bin);
    }
    /// True while earlier messages still wait for window; null once the stream or the connection
    /// is gone.
    pub fn blocked(l: *Link) ?bool {
        return l.vt.blocked(l.impl, l.stream_id);
    }
};

/// The runtime of the request a handler is answering on this thread (set around the call).
pub const Attacher = struct {
    ctx: *anyopaque,
    attach: *const fn (ctx: *anyopaque, stream_id: u32, pump: Pump) bool,
};

pub threadlocal var current: ?Attacher = null;

/// Called by a handler for the stream it answers with `Status.deferred`. False when the
/// connection cannot carry deferred streams (no streaming runtime around the call).
pub fn attach(stream_id: u32, p: Pump) bool {
    const a = current orelse return false;
    return a.attach(a.ctx, stream_id, p);
}

/// True when the calling handler runs under a runtime that carries deferred streams.
pub fn streaming() bool {
    return current != null;
}
