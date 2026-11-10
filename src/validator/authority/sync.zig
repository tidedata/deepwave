//! A tiny spin lock for short critical sections shared between the handler thread, the consensus
//! threads and API threads (map lookups and inserts; never held across I/O).
const std = @import("std");

pub const Spin = struct {
    v: std.atomic.Value(u32) = .init(0),
    pub fn lock(s: *Spin) void {
        while (s.v.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    pub fn unlock(s: *Spin) void {
        s.v.store(0, .release);
    }
};
