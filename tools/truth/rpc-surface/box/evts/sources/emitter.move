module evts::emitter;

use sui::event;

public struct Ping has copy, drop { value: u64 }
public struct Pong<phantom T> has copy, drop { value: u64 }
public struct Marker has drop {}
public struct Other has drop {}

public fun ping(value: u64) { event::emit(Ping { value }) }
public fun pong_marker(value: u64) { event::emit(Pong<Marker> { value }) }
public fun pong_other(value: u64) { event::emit(Pong<Other> { value }) }
public fun both(value: u64) {
    event::emit(Ping { value });
    event::emit(Pong<Marker> { value: value + 1 });
}
