module evts::counter;

use sui::event;

public struct Counter has key { id: UID, n: u64 }
public struct Bumped has copy, drop { n: u64, by: address }
public struct Thing has key, store { id: UID, v: u64 }

fun init(ctx: &mut TxContext) {
    transfer::share_object(Counter { id: object::new(ctx), n: 0 });
}

public fun bump(c: &mut Counter, ctx: &TxContext) {
    c.n = c.n + 1;
    event::emit(Bumped { n: c.n, by: ctx.sender() });
}

public fun new_thing(v: u64, ctx: &mut TxContext) {
    transfer::public_transfer(Thing { id: object::new(ctx), v }, ctx.sender());
}

public fun set_thing(t: &mut Thing, v: u64) { t.v = v; }

public fun delete_thing(t: Thing) {
    let Thing { id, v: _ } = t;
    id.delete();
}

public fun recv(parent: &mut Thing, r: transfer::Receiving<Thing>, ctx: &TxContext) {
    let t = transfer::public_receive(&mut parent.id, r);
    transfer::public_transfer(t, ctx.sender());
}
