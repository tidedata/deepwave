// zui-truth-exec funds-sched: an object whose balance a transaction withdraws from at runtime
// (`balance::withdraw_funds_from_object`), so two withdrawals read at one accumulator version
// exercise the unsettled object withdrawals (G5). Built with Mysten's `sui move build`
// (tools/truth/exec/README.md); the tool publishes the bytecode at a fixed id.
module vault::vault;

use sui::balance;

public struct Vault has key, store {
    id: UID,
}

/// Withdraws `amount` of `T` from the vault's object balance and sends it to `recipient`'s
/// address balance.
public fun withdraw<T>(v: &mut Vault, amount: u64, recipient: address) {
    let w = balance::withdraw_funds_from_object<T>(&mut v.id, amount);
    balance::send_funds(balance::redeem_funds(w), recipient);
}
