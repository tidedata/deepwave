// Links a package that may be refused at load: make_vm for this root fails when its dependency does.
module zbd::d;

public fun f(): u64 { zbig::b::one() + 1 }
