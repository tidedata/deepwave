#!/bin/bash
# Events burst while the subscriptions are open: A and B each emit Ping, Pong<Marker>, Pong<Other>, both, Bumped.
set -x
export PATH=$HOME/sui/target/release:$PATH
C="sui client --client.config $HOME/ln/client.yaml"
source <(tr ' ' '\n' < $HOME/act.env)
for s in $A $B; do
  $C switch --address $s
  $C call --package $PKG --module emitter --function ping --args 7 --gas-budget 10000000 --json | jq -r .digest
  $C call --package $PKG --module emitter --function pong_marker --args 8 --gas-budget 10000000 --json | jq -r .digest
  $C call --package $PKG --module emitter --function pong_other --args 9 --gas-budget 10000000 --json | jq -r .digest
  $C call --package $PKG --module emitter --function both --args 10 --gas-budget 10000000 --json | jq -r .digest
  $C call --package $PKG --module counter --function bump --args $CTR --gas-budget 10000000 --json | jq -r .digest
done
$C switch --address $A
