#!/bin/bash
# One-time chain activity before the captures: transfers, publish evts, things for proofs / receiving.
set -ex
export PATH=$HOME/sui/target/release:$PATH
C="sui client --client.config $HOME/ln/client.yaml"
ADDRS=($($C addresses --json | jq -r '.addresses[][1]'))
A=${ADDRS[0]}; B=${ADDRS[1]}
$C switch --address $A
for i in 1 2; do $C pay-sui --input-coins $($C gas --json | jq -r '.gasCoins[1].gasCoinId') --recipients $B --amounts 1000000000 --gas-budget 10000000 --json > /dev/null; done
cd $HOME/box/evts
$C publish --gas-budget 500000000 --json > $HOME/publish.json 2> $HOME/publish.err || $C test-publish --build-env testnet --gas-budget 500000000 --json > $HOME/publish.json 2>> $HOME/publish.err
PKG=$(jq -r '.objectChanges[] | select(.type=="published") | .packageId' $HOME/publish.json)
CTR=$(jq -r '.objectChanges[] | select(.objectType? and (.objectType|endswith("::counter::Counter"))) | .objectId' $HOME/publish.json)
CAP=$(jq -r '.objectChanges[] | select(.objectType? and (.objectType|endswith("::package::UpgradeCap"))) | .objectId' $HOME/publish.json)
thing() { $C call --package $PKG --module counter --function new_thing --args $1 --gas-budget 10000000 --json | jq -r '.objectChanges[] | select(.objectType? and (.objectType|endswith("::counter::Thing"))) | .objectId'; }
T1=$(thing 1); T2=$(thing 2); T3=$(thing 3)
$C call --package $PKG --module counter --function set_thing --args $T1 5 --gas-budget 10000000 --json > /dev/null
$C transfer --object-id $T2 --to $T1 --gas-budget 10000000 --json > /dev/null
$C call --package $PKG --module counter --function delete_thing --args $T3 --gas-budget 10000000 --json > $HOME/delete.json
$C call --package $PKG --module counter --function bump --args $CTR --gas-budget 10000000 --json > /dev/null
$C switch --address $B
TB=$(thing 9)
$C call --package $PKG --module counter --function bump --args $CTR --gas-budget 10000000 --json > /dev/null
cat > $HOME/act.env <<EOT
A=$A B=$B PKG=$PKG CTR=$CTR CAP=$CAP T1=$T1 T2=$T2 T3=$T3 TB=$TB
EOT
python3 -c "import json;print(json.dumps(dict(kv.split('=',1) for kv in open('$HOME/act.env').read().split())))" > $HOME/act.env.json
cat $HOME/act.env
