#!/bin/bash
# Build and sign the deny-case transactions (never executed on the deny nodes) -> ~/deny-txs.jsonl
export PATH=$HOME/sui/target/release:$PATH
C="sui client --client.config $HOME/ln/client.yaml"
source <(tr ' ' '\n' < $HOME/act.env)
GB="--gas-budget 50000000"
out=$HOME/deny-txs.jsonl; [ -z "$ONLY" ] && : > $out
mk() { # mk <name> <sender> <cmd...>
  [ -n "$ONLY" ] && [[ " $ONLY " != *" $1 "* ]] && return
  local name=$1 who=$2; shift 2
  $C switch --address $who >/dev/null
  local tx; tx=$("$@" $GB --serialize-unsigned-transaction 2>$HOME/prep-$name.err | tail -1)
  if [ -z "$tx" ]; then echo "FAIL $name: $(tail -3 $HOME/prep-$name.err)"; return; fi
  local sig; sig=$(sui keytool --keystore-path $HOME/ln/sui.keystore sign --address $who --data "$tx" --json | jq -r .suiSignature)
  echo "{\"name\":\"$name\",\"sender\":\"$who\",\"tx_b64\":\"$tx\",\"sig_b64\":\"$sig\"}" >> $out
  echo "ok $name"
}
coinA=$($C gas $A --json | jq -r '.gasCoins[0].gasCoinId')
mk transfer-a $A $C pay-sui --input-coins $coinA --recipients $B --amounts 1000
mk transfer-b $B $C pay-sui --input-coins $($C gas $B --json | jq -r '.gasCoins[0].gasCoinId') --recipients $A --amounts 1000
mk bump-shared $A $C call --package $PKG --module counter --function bump --args $CTR
mk ping-pkg $A $C call --package $PKG --module emitter --function ping --args 1
mk set-t1 $A $C call --package $PKG --module counter --function set_thing --args $T1 6
mk recv-t2 $A $C call --package $PKG --module counter --function recv --args $T1 $T2
rm -rf $HOME/evts2 && cp -r $HOME/box/evts $HOME/evts2 && rm -f $HOME/evts2/Pub.localnet.toml
(cd $HOME/evts2 && mk publish $A $C test-publish --build-env testnet)
(cd $HOME/box/evts && mk upgrade $A $C test-upgrade --build-env testnet --upgrade-capability $CAP)
$C switch --address $A >/dev/null
wc -l $out
