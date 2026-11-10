#!/bin/bash
# Start the capture localnet: 4 validators + the swarm fullnode on :9000 (CLI endpoint).
set -e
export PATH=$HOME/sui/target/release:$PATH
LN=$HOME/ln
if [ ! -f $LN/genesis.blob ]; then
  sui genesis --working-dir $LN --epoch-duration-ms 7200000 > $HOME/genesis.log 2>&1
fi
cd $HOME
nohup sui start --network.config $LN --fullnode-rpc-port 9000 > $HOME/start.log 2>&1 &
echo $! > $HOME/start.pid
for i in $(seq 60); do curl -s -o /dev/null localhost:9000 && break; sleep 2; done
echo started
