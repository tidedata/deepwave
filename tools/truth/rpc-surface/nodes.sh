#!/bin/bash
# nodes.sh start|stop <variant>...: run sui-node 1.83.1 with ~/cfg/<variant>.yaml (log ~/nodes/<v>/node.log)
cmd=$1; shift
for v in "$@"; do
  mkdir -p ~/nodes/$v
  if [ $cmd = start ]; then
    RUST_LOG=info,sui_core=warn,anemo=warn nohup ~/sui/target/release/sui-node --config-path ~/cfg/$v.yaml > ~/nodes/$v/node.log 2>&1 &
    echo $! > ~/nodes/$v/pid
  else
    kill $(cat ~/nodes/$v/pid) 2>/dev/null
  fi
done
