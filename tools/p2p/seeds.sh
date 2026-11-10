#!/usr/bin/env bash
# tools/p2p/seeds.sh [mainnet|testnet]. Testnet: Mysten's four tnt-ssfn seeds (sui scripts/compatibility).
# Prints mainnet's state-sync seed peers (Mysten's defaults plus
# nodeinfra, overclock and rpcpool) as deepwave's --p2p value: ip:8084@peerid,... (DNS resolved now).
set -euo pipefail
seeds=(
  mel-00.mainnet.sui.io@d32b55bdf1737ec415df8c88b3bf91e194b59ee3127e3f38ea46fd88ba2e7849
  ewr-00.mainnet.sui.io@c7bf6cb93ca8fdda655c47ebb85ace28e6931464564332bf63e27e90199c50ee
  ewr-01.mainnet.sui.io@3227f8a05f0faa1a197c075d31135a366a1c6f3d4872cb8af66c14dea3e0eb66
  lhr-00.mainnet.sui.io@c619a5e0f8f36eac45118c1f8bda28f0f508e2839042781f1d4a9818043f732c
  sui-mainnet-ssfn-1.nodeinfra.com@0c52ca8d2b9f51be4a50eb44ace863c05aadc940a7bd15d4d3f498deb81d7fc6
  sui-mainnet-ssfn-2.nodeinfra.com@1dbc28c105aa7eb9d1d3ac07ae663ea638d91f2b99c076a52bbded296bd3ed5c
  sui-mainnet-ssfn-ashburn-na.overclock.run@5ff8461ab527a8f241767b268c7aaf24d0312c7b923913dd3c11ee67ef181e45
  sui-mainnet-ssfn-dallas-na.overclock.run@e1a4f40d66f1c89559a195352ba9ff84aec28abab1d3aa1c491901a252acefa6
  ssn01.mainnet.sui.rpcpool.com@fadb7ccb0b7fc99223419176e707f5122fef4ea686eb8e80d1778588bf5a0bcd
  ssn02.mainnet.sui.rpcpool.com@13783584a90025b87d4604f1991252221e5fd88cab40001642f4b00111ae9b7e
)
if [ "${1:-mainnet}" = testnet ]; then
  seeds=(
    ewr-tnt-ssfn-00.testnet.sui.io@df8a8d128051c249e224f95fcc463f518a0ebed8986bbdcc11ed751181fecd38
    lax-tnt-ssfn-00.testnet.sui.io@f9a72a0a6c17eed09c27898eab389add704777c03e135846da2428f516a0c11d
    lhr-tnt-ssfn-00.testnet.sui.io@9393d6056bb9c9d8475a3cf3525c747257f17c6a698a7062cbbd1875bc6ef71e
    mel-tnt-ssfn-00.testnet.sui.io@c88742f46e66a11cb8c84aca488065661401ef66f726cb9afeb8a5786d83456e
  )
fi
out=()
for s in "${seeds[@]}"; do
  host=${s%@*}; id=${s#*@}
  ip=$( (getent ahostsv4 "$host" 2>/dev/null || dig +short A "$host" 2>/dev/null) | awk '/^[0-9.]+/{print $1; exit}')
  [ -n "$ip" ] && out+=("$ip:8084@$id")
done
(IFS=,; echo "${out[*]}")
