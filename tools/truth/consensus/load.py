"""Transaction load for tools/truth/consensus/capture.sh (a Mysten localnet on loopback).

Usage: load.py SUI_BIN CLIENT_YAML CAP_DIR WORKERS

The 1.83.1 full node serves no JSON-RPC, so everything goes through the `sui` CLI (gRPC): gas
coins from `sui client gas`, validator addresses from the account keys of the generated validator
configs (`sui keytool convert` + `import` into a scratch keystore in CAP_DIR).

Each worker owns one gas coin of one of the genesis addresses and loops through owned transfers,
a read-only shared input (Clock), a randomness call (Random) and, every tenth round, a stake
request on the system state (mutable shared object; it also moves voting power at the next
epoch). Stops when CAP_DIR/stop-load exists. Counters go to CAP_DIR/load.stats.
"""
import json
import os
import subprocess
import sys
import threading
import time
import glob
import re

sui, client, cap, workers = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
stop = os.path.join(cap, "stop-load")
stats = {"ok": 0, "fail": 0}
by_kind = {}
lock = threading.Lock()


def cli(*args):
    return subprocess.run([sui, "client", "--client.config", client, *args], capture_output=True, text=True, timeout=120)


addrs = json.loads(cli("addresses", "--json").stdout)["addresses"]
addrs = [a[1] for a in addrs]
coins = {}
for a in addrs:
    got = json.loads(cli("gas", "--json", a).stdout)
    got = got["gasCoins"] if isinstance(got, dict) else got
    coins[a] = sorted(c["gasCoinId"] for c in got)
validators = []
vks = os.path.join(cap, "validators.keystore")
cfg_dir = os.path.dirname(client)
for y in sorted(glob.glob(os.path.join(cfg_dir, "*.yaml"))):
    if os.path.basename(y) in ("network.yaml", "fullnode.yaml", "client.yaml"):
        continue
    m = re.search(r"account-key-pair:\s*\n\s*value: (\S+)", open(y).read())
    if not m:
        continue
    conv = json.loads(subprocess.run([sui, "keytool", "--json", "convert", m.group(1)], capture_output=True, text=True).stdout)
    imp = subprocess.run([sui, "keytool", "--keystore-path", vks, "--json", "import", conv["bech32WithFlag"], "ed25519"],
                         capture_output=True, text=True).stdout
    validators.append(re.search(r'"suiAddress":\s*"(0x[0-9a-f]+)"', imp).group(1))
slots = []
for k in range(max(len(c) for c in coins.values())):
    for a in addrs:
        if k < len(coins[a]):
            slots.append((a, coins[a][k]))
slots = slots[:workers]
print(f"load: {len(slots)} workers over {len(addrs)} addresses, {len(validators)} validators", flush=True)


def worker(i, addr, gas):
    n = 0
    while not os.path.exists(stop):
        n += 1
        common = ["--sender", f"@{addr}", "--gas-coin", f"@{gas}", "--gas-budget", "50000000"]
        if n % 10 == 0:
            kind = "stake"
            v = validators[(i + n) % len(validators)]
            cmd = ["--split-coins", "gas", "[1000000000]", "--assign", "s",
                   "--move-call", "0x3::sui_system::request_add_stake", "@0x5", "s.0", f"@{v}"]
        elif n % 3 == 0:
            kind = "random"
            cmd = ["--move-call", "0x2::random::new_generator", "@0x8"]
        elif n % 3 == 1:
            kind = "transfer"
            cmd = ["--split-coins", "gas", "[1000]", "--assign", "c", "--transfer-objects", "[c.0]", f"@{addr}"]
        else:
            kind = "clock"
            cmd = ["--move-call", "0x2::clock::timestamp_ms", "@0x6"]
        try:
            r = cli("ptb", *cmd, *common)
            ok = r.returncode == 0 and "Status: Success" in r.stdout
        except subprocess.TimeoutExpired:
            ok = False
            r = None
        with lock:
            stats["ok" if ok else "fail"] += 1
            k = by_kind.setdefault(kind, [0, 0])
            k[0 if ok else 1] += 1
            if not ok and stats["fail"] <= 20 and r is not None:
                print(f"fail {kind}: {r.stdout[-400:]} {r.stderr[-400:]}", flush=True)
        if not ok:
            time.sleep(1)


ts = [threading.Thread(target=worker, args=(i, a, g), daemon=True) for i, (a, g) in enumerate(slots)]
for t in ts:
    t.start()
while not os.path.exists(stop):
    time.sleep(10)
    with lock:
        line = json.dumps({"t": int(time.time()), **stats, "kinds": by_kind})
    with open(os.path.join(cap, "load.stats"), "a") as f:
        f.write(line + "\n")
    print(line, flush=True)
for t in ts:
    t.join(timeout=150)
