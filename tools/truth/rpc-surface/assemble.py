#!/usr/bin/env python3
"""Assemble the pulled capture tree (PULL dir from the box: vectors/, cfg/, ln/genesis.blob, chk/ converted with
`zui-dumper convert`, loaded.jsonl from `zui-dumper loaded`) into src/serve/vectors/rpc-surface. Usage: assemble.py PULL REPO"""
import base64, hashlib, json, os, re, shutil, sys

pull, repo = sys.argv[1], sys.argv[2]
dst = os.path.join(repo, "src/serve/vectors/rpc-surface")
shutil.rmtree(dst, ignore_errors=True)
os.makedirs(dst + "/localnet/chk")
os.makedirs(dst + "/configs/tls")


def fields(b):
    i = 0
    while i < len(b):
        k = 0; s = 0
        while True:
            c = b[i]; i += 1; k |= (c & 0x7F) << s; s += 7
            if c < 0x80: break
        f, t = k >> 3, k & 7
        if t == 0:
            v = 0; s = 0
            while True:
                c = b[i]; i += 1; v |= (c & 0x7F) << s; s += 7
                if c < 0x80: break
            yield f, v
        elif t == 2:
            n = 0; s = 0
            while True:
                c = b[i]; i += 1; n |= (c & 0x7F) << s; s += 7
                if c < 0x80: break
            yield f, b[i:i + n]; i += n
        elif t == 1: yield f, b[i:i + 8]; i += 8
        elif t == 5: yield f, b[i:i + 4]; i += 4
        else: raise ValueError(t)


def wm_cp(msg):  # SubscribeEventsResponse / ListCheckpointsResponse: watermark = 2 { checkpoint = 2 }
    out = []
    for f, v in fields(msg):
        if f == 2 and isinstance(v, bytes):
            out += [x for g, x in fields(v) if g == 2 and isinstance(x, int)]
    return out


RENAME = {"err-object-no-0x": "object-no-0x-prefix", "err-cursor-wrong-direction": "cursor-after-with-descending",
          "err-before-and-after": "cursor-before-and-after", "err-f-affected-expand": "f-affected-address-or-5x2",
          "err-sender-empty": "err-sender-empty-string"}
maxcp = 0
counts = {}
for feat in sorted(os.listdir(pull + "/vectors")):
    os.makedirs(f"{dst}/{feat}")
    out = open(f"{dst}/{feat}/cases.jsonl", "w")
    n = 0
    for line in open(f"{pull}/vectors/{feat}/cases.jsonl"):
        r = json.loads(line)
        r["name"] = RENAME.get(r["name"], r["name"])
        if feat == "config":
            body = base64.b64decode(r["resp"]["body_b64"])
            r["resp"]["body_sha256"] = hashlib.sha256(body).hexdigest()
            r["resp"]["body_len"] = len(body)
            # the Debug print embeds the whole loaded genesis (~18 MB): elide that field
            body = re.sub(rb"\n    genesis: Genesis \{\n.*?\n    \},\n", b"\n    genesis: Genesis { <elided> },\n", body, flags=re.S)
            r["resp"]["body_b64"] = base64.b64encode(body).decode()
            r["note"] = "body: Rust {:#?} of NodeConfig; the genesis field is elided, body_sha256/body_len are of the full body; keypairs are random per start"
        if feat in ("subscribe-events", "list-checkpoints") and not r["name"].startswith("sub-limit/"):
            for m in r["resp"].get("messages_b64", []):
                cps = wm_cp(base64.b64decode(m))
                if cps: maxcp = max(maxcp, max(cps))
        out.write(json.dumps(r) + "\n"); n += 1
    counts[feat] = n
last = maxcp + 2
for s in range(0, last + 1):
    shutil.copy(f"{pull}/chk/{s}.chk", f"{dst}/localnet/chk/{s}.chk")
shutil.copy(f"{pull}/ln/genesis.blob", f"{dst}/localnet/genesis.blob")
# each transaction's unchanged_loaded_runtime_objects (`zui-dumper loaded`): the .chk form drops them
if os.path.exists(pull + "/loaded.jsonl"):
    with open(pull + "/loaded.jsonl") as src, open(f"{dst}/localnet/loaded.jsonl", "w") as out:
        for line in src:
            if line.strip() and json.loads(line)["checkpoint"] <= last:
                out.write(line)
for f in os.listdir(pull + "/cfg"):
    if f.endswith(".yaml"):
        shutil.copy(f"{pull}/cfg/{f}", f"{dst}/configs/{f}")
for f in ("cert.pem", "key.pem"):
    shutil.copy(f"{pull}/cfg/tls/{f}", f"{dst}/configs/tls/{f}")
act = json.load(open(pull + "/act.env.json"))
meta = {"sui": "mainnet-v1.83.1 " + open(pull + "/sui-commit.txt").read().strip(), "chk_range": [0, last],
        "accounts_objects": act, "ports": json.load(open(pull + "/variants.final.json")),
        "home_on_capture_box": "/home/ubuntu (config paths)", "counts": counts}
json.dump(meta, open(f"{dst}/localnet/localnet.json", "w"), indent=1)
shutil.copy(pull + "/deny-txs.jsonl", f"{dst}/deny/txs.jsonl")
shutil.copy(pull + "/proof-objs.json", f"{dst}/proof/objects.json")
shutil.copy(pull + "/burst.log", f"{dst}/subscribe-events/burst.log")
print(json.dumps(counts), "chk 0..", last)
