#!/usr/bin/env python3
"""Write the fullnode.yaml of every capture variant into ~/cfg/<variant>.yaml and ~/variants.json (ports).
Seed peers and genesis come from the `sui genesis` working dir ~/ln (its fullnode.yaml)."""
import json, os, yaml

H = os.path.expanduser("~")
base = yaml.safe_load(open(f"{H}/ln/fullnode.yaml"))
seeds = base.get("p2p-config", {}).get("seed-peers", [])
STRICT = {"client-id-source": "socket-addr", "connection-blocklist-ttl-sec": 60, "dry-run": False,
          "spam-sample-rate": 1.0, "channel-capacity": 100,
          "spam-policy-type": {"freq-threshold": {"client-threshold": 3, "window-size-secs": 5, "update-interval-secs": 1}},
          "error-policy-type": {"freq-threshold": {"client-threshold": 2, "window-size-secs": 5, "update-interval-secs": 1}}}
DYN = {"deny-dyn-false": "False", "deny-dyn-int": "1", "deny-dyn-error": "1 // 0", "deny-dyn-true": "True"}
E = json.load(open(f"{H}/act.env.json")) if os.path.exists(f"{H}/act.env.json") else {}
V = {
    "idx": {"rpc": {"enable-indexing": True}, "ingest": True},
    "noidx": {"rpc": {}},
    "tls": {"rpc": {"enable-indexing": True, "tls": {"cert": f"{H}/cfg/tls/cert.pem", "key": f"{H}/cfg/tls/key.pem"}}},
    "timeout": {"rpc": {"enable-indexing": True, "grpc-timeout-ms": 1}},
    "limits": {"rpc": {"enable-indexing": True}, "top": {"grpc-load-shed": True, "grpc-concurrency-limit": 1}},
    "deny-lists": {"deny": {"object-deny-list": [E.get("CTR"), E.get("T1")], "package-deny-list": [E.get("PKG")],
                            "address-deny-list": [E.get("B")]}},
    "deny-publish": {"deny": {"package-publish-disabled": True}},
    "deny-upgrade": {"deny": {"package-upgrade-disabled": True}},
    "deny-shared": {"deny": {"shared-object-disabled": True}},
    "deny-user": {"deny": {"user-transaction-disabled": True}},
    "deny-receiving": {"deny": {"receiving-objects-disabled": True}},
    "deny-receiving-object": {"deny": {"object-deny-list": [E.get("T2")]}},
    "deny-zklogin-sig": {"deny": {"zklogin-sig-disabled": True}},
    "deny-zklogin-providers": {"deny": {"zklogin-disabled-providers": ["Google", "Facebook"]}},
    "deny-gasless": {"deny": {"gasless-disabled": True}},
    "deny-no-early-validation": {"deny": {"user-transaction-disabled": True},
                                 "top": {"transaction-driver-config": {"enable-early-validation": False}}},
    "traffic-default": {"rpc": {}},
    "traffic-strict": {"policy": STRICT},
    "traffic-xff1": {"policy": dict(STRICT, **{"client-id-source": {"x-forwarded-for": 1}})},
    "traffic-xff2": {"policy": dict(STRICT, **{"client-id-source": {"x-forwarded-for": 2}})},
    "traffic-null": {"policy": None},
    "traffic-noop": {"policy": {"spam-policy-type": "NoOp", "error-policy-type": "NoOp", "dry-run": False}},
    "traffic-dry": {"policy": dict(STRICT, **{"dry-run": True})},
}
for k, prog in DYN.items():
    V[k] = {"deny": {"dynamic-transaction-checks": prog}}
V["sub-limit"] = {"rpc": {"subscription-max-subscribers": 1, "subscription-watermark-interval": 5}}
os.makedirs(f"{H}/cfg", exist_ok=True)
ports = {}
for i, (name, v) in enumerate(V.items()):
    p = {"rpc": 9100 + i, "https": 9500 + i, "admin": 1400 + i, "metrics": 9300 + i, "p2p": 8200 + i}
    ports[name] = p
    c = {"db-path": f"{H}/nodes/{name}/db", "network-address": f"/ip4/127.0.0.1/tcp/{7700 + i}/http",
         "json-rpc-address": f"127.0.0.1:{p['rpc']}", "metrics-address": f"127.0.0.1:{p['metrics']}",
         "admin-interface-port": p["admin"],
         "genesis": {"genesis-file-location": f"{H}/ln/genesis.blob"},
         "p2p-config": {"listen-address": f"127.0.0.1:{p['p2p']}", "external-address": f"/ip4/127.0.0.1/udp/{p['p2p']}",
                        "seed-peers": seeds}}
    rpc = dict(v.get("rpc", {}))
    if "tls" in rpc:
        rpc["https-address"] = f"127.0.0.1:{p['https']}"
    c["rpc"] = rpc
    if v.get("ingest"):
        c["checkpoint-executor-config"] = {"data-ingestion-dir": f"{H}/nodes/{name}/ingest"}
    if "deny" in v:
        c["transaction-deny-config"] = v["deny"]
    if "policy" in v:
        c["policy-config"] = v["policy"]
    c.update(v.get("top", {}))
    with open(f"{H}/cfg/{name}.yaml", "w") as f:
        yaml.safe_dump(c, f, sort_keys=False)
json.dump(ports, open(f"{H}/variants.json", "w"), indent=1)
print(" ".join(V))
