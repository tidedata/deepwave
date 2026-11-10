"""StateService latency: ListOwnedObjects, ListBalances and ListDynamicFields over seeds from
seed.py, one connection per thread, end to end (gRPC-web). sui-node through the tunnel: one thread,
--rate 18 (never above 20 req/s); `--rtt` measures GetServiceInfo first and reports p50/p99 minus
the median round trip. zui: any --threads (load), --rate 0 = unthrottled.
Usage: latency.py --port P --seeds seeds.json [--n 600] [--threads 1] [--rate 18] [--rtt] [--out f.json]"""
import argparse, json, os, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pb

ap = argparse.ArgumentParser()
ap.add_argument("--host", default="127.0.0.1")
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--seeds", required=True)
ap.add_argument("--n", type=int, default=600, help="requests per method per thread")
ap.add_argument("--threads", type=int, default=1)
ap.add_argument("--rate", type=float, default=18.0, help="per thread; 0 = unthrottled")
ap.add_argument("--page", type=int, default=50)
ap.add_argument("--rtt", action="store_true")
ap.add_argument("--out")
a = ap.parse_args()
seeds = json.load(open(a.seeds))
addrs = seeds["addresses"]
parents = [p["id"] for p in seeds["parents"]]

def owned(o): return pb.field_bytes(1, o) + pb.field_varint(2, a.page)
def bals(o): return pb.field_bytes(1, o) + pb.field_varint(2, a.page)
def dfs(p): return pb.field_bytes(1, p) + pb.field_varint(2, a.page)
methods = [("ListOwnedObjects", addrs, owned), ("ListBalances", addrs, bals), ("ListDynamicFields", parents, dfs)]

lat = {m: [] for m, _, _ in methods}
errs = {m: 0 for m, _, _ in methods}
mu = threading.Lock()

def worker(t):
    c = pb.Client(a.host, a.port, rate=a.rate if a.rate > 0 else 1e9)
    for i in range(a.n):
        for m, pool, req in methods:
            x = pool[(i * a.threads + t) % len(pool)]
            t0 = time.monotonic()
            st, msg, resp, _ = c.call("StateService", m, req(x))
            dt = (time.monotonic() - t0) * 1000
            with mu:
                lat[m].append(dt)
                if st != 0: errs[m] += 1

rtt = None
if a.rtt:
    c = pb.Client(a.host, a.port, rate=a.rate if a.rate > 0 else 1e9)
    r = []
    for _ in range(60):
        t0 = time.monotonic(); c.call("LedgerService", "GetServiceInfo", b""); r.append((time.monotonic() - t0) * 1000)
    rtt = sorted(r)[len(r) // 2]
t0 = time.monotonic()
ts = [threading.Thread(target=worker, args=(t,)) for t in range(a.threads)]
for t in ts: t.start()
for t in ts: t.join()
wall = time.monotonic() - t0

def pct(v, p): v = sorted(v); return v[min(len(v) - 1, int(len(v) * p))]
out = {"threads": a.threads, "rate": a.rate, "wall_s": round(wall, 1), "rtt_ms": rtt, "methods": {}}
for m, _, _ in methods:
    v = lat[m]
    row = {"n": len(v), "errors": errs[m], "p50": round(pct(v, .5), 2), "p90": round(pct(v, .9), 2), "p99": round(pct(v, .99), 2), "max": round(max(v), 2)}
    if rtt is not None:
        row["p50_minus_rtt"] = round(row["p50"] - rtt, 2); row["p99_minus_rtt"] = round(row["p99"] - rtt, 2)
    out["methods"][m] = row
print(json.dumps(out, indent=1))
if a.out: json.dump(out, open(a.out, "w"), indent=1)
