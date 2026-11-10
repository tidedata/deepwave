"""Field-level diff of index-parity failures: diff.py <fixture.bin> <dump dir> [max]
Decodes sui-node's answer and zui's (ZUI_INDEX_DUMP files) as nested protobuf and prints paths that differ."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pb

def load(path):
    b = open(path, "rb").read(); i = 5
    n = struct.unpack_from("<I", b, i)[0]; i += 4
    for _ in range(n):
        ln = struct.unpack_from("<I", b, i)[0]; i += 4 + ln
    n = struct.unpack_from("<I", b, i)[0]; i += 4
    out = []
    for _ in range(n):
        def take(fmt):
            nonlocal i
            v = struct.unpack_from(fmt, b, i)[0]; i += struct.calcsize(fmt); return v
        def blob(fmt):
            nonlocal i
            ln = take(fmt); v = b[i:i + ln]; i += ln; return v
        name = blob("<H").decode(); path = blob("<H").decode(); body = blob("<I"); st = take("<I"); msg = blob("<H"); resp = blob("<I")
        out.append((name, path, body, st, msg, resp))
    return out

def tree(buf, depth=0):
    try:
        fs = list(pb.fields(buf))
    except Exception:
        return None
    out = []
    for n, wt, v in fs:
        if wt == 2 and depth < 6 and v and not all(32 <= c < 127 for c in v):
            t = tree(v, depth + 1)
            out.append((n, t if t is not None else v))
        elif wt == 2 and all(32 <= c < 127 for c in v):
            out.append((n, v.decode()))
        else:
            out.append((n, v))
    return out

def flat(t, prefix=""):
    res = []
    counts = {}
    for n, v in t:
        k = counts.get(n, 0); counts[n] = k + 1
        p = "%s%d[%d]" % (prefix, n, k)
        if isinstance(v, list): res += flat(v, p + ".")
        else: res.append((p, v))
    return res

cases = load(sys.argv[1]); d = sys.argv[2]; mx = int(sys.argv[3]) if len(sys.argv) > 3 else 20
shown = 0
for idx, (name, path, body, st, msg, resp) in enumerate(cases):
    f = os.path.join(d, "%s-%d.zui" % (os.path.basename(sys.argv[1]), idx))
    if not os.path.exists(f): continue
    z = open(f, "rb").read()
    a, b = dict(flat(tree(resp) or [])), dict(flat(tree(z) or []))
    keys = sorted(set(a) | set(b))
    diffs = [(k, a.get(k), b.get(k)) for k in keys if a.get(k) != b.get(k)]
    print("==", name, "diffs", len(diffs))
    for k, x, y in diffs[:8]:
        sx = (x.hex()[:80] if isinstance(x, bytes) else str(x)[:100]); sy = (y.hex()[:80] if isinstance(y, bytes) else str(y)[:100])
        print("   ", k, "\n      node:", sx, "\n      zui: ", sy)
    shown += 1
    if shown >= mx: break
