"""Minimal sui.rpc.v2 gRPC client over curl (h2c), plus a protobuf wire decoder.
Rate limited (default 15 req/s) for the live sui-node. Used by the render lane's capture scripts."""
import os, struct, subprocess, threading, time
from concurrent.futures import ThreadPoolExecutor

URL = os.environ.get("SUI_NODE", "http://127.0.0.1:19000")
RATE = float(os.environ.get("RPS", "15"))
_next = [0.0]
_lock = threading.Lock()
POOL = ThreadPoolExecutor(int(os.environ.get("CONC", "12")))


def pmap(fn, items):
    """Runs fn over items concurrently (the rate limit stays global); results in order."""
    return list(POOL.map(fn, items))


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def fld(num, wt, payload):
    key = varint((num << 3) | wt)
    if wt == 0:
        return key + varint(payload)
    if isinstance(payload, str):
        payload = payload.encode()
    return key + varint(len(payload)) + payload


def mask(paths):
    return b"".join(fld(1, 2, p) for p in paths)


def call(method, body, service="LedgerService"):
    with _lock:
        now = time.time()
        slot = max(now, _next[0])
        _next[0] = slot + 1.0 / RATE
    if slot > now:
        time.sleep(slot - now)
    frame = b"\x00" + struct.pack(">I", len(body)) + body
    p = subprocess.run(
        ["curl", "-s", "--http2-prior-knowledge", "-X", "POST", "-H", "content-type: application/grpc",
         "-H", "te: trailers", "--data-binary", "@-", "-D", "/dev/stderr",
         f"{URL}/sui.rpc.v2.{service}/{method}"],
        input=frame, capture_output=True, timeout=60)
    data = p.stdout
    hdrs = p.stderr.decode(errors="replace").lower()
    status = 0
    for line in hdrs.splitlines():
        if line.startswith("grpc-status:"):
            status = int(line.split(":", 1)[1].strip())
    if len(data) < 5:
        return status, b""
    n = struct.unpack(">I", data[1:5])[0]
    return status, data[5:5 + n]


def call_stream(method, body, service="LedgerService"):
    """A server-streaming call: (grpc-status, [message bytes of every frame])."""
    with _lock:
        now = time.time()
        slot = max(now, _next[0])
        _next[0] = slot + 1.0 / RATE
    if slot > now:
        time.sleep(slot - now)
    frame = b"\x00" + struct.pack(">I", len(body)) + body
    p = subprocess.run(
        ["curl", "-s", "--http2-prior-knowledge", "-X", "POST", "-H", "content-type: application/grpc",
         "-H", "te: trailers", "--data-binary", "@-", "-D", "/dev/stderr",
         f"{URL}/sui.rpc.v2.{service}/{method}"],
        input=frame, capture_output=True, timeout=120)
    data = p.stdout
    status = 0
    for line in p.stderr.decode(errors="replace").lower().splitlines():
        if line.startswith("grpc-status:"):
            status = int(line.split(":", 1)[1].strip())
    out, i = [], 0
    while i + 5 <= len(data):
        n = struct.unpack(">I", data[i + 1:i + 5])[0]
        out.append(data[i + 5:i + 5 + n])
        i += 5 + n
    return status, out


def parse(buf):
    """Wire decode to a list of (field, wiretype, value) with raw bytes for length-delimited."""
    out, i = [], 0
    while i < len(buf):
        k, i = _rv(buf, i)
        f, wt = k >> 3, k & 7
        if wt == 0:
            v, i = _rv(buf, i)
        elif wt == 2:
            ln, i = _rv(buf, i)
            v = buf[i:i + ln]
            i += ln
        elif wt == 1:
            v = buf[i:i + 8]; i += 8
        elif wt == 5:
            v = buf[i:i + 4]; i += 4
        else:
            raise ValueError("wiretype %d" % wt)
        out.append((f, wt, v))
    return out


def _rv(b, i):
    n = s = 0
    while True:
        c = b[i]; i += 1
        n |= (c & 0x7F) << s
        s += 7
        if c < 0x80:
            return n, i
