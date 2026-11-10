#!/usr/bin/env python3
"""Capture sui-node's wire behaviour on :9000 (gRPC-web over HTTP/1.1, h2c) as test vectors.

Usage: capture.py HOST:PORT OUTDIR [SEQ]
Run through the SSH tunnel (ssh -N -L 19000:127.0.0.1:9000 node), about 40 requests at < 10/s.
Each vector is the exact bytes the server sent (`<name>.resp`) next to the request (`<name>.req`).
h2c cases go through curl (`<name>.hdr` = headers + trailers, `<name>.body` = DATA payload).
"""
import base64, os, socket, subprocess, sys, threading, time

host, port = sys.argv[1].rsplit(":", 1)
port = int(port)
out = sys.argv[2]
os.makedirs(out, exist_ok=True)


def pb_str(field, s):
    b = s.encode() if isinstance(s, str) else s
    return bytes([field << 3 | 2]) + varint(len(b)) + b


def pb_u64(field, v):
    return bytes([field << 3]) + varint(v)


def varint(v):
    o = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            o.append(b | 0x80)
        else:
            o.append(b)
            return bytes(o)


def mask(*paths):
    return b"".join(pb_str(1, p) for p in paths)


def frame(msg, flag=0):
    return bytes([flag]) + len(msg).to_bytes(4, "big") + msg


def save(name, ext, data):
    with open(os.path.join(out, name + "." + ext), "wb") as f:
        f.write(data)


def h1(name, path, body, ctype="application/grpc-web+proto", extra=(), method="POST", read_s=2.0, text=False):
    if text:
        body = base64.b64encode(body)
    hdrs = [f"{method} {path} HTTP/1.1", f"host: {host}:{port}"]
    if method == "POST":
        hdrs += [f"content-type: {ctype}", "x-grpc-web: 1", f"content-length: {len(body)}"]
    hdrs += list(extra)
    req = ("\r\n".join(hdrs) + "\r\n\r\n").encode() + (body if method == "POST" else b"")
    s = socket.create_connection((host, port))
    s.sendall(req)
    s.settimeout(read_s)
    got = bytearray()
    t0 = time.time()
    try:
        while time.time() - t0 < read_s:
            d = s.recv(65536)
            if not d:
                break
            got += d
            if got.endswith(b"0\r\n\r\n") or (b"content-length: " in got.lower() and complete_cl(got)):
                break
    except socket.timeout:
        pass
    s.close()
    save(name, "req", req)
    save(name, "resp", bytes(got))
    print(name, len(got), got.split(b"\r\n", 1)[0])
    time.sleep(0.15)


def complete_cl(got):
    head, sep, rest = bytes(got).partition(b"\r\n\r\n")
    if not sep:
        return False
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            return len(rest) >= int(line.split(b":")[1])
    return False


def h2(name, path, body, extra=(), max_time=5):
    args = ["curl", "-s", "--http2-prior-knowledge", "-m", str(max_time), "-D", os.path.join(out, name + ".hdr"),
            "-o", os.path.join(out, name + ".body"), "-H", "content-type: application/grpc", "-H", "te: trailers"]
    for e in extra:
        args += ["-H", e]
    args += ["--data-binary", "@-", f"http://{host}:{port}{path}"]
    subprocess.run(args, input=body)
    save(name, "req", body)
    print(name, open(os.path.join(out, name + ".hdr"), "rb").read().split(b"\r\n", 1)[0])
    time.sleep(0.15)


def idle_h1(result):
    s = socket.create_connection((host, port))
    body = frame(b"")
    s.sendall(f"POST /sui.rpc.v2.LedgerService/GetServiceInfo HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: {len(body)}\r\n\r\n".encode() + body)
    s.settimeout(60)
    t0 = None
    got = bytearray()
    while True:
        d = s.recv(65536)
        if t0 is None:
            t0 = time.time()
        if not d:
            break
        got += d
    result["h1_idle_close_s"] = round(time.time() - t0, 2)


def idle_h2(result):
    s = socket.create_connection((host, port))
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes([0, 0, 0, 4, 0, 0, 0, 0, 0]))
    s.settimeout(70)
    t0 = time.time()
    got = bytearray()
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            got += d
            if time.time() - t0 > 65:
                break
    except socket.timeout:
        pass
    save("h2-settings", "resp", bytes(got[:200]))
    result["h2_idle_close_s"] = round(time.time() - t0, 2)


si = frame(b"")
h1("h1-svcinfo-bin", "/sui.rpc.v2.LedgerService/GetServiceInfo", si)
h1("h1-svcinfo-text", "/sui.rpc.v2.LedgerService/GetServiceInfo", si, ctype="application/grpc-web-text", text=True)
h1("h1-svcinfo-bin-zstd", "/sui.rpc.v2.LedgerService/GetServiceInfo", si, extra=["grpc-accept-encoding: zstd"])
h1("h1-svcinfo-text-zstd", "/sui.rpc.v2.LedgerService/GetServiceInfo", si, ctype="application/grpc-web-text", text=True, extra=["grpc-accept-encoding: zstd"])
h1("h1-svcinfo-bin-gzip", "/sui.rpc.v2.LedgerService/GetServiceInfo", si, extra=["grpc-accept-encoding: gzip"])
h1("h1-svcinfo-bin-identity-zstd", "/sui.rpc.v2.LedgerService/GetServiceInfo", si, extra=["grpc-accept-encoding: identity, deflate, zstd, gzip"])
h1("h1-svcinfo-grpcweb-plain", "/sui.rpc.v2.LedgerService/GetServiceInfo", si, ctype="application/grpc-web")
h1("h1-svcinfo-textproto", "/sui.rpc.v2.LedgerService/GetServiceInfo", si, ctype="application/grpc-web-text+proto", text=True)
h1("h1-svcinfo-origin", "/sui.rpc.v2.LedgerService/GetServiceInfo", si, extra=["origin: https://example.com"])
h1("h1-svcinfo-sdk", "/sui.rpc.v2.LedgerService/GetServiceInfo", si, ctype="application/grpc-web-text", text=True,
   extra=["accept: application/grpc-web-text", "x-sui-client-protocol-version: 138", "x-user-agent: grpc-web-javascript/0.1", "grpc-timeout: 30000m"])
h1("h1-svcinfo-grpc-h1", "/sui.rpc.v2.LedgerService/GetServiceInfo", si, ctype="application/grpc")
seq = int(sys.argv[3]) if len(sys.argv) > 3 else None
if seq is None:
    raise SystemExit("pass SEQ (a recent checkpoint)")
ck = frame(pb_u64(1, seq) + pb_str(3, mask("sequence_number", "digest", "summary.timestamp")))
h1("h1-ckpt-bin", "/sui.rpc.v2.LedgerService/GetCheckpoint", ck)
h1("h1-ckpt-text", "/sui.rpc.v2.LedgerService/GetCheckpoint", ck, ctype="application/grpc-web-text", text=True)
h1("h1-ckpt-bin-zstd", "/sui.rpc.v2.LedgerService/GetCheckpoint", ck, extra=["grpc-accept-encoding: zstd"])
ckbig = frame(pb_u64(1, seq) + pb_str(3, mask("summary.bcs", "contents.bcs", "transactions.effects.bcs")))
h1("h1-ckpt-big-text-zstd", "/sui.rpc.v2.LedgerService/GetCheckpoint", ckbig, ctype="application/grpc-web-text", text=True, extra=["grpc-accept-encoding: zstd"], read_s=4)
nf = frame(pb_str(1, "0x" + "00" * 31 + "de"))
h1("h1-obj-notfound-bin", "/sui.rpc.v2.LedgerService/GetObject", nf)
h1("h1-obj-notfound-text", "/sui.rpc.v2.LedgerService/GetObject", nf, ctype="application/grpc-web-text", text=True)
h1("h1-obj-bad-bin", "/sui.rpc.v2.LedgerService/GetObject", frame(pb_str(1, "zz")))
h1("h1-unimpl-method", "/sui.rpc.v2.LedgerService/Nope", si)
h1("h1-unknown-service", "/foo.Bar/Baz", si)
h1("h1-timeout", "/sui.rpc.v2.LedgerService/GetCheckpoint", ck, extra=["grpc-timeout: 1n"])
h1("h1-timeout-text", "/sui.rpc.v2.LedgerService/GetCheckpoint", ck, ctype="application/grpc-web-text", text=True, extra=["grpc-timeout: 1n"])
h1("h1-timeout-bad", "/sui.rpc.v2.LedgerService/GetServiceInfo", si, extra=["grpc-timeout: abc"])
h1("h1-req-gzip", "/sui.rpc.v2.LedgerService/GetServiceInfo", frame(b"", 1), extra=["grpc-encoding: gzip"])
h1("h1-req-zstd", "/sui.rpc.v2.LedgerService/GetServiceInfo", frame(b"", 1), extra=["grpc-encoding: zstd"])
h1("h1-req-flag-noenc", "/sui.rpc.v2.LedgerService/GetServiceInfo", frame(b"", 1))
h1("h1-req-short", "/sui.rpc.v2.LedgerService/GetServiceInfo", b"\x00\x00\x00")
h1("h1-req-twoframes", "/sui.rpc.v2.LedgerService/GetServiceInfo", si + si)
h1("h1-health-check", "/grpc.health.v1.Health/Check", frame(b""))
h1("h1-health-check-svc", "/grpc.health.v1.Health/Check", frame(pb_str(1, "sui.rpc.v2.LedgerService")))
h1("h1-health-check-unknown", "/grpc.health.v1.Health/Check", frame(pb_str(1, "nope.Svc")))
h1("h1-get-health", "/health", b"", method="GET")
h1("h1-get-health-thresh", "/health?threshold_seconds=1", b"", method="GET")
h1("h1-get-root", "/", b"", method="GET")
h1("h1-get-grpc-path", "/sui.rpc.v2.LedgerService/GetServiceInfo", b"", method="GET")
h1("h1-options", "/sui.rpc.v2.LedgerService/GetServiceInfo", b"", method="OPTIONS",
   extra=["origin: https://example.com", "access-control-request-method: POST", "access-control-request-headers: content-type,x-grpc-web"])
sub = frame(pb_str(1, mask("sequence_number")))
h1("h1-sub-bin", "/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", sub, read_s=2.5)
h1("h1-sub-text", "/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", sub, ctype="application/grpc-web-text", text=True, read_s=2.5)
h1("h1-sub-bin-zstd", "/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", sub, extra=["grpc-accept-encoding: zstd"], read_s=2.5)

h2("h2-svcinfo", "/sui.rpc.v2.LedgerService/GetServiceInfo", si)
h2("h2-svcinfo-zstd", "/sui.rpc.v2.LedgerService/GetServiceInfo", si, extra=["grpc-accept-encoding: zstd,gzip"])
h2("h2-ckpt", "/sui.rpc.v2.LedgerService/GetCheckpoint", ck)
h2("h2-obj-notfound", "/sui.rpc.v2.LedgerService/GetObject", nf)
h2("h2-unimpl-method", "/sui.rpc.v2.LedgerService/Nope", si)
h2("h2-timeout", "/sui.rpc.v2.LedgerService/GetCheckpoint", ck, extra=["grpc-timeout: 1n"])
h2("h2-req-gzip", "/sui.rpc.v2.LedgerService/GetServiceInfo", frame(b"", 1), extra=["grpc-encoding: gzip"])
h2("h2-health-check", "/grpc.health.v1.Health/Check", frame(b""))
h2("h2-reflection-list", "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", frame(pb_str(7, "")))
h2("h2-reflection-v1alpha-list", "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", frame(pb_str(7, "")))
h2("h2-sub", "/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", sub, max_time=2)
h2("h2-sub-zstd", "/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", sub, extra=["grpc-accept-encoding: zstd"], max_time=2)

res = {}
ts = [threading.Thread(target=idle_h1, args=(res,)), threading.Thread(target=idle_h2, args=(res,))]
[t.start() for t in ts]
[t.join() for t in ts]
print(res)
with open(os.path.join(out, "idle.txt"), "w") as f:
    f.write(repr(res) + "\n")
