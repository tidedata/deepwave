"""Shared helpers for the rpc-surface captures (run on the capture box, python venv with h2 + protobuf,
protos compiled by grpc_tools.protoc into $PB, default ~/pb)."""
import base64, json, os, subprocess, sys, threading, time

sys.path.insert(0, os.environ.get("PB", os.path.expanduser("~/pb")))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from google.protobuf import field_mask_pb2  # noqa: E402
from sui.rpc.v2 import (filter_pb2 as F, subscription_service_pb2 as SS, ledger_service_pb2 as LS,  # noqa: E402
                        query_options_pb2 as Q, transaction_execution_service_pb2 as TX, transaction_pb2 as T,
                        signature_pb2 as SG, bcs_pb2 as BCS, event_pb2 as EV)
from sui.rpc.v2alpha import proof_service_pb2 as PR  # noqa: E402
import wire  # noqa: E402

OUT = os.environ.get("OUT", os.path.expanduser("~/vectors"))
HOST = "127.0.0.1"
B64 = wire.B64
VARIANTS = json.load(open(os.path.expanduser("~/variants.json"))) if os.path.exists(os.path.expanduser("~/variants.json")) else {}


def port(variant, kind="rpc"):
    return VARIANTS[variant][kind]


def mask(*paths):
    return field_mask_pb2.FieldMask(paths=list(paths))


def record(feature, name, variant, transport, path, method="POST", req_headers=None, req_msgs=None, req_body=None,
           resp=None, context=None, note=None):
    os.makedirs(os.path.join(OUT, feature), exist_ok=True)
    rec = {"name": name, "variant": variant, "transport": transport, "path": path, "method": method,
           "req_headers": req_headers or {}}
    if req_msgs is not None:
        rec["req_messages_b64"] = [B64(m) for m in req_msgs]
    if req_body is not None:
        rec["req_body_b64"] = B64(req_body)
    rec["resp"] = resp
    rec["context"] = context or {}
    if note:
        rec["note"] = note
    with open(os.path.join(OUT, feature, "cases.jsonl"), "a") as f:
        f.write(json.dumps(rec, sort_keys=False) + "\n")
    tr = resp.get("trailers", {}) if isinstance(resp, dict) else {}
    print(f"[{feature}] {name}: http={resp.get('http_status')} msgs={len(resp.get('messages_b64', []))} "
          f"status={tr.get('grpc-status')} msg={tr.get('grpc-message', '')[:100]}", flush=True)
    return rec


def call(feature, name, variant, path, msgs, headers=None, transport="h2c", max_msgs=None, read_s=10.0,
         context=None, note=None, kind="rpc"):
    raw = [m if isinstance(m, bytes) else m.SerializeToString() for m in msgs]
    tls = transport == "tls"
    p = port(variant, "https" if tls else kind)
    if transport in ("grpc-web", "grpc-web-tls"):
        resp = wire.grpc_web(HOST, port(variant, "https" if transport == "grpc-web-tls" else kind), path, raw,
                             headers=headers, read_s=read_s, tls=transport == "grpc-web-tls")
        timing = {}
    else:
        resp, timing = wire.grpc(HOST, p, path, raw, headers=headers, tls=tls, max_msgs=max_msgs, read_s=read_s)
    ctx = dict(context or {})
    ctx.update(timing)
    return record(feature, name, variant, transport, path, req_headers=headers, req_msgs=raw, resp=resp,
                  context=ctx, note=note)


def admin(feature, name, variant, method, path, body=b"", headers=None, note=None, context=None):
    st, hd, b, raw = wire.http1(HOST, port(variant, "admin"), method, path, body, headers)
    resp = {"http_status": st, "headers": hd, "body_b64": B64(b)}
    rec = record(feature, name, variant, "http", path, method=method, req_headers=headers,
                 req_body=body if method == "POST" else None, resp=resp, context=context, note=note)
    print("   body:", b[:300], flush=True)
    return rec


def decode_msgs(rec, cls):
    out = []
    for m in rec["resp"]["messages_b64"]:
        x = cls()
        x.ParseFromString(base64.b64decode(m))
        out.append(x)
    return out


def sh(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{cmd}: {r.stderr[-2000:]}")
    return r.stdout


def act_env():
    env = {}
    for line in open(os.path.expanduser("~/act.env")):
        for kv in line.split():
            k, v = kv.split("=", 1)
            env[k] = v
    return env
