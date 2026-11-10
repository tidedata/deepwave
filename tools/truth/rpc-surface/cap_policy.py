#!/usr/bin/env python3
"""deny, traffic, transport and config captures. Usage: cap_policy.py deny|deny-late|traffic|transport|config"""
import base64, json, os, sys, threading, time
from common import *  # noqa
from sui.rpc.v2 import ledger_service_pb2 as LS2, state_service_pb2 as ST  # noqa

EXEC = "/sui.rpc.v2.TransactionExecutionService/ExecuteTransaction"
SIM = "/sui.rpc.v2.TransactionExecutionService/SimulateTransaction"
GETOBJ = "/sui.rpc.v2.LedgerService/GetObject"
INFO = "/sui.rpc.v2.LedgerService/GetServiceInfo"
SUB = "/sui.rpc.v2.SubscriptionService/SubscribeEvents"
LIST = "/sui.rpc.v2.LedgerService/ListCheckpoints"
TXS = {}
if os.path.exists(os.path.expanduser("~/deny-txs.jsonl")):
    for l in open(os.path.expanduser("~/deny-txs.jsonl")):
        d = json.loads(l)
        TXS[d["name"]] = d


def ex_req(name):
    d = TXS[name]
    r = TX.ExecuteTransactionRequest()
    r.transaction.bcs.value = base64.b64decode(d["tx_b64"])
    r.signatures.add().bcs.value = base64.b64decode(d["sig_b64"])
    return r


def sim_req(name):
    r = TX.SimulateTransactionRequest()
    r.transaction.bcs.value = base64.b64decode(TXS[name]["tx_b64"])
    return r


PLAN = {  # variant: ([txs executed + simulated], [txs simulated only])
    "deny-lists": (["transfer-b", "bump-shared", "set-t1", "ping-pkg"], ["transfer-a"]),
    "deny-publish": (["publish"], ["upgrade", "transfer-a"]),
    "deny-upgrade": (["upgrade"], ["publish"]),
    "deny-shared": (["bump-shared"], ["set-t1"]),
    "deny-user": (["transfer-a", "ping-pkg"], ["transfer-b"]),
    "deny-receiving": (["recv-t2"], ["set-t1"]),
    "deny-receiving-object": (["recv-t2"], ["set-t1"]),
    "deny-zklogin-sig": ([], ["transfer-a"]),
    "deny-zklogin-providers": ([], ["transfer-a"]),
    "deny-gasless": ([], ["transfer-a"]),
    "deny-dyn-false": (["transfer-a"], []),
    "deny-dyn-int": (["transfer-a"], []),
    "deny-dyn-error": (["transfer-a"], []),
    "deny-dyn-true": ([], ["transfer-a"]),
    "idx": ([], ["transfer-a", "transfer-b", "bump-shared", "set-t1", "ping-pkg", "recv-t2", "publish", "upgrade"]),
}


def deny():
    for v, (exe, sim) in PLAN.items():
        admin("deny", f"{v}/admin-get", v, "GET", "/transaction-deny-config")
        for t in exe:
            if t in TXS:
                call("deny", f"{v}/execute/{t}", v, EXEC, [ex_req(t)], context={"tx": t, "sender": TXS[t]["sender"]})
        for t in exe + sim:
            if t in TXS:
                call("deny", f"{v}/simulate/{t}", v, SIM, [sim_req(t)], context={"tx": t, "sender": TXS[t]["sender"]})
        call("deny", f"{v}/execute/no-signature", v, EXEC, [TX.ExecuteTransactionRequest(transaction=ex_req("transfer-a").transaction)]) if v == "deny-user" else None
    admin("deny", "deny-lists/admin-post-broadcast", "deny-lists", "POST", "/broadcast-transaction-deny-config")
    admin("deny", "deny-lists/admin-post-withdraw", "deny-lists", "POST", "/withdraw-transaction-deny-config")
    admin("deny", "deny-lists/admin-get-wrong-method", "deny-lists", "POST", "/transaction-deny-config")


def deny_late():
    """deny-no-early-validation executes transfer-a for real (validators do not deny); then the
    already-executed transaction on deny-user skips the deny check."""
    v = "deny-no-early-validation"
    admin("deny", f"{v}/admin-get", v, "GET", "/transaction-deny-config")
    call("deny", f"{v}/simulate/transfer-a", v, SIM, [sim_req("transfer-a")])
    call("deny", f"{v}/execute/transfer-a", v, EXEC, [ex_req("transfer-a")], read_s=30,
         note="early validation off: fullnode deny config not applied, validators execute it")
    time.sleep(3)
    call("deny", "deny-user/execute/transfer-a-already-executed", "deny-user", EXEC, [ex_req("transfer-a")], read_s=30,
         note="transfer-a was executed via deny-no-early-validation; executed transactions skip the deny check")
    call("deny", "deny-user/simulate/transfer-a-already-executed", "deny-user", SIM, [sim_req("transfer-a")])


def stable_get():
    return LS2.GetObjectRequest(object_id="0x2", version=1, read_mask=mask("object_id", "version", "digest"))


def missing_get():
    return LS2.GetObjectRequest(object_id="0x" + "77" * 32)


def traffic():
    for v in ("traffic-default", "traffic-strict", "traffic-xff1", "traffic-xff2", "traffic-null", "traffic-noop", "traffic-dry"):
        admin("traffic", f"{v}/admin-post-empty", v, "POST", "/traffic-control")
    v = "traffic-strict"
    for i in range(12):
        call("traffic", f"{v}/spam-h2c-{i}", v, GETOBJ, [stable_get()], context={"seq": i})
    for i in range(8):
        call("traffic", f"{v}/error-h2c-{i}", v, GETOBJ, [missing_get()], context={"seq": i})
    for i in range(8):
        call("traffic", f"{v}/spam-grpcweb-{i}", v, GETOBJ, [stable_get()], transport="grpc-web", context={"seq": i})
    for i in range(4):
        call("traffic", f"{v}/after-errors-h2c-{i}", v, GETOBJ, [stable_get()], context={"seq": i})
    for v in ("traffic-xff1", "traffic-xff2"):
        for hn, hv in (("none", None), ("one", "10.0.0.1"), ("two", "10.0.0.1, 10.0.0.2"), ("three", "10.0.0.1, 10.0.0.2, 10.0.0.3"),
                       ("garbage", "not-an-ip")):
            hdr = {"x-forwarded-for": hv} if hv else None
            for i in range(5):
                call("traffic", f"{v}/xff-{hn}-{i}", v, GETOBJ, [stable_get()], headers=hdr, context={"seq": i})
            for i in range(4):
                call("traffic", f"{v}/xff-{hn}-err-{i}", v, GETOBJ, [missing_get()], headers=hdr, context={"seq": i})
            call("traffic", f"{v}/xff-{hn}-grpcweb", v, GETOBJ, [stable_get()], headers=hdr, transport="grpc-web")
    for v in ("traffic-strict", "traffic-default", "traffic-dry"):
        for q in ("?error_threshold=5", "?spam_threshold=7", "?dry_run=false", "?error_threshold=1&spam_threshold=1&dry_run=false",
                  "?dry_run=yes", "?error_threshold=-1", "?bogus=1", ""):
            admin("traffic", f"{v}/admin-post{q or '-again'}", v, "POST", "/traffic-control" + q)
        admin("traffic", f"{v}/admin-get-405", v, "GET", "/traffic-control")
    for i in range(6):
        call("traffic", f"traffic-strict/after-admin-h2c-{i}", "traffic-strict", GETOBJ, [missing_get()], context={"seq": i})
    admin("traffic", "traffic-null/admin-post-threshold", "traffic-null", "POST", "/traffic-control?error_threshold=5")
    admin("traffic", "traffic-noop/admin-post-threshold", "traffic-noop", "POST", "/traffic-control?error_threshold=5")
    admin("traffic", "traffic-noop/admin-post-dryrun", "traffic-noop", "POST", "/traffic-control?dry_run=true")


def transport():
    v = "tls"
    call("transport", "tls/h2-getobject", v, GETOBJ, [stable_get()], transport="tls")
    call("transport", "tls/h2-getobject-missing", v, GETOBJ, [missing_get()], transport="tls")
    call("transport", "tls/h2-list-0-3", v, LIST, [LS.ListCheckpointsRequest(start_checkpoint=0, end_checkpoint=3)], transport="tls")
    call("transport", "tls/grpc-web-http1", v, GETOBJ, [stable_get()], transport="grpc-web-tls")
    call("transport", "h2c-on-tls-variant", v, GETOBJ, [stable_get()])
    p = port(v, "https")
    # no ALPN, h2 prior knowledge over TLS
    resp, t = wire.grpc(HOST, p, GETOBJ, [stable_get().SerializeToString()], tls=True, alpn=None)
    record("transport", "tls/h2-no-alpn", v, "tls", GETOBJ, req_msgs=[stable_get().SerializeToString()], resp=resp, context={"alpn": None})
    for path in ("/health", "/", "/nope"):
        st, hd, b, raw = wire.http1(HOST, p, "GET", path, tls=True, alpn=("http/1.1",))
        record("transport", f"tls/http1-get{path}", v, "tls", path, method="GET", resp={"http_status": st, "headers": hd, "body_b64": B64(b)})
        st, hd, b, raw = wire.http1(HOST, port(v), "GET", path)
        record("transport", f"plain/http1-get{path}", v, "http", path, method="GET", resp={"http_status": st, "headers": hd, "body_b64": B64(b)})
    # what TLS handshake offers
    import ssl, socket
    for alpn in (("h2",), ("http/1.1",), ("h2", "http/1.1"), ("grpc-exp",)):
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(list(alpn))
        try:
            s = ctx.wrap_socket(socket.create_connection((HOST, p)), server_hostname="localhost")
            r = {"selected_alpn": s.selected_alpn_protocol(), "tls_version": s.version()}
            s.close()
        except Exception as e:
            r = {"error": repr(e)}
        record("transport", f"tls/alpn-{'+'.join(alpn)}", v, "tls", "(handshake)", method="TLS", resp={"handshake": r})
    # plain h2c port: HTTP/1.1 POST application/grpc (no grpc-web)
    st, hd, b, raw = wire.http1(HOST, port("idx"), "POST", GETOBJ, wire.frame(stable_get().SerializeToString()),
                                {"content-type": "application/grpc"})
    record("transport", "http1-grpc-not-web", "idx", "http", GETOBJ, req_body=wire.frame(stable_get().SerializeToString()),
           resp={"http_status": st, "headers": hd, "body_b64": B64(b)})
    call("transport", "grpc-web-text", "idx", GETOBJ, [stable_get()], transport="grpc-web", note="grpc-web+proto")
    resp = wire.grpc_web(HOST, port("idx"), GETOBJ, [stable_get().SerializeToString()], text=True)
    record("transport", "grpc-web-text-b64", "idx", "grpc-web", GETOBJ, req_headers={"content-type": "application/grpc-web-text"},
           req_msgs=[stable_get().SerializeToString()], resp=resp)
    # server grpc-timeout-ms: 1
    v = "timeout"
    for i in range(3):
        call("transport", f"timeout/getobject-{i}", v, GETOBJ, [stable_get()], note="grpc-timeout-ms: 1; may or may not beat 1 ms")
    call("transport", "timeout/subscribe-first-msg", v, SUB, [SS.SubscribeEventsRequest()], max_msgs=1, read_s=20)
    call("transport", "timeout/list-0-50", v, LIST, [LS.ListCheckpointsRequest(start_checkpoint=0, read_mask=mask("sequence_number", "digest", "summary", "contents", "transactions"), options=Q.QueryOptions(limit=50))], read_s=20)
    call("transport", "timeout/grpc-web-subscribe", v, SUB, [SS.SubscribeEventsRequest()], transport="grpc-web", read_s=5)
    # client grpc-timeout header on the default (60 s) node
    v = "idx"
    for h in ("1m", "1n", "50m", "1S", "abc", "123456789S", "1H", "1x"):
        call("transport", f"client-timeout/subscribe-{h}", v, SUB, [SS.SubscribeEventsRequest()], headers={"grpc-timeout": h},
             max_msgs=1, read_s=8)
    call("transport", "client-timeout/getobject-1n", v, GETOBJ, [stable_get()], headers={"grpc-timeout": "1n"})
    call("transport", "client-timeout/getobject-10S", v, GETOBJ, [stable_get()], headers={"grpc-timeout": "10S"})
    # grpc-load-shed + grpc-concurrency-limit: 1 (validator-server only keys) under 24 concurrent calls
    v = "limits"
    res = {}
    def one(i):
        res[i] = wire.grpc(HOST, port(v), LIST, [LS.ListCheckpointsRequest(start_checkpoint=0, options=Q.QueryOptions(limit=50)).SerializeToString()], read_s=20)
    th = [threading.Thread(target=one, args=(i,)) for i in range(24)]
    [t.start() for t in th]; [t.join() for t in th]
    for i in sorted(res):
        record("transport", f"limits/concurrent-list-{i}", v, "h2c", LIST,
               req_msgs=[LS.ListCheckpointsRequest(start_checkpoint=0, options=Q.QueryOptions(limit=50)).SerializeToString()],
               resp=res[i][0], context=res[i][1], note="24 concurrent calls, grpc-load-shed true, grpc-concurrency-limit 1")


def config():
    for v in VARIANTS:
        admin("config", f"{v}/node-config", v, "GET", "/node-config")


if __name__ == "__main__":
    {"deny": deny, "deny-late": deny_late, "traffic": traffic, "transport": transport, "config": config}[sys.argv[1]]()


def transport_slow():
    """Calls slow enough for grpc-timeout to fire: simulate and execute (await consensus)."""
    call("transport", "timeout/simulate-transfer-b", "timeout", SIM, [sim_req("transfer-b")])
    for h in ("1n", "1m", "1u"):
        call("transport", f"client-timeout/simulate-{h}", "idx", SIM, [sim_req("transfer-b")], headers={"grpc-timeout": h})
    call("transport", "timeout/execute-ping-pkg", "timeout", EXEC, [ex_req("ping-pkg")], read_s=20,
         note="grpc-timeout-ms 1; the transaction still executes in the background")
    call("transport", "client-timeout/execute-set-t1-1m", "idx", EXEC, [ex_req("set-t1")], headers={"grpc-timeout": "1m"}, read_s=20,
         note="client grpc-timeout 1m; the transaction still executes in the background")


if len(sys.argv) > 1 and sys.argv[1] == "transport-slow":
    transport_slow()
