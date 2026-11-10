#!/usr/bin/env python3
"""subscribe-events, list-checkpoints and proof captures. Usage: cap_ledger.py subscribe|list|proof"""
import base64, json, os, sys, threading, time
from common import *  # noqa

SUB = "/sui.rpc.v2.SubscriptionService/SubscribeEvents"
LIST = "/sui.rpc.v2.LedgerService/ListCheckpoints"
PROOF = "/sui.rpc.v2alpha.ProofService/GetCheckpointObjectProof"
E = act_env()
A, B, PKG, CTR = E["A"], E["B"], E["PKG"], E["CTR"]


def lit(kind, val=None, neg=False, tx=False):
    L = F.TransactionLiteral() if tx else F.EventLiteral()
    if neg:
        L.negated = True
    if kind == "none":
        return L
    msg = getattr(L, kind)
    msg.SetInParent()
    field = {"sender": "address", "affected_address": "address", "affected_object": "object_id",
             "move_call": "function", "emit_module": "module", "event_type": "event_type",
             "event_stream_head": "stream_id"}.get(kind)
    if val is not None and field:
        setattr(msg, field, val)
    return L


def efilter(*terms, tx=False):
    f = F.TransactionFilter() if tx else F.EventFilter()
    for t in terms:
        term = f.terms.add()
        for l in t:
            term.literals.add().CopyFrom(l)
    return f


def subscribe():
    cases = [
        ("no-filter", SS.SubscribeEventsRequest()),
        ("no-filter-mask-all", SS.SubscribeEventsRequest(read_mask=mask(
            "package_id", "module", "sender", "event_type", "contents", "json", "checkpoint",
            "transaction_digest", "transaction_index", "event_index"))),
        ("no-filter-mask-position", SS.SubscribeEventsRequest(read_mask=mask(
            "checkpoint", "transaction_digest", "transaction_index", "event_index"))),
        ("no-filter-mask-contents", SS.SubscribeEventsRequest(read_mask=mask("contents", "json"))),
        ("sender-a", SS.SubscribeEventsRequest(filter=efilter([lit("sender", A)]))),
        ("sender-b", SS.SubscribeEventsRequest(filter=efilter([lit("sender", B)]))),
        ("emit-module-pkg", SS.SubscribeEventsRequest(filter=efilter([lit("emit_module", PKG)]))),
        ("emit-module-emitter", SS.SubscribeEventsRequest(filter=efilter([lit("emit_module", PKG + "::emitter")]))),
        ("emit-module-counter", SS.SubscribeEventsRequest(filter=efilter([lit("emit_module", PKG + "::counter")]))),
        ("type-address", SS.SubscribeEventsRequest(filter=efilter([lit("event_type", PKG)]))),
        ("type-module", SS.SubscribeEventsRequest(filter=efilter([lit("event_type", PKG + "::emitter")]))),
        ("type-struct-ping", SS.SubscribeEventsRequest(filter=efilter([lit("event_type", PKG + "::emitter::Ping")]))),
        ("type-struct-pong-any", SS.SubscribeEventsRequest(filter=efilter([lit("event_type", PKG + "::emitter::Pong")]))),
        ("type-struct-pong-marker", SS.SubscribeEventsRequest(filter=efilter([lit("event_type", f"{PKG}::emitter::Pong<{PKG}::emitter::Marker>")]))),
        ("type-system-coin", SS.SubscribeEventsRequest(filter=efilter([lit("event_type", "0x" + "0" * 63 + "2::coin")]))),
        ("stream-head", SS.SubscribeEventsRequest(filter=efilter([lit("event_stream_head", "0x" + "ab" * 32)]))),
        ("and-sender-a-pong", SS.SubscribeEventsRequest(filter=efilter([lit("sender", A), lit("event_type", PKG + "::emitter::Pong")]))),
        ("or-sender-b-ping", SS.SubscribeEventsRequest(filter=efilter([lit("sender", B)], [lit("event_type", PKG + "::emitter::Ping")]))),
        ("not-sender-a", SS.SubscribeEventsRequest(filter=efilter([lit("sender", A, neg=True)]))),
        ("module-and-not-ping", SS.SubscribeEventsRequest(filter=efilter([lit("emit_module", PKG), lit("event_type", PKG + "::emitter::Ping", neg=True)]))),
        ("or-not-combo", SS.SubscribeEventsRequest(filter=efilter([lit("sender", A), lit("emit_module", PKG + "::counter")], [lit("sender", A, neg=True), lit("event_type", PKG + "::emitter::Pong", neg=True)]))),
        ("empty-term", SS.SubscribeEventsRequest(filter=efilter([]))),
        ("filter-and-mask", SS.SubscribeEventsRequest(filter=efilter([lit("sender", B)]), read_mask=mask("sender", "event_type", "checkpoint", "event_index"))),
    ]
    bad = [
        ("err-empty-filter", SS.SubscribeEventsRequest(filter=F.EventFilter())),
        ("err-too-many-literals", SS.SubscribeEventsRequest(filter=efilter([lit("sender", A)] * 6, [lit("sender", B)] * 5))),
        ("err-no-predicate", SS.SubscribeEventsRequest(filter=efilter([lit("none")]))),
        ("err-sender-missing", SS.SubscribeEventsRequest(filter=efilter([lit("sender")]))),
        ("err-sender-short", SS.SubscribeEventsRequest(filter=efilter([lit("sender", "0x2")]))),
        ("err-sender-garbage", SS.SubscribeEventsRequest(filter=efilter([lit("sender", "zz")]))),
        ("err-sender-empty", SS.SubscribeEventsRequest(filter=efilter([lit("sender", "")]))),
        ("err-module-missing", SS.SubscribeEventsRequest(filter=efilter([lit("emit_module")]))),
        ("err-module-bad", SS.SubscribeEventsRequest(filter=efilter([lit("emit_module", PKG + "::a::b")]))),
        ("err-module-short-pkg", SS.SubscribeEventsRequest(filter=efilter([lit("emit_module", "0x2::coin")]))),
        ("err-type-missing", SS.SubscribeEventsRequest(filter=efilter([lit("event_type")]))),
        ("err-type-unclosed", SS.SubscribeEventsRequest(filter=efilter([lit("event_type", PKG + "::emitter::Pong<")]))),
        ("err-type-generic-no-name", SS.SubscribeEventsRequest(filter=efilter([lit("event_type", PKG + "::emitter<u64>")]))),
        ("err-type-primitive", SS.SubscribeEventsRequest(filter=efilter([lit("event_type", "u64")]))),
        ("err-type-vector", SS.SubscribeEventsRequest(filter=efilter([lit("event_type", f"{PKG}::emitter::Pong<vector<>>")]))),
        ("err-type-too-deep", SS.SubscribeEventsRequest(filter=efilter([lit("event_type", PKG + "::a::B::c")]))),
        ("err-stream-missing", SS.SubscribeEventsRequest(filter=efilter([lit("event_stream_head")]))),
        ("err-stream-bad", SS.SubscribeEventsRequest(filter=efilter([lit("event_stream_head", "nope")]))),
        ("err-negated-only-missing", SS.SubscribeEventsRequest(filter=efilter([lit("sender", neg=True)]))),
        ("err-mask-bad", SS.SubscribeEventsRequest(read_mask=mask("bogus"))),
        ("err-mask-nested-bad", SS.SubscribeEventsRequest(read_mask=mask("contents.nope"))),
        ("err-mask-and-filter", SS.SubscribeEventsRequest(read_mask=mask("bogus"), filter=F.EventFilter())),
    ]
    variant = "idx"
    for name, req in bad:
        call("subscribe-events", name, variant, SUB, [req], read_s=5)
    # also the same on the non-indexed node (subscription does not need indexes)
    results = {}
    threads = []
    N = int(os.environ.get("SUB_N", "24"))
    for v, cs in (("idx", cases), ("noidx", cases[:1] + cases[4:5])):
        for name, req in cs:
            def run(name=name, req=req, v=v):
                raw = req.SerializeToString()
                resp, timing = wire.grpc(HOST, port(v), SUB, [raw], max_msgs=N, read_s=float(os.environ.get("SUB_S", "120")))
                results[(v, name)] = (raw, resp, timing)
            t = threading.Thread(target=run)
            t.start()
            threads.append(t)
    time.sleep(3)
    sh("bash ~/box/burst.sh > ~/burst.log 2>&1")
    for t in threads:
        t.join()
    for (v, name), (raw, resp, timing) in sorted(results.items()):
        first = None
        if resp["messages_b64"]:
            m = SS.SubscribeEventsResponse()
            m.ParseFromString(base64.b64decode(resp["messages_b64"][0]))
            first = m.watermark.checkpoint if m.HasField("watermark") else None
        ctx = dict(timing)
        ctx["stream_start_seq"] = None if first is None else first + 1
        ctx["first_watermark_checkpoint"] = first
        ctx["max_msgs"] = N
        record("subscribe-events", name + ("" if v == "idx" else "-noidx"), v, "h2c", SUB, req_msgs=[raw], resp=resp,
               context=ctx, note="stream opened before the burst (box/burst.sh); first N messages, then client RST_STREAM(CANCEL)")


def lq(start=None, end=None, filt=None, limit=None, after=None, before=None, ordering=None, read_mask=None):
    r = LS.ListCheckpointsRequest()
    if start is not None: r.start_checkpoint = start
    if end is not None: r.end_checkpoint = end
    if filt is not None: r.filter.CopyFrom(filt)
    if read_mask is not None: r.read_mask.CopyFrom(read_mask)
    if any(x is not None for x in (limit, after, before, ordering)):
        r.options.SetInParent()
        if limit is not None: r.options.limit = limit
        if after is not None: r.options.after = after
        if before is not None: r.options.before = before
        if ordering is not None: r.options.ordering = ordering
    return r


def last_cursor(rec):
    ms = decode_msgs(rec, LS.ListCheckpointsResponse)
    return ms[-1].watermark.cursor if ms else None


def listcp():
    end = int(os.environ["LIST_END"])  # an indexed checkpoint bound past all activity
    v = "idx"
    c = lambda name, req, **kw: call("list-checkpoints", name, kw.pop("variant", v), LIST, [req], read_s=15,
                                     context={"end_bound": end}, **kw)
    c("unfiltered-default", lq())
    c("unfiltered-range", lq(0, end))
    c("range-mask-summary", lq(0, 5, read_mask=mask("sequence_number", "digest", "summary")))
    c("range-mask-all", lq(1, 3, read_mask=mask("sequence_number", "digest", "summary", "signature", "contents", "transactions", "objects")))
    c("range-mask-bad", lq(0, 3, read_mask=mask("bogus")))
    c("start-only", lq(start=end - 3, end=end))
    c("end-eq-start", lq(5, 5))
    c("err-end-lt-start", lq(6, 5))
    c("limit-0", lq(0, end, limit=0))
    c("limit-1", lq(0, end, limit=1))
    c("limit-3", lq(0, end, limit=3))
    c("limit-1000-clamped", lq(0, end, limit=1000))
    p1 = c("page-1", lq(0, end, limit=4))
    p2 = c("page-2-after", lq(0, end, limit=4, after=last_cursor(p1)))
    c("page-3-after", lq(0, end, limit=4, after=last_cursor(p2)))
    d1 = c("desc-limit-4", lq(0, end, limit=4, ordering=1))
    c("desc-page-2-before", lq(0, end, limit=4, ordering=1, before=last_cursor(d1)))
    c("err-ordering-bad", lq(0, end, ordering=7))
    c("err-cursor-garbage", lq(0, end, after=b"\x01\x02garbage"))
    c("err-cursor-wrong-direction", lq(0, end, ordering=1, after=last_cursor(p1)))
    c("err-before-and-after", lq(0, end, after=last_cursor(p1), before=last_cursor(d1)))
    c("start-above-tip-asc", lq(start=10**9))
    c("err-desc-above-tip", lq(start=10**9, end=10**9 + 10, ordering=1))
    c("desc-no-bounds", lq(ordering=1, limit=3))
    tx = dict(tx=True)
    fl = [
        ("f-sender-a", efilter([lit("sender", A, **tx)], **tx)),
        ("f-sender-b", efilter([lit("sender", B, **tx)], **tx)),
        ("f-affected-address-b", efilter([lit("affected_address", B, **tx)], **tx)),
        ("f-affected-object-ctr", efilter([lit("affected_object", CTR, **tx)], **tx)),
        ("f-affected-object-short", efilter([lit("affected_object", "0x5", **tx)], **tx)),
        ("f-move-call-pkg", efilter([lit("move_call", PKG, **tx)], **tx)),
        ("f-move-call-module", efilter([lit("move_call", PKG + "::counter", **tx)], **tx)),
        ("f-move-call-function", efilter([lit("move_call", PKG + "::counter::bump", **tx)], **tx)),
        ("f-emit-module", efilter([lit("emit_module", PKG + "::emitter", **tx)], **tx)),
        ("f-event-type", efilter([lit("event_type", PKG + "::emitter::Ping", **tx)], **tx)),
        ("f-event-type-generic", efilter([lit("event_type", f"{PKG}::emitter::Pong<{PKG}::emitter::Other>", **tx)], **tx)),
        ("f-stream-head", efilter([lit("event_stream_head", "0x" + "ab" * 32, **tx)], **tx)),
        ("f-package-write", efilter([lit("package_write", **tx)], **tx)),
        ("f-and", efilter([lit("sender", B, **tx), lit("move_call", PKG + "::counter", **tx)], **tx)),
        ("f-or", efilter([lit("sender", B, **tx)], [lit("package_write", **tx)], **tx)),
        ("f-not-sender-a", efilter([lit("sender", A, neg=True, **tx)], **tx)),
        ("f-and-not", efilter([lit("affected_address", A, **tx), lit("move_call", PKG, neg=True, **tx)], **tx)),
        ("f-empty-term", efilter([], **tx)),
        ("err-f-empty", F.TransactionFilter()),
        ("err-f-too-many", efilter([lit("sender", A, **tx)] * 11, **tx)),
        ("err-f-affected-expand", efilter(*([[lit("affected_address", A, **tx)] * 0 + [lit("affected_address", A, **tx), lit("affected_address", B, **tx)]] * 5), **tx)),
        ("err-f-move-call-bad", efilter([lit("move_call", PKG + "::a::b::c", **tx)], **tx)),
        ("err-f-move-call-missing", efilter([lit("move_call", **tx)], **tx)),
        ("err-f-object-bad", efilter([lit("affected_object", "xyz", **tx)], **tx)),
        ("err-f-object-missing", efilter([lit("affected_object", **tx)], **tx)),
        ("err-f-no-predicate", efilter([lit("none", **tx)], **tx)),
    ]
    for name, f in fl:
        c(name, lq(0, end, filt=f, limit=50))
    c("f-sender-b-limit-2", lq(0, end, filt=efilter([lit("sender", B, **tx)], **tx), limit=2))
    c("f-sender-b-desc", lq(0, end, filt=efilter([lit("sender", B, **tx)], **tx), ordering=1))
    c("noidx-unfiltered", lq(0, 5), variant="noidx")
    c("noidx-filtered", lq(0, 5, filt=efilter([lit("sender", A, **tx)], **tx)), variant="noidx")


def proof():
    objs = json.load(open(os.path.expanduser("~/proof-objs.json")))  # [{"label","id","checkpoint"}]
    for o in objs:
        r = PR.GetCheckpointObjectProofRequest(object_id=o["id"], checkpoint=o["checkpoint"])
        call("proof", o["label"], "idx", PROOF, [r], context={k: v for k, v in o.items() if k != "label"})
    tip = int(os.environ["LIST_END"])
    bad = [
        ("err-missing-checkpoint", PR.GetCheckpointObjectProofRequest(object_id=CTR)),
        ("err-missing-object", PR.GetCheckpointObjectProofRequest(checkpoint=1)),
        ("err-empty-object", PR.GetCheckpointObjectProofRequest(object_id="  ", checkpoint=1)),
        ("err-object-no-0x", PR.GetCheckpointObjectProofRequest(object_id=CTR[2:], checkpoint=1)),
        ("err-object-garbage", PR.GetCheckpointObjectProofRequest(object_id="0xzz", checkpoint=1)),
        ("short-object-id", PR.GetCheckpointObjectProofRequest(object_id="0x5", checkpoint=1)),
        ("err-object-too-long", PR.GetCheckpointObjectProofRequest(object_id="0x" + "11" * 33, checkpoint=1)),
        ("err-checkpoint-future", PR.GetCheckpointObjectProofRequest(object_id=CTR, checkpoint=10**9)),
        ("checkpoint-0-genesis-object", PR.GetCheckpointObjectProofRequest(object_id="0x5", checkpoint=0)),
        ("empty-request", PR.GetCheckpointObjectProofRequest()),
    ]
    for name, r in bad:
        call("proof", name, "idx", PROOF, [r], context={"tip": tip})
    call("proof", "noidx-ctr", "noidx", PROOF, [PR.GetCheckpointObjectProofRequest(object_id=CTR, checkpoint=2)])
    call("proof", "noidx-missing-checkpoint", "noidx", PROOF, [PR.GetCheckpointObjectProofRequest(object_id=CTR)])


def sublimit():
    """subscription-max-subscribers 1, watermark interval 5: the second concurrent subscriber is refused."""
    v = "sub-limit"
    res = {}
    def first():
        res["first"] = wire.grpc(HOST, port(v), SUB, [b""], max_msgs=6, read_s=30)
    t = threading.Thread(target=first); t.start(); time.sleep(1.5)
    call("subscribe-events", "sub-limit/second-subscriber", v, SUB, [SS.SubscribeEventsRequest()], max_msgs=2, read_s=10)
    call("subscribe-events", "sub-limit/second-subscriber-bad-filter", v, SUB, [SS.SubscribeEventsRequest(filter=F.EventFilter())], read_s=5)
    t.join()
    record("subscribe-events", "sub-limit/first-subscriber", v, "h2c", SUB, req_msgs=[b""], resp=res["first"][0],
           context=res["first"][1], note="watermark interval 5; 6 messages then cancel")
    time.sleep(1)
    call("subscribe-events", "sub-limit/after-first-closed", v, SUB, [SS.SubscribeEventsRequest()], max_msgs=2, read_s=10)


if __name__ == "__main__":
    {"sublimit": sublimit, "subscribe": subscribe, "list": listcp, "proof": proof}[sys.argv[1]]()
