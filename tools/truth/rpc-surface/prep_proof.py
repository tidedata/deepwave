#!/usr/bin/env python3
"""Pick proof cases: for each object, the checkpoints that touched it (ListCheckpoints affected_object on idx),
plus an untouched checkpoint before and after. Writes ~/proof-objs.json. Usage: prep_proof.py END"""
import json, os, sys, base64
from common import *  # noqa
from cap_ledger import lq, efilter, lit, LIST
end = int(sys.argv[1])
E = act_env()
out = []
for label, oid in [("counter-shared", E["CTR"]), ("thing1-created-mutated-receiver", E["T1"]), ("thing2-transferred-to-object", E["T2"]),
                   ("thing3-created-deleted", E["T3"]), ("thing-b", E["TB"]), ("package", E["PKG"]), ("upgrade-cap", E["CAP"]),
                   ("clock-0x6", "0x6"), ("system-0x5", "0x5"), ("framework-0x2", "0x2")]:
    req = lq(0, end, filt=efilter([lit("affected_object", oid, tx=True)], tx=True), limit=50, read_mask=mask("sequence_number"))
    resp, _ = wire.grpc(HOST, port("idx"), LIST, [req.SerializeToString()], read_s=10)
    cps = []
    for m in resp["messages_b64"]:
        x = LS.ListCheckpointsResponse(); x.ParseFromString(base64.b64decode(m))
        if x.HasField("checkpoint"):
            cps.append(x.checkpoint.sequence_number)
    print(label, cps[:8], len(cps))
    sel = cps[:4] if label != "clock-0x6" else cps[:2]
    for c in sel:
        out.append({"label": f"{label}-touched-cp{c}", "id": oid, "checkpoint": c, "touched": True})
    if cps:
        if cps[0] > 0:
            out.append({"label": f"{label}-before-cp{cps[0]-1}", "id": oid, "checkpoint": cps[0] - 1, "touched": False})
        out.append({"label": f"{label}-after-cp{cps[-1]+2}", "id": oid, "checkpoint": cps[-1] + 2, "touched": False})
    else:
        out.append({"label": f"{label}-untouched-cp5", "id": oid, "checkpoint": 5, "touched": False})
out.append({"label": "never-existed-cp10", "id": "0x" + "99" * 32, "checkpoint": 10, "touched": False})
out.append({"label": "short-id-0x6-cp1", "id": "0x6", "checkpoint": 1, "touched": None})
json.dump(out, open(os.path.expanduser("~/proof-objs.json"), "w"), indent=1)
