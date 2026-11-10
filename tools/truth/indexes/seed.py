"""Seeds for the G4 parity run from recent sui-node checkpoints: active addresses (senders and
balance-change owners), dynamic-field parents (owners of object-owned changed objects, tagged by
the child's type), and coin types. Usage: seed.py <out.json> [checkpoints=400]"""
import json, sys, collections, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pb

out = sys.argv[1]
ncp = int(sys.argv[2]) if len(sys.argv) > 2 else 400
c = pb.Client(port=int(os.environ.get("PORT", "19004")), rate=float(os.environ.get("RATE", "15")))
info = c.call("LedgerService", "GetServiceInfo", b"")[2]
tip = pb.one(info, 4)  # GetServiceInfoResponse.checkpoint_height (3 is the epoch)
m = pb.mask(["transactions.transaction.sender", "transactions.balance_changes.address",
             "transactions.balance_changes.coin_type", "transactions.effects.changed_objects.object_type",
             "transactions.effects.changed_objects.output_owner"])
senders = collections.Counter()
coin_types = collections.Counter()
parents = {}
step = 5  # spread over ~2000 checkpoints
for k in range(ncp):
    seq = tip - 10 - k * step
    st, msg, r, _ = c.call("LedgerService", "GetCheckpoint", pb.field_varint(1, seq) + pb.field_bytes(3, m))
    if st != 0:
        continue
    cp = pb.one(r, 1)
    for tx in pb.get(cp, 6):
        t = pb.one(tx, 2)
        if t:
            s = pb.one(t, 5)
            if s: senders[s.decode()] += 1
        for bc in pb.get(tx, 8):
            a, ct = pb.one(bc, 1), pb.one(bc, 2)
            if a: senders[a.decode()] += 1
            if ct: coin_types[ct.decode()] += 1
        eff = pb.one(tx, 4)
        if not eff: continue
        for co in pb.get(eff, 12):
            ow = pb.one(co, 9)
            ty = pb.one(co, 11)
            if ow and pb.one(ow, 1) == 2:
                p = pb.one(ow, 2).decode()
                parents.setdefault(p, ty.decode() if ty else "")
    if k % 50 == 0:
        print("seq", seq, "senders", len(senders), "parents", len(parents), "coins", len(coin_types), file=sys.stderr)

def tag(t):
    tl = t.lower()
    for key, words in [("deepbook", ["deepbook"]), ("kiosk", ["kiosk"]), ("suins", ["suins", "name_record", "domain::domain"]),
                       ("cetus", ["cetus", "skip_list", "tick::tick", "position::position"]), ("turbos", ["turbos"]),
                       ("suilend", ["suilend", "obligation", "lending_market"]), ("navi", ["navi", "lending_core", "storage::"]),
                       ("scallop", ["scallop", "x_oracle", "witness_table"]), ("accumulator", ["accumulator"])]:
        if any(w in tl for w in words):
            return key
    return "other"

json.dump({"tip": tip, "addresses": [a for a, _ in senders.most_common()],
           "parents": [{"id": p, "child_type": t, "tag": tag(t)} for p, t in parents.items()],
           "coin_types": [t for t, _ in coin_types.most_common()]}, open(out, "w"), indent=0)
print("done calls", c.calls, "addresses", len(senders), "parents", len(parents), "coin types", len(coin_types),
      "tags", collections.Counter(tag(t) for t in parents.values()), file=sys.stderr)
