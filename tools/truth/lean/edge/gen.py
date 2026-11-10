"""Reviewer edge cases for the lean oracles, written from the Rust source (tables.rs, gas_v3.rs,
gas_common.rs, bcs 0.1.6 de.rs) for paths the generated vectors do not reach: u64 overflow in
the meter (ARITHMETIC_OVERFLOW, PC_OVERFLOW), the 10M instruction and 100M size tiers, exact tier
starts, storage tracking overflow, the u128 package-read path, price and rounding boundaries,
and the depth limit through unit structs, tuple structs and struct-in-option chains.

The expected results come from Rust, never from Lean:

  python3 -I gen.py gen  <dir> lean/data/gas-config-mainnet.json   # writes <dir>/{gas,bcs}.jsonl, expect empty
  zui-lean-truth gas-check <dir>/gas.jsonl > <dir>/gas.out          # FAIL lines carry Rust's result
  zui-lean-truth bcs-check lean/data/sui-format-1.83.1.json <dir>/bcs.jsonl > <dir>/bcs.out
  python3 -I gen.py fill <dir>                                      # writes gas.jsonl/bcs.jsonl here

(the checkers print at most 50 FAIL lines: keep each file under 50 items or split it). Then
both `zui-spec gas|bcs` and `zui-lean-truth gas-check|bcs-check` must pass on the filled files.
"""
import json, os, re, sys

def fill(d):
    here = os.path.dirname(os.path.abspath(__file__))
    for kind, isgas in (("gas", True), ("bcs", False)):
        res = {}
        for l in open(os.path.join(d, kind + ".out")):
            m = re.match(r'FAIL (\S+) lean=(.*) rust=(.*)$', l.strip())
            if m:
                res[m.group(1).strip('"')] = json.loads(m.group(3)) if isgas else m.group(3)
        with open(os.path.join(here, kind + ".jsonl"), "w") as f:
            for l in open(os.path.join(d, kind + ".jsonl")):
                v = json.loads(l)
                v["expect"] = res[v["id"]]
                f.write(json.dumps(v, separators=(",", ":")) + "\n")

if sys.argv[1] == "fill":
    fill(sys.argv[2])
    sys.exit(0)
out = sys.argv[2]
cfgs = {r["pv"]: r for r in json.load(open(sys.argv[3]))}
M = 2**64 - 1
gas = []
def g(name, pv, budget, price, rgp, ops):
    gas.append({"id": "rev-gas/" + name, "pv": pv, "cfg": cfgs[pv], "budget": budget, "price": price, "rgp": rgp, "ops": ops, "expect": {}})
B = 50_000_000_000_000
for pv in (138, 141):
    # instruction tiers: exact boundary (not crossed), +1 crossing, jump straight to the 10M tier, past last tier
    g(f"instr-exact-20000/{pv}", pv, B, 1000, 1000, [["charge", 20000, 0, 0, 0, 0], ["charge", 1, 0, 0, 0, 0], ["charge", 1, 0, 0, 0, 0]])
    g(f"instr-jump-10M/{pv}", pv, B, 1000, 1000, [["charge", 15_000_000, 0, 0, 0, 0], ["charge", 3, 0, 0, 0, 0], ["bucketize", 0], ["storage"]])
    g(f"instr-exact-10M/{pv}", pv, B, 1000, 1000, [["charge", 10_000_000, 0, 0, 0, 0], ["charge", 1, 0, 0, 0, 0], ["bucketize", 1]])
    # height tiers: exactly 1000 then 1001; pop back below the tier (multiplier must stay)
    g(f"height-1000/{pv}", pv, B, 1000, 1000, [["charge", 1, 1000, 0, 0, 0], ["charge", 1, 1, 0, 0, 0], ["charge", 1, 0, 1001, 0, 0], ["charge", 1, 5, 0, 0, 0]])
    g(f"height-10000/{pv}", pv, B, 1000, 1000, [["charge", 1, 10001, 10001, 0, 0], ["charge", 1, 3, 3, 0, 0]])
    # size tiers incl. the 100M tier
    g(f"size-100M/{pv}", pv, B, 1000, 1000, [["charge", 1, 0, 0, 100_000_000, 0], ["charge", 1, 0, 0, 1, 0], ["charge", 1, 0, 0, 7, 0]])
    # overflow paths: instruction count, multiplier product, push height
    g(f"pc-overflow/{pv}", pv, B, 1000, 1000, [["charge", M, 0, 0, 0, 0], ["charge", 1, 0, 0, 0, 0], ["charge", 0, 1, 0, 0, 0]])
    g(f"mul-overflow-instr/{pv}", pv, B, 1000, 1000, [["charge", M // 2, 0, 0, 0, 0]])
    g(f"push-overflow/{pv}", pv, B, 1000, 1000, [["charge", 0, M, 0, 0, 0], ["charge", 0, 1, 0, 0, 0], ["charge", 1, 0, 0, 0, 0]])
    g(f"size-overflow/{pv}", pv, B, 1000, 1000, [["charge", 0, 0, 0, M, 0], ["charge", 0, 0, 0, 1, 0]])
    g(f"pop-underflow/{pv}", pv, B, 1000, 1000, [["charge", 1, 2, 5, 0, 0], ["charge", 1, 1, 0, 0, 0]])
    # deduct exactly everything, then one more
    g(f"deduct-exact/{pv}", pv, 1_000_000, 1000, 1000, [["deduct", 1_000_000], ["deduct", 0], ["deduct", 1]])
    g(f"deduct-max/{pv}", pv, B, 1000, 1000, [["deduct", M]])
    # storage tracking overflow: cost overflow -> none; rebate overflow after cost added
    g(f"mutate-cost-overflow/{pv}", pv, B, 1000, 1000, [["mutate", 2**62, 0], ["mutate", 1, M], ["mutate", 1, 1], ["storage"]])
    g(f"mutate-total-overflow/{pv}", pv, B, 1000, 1000, [["mutate", 2**64 // 7600 - 1, 0], ["mutate", 2**64 // 7600 - 1, 0], ["storage"]])
    # package read: u128 saturating path
    g(f"pkgread-huge/{pv}", pv, B, 1000, 1000, [["pkgread", M], ["pkgread", 0], ["pkgread", 1], ["pkgread", 1024], ["pkgread", 1025]])
    # budget above the computation bucket (capped meter), price at rgp, at max-1, at max
    g(f"budget-cap/{pv}", pv, B, 1000, 1000, [["charge", 60000, 0, 0, 0, 0], ["bucketize", 0], ["storage"]])
    g(f"price-eq-rgp/{pv}", pv, 2_000_000, 750, 750, [["charge", 5, 1, 1, 8, 0], ["bucketize", 0], ["storage"]])
    mx = cfgs[pv]["max_gas_price"]
    g(f"price-max-1/{pv}", pv, B, mx - 1, 1, [["charge", 1, 0, 0, 0, 0], ["bucketize", 1], ["storage"]])
    g(f"price-max/{pv}", pv, B, mx, 1, [])
    g(f"price-under/{pv}", pv, B, 999, 1000, [])
    # abort cap: user price far above factor * rgp, aborted and not
    g(f"abort-cap/{pv}", pv, 10_000_000_000, 200_000, 1000, [["charge", 30000, 2, 2, 100, 0], ["bucketize", 1], ["storage"], ["bucketize", 0], ["storage"]])
    # half-digit rounding boundaries (used units 999, 1000, 1001, 999999, 1000001)
    for units in (999, 1000, 1001, 20001, 999_999, 1_000_001):
        g(f"round-{units}/{pv}", pv, B, 1000, 1000, [["deduct", units * 1000], ["bucketize", 0], ["storage"]])
    # storage exactly at the limit
    g(f"storage-exact/{pv}", pv, 1_000_000 + 7600 * 100, 1000, 1000, [["deduct", 999_000], ["bucketize", 0], ["mutate", 100, 0], ["storage"], ["mutate", 1, 0], ["storage"]])
    # oog then more charges and reset
    g(f"oog-after/{pv}", pv, 5_000_000, 1000, 1000, [["mutate", 10, 5000], ["oog"], ["mutate", 10, 5000], ["storage"], ["reset"]])
with open(out + "/gas.jsonl", "w") as f:
    for v in gas: f.write(json.dumps(v, separators=(",", ":")) + "\n")

# BCS: all named container kinds count for depth, at the 500 boundary
bcs = []
types_u = {"K": {"ENUM": {"0": {"End": {"NEWTYPE": {"TYPENAME": "U"}}}, "1": {"More": {"NEWTYPE": {"TYPENAME": "K"}}}}}, "U": "UNITSTRUCT",
           "T": {"TUPLESTRUCT": ["U8", {"TYPENAME": "K"}]},
           "S": {"STRUCT": [{"a": {"OPTION": {"TYPENAME": "S"}}}, {"b": "U8"}]},
           "MK": {"STRUCT": [{"m": {"MAP": {"KEY": {"TYPENAME": "U"}, "VALUE": "U8"}}}]}}
for n in (497, 498, 499, 500):
    # n x More, then End(U): n + 1 K's plus U = n + 2 containers
    bcs.append({"id": f"rev-depth-unitstruct/{n}", "types": types_u, "fmt": {"TYPENAME": "K"}, "hex": ("01" * n) + "00", "expect": ""})
    # T wraps: T + (n+1) K + U = n + 3
    bcs.append({"id": f"rev-depth-tuplestruct/{n}", "types": types_u, "fmt": {"TYPENAME": "T"}, "hex": "07" + ("01" * n) + "00", "expect": ""})
for n in (498, 499, 500, 501):
    # S chain through options: n S's with Some, then None
    bcs.append({"id": f"rev-depth-struct-option/{n}", "types": types_u, "fmt": {"TYPENAME": "S"}, "hex": ("0105" * 0) + ("01" * (n - 1)) + "00" + ("05" * n), "expect": ""})
# map keyed by a unit struct: second key encodes to the same empty bytes -> NonCanonicalMap; one entry ok
bcs.append({"id": "rev-map-unitkey/1", "types": types_u, "fmt": {"TYPENAME": "MK"}, "hex": "0109", "expect": ""})
bcs.append({"id": "rev-map-unitkey/2", "types": types_u, "fmt": {"TYPENAME": "MK"}, "hex": "020909", "expect": ""})
# u128 / u256 max, i-types absent from registry; 33-byte Passkey public key variant 4
bcs.append({"id": "rev-pk-passkey", "fmt": {"TYPENAME": "PublicKey"}, "hex": "04" + "02" * 33, "expect": ""})
bcs.append({"id": "rev-pk-passkey-short", "fmt": {"TYPENAME": "PublicKey"}, "hex": "04" + "02" * 32, "expect": ""})
bcs.append({"id": "rev-pk-variant5", "fmt": {"TYPENAME": "PublicKey"}, "hex": "05" + "02" * 33, "expect": ""})
with open(out + "/bcs.jsonl", "w") as f:
    for v in bcs: f.write(json.dumps(v, separators=(",", ":")) + "\n")
print(len(gas), "gas", len(bcs), "bcs")
