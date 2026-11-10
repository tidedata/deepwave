"""Error-path cases for index-parity (no objects needed): invalid owners, types, page tokens,
masks; empty owners; unknown coin types. Usage: errors.py --port P --out $ZUI_CORPUS/vectors/index/errors.bin"""
import argparse, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pb

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--out", required=True)
args = ap.parse_args()
c = pb.Client("127.0.0.1", args.port, rate=10)
S = "StateService"
rnd = "0x" + "5e" * 32
f, v, m = pb.field_bytes, pb.field_varint, pb.mask
reqs = [
    ("ListOwnedObjects", b""),
    ("ListOwnedObjects", f(1, "0xzz")),
    ("ListOwnedObjects", f(1, "")),
    ("ListOwnedObjects", f(1, "0x" + "1" * 65)),
    ("ListOwnedObjects", f(1, rnd)),
    ("ListOwnedObjects", f(1, "0x" + "7a" * 32) + v(2, 3)),
    ("ListOwnedObjects", f(1, rnd) + f(5, "not a type")),
    ("ListOwnedObjects", f(1, rnd) + f(5, "0x2::coin::Coin<")),
    ("ListOwnedObjects", f(1, rnd) + f(5, "u64")),
    ("ListOwnedObjects", f(1, rnd) + f(5, "0x2::coin::Coin<0x2::sui::SUI>")),
    ("ListOwnedObjects", f(1, rnd) + f(3, b"\x01\x02")),
    ("ListOwnedObjects", f(1, rnd) + f(4, m(["nope"]))),
    ("ListOwnedObjects", f(1, rnd) + v(2, 0)),
    ("ListDynamicFields", b""),
    ("ListDynamicFields", f(1, "xyz")),
    ("ListDynamicFields", f(1, rnd)),
    ("ListDynamicFields", f(1, rnd) + f(3, b"\x00" * 10)),
    ("ListDynamicFields", f(1, rnd) + f(4, m(["field_object.nope"]))),
    ("GetBalance", b""),
    ("GetBalance", f(1, rnd)),
    ("GetBalance", f(1, rnd) + f(2, "0x2::sui::SUI")),
    ("GetBalance", f(1, rnd) + f(2, "garbage")),
    ("GetBalance", f(1, rnd) + f(2, "vector<u8>")),
    ("GetBalance", f(1, "0xq") + f(2, "0x2::sui::SUI")),
    ("ListBalances", b""),
    ("ListBalances", f(1, rnd)),
    ("ListBalances", f(1, rnd) + f(3, b"\x01")),
    ("ListBalances", f(1, rnd) + f(3, bytes.fromhex("5e" * 32))),
    ("GetCoinInfo", b""),
    ("GetCoinInfo", f(1, "0x2::nope::NOPE")),
    ("GetCoinInfo", f(1, "garbage")),
    ("GetCoinInfo", f(1, "0x2::coin::Coin<0x2::sui::SUI>")),
]
out_cases = []
for i, (meth, body) in enumerate(reqs):
    st, msg, r, _ = c.call(S, meth, body)
    out_cases.append(("err/%d/%s" % (i, meth), "/sui.rpc.v2.%s/%s" % (S, meth), body, st, msg, r or b""))
    print(i, meth, st, msg[:120], file=sys.stderr)
out = bytearray(b"ZIDX1") + struct.pack("<I", 0) + struct.pack("<I", len(out_cases))
for name, path, body, st, msg, resp in out_cases:
    nb, pbb, mb = name.encode(), path.encode(), msg.encode()
    out += struct.pack("<H", len(nb)) + nb + struct.pack("<H", len(pbb)) + pbb + struct.pack("<I", len(body)) + body
    out += struct.pack("<IH", st, len(mb)) + mb + struct.pack("<I", len(resp)) + resp
open(args.out, "wb").write(out)
