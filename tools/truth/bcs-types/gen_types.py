#!/usr/bin/env python3
"""Generates src/types/gen.zig from spec/sui-format-1.83.1.yaml.snap (the serde-reflection
registry of Mysten's sui-types 1.83.1). Run from the repo root:

    python3 tools/truth/bcs-types/gen_types.py

The output is committed; regenerate only when the registry snapshot changes. Shapes, names and
variant order come straight from the registry; the OVERRIDES below name the types whose Zig
form is hand-written in src/types/hand.zig (hooks for validation) and the fields whose Rust type
is `Identifier` rather than `String`.
"""
import os, re, sys
sys.path.insert(0, os.path.dirname(__file__))
import yamlmini

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SNAP = os.path.join(ROOT, "spec", "sui-format-1.83.1.yaml.snap")

# registry type name -> expression in hand.zig (or generic instantiation)
HAND = {
    "Digest": "hand.Digest",
    "AuthorityPublicKeyBytes": "hand.AuthorityPublicKeyBytes",
    "Intent": "hand.Intent",
    "GenericSignature": "hand.GenericSignature",
    # Rust Deserialize checks beyond the shape: serde Duration overflow + normalization, Party
    # (`try_from = "RawPartySerde"`, ObjectPermissions `try_from = "u64"`), and the transaction
    # intent check in SenderSignedTransaction's hand-written Deserialize.
    "Duration": "hand.Duration",
    "RawPartySerde": "hand.RawPartySerdeOf(SuiAddress)",
    "SenderSignedTransaction": "hand.SenderSignedTransactionOf(TransactionData)",
    "IntentMessage": "hand.IntentMessage(hand.Intent, TransactionData)",
    "sui_types::message_envelope::Envelope<sui_types::messages_checkpoint::CheckpointSummary, sui_types::crypto::AuthorityQuorumSignInfo<true>>":
        "hand.Envelope(CheckpointSummary, AuthorityQuorumSignInfo)",
    "sui_types::message_envelope::Envelope<sui_types::transaction::SenderSignedData, sui_types::crypto::EmptySignInfo>":
        "hand.Envelope(SenderSignedData, EmptySignInfo)",
}
# (type, field) whose Rust type is move_core_types::Identifier
IDENT = {
    ("StructTag", "module"), ("StructTag", "name"), ("ModuleId", "name"), ("Event", "transaction_module"),
}
RESERVED = set("""addrspace align allowzero and anyframe anytype asm async await break callconv catch comptime const continue
defer else enum errdefer error export extern fn for if inline linksection noalias noinline nosuspend opaque or orelse packed
pub resume return struct suspend switch test threadlocal try union unreachable usingnamespace var volatile while
bool void type anyerror noreturn isize usize comptime_int comptime_float c_int c_uint c_long c_char f16 f32 f64 f80 f128""".split())

# Variants that exist in sui-types 1.83.1 but that the registry test never traced (the registry has
# a hole at that index): wire index -> (variant, Zig payload type). Without them a following
# variant would get the wrong index. The bcs-format suite skips these when comparing.
REGISTRY_HOLES = {
    "PublicKey": {4: ("Passkey", "[33]u8")},
    "CompressedSignature": {4: ("Passkey", "PasskeyAuthenticatorAsBytes")},
}

# The registry lists the alias spellings of these variants; serde serializes the renames.
LOWER_VARIANTS = {"TypeTag", "TypeInput"}

def zname(n):
    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', n) and n not in RESERVED and not re.match(r'^[ui][0-9]+$', n):
        return n
    return '@"%s"' % n

PRIM = {"U8": "u8", "U16": "u16", "U32": "u32", "U64": "u64", "U128": "u128", "BOOL": "bool", "STR": "bcs.String",
        "BYTES": "[]const u8", "UNIT": "void", "I8": "i8", "I16": "i16", "I32": "i32", "I64": "i64"}

class Gen:
    def __init__(self, reg):
        self.reg = reg
        self.cur = None
    def ty(self, x, ctx):
        """Zig type expression for registry node x. ctx = (type, field) for Identifier overrides."""
        if isinstance(x, str):
            return PRIM[x]
        (k, v), = x.items()
        if k == "TYPENAME":
            if v in HAND:
                return HAND[v]
            assert v in self.reg, v
            return v
        if k == "SEQ":
            return "[]const " + self.ty(v, None)
        if k == "OPTION":
            return "?" + self.ty(v, None)
        if k == "TUPLEARRAY":
            return "[%s]%s" % (v["SIZE"], self.ty(v["CONTENT"], None))
        if k == "TUPLE":
            return "struct { " + ", ".join(self.ty(i, None) for i in v) + " }"
        if k == "MAP":
            return "bcs.Map(%s, %s)" % (self.ty(v["KEY"], None), self.ty(v["VALUE"], None))
        raise Exception("unknown " + k)
    def field_ty(self, tname, fname, x):
        if (tname, fname) == ("AuthorityQuorumSignInfo", "signers_map"):
            return "hand.SuiBitmap"
        if (tname, fname) in IDENT:
            assert x == "STR"
            return "hand.Identifier"
        return self.ty(x, None)

    def emit(self, name, d):
        self.cur = name
        (kind, body), = d.items()
        out = []
        if kind == "STRUCT" and body == "[]":
            body = []
        if kind == "STRUCT":
            out.append("pub const %s = struct {" % name)
            for f in body:
                (fn, fv), = f.items()
                out.append("    %s: %s," % (zname(fn), self.field_ty(name, fn, fv)))
            out.append("};")
        elif kind == "NEWTYPESTRUCT":
            inner = self.ty(body, None)
            if name == "SenderSignedData":
                inner = "hand.SizeOneVec(SenderSignedTransaction)"
            out.append("pub const %s = struct {\n    @\"0\": %s,\n    pub const bcs_newtype = true;\n};" % (name, inner))
        elif kind == "ENUM":
            out.append("pub const %s = union(enum) {" % name)
            holes = REGISTRY_HOLES.get(name, {})
            idxs = sorted(int(k) for k in body)
            assert sorted(set(idxs) | set(holes)) == list(range(max(idxs) + 1)), (name, idxs)
            for i in range(max(idxs) + 1):
                if i in holes:
                    out.append("    %s: %s," % (zname(holes[i][0]), holes[i][1]))
                    continue
                (vn, vb), = body[str(i)].items()
                if vb == "UNIT":
                    pt = "void"
                else:
                    (vk, vv), = vb.items()
                    if vk == "NEWTYPE":
                        pt = self.ty(vv, None)
                        if isinstance(vv, dict) and vv.get("TYPENAME") == name:
                            pt = "*const " + name
                    elif vk == "TUPLE":
                        pt = "struct { " + ", ".join(self.ty(a, None) for a in vv) + " }"
                    elif vk == "STRUCT":
                        fs = []
                        for f in vv:
                            (fn, fv), = f.items()
                            fs.append("%s: %s" % (zname(fn), self.ty(fv, None)))
                        pt = "struct { " + ", ".join(fs) + ", pub const bcs_no_depth = true; }"
                    else:
                        raise Exception(vk)
                if name in LOWER_VARIANTS:
                    vn = vn.lower()
                out.append("    %s: %s," % (zname(vn), pt))
            out.append("};")
        else:
            raise Exception(kind)
        return "\n".join(out)

def main():
    text = open(SNAP).read().split("---\n", 2)[2]
    reg = yamlmini.parse(text)
    g = Gen(reg)
    lines = ["//! GENERATED by tools/truth/bcs-types/gen_types.py from spec/sui-format-1.83.1.yaml.snap. Do not edit.",
             "//! Names, field order and variant order are the serde-reflection registry of sui-types 1.83.1.",
             "const bcs = @import(\"bcs\");", "const hand = @import(\"hand.zig\");", ""]
    names = []
    for name, d in reg.items():
        if name in HAND:
            continue
        lines.append(g.emit(name, d))
        lines.append("")
        names.append(name)
    for name, z in HAND.items():
        if "::" not in name:
            lines.append("pub const %s = %s;" % (name, z))
    lines.append("")
    lines.append("pub const PasskeyAuthenticatorAsBytes = struct {\n    @\"0\": []const u8,\n    pub const bcs_newtype = true;\n};\n")
    lines.append("/// Every registry type: (registry name, Zig type). Used by the bcs-format suite.")
    lines.append("pub const registry = .{")
    for name in reg.keys():
        z = HAND.get(name, name)
        lines.append('    .{ "%s", %s },' % (name.replace('"', '\\"'), z))
    lines.append("};")
    open(os.path.join(ROOT, "src", "types", "gen.zig"), "w").write("\n".join(lines) + "\n")
    rp = os.path.join(ROOT, "src", "types", "root.zig")
    root = open(rp).read()
    a = root.index("// BEGIN GENERATED EXPORTS")
    b = root.index("// END GENERATED EXPORTS")
    ex = ["// BEGIN GENERATED EXPORTS (tools/truth/bcs-types/gen_types.py)"]
    for name in reg.keys():
        if "::" in name:
            continue
        ex.append("pub const %s = gen.%s;" % (name, name))
    root = root[:a] + "\n".join(ex) + "\n" + root[b:]
    open(rp, "w").write(root)
    print("wrote src/types/gen.zig:", len(names), "types +", len([n for n in reg if n in HAND]), "hand")

main()
