"""Minimal YAML subset reader for the serde-reflection registry (block maps, block lists, scalars).
Used only by tools/truth/bcs-types/gen_types.py; the registry is frozen in spec/."""
import re

def _scalar(s):
    s = s.strip()
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s

KEY = re.compile(r'^("[^"]*"|[^\s:"][^:]*?):(?:\s+(.*))?$')

def parse(text):
    lines = []
    for raw in text.split("\n"):
        if not raw.strip() or raw.startswith("---") or raw.lstrip().startswith("#"):
            continue
        lines.append(raw)
    # Expand "- x" into a standalone item line: ("- " marker at indent i, content at indent i+2)
    toks = []  # (indent, is_item, content)
    for l in lines:
        ind = len(l) - len(l.lstrip(" "))
        c = l.lstrip(" ")
        # a line may be "- - x"; handle repeated markers
        while c.startswith("- ") or c == "-":
            toks.append((ind, True, ""))
            c = c[2:]
            ind += 2
        toks.append((ind, False, c))
    pos = [0]

    def block(ind):
        # peek: the next token decides list vs map
        i = pos[0]
        if toks[i][1]:
            return seq(toks[i][0])
        return mapping(toks[i][0])

    def seq(ind):
        out = []
        while pos[0] < len(toks) and toks[pos[0]][1] and toks[pos[0]][0] == ind:
            pos[0] += 1  # the marker
            # item content starts at indent ind+2 (next token)
            if pos[0] < len(toks) and not toks[pos[0]][1] and toks[pos[0]][0] == ind + 2:
                nxt = toks[pos[0]][2]
                if KEY.match(nxt):
                    out.append(mapping(ind + 2))
                else:
                    out.append(_scalar(nxt)); pos[0] += 1
            elif pos[0] < len(toks) and toks[pos[0]][1] and toks[pos[0]][0] == ind + 2:
                out.append(seq(ind + 2))
            else:
                out.append(None)
        return out

    def mapping(ind):
        d = {}
        while pos[0] < len(toks) and not toks[pos[0]][1] and toks[pos[0]][0] == ind:
            c = toks[pos[0]][2]
            m = KEY.match(c)
            assert m, c
            pos[0] += 1
            k = _scalar(m.group(1))
            v = m.group(2)
            if v is not None and v != "":
                d[k] = _scalar(v)
            elif pos[0] < len(toks) and (toks[pos[0]][0] > ind or (toks[pos[0]][1] and toks[pos[0]][0] == ind)):
                d[k] = block(toks[pos[0]][0])
            else:
                d[k] = None
        return d

    return mapping(0)
