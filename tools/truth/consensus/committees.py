"""Consensus context of every epoch of a Mysten localnet capture, from sui-node's own log lines.

Usage: committees.py OUT_DIR VALIDATOR_LOG...

consensus_core::authority_node logs, each time consensus starts:
  Starting consensus validator authority [i] <host>, <protocol version>, epoch start timestamp <ms>, ...
  Consensus committee: Committee { epoch: N, authorities: [Authority { stake: S, ..., protocol_key:
  ProtocolPublicKey(<b64>), network_key: NetworkPublicKey(<b64>) }, ...] }
Writes OUT_DIR/epoch-N.meta (every validator's lines must agree; a restart's repeated lines too):
  epoch N
  protocol V
  start_ms T
  authority <index> <stake> <protocol key hex> <network key hex> <hostname>
"""
import base64
import re
import sys

out_dir, logs = sys.argv[1], sys.argv[2:]
start_re = re.compile(r"Starting consensus validator authority \[(\d+)\] (\S+), (\d+), epoch start timestamp (\d+)")
comm_re = re.compile(r"Consensus committee: Committee \{ epoch: (\d+), authorities: \[(.*)\], total_stake: (\d+)")
auth_re = re.compile(
    r'Authority \{ stake: (\d+), address: Multiaddr\([^)]*\), hostname: "([^"]*)", authority_name: AuthorityName\([^)]*\), '
    r"protocol_key: ProtocolPublicKey\(([^)]*)\), network_key: NetworkPublicKey\(([^)]*)\) \}"
)

epochs = {}
for path in logs:
    pending = None
    for line in open(path, errors="replace"):
        m = start_re.search(line)
        if m:
            pending = (int(m.group(3)), int(m.group(4)))
            continue
        m = comm_re.search(line)
        if not m:
            continue
        epoch = int(m.group(1))
        auths = [
            (int(a[0]), base64.b64decode(a[2]).hex(), base64.b64decode(a[3]).hex(), a[1])
            for a in auth_re.findall(m.group(2))
        ]
        assert auths, f"{path}: no authorities parsed for epoch {epoch}"
        assert pending, f"{path}: committee line without a start line"
        rec = (pending[0], pending[1], tuple(auths))
        prev = epochs.setdefault(epoch, rec)
        assert prev == rec, f"{path}: epoch {epoch} context differs between validators or restarts"
        pending = None

for epoch, (protocol, start_ms, auths) in sorted(epochs.items()):
    with open(f"{out_dir}/epoch-{epoch}.meta", "w") as f:
        f.write(f"epoch {epoch}\nprotocol {protocol}\nstart_ms {start_ms}\n")
        for i, (stake, pk, nk, host) in enumerate(auths):
            f.write(f"authority {i} {stake} {pk} {nk} {host}\n")
    print(f"epoch {epoch}: protocol {protocol}, start {start_ms}, stakes {[a[0] for a in auths]}")
