# rpc-surface truth (sui-node mainnet-v1.83.1, 6a567faf)

Captures in `src/serve/vectors/rpc-surface/` (format: lane brief; `localnet/localnet.json` has the accounts,
objects, ports and the chk range). One capture box run, all against a 4-validator `sui genesis` localnet
plus one sui-node 1.83.1 process per `configs/<variant>.yaml` (paths there are /home/ubuntu on the box).

Rerun (Ubuntu 24.04, sui + sui-node built at the tag, venv with h2 protobuf grpcio-tools pyyaml, the sui-rpc
protos compiled into ~/pb, this dir at ~/tool and `box/` at ~/box):
1. `box/localnet.sh`, `box/activity.sh`, `gen_configs.py`, `nodes.sh start <all variants>`.
2. `cap_ledger.py subscribe` (runs `box/burst.sh` while the streams are open), `prep_proof.py END`,
   `LIST_END=END cap_ledger.py list|proof`, `box/prep_deny.sh`, `cap_policy.py deny`, `deny-late`,
   `traffic`, `transport`, `transport-slow`, `config`, `cap_ledger.py sublimit`.
3. Pull, `zui-dumper convert <pull>/chk <idx data-ingestion-dir>/*.binpb.zst`,
   `zui-dumper loaded <pull>/loaded.jsonl <idx data-ingestion-dir>/*.binpb.zst`, `assemble.py <pull> <repo>`.
   `localnet/loaded.jsonl` carries each transaction's `unchanged_loaded_runtime_objects` (effects field 15),
   which the .chk form drops; without it `list-checkpoints/range-mask-all` cannot match.

Replay notes:
- Every response carries tip-dependent headers (`x-sui-checkpoint-height`, `x-sui-timestamp-ms`,
  `x-sui-timestamp`, `x-sui-lowest-available-*`, `x-sui-epoch`); compare them against the replay tip, not
  as bytes. `date` is dropped.
- subscribe-events: streams opened before the burst; `context.stream_start_seq` is the first checkpoint the
  stream covers (first frame = watermark at start-1). The client cancels (RST_STREAM CANCEL) after N messages,
  so those records have no trailers. `sub-limit/*` ran past the shipped chk range (status-only).
- list-checkpoints cases without `end_checkpoint` depend on the indexed tip at capture time.
- deny/txs.jsonl: the signed transactions (tx = BCS TransactionData, sig = flag||sig||pk). Each was never
  executed on the deny nodes, except transfer-a, executed by `deny-no-early-validation` before
  `deny-user/execute/transfer-a-already-executed`.
- config: NodeConfig Debug print with the 18 MB genesis field elided (sha256/len of the full body kept).
