# tools/truth/net

Ground truth for the `net` lane. One Rust binary, `zui-net-truth`, built into the shared cargo
target dir (`~/.cache/zui/target-swarm/release/zui-net-truth`). It links Mysten's code at the pinned
revisions: `anemo` (git rev `68adc31`, with its quinn, rustls and ring), `mysten-network`'s
`BcsSnappyCodec`, `sui-types` at mainnet-v1.83.1, and the `snap` 1.1 crate.

```
cd tools/truth/net && source ../../env.sh && cargo build --release
V=$ZUI_CORPUS/vectors
zui-net-truth wire   $V/anemo-wire/vectors.jsonl
zui-net-truth snappy $V/sync-rpc-codec/snappy.jsonl
zui-net-truth sync   $V/sync-rpc-codec/sync.jsonl $ZUI_CORPUS/chk 600
zui-net-truth discovery $V/sync-rpc-codec/discovery.jsonl
zui-net-truth peer --key HEX --ready FILE --log FILE [--fixtures DIR] [--server-name S] [--port N]
zui-net-truth bench <name> --iters N --list FILE        # harness baseline protocol
zui-net-truth sync-from --peer HOST:PORT --peer-id HEX [--server-name sui-35834a8a] --from N --to M
              [--concurrency 32] [--bucket https://checkpoints.mainnet.sui.io] [--out results.json]
              [--sample 50] [--key HEX] [--timeout-s 60] [--no-discovery] [--no-signatures]
zui-net-truth serve-probe --peer HOST:PORT --peer-id HEX [--interval-s 5] [--count N]
zui-net-truth peer-id KEYFILE                           # anemo peer id of a deepwave --p2p-key file
```

## sync-from: a sui-node state-sync client against a serving node (p2p-server acceptance)

`sync-from` links sui-network (mainnet-v1.83.1) itself: the anemo-build generated `StateSyncClient`
and `DiscoveryClient` (route names, `BcsSnappyCodec`, request/response types are sui-node's), on an
anemo `Network` with sui-node's QUIC settings (`create_p2p_network`, socket buffers included). It
dials the peer with the expected peer id and runs sui-node's client sequence:

1. `GetCheckpointSummary(BySequenceNumber(0))`: digest must be mainnet's genesis
   `4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S` (sui-node's same-chain test) and the bytes the bucket's.
2. `GetCheckpointAvailability`: highest synced summary (BLS-verified with its epoch's committee) and
   lowest available. `--from`/`--to` accept `N`, `tip`, `tip-N`, `low`, `low+N` against these.
3. `GetKnownPeersV2` and `GetKnownPeersV3` (with our own signed `VersionedNodeInfo::V2`): the
   peer's own info must be signed by the dialed peer id; every known peer goes through sui-network's
   checks (signature over `bcs(info)`, address count and length, anemo-dialable, endpoint identity).
4. Every checkpoint in `[from, to]`, `--concurrency` at a time: `GetCheckpointSummary(BySequenceNumber)`,
   `GetCheckpointContentsV2(summary.content_digest)` with `VersionedFullCheckpointContents::verify_digests`;
   every `--sample`th (and the ends) also `ByDigest`, `GetCheckpointContents` (V1), and the 1.83 paged
   pair `GetCheckpointContentsDigests` + `GetCheckpointTransactions` with sui-node's page checks
   (contents digest, per-item `ExecutionData::digests`, a non-empty page inside the range), plus an
   out-of-range page that must answer 400.
5. In order: `sui_storage::verify_checkpoint_with_committee` on each summary (previous_digest link,
   epoch step, quorum signature; committees from the bucket's `epochs.json` end-of-epoch checkpoints).

Expected bytes come from the public bucket (`{seq}.binpb.zst`, fetched by sui-storage's
`fetch_checkpoint`), turned into state-sync types exactly like sui-node's archive path
(`process_archive_checkpoint`). Every response is compared as BCS bytes. The JSON report has
`requested`, `equal`, `mismatched`, `missing` (the peer said None), `bucket_missing`,
`verify_failures`, `chain_checked`, per-route `count/errors/p50_ms/p99_ms/max_ms`, `total_mb`
(BCS bytes received), `first_diffs` (offset and hex around the first differing byte). Exit status
is nonzero on any mismatch, missing answer, verification failure or failed preamble.

Canonical form (default; `--strict` turns it off). Two parts of an answer differ between honest
sui-nodes and the bucket, so a raw byte match against the bucket is not the truth for them:
- a certified summary's aggregate signature (signer bitmap + BLS aggregate): each validator
  aggregates the signatures it collected. The summary bytes must be equal; the certificate must
  carry a quorum (the chain pass); differing certificate bytes are counted in `cert_bytes_differ`.
- the order of a transaction's own signature list (`SenderSignedData.tx_signatures`, covered by no
  digest): sui-node serves the order the transaction arrived with, while Mysten's archive
  conversion (`TryFrom<&proto::Checkpoint>`) uses the contents' `user_signatures` order. The
  answer must hold exactly the contents' signatures (as a multiset); it is compared in contents
  order and the reorderings are counted in `sig_order_normalized`.

Self-check against Mysten's own sui-node 1.83.1 seeds (runner box, 2026-11-08, run
p2p-server-1108-065420-5bd3-b3): ewr-00, 2,251 checkpoints: 2,251 equal, 0 mismatched or missing,
all chain links and quorum signatures verified, 1,446 signature reorderings, 386 differing
certificates, 182.5 MB in 22.5 s at concurrency 32 (summary p50 69 / p99 82 ms, contents V2
p50 71 / p99 192 ms). lhr-00, 1,251 checkpoints: all equal, 828 reorderings, 1,300 differing
certificates. Discovery V2/V3 own infos verified, 200 known peers, none rejected. `--strict` over
251 lhr-00 checkpoints: 251 mismatched (certificates), as expected.

`serve-probe` is a mainnet-peer imitation: connects, checks checkpoint 0, then asks
`GetCheckpointAvailability` every `--interval-s` (state sync's peer-height poll).

`tools/p2p/serve-accept.sh` runs both against deepwave serving on 8084/udp on a runner box
(loopback and the box's public IP); `tools/p2p/sg-8084.sh open|close|status` (Mac) manages the one
inbound udp/8084 rule the public pass needs.

## Suites and vector formats

`anemo-wire` (`vectors/anemo-wire/vectors.jsonl`, 83 vectors). One JSON object per line, `kind`:
- `version`: `hex` = the 8-byte version frame.
- `frame`: `payload_hex`, `hex` = tokio-util `LengthDelimitedCodec` (4-byte big endian) output.
- `request` / `response`: `route` or `status`, `headers` (sorted pairs), `header_hex` = bincode 1.3
  of anemo's `RawRequestHeader` / `RawResponseHeader` (a field-for-field copy: the originals are
  `pub(crate)`), `body_hex`, `hex` = the whole stream (version frame, header frame, body frame).
  `ordered:false` entries carry several headers in Rust's `HashMap` order, so the encode direction is
  only compared when `ordered` is true; the decode direction is always compared.

`sync-rpc-codec`:
- `snappy.jsonl`: `raw_hex`, `framed_hex` (`snap::write::FrameEncoder`, one `write_all`),
  `block_hex` (`snap::raw::Encoder`). Random, zero, periodic and text-like payloads from 0 B to
  1 MiB, around every block boundary.
- `sync.jsonl`: `bcs_hex` and `snappy_hex` produced by `mysten_network::codec::anemo::BcsSnappyCodec`
  for the state-sync requests (`GetCheckpointSummaryRequest` all three variants,
  `CheckpointContentsDigest`, `u64`, `GetCheckpointTransactionsRequest`, `()`) and for 600+ real
  responses (`Option<CertifiedCheckpointSummary>` of corpus checkpoints, spread over all epochs, and
  `GetCheckpointAvailabilityResponse`).
- `discovery.jsonl`: `GetKnownPeersResponseV2/V3` and `GetKnownPeersRequestV3` bodies holding signed node infos (V1
  and V2 infos, three address kinds, an empty address list, one wrong-key signature), signed as
  sui-network does (`sign(bcs(info))`), with the expected fields and signature verdicts per peer.
- `live-*.jsonl`: exchanges recorded from our own sui-node by `src/net/live.zig`
  (`ZUI_NET_LIVE=host:8084 ZUI_NET_LIVE_RECORD=path ./zig build test -Dlane=net`). Re-compressing the
  decoded BCS must reproduce the node's bytes.

`anemo-interop`: the suite spawns `zui-net-truth peer` (an anemo `Network` with sui-node's QUIC
settings and server name `sui-35834a8a`, serving fixtures and test routes) and drives it with deepwave's
client over loopback. The peer logs every request it decoded to `sessions/net/requests-main.jsonl`,
which the suite compares with what deepwave sent. Routes: `/zui.Test/Echo` (echoes body and `x-*` headers),
`/zui.Test/Big` (deterministic bytes of the requested size), `/zui.Test/Status`, `/zui.Test/Callback`
(the peer then sends requests *to* the client), `/zui.Test/CallbackResult`, and fixture routes.

## Known limits of the truth

- The wire header structs are copies; the QUIC streams themselves are verified end to end by the
  interop suite (a wrong byte makes the Rust peer reject or misparse the request).
- Compression equality is proven for a single `write_all` of the message. The Rust encoder's output
  for messages above 64 KiB depends on the write pattern of `bcs::serialize_into`; deepwave never sends
  such messages (requests are tens of bytes), and the decoder accepts any valid stream.
