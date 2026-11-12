//! deepwave: the deepwave full node (docs/NODE.md).
//!
//!   deepwave --version                                       `deepwave <x.y.z>-<sha>` (sui-node's shape)
//!   deepwave run --dir D [--source http|s3|dir:PATH] [--mode verify|execute] [--from tip|N] [--to N]
//!                [--genesis FILE --epochs FILE --trust-dir PATH] [--serve ADDR] [--metrics ADDR] ...
//!   deepwave check --dir D --against PATH --from A --to B   compare the store with checkpoint blobs
//!   deepwave convert IN.binpb.zst OUT.chk                    archive proto to checkpoint blob
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const node = @import("node");
const rpc_exec = @import("rpc_exec");
const move_vm = @import("move_vm");
const build_options = @import("build_options");
const store = node.store;
const node_options = @import("node_options");
const edge = @import("edge");

/// `deepwave validator ARGS...`: validator mode lives in its own binary (the unaudited validator
/// modules are never linked into deepwave, docs/VALIDATOR-DESIGN.md 3); this hands over to the
/// `deepwave-validator` installed next to this executable with the same arguments.
fn validatorCmd(io: Io, arena: std.mem.Allocator, rest: []const []const u8) !u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = std.process.executableDirPath(io, &buf) catch {
        std.debug.print("deepwave validator: cannot locate deepwave-validator next to this executable\n", .{});
        return 1;
    };
    const exe = try std.fmt.allocPrint(arena, "{s}/deepwave-validator", .{buf[0..n]});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(arena, exe);
    try argv.appendSlice(arena, rest);
    const e = std.process.replace(io, .{ .argv = argv.items });
    std.debug.print("deepwave validator: cannot run {s}: {s} (build it with ./zig build validator)\n", .{ exe, @errorName(e) });
    return 1;
}

const usage =
    \\deepwave run --dir DIR [options]       follow mainnet or testnet: verify, (execute,) store, serve
    \\  --network mainnet | testnet          chain to follow (default mainnet): chain id, protocol table, buckets,
    \\                                       snapshot origin, stream full node, p2p server name (pair it with that
    \\                                       network's --genesis, --epochs, --trust-dir and --packages)
    \\  --source http[:URL] | s3 | dir:PATH  checkpoint source (default http: https://checkpoints.<network>.sui.io,
    \\                                       no credentials; S3 is its fallback when the credentials below load)
    \\  --no-s3-fallback                     http source without the S3 fallback
    \\  --source zui1:ADDR:PORT/KEYHEX[,...]  edge node: follow core nodes (or other edges) over zui/1; the
    \\                                       feeds are verified here like any other source (certificate, digests, objects)
    \\  --profile core | edge | macmini      flag defaults of a node kind (edge: one epoch of history, no read sets, age-out deferred in catch-up;
    \\                                       macmini: Mac mini 32 GB and up); flags after it win
    \\  --edge-feed                          serve the edge feed and its zstd dictionary on --native-listen (core nodes, and
    \\                                       edges that feed other edges); off by default
    \\  --native-http-rpc                    POST /zui1/rpc on the --native-listen TCP port: zui/1 requests over HTTP/1.1 (Workers, fetch;
    \\                                       put a TLS terminator in front); never dry_run, submit, subscribe or the feed
    \\  --gate URL                           access gate: API keys (x-api-key, the zui/1 hello token), rate limits
    \\                                       and usage metering against the gate service at this https base URL; resolve,
    \\                                       free and usage are appended. Needs --gate-token-file and --gate-edge-id. Off by default.
    \\                                       http:// is taken only for a gate on this machine (localhost, 127.0.0.0/8, [::1])
    \\  --gate-token-file FILE               this node's credential for the gate (one line, at least 24 characters), sent as a bearer token
    \\  --gate-edge-id NAME                  this node's name at the gate (A-Z a-z 0-9 . _ -)
    \\  --gate-dir DIR                       the free tier's last answer and the usage spool (default <dir>/node/gate)
    \\  --gate-ca-file FILE                  PEM certificate authorities trusted for the gate connection only, beside the
    \\                                       system roots (a gate behind a private CA)
    \\  --gate-trusted-proxy CIDR            read the caller's address from x-forwarded-for when the peer is in CIDR (repeatable,
    \\                                       at most 8; default none: the socket peer is the caller)
    \\  --edge-conns N                       zui/1 connections to the cores (default 4; the profile's)
    \\  --no-edge-zstd                       ask the cores for raw feeds (no zstd dictionary)
    \\  --feed-max-inflight N                most feed requests in flight at the cores in catch-up (default 16;
    \\                                       set from measurements, never above the window; 0: one per fetcher).
    \\                                       Keep N well under the core's feed queue (64 for all its clients)
    \\                                       divided by the number of edges that follow it
    \\  --edge-fallback off | http[:URL] | dir:PATH
    \\                                       with --source zui1: where checkpoints come from while no core can serve the
    \\                                       next one (down, restarting, no --edge-feed, behind, pruned): http is the
    \\                                       network's public bucket (the --source http path, never S3; --net-max-mbps
    \\                                       applies), dir a local mirror. Falls back after 3 s without an answer (at once
    \\                                       on a core's shutdown notice or a hello without the feed), probes the cores
    \\                                       twice a second and returns after 5 s healthy. Every
    \\                                       checkpoint is verified whichever side served it, and stored as the core's feed
    \\                                       of it would be. One unit restores, follows by the bucket and attaches to the
    \\                                       core when it serves the feed. With http the edge also asks the network's
    \\                                       full node for signature orders, as --source http does (--sig-order-from,
    \\                                       --sig-order-rps 0 = off). Default: http with --profile edge or macmini, else
    \\                                       off (an outage of every core stalls the edge)
    \\  --stream URL[,URL...] | off         live SubscribeCheckpoints streams (gRPC-web) racing each other and the
    \\                                       tip polls; default https://fullnode.<network>.sui.io with a network source
    \\                                       (off with --source zui1: give one to race the cores from a far edge).
    \\                                       Any node works (http://127.0.0.1:9000 = the local sui-node standby);
    \\                                       every checkpoint is verified whichever source wins
    \\  --sig-order-from URL                 node (gRPC-web) asked for the submitted signature order of bucket
    \\                                       checkpoints with sponsored or multi-signer transactions (the bucket holds
    \\                                       only the signer order); default the first loopback --stream URL, else the first
    \\  --sig-order-rps N                    its request budget (default 20, 200 for a loopback node; 0 = off)
    \\  --sig-order-sweep on|off             also sweep committed checkpoints (BatchGetTransactions, 200 a request) and
    \\                                       serve that node's order for transactions stored in the contents' order
    \\                                       (node/sig-order.log; default on)
    \\  --p2p HOST:PORT[@PEERID][,...]       also follow over p2p state sync (anemo) from these peers: summaries
    \\                                       and contents from peers, every transaction executed locally, the
    \\                                       checkpoint taken only when all effects equal the certified ones
    \\  --p2p-key FILE                       Ed25519 network key seed (32 bytes or 64 hex); random when absent
    \\  --p2p-race N                         peers asked for a checkpoint's contents at once, lowest RTT first (default 1;
    \\                                       another joins after 120 ms without an answer)
    \\  --p2p-push-peers N                   peers contents are fetched from and polled at full rate: those whose pushes
    \\                                       arrive first (default 8; 0: every connected peer)
    \\  --p2p-discover N                     peers to add from the seeds' known peers (default 32; 0: seeds only)
    \\  --p2p-only | --source p2p          follow from p2p peers alone (needs --p2p and a store to resume): no bucket,
    \\                                       S3 or stream; a checkpoint deepwave cannot build is retried, never left
    \\  --p2p-pinned SEQ:DIGEST[,...]        pinned checkpoints: a summary at SEQ must have this digest (base58)
    \\  --tiles                             run the p2p tip path as pinned tiles on shared-memory rings (ingest, verify, exec, store, notify); default off
    \\  --tile-cpus A,B,C,D,E                cores for the five tiles in order (default: not pinned); --tile-spin: never sleep when idle
    \\  --p2p-exec-threads N                 threads executing a checkpoint's independent transactions (default 4; 1: in order)
    \\  --p2p-reconcile-wait S               a checkpoint built over p2p has its read sets compared with sui-node's copy and repaired
    \\                                       (the stream's duplicate, or the bucket's after S seconds; default 10; 0: off)
    \\  --sig-fast                           signature speed layer: decoded public-key caches, zkLogin proof cache, multisig batch (on with --sig-parallel; same verdicts)
    \\  --sig-parallel MODE                  auto|on|off: batch signature and certificate checks on every core (CPU pool from the hw plan) and on
    \\                                       the GPU when one passes its startup self-check; auto = on with more than 2 cores or such a GPU (default auto;
    \\                                       verdicts identical in every mode)
    \\  --gpu MODE                           off|auto|metal|cuda: accelerator for --sig-parallel (default: $ZUI_GPU, unset = auto)
    \\  --cert-batch N                       checkpoint certificates decided as randomized batches of up to N (default 0: one
    \\                                       pairing check per certificate, on every worker; same verdicts)
    \\  --exec-threads N                     execute mode: threads running transactions, across checkpoints (default: half the CPUs, at most 16; 0: one at a time on the ordered thread)
    \\  --exec-window N                      execute mode: checkpoints in flight between commit and execution (default 64)
    \\  --exec-cache-mb N                    execute mode: memory the threads' Move package caches share (default 3072)
    \\  --exec-window-mb N                   execute mode: checkpoint bytes in flight, besides --exec-window (default 128)
    \\  --p2p-trace                          log each applied checkpoint's p2p timeline (ms after its timestamp)
    \\  --p2p-listen ADDR:PORT | off         serve state sync and discovery to inbound peers on this UDP address. Off unless
    \\                                       given here or as fullnode.yaml p2p-config.listen-address (sui-node binds
    \\                                       0.0.0.0:8084 even without the key; deepwave does not). `off` wins over the yaml.
    \\                                       A port already in use is a warning, not a failed start
    \\  --p2p-external ADDR:PORT             address we advertise in our signed node info (IP, [IPv6], DNS name or a multiaddr)
    \\  --p2p-access public|private|trusted  advertised access type (sui-node discovery.access-type; default public)
    \\  --p2p-opt KEY=VALUE                  a sui-node p2p-config key (fullnode.yaml path under p2p-config), e.g.
    \\                                       discovery.peer-failure-cooldown-ms=3600000, state-sync.use-get-checkpoint-contents-v2=false,
    \\                                       discovery.allowlisted-peers=PEERID[@MULTIADDR],..., peer-address-overrides=PEERID@MULTIADDR[|..],...,
    \\                                       discovery.peer-addr-store-path=PATH|off (default DIR/discovery_peer_cache.yaml)
    \\  --p2p-listen-threads N               inbound request workers (default 0: auto)
    \\  --config FILE                        `key = value` lines of these flags without `--`, or sui-node's fullnode.yaml
    \\                                       (FILE.yaml/.yml: the keys deepwave has are mapped, the rest noted); command-line flags win
    \\  --s3-profile NAME                    credentials profile (default: default)
    \\  --s3-credentials FILE                credentials file (default $AWS_SHARED_CREDENTIALS_FILE or ~/.aws/credentials)
    \\  --s3-budget USD                      stop fetching when the estimated spend reaches this (default 5)
    \\  --mode verify | execute              verify-only (default) or also execute what exec supports
    \\  --from tip | N                       first checkpoint for a fresh store (default tip); a store resumes
    \\  --to N                               stop after checkpoint N
    \\  --genesis FILE                       the network's genesis.blob (trust root for the committee walk)
    \\  --epochs FILE                        epoch index (epochs.jsonl) to find end-of-epoch checkpoints fast
    \\  --trust-dir PATH                     local checkpoints tried first during the committee walk
    \\  --serve ADDR                         sui.rpc.v2 gRPC (h2c), e.g. 127.0.0.1:9000
    \\  --h2-max-cancelled N                 calls a peer cancelled that are still running, per connection, before it is closed
    \\                                       with GOAWAY(ENHANCE_YOUR_CALM) (default 4096; deepwave's rapid-reset bound)
    \\  --serve-tls ADDR                     the same sui.rpc.v2 over TLS 1.3 (sui-node rpc.https-address); needs --serve
    \\  --serve-tls-cert FILE --serve-tls-key FILE  PEM certificate chain and private key (rpc.tls; P-256, P-384,
    \\                                       Ed25519 or RSA; loaded again on SIGHUP or when the files change: a renewed
    \\                                       certificate needs no restart); without them a self-signed P-256 cert for
    \\                                       localhost (13 days)
    \\  --rpc KEY=VALUE                      fullnode.yaml rpc.* scalar: grpc-timeout-ms (60000, 0 = none),
    \\                                       max-connection-age-secs (14400, 0 = none), max-connection-age-grace-secs (600),
    \\                                       subscription-watermark-interval (25), subscription-max-subscribers (1024)
    \\  --native-listen ADDR                 zui/1 native protocol on UDP (QUIC zui/1 + WebTransport), off by default
    \\  --native-cert FILE --native-key FILE  PEM certificate chain (leaf first) and private key for zui/1 and WebTransport:
    \\                                       a WebPKI certificate, so browsers connect with a plain https URL and no hash
    \\                                       (P-256, P-384, Ed25519 or RSA; checked at start; loaded again on SIGHUP or when
    \\                                       the files change). Without them: a self-signed P-256 certificate, rotated weekly
    \\  --native-cert-hash-file FILE         write the WebTransport cert sha256, the zui/1 key, the next cert's sha256 and the
    \\                                       unix second it takes over (one per line; rewritten at each 7-day rotation)
    \\  --native-identity-file FILE          zui/1 Ed25519 seed, kept across restarts (default <dir>/node/native-identity.seed);
    \\                                       the WebTransport certificates derive from it
    \\  --native-keys FILE                   zui/1 API keys: `<key> <tier> [<Agent Pass hex>]` per line (NATIVE-PROTOCOL.md 6.1)
    \\  --native-pass-dir DIR                Agent Pass ledgers (default <dir>/node/agent-pass)
    \\  --native-feed-workers N              threads that assemble edge feeds for --edge-feed (default 4)
    \\  --native-feed-queue N                edge feed requests held at once, queued or running, for all clients together
    \\                                       (default 64). Each client with requests in flight has an equal share of it
    \\                                       and may use what the others leave; over its share of a full queue it is refused
    \\  --rpc-release 1.83 | 1.84 | N        GetEpoch protocol_config lists the fields of this sui-node release (default 1.83, as sui-node 1.83.1; raised to the chain's protocol version when newer)
    \\  --indexes | --no-indexes             StateService indexes (on disk in DIR/state-index: built from the live set once, then replayed from its watermark)
    \\  --metrics ADDR                       Prometheus text at http://ADDR/metrics
    \\  --metrics-push-url URL               also POST the registry to URL (sui-node metrics.push-url: protobuf, snappy; no mTLS)
    \\  --metrics-push-interval S            push period in seconds (60)
    \\  --admin-port N                       admin interface on 127.0.0.1:N (default 1337 as sui-node; 0 = off):
    \\                                       GET/POST /logging, /capabilities, /node-config, /version
    \\  --state-hash verify-only|halt|off    end-of-epoch state root check; on a mismatch stop executing
    \\                                       (verify-only, default) or stop the node (halt)
    \\  --sui-conservation verify-only|halt|off  end-of-epoch SUI conservation check (sui-node's
    \\                                       expensive_check_sui_conservation) on a background thread;
    \\                                       a failure stops executing (verify-only) or stops the node
    \\                                       (halt); off by default, as sui-node's
    \\                                       enable-epoch-sui-conservation-check
    \\  RUST_LOG=FILTER                      log filter (info by default; `debug`, `warn,serve=debug`), reloadable via POST /logging
    \\  RUST_LOG_JSON=1                      JSON lines (tracing-subscriber layout: timestamp, level, fields.message, target)
    \\  RUST_LOG_FILE=PREFIX                 log to PREFIX.YYYY-MM-DD (UTC day, appended) instead of stderr
    \\  --execute-epoch-from HOST:PORT[/plain]  serve ExecuteTransaction (to validators); committee from GetEpoch there
    \\  --core-upstream HOST:PORT[/pin=HEX|/plain]  an edge's core (its sui.rpc.v2 gRPC): with --serve, requests this node
    \\                                       cannot answer exactly are passed to it and its answer returned unchanged.
    \\                                       TLS against the system CAs; /pin=HEX: TLS with the core's
    \\                                       certificate SHA-256 pinned; /plain: cleartext (the default only for loopback)
    \\  --core-upstream-pin HEX              the same pin, as a flag
    \\  --edge-forward on | off              forwarding with --core-upstream (default on)
    \\  --edge-read-sets on | off            read sets through the edge feed (default off). On an
    \\                                       edge (--source zui1:): ask the cores for each checkpoint's loaded-object lists,
    \\                                       keep read sets, and answer effects, balance_changes and objects here for the
    \\                                       checkpoints that have one. On a node with read sets and --edge-feed: mark
    \\                                       checkpoints and send their lists to edges that ask
    \\  --edge-raw hold | reads | off        read-after-write for transactions executed through this node (default reads):
    \\                                       reads: answer the execute at once; reads of what it wrote wait until this node
    \\                                       applied it; hold: hold the execute answer instead; off: neither
    \\  --edge-raw-waiters N                 reads that may wait at once (default a quarter of the serve workers); more are forwarded
    \\  --edge-execute-wait-ms N             the bound of either wait (default 2000; 0: off)
    \\  --edge-max-lag N                     checkpoints behind the core before everything is forwarded (default 5)
    \\  --edge-ahead-wait-ms N               wait for a checkpoint or object version ahead of this node before forwarding (default 300)
    \\  --edge-balance-lists forward | local where ListBalances is answered (default forward; env ZUI_EDGE_BALANCE_LISTS).
    \\                                       local: from this node's index; it can differ from the core's answer only in
    \\                                       rows of coin types emptied to zero; needs --indexes
    \\  --edge-simulate forward | local | local-gas
    \\                                       where SimulateTransaction is answered (default forward; env ZUI_EDGE_SIMULATE).
    \\                                       local needs the whole live set (a snapshot restore or genesis), else it stays on
    \\                                       forward; gas selection and simulations that fail here still go to the core.
    \\                                       local-gas: gas selection here too (needs --indexes), without the core's
    \\                                       proposer restriction
    \\  --pending-tx-dir PATH|off       ExecuteTransaction's pending-tx log (default DIR/node/pending-tx): resubmitted after a restart
    \\  --exec-driver zui|sui-node      ExecuteTransaction's validator driver: zui (default: 3 proposers, effects with the fastest acks)
    \\                                   or sui-node (1.83.1 exactly: gas price / RGP proposers, acks without details); same responses
    \\  --workers N --fetchers N --window N --poll-ms N --status-every S
    \\                                       (--poll-ms: tip request spacing, default 25 for http, 100 for s3)
    \\  --net-max-mbps N                     download cap in MiB per second (megabytes, not megabits) for checkpoint
    \\                                       fetches and the snapshot restore together; 0 (default) = no cap
    \\  --lookahead N                        at the tip, checkpoints past the frontier requested at once each time it moves (default 2, 0 = off)
    \\  --sync none | data | full            store durability (default data)
    \\  --vm-aot                             run compiled Move code (src/move/vm/aot_gen, built by deepwave-aot) for packages whose bytecode digest
    \\                                       matches; everything else interprets (off by default)
    \\  --vm-aot-hot FILE                    with --vm-aot: only the functions this hot list names (<addr>::<module>::<fn|*> [calls [instrs]] per line)
    \\  --no-halt                            execute mode: keep going after a mismatch
    \\  --snapshot EPOCH | latest | retained   empty store: restore Mysten's formal snapshot of EPOCH, then follow;
    \\                                       retained: the newest one at or below current - --retention-epochs, so the
    \\                                       node holds every checkpoint sui-node holds (latest starts with less)
    \\  --epoch-records N                   GetEpoch records of the N epochs before the current one, filled from their
    \\                                       end-of-epoch checkpoints when the store did not follow them (default 30)
    \\  --snapshot-origin URL | dir:PATH     where snapshot files come from (default https://formal-snapshot.<network>.sui.io)
    \\  --snapshot-threads N                 partitions fetched and checked in parallel (default 8)
    \\  --live-capacity N                   initial live index capacity of a new store (default 1M; leave it unset for a snapshot restore: a large initial table makes every bulk-restore lookup a random fault)
    \\  --live-dirty-pages N                live-table pages changed before a flush (default 131072, 512 MiB; the flush runs on its own thread, the commit path only freezes the set)
    \\  --index-flush-interval N            checkpoints between live-table flushes (default 4096; bounds recovery replay)
    \\  --flush-writers N                   live-table flush writers: 0 (default) one buffered writer synced at the next flush; N > 0 parallel buffered writers with write-back as they go and one fdatasync
    \\  --flush-direct                      with --flush-writers N: O_DIRECT writers (Linux; leaves flushed pages cold in the page cache)
    \\  --compress-threads N                threads compressing one commit group's segment chunks (default min(4, cores); same bytes for any N)
    \\  --retention-epochs N                sui-node num-epochs-to-retain-for-checkpoints (default 2): checkpoints, transactions, effects, events (CONTRACTS 6.8)
    \\  --object-retention-epochs N         sui-node num-epochs-to-retain (default 1): superseded object versions
    \\  --no-compress                       write new segments uncompressed (default: zstd chunks, store/chunk.zig)
    \\  --age-mem-mb N                      memory the ager may hold (default 256): a quarter for the set of superseded locations it remembers, half for the live set's bits, the rest for its buffers; exported as zui_store_age_mem_bytes
    \\  --age-out [on | off | defer]        background age-out: superseded versions and checkpoint data below the retention floors become holes in sealed segments, freed by hole punching. on (also the bare flag): always; defer: only while the node is within 10 s of the tip, so catch-up has the disk to itself (it still catches up in one run once 16 GiB of history wait below the checkpoint floor); off. Default off; the edge and macmini profiles set defer. ZUI_AGE_OUT=on|off|defer overrides both (1: on, or defer where that is configured; 0: off)
    \\  --chunk-cache-mb N                  decoded-chunk cache budget in MiB (default 1024)
    \\  --hw SPEC                           machine profile and path overrides (also env ZUI_HW), e.g. profile=server,sha_ni=off,pin=on;
    \\                                       off unless given; explicit cache flags win. keys: src/core/hw.zig, `deepwave-hw report`
    \\  --cp-cache-mb N                     pre-encoded GetCheckpoint response cache in MiB (default 256, 0 off)
    \\  --no-smooth                         prune whole epochs at once (sui-node smooth: false); default: smoothed over the epoch like sui-node
    \\  --memtable-versions N               object versions per index run (default 4M; leave it unset for a snapshot restore, like --live-capacity: the bulk restore needs no larger runs)
    \\  --keep-spool                         keep fetched blobs in DIR/node/spool (for check after a live run)
    \\  --no-read-sets                       do not store input versions and loaded runtime object lists
    \\  --packages DIR                       execute mode: `<id hex>.obj` package objects tried before the store
    \\  --packages-from URL                  execute mode: a full node (gRPC-web) asked for packages found nowhere
    \\                                       else, 20 req/s, saved to --packages DIR (untrusted: a wrong one mismatches)
    \\  --deny-state FILE                    execute mode: exec's deny-list state (deny/objects.bin.zst) for a store without the full live set
    \\  --tx-deny KEY=VALUE                  transaction-deny-config rule (repeatable; fullnode.yaml keys, lists comma-separated)
    \\  --policy KEY=VALUE                   policy-config (traffic controller) key (repeatable; `off` = policy-config: null)
    \\  --early-validation true|false        ExecuteTransaction's early validation (default true; false also skips the
    \\                                       transaction-deny-config checks, as transaction-driver-config does)
    \\  --dev-inspect-disabled true|false    SimulateTransaction with checks disabled (fullnode.yaml dev-inspect-disabled):
    \\                                       true refuses it as sui-node does, false runs it as sui-node's dev-inspect
    \\                                       (private functions and arbitrary values from any client). Not given: no
    \\                                       dev-inspect execution, requests that need its rules answer UNIMPLEMENTED
    \\  --ledger-history KEY=VALUE           a ListTransactions/ListEvents/ListCheckpoints limit (fullnode.yaml rpc.ledger-history,
    \\                                       e.g. list-checkpoints.max-limit-items=100); repeatable
    \\  --snapshot-write DIR                 at every epoch end write DIR/epoch_<E>/, a formal snapshot (Mysten's format) checked
    \\                                       against the certified root before its MANIFEST appears
    \\  --rpc-index-dir PATH                 rpc index (with --serve; default DIR/rpc; fullnode.yaml zui.rpc-index-path)
    \\  --ledger-history-dir PATH            ledger-history index (default DIR/ledger-history; zui.ledger-history-path)
    \\  --no-history-backfill                never build the ledger-history index for checkpoints it does not hold (also
    \\                                       ZUI_LH_BACKFILL=0): List* then answer from where the index begins
    \\  --snapshot-write-threads N           (default half the cores, 4 to 16)
    \\  --drain-ms N                         SIGTERM: time open RPC calls and streams get to finish (default 20000)
    \\  --shutdown-timeout S                 SIGTERM: exit after S seconds even if the flush is not done (default 110)
    \\  --handoff-sock PATH                  zero-downtime upgrade: take over from a running deepwave on PATH, and be taken over from (SIGUSR2 starts a successor); takes DIR/zui.lock; off by default
    \\  --verify-fallback                    protocol newer than this binary: keep following and serving, pause execution (alert lines are always on; zui_protocol_* metrics with this flag); off by default
    \\deepwave --config-path FILE.yaml [flags]          sui-node's command line: run with its fullnode.yaml
    \\deepwave config-check FILE                         the deepwave flags a config (fullnode.yaml or key = value) becomes
    \\deepwave check --dir DIR --against PATH --from A --to B
    \\deepwave convert IN.binpb.zst OUT.chk
    \\deepwave --version | --protocol-range           sui-node-shaped version line | supported protocol range
    \\deepwave decode-bench FILE.binpb.zst...           per-checkpoint cost: zstd (windowed vs direct) and proto conversion
    \\deepwave stream-check [--network N] [--stream URL] [--source http[:URL]] [--count N]
    \\                                     N live stream checkpoints vs the bucket's: blob and aux byte-equal
    \\deepwave snapshot-make SRC_DIR FROM TO EPOCH OUT_DIR    test snapshot: net live set of FROM..TO (no tombstones)
    \\deepwave snapshot-check [--network N] --epoch E [--origin URL|dir:PATH] [--parts B_P,...]   check formal snapshot partitions
    \\deepwave store-chunkbench DIR EPOCH [SAMPLE_MIB] [THREADS]                 chunk-size study (ratio, compress and decode speed) on a raw segment
    \\deepwave store-compress DIR [THREADS] [CHUNK_KIB]                           rewrite a stopped store's raw segments as compressed chunks (same logical offsets)
    \\deepwave du DIR [--kinds EPOCH [SAMPLE_MIB]]                                disk use per component (store parts, indexes), per segment ratio; --kinds: bytes by record kind
    \\
;

/// `--tx-deny KEY=VALUE` (transaction-deny-config) and `--policy KEY=VALUE` (policy-config), as
/// fullnode_yaml.zig writes them; installed process-wide before the node serves.
const policy_flags = struct {
    var tx_deny: std.ArrayList([]const u8) = .empty;
    var policy: std.ArrayList([]const u8) = .empty;
    var ctl: node.serve.traffic.Controller = undefined;

    fn install() !void {
        const arena = std.heap.page_allocator;
        const d = try rpc_exec.txdeny.parseItems(arena, tx_deny.items);
        rpc_exec.txdeny.install(d);
        if (d.has_dynamic_transaction_checks) std.log.warn("transaction-deny-config: dynamic-transaction-checks: zui evaluates constant Starlark programs only (True, False, integers, a // b); other programs pass", .{});
        if (!d.rules.isEmpty()) std.log.info("transaction-deny-config: deny rules active (GET /transaction-deny-config on the admin port)", .{});
        if (!rpc_exec.live.early.enabled.load(.monotonic)) std.log.info("transaction-driver-config: early validation off (ExecuteTransaction submits without the deny and input checks)", .{});
        if (try node.serve.traffic.parseItems(arena, policy.items)) |pc| {
            // the controller's tables grow and shrink at run time: a real allocator, not pages
            ctl = try node.serve.traffic.Controller.init(std.heap.smp_allocator, pc, node.serve.h2.meta.monoNs);
            node.node.admin.traffic_ctl = &ctl;
        } else node.node.admin.traffic_ctl = null;
    }
};

// Every level is compiled in; the runtime filter (RUST_LOG, admin POST /logging) decides.
pub const std_options: std.Options = .{ .log_level = .debug, .logFn = logFn };

fn logFn(comptime level: std.log.Level, comptime scope: @TypeOf(.enum_literal), comptime fmt: []const u8, args: anytype) void {
    if (!node.node.logfilter.enabled(level, @tagName(scope))) return;
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    // Pacific time for humans: PST (UTC-8) in November; the tag says which offset was used.
    const pst = @as(i64, @intCast(ts.sec)) - 8 * 3600;
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(pst) };
    const ds = es.getDaySeconds();
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const out = node.node.logout;
    if (out.json) {
        // RUST_LOG_JSON: tracing-subscriber's JSON layout (UTC timestamp), message escaped
        var mbuf: [2048]u8 = undefined;
        var mw = std.Io.Writer.fixed(&mbuf);
        mw.print(fmt, args) catch {};
        const msg = mw.buffered();
        var jbuf: [4608]u8 = undefined;
        out.write(out.jsonLine(&jbuf, level, @tagName(scope), msg, @intCast(ts.sec), @intCast(ts.nsec)));
        return;
    }
    var buf: [2048]u8 = undefined;
    const prefix = std.fmt.bufPrint(&buf, "{d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} PST {s} ", .{ yd.year, md.month.numeric(), @as(u32, md.day_index) + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(), node.ops.levelName(level) }) catch return;
    const rest = std.fmt.bufPrint(buf[prefix.len..], fmt ++ "\n", args) catch return;
    out.write(buf[0 .. prefix.len + rest.len]);
}

/// `run --config FILE`: the file's `key = value` lines (`#` comments, blank lines) are the run
/// flags without their `--` (`dir = /data/zui`, `source = s3`, `keep-spool = true`), placed before
/// the command line's flags, so a flag given on the command line wins.
/// Run flags this build parses for fullnode.yaml keys owned by other lanes (fullnode_yaml.Options).
const yaml_opts: node.fullnode_yaml.Options = .{
    .p2p_seeds_flag = if (@hasField(node.Config, "p2p")) "--p2p" else null,
    .p2p_key_flag = if (@hasField(node.Config, "p2p_key")) "--p2p-key" else null,
    // lane p2p-full: the listener is off unless fullnode.yaml sets listen-address (or the flag is
    // given); `--p2p-listen off` after the config turns it off, and a busy port only warns.
    .p2p_listen_flag = "--p2p-listen",
    .p2p_external_flag = "--p2p-external",
    .p2p_opt_flag = "--p2p-opt",
    .p2p_access_flag = "--p2p-access",
    .p2p_pinned_flag = "--p2p-pinned",
    // lane storage-fit: sui-node's two pruning windows (CONTRACTS 6.8).
    .object_retention_flag = "--object-retention-epochs",
};

/// fullnode.yaml -> flags, with each note logged (warn or info). Never fails on a key.
fn yamlFlags(arena: std.mem.Allocator, io: Io, path: []const u8, log_notes: bool) ![]const []const u8 {
    const text = try Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20));
    const tr = try node.fullnode_yaml.translate(arena, text, yaml_opts);
    if (log_notes) for (tr.notes) |nt| switch (nt.level) {
        .warn => std.log.warn("{s}: {s}", .{ path, nt.text }),
        .info => std.log.info("{s}: {s}", .{ path, nt.text }),
    };
    return tr.args;
}

fn withConfigFile(arena: std.mem.Allocator, io: Io, args: []const []const u8) ![]const []const u8 {
    var path: ?[]const u8 = null;
    var rest: std.ArrayList([]const u8) = .empty;
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--config") and i + 1 < args.len) {
            path = args[i + 1];
            i += 1;
        } else try rest.append(arena, args[i]);
    }
    const p = path orelse return args;
    var out: std.ArrayList([]const u8) = .empty;
    try out.appendSlice(arena, args[0..2]);
    if (node.fullnode_yaml.looksLikeYaml(p)) {
        try out.appendSlice(arena, try yamlFlags(arena, io, p, true));
        try out.appendSlice(arena, rest.items);
        return out.items;
    }
    const text = try Io.Dir.cwd().readFileAlloc(io, p, arena, .limited(1 << 20));
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, if (std.mem.indexOfScalar(u8, raw, '#')) |h| raw[0..h] else raw, " \t\r");
        if (line.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=');
        const key = std.mem.trim(u8, if (eq) |e| line[0..e] else line, " \t");
        const val = if (eq) |e| std.mem.trim(u8, line[e + 1 ..], " \t") else "true";
        const is_bool = for ([_][]const u8{ "keep-spool", "no-read-sets", "no-halt", "no-s3-fallback", "p2p-only", "tiles", "tile-spin", "edge-feed", "no-edge-zstd", "native-http-rpc" }) |b| {
            if (std.mem.eql(u8, key, b)) break true;
        } else false;
        if (is_bool) {
            if (std.mem.eql(u8, val, "true")) try out.append(arena, try std.fmt.allocPrint(arena, "--{s}", .{key}));
            continue;
        }
        try out.append(arena, try std.fmt.allocPrint(arena, "--{s}", .{key}));
        try out.append(arena, val);
    }
    try out.appendSlice(arena, rest.items);
    return out.items;
}

fn hwSpecErr(e: node.core.hw.ParseError, f: *const node.core.hw.ParseFail) u8 {
    std.debug.print("--hw / ZUI_HW: {s} at {s}={s}\n", .{ @errorName(e), f.key[0..f.key_len], f.value[0..f.value_len] });
    return 2;
}

fn need(args: []const []const u8, i: *usize) ![]const u8 {
    i.* += 1;
    if (i.* >= args.len) return error.MissingValue;
    return args[i.*];
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const raw_args0 = try init.minimal.args.toSlice(init.arena.allocator());
    // sui-node's command line (`--config-path FILE`): the same unit file runs deepwave.
    const raw_args = if (raw_args0.len >= 3 and std.mem.eql(u8, raw_args0[1], "--config-path")) blk: {
        var v: std.ArrayList([]const u8) = .empty;
        try v.appendSlice(init.arena.allocator(), &.{ raw_args0[0], "run", "--config" });
        try v.appendSlice(init.arena.allocator(), raw_args0[2..]);
        break :blk v.items;
    } else raw_args0;
    node.node.logout.init();
    if (std.c.getenv("RUST_LOG")) |f| node.node.logfilter.set(std.mem.span(f)) catch {
        std.debug.print("RUST_LOG: not a filter, keeping {s}\n", .{node.node.logfilter.default_text});
    };
    // `run --config FILE` expands to the file's flags followed by the command line's.
    const args = if (raw_args.len >= 2 and std.mem.eql(u8, raw_args[1], "run")) try withConfigFile(init.arena.allocator(), io, raw_args) else raw_args;
    if (args.len < 2) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "--version") or std.mem.eql(u8, cmd, "-V")) {
        var buf: [128]u8 = undefined;
        var w = std.Io.File.stdout().writer(io, &buf);
        try node.node.ops.printVersion(&w.interface, build_options.git_sha);
        try w.interface.flush();
        return 0;
    }
    if (std.mem.eql(u8, cmd, "--protocol-range")) {
        var buf: [256]u8 = undefined;
        var w = std.Io.File.stdout().writer(io, &buf);
        try node.node.ops.printProtocolRange(&w.interface);
        try w.interface.flush();
        return 0;
    }
    if (std.mem.eql(u8, cmd, "validator")) return validatorCmd(io, init.arena.allocator(), args[2..]);
    if (std.mem.eql(u8, cmd, "config-check") and args.len == 3) return configCheckCmd(init.arena.allocator(), io, args[2]);
    if (std.mem.eql(u8, cmd, "convert") and args.len == 4) return convertCmd(gpa, io, args[2], args[3]);
    if (std.mem.eql(u8, cmd, "check")) return checkCmd(gpa, io, args);
    if (std.mem.eql(u8, cmd, "p2p-probe")) return node.p2p_probe.run(gpa, io, args);
    if (std.mem.eql(u8, cmd, "store-compress") and args.len >= 3) return storeCompressCmd(gpa, io, args[2..]);
    if (std.mem.eql(u8, cmd, "du")) return node.du.run(gpa, io, args[2..]);
    if (std.mem.eql(u8, cmd, "store-chunkbench") and args.len >= 4) return storeChunkBenchCmd(gpa, io, args[2..]);
    if (std.mem.eql(u8, cmd, "stream-check")) return streamCheckCmd(gpa, io, args);
    if (std.mem.eql(u8, cmd, "history-bench")) return node.history_bench.run(gpa, io, args);
    if (std.mem.eql(u8, cmd, "decode-bench") and args.len >= 3) return decodeBenchCmd(gpa, io, args[2..]);
    if (std.mem.eql(u8, cmd, "snapshot-check")) return snapshotCheckCmd(gpa, io, args);
    if (std.mem.eql(u8, cmd, "snapshot-make") and args.len == 7) return snapshotMakeCmd(gpa, io, args[2], try std.fmt.parseInt(u64, args[3], 10), try std.fmt.parseInt(u64, args[4], 10), try std.fmt.parseInt(u64, args[5], 10), args[6]);
    if (!std.mem.eql(u8, cmd, "run")) {
        std.debug.print("{s}", .{usage});
        return 2;
    }

    var cfg: node.Config = .{ .dir = "", .source = .{ .http = .{} }, .admin_port = node.node.admin.default_port };
    cfg.version_label = try std.fmt.allocPrint(init.arena.allocator(), "{s}-{s}", .{ node.node.ops.version, build_options.git_sha });
    var execute_epoch_from: ?[]const u8 = null;
    // ExecuteTransaction's pending-tx log (sui-node fullnode_pending_transactions); default
    // DIR/node/pending-tx, "off" for none
    var pending_tx_dir: ?[]const u8 = null;
    var exec_driver: rpc_exec.live.node_exec.NodeExec.Driver = .zui;
    var stream_url: ?[]const u8 = null;
    var stream_set = false;
    var vm_aot = false;
    var vm_aot_hot: ?[]const u8 = null;
    // Machine profile (core/hw.zig): ZUI_HW first, `--hw` layered on top. Applied only if either is given.
    const hw = node.core.hw;
    var hw_spec: hw.Spec = .{};
    var hw_fail: hw.ParseFail = .{};
    hw.parseEnv(&hw_spec, &hw_fail) catch |e| return hwSpecErr(e, &hw_fail);

    var sig_parallel: node.gpu.engine.Parallel = .auto;
    var cert_batch: ?u32 = null;
    var gpu_mode: ?node.gpu.Mode = null;
    var edge_conns: ?u32 = null;
    var feed_max_inflight: ?u32 = null;
    var edge_zstd = true;
    var edge_fallback: ?node.node.EdgeFallbackSpec = null;
    var gate_url: ?[]const u8 = null;
    var gate_token_file: ?[]const u8 = null;
    var gate_edge_id: ?[]const u8 = null;
    var gate_dir: ?[]const u8 = null;
    var gate_ca_file: ?[]const u8 = null;
    var gate_proxies: [node.gate.max_proxies]edge.gate.ident.Cidr = undefined;
    var gate_nproxies: usize = 0;
    var profile: ?edge.profile.Kind = null;
    // `--profile` sets defaults, so it is applied before any other flag (a flag still wins).
    {
        var k: usize = 2;
        while (k + 1 < args.len) : (k += 1) if (std.mem.eql(u8, args[k], "--profile")) {
            profile = edge.profile.Kind.parse(args[k + 1]) orelse return usageErr("--profile core | edge | macmini");
            const ps = edge.profile.settings(profile.?);
            cfg.store_cfg.retention_epochs = ps.retention_epochs;
            cfg.store_cfg.object_retention_epochs = ps.object_retention_epochs;
            // A profile with age-out runs it deferred: never against catch-up.
            cfg.age_out = if (ps.age_out) .deferred else .off;
            cfg.store_cfg.cache_bytes = @as(u64, ps.chunk_cache_mb) << 20;
            cfg.cp_cache_bytes = @as(u64, ps.cp_cache_mb) << 20;
            cfg.fetchers = ps.fetchers;
            cfg.window = ps.window;
            cfg.read_sets = ps.read_sets;
            cfg.indexes = ps.indexes;
            cfg.edge_feed = ps.edge_feed and profile.? != .core;
            cfg.native_http_rpc = ps.http_rpc;
            std.log.info("profile {s}: cache budget about {d} MiB", .{ @tagName(profile.?), edge.profile.cacheBudgetMb(ps) });
        };
    }
    // the edge's policy settings from the environment; the flags below come after and win
    if (edge.forward.policyEnv(&cfg.edge_forward_cfg, if (std.c.getenv("ZUI_EDGE_BALANCE_LISTS")) |v| std.mem.span(v) else null, if (std.c.getenv("ZUI_EDGE_SIMULATE")) |v| std.mem.span(v) else null)) |msg| return usageErr(msg);
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--dir")) {
            cfg.dir = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--network")) {
            cfg.network = node.node.Network.parse(try need(args, &i)) orelse return usageErr("--network mainnet | testnet");
        } else if (std.mem.eql(u8, a, "--source")) {
            const v = try need(args, &i);
            if (std.mem.eql(u8, v, "s3")) {
                // Copy the fallback's settings out first: assigning `cfg.source` while its initializer
                // reads `cfg.source.http.fallback` aliases the result location, and the
                // --s3-credentials/--s3-profile given before --source s3 were lost.
                if (cfg.source != .s3) {
                    const keep: node.node.S3Spec = if (cfg.source == .http) cfg.source.http.fallback orelse .{} else .{};
                    cfg.source = .{ .s3 = keep };
                }
            } else if (std.mem.eql(u8, v, "http")) {
                if (cfg.source != .http) cfg.source = .{ .http = .{} };
            } else if (std.mem.startsWith(u8, v, "http:")) {
                cfg.source = .{ .http = .{ .base = v[5..] } };
            } else if (std.mem.startsWith(u8, v, "dir:")) {
                cfg.source = .{ .dir = v[4..] };
            } else if (std.mem.startsWith(u8, v, "zui1:")) {
                cfg.source = .{ .zui1 = .{ .cores = v[5..] } };
            } else if (std.mem.eql(u8, v, "p2p")) {
                cfg.p2p_only = true;
            } else return usageErr("--source http[:URL] | s3 | dir:PATH | p2p");
        } else if (std.mem.eql(u8, a, "--profile")) {
            _ = try need(args, &i); // applied above
        } else if (std.mem.eql(u8, a, "--edge-feed")) {
            cfg.edge_feed = true;
        } else if (std.mem.eql(u8, a, "--native-http-rpc")) {
            cfg.native_http_rpc = true;
        } else if (std.mem.eql(u8, a, "--gate")) {
            gate_url = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--gate-token-file")) {
            gate_token_file = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--gate-edge-id")) {
            gate_edge_id = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--gate-dir")) {
            gate_dir = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--gate-ca-file")) {
            gate_ca_file = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--gate-trusted-proxy")) {
            if (gate_nproxies == gate_proxies.len) return usageErr("--gate-trusted-proxy: at most 8");
            gate_proxies[gate_nproxies] = edge.gate.ident.Cidr.parse(try need(args, &i)) orelse return usageErr("--gate-trusted-proxy CIDR, e.g. 10.0.0.0/8 or 2001:db8::/32");
            gate_nproxies += 1;
        } else if (std.mem.eql(u8, a, "--edge-conns")) {
            edge_conns = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--feed-max-inflight")) {
            feed_max_inflight = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--no-edge-zstd")) {
            edge_zstd = false;
        } else if (std.mem.eql(u8, a, "--edge-fallback")) {
            const v = try need(args, &i);
            edge_fallback = if (std.mem.eql(u8, v, "off"))
                .off
            else if (std.mem.eql(u8, v, "http"))
                .{ .http = .{} }
            else if (std.mem.startsWith(u8, v, "http:") and v.len > 5)
                .{ .http = .{ .base = v[5..] } }
            else if (std.mem.startsWith(u8, v, "dir:") and v.len > 4)
                .{ .dir = v[4..] }
            else
                return usageErr("--edge-fallback off | http[:URL] | dir:PATH");
        } else if (std.mem.eql(u8, a, "--stream")) {
            const v = try need(args, &i);
            stream_url = if (std.mem.eql(u8, v, "off")) null else v;
            stream_set = true;
        } else if (std.mem.eql(u8, a, "--p2p")) {
            cfg.p2p = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--p2p-key")) {
            cfg.p2p_key = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--p2p-discover")) {
            cfg.p2p_discover = try std.fmt.parseInt(u8, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--sig-fast")) {
            node.sig.fast.configure(node.sig.fast.all_on);
        } else if (std.mem.eql(u8, a, "--sig-parallel")) {
            sig_parallel = node.gpu.engine.Parallel.parse(try need(args, &i)) orelse return usageErr("--sig-parallel: auto, on or off");
        } else if (std.mem.eql(u8, a, "--cert-batch")) {
            cert_batch = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--gpu")) {
            gpu_mode = node.gpu.Mode.parse(try need(args, &i)) orelse return usageErr("--gpu: off, auto, metal or cuda");
        } else if (std.mem.eql(u8, a, "--exec-threads")) {
            cfg.exec_threads = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--exec-window-mb")) {
            cfg.exec_window_mb = @max(1, try std.fmt.parseInt(u32, try need(args, &i), 10));
        } else if (std.mem.eql(u8, a, "--exec-cache-mb")) {
            cfg.exec_cache_mb = @max(64, try std.fmt.parseInt(u32, try need(args, &i), 10));
        } else if (std.mem.eql(u8, a, "--exec-window")) {
            cfg.exec_window = @max(2, try std.fmt.parseInt(u32, try need(args, &i), 10));
        } else if (std.mem.eql(u8, a, "--tiles")) {
            cfg.tiles = true;
        } else if (std.mem.eql(u8, a, "--tile-cpus")) {
            cfg.tile_cpus = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--tile-spin")) {
            cfg.tile_spin = true;
        } else if (std.mem.eql(u8, a, "--p2p-only")) {
            cfg.p2p_only = true;
        } else if (std.mem.eql(u8, a, "--p2p-pinned")) {
            cfg.p2p_pinned = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--p2p-exec-threads")) {
            cfg.p2p_exec_threads = try std.fmt.parseInt(u8, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--p2p-reconcile-wait")) {
            cfg.p2p_reconcile_wait_s = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--p2p-listen")) {
            const v = try need(args, &i);
            cfg.p2p_listen = if (std.mem.eql(u8, v, "off")) null else v;
        } else if (std.mem.eql(u8, a, "--p2p-opt")) {
            const v = try need(args, &i);
            node.p2p_config.set(&cfg.p2p_tuning, v) catch |e| {
                std.debug.print("--p2p-opt {s}: {s}\n", .{ v, if (e == error.UnknownP2pOpt) "unknown key" else "bad value" });
                return 2;
            };
        } else if (std.mem.eql(u8, a, "--p2p-external")) {
            cfg.p2p_external = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--p2p-access")) {
            const v = try need(args, &i);
            cfg.p2p_access = node.p2p_config.parseAccess(v) orelse return error.BadP2pAccess;
        } else if (std.mem.eql(u8, a, "--p2p-listen-threads")) {
            cfg.p2p_listen_threads = try std.fmt.parseInt(u16, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--p2p-trace")) {
            cfg.p2p_trace = true;
        } else if (std.mem.eql(u8, a, "--p2p-push-peers")) {
            cfg.p2p_push_peers = try std.fmt.parseInt(u8, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--p2p-race")) {
            cfg.p2p_race = try std.fmt.parseInt(u8, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--no-s3-fallback")) {
            // An edge's bucket fallback (--edge-fallback http) never has S3 behind it: already so.
            if (cfg.source == .zui1) continue;
            if (cfg.source != .http) return usageErr("--no-s3-fallback needs --source http");
            cfg.source.http.fallback = null;
        } else if (std.mem.eql(u8, a, "--s3-profile")) {
            const sp = s3Spec(&cfg) orelse return usageErr("--s3-profile needs --source s3, or http with its S3 fallback");
            sp.profile = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--s3-credentials")) {
            const sp = s3Spec(&cfg) orelse return usageErr("--s3-credentials needs --source s3, or http with its S3 fallback");
            sp.credentials = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--s3-budget")) {
            const sp = s3Spec(&cfg) orelse return usageErr("--s3-budget needs --source s3, or http with its S3 fallback");
            sp.budget_usd = try std.fmt.parseFloat(f64, try need(args, &i));
        } else if (std.mem.eql(u8, a, "--mode")) {
            cfg.mode = std.meta.stringToEnum(node.Mode, try need(args, &i)) orelse return usageErr("--mode verify | execute");
        } else if (std.mem.eql(u8, a, "--from")) {
            const v = try need(args, &i);
            cfg.start = if (std.mem.eql(u8, v, "tip")) .tip else .{ .seq = try std.fmt.parseInt(u64, v, 10) };
        } else if (std.mem.eql(u8, a, "--to")) {
            cfg.to = try std.fmt.parseInt(u64, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--genesis")) {
            cfg.genesis = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--epochs")) {
            cfg.epochs_index = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--trust-dir")) {
            cfg.trust_dir = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--execute-epoch-from")) {
            execute_epoch_from = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--core-upstream")) {
            cfg.core_upstream = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--core-upstream-pin")) {
            cfg.core_upstream_pin = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--edge-read-sets")) {
            const v = try need(args, &i);
            cfg.edge_read_sets = if (std.mem.eql(u8, v, "on")) true else if (std.mem.eql(u8, v, "off")) false else return usageErr("--edge-read-sets on | off");
        } else if (std.mem.eql(u8, a, "--edge-forward")) {
            const v = try need(args, &i);
            cfg.edge_forward = if (std.mem.eql(u8, v, "on")) true else if (std.mem.eql(u8, v, "off")) false else return usageErr("--edge-forward on | off");
        } else if (std.mem.eql(u8, a, "--edge-execute-wait-ms")) {
            cfg.edge_forward_cfg.execute_wait_ms = std.fmt.parseInt(u32, try need(args, &i), 10) catch return usageErr("--edge-execute-wait-ms N (milliseconds; 0: off)");
        } else if (std.mem.eql(u8, a, "--edge-raw")) {
            cfg.edge_forward_cfg.raw = edge.forward.ExecMode.parse(try need(args, &i)) orelse return usageErr("--edge-raw hold | reads | off");
        } else if (std.mem.eql(u8, a, "--edge-raw-waiters")) {
            cfg.edge_forward_cfg.raw_max_waiters = std.fmt.parseInt(u32, try need(args, &i), 10) catch return usageErr("--edge-raw-waiters N");
            cfg.edge_raw_waiters_set = true;
        } else if (std.mem.eql(u8, a, "--edge-balance-lists")) {
            cfg.edge_forward_cfg.balance_lists = edge.route.parseWhere(try need(args, &i)) orelse return usageErr("--edge-balance-lists forward | local");
        } else if (std.mem.eql(u8, a, "--edge-simulate")) {
            cfg.edge_forward_cfg.simulate = edge.route.Simulate.parse(try need(args, &i)) orelse return usageErr("--edge-simulate forward | local | local-gas");
        } else if (std.mem.eql(u8, a, "--edge-max-lag")) {
            cfg.edge_forward_cfg.max_lag = std.fmt.parseInt(u64, try need(args, &i), 10) catch return usageErr("--edge-max-lag N (checkpoints)");
        } else if (std.mem.eql(u8, a, "--edge-ahead-wait-ms")) {
            cfg.edge_forward_cfg.ahead_wait_ms = std.fmt.parseInt(u32, try need(args, &i), 10) catch return usageErr("--edge-ahead-wait-ms N (milliseconds)");
        } else if (std.mem.eql(u8, a, "--pending-tx-dir")) {
            pending_tx_dir = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--exec-driver")) {
            const v = try need(args, &i);
            exec_driver = std.meta.stringToEnum(rpc_exec.live.node_exec.NodeExec.Driver, v) orelse return error.BadExecDriver;
        } else if (std.mem.eql(u8, a, "--serve")) {
            cfg.serve_addr = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--h2-max-cancelled")) {
            cfg.serve_opts.h2.max_reset_running = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--serve-tls")) {
            cfg.serve_tls_addr = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--serve-tls-cert")) {
            cfg.serve_tls_cert = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--serve-tls-key")) {
            cfg.serve_tls_key = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--rpc")) {
            node.node.setRpc(&cfg, try need(args, &i)) catch return usageErr("--rpc KEY=VALUE: grpc-timeout-ms, max-connection-age-secs, max-connection-age-grace-secs, subscription-watermark-interval or subscription-max-subscribers, VALUE a number");
        } else if (std.mem.eql(u8, a, "--native-listen")) {
            cfg.native_listen = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--native-cert-hash-file")) {
            cfg.native_cert_hash_file = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--native-cert")) {
            cfg.native_cert = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--native-key")) {
            cfg.native_key = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--native-identity-file")) {
            cfg.native_identity_file = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--native-keys")) {
            cfg.native_keys = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--native-pass-dir")) {
            cfg.native_pass_dir = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--native-feed-workers")) {
            cfg.native_feed_workers = @max(1, try std.fmt.parseInt(u32, try need(args, &i), 10));
        } else if (std.mem.eql(u8, a, "--native-feed-queue")) {
            cfg.native_feed_queue = @max(1, try std.fmt.parseInt(u32, try need(args, &i), 10));
        } else if (std.mem.eql(u8, a, "--rpc-release")) {
            cfg.rpc_release_max = node.node.parseRpcRelease(try need(args, &i)) orelse return usageErr("--rpc-release 1.83 | 1.84 | protocol version");
        } else if (std.mem.eql(u8, a, "--indexes")) {
            cfg.indexes = true;
        } else if (std.mem.eql(u8, a, "--no-indexes")) {
            cfg.indexes = false; // after a config's `--indexes` (fullnode.yaml rpc.enable-indexing)
        } else if (std.mem.eql(u8, a, "--metrics")) {
            cfg.metrics_addr = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--metrics-push-url")) {
            cfg.metrics_push_url = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--metrics-push-interval")) {
            cfg.metrics_push_interval_s = try std.fmt.parseInt(u64, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--admin-port")) {
            const p = try std.fmt.parseInt(u16, try need(args, &i), 10);
            cfg.admin_port = if (p == 0) null else p;
        } else if (std.mem.eql(u8, a, "--state-hash")) {
            const v = try need(args, &i);
            cfg.state_hash = if (std.mem.eql(u8, v, "verify-only")) .verify_only else if (std.mem.eql(u8, v, "halt")) .halt else if (std.mem.eql(u8, v, "off")) .off else return usageErr("--state-hash verify-only | halt | off");
        } else if (std.mem.eql(u8, a, "--sui-conservation")) {
            const v = try need(args, &i);
            cfg.sui_conservation = if (std.mem.eql(u8, v, "verify-only")) .verify_only else if (std.mem.eql(u8, v, "halt")) .halt else if (std.mem.eql(u8, v, "off")) .off else return usageErr("--sui-conservation verify-only | halt | off");
        } else if (std.mem.eql(u8, a, "--workers")) {
            cfg.workers = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--fetchers")) {
            cfg.fetchers = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--net-max-mbps")) {
            cfg.net_max_mbps = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--lookahead")) {
            cfg.lookahead = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--sig-order-rps")) {
            cfg.sig_order_rps = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--sig-order-from")) {
            cfg.sig_order_from = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--sig-order-sweep")) {
            const v = try need(args, &i);
            cfg.sig_order_sweep = if (std.mem.eql(u8, v, "on")) true else if (std.mem.eql(u8, v, "off")) false else return usageErr("--sig-order-sweep on | off");
        } else if (std.mem.eql(u8, a, "--window")) {
            cfg.window = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--poll-ms")) {
            cfg.poll_ms = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--status-every")) {
            cfg.status_every_s = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--sync")) {
            cfg.sync_mode = std.meta.stringToEnum(store.SyncMode, try need(args, &i)) orelse return usageErr("--sync none | data | full");
        } else if (std.mem.eql(u8, a, "--vm-aot")) {
            vm_aot = true;
        } else if (std.mem.eql(u8, a, "--vm-aot-hot")) {
            vm_aot_hot = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--no-halt")) {
            cfg.halt_on_mismatch = false;
        } else if (std.mem.eql(u8, a, "--snapshot")) {
            const v = try need(args, &i);
            if (cfg.snapshot == null) cfg.snapshot = .{};
            cfg.snapshot.?.retained = std.mem.eql(u8, v, "retained");
            cfg.snapshot.?.epoch = if (std.mem.eql(u8, v, "latest") or cfg.snapshot.?.retained) null else try std.fmt.parseInt(u64, v, 10);
        } else if (std.mem.eql(u8, a, "--epoch-records")) {
            cfg.epoch_records = try std.fmt.parseInt(u64, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--snapshot-origin")) {
            const v = try need(args, &i);
            if (cfg.snapshot == null) cfg.snapshot = .{};
            cfg.snapshot.?.origin = if (std.mem.startsWith(u8, v, "dir:")) .{ .dir = .{ .root = try Io.Dir.cwd().openDir(io, v[4..], .{}) } } else .{ .https = v };
        } else if (std.mem.eql(u8, a, "--snapshot-threads")) {
            if (cfg.snapshot == null) cfg.snapshot = .{};
            cfg.snapshot.?.threads = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (node_options.test_flags and std.mem.eql(u8, a, "--test-protocol-max")) {
            // Test-only: claim protocols above N unsupported (drives --verify-fallback on a real chain).
            node.node.upgrade.test_protocol_max = try std.fmt.parseInt(u64, try need(args, &i), 10);
        } else if (node_options.test_flags and std.mem.eql(u8, a, "--snapshot-expect-root")) {
            // Test-only trust bypass (a synthetic snapshot's root): built only with -Dnode-test-flags.
            if (cfg.snapshot == null) cfg.snapshot = .{};
            var r: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&r, try need(args, &i));
            cfg.snapshot.?.expect_root = r;
        } else if (std.mem.eql(u8, a, "--memtable-versions")) {
            cfg.store_cfg.max_object_versions = try std.fmt.parseInt(u64, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--live-capacity")) {
            cfg.store_cfg.max_live_objects = try std.fmt.parseInt(u64, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--live-dirty-pages")) {
            cfg.store_cfg.max_dirty_pages = try std.fmt.parseInt(u64, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--index-flush-interval")) {
            cfg.store_cfg.index_flush_interval = try std.fmt.parseInt(u64, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--compress-threads")) {
            cfg.store_cfg.compress_threads = @max(1, @min(64, try std.fmt.parseInt(u32, try need(args, &i), 10)));
        } else if (std.mem.eql(u8, a, "--flush-writers")) {
            cfg.store_cfg.flush_writers = @min(64, try std.fmt.parseInt(u64, try need(args, &i), 10));
        } else if (std.mem.eql(u8, a, "--flush-direct")) {
            cfg.store_cfg.flush_direct = true;
        } else if (std.mem.eql(u8, a, "--retention-epochs")) {
            cfg.store_cfg.retention_epochs = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--object-retention-epochs")) {
            cfg.store_cfg.object_retention_epochs = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--no-smooth")) {
            cfg.store_cfg.smooth = false;
        } else if (std.mem.eql(u8, a, "--no-compress")) {
            cfg.store_cfg.compress = false;
        } else if (std.mem.eql(u8, a, "--age-out")) {
            // The bare flag is `on`, as before; a value after it overrides the profile.
            cfg.age_out = .on;
            if (i + 1 < args.len) if (node.node.AgeOut.parse(args[i + 1])) |m| {
                cfg.age_out = m;
                i += 1;
            };
        } else if (std.mem.eql(u8, a, "--age-mem-mb")) {
            cfg.store_cfg.age_mem_bytes = (try std.fmt.parseInt(u64, try need(args, &i), 10)) << 20;
        } else if (std.mem.eql(u8, a, "--hw")) {
            hw.parse(&hw_spec, try need(args, &i), &hw_fail) catch |e| return hwSpecErr(e, &hw_fail);
        } else if (std.mem.eql(u8, a, "--cp-cache-mb")) {
            cfg.cp_cache_bytes = (try std.fmt.parseInt(u64, try need(args, &i), 10)) << 20;
        } else if (std.mem.eql(u8, a, "--chunk-cache-mb")) {
            cfg.store_cfg.cache_bytes = (try std.fmt.parseInt(u64, try need(args, &i), 10)) << 20;
        } else if (std.mem.eql(u8, a, "--keep-spool")) {
            cfg.keep_spool = true;
        } else if (std.mem.eql(u8, a, "--no-read-sets")) {
            cfg.read_sets = false;
        } else if (std.mem.eql(u8, a, "--packages")) {
            cfg.packages_dir = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--packages-from")) {
            cfg.packages_from = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--tx-deny")) {
            policy_flags.tx_deny.append(std.heap.page_allocator, try need(args, &i)) catch return usageErr("out of memory");
        } else if (std.mem.eql(u8, a, "--policy")) {
            policy_flags.policy.append(std.heap.page_allocator, try need(args, &i)) catch return usageErr("out of memory");
        } else if (std.mem.eql(u8, a, "--early-validation")) {
            const v = try need(args, &i);
            if (std.mem.eql(u8, v, "true")) {
                rpc_exec.live.early.enabled.store(true, .monotonic);
            } else if (std.mem.eql(u8, v, "false")) {
                rpc_exec.live.early.enabled.store(false, .monotonic);
            } else return usageErr("--early-validation takes true or false");
        } else if (std.mem.eql(u8, a, "--dev-inspect-disabled")) {
            const v = try need(args, &i);
            if (std.mem.eql(u8, v, "true")) {
                cfg.dev_inspect_disabled = true;
            } else if (std.mem.eql(u8, v, "false")) {
                cfg.dev_inspect_disabled = false;
            } else return usageErr("--dev-inspect-disabled takes true or false");
        } else if (std.mem.eql(u8, a, "--deny-state")) {
            cfg.deny_state = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--ledger-history")) {
            if (cfg.lh_cfg == null) cfg.lh_cfg = .{};
            node.node.setLedgerHistory(&cfg.lh_cfg.?, try need(args, &i)) catch return usageErr("--ledger-history KEY=VALUE (fullnode.yaml rpc.ledger-history keys)");
        } else if (std.mem.eql(u8, a, "--rpc-index-dir")) {
            cfg.rpc_dir = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--ledger-history-dir")) {
            cfg.history_dir = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--no-history-backfill")) {
            cfg.lh_backfill = false;
        } else if (std.mem.eql(u8, a, "--snapshot-write")) {
            cfg.snapshot_write = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--snapshot-write-threads")) {
            cfg.snapshot_write_threads = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--drain-ms")) {
            cfg.drain_ms = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--handoff-sock")) {
            cfg.handoff_sock = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--verify-fallback")) {
            cfg.verify_fallback = true;
        } else if (std.mem.eql(u8, a, "--shutdown-timeout")) {
            cfg.shutdown_timeout_s = try std.fmt.parseInt(u32, try need(args, &i), 10);
        } else {
            std.debug.print("unknown argument {s}\n{s}", .{ a, usage });
            return 2;
        }
    }
    if (cfg.dir.len == 0) return usageErr("--dir is required");
    if (!stream_set) stream_url = cfg.network.params().fullnode_url;
    if (vm_aot_hot != null and !vm_aot) return usageErr("--vm-aot-hot needs --vm-aot");
    if (vm_aot) {
        var hot: ?move_vm.aot.HotList = null;
        if (vm_aot_hot) |hp| {
            const text = Io.Dir.cwd().readFileAlloc(io, hp, std.heap.page_allocator, .limited(64 << 20)) catch |e| {
                std.debug.print("--vm-aot-hot {s}: {s}\n", .{ hp, @errorName(e) });
                return 2;
            };
            hot = move_vm.aot.HotList.parse(std.heap.page_allocator, text) catch |e| {
                std.debug.print("--vm-aot-hot {s}: {s}\n", .{ hp, @errorName(e) });
                return 2;
            };
        }
        const n = move_vm.aot.enable(hot) catch return usageErr("out of memory");
        std.log.info("vm-aot: on, {d} compiled modules{s}", .{ n, if (hot != null) " (hot list)" else "" });
    }
    std.log.info("network: {s} (chain id {s})", .{ cfg.network.params().name, cfg.network.params().chain_id_b58 });
    if (hw_spec.any) {
        const m = hw.detect(cfg.dir);
        const plan = hw.plan(&m, &hw_spec);
        // Explicit cache flags win over the profile.
        var exec_set = false;
        var chunk_set = false;
        var cp_set = false;
        var workers_set = false;
        var memtable_set = false;
        var net_set = false;
        for (args[2..]) |a| {
            workers_set = workers_set or std.mem.eql(u8, a, "--workers");
            memtable_set = memtable_set or std.mem.eql(u8, a, "--memtable-versions");
            net_set = net_set or std.mem.eql(u8, a, "--p2p-listen-threads");
            exec_set = exec_set or std.mem.eql(u8, a, "--exec-cache-mb");
            chunk_set = chunk_set or std.mem.eql(u8, a, "--chunk-cache-mb");
            cp_set = cp_set or std.mem.eql(u8, a, "--cp-cache-mb");
        }
        if (!exec_set) cfg.exec_cache_mb = @max(64, plan.exec_cache_mb);
        if (!chunk_set) cfg.store_cfg.cache_bytes = @as(u64, plan.chunk_cache_mb) << 20;
        if (!cp_set) cfg.cp_cache_bytes = @as(u64, plan.cp_cache_mb) << 20;
        if (!workers_set) if (plan.workers) |w| {
            cfg.workers = w;
        };
        // A snapshot restore wants the default run size (see --memtable-versions).
        if (!memtable_set and cfg.snapshot == null) if (plan.memtable_versions) |v| {
            cfg.store_cfg.max_object_versions = v;
        };
        if (!net_set) if (plan.net_threads) |v| {
            cfg.p2p_listen_threads = v;
        };
        const applied = hw.apply(&m, &plan);
        hw.logPlan(&m, &plan, applied);
    }
    node.core.cpu.logChoice();
    // Signature engine (gpu.engine): the CPU pool from the hw plan (cgroup quota and affinity
    // counted), the GPU when one passes its self-check, installed for every batch path:
    // checkpoint certificates (follower), zkLogin and Ed25519 batches (sig.batch), intake caches.
    const sig_engine = blk: {
        const m = hw.detect(cfg.dir);
        const plan = hw.plan(&m, &hw_spec);
        // follower workers: cores the cgroup quota and affinity leave us (getCpuCount ignores both)
        if (cfg.workers == 0) cfg.workers = @max(1, plan.cores -| 1);
        break :blk node.gpu.engine.install(io, std.heap.page_allocator, .{ .parallel = sig_parallel, .gpu = gpu_mode, .plan = &plan });
    };
    defer node.gpu.engine.uninstall();
    // Checkpoint certificates as randomized batches (same verdicts): opt-in until the follower's
    // batched wall time is measured at or under unbatched (dense window: 6.39 s vs 4.96 s before
    // 2f4e4f3c). The workers already check certificates in parallel on every core.
    _ = sig_engine;
    cfg.cert_batch = cert_batch orelse 0;
    // The stream races tip polling of a network source; a local directory has no tip to race.
    if (cfg.source != .dir and cfg.source != .zui1) cfg.stream = stream_url;
    if (cfg.source == .zui1) {
        cfg.stream = if (stream_set) stream_url else null; // an edge follows its cores, not a public full node
        const ps = edge.profile.settings(profile orelse .edge);
        cfg.source.zui1.max_conns = edge_conns orelse ps.max_conns;
        if (feed_max_inflight) |v| cfg.source.zui1.max_inflight = v;
        cfg.source.zui1.zstd = edge_zstd;
        // The fallback is a default of the edge profiles only: a bare `--source zui1:` behaves
        // as before unless `--edge-fallback` asks for one.
        cfg.source.zui1.fallback = edge_fallback orelse if (profile != null and ps.edge_fallback) .{ .http = .{} } else .off;
        // The feed carries no input objects, so input read sets (and the package floor rows for
        // system packages upgraded in place) cannot be built from it: off, not silently partial.
        // With `--edge-read-sets on` the edge builds them from what its cores send with the
        // feed and from its own store, per checkpoint, and says which checkpoints have one
        // (docs/EDGE.md section 12); the package floor rows stay out either way.
        if (cfg.edge_read_sets) {
            cfg.read_sets = true;
        } else {
            if (cfg.read_sets) std.log.info("read sets: off (a zui1 source carries no input objects)", .{});
            cfg.read_sets = false;
        }
        if (cfg.poll_ms == null and profile != null) cfg.poll_ms = ps.poll_ms;
    }

    if (edge_fallback != null and cfg.source != .zui1) return usageErr("--edge-fallback needs --source zui1:...");
    if (feed_max_inflight != null and cfg.source != .zui1) return usageErr("--feed-max-inflight needs --source zui1:...");
    if (gate_url) |url| {
        var db: [std.fs.max_path_bytes]u8 = undefined;
        const gs: node.gate.Settings = .{
            .url = url,
            .token_file = gate_token_file orelse "",
            .edge_id = gate_edge_id orelse "",
            .dir = gate_dir orelse try std.heap.page_allocator.dupe(u8, try std.fmt.bufPrint(&db, "{s}/node/gate", .{cfg.dir})),
            .proxies = try std.heap.page_allocator.dupe(edge.gate.ident.Cidr, gate_proxies[0..gate_nproxies]),
            .ca_file = gate_ca_file,
        };
        // the flags and the files they name, before the store is opened: a wrong one stops the
        // start here, in a second, with the flag's name
        if (node.gate.preflight(gpa, io, &gs)) |msg| return usageErr(msg);
        cfg.gate = gs;
    } else if (gate_token_file != null or gate_edge_id != null or gate_dir != null or gate_ca_file != null or gate_nproxies != 0) {
        return usageErr("--gate-token-file, --gate-edge-id, --gate-dir, --gate-ca-file and --gate-trusted-proxy need --gate URL");
    }

    policy_flags.install() catch |e| {
        std.log.err("start: transaction-deny-config / policy-config: {s}", .{@errorName(e)});
        return 1;
    };
    node.installSignalHandlers();
    node.node.ops.logStartup(build_options.git_sha);
    // The node allocates through glibc malloc with a fixed mmap threshold (nodeAllocator).
    // Live bytes are counted (status line `mem ... node gpa`).
    node.memstat.node_gpa.parent = nodeAllocator();
    if (std.c.getenv("ZUI_MEMTRACE")) |v| node.memstat.trace_min = (std.fmt.parseInt(usize, std.mem.span(v), 10) catch 32) << 20;
    if (cfg.handoff_sock) |sock| {
        node.node.handoff.setSuccessorArgs(std.heap.page_allocator, args) catch {};
        node.node.handoff.installUsr2();
        _ = node.node.handoff.begin(.{ .dir = cfg.dir, .sock = sock }) catch |e| {
            std.log.err("handoff: {s}: another deepwave owns {s}, or the takeover from {s} failed", .{ @errorName(e), cfg.dir, sock });
            return 1;
        };
        // Rehearsal knob (tools/handoff/systemd-rehearsal.sh): a slow store open, as a big store has.
        if (std.c.getenv("ZUI_HANDOFF_TEST_INIT_DELAY_S")) |v| {
            const secs = std.fmt.parseInt(c_uint, std.mem.span(v), 10) catch 0;
            std.log.warn("handoff: test delay of {d} s before the store open", .{secs});
            var ts: std.c.timespec = .{ .sec = @intCast(secs), .nsec = 0 };
            _ = std.c.nanosleep(&ts, &ts);
        }
    }
    // Runs after the node's own deinit below (defers are LIFO): the store is closed by then.
    defer node.node.handoff.finishActive();
    const n = node.Node.init(node.memstat.node_gpa.allocator(), io, cfg) catch |e| {
        std.log.err("start: {s}", .{@errorName(e)});
        return 1;
    };
    defer n.deinit();
    if (execute_epoch_from) |from| {
        const ptx: ?[]const u8 = if (pending_tx_dir) |p|
            (if (std.mem.eql(u8, p, "off")) null else p)
        else
            try std.fmt.allocPrint(gpa, "{s}/node/pending-tx", .{cfg.dir});
        const x = rpc_exec.live.node_exec.NodeExec.startWith(gpa, io, n.st, from, ptx, exec_driver) catch |e| {
            std.log.err("execute: {s}", .{@errorName(e)});
            return 1;
        };
        n.exec_rpc.execute = x.handler();
        n.exec_rpc.setProposers(x.proposerSelector());
        const es = n.exec_rpc.env.source();
        x.setEnv(.{ .ctx = es.ctx, .get = es.get });
    }
    n.run() catch |e| switch (e) {
        error.Mismatch => return 3,
        else => {
            std.log.err("{s}", .{@errorName(e)});
            return 1;
        },
    };
    return 0;
}

/// `deepwave config-check FILE`: the run flags a config becomes, then its notes.
fn configCheckCmd(arena: std.mem.Allocator, io: Io, path: []const u8) !u8 {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const o = &w.interface;
    if (node.fullnode_yaml.looksLikeYaml(path)) {
        const text = try Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20));
        const tr = node.fullnode_yaml.translate(arena, text, yaml_opts) catch return 1;
        try o.print("deepwave run", .{});
        for (tr.args) |x| try o.print(" {s}", .{x});
        try o.print("\n", .{});
        for (tr.notes) |nt| try o.print("{s}: {s}\n", .{ @tagName(nt.level), nt.text });
    } else {
        const flags = try withConfigFile(arena, io, &.{ "deepwave", "run", "--config", path });
        try o.print("deepwave", .{});
        for (flags[1..]) |x| try o.print(" {s}", .{x});
        try o.print("\n", .{});
    }
    try o.flush();
    return 0;
}

/// The S3 settings in use: the s3 source, or the http source's fallback.
fn s3Spec(cfg: *node.Config) ?*node.node.S3Spec {
    return switch (cfg.source) {
        .s3 => |*sp| sp,
        .http => |*h| if (h.fallback) |*fb| fb else null,
        .dir, .zui1 => null,
    };
}

fn usageErr(msg: []const u8) u8 {
    std.debug.print("{s}\n{s}", .{ msg, usage });
    return 2;
}

fn convertCmd(gpa: std.mem.Allocator, io: Io, in: []const u8, out_path: []const u8) !u8 {
    const z = try Io.Dir.cwd().readFileAlloc(io, in, gpa, .limited(1 << 30));
    defer gpa.free(z);
    const proto = try node.convert.unzstd(gpa, z, 1 << 30);
    defer gpa.free(proto);
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    _ = try node.convert.protoToChk(gpa, arena.allocator(), proto, &out);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = out.items });
    return 0;
}

/// `deepwave store-compress DIR [THREADS] [CHUNK_KIB]` (default 256): rewrites every raw segment of a closed store (DIR is
/// the node's data dir or its `store/`) as compressed chunks with identical logical offsets
/// (store/convert.zig). Safe to interrupt and rerun: each segment switches with two renames.
fn storeCompressCmd(gpa: std.mem.Allocator, io: Io, args: []const []const u8) !u8 {
    const st = node.store;
    var threads: u32 = node.Node.usableCpus(); // the cgroup CPU quota included
    if (args.len >= 2) threads = try std.fmt.parseInt(u32, args[1], 10);
    var copts: st.convert.Options = .{ .threads = threads };
    if (args.len >= 3) copts.chunk_bytes = (try std.fmt.parseInt(u32, args[2], 10)) << 10;
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const sub = try std.fmt.bufPrint(&pb, "{s}/store", .{args[0]});
    const path = if (Io.Dir.cwd().access(io, sub, .{})) |_| sub else |_| args[0];
    const r = try st.io.RealIo.init(gpa, io, path, .{});
    defer r.deinit();
    var epochs: std.ArrayList(u64) = .empty;
    defer epochs.deinit(gpa);
    {
        var d = try r.root.openDir(io, "seg", .{ .iterate = true });
        defer d.close(io);
        var it = d.iterate();
        while (try it.next(io)) |e| {
            if (!std.mem.endsWith(u8, e.name, ".log")) continue;
            const ep = std.fmt.parseInt(u64, e.name[0 .. e.name.len - 4], 10) catch continue;
            try epochs.append(gpa, ep);
        }
    }
    std.mem.sort(u64, epochs.items, {}, std.sort.asc(u64));
    var tot_raw: u64 = 0;
    var tot_phys: u64 = 0;
    var tot_dir: u64 = 0;
    for (epochs.items) |ep| {
        const rep = try st.convert.convertSegment(gpa, r, ep, copts);
        if (rep.skipped) {
            std.debug.print("segment {d}: already compressed\n", .{ep});
            continue;
        }
        tot_raw += rep.raw_bytes;
        tot_phys += rep.phys_bytes;
        tot_dir += rep.dir_bytes;
        const secs = @as(f64, @floatFromInt(rep.ns)) / 1e9;
        std.debug.print("segment {d}: raw {d} logical {d} -> {d} (+dir {d}), ratio {d:.3}, {d} groups, {d} chunks, dropped tail {d}, {d:.1}s ({d:.0} MiB/s)\n", .{
            ep,                rep.raw_bytes, rep.logical_bytes, rep.phys_bytes, rep.dir_bytes,
            @as(f64, @floatFromInt(rep.logical_bytes)) / @as(f64, @floatFromInt(@max(rep.phys_bytes, 1))),
            rep.groups,        rep.chunks,    rep.dropped_tail,  secs,
            @as(f64, @floatFromInt(rep.logical_bytes)) / 1048576.0 / @max(secs, 1e-9),
        });
    }
    std.debug.print("total: raw {d} -> {d} (+dir {d})\n", .{ tot_raw, tot_phys, tot_dir });
    return 0;
}

/// `deepwave store-chunkbench DIR EPOCH [SAMPLE_MIB] [THREADS]`: ratio, compression and decode
/// speed of chunk sizes 4 KiB to 256 KiB over the start of raw segment EPOCH.
fn storeChunkBenchCmd(gpa: std.mem.Allocator, io: Io, args: []const []const u8) !u8 {
    const st = node.store;
    const epoch = try std.fmt.parseInt(u64, args[1], 10);
    const sample: u64 = (if (args.len >= 3) try std.fmt.parseInt(u64, args[2], 10) else 1024) << 20;
    const threads: u32 = if (args.len >= 4) try std.fmt.parseInt(u32, args[3], 10) else node.Node.usableCpus();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const sub = try std.fmt.bufPrint(&pb, "{s}/store", .{args[0]});
    const path = if (Io.Dir.cwd().access(io, sub, .{})) |_| sub else |_| args[0];
    const r = try st.io.RealIo.init(gpa, io, path, .{});
    defer r.deinit();
    const sizes = [_]u32{ 4 << 10, 8 << 10, 16 << 10, 32 << 10, 64 << 10, 128 << 10, 256 << 10 };
    var rows: [sizes.len]st.convert.BenchRow = undefined;
    try st.convert.benchSegment(gpa, r, epoch, sample, &sizes, threads, &rows);
    std.debug.print("| chunk | logical MiB | physical MiB | ratio | chunks | compress MiB/s ({d} thr) | decode MiB/s (1 thr) | decode us/chunk |\n|---|---|---|---|---|---|---|---|\n", .{threads});
    for (rows) |w| {
        const lm = @as(f64, @floatFromInt(w.logical)) / 1048576.0;
        std.debug.print("| {d} KiB | {d:.0} | {d:.0} | {d:.3} | {d} | {d:.0} | {d:.0} | {d:.1} |\n", .{
            w.chunk_bytes >> 10,                                                lm,
            @as(f64, @floatFromInt(w.phys)) / 1048576.0,                       @as(f64, @floatFromInt(w.logical)) / @as(f64, @floatFromInt(w.phys)),
            w.chunks,                                                           lm / (@as(f64, @floatFromInt(w.compress_ns)) / 1e9),
            lm / (@as(f64, @floatFromInt(w.decode_ns)) / 1e9),                 @as(f64, @floatFromInt(w.decode_ns)) / 1e3 / @as(f64, @floatFromInt(@max(w.chunks, 1))),
        });
    }
    return 0;
}

fn checkCmd(gpa: std.mem.Allocator, io: Io, args: []const []const u8) !u8 {
    var dir: []const u8 = "";
    var against: []const u8 = "";
    var from: u64 = 0;
    var to: u64 = 0;
    var opts: node.check.Options = .{};
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--dir")) dir = try need(args, &i) else if (std.mem.eql(u8, a, "--against")) against = try need(args, &i) else if (std.mem.eql(u8, a, "--from")) from = try std.fmt.parseInt(u64, try need(args, &i), 10) else if (std.mem.eql(u8, a, "--to")) to = try std.fmt.parseInt(u64, try need(args, &i), 10) else if (std.mem.eql(u8, a, "--records-from")) opts.records_from = try std.fmt.parseInt(u64, try need(args, &i), 10) else if (std.mem.eql(u8, a, "--no-read-sets")) opts.read_sets = false else return usageErr("check: unknown argument");
    }
    if (dir.len == 0 or against.len == 0 or to < from) return usageErr("check: --dir, --against, --from, --to");
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var scfg: store.Config = .{ .dir = try std.fs.path.join(arena.allocator(), &.{ dir, "store" }), .codec = node.check.store_codec };
    _ = &scfg;
    const opened = try store.openDir(gpa, io, &scfg, .{});
    defer {
        opened.store.close() catch {};
        opened.io.deinit();
    }
    const src: node.source.Source = .{ .gpa = gpa, .io = io, .kind = .{ .dir = try Io.Dir.cwd().openDir(io, against, .{}) } };
    const rep = try node.check.runOpts(gpa, io, opened.store, &src, from, to, opts);
    std.log.info("check {d}..{d}: {d} checkpoints, {d} transactions, {d} object versions, {d} live ids, {d} read-set versions, {d} loaded lists ({d} checkpoints without aux): {d} failures", .{ from, to, rep.checkpoints, rep.transactions, rep.objects, rep.live_checked, rep.read_set_objects, rep.loaded_lists, rep.no_aux, rep.failures });
    return if (rep.failures == 0) 0 else 1;
}

fn snapshotCheckCmd(gpa: std.mem.Allocator, io: Io, args: []const []const u8) !u8 {
    var epoch: ?u64 = null;
    var origin: ?node.snapshot.Origin = null;
    var net: node.node.Network = .mainnet;
    var parts_arg: ?[]const u8 = null;
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--network")) {
            net = node.node.Network.parse(try need(args, &i)) orelse return usageErr("--network mainnet | testnet");
        } else if (std.mem.eql(u8, a, "--epoch")) {
            epoch = try std.fmt.parseInt(u64, try need(args, &i), 10);
        } else if (std.mem.eql(u8, a, "--origin")) {
            const v = try need(args, &i);
            origin = if (std.mem.startsWith(u8, v, "dir:")) .{ .dir = .{ .root = try Io.Dir.cwd().openDir(io, v[4..], .{}) } } else .{ .https = v };
        } else if (std.mem.eql(u8, a, "--parts")) {
            parts_arg = try need(args, &i);
        } else return usageErr("snapshot-check: unknown argument");
    }
    const e = epoch orelse return usageErr("snapshot-check: --epoch is required");
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var f: node.snapshot.Fetcher = .{ .gpa = gpa, .io = io, .origin = origin orelse .{ .https = net.params().formal_snapshot_url } };
    defer f.deinit();
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try f.get(e, "MANIFEST", &buf);
    const m = try node.snapshot.parseManifest(arena.allocator(), buf.items);
    const parts = try m.partitions(arena.allocator());
    std.log.info("manifest of epoch {d}: version {d}, {d} files, {d} partitions (sha3 ok)", .{ m.epoch, m.snapshot_version, m.files.len, parts.len });
    var obj: std.ArrayList(u8) = .empty;
    defer obj.deinit(gpa);
    var ref: std.ArrayList(u8) = .empty;
    defer ref.deinit(gpa);
    var total: u64 = 0;
    var it = std.mem.splitScalar(u8, parts_arg orelse "", ',');
    while (it.next()) |want| {
        if (want.len == 0) continue;
        const us = std.mem.indexOfScalar(u8, want, '_') orelse return usageErr("--parts B_P,...");
        const bk = try std.fmt.parseInt(u32, want[0..us], 10);
        const pt = try std.fmt.parseInt(u32, want[us + 1 ..], 10);
        const p = for (parts) |p| {
            if (p.bucket == bk and p.part == pt) break p;
        } else return error.NoSuchPartition;
        var nb: [64]u8 = undefined;
        try f.get(e, p.ref.?.name(&nb), &ref);
        try f.get(e, p.obj.?.name(&nb), &obj);
        var c: node.snapshot.Checked = .{};
        defer c.deinit(gpa);
        const t0 = node.source.nowNs();
        try node.snapshot.checkPartition(gpa, p, obj.items, ref.items, &c);
        const ms = (node.source.nowNs() - t0) / std.time.ns_per_ms;
        var objects: u64 = 0;
        var wrapped: u64 = 0;
        for (c.entries.items) |en| switch (en) {
            .object => objects += 1,
            .wrapped => wrapped += 1,
        };
        total += objects;
        const d = c.acc.digest();
        std.log.info("partition {d}_{d}: {d} objects, {d} wrapped, {d} + {d} bytes stored ({d} + {d} plain); sha3, magic, every object's id/version/digest equal its ref; checked in {d} ms; partial root {x}", .{ bk, pt, objects, wrapped, obj.items.len, ref.items.len, c.obj_plain.items.len, c.ref_plain.items.len, ms, &d });
    }
    std.log.info("{d} objects checked, 0 failures", .{total});
    return 0;
}

/// Writes a formal snapshot (uncompressed) of the net live object set the checkpoints FROM..TO of
/// SRC_DIR produce, as `OUT_DIR/epoch_<EPOCH>/`, and prints its root. Test tool: it shows that a
/// store restored from a snapshot ends in the same state as one built from the same history.
fn snapshotMakeCmd(gpa: std.mem.Allocator, io: Io, src_dir: []const u8, from: u64, to: u64, epoch: u64, out_dir: []const u8) !u8 {
    const src: node.source.Source = .{ .gpa = gpa, .io = io, .kind = .{ .dir = try Io.Dir.cwd().openDir(io, src_dir, .{}) } };
    var sc = node.source.Scratch.init(gpa);
    defer sc.deinit(gpa);
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var idx = try node.types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var keep: std.heap.ArenaAllocator = .init(gpa);
    defer keep.deinit();
    var live: std.AutoArrayHashMapUnmanaged([32]u8, ?[]const u8) = .empty;
    defer live.deinit(gpa);
    var seq = from;
    while (seq <= to) : (seq += 1) {
        _ = arena.reset(.retain_capacity);
        if (try src.fetch(&sc, seq, &blob) != .ok) return error.SourceMissing;
        try node.types.indexCheckpointData(blob.items, &idx);
        const c = switch (try node.sync.verify.check(arena.allocator(), blob.items, &idx)) {
            .ok => |c| c,
            .bad => return error.BadBlob,
        };
        for (c.txs) |plan| {
            for (plan.puts) |p| try live.put(gpa, p.id.*, try keep.allocator().dupe(u8, idx.objs[p.index].slice(blob.items)));
            for (plan.removes) |r| try live.put(gpa, r.id, null);
        }
    }
    var objs: std.ArrayList([]const u8) = .empty;
    defer objs.deinit(gpa);
    for (live.values()) |v| if (v) |b| try objs.append(gpa, b);
    try Io.Dir.cwd().createDirPath(io, out_dir);
    const root = try node.snapshot.writeSnapshot(gpa, io, try Io.Dir.cwd().openDir(io, out_dir, .{}), epoch, objs.items, 50_000);
    std.log.info("snapshot of {d}..{d}: {d} live objects, root {x}", .{ from, to, objs.items.len, &root });
    return 0;
}

/// `deepwave stream-check`: the live stream's checkpoints converted exactly as the node does,
/// compared byte for byte (blob and aux) with the same checkpoints from the bucket.
fn streamCheckCmd(gpa: std.mem.Allocator, io: Io, args: []const []const u8) !u8 {
    const stream = node.stream;
    const source = node.source;
    var url: ?[]const u8 = null;
    var base: ?[]const u8 = null;
    var net: node.node.Network = .mainnet;
    var count: u64 = 20;
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--network")) {
            net = node.node.Network.parse(try need(args, &i)) orelse return usageErr("--network mainnet | testnet");
        } else if (std.mem.eql(u8, a, "--stream")) {
            url = try need(args, &i);
        } else if (std.mem.eql(u8, a, "--source")) {
            const v = try need(args, &i);
            if (std.mem.startsWith(u8, v, "http:")) base = v[5..] else if (!std.mem.eql(u8, v, "http")) return usageErr("stream-check --source http[:URL]");
        } else if (std.mem.eql(u8, a, "--count")) {
            count = try std.fmt.parseInt(u64, try need(args, &i), 10);
        } else return usageErr("stream-check [--network N] [--stream URL] [--source http[:URL]] [--count N]");
    }
    const np = net.params();
    var pub_src = node.http.Public.init(gpa, io, base orelse np.bucket_url);
    defer pub_src.deinit();
    const src: source.Source = .{ .gpa = gpa, .io = io, .kind = .{ .http = &pub_src } };
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    const body = try stream.requestBody(gpa);
    defer gpa.free(body);
    const c = try gpa.create(stream.Conn);
    defer gpa.destroy(c);
    var sa = source.Scratch.init(gpa);
    defer sa.deinit(gpa);
    var sb = source.Scratch.init(gpa);
    defer sb.deinit(gpa);
    var blob_a: std.ArrayList(u8) = .empty;
    defer blob_a.deinit(gpa);
    var blob_b: std.ArrayList(u8) = .empty;
    defer blob_b.deinit(gpa);
    var aux_a: std.ArrayList(u8) = .empty;
    defer aux_a.deinit(gpa);
    var equal: u64 = 0;
    var cert_only: u64 = 0;
    var sig_order: u64 = 0;
    var differ: u64 = 0;
    var bad: u64 = 0;
    var bytes: u64 = 0;
    var lead_ms: std.ArrayList(i64) = .empty;
    defer lead_ms.deinit(gpa);
    var done: u64 = 0;
    while (done < count) {
        try c.open(gpa, &client, std.mem.trimEnd(u8, url orelse np.fullnode_url, "/"), body, null);
        defer c.close();
        while (done < count) {
            const m = (try c.next()) orelse break;
            const t_stream = source.wallMs();
            const seq = m.cursor orelse return error.NoCursor;
            done += 1;
            bytes += m.checkpoint.len;
            _ = sa.arena.reset(.retain_capacity);
            source.decodeProto(gpa, &sa, m.checkpoint, seq, &blob_a) catch |e| {
                std.log.err("stream {d}: {s}", .{ seq, @errorName(e) });
                bad += 1;
                continue;
            };
            aux_a.clearRetainingCapacity();
            try aux_a.appendSlice(gpa, sa.aux.items);
            // The bucket has it about 100 ms later: poll every 50 ms (at most 20 req/s), 30 s max.
            var tries: u32 = 0;
            const got = while (tries < 600) : (tries += 1) {
                if (try src.fetch(&sb, seq, &blob_b) == .ok) break true;
                io.sleep(.fromMilliseconds(50), .awake) catch {};
            } else false;
            if (!got) {
                std.log.err("bucket never served {d}", .{seq});
                bad += 1;
                continue;
            }
            try lead_ms.append(gpa, @as(i64, @intCast(source.wallMs())) - @as(i64, @intCast(t_stream)));
            // The stream carries each transaction's stored signature order, the bucket only the
            // contents' signer order (convert.zig "Signature order"): compare with it set aside.
            var blob_n: std.ArrayList(u8) = .empty;
            defer blob_n.deinit(gpa);
            source.decodeProtoOpts(gpa, &sa, m.checkpoint, seq, &blob_n, .{ .tx_signature_order = false }) catch {};
            if (std.mem.eql(u8, blob_a.items, blob_b.items) and std.mem.eql(u8, aux_a.items, sb.aux.items)) {
                equal += 1;
            } else if (std.mem.eql(u8, blob_n.items, blob_b.items) and std.mem.eql(u8, aux_a.items, sb.aux.items)) {
                sig_order += 1;
            } else if (std.mem.eql(u8, aux_a.items, sb.aux.items) and certOnly(gpa, &sa, &sb, m.checkpoint, seq, blob_b.items)) {
                cert_only += 1;
            } else {
                differ += 1;
                std.log.err("checkpoint {d} differs: blob {d} vs {d} bytes ({s}), aux {d} vs {d} bytes ({s})", .{ seq, blob_a.items.len, blob_b.items.len, if (std.mem.eql(u8, blob_a.items, blob_b.items)) "equal" else "differ", aux_a.items.len, sb.aux.items.len, if (std.mem.eql(u8, aux_a.items, sb.aux.items)) "equal" else "differ" });
            }
            // Read ahead past messages that queued while this one was compared.
        }
    }
    std.sort.pdq(i64, lead_ms.items, {}, std.sort.asc(i64));
    const med = if (lead_ms.items.len > 0) lead_ms.items[lead_ms.items.len / 2] else 0;
    var ob: [512]u8 = undefined;
    var w = Io.File.stdout().writer(io, &ob);
    try w.interface.print("{{\"compare\":\"stream-vs-bucket\",\"checkpoints\":{d},\"equal\":{d},\"equal_but_certificate\":{d},\"equal_but_signature_order\":{d},\"differ\":{d},\"bad\":{d},\"stream_mib\":{d},\"bucket_after_stream_ms_p50_upper_bound\":{d}}}\n", .{ done, equal, cert_only, sig_order, differ, bad, bytes >> 20, med });
    try w.interface.flush();
    return if (differ == 0 and bad == 0 and equal + cert_only + sig_order > 0) 0 else 1;
}

/// The stream's proto with the bucket's certificate (`signature`, field 4) converts to the
/// bucket's blob: the two differ only in which validators' signatures were aggregated.
fn certOnly(gpa: std.mem.Allocator, sa: *node.source.Scratch, sb: *node.source.Scratch, stream_proto: []const u8, seq: u64, bucket_blob: []const u8) bool {
    const a = sb.arena.allocator();
    const bucket_proto = node.convert.unzstdArena(a, sb.raw.items, node.source.max_blob) catch return false;
    const spliced = node.stream.replaceField(a, stream_proto, bucket_proto, 4) catch return false;
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    node.source.decodeProtoOpts(gpa, sa, spliced, seq, &blob, .{ .tx_signature_order = false }) catch return false;
    return std.mem.eql(u8, blob.items, bucket_blob);
}

/// `deepwave decode-bench FILES`: the fetch path's per-checkpoint CPU, one thread: zstd with the
/// windowed decoder (`unzstd`, the old path), zstd in direct mode (`unzstdArena`), and the proto
/// to blob conversion. Each file 20 times.
fn decodeBenchCmd(gpa: std.mem.Allocator, io: Io, files: []const []const u8) !u8 {
    const convert = node.convert;
    const now = node.source.nowNs;
    var t_old: u64 = 0;
    var t_new: u64 = 0;
    var t_conv: u64 = 0;
    var bytes_in: u64 = 0;
    var bytes_out: u64 = 0;
    const reps = 20;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(gpa);
    for (files) |path| {
        const z = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 30));
        defer gpa.free(z);
        for (0..reps) |_| {
            var t0 = now();
            const p_old = try convert.unzstd(gpa, z, 1 << 30);
            t_old += now() - t0;
            gpa.free(p_old);
            _ = arena.reset(.retain_capacity);
            t0 = now();
            const p_new = try convert.unzstdArena(arena.allocator(), z, 1 << 30);
            t_new += now() - t0;
            t0 = now();
            _ = try convert.protoToChkAux(gpa, arena.allocator(), p_new, &blob, &aux);
            t_conv += now() - t0;
            bytes_in += z.len;
            bytes_out += p_new.len;
        }
    }
    const n: u64 = files.len * reps;
    var ob: [512]u8 = undefined;
    var w = Io.File.stdout().writer(io, &ob);
    try w.interface.print("{{\"bench\":\"decode\",\"checkpoints\":{d},\"zstd_in_kib\":{d},\"proto_kib\":{d},\"zstd_windowed_us\":{d},\"zstd_direct_us\":{d},\"convert_us\":{d},\"direct_mb_s\":{d}}}\n", .{
        files.len, bytes_in / n / 1024, bytes_out / n / 1024, t_old / n / 1000, t_new / n / 1000, t_conv / n / 1000, if (t_new > 0) bytes_out * 1000 / t_new else 0,
    });
    try w.interface.flush();
    return 0;
}

const glibc = struct {
    extern "c" fn mallopt(param: c_int, value: c_int) c_int;
};

/// The node's allocator (`ZUI_ALLOC=smp` for smp_allocator).
///
/// Not smp_allocator: its small blocks (64 KiB slabs, never unmapped) go back to the slot of
/// the freeing thread, and a thread allocates only from its current slot and one other
/// (max_alloc_search 1), moving to another slot whenever its own is locked. The node's ordered
/// thread allocates and frees hundreds of MiB of small blocks a minute (state and history
/// index rows, memtables, per-checkpoint arenas) among ~200 threads, so its frees kept landing
/// in slots it no longer allocated from and it mapped new slabs: rig rehearsal 2026-11-09,
/// catch-up at ~50 cp/s, anon minus `node gpa` grew ~80 MiB a minute after the lsm memtable
/// fix (~200 before) with live bytes flat, 20 to 60 new slabs a second, all on that thread.
/// glibc returns a freed chunk to the arena that owns it, whatever thread frees it.
///
/// Not glibc's defaults either: its mmap threshold rises to 32 MiB after large frees, so
/// per-checkpoint buffers of a few MiB came from heap and thread arenas it never returns
/// (about 1 GiB of a sync's private memory by checkpoint 1.7M). Setting M_MMAP_THRESHOLD
/// turns that adjustment off: blocks of 128 KiB and more are mapped and unmapped on free, as
/// smp_allocator did. M_ARENA_MAX bounds the arenas (default 8 per core).
fn nodeAllocator() std.mem.Allocator {
    if (std.c.getenv("ZUI_ALLOC")) |v| if (std.mem.eql(u8, std.mem.span(v), "smp")) return std.heap.smp_allocator;
    if (builtin.os.tag != .linux or builtin.abi != .gnu) return std.heap.smp_allocator;
    const M_TRIM_THRESHOLD = -1;
    const M_MMAP_THRESHOLD = -3;
    const M_ARENA_MAX = -8;
    _ = glibc.mallopt(M_MMAP_THRESHOLD, 128 << 10);
    _ = glibc.mallopt(M_TRIM_THRESHOLD, 32 << 20);
    _ = glibc.mallopt(M_ARENA_MAX, 16);
    return std.heap.c_allocator;
}
