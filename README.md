<p align="center">
  <img src="assets/banner.png" alt="Deepwave" width="100%">
</p>

Deepwave is a Sui full node written from scratch in Zig. It is a drop-in replacement for Mysten's
`sui-node`: it follows mainnet, verifies every checkpoint against the committee chain from genesis,
can re-execute every transaction in its own Move VM, stores the result in its own crash-safe store
and serves the same `sui.rpc.v2` gRPC API, with answers byte for byte the ones sui-node 1.83.1
gives. It reads sui-node's `fullnode.yaml` and command line, supports protocol versions 1 to 142,
and has no RocksDB and no Rust: everything is Zig, apart from the vendored zstd library.

Deepwave is in beta.
The validator part is under development and should not be used.

## Why

Measured against sui-node 1.83.1 on the same machine (Mysten's recommended full-node spec) with the
same mainnet inputs. Details in [docs/performance.md](docs/performance.md).

- **5x faster Move VM**: 15.8 ns per instruction against 78 ns.
- **4.9x faster catch-up**, both executing every transaction: 11,871 tx/s against 2,427 tx/s, at
  3.6x less CPU per transaction.
- **13x less RAM to follow mainnet with every checkpoint verified**: 961 MB in verify mode, which checks
  signatures and certificates without re-executing, against 12,781 MB for sui-node, which always executes.
- **About half the disk**: 183 GB at the tip after a fresh mainnet restore, against 346 GB.
- **28x less CPU per RPC read**: 238 us per GetCheckpoint against 6,817 us.
- **Byte-identical gRPC**: 4,722,443 of 4,722,443 responses equal to sui-node's, and 988,204
  mainnet transactions re-executed with 0 differences.

## Requirements

- **OS**: x86_64 Linux with glibc 2.35 or newer (Ubuntu 22.04, 24.04) for production. macOS on
  Apple silicon works for development.
- **Hardware**: 4 cores or more (AVX2 or newer), 16 GB RAM, local NVMe with 250 GB free.
- **Zig 0.17.1**, pinned: the `./zig` wrapper downloads and verifies it on first use. Nothing else.

## Build

```
./zig build node -Doptimize=ReleaseSafe                     # zig-out/bin/deepwave
./zig build node tool -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-gnu.2.35
./zig build test                                            # unit tests
```

`deepwave --version` prints `deepwave <version>-<commit>`; `deepwave --help` lists every command
and flag. Other binaries: `deepwave-tool` (sui-tool and db-tool operator commands),
`deepwave-execute`, `deepwave-simproxy`, `deepwave-native`, `deepwave-store-bench` and
`deepwave-conformance` ([docs/install.md](docs/install.md)).

## Run

A mainnet full node that restores the newest formal snapshot, executes every transaction, follows
the tip over the public checkpoint bucket, the live stream and p2p state sync, and serves gRPC:

```
zig-out/bin/deepwave run --dir /var/lib/deepwave \
  --genesis /etc/deepwave/genesis.blob --epochs tools/corpus/epochs.jsonl \
  --snapshot latest --snapshot-threads 16 --mode execute --indexes \
  --p2p "$(tools/p2p/seeds.sh mainnet)" \
  --serve 0.0.0.0:9000 --metrics 127.0.0.1:9184
```

`genesis.blob` is mainnet's, the same file sui-node reads; it is the trust root. The first start
walks the end-of-epoch certificates from genesis once and saves the committees; older end-of-epoch
checkpoints come from Mysten's S3 archive (AWS credentials, `--s3-profile`) or a local
`--trust-dir`. Drop `--mode execute` for verify mode. A systemd unit is in
[deploy/](deploy/deepwave.service).

## Configuration

Deepwave is a drop-in for sui-node's config:

```
deepwave --config-path /opt/sui/config/fullnode.yaml     # run with sui-node's fullnode.yaml
deepwave config-check fullnode.yaml                       # print the flags it maps to, and every key it ignores
```

Command-line flags win over the yaml. Ports and the gRPC API are sui-node's, so clients and
monitoring keep working. See [docs/configuration.md](docs/configuration.md) and
[docs/compatibility.md](docs/compatibility.md).

## Docs

- [Install](docs/install.md): hardware, build, systemd.
- [Configuration](docs/configuration.md): every flag, the fullnode.yaml mapping, environment.
- [RPC](docs/rpc.md): the gRPC surface, transports, metrics and admin.
- [Compatibility](docs/compatibility.md): what a sui-node operator can swap, and what is open.
- [Architecture](docs/architecture.md): modules, storage, parallel execution, verify mode.
- [Performance](docs/performance.md): every measurement and how it was taken.
- [Testing](docs/testing.md): unit tests, conformance suites against Mysten's code, proofs.
