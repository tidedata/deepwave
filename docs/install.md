# Installing Deepwave

This page covers the hardware Deepwave needs, how to build it from source and how to run it as a
systemd service. Flags are described in [configuration.md](configuration.md).

## Requirements

**Operating system.**
- Production: x86_64 Linux with glibc 2.35 or newer (Ubuntu 22.04, Ubuntu 24.04 or equivalent).
  Release binaries are built for `x86_64-linux-gnu.2.35`, so one binary runs on every distribution
  at or above that glibc.
- Development: macOS on Apple silicon (arm64) builds and runs the unit tests and conformance
  suites. Linux is the only supported production platform (io_uring, hole punching, O_DIRECT).

**Toolchain.** Zig 0.17.1, pinned. You do not install it yourself: the `./zig` wrapper in the
repository root runs `tools/bootstrap.sh` on first use, which downloads the official release,
checks its sha256 and unpacks it into `~/.cache/zui/zig-0.17.1/`. Every later `./zig` call uses
that copy. The build has no other dependencies: no package manager, no RocksDB, no Rust. zstd is
vendored under `vendor/zstd` and compiled from source.

**Hardware.** 4 cores or more (AVX2 or newer), 16 GB RAM, local NVMe with 250 GB free.

Memory figures from [performance.md](performance.md):
- Verify mode, following mainnet: about 1 GB resident.
- Execute mode catch-up with the full live set: about 2.1 GB of private memory.
- Following the tip with compressed segments: 2.8 to 5.8 GB of private memory.
- Formal snapshot restore: 7.0 GB of private memory at peak.

The store is memory mapped, so resident memory grows with the page cache on a box with spare RAM;
that memory is reclaimable. Plan disk for the retention you choose: about 183 GB right after a
restore, and roughly 300 GB projected at sui-node's default retention with the StateService and
RPC indexes on. A formal snapshot restore downloads about 167 GB from Mysten's public endpoint.

## Build

```
git clone <this repository> deepwave && cd deepwave
./zig build node -Doptimize=ReleaseSafe                 # zig-out/bin/deepwave
```

Common variants:

```
# Production binary for any x86_64 Linux with glibc >= 2.35, safety checks kept on
./zig build node tool -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-gnu.2.35

# Fastest binary, tuned for the CPU of the machine that builds it
./zig build node -Doptimize=ReleaseFast -Dcpu=native

# Every binary
./zig build node tool execute simproxy native-client store-bench conformance-runner
```

`-Doptimize=ReleaseSafe` keeps bounds and overflow checks and is the recommended production
build. `ReleaseFast` drops them for a few percent more throughput. Without `-Dcpu`, an x86_64 build
targets the baseline CPU and still uses the faster kernels where the CPU has them.

Build steps and what they install into `zig-out/bin/`:

| step | binary | purpose |
|---|---|---|
| `node` | `deepwave` | the full node |
| `tool` | `deepwave-tool` | operator commands on a stopped node directory (sui-tool and db-tool equivalents) |
| `execute` | `deepwave-execute` | sends transactions through ExecuteTransaction on two nodes and compares the answers |
| `simproxy` | `deepwave-simproxy` | SimulateTransaction parity proxy |
| `native-client` | `deepwave-native` | test and benchmark client for the native `zui/1` protocol |
| `store-bench` | `deepwave-store-bench` | storage engine benchmark |
| (default) | `deepwave-conformance` | conformance runner, see [testing.md](testing.md) |

Check the result:

```
zig-out/bin/deepwave --version            # deepwave 0.1.0-<commit>
zig-out/bin/deepwave --protocol-range     # supported protocol versions, sui-node's format
zig-out/bin/deepwave --help
```

## Trust inputs

Deepwave verifies every checkpoint against the committee of its epoch, and derives every committee
by walking the chain of end-of-epoch certificates from genesis. It needs:
- `--genesis FILE`: the network's `genesis.blob`, the same file sui-node reads. This is the trust
  root.
- `--epochs FILE` (optional): an epoch index (`epochs.jsonl`) that names each end-of-epoch
  checkpoint, so the walk does not search for them.
- `--trust-dir PATH` (optional): a directory of local end-of-epoch checkpoints read before the
  network source.

Without the optional inputs the walk fetches what it needs from the checkpoint source. The walk
runs once per data directory: the verified committees are saved under `DIR/node/epochs/` and read
back on every restart. Nothing a source sends is trusted until the walk and the per-checkpoint
checks accept it.

## Run as a systemd service

The repository ships a unit and an environment file in `deploy/`.

```
sudo useradd --system --home /var/lib/deepwave --shell /usr/sbin/nologin deepwave
sudo install -d -o deepwave -g deepwave -m 0750 /var/lib/deepwave
sudo install -d -m 0755 /etc/deepwave
sudo install -m 0755 zig-out/bin/deepwave /usr/local/bin/deepwave
sudo install -m 0644 deploy/deepwave.env /etc/deepwave/deepwave.env
sudo install -m 0644 /path/to/genesis.blob /etc/deepwave/genesis.blob
sudo install -m 0644 deploy/deepwave.service /etc/systemd/system/deepwave.service
sudoedit /etc/deepwave/deepwave.env       # set DEEPWAVE_ARGS
sudo systemctl daemon-reload
sudo systemctl enable --now deepwave
journalctl -u deepwave -f
```

The unit runs `/usr/local/bin/deepwave $DEEPWAVE_ARGS` as the `deepwave` user, reads
`/etc/deepwave/deepwave.env` and keeps its data in `/var/lib/deepwave`. The data directory must be
owned by the service user: Deepwave creates its index directories as it needs them and wipes
`store/` itself after an interrupted snapshot restore.

To start from sui-node's configuration instead, point the unit at the same `fullnode.yaml`:

```
DEEPWAVE_ARGS=--config-path /etc/deepwave/fullnode.yaml
```

See [compatibility.md](compatibility.md) for what that file maps to.

## Stop, restart and upgrade

- `SIGTERM` (what `systemctl stop` sends): Deepwave stops taking new work, lets open RPC calls and
  streams finish (`--drain-ms`, default 20 s), finishes and commits the checkpoint in hand, flushes
  its indexes and exits. A clean stop takes seconds. `--shutdown-timeout` (default 110 s) bounds it.
- `kill -9` or power loss: every checkpoint is one commit group made durable with one fsync, so the
  next start resumes after the last durable checkpoint. Nothing needs repair.
- An interrupted snapshot restore restarts the restore from scratch on the next start.
- Upgrade: build the new binary, check `deepwave --protocol-range` covers the network's current
  protocol version, replace `/usr/local/bin/deepwave` and restart. The store format is read in place.

## Next

- [configuration.md](configuration.md): every flag and the fullnode.yaml mapping.
- [rpc.md](rpc.md): what is served, metrics and admin.
- [architecture.md](architecture.md): how the node is built.
