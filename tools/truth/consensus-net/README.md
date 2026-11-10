# tools/truth/consensus-net

Ground truth for the consensus network lane (val-consensus-net). Test machine only, loopback only.

- `proto-vectors/`: Rust crate with the ConsensusService message structs copied from
  `tonic_network.rs` (mainnet-v1.83.1). `cargo run --release` prints `name hex` lines of prost's
  encoding for a fixed input table. Save them as `vectors/proto.txt`; the Zig test
  "prost vectors" in `src/consensus/net/proto.zig` encodes the same table and compares (it skips
  when the file is absent).
- `vectors/proto.txt`: prost 0.14 output for that table (generated 2026-11-09 on the Mac with
  `cargo run --release --offline`, prost 0.14.4 per `proto-vectors/Cargo.lock`); the Zig test
  checks all 12 lines.
- `interop/`: the real proof of TLS 1.3, HTTP/2, tonic framing and zstd. `run.sh` drops
  `zui_interop.rs` into a scratch worktree of the sui checkout as a consensus-core unit test (it
  uses Mysten's own `TonicManager`, `TonicValidatorClient` and sui-tls verifiers), builds it in
  the shared target dir and runs the Zig test "tonic interop" (`src/consensus/net/interop.zig`),
  which starts a deepwave server and client and runs the Rust test as a child process: every
  ConsensusService RPC in both directions, both certificate verifiers, status codes, block and
  commit BCS decoded on the other side. Loopback, generated keys.

Run on a test machine:

    cd tools/truth/consensus-net/proto-vectors && cargo run --release > ../vectors/proto.txt && cd ../../../.. && ./zig build test -Dlane=consensus_net
