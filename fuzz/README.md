# rustoshi decoder-fuzz harness

libFuzzer / cargo-fuzz targets for rustoshi's four consensus-critical byte
decoders. Each target feeds arbitrary/mutated bytes to a decoder that parses
untrusted network input and asserts the decoder never panics, OOM-aborts, or
hangs.

## Targets

| target | decoder | entry point |
|--------|---------|-------------|
| `fuzz_block_decode`  | Block        | `<Block as Decodable>::deserialize` (primitives) |
| `fuzz_tx_decode`     | Transaction  | `Transaction::deserialize` (segwit) + `decode_no_witness` (legacy) |
| `fuzz_eval_script`   | Script interpreter | `eval_script` / `verify_script` (consensus, `DummyChecker`) |
| `fuzz_netmsg_decode` | P2P message  | `NetworkMessage::deserialize(command, payload)` (network) |

`fuzz/` is a standalone workspace (its own `[workspace]` table) nested in the
repository, so the libFuzzer and sanitizer dependencies stay out of the main
workspace and a stable `cargo build --release` is unaffected.

## Requirements

A nightly toolchain and `cargo-fuzz`:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

Run the commands below from the repository root.

## Build all targets

```bash
cargo +nightly fuzz build
```

## Run one target

```bash
cargo +nightly fuzz run fuzz_block_decode -- -max_total_time=60
```

Drop `-max_total_time` to run until stopped. Useful libFuzzer options are
`-jobs=N -workers=N` for parallel runs and `-rss_limit_mb=4096`, which reports
any input that makes a decoder allocate more than about 4 GB as an
out-of-memory finding.

The corpus grows under `fuzz/corpus/<target>/`. Crashing, out-of-memory and
timeout inputs are saved under `fuzz/artifacts/<target>/` with a `crash-`,
`oom-` or `timeout-` prefix. Run a single saved input with:

```bash
cargo +nightly fuzz run fuzz_block_decode fuzz/corpus/fuzz_block_decode/00939fdc1a1c47dbc3e994e1cc275153409e3524
```

Pass a file from `fuzz/artifacts/<target>/` the same way to reproduce a finding.
