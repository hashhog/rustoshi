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

`fuzz/` is a **standalone workspace** (its own `[workspace]` table) nested in the
rustoshi repo, so the libfuzzer/sanitizer deps stay out of the parent
`Cargo.lock` and the fleet's stable `cargo build --release` is unaffected.

## Requirements

nightly toolchain + `cargo-fuzz` (both present on maxbox):

```bash
cargo +nightly fuzz build
```

## Run one target

```bash
cargo +nightly fuzz run fuzz_block_decode
```

## Background accumulation (all four, 8 workers each)

```bash
cd rustoshi        # the rustoshi submodule root (fuzz/ lives here)
for t in fuzz_block_decode fuzz_tx_decode fuzz_eval_script fuzz_netmsg_decode; do
  nohup cargo +nightly fuzz run "$t" -- \
    -jobs=8 -workers=8 -rss_limit_mb=4096 \
    > "fuzz/${t}.log" 2>&1 &
done
```

Corpus accumulates under `fuzz/corpus/<target>/`; crashing/OOM inputs are saved
under `fuzz/artifacts/<target>/` (prefixed `crash-`, `oom-`, `timeout-`).
Reproduce any finding with:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>
```

`-rss_limit_mb=4096` makes libFuzzer flag any single allocation above ~4 GB as
an out-of-memory finding — the mechanism that surfaced the `reject`-message DoS
(see project report).
