# Building rustoshi

## Toolchain

rustoshi builds with stable Rust. It is tested with rustc 1.99.0. The `rust-version` field in `Cargo.toml` is not a tested minimum; use a current stable toolchain from <https://rustup.rs>.

```bash
rustc --version
cargo --version
```

## System packages

The Rust dependencies compile RocksDB, ZeroMQ, zstd, lz4, bzip2 and zlib from source, so no system copies of those libraries are needed. You need a C/C++ compiler, CMake (for ZeroMQ), and libclang (for the RocksDB bindings). On Debian 13:

```bash
sudo apt-get install -y build-essential clang libclang-dev cmake pkg-config curl git
```

## Build

```bash
cargo build --release
./target/release/rustoshi --version
```

The binary is `target/release/rustoshi`. A clean release build takes a few minutes on a modern desktop; most of that is RocksDB.

The release profile keeps integer-overflow checks on (`[profile.release] overflow-checks = true` in `Cargo.toml`). An overflow in consensus code then stops the node instead of silently producing a different answer from Bitcoin Core. Do not turn this off.

There are no optional Cargo features; indexes, REST, ZMQ and the wallet are all compiled in and switched on at runtime (see [running.md](running.md)).

## Tests

```bash
cargo test --workspace
```

This builds a debug profile and runs the unit tests, the integration tests under each crate's `tests/` directory, and the doctests. Test data such as Bitcoin Core's `script_tests.json` and `sighash.json` lives in `crates/consensus/testdata/`.

To run one crate's tests, use `-p`, for example:

```bash
cargo test -p rustoshi-consensus --test script_vectors
```

## Fuzzing

`fuzz/` is a separate cargo-fuzz workspace with targets for the block, transaction and P2P message decoders and the script interpreter. It needs a nightly toolchain and `cargo install cargo-fuzz`. See [fuzz/README.md](../fuzz/README.md).

## Reproducible builds

`Cargo.lock` is not committed, so dependency versions are resolved when you build. Two builds of the same commit made at different times can therefore pick up different dependency patch releases, and their binaries will differ. Bit-for-bit reproducibility is not provided.

To compare your binary with someone else's, both of you need the same commit, the same `rustc` version, the same target triple (`x86_64-unknown-linux-gnu` is the tested one), the same `Cargo.lock` and the same build path. Then:

```bash
sha256sum target/release/rustoshi
```

Even with all of that fixed, differences in the host C toolchain (used for the bundled C/C++ libraries) can change the output.
