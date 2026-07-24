# Reproducible build — rustoshi v0.1.0-rc1

How to build the tagged rustoshi validator and verify it. Part of the tagged-validator
release wrapper (see `SECURITY.md` and `../receipts/PRODUCTION-GATE.md` "three bars").

## Released artifact

| | |
|---|---|
| Tag | `rustoshi v0.1.0-rc1` |
| Commit | `e735ef16d5c0444f77a140f36db6f772ea4615d5` |
| Binary | `target/release/rustoshi` (pinned to `../deploy/rustoshi/rustoshi`, live on mainnet) |
| **sha256** | `f30e8ca7673a8a5776c6bd74d7c08f13ce4f40bad962e476cee3db8c522400fe` |
| Toolchain | `rustc 1.97.0 (2d8144b78 2026-07-07)`, `cargo 1.97.0` |
| Target | `x86_64-unknown-linux-gnu` |
| Build | `cargo build --release` |

## Build

```bash
git clone git@github.com:hashhog/rustoshi.git
cd rustoshi
git checkout v0.1.0-rc1
rustup toolchain install 1.97.0   # match the release toolchain
cargo +1.97.0 build --release
sha256sum target/release/rustoshi
```

## Verify

Reproducibility holds **when the toolchain and target match**: same `rustc 1.97.0`,
same `x86_64-unknown-linux-gnu`, a clean checkout of the tagged commit.

**Honest caveats** (a hash mismatch under a *different* environment is expected, not
tampering):
- Rust release artifacts are **not** guaranteed bit-identical across different rustc
  versions, host libc/linker versions, or build paths (embedded `CARGO_*` paths, LTO,
  codegen-units).
- For an exact match, build with the pinned `1.97.0` toolchain on a comparable
  Linux/glibc host.
- The stronger guarantee this release rests on is **behavioural, not bit-level**:
  the binary validates Bitcoin mainnet in consensus with Bitcoin Core —
  trustless-from-genesis (`--assumevalid=0`, byte-exact to the Core tip), crash-recovery
  3/3, deep-reorg 6/6 (incl. a 110-block reorg), clean differential guard, a 386-entry
  adversarial corpus. Run it beside Core with `consensus-diff` as a live divergence
  alarm — that is the intended trust model (validator, **not** custody).

## Scope of this release

- **Is:** a trustless-from-genesis validating node, byte-exact with Core, P2P
  DoS-hardened (getblocktxn-depth + accept-time inbound caps) + signature cache, to run
  beside Core in watchtower mode.
- **Is not:** fund-capable for general custody (see `SECURITY.md` "Custody caveats").

The release-gate smoke check is `tools/smoke-harness.sh --node=rustoshi` (regtest boot +
genesis-state RPC + clean shutdown), which passes at the tagged commit.
