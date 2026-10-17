# Contributing to rustoshi

Thank you for helping. rustoshi is a from-scratch Bitcoin node, so correctness matters more than features or speed.

## Build and test

See [docs/building.md](docs/building.md) for the toolchain and system packages. Then:

```bash
cargo build --release
cargo test --workspace
```

Before opening a pull request, run the tests and check that your change does not add failures. If the suite already has failing tests on `master`, say which ones in the pull request so reviewers can tell them apart from new ones.

Match the style of the code around your change. The tree is not rustfmt-clean as a whole, so do not run `cargo fmt` over the workspace: it would reformat thousands of unrelated lines.

## Pull requests

- Every behaviour change comes with a test that fails before the change and passes after it. Name the test in the pull request description.
- Keep each pull request to one change. Refactors go in their own pull request.
- Do not disable or delete a test without explaining why in the pull request.
- Branch from and target `master`.

## Commit messages

Use a conventional prefix and explain why the change is needed, not only what it does:

```
fix(rpc): return -8 for an out-of-range height in getblockhash

Core returns RPC_INVALID_PARAMETER (-8) here; we returned -1, which broke
clients that match on the code.
```

Common prefixes: `fix`, `feat`, `perf`, `refactor`, `test`, `docs`, `chore`. A scope in parentheses (`consensus`, `net`, `rpc`, `storage`, `wallet`) helps reviewers.

## Consensus changes

Anything that can change whether a block or transaction is accepted (script, validation, UTXO handling, chain selection, reorgs) needs evidence that rustoshi behaves like Bitcoin Core afterwards. Point to the Core source that defines the behaviour, add a test with the concrete input (Core's test vectors where they exist), and describe how the change could make a valid block invalid or an invalid block valid, and which test covers that. Where possible, show the same input on Core and on rustoshi giving the same result, for example on regtest as in [docs/status.md](docs/status.md).
