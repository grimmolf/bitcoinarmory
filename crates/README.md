# Armory (Rust)

The Rust rebuild of Armory for Fedora Linux and macOS. Design and status:
[`docs/rust-rebuild/`](../docs/rust-rebuild/README.md).

| Crate | Purpose |
|---|---|
| `armory-crypto` | Byte-exact legacy primitives: Armory HMAC, checksums, Easy16, ROMix KDF, AES, 1.35 key chain, Shamir, SecurePrint |
| `armory-wallet` | Legacy v1.35 `.wallet` files: read/write, encryption, address pool, watching-only copies, safe file updates |
| `armory` | The `armory` command-line program (TUI to follow) |

## Build and test

```sh
cargo build --release            # binary at target/release/armory
cargo test --workspace --release
```

Requires Rust 1.85 or newer (`dnf install rust cargo` on Fedora, `brew install rust` or rustup on macOS).

## Try it with the legacy fixtures

```sh
A="target/release/armory --datadir /tmp/armory-demo --network testnet3"
$A wallet import fixtures/legacy/armory_GDHFnMQ2_.wallet
$A wallet list
$A address list GDHFnMQ2
$A address new GDHFnMQ2          # -> muEePRR9ShvRm2nqeiJyD8pJRHPuww2ECG
```

Without `--datadir`, wallets live in `~/.local/share/armory/<network>/wallets` (Fedora) or
`~/Library/Application Support/Armory/<network>/wallets` (macOS). Wallet files are created with mode 0600 and
world-readable wallets are refused.

## Status

| Milestone | State |
|---|---|
| M0 primitives | done |
| M1 legacy wallets + CLI (`wallet`, `address`) | done |
| M2 paper / SecurePrint / fragmented backups | primitives done; CLI next |
| M3 Bitcoin Core backend | not started |
| M4 spending (PSBT / USTX) | not started |
| M5 lockboxes, messages | not started |
| M6 TUI | not started |
| M7 BIP32 wallets | pending decision D-1 |
| M8 daemon, packaging | not started |
