# Armory (Rust)

The Rust rebuild of Armory for Fedora Linux and macOS. Design and status:
[`docs/rust-rebuild/`](../docs/rust-rebuild/README.md).

| Crate | Purpose |
|---|---|
| `armory-crypto` | Byte-exact legacy primitives: Armory HMAC, checksums, Easy16, ROMix KDF, AES, 1.35 key chain, Shamir, SecurePrint |
| `armory-wallet` | Modern v2 wallets (BIP39/BIP32, BIP84 SegWit + BIP86 Taproot accounts, descriptors, Argon2id + XChaCha20-Poly1305) and legacy v1.35 `.wallet` files (byte-compatible read/write, migration) |
| `armory` | The `armory` command-line program (TUI to follow) |

## Build and test

```sh
cargo build --release            # binary at target/release/armory
cargo test --workspace --release
```

Requires Rust 1.85 or newer (`dnf install rust cargo` on Fedora, `brew install rust` or rustup on macOS).

## Try it

```sh
A="target/release/armory --datadir /tmp/armory-demo --network testnet3"
$A wallet create --label Savings          # prints 24 recovery words; asks for a passphrase
$A address new <ID>                       # tb1q... (never needs the passphrase)
$A wallet descriptors <ID>                # wpkh([fp/84h/1h/0h]tpub.../0/*)#...
$A wallet migrate fixtures/legacy/armory_GDHFnMQ2_.wallet --no-encrypt   # Armory 0.93 wallet -> legacy account
$A backup paper <ID> --secureprint -o sheet.txt   # code shown on screen only
$A restore paper --file sheet.txt --secureprint --test <ID>   # PASS/FAIL, writes nothing
$A backup fragments <ID> -m 2 -n 3 --output-dir frags/
$A legacy wallet show GDHFnMQ2            # v1.35 files stay readable byte-for-byte
```

Without `--datadir`, wallets (`<id>.armory`) live in `~/.local/share/armory/<network>/wallets` (Fedora) or
`~/Library/Application Support/Armory/<network>/wallets` (macOS). Wallet files are created with mode 0600 and
world-readable wallets are refused.

## Status

| Milestone | State |
|---|---|
| M0 primitives | done |
| M1 legacy v1.35 wallets (`armory legacy …`) | done |
| M1b modern wallets: BIP39/BIP84/BIP86, encryption, migration, descriptors | done |
| M2 paper / SecurePrint / fragmented backups (create, restore, `--test`; Armory 0.93 sheets and fragments restore) | done |
| M3 Bitcoin Core backend | not started |
| M4 spending (PSBT / USTX) | not started |
| M5 lockboxes, messages | not started |
| M6 TUI | not started |
| M7 goatpig `.lmdb` import | not started |
| M8 daemon, packaging | not started |
