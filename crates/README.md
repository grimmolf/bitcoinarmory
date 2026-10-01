# Armory (Rust)

The Rust rebuild of Armory for Fedora Linux and macOS. Design and status:
[`docs/rust-rebuild/`](../docs/rust-rebuild/README.md).

| Crate | Purpose |
|---|---|
| `armory-crypto` | Byte-exact legacy primitives: Armory HMAC, checksums, Easy16, ROMix KDF, AES, 1.35 key chain, Shamir, SecurePrint |
| `armory-wallet` | Modern v2 wallets (BIP39/BIP32, BIP84 SegWit + BIP86 Taproot accounts, descriptors, Argon2id + XChaCha20-Poly1305) and legacy v1.35 `.wallet` files (byte-compatible read/write, migration) |
| `armory-node` | Bitcoin Core JSON-RPC backend: watch-only descriptor wallets, balances, history, UTXOs, fees, broadcast |
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

## Using Bitcoin Core

Run Bitcoin Core 29 or newer (`server=1`). Armory uses cookie authentication from the Bitcoin data
directory by default (`--bitcoin-datadir`, `--rpc-cookie`, `--rpc-addr` override it) and creates one watch-only
wallet `armory-<id>` per Armory wallet:

```sh
armory node status
armory wallet sync <ID>        # imports descriptors; rescans from the wallet birthday
armory balance <ID>
armory history <ID> --csv history.csv
armory send <ID> --to bc1q...=0.01 --target 6
armory send <ID> --to bc1q...=0.01 --unsigned-out tx.psbt   # sign offline:
armory tx sign tx.psbt --wallet <ID>                         # (offline machine)
armory tx broadcast tx.psbt                                  # (online machine)
armory wallet sweep-legacy <ID>                              # Armory 0.93 funds -> SegWit
```

## Status

| Milestone | State |
|---|---|
| M0 primitives | done |
| M1 legacy v1.35 wallets (`armory legacy …`) | done |
| M1b modern wallets: BIP39/BIP84/BIP86, encryption, migration, descriptors | done |
| M2 paper / SecurePrint / fragmented backups (create, restore, `--test`; Armory 0.93 sheets and fragments restore) | done |
| M3 Bitcoin Core backend (`node status`, `wallet sync`, `balance`, `history --csv`, `utxos`) | done against a mock Core RPC server; not yet run against a real regtest node |
| M4 spending: `send` (incl. `--max`, RBF), `tx show/sign/broadcast` (offline PSBT), `wallet sweep-legacy` | done; signing verified locally for P2WPKH, P2TR and legacy P2PKH; Core funding tested against the mock only. Legacy USTX import/export not yet |
| M5 lockboxes, messages | not started |
| M6 TUI | not started |
| M7 goatpig `.lmdb` import | not started |
| M8 daemon, packaging | not started |
