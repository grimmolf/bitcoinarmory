# Armory (Rust)

The Rust rebuild of Armory for Fedora Linux and macOS. Design and status:
[`docs/rust-rebuild/`](../docs/rust-rebuild/README.md).

| Crate | Purpose |
|---|---|
| `armory-crypto` | Byte-exact legacy primitives: Armory HMAC, checksums, Easy16, ROMix KDF, AES, 1.35 key chain, Shamir, SecurePrint |
| `armory-wallet` | Modern v2 wallets (BIP39/BIP32, BIP84 SegWit + BIP86 Taproot accounts, descriptors, Argon2id + XChaCha20-Poly1305) and legacy v1.35 `.wallet` files (byte-compatible read/write, migration) |
| `armory-node` | Bitcoin Core JSON-RPC backend: watch-only descriptor wallets, balances, history, UTXOs, fees, broadcast |
| `armory` | The `armory` program: command line and full-screen terminal interface (`armory` / `armory tui`) |

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

## Terminal interface

Run `armory` (or `armory tui`) with the same global options as the commands (`--network`, `--datadir`,
the node options; values from `armory.toml` apply too). `1`–`0` or Tab switch screens, `[` `]` switch
wallet, `?` shows the keys of the screen, `:` runs any `armory` command and shows its output.

The TUI never has a second implementation of an action. Transactions go through the shared
prepare/execute operations (`src/ops.rs`); every other action runs the very same CLI command in-process,
with its output captured and its prompts answered from the TUI's dialogs (`src/io.rs`). Displays read
the wallet files and Bitcoin Core directly.

| Command | TUI |
|---|---|
| `wallet list` / `show` | Overview (1), Wallets (2) |
| `wallet create` / `restore` / `import` / `migrate` | Wallets: `c` / `R` / `I` / `m` |
| `wallet rename` / `passphrase` / `add-account` | Wallets: `e` / `p` / `A` |
| `wallet sync` | Wallets or Overview: `s` |
| `wallet descriptors [--private]` / `check` | Wallets: `d` / `D` / `k` |
| `wallet show-seed` / `export-keys` / `export-watchonly` / `remove` | Wallets: `S` / `X` / `E` / `x` |
| `wallet sweep-legacy` | Wallets: `L` |
| `address new` / `list` / `label` / `qr` | Receive (3): `n` / table / `l` / QR panel and Enter (`y` copies) |
| `uri create` | Receive: `u` |
| `send` (`--to`, `lockbox:ID=BTC`, `--max`, `--account`, fees, `--comment`, `--unsigned-out`, `--uri`) | Send (4): `n`, `u`, Enter on a contact |
| `send --from-utxo` (coin control) | History → coins: Space marks, `s` pays from the marked coins |
| `addressbook list` / `add` / `remove` | Send: table / `b` / `d` |
| `balance` / `history [--csv]` / `utxos` | Overview, History (5): table / `e` / `v` |
| `tx comment` / `bump-fee` / `abandon` | History: `c` / `f` / `x` |
| `tx show` / `sign` / `broadcast [--raw]` / `convert` / `combine` | Offline (6): `o` or `p` / `s` / `b`, `r` / `c` / `m` |
| `lockbox export-key` / `create` / `import` / `export` | Lockboxes (7): `k` / `n` / `i` / `e` |
| `lockbox list` / `show` / `address` / `sync` / `balance` / `utxos` / `spend` | Lockboxes: list / details / `a` / `s` / `b` / `u` / `p` |
| `backup paper` / `fragments` / `file` | Backup (8): `p` / `f` / `d` |
| `restore paper` / `fragments` (and `--test`) | Backup: `R` / `F` (`t` / `T`) |
| `message sign` / `verify` (and `--block`) | Tools (9): `s` / `v` / `b` |
| `sweep` / `tools key-info` / `tools decode-tx` / `uri parse` | Tools: `k` / `i` / `d` / `u` |
| `legacy …` (Armory 0.93 files: inspect, keys, byte-compatible edits) | Tools: `l` lists them; the commands run from `:` |
| `node status` | Overview, Settings (0): `t` |
| `config set` (network, node connection) | Settings: `n` / `c` ("save as defaults") |
| `about` | Settings: `a` |
| `completions`, `manpage` | command line only (shell integration) |

## Status

| Milestone | State |
|---|---|
| M0 primitives | done |
| M1 legacy v1.35 wallets (`armory legacy …`) | done |
| M1b modern wallets: BIP39/BIP84/BIP86, encryption, migration, descriptors | done |
| M2 paper / SecurePrint / fragmented backups (create, restore, `--test`; Armory 0.93 sheets and fragments restore) | done |
| M3 Bitcoin Core backend (`node status`, `wallet sync`, `balance`, `history --csv`, `utxos`) | done; end-to-end against `bitcoind -regtest` 29.1 in CI |
| M4 spending: `send` (incl. `--max`, BIP21, RBF bump, abandon), offline PSBT, Armory 0.93 offline transactions (USTX), `wallet sweep-legacy`, `sweep` (private keys) | done; regtest end-to-end in CI |
| M5 lockboxes (SegWit multisig, Armory 0.93 lockbox import), messages (BIP322, BIP137, Armory signed blocks), address book | done |
| M6 TUI | done: every command reachable (table above); tests render every screen and drive dialogs, incl. a payment against regtest Core |
| M7 goatpig `.lmdb` import | not started |
| M8 packaging (Fedora RPM, Homebrew), daemon | packaging: see `packaging/`; daemon not started |
