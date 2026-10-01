# CLAUDE.md — Armory Rust rebuild (handoff guide)

This repository holds two things:

- **The original Armory** (Python 2 / PyQt4 / C++, 2011–2015) at the top level (`ArmoryQt.py`, `armoryengine/`,
  `cppForSwig/`, …). It is **reference material only**: never modify it. Specs cite it as `file:line`.
- **The Rust rebuild** for Fedora Linux and macOS: `crates/`, `docs/rust-rebuild/`, `fixtures/`, `tools/`,
  `packaging/`, `.github/workflows/rust.yml`. All new work happens here, on branch `rust-rebuild`.

Start with [`crates/README.md`](crates/README.md) (usage, the command → TUI key map, status) and
[`docs/rust-rebuild/README.md`](docs/rust-rebuild/README.md) (design docs and byte-level specs).

## Status (v0.1, 2026-10-01)

CLI and TUI are feature-complete against the project's own parity map:
[`docs/rust-rebuild/00-feature-evaluation.md`](docs/rust-rebuild/00-feature-evaluation.md) §7 lists every row as
delivered or deferred (with the reason). CI is green on all jobs. No pull request has been opened.

## Build, test, check — run all before every commit

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked            # ~110 tests; offline, no node needed
```

Rust 1.85+ (edition 2024). `rustfmt.toml`: max_width 110. Lints: `unsafe_code = "forbid"` (workspace).

Optional, needs local tools:

- **Real Bitcoin Core end-to-end** (what CI's `regtest` job runs; download Core 29+ from bitcoincore.org):
  ```sh
  export ARMORY_BITCOIND=/path/to/bitcoin-31.1/bin/bitcoind
  cargo test -p armory --test regtest --release -- --nocapture                # CLI flows
  cargo test -p armory --bin armory --release regtest -- --nocapture          # TUI payment flow
  ```
  Without `ARMORY_BITCOIND` these tests print "skipping" and pass.
- **Legacy crypto oracle** (original C++ crypto as reference): `tools/legacy-oracle/build.sh`, then
  `diff <(tools/legacy-oracle/build/harness) tools/legacy-oracle/expected-output.txt`.
- **Packages**: `packaging/dist.sh` (tarball); RPM via `packaging/fedora/armory.spec` (CI job `rpm` shows how).
- **Try the TUI**: `cargo run -p armory -- --network regtest --datadir /tmp/armory-try` (no node needed for
  wallets, backups, offline signing).

## Workspace map

| Crate | Role |
|---|---|
| `armory-crypto` | Byte-exact legacy primitives (Armory HMAC, ROMix, AES-CFB, 1.35 chain, Easy16, Shamir, SecurePrint) |
| `armory-wallet` | `legacy.rs`/`record.rs`/`store.rs`: v1.35 `.wallet` files (byte-identical round trip). `modern.rs`: v2 wallet (BIP39, BIP84/BIP86/legacy-1.35 accounts, Argon2id + XChaCha20-Poly1305). `sign.rs` PSBT signing/finalizing/checking, `backup.rs`, `lockbox.rs`, `message.rs`, `ustx.rs` (Armory 0.93 offline tx), `sweep.rs`, `descriptor.rs` |
| `armory-node` | Bitcoin Core JSON-RPC (hand-written HTTP/1.1, cookie auth); `core.rs` = watch-only descriptor wallets `armory-<id>` / `armory-lb-<id>` |
| `armory` | The binary. `main.rs` (clap tree, `run`, `run_captured`), `cli_*.rs` per command group, `ops.rs` shared transaction flows, `io.rs` terminal I/O + capture, `tui/` |

## Architecture rules (keep them)

1. **One implementation per action.** The TUI never re-implements a command:
   - Transactions: `ops::prepare_send` / `prepare_sweep_legacy` / `prepare_bump` build and *check* a PSBT
     (no prompts, no printing); `ops::execute` / `execute_unlocked` sign and broadcast. CLI and TUI both compose these.
   - Everything else: the TUI builds an argv and calls `crate::run_captured(args, inputs)` on a worker thread.
2. **All command I/O goes through `io.rs`**: `outln!` / `noteln!` instead of `println!` / `eprintln!`,
   `io::secret(prompt)` for secrets, `io::read_all(what)` for pasted text, `io::confirm`. In capture mode prompts
   are answered from `Inputs` **matched by prompt prefix** ("New passphrase", "Passphrase for wallet",
   "Recovery phrase", "BIP39 passphrase", "Passphrase of legacy wallet", "Private key", "SecurePrint code",
   "backup lines", "fragments", "signed block"). If you add a prompt, keep its wording stable or update the TUI
   callers in `tui/screens.rs`.
3. **Never trust Core's PSBT blindly**: `sign::check_psbt` runs before signing (own inputs, exact payments,
   other outputs ours, fee cap); `sign::finalize` verifies every multisig cosigner signature.
4. **Wallet files**: atomic writes (`store::atomic_write`), 0600 files / 0700 dirs, world-readable wallets refused.
   Legacy saves keep Armory's `_backup` twin + flag-file order. v2 public data is authenticated (AAD) and
   re-verified on unlock.
5. **TUI**: global keys (`tui/app.rs` `GLOBAL_KEYS`: q r w W [ ] ? : digits) are handled before screens;
   screens must not use them. Every advertised key must do something — `every_advertised_key_does_something`
   enforces it; update its key strings when you add keys, and the help/footer text in `screens.rs`.
   Jobs run under `catch_unwind`; only UI-thread panics restore the terminal.
6. **Compatibility is proven, not assumed**: new legacy-format code needs a golden fixture, an oracle value or a
   published vector (see `fixtures/legacy/README.md`).

## Conventions

- Commit messages: imperative subject, wrapped body explaining why; write them to a file and use `git commit -F`
  (backticks in shell strings get executed). Trailers used so far:
  `Co-Authored-By: …` and `Claude-Session: …` — keep whatever your own session requires.
- Never put a model identifier in commits or docs. Don't open PRs unless asked.
- Docs: plain, precise; specs cite `file:line`; mark anything unverified as such.
- Update `crates/README.md` (key map, status) and feature-evaluation §7 when a row changes state.

## Next work (prioritised)

1. **goatpig "0.97" `.lmdb` import** — research done: [`docs/rust-rebuild/specs/08-goatpig-lmdb-format.md`](docs/rust-rebuild/specs/08-goatpig-lmdb-format.md)
   (read its "Findings" section first). Steps:
   1. `git clone https://github.com/goatpig/BitcoinArmory` (branch `dev`, spec written against `d0294d5`);
      build an oracle like `tools/legacy-oracle/` that creates sample `.lmdb` wallets with known passphrases
      (legacy-chain default wallet, BIP39 restore, watching-only, empty and non-empty control passphrase) and
      dumps expected IDs/addresses. This also settles the spec's open questions (AES-CBC padding, HMAC argument
      order, host-endian counters).
   2. Reader in `armory-wallet` (new module, read-only; **always open a copy** — goatpig mutates the file on open).
      Needs an LMDB reader crate (e.g. `heed`/`lmdb-rkv`) or a minimal read-only LMDB page parser.
   3. Mapping: legacy chain → `legacy-1.35` account (needs **per-address types**: compressed/P2WPKH/P2SH-P2WPKH
      on the legacy chain — not modelled yet); BIP39 → restore + BIP84 (+ new BIP44/BIP49 account kinds);
      salted/ECDH accounts → refuse with a clear message or key-by-key export.
   4. CLI `wallet migrate --from-lmdb FILE`, TUI Wallets `m` form option, tests, §7 update.
2. Smaller deferred rows (feature-evaluation §7): WM-17 damaged-wallet recovery, AR-02 no-backup warning,
   BK-03 PDF sheets, MS-12..14 promissory notes (fixtures exist in `fixtures/legacy/`), TL-03 EC calculator,
   logging (MI-16/TL-02), `config get/reset`, NO_COLOR, single-instance lock, `bitcoin:` URI handler.
3. Release automation: tag-triggered workflow running `packaging/dist.sh` per target, Homebrew sha256.
4. Phase 3: `armory daemon` (JSON-RPC, decision D-5 in `00-feature-evaluation.md`).

## Gotchas

- `ModernWallet::unlock` costs an Argon2id run (256 MiB default): tests use `--kdf-memory-mib 1 --kdf-iterations 1`.
- Core tops up ranged descriptors to its keypool (1000); re-imports must not narrow the range
  (`Core::import_descriptors` retries with Core's reported range).
- `tests/regtest.rs` and `tui/tests.rs::regtest_*` are the only tests against real Core; the mock Core
  (`armory-node/tests/mock_core.rs`) mimics the range behaviour above.
- The Fedora container skips man pages on install (nodocs): check RPM contents with `rpm -qlp`, not `ls`.
- Testnet3/4/signet/regtest share testnet's base58 version bytes for legacy files.
