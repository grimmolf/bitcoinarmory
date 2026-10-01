# ADR-001: Architecture of the Rust rebuild

Status: proposed · Date: 2026-10-01 · Depends on: [00-feature-evaluation](00-feature-evaluation.md)

## Context

Armory 0.93 is about 45k lines of Python 2/PyQt4 plus a C++ block indexer bridged through SWIG. The indexer no
longer works against current Bitcoin Core (no BIP144 parsing, XOR-obfuscated block files, removed RPCs; see
[spec 05](specs/05-blockchain-backend-and-network.md)). Python 2, PyQt4 and Crypto++ 5.6 are not packaged on current
Fedora or macOS. The parts of Armory that still have value are its key management, backups, offline signing and
multisig workflows. Their on-disk and on-paper formats must stay readable forever, because people still hold 2013-era
paper backups.

## Decision

### 1. Keep Armory's founding principle: let Bitcoin Core do the networking

The rebuild never parses `blk*.dat` and never speaks P2P. All chain data comes through a `ChainBackend` trait. Its v1
implementation is **Bitcoin Core JSON-RPC** (Core ≥ 29 supported, ≥ 21 the hard floor, cookie auth, local or
remote). Each Armory wallet or lockbox is mirrored into a **descriptor watch-only Core wallet**, one `pkh()` or
`sh(multi())` descriptor per address, imported in lookahead batches. An Electrum-protocol backend is a v2 option
behind the same trait. A `NullBackend` gives fully offline operation for the signing machine.

### 2. Cargo workspace

```
Cargo.toml                 (workspace, AGPL-3.0-or-later, MSRV pinned)
crates/
  armory-crypto/           primitives; no I/O
      hash, armory_hmac (32-byte-block HMAC quirk), checksum (+1-byte repair), easy16,
      kdf (ROMix), aes_cfb, legacy_chain (1.35 chained priv/pub keys), keys (WIF, mini, hex parsing),
      shamir (legacy deterministic restore + random-coefficient create)
  armory-wallet/           wallet file formats and backups
      legacy (v1.35 .wallet read/write, 237-byte address records, entry stream, atomic update + _backup copy),
      paper (single-sheet 1.35a/1.35c, SecurePrint), fragments (M-of-N), watchonly (root data),
      recovery (full/stripped/bare/meta), bip32 (new wallet type, decision D-1), store (dirs, perms, locking)
  armory-tx/               transactions and interchange
      ustx (3 legacy layouts in, newest layout out), psbt bridge, signing (P2PKH, P2SH-multisig, bare multisig, P2PK,
      + segwit for BIP32 wallets), coinselect, fees (sat/vB), message (Bitcoin-Qt, Armory clearsign/base64, BIP322),
      lockbox (lockbox, public-key block, promissory note, simulfunding), armor (ASCII blocks, 64/80 col, CRLF), uri
  armory-node/             ChainBackend trait, CoreRpc implementation (ureq JSON-RPC 2.0), NullBackend, sync cursor
  armory/                  the single binary
      app/  (service layer: every user operation as one function; used by both front-ends)
      cli/  (clap command tree from the parity map)
      tui/  (ratatui screens calling the same app functions)
      daemon/ (phase 3: armoryd-style JSON-RPC over a Unix socket)
tools/legacy-oracle/       C++ harness producing reference vectors from the original crypto
fixtures/legacy/           golden files from pytest/tiab.zip
```

Layering rule: `crypto` ← `wallet` ← `tx` ← `node` ← `armory`. Lower crates never depend on higher ones. Only
`armory` does terminal I/O. `node` is the only crate that touches the network.

### 3. Dependencies (choices)

| Need | Crate | Why |
|---|---|---|
| Bitcoin types, script, PSBT, bech32, sighash, BIP32 | `bitcoin` 0.32 (and its re-exported `secp256k1`) | De-facto standard. Using its re-export avoids two secp256k1 versions. |
| SHA-2, RIPEMD-160, AES, CFB | RustCrypto `sha2`, `ripemd`, `aes`, `cfb-mode` | Pure Rust, audited, portable to arm64 macOS |
| HMAC | Hand-written: Armory's HMAC uses a 32-byte block for SHA-256 (spec 01) | `hmac` crate cannot express the quirk |
| KDF | Hand-written ROMix (spec 01 §3) | Armory-specific |
| Secret hygiene | `zeroize`, `secrecy` | Wipes keys and passphrases on drop |
| CLI | `clap` 4 (derive) | |
| TUI | `ratatui` + `crossterm` | Works in any terminal on Fedora and macOS |
| RPC | `ureq` + `serde_json` (a small hand-written client) | Tiny surface; avoids an async runtime |
| Config | `serde` + `toml`, `directories` | XDG on Fedora, `~/Library/...` on macOS |
| Passphrase input | `rpassword` | |
| QR | `qrcode` (Unicode half-blocks) | Replaces `qrcodenative.py` |
| Errors | `thiserror` (libs), `anyhow` (bin) | Typed errors map to stable exit codes (#183) |
| Logging | `tracing` + `tracing-appender` (rotating) | #251 |

### 4. Data locations

Spec 05 §5.3 is adopted as is. Config lives in `~/.config/armory/armory.toml` (macOS:
`~/Library/Application Support/Armory/`). Wallets live in `<data>/<network>/wallets/`, with the directory 0700 and
files 0600; the program refuses to modify a wallet file that other users can read and tells the user to `chmod 600` it (#281).
`--datadir` puts everything under one root for air-gapped USB use. Legacy `~/.armory` is detected and its wallets
**copied**, never moved. Config precedence is CLI > env (`ARMORY_*`) > file > default (#288).

### 5. Security rules

- Every write of a wallet file is atomic: write a temp file, fsync, rename, fsync the directory. The legacy
  `_backup.wallet` twin is kept and both are updated with the legacy two-phase protocol (spec 01 §7). A new address
  is fsynced before it is displayed (#9).
- Private keys exist only in `Zeroizing` buffers. The CLI never caches an unlocked wallet between commands.
- Secrets are never logged. Debug formatting of secret types is redacted.
- Every signature is verified before a transaction is finalized or broadcast. A multisig spend with a bad signature
  is an error, not a warning (#291).
- New Shamir fragment sets use CSPRNG coefficients and a random set ID. Legacy deterministic sets are restore-only.
- The program never phones home. The only network peer is the configured backend.
- Signing uses standard RFC 6979 via libsecp256k1 with low-S (D-6).

### 6. Compatibility contract

| Artifact | Read | Write |
|---|---|---|
| `.wallet` v1.35 (encrypted/unencrypted/watching-only) | yes: unencrypted and encrypted (incl. pending records) verified on real Armory files; watching-only/imported/deleted records verified by code reading only | yes (byte-compatible with Armory 0.93) |
| Paper backup 1.35a/1.35c, SecurePrint | yes | yes |
| Fragmented backup (legacy deterministic) | yes | no (new sets are randomized; documented break) |
| USTX (all 3 layouts), lockbox (v0/v1), public-key block, promissory note, signed-message blocks | yes | newest layout, 80-column armour |
| `multisigs.txt` | yes | no (lockboxes move to `lockboxes.toml`; export to ASCII blocks remains) |
| `ArmorySettings.txt` | import once | no |
| Passphrase change on an encrypted wallet | — | recalibrates the KDF parameters (Armory 0.93 silently kept the old ones, spec 01a D2); the file stays readable by Armory |
| Watching-only copy | — | IVs are wiped (Armory 0.93 kept them by mistake and cleared them on the next read, spec 01a D1) |
| TxDP (pre-0.92) | no | no |
| goatpig `.lmdb` wallets | roadmap | no |

### 7. Testing strategy

1. **Vectors**: every hard-coded vector in `pytest/` plus the C++ oracle output (`tools/legacy-oracle/expected-output.txt`)
   become Rust unit tests, each citing its source line.
2. **Golden fixtures**: `fixtures/legacy/` wallets must parse, re-derive all 50 addresses, re-serialize
   byte-identically, and round-trip through lock/unlock. All USTX and lockbox fixtures must decode, recompute their
   IDs, and verify their signatures.
3. **Property tests** (`proptest`): Easy16 round-trip with single-byte repair, Shamir split/restore for every M ≤ 8,
   coin selection invariants (#46), armour parsing.
4. **Regtest integration**: CLI end-to-end against a real `bitcoind -regtest` (create, receive, send, PSBT/USTX
   offline round-trip, lockbox spend, reorg via `invalidateblock` (#14)). These tests are skipped when `bitcoind` is
   absent.
5. **CI**: GitHub Actions on `fedora:latest` (container) and `macos-latest` (arm64): fmt, clippy `-D warnings`,
   tests, `cargo deny`.

### 8. Packaging

- Fedora: an RPM spec (`packaging/fedora/armory.spec`) built in COPR, with a man page generated by `clap_mangen`
  and shell completions.
- macOS: a Homebrew formula (tap) and universal2 release tarballs.
- The binaries are portable; nothing is built with `target-cpu=native` (#335).

## Milestones

| # | Milestone | Exit criterion |
|---|---|---|
| M0 | Workspace and primitives | KDF/AES/chain match the oracle; Easy16, checksum and Shamir vectors pass |
| M1 | Legacy wallets | All fixture wallets parse, re-derive and re-serialize byte-identically; `armory wallet list/show/import`, `address list/new` offline |
| M2 | Backups | Paper/SecurePrint/fragments create and restore; `backup test`; legacy deterministic fragments restore |
| M3 | Core backend | Regtest: sync, balance, history, UTXOs for legacy wallets via descriptor watch-only wallets |
| M4 | Spending | Send (P2PKH legacy inputs → any output type), PSBT and USTX offline round-trip, broadcast with reject reasons, RBF |
| M5 | Lockboxes and messages | Lockbox create/import/fund/spend/merge, promissory notes, message sign/verify |
| M6 | TUI | All screens from evaluation §5 |
| M7 | New wallet type (D-1/D-2) | BIP32/BIP84 wallets with Armory paper and fragment backups |
| M8 | Daemon and packaging | `armory daemon`; RPM/COPR and Homebrew |

## Consequences

- The C++ tree, SWIG, LMDB, BitTornado, Qt and the Windows build are retired once parity is reached. Until then they
  stay in the repo as the reference implementation.
- Users must run Bitcoin Core ≥ 21 (≥ 29 recommended). A pruned node cannot restore old wallets until the Electrum
  backend lands.
- Legacy Armory wallets keep working, but they are P2PKH-only by construction. New funds should go to the new wallet
  type.
